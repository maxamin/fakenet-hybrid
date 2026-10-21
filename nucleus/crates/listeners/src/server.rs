//! Binds the configured listeners and runs them until dropped

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use fakenet_schema::Transport;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::config::ListenerConfig;
use crate::dispatch;
use crate::session::{Context, Session};

/// A listener's config and what was loaded for it
pub struct Listener {
    pub config: ListenerConfig,
    pub custom: Option<Arc<crate::custom::CustomResponses>>,
    /// The port actually bound (differs from the config's when it asks for port 0)
    pub bound_port: std::sync::atomic::AtomicU16,
}

/// The running listeners. Dropping it stops them all.
pub struct Server {
    /// (listener name, transport, bound address), in config order
    pub bound: Vec<(String, Transport, SocketAddr)>,
    _tasks: JoinSet<()>,
}

impl Server {
    pub async fn start(ctx: Arc<Context>, bind: IpAddr, listeners: &[ListenerConfig]) -> anyhow::Result<Server> {
        let mut tasks = JoinSet::new();
        let mut bound = Vec::new();
        for config in listeners {
            let custom = match &config.custom {
                Some(file) => Some(Arc::new(crate::custom::CustomResponses::load(file, config).with_context(|| format!("listener {}", config.name))?)),
                None => None,
            };
            let config = Arc::new(Listener { config: config.clone(), custom, bound_port: std::sync::atomic::AtomicU16::new(config.port) });
            let config_ref = &config.config;
            let address = SocketAddr::new(bind, config_ref.port);
            match config_ref.transport {
                Transport::Tcp => {
                    let socket = TcpListener::bind(address).await.with_context(|| format!("binding {} to tcp {address}", config_ref.name))?;
                    bound.push((config_ref.name.clone(), Transport::Tcp, socket.local_addr()?));
                    tasks.spawn(serve_tcp(ctx.clone(), config.clone(), socket));
                }
                Transport::Udp if is_http3(config_ref) => {
                    let socket = std::net::UdpSocket::bind(address).with_context(|| format!("binding {} to udp {address}", config_ref.name))?;
                    let local = socket.local_addr()?;
                    config.bound_port.store(local.port(), std::sync::atomic::Ordering::Relaxed);
                    bound.push((config_ref.name.clone(), Transport::Udp, local));
                    tasks.spawn(crate::http3::serve(ctx.clone(), config.clone(), socket));
                }
                Transport::Udp => {
                    let socket = UdpSocket::bind(address).await.with_context(|| format!("binding {} to udp {address}", config_ref.name))?;
                    bound.push((config_ref.name.clone(), Transport::Udp, socket.local_addr()?));
                    tasks.spawn(serve_udp(ctx.clone(), config.clone(), Arc::new(socket)));
                }
            }
        }
        Ok(Server { bound, _tasks: tasks })
    }

    pub fn address(&self, name: &str) -> Option<SocketAddr> {
        self.bound.iter().find(|(n, _, _)| n == name).map(|(_, _, a)| *a)
    }
}

/// A UDP listener with protocol "http" serves HTTP/3 (QUIC)
fn is_http3(config: &ListenerConfig) -> bool {
    config.protocol == crate::config::ListenerProtocol::Fixed(fakenet_schema::Protocol::Http)
}

async fn serve_tcp(ctx: Arc<Context>, config: Arc<Listener>, socket: TcpListener) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = socket.accept() => match accepted {
                Ok((stream, client)) => {
                    let Some(permit) = ctx.limits.admit(client.ip(), &config.config.name) else {
                        continue; // Dropping the stream closes it
                    };
                    let (ctx, config) = (ctx.clone(), config.clone());
                    connections.spawn(async move {
                        let _permit = permit;
                        if let Err(e) = dispatch::handle_tcp(ctx, config.clone(), stream, client).await {
                            tracing::debug!("[{}] {client}: {e:#}", config.config.name);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("[{}] accept: {e}", config.config.name);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            },
            // Reap finished connections so the set doesn't grow
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

type UdpSessions = Mutex<HashMap<SocketAddr, (Arc<Mutex<Session>>, Instant, crate::limits::SessionPermit)>>;

/// Datagrams being answered at once per UDP listener; past it, new ones are dropped (UDP
/// may lose packets anyway) rather than queued without bound
const MAX_UDP_IN_FLIGHT: usize = 1024;

/// One session per client address, expired after the idle timeout. Datagrams from one
/// client are answered in order; different clients in parallel.
async fn serve_udp(ctx: Arc<Context>, config: Arc<Listener>, socket: Arc<UdpSocket>) {
    let sessions: Arc<UdpSessions> = Arc::default();
    let local = match socket.local_addr() {
        Ok(local) => local,
        Err(_) => return,
    };
    if let Err(e) = crate::original_dst::enable_udp_original_destination(&socket) {
        tracing::debug!("[{}] original UDP destinations unavailable: {e}", config.config.name);
    }
    let mut tasks = JoinSet::new();
    let mut sweep = tokio::time::interval(ctx.timeout);
    let mut buffer = vec![0u8; 65536];
    loop {
        tokio::select! {
            received = crate::original_dst::recv_with_original(&socket, &mut buffer) => {
                let (length, client, arrived) = match received {
                    Ok(received) => received,
                    Err(e) => {
                        // e.g. ICMP port unreachable surfacing on Windows; keep serving
                        tracing::debug!("[{}] recv: {e}", config.config.name);
                        continue;
                    }
                };
                if tasks.len() >= MAX_UDP_IN_FLIGHT {
                    continue;
                }
                let data = buffer[..length].to_vec();
                let session = {
                    let mut table = sessions.lock().await;
                    if !table.contains_key(&client) {
                        let Some(permit) = ctx.limits.admit(client.ip(), &config.config.name) else { continue };
                        // Where the datagram arrived (after a REDIRECT: e.g. 127.0.0.1), and
                        // where the client sent it, from connection tracking
                        let arrived_at = arrived.unwrap_or(local);
                        let redirected = crate::original_dst::conntrack_original(17, arrived_at, client)
                            .or(arrived)
                            .filter(|o| *o != local);
                        let mut session = Session::new(ctx.clone(), &config.config.name, fakenet_schema::Protocol::Raw, Transport::Udp, client, arrived_at, redirected);
                        session.custom = config.custom.clone();
                        let protocol = dispatch::udp_protocol(&config.config, &data, session.builder.dst.port());
                        if protocol != fakenet_schema::Protocol::Raw {
                            session.set_protocol(protocol, false);
                        }
                        table.insert(client, (Arc::new(Mutex::new(session)), Instant::now(), permit));
                    }
                    let entry = table.get_mut(&client).expect("inserted above");
                    entry.1 = Instant::now();
                    entry.0.clone()
                };
                let socket = socket.clone();
                let listener = config.clone();
                tasks.spawn(async move {
                    let mut session = session.lock().await;
                    if let Some(reason) = crate::custom::filter(&listener.config, session.builder.process.as_ref(), session.builder.dst.ip()) {
                        session.log("filtered", serde_json::json!({ "reason": reason }));
                        return;
                    }
                    if let Some(reply) = dispatch::handle_udp(&mut session, &data, client, &socket).await {
                        // From the address the request arrived at, so a REDIRECT's NAT applies
                        let _ = crate::original_dst::send_from(&socket, &reply, arrived.map(|a| a.ip()), client).await;
                    }
                });
            }
            _ = sweep.tick() => {
                let idle = ctx.timeout;
                sessions.lock().await.retain(|_, (_, last, _)| last.elapsed() < idle);
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
