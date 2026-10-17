//! Shared test harness: a nucleus on ephemeral localhost ports and fake daemons

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fakenet_capture::Capture;
use fakenet_link::{Link, LinkConfig};
use fakenet_listeners::config::{AutoKeyword, ListenerProtocol};
use fakenet_listeners::{Context, Defaults, LimitsConfig, ListenerConfig, Server, TlsAuthority};
use fakenet_schema::{Action, ActionKind, Event, Protocol, Transport, VERSION};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite;

pub fn listener(name: &str, protocol: Option<Protocol>, transport: Transport, tls: bool) -> ListenerConfig {
    ListenerConfig {
        name: name.into(),
        protocol: protocol.map(ListenerProtocol::Fixed).unwrap_or(ListenerProtocol::Auto(AutoKeyword::Auto)),
        transport,
        tls,
        ..ListenerConfig::default()
    }
}

pub struct Nucleus {
    pub server: Server,
    pub dir: PathBuf,
    pub ca: Arc<TlsAuthority>,
}

impl Nucleus {
    pub async fn start(name: &str, link: LinkConfig, listeners: &[ListenerConfig]) -> Nucleus {
        Nucleus::start_with(name, link, listeners, Defaults::default()).await
    }

    pub async fn start_with(name: &str, link: LinkConfig, listeners: &[ListenerConfig], defaults: Defaults) -> Nucleus {
        Nucleus::start_full(name, link, listeners, defaults, None, LimitsConfig::default()).await
    }

    pub async fn start_full(name: &str, link: LinkConfig, listeners: &[ListenerConfig], defaults: Defaults, explorer: Option<Arc<fakenet_explorer::Explorer>>, limits: LimitsConfig) -> Nucleus {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("listeners-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = Arc::new(TlsAuthority::generate().unwrap());
        let ctx = Arc::new(Context {
            link: Link::start(link),
            capture: Capture::open(&dir).unwrap(),
            defaults: arc_swap::ArcSwap::from_pointee(defaults),
            tls: ca.clone(),
            timeout: Duration::from_secs(5),
            first_data_timeout: Duration::from_millis(300),
            original: None,
            explorer,
            limits: Arc::new(fakenet_listeners::Limits::new(&limits)),
            known_fingerprints: Default::default(),
        });
        let server = Server::start(ctx, "127.0.0.1".parse().unwrap(), listeners).await.unwrap();
        Nucleus { server, dir, ca }
    }

    pub fn address(&self, name: &str) -> SocketAddr {
        self.server.address(name).unwrap()
    }

    pub fn events(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("events.jsonl")).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    pub fn kinds(&self, kind: &str) -> Vec<Value> {
        self.events().into_iter().filter(|e| e["kind"] == kind).collect()
    }

    pub fn tls_connector(&self) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.ca_der().clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

/// Nothing listens on this port: the daemon is "stopped"
pub fn stopped_daemon() -> LinkConfig {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    LinkConfig { websocket_url: Some(format!("ws://127.0.0.1:{port}/link")), ..LinkConfig::default() }
}

/// What a fake daemon answers: None = the default; Some((response, close))
pub type Responder = fn(&Event) -> Option<(Vec<u8>, bool)>;

/// A fake daemon over the real WebSocket channel, answering after `delay`
pub async fn fake_daemon(delay: Duration, responder: Responder) -> LinkConfig {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = socket.accept().await {
            tokio::spawn(async move {
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let (sink, mut events) = websocket.split();
                let sink = Arc::new(tokio::sync::Mutex::new(sink));
                while let Some(Ok(tungstenite::Message::Text(text))) = events.next().await {
                    let event: Event = serde_json::from_str(text.as_str()).unwrap();
                    if !event.expects_reply {
                        continue;
                    }
                    let answer = responder(&event);
                    let action = Action {
                        version: VERSION,
                        kind: ActionKind::Action,
                        route: Some(format!("fake-{}", event.protocol.name())),
                        request_id: event.request_id,
                        session_id: event.session_id,
                        close: answer.as_ref().is_some_and(|a| a.1),
                        response: answer.map(|a| a.0),
                        delay_ms: None,
                        auth: None,
                    };
                    let sink = sink.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = sink.lock().await.send(tungstenite::Message::text(serde_json::to_string(&action).unwrap())).await;
                    });
                }
            });
        }
    });
    LinkConfig { websocket_url: Some(format!("ws://{address}/link")), ..LinkConfig::default() }
}

/// The link connects in the background; give it a moment before the first request
pub async fn wait_connected() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}
