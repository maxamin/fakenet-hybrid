//! Picks a protocol handler for each connection: fixed listeners use their protocol;
//! "auto" listeners peek at the first bytes (unwrapping TLS first if needed) and sniff.

use std::net::SocketAddr;
use std::sync::Arc;

use fakenet_schema::{Protocol, Transport};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use std::future::Future;
use std::pin::Pin;

use crate::config::{AutoKeyword, ListenerConfig, ListenerProtocol};
use crate::session::{Context, Session};
use crate::stream::{BoxStream, PrefixedStream};
use crate::{dns, ftp, http, imap, irc, ntp, pop3, raw, redis, simple, smtp, socks, ssh, syslog, telnet, tftp};

const PEEK: usize = 4096;

pub async fn handle_tcp(ctx: Arc<Context>, listener: Arc<crate::server::Listener>, stream: TcpStream, client: SocketAddr) -> anyhow::Result<()> {
    let (custom, listener) = (listener.custom.clone(), &listener.config);
    let _ = stream.set_nodelay(true);
    let local = stream.local_addr()?;
    let redirected = crate::original_dst::original_destination(&stream).filter(|d| *d != local);
    let initial = match listener.protocol {
        ListenerProtocol::Fixed(protocol) => protocol,
        ListenerProtocol::Auto(_) => Protocol::Raw,
    };
    let mut session = Session::new(ctx, &listener.name, initial, Transport::Tcp, client, local, redirected);
    session.custom = custom;
    if let Some(reason) = crate::custom::filter(listener, session.builder.process.as_ref(), session.builder.dst.ip()) {
        session.log("filtered", json!({ "reason": reason }));
        return Ok(());
    }
    serve(session, Box::new(stream), listener.protocol, listener.tls).await
}

/// A stream tunnelled through an HTTP proxy CONNECT: a new session (to the tunnel's
/// target), sniffed like an "auto" listener's connection
pub(crate) fn serve_tunnel(parent: &Session, stream: BoxStream, target: String, dst: SocketAddr) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> {
    let mut session = Session::new(parent.ctx.clone(), &parent.listener, Protocol::Raw, Transport::Tcp, parent.builder.src, parent.local, Some(dst));
    session.builder.dst = dst;
    session.tls_fallback_name = Some(target.rsplit_once(':').map(|(host, _)| host).unwrap_or(&target).trim_matches(['[', ']']).to_string());
    session.log("proxy_tunnel", json!({ "parent_session": parent.builder.session_id, "target": target }));
    Box::pin(serve(session, stream, ListenerProtocol::Auto(AutoKeyword::Auto), false))
}

/// Unwraps TLS and/or sniffs as configured, then runs the protocol's handler
pub(crate) async fn serve(mut session: Session, mut stream: BoxStream, protocol: ListenerProtocol, tls: bool) -> anyhow::Result<()> {
    let ctx = session.ctx.clone();
    let dst = session.builder.dst;
    match protocol {
        ListenerProtocol::Fixed(protocol) => {
            if tls {
                stream = terminate_tls(stream, &mut session).await?;
                session.set_protocol(protocol, true);
            }
        }
        ListenerProtocol::Auto(_) => {
            let mut first = peek(&mut stream, &ctx).await?;
            let mut is_tls = false;
            if fakenet_sniffer::looks_like_tls(&first) || tls {
                stream = terminate_tls(Box::new(PrefixedStream::new(first, stream)), &mut session).await?;
                first = peek(&mut stream, &ctx).await?;
                is_tls = true;
            }
            let candidates = fakenet_sniffer::DEFAULT_ORDER;
            let protocol = if first.is_empty() {
                fakenet_sniffer::sniff_silent(candidates, dst.port())
            } else {
                fakenet_sniffer::sniff(candidates, &first, dst.port(), Transport::Tcp)
            };
            session.set_protocol(protocol, is_tls);
            stream = Box::new(PrefixedStream::new(first, stream));
        }
    }

    match session.protocol() {
        Protocol::Http => http::handle(stream, session).await,
        Protocol::Dns => dns::handle_tcp(stream, session).await,
        Protocol::Smtp => smtp::handle(stream, session).await,
        Protocol::Pop3 => pop3::handle(stream, session).await,
        Protocol::Ftp => ftp::handle(stream, session).await,
        Protocol::Irc => irc::handle(stream, session).await,
        Protocol::Imap => imap::handle(stream, session).await,
        Protocol::Ssh => ssh::handle(stream, session).await,
        Protocol::Telnet => telnet::handle(stream, session).await,
        Protocol::Redis => redis::handle(stream, session).await,
        Protocol::Socks => socks::handle(stream, session).await,
        Protocol::Syslog => syslog::handle_tcp(stream, session).await,
        Protocol::Echo | Protocol::Discard | Protocol::Daytime | Protocol::Chargen | Protocol::Time | Protocol::Qotd | Protocol::Finger
        | Protocol::Whois => simple::handle_tcp(stream, session).await,
        // TFTP and NTP are UDP-only; anything else gets the catch-all
        Protocol::Raw | Protocol::Tftp | Protocol::Ntp => raw::handle_tcp(stream, session).await,
    }
}

/// The client's first bytes, or nothing if it waits for us to speak first
async fn peek(stream: &mut BoxStream, ctx: &Context) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![0u8; PEEK];
    match tokio::time::timeout(ctx.first_data_timeout, stream.read(&mut buffer)).await {
        Err(_) => Ok(Vec::new()),
        Ok(read) => {
            buffer.truncate(read?);
            Ok(buffer)
        }
    }
}

/// Terminates TLS with a certificate for the client's SNI, or (no SNI: clients connecting
/// to an IP) for the session's fallback name or destination IP. Offers h2/http/1.1 when
/// the client asks for them.
pub(crate) async fn terminate_tls(stream: BoxStream, session: &mut Session) -> anyhow::Result<BoxStream> {
    let ctx = session.ctx.clone();
    let accept = async {
        let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
        let hello = start.client_hello();
        let sni = hello.server_name().map(str::to_string);
        let offered: Vec<Vec<u8>> = hello.alpn().map(|protocols| protocols.map(<[u8]>::to_vec).collect()).unwrap_or_default();
        let alpn = [b"h2".to_vec(), b"http/1.1".to_vec()].into_iter().filter(|p| offered.contains(p)).collect();
        let name = sni.clone().or_else(|| session.tls_fallback_name.clone()).unwrap_or_else(|| session.builder.dst.ip().to_string());
        let config = ctx.tls.config_for(&name, alpn)?;
        let tls = start.into_stream(config).await?;
        anyhow::Ok((tls, sni, name))
    };
    match tokio::time::timeout(ctx.timeout, accept).await {
        Ok(Ok((tls, sni, certificate))) => {
            let alpn = tls.get_ref().1.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
            session.log("tls_handshake", json!({ "sni": sni, "certificate": certificate, "alpn": alpn }));
            Ok(Box::new(tls))
        }
        Ok(Err(e)) => {
            session.log("tls_failed", json!({ "error": e.to_string() }));
            Err(e)
        }
        Err(_) => {
            session.log("tls_failed", json!({ "error": "timeout" }));
            anyhow::bail!("TLS handshake timed out")
        }
    }
}

/// Which handler a UDP datagram gets
pub fn udp_protocol(listener: &ListenerConfig, data: &[u8], port: u16) -> Protocol {
    match listener.protocol {
        ListenerProtocol::Fixed(protocol) => protocol,
        ListenerProtocol::Auto(_) => fakenet_sniffer::sniff(fakenet_sniffer::DEFAULT_ORDER, data, port, Transport::Udp),
    }
}

/// Answers one UDP datagram within its session. `peer` is the sender as our socket sees it
/// (where replies go; not always the original client, see `Session::new`).
pub async fn handle_udp(session: &mut Session, data: &[u8], peer: SocketAddr, socket: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
    match session.protocol() {
        Protocol::Dns => dns::answer(data, session).await,
        Protocol::Tftp => tftp::handle(data, session, peer).await,
        Protocol::Ntp => ntp::handle(data, session).await,
        Protocol::Syslog => syslog::handle_udp(data, session),
        Protocol::Echo | Protocol::Discard | Protocol::Daytime | Protocol::Chargen | Protocol::Time | Protocol::Qotd => simple::handle_udp(data, session).await,
        _ => raw::handle_udp(data, session, peer, socket).await,
    }
}
