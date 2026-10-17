//! HTTP/3 over QUIC (quinn + h3): a UDP listener with `protocol = "http"`. TLS is QUIC's
//! own (TLS 1.3, ALPN h3), with certificates minted per SNI by the same authority as
//! HTTPS. Each QUIC connection is one session; each request goes through the same path as
//! HTTP/1.1 & HTTP/2 (`http::answer`), so events, decisions and defaults are identical.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use fakenet_schema::{Protocol, Transport};
use http_body_util::BodyExt;
use serde_json::json;
use tokio::task::JoinSet;

use crate::session::{Context, Session};

/// Serves HTTP/3 on a bound UDP socket until dropped
pub async fn serve(ctx: Arc<Context>, listener: Arc<crate::server::Listener>, socket: std::net::UdpSocket) {
    let name = listener.config.name.clone();
    let endpoint = match endpoint(&ctx, socket) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            tracing::error!("[{name}] HTTP/3 unavailable: {e:#}");
            return;
        }
    };
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return };
                let Some(permit) = ctx.limits.admit(incoming.remote_address().ip(), &name) else {
                    incoming.refuse();
                    continue;
                };
                let (ctx, listener) = (ctx.clone(), listener.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = connection(ctx, listener, incoming).await {
                        tracing::debug!("HTTP/3 connection: {e:#}");
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

fn endpoint(ctx: &Context, socket: std::net::UdpSocket) -> anyhow::Result<quinn::Endpoint> {
    let tls = ctx.tls.server_config(&[b"h3"]);
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(ctx.timeout.try_into()?));
    config.transport_config(Arc::new(transport));
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(config), socket, Arc::new(quinn::TokioRuntime))?)
}

async fn connection(ctx: Arc<Context>, listener: Arc<crate::server::Listener>, incoming: quinn::Incoming) -> anyhow::Result<()> {
    let peer = incoming.remote_address();
    let local: SocketAddr = incoming.local_ip().map(|ip| SocketAddr::new(ip, 0)).unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let connection = incoming.await?;
    let sni = connection.handshake_data().and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|d| d.server_name);
    let local_port = connection_local_port(&listener);
    let mut session = Session::new(ctx.clone(), &listener.config.name, Protocol::Http, Transport::Udp, peer, SocketAddr::new(local.ip(), local_port), None);
    session.builder.tls = true;
    session.custom = listener.custom.clone();
    if let Some(reason) = crate::custom::filter(&listener.config, session.builder.process.as_ref(), session.builder.dst.ip()) {
        session.log("filtered", json!({ "reason": reason }));
        connection.close(0u32.into(), b"");
        return Ok(());
    }
    session.log("tls_handshake", json!({ "sni": sni, "alpn": "h3" }));
    let session = Arc::new(tokio::sync::Mutex::new(session));

    let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await?;
    let mut requests = JoinSet::new();
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let session = session.clone();
                requests.spawn(async move {
                    if let Err(e) = request(resolver, session).await {
                        tracing::debug!("HTTP/3 request: {e:#}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("HTTP/3 accept: {e}");
                break;
            }
        }
    }
    while requests.join_next().await.is_some() {}
    Ok(())
}

/// The listener's configured port (QUIC endpoints don't expose a per-connection local address)
fn connection_local_port(listener: &crate::server::Listener) -> u16 {
    listener.bound_port.load(std::sync::atomic::Ordering::Relaxed)
}

async fn request<C>(resolver: h3::server::RequestResolver<C, Bytes>, session: Arc<tokio::sync::Mutex<Session>>) -> anyhow::Result<()>
where
    C: h3::quic::Connection<Bytes>,
{
    let (request, mut stream) = resolver.resolve_request().await?;
    let (max, mut held) = {
        let session = session.lock().await;
        (session.ctx.defaults.http.max_body_bytes, session.ctx.limits.hold())
    };
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if body.len() + chunk.remaining() > max || held.grow(chunk.remaining()).is_err() {
            let response = hyper::Response::builder().status(413).body(())?;
            stream.send_response(response).await?;
            stream.finish().await?;
            return Ok(());
        }
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let length = part.len();
            chunk.advance(length);
        }
    }
    let (parts, ()) = request.into_parts();
    let response = {
        let mut session = session.lock().await;
        crate::http::answer(&mut session, parts, Bytes::from(body)).await
    };
    let (mut head, body) = response.into_parts();
    // Connection-specific headers are forbidden in HTTP/3 (RFC 9114 4.2)
    head.headers.remove("connection");
    let content = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    stream.send_response(hyper::Response::from_parts(head, ())).await?;
    if !content.is_empty() {
        stream.send_data(content).await?;
    }
    stream.finish().await?;
    Ok(())
}
