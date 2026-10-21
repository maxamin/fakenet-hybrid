//! The catch-all: raw TCP & UDP. Every chunk (TCP) or datagram (UDP) is an event; the
//! daemon may reply with any bytes and/or close, else the default applies (echo, as in
//! FakeNet-NG's RawListener, or a configured static response).

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::RawMode;
use crate::custom::RawResponse;
use crate::session::Session;
use crate::stream::BoxStream;

const CHUNK: usize = 16 * 1024;

fn default_reply(session: &Session, data: &[u8]) -> Vec<u8> {
    if let Some((_, RawResponse::Static(bytes))) = session.custom.as_deref().and_then(|c| c.raw.as_ref()) {
        return bytes.clone();
    }
    let guard = session.ctx.defaults.load();
    let defaults = &guard.raw;
    match defaults.mode {
        RawMode::Echo => data.to_vec(),
        RawMode::Static => defaults.response.as_bytes().to_vec(),
    }
}

/// A TcpDynamic custom provider takes over the whole connection (no per-chunk events)
fn dynamic_provider(session: &Session) -> Option<(String, std::path::PathBuf)> {
    match session.custom.as_deref().and_then(|c| c.raw.as_ref()) {
        Some((name, RawResponse::Dynamic(path))) => Some((name.clone(), path.clone())),
        _ => None,
    }
}

pub async fn handle_tcp(mut stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    if let Some((name, provider)) = dynamic_provider(&session) {
        session.log("custom_response", json!({ "section": name, "provider": provider.display().to_string() }));
        return crate::custom::run_tcp_provider(&provider, stream, session.ctx.timeout).await;
    }
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = match tokio::time::timeout(session.ctx.timeout, stream.read(&mut buffer)).await {
            Err(_) | Ok(Ok(0)) => return Ok(()),
            Ok(result) => result?,
        };
        let data = buffer[..read].to_vec();
        session.client_data(&data);
        let default = default_reply(&session, &data);
        let action = session.decide_with_default(&data, json!({ "bytes": read }), Some(&default)).await;
        let close = action.as_ref().is_some_and(|a| a.close);
        let reply = action.and_then(|a| a.response).unwrap_or(default);
        if !reply.is_empty() {
            stream.write_all(&reply).await?;
            stream.flush().await?;
            session.server_data(&reply);
        }
        if close {
            let _ = stream.shutdown().await;
            return Ok(());
        }
    }
}

pub async fn handle_udp(data: &[u8], session: &mut Session, peer: std::net::SocketAddr, socket: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
    session.client_data(data);
    if let Some((name, provider)) = dynamic_provider(session) {
        session.log("custom_response", json!({ "section": name, "provider": provider.display().to_string() }));
        if let Err(e) = crate::custom::run_udp_provider(&provider, socket, data, peer).await {
            session.log("custom_failed", json!({ "error": e.to_string() }));
        }
        return None;
    }
    let default = default_reply(session, data);
    let action = session.decide_with_default(data, json!({ "bytes": data.len() }), Some(&default)).await;
    let reply = action.and_then(|a| a.response).unwrap_or(default);
    if reply.is_empty() {
        return None;
    }
    session.server_data(&reply);
    Some(reply)
}
