//! WebSocket (RFC 6455) after an HTTP/1.1 upgrade: the upgrade request is an HTTP event (a
//! rule's response refuses it, e.g. with a 403), then a child session with protocol
//! "websocket" carries each text/binary message to the daemon as an event; a non-empty
//! response goes back as a message (text when it's UTF-8), and the close flag ends it.
//! Framing, masking and ping/pong are tungstenite's.

use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use crate::lines::preview;
use crate::session::Session;

/// A client's largest message (and frame)
const MAX_MESSAGE: usize = 1 << 20;

/// Whether `request` asks to become a WebSocket
pub fn is_upgrade(request: &Request<Incoming>) -> bool {
    let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
    request.method() == hyper::Method::GET
        && request.version() == hyper::Version::HTTP_11
        && header("upgrade").eq_ignore_ascii_case("websocket")
        && header("connection").split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        && !header("sec-websocket-key").is_empty()
}

/// Answers an upgrade request: the daemon may refuse it, else 101 and the WebSocket session
/// runs on its own
pub async fn accept(mut request: Request<Incoming>, session: &mut Session) -> Response<Full<Bytes>> {
    let defaults = session.ctx.defaults.http.clone();
    let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let key = header("sec-websocket-key");
    let protocols: Vec<String> = header("sec-websocket-protocol").split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    let path = request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".into());
    let host = header("host");
    let line = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n\r\n");
    session.client_data(line.as_bytes());
    let meta = json!({ "method": "GET", "path": path, "host": host, "websocket": true, "protocols": protocols, "headers": { "user-agent": header("user-agent"), "origin": header("origin") } });
    if let Some(response) = session.decide(line.as_bytes(), meta).await.and_then(|a| a.response) {
        return crate::http::from_raw(&response, &defaults.server_header, true);
    }
    let upgrade = hyper::upgrade::on(&mut request);
    let mut child = Session::new(session.ctx.clone(), &session.listener, fakenet_schema::Protocol::Websocket, fakenet_schema::Transport::Tcp, session.builder.src, session.local, None);
    child.builder.dst = session.builder.dst;
    child.builder.tls = session.builder.tls;
    child.builder.process = session.builder.process.clone();
    child.log("websocket_open", json!({ "parent_session": session.builder.session_id, "path": path, "host": host, "protocols": protocols }));
    tokio::spawn(async move {
        let stream = crate::http::PendingUpgrade::new(upgrade);
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let socket = WebSocketStream::from_raw_socket(stream, Role::Server, Some(config)).await;
        if let Err(e) = run(socket, child, path).await {
            tracing::debug!("websocket: {e:#}");
        }
    });
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-accept", tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes()));
    if let Some(protocol) = protocols.first() {
        response = response.header("sec-websocket-protocol", protocol);
    }
    response.body(Full::new(Bytes::new())).unwrap_or_default()
}

async fn run<S>(mut socket: WebSocketStream<S>, mut session: Session, path: String) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    while let Some(message) = tokio::time::timeout(session.ctx.timeout * 4, socket.next()).await.ok().flatten() {
        let (kind, data) = match message? {
            Message::Text(text) => ("text", text.as_bytes().to_vec()),
            Message::Binary(data) => ("binary", data.to_vec()),
            // Polling on sends tungstenite's close reply, then the stream ends; pings are
            // answered the same way
            _ => continue,
        };
        session.client_data(&data);
        let meta = json!({ "path": path, "opcode": kind, "message": preview(&data, 512), "message_bytes": data.len() });
        session.log("websocket_message", meta.clone());
        let (response, close) = session.answer(&data, meta, Vec::new(), false).await;
        if !response.is_empty() {
            session.server_data(&response);
            let reply = match String::from_utf8(response) {
                Ok(text) => Message::text(text),
                Err(e) => Message::binary(e.into_bytes()),
            };
            socket.send(reply).await?;
        }
        if close {
            let _ = socket.close(None).await;
            break;
        }
    }
    Ok(())
}
