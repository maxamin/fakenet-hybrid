//! Asks the Camel daemon how to answer an event, within a deadline, never failing: on any
//! problem the caller gets a `Fallback` with the reason, and uses its built-in default.
//!
//! - Primary: one long-lived WebSocket (tokio-tungstenite), carrying many requests at once,
//!   matched to their Actions by `request_id`. Reconnects with exponential backoff + jitter.
//! - Secondary: one-shot HTTP POST (reqwest), used while the WebSocket is down.
//!
//! With a shared secret, the link authenticates both ways (see `fakenet_schema::auth`):
//! each WebSocket connection starts with a challenge the daemon must sign before any event
//! is sent on it, events are signed, and unsigned or forged Actions are rejected (falling
//! back to the default). This stops a local process that grabs the daemon's port from
//! steering the nucleus or reading its events.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fakenet_schema::auth::{self, Secret};
use fakenet_schema::{Action, Event, Hello, HelloKind, VERSION};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// e.g. ws://127.0.0.1:8090/link; None disables the WebSocket channel
    pub websocket_url: Option<String>,
    /// e.g. http://127.0.0.1:8091/decide; None disables the HTTP channel
    pub http_url: Option<String>,
    /// How long a listener waits for a decision before using its default
    pub deadline: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// Shared with the daemon; None = unauthenticated link
    pub secret: Option<Secret>,
}

impl Default for LinkConfig {
    fn default() -> Self {
        LinkConfig {
            websocket_url: None,
            http_url: None,
            deadline: Duration::from_millis(200),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_secs(10),
            secret: None,
        }
    }
}

/// Why a listener used its built-in default instead of a daemon decision
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", content = "detail", rename_all = "snake_case")]
pub enum Fallback {
    /// No channel is configured
    Disabled,
    /// Configured, but neither channel is available right now
    Unavailable,
    /// No decision within the deadline
    Timeout,
    /// The channel failed (connection dropped, HTTP error...)
    Error(String),
    /// An answer arrived, but it isn't a valid Action for this event
    Invalid(String),
}

#[derive(Debug, Clone)]
pub enum Decision {
    Action(Action),
    Fallback(Fallback),
}

#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub websocket_configured: bool,
    pub websocket_connected: bool,
    pub http_configured: bool,
    pub decisions: u64,
    pub fallbacks: u64,
    pub reconnects: u64,
}

type Pending = Arc<Mutex<HashMap<String, oneshot::Sender<Result<Action, String>>>>>;

struct Inner {
    config: LinkConfig,
    sender: Mutex<Option<mpsc::Sender<Message>>>,
    connected: AtomicBool,
    pending: Pending,
    http: reqwest::Client,
    decisions: AtomicU64,
    fallbacks: AtomicU64,
    reconnects: AtomicU64,
}

#[derive(Clone)]
pub struct Link {
    inner: Arc<Inner>,
}

impl Link {
    /// Creates the link, and starts maintaining the WebSocket connection (if configured).
    /// Must be called within a tokio runtime.
    pub fn start(config: LinkConfig) -> Link {
        let http = reqwest::Client::builder()
            .no_proxy() // The daemon is always local: never route it via a proxy
            .build()
            .expect("HTTP client with default settings");
        let link = Link {
            inner: Arc::new(Inner {
                config,
                sender: Mutex::new(None),
                connected: AtomicBool::new(false),
                pending: Arc::new(Mutex::new(HashMap::new())),
                http,
                decisions: AtomicU64::new(0),
                fallbacks: AtomicU64::new(0),
                reconnects: AtomicU64::new(0),
            }),
        };
        if let Some(url) = link.inner.config.websocket_url.clone() {
            let weak = Arc::downgrade(&link.inner);
            tokio::spawn(maintain_websocket(weak, url));
        }
        link
    }

    pub fn deadline(&self) -> Duration {
        self.inner.config.deadline
    }

    /// Asks for a decision on `event`, within the deadline. Never fails: problems become
    /// `Decision::Fallback`.
    pub async fn decide(&self, event: &Event) -> Decision {
        let inner = &self.inner;
        if inner.config.websocket_url.is_none() && inner.config.http_url.is_none() {
            return self.fallback(Fallback::Disabled);
        }
        let result = match tokio::time::timeout(inner.config.deadline, self.ask(event)).await {
            Err(_) => {
                inner.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&event.request_id);
                Err(Fallback::Timeout)
            }
            Ok(result) => result,
        };
        let checked = result.and_then(|action| {
            action.validate_for(event).map_err(Fallback::Invalid)?;
            match &inner.config.secret {
                Some(secret) if !secret.verify(&auth::action_text(&action), action.auth.as_deref()) => {
                    Err(Fallback::Invalid("unsigned or forged action".into()))
                }
                _ => Ok(action),
            }
        });
        match checked {
            Ok(action) => {
                inner.decisions.fetch_add(1, Ordering::Relaxed);
                Decision::Action(action)
            }
            Err(reason) => self.fallback(reason),
        }
    }

    /// Sends an event that needs no answer (e.g. a closed connection), if connected
    pub fn notify(&self, event: &Event) {
        let sender = self.inner.sender.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let (Some(sender), Ok(json)) = (sender, serde_json::to_string(&self.signed(event))) {
            let _ = sender.try_send(Message::text(json));
        }
    }

    pub fn health(&self) -> Health {
        let inner = &self.inner;
        Health {
            websocket_configured: inner.config.websocket_url.is_some(),
            websocket_connected: inner.connected.load(Ordering::Relaxed),
            http_configured: inner.config.http_url.is_some(),
            decisions: inner.decisions.load(Ordering::Relaxed),
            fallbacks: inner.fallbacks.load(Ordering::Relaxed),
            reconnects: inner.reconnects.load(Ordering::Relaxed),
        }
    }

    fn signed(&self, event: &Event) -> Event {
        let mut event = event.clone();
        event.auth = self.inner.config.secret.as_ref().map(|s| s.sign(&auth::event_text(&event)));
        event
    }

    fn fallback(&self, reason: Fallback) -> Decision {
        self.inner.fallbacks.fetch_add(1, Ordering::Relaxed);
        Decision::Fallback(reason)
    }

    async fn ask(&self, event: &Event) -> Result<Action, Fallback> {
        let inner = &self.inner;
        let json = serde_json::to_string(&self.signed(event)).map_err(|e| Fallback::Error(e.to_string()))?;

        let sender = inner.sender.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(sender) = sender {
            let (reply_tx, reply_rx) = oneshot::channel();
            inner.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(event.request_id.clone(), reply_tx);
            if sender.send(Message::text(json.clone())).await.is_ok() {
                return match reply_rx.await {
                    Ok(Ok(action)) => Ok(action),
                    Ok(Err(error)) => Err(Fallback::Error(error)),
                    Err(_) => Err(Fallback::Error("websocket closed while waiting".into())),
                };
            }
            inner.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&event.request_id);
        }

        match &inner.config.http_url {
            Some(url) => {
                let response = inner.http
                    .post(url)
                    .header("content-type", "application/json")
                    .body(json)
                    .send()
                    .await
                    .map_err(|e| Fallback::Error(format!("http: {e}")))?;
                if !response.status().is_success() {
                    return Err(Fallback::Error(format!("http status {}", response.status())));
                }
                let body = response.bytes().await.map_err(|e| Fallback::Error(format!("http: {e}")))?;
                serde_json::from_slice(&body).map_err(|e| Fallback::Invalid(format!("not an Action: {e}")))
            }
            None => Err(Fallback::Unavailable),
        }
    }
}

/// Sends a fresh challenge and waits for the daemon's signed answer. Nothing else is
/// sent on a connection until this succeeds.
async fn handshake<Si, St>(secret: &Secret, sink: &mut Si, stream: &mut St) -> Result<(), String>
where
    Si: futures_util::Sink<Message> + Unpin,
    St: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let nonce = auth::random_hex(16);
    let hello = Hello { version: VERSION, kind: HelloKind::Hello, nonce: nonce.clone(), auth: None };
    let json = serde_json::to_string(&hello).map_err(|e| e.to_string())?;
    sink.send(Message::text(json)).await.map_err(|_| "send failed".to_string())?;
    let reply = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(text))) => return serde_json::from_str::<Hello>(text.as_str()).map_err(|e| format!("not a hello: {e}")),
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return Err("closed during handshake".to_string()),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .map_err(|_| "no handshake answer".to_string())??;
    if reply.nonce != nonce || !secret.verify(&auth::hello_text(&nonce), reply.auth.as_deref()) {
        return Err("bad handshake signature".into());
    }
    Ok(())
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// Keeps the WebSocket connected for as long as the Link exists, reconnecting with
/// exponential backoff (with jitter, so many nuclei don't reconnect in lockstep)
async fn maintain_websocket(inner: std::sync::Weak<Inner>, url: String) {
    let mut backoff = match inner.upgrade() {
        Some(i) => i.config.backoff_initial,
        None => return,
    };
    let mut first = true;
    loop {
        let Some(link) = inner.upgrade() else { return };
        let connect = tokio::time::timeout(Duration::from_secs(5), tokio_tungstenite::connect_async(url.as_str())).await;
        match connect {
            Ok(Ok((socket, _))) => {
                if !first {
                    link.reconnects.fetch_add(1, Ordering::Relaxed);
                }
                first = false;
                backoff = link.config.backoff_initial;
                tracing::info!("Connected to the daemon at {url}");
                run_connection(&link, socket).await;
                tracing::warn!("Disconnected from the daemon at {url}");
            }
            Ok(Err(e)) => tracing::debug!("Daemon WebSocket connection failed: {e}"),
            Err(_) => tracing::debug!("Daemon WebSocket connection timed out"),
        }
        let max = link.config.backoff_max;
        drop(link);
        let jitter = Duration::from_millis(u64::from(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_millis()).unwrap_or(0)) % 100);
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(max);
    }
}

async fn run_connection<S>(link: &Inner, socket: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = socket.split();
    if let Some(secret) = &link.config.secret {
        if let Err(e) = handshake(secret, &mut sink, &mut stream).await {
            tracing::warn!("Daemon failed authentication, disconnecting: {e}");
            let _ = sink.close().await;
            return;
        }
    }
    let (tx, mut rx) = mpsc::channel::<Message>(1024);
    *link.sender.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());
    link.connected.store(true, Ordering::Relaxed);

    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    while let Some(message) = stream.next().await {
        match message {
            Ok(Message::Text(text)) => match serde_json::from_str::<Action>(text.as_str()) {
                Ok(action) => {
                    let waiter = link.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&action.request_id);
                    match waiter {
                        Some(waiter) => {
                            let _ = waiter.send(Ok(action));
                        }
                        // Usually: answered after its deadline. Harmless.
                        None => tracing::debug!("Action for unknown or expired request {}", action.request_id),
                    }
                }
                Err(e) => tracing::warn!("Ignoring an invalid message from the daemon: {e}"),
            },
            Ok(Message::Ping(data)) => {
                let _ = tx.try_send(Message::Pong(data));
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }

    link.connected.store(false, Ordering::Relaxed);
    *link.sender.lock().unwrap_or_else(|e| e.into_inner()) = None;
    drop(tx);
    writer.abort();
    // Fail everything still waiting now, rather than at each one's deadline
    for (_, waiter) in link.pending.lock().unwrap_or_else(|e| e.into_inner()).drain() {
        let _ = waiter.send(Err("websocket disconnected".into()));
    }
}
