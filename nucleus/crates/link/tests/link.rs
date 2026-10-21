//! The link against fake daemons (a real WebSocket server & a real HTTP server)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fakenet_link::{Decision, Fallback, Link, LinkConfig};
use fakenet_schema::{Action, ActionKind, Event, EventBuilder, Protocol, Transport, VERSION};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

fn event() -> Event {
    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1234".parse().unwrap(), "1.2.3.4:4444".parse().unwrap());
    builder.event(b"hello".to_vec(), serde_json::json!({}), true)
}

fn answer(event: &Event, response: &[u8]) -> Action {
    Action {
        version: VERSION,
        kind: ActionKind::Action,
        request_id: event.request_id.clone(),
        session_id: event.session_id.clone(),
        response: Some(response.to_vec()),
        close: false,
        delay_ms: None,
        auth: None,
        route: Some("test".into()),
    }
}

/// A fake daemon: a WebSocket server answering each event with its payload uppercased,
/// after `delay` (shuffling order across concurrent requests)
async fn websocket_daemon(delay: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        // Connections live in this set, so aborting the daemon drops them all, like a crash
        let mut connections = tokio::task::JoinSet::new();
        while let Ok((stream, _)) = listener.accept().await {
            connections.spawn(async move {
                let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let (sink, mut stream) = socket.split();
                let sink = Arc::new(tokio::sync::Mutex::new(sink));
                let mut replies = tokio::task::JoinSet::new();
                while let Some(Ok(Message::Text(text))) = stream.next().await {
                    let event: Event = serde_json::from_str(text.as_str()).unwrap();
                    let sink = sink.clone();
                    replies.spawn(async move {
                        // Later sequence numbers answer sooner: replies arrive out of order
                        tokio::time::sleep(delay / (event.payload.len() as u32 + 1)).await;
                        let reply = answer(&event, &event.payload.to_ascii_uppercase());
                        let _ = sink.lock().await.send(Message::text(serde_json::to_string(&reply).unwrap())).await;
                    });
                }
            });
        }
    });
    (address, task)
}

/// A fake daemon's one-shot HTTP endpoint (counts its calls)
async fn http_daemon(calls: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let calls = calls.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                // Read the headers & the Content-Length body
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length: usize = headers.lines().find_map(|l| l.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                        while request.len() < end + 4 + length {
                            let read = stream.read(&mut buffer).await.unwrap();
                            request.extend_from_slice(&buffer[..read]);
                        }
                        let event: Event = serde_json::from_slice(&request[end + 4..]).unwrap();
                        calls.fetch_add(1, Ordering::SeqCst);
                        let body = serde_json::to_string(&answer(&event, b"via http")).unwrap();
                        let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        stream.write_all(reply.as_bytes()).await.unwrap();
                        return;
                    }
                }
            });
        }
    });
    address
}

fn config(websocket: Option<SocketAddr>, http: Option<SocketAddr>, deadline_ms: u64) -> LinkConfig {
    LinkConfig {
        websocket_url: websocket.map(|a| format!("ws://{a}/link")),
        http_url: http.map(|a| format!("http://{a}/decide")),
        deadline: Duration::from_millis(deadline_ms),
        backoff_initial: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        secret: None,
        max_payload: 1024 * 1024,
    }
}

async fn until_connected(link: &Link) {
    for _ in 0..200 {
        if link.health().websocket_connected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never connected");
}

fn response(decision: Decision) -> Vec<u8> {
    match decision {
        Decision::Action(action) => action.response.unwrap(),
        Decision::Fallback(f) => panic!("fallback: {f:?}"),
    }
}

#[tokio::test]
async fn correlates_concurrent_requests_over_one_websocket() {
    let (address, _daemon) = websocket_daemon(Duration::from_millis(80)).await;
    let link = Link::start(config(Some(address), None, 2000));
    until_connected(&link).await;

    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1".parse().unwrap(), "1.2.3.4:2".parse().unwrap());
    let events: Vec<Event> = ["a", "bb", "ccc", "dddd", "eeeee"].iter().map(|p| builder.event(p.as_bytes().to_vec(), serde_json::json!({}), true)).collect();
    let decisions = futures_util::future::join_all(events.iter().map(|e| link.decide(e))).await;
    let responses: Vec<Vec<u8>> = decisions.into_iter().map(response).collect();
    assert_eq!(responses, vec![b"A".to_vec(), b"BB".to_vec(), b"CCC".to_vec(), b"DDDD".to_vec(), b"EEEEE".to_vec()]);
    assert_eq!(link.health().decisions, 5);
}

#[tokio::test]
async fn falls_back_within_the_deadline_when_the_daemon_is_slow() {
    let (address, _daemon) = websocket_daemon(Duration::from_secs(5)).await;
    let link = Link::start(config(Some(address), None, 200));
    until_connected(&link).await;

    let start = Instant::now();
    let decision = link.decide(&event()).await;
    let elapsed = start.elapsed();
    assert!(matches!(decision, Decision::Fallback(Fallback::Timeout)), "{decision:?}");
    assert!(elapsed >= Duration::from_millis(190) && elapsed < Duration::from_millis(600), "{elapsed:?}");
    assert_eq!(link.health().fallbacks, 1);
}

#[tokio::test]
async fn falls_back_immediately_when_the_daemon_is_down() {
    // Nothing listens on these ports
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let link = Link::start(config(Some(free), Some(free), 200));
    let start = Instant::now();
    let decision = link.decide(&event()).await;
    assert!(matches!(decision, Decision::Fallback(Fallback::Error(_))), "{decision:?}");
    assert!(start.elapsed() < Duration::from_millis(200), "refused connections shouldn't wait out the deadline");

    let unconfigured = Link::start(LinkConfig::default());
    assert!(matches!(unconfigured.decide(&event()).await, Decision::Fallback(Fallback::Disabled)));
}

#[tokio::test]
async fn uses_http_while_the_websocket_is_down() {
    let calls = Arc::new(AtomicUsize::new(0));
    let http = http_daemon(calls.clone()).await;
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let link = Link::start(config(Some(free), Some(http), 2000));
    assert_eq!(response(link.decide(&event()).await), b"via http");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!link.health().websocket_connected);
}

#[tokio::test]
async fn reconnects_after_the_daemon_restarts() {
    let (address, daemon) = websocket_daemon(Duration::from_millis(1)).await;
    let link = Link::start(config(Some(address), None, 1000));
    until_connected(&link).await;
    assert_eq!(response(link.decide(&event()).await), b"HELLO");

    // Stop the daemon (dropping its listener & connections)
    daemon.abort();
    let _ = daemon.await;
    for _ in 0..200 {
        if !link.health().websocket_connected { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Meanwhile: fallbacks, quickly
    assert!(matches!(link.decide(&event()).await, Decision::Fallback(_)));

    // Restart on the same port: the link reconnects by itself
    let listener = TcpListener::bind(address).await.unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let event: Event = serde_json::from_str(text.as_str()).unwrap();
            socket.send(Message::text(serde_json::to_string(&answer(&event, b"back")).unwrap())).await.unwrap();
        }
    });
    until_connected(&link).await;
    assert_eq!(response(link.decide(&event()).await), b"back");
    assert!(link.health().reconnects >= 1);
}

#[tokio::test]
async fn rejects_actions_for_the_wrong_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            let event: Event = serde_json::from_str(text.as_str()).unwrap();
            // Right request_id, wrong session: must not be accepted
            let mut bad = answer(&event, b"x");
            bad.session_id = "someone-else".into();
            socket.send(Message::text(serde_json::to_string(&bad).unwrap())).await.unwrap();
        }
    });
    let link = Link::start(config(Some(address), None, 1000));
    until_connected(&link).await;
    assert!(matches!(link.decide(&event()).await, Decision::Fallback(Fallback::Invalid(_))));
}

/// A WebSocket daemon that answers the handshake with `key` (None: skips it) and signs
/// its actions with `key`
async fn authenticating_daemon(key: Option<&'static [u8]>) -> SocketAddr {
    use fakenet_schema::auth::{self, Secret};
    use fakenet_schema::Hello;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let secret = key.map(Secret::new);
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    if let Ok(mut hello) = serde_json::from_str::<Hello>(text.as_str()) {
                        if let Some(secret) = &secret {
                            hello.auth = Some(secret.sign(&auth::hello_text(&hello.nonce)));
                            socket.send(Message::text(serde_json::to_string(&hello).unwrap())).await.unwrap();
                        }
                        continue;
                    }
                    let event: Event = serde_json::from_str(text.as_str()).unwrap();
                    let mut action = answer(&event, b"signed");
                    action.auth = secret.as_ref().map(|s| s.sign(&auth::action_text(&action)));
                    socket.send(Message::text(serde_json::to_string(&action).unwrap())).await.unwrap();
                }
            });
        }
    });
    address
}

fn authenticated(address: SocketAddr) -> LinkConfig {
    LinkConfig { secret: Some(fakenet_schema::auth::Secret::new(b"lab-secret")), ..config(Some(address), None, 500) }
}

#[tokio::test]
async fn authenticates_the_daemon_both_ways() {
    // The real daemon: handshake passes, signed decisions are used
    let link = Link::start(authenticated(authenticating_daemon(Some(b"lab-secret")).await));
    until_connected(&link).await;
    match link.decide(&event()).await {
        Decision::Action(action) => assert_eq!(action.response.as_deref(), Some(&b"signed"[..])),
        other => panic!("{other:?}"),
    }

    // An impostor with the wrong key never becomes the link's daemon
    let link = Link::start(authenticated(authenticating_daemon(Some(b"guessed")).await));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!link.health().websocket_connected);
    assert!(matches!(link.decide(&event()).await, Decision::Fallback(Fallback::Unavailable)));
}

#[tokio::test]
async fn rejects_unsigned_actions() {
    // Unsigned actions are fine on an unauthenticated link...
    let address = authenticating_daemon(None).await;
    let open = Link::start(config(Some(address), None, 500));
    until_connected(&open).await;
    assert!(matches!(open.decide(&event()).await, Decision::Action(_)));
    // ...but with a secret they're rejected (HTTP channel: no handshake to fail first)

    let strict = Link::start(LinkConfig { secret: Some(fakenet_schema::auth::Secret::new(b"lab-secret")), ..config(None, Some(http_daemon_unsigned().await), 500) });
    match strict.decide(&event()).await {
        Decision::Fallback(Fallback::Invalid(reason)) => assert!(reason.contains("unsigned"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

/// An HTTP daemon that answers every event with an unsigned action
async fn http_daemon_unsigned() -> SocketAddr {
    http_daemon(Arc::new(AtomicUsize::new(0))).await
}

#[test]
fn signatures_cover_the_response() {
    use fakenet_schema::auth::{action_text, Secret};
    let secret = Secret::new(b"k");
    let mut action = answer(&event(), b"one");
    let signature = secret.sign(&action_text(&action));
    assert!(secret.verify(&action_text(&action), Some(&signature)));
    action.response = Some(b"two".to_vec());
    assert!(!secret.verify(&action_text(&action), Some(&signature)));
    assert!(!secret.verify(&action_text(&action), Some("zz")));
    assert!(!secret.verify(&action_text(&action), None));
}
