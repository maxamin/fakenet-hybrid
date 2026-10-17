//! The listeners end to end: real clients against the nucleus, with no daemon (fallback),
//! a fake daemon that decides, and a daemon too slow for the deadline.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{fake_daemon, listener, stopped_daemon, wait_connected, Nucleus};
use fakenet_link::LinkConfig;
use fakenet_listeners::ListenerConfig;
use fakenet_schema::{Event, Protocol, Transport};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const LISTENERS: fn() -> Vec<ListenerConfig> = || vec![
    listener("http", Some(Protocol::Http), Transport::Tcp, false),
    listener("https", Some(Protocol::Http), Transport::Tcp, true),
    listener("dns", Some(Protocol::Dns), Transport::Udp, false),
    listener("dns-tcp", Some(Protocol::Dns), Transport::Tcp, false),
    listener("raw", Some(Protocol::Raw), Transport::Tcp, false),
    listener("auto", None, Transport::Tcp, false),
    listener("raw-udp", None, Transport::Udp, false),
];

async fn http_exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await.unwrap().unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

async fn http_get(address: SocketAddr, path: &str) -> String {
    let stream = TcpStream::connect(address).await.unwrap();
    http_exchange(stream, &format!("GET {path} HTTP/1.1\r\nHost: c2.example\r\nConnection: close\r\n\r\n")).await
}

fn dns_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut query = Message::new(0x1234, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    query.to_vec().unwrap()
}

async fn dns_udp(address: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&dns_query(name, qtype), address).await.unwrap();
    let mut buffer = [0u8; 4096];
    let length = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer)).await.unwrap().unwrap();
    Message::from_vec(&buffer[..length]).unwrap()
}

fn first_a(message: &Message) -> String {
    match &message.answers[0].data {
        RData::A(a) => a.0.to_string(),
        other => panic!("not an A record: {other:?}"),
    }
}

async fn raw_exchange(address: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(data).await.unwrap();
    let mut buffer = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await.unwrap().unwrap();
    buffer.truncate(read);
    buffer
}

#[tokio::test]
async fn falls_back_to_defaults_when_the_daemon_is_stopped() {
    let nucleus = Nucleus::start("fallback", stopped_daemon(), &LISTENERS()).await;
    let started = Instant::now();

    let page = http_get(nucleus.address("http"), "/index.html").await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    assert!(page.contains("<h1>FakeNet</h1>"));
    assert!(page.to_ascii_lowercase().contains("server: microsoft-iis/10.0"));

    let dns = dns_udp(nucleus.address("dns"), "evil.example.", RecordType::A).await;
    assert_eq!(dns.metadata.id, 0x1234);
    assert_eq!(first_a(&dns), "192.0.2.123");

    assert_eq!(raw_exchange(nucleus.address("raw"), b"\x01\x02beacon").await, b"\x01\x02beacon");

    // A stopped daemon fails fast: no waiting out the deadline
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());

    let fallbacks = nucleus.kinds("fallback");
    assert_eq!(fallbacks.len(), 3, "{fallbacks:#?}");
    assert!(fallbacks.iter().all(|f| f["fallback"]["reason"] == "unavailable"), "{fallbacks:#?}");
    let events = nucleus.kinds("event");
    let protocols: Vec<_> = events.iter().map(|e| e["protocol"].as_str().unwrap()).collect();
    assert_eq!(protocols, ["http", "dns", "raw"]);
    let dns_event = &events[1];
    assert_eq!(dns_event["meta"]["qname"], "evil.example");
    assert_eq!(dns_event["meta"]["qtype"], "A");
}

#[tokio::test]
async fn auto_listener_sniffs_and_unwraps_tls() {
    let nucleus = Nucleus::start("auto", LinkConfig::default(), &LISTENERS()).await;
    let auto = nucleus.address("auto");

    // HTTP on a port that isn't HTTP's
    let page = http_get(auto, "/x.txt").await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    assert!(page.to_ascii_lowercase().contains("content-type: text/plain"));

    // HTTPS to the same port, with a certificate minted for the SNI
    let connector = nucleus.tls_connector();
    let tcp = TcpStream::connect(auto).await.unwrap();
    let tls = connector.connect("c2.example".try_into().unwrap(), tcp).await.unwrap();
    let page = http_exchange(tls, "GET / HTTP/1.1\r\nHost: c2.example\r\nConnection: close\r\n\r\n").await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");

    // Unrecognized bytes get the raw catch-all
    assert_eq!(raw_exchange(auto, b"\xde\xad\xbe\xef").await, b"\xde\xad\xbe\xef");

    let detected: Vec<_> = nucleus.kinds("detected").iter().map(|d| (d["detected"].as_str().unwrap().to_string(), d["tls"].as_bool().unwrap())).collect();
    assert_eq!(detected, [("http".to_string(), false), ("http".to_string(), true), ("raw".to_string(), false)]);
    let handshake = nucleus.kinds("tls_handshake");
    assert_eq!(handshake[0]["sni"], "c2.example");

    // DNS over TCP on its fixed listener
    let mut stream = TcpStream::connect(nucleus.address("dns-tcp")).await.unwrap();
    let query = dns_query("tcp.example.", RecordType::A);
    stream.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
    stream.write_all(&query).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut reply = vec![0u8; length as usize];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(first_a(&Message::from_vec(&reply).unwrap()), "192.0.2.123");
}

#[tokio::test]
async fn saves_post_bodies_and_writes_the_pcap() {
    let nucleus = Nucleus::start("post", LinkConfig::default(), &LISTENERS()).await;
    let stream = TcpStream::connect(nucleus.address("http")).await.unwrap();
    let body = "exfil=secret-data";
    let response = http_exchange(stream, &format!(
        "POST /upload.php HTTP/1.1\r\nHost: c2.example\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
    )).await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let event = &nucleus.kinds("event")[0];
    let saved = event["meta"]["saved_body"].as_str().unwrap();
    assert_eq!(std::fs::read_to_string(saved).unwrap(), body);
    assert!(std::fs::metadata(nucleus.dir.join("traffic.pcap")).unwrap().len() > 24);
    // The link is disabled here: that's a fallback too, recorded as such
    assert_eq!(nucleus.kinds("fallback")[0]["fallback"]["reason"], "disabled");
}

/// Answers per protocol like the Camel routes do
fn camel_like(event: &Event) -> Option<(Vec<u8>, bool)> {
    Some(match event.protocol {
        Protocol::Http => (b"HTTP/1.1 418 I'm a teapot\r\nX-C2: yes\r\n\r\ntask=sleep".to_vec(), false),
        Protocol::Dns => (b"A 10.6.6.6".to_vec(), false),
        _ => (b"PONG\n".to_vec(), true),
    })
}

#[tokio::test]
async fn uses_the_daemons_decisions() {
    let nucleus = Nucleus::start("daemon", fake_daemon(Duration::ZERO, camel_like).await, &LISTENERS()).await;
    wait_connected().await;

    let page = http_get(nucleus.address("http"), "/gate.php").await;
    assert!(page.starts_with("HTTP/1.1 418"), "{page}");
    assert!(page.contains("x-c2: yes") || page.contains("X-C2: yes"));
    assert!(page.ends_with("task=sleep"));

    assert_eq!(first_a(&dns_udp(nucleus.address("dns"), "c2.example.", RecordType::A).await), "10.6.6.6");

    // The daemon replies then closes
    let mut stream = TcpStream::connect(nucleus.address("raw")).await.unwrap();
    stream.write_all(b"PING\n").await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut reply)).await.unwrap().unwrap();
    assert_eq!(reply, b"PONG\n");

    let routes: Vec<_> = nucleus.kinds("decision").iter().map(|d| d["route"].as_str().unwrap().to_string()).collect();
    assert_eq!(routes, ["fake-http", "fake-dns", "fake-raw"]);
    assert!(nucleus.kinds("fallback").is_empty());
}

#[tokio::test]
async fn a_slow_daemon_misses_the_deadline_and_defaults_apply() {
    let nucleus = Nucleus::start("slow", fake_daemon(Duration::from_secs(2), camel_like).await, &LISTENERS()).await;
    wait_connected().await;

    let started = Instant::now();
    let dns = dns_udp(nucleus.address("dns"), "late.example.", RecordType::A).await;
    let elapsed = started.elapsed();
    assert_eq!(first_a(&dns), "192.0.2.123");
    assert!(elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(nucleus.kinds("fallback")[0]["fallback"]["reason"], "timeout");

    // Other query types get their configured defaults too
    let mx = dns_udp(nucleus.address("dns"), "late.example.", RecordType::MX).await;
    assert_eq!(mx.metadata.response_code, ResponseCode::NoError);
    assert_eq!(mx.answers.len(), 1);
}

#[tokio::test]
async fn raw_udp_echoes_by_default() {
    let nucleus = Nucleus::start("udp", LinkConfig::default(), &LISTENERS()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"\x00hello", nucleus.address("raw-udp")).await.unwrap();
    let mut buffer = [0u8; 64];
    let length = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(&buffer[..length], b"\x00hello");
}

/// Reads until the nucleus answers or closes: Some(answer), or None when it was refused
async fn echoed(stream: &mut TcpStream, data: &[u8]) -> Option<Vec<u8>> {
    let _ = stream.write_all(data).await;
    let mut buffer = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await.expect("neither answered nor closed") {
        Ok(0) | Err(_) => None,
        Ok(read) => Some(buffer[..read].to_vec()),
    }
}

#[tokio::test]
async fn max_sessions_drops_new_connections_until_one_ends() {
    let limits = fakenet_listeners::LimitsConfig { max_sessions: 2, ..Default::default() };
    let nucleus = Nucleus::start_full("max-sessions", LinkConfig::default(), &LISTENERS(), Default::default(), None, limits).await;
    let raw = nucleus.address("raw");
    let mut first = TcpStream::connect(raw).await.unwrap();
    let mut second = TcpStream::connect(raw).await.unwrap();
    assert_eq!(echoed(&mut first, b"one").await.unwrap(), b"one");
    assert_eq!(echoed(&mut second, b"two").await.unwrap(), b"two");
    let mut third = TcpStream::connect(raw).await.unwrap();
    assert_eq!(echoed(&mut third, b"three").await, None);
    // The sessions already open keep working
    assert_eq!(echoed(&mut first, b"again").await.unwrap(), b"again");
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut fourth = TcpStream::connect(raw).await.unwrap();
    assert_eq!(echoed(&mut fourth, b"four").await.unwrap(), b"four");
}

#[tokio::test]
async fn per_source_rate_limits_new_sessions() {
    let limits = fakenet_listeners::LimitsConfig { per_source_per_second: 0.01, per_source_burst: 2, ..Default::default() };
    let nucleus = Nucleus::start_full("rate", LinkConfig::default(), &LISTENERS(), Default::default(), None, limits).await;
    assert_eq!(raw_exchange(nucleus.address("raw"), b"a").await, b"a");
    assert_eq!(raw_exchange(nucleus.address("raw"), b"b").await, b"b");
    let mut third = TcpStream::connect(nucleus.address("raw")).await.unwrap();
    assert_eq!(echoed(&mut third, b"c").await, None);
    // UDP clients count as sessions too
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"\x00udp", nucleus.address("raw-udp")).await.unwrap();
    let mut buffer = [0u8; 16];
    assert!(tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buffer)).await.is_err());
}

#[tokio::test]
async fn memory_budget_refuses_oversized_payloads() {
    let limits = fakenet_listeners::LimitsConfig { memory_budget_mb: 1, ..Default::default() };
    let nucleus = Nucleus::start_full("memory", LinkConfig::default(), &LISTENERS(), Default::default(), None, limits).await;
    let body = vec![b'x'; 2 << 20];
    let mut stream = TcpStream::connect(nucleus.address("http")).await.unwrap();
    let head = format!("POST /upload HTTP/1.1\r\nHost: c2.example\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(head.as_bytes()).await.unwrap();
    let _ = stream.write_all(&body).await; // The nucleus may close before it's all sent
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413"), "{}", String::from_utf8_lossy(&response));
    let bad = nucleus.kinds("bad_request");
    assert!(bad[0]["error"].as_str().unwrap().contains("memory budget"), "{bad:?}");
    // The budget is released: a small request still works
    assert!(http_get(nucleus.address("http"), "/small.txt").await.starts_with("HTTP/1.1 200"));
}
