//! The nucleus against the real Camel daemon (daemon/target/fakenet-daemon.jar):
//! scripted decisions over both channels, hot reload, fallback while the daemon is
//! stopped, and reconnection when it comes back.
//!
//! Needs Java 21 (JAVA_HOME or `java` on PATH) and the daemon built (`mvn package` in
//! daemon/). Run with: cargo test -p fakenet-cli --test camel_link -- --ignored

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fakenet_capture::Capture;
use fakenet_link::{Decision, Fallback, Link, LinkConfig};
use fakenet_listeners::config::ListenerProtocol;
use fakenet_listeners::{Context, Defaults, ListenerConfig, Server, TlsAuthority};
use fakenet_schema::{EventBuilder, Protocol, Transport};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const DAEMON_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../daemon");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Daemon {
    child: Child,
    work: PathBuf,
}

impl Daemon {
    /// Starts the daemon in `work` (holding its routes/ & audit/) and waits until it's healthy
    async fn start(work: &Path, ports: (u16, u16, u16)) -> Daemon {
        let java = std::env::var_os("JAVA_HOME")
            .map(|home| PathBuf::from(home).join("bin").join(format!("java{}", std::env::consts::EXE_SUFFIX)))
            .unwrap_or_else(|| "java".into());
        let jar = Path::new(DAEMON_DIR).join("target/fakenet-daemon.jar");
        assert!(jar.exists(), "build the daemon first: (cd daemon && mvn package)");
        let child = Command::new(java)
            .arg(format!("-Dfakenet.link.secret-file={}", work.join("link.secret").display()))
            .arg(format!("-Dfakenet.link.port={}", ports.0))
            .arg(format!("-Dcamel.server.port={}", ports.1))
            .arg(format!("-Dcamel.management.port={}", ports.2))
            .arg("-jar")
            .arg(jar)
            .current_dir(work)
            .stdout(Stdio::from(std::fs::File::create(work.join("daemon.log")).unwrap()))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("starting java");
        let daemon = Daemon { child, work: work.to_path_buf() };
        let deadline = Instant::now() + Duration::from_secs(90);
        while !health_up(ports.2).await {
            assert!(Instant::now() < deadline, "daemon never became healthy; see {}/daemon.log", work.display());
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        daemon
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.work.join("daemon.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill(); // SIGKILL: as abrupt as a crash
        let _ = self.child.wait();
    }
}

async fn health_up(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)).await else { return false };
    let request = "GET /observe/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response)).await;
    response.starts_with("HTTP/1.1 200") && response.contains("\"UP\"")
}

async fn wait_for(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn listener(name: &str, protocol: Protocol, transport: Transport) -> ListenerConfig {
    ListenerConfig { name: name.into(), protocol: ListenerProtocol::Fixed(protocol), transport, ..ListenerConfig::default() }
}

async fn http_get(address: SocketAddr, host: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response)).await.unwrap().unwrap();
    response
}

async fn dns(address: SocketAddr, name: &str) -> Message {
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&query.to_vec().unwrap(), address).await.unwrap();
    let mut buffer = [0u8; 4096];
    let length = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer)).await.unwrap().unwrap();
    Message::from_vec(&buffer[..length]).unwrap()
}

fn a_record(message: &Message) -> String {
    match &message.answers[0].data {
        RData::A(a) => a.0.to_string(),
        other => panic!("{other:?}"),
    }
}

/// Sends one raw TCP message and reads until the server closes (or 1 s of silence)
async fn raw(address: SocketAddr, data: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(data).await.unwrap();
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    while let Ok(Ok(read)) = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
#[ignore = "needs Java 21 and the daemon jar (see the module docs)"]
async fn nucleus_and_camel_daemon() {
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("camel-link");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(work.join("routes")).unwrap();
    for file in ["link.yaml", "decisions.yaml"] {
        std::fs::copy(Path::new(DAEMON_DIR).join("routes").join(file), work.join("routes").join(file)).unwrap();
    }
    let ports = (free_port(), free_port(), free_port());
    fakenet_cli::generate_secret(&work.join("link.secret")).unwrap();
    let secret = std::fs::read_to_string(work.join("link.secret")).unwrap().trim().to_string();
    let signed = || Some(fakenet_schema::auth::Secret::new(secret.as_bytes()));
    let mut daemon = Some(Daemon::start(&work, ports).await);

    // This test checks behaviour, not latency (the listeners' tests cover the deadline), so
    // it allows more than the 200 ms default: a JVM on a busy CI machine can miss that
    let deadline = Duration::from_secs(2);
    let link = Link::start(LinkConfig {
        websocket_url: Some(format!("ws://127.0.0.1:{}/link", ports.0)),
        deadline,
        backoff_max: Duration::from_millis(500),
        secret: signed(),
        ..LinkConfig::default()
    });
    let ctx = Arc::new(Context {
        link: link.clone(),
        capture: Capture::open(&work.join("capture")).unwrap(),
        defaults: Defaults::default(),
        tls: Arc::new(TlsAuthority::generate().unwrap()),
        timeout: Duration::from_secs(5),
        first_data_timeout: Duration::from_millis(300),
        original: None,
        explorer: None,
        limits: Default::default(),
    });
    let server = Server::start(ctx, "127.0.0.1".parse().unwrap(), &[
        listener("http", Protocol::Http, Transport::Tcp),
        listener("dns", Protocol::Dns, Transport::Udp),
        listener("raw", Protocol::Raw, Transport::Tcp),
    ]).await.unwrap();
    let (http_addr, dns_addr, raw_addr) = (server.address("http").unwrap(), server.address("dns").unwrap(), server.address("raw").unwrap());
    wait_for("the WebSocket link", || link.health().websocket_connected).await;

    // Scripted HTTP (Groovy), templated HTTP (Simple), and the default for anything else
    let gate = http_get(http_addr, "c2.example", "/gate.php?id=1").await;
    assert!(gate.starts_with("HTTP/1.1 200 OK"), "{gate}");
    assert!(gate.contains("x-powered-by: PHP/7.4.3"), "{gate}");
    assert!(gate.contains("task=sleep;interval=3600"), "{gate}");
    let update = http_get(http_addr, "cdn.update.example.com", "/check").await;
    assert!(update.ends_with(r#"{"version":"9.9.9","url":"http://cdn.update.example.com/patch.exe"}"#), "{update}");
    assert!(http_get(http_addr, "other.example", "/").await.contains("<h1>FakeNet</h1>"));

    // DNS through the Content-Based Router
    assert_eq!(a_record(&dns(dns_addr, "beacon.c2.example.").await), "10.6.6.6");
    assert_eq!(dns(dns_addr, "killswitch.example.").await.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(a_record(&dns(dns_addr, "benign.example.").await), "192.0.2.123");

    // Scripted raw TCP (Groovy): reply, then the daemon's close flag ends the connection
    let welcome = raw(raw_addr, b"HELLO bot42\n").await;
    assert!(welcome.starts_with("WELCOME bot42 KEY=") && welcome.ends_with("CMD sysinfo\n"), "{welcome}");
    assert_eq!(raw(raw_addr, b"PING\n").await, "PONG\n");
    assert_eq!(raw(raw_addr, b"unknown\n").await, "unknown\n"); // default: echo
    assert_eq!(link.health().fallbacks, 0, "{}", daemon.as_ref().unwrap().log());

    // The secondary channel: one-shot HTTP to the same rules
    let http_only = Link::start(LinkConfig { http_url: Some(format!("http://127.0.0.1:{}/decide", ports.1)), deadline, secret: signed(), ..LinkConfig::default() });
    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1000".parse().unwrap(), "1.2.3.4:4444".parse().unwrap());
    match http_only.decide(&builder.event(b"PING".to_vec(), serde_json::json!({}), true)).await {
        Decision::Action(action) => {
            assert_eq!(action.response.as_deref(), Some(&b"PONG\n"[..]));
            assert_eq!(action.route.as_deref(), Some("ping"));
        }
        other => panic!("{other:?}"),
    }

    // An unsigned event (a local process posing as the nucleus) is refused
    let unsigned = Link::start(LinkConfig { http_url: Some(format!("http://127.0.0.1:{}/decide", ports.1)), deadline, ..LinkConfig::default() });
    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1000".parse().unwrap(), "1.2.3.4:4444".parse().unwrap());
    match unsigned.decide(&builder.event(b"PING".to_vec(), serde_json::json!({}), true)).await {
        Decision::Fallback(Fallback::Error(reason)) => assert!(reason.contains("401"), "{reason}"),
        other => panic!("{other:?}"),
    }

    // Hot reload: change a reply, save, and the next decision uses it (over the same WebSocket)
    let decisions = work.join("routes/decisions.yaml");
    let original = std::fs::read_to_string(&decisions).unwrap();
    let edited = original.replace(r#"expression: "PONG\n""#, r#"expression: "PONG v2\n""#);
    assert_ne!(original, edited, "the PING rule changed; update this test");
    std::fs::write(&decisions, edited).unwrap();
    let reconnects = link.health().reconnects;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if raw(raw_addr, b"PING\n").await == "PONG v2\n" {
            break;
        }
        assert!(Instant::now() < deadline, "reload never applied: {}", daemon.as_ref().unwrap().log());
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(link.health().reconnects, reconnects, "reloading the rules must not drop the WebSocket");

    // The audit Wire Tap recorded events with their actions
    let audit = std::fs::read_dir(work.join("audit")).unwrap().next().unwrap().unwrap().path();
    let audit = std::fs::read_to_string(audit).unwrap();
    assert!(audit.lines().any(|l| l.contains("\"route\":\"c2-gate\"")), "{audit}");

    // Stop the daemon: everything still answers, with the defaults, immediately
    let fallbacks = link.health().fallbacks;
    drop(daemon.take());
    wait_for("the link to notice", || !link.health().websocket_connected).await;
    let started = Instant::now();
    assert!(http_get(http_addr, "c2.example", "/gate.php").await.contains("<h1>FakeNet</h1>"));
    assert_eq!(a_record(&dns(dns_addr, "beacon.c2.example.").await), "192.0.2.123");
    assert_eq!(raw(raw_addr, b"HELLO bot42\n").await, "HELLO bot42\n");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    assert_eq!(link.health().fallbacks, fallbacks + 3);
    let unavailable = Decision::Fallback(Fallback::Unavailable);
    let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1000".parse().unwrap(), "1.2.3.4:4444".parse().unwrap());
    assert_eq!(format!("{:?}", link.decide(&builder.event(vec![], serde_json::json!({}), true)).await), format!("{unavailable:?}"));

    // Restart it: the link reconnects by itself and decisions resume
    let _daemon = Daemon::start(&work, ports).await;
    wait_for("the link to reconnect", || link.health().websocket_connected).await;
    assert_eq!(a_record(&dns(dns_addr, "beacon.c2.example.").await), "10.6.6.6");
}
