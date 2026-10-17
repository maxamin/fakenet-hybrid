//! The Linux diverter for real, inside a private network namespace (so the host's own
//! iptables & traffic are never touched): REDIRECT to the listeners, original destinations,
//! un-NATed UDP replies, NFQUEUE process exclusion, and complete cleanup.
//!
//! Run with: scripts/test-linux-diversion.sh (it creates the namespace). The test refuses
//! to run anywhere else.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use fakenet_capture::Capture;
use fakenet_diverter::{Diverter, DiverterConfig, Plan};
use fakenet_link::{Link, LinkConfig};
use fakenet_listeners::config::{AutoKeyword, ListenerProtocol};
use fakenet_listeners::{Context, Defaults, ListenerConfig, Server, TlsAuthority};
use fakenet_schema::{Protocol, Transport};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn in_private_namespace() -> bool {
    let ours = std::fs::read_link("/proc/self/ns/net").ok();
    let init = std::fs::read_link("/proc/1/ns/net").ok();
    std::env::var("FAKENET_NETNS_TEST").is_ok_and(|v| v == "1") && (init.is_none() || ours != init)
}

fn sh(command: &str) -> String {
    let output = Command::new("sh").arg("-c").arg(command).output().unwrap();
    assert!(output.status.success(), "{command}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn iptables_rules() -> String {
    String::from_utf8_lossy(&Command::new("iptables").args(["-w", "-t", "nat", "-S"]).output().unwrap().stdout).into_owned()
}

fn listener(name: &str, protocol: Option<Protocol>, transport: Transport, port: u16) -> ListenerConfig {
    ListenerConfig { name: name.into(), protocol: protocol.map(ListenerProtocol::Fixed).unwrap_or(ListenerProtocol::Auto(AutoKeyword::Auto)), transport, port, ..ListenerConfig::default() }
}

fn events(dir: &PathBuf, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(dir.join("events.jsonl")).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()).filter(|e| e["kind"] == kind).collect()
}

#[tokio::test]
#[ignore = "needs a private network namespace: scripts/test-linux-diversion.sh"]
async fn diverts_inside_a_network_namespace() {
    assert!(in_private_namespace(), "refusing to touch iptables outside a private network namespace");
    // "The internet": a default route, so remote addresses pass the routing decision and
    // reach the OUTPUT NAT. Via loopback, since that's the only device a bare namespace is
    // guaranteed to have; undiverted packets to remote addresses then go nowhere.
    sh("ip link set lo up && ip route add default dev lo");

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("linux-diversion");
    let _ = std::fs::remove_dir_all(&dir);
    let ctx = Arc::new(Context {
        link: Link::start(LinkConfig::default()),
        capture: Capture::open(&dir).unwrap(),
        defaults: Defaults::default(),
        tls: Arc::new(TlsAuthority::generate().unwrap()),
        timeout: Duration::from_secs(5),
        first_data_timeout: Duration::from_millis(300),
        original: None,
    });
    let listeners = [
        listener("http", Some(Protocol::Http), Transport::Tcp, 80),
        listener("dns", Some(Protocol::Dns), Transport::Udp, 53),
        listener("auto", None, Transport::Tcp, 1337),
        listener("auto-udp", None, Transport::Udp, 1338),
    ];
    let _server = Server::start(ctx, "0.0.0.0".parse().unwrap(), &listeners).await.unwrap();
    let plan = Plan { tcp_ports: vec![80], udp_ports: vec![53], tcp_default: Some(1337), udp_default: Some(1338), ..Plan::default() };
    let config = DiverterConfig { enabled: true, ipv6: false, ..DiverterConfig::default() };
    let diverter = Diverter::start(&config, plan.clone()).unwrap();
    assert!(iptables_rules().contains("-A OUTPUT -j FAKENET"));

    // HTTP to a "remote" server lands on the HTTP listener, which sees the real destination
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect("93.184.216.34:80")).await.unwrap().unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut page = String::new();
    stream.read_to_string(&mut page).await.unwrap();
    assert!(page.contains("<h1>FakeNet</h1>"), "{page}");

    // Any other port goes to the auto listener (raw echo), with its original destination
    let mut stream = TcpStream::connect("203.0.113.9:4444").await.unwrap();
    stream.write_all(b"\x01beacon").await.unwrap();
    let mut echo = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echo)).await.unwrap().unwrap();
    assert_eq!(&echo, b"\x01beacon");

    // DNS to any resolver is answered, and the reply comes back from that resolver's address
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03evil\x07example\x00\x00\x01\x00\x01";
    socket.send_to(query, "198.51.100.53:53").await.unwrap();
    let mut buffer = [0u8; 512];
    let (length, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(from, "198.51.100.53:53".parse::<SocketAddr>().unwrap());
    assert_eq!(&buffer[length - 4..length], &[192, 0, 2, 123]);

    // UDP to an unlisted port reaches the auto listener, which learns the real port
    socket.send_to(b"\x7fudp-beacon", "203.0.113.9:9999").await.unwrap();
    let (length, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!((&buffer[..length], from), (&b"\x7fudp-beacon"[..], "203.0.113.9:9999".parse::<SocketAddr>().unwrap()));

    // Pings to anywhere are answered
    let ping = Command::new("ping").args(["-c", "1", "-W", "2", "198.51.100.1"]).output();
    if let Ok(ping) = ping {
        assert!(ping.status.success(), "ping: {}", String::from_utf8_lossy(&ping.stdout));
    }

    let destinations: Vec<String> = events(&dir, "session_start").iter().map(|e| e["dst"].as_str().unwrap().to_string()).collect();
    assert!(destinations.contains(&"93.184.216.34:80".to_string()), "{destinations:?}");
    assert!(destinations.contains(&"203.0.113.9:4444".to_string()), "{destinations:?}");
    assert!(destinations.contains(&"203.0.113.9:9999".to_string()), "{destinations:?}");
    let detected: Vec<String> = events(&dir, "session_start").iter().map(|e| e["process"]["pid"].to_string()).collect();
    assert!(detected.contains(&std::process::id().to_string()), "attributed to this process: {detected:?}");

    // Stopping removes every trace
    diverter.stop().unwrap();
    let rules = iptables_rules();
    assert!(!rules.contains("FAKENET"), "{rules}");

    // Excluded processes are never diverted: this test's own connection now goes nowhere
    let own_name = std::fs::read_to_string("/proc/self/comm").unwrap().trim().to_string();
    let config = DiverterConfig { enabled: true, ipv6: false, excluded_processes: vec![own_name], ..DiverterConfig::default() };
    let diverter = Diverter::start(&config, plan).unwrap();
    assert!(iptables_rules().contains("-A FAKENET -m mark --mark 0x4b1d/0x4b1d -j RETURN"));
    let attempt = tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect("93.184.216.34:80")).await;
    assert!(attempt.is_err() || attempt.unwrap().is_err(), "an excluded process was diverted");
    drop(diverter); // Dropping restores too
    assert!(!iptables_rules().contains("FAKENET"));
    let mangle = String::from_utf8_lossy(&Command::new("iptables").args(["-w", "-t", "mangle", "-S"]).output().unwrap().stdout).into_owned();
    assert!(!mangle.contains("FAKENET"), "{mangle}");
}

#[tokio::test]
#[ignore = "needs a private network namespace: scripts/test-linux-diversion.sh"]
async fn captures_real_packets_inside_a_network_namespace() {
    assert!(in_private_namespace(), "refusing to capture packets outside a private network namespace");
    let _ = Command::new("ip").args(["link", "set", "lo", "up"]).status();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wire-capture");
    let _ = std::fs::remove_dir_all(&dir);
    let capture = Capture::open(&dir).unwrap();
    let sink = capture.clone();
    let wire = fakenet_diverter::wire::WireCapture::start(Arc::new(move |packet: &[u8]| sink.wire_packet(packet))).unwrap();

    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"on-the-wire", receiver.local_addr().unwrap()).await.unwrap();
    let mut buffer = [0u8; 64];
    receiver.recv_from(&mut buffer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(wire); // Stops within its 200 ms receive timeout

    let pcap = std::fs::read(dir.join("wire.pcap")).unwrap();
    assert_eq!(u32::from_le_bytes(pcap[20..24].try_into().unwrap()), 101); // LINKTYPE_RAW
    let found = pcap.windows(11).filter(|w| *w == b"on-the-wire").count();
    assert_eq!(found, 1, "the datagram once (loopback duplicates dropped)");
}
