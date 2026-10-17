//! Does exploration find more of a sample than static defaults? A simulated bot with
//! hidden branches that only open for the right answers (as real bots' command handlers
//! do), whose "binary" contains its command strings.

use std::collections::BTreeSet;

use base64::Engine as _;
use fakenet_explorer::{Explorer, ExplorerConfig, Hints};
use fakenet_schema::{Event, EventBuilder, ProcessInfo, Protocol, Transport};
use serde_json::json;

fn event(protocol: Protocol, transport: Transport, dst: &str, payload: &[u8], meta: serde_json::Value) -> Event {
    let mut builder = EventBuilder::new(protocol, transport, "10.0.2.15:50000".parse().unwrap(), dst.parse().unwrap());
    builder.process = Some(ProcessInfo { pid: 4242, name: "bot.exe".into(), exe: None });
    builder.event(payload.to_vec(), meta, true)
}

fn beacon() -> Event {
    event(Protocol::Http, Transport::Tcp, "203.0.113.10:80", b"GET /gate.php?id=7 HTTP/1.1\r\n\r\n", json!({ "method": "GET", "path": "/gate.php?id=7", "host": "c2.evil.example" }))
}

fn txt_query() -> Event {
    event(Protocol::Dns, Transport::Udp, "10.0.2.3:53", b"", json!({ "qname": "cfg.c2.evil.example", "qtype": "TXT" }))
}

/// What the bot does next, given the C2's answers: its hidden branches
fn react(http_body: &[u8], status: u16, txt: &str) -> Vec<(Event, &'static str)> {
    let text = String::from_utf8_lossy(http_body).to_string();
    let decoded = base64::engine::general_purpose::STANDARD.decode(text.trim()).ok().map(|d| String::from_utf8_lossy(&d).to_string()).unwrap_or_default();
    let mut next = Vec::new();
    if text.contains("download") {
        next.push((event(Protocol::Http, Transport::Tcp, "203.0.113.10:80", b"GET /payload.exe", json!({ "method": "GET", "path": "/payload.exe", "host": "c2.evil.example" })), "cmd_download"));
    }
    if serde_json::from_str::<serde_json::Value>(&text).ok().and_then(|v| v.get("task").and_then(|t| t.as_str().map(str::to_string))).as_deref() == Some("scan") {
        next.push((event(Protocol::Raw, Transport::Tcp, "192.168.1.20:445", b"\x00\x00\x00\x85\xffSMB", json!({ "bytes": 8 })), "cmd_scan"));
    }
    if decoded.contains("keylog") {
        next.push((event(Protocol::Http, Transport::Tcp, "203.0.113.10:80", b"POST /upload?type=keys", json!({ "method": "POST", "path": "/upload?type=keys", "host": "c2.evil.example" })), "cmd_keylog"));
    }
    if status == 404 {
        next.push((event(Protocol::Dns, Transport::Udp, "10.0.2.3:53", b"", json!({ "qname": "backup.c2.evil.example", "qtype": "A" })), "fallback_c2"));
    }
    if txt.contains("sleep") {
        next.push((event(Protocol::Dns, Transport::Udp, "10.0.2.3:53", b"", json!({ "qname": "sleeping.c2.evil.example", "qtype": "A" })), "cmd_sleep"));
    }
    next
}

fn http_parts(response: &[u8]) -> (u16, Vec<u8>) {
    let text = String::from_utf8_lossy(response);
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let body = response.windows(4).position(|w| w == b"\r\n\r\n").map(|i| response[i + 4..].to_vec()).unwrap_or_default();
    (status, body)
}

/// Runs `rounds` beacons; returns the branches (functions) the bot took
fn run(explorer: Option<&Explorer>, rounds: usize) -> BTreeSet<&'static str> {
    let mut taken = BTreeSet::new();
    for _ in 0..rounds {
        let (beacon, query) = (beacon(), txt_query());
        let mut http = (200, b"<html>FakeNet</html>".to_vec());
        let mut txt = "FAKENET".to_string();
        if let Some(explorer) = explorer {
            explorer.observe(&beacon);
            if let Some(proposal) = explorer.propose(&beacon) {
                http = http_parts(&proposal.response);
            }
            explorer.observe(&query);
            if let Some(proposal) = explorer.propose(&query) {
                txt = String::from_utf8_lossy(&proposal.response).into_owned();
            }
        }
        for (event, function) in react(&http.1, http.0, &txt) {
            taken.insert(function);
            if let Some(explorer) = explorer {
                explorer.observe(&event);
                explorer.ingest_coverage_line(&json!({ "pid": 4242, "functions": [function] }).to_string()).unwrap();
            }
        }
    }
    taken
}

fn explorer() -> Explorer {
    let binary = b"\x00MZ\x00download\x00scan\x00keylog\x00sleep\x00task=%s\x00http://c2.evil.example/gate.php\x00".to_vec();
    let hints = Hints::from_binary(&binary);
    let config = ExplorerConfig { enabled: true, rate: 1.0, seed: 42, ..ExplorerConfig::default() };
    Explorer::new(config, fakenet_explorer::templates::parse(fakenet_explorer::templates::DEFAULT_TEMPLATES).unwrap(), hints)
}

#[test]
fn exploration_unlocks_hidden_branches_that_defaults_never_reach() {
    let baseline = run(None, 300);
    assert!(baseline.is_empty(), "static defaults already trigger {baseline:?}");

    let explorer = explorer();
    let explored = run(Some(&explorer), 300);
    eprintln!("explored branches: {explored:?}");
    assert!(explored.len() >= 4, "only {explored:?}");

    // The map says which answers unlocked which behaviour and functions
    let map = explorer.map();
    let reached: Vec<&str> = map["functions"]["reached"].as_array().unwrap().iter().filter_map(|f| f.as_str()).collect();
    assert!(reached.len() >= 4, "{reached:?}");
    let templates = map["templates"].as_array().unwrap();
    let credited: BTreeSet<&str> = templates.iter().flat_map(|t| t["functions"].as_array().unwrap().iter().filter_map(|f| f.as_str())).collect();
    assert!(credited.contains("cmd_download"), "{map:#}");
    // Rewarded templates rank first; the hint tokens that unlocked branches score
    assert!(templates[0]["reward"].as_f64().unwrap() > 0.0);
    let tokens: Vec<&str> = map["tokens"].as_array().unwrap().iter().filter_map(|t| t["token"].as_str()).collect();
    assert!(tokens.iter().any(|t| ["download", "scan", "keylog", "sleep"].contains(t)), "{tokens:?}");
}

#[test]
fn exploration_is_reproducible_from_its_seed() {
    let first = run(Some(&explorer()), 60);
    let second = run(Some(&explorer()), 60);
    assert_eq!(first, second);
}
