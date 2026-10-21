//! Which events a live-manual hold or a hook applies to: by protocol, by host (the HTTP
//! `Host`, the DNS name, a proxy target, or the destination IP) and by a substring of the
//! request line (the HTTP path, a DNS name, a line protocol's command and argument).

use fakenet_schema::{Event, Protocol};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EventFilter {
    /// Only these protocols (empty: any)
    pub protocols: Vec<Protocol>,
    /// Only these hosts or their subdomains, or these destination IPs (empty: any)
    pub hosts: Vec<String>,
    /// Only requests whose path, name or command contains this (case-insensitive)
    pub contains: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, event: &Event) -> bool {
        if !self.protocols.is_empty() && !self.protocols.contains(&event.protocol) {
            return false;
        }
        if !self.hosts.is_empty() {
            let host = host_of(event);
            let host = host.as_deref().unwrap_or("");
            let matched = self.hosts.iter().any(|wanted| {
                let wanted = wanted.trim_end_matches('.').to_ascii_lowercase();
                host == wanted || host.ends_with(&format!(".{wanted}")) || event.dst == wanted
            });
            if !matched {
                return false;
            }
        }
        match &self.contains {
            Some(needle) => request_text(event).to_ascii_lowercase().contains(&needle.to_ascii_lowercase()),
            None => true,
        }
    }
}

/// The name the client asked for, lowercased and without a port or trailing dot
pub fn host_of(event: &Event) -> Option<String> {
    let meta = &event.meta;
    let raw = ["host", "qname", "sni", "target"].iter().find_map(|key| meta[*key].as_str().filter(|v| !v.is_empty()))?;
    let raw = raw.trim().trim_end_matches('.');
    // host:port, [v6]:port
    let host = match raw.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => match raw.rsplit_once(':') {
            Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => name,
            _ => raw,
        },
    };
    Some(host.to_ascii_lowercase())
}

/// A one-line summary of what the client asked: the path, the name, or the command
pub fn request_text(event: &Event) -> String {
    let meta = &event.meta;
    let field = |key: &str| meta[key].as_str().unwrap_or("").to_string();
    if meta["path"].is_string() {
        format!("{} {}", field("method"), field("path")).trim().to_string()
    } else if meta["qname"].is_string() {
        format!("{} {}", field("qtype"), field("qname")).trim().to_string()
    } else if meta["command"].is_string() {
        format!("{} {}", field("command"), field("argument")).trim().to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn event(protocol: Protocol, meta: serde_json::Value) -> Event {
        serde_json::from_value(json!({
            "version": 1, "type": "event", "request_id": "r", "session_id": "s", "seq": 1,
            "protocol": protocol, "transport": "tcp", "src": "10.0.0.5", "dst": "198.18.0.7", "dport": 80,
            "timestamp": "2026-01-01T00:00:00Z", "payload": "", "meta": meta, "expects_reply": true,
        }))
        .unwrap()
    }

    #[test]
    fn matches_protocol_host_and_text() {
        let gate = event(Protocol::Http, json!({ "method": "POST", "path": "/Gate.php?id=1", "host": "C2.Evil.Example:8080" }));
        let dns = event(Protocol::Dns, json!({ "qname": "beacon.evil.example", "qtype": "TXT" }));
        let filter = |protocols: Vec<Protocol>, hosts: &[&str], contains: Option<&str>| EventFilter {
            protocols,
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            contains: contains.map(str::to_string),
        };
        assert!(filter(vec![], &[], None).matches(&gate));
        assert!(filter(vec![Protocol::Http], &["evil.example"], Some("gate.php")).matches(&gate));
        assert!(!filter(vec![Protocol::Dns], &[], None).matches(&gate));
        assert!(!filter(vec![], &["vil.example"], None).matches(&gate)); // Label boundaries
        assert!(filter(vec![], &["198.18.0.7"], None).matches(&gate)); // The destination IP
        assert!(filter(vec![], &["evil.example."], Some("txt beacon")).matches(&dns));
        assert_eq!(host_of(&gate).as_deref(), Some("c2.evil.example"));
        assert_eq!(request_text(&gate), "POST /Gate.php?id=1");
    }
}
