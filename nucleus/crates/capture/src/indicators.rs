//! Indicators from an event log, for sharing and hunting: CSV, STIX 2.1 and MISP.
//!
//! What a sample reached for: domains (DNS, SNI, HTTP hosts, tunnels), URLs, IP addresses
//! it connected to directly, User-Agents, email addresses, and its TLS/SSH client
//! fingerprints. Addresses the nucleus itself handed out (private, documentation and
//! benchmarking ranges) aren't indicators, and neither are operating-system connectivity
//! checks. Everything is an observation from a sandbox run: review before blocking on it
//! (MISP attributes are exported with to_ids = false).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Domain,
    Url,
    Ip,
    UserAgent,
    Email,
    Ja3,
    Ja4,
    Hassh,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Domain => "domain",
            Kind::Url => "url",
            Kind::Ip => "ip",
            Kind::UserAgent => "user-agent",
            Kind::Email => "email",
            Kind::Ja3 => "ja3",
            Kind::Ja4 => "ja4",
            Kind::Hassh => "hassh",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Indicator {
    pub kind: Kind,
    pub value: String,
    pub count: usize,
    pub first_seen: String,
    /// Protocols it was seen with
    pub protocols: Vec<String>,
    /// A known-fingerprint label, when one matched
    pub known: Option<String>,
}

/// Connectivity checks & other operating-system noise: not the sample's doing
const NOISE: &[&str] = &[
    "msftncsi.com",
    "msftconnecttest.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "captive.apple.com",
    "detectportal.firefox.com",
    "connectivity-check.ubuntu.com",
    "nmcheck.gnome.org",
    "in-addr.arpa",
    "ip6.arpa",
    "local",
    "localhost",
    "wpad",
];

fn is_noise(domain: &str) -> bool {
    NOISE.iter().any(|n| domain == *n || domain.ends_with(&format!(".{n}")))
}

/// Publicly routable: what a sample hardcoded, rather than what our DNS gave it
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..128).contains(&b)) // Shared address space (CGNAT)
                || (a == 198 && (b == 18 || b == 19)) // Benchmarking: the per-domain pool
                || (a == 192 && b == 0 && c == 0)
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_global(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // Unique local
                || (first & 0xffc0) == 0xfe80 // Link local
                || first == 0x2001 && v6.segments()[1] == 0x0db8) // Documentation
        }
    }
}

#[derive(Default)]
struct Collector(BTreeMap<(Kind, String), Indicator>);

impl Collector {
    fn add(&mut self, kind: Kind, value: &str, record: &Value) {
        let value = value.trim();
        if value.is_empty() || value.len() > 2048 {
            return;
        }
        let value = match kind {
            Kind::Domain | Kind::Email | Kind::Ja3 | Kind::Ja4 | Kind::Hassh => value.trim_end_matches('.').to_ascii_lowercase(),
            _ => value.to_string(),
        };
        if kind == Kind::Domain {
            if let Ok(ip) = value.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
                return self.add_ip(ip, record);
            }
            if is_noise(&value) || !value.contains('.') {
                return;
            }
        }
        let timestamp = record["timestamp"].as_str().unwrap_or_default().to_string();
        let protocol = record["protocol"].as_str().unwrap_or_default().to_string();
        let entry = self.0.entry((kind, value.clone())).or_insert_with(|| Indicator {
            kind,
            value,
            count: 0,
            first_seen: timestamp.clone(),
            protocols: Vec::new(),
            known: None,
        });
        entry.count += 1;
        if !timestamp.is_empty() && (entry.first_seen.is_empty() || timestamp < entry.first_seen) {
            entry.first_seen = timestamp;
        }
        if !protocol.is_empty() && !entry.protocols.contains(&protocol) {
            entry.protocols.push(protocol);
        }
        // A known-fingerprint label belongs to the fingerprints, not the record's other values
        if let (Kind::Ja3 | Kind::Ja4 | Kind::Hassh, Some(known)) = (kind, record["known"].as_str()) {
            entry.known = Some(known.to_string());
        }
    }

    fn add_ip(&mut self, ip: IpAddr, record: &Value) {
        if is_global(ip) {
            self.add(Kind::Ip, &ip.to_string(), record);
        }
    }
}

/// "host:port" or "[v6]:port" -> host
fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// The indicators in an event log, by kind then value
pub fn collect(records: &[Value]) -> Vec<Indicator> {
    let mut found = Collector::default();
    for record in records {
        let kind = record["kind"].as_str().unwrap_or_default();
        let meta = &record["meta"];
        match kind {
            "event" if record["protocol"] == "dns" => {
                if meta["qtype"] != "PTR" {
                    found.add(Kind::Domain, meta["qname"].as_str().unwrap_or_default(), record);
                }
            }
            "event" if record["protocol"] == "http" => {
                let host = host_of(meta["host"].as_str().unwrap_or_default()).to_string();
                found.add(Kind::Domain, &host, record);
                let path = meta["path"].as_str().unwrap_or_default();
                if meta["method"] != "CONNECT" && !host.is_empty() && !is_noise(&host.to_ascii_lowercase()) {
                    let url = if path.contains("://") {
                        path.to_string()
                    } else {
                        let scheme = if record["tls"] == Value::Bool(true) { "https" } else { "http" };
                        format!("{scheme}://{}{path}", meta["host"].as_str().unwrap_or_default())
                    };
                    found.add(Kind::Url, &url, record);
                }
                if let Some(agent) = meta["headers"]["user-agent"].as_str() {
                    found.add(Kind::UserAgent, agent, record);
                }
            }
            "tls_handshake" => {
                found.add(Kind::Domain, record["sni"].as_str().unwrap_or_default(), record);
                found.add(Kind::Ja3, record["ja3"].as_str().unwrap_or_default(), record);
                found.add(Kind::Ja4, record["ja4"].as_str().unwrap_or_default(), record);
            }
            "ssh_client" => found.add(Kind::Hassh, record["hassh"].as_str().unwrap_or_default(), record),
            "proxy_tunnel" | "socks_refused" => found.add(Kind::Domain, host_of(record["target"].as_str().unwrap_or_default()), record),
            "email" => {
                found.add(Kind::Email, record["from"].as_str().unwrap_or_default(), record);
                for to in record["to"].as_array().into_iter().flatten() {
                    found.add(Kind::Email, to.as_str().unwrap_or_default(), record);
                }
            }
            "session_start" => {
                if let Some(Ok(address)) = record["dst"].as_str().map(str::parse::<std::net::SocketAddr>) {
                    found.add_ip(address.ip(), record);
                }
            }
            _ => {}
        }
    }
    found.0.into_values().collect()
}

pub fn to_csv(indicators: &[Indicator]) -> String {
    let quote = |s: &str| if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() };
    let mut csv = String::from("type,value,count,first_seen,protocols,known\n");
    for i in indicators {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            i.kind.name(),
            quote(&i.value),
            i.count,
            i.first_seen,
            quote(&i.protocols.join(" ")),
            quote(i.known.as_deref().unwrap_or("")),
        ));
    }
    csv
}

/// A STIX pattern string literal
fn stix_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn stix_id(kind: &str) -> String {
    format!("{kind}--{}", uuid::Uuid::new_v4())
}

/// STIX 2.1 Cyber-observable IDs are deterministic (section 2.9): a UUIDv5 in the STIX
/// namespace over the canonical JSON of the ID-contributing properties
fn stix_observable_id(kind: &str, contributing: &Value) -> String {
    const NAMESPACE: uuid::Uuid = uuid::uuid!("00abedb4-aa42-466c-9c01-fed23315a9b7");
    // serde_json sorts object keys and writes no whitespace: canonical for these values
    let mut input = NAMESPACE.as_bytes().to_vec();
    input.extend_from_slice(contributing.to_string().as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    let bytes: [u8; 16] = digest.as_ref()[..16].try_into().expect("SHA-1 is 20 bytes");
    format!("{kind}--{}", uuid::Builder::from_sha1_bytes(bytes).into_uuid())
}

fn now() -> String {
    time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

/// A STIX 2.1 bundle: an Indicator per value (JA3/JA4/HASSH have no standard STIX pattern,
/// so they're in the CSV and MISP exports only). With the run's `sample` ({name, sha256,
/// md5}, as in run.json), also the sample as a File and a Malware object, which every
/// Indicator `indicates`.
pub fn to_stix(indicators: &[Indicator], sample: Option<&Value>) -> Value {
    let created = now();
    let identity = stix_id("identity");
    let mut objects = vec![json!({
        "type": "identity", "spec_version": "2.1", "id": identity, "created": created, "modified": created,
        "name": "fakenet-hybrid", "identity_class": "system",
    })];
    let malware = sample.filter(|s| s["sha256"].is_string()).map(|sample| {
        // A File's ID comes from its name and one hash, MD5 first (as the spec & stix2 library choose)
        let hash = if sample["md5"].is_string() { json!({ "MD5": sample["md5"] }) } else { json!({ "SHA-256": sample["sha256"] }) };
        let file = stix_observable_id("file", &json!({ "hashes": hash, "name": sample["name"] }));
        let malware = stix_id("malware");
        objects.push(json!({
            "type": "file", "spec_version": "2.1", "id": file, "name": sample["name"],
            "hashes": { "SHA-256": sample["sha256"], "MD5": sample["md5"] },
        }));
        objects.push(json!({
            "type": "malware", "spec_version": "2.1", "id": malware, "created": created, "modified": created,
            "created_by_ref": identity, "name": sample["name"], "is_family": false, "sample_refs": [file],
            "description": "The sample run under fakenet-hybrid",
        }));
        malware
    });
    for i in indicators {
        let pattern = match i.kind {
            Kind::Domain => format!("[domain-name:value = {}]", stix_literal(&i.value)),
            Kind::Url => format!("[url:value = {}]", stix_literal(&i.value)),
            Kind::Ip if i.value.contains(':') => format!("[ipv6-addr:value = {}]", stix_literal(&i.value)),
            Kind::Ip => format!("[ipv4-addr:value = {}]", stix_literal(&i.value)),
            Kind::UserAgent => format!("[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = {}]", stix_literal(&i.value)),
            Kind::Email => format!("[email-addr:value = {}]", stix_literal(&i.value)),
            Kind::Ja3 | Kind::Ja4 | Kind::Hassh => continue,
        };
        let id = stix_id("indicator");
        let valid_from = if i.first_seen.is_empty() { created.clone() } else { i.first_seen.clone() };
        objects.push(json!({
            "type": "indicator", "spec_version": "2.1", "id": id, "created": created, "modified": created,
            "created_by_ref": identity, "name": format!("{}: {}", i.kind.name(), i.value),
            "description": format!("Observed {} time(s) under fakenet-hybrid ({})", i.count, i.protocols.join(", ")),
            "indicator_types": ["unknown"], "pattern": pattern, "pattern_type": "stix", "valid_from": valid_from,
        }));
        if let Some(malware) = &malware {
            objects.push(json!({
                "type": "relationship", "spec_version": "2.1", "id": stix_id("relationship"), "created": created, "modified": created,
                "relationship_type": "indicates", "source_ref": id, "target_ref": malware,
            }));
        }
    }
    json!({ "type": "bundle", "id": stix_id("bundle"), "objects": objects })
}

/// A MISP event (importable with "Add Event > Import from MISP JSON"); attributes have
/// to_ids = false, for an analyst to promote
pub fn to_misp(indicators: &[Indicator], sample: Option<&Value>) -> Value {
    let mut attributes = Vec::new();
    let mut attribute = |kind: &str, category: &str, value: &str, comment: String| {
        attributes.push(json!({ "type": kind, "category": category, "value": value, "to_ids": false, "comment": comment }));
    };
    if let Some(sample) = sample {
        for (kind, key) in [("filename", "name"), ("sha256", "sha256"), ("md5", "md5")] {
            if let Some(value) = sample[key].as_str() {
                attribute(kind, "Payload delivery", value, "The sample run under fakenet-hybrid".into());
            }
        }
    }
    for i in indicators {
        let mut comment = format!("Seen {} time(s) ({})", i.count, i.protocols.join(", "));
        if let Some(known) = &i.known {
            comment.push_str(&format!("; known: {known}"));
        }
        let (kind, category) = match i.kind {
            Kind::Domain => ("domain", "Network activity"),
            Kind::Url => ("url", "Network activity"),
            Kind::Ip => ("ip-dst", "Network activity"),
            Kind::UserAgent => ("user-agent", "Network activity"),
            Kind::Email => ("email-dst", "Network activity"),
            Kind::Ja3 => ("ja3-fingerprint-md5", "Network activity"),
            Kind::Hassh => ("hassh-md5", "Network activity"),
            Kind::Ja4 => {
                comment = format!("JA4 TLS client fingerprint; {comment}");
                ("text", "Network activity")
            }
        };
        attribute(kind, category, &i.value, comment);
    }
    let date = now().get(..10).unwrap_or_default().to_string();
    let info = match sample.and_then(|s| s["name"].as_str()) {
        Some(name) => format!("fakenet-hybrid run: {name}"),
        None => "fakenet-hybrid run".to_string(),
    };
    json!({ "Event": {
        "info": info, "date": date, "threat_level_id": "4", "analysis": "0", "distribution": "0",
        "Attribute": attributes,
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<Value> {
        let lines = [
            r#"{"kind":"event","protocol":"dns","timestamp":"2026-10-17T01:00:02Z","meta":{"qname":"C2.Evil.example.","qtype":"A"}}"#,
            r#"{"kind":"event","protocol":"dns","timestamp":"2026-10-17T01:00:01Z","meta":{"qname":"c2.evil.example","qtype":"A"}}"#,
            r#"{"kind":"event","protocol":"dns","timestamp":"2026-10-17T01:00:01Z","meta":{"qname":"www.msftconnecttest.com","qtype":"A"}}"#,
            r#"{"kind":"event","protocol":"dns","meta":{"qname":"4.3.2.1.in-addr.arpa","qtype":"PTR"}}"#,
            r#"{"kind":"event","protocol":"http","tls":true,"timestamp":"2026-10-17T01:00:03Z","meta":{"method":"GET","host":"c2.evil.example:8443","path":"/gate.php?id=1","headers":{"user-agent":"EvilBot/1.0"}}}"#,
            r#"{"kind":"event","protocol":"http","meta":{"method":"GET","host":"203.0.113.9","path":"/x"}}"#,
            r#"{"kind":"session_start","protocol":"raw","dst":"8.8.4.4:4444"}"#,
            r#"{"kind":"session_start","protocol":"http","dst":"198.18.0.7:80"}"#,
            r#"{"kind":"session_start","protocol":"http","dst":"192.0.2.123:80"}"#,
            r#"{"kind":"session_start","protocol":"http","dst":"10.0.0.5:80"}"#,
            r#"{"kind":"tls_handshake","protocol":"http","sni":"cdn.evil.example","ja3":"ADC2BD4BB269872516EEAA7ADE78FE75","ja4":"t13i9012h2_c6771aded2ed_57a60bdf03d1","known":"curl"}"#,
            r#"{"kind":"ssh_client","protocol":"ssh","hassh":"ec7378c1a92f5a8dde7e8b7a1ddf33d1"}"#,
            r#"{"kind":"email","protocol":"smtp","from":"bot@victim.example","to":["drop@evil.example"]}"#,
            r#"{"kind":"proxy_tunnel","protocol":"http","target":"tunnel.evil.example:443"}"#,
        ];
        lines.iter().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn values(indicators: &[Indicator], kind: Kind) -> Vec<&str> {
        indicators.iter().filter(|i| i.kind == kind).map(|i| i.value.as_str()).collect()
    }

    #[test]
    fn collects_what_the_sample_reached_for() {
        let found = collect(&records());
        assert_eq!(values(&found, Kind::Domain), ["c2.evil.example", "cdn.evil.example", "tunnel.evil.example"]);
        let c2 = found.iter().find(|i| i.value == "c2.evil.example").unwrap();
        assert_eq!((c2.count, c2.first_seen.as_str()), (3, "2026-10-17T01:00:01Z"));
        assert_eq!(c2.protocols, ["dns", "http"]);
        assert_eq!(values(&found, Kind::Url), ["http://203.0.113.9/x", "https://c2.evil.example:8443/gate.php?id=1"]);
        // Only addresses the sample chose: not our DNS answers or the lab network
        assert_eq!(values(&found, Kind::Ip), ["8.8.4.4"]);
        assert_eq!(values(&found, Kind::UserAgent), ["EvilBot/1.0"]);
        assert_eq!(values(&found, Kind::Email), ["bot@victim.example", "drop@evil.example"]);
        assert_eq!(values(&found, Kind::Ja3), ["adc2bd4bb269872516eeaa7ade78fe75"]);
        assert_eq!(found.iter().find(|i| i.kind == Kind::Ja3).unwrap().known.as_deref(), Some("curl"));
        assert_eq!(found.iter().find(|i| i.value == "cdn.evil.example").unwrap().known, None);
        assert_eq!(values(&found, Kind::Hassh), ["ec7378c1a92f5a8dde7e8b7a1ddf33d1"]);
    }

    #[test]
    fn global_addresses() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_global(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.1.2.3", "192.168.0.1", "172.16.0.1", "127.0.0.1", "198.18.0.1", "198.19.255.1", "192.0.2.123", "100.64.0.1", "169.254.1.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "2001:db8::123", "::ffff:10.0.0.1", "255.255.255.255"] {
            assert!(!is_global(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn stix_bundle_links_indicators_to_the_sample() {
        let sample = json!({ "name": "bot.exe", "sha256": "ab".repeat(32), "md5": "cd".repeat(16) });
        let bundle = to_stix(&collect(&records()), Some(&sample));
        let objects = bundle["objects"].as_array().unwrap();
        let of = |kind: &str| objects.iter().filter(|o| o["type"] == kind).collect::<Vec<_>>();
        let indicators = of("indicator");
        // Domains 3, URLs 2, IP 1, User-Agent 1, emails 2; fingerprints aren't STIX patterns
        assert_eq!(indicators.len(), 9);
        assert_eq!(of("relationship").len(), 9);
        assert_eq!(of("malware")[0]["sample_refs"][0], of("file")[0]["id"]);
        assert!(indicators.iter().any(|i| i["pattern"] == "[domain-name:value = 'c2.evil.example']"));
        assert!(indicators.iter().any(|i| i["pattern"] == "[ipv4-addr:value = '8.8.4.4']"));
        assert!(indicators.iter().all(|i| i["id"].as_str().unwrap().starts_with("indicator--") && i["spec_version"] == "2.1"));
    }

    #[test]
    fn file_ids_match_the_stix2_library() {
        // stix2.File(name='bot.exe', hashes={'SHA-256': 'ab'*32, 'MD5': 'cd'*16}).id, and without MD5
        let both = json!({ "name": "bot.exe", "sha256": "ab".repeat(32), "md5": "cd".repeat(16) });
        let sha256_only = json!({ "name": "bot.exe", "sha256": "ab".repeat(32) });
        let file_id = |sample: &Value| to_stix(&[], Some(sample))["objects"].as_array().unwrap().iter().find(|o| o["type"] == "file").unwrap()["id"].clone();
        assert_eq!(file_id(&both), "file--3eca0424-0d2a-52a3-a02c-5b33fd5bf5e0");
        assert_eq!(file_id(&sha256_only), "file--9d39436c-4583-57fc-a215-7968bb8f75fa");
    }

    #[test]
    fn stix_literals_are_escaped() {
        assert_eq!(stix_literal(r"a'b\c"), r"'a\'b\\c'");
    }

    #[test]
    fn misp_and_csv() {
        let found = collect(&records());
        let misp = to_misp(&found, Some(&json!({ "name": "bot.exe", "sha256": "ab".repeat(32), "md5": "cd".repeat(16) })));
        let attributes = misp["Event"]["Attribute"].as_array().unwrap();
        assert!(attributes.iter().all(|a| a["to_ids"] == false));
        assert!(attributes.iter().any(|a| a["type"] == "ja3-fingerprint-md5" && a["comment"].as_str().unwrap().contains("known: curl")));
        assert!(attributes.iter().any(|a| a["type"] == "sha256" && a["category"] == "Payload delivery"));
        let csv = to_csv(&found);
        assert!(csv.starts_with("type,value,count,first_seen,protocols,known\n"));
        assert!(csv.contains("\ndomain,c2.evil.example,3,2026-10-17T01:00:01Z,dns http,\n"), "{csv}");
    }
}
