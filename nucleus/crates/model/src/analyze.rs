//! Protocol analysers: how a request is keyed (so similar requests share learned answers)
//! and how a recorded answer is stored (in the form the nucleus's handler takes).
//!
//! To support a protocol better, implement `Analyzer` and add it to `analyzers()`. Keys go
//! from most specific to least; learning files an answer under the first, and answering
//! looks them up in order. A key never contains raw sample bytes beyond a short, normalised
//! command, so model packs stay small and shareable.

use fakenet_schema::{Protocol, Transport};

pub trait Analyzer: Send + Sync {
    /// The protocol's name, as `fakenet_schema::Protocol::name`
    fn protocol(&self) -> &'static str;
    /// Lookup keys for a request as captured on the wire, most specific first (an empty
    /// request: a greeting)
    fn keys(&self, request: &[u8]) -> Vec<String>;
    /// The same keys for a live event, whose payload some handlers reduce to the message
    /// body (the rest is in `meta`: MQTT's topic, CoAP's method and path)
    fn keys_for_event(&self, payload: &[u8], _meta: &serde_json::Value) -> Vec<String> {
        self.keys(payload)
    }
    /// The answer as stored and replayed; None to skip it (incomplete, unusable)
    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {
        Some(response.to_vec())
    }
    /// Whether a stored answer is a failure (not found, refused, server error): kept for
    /// realism, left out when only successful answers are wanted
    fn is_failure(&self, _answer: &[u8]) -> bool {
        false
    }
}

/// The key for answers to an empty request (what a server says first)
pub const GREETING: &str = "<greeting>";

/// Every analyser, by protocol; `generic()` covers the rest
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(Http),
        Box::new(Dns),
        Box::new(Lines { protocol: "smtp", tag_first: false }),
        Box::new(Lines { protocol: "pop3", tag_first: false }),
        Box::new(Lines { protocol: "ftp", tag_first: false }),
        Box::new(Lines { protocol: "irc", tag_first: false }),
        Box::new(Lines { protocol: "telnet", tag_first: false }),
        Box::new(Lines { protocol: "imap", tag_first: true }),
        Box::new(Redis),
        Box::new(Mqtt),
        Box::new(Coap),
    ]
}

/// The analyser for `protocol` (the generic one when none is specific)
pub fn for_protocol(protocol: &str) -> Box<dyn Analyzer> {
    analyzers().into_iter().find(|a| a.protocol() == protocol).unwrap_or_else(|| Box::new(Generic { protocol: leak(protocol) }))
}

/// Protocol names are a small closed set (schema enum, plus "tls" and "unknown")
fn leak(protocol: &str) -> &'static str {
    match serde_json::from_value::<Protocol>(serde_json::Value::String(protocol.to_string())) {
        Ok(p) => p.name(),
        Err(_) if protocol == "tls" => "tls",
        Err(_) => "raw",
    }
}

/// Which protocol a flow speaks, from its first client bytes and the server's port
pub fn identify(transport: Transport, server_port: u16, first_client_bytes: &[u8]) -> &'static str {
    if fakenet_sniffer::looks_like_tls(first_client_bytes) {
        return "tls";
    }
    let protocol = match first_client_bytes.is_empty() {
        true => fakenet_sniffer::sniff_silent(fakenet_sniffer::DEFAULT_ORDER, server_port),
        false => fakenet_sniffer::sniff(fakenet_sniffer::DEFAULT_ORDER, first_client_bytes, server_port, transport),
    };
    protocol.name()
}

/// A path segment with the variable parts of URLs (ids, hashes, tokens) replaced by a type
fn normalize_segment(segment: &str) -> String {
    // name=value segments (`site=0000127709`): keep the name, type the value
    if let Some((name, value)) = segment.split_once('=') {
        if !name.is_empty() && name.len() <= 32 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
            return format!("{name}={}", normalize_segment(value));
        }
    }
    let hex = segment.len() >= 8 && segment.bytes().all(|b| b.is_ascii_hexdigit());
    let uuid = segment.len() == 36 && segment.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() });
    let token = segment.len() >= 16 && segment.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b)) && segment.bytes().any(|b| b.is_ascii_digit());
    if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
        "{n}".into()
    } else if uuid {
        "{uuid}".into()
    } else if hex {
        "{hex}".into()
    } else if token {
        "{token}".into()
    } else {
        segment.chars().take(64).collect()
    }
}

struct Http;

impl Analyzer for Http {
    fn protocol(&self) -> &'static str {
        "http"
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        if request.is_empty() {
            return vec![GREETING.into()];
        }
        let line = String::from_utf8_lossy(&request[..request.len().min(2048)]);
        let line = line.lines().next().unwrap_or("");
        let mut parts = line.split(' ');
        let method: String = parts.next().unwrap_or("").chars().filter(char::is_ascii_uppercase).take(16).collect();
        let target = parts.next().unwrap_or("/");
        // Absolute-form (proxies): keep the path
        let path = match target.split_once("://") {
            Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or("/"),
            None => target,
        };
        let path = path.split(['?', '#']).next().unwrap_or("/");
        let normalized: Vec<String> = path.split('/').take(12).map(normalize_segment).collect();
        vec![format!("{method} {}", normalized.join("/")), format!("{method} *"), "*".into()]
    }

    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {
        if !response.starts_with(b"HTTP/") {
            return None;
        }
        // Only complete responses: a declared length that matches, and no chunking
        let end = response.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
        if head.contains("transfer-encoding: chunked") {
            return None;
        }
        let body = response.len() - end - 4;
        match head.lines().find_map(|l| l.strip_prefix("content-length:")).map(|v| v.trim().parse::<usize>()) {
            Some(Ok(length)) if length != body => None,
            Some(Err(_)) => None,
            _ => Some(response.to_vec()),
        }
    }

    fn is_failure(&self, answer: &[u8]) -> bool {
        // "HTTP/1.1 404 ..." -> 404
        let status = answer.split(|&b| b == b' ').nth(1).and_then(|s| std::str::from_utf8(s).ok()).and_then(|s| s.parse::<u16>().ok());
        status.is_some_and(|s| s >= 400)
    }
}

struct Dns;

impl Dns {
    fn message(bytes: &[u8]) -> Option<hickory_proto::op::Message> {
        // DNS over TCP carries a 2-byte length first
        let body = match bytes.len() > 2 && usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) == bytes.len() - 2 {
            true => &bytes[2..],
            false => bytes,
        };
        hickory_proto::op::Message::from_vec(body).ok()
    }
}

impl Analyzer for Dns {
    fn protocol(&self) -> &'static str {
        "dns"
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        match Dns::message(request).and_then(|m| m.queries.first().map(|q| q.query_type().to_string())) {
            Some(qtype) => vec![qtype, "*".into()],
            None => vec!["*".into()],
        }
    }

    /// As the answer lines the nucleus's DNS handler takes ("A 1.2.3.4", "NXDOMAIN"...)
    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::RData;
        let message = Dns::message(response)?;
        match message.metadata.response_code {
            ResponseCode::NXDomain => return Some(b"NXDOMAIN".to_vec()),
            ResponseCode::ServFail => return Some(b"SERVFAIL".to_vec()),
            ResponseCode::Refused => return Some(b"REFUSED".to_vec()),
            _ => {}
        }
        let lines: Vec<String> = message
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(format!("A {}", a.0)),
                RData::AAAA(a) => Some(format!("AAAA {}", a.0)),
                RData::TXT(t) => Some(format!("TXT {}", t.txt_data.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect::<String>().replace('\n', " "))),
                RData::MX(m) => Some(format!("MX {} {}", m.preference, m.exchange)),
                RData::CNAME(n) => Some(format!("CNAME {}", n.0)),
                RData::NS(n) => Some(format!("NS {}", n.0)),
                RData::PTR(n) => Some(format!("PTR {}", n.0)),
                _ => None,
            })
            .collect();
        Some(lines.join("\n").into_bytes())
    }

    fn is_failure(&self, answer: &[u8]) -> bool {
        answer.is_empty() || matches!(answer, b"NXDOMAIN" | b"SERVFAIL" | b"REFUSED")
    }
}

/// Line protocols: keyed by their command (IMAP: after the tag)
struct Lines {
    protocol: &'static str,
    tag_first: bool,
}

impl Analyzer for Lines {
    fn protocol(&self) -> &'static str {
        self.protocol
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        if request.is_empty() {
            return vec![GREETING.into()];
        }
        let line = String::from_utf8_lossy(&request[..request.len().min(1024)]);
        let mut words = line.split_whitespace();
        if self.tag_first {
            words.next();
        }
        let command: String = words.next().unwrap_or("").chars().filter(char::is_ascii_alphanumeric).take(16).collect::<String>().to_ascii_uppercase();
        vec![command, "*".into()]
    }
}

/// Redis (RESP): keyed by the command name in the first bulk string
struct Redis;

impl Analyzer for Redis {
    fn protocol(&self) -> &'static str {
        "redis"
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(&request[..request.len().min(1024)]);
        let command = match text.starts_with('*') {
            true => text.split("\r\n").nth(2).unwrap_or(""),
            false => text.split_whitespace().next().unwrap_or(""), // Inline commands
        };
        vec![command.chars().filter(char::is_ascii_alphanumeric).take(16).collect::<String>().to_ascii_uppercase(), "*".into()]
    }
}

/// A topic or path with its variable segments typed (`bots/{n}/tasks`)
fn normalize_path(path: &str, separator: char) -> String {
    path.split(separator).take(12).map(normalize_segment).collect::<Vec<_>>().join(&separator.to_string())
}

/// MQTT: keyed by packet type and topic; the stored answer is the body of the first message
/// the server PUBLISHed (what the nucleus's MQTT handler sends a subscriber)
struct Mqtt;

/// MQTT packets in `bytes`: (type, flags, body)
fn mqtt_packets(mut bytes: &[u8]) -> Vec<(u8, u8, &[u8])> {
    let mut packets = Vec::new();
    while let Some(&first) = bytes.first() {
        let (mut length, mut used) = (0usize, 1usize);
        loop {
            let Some(&byte) = bytes.get(used) else { return packets };
            length |= usize::from(byte & 0x7f) << (7 * (used - 1));
            used += 1;
            if byte & 0x80 == 0 || used > 4 {
                break;
            }
        }
        let Some(body) = bytes.get(used..used + length) else { return packets };
        packets.push((first >> 4, first & 0x0f, body));
        bytes = &bytes[used + length..];
        if packets.len() >= 64 {
            break;
        }
    }
    packets
}

/// A length-prefixed MQTT string at the start of `body`
fn mqtt_string(body: &[u8]) -> Option<(&str, &[u8])> {
    let length = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
    let text = std::str::from_utf8(body.get(2..2 + length)?).ok()?;
    Some((text, &body[2 + length..]))
}

const MQTT_TYPES: [&str; 16] = ["RESERVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH"];

impl Mqtt {
    fn key(packet: &str, topic: Option<&str>) -> Vec<String> {
        match topic {
            Some(topic) => vec![format!("{packet} {}", normalize_path(topic, '/')), format!("{packet} *"), "*".into()],
            None => vec![packet.to_string(), "*".into()],
        }
    }
}

impl Analyzer for Mqtt {
    fn protocol(&self) -> &'static str {
        "mqtt"
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        let Some(&(kind, _, body)) = mqtt_packets(request).iter().find(|(kind, _, _)| matches!(kind, 3 | 8)) else {
            return vec!["*".into()];
        };
        // PUBLISH: topic first; SUBSCRIBE: packet id, then (v3.1.1) the first topic
        let topic = match kind {
            3 => mqtt_string(body).map(|(t, _)| t),
            _ => body.get(2..).and_then(mqtt_string).map(|(t, _)| t),
        };
        Mqtt::key(MQTT_TYPES[usize::from(kind)], topic)
    }

    fn keys_for_event(&self, _payload: &[u8], meta: &serde_json::Value) -> Vec<String> {
        let packet = meta["packet"].as_str().unwrap_or("");
        let topic = meta["topic"].as_str().or_else(|| meta["topics"][0].as_str());
        Mqtt::key(packet, topic)
    }

    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {
        let (_, flags, body) = mqtt_packets(response).into_iter().find(|(kind, _, _)| *kind == 3)?;
        let (_, rest) = mqtt_string(body)?;
        // QoS 1 and 2 carry a packet id (v3.1.1 layout)
        let message = if flags & 0x06 != 0 { rest.get(2..)? } else { rest };
        Some(message.to_vec())
    }
}

/// CoAP (RFC 7252): keyed by method and Uri-Path; the stored answer is the response payload
struct Coap;

const COAP_METHODS: [&str; 8] = ["EMPTY", "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "IPATCH"];

/// A CoAP message: (code, Uri-Path, payload)
fn coap_parse(message: &[u8]) -> Option<(u8, String, &[u8])> {
    if message.len() < 4 || message[0] >> 6 != 1 {
        return None;
    }
    let mut at = 4 + usize::from(message[0] & 0x0f);
    let mut option = 0u32;
    let mut path = Vec::new();
    while let Some(&byte) = message.get(at) {
        if byte == 0xff {
            return Some((message[1], format!("/{}", path.join("/")), message.get(at + 1..).unwrap_or_default()));
        }
        at += 1;
        let mut extended = |nibble: u8| -> Option<u32> {
            Some(match nibble {
                13 => {
                    let value = u32::from(*message.get(at)?) + 13;
                    at += 1;
                    value
                }
                14 => {
                    let value = u32::from(u16::from_be_bytes([*message.get(at)?, *message.get(at + 1)?])) + 269;
                    at += 2;
                    value
                }
                15 => return None,
                n => u32::from(n),
            })
        };
        let delta = extended(byte >> 4)?;
        let length = extended(byte & 0x0f)? as usize;
        option += delta;
        let value = message.get(at..at + length)?;
        at += length;
        if option == 11 && path.len() < 12 {
            path.push(String::from_utf8_lossy(value).into_owned());
        }
    }
    Some((message[1], format!("/{}", path.join("/")), &[]))
}

impl Coap {
    fn key(method: &str, path: &str) -> Vec<String> {
        vec![format!("{method} {}", normalize_path(path, '/')), format!("{method} *"), "*".into()]
    }
}

impl Analyzer for Coap {
    fn protocol(&self) -> &'static str {
        "coap"
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        match coap_parse(request) {
            Some((code, path, _)) if code >> 5 == 0 => Coap::key(COAP_METHODS.get(usize::from(code & 0x1f)).copied().unwrap_or("UNKNOWN"), &path),
            _ => vec!["*".into()],
        }
    }

    fn keys_for_event(&self, _payload: &[u8], meta: &serde_json::Value) -> Vec<String> {
        Coap::key(meta["method"].as_str().unwrap_or(""), meta["path"].as_str().unwrap_or("/"))
    }

    fn stored_answer(&self, response: &[u8]) -> Option<Vec<u8>> {
        let (code, _, payload) = coap_parse(response)?;
        // Responses only (2.xx-5.xx), with something to send back
        (code >> 5 >= 2 && !payload.is_empty()).then(|| payload.to_vec())
    }

    fn is_failure(&self, _answer: &[u8]) -> bool {
        false
    }
}

/// Anything else: keyed by the first two bytes and the size class
struct Generic {
    protocol: &'static str,
}

impl Analyzer for Generic {
    fn protocol(&self) -> &'static str {
        self.protocol
    }

    fn keys(&self, request: &[u8]) -> Vec<String> {
        if request.is_empty() {
            return vec![GREETING.into()];
        }
        // Text (a C2 command, often once decoded): its first word, like a line protocol
        let sample = &request[..request.len().min(256)];
        if sample.iter().all(|&b| (0x20..0x7f).contains(&b) || b"\r\n\t".contains(&b)) {
            // The leading letters of the first token: "uptime=7" and "uptime=9" share "UPTIME"
            let word: String = String::from_utf8_lossy(sample).split_whitespace().next().unwrap_or("").chars().take_while(|c| c.is_ascii_alphabetic() || *c == '_').take(16).collect();
            if !word.is_empty() {
                return vec![format!("text:{}", word.to_ascii_uppercase()), "text:*".into(), "*".into()];
            }
        }
        let size = format!("len{}", request.len().next_power_of_two());
        let magic: String = request.iter().take(2).map(|b| format!("{b:02x}")).collect();
        vec![format!("{magic}:{size}"), size, "*".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_generalise_variable_parts() {
        let http = for_protocol("http");
        assert_eq!(http.keys(b"GET /api/v1/bots/1234/task?x=1 HTTP/1.1\r\n")[0], "GET /api/v1/bots/{n}/task");
        assert_eq!(http.keys(b"POST http://c2.example/g/0123456789abcdef HTTP/1.1\r\n")[0], "POST /g/{hex}");
        assert_eq!(http.keys(b"GET /s/6f1c2b0e-4c5a-4f0e-9a39-2b7f4d3c1a10 HTTP/1.1")[0], "GET /s/{uuid}");
        assert_eq!(http.keys(b"GET /x HTTP/1.1")[1], "GET *");
        assert_eq!(http.keys(b"GET /site=0000127709/genr=1/logs HTTP/1.1")[0], "GET /site={n}/genr={n}/logs");
        assert_eq!(for_protocol("imap").keys(b"a1 LOGIN bob pw\r\n")[0], "LOGIN");
        assert_eq!(for_protocol("smtp").keys(b"ehlo bot\r\n")[0], "EHLO");
        assert_eq!(for_protocol("smtp").keys(b"")[0], GREETING);
        assert_eq!(for_protocol("redis").keys(b"*1\r\n$4\r\nPING\r\n")[0], "PING");
        assert_eq!(for_protocol("raw").keys(b"\xde\xad\x01")[0], "dead:len4");
        assert_eq!(for_protocol("raw").keys(b"hello operator\n")[0], "text:HELLO");
        assert_eq!(for_protocol("raw").keys(b"uptime=7 user=bob")[0], for_protocol("raw").keys(b"uptime=9 user=eve")[0]);
        assert_eq!(for_protocol("nonsense").protocol(), "raw");
    }

    #[test]
    fn mqtt_and_coap_key_the_wire_and_events_alike() {
        // MQTT PUBLISH (QoS 0) of "go" to bots/1234/tasks, as captured
        let topic = b"bots/1234/tasks";
        let mut publish = vec![0x30, (2 + topic.len() + 2) as u8, 0, topic.len() as u8];
        publish.extend(topic);
        publish.extend(b"go");
        let mqtt = for_protocol("mqtt");
        assert_eq!(mqtt.keys(&publish)[0], "PUBLISH bots/{n}/tasks");
        assert_eq!(mqtt.keys_for_event(b"go", &serde_json::json!({ "packet": "PUBLISH", "topic": "bots/99/tasks" }))[0], "PUBLISH bots/{n}/tasks");
        assert_eq!(mqtt.stored_answer(&publish).unwrap(), b"go"); // The body, as the handler sends it
        let connack = [0x20, 2, 0, 0];
        assert!(mqtt.stored_answer(&connack).is_none());
        // CoAP GET /sensors/7 (confirmable, token 1 byte), and a 2.05 Content response
        let get = [0x41, 0x01, 0x12, 0x34, 0xaa, 0xb7, b's', b'e', b'n', b's', b'o', b'r', b's', 0x01, b'7'];
        let coap = for_protocol("coap");
        assert_eq!(coap.keys(&get)[0], "GET /sensors/{n}");
        assert_eq!(coap.keys_for_event(b"", &serde_json::json!({ "method": "GET", "path": "/sensors/12" }))[0], "GET /sensors/{n}");
        let content = [0x61, 0x45, 0x12, 0x34, 0xaa, 0xff, b'2', b'1', b'.', b'5'];
        assert_eq!(coap.stored_answer(&content).unwrap(), b"21.5");
        assert!(coap.stored_answer(&get).is_none()); // A request isn't an answer
        assert!(coap.keys(&[0x41, 0x01, 0, 0, 0, 0xf0]).len() == 1); // Malformed option: no panic
    }

    #[test]
    fn stores_only_usable_answers() {
        let http = for_protocol("http");
        assert!(http.stored_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_some());
        assert!(http.stored_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nok").is_none()); // Cut short
        assert!(http.stored_answer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n").is_none());
        assert!(http.stored_answer(b"garbage").is_none());
    }

    #[test]
    fn dns_answers_become_handler_lines() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
        let name = Name::from_ascii("c2.example.").unwrap();
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name.clone(), RecordType::A));
        let mut answer = Message::new(7, MessageType::Response, OpCode::Query);
        answer.add_query(Query::query(name.clone(), RecordType::A));
        answer.add_answer(Record::from_rdata(name, 60, RData::A(A("198.51.100.7".parse().unwrap()))));
        let dns = for_protocol("dns");
        assert_eq!(dns.keys(&query.to_vec().unwrap())[0], "A");
        assert_eq!(dns.stored_answer(&answer.to_vec().unwrap()).unwrap(), b"A 198.51.100.7");
    }

    #[test]
    fn identifies_protocols_from_the_first_bytes() {
        assert_eq!(identify(Transport::Tcp, 8080, b"GET / HTTP/1.1\r\n"), "http");
        assert_eq!(identify(Transport::Tcp, 443, b"\x16\x03\x01\x00\x10"), "tls");
        assert_eq!(identify(Transport::Tcp, 25, b""), "smtp"); // The server speaks first
    }
}
