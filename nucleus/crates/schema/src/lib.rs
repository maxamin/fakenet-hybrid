//! The link messages between the nucleus and the Camel daemon: version 1 of
//! `schema/fakenet-link-v1.schema.json`. Unknown fields are ignored on input, so the daemon
//! may add fields without breaking older nuclei.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Dns,
    Raw,
    Smtp,
    Pop3,
    Ftp,
    Tftp,
    Irc,
    Imap,
    Ssh,
    Telnet,
    Redis,
    Ntp,
    Socks,
    Syslog,
    Echo,
    Discard,
    Daytime,
    Chargen,
    Time,
    Qotd,
    Finger,
    Whois,
    Mqtt,
    Coap,
    Vnc,
    Rdp,
    Ldap,
    Smb,
    Websocket,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Dns => "dns",
            Protocol::Raw => "raw",
            Protocol::Smtp => "smtp",
            Protocol::Pop3 => "pop3",
            Protocol::Ftp => "ftp",
            Protocol::Tftp => "tftp",
            Protocol::Irc => "irc",
            Protocol::Imap => "imap",
            Protocol::Ssh => "ssh",
            Protocol::Telnet => "telnet",
            Protocol::Redis => "redis",
            Protocol::Ntp => "ntp",
            Protocol::Socks => "socks",
            Protocol::Syslog => "syslog",
            Protocol::Echo => "echo",
            Protocol::Discard => "discard",
            Protocol::Daytime => "daytime",
            Protocol::Chargen => "chargen",
            Protocol::Time => "time",
            Protocol::Qotd => "qotd",
            Protocol::Finger => "finger",
            Protocol::Whois => "whois",
            Protocol::Mqtt => "mqtt",
            Protocol::Coap => "coap",
            Protocol::Vnc => "vnc",
            Protocol::Rdp => "rdp",
            Protocol::Ldap => "ldap",
            Protocol::Smb => "smb",
            Protocol::Websocket => "websocket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

/// Something the malware sent (nucleus → daemon)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: EventKind,
    pub request_id: String,
    pub session_id: String,
    pub seq: u64,
    pub protocol: Protocol,
    pub transport: Transport,
    #[serde(default)]
    pub tls: bool,
    pub src: String,
    pub dst: String,
    pub dport: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    /// RFC 3339, UTC
    pub timestamp: String,
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub meta: Value,
    pub expects_reply: bool,
    /// HMAC when the link has a shared secret (see `auth`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Event,
}

/// How to answer one event (daemon → nucleus)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: ActionKind,
    pub request_id: String,
    pub session_id: String,
    /// None: use the nucleus's built-in default response
    #[serde(default, with = "optional_base64_bytes", skip_serializing_if = "Option::is_none")]
    pub response: Option<Vec<u8>>,
    #[serde(default)]
    pub close: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// HMAC when the link has a shared secret (see `auth`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

/// The WebSocket handshake: the nucleus sends a random nonce; the daemon proves it holds
/// the shared secret by returning it with `auth`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    #[serde(rename = "type")]
    pub kind: HelloKind,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HelloKind {
    Hello,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Action,
}

/// Message authentication with a shared secret: lowercase hex HMAC-SHA256 over a
/// canonical text of the message's key fields (the daemon computes the same text):
/// - hello:  "fakenet-link-v1 hello\n{nonce}"
/// - event:  "fakenet-link-v1 event\n{request_id}\n{session_id}\n{payload base64}"
/// - action: "fakenet-link-v1 action\n{request_id}\n{session_id}\n{response base64 or -}\n{close}\n{delay_ms or -}"
/// The key is the secret file's contents, trimmed.
pub mod auth {

    use ring::hmac;

    #[derive(Clone)]
    pub struct Secret(hmac::Key);

    impl std::fmt::Debug for Secret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Secret(..)")
        }
    }

    impl Secret {
        pub fn new(key: &[u8]) -> Secret {
            Secret(hmac::Key::new(hmac::HMAC_SHA256, key))
        }

        pub fn sign(&self, text: &str) -> String {
            hmac::sign(&self.0, text.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect()
        }

        /// Constant-time check of a hex signature
        pub fn verify(&self, text: &str, signature: Option<&str>) -> bool {
            let Some(bytes) = signature.and_then(decode_hex) else { return false };
            hmac::verify(&self.0, text.as_bytes(), &bytes).is_ok()
        }
    }

    fn decode_hex(text: &str) -> Option<Vec<u8>> {
        if text.len() % 2 != 0 {
            return None;
        }
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
    }

    /// A random hex string (nonces, generated secrets)
    pub fn random_hex(bytes: usize) -> String {
        use ring::rand::SecureRandom;
        let mut buffer = vec![0u8; bytes];
        ring::rand::SystemRandom::new().fill(&mut buffer).expect("system randomness");
        buffer.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn hello_text(nonce: &str) -> String {
        format!("fakenet-link-v2 hello\n{nonce}")
    }

    /// Events and actions are signed whole: the MAC covers this prefix plus the exact JSON
    /// text sent, without its `auth` member, which is appended last. Every field is covered,
    /// and neither side has to reproduce the other's JSON formatting.
    pub const SEALED: &str = "fakenet-link-v2\n";
    /// `,"auth":"` + 64 hex digits + `"}`
    const SEAL_SUFFIX: usize = 9 + 64 + 2;

    /// Appends `"auth"` (the MAC of `json`) as the last member of the JSON object `json`
    pub fn seal(secret: &Secret, json: &str) -> String {
        let json = json.trim_end();
        let mac = secret.sign(&format!("{SEALED}{json}"));
        let open = json.strip_suffix('}').unwrap_or(json);
        let separator = if open.trim_end().ends_with('{') { "" } else { "," };
        format!("{open}{separator}\"auth\":\"{mac}\"}}")
    }

    /// Checks a sealed message; true when its MAC covers everything before `auth`
    pub fn unseal(secret: &Secret, text: &str) -> bool {
        let text = text.trim_end();
        let Some(split) = text.len().checked_sub(SEAL_SUFFIX) else { return false };
        let (Some(body), Some(suffix)) = (text.get(..split), text.get(split..)) else { return false };
        let Some(mac) = suffix.strip_prefix(",\"auth\":\"").and_then(|s| s.strip_suffix("\"}")) else { return false };
        if mac.len() != 64 || !mac.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return false;
        }
        secret.verify(&format!("{SEALED}{body}}}"), Some(mac))
    }
}

/// The most a daemon may ask the nucleus to wait before replying
pub const MAX_DELAY_MS: u64 = 60_000;

impl Action {
    /// Checks an Action is a valid answer to `event` (version, correlation, limits)
    pub fn validate_for(&self, event: &Event) -> Result<(), String> {
        if self.version != VERSION {
            return Err(format!("unsupported version {}", self.version));
        }
        if self.request_id != event.request_id || self.session_id != event.session_id {
            return Err("request_id/session_id don't match the event".into());
        }
        if self.delay_ms.is_some_and(|d| d > MAX_DELAY_MS) {
            return Err(format!("delay_ms over {MAX_DELAY_MS}"));
        }
        Ok(())
    }
}

/// Builds events, numbering them within their session. Clones share the numbering (one
/// session's concurrent requests: HTTP/2 streams, UDP datagrams)
#[derive(Clone)]
pub struct EventBuilder {
    pub session_id: String,
    next_seq: std::sync::Arc<AtomicU64>,
    pub protocol: Protocol,
    pub transport: Transport,
    pub tls: bool,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub process: Option<ProcessInfo>,
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A new session ID, unique within this nucleus run ("tcp-0000000000000007")
pub fn new_session_id(transport: Transport) -> String {
    let prefix = match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    };
    format!("{prefix}-{:016}", SESSION_COUNTER.fetch_add(1, Ordering::Relaxed))
}

impl EventBuilder {
    pub fn new(protocol: Protocol, transport: Transport, src: SocketAddr, dst: SocketAddr) -> EventBuilder {
        EventBuilder {
            session_id: new_session_id(transport),
            next_seq: Default::default(),
            protocol,
            transport,
            tls: false,
            src,
            dst,
            process: None,
        }
    }

    pub fn event(&mut self, payload: Vec<u8>, meta: Value, expects_reply: bool) -> Event {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        Event {
            version: VERSION,
            kind: EventKind::Event,
            request_id: uuid::Uuid::new_v4().to_string(),
            session_id: self.session_id.clone(),
            seq,
            protocol: self.protocol,
            transport: self.transport,
            tls: self.tls,
            src: self.src.to_string(),
            dst: self.dst.to_string(),
            dport: self.dst.port(),
            process: self.process.clone(),
            timestamp: now_rfc3339(),
            payload,
            meta,
            expects_reply,
            auth: None,
        }
    }
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

pub fn encode_base64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(text)
}

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode_base64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::decode_base64(&text).map_err(serde::de::Error::custom)
    }
}

mod optional_base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_str(&super::encode_base64(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            Some(text) => super::decode_base64(&text).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors are checked by the daemon's LinkAuthTest: both sides must agree
    #[test]
    fn signatures_match_the_shared_vectors() {
        let secret = auth::Secret::new(b"0123456789abcdef0123456789abcdef");
        assert_eq!(secret.sign(&auth::hello_text("nonce42")), "ff24b35c3d3f7b507784ce66fb2716df6f0ba55d8d5d5b89a1d4fbd5ce7209e8");
        let event = r#"{"version":2,"type":"event","request_id":"req-1","session_id":"tcp-0000000000000001","payload":"UElORw=="}"#;
        let sealed = auth::seal(&secret, event);
        assert_eq!(sealed, format!("{},\"auth\":\"0a0efe72bc4a479c99323926e3ce6910eea50038f8ff9b27237fe980726ae88e\"}}", &event[..event.len() - 1]));
        assert!(auth::unseal(&secret, &sealed));
        let action = r#"{"version":2,"type":"action","request_id":"req-1","session_id":"tcp-0000000000000001","response":"UE9ORwo=","close":false,"route":"c2"}"#;
        assert!(auth::seal(&secret, action).ends_with(r#""auth":"bb6015bd0446842a83729ae706287bbc4d5cd74277646c855d20fc7f47da1b69"}"#));
    }

    #[test]
    fn every_field_is_sealed() {
        let secret = auth::Secret::new(b"0123456789abcdef0123456789abcdef");
        let sealed = auth::seal(&secret, r#"{"type":"event","protocol":"http","meta":{"host":"c2.example"},"dport":80}"#);
        assert!(auth::unseal(&secret, &sealed));
        assert!(auth::unseal(&secret, &format!("{sealed}\n"))); // Trailing whitespace is fine
        for (from, to) in [("http", "dns!"), ("c2.example", "c3.example"), ("80", "81")] {
            assert!(!auth::unseal(&secret, &sealed.replacen(from, to, 1)), "{from} -> {to} went unnoticed");
        }
        assert!(!auth::unseal(&auth::Secret::new(b"another-secret-another-secret-xx"), &sealed));
        assert!(!auth::unseal(&secret, r#"{"type":"event"}"#)); // Unsigned
        assert!(!auth::unseal(&secret, ""));
        assert_eq!(auth::seal(&secret, "{}").len(), r#"{"auth":""}"#.len() + 64);
    }

    const EXAMPLES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../schema/examples");

    fn example(name: &str) -> String {
        std::fs::read_to_string(format!("{EXAMPLES}/{name}.json")).unwrap()
    }

    #[test]
    fn parses_the_shared_schema_examples() {
        let event: Event = serde_json::from_str(&example("event-http")).unwrap();
        assert_eq!(event.protocol, Protocol::Http);
        assert_eq!(event.dport, 80);
        assert!(event.payload.starts_with(b"GET /gate?id=42 HTTP/1.1\r\n"));
        assert_eq!(event.meta["host"], "c2.evil.example");

        let action: Action = serde_json::from_str(&example("action-http")).unwrap();
        assert!(action.response.unwrap().ends_with(br#"{"cmd":"sleep","n":60}"#));
        assert_eq!(action.route.as_deref(), Some("http-c2-gate"));

        let default: Action = serde_json::from_str(&example("action-default")).unwrap();
        assert_eq!(default.response, None);
        assert!(!default.close);
    }

    #[test]
    fn round_trips_and_ignores_unknown_fields() {
        let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1000".parse().unwrap(), "1.2.3.4:4444".parse().unwrap());
        let first = builder.event(vec![0, 1, 255], serde_json::json!({}), true);
        let second = builder.event(vec![], Value::Null, false);
        assert_eq!((first.seq, second.seq), (0, 1));
        assert_eq!(first.session_id, second.session_id);
        assert_ne!(first.request_id, second.request_id);
        assert!(first.session_id.starts_with("tcp-"));

        let json = serde_json::to_value(&first).unwrap();
        assert_eq!(json["type"], "event");
        assert_eq!(json["payload"], "AAH/");
        assert_eq!(serde_json::from_value::<Event>(json).unwrap(), first);

        let mut with_extra: Value = serde_json::from_str(&example("action-http")).unwrap();
        with_extra["future_field"] = serde_json::json!({"x": 1});
        assert!(serde_json::from_value::<Action>(with_extra).is_ok());
    }

    #[test]
    fn validates_actions_against_their_event() {
        let event: Event = serde_json::from_str(&example("event-http")).unwrap();
        let action: Action = serde_json::from_str(&example("action-http")).unwrap();
        assert!(action.validate_for(&event).is_ok());

        let wrong_request = Action { request_id: "other".into(), ..action.clone() };
        assert!(wrong_request.validate_for(&event).is_err());
        let wrong_version = Action { version: 1, ..action.clone() };
        assert!(wrong_version.validate_for(&event).unwrap_err().contains("version"));
        let too_slow = Action { delay_ms: Some(MAX_DELAY_MS + 1), ..action };
        assert!(too_slow.validate_for(&event).is_err());
        assert!(serde_json::from_str::<Action>(r#"{"version":1,"type":"action","request_id":"a","session_id":"b","response":"!!"}"#).is_err());
    }
}
