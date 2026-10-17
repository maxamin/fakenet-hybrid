//! The link messages between the nucleus and the Camel daemon: version 1 of
//! `schema/fakenet-link-v1.schema.json`. Unknown fields are ignored on input, so the daemon
//! may add fields without breaking older nuclei.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 1;

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
    use super::{encode_base64, Action, Event};
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
        format!("fakenet-link-v1 hello\n{nonce}")
    }

    pub fn event_text(event: &Event) -> String {
        format!("fakenet-link-v1 event\n{}\n{}\n{}", event.request_id, event.session_id, encode_base64(&event.payload))
    }

    pub fn action_text(action: &Action) -> String {
        let response = action.response.as_deref().map(encode_base64).unwrap_or_else(|| "-".into());
        let delay = action.delay_ms.map(|d| d.to_string()).unwrap_or_else(|| "-".into());
        format!("fakenet-link-v1 action\n{}\n{}\n{response}\n{}\n{delay}", action.request_id, action.session_id, action.close)
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

/// Builds events, numbering them within their session
pub struct EventBuilder {
    pub session_id: String,
    next_seq: u64,
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
            next_seq: 0,
            protocol,
            transport,
            tls: false,
            src,
            dst,
            process: None,
        }
    }

    pub fn event(&mut self, payload: Vec<u8>, meta: Value, expects_reply: bool) -> Event {
        let seq = self.next_seq;
        self.next_seq += 1;
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
        assert_eq!(secret.sign(&auth::hello_text("nonce42")), "df550b26dfd2e6b34bf9c9a0b701fc3b610783c1d198aa87a4ee8525f82e87e7");
        let mut builder = EventBuilder::new(Protocol::Raw, Transport::Tcp, "10.0.0.5:1".parse().unwrap(), "1.2.3.4:2".parse().unwrap());
        let mut event = builder.event(b"PING".to_vec(), Value::Null, true);
        event.request_id = "req-1".into();
        event.session_id = "tcp-0000000000000001".into();
        assert_eq!(secret.sign(&auth::event_text(&event)), "3a16f8a98d04c4d3b4fe60739099b2f579949d6a0f9ab2154881a500fe373508");
        let action = Action {
            version: VERSION, kind: ActionKind::Action, request_id: "req-1".into(), session_id: "tcp-0000000000000001".into(),
            response: Some(b"PONG\n".to_vec()), close: false, delay_ms: None, route: None, auth: None,
        };
        assert_eq!(secret.sign(&auth::action_text(&action)), "cd9cdbbe8ac362d384c0eb0e591bf95301297bf668f0fbde4547bf8244af10d3");
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
        let wrong_version = Action { version: 2, ..action.clone() };
        assert!(wrong_version.validate_for(&event).unwrap_err().contains("version"));
        let too_slow = Action { delay_ms: Some(MAX_DELAY_MS + 1), ..action };
        assert!(too_slow.validate_for(&event).is_err());
        assert!(serde_json::from_str::<Action>(r#"{"version":1,"type":"action","request_id":"a","session_id":"b","response":"!!"}"#).is_err());
    }
}
