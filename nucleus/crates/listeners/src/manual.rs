//! Live manual mode: matching requests are held while the analyst reads them in the
//! dashboard and sends the proposed answer (a rule's, the explorer's or the handler's
//! default), an edited one, or closes the connection. A request nobody answers gets the
//! proposed answer after `timeout_ms`.
//!
//! This deliberately waits past the daemon deadline: it is off by default, and only the
//! requests the filter selects wait.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fakenet_schema::Event;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::event_filter::{host_of, request_text, EventFilter};

/// Requests held at once; past it new ones get the proposed answer straight away
const MAX_PENDING: usize = 256;
/// The payload shown per request (the full payload is in events.jsonl)
const MAX_SHOWN: usize = 64 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ManualConfig {
    pub enabled: bool,
    /// How long a held request waits for the analyst before the proposed answer goes
    pub timeout_ms: u64,
    #[serde(flatten)]
    pub filter: EventFilter,
}

impl Default for ManualConfig {
    fn default() -> Self {
        ManualConfig { enabled: false, timeout_ms: 120_000, filter: EventFilter::default() }
    }
}

/// What the analyst chose for a held request
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The proposed answer (also what a timeout gives)
    Proposed,
    Send { response: Vec<u8>, close: bool },
    /// Close the connection without answering
    Close,
}

struct Pending {
    shown: Value,
    reply: oneshot::Sender<Verdict>,
}

pub struct Manual {
    config: ManualConfig,
    pending: Mutex<BTreeMap<u64, Pending>>,
    next: AtomicU64,
}

impl Manual {
    pub fn new(config: ManualConfig) -> Manual {
        Manual { config, pending: Mutex::new(BTreeMap::new()), next: AtomicU64::new(1) }
    }

    pub fn config(&self) -> &ManualConfig {
        &self.config
    }

    pub fn wants(&self, event: &Event) -> bool {
        self.config.enabled && event.expects_reply && self.config.filter.matches(event)
    }

    /// Holds `event` until the analyst decides or the timeout passes
    pub async fn hold(&self, event: &Event, proposed: Option<&[u8]>, close: bool) -> Verdict {
        let (sender, receiver) = oneshot::channel();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if pending.len() >= MAX_PENDING {
                return Verdict::Proposed;
            }
            let held_at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            let shown = json!({
                "id": id,
                "held_at_ms": held_at,
                "expires_at_ms": held_at + self.config.timeout_ms,
                "session_id": event.session_id,
                "request_id": event.request_id,
                "protocol": event.protocol,
                "transport": event.transport,
                "tls": event.tls,
                "src": event.src,
                "dst": format!("{}:{}", event.dst, event.dport),
                "host": host_of(event),
                "request": request_text(event),
                "process": event.process,
                "meta": event.meta,
                "payload": fakenet_schema::encode_base64(&event.payload[..event.payload.len().min(MAX_SHOWN)]),
                "payload_bytes": event.payload.len(),
                "proposed": proposed.map(fakenet_schema::encode_base64),
                "proposed_close": close,
            });
            pending.insert(id, Pending { shown, reply: sender });
        }
        let verdict = tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), receiver).await;
        // Gone already when answered; removed here on timeout (or a dropped sender)
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        match verdict {
            Ok(Ok(verdict)) => verdict,
            _ => Verdict::Proposed,
        }
    }

    /// The held requests, oldest first
    pub fn pending(&self) -> Vec<Value> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).values().map(|p| p.shown.clone()).collect()
    }

    /// Answers held request `id`; false if it isn't held (answered, or timed out)
    pub fn resolve(&self, id: u64, verdict: Verdict) -> bool {
        let held = self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        match held {
            Some(held) => held.reply.send(verdict).is_ok(),
            None => false,
        }
    }

    /// Releases every held request with its proposed answer (at shutdown)
    pub fn release_all(&self) {
        let held = std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()));
        for (_, pending) in held {
            let _ = pending.reply.send(Verdict::Proposed);
        }
    }
}

/// A verdict from the dashboard's JSON: `{"action": "proposed" | "send" | "close",
/// "response": "<text>" or "response_base64": "...", "close": bool}`
pub fn parse_verdict(body: &Value) -> Result<Verdict, String> {
    match body["action"].as_str() {
        Some("proposed") => Ok(Verdict::Proposed),
        Some("close") => Ok(Verdict::Close),
        Some("send") => {
            let response = match (body["response_base64"].as_str(), body["response"].as_str()) {
                (Some(encoded), _) => fakenet_schema::decode_base64(encoded).map_err(|e| format!("response_base64: {e}"))?,
                (None, Some(text)) => text.as_bytes().to_vec(),
                (None, None) => return Err("send needs response or response_base64".into()),
            };
            Ok(Verdict::Send { response, close: body["close"].as_bool().unwrap_or(false) })
        }
        _ => Err("action must be proposed, send or close".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fakenet_schema::Protocol;
    use std::sync::Arc;

    fn event() -> Event {
        serde_json::from_value(json!({
            "version": 1, "type": "event", "request_id": "r1", "session_id": "s1", "seq": 1,
            "protocol": "http", "transport": "tcp", "src": "10.0.0.5:4000", "dst": "198.18.0.7", "dport": 80,
            "timestamp": "2026-01-01T00:00:00Z", "payload": "R0VU", "meta": { "method": "GET", "path": "/gate.php", "host": "c2.example" },
            "expects_reply": true,
        }))
        .unwrap()
    }

    fn manual(timeout_ms: u64) -> Arc<Manual> {
        Arc::new(Manual::new(ManualConfig { enabled: true, timeout_ms, filter: EventFilter { protocols: vec![Protocol::Http], ..Default::default() } }))
    }

    #[tokio::test]
    async fn the_analyst_answers_a_held_request() {
        let manual = manual(5_000);
        let held = { let manual = manual.clone(); tokio::spawn(async move { manual.hold(&event(), Some(b"default"), false).await }) };
        let shown = loop {
            if let Some(shown) = manual.pending().pop() {
                break shown;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(shown["request"], "GET /gate.php");
        assert_eq!(shown["proposed"], fakenet_schema::encode_base64(b"default"));
        let id = shown["id"].as_u64().unwrap();
        assert!(manual.resolve(id, Verdict::Send { response: b"edited".to_vec(), close: true }));
        assert_eq!(held.await.unwrap(), Verdict::Send { response: b"edited".to_vec(), close: true });
        assert!(manual.pending().is_empty());
        assert!(!manual.resolve(id, Verdict::Close)); // Already answered
    }

    #[tokio::test]
    async fn unanswered_requests_get_the_proposed_answer() {
        let manual = manual(50);
        assert_eq!(manual.hold(&event(), None, false).await, Verdict::Proposed);
        assert!(manual.pending().is_empty());
        let mut dns = event();
        dns.protocol = Protocol::Dns;
        assert!(!manual.wants(&dns));
        assert!(manual.wants(&event()));
    }

    #[test]
    fn parses_verdicts() {
        assert_eq!(parse_verdict(&json!({ "action": "proposed" })), Ok(Verdict::Proposed));
        assert_eq!(parse_verdict(&json!({ "action": "send", "response": "hi", "close": true })), Ok(Verdict::Send { response: b"hi".to_vec(), close: true }));
        assert_eq!(parse_verdict(&json!({ "action": "send", "response_base64": "AAE=" })), Ok(Verdict::Send { response: vec![0, 1], close: false }));
        assert!(parse_verdict(&json!({ "action": "send" })).is_err());
        assert!(parse_verdict(&json!({ "action": "rm -rf" })).is_err());
    }
}
