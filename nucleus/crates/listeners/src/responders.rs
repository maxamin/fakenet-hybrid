//! Responders: pluggable answer sources consulted, in config order, when neither the
//! daemon's rules nor the explorer answered. The first one that answers wins; the rest of
//! the time the handler's built-in default applies.
//!
//! - `model`: a learned traffic model (`fakenet_model`): answers the way real servers did,
//!   at random, in proportion to how often each answer was seen.
//! - `plugin`: an external program, in any language, speaking JSON lines on stdin/stdout
//!   (see `PluginResponder`): community generators, Radamsa wrappers, ML models.
//!
//! Each `[[responder]]` takes the event filter keys (`protocols`, `hosts`, `contains`) and a
//! `rate` (the share of matching requests it answers).

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fakenet_schema::Event;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::event_filter::EventFilter;

/// What a responder offers for a request
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub response: Vec<u8>,
    pub close: bool,
    /// Logged as the decision's route (e.g. "model:GET /gate/{n}")
    pub route: String,
    /// Logged with it (e.g. the answer's probability)
    pub detail: Value,
}

pub type Respond<'a> = Pin<Box<dyn Future<Output = Option<Proposal>> + Send + 'a>>;

pub trait Responder: Send + Sync {
    fn name(&self) -> &str;
    /// An answer for `event` (`default`: the handler's built-in answer, when known), or None
    fn respond<'a>(&'a self, event: &'a Event, default: Option<&'a [u8]>) -> Respond<'a>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponderKind {
    Model,
    Plugin,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcomes {
    #[default]
    Successful,
    All,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponderConfig {
    pub name: String,
    pub kind: ResponderKind,
    /// `model`: model packs (JSON), merged
    #[serde(default)]
    pub packs: Vec<PathBuf>,
    /// `plugin`: the program and its arguments (no shell)
    #[serde(default)]
    pub command: Vec<String>,
    /// `plugin`: how long an answer may take (keep it under the daemon deadline)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The share of matching requests it answers (0..=1)
    #[serde(default = "default_rate")]
    pub rate: f64,
    /// `model`: `successful` (default: answers that keep the sample going) or `all` (the
    /// recorded distribution, failures such as NXDOMAIN and HTTP errors included)
    #[serde(default)]
    pub outcomes: Outcomes,
    /// `model`: decoding steps applied to a request before looking it up, as it was learned
    /// with (`--learn --transform ...`): base64, hex, xor:KEY, rc4:KEY, skip:N
    #[serde(default)]
    pub key_transforms: Vec<String>,
    #[serde(flatten)]
    pub filter: EventFilter,
}

fn default_timeout_ms() -> u64 {
    150
}

fn default_rate() -> f64 {
    1.0
}

/// Builds the configured responders (model packs are loaded now, so a bad pack fails the start)
pub fn build(configs: &[ResponderConfig]) -> anyhow::Result<Vec<Arc<dyn Responder>>> {
    let mut responders: Vec<Arc<dyn Responder>> = Vec::new();
    for config in configs {
        anyhow::ensure!((0.0..=1.0).contains(&config.rate), "[[responder]] {}: rate must be between 0 and 1", config.name);
        let gate = Gate { filter: config.filter.clone(), rate: config.rate, rng: Mutex::new(fakenet_model::Rng::from_time()) };
        match config.kind {
            ResponderKind::Model => {
                anyhow::ensure!(!config.packs.is_empty(), "[[responder]] {}: a model needs packs = [\"...json\"]", config.name);
                let model = fakenet_model::Model::load(&config.packs).map_err(|e| anyhow::anyhow!("[[responder]] {}: {e:#}", config.name))?;
                let key_transforms = config.key_transforms.iter().map(|t| fakenet_model::transform::parse_transform(t)).collect::<anyhow::Result<Vec<_>>>().map_err(|e| anyhow::anyhow!("[[responder]] {}: key_transforms: {e:#}", config.name))?;
                responders.push(Arc::new(ModelResponder { name: config.name.clone(), model, gate, successful_only: config.outcomes == Outcomes::Successful, key_transforms }));
            }
            ResponderKind::Plugin => {
                anyhow::ensure!(!config.command.is_empty(), "[[responder]] {}: a plugin needs command = [\"program\", ...]", config.name);
                responders.push(Arc::new(PluginResponder::new(config.name.clone(), config.command.clone(), Duration::from_millis(config.timeout_ms), gate)));
            }
        }
    }
    Ok(responders)
}

/// The filter and rate every responder applies first
pub(crate) struct Gate {
    filter: EventFilter,
    rate: f64,
    rng: Mutex<fakenet_model::Rng>,
}

impl Gate {
    fn admits(&self, event: &Event) -> bool {
        if !event.expects_reply || !self.filter.matches(event) {
            return false;
        }
        self.rate >= 1.0 || (self.rng.lock().unwrap_or_else(|e| e.into_inner()).below(1_000_000) as f64) < self.rate * 1_000_000.0
    }
}

/// Answers from a learned traffic model
pub struct ModelResponder {
    name: String,
    model: fakenet_model::Model,
    gate: Gate,
    successful_only: bool,
    key_transforms: Vec<fakenet_model::transform::Transform>,
}

impl Responder for ModelResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn respond<'a>(&'a self, event: &'a Event, _default: Option<&'a [u8]>) -> Respond<'a> {
        Box::pin(async move {
            if !self.gate.admits(event) {
                return None;
            }
            let protocol = event.protocol.name();
            let sampled = {
                let mut rng = self.gate.rng.lock().unwrap_or_else(|e| e.into_inner());
                // Looked up as learned: decoded the same way (or as sent, if it doesn't decode)
                let decoded = (!self.key_transforms.is_empty()).then(|| fakenet_model::transform::apply(&self.key_transforms, &event.payload).ok()).flatten();
                self.model.answer_event(protocol, decoded.as_deref().unwrap_or(&event.payload), &event.meta, &mut rng, self.successful_only)?
            };
            Some(Proposal {
                response: sampled.bytes,
                close: false,
                route: format!("{}:{}", self.name, sampled.key),
                detail: json!({ "key": sampled.key, "probability": (sampled.probability * 1000.0).round() / 1000.0 }),
            })
        })
    }
}

/// A long-lived external program answering over JSON lines.
///
/// To the plugin, one line per request:
/// `{"type":"respond","id":7,"protocol":"http","event":{...the Event...},"default_base64":"..."}`
/// (`default_base64` only when the handler's default is known). From the plugin, one line
/// per answer, in any order: `{"id":7,"response_base64":"...","close":false,"route":"x"}`, or
/// `{"id":7,"skip":true}`. Answers later than `timeout_ms` are dropped. The plugin's stderr is
/// the nucleus's; if it exits it is restarted, at most every 5 seconds.
pub struct PluginResponder {
    name: String,
    command: Vec<String>,
    timeout: Duration,
    gate: Gate,
    process: tokio::sync::Mutex<Option<Running>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    next_id: AtomicU64,
    last_start: Mutex<Option<Instant>>,
}

struct Running {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
}

/// The longest line read from a plugin
const MAX_PLUGIN_LINE: usize = 16 * 1024 * 1024;
const RESTART_EVERY: Duration = Duration::from_secs(5);

impl PluginResponder {
    pub(crate) fn new(name: String, command: Vec<String>, timeout: Duration, gate: Gate) -> PluginResponder {
        PluginResponder { name, command, timeout, gate, process: tokio::sync::Mutex::new(None), pending: Arc::default(), next_id: AtomicU64::new(1), last_start: Mutex::new(None) }
    }

    /// The running process, started (or restarted) if needed
    fn spawn(&self) -> std::io::Result<Running> {
        let mut child = tokio::process::Command::new(&self.command[0])
            .args(&self.command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let (pending, name) = (self.pending.clone(), self.name.clone());
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::with_capacity(64 * 1024, stdout);
            let mut line = Vec::new();
            loop {
                line.clear();
                let mut limited = (&mut lines).take(MAX_PLUGIN_LINE as u64);
                match limited.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let Ok(reply) = serde_json::from_slice::<Value>(&line) else {
                    tracing::debug!("Responder {name}: ignoring a line that isn't JSON");
                    continue;
                };
                let Some(id) = reply["id"].as_u64() else { continue };
                if let Some(waiter) = pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                    let _ = waiter.send(reply);
                }
            }
            tracing::warn!("Responder {name}: the plugin's output ended");
        });
        tracing::info!("Responder {}: started {:?}", self.name, self.command);
        Ok(Running { child, stdin })
    }

    async fn ask(&self, event: &Event, default: Option<&[u8]>) -> Option<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = json!({ "type": "respond", "id": id, "protocol": event.protocol.name(), "event": event });
        if let Some(default) = default {
            request["default_base64"] = json!(fakenet_schema::encode_base64(default));
        }
        let mut line = serde_json::to_vec(&request).ok()?;
        line.push(b'\n');
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(id, sender);
        let sent = async {
            let mut process = self.process.lock().await;
            let exited = match process.as_mut() {
                Some(running) => running.child.try_wait().ok().flatten().is_some(),
                None => true,
            };
            if exited {
                let mut last = self.last_start.lock().unwrap_or_else(|e| e.into_inner());
                if last.is_some_and(|at| at.elapsed() < RESTART_EVERY) {
                    return false;
                }
                *last = Some(Instant::now());
                drop(last);
                match self.spawn() {
                    Ok(running) => *process = Some(running),
                    Err(e) => {
                        tracing::warn!("Responder {}: can't start {:?}: {e}", self.name, self.command);
                        return false;
                    }
                }
            }
            let Some(running) = process.as_mut() else { return false };
            running.stdin.write_all(&line).await.is_ok() && running.stdin.flush().await.is_ok()
        };
        let reply = match tokio::time::timeout(self.timeout, async { if sent.await { receiver.await.ok() } else { None } }).await {
            Ok(reply) => reply,
            Err(_) => None,
        };
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        reply
    }
}

impl Responder for PluginResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn respond<'a>(&'a self, event: &'a Event, default: Option<&'a [u8]>) -> Respond<'a> {
        Box::pin(async move {
            if !self.gate.admits(event) {
                return None;
            }
            let reply = self.ask(event, default).await?;
            if reply["skip"].as_bool() == Some(true) {
                return None;
            }
            let response = fakenet_schema::decode_base64(reply["response_base64"].as_str()?).ok()?;
            let route = reply["route"].as_str().map(|r| format!("{}:{}", self.name, r.chars().take(80).collect::<String>())).unwrap_or_else(|| self.name.clone());
            Some(Proposal { response, close: reply["close"].as_bool().unwrap_or(false), route, detail: json!({}) })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(protocol: &str, payload: &[u8]) -> Event {
        serde_json::from_value(json!({
            "version": 2, "type": "event", "request_id": "r", "session_id": "s", "seq": 1,
            "protocol": protocol, "transport": "tcp", "src": "10.0.0.5:1", "dst": "198.51.100.7:80", "dport": 80,
            "timestamp": "2026-01-01T00:00:00Z", "payload": fakenet_schema::encode_base64(payload), "meta": {}, "expects_reply": true,
        }))
        .unwrap()
    }

    fn gate(protocols: Vec<fakenet_schema::Protocol>, rate: f64) -> Gate {
        Gate { filter: EventFilter { protocols, ..Default::default() }, rate, rng: Mutex::new(fakenet_model::Rng::new(3)) }
    }

    #[tokio::test]
    async fn the_model_answers_matching_requests() {
        let mut pack = fakenet_model::Pack::default();
        pack.add("http", b"GET /gate/1 HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntask");
        let responder = ModelResponder { name: "model".into(), model: fakenet_model::Model::new(pack), gate: gate(vec![fakenet_schema::Protocol::Http], 1.0), successful_only: true, key_transforms: Vec::new() };
        let proposal = responder.respond(&event("http", b"GET /gate/2 HTTP/1.1\r\n"), None).await.unwrap();
        assert!(proposal.response.ends_with(b"task"));
        assert_eq!(proposal.route, "model:GET /gate/{n}");
        assert!(responder.respond(&event("dns", b""), None).await.is_none()); // Filtered out
        let never = ModelResponder { name: "m".into(), model: fakenet_model::Model::new(fakenet_model::Pack::default()), gate: gate(vec![], 0.0), successful_only: true, key_transforms: Vec::new() };
        assert!(never.respond(&event("http", b"GET / HTTP/1.1"), None).await.is_none()); // rate 0
    }

    #[tokio::test]
    async fn a_plugin_answers_over_json_lines() {
        // A plugin that answers "plugin:" + the default, and skips raw
        let script = r#"
import json, sys, base64
for line in sys.stdin:
    request = json.loads(line)
    if request["protocol"] == "raw":
        print(json.dumps({"id": request["id"], "skip": True}), flush=True)
        continue
    default = base64.b64decode(request.get("default_base64", ""))
    print(json.dumps({"id": request["id"], "response_base64": base64.b64encode(b"plugin:" + default).decode(), "route": "echo"}), flush=True)
"#;
        let responder = PluginResponder::new("py".into(), vec!["python3".into(), "-I".into(), "-c".into(), script.into()], Duration::from_secs(5), gate(vec![], 1.0));
        let proposal = responder.respond(&event("http", b"GET / HTTP/1.1"), Some(b"default")).await.unwrap();
        assert_eq!(proposal.response, b"plugin:default");
        assert_eq!(proposal.route, "py:echo");
        assert!(responder.respond(&event("raw", b"x"), None).await.is_none());
        // A plugin that never answers is cut off at the timeout
        let silent = PluginResponder::new("slow".into(), vec!["python3".into(), "-I".into(), "-c".into(), "import time; time.sleep(30)".into()], Duration::from_millis(200), gate(vec![], 1.0));
        let started = Instant::now();
        assert!(silent.respond(&event("http", b"GET /"), None).await.is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
