//! Per-connection (or per-UDP-flow) state shared by every protocol handler: the session's
//! event numbering, its pcap conversation, and asking the daemon with a fallback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fakenet_capture::{Capture, TcpFlow};
use fakenet_link::{Decision, Link};
use fakenet_schema::{Action, EventBuilder, ProcessInfo, Protocol, Transport};
use serde_json::{json, Value};

use crate::config::Defaults;
use crate::tls::TlsAuthority;

/// A diverted connection's real endpoints, for diverters that rewrite addresses (WinDivert
/// reflection) rather than NAT the kernel can undo (Linux, via SO_ORIGINAL_DST)
#[derive(Debug, Clone, PartialEq)]
pub struct Original {
    pub client: SocketAddr,
    pub dst: SocketAddr,
    pub process: Option<ProcessInfo>,
}

/// (transport, peer address as the listener sees it, listener's local address) -> Original
pub type OriginalLookup = Arc<dyn Fn(Transport, SocketAddr, SocketAddr) -> Option<Original> + Send + Sync>;

/// Shared by all listeners
pub struct Context {
    pub link: Link,
    pub capture: Arc<Capture>,
    /// The built-in default responses; hot-swappable (SIGHUP reloads [defaults])
    pub defaults: arc_swap::ArcSwap<Defaults>,
    pub tls: Arc<TlsAuthority>,
    /// Idle timeout for client reads
    pub timeout: Duration,
    /// How long auto listeners wait for a client's first bytes
    pub first_data_timeout: Duration,
    /// Set when a diverter rewrites addresses (Windows)
    pub original: Option<OriginalLookup>,
    /// Response exploration (when enabled): answers what the daemon leaves to the default
    pub explorer: Option<Arc<fakenet_explorer::Explorer>>,
    /// Session, per-source and memory limits
    pub limits: Arc<crate::limits::Limits>,
    /// Known JA3/JA4/HASSH fingerprints -> label (see fakenet_sniffer::tls::parse_known)
    pub known_fingerprints: Arc<std::collections::HashMap<String, String>>,
    /// Live manual mode (when enabled): the analyst answers matching requests
    pub manual: Option<Arc<crate::manual::Manual>>,
    /// Reverse-engineering hooks: pause, dump or instrument the sample on matching events
    pub hooks: Option<Arc<crate::hooks::Hooks>>,
    /// Answer sources tried, in order, when neither the rules nor the explorer answered
    pub responders: Vec<Arc<dyn crate::responders::Responder>>,
    /// Online learning (`[learn]`): records curated answers into a model pack
    pub learner: Option<Arc<crate::responders::OnlineLearner>>,
}

pub struct Session {
    pub ctx: Arc<Context>,
    pub listener: String,
    pub builder: EventBuilder,
    /// Our end of the connection (differs from `builder.dst` when diverted)
    pub local: SocketAddr,
    /// The certificate name for TLS clients that send no SNI (default: the destination IP;
    /// proxy tunnels use their target host)
    pub tls_fallback_name: Option<String>,
    /// The listener's FakeNet-NG Custom Responses, if configured
    pub custom: Option<Arc<crate::custom::CustomResponses>>,
    flow: Option<Arc<TcpFlow>>,
    /// A view (see `view`): the session's end isn't logged when it drops
    is_view: bool,
    /// Proxy tunnels (CONNECT, SOCKS) this session is nested in
    pub tunnel_depth: u8,
}

impl Session {
    /// A session for a client `peer` reaching our `local` address. The event's endpoints are
    /// the real ones: after a REDIRECT, `local` is replaced by the original destination
    /// (`redirected_dst`); after WinDivert reflection, the diverter's lookup provides both.
    pub fn new(ctx: Arc<Context>, listener: &str, protocol: Protocol, transport: Transport, peer: SocketAddr, local: SocketAddr, redirected_dst: Option<SocketAddr>) -> Session {
        let original = ctx.original.as_ref().and_then(|lookup| lookup(transport, peer, local));
        let (src, dst, process) = match original {
            Some(original) => (original.client, original.dst, original.process),
            None => {
                let dst = redirected_dst.unwrap_or(local);
                (peer, dst, crate::process::find_process(transport, peer, dst))
            }
        };
        let mut builder = EventBuilder::new(protocol, transport, src, dst);
        builder.process = process;
        let flow = (transport == Transport::Tcp).then(|| Arc::new(ctx.capture.tcp_flow(src, dst)));
        let session = Session { ctx, listener: listener.to_string(), builder, local, tls_fallback_name: None, custom: None, flow, is_view: false, tunnel_depth: 0 };
        session.log("session_start", json!({}));
        session
    }

    /// The same session for one concurrent step (an HTTP/2 or HTTP/3 request, a UDP
    /// datagram): same ID, shared event numbering and pcap conversation, so steps decide in
    /// parallel instead of queueing behind one lock. Changes to a view stay in the view.
    pub fn view(&self) -> Session {
        Session {
            ctx: self.ctx.clone(),
            listener: self.listener.clone(),
            builder: self.builder.clone(),
            local: self.local,
            tls_fallback_name: self.tls_fallback_name.clone(),
            custom: self.custom.clone(),
            flow: self.flow.clone(),
            is_view: true,
            tunnel_depth: self.tunnel_depth,
        }
    }

    /// Switches protocol after sniffing (same session, same pcap conversation)
    pub fn set_protocol(&mut self, protocol: Protocol, tls: bool) {
        self.builder.protocol = protocol;
        self.builder.tls = tls;
        self.log("detected", json!({ "detected": protocol.name(), "tls": tls }));
    }

    pub fn protocol(&self) -> Protocol {
        self.builder.protocol
    }

    /// Records a record about this session in the event log
    pub fn log(&self, kind: &str, details: Value) {
        let mut record = json!({
            "listener": self.listener,
            "session_id": self.builder.session_id,
            "protocol": self.builder.protocol.name(),
            "transport": self.builder.transport,
            "tls": self.builder.tls,
            "src": self.builder.src.to_string(),
            "dst": self.builder.dst.to_string(),
        });
        if let Some(process) = &self.builder.process {
            record["process"] = json!(process);
        }
        if let (Value::Object(record), Value::Object(details)) = (&mut record, details) {
            record.extend(details);
        }
        self.ctx.capture.log(kind, record);
    }

    /// What the client sent, for the pcap
    pub fn client_data(&self, data: &[u8]) {
        match &self.flow {
            Some(flow) => flow.client_data(data),
            None => self.ctx.capture.udp_datagram(self.builder.src, self.builder.dst, data),
        }
    }

    /// What we sent back, for the pcap
    pub fn server_data(&self, data: &[u8]) {
        match &self.flow {
            Some(flow) => flow.server_data(data),
            None => self.ctx.capture.udp_datagram(self.builder.dst, self.builder.src, data),
        }
    }

    /// Asks the daemon how to answer one step of the protocol. None means: use the default.
    /// Never fails and never waits longer than the link's deadline (plus any delay the daemon
    /// asked for).
    pub async fn decide(&mut self, payload: &[u8], meta: Value) -> Option<Action> {
        self.decide_with_default(payload, meta, None).await
    }

    /// `decide`, telling live manual mode what the handler would answer by default
    pub async fn decide_with_default(&mut self, payload: &[u8], meta: Value, default: Option<&[u8]>) -> Option<Action> {
        let event = self.builder.event(payload.to_vec(), meta, true);
        self.ctx.capture.log("event", json!(event));
        if let Some(explorer) = &self.ctx.explorer {
            explorer.observe(&event);
        }
        if let Some(hooks) = &self.ctx.hooks {
            hooks.fire(&event, &self.ctx.capture).await;
        }
        let decided = self.decide_event(&event, default).await;
        let chosen = self.with_manual(&event, decided, default).await;
        if let (Some(learner), Some(action)) = (&self.ctx.learner, &chosen) {
            if let Some(response) = &action.response {
                learner.observe(&event, self.source_of(action), response);
            }
        }
        chosen
    }

    /// Where an answer came from, for online learning
    fn source_of(&self, action: &Action) -> Option<crate::responders::LearnSource> {
        use crate::responders::LearnSource;
        let route = action.route.as_deref().unwrap_or("");
        if route == "manual" {
            return Some(LearnSource::Manual);
        }
        if route.starts_with("explorer:") {
            return Some(LearnSource::Explorer);
        }
        let responder = self.ctx.responders.iter().find(|r| route == r.name() || route.strip_prefix(r.name()).is_some_and(|rest| rest.starts_with(':')));
        match responder {
            Some(responder) => responder.learnable().then_some(LearnSource::Plugins),
            None => Some(LearnSource::Rules),
        }
    }

    /// Live manual mode's turn: holds matching requests for the analyst
    async fn with_manual(&mut self, event: &fakenet_schema::Event, decided: Option<Action>, default: Option<&[u8]>) -> Option<Action> {
        match &self.ctx.manual {
            Some(manual) if manual.wants(event) => {
                let proposed = decided.as_ref().and_then(|a| a.response.as_deref()).or(default);
                let close = decided.as_ref().is_some_and(|a| a.close);
                let verdict = manual.hold(event, proposed, close).await;
                let (response, close, chosen) = match verdict {
                    crate::manual::Verdict::Proposed => return decided,
                    crate::manual::Verdict::Send { response, close } => (response, close, "send"),
                    crate::manual::Verdict::Close => (Vec::new(), true, "close"),
                };
                self.ctx.capture.log("manual", json!({
                    "session_id": event.session_id, "request_id": event.request_id, "verdict": chosen,
                    "close": close, "response_bytes": response.len(),
                }));
                Some(Action {
                    version: fakenet_schema::VERSION,
                    kind: fakenet_schema::ActionKind::Action,
                    request_id: event.request_id.clone(),
                    session_id: event.session_id.clone(),
                    response: Some(response),
                    close,
                    delay_ms: None,
                    route: Some("manual".into()),
                    auth: None,
                })
            }
            _ => decided,
        }
    }

    /// The daemon's decision, or the explorer's proposal for what it left to the default, or
    /// a responder's answer
    async fn decide_event(&mut self, event: &fakenet_schema::Event, default: Option<&[u8]>) -> Option<Action> {
        let decided = match self.ctx.link.decide(event).await {
            Decision::Action(action) => {
                self.ctx.capture.log("decision", json!({
                    "session_id": event.session_id, "request_id": event.request_id, "route": action.route,
                    "default": action.response.is_none(), "close": action.close, "delay_ms": action.delay_ms,
                    "response_bytes": action.response.as_ref().map(Vec::len),
                }));
                if let Some(delay) = action.delay_ms {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                Some(action)
            }
            Decision::Fallback(reason) => {
                self.ctx.capture.log("fallback", json!({
                    "session_id": event.session_id, "request_id": event.request_id, "fallback": reason,
                }));
                None
            }
        };
        self.jitter().await;
        // The analyst's rules win; the explorer may answer what they left to the default
        if decided.as_ref().is_some_and(|a| a.response.is_some()) {
            return decided;
        }
        let proposal = self.ctx.explorer.as_ref().and_then(|explorer| explorer.propose(event));
        match proposal {
            Some(proposal) => {
                self.ctx.capture.log("explored", json!({
                    "session_id": event.session_id, "request_id": event.request_id, "template": proposal.template,
                    "tokens": proposal.tokens, "close": proposal.close, "response_bytes": proposal.response.len(),
                }));
                Some(Action {
                    version: fakenet_schema::VERSION,
                    kind: fakenet_schema::ActionKind::Action,
                    request_id: event.request_id.clone(),
                    session_id: event.session_id.clone(),
                    response: Some(proposal.response),
                    close: proposal.close || decided.as_ref().is_some_and(|a| a.close),
                    delay_ms: None,
                    route: Some(format!("explorer:{}", proposal.template)),
                    auth: None,
                })
            }
            None => self.respond(event, default).await.or(decided),
        }
    }

    /// The first responder's answer (see `responders`), if any answers
    async fn respond(&self, event: &fakenet_schema::Event, default: Option<&[u8]>) -> Option<Action> {
        for responder in &self.ctx.responders {
            let Some(proposal) = responder.respond(event, default).await else { continue };
            self.ctx.capture.log("responded", json!({
                "session_id": event.session_id, "request_id": event.request_id, "responder": responder.name(),
                "route": proposal.route, "detail": proposal.detail, "close": proposal.close, "response_bytes": proposal.response.len(),
            }));
            return Some(Action {
                version: fakenet_schema::VERSION,
                kind: fakenet_schema::ActionKind::Action,
                request_id: event.request_id.clone(),
                session_id: event.session_id.clone(),
                response: Some(proposal.response),
                close: proposal.close,
                delay_ms: None,
                route: Some(proposal.route),
                auth: None,
            });
        }
        None
    }

    /// Saves a payload under files/ on the blocking pool, so the disk write doesn't hold a
    /// runtime worker; the saved path, or None (budget reached, write failed)
    pub async fn save_file(&self, prefix: &'static str, name: &str, data: hyper::body::Bytes) -> Option<String> {
        let capture = self.ctx.capture.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || capture.save_file(prefix, &name, &data)).await.ok()?.ok().map(|p| p.display().to_string())
    }

    /// The configured random delay (defaults.latency_ms) before answering
    async fn jitter(&self) {
        let [min, max] = self.ctx.defaults.load().latency_ms;
        if max == 0 {
            return;
        }
        let spread = max.saturating_sub(min) + 1;
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let delay = min + u64::from(nanos) % spread;
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    /// One protocol step: asks the daemon, and returns its response or else `default`, plus
    /// whether to close the connection afterwards (the daemon's close flag, or `close`)
    pub async fn answer(&mut self, payload: &[u8], meta: Value, default: Vec<u8>, close: bool) -> (Vec<u8>, bool) {
        match self.decide_with_default(payload, meta, Some(&default)).await {
            Some(action) => {
                let close = close || action.close;
                (action.response.unwrap_or(default), close)
            }
            None => (default, close),
        }
    }

    /// Tells the daemon about something that needs no answer (e.g. the session ending)
    pub fn notify(&mut self, payload: &[u8], meta: Value) {
        let event = self.builder.event(payload.to_vec(), meta, false);
        if let Some(explorer) = &self.ctx.explorer {
            explorer.observe(&event);
        }
        self.ctx.link.notify(&event);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.is_view {
            return;
        }
        self.notify(&[], json!({ "closed": true }));
        self.log("session_end", json!({}));
    }
}
