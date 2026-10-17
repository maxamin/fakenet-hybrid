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
    pub defaults: Defaults,
    pub tls: Arc<TlsAuthority>,
    /// Idle timeout for client reads
    pub timeout: Duration,
    /// How long auto listeners wait for a client's first bytes
    pub first_data_timeout: Duration,
    /// Set when a diverter rewrites addresses (Windows)
    pub original: Option<OriginalLookup>,
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
    flow: Option<TcpFlow>,
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
        let flow = (transport == Transport::Tcp).then(|| ctx.capture.tcp_flow(src, dst));
        let session = Session { ctx, listener: listener.to_string(), builder, local, tls_fallback_name: None, custom: None, flow };
        session.log("session_start", json!({}));
        session
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
        let event = self.builder.event(payload.to_vec(), meta, true);
        self.ctx.capture.log("event", json!(event));
        match self.ctx.link.decide(&event).await {
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
        }
    }

    /// One protocol step: asks the daemon, and returns its response or else `default`, plus
    /// whether to close the connection afterwards (the daemon's close flag, or `close`)
    pub async fn answer(&mut self, payload: &[u8], meta: Value, default: Vec<u8>, close: bool) -> (Vec<u8>, bool) {
        match self.decide(payload, meta).await {
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
        self.ctx.link.notify(&event);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.notify(&[], json!({ "closed": true }));
        self.log("session_end", json!({}));
    }
}
