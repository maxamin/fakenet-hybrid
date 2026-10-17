//! `--replay EVENTS`: sends a capture's events (events.jsonl) to the daemon, as the nucleus
//! would have, and prints what the current rules decide: a way to test rules offline,
//! without the sample. Uses the config's [daemon] settings (including its secret).

use fakenet_link::{Decision, Link};
use fakenet_schema::Event;
use serde_json::{json, Value};

/// One line per event: what it was, and the decision (or the fallback's reason)
pub async fn replay(link: &Link, records: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut out = Vec::new();
    for record in records {
        if record["kind"] != "event" || record["expects_reply"] == false {
            continue;
        }
        let Ok(event) = serde_json::from_value::<Event>(record) else { continue };
        let meta = &event.meta;
        let summary = ["method", "host", "path", "qname", "qtype", "command", "argument"]
            .iter()
            .filter_map(|k| meta.get(*k).and_then(Value::as_str).map(|v| format!("{k}={v}")))
            .collect::<Vec<_>>()
            .join(" ");
        let line = match link.decide(&event).await {
            Decision::Action(action) => json!({
                "protocol": event.protocol.name(), "request": summary, "route": action.route,
                "default": action.response.is_none(), "close": action.close,
                "response": action.response.as_deref().map(|r| String::from_utf8_lossy(&r[..r.len().min(160)]).into_owned()),
            }),
            Decision::Fallback(reason) => json!({ "protocol": event.protocol.name(), "request": summary, "fallback": reason }),
        };
        out.push(line);
    }
    out
}
