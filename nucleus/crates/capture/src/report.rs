//! An HTML report of events.jsonl (like FakeNet-NG's): key indicators first (DNS, HTTP,
//! SNI, credentials, emails, files, SSH, IRC, suspicious commands, tunnels), then the
//! daemon's decisions & fallbacks, then every record grouped by process and protocol.
//!
//! Every value comes from the sample under analysis, so all of it is HTML-escaped, and the
//! report contains no scripts (collapsible sections are plain <details> elements) and
//! forbids any with its Content-Security-Policy.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use serde_json::Value;

pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn field(record: &Value, key: &str) -> String {
    text(&record[key])
}

/// Shown in every record's header, not repeated in its details
const COMMON: &[&str] = &["timestamp", "kind", "listener", "protocol", "transport", "src", "dst", "tls", "process", "session_id"];

/// Deduplicated values with how often each appeared
#[derive(Default)]
struct Tally(BTreeMap<String, usize>);

impl Tally {
    fn add(&mut self, value: String) {
        if !value.is_empty() {
            *self.0.entry(value).or_insert(0) += 1;
        }
    }
}

fn join(value: &Value) -> String {
    value.as_array().map(|items| items.iter().map(text).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// An HTTP request as a URL: absolute-form targets (proxy clients) are already URLs
fn request_line(record: &Value) -> String {
    let meta = &record["meta"];
    let method = field(meta, "method");
    let path = field(meta, "path");
    if method == "CONNECT" || path.contains("://") {
        return format!("{method} {path}");
    }
    let scheme = if record["tls"] == Value::Bool(true) { "https" } else { "http" };
    format!("{method} {scheme}://{}{path}", field(meta, "host"))
}

pub fn render(records: &[Value]) -> String {
    render_with_map(records, None)
}

/// The explorer's section: what each kind of answer unlocked
fn explorer_section(html: &mut String, map: &Value) {
    let count = |v: &Value| v.as_array().map(Vec::len).unwrap_or(0);
    let _ = write!(
        html,
        "<h2>Explorer</h2><p class=\"meta\">{} explored answers · {} kinds of behaviour seen · functions reached {} of {}</p>",
        escape(&text(&map["proposals"])),
        escape(&text(&map["behaviors"])),
        count(&map["functions"]["reached"]),
        escape(&text(&map["functions"]["known"])),
    );
    if let Some(templates) = map["templates"].as_array() {
        html.push_str("<section class=\"indicator\"><h3>Answers ranked by what they unlocked</h3><ol>");
        for template in templates.iter().filter(|t| t["reward"].as_f64().unwrap_or(0.0) > 0.0).take(30) {
            let list = |key: &str| template[key].as_array().map(|items| items.iter().map(text).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let tokens = template["best_tokens"].as_array().map(|t| t.iter().map(|x| text(&x["token"])).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let _ = write!(
                html,
                "<li><code>{}</code> <span class=\"times\">reward {} · used {}</span><dl><dt>behaviour</dt><dd>{}</dd><dt>functions</dt><dd>{}</dd><dt>tokens</dt><dd>{}</dd></dl></li>",
                escape(&text(&template["template"])),
                escape(&text(&template["reward"])),
                escape(&text(&template["uses"])),
                escape(&list("behaviors")),
                escape(&list("functions")),
                escape(&tokens),
            );
        }
        html.push_str("</ol></section>");
    }
    let unreached = map["functions"]["unreached"].as_array().map(|f| f.iter().map(text).collect::<Vec<_>>()).unwrap_or_default();
    if !unreached.is_empty() {
        let _ = write!(html, "<details><summary>Known functions never reached <span class=\"count\">{}</span></summary><p><code>{}</code></p></details>", unreached.len(), escape(&unreached.join(", ")));
    }
}

/// The report, with the explorer's map (explorer-map.json) when exploration ran
pub fn render_with_map(records: &[Value], map: Option<&Value>) -> String {
    let mut domains = Tally::default();
    let mut urls = Tally::default();
    let mut sni = Tally::default();
    let mut tls_clients = Tally::default();
    let mut credentials = Tally::default();
    let mut emails = Tally::default();
    let mut files = Tally::default();
    let mut ssh = Tally::default();
    let mut irc = Tally::default();
    let mut suspicious = Tally::default();
    let mut tunnels = Tally::default();
    let mut routes = Tally::default();
    let mut fallbacks = Tally::default();
    let mut yara = Tally::default();

    // process -> protocol -> records; link/nucleus records separately
    let mut by_process: BTreeMap<String, BTreeMap<String, Vec<&Value>>> = BTreeMap::new();
    let mut link: Vec<&Value> = Vec::new();

    for record in records {
        let kind = field(record, "kind");
        match kind.as_str() {
            "event" if record["protocol"] == "dns" => domains.add(format!("{} ({})", field(&record["meta"], "qname"), field(&record["meta"], "qtype"))),
            "event" if record["protocol"] == "http" => urls.add(request_line(record)),
            "tls_handshake" => {
                sni.add(field(record, "sni"));
                if !record["ja4"].is_null() {
                    let known = if record["known"].is_null() { String::new() } else { format!(" — known: {}", field(record, "known")) };
                    tls_clients.add(format!("JA4 {} JA3 {}{known}", field(record, "ja4"), field(record, "ja3")));
                }
            }
            "credentials" => {
                let mut parts = vec![format!("{}:", field(record, "protocol"))];
                for key in ["username", "password", "mechanism", "apop_digest", "hash_type", "hash"] {
                    if !record[key].is_null() {
                        parts.push(format!("{key}={}", field(record, key)));
                    }
                }
                credentials.add(parts.join(" "));
            }
            "email" => emails.add(format!("{} → {} : {}", field(record, "from"), join(&record["to"]), field(record, "subject"))),
            "upload" | "download" => {
                let name = ["filename", "name", "path"].iter().map(|k| field(record, k)).find(|n| !n.is_empty()).unwrap_or_default();
                files.add(format!("{} {kind} {name} ({} bytes)", field(record, "protocol"), field(record, "size")));
            }
            "ssh_client" => {
                let known = if record["known"].is_null() { String::new() } else { format!(" — known: {}", field(record, "known")) };
                ssh.add(format!("{} hassh={}{known}", field(record, "version"), field(record, "hassh")))
            }
            "join" => irc.add(format!("JOIN {} key={}", field(record, "channels"), field(record, "keys"))),
            "message" if record["protocol"] == "irc" => irc.add(format!("{} → {}: {}", field(record, "nick"), field(record, "target"), field(record, "text"))),
            "suspicious_command" => suspicious.add(format!("{} {}", field(record, "command"), join(&record["arguments"]).replace(", ", " "))),
            "proxy_tunnel" => tunnels.add(field(record, "target")),
            "socks_refused" => tunnels.add(format!("{} (refused)", field(record, "target"))),
            "decision" => routes.add(if record["default"] == Value::Bool(true) { format!("{} (default answer)", field(record, "route")) } else { field(record, "route") }),
            "explored" => routes.add(format!("explorer:{}", field(record, "template"))),
            "fallback" => fallbacks.add(field(&record["fallback"], "reason")),
            "yara_match" => {
                let file = field(record, "file");
                let file = file.rsplit(['/', '\\']).next().unwrap_or_default().to_string();
                for rule in record["rules"].as_array().into_iter().flatten() {
                    yara.add(format!("{} — {file}", text(rule)));
                }
            }
            _ => {}
        }
        if record["protocol"].is_null() {
            link.push(record);
            continue;
        }
        let process = match &record["process"] {
            Value::Object(p) => format!("{} (PID {})", text(&p["name"]), text(&p["pid"])),
            _ => "Remote or unknown process".to_string(),
        };
        by_process.entry(process).or_default().entry(field(record, "protocol")).or_default().push(record);
    }

    let mut html = String::from(HEADER);
    let _ = write!(html, "<p class=\"meta\">{} records from {} processes</p>", records.len(), by_process.len());
    html.push_str("<h2>Key indicators</h2>");
    let sections: [(&str, &Tally); 14] = [
        ("DNS queries", &domains),
        ("HTTP requests", &urls),
        ("TLS server names (SNI)", &sni),
        ("TLS clients (fingerprints)", &tls_clients),
        ("YARA matches", &yara),
        ("Credentials", &credentials),
        ("Emails", &emails),
        ("File transfers", &files),
        ("SSH clients", &ssh),
        ("IRC", &irc),
        ("Suspicious commands", &suspicious),
        ("Proxy & SOCKS tunnels", &tunnels),
        ("Daemon decisions (by route)", &routes),
        ("Fallbacks to built-in defaults (by reason)", &fallbacks),
    ];
    for (title, tally) in sections {
        if tally.0.is_empty() {
            continue;
        }
        let _ = write!(html, "<section class=\"indicator\"><h3>{} <span class=\"count\">{}</span></h3><ul>", escape(title), tally.0.len());
        for (value, count) in &tally.0 {
            let times = if *count > 1 { format!(" <span class=\"times\">×{count}</span>") } else { String::new() };
            let _ = write!(html, "<li><code>{}</code>{times}</li>", escape(value));
        }
        html.push_str("</ul></section>");
    }
    if records.is_empty() {
        html.push_str("<p>No network activity was recorded.</p>");
    }

    if let Some(map) = map {
        explorer_section(&mut html, map);
    }
    html.push_str("<h2>All records, by process</h2>");
    for (process, protocols) in &by_process {
        let total: usize = protocols.values().map(Vec::len).sum();
        let _ = write!(html, "<details class=\"process\" open><summary>{} <span class=\"count\">{total}</span></summary>", escape(process));
        for (protocol, records) in protocols {
            let _ = write!(html, "<details class=\"protocol\"><summary>{} <span class=\"count\">{}</span></summary><ol>", escape(&protocol.to_uppercase()), records.len());
            for record in records {
                write_record(&mut html, record);
            }
            html.push_str("</ol></details>");
        }
        html.push_str("</details>");
    }
    if !link.is_empty() {
        let _ = write!(html, "<details class=\"process\"><summary>Nucleus &amp; daemon link <span class=\"count\">{}</span></summary><ol>", link.len());
        for record in &link {
            write_record(&mut html, record);
        }
        html.push_str("</ol></details>");
    }
    html.push_str("</main></body></html>\n");
    html
}

fn write_record(html: &mut String, record: &Value) {
    let _ = write!(
        html,
        "<li><div class=\"event-head\"><b>{}</b> {} {} {}{} <span class=\"listener\">{} {}</span></div><dl>",
        escape(&field(record, "kind")),
        escape(&field(record, "timestamp")),
        escape(&field(record, "src")),
        if record["dst"].is_null() { "" } else { "→" },
        escape(&format!("{}{}", field(record, "dst"), if record["tls"] == Value::Bool(true) { " (TLS)" } else { "" })),
        escape(&field(record, "listener")),
        escape(&field(record, "session_id")),
    );
    if let Value::Object(map) = record {
        for (key, value) in map.iter().filter(|(k, _)| !COMMON.contains(&k.as_str())) {
            let _ = write!(html, "<dt>{}</dt><dd>{}</dd>", escape(key), escape(&text(value)));
        }
    }
    html.push_str("</dl></li>");
}

/// Reads an events.jsonl (skipping unparseable lines) and renders it
pub fn render_file(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)?;
    let records: Vec<Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    Ok(render(&records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_everything_and_summarizes() {
        let records = vec![
            json!({ "kind": "event", "protocol": "http", "tls": true, "meta": { "method": "GET", "path": "/a?<script>", "host": "c2.example" }, "process": { "name": "evil", "pid": 6 } }),
            json!({ "kind": "event", "protocol": "dns", "meta": { "qname": "c2.example", "qtype": "A" } }),
            json!({ "kind": "credentials", "protocol": "ftp", "username": "<img src=x onerror=alert(1)>", "password": "x" }),
            json!({ "kind": "credentials", "protocol": "smb", "username": "alice", "hash_type": "netntlmv2", "hash": "alice::LAB:1122334455667788:aabb:ccdd" }),
            json!({ "kind": "fallback", "fallback": { "reason": "timeout" } }),
            json!({ "kind": "decision", "route": "c2-gate", "default": false }),
        ];
        let html = render(&records);
        assert!(html.contains("GET https://c2.example/a?&lt;script&gt;"));
        assert!(!html.contains("<script>") && !html.contains("<img"));
        assert!(html.contains("hash_type=netntlmv2") && html.contains("hash=alice::LAB:1122334455667788:aabb:ccdd"));
        assert!(html.contains("username=&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("c2.example (A)") && html.contains("timeout") && html.contains("c2-gate"));
        assert!(html.contains("evil (PID 6)") && html.contains("Nucleus &amp; daemon link"));
        assert!(html.contains("default-src 'none'"));
    }
}

const HEADER: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>FakeNet hybrid report</title>
<style>
:root { --bg: #f7f7f8; --fg: #1d1d1f; --card: #fff; --muted: #6b6b75; --border: #dcdce2; --accent: #b4261b; --code: #f0f0f3; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #16161a; --fg: #e8e8ec; --card: #202026; --muted: #9a9aa6; --border: #34343c; --accent: #ff7a6b; --code: #2a2a31; }
}
body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.45 system-ui, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { margin: 0 0 4px; font-size: 24px; } h1 span { color: var(--accent); }
h2 { margin: 32px 0 12px; font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
h3 { margin: 0 0 8px; font-size: 15px; }
.meta, .listener, .times { color: var(--muted); }
.count { display: inline-block; min-width: 1.6em; padding: 0 6px; margin-left: 6px; border-radius: 9px; background: var(--code); color: var(--muted); font-size: 12px; text-align: center; }
.indicator, details { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; margin: 10px 0; }
.indicator ul { margin: 0; padding-left: 20px; }
code, dd { font-family: ui-monospace, monospace; font-size: 13px; overflow-wrap: anywhere; }
code { background: var(--code); padding: 1px 4px; border-radius: 4px; }
summary { cursor: pointer; font-weight: 600; }
details.protocol { margin-left: 8px; }
ol { padding-left: 20px; } li { margin: 8px 0; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 4px 0 0; }
dt { color: var(--muted); } dd { margin: 0; white-space: pre-wrap; }
</style></head>
<body><main><h1><span>FakeNet</span> hybrid report</h1>
"#;
