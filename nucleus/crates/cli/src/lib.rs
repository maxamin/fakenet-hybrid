//! The nucleus's TOML config, its validation, and the loopback-only health endpoint

pub mod har;
pub mod import;
pub mod replay;
pub mod run;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _};
use fakenet_diverter::{DiverterConfig, Plan};
use fakenet_link::{Link, LinkConfig};
use fakenet_listeners::config::ListenerProtocol;
use fakenet_listeners::{Defaults, ListenerConfig};
use fakenet_schema::Transport;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub nucleus: NucleusConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub diverter: DiverterConfig,
    #[serde(default)]
    pub explorer: fakenet_explorer::ExplorerConfig,
    #[serde(default)]
    pub limits: fakenet_listeners::LimitsConfig,
    #[serde(default)]
    pub yara: YaraConfig,
    #[serde(default, rename = "listener")]
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NucleusConfig {
    /// Where the fake services listen (the analysis network side)
    pub bind: IpAddr,
    /// events.jsonl, traffic.pcap, files/ and ca.pem go here
    pub capture_dir: PathBuf,
    /// Idle timeout for client connections
    pub timeout_ms: u64,
    /// How long auto listeners wait for a client's first bytes before assuming it waits for a greeting
    pub first_data_timeout_ms: u64,
    /// The health endpoint: must be a loopback address
    pub health: SocketAddr,
    /// Rotate events.jsonl / the pcaps past these sizes (MB, 0 = never), keeping this many
    pub max_events_mb: u64,
    pub max_pcap_mb: u64,
    pub keep_rotations: usize,
    /// Stop saving payloads to files/ past this total (MB, 0 = no limit)
    pub max_files_mb: u64,
    /// Also record every real packet to wire.pcap (needs root/Administrator)
    pub wire_capture: bool,
    /// CSV lists of known JA3/JA4/HASSH fingerprints (fingerprint first, label last), e.g.
    /// abuse.ch SSLBL's ja3_fingerprints.csv; matches are labelled in the capture & report
    pub fingerprints: Vec<PathBuf>,
    /// Write TLS session secrets to capture_dir/tls-keys.log (NSS key log format), so
    /// Wireshark can decrypt wire.pcap
    pub tls_keylog: bool,
}

impl Default for NucleusConfig {
    fn default() -> Self {
        NucleusConfig {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            capture_dir: PathBuf::from("capture"),
            timeout_ms: 30_000,
            first_data_timeout_ms: 500,
            health: SocketAddr::from(([127, 0, 0, 1], 8099)),
            max_events_mb: 256,
            max_pcap_mb: 1024,
            keep_rotations: 4,
            max_files_mb: 2048,
            wire_capture: false,
            fingerprints: Vec::new(),
            tls_keylog: true,
        }
    }
}

/// YARA scanning of captured payloads (off without rules)
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct YaraConfig {
    /// Rule files, or folders of *.yar / *.yara
    pub rules: Vec<PathBuf>,
    /// The YARA tools (on PATH by default)
    pub yara: String,
    pub yarac: String,
}

impl Default for YaraConfig {
    fn default() -> Self {
        YaraConfig { rules: Vec::new(), yara: "yara".into(), yarac: "yarac".into() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonConfig {
    /// The Camel daemon's WebSocket (primary channel); "" disables it
    pub websocket_url: String,
    /// The Camel daemon's one-shot HTTP endpoint (secondary channel); "" disables it
    pub http_url: String,
    pub deadline_ms: u64,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    /// Shared secret authenticating the link both ways (and /health details). Create it
    /// with `fakenet-nucleus --generate-secret PATH`; the daemon reads the same file.
    pub secret_file: Option<PathBuf>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            websocket_url: "ws://127.0.0.1:8090/link".into(),
            http_url: "http://127.0.0.1:8091/decide".into(),
            deadline_ms: 200,
            backoff_initial_ms: 100,
            backoff_max_ms: 10_000,
            secret_file: None,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.resolve_paths(path.parent().unwrap_or(Path::new(".")));
        config.validate()?;
        Ok(config)
    }

    /// Relative paths in the config are relative to the config file's directory, so it works
    /// wherever the nucleus is started from
    pub fn resolve_paths(&mut self, base: &Path) {
        let resolve = |path: &mut PathBuf| {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        };
        resolve(&mut self.nucleus.capture_dir);
        self.nucleus.fingerprints.iter_mut().for_each(resolve);
        self.yara.rules.iter_mut().for_each(resolve);
        for path in [&mut self.daemon.secret_file, &mut self.defaults.http.webroot, &mut self.defaults.ftp.root, &mut self.defaults.tftp.root] {
            if let Some(path) = path.as_mut() {
                resolve(path);
            }
        }
        for listener in &mut self.listeners {
            if let Some(custom) = listener.custom.as_mut() {
                resolve(custom);
            }
        }
        let explorer = &mut self.explorer;
        for path in explorer.templates.iter_mut().chain(explorer.samples.iter_mut()).chain(explorer.rea.iter_mut()).chain(explorer.coverage_dir.iter_mut()) {
            resolve(path);
        }
    }

    /// The known-fingerprint lists, merged (later files win)
    pub fn known_fingerprints(&self) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let mut known = std::collections::HashMap::new();
        for path in &self.nucleus.fingerprints {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading fingerprints {}", path.display()))?;
            known.extend(fakenet_sniffer::tls::parse_known(&text));
        }
        Ok(known)
    }

    /// Enforces the lab-safety rules: control interfaces on loopback only
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.nucleus.health.ip().is_loopback() {
            bail!("nucleus.health must be a loopback address (got {})", self.nucleus.health);
        }
        for url in [&self.daemon.websocket_url, &self.daemon.http_url] {
            if !url.is_empty() && !loopback_url(url) {
                bail!("daemon URLs must point at 127.0.0.1, ::1 or localhost (got {url})");
            }
        }
        if self.daemon.deadline_ms == 0 || self.daemon.backoff_initial_ms == 0 || self.daemon.backoff_max_ms < self.daemon.backoff_initial_ms {
            bail!("daemon: deadline_ms and backoff_initial_ms must be > 0, and backoff_max_ms >= backoff_initial_ms");
        }
        if self.listeners.is_empty() {
            bail!("no [[listener]] configured");
        }
        let mut seen = std::collections::HashSet::new();
        for listener in &self.listeners {
            if !seen.insert(&listener.name) {
                bail!("duplicate listener name {}", listener.name);
            }
            if listener.transport == Transport::Udp && listener.tls {
                bail!("listener {}: tls = true is for TCP (an http listener on UDP is HTTP/3, which is always encrypted)", listener.name);
            }
        }
        if self.diverter.enabled && !self.diverter.block_undiverted {
            // Without a catch-all listener and without the block, every other port would
            // reach the real network
            let plan = self.plan();
            for (transport, default) in [("tcp", plan.tcp_default), ("udp", plan.udp_default)] {
                if default.is_none() {
                    bail!("[diverter] is on with block_undiverted = false but there is no \"auto\" {transport} listener: {transport} traffic to other ports would reach the real network");
                }
            }
        }
        Ok(())
    }

    /// Where the diverter sends traffic: listener ports keep their port; everything else
    /// goes to the first "auto" listener of its transport
    pub fn plan(&self) -> Plan {
        let fixed = |transport| -> Vec<u16> {
            self.listeners.iter().filter(|l| l.transport == transport && matches!(l.protocol, ListenerProtocol::Fixed(_))).map(|l| l.port).collect()
        };
        let auto = |transport| {
            self.listeners.iter().find(|l| l.transport == transport && matches!(l.protocol, ListenerProtocol::Auto(_))).map(|l| l.port)
        };
        let (first, last) = self.defaults.ftp.passive_ports;
        Plan {
            tcp_ports: fixed(Transport::Tcp),
            udp_ports: fixed(Transport::Udp),
            tcp_default: auto(Transport::Tcp),
            udp_default: auto(Transport::Udp),
            passive_ports: (first != 0).then_some((first, last.max(first))),
            ignore_ports: self.diverter.ignore_ports.clone(),
        }
    }

    /// The shared secret's contents (trimmed), if configured
    pub fn secret(&self) -> anyhow::Result<Option<String>> {
        let Some(path) = &self.daemon.secret_file else { return Ok(None) };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the link secret {} (create it with --generate-secret)", path.display()))?;
        let secret = text.trim().to_string();
        if secret.len() < 32 {
            bail!("the link secret in {} is too short (use --generate-secret)", path.display());
        }
        Ok(Some(secret))
    }

    pub fn capture_limits(&self) -> fakenet_capture::Limits {
        let mb = |n: u64| n * 1024 * 1024;
        fakenet_capture::Limits {
            max_events_bytes: mb(self.nucleus.max_events_mb),
            max_pcap_bytes: mb(self.nucleus.max_pcap_mb),
            max_files_bytes: mb(self.nucleus.max_files_mb),
            keep: self.nucleus.keep_rotations,
        }
    }

    pub fn link(&self, secret: Option<&str>) -> LinkConfig {
        let optional = |url: &str| (!url.is_empty()).then(|| url.to_string());
        LinkConfig {
            secret: secret.map(|s| fakenet_schema::auth::Secret::new(s.as_bytes())),
            websocket_url: optional(&self.daemon.websocket_url),
            http_url: optional(&self.daemon.http_url),
            deadline: Duration::from_millis(self.daemon.deadline_ms),
            backoff_initial: Duration::from_millis(self.daemon.backoff_initial_ms),
            backoff_max: Duration::from_millis(self.daemon.backoff_max_ms),
        }
    }
}

fn loopback_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The HTML report of event logs (in order, e.g. rotated ones first), with the explorer's
/// map if there is one next to them
pub fn write_report(event_files: &[PathBuf], output: &Path) -> anyhow::Result<()> {
    let records = read_records(event_files)?;
    let map = event_files
        .last()
        .and_then(|f| f.parent())
        .and_then(|dir| std::fs::read_to_string(dir.join("explorer-map.json")).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    std::fs::write(output, fakenet_capture::report::render_with_map(&records, map.as_ref())).with_context(|| format!("writing {}", output.display()))
}

fn read_records(event_files: &[PathBuf]) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for file in event_files {
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        records.extend(text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()));
    }
    Ok(records)
}

/// Writes the event logs' indicators to `dir`: indicators.csv, indicators.stix.json (STIX
/// 2.1) and indicators.misp.json. `sample` is run.json's sample ({name, sha256, md5}), or
/// read from dir/run.json when there is one. Returns how many indicators there were.
pub fn write_indicators(event_files: &[PathBuf], dir: &Path, sample: Option<&serde_json::Value>) -> anyhow::Result<usize> {
    use fakenet_capture::indicators;
    let records = read_records(event_files)?;
    let found = indicators::collect(&records);
    let from_run = std::fs::read_to_string(dir.join("run.json")).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).map(|run| run["sample"].clone());
    let sample = sample.or(from_run.as_ref());
    let write = |name: &str, contents: String| {
        let path = dir.join(name);
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))
    };
    write("indicators.csv", indicators::to_csv(&found))?;
    write("indicators.stix.json", serde_json::to_string_pretty(&indicators::to_stix(&found, sample))?)?;
    write("indicators.misp.json", serde_json::to_string_pretty(&indicators::to_misp(&found, sample))?)?;
    Ok(found.len())
}

/// Feeds coverage written by a tracer into the explorer: new drcov files (once they've
/// stopped growing) and new lines of JSONL files. Polls; runs until dropped.
pub async fn watch_coverage(explorer: Arc<fakenet_explorer::Explorer>, dir: PathBuf, capture: Arc<fakenet_capture::Capture>) {
    use std::collections::HashMap;
    let mut done: std::collections::HashSet<PathBuf> = Default::default();
    let mut sizes: HashMap<PathBuf, u64> = HashMap::new();
    let mut offsets: HashMap<PathBuf, usize> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.ends_with(".jsonl") {
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                let start = offsets.get(&path).copied().unwrap_or(0).min(text.len());
                // Only complete lines; a partial last line waits for the next poll
                let complete = text[start..].rfind('\n').map(|i| start + i + 1).unwrap_or(start);
                for line in text[start..complete].lines().filter(|l| !l.trim().is_empty()) {
                    match explorer.ingest_coverage_line(line) {
                        Ok(new) if new > 0 => capture.log("coverage", json!({ "source": name, "new_functions": new })),
                        Ok(_) => {}
                        Err(e) => tracing::debug!("coverage line in {name}: {e}"),
                    }
                }
                offsets.insert(path, complete);
            } else if name.ends_with(".log") && !done.contains(&path) {
                // drcov writes at process exit: wait until the size is stable
                if sizes.insert(path.clone(), size) != Some(size) {
                    continue;
                }
                done.insert(path.clone());
                match std::fs::read(&path).map_err(anyhow::Error::from).and_then(|data| explorer.ingest_drcov(&data, &name)) {
                    Ok(new) => capture.log("coverage", json!({ "source": name, "new_functions": new })),
                    Err(e) => tracing::warn!("coverage file {name}: {e:#}"),
                }
            }
        }
    }
}

/// Writes a new random secret readable only by its owner
pub fn generate_secret(path: &Path) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    std::io::Write::write_all(&mut file, format!("{}\n", fakenet_schema::auth::random_hex(32)).as_bytes())?;
    Ok(())
}

/// What the loopback control server (health & dashboard) reports on
pub struct Control {
    pub link: Link,
    pub listeners: Vec<(String, Transport, SocketAddr)>,
    /// The link secret: required (as a bearer token, or the dashboard's cookie) for
    /// anything beyond `/health`'s "ok"; None = no authentication configured
    pub secret: Option<String>,
    pub capture: Arc<fakenet_capture::Capture>,
    pub explorer: Option<Arc<fakenet_explorer::Explorer>>,
    pub limits: Arc<fakenet_listeners::Limits>,
}

const DASHBOARD_HTML: &str = include_str!("dashboard/index.html");
const DASHBOARD_JS: &str = include_str!("dashboard/dashboard.js");
const DASHBOARD_CSS: &str = include_str!("dashboard/dashboard.css");
/// Everything shown comes from the sample: no inline script, nothing from elsewhere
const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The loopback control server:
/// - `GET /health`: "ok"; with the secret, the daemon link's state and the listeners
/// - `GET /dashboard?token=SECRET`: sets a cookie and redirects; `/dashboard` is the live view
/// - `GET /api/records?after=N`, `GET /api/summary`: the dashboard's data
pub async fn serve_control(socket: TcpListener, control: Arc<Control>) {
    loop {
        let Ok((stream, _)) = socket.accept().await else { continue };
        let control = control.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let control = control.clone();
                async move { Ok::<_, std::convert::Infallible>(control_response(&control, &request)) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
        });
    }
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

fn authorized(control: &Control, request: &hyper::Request<hyper::body::Incoming>) -> bool {
    let Some(secret) = control.secret.as_deref() else { return true };
    let headers = request.headers();
    let bearer = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let cookie = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix("fakenet_token="));
    [bearer, cookie].into_iter().flatten().any(|token| constant_time_eq(token.as_bytes(), secret.as_bytes()))
}

fn control_response(control: &Control, request: &hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = request.uri().path();
    let query = request.uri().query().unwrap_or("");
    let authorized = authorized(control, request);
    let respond = |status: StatusCode, content_type: &str, body: String| {
        Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("referrer-policy", "no-referrer")
            .header("content-security-policy", DASHBOARD_CSP)
            .body(Full::new(Bytes::from(body)))
            .expect("valid response")
    };
    let json_response = |value: serde_json::Value| respond(StatusCode::OK, "application/json", value.to_string());
    match path {
        "/health" if !authorized => json_response(json!({ "status": "ok" })),
        "/health" => {
            let listeners: Vec<_> = control.listeners.iter().map(|(n, t, a)| json!({ "name": n, "transport": t, "address": a.to_string() })).collect();
            json_response(json!({ "status": "ok", "daemon": control.link.health(), "listeners": listeners, "limits": control.limits.stats() }))
        }
        "/dashboard" => {
            // Opening /dashboard?token=SECRET sets the cookie, then drops the token from the URL
            if let (Some(token), Some(secret)) = (query_param(query, "token"), control.secret.as_deref()) {
                if constant_time_eq(token.as_bytes(), secret.as_bytes()) {
                    let mut response = respond(StatusCode::SEE_OTHER, "text/plain", String::new());
                    response.headers_mut().insert("location", hyper::header::HeaderValue::from_static("/dashboard"));
                    if let Ok(cookie) = hyper::header::HeaderValue::from_str(&format!("fakenet_token={secret}; HttpOnly; SameSite=Strict; Path=/")) {
                        response.headers_mut().insert("set-cookie", cookie);
                    }
                    return response;
                }
            }
            if authorized {
                respond(StatusCode::OK, "text/html; charset=utf-8", DASHBOARD_HTML.to_string())
            } else {
                respond(StatusCode::UNAUTHORIZED, "text/plain; charset=utf-8", "Open /dashboard?token=<the link secret> (the [daemon] secret_file's contents)\n".to_string())
            }
        }
        "/dashboard.js" => respond(StatusCode::OK, "text/javascript; charset=utf-8", DASHBOARD_JS.to_string()),
        "/dashboard.css" => respond(StatusCode::OK, "text/css; charset=utf-8", DASHBOARD_CSS.to_string()),
        "/api/records" | "/api/summary" if !authorized => respond(StatusCode::UNAUTHORIZED, "application/json", r#"{"error":"unauthorized"}"#.into()),
        "/api/records" => {
            let after = query_param(query, "after").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit = query_param(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(1000usize).min(5000);
            let (records, latest) = control.capture.recent(after, limit);
            let records: Vec<_> = records.into_iter().map(|(seq, record)| json!({ "seq": seq, "record": record })).collect();
            json_response(json!({ "latest": latest, "records": records }))
        }
        "/api/summary" => {
            let explorer = control.explorer.as_ref().map(|e| {
                let map = e.map();
                let templates: Vec<_> = map["templates"].as_array().map(|t| t.iter().filter(|t| t["reward"].as_f64().unwrap_or(0.0) > 0.0).take(8).cloned().collect()).unwrap_or_default();
                json!({
                    "proposals": map["proposals"], "behaviors": map["behaviors"],
                    "functions_reached": map["functions"]["reached"].as_array().map(Vec::len).unwrap_or(0),
                    "functions_known": map["functions"]["known"],
                    "templates": templates.iter().map(|t| json!({ "template": t["template"], "reward": t["reward"], "functions": t["functions"] })).collect::<Vec<_>>(),
                })
            });
            let listeners: Vec<_> = control.listeners.iter().map(|(n, t, a)| json!({ "name": n, "transport": t, "address": a.to_string() })).collect();
            json_response(json!({ "daemon": control.link.health(), "listeners": listeners, "explorer": explorer, "limits": control.limits.stats() }))
        }
        _ => respond(StatusCode::NOT_FOUND, "application/json", r#"{"error":"not found"}"#.into()),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn loads_the_sample_config() {
        let config = Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/fakenet.toml")).unwrap();
        assert!(config.listeners.iter().any(|l| l.name == "Auto"));
        assert_eq!(config.link(None).deadline, Duration::from_millis(200));
        assert!(!config.diverter.enabled); // Never on by default
        let plan = config.plan();
        assert_eq!(plan.tcp_ports, [53, 80, 443, 25, 465, 110, 21, 6667, 143, 23, 6379, 1080, 22, 445, 389, 3389, 5900, 1883, 853]);
        assert_eq!(plan.udp_ports, [53, 443, 69, 123, 514, 5683]); // 443: HTTP/3; 5683: CoAP
        assert_eq!((plan.tcp_default, plan.udp_default), (Some(1337), Some(1338)));
        assert_eq!(plan.passive_ports, Some((60000, 60010)));
        // Relative paths resolve against the config's directory: the bundled default files
        let webroot = config.defaults.http.webroot.as_deref().unwrap();
        assert!(webroot.is_absolute() && webroot.join("FakeNetMini.exe").exists(), "{}", webroot.display());
        assert!(config.nucleus.capture_dir.ends_with("config/capture"));
    }

    #[test]
    fn keeps_control_interfaces_on_loopback() {
        let listener = "[[listener]]\nname = \"x\"\nprotocol = \"raw\"\nport = 1\n";
        assert!(parse(listener).is_ok());
        assert!(parse(&format!("[nucleus]\nhealth = \"0.0.0.0:8099\"\n{listener}")).is_err());
        assert!(parse(&format!("[daemon]\nwebsocket_url = \"ws://10.0.0.2:8090/link\"\n{listener}")).is_err());
        assert!(parse(&format!("[daemon]\nwebsocket_url = \"ws://[::1]:8090/link\"\nhttp_url = \"\"\n{listener}")).is_ok());
        assert!(parse(&format!("[daemon]\nhttp_url = \"http://localhost.evil.example/decide\"\n{listener}")).is_err());
        assert!(parse("").is_err()); // no listeners
        assert!(parse(&format!("{listener}{listener}")).is_err()); // duplicate
        assert!(parse(&format!("bogus = 1\n{listener}")).is_err());
    }
}
