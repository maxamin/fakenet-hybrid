//! The nucleus's TOML config, its validation, and the loopback-only health endpoint

pub mod diff;
pub mod har;
pub mod infer;
pub mod import;
pub mod replay;
pub mod run;
#[cfg(windows)]
pub mod run_windows;

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
    /// Live manual mode: the analyst answers matching requests from the dashboard
    #[serde(default)]
    pub manual: fakenet_listeners::manual::ManualConfig,
    /// Reverse-engineering hooks (pause, dump, command) on matching events
    #[serde(default, rename = "hook")]
    pub hooks: Vec<fakenet_listeners::hooks::HookConfig>,
    /// Answer sources (learned models, plugins) for what the rules and the explorer leave
    #[serde(default, rename = "responder")]
    pub responders: Vec<fakenet_listeners::responders::ResponderConfig>,
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
    /// The interception CA's certificate and private key (PEM). Loaded when both exist,
    /// created and saved there when neither does, so the VM keeps trusting it across
    /// restarts. Unset: a new CA at every start
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
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
            ca_cert: None,
            ca_key: None,
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
    /// Payload sent to the daemon per event (KB); larger ones are cut (meta.payload_truncated)
    pub max_payload_kb: u64,
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
            max_payload_kb: 1024,
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
        self.responders.iter_mut().flat_map(|r| r.packs.iter_mut()).for_each(resolve);
        self.nucleus.fingerprints.iter_mut().for_each(resolve);
        self.yara.rules.iter_mut().for_each(resolve);
        for path in [&mut self.nucleus.ca_cert, &mut self.nucleus.ca_key, &mut self.daemon.secret_file, &mut self.defaults.http.webroot, &mut self.defaults.ftp.root, &mut self.defaults.tftp.root] {
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
        let ftp = self.listeners.iter().any(|l| matches!(l.protocol, ListenerProtocol::Fixed(fakenet_schema::Protocol::Ftp)) || matches!(l.protocol, ListenerProtocol::Auto(_)));
        if self.diverter.enabled && ftp && self.defaults.ftp.passive_ports.0 == 0 {
            bail!("[defaults.ftp] passive_ports = [0, 0] with the diverter on: passive data connections would be diverted to the auto listener; set a range (default [60000, 60010])");
        }
        let mut names = std::collections::HashSet::new();
        for hook in &self.hooks {
            if !names.insert(hook.name.as_str()) {
                bail!("[[hook]] names must be unique ({} appears twice)", hook.name);
            }
            if hook.actions.is_empty() {
                bail!("[[hook]] {}: actions is empty (pause, dump, command)", hook.name);
            }
            if hook.actions.contains(&fakenet_listeners::hooks::HookAction::Command) && hook.command.is_empty() {
                bail!("[[hook]] {}: the command action needs command = [\"program\", \"arg\", ...]", hook.name);
            }
        }
        if self.manual.enabled && self.manual.timeout_ms == 0 {
            bail!("[manual] timeout_ms must be > 0");
        }
        if self.nucleus.ca_cert.is_some() != self.nucleus.ca_key.is_some() {
            bail!("nucleus: set both ca_cert and ca_key, or neither");
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
            max_payload: usize::try_from(self.daemon.max_payload_kb.saturating_mul(1024)).unwrap_or(usize::MAX),
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
    let records = read_records_with(event_files, Some(REPORT_PAYLOAD_BYTES))?;
    let map = event_files
        .last()
        .and_then(|f| f.parent())
        .and_then(|dir| std::fs::read_to_string(dir.join("explorer-map.json")).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    std::fs::write(output, fakenet_capture::report::render_with_map(&records, map.as_ref())).with_context(|| format!("writing {}", output.display()))
}

/// The pcap files to learn from: files as given; in folders (capture folders, `previous/`
/// archives), every traffic*.pcap and wire*.pcap, recursively, sorted
pub fn learn_inputs(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>, depth: usize) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() && depth < 4 {
                walk(&path, found, depth + 1)?;
            } else if (name.starts_with("traffic") || name.starts_with("wire")) && name.ends_with(".pcap") {
                found.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    for path in paths {
        match path.is_dir() {
            true => {
                let mut found = Vec::new();
                walk(path, &mut found, 0)?;
                found.sort();
                files.extend(found);
            }
            false => files.push(path.clone()),
        }
    }
    Ok(files)
}

pub fn read_records(event_files: &[PathBuf]) -> anyhow::Result<Vec<serde_json::Value>> {
    read_records_with(event_files, None)
}

/// Payload bytes kept per record for the report and indicators (the full payloads stay in
/// events.jsonl and files/)
const REPORT_PAYLOAD_BYTES: usize = 1024;

/// Parses event files line by line; with `max_payload`, each record's payload is cut to that
/// many bytes (`payload_bytes` and `payload_truncated` say so), which keeps a large capture's
/// report within memory
pub fn read_records_with(event_files: &[PathBuf], max_payload: Option<usize>) -> anyhow::Result<Vec<serde_json::Value>> {
    use std::io::BufRead as _;
    let mut records = Vec::new();
    for file in event_files {
        let reader = std::io::BufReader::new(std::fs::File::open(file).with_context(|| format!("reading {}", file.display()))?);
        for line in reader.split(b'\n') {
            let line = line.with_context(|| format!("reading {}", file.display()))?;
            let Ok(mut record) = serde_json::from_slice::<serde_json::Value>(&line) else { continue };
            if let Some(max) = max_payload {
                trim_payload(&mut record, max);
            }
            records.push(record);
        }
    }
    Ok(records)
}

fn trim_payload(record: &mut serde_json::Value, max: usize) {
    let Some(encoded) = record["payload"].as_str() else { return };
    // Base64: 4 characters per 3 bytes
    if encoded.len() <= max.div_ceil(3) * 4 {
        return;
    }
    let Ok(bytes) = fakenet_schema::decode_base64(encoded) else { return };
    record["payload_bytes"] = json!(bytes.len());
    record["payload_truncated"] = json!(true);
    record["payload"] = json!(fakenet_schema::encode_base64(&bytes[..max.min(bytes.len())]));
}

/// Writes the event logs' indicators to `dir`: indicators.csv, indicators.stix.json (STIX
/// 2.1) and indicators.misp.json. `sample` is run.json's sample ({name, sha256, md5}), or
/// read from dir/run.json when there is one. Returns how many indicators there were.
pub fn write_indicators(event_files: &[PathBuf], dir: &Path, sample: Option<&serde_json::Value>) -> anyhow::Result<usize> {
    use fakenet_capture::indicators;
    let records = read_records_with(event_files, Some(REPORT_PAYLOAD_BYTES))?;
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
    // Per JSONL file: bytes consumed, and an incomplete last line kept for the next poll
    let mut tails: HashMap<PathBuf, (u64, Vec<u8>)> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.ends_with(".jsonl") {
                let (offset, partial) = tails.entry(path.clone()).or_default();
                if size < *offset {
                    // Truncated or replaced: start over
                    *offset = 0;
                    partial.clear();
                }
                if size == *offset {
                    continue;
                }
                let lines = match read_new_lines(&path, offset, partial) {
                    Ok(lines) => lines,
                    Err(e) => {
                        tracing::debug!("coverage file {name}: {e}");
                        continue;
                    }
                };
                for line in lines {
                    // Bytes, decoded per line: one bad line doesn't hide the rest of the file
                    let line = String::from_utf8_lossy(&line);
                    if line.trim().is_empty() {
                        continue;
                    }
                    match explorer.ingest_coverage_line(&line) {
                        Ok(new) if new > 0 => capture.log("coverage", json!({ "source": name, "new_functions": new })),
                        Ok(_) => {}
                        Err(e) => tracing::debug!("coverage line in {name}: {e}"),
                    }
                }
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

/// The complete lines appended to `path` since `offset` (only the new bytes are read),
/// holding a trailing partial line in `partial` until its newline arrives
fn read_new_lines(path: &Path, offset: &mut u64, partial: &mut Vec<u8>) -> std::io::Result<Vec<Vec<u8>>> {
    use std::io::{Read as _, Seek as _};
    /// Read per poll, so a huge file is consumed over several polls
    const CHUNK: u64 = 8 * 1024 * 1024;
    /// A "line" longer than this is dropped rather than buffered forever
    const MAX_LINE: usize = 1024 * 1024;
    let mut file = std::fs::File::open(path)?;
    file.seek(std::io::SeekFrom::Start(*offset))?;
    let mut data = Vec::new();
    file.take(CHUNK).read_to_end(&mut data)?;
    *offset += data.len() as u64;
    partial.extend_from_slice(&data);
    let mut lines = Vec::new();
    while let Some(end) = partial.iter().position(|&b| b == b'\n') {
        let rest = partial.split_off(end + 1);
        let mut line = std::mem::replace(partial, rest);
        line.pop();
        lines.push(line);
    }
    if partial.len() > MAX_LINE {
        partial.clear();
    }
    Ok(lines)
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
    pub manual: Option<Arc<fakenet_listeners::manual::Manual>>,
    pub hooks: Option<Arc<fakenet_listeners::hooks::Hooks>>,
    /// Dashboard logins
    pub sessions: Sessions,
}

/// Dashboard sessions: a login (POSTing the link secret once) gets a random token for the
/// cookie, so the secret itself is never in a URL, the browser history or the cookie store
#[derive(Default)]
pub struct Sessions(std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>);

/// How long a dashboard login lasts
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// Logins kept at once (the oldest goes first)
const MAX_SESSIONS: usize = 64;

impl Sessions {
    fn create(&self) -> String {
        let token = fakenet_schema::auth::random_hex(32);
        let mut sessions = self.0.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, created| created.elapsed() < SESSION_TTL);
        while sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = sessions.iter().min_by_key(|(_, created)| **created).map(|(t, _)| t.clone()) else { break };
            sessions.remove(&oldest);
        }
        sessions.insert(token.clone(), std::time::Instant::now());
        token
    }

    fn valid(&self, token: &str) -> bool {
        // 256 random bits: a lookup's timing reveals nothing usable
        self.0.lock().unwrap_or_else(|e| e.into_inner()).get(token).is_some_and(|created| created.elapsed() < SESSION_TTL)
    }

    fn end(&self, token: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }
}

/// The dashboard's login page (no script; posts to /dashboard/login)
const LOGIN_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FakeNet live</title><link rel="stylesheet" href="/dashboard.css"></head>
<body><main class="login"><h1><span class="brand">FakeNet</span> live</h1>
<form method="post" action="/dashboard/login">
<label>Link secret (the [daemon] secret_file's contents)<br><input type="password" name="token" autocomplete="off" autofocus required></label>
<button type="submit">Open the dashboard</button>
</form>MESSAGE</main></body></html>
"#;
const LOGIN_CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

fn login_page(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let message = if message.is_empty() { String::new() } else { format!("<p class=\"muted\">{message}</p>") };
    let mut response = plain_response(status, "text/html; charset=utf-8", LOGIN_HTML.replace("MESSAGE", &message));
    response.headers_mut().insert("content-security-policy", hyper::header::HeaderValue::from_static(LOGIN_CSP));
    response
}

/// `token=...` from a form body (percent-decoded)
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let value = text.split('&').find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))?;
    let bytes = value.replace('+', " ").into_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(byte)) => {
                decoded.push(byte);
                i += 3;
            }
            (byte, _) => {
                decoded.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn session_cookie(request: &hyper::Request<hyper::body::Incoming>) -> Option<String> {
    request
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix("fakenet_session=").map(str::to_string))
}

const DASHBOARD_HTML: &str = include_str!("dashboard/index.html");
const DASHBOARD_JS: &str = include_str!("dashboard/dashboard.js");
const DASHBOARD_CSS: &str = include_str!("dashboard/dashboard.css");
/// Everything shown comes from the sample: no inline script, nothing from elsewhere
const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The loopback control server:
/// - `GET /health`: "ok"; with the secret, the daemon link's state and the listeners
/// - `GET /dashboard?token=SECRET`: sets a cookie and redirects; `/dashboard` is the live view
/// - `GET /api/records?after=N`, `GET /api/summary`: the dashboard's data
/// - `GET /api/manual`, `GET /api/paused`: requests held for the analyst, processes paused
///   by hooks; answered with the POSTs in `control_post`
pub async fn serve_control(socket: TcpListener, control: Arc<Control>) {
    loop {
        let Ok((stream, _)) = socket.accept().await else { continue };
        let control = control.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let control = control.clone();
                async move {
                    let response = match request.method() == hyper::Method::POST {
                        true => control_post(&control, request).await,
                        false => control_response(&control, &request),
                    };
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
        });
    }
}

/// The largest body the control server reads (a manual answer)
const MAX_CONTROL_BODY: usize = 16 * 1024 * 1024;

fn plain_response(status: StatusCode, content_type: &str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("content-security-policy", DASHBOARD_CSP)
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

/// The analyst's actions (authenticated, JSON only, which a cross-site form can't send):
/// - `POST /api/manual/<id>`: answer a held request (see `manual::parse_verdict`)
/// - `POST /api/paused/<pid>/resume`: resume a process a hook paused
async fn control_post(control: &Control, request: hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt as _;
    let error = |status: StatusCode, message: &str| plain_response(status, "application/json", json!({ "error": message }).to_string());
    match request.uri().path() {
        "/dashboard/login" => return dashboard_login(control, request).await,
        "/dashboard/logout" => {
            if let Some(token) = session_cookie(&request) {
                control.sessions.end(&token);
            }
            let mut response = login_page(StatusCode::OK, "Logged out.");
            response.headers_mut().insert("set-cookie", hyper::header::HeaderValue::from_static("fakenet_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"));
            return response;
        }
        _ => {}
    }
    if !authorized(control, &request) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let json_body = request.headers().get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("application/json"));
    if !json_body {
        return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "send application/json");
    }
    let path = request.uri().path().to_string();
    let body = match http_body_util::Limited::new(request.into_body(), MAX_CONTROL_BODY).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body too large"),
    };
    let body: serde_json::Value = if body.is_empty() { json!({}) } else {
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(e) => return error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
        }
    };
    if let Some(id) = path.strip_prefix("/api/manual/").and_then(|id| id.parse::<u64>().ok()) {
        let Some(manual) = &control.manual else { return error(StatusCode::NOT_FOUND, "live manual mode is off") };
        return match fakenet_listeners::manual::parse_verdict(&body).map(|verdict| manual.resolve(id, verdict)) {
            Ok(true) => plain_response(StatusCode::OK, "application/json", r#"{"ok":true}"#.into()),
            Ok(false) => error(StatusCode::GONE, "not held any more (answered or timed out)"),
            Err(message) => error(StatusCode::BAD_REQUEST, &message),
        };
    }
    if let Some(pid) = path.strip_prefix("/api/paused/").and_then(|rest| rest.strip_suffix("/resume")).and_then(|pid| pid.parse::<u32>().ok()) {
        let Some(hooks) = &control.hooks else { return error(StatusCode::NOT_FOUND, "no hooks configured") };
        return match hooks.resume(pid) {
            Ok(true) => plain_response(StatusCode::OK, "application/json", r#"{"ok":true}"#.into()),
            Ok(false) => error(StatusCode::NOT_FOUND, "no hook paused that process"),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
    }
    error(StatusCode::NOT_FOUND, "not found")
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

/// The secret as a bearer token (scripts), or a dashboard session cookie (browsers)
fn authorized(control: &Control, request: &hyper::Request<hyper::body::Incoming>) -> bool {
    let Some(secret) = control.secret.as_deref() else { return true };
    let bearer = request.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    bearer.is_some_and(|token| constant_time_eq(token.as_bytes(), secret.as_bytes())) || session_cookie(request).is_some_and(|token| control.sessions.valid(&token))
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
        "/dashboard" if authorized => respond(StatusCode::OK, "text/html; charset=utf-8", DASHBOARD_HTML.to_string()),
        // The secret is never taken from a URL (it would land in the browser history)
        "/dashboard" if query_param(query, "token").is_some() => login_page(StatusCode::UNAUTHORIZED, "Secrets in the URL aren't accepted: enter it here."),
        "/dashboard" => login_page(StatusCode::UNAUTHORIZED, ""),
        "/dashboard.js" => respond(StatusCode::OK, "text/javascript; charset=utf-8", DASHBOARD_JS.to_string()),
        "/dashboard.css" => respond(StatusCode::OK, "text/css; charset=utf-8", DASHBOARD_CSS.to_string()),
        "/api/records" | "/api/summary" | "/api/manual" | "/api/paused" if !authorized => respond(StatusCode::UNAUTHORIZED, "application/json", r#"{"error":"unauthorized"}"#.into()),
        "/api/records" => {
            let after = query_param(query, "after").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit = query_param(query, "limit").and_then(|v| v.parse().ok()).unwrap_or(1000usize).min(5000);
            let (records, latest) = control.capture.recent(after, limit);
            let records: Vec<_> = records.into_iter().map(|(seq, record)| json!({ "seq": seq, "record": record })).collect();
            json_response(json!({ "latest": latest, "records": records }))
        }
        "/api/manual" => json_response(json!({
            "enabled": control.manual.is_some(),
            "timeout_ms": control.manual.as_ref().map(|m| m.config().timeout_ms),
            "pending": control.manual.as_ref().map(|m| m.pending()).unwrap_or_default(),
        })),
        "/api/paused" => json_response(json!({
            "hooks": control.hooks.is_some(),
            "paused": control.hooks.as_ref().map(|h| h.paused()).unwrap_or_default(),
        })),
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

/// POST /dashboard/login (a form with the link secret): a session cookie, then the dashboard
async fn dashboard_login(control: &Control, request: hyper::Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt as _;
    let Some(secret) = control.secret.as_deref() else {
        return redirect("/dashboard"); // No secret configured: nothing to log in to
    };
    let body = match http_body_util::Limited::new(request.into_body(), 4096).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return login_page(StatusCode::PAYLOAD_TOO_LARGE, "Too long."),
    };
    match form_field(&body, "token") {
        Some(token) if constant_time_eq(token.trim().as_bytes(), secret.as_bytes()) => {
            let mut response = redirect("/dashboard");
            if let Ok(cookie) = hyper::header::HeaderValue::from_str(&format!("fakenet_session={}; HttpOnly; SameSite=Strict; Path=/", control.sessions.create())) {
                response.headers_mut().insert("set-cookie", cookie);
            }
            response
        }
        _ => login_page(StatusCode::UNAUTHORIZED, "That isn't the link secret."),
    }
}

fn redirect(location: &'static str) -> Response<Full<Bytes>> {
    let mut response = plain_response(StatusCode::SEE_OTHER, "text/plain", String::new());
    response.headers_mut().insert("location", hyper::header::HeaderValue::from_static(location));
    response
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

    #[test]
    fn report_records_keep_a_payload_preview() {
        let dir = std::env::temp_dir().join(format!("fakenet-trim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let big = fakenet_schema::encode_base64(&vec![b'A'; 100_000]);
        let small = fakenet_schema::encode_base64(b"hi");
        let path = dir.join("events.jsonl");
        std::fs::write(&path, format!("{{\"kind\":\"event\",\"payload\":\"{big}\"}}\nnot json\n{{\"kind\":\"event\",\"payload\":\"{small}\"}}\n")).unwrap();
        let records = read_records_with(std::slice::from_ref(&path), Some(1024)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["payload_bytes"], 100_000);
        assert_eq!(fakenet_schema::decode_base64(records[0]["payload"].as_str().unwrap()).unwrap().len(), 1024);
        assert_eq!(records[1]["payload"], small.as_str());
        assert!(records[1]["payload_truncated"].is_null());
        assert_eq!(read_records(&[path]).unwrap()[0]["payload"], big.as_str()); // Untrimmed for --infer and friends
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_files_are_read_incrementally() {
        let dir = std::env::temp_dir().join(format!("fakenet-coverage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cov.jsonl");
        std::fs::write(&path, b"{\"a\":1}\n\xff\xfe bad\n{\"b\":").unwrap();
        let (mut offset, mut partial) = (0, Vec::new());
        let lines = read_new_lines(&path, &mut offset, &mut partial).unwrap();
        assert_eq!(lines, [b"{\"a\":1}".to_vec(), b"\xff\xfe bad".to_vec()]); // Invalid UTF-8 doesn't stop the file
        assert_eq!(partial, b"{\"b\":");
        std::io::Write::write_all(&mut std::fs::OpenOptions::new().append(true).open(&path).unwrap(), b"2}\n").unwrap();
        let lines = read_new_lines(&path, &mut offset, &mut partial).unwrap();
        assert_eq!(lines, [b"{\"b\":2}".to_vec()]);
        assert_eq!(offset, std::fs::metadata(&path).unwrap().len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diverting_ftp_needs_a_passive_range() {
        let ftp = "[diverter]\nenabled = true\n[[listener]]\nname = \"ftp\"\nprotocol = \"ftp\"\nport = 21\n[[listener]]\nname = \"a\"\nprotocol = \"auto\"\nport = 1337\n[[listener]]\nname = \"u\"\nprotocol = \"auto\"\ntransport = \"udp\"\nport = 1338\n";
        let config = parse(ftp).unwrap();
        assert_eq!(config.plan().passive_ports, Some((60000, 60010))); // The default range
        assert!(parse(&format!("[defaults.ftp]\npassive_ports = [0, 0]\n{ftp}")).is_err());
        assert!(parse(&format!("[nucleus]\nca_cert = \"ca.pem\"\n{ftp}")).is_err()); // ca_key missing
    }
}
