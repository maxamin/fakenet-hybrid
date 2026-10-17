//! The nucleus's TOML config, its validation, and the loopback-only health endpoint

pub mod import;

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
        }
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

/// The HTML report of event logs (in order, e.g. rotated ones first)
pub fn write_report(event_files: &[PathBuf], output: &Path) -> anyhow::Result<()> {
    let mut records = Vec::new();
    for file in event_files {
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        records.extend(text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()));
    }
    std::fs::write(output, fakenet_capture::report::render(&records)).with_context(|| format!("writing {}", output.display()))
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

/// GET /health: the nucleus is up. With the link secret as a bearer token (or when no
/// secret is configured) it also reports the daemon link's state & counters and the
/// listeners. The nucleus is healthy whether or not the daemon is (it falls back).
pub async fn serve_health(socket: TcpListener, link: Link, listeners: Arc<Vec<(String, Transport, SocketAddr)>>, secret: Option<String>) {
    let secret = Arc::new(secret);
    loop {
        let Ok((stream, _)) = socket.accept().await else { continue };
        let (link, listeners, secret) = (link.clone(), listeners.clone(), secret.clone());
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let (link, listeners, secret) = (link.clone(), listeners.clone(), secret.clone());
                async move {
                    let authorized = match secret.as_deref() {
                        None => true,
                        Some(secret) => request
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "))
                            .is_some_and(|token| constant_time_eq(token.as_bytes(), secret.as_bytes())),
                    };
                    let (status, body) = if request.uri().path() == "/health" && !authorized {
                        (StatusCode::OK, json!({ "status": "ok" }))
                    } else if request.uri().path() == "/health" {
                        let listeners: Vec<_> = listeners.iter().map(|(n, t, a)| json!({ "name": n, "transport": t, "address": a.to_string() })).collect();
                        (StatusCode::OK, json!({ "status": "ok", "daemon": link.health(), "listeners": listeners }))
                    } else {
                        (StatusCode::NOT_FOUND, json!({ "error": "not found" }))
                    };
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body.to_string())))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
        });
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
        assert_eq!(plan.tcp_ports, [53, 80, 443, 25, 465, 110, 21, 6667, 143, 23, 6379, 1080, 22]);
        assert_eq!(plan.udp_ports, [53, 443, 69, 123, 514]); // 443: HTTP/3
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
