//! FakeNet-NG Custom Responses (its docs/CustomResponse.md): a listener's `custom` setting
//! names an INI file whose sections override responses for HTTP listeners (matched by host
//! and/or URI) and raw TCP/UDP listeners. Static responses (strings, base64, raw files) and
//! FakeNet-NG's Python providers (HttpDynamic/TcpDynamic/UdpDynamic, unmodified, Unix only)
//! are supported. A custom response is the listener's *default*: the daemon can still
//! override it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use fakenet_schema::{Protocol, Transport};
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::config::{ListenerConfig, ListenerProtocol};

const PROVIDER_SHIM: &str = include_str!("providers.py");
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

/// One INI section, keys lowercased
#[derive(Debug, Clone, Default)]
pub struct Section {
    pub name: String,
    values: Vec<(String, String)>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn get_list(&self, key: &str) -> Vec<String> {
        self.get(key).map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
    }
}

/// Python configparser-style INI: [sections], "key: value" or "key = value", ; and #
/// comments, indented continuation lines
pub fn parse_ini(text: &str) -> Result<Vec<Section>> {
    let mut sections: Vec<Section> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|n| n.strip_suffix(']')) {
            sections.push(Section { name: name.trim().to_string(), values: Vec::new() });
            continue;
        }
        let section = sections.last_mut().ok_or_else(|| anyhow!("line {}: a setting before any [section]", number + 1))?;
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = section.values.last_mut() {
                value.push('\n');
                value.push_str(trimmed);
                continue;
            }
        }
        let split = trimmed.find([':', '=']).ok_or_else(|| anyhow!("line {}: expected key: value", number + 1))?;
        let (key, value) = trimmed.split_at(split);
        section.values.push((key.trim().to_ascii_lowercase(), value[1..].trim().to_string()));
    }
    Ok(sections)
}

#[derive(Debug, Clone)]
pub enum HttpResponse {
    /// A complete raw HTTP response (<RAW-DATE> replaced)
    Raw(Vec<u8>),
    /// A body for a 200 response
    Static { text: String, content_type: Option<String> },
    /// A FakeNet-NG Python provider (HandleHttp / HandleRequest)
    Dynamic(PathBuf),
}

#[derive(Debug, Clone)]
pub struct HttpCustom {
    pub name: String,
    hosts: Vec<String>,
    uris: Vec<String>,
    pub response: HttpResponse,
}

impl HttpCustom {
    /// FakeNet-NG's matching: hosts case-insensitively (with or without the port), URIs as
    /// suffixes; both must match when both are configured
    pub fn matches(&self, host: &str, uri: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        let host_match = self.hosts.contains(&host) || host.split_once(':').is_some_and(|(name, _)| self.hosts.iter().any(|h| h == name));
        let uri_match = self.uris.iter().any(|u| uri.ends_with(u.as_str()));
        if !self.hosts.is_empty() && !self.uris.is_empty() { host_match && uri_match } else { host_match || uri_match }
    }
}

#[derive(Debug, Clone)]
pub enum RawResponse {
    /// Sent in reply to every chunk (TCP) or datagram (UDP)
    Static(Vec<u8>),
    /// A FakeNet-NG Python provider (HandleTcp / HandleUdp), which takes over the exchange
    Dynamic(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub struct CustomResponses {
    pub http: Vec<HttpCustom>,
    pub raw: Option<(String, RawResponse)>,
}

/// As given if it exists, else relative to the custom file's directory
fn qualify(value: &str, base: &Path) -> Result<PathBuf> {
    let direct = PathBuf::from(value);
    if direct.exists() {
        return Ok(direct);
    }
    let relative = base.join(value);
    if relative.exists() {
        return Ok(relative);
    }
    bail!("cannot find {value}")
}

fn exactly_one<'a>(section: &'a Section, keys: &[&'a str]) -> Result<(&'a str, &'a str)> {
    let present: Vec<(&str, &str)> = keys.iter().filter_map(|k| section.get(k).map(|v| (*k, v))).collect();
    match present[..] {
        [one] => Ok(one),
        _ => bail!("custom section {} has {} of {}", section.name, present.len(), keys.join("/")),
    }
}

impl CustomResponses {
    /// The responses for one listener: sections whose InstanceName is the listener's name,
    /// or whose ListenerType is HTTP / TCP / UDP matching it
    pub fn load(file: &Path, listener: &ListenerConfig) -> Result<CustomResponses> {
        let text = std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let base = file.parent().unwrap_or(Path::new("."));
        let kind = match (listener.protocol, listener.transport) {
            (ListenerProtocol::Fixed(Protocol::Http), _) => "HTTP",
            (ListenerProtocol::Fixed(Protocol::Raw), Transport::Tcp) => "TCP",
            (ListenerProtocol::Fixed(Protocol::Raw), Transport::Udp) => "UDP",
            _ => bail!("listener {}: custom responses need protocol \"http\" or \"raw\"", listener.name),
        };
        let mut responses = CustomResponses::default();
        for section in parse_ini(&text).with_context(|| format!("parsing {}", file.display()))? {
            let (instance, section_kind) = (section.get("instancename"), section.get("listenertype"));
            if instance.is_none() && section_kind.is_none() {
                bail!("custom section {} lacks ListenerType or InstanceName", section.name);
            }
            let applies = instance.is_some_and(|i| i.eq_ignore_ascii_case(&listener.name)) || section_kind.is_some_and(|t| t.eq_ignore_ascii_case(kind));
            if !applies {
                continue;
            }
            if kind == "HTTP" {
                responses.http.push(parse_http(&section, base)?);
            } else {
                if responses.raw.is_some() {
                    bail!("only one {kind} custom response can apply to a listener");
                }
                responses.raw = Some((section.name.clone(), parse_raw(&section, kind, base)?));
            }
        }
        Ok(responses)
    }

    pub fn match_http(&self, host: &str, uri: &str) -> Option<&HttpCustom> {
        self.http.iter().find(|c| c.matches(host, uri))
    }
}

fn parse_http(section: &Section, base: &Path) -> Result<HttpCustom> {
    let hosts: Vec<String> = section.get_list("httphosts").into_iter().map(|h| h.to_ascii_lowercase()).collect();
    let uris = section.get_list("httpuris");
    if hosts.is_empty() && uris.is_empty() {
        bail!("custom HTTP section {} lacks HttpURIs/HttpHosts", section.name);
    }
    let (key, value) = exactly_one(section, &["httprawfile", "httpstaticstring", "httpdynamic"])?;
    if section.get("contenttype").is_some() && key != "httpstaticstring" {
        bail!("custom HTTP section {}: ContentType only goes with HttpStaticString", section.name);
    }
    let response = match key {
        "httprawfile" => HttpResponse::Raw(std::fs::read(qualify(value, base)?)?),
        "httpstaticstring" => HttpResponse::Static { text: value.replace("\\r\\n", "\r\n"), content_type: section.get("contenttype").map(str::to_string) },
        _ => HttpResponse::Dynamic(qualify(value, base)?),
    };
    Ok(HttpCustom { name: section.name.clone(), hosts, uris, response })
}

fn parse_raw(section: &Section, kind: &str, base: &Path) -> Result<RawResponse> {
    let p = kind.to_ascii_lowercase();
    let keys = [format!("{p}rawfile"), format!("{p}staticstring"), format!("{p}staticbase64"), format!("{p}dynamic")];
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let (key, value) = exactly_one(section, &refs)?;
    Ok(if key.ends_with("staticstring") {
        RawResponse::Static(value.trim_end_matches(['\r', '\n']).as_bytes().to_vec())
    } else if key.ends_with("staticbase64") {
        RawResponse::Static(fakenet_schema::decode_base64(value.trim()).map_err(|e| anyhow!("[{}] invalid base64: {e}", section.name))?)
    } else if key.ends_with("rawfile") {
        RawResponse::Static(std::fs::read(qualify(value, base)?)?)
    } else {
        RawResponse::Dynamic(qualify(value, base)?)
    })
}

/// FakeNet-NG's <RAW-DATE> token, replaced by the current HTTP date
pub fn replace_date(data: &[u8]) -> Vec<u8> {
    let date = httpdate(std::time::SystemTime::now());
    let token = b"<RAW-DATE>";
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(token) {
            out.extend_from_slice(date.as_bytes());
            i += token.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

fn httpdate(time: std::time::SystemTime) -> String {
    let format = time::macros::format_description!("[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT");
    time::OffsetDateTime::from(time).format(&format).unwrap_or_default()
}

fn provider_command(mode: &str, provider: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("python3");
    command.arg("-I").arg("-c").arg(PROVIDER_SHIM).arg(mode).arg(provider).kill_on_drop(true);
    command
}

/// One request through an HttpDynamic provider: the raw response it wrote
pub async fn run_http_provider(provider: &Path, method: &str, target: &str, headers: &[(String, String)], body: &[u8], peer: std::net::SocketAddr) -> Result<Vec<u8>> {
    let input = json!({
        "method": method, "target": target, "version": "HTTP/1.1", "headers": headers,
        "body": fakenet_schema::encode_base64(body), "peer_host": peer.ip().to_string(), "peer_port": peer.port(),
    });
    let mut child = provider_command("http", provider)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running python3 for an HttpDynamic provider")?;
    let mut stdin = child.stdin.take().expect("piped");
    stdin.write_all(input.to_string().as_bytes()).await?;
    drop(stdin);
    let output = tokio::time::timeout(PROVIDER_TIMEOUT, child.wait_with_output()).await.map_err(|_| anyhow!("provider {} timed out", provider.display()))??;
    if !output.status.success() {
        bail!("provider {} failed: {}", provider.display(), String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(output.stdout)
}

/// Hands a TCP connection to a TcpDynamic provider (its socket is fd 3), until either side
/// closes. Thin FFI: dup2 in the child, between fork and exec, on a descriptor we own.
#[cfg(unix)]
pub async fn run_tcp_provider(provider: &Path, mut stream: crate::stream::BoxStream, timeout: Duration) -> Result<()> {
    use std::os::fd::{AsRawFd, OwnedFd};
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let theirs: OwnedFd = theirs.into();
    let theirs_fd = theirs.as_raw_fd();
    let mut command = provider_command("tcp", provider);
    command.env("FAKENET_TIMEOUT", timeout.as_secs_f64().to_string());
    // SAFETY: only async-signal-safe dup2 runs in the child; theirs_fd stays open until
    // after spawn() returns (dropped below)
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(theirs_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("running python3 for a TcpDynamic provider")?;
    drop(theirs);
    ours.set_nonblocking(true)?;
    let mut ours = tokio::net::UnixStream::from_std(ours)?;
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut ours).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    Ok(())
}

/// Hands a datagram to a UdpDynamic provider, which replies through the listener's own
/// socket (fd 3). Same FFI contract as `run_tcp_provider`.
#[cfg(unix)]
pub async fn run_udp_provider(provider: &Path, socket: &tokio::net::UdpSocket, data: &[u8], peer: std::net::SocketAddr) -> Result<()> {
    use std::os::fd::AsRawFd;
    let socket_fd = socket.as_raw_fd();
    let mut command = provider_command("udp", provider);
    command
        .env("FAKENET_UDP_DATA", fakenet_schema::encode_base64(data))
        .env("FAKENET_UDP_HOST", peer.ip().to_string())
        .env("FAKENET_UDP_PORT", peer.port().to_string());
    // SAFETY: as above; the socket outlives the child's spawn
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(socket_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let status = tokio::time::timeout(PROVIDER_TIMEOUT, command.status()).await.map_err(|_| anyhow!("provider {} timed out", provider.display()))??;
    if !status.success() {
        bail!("provider {} failed ({status})", provider.display());
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_tcp_provider(_provider: &Path, _stream: crate::stream::BoxStream, _timeout: Duration) -> Result<()> {
    bail!("TcpDynamic providers are only supported on Unix")
}

#[cfg(not(unix))]
pub async fn run_udp_provider(_provider: &Path, _socket: &tokio::net::UdpSocket, _data: &[u8], _peer: std::net::SocketAddr) -> Result<()> {
    bail!("UdpDynamic providers are only supported on Unix")
}

/// FakeNet-NG's per-listener ProcessWhiteList/BlackList & HostWhiteList/BlackList: why a
/// connection must be refused, if it must
pub fn filter(listener: &ListenerConfig, process: Option<&fakenet_schema::ProcessInfo>, destination: std::net::IpAddr) -> Option<&'static str> {
    let matches_process = |list: &[String]| {
        process.is_some_and(|p| {
            let exe_name = p.exe.as_deref().and_then(|e| e.rsplit(['/', '\\']).next()).unwrap_or("");
            list.iter().any(|item| item.eq_ignore_ascii_case(&p.name) || item.eq_ignore_ascii_case(exe_name))
        })
    };
    let matches_host = |list: &[String]| list.iter().any(|item| item.parse::<std::net::IpAddr>().is_ok_and(|i| i.to_canonical() == destination.to_canonical()));
    if !listener.process_whitelist.is_empty() && !matches_process(&listener.process_whitelist) {
        return Some("process not in process_whitelist");
    }
    if matches_process(&listener.process_blacklist) {
        return Some("process in process_blacklist");
    }
    if !listener.host_whitelist.is_empty() && !matches_host(&listener.host_whitelist) {
        return Some("destination not in host_whitelist");
    }
    if matches_host(&listener.host_blacklist) {
        return Some("destination in host_blacklist");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/custom/sample_custom_response.ini");

    fn listener(name: &str, protocol: Protocol, transport: Transport) -> ListenerConfig {
        ListenerConfig { name: name.into(), protocol: ListenerProtocol::Fixed(protocol), transport, ..ListenerConfig::default() }
    }

    #[test]
    fn loads_fakenet_ngs_own_sample() {
        let sample = Path::new(SAMPLE);
        let http = CustomResponses::load(sample, &listener("HTTPListener80", Protocol::Http, Transport::Tcp)).unwrap();
        assert!(!http.http.is_empty());
        let raw = CustomResponses::load(sample, &listener("RawTCPListener", Protocol::Raw, Transport::Tcp)).unwrap();
        assert!(raw.raw.is_some());
        assert!(CustomResponses::load(sample, &listener("x", Protocol::Dns, Transport::Udp)).is_err());
    }

    #[test]
    fn parses_ini_and_matches_like_fakenet() {
        let sections = parse_ini("; c\n[A]\nInstanceName: HTTP\nHttpHosts = evil.example, c2.example\nHttpURIs: /gate.php\nHttpStaticString: hi\\r\\n\n").unwrap();
        let custom = parse_http(&sections[0], Path::new(".")).unwrap();
        assert!(custom.matches("C2.example:8080", "/x/gate.php"));
        assert!(!custom.matches("c2.example", "/other"));
        assert!(matches!(&custom.response, HttpResponse::Static { text, .. } if text == "hi\r\n"));
        assert!(replace_date(b"Date: <RAW-DATE>").ends_with(b" GMT"));
    }

    #[test]
    fn filters_by_process_and_host() {
        let mut config = listener("x", Protocol::Raw, Transport::Tcp);
        config.process_blacklist = vec!["chrome.exe".into()];
        config.host_whitelist = vec!["10.0.0.1".into()];
        let chrome = fakenet_schema::ProcessInfo { pid: 1, name: "chrome".into(), exe: Some("C:\\x\\chrome.exe".into()) };
        assert_eq!(filter(&config, Some(&chrome), "10.0.0.1".parse().unwrap()), Some("process in process_blacklist"));
        assert_eq!(filter(&config, None, "10.0.0.2".parse().unwrap()), Some("destination not in host_whitelist"));
        assert_eq!(filter(&config, None, "::ffff:10.0.0.1".parse().unwrap()), None);
    }
}
