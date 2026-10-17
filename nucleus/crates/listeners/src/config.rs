//! Listener configuration (the `[[listener]]` and `[defaults.*]` tables of the TOML config)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use fakenet_schema::{Protocol, Transport};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    /// A protocol, or "auto" to sniff each connection's protocol (the catch-all listener)
    pub protocol: ListenerProtocol,
    #[serde(default = "default_transport")]
    pub transport: Transport,
    pub port: u16,
    /// Terminate TLS before the protocol (e.g. HTTPS on 443)
    #[serde(default)]
    pub tls: bool,
    /// A FakeNet-NG Custom Response INI file (http and raw listeners)
    #[serde(default)]
    pub custom: Option<std::path::PathBuf>,
    /// FakeNet-NG's per-listener filters: connections that fail them are closed (and logged)
    #[serde(default)]
    pub process_whitelist: Vec<String>,
    #[serde(default)]
    pub process_blacklist: Vec<String>,
    #[serde(default)]
    pub host_whitelist: Vec<String>,
    #[serde(default)]
    pub host_blacklist: Vec<String>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig {
            name: String::new(),
            protocol: ListenerProtocol::Auto(AutoKeyword::Auto),
            transport: Transport::Tcp,
            port: 0,
            tls: false,
            custom: None,
            process_whitelist: Vec::new(),
            process_blacklist: Vec::new(),
            host_whitelist: Vec::new(),
            host_blacklist: Vec::new(),
        }
    }
}

fn default_transport() -> Transport {
    Transport::Tcp
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ListenerProtocol {
    Fixed(Protocol),
    Auto(AutoKeyword),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoKeyword {
    Auto,
}

/// Built-in default responses: what the malware gets whenever the daemon doesn't decide
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    pub http: HttpDefaults,
    pub dns: DnsDefaults,
    pub raw: RawDefaults,
    pub mail: MailDefaults,
    pub ftp: FtpDefaults,
    pub irc: IrcDefaults,
    pub tftp: TftpDefaults,
    pub ssh: SshDefaults,
    pub telnet: TelnetDefaults,
    pub ntp: NtpDefaults,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            http: HttpDefaults::default(),
            dns: DnsDefaults::default(),
            raw: RawDefaults::default(),
            mail: MailDefaults::default(),
            ftp: FtpDefaults::default(),
            irc: IrcDefaults::default(),
            tftp: TftpDefaults::default(),
            ssh: SshDefaults::default(),
            telnet: TelnetDefaults::default(),
            ntp: NtpDefaults::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpDefaults {
    /// Files served by path; requests for missing files get a default file of their type
    pub webroot: Option<PathBuf>,
    pub server_header: String,
    pub max_body_bytes: usize,
    /// Save request bodies (POST/PUT...) under files/
    pub save_bodies: bool,
}

impl Default for HttpDefaults {
    fn default() -> Self {
        HttpDefaults { webroot: None, server_header: "Microsoft-IIS/10.0".into(), max_body_bytes: 16 << 20, save_bodies: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsDefaults {
    pub a: Ipv4Addr,
    pub aaaa: Option<Ipv6Addr>,
    pub mx: String,
    pub txt: String,
    pub ttl: u32,
}

impl Default for DnsDefaults {
    fn default() -> Self {
        DnsDefaults { a: Ipv4Addr::new(192, 0, 2, 123), aaaa: None, mx: "mail.fakenet.local".into(), txt: "FAKENET".into(), ttl: 60 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RawDefaults {
    /// "echo" (FakeNet-NG's default) or "static"
    pub mode: RawMode,
    /// For mode = "static"
    pub response: String,
}

impl Default for RawDefaults {
    fn default() -> Self {
        RawDefaults { mode: RawMode::Echo, response: String::new() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawMode {
    Echo,
    Static,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MailDefaults {
    pub hostname: String,
}

impl Default for MailDefaults {
    fn default() -> Self {
        MailDefaults { hostname: "mail.fakenet.local".into() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FtpDefaults {
    pub root: Option<PathBuf>,
    pub banner: String,
    /// Passive data connection ports; 0 = any free port
    pub passive_ports: (u16, u16),
}

impl Default for FtpDefaults {
    fn default() -> Self {
        FtpDefaults { root: None, banner: "FTP Server Ready".into(), passive_ports: (0, 0) }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IrcDefaults {
    pub server_name: String,
}

impl Default for IrcDefaults {
    fn default() -> Self {
        IrcDefaults { server_name: "irc.fakenet.local".into() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TftpDefaults {
    pub root: Option<PathBuf>,
}

impl Default for TftpDefaults {
    fn default() -> Self {
        TftpDefaults { root: None }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshDefaults {
    pub banner: String,
}

impl Default for SshDefaults {
    fn default() -> Self {
        SshDefaults { banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10".into() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelnetDefaults {
    pub banner: String,
}

impl Default for TelnetDefaults {
    fn default() -> Self {
        TelnetDefaults { banner: "Ubuntu 20.04.6 LTS".into() }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NtpDefaults {
    /// Seconds added to the time served (e.g. to trigger time-bombed behaviour)
    pub time_offset: i64,
}

pub fn bind_any() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}
