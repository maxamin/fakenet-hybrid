//! Converts a FakeNet-NG configuration (default.ini, including fakenet-rs's extended one)
//! into this nucleus's TOML config, so existing setups carry over. Anything without an equivalent is listed as a comment at
//! the top of the output, never silently dropped.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use fakenet_listeners::custom::{parse_ini, Section};
use toml::{Table, Value};

/// FakeNet-NG listener types and their protocol here ("auto": the sniffing ProxyListener)
fn protocol_for(kind: &str) -> Option<&'static str> {
    Some(match kind.to_ascii_lowercase().as_str() {
        "proxylistener" => "auto",
        "rawlistener" => "raw",
        "httplistener" | "bitslistener" => "http",
        "dnslistener" => "dns",
        "smtplistener" => "smtp",
        "poplistener" => "pop3",
        "ftplistener" => "ftp",
        "tftplistener" => "tftp",
        "irclistener" => "irc",
        "imaplistener" => "imap",
        "sshlistener" => "ssh",
        "telnetlistener" => "telnet",
        "ntplistener" => "ntp",
        // fakenet-rs's extra listener types
        "redislistener" => "redis",
        "socks5listener" | "sockslistener" => "socks",
        "sysloglistener" => "syslog",
        "echolistener" => "echo",
        "discardlistener" => "discard",
        "daytimelistener" => "daytime",
        "chargenlistener" => "chargen",
        "timelistener" => "time",
        "qotdlistener" => "qotd",
        "fingerlistener" => "finger",
        "whoislistener" => "whois",
        _ => return None,
    })
}

fn yes(value: Option<&str>) -> bool {
    value.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on"))
}

fn ports(value: &str) -> Vec<u16> {
    value.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn strings(section: &Section, key: &str) -> Option<Value> {
    let list = section.get_list(key);
    (!list.is_empty()).then(|| Value::Array(list.into_iter().map(Value::String).collect()))
}

/// A path relative to the INI's directory, as FakeNet-NG resolves them
fn resolve(base: &Path, value: &str) -> String {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() { path } else { base.join(path) }.display().to_string()
}

pub fn convert(ini: &str, base: &Path) -> anyhow::Result<String> {
    let sections = parse_ini(ini).context("parsing the FakeNet-NG config")?;
    let mut notes: Vec<String> = Vec::new();
    let mut listeners: Vec<Value> = Vec::new();
    let mut diverter = Table::new();
    let mut http = Table::new();
    let mut ftp = Table::new();
    let mut tftp = Table::new();

    for section in &sections {
        match section.name.to_ascii_lowercase().as_str() {
            "fakenet" => continue,
            "diverter" => {
                let gateway = section.get("networkmode").is_some_and(|m| m.eq_ignore_ascii_case("multihost"));
                diverter.insert("mode".into(), Value::String(if gateway { "gateway" } else { "single_host" }.into()));
                let mut ignore: Vec<u16> = section.get("blacklistportstcp").map(ports).unwrap_or_default();
                for port in section.get("blacklistportsudp").map(ports).unwrap_or_default() {
                    if !ignore.contains(&port) {
                        ignore.push(port);
                    }
                }
                if !ignore.is_empty() {
                    diverter.insert("ignore_ports".into(), Value::Array(ignore.into_iter().map(|p| Value::Integer(p.into())).collect()));
                    notes.push("BlackListPortsTCP/UDP were merged into ignore_ports (both transports)".into());
                }
                if let Some(processes) = strings(section, "processblacklist") {
                    diverter.insert("excluded_processes".into(), processes);
                }
                if yes(section.get("modifylocaldns")) {
                    diverter.insert("fix_dns".into(), Value::Boolean(true));
                }
                if yes(section.get("fixgateway")) {
                    diverter.insert("fix_gateway".into(), Value::Boolean(true));
                }
                for unsupported in ["hostblacklist", "processwhitelist", "dumppackets", "stopdnsservice", "linuxrestrictinterface"] {
                    if let Some(value) = section.get(unsupported) {
                        notes.push(format!("[Diverter] {unsupported} = {value}: no direct equivalent (see [nucleus] wire_capture and per-listener filters)"));
                    }
                }
                continue;
            }
            _ => {}
        }
        if section.get("enabled").is_some_and(|e| !yes(Some(e))) {
            continue;
        }
        let Some(port_text) = section.get("port") else { continue };
        // A port range is FakeNet-NG's FTP passive range
        if let Some((first, last)) = port_text.split_once('-') {
            if let (Ok(first), Ok(last)) = (first.trim().parse::<i64>(), last.trim().parse::<i64>()) {
                ftp.insert("passive_ports".into(), Value::Array(vec![Value::Integer(first), Value::Integer(last)]));
            }
            continue;
        }
        let Ok(port) = port_text.trim().parse::<i64>() else {
            notes.push(format!("[{}]: unreadable Port {port_text}", section.name));
            continue;
        };
        let Some(kind) = section.get("listener") else {
            notes.push(format!("[{}]: no Listener type (e.g. a forwarder), skipped", section.name));
            continue;
        };
        let Some(protocol) = protocol_for(kind) else {
            notes.push(format!("[{}]: listener type {kind} has no equivalent, skipped", section.name));
            continue;
        };
        let mut listener = Table::new();
        listener.insert("name".into(), Value::String(section.name.clone()));
        listener.insert("protocol".into(), Value::String(protocol.into()));
        let transport = section.get("protocol").unwrap_or("TCP").to_ascii_lowercase();
        listener.insert("transport".into(), Value::String(if transport == "udp" { "udp" } else { "tcp" }.into()));
        listener.insert("port".into(), Value::Integer(port));
        if yes(section.get("usessl")) {
            listener.insert("tls".into(), Value::Boolean(true));
        }
        if let Some(custom) = section.get("custom") {
            listener.insert("custom".into(), Value::String(resolve(base, custom)));
        }
        for (key, name) in [("processwhitelist", "process_whitelist"), ("processblacklist", "process_blacklist"), ("hostwhitelist", "host_whitelist"), ("hostblacklist", "host_blacklist")] {
            if let Some(list) = strings(section, key) {
                listener.insert(name.into(), list);
            }
        }
        if let Some(webroot) = section.get("webroot") {
            http.entry("webroot").or_insert_with(|| Value::String(resolve(base, webroot)));
        }
        if let Some(root) = section.get("ftproot") {
            ftp.entry("root").or_insert_with(|| Value::String(resolve(base, root)));
        }
        if let Some(root) = section.get("tftproot") {
            tftp.entry("root").or_insert_with(|| Value::String(resolve(base, root)));
        }
        if protocol == "auto" && section.get("listeners").is_some() {
            notes.push(format!("[{}]: the auto listener sniffs every supported protocol (its Listeners list isn't needed)", section.name));
        }
        listeners.push(Value::Table(listener));
    }

    let mut config = Table::new();
    if !diverter.is_empty() {
        config.insert("diverter".into(), Value::Table(diverter));
    }
    let mut defaults = Table::new();
    for (name, table) in [("http", http), ("ftp", ftp), ("tftp", tftp)] {
        if !table.is_empty() {
            defaults.insert(name.into(), Value::Table(table));
        }
    }
    if !defaults.is_empty() {
        config.insert("defaults".into(), Value::Table(defaults));
    }
    config.insert("listener".into(), Value::Array(listeners));

    let mut out = String::from("# Converted from a FakeNet-NG configuration by fakenet-nucleus --import-fakenet-ini.\n# Review it; [nucleus] and [daemon] use their defaults (see config/fakenet.toml).\n");
    for note in &notes {
        // Notes quote the input: control characters (and line breaks, which would end the
        // comment and inject config) are escaped
        let safe: String = note.chars().flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] }).collect();
        out.push_str(&format!("# NOTE: {safe}\n"));
    }
    out.push('\n');
    out.push_str(&toml::to_string(&config)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_fakenet_ngs_default_config() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let ini = std::fs::read_to_string(fixtures.join("fakenet-ng-default.ini")).unwrap();
        let toml = convert(&ini, Path::new("/opt/fakenet/configs")).unwrap();
        let config: crate::Config = toml::from_str(&toml).unwrap_or_else(|e| panic!("{e}\n{toml}"));
        config.validate().unwrap();
        let named = |name: &str| config.listeners.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("no {name} in\n{toml}"));
        assert!(named("HTTPListener443").tls);
        assert_eq!(named("DNS Server").transport, fakenet_schema::Transport::Udp);
        assert!(matches!(named("ProxyTCPListener").protocol, fakenet_listeners::config::ListenerProtocol::Auto(_)));
        assert!(config.listeners.iter().all(|l| l.name != "FilteredListener")); // Enabled: False
        assert_eq!(config.defaults.ftp.passive_ports, (60000, 60010));
        assert_eq!(config.defaults.http.webroot.as_deref(), Some(Path::new("/opt/fakenet/configs/defaultFiles/")));
        assert!(config.diverter.fix_dns && config.diverter.fix_gateway);
        assert!(config.diverter.ignore_ports.contains(&139) && config.diverter.ignore_ports.contains(&5355));
        assert!(!config.diverter.enabled); // Never switched on by an import
        assert!(toml.contains("# NOTE:"));
        // The plan sends unlisted traffic to the converted proxy listeners
        let plan = config.plan();
        assert_eq!((plan.tcp_default, plan.udp_default), (Some(38926), Some(38926)));
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    /// Found by fuzzing: a control character in a quoted value made the output invalid TOML;
    /// a line break could have injected settings
    #[test]
    fn quoted_values_cant_break_out_of_comments() {
        let ini = "[Diverter]\nNetworkMode: SingleHost\n[HTTP]\nEnabled: True\nPort: 8\u{10}\nProtocol: TCP\nListener: HTTPListener\n[X]\nEnabled: True\nPort: 1\nListener: Weird\n  [diverter]\n  enabled = true\n";
        let toml_text = convert(ini, Path::new("/base")).unwrap();
        let table: toml::Table = toml_text.parse().unwrap_or_else(|e| panic!("{e}\n{toml_text}"));
        assert!(table.get("diverter").and_then(|d| d.get("enabled")).is_none(), "{toml_text}");
    }
}

#[cfg(test)]
mod fakenet_rs_tests {
    use super::*;

    #[test]
    fn converts_fakenet_rs_extended_config() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let ini = std::fs::read_to_string(fixtures.join("fakenet-rs-default.ini")).unwrap();
        let toml = convert(&ini, Path::new("/opt/fakenet")).unwrap();
        let config: crate::Config = toml::from_str(&toml).unwrap_or_else(|e| panic!("{e}\n{toml}"));
        config.validate().unwrap();
        assert!(!toml.contains("has no equivalent"), "{toml}");
        let protocols: Vec<String> = config.listeners.iter().map(|l| format!("{:?}", l.protocol)).collect();
        for expected in ["Redis", "Socks", "Syslog", "Finger", "Ssh", "Telnet", "Ntp", "Imap"] {
            assert!(protocols.iter().any(|p| p.contains(expected)), "{expected} missing from {protocols:?}");
        }
    }
}
