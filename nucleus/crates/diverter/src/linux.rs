//! Linux: iptables NAT REDIRECT in our own chains, plus optional NFQUEUE marking of
//! excluded processes. Only ever touches the `FAKENET` chains and the jumps to them.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{bail, Context as _};
use crate::{packet, DiverterConfig, Mode, Plan};

const CHAIN: &str = "FAKENET";
/// Marks connections from excluded processes; the NAT chain skips them
const MARK: &str = "0x4b1d/0x4b1d";
const MARK_VALUE: u32 = 0x4b1d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn binary(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    fn loopback(self) -> &'static str {
        match self {
            Family::V4 => "127.0.0.0/8",
            Family::V6 => "::1/128",
        }
    }
}

fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}

/// The iptables commands (without the binary) that set up diversion, in order
pub fn rules(config: &DiverterConfig, plan: &Plan, family: Family) -> Vec<Vec<String>> {
    let mut rules = vec![args(&format!("-t nat -N {CHAIN}"))];
    let nat = |rule: String| args(&format!("-t nat -A {CHAIN} {rule}"));
    match config.mode {
        // The host's own addresses: the daemon link, FTP active data to the client...
        Mode::SingleHost => rules.push(nat("-m addrtype --dst-type LOCAL -j RETURN".into())),
        Mode::Gateway => rules.push(nat(format!("-d {} -j RETURN", family.loopback()))),
    }
    let marking = config.mode == Mode::SingleHost && !config.excluded_processes.is_empty();
    if marking {
        rules.push(nat(format!("-m mark --mark {MARK} -j RETURN")));
    }
    for port in &plan.ignore_ports {
        rules.push(nat(format!("-p tcp --dport {port} -j RETURN")));
        rules.push(nat(format!("-p udp --dport {port} -j RETURN")));
    }
    if config.answer_ping {
        // The kernel answers; conntrack makes the reply come from the pinged address
        rules.push(nat(match family {
            Family::V4 => "-p icmp --icmp-type echo-request -j REDIRECT".to_string(),
            Family::V6 => "-p ipv6-icmp --icmpv6-type echo-request -j REDIRECT".to_string(),
        }));
    }
    for port in &plan.tcp_ports {
        rules.push(nat(format!("-p tcp --dport {port} -j REDIRECT --to-ports {port}")));
    }
    if let Some((first, last)) = plan.passive_ports {
        rules.push(nat(format!("-p tcp --dport {first}:{last} -j REDIRECT")));
    }
    for port in &plan.udp_ports {
        rules.push(nat(format!("-p udp --dport {port} -j REDIRECT --to-ports {port}")));
    }
    if let Some(port) = plan.tcp_default {
        rules.push(nat(format!("-p tcp -j REDIRECT --to-ports {port}")));
    }
    if let Some(port) = plan.udp_default {
        rules.push(nat(format!("-p udp -j REDIRECT --to-ports {port}")));
    }
    let parent = if config.mode == Mode::SingleHost { "OUTPUT" } else { "PREROUTING" };
    rules.push(args(&format!("-t nat -I {parent} -j {CHAIN}")));

    if marking {
        rules.push(args(&format!("-t mangle -N {CHAIN}")));
        for protocol in ["tcp", "udp"] {
            rules.push(args(&format!(
                "-t mangle -A {CHAIN} -p {protocol} -m addrtype ! --dst-type LOCAL -m conntrack --ctstate NEW -j NFQUEUE --queue-num {} --queue-bypass",
                config.queue_num
            )));
        }
        rules.push(args(&format!("-t mangle -I OUTPUT -j {CHAIN}")));
    }
    rules
}

/// Commands that undo `rules` (each may fail harmlessly when there's nothing to undo)
pub fn cleanup_commands() -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for (table, parent) in [("nat", "OUTPUT"), ("nat", "PREROUTING"), ("mangle", "OUTPUT")] {
        commands.push(args(&format!("-t {table} -D {parent} -j {CHAIN}")));
    }
    for table in ["nat", "mangle"] {
        commands.push(args(&format!("-t {table} -F {CHAIN}")));
        commands.push(args(&format!("-t {table} -X {CHAIN}")));
    }
    commands
}

fn run(family: Family, args: &[String]) -> anyhow::Result<()> {
    let output = Command::new(family.binary())
        .arg("-w") // Wait for the xtables lock rather than fail
        .args(args)
        .output()
        .with_context(|| format!("running {}", family.binary()))?;
    if !output.status.success() {
        bail!("{} {}: {}", family.binary(), args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

fn cleanup_family(family: Family) {
    for command in cleanup_commands() {
        // A jump may have been added more than once by a crashed run: delete until gone
        let repeat = if command.contains(&"-D".to_string()) { 8 } else { 1 };
        for _ in 0..repeat {
            if run(family, &command).is_err() {
                break;
            }
        }
    }
}

pub fn cleanup() -> anyhow::Result<()> {
    cleanup_family(Family::V4);
    cleanup_family(Family::V6);
    Ok(())
}

pub struct Active {
    families: Vec<Family>,
    queue: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
}

impl Active {
    pub fn start(config: &DiverterConfig, plan: &Plan) -> anyhow::Result<Active> {
        cleanup()?; // Leftovers from a run that was killed
        let mut families = Vec::new();
        for family in [Family::V4, Family::V6] {
            if family == Family::V6 && !config.ipv6 {
                continue;
            }
            let applied = rules(config, plan, family).iter().try_for_each(|rule| run(family, rule));
            match applied {
                Ok(()) => families.push(family),
                Err(e) if family == Family::V6 => {
                    tracing::warn!("IPv6 traffic is not diverted: {e:#}");
                    cleanup_family(family);
                }
                Err(e) => {
                    cleanup_family(family);
                    return Err(e.context("setting up iptables diversion (needs root, and the nat table)"));
                }
            }
        }
        let queue = (config.mode == Mode::SingleHost && !config.excluded_processes.is_empty())
            .then(|| start_queue(config.queue_num, config.excluded_processes.clone()))
            .transpose()?;
        tracing::info!("Diverting traffic ({:?}, {:?})", config.mode, families);
        Ok(Active { families, queue })
    }

    pub fn stop(self) -> anyhow::Result<()> {
        for family in &self.families {
            cleanup_family(*family);
        }
        if let Some((stop, thread)) = self.queue {
            stop.store(true, Ordering::Relaxed);
            let _ = thread.join();
        }
        tracing::info!("Diversion removed");
        Ok(())
    }
}

/// Marks the first packet of each new connection from an excluded process
fn start_queue(queue_num: u16, excluded: Vec<String>) -> anyhow::Result<(Arc<AtomicBool>, JoinHandle<()>)> {
    let mut queue = nfq::Queue::open().context("opening NFQUEUE")?;
    queue.bind(queue_num).with_context(|| format!("binding NFQUEUE {queue_num}"))?;
    queue.set_nonblocking(true);
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let thread = std::thread::Builder::new().name("fakenet-nfqueue".into()).spawn(move || {
        while !stopping.load(Ordering::Relaxed) {
            let mut message = match queue.recv() {
                Ok(message) => message,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => {
                    tracing::warn!("NFQUEUE: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            if let Some(flow) = packet::parse(message.get_payload()) {
                let owner = fakenet_listeners::process::find_process(flow.transport, flow.src, flow.dst);
                if owner.as_ref().is_some_and(|p| is_excluded(&p.name, &excluded)) {
                    message.set_nfmark(message.get_nfmark() | MARK_VALUE);
                }
            }
            message.set_verdict(nfq::Verdict::Accept);
            if let Err(e) = queue.verdict(message) {
                tracing::warn!("NFQUEUE verdict: {e}");
            }
        }
        let _ = queue.unbind(queue_num);
    })?;
    Ok((stop, thread))
}

pub fn is_excluded(name: &str, excluded: &[String]) -> bool {
    excluded.iter().any(|e| e.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan { tcp_ports: vec![80, 443], udp_ports: vec![53], tcp_default: Some(1337), udp_default: Some(1338), passive_ports: Some((60000, 60010)), ignore_ports: vec![22] }
    }

    fn joined(rules: &[Vec<String>]) -> Vec<String> {
        rules.iter().map(|r| r.join(" ")).collect()
    }

    #[test]
    fn single_host_rules_keep_listener_ports_and_skip_local_traffic() {
        let config = DiverterConfig { enabled: true, ..DiverterConfig::default() };
        let single = joined(&rules(&config, &plan(), Family::V4));
        assert_eq!(single, [
            "-t nat -N FAKENET",
            "-t nat -A FAKENET -m addrtype --dst-type LOCAL -j RETURN",
            "-t nat -A FAKENET -p tcp --dport 22 -j RETURN",
            "-t nat -A FAKENET -p udp --dport 22 -j RETURN",
            "-t nat -A FAKENET -p icmp --icmp-type echo-request -j REDIRECT",
            "-t nat -A FAKENET -p tcp --dport 80 -j REDIRECT --to-ports 80",
            "-t nat -A FAKENET -p tcp --dport 443 -j REDIRECT --to-ports 443",
            "-t nat -A FAKENET -p tcp --dport 60000:60010 -j REDIRECT",
            "-t nat -A FAKENET -p udp --dport 53 -j REDIRECT --to-ports 53",
            "-t nat -A FAKENET -p tcp -j REDIRECT --to-ports 1337",
            "-t nat -A FAKENET -p udp -j REDIRECT --to-ports 1338",
            "-t nat -I OUTPUT -j FAKENET",
        ]);
    }

    #[test]
    fn exclusions_add_marking_and_gateways_use_prerouting() {
        let config = DiverterConfig { enabled: true, excluded_processes: vec!["python3".into()], ..DiverterConfig::default() };
        let marked = joined(&rules(&config, &plan(), Family::V6));
        assert!(marked.contains(&"-t nat -A FAKENET -m mark --mark 0x4b1d/0x4b1d -j RETURN".to_string()));
        assert!(marked.iter().any(|r| r.starts_with("-t mangle -A FAKENET -p tcp") && r.ends_with("NFQUEUE --queue-num 4242 --queue-bypass")));
        assert_eq!(marked.last().unwrap(), "-t mangle -I OUTPUT -j FAKENET");

        let gateway = DiverterConfig { enabled: true, mode: Mode::Gateway, excluded_processes: vec!["x".into()], ..DiverterConfig::default() };
        let gateway_rules = joined(&rules(&gateway, &plan(), Family::V6));
        assert!(gateway_rules.contains(&"-t nat -A FAKENET -d ::1/128 -j RETURN".to_string()));
        assert!(gateway_rules.contains(&"-t nat -I PREROUTING -j FAKENET".to_string()));
        assert!(gateway_rules.contains(&"-t nat -A FAKENET -p ipv6-icmp --icmpv6-type echo-request -j REDIRECT".to_string()));
        assert!(!gateway_rules.iter().any(|r| r.contains("mangle"))); // No local processes to exclude
    }

    #[test]
    fn cleanup_undoes_everything_it_could_have_added() {
        let cleanup = joined(&cleanup_commands());
        for jump in ["-t nat -D OUTPUT -j FAKENET", "-t nat -D PREROUTING -j FAKENET", "-t mangle -D OUTPUT -j FAKENET"] {
            assert!(cleanup.contains(&jump.to_string()));
        }
        assert_eq!(cleanup.iter().filter(|c| c.contains("-X FAKENET")).count(), 2);
        assert!(is_excluded("Python3", &["python3".into()]));
    }
}
