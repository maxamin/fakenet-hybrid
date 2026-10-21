//! Packet-level diversion to local listeners for WinDivert (cf. its streamdump example and
//! FakeNet-NG's Windows diverter). Pure state, no I/O: the Windows glue feeds it packets;
//! tests drive it directly.
//!
//! - Single host (the malware runs here): a client packet S:sp -> D:dp is re-injected
//!   inbound as D:sp -> S:L (L: the listener for dp); the listener's reply S:L -> D:sp goes
//!   back as D:dp -> S:sp, which is what the client expects.
//! - Gateway (this host routes the analysis network): a forwarded packet C:cp -> D:dp is
//!   delivered as C:cp -> G:L (G: this host); the reply G:L -> C:cp leaves as D:dp -> C:cp.
//!
//! Listeners recover the real endpoints with `original()`. UDP replies from a port that
//! isn't a listener's (TFTP's per-transfer port) open an alias flow, so the client's answers
//! to D:<that port> reach it.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use fakenet_listeners::Original;
use fakenet_schema::{ProcessInfo, Transport};

use crate::packet::Flow;
use crate::Plan;

const IDLE: Duration = Duration::from_secs(600);
const MAX_ENTRIES: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    SingleHost,
    /// This host's addresses on the analysis network (where the listeners are reached)
    Gateway { v4: Option<IpAddr>, v6: Option<IpAddr> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Let it through: exempt (`ignore_ports`, an excluded process) or not ours to judge
    Pass,
    /// Neither diverted nor exempt (no listener for the port, a connection that predates the
    /// diversion): dropped when `block_undiverted` is on, else passed
    Undiverted,
    /// Rewrite to these addresses and inject it toward the local stack (single host:
    /// inbound) or out to the client (gateway replies)
    Reflect { src: SocketAddr, dst: SocketAddr },
}

/// Whether the Windows glue drops a packet rather than letting it out. `verdict` is None for
/// packets that aren't TCP/UDP (other IP protocols, ICMP that wasn't answered). With
/// `block` (`block_undiverted`), anything neither diverted nor exempt is dropped, except
/// link-local control traffic (it can't leave the segment, and the network needs it).
pub fn drops(verdict: Option<&Verdict>, block: bool, link_local_control: bool) -> bool {
    block && !link_local_control && matches!(verdict, None | Some(Verdict::Undiverted))
}

/// (transport, client, original destination)
type ClientKey = (Transport, SocketAddr, SocketAddr);
/// (transport, the peer as the listener sees it, the listener's port)
type ListenerKey = (Transport, SocketAddr, u16);

struct Entry {
    listener_port: u16,
    process: Option<ProcessInfo>,
    last_seen: Instant,
}

pub struct Reflector {
    plan: Plan,
    mode: Mode,
    listener_ports: HashSet<(Transport, u16)>,
    entries: HashMap<ClientKey, Entry>,
    reverse: HashMap<ListenerKey, ClientKey>,
}

impl Reflector {
    pub fn new(plan: Plan, mode: Mode) -> Reflector {
        let listener_ports = plan
            .tcp_ports
            .iter()
            .map(|p| (Transport::Tcp, *p))
            .chain(plan.udp_ports.iter().map(|p| (Transport::Udp, *p)))
            .chain(plan.tcp_default.map(|p| (Transport::Tcp, p)))
            .chain(plan.udp_default.map(|p| (Transport::Udp, p)))
            .chain(plan.passive_ports.map(|(a, b)| (a..=b).map(|p| (Transport::Tcp, p))).into_iter().flatten())
            .collect();
        Reflector { plan, mode, listener_ports, entries: HashMap::new(), reverse: HashMap::new() }
    }

    fn listener_for(&self, transport: Transport, port: u16) -> Option<u16> {
        if self.plan.ignore_ports.contains(&port) {
            return None;
        }
        let (ports, default) = match transport {
            Transport::Tcp => (&self.plan.tcp_ports, self.plan.tcp_default),
            Transport::Udp => (&self.plan.udp_ports, self.plan.udp_default),
        };
        let passive = transport == Transport::Tcp && self.plan.passive_ports.is_some_and(|(a, b)| (a..=b).contains(&port));
        if ports.contains(&port) || passive { Some(port) } else { default }
    }

    /// The peer address a listener sees for a client (single host: the destination's IP
    /// with the client's port; gateway: the client itself)
    fn seen_peer(&self, client: SocketAddr, dst: SocketAddr) -> SocketAddr {
        match self.mode {
            Mode::SingleHost => SocketAddr::new(dst.ip(), client.port()),
            Mode::Gateway { .. } => client,
        }
    }

    /// Where a client's packets are delivered: our address with the listener's port
    fn listener_address(&self, client: SocketAddr, port: u16) -> Option<SocketAddr> {
        let ip = match self.mode {
            Mode::SingleHost => client.ip(),
            Mode::Gateway { v4, v6 } => if client.is_ipv4() { v4? } else { v6? },
        };
        Some(SocketAddr::new(ip, port))
    }

    /// Decides what to do with a packet: outbound from this host (single host), or
    /// forwarded through it (gateway). `process` finds a new client flow's owner;
    /// `excluded` says whether it's exempt.
    pub fn handle(
        &mut self,
        flow: &Flow,
        now: Instant,
        process: impl FnOnce() -> Option<ProcessInfo>,
        excluded: impl FnOnce(&Option<ProcessInfo>) -> bool,
    ) -> Verdict {
        // A listener's reply to a diverted flow?
        if let Some(key) = self.reverse.get(&(flow.transport, flow.dst, flow.src.port())).copied() {
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.last_seen = now;
                return Verdict::Reflect { src: key.2, dst: key.1 };
            }
        }
        // UDP from a non-listener port to a diverted client: open an alias flow (TFTP)
        if flow.transport == Transport::Udp && !self.listener_ports.contains(&(Transport::Udp, flow.src.port())) {
            let parent = self.reverse.iter().find(|((t, peer, _), _)| *t == Transport::Udp && *peer == flow.dst).map(|(_, key)| *key);
            if let Some((transport, client, dst)) = parent {
                let alias_dst = SocketAddr::new(dst.ip(), flow.src.port());
                let process = self.entries.get(&(transport, client, dst)).and_then(|e| e.process.clone());
                self.insert((transport, client, alias_dst), flow.src.port(), process, now);
                return Verdict::Reflect { src: alias_dst, dst: client };
            }
        }
        // A known client flow?
        let key = (flow.transport, flow.src, flow.dst);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = now;
            let port = entry.listener_port;
            return match self.listener_address(flow.src, port) {
                Some(dst) => Verdict::Reflect { src: self.seen_peer(flow.src, flow.dst), dst },
                None => Verdict::Pass,
            };
        }
        // Only a connection's first packet starts a TCP flow (we may have started mid-way)
        if flow.transport == Transport::Tcp && !flow.syn {
            return Verdict::Undiverted;
        }
        if self.plan.ignore_ports.contains(&flow.dst.port()) {
            return Verdict::Pass;
        }
        let Some(port) = self.listener_for(flow.transport, flow.dst.port()) else { return Verdict::Undiverted };
        let Some(listener) = self.listener_address(flow.src, port) else { return Verdict::Pass };
        let process = process();
        if excluded(&process) {
            return Verdict::Pass;
        }
        self.insert(key, port, process, now);
        Verdict::Reflect { src: self.seen_peer(flow.src, flow.dst), dst: listener }
    }

    fn insert(&mut self, key: ClientKey, listener_port: u16, process: Option<ProcessInfo>, now: Instant) {
        self.expire(now);
        let (transport, client, dst) = key;
        self.reverse.insert((transport, self.seen_peer(client, dst), listener_port), key);
        self.entries.insert(key, Entry { listener_port, process, last_seen: now });
    }

    /// The real endpoints of a diverted flow, from the listener's view of it
    pub fn original(&self, transport: Transport, peer: SocketAddr, local: SocketAddr) -> Option<Original> {
        let key = self.reverse.get(&(transport, peer, local.port()))?;
        let entry = self.entries.get(key)?;
        Some(Original { client: key.1, dst: key.2, process: entry.process.clone() })
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, e| now.duration_since(e.last_seen) < IDLE);
        if self.entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = self.entries.iter().min_by_key(|(_, e)| e.last_seen).map(|(k, _)| *k) {
                self.entries.remove(&oldest);
            }
        }
        let entries = &self.entries;
        self.reverse.retain(|_, key| entries.contains_key(key));
    }

    pub fn is_gateway(&self) -> bool {
        matches!(self.mode, Mode::Gateway { .. })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{parse, rewrite, tests::{checksums_valid, packet}};

    fn plan() -> Plan {
        Plan { tcp_ports: vec![80, 443], udp_ports: vec![53, 69], tcp_default: Some(1337), udp_default: Some(1338), passive_ports: Some((60000, 60001)), ignore_ports: vec![3389] }
    }

    fn flow(transport: Transport, src: &str, dst: &str) -> Flow {
        parse(&packet(transport, src.parse().unwrap(), dst.parse().unwrap(), b"x")).unwrap()
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn malware() -> Option<ProcessInfo> {
        Some(ProcessInfo { pid: 666, name: "evil.exe".into(), exe: None })
    }

    #[test]
    fn reflects_a_tcp_connection_both_ways() {
        let mut reflector = Reflector::new(plan(), Mode::SingleHost);
        let now = Instant::now();
        let syn = flow(Transport::Tcp, "10.0.2.15:50000", "93.184.216.34:8443");
        assert_eq!(reflector.handle(&syn, now, malware, |_| false), Verdict::Reflect { src: addr("93.184.216.34:50000"), dst: addr("10.0.2.15:1337") });
        let original = reflector.original(Transport::Tcp, addr("93.184.216.34:50000"), addr("10.0.2.15:1337")).unwrap();
        assert_eq!((original.client, original.dst), (addr("10.0.2.15:50000"), addr("93.184.216.34:8443")));
        assert_eq!(original.process.unwrap().name, "evil.exe");
        let reply = flow(Transport::Tcp, "10.0.2.15:1337", "93.184.216.34:50000");
        assert_eq!(reflector.handle(&reply, now, || panic!("no lookup for replies"), |_| false), Verdict::Reflect { src: addr("93.184.216.34:8443"), dst: addr("10.0.2.15:50000") });
        let mut bytes = packet(Transport::Tcp, reply.src, reply.dst, b"hi");
        assert!(rewrite(&mut bytes, addr("93.184.216.34:8443"), addr("10.0.2.15:50000")));
        assert!(checksums_valid(&bytes));
        // Two connections from one client port to different servers stay apart
        let other = flow(Transport::Tcp, "10.0.2.15:50000", "198.51.100.7:8443");
        assert!(matches!(reflector.handle(&other, now, || None, |_| false), Verdict::Reflect { .. }));
        assert_eq!(reflector.len(), 2);
    }

    #[test]
    fn follows_tftp_transfers_to_their_own_port() {
        let mut reflector = Reflector::new(plan(), Mode::SingleHost);
        let now = Instant::now();
        let rrq = flow(Transport::Udp, "10.0.2.15:40000", "203.0.113.5:69");
        assert_eq!(reflector.handle(&rrq, now, || None, |_| false), Verdict::Reflect { src: addr("203.0.113.5:40000"), dst: addr("10.0.2.15:69") });
        // The server answers from a fresh port 55555 (its transfer ID)
        let data = flow(Transport::Udp, "10.0.2.15:55555", "203.0.113.5:40000");
        assert_eq!(reflector.handle(&data, now, || None, |_| false), Verdict::Reflect { src: addr("203.0.113.5:55555"), dst: addr("10.0.2.15:40000") });
        // ...and the client's ACK to 203.0.113.5:55555 reaches it
        let ack = flow(Transport::Udp, "10.0.2.15:40000", "203.0.113.5:55555");
        assert_eq!(reflector.handle(&ack, now, || None, |_| false), Verdict::Reflect { src: addr("203.0.113.5:40000"), dst: addr("10.0.2.15:55555") });
    }

    #[test]
    fn gateway_mode_keeps_the_real_client() {
        let mode = Mode::Gateway { v4: Some("10.6.6.1".parse().unwrap()), v6: None };
        let mut reflector = Reflector::new(plan(), mode);
        let now = Instant::now();
        let syn = flow(Transport::Tcp, "10.6.6.20:50000", "93.184.216.34:80");
        assert_eq!(reflector.handle(&syn, now, || None, |_| false), Verdict::Reflect { src: addr("10.6.6.20:50000"), dst: addr("10.6.6.1:80") });
        let original = reflector.original(Transport::Tcp, addr("10.6.6.20:50000"), addr("10.6.6.1:80")).unwrap();
        assert_eq!(original.dst, addr("93.184.216.34:80"));
        let reply = flow(Transport::Tcp, "10.6.6.1:80", "10.6.6.20:50000");
        assert_eq!(reflector.handle(&reply, now, || None, |_| false), Verdict::Reflect { src: addr("93.184.216.34:80"), dst: addr("10.6.6.20:50000") });
        // No IPv6 address configured: IPv6 clients pass untouched
        let v6 = flow(Transport::Tcp, "[2001:db8::20]:50000", "[2001:db8::1]:80");
        assert_eq!(reflector.handle(&v6, now, || None, |_| false), Verdict::Pass);
    }

    #[test]
    fn keeps_listener_ports_and_respects_exclusions() {
        let mut reflector = Reflector::new(plan(), Mode::SingleHost);
        let now = Instant::now();
        let to_dns = flow(Transport::Udp, "10.0.2.15:5353", "8.8.8.8:53");
        assert!(matches!(reflector.handle(&to_dns, now, || None, |_| false), Verdict::Reflect { dst, .. } if dst.port() == 53));
        let passive = flow(Transport::Tcp, "10.0.2.15:50001", "93.184.216.34:60001");
        assert!(matches!(reflector.handle(&passive, now, || None, |_| false), Verdict::Reflect { dst, .. } if dst.port() == 60001));
        assert_eq!(reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50002", "10.0.0.1:3389"), now, || None, |_| false), Verdict::Pass);
        assert_eq!(reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50003", "1.1.1.1:80"), now, malware, |p| p.is_some()), Verdict::Pass);
        let mut established = flow(Transport::Tcp, "10.0.2.15:50004", "1.1.1.1:80");
        established.syn = false;
        assert_eq!(reflector.handle(&established, now, || None, |_| false), Verdict::Undiverted);
        assert_eq!(reflector.len(), 2);
        let later = now + IDLE + Duration::from_secs(1);
        reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50005", "1.1.1.1:80"), later, || None, |_| false);
        assert_eq!(reflector.len(), 1);
        assert!(reflector.original(Transport::Udp, addr("8.8.8.8:5353"), addr("10.0.2.15:53")).is_none()); // Expired
    }

    #[test]
    fn tells_exempt_traffic_from_undiverted_traffic() {
        // No catch-all listeners: unlisted ports aren't diverted
        let narrow = Plan { tcp_default: None, udp_default: None, ..plan() };
        let mut reflector = Reflector::new(narrow, Mode::SingleHost);
        let now = Instant::now();
        assert_eq!(reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50010", "1.1.1.1:8443"), now, || None, |_| false), Verdict::Undiverted);
        assert_eq!(reflector.handle(&flow(Transport::Udp, "10.0.2.15:50011", "1.1.1.1:5000"), now, || None, |_| false), Verdict::Undiverted);
        assert_eq!(reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50012", "10.0.0.1:3389"), now, || None, |_| false), Verdict::Pass); // ignore_ports
        assert!(matches!(reflector.handle(&flow(Transport::Tcp, "10.0.2.15:50013", "1.1.1.1:80"), now, || None, |_| false), Verdict::Reflect { .. }));
    }


    #[test]
    fn drops_only_undiverted_traffic_when_blocking() {
        let reflect = Verdict::Reflect { src: "1.1.1.1:80".parse().unwrap(), dst: "10.0.2.15:80".parse().unwrap() };
        assert!(drops(Some(&Verdict::Undiverted), true, false));
        assert!(drops(None, true, false)); // GRE, non-echo ICMP...
        assert!(!drops(None, true, true)); // Neighbour discovery
        assert!(!drops(Some(&Verdict::Pass), true, false)); // ignore_ports, excluded processes
        assert!(!drops(Some(&reflect), true, false));
        assert!(!drops(Some(&Verdict::Undiverted), false, false)); // block_undiverted = false
    }

}
