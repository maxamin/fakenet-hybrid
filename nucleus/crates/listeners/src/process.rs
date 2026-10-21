//! Which local process owns a connection (Linux, SingleHost mode): finds the client's socket
//! in /proc/net/{tcp,tcp6,udp,udp6}, then the process holding it. Verified against real
//! sockets by the tests below and the protocol tests' process filters.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fakenet_schema::{ProcessInfo, Transport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub inode: u64,
}

/// "0100007F:1F90" (IPv4) or 32 hex digits + port (IPv6). Addresses are the raw network-order
/// bytes, printed as host-order 32-bit words.
fn parse_address(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(address, 16).ok()?.to_ne_bytes())),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = u32::from_str_radix(&address[i * 8..i * 8 + 8], 16).ok()?;
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses a /proc/net/{tcp,udp}{,6} table
pub fn parse_socket_table(text: &str) -> Vec<SocketEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(SocketEntry {
                local: parse_address(fields.get(1)?)?,
                remote: parse_address(fields.get(2)?)?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// IPv4-mapped IPv6 addresses (dual-stack sockets) compare equal to their IPv4 form
#[cfg(target_os = "linux")]
fn same_address(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

/// How long an "is this address ours" answer is reused
#[cfg(target_os = "linux")]
const LOCAL_TTL: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(target_os = "linux")]
fn is_local(ip: IpAddr) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static CACHE: OnceLock<Mutex<HashMap<IpAddr, (bool, Instant)>>> = OnceLock::new();
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return true;
    }
    let cache = CACHE.get_or_init(Default::default);
    if let Some((local, at)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&ip) {
        if at.elapsed() < LOCAL_TTL {
            return *local;
        }
    }
    // Our own interface addresses: a socket bound to the address is the cheapest check
    let local = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok();
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= 1024 {
        cache.clear(); // Sources are sample-controlled (spoofing, scans): stay bounded
    }
    cache.insert(ip, (local, Instant::now()));
    local
}

/// The process owning the client end of a connection from `client` to `server`
#[cfg(target_os = "linux")]
pub fn find_process(transport: Transport, client: SocketAddr, server: SocketAddr) -> Option<ProcessInfo> {
    if !is_local(client.ip()) {
        return None;
    }
    // TCP: one exact netlink query; the /proc tables (slow to generate: the kernel walks
    // every socket) only when it fails, and for UDP (small tables, wildcard sockets)
    let diagnosed = match transport {
        Transport::Tcp => sock_diag::tcp_inode(client, server),
        Transport::Udp => None,
    };
    let inode = match diagnosed {
        Some(inode) => inode,
        None => {
            let tables: &[&str] = match transport {
                Transport::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
                Transport::Udp => &["/proc/net/udp", "/proc/net/udp6"],
            };
            let entries: Vec<SocketEntry> = tables.iter().filter_map(|table| std::fs::read_to_string(table).ok()).flat_map(|text| parse_socket_table(&text)).collect();
            matching_socket(&entries, transport, client, server)?
        }
    };
    if inode == 0 {
        return None;
    }
    find_socket_owner(inode)
}

/// The socket in `entries` at the client end: its exact address; for UDP, else one bound to
/// the wildcard address on the client's port (a client that `sendto()`s without
/// `connect()`ing shows as 0.0.0.0:port or [::]:port)
#[cfg(target_os = "linux")]
fn matching_socket(entries: &[SocketEntry], transport: Transport, client: SocketAddr, server: SocketAddr) -> Option<u64> {
    let exact = entries.iter().find(|e| {
        same_address(e.local, client)
            // For TCP, its peer must be us (another socket may share the local port on a
            // different address); unconnected UDP sockets have no peer
            && (transport == Transport::Udp || same_address(e.remote, server))
    });
    let wildcard = || match transport {
        Transport::Udp => entries.iter().find(|e| e.local.port() == client.port() && e.local.ip().is_unspecified()),
        Transport::Tcp => None,
    };
    exact.or_else(wildcard).map(|e| e.inode)
}

#[cfg(not(target_os = "linux"))]
pub fn find_process(_transport: Transport, _client: SocketAddr, _server: SocketAddr) -> Option<ProcessInfo> {
    None
}

/// For the processes scanned last (newest first): which descriptor held which socket.
/// A sample opens many sockets; a new one is usually on a descriptor number not seen
/// before, so a rescan reads only those links first, instead of every descriptor again.
#[cfg(target_os = "linux")]
static RECENT_OWNERS: std::sync::Mutex<Vec<(u32, std::collections::HashMap<u32, u64>)>> = std::sync::Mutex::new(Vec::new());
#[cfg(target_os = "linux")]
const RECENT_OWNERS_KEPT: usize = 32;

#[cfg(target_os = "linux")]
fn socket_inode(pid: u32, fd: u32) -> Option<u64> {
    let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Whether `pid` holds socket `inode`, updating `known` (fd -> socket inode) as it reads
#[cfg(target_os = "linux")]
fn scan_process(pid: u32, inode: u64, known: &mut std::collections::HashMap<u32, u64>) -> bool {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return false }; // Gone, or no access
    let numbers: Vec<u32> = fds.flatten().filter_map(|fd| fd.file_name().to_str().and_then(|n| n.parse().ok())).collect();
    known.retain(|fd, _| numbers.contains(fd));
    // New descriptors first, then the known ones (a closed socket's number gets reused)
    let (new, old): (Vec<u32>, Vec<u32>) = numbers.into_iter().partition(|fd| !known.contains_key(fd));
    for fd in new.into_iter().chain(old) {
        match socket_inode(pid, fd) {
            Some(socket) => {
                known.insert(fd, socket);
                if socket == inode {
                    return true;
                }
            }
            None => {
                known.remove(&fd);
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn find_socket_owner(inode: u64) -> Option<ProcessInfo> {
    // Taken out while scanning (a concurrent lookup then starts from /proc), put back after
    let mut recent = std::mem::take(&mut *RECENT_OWNERS.lock().unwrap_or_else(|e| e.into_inner()));
    let owner = match recent.iter_mut().position(|(pid, known)| scan_process(*pid, inode, known)) {
        Some(index) => {
            let entry = recent.remove(index);
            let pid = entry.0;
            recent.insert(0, entry);
            Some(pid)
        }
        None => {
            // Newest processes first: clients are usually recently started, so this finds them fast
            let mut pids: Vec<u32> = std::fs::read_dir("/proc")
                .ok()?
                .flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                .filter(|pid| !recent.iter().any(|(known, _)| known == pid))
                .collect();
            pids.sort_unstable_by(|a, b| b.cmp(a));
            let mut known = std::collections::HashMap::new();
            let found = pids.into_iter().find(|pid| {
                known.clear();
                scan_process(*pid, inode, &mut known)
            });
            if let Some(pid) = found {
                recent.insert(0, (pid, known));
            }
            found
        }
    };
    recent.truncate(RECENT_OWNERS_KEPT);
    {
        let mut shared = RECENT_OWNERS.lock().unwrap_or_else(|e| e.into_inner());
        if shared.is_empty() {
            *shared = recent;
        }
    }
    let owner = owner?;
    let path = std::path::PathBuf::from(format!("/proc/{owner}"));
    let name = std::fs::read_to_string(path.join("comm")).unwrap_or_default().trim().to_string();
    let exe = std::fs::read_link(path.join("exe")).ok().map(|p| p.display().to_string());
    Some(ProcessInfo { pid: owner, name, exe })
}

/// NETLINK_SOCK_DIAG (inet_diag): a TCP socket's inode from its exact endpoints
#[cfg(target_os = "linux")]
mod sock_diag {
    use std::net::{IpAddr, SocketAddr};

    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const INET_DIAG_NOCOOKIE: u32 = !0;
    /// nlmsghdr (16) + inet_diag_req_v2 (8 + inet_diag_sockid 48)
    const REQUEST: usize = 16 + 56;

    fn address_words(ip: IpAddr) -> [u8; 16] {
        let mut out = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
        }
        out
    }

    /// The request for the socket whose local end is `local` and remote end `remote`
    pub(super) fn request(local: SocketAddr, remote: SocketAddr, sequence: u32) -> [u8; REQUEST] {
        let mut message = [0u8; REQUEST];
        message[0..4].copy_from_slice(&(REQUEST as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        message[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());
        let family = if local.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        message[16] = family as u8;
        message[17] = libc::IPPROTO_TCP as u8;
        message[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // Every state
        let id = 24;
        message[id..id + 2].copy_from_slice(&local.port().to_be_bytes());
        message[id + 2..id + 4].copy_from_slice(&remote.port().to_be_bytes());
        message[id + 4..id + 20].copy_from_slice(&address_words(local.ip()));
        message[id + 20..id + 36].copy_from_slice(&address_words(remote.ip()));
        message[id + 40..id + 44].copy_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
        message[id + 44..id + 48].copy_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
        message
    }

    /// The inode in a reply: nlmsghdr, then inet_diag_msg (inode at offset 68)
    pub(super) fn parse_reply(reply: &[u8]) -> Option<u64> {
        let kind = u16::from_ne_bytes(reply.get(4..6)?.try_into().ok()?);
        if kind != SOCK_DIAG_BY_FAMILY {
            return None; // NLMSG_ERROR (no such socket) or anything unexpected
        }
        let inode = u32::from_ne_bytes(reply.get(16 + 68..16 + 72)?.try_into().ok()?);
        (inode != 0).then_some(u64::from(inode))
    }

    pub fn tcp_inode(client: SocketAddr, server: SocketAddr) -> Option<u64> {
        // Both ends in one family, as the kernel keyed them
        let (client, server) = match (client.ip().to_canonical(), server.ip().to_canonical()) {
            (IpAddr::V4(c), IpAddr::V4(s)) => (SocketAddr::new(c.into(), client.port()), SocketAddr::new(s.into(), server.port())),
            (IpAddr::V6(_), IpAddr::V6(_)) => (client, server),
            _ => return None,
        };
        // SAFETY: plain socket(2); checked before use and owned (closed) by OwnedFd
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG) };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a fresh descriptor nothing else owns
        let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let timeout = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        // SAFETY: valid timeval of the size passed, on the open descriptor
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
        let message = request(client, server, 1);
        // SAFETY: a zeroed sockaddr_nl with only the family set addresses the kernel
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `message` and `kernel` are valid for the lengths passed
        let sent = unsafe { libc::sendto(fd, message.as_ptr().cast(), message.len(), 0, (&kernel as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
        if sent < 0 {
            return None;
        }
        let mut reply = [0u8; 512];
        // SAFETY: `reply` is writable for its length
        let received = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
        drop(owned);
        if received <= 0 {
            return None;
        }
        parse_reply(&reply[..received as usize])
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_this_process_behind_a_local_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server_side = listener.accept().unwrap();
        let found = find_process(Transport::Tcp, client.local_addr().unwrap(), listener.local_addr().unwrap()).unwrap();
        assert_eq!(found.pid, std::process::id());
        assert_eq!(find_process(Transport::Tcp, "192.0.2.1:1".parse().unwrap(), listener.local_addr().unwrap()), None);
    }

    #[test]
    fn finds_unconnected_udp_clients_on_wildcard_sockets() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        client.send_to(b"q", server.local_addr().unwrap()).unwrap();
        let mut buffer = [0u8; 4];
        let (_, from) = server.recv_from(&mut buffer).unwrap(); // 127.0.0.1:port
        let found = find_process(Transport::Udp, from, server.local_addr().unwrap()).unwrap();
        assert_eq!(found.pid, std::process::id());
    }

    #[test]
    fn sock_diag_finds_the_client_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server_side = listener.accept().unwrap();
        let (local, remote) = (client.local_addr().unwrap(), listener.local_addr().unwrap());
        let inode = sock_diag::tcp_inode(local, remote).expect("inet_diag answers for our own socket");
        let entries: Vec<SocketEntry> = parse_socket_table(&std::fs::read_to_string("/proc/net/tcp").unwrap());
        assert_eq!(Some(inode), matching_socket(&entries, Transport::Tcp, local, remote));
        assert_eq!(sock_diag::tcp_inode("127.0.0.1:1".parse().unwrap(), remote), None); // No such socket
    }

    #[test]
    fn prefers_the_exact_socket_over_a_wildcard_one() {
        let entry = |local: &str, inode| SocketEntry { local: local.parse().unwrap(), remote: "0.0.0.0:0".parse().unwrap(), inode };
        let entries = [entry("0.0.0.0:5353", 1), entry("10.0.0.5:5353", 2)];
        let server = "10.0.0.1:53".parse().unwrap();
        assert_eq!(matching_socket(&entries, Transport::Udp, "10.0.0.5:5353".parse().unwrap(), server), Some(2));
        assert_eq!(matching_socket(&entries, Transport::Udp, "10.0.0.9:5353".parse().unwrap(), server), Some(1));
        assert_eq!(matching_socket(&entries, Transport::Tcp, "10.0.0.9:5353".parse().unwrap(), server), None);
    }
}
