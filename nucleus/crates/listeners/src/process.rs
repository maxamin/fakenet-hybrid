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

#[cfg(target_os = "linux")]
fn is_local(ip: IpAddr) -> bool {
    if ip.to_canonical().is_loopback() {
        return true;
    }
    // Our own interface addresses: a socket bound to the address is the cheapest check
    std::net::UdpSocket::bind(SocketAddr::new(ip.to_canonical(), 0)).is_ok()
}

/// The process owning the client end of a connection from `client` to `server`
#[cfg(target_os = "linux")]
pub fn find_process(transport: Transport, client: SocketAddr, server: SocketAddr) -> Option<ProcessInfo> {
    if !is_local(client.ip()) {
        return None;
    }
    let tables: &[&str] = match transport {
        Transport::Tcp => &["/proc/net/tcp", "/proc/net/tcp6"],
        Transport::Udp => &["/proc/net/udp", "/proc/net/udp6"],
    };
    let entries: Vec<SocketEntry> = tables.iter().filter_map(|table| std::fs::read_to_string(table).ok()).flat_map(|text| parse_socket_table(&text)).collect();
    let inode = matching_socket(&entries, transport, client, server)?;
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

#[cfg(target_os = "linux")]
fn find_socket_owner(inode: u64) -> Option<ProcessInfo> {
    let target = format!("socket:[{inode}]");
    // Newest processes first: clients are usually recently started, so this finds them fast
    let mut pids: Vec<u32> = std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .collect();
    pids.sort_unstable_by(|a, b| b.cmp(a));
    for pid in pids {
        let path = std::path::PathBuf::from(format!("/proc/{pid}"));
        let Ok(fds) = std::fs::read_dir(path.join("fd")) else { continue }; // Gone, or no access
        let owns = fds.flatten().any(|fd| {
            std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
        });
        if owns {
            let name = std::fs::read_to_string(path.join("comm")).unwrap_or_default().trim().to_string();
            let exe = std::fs::read_link(path.join("exe")).ok().map(|p| p.display().to_string());
            return Some(ProcessInfo { pid, name, exe });
        }
    }
    None
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
    fn prefers_the_exact_socket_over_a_wildcard_one() {
        let entry = |local: &str, inode| SocketEntry { local: local.parse().unwrap(), remote: "0.0.0.0:0".parse().unwrap(), inode };
        let entries = [entry("0.0.0.0:5353", 1), entry("10.0.0.5:5353", 2)];
        let server = "10.0.0.1:53".parse().unwrap();
        assert_eq!(matching_socket(&entries, Transport::Udp, "10.0.0.5:5353".parse().unwrap(), server), Some(2));
        assert_eq!(matching_socket(&entries, Transport::Udp, "10.0.0.9:5353".parse().unwrap(), server), Some(1));
        assert_eq!(matching_socket(&entries, Transport::Tcp, "10.0.0.9:5353".parse().unwrap(), server), None);
    }
}
