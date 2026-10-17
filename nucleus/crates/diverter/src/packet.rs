//! Minimal IPv4/IPv6 + TCP/UDP parsing & address rewriting (with checksum recomputation),
//! for diverters that see raw packets (NFQUEUE, WinDivert)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fakenet_schema::Transport;

/// The addresses of one TCP/UDP packet, and where its parts are
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub transport: Transport,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// TCP SYN without ACK: the first packet of a connection
    pub syn: bool,
    /// TCP FIN or RST
    pub fin: bool,
    l4_offset: usize,
}

const TCP: u8 = 6;
const UDP: u8 = 17;

pub fn parse(packet: &[u8]) -> Option<Flow> {
    let (protocol, src_ip, dst_ip, l4_offset): (u8, IpAddr, IpAddr, usize) = match packet.first()? >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let fragment = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]) & 0x1fff;
            if header_len < 20 || packet.len() < header_len || fragment != 0 {
                return None; // Non-first fragments carry no ports
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            (packet[9], src.into(), dst.into(), header_len)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let src: [u8; 16] = packet[8..24].try_into().ok()?;
            let dst: [u8; 16] = packet[24..40].try_into().ok()?;
            // Extension headers aren't followed: diverted traffic is plain TCP/UDP
            (packet[6], Ipv6Addr::from(src).into(), Ipv6Addr::from(dst).into(), 40)
        }
        _ => return None,
    };
    let transport = match protocol {
        TCP => Transport::Tcp,
        UDP => Transport::Udp,
        _ => return None,
    };
    let l4 = packet.get(l4_offset..)?;
    let minimum = if transport == Transport::Tcp { 20 } else { 8 };
    if l4.len() < minimum {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let flags = if transport == Transport::Tcp { l4[13] } else { 0 };
    Some(Flow {
        transport,
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        syn: flags & 0x12 == 0x02,
        fin: flags & 0x05 != 0,
        l4_offset,
    })
}

/// Rewrites a packet's addresses (same IP family as before) and recomputes its checksums.
/// Returns false if the packet can't be rewritten (unparseable, or a family change).
pub fn rewrite(packet: &mut [u8], src: SocketAddr, dst: SocketAddr) -> bool {
    let Some(flow) = parse(packet) else { return false };
    if src.is_ipv4() != flow.src.is_ipv4() || dst.is_ipv4() != flow.src.is_ipv4() {
        return false;
    }
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            packet[12..16].copy_from_slice(&s.octets());
            packet[16..20].copy_from_slice(&d.octets());
            packet[10..12].fill(0);
            let checksum = internet_checksum(&packet[..flow.l4_offset], 0);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            packet[8..24].copy_from_slice(&s.octets());
            packet[24..40].copy_from_slice(&d.octets());
        }
        _ => return false,
    }
    let l4 = flow.l4_offset;
    packet[l4..l4 + 2].copy_from_slice(&src.port().to_be_bytes());
    packet[l4 + 2..l4 + 4].copy_from_slice(&dst.port().to_be_bytes());
    let checksum_at = l4 + if flow.transport == Transport::Tcp { 16 } else { 6 };
    packet[checksum_at..checksum_at + 2].fill(0);
    let mut checksum = internet_checksum(&packet[l4..], pseudo_header_sum(src.ip(), dst.ip(), flow.transport, packet.len() - l4));
    if flow.transport == Transport::Udp && checksum == 0 {
        checksum = 0xffff; // 0 means "no checksum" in UDP
    }
    packet[checksum_at..checksum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    true
}

fn pseudo_header_sum(src: IpAddr, dst: IpAddr, transport: Transport, length: usize) -> u32 {
    let protocol = u32::from(if transport == Transport::Tcp { TCP } else { UDP });
    let words = |bytes: &[u8]| bytes.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum::<u32>();
    let addresses = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => words(&s.octets()) + words(&d.octets()),
        (IpAddr::V6(s), IpAddr::V6(d)) => words(&s.octets()) + words(&d.octets()),
        _ => 0,
    };
    addresses + protocol + (length as u32 & 0xffff) + (length as u32 >> 16)
}

/// An ICMP/ICMPv6 echo request turned into its echo reply (addresses swapped, type changed,
/// checksum recomputed), for answering pings to any address. None for anything else.
pub fn echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    let mut reply = packet.to_vec();
    match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if packet.len() < header + 8 || packet[9] != 1 || packet[header] != 8 {
                return None;
            }
            let (src, dst) = (packet[12..16].to_vec(), packet[16..20].to_vec());
            reply[12..16].copy_from_slice(&dst);
            reply[16..20].copy_from_slice(&src);
            reply[8] = 64; // TTL
            reply[10..12].fill(0);
            let checksum = internet_checksum(&reply[..header], 0);
            reply[10..12].copy_from_slice(&checksum.to_be_bytes());
            reply[header] = 0; // Echo reply
            reply[header + 2..header + 4].fill(0);
            let checksum = internet_checksum(&reply[header..], 0);
            reply[header + 2..header + 4].copy_from_slice(&checksum.to_be_bytes());
        }
        6 => {
            if packet.len() < 48 || packet[6] != 58 || packet[40] != 128 {
                return None;
            }
            let (src, dst) = (packet[8..24].to_vec(), packet[24..40].to_vec());
            reply[8..24].copy_from_slice(&dst);
            reply[24..40].copy_from_slice(&src);
            reply[7] = 64; // Hop limit
            reply[40] = 129; // Echo reply
            reply[42..44].fill(0);
            let words = |bytes: &[u8]| bytes.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum::<u32>();
            let length = (reply.len() - 40) as u32;
            let pseudo = words(&reply[8..24]) + words(&reply[24..40]) + length + 58;
            let checksum = internet_checksum(&reply[40..], pseudo);
            reply[42..44].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => return None,
    }
    Some(reply)
}

/// RFC 1071 one's complement checksum, seeded with `initial`
pub fn internet_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for chunk in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A valid TCP SYN (IPv4) or UDP datagram (IPv6) built by hand
    pub fn packet(transport: Transport, src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let l4_len = if transport == Transport::Tcp { 20 } else { 8 } + payload.len();
        let mut l4 = vec![0u8; l4_len];
        l4[0..2].copy_from_slice(&src.port().to_be_bytes());
        l4[2..4].copy_from_slice(&dst.port().to_be_bytes());
        if transport == Transport::Tcp {
            l4[12] = 5 << 4;
            l4[13] = 0x02; // SYN
            l4[20..].copy_from_slice(payload);
        } else {
            l4[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
            l4[8..].copy_from_slice(payload);
        }
        let protocol = if transport == Transport::Tcp { TCP } else { UDP };
        let mut ip = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0];
                h[2..4].copy_from_slice(&((20 + l4_len) as u16).to_be_bytes());
                h.extend(s.octets());
                h.extend(d.octets());
                h
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let mut h = vec![0x60, 0, 0, 0, 0, 0, protocol, 64];
                h[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
                h.extend(s.octets());
                h.extend(d.octets());
                h
            }
            _ => unreachable!(),
        };
        ip.extend(l4);
        assert!(rewrite(&mut ip, src, dst)); // Fills in valid checksums
        ip
    }

    /// Checksums verify: summing a header with its checksum gives 0
    pub fn checksums_valid(packet: &[u8]) -> bool {
        let flow = parse(packet).unwrap();
        let ip_ok = !flow.src.is_ipv4() || internet_checksum(&packet[..flow.l4_offset], 0) == 0;
        let l4 = &packet[flow.l4_offset..];
        ip_ok && internet_checksum(l4, pseudo_header_sum(flow.src.ip(), flow.dst.ip(), flow.transport, l4.len())) == 0
    }

    #[test]
    fn parses_and_rewrites_ipv4_tcp() {
        let src: SocketAddr = "10.0.2.15:50000".parse().unwrap();
        let dst: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut syn = packet(Transport::Tcp, src, dst, b"");
        let flow = parse(&syn).unwrap();
        assert_eq!((flow.transport, flow.src, flow.dst, flow.syn, flow.fin), (Transport::Tcp, src, dst, true, false));
        assert!(checksums_valid(&syn));

        let (new_src, new_dst) = ("93.184.216.34:50000".parse().unwrap(), "10.0.2.15:1337".parse().unwrap());
        assert!(rewrite(&mut syn, new_src, new_dst));
        let flow = parse(&syn).unwrap();
        assert_eq!((flow.src, flow.dst), (new_src, new_dst));
        assert!(checksums_valid(&syn));
        assert!(!rewrite(&mut syn, "[::1]:1".parse().unwrap(), new_dst)); // No family change
    }

    #[test]
    fn answers_pings() {
        // A real ping: 10.0.2.15 -> 8.8.8.8, id 1, seq 1, "abcd"
        let mut request = vec![0x45, 0, 0, 32, 0, 1, 0, 0, 64, 1, 0, 0, 10, 0, 2, 15, 8, 8, 8, 8, 8, 0, 0, 0, 0, 1, 0, 1, b'a', b'b', b'c', b'd'];
        let checksum = internet_checksum(&request[..20], 0);
        request[10..12].copy_from_slice(&checksum.to_be_bytes());
        let checksum = internet_checksum(&request[20..], 0);
        request[22..24].copy_from_slice(&checksum.to_be_bytes());
        let reply = echo_reply(&request).unwrap();
        assert_eq!((&reply[12..16], &reply[16..20], reply[20]), (&[8, 8, 8, 8][..], &[10, 0, 2, 15][..], 0));
        assert_eq!(internet_checksum(&reply[..20], 0), 0);
        assert_eq!(internet_checksum(&reply[20..], 0), 0);
        assert_eq!(&reply[24..], &request[24..]); // Same id, sequence & data
        assert!(echo_reply(&reply).is_none()); // Replies aren't answered
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        v6.extend([0u8; 15]);
        v6.push(1);
        v6.extend([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend([128, 0, 0, 0, 0, 7, 0, 1]);
        let reply = echo_reply(&v6).unwrap();
        assert_eq!(reply[40], 129);
        let words = |b: &[u8]| b.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum::<u32>();
        assert_eq!(internet_checksum(&reply[40..], words(&reply[8..40]) + 8 + 58), 0);
    }

    #[test]
    fn parses_and_rewrites_ipv6_udp() {
        let src: SocketAddr = "[2001:db8::15]:5353".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
        let mut datagram = packet(Transport::Udp, src, dst, b"\x12\x34query");
        assert_eq!(parse(&datagram).unwrap().transport, Transport::Udp);
        assert!(rewrite(&mut datagram, dst, src));
        assert!(checksums_valid(&datagram));
        assert_eq!(&datagram[48..], b"\x12\x34query"); // Payload untouched
        assert!(parse(&[0x45, 0, 0]).is_none());
        assert!(parse(b"").is_none());
    }
}
