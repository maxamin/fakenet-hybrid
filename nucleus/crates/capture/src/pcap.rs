//! A pcap writer for conversations reconstructed from what the listeners saw.
//!
//! Listeners see byte streams (TLS already decrypted), not packets, so TCP conversations
//! are synthesized: handshake, data segments with correct sequence numbers & checksums,
//! acknowledgements, and FIN. Wireshark/tshark decode them like a real capture, with the
//! advantage that TLS-protected traffic appears as plaintext. For byte-exact wire captures,
//! run tcpdump alongside.
//!
//! Format: classic pcap, link type 101 (raw IPv4/IPv6 packets, no Ethernet header).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const LINKTYPE_RAW: u32 = 101;
const SEGMENT_SIZE: usize = 1400;

pub struct PcapWriter {
    out: BufWriter<File>,
}

impl PcapWriter {
    pub fn create(path: &Path) -> std::io::Result<PcapWriter> {
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?; // Magic (microsecond timestamps)
        out.write_all(&2u16.to_le_bytes())?; // Version 2.4
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // GMT offset
        out.write_all(&0u32.to_le_bytes())?; // Timestamp accuracy
        out.write_all(&65_535u32.to_le_bytes())?; // Snap length
        out.write_all(&LINKTYPE_RAW.to_le_bytes())?;
        out.flush()?;
        Ok(PcapWriter { out })
    }

    pub fn write(&mut self, packet: &[u8]) -> std::io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        self.out.write_all(&(now.as_secs() as u32).to_le_bytes())?;
        self.out.write_all(&now.subsec_micros().to_le_bytes())?;
        self.out.write_all(&(packet.len() as u32).to_le_bytes())?;
        self.out.write_all(&(packet.len() as u32).to_le_bytes())?;
        self.out.write_all(packet)?;
        self.out.flush()
    }
}

/// Both ends in the same IP family (IPv4-mapped IPv6 addresses become IPv4; a remaining
/// mismatch maps the IPv4 side into IPv6)
fn same_family(a: SocketAddr, b: SocketAddr) -> (SocketAddr, SocketAddr) {
    let canonical = |s: SocketAddr| SocketAddr::new(s.ip().to_canonical(), s.port());
    let (a, b) = (canonical(a), canonical(b));
    let to_v6 = |s: SocketAddr| match s.ip() {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), s.port()),
        IpAddr::V6(_) => s,
    };
    if a.is_ipv4() == b.is_ipv4() { (a, b) } else { (to_v6(a), to_v6(b)) }
}

fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for chunk in chunks {
        for &byte in *chunk {
            match odd.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => odd = Some(byte),
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(high) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IP packet around a transport segment, with the transport checksum (at
/// `checksum_offset` within it) filled in from the pseudo-header
fn ip_packet(src: SocketAddr, dst: SocketAddr, protocol: u8, mut segment: Vec<u8>, checksum_offset: usize) -> Vec<u8> {
    let length = segment.len();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pseudo = [&s.octets()[..], &d.octets()[..], &[0, protocol], &(length as u16).to_be_bytes()].concat();
            let sum = checksum(&[&pseudo, &segment]);
            segment[checksum_offset..checksum_offset + 2].copy_from_slice(&sum.to_be_bytes());
            let mut header = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0];
            header[2..4].copy_from_slice(&((20 + length) as u16).to_be_bytes());
            header.extend(s.octets());
            header.extend(d.octets());
            let header_sum = checksum(&[&header]);
            header[10..12].copy_from_slice(&header_sum.to_be_bytes());
            [header, segment].concat()
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => v6_packet(s, d, protocol, segment, checksum_offset),
        _ => unreachable!("same_family() aligns the address families"),
    }
}

fn v6_packet(s: Ipv6Addr, d: Ipv6Addr, protocol: u8, mut segment: Vec<u8>, checksum_offset: usize) -> Vec<u8> {
    let length = segment.len() as u32;
    let pseudo = [&s.octets()[..], &d.octets()[..], &length.to_be_bytes(), &[0, 0, 0, protocol]].concat();
    let sum = checksum(&[&pseudo, &segment]);
    segment[checksum_offset..checksum_offset + 2].copy_from_slice(&sum.to_be_bytes());
    let mut header = vec![0x60, 0, 0, 0];
    header.extend((length as u16).to_be_bytes());
    header.extend([protocol, 64]);
    header.extend(s.octets());
    header.extend(d.octets());
    [header, segment].concat()
}

pub fn udp_packet(src: SocketAddr, dst: SocketAddr, data: &[u8]) -> Vec<u8> {
    let (src, dst) = same_family(src, dst);
    let mut segment = Vec::with_capacity(8 + data.len());
    segment.extend(src.port().to_be_bytes());
    segment.extend(dst.port().to_be_bytes());
    segment.extend(((8 + data.len()) as u16).to_be_bytes());
    segment.extend([0, 0]);
    segment.extend(data);
    ip_packet(src, dst, 17, segment, 6)
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// A synthesized TCP conversation: tracks both sides' sequence numbers
pub struct TcpConversation {
    client: SocketAddr,
    server: SocketAddr,
    client_seq: u32,
    server_seq: u32,
    closed: bool,
}

impl TcpConversation {
    pub fn new(client: SocketAddr, server: SocketAddr) -> TcpConversation {
        let (client, server) = same_family(client, server);
        // Distinct, deterministic-per-connection initial sequence numbers
        let seed = (u32::from(client.port()) << 16) ^ u32::from(server.port());
        TcpConversation { client, server, client_seq: seed.wrapping_mul(2_654_435_761), server_seq: seed.wrapping_mul(40_503), closed: false }
    }

    fn segment(&self, from_client: bool, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (src, dst, seq, ack) = if from_client {
            (self.client, self.server, self.client_seq, self.server_seq)
        } else {
            (self.server, self.client, self.server_seq, self.client_seq)
        };
        let mut segment = Vec::with_capacity(20 + payload.len());
        segment.extend(src.port().to_be_bytes());
        segment.extend(dst.port().to_be_bytes());
        segment.extend(seq.to_be_bytes());
        segment.extend((if flags & ACK != 0 { ack } else { 0 }).to_be_bytes());
        segment.extend([0x50, flags]); // 20 byte header
        segment.extend(65_535u16.to_be_bytes()); // Window
        segment.extend([0, 0, 0, 0]); // Checksum, urgent pointer
        segment.extend(payload);
        ip_packet(src, dst, 6, segment, 16)
    }

    pub fn open(&mut self) -> Vec<Vec<u8>> {
        let syn = self.segment(true, SYN, &[]);
        self.client_seq = self.client_seq.wrapping_add(1);
        let syn_ack = self.segment(false, SYN | ACK, &[]);
        self.server_seq = self.server_seq.wrapping_add(1);
        let ack = self.segment(true, ACK, &[]);
        vec![syn, syn_ack, ack]
    }

    fn data(&mut self, from_client: bool, data: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        for chunk in data.chunks(SEGMENT_SIZE) {
            packets.push(self.segment(from_client, PSH | ACK, chunk));
            if from_client {
                self.client_seq = self.client_seq.wrapping_add(chunk.len() as u32);
            } else {
                self.server_seq = self.server_seq.wrapping_add(chunk.len() as u32);
            }
        }
        if !packets.is_empty() {
            packets.push(self.segment(!from_client, ACK, &[]));
        }
        packets
    }

    pub fn client_data(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.data(true, data)
    }

    pub fn server_data(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.data(false, data)
    }

    pub fn close(&mut self) -> Vec<Vec<u8>> {
        if self.closed {
            return vec![];
        }
        self.closed = true;
        let fin = self.segment(false, FIN | ACK, &[]);
        self.server_seq = self.server_seq.wrapping_add(1);
        let client_fin = self.segment(true, FIN | ACK, &[]);
        self.client_seq = self.client_seq.wrapping_add(1);
        let last_ack = self.segment(false, ACK, &[]);
        vec![fin, client_fin, last_ack]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_internet_checksums() {
        // RFC 1071's example words sum to 0xddf2; the checksum is its complement
        assert_eq!(checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]), !0xddf2);
        // A packet including its correct checksum sums to zero
        let packet = udp_packet("10.0.0.1:1000".parse().unwrap(), "10.0.0.2:53".parse().unwrap(), b"odd");
        assert_eq!(checksum(&[&packet[..20]]), 0); // IPv4 header
    }

    #[test]
    fn tracks_tcp_sequence_numbers() {
        let mut conversation = TcpConversation::new("10.0.0.1:40000".parse().unwrap(), "10.0.0.2:80".parse().unwrap());
        let handshake = conversation.open();
        assert_eq!(handshake.len(), 3);
        let start = conversation.client_seq;
        let packets = conversation.client_data(&vec![b'x'; 3000]);
        assert_eq!(packets.len(), 4); // 1400 + 1400 + 200, then the server's ACK
        assert_eq!(conversation.client_seq, start.wrapping_add(3000));
        assert_eq!(conversation.close().len(), 3);
        assert!(conversation.close().is_empty());
    }

    #[test]
    fn aligns_address_families() {
        let (a, b) = same_family("[::ffff:10.0.0.1]:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
        assert!(a.is_ipv4() && b.is_ipv4());
        let (a, b) = same_family("[2001:db8::1]:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
        assert!(a.is_ipv6() && b.is_ipv6());
        let packet = udp_packet("[2001:db8::1]:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap(), b"x");
        assert_eq!(packet[0] >> 4, 6);
    }
}
