//! Reads classic pcap files (this project's traffic.pcap and wire.pcap, or captures from
//! anywhere: tcpdump, Wireshark saved as pcap, public datasets) down to TCP and UDP
//! segments, from classic pcap or pcapng (Wireshark's default). Link types: raw IP, Ethernet
//! (with VLAN tags), Linux cooked v1 and v2.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

/// One TCP segment or UDP datagram
#[derive(Debug, Clone)]
pub struct Segment {
    /// Seconds since the epoch
    pub time: f64,
    pub transport: Transport,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// TCP only
    pub seq: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin_or_rst: bool,
    pub payload: Vec<u8>,
}

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_IPV4: u32 = 228;
const LINKTYPE_IPV6: u32 = 229;
const LINKTYPE_LINUX_SLL2: u32 = 276;

/// The TCP and UDP segments of a pcap or pcapng file, in file order (others are skipped)
pub fn read(bytes: &[u8]) -> Result<Vec<Segment>> {
    if bytes.len() >= 4 && bytes[0..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        return read_pcapng(bytes);
    }
    if bytes.len() < 24 {
        bail!("too short for a pcap file");
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into()?);
    let (big_endian, nanoseconds) = match magic {
        0xa1b2_c3d4 => (false, false),
        0xa1b2_3c4d => (false, true),
        0xd4c3_b2a1 => (true, false),
        0x4d3c_b2a1 => (true, true),
        _ => bail!("not a pcap file"),
    };
    let word = |at: usize| -> u32 {
        let raw: [u8; 4] = bytes[at..at + 4].try_into().expect("4 bytes");
        if big_endian { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) }
    };
    let linktype = word(20) & 0x0fff_ffff;
    let mut segments = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let (seconds, fraction, captured) = (word(at), word(at + 4), word(at + 8) as usize);
        at += 16;
        let Some(frame) = bytes.get(at..at + captured) else { break };
        at += captured;
        let time = f64::from(seconds) + f64::from(fraction) / if nanoseconds { 1e9 } else { 1e6 };
        if let Some(segment) = link_payload(linktype, frame)?.and_then(|ip| parse_ip(ip, time)) {
            segments.push(segment);
        }
    }
    Ok(segments)
}

/// The IP packet in a frame of `linktype` (None: not IP); an unknown link type is an error
fn link_payload(linktype: u32, frame: &[u8]) -> Result<Option<&[u8]>> {
    Ok(match linktype {
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => Some(frame),
        LINKTYPE_ETHERNET => ethernet_payload(frame),
        LINKTYPE_LINUX_SLL => frame.get(16..).filter(|_| frame.len() >= 16 && is_ip_ethertype(u16::from_be_bytes([frame[14], frame[15]]))),
        LINKTYPE_LINUX_SLL2 => frame.get(20..).filter(|_| frame.len() >= 20 && is_ip_ethertype(u16::from_be_bytes([frame[0], frame[1]]))),
        other => bail!("unsupported link type {other}"),
    })
}

/// pcapng (the IETF draft's block format): section headers set the byte order, interface
/// descriptions the link type and timestamp resolution; enhanced and simple packet blocks
/// carry frames; other blocks are skipped
fn read_pcapng(bytes: &[u8]) -> Result<Vec<Segment>> {
    struct Interface {
        linktype: u32,
        /// Seconds per timestamp unit
        resolution: f64,
        snaplen: usize,
    }
    let mut segments = Vec::new();
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut big_endian = false;
    let mut at = 0;
    while at + 12 <= bytes.len() {
        let block_type_raw: [u8; 4] = bytes[at..at + 4].try_into()?;
        if block_type_raw == [0x0a, 0x0d, 0x0d, 0x0a] {
            // Section header: the byte-order magic follows the length
            let magic = bytes.get(at + 8..at + 12).ok_or_else(|| anyhow::anyhow!("truncated section header"))?;
            big_endian = match magic {
                [0x1a, 0x2b, 0x3c, 0x4d] => true,
                [0x4d, 0x3c, 0x2b, 0x1a] => false,
                _ => bail!("not a pcapng file"),
            };
            interfaces.clear();
        }
        let word = |offset: usize| -> Option<u32> {
            let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
            Some(if big_endian { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
        };
        let half = |offset: usize| -> Option<u16> {
            let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
            Some(if big_endian { u16::from_be_bytes(raw) } else { u16::from_le_bytes(raw) })
        };
        let block_type = word(at).unwrap_or(0);
        let length = word(at + 4).unwrap_or(0) as usize;
        if length < 12 || length % 4 != 0 || at + length > bytes.len() {
            break; // Truncated or corrupt: keep what was read
        }
        let body = at + 8;
        let body_end = at + length - 4;
        match block_type {
            1 => {
                // Interface description: link type, snap length, options (if_tsresol = 9)
                let linktype = u32::from(half(body).unwrap_or(0));
                let snaplen = word(body + 4).unwrap_or(0) as usize;
                let mut resolution = 1e-6;
                let mut option = body + 8;
                while option + 4 <= body_end {
                    let (code, size) = (half(option).unwrap_or(0), usize::from(half(option + 2).unwrap_or(0)));
                    if code == 0 {
                        break;
                    }
                    if code == 9 && size >= 1 {
                        let value = bytes[option + 4];
                        let exponent = i32::from(value & 0x7f);
                        resolution = if value & 0x80 == 0 { 10f64.powi(-exponent) } else { 2f64.powi(-exponent) };
                    }
                    option += 4 + size.div_ceil(4) * 4;
                }
                interfaces.push(Interface { linktype, resolution, snaplen: if snaplen == 0 { usize::MAX } else { snaplen } });
            }
            6 => {
                // Enhanced packet: interface, timestamp (high, low), captured and original lengths
                let (Some(id), Some(high), Some(low), Some(captured)) = (word(body), word(body + 4), word(body + 8), word(body + 12)) else { break };
                let Some(interface) = interfaces.get(id as usize) else { at += length; continue };
                let Some(frame) = bytes.get(body + 20..(body + 20 + captured as usize).min(body_end)) else { at += length; continue };
                let time = ((u64::from(high) << 32) | u64::from(low)) as f64 * interface.resolution;
                if let Some(segment) = link_payload(interface.linktype, frame)?.and_then(|ip| parse_ip(ip, time)) {
                    segments.push(segment);
                }
            }
            3 => {
                // Simple packet: interface 0, original length, no timestamp
                let Some(interface) = interfaces.first() else { at += length; continue };
                let original = word(body).unwrap_or(0) as usize;
                let end = (body + 4 + original.min(interface.snaplen)).min(body_end);
                if let Some(frame) = bytes.get(body + 4..end) {
                    if let Some(segment) = link_payload(interface.linktype, frame)?.and_then(|ip| parse_ip(ip, 0.0)) {
                        segments.push(segment);
                    }
                }
            }
            _ => {}
        }
        at += length;
    }
    Ok(segments)
}

fn is_ip_ethertype(ethertype: u16) -> bool {
    ethertype == 0x0800 || ethertype == 0x86dd
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    let mut offset = 12;
    loop {
        let ethertype = u16::from_be_bytes([*frame.get(offset)?, *frame.get(offset + 1)?]);
        match ethertype {
            0x8100 | 0x88a8 => offset += 4, // VLAN tags
            t if is_ip_ethertype(t) => return frame.get(offset + 2..),
            _ => return None,
        }
    }
}

/// The TCP or UDP segment in an IP packet (fragments and other protocols: None)
pub fn parse_ip(packet: &[u8], time: f64) -> Option<Segment> {
    let (src, dst, protocol, payload) = match packet.first()? >> 4 {
        4 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            let flags_offset = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
            if header < 20 || header > packet.len() || flags_offset & 0x3fff != 0 {
                return None; // Bad header, or a fragment
            }
            // The declared length, within what was captured (clamp would panic if header > len)
            let end = total.min(packet.len()).max(header);
            let src = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(*packet.get(16)?, packet[17], packet[18], packet[19]));
            (src, dst, packet[9], packet.get(header..end)?)
        }
        6 => {
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?));
            let mut next = *packet.get(6)?;
            let mut offset = 40;
            // Hop-by-hop, routing and destination options
            while matches!(next, 0 | 43 | 60) {
                next = *packet.get(offset)?;
                offset += (usize::from(*packet.get(offset + 1)?) + 1) * 8;
            }
            let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if offset > packet.len() {
                return None; // Extension headers longer than the packet
            }
            let end = (40 + length).min(packet.len()).max(offset);
            (src, dst, next, packet.get(offset..end)?)
        }
        _ => return None,
    };
    match protocol {
        6 => {
            let header = usize::from(*payload.get(12)? >> 4) * 4;
            let flags = *payload.get(13)?;
            Some(Segment {
                time,
                transport: Transport::Tcp,
                src: SocketAddr::new(src, u16::from_be_bytes([payload[0], payload[1]])),
                dst: SocketAddr::new(dst, u16::from_be_bytes([payload[2], payload[3]])),
                seq: u32::from_be_bytes(payload.get(4..8)?.try_into().ok()?),
                syn: flags & 0x02 != 0,
                ack: flags & 0x10 != 0,
                fin_or_rst: flags & 0x05 != 0,
                payload: payload.get(header.max(20)..).unwrap_or_default().to_vec(),
            })
        }
        17 => Some(Segment {
            time,
            transport: Transport::Udp,
            src: SocketAddr::new(src, u16::from_be_bytes([*payload.first()?, *payload.get(1)?])),
            dst: SocketAddr::new(dst, u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?])),
            seq: 0,
            syn: false,
            ack: false,
            fin_or_rst: false,
            payload: payload.get(8..)?.to_vec(),
        }),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A raw-IP pcap of IPv4 packets (what fakenet_capture writes)
    pub fn pcap(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(0xa1b2_c3d4u32.to_le_bytes());
        out.extend(2u16.to_le_bytes());
        out.extend(4u16.to_le_bytes());
        out.extend([0u8; 8]);
        out.extend(65_535u32.to_le_bytes());
        out.extend(LINKTYPE_RAW.to_le_bytes());
        for (i, packet) in packets.iter().enumerate() {
            out.extend((1_700_000_000u32 + i as u32).to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend((packet.len() as u32).to_le_bytes());
            out.extend((packet.len() as u32).to_le_bytes());
            out.extend(packet);
        }
        out
    }

    /// An IPv4 TCP packet (checksums left zero: the reader doesn't check them)
    pub fn tcp(src: &str, dst: &str, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else { panic!() };
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0];
        p.extend(s.octets());
        p.extend(d.octets());
        p.extend(src.port().to_be_bytes());
        p.extend(dst.port().to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend(0u32.to_be_bytes());
        p.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    pub fn udp(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else { panic!() };
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p.extend(s.octets());
        p.extend(d.octets());
        p.extend(src.port().to_be_bytes());
        p.extend(dst.port().to_be_bytes());
        p.extend(((payload.len() + 8) as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn reads_raw_and_ethernet_captures() {
        let packet = tcp("10.0.0.5:4000", "1.2.3.4:80", 7, 0x18, b"GET / HTTP/1.1\r\n\r\n");
        let segments = read(&pcap(&[packet.clone(), udp("10.0.0.5:5353", "8.8.8.8:53", b"q")])).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].dst, "1.2.3.4:80".parse().unwrap());
        assert_eq!(segments[0].payload, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(segments[1].transport, Transport::Udp);

        // The same packet in an Ethernet frame with a VLAN tag
        let mut file = pcap(&[]);
        file[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
        let mut frame = vec![0u8; 12];
        frame.extend([0x81, 0x00, 0, 5, 0x08, 0x00]);
        frame.extend(&packet);
        file.extend(1u32.to_le_bytes());
        file.extend(0u32.to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend(frame);
        assert_eq!(read(&file).unwrap()[0].src, "10.0.0.5:4000".parse().unwrap());

        assert!(read(b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00 not a byte-order magic").is_err());
        // Found by fuzzing: header lengths longer than the packet (IPv4 IHL, IPv6 extensions)
        let mut long_header = tcp("10.0.0.5:1", "1.2.3.4:2", 1, 0x02, b"");
        long_header[0] = 0x4f; // 60-byte header in a 40-byte packet
        assert!(parse_ip(&long_header, 0.0).is_none());
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 0, 64];
        v6.extend([0u8; 32]);
        v6.extend([6, 200, 0, 0, 0, 0, 0, 0]); // Hop-by-hop claiming 1608 bytes
        assert!(parse_ip(&v6, 0.0).is_none());
        assert!(read(b"short").is_err());
    }

    /// A little-endian pcapng block
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let length = (body.len() + 12) as u32;
        let mut out = kind.to_le_bytes().to_vec();
        out.extend(length.to_le_bytes());
        out.extend(body);
        out.extend(length.to_le_bytes());
        out
    }

    #[test]
    fn reads_pcapng() {
        let packet = tcp("10.0.0.5:4000", "1.2.3.4:80", 7, 0x18, b"GET / HTTP/1.1\r\n\r\n");
        let mut file = block(0x0a0d_0d0a, &[0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Interface 0: raw IP, nanosecond timestamps (if_tsresol = 9)
        let mut idb = LINKTYPE_RAW.to_le_bytes()[..2].to_vec();
        idb.extend([0, 0]);
        idb.extend(0u32.to_le_bytes());
        idb.extend([9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        file.extend(block(1, &idb));
        let nanoseconds: u64 = 1_700_000_000_500_000_000;
        let mut epb = 0u32.to_le_bytes().to_vec();
        epb.extend(((nanoseconds >> 32) as u32).to_le_bytes());
        epb.extend((nanoseconds as u32).to_le_bytes());
        epb.extend((packet.len() as u32).to_le_bytes());
        epb.extend((packet.len() as u32).to_le_bytes());
        epb.extend(&packet);
        file.extend(block(6, &epb));
        file.extend(block(0x0bad, b"custom block, skipped"));
        let mut spb = (packet.len() as u32).to_le_bytes().to_vec();
        spb.extend(&packet);
        file.extend(block(3, &spb));
        let segments = read(&file).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].payload, b"GET / HTTP/1.1\r\n\r\n");
        assert!((segments[0].time - 1_700_000_000.5).abs() < 1e-3, "{}", segments[0].time);
        assert_eq!(segments[1].dst, "1.2.3.4:80".parse().unwrap());
        // Truncated: what was complete is kept
        assert_eq!(read(&file[..file.len() - 10]).unwrap().len(), 1);
    }

}
