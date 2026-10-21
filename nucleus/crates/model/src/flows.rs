//! Segments to conversations: TCP streams reassembled per direction, UDP grouped per flow,
//! then cut into exchanges (what the client sent, what the server answered). Bounded: a
//! hostile or huge capture can't exhaust memory.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::pcap::{Segment, Transport};

/// Bytes kept per direction of one flow
const MAX_STREAM: usize = 1024 * 1024;
/// Flows followed at once
const MAX_FLOWS: usize = 100_000;
/// Messages kept per flow
const MAX_MESSAGES: usize = 1_000;

/// One request and its answer. An empty request is a server greeting (a banner sent first).
#[derive(Debug, Clone, PartialEq)]
pub struct Exchange {
    pub transport: Transport,
    /// The port the client connected to
    pub server_port: u16,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    /// The flow's first client bytes (for telling its protocol)
    pub first_client_bytes: Vec<u8>,
}

#[derive(Default)]
struct Direction {
    next_seq: Option<u32>,
    bytes: usize,
}

struct Flow {
    transport: Transport,
    client: SocketAddr,
    server: SocketAddr,
    /// (from the client?, bytes), consecutive same-direction data merged
    messages: Vec<(bool, Vec<u8>)>,
    to_server: Direction,
    to_client: Direction,
}

impl Flow {
    fn add(&mut self, from_client: bool, data: &[u8]) {
        if data.is_empty() || self.messages.len() >= MAX_MESSAGES {
            return;
        }
        match self.messages.last_mut() {
            Some((direction, bytes)) if *direction == from_client => bytes.extend_from_slice(data),
            _ => self.messages.push((from_client, data.to_vec())),
        }
    }
}

/// The exchanges of a capture, flow by flow in order of their first packet
pub fn exchanges(segments: &[Segment]) -> Vec<Exchange> {
    let mut flows: Vec<Flow> = Vec::new();
    let mut index: HashMap<(Transport, SocketAddr, SocketAddr), usize> = HashMap::new();
    for segment in segments {
        let forward = (segment.transport, segment.src, segment.dst);
        let backward = (segment.transport, segment.dst, segment.src);
        let (slot, from_client) = match (index.get(&forward), index.get(&backward)) {
            (Some(&i), _) => (i, true),
            (None, Some(&i)) => (i, false),
            (None, None) => {
                // A SYN+ACK means we missed the SYN: the sender is the server
                let reversed = segment.transport == Transport::Tcp && segment.syn && segment.ack;
                if flows.len() >= MAX_FLOWS || (segment.transport == Transport::Tcp && !segment.syn && segment.payload.is_empty()) {
                    continue;
                }
                let (client, server) = if reversed { (segment.dst, segment.src) } else { (segment.src, segment.dst) };
                flows.push(Flow { transport: segment.transport, client, server, messages: Vec::new(), to_server: Direction::default(), to_client: Direction::default() });
                index.insert((segment.transport, client, server), flows.len() - 1);
                (flows.len() - 1, !reversed)
            }
        };
        let flow = &mut flows[slot];
        let direction = if from_client { &mut flow.to_server } else { &mut flow.to_client };
        if segment.transport == Transport::Udp {
            if direction.bytes + segment.payload.len() <= MAX_STREAM {
                direction.bytes += segment.payload.len();
                // Each datagram is its own message
                if !segment.payload.is_empty() && flow.messages.len() < MAX_MESSAGES {
                    flow.messages.push((from_client, segment.payload.clone()));
                }
            }
            continue;
        }
        if segment.syn {
            direction.next_seq = Some(segment.seq.wrapping_add(1));
            continue;
        }
        let mut data: &[u8] = &segment.payload;
        if let Some(expected) = direction.next_seq {
            let behind = expected.wrapping_sub(segment.seq);
            // Retransmitted (wholly or partly): keep only what's new
            if behind != 0 && behind < 1 << 30 {
                data = data.get(behind as usize..).unwrap_or_default();
            }
        }
        let room = MAX_STREAM.saturating_sub(direction.bytes);
        let data = &data[..data.len().min(room)];
        direction.next_seq = Some(segment.seq.wrapping_add(segment.payload.len() as u32));
        direction.bytes += data.len();
        flow.add(from_client, data);
    }

    let mut out = Vec::new();
    for flow in flows {
        let first_client_bytes = flow.messages.iter().find(|(c, _)| *c).map(|(_, b)| b[..b.len().min(4096)].to_vec()).unwrap_or_default();
        let mut pending: Option<Vec<u8>> = None;
        let mut started = false;
        for (from_client, bytes) in flow.messages {
            match from_client {
                true => {
                    started = true;
                    pending = Some(bytes);
                }
                false => {
                    // Server data before any request: a greeting
                    let request = match (&pending, started) {
                        (Some(_), _) => pending.take().unwrap_or_default(),
                        (None, false) => Vec::new(),
                        (None, true) => continue, // A second server message: already answered
                    };
                    started = true;
                    out.push(Exchange { transport: flow.transport, server_port: flow.server.port(), request, response: bytes, first_client_bytes: first_client_bytes.clone() });
                }
            }
        }
        let _ = flow.client;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::{read, tests::{pcap, tcp, udp}};

    #[test]
    fn reassembles_tcp_and_pairs_requests_with_answers() {
        let c = "10.0.0.5:4000";
        let s = "1.2.3.4:21";
        let packets = vec![
            tcp(c, s, 100, 0x02, b""),
            tcp(s, c, 500, 0x12, b""),
            tcp(s, c, 501, 0x18, b"220 ready\r\n"),
            tcp(c, s, 101, 0x18, b"USER "),
            tcp(c, s, 106, 0x18, b"bob\r\n"),
            tcp(c, s, 101, 0x18, b"USER "), // Retransmission
            tcp(s, c, 512, 0x18, b"331 password?\r\n"),
            udp("10.0.0.5:5353", "8.8.8.8:53", b"query"),
            udp("8.8.8.8:53", "10.0.0.5:5353", b"answer"),
        ];
        let exchanges = exchanges(&read(&pcap(&packets)).unwrap());
        assert_eq!(exchanges.len(), 3);
        assert_eq!((exchanges[0].request.as_slice(), exchanges[0].response.as_slice()), (&b""[..], &b"220 ready\r\n"[..])); // Greeting
        assert_eq!(exchanges[1].request, b"USER bob\r\n");
        assert_eq!(exchanges[1].response, b"331 password?\r\n");
        assert_eq!(exchanges[1].server_port, 21);
        assert_eq!((exchanges[2].request.as_slice(), exchanges[2].response.as_slice()), (&b"query"[..], &b"answer"[..]));
    }
}
