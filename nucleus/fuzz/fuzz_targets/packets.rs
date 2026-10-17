//! The diverter's packet code: parsing, rewriting (which must keep packets valid), ping
//! replies, and the reflector's state machine
#![no_main]
use std::net::SocketAddr;
use std::time::Instant;

use fakenet_diverter::packet;
use fakenet_diverter::reflect::{Mode, Reflector, Verdict};
use fakenet_diverter::Plan;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(flow) = packet::parse(data) else {
        let _ = packet::echo_reply(data);
        return;
    };
    let mut reflector = Reflector::new(
        Plan { tcp_ports: vec![80], udp_ports: vec![53], tcp_default: Some(1337), udp_default: Some(1338), passive_ports: Some((60000, 60001)), ignore_ports: vec![22] },
        Mode::SingleHost,
    );
    let verdict = reflector.handle(&flow, Instant::now(), || None, |_| false);
    if let Verdict::Reflect { src, dst } = verdict {
        let mut rewritten = data.to_vec();
        if packet::rewrite(&mut rewritten, src, dst) {
            let again = packet::parse(&rewritten).expect("a rewritten packet still parses");
            assert_eq!((again.src, again.dst), (src, dst));
            assert_eq!(rewritten.len(), data.len());
        }
        let peer: SocketAddr = SocketAddr::new(flow.dst.ip(), flow.src.port());
        let _ = reflector.original(flow.transport, peer, dst);
    }
    if let Some(reply) = packet::echo_reply(data) {
        assert_eq!(reply.len(), data.len());
    }
});
