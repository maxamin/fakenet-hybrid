//! Every protocol handler, fed arbitrary client bytes over a real (in-memory) connection.
//! The first byte picks the handler: TCP protocols (and "auto" sniffing), then UDP ones.
#![no_main]
use fakenet_listeners::fuzzing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else { return };
    let choice = selector as usize % (fuzzing::TCP.len() + fuzzing::UDP.len());
    if choice < fuzzing::TCP.len() {
        fuzzing::tcp(fuzzing::TCP[choice], input);
    } else {
        fuzzing::udp(fuzzing::UDP[choice - fuzzing::TCP.len()], input);
    }
});
