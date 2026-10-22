//! The traffic model: pcap files and model packs come from datasets anyone can supply, so
//! parsing, reassembly, analysis and sampling must survive any input
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // As a pcap file: read, reassemble, learn, answer
    if let Ok(segments) = fakenet_model::pcap::read(data) {
        let mut pack = fakenet_model::Pack::default();
        for exchange in fakenet_model::flows::exchanges(&segments) {
            let transport = match exchange.transport {
                fakenet_model::pcap::Transport::Tcp => fakenet_schema::Transport::Tcp,
                fakenet_model::pcap::Transport::Udp => fakenet_schema::Transport::Udp,
            };
            let protocol = fakenet_model::analyze::identify(transport, exchange.server_port, &exchange.first_client_bytes);
            pack.add(protocol, &exchange.request, &exchange.response);
        }
        let model = fakenet_model::Model::new(pack);
        let mut rng = fakenet_model::Rng::new(1);
        for protocol in ["http", "dns", "smtp", "raw"] {
            let _ = model.answer_with(protocol, data, &mut rng, true);
        }
    }
    // As TLS: messages split at 0xff bytes, alternating client and server, against a key log
    // with every secret for an all-zero client random (TLS 1.2 and 1.3), and as a key log
    let zero = "00".repeat(32);
    let keys = fakenet_model::tls::KeyLog::parse(&["CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"].map(|label| format!("{label} {zero} {}\n", "11".repeat(48))).concat());
    let messages = data.split(|&b| b == 0xff).enumerate().map(|(i, m)| (i % 2 == 0, m.to_vec())).collect();
    let conversation = fakenet_model::flows::Conversation { transport: fakenet_model::pcap::Transport::Tcp, server_port: 443, messages };
    let _ = fakenet_model::tls::decrypt(&conversation, &keys);
    let _ = fakenet_model::tls::KeyLog::parse(&String::from_utf8_lossy(data));
    // As one IP packet
    let _ = fakenet_model::pcap::parse_ip(data, 0.0);
    // As a request to every analyser
    for analyzer in fakenet_model::analyze::analyzers() {
        let _ = analyzer.keys(data);
        if let Some(answer) = analyzer.stored_answer(data) {
            let _ = analyzer.is_failure(&answer);
        }
    }
    // Through every transform
    for step in ["base64", "hex", "xor:5a", "rc4:text:key", "skip:3"] {
        let transform = fakenet_model::transform::parse_transform(step).expect("valid step");
        let _ = fakenet_model::transform::apply(&[transform], data);
    }
    // As a live event to every analyser (meta from the input, when it's JSON)
    let meta = serde_json::from_slice::<serde_json::Value>(data).unwrap_or_default();
    for analyzer in fakenet_model::analyze::analyzers() {
        let _ = analyzer.keys_for_event(data, &meta);
    }
    // As a model pack
    if let Ok(pack) = serde_json::from_slice::<fakenet_model::Pack>(data) {
        let _ = pack.summary();
        let model = fakenet_model::Model::new(pack);
        let _ = model.answer("http", b"GET / HTTP/1.1\r\n", &mut fakenet_model::Rng::new(2));
    }
});
