//! TLS decryption against real sessions: an in-memory rustls client and server, every
//! decryptable suite and both versions, their key log fed to `tls::decrypt`.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use fakenet_model::flows::Conversation;
use fakenet_model::pcap::Transport;
use fakenet_model::tls::{decrypt, KeyLog};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CipherSuite, DigitallySignedStruct, SignatureScheme};

#[derive(Debug, Default)]
struct Collector(Mutex<String>);

impl rustls::KeyLog for Collector {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        self.0.lock().unwrap().push_str(&format!("{label} {} {}\n", hex(client_random), hex(secret)));
    }
}

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn session(suite: CipherSuite, tls13: bool, exchanges: &[(&[u8], &[u8])]) -> (Conversation, KeyLog) {
    let provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(rustls::crypto::CryptoProvider { cipher_suites: provider.cipher_suites.iter().filter(|s| s.suite() == suite).cloned().collect(), ..provider });
    let versions: &[&rustls::SupportedProtocolVersion] = if tls13 { &[&rustls::version::TLS13] } else { &[&rustls::version::TLS12] };
    let certified = rcgen::generate_simple_self_signed(vec!["c2.test".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).unwrap().with_no_client_auth().with_single_cert(vec![certified.cert.der().clone()], key).unwrap();
    let keys = Arc::new(Collector::default());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider).with_protocol_versions(versions).unwrap().dangerous().with_custom_certificate_verifier(Arc::new(AcceptAny)).with_no_client_auth();
    client_config.key_log = keys.clone();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), "c2.test".try_into().unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
    let mut wire: Vec<(bool, Vec<u8>)> = Vec::new();

    fn transfer(from: &mut impl FnMut(&mut Vec<u8>) -> usize, to: &mut impl FnMut(&[u8]), from_client: bool, wire: &mut Vec<(bool, Vec<u8>)>) -> bool {
        let mut bytes = Vec::new();
        while from(&mut bytes) > 0 {}
        if bytes.is_empty() {
            return false;
        }
        to(&bytes);
        wire.extend(bytes.chunks(100).map(|c| (from_client, c.to_vec())));
        true
    }
    macro_rules! settle {
        () => {
            loop {
                let a = transfer(&mut |b| client.write_tls(b).unwrap(), &mut |mut b| while !b.is_empty() { server.read_tls(&mut b).unwrap(); server.process_new_packets().unwrap(); }, true, &mut wire);
                let b = transfer(&mut |b| server.write_tls(b).unwrap(), &mut |mut b| while !b.is_empty() { client.read_tls(&mut b).unwrap(); client.process_new_packets().unwrap(); }, false, &mut wire);
                if !a && !b {
                    break;
                }
            }
        };
    }
    settle!();
    assert!(!client.is_handshaking() && !server.is_handshaking());
    for (request, response) in exchanges {
        client.writer().write_all(request).unwrap();
        settle!();
        let mut got = vec![0u8; request.len()];
        server.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, request);
        server.writer().write_all(response).unwrap();
        settle!();
        let mut got = vec![0u8; response.len()];
        client.reader().read_exact(&mut got).unwrap();
    }
    let log = KeyLog::parse(&keys.0.lock().unwrap());
    (Conversation { transport: Transport::Tcp, server_port: 443, messages: wire }, log)
}

#[test]
fn decrypts_every_aead_suite_of_tls12_and_tls13() {
    let big = vec![b'x'; 15_000]; // Spans 150 messages
    let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 15000\r\n\r\n".to_vec();
    response.extend(&big);
    let exchanges: Vec<(&[u8], &[u8])> = vec![(b"GET /beacon?id=7 HTTP/1.1\r\nHost: c2.test\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nwait"), (b"POST /out HTTP/1.1\r\nHost: c2.test\r\nContent-Length: 2\r\n\r\nhi", &response)];
    let suites = [
        (CipherSuite::TLS13_AES_128_GCM_SHA256, true),
        (CipherSuite::TLS13_AES_256_GCM_SHA384, true),
        (CipherSuite::TLS13_CHACHA20_POLY1305_SHA256, true),
        (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, false),
        (CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, false),
        (CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, false),
    ];
    for (suite, tls13) in suites {
        let (conversation, log) = session(suite, tls13, &exchanges);
        assert!(!log.is_empty(), "{suite:?}: no keys logged");
        let plain = decrypt(&conversation, &log).unwrap_or_else(|| panic!("{suite:?}: nothing decrypted"));
        let expected: Vec<(bool, Vec<u8>)> = exchanges.iter().flat_map(|(q, a)| [(true, q.to_vec()), (false, a.to_vec())]).collect();
        assert_eq!(plain.messages, expected, "{suite:?}");
        // Without the keys: left alone
        assert!(decrypt(&conversation, &KeyLog::default()).is_none());
    }
}

/// A pcap (Ethernet, IPv4, TCP) of the conversation, with handshake and sequence numbers
fn pcap_of(conversation: &Conversation) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
    let (client, server) = ([10, 0, 0, 5], [1, 2, 3, 4]);
    let (mut client_seq, mut server_seq) = (1000u32, 5000u32);
    let mut frame = |from_client: bool, seq: u32, flags: u8, payload: &[u8]| {
        let (src, dst, sport, dport) = if from_client { (client, server, 40000u16, 443u16) } else { (server, client, 443, 40000) };
        let mut tcp = Vec::new();
        tcp.extend(sport.to_be_bytes());
        tcp.extend(dport.to_be_bytes());
        tcp.extend(seq.to_be_bytes());
        tcp.extend(0u32.to_be_bytes());
        tcp.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        tcp.extend(payload);
        let mut ip = vec![0x45, 0];
        ip.extend(((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend([0, 0, 0x40, 0, 64, 6, 0, 0]);
        ip.extend(src);
        ip.extend(dst);
        ip.extend(tcp);
        let mut ethernet = vec![0u8; 12];
        ethernet.extend([0x08, 0x00]);
        ethernet.extend(ip);
        out.extend([0u8; 8]);
        out.extend((ethernet.len() as u32).to_le_bytes());
        out.extend((ethernet.len() as u32).to_le_bytes());
        out.extend(ethernet);
    };
    frame(true, client_seq - 1, 0x02, b"");
    frame(false, server_seq - 1, 0x12, b"");
    for (from_client, bytes) in &conversation.messages {
        let seq = if *from_client { &mut client_seq } else { &mut server_seq };
        frame(*from_client, *seq, 0x18, bytes);
        *seq = seq.wrapping_add(bytes.len() as u32);
    }
    out
}

#[test]
fn learns_http_from_a_decrypted_capture() {
    let exchanges: Vec<(&[u8], &[u8])> = vec![(b"GET /task HTTP/1.1\r\nHost: c2.test\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nsleep")];
    let (conversation, log) = session(CipherSuite::TLS13_AES_256_GCM_SHA384, true, &exchanges);
    let dir = std::env::temp_dir().join(format!("fakenet-tls-learn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tls.pcap");
    std::fs::write(&path, pcap_of(&conversation)).unwrap();

    let pack = fakenet_model::learn_with(&[path.clone()], &|_, _, _| None, Some(&log)).unwrap();
    assert_eq!(pack.decrypted, 1);
    let http = &pack.protocols["http"];
    let (key, model) = http.keys.iter().next().unwrap();
    assert!(key.contains("/task"), "{key}");
    assert!(model.answers[0].bytes.ends_with(b"sleep"));

    // Without the key log: one opaque TLS exchange stream, no HTTP
    let pack = fakenet_model::learn(&[path]).unwrap();
    assert_eq!(pack.decrypted, 0);
    assert!(!pack.protocols.contains_key("http") && pack.protocols.contains_key("tls"));
    std::fs::remove_dir_all(dir).ok();
}
