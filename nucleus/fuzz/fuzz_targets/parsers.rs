//! The pure parsers, with invariants beyond "doesn't crash"
#![no_main]
use std::path::Path;

use fakenet_listeners::{custom, dns, ftp, http, imap, irc, ssh, telnet, tftp};
use fakenet_schema::{Protocol, Transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for transport in [Transport::Tcp, Transport::Udp] {
        let port = data.first().map(|&b| u16::from(b) * 7).unwrap_or(0);
        let protocol = fakenet_sniffer::sniff(fakenet_sniffer::DEFAULT_ORDER, data, port, transport);
        // Whatever is chosen must be servable on that transport
        assert!(fakenet_sniffer::supports(protocol, transport), "{protocol:?} on {transport:?}");
    }
    let _ = fakenet_sniffer::sniff_silent(fakenet_sniffer::DEFAULT_ORDER, 25);
    let _ = fakenet_sniffer::syslog_priority(&text);
    let _ = dns::parse_answer(&text);
    let _ = tftp::parse_request(data);
    let _ = ftp::parse_port_argument(&text);
    let _ = ftp::parse_eprt_argument(&text);
    let resolved = ftp::resolve_virtual("/a/b", &text);
    assert!(resolved.starts_with('/'));
    let _ = irc::parse_message(&text);
    let _ = imap::parse_arguments(&text);
    let stripped = telnet::strip_commands(data);
    assert!(stripped.len() <= data.len());
    let _ = telnet::shell_response(&text);
    if let Some(kex) = ssh::KexInit::parse(data) {
        assert_eq!(kex.hassh().len(), 32);
    }
    let _ = http::from_raw(data, "S", Protocol::Http == Protocol::Http);
    let _ = http::mime_type(&text);
    // Never escapes its root, whatever the request path
    if let Some(joined) = http::safe_join(Path::new("/srv/root"), &text) {
        assert!(joined.starts_with("/srv/root"), "{joined:?}");
    }
    let _ = custom::parse_ini(&text);
    // ClientHellos: fingerprints have fixed shapes; completeness agrees with parsing
    if let Some(hello) = fakenet_sniffer::tls::ClientHello::parse(data) {
        assert_eq!(hello.ja3().len(), 32);
        let ja4 = hello.ja4(false);
        assert_eq!(ja4.len(), 36, "{ja4}");
    }
    let _ = fakenet_sniffer::tls::hello_wants_more(data);
    let _ = fakenet_sniffer::tls::parse_known(&text);
});
