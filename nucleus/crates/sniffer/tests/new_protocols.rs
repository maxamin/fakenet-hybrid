//! The first bytes of real clients (smbclient 4, ldapsearch, FreeRDP 3, paho-mqtt) and a
//! CoAP GET, recognised on any port

use fakenet_schema::{Protocol, Transport};
use fakenet_sniffer::{sniff, sniff_silent, DEFAULT_ORDER};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/first-{name}.bin", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn real_clients_on_odd_ports() {
    let tcp = |data: &[u8]| sniff(DEFAULT_ORDER, data, 4444, Transport::Tcp);
    assert_eq!(tcp(&fixture("smb")), Protocol::Smb);
    assert_eq!(tcp(&fixture("ldap")), Protocol::Ldap);
    assert_eq!(tcp(&fixture("rdp")), Protocol::Rdp);
    assert_eq!(tcp(&fixture("mqtt")), Protocol::Mqtt);
    assert_eq!(tcp(b"RFB 003.008\n"), Protocol::Vnc);
}

#[test]
fn coap_requests_and_lookalikes() {
    let udp = |data: &[u8]| sniff(DEFAULT_ORDER, data, 4444, Transport::Udp);
    // CON GET, message ID 0x1234, no token, Uri-Path "status"
    assert_eq!(udp(b"\x40\x01\x12\x34\xb6status"), Protocol::Coap);
    // With a 2-byte token, two Uri-Path options and a payload
    assert_eq!(udp(b"\x42\x02\x00\x07\xab\xcd\xb3api\x04ping\xffhello"), Protocol::Coap);
    // A response code (2.05), a truncated option and a bare payload marker aren't requests
    assert_eq!(udp(b"\x60\x45\x12\x34"), Protocol::Raw);
    assert_eq!(udp(b"\x40\x01\x12\x34\xb6sta"), Protocol::Raw);
    assert_eq!(udp(b"\x40\x01\x12\x34\xff"), Protocol::Raw);
}

#[test]
fn ports_and_silent_clients() {
    assert_eq!(sniff_silent(DEFAULT_ORDER, 5900), Protocol::Vnc);
    // DNS over TLS: after the TLS layer, DNS over TCP on 853
    let query = b"\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    assert_eq!(sniff(DEFAULT_ORDER, query, 853, Transport::Tcp), Protocol::Dns);
    // Plain HTTP stays HTTP (WebSocket is only reached by upgrading it)
    assert_eq!(sniff(DEFAULT_ORDER, b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n", 80, Transport::Tcp), Protocol::Http);
}
