//! JA3 / JA4 against Wireshark 4.6's own (tshark -e tls.handshake.ja3 -e tls.handshake.ja4)
//! on real ClientHellos: OpenSSL 3 (TLS 1.3, SNI, ALPN), curl to an IP (no SNI), and
//! OpenSSL forced to TLS 1.2 without SNI or ALPN.

use fakenet_sniffer::tls::ClientHello;

fn hello(name: &str) -> ClientHello {
    let data = std::fs::read(format!("{}/tests/fixtures/clienthello-{name}.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
    ClientHello::parse(&data).unwrap()
}

#[test]
fn openssl_tls13_with_sni_and_alpn() {
    let hello = hello("openssl");
    assert_eq!(hello.sni.as_deref(), Some("c2.example"));
    assert_eq!(hello.alpn, [b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert_eq!(hello.ja3(), "9f8a8b097ad4079207681de7b51f78b5");
    assert_eq!(hello.ja4(false), "t13d9112h2_0d5420ba6086_ec21bdc2dd35");
}

#[test]
fn curl_without_sni() {
    let hello = hello("curl");
    assert_eq!(hello.sni, None);
    assert_eq!(hello.ja3(), "adc2bd4bb269872516eeaa7ade78fe75");
    assert_eq!(hello.ja4(false), "t13i9012h2_c6771aded2ed_57a60bdf03d1");
}

#[test]
fn openssl_tls12_without_extensions_of_note() {
    let hello = hello("openssl12");
    assert_eq!(hello.ja3_string(), "771,49196-49200-163-159-52393-52392-52394-49325-49311-49245-49249-49239-49235-167-49195-49199-162-158-49324-49310-49244-49248-49238-49234-166-49327-49326-49315-49314-49188-49192-107-106-49267-49271-196-195-109-197-49187-49191-103-64-49266-49270-190-189-108-191-49162-49172-57-56-136-135-49177-58-137-49161-49171-51-50-154-153-69-68-49176-52-155-70-157-49309-49233-156-49308-49232-49313-49312-61-192-60-186-53-132-47-150-65,65281-11-10-35-22-23-13,29-23-30-24-25,0");
    assert_eq!(hello.ja3(), "3ee8f208df597ffcc47095cdb358d08e");
    assert_eq!(hello.ja4(false), "t12i870700_f57cb6f61e35_322a62d02564");
}

#[test]
fn every_truncation_is_rejected_or_parsed_without_panicking() {
    let data = std::fs::read(format!("{}/tests/fixtures/clienthello-openssl.bin", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for length in 0..data.len() {
        let _ = ClientHello::parse(&data[..length]).map(|h| (h.ja3(), h.ja4(true)));
    }
}
