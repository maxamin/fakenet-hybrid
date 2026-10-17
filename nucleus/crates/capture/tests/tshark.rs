//! The synthesized pcap, decoded by the real tshark (skipped if it isn't installed)

use std::process::Command;

use fakenet_capture::Capture;

fn tshark_available() -> bool {
    Command::new("tshark").arg("--version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn tshark_decodes_the_conversations() {
    if !tshark_available() {
        eprintln!("tshark not installed: skipping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("fakenet-capture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let capture = Capture::open(&dir).unwrap();
        let flow = capture.tcp_flow("10.0.0.5:49812".parse().unwrap(), "93.184.216.34:80".parse().unwrap());
        flow.client_data(b"GET /gate?id=42 HTTP/1.1\r\nHost: c2.evil.example\r\n\r\n");
        let body = vec![b'A'; 3000];
        let response = [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(), body].concat();
        flow.server_data(&response);
        drop(flow);

        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(b"\x04evil\x07example\x00\x00\x01\x00\x01");
        capture.udp_datagram("[2001:db8::5]:5353".parse().unwrap(), "[2001:db8::53]:53".parse().unwrap(), &query);
        capture.log("test", serde_json::json!({ "ok": true }));
    }

    let output = Command::new("tshark")
        .args(["-r"]).arg(dir.join("traffic.pcap"))
        .args(["-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE"])
        .args(["-T", "fields", "-e", "frame.protocols", "-e", "http.request.uri", "-e", "http.response.code",
               "-e", "dns.qry.name", "-e", "_ws.expert.message"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(text.contains("/gate?id=42"), "{text}");
    assert!(text.lines().any(|l| l.contains("http") && l.contains("\t200\t")), "{text}");
    assert!(text.contains("evil.example"), "{text}");
    assert!(!text.to_lowercase().contains("checksum"), "checksum problems: {text}");
    assert!(!text.contains("Previous segment not captured"), "{text}");

    let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    assert!(events.contains("\"kind\":\"test\""));
}
