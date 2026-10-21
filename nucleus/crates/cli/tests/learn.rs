//! The learning loop with the real binary: a capture this project wrote (traffic.pcap) ->
//! `--learn` -> a model pack -> `--model-info`

use std::path::PathBuf;
use std::process::Command;

#[test]
fn learns_a_model_from_its_own_capture() {
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("learn");
    let _ = std::fs::remove_dir_all(&work);
    let capture_dir = work.join("capture");
    {
        let capture = fakenet_capture::Capture::open(&capture_dir).unwrap();
        let flow = capture.tcp_flow("10.0.0.5:40000".parse().unwrap(), "198.51.100.7:80".parse().unwrap());
        flow.client_data(b"GET /beacon/31337 HTTP/1.1\r\nHost: c2.example\r\n\r\n");
        flow.server_data(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsleep 60");
        flow.client_data(b"GET /beacon/31338 HTTP/1.1\r\nHost: c2.example\r\n\r\n");
        flow.server_data(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsleep 60");
        drop(flow);
        capture.flush();
    }
    let pack = work.join("model.json");
    let nucleus = env!("CARGO_BIN_EXE_fakenet-nucleus");
    let learned = Command::new(nucleus).arg("--learn").arg(&capture_dir).arg("-o").arg(&pack).output().unwrap();
    assert!(learned.status.success(), "{}", String::from_utf8_lossy(&learned.stderr));
    assert!(String::from_utf8_lossy(&learned.stdout).contains("Learned 2 exchanges"), "{}", String::from_utf8_lossy(&learned.stdout));
    let info = Command::new(nucleus).arg("--model-info").arg(&pack).output().unwrap();
    let summary: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(summary["protocols"]["http"]["exchanges"], 2);
    assert_eq!(summary["protocols"]["http"]["top"][0]["key"], "GET /beacon/{n}");
    assert_eq!(summary["protocols"]["http"]["top"][0]["count"], 2);
    // The pack answers like the server did
    let model = fakenet_model::Model::load(&[pack]).unwrap();
    let sampled = model.answer("http", b"GET /beacon/1 HTTP/1.1\r\n\r\n", &mut fakenet_model::Rng::new(1)).unwrap();
    assert!(sampled.bytes.ends_with(b"sleep 60"));
    // Nothing to learn from: a clear error
    let empty = Command::new(nucleus).arg("--learn").arg(work.join("nowhere-empty")).output().unwrap();
    assert!(!empty.status.success());
}
