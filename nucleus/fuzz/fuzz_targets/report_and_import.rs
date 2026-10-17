//! The HTML report (attacker-controlled values must always come out escaped) and the
//! FakeNet-NG config importer (output is valid TOML, or a clean error)
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    // The value lands in fields the report shows prominently
    let records = vec![
        serde_json::json!({ "kind": "event", "protocol": "http", "meta": { "method": text, "path": text, "host": text }, "process": { "name": text, "pid": 1 } }),
        serde_json::json!({ "kind": "credentials", "protocol": text, "username": text, "password": text }),
        serde_json::json!({ "kind": "decision", "route": text }),
    ];
    let html = fakenet_capture::report::render(&records);
    if text.contains('<') {
        assert!(!html.contains(&text), "unescaped value in the report");
    }
    if let Ok(toml_text) = fakenet_cli::import::convert(&text, std::path::Path::new("/base")) {
        toml_text.parse::<toml::Table>().expect("the importer produced invalid TOML");
    }
});
