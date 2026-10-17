//! The HTML report (attacker-controlled values must always come out escaped) and the
//! FakeNet-NG config importer (output is valid TOML, or a clean error)
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();
    // Unique markers around the value: its raw form can then only appear if it wasn't escaped
    // (a bare "<" alone appears in the report's own markup)
    let value = format!("FZ\u{1}{text}\u{1}ZF");
    let records = vec![
        serde_json::json!({ "kind": "event", "protocol": "http", "meta": { "method": value, "path": value, "host": value }, "process": { "name": value, "pid": 1 } }),
        serde_json::json!({ "kind": "credentials", "protocol": value, "username": value, "password": value }),
        serde_json::json!({ "kind": "decision", "route": value }),
    ];
    let html = fakenet_capture::report::render(&records);
    if text.contains(['<', '>', '&', '"', '\'']) {
        assert!(!html.contains(&value), "unescaped value in the report");
    }
    if let Ok(toml_text) = fakenet_cli::import::convert(&text, std::path::Path::new("/base")) {
        toml_text.parse::<toml::Table>().expect("the importer produced invalid TOML");
    }
});
