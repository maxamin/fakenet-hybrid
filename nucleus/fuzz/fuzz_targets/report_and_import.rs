//! The HTML report (attacker-controlled values must always come out escaped) and the
//! FakeNet-NG config importer (output is valid TOML, or a clean error), and the indicator
//! exports (a value can't break out of its STIX pattern literal)
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
    indicators(&text);
    if let Ok(toml_text) = fakenet_cli::import::convert(&text, std::path::Path::new("/base")) {
        toml_text.parse::<toml::Table>().expect("the importer produced invalid TOML");
    }
});

fn indicators(text: &str) {
    use fakenet_capture::indicators;
    let records = vec![
        serde_json::json!({ "kind": "event", "protocol": "dns", "meta": { "qname": format!("{text}.example"), "qtype": "A" } }),
        serde_json::json!({ "kind": "event", "protocol": "http", "meta": { "method": "GET", "host": text, "path": text, "headers": { "user-agent": text } } }),
        serde_json::json!({ "kind": "email", "protocol": "smtp", "from": text, "to": [text] }),
        serde_json::json!({ "kind": "session_start", "protocol": "raw", "dst": text }),
        serde_json::json!({ "kind": "tls_handshake", "protocol": "http", "sni": text, "ja3": text, "ja4": text, "known": text }),
    ];
    let found = indicators::collect(&records);
    let _ = indicators::to_csv(&found);
    let _ = indicators::to_misp(&found, None);
    let bundle = indicators::to_stix(&found, Some(&serde_json::json!({ "name": text, "sha256": text, "md5": text })));
    for object in bundle["objects"].as_array().unwrap() {
        let Some(pattern) = object["pattern"].as_str() else { continue };
        // "[path = 'literal']": the literal must unescape to exactly one indicator's value
        let start = pattern.find(" = '").expect("a comparison") + 4;
        let literal = pattern[start..].strip_suffix("']").expect("one closing quote");
        let mut value = String::new();
        let mut chars = literal.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => value.push(chars.next().expect("a complete escape")),
                '\'' => panic!("unescaped quote in {pattern:?}"),
                c => value.push(c),
            }
        }
        assert!(found.iter().any(|i| i.value == value), "{pattern:?}");
    }
}
