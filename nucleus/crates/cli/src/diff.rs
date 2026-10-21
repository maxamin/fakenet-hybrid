//! `--diff A B`: what changed between two runs (the same sample answered differently, or two
//! variants): the destinations, names, requests, commands, credentials, TLS clients and
//! record kinds only one of them has, so the effect of each answer shows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// What a run did, as comparable sets (and record counts)
#[derive(Debug, Default)]
pub struct Behaviour {
    pub sets: BTreeMap<&'static str, BTreeSet<String>>,
    pub kinds: BTreeMap<String, u64>,
}

const ASPECTS: [&str; 9] = ["destinations", "dns", "http", "commands", "raw", "credentials", "tls", "files", "detections"];

/// The event files of a capture: a folder (its events.jsonl and rotations) or one file
pub fn capture_files(path: &Path) -> Vec<PathBuf> {
    let events = if path.is_dir() { path.join("events.jsonl") } else { path.to_path_buf() };
    fakenet_capture::with_rotations(&events)
}

pub fn behaviour(records: &[Value]) -> Behaviour {
    let mut found = Behaviour::default();
    for aspect in ASPECTS {
        found.sets.insert(aspect, BTreeSet::new());
    }
    let text = |value: &Value| value.as_str().map(str::to_string).unwrap_or_else(|| if value.is_null() { String::new() } else { value.to_string() });
    for record in records {
        let kind = text(&record["kind"]);
        *found.kinds.entry(kind.clone()).or_default() += 1;
        let mut add = |aspect: &'static str, value: String| {
            if !value.trim().is_empty() {
                found.sets.get_mut(aspect).expect("aspect").insert(value);
            }
        };
        let meta = &record["meta"];
        match kind.as_str() {
            "event" => {
                let protocol = text(&record["protocol"]);
                add("destinations", format!("{protocol} {}", text(&record["dst"])));
                if meta["qname"].is_string() {
                    add("dns", format!("{} {}", text(&meta["qtype"]), text(&meta["qname"]).trim_end_matches('.').to_ascii_lowercase()));
                }
                if meta["path"].is_string() && protocol == "http" {
                    add("http", format!("{} {}{}", text(&meta["method"]), text(&meta["host"]).to_ascii_lowercase(), text(&meta["path"])));
                }
                // Unparsed messages, by content: a short escaped preview and the length
                if protocol == "raw" {
                    if let Some(bytes) = record["payload"].as_str().and_then(|p| fakenet_schema::decode_base64(p).ok()).filter(|b| !b.is_empty()) {
                        let preview: String = bytes.iter().take(48).map(|&b| if (0x20..0x7f).contains(&b) { (b as char).to_string() } else { format!("\\x{b:02x}") }).collect();
                        add("raw", format!("{} {preview} ({} bytes)", text(&record["dst"]), bytes.len()));
                    }
                }
                if meta["command"].is_string() {
                    add("commands", format!("{protocol}: {} {}", text(&meta["command"]), text(&meta["argument"])).trim().to_string());
                }
            }
            "credentials" => add("credentials", format!("{}: {} / {}", text(&record["protocol"]), text(&record["username"]), text(&record["password"]))),
            "tls_handshake" => add("tls", format!("sni={} ja3={} ja4={}", text(&record["sni"]), text(&record["ja3"]), text(&record["ja4"]))),
            "ssh_client" => add("tls", format!("ssh {} hassh={}", text(&record["version"]), text(&record["hassh"]))),
            "yara_match" => add("detections", format!("yara {} in {}", text(&record["rule"]), file_name(&text(&record["file"])))),
            "suspicious_command" => add("detections", format!("{}: {}", text(&record["protocol"]), text(&record["command"]))),
            _ => {}
        }
        // Saved payloads, by name without the per-run counter (http_body_000003_gate.php -> http_body gate.php)
        for key in ["saved", "saved_body", "file"] {
            let value = if key == "file" && kind != "upload" { Value::Null } else { record[key].clone() };
            if let Some(saved) = value.as_str().or_else(|| meta[key].as_str()) {
                add("files", saved_name(saved));
            }
        }
    }
    found
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn saved_name(path: &str) -> String {
    // <prefix>_<6-digit counter>_<name>, the prefix possibly containing '_' (http_body)
    let name = file_name(path);
    let counter = name.match_indices('_').find(|(i, _)| {
        let rest = &name[i + 1..];
        rest.len() > 7 && rest.as_bytes()[..6].iter().all(u8::is_ascii_digit) && rest.as_bytes()[6] == b'_'
    });
    match counter {
        Some((i, _)) => format!("{} {}", &name[..i], &name[i + 8..]),
        None => name,
    }
}

/// The differences, as JSON: per aspect, what only A and only B have; and record counts
pub fn compare(a: &Behaviour, b: &Behaviour) -> Value {
    let mut aspects = serde_json::Map::new();
    for aspect in ASPECTS {
        let (left, right) = (&a.sets[aspect], &b.sets[aspect]);
        let only_a: Vec<&String> = left.difference(right).collect();
        let only_b: Vec<&String> = right.difference(left).collect();
        aspects.insert(aspect.into(), json!({ "only_a": only_a, "only_b": only_b, "common": left.intersection(right).count() }));
    }
    let kinds: BTreeSet<&String> = a.kinds.keys().chain(b.kinds.keys()).collect();
    let counts: BTreeMap<&String, [u64; 2]> = kinds
        .into_iter()
        .map(|k| (k, [a.kinds.get(k).copied().unwrap_or(0), b.kinds.get(k).copied().unwrap_or(0)]))
        .filter(|(_, [x, y])| x != y)
        .collect();
    json!({ "aspects": aspects, "record_counts": counts })
}

/// A readable summary of `compare`'s result
pub fn render(diff: &Value, a: &str, b: &str) -> String {
    let mut out = format!("A = {a}\nB = {b}\n");
    let mut same = true;
    for aspect in ASPECTS {
        let entry = &diff["aspects"][aspect];
        let only = |side: &str| entry[side].as_array().cloned().unwrap_or_default();
        let (only_a, only_b) = (only("only_a"), only("only_b"));
        if only_a.is_empty() && only_b.is_empty() {
            continue;
        }
        same = false;
        out.push_str(&format!("\n{aspect} ({} in both)\n", entry["common"]));
        for value in &only_a {
            out.push_str(&format!("  - {}\n", value.as_str().unwrap_or_default()));
        }
        for value in &only_b {
            out.push_str(&format!("  + {}\n", value.as_str().unwrap_or_default()));
        }
    }
    if let Some(counts) = diff["record_counts"].as_object().filter(|c| !c.is_empty()) {
        out.push_str("\nrecord counts (A -> B)\n");
        for (kind, pair) in counts {
            out.push_str(&format!("  {kind}: {} -> {}\n", pair[0], pair[1]));
        }
    }
    if same {
        out.push_str("\nSame behaviour on every aspect compared.\n");
    }
    out.push_str("\n(- only in A, + only in B)\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(c2_path: &str, extra: Option<Value>) -> Vec<Value> {
        let mut records = vec![
            json!({ "kind": "event", "protocol": "dns", "dst": "10.0.0.1:53", "meta": { "qname": "C2.Example.", "qtype": "A" } }),
            json!({ "kind": "event", "protocol": "http", "dst": "198.18.0.5:80", "meta": { "method": "GET", "host": "c2.example", "path": c2_path, "saved_body": "/cap/files/http_body_000004_gate.php" } }),
        ];
        records.extend(extra);
        records
    }

    #[test]
    fn shows_what_each_answer_changed() {
        let a = behaviour(&run("/gate.php", None));
        let b = behaviour(&run("/gate.php?stage=2", Some(json!({ "kind": "credentials", "protocol": "ftp", "username": "u", "password": "p" }))));
        let diff = compare(&a, &b);
        assert_eq!(diff["aspects"]["http"]["only_a"], json!(["GET c2.example/gate.php"]));
        assert_eq!(diff["aspects"]["http"]["only_b"], json!(["GET c2.example/gate.php?stage=2"]));
        assert_eq!(diff["aspects"]["dns"]["common"], 1); // Case and the trailing dot don't count
        assert_eq!(diff["aspects"]["files"]["common"], 1); // Nor the per-run file counter
        assert_eq!(diff["aspects"]["credentials"]["only_b"], json!(["ftp: u / p"]));
        assert_eq!(diff["record_counts"]["credentials"], json!([0, 1]));
        let text = render(&diff, "run1", "run2");
        assert!(text.contains("  + GET c2.example/gate.php?stage=2"), "{text}");
        assert!(render(&compare(&a, &a), "x", "x").contains("Same behaviour"));
    }
}
