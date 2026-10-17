//! What the sample itself suggests answering with: strings extracted from its binary,
//! REA's analysis (procedure and string records), and tokens it sends on the wire.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A function known to exist in the sample (from REA), for coverage mapping
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Function {
    pub address: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hints {
    /// Short identifier-like words a C2 protocol might use as commands ("download", "!ddos")
    pub commands: BTreeSet<String>,
    /// Likely keys of key/value or JSON messages ("cmd", "task", "id")
    pub keys: BTreeSet<String>,
    pub urls: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    /// URL paths ("/gate.php")
    pub paths: BTreeSet<String>,
    /// Other printable strings worth echoing back
    pub strings: BTreeSet<String>,
    pub functions: Vec<Function>,
    /// Tokens most likely to matter: words from the sample's own function names, and its
    /// strings that match them (weighted up when answering)
    #[serde(default)]
    pub priority: BTreeSet<String>,
    /// Never tokens: imported API names, section names (from REA)
    #[serde(default)]
    pub excluded: BTreeSet<String>,
    /// SHA-256 of the binaries REA analysed (to catch analyses of a different build)
    #[serde(default)]
    pub analysed: BTreeSet<String>,
}

const MIN_STRING: usize = 4;
const MAX_TOKENS: usize = 4096;

/// Words that are almost never commands, however often they appear in binaries
const NOISE: &[&str] = &[
    "this", "that", "with", "from", "have", "true", "false", "null", "void", "char", "const", "error", "string", "data",
    "length", "size", "value", "type", "name", "file", "path", "windows", "microsoft", "kernel", "library", "program",
    "cannot", "mode", "runtime", "version", "invalid", "unknown", "failed",
];

impl Hints {
    pub fn merge(&mut self, other: Hints) {
        self.commands.extend(other.commands);
        self.keys.extend(other.keys);
        self.urls.extend(other.urls);
        self.domains.extend(other.domains);
        self.paths.extend(other.paths);
        self.strings.extend(other.strings);
        self.functions.extend(other.functions);
        self.functions.sort();
        self.functions.dedup();
        self.priority.extend(other.priority);
        self.excluded.extend(other.excluded);
        self.analysed.extend(other.analysed);
        self.prune();
        self.trim();
    }

    /// Drops excluded tokens (imports, section names) and promotes strings matching
    /// priority words
    fn prune(&mut self) {
        let excluded = self.excluded.clone();
        // Imports, section names, and C/C++ runtime symbols (_IO_stdin_used, _ZN..., GLIBC_2.34)
        let junk = |t: &String| excluded.contains(t) || t.starts_with('.') || t.starts_with('_') || t.starts_with("GLIBC") || t.contains("@GLIBC") || t.contains("@@");
        self.commands.retain(|t| !junk(t));
        self.strings.retain(|t| !junk(t));
        self.keys.retain(|t| !junk(t));
        let words: BTreeSet<String> = self.priority.clone();
        for token in self.commands.iter().chain(&self.strings) {
            let lower = token.to_ascii_lowercase();
            if words.iter().any(|w| lower.trim_start_matches(['!', '.', '/', '-']) == *w) {
                self.priority.insert(token.clone());
            }
        }
    }

    fn trim(&mut self) {
        for set in [&mut self.commands, &mut self.keys, &mut self.urls, &mut self.domains, &mut self.paths, &mut self.strings] {
            while set.len() > MAX_TOKENS {
                let last = set.iter().next_back().cloned();
                if let Some(last) = last {
                    set.remove(&last);
                }
            }
        }
    }

    /// Classifies printable strings (from a binary, REA, or traffic)
    pub fn classify<'a>(strings: impl IntoIterator<Item = &'a str>) -> Hints {
        let mut hints = Hints::default();
        for raw in strings {
            let s = raw.trim();
            if s.len() < 3 || s.len() > 512 {
                continue;
            }
            let lower = s.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                hints.urls.insert(s.to_string());
                if let Some(host) = s.split("://").nth(1).and_then(|r| r.split(['/', ':', '?']).next()) {
                    if host.contains('.') {
                        hints.domains.insert(host.to_ascii_lowercase());
                    }
                }
                if let Some(path) = s.split("://").nth(1).and_then(|r| r.find('/').map(|i| &r[i..])) {
                    hints.paths.insert(path.split('?').next().unwrap_or(path).to_string());
                }
                continue;
            }
            if s.starts_with('/') && s.len() > 1 && !s.contains(' ') && s.chars().all(|c| c.is_ascii_graphic()) {
                hints.paths.insert(s.split('?').next().unwrap_or(s).to_string());
                continue;
            }
            if is_domain(&lower) {
                hints.domains.insert(lower);
                continue;
            }
            // "key=value" and "key": shapes give us keys
            for part in s.split(['&', ',', '{', '}', ' ', ';']) {
                if let Some((key, _)) = part.split_once('=').or_else(|| part.split_once("\":")) {
                    let key = key.trim_matches(['"', '\'', ' ']);
                    if is_identifier(key) && key.len() <= 24 {
                        hints.keys.insert(key.to_string());
                    }
                }
            }
            // Command-like words: "!download", "/exec", "cmd_shell", "getinfo"
            let word = s.trim_start_matches(['!', '.', '/', '-', '#']);
            if s.split_whitespace().count() == 1 && is_identifier(word) && (3..=20).contains(&word.len()) && !NOISE.contains(&word.to_ascii_lowercase().as_str()) {
                hints.commands.insert(s.to_string());
            } else if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                hints.strings.insert(s.to_string());
            }
        }
        hints.trim();
        hints
    }

    /// Strings in a binary: ASCII and UTF-16LE runs of printable characters (like `strings
    /// -el`), then classified
    pub fn from_binary(bytes: &[u8]) -> Hints {
        let strings = extract_strings(bytes);
        Hints::classify(strings.iter().map(String::as_str))
    }

    /// REA output, however it's wrapped (a CLI result, Evidence records, an exported
    /// bundle). REA's Evidence says what its records are in `operation`
    /// (`search_procedures`, `list_strings`...), and records are `{address, value}` (or
    /// `{address, name}`). Procedures with real addresses become coverage targets, and their
    /// names yield command words ("cmd_download" -> "download"); strings become hints.
    /// Imports (`EXTERNAL:...`) and section-relative addresses aren't locations.
    pub fn from_rea(value: &Value) -> Hints {
        Hints::from_rea_all(std::slice::from_ref(value))
    }

    /// Several REA outputs analysed together: the overview's segment table (often in its
    /// own file) tells which strings are the program's literals and which are loader
    /// tables (import names in .dynstr, debug info...)
    pub fn from_rea_all(values: &[Value]) -> Hints {
        let mut functions = Vec::new();
        let mut located: Vec<(Option<u64>, String)> = Vec::new();
        let mut imports = BTreeSet::new();
        let mut segments: Vec<(String, u64, u64)> = Vec::new();
        let mut analysed = BTreeSet::new();
        for value in values {
            collect_rea(value, None, &mut functions, &mut located, &mut imports, &mut segments);
            find_digests(value, &mut analysed);
        }
        let in_metadata = |address: u64| {
            segments.iter().any(|(name, start, end)| (*start..*end).contains(&address) && is_metadata_section(name))
        };
        let strings: Vec<&str> = located.iter().filter(|(address, _)| !address.is_some_and(in_metadata)).map(|(_, text)| text.as_str()).collect();
        let mut hints = Hints::classify(strings);
        for function in &functions {
            // Library & runtime functions say nothing about the sample's protocol
            if is_runtime_function(&function.name) {
                continue;
            }
            for word in name_words(&function.name) {
                if (3..=20).contains(&word.len()) && !NOISE.contains(&word.as_str()) && !GENERIC_FUNCTION_WORDS.contains(&word.as_str()) {
                    hints.commands.insert(word.clone());
                    hints.priority.insert(word);
                }
            }
        }
        hints.excluded = imports;
        hints.analysed = analysed;
        functions.sort();
        functions.dedup();
        hints.functions = functions;
        hints.prune();
        hints.trim();
        hints
    }

    /// Learns from what the sample sends: its words become candidate tokens and keys
    pub fn learn_from_traffic(&mut self, payload: &[u8], meta: &Value) {
        let text = String::from_utf8_lossy(&payload[..payload.len().min(4096)]);
        for part in text.split(['&', '?', '\r', '\n', ' ', ';', ',', '{', '}']) {
            if let Some((key, value)) = part.split_once('=').or_else(|| part.split_once("\":")) {
                let key = key.trim_matches(['"', '\'', ' ', '/']);
                if is_identifier(key) && key.len() <= 24 {
                    self.keys.insert(key.to_string());
                }
                let value = value.trim_matches(['"', '\'', ' ']);
                if is_identifier(value) && (3..=20).contains(&value.len()) {
                    self.commands.insert(value.to_string());
                }
            }
        }
        if let Some(path) = meta.get("path").and_then(Value::as_str) {
            self.paths.insert(path.split('?').next().unwrap_or(path).to_string());
        }
        if let Some(host) = meta.get("host").and_then(Value::as_str) {
            if is_domain(&host.to_ascii_lowercase()) {
                self.domains.insert(host.to_ascii_lowercase());
            }
        }
        if let Some(qname) = meta.get("qname").and_then(Value::as_str) {
            self.domains.insert(qname.to_ascii_lowercase());
        }
        self.trim();
    }
}

/// Words in a function name: snake_case, camelCase, namespaces ("Bot::HandleDownload")
pub fn name_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            previous_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current).to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase();
        current.push(c);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

/// Words common in function names that aren't C2 commands
const GENERIC_FUNCTION_WORDS: &[&str] = &[
    "sub", "fun", "func", "function", "handle", "handler", "process", "init", "main", "start", "entry", "thunk", "impl",
    "get", "set", "new", "free", "alloc", "malloc", "memcpy", "memset", "strlen", "the", "and", "for", "std", "core",
];

fn is_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') && s.chars().any(|c| c.is_ascii_alphabetic())
}

fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && s.len() <= 253
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && labels.last().is_some_and(|tld| (2..=24).contains(&tld.len()) && tld.chars().all(|c| c.is_ascii_alphabetic()))
        && !["dll", "exe", "sys", "txt", "dat", "ini", "log", "cpp", "rs", "so", "json", "xml", "png", "jpg"].contains(labels.last().unwrap())
}

/// A numeric address ("0x401000", 4198400); None for symbolic ones ("EXTERNAL:0x1",
/// ".strtab:0x11f")
fn parse_address(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ReaKind {
    Procedures,
    Strings,
}

/// Compiler, libc & runtime functions (not the sample's own code)
fn is_runtime_function(name: &str) -> bool {
    name.starts_with('_') || name.starts_with("FUN_") || name.starts_with("thunk_")
        || ["frame_dummy", "register_tm_clones", "deregister_tm_clones", "entry", "start", "main"].contains(&name)
}

/// REA Evidence names its subject: {"subject": {"digest": {"sha256": ...}}}
fn find_digests(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(sha) = object.get("subject").and_then(|s| s.get("digest")).and_then(|d| d.get("sha256")).and_then(Value::as_str) {
                out.insert(sha.to_ascii_lowercase());
            }
            object.values().for_each(|v| find_digests(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| find_digests(v, out)),
        _ => {}
    }
}

/// Lowercase hex SHA-256
pub fn sha256(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Loader & metadata sections: their strings are symbol/import names or debug info, not
/// the program's own literals
fn is_metadata_section(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [".dynstr", ".dynsym", ".interp", ".gnu", ".rela", ".rel.", ".note", ".eh_frame", ".comment", ".debug", ".strtab", ".symtab", ".shstrtab", ".idata", ".edata", ".reloc", ".pdata", ".dynamic", ".got", "_elf"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn collect_rea(
    value: &Value,
    kind: Option<ReaKind>,
    functions: &mut Vec<Function>,
    strings: &mut Vec<(Option<u64>, String)>,
    imports: &mut BTreeSet<String>,
    segments: &mut Vec<(String, u64, u64)>,
) {
    match value {
        Value::Object(object) => {
            let kind = object
                .get("operation")
                .and_then(Value::as_str)
                .map(|op| if op.contains("procedure") || op.contains("function") || op.contains("names") { Some(ReaKind::Procedures) } else if op.contains("string") { Some(ReaKind::Strings) } else { None })
                .unwrap_or(kind);
            // The overview's segment table: {name, start, end}
            if let (Some(name), Some(start), Some(end)) = (object.get("name").and_then(Value::as_str), object.get("start").and_then(parse_address), object.get("end").and_then(parse_address)) {
                segments.push((name.to_string(), start, end));
            }
            if let Some(address) = object.get("address") {
                let name = object.get("name").and_then(Value::as_str);
                let text = object.get("value").or_else(|| object.get("string")).and_then(Value::as_str);
                match (kind, name, text) {
                    // Symbol & section name tables (".strtab:0x11f") hold symbol names, not the
                    // program's string literals; functions come from the procedure list
                    (Some(ReaKind::Strings), _, Some(_)) if address.as_str().is_some_and(|a| a.starts_with('.') && a.contains(':')) => {}
                    (Some(ReaKind::Strings), _, Some(text)) => strings.push((parse_address(address), text.to_string())),
                    (_, Some(name), _) | (Some(ReaKind::Procedures), None, Some(name)) => {
                        if let Some(import) = name.strip_prefix("<EXTERNAL>::") {
                            imports.insert(import.to_string());
                        }
                        // Imports & section-relative addresses aren't locations in the image
                        if let Some(address) = parse_address(address) {
                            if !name.starts_with("<EXTERNAL>") {
                                let size = object.get("size").and_then(Value::as_u64);
                                functions.push(Function { address, name: name.to_string(), size });
                            }
                        }
                    }
                    (None, None, Some(text)) => strings.push((parse_address(address), text.to_string())),
                    _ => {}
                }
            }
            for child in object.values() {
                collect_rea(child, kind, functions, strings, imports, segments);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_rea(item, kind, functions, strings, imports, segments)),
        _ => {}
    }
}

/// Printable runs (ASCII and UTF-16LE) of at least MIN_STRING characters
pub fn extract_strings(bytes: &[u8]) -> Vec<String> {
    let printable = |b: u8| (0x20..0x7f).contains(&b);
    let mut out = Vec::new();
    let mut run = Vec::new();
    for &b in bytes {
        if printable(b) {
            run.push(b);
        } else {
            if run.len() >= MIN_STRING {
                out.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
        }
    }
    if run.len() >= MIN_STRING {
        out.push(String::from_utf8_lossy(&run).into_owned());
    }
    for start in 0..2 {
        let mut run = String::new();
        for pair in bytes.get(start..).unwrap_or(&[]).chunks_exact(2) {
            if pair[1] == 0 && printable(pair[0]) {
                run.push(pair[0] as char);
            } else {
                if run.len() >= MIN_STRING {
                    out.push(std::mem::take(&mut run));
                }
                run.clear();
            }
        }
        if run.len() >= MIN_STRING {
            out.push(run);
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_commands_keys_urls_in_a_binary() {
        let mut binary = b"\x00\x01MZ\x90\x00!download\x00cmd=%s&id=%d\x00http://c2.evil.example/gate.php?x=1\x00".to_vec();
        binary.extend(b"\xff\xff"); // Separator, as between real string table entries
        binary.extend("sleep".encode_utf16().flat_map(|c| c.to_le_bytes()));
        binary.extend(b"\x00\x00kernel32.dll\x00This program cannot be run in DOS mode\x00");
        let hints = Hints::from_binary(&binary);
        assert!(hints.commands.contains("!download") && hints.commands.contains("sleep"), "{hints:?}");
        assert!(hints.keys.contains("cmd") && hints.keys.contains("id"));
        assert!(hints.urls.contains("http://c2.evil.example/gate.php?x=1"));
        assert!(hints.domains.contains("c2.evil.example") && hints.paths.contains("/gate.php"));
        assert!(!hints.domains.contains("kernel32.dll"));
    }

    #[test]
    fn imports_rea_procedures_and_strings_however_wrapped() {
        let evidence = serde_json::json!({
            "evidence_id": "ev-1", "operation": "list_procedures",
            "result": { "procedures": [
                { "address": "0x401000", "name": "start" },
                { "address": "0x401200", "name": "cmd_download_file" },
                { "address": 4202496, "name": "Bot::HandleKeylog", "size": 64 }
            ]},
            "more": [{ "operation": "list_strings", "result": { "strings": [{ "address": "0x405000", "value": "task=" }, { "address": "0x405010", "value": "!ddos" }] } }]
        });
        let hints = Hints::from_rea(&evidence);
        assert_eq!(hints.functions.len(), 3);
        assert_eq!(hints.functions[0].address, 0x401000);
        assert!(hints.commands.contains("download") && hints.commands.contains("keylog") && hints.commands.contains("!ddos"), "{:?}", hints.commands);
        assert!(!hints.commands.contains("handle") && !hints.commands.contains("start"));
        assert!(hints.keys.contains("task"));
        assert_eq!(name_words("Bot::HandleKeylog"), ["bot", "handle", "keylog"]);
    }

    /// REA 6.5.0 + Ghidra 12.1.3 on examples/explorer-demo/bot.c (real CLI output)
    #[test]
    fn imports_real_rea_ghidra_output() {
        let fixture = |name: &str| serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{}/tests/fixtures/rea/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
        let hints = Hints::from_rea_all(&[fixture("rea-bot-procedures.json"), fixture("rea-bot-strings.json"), fixture("rea-bot.json")]);
        let names: Vec<&str> = hints.functions.iter().map(|f| f.name.as_str()).collect();
        for expected in ["cmd_download", "cmd_keylog", "cmd_scan", "cmd_update", "cmd_sleep", "fallback_c2", "handle_task", "main"] {
            assert!(names.contains(&expected), "{expected} missing from {names:?}");
        }
        assert!(!names.iter().any(|n| n.starts_with("<EXTERNAL>")));
        let download = hints.functions.iter().find(|f| f.name == "cmd_download").unwrap();
        assert_eq!(download.address, 0x401afd); // As `nm` reports for the non-PIE build
        for command in ["download", "keylog", "scan", "update", "sleep"] {
            assert!(hints.commands.contains(command), "{command} missing from {:?}", hints.commands);
        }
        assert!(hints.keys.contains("task"), "{:?}", hints.keys); // From the "task":"scan" string
        // Toolchain noise is gone, and the sample's own words are prioritized
        assert!(!hints.commands.iter().any(|c| c.starts_with('.') || ["stderr", "recv", "getenv"].contains(&c.as_str())), "{:?}", hints.commands);
        // The program's own literals survive
        assert!(hints.paths.iter().any(|p| p.starts_with("/poll.php")) && hints.domains.contains("cfg.c2.evil.example"), "{hints:?}");
        for word in ["download", "keylog", "scan", "update", "sleep"] {
            assert!(hints.priority.contains(word), "{word} not prioritized: {:?}", hints.priority);
        }
    }

    #[test]
    fn learns_from_the_samples_own_requests() {
        let mut hints = Hints::default();
        hints.learn_from_traffic(b"POST /api HTTP/1.1\r\n\r\n{\"bot_id\":\"abc\",\"status\":\"idle\"}", &serde_json::json!({ "path": "/api/v2", "host": "c2.example" }));
        assert!(hints.keys.contains("bot_id") && hints.commands.contains("idle"), "{hints:?}");
        assert!(hints.paths.contains("/api/v2") && hints.domains.contains("c2.example"));
    }
}
