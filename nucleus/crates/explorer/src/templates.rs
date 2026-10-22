//! The template language: literal text with `{slot}`s, filled from hints and the event
//! being answered (see templates/default.toml for the slot list)

use std::collections::BTreeMap;

use anyhow::{bail, Context as _};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;

use crate::rng::Rng;

pub const DEFAULT_TEMPLATES: &str = include_str!("../templates/default.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub name: String,
    pub protocol: String,
    pub body: String,
    #[serde(default)]
    pub close: bool,
    /// Conditions on the event's meta fields
    #[serde(default)]
    pub when: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct TemplateFile {
    #[serde(rename = "template")]
    templates: Vec<Template>,
}

pub fn parse(text: &str) -> anyhow::Result<Vec<Template>> {
    let file: TemplateFile = toml::from_str(text).context("parsing templates")?;
    for template in &file.templates {
        // Every slot must be known: a typo should fail at load, not at answer time
        let mut probe = Probe;
        render_with(&template.body, &mut probe).with_context(|| format!("template {}", template.name))?;
    }
    Ok(file.templates)
}

impl Template {
    pub fn applies(&self, protocol: &str, meta: &Value) -> bool {
        self.protocol.eq_ignore_ascii_case(protocol)
            && self.when.iter().all(|(field, expected)| {
                let actual = meta.get(field);
                match expected {
                    Value::Bool(false) => matches!(actual, None | Some(Value::Null) | Some(Value::Bool(false))),
                    Value::Bool(true) => actual == Some(&Value::Bool(true)),
                    Value::String(text) => actual.and_then(Value::as_str).is_some_and(|a| a.eq_ignore_ascii_case(text)),
                    other => actual == Some(other),
                }
            })
    }
}

/// What slots draw from
pub trait Source {
    /// A value for a slot (`name` without functions), or None if unknown
    fn value(&mut self, name: &str) -> Option<Vec<u8>>;
}

/// Accepts every known slot with a placeholder (template validation)
struct Probe;

impl Source for Probe {
    fn value(&mut self, name: &str) -> Option<Vec<u8>> {
        let known = ["command", "key", "token", "string", "url", "domain", "path", "int", "ip", "port", "random", "offset", "mirror", "mutate", "corpus", "mz", "session", "param"];
        (known.contains(&name) || name.starts_with("meta:")).then(|| b"x".to_vec())
    }
}

/// Renders a body: text, `{{`/`}}` escapes, and slots with optional functions
pub fn render_with(body: &str, source: &mut dyn Source) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while let Some(i) = rest.find(['{', '}']) {
        out.extend_from_slice(rest[..i].as_bytes());
        let tail = &rest[i..];
        if tail.starts_with("{{") || tail.starts_with("}}") {
            out.push(tail.as_bytes()[0]);
            rest = &tail[2..];
            continue;
        }
        if tail.starts_with('}') {
            bail!("unmatched }}");
        }
        let end = tail.find('}').context("unclosed {")?;
        out.extend(slot(&tail[1..end], source)?);
        rest = &tail[end + 1..];
    }
    out.extend_from_slice(rest.as_bytes());
    Ok(out)
}

const FUNCTIONS: &[&str] = &["b64", "hex", "json", "urlenc", "upper", "lower", "len8", "len16be", "len16le", "len32be", "len32le", "bulk"];

fn slot(spec: &str, source: &mut dyn Source) -> anyhow::Result<Vec<u8>> {
    // "f1:f2:name": functions apply right to left; "meta:FIELD" is a value, not a function
    let mut parts: Vec<&str> = spec.split(':').collect();
    let mut functions = Vec::new();
    while parts.len() > 1 && FUNCTIONS.contains(&parts[0]) {
        functions.push(parts.remove(0));
    }
    let name = parts.join(":");
    let mut value = source.value(&name).with_context(|| format!("unknown slot {{{name}}}"))?;
    for function in functions.iter().rev() {
        value = apply(function, value);
    }
    Ok(value)
}

fn apply(function: &str, value: Vec<u8>) -> Vec<u8> {
    let len = value.len();
    let prefixed = |prefix: Vec<u8>| [prefix, value.clone()].concat();
    match function {
        "b64" => base64::engine::general_purpose::STANDARD.encode(&value).into_bytes(),
        "hex" => value.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes(),
        "json" => {
            let text = serde_json::to_string(&String::from_utf8_lossy(&value)).unwrap_or_default();
            text.as_bytes()[1..text.len() - 1].to_vec()
        }
        "urlenc" => value
            .iter()
            .flat_map(|&b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { vec![b] } else { format!("%{b:02X}").into_bytes() })
            .collect(),
        "upper" => value.to_ascii_uppercase(),
        "lower" => value.to_ascii_lowercase(),
        "len8" => prefixed(vec![len.min(255) as u8]),
        "len16be" => prefixed((len.min(65535) as u16).to_be_bytes().to_vec()),
        "len16le" => prefixed((len.min(65535) as u16).to_le_bytes().to_vec()),
        "len32be" => prefixed((len as u32).to_be_bytes().to_vec()),
        "len32le" => prefixed((len as u32).to_le_bytes().to_vec()),
        "bulk" => [format!("${len}\r\n").into_bytes(), value.clone(), b"\r\n".to_vec()].concat(),
        _ => value,
    }
}

/// Mutations of a payload (for {mutate}): bit flips, byte changes, truncation, duplication,
/// interesting values
pub fn mutate(payload: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = payload.to_vec();
    if data.is_empty() {
        return vec![0; 1 + rng.below(8)];
    }
    for _ in 0..1 + rng.below(4) {
        let i = rng.below(data.len());
        match rng.below(6) {
            0 => data[i] ^= 1 << rng.below(8),
            1 => data[i] = [0x00, 0xff, 0x7f, 0x80, b'\n', b'%'][rng.below(6)],
            2 => data.truncate(1 + rng.below(data.len())),
            3 if data.len() < 8192 => {
                let start = rng.below(data.len());
                let end = (start + 1 + rng.below(16)).min(data.len());
                let chunk = data[start..end].to_vec();
                data.splice(i..i, chunk);
            }
            4 => data[i] = data[i].wrapping_add(1),
            _ => data.insert(i, rng.below(256) as u8),
        }
        if data.is_empty() {
            data.push(0);
        }
    }
    data
}

/// A minimal (non-functional) PE: enough for "is this an executable?" checks to pass
pub fn mz_stub() -> Vec<u8> {
    let mut pe = vec![0u8; 0x200];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x40..0x40 + 39].copy_from_slice(b"This program cannot be run in DOS mode.");
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl Source for Fixed {
        fn value(&mut self, name: &str) -> Option<Vec<u8>> {
            Some(match name {
                "command" => b"run \"x\"".to_vec(),
                "key" => b"cmd".to_vec(),
                other if other.starts_with("meta:") => other[5..].as_bytes().to_vec(),
                _ => return None,
            })
        }
    }

    #[test]
    fn renders_slots_functions_and_escapes() {
        let out = render_with("{{\"{json:key}\":\"{json:command}\"}} {b64:key} {len16be:key} {meta:tag} {upper:hex:key}", &mut Fixed).unwrap();
        assert_eq!(out, b"{\"cmd\":\"run \\\"x\\\"\"} Y21k \x00\x03cmd tag 636D64");
        assert!(render_with("{nope}", &mut Fixed).is_err());
        assert!(render_with("{key", &mut Fixed).is_err());
        assert!(render_with("a } b", &mut Fixed).is_err());
    }

    #[test]
    fn the_default_templates_are_valid() {
        let templates = parse(DEFAULT_TEMPLATES).unwrap();
        assert!(templates.len() >= 50);
        let ftp_file = templates.iter().find(|t| t.name == "ftp-file-exe").unwrap();
        assert!(ftp_file.applies("ftp", &serde_json::json!({ "command": "RETR", "file": true })));
        assert!(!ftp_file.applies("ftp", &serde_json::json!({ "command": "LIST" })));
        let reject = templates.iter().find(|t| t.name == "ftp-reject").unwrap();
        assert!(reject.applies("ftp", &serde_json::json!({ "command": "LIST" })));
        assert!(parse("[[template]]\nname = \"bad\"\nprotocol = \"raw\"\nbody = \"{typo}\"\n").is_err());
    }

    #[test]
    fn mutates_without_growing_unboundedly() {
        let mut rng = Rng::new(7);
        for _ in 0..1000 {
            let out = mutate(b"hello world", &mut rng);
            assert!(!out.is_empty() && out.len() < 200);
        }
        assert_eq!(&mz_stub()[..2], b"MZ");
    }
}
