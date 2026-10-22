//! Help with unknown C2 protocols, from a capture's client messages:
//! - `--infer`: per destination, the structure the messages share (magic bytes, constant
//!   bytes, a length field, a per-session counter) and how they look encoded (text, base64,
//!   hex, compressed, high-entropy, single-byte XOR), plus a Wireshark Lua dissector
//!   skeleton for what was found.
//! - `--decode`: applies transforms (base64, hex, xor:KEY, rc4:KEY, skip:N) to the payloads,
//!   writing the results next to an index.
//!
//! Heuristics only: they point at what to look at, they don't prove a format.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context as _;
use serde_json::{json, Value};

/// One client message: its session, its order in the session, and its bytes
#[derive(Debug, Clone)]
pub struct Message {
    pub session: String,
    pub seq: u64,
    pub bytes: Vec<u8>,
}

/// Client messages grouped by "<protocol> <destination>", in capture order. `all`: every
/// protocol; otherwise only `raw` (what no handler understood)
pub fn group_messages(records: &[Value], all: bool) -> BTreeMap<String, Vec<Message>> {
    let mut groups: BTreeMap<String, Vec<Message>> = BTreeMap::new();
    for record in records.iter().filter(|r| r["kind"] == "event") {
        let protocol = record["protocol"].as_str().unwrap_or("?");
        if !all && protocol != "raw" {
            continue;
        }
        let Some(bytes) = record["payload"].as_str().and_then(|p| fakenet_schema::decode_base64(p).ok()).filter(|b| !b.is_empty()) else { continue };
        let key = format!("{protocol} {}", record["dst"].as_str().unwrap_or("?"));
        groups.entry(key).or_default().push(Message {
            session: record["session_id"].as_str().unwrap_or("").to_string(),
            seq: record["seq"].as_u64().unwrap_or(0),
            bytes,
        });
    }
    groups
}

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t').count() as f64 / data.len() as f64
}

/// Shannon entropy in bits per byte
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn looks_base64(data: &[u8]) -> bool {
    let trimmed: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    trimmed.len() >= 8
        && trimmed.len() % 4 == 0
        && trimmed.iter().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b))
        && fakenet_schema::decode_base64(std::str::from_utf8(&trimmed).unwrap_or("")).is_ok()
}

fn looks_hex(data: &[u8]) -> bool {
    let trimmed: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    trimmed.len() >= 8 && trimmed.len() % 2 == 0 && trimmed.iter().all(u8::is_ascii_hexdigit)
}

fn compression(data: &[u8]) -> Option<&'static str> {
    match data {
        [0x1f, 0x8b, ..] => Some("gzip"),
        [0x78, 0x01 | 0x5e | 0x9c | 0xda, ..] => Some("zlib"),
        [b'P', b'K', 3, 4, ..] => Some("zip"),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some("zstd"),
        _ => None,
    }
}

/// How much `data` reads like text: letters, digits, spaces and common separators (plain
/// printability isn't enough: many XOR'd letters are printable punctuation)
fn text_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().filter(|&&b| b.is_ascii_alphanumeric() || b" =.,:/-_\r\n".contains(&b)).count() as f64 / data.len() as f64
}

/// The single-byte XOR key that makes the messages most text-like, if it clearly does
fn single_byte_xor(messages: &[Message], header: usize) -> Option<(u8, f64)> {
    let sample: Vec<u8> = messages.iter().flat_map(|m| m.bytes.iter().skip(header).copied()).take(64 * 1024).collect();
    if sample.len() < 8 || text_score(&sample) > 0.7 {
        return None;
    }
    let (key, score) = (1..=255u8)
        .map(|key| {
            let decoded: Vec<u8> = sample.iter().map(|b| b ^ key).collect();
            (key, text_score(&decoded))
        })
        .max_by(|a, b| a.1.total_cmp(&b.1))?;
    (score >= 0.9).then_some((key, score))
}

fn common_prefix(messages: &[Message]) -> Vec<u8> {
    let first = &messages[0].bytes;
    let length = messages.iter().map(|m| m.bytes.iter().zip(first).take_while(|(a, b)| a == b).count()).min().unwrap_or(0);
    first[..length].to_vec()
}

/// Byte positions (past the magic) equal in every message
fn constant_ranges(messages: &[Message], from: usize) -> Vec<(usize, usize)> {
    let shortest = messages.iter().map(|m| m.bytes.len()).min().unwrap_or(0);
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for i in from..shortest {
        if messages.iter().all(|m| m.bytes[i] == messages[0].bytes[i]) {
            match ranges.last_mut() {
                Some((_, end)) if *end == i => *end = i + 1,
                _ => ranges.push((i, i + 1)),
            }
        }
    }
    ranges
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Field {
    pub offset: usize,
    pub width: usize,
    pub big_endian: bool,
}

fn read_field(data: &[u8], field: Field) -> Option<u64> {
    let bytes = data.get(field.offset..field.offset + field.width)?;
    Some(match field.big_endian {
        true => bytes.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)),
        false => bytes.iter().rev().fold(0u64, |v, &b| (v << 8) | u64::from(b)),
    })
}

fn candidate_fields() -> impl Iterator<Item = Field> {
    (0..16).flat_map(|offset| [(4, true), (4, false), (2, true), (2, false), (1, true)].into_iter().map(move |(width, big_endian)| Field { offset, width, big_endian }))
}

/// A field holding the message length minus a constant (the header before it, typically)
fn length_field(messages: &[Message]) -> Option<(Field, i64)> {
    // Lengths must vary, or any constant field would "match"
    let lengths: std::collections::BTreeSet<usize> = messages.iter().map(|m| m.bytes.len()).collect();
    if messages.len() < 2 || lengths.len() < 2 {
        return None;
    }
    candidate_fields().find_map(|field| {
        let adjust = messages[0].bytes.len() as i64 - read_field(&messages[0].bytes, field)? as i64;
        let fits = messages.iter().all(|m| read_field(&m.bytes, field).is_some_and(|v| m.bytes.len() as i64 - v as i64 == adjust));
        (fits && (0..=64).contains(&adjust)).then_some((field, adjust))
    })
}

/// A field that grows by a constant step from message to message within each session
fn counter_field(messages: &[Message], skip: Option<Field>) -> Option<(Field, u64)> {
    let mut sessions: BTreeMap<&str, Vec<&Message>> = BTreeMap::new();
    for message in messages {
        sessions.entry(&message.session).or_default().push(message);
    }
    let pairs: usize = sessions.values().map(|s| s.len().saturating_sub(1)).sum();
    if pairs < 2 {
        return None;
    }
    candidate_fields().filter(|f| Some(*f) != skip).find_map(|field| {
        let mut step = None;
        for session in sessions.values_mut() {
            session.sort_by_key(|m| m.seq);
            for pair in session.windows(2) {
                let (a, b) = (read_field(&pair[0].bytes, field)?, read_field(&pair[1].bytes, field)?);
                let delta = b.checked_sub(a)?;
                if delta == 0 || delta > 16 || step.is_some_and(|s| s != delta) {
                    return None;
                }
                step = Some(delta);
            }
        }
        step.map(|s| (field, s))
    })
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn field_json(field: Field) -> Value {
    json!({ "offset": field.offset, "width": field.width, "endian": if field.big_endian { "big" } else { "little" } })
}

/// What one group of messages shares
pub fn analyse(messages: &[Message]) -> Value {
    let all: Vec<u8> = messages.iter().flat_map(|m| m.bytes.iter().copied()).collect();
    let lengths: Vec<usize> = messages.iter().map(|m| m.bytes.len()).collect();
    let length = length_field(messages);
    let counter = counter_field(messages, length.map(|(f, _)| f));
    // The shared prefix, up to the first field found (a length's high byte is often 0 in
    // every message, but it isn't magic)
    let mut magic = if messages.len() >= 2 { common_prefix(messages) } else { Vec::new() };
    if let Some(start) = [length.map(|(f, _)| f.offset), counter.map(|(f, _)| f.offset)].into_iter().flatten().min() {
        magic.truncate(start);
    }
    let magic = if magic.len() >= 2 { magic } else { Vec::new() };
    let mut encodings = Vec::new();
    let printable = printable_ratio(&all);
    if printable > 0.95 {
        encodings.push("text");
    }
    if messages.iter().all(|m| looks_base64(&m.bytes)) {
        encodings.push("base64");
    }
    if messages.iter().all(|m| looks_hex(&m.bytes)) {
        encodings.push("hex");
    }
    if let Some(kind) = messages.iter().find_map(|m| compression(&m.bytes[magic.len().min(m.bytes.len())..]).or_else(|| compression(&m.bytes))) {
        encodings.push(kind);
    }
    let bits = entropy(&all);
    if bits > 7.2 && all.len() >= 256 {
        encodings.push("high-entropy (encrypted or compressed)");
    }
    // Past the header found (magic and fields), where an encoded body would start
    let header = [magic.len()]
        .into_iter()
        .chain(length.map(|(f, _)| f.offset + f.width))
        .chain(counter.map(|(f, _)| f.offset + f.width))
        .max()
        .unwrap_or(0);
    let xor = single_byte_xor(messages, header).map(|(key, score)| (key, score, header));
    json!({
        "messages": messages.len(),
        "sessions": messages.iter().map(|m| m.session.as_str()).collect::<std::collections::BTreeSet<_>>().len(),
        "length": { "min": lengths.iter().min(), "max": lengths.iter().max() },
        "magic": (!magic.is_empty()).then(|| json!({ "hex": hex(&magic), "text": String::from_utf8_lossy(&magic) })),
        "constant": constant_ranges(messages, magic.len()).iter().map(|(a, b)| json!({ "from": a, "to": b, "hex": hex(&messages[0].bytes[*a..*b]) })).collect::<Vec<_>>(),
        "length_field": length.map(|(f, adjust)| { let mut v = field_json(f); v["adjust"] = json!(adjust); v }),
        "counter": counter.map(|(f, step)| { let mut v = field_json(f); v["step"] = json!(step); v }),
        "entropy_bits_per_byte": (bits * 100.0).round() / 100.0,
        "printable": (printable * 100.0).round() / 100.0,
        "encodings": encodings,
        "xor_key": xor.map(|(key, score, from)| json!({ "key": format!("{key:02x}"), "from_offset": from, "text_after": (score * 100.0).round() / 100.0 })),
        "first": hex(&messages[0].bytes[..messages[0].bytes.len().min(64)]),
    })
}

/// A Wireshark Lua dissector for what `analyse` found (`port`: the TCP port to register)
pub fn dissector(name: &str, port: u16, found: &Value) -> String {
    let id: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
    let mut fields = vec![format!("local f_payload = ProtoField.bytes(\"{id}.payload\", \"Payload\")")];
    let mut tree = Vec::new();
    let mut names = vec!["f_payload".to_string()];
    let mut header_end = 0;
    if let Some(magic) = found["magic"]["hex"].as_str() {
        let length = magic.len() / 2;
        fields.push(format!("local f_magic = ProtoField.bytes(\"{id}.magic\", \"Magic\")"));
        names.push("f_magic".into());
        tree.push(format!("    subtree:add(f_magic, buffer(0, {length}))"));
        header_end = header_end.max(length);
    }
    for (key, label) in [("length_field", "Length"), ("counter", "Counter")] {
        let field = &found[key];
        let (Some(offset), Some(width)) = (field["offset"].as_u64(), field["width"].as_u64()) else { continue };
        let kind = match width {
            1 => "uint8",
            2 => "uint16",
            _ => "uint32",
        };
        let short = if key == "counter" { "counter" } else { "length" };
        fields.push(format!("local f_{short} = ProtoField.{kind}(\"{id}.{short}\", \"{label}\")"));
        names.push(format!("f_{short}"));
        let add = if field["endian"] == "little" { "add_le" } else { "add" };
        tree.push(format!("    subtree:{add}(f_{short}, buffer({offset}, {width}))"));
        header_end = header_end.max((offset + width) as usize);
    }
    format!(
        "-- Wireshark dissector skeleton generated by fakenet-nucleus --infer for {name}.\n\
         -- Heuristic: check each field against the sample's code before relying on it.\n\
         -- Install: copy to Wireshark's personal plugins folder (Help > About > Folders).\n\
         local proto = Proto(\"{id}\", \"FakeNet inferred: {name}\")\n{}\n\
         proto.fields = {{ {} }}\n\n\
         function proto.dissector(buffer, pinfo, tree)\n\
         \x20   if buffer:len() == 0 then return end\n\
         \x20   pinfo.cols.protocol = \"{id}\"\n\
         \x20   local subtree = tree:add(proto, buffer(), \"FakeNet inferred: {name}\")\n{}\n\
         \x20   if buffer:len() > {header_end} then subtree:add(f_payload, buffer({header_end})) end\n\
         end\n\n\
         DissectorTable.get(\"tcp.port\"):add({port}, proto)\n",
        fields.join("\n"),
        names.join(", "),
        tree.join("\n"),
    )
}

/// `--infer`: the analysis per group, and dissectors written to `out` (if given)
pub fn infer(records: &[Value], all: bool, out: Option<&Path>) -> anyhow::Result<Value> {
    let groups = group_messages(records, all);
    let mut results = serde_json::Map::new();
    if let Some(out) = out {
        std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    }
    for (name, messages) in &groups {
        let mut found = analyse(messages);
        if let Some(out) = out {
            let port = name.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0);
            let file: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
            let path = out.join(format!("{file}.lua"));
            std::fs::write(&path, dissector(name, port, &found)).with_context(|| format!("writing {}", path.display()))?;
            found["dissector"] = json!(path.display().to_string());
        }
        results.insert(name.clone(), found);
    }
    Ok(Value::Object(results))
}

pub use fakenet_model::transform::{apply, parse_transform, Transform};

/// `--decode`: every client payload (of `filter`'s groups, if given) through `transforms`,
/// saved to `out` as `<n>_<session>.bin` plus `index.json`
pub fn decode(records: &[Value], transforms: &[Transform], filter: Option<&str>, out: &Path) -> anyhow::Result<Value> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let mut index = Vec::new();
    let mut n = 0;
    for (group, messages) in group_messages(records, true) {
        if filter.is_some_and(|f| !group.contains(f)) {
            continue;
        }
        for message in messages {
            n += 1;
            let entry = match apply(transforms, &message.bytes) {
                Ok(decoded) => {
                    let session: String = message.session.chars().filter(char::is_ascii_alphanumeric).take(36).collect();
                    let name = format!("{n:06}_{session}.bin");
                    std::fs::write(out.join(&name), &decoded).with_context(|| format!("writing {name}"))?;
                    json!({ "group": group, "session": message.session, "seq": message.seq, "file": name, "bytes": decoded.len(), "printable": (printable_ratio(&decoded) * 100.0).round() / 100.0, "preview": String::from_utf8_lossy(&decoded[..decoded.len().min(80)]) })
                }
                Err(e) => json!({ "group": group, "session": message.session, "seq": message.seq, "error": e.to_string() }),
            };
            index.push(entry);
        }
    }
    let index = Value::Array(index);
    std::fs::write(out.join("index.json"), serde_json::to_vec_pretty(&index)?)?;
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(session: &str, seq: u64, bytes: Vec<u8>) -> Message {
        Message { session: session.into(), seq, bytes }
    }

    /// "BOT" + u16 BE length of the rest + u32 LE counter + XOR-0x5a'd text
    fn framed(counter: u32, body: &str) -> Vec<u8> {
        let payload: Vec<u8> = body.bytes().map(|b| b ^ 0x5a).collect();
        let mut out = b"BOT".to_vec();
        out.extend(((payload.len() + 4) as u16).to_be_bytes());
        out.extend(counter.to_le_bytes());
        out.extend(payload);
        out
    }

    #[test]
    fn finds_magic_length_counter_and_xor() {
        let messages = vec![
            message("a", 1, framed(7, "hello there, operator")),
            message("a", 2, framed(8, "uptime=42 user=bob")),
            message("a", 3, framed(9, "ok")),
            message("b", 1, framed(100, "another session with text")),
            message("b", 2, framed(101, "and more of it")),
        ];
        let found = analyse(&messages);
        assert_eq!(found["magic"]["text"], "BOT");
        assert_eq!(found["length_field"], json!({ "offset": 3, "width": 2, "endian": "big", "adjust": 5 }));
        assert_eq!(found["counter"]["offset"], 5);
        assert_eq!(found["counter"]["endian"], "little");
        assert_eq!(found["counter"]["step"], 1);
        let lua = dissector("raw 198.18.0.9:4444", 4444, &found);
        assert!(lua.contains("ProtoField.uint16(\"raw_198_18_0_9_4444.length\"") && lua.contains("subtree:add_le(f_counter, buffer(5, 4))"), "{lua}");
        assert!(lua.contains("DissectorTable.get(\"tcp.port\"):add(4444, proto)"));

        // The bodies alone: single-byte XOR
        let bodies: Vec<Message> = messages.iter().map(|m| message(&m.session, m.seq, m.bytes[9..].to_vec())).collect();
        assert_eq!(analyse(&bodies)["xor_key"]["key"], "5a");
    }

    #[test]
    fn recognises_encodings() {
        let b64 = vec![message("a", 1, b"aGVsbG8gd29ybGQh".to_vec()), message("a", 2, b"dGFza2luZyBkYXRh".to_vec())];
        assert!(analyse(&b64)["encodings"].as_array().unwrap().contains(&json!("base64")));
        let zlib = vec![message("a", 1, vec![0x78, 0x9c, 1, 2, 3])];
        assert!(analyse(&zlib)["encodings"].as_array().unwrap().contains(&json!("zlib")));
    }

    #[test]
    fn transforms_chain() {
        let transforms = [parse_transform("base64").unwrap(), parse_transform("xor:5a").unwrap()];
        let encoded = fakenet_schema::encode_base64(&b"secret".iter().map(|b| b ^ 0x5a).collect::<Vec<u8>>());
        assert_eq!(apply(&transforms, encoded.as_bytes()).unwrap(), b"secret");
        assert_eq!(apply(&[parse_transform("skip:3").unwrap(), Transform::Hex], b"BOT414243").unwrap(), b"ABC");
        assert_eq!(parse_transform("rc4:text:Key").unwrap(), Transform::Rc4(b"Key".to_vec()));
        assert!(parse_transform("xor:zz").is_err() && parse_transform("xor:").is_err() && parse_transform("rot13").is_err());
    }
}
