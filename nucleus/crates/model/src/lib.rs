//! A statistical model of network traffic, learned from captures, for answering requests
//! the way real servers did.
//!
//! - `learn`: pcap files (this project's captures, fuzzing or REA runs, public datasets) ->
//!   a `Pack`: per protocol and request key, the answers seen and how often.
//! - `Model`: one or more packs, merged; `answer` picks a recorded answer for a request at
//!   random, weighted by how often it was seen (falling back from the most specific key to
//!   the protocol as a whole).
//!
//! Packs are JSON (`fakenet-model-pack`, version 1), so they can be shared, reviewed and
//! combined. Protocols are analysed by `analyze::Analyzer`s, which contributors can extend.

pub mod analyze;
pub mod flows;
pub mod pcap;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "fakenet-model-pack";
pub const PACK_VERSION: u32 = 1;

/// Largest answer kept (bigger ones are counted, not stored)
const MAX_ANSWER: usize = 64 * 1024;
/// Distinct answers kept per key
const MAX_ANSWERS_PER_KEY: usize = 16;
/// Keys kept per protocol
const MAX_KEYS: usize = 5_000;

/// A shareable model: what servers answered, per protocol and request key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pack {
    pub format: String,
    pub version: u32,
    /// Where it was learned from (file names), for provenance
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub created: String,
    pub protocols: BTreeMap<String, ProtocolModel>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProtocolModel {
    /// Exchanges seen (including ones not stored)
    pub exchanges: u64,
    /// Request key -> what was answered
    pub keys: BTreeMap<String, KeyModel>,
    /// Answer sizes: log2 bucket -> count
    #[serde(default)]
    pub answer_sizes: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct KeyModel {
    pub count: u64,
    pub answers: Vec<Answer>,
    /// Answers not stored (too big, or past the per-key limit)
    #[serde(default)]
    pub other: u64,
}

impl KeyModel {
    /// Counts `count` more of an answer: a known one, a new one while there's room, else other
    fn record(&mut self, bytes: Vec<u8>, count: u64) {
        match self.answers.iter().position(|a| a.bytes == bytes) {
            Some(i) => self.answers[i].count += count,
            None if self.answers.len() < MAX_ANSWERS_PER_KEY => self.answers.push(Answer { count, bytes }),
            None => self.other += count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Answer {
    pub count: u64,
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
}

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&fakenet_schema::encode_base64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        fakenet_schema::decode_base64(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Default for Pack {
    fn default() -> Self {
        Pack { format: FORMAT.into(), version: PACK_VERSION, sources: Vec::new(), created: String::new(), protocols: BTreeMap::new() }
    }
}

impl Pack {
    /// Adds one request/answer pair of `protocol`
    pub fn add(&mut self, protocol: &str, request: &[u8], response: &[u8]) {
        let analyzer = analyze::for_protocol(protocol);
        let model = self.protocols.entry(analyzer.protocol().to_string()).or_default();
        model.exchanges += 1;
        *model.answer_sizes.entry(usize::BITS - response.len().leading_zeros()).or_default() += 1;
        let Some(key) = analyzer.keys(request).into_iter().next() else { return };
        if model.keys.len() >= MAX_KEYS && !model.keys.contains_key(&key) {
            return;
        }
        let entry = model.keys.entry(key).or_default();
        entry.count += 1;
        let stored = analyzer.stored_answer(response).filter(|a| a.len() <= MAX_ANSWER);
        match stored {
            Some(bytes) => entry.record(bytes, 1),
            None => entry.other += 1,
        }
    }

    /// Adds another pack's counts to this one
    pub fn merge(&mut self, other: &Pack) {
        self.sources.extend(other.sources.iter().cloned());
        for (protocol, theirs) in &other.protocols {
            let ours = self.protocols.entry(protocol.clone()).or_default();
            ours.exchanges += theirs.exchanges;
            for (size, count) in &theirs.answer_sizes {
                *ours.answer_sizes.entry(*size).or_default() += count;
            }
            for (key, model) in &theirs.keys {
                if ours.keys.len() >= MAX_KEYS && !ours.keys.contains_key(key) {
                    continue;
                }
                let entry = ours.keys.entry(key.clone()).or_default();
                entry.count += model.count;
                entry.other += model.other;
                for answer in &model.answers {
                    entry.record(answer.bytes.clone(), answer.count);
                }
            }
        }
    }

    pub fn load(path: &Path) -> Result<Pack> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let pack: Pack = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if pack.format != FORMAT || pack.version != PACK_VERSION {
            bail!("{} is not a {FORMAT} version {PACK_VERSION}", path.display());
        }
        Ok(pack)
    }

    /// A readable summary: exchanges and keys per protocol, the most frequent keys
    pub fn summary(&self) -> serde_json::Value {
        let protocols: serde_json::Map<String, serde_json::Value> = self
            .protocols
            .iter()
            .map(|(name, model)| {
                let mut keys: Vec<(&String, &KeyModel)> = model.keys.iter().collect();
                keys.sort_by(|a, b| b.1.count.cmp(&a.1.count));
                let top: Vec<serde_json::Value> = keys.iter().take(10).map(|(k, m)| serde_json::json!({ "key": k, "count": m.count, "answers": m.answers.len() })).collect();
                (name.clone(), serde_json::json!({ "exchanges": model.exchanges, "keys": model.keys.len(), "top": top }))
            })
            .collect();
        serde_json::json!({ "sources": self.sources, "protocols": protocols })
    }
}

/// Learns a pack from pcap files
pub fn learn(paths: &[std::path::PathBuf]) -> Result<Pack> {
    let mut pack = Pack::default();
    for path in paths {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let segments = pcap::read(&bytes).with_context(|| format!("reading {}", path.display()))?;
        for exchange in flows::exchanges(&segments) {
            let transport = match exchange.transport {
                pcap::Transport::Tcp => fakenet_schema::Transport::Tcp,
                pcap::Transport::Udp => fakenet_schema::Transport::Udp,
            };
            let protocol = analyze::identify(transport, exchange.server_port, &exchange.first_client_bytes);
            pack.add(protocol, &exchange.request, &exchange.response);
        }
        pack.sources.push(path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    }
    let format = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    pack.created = time::OffsetDateTime::now_utc().format(&format).unwrap_or_default();
    Ok(pack)
}

/// A small, fast random source (xorshift): sampling answers needs no cryptography
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub fn from_time() -> Rng {
        Rng::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0x9e37_79b9))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// A sampled answer and where it came from
#[derive(Debug, Clone, PartialEq)]
pub struct Sampled {
    pub bytes: Vec<u8>,
    /// The key it was filed under ("*": the protocol as a whole)
    pub key: String,
    /// How often this answer was seen, over all answers under that key
    pub probability: f64,
}

/// Loaded packs, merged, ready to answer
pub struct Model {
    pack: Pack,
}

impl Model {
    pub fn new(pack: Pack) -> Model {
        Model { pack }
    }

    pub fn load(paths: &[std::path::PathBuf]) -> Result<Model> {
        let mut pack = Pack::default();
        for path in paths {
            pack.merge(&Pack::load(path)?);
        }
        Ok(Model { pack })
    }

    pub fn pack(&self) -> &Pack {
        &self.pack
    }

    pub fn knows(&self, protocol: &str) -> bool {
        self.pack.protocols.contains_key(protocol)
    }

    /// A recorded answer for `request`, weighted by how often each was seen; the most
    /// specific key with answers wins, then the protocol's answers overall
    pub fn answer(&self, protocol: &str, request: &[u8], rng: &mut Rng) -> Option<Sampled> {
        self.answer_with(protocol, request, rng, false)
    }

    /// `answer`, but with `successful_only`, failures (not found, server errors...) are left
    /// out, so a mock keeps the sample going
    pub fn answer_with(&self, protocol: &str, request: &[u8], rng: &mut Rng, successful_only: bool) -> Option<Sampled> {
        let model = self.pack.protocols.get(protocol)?;
        let analyzer = analyze::for_protocol(protocol);
        let keep = |answer: &&Answer| !successful_only || !analyzer.is_failure(&answer.bytes);
        for key in analyzer.keys(request) {
            let candidates: Vec<&Answer> = match key.as_str() {
                // Everything the protocol answered (but not greetings, unless asked)
                "*" => model.keys.iter().filter(|(k, _)| k.as_str() != analyze::GREETING).flat_map(|(_, m)| m.answers.iter()).collect(),
                _ => match model.keys.get(&key) {
                    Some(entry) => entry.answers.iter().collect(),
                    None => {
                        // A wildcard key ("GET *"): every key it covers
                        match key.strip_suffix('*') {
                            Some(prefix) if !prefix.is_empty() => model.keys.iter().filter(|(k, _)| k.starts_with(prefix)).flat_map(|(_, m)| m.answers.iter()).collect(),
                            _ => Vec::new(),
                        }
                    }
                },
            };
            let candidates: Vec<&Answer> = candidates.into_iter().filter(keep).collect();
            if let Some(sampled) = pick(&candidates, rng) {
                return Some(Sampled { key, ..sampled });
            }
        }
        None
    }
}

fn pick(candidates: &[&Answer], rng: &mut Rng) -> Option<Sampled> {
    let total: u64 = candidates.iter().map(|a| a.count).sum();
    if total == 0 {
        return None;
    }
    let mut point = rng.below(total);
    for answer in candidates {
        if point < answer.count {
            return Some(Sampled { bytes: answer.bytes.clone(), key: String::new(), probability: answer.count as f64 / total as f64 });
        }
        point -= answer.count;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn answers_follow_the_observed_frequencies() {
        let mut pack = Pack::default();
        for _ in 0..90 {
            pack.add("http", b"GET /gate/17 HTTP/1.1\r\n\r\n", &http("200 OK", "task=sleep"));
        }
        for _ in 0..10 {
            pack.add("http", b"GET /gate/42 HTTP/1.1\r\n\r\n", &http("200 OK", "task=exfil"));
        }
        pack.add("http", b"POST /upload HTTP/1.1\r\n\r\n", &http("201 Created", ""));
        let model = Model::new(pack);
        let mut rng = Rng::new(7);
        let mut exfil = 0;
        for _ in 0..2000 {
            let sampled = model.answer("http", b"GET /gate/99 HTTP/1.1\r\n\r\n", &mut rng).unwrap();
            assert_eq!(sampled.key, "GET /gate/{n}"); // Same normalised key
            exfil += usize::from(sampled.bytes.ends_with(b"exfil"));
        }
        assert!((140..260).contains(&exfil), "{exfil} of 2000 should be about 10%");
        // An unseen path falls back to the method, then the protocol
        assert_eq!(model.answer("http", b"GET /never HTTP/1.1\r\n", &mut rng).unwrap().key, "GET *");
        assert_eq!(model.answer("http", b"DELETE /x HTTP/1.1\r\n", &mut rng).unwrap().key, "*");
        assert!(model.answer("dns", b"", &mut rng).is_none());
    }

    #[test]
    fn failures_can_be_left_out() {
        let mut pack = Pack::default();
        for _ in 0..9 {
            pack.add("http", b"GET /a HTTP/1.1\r\n", &http("404 Not Found", ""));
        }
        pack.add("http", b"GET /b HTTP/1.1\r\n", &http("200 OK", "ok"));
        let model = Model::new(pack);
        let mut rng = Rng::new(5);
        // /a only ever failed: successful-only falls through to the protocol's successes
        let sampled = model.answer_with("http", b"GET /a HTTP/1.1\r\n", &mut rng, true).unwrap();
        assert!(sampled.bytes.starts_with(b"HTTP/1.1 200"));
        assert_eq!(sampled.key, "GET *");
        assert!(model.answer("http", b"GET /a HTTP/1.1\r\n", &mut rng).unwrap().bytes.starts_with(b"HTTP/1.1 404"));
    }

    #[test]
    fn packs_merge_and_round_trip() {
        let mut a = Pack::default();
        a.add("smtp", b"", b"220 mail.example ESMTP\r\n");
        a.add("smtp", b"EHLO x\r\n", b"250 ok\r\n");
        let mut b = Pack::default();
        b.add("smtp", b"EHLO y\r\n", b"250 ok\r\n");
        b.sources.push("b.pcap".into());
        a.merge(&b);
        let ehlo = &a.protocols["smtp"].keys["EHLO"];
        assert_eq!((ehlo.count, ehlo.answers.len(), ehlo.answers[0].count), (2, 1, 2));
        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<Pack>(&text).unwrap(), a);
        // Greetings are answered only to empty requests
        let model = Model::new(a);
        let mut rng = Rng::new(1);
        assert_eq!(model.answer("smtp", b"", &mut rng).unwrap().bytes, b"220 mail.example ESMTP\r\n");
        assert_eq!(model.answer("smtp", b"NOOP\r\n", &mut rng).unwrap().bytes, b"250 ok\r\n");
    }

    #[test]
    fn learns_from_a_capture() {
        use pcap::tests::{pcap, tcp};
        let (c, s) = ("10.0.0.5:4000", "198.51.100.7:8080");
        let file = pcap(&[
            tcp(c, s, 1, 0x02, b""),
            tcp(s, c, 9, 0x12, b""),
            tcp(c, s, 2, 0x18, b"GET /beacon/5 HTTP/1.1\r\nHost: c2\r\n\r\n"),
            tcp(s, c, 10, 0x18, &http("200 OK", "sleep 60")),
        ]);
        let dir = std::env::temp_dir().join(format!("fakenet-model-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c2.pcap");
        std::fs::write(&path, file).unwrap();
        let pack = learn(&[path]).unwrap();
        assert_eq!(pack.sources, ["c2.pcap"]);
        assert_eq!(pack.protocols["http"].keys["GET /beacon/{n}"].answers[0].bytes, http("200 OK", "sleep 60"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
