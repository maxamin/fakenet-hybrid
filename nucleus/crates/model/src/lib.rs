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
pub mod generate;
pub mod pcap;
pub mod tls;
pub mod transform;

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
    /// TLS sessions learned from their decrypted plaintext (`--keylog`)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub decrypted: u64,
    pub protocols: BTreeMap<String, ProtocolModel>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
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
        Pack { format: FORMAT.into(), version: PACK_VERSION, sources: Vec::new(), created: String::new(), decrypted: 0, protocols: BTreeMap::new() }
    }
}

impl Pack {
    /// Adds one request/answer pair of `protocol`
    pub fn add(&mut self, protocol: &str, request: &[u8], response: &[u8]) {
        self.add_keyed(protocol, request, response);
    }

    /// `add`, with the key taken from `key_source` (e.g. the request decoded: see
    /// `learn_with`); the answer is stored as sent
    pub fn add_keyed(&mut self, protocol: &str, key_source: &[u8], response: &[u8]) {
        let request = key_source;
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

    /// Adds an answer already in its stored form (as a handler gives it) under `key`: what
    /// online learning records
    pub fn add_stored(&mut self, protocol: &str, key: &str, answer: &[u8]) {
        let model = self.protocols.entry(protocol.to_string()).or_default();
        model.exchanges += 1;
        *model.answer_sizes.entry(usize::BITS - answer.len().leading_zeros()).or_default() += 1;
        if model.keys.len() >= MAX_KEYS && !model.keys.contains_key(key) {
            return;
        }
        let entry = model.keys.entry(key.to_string()).or_default();
        entry.count += 1;
        match answer.len() <= MAX_ANSWER {
            true => entry.record(answer.to_vec(), 1),
            false => entry.other += 1,
        }
    }

    /// Writes the pack as JSON, atomically (a temporary file, then a rename)
    pub fn save(&self, path: &Path) -> Result<()> {
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?).with_context(|| format!("writing {}", temporary.display()))?;
        std::fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Adds another pack's counts to this one
    pub fn merge(&mut self, other: &Pack) {
        self.sources.extend(other.sources.iter().cloned());
        self.decrypted += other.decrypted;
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

/// Learns a pack from pcap or pcapng files
pub fn learn(paths: &[std::path::PathBuf]) -> Result<Pack> {
    learn_with(paths, &|_, _, _| None, None)
}

/// `learn`, keying each request by `decode(protocol, server_port, request)` when it returns
/// bytes (an encoded C2 message, decoded); answers are stored as sent
///
/// With `keys` (an NSS key log), TLS conversations it has secrets for are decrypted and
/// learned from their plaintext (see [`tls`]); the rest stay keyed as `tls`.
pub fn learn_with(paths: &[std::path::PathBuf], decode: &dyn Fn(&str, u16, &[u8]) -> Option<Vec<u8>>, keys: Option<&tls::KeyLog>) -> Result<Pack> {
    let mut pack = Pack::default();
    for path in paths {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let segments = pcap::read(&bytes).with_context(|| format!("reading {}", path.display()))?;
        let mut conversations = flows::conversations(&segments);
        for conversation in conversations.iter_mut() {
            if let Some(plain) = keys.and_then(|keys| tls::decrypt(conversation, keys)) {
                *conversation = plain;
                pack.decrypted += 1;
            }
        }
        for exchange in conversations.iter().flat_map(flows::exchanges_of) {
            let transport = match exchange.transport {
                pcap::Transport::Tcp => fakenet_schema::Transport::Tcp,
                pcap::Transport::Udp => fakenet_schema::Transport::Udp,
            };
            let protocol = analyze::identify(transport, exchange.server_port, &exchange.first_client_bytes);
            match decode(protocol, exchange.server_port, &exchange.request) {
                Some(decoded) => pack.add_keyed(protocol, &decoded, &exchange.response),
                None => pack.add(protocol, &exchange.request, &exchange.response),
            }
        }
        pack.sources.push(path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    }
    let format = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    pack.created = time::OffsetDateTime::now_utc().format(&format).unwrap_or_default();
    Ok(pack)
}

/// Online learning: answers given during a run, added to a pack file. The file's earlier
/// contents are kept (loaded at start), and `save` rewrites it with what was added since.
pub struct Learner {
    path: std::path::PathBuf,
    pack: std::sync::Mutex<Pack>,
    added: std::sync::atomic::AtomicU64,
    saved: std::sync::atomic::AtomicU64,
}

impl Learner {
    /// Opens (or starts) the pack at `path`, labelling what this run adds with `source`
    pub fn open(path: &Path, source: &str) -> Result<Learner> {
        let mut pack = match path.exists() {
            true => Pack::load(path)?,
            false => Pack::default(),
        };
        if !pack.sources.iter().any(|s| s == source) {
            pack.sources.push(source.to_string());
        }
        Ok(Learner { path: path.to_path_buf(), pack: std::sync::Mutex::new(pack), added: Default::default(), saved: Default::default() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records one answer (in the handler's form) for a request with these keys (the most
    /// specific is used)
    pub fn record(&self, protocol: &str, keys: &[String], answer: &[u8]) {
        let Some(key) = keys.first() else { return };
        self.pack.lock().unwrap_or_else(|e| e.into_inner()).add_stored(protocol, key, answer);
        self.added.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Answers recorded so far this run
    pub fn added(&self) -> u64 {
        self.added.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Writes the pack if anything was added since the last save; true when written
    pub fn save(&self) -> Result<bool> {
        let added = self.added();
        if added == self.saved.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(false);
        }
        let pack = self.pack.lock().unwrap_or_else(|e| e.into_inner()).clone();
        pack.save(&self.path)?;
        self.saved.store(added, std::sync::atomic::Ordering::Relaxed);
        Ok(true)
    }
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
    /// Generated from the key's answers (`Model::generate_event`), not replayed
    pub generated: bool,
}

/// Markov order for generated text
const GENERATE_ORDER: usize = 4;
/// Text models kept (one per protocol and key)
const MAX_TEXT_MODELS: usize = 1_000;

/// Loaded packs, merged, ready to answer
pub struct Model {
    pack: Pack,
    /// Text models for generation, trained on first use: (protocol, key) -> model
    text_models: std::sync::Mutex<std::collections::HashMap<(String, String), std::sync::Arc<generate::TextModel>>>,
}

/// A model that reloads its packs when one changes on disk (online learning, or another
/// `--learn --merge` run), checked at most every `RELOAD_CHECK`
pub struct LiveModel {
    paths: Vec<std::path::PathBuf>,
    model: std::sync::RwLock<std::sync::Arc<Model>>,
    stamps: std::sync::Mutex<(std::time::Instant, Vec<Option<std::time::SystemTime>>)>,
}

const RELOAD_CHECK: std::time::Duration = std::time::Duration::from_secs(2);

fn modified(paths: &[std::path::PathBuf]) -> Vec<Option<std::time::SystemTime>> {
    paths.iter().map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()).collect()
}

impl LiveModel {
    pub fn load(paths: &[std::path::PathBuf]) -> Result<LiveModel> {
        let model = Model::load(paths)?;
        Ok(LiveModel { paths: paths.to_vec(), model: std::sync::RwLock::new(std::sync::Arc::new(model)), stamps: std::sync::Mutex::new((std::time::Instant::now(), modified(paths))) })
    }

    /// The current model, reloaded first if a pack changed (a pack that fails to load is
    /// reported and the previous model kept)
    pub fn current(&self) -> std::sync::Arc<Model> {
        let mut stamps = self.stamps.lock().unwrap_or_else(|e| e.into_inner());
        if stamps.0.elapsed() >= RELOAD_CHECK {
            stamps.0 = std::time::Instant::now();
            let now = modified(&self.paths);
            if now != stamps.1 {
                stamps.1 = now;
                match Model::load(&self.paths) {
                    Ok(model) => *self.model.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(model),
                    Err(e) => eprintln!("model packs changed but don't load ({e:#}); keeping the previous model"),
                }
            }
        }
        self.model.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Forces the next `current` to check the files (tests)
    pub fn check_now(&self) {
        self.stamps.lock().unwrap_or_else(|e| e.into_inner()).0 = std::time::Instant::now() - RELOAD_CHECK;
    }
}

impl Model {
    pub fn new(pack: Pack) -> Model {
        Model { pack, text_models: Default::default() }
    }

    pub fn load(paths: &[std::path::PathBuf]) -> Result<Model> {
        let mut pack = Pack::default();
        for path in paths {
            pack.merge(&Pack::load(path)?);
        }
        Ok(Model::new(pack))
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
        self.answer_keys(protocol, analyze::for_protocol(protocol).keys(request), rng, successful_only)
    }

    /// For a live event: keys from its payload and `meta` (`Analyzer::keys_for_event`)
    pub fn answer_event(&self, protocol: &str, payload: &[u8], meta: &serde_json::Value, rng: &mut Rng, successful_only: bool) -> Option<Sampled> {
        self.answer_keys(protocol, analyze::for_protocol(protocol).keys_for_event(payload, meta), rng, successful_only)
    }

    fn answer_keys(&self, protocol: &str, keys: Vec<String>, rng: &mut Rng, successful_only: bool) -> Option<Sampled> {
        self.sample_keys(protocol, keys, rng, successful_only).map(|(sampled, _)| sampled)
    }

    /// `answer_event`, then (for text answers) a new answer generated from the chosen key's
    /// answers (see `generate`); replayed when there is too little text to model
    pub fn generate_event(&self, protocol: &str, payload: &[u8], meta: &serde_json::Value, rng: &mut Rng, successful_only: bool) -> Option<Sampled> {
        let keys = analyze::for_protocol(protocol).keys_for_event(payload, meta);
        let (sampled, candidates) = self.sample_keys(protocol, keys, rng, successful_only)?;
        if protocol == "dns" {
            return Some(sampled); // Structured answer lines: never generated
        }
        let texts: Vec<&[u8]> = match protocol {
            "http" => candidates.iter().filter_map(|a| generate::split_http(a)).map(|(_, body)| body).filter(|b| generate::is_text(b)).collect(),
            _ => candidates.iter().map(Vec::as_slice).filter(|a| generate::is_text(a)).collect(),
        };
        let model = {
            let mut models = self.text_models.lock().unwrap_or_else(|e| e.into_inner());
            let id = (protocol.to_string(), sampled.key.clone());
            if !models.contains_key(&id) && models.len() >= MAX_TEXT_MODELS {
                models.clear();
            }
            models.entry(id).or_insert_with(|| std::sync::Arc::new(generate::TextModel::train(&texts, GENERATE_ORDER))).clone()
        };
        if model.is_empty() {
            return Some(sampled);
        }
        let bytes = match protocol {
            "http" => {
                let (head, body) = generate::split_http(&sampled.bytes)?;
                if !generate::is_text(body) {
                    return Some(sampled); // A binary body (an image, a payload): replayed
                }
                generate::http_with_body(head, &model.generate(rng))
            }
            _ if generate::is_text(&sampled.bytes) => generate::end_like(model.generate(rng), &texts),
            _ => return Some(sampled),
        };
        Some(Sampled { bytes, generated: true, ..sampled })
    }

    /// The sampled answer and every candidate answer under the key it came from
    fn sample_keys(&self, protocol: &str, keys: Vec<String>, rng: &mut Rng, successful_only: bool) -> Option<(Sampled, Vec<Vec<u8>>)> {
        let model = self.pack.protocols.get(protocol)?;
        let analyzer = analyze::for_protocol(protocol);
        let keep = |answer: &&Answer| !successful_only || !analyzer.is_failure(&answer.bytes);
        for key in keys {
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
                let all = candidates.iter().map(|a| a.bytes.clone()).collect();
                return Some((Sampled { key, ..sampled }, all));
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
            return Some(Sampled { bytes: answer.bytes.clone(), key: String::new(), probability: answer.count as f64 / total as f64, generated: false });
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

    #[test]
    fn learns_online_and_reloads() {
        let dir = std::env::temp_dir().join(format!("fakenet-online-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("live.json");
        // An existing pack is kept and added to
        let mut first = Pack::default();
        first.add("smtp", b"EHLO x\r\n", b"250 ok\r\n");
        first.save(&path).unwrap();
        let live = LiveModel::load(std::slice::from_ref(&path)).unwrap();
        let mut rng = Rng::new(3);
        assert!(live.current().answer("raw", b"hello", &mut rng).is_none());

        let learner = Learner::open(&path, "run-1").unwrap();
        assert!(!learner.save().unwrap()); // Nothing added yet
        learner.record("raw", &["text:HELLO".into(), "*".into()], b"welcome back");
        assert!(learner.save().unwrap());
        let saved = Pack::load(&path).unwrap();
        assert_eq!(saved.protocols["smtp"].keys["EHLO"].count, 1);
        assert_eq!(saved.protocols["raw"].keys["text:HELLO"].answers[0].bytes, b"welcome back");
        assert!(saved.sources.contains(&"run-1".to_string()));

        // The responder's model picks the change up
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, std::fs::read(&path).unwrap()).unwrap(); // A fresh modification time
        live.check_now();
        assert_eq!(live.current().answer("raw", b"hello there", &mut rng).unwrap().bytes, b"welcome back");
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn generates_new_http_bodies_and_line_replies() {
        let mut pack = Pack::default();
        for body in ["your client is up to date, check again in one hour", "a new update is ready for your client, download it now", "the update server is busy, check again in a few minutes"] {
            pack.add("http", b"GET /update HTTP/1.1\r\n", &http("200 OK", body));
        }
        for reply in ["250 mail.example greets you\r\n", "250 mail.example is ready for you\r\n"] {
            pack.add("smtp", b"EHLO x\r\n", reply.as_bytes());
        }
        pack.add("http", b"GET /logo.png HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x89PNG");
        let model = Model::new(pack);
        let mut rng = Rng::new(4);
        let meta = serde_json::Value::Null;
        let mut bodies = std::collections::BTreeSet::new();
        for _ in 0..30 {
            let answer = model.generate_event("http", b"GET /update HTTP/1.1\r\n", &meta, &mut rng, true).unwrap();
            assert!(answer.generated);
            let (head, body) = generate::split_http(&answer.bytes).unwrap();
            assert!(String::from_utf8_lossy(head).contains(&format!("Content-Length: {}", body.len())));
            bodies.insert(body.to_vec());
        }
        assert!(bodies.len() > 5, "{} distinct bodies", bodies.len());
        let reply = model.generate_event("smtp", b"EHLO y\r\n", &meta, &mut rng, true).unwrap();
        assert!(reply.bytes.starts_with(b"250 ") && reply.bytes.ends_with(b"\r\n"), "{:?}", String::from_utf8_lossy(&reply.bytes));
        // A binary body is replayed as recorded
        let image = model.generate_event("http", b"GET /logo.png HTTP/1.1\r\n", &meta, &mut rng, true).unwrap();
        assert!(!image.generated && image.bytes.ends_with(b"\x89PNG"));
    }

}
