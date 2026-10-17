//! The exploration loop: propose answers, watch what the sample does next, reward the
//! answers that unlocked new behaviour (or new code), and keep the map.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fakenet_schema::{Event, Protocol};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::coverage::{CoverageEvent, Drcov, FunctionMap};
use crate::hints::Hints;
use crate::rng::Rng;
use crate::templates::{self, Source, Template};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExplorerConfig {
    pub enabled: bool,
    /// Chance that a request the daemon doesn't answer gets an explored answer (the rest
    /// keep the defaults, so the baseline behaviour is still seen)
    pub rate: f64,
    /// For reproducible runs
    pub seed: u64,
    /// How long after an answer the sample's new behaviour is credited to it
    pub window_ms: u64,
    /// Reward per newly reached function (behaviour scores 1 per new kind)
    pub coverage_weight: f64,
    /// Extra template files (see templates/default.toml)
    pub templates: Vec<PathBuf>,
    /// The sample's binaries: strings are extracted as hints
    pub samples: Vec<PathBuf>,
    /// REA output files (tool results, Evidence records or bundles): procedures & strings
    pub rea: Vec<PathBuf>,
    /// A directory a tracer writes coverage to (drcov `*.log`, or `*.jsonl`)
    pub coverage_dir: Option<PathBuf>,
    /// The sample's module name in the coverage (e.g. "bot.exe"), for drcov
    pub module: Option<String>,
    /// The image base REA's addresses use ("0x400000"); drcov offsets are rebased onto it
    pub image_base: Option<String>,
    /// Protocols to explore (empty: all with templates)
    pub protocols: Vec<String>,
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        ExplorerConfig {
            enabled: false,
            rate: 0.8,
            seed: 0x5eed,
            window_ms: 3000,
            coverage_weight: 5.0,
            templates: Vec::new(),
            samples: Vec::new(),
            rea: Vec::new(),
            coverage_dir: None,
            module: None,
            image_base: None,
            protocols: Vec::new(),
        }
    }
}

/// An explored answer for one request
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub response: Vec<u8>,
    pub close: bool,
    pub template: String,
    pub tokens: Vec<String>,
}

#[derive(Default)]
struct ArmStats {
    uses: u64,
    reward: f64,
}

#[derive(Default)]
struct TemplateStats {
    uses: u64,
    reward: f64,
    behaviors: BTreeSet<String>,
    functions: BTreeSet<String>,
    tokens: BTreeMap<String, f64>,
}

struct Pending {
    template: String,
    context: String,
    tokens: Vec<String>,
    at: Instant,
    /// Wall-clock time, to match timestamped coverage
    wall: std::time::SystemTime,
}

struct State {
    rng: Rng,
    hints: Hints,
    learned: Hints,
    seen: BTreeSet<String>,
    first_seen_after: BTreeMap<String, String>,
    arms: HashMap<(String, String), ArmStats>,
    templates: BTreeMap<String, TemplateStats>,
    token_reward: HashMap<String, f64>,
    token_uses: HashMap<String, u64>,
    pending: HashMap<String, VecDeque<Pending>>,
    reached: BTreeSet<String>,
    /// Source address -> the process last seen behind it, so events without process
    /// attribution (often UDP) still count as that sample's
    aliases: HashMap<String, String>,
    proposals: u64,
    observed: u64,
}

pub struct Explorer {
    config: ExplorerConfig,
    templates: Vec<Template>,
    functions: FunctionMap,
    state: Mutex<State>,
}

const MAX_PENDING: usize = 32;
const MAX_BEHAVIORS_PER_TEMPLATE: usize = 200;

impl Explorer {
    /// Loads templates (built-in + configured) and hints (samples, REA files)
    pub fn load(config: ExplorerConfig) -> anyhow::Result<Explorer> {
        let mut templates = templates::parse(templates::DEFAULT_TEMPLATES)?;
        for file in &config.templates {
            let text = std::fs::read_to_string(file).map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            templates.extend(templates::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e:#}", file.display()))?);
        }
        let mut hints = Hints::default();
        let mut sample_digests = BTreeSet::new();
        for sample in &config.samples {
            let data = std::fs::read(sample).map_err(|e| anyhow::anyhow!("reading {}: {e}", sample.display()))?;
            sample_digests.insert(crate::hints::sha256(&data));
            hints.merge(Hints::from_binary(&data));
        }
        let mut rea = Vec::new();
        for file in &config.rea {
            let text = std::fs::read_to_string(file).map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            // A JSON document, or JSON lines (REA's CLI can stream records)
            match serde_json::from_str::<Value>(&text) {
                Ok(value) => rea.push(value),
                Err(_) => rea.extend(text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok())),
            }
        }
        if !rea.is_empty() {
            // Together: the overview's segments classify the other files' strings
            let analysis = Hints::from_rea_all(&rea);
            // Addresses from an analysis of another build map coverage to the wrong functions
            let mismatched: Vec<&String> = analysis.analysed.iter().filter(|d| !sample_digests.is_empty() && !sample_digests.contains(*d)).collect();
            if !mismatched.is_empty() {
                tracing::warn!(
                    "REA analysed a different binary than [explorer] samples (sha256 {:?} vs {:?}): function mapping will be wrong; re-run scripts/rea-hints.sh on this build",
                    mismatched,
                    sample_digests
                );
            }
            hints.merge(analysis);
        }
        Ok(Explorer::new(config, templates, hints))
    }

    pub fn new(config: ExplorerConfig, templates: Vec<Template>, hints: Hints) -> Explorer {
        let functions = FunctionMap::new(hints.functions.clone());
        let state = State {
            rng: Rng::new(config.seed),
            hints,
            learned: Hints::default(),
            seen: BTreeSet::new(),
            first_seen_after: BTreeMap::new(),
            arms: HashMap::new(),
            templates: BTreeMap::new(),
            token_reward: HashMap::new(),
            token_uses: HashMap::new(),
            pending: HashMap::new(),
            reached: BTreeSet::new(),
            aliases: HashMap::new(),
            proposals: 0,
            observed: 0,
        };
        Explorer { config, templates, functions, state: Mutex::new(state) }
    }

    pub fn config(&self) -> &ExplorerConfig {
        &self.config
    }

    /// Who an event comes from: its process if known (remembered for its address), else
    /// the process last seen at its address, else the address
    fn actor(state: &mut State, event: &Event) -> String {
        let ip = format!("ip:{}", event.src.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&event.src));
        match &event.process {
            Some(process) => {
                let actor = format!("pid:{}", process.pid);
                if state.aliases.len() < 65536 {
                    state.aliases.insert(ip, actor.clone());
                }
                actor
            }
            None => state.aliases.get(&ip).cloned().unwrap_or(ip),
        }
    }

    /// Feeds one event: new kinds of behaviour reward the recent answers to the same actor
    pub fn observe(&self, event: &Event) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let actor = Self::actor(&mut state, event);
        state.observed += 1;
        state.learned.learn_from_traffic(&event.payload, &event.meta);
        for signature in signatures(event) {
            if !state.seen.insert(signature.clone()) {
                continue;
            }
            self.credit(&mut state, &actor, now, 1.0, |stats| {
                if stats.behaviors.len() < MAX_BEHAVIORS_PER_TEMPLATE {
                    stats.behaviors.insert(signature.clone());
                }
            }, Some(&signature));
        }
    }

    /// Credits `reward` to the actor's recent answers (the latest fully, older ones less).
    /// With `when` (the time the behaviour happened), only answers given before it count.
    fn credit(&self, state: &mut State, actor: &str, now: Instant, reward: f64, record: impl FnMut(&mut TemplateStats), signature: Option<&str>) {
        self.credit_at(state, actor, now, None, reward, record, signature)
    }

    #[allow(clippy::too_many_arguments)]
    fn credit_at(&self, state: &mut State, actor: &str, now: Instant, when: Option<std::time::SystemTime>, reward: f64, mut record: impl FnMut(&mut TemplateStats), signature: Option<&str>) {
        let window = Duration::from_millis(self.config.window_ms);
        let recent: Vec<(String, String, Vec<String>)> = state
            .pending
            .get(actor)
            .map(|queue| {
                queue
                    .iter()
                    .rev()
                    .filter(|p| match when {
                        Some(when) => p.wall <= when && when.duration_since(p.wall).unwrap_or_default() <= window,
                        None => now.duration_since(p.at) <= window,
                    })
                    .map(|p| (p.template.clone(), p.context.clone(), p.tokens.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if let (Some(signature), Some((template, _, _))) = (signature, recent.first()) {
            state.first_seen_after.insert(signature.to_string(), template.clone());
        }
        for (rank, (template, context, tokens)) in recent.into_iter().enumerate() {
            let share = reward * 0.5f64.powi(rank as i32);
            state.arms.entry((context, template.clone())).or_default().reward += share;
            let stats = state.templates.entry(template).or_default();
            stats.reward += share;
            // Learning spreads credit over recent answers; the map names only the most
            // likely cause: the latest answer before the behaviour
            if rank == 0 {
                record(stats);
            }
            for token in tokens {
                *stats.tokens.entry(token.clone()).or_default() += share;
                *state.token_reward.entry(token).or_default() += share;
            }
        }
    }

    /// An explored answer for a request the daemon left to the default, or None (not
    /// explored this time, or no template applies)
    pub fn propose(&self, event: &Event) -> Option<Proposal> {
        let protocol = event.protocol.name();
        if !self.config.protocols.is_empty() && !self.config.protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol)) {
            return None;
        }
        let applicable: Vec<&Template> = self.templates.iter().filter(|t| t.applies(protocol, &event.meta)).collect();
        if applicable.is_empty() {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.rng.unit() >= self.config.rate {
            return None;
        }
        let context = context(event);
        let template = select(&mut state, &context, &applicable);
        let mut source = Filler { state: &mut state, event, tokens: Vec::new() };
        let response = match templates::render_with(&template.body, &mut source) {
            Ok(response) => response,
            Err(e) => {
                tracing::warn!("explorer template {}: {e:#}", template.name);
                return None;
            }
        };
        let tokens = std::mem::take(&mut source.tokens);
        state.proposals += 1;
        state.arms.entry((context.clone(), template.name.clone())).or_default().uses += 1;
        state.templates.entry(template.name.clone()).or_default().uses += 1;
        let actor = Self::actor(&mut state, event);
        let queue = state.pending.entry(actor).or_default();
        queue.push_back(Pending { template: template.name.clone(), context, tokens: tokens.clone(), at: Instant::now(), wall: std::time::SystemTime::now() });
        while queue.len() > MAX_PENDING {
            queue.pop_front();
        }
        Some(Proposal { response, close: template.close, template: template.name.clone(), tokens })
    }

    /// Newly reached functions (from coverage) reward the actor's recent answers
    pub fn reached(&self, pid: Option<u32>, functions: BTreeSet<String>) -> usize {
        self.reached_at(pid, functions, None)
    }

    /// Like `reached`, for code that ran at `when`: the answers just before it get the credit
    pub fn reached_at(&self, pid: Option<u32>, functions: BTreeSet<String>, when: Option<std::time::SystemTime>) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let new: Vec<String> = functions.into_iter().filter(|f| !state.reached.contains(f)).collect();
        if new.is_empty() {
            return 0;
        }
        state.reached.extend(new.iter().cloned());
        let actor = match pid {
            Some(pid) => format!("pid:{pid}"),
            // Unknown process: the most recently answered actor
            None => state.pending.iter().max_by_key(|(_, q)| q.back().map(|p| p.at)).map(|(a, _)| a.clone()).unwrap_or_default(),
        };
        let count = new.len();
        let reward = self.config.coverage_weight * count as f64;
        self.credit_at(&mut state, &actor, Instant::now(), when, reward, |stats| stats.functions.extend(new.iter().cloned()), None);
        count
    }

    /// A drcov file from the tracer
    pub fn ingest_drcov(&self, data: &[u8], file_name: &str) -> anyhow::Result<usize> {
        let coverage = Drcov::parse(data, file_name)?;
        let module = self.config.module.clone().unwrap_or_default();
        let base = self.config.image_base.as_deref().and_then(crate::coverage::parse_hex).unwrap_or(0x400000);
        let functions = self.functions.functions_for(coverage.addresses(&module, base));
        Ok(self.reached(coverage.pid, functions))
    }

    /// One JSON-lines coverage record
    pub fn ingest_coverage_line(&self, line: &str) -> anyhow::Result<usize> {
        let event: CoverageEvent = serde_json::from_str(line)?;
        let mut functions: BTreeSet<String> = event.functions.into_iter().collect();
        functions.extend(self.functions.functions_for(event.addresses.iter().filter_map(|a| crate::coverage::parse_hex(a))));
        let when = event.time.map(|ms| std::time::UNIX_EPOCH + Duration::from_secs_f64(ms / 1000.0));
        Ok(self.reached_at(event.pid, functions, when))
    }

    /// The map: what each template unlocked (behaviour & functions), the best tokens, and
    /// the known functions never reached
    pub fn map(&self) -> Value {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut templates: Vec<Value> = state
            .templates
            .iter()
            .map(|(name, stats)| {
                let mut tokens: Vec<(&String, &f64)> = stats.tokens.iter().collect();
                tokens.sort_by(|a, b| b.1.total_cmp(a.1));
                json!({
                    "template": name, "uses": stats.uses, "reward": round(stats.reward),
                    "behaviors": stats.behaviors, "functions": stats.functions,
                    "best_tokens": tokens.iter().take(10).map(|(t, r)| json!({ "token": t, "reward": round(**r) })).collect::<Vec<_>>(),
                })
            })
            .collect();
        templates.sort_by(|a, b| b["reward"].as_f64().unwrap_or(0.0).total_cmp(&a["reward"].as_f64().unwrap_or(0.0)));
        let mut tokens: Vec<(&String, &f64)> = state.token_reward.iter().collect();
        tokens.sort_by(|a, b| b.1.total_cmp(a.1).then(a.0.cmp(b.0)));
        let known: BTreeSet<&str> = self.functions.names().collect();
        let unreached: Vec<&&str> = known.iter().filter(|f| !state.reached.contains(**f)).take(1000).collect();
        json!({
            "proposals": state.proposals,
            "events_observed": state.observed,
            "behaviors": state.seen.len(),
            "templates": templates,
            "tokens": tokens.iter().take(50).map(|(t, r)| json!({ "token": t, "reward": round(**r) })).collect::<Vec<_>>(),
            "first_seen_after": state.first_seen_after,
            "functions": { "known": known.len(), "reached": state.reached, "unreached": unreached },
            "hints": {
                "rea_analysed": state.hints.analysed,
                "commands": state.hints.commands.len(), "keys": state.hints.keys.len(), "urls": state.hints.urls.len(),
                "domains": state.hints.domains.len(), "functions": state.hints.functions.len(),
                "learned_tokens": state.learned.commands.len() + state.learned.keys.len(),
            },
        })
    }
}

fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// UCB1 over the applicable templates in this request context; untried ones first
fn select<'a>(state: &mut State, context: &str, applicable: &[&'a Template]) -> &'a Template {
    let untried: Vec<&&Template> = applicable.iter().filter(|t| !state.arms.contains_key(&(context.to_string(), t.name.clone()))).collect();
    if !untried.is_empty() {
        let index = state.rng.below(untried.len());
        return untried[index];
    }
    let total: u64 = applicable.iter().filter_map(|t| state.arms.get(&(context.to_string(), t.name.clone()))).map(|a| a.uses).sum();
    let ln_total = (total.max(1) as f64).ln();
    let mut best = (f64::MIN, applicable[0]);
    for template in applicable {
        let arm = &state.arms[&(context.to_string(), template.name.clone())];
        let uses = arm.uses.max(1) as f64;
        // Small noise breaks ties between equal arms
        let score = arm.reward / uses + 1.4 * (ln_total / uses).sqrt() + state.rng.unit() * 1e-6;
        if score > best.0 {
            best = (score, template);
        }
    }
    best.1
}

/// The bandit's context: the same kind of request is a separate learning problem
fn context(event: &Event) -> String {
    let meta = &event.meta;
    let field = |name: &str| meta.get(name).and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    match event.protocol {
        Protocol::Http => format!("http {} {}", field("method"), pattern(field("path").split('?').next().unwrap_or(""))),
        Protocol::Dns => format!("dns {}", field("qtype")),
        Protocol::Raw => format!("raw {:?} {}", event.transport, event.dport),
        _ => format!("{} {}", event.protocol.name(), field("command")),
    }
}

/// Kinds of behaviour an event shows (new ones are what exploration is rewarded for)
pub fn signatures(event: &Event) -> Vec<String> {
    let meta = &event.meta;
    let field = |name: &str| meta.get(name).and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    let mut out = vec![format!("protocol {} {:?}", event.protocol.name(), event.transport), format!("destination {}", event.dst)];
    out.push(match event.protocol {
        Protocol::Http => {
            let path = field("path");
            let (route, query) = path.split_once('?').unwrap_or((&path, ""));
            let mut keys: Vec<&str> = query.split('&').filter_map(|kv| kv.split('=').next()).filter(|k| !k.is_empty()).collect();
            keys.sort();
            format!("http {} {}{} {}", field("method"), field("host"), pattern(route), keys.join("&"))
        }
        Protocol::Dns => format!("dns {} {}", field("qtype"), pattern(&field("qname"))),
        Protocol::Raw | Protocol::Echo | Protocol::Discard => format!("{} {:?} {} {}", event.protocol.name(), event.transport, event.dport, shape(&event.payload)),
        _ => format!("{} {}", event.protocol.name(), field("command")),
    });
    out
}

/// Digits and long random-looking runs abstracted, so ids & nonces don't count as new
fn pattern(text: &str) -> String {
    let mut out = String::new();
    for part in text.split_inclusive(['/', '.', '-', '_', '=', '&']) {
        let (word, separator) = match part.char_indices().last() {
            Some((i, c)) if "/.-_=&".contains(c) => (&part[..i], &part[i..]),
            _ => (part, ""),
        };
        let digits = word.chars().filter(char::is_ascii_digit).count();
        if word.is_empty() {
        } else if digits == word.len() {
            out.push('#');
        } else if word.len() >= 16 && (digits >= 4 || word.chars().all(|c| c.is_ascii_hexdigit())) {
            out.push('*');
        } else {
            out.push_str(&word.chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).collect::<String>());
        }
        out.push_str(separator);
    }
    out
}

/// A payload's rough shape: its size class and how it starts
fn shape(payload: &[u8]) -> String {
    let size = match payload.len() {
        0 => "empty",
        1..=16 => "tiny",
        17..=256 => "small",
        257..=4096 => "medium",
        _ => "large",
    };
    let head = &payload[..payload.len().min(6)];
    let start = if !head.is_empty() && head.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        pattern(&String::from_utf8_lossy(head).to_ascii_lowercase())
    } else {
        head.iter().take(2).map(|b| format!("{b:02x}")).collect()
    };
    format!("{size}:{start}")
}

/// Fills a template's slots for one request
struct Filler<'a> {
    state: &'a mut State,
    event: &'a Event,
    tokens: Vec<String>,
}

impl Filler<'_> {
    /// A token from `pools`, weighted by how much it has unlocked so far
    fn token(&mut self, pools: &[&str]) -> Option<String> {
        let mut candidates: Vec<String> = Vec::new();
        for pool in pools {
            let set = |hints: &Hints| -> Vec<String> {
                match *pool {
                    "commands" => hints.commands.iter().cloned().collect(),
                    "keys" => hints.keys.iter().cloned().collect(),
                    "urls" => hints.urls.iter().cloned().collect(),
                    "domains" => hints.domains.iter().cloned().collect(),
                    "paths" => hints.paths.iter().cloned().collect(),
                    "strings" => hints.strings.iter().cloned().collect(),
                    _ => Vec::new(),
                }
            };
            candidates.extend(set(&self.state.hints));
            candidates.extend(set(&self.state.learned));
        }
        candidates.sort();
        candidates.dedup();
        if candidates.is_empty() {
            return None;
        }
        // Reward per use, so a token that stops finding anything new fades; untried tokens
        // get a bonus, so every hint gets a chance
        let weights: Vec<f64> = candidates
            .iter()
            .map(|c| {
                let base = match self.state.token_uses.get(c).copied().unwrap_or(0) {
                    0 => 3.0,
                    uses => 1.0 + 4.0 * self.state.token_reward.get(c).copied().unwrap_or(0.0) / uses as f64,
                };
                // The sample's own words (its function names) are the best bets
                if self.state.hints.priority.contains(c) { base * 8.0 } else { base }
            })
            .collect();
        let total: f64 = weights.iter().sum();
        let mut target = self.state.rng.unit() * total;
        for (candidate, weight) in candidates.iter().zip(weights) {
            if target < weight {
                return Some(candidate.clone());
            }
            target -= weight;
        }
        candidates.last().cloned()
    }

    fn remember(&mut self, token: String) -> Vec<u8> {
        *self.state.token_uses.entry(token.clone()).or_default() += 1;
        self.tokens.push(token.clone());
        token.into_bytes()
    }
}

/// Fallbacks when the sample gave no hints of a kind
const DEFAULT_COMMANDS: &[&str] = &["run", "exec", "download", "upload", "update", "sleep", "kill", "shell", "info", "scan", "ok", "1"];
const DEFAULT_KEYS: &[&str] = &["cmd", "command", "task", "id", "url", "data", "action", "status"];
const INTERESTING_INTS: &[&str] = &["0", "1", "-1", "2", "7", "60", "255", "256", "1024", "3600", "65535", "65536", "2147483647", "4294967295"];
/// Time shifts (seconds) that trip time-bombed code: a day/week/year either way, 2038
const OFFSETS: &[&str] = &["-31536000", "-86400", "+3600", "+86400", "+604800", "+2592000", "+31536000", "+63072000", "+378691200"];

impl Source for Filler<'_> {
    fn value(&mut self, name: &str) -> Option<Vec<u8>> {
        let pick = |filler: &mut Self, pools: &[&str], fallback: &[&str]| -> Vec<u8> {
            let token = filler.token(pools).unwrap_or_else(|| fallback[filler.state.rng.below(fallback.len())].to_string());
            filler.remember(token)
        };
        Some(match name {
            "command" => pick(self, &["commands"], DEFAULT_COMMANDS),
            "key" => pick(self, &["keys"], DEFAULT_KEYS),
            "token" => pick(self, &["commands", "keys", "strings"], DEFAULT_COMMANDS),
            "string" => pick(self, &["strings", "commands"], DEFAULT_COMMANDS),
            "url" => match self.token(&["urls"]) {
                Some(url) => self.remember(url),
                None => {
                    let domain = self.token(&["domains"]).unwrap_or_else(|| "update.fakenet.local".into());
                    let path = self.token(&["paths"]).unwrap_or_else(|| "/payload.bin".into());
                    format!("http://{domain}{path}").into_bytes()
                }
            },
            "domain" => pick(self, &["domains"], &["c2.fakenet.local"]),
            "path" => pick(self, &["paths"], &["/gate.php"]),
            "int" => INTERESTING_INTS[self.state.rng.below(INTERESTING_INTS.len())].as_bytes().to_vec(),
            "offset" => {
                let offset = OFFSETS[self.state.rng.below(OFFSETS.len())];
                self.remember(offset.to_string())
            }
            "ip" => format!("10.{}.{}.{}", self.state.rng.below(256), self.state.rng.below(256), 1 + self.state.rng.below(254)).into_bytes(),
            "port" => (1024 + self.state.rng.below(64511)).to_string().into_bytes(),
            "random" => (0..8).map(|_| b"abcdefghijklmnopqrstuvwxyz0123456789"[self.state.rng.below(36)]).collect(),
            "mirror" => self.event.payload.clone(),
            "mutate" => templates::mutate(&self.event.payload, &mut self.state.rng),
            "mz" => templates::mz_stub(),
            "session" => self.event.session_id.clone().into_bytes(),
            "param" => self.event.meta.get("params").and_then(|p| p.get(0)).and_then(Value::as_str).unwrap_or("#c2").as_bytes().to_vec(),
            other => {
                let field = other.strip_prefix("meta:")?;
                match self.event.meta.get(field) {
                    Some(Value::String(text)) => text.clone().into_bytes(),
                    Some(value) => value.to_string().into_bytes(),
                    None => Vec::new(),
                }
            }
        })
    }
}
