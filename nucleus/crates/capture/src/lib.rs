//! Everything the nucleus records, in its output directory:
//!
//! - `events.jsonl`: one JSON object per line (events, decisions, fallbacks, ...)
//! - `traffic.pcap`: the conversations the listeners saw, as packets (see `pcap`)
//! - `files/`: HTTP POST bodies, uploads and other payloads worth keeping
//!
//! Writes are flushed immediately: analysis VMs are often reverted abruptly.
//!
//! With `Limits`, the event log and pcap rotate by size (`events.1.jsonl` is the newest
//! rotated log, up to `events.<keep>.jsonl`), and `files/` has a total budget beyond which
//! new files are refused rather than old evidence deleted.

pub mod pcap;
pub mod indicators;
pub mod report;
pub mod yara;

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde_json::{Map, Value};

/// Size limits; 0 means unlimited
#[derive(Debug, Clone, Copy, Default)]
pub struct Limits {
    pub max_events_bytes: u64,
    pub max_pcap_bytes: u64,
    pub max_files_bytes: u64,
    /// Rotated event logs / pcaps kept (older ones are deleted)
    pub keep: usize,
}

struct EventLog {
    writer: BufWriter<File>,
    bytes: u64,
}

struct Pcap {
    writer: pcap::PcapWriter,
    bytes: u64,
}

/// Work for the writer thread
enum Job {
    Record(String),
    /// Packets for traffic.pcap, stamped when they were made
    Packets(Vec<Vec<u8>>, std::time::Duration),
    Wire(Vec<u8>, std::time::Duration),
    /// Answered once everything queued before it is written and flushed
    Flush(std::sync::mpsc::Sender<()>),
}

/// Jobs queued before senders wait (back-pressure only when the disk can't keep up)
const QUEUE: usize = 65_536;
/// How often written data is synced to disk (an abrupt VM revert loses at most this much)
const SYNC_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// The thread that owns the event log and the pcaps: sessions never wait on disk I/O or on
/// each other's writes, only on a bounded queue
struct Writer {
    dir: PathBuf,
    limits: Limits,
    events: EventLog,
    pcap: Pcap,
    wire: Option<Pcap>,
    last_sync: std::time::Instant,
    dirty: bool,
}

impl Writer {
    fn run(mut self, jobs: std::sync::mpsc::Receiver<Job>) {
        while let Ok(job) = jobs.recv() {
            let mut waiting = Vec::new();
            self.handle(job, &mut waiting);
            // Batch whatever else is queued, then flush once
            while let Ok(job) = jobs.try_recv() {
                self.handle(job, &mut waiting);
            }
            self.flush();
            for waiter in waiting {
                let _ = waiter.send(());
            }
        }
        self.flush();
        self.sync();
    }

    fn handle(&mut self, job: Job, waiting: &mut Vec<std::sync::mpsc::Sender<()>>) {
        self.dirty = true;
        match job {
            Job::Record(line) => self.record(&line),
            Job::Packets(packets, time) => Self::write_rotating(&self.dir, "traffic.pcap", &self.limits, &mut self.pcap, packets, time),
            Job::Wire(packet, time) => self.wire_packet(packet, time),
            Job::Flush(waiter) => waiting.push(waiter),
        }
    }

    fn record(&mut self, line: &str) {
        let events = &mut self.events;
        if self.limits.max_events_bytes > 0 && events.bytes + line.len() as u64 + 1 > self.limits.max_events_bytes && events.bytes > 0 {
            let _ = events.writer.flush();
            rotate(&self.dir, "events.jsonl", self.limits.keep);
            match OpenOptions::new().create(true).append(true).open(self.dir.join("events.jsonl")) {
                Ok(file) => *events = EventLog { writer: BufWriter::new(file), bytes: 0 },
                Err(e) => tracing::warn!("Could not rotate the event log: {e}"),
            }
        }
        // Best effort: a full disk must not take the fake services down
        if writeln!(events.writer, "{line}").is_err() {
            tracing::warn!("Could not write to the event log");
        }
        events.bytes += line.len() as u64 + 1;
    }

    fn wire_packet(&mut self, packet: Vec<u8>, time: std::time::Duration) {
        if self.wire.is_none() {
            if self.dir.join("wire.pcap").exists() {
                // Never truncate an earlier capture, whatever `keep` says
                rotate(&self.dir, "wire.pcap", self.limits.keep.max(1));
            }
            match pcap::PcapWriter::create(&self.dir.join("wire.pcap")) {
                Ok(writer) => self.wire = Some(Pcap { writer, bytes: 24 }),
                Err(e) => {
                    tracing::warn!("Could not create wire.pcap: {e}");
                    return;
                }
            }
        }
        if let Some(pcap) = self.wire.as_mut() {
            Self::write_rotating(&self.dir, "wire.pcap", &self.limits, pcap, vec![packet], time);
        }
    }

    fn write_rotating(dir: &Path, name: &str, limits: &Limits, pcap: &mut Pcap, packets: Vec<Vec<u8>>, time: std::time::Duration) {
        for packet in packets {
            let size = packet.len() as u64 + 16;
            if limits.max_pcap_bytes > 0 && pcap.bytes + size > limits.max_pcap_bytes {
                let _ = pcap.writer.flush();
                rotate(dir, name, limits.keep);
                match pcap::PcapWriter::create(&dir.join(name)) {
                    Ok(writer) => *pcap = Pcap { writer, bytes: 24 },
                    Err(e) => {
                        tracing::warn!("Could not rotate {name}: {e}");
                        return;
                    }
                }
            }
            if pcap.writer.write_at(&packet, time).is_err() {
                tracing::warn!("Could not write to {name}");
                return;
            }
            pcap.bytes += size;
        }
    }

    fn flush(&mut self) {
        let _ = self.events.writer.flush();
        let _ = self.pcap.writer.flush();
        if let Some(wire) = self.wire.as_mut() {
            let _ = wire.writer.flush();
        }
        if self.dirty && self.last_sync.elapsed() >= SYNC_EVERY {
            self.sync();
        }
    }

    fn sync(&mut self) {
        let _ = self.events.writer.get_ref().sync_data();
        let _ = self.pcap.writer.sync();
        if let Some(wire) = self.wire.as_mut() {
            let _ = wire.writer.sync();
        }
        self.last_sync = std::time::Instant::now();
        self.dirty = false;
    }
}

/// Cuts a record's base64 `payload` to `max` bytes, noting `payload_bytes` and
/// `payload_truncated`
fn trim_payload(record: &mut Value, max: usize) {
    let Some(encoded) = record["payload"].as_str() else { return };
    if encoded.len() <= max.div_ceil(3) * 4 {
        return;
    }
    let Ok(bytes) = fakenet_schema::decode_base64(encoded) else { return };
    record["payload_bytes"] = Value::from(bytes.len());
    record["payload_truncated"] = Value::Bool(true);
    record["payload"] = Value::String(fakenet_schema::encode_base64(&bytes[..max.min(bytes.len())]));
}

fn since_epoch() -> std::time::Duration {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}

/// How many recent records stay in memory (for the live dashboard)
const RECENT: usize = 5000;
/// Payload bytes kept per record in that ring (the event log has them all)
const RECENT_PAYLOAD: usize = 4096;

pub struct Capture {
    dir: PathBuf,
    limits: Limits,
    /// To the writer thread (None once dropped)
    jobs: Option<std::sync::mpsc::SyncSender<Job>>,
    writer: Option<std::thread::JoinHandle<()>>,
    /// (sequence number, record), newest last
    recent: Mutex<std::collections::VecDeque<(u64, Value)>>,
    sequence: AtomicU64,
    file_counter: AtomicU64,
    files_bytes: AtomicU64,
    /// YARA scanning of saved files, when rules are configured
    yara: Mutex<Option<yara::Scanner>>,
}

/// "events.jsonl" -> "events.3.jsonl"
fn numbered(dir: &Path, name: &str, n: usize) -> PathBuf {
    let (stem, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    dir.join(format!("{stem}.{n}.{extension}"))
}

/// `events` and its rotated siblings (`events.N.jsonl`, oldest first), for reading a whole
/// capture from the path of its live log
pub fn with_rotations(events: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (events.parent(), events.file_name().and_then(|n| n.to_str())) else {
        return vec![events.to_path_buf()];
    };
    let mut rotated: Vec<(usize, PathBuf)> = (1..)
        .map(|n| (n, numbered(dir, name, n)))
        .take_while(|(_, path)| path.exists())
        .collect();
    rotated.sort_by(|a, b| b.0.cmp(&a.0));
    let mut files: Vec<PathBuf> = rotated.into_iter().map(|(_, path)| path).collect();
    files.push(events.to_path_buf());
    files
}

/// Shifts name -> name.1 -> name.2 ..., dropping what falls past `keep`
fn rotate(dir: &Path, name: &str, keep: usize) {
    let _ = std::fs::remove_file(numbered(dir, name, keep.max(1)));
    for n in (1..keep.max(1)).rev() {
        let _ = std::fs::rename(numbered(dir, name, n), numbered(dir, name, n + 1));
    }
    if keep == 0 {
        let _ = std::fs::remove_file(dir.join(name));
    } else {
        let _ = std::fs::rename(dir.join(name), numbered(dir, name, 1));
    }
}

/// What a start writes at the top of a capture folder (ca.pem is rewritten each start)
fn is_run_output(name: &str) -> bool {
    let rotated = |stem: &str, extension: &str| {
        name.strip_prefix(stem).and_then(|r| r.strip_suffix(extension)).is_some_and(|middle| middle.is_empty() || middle.strip_prefix('.').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
    };
    rotated("events", ".jsonl")
        || rotated("traffic", ".pcap")
        || rotated("wire", ".pcap")
        || ["files", "report.html", "indicators.csv", "indicators.stix.json", "indicators.misp.json", "tls-keys.log", "explorer-map.json"].contains(&name)
}

/// Moves a previous start's outputs into `previous/<UTC time>/`, so this start neither
/// overwrites its saved files and pcaps nor mixes its records into this run's report.
/// Returns where they went (None: nothing recorded yet)
pub fn archive_previous(dir: &Path) -> Result<Option<PathBuf>> {
    // Past an empty log, or a pcap holding only its 24-byte header
    let recorded = |name: &str, empty: u64| std::fs::metadata(dir.join(name)).map(|m| m.len() > empty).unwrap_or(false);
    let files_saved = std::fs::read_dir(dir.join("files")).map(|mut e| e.next().is_some()).unwrap_or(false);
    if !recorded("events.jsonl", 0) && !recorded("traffic.pcap", 24) && !files_saved {
        return Ok(None);
    }
    let format = time::macros::format_description!("[year][month][day]-[hour][minute][second]");
    let stamp = time::OffsetDateTime::now_utc().format(&format).unwrap_or_default();
    let mut target = dir.join("previous").join(&stamp);
    let mut n = 1;
    while target.exists() {
        n += 1;
        target = dir.join("previous").join(format!("{stamp}-{n}"));
    }
    std::fs::create_dir_all(&target).with_context(|| format!("creating {}", target.display()))?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(is_run_output) {
            std::fs::rename(entry.path(), target.join(&name)).with_context(|| format!("moving {} to {}", entry.path().display(), target.display()))?;
        }
    }
    Ok(Some(target))
}

impl Capture {
    pub fn open(dir: &Path) -> Result<Arc<Capture>> {
        Capture::open_with(dir, Limits::default())
    }

    pub fn open_with(dir: &Path, limits: Limits) -> Result<Arc<Capture>> {
        if let Some(previous) = archive_previous(dir)? {
            tracing::info!("The previous run's capture moved to {}", previous.display());
        }
        std::fs::create_dir_all(dir.join("files")).with_context(|| format!("creating {}", dir.display()))?;
        let events = OpenOptions::new().create(true).append(true).open(dir.join("events.jsonl"))?;
        let bytes = events.metadata().map(|m| m.len()).unwrap_or(0);
        let files_bytes = std::fs::read_dir(dir.join("files"))
            .map(|entries| entries.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum())
            .unwrap_or(0);
        let pcap = pcap::PcapWriter::create(&dir.join("traffic.pcap"))?;
        let writer = Writer {
            dir: dir.to_path_buf(),
            limits,
            events: EventLog { writer: BufWriter::with_capacity(64 * 1024, events), bytes },
            pcap: Pcap { writer: pcap, bytes: 24 },
            wire: None,
            last_sync: std::time::Instant::now(),
            dirty: false,
        };
        let (jobs, receiver) = std::sync::mpsc::sync_channel(QUEUE);
        let writer = std::thread::Builder::new().name("capture-writer".into()).spawn(move || writer.run(receiver))?;
        Ok(Arc::new(Capture {
            dir: dir.to_path_buf(),
            limits,
            jobs: Some(jobs),
            writer: Some(writer),
            recent: Mutex::new(std::collections::VecDeque::with_capacity(RECENT)),
            sequence: AtomicU64::new(0),
            file_counter: AtomicU64::new(0),
            files_bytes: AtomicU64::new(files_bytes),
            yara: Mutex::new(None),
        }))
    }

    /// Records after sequence number `after` (at most `limit`, oldest first), and the latest
    /// sequence number
    pub fn recent(&self, after: u64, limit: usize) -> (Vec<(u64, Value)>, u64) {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        let latest = recent.back().map(|(s, _)| *s).unwrap_or(0);
        let records = recent.iter().filter(|(s, _)| *s > after).take(limit).cloned().collect();
        (records, latest)
    }

    /// Waits until everything logged so far is written and flushed
    pub fn flush(&self) {
        let (done, wait) = std::sync::mpsc::channel();
        if self.send(Job::Flush(done)) {
            let _ = wait.recv();
        }
    }

    fn send(&self, job: Job) -> bool {
        self.jobs.as_ref().is_some_and(|jobs| jobs.send(job).is_ok())
    }

    /// The event logs, oldest first (rotated ones, then the current one), flushed
    pub fn event_files(&self) -> Vec<PathBuf> {
        self.flush();
        let mut files: Vec<PathBuf> = (1..=self.limits.keep).rev().map(|n| numbered(&self.dir, "events.jsonl", n)).filter(|p| p.exists()).collect();
        files.push(self.dir.join("events.jsonl"));
        files
    }

    /// Scans every file saved from now on with these YARA rules (files or folders of
    /// *.yar/*.yara), logging `yara_match` records; fails if the rules don't compile
    pub fn enable_yara(self: &Arc<Self>, rules: &[PathBuf], yara: &str, yarac: &str) -> Result<()> {
        let scanner = yara::Scanner::start(self, rules, yara, yarac)?;
        *self.yara.lock().unwrap_or_else(|e| e.into_inner()) = Some(scanner);
        Ok(())
    }

    /// Waits for the queued YARA scans (call before writing the report)
    pub fn finish_scans(&self) {
        let scanner = self.yara.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(scanner) = scanner {
            scanner.finish(yara::FINISH_LIMIT);
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Appends one record: `{"timestamp": ..., "kind": kind, ...fields}`
    pub fn log(&self, kind: &str, fields: Value) {
        let mut record = Map::new();
        record.insert("timestamp".into(), Value::String(fakenet_schema::now_rfc3339()));
        record.insert("kind".into(), Value::String(kind.into()));
        if let Value::Object(fields) = fields {
            record.extend(fields);
        }
        let mut record = Value::Object(record);
        let line = record.to_string();
        trim_payload(&mut record, RECENT_PAYLOAD);
        {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
            if recent.len() == RECENT {
                recent.pop_front();
            }
            recent.push_back((sequence, record));
        }
        self.send(Job::Record(line));
    }

    /// Saves a payload under files/, named from a prefix and a sanitized client-supplied name
    /// Fails when the files budget would be exceeded (existing evidence is never deleted)
    pub fn save_file(&self, prefix: &str, name: &str, data: &[u8]) -> Result<PathBuf> {
        let budget = self.limits.max_files_bytes;
        let used = self.files_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        if budget > 0 && used + data.len() as u64 > budget {
            self.files_bytes.fetch_sub(data.len() as u64, Ordering::Relaxed);
            anyhow::bail!("files budget of {budget} bytes reached; not saved");
        }
        let safe: String = name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' })
            .take(100)
            .collect();
        // create_new: never overwrite a saved payload, whoever wrote it
        let path = loop {
            let n = self.file_counter.fetch_add(1, Ordering::Relaxed);
            let path = self.dir.join("files").join(format!("{prefix}_{n:06}_{}", if safe.is_empty() { "data" } else { &safe }));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(data)?;
                    break path;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        };
        if let Some(scanner) = self.yara.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            scanner.queue(path.clone());
        }
        Ok(path)
    }

    /// Starts recording a TCP conversation into the pcap (writes its handshake)
    pub fn tcp_flow(self: &Arc<Self>, client: SocketAddr, server: SocketAddr) -> TcpFlow {
        let mut flow = pcap::TcpConversation::new(client, server);
        self.write_packets(flow.open());
        TcpFlow { capture: self.clone(), flow: Mutex::new(flow) }
    }

    pub fn udp_datagram(&self, src: SocketAddr, dst: SocketAddr, data: &[u8]) {
        self.write_packets(vec![pcap::udp_packet(src, dst, data)]);
    }

    /// Records one real IP packet into wire.pcap (created on first use, rotated like
    /// traffic.pcap)
    pub fn wire_packet(&self, packet: &[u8]) {
        self.send(Job::Wire(packet.to_vec(), since_epoch()));
    }

    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        if !packets.is_empty() {
            self.send(Job::Packets(packets, since_epoch()));
        }
    }
}

impl Drop for Capture {
    /// Lets the writer finish the queue, flush and sync
    fn drop(&mut self) {
        drop(self.jobs.take());
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// One TCP conversation in the pcap
pub struct TcpFlow {
    capture: Arc<Capture>,
    flow: Mutex<pcap::TcpConversation>,
}

impl TcpFlow {
    pub fn client_data(&self, data: &[u8]) {
        let packets = self.flow.lock().unwrap_or_else(|e| e.into_inner()).client_data(data);
        self.capture.write_packets(packets);
    }

    pub fn server_data(&self, data: &[u8]) {
        let packets = self.flow.lock().unwrap_or_else(|e| e.into_inner()).server_data(data);
        self.capture.write_packets(packets);
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        let packets = self.flow.lock().unwrap_or_else(|e| e.into_inner()).close();
        self.capture.write_packets(packets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_logs_and_budgets_files() {
        let dir = std::env::temp_dir().join(format!("fakenet-capture-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let capture = Capture::open_with(&dir, Limits { max_events_bytes: 300, max_pcap_bytes: 600, max_files_bytes: 10, keep: 2 }).unwrap();
        for i in 0..20 {
            capture.log("test", serde_json::json!({ "i": i, "padding": "x".repeat(40) }));
        }
        let files = capture.event_files();
        assert_eq!(files.len(), 3, "{files:?}"); // events.2, events.1, events
        assert!(std::fs::metadata(&files[2]).unwrap().len() <= 300);
        assert!(std::fs::read_to_string(&files[2]).unwrap().contains("\"i\":19"));
        assert!(!dir.join("events.3.jsonl").exists());

        let (a, b) = ("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap());
        for _ in 0..10 {
            capture.udp_datagram(a, b, &[0u8; 100]);
        }
        capture.flush();
        assert!(dir.join("traffic.1.pcap").exists());
        assert!(std::fs::metadata(dir.join("traffic.pcap")).unwrap().len() <= 600);

        let (records, latest) = capture.recent(15, 100);
        assert_eq!((records.len(), latest), (5, 20));
        assert_eq!(records[0].1["i"], 15);
        assert!(capture.save_file("t", "a", b"12345").is_ok());
        assert!(capture.save_file("t", "b", b"123456").is_err()); // Over the 10-byte budget
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_start_archives_the_first_run() {
        let dir = std::env::temp_dir().join(format!("fakenet-capture-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let limits = Limits { max_events_bytes: 0, max_pcap_bytes: 0, max_files_bytes: 0, keep: 0 };
        let first = Capture::open_with(&dir, limits.clone()).unwrap();
        first.log("test", serde_json::json!({ "run": 1 }));
        let saved = first.save_file("http_body", "/gate.php", b"first run").unwrap();
        first.udp_datagram("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap(), b"x");
        drop(first);
        std::fs::write(dir.join("ca.pem"), "kept").unwrap();

        let second = Capture::open_with(&dir, limits).unwrap();
        second.log("test", serde_json::json!({ "run": 2 }));
        let saved_again = second.save_file("http_body", "/gate.php", b"second run").unwrap();
        drop(second);

        // This run's log holds only this run; the first run's outputs are intact in previous/
        let events = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        assert!(events.contains("\"run\":2") && !events.contains("\"run\":1"));
        let previous: Vec<PathBuf> = std::fs::read_dir(dir.join("previous")).unwrap().flatten().map(|e| e.path()).collect();
        assert_eq!(previous.len(), 1);
        let old = &previous[0];
        assert!(std::fs::read_to_string(old.join("events.jsonl")).unwrap().contains("\"run\":1"));
        assert!(std::fs::metadata(old.join("traffic.pcap")).unwrap().len() > 24); // Not truncated (BUG-03)
        assert_eq!(std::fs::read(old.join("files").join(saved.file_name().unwrap())).unwrap(), b"first run");
        assert_eq!(std::fs::read(&saved_again).unwrap(), b"second run");
        assert_eq!(std::fs::read_to_string(dir.join("ca.pem")).unwrap(), "kept");

        // An empty start archives nothing
        drop(Capture::open_with(&std::env::temp_dir().join(format!("fakenet-capture-empty-{}", std::process::id())), Limits::default()).unwrap());
        assert!(archive_previous(&std::env::temp_dir().join(format!("fakenet-capture-empty-{}", std::process::id()))).unwrap().is_none());
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("fakenet-capture-empty-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_rotations_lists_oldest_first() {
        let dir = std::env::temp_dir().join(format!("fakenet-capture-rotations-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["events.jsonl", "events.1.jsonl", "events.2.jsonl"] {
            std::fs::write(dir.join(name), "").unwrap();
        }
        let names: Vec<String> = with_rotations(&dir.join("events.jsonl")).iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["events.2.jsonl", "events.1.jsonl", "events.jsonl"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
