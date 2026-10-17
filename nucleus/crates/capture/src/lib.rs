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

/// How many recent records stay in memory (for the live dashboard)
const RECENT: usize = 5000;

pub struct Capture {
    dir: PathBuf,
    limits: Limits,
    events: Mutex<EventLog>,
    /// (sequence number, record), newest last
    recent: Mutex<std::collections::VecDeque<(u64, Value)>>,
    sequence: AtomicU64,
    pcap: Mutex<Pcap>,
    /// wire.pcap: real packets, when a wire capture runs
    wire: Mutex<Option<Pcap>>,
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

impl Capture {
    pub fn open(dir: &Path) -> Result<Arc<Capture>> {
        Capture::open_with(dir, Limits::default())
    }

    pub fn open_with(dir: &Path, limits: Limits) -> Result<Arc<Capture>> {
        std::fs::create_dir_all(dir.join("files")).with_context(|| format!("creating {}", dir.display()))?;
        let events = OpenOptions::new().create(true).append(true).open(dir.join("events.jsonl"))?;
        let bytes = events.metadata().map(|m| m.len()).unwrap_or(0);
        let files_bytes = std::fs::read_dir(dir.join("files"))
            .map(|entries| entries.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum())
            .unwrap_or(0);
        if limits.max_pcap_bytes > 0 && dir.join("traffic.pcap").exists() {
            rotate(dir, "traffic.pcap", limits.keep); // Keep the previous run's capture
        }
        let pcap = pcap::PcapWriter::create(&dir.join("traffic.pcap"))?;
        Ok(Arc::new(Capture {
            dir: dir.to_path_buf(),
            limits,
            events: Mutex::new(EventLog { writer: BufWriter::new(events), bytes }),
            recent: Mutex::new(std::collections::VecDeque::with_capacity(RECENT)),
            sequence: AtomicU64::new(0),
            pcap: Mutex::new(Pcap { writer: pcap, bytes: 24 }),
            wire: Mutex::new(None),
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

    /// The event logs, oldest first (rotated ones, then the current one)
    pub fn event_files(&self) -> Vec<PathBuf> {
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
            scanner.finish();
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
        let record = Value::Object(record);
        let line = record.to_string();
        {
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
            if recent.len() == RECENT {
                recent.pop_front();
            }
            recent.push_back((sequence, record));
        }
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if self.limits.max_events_bytes > 0 && events.bytes + line.len() as u64 + 1 > self.limits.max_events_bytes && events.bytes > 0 {
            let _ = events.writer.flush();
            rotate(&self.dir, "events.jsonl", self.limits.keep);
            match OpenOptions::new().create(true).append(true).open(self.dir.join("events.jsonl")) {
                Ok(file) => *events = EventLog { writer: BufWriter::new(file), bytes: 0 },
                Err(e) => tracing::warn!("Could not rotate the event log: {e}"),
            }
        }
        // Best effort: a full disk must not take the fake services down
        if writeln!(events.writer, "{line}").and_then(|_| events.writer.flush()).is_err() {
            tracing::warn!("Could not write to the event log");
        }
        events.bytes += line.len() as u64 + 1;
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
        let n = self.file_counter.fetch_add(1, Ordering::Relaxed);
        let path = self.dir.join("files").join(format!("{prefix}_{n:06}_{}", if safe.is_empty() { "data" } else { &safe }));
        std::fs::write(&path, data)?;
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
        let mut wire = self.wire.lock().unwrap_or_else(|e| e.into_inner());
        if wire.is_none() {
            if self.dir.join("wire.pcap").exists() {
                rotate(&self.dir, "wire.pcap", self.limits.keep);
            }
            match pcap::PcapWriter::create(&self.dir.join("wire.pcap")) {
                Ok(writer) => *wire = Some(Pcap { writer, bytes: 24 }),
                Err(e) => {
                    tracing::warn!("Could not create wire.pcap: {e}");
                    return;
                }
            }
        }
        let Some(pcap) = wire.as_mut() else { return };
        Self::write_rotating(&self.dir, "wire.pcap", &self.limits, pcap, vec![packet.to_vec()]);
    }

    fn write_rotating(dir: &Path, name: &str, limits: &Limits, pcap: &mut Pcap, packets: Vec<Vec<u8>>) {
        for packet in packets {
            let size = packet.len() as u64 + 16;
            if limits.max_pcap_bytes > 0 && pcap.bytes + size > limits.max_pcap_bytes {
                rotate(dir, name, limits.keep);
                match pcap::PcapWriter::create(&dir.join(name)) {
                    Ok(writer) => *pcap = Pcap { writer, bytes: 24 },
                    Err(e) => {
                        tracing::warn!("Could not rotate {name}: {e}");
                        return;
                    }
                }
            }
            if pcap.writer.write(&packet).is_err() {
                tracing::warn!("Could not write to {name}");
                return;
            }
            pcap.bytes += size;
        }
    }

    fn write_packets(&self, packets: Vec<Vec<u8>>) {
        let mut pcap = self.pcap.lock().unwrap_or_else(|e| e.into_inner());
        Self::write_rotating(&self.dir, "traffic.pcap", &self.limits, &mut pcap, packets);
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
        assert!(dir.join("traffic.1.pcap").exists());
        assert!(std::fs::metadata(dir.join("traffic.pcap")).unwrap().len() <= 600);

        let (records, latest) = capture.recent(15, 100);
        assert_eq!((records.len(), latest), (5, 20));
        assert_eq!(records[0].1["i"], 15);
        assert!(capture.save_file("t", "a", b"12345").is_ok());
        assert!(capture.save_file("t", "b", b"123456").is_err()); // Over the 10-byte budget
        let _ = std::fs::remove_dir_all(&dir);
    }
}
