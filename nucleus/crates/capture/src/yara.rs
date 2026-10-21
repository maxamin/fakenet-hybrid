//! YARA on captured payloads: every file the capture saves (HTTP bodies, uploads, emails,
//! FTP/TFTP transfers) is scanned with the analyst's rules, and matches are logged as
//! `yara_match` records. Uses the stock YARA tools (`yarac` once at start, so a broken rule
//! fails the start; `yara --scan-list` per batch of queued files, in a background thread,
//! never delaying an answer). The queue is bounded and shutdown waits a bounded time: files
//! skipped either way are counted in a `yara_summary` record.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::Capture;

/// Seconds a single scan may take (yara -a)
const SCAN_TIMEOUT: &str = "30";

/// Files waiting for a scan; past it new ones are skipped (and counted)
const QUEUE: usize = 10_000;
/// Files per yara run
const BATCH: usize = 64;
/// How long shutdown waits for queued scans before giving up on the rest
pub const FINISH_LIMIT: Duration = Duration::from_secs(60);

pub struct Scanner {
    jobs: mpsc::SyncSender<PathBuf>,
    worker: std::thread::JoinHandle<()>,
    done: mpsc::Receiver<()>,
    counts: Arc<Counts>,
    capture: Weak<Capture>,
}

#[derive(Default)]
struct Counts {
    /// The queue was full
    skipped: AtomicU64,
    /// Still queued when shutdown stopped waiting
    unscanned: AtomicU64,
    stop: AtomicBool,
}

/// The rule files: given files, and *.yar / *.yara under given directories (sorted)
pub fn rule_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut found = Vec::new();
            collect(path, &mut found)?;
            found.sort();
            files.extend(found);
        } else if path.is_file() {
            files.push(path.clone());
        } else {
            bail!("YARA rules {} not found", path.display());
        }
    }
    Ok(files)
}

fn collect(dir: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, found)?;
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara")) {
            found.push(path);
        }
    }
    Ok(())
}

/// Compiles `rules` with `yarac` into `compiled`
pub fn compile(yarac: &str, rules: &[PathBuf], compiled: &Path) -> Result<()> {
    if rules.is_empty() {
        bail!("no YARA rule files");
    }
    let output = Command::new(yarac).args(rules).arg(compiled).output().with_context(|| format!("running {yarac} (install YARA, or set [yara] yarac)"))?;
    if !output.status.success() {
        bail!("{yarac} rejected the rules: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

/// Scans several files with one yara run; the matching rules per file (files without a
/// match are left out)
pub fn scan_batch(yara: &str, compiled: &Path, files: &[PathBuf]) -> Result<Vec<(PathBuf, Vec<String>)>> {
    static LISTS: AtomicU64 = AtomicU64::new(0);
    // The paths are the capture's own (sanitised names under files/): one per line is safe
    let list = std::env::temp_dir().join(format!("fakenet-yara-{}-{}.list", std::process::id(), LISTS.fetch_add(1, Ordering::Relaxed)));
    let text: String = files.iter().map(|f| format!("{}\n", f.display())).collect();
    std::fs::write(&list, text).with_context(|| format!("writing {}", list.display()))?;
    let output = Command::new(yara).args(["-w", "-a", SCAN_TIMEOUT, "-C", "--scan-list"]).arg(compiled).arg(&list).output();
    let _ = std::fs::remove_file(&list);
    let output = output.with_context(|| format!("running {yara}"))?;
    if !output.status.success() {
        bail!("{yara}: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    let mut matches: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some((rule, file)) = line.split_once(' ') else { continue };
        let file = PathBuf::from(file);
        match matches.iter_mut().find(|(f, _)| *f == file) {
            Some((_, rules)) => rules.push(rule.to_string()),
            None => matches.push((file, vec![rule.to_string()])),
        }
    }
    Ok(matches)
}

/// Scans one file; returns the names of the matching rules
pub fn scan(yara: &str, compiled: &Path, file: &Path) -> Result<Vec<String>> {
    let output = Command::new(yara).args(["-w", "-a", SCAN_TIMEOUT, "-C"]).arg(compiled).arg(file).output().with_context(|| format!("running {yara}"))?;
    if !output.status.success() {
        bail!("{yara}: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    // "RULE FILE" per match; the file is ours, so only the rule name needs parsing
    Ok(String::from_utf8_lossy(&output.stdout).lines().filter_map(|line| line.split_once(' ').map(|(rule, _)| rule.to_string())).collect())
}

impl Scanner {
    /// Compiles the rules into the capture folder and starts the scanning thread
    pub fn start(capture: &Arc<Capture>, rules: &[PathBuf], yara: &str, yarac: &str) -> Result<Scanner> {
        let files = rule_files(rules)?;
        let compiled = capture.dir().join("yara-rules.compiled");
        compile(yarac, &files, &compiled)?;
        let (jobs, queue) = mpsc::sync_channel::<PathBuf>(QUEUE);
        let (finished, done) = mpsc::channel();
        let counts = Arc::new(Counts::default());
        let (weak, yara, worker_counts) = (Arc::downgrade(capture), yara.to_string(), counts.clone());
        let worker = std::thread::Builder::new().name("yara".into()).spawn(move || {
            run(queue, weak, yara, compiled, &worker_counts);
            let _ = finished.send(());
        })?;
        tracing::info!("YARA: {} rule files", files.len());
        Ok(Scanner { jobs, worker, done, counts, capture: Arc::downgrade(capture) })
    }

    /// Queues a file; skipped (and counted) when the queue is full
    pub fn queue(&self, file: PathBuf) {
        if let Err(mpsc::TrySendError::Full(_)) = self.jobs.try_send(file) {
            self.counts.skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Finishes the queued scans, waiting at most `limit` (then only the running scan,
    /// bounded by yara's timeout); logs what was skipped
    pub fn finish(self, limit: Duration) {
        drop(self.jobs);
        if self.done.recv_timeout(limit).is_err() {
            self.counts.stop.store(true, Ordering::Relaxed);
        }
        let _ = self.worker.join();
        let (skipped, unscanned) = (self.counts.skipped.load(Ordering::Relaxed), self.counts.unscanned.load(Ordering::Relaxed));
        if skipped + unscanned > 0 {
            if let Some(capture) = self.capture.upgrade() {
                capture.log("yara_summary", json!({ "skipped_queue_full": skipped, "unscanned_at_stop": unscanned }));
            }
        }
    }
}

fn run(queue: mpsc::Receiver<PathBuf>, capture: Weak<Capture>, yara: String, compiled: PathBuf, counts: &Counts) {
    while let Ok(first) = queue.recv() {
        let mut batch = vec![first];
        while batch.len() < BATCH {
            match queue.try_recv() {
                Ok(file) => batch.push(file),
                Err(_) => break,
            }
        }
        if counts.stop.load(Ordering::Relaxed) {
            counts.unscanned.fetch_add(batch.len() as u64, Ordering::Relaxed);
            continue;
        }
        let result = scan_batch(&yara, &compiled, &batch);
        let Some(capture) = capture.upgrade() else { return };
        match result {
            Ok(matches) => {
                for (file, rules) in matches {
                    capture.log("yara_match", json!({ "file": file.display().to_string(), "rules": rules }));
                }
            }
            Err(e) => {
                for file in &batch {
                    capture.log("yara_error", json!({ "file": file.display().to_string(), "error": format!("{e:#}") }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yara_installed() -> bool {
        Command::new("yarac").arg("--version").output().is_ok_and(|o| o.status.success())
    }

    #[test]
    fn scans_saved_files_and_logs_matches() {
        if !yara_installed() {
            eprintln!("yara not installed: skipped");
            return;
        }
        let dir = std::env::temp_dir().join(format!("fakenet-yara-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules/nested")).unwrap();
        std::fs::write(dir.join("rules/c2.yar"), "rule C2_Beacon { strings: $a = \"beacon_id=\" condition: $a }").unwrap();
        std::fs::write(dir.join("rules/nested/mz.yara"), "rule Embedded_PE { condition: uint16(0) == 0x5a4d }").unwrap();
        std::fs::write(dir.join("rules/notes.txt"), "not a rule").unwrap();
        let capture = Capture::open(&dir.join("capture")).unwrap();
        capture.enable_yara(&[dir.join("rules")], "yara", "yarac").unwrap();
        capture.save_file("http", "post.bin", b"x=1&beacon_id=42").unwrap();
        capture.save_file("ftp", "evil.exe", b"MZ\x90\x00 beacon_id=7").unwrap();
        capture.save_file("http", "clean.txt", b"nothing to see").unwrap();
        capture.finish_scans();
        capture.flush();
        let log = std::fs::read_to_string(dir.join("capture/events.jsonl")).unwrap();
        let mut matches: Vec<serde_json::Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).filter(|r: &serde_json::Value| r["kind"] == "yara_match").collect();
        assert_eq!(matches.len(), 2, "{log}");
        // One yara run may report the batch's files in any order
        matches.sort_by_key(|m| m["file"].as_str().unwrap().ends_with("evil.exe"));
        assert!(matches[0]["file"].as_str().unwrap().ends_with("post.bin"));
        assert_eq!(matches[0]["rules"], json!(["C2_Beacon"]));
        let mut rules: Vec<String> = serde_json::from_value(matches[1]["rules"].clone()).unwrap();
        rules.sort();
        assert_eq!(rules, ["C2_Beacon", "Embedded_PE"]);
        assert!(!log.contains("yara_summary")); // Nothing skipped
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_rules_fail_the_start() {
        if !yara_installed() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("fakenet-yara-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad.yar"), "rule Broken { condition: $missing }").unwrap();
        let capture = Capture::open(&dir.join("capture")).unwrap();
        let error = capture.enable_yara(&[dir.join("bad.yar")], "yara", "yarac").unwrap_err();
        assert!(format!("{error:#}").contains("rejected the rules"), "{error:#}");
        assert!(capture.enable_yara(&[dir.join("missing.yar")], "yara", "yarac").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
