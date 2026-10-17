//! YARA on captured payloads: every file the capture saves (HTTP bodies, uploads, emails,
//! FTP/TFTP transfers) is scanned with the analyst's rules, and matches are logged as
//! `yara_match` records. Uses the stock YARA tools (`yarac` once at start, so a broken rule
//! fails the start; `yara` per file, in a background thread, never delaying an answer).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Weak};

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::Capture;

/// Seconds a single scan may take (yara -a)
const SCAN_TIMEOUT: &str = "30";

pub struct Scanner {
    jobs: mpsc::Sender<PathBuf>,
    worker: std::thread::JoinHandle<()>,
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
        let (jobs, queue) = mpsc::channel::<PathBuf>();
        let (capture, yara) = (Arc::downgrade(capture), yara.to_string());
        let worker = std::thread::Builder::new().name("yara".into()).spawn(move || run(queue, capture, yara, compiled))?;
        tracing::info!("YARA: {} rule files", files.len());
        Ok(Scanner { jobs, worker })
    }

    pub fn queue(&self, file: PathBuf) {
        let _ = self.jobs.send(file);
    }

    /// Finishes the queued scans (each is bounded by yara's timeout)
    pub fn finish(self) {
        drop(self.jobs);
        let _ = self.worker.join();
    }
}

fn run(queue: mpsc::Receiver<PathBuf>, capture: Weak<Capture>, yara: String, compiled: PathBuf) {
    for file in queue {
        let result = scan(&yara, &compiled, &file);
        let Some(capture) = capture.upgrade() else { return };
        match result {
            Ok(rules) if rules.is_empty() => {}
            Ok(rules) => capture.log("yara_match", json!({ "file": file.display().to_string(), "rules": rules })),
            Err(e) => capture.log("yara_error", json!({ "file": file.display().to_string(), "error": format!("{e:#}") })),
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
        let log = std::fs::read_to_string(dir.join("capture/events.jsonl")).unwrap();
        let matches: Vec<serde_json::Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).filter(|r: &serde_json::Value| r["kind"] == "yara_match").collect();
        assert_eq!(matches.len(), 2, "{log}");
        assert_eq!(matches[0]["rules"], json!(["C2_Beacon"]));
        let mut rules: Vec<String> = serde_json::from_value(matches[1]["rules"].clone()).unwrap();
        rules.sort();
        assert_eq!(rules, ["C2_Beacon", "Embedded_PE"]);
        assert!(matches[1]["file"].as_str().unwrap().ends_with("evil.exe"));
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
