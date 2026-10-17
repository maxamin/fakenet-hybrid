//! Per-sample runs (`--run SAMPLE`): the sample is started once everything listens, the
//! run ends when it exits (plus a grace period for its last connections), at the timeout
//! (it's killed), or on Ctrl+C; run.json ties the capture to the sample's hashes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use fakenet_capture::Capture;
use md5::{Digest, Md5};
use serde_json::{json, Value};

/// After the sample exits: time for its last connections (and child processes) to show
const GRACE: Duration = Duration::from_secs(5);

pub struct Sample {
    pub path: PathBuf,
    pub args: Vec<String>,
    pub name: String,
    pub sha256: String,
    pub md5: String,
    pub size: u64,
}

impl Sample {
    pub fn inspect(path: &std::path::Path, args: Vec<String>) -> anyhow::Result<Sample> {
        let path = path.canonicalize().with_context(|| format!("sample {}", path.display()))?;
        let data = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "sample".into());
        Ok(Sample {
            sha256: fakenet_explorer::hints::sha256(&data),
            md5: Md5::digest(&data).iter().map(|b| format!("{b:02x}")).collect(),
            size: data.len() as u64,
            path,
            args,
            name,
        })
    }

    /// "20261017-012345-bot.exe-5b2dff292973"
    pub fn folder_name(&self) -> String {
        let format = time::macros::format_description!("[year][month][day]-[hour][minute][second]");
        let stamp = time::OffsetDateTime::now_utc().format(&format).unwrap_or_default();
        let safe: String = self.name.chars().map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' }).take(40).collect();
        format!("{stamp}-{safe}-{}", &self.sha256[..12])
    }
}

pub struct Outcome {
    pub pid: Option<u32>,
    /// "exited", "timeout", "interrupted" or "failed to start"
    pub reason: &'static str,
    pub exit: Option<String>,
    pub started: time::OffsetDateTime,
    pub runtime: Duration,
    pub error: Option<String>,
}

/// Runs the sample until it exits (+ grace), `timeout`, or `interrupt` completes
pub async fn execute(sample: &Sample, timeout: Duration, capture: &Arc<Capture>, interrupt: impl std::future::Future<Output = ()>) -> Outcome {
    let started = time::OffsetDateTime::now_utc();
    let clock = Instant::now();
    let mut command = tokio::process::Command::new(&sample.path);
    command.args(&sample.args).kill_on_drop(true);
    if let Some(dir) = sample.path.parent() {
        command.current_dir(dir);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            capture.log("sample_failed", json!({ "path": sample.path.display().to_string(), "error": e.to_string() }));
            return Outcome { pid: None, reason: "failed to start", exit: None, started, runtime: clock.elapsed(), error: Some(e.to_string()) };
        }
    };
    let pid = child.id();
    capture.log("sample_started", json!({ "path": sample.path.display().to_string(), "sha256": sample.sha256, "pid": pid, "args": sample.args }));
    tracing::info!("Running {} (pid {:?}) for up to {}s", sample.path.display(), pid, timeout.as_secs());
    tokio::pin!(interrupt);
    let (reason, exit) = tokio::select! {
        status = child.wait() => {
            let exit = status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            capture.log("sample_exited", json!({ "pid": pid, "status": exit, "runtime_ms": clock.elapsed().as_millis() as u64 }));
            // Its children & last connections may still be going: give them the grace period
            tokio::select! {
                _ = tokio::time::sleep(GRACE) => {}
                _ = &mut interrupt => {}
            }
            ("exited", Some(exit))
        }
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            capture.log("sample_killed", json!({ "pid": pid, "reason": "timeout" }));
            ("timeout", None)
        }
        _ = &mut interrupt => {
            let _ = child.kill().await;
            capture.log("sample_killed", json!({ "pid": pid, "reason": "interrupted" }));
            ("interrupted", None)
        }
    };
    Outcome { pid, reason, exit, started, runtime: clock.elapsed(), error: None }
}

/// run.json: the sample, how the run went, and what it did (records by kind)
pub fn summary(sample: &Sample, outcome: &Outcome, capture: &Capture) -> Value {
    let mut kinds = std::collections::BTreeMap::<String, u64>::new();
    let mut protocols = std::collections::BTreeMap::<String, u64>::new();
    for file in capture.event_files() {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        for record in text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
            *kinds.entry(record["kind"].as_str().unwrap_or("").to_string()).or_default() += 1;
            if record["kind"] == "event" {
                *protocols.entry(record["protocol"].as_str().unwrap_or("").to_string()).or_default() += 1;
            }
        }
    }
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    json!({
        "sample": { "path": sample.path.display().to_string(), "name": sample.name, "sha256": sample.sha256, "md5": sample.md5, "size": sample.size, "args": sample.args },
        "run": {
            "pid": outcome.pid, "ended_by": outcome.reason, "exit": outcome.exit, "error": outcome.error,
            "started": outcome.started.format(rfc3339).unwrap_or_default(), "runtime_seconds": outcome.runtime.as_secs_f64(),
        },
        "records": kinds,
        "events_by_protocol": protocols,
        "files": { "events": "events.jsonl", "pcap": "traffic.pcap", "report": "report.html", "explorer_map": "explorer-map.json", "captured": "files/" },
    })
}
