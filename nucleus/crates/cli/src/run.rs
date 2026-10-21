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
    /// "exited" (the whole process tree), "timeout", "interrupted" or "failed to start"
    pub reason: &'static str,
    pub exit: Option<String>,
    pub started: time::OffsetDateTime,
    pub runtime: Duration,
    pub error: Option<String>,
}

/// The account a `--run` sample runs as (Unix): resolved before starting, so the child only
/// makes the set*id calls
#[derive(Debug, Clone)]
pub struct RunAs {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: String,
}

impl RunAs {
    /// Looks up a user name (getpwnam_r, getgrouplist)
    #[cfg(unix)]
    pub fn resolve(name: &str) -> anyhow::Result<RunAs> {
        let c_name = std::ffi::CString::new(name)?;
        let mut buffer = vec![0u8; 16 * 1024];
        // SAFETY: getpwnam_r writes into `entry` and `buffer`, both live and passed with their
        // sizes; `result` points to `entry` or is null. Strings in `entry` point into `buffer`,
        // which outlives their use here.
        let (uid, gid, home) = unsafe {
            let mut entry: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let status = libc::getpwnam_r(c_name.as_ptr(), &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut result);
            anyhow::ensure!(status == 0 && !result.is_null(), "--run-as: no user {name}");
            let home = std::ffi::CStr::from_ptr(entry.pw_dir).to_string_lossy().into_owned();
            (entry.pw_uid, entry.pw_gid, home)
        };
        let mut groups = vec![0 as libc::gid_t; 256];
        let mut count = groups.len() as libc::c_int;
        // SAFETY: `groups` holds `count` entries; getgrouplist writes at most that many and
        // updates `count`
        let status = unsafe { libc::getgrouplist(c_name.as_ptr(), gid as _, groups.as_mut_ptr().cast(), &mut count) };
        anyhow::ensure!(status >= 0, "--run-as: {name} is in too many groups");
        groups.truncate(count.max(0) as usize);
        Ok(RunAs { name: name.to_string(), uid, gid, groups: groups.into_iter().map(|g| g as u32).collect(), home })
    }

    #[cfg(not(unix))]
    pub fn resolve(_name: &str) -> anyhow::Result<RunAs> {
        anyhow::bail!("--run-as is only supported on Unix")
    }
}

/// The sample's whole process tree: its own session (process group) and, when the cgroup v2
/// hierarchy lets us create one, its own cgroup, which also catches descendants that start a
/// session of their own
struct Tree {
    #[cfg_attr(not(unix), allow(dead_code))]
    group: Option<i32>,
    cgroup: Option<std::path::PathBuf>,
}

impl Tree {
    /// A new cgroup under the nucleus's own (Linux, cgroup v2, where creating one is allowed)
    fn cgroup() -> Option<std::path::PathBuf> {
        #[cfg(target_os = "linux")]
        {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
            let relative = own.lines().find_map(|l| l.strip_prefix("0::"))?.trim().trim_start_matches('/');
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::path::Path::new("/sys/fs/cgroup").join(relative).join(format!("fakenet-run-{}-{n}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => Some(path),
                Err(e) => {
                    tracing::warn!("No cgroup for the sample ({}: {e}); descendants that leave its session can't be tracked", path.display());
                    None
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    fn members(&self) -> Vec<i32> {
        match &self.cgroup {
            Some(cgroup) => std::fs::read_to_string(cgroup.join("cgroup.procs")).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect(),
            None => Vec::new(),
        }
    }

    /// Whether any process of the tree is still running
    fn alive(&self) -> bool {
        if !self.members().is_empty() {
            return true;
        }
        #[cfg(unix)]
        if let Some(group) = self.group {
            // SAFETY: signal 0 only checks that the process group exists
            return unsafe { libc::kill(-group, 0) } == 0;
        }
        false
    }

    /// Kills every process of the tree; returns how many were still running
    fn kill(&self) -> usize {
        let members = self.members();
        if let Some(cgroup) = &self.cgroup {
            if std::fs::write(cgroup.join("cgroup.kill"), "1").is_err() {
                #[cfg(unix)]
                for pid in &members {
                    // SAFETY: plain kill(2) of a PID listed in our own cgroup
                    unsafe { libc::kill(*pid, libc::SIGKILL) };
                }
            }
        }
        #[cfg(unix)]
        if let Some(group) = self.group {
            // SAFETY: kill(2) of the sample's own process group
            if unsafe { libc::kill(-group, libc::SIGKILL) } == 0 && members.is_empty() {
                return 1;
            }
        }
        members.len()
    }

    /// Kills what's left and removes the cgroup once it's empty
    async fn finish(&self) -> usize {
        let killed = self.kill();
        if let Some(cgroup) = &self.cgroup {
            for _ in 0..40 {
                if std::fs::remove_dir(cgroup).is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        killed
    }

    async fn exited(&self) {
        while self.alive() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

/// Runs the sample until its whole process tree has exited (+ grace), `timeout`, or
/// `interrupt` completes; whatever is left of the tree is then killed. With `run_as`, the
/// sample runs as that user.
pub async fn execute(sample: &Sample, timeout: Duration, capture: &Arc<Capture>, run_as: Option<&RunAs>, interrupt: impl std::future::Future<Output = ()>) -> Outcome {
    let started = time::OffsetDateTime::now_utc();
    let clock = Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut command = tokio::process::Command::new(&sample.path);
    command.args(&sample.args).kill_on_drop(true);
    if let Some(dir) = sample.path.parent() {
        command.current_dir(dir);
    }
    let cgroup = Tree::cgroup();
    #[cfg(unix)]
    {
        let procs = cgroup.as_ref().and_then(|c| std::ffi::CString::new(c.join("cgroup.procs").into_os_string().into_encoded_bytes()).ok());
        let user = run_as.cloned();
        if let Some(user) = &user {
            command.env("HOME", &user.home).env("USER", &user.name).env("LOGNAME", &user.name);
        }
        // SAFETY: between fork and exec the closure only makes async-signal-safe system calls
        // (setsid, open, write, close, setgroups, setgid, setuid) on values prepared before
        // the fork; it allocates nothing.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(procs) = &procs {
                    let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    if fd >= 0 {
                        libc::write(fd, b"0".as_ptr().cast(), 1);
                        libc::close(fd);
                    }
                }
                if let Some(user) = &user {
                    if libc::setgroups(user.groups.len() as _, user.groups.as_ptr().cast()) == -1
                        || libc::setgid(user.gid as _) == -1
                        || libc::setuid(user.uid as _) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            let tree = Tree { group: None, cgroup };
            tree.finish().await;
            capture.log("sample_failed", json!({ "path": sample.path.display().to_string(), "error": e.to_string() }));
            return Outcome { pid: None, reason: "failed to start", exit: None, started, runtime: clock.elapsed(), error: Some(e.to_string()) };
        }
    };
    let pid = child.id();
    // setsid() made the sample its own process group's leader
    let tree = Tree { group: pid.and_then(|p| i32::try_from(p).ok()), cgroup };
    let user = run_as.map(|u| json!({ "name": u.name, "uid": u.uid }));
    capture.log("sample_started", json!({
        "path": sample.path.display().to_string(), "sha256": sample.sha256, "pid": pid, "args": sample.args,
        "run_as": user, "cgroup": tree.cgroup.as_ref().map(|c| c.display().to_string()),
    }));
    tracing::info!("Running {} (pid {:?}) for up to {}s", sample.path.display(), pid, timeout.as_secs());
    tokio::pin!(interrupt);
    let (reason, exit) = tokio::select! {
        status = child.wait() => {
            let exit = status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
            capture.log("sample_exited", json!({ "pid": pid, "status": exit, "runtime_ms": clock.elapsed().as_millis() as u64 }));
            // Descendants it left running are part of the run: wait for them too
            let reason = tokio::select! {
                _ = tree.exited() => "exited",
                _ = tokio::time::sleep_until(deadline) => "timeout",
                _ = &mut interrupt => "interrupted",
            };
            if reason == "exited" {
                // Its last connections may still be in flight: the grace period
                tokio::select! {
                    _ = tokio::time::sleep(GRACE) => {}
                    _ = &mut interrupt => {}
                }
            } else {
                let killed = tree.kill();
                capture.log("sample_killed", json!({ "pid": pid, "reason": reason, "descendants": killed }));
            }
            (reason, Some(exit))
        }
        _ = tokio::time::sleep_until(deadline) => {
            let killed = tree.kill();
            let _ = child.kill().await;
            capture.log("sample_killed", json!({ "pid": pid, "reason": "timeout", "descendants": killed }));
            ("timeout", None)
        }
        _ = &mut interrupt => {
            let killed = tree.kill();
            let _ = child.kill().await;
            capture.log("sample_killed", json!({ "pid": pid, "reason": "interrupted", "descendants": killed }));
            ("interrupted", None)
        }
    };
    // Anything started during the grace period goes too
    let leftover = tree.finish().await;
    if leftover > 0 && reason == "exited" {
        capture.log("sample_killed", json!({ "pid": pid, "reason": "run ended", "descendants": leftover }));
    }
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
        "files": { "events": "events.jsonl", "pcap": "traffic.pcap", "report": "report.html", "explorer_map": "explorer-map.json", "captured": "files/", "indicators": ["indicators.csv", "indicators.stix.json", "indicators.misp.json"] },
    })
}
