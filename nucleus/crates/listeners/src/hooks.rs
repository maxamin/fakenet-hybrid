//! Reverse-engineering hooks: when an event matches a `[[hook]]`, act on the sample's process
//! before it gets its answer, so a debugger lands in the code that handles it.
//! - `pause`: SIGSTOP the process that owns the connection; resume it from the dashboard
//!   (`POST /api/paused/<pid>/resume`) once a debugger is attached.
//! - `dump`: write the process's readable memory (Linux, /proc/<pid>/mem) to
//!   `capture/hooks/`, while the process is stopped: decrypted configs and keys live there.
//! - `command`: run a program (Frida, gdb, a script) with fixed placeholders. The argv is
//!   used as written, never through a shell, and placeholders hold only values the nucleus
//!   made (pid, ids, paths): nothing the sample controls.
//!
//! A hook needs the process: it applies to connections process attribution resolved (local
//! clients on Linux, or diverted ones on Windows).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use fakenet_capture::Capture;
use fakenet_schema::Event;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::event_filter::{host_of, request_text, EventFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookAction {
    Pause,
    Dump,
    Command,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    pub name: String,
    #[serde(flatten)]
    pub filter: EventFilter,
    pub actions: Vec<HookAction>,
    /// For `command`: the program and its arguments. Placeholders: {pid}, {session_id},
    /// {request_id}, {protocol}, {event} (a JSON file holding the event), {dir} (this
    /// hook's output folder)
    #[serde(default)]
    pub command: Vec<String>,
    /// Hold the answer until the command exits (at most this long; 0: don't wait)
    #[serde(default)]
    pub wait_ms: u64,
    /// Fire only for the first matching event
    #[serde(default)]
    pub once: bool,
    /// Largest dump written (MB)
    #[serde(default = "default_max_dump_mb")]
    pub max_dump_mb: u64,
}

fn default_max_dump_mb() -> u64 {
    512
}

pub struct Hooks {
    hooks: Vec<HookConfig>,
    fired: Mutex<Vec<bool>>,
    /// pid -> what paused it
    paused: Mutex<BTreeMap<u32, Value>>,
}

impl Hooks {
    pub fn new(hooks: Vec<HookConfig>) -> Hooks {
        let fired = Mutex::new(vec![false; hooks.len()]);
        Hooks { hooks, fired, paused: Mutex::new(BTreeMap::new()) }
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Runs the hooks `event` matches. Called before the answer is computed.
    pub async fn fire(&self, event: &Event, capture: &Capture) {
        let matching: Vec<&HookConfig> = {
            let mut fired = self.fired.lock().unwrap_or_else(|e| e.into_inner());
            let mut matching = Vec::new();
            for (i, hook) in self.hooks.iter().enumerate() {
                if !(hook.once && fired[i]) && hook.filter.matches(event) {
                    fired[i] = true;
                    matching.push(hook);
                }
            }
            matching
        };
        for hook in matching {
            let Some(pid) = event.process.as_ref().map(|p| p.pid).filter(|pid| acceptable_pid(*pid)) else {
                capture.log("hook", json!({ "hook": hook.name, "session_id": event.session_id, "request_id": event.request_id, "error": "no attributed process" }));
                continue;
            };
            let dir = capture.dir().join("hooks").join(format!("{}-{}-{pid}", safe(&hook.name), safe(&event.request_id)));
            let mut record = json!({ "hook": hook.name, "session_id": event.session_id, "request_id": event.request_id, "pid": pid, "process": event.process });
            if let Err(e) = std::fs::create_dir_all(&dir) {
                record["error"] = json!(format!("creating {}: {e}", dir.display()));
                capture.log("hook", record);
                continue;
            }
            let event_file = dir.join("event.json");
            let _ = std::fs::write(&event_file, serde_json::to_vec_pretty(event).unwrap_or_default());
            let mut results = serde_json::Map::new();
            if hook.actions.contains(&HookAction::Dump) {
                let max = hook.max_dump_mb.saturating_mul(1024 * 1024);
                let dump_dir = dir.clone();
                let result = tokio::task::spawn_blocking(move || dump_process(pid, &dump_dir, max)).await;
                results.insert("dump".into(), match result {
                    Ok(Ok(summary)) => summary,
                    Ok(Err(e)) => json!({ "error": e.to_string() }),
                    Err(e) => json!({ "error": e.to_string() }),
                });
            }
            if hook.actions.contains(&HookAction::Pause) {
                results.insert("pause".into(), match signal(pid, Signal::Stop) {
                    Ok(()) => {
                        let shown = json!({ "pid": pid, "process": event.process, "hook": hook.name, "request": request_text(event), "host": host_of(event), "session_id": event.session_id });
                        self.paused.lock().unwrap_or_else(|e| e.into_inner()).insert(pid, shown);
                        json!("paused")
                    }
                    Err(e) => json!({ "error": e.to_string() }),
                });
            }
            if hook.actions.contains(&HookAction::Command) && !hook.command.is_empty() {
                let argv: Vec<String> = hook.command.iter().map(|arg| expand(arg, pid, event, &event_file, &dir)).collect();
                results.insert("command".into(), run_command(&argv, &dir, hook.wait_ms).await);
            }
            record["dir"] = json!(dir.display().to_string());
            record["results"] = Value::Object(results);
            capture.log("hook", record);
        }
    }

    /// The processes paused by hooks
    pub fn paused(&self) -> Vec<Value> {
        self.paused.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect()
    }

    /// Resumes a process a hook paused; false if no hook paused it
    pub fn resume(&self, pid: u32) -> std::io::Result<bool> {
        let held = self.paused.lock().unwrap_or_else(|e| e.into_inner()).remove(&pid);
        match held {
            Some(_) => signal(pid, Signal::Continue).map(|()| true),
            None => Ok(false),
        }
    }
}

/// Never the nucleus itself, init, or a process group (0 / negative after the cast)
fn acceptable_pid(pid: u32) -> bool {
    pid > 1 && pid != std::process::id() && i32::try_from(pid).is_ok()
}

fn safe(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_alphanumeric() || "-_".contains(c) { c } else { '_' }).take(60).collect()
}

/// Substitutes the placeholders; each is a value the nucleus produced
fn expand(arg: &str, pid: u32, event: &Event, event_file: &Path, dir: &Path) -> String {
    arg.replace("{pid}", &pid.to_string())
        .replace("{session_id}", &safe(&event.session_id))
        .replace("{request_id}", &safe(&event.request_id))
        .replace("{protocol}", &format!("{:?}", event.protocol).to_ascii_lowercase())
        .replace("{event}", &event_file.display().to_string())
        .replace("{dir}", &dir.display().to_string())
}

async fn run_command(argv: &[String], dir: &Path, wait_ms: u64) -> Value {
    let log = |name: &str| std::fs::File::create(dir.join(name)).map(std::process::Stdio::from).unwrap_or_else(|_| std::process::Stdio::null());
    let spawned = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(log("command.stdout"))
        .stderr(log("command.stderr"))
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return json!({ "argv": argv, "error": e.to_string() }),
    };
    let pid = child.id();
    if wait_ms == 0 {
        // Reaped in the background; it may outlive the session (a debugger, say)
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        return json!({ "argv": argv, "pid": pid });
    }
    match tokio::time::timeout(Duration::from_millis(wait_ms), child.wait()).await {
        Ok(Ok(status)) => json!({ "argv": argv, "pid": pid, "exit": status.code() }),
        Ok(Err(e)) => json!({ "argv": argv, "pid": pid, "error": e.to_string() }),
        Err(_) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            json!({ "argv": argv, "pid": pid, "still_running_after_ms": wait_ms })
        }
    }
}

#[derive(Clone, Copy)]
enum Signal {
    Stop,
    Continue,
}

#[cfg(unix)]
fn signal(pid: u32, signal: Signal) -> std::io::Result<()> {
    if !acceptable_pid(pid) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "refusing to signal that pid"));
    }
    let number = match signal {
        Signal::Stop => libc::SIGSTOP,
        Signal::Continue => libc::SIGCONT,
    };
    // SAFETY: kill(2) on a positive pid checked above; no memory is passed
    match unsafe { libc::kill(pid as libc::pid_t, number) } {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

#[cfg(not(unix))]
fn signal(_pid: u32, _signal: Signal) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "pausing processes needs Linux (use a command hook with your debugger on Windows)"))
}

/// One mapping of /proc/<pid>/maps
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
struct Region {
    start: u64,
    end: u64,
    perms: String,
    path: String,
}

#[cfg(target_os = "linux")]
fn parse_maps(text: &str) -> Vec<Region> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let perms = fields.next()?.to_string();
            let path = fields.nth(3).unwrap_or("").to_string();
            Some(Region { start: u64::from_str_radix(start, 16).ok()?, end: u64::from_str_radix(end, 16).ok()?, perms, path })
        })
        .collect()
}

/// Writes the readable memory of `pid` (stopped meanwhile) to `dir`: `maps.txt`, one
/// `<start>-<end>-<perms>.bin` per region, and `regions.json`; at most `max` bytes
#[cfg(target_os = "linux")]
fn dump_process(pid: u32, dir: &Path, max: u64) -> std::io::Result<Value> {
    use std::os::unix::fs::FileExt;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    std::fs::write(dir.join("maps.txt"), &maps)?;
    // Stopped while reading, so the regions are consistent; resumed after unless it was
    // already stopped (by a pause hook or the analyst)
    let was_stopped = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| s.rsplit_once(')').map(|(_, rest)| rest.trim_start().starts_with('T'))).unwrap_or(false);
    if !was_stopped {
        signal(pid, Signal::Stop)?;
    }
    let result = (|| {
        let memory = std::fs::File::open(format!("/proc/{pid}/mem"))?;
        let mut written = 0u64;
        let mut regions = Vec::new();
        let mut truncated = false;
        for region in parse_maps(&maps) {
            // Unreadable, or kernel-provided pages reads of which fail
            if !region.perms.starts_with('r') || region.path == "[vvar]" || region.path == "[vsyscall]" || region.path == "[vvar_vclock]" {
                continue;
            }
            let length = region.end - region.start;
            if written + length > max {
                truncated = true;
                continue;
            }
            let mut data = vec![0u8; usize::try_from(length).unwrap_or(0)];
            let mut filled = 0;
            while filled < data.len() {
                match memory.read_at(&mut data[filled..], region.start + filled as u64) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => filled += n,
                }
            }
            if filled == 0 {
                continue;
            }
            data.truncate(filled);
            let name = format!("{:016x}-{:016x}-{}.bin", region.start, region.end, region.perms);
            std::fs::write(dir.join(&name), &data)?;
            written += filled as u64;
            regions.push(json!({ "file": name, "start": format!("{:#x}", region.start), "end": format!("{:#x}", region.end), "perms": region.perms, "path": region.path, "bytes": filled }));
        }
        std::fs::write(dir.join("regions.json"), serde_json::to_vec_pretty(&regions).unwrap_or_default())?;
        Ok(json!({ "regions": regions.len(), "bytes": written, "truncated": truncated }))
    })();
    if !was_stopped {
        let _ = signal(pid, Signal::Continue);
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn dump_process(_pid: u32, _dir: &Path, _max: u64) -> std::io::Result<Value> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "memory dumps need Linux (use a command hook with procdump on Windows)"))
}

/// Where hook outputs go, for docs and the report
pub fn hooks_dir(capture: &Capture) -> PathBuf {
    capture.dir().join("hooks")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_maps() {
        let maps = "55d0c0a00000-55d0c0a21000 r-xp 00000000 08:01 1234 /usr/bin/sample\n7ffd1000-7ffd2000 rw-p 00000000 00:00 0 [stack]\n7ffd3000-7ffd4000 rw-p 00000000 00:00 0\n";
        let regions = parse_maps(maps);
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0], Region { start: 0x55d0c0a00000, end: 0x55d0c0a21000, perms: "r-xp".into(), path: "/usr/bin/sample".into() });
        assert_eq!(regions[1].path, "[stack]");
        assert_eq!(regions[2].path, "");
    }

    #[test]
    fn placeholders_hold_only_nucleus_values() {
        let event: Event = serde_json::from_value(json!({
            "version": 1, "type": "event", "request_id": "r1;rm -rf", "session_id": "s1", "seq": 1,
            "protocol": "http", "transport": "tcp", "src": "10.0.0.5", "dst": "198.18.0.7", "dport": 80,
            "timestamp": "2026-01-01T00:00:00Z", "payload": "", "meta": {}, "expects_reply": true,
        }))
        .unwrap();
        let arg = expand("--pid={pid} {request_id} {protocol} {event}", 42, &event, Path::new("/c/event.json"), Path::new("/c"));
        assert_eq!(arg, "--pid=42 r1_rm_-rf http /c/event.json");
        assert!(!acceptable_pid(1) && !acceptable_pid(0) && !acceptable_pid(std::process::id()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pauses_dumps_and_resumes_a_process() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let dir = std::env::temp_dir().join(format!("fakenet-hooks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let summary = dump_process(pid, &dir, 64 * 1024 * 1024).unwrap();
        assert!(summary["regions"].as_u64().unwrap() > 0, "{summary}");
        assert!(std::fs::read_to_string(dir.join("maps.txt")).unwrap().contains("sleep"));
        let state = || std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap().rsplit_once(')').unwrap().1.trim_start().chars().next().unwrap();
        assert_ne!(state(), 'T'); // Resumed after the dump

        let hooks = Hooks::new(vec![]);
        signal(pid, Signal::Stop).unwrap();
        hooks.paused.lock().unwrap().insert(pid, json!({ "pid": pid }));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(state(), 'T');
        assert!(hooks.resume(pid).unwrap());
        std::thread::sleep(Duration::from_millis(50));
        assert_ne!(state(), 'T');
        assert!(!hooks.resume(pid).unwrap()); // Not paused any more
        child.kill().unwrap();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
