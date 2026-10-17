//! Resource limits: a hostile sample shouldn't be able to exhaust the nucleus (and lose the
//! rest of the run's evidence) by opening endless connections or sending huge payloads.
//!
//! - `max_sessions`: concurrent TCP connections and UDP clients; past it, new ones are
//!   dropped (existing sessions are never cut).
//! - `per_source_per_second` / `per_source_burst`: new sessions per source address (a token
//!   bucket); off by default, since scanning malware legitimately opens many.
//! - `memory_budget_mb`: payload bytes buffered at once by all sessions (request bodies,
//!   uploads, emails, Redis values). A session that would exceed it fails like one that
//!   sent too much.
//!
//! Refusals are counted (for /health and the dashboard) and logged at most once a second.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// Concurrent sessions (TCP connections + UDP clients); 0: unlimited
    pub max_sessions: usize,
    /// New sessions per second per source address; 0: unlimited
    pub per_source_per_second: f64,
    /// Sessions a source may open at once before the rate applies
    pub per_source_burst: u32,
    /// Payload bytes buffered at once by all sessions (MB); 0: unlimited
    pub memory_budget_mb: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig { max_sessions: 4096, per_source_per_second: 0.0, per_source_burst: 200, memory_budget_mb: 1024 }
    }
}

/// Source addresses tracked at most (a spoofed flood can't grow the table without bound)
const MAX_SOURCES: usize = 65_536;

pub struct Limits {
    sessions: Option<(Arc<Semaphore>, usize)>,
    rate: Option<(f64, f64)>,
    sources: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    memory: Arc<Memory>,
    refused_sessions: AtomicU64,
    refused_rate: AtomicU64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits::new(&LimitsConfig::default())
    }
}

/// Held for a session's lifetime: releases its slot when dropped
pub struct SessionPermit(#[allow(dead_code)] Option<OwnedSemaphorePermit>);

impl Limits {
    pub fn new(config: &LimitsConfig) -> Limits {
        Limits {
            sessions: (config.max_sessions > 0).then(|| {
                let total = config.max_sessions.min(Semaphore::MAX_PERMITS);
                (Arc::new(Semaphore::new(total)), total)
            }),
            rate: (config.per_source_per_second > 0.0).then(|| (config.per_source_per_second, config.per_source_burst.max(1) as f64)),
            sources: Mutex::default(),
            memory: Arc::new(Memory {
                used: AtomicUsize::new(0),
                limit: match config.memory_budget_mb {
                    0 => usize::MAX,
                    mb => usize::try_from(mb.saturating_mul(1 << 20)).unwrap_or(usize::MAX),
                },
                refused: AtomicU64::new(0),
                last_warning: Mutex::default(),
            }),
            refused_sessions: AtomicU64::new(0),
            refused_rate: AtomicU64::new(0),
        }
    }

    /// Admits a new session from `source`, or None (counted and logged) if a limit says no
    pub fn admit(&self, source: IpAddr, listener: &str) -> Option<SessionPermit> {
        if !self.take_token(source) {
            self.refused_rate.fetch_add(1, Ordering::Relaxed);
            self.memory.warn(|| format!("[{listener}] {source} is opening sessions faster than per_source_per_second; dropping new ones"));
            return None;
        }
        match &self.sessions {
            None => Some(SessionPermit(None)),
            Some((semaphore, _)) => match semaphore.clone().try_acquire_owned() {
                Ok(permit) => Some(SessionPermit(Some(permit))),
                Err(_) => {
                    self.refused_sessions.fetch_add(1, Ordering::Relaxed);
                    self.memory.warn(|| format!("[{listener}] max_sessions reached; dropping new sessions (from {source})"));
                    None
                }
            },
        }
    }

    fn take_token(&self, source: IpAddr) -> bool {
        let Some((per_second, burst)) = self.rate else { return true };
        let now = Instant::now();
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if sources.len() >= MAX_SOURCES && !sources.contains_key(&source) {
            // Forget the sources whose buckets have refilled: they're as good as new
            sources.retain(|_, (tokens, last)| *tokens + last.elapsed().as_secs_f64() * per_second < burst);
            if sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let (tokens, last) = sources.entry(source).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * per_second).min(burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// A share of the memory budget for one session's buffers, growing as they do
    pub fn hold(&self) -> Held {
        Held { memory: self.memory.clone(), bytes: 0 }
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "sessions_active": self.sessions.as_ref().map(|(s, total)| total.saturating_sub(s.available_permits())),
            "max_sessions": self.sessions.as_ref().map(|(_, total)| *total),
            "memory_bytes": self.memory.used.load(Ordering::Relaxed),
            "refused_max_sessions": self.refused_sessions.load(Ordering::Relaxed),
            "refused_rate": self.refused_rate.load(Ordering::Relaxed),
            "refused_memory": self.memory.refused.load(Ordering::Relaxed),
        })
    }
}

struct Memory {
    used: AtomicUsize,
    limit: usize,
    refused: AtomicU64,
    last_warning: Mutex<Option<Instant>>,
}

impl Memory {
    /// Logs a refusal, at most once a second (a flood shouldn't flood the log too)
    fn warn(&self, message: impl FnOnce() -> String) {
        let mut last = self.last_warning.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_none_or(|l| l.elapsed().as_secs() >= 1) {
            *last = Some(Instant::now());
            tracing::warn!("{}", message());
        }
    }
}

/// Bytes of the memory budget held by one buffer; released when dropped
pub struct Held {
    memory: Arc<Memory>,
    bytes: usize,
}

impl Held {
    /// Reserves `more` bytes before buffering them; fails when the budget is spent
    pub fn grow(&mut self, more: usize) -> anyhow::Result<()> {
        let reserved = self.memory.used.fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| used.checked_add(more).filter(|total| *total <= self.memory.limit));
        match reserved {
            Ok(_) => {
                self.bytes += more;
                Ok(())
            }
            Err(_) => {
                self.memory.refused.fetch_add(1, Ordering::Relaxed);
                self.memory.warn(|| "memory_budget_mb reached; refusing payloads until sessions finish".to_string());
                anyhow::bail!("memory budget exhausted")
            }
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.memory.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_sessions: usize, per_second: f64, burst: u32, memory_mb: u64) -> Limits {
        Limits::new(&LimitsConfig { max_sessions, per_source_per_second: per_second, per_source_burst: burst, memory_budget_mb: memory_mb })
    }

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn max_sessions_frees_slots_when_sessions_end() {
        let limits = limits(2, 0.0, 1, 0);
        let first = limits.admit(A, "t").unwrap();
        let _second = limits.admit(B, "t").unwrap();
        assert!(limits.admit(A, "t").is_none());
        drop(first);
        assert!(limits.admit(A, "t").is_some());
        assert_eq!(limits.stats()["refused_max_sessions"], 1);
    }

    #[test]
    fn rate_limits_each_source_separately() {
        let limits = limits(0, 0.001, 3, 0);
        for _ in 0..3 {
            assert!(limits.admit(A, "t").is_some());
        }
        assert!(limits.admit(A, "t").is_none());
        assert!(limits.admit(B, "t").is_some());
        assert_eq!(limits.stats()["refused_rate"], 1);
    }

    #[test]
    fn rate_refills_over_time() {
        let limits = limits(0, 1000.0, 1, 0);
        assert!(limits.admit(A, "t").is_some());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limits.admit(A, "t").is_some());
    }

    #[test]
    fn memory_budget_is_shared_and_released() {
        let limits = limits(0, 0.0, 1, 1);
        let mut one = limits.hold();
        let mut two = limits.hold();
        one.grow(700 << 10).unwrap();
        assert!(two.grow(400 << 10).is_err());
        drop(one);
        two.grow(400 << 10).unwrap();
        assert_eq!(limits.stats()["memory_bytes"], 400 << 10);
        assert_eq!(limits.stats()["refused_memory"], 1);
        drop(two);
        assert_eq!(limits.stats()["memory_bytes"], 0);
    }

    #[test]
    fn zero_means_unlimited() {
        let limits = limits(0, 0.0, 1, 0);
        let permits: Vec<_> = (0..10_000).map(|_| limits.admit(A, "t").unwrap()).collect();
        assert_eq!(permits.len(), 10_000);
        limits.hold().grow(usize::MAX / 2).unwrap();
    }
}
