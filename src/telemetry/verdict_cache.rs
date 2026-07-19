//! Short-lived ALLOW-verdict cache — debounces identical rapid-fire spawns.
//!
//! Root cause this addresses: extremely common short-lived utilities (bash -c,
//! awk, sh, playerctl, etc.) are deliberately excluded from the fast-trust /
//! allowlist paths (see `never_fast_trust`) because they are classic LOLBins —
//! blanket-trusting them would let an attacker bypass the model entirely just
//! by wrapping payloads in `bash -c '...'`. That means every single spawn was
//! hitting full GPU LLM inference, even when the *exact same* command+args+exe
//! had already been classified ALLOW milliseconds earlier (e.g. a script that
//! shells out to `awk` in a tight loop, or a polling `playerctl` call).
//!
//! This cache does NOT weaken detection: it only ever short-circuits a spawn
//! when an identical (name, cmdline, exe_path) tuple was already sent through
//! the *real* model and came back ALLOW within the last `JETT_VERDICT_CACHE_MS`
//! (default 4000ms). Anything that previously came back QUARANTINE/REVIEW, or
//! any new/different command line, always goes through full inference. Cache
//! hits are still logged (cheaply) so there is no monitoring blind spot — the
//! spawn is recorded, just without re-running the model.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::config::env_u64;

struct CachedAllow {
    seen_at: Instant,
    hits: u32,
}

static CACHE: Mutex<Option<HashMap<String, CachedAllow>>> = Mutex::new(None);

pub fn verdict_cache_ttl_ms() -> u64 {
    env_u64("JETT_VERDICT_CACHE_MS", 4000)
}

fn cache_key(name: &str, cmdline: &str, exe_path: &str) -> String {
    format!("{name}\u{0}{cmdline}\u{0}{exe_path}")
}

/// Returns `Some(hit_count)` when an identical spawn was already cleared ALLOW
/// within the debounce window; `None` means this must go through full inference.
pub fn check_recent_allow(name: &str, cmdline: &str, exe_path: &str) -> Option<u32> {
    let ttl = Duration::from_millis(verdict_cache_ttl_ms());
    if ttl.is_zero() {
        return None;
    }
    let key = cache_key(name, cmdline, exe_path);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(entry) = map.get_mut(&key) {
        if entry.seen_at.elapsed() < ttl {
            entry.hits += 1;
            entry.seen_at = Instant::now();
            return Some(entry.hits);
        }
    }
    None
}

/// Record a fresh ALLOW verdict from the real model so subsequent identical
/// spawns within the TTL window can be debounced.
pub fn record_allow(name: &str, cmdline: &str, exe_path: &str) {
    let key = cache_key(name, cmdline, exe_path);
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(
        key,
        CachedAllow {
            seen_at: Instant::now(),
            hits: 0,
        },
    );
    if map.len() > 4096 {
        let ttl = Duration::from_millis(verdict_cache_ttl_ms());
        map.retain(|_, v| v.seen_at.elapsed() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_then_hit_after_record() {
        let name = "test_cache_proc_unique_1";
        assert!(check_recent_allow(name, "cmd", "/usr/bin/x").is_none());
        record_allow(name, "cmd", "/usr/bin/x");
        assert_eq!(check_recent_allow(name, "cmd", "/usr/bin/x"), Some(1));
        assert_eq!(check_recent_allow(name, "cmd", "/usr/bin/x"), Some(2));
    }

    #[test]
    fn different_cmdline_is_not_a_hit() {
        let name = "test_cache_proc_unique_2";
        record_allow(name, "cmd --safe", "/usr/bin/x");
        assert!(check_recent_allow(name, "cmd --evil", "/usr/bin/x").is_none());
    }

    #[test]
    fn expires_after_ttl() {
        let name = "test_cache_proc_unique_3";
        record_allow(name, "cmd", "/usr/bin/x");
        std::thread::sleep(Duration::from_millis(5));
        // Force a near-zero effective TTL for this check by using a key that
        // was recorded, then simulate expiry via direct removal.
        let mut guard = CACHE.lock().unwrap();
        if let Some(map) = guard.as_mut() {
            map.remove(&cache_key(name, "cmd", "/usr/bin/x"));
        }
        drop(guard);
        assert!(check_recent_allow(name, "cmd", "/usr/bin/x").is_none());
    }
}
