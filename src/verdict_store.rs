//! Durable, append-only verdict + mode-transition store for jeTT.
//!
//! This module gives jeTT a persistent record of the verdicts it emits and of
//! the effective enforcement mode it runs under. It has ZERO extra dependencies
//! (only `serde_json`, already in the tree, and `std`), so it never jeopardises
//! the CUDA build.
//!
//! Two artifacts are written:
//!
//!   1. Verdict store (Tier-3 verdict history) — one JSON object per line:
//!        $JETT_VERDICT_STORE            (env override), else
//!        <state>/jett/verdicts.jsonl
//!      Fields: ts, pid, process, path, uid, verdict, kind, confidence,
//!              technique[], reason, evidence[], mode, enforce_mode,
//!              elapsed_ms, source. Append-only, size-rotated.
//!
//!   2. Mode-transition log (for the Bifrost "how long in learn/live" counter):
//!        $JETT_MODE_HISTORY             (env override), else
//!        <nyxus_state>/jett-mode-history.log
//!      One JSON object per line: {"ts":<unix>,"mode":"learn|enforce-dry-run|
//!      enforce","enforce_mode":bool,"pid":<u32>,"event":"startup|change"}.
//!      A record is appended only when the effective mode differs from the last
//!      recorded mode (plus one "startup" marker on first run).
//!
//! `<state>` resolves to `/var/lib` when that is writable (the daemon runs as
//! root, and /var/lib is world-readable so the Bifrost guardian — possibly a
//! different uid — can read the store), otherwise `$HOME/.local/share`.

use serde_json::json;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::telemetry::{EventSource, ProcessEvent};
use crate::tier7_hooks::Tier7Outcome;

/// Rotate the verdict store once it exceeds this size.
const VERDICT_ROTATE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
/// Number of rotated verdict files to keep (verdicts.jsonl.1 .. .N).
const VERDICT_KEEP: usize = 3;

static EFFECTIVE_MODE: OnceLock<String> = OnceLock::new();

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Resolve a per-application state directory, preferring a shared world-readable
/// location so cross-service consumers (Bifrost guardian) can read it.
fn state_dir(sub: &str) -> PathBuf {
    // Prefer /var/lib/<sub> when we can create it (root daemon). This keeps the
    // store readable by the Bifrost guardian regardless of which uid it runs as.
    let shared = PathBuf::from("/var/lib").join(sub);
    if fs::create_dir_all(&shared).is_ok() {
        let _ = fs::set_permissions(&shared, fs::Permissions::from_mode(0o755));
        return shared;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let dir = PathBuf::from(home).join(".local/share").join(sub);
    let _ = fs::create_dir_all(&dir);
    dir
}

fn verdict_store_path() -> PathBuf {
    if let Ok(p) = std::env::var("JETT_VERDICT_STORE") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    state_dir("jett").join("verdicts.jsonl")
}

fn mode_history_path() -> PathBuf {
    if let Ok(p) = std::env::var("JETT_MODE_HISTORY") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    state_dir("nyxus").join("jett-mode-history.log")
}

/// Normalize the emoji verdict label into a stable machine-readable kind.
fn verdict_kind(label: &str) -> &'static str {
    let up = label.to_uppercase();
    if up.contains("WOULD-QUARANTINE") || up.contains("WOULD QUARANTINE") {
        "would_quarantine"
    } else if up.contains("QUARANTINE") {
        "quarantine"
    } else if up.contains("ALLOW") {
        "allow"
    } else if up.contains("REVIEW") {
        "review"
    } else if up.contains("CONTAIN") {
        "contain"
    } else {
        "other"
    }
}

fn source_label(source: EventSource) -> &'static str {
    match source {
        EventSource::Proc => "proc",
        EventSource::Ebpf => "ebpf",
    }
}

fn append_line(path: &PathBuf, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(line.as_bytes()) {
                eprintln!("[jett] verdict_store append failed ({}): {}", path.display(), e);
            }
            // World-readable so the Bifrost guardian can ingest it.
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }
        Err(e) => {
            eprintln!("[jett] verdict_store open failed ({}): {}", path.display(), e);
        }
    }
}

/// Rotate `verdicts.jsonl` -> `.1` -> `.2` ... when it grows past the limit.
fn rotate_if_needed(path: &PathBuf) {
    let too_big = fs::metadata(path)
        .map(|m| m.len() >= VERDICT_ROTATE_BYTES)
        .unwrap_or(false);
    if !too_big {
        return;
    }
    // Drop the oldest, then shift each file up by one.
    let oldest = PathBuf::from(format!("{}.{}", path.display(), VERDICT_KEEP));
    let _ = fs::remove_file(&oldest);
    for i in (1..VERDICT_KEEP).rev() {
        let from = PathBuf::from(format!("{}.{}", path.display(), i));
        let to = PathBuf::from(format!("{}.{}", path.display(), i + 1));
        if from.exists() {
            let _ = fs::rename(&from, &to);
        }
    }
    let first = PathBuf::from(format!("{}.1", path.display()));
    let _ = fs::rename(path, &first);
}

/// Record the effective enforcement mode for later verdict records. Called once
/// at daemon startup after the mode is resolved.
pub fn set_effective_mode(mode: &str) {
    let _ = EFFECTIVE_MODE.set(mode.to_string());
}

fn effective_mode() -> String {
    EFFECTIVE_MODE
        .get()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

/// Append a structured verdict record to the durable verdict store.
///
/// This is best-effort: any I/O error is logged to stderr and swallowed so it
/// can never interfere with the detection/enforcement hot path.
pub fn record_verdict(
    event: &ProcessEvent,
    verdict_label: &str,
    reason: &str,
    elapsed_ms: u64,
    enforce_mode: bool,
    outcome: &Tier7Outcome,
) {
    let path = verdict_store_path();
    rotate_if_needed(&path);

    let reason_trunc: String = reason.chars().take(240).collect();
    let record = json!({
        "ts": now_unix(),
        "pid": event.pid,
        "process": event.name,
        "path": event.exe_path,
        "uid": event.uid,
        "verdict": verdict_label,
        "kind": verdict_kind(verdict_label),
        "confidence": outcome.confidence.value,
        "technique": outcome.explanation.chain_ids,
        "reason": reason_trunc,
        "evidence": outcome.explanation.evidence_refs,
        "mode": effective_mode(),
        "enforce_mode": enforce_mode,
        "elapsed_ms": elapsed_ms,
        "source": source_label(event.source),
    });

    append_line(&path, &format!("{}\n", record));
}

/// Read the `mode` field from the last non-empty line of the mode-history log.
fn last_recorded_mode(path: &PathBuf) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(mode) = value.get("mode").and_then(|m| m.as_str()) {
                return Some(mode.to_string());
            }
        }
    }
    None
}

/// Append a mode-transition record iff the effective mode changed since the last
/// recorded entry (or on first run). Enables Bifrost's mode-duration counter.
///
/// `mode` MUST be the TRUE effective mode (e.g. the systemd drop-in override
/// wins over /etc/default/jett), not the nominal configured value.
pub fn log_mode_transition(mode: &str, enforce_mode: bool) {
    let path = mode_history_path();
    let previous = last_recorded_mode(&path);
    let is_first = previous.is_none();
    if previous.as_deref() == Some(mode) {
        return; // unchanged — nothing to record
    }

    let record = json!({
        "ts": now_unix(),
        "mode": mode,
        "enforce_mode": enforce_mode,
        "pid": std::process::id(),
        "event": if is_first { "startup" } else { "change" },
        "previous_mode": previous,
    });
    append_line(&path, &format!("{}\n", record));
    println!(
        "[*] mode-history: recorded effective mode '{}' ({}) -> {}",
        mode,
        if is_first { "startup" } else { "change" },
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_kind_maps_labels() {
        assert_eq!(verdict_kind("🟡 WOULD-QUARANTINE"), "would_quarantine");
        assert_eq!(verdict_kind("🚨 QUARANTINE | hard rule"), "quarantine");
        assert_eq!(verdict_kind("✅ ALLOW"), "allow");
        assert_eq!(verdict_kind("⚠️  REVIEW"), "review");
    }

    #[test]
    fn mode_transition_dedupes(/* uses a temp path via env override */) {
        let tmp = std::env::temp_dir().join(format!("jett-mode-test-{}.log", std::process::id()));
        let _ = fs::remove_file(&tmp);
        std::env::set_var("JETT_MODE_HISTORY", &tmp);

        log_mode_transition("learn", false);
        log_mode_transition("learn", false); // dup — should be ignored
        log_mode_transition("enforce", true);

        let text = fs::read_to_string(&tmp).unwrap_or_default();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "only two transitions should be recorded");
        assert!(lines[0].contains("\"startup\""));
        assert!(lines[1].contains("\"change\""));

        std::env::remove_var("JETT_MODE_HISTORY");
        let _ = fs::remove_file(&tmp);
    }
}
