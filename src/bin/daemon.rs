use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::collections::HashSet;

// ─────────────────────────────────────────────
// jeTT Daemon — Real System Event Monitor
// Watches /proc, auditd, and system logs
// Feeds events to jeTT AI engine for verdicts
// ─────────────────────────────────────────────



const LOG_DIR: &str = "/var/log/jett";
const QUARANTINE_DIR: &str = "/var/jett/quarantine";
const VERSION: &str = "1.0.0";

// Trusted paths — instant ALLOW, no AI needed
const TRUSTED_PATHS: &[&str] = &[
    "/home/",  // matches any user home directory
    "/usr/bin/",
    "/usr/lib/",
    "/usr/share/",
    "/etc/systemd/",
    "/opt/",
    "/home/",
    "/opt/jett/",
];

// Trusted process names — instant ALLOW
const TRUSTED_PROCS: &[&str] = &[
    "bifrost", "ollama", "docker", "cowrie", "prometheus", "grafana",
    "loki", "promtail", "portainer", "mosquitto", "cosmic-comp",
    "cargo", "rclone", "meshtastic", "gni_server", "systemd",
    "sshd", "python3", "node", "pacman", "yay", "jett",
    "wireguard", "wg", "bash", "zsh", "tmux", "screen",
];

// Suspicious indicators — immediate flag for AI analysis
const SUSPICIOUS_INDICATORS: &[&str] = &[
    "/tmp/.",
    "/dev/shm/",
    "memfd_create",
    "/proc/self/mem",
    "LD_PRELOAD",
    "/etc/shadow",
    "/etc/passwd",
    "chmod +x /tmp",
    "curl.*|.*sh",
    "wget.*|.*sh",
    "nc -e",
    "netcat.*-e",
    "python.*socket.*exec",
    "base64.*decode.*exec",
    "insmod /tmp",
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

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_time(ts: u64) -> String {
    // Simple timestamp formatting
    format!("{}", ts)
}

fn read_proc_info(pid: u32) -> Option<ProcessEvent> {
    let proc_path = format!("/proc/{}", pid);
    
    // Read process name
    let name = fs::read_to_string(format!("{}/comm", proc_path))
        .unwrap_or_default()
        .trim()
        .to_string();
    
    if name.is_empty() {
        return None;
    }

    // Read cmdline
    let cmdline = fs::read(format!("{}/cmdline", proc_path))
        .unwrap_or_default()
        .iter()
        .map(|&b| if b == 0 { b' ' } else { b })
        .collect::<Vec<u8>>();
    let cmdline = String::from_utf8_lossy(&cmdline).trim().to_string();

    // Read exe path
    let exe_path = fs::read_link(format!("{}/exe", proc_path))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // Read UID from status
    let uid = fs::read_to_string(format!("{}/status", proc_path))
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Some(ProcessEvent {
        pid,
        name,
        cmdline,
        exe_path,
        uid,
        timestamp: get_timestamp(),
    })
}

fn is_trusted(event: &ProcessEvent) -> bool {
    // Check trusted process names
    for trusted in TRUSTED_PROCS {
        if event.name.contains(trusted) || event.cmdline.contains(trusted) {
            return true;
        }
    }
    
    // Check trusted paths
    for path in TRUSTED_PATHS {
        if event.exe_path.starts_with(path) || event.cmdline.contains(path) {
            return true;
        }
    }
    
    false
}

fn is_suspicious(event: &ProcessEvent) -> bool {
    let combined = format!("{} {} {}", event.name, event.cmdline, event.exe_path).to_lowercase();
    
    for indicator in SUSPICIOUS_INDICATORS {
        if combined.contains(&indicator.to_lowercase()) {
            return true;
        }
    }
    
    // Execution from /tmp
    if event.exe_path.starts_with("/tmp") || event.exe_path.starts_with("/dev/shm") {
        return true;
    }
    
    // Hidden file execution
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

fn log_verdict(verdict: &JettVerdict) {
    let log_line = format!(
        "[{}] {} PID:{} → {} ({}) {}ms\n",
        verdict.event.timestamp,
        verdict.event.name,
        verdict.event.pid,
        verdict.verdict,
        verdict.reason.chars().take(80).collect::<String>(),
        verdict.elapsed_ms,
    );
    
    // Print to stdout
    println!("{}", log_line.trim());
    
    // Write to log file
    let log_path = format!("{}/jett.log", LOG_DIR);
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        use std::io::Write;
        let _ = file.write_all(log_line.as_bytes());
    }
    
    // If quarantine, write to quarantine log
    if verdict.verdict.contains("QUARANTINE") {
        let quarantine_log = format!("{}/quarantine.log", QUARANTINE_DIR);
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&quarantine_log)
        {
            use std::io::Write;
            let entry = format!(
                "[{}] PID:{} NAME:{} EXE:{} CMD:{} REASON:{}\n",
                verdict.event.timestamp,
                verdict.event.pid,
                verdict.event.name,
                verdict.event.exe_path,
                verdict.event.cmdline.chars().take(200).collect::<String>(),
                verdict.reason.chars().take(200).collect::<String>(),
            );
            let _ = file.write_all(entry.as_bytes());
        }
        
        // Send desktop notification
        let _ = Command::new("notify-send")
            .args(&[
                "--urgency=critical",
                "--icon=security-high",
                "🚨 jeTT QUARANTINE",
                &format!("PID:{} {} - {}", verdict.event.pid, verdict.event.name, 
                    verdict.reason.chars().take(60).collect::<String>()),
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
        
        let mut seen = seen_pids.lock().unwrap();
        if seen.contains(&pid) {
            continue;
        }
        seen.insert(pid);
        drop(seen);
        
        if let Some(event) = read_proc_info(pid) {
            new_events.push(event);
        }
    }
    
    new_events
}

fn cleanup_dead_pids(seen_pids: &Arc<Mutex<HashSet<u32>>>) {
    let mut seen = seen_pids.lock().unwrap();
    seen.retain(|&pid| Path::new(&format!("/proc/{}", pid)).exists());
}

fn main() {
    println!("╔═══════════════════════════════════════════╗");
    println!("║   jeTT Daemon v{}                       ║", VERSION);
    println!("║   GowskiNet AI Security Monitor           ║");
    println!("║   IBM Granite 3.3 2B — RTX 3060           ║");
    println!("╚═══════════════════════════════════════════╝");
    println!();

    // Create directories
    for dir in &[LOG_DIR, QUARANTINE_DIR] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("[!] Could not create {}: {} (try: sudo mkdir -p {})", dir, e, dir);
        }
    }

    println!("[*] Loading jeTT AI model...");
    let model_path = std::env::var("JETT_MODEL").unwrap_or_else(|_| "/opt/jett/models/jeTT-q4.gguf".to_string());
    println!("[*] Model: {}", model_path);
    
    if !Path::new(&model_path).exists() {
        eprintln!("[!] Model not found: {}", model_path);
        std::process::exit(1);
    }

    // NOTE: In production this would load the llama model here
    // For now we use the guard/alert/query binary via subprocess
    // Full Rust integration would use llama_cpp_2 directly
    
    println!("[✅] jeTT daemon started — watching /proc for new processes");
    println!("[*] Logs: {}", LOG_DIR);
    println!("[*] Quarantine: {}", QUARANTINE_DIR);
    println!("[*] Press Ctrl+C to stop\n");

    let seen_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    
    // Initial scan — populate seen_pids with existing processes (don't alert on boot procs)
    println!("[*] Initial process scan...");
    let initial_events = scan_new_processes(&seen_pids);
    println!("[*] Found {} existing processes — these will be skipped", initial_events.len());
    println!("[*] Now monitoring for NEW processes...\n");

    let mut loop_count = 0u64;
    
    loop {
        // Scan for new processes
        let new_events = scan_new_processes(&seen_pids);
        
        for event in new_events {
            // Skip kernel threads (no exe path)
            if event.exe_path.is_empty() || event.exe_path.contains("(deleted)") {
                continue;
            }
            
            let t = Instant::now();
            
            // Fast path: trusted process
            if is_trusted(&event) {
                let verdict = JettVerdict {
                    verdict: "✅ ALLOW".to_string(),
                    reason: "Trusted GowskiNet process".to_string(),
                    elapsed_ms: t.elapsed().as_millis() as u64,
                    event,
                };
                // Only log non-trivial trusted processes
                if verdict.event.uid == 1000 {
                    log_verdict(&verdict);
                }
                continue;
            }
            
            // Fast path: suspicious indicators
            if is_suspicious(&event) {
                let event_str = format_event_for_ai(&event);
                println!("🚨 [SUSPICIOUS DETECTED] {} — sending to AI...", event.name);
                
                // Call jeTT binary for AI verdict
                let output = Command::new(std::env::var("JETT_BIN").unwrap_or_else(|_| format!("{}/Projects/jeTT/target/release/jeTT", std::env::var("HOME").unwrap_or_default())))
                    .arg("--guard")
                    .arg(&event_str)
                    .output();
                
                let reason = match output {
                    Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
                    Err(_) => "Suspicious path execution".to_string(),
                };
                
                let verdict = JettVerdict {
                    verdict: "🚨 QUARANTINE".to_string(),
                    reason,
                    elapsed_ms: t.elapsed().as_millis() as u64,
                    event,
                };
                log_verdict(&verdict);
                continue;
            }
            
            // Unknown process — log for review
            let verdict = JettVerdict {
                verdict: "⚠️  REVIEW".to_string(),
                reason: format!("Unknown process: {}", event.exe_path),
                elapsed_ms: t.elapsed().as_millis() as u64,
                event,
            };
            log_verdict(&verdict);
        }
        
        // Cleanup dead PIDs every 60 seconds
        loop_count += 1;
        if loop_count % 60 == 0 {
            cleanup_dead_pids(&seen_pids);
        }
        
        thread::sleep(Duration::from_millis(100));
    }
}
