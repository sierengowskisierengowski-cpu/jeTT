use std::time::Instant;
// jeTT shared inference engine — used by both the CLI and the daemon.
// Single source of truth for model loading, inference, verdicts, allowlist.

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::context::LlamaContext;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel, Special};
use llama_cpp_2::sampling::LlamaSampler;
use sha2::{Digest, Sha256};
use std::io::Write as _IoWrite;

pub fn allowlist_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{}/.config/jett/allowlist.txt", home)
}

pub fn hash_file(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

pub fn load_allowlist() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(text) = std::fs::read_to_string(allowlist_path()) {
        for line in text.lines() {
            let h = line.trim();
            if !h.is_empty() && !h.starts_with('#') {
                if let Some(hash) = h.split_whitespace().next() {
                    set.insert(hash.to_string());
                }
            }
        }
    }
    set
}

pub fn trust_binary(path: &str) {
    let Some(hash) = hash_file(path) else {
        eprintln!("[!] Could not read/hash: {}", path);
        std::process::exit(1);
    };
    let ap = allowlist_path();
    if let Some(parent) = std::path::Path::new(&ap).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing = load_allowlist();
    if existing.contains(&hash) {
        println!("Already trusted: {} ({})", path, &hash[..16]);
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&ap) {
        let _ = writeln!(f, "{}  {}", hash, path);
        println!("Trusted: {}", path);
        println!("   SHA-256: {}", hash);
    } else {
        eprintln!("[!] Could not write allowlist at {}", ap);
        std::process::exit(1);
    }
}

pub fn untrust_binary(path: &str) {
    let Some(hash) = hash_file(path) else {
        eprintln!("[!] Could not read/hash: {}", path);
        std::process::exit(1);
    };
    let ap = allowlist_path();
    let Ok(text) = std::fs::read_to_string(&ap) else {
        println!("Allowlist is empty.");
        return;
    };
    let kept: Vec<String> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with(&hash))
        .map(|l| l.to_string())
        .collect();
    let _ = std::fs::write(&ap, kept.join("
") + "
");
    println!("Untrusted: {} ({})", path, &hash[..16]);
}

pub fn list_trusted() {
    match std::fs::read_to_string(allowlist_path()) {
        Ok(text) if !text.trim().is_empty() => {
            println!("jeTT trusted binaries:");
            for line in text.lines() {
                let l = line.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    println!("  {}", l);
                }
            }
        }
        _ => println!("No trusted binaries yet. Add one: jett --trust /path/to/binary"),
    }
}


const SYSTEM_CONTEXT: &str = "You are jeTT — autonomous AI Anti-Virus and Security engine. You protect this system with zero tolerance for threats. ALWAYS ALLOW: bifrost, ollama, docker, systemd, cosmic-comp, meshtastic, gps-logger, cerberus, ghost-relay, cargo build, Govee scripts, rclone, Bambu printer, Flipper Zero, jeTT itself. ALWAYS QUARANTINE: execution from /tmp/, hidden dotfiles executing, unknown processes spawned by sshd at unusual hours, unexpected outbound connections after file downloads, privilege escalation attempts, processes reading /etc/shadow, crypto miners, reverse shells.";

pub fn clean_output(raw: &str) -> String {
    raw.replace("Answer:", "")
        .replace("VERDICT:", "")
        .replace("Final Verdict:", "")
        .replace("Verdict:", "")
        .replace("[VERDICT]", "")
        .replace("[ANSWER]", "")
        .replace("[ALERT]", "")
        .replace("<|assistant|>", "")
        .replace("<|user|>", "")
        .replace("<|system|>", "")
        .trim()
        .to_string()
}

pub fn guard_n_ctx() -> u32 {
    std::env::var("JETT_N_CTX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512)
}

pub fn guard_max_tokens() -> i32 {
    std::env::var("JETT_GUARD_MAX_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6)
}

pub fn new_guard_context(engine: &Engine) -> Result<LlamaContext<'_>, Box<dyn std::error::Error>> {
    let ctx_params = LlamaContextParams::default().with_n_ctx(
        Some(
            std::num::NonZeroU32::new(guard_n_ctx())
                .unwrap_or(std::num::NonZeroU32::MIN),
        ),
    );
    Ok(engine.model.new_context(&engine.backend, ctx_params)?)
}

pub fn infer_on_context(
    ctx: &mut LlamaContext,
    model: &LlamaModel,
    prompt: &str,
    max_tokens: i32,
) -> Result<String, Box<dyn std::error::Error>> {
    ctx.clear_kv_cache();
    let tokens = model.str_to_token(prompt, AddBos::Always)?;
    let n_batch = ctx.n_batch().min(512) as usize;
    let mut batch = LlamaBatch::new(n_batch, 1);
    let last = tokens.len().saturating_sub(1);
    for (i, token) in tokens.iter().enumerate() {
        batch.add(*token, i as i32, &[0], i == last)?;
    }
    ctx.decode(&mut batch)?;
    let mut output = String::new();
    let mut sampler = LlamaSampler::chain_simple([LlamaSampler::temp(0.1), LlamaSampler::greedy()]);
    let mut n_pos = tokens.len() as i32;
    for _ in 0..max_tokens {
        let token = sampler.sample(ctx, -1);
        if model.is_eog_token(token) {
            break;
        }
        let piece = model.token_to_str(token, Special::Tokenize)?;
        output.push_str(&piece);
        batch.clear();
        batch.add(token, n_pos, &[0], true)?;
        ctx.decode(&mut batch)?;
        n_pos += 1;
    }
    Ok(clean_output(&output))
}

pub fn infer(
    model: &LlamaModel,
    backend: &LlamaBackend,
    prompt: &str,
    max_tokens: i32,
) -> Result<String, Box<dyn std::error::Error>> {
    let ctx_params = LlamaContextParams::default().with_n_ctx(Some(
        std::num::NonZeroU32::new(4096).unwrap_or(std::num::NonZeroU32::MIN),
    ));
    let mut ctx = model.new_context(backend, ctx_params)?;
    infer_on_context(&mut ctx, model, prompt, max_tokens)
}

pub fn guard(
    ctx: &mut LlamaContext,
    model: &LlamaModel,
    event: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    ctx.clear_kv_cache();
    let prompt = format!(
        "You are jeTT, a security classifier. Analyze this process event and respond with EXACTLY ONE WORD: either QUARANTINE (if malicious/suspicious) or ALLOW (if legitimate). Do not explain. Do not add detail.\n\n[EVENT] {}\n\nVERDICT:",
        event
    );
    // Pre-check: ONLY trust immutable system paths + known toolchain dirs.
    // $HOME is deliberately NOT blanket-trusted — it is attacker-writable.
    // SECURITY: we extract ONLY the real exe path and match it as a PREFIX.
    // We do NOT substring-match the whole event — that let an attacker
    // whitelist malware just by putting "/usr/" anywhere in an argument.
    let home = std::env::var("HOME").unwrap_or_default();
    let cargo_dir = format!("{}/.cargo/", home);
    let rustup_dir = format!("{}/.rustup/", home);
    let trusted_prefixes = [
        "/usr/",
        "/etc/systemd/",
        "/opt/",
        cargo_dir.as_str(),
        rustup_dir.as_str(),
    ];

    let exe_path = event
        .split("exe:")
        .nth(1)
        .and_then(|s| s.split(" cmd:").next())
        .unwrap_or("")
        .trim();

    let exe_name = exe_path.rsplit('/').next().unwrap_or("");
    let is_interpreter = crate::telemetry::matches_never_fast_trust(exe_name);

    if !is_interpreter {
        for prefix in &trusted_prefixes {
            if exe_path.starts_with(prefix) {
                println!("\u{1f6e1}\u{fe0f}  GUARD  \u{2192} \u{2705} ALLOW | raw: TRUSTED_PATH (0ms)");
                return Ok("ALLOW".to_string());
            }
        }

        if !exe_path.is_empty() {
            if let Some(hash) = hash_file(exe_path) {
                if load_allowlist().contains(&hash) {
                    println!("\u{1f6e1}\u{fe0f}  GUARD  \u{2192} \u{2705} ALLOW | raw: TRUSTED_HASH (0ms)");
                    return Ok("ALLOW".to_string());
                }
            }
        }
    }


    let t = Instant::now();
    let result = infer_on_context(ctx, model, &prompt, guard_max_tokens())?;
    let up = result.to_uppercase();
    let verdict = if up.contains("QUARANTINE")
        || up.contains("MALICIOUS")
        || up.contains("SUSPICIOUS")
        || up.contains("HIGH-RISK")
        || up.contains("THREAT")
        || up.contains("TARGET HOST")
        || up.contains("OUTBOUND CONNECTION")
        || up.contains("ANOMALOUS")
        || up.contains("EXECUTION PATH")
        || up.contains("SHELLCODE")
        || up.contains("INJECTION")
        || up.contains("MINER")
        || up.contains("CRYPTO")
        || up.contains("REVERSE SHELL")
        || up.contains("EXPLOIT")
        || up.contains("BACKDOOR")
        || up.contains("ROOTKIT")
        || up.contains("PAYLOAD")
        || up.contains("PRIVILEGE ESCALATION")
        || up.contains("UNAUTHORIZED")
        || up.contains("POLYMORPHIC")
        || up.contains("OBFUSCAT")
        || up.contains("C2")
        || up.contains("EXFILTRAT")
    {
        format!("🚨 QUARANTINE")
    } else if up.contains("AUTHORIZED")
        || up.contains("LEGITIMATE")
        || up.contains("TRUSTED")
        || up.contains("ALLOW")
        || up.contains("NORMAL")
        || up.contains("NO MALICIOUS")
        || up.contains("GOWSKINET")
        || up.contains("BOOT SEQUENCE")
        || up.contains("NATIVE LINUX")
        || up.contains("AUTHORIZED ADMIN")
        || up.contains("SAFE")
        || up.contains("SCRIPTS")
        || up.contains("UTILITIES")
        || up.contains("/HOME/COSMIC")
        || up.contains("USER DIRECTORY")
        || up.contains("NON-STANDARD USER")
    {
        format!("✅ ALLOW")
    } else {
        format!("⚠️  REVIEW")
    };
    // Build the human-readable reason from the REAL behavioral facts in the
    // event — NOT from the model's prose. The model decides (verdict); our
    // code explains using ground truth we actually collected. This makes every
    // logged reason factually true and eliminates hallucinated explanations.
    let reason = build_factual_reason(event, &verdict);
    println!(
        "🛡️  GUARD  → {} | {} ({}ms)",
        verdict,
        reason,
        t.elapsed().as_millis()
    );
    // Return "VERDICT | factual-reason": verdict drives the kill decision,
    // the fact-based reason is logged for forensics.
    Ok(format!("{} | {}", verdict, reason))
}

/// Build a factual reason string from the actual event data, not model prose.
/// Pulls the real behavioral signals the daemon collected and the launch path.
fn build_factual_reason(event: &str, verdict: &str) -> String {
    let mut facts: Vec<String> = Vec::new();

    // Extract the launch path
    if let Some(after) = event.split("exe:").nth(1) {
        if let Some(path) = after.split(" cmd:").next() {
            let p = path.trim();
            if p.starts_with("/tmp/") || p.contains("/.cache/")
                || p.starts_with("/var/tmp/") || p.contains("/Downloads/")
                || p.starts_with("/dev/shm/") {
                facts.push(format!("executed from suspicious path {}", p));
            }
        }
    }

    // Extract real outbound connections (collected from /proc)
    if let Some(after) = event.split("outbound_connections:[").nth(1) {
        if let Some(conns) = after.split(']').next() {
            if !conns.is_empty() {
                facts.push(format!("outbound connections to [{}]", conns));
            }
        }
    }

    // Extract real sensitive file access
    if let Some(after) = event.split("sensitive_files:[").nth(1) {
        if let Some(files) = after.split(']').next() {
            if !files.is_empty() {
                facts.push(format!("accessed sensitive files [{}]", files));
            }
        }
    }

    // Extract real spawned children
    if let Some(after) = event.split("spawned_children:[").nth(1) {
        if let Some(kids) = after.split(']').next() {
            if !kids.is_empty() {
                facts.push(format!("spawned child processes [{}]", kids));
            }
        }
    }

    if facts.is_empty() {
        if verdict.contains("QUARANTINE") {
            "flagged by model on launch profile".to_string()
        } else {
            "no suspicious behavior observed".to_string()
        }
    } else {
        facts.join("; ")
    }
}

pub fn alert(
    model: &LlamaModel,
    backend: &LlamaBackend,
    event: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prompt = format!(
        "You are jeTT, the GowskiNet AI cybersecurity engine.\n\n[EVENT] {}\n\nIn one sentence explain why this is suspicious or safe:\n",
        event
    );
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 25)?;
    println!("⚠️   ALERT  → {} ({}ms)", result, t.elapsed().as_millis());
    Ok(())
}

pub fn query(
    model: &LlamaModel,
    backend: &LlamaBackend,
    question: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prompt = format!(
        "{}\n\n[QUESTION] {}\n\n[ANSWER]:\n",
        SYSTEM_CONTEXT, question
    );
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 500)?;
    println!("🔍  QUERY  → {} ({}ms)", result, t.elapsed().as_millis());
    Ok(())
}

use std::path::PathBuf;

pub struct Engine {
    pub backend: LlamaBackend,
    pub model: LlamaModel,
}

pub fn load_model(model_path: &str) -> Result<Engine, Box<dyn std::error::Error>> {
    let backend = LlamaBackend::init()?;
    let params = LlamaModelParams::default().with_n_gpu_layers(99);
    let model = LlamaModel::load_from_file(&backend, &PathBuf::from(model_path), &params)?;
    Ok(Engine { backend, model })
}
