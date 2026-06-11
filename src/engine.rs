use std::time::Instant;
// jeTT shared inference engine — used by both the CLI and the daemon.
// Single source of truth for model loading, inference, verdicts, allowlist.

use llama_cpp_2::context::params::LlamaContextParams;
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

pub fn infer(
    model: &LlamaModel,
    backend: &LlamaBackend,
    prompt: &str,
    max_tokens: i32,
) -> Result<String, Box<dyn std::error::Error>> {
    let ctx_params = LlamaContextParams::default().with_n_ctx(std::num::NonZeroU32::new(4096));
    let mut ctx = model.new_context(backend, ctx_params)?;
    let tokens = model.str_to_token(prompt, AddBos::Always)?;
    let mut batch = LlamaBatch::new(512, 1);
    let last = tokens.len() - 1;
    for (i, token) in tokens.iter().enumerate() {
        batch.add(*token, i as i32, &[0], i == last)?;
    }
    ctx.decode(&mut batch)?;
    let mut output = String::new();
    let mut sampler = LlamaSampler::chain_simple([LlamaSampler::temp(0.1), LlamaSampler::greedy()]);
    let mut n_pos = tokens.len() as i32;
    for _ in 0..max_tokens {
        let token = sampler.sample(&ctx, -1);
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

pub fn guard(
    model: &LlamaModel,
    backend: &LlamaBackend,
    event: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        "You are jeTT, the GowskiNet AI cybersecurity engine.\n\n[EVENT] {}\n\nREQUIRED TACTICAL VERDICT:\nAnalysis Matrix:\n- Pattern Recognition:",
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
    // Pull out just the exe path from "...exe:/real/path cmd:..."
    let exe_path = event
        .split("exe:")
        .nth(1)
        .and_then(|s| s.split(" cmd:").next())
        .unwrap_or("")
        .trim();
    for prefix in &trusted_prefixes {
        if exe_path.starts_with(prefix) {
            println!("🛡️  GUARD  → ✅ ALLOW | raw: TRUSTED_PATH (0ms)");
            return Ok("ALLOW".to_string());
        }
    }
    // Hash-based allowlist: a binary trusted by SHA-256 is allowed no matter
    // where it runs from. Path can be faked; the hash cannot.
    if !exe_path.is_empty() {
        if let Some(hash) = hash_file(exe_path) {
            if load_allowlist().contains(&hash) {
                println!("\u{1f6e1}\u{fe0f}  GUARD  \u{2192} \u{2705} ALLOW | raw: TRUSTED_HASH (0ms)");
                return Ok("ALLOW".to_string());
            }
        }
    }
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 25)?;
    let verdict = if result.to_uppercase().contains("QUARANTINE")
        || result.to_uppercase().contains("MALICIOUS")
        || result.to_uppercase().contains("SUSPICIOUS")
        || result.to_uppercase().contains("HIGH-RISK")
        || result.to_uppercase().contains("THREAT")
        || result.to_uppercase().contains("TARGET HOST")
        || result.to_uppercase().contains("OUTBOUND CONNECTION")
        || result.to_uppercase().contains("ANOMALOUS")
        || result.to_uppercase().contains("EXECUTION PATH")
    {
        format!("🚨 QUARANTINE")
    } else if result.to_uppercase().contains("AUTHORIZED")
        || result.to_uppercase().contains("LEGITIMATE")
        || result.to_uppercase().contains("TRUSTED")
        || result.to_uppercase().contains("ALLOW")
        || result.to_uppercase().contains("NORMAL")
        || result.to_uppercase().contains("NO MALICIOUS")
        || result.to_uppercase().contains("GOWSKINET")
        || result.to_uppercase().contains("BOOT SEQUENCE")
        || result.to_uppercase().contains("NATIVE LINUX")
        || result.to_uppercase().contains("AUTHORIZED ADMIN")
        || result.to_uppercase().contains("SAFE")
        || result.to_uppercase().contains("SCRIPTS")
        || result.to_uppercase().contains("UTILITIES")
        || result.to_uppercase().contains("/HOME/COSMIC")
        || result.to_uppercase().contains("USER DIRECTORY")
        || result.to_uppercase().contains("NON-STANDARD USER")
    {
        format!("✅ ALLOW")
    } else {
        format!("⚠️  REVIEW")
    };
    println!(
        "🛡️  GUARD  → {} | raw: {} ({}ms)",
        verdict,
        result,
        t.elapsed().as_millis()
    );
    Ok(result)
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
