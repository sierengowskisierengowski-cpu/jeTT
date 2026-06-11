use std::path::PathBuf;
use std::time::Instant;

const DEFAULT_BRAND_MODEL: &str = "IBM Granite 3.3 2B";
const DEFAULT_BRAND_HARDWARE: &str = "RTX 3060";
const BANNER_CONTENT_WIDTH: usize = 35;

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
    println!("║ {:<35} ║", rendered);
}

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel, Special};
use llama_cpp_2::sampling::LlamaSampler;

const SYSTEM_CONTEXT: &str = "You are jeTT — autonomous AI Anti-Virus and Security engine. You protect this system with zero tolerance for threats. ALWAYS ALLOW: bifrost, ollama, docker, systemd, cosmic-comp, meshtastic, gps-logger, cerberus, ghost-relay, cargo build, Govee scripts, rclone, Bambu printer, Flipper Zero, jeTT itself. ALWAYS QUARANTINE: execution from /tmp/, hidden dotfiles executing, unknown processes spawned by sshd at unusual hours, unexpected outbound connections after file downloads, privilege escalation attempts, processes reading /etc/shadow, crypto miners, reverse shells.";

fn clean_output(raw: &str) -> String {
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

fn infer(
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

fn guard(
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

fn alert(
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

fn query(
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

enum RunMode {
    Demo,
    Cli { flag: String, payload: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mode = if args.len() > 1 {
        let f = &args[1];
        if f == "--guard" || f == "--alert" || f == "--query" {
            if args.len() != 3 {
                eprintln!(
                    "Error: Flag {} requires exactly one payload string argument.",
                    f
                );
                eprintln!("Usage: jeTT [--guard | --alert | --query] <payload>");
                std::process::exit(1);
            }
            RunMode::Cli {
                flag: f.clone(),
                payload: args[2].clone(),
            }
        } else if f == "--help" || f == "-h" {
            println!("jeTT — Local AI EDR Engine");
            println!("Usage:");
            println!("  jeTT                              Run the built-in demo test suite");
            println!("  jeTT --guard <event>              Run guard evaluation on a process event");
            println!("  jeTT --alert <event>              Explain a security threat alert in one sentence");
            println!("  jeTT --query <question>           Execute an offline prompt query");
            return Ok(());
        } else {
            eprintln!("Error: Unknown flag: {}", f);
            eprintln!("Usage: jeTT [--guard | --alert | --query] <payload>");
            std::process::exit(1);
        }
    } else {
        RunMode::Demo
    };

    // Determine default model path safely
    let model_path = if let Ok(jett_model) = std::env::var("JETT_MODEL") {
        PathBuf::from(jett_model)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(format!("{}/Projects/jeTT/models/jeTT-r3-q4.gguf", home))
    } else {
        PathBuf::from("models/jeTT-r3-q4.gguf")
    };

    if !model_path.exists() {
        return Err(format!("Model not found: {:?}", model_path).into());
    }

    let backend = LlamaBackend::init()?;
    let model_params = LlamaModelParams::default().with_n_gpu_layers(99);
    let model = LlamaModel::load_from_file(&backend, &model_path, &model_params)?;

    match mode {
        RunMode::Cli { flag, payload } => match flag.as_str() {
            "--guard" => {
                guard(&model, &backend, &payload)?;
            }
            "--alert" => {
                alert(&model, &backend, &payload)?;
            }
            "--query" => {
                query(&model, &backend, &payload)?;
            }
            _ => unreachable!("Invalid CLI flag matched after validation"),
        },
        RunMode::Demo => {
            println!("╔═══════════════════════════════════════╗");
            print_banner_line("jeTT — AI Anti-Virus & Security");
            print_banner_line(&format!(
                "{} — {}",
                get_env_or_default("JETT_BRAND_MODEL", DEFAULT_BRAND_MODEL),
                get_env_or_default("JETT_BRAND_HARDWARE", DEFAULT_BRAND_HARDWARE),
            ));
            print_banner_line("GowskiNet Security Lab");
            println!("╚═══════════════════════════════════════╝");
            println!();

            // TEST 1 — Obvious threat
            println!("--- TEST 1: Obvious Threat ---");
            guard(&model, &backend, "python3 PID:4821 executed from /tmp/.hidden spawned by sshd uid:1000 time:03:14 made outbound connection to 185.220.x.x")?;

            // TEST 2 — Legitimate process
            println!("\n--- TEST 2: Legitimate Process ---");
            guard(
                &model,
                &backend,
                "bifrost PID:1204 started by systemd uid:1000 time:22:00 normal startup sequence",
            )?;

            // TEST 3 — Gray area
            println!("\n--- TEST 3: Gray Area ---");
            guard(&model, &backend, &format!("python3 PID:3301 running govee-art.sh from {}/Scripts/utilities/ time:23:30 uid:1000", std::env::var("HOME").unwrap_or_default()))?;

            // TEST 4 — Alert mode
            println!("\n--- TEST 4: Alert Mode ---");
            alert(
                &model,
                &backend,
                "curl downloaded ELF binary to /tmp/ then chmod +x and executed it",
            )?;

            // TEST 5 — Query mode
            println!("\n--- TEST 5: Query Mode ---");
            query(
                &model,
                &backend,
                "What are the top signs of a cryptominer on a Linux system?",
            )?;
        }
    }

    Ok(())
}
