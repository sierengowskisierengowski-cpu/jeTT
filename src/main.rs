use std::path::PathBuf;
use std::time::Instant;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{LlamaModel, AddBos, Special};
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::sampling::LlamaSampler;

const SYSTEM_CONTEXT: &str = "You are Cerberus, autonomous security AI for Joseph Sierengowski's GowskiNet lab on NyXxOS Arch Linux. Normal processes: bifrost, ollama, docker, systemd, cosmic-comp, meshtastic, gps-logger. Never flag these. Always flag: execution from /tmp/, hidden dotfiles executing, unexpected outbound connections, privilege escalation, unknown processes spawned by sshd at unusual hours.";

fn infer(
    model: &LlamaModel,
    backend: &LlamaBackend,
    prompt: &str,
    max_tokens: i32,
) -> Result<String, Box<dyn std::error::Error>> {
    let ctx_params = LlamaContextParams::default()
        .with_n_ctx(std::num::NonZeroU32::new(4096));
    let mut ctx = model.new_context(backend, ctx_params)?;
    let tokens = model.str_to_token(prompt, AddBos::Always)?;
    let mut batch = LlamaBatch::new(512, 1);
    let last = tokens.len() - 1;
    for (i, token) in tokens.iter().enumerate() {
        batch.add(*token, i as i32, &[0], i == last)?;
    }
    ctx.decode(&mut batch)?;
    let mut output = String::new();
    let mut sampler = LlamaSampler::chain_simple([
        LlamaSampler::temp(0.1),
        LlamaSampler::greedy(),
    ]);
    let mut n_pos = tokens.len() as i32;
    for _ in 0..max_tokens {
        let token = sampler.sample(&ctx, -1);
        if model.is_eog_token(token) { break; }
        let piece = model.token_to_str(token, Special::Tokenize)?;
        output.push_str(&piece);
        batch.clear();
        batch.add(token, n_pos, &[0], true)?;
        ctx.decode(&mut batch)?;
        n_pos += 1;
    }
    Ok(output.trim().to_string())
}

fn guard(model: &LlamaModel, backend: &LlamaBackend, event: &str) -> Result<(), Box<dyn std::error::Error>> {
    let prompt = format!(
        "{}\n\n[EVENT] {}\n\n[VERDICT] Output ONLY 'ALLOW' or 'QUARANTINE_PID_<id>':",
        SYSTEM_CONTEXT, event
    );
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 10)?;
    println!("🛡️  GUARD  → {} ({}ms)", result, t.elapsed().as_millis());
    Ok(())
}

fn alert(model: &LlamaModel, backend: &LlamaBackend, event: &str) -> Result<(), Box<dyn std::error::Error>> {
    let prompt = format!(
        "{}\n\n[EVENT] {}\n\n[ALERT] One sentence explanation:",
        SYSTEM_CONTEXT, event
    );
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 30)?;
    println!("⚠️   ALERT  → {} ({}ms)", result, t.elapsed().as_millis());
    Ok(())
}

fn query(model: &LlamaModel, backend: &LlamaBackend, question: &str) -> Result<(), Box<dyn std::error::Error>> {
    let prompt = format!(
        "{}\n\n[QUESTION] {}\n\n[ANSWER]:",
        SYSTEM_CONTEXT, question
    );
    let t = Instant::now();
    let result = infer(model, backend, &prompt, 200)?;
    println!("🔍  QUERY  → {} ({}ms)", result, t.elapsed().as_millis());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model_path = PathBuf::from("../../models/granite-3.3-2b-instruct.Q4_K_M.gguf");
    if !model_path.exists() {
        return Err(format!("Model not found: {:?}", model_path).into());
    }

    let backend = LlamaBackend::init()?;
    let model_params = LlamaModelParams::default().with_n_gpu_layers(99);
    let model = LlamaModel::load_from_file(&backend, &model_path, &model_params)?;
    println!("[+] Cerberus Brain online — RTX 3060 GPU\n");

    // TEST 1 — Obvious threat
    guard(&model, &backend, "python3 PID:4821 executed from /tmp/.hidden spawned by sshd uid:1000 time:03:14 outbound connection to 185.220.x.x")?;

    // TEST 2 — Legitimate process
    guard(&model, &backend, "bifrost PID:1204 started by systemd uid:1000 time:22:00 normal startup")?;

    // TEST 3 — Alert explanation
    alert(&model, &backend, "python3 PID:4821 executed from /tmp/.hidden spawned by sshd")?;

    // TEST 4 — Query mode
    query(&model, &backend, "What are signs of a cryptominer on Linux?")?;

    Ok(())
}
