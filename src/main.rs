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


use jeTT::engine::{guard, alert, query, trust_binary, untrust_binary, list_trusted, load_model};


enum RunMode {
    Demo,
    Cli { flag: String, payload: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Allowlist management commands — handled before loading the model.
    if args.len() > 1 {
        match args[1].as_str() {
            "--trust" => {
                if args.len() != 3 {
                    eprintln!("Usage: jett --trust /path/to/binary");
                    std::process::exit(1);
                }
                trust_binary(&args[2]);
                return Ok(());
            }
            "--untrust" => {
                if args.len() != 3 {
                    eprintln!("Usage: jett --untrust /path/to/binary");
                    std::process::exit(1);
                }
                untrust_binary(&args[2]);
                return Ok(());
            }
            "--list-trusted" => {
                list_trusted();
                return Ok(());
            }
            _ => {}
        }
    }

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

    let engine = load_model(&model_path.to_string_lossy())?;
    let model = &engine.model;
    let backend = &engine.backend;

    match mode {
        RunMode::Cli { flag, payload } => match flag.as_str() {
            "--guard" => {
                guard(model, backend, &payload)?;
            }
            "--alert" => {
                alert(model, backend, &payload)?;
            }
            "--query" => {
                query(model, backend, &payload)?;
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
            guard(model, backend, "python3 PID:4821 executed from /tmp/.hidden spawned by sshd uid:1000 time:03:14 made outbound connection to 185.220.x.x")?;

            // TEST 2 — Legitimate process
            println!("\n--- TEST 2: Legitimate Process ---");
            guard(
                model,
                backend,
                "bifrost PID:1204 started by systemd uid:1000 time:22:00 normal startup sequence",
            )?;

            // TEST 3 — Gray area
            println!("\n--- TEST 3: Gray Area ---");
            guard(model, backend, &format!("python3 PID:3301 running govee-art.sh from {}/Scripts/utilities/ time:23:30 uid:1000", std::env::var("HOME").unwrap_or_default()))?;

            // TEST 4 — Alert mode
            println!("\n--- TEST 4: Alert Mode ---");
            alert(
                model,
                backend,
                "curl downloaded ELF binary to /tmp/ then chmod +x and executed it",
            )?;

            // TEST 5 — Query mode
            println!("\n--- TEST 5: Query Mode ---");
            query(
                model,
                backend,
                "What are the top signs of a cryptominer on a Linux system?",
            )?;
        }
    }

    Ok(())
}
