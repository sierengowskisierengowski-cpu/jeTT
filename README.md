# jeTT — Autonomous AI EDR Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Build](https://github.com/sierengowskisierengowski-cpu/jeTT/actions/workflows/ci.yml/badge.svg)](https://github.com/sierengowskisierengowski-cpu/jeTT/actions/workflows/ci.yml)

> **Autonomous local AI security brain. IBM Granite 3.3 2B running on CUDA. Zero cloud. Zero wrappers. Pure Rust.**

---

## What is jeTT?

jeTT is the on-box AI Endpoint Detection and Response (EDR) engine powering the **Cerberus** Linux XDR platform. It runs IBM Granite 3.3 2B entirely locally — no cloud inference, no third-party API, no internet dependency at detection time. Every security verdict is made on-device in milliseconds by a fine-tuned language model that has been trained on millions of real-world attack patterns, MITRE ATT&CK techniques, and behavior-based threat signatures.

jeTT is designed for defenders who need a system that thinks, not just a system that matches signatures. It understands *context* — the same `curl` invocation is safe in a developer's home directory but suspicious when run from `/tmp` by an SSH process at 3 AM.

---

## Key Features

- **Local-only inference** — GGUF model runs via `llama-cpp-2` with CUDA; no data leaves the machine
- **Three operating modes** — `--guard` (binary verdict), `--alert` (threat explanation), `--query` (freeform AI query)
- **Binary allowlist** — SHA-256-based allowlist (`--trust` / `--untrust` / `--list-trusted`) prevents false positives on trusted binaries
- **Persistent daemon** — `jett-daemon` monitors `/proc` for new processes and dispatches guard evaluations automatically
- **eBPF kernel sensors** — `bpf/jett_sensor.bpf.c` captures `sched_process_exec` events for low-overhead telemetry
- **Fine-tuned on 65 k+ curated pairs** — MITRE ATT&CK, CVEs, GTFOBins, LOLBAS, supply-chain attacks, LOLbins, C2 variety, and own-stack allowlisting
- **Systemd integration** — ships with a service unit and a TUI control panel (`jett-control.sh`)
- **Arch Linux packaging** — `PKGBUILD` included for AUR-style installation

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      jeTT Runtime                        │
│                                                          │
│  jett-control.sh (TUI)                                   │
│       │                                                  │
│       ▼                                                  │
│  jett (wrapper) ──► src/main.rs (CLI: --guard/alert/query)│
│                         │                               │
│                         ▼                               │
│              src/engine.rs (inference core)             │
│              ├── load_model() — llama-cpp-2 + CUDA      │
│              ├── guard()  — single-token verdict        │
│              ├── alert()  — threat explanation          │
│              ├── query()  — freeform prompt             │
│              └── allowlist — SHA-256 per-binary         │
│                                                          │
│  src/bin/daemon.rs  ◄── /proc scanner                   │
│       │  (jett-daemon systemd service)                  │
│       └──► engine::guard() for each new PID             │
│                                                          │
│  bpf/jett_sensor.bpf.c ◄── sched_process_exec hook     │
│  (optional eBPF telemetry layer)                         │
│                                                          │
│  cmd/server/ (Go)  — dual-model consensus API           │
│  cmd/agent/        — Rust telemetry agent               │
│  cmd/sensor-test/  — eBPF sensor validation binary      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  Training Pipeline                        │
│                                                          │
│  training/intel/        — threat intelligence ingestion │
│  training/generators/   — per-bucket data generation   │
│  training/merge/        — stratified dataset assembly  │
│  training/coverage/     — MITRE ATT&CK coverage gate   │
│  training/train_core_weights.py — LoRA fine-tuning      │
│  scripts/run_round*_pipeline.sh — end-to-end automation │
└─────────────────────────────────────────────────────────┘
```

The **Modelfile** at the repo root configures the Ollama-compatible model persona. At runtime, jeTT loads the GGUF from the path in `JETT_MODEL` and performs inference entirely in-process — there is no separate model server.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a deeper component walkthrough.

---

## Requirements

| Requirement | Notes |
|---|---|
| Linux (x86_64) | Tested on Arch, Ubuntu 22.04+ |
| CUDA Toolkit 12+ | Required — `llama-cpp-2` is compiled with `features = ["cuda"]` |
| NVIDIA GPU | RTX 30-series or newer recommended (RTX 3060+ for 2B model) |
| Rust 1.77+ | `cargo build --release` |
| Go 1.22+ | For the Go control-plane (`cmd/server/`) |
| Python 3.10+ | Training pipeline only — not needed at runtime |

---

## Quick Start

### Install from source

```bash
git clone https://github.com/sierengowskisierengowski-cpu/jeTT.git
cd jeTT
cargo build --release
```

### Install from release (automated)

```bash
sudo bash install.sh
```

This downloads the latest release binaries, installs them to `/usr/local/lib/jett/` and `/usr/local/bin/`, deploys the systemd service, and enables it.

For full build instructions see [`INSTALL.md`](INSTALL.md).

---

## Usage

### Launch the TUI control panel

```bash
jett-control.sh
```

Interactive menu for daemon management, live log viewing, quarantine review, and inline guard/alert/query testing.

### CLI modes

```bash
# Evaluate a process event — returns ALLOW or QUARANTINE_PID
jett --guard "python3 PID:4821 executed from /tmp/.hidden spawned by sshd uid:1000 made outbound connection to 185.220.x.x"

# Explain a threat in one sentence
jett --alert "curl downloaded ELF binary to /tmp/ then chmod +x and executed it"

# Ask jeTT anything
jett --query "What are the top indicators of a cryptominer on Linux?"

# Manage the binary allowlist
jett --trust /usr/bin/my-trusted-tool
jett --untrust /usr/bin/my-trusted-tool
jett --list-trusted
```

### Daemon / systemd

```bash
sudo systemctl start jett-daemon
sudo systemctl status jett-daemon
journalctl -u jett-daemon -f
```

Set `JETT_MODEL` in the service environment to point at your GGUF:

```bash
# /etc/systemd/system/jett-daemon.service.d/override.conf
[Service]
Environment="JETT_MODEL=/path/to/jeTT-q4.gguf"
```

---

## Project Structure

```
jeTT/
├── src/                        # Rust core
│   ├── main.rs                 # CLI entry point (--guard, --alert, --query)
│   ├── lib.rs                  # Public engine API
│   ├── engine.rs               # Inference, verdict, allowlist logic
│   └── bin/daemon.rs           # jett-daemon process monitor
├── bpf/                        # eBPF kernel sensors
│   └── jett_sensor.bpf.c       # sched_process_exec telemetry
├── cmd/                        # Additional components
│   ├── agent/                  # Rust telemetry agent
│   ├── sensor-test/            # eBPF sensor test binary
│   └── server/                 # Go dual-model consensus API
├── internal/                   # Internal / experimental
│   ├── deception/              # Adversary deception layer
│   └── kernel/                 # eBPF kernel helpers
├── training/                   # Python training pipeline
│   ├── generators/             # Per-bucket dataset generators
│   ├── merge/                  # Stratified dataset assembler
│   ├── intel/                  # Threat intelligence ingestion
│   ├── coverage/               # MITRE ATT&CK coverage gate
│   ├── train_core_weights.py   # LoRA fine-tuning (Unsloth/SFTTrainer)
│   ├── jett_extended_training.py
│   └── eval_guard.py
├── scripts/                    # Pipeline and deployment automation
│   ├── run_round{4..7}_pipeline.sh
│   ├── build_bpf.sh
│   └── runpod_*.sh             # RunPod cloud training helpers
├── tests/                      # Evaluation data and test suites
│   ├── guard_eval_v7.jsonl     # Latest held-out eval set
│   ├── test_jett_brain.py
│   └── test_training_pipeline.py
├── docs/                       # Deep documentation
│   ├── ARCHITECTURE.md
│   └── EBPF.md
├── Cargo.toml                  # Rust workspace (llama-cpp-2 cuda)
├── Modelfile                   # Ollama model configuration
├── PKGBUILD                    # Arch Linux packaging
├── install.sh                  # Automated release installer
├── jett                        # Wrapper script (installed to PATH)
├── jett-control.sh             # TUI control panel
├── jett-daemon.service         # Systemd unit
├── INSTALL.md
├── TRAINING.md
├── CONTRIBUTING.md
├── SECURITY.md
├── DISCLAIMER.md
└── LICENSE
```

---

## Documentation

| Document | Description |
|---|---|
| [INSTALL.md](INSTALL.md) | Build from source, prerequisites, runtime configuration |
| [TRAINING.md](TRAINING.md) | End-to-end training pipeline walkthrough |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component deep-dive and data flow |
| [docs/EBPF.md](docs/EBPF.md) | eBPF sensor design |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to build, contribute, and submit PRs |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |
| [DISCLAIMER.md](DISCLAIMER.md) | Legal / usage disclaimer |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## Security Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer. In brief: jeTT is a **defensive research tool**. The AI model may produce false positives or miss novel threats. It is **not** a replacement for a comprehensive, professionally audited security stack. Use responsibly.

---

## License

[MIT](LICENSE) — © GowskiNet Security Lab

