# jeTT - Local AI-Powered EDR Engine

jeTT is an autonomous, local Endpoint Detection and Response (EDR) and AI-powered Anti-Virus engine built in pure Rust. Leveraging IBM Granite 3.3 2B running entirely offline, jeTT delivers sub-250ms threat verdicts on raw system telemetry without relying on cloud APIs or external network connections.

## Overview

Traditional EDRs rely on cloud agents and continuous network access. jeTT flips this model:

- Zero-Cloud Design: All AI analysis runs 100% locally. No SaaS, no API keys, no data leaving your machine.
- Sub-250ms Verdicts: Fast-path heuristics combined with a 4-bit quantized local model.
- Dual-Component Architecture:
  - jeTT (Inference Engine): Rust runner managing the local GGUF model via CUDA llama-cpp-2.
  - jett-daemon (Telemetry Monitor): Real-time /proc monitor that delegates suspicious events to the AI core.

## Features

- IBM Granite 3.3 2B fine-tuned for security threat detection
- Pure Rust performance - single native binary
- Real-time /proc process discovery
- Local logging to /var/log/jett and quarantine to /var/jett/quarantine
- Fast-path trusted process bypass (0ms for known good processes)
- systemd service support

## Requirements

- Linux with /proc support
- NVIDIA GPU with CUDA (RTX 3060+ recommended, 6GB VRAM minimum)
- Rust 2021 toolchain
- libnccl

## Build

    git clone https://github.com/sierengowskisierengowski-cpu/jeTT
    cd jeTT
    RUSTFLAGS="-L /usr/lib -l nccl" cargo build --release

## Usage

    # Set model path
    export JETT_MODEL=/path/to/jeTT-q4.gguf

    # Demo mode (runs 5 built-in tests)
    ./target/release/jeTT

    # CLI mode (used by daemon)
    ./target/release/jeTT --guard "process event string"
    ./target/release/jeTT --alert "suspicious event description"
    ./target/release/jeTT --query "security question"

## Daemon

    sudo mkdir -p /var/log/jett /var/jett/quarantine
    export JETT_MODEL=/path/to/jeTT-q4.gguf
    export JETT_BIN=/path/to/target/release/jeTT
    sudo -E ./target/release/jett-daemon

    # Or as systemd service
    sudo systemctl enable --now jett-daemon
    tail -f /var/log/jett/jett.log

## Performance

| Mode | Latency |
|------|---------|
| Guard | ~250ms |
| Alert | ~250ms |
| Query | ~1-4s |
| Trusted (cached) | 0ms |

## Training

See TRAINING.md for the full fine-tuning pipeline.

## Disclaimer

jeTT is an experimental security research project. Use in controlled environments and security labs. Not a substitute for production-hardened EDR solutions.

## Author

Joseph Sierengowski - GowskiNet Security Lab
