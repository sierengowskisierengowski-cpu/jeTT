# Install

## Prerequisites

- Linux (x86_64)
- Rust toolchain
- CMake and a C/C++ compiler
- CUDA Toolkit — `llama-cpp-2` is built with CUDA support
- NVIDIA driver + NCCL libs for release builds (`RUSTFLAGS="-L /usr/lib -l nccl"` if needed)

## Build from source

```bash
cargo build --release --features ebpf
```

Binaries: `target/release/jeTT`, `target/release/jett-daemon`. Wrapper: `./jett` → `scripts/jett-ctl.sh`.

```bash
cargo test --lib
```

## Runtime configuration

Create `/etc/default/jett` (or edit after `install.sh`):

```bash
JETT_MODEL=/opt/jett/models/jett-r6-q4_k_m.gguf
JETT_MODE=learn                    # learn | enforce
JETT_TELEMETRY=both                # proc | ebpf | both
JETT_ALLOWLIST=/etc/jett/allowlist.conf
JETT_MODEL_PIN=/etc/jett/model.sha256
# JETT_ENFORCE_DRY_RUN=1          # safe enforce smoke only — not for production enforce
```

Install supporting files:

```bash
sudo ./scripts/install_allowlist.sh
sudo JETT_MODEL="$JETT_MODEL" ./scripts/pin_model.sh
```

Systemd unit: `jett-daemon.service` (reads `EnvironmentFile=-/etc/default/jett`).

```bash
sudo cp jett-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jett-daemon
```

## Post-install checks

```bash
./jett status
./jett smoke                       # learn-mode ART atoms
./scripts/enforce_smoke.sh --enforce-check   # after enforce+dry-run config
```

## Release install (when available)

```bash
sudo bash install.sh
```

Downloads latest GitHub release assets for `jeTT` and `jett-daemon`. Model GGUF is separate — set `JETT_MODEL` after install.

## Eval (optional)

```bash
sudo systemctl stop jett-daemon    # free GPU
python3 eval_guard.py --eval tests/guard_eval_v6.jsonl
./scripts/run_adversarial_eval.sh
```

See [TRAINING.md](TRAINING.md) for dataset and fine-tune workflows.
