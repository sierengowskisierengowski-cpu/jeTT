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
bash scripts/post_install_smoke.sh     # status + config checks; JETT_POST_INSTALL_FULL=1 for full ART
./jett smoke                           # learn-mode ART atoms
./scripts/enforce_smoke.sh --enforce-check   # after enforce+dry-run config
```

## Guided deploy walkthrough

Interactive, step-by-step (prints commands; you run sudo/systemctl locally):

```bash
bash scripts/deploy_walkthrough.sh
# optional: bash scripts/deploy_walkthrough.sh --model /opt/jett/models/jett-r6-q4_k_m.gguf
```

Steps: verify build → pin model → allowlist → restart daemon → verify sha256 in journal →
stop daemon → v6 eval → adversarial eval → restart daemon → optional enforce dry-run preflight.

## Release install

```bash
sudo bash install.sh
```

Downloads latest GitHub release assets for `jeTT` and `jett-daemon` when available.
If no release exists yet, **falls back to a local `cargo build --release`** (CUDA when `nvcc`
is present, otherwise CPU-only).

Model GGUF is **not bundled** — set `JETT_MODEL` after install. See license/size notes in
[TRAINING.md](TRAINING.md).

### Build release tarballs locally

```bash
# Production CUDA build (RunPod / GPU host)
bash scripts/build_release.sh

# CPU-only (CI smoke)
JETT_CPU_ONLY=1 bash scripts/build_release.sh

# Optional: publish with gh cli
bash scripts/create_github_release.sh v0.1.0
```

**CI note:** GitHub Actions builds CPU-only assets. Production GPU inference requires a
CUDA + NCCL build on a self-hosted runner, RunPod pod, or your deploy host (`install.sh`
local fallback with `nvcc`).

## Eval (optional)

```bash
sudo systemctl stop jett-daemon    # free GPU
python3 eval_guard.py --eval tests/guard_eval_v6.jsonl
./scripts/run_adversarial_eval.sh
```

See [TRAINING.md](TRAINING.md) for dataset and fine-tune workflows.
