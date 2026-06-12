# Contributing to jeTT

Thank you for your interest in contributing to jeTT. This guide covers how to build each component, the coding conventions we follow, and the pull request process.

---

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating. We are committed to a welcoming and inclusive community.

---

## Before you start

- Check [open issues](https://github.com/sierengowskisierengowski-cpu/jeTT/issues) to see if your idea or bug is already being tracked.
- For significant changes, open an issue to discuss your approach before writing code.
- Security vulnerabilities **must not** be reported publicly — see [SECURITY.md](SECURITY.md).

---

## Development environment

### Rust components (`src/`, `cmd/agent/`, `cmd/sensor-test/`)

Requirements: Rust 1.77+, CUDA Toolkit 12+, CMake 3.20+, C/C++ compiler.

```bash
# Build all Rust targets
cargo build --release

# Format code (required before committing)
cargo fmt

# Lint
cargo clippy

# Run tests
cargo test
```

The main crate (`Cargo.toml` at the repo root) builds:
- `jeTT` — CLI inference binary (`src/main.rs`)
- `jett-daemon` — process monitor daemon (`src/bin/daemon.rs`)

The `cmd/agent/` and `cmd/sensor-test/` crates are separate Cargo workspaces and are built independently.

### Go component (`cmd/server/`)

Requirements: Go 1.22+.

```bash
cd cmd/server
go build ./...
go test ./...
go vet ./...
```

### eBPF sensor (`bpf/`)

Requirements: `clang`, `llvm`, kernel headers, `libbpf`.

```bash
bash scripts/build_bpf.sh
```

### Python training pipeline (`training/`)

Requirements: Python 3.10+, pip.

```bash
pip install torch transformers trl accelerate peft bitsandbytes unsloth pyyaml

# Syntax check all training scripts
python3 -m py_compile training/generators/*.py training/merge/*.py training/intel/*.py training/*.py

# Run pipeline tests (no GPU required)
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## Coding conventions

### Rust

- Follow standard Rust idioms; run `cargo fmt` before every commit.
- Keep `src/engine.rs` as the single source of truth for model interaction — do not duplicate inference logic in `daemon.rs` or CLI code.
- Error handling: prefer `Result<T, Box<dyn std::error::Error>>` for binary entry points; use typed errors inside the library.
- Public API items must have doc comments.

### Go

- Follow `gofmt` formatting.
- Use `go vet` before submitting.
- Keep the consensus server (`cmd/server/main.go`) stateless where possible.

### Python

- Target Python 3.10+ syntax.
- All scripts must have a `#!/usr/bin/env python3` shebang and be importable (use `if __name__ == "__main__":` guards).
- Generator scripts must accept `--count`/`--out` CLI arguments (see existing generators for the pattern).
- Do not commit generated data files — they are gitignored under `data/`.

### Shell scripts

- All scripts must start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Use `cd "$(dirname "$0")/.."` in `scripts/` to anchor paths to the repo root.

---

## Pull request process

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```
2. Make your changes, following the coding conventions above.
3. Ensure `cargo fmt --check` and `cargo clippy` pass for Rust changes.
4. Ensure Python scripts pass `python3 -m py_compile`.
5. Update relevant documentation (`README.md`, `TRAINING.md`, `INSTALL.md`, `docs/ARCHITECTURE.md`) if your change affects user-facing behaviour or the architecture.
6. Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]`.
7. Open a pull request against `main` using the PR template.

Pull requests that introduce new training techniques should include:
- A description of what MITRE ATT&CK technique(s) are covered.
- Evidence that the coverage gate passes after your changes.

---

## Repository layout quick reference

```
src/          — Rust inference core (do not break this)
bpf/          — eBPF sensor (C; requires kernel toolchain)
cmd/          — Separate Rust/Go components
internal/     — Experimental / internal modules
training/     — Python training pipeline
  generators/ — Per-bucket data generators
  merge/      — Stratified merge script
  intel/      — Threat intelligence ingestion
  coverage/   — MITRE coverage gate
scripts/      — Automation (bash pipeline, RunPod helpers)
tests/        — Eval JSONL sets + Python test suites
docs/         — Deep documentation
```
