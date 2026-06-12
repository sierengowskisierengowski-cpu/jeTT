# Installation Guide

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux x86_64 | Tested on Arch Linux and Ubuntu 22.04+ |
| CUDA Toolkit 12+ | Required — `llama-cpp-2` is compiled with CUDA support |
| NVIDIA GPU | RTX 3060 or newer recommended (8 GB VRAM for the 2B model) |
| Rust 1.77+ | Install via [rustup](https://rustup.rs/) |
| CMake 3.20+ | Required by the llama-cpp-2 build system |
| C/C++ compiler | `gcc`/`clang` |
| Go 1.22+ | Required only for the Go control-plane (`cmd/server/`) |

---

## Option A — Automated release installer

Downloads the latest pre-built release binaries and installs them system-wide:

```bash
sudo bash install.sh
```

This script:
1. Fetches the latest release metadata from GitHub
2. Downloads the `jeTT` inference engine and `jett-daemon` binaries
3. Installs them to `/usr/local/lib/jett/jeTT` and `/usr/local/bin/jett-daemon`
4. Installs the `jett` wrapper script to `/usr/local/bin/jett`
5. Deploys the systemd service unit and enables it

After installation, set the model path and start the daemon:

```bash
export JETT_MODEL=/path/to/jeTT-q4.gguf
sudo systemctl start jett-daemon
```

---

## Option B — Build from source

### 1. Clone the repository

```bash
git clone https://github.com/sierengowskisierengowski-cpu/jeTT.git
cd jeTT
```

### 2. Build the Rust components

```bash
# Build everything (requires CUDA toolkit on PATH / LD_LIBRARY_PATH)
cargo build --release

# Build just the inference engine
cargo build --release --bin jeTT

# Build just the daemon
cargo build --release --bin jett-daemon
```

Binaries are written to `target/release/`.

### 3. Build the Go control-plane server (optional)

```bash
cd cmd/server
go build -o cerberus-tower ./...
```

### 4. Build the eBPF sensor (optional, requires kernel headers)

```bash
bash scripts/build_bpf.sh
```

### 5. Install manually

```bash
# Install engine and daemon
sudo install -Dm755 target/release/jeTT /usr/local/lib/jett/jeTT
sudo install -Dm755 target/release/jett-daemon /usr/local/bin/jett-daemon

# Install wrapper and service
sudo install -Dm755 jett /usr/local/bin/jett
sudo install -Dm644 jett-daemon.service /etc/systemd/system/jett-daemon.service

# Create runtime directories
sudo install -d -m 0750 /var/log/jett /var/jett/quarantine

# Enable the daemon
sudo systemctl daemon-reload
sudo systemctl enable --now jett-daemon
```

---

## Option C — Arch Linux (PKGBUILD)

```bash
makepkg -si
```

---

## Runtime configuration

All runtime behaviour is controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `JETT_MODEL` | `~/Projects/jeTT/models/jeTT-r3-q4.gguf` | Path to the GGUF model file |
| `JETT_BIN` | `/usr/local/bin/jett` | Path to the jeTT wrapper (used by control panel) |
| `JETT_ENGINE_BIN` | `/usr/local/lib/jett/jeTT` | Path to the raw inference binary |

Set these in `/etc/systemd/system/jett-daemon.service.d/override.conf` for the daemon:

```ini
[Service]
Environment="JETT_MODEL=/path/to/jeTT-q4.gguf"
```

---

## Running tests

```bash
# Rust unit tests (requires CUDA)
cargo test

# Python training pipeline tests (no GPU required)
python3 -m unittest discover -s tests -p "test_*.py" -v
```

