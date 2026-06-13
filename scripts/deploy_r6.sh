#!/usr/bin/env bash
# Deploy jeTT r6 model + rebuilt binaries to systemd daemon.
set -euo pipefail
cd "$(dirname "$0")/.."

MODEL="${JETT_MODEL:-$PWD/models/jett-r6-q4_k_m.gguf}"
INSTALL_DIR="${JETT_INSTALL_DIR:-/usr/lib/jett}"

if [[ ! -f "$MODEL" ]]; then
  echo "[!] missing model: $MODEL"
  exit 1
fi

echo "[build] BPF object..."
bash scripts/build_bpf.sh

echo "[build] release binaries (ebpf feature)..."
RUSTFLAGS="${RUSTFLAGS:--L /usr/lib -l nccl}" \
  cargo build --release --features ebpf --bin jeTT --bin jett-daemon

echo "[install] -> $INSTALL_DIR"
sudo install -Dm755 target/release/jeTT "$INSTALL_DIR/jeTT"
sudo install -Dm755 target/release/jett-daemon "$INSTALL_DIR/jett-daemon"

echo "[systemd] JETT_MODEL=$MODEL"
sudo mkdir -p /etc/systemd/system/jett-daemon.service.d
sudo tee /etc/systemd/system/jett-daemon.service.d/override.conf >/dev/null <<EOF
[Service]
Environment="JETT_MODEL=$MODEL"
Environment="JETT_TELEMETRY=both"
Environment="JETT_MODE=learn"
EOF

sudo systemctl daemon-reload
sudo systemctl restart jett-daemon
sudo systemctl status jett-daemon --no-pager | head -15

echo "[+] deployed r6 — verify: journalctl -u jett-daemon -f"
