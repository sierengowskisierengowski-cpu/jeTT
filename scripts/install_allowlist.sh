#!/usr/bin/env bash
# Install own-stack allowlist to /etc/jett/allowlist.conf
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${JETT_ALLOWLIST_SRC:-$REPO_ROOT/config/allowlist.example.conf}"
DEST="${JETT_ALLOWLIST_DEST:-/etc/jett/allowlist.conf}"

if [[ ! -f "$SRC" ]]; then
  echo "[!] missing source: $SRC" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  sudo mkdir -p "$(dirname "$DEST")"
  sudo cp "$SRC" "$DEST"
  sudo chmod 644 "$DEST"
  echo "[+] installed $DEST (from $SRC)"
else
  mkdir -p "$(dirname "$DEST")"
  cp "$SRC" "$DEST"
  chmod 644 "$DEST"
  echo "[+] installed $DEST (from $SRC)"
fi

echo "[*] set in systemd: Environment=JETT_ALLOWLIST=$DEST"
