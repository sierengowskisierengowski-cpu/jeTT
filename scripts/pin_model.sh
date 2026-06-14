#!/usr/bin/env bash
# Write SHA-256 pin for JETT_MODEL to /etc/jett/model.sha256
set -euo pipefail
MODEL="${1:-${JETT_MODEL:-}}"
DEST="${JETT_MODEL_PIN_DEST:-/etc/jett/model.sha256}"

if [[ -z "$MODEL" ]]; then
  echo "usage: pin_model.sh /path/to/model.gguf" >&2
  echo "   or: JETT_MODEL=/path/to/model.gguf pin_model.sh" >&2
  exit 1
fi
if [[ ! -f "$MODEL" ]]; then
  echo "[!] not found: $MODEL" >&2
  exit 1
fi

HASH="$(sha256sum "$MODEL" | awk '{print $1}')"
BODY="# jeTT model pin — verified at daemon/CLI startup
# file: $MODEL
sha256:${HASH}
"

if [[ "${EUID}" -ne 0 ]]; then
  sudo mkdir -p "$(dirname "$DEST")"
  printf '%s' "$BODY" | sudo tee "$DEST" >/dev/null
  sudo chmod 644 "$DEST"
else
  mkdir -p "$(dirname "$DEST")"
  printf '%s' "$BODY" >"$DEST"
  chmod 644 "$DEST"
fi

echo "[+] pinned $MODEL"
echo "    $DEST"
echo "    sha256:${HASH}"
