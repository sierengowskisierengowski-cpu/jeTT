#!/usr/bin/env bash
# Run adversarial guard eval (30-row injection/honeypot suite). Requires GPU; stop daemon first.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if systemctl is-active --quiet jett-daemon 2>/dev/null; then
  echo "jett-daemon is running — stop it first so eval can use the GPU:"
  echo "  sudo systemctl stop jett-daemon"
  exit 1
fi

python3 eval_guard.py --suite adversarial "$@"
