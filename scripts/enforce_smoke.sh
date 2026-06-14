#!/usr/bin/env bash
# Safe enforce-mode smoke — validates the QUARANTINE verdict path without killing processes.
#
# Prerequisites (set in /etc/default/jett, then restart jett-daemon):
#   JETT_MODE=enforce
#   JETT_ENFORCE_DRY_RUN=1          # suppresses kill -9 and quarantine copies
#   JETT_MODEL=<path-to-gguf>       # e.g. models/jett-r6-q4_k_m.gguf
#   JETT_ALLOWLIST=/etc/jett/allowlist.conf   (recommended)
#
# Daemon must be running. Do NOT run with JETT_ENFORCE_DRY_RUN unset in enforce mode
# on a production host — that enables real kills.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEFAULT_FILE="${JETT_DEFAULT_FILE:-/etc/default/jett}"
ART_SCRIPT="${ROOT}/scripts/art_jett_smoke.sh"
PASS=0
FAIL=0

usage() {
  cat <<'EOF'
Usage: scripts/enforce_smoke.sh [--enforce-check | --dry-run]

Validates jeTT enforce-mode pipeline safely via JETT_ENFORCE_DRY_RUN=1.

  --enforce-check   Preflight only: mode, dry-run flag, daemon banner (no atoms)
  --dry-run         Print planned checks and atoms without executing

Prerequisites (/etc/default/jett + systemctl restart jett-daemon):
  JETT_MODE=enforce
  JETT_ENFORCE_DRY_RUN=1
  jett-daemon active with model loaded

After preflight passes, runs scripts/art_jett_smoke.sh atoms and checks logs for
QUARANTINE + dry-run lines (not WOULD-quarantine, not "Killed quarantined PID").

EOF
}

load_defaults() {
  if [[ -f "$DEFAULT_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$DEFAULT_FILE"
    set +a
  fi
}

check() {
  local label="$1"
  shift
  if "$@"; then
    echo "  [ok] $label"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $label"
    FAIL=$((FAIL + 1))
  fi
}

enforce_check() {
  echo "[enforce] preflight — enforce path (dry-run required)"
  load_defaults

  check "JETT_MODE=enforce" \
    '[[ "${JETT_MODE:-learn}" =~ ^[Ee]nforce ]]'

  check "JETT_ENFORCE_DRY_RUN=1" \
    '[[ "${JETT_ENFORCE_DRY_RUN:-}" =~ ^(1|true|yes|TRUE|YES)$ ]]'

  if command -v systemctl >/dev/null 2>&1; then
    check "jett-daemon active" systemctl is-active --quiet jett-daemon
  else
    echo "  [warn] systemctl unavailable — ensure jett-daemon is running manually"
  fi

  if command -v journalctl >/dev/null 2>&1; then
    if journalctl -u jett-daemon --no-pager -n 80 2>/dev/null \
      | rg -q 'ENFORCE MODE \(DRY-RUN\)|ENFORCE DRY-RUN'; then
      check "daemon logged ENFORCE DRY-RUN banner" true
    elif journalctl -u jett-daemon --no-pager -n 80 2>/dev/null \
      | rg -q 'ENFORCE MODE'; then
      echo "  [FAIL] daemon in ENFORCE MODE but missing DRY-RUN banner"
      echo "         set JETT_ENFORCE_DRY_RUN=1 in ${DEFAULT_FILE} and restart"
      FAIL=$((FAIL + 1))
    else
      echo "  [warn] could not confirm ENFORCE DRY-RUN banner in journal (daemon recently restarted?)"
    fi
  fi

  if [[ -n "${JETT_MODEL:-}" ]]; then
    check "JETT_MODEL file exists" test -f "${JETT_MODEL}"
  else
    echo "  [warn] JETT_MODEL unset in ${DEFAULT_FILE}"
  fi

  echo ""
  if [[ "$FAIL" -gt 0 ]]; then
    echo "[enforce] preflight FAILED ($FAIL check(s))"
    echo ""
    echo "Fix /etc/default/jett, then:"
    echo "  sudo systemctl restart jett-daemon"
    echo "  journalctl -u jett-daemon -n 20 | rg -i 'ENFORCE|DRY-RUN'"
    return 1
  fi
  echo "[enforce] preflight passed ($PASS checks)"
  return 0
}

verify_enforce_logs() {
  echo ""
  echo "[enforce] verifying logs (last ~10 min)..."
  local journal_ok=0
  local dry_ok=0
  local kill_ok=1

  if command -v journalctl >/dev/null 2>&1; then
    local recent
    recent="$(journalctl -u jett-daemon --since '10 min ago' --no-pager 2>/dev/null || true)"
    if echo "$recent" | rg -q 'QUARANTINE'; then
      journal_ok=1
      echo "  [ok] journal contains QUARANTINE verdict lines"
    else
      echo "  [warn] no QUARANTINE lines in recent journal — suspicious atoms may not have fired"
    fi
    if echo "$recent" | rg -qi 'dry-run|DRY-RUN'; then
      dry_ok=1
      echo "  [ok] journal contains dry-run suppression lines"
    else
      echo "  [warn] no dry-run lines — confirm JETT_ENFORCE_DRY_RUN=1"
    fi
    if echo "$recent" | rg -q 'Killed quarantined PID'; then
      kill_ok=0
      echo "  [FAIL] journal shows real kills — dry-run may be off"
    else
      echo "  [ok] no 'Killed quarantined PID' in journal"
    fi
  fi

  if [[ -f /var/log/jett/jett.log ]] && [[ -r /var/log/jett/jett.log ]]; then
    local tail_log
    tail_log="$(tail -80 /var/log/jett/jett.log 2>/dev/null || true)"
    if echo "$tail_log" | rg -q 'WOULD-QUARANTINE'; then
      echo "  [warn] jett.log has WOULD-QUARANTINE — daemon may still be in learn mode"
    fi
  fi

  if [[ "$kill_ok" -eq 0 ]]; then
    return 1
  fi
  if [[ "$journal_ok" -eq 1 && "$dry_ok" -eq 1 ]]; then
    return 0
  fi
  return 0
}

MODE="${1:-}"
case "$MODE" in
  -h|--help)
    usage
    exit 0
    ;;
  --enforce-check)
    enforce_check
    exit $?
    ;;
  --dry-run)
    usage
    echo "[enforce] dry-run — would run preflight then:"
    echo "  bash ${ART_SCRIPT}"
    exit 0
    ;;
  "")
    ;;
  *)
    echo "Unknown option: $MODE" >&2
    usage >&2
    exit 1
    ;;
esac

enforce_check

echo ""
echo "[enforce] running ART atoms (safe, same as learn smoke)..."
if [[ ! -x "$ART_SCRIPT" ]]; then
  chmod +x "$ART_SCRIPT"
fi
bash "$ART_SCRIPT"

verify_enforce_logs
echo ""
echo "[enforce] done — review:"
echo "  journalctl -u jett-daemon --since '10 min ago' | rg -i 'QUARANTINE|DRY-RUN|SUSPICIOUS'"
echo "  expect 🚨 QUARANTINE + dry-run lines; no kills while JETT_ENFORCE_DRY_RUN=1"
