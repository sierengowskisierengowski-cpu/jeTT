#!/usr/bin/env bash
# Post-install smoke — status checks and learn-mode ART preflight.
# Safe to run without sudo (daemon checks degrade gracefully).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
WARN=0
FAIL=0

log_ok() {
  echo "[ok] $*"
  PASS=$((PASS + 1))
}

log_warn() {
  echo "[!] $*"
  WARN=$((WARN + 1))
}

log_fail() {
  echo "[FAIL] $*"
  FAIL=$((FAIL + 1))
}

check() {
  local label="$1"
  shift
  if "$@"; then
    log_ok "$label"
  else
    log_fail "$label"
  fi
}

echo "[post_install] jeTT post-install smoke"
echo "[post_install] repo: $ROOT"
echo ""

# ── Wrapper + engine ─────────────────────────────────────────────────────────
if [[ -x "$ROOT/jett" ]]; then
  log_ok "jett wrapper present"
else
  log_fail "missing ./jett wrapper"
fi

ENGINE=""
for candidate in \
  "$ROOT/target/release/jeTT" \
  "/usr/local/lib/jett/jeTT" \
  "/usr/lib/jett/jeTT"; do
  if [[ -x "$candidate" ]]; then
    ENGINE="$candidate"
    log_ok "engine binary: $candidate"
    break
  fi
done
[[ -n "$ENGINE" ]] || log_fail "no jeTT engine binary found"

DAEMON=""
for candidate in \
  "$ROOT/target/release/jett-daemon" \
  "/usr/local/bin/jett-daemon" \
  "/usr/bin/jett-daemon"; do
  if [[ -x "$candidate" ]]; then
    DAEMON="$candidate"
    log_ok "daemon binary: $candidate"
    break
  fi
done
[[ -n "$DAEMON" ]] || log_warn "jett-daemon binary not found (install or build first)"

# ── Config files ─────────────────────────────────────────────────────────────
DEFAULT_FILE="${JETT_DEFAULT_FILE:-/etc/default/jett}"
if [[ -f "$DEFAULT_FILE" ]]; then
  log_ok "defaults: $DEFAULT_FILE"
  # shellcheck disable=SC1090
  set -a
  source "$DEFAULT_FILE"
  set +a
else
  log_warn "no $DEFAULT_FILE — copy example from INSTALL.md"
fi

if [[ -f "${JETT_ALLOWLIST:-/etc/jett/allowlist.conf}" ]]; then
  log_ok "allowlist: ${JETT_ALLOWLIST:-/etc/jett/allowlist.conf}"
else
  log_warn "allowlist missing — run: sudo bash scripts/install_allowlist.sh"
fi

PIN="${JETT_MODEL_PIN:-/etc/jett/model.sha256}"
if [[ -f "$PIN" ]]; then
  log_ok "model pin: $PIN"
else
  log_warn "model pin missing — run: sudo JETT_MODEL=\$JETT_MODEL bash scripts/pin_model.sh"
fi

MODEL="${JETT_MODEL:-}"
if [[ -n "$MODEL" && -f "$MODEL" ]]; then
  log_ok "model file: $MODEL"
elif [[ -n "$MODEL" ]]; then
  log_fail "JETT_MODEL set but missing: $MODEL"
else
  log_warn "JETT_MODEL unset"
fi

# ── Daemon status ─────────────────────────────────────────────────────────────
echo ""
echo "[post_install] daemon status"
if [[ -x "$ROOT/jett" ]]; then
  "$ROOT/jett" status || log_warn "jett status returned non-zero"
else
  log_warn "skipped jett status (no wrapper)"
fi

DAEMON_ACTIVE=0
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet jett-daemon 2>/dev/null; then
    DAEMON_ACTIVE=1
    log_ok "jett-daemon systemd unit active"
  else
    log_warn "jett-daemon not active — start with: sudo systemctl start jett-daemon"
  fi
else
  log_warn "systemctl unavailable"
fi

# ── Model integrity in logs (read-only) ────────────────────────────────────────
if [[ "$DAEMON_ACTIVE" -eq 1 ]] && command -v journalctl >/dev/null 2>&1; then
  if journalctl -u jett-daemon --no-pager -n 60 2>/dev/null \
    | rg -qi 'sha256|integrity|model.*pin|verified'; then
    log_ok "journal shows model integrity / pin lines"
  else
    log_warn "no model sha256 lines in recent journal (recent restart?)"
  fi
fi

# ── ART smoke ─────────────────────────────────────────────────────────────────
echo ""
ART="${ROOT}/scripts/art_jett_smoke.sh"
if [[ ! -x "$ART" ]]; then
  chmod +x "$ART" 2>/dev/null || true
fi

if [[ "${JETT_POST_INSTALL_FULL:-0}" == "1" && "$DAEMON_ACTIVE" -eq 1 ]]; then
  echo "[post_install] running full ART smoke (JETT_POST_INSTALL_FULL=1)"
  bash "$ART" || log_warn "ART smoke exited non-zero"
elif [[ "$DAEMON_ACTIVE" -eq 1 ]]; then
  echo "[post_install] running ART dry-run listing (set JETT_POST_INSTALL_FULL=1 for full run)"
  bash "$ART" --dry-run
  echo "[post_install] for live atoms: ./jett smoke"
else
  echo "[post_install] daemon inactive — ART dry-run only"
  bash "$ART" --dry-run
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[post_install] passed=$PASS warn=$WARN fail=$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  echo "[post_install] fix failures above, then re-run"
  exit 1
fi
echo "[post_install] smoke complete"
exit 0
