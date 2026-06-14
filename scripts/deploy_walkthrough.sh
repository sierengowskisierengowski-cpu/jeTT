#!/usr/bin/env bash
# Interactive deploy walkthrough — one step at a time, Enter to continue.
# Does not invoke sudo or systemctl; prints exact commands for you to run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STEP=0
MODEL="${JETT_MODEL:-/opt/jett/models/jett-r6-q4_k_m.gguf}"
DEFAULT_FILE="${JETT_DEFAULT_FILE:-/etc/default/jett}"

C_BOLD='\033[1m'
C_DIM='\033[2m'
C_CYAN='\033[0;36m'
C_GRN='\033[0;32m'
C_YEL='\033[1;33m'
C_RED='\033[0;31m'
C_RST='\033[0m'

banner() {
  echo ""
  echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}"
  echo -e "${C_BOLD}  jeTT deploy walkthrough${C_RST}"
  echo -e "${C_DIM}  Repo: ${ROOT}${C_RST}"
  echo -e "${C_DIM}  Model default: ${MODEL}${C_RST}"
  echo -e "${C_BOLD}${C_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RST}"
  echo ""
}

step() {
  local title="$1"
  STEP=$((STEP + 1))
  echo ""
  echo -e "${C_BOLD}${C_CYAN}Step ${STEP}: ${title}${C_RST}"
  echo -e "${C_DIM}────────────────────────────────────────${C_RST}"
}

wait_enter() {
  read -rp "$(echo -e "${C_DIM}  Press Enter to continue...${C_RST}")" _
}

run_or_show() {
  local desc="$1"
  local cmd="$2"
  local may_run="${3:-0}"

  echo -e "  ${C_BOLD}Command:${C_RST}"
  echo -e "    ${C_YEL}${cmd}${C_RST}"
  echo ""

  if [[ "$may_run" == "1" ]]; then
    echo -e "  ${C_DIM}Running (no sudo)...${C_RST}"
    if bash -c "$cmd"; then
      echo -e "  ${C_GRN}[ok]${C_RST} $desc"
    else
      echo -e "  ${C_YEL}[warn]${C_RST} $desc — exit $?"
    fi
  else
    echo -e "  ${C_DIM}Run the command above in another terminal (sudo may be required).${C_RST}"
  fi
}

check_file() {
  local path="$1"
  local label="$2"
  if [[ -f "$path" ]]; then
    echo -e "  ${C_GRN}[ok]${C_RST} $label: $path"
    return 0
  fi
  echo -e "  ${C_YEL}[!]${C_RST} $label missing: $path"
  return 1
}

check_bin() {
  local path="$1"
  if [[ -x "$path" ]]; then
    echo -e "  ${C_GRN}[ok]${C_RST} binary: $path"
    return 0
  fi
  echo -e "  ${C_YEL}[!]${C_RST} not found: $path"
  return 1
}

load_defaults() {
  if [[ -f "$DEFAULT_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$DEFAULT_FILE"
    set +a
    MODEL="${JETT_MODEL:-$MODEL}"
  fi
}

usage() {
  cat <<'EOF'
Usage: bash scripts/deploy_walkthrough.sh [--model /path/to/model.gguf]

Interactive, step-by-step deploy guide for a production host.
Prints exact commands; waits for Enter between steps.
Does not run sudo or systemctl — you execute those locally.

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

banner
load_defaults

# ── Step 1: Verify build ──────────────────────────────────────────────────────
step "Verify build / binaries"
ENGINE=""
for candidate in \
  "$ROOT/target/release/jeTT" \
  "/usr/local/lib/jett/jeTT" \
  "/usr/lib/jett/jeTT"; do
  if check_bin "$candidate"; then
    ENGINE="$candidate"
    break
  fi
done

if [[ -z "$ENGINE" ]]; then
  echo ""
  echo -e "  ${C_YEL}No release binary found — build from source:${C_RST}"
  run_or_show "release build" \
    "cd '$ROOT' && RUSTFLAGS=\"-L /usr/lib -l nccl\" cargo build --release --bin jeTT --bin jett-daemon" 0
else
  echo -e "  ${C_GRN}Engine ready:${C_RST} $ENGINE"
fi

check_bin "$ROOT/target/release/jett-daemon" || \
  check_bin "/usr/local/bin/jett-daemon" || true

wait_enter

# ── Step 2: Pin model ─────────────────────────────────────────────────────────
step "Pin model SHA-256"
check_file "$MODEL" "GGUF model" || true
run_or_show "pin model" \
  "sudo JETT_MODEL='$MODEL' bash '$ROOT/scripts/pin_model.sh'" 0
echo -e "  ${C_DIM}Creates /etc/jett/model.sha256 — daemon verifies at startup.${C_RST}"
wait_enter

# ── Step 3: Install allowlist ─────────────────────────────────────────────────
step "Install own-stack allowlist"
run_or_show "install allowlist" \
  "sudo bash '$ROOT/scripts/install_allowlist.sh'" 0
check_file "/etc/jett/allowlist.conf" "allowlist" || true
wait_enter

# ── Step 4: Restart daemon ────────────────────────────────────────────────────
step "Restart jett-daemon (load config + model pin)"
echo -e "  ${C_DIM}Ensure /etc/default/jett has JETT_MODEL, JETT_MODE=learn, JETT_TELEMETRY=both${C_RST}"
run_or_show "restart daemon" \
  "sudo systemctl daemon-reload && sudo systemctl restart jett-daemon" 0
run_or_show "check status" \
  "./jett status" 1
wait_enter

# ── Step 5: Verify sha256 in journal ──────────────────────────────────────────
step "Verify model SHA-256 in daemon logs"
run_or_show "journal grep" \
  "journalctl -u jett-daemon --no-pager -n 50 | rg -i 'sha256|model.*pin|integrity|verified'" 1
if [[ -f /var/log/jett/jett.log ]] && [[ -r /var/log/jett/jett.log ]]; then
  echo -e "  ${C_DIM}Or tail file log:${C_RST}"
  echo -e "    ${C_YEL}rg -i 'sha256|pin|integrity' /var/log/jett/jett.log | tail -20${C_RST}"
else
  echo -e "  ${C_DIM}/var/log/jett/jett.log not readable from this user — use journalctl.${C_RST}"
fi
wait_enter

# ── Step 6: Stop daemon (free GPU for eval) ───────────────────────────────────
step "Stop daemon (free GPU for eval)"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet jett-daemon 2>/dev/null; then
  echo -e "  ${C_YEL}jett-daemon is currently active.${C_RST}"
else
  echo -e "  ${C_DIM}Daemon not active (or systemctl unavailable).${C_RST}"
fi
run_or_show "stop daemon" \
  "sudo systemctl stop jett-daemon" 0
wait_enter

# ── Step 7: v6 eval ───────────────────────────────────────────────────────────
step "Run v6 guard eval (382 rows)"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet jett-daemon 2>/dev/null; then
  echo -e "  ${C_RED}[!] Stop jett-daemon first — eval needs the GPU.${C_RST}"
fi
run_or_show "v6 eval" \
  "cd '$ROOT' && python3 eval_guard.py --suite v6" 1
wait_enter

# ── Step 8: Adversarial eval ──────────────────────────────────────────────────
step "Run adversarial eval (30-row injection suite)"
run_or_show "adversarial eval" \
  "cd '$ROOT' && bash scripts/run_adversarial_eval.sh" 1
wait_enter

# ── Step 9: Restart daemon ────────────────────────────────────────────────────
step "Restart daemon (return to learn mode)"
run_or_show "start daemon" \
  "sudo systemctl start jett-daemon && ./jett status" 0
wait_enter

# ── Step 10: Optional enforce dry-run preflight ───────────────────────────────
step "Optional — enforce dry-run preflight"
echo -e "  ${C_DIM}Only if testing enforce path safely. Requires in /etc/default/jett:${C_RST}"
echo -e "    JETT_MODE=enforce"
echo -e "    JETT_ENFORCE_DRY_RUN=1"
echo -e "  ${C_DIM}Then restart daemon and run preflight (no kills):${C_RST}"
run_or_show "enforce preflight" \
  "bash '$ROOT/scripts/enforce_smoke.sh' --enforce-check" 1
echo ""
read -rp "$(echo -e "${C_DIM}  Run full enforce smoke now? [y/N] ${C_RST}")" DO_ENFORCE
if [[ "${DO_ENFORCE,,}" == "y" ]]; then
  run_or_show "enforce smoke" \
    "bash '$ROOT/scripts/enforce_smoke.sh'" 1
else
  echo -e "  ${C_DIM}Skipped — revert JETT_MODE=learn when done testing enforce.${C_RST}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}${C_GRN}Deploy walkthrough complete.${C_RST}"
echo ""
echo -e "  Next: ${C_YEL}bash scripts/post_install_smoke.sh${C_RST}  (status + ART smoke)"
echo -e "  Soak: watch ${C_YEL}journalctl -u jett-daemon -f${C_RST} in learn mode"
echo ""
