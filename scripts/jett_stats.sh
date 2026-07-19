#!/usr/bin/env bash
# Verdict dashboard — ALLOW / WOULD-quarantine / QUARANTINE counts from jett.log.
# Works in learn mode and enforce mode (labels adjust automatically).
set -euo pipefail

LOG_FILE="${JETT_LOG:-/var/log/jett/jett.log}"
QUAR_LOG="${JETT_QUAR_LOG:-/var/jett/quarantine/quarantine.log}"
DEFAULT_FILE="${JETT_DEFAULT_FILE:-/etc/default/jett}"
SERVICE="${JETT_SERVICE:-jett-daemon.service}"
EVIDENCE_VAULT="${JETT_EVIDENCE_VAULT:-/var/jett/evidence/vault.jsonl}"

WATCH=0
INTERVAL=5
TAIL_RECENT=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--watch) WATCH=1; shift ;;
    -i|--interval) INTERVAL="${2:-5}"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: jett stats [-w] [-i SECONDS]

  Verdict summary from /var/log/jett/jett.log (learn + enforce).

  -w, --watch       Refresh every 5s (use -i to change)
  -i, --interval N  Watch interval (default: 5)

Examples:
  jett stats
  jett stats -w
  watch -n 10 jett stats
EOF
      exit 0
      ;;
    *) echo "[!] unknown option: $1" >&2; exit 1 ;;
  esac
done

C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_CYAN='\033[0;36m'
C_DIM='\033[2m'
C_BOLD='\033[1m'
C_RST='\033[0m'

load_mode() {
  if [[ -f "$DEFAULT_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$DEFAULT_FILE"
    set +a
  fi
  if [[ "${JETT_MODE:-learn}" =~ ^[Ee]nforce ]]; then
    MODE="enforce"
  else
    MODE="learn"
  fi
}

daemon_active() {
  systemctl is-active --quiet "$SERVICE" 2>/dev/null
}

count_pat() {
  local pat="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  grep -cE "$pat" "$file" 2>/dev/null || echo 0
}

render() {
  load_mode

  local allows would_q real_q review trusted dropped quar_lines evidence_lines
  allows=$(count_pat '→ .+ ALLOW' "$LOG_FILE")
  would_q=$(count_pat 'WOULD-QUARANTINE' "$LOG_FILE")
  real_q=$(count_pat '🚨 QUARANTINE' "$LOG_FILE")
  review=$(count_pat 'REVIEW' "$LOG_FILE")
  trusted=$(count_pat 'Trusted GowskiNet' "$LOG_FILE")
  dropped=$(count_pat 'log rate limiter dropped' "$LOG_FILE")
  quar_lines=$(wc -l < "$QUAR_LOG" 2>/dev/null || echo 0)
  evidence_lines=$(wc -l < "$EVIDENCE_VAULT" 2>/dev/null || echo 0)

  local total_logged=$((allows + would_q + real_q + review))
  [[ "$total_logged" -lt 0 ]] && total_logged=0

  clear 2>/dev/null || true
  echo -e "${C_BOLD}${C_CYAN}jeTT stats${C_RST}  ${C_DIM}$(date '+%Y-%m-%d %H:%M:%S')${C_RST}"
  echo -e "${C_DIM}────────────────────────────────────────${C_RST}"

  if daemon_active; then
    echo -e "  Daemon   ${C_GREEN}● running${C_RST}"
  else
    echo -e "  Daemon   ${C_RED}● stopped${C_RST}"
  fi

  if [[ "$MODE" == "learn" ]]; then
    echo -e "  Mode     ${C_YELLOW}LEARN${C_RST} ${C_DIM}(would-quarantine only, no kills)${C_RST}"
  else
    echo -e "  Mode     ${C_RED}ENFORCE${C_RST} ${C_DIM}(real quarantine + kills)${C_RST}"
  fi

  if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "\n  ${C_YELLOW}[!] no log yet: ${LOG_FILE}${C_RST}"
    return
  fi

  echo ""
  echo -e "  ${C_BOLD}Verdicts (all time, jett.log)${C_RST}"
  echo -e "  ${C_GREEN}ALLOW${C_RST}              ${allows}"
  if [[ "$MODE" == "learn" ]]; then
    echo -e "  ${C_YELLOW}WOULD-quarantine${C_RST}   ${would_q}"
  else
    echo -e "  ${C_YELLOW}WOULD-quarantine${C_RST}   ${would_q} ${C_DIM}(legacy/learn lines)${C_RST}"
    echo -e "  ${C_RED}QUARANTINE${C_RST}         ${real_q} ${C_DIM}(enforce)${C_RST}"
  fi
  echo -e "  ${C_DIM}REVIEW${C_RST}               ${review}"
  [[ "$trusted" -gt 0 ]] 2>/dev/null && echo -e "  ${C_DIM}Trusted (fast)${C_RST}       ${trusted}"
  [[ "$dropped" -gt 0 ]] 2>/dev/null && echo -e "  ${C_DIM}Log drops${C_RST}            ${dropped}"

  echo ""
  echo -e "  ${C_BOLD}Side logs${C_RST}"
  echo -e "  Quarantine log lines   ${quar_lines}"
  echo -e "  Evidence vault rows    ${evidence_lines}"

  echo ""
  echo -e "  ${C_BOLD}Recent flags${C_RST} ${C_DIM}(last ${TAIL_RECENT})${C_RST}"
  if grep -qE 'WOULD-QUARANTINE|→ .+ QUARANTINE|REVIEW' "$LOG_FILE" 2>/dev/null; then
    grep -E 'WOULD-QUARANTINE|→ .+ QUARANTINE|REVIEW' "$LOG_FILE" | tail -n "$TAIL_RECENT" | while IFS= read -r line; do
      if [[ "$line" == *"WOULD-QUARANTINE"* ]]; then
        echo -e "  ${C_YELLOW}•${C_RST} ${line}"
      elif [[ "$line" == *"QUARANTINE"* ]]; then
        echo -e "  ${C_RED}•${C_RST} ${line}"
      else
        echo -e "  ${C_DIM}•${C_RST} ${line}"
      fi
    done
  else
    echo -e "  ${C_DIM}(none yet)${C_RST}"
  fi

  echo ""
  echo -e "${C_DIM}────────────────────────────────────────${C_RST}"
  if [[ "$WATCH" -eq 1 ]]; then
    echo -e "${C_DIM}  refreshing every ${INTERVAL}s — Ctrl+C to stop${C_RST}"
  else
    echo -e "${C_DIM}  live: jett stats -w   |   tail: jett logs -f${C_RST}"
  fi
}

if [[ "$WATCH" -eq 1 ]]; then
  while true; do
    render
    sleep "$INTERVAL"
  done
else
  render
fi
