#!/usr/bin/env bash
# jeTT control panel — interactive menu + subcommands (start/stop/logs/config).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_FILE="/var/log/jett/jett.log"
AUDIT_LOG="/var/log/jett/scoring_audit.log"
QUAR_LOG="/var/jett/quarantine/quarantine.log"
DEFAULT_FILE="/etc/default/jett"
SERVICE="jett-daemon.service"

load_defaults() {
  if [[ -f "$DEFAULT_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$DEFAULT_FILE"
    set +a
  fi
}

resolve_engine_bin() {
  if [[ -n "${JETT_ENGINE_BIN:-}" && -x "${JETT_ENGINE_BIN}" ]]; then
    printf '%s\n' "${JETT_ENGINE_BIN}"
    return
  fi
  for candidate in \
    "${REPO_ROOT}/target/release/jeTT" \
    "/usr/local/lib/jett/jeTT" \
    "/usr/lib/jett/jeTT"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  printf '%s\n' "${REPO_ROOT}/target/release/jeTT"
}

resolve_model() {
  load_defaults
  if [[ -n "${JETT_MODEL:-}" && -f "${JETT_MODEL}" ]]; then
    printf '%s\n' "${JETT_MODEL}"
    return
  fi
  local latest=""
  latest="$(find "${REPO_ROOT}/models" -maxdepth 1 -name 'jett-r*-q4_k_m.gguf' 2>/dev/null | sort -V | tail -1 || true)"
  if [[ -n "$latest" ]]; then
    printf '%s\n' "$latest"
    return
  fi
  for fallback in \
    "${REPO_ROOT}/models/jett-r6-q4_k_m.gguf" \
    "${REPO_ROOT}/models/jeTT-r3-q4.gguf" \
    "/opt/jett/models/jeTT-q4.gguf"; do
    if [[ -f "$fallback" ]]; then
      printf '%s\n' "$fallback"
      return
    fi
  done
  printf '%s\n' "${REPO_ROOT}/models/jett-r6-q4_k_m.gguf"
}

daemon_active() {
  systemctl is-active --quiet "$SERVICE" 2>/dev/null
}

mode_label() {
  load_defaults
  if [[ "${JETT_MODE:-learn}" =~ ^[Ee]nforce ]]; then
    echo -e "${RED}ENFORCE${NC} (kills enabled)"
  else
    echo -e "${YELLOW}LEARN${NC} (log only)"
  fi
}

telemetry_label() {
  load_defaults
  echo "${JETT_TELEMETRY:-proc}"
}

need_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

banner() {
  echo -e "${RED}${BOLD}"
  cat <<'BANNER'
     _ _____ _____ _____
    | | ____|_   _|_   _|
 _  | |  _|   | |   | |
| |_| | |___  | |   | |
 \___/|_____| |_|   |_|
BANNER
  echo -e "${NC}${DIM}  Local AI EDR — IBM Granite 3.3 2B${NC}"
  echo ""
}

status_block() {
  load_defaults
  local engine model lines quar
  engine="$(resolve_engine_bin)"
  model="$(resolve_model)"

  echo -e "${BOLD}${CYAN}────────────────────────────────────────${NC}"
  if daemon_active; then
    echo -e "  Daemon   ${GREEN}● running${NC}"
  else
    echo -e "  Daemon   ${RED}● stopped${NC}"
  fi
  echo -e "  Mode     $(mode_label)"
  echo -e "  Telemetry $(telemetry_label)"
  if [[ -f "$model" ]]; then
    echo -e "  Model    ${DIM}$(basename "$model")${NC}"
  else
    echo -e "  Model    ${RED}missing: ${model}${NC}"
  fi
  if [[ -x "$engine" ]]; then
    echo -e "  Engine   ${DIM}$(basename "$engine")${NC}"
  else
    echo -e "  Engine   ${RED}not built — run: jett rebuild${NC}"
  fi
  lines="$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)"
  quar="$(wc -l < "$QUAR_LOG" 2>/dev/null || echo 0)"
  echo -e "  Log      ${DIM}${lines} lines${NC}  Quarantine ${DIM}${quar} events${NC}"
  echo -e "${BOLD}${CYAN}────────────────────────────────────────${NC}"
}

cmd_start() {
  need_sudo systemctl start "$SERVICE"
  sleep 1
  if daemon_active; then
    echo -e "${GREEN}[+] jeTT daemon started${NC}"
  else
    echo -e "${RED}[!] failed to start — try: jett status${NC}"
    need_sudo systemctl status "$SERVICE" --no-pager || true
  fi
}

cmd_stop() {
  need_sudo systemctl stop "$SERVICE"
  echo -e "${RED}[-] jeTT daemon stopped${NC}"
}

cmd_restart() {
  need_sudo systemctl restart "$SERVICE"
  sleep 1
  echo -e "${YELLOW}[~] jeTT daemon restarted${NC}"
}

cmd_status() {
  banner
  status_block
  echo ""
  if daemon_active; then
    need_sudo systemctl status "$SERVICE" --no-pager -l || true
  fi
}

cmd_logs() {
  local follow="${1:-}"
  if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${YELLOW}[!] no log yet at ${LOG_FILE}${NC}"
    return 1
  fi
  if [[ "$follow" == "-f" || "$follow" == "--follow" ]]; then
    echo -e "${DIM}tail -f ${LOG_FILE} — Ctrl+C to stop${NC}"
    tail -f "$LOG_FILE"
  else
    tail -n "${1:-50}" "$LOG_FILE"
  fi
}

cmd_audit() {
  if [[ ! -f "$AUDIT_LOG" ]]; then
    echo -e "${DIM}no scoring audit log yet (${AUDIT_LOG})${NC}"
    return 0
  fi
  tail -n "${1:-30}" "$AUDIT_LOG"
}

cmd_quarantine() {
  if [[ ! -f "$QUAR_LOG" ]]; then
    echo -e "${GREEN}[+] no quarantine events${NC}"
    return 0
  fi
  cat "$QUAR_LOG"
}

run_engine() {
  local flag="$1"
  shift
  local payload="$*"
  local engine model
  engine="$(resolve_engine_bin)"
  model="$(resolve_model)"
  if [[ ! -x "$engine" ]]; then
    echo -e "${RED}[!] engine not found — run: jett rebuild${NC}"
    return 1
  fi
  if [[ ! -f "$model" ]]; then
    echo -e "${RED}[!] model not found: ${model}${NC}"
    return 1
  fi
  JETT_MODEL="$model" "$engine" "$flag" "$payload"
}

cmd_config() {
  load_defaults
  echo -e "${BOLD}Runtime config${NC}"
  echo "  file: ${DEFAULT_FILE}"
  echo ""
  if [[ -f "$DEFAULT_FILE" ]]; then
    grep -E '^JETT_' "$DEFAULT_FILE" || echo "  (no JETT_* vars set)"
  else
    echo "  (file missing — using defaults)"
    echo "  JETT_MODE=learn"
    echo "  JETT_TELEMETRY=proc"
  fi
  echo ""
  echo -e "${DIM}Edit: sudo \$EDITOR ${DEFAULT_FILE}${NC}"
  echo -e "${DIM}Then: jett restart${NC}"
}

set_default_var() {
  local key="$1"
  local val="$2"
  need_sudo mkdir -p "$(dirname "$DEFAULT_FILE")"
  if [[ -f "$DEFAULT_FILE" ]] && grep -q "^${key}=" "$DEFAULT_FILE"; then
    need_sudo sed -i "s|^${key}=.*|${key}=${val}|" "$DEFAULT_FILE"
  else
    echo "${key}=${val}" | need_sudo tee -a "$DEFAULT_FILE" >/dev/null
  fi
}

cmd_mode() {
  local mode="${1:-}"
  case "$mode" in
    learn)
      set_default_var JETT_MODE learn
      echo -e "${YELLOW}[~] learn mode — logs WOULD-quarantine, no kills${NC}"
      ;;
    enforce)
      set_default_var JETT_MODE enforce
      echo -e "${RED}[!] enforce mode — quarantine kills enabled${NC}"
      ;;
    *)
      echo "Usage: jett mode learn|enforce"
      return 1
      ;;
  esac
  echo -e "${DIM}restart daemon to apply: jett restart${NC}"
}

cmd_model() {
  local path="${1:-}"
  if [[ -z "$path" ]]; then
    echo "Model: $(resolve_model)"
    echo ""
    echo "Installed:"
    ls -1 "${REPO_ROOT}/models"/jett-r*.gguf 2>/dev/null || echo "  (none in repo)"
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    echo -e "${RED}[!] not found: ${path}${NC}"
    return 1
  fi
  set_default_var JETT_MODEL "$path"
  echo -e "${GREEN}[+] model set to ${path}${NC}"
  echo -e "${DIM}restart daemon to apply: jett restart${NC}"
}

cmd_rebuild() {
  echo -e "${CYAN}[*] building jeTT + jett-daemon (release)...${NC}"
  (cd "$REPO_ROOT" && cargo build --release --features ebpf)
  echo -e "${GREEN}[+] build done${NC}"
  echo -e "${DIM}restart daemon to pick up binaries: jett restart${NC}"
}

cmd_smoke() {
  local script="${REPO_ROOT}/scripts/art_jett_smoke.sh"
  if [[ ! -x "$script" ]]; then
    echo -e "${RED}[!] missing ${script}${NC}"
    return 1
  fi
  bash "$script"
}

cmd_demo() {
  local engine model
  engine="$(resolve_engine_bin)"
  model="$(resolve_model)"
  if [[ ! -x "$engine" ]]; then
    echo -e "${RED}[!] engine not found — run: jett rebuild${NC}"
    return 1
  fi
  if [[ ! -f "$model" ]]; then
    echo -e "${RED}[!] model not found: ${model}${NC}"
    return 1
  fi
  JETT_MODEL="$model" "$engine"
}

cmd_help() {
  cat <<EOF
jeTT control panel

  jett                  Open interactive menu
  jett status           Daemon + config summary
  jett start|stop|restart
  jett logs [-f]        Main daemon log (default: last 50 lines)
  jett audit [N]        Deception/scoring audit log
  jett quarantine       Quarantine event log
  jett guard <event>    Test guard on one event string
  jett alert <event>    Threat explanation
  jett query <text>     Offline prompt query
  jett mode learn|enforce
  jett model [path]     Show or set JETT_MODEL in ${DEFAULT_FILE}
  jett config           Show runtime env file
  jett rebuild          cargo build --release --features ebpf
  jett smoke            Safe ART learn-mode smoke tests
  jett demo             Run built-in engine demo suite

Engine CLI flags also work: jett --guard|--alert|--query|--trust|--list-trusted ...
EOF
}

show_menu() {
  clear
  banner
  status_block
  echo ""
  echo -e "  ${GREEN}1${NC}  Start daemon      ${RED}2${NC}  Stop daemon      ${YELLOW}3${NC}  Restart"
  echo -e "  ${CYAN}4${NC}  Status detail     ${CYAN}5${NC}  Live logs        ${CYAN}6${NC}  Quarantine log"
  echo -e "  ${CYAN}7${NC}  Audit log         ${YELLOW}8${NC}  Guard test       ${YELLOW}9${NC}  Query jeTT"
  echo -e "  ${YELLOW}0${NC}  Alert explain     ${DIM}a${NC}  Config           ${DIM}m${NC}  Set mode"
  echo -e "  ${DIM}r${NC}  Rebuild           ${DIM}s${NC}  ART smoke        ${DIM}d${NC}  Demo suite"
  echo ""
  echo -e "  ${DIM}h  Help    q  Quit${NC}"
  echo ""
  echo -ne "  ${BOLD}→ ${NC}"
}

menu_loop() {
  while true; do
    show_menu
    read -r choice
    case "$choice" in
      1) echo ""; cmd_start; read -rp "  Enter..." _ ;;
      2) echo ""; cmd_stop; read -rp "  Enter..." _ ;;
      3) echo ""; cmd_restart; read -rp "  Enter..." _ ;;
      4) echo ""; cmd_status; read -rp "  Enter..." _ ;;
      5) echo ""; cmd_logs -f ;;
      6) echo ""; cmd_quarantine; read -rp "  Enter..." _ ;;
      7) echo ""; cmd_audit 40; read -rp "  Enter..." _ ;;
      8)
        echo ""
        echo -ne "  ${YELLOW}Event: ${NC}"
        read -r event
        run_engine --guard "$event" || true
        read -rp "  Enter..." _
        ;;
      9)
        echo ""
        echo -ne "  ${YELLOW}Question: ${NC}"
        read -r q
        run_engine --query "$q" || true
        read -rp "  Enter..." _
        ;;
      0)
        echo ""
        echo -ne "  ${YELLOW}Event: ${NC}"
        read -r event
        run_engine --alert "$event" || true
        read -rp "  Enter..." _
        ;;
      a|A) echo ""; cmd_config; read -rp "  Enter..." _ ;;
      m|M)
        echo ""
        echo -e "  ${YELLOW}1${NC} learn   ${RED}2${NC} enforce"
        echo -ne "  ${BOLD}→ ${NC}"
        read -r mchoice
        case "$mchoice" in
          1) cmd_mode learn ;;
          2) cmd_mode enforce ;;
        esac
        read -rp "  Enter..." _
        ;;
      r|R) echo ""; cmd_rebuild; read -rp "  Enter..." _ ;;
      s|S) echo ""; cmd_smoke; read -rp "  Enter..." _ ;;
      d|D) echo ""; cmd_demo; read -rp "  Enter..." _ ;;
      h|H) echo ""; cmd_help; read -rp "  Enter..." _ ;;
      q|Q) echo ""; exit 0 ;;
    esac
  done
}

main() {
  local cmd="${1:-menu}"
  shift || true
  case "$cmd" in
    menu|panel|"")
      menu_loop
      ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    logs)
      if [[ "${1:-}" == "-f" || "${1:-}" == "--follow" ]]; then
        cmd_logs -f
      else
        cmd_logs "${1:-50}"
      fi
      ;;
    audit) cmd_audit "${1:-30}" ;;
    quarantine|quar) cmd_quarantine ;;
    guard) run_engine --guard "$*" ;;
    alert) run_engine --alert "$*" ;;
    query) run_engine --query "$*" ;;
    config|cfg) cmd_config ;;
    mode) cmd_mode "${1:-}" ;;
    model) cmd_model "${1:-}" ;;
    rebuild|build) cmd_rebuild ;;
    smoke|art) cmd_smoke ;;
    demo) cmd_demo ;;
    help|-h|--help) cmd_help ;;
    *)
      echo "Unknown command: $cmd"
      cmd_help
      exit 1
      ;;
  esac
}

main "$@"
