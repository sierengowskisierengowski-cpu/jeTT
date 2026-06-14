#!/usr/bin/env bash
set -euo pipefail

REPO="sierengowskisierengowski-cpu/jeTT"
INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_LIB_DIR="/usr/local/lib/jett"
SERVICE_PATH="/etc/systemd/system/jett-daemon.service"

log() {
  printf '[jett-install] %s\n' "$*"
}

die() {
  printf '[jett-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root (for example: sudo bash install.sh)"
fi

require_cmd curl
require_cmd python3
require_cmd install
require_cmd systemctl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

install_wrapper_and_service() {
  local tag="${1:-main}"
  local wrapper_source="${SCRIPT_DIR}/jett"
  local service_source="${SCRIPT_DIR}/jett-daemon.service"

  if [[ ! -f "${wrapper_source}" ]]; then
    wrapper_source="${TMP_DIR}/jett"
    local wrapper_url="https://raw.githubusercontent.com/${REPO}/${tag}/jett"
    curl -fsSL "${wrapper_url}" -o "${wrapper_source}" || die "Unable to fetch jett wrapper script from ${wrapper_url}"
  fi

  if [[ ! -f "${service_source}" ]]; then
    service_source="${TMP_DIR}/jett-daemon.service"
    local service_url="https://raw.githubusercontent.com/${REPO}/${tag}/jett-daemon.service"
    curl -fsSL "${service_url}" -o "${service_source}" || die "Unable to fetch jett-daemon.service from ${service_url}"
  fi

  install -Dm755 "${wrapper_source}" "${INSTALL_BIN_DIR}/jett"
  ln -sf "${INSTALL_BIN_DIR}/jett" "${INSTALL_BIN_DIR}/jeTT"
  install -Dm644 "${service_source}" "${SERVICE_PATH}"
}

extract_binary() {
  local downloaded_file="$1"
  local match_pattern="$2"
  local out_path="$3"

  if tar -tf "${downloaded_file}" >/dev/null 2>&1; then
    local unpack_dir="${TMP_DIR}/unpack-$(basename "${out_path}")"
    mkdir -p "${unpack_dir}"
    tar -xf "${downloaded_file}" -C "${unpack_dir}"
    local found
    found="$(find "${unpack_dir}" -type f -perm -111 | grep -Ei "${match_pattern}" | head -n 1 || true)"
    [[ -n "${found}" ]] || die "Could not find expected binary in archive ${downloaded_file}"
    install -Dm755 "${found}" "${out_path}"
    return
  fi

  if python3 - <<'PY' "${downloaded_file}"
import sys, zipfile
try:
    with zipfile.ZipFile(sys.argv[1], "r"):
        pass
except zipfile.BadZipFile:
    raise SystemExit(1)
PY
  then
    local unpack_dir="${TMP_DIR}/unpack-$(basename "${out_path}")"
    mkdir -p "${unpack_dir}"
    python3 - <<'PY' "${downloaded_file}" "${unpack_dir}"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "r") as zf:
    zf.extractall(sys.argv[2])
PY
    local found
    found="$(find "${unpack_dir}" -type f -perm -111 | grep -Ei "${match_pattern}" | head -n 1 || true)"
    [[ -n "${found}" ]] || die "Could not find expected binary in zip asset ${downloaded_file}"
    install -Dm755 "${found}" "${out_path}"
    return
  fi

  install -Dm755 "${downloaded_file}" "${out_path}"
}

find_asset_url() {
  local release_json="$1"
  local kind="$2"
  python3 - <<'PY' "${release_json}" "${kind}"
import json, sys
release_json_path, kind = sys.argv[1], sys.argv[2]
with open(release_json_path, 'r', encoding='utf-8') as fh:
    data = json.load(fh)
assets = data.get('assets', [])

def score(name: str, target: str) -> int:
    n = name.lower()
    if n.endswith(('.sha256', '.sig', '.asc', '.txt')):
        return -1
    if 'linux' not in n:
        return -1
    if target == 'daemon':
        if 'daemon' not in n or 'jett' not in n:
            return -1
    else:
        if 'jett' not in n or 'daemon' in n:
            return -1
    s = 10
    if 'x86_64' in n or 'amd64' in n:
        s += 5
    if n.endswith(('.tar.gz', '.tgz', '.tar')):
        s += 2
    if n.endswith('.zip'):
        s += 1
    return s

best = None
for asset in assets:
    name = asset.get('name', '')
    s = score(name, kind)
    if s < 0:
        continue
    if best is None or s > best[0]:
        best = (s, asset.get('browser_download_url', ''), name)

if best:
    print(best[1])
PY
}

install_from_github_release() {
  local release_json="${TMP_DIR}/release.json"
  log "Fetching latest release metadata from ${REPO}"
  if ! curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "${release_json}"; then
    log "No published GitHub release yet (API unreachable or 404)"
    return 1
  fi

  local tag
  tag="$(python3 - <<'PY' "${release_json}"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
print(data.get('tag_name', ''))
PY
)"
  [[ -n "${tag}" ]] || {
    log "Release metadata missing tag_name"
    return 1
  }
  log "Using release ${tag}"

  local engine_url daemon_url
  engine_url="$(find_asset_url "${release_json}" engine)"
  daemon_url="$(find_asset_url "${release_json}" daemon)"

  if [[ -z "${engine_url}" || -z "${daemon_url}" ]]; then
    log "Release ${tag} has no Linux engine/daemon tarballs yet"
    return 1
  fi

  install -d -m 0755 "${INSTALL_BIN_DIR}" "${INSTALL_LIB_DIR}"
  install -d -m 0750 "/var/log/jett" "/var/jett/quarantine"

  log "Downloading inference engine"
  local engine_file="${TMP_DIR}/engine-asset"
  curl -fL "${engine_url}" -o "${engine_file}"

  log "Downloading daemon"
  local daemon_file="${TMP_DIR}/daemon-asset"
  curl -fL "${daemon_url}" -o "${daemon_file}"

  extract_binary "${engine_file}" '(^|/)jett$|(^|/)jett-.*|(^|/)jeTT$' "${INSTALL_LIB_DIR}/jeTT"
  extract_binary "${daemon_file}" '(^|/)jett-daemon$|(^|/)jett-daemon-.*' "${INSTALL_BIN_DIR}/jett-daemon"

  install_wrapper_and_service "${tag}"
  return 0
}

build_from_source() {
  log "Building from source in ${SCRIPT_DIR} (no GitHub release assets)"
  require_cmd cargo
  require_cmd cmake

  cd "${SCRIPT_DIR}"

  local cargo_args=(build --release --bin jeTT --bin jett-daemon)
  if command -v nvcc >/dev/null 2>&1; then
    log "CUDA toolkit detected — building with default cuda feature"
    export RUSTFLAGS="${RUSTFLAGS:--L /usr/lib -l nccl}"
  else
    log "CUDA not detected — CPU-only build (slow inference; use GPU host for production)"
    cargo_args+=(--no-default-features)
  fi

  cargo "${cargo_args[@]}"

  install -d -m 0755 "${INSTALL_BIN_DIR}" "${INSTALL_LIB_DIR}"
  install -d -m 0750 "/var/log/jett" "/var/jett/quarantine"
  install -Dm755 "${SCRIPT_DIR}/target/release/jeTT" "${INSTALL_LIB_DIR}/jeTT"
  install -Dm755 "${SCRIPT_DIR}/target/release/jett-daemon" "${INSTALL_BIN_DIR}/jett-daemon"
  install_wrapper_and_service "main"
}

if install_from_github_release; then
  log "Installed from GitHub release"
else
  build_from_source
fi

log "Reloading systemd and enabling jett-daemon service"
systemctl daemon-reload
systemctl enable --now jett-daemon.service

log "Install complete"
log "Configure /etc/default/jett (JETT_MODEL, JETT_MODE=learn), then:"
log "  sudo bash scripts/install_allowlist.sh"
log "  sudo JETT_MODEL=/path/to/model.gguf bash scripts/pin_model.sh"
log "  bash scripts/deploy_walkthrough.sh"
log "  bash scripts/post_install_smoke.sh"
log "Run 'jett' or 'jeTT' for the control panel, or 'jett --guard|--alert|--query <payload>' for CLI mode"
