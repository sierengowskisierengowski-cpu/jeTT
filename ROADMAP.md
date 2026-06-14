# jeTT Master Roadmap

Prioritized top → bottom. **One item at a time.** Check off as done.

Legend: `[x]` done · `[ ]` open · `[~]` in progress / ongoing

---

## Tier 0 — Tonight's win (architecture path)

| # | Item | Status |
|---|------|--------|
| 0.1 | NEVER_FAST_TRUST precedence (no 0ms shell bypass) | [x] |
| 0.2 | Hard quarantine floor (threat patterns) | [x] |
| 0.3 | Own-stack ALLOW floor (exe-prefix + pip/php-fpm) | [x] |
| 0.4 | v6 eval **382/382 (100%)**, threat **148/148** | [x] |
| 0.5 | Code pushed to GitHub (`fe5087e`) | [x] |
| 0.6 | Production model: **r6** GGUF on daemon | [x] |

---

## Tier 1 — Lock production (do first)

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1.1 | Confirm live daemon runs **fe5087e** binary (`jett status`, restart if stale) | [x] | PID active, binary Jun 14 01:58, HEAD fe5087e |
| 1.2 | Confirm **learn mode** (not enforce) in `/etc/default/jett` | [x] | Default learn; no JETT_MODE=enforce in unit |
| 1.3 | **Stop RunPod pod** if still running | [x] | Connection refused — pod already down |
| 1.4 | Learn-mode **soak** (1–2 weeks, watch `/var/log/jett/jett.log`) | [~] | Ongoing; harvest FPs |
| 1.5 | Run `harvest_learn_log.py` weekly → candidate rows for v7 eval | [ ] | After soak starts |

---

## Tier 2 — Public / security-firm blockers (code)

| # | Item | Status | Notes |
|---|------|--------|-------|
| 2.1 | **Externalize own-stack allowlist** (`/etc/jett/allowlist.conf` + `JETT_ALLOWLIST`) | [x] | `allowlist_config.rs` + `config/allowlist.example.conf` |
| 2.2 | **Externalize daemon trusted/toolchain lists** (same config file) | [x] | `trusted_path/proc`, `toolchain_*` in allowlist.conf |
| 2.3 | Model path + **GGUF integrity check** at startup (sha256) | [ ] | Tamper detection |
| 2.4 | **Adversarial eval set** + CI tests (prompt injection can't flip verdict) | [ ] | Extend `adversarial.rs` coverage |
| 2.5 | **Enforce mode** smoke/ART suite before any enforce deploy | [ ] | Real kills |
| 2.6 | Fix **README / STATUS / INSTALL** (jeTT product, not "prototype") | [ ] | Public face |

---

## Tier 3 — Installer & releases

| # | Item | Status | Notes |
|---|------|--------|-------|
| 3.1 | GitHub Actions: build `jeTT` + `jett-daemon` (CUDA/NCCL) | [ ] | |
| 3.2 | Create **GitHub Release** assets (tarball + checksums) | [ ] | `install.sh` needs this |
| 3.3 | Wire **`install.sh`** to releases (binaries + systemd + default config) | [ ] | Script exists; no releases yet |
| 3.4 | Model download step (GGUF separate or bundled) + license note | [ ] | Size/legal |
| 3.5 | Post-install: `jett smoke` + learn mode defaults | [ ] | |

---

## Tier 4 — Model & training (only when needed)

| # | Item | Status | Notes |
|---|------|--------|-------|
| 4.1 | Verify **r6 LoRA checkpoint** exports to ~92.1% GGUF (Phase 1 gate) | [ ] | `outputs/r6/checkpoint-250` |
| 4.2 | Build **guard_eval_v7.jsonl** from learn-mode harvest | [ ] | After Tier 1 soak |
| 4.3 | **Surgical r11** from verified r6 adapter (25–40 steps, 1e-5) | [ ] | Only if rules+r6 miss v7 |
| 4.4 | **No full retrains** from Granite base | [x] | Policy — r10/r6+ proved regression |

---

## Tier 5 — Speed, telemetry, platform

| # | Item | Status | Notes |
|---|------|--------|-------|
| 5.1 | Guard latency budget doc (warm batch, daemon GPU sharing) | [ ] | |
| 5.2 | eBPF Phase 2 **production** path (`JETT_TELEMETRY=both`) | [ ] | Scaffold in tree |
| 5.3 | QUARANTINE **alerting** (notify on enforce quarantine) | [ ] | Daemon hook |
| 5.4 | Control plane / fleet enrollment | [ ] | Cerberus layer |
| 5.5 | Heimdall / Bifrost integration cleanup | [ ] | Separate repo |

---

## Tier 6 — Nice-to-have / later

| # | Item | Status |
|---|------|--------|
| 6.1 | Configurable honeypot decoy (`JETT_HONEYPOT`) docs | [ ] |
| 6.2 | Rate limit guard CPU (event flood DoS) | [ ] |
| 6.3 | Signed config / policy bundles | [ ] |
| 6.4 | Multi-user allowlist profiles | [ ] |

---

## Current focus

**Next item:** **2.3** — GGUF integrity check at startup.

---

## Scoreboard (eval)

| Milestone | Score |
|-----------|-------|
| r6 model alone (historical) | 92.1% v6 |
| + hard rules (before ALLOW floor) | 90.8% v6 |
| + own-stack ALLOW (`fe5087e`) | **100% v6** |
| Threat bucket | **148/148** |

*100% on v6 is the floor. Real-world coverage = learn mode → v7 eval.*
