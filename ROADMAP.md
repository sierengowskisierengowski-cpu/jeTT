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
| 2.3 | Model path + **GGUF integrity check** at startup (sha256) | [x] | `model_integrity.rs`, `scripts/pin_model.sh` |
| 2.4 | **Adversarial eval set** + CI tests (prompt injection can't flip verdict) | [x] | `tests/guard_eval_adversarial.jsonl`, `eval_guard.py --suite adversarial`, `scripts/run_adversarial_eval.sh` |
| 2.5 | **Enforce mode** smoke/ART suite before any enforce deploy | [x] | `scripts/enforce_smoke.sh`, `JETT_ENFORCE_DRY_RUN=1`, `src/enforce.rs` |
| 2.6 | Fix **README / STATUS / INSTALL** (jeTT product, not "prototype") | [x] | Public face |

---

## Tier 3 — Installer & releases

| # | Item | Status | Notes |
|---|------|--------|-------|
| 3.1 | GitHub Actions: build `jeTT` + `jett-daemon` (CUDA/NCCL) | [~] | `.github/workflows/ci.yml` — lib tests + CPU bin build; CUDA needs self-hosted / local |
| 3.2 | Create **GitHub Release** assets (tarball + checksums) | [~] | `release.yml` + `scripts/build_release.sh`; first `v*` tag pending |
| 3.3 | Wire **`install.sh`** to releases (binaries + systemd + default config) | [x] | Release download + **local build fallback** when no assets |
| 3.4 | Model download step (GGUF separate or bundled) + license note | [~] | Documented in INSTALL.md — not bundled (size/legal) |
| 3.5 | Post-install: `jett smoke` + learn mode defaults | [x] | `scripts/post_install_smoke.sh` + `scripts/deploy_walkthrough.sh` |

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

## Tier 7 — North Star (enterprise differentiators)

Vision: jeTT as a **fully offline SOC-on-host** — kernel telemetry → live risk graph → ATT&CK-mapped chains → confidence-calibrated response → tamper-proof evidence — with optional privacy-preserving fleet intel.

| # | Capability | Status | Today / next step |
|---|------------|--------|-------------------|
| 7.1 | **Kernel-to-LLM real-time risk graph** | [ ] | Partial: `ProcessEvent` → behavior → guard; no graph store or edge scoring |
| 7.2 | **Attack-chain detection** (sequence, ATT&CK-mapped) | [ ] | Partial: `spawned_children` / outbound in prompt only; no chain engine |
| 7.3 | **Autonomous response tiers** (log / contain / kill+quarantine) | [~] | Learn vs enforce + `JETT_ENFORCE_DRY_RUN`; add contain tier (cgroup/net ns) |
| 7.4 | **Adaptive baseline + drift-aware anomaly** | [ ] | Net-new; harvest learn log as seed corpus |
| 7.5 | **eBPF + BPF LSM hybrid** (observe + enforce) | [~] | eBPF scaffold (`JETT_TELEMETRY=both`); LSM hooks not started — see `docs/jeTT-eBPF-Integration-Plan-v2.md` |
| 7.6 | **Memory / syscall intent fingerprinting** | [ ] | Net-new; extend behavior pipeline beyond /proc snapshot |
| 7.7 | **Tamper-resistant append-only evidence vault** | [~] | Quarantine copies + logs; not append-only or signed |
| 7.8 | **Deterministic explainability** on every verdict | [~] | Hard rules + reasons; model path still opaque — require rule id / evidence refs |
| 7.9 | **Built-in red-team / adversary simulation** | [~] | `art_jett_smoke.sh`, `enforce_smoke.sh`, adversarial eval; unify as `jett redteam` mode |
| 7.10 | **Detector Plugin SDK** (Rust / C / Go) | [ ] | Net-new; WASM or IPC plugin host after core graph stable |
| 7.11 | **Fully offline SOC-on-host** | [~] | Local GGUF + rules; document air-gap install; no cloud dependency |
| 7.12 | **Self-optimizing probe manager** (load / threat adaptive) | [ ] | Net-new; ties to 7.5 + AI funnel backpressure (eBPF plan §3) |
| 7.13 | **Confidence-calibrated autonomous response** | [ ] | Net-new; score from rules + model + chain context → tier pick |
| 7.14 | **Privacy-preserving cross-host intel federation** | [ ] | Net-new; Cerberus / fleet layer; no raw telemetry export |

### Suggested build order (after Tier 3 ship)

1. **7.5 + 7.1** — eBPF production + event graph (foundation for chains and probes)
2. **7.2 + 7.8** — ATT&CK chain matcher + structured explain records
3. **7.3 + 7.13** — response tiers + confidence gating (extend `enforce.rs`)
4. **7.7 + 7.9** — evidence vault + unified red-team mode
5. **7.4 + 7.6 + 7.12** — baseline/drift, syscall fingerprints, adaptive probes
6. **7.10 + 7.14** — plugin SDK, then optional federated intel

---

## Current focus

**Next item:** **3.2** — tag first release (`v0.1.0`) and verify `install.sh` download path; CUDA assets via local `build_release.sh` on GPU host.

---

## Scoreboard (eval)

| Milestone | Score |
|-----------|-------|
| r6 model alone (historical) | 92.1% v6 |
| + hard rules (before ALLOW floor) | 90.8% v6 |
| + own-stack ALLOW (`fe5087e`) | **100% v6** |
| Threat bucket | **148/148** |

*100% on v6 is the floor. Real-world coverage = learn mode → v7 eval.*
