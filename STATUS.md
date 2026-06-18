# jeTT Status

**Last updated:** 2026-06-14 · **Git:** `main` · **Release:** `v0.1.0` · **Remote:** https://github.com/sierengowskisierengowski-cpu/jeTT

---

## Production host (nyx-cosmic) — deploy complete

| Item | Value |
|------|-------|
| Daemon | `active`, learn mode |
| Binary | `~/Projects/jeTT/target/release/jett-daemon` |
| Model | `~/Projects/jeTT/models/jett-r6-q4_k_m.gguf` |
| Pin | `/etc/jett/model.sha256` → `fcbaaac8095121af…` (verified every restart) |
| Allowlist | `/etc/jett/allowlist.conf` |
| Logs | `/var/log/jett` |
| Quarantine | `/var/jett/quarantine` |
| Evidence vault | `/var/jett/evidence/vault.jsonl` |
| Baseline | `/var/jett/baseline.json` |

Machine-specific paths above are **not in git** (by design). Templates: `config/allowlist.example.conf`, `config/model.sha256.example`.

---

## Shipping today (runtime — Rust + C)

- **AI EDR daemon** (`jett-daemon`) — `/proc` and optional eBPF telemetry, behavior profiling, Granite guard inference
- **Learn mode (default)** — logs `WOULD-quarantine` without killing processes
- **Enforce mode (opt-in)** — `kill -9` + quarantine copy; `JETT_ENFORCE_DRY_RUN=1` for safe smoke validation
- **Hard rules** — never-fast-trust, quarantine floor, own-stack allowlist (`/etc/jett/allowlist.conf`)
- **Model integrity** — SHA-256 pin at startup (`scripts/pin_model.sh`, `JETT_MODEL_PIN`)
- **Tier 7 SOC pipeline** — risk graph, ATT&CK chains, explainability, evidence vault, baseline/drift, confidence → response tier (`src/tier7_hooks.rs`)
- **Eval** — v6 **382/382** and adversarial **30/30** (100%) on production stack
- **Smoke harness** — learn: `scripts/art_jett_smoke.sh`; enforce dry-run: `scripts/enforce_smoke.sh`; red-team: `scripts/jett_redteam.sh`
- **Deploy walkthrough** — `scripts/deploy_walkthrough.sh` (step-by-step host setup)
- **Control panel** — `./jett` (status, logs, mode, smoke, rebuild)

## Dev / training (Python — not runtime)

32 tracked Python files: `training/eval_guard.py`, dataset generators, RunPod training pipelines. Local `.venv/` and `intelligence/` are gitignored.

---

## GitHub repo state

All product code through Tier 2, Tier 3 scaffolding, and Tier 7 foundation modules is **committed and pushed** to `main`.

| Tier | Status |
|------|--------|
| 0 — Architecture | **100%** |
| 1 — Lock production | **Soak active** (1.4); weekly harvest script (1.5) |
| 2 — Public blockers | **100%** |
| 3 — Installer/releases | **v0.1.0 tagged**; CI + `install.sh` + release scripts |
| 4 — Model/training | Policy locked; v7 harvest after soak |
| 5–6 | Planned |
| 7 — North Star | Foundation modules wired; hardening ongoing |

---

## Eval scoreboard

| Milestone | Score |
|-----------|-------|
| r6 + hard rules + own-stack ALLOW | **382/382 v6 (100%)** |
| Threat bucket | **148/148** |
| Adversarial suite | **30/30 (100%)** |

Real-world coverage expands via learn-mode harvest → v7 eval set.

## Architecture decisions

**[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md)** — why NEVER_FAST_TRUST, connection attribution, max_tokens, no full retrains, and more.

---

## Next (optional, not blocking prod)

1. Weekly `bash scripts/weekly_harvest.sh` during soak
2. eBPF production path, enforce on secondary test host only
3. Continue Tier 7 hardening

Release **v0.1.0** tagged. See `docs/RELEASE_v0.1.0.md`.
