# jeTT Status

## Shipping today

- **AI EDR daemon** (`jett-daemon`) — `/proc` and optional eBPF telemetry, behavior profiling, Granite guard inference
- **Learn mode (default)** — logs `WOULD-quarantine` without killing processes
- **Enforce mode (opt-in)** — `kill -9` + quarantine copy; `JETT_ENFORCE_DRY_RUN=1` for safe smoke validation
- **Hard rules** — never-fast-trust, quarantine floor, own-stack allowlist (`/etc/jett/allowlist.conf`)
- **Model integrity** — SHA-256 pin at startup (`scripts/pin_model.sh`, `JETT_MODEL_PIN`)
- **Eval** — v6 guard set at 100% with rules; adversarial suite (`eval_guard.py --suite adversarial`)
- **Smoke harness** — learn: `scripts/art_jett_smoke.sh`; enforce dry-run: `scripts/enforce_smoke.sh`
- **Control panel** — `./jett` (status, logs, mode, smoke, rebuild)

## In progress

- Learn-mode soak on production stack (harvest FPs for v7 eval)
- GitHub release binaries + `install.sh` wiring (Tier 3)

## Planned

- GitHub Actions release builds (CUDA/NCCL)
- eBPF production path hardening (`JETT_TELEMETRY=both`)
- Quarantine alerting hooks and fleet control plane (Cerberus layer)

## Eval scoreboard

| Milestone | Score |
|-----------|-------|
| r6 + hard rules + own-stack ALLOW | **382/382 v6 (100%)** |
| Threat bucket | **148/148** |
| Adversarial suite | CI via `scripts/run_adversarial_eval.sh` |

Real-world coverage expands via learn-mode harvest → v7 eval set.

## North Star (Tier 7)

Enterprise differentiators — kernel risk graph, ATT&CK chains, tiered response, eBPF+LSM, evidence vault, plugin SDK, offline SOC, federated intel. Full matrix and build order in `ROADMAP.md` § Tier 7.
