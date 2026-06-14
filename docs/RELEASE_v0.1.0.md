# jeTT v0.1.0

First production release baseline — architecture-complete single-host EDR.

## Highlights

- **r6 Granite guard** with rules-first precedence (NEVER_FAST_TRUST → hard quarantine → own-stack ALLOW → model)
- **100% v6 eval** (382/382) and **100% adversarial** (30/30) on reference stack
- **Learn mode default**; enforce opt-in with dry-run smoke
- **Model SHA-256 pin** at startup (`scripts/pin_model.sh`)
- **External allowlist** (`/etc/jett/allowlist.conf`)
- **Tier 7 foundation** — risk graph, ATT&CK chains, evidence vault, explainability
- **Deploy walkthrough** — `scripts/deploy_walkthrough.sh`

## Install

See [INSTALL.md](../INSTALL.md) and [docs/MACHINE_CONFIG.md](MACHINE_CONFIG.md).

Model GGUF is **not bundled** (size/license). Pin after install.

## Architecture

See [docs/DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) for the *why* behind key choices.

## Git

Tag `v0.1.0` → commit `30f7cba` series (production deploy complete).
