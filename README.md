# jeTT

jeTT is a Linux AI EDR (Endpoint Detection and Response) product: a local `jett-daemon` watches new processes, profiles behavior, and runs an on-box Granite guard model to produce **ALLOW** or **QUARANTINE** verdicts. Default operation is **learn mode** (log would-quarantine, no kills); **enforce mode** is opt-in.

## Quick start

```bash
# Build
cargo build --release --features ebpf

# Install allowlist + pin model (production paths)
sudo ./scripts/install_allowlist.sh
sudo JETT_MODEL=/path/to/jett-r6-q4_k_m.gguf ./scripts/pin_model.sh

# Control panel
./jett status
./jett smoke              # learn-mode ART smoke (safe)
```

Set `JETT_MODEL` to your GGUF path. The daemon reads `/etc/default/jett` (see `jett-daemon.service`).

## Learn vs enforce

| Mode | `JETT_MODE` | Behavior |
|------|-------------|----------|
| **Learn** (default) | `learn` | Logs `WOULD-quarantine`; no `kill -9` |
| **Enforce** | `enforce` | Kills quarantined PIDs and copies binaries to `/var/jett/quarantine` |

Switch via `./jett mode learn` or `./jett mode enforce`, then restart the daemon.

Before enabling real enforce on a host, run the safe dry-run smoke suite:

```bash
# In /etc/default/jett:
#   JETT_MODE=enforce
#   JETT_ENFORCE_DRY_RUN=1
sudo systemctl restart jett-daemon
./scripts/enforce_smoke.sh --enforce-check   # preflight
./scripts/enforce_smoke.sh                   # atoms + log verification
```

Unset `JETT_ENFORCE_DRY_RUN` only when you intend real kills.

## Eval & security tests

```bash
# v6 guard eval (stop daemon first if GPU-bound)
python3 eval_guard.py --eval tests/guard_eval_v6.jsonl

# Adversarial suite (prompt injection / honeypot)
./scripts/run_adversarial_eval.sh

# Model integrity pin
sudo ./scripts/pin_model.sh /path/to/model.gguf
```

See [docs/ART.md](docs/ART.md) for the learn-mode smoke harness.

## Repository contents

- `jeTT` CLI — `--guard`, `--alert`, `--query`
- `jett-daemon` — process monitor and enforcement dispatcher
- `src/engine.rs` — model inference and hard-rule precedence
- Training/eval scripts, systemd unit, installer

## Status & install

- [STATUS.md](STATUS.md) — what ships today vs planned
- [INSTALL.md](INSTALL.md) — build prerequisites and runtime env
- [ROADMAP.md](ROADMAP.md) — prioritized delivery checklist
- [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) — **why** key architectural choices
- [docs/RELEASE_v0.1.0.md](docs/RELEASE_v0.1.0.md) — first production release notes

## License

See [LICENSE](LICENSE).
