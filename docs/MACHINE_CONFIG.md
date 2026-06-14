# Production machine config (not in git)

These files live on the host under `/etc/jett/` and `/etc/default/jett`. They are **machine-specific** and must be created during deploy — they are never committed.

## Required on a production host

| Path | Created by | Purpose |
|------|------------|---------|
| `/etc/jett/model.sha256` | `scripts/pin_model.sh` | GGUF SHA-256 pin |
| `/etc/jett/allowlist.conf` | `scripts/install_allowlist.sh` | Own-stack ALLOW + trusted paths |
| `/etc/default/jett` | manual / `install.sh` | `JETT_MODEL`, `JETT_MODE`, telemetry |

## nyx-cosmic reference (2026-06-14)

```
JETT_MODEL=/home/cosmic/Projects/jeTT/models/jett-r6-q4_k_m.gguf
JETT_MODE=learn
JETT_ALLOWLIST=/etc/jett/allowlist.conf
JETT_MODEL_PIN=/etc/jett/model.sha256
```

Pin hash: `fcbaaac8095121af596d576c4462bfcd4b3ace8c967d77dffe3c7f523038806a`

## Runtime data (created by daemon)

| Path | Purpose |
|------|---------|
| `/var/log/jett/` | Event and verdict logs |
| `/var/jett/quarantine/` | Enforce-mode binary copies |
| `/var/jett/evidence/vault.jsonl` | Tier 7 hash-chained evidence |
| `/var/jett/baseline.json` | Tier 7 benign baseline |

## Re-deploy from git

```bash
cd ~/Projects/jeTT && git pull
RUSTFLAGS="-L /usr/lib -l nccl" cargo build --release --bin jeTT --bin jett-daemon
bash scripts/pin_model.sh "$JETT_MODEL"
bash scripts/install_allowlist.sh
sudo systemctl restart jett-daemon
```

Full walkthrough: `bash scripts/deploy_walkthrough.sh`

## Learn soak + weekly harvest

Keep `JETT_MODE=learn` for 1–2 weeks. Harvest false positives weekly:

```bash
bash ~/Projects/jeTT/scripts/weekly_harvest.sh
```

Cron example (Sundays 03:00): see script header in `scripts/weekly_harvest.sh`.
