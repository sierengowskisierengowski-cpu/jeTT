# Cerberus

Cerberus is a Linux XDR (Extended Detection and Response) platform built around three layers:

- **eBPF kernel sensors** for low-overhead telemetry collection
- **A userland agent** to normalize, enrich, and evaluate events
- **A control plane** for policy, alerting, and fleet-wide visibility

This repository currently contains the local Rust prototype that powers the CLI, daemon, and model-driven verdict path used for Cerberus development.

**jeTT** is the name of the runtime in this repo: the `jeTT` CLI, `jett-daemon`, `src/engine.rs`, and training generators. Cerberus is the broader XDR platform; jeTT is the on-box AI EDR brain.

## Repository contents

- Rust inference binary with `--guard`, `--alert`, and `--query`
- `jett-daemon` process monitor and dispatcher
- Training/data generation utilities
- Systemd service and packaging artifacts

## Status

See [STATUS.md](STATUS.md) for what is already working and what is still planned.

## Install

See [INSTALL.md](INSTALL.md) for build instructions.

## License

See [LICENSE](LICENSE).
