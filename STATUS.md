# Cerberus Status

## Working

- Rust CLI binary with `--guard`, `--alert`, and `--query`
- Offline model-backed verdict path
- `jett-daemon` process monitoring and dispatch
- Training and dataset generation scripts
- Packaging and service files for local deployment

## Planned

- eBPF kernel sensors for process, file, and network telemetry
- Userland agent for telemetry collection and normalization
- Control plane APIs for alerting, policy, and fleet management
- Centralized sensor enrollment and configuration
- Remote response actions and reporting

## Notes

Cerberus is being developed as a Linux-first XDR stack. The current repository is a prototype stage codebase, so the control-plane and eBPF layers are not yet complete.
