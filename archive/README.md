# archive/ — Legacy Cerberus Prototype Code

This directory contains **archived** prototype code from an earlier Cerberus
design exploration.  It is **not** part of the current jeTT runtime and is
preserved here only for historical reference.

| Directory | Language | Description |
|-----------|----------|-------------|
| `agent/`  | Rust     | Prototype eBPF-based agent that shipped events to an HTTP tower. |
| `server/` | Go       | Prototype HTTP telemetry receiver for the agent above. |
| `sensor-test/` | Rust | Test harness for the early BPF ring-buffer sensor. |

## Current runtime

The current jeTT runtime is fully contained in:

- `src/` — Rust library and `jett-daemon` binary
- `bpf/jett_sensor.bpf.c` — production eBPF sensor (feature-gated)

Do **not** use anything from this directory for production deployments.
