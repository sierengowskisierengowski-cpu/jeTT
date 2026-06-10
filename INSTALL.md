# Install

## Prerequisites

- Linux
- Rust toolchain
- CMake and a C/C++ compiler
- CUDA Toolkit, because the Rust model backend is built with `llama-cpp-2` CUDA support
- Go 1.22+ for any Go-based control-plane services

## Rust components

Build the Rust binaries:

```bash
cargo build --release
```

Build just the daemon:

```bash
cargo build --release --bin jett-daemon
```

Run the local test suite:

```bash
cargo test
```

## Go components

When the Go control-plane module is present, build it from that module directory:

```bash
go build ./...
```

Run Go tests:

```bash
go test ./...
```

## Runtime notes

- Set `JETT_MODEL` to the GGUF model path before running the binaries.
- The daemon expects the `jeTT` binary path to be available through `JETT_BIN` or the service configuration.
