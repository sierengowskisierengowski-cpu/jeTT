# jeTT eBPF → BPF LSM Hybrid Roadmap

> **Tier 7.5** — observe with eBPF today, enforce with BPF LSM hooks tomorrow.
> Aligns with [jeTT-eBPF-Integration-Plan-v2.md](jeTT-eBPF-Integration-Plan-v2.md) and ROADMAP Tier 5.2.

## Current state (Phase 1 — observe)

| Component | Status | Notes |
|-----------|--------|-------|
| `sched_process_exec` sensor | Scaffold | `bpf/jett_sensor.bpf.c`, `JETT_TELEMETRY=both` |
| `/proc` fallback | Production | 100ms poll, argv enrichment |
| Event coordinator | Production | Dedup, backpressure, stats |
| Userspace enforce | Production | `kill -9` + quarantine copy (`daemon.rs`) |
| Risk graph / chains | Scaffold | Tier 7.1/7.2 in-process (`risk_graph.rs`, `attack_chain.rs`) |

**Principle:** BPF observes; Rust decides. AI and policy stay in userspace.

## Phase 2 — production eBPF path (Tier 5.2)

Cross-ref ROADMAP **5.2**: ship `JETT_TELEMETRY=both` as default for security-firm installs.

1. Harden ringbuf consumer + characterization tests (eBPF plan §6).
2. inode/dev identity keying for quarantine (v1.5 in integration plan).
3. Self-noise audit — behavior collectors must not re-trigger the sensor.
4. Adaptive probe budget (`probe_manager.rs`) tied to AI queue depth.

**Exit criteria:** 24h soak with `both` mode, dedup rate stable, no AI queue stall.

## Phase 3 — BPF LSM enforce hooks (not started)

Kernel LSM programs attach at decision points; userspace still owns verdict logic.

| Hook | Purpose | jeTT action |
|------|---------|-------------|
| `bpf_lsm_bprm_check_security` | Block exec of quarantined inode | Deny exec after vault verdict |
| `bpf_lsm_file_open` | Sensitive path read/write | Log + escalate to graph |
| `bpf_lsm_socket_connect` | Egress control | Contain tier (`response.rs`) |
| `bpf_lsm_task_alloc` | Parent/child lineage | Feed `risk_graph` spawn edges |

### Implementation plan (when LSM work begins)

```
bpf/
  jett_sensor.bpf.c      # existing observe
  jett_lsm_enforce.bpf.c # NEW — LSM programs (Phase 3)
src/ebpf/
  lsm_loader.rs          # attach LSM links alongside sensor
```

1. **Map design:** `quarantine_inodes` (hash), `policy_flags` (array), `audit_ringbuf`.
2. **Userspace sync:** After `EvidenceVault::append` + KillQuarantine tier, pin inode in map.
3. **Contain tier:** LSM socket_connect → `SK_DENY` for PID cgroup (placeholder today in `apply_contain_placeholder`).
4. **Fail-open telemetry, fail-closed enforce:** LSM detach → log error; do not silently allow quarantine bypass.

## Phase 4 — hybrid operations

| Mode | Observe | Enforce |
|------|---------|---------|
| `learn` | eBPF + /proc | Log only |
| `enforce` | eBPF + /proc | Userspace kill + LSM exec block |
| `contain` | Full | cgroup/netns + LSM egress (Tier 7.3) |

Environment knobs (future):

```bash
JETT_LSM_ENFORCE=0|1          # default 0 until Phase 3 ships
JETT_LSM_SOCKET_DENY=0|1      # contain tier egress
JETT_TELEMETRY=proc|ebpf|both
```

## Dependencies

- Kernel ≥ 5.7 with BPF LSM enabled (`CONFIG_BPF_LSM=y`)
- libbpf-rs loader already in tree (`--features ebpf`)
- Tier 7.7 evidence vault provides tamper-evident audit trail for LSM denials

## What we are NOT doing yet

- No `jett_lsm_enforce.bpf.c` in this milestone (document only).
- No inference in BPF.
- No replacement of `collect_behavior()` — LSM supplements, not replaces, behavior funnel.

## Suggested order

1. Finish Phase 2 (Tier 5.2 production eBPF).
2. Ship Tier 7.1–7.3 graph + chains + response tiers in userspace.
3. Add LSM exec block keyed on vault inode (Phase 3 smallest slice).
4. Expand to socket/file hooks for contain tier.
