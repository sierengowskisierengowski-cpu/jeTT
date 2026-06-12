# jeTT eBPF Integration Plan (v2 — corrected)

Authoritative design doc for adding kernel telemetry to jeTT. This revision folds in
review feedback on hooks, short-lived processes, AI throughput, quarantine identity,
self-noise, and Phase 0 testing discipline.

**Status:** planning — not yet implemented on `main`.

---

## 1. Goals and non-goals

### Goals

- Kernel-native telemetry for **successful** process execution (and later sensitive file access).
- One unified pipeline: all sources → `ProcessEvent` → classify → profile → `engine::guard` → enforce/log.
- Self-contained in jeTT (`bpf/` + `build.rs`; daemon loads its own program).
- Safe by default: learn mode unchanged; enforce opt-in; graceful fallback if BPF fails.
- CO-RE (`vmlinux.h` + BTF) for portable builds on Arch rolling kernels.

### Non-goals (v1)

- Bifrost / external socket integration.
- Tetragon-scale full syscall observability.
- Inference inside BPF.
- TensorRT / cloud routing.

---

## 2. Design principles

| Principle | Meaning |
|-----------|---------|
| **BPF observes, userspace decides** | AI and policy live in Rust only. |
| **Fail open on telemetry, fail closed on enforce** | BPF dies → fall back to `/proc`. AI error → do not kill (unless explicit policy). |
| **Exec success, not exec intent** | Detection ringbuf uses `sched_process_exec`, not `sys_enter_execve`. |
| **Snapshot fast, judge slow** | On eBPF event, capture `/proc` immediately; do not wait 1.5s for short-lived PIDs. |
| **Heuristics must drop 99%+** | AI is ~4 verdicts/sec; kernel prefilter + `classify_event` must be ruthless. |
| **Identity over PID** | Quarantine keys `(st_dev, st_ino)` at v1.5, not bare PID. |
| **Single inference thread** | `LlamaModel` is not thread-safe; never call `guard()` from ringbuf callback. |
| **Characterize before refactor** | Phase 0 pins behavior with tests before moving `daemon.rs`. |

---

## 3. Current jeTT pipeline (baseline)

```
/proc poll (100ms) → ProcessEvent → classify_event
  → Trusted: log
  → Suspicious: collect_behavior (~1.5s) → engine_guard → kill or learn-log
  → Unknown: review log
```

eBPF replaces **how** `ProcessEvent` is created. Everything from `classify_event` onward
stays, but **profiling strategy splits by event source** (see §7).

**Verified (2026-05):** `collect_behavior()` reads `/proc` via `fs::*` only — no `Command::`
subprocesses for profiling. Self-noise risk is from **other** daemon paths (`run_guard_subprocess`,
`kill`, `notify-send`), not from behavior collection. Seed `trusted_tgid` with daemon TGID anyway.

---

## 4. Target architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Kernel                                                          │
│  sched_process_exec ──► ringbuf (detection)                     │
│  sys_enter_execve   ──► LSM bprm (block only, Phase 4)          │
│  sys_enter_openat   ──► ringbuf (filtered, Phase 3)             │
│  quarantine map     ◄── userspace (inode+dev key, Phase 1.5)    │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│ Telemetry layer                                                 │
│  EbpfSensor (ringbuf poll thread)                               │
│  ProcScanner (fallback / argv enrichment)                       │
│  EventCoordinator (dedup, rate limit, bounded queue)            │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│ Inference worker (ONE thread — owns Engine)                     │
│  classify_event → profile → engine_guard → enforce / log        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Hook selection (corrected)

### Detection — `tp/sched/sched_process_exec`

**Use for the ringbuf.** Fires after the kernel commits exec: real binary, real PID/TGID,
no noise from failed exec attempts (ENOENT, permission denied).

This is what Falco and Tetragon use for “process actually executed.”

```c
SEC("tp/sched/sched_process_exec")
int jett_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Read resolved path from ctx (CO-RE field access per kernel version)
    // Submit jett_event to ringbuf
}
```

Event fields from tracepoint (typical):

- `pid`, `old_pid` (thread semantics — document which you key on; prefer **TGID**)
- Resolved executable path (post-commit)
- `comm` updated

### Blocking — `lsm/bprm_check_security` (Phase 4 only)

Intercept **before** exec commits. Return `-EPERM` if `(st_dev, st_ino)` or cgroup is quarantined.

Do **not** use `sys_enter_execve` for detection ringbuf.

### Optional — `tp/syscalls/sys_enter_execve`

Reserve for future “block on attempt” LSM complement or research tooling — not v1 detection.

### Phase 3 — `tp/syscalls/sys_enter_openat`

Sensitive path prefixes only (kernel-side filter). See §8.

---

## 6. Event schema

### Kernel struct (`bpf/jett_sensor.bpf.c`)

```c
#define JETT_EVENT_VERSION 2
#define JETT_EVT_EXEC     1   // sched_process_exec
#define JETT_EVT_OPENAT   2   // phase 3

struct jett_event {
    __u32 version;
    __u32 pid;          // TGID
    __u32 uid;
    __u32 event_type;
    __u64 ts_ns;
    __u64 inode;        // st_ino at exec time (userspace may also stat)
    __u32 dev_major;
    __u32 dev_minor;
    char comm[16];
    char path[256];     // resolved exe path
};
```

### Rust `ProcessEvent`

```rust
pub struct ProcessEvent {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: String,
    pub uid: u32,
    pub timestamp: u64,
    pub source: EventSource,
    pub inode: Option<(u64, u64)>,  // (dev, ino) from immediate stat
}
```

### Dedup key

`(pid, event_type, inode)` within `JETT_DEDUP_MS` (default 2000ms).

BPF `sched_process_exec` + `/proc` scanner may both see the same exec — coordinator drops duplicates.

---

## 7. Short-lived processes vs behavioral profiling (resolved)

### The tension

eBPF wins by seeing execs that die before the next 100ms `/proc` scan.

`collect_behavior()` polls `/proc` three times over **~1.5s**. A dropper that exits in 50ms
leaves nothing to profile — AI gets path+comm only (weak signal → hallucination risk).

### The fix — dual profiling strategy

| Source | Profiling | When |
|--------|-----------|------|
| **eBPF exec event** | `snapshot_behavior(pid)` — single immediate read of fds, tcp, children | **< 10ms** after event |
| **/proc-only event** | `collect_behavior(pid)` — 3× poll over 1.5s | Long-lived or fallback path |
| **openat events (Phase 3)** | Append path access to rolling per-PID buffer | While process alive |

#### `snapshot_behavior(pid)` (new)

On eBPF path, **before** any sleep:

1. `collect_connections(pid)`
2. `collect_open_files(pid)`
3. `collect_children(pid)`
4. Optional: read `/proc/{pid}/maps` first line, `/proc/{pid}/status` VmRSS
5. If `/proc/{pid}` already gone → log `behavior:exited_before_snapshot` (still have kernel path)

If process still alive after snapshot and disposition is Suspicious, optionally run **one**
additional 200ms poll (`JETT_BEHAVIOR_FOLLOWUP_MS`) — not 1.5s by default on eBPF path.

#### AI input priority

```
kernel_path + comm + immediate_snapshot + (optional openat trail)
```

Path-only judgment is the **fallback**, not the eBPF default.

---

## 8. Throughput and backpressure (quantified)

### AI ceiling

- Single thread, ~225ms/inference → **~4.4 verdicts/sec sustained**
- Burst: small queue absorbs spikes; sustained overload must drop

### Exec rates (why this matters)

| Workload | execs/sec (order of magnitude) |
|----------|-------------------------------|
| Idle desktop | 1–20 |
| `cargo build` | 500–5000+ |
| Malware dropper | 1–10 |

Kernel prefilter dropping `/usr/` is necessary but **insufficient** — `rustc`, `cc`, and
build scripts exec from `~/.cargo`, `target/debug`, and `/tmp`.

### Three-stage funnel (target: <0.1% reach AI)

| Stage | Drop mechanism | Target pass rate |
|-------|----------------|------------------|
| **1. Kernel** | Prefix allow: `/usr/`, `/lib/`, `/opt/jett/`; submit suspicious paths | <5% of all execs to ringbuf |
| **2. classify_event** | `TRUSTED_PROCS`, hash allowlist, trusted prefixes | <1% of ringbuf |
| **3. Bounded queue** | `crossbeam_channel::bounded(64)`; on full → `ai_queue_dropped` | trickle to AI |

### Config

```bash
JETT_AI_QUEUE_SIZE=64
JETT_AI_QUEUE_POLICY=drop_new   # drop_new | drop_old
JETT_STAT_LOG_INTERVAL_SEC=60
```

### Stats line (every 60s)

```
[stats] ringbuf_in=12041 ringbuf_drop=3 dedup=882 classify_drop=11052
        ai_queued=38 ai_dropped=12 ai_verdicts=26 quarantine=1
```

**Acceptance:** `cargo build` with `JETT_TELEMETRY=ebpf` + learn mode — daemon stays responsive.

---

## 9. Enforcement identity (corrected)

### v1 — Userspace kill (unchanged)

`kill -9` + copy binary to `/var/jett/quarantine`.

### v1.5 — BPF quarantine map keyed by `(st_dev, st_ino)`

At exec handling time, immediately:

```rust
let (dev, ino) = stat_exe(&event.exe_path)?;
quarantine_map.update(&(dev, ino), &1, MapFlags::ANY)?;
```

TTL sweeper: `JETT_QUARANTINE_TTL_SEC` default **300** (not 60).

**Do not** rely on PID-only map for soundness. PID still used for immediate kill target.

### Fork / children

On QUARANTINE + enforce: kill TGID where possible; write inode key; optional child walk.

### Phase 4 — LSM `bprm_check_security`

Lookup quarantine by inode of file being executed. Requires `CONFIG_BPF_LSM`.

### trusted_tgid map

Seed at daemon start with jeTT daemon TGID + optional `JETT_TRUSTED_TGIDS`.

---

## 10. Repo layout

```
jeTT/
├── bpf/jett_sensor.bpf.c
├── build.rs
├── docs/EBPF.md
├── src/
│   ├── telemetry/     # event, coordinator, proc
│   ├── ebpf/          # Sensor
│   ├── pipeline/      # classify, behavior, enforce, handle
│   └── bin/daemon.rs
└── tests/
    ├── characterization/   # Phase 0 — BEFORE refactor
    └── integration/        # root, #[ignore]
```

---

## 11. Phased implementation (revised)

### Phase 0 — Characterization tests + refactor

**Do not move code until tests exist.**

| Task | Acceptance |
|------|------------|
| `tests/characterization/` pins classify + pipeline | Pass before and after extract |
| Extract `pipeline/`, `telemetry/proc.rs` | Behavior unchanged |
| `handle_process_event()` single entry | No duplicated logic |

**Timeline:** 1–2 weekends.

### Phase 1 — BPF smoke test (`sched_process_exec`)

| Task | Acceptance |
|------|------------|
| `sched_process_exec` → ringbuf | `sensor_test` prints successful execs |
| Failed exec silent | `ls /nonexistent` does not emit |

**Timeline:** 2 weekends (verifier + CO-RE).

### Phase 2 — Wire daemon + immediate snapshot

| Task | Acceptance |
|------|------------|
| Coordinator + bounded AI queue | Stats logged |
| `snapshot_behavior` on eBPF path | Short-lived `/tmp` test works |
| `JETT_TELEMETRY=ebpf\|both` | Learn mode E2E |

### Phase 3 — Kernel prefilter + openat

Prefix filter in kernel; sensitive openat only; per-PID trail in userspace.

### Phase 4 — Inode quarantine map + optional LSM

### Phase 5 — Ship (PKGBUILD deps, docs, delete stale `feature/ebpf-realtime`)

---

## 12. Configuration reference

```bash
JETT_TELEMETRY=both           # ebpf | proc | both
JETT_MODEL=/opt/jett/models/jeTT-q4.gguf
JETT_MODE=learn               # learn | enforce
JETT_EBPF_RINGBUF_MB=4
JETT_DEDUP_MS=2000
JETT_BEHAVIOR_FOLLOWUP_MS=200
JETT_BEHAVIOR_WINDOW_MS=1500
JETT_AI_QUEUE_SIZE=64
JETT_AI_QUEUE_POLICY=drop_new
JETT_QUARANTINE_TTL_SEC=300
```

---

## 13. Failure modes

| Failure | Behavior |
|---------|----------|
| BPF load fails | `both` → proc fallback |
| Ringbuf full | Increment `ringbuf_drop` |
| AI queue full | `drop_new`; increment `ai_dropped` |
| Process dead before snapshot | Kernel path + `exited_before_snapshot` |
| LSM unavailable | Userspace kill + inode map only |

---

## 14. What not to do

- Do not use `sys_enter_execve` for detection ringbuf.
- Do not call `engine_guard` from ringbuf callback thread.
- Do not use 1.5s `collect_behavior` as the only eBPF profile path.
- Do not ship PID-only quarantine map as sole enforcement identity.
- Do not refactor without characterization tests.

---

## 15. Load-bearing decisions checklist

- [x] Detection hook: `sched_process_exec`
- [x] Profiling: immediate `snapshot_behavior` on eBPF path
- [x] AI funnel: 99%+ dropped before queue
- [x] Quarantine: inode+dev at v1.5
- [x] Self-noise: `collect_behavior` is `/proc` direct (verified)
- [x] Phase 0: characterization tests before refactor

---

## 16. Branch strategy

```
main → refactor/telemetry-pipeline → feature/ebpf-sched-exec → feature/ebpf-openat → feature/ebpf-enforce-inode
```

Tag `v0.2.0-ebpf` when Phase 2 learn-mode E2E is stable.

---

## Revision history

| Version | Change |
|---------|--------|
| v1 | Initial plan (execve hook, 1.5s behavior for all, PID quarantine v2) |
| v2 | Corrected hooks, snapshot profiling, throughput math, inode v1.5, Phase 0 tests |
