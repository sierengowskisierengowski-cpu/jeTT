# jeTT eBPF Integration Plan — v2 (corrected)

> **What this is:** the original integration plan, reworked after a technical
> review. Every material change from the first draft is flagged with a
> **🔧 CORRECTION** callout that says *what* changed and *why*. Sections without
> a callout are kept from the original because they were already sound.
>
> **Six load-bearing fixes folded in:**
> 1. Telemetry hook switched `sys_enter_execve` → `sched_process_exec` (success-only, trustworthy).
> 2. Resolved the short-lived-process vs `collect_behavior()` (1.5 s) collision with an immediate /proc snapshot + honest low-confidence path.
> 3. Quantified the AI throughput ceiling (~4 verdicts/s) and made the pre-AI funnel a hard requirement with explicit backpressure.
> 4. Pulled inode+dev quarantine keying up from "v2" to **v1.5** (PID-only is racy for a security tool).
> 5. Added a self-noise audit so `collect_behavior` can't feed its own helper execs back into the sensor.
> 6. Added a characterization-test gate **before** the Phase 0 refactor.

---

## 1. Goals and non-goals

**Goals**
- Kernel-native telemetry for process execution (and later file access) with sub-millisecond delivery to userspace.
- One unified pipeline — eBPF and /proc both produce the same `ProcessEvent` → `classify_event` → `collect_behavior` → `engine::guard` → enforce/log.
- Self-contained in jeTT — BPF compiles via `build.rs`; daemon loads and owns its program (no separate `bpftool` systemd loader).
- Safe by default — learn mode unchanged; enforce is opt-in; graceful fallback if BPF can't load.
- Verifier-safe, CO-RE — works across kernel updates on Arch without recompiling against exact kernel headers.

**Non-goals (v1)**
- Replacing `collect_behavior()` with eBPF (behavior still needs /proc or more BPF hooks later).
- Bifrost / Unix socket integration (separate project).
- Full Tetragon-style observability (keep scope tight).
- Running inference inside BPF (impossible / wrong).

---

## 2. Current jeTT pipeline (what you're extending)

```
/proc poll (100ms) → ProcessEvent → classify_event
  → Trusted:    log
  → Suspicious: collect_behavior (~1.5s) → engine::guard → kill or learn-log
  → Unknown:    review log
```

eBPF changes the **left side only** — how `ProcessEvent` is born. Everything right of `classify_event` stays.

**Critical constraint:** `LlamaModel` / `LlamaContext` are **not** thread-safe. All `engine::guard()` calls must stay on one thread. Never call it from the ringbuf callback.

---

## 3. Design principles

| Principle | Why |
|---|---|
| BPF observes, userspace decides | AI + policy belong in Rust, not the kernel |
| Kernel filters noise | `openat`/`exec` without filtering will melt the ringbuf |
| Single event bus | Avoid duplicating classify/guard/enforce logic |
| Dedup before AI | exec + /proc may both see the same PID |
| Fail **open** on telemetry, fail **closed** on enforce | If BPF dies, fall back to /proc; if AI errors, don't kill unless explicit policy |
| **Identity > PID** | inode/dev keying from v1.5 — PID quarantine alone is racy |
| Ship in phases | Each phase has tests + acceptance criteria before the next |

> **🔧 CORRECTION (row 6):** original said "PID quarantine is v1; inode/hash/cgroup is v2." For a *security* tool that's too loose — see §10. Identity keying moves up to **v1.5**.

---

## 4. Target architecture

```
 Telemetry sources                Event coordinator         Inference (1 thread)      Enforcement
┌────────────────────┐          ┌───────────────────┐     ┌──────────────────┐     ┌──────────────┐
│ eBPF sensor        │  ringbuf │ dedup + ratelimit │ ch  │ classify_event   │     │ kill -9      │
│ sched_process_exec │ ───────> │ early /proc snap  │ ──> │ collect_behavior │ ──> │ (userspace)  │
│ (success only)     │          │ (bounded channel) │     │ engine::guard    │     │ quarantine   │
├────────────────────┤          │ backpressure=drop │     │                  │     │ map (BPF)    │
│ /proc scanner      │  fallback│ + stats           │     │                  │     │ LSM bprm     │
│ (argv enrichment)  │ ───────> │                   │     │                  │     │ (optional)   │
└────────────────────┘          └───────────────────┘     └──────────────────┘     └──────────────┘
```

> **🔧 CORRECTION:** the sensor box now reads **`sched_process_exec`** (not `sys_enter_execve`), and the coordinator does an **early /proc snapshot** the instant the event arrives, before the process can die. Both explained below.

---

## 5. Repo structure (final shape)

```
jeTT/
├── bpf/
│   ├── vmlinux.h              # generated at build, gitignored
│   ├── jett_sensor.bpf.c      # kernel programs
│   └── README.md              # hook docs, map layout
├── build.rs                   # libbpf-cargo + vmlinux.h generation
├── Cargo.toml
├── src/
│   ├── lib.rs                 # pub mod engine; pub mod ebpf; pub mod telemetry;
│   ├── engine.rs              # unchanged API
│   ├── telemetry/
│   │   ├── mod.rs
│   │   ├── event.rs           # ProcessEvent, KernelEvent, EventSource, Confidence
│   │   ├── coordinator.rs     # dedup, early-snapshot, channel, metrics, backpressure
│   │   └── proc.rs            # extracted from daemon.rs
│   ├── ebpf/
│   │   ├── mod.rs             # Sensor::open, poll, enforce_map_update
│   │   └── metrics.rs
│   ├── pipeline/
│   │   ├── mod.rs
│   │   ├── classify.rs        # moved TRUSTED_*, is_suspicious, etc.
│   │   ├── behavior.rs        # collect_behavior + helpers (no subprocess spawning!)
│   │   ├── enforce.rs         # quarantine_process, bpf map write (inode+dev keyed)
│   │   └── handle.rs          # single handle_process_event(event, engine, mode)
│   └── bin/
│       ├── daemon.rs          # thin: boot, spawn sources, run worker
│       └── jett-sensor.rs     # optional: BPF-only smoke test binary
├── tests/
│   ├── characterization.rs    # NEW: pins CURRENT behavior before refactor
│   ├── pipeline_unit.rs
│   └── integration/           # needs root + CAP_BPF
├── packaging/
│   └── jett-daemon.service    # + CapabilityBoundingSet notes
└── docs/
    └── EBPF.md                # operator guide
```

**Refactor first, BPF second.** Extract /proc + pipeline into modules before touching the kernel. That keeps diffs reviewable.

> **🔧 CORRECTION:** added `tests/characterization.rs` (see §11, new Phase 0a) and a note on `behavior.rs` (no subprocess spawning — see §13, fix #5).

---

## 6. Event schema (contract between kernel and Rust)

> **🔧 CORRECTION:** schema reworked for `sched_process_exec`. That tracepoint fires **after a successful exec**, so you never log failed attempts. The trade-off: the tracepoint's own `filename` field is the raw path handed to `execve` and **may be relative**. To get the absolute, resolved binary path, read it from the new task's `exe_file` via `bpf_d_path()`. Added a `confidence` field so the model is told when it's judging on path+comm only (short-lived process) vs. a full behavioral snapshot.

**Kernel struct (`bpf/jett_sensor.bpf.c`)**
```c
// Fixed layout — bump JETT_EVENT_VERSION on any change
#define JETT_EVENT_VERSION 2
#define JETT_EVT_EXEC      1
#define JETT_EVT_OPENAT    2   // phase 3 only

struct jett_event {
    __u32 version;
    __u32 pid;             // new pid from tracepoint
    __u32 tgid;
    __u32 uid;
    __u32 event_type;
    __u64 ts_ns;           // bpf_ktime_get_ns()
    char  comm[16];        // bpf_get_current_comm()
    char  path[256];       // absolute path via bpf_d_path(exe_file), see note
};
```

**Rust mirror (`src/telemetry/event.rs`)**
```rust
#[repr(C)]
pub struct KernelEvent { /* fields match exactly */ }

pub enum EventSource { Ebpf, Proc }

pub enum Confidence {
    Full,        // behavioral snapshot collected (process was alive)
    PathOnly,    // process already dead — judge on path + comm only
}

pub struct ProcessEvent {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,     // enriched from /proc when alive, else empty
    pub exe_path: String,
    pub uid: u32,
    pub timestamp: u64,
    pub source: EventSource,
    pub confidence: Confidence,
}
```

**Conversion / path notes**
- `sched_process_exec` gives `comm`, `pid`, `old_pid`. Pull the **absolute** binary path with `bpf_d_path()` on `task->mm->exe_file->f_path` (read via `bpf_get_current_task_btf()`), not the relative `filename` field.
- argv is still not available kernel-side. Enrich `cmdline` from `/proc/<pid>/cmdline` in the **early snapshot** (§9 Step B′) if the process is still alive; otherwise leave it empty and set `confidence = PathOnly`.

---

## 7. BPF program design

**Maps**

| Map | Type | Purpose |
|---|---|---|
| `events` | RINGBUF | 2–4 MiB — telemetry to userspace |
| `quarantine` | HASH `(dev,ino)→u8` | flagged binary identity (v1.5) |
| `quarantine_pid` | HASH `u32→u8` | short-TTL PID mirror for the kill path only |
| `stats` | ARRAY | drops, submissions (debug) |
| `trusted_tgid` | HASH | skip jeTT/ollama/bifrost self-noise |

> **🔧 CORRECTION:** `quarantine` is now keyed on `(dev, ino)` (binary identity), with a separate short-TTL `quarantine_pid` used *only* to drive the kill syscall. See §10.

**Hooks — phased**

| Phase | Hook | Purpose |
|---|---|---|
| 1 | `tp/sched/sched_process_exec` | **Primary, success-only process-creation signal** |
| 2 | same + kernel prefix filter | Drop `/usr/`, `/opt/jett/` before ringbuf |
| 3 | `tp/syscalls/sys_enter_openat` | Sensitive paths only (prefix cascade) |
| 4 | `lsm/bprm_check_security` | Block exec if quarantined — only if `CONFIG_BPF_LSM` |

> **🔧 CORRECTION (Phase 1 hook):** was `tp/syscalls/sys_enter_execve`. That fires on the *attempt* — including execs that fail with ENOENT/EACCES — and the task is still running the old program's image. `sched_process_exec` fires after the exec commits, so every event is a real, successful process launch. Reserve `sys_enter_execve` for the Phase-4 LSM path, where intercepting *before* commit is the whole point. If you later confirm BPF-LSM is available, `bprm_check_security` can unify telemetry **and** enforcement in one hook (it hands you `bprm->file` directly) — but don't make core detection depend on LSM.

**Verifier-safe rules**
- Use `bpf_d_path()` for the exe path (allowed in tracing progs with the right helper set); fall back to `bpf_probe_read_kernel_str` on the dentry name if `bpf_d_path` is unavailable on your kernel.
- `bpf_ringbuf_reserve` → fill → `submit`, or `discard` on partial-read failure.
- No loops over unbounded data; path capped at 256 (see truncation note below).
- GPL license section (required for tracepoints/LSM).

> **Path truncation note:** 256 bytes is pragmatic but `PATH_MAX` is 4096. A binary buried at a very deep path will truncate silently. Acceptable for v1; if you ever see truncated paths in logs, bump to 512 and re-measure ringbuf pressure.

**Kernel-side prefilter (phase 2)** — before `ringbuf_submit`, drop if path starts with:
- `/usr/`
- `/opt/jett/`
- `/home/cosmic/.cargo/` (dev paths — make configurable later via a map)

This cuts ringbuf pressure before userspace heuristics. **Note:** `/tmp`, `/var/tmp`, `/dev/shm`, `~/.cache`, `~/Downloads` are deliberately **not** dropped — those are your hunting grounds.

---

## 8. Rust / build integration

**Dependencies**
```toml
[dependencies]
libbpf-rs = "0.24"
crossbeam-channel = "0.5"
# existing: llama-cpp-2, sha2

[build-dependencies]
libbpf-cargo = "0.24"
```

**`build.rs` responsibilities**
1. Generate `bpf/vmlinux.h` from `/sys/kernel/btf/vmlinux` (or via libbpf-cargo's helper).
2. Compile `bpf/jett_sensor.bpf.c` → skeleton `jett.skel.rs` in `OUT_DIR`.
3. `rerun-if-changed` on `.bpf.c`.

> **Build-host note:** generating `vmlinux.h` requires the **build machine** to have BTF (`CONFIG_DEBUG_INFO_BTF=y`). Modern Arch ships this, so you're fine — but if you ever build the package on a stripped host, vendor a pre-generated `vmlinux.h` for your target kernel as a fallback.

**Sensor API (`src/ebpf/mod.rs`)**
```rust
pub struct Sensor {
    skel: JettSensorSkel<'static>,
    ringbuf: RingBuffer<'static>,
}
impl Sensor {
    pub fn open() -> Result<Self>;                         // load + attach
    pub fn poll_once(&mut self, timeout: Duration) -> Result<()>;
    pub fn quarantine(&mut self, dev: u64, ino: u64) -> Result<()>;  // identity-keyed
    pub fn stats(&self) -> SensorStats;
}
```

Ringbuf callback parses `KernelEvent`, converts to `ProcessEvent`, sends on the channel — **never calls AI from the callback.**

---

## 9. Daemon refactor (before BPF lands)

**Step A — Extract modules (no BPF yet).** Move from `daemon.rs` into:
- `telemetry/proc.rs` — `scan_new_processes`, `read_proc_info`
- `pipeline/classify.rs` — `TRUSTED_*`, `classify_event`, `is_suspicious`
- `pipeline/behavior.rs` — `collect_behavior` and helpers
- `pipeline/enforce.rs` — `quarantine_process`, `log_verdict`
- `pipeline/handle.rs` — single `handle_process_event(event, engine, mode)`

`daemon.rs` becomes ~150 lines: banner, load model, spawn threads, recv loop.

**Step B — Event coordinator**
```rust
struct EventCoordinator {
    seen: HashMap<(u32, u32), Instant>,  // (pid, event_type) → last seen
    dedup_window: Duration,              // e.g. 2s
    tx: Sender<ProcessEvent>,
    dropped: AtomicU64,                  // backpressure counter
}
```
Drop duplicate `(pid, exec)` from BPF + /proc within the window.

**Step B′ — Early /proc snapshot** *(new)*

> **🔧 CORRECTION (fixes the short-lived collision):** the original waited ~1.5 s for `collect_behavior` before profiling — but eBPF's whole value is catching processes that die in milliseconds. By the time `collect_behavior` runs, the short-lived dropper is **gone**, and you'd fall back to path+comm-only — the exact weak signal that caused earlier hallucinations.
>
> Fix: the instant an exec event arrives, take a **cheap immediate snapshot** of `/proc/<pid>/{fd,maps,status,cmdline}` *before* queueing for AI. Two outcomes:
> - **Process still alive:** you captured real fds/connections at birth → `confidence = Full`. The later `collect_behavior` can still enrich if it survives.
> - **Process already dead** (`/proc/<pid>` gone): `confidence = PathOnly`. Queue it, but tell the model explicitly it's judging on path + comm with no behavior — *don't* let it invent behavior it never saw. Log these distinctly so you can measure how often it happens.
>
> Phase 3's in-kernel `openat` hook later closes most of this gap by capturing file-access behavior while the process is still alive in-kernel.

**Step C — Config surface (`/etc/default/jett`)**
```
JETT_TELEMETRY=both      # ebpf | proc | both
JETT_MODEL=/opt/jett/models/jeTT-q4.gguf
JETT_MODE=learn          # learn | enforce
JETT_EBPF_RINGBUF_MB=4
JETT_DEDUP_MS=2000
JETT_BEHAVIOR_MS=1500    # collect_behavior window
JETT_AI_QUEUE_MAX=64     # bounded channel depth; over this → drop+count
```

Startup logic: try `Sensor::open()` if `ebpf`/`both`; on failure → log warning, force `proc` if `both`, exit if `ebpf`-only and the user insisted.

---

## 10. Enforcement model (thought through)

> **🔧 CORRECTION:** identity keying moved from "v2" up to **v1.5**. Bare-PID quarantine is genuinely racy for a security tool: a fast dropper forks children with new PIDs before your map write lands, and "clear the PID entry after 60 s" means a *legit* process that recycles that PID inside the window gets wrongly blocked. Keying on `(dev, ino)` of the binary fixes both — the malware's identity doesn't change when it forks, and you're not blocking innocent PID-reuse.

**v1 — Userspace (what you have)**
- `kill -9` + copy binary to `/var/jett/quarantine`. Works today; keep as the primary enforce path.

**v1.5 — BPF quarantine map (identity-keyed)**
- On QUARANTINE + enforce: `stat` the exe → write `(dev, ino) → 1` to the `quarantine` map.
- Also write the current `pid → 1` into the short-TTL `quarantine_pid` map purely to drive the immediate kill; expire it fast (a few seconds), since its only job is "kill this specific running PID now."
- Identity map (`dev,ino`) has no PID-reuse problem, so it can persist until you explicitly clear it.
- Map size: 4096 entries.

**v2 — broader identity**
- Add `cgroup id` keying if you ever target container workloads.

**LSM (optional, phase 4)**
- `bprm_check_security`: if the binary's `(dev, ino)` is in `quarantine`, return `-EPERM`.
- Probe at startup: if attach fails (no `CONFIG_BPF_LSM` / bpf not in the active LSM list), log once and continue userspace-only.
- Never block jeTT/ollama/bifrost — seed `trusted_tgid` at daemon start.

> **Verify before betting Phase 4 on it:** check `CONFIG_BPF_LSM=y` and that `bpf` is in your kernel's active LSM list. Quick check:
> ```bash
> zgrep BPF_LSM /proc/config.gz 2>/dev/null || grep BPF_LSM /boot/config-$(uname -r)
> cat /sys/kernel/security/lsm   # is "bpf" in the comma list?
> ```

**Enforce gating (unchanged philosophy)**
```
heuristic suspicious → behavioral profile → AI says QUARANTINE → enforce (if JETT_MODE=enforce)
```
eBPF does **not** shortcut to kill on heuristics alone.

---

## 11. Phased implementation

> **🔧 CORRECTION:** added **Phase 0a (characterization tests)** before the refactor. A pure refactor whose acceptance criterion is "behavior identical" is a *hope* unless you've pinned the current behavior in tests first. Lock down what the daemon does today, then refactor against that net.

### Phase 0a — Characterization tests *(new, ~2–3 days)*
**Deliverable:** the current daemon's decisions are pinned in code.

| Task | Acceptance |
|---|---|
| Feed known events → assert current verdicts | Tests capture today's classify/guard/enforce outputs |
| Snapshot trusted-path + suspicious-path cases | `cargo test` green on current `main` |

### Phase 0 — Refactor (~1 week, realistically 1–2)
**Deliverable:** same behavior, cleaner modules.

| Task | Acceptance |
|---|---|
| Extract `pipeline/`, `telemetry/proc.rs` | Characterization tests still pass — behavior identical |
| `handle_process_event()` single entry | No duplicated classify/guard blocks |
| Audit `collect_behavior` for subprocess spawning (fix #5) | Confirmed it reads /proc directly; any helper execs removed or marked |
| Add `JETT_TELEMETRY=proc` (default) | Config parsed, logged at startup |

### Phase 1 — BPF smoke test (~1 week, realistically 2)
**Deliverable:** kernel events visible, no AI.

| Task | Acceptance |
|---|---|
| `bpf/jett_sensor.bpf.c` — `sched_process_exec` only | `cargo build` succeeds |
| `jett-sensor` binary / `--sensor-test` flag | Running as root prints **absolute** exec paths |
| Ringbuf stats: received / dropped | Logged every 60s |

Test: `cp /bin/ls /tmp/t && /tmp/t` appears in output with absolute path `/tmp/t`.

### Phase 2 — Wire into daemon (~1 week)
**Deliverable:** eBPF triggers full pipeline.

| Task | Acceptance |
|---|---|
| Coordinator + dedup + early snapshot | Same PID doesn't double-trigger AI; live procs get `Full` confidence |
| `JETT_TELEMETRY=ebpf` | Suspicious exec hits `engine::guard` |
| `both` mode | BPF primary, /proc fallback |
| Backpressure | Channel over `JETT_AI_QUEUE_MAX` → drop + increment counter, never block reader |
| Metrics in log | `ebpf_events`, `proc_events`, `dedup_dropped`, `ai_escalations`, `queue_dropped`, `path_only` |

Test: learn mode — `/tmp` binary gets AI verdict in `/var/log/jett/jett.log`, tagged `Full` or `PathOnly`.

### Phase 3 — Kernel prefilter + openat (~2 weeks)
**Deliverable:** sustainable event rate.

| Task | Acceptance |
|---|---|
| Prefix filter in BPF | `/usr/bin/bash` not submitted to ringbuf |
| `openat` on sensitive prefixes only | `/etc/shadow`, `~/.ssh/` events appear |
| Load test | Desktop idle < 100 evt/min; **`cargo build` all day stays under queue cap with zero `queue_dropped`** |

### Phase 4 — Enforcement map + optional LSM (~1–2 weeks)
**Deliverable:** kernel-assisted block.

| Task | Acceptance |
|---|---|
| `quarantine(dev,ino)` on enforce | Identity map entry written; PID mirror drives kill |
| TTL cleanup thread | Stale `quarantine_pid` entries removed; identity entries persist |
| LSM attach if available | Re-exec of quarantined binary blocked |
| Self-protection | jeTT/ollama/bifrost TGIDs in `trusted_tgid` |

Test: enforce mode — quarantined malware can't re-exec (if LSM on), even after forking to a new PID.

### Phase 5 — Hardening + ship (~1 week)
| Task | Acceptance |
|---|---|
| `docs/EBPF.md` | Operator prerequisites documented |
| PKGBUILD + makedepends | `clang`, `bpftool`, `libbpf` |
| systemd capabilities | Document root vs `CAP_BPF`/`CAP_PERFMON` |
| Integration tests (root) | CI-skippable `#[ignore]` tests |
| Delete stale `feature/ebpf-realtime` | Branch replaced by real work |

> **Timeline reality check:** the per-phase "1 week" figures assume uninterrupted time. First-time eBPF verifier debugging can eat a whole weekend by itself. Expect Phases 0–2 to run closer to **6–8 weeks of nights** combined. That's normal; don't read slowness as failure.

---

## 12. Testing strategy

**Unit tests (no root)**
- `KernelEvent` ↔ `ProcessEvent` roundtrip
- Dedup logic
- `classify_event` cases (extend the characterization set)
- `validate_guard_output`
- **Confidence tagging:** dead-process path yields `PathOnly`, live yields `Full`

**Integration tests (root, `#[ignore]`)**
```bash
sudo cargo test --release -- --ignored test_ebpf_exec_delivery
sudo cargo test --release -- --ignored test_enforce_quarantine_map
```

**Manual playbook**
1. Learn mode + `JETT_TELEMETRY=ebpf` — verify logs.
2. Run a normal dev day (full `cargo build`) — no runaway CPU/VRAM, `queue_dropped=0`.
3. Enforce off — confirm no kills.
4. Enforce on in a VM — `/tmp` dropper killed; verify a forked child (new PID) is still blocked via identity map.
5. Stop daemon — BPF detaches cleanly (no orphaned progs: `sudo bpftool prog show`).

**Observability** — log line every 60s:
```
[stats] ebpf=1247 proc=89 dedup=312 ai=41 path_only=7 queue_drop=0 quarantine=2 ringbuf_drop=0
```

---

## 13. Failure modes and mitigations

| Failure | Behavior |
|---|---|
| No `CAP_BPF` / not root | Fall back to /proc; warn |
| Verifier reject on kernel update | CO-RE + CI on latest Arch kernel |
| Ringbuf full | Increment `ringbuf_drop`; don't crash |
| **AI queue saturated** | **Bounded channel; over `JETT_AI_QUEUE_MAX` → drop + count `queue_drop`, never block the ringbuf reader (blocking it → ringbuf fills → kernel drops, which is worse)** |
| **AI throughput ceiling** | **~4 verdicts/s on one thread @ ~225ms. `classify_event` MUST eliminate 99%+ (hash allowlist, trusted parent, known path) before the AI ever sees an event. This is a hard requirement, not a nicety — see fix #3.** |
| PID reuse | Identity-keyed quarantine (`dev,ino`); PID mirror is short-TTL kill-only |
| Short-lived process dies before `collect_behavior` | Early /proc snapshot on event; if already dead → `PathOnly`, model told not to invent behavior |
| **`collect_behavior` self-noise** | **Audit it: it must read /proc via syscalls, not spawn `ss`/`lsof`/`cat` subprocesses — those execs would hit your own sensor and loop. Seed `trusted_tgid` with the daemon TGID regardless.** |
| LSM unavailable | Skip; userspace kill only |

> **🔧 CORRECTION:** rows for AI queue saturation, the throughput ceiling, and `collect_behavior` self-noise are new (fixes #3 and #5). The PID-reuse and short-lived rows were rewritten to match the identity-keying and early-snapshot decisions.

---

## 14. What NOT to do

- Don't use the Kage-Ryu bash generator — integrate into the crate properly.
- Don't call `engine::guard` from the ringbuf callback thread.
- Don't ship `openat` without kernel filtering.
- Don't use `bpftool loadall` in systemd without a userspace reader.
- Don't block finishing jeTT core on LSM — it's Phase 4 optional.
- **Don't hook `sys_enter_execve` for detection** — it logs failed attempts and fires pre-commit. Use `sched_process_exec`.
- **Don't quarantine on bare PID** — key on `(dev, ino)`.
- **Don't refactor `daemon.rs` without characterization tests pinning current behavior first.**
- **Don't let `classify_event` pass more than a trickle to the AI** — the one inference thread is a ~4/s funnel; everything upstream of it must be cheap and ruthless.

---

## 15. Suggested order of work (while you finish jeTT)

1. **Finish current daemon/engine work on `main`** (behavioral analysis, guard tuning — you're nearly there).
2. **Decide the two architecture questions on paper first:** confirm `sched_process_exec` path-reading on your kernel, and the early-snapshot approach for short-lived processes. These shape the schema.
3. **Phase 0a** — characterization tests. Cheap, and it makes the refactor safe.
4. **Phase 0** — module extraction + `collect_behavior` self-noise audit.
5. **Phase 1** — BPF smoke test (kernel → Rust bytes).
6. **Phase 2** — real EDR path in learn mode.
7. **Phases 3–5** — once core AI quality is where you want it.

eBPF makes you **faster and more reliable at detection; it does not fix model quality.** Get guard verdicts solid in learn mode first.

---

## 16. Branch and release strategy

```bash
git checkout main
git checkout -b test/characterization            # Phase 0a — merge to main
git checkout -b refactor/telemetry-pipeline       # Phase 0 — merge to main
git checkout -b feature/ebpf-exec                  # Phases 1–2 — merge when learn-mode e2e works
git checkout -b feature/ebpf-enforce               # Phases 3–4
```

Tag `v0.2.0-ebpf` when Phase 2 is stable in learn mode. Tag `v0.3.0-enforce` when the identity map + enforce are hardened.

---

## Bottom line

The original plan was 85% right and the shape is correct. The six corrections that take it to flawless:

1. **`sched_process_exec`, not `sys_enter_execve`** — trustworthy, success-only telemetry.
2. **Early /proc snapshot** — resolves eBPF's short-lived advantage colliding with the 1.5 s behavioral window; honest `PathOnly` confidence when the process is already gone.
3. **AI is a ~4/s funnel** — `classify_event` must drop 99%+ before the queue; explicit drop-and-count backpressure so a `cargo build` can't melt it.
4. **Identity (`dev,ino`) quarantine at v1.5** — bare PID is racy for a security tool.
5. **Self-noise audit** — `collect_behavior` must not exec helpers into its own sensor.
6. **Characterization tests before the refactor** — "behavior identical" becomes a check, not a hope.

The two that actually shape the architecture are **#1 (hook)** and **#2 (early snapshot)** — settle those on paper before you write a line of Phase 0.
