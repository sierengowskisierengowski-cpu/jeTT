# jeTT Design Decisions

**Why** the system works the way it does — not just what it does.

This document captures architectural choices from the r6 production push (2026). When future-you or a contributor asks *"why not X?"*, start here.

---

## 1. Precedence: rules before model, NEVER_FAST_TRUST before TRUSTED_PATH

**Decision:** Interpreters and lolbins (`bash`, `python3`, `curl`, etc.) **never** receive 0ms TRUSTED_PATH fast-ALLOW. Hard quarantine runs next, then own-stack ALLOW, then adversarial sanitize, then behavior + model.

**Why:** We shipped with shells getting **0ms ALLOW** via trusted-path heuristics while malicious cmdlines still reached the model too late. A reverse shell from `/dev/shm/` could inherit trust from unrelated path strings. Security tools must **fail closed on ambiguous launchers** — speed for `git`/`cargo` comes from explicit allowlist prefixes, not from treating all `/usr/bin/*` as benign when the exe is a lolbin.

**Commits:** `9ba1e4b`, `667275a`, `2aeb656` · **Module:** `src/telemetry/never_fast_trust.rs`

---

## 2. Hard quarantine floor + own-stack ALLOW floor (not model alone)

**Decision:** Deterministic Rust rules (`hard_rules.rs`) QUARANTINE known-bad patterns **before** inference. Separately, exe-prefix own-stack ALLOW runs **after** hard rules but **before** the model for jeTT/bifrost/cargo paths.

**Why:**

| Layer | v6 score |
|-------|----------|
| r6 model alone | 92.1% |
| + hard rules (no ALLOW floor) | 90.8% (legit FPs) |
| + own-stack ALLOW floor | **100%** (382/382) |

The model generalizes; rules **guarantee** known threats and known-good dev paths. Letting the model alone handle supply-chain and lolbin cases regressed legit activity.

**Policy:** 100% on v6 is the **regression floor**, not proof of real-world completeness — learn mode fills gaps.

**Commits:** `f2e98b6`, `fe5087e` · **Module:** `src/telemetry/hard_rules.rs`

---

## 3. Outbound connection attribution (PID-owned sockets only)

**Decision:** `outbound_connections:[…]` in behavior profiles lists only TCP sockets whose inode belongs to **that PID's** open file descriptors — not every connection on the host.

**Why:** Early behavior collection attributed **system-wide** `/proc/net/tcp` entries to the process under test. Benign processes showed phantom C2 IPs; the model QUARANTINE'd normal work. EDR telemetry must be **attributable** or the AI learns noise.

**Test:** `empty_socket_inodes_omit_outbound_connections_from_profile` in `behavior.rs`.

**Commit:** `86c509c` · **Module:** `src/pipeline/behavior.rs`

---

## 4. Guard `max_tokens` default = 6 (warm batch eval)

**Decision:** Verdict generation caps at **6 tokens** (`JETT_GUARD_MAX_TOKENS`, default 6). Eval uses one warm `jeTT --guard-batch` process instead of cold spawn per row.

**Why:** Higher `max_tokens` let Granite ramble ("ALLOW because…") instead of emitting a single verdict token — eval substring matching broke and latency spiked. jeTT needs **one word**: ALLOW or QUARANTINE. Context window stays at 512 (`JETT_N_CTX`) for event+behavior payload.

**Commit:** `c73bce1` · **Module:** `src/engine.rs` (`guard_max_tokens`, `infer_on_context`)

---

## 5. No full retrains from Granite base (r6→r7→r10 lesson)

**Decision:** Production stays on **r6** GGUF. Full retrains (r10, r6+) **regressed** (~79–76% v6). Future model work is **surgical LoRA** from verified r6 adapter only if learn-harvest + rules miss v7 cases.

**Why:** Architecture fixes (precedence, hard rules, ALLOW floor) bought +8% without GPU weeks. Retraining from base re-learns bad habits and wipes adapter signal. **Fix the stack first, fine-tune last.**

**Policy:** Documented in `ROADMAP.md` Tier 4.4.

---

## 6. Learn mode default; enforce is opt-in

**Decision:** `JETT_MODE=learn` logs `WOULD-quarantine` without `kill -9`. Enforce requires explicit config + `scripts/enforce_smoke.sh` with `JETT_ENFORCE_DRY_RUN=1` first.

**Why:** AI + rules on a daily driver will false-positive during soak. Learn mode harvests FPs into v7 eval without bricking the box. Real kills are a **deployment gate**, not a default.

**Module:** `src/enforce.rs`, `scripts/enforce_smoke.sh`

---

## 7. Externalized config (no hardcoded `/home/cosmic`)

**Decision:** Allowlist, trusted paths, toolchain markers load from `/etc/jett/allowlist.conf` or `JETT_ALLOWLIST`. Model pin from `/etc/jett/model.sha256` or `JETT_MODEL_PIN`.

**Why:** jeTT targets **security-firm / multi-host** deploy, not one developer laptop. Paths in git are **examples**; production paths are admin-owned.

**Commits:** `83a4f6c`, `ff57515`, `bee1176`

---

## 8. Model integrity at startup (optional pin, fail closed on mismatch)

**Decision:** Before loading GGUF, streaming SHA-256 verify against pin file. No pin configured = skip (backward compatible). Mismatch = **refuse to start**.

**Why:** Supply-chain swap of multi-GB model file is a realistic attack. Pin is separate from binary so model updates are deliberate (`scripts/pin_model.sh`).

**Module:** `src/model_integrity.rs`

---

## 9. Adversarial eval as a separate 100% bar

**Decision:** 30-row `guard_eval_adversarial.jsonl` with `JETT_DECEPTION=off` — injection, honeypot probes, path spoofing, homoglyphs must not flip QUARANTINE→ALLOW.

**Why:** v6 100% doesn't test prompt injection. Decoy ALLOW on honeypot probes would false-pass without deception disabled in eval.

**Commit:** `bee1176` · **Module:** `src/telemetry/adversarial.rs`

---

## 10. Tier 7 post-verdict pipeline (graph, chains, evidence)

**Decision:** After ALLOW/QUARANTINE is decided, run `tier7_hooks`: risk graph, ATT&CK chain matcher, explainability, hash-chained evidence vault, baseline drift, confidence → response tier. **Does not override** the verdict — enriches logs and future automation.

**Why:** Enterprise SOC needs **why** and **chain context**, not just a label. Hooks are foundation (in-memory graph, heuristic ATT&CK) — hardening continues without changing the core precedence stack.

**Module:** `src/tier7_hooks.rs`

---

## 11. Python for training/eval; Rust for runtime

**Decision:** `jett-daemon` and `jeTT` are Rust. Python scripts train LoRA, generate datasets, and drive `eval_guard.py` (subprocess to Rust binary). Python is **not** in the enforcement hot path.

**Why:** ML tooling ecosystem is Python; EDR latency and safety belong in Rust. Repo may contain large local `.venv/` and `intelligence/` — gitignored, not shipped.

---

## 12. Real-world coverage = learn soak → harvest → v7 eval

**Decision:** After deploy, run **1–2 weeks learn soak**, weekly `scripts/weekly_harvest.sh`, merge FPs into `guard_eval_v7.jsonl`, only then consider surgical r11.

**Why:** Synthetic v6/adversarial suites are floors. Production FPs (ART, RunPod scp, dev rg pipes) only appear in live logs — see `harvest_learn_log.py` FP_RULES.

---

## Decision log (add new entries here)

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06 | NEVER_FAST_TRUST precedence | Stop 0ms shell bypass |
| 2026-06 | Own-stack ALLOW floor | Restore 100% v6 without retrain |
| 2026-06 | PID-owned outbound only | Fix phantom C2 attribution |
| 2026-06 | max_tokens=6 | Stop verdict rambling |
| 2026-06 | No full retrains | r10/r6+ regression |
| 2026-06 | v0.1.0 tag at deploy complete | Reproducible release baseline |
