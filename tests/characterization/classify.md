# Phase 0 — classification characterization

These behaviors are pinned by unit tests in `src/bin/daemon.rs` (`mod tests`).

Before extracting `classify_event` / `is_suspicious` into `src/pipeline/`, any refactor
must keep these outcomes:

| Case | Expected |
|------|----------|
| `python3` running `/tmp/dropper.py` | `Suspicious` (path beats interpreter name) |
| Binary under `/home/alice/...` | Not blanket trusted |
| `curl \| sh`, python socket exec, `nc -e` | Suspicious patterns match |

Run: `cargo test --bin jett-daemon`
