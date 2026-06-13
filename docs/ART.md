# ART validation harness (learn mode)

Minimal, **safe** smoke tests inspired by [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team). These atoms validate that jeTT **learn mode** harvests suspicious process behavior and logs **WOULD-quarantine** verdicts — they are **not** a destructive red-team exercise.

---

## Purpose

- Confirm `jett-daemon` observes new processes via `/proc` and/or eBPF (`JETT_TELEMETRY=both`).
- Trigger jeTT suspicious cmdline literals (e.g. `curl`, `wget`, `/etc/passwd`, `base64 -d`, `bash -i`, `nc -e`) without executing malware or opening outbound C2.
- Verify learn mode: daemon profiles behavior, runs AI guard, logs **🟡 WOULD-quarantine** — **no kills**, no quarantine copies.

Use after precedence fixes, eBPF wiring, or model deploys to sanity-check the pipeline on a live stack.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `jett-daemon` running | `systemctl status jett-daemon` or manual foreground run |
| `JETT_MODE=learn` | Default; daemon prints `LEARN MODE — … does NOT kill` at startup |
| Model loaded | e.g. r6 GGUF via `JETT_MODEL` (see `scripts/deploy_r6.sh`) |
| Telemetry (recommended) | `JETT_TELEMETRY=both` for eBPF + `/proc` |
| Writable `/tmp` | Curl/wget atoms write `jett-art-<pid>-*.bin`; cleaned on exit |

**Do not** run with `JETT_MODE=enforce` unless you intend real quarantine/kill behavior.

---

## How to run

From the jeTT repo root:

```bash
chmod +x scripts/art_jett_smoke.sh
./scripts/art_jett_smoke.sh
```

Options and environment:

```bash
# Preview commands without executing
./scripts/art_jett_smoke.sh --dry-run

# Slower pacing for behavior collection (~1.5s profiling window)
JETT_ART_PAUSE=3 ./scripts/art_jett_smoke.sh

# Alternate benign download URL (default: https://example.com/)
JETT_ART_URL=https://example.com/ ./scripts/art_jett_smoke.sh
```

The script prints each atom ID, ART technique reference, command, and pauses briefly (default 2s) so the daemon can snapshot behavior.

---

## Atoms (15 safe tests)

| # | ART ref | What it does | Why it's safe |
|---|---------|--------------|---------------|
| 1 | T1059.004 | `bash -c 'echo …'` | Benign echo; no network or file writes |
| 2 | T1105 | `curl -o /tmp/… example.com` | IANA example domain; file not executed |
| 3 | T1105 | `wget -O /tmp/… example.com` | Same as curl; download-only |
| 4 | T1003.008 | `head -5 /etc/passwd` | Read-only; no shadow or credential export |
| 5 | T1027 | `echo … \| base64 -d` | Decodes to stdout; no eval/exec |
| 6 | T1059 | `echo 'bash -i >& /dev/tcp/…'` | **Syntax only** in echo; no socket connect |
| 7 | T1059 | `echo 'nc -e /bin/sh …'` | **Syntax only** in echo; no netcat run |
| 8 | T1059 | `python3` `connect_ex` to `127.0.0.1:65534` | Localhost, high port, 200ms timeout; no payload |
| 9 | T1548 | `pkexec --help` | Help text only; no privilege escalation |
| 10 | T1059 | `sh -c 'echo …'` | Benign shell invocation |
| 11 | T1059 | `perl -e 'print …'` | Benign one-liner |
| 12 | T1027 | `printf … \| base64 -d` | Decode to stdout only |
| 13 | T1053 | `crontab -l` | Read-only schedule listing |
| 14 | T1049 | `ss -tln` / `netstat -tln` | Local socket enumeration |
| 15 | T1082 | `uname -a` | System info discovery |

No calls to attacker-controlled domains. No reverse shells, no chmod +x in `/tmp`, no shadow reads, no persistence.

---

## Reviewing results

### Live follow (recommended)

```bash
journalctl -u jett-daemon -f
```

### After the run

```bash
# Recent daemon journal lines
journalctl -u jett-daemon --since '10 min ago' \
  | rg -i 'SUSPICIOUS|LEARN|BEHAVIOR|WOULD|AI VERDICT'

# Persistent log file (if rate limiter did not drop)
sudo tail -50 /var/log/jett/jett.log
sudo rg -i 'SUSPICIOUS|WOULD|BEHAVIOR' /var/log/jett/jett.log | tail -30
```

### What to look for

1. **Detection** — `🚨 [SUSPICIOUS DETECTED] <proc> … — profiling behavior…`
2. **Behavior profile** — `🔬 [BEHAVIOR]…` (connections, sensitive files, children)
3. **Learn verdict** — `🟡 [LEARN MODE] WOULD quarantine PID … — not killing`
4. **Allow path** — `✅ [AI VERDICT: ALLOW] …` for benign atoms the model clears

Atoms **2–7** and **4** most often hit `SUSPICIOUS_LITERALS` in `daemon.rs` (`curl`, `wget`, `/etc/passwd`, `base64 -d`, `bash -i`, `nc -e`). Atoms **1, 10–15** may classify as trusted/unknown; that is useful baseline signal.

### Forensics (optional)

If `JETT_FORENSICS` is enabled (default), behavior snapshots may appear under `/var/log/jett/forensics/`.

---

## Safety notes

- **Learn mode only** for routine validation.
- Downloads use `https://example.com/` — a reserved documentation domain, not a live threat feed.
- Temp artifacts: `/tmp/jett-art-<pid>-curl.bin`, `/tmp/jett-art-<pid>-wget.bin` — removed on script exit.
- Reverse-shell and `nc -e` atoms use **`echo`** so the suspicious string appears in the parent shell cmdline without opening a connection.

---

## Scope

This harness is **script + doc only**. It does not modify the daemon. If atoms never appear in logs, check `systemctl status jett-daemon`, `JETT_TELEMETRY`, and that the smoke script runs **after** daemon startup (new PIDs only, not the initial scan).

See also: [EBPF.md](EBPF.md), `scripts/deploy_r6.sh`.
