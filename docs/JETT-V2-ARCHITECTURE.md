# jeTT v2 — HA-jeTT Architecture Vision
## "Fast as lightning. Hard as thunder."

**Author:** Joseph Sierengowski
**Project:** jeTT — GowskiNet AI Security Brain
**Date:** June 2026
**Status:** Vision Document — Active Development

## The Problem With Traditional Security

Every existing EDR follows the same broken model:
- Rules catch only what humans already thought of
- AI bolted on as an afterthought
- The gate is never smart enough to be first line

## The Vision

One AI brain. Two engines. Every layer of the stack covered.
From the wire to the kernel to the process — nothing moves without jeTT knowing.
Fast as lightning on the obvious. Hard as thunder on the unknown.

## HA-jeTT Twin Engine Architecture

ENGINE 1 — FAST GATE
- Tiny distilled model trained on Engine 2 verdicts
- In-memory rules — never touches disk
- 10-50ms decision window
- Handles 90-95% of all events
- Outputs: ALLOW / KILL / ESCALATE

ENGINE 2 — DEEP ANALYSIS
- IBM Granite 3.3 2B full model
- 288ms deep contextual analysis
- Only sees what Engine 1 escalates (~5-10% of events)
- Outputs: ALLOW / QUARANTINE / CONTAIN / REVIEW

CONSENSUS LOGIC
- E1 ALLOW + E2 ALLOW = ALLOW
- E1 KILL + E2 any = KILL (E1 wins on speed)
- E1 ESCALATE + E2 QUARANTINE = QUARANTINE
- E1 and E2 DISAGREE = QUARANTINE until review
- DISAGREEMENT = ASSUME WORST. ALWAYS.

## Self-Improving Design

Engine 2 teaches Engine 1 automatically.
Learn mode verdicts become Engine 1 training data.
The system improves itself the longer it runs.

## Full Stack — Layer by Layer

Layer 0 — The Wire (SmartNIC)
Hardware: NVIDIA BlueField-3 or equivalent
Speed: Nanoseconds
- jeTT Engine 1 runs directly ON the network card
- Every packet intercepted before host CPU sees it
- Obvious threats dropped at wire speed
- Host machine never touched by obvious attacks

Layer 1 — Packet Processing (DPDK)
Technology: Data Plane Development Kit — Rust bindings
Speed: Nanoseconds — kernel bypassed entirely
- Packets go directly NIC to userspace
- Zero kernel network stack overhead
- Deep packet inspection at line speed

Layer 2 — Kernel Syscall Interception (eBPF)
Technology: eBPF LSM + network hooks
Speed: Microseconds
- Every exec syscall intercepted
- Every connect(), bind(), sendto() watched
- mmap(PROT_EXEC) monitored — catches fileless malware
- File writes monitored — catches persistence attempts
- Syscall sequence fingerprinting
- PID to process to network correlation in real time

Layer 3 — AI Decision Layer (HA-jeTT)
Technology: Pure Rust — llama-cpp-2 direct inference
Speed: 10-50ms Engine 1 / 288ms Engine 2

Layer 4 — Visibility (Bifrost)
Technology: Tauri v2 + React
Real time verdict stream, attack timeline, full telemetry dashboard

Layer 5 — Deception (PHANTOM AI Honeypot)
Technology: Pure Rust HTTP server
- Fake Ollama endpoint
- Fake OpenAI compatible endpoint
- Fake Anthropic endpoint
- Captures prompt injection, jailbreak, extraction attacks
- Feeds attacker TTPs directly into jeTT training data

## Attack Timeline

T+0ms      Packet arrives at NIC
T+0.001ms  SmartNIC Engine 1 — first inspection
T+0.5ms    DPDK deep packet analysis
T+1ms      eBPF intercepts exec syscall
T+2ms      Engine 1 fast gate decision
           OBVIOUS = DEAD. Done.
           UNCERTAIN = escalate to Engine 2
T+50ms     Engine 2 deep analysis begins
T+288ms    Engine 2 verdict fires
T+289ms    Attacker is dead and doesnt know why

## Speed Targets

Layer         | Technology  | Target  | Status
Wire          | SmartNIC    | <1ms    | Planned
Packet        | DPDK        | <1ms    | Planned
Kernel        | eBPF LSM    | <1ms    | In progress
Fast gate     | Engine 1    | 10-50ms | Planned
Deep analysis | Engine 2    | <288ms  | Current
Dashboard     | Bifrost     | Realtime| In progress

## Project Status

jeTT Engine 2 current     | LIVE — Learn mode
eBPF process sensor       | Production
Evidence vault            | Complete
Deception mode            | Complete
Bifrost integration       | In progress
eBPF network monitor      | Planned
Engine 1 distillation     | Planned
PHANTOM AI honeypot       | Planned
eBPF LSM hooks            | Planned
DPDK integration          | Future
SmartNIC deployment       | Future

## The Goal

Make attacking this system so expensive in time and effort
that no attacker — automated or human — finds it worth pursuing.

Not unbeatable. Unstoppable is a fantasy.
But make the cost of getting through so high
they move on to easier targets.

Fast as lightning. Hard as thunder.
See everything. Miss nothing. Strike without hesitation.

---
GowskiNet Security Research — Milford Michigan
Joseph Sierengowski — self taught, zero shortcuts
