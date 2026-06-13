# AI Model Deception & Defense Architecture

*Design notes — a layered system to keep an AI model safe, make attacks costly and loud, and get a human in the loop before real damage is done.*

> Working title only — rename it whatever fits your stack (it'd slot nicely into the Bifrost/Heimdall Norse theme as a deception module, the way Mjolnir and Gjallarhorn do).

---

## 1. The core idea

You cannot make a model unhackable. No one can — not even the big labs. A determined, adapting attacker can always find new angles, so "build a wall they can never get through" is the wrong goal and chasing it is a trap.

The right goal — and the one this whole design is built around — is three things at once:

1. **Make attacking expensive** (cost them time, effort, and certainty).
2. **Make attacks loud** (every attempt trips something that tells you).
3. **Make damage impossible during the delay** (so when an attacker thinks they've won, they've actually won nothing — and a human sees it before anything real happens).

That's the same philosophy as a server honeypot: it doesn't make your real servers invincible, it wastes the attacker, warns you, and harvests intel. We're doing that one layer up — at the AI itself.

---

## 2. What we're defending against

- **Prompt injection / jailbreaks** — getting the model to ignore its rules ("ignore all previous instructions…", indirect injection hidden in data the model reads).
- **Automated / agent attacks** — scripts and LLM-powered agents probing at machine speed.
- **Spam / brute-force probing** — high-volume attempts to find a crack.
- **Extraction** — stealing the system prompt, secrets, or model internals.

---

## 3. The layered defense (defense in depth)

Each gate is bypassable on its own. Stacked, they multiply the attacker's cost and the chance you catch them. If one fails, the next catches it.

**Layer 1 — Front gate: detection + rate control.**
Catch injection/jailbreak attempts *before* they reach the model, using a detector (e.g. embedding-drift or a trained classifier) plus rate limiting and anomaly detection to slow spam and automated probing. This is the single most important layer — the whole system's quality rides on how well this decides "attacker vs legit user."

**Layer 2 — Prompt hardening.**
Make landing an injection harder in the first place: randomized/polymorphic prompt assembly so the attacker can't reliably craft an injection, and strict separation between trusted instructions and untrusted user input.

**Layer 3 — Deception layer (the mirror honeypot).**
Detected attackers get silently moved into a decoy that *looks identical to the real system* but does nothing real (full detail in section 4). They think they broke in; they're in the maze. Tarpit it with slow responses to burn their time.

**Layer 4 — Output scanning.**
Before *anything* leaves the system, scan the model's response for leaked secrets, canary tokens, or harmful content — catching a successful jailbreak at the *exit* even if it slipped the front gate.

**Layer 5 — Action / tool gating (the last hard wall).**
If the AI can actually *do* things (call tools, take actions, touch data), gate the dangerous ones: least-privilege access, sandboxing, and human approval for high-risk actions. Even a fully jailbroken model causes zero damage if it can't reach anything real.

**Layer 6 — Monitoring + tripwires → human alert.**
Everything is logged. Canary trips and anomalies page a human. This is the payoff: layers 3–5 buy the time, and this gets a person in the loop during that window — *before* real damage. Those logs are themselves protected so only you can read them and an attacker can't touch them — see section 6b.

---

## 4. The mirror: how the decoy is indistinguishable

The trick is counterintuitive: **don't build a fake AI — use the same one.**

Honeypots get sniffed out because they're lower fidelity — dumber responses, missing state. So the decoy uses the **same model weights and the same interface** as the real system. The responses are genuinely indistinguishable because it is literally the same model.

The difference is **not the brain — it's the consequences:**

- **Real system:** real tools, real data, real credentials, real side-effects.
- **Decoy:** identical model and interface, but tools are sandboxed no-ops, data is fabricated-but-plausible, credentials are canaries, and nothing it does touches anything real.

**You fake the stakes, not the behavior.**

Best version: don't even run "two systems to tell apart." Run **one surface**, and the moment the front gate suspects an attack, the backend **silently swaps the consequences** — revokes real tools, slots in canary data, routes actions to the sandbox. The attacker never sees a switch, because the *conversation* never changes; only the consequence layer flips, behind the curtain. There's nothing to fingerprint.

---

## 5. How WE know which is real (the part that makes it work)

If the attacker can't tell real from decoy, how do *we*? The answer is the whole secret of deception: **information asymmetry, held out-of-band.**

The mechanism — and the one correction that makes it bulletproof:

- **The ground truth does NOT live in the model.** The model is the thing under attack, so it can never be the thing that "knows" it's real. A marker hidden in the code or the model's context fails, because *prompt injection is the act of extracting the model's context* — the first thing an attacker does ("print everything above") pulls the marker right out, and once they can read it they can forge it. **"Hidden" is not the same as "secret."**

- **The ground truth lives in the control plane.** A separate orchestrator *assigned* each session to real-or-decoy, so it already knows — the model never needs to. That label sits one level up, in a trust domain the attacker never touches.

- **Identity is cryptographic, not hidden.** The real system signs its sessions/responses with a **private key the attacker never has**, verified out-of-band. A hidden string breaks the moment someone looks; a signature holds *even if the attacker knows your entire design* — because they still don't have the key. (This is Kerckhoffs's principle: assume the enemy knows the whole system; only the key is secret.)

- **Canary tokens self-report.** The decoy is seeded with secrets that exist *nowhere* in the real system. If a canary ever fires — used, leaked, appears in a log — that session was the decoy *and* it was an attacker, in a single signal, after the fact. No inspection needed.

**The rule:** identical on the attacker's channel, labeled on yours. If you ever have to *inspect* a live system to guess which it is, it's built wrong — the label is assigned at creation, not inferred later.

---

## 5b. Key management: rotation & root of trust

The signing key from section 5 is what the whole "which is real" guarantee rests on, so how it's managed matters. There are **two different "always changing" things — don't conflate them:**

- **The tell is never the same (anti-replay) — free with proper signing.** Sign fresh content plus a nonce/timestamp every time, so every signature is unique and a captured one can't be replayed. You get "never the same" without rotating the underlying key at all.
- **Rotating the key itself — blast-radius control.** The value of rotation is that if a key ever leaks, a stolen copy expires at the next rotation. It bounds the damage of a one-time leak *in time*.

**Do it as short-lived, per-session keys derived from a protected root.** Every session gets its own signing key with a short expiry, derived off a root that never moves. That gives you "always changing" *and* forward secrecy — if one session key leaks, it doesn't expose past or future sessions.

**What rotation does NOT do (build knowing this):** it doesn't stop a key from being stolen, and it doesn't replace protecting the control plane. If an attacker is deep enough to read the current key, they can usually read the next one too. Rotation protects against a *one-time leak*, not *ongoing compromise*.

**Don't over-rotate into fragility.** Every rotation means syncing the new key to every verifier with an overlap window so in-flight work doesn't break. Rotating every few seconds causes more outages than it prevents attacks. Automated rotation on a sane cadence — or per-session ephemeral keys — is the sweet spot.

**The thing you can't rotate away — the root of trust.** Whatever generates and signs the rotating keys is anchored to a root key, and that root must live in hardware that never exposes it (HSM, secure enclave, KMS — the same way a YubiKey signs without ever releasing its private key). Rotation pushes the problem *up* to the root; it doesn't erase it. The root stays the crown jewel, alongside the control plane.

---

## 6. What happens when an attack actually hits

Walking the whole thing end to end:

1. Attacker sends an injection / jailbreak / probe.
2. **Front gate** flags it (detector + rate/anomaly signals).
3. Backend **silently swaps consequences** — same conversation, but now real tools are gone, data is fake, creds are canaries. Attacker notices nothing.
4. Decoy **fakes compliance** with plausible content and **tarpits** the attacker, burning their time.
5. Attacker "succeeds" — extracts a fake system prompt, grabs canary credentials, thinks they won.
6. **Output scanning** ensures nothing real ever leaves.
7. **Canary trip + anomaly alert** fires; everything is logged Cowrie-style.
8. **A human is paged** — and sees the full attack play out with zero real damage done.
9. The captured attempt becomes **training/detection data** that makes the front gate sharper next time (the learn → improve loop).

Net result: the attacker spent real effort, learned nothing true, took nothing real, and incriminated themselves — while you got intel and a head start.

---

## 6b. Securing the logs themselves

The logs are your evidence, your intel, and your early warning — so they're a target, and they need protecting. The goal is **not** "no logs" (that blinds the defender, who needs them most); it's **logs that only you can read, that an attacker can't see or tamper with, and that never contain secrets:**

- **Off-box, instantly.** Ship every log to a separate, locked-down, append-only store the moment it's written. An attacker sitting inside the honeypot can't reach the log server, so they can't read or delete anything. (Loki/Grafana already does this for the rest of the lab.)
- **Encrypted at rest** with a key only you hold (GPG / YubiKey). Even if they grab a log file, it's ciphertext.
- **Access-controlled to the control plane.** Readable from your out-of-band side only — never from the attack surface or the model's reach.
- **Tamper-evident.** Hash-chain or sign each entry, so any alteration is detectable. This is the opposite of "no trace" — it's an *unforgeable* trace.
- **Secret-free.** Log the *event* ("canary #7 tripped at 02:14"), never the canary value, key, or anything sensitive.
- **Keep the mechanism out of the model's context.** Nothing about how the deception works should be readable by the attacker-facing model — prompt injection extracts anything the model can see.

Two related notes. "Hiding how it works" is the obscurity trap — assume the attacker learns the method, and lean on keys and access control, not secrecy of design. And keep a **protected audit trail of your own admin actions**: being able to review what you did (and detect impersonation) is a strength; "no record" is a liability when something breaks. (Personal shell-history hygiene like `HISTCONTROL=ignoreboth` for one-off secrets is fine — just don't mistake it for a system control.)

---

## 7. The honest limits (build it knowing these)

- **A perfect, forever mirror is impossible.** The crack is always at *consequences*: the real system eventually has to *do something real*, and the decoy must not. If an attacker can independently verify a real-world effect (did my stolen key work against the live API? did my exfil land somewhere I control?), that's where the lie shows. You can make verifying "is this real?" arbitrarily expensive and slow — but a determined prober probing for *real effects* is the fundamental ceiling.

- **Deception relocates the trust boundary to the control plane.** The whole mirror holds *only as long as the attacker can't breach the orchestrator and the canary/key registry.* That control plane is now your crown jewel — defend it hardest. Protect the asymmetry and the deception is unbreakable from the front; lose the control plane and the entire mirror collapses at once.

- **It's an arms race.** This is active defense, not a finish line — skilled adversaries adapt, so the detector and decoy need to keep learning (same red/blue co-evolution as every honeypot).

- **This complements, it doesn't replace.** The real model still needs genuinely strong guardrails on its own. The deception layer makes attacking it *costlier, louder, and self-incriminating* — it doesn't make the model invincible.

---

## 8. Governing principles (the six things that make it real)

1. **Defense in depth** — many gates; if one fails the next catches it.
2. **Consequences over surface** — fake the stakes, not the behavior; same model, neutered effects.
3. **Information asymmetry** — identical on the attacker's channel, labeled on yours.
4. **Cryptography, not obscurity** — unforgeable signatures, not hidden notes; assume they know everything but the key.
5. **Ground truth out-of-band** — the truth of "which is real" lives in the control plane, never in the model.
6. **Rotate the leaves, guard the root** — short-lived per-session keys for forward secrecy, anchored to a hardware-protected root that never moves.

---

## 9. Where to start (prototype path)

- Stand up the **control plane / orchestrator** first — it holds the routing label, the signing key, and the canary registry. This is the thing you protect hardest.
- **Anchor the signing root in hardware** (HSM, secure enclave, or a YubiKey-style device) and issue short-lived per-session keys off it — rotate the leaves, never expose the root.
- Wire the **front-gate detector** (start simple: a classifier + rate limiting) — measure its false-positive / false-negative rate before trusting it, exactly like jeTT's eval gate.
- Build the **consequence-swap**: one model surface, two consequence backends (real tools vs sandbox + canaries), flipped by the control plane.
- Add **canary tokens** and the **alerting tripwire** — this is the cheapest, highest-value piece and proves the whole concept.
- Log everything, feed captured attacks back into the detector.

The asymmetry and the control plane are where the effort should go — not making the mirror visually perfect (diminishing returns, impossible at the limit). Same model up front, swapped consequences behind the curtain, canaries that self-report, and a control plane the attacker can never reach. That's the version that's actually that good.
