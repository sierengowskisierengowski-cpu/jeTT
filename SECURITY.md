# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Active development |
| Tagged releases | ✅ Best-effort patch support |
| Older releases | ❌ No support |

---

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

jeTT is a security tool — responsible disclosure is essential. If you discover a vulnerability (including model poisoning risks, privilege escalation in the daemon, or bypass techniques against the guard logic), please report it privately.

### How to report

Send a detailed report to the maintainers via one of the following channels:

1. **GitHub private security advisory** (preferred):
   Navigate to the repository → Security → Advisories → "Report a vulnerability".
   GitHub will keep the report confidential until a fix is ready.

2. **Direct contact**:
   Reach out to a repository maintainer directly via GitHub direct message or the contact information listed on their GitHub profile.

### What to include

A good vulnerability report includes:

- A description of the vulnerability and its potential impact
- Steps to reproduce (minimal proof-of-concept if possible)
- The component affected (`src/engine.rs`, `src/bin/daemon.rs`, training pipeline, etc.)
- Any suggested mitigations

### What to expect

- **Acknowledgement** within 3 business days
- **Initial assessment** within 7 days
- **Patch or mitigation** shipped as soon as practical — critical issues within 14 days where possible
- **Credit** in the CHANGELOG and release notes (unless you prefer to remain anonymous)

---

## Scope

We consider the following in-scope:

- Remote code execution or privilege escalation via the daemon
- Model poisoning or training data injection that degrades detection accuracy
- Authentication or authorisation bypass in the control-plane server (`cmd/server/`)
- Path traversal or arbitrary file read/write in any component
- Denial-of-service affecting the daemon or guard path

Out of scope:

- Theoretical attacks that require physical access to the machine
- Issues in dependencies that already have upstream CVEs (please report those to the upstream project)
- False-positive or false-negative detections (these are accuracy issues, not security vulnerabilities — open a regular issue)

---

## Disclosure policy

We follow a coordinated disclosure model. We ask that you give us a reasonable amount of time to patch a vulnerability before making details public. We will coordinate a public disclosure date with you.
