# Security Policy

ChronX is a financial protocol. Security vulnerabilities — especially those affecting consensus, cryptography, or fund safety — are treated as the highest priority. We appreciate responsible disclosure and commit to working with researchers promptly and transparently.

---

## Supported Versions

| Version | Protocol | Supported |
|---|---|---|
| Current | V3.1 | ✅ Yes |
| Prior releases | V3, V2, V1 | ❌ No — please upgrade |

Only the current protocol version (V3.1) receives security patches. If you are running an older version, upgrade immediately.

---

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report all security findings to:

**Email:** security@chronx.io

Please encrypt your report using our PGP key (available at [chronx.io/security](https://chronx.io/security)) if the finding is sensitive.

---

## What to Include in Your Report

A useful vulnerability report includes:

1. **Description** — What is the vulnerability? What is the affected component?
2. **Impact** — What could an attacker achieve? (fund theft, double-spend, DoS, etc.)
3. **Reproduction steps** — Minimal steps or code to reproduce the issue.
4. **Affected versions** — Which node versions or protocol versions are affected?
5. **Your suggested fix** (optional) — If you have a proposed patch or mitigation.
6. **Your contact information** — So we can coordinate disclosure with you.

---

## Response Timeline

| Stage | Timeline |
|---|---|
| Acknowledgement | Within 48 hours of receipt |
| Triage and severity assessment | Within 7 days |
| Patch for critical vulnerabilities | Within 30 days |
| Patch for high/medium vulnerabilities | Within 60 days |
| Public disclosure | Coordinated with reporter after patch is released |

We will keep you informed throughout the process. If we need more information, we will contact you promptly.

---

## Scope

**In scope:**

- **chronx-node** — Full-node binary, startup sequence, genesis application
- **chronx-state** — StateEngine consensus rules, state transitions, double-spend prevention
- **chronx-crypto** — Dilithium2 signing, PoW validation, key generation
- **chronx-rpc** — JSON-RPC API, input validation, CORS handling
- **chronx-genesis** — Genesis state construction, supply verification
- **chronx-p2p** — Peer-to-peer networking, message validation
- **Wallet** — Key storage, transaction signing, CLI and GUI wallets

**Out of scope:**

- Third-party dependencies (report those directly to the upstream maintainer)
- Issues requiring physical access to the machine running the node
- Social engineering attacks
- Theoretical vulnerabilities without a practical exploit
- Issues in test utilities or development-only tooling

---

## Post-Quantum Cryptography

ChronX uses **Dilithium2** (CRYSTALS-Dilithium, NIST PQC Round 3 winner) for all transaction signing. Any finding related to the implementation or use of post-quantum cryptography — including side-channel attacks, key generation weaknesses, or signature malleability — is treated as a **Critical** priority regardless of apparent exploitability.

We do not use ECDSA, Ed25519, or any classical elliptic-curve signature scheme for consensus-critical operations.

---

## Acknowledgements

We publicly acknowledge security researchers who responsibly disclose vulnerabilities (with their permission) in our release notes and on the ChronX website.
