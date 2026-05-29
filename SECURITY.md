# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities by emailing **security@qwentrix.com**. Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (where safe to share)
- Affected versions (if known)
- Any suggested mitigations

We follow a **90-day coordinated disclosure** policy:

1. We will acknowledge receipt of your report within **2 business days**.
2. We will send an initial assessment (severity, affected scope) within **7 business days**.
3. We aim to release a fix or mitigation within **90 calendar days** of acknowledgement. If a fix requires more time due to complexity, we will notify you and agree on an extended timeline.
4. We will credit you in the release notes unless you prefer to remain anonymous.
5. We ask that you do not publicly disclose the vulnerability until we have released a fix or the 90-day window has elapsed, whichever comes first.

## Scope

This policy covers the `lumen-scoring` Go module. For vulnerabilities in the Lumen web application or the `lumen` scanner CLI, use the same email address.

## No Bug Bounty

We do not currently offer a paid bug bounty program. We will acknowledge your contribution publicly (with your permission).

## Supported Versions

We support the latest published release. Older minor versions receive security backports at our discretion based on severity.

| Version | Supported |
|---|---|
| Latest (`v0.x.x`) | Yes |
| Earlier | Best-effort |

## PGP Key

We do not yet publish a PGP key for encrypted email. If you need a secure channel, request one at security@qwentrix.com and we will arrange a secure drop.
