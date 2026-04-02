# Security Policy

DSM is an early beta repository that includes novel cryptographic and wallet
code. Please treat security reports seriously and avoid posting vulnerabilities
publicly until they have been reviewed.

## Supported Versions

We currently review security issues for:

- The `main` branch
- The latest tagged beta or release candidate

Older snapshots may not receive fixes.

## Reporting a Vulnerability

Please email `team@irrefutablelabs.org` with:

- A clear description of the issue
- Impact and affected components
- Reproduction steps or a proof of concept
- Any suggested mitigation or patch, if you have one

Do not open a public GitHub issue for vulnerabilities that could put users,
contributors, or infrastructure at risk.

## Response timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | Within **5 business days** of report receipt |
| Triage / severity assessment | Within **10 business days** where possible |
| Fix coordination | Depends on severity; critical issues are prioritized on `main` |

These are goals, not SLAs. If you need a status update, reply to the same thread.

## PGP / encrypted reports (optional)

For sensitive material you may encrypt to a maintainer PGP key **when one is published**
in this repository or on the project website. Until a project key is listed here,
use the contact email above and request a secure channel if needed.

## What to Expect

- We will acknowledge receipt as soon as practical.
- We may ask follow-up questions or request a private reproduction.
- Once a fix is ready, we will coordinate disclosure in a changelog entry or
  release note when appropriate.

## Scope

Security reports are especially helpful for:

- Wallet key handling and signing flows
- JNI / Android boundary handling
- Protobuf parsing and transport validation
- Storage node trust boundaries and authorization
- Supply, accounting, or state transition invariants
