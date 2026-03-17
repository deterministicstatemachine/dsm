# Security Policy

## Reporting a Vulnerability

**Do not file public issues for security vulnerabilities.**

If you discover a security vulnerability in DSM, please report it responsibly through one of the following channels:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/deterministicstatemachine/dsm/security/advisories/new)
2. **Email**: security@deterministicstatemachine.org

### What to Include

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected versions and components
- Potential impact assessment
- Any suggested fixes (optional)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix development and testing | Within 30 days (critical), 90 days (other) |
| Public disclosure | After fix is released, coordinated with reporter |

## Scope

The following areas are in scope for security reports:

- **Cryptographic implementations** — hash functions, signatures, key exchange, commitments in `dsm-crypto`
- **State machine integrity** — state transition validation, determinism guarantees in `dsm-core`
- **Consensus safety** — agreement protocol correctness, Byzantine fault handling in `dsm-consensus`
- **P2P protocol** — message authentication, peer verification, transport security in `dsm-network`
- **Storage integrity** — Merkle tree correctness, snapshot tampering, data corruption in `dsm-storage`
- **Supply chain** — dependency vulnerabilities, build reproducibility

### Out of Scope

- Social engineering attacks against maintainers or users
- Denial of service attacks (unless they reveal an algorithmic complexity vulnerability)
- Vulnerabilities in third-party dependencies (report these upstream; notify us if they affect DSM)
- Issues in code not yet merged to `main`

## Disclosure Policy

We follow a coordinated disclosure model:

1. Reporter submits vulnerability privately.
2. We acknowledge and assess within the timelines above.
3. We develop and test a fix on a private branch.
4. We release the fix and publish a security advisory.
5. Reporter is credited (unless they prefer anonymity).

We ask reporters to:

- Allow us reasonable time to address the issue before public disclosure.
- Make a good-faith effort to avoid privacy violations, data destruction, or service disruption during testing.
- Not exploit the vulnerability beyond what is necessary to demonstrate it.

## Recognition

We gratefully acknowledge security researchers who report vulnerabilities responsibly. With your permission, we will credit you in:

- The GitHub Security Advisory
- The CHANGELOG entry for the fix
- The project's security acknowledgments

## Security Measures

DSM employs the following security practices:

- **No unsafe code** — `unsafe` is denied workspace-wide
- **No panics in library code** — `unwrap()` and `panic!()` are denied via clippy lints
- **Dependency auditing** — `cargo audit` and `cargo deny` run in CI on every push and weekly
- **License compliance** — only permissive licenses (MIT, Apache-2.0, BSD) are allowed
- **Signed commits** — required for all contributions to `main`
- **Code review** — minimum 2 reviewers required, with security team review for crypto changes

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |
