# Security Policy

DSM (Deterministic State Machine) is a post-quantum identity and bilateral-settlement
protocol with novel cryptography and a custom JNI / Android / iOS / storage-node stack.
Vulnerability reports are taken seriously and follow a coordinated-disclosure model.

## Reporting a Vulnerability

**Email:** `security@deterministicstatemachine.org`

**Encrypt to the DSM Security PGP key** (fingerprint + armored block below).

Public GitHub issues for security-impacting bugs are discouraged until the
embargo period ends. If a public issue has already been filed and you realize
it is security-impacting, email immediately and reference the issue number.

Include in your report:

- A clear description of the issue.
- Affected components, files, commits, or releases.
- Reproduction steps or a proof-of-concept.
- Suggested mitigation or patch, if you have one.
- Whether you intend to disclose publicly, and on what timeline.

## Response Timeline (SLA)

We commit to the following turnaround on every report sent to
`security@deterministicstatemachine.org`:

| Stage | Target |
|---|---|
| **Acknowledgement of receipt** | within **48 hours** |
| **Initial triage + severity assessment** | within **7 days** |
| **Mitigation plan or fix ETA** | within **30 days** |
| **Embargo / coordinated-disclosure window** | default **90 days** from acknowledgement, negotiable for fixes that require platform coordination |
| **CVE assignment (if applicable)** | requested before public disclosure |

Acknowledgement comes from a human, not an autoresponder. If you do not
receive a reply within 48 hours, retry the same address with `[URGENT]` in
the subject line, then escalate via the maintainer's GitHub profile.

## Supported Versions

| Version | Supported |
|---|---|
| `main` (active development) | ✅ Yes |
| Latest tagged beta / release candidate | ✅ Yes |
| Previous tagged release | ⚠️ Critical fixes only |
| Older snapshots | ❌ No — please update |

DSM is pre-mainnet beta software. There is no long-tail of supported
release branches; security fixes land on `main` and the next beta tag.

## Scope

In-scope for security reports:

- Wallet key handling and signing flows (SPHINCS+ ephemeral keys, cert chain).
- Fused hardware-anchor enrollment (σ^chip / σ^host) + anti-clone gate, attractor commitment derivation.
- JNI / Android / iOS boundary handling (memory safety, FFI signatures).
- Protobuf parsing and Envelope v3 transport validation.
- Bilateral 3-phase commit protocol (Phase 1/2/3 ordering, abort safety).
- Receipt acceptance pipeline (verify_stitched_receipt, SMT replace, EK cert chain).
- Storage node trust boundaries (PaidK gate, signal hysteresis, registry update).
- Bitcoin SPV verifier, HTLC unlock, dBTC bridge confirmation gate.
- Supply, accounting, double-spend, fork resolution, or state-transition invariants.
- Recovery capsule (NFC ring, AEAD AAD format, nonce derivation, ring KDF).
- Commitments layer (pre-commit, smart-commit, oracle binding).

Out of scope (please report via normal issue tracker, not via security email):

- Frontend layout / styling / accessibility bugs (unless they enable spoofing).
- Build-system or CI failures that don't affect shipped artifacts.
- Bugs in third-party dependencies — report upstream first; we'll coordinate
  if the bug is exploitable through our usage.

## What to Expect (Disclosure Workflow)

1. You email `security@deterministicstatemachine.org` encrypted with the
   DSM Security PGP key.
2. We acknowledge within 48 hours, sign-encrypted.
3. We open a **private security advisory** on GitHub (Dependabot-style) and
   add you as a viewer if you provide a GitHub handle.
4. We confirm the issue privately, agree on severity (CVSS v3.1) + embargo.
5. We develop and test a fix on a private branch.
6. We coordinate disclosure date with you. Default 90 days; we may publish
   sooner if a fix is verified or the bug is already in the wild.
7. Public advisory + changelog entry on disclosure date, crediting the
   reporter (unless you request anonymity).

If you do not want to be credited, say so explicitly in your initial email.

## Known Cryptographic Limitations

Stated up front so that neither a reviewer nor an integrator has to discover
them by reading the source.

**The SPHINCS+ implementation is custom and unaudited.** It substitutes BLAKE3
for SHA2/SHAKE in every hash, PRF and `thash` call, and it uses its own address
word layout. Only the parameter set *sizes* match the standardised sets. It is
therefore **not FIPS-205 conformant and not interoperable** with any reference
implementation, and no published known-answer vectors apply to it. The vectors
in `dsm/src/crypto/sphincs_kat_tests.rs` are frozen in-source regression
tripwires, not independent validation. A third-party cryptographic audit has
not been performed.

**A FORS address collision was found and fixed by internal review (2026-08-03).**
Two address fields shared a word, so in `fors_sign` the FORS tree number was
overwritten by the leaf index before the secret was derived. All `k` FORS trees
drew from a single pool of `2^a` secrets rather than `k` independent pools. For
SPX128f (`a=6, k=33`) — the variant the anchor firmware signs with — that is 33
trees over one 64-leaf pool, so a single signature revealed up to 33 of the 64
secrets in it. FORS is a few-time signature and its security argument requires
the trees to be independent; that assumption did not hold. The exact forgery
cost has not been quantified by a cryptographer.

The defect was invisible to the test suite because the verifier reproduced the
same address construction: signatures verified, an exhaustive single-bit
malleability sweep passed, and the file named for known-answer testing contained
only self-comparisons. **A sign/verify round trip cannot detect a defect that
the signer and the verifier share.** Coverage over such shared code must come
from tests that assert on the intermediate structure directly.

Fixing it changed the hypertree root, so **every key and signature produced
before the fix is invalid after it**, and the same mnemonic now derives a
different identity. Keys, signatures and device state from before the fix must
be discarded rather than migrated; devices and anchors need re-provisioning.
Because DSM is pre-release and has no external users, this was taken as a clean
cut with no compatibility path.

**Signing is deterministic.** The optional randomiser (`opt_rand`) that
SPHINCS+ permits for the message randomiser `R` is not implemented, so `R` is a
deterministic function of the secret key and the message. This is a permitted
mode, but it removes the hedge against fault-injection and side-channel attacks
that re-signing the same message with fresh randomness would provide. Tracked as
a hardening item, not a defect.

## Past Disclosures

| Advisory ID | Date | Severity | Component | Status |
|---|---|---|---|---|
| _(none yet — first advisory will populate this table)_ | | | | |

This table is updated by hand on each disclosure. The GitHub Security
Advisories tab is the canonical record; this table is for quick scanning.

## Secure Communications

### DSM Security PGP Key

- **UID:** `DSM Security <security@deterministicstatemachine.org>`
- **Fingerprint:** `CB2B 972F FE87 6EAF BED7  9FA6 F43F 6F37 334D 1149`
- **Algorithm:** RSA 4096, created 2026-05-28, expires 2028-05-27
- **Status:** Primary signing + encryption key for the `security@` mailbox

Verify the fingerprint **before** encrypting anything sensitive. The block
below is the canonical source; do not trust a copy fetched elsewhere
without comparing the fingerprint.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=ja0I
-----END PGP PUBLIC KEY BLOCK-----
```

To import:

```bash
gpg --import < /path/to/dsm-security.asc      # from a file
gpg --recv-keys CB2B972FFE876EAFBED79FA6F43F6F37334D1149   # once published
```

After import, **verify the fingerprint matches** before trusting the key:

```bash
gpg --fingerprint security@deterministicstatemachine.org
# expect: CB2B 972F FE87 6EAF BED7  9FA6 F43F 6F37 334D 1149
```

### Key Rotation

The DSM Security key may rotate before its 2028-05-27 expiration if:

- The current key is suspected compromised.
- The maintainer set changes and a new shared key is generated.
- An algorithm migration (e.g., post-quantum signing) is adopted.

Any rotation will be announced via:
1. A signed commit to this file bumping the fingerprint + replacing the
   armored block.
2. A signed revocation certificate published for the old fingerprint.
3. A GitHub Release announcement referencing both.

Old reports already in flight under a rotated key remain valid; we will
re-acknowledge them under the new key on request.

## Reproducibility & Verification

For reports that include a proof-of-concept, please target the latest
`main` commit hash and include:

- The exact `cargo` / `npm` / `gradle` versions used.
- The exact Android API level (if relevant to a JNI bug).
- The storage-node deployment topology used (single-node vs replica set).
- For protocol-layer bugs: the protobuf payload bytes that triggered the
  bug, hex-encoded.

We will reproduce against `main` HEAD before triaging.

## Acknowledgements

We will credit reporters in the public advisory + changelog entry unless
they request anonymity. Bounty programs are not currently active; we may
revisit this for severe vulnerabilities on a case-by-case basis.
