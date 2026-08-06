<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0001 — Three domain-separation constructions, kept explicitly separate

Status: accepted
Date: 2026-08-04

## Context

An audit found **seven** independent implementations of "domain-separate this
hash" across the repository, disagreeing on how the domain is encoded:

| # | rule | where |
|---|---|---|
| 1 | `domain \|\| 0x00` | `dsm::crypto::blake3::dsm_domain_hasher` |
| 2 | `trim_end_matches('\0')(domain) \|\| 0x00` | `dsm_sdk::wire::domain_hash_bytes` |
| 3 | outer tag, then `domain` written **raw** | `canonical_lp::hash_lp*`, `commitments::deterministic::hash_fields` |
| 4 | `domain \|\| 0x00`, no prefix assertion, no trim | `dsm_storage_node::api::infra::hardening::blake3_tagged` (71 sites) |
| 5 | `domain` with **no delimiter at all** | `dsm-anchor-core::hash::h` / `kdf` |
| 6 | BLAKE3 derive-key mode | `blake3::derive_key`, contexts carrying embedded NULs |
| 7 | hand-inlined copies of rule 1 | `whitepaper_kat.rs:30`, `crypto_kat.rs:82`, `pg.rs:497`, `sqlite.rs:450`, `registry/core.rs:77`, `benchmark.rs:619` |

Rules 1 and 2 disagree on the same declared tag. Rule 4 is rule 2's mirror image:
it never trims, so a caller that spells the NUL itself gets a doubled one. Rule 7
is rule 1 retyped by hand in six places, each free to drift.

## Decision

**The same cryptographic construction must encode domains identically
everywhere. Different constructions stay explicitly different, never share
helpers, and never silently normalize one another.**

Three constructions, three types, no generic `&[u8]` domain parameter shared
between them.

### `TaggedHashDomain` — the ordinary tagged hash (rules 1, 2, 3, 4, 7)

```text
source domain:   bytes with NO NUL, anywhere
encoded domain:  domain || 0x00
```

- A source domain containing a NUL — embedded or trailing — is **rejected**, not
  normalized. `trim_end_matches('\0')` is deleted.
- Core, SDK and the storage node call the same implementation. The hand-inlined
  copies are replaced by it.
- **No caller appends its own delimiter.** A caller that spells the NUL is now a
  compile-time or construction-time error rather than a silent double.
- Rule 3 joins by moving the delimiter from the constant into the encoder:
  ```text
  old:  DOM_X = "DSM/example\0"   and hash_lp writes DOM_X raw
  new:  DOM_X = "DSM/example"     and hash_lp writes DOM_X || 0x00
  ```
  For a constant that ends with exactly one NUL and contains no other, this is
  **byte-identical**. Any constant that does not fit the transformation is a
  breaking row in the impact table, never a silent normalization.

### `DeriveKeyContext` — BLAKE3 key derivation (rule 6), unchanged

`blake3::derive_key` is a KDF, not a tagged hash. Its context string is absorbed
by BLAKE3's own key-derivation mode; it is **not** `context || 0x00`, and making
it byte-compatible with `TaggedHashDomain` would be a category error.

- Context strings stay **exact and frozen**: no trimming, no normalization, not
  even for aesthetic consistency with the tagged-hash spelling.
- These contexts address **physical media**. `recovery/capsule.rs:302` keys the
  AEAD for recovery capsules written to NFC rings; `:323` derives the
  recovery-authority seed. Changing them silently rekeys objects that already
  exist in the physical world and cannot be migrated.
- A dedicated type prevents an ordinary domain tag from being passed to
  `derive_key` by accident, and vice versa.
- Frozen vectors are required for the capsule AEAD key and the recovery-authority
  seed.

Contexts are changed only if a concrete defect is found — not for consistency.

### `AnchorHashDomain` — the anchor construction (rule 5), decided separately

`dsm-anchor-core::hash::h` writes the domain with **no delimiter**. Its module
header justifies this by "fixed-length fields", and that justification is
contradicted in-crate: `anchor_glue.rs:118` passes variable-length `stpub`, and
`integration.rs:85` passes `"test/partsign"`, which has no `DSM/` prefix and so
proves no assertion exists to violate.

This is **not** absorbed into `TaggedHashDomain`, and it is **not** declared safe
by documentation. It gets its own investigation and its own type:

- Determine whether every component reaching `h()` is independently
  length-delimited before it arrives.
- If every component is unambiguous: freeze the construction with independent
  byte fixtures behind an `AnchorHashDomain` API.
- If it is raw concatenation with variable-length components: it is a real
  ambiguity, and it needs its own clean anchor cut **and a reflash**, because the
  verifier is flashed silicon.

That investigation is deliberately kept out of the host/storage delimiter work.

## Consequences

- Seven rules become three constructions that cannot be confused, because they
  do not share a parameter type.
- The host/storage cut is **almost entirely byte-preserving** — see
  `docs/adr/0001-impact-table.md`. Four production digests move, all four
  currently double-NUL.
- Physical NFC media and flashed anchor silicon are untouched by this cut.
- The four moving digests are a clean cryptographic cut: regenerate the affected
  fixtures, clear the affected host and fleet state, and add **no fallback
  reader**.
