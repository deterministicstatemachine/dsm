<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0001 — impact table for the tagged-hash cut (rules 1, 2, 3, 4, 7)

Every domain literal reaching an ordinary tagged-hash path, classified against
the canonical transformation:

```text
source domain: bytes with no NUL      encoded domain: domain || 0x00
```

Scope: rules 1, 2, 3, 4, 7. Rule 6 (`blake3::derive_key`) and rule 5
(`dsm-anchor-core::hash::h`) are out of scope by decision — see the ADR.

## Byte-preserving — no digest moves

These change spelling only. Verified by
`dsm/tests/domain_encoding_byte_preservation.rs`.

| # | site | today | after | why identical |
|---|---|---|---|---|
| 1 | 5 × `DOM_*` in `commitments/precommit.rs:30-34` | `hash_lp*` writes the constant raw; each ends with exactly one `\0` | constant loses the `\0`; encoder appends it | same bytes |
| 2 | 4 × `DOM_*` in `commitments/deterministic.rs:21-24` | `hash_fields` writes the constant raw under `TAG_COMMITMENT_FIELDS` | same move | same bytes |
| 3 | `LEGACY_V1_DOMAIN` `precommit.rs:1389` (test-only) | ends with one `\0`, written raw | same move | same bytes |
| 4 | every registry tag without a trailing NUL, via `dsm_domain_hasher` | `tag \|\| 0x00` | unchanged | already canonical |
| 5 | `TAG_DSM_DLV_OPEN_NUL` via the SDK shim (`vault/lifecycle.rs:35`) | shim trims → `"DSM/dlv/open" \|\| 0x00` | constant renamed to `TAG_DSM_DLV_OPEN`, no shim | same bytes |
| 6 | 69 of 71 `blake3_tagged` call sites in `dsm_storage_node` | `tag \|\| 0x00` | unchanged | already canonical |
| 7 | `replication.rs:253` `blake3_tagged("DSM/place", …)` | already passes no NUL | unchanged | already canonical |
| 8 | `db/pg.rs:497`, `db/sqlite.rs:450` `update(b"DSM/smt-node\0")` | one literal into a plain hasher | encoder, tag `"DSM/smt-node"` | same bytes |
| 9 | `api/registry/core.rs:77` `update(b"DSM/registry\0")` | same shape | encoder, tag `"DSM/registry"` | same bytes |
| 10 | `crypto_kat.rs:82` `manual.update(b"DSM/state-hash\0")` | same shape | encoder | same bytes |
| 11 | `whitepaper_kat.rs:30` `spec_digest` | `update(tag); update(&[0]);` | encoder | same bytes |
| 12 | `benchmark.rs:619` `domain_hash` + `b"DSM/bench-*\0"` literals | tag written raw, NUL inside the literal | encoder, tag without NUL | same bytes |

**Consequence: none of the frozen artifacts the sweep flagged actually move.**
The whitepaper KAT digests, the SMT golden vectors, the ML-KEM keygen pins, all
five copies of the protobuf vector corpus, and the SQLite primary keys
(`token_policies.policy_commit`, `token_registry.token_id`, canonical balance
keys) all derive from non-NUL tags through rule 1 and are preserved.

## Breaking — digest moves, clean cut required

Four production sites. All four are **double-NUL today**: a literal that already
ends with `\0` passed to a helper that appends another.

| # | site | today | after | blast radius | action |
|---|---|---|---|---|---|
| B1 | `dsm_storage_node/src/api/infra/hardening.rs:124` `blake3_tagged("DSM/perm\0", …)` | `"DSM/perm" \|\| 0x00 \|\| 0x00` | `"DSM/perm" \|\| 0x00` | PRF behind `permute_unbiased` → **replica placement on the live fleet** | redeploy all 3 nodes together; placement is recomputed, not stored — confirm before assuming migration-free |
| B2 | `dsm_storage_node/src/api/infra/hardening.rs:149` `blake3_tagged("DSM/mirror\0", …)` | doubled | single | mirror-set seed → **live fleet** | same redeploy |
| B3 | `dsm_sdk/src/storage/client_db/cert_resync.rs:363` `dsm_domain_hasher("DSM/cert-restart/v1\0")` | doubled | single | `compute_joint_auth_hash` — the joint cert-restart statement **both AKs sign** | clear pending cert-restart state; no fallback reader |
| B4 | `dsm_sdk/src/sdk/kyber_identity.rs:29` `KYBER_IDENTITY_BINDING_TAG = "DSM/kyber-identity-binding\0"` into the **core** `domain_hash` (import confirmed at `:23`) | doubled | single | ML-KEM ↔ device-identity binding; AK-signed, verifier re-derives | regenerate bindings; peers must update together |

Plus one test-only group:

| # | site | today | after | action |
|---|---|---|---|---|
| B5 | `canonical_lp.rs` test literals `b"d"`, `b"dom"`, `b"domain-a"`, `b"domain-b"` | written raw with **no** NUL | `\|\| 0x00` appended | regenerate expectations. Note these literals are deliberately prefix-related (`b"d"` ⊂ `b"dom"` ⊂ `b"domain-a"`); the canonical rule **removes** the ambiguity they probe, so the tests should be re-aimed at proving separation rather than characterizing collision |

## Not in this cut

| construction | why | where it goes |
|---|---|---|
| rule 6 — `blake3::derive_key` contexts (`recovery/capsule.rs:25-26`, `sdk/seed_vault.rs`, `sdk/recovery_sdk.rs`, `crates/dsm-sphincs/src/lib.rs:297`) | different construction; addresses **physical NFC media** | `DeriveKeyContext`, frozen, unchanged |
| rule 5 — `dsm-anchor-core::hash::h` (~20 `DSM/anchor/*` tags) | no delimiter at all; verifier is **flashed silicon** | `AnchorHashDomain`, separate reviewed cut |
