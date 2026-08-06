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

Six production sites. All six are **double-NUL today**: a literal that already
ends with `\0` passed to a helper that appends another. (It was recorded as four
until the rule-1 pass found B5/B6 — see the correction below.)

| # | site | today | after | blast radius | action |
|---|---|---|---|---|---|
| B1 | `dsm_storage_node/src/api/infra/hardening.rs:124` `blake3_tagged("DSM/perm\0", …)` | `"DSM/perm" \|\| 0x00 \|\| 0x00` | `"DSM/perm" \|\| 0x00` | PRF behind `permute_unbiased` → server-side replication **push order**. NOT a discovery function — see the trace below | synchronized redeploy of the assigned holders; **no migration, no re-replication** |
| B2 | `dsm_storage_node/src/api/infra/hardening.rs:149` `blake3_tagged("DSM/mirror\0", …)` | doubled | single | `mirror_set_w` → `expected_mirrors`, which feeds **only an `info!` log line** | redeploy; nothing else observes it |

### Why B1/B2 strand nothing — the read/repair trace

Traced from each PRF's output to its sink, and the read path separately, because
"no placement column" is not sufficient: blob location is itself persisted state.

**Write side.** `permute_unbiased` (the `DSM/perm` consumer) is reached only from
`replication.rs:254` inside `get_replication_targets`, whose sole production
caller is `replicate_object` (`store.rs:276`, `b0x.rs:286`). That enqueues
server-to-server replication pushes. It is a **push preference**, and it is
belt-and-braces: the SDK already writes to every node itself —
`put_to_all_replicas` (`storage_node_sdk.rs:983`) loops `self.clients` with no
placement-derived subset, and `delete_at_all_replicas` (`:1038`) mirrors it.

**Read side — the decisive one.** The node's `get_object_handler`
(`store.rs:341`) is **local-only**: `db::get_object_by_key` against its own DB,
404 otherwise. It never recomputes placement and never queries a peer. Discovery
therefore lives in the client, and `get_from_any_node_path`
(`dsm_sdk/src/sdk/storage_io.rs:254-283`) iterates **every** entry in
`config.node_urls`, returning the first success. That is global
content-addressed discovery over the configured fleet — the address is the only
input, and the placement function is not consulted.

So an object written under the old permutation stays exactly where it is and
stays findable, because a reader tries every node regardless of what any PRF
says.

**Mirror set.** `mirror_set_w` has two call sites: `hardening.rs:157` (its own
internals) and `bytecommit.rs:170`. At `:170` the result is bound to
`expected_mirrors` and used **only** in the `info!` at `:176-179` — verified by
grepping every occurrence in that file. Nothing routes, verifies or persists it,
and no cross-node comparison exists, so two nodes disagreeing about a mirror set
would go unnoticed today.

**Repair/gossip.** `api/transport/gossip.rs` contains no reference to
`permute_unbiased`, `get_replication_targets`, `mirror_set_w` or
`blake3_tagged` — it does not recompute placement, so there is no repair worker
that could fail to find an old copy.

**Conclusion.** B1 and B2 remain *cryptographically* breaking — the bytes move —
but their operational blast radius is a synchronized redeploy. No stranded
objects, no re-replication, no reindex, no fleet-state clear. A rebalance is
optional cosmetics, not a correctness requirement.

**Caveat, unverified:** this is a source trace, not a fleet exercise. The runtime
content of `config.node_urls` is deployment configuration, and the conclusion
assumes readers are configured with the full node set. If any deployment
configures a reader with a strict subset of the fleet, discovery narrows to that
subset — which is true today independently of this cut, but would make an
unbalanced push order matter more than it does now.
| B3 | `dsm_sdk/src/storage/client_db/cert_resync.rs:363` `dsm_domain_hasher("DSM/cert-restart/v1\0")` | doubled | single | `compute_joint_auth_hash` — the joint cert-restart statement **both AKs sign** | clear pending cert-restart state; no fallback reader |
| B4 | `dsm_sdk/src/sdk/kyber_identity.rs:29` `KYBER_IDENTITY_BINDING_TAG = "DSM/kyber-identity-binding\0"` into the **core** `domain_hash` (import confirmed at `:23`) | doubled | single | ML-KEM ↔ device-identity binding, AK-signed. **Nothing verifies it today** — see the cache trace below | regenerate bindings; peers must update together |

| B5 | `dsm_sdk/src/sdk/b0x_sdk.rs:1349` `dsm_domain_hasher("DSM/b0x-reply-message-id\0")` | doubled | single | b0x transport-local spool id (16 truncated bytes). Dedupes redeliveries onto one spool row; unsigned, not persisted as an identity | synchronized client update; in-flight messages may spool twice across the upgrade |
| B6 | `dsm_sdk/src/sdk/b0x_sdk.rs:1513` `dsm_domain_hasher("DSM/b0x-certresync-message-id\0")` | doubled | single | same class, cert-resync transport id | same |

### B4 cache trace — no verdict is cached anywhere, and nothing verifies

Searched for persisted verification booleans, accepted-binding rows, in-memory
maps, Android-side caches, and any lookup keyed by the preserved identity rather
than the binding digest. Result:

- **`verify_kyber_identity_binding` has ZERO production callers.** Only
  `build_local_kyber_identity_binding` is used — `b0x_sdk.rs:979`, `:1155`,
  `storage_node_sdk.rs:3148`. The binding is produced and shipped; nothing on
  any path checks it.
- **The storage node persists but does not verify.** `kyber_public_key` and
  `kyber_binding_sig` are columns on the device registry (`db/pg.rs:286-287`,
  `db/sqlite.rs:206`), written by the registration insert and read back by
  `get_device`. No signature check exists on that path.
- **`contacts.kyber_public_key` caches the peer's KEY**, not the binding digest
  and not a verdict.
- **`contacts.verified` / `verification_proof` are contact-trust fields**, sticky
  -OR on upsert and written from `ContactRecord`, never from a binding check.
  Pinned by `storing_a_kyber_public_key_does_not_cache_a_verification_verdict`,
  which compares the column BEFORE and AFTER storing a key rather than against a
  literal — the fixture already sets it, so a fixed-value assertion would have
  measured the fixture.
- **No Android/Kotlin reference exists at all.**

Consequence, stated plainly: **B4's digest move is inert in production today**,
because no code verifies the binding. The stored `kyber_binding_sig` rows become
unverifiable-if-anyone-ever-checks, which is why they are still regenerated — but
there is no cached verdict to invalidate, and the earlier claim in the B4 row
that a "verifier re-derives" was wrong. A verifier exists; nothing calls it.

### Correction: the breaking set is SIX, not four

B5 and B6 were missed in the original enumeration. The cause was mine and is
worth recording so the method is not trusted further than it earns: the grep that
enumerated NUL-bearing literals was run with `head -30`, and the truncated output
was treated as the complete set. Re-running it unbounded against the rule-1
helpers found both.

They were caught before any code changed, by the per-layer discipline rather than
by the inventory — which is the argument for keeping that discipline for rule 1
rather than trusting the table. But "exactly four" should never have been
asserted on the strength of a truncated search.

Severity: LOW relative to B3/B4 — no key regeneration, no identity to reissue.
But **"no state clear required" was wrong**, and the correction matters: a
synchronized client update does not remove a spool row that already exists under
the old id.

Evidence from the schema (`db/sqlite.rs:221-234`, `db/pg.rs:306`):

  message_id      TEXT NOT NULL UNIQUE
  expires_at_iter INTEGER            -- NULLABLE

Dedup is enforced by that UNIQUE column plus `INSERT OR IGNORE`
(`sqlite.rs:1129`, `:1157`), so it keys on the exact id. Purges are
`DELETE ... WHERE expires_at_iter IS NOT NULL AND expires_at_iter < ?`
(`:1284`) and `DELETE ... WHERE acked = 1 AND seq_num < ?` (`:1290`). An UNACKED
row with a NULL expiry is therefore removed by neither and persists indefinitely.
A repost after the cut computes a different id, `INSERT OR IGNORE` sees no
conflict, and the recipient holds the same logical message twice.

**Procedure chosen: quiesce and drain, as an actual cut boundary.**

The order matters. Querying the count while producers are still running proves
nothing: a message can arrive between the query and the upgrade, and the drain
becomes a hopeful observation rather than a boundary.

  1. Disable new b0x producers AND retries.
  2. Let in-flight deliveries and acknowledgements settle.
  3. On every node that can HOLD a row for the affected traffic, verify

         SELECT COUNT(*) FROM inbox_spool WHERE acked = 0;   -- must be 0

     "Every node" is the wrong rule and only looks right at the current fleet
     size. Replication is epidemic: an object lives on its ASSIGNED replica set
     (`get_replication_targets` permutes alive nodes and takes
     `replication_factor`; `mirror_set_w` takes `MMIRROR`), not on all of them.
     The b0x spool is placed differently again — the SDK submit loop posts to
     every endpoint in `storage_node_endpoints` WITHOUT breaking on first
     success (`b0x_sdk.rs:1470-1507`), so a row can exist on any endpoint a
     participating client was configured with.

     AND THE SET IS HISTORICAL, NOT CURRENT. An unacked row with a NULL
     `expires_at_iter` is purged by neither sweep, so it survives indefinitely —
     including across a node being taken out of service and later rejoining. The
     required set is therefore **every storage node that could have received a
     pre-cut submission and may return to service**, not the union of today's
     endpoint lists. A node that is unavailable at check time CANNOT be silently
     omitted: it must be permanently decommissioned, or cleared before it
     rejoins, or the cut is refused.

     If that historical set cannot be established with confidence, the safe rule
     is to drain or wipe the entire potentially reachable storage fleet. An
     unchecked node that rejoins carries pre-cut rows back into service.

  4. Keep producers disabled — the check is only valid while nothing can write.
  5. Upgrade all clients and nodes together.
  6. Re-enable traffic only once every participant is on the canonical encoding.

Steps 1 and 4 are what make step 3 meaningful. With producers still enabled the
zero is a sample, not an invariant.

Why not the alternatives:

  - *Clear only pending reply and cert-resync rows.* The envelope is an opaque
    BLOB and the id is a truncated digest, so selecting exactly those two message
    classes means decoding every spooled envelope. More moving parts than
    draining, for no benefit once drained.
  - *Accept a bounded duplicate window and rely on handler idempotency.* NOT
    chosen, because that idempotency is not established. The bilateral confirm
    path already has a known completion asymmetry where a receiver commits and
    the sender does not, and the proposed remedy there was to ADD an idempotent
    re-ACK cache — i.e. the property is a wish, not a fact. Accepting duplicates
    on the strength of an unproven claim is exactly the move this cut exists to
    stop making.

`no_unlisted_nul_bearing_literal_reaches_a_rule1_helper` now pins the count and
tells the next reader to re-run the enumeration unbounded before changing it.

Plus one test-only group:

| # | site | today | after | action |
|---|---|---|---|---|
| B5 | `canonical_lp.rs` test literals `b"d"`, `b"dom"`, `b"domain-a"`, `b"domain-b"` | written raw with **no** NUL | `\|\| 0x00` appended | regenerate expectations. Note these literals are deliberately prefix-related (`b"d"` ⊂ `b"dom"` ⊂ `b"domain-a"`); the canonical rule **removes** the ambiguity they probe, so the tests should be re-aimed at proving separation rather than characterizing collision |

## Not in this cut

| construction | why | where it goes |
|---|---|---|
| rule 6 — `blake3::derive_key` contexts (`recovery/capsule.rs:25-26`, `sdk/seed_vault.rs`, `sdk/recovery_sdk.rs`, `crates/dsm-sphincs/src/lib.rs:297`) | different construction; addresses **physical NFC media** | `DeriveKeyContext`, frozen, unchanged |
| rule 5 — `dsm-anchor-core::hash::h` (~20 `DSM/anchor/*` tags) | no delimiter at all; verifier is **flashed silicon** | `AnchorHashDomain`, separate reviewed cut |
