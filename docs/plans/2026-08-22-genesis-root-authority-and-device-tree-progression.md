# Genesis root authority and Device Tree root progression — normative semantics

Answers the three questions area 8 left open, in the order they have to be answered. It is
**semantics, not encoding**: no object class, no wire schema, no publication address, no resolver
API, no storage behaviour. Those are gated at the end and are defined only against the predicate
below.

**Status of the inputs.** [Area 8](../reports/2026-08-21-rev15-conformance-delta.md) (merged,
`12b8b1ec`) records that a foreign verifier cannot construct a chain from a vault to an
authenticated owner-device authority.
[The authority audit](../audits/2026-08-22-owner-device-identity-authority.md) established that no
non-circular `g_o → R_G` edge exists today, and why: under canonical Genesis v2 there is no
genesis-committed public key for one to be rooted in. This document introduces one.

Baseline: `12b8b1ec`.

## Decisions taken

**Q1, genesis authority — a dedicated Genesis Root Key.** Not the recovery authority key `K_A`,
even though `K_A` is available early enough to be committed. `K_A` is semantically a recovery
authority: the recovery code uses it for tombstone/succession authority, possession proofs and
bind-once behaviour. Domain-separated signatures would make the reuse cryptographically
defensible, but the architectural coupling between two security domains buys nothing when another
deterministic SPHINCS+ derivation costs one KDF call.

**Q2, root progression — GRK establishes authority; a GRK-signed delegation exercises it.** The
mnemonic-derived root secret does not enter ordinary device operations. Root transitions are signed
by a delegated key whose authority descends from `g_o`, never from the tree being updated.

### The derivation-order constraint that forces this shape

The existing key tree is strictly ordered
(`dsm/src/core/identity/genesis_v2.rs:236-243`):

```
wallet_seed → genesis_nonce → G → { s0, device_seed → AK, AttA } → DevID → Smaster
```

Every device-scoped key already depends on `G`. Folding `AK_pk` into `G`'s preimage is therefore
circular **by construction**, not merely by trust — which is why the intuitive answer is
unavailable and why a new pre-genesis role is the correct one rather than an extra one.

### Stale claim to correct in the same change

`dsm/src/recovery/authority_anchor.rs:12-16` states that `K_A_pub` "CANNOT be a genesis field"
because the recovery mnemonic "is generated only when the user enables NFC backup … the mnemonic is
not in scope when `create_genesis_via_blind_mpc*` runs". That is true of the MPC path it names and
false under canonical Genesis v2: `system.createGenesisV2` requires the mnemonic
(`dsm_sdk/src/handlers/system_routes.rs:228-230`), caches it at step 1 (`:284`), and only then
computes genesis at step 2 (`:300`). The comment must be corrected when this lands, since the
design's reasoning depends on the true ordering.

---

## Part 1 — Genesis authority

### Derivation

```
GRK_seed = KDF(wallet_seed, "DSM/genesis-root-authority/v1" ‖ network_id ‖ wallet_index)
GRK      = SPHINCS+.KeyGen(GRK_seed)                        # SPX256f; pk = 64 B, sig = 49_856 B
```

`KDF` is the existing HKDF-BLAKE3 helper (`genesis_v2.rs:59-79`), used exactly as `genesis_nonce`
uses it. The inputs are `wallet_seed`, `network_id` and `wallet_index` — the same inputs
`derive_genesis_nonce` takes, and **`G` is not among them**.

### Genesis v3

`G` commits the exact public key:

```
G = H("DSM/genesis/v3" ‖ genesis_nonce ‖ network_id ‖ genesis_version
        ‖ grk_alg_id ‖ GRK_pk)
```

Three requirements on that preimage.

- **The exact key, not a commitment to it.** `H(GRK_pk)` would need its own preimage rules — a
  second canonicalization question, which is the area 7 failure mode reproduced in miniature. `G`
  is already a hash; folding the key directly *is* the commitment.
- **`grk_alg_id` is committed** so a future SPHINCS+ variant cannot be substituted for the
  committed one.
- **Variable-length fields are length-prefixed and fixed-width fields are big-endian.** The current
  v2 preimage concatenates a bare `network_id` and a little-endian `genesis_version`
  (`genesis_v2.rs:92-103`); with a variable-length key in the preimage, unprefixed concatenation is
  ambiguous. The exact byte layout is **not settled here and must not be settled in Rust**: the
  genesis preimage now feeds an authority check, so it needs a normative object class under the
  same registry discipline area 7 requires — object-class discriminant, schema version, field
  numbering, explicit widths.

### Non-circularity

The dependency graph with `GRK` added:

```
wallet_seed ─┬─► genesis_nonce ─┐
             └─► GRK ───────────┴─► G ─► { s0, device_seed → AK, AttA } ─► DevID ─► Smaster
```

Acyclic, and `GRK` sits strictly upstream of `G`. A verifier holding `g_o` authenticates `GRK_pk`
by **recomputation alone** — no fetch, no signature, no lookup, nothing that could itself require
an authority. That is the property the whole chain rests on, and it is the reason this edge is
non-circular rather than merely conventionally trusted.

### Role constraint

**GRK is not a device key, not a recovery key, not an anti-clone key, and not a spending key.** Its
only semantics are genesis-rooted authority and delegation. Specifically:

- a GRK signature MUST NOT be accepted as owner authority for any value operation, state
  advancement, or DLV successor;
- GRK MUST NOT appear as a device leaf in the Device Tree;
- the only preimages GRK ever signs are delegations under Part 2, each carrying a role
  discriminant, so no GRK signature is meaningful in any other context.

This is deliberate scope containment: the new trust edge must stay narrow enough that Part 2 does
not turn GRK into a universal authority.

### Availability and secrecy

`GRK_seed` and `GRK`'s secret key are **never persisted** — re-derived on demand from the unlocked
wallet seed, exactly as `s0` and `Smaster` are. `GRK` is fully re-derivable from the mnemonic alone
(`wallet_seed`, `network_id`, `wallet_index` are all available at recovery), so it survives device
loss with no additional backup artifact.

Compromise of the mnemonic already compromises the identity completely; GRK adds no new exposure.

### No migration path exists

A Genesis v2 identity cannot be upgraded. `g_o` is a hash of a preimage that did not contain a key,
and no later act can make it commit one. Existing identities must be re-provisioned under
`genesis_version = 3`. This is a fact about hashing rather than a policy choice, and it agrees with
the beta clean-cut rule: no dual-read, no fallback, no legacy acceptance path.

---

## Part 2 — Root progression

### One rule for every root

There is no special case for the first root. Every Device Tree root is produced by a **transition**
signed by a delegated key, including `R_G,0`, whose predecessor is a fixed domain-separated genesis
sentinel distinct from any reachable root — the same shape as Rev 15's `h_0` and the PD-SMT head
chain's all-zero parent. The sentinel's exact value is fixed by the encoding registry, not here.

GRK signs delegations only. It never signs a root.

### Delegation

A delegation binds at minimum:

| Field | Why it is required |
|---|---|
| `genesis_id` (`g_o`) | a delegation must not be replayable under another genesis |
| `role`, `role_version` | scoped to Device Tree root progression only; a future role change must not be silently accepted |
| `delegated_alg_id`, `delegated_pk` | the exact key authorized, named directly — never a DevID, never a tree position |
| `delegation_number` | monotone from 0 |
| `parent_delegation_digest` | digest of delegation `n−1`; the genesis sentinel at `n = 0` |

Signed by `GRK` over a domain-separated digest of those fields.

**The delegated key is named by key, not by tree membership.** This is the whole non-circularity
condition: nothing about the delegation's validity depends on the Device Tree it authorizes changes
to.

**Supersession is revocation.** Delegation `n+1`, chaining `n`, replaces it. There is no separate
revocation object. Roots signed under a superseded delegation remain valid history — supersession
changes who may sign *next*, not what was already authorized.

**Lineage gives fork evidence, not fork prevention.** Chaining each delegation to its predecessor's
digest means two delegations at the same number are detectable as a fork by any verifier holding
both. It cannot prevent the GRK holder from signing two — nothing can; it is their key. The
guarantee is that equivocation is evident rather than silent, and a verifier that sees a fork must
refuse rather than pick.

### Transition

A transition binds at minimum: `genesis_id`, `old_root`, `new_root`, `version_number`, and the
**digest of the delegation it acts under**. Signed by that delegation's `delegated_pk`.

The delegation digest is load-bearing and is missing from today's `DeviceTreeRootUpdateV1`
(`proto/dsm_app.proto:3732-3737`), which binds only `old_root`, `new_root` and `version_number`.
Without `genesis_id` a transition is replayable across identities, and without the delegation digest
a verifier cannot tell which authority to check it against. **The existing message is insufficient
even once a signer exists**, which is worth stating plainly so it is replaced rather than adopted.

Two ordering rules, both wall-clock-free:

- `version_number` is strictly monotone and `old_root` equals the predecessor's `new_root`;
- the bound delegation's `delegation_number` is **greater than or equal to** the one bound by the
  predecessor transition. Authority never moves backwards along the chain.

### What the prior root does and does not do

The prior authenticated root **constrains which transition is legal** — it fixes `old_root`, and it
is the state any churn or well-formedness bound is evaluated against. It is **not** what makes
`delegated_pk` authoritative. Those are two separate predicates over two separate objects, and
conflating them is exactly the circularity this design exists to avoid.

---

## Part 3 — The acceptance predicate

The verifier's only a priori input is `g_o`. Everything else is **presented** and nothing presented
is trusted before the step that authenticates it. Obtaining candidate material is not a step of the
predicate; it is input gathering, and it may use any mutable discovery path precisely because
discovery decides nothing.

The steps are ordered and the order is normative.

**P0 — Genesis binding.** Recompute `G′` over the presented genesis parameter set
(`genesis_nonce`, `network_id`, `genesis_version`, `grk_alg_id`, `GRK_pk`). Require `G′ = g_o`.
`GRK_pk` is now authoritative. *(No signature is checked here. That is the point: the step that
bootstraps authority consumes nothing but the identifier the verifier already holds.)*

**P1 — Delegation chain.** Walk `D_0 … D_k`: `D_0` at number 0 with the sentinel parent; each
`D_{i+1}` at number `i+1` with `parent_delegation_digest = digest(D_i)`; every `D_i` signed by
`GRK_pk`, binding `genesis_id = g_o`, carrying the root-progression role at a supported
`role_version`. Refuse on any fork. The tip `D_k` is the currently applicable delegation.

**P2 — Root chain.** Fold transitions `T_0 … T_n` forward from the genesis sentinel. For each: the
bound delegation must be on the chain authenticated in P1; its `delegation_number` must not
decrease; `old_root` must equal the running root; `version_number` must be strictly monotone; and
the signature must verify under that delegation's `delegated_pk`.

**P3 — Applicable root.** The applicable root is the highest-`version_number` root reachable by P2.
A root is never applicable because a node returned it as "latest" — an unauthenticatable root is a
refusal, not a fallback. If a node serves a root the verifier cannot reach by an authenticated
chain, the verifier refuses and reports *which* failure it hit (below).

**P4 — Membership.** Verify the inclusion proof for the presented `d_o` against **exactly** the
root authenticated in P3. `DeviceInclusionProofV1` carries its own `root_hash`
(`proto/dsm_app.proto:3750-3756`); that field must be required to equal the authenticated root and
must never be used *as* the root.

**P5 — Identifier recomputation.** Compute `d_o′ = H("DSM/devid" ‖ AK_pk ‖ AttA)` from the
independently presented `AK_pk` and `AttA`, and require `d_o′ = d_o` as proven included in P4.

**P6 — Promotion.** Only now is `AK_pk` owner authority for facts attributed to `d_o` under `g_o`.
The promotion is scoped: it authorizes device-attributed statements. It is not a spending
authorization and asserts nothing about anti-clone.

### Why the order is normative

A verifier that runs P5 before P2 has proven only that a presented triple is internally consistent
— anyone can generate a keypair and a 32-byte value whose hash matches a leaf they also chose. A
verifier that runs P4 against a root it has not authenticated has proven membership in a tree the
attacker supplied. Each step's authority comes from a strictly earlier step, and P0 depends on
nothing. That induction is the correctness argument, and it should be written down as such rather
than left implicit in call order.

### Failure taxonomy

Every refusal must distinguish:

- **absent** — no delegation chain, no root chain, no inclusion proof, no presented material. A
  liveness condition: the identity may be perfectly valid and simply unpublished.
- **incomplete** — a chain exists but the verifier cannot reach the claimed tip. Usually liveness,
  possibly withholding.
- **invalid** — a signature fails, a link breaks, a recomputation mismatches, or a fork is
  observed. An attack or a bug, never a retry.

A single error type covering all three would hide the only one that matters.

---

## Consequence: immutable publication is a prerequisite, not a companion

Adding signatures does not by itself make publication safe, because the current slot is mutable and
version-ordered. `upsert_device_tree_state_if_monotonic` accepts strictly-increasing
`version_number` and rejects everything else as stale (`dsm_storage_node/src/db/sqlite.rs:613-619`),
and the route is unauthenticated. **One anonymous PUT at `i64::MAX` permanently locks a genesis's
device-tree slot**: every genuine update afterwards is refused with 409. That is a live denial of
service today, independent of the authority question, and signing the payload does not fix it — the
node would still be ordering by a field it cannot verify.

The fix is area 4's shape, not a node-side signature check (which would break the index-only
invariant): transitions are published as immutable content-addressed objects, and the **client**
selects the tip by authenticating the chain. A garbage publish then becomes an unreferenced object
rather than a poisoned slot. **Area 4's immutable namespace therefore sequences before this work
ships**, and this is the sharpest reason yet for it.

---

## Proof obligations

The implementation must carry these as tests, not as comments:

1. **Structural non-circularity.** The GRK derivation must not accept `G` — enforce at the type
   level (no `g` parameter) and assert the dependency order in a test that would fail if `G` were
   threaded in.
2. **Recoverability.** GRK re-derived from the mnemonic alone is byte-identical to the one genesis
   committed.
3. **Genesis binding is sensitive to the key.** Flipping one byte of `GRK_pk` changes `G`.
4. **Ordering enforcement.** P4-before-P2 and P5-before-P2 orderings must be unreachable — a test
   that presents a valid inclusion proof under an *unauthenticated* root must be refused.
5. **Fork refusal.** Two delegations at the same number, both validly GRK-signed, must produce a
   refusal and never a selection.
6. **Backwards authority refusal.** A transition binding a lower `delegation_number` than its
   predecessor must be refused.
7. **Role isolation.** A GRK signature over a non-delegation preimage must not verify in any other
   context; a delegated-key signature over a non-transition preimage likewise.
8. **Mutation controls.** Each gate above disabled in turn must turn its test red, per the standing
   rule that an untested gate is an assumed one.

---

## Deliberately not decided here

Gated on this document being accepted as normative:

- object classes and their CCB byte layouts for the genesis-v3 preimage, the delegation, and the
  transition;
- any protobuf message or wire schema;
- immutable publication addresses and the canonical address derivation;
- the resolver API and its discovery paths;
- storage-node behaviour and endpoint shape;
- resumption of the five `compose_vault_state` call sites.

Two questions this design does not answer and should not:

- **Rollback of roots signed by a compromised delegate.** Supersession changes who signs next; it
  does not retract history. Retracting an append-only monotone chain is a substantive decision with
  its own failure modes.
- **Checkpointing.** A foreign verifier currently replays every transition, and each carries a
  49,856-byte SPX256f signature — roughly 0.5 MB for ten updates. Tolerable at expected device
  counts, and the honest bound on how long a chain a stranger can be asked to walk. Any checkpoint
  must preserve the P0-rooted induction rather than substitute for it.

## Sequencing

```
Area 4 immutable namespace ─┐
                            ├─► genesis v3 + GRK + delegation semantics ─► presentation object,
Area 8 semantics (merged) ──┘                                              resolver, publication
                                                                                    │
                                        resume schema-6 V2 lifecycle cut ◄───────────┘
                                        exact VaultStateV2 materialization
                                        atomic h_n lineage advancement
                                        finish V1 deletion
```

The five composition call sites stay paused throughout. There is still no legitimate
`expected_owner_public_key` to feed them, and there will not be one until P6 can be discharged.
