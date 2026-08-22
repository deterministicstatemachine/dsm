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
by a delegated key whose authority descends from `g_o`, never from the tree being updated. Each
delegation carries a **causal activation edge** so that supersession is enforced by the acceptance
predicate rather than merely asserted — and that enforcement is relative to a chain the verifier
holds, which is why revocation against a stranger additionally requires the frontier work Part 3
identifies as blocking **for that capability**. It does not block the SoFi path, which is
position-bound.

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
GRK_seed = KDF(wallet_seed, "DSM/genesis-root-authority/v1"
                            ‖ network_id ‖ wallet_index ‖ genesis_version)
GRK      = SPHINCS+.KeyGen(GRK_seed)                        # SPX256f; pk = 64 B, sig = 49_856 B
```

`KDF` is the existing HKDF-BLAKE3 helper (`genesis_v2.rs:59-79`). The inputs are `wallet_seed`,
`network_id`, `wallet_index` and `genesis_version` — and **`G` is not among them**.
`genesis_version` is a plain caller parameter, not a derivative of `G`, so including it keeps the
graph acyclic.

**GRK is identity-specific, not wallet-context-wide.** `derive_genesis_nonce` omits
`genesis_version` and is right to: it is a public nonce, and `G` folds the version itself, so the
identities still differ. A *key* is different. Without the version, one mnemonic would reuse the
same root authority across a v3 identity and any future v4 — so a GRK compromised under v3 would
carry into the v4 identity, and re-provisioning would not re-root the thing re-provisioning exists
to re-root. Binding the version makes the root authority per-identity, which is what "clean cut"
has to mean for a key.

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

Compromise of the mnemonic already compromises every mnemonic-rooted authority — authorship,
recovery, and now root delegation — so GRK adds no new exposure to that domain. It does **not**
compromise the identity completely: the fused anti-clone anchor is deliberately a separate
authority domain and is not mnemonic-derived, which is precisely why a seed copy can sign and still
cannot clone. Keeping those domains distinct in the wording matters, because a design that treats
"mnemonic compromise" as total loss has no reason to preserve the separation that limits it.

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
| `activation_transition_digest` | the chain position after which this delegation takes effect; the genesis sentinel at `n = 0` |

Signed by `GRK` over a domain-separated digest of those fields.

**The delegated key is named by key, not by tree membership.** This is the whole non-circularity
condition: nothing about the delegation's validity depends on the Device Tree it authorizes changes
to.

#### Activation, and why supersession needs it

Chaining `D_{n+1}` to `D_n` orders the delegations but does not retire `D_n`. Without an activation
edge, a verifier can only require that a transition's delegation number not decrease — and a
compromised `D_n` key satisfies that forever, because nothing forces any transition to bind
`D_{n+1}` at all. Supersession would be an assertion the acceptance predicate never checks. This is
forward authority, not the deferred question of retracting history.

So each delegation binds `activation_transition_digest`: the transition after which it becomes
effective. Write `act(D_i)` for that position, with the genesis sentinel meaning "effective from the
start of the chain".

**Ancestry means proper predecessors only.** The ancestry of `T_j` is `T_0 … T_{j−1}` — it does not
include `T_j`. Everything below depends on that being fixed mechanically rather than left to the
word "after".

> **Applicable delegation.** For a transition `T_j`, the applicable delegation is the
> **highest-numbered activation-eligible** delegation whose activation position lies in `T_j`'s
> **proper** ancestry. `T_j` must bind exactly that delegation.

Activation-eligibility is defined below and is not optional shorthand: without it, a delegation
whose predecessor never activated could still take effect.

Exactly one delegation qualifies for any `T_j`, and it is determined by the chain rather than
chosen by the signer. Once `D_{n+1}` is activation-eligible and `act(D_{n+1})` lies in a
transition's proper ancestry, `D_n` is no longer applicable for it, so supersession is enforced
rather than declared. This rule **replaces** the
earlier non-decreasing-number rule, which it strictly implies.

**A delegation does not authorize its own activation transition.** Because ancestry is proper,
`act(D_{n+1})` is not in its own ancestry: the activation transition is still authorized by `D_n`,
and `D_{n+1}` begins with the **child** of `act(D_{n+1})`. Handing `D_{n+1}` the transition that
names it would let a delegation bootstrap its own authority at the position it selected, which is
the self-activation ambiguity the proper-ancestry rule removes.

Three supporting constraints:

- **The digest, not the root value.** Activation names a transition digest because root *values*
  demonstrably recur. The existing suite asserts exactly that: after an add and a remove, the root
  at `version_number = 2` equals the single-device root at version 0
  (`dsm_sdk/src/sdk/storage_node_sdk.rs:4695-4713`). A root value is therefore not a unique chain
  position — naming one would activate a delegation at two places at once — while a transition
  digest is unique by construction.
- **Activation is forward-only.** `act(D_{n+1})` must be a strict descendant of `act(D_n)`. A
  delegation activating at or before its predecessor's activation would retroactively unseat
  transitions already authorized — that is history retraction, which is out of scope and must be
  refused rather than silently honoured. **Where this is discharged matters**: descendancy is a
  fact about the transition chain, so it cannot be checked while only delegations are authenticated.
  It is validated during the root-chain fold, as positions resolve — see P2.
- **An unresolvable activation never activates, and its inactivity cascades.** A delegation whose
  `activation_transition_digest` names no authenticated transition on the chain is not effective
  there. That is not a refusal — a delegation may legitimately be published ahead of the transition
  that activates it — but it must not become applicable, and it must not retire its predecessor.

  The cascade is the part that is easy to miss. Activation eligibility is a property of the
  **contiguous resolved prefix**, not of a delegation in isolation:

  > `D_i`, for `i > 0`, is **activation-eligible** only if every predecessor activation through
  > `act(D_{i−1})` resolves on the authenticated transition chain, *and* `act(D_i)` strictly
  > descends `act(D_{i−1})`. `D_0` is eligible by the sentinel.

  Without the cascade, a chain `D_0 → D_1 → D_2` in which `act(D_1)` never resolves but `act(D_2)`
  does would let `D_2` activate — and the verifier would have no way to establish that `act(D_2)`
  descends from `act(D_1)`, which is precisely what the forward-only rule requires. The lineage
  would have skipped an edge it never proved. An unresolved predecessor therefore blocks activation
  of **all** its descendants, while leaving the delegation objects themselves perfectly valid.

  This is a liveness failure of supersession, not a safety failure of the predicate: the effect is
  that an older delegation stays applicable, never that a newer one is honoured without proof. It is
  also indistinguishable from withholding the activating transition — one more reason revocation
  against strangers needs the frontier work rather than this rule.

**Roots signed under a superseded delegation remain valid history.** Supersession changes who may
sign *next*; it does not invalidate what was already authorized.

**What activation does not deliver.** Enforcement is relative to one authenticated chain. A
compromised `D_n` holder can still sign transitions on a branch that never contains
`act(D_{n+1})` — but that branch is a fork, and forks are refused (below). And a verifier that has
not discovered `D_{n+1}` cannot apply it at all, which is the frontier problem treated in Part 3.
**Supersession as revocation-against-strangers is not delivered by activation alone.**

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

Two rules, both wall-clock-free:

- `version_number` is strictly monotone and `old_root` equals the predecessor's `new_root`;
- the bound delegation is **the applicable delegation** for this transition, per the activation
  rule above. Authority never moves backwards, and never lingers past its successor's activation.

**A transition has at most one valid child.** Two transitions consuming the same authenticated
predecessor are a fork, even when both signatures verify under a properly applicable delegation.
The delegate is authorized to advance the chain, not to branch it.

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

**P1 — Delegation objects only.** Walk `D_0 … D_k`: `D_0` at number 0 with the sentinel parent and
sentinel activation; each `D_{i+1}` at number `i+1` with `parent_delegation_digest = digest(D_i)`;
every `D_i` signed by `GRK_pk`, binding `genesis_id = g_o`, carrying the root-progression role at a
supported `role_version`. Refuse on any fork — two delegations at one number are evidence, never a
choice.

Each `activation_transition_digest` is **recorded as an asserted position and nothing more**. P1
does not evaluate it. Whether one activation descends from another is a fact about the transition
chain, which P1 has not authenticated and must not consult — checking it here would make P1 depend
on P2 and break the very ordering property this predicate exists to guarantee.

**P2 — Root chain, and activation ordering.** Fold transitions forward from the genesis sentinel.
At each step the prefix `T_0 … T_{j−1}` is already authenticated, so `T_j` is admitted only when all
of the following hold against that prefix:

- `old_root` equals the running root and `version_number` is strictly monotone;
- the bound delegation digest identifies some `D_i` on P1's authenticated chain;
- `D_i` is **activation-eligible** against the current prefix — every activation through
  `act(D_{i−1})` resolves in it and each strictly descends its predecessor, `D_0` by the sentinel;
- `act(D_i)` resolves to a transition in `T_j`'s **proper** ancestry, or is the genesis sentinel;
- no higher-numbered **activation-eligible** `D_m` (`m > i`) has an activation resolving into that
  same proper ancestry — this is what retires `D_i`. A delegation outside the eligible prefix is
  inert: it neither activates nor retires;
- the signature verifies under `D_i`'s `delegated_pk`.

Then `T_j` joins the authenticated prefix. Activation ordering is validated here as positions
resolve: a delegation whose activation resolves at or before its predecessor's is refused as
history retraction; one whose activation never resolves is inert, and so is every delegation after
it until the lineage becomes constructible.

The eligible prefix is computed against the prefix authenticated so far, and it only ever grows as
the chain extends — a later activation resolves at a position at or beyond the current end, so it
can never enter an earlier transition's proper ancestry. The fold is therefore deterministic and
never revises a decision it already made.

Every fact P2 consumes is either authenticated by P0/P1 or by P2's own already-authenticated prefix.
The induction is over the chain, not over the document's section order.

**P3 — Chain tip, and fork refusal.** Two transitions consuming the same authenticated predecessor
are a **fork**, and a verifier holding both refuses. It does not take the higher `version_number`:
selecting a branch by ordering would convert equivocation into a rule, and hand any compromised
delegate a way to overwrite the chain by simply numbering higher. The tip is the end of the unique
authenticated chain, or a refusal.

A root is never accepted because a node returned it as "latest". An unauthenticatable root is a
refusal, not a fallback, and the verifier reports *which* failure it hit (below).

As with delegation forks, this is **evidence, not prevention**. A sibling that has not surfaced
cannot be detected, so a verifier's fork-freedom is only ever over the material it holds.

**P4 — Membership.** Verify the inclusion proof for the presented `d_o` against **exactly** the
root authenticated in P3. `DeviceInclusionProofV1` carries its own `root_hash`
(`proto/dsm_app.proto:3750-3756`); that field must be required to equal the authenticated root and
must never be used *as* the root.

**P5 — Identifier recomputation.** Compute `d_o′ = H("DSM/devid" ‖ AK_pk ‖ AttA)` from the
independently presented `AK_pk` and `AttA`, and require `d_o′ = d_o` as proven included in P4.

**P6 — Promotion.** `AK_pk` is owner authority for facts attributed to `d_o` under `g_o`
**as of the chain position established in P3**. The promotion is scoped twice over: it authorizes
device-attributed statements — not spending, and nothing about anti-clone — and it is relative to a
position, not to the present. See the next section, which is a limitation of the predicate rather
than a caveat on it.

### What P0–P6 prove, and what they cannot

The predicate proves **descent**: this root is authentically descended from `g_o`, this `d_o` is in
it, and this `AK_pk` recomputes it. It does **not** prove **frontier**: that no newer authentic
delegation or root exists.

Immutable publication does not close that gap. Area 4 defeats *poisoning* — garbage becomes an
unreferenced object instead of owning `/latest` — but it says nothing about *withholding*. A
verifier shown a truthful prefix of the chain cannot distinguish it from the whole chain, so
"currently applicable" is not a property a presented chain can carry. The word is avoided
throughout this document for that reason.

The consequence for Part 2 is direct and must not be glossed: **activation makes supersession
enforceable relative to a chain the verifier holds, and therefore does not by itself revoke a
compromised delegate against a stranger.** A stranger who never learns of `D_{n+1}` keeps accepting
`D_n`'s transitions, and nothing in the presented material tells them to look further. Revocation
against strangers requires frontier semantics, full stop.

Two ways to make the question well-posed, and this document adopts the first:

- **Bound verification (adopted now).** The consumer names the exact authority and chain position it
  wants verified, and the predicate answers a closed question: *was `AK_pk` authorized for `d_o`
  under `g_o` at this position?* That has a definite answer from the presented material alone, with
  no freshness assumption anywhere.

  **The consumer-side half of this does not exist yet, and must not be assumed.** Bound
  verification only closes the question if the position is *committed by the owner*, and nothing in
  SoFi commits one today. `VaultStateAnchorV2` binds
  `(vault_id, generation, parent_state_commitment, reserves_digest, storage_set_id, q)` — no Device
  Tree authority position anywhere in it. Nor does `V_n.r_o` supply one: Rev 15 names it "the
  authenticated owner root" exactly once (spec:483-493) and never defines it further — it is
  certainly not equated to a Genesis Device Tree transition position, and assuming it is would be
  reading a resolution procedure into a phrase the specification does not give one for.

  So the dependency is explicit: **before the five SoFi composition sites resume, some canonical
  owner-authenticated SoFi artifact must bind the exact Device Tree authority position against
  which `AK_pk` is verified.** Which artifact, and its encoding, are deliberately deferred.
  `VaultStateAnchorV2` as specified **must not be treated as already carrying that fact**. Without
  this, an implementation would verify against whatever identity chain it happened to fetch — which
  is the frontier problem walking back in through the consumer side after being closed on the
  verifier side.
- **Authenticated frontier (deferred, and required before revocation means anything to a
  stranger).** An explicit freshness construct with stated semantics — what it asserts, what
  refreshes it, and what an absent or stale frontier obliges a verifier to do. It is deferred
  because it is a design in its own right, not because it is optional: any use of supersession as
  revocation is blocked on it.

Until a frontier exists, an implementation must not present bound verification as currency, and
must not name any API in a way that implies it ("latest", "current", "resolve").

### Why the order is normative

A verifier that runs P5 before P2 has proven only that a presented triple is internally consistent
— anyone can generate a keypair and a 32-byte value whose hash matches a leaf they also chose. A
verifier that runs P4 against a root it has not authenticated has proven membership in a tree the
attacker supplied. Each step's authority comes from a strictly earlier step, and P0 depends on
nothing. That induction is the correctness argument, and it should be written down as such rather
than left implicit in call order.

The P1/P2 split is the sharpest instance and the easiest to lose. Activation ordering *looks* like
a delegation property — it is written in the delegation object — but it is a claim about transition
positions, so evaluating it in P1 would have P1 consuming exactly the material P2 exists to
authenticate. P1 therefore records activation and evaluates nothing; the check lands in P2, where
the chain to evaluate it against exists. A predicate that reads correctly stage by stage can still
be circular across stages, which is the failure mode this document has now hit twice.

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
and the route is unauthenticated. **One anonymous PUT at `i64::MAX` locks a genesis's device-tree
slot indefinitely under the current API**: every genuine update afterwards is refused with 409, and
the API exposes no reset — recovery would require operator intervention or reprovision, neither of
which is a protocol path. That is a live denial of service today, independent of the authority
question, and signing the payload does not fix it: the node would still be ordering by a field it
cannot verify.

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
4. **Version binding.** The same mnemonic, network and wallet index under `genesis_version` 3 and 4
   must produce different GRK keypairs.
5. **Ordering enforcement.** P4-before-P2 and P5-before-P2 orderings must be unreachable — a test
   that presents a valid inclusion proof under an *unauthenticated* root must be refused.
6. **Delegation fork refusal.** Two delegations at the same number, both validly GRK-signed, must
   produce a refusal and never a selection.
7. **Transition fork refusal.** Two transitions consuming the same authenticated predecessor, both
   validly signed under a properly applicable delegation, must produce a refusal — specifically,
   the higher `version_number` must **not** win.
8. **Supersession is enforced, not declared.** After `act(D_{n+1})` enters a transition's ancestry,
   a further transition bound to `D_n` must be refused *even though `D_n` is validly GRK-signed and
   on the authenticated chain*. This is the test that would have caught the defect this rule fixes,
   so it is the one that must not be skipped.
9. **Retroactive activation refusal.** A delegation whose activation is at or before its
   predecessor's must be refused rather than honoured as history retraction.
10. **Unresolvable activation never applies.** A `D_{n+1}` whose `activation_transition_digest`
    names a nonexistent or unauthenticated transition must not become applicable to any transition,
    and must not retire `D_n`.
11. **Inactivity cascades.** If `act(D_{n+1})` is unresolved, `D_{n+2}` must not become applicable
    **even when `act(D_{n+2})` resolves to an authenticated transition** — the skipped edge was
    never proven, so the lineage is not constructible. The delegation objects stay valid; only
    their activation is blocked.
12. **No self-activation.** The transition named by `act(D_{n+1})` must verify under `D_n`, and a
    version of it signed by `D_{n+1}` must be refused — proper ancestry asserted mechanically, not
    inferred from the word "after".
13. **Stage isolation.** P1 must be unable to consult transition material at all — enforce
    structurally (P1 takes no transition input) so activation ordering cannot drift back into it.
    This is the obligation that keeps the ordering property from silently regressing.
14. **Role isolation.** A GRK signature over a non-delegation preimage must not verify in any other
    context; a delegated-key signature over a non-transition preimage likewise.
15. **No implied frontier.** A verifier handed a truthful *prefix* of the chain must return a
    position-scoped result, never a "current" one — asserted against the API surface, since this is
    the failure that hides in naming rather than in logic.
16. **Mutation controls.** Each gate above disabled in turn must turn its test red, per the standing
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
- **which owner-authenticated SoFi artifact binds the Device Tree authority position** a trader
  verifies against, and its encoding — see Part 3. `VaultStateAnchorV2` does not carry it today;
- resumption of the five `compose_vault_state` call sites.

Three questions this design does not answer:

- **Authenticated frontier and freshness semantics.** A **blocking dependency for
  revocation-against-strangers specifically** — not a general blocker, and in particular **not on
  the SoFi path**, which proceeds on position-bound verification once the owner-authenticated
  position commitment exists. What it gates is any feature that relies on supersession having
  effect for a verifier who has not been shown the superseding material. Must state what the
  frontier asserts, what refreshes it, and what an absent or stale one obliges a verifier to do.
  Until it exists, verification is bound to a named position and no API may imply currency.
- **Rollback of roots signed by a compromised delegate.** Supersession changes who signs next; it
  does not retract history. Retracting an append-only monotone chain is a substantive decision with
  its own failure modes. Note this is now cleanly separable: activation handles *forward* authority,
  so rollback is genuinely only about the past.
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

The authenticated frontier is **not** on this path, and deliberately so: SoFi needs bound
verification against a position the owner committed, which P0–P6 delivers without any freshness
assumption. The frontier gates a different capability — revoking a delegate against strangers — and
must land before any feature depends on supersession having that effect.

The five composition call sites stay paused throughout, and now on **two** preconditions rather than
one: P6 must be dischargeable, and some owner-authenticated SoFi artifact must commit the authority
position to discharge it *against*. Satisfying only the first would leave a verifier checking a
position nobody claimed.
