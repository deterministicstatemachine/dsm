# SoFi Revision 15 conformance delta

Architecture diff of the landed DLV close stack against Revision 15. This report changes no
code. It exists so that the schema-v5 reprovision, the fleet redeploy and the invariant-4
hardware proof are planned against structures that are not about to move — and because
Req 6.6 mandates a clean cut rather than a dual-read path, so the schema bump is downstream
of this delta by the specification's own rule.

## Baselines

Two commits are pinned, because the code boundary and the specification boundary are one
commit apart.

| Baseline | Commit | Fixes |
|---|---|---|
| Implementation | `d0bd5d0d` | the landed #676–#681 code under comparison |
| Normative specification | `5efc1d3a` | the Rev 15 text compared against |

Specification path and blob:
`.github/instructions/sofispecs.instructions.md` @ `726e737254de92900b8e81518bfd840bf7c8076a`

`5efc1d3a` is the direct child of `d0bd5d0d` and is spec-only: it touches two instruction
files and no code, replacing that path's blob (`3800fead` → `726e7372`) and deleting the
superseded `sofi.instructions.md`.

**At `d0bd5d0d` that path is a transcript, not the specification.** Any citation of
normative text at the implementation SHA is historically false and will not reproduce. Spec
citations in this report therefore resolve at `5efc1d3a`; code citations resolve at
`d0bd5d0d`.

Recording the blob hash means a later revision landing on that path is detected rather than
silently absorbed.

### Amendments since the freeze

The mechanism above has fired four times, as designed. The spec blob is now
`12c69d4cc95c23a80e7aaa74b7b893773c42004c`.

**`parent_state_commitment` recurrence and genesis rule.** Rev 15 named
`parent_state_commitment` in three places — Def 6.4, the settlement resource key of Def 6.17,
and the trader fence of Req 6.23 — but never gave its construction; Req 6.5 constrained only
its property. Def 4.1 already supplied the missing pieces, defining `h_n` as "the local parent
commitment" and `c_n = H(DSM/vault-state ‖ Canon(V_n))`, without ever relating them. The
amendment states the recurrence:

```
h_0 = H(DSM/vault-state-parent/genesis/v2 ‖ vault_id)
h_n = c_{n-1}                                        for n > 0
```

and records that `parent_state_commitment` is exactly that `h_n`.

This resolves an underspecification in the normative authority rather than in Rust, which is
the point: a construction chosen only in the implementation would have been indistinguishable
from one the specification required. **None of the six findings below changes** — the
amendment fixes what Anchor V2 must build, not whether the current anchor diverges.

**Fulfillment mechanism de-duplication, and the shape of `P_M`.** Def 5.2 committed
`Canon(P_M)` and had `B_M` commit the fee policy and "storage-set settlement parameters" —
but `P_M`, `Φ`, `S` and `q` are all members of `V_0` under Def 4.1, and `c_0` commits the
complete canonical `V_0`. The mechanism therefore already committed every one of them
transitively, and the second copies were aliases rather than bindings. Def 5.2 now reads

```
M = H(DSM/fulfillment ‖ vault_id ‖ c_0 ‖ CCB(B_M))
```

with `B_M` narrowed to the invariant, the per-transition size ceiling, and the authorized
encumbrance purposes. `V_n` is the single value source for `P_M`, `Φ`, `S` and `q`. The
reason is structural rather than aesthetic: two authoritative copies of one fact create states
that encode validly while disagreeing internally, and no equality rule can be enforced by a
verifier holding only one of the two objects.

The same amendment fixes the *shape* of `P_M` — a birth-time versioned descriptor
`(family_id, family_version, evaluation_budget, family_parameters)`, explicitly not a Def 7.1
Smart Commitment, since `Δ_in`, `Δ_out` and the intent bounds are transaction-time values that
do not exist when `P_M` is committed. It deliberately does **not** name the beta market
family: Rev 15 never uses the phrase "constant product", and naming a family is a normative
economic decision requiring its invariant and exact §3.4 arithmetic. Until that lands, `P_M`
has a shape and no admissible member.

**The beta market family, `Φ`, and an exact-rational allowance in §3.4.** The family is now
named: `CONSTANT_PRODUCT_EXACT_INPUT` version 1, parameterised by the canonical token pair, with
`Φ = FeePolicyV1{fee_bps: u32}` under `0 ≤ fee_bps < 10_000`. §3.4 gained an allowance for exact
versioned rationals with a fixed denominator, because `fee_bps/10_000` converted to scale 2³²
would introduce a rounding stage with no protocol meaning.

The pricing rule is stated as the fused expression
`output = floor(y·a·(D−f) / (x·D + a·(D−f)))` with **one** floor division, and the text forbids
computing a rounded fee-adjusted input first — two implementations disagreeing about that second
rounding produce different outputs from identical inputs. That is not a contrived corner: at
`a=1, x=1, y=3` the fused rule yields 1 and the doubly-rounded variant yields 0, and a brute-force
sweep of small reserves finds tens of thousands of divergent cases — precisely the region a
low-liquidity vault operates in. The successor credits the **full**
input, `R'_in = R_in + a`, with the fee remaining in reserves as LP yield.

Acceptance is equality with the recomputed successor. The nondecreasing product
`R'_in·R'_out ≥ R_in·R_out` is recorded as a consequence and explicitly barred from serving as
the acceptance condition, since many successors far worse for the trader also satisfy it.

Two aliases were removed in the same pass: `B_M` no longer carries the invariant, which
`family_id` now names, and `evaluation_budget` is a family-version constant rather than an
owner-configurable field — otherwise two implementations could agree on every byte while
disagreeing on whether evaluation exhausted its allowance.

This formalizes implementation behaviour verified at `routing_path_sdk.rs:125-155`, **not** the
stale prose at `proto/dsm_app.proto:202`, which says `reserve_in += input_after_fee` while the
reserve semantics and their test credit the full input.

Rev 15 identity was verified by content markers, not by the title: the "Revision 15" running
head; the domains `DSM/vault-state-anchor/v2`, `DSM/trader-settlement-acceptance/v2`,
`DSM/binding-tx`, `DSM/binding-keyset`; Req 6.6's clean `VaultStateAnchorV2` cut; Req 6.13's
five-member `q=4` profile; the `(C_T^+, σ_T^+)` acceptance artifact with the
bound-but-unrealized market state; and Req 6.30's one-phase owner-local close rule.

Two surviving in-repo files are numbering false positives; cite neither.
`recovery-and-dlv.instructions.md` has a §6.5/§6.6 ("Recovery Intent",
"Mnemonic-Authorized Tombstone Proposal") and `whitepaper.instructions.md` has a §15.2/§15.5
("Local Predicates", "Bifurcation Resistance"). Untracked `~/Documents/sofi-revision-*.tex`
and `SoFi-V2.pdf` are drafting artifacts.

## Summary

| # | Area | Verdict |
|---|---|---|
| 1 | Node semantics | Divergent — the endpoint is settlement-specific |
| 2 | Route-wide multi-key binding | Absent entirely |
| 3 | Committed storage-set / quorum profile | Divergent, safety-relevant |
| 4 | Immutable object vs mutable index | Divergent — two distinct violations |
| 5 | Trader acceptance realization | Partial, security-relevant — gate correctly placed, witness format non-conformant |
| 6 | One-phase owner-local close | Non-conformant in candidate completeness and realization boundary |
| 7 | Canonical commit bytes | **Underspecified protocol-wide — prerequisite to 1–6; 10 of 19 classes now specified** |

Two areas reverse decisions that are currently documented as deliberate in landed code. They
are called out in **Reversals of landed decisions** below so that neither is made silently.

Area 7 was found while preparing the Anchor V2 work and is a **prerequisite**, not a peer:
it determines whether two independent implementations can agree on the inputs to the rest of
Rev 15 at all. It blocks Anchor V2.

---

## 1. Node semantics

**Rev 15.** §15.2 (spec:1378-1379) lists what a Class N member must not do, including item 3,
"parse a SettlementBundle in order to decide whether storage should accept it", and item 4,
"determine the threshold q or count responses from other members". Req 15.7 (spec:1451)
confines the node to "schema version, round ordering, exact expected digest, and key-set
equality", with "the value payload addressed by the record remains opaque". §15.5
(spec:1419) opens "The node-side binding interface is application-blind."

**Current.** `dsm_storage_node/src/api/vault/settlement_slot.rs` decodes the
`SettlementSlotClaimV1` envelope server-side and verifies its SPHINCS+ signature
(`:107`), then reads domain fields — `vault_id`, `parent_sequence`, `x`,
`claimant_public_key`, `storage_set_id` — to enforce claimant attribution (`:117-119`) and
storage-set membership (`:125-127`). The module header concedes the point directly: for this
endpoint the "dumb indexer" description "is not accurate" (`:16`).

**Verdict: divergent.** The endpoint is settlement-specific in exactly the way §15.2(3) and
Req 15.7 forbid.

**Already conformant, do not regress.** The node never counts responses and never learns
`q`, satisfying §15.2(4) — `ClaimFanout` is documented "Never short-circuits; the caller
decides quorum" (`sdk/storage_node_sdk.rs:125`). Write-once is enforced in SQL,
`ON CONFLICT (vault_id, parent_sequence) DO NOTHING` (`db/pg.rs:815-819`,
`db/sqlite.rs:736-742`), with no update and no delete path.

**Cost.** Moderate-to-large. Replacing a domain endpoint with a generic one is mechanically
contained, but every client call site and the recovery path move with it, and the attribution
and set-membership checks the node performs today must be re-established client-side or
re-expressed as generic storage metadata under Req 15.7.

---

## 2. Route-wide multi-key binding

**Rev 15.** §15.5 (spec:1419) specifies `CompareExchangeMany(keys[], expected_digest,
replacement)` over "strictly sorted opaque resource keys". Req 15.6 (spec:1448):
"`CompareExchangeMany` is atomic only within one member: all named local keys change to the
replacement record or none do. It does not know q, does not contact peers, and does not
decide whether the caller has committed a SoFi trade."

**Current.** Absent. The register binds a single key, `(vault_id, parent_sequence)`, with no
expected-digest compare-and-exchange and no multi-key atomicity.

Symbol check at `d0bd5d0d` over `dsm_client/`, `dsm_storage_node/`, `proto/` —
`PutImmutable`, `CompareExchangeMany`, `IndexResolve`, `QuorumBind`, `keyset_digest`: zero
files each. Here the concept is genuinely absent, so the symbol check is sound evidence.

**Verdict: absent entirely.** This is the primitive multi-vault route atomicity rests on, so
its absence bounds what routing can correctly do today.

**Cost.** Large. New node-side transaction machinery, a new client primitive, and the
SettlementBundle identity that area 5 depends on.

---

## 3. Committed storage-set and quorum profile

**Rev 15.** Definition 6.4 (spec:647-659) fixes the parent binding as

```
p_v = H(DSM/vault-state-anchor/v2 ‖ vault_id ‖ generation ‖ parent_state_commitment
        ‖ reserves_digest ‖ storage_set_id ‖ q)
```

so **`q` is owner-committed inside the signed anchor**, alongside the parent state
commitment — which, per the amendment recorded above, is the local parent commitment `h_n`
of Def 4.1, chaining the canonical prior DLV state `c_{n-1}`. Req 6.5 (spec:660) requires the anchor to "bind the history commitment that
produced the advertised reserves, not only the vault identifier, local generation, and
reserves digest". Req 6.6 (spec:664) requires the history-bound `VaultStateAnchorV2` to use
"a new domain/schema" that "must not be silently accepted as the legacy anchor format or
vice versa", with "a schema bump and clean reprovision rather than a dual-read or fallback
path". Req 6.13 (spec:707) fixes the beta profile at `n=5, q=4`, justified by
`|Q1 ∩ Q2| ≥ 4 + 4 − 5 = 3`. Req 15.8 (spec:1457) requires Class K to "count only distinct
authenticated members of the exact owner-committed S".

**Current.** `dsm/src/dlv/vault_state_anchor.rs:96-109` signs

```
BLAKE3(DOMAIN_ANCHOR ‖ vault_id ‖ sequence_be ‖ reserves_digest ‖ storage_set_id)
```

with `DOMAIN_ANCHOR = b"DSM/vault-state-anchor\0"` (`:17`) — no `/v2`, no
`parent_state_commitment`, no `q`. The anchor carries no predecessor link of any kind;
`sequence` is a bare `u64`. The nearest history relation is external and two-point: the
composer separately fetches the seq-0 birth anchor and compares it to the baseline
(`sdk/vault_state_composition.rs:375-387`), leaving intermediate generations unchecked
against one another.

`q` is not committed anywhere. It is derived locally:

```rust
pub fn quorum_for(node_count: usize) -> u32 {
    if node_count == 0 { return 0; }
    (node_count as u32 / 2) + 1
}
```

(`storage/client_db/publication.rs:75-80`), surfaced once as `StorageSet::quorum()`
(`sdk/storage_set.rs:141-143`). No config key, environment variable or flag sets it.

**Verdict: divergent, safety-relevant.** Two consequences.

**At `n=5` the current rule yields `q=3`, not `4`.** Replicating the `u32` integer
arithmetic: `quorum_for(3) = 3/2+1 = 2`; `quorum_for(5) = 5/2+1 = 3`. Deploying five nodes
without changing the rule collapses the Req 6.13 intersection margin from ≥3 to ≥1. **Fleet
size alone does not deliver Req 6.13** — this must be fixed before, not during, the redeploy.

**Nothing detects disagreement.** What is signed is the member set, not the threshold. Two
clients with divergent `quorum_for` implementations would disagree today and no signature or
wire field would catch it.

**Cost.** Anchor schema change (large, and gates the reprovision by Req 6.6) plus a small,
sharply-scoped change to the quorum rule. The `q` change is cheap in lines and expensive in
consequence.

---

## 4. Immutable objects versus mutable indexes

**Rev 15.** §15.3 (spec:1403) defines `addr(P) = H(DSM/storage-object ‖ N ‖ H(N ‖ P))`.
Req 15.2 (spec:1406): "`PutImmutable(P)` must be idempotent for identical bytes. It must not
overwrite a different payload at the same canonical address." Req 15.3 (spec:1409): "Every
Class K consumer must re-hash returned bytes and compare the result with the requested
canonical address before decoding or verifying higher-level protocol content." §15.2 item 7
forbids a member from treating "a mutable discovery path as canonical object identity".

**Current.** Two separate divergences.

*The store enforces no immutability at all.* `upsert_object` is
`ON CONFLICT (key) DO UPDATE SET value = excluded.value, ...`
(`dsm_storage_node/src/db/sqlite.rs:1034-1036`). For every object key, last writer wins.
Write-once is a convention of the client's local freeze table, which the node does not share.

*Mutable paths are treated as identity.* `sofi/vault-state/{vault}/latest`
(`sdk/vault_state_anchor_codec.rs:78-81`) and `sofi/vault-state-inclusion/{vault}/latest`
(`sdk/vault_smt_inclusion_codec.rs:38-41`) are published and consumed as authoritative and
overwritten in place across generations.

**Verdict: divergent, two violations.**

**Already well-shaped.** The local `frozen_publication_artifact` table is keyed
`(object_key, content_digest)` and supersedes rather than overwrites
(`storage/client_db/frozen_publication_artifact.rs:31-35,161-166`), and the digest is derived
from the bytes with "no API that accepts a caller-supplied digest" (`:103`). The gap is the
node contract and the consumer's re-hash, not the client's bookkeeping.

**Cost.** Moderate. A write-once immutable namespace on the node, a canonical address
derivation shared by both sides, a consumer-side re-hash before decode, and a migration of
the `/latest` mirrors from identity to index.

---

## 5. Trader acceptance realization

**The realization gate already exists and is in the right causal place.** This section must
not be read as "the concept is missing".

**Rev 15.** Def 6.1(a) (spec:588) makes a market successor composable "only when its complete
SettlementBundle is binding-final under Definition 6.24 and the exact initiating trader
successor has a verified acceptance artifact `A_B` under Definition 6.26". Req 6.2
(spec:612): "a market quorum COMMIT without trader acceptance … has no effect on the reserve
cursor." Req 6.27 (spec:987) defines the bound-but-unrealized state and its consequences.

**Current — what already conforms.**

- The composer gates reserve folding on a verified receipt. A valid pending pointer with no
  verified receipt is inert: reserves and sequence do not fold, and the parent is recorded
  through `blocked_by_unreceipted_pointer_at_parent`
  (`sdk/vault_state_composition.rs:121,697`). Composition proceeds only once
  `fetch_verified_receipt` succeeds (`sdk/settlement_receipt_codec.rs:124`), the receipt
  commitment matches the pointer, and the sequence pair matches.
- Routing honours it: `handlers/route_routes.rs:894` drops the vault when the flag is set.
- Market settlement and close contend for the same parent through the same primitive.
  `claim_settlement_slot` is called from `handlers/route_routes.rs:1233` and
  `handlers/dlv_routes.rs:2750` on the market side, and `handlers/dlv_routes.rs:2249` and
  `:1863` for close, live and resume respectively. A market-first quorum claim therefore
  already prevents close from bypassing it.

So bound-but-unrealized behaviour exists in substance under the per-vault register.

**Current — the actual divergence: root provenance.**
`SignedTraderSettlementReceipt` signs

```
H("DSM/settlement-receipt-sign" ‖ vault_id ‖ receipt_id ‖ leaf_value
  ‖ trader_genesis ‖ trader_devid ‖ post_root)
```

(`dsm/src/dlv/settlement_receipt_leaf.rs:177-178`), carrying a trader-selected `post_root`
and a 256-sibling inclusion path (`:113-114`). The verifier establishes that bespoke
signature and Merkle inclusion under the root it was handed.

Rev 15 requires the ordinary DSM accepted-successor commitment `C_T^+` with the ordinary
successor-state authentication `σ_T^+` **directly over** `C_T^+`, where `C_T^+` itself
commits the post-advance root. It rules out precisely the current construction (spec:971-976):

> "A Merkle proof authenticates membership relative to a root; it does not authenticate the
> provenance of that root."

and

> "A constructor that merely possesses B can construct an arbitrary Merkle tree and inclusion
> path, but cannot satisfy Definition 6.26 without the valid ordinary DSM authentication
> σ_T^+."

Def 14.1 (spec:1292) fixes the artifact's content digest domain as
`DSM/trader-settlement-acceptance/v2`.

**Verdict: partial, security-relevant.** The gate fires at the right moment, but what it
accepts as proof does not authenticate `post_root` as the root committed by the accepted
ordinary DSM successor.

**Direction.** Upgrade the existing receipt/evidence path; do not reposition it and do not
build a parallel artifact. A conformant `TraderSettlementAcceptanceV2` must carry and verify
`(C_T^+, σ_T^+)` *and* match the exact SettlementBundle identity, route commitment, trader
parent/successor, and acceptance leaf/proof.

**Dependency.** Area 5 depends on the SettlementBundle identity machinery delivered with
area 2. The witness can be *specified* before `CompareExchangeMany` exists — multi-key CAS is
not cryptographically necessary to construct `A_B` — but matching an exact bundle identity
needs the bundle-id machinery that arrives with area 2, so the implementations sequence in
that order.

**Cost.** Moderate, concentrated in the receipt format and its verifier, plus the trader-side
production of `(C_T^+, σ_T^+)` from ordinary DSM advancement. The gate wiring is reusable.

---

## 6. One-phase owner-local close

**Rev 15.** Def 6.1(b) (spec:588) makes an owner release/close successor composable when its
candidate "is binding-final for the current DLV parent and the exact successor already
verifies under Requirement 4.6, the applicable token policy, conservation, and concrete owner
authority under Definition 5.1(a). It requires no trader-acceptance witness and no owner-side
post-binding acceptance artifact."

Req 4.6 (spec:526) requires the beta decision be decidable from "the authenticated current
DLV parent, the exact owner-signed release/close successor, the applicable token policy, and
canonical proof/bundle bytes that are complete before the first mutating binding step", and
that it "must not require a post-binding owner action".

Def 5.1(a) (spec:547-548) defines concrete owner authority as a witness containing
`Sign_owner(CCB(V_{n+1}))`.

Req 6.30 (spec:1042) states the realization rule: because the owner signature over the exact
release successor "is already present before binding begins, there is no sovereign second leg
left to accept. **Binding Finality therefore realizes that release/close successor at the
DLV.**"

**Current — what already conforms.** `dlv.close` is one-phase and owner-local: no
counterparty, no second leg, no trader witness, and the register serves as a serialization
primitive rather than a counterparty. Req 6.30's market-first rule is honoured in substance,
since close and market settlement contend for the same parent through the same
`claim_settlement_slot` primitive. The close also derives and signs an
`Operation::DlvClose` binding both reserve legs, exact amounts, parent and child generation,
fee and terminal economics, and freezes those signed bytes into the durable intent before the
claim (`handlers/dlv_routes.rs:2148-2235`). **That construction is sound and should be
preserved.**

**Current — non-conformance 1: candidate completeness.** A signed operation that
deterministically *describes* the future mutation is not the already-constructed,
owner-authenticated DLV successor that Req 4.6 and Def 5.1(a) require. The exact successor is
still constructed **after** the quorum claim, inside `commit_canonical_close`: that function
builds the `VaultReserveMutation::Withdraw` (`handlers/dlv_routes.rs:1615-1621`), runs
`execute_on_relationship_staged_with_reserve_mutation`, and only there commits the owner
balance credit and the zero-reserve successor.

**Current — non-conformance 2: realization boundary.** The code treats the claim as
reservation and the commit as realization, with the intent moving
`PreparedClose → ClaimPublished → CanonicalCloseCommitted`. Under Req 6.30 the close is
already realized at binding Finality, so a permanent failure at the commit step leaves local
state behind a truth any conforming verifier can already derive.

The cleanest test of both is recovery. `resume_close_intents` returns early when
`!can_sign()`, because "a locked wallet cannot sign the terminal proofs"
(`handlers/dlv_routes.rs:1754-1761`). Rev 15's one-phase rule is built so that after binding
Finality **no new owner material is needed at all**. A close that still requires signing
authority to finish has not realized at binding.

**Verdict: non-conformant in candidate completeness and realization boundary.**

**Direction.** Promote the existing pre-binding construction one level up. Before QuorumBind,
derive the exact release successor, authenticate it in the Rev 15 form, and freeze all
verification and proof bytes, then bind that candidate. Once COMMITTED, no new signing or
economic decision remains, and `commit_canonical_close` becomes purely local application of
an already-realized successor.

**Cost.** Moderate. The economics and the durable-intent discipline are already right; the
work is moving successor construction and authentication ahead of the claim and demoting the
commit to materialization.

---

## 7. Canonical commit bytes are underspecified protocol-wide

Found while preparing Anchor V2. This is a defect in the specification's serialization layer,
not a divergence between spec and code: it determines whether two independent implementations
can agree on the **inputs** to everything in areas 1–6.

Note on terminology: this is **canonical cross-implementation commitment encoding**, not
consensus encoding. DSM has no global consensus layer, and calling it that would import a
model the protocol does not have.

**Rev 15.** Req 3.1 (spec:438) defines generic CCB rules — fixed-width big-endian integers,
4-byte length-prefixed byte strings, "fields emitted in ascending declared field-number
order", explicit absence markers for optional fields, sets sorted lexicographically by element
CCB, sorted maps, no floating point, and "every CCB blob begins with an object-class
discriminant and CCB schema version". Req 3.2 adds that no two logical objects may share a
CCB encoding and no logical object may have two.

**The defect.** The rules require metadata the document never supplies.

- **No field number is declared for any object, anywhere.** The phrase `declared field`
  occurs exactly once in the specification — inside rule 3 itself.
- **No object-class discriminant ever takes a value**, and neither does any CCB schema
  version. Both appear only in rule 8's statement of the requirement.
- **The document contains two width mentions in total**: `4-byte`, for the CCB length prefix,
  and one `32-byte`. No state field has a declared width or type.
- `Canon(...)` is invoked **fifteen distinct ways and defined zero times** — `Canon(V_n)`,
  `Canon(S)`, `Canon(P_M)`, `Canon(B_M)`, `Canon(A_B)`, `Canon(R)`, `Canon(B)`,
  `Canon(TradeIntent)`, `Canon(TradeDigest)`, `Canon(x)`, `Canon(X)`, and the set forms.
  `CCB(...)` appears twice, both as references — `CCB(M)` and `CCB(V_{n+1})` — never as a
  definition.

Consequently `c_n`, the fulfillment mechanism `M`, `storage_set_id`, the acceptance digest
`a_B`, and the Def 6.17 settlement resource key are **all non-derivable from the
specification**. Req 3.2's uniqueness guarantee cannot be checked against anything, because
there is no encoding to check.

For the Def 4.1 state tuple specifically, **none of the fifteen members of
`V_n = (g_o, d_o, vault_id, n, R_A, R_B, P_M, P_R, Φ, E, β, h_n, r_o, S, q)` has a unique
normative representation.** `P_M`, `P_R`, `Φ`, `E` and `β` appear only as prose names in that
tuple; the scalars have no declared widths; `β`'s absence marker has no encoding; and the
nested objects have no CCB of their own to be nested by value or referenced by digest.

**The precedent is already live.** `storage_set_id = H(DSM/storage-set ‖ Canon(S))` ships
today, and `Canon(S)` was chosen **only in Rust**:

```
H(TAG ‖ 0x00 ‖ u32_be(count) ‖ for each id in lexicographic byte order: u32_be(len(id)) ‖ id)
```

(`sdk/storage_set.rs:51-86`). It is load-bearing across the trust boundary —
`dsm_storage_node/src/lib.rs:55` calls the client's `compute_storage_set_id` directly, so node
and client agree because they share one helper. That is implementation monoculture, not
protocol specification, and the agreement it produces would not survive a second
implementation. It is the concrete demonstration of what happens when a `Canon` is settled in
code, and the reason area 7 gates the rest.

**Verdict: underspecified protocol-wide; prerequisite to areas 1–6.**

**Direction.** A normative CCB object registry, landed before any Anchor V2 code, defining
once: object-class discriminants, CCB schema versions, primitive encodings, field numbering,
option encoding, set and map ordering, and nested-object treatment — then a concrete field
table per object covering every Rev 15 object whose `Canon(...)` result feeds a hash,
signature, storage address, resource key or authority check. At minimum `V_n`, `S`, `P_M`,
`P_R`, `B_M`, `E`, `TradeIntent`, the route and allocation structures, the SettlementBundle
`B`, and `A_B`.

Two constraints on that work.

*Sub-objects by digest is not a solution.* Inserting `P_M`, `P_R`, `Φ` or `E` as committed
digests looks bounded but relocates the ambiguity one layer down: "digest of which canonical
bytes?" is the same question again unless those preimages are themselves fully defined.

*Order is normative schema first, encoder second, vectors third.* The reference encoder must
not define the protocol by accident. Golden vectors are outputs of an already-defined schema,
not the source of truth — and they should be verified by an independent conformance
encoder/parser that does not call the production canonicalization helpers, so that a bug in
one implementation cannot bless itself.

The registry should **absorb the existing `storage_set_id` byte layout** as written rather
than silently changing it, unless the storage-set commitment is deliberately versioned in the
same change.

---

## Reversals of landed decisions

Recorded explicitly so neither is made silently.

**Owner-committed `q` reverses a documented invariant.**
`storage/client_db/frozen_publication_artifact.rs:40-41` states: "Quorum is always
`quorum_for(|S|)` over the resolved set — never a stored integer." The same claim appears at
`storage/client_db/mod.rs:497`. Rev 15's Def 6.4 puts `q` inside the signed anchor preimage.
This is not a gap to fill; it is a deliberate decision being reversed, and the code comments
asserting the old position must be updated in the same change rather than left contradicting
the new one.

**Realization at binding reverses the close's staging model.** The landed close is built
around claim-then-commit, with `ClaimPublished` as a genuine intermediate state and a resume
pass that re-signs terminal proofs. Rev 15 makes binding Finality the realization point.
`ClaimPublished` stops being "pending" and becomes "realized, not yet materialized" — a
different meaning for the same state, which the intent-table documentation must reflect.

---

## Implementation sequence

Ordered by dependency, not by size.

0. **Area 7, the CCB object registry.** Gates everything below that produces or verifies a
   commitment. Until it lands, `c_n`, `M`, `a_B` and the Def 6.17 resource key have no
   derivable bytes, so an implementation of steps 2, 4, 5 or 6 would be settling protocol in
   Rust. Normative schema, then reference encoder, then golden vectors — in that order.
1. **Area 3, `q` rule only.** Smallest change, largest immediate risk reduction, and a hard
   precondition of the fleet redeploy: at `n=5` the current rule silently yields `q=3`.
   Independent of step 0: it is an integer threshold, not an encoding. **Landed in #683.**
2. **Area 3, anchor V2. UNBLOCKED.** `parent_state_commitment` and `q` in a `/v2` domain.
   Gates the schema-v5 reprovision under Req 6.6's clean-cut rule. The normative prerequisites
   are complete: the lineage recurrence `h_n = c_{n-1}`, the beta market and release families,
   `Φ`, and `CCB(VaultStateV2)` are all specified. What stands between here and implementation
   is an encoder for `0x0001`, checked against an independent one — not another amendment.
3. **Area 4.** Immutable namespace, shared address derivation, consumer re-hash, `/latest`
   demoted from identity to index. Independent of 1–2 and can run in parallel.
4. **Area 1 + area 2 together.** The generic `CanonicalStorage` interface and
   `CompareExchangeMany` are one node-side change; splitting them would mean building the
   endpoint twice.
5. **Area 5.** Needs the SettlementBundle identity from step 4.
6. **Area 6.** Independent of 4–5 in principle, but sequenced last so the close is rebuilt
   once, against final anchor and binding semantics.

Downstream and gated on this delta being frozen: schema-v5 reprovision; canonical storage-set
fleet redeploy against the final schema and config contract; the invariant-4 hardware
withdrawal proof.

---

## Reproducing the citations

Spec citations resolve at `5efc1d3a`:

```bash
git show 5efc1d3a:.github/instructions/sofispecs.instructions.md | sed -n '660p'
```

The same path at `d0bd5d0d` returns a transcript, and any citation that resolves there is
wrong by construction.

Code citations resolve at `d0bd5d0d`:

```bash
git show d0bd5d0d:dsm_client/deterministic_state_machine/dsm/src/dlv/vault_state_anchor.rs | sed -n '96,109p'
```

Negative claims, scoped to what a symbol search can actually establish:

```bash
git grep -l 'PutImmutable\|CompareExchangeMany\|IndexResolve\|QuorumBind\|keyset_digest' \
  d0bd5d0d -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'   # zero files
git grep -l 'VaultStateAnchorV2' d0bd5d0d -- 'dsm_client/*' 'proto/*'   # zero files
```

For these the concept is genuinely absent, so the symbol check is sound evidence.

**`A_B` is a naming observation only, and is not evidence of semantic absence.** The
realization gate exists under other names — see area 5. The search is also noisy: at
`d0bd5d0d`, `git grep -lw A_B` matches six files, all of them GIF binaries where the bytes
occur by coincidence. The load-bearing negative for area 5 is instead that **no acceptance
object carries or verifies an ordinary `C_T^+` together with `σ_T^+` directly over it**,
which is checked against the receipt's signing preimage at
`dsm/src/dlv/settlement_receipt_leaf.rs:177-178` and its verifier, not by symbol search.

The `q` arithmetic is checked against the source rule rather than asserted: `quorum_for` is
`(node_count as u32 / 2) + 1` (`storage/client_db/publication.rs:75-80`), so `quorum_for(3)`
is 2 and `quorum_for(5)` is 3, against Req 6.13's required 4.
