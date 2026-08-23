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

**Two classes of claim, kept apart.** Everything above is *durable*: `d0bd5d0d`, `5efc1d3a` and the
blob `726e7372` are fixed points, and a sentence about them is true forever. A sentence about the
*current* head of a mutable path is a different kind of claim — it is true when written and false
after the next legitimate edit. This report therefore states no current-head value anywhere. To
obtain one, compute it:

```bash
git hash-object .github/instructions/sofispecs.instructions.md
```

An earlier revision embedded a current-head assertion in this otherwise historical artifact, and it
went stale exactly as that predicts.

### Amendments since the freeze

The mechanism above has fired repeatedly, as designed; the passes it caught are recorded below and
that list, not a count, is the register.

`10c28699abc9138ce6a17827d6d1e118f666b321` is **the blob this report observed** when its amendment
passes were written. It is recorded as an observation, and deliberately not as a statement about the
current head — the specification has been amended since, including by the state-identity cut, and
any value written here would be stale again by the next amendment. What stays true is the
comparison: a spec blob differing from `10c28699` means normative text has moved since this report
last looked, which is precisely the detection the pin exists to provide.

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

**Encumbrance types, and a third symbol overload.** Amendment 2b's field tables were gated on
one question: the type of `e` in Def 9.1. Rev 15 answers it — Req 8.2 reads
`∑_{e ∈ E_t} amount(e) ≤ R_t`, iterating `E` and calling `amount(e)`, so lowercase `e` ranges
over individual claims. Def 9.1's `e` is therefore the claim an allocation consumes, not the
vault's commitment.

That exposed `E` as overloaded exactly like `X` and `A_B` before it: Def 4.1 lists it as a set
member of `V_n` and Req 8.2 iterates it, while §8 also defined `E = H(DSM/enc ‖ …)` as a
digest. The set keeps `E`; the digest becomes `EC_v`. **Three overloads in one specification
is a pattern rather than three slips** — each was a container and its commitment sharing a
name, and each stayed invisible until a field table forced the question.

`{EC_v}` is neither an alias of `e` nor implied by `p_v`: `p_v` commits the **parent** state
commitment and the current reserves digest, but not the current generation's encumbrance set.
A plain set suffices rather than a keyed map, because `vault_id` sits inside every `EC_v`
preimage. §9.3's route commitment becomes `X = H(DSM/route-set ‖ CCB(Q))` over the
`RouteCommitmentBody`.

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
| 7 | Canonical commit bytes | **Underspecified protocol-wide — prerequisite to 1–6; 13 of 21 live classes now specified** |
| 8 | Authenticated owner-device identity resolution | **Absent, security-critical prerequisite — three broken edges; one trust anchor actively unauthenticated** |

Two areas reverse decisions that are currently documented as deliberate in landed code. They
are called out in **Reversals of landed decisions** below so that neither is made silently.

Area 7 was found while preparing the Anchor V2 work and is a **prerequisite**, not a peer:
it determines whether two independent implementations can agree on the inputs to the rest of
Rev 15 at all. It blocks Anchor V2.

Area 8 was found the same way and is also a prerequisite rather than a peer, but it sits one
layer above area 7. Area 7 asks whether two independent implementations can agree on the
**bytes**. Area 8 asks whether a foreign verifier can establish **who is authorized to produce
them**. The two are independent: a complete CCB registry does not make an unauthenticated owner
key authentic, and an authenticated owner key does not make ambiguous bytes canonical. Area 8
blocks the end-to-end trader-side market path.

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

**See also area 8.** The same failure shape — a mutable discovery path treated as authoritative,
against §15.2 item 7 — appears there on `devtree/root`, and the migration this area describes is
the pattern area 8's publication form will have to follow. The consequences differ in kind: a
mutable `/latest` path can cause consumers to misidentify **state**, while area 8's mutable root
can cause them to misidentify **authority**. In neither case is mutability itself the defect;
making the mutable index authoritative is.

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

## 8. Authenticated owner-device identity resolution

Found while preparing the Anchor V2 work. It presented as a narrow question — which key source
`compose_vault_state` should use — and is not one. A foreign trader has no constructible chain
from a vault it discovers to an authenticated owner-device authority, and one of the would-be
trust anchors is actively unauthenticated. This is a substrate defect that SoFi exposes, not a
SoFi gap.

**Rev 15.** Definition 4.1 (spec:483-493) makes `g_o` and `d_o` members of the vault state tuple
`V_n`, "where `g_o` and `d_o` bind owner identity", alongside `r_o`, "the authenticated owner
root". Those three are the specification's entire treatment of the subject: `r_o` is named once
and never defined, and the words *Device Tree*, *DevID* and *device identity* do not occur in the
document at all. Rev 15 therefore states that owner identity is bound into the state without
saying how a verifier resolves or authenticates it.

**Boundary against area 7.** These are not area 7 findings and area 8 does not reopen the CCB
registry. The `CCB(V_n)` schema and encoder can be **completed** once the fifteen members and
their encodings are fixed. What cannot be completed is **foreign verification of the authority
and provenance of `g_o`, `d_o` and `r_o`** — a question that lives above the byte-encoding layer.

### The chain, and its three broken edges

A foreign verifier needs the composed chain
`g_o → R_G → d_o ∈ R_G → d_o = H(AK_pk ‖ AttA) → AK_pk is owner authority`.
Every edge of it is broken, in three distinct ways.

**Edge 1 — `AK_pk + AttA → d_o`: construction exists, presentation material absent.**
`DevID = H("DSM/devid" ‖ AK_pk ‖ AttA)` is implemented and correct
(`dsm/src/core/identity/genesis_v2.rs:157-163`). `AttA` is
`KDF(wallet_seed, "DSM/atta/v2" ‖ G ‖ device_slot)` (`genesis_v2.rs:165-176`) — deliberately a
wallet-seed derivation so `DevID` survives mnemonic recovery, and consequently **not derivable by
anyone else**. It appears in no proto message and in no published object. The derivation is
therefore never exercised against foreign material: `derive_devid` occurs three times in the tree
— its definition (`:158`), the device deriving its own id inside `derive_genesis_v2` (`:242`), and
one test assertion (`:311`). **No verifier anywhere recomputes another device's `d_o`.**

**Edge 2 — `d_o → R_G`: the inclusion primitive exists, the applicable root is not
authenticated.** The tree is real: domain-separated `DSM/dev-leaf` / `DSM/dev-merkle` hashing
(`dsm/src/common/domain_tags/dsm/core.rs:94-95`), a portable `DeviceInclusionProofV1`
(`proto/dsm_app.proto:3750-3756`) that the node **rebuilds deterministically on every GET and
never accepts from a caller** (`dsm_storage_node/src/api/identity/devtree.rs:301-304`). But the
leaf commits a 32-byte identifier and nothing else — `DeviceTreeStateV1` carries `device_ids`
only (`proto/dsm_app.proto:3813-3816`), with no `AK_pk` and no `AttA` — so inclusion proves
membership of an identifier and yields no key. And the root it proves membership against is
whatever last survived the bounded validator, which is edge 3.

**Edge 3 — `g_o → R_G`: no independently authenticated root-progression edge has been
established.** `PUT /api/v2/identity/{genesis}/devtree/root` accepts any well-formed,
version-monotonic `DeviceTreeStateV1` for any genesis. Its validator is bounded by design and
says so: it "does **not** verify Merkle structure, signatures, or DevID derivation — those are
client-side concerns" (`devtree.rs:16-17`), running only decode, a 32-byte non-zero root, a
device-count/length check, and an atomic monotonic-version upsert (`devtree.rs:206-295`). The
route is mounted with a rate limiter and no auth middleware (`dsm_storage_node/src/main.rs:230`),
in the same file where the object-write router is wrapped in `auth::device_auth` (`:216-220`) —
so the omission is a property of this route, not of the server. The one field designed to carry
root authority, `DeviceTreeRootUpdateV1.signature`, is documented as deferred — verification "is
out of scope for B.1 and lands with the bounded-validator work in Phase B.4 (issue #275) once
`RootBindingRecord` is in place" (`proto/dsm_app.proto:3722-3737`) — and `RootBindingRecord`
occurs nowhere but that comment and its generated TypeScript mirror. `DeviceTreeRootUpdateV1`
itself is constructed only in `dsm/tests/device_tree_root_lifecycle_test.rs`. Nothing in
production produces or verifies a root-update authorization.

### Subfinding: the device registry is discovery, not authority

The existing device-identity lookup does not close edge 1 and cannot be made to.
`GET /api/v2/device/{device_id}` returns the stored `(genesis_hash, pubkey, kyber_public_key,
kyber_binding_sig)` row and describes itself accurately: "Storage nodes remain dumb indexers:
this is a raw identity lookup only" (`dsm_storage_node/src/api/identity/device_api.rs:167-190`).
The row is written by `POST /api/v2/device/register`, which validates lengths and presence only
and is first-writer-wins (`device_api.rs:75-150`). Client-side,
`fetch_quorum_device_identity` reads that row from every configured endpoint and requires the
mirrors to agree (`dsm_sdk/src/handlers/app_router_impl.rs:3101-3216`) — which establishes
agreement about a **record**, not a proof about a **key**. It never checks
`d_o = H(AK_pk ‖ AttA)`; nothing does. The only signature in the row is `kyber_binding_sig`,
which binds an ML-KEM key to an AK (`dsm_sdk/src/sdk/kyber_identity.rs:35-82`) and says nothing
about whether that AK belongs to `d_o`.

Stated as the finding: **the apparent genesis/device birth binding does not currently establish
`d_o → AK_pk` for a foreign verifier, because its key source ultimately resolves through an
unauthenticated device-registry row and does not independently verify
`d_o = H(AK_pk ‖ AttA)`. It therefore cannot serve as the missing non-circular trust root.**

Mutable discovery paths may *locate* candidate `AK_pk` bytes. Those bytes become authoritative
only after the DSM identity proof chain independently authenticates them.

### Confirmed impact

The unauthenticated `device_id → AK_pk` lookup is already load-bearing in at least two places.

- **SoFi trader-side foreign-vault owner authentication** — the subject of this area.
- **Recovery/authority-anchor verification.** `dsm/src/recovery/authority_anchor.rs:19-23`
  documents its genesis binding as a signature by the device's genesis signing key, "which IS
  genesis-authenticated and fetchable by peers via the device-tree quorum path
  (`fetch_quorum_device_identity` + `verify_device_tree_evidence_quorum`)". That is the same
  registry path. The asserted genesis/device binding therefore inherits the same
  unauthenticated-key dependency.

The identical assumption is restated once more at `dsm_sdk/src/sdk/kyber_identity.rs:86-88`,
where a peer's AK is described as "already trusted via the registry attestation that binds it to
`device_id` + `genesis`".

Recorded as confirmed impact of area 8. **Recovery-specific remediation is outside this area's
implementation scope, and this area is not a recovery conformance audit.**

### Already conformant, do not regress

The primitives underneath are sound and none of them is the defect. The Merkle tree and its
leaf/pad domain separation; the node-rebuilt, never caller-supplied inclusion proof; the
bind-once-per-genesis recovery-authority anchor store, which exists precisely so "a later
device-holding attacker cannot overwrite a legitimately-enrolled authority"
(`dsm_storage_node/src/api/identity/recovery_anchor.rs:14-21`); and the append-only PD-SMT head
chain, which enforces chain shape and derives `head_hash` itself so "a client cannot lie about
chain links" (`dsm_storage_node/src/api/identity/pdsmt_head.rs:12-15`). What is missing is the
authority edge above them.

**Verdict: absent, security-critical prerequisite.**

### Required property, not a mechanism

A foreign verifier must be able to start from `g_o`, authenticate the current or applicable
Device Tree root, prove `d_o` is in that tree, recompute `d_o` from independently presented
`AK_pk` and `AttA`, and only then treat that `AK_pk` as owner authority. Mutable discovery paths
may locate those objects; they cannot themselves be the authority.

**This finding deliberately does not solve the `R_G` authentication mechanism.** Choosing one
here would be choosing it from convenience, and the obvious choice is circular: signing `R_G`
with a device key whose legitimacy is established only by that same `R_G` proves nothing. What
genesis-authenticated authority actually exists, and whether any of it can authorize Device Tree
root progression without circularity, is audited in
[`docs/audits/2026-08-22-owner-device-identity-authority.md`](../audits/2026-08-22-owner-device-identity-authority.md).
The required semantics of the presentation path are scoped in
[`docs/plans/2026-08-22-device-identity-presentation-semantics.md`](../plans/2026-08-22-device-identity-presentation-semantics.md),
which is gated on that audit's answer.

### Standing constraint on `compose_vault_state`

The composition boundary stays exactly where it is. `compose_vault_state`
(`dsm_sdk/src/sdk/vault_state_composition.rs:259-266`) today authenticates key *continuity* — the
seq-0 birth anchor must verify and carry the same `owner_public_key` and `storage_set_id` as the
baseline (`:367-386`) — which is a real and worthwhile check, and is not owner authority: the key
it pins is self-attested inside the anchor it validates.

`baseline.owner_public_key`, routing-advertisement keys and identity-endpoint keys **must not be
threaded through as a temporary shim**. The five production call sites
(`handlers/dlv_routes.rs:1812,2067,2493,4894`; `handlers/route_routes.rs:856`) are paused, not
adapted. The reason is that a shim does not fail visibly: it would make an unauthenticated key
indistinguishable from a resolved one at every call site downstream of it, and each of those sites
would then encode the assumption that identity resolution had already happened.

**Cost.** Large and substrate-wide. Not estimable until the `g_o → R_G` edge exists, because the
shape of everything above it depends on what that edge turns out to be.

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
7. **Area 8, the identity-resolution prerequisite.** Sequenced last in this list only because
   its own first step is an audit rather than an implementation; see below for what it blocks
   and what it does not.

**What area 8 blocks: the end-to-end trader-side market path.** The blocked edge is
**foreign-vault composition and parent authentication** — a trader cannot establish that the V2
anchor and the `V_n` facts it composes against came from the actual DLV owner. That is the whole
of the dependency, and it must not be overstated into area 5's subject matter: a conformant
`TraderSettlementAcceptanceV2` proves the **trader's** ordinary DSM accepted successor
`(C_T^+, σ_T^+)`. That is trader authority, not owner authority, and area 8 does not change what
the acceptance witness authenticates. Area 5 remains sequenced on the SettlementBundle identity
from step 4; area 8 blocks the path those two sit on, end to end.

**What area 8 does not block.** Steps 1, 2 and 3 — the `q` rule, Anchor V2's encoder, and area
4's immutable namespace — all proceed. Area 8 sits above the byte-encoding layer: the
`CCB(V_n)` schema and encoder can be **completed** once the fifteen members and their encodings
are fixed. What cannot be completed is foreign verification of the authority and provenance of
`g_o`, `d_o` and `r_o`.

**Area 8's own first step is not an implementation.** It is the audit of what
genesis-authenticated authority exists that could authorize Device Tree root progression without
circularity. Until that edge is specified, the presentation object, its resolver, its immutable
publication form and any wire schema stay undefined, and the five composition call sites stay
paused rather than shimmed.

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

### Area 8

Area 8's code citations were read at `fbf1d1ba` rather than at the pinned `d0bd5d0d`. That is
safe here and the check is recorded rather than assumed: every file area 8 cites is
byte-identical at the two commits, so its citations resolve at the report's baseline as well.
Re-run the check before amending area 8:

```bash
for f in dsm_client/deterministic_state_machine/dsm/src/core/identity/genesis_v2.rs \
         dsm_client/deterministic_state_machine/dsm/src/recovery/authority_anchor.rs \
         dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/app_router_impl.rs \
         dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/kyber_identity.rs \
         dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/vault_state_composition.rs \
         dsm_storage_node/src/api/identity/devtree.rs \
         dsm_storage_node/src/api/identity/device_api.rs \
         dsm_storage_node/src/main.rs proto/dsm_app.proto; do
  [ "$(git rev-parse d0bd5d0d:$f)" = "$(git rev-parse HEAD:$f)" ] && echo "SAME $f" || echo "DIFF $f"
done
```

The load-bearing negatives, which are the finding rather than decoration:

```bash
git grep -n 'derive_devid' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
# 3 hits, all in genesis_v2.rs: the definition (:158), the device deriving its OWN id (:242),
# and one test (:311). No verifier recomputes a foreign d_o.

git grep -nw 'atta\|AttA' -- 'proto/*'          # zero — AttA is in no wire object

git grep -ln 'RootBindingRecord' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
# proto/dsm_app.proto and its generated TS mirror only — a comment, no message, no code

git grep -ln 'DeviceTreeRootUpdateV1' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
# proto, its generated TS mirror, and dsm/tests/device_tree_root_lifecycle_test.rs — never
# produced or verified in production
```

`git grep -n 'atta'` without `-w` is noisy and must not be used for this claim: it matches
*attacker*, *attach* and *attested* throughout the proto. The word-boundary form is the check.

The absence of the subject from Rev 15 itself resolves against the current spec blob
`10c28699`:

```bash
grep -c 'Device Tree\|DevID\|device identity' .github/instructions/sofispecs.instructions.md   # 0
grep -n 'authenticated owner root' .github/instructions/sofispecs.instructions.md              # one hit
```
