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

Two areas reverse decisions that are currently documented as deliberate in landed code. They
are called out in **Reversals of landed decisions** below so that neither is made silently.

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
commitment. Req 6.5 (spec:660) requires the anchor to "bind the history commitment that
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

1. **Area 3, `q` rule only.** Smallest change, largest immediate risk reduction, and a hard
   precondition of the fleet redeploy: at `n=5` the current rule silently yields `q=3`.
2. **Area 3, anchor V2.** `parent_state_commitment` and `q` in a `/v2` domain. Gates the
   schema-v5 reprovision under Req 6.6's clean-cut rule.
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
