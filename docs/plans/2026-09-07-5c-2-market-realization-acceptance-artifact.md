# 5c-2 — Market realization: the trader-acceptance artifact `TA_B`

> ## STATUS 2026-09-09 — what the 2c-A.1 encoder cut falsified in this plan
>
> Required by amendment 2c-C4 §10. **The body below is NOT rewritten** — it is the plan as written
> on 2026-09-07, and rewriting it would destroy the record of what was decided when. Read it with
> these corrections applied. Each was checked against the tree at `main`, not inferred.
>
> | the plan says | now |
> |---|---|
> | `SettlementBundleV1` needs no schema change; field 8 holds `C_T^+` (:461) | **The proto message is deleted** (2c-A.1 ruling 13). `B` is the CCB object `0x000E`; the successor is `MarketTerms` field 5 |
> | use the existing proto field for recovery material (:745) | **`MarketTerms` field 6 is a mandatory nested `0x0031`** `DsmSuccessorEvidence`, strictly decoded and round-tripped — not a bytes field |
> | the transport is `repeated bytes proof_material` (:757) | `0x0010` `DlvProofMaterial` has **zero fields** and beta encodes `0x000F` field 3 absent, so it never appears on the wire (2c-A.1 ruling 6) |
> | `settlement_bundle::validate` only width-checks the two successor fields (:417) | **`validate` is deleted.** Strict decoders, a whole-bundle round trip, and the in-bundle structural checks replaced it (2c-A.1 rulings 8, 9) |
> | the bundle is bound at `dlv_routes.rs:3264` (:396) | **The market route now refuses before binding** (`dlv_routes.rs:3340`, "deployment-blocked until 5c-2 Step 2"). The ordering problem the line names is real and unchanged; the line number is not |
>
> **One flagged item was checked and is NOT stale.** A survey reported that
> `execute_on_relationship_staged` (`core_sdk.rs:1617`) does not exist. It does, at exactly that
> line. The plan's Step 3 guidance stands, and the claim is recorded here as refuted so nobody
> re-derives it.
>
> **What this plan still owes, unchanged by the cut:** Step 2/3 re-order the market producer so the
> trader successor and its evidence exist BEFORE binding, which is the only thing that lifts the
> emission refusal. Landing with it: 2c-B's deferred grammar and chain-tip conjuncts (`G1`–`G4` in
> 2c-C4 §2.1) and a regenerated market class-1 vector carrying genuine `operation_bytes` and a
> genuine `trader_successor`. **Nothing may fabricate those operands to make the current vector
> pass** (owner ruling, 2026-09-09).

> ## OPEN GATE — prove the ~50 KB owner-close bundle survives every real path
>
> A fully pinned owner-close `SettlementBundle` under 2c-A is **50,330 bytes**, almost entirely
> because `0x000F` field 4 carries a SPHINCS+ **SPX256f** signature of **49,856 bytes**
> (`dsm/src/crypto/sphincs.rs:19`, asserted `:1552`; `sphincs_sign` pins SPX256f at `:1152`).
> A market bundle has no such field and is far smaller.
>
> This does **not** invalidate 2c-A — carrying the exact owner authorization is the right design,
> and the size must not be reduced by weakening authorization semantics. But **owner-close
> implementation is not routine until every actual configured path is shown to carry it.** DSM has
> already hit an HTTP 413 once, so limits in this stack are real. The question is DSM's configured
> path, never generic web capacity.
>
> ```text
> owner-close CCB ~ 50,330 bytes
>         v  verify EVERY hop that actually carries B:
>     PutImmutable request/body limit
>     Class N immutable-object size limit
>     HTTP / reverse-proxy limit          (nginx default client_max_body_size is 1 MB)
>     client persistence / blob limit
>     recovery fetch path
>     BLE / USB / offline framing, IF B traverses it
>     q-replication batching limit
>     any Base32-Crockford encoding hop   (~1.6x -> ~80 KB on the wire)
> ```
>
> ### GATE RESULT — 2026-09-07: **PASS WITH DEPLOYMENT CONTROL OWED.** 10.4x margin at the
> repository and configuration level. Not architecture work; the residue is validation.
>
> ```text
> BINDING LIMIT   512 KiB = 524,288 B   device_auth body buffer
>                                       dsm_storage_node/src/auth/mod.rs:224-228
>                                       (hardcoded; http.body_limit_bytes cannot reach it)
> owner-close B        50,330 B   =  9.6% of the cap
> headroom            473,958 B   =  10.42x
> ```
>
> | hop | limit | verdict |
> |---|---|---|
> | `device_auth` body buffer (**binding**) | 524,288 | passes |
> | `RequestBodyLimitLayer` (outer) | 1,048,576 | passes |
> | `MAX_IMMUTABLE_PAYLOAD_BYTES` (inner) | 1,048,576 | passes |
> | reverse proxy | **none exists** — TLS terminates in-process, `8080` published directly | n/a |
> | Postgres `BYTEA` / SQLite `BLOB` | 1 GB / 1e9 | passes |
> | client HTTP put/fetch | no body, response or timeout cap configured | passes |
> | client persistence | bundle is **never** stored locally — fence table is 32-byte digests | n/a |
> | Class N binding register | **digests only** (~180 B regardless of bundle size) | n/a |
> | BLE / USB | **not traversed** by a settlement bundle | n/a |
> | q-replication | sequential per-member PUT; each measured alone, never aggregate | passes |
>
> **Two hypotheses tested and both negative — record them so they are not re-raised.**
> *Base32 inflation does not occur:* the body is raw `application/octet-stream`; Base32 Crockford is
> applied only to the 32-byte address (`storage_node_sdk.rs:832-833`). Wire size is 50,330, not
> ~80,530. *The register is not implicated:* `BindingRecord` is seven fixed-width fields
> (`dsm/src/storage/binding_record.rs:96-104`); the bundle is referenced by `value_addr` and never
> carried inline.
>
> **~50 KB is already routine on this exact path.** The close flow persists and PUTs two comparable
> objects *before* the bundle exists: `dlv_close_intent.op_bytes` (the signed `Operation::DlvClose`,
> embedding a 49,856-byte signature) and `pointer_bytes` (`VaultPendingPointerV1` with its own
> publisher signature), the latter HTTP-PUT to every node (`dlv_routes.rs:2621-2666`).
>
> **The prior 413 was a different route, and its lesson is preserved.** `b0x` envelope cap is
> 131,072 (`b0x.rs:32`); it was overrun at 168,400 bytes by a cached per-relationship state that
> embedded a 49,856-byte SPHINCS+ signature. It was fixed by **shrinking the payload**, not raising
> the cap (`bcr.rs:87-92`). A settlement bundle does not traverse `b0x` — but if one ever were
> routed there the margin would be 2.60x, and a second signature in the same envelope would break
> it. **Do not route a bundle onto `b0x`.**
>
> ### The defect this trace exposed is the more consequential finding
>
> It sits at the durability-before-binding seam, where a failure is far harder to recover from than
> any payload-size problem.
>
> `settlement_bind.rs:74-77` writes `put_immutable_to_all_members(...).await.map(|_| ())`. The inner
> call returns `Ok(KeyedPutFanout)` whenever the SDK could be *constructed*; per-member outcomes
> live in `fanout.accepted`, which is **discarded**. So **0 of 3 members accepting — a 413, a 401,
> an unreachable fleet — still returns `Ok`**, the bind proceeds, and the fence is placed against a
> `value_addr` no member holds. `settlement_resume`'s fetch can then never succeed and the parent
> stays fenced forever.
>
> Req 6.15's **ordering** (PutImmutable before the first mutating op) is enforced; its **success**
> is not. The caller erases the distinction between two different facts:
>
> ```text
> SDK invocation succeeded
>         vs
> enough committed Class N members actually accepted B
> ```
>
> The pathological sequence the current code permits:
>
> ```text
> immutable PUT attempted -> 0 members accept B -> outer fn still returns Ok
>   -> fence placed / QuorumBind proceeds -> binding names value_addr
>   -> B unavailable from the committed storage set
>   -> recovery cannot obtain the exact bound object -> fence cannot complete normally
> ```
>
> **The normative rule for the fix — not merely `accepted > 0`.** The threshold derives from the
> protocol, since the invariant is quorum-durable publication before binding mutation:
>
> ```text
> accepted attributable members >= q      for the EXACT committed storage set
> otherwise: reject BEFORE the first occupancy mutation
> ```
>
> **Boundary tests to pin, at beta `n=3, q=2`:**
>
> ```text
> 0 / 3 accepted  -> refuse before bind
> 1 / 3 accepted  -> refuse before bind
> 2 / 3 accepted  -> publication prerequisite satisfied
> 3 / 3 accepted  -> publication prerequisite satisfied
> ```
>
> Plus the case that names the semantic hole `.map(|_| ())` hides: **every HTTP call returned
> normally, and every member rejected the PUT.** That must refuse.
>
> **Fix this regardless of the size margin** — the margin is only load-bearing because the client
> currently cannot observe the put failing at all.
>
> ### CAVEAT 2 — what is asserted from source rather than measured
>
> - The live `node.toml` on the three ECS boxes was not read. This cannot flip the verdict — the
>   binding 512 KiB is hardcoded in the binary and `http.body_limit_bytes` can only tighten a
>   looser outer hop — but it is an assertion, not an observation.
> - **No positive control was run.** Nothing has PUT a real ~50 KB bundle at a live node. Given
>   that this repo's own 413 was discovered in production rather than in review, one
>   `curl --data-binary @50k.bin .../api/v2/immutable/put` expecting 201 is worth doing before the
>   owner-close path is treated as proven.
> - No test pins a ~50 KB body through the fully-layered router. That is a coverage gap, not a
>   failing limit.
>
> ### Work order set by the owner, 2026-09-07
>
> ```text
> 1. Fix/pin immutable publication success semantics   (accepted >= q, before any mutation)
> 2. Live positive control: PUT a real ~50 KB immutable object, expect 201;
>    and read the deployed node.toml on the three ECS boxes
> 3. 2c-B -- still the normative dependency blocking complete market Canon(B)
>    and the first conformant market b
> 4. 2c-C / 2c-D and the 5c-2 conformance work
> ```
>
> **Nothing in this trace justifies redesigning `close_authorization` or shrinking the canonical
> bundle.** Items 1 and 2 are validation and a bug fix; the amendment stands.

> **Corrected by [amendment 2c-A](../papers/amendment-2c-a-bundle-and-transition.md), 2026-09-07.**
> This plan predates the canonical bundle shape. Under 2c-A there is **no `successor_ccb`, no
> `reserve_deltas`, and no bundle-level `proof_material` or `bundle_signatures`**; the bundle is
> `{market_terms?, transitions}`, a transition carries the complete nested `V_{n+1}`, `P_v` nests
> inside its transition, and the shape discriminator is `market_terms` presence. Inline
> `Corrected by 2c-A` notes mark each affected passage. **Where the two disagree, 2c-A governs.**

Status: APPROVED, implementation starting 2026-09-07. Follows 5c-1
(`docs/plans/2026-09-06-5c-1-binding-occupancy-cutover.md`).

Paths below are relative to `dsm_client/deterministic_state_machine/` unless stated.

> Note on symbols: the CCB registry (Finding 4) retires bare `A_B`. The trader-acceptance
> artifact is `TA_B` with digest `ta_B`; `A_B` now denotes only the allocation bundle.
> Some headings below still read `A_B` where they quote the earlier framing.

---

> **Canonical location:** this plan belongs at
> `docs/plans/2026-09-07-5c-2-market-realization-acceptance-artifact.md`.
> Plan mode restricts edits to this codename file, so the repo copy is created
> the moment plan mode exits. (The 5c-1 plan above never got its repo copy —
> that is a miss to correct at the same time.)

## Context

C3 (`9461cf9f`) made QuorumBind the authoritative occupancy mechanism and split
two facts the settlement-slot register had fused:

```
binding occupancy = this DLV parent is no longer available to a rival
realized frontier = this successor actually became economic state
```

For an owner close those still coincide — the successor is complete and
pre-authorized, so binding finality realizes it one-phase (Req 6.30). For a
**market** bundle they deliberately do not, and C3 shipped that asymmetry
honestly: a market bundle takes occupancy at bind time, and the walk reports
`FrontierBinding::BoundUnrealized` until something proves the successor became
real.

**What C3 used as that proof is scaffolding, and it was labelled as such in
code.** `realize_market_successor_5c1` keeps the PRE-BUNDLE evidence verbatim —
a settlement receipt, the published RouteCommit whose `X` recomputes from its own
bytes, routed-unlock eligibility, the hop's parent binding, and an exact
constant-product re-simulation. That was the right call for an atomic switch: it
kept successful trades advancing reserves while the acceptance seam did not
exist. It is not the Rev-15 rule.

**5c-2 replaces it with the actual rule:** a market successor is realized when
the exact bundled trader successor has been accepted under ordinary DSM
advancement AND a trader-acceptance artifact `A_B` verifies (Def 6.26, Def 14.1).

### Why this is the merge blocker

The branch has stayed unmerged since C1 under a no-legacy-coexistence rule. It
cannot merge while the market path realizes on evidence the spec does not
recognize, because that evidence is a second, weaker realization mechanism
living beside the one the spec defines. 5c-2 is what makes the branch a single
coherent architecture; 5d (deleting the old register from the storage node) and
5e (the beta wipe) follow it.

### Three things C3 left explicitly for this step

1. **The temporary gate itself** — `realize_market_successor_5c1` and everything
   it consumes, marked in code for wholesale deletion.
2. **The market bundle's placeholder `trader_successor`**, which currently
   carries the trade identity `X` because there was no successor commitment to
   name. It becomes the real thing here. *Corrected by 2c-A: the close/market
   discriminator is `market_terms` presence, so the trader coordinates exist only
   in the market shape and this change cannot disturb close identification.*
3. **The trader-parent fence has no release producer.** `SuccessorAccepted`'s
   only non-definition use is inside `mod tests`. Every committed market settle
   therefore leaves a `committed_awaiting_acceptance` row that nothing releases,
   and `recover_all` — wired at cold boot in C3 — reads that list on every sync.
   Acceptance is precisely the event that releases it, so the producer belongs
   here.

*(Spec requirements, design, file map, ordering and verification follow — three
exploration passes in flight.)*

## What Rev-15 actually requires (read, not assumed)

`A_B` is fully specified. The important discovery is that **SoFi adds no new
signature and no new signing round** — `A_B` *packages* ordinary DSM material.

### Definition 6.26 — the five bindings

```
C_T^+   the ordinary DSM accepted-successor commitment. Commits the trader
        relationship/chain identity, the exact accepted
        trader_parent -> trader_successor transition, and the post-advance
        authenticated state root R_T^+.
sigma_T^+  the ordinary DSM successor-state authentication OVER C_T^+ itself:
        Verify(K_T, C_T^+, sigma_T^+) = 1.
X, b    the exact route commitment and bundle identifier.
L_B     a deterministic settlement/acceptance leaf under the R_T^+ committed
        inside C_T^+.
pi_B    the inclusion proof for L_B under that same R_T^+.
```

A verifier parses and verifies `C_T^+` under ordinary DSM rules, requires it to
commit the exact trader relationship / parent / successor already carried by `B`,
verifies `σ_T^+` **directly over `C_T^+`**, extracts the committed `R_T^+`,
verifies `π_B` under that authenticated root, and verifies `L_B` binds the exact
`(trader_parent, trader_successor, b, X)` committed by `B` (`:1114-1125`).

### The clause the whole design turns on

> *"A Merkle proof authenticates membership relative to a root; it does not
> authenticate the provenance of that root."* (`:1132`)

The successor authorization **already inside `B`** cannot authenticate `R_T^+`,
because `R_T^+` exists only as part of the accepted successor state. So a
constructor holding `B` can build an arbitrary Merkle tree and a valid-looking
inclusion path, and still fail Def 6.26 without the genuine `σ_T^+` over the
exact `C_T^+` that commits that root (`:1138-1142`).

**Req 21.17 makes a forged-root test vector MANDATORY**, and says why in the same
words. That is our first conformance test, not an afterthought.

### Realization, and what it is not

`A_B` verifying is only half. Def 6.26 `:1144-1146`: a bundle is realized only
when **(a)** it is binding-final under Def 6.24 **and** **(b)** `A_B` verifies
and matches the exact trader parent/successor committed inside `B`.

Requirement 6.27 `:1152-1162` enumerates the bound-but-unrealized state in six
clauses. C3 already satisfies several by construction — reserves and generation
stay at the composed parent, no different bundle may consume the parent, a later
quote must treat it as blocked, and **owner release/close over the same parent
remains blocked** (C3's `dlv_close` gate refuses `BoundUnrealized`). The clause
5c-2 must still honour is *"no proposed trader output is spendable"*.

### Ordering is normative (§16.2 `:1780-1790`)

```
bind -> accept exact B.trader_successor from B.trader_parent through ordinary
DSM bilateral rules -> obtain C_T^+ and sigma_T^+ -> construct and verify A_B
-> clear the trader-parent fence ONLY after that authenticated acceptance
-> only then mark B realized and its DLV successors composable
-> publish/index receipt, A_B, and supporting immutable objects
```

This maps almost exactly onto the shape `dlv_unlock_routed` already has (bind,
advance, publish receipt) — the new work slots between the advance and the
receipt.

### Consequences we had not accounted for

- **The receipt format changes.** Def 14.2 `:1515`:
  `Receipt = H(DSM/receipt ‖ b ‖ X ‖ a_B ‖ Canon({successor_hash_v, witness_hash_v}))`.
  The receipt must bind `a_B`, and Req 14.4 forbids publishing one before the
  bundle is binding-final *and* a valid `A_B` exists. Publishing for a
  bound-but-unrealized bundle is explicitly non-conforming.
- **The fence release producer is normative, not tidy-up.** Req 6.23(4): COMMITTED
  fixes the permitted continuation to the exact bundled successor, *"the quorum
  result alone does not consume the fence"*, and Class K releases it only on
  ordinary-DSM acceptance. §16.2 `:1787` puts it after `A_B` verifies.
- **Content address and object class.** `a_B = H(DSM/trader-settlement-acceptance/v2 ‖ Canon(A_B))`
  (`:1494`), object class `TraderSettlementAcceptanceV2` (`:1710`). The tag
  already exists in the reserved table at `:430`.
- **Owner side: nothing to build.** There is no owner acceptance artifact and no
  owner-side materialization step (`:118`, `:735`, `:2577`). Market realization
  credits the DLV reserve state; reserves reach owner spendable balance only via
  release/close. Owner catch-up (Req 6.31) folds *realized* history into a fresh
  baseline and must never fold a bound-but-unrealized candidate.
- **Name collision.** Def 9.2 uses `AB` for **AllocationBundle** — an unrelated
  object. Any grep for `A_B`/`AB` hits both.

### Conformance obligations

Req 21.15, 21.16, **21.17 (mandatory forged-root vector)**, 21.18, plus the §21
rows `half-completion/`, `acceptance-root-auth/`, `receipt-verifier/`. Req 14.5
defines the third-party verifier form: a party with no write authority must
independently establish the bundle economics, the binding-final choice, the
acceptance of the exact successor, and **equality between the trader exchange
proved by `A_B` and the DLV reserve deltas committed by `B`**.

## What the code already has (and the one place it falls short)

### The artifact is 90% built, under another name

`dsm/src/economic/successor_evidence.rs` already produces and verifies almost
exactly what Def 6.26 describes, for the economic-admission path:

```rust
sign_dsm_successor_evidence(rel_key, embedded_parent, counterparty_devid,
    operation_bytes, entropy, encapsulated_entropy, genesis, device_id, ak_sk)
// carries: the v2 chain-tip preimage fields, the resulting C_dsm+, and
// sigma_dsm = AK signature over
//   H(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖ operation_digest)

verify_dsm_successor_evidence(..) -> VerifiedDsmSuccessor {
    operation, operation_digest, c_dsm_plus, embedded_parent
}
```

Its module header states the same reasoning Def 6.26 does — before it existed,
"the device accepted this successor" was a local assertion, and a foreign
verifier now recomputes `C_dsm+` through the one canonical helper and checks the
signature under the P0–P6-proven AK. `peer_lineage.rs:290-470` is a complete
foreign-verifier walk over it. The producer is already wired in
`economic_admission_flow.rs:359-374`.

Mapping onto the spec: `C_T^+` ↦ `c_dsm_plus`, `σ_T^+` ↦ `sigma_dsm`, and the
decoded `operation` gives every trade quantity — from the **signed**
`Operation::DlvSettle`, which is strictly stronger than reading them off a
receipt.

### 🚩 The gap: `C_dsm+` does not commit the post-advance root

Def 6.26 requires `C_T^+` to commit *"the post-advance authenticated state root
`R_T^+`"* (`:1083-1090`), and `π_B` then proves `L_B` **under that same root**.
That is the entire anti-forgery argument: a Merkle proof authenticates membership
relative to a root, not the provenance of the root.

But `relationship_chain_tip_v2(rel_key, embedded_parent, counterparty_devid,
operation_bytes, entropy, encapsulated_entropy)` commits **no root**. So
`c_dsm_plus` satisfies the chain-identity and transition halves of Def 6.26 item
1 and not the root half — and `sigma_dsm`'s digest
`(G ‖ DevID ‖ C_dsm+ ‖ operation_digest)` does not cover a root either.

This matters because it is precisely the defect the settlement receipt already
has, self-documented in `settlement_receipt_leaf.rs:19-44`:

> **Retracted claim.** … `verify_trader_settlement_receipt` reads
> `trader_public_key`, `trader_genesis`, `trader_devid` and `post_root` **out of
> the receipt itself**. … The cheapest tree satisfying the inclusion check has
> ONE leaf, so the honest-path fixture and a forgery are byte-identical
> constructions … Closing this requires binding `post_root` to an independently
> verifiable trader state transition.

`A_B` is that closure — but only if the root is authenticated. Reusing
`DsmSuccessorEvidenceV1` unchanged would carry the receipt's defect forward under
a better name. **The design decision is where `R_T^+` gets signed**, and it is
the one question in 5c-2 worth getting exactly right.

### Other findings that shape the work

- **`AdvanceOutcome` is discarded.** `dlv_routes.rs:3371-3378` is
  `if let Err(e) = execute_on_relationship(..)` — the `Ok` value carrying
  `new_chain_state.compute_chain_tip()` (= `C_dsm+`), `embedded_parent`, and
  `child_r_a` (the post-advance device root) is dropped on the floor. Capturing
  it is the smallest change that makes the trader successor nameable.
- **An ordering inversion to resolve.** The bundle is bound at `:3264`, but
  `C_dsm+` only exists after `prepare_advance_relationship`. Two existing seams:
  `execute_on_relationship_staged` (`core_sdk.rs:1617-1641`) and the prepare-only
  view (`core_sdk.rs:2187-2199`, "identical inputs → identical outcome").
- **`trader_parent` is a placeholder too**, not just `trader_successor`: it is
  the *vault's* `c_n`, while `permits_successor` is keyed on the trader's parent.
  The market path also fences on `(vault_id, vault_c_n)` (`:3268-3269`), which
  contradicts the doc at `vault_state_composition.rs:126-131` claiming a market
  settle fences the trader's chain. Changing that key changes what
  `local_fence_overlay` and the resumed-close identity check can see.
- **The fence release call site is obvious once the outcome is captured**:
  `record_event(.., SuccessorAccepted { successor })` — **but see the single normative ordering
  below: this is emitted only AFTER `TA_B` verifies, never beside `AdvanceOutcome`**
  with `successor == C_dsm+ == bundle.trader_successor`.
- **The owner side is a single substitution point.** `dlv_reconcile`'s only
  evidence input is `fetch_verified_receipt` (`dlv_routes.rs:1633`); every
  downstream field derives from it. Two invariants it already enforces must not
  weaken: the parent state comes from `compose_own_vault` and never from the
  evidence, and the pre-sign curve re-simulation still runs against that composed
  parent.
- **Nothing structurally enforces the new meaning.** `settlement_bundle::validate`
  only width-checks `trader_parent`/`trader_successor` (`:102-103`).
- **Rejected reuse candidates**, checked: `peer_acceptance` needs a recipient
  countersignature and the settle is a self-loop (`rel_key = compute_smt_key(actor, actor)`);
  `OfflineBoundaryAttestationV1` is the wrong domain. `close_authorization` is the
  right *pattern* — reconstruct what DSM already signs — but its own note warns
  reconstruction must stay total, and a market settle cannot be reconstructed
  (`route_commit_bytes`, `sigma`, `entropy` are not composer-derivable), so `A_B`
  must carry the operation bytes. `DsmSuccessorEvidenceV1` already does.

## The repo has already ruled on this (two documents I had not read)

**`docs/reports/2026-08-21-rev15-conformance-delta.md:347-420` — §5 Trader
acceptance realization.** It reaches the same diagnosis independently and gives
a direction:

> **Verdict: partial, security-relevant.** The gate fires at the right moment,
> but what it accepts as proof does not authenticate `post_root` as the root
> committed by the accepted ordinary DSM successor.
>
> **Direction.** Upgrade the existing receipt/evidence path; do not reposition it
> and do not build a parallel artifact. A conformant
> `TraderSettlementAcceptanceV2` must carry and verify `(C_T^+, σ_T^+)` *and*
> match the exact SettlementBundle identity, route commitment, trader
> parent/successor, and acceptance leaf/proof.

It also states the constraint that creates the open question below: *"Rev 15
requires the ordinary DSM accepted-successor commitment `C_T^+` … where `C_T^+`
itself commits the post-advance root."*

**`docs/papers/ccb-object-registry.md`** fixes the identity and — importantly —
**renames the symbol**:

| Object | Symbol | Class | Digest |
|---|---|---|---|
| Trader acceptance for `B` | **`TA_B`** | `0x0011` | `ta_B = H(DSM/trader-settlement-acceptance/v2 ‖ CCB)` |
| Allocation bundle for `A→B` | `AB_{A→B}` | `0x0016` | — |

> Bare `A_B` is retained for neither … This matters most for amendment 2c, where
> `TraderAcceptance` is security-critical and a reader resolving the wrong
> definition would be reading about routing.

**Consequence:** the six `A_B` markers C3 left in code point a reader at the
allocation bundle. 5c-2 renames them to `TA_B` / `ta_B`.

`SettlementBundleV1` needs **no schema change**: field 8 holds `C_T^+`, and
`TA_B` is its own object class fetched by digest.

## 🚩 A live defect C3 activated

`FenceEvent::SuccessorAccepted` has no production caller — its only
non-declaration uses are in `mod tests`. So **every** `Outcome::Committed`, market
and close alike, leaves a permanent `committed_awaiting_acceptance` row.

That was latent before C3, because `recover_all` had no caller. **C3 wired
`recover_all` into `storage.sync`**, and `list_unresolved_fences` selects
`state IN ('fenced','committed_awaiting_acceptance')`. So on every sync this
device now re-fetches the bundle and re-drives a full QuorumBind round for every
settlement it has *ever successfully completed* — re-committing, re-recording
`Committed`, and burning a ballot each pass (`base_ballot: fence.ballot` →
`engine.ballot()` written back).

It is not a safety fault: the re-commit is idempotent and the conformance suite
covers that path. It is unbounded, monotonically growing work, and I introduced
its activation. The producer that fixes it is exactly the one 5c-2 must build —
on acceptance, emit `SuccessorAccepted { successor }` — so the fix belongs here,
but the *timing* is a decision (below).

A second consequence of the same hole: `active_verdict` → `FenceVerdict::PermitsOnly`
has **no production caller either**. The Req 6.23(4) advancement gate is
implemented and tested but never consulted, because a real `permitted_successor`
does not exist until `trader_successor` is real.

## Everything 5c-2 must touch (mapped)

**Delete** — `vault_state_composition.rs:622-779` (`MarketRealization` +
`realize_market_successor_5c1`), its call arm at `:505-553`, and the stale module
doc at `:38-52` which still says "exactly three outcomes" and describes the
receipt rule as the invariant. All four imports it uses have other callers, so
nothing becomes dead-code-warned.

**Re-source, do not delete** — of the eleven evidence checks in the temporary
gate, most become *bundle-internal* rather than disappearing: the RouteCommit is
already inside `B.selected_route` (so the network fetch dies), X-recompute and
routed-unlock eligibility become internal consistency checks, the hop parent
binding and pair/amount checks survive, and the constant-product re-simulation
moves onto the authenticated `V_n` and the inline `V_{n+1}` (*2c-A removed `reserve_deltas`; the
movement is their difference*). **X-recompute does NOT become bundle-internal** — it needs `Q`,
which 2c-A ruling 2 places in the Def 14.2 receipt publication set, so it stays a Tier-3 obligation
of the Req 14.5 verifier. The one genuine deletion
is successor *construction*: the walk currently derives the successor locally and
must instead **read `T_v.successor`** — the largest semantic inversion
in the change. The walk already binds `transition` and throws it away
(`let _ = transition;`).

**Populate for real** — the whole `market_terms` subobject plus `T_v.successor`, at
`dlv_routes.rs:3229-3260` plus five fixture sites (`vault_state_composition.rs:978`,
`dlv_routes.rs:7017`/`:8130`, `binding_occupancy.rs:479`, `settlement_bind.rs:242`)
that must move in lockstep or the tests keep asserting the placeholder shape.

*Corrected by 2c-A: there is no `successor_ccb`, no `reserve_deltas` and no bundle-level
`proof_material`. `intent_commitment` becomes the nested `TradeIntent` object rather than a digest
aliased to `X` — two distinct spec objects that were sharing one value.*

**Wire the missing producer** — `SuccessorAccepted`. Capturing `AdvanceOutcome` is what makes
the successor *nameable*; it is **not** the release point. The single normative ordering, and the
only one in this document:

```text
advance exact successor
  -> finish / validate economic admission
  -> construct + verify TA_B
  -> SuccessorAccepted / fence release
  -> realize
  -> publish the Def 14.2 receipt
```

Releasing on `Committed`, or beside `AdvanceOutcome`, makes a different continuation creatable
from the fenced parent. An earlier draft of this plan said "immediately after the settle advance";
that instruction is **deleted**, not softened.

**Provenance** — the arm validates occupancy, bundle identity/scoping, parent
naming, trade identity and authorship. It does **not** validate realization, and
that is arguably correct: the trader's own credit is funded by its own settle
against a parent it exclusively holds. Two additions are cheap and close real
gaps: `bundle.trader_successor == C_T^+` belongs here (this is the only place
`ctx.proven_ak` is bound to the settling identity), and the bundle's stated
successor should be required consistent with the settle's own re-simulated
amounts. The five-way `BindingObservation` taxonomy must survive verbatim; an
absent `TA_B` is a sixth thing and maps to `Incomplete`, never `Invalid`.

**Rig** — `BindingProbe` is an occupancy probe driven off `folded_parents`, which
by construction only contains *already realized* parents, so it cannot currently
speak about realization. Minimal extension: emit the frontier's `FrontierBinding`
variant (the walk already computes it and `probe_vault_bindings` discards it),
then per-parent `realized_successor` / `acceptance_verified` / `ta_b`. **The
script's frontier assertion is already wrong** — `verdict not in ("FREE",)`
mis-fails a legitimately `BoundUnrealized` frontier. That is a bug in my C3 rig
port, independent of 5c-2.

> **Superseded by 2c-A's close/market ruling.** The paragraph below described the discriminator
> as a recomputed `successor_ccb` and noted that `close_bundle` writes `x_close` into both
> successor fields. Neither survives.

**The close discriminator is `market_terms` presence, and the close shape is outside 5c-2's
scope.** Under 2c-A a close bundle carries no `market_terms` — hence no trader coordinates, no
intent, no route and no recovery material — so `permits_successor` no longer means two different
things by shape, because the close shape has no trader successor to permit. `key_set` is still
derived purely from `parent_binding`, so resumption is byte-identical across the change and both
shapes still contend on the identical `k_v`.

**One live deviation this exposes, with an owner.** Req 6.30 gives owner close *"no owner-side
analogue of the Requirement 6.23 trader-parent fence"*, yet the shipped code writes a
`trader_parent_fence` row for **every** close. **Removing it is owned by the 5c-2 implementation
commit that consumes the 2c-A bundle shape** — that commit already rewrites `bind_settlement`'s
fence call for the market path, so the close call site is open on the same line of the same
function. (2c-A itself is a normative document with no implementation phase.) The close path keeps
whatever local durability resume needs; what it must stop doing is claiming a Req 6.23
trader-parent fence it has no trader chain for.

*Historical text follows.* One asymmetry stated at the time: `close_bundle`
writes `x_close` into *both* successor fields, so after 5c-2 the market shape
carries a real `C_T^+` in field 8 while the close shape carries a public
derivation — `permits_successor` then means two different things by shape.

## Owner rulings (2026-09-07)

**1. `R_T^+` is the trader's validated post-economic root, via economic
admission.** Do **not** mint a `DsmSuccessorEvidenceV2` that starts signing the
device SMT root. DSM already has a purpose-built authenticated economic-root
layer, and the successor-evidence code is explicit that `C_dsm+`/`sigma_dsm`
authenticates the accepted DSM successor while the economic balance effect is
deliberately *not* carried there — `R_econ` is the sole authenticated balance
representation. So `R_T^+` is the post-economic root produced by admitting the
exact `DlvSettle`, `L_B` is the existing `EconomicSettlementReceiptState`, and
`π_B` is the existing settlement-payment inclusion proof.

**…and the wording mismatch gets resolved, not papered over.** Def 6.26 says
`C_T^+` commits `R_T^+` and `σ_T^+` authenticates that exact commitment. The
implementation instead has a cryptographically **linked pair**:

```
sigma_dsm                 -> C_dsm+ + operation
signed EconomicRootClaimBody -> post_economic_root + manifest -> exact DSM successor evidence
```

Before implementing, make that correspondence explicit: either define SoFi's
ordinary accepted-successor authentication AS that linked economic-admission
construction, or amend Def 6.26 so it stops claiming the relationship chain tip
itself contains the economic root. **Do not invent a second authenticated state
root merely to match the current prose.**

**2. Narrow recovery now, as its own small commit before 5c-2 proper.**
`recover_unresolved_fences` must re-drive only `FenceState::Fenced`.
`CommittedAwaitingAcceptance` is terminal from QuorumBind's perspective and must
never be handed back to `resume_one`/`run_fenced` — conflating "binding
unresolved" with "acceptance outstanding" is the defect. Keep the committed row
intact: it still enforces `PermitsOnly(exact_successor)` and supplies the
close-resume identity check. Rename the selector so the prose stops calling both
states unresolved — `list_binding_recovery_fences()` with `WHERE state = 'fenced'`.
`active_fence()` keeps including both, because both still constrain advancement.

**3. Unblock `DlvProofMaterial` (`0x0010`) as part of 5c-2** — it is amendment 2c
by the registry's own decomposition, and shipping the final realization mechanism
while the object carrying its verification material stays formally undefined
would be incoherent. **Spec first, encoder second**: define the normative CCB
shape, then implement it; do not let the Rust encoder define the protocol by
accident. Keep `P_v` **minimal and non-redundant** — nothing already committed by
`V_n`, `T_v`, the selected route or `X` may be repeated for convenience, and
reserve/input/output values derivable from the authenticated parent plus the
successor do not belong in it.

> **Amended by 2c-A.** This ruling originally read *"`T_v` carries the complete DLV successor,
> **exact reserve deltas** and required witnesses."* The deltas are removed: `T_v.parent_binding →
> V_n` and the inline `T_v.successor = V_{n+1}` each commit their own reserves, so the movement is
> their difference, and a carried copy would be a third independently encodable statement of it
> (the route's `Allocation.delta_in`/`delta_out` is the second). The ruling's *purpose* is better
> served, not weakened — the continuation is now carried complete rather than by digest.
> `0x0010 DlvProofMaterial` was settled by 2c-A with **zero fields** for the beta pricing family,
> and `P_v` nests inside its own `T_v` rather than sitting parallel to `{T_v}`. Preserve the boundary: `T_v` carries the
complete DLV successor and required witnesses; `P_v`
carries only the irreducible witness material a foreign Class K verifier needs to
re-check the exact selected continuation. The target property: a third party can
verify from `authenticated parent + selected route/X + T_v + P_v + TA_B` with no
constructor-local state and no live RouteCommit fetch.

## Owner amendments to the plan (2026-09-07, second pass)

> **Field-path shorthand.** Below, `B.trader_parent` / `B.trader_successor` abbreviate
> `B.market_terms.trader_parent` / `B.market_terms.trader_successor` under 2c-A. They are members
> of `MarketTerms`, and an owner close has neither.

**A. Two coordinate systems, never aliases.** The map found that
`bundle.trader_parent` is currently the *vault's* `c_n` and the market fence is
keyed `(vault_id, vault_c_n)`. Fixing only `trader_successor` is not enough:

```
B.trader_parent                      = exact ordinary-DSM trader relationship parent
B.trader_successor                   = exact prepared C_dsm+
FenceKey.trader_chain_id             = actual trader relationship/chain identity
FenceKey.trader_parent_state_commitment = exact trader parent commitment
QuorumBind K(B)                      = STILL derived from the DLV parent c_n
```

**DLV `c_n` controls liquidity occupancy; the trader parent controls which
ordinary-DSM continuation is permitted.** Two jobs, two coordinate systems.

*Consequence worth stating:* once market fences move to the trader's chain,
`local_fence_overlay` — which reads `active_fence(vault_id, cursor_c_n)` — stops
seeing market fences entirely. That is correct, and it finally makes the code
match the doc C3 already wrote: `LocallyFenced` is well-defined for the owner's
own close only. The close keeps `trader_chain_id = vault_id` because a close has
no trader chain; the asymmetry is real and gets said out loud.

**B. Narrowing binding recovery creates an orphan, and 5c-2 must own it.** Once
`CommittedAwaitingAcceptance` leaves the QuorumBind worklist, a crash after
COMMIT and before `TA_B` completion leaves a committed fence **no worker owns** —
`settlement_resume` only re-drives binding transactions and has no
acceptance-completion machinery. 5c-2 needs a separate **acceptance continuation
path**, not a second QuorumBind resume. On startup/sync, for each
`CommittedAwaitingAcceptance`: fetch exact `B`, then deterministically continue
the permitted successor — if the trader chain is still at `B.trader_parent`,
resume/commit only `B.trader_successor`; if it already sits at that exact
successor, continue from there — then resume economic admission, construct and
verify `TA_B`, release the fence, realize, and only then publish the Def 14.2
receipt (ordering corrected per amendment D). Reuse the
existing `resume_pending_admission` rather than inventing another durability
protocol.

**C. A signed `EconomicRootClaimBody` is NOT proof of `R_T^+`.** The economic
register's own doc says *registered is not validated*: a malicious trader
registers an arbitrary root perfectly consistently, and the register establishes
non-equivocation, not transition validity. So the linked construction is not
`signed root claim -> R_T^+`. The foreign `TA_B` verifier must invoke the
economic-admission **validity** path:

```
previously validated R_econ
  -> verified economic transition / write set
  -> manifest + authority evidence
  -> exact DsmSuccessorEvidence
  -> VALIDATED post-economic root R_T^+
  -> L_B + pi_B under that root
```

Verifying only that the trader signed a claim naming some root would let Req
21.17's forged-root attack survive in a slightly different shape.

**D. Fence release is ordered after `TA_B` verifies, not after the advance.** The
normative order is bind → accept successor → construct and verify `TA_B` → clear
the fence → realize. Either emit `SuccessorAccepted` only after the `TA_B`
verification step, or introduce a better-named terminal event — the state-machine
name must not tempt anyone to move release back beside `AdvanceOutcome`.

**E. `TA_B` discovery, and two different "receipts".** `TA_B` cannot be named
inside `B`, because `B` is bound before `TA_B` exists. Define ONE
non-authoritative discovery edge keyed by `b` — reuse the existing receipt/index
machinery if it can cleanly map `b -> ta_B`, otherwise a small `b -> ta_B` index.
Retrieved bytes stay authoritative only by content hash and by the artifact
naming the exact `(b, X, trader_parent, trader_successor)`.

Terminology, kept strict: **`L_B`** is the economic settlement/acceptance leaf
under `R_T^+`. The **Def 14.2 public Receipt** is a later object that binds
`ta_B`. **Do not put `ta_B` into `EconomicSettlementReceiptState` / `L_B`** — that
is circular: `TA_B` hashes `L_B`, and `L_B` would contain `ta_B = H(TA_B)`.

Pin this in the names and comments too: `Operation::DlvSettle.settlement_receipt_id`
belongs to the economic settlement leaf / `L_B` machinery, **not** to the Def 14.2
public Receipt. Two different objects have been called "the receipt" throughout
this code, and that is exactly how a circular `TA_B` ↔ Receipt dependency gets
built by someone reading the wrong one.

**F. `P_v` may legitimately be empty.** If the authenticated parent, the selected
route/`X` and `T_v` already suffice for the constant-product check, the current
profile carries no irreducible extra proof material. Do not manufacture fields so
that `P_v` is nonempty.

**G. `recovery_material` gets normative semantics.** The acceptance-continuation
worker of amendment B cannot do its job without this, and the map already proved
why: a market settle **cannot be reconstructed from the commitment alone** —
`route_commit_bytes`, signature material and entropy are not all
composer-derivable. `B.trader_successor = C_dsm+` states what the answer must be;
a 32-byte target is not reconstruction material.

So a binding-final `B` must carry enough **non-secret canonical** material to
reconstruct and commit the exact already-prepared ordinary-DSM trader successor
after a crash. Define the contents and canonical encoding of
`SettlementBundle.recovery_material` in Step 1, and make the worker **recompute
and require exactly `B.trader_parent -> B.trader_successor` before committing
anything**. Use the existing proto field — it is already there and currently has
no semantics — rather than a local recovery database whose contents could
disappear independently of the bundle that was bound.

**H. Populate the real `I`.** `intent_commitment` is presently set equal to `X`,
though `I` and `X` are distinct commitments. It must be the canonical TradeIntent
commitment, and both bundle construction and third-party verification must check
that the selected route satisfies that exact `I`. No two distinct normative
commitment fields may remain aliases because the old path had placeholders.

**I. `P_v` cardinality, mapping and empty encoding must be canonical.** "May be
empty" is insufficient for a cross-implementation encoding. The transport is
`repeated bytes proof_material`, so the amendment must answer: does a two-vault
bundle with no additional witnesses encode `proof_material = []` or
`[CCB(empty P_v), CCB(empty P_v)]`, and when non-empty, exactly how does each
`P_v` associate with its sorted `T_v`? Otherwise two conforming implementations
produce different bundle bytes for the same settlement.

## Plan

**Sequencing note.** The bundle must become real *before* anything binds it live.
"Build and bind `B`" is not safe until `I`, the trader coordinates, the recovery
material, the DLV successor and the proof semantics are all real — so Step 2 and
Step 3 may land as one commit, but never in the other order.

### Step 0 — narrow binding recovery (separate commit, first)

`recover_unresolved_fences` re-drives only `FenceState::Fenced`. Rename
`list_unresolved_fences` → `list_binding_recovery_fences` with
`WHERE state = 'fenced'`; `active_fence` unchanged (both states still constrain
advancement). Tests: a committed fence is never handed to the resume driver; a
`Fenced` row still is. Stops the live growing per-sync cost C3 activated.

### Step 1 — normative work, before any encoder

Four documents, reviewed before code:

1. **The `C_T^+` correspondence** (amendment C): SoFi's ordinary
   accepted-successor authentication IS the *validated* economic-admission
   construction, or Def 6.26 is amended to stop claiming the relationship chain
   tip contains the economic root. It must state the validity chain, never the
   registration.
2. **`DlvProofMaterial` `0x0010` CCB shape** — minimal, non-redundant, possibly
   empty in this profile (F), with cardinality, `T_v` association and the
   zero-material encoding all pinned (I).
3. **`recovery_material` semantics** (G) — the non-secret canonical material that
   reconstructs the exact prepared trader transition.
4. **The canonical TradeIntent commitment `I`** and what "the route satisfies
   `I`" means to a verifier (H).

### Step 2 — the bundle becomes real

Every placeholder replaced, in the right coordinate system (A):

```
B.trader_parent      = exact ordinary-DSM trader relationship parent
B.trader_successor   = exact prepared C_dsm+
B.market_terms.intent            = the real TradeIntent OBJECT; I is derived
T_v.successor                    = the complete canonical V_{n+1}; c_{n+1} derived
T_v.proof_material               = P_v per Step 1 (absent in the beta profile)
T_v.close_authorization          = ABSENT for every market transition
B.recovery_material  = per Step 1
K(B)                 = STILL derived from the DLV parent c_n
```

The five fixture sites move in lockstep or the tests keep asserting the
placeholder shape.

### Step 3 — the live path binds it, and the trader produces the acceptance

`FenceKey` moves to the trader's chain identity and parent (A). Route `DlvSettle`
through economic admission (already `ClosedWriteSet`, with a write-set arm and a
`ValidatedDlvSettlementPayment` credit source the settle path never ran).

**The exact sequence, pinned.** DSM's admission architecture requires the
Prepared economic admission to be attached *before* `advance` — `DeviceState::advance`
refuses an economic operation with no pending admission, and the established
pipeline is phase-one admission → advance → `finish_admission`. So:

```
prepare exact trader successor
  -> derive C_dsm+
  -> construct the fully-real B
  -> QuorumBind B to Finality
  -> build economic admission from that exact prepared successor
  -> stage PendingEconomicAdmission::Prepared on the current head
  -> commit ONLY the exact B.trader_successor
  -> finish_admission
  -> obtain validated R_T^+
  -> build + verify TA_B
  -> release trader fence
  -> realize the DLV successor
  -> publish the final Def 14.2 Receipt
```

This ordering is also stronger than the naive one: the liquidity parent is
occupied **before** the spendable trader output can be admitted, while DSM's own
economic fence still prevents the trader successor from committing without its
exact admission. Use the prepare-only view (`core_sdk.rs:2187`) or
`execute_on_relationship_staged` (`:1617`), and capture the `AdvanceOutcome` that
`dlv_routes.rs:3371` discards.

Then build `TA_B` (`0x0011`, `ta_B = H(DSM/trader-settlement-acceptance/v2 ‖ CCB)`)
carrying the linked pair, `L_B`, `π_B` and exact `(b, X)`; publish it and the
`b -> ta_B` discovery edge; publish the Def 14.2 receipt only after `TA_B` exists
(Req 14.4), with `ta_B` bound into it.

### Step 4 — realization moves to `TA_B`

Delete `MarketRealization` / `realize_market_successor_5c1` and its walk arm. The
walk resolves `ta_B` through the discovery edge, verifies `TA_B` **through the
economic-admission validity path** (C), requires it to match the bundle's exact
trader parent/successor and `(b, X)`, and then **reads** the successor from
`T_v.successor` (the complete nested `V_{n+1}`) instead of constructing it. `BoundUnrealized` survives
as the normal mid-flight state.

**The discovery edge tells a verifier WHERE TO LOOK, never WHAT IS TRUE.** A
stale, hostile or unavailable `b -> ta_B` entry must never produce
`Contradicts`, `Invalid`, a quarantine, or any permanent negative conclusion
about `B` — otherwise a non-authoritative locator becomes an availability attack
on realized liquidity. The full table:

```
no locator                                  -> Absent / BoundUnrealized
locator unavailable                         -> Incomplete / BoundUnrealized
locator -> bytes with the wrong content hash-> ignore / Incomplete
locator -> TA_B for another b/X/parent/succ -> irrelevant locator; do not realize
at least one TA_B that content-hashes correctly
  + verifies validated economic admission
  + names exact b, X, trader_parent, trader_successor
                                            -> realization evidence
```

### Step 5 — acceptance continuation, fence, provenance, rig, rename

The acceptance-continuation worker (B), reusing `resume_pending_admission`, which
**reconstructs from `recovery_material` and requires exactly
`B.trader_parent -> B.trader_successor` before committing anything** (G). Fence
release ordered after `TA_B` verifies (D). Add
`bundle.trader_successor == C_T^+` to the provenance arm (the only place
`ctx.proven_ak` is bound to the settling identity), and wire `active_verdict`
into successor creation — implemented, tested, currently consulted by nothing.
Extend `BindingProbe` with the frontier's `FrontierBinding` variant and per-parent
realization fields, **and fix the rig's frontier assertion, which today mis-fails
a legitimately `BoundUnrealized` frontier**. Rename the six `A_B` markers to
`TA_B`/`ta_B`.

## The lifecycle this produces

```
prepare exact trader successor
  -> B commits exact trader parent/successor + I + DLV continuations + recovery material
  -> QuorumBind wins DLV occupancy (K(B) from the DLV c_n)
  -> [crash-safe: reconstruct from recovery_material, require exact successor]
  -> stage the economic admission for that exact prepared successor
  -> commit ONLY B.trader_successor  (ordinary DSM acceptance)
  -> finish_admission -> VALIDATED R_T^+
  -> prove L_B under R_T^+
  -> construct + verify TA_B
  -> release the trader fence
  -> the DLV market successor becomes realized
  -> publish the Def 14.2 Receipt (binds ta_B)
```

## Verification

Per step, then the full sequence on one unchanged tree: targeted
composition/provenance/settlement suites; full `dsm`; full `dsm_sdk`; the
workspace release board; `make lint`; `ci/production_safety_checks.sh`; the probe
build. No edit after the stamps.

**Conformance vectors, named by the spec and not optional:** Req 21.15, 21.16,
**21.17 (the mandatory forged-root vector)**, 21.18, plus the §21 rows
`half-completion/`, `acceptance-root-auth/` and `receipt-verifier/`.

**Crash tests at five seams** (B), each resuming to a correct terminal state and
each requiring the reconstruction to reproduce the exact successor (G). Note
there are five, not four: staging admission *before* the advance means "advanced
but not yet admitted" is a state that must not exist.

```
1. QuorumBind COMMIT      -> before admission staged
2. admission staged       -> before the DSM successor commits
3. DSM successor committed-> before finish_admission completes
4. validated admission    -> before TA_B
5. TA_B verified          -> before fence release / realize / receipt
```

**Encoding determinism** (I): two independently constructed bundles for the same
settlement must be byte-identical, including the zero-material `P_v` case.

> **Corrected by 2c-A ruling 3.** This originally also demanded a multi-vault bundle vector. Beta
> fixes `|{T_v}| = 1`, which forces single-hop / fanout-1, so a multi-vault bundle is **not a valid
> beta bundle** and cannot be a beta conformance vector — retained only as a labelled future
> non-beta encoding exercise. Note also that "same market settlement" means the same exact prepared
> trader successor and the same exact canonical recovery material, not merely the same economic
> trade; recovery material is not composer-derivable.

**Mutation controls**, each reproducing the forbidden state:
1. Drop the `TA_B` verification → a bound-but-unaccepted bundle folds reserves.
2. Verify `TA_B` against a **registered but unvalidated** root claim instead of
   the validated admission path → Req 21.17's forged-root vector goes red.
   Amendment C exists because this is the easy mistake.
3. Accept a `TA_B` whose `L_B` proves under a self-built root → same vector.
4. Release the fence after DSM advancement but **before** `TA_B` verification →
   a different continuation becomes creatable from the fenced parent. (Releasing
   on `Committed` is the earlier, easier failure; this is the one D guards.)
5. Let the acceptance worker commit a successor that reconstruction did **not**
   reproduce → a crash-resumed settle binds a continuation `B` never named.
