# Amendment 2c-D — the bundle-acceptance leaf, `TraderAcceptance`, and realization

> **Status.** FROZEN 2026-09-10 by owner ruling. This is the **fourth and final** amendment of the
> 2c series. 2c-A froze the bundle and its transition, 2c-B the accepted-successor substrate, 2c-C
> (C1–C4) the verification closure. Each stopped at the same boundary and named this document as the
> only thing that can cross it.
>
> **What crossing it means.** `IndependentRealization` becomes constructible; a market fold can
> leave `PartialPendingRealization`; a market fence becomes releasable; Req 21.16's receipt verifier
> becomes writable. None of those are reachable before this amendment's adopting change lands, and
> none of them are reachable *from this document alone* — it is normative text, not code.

---

## §1 — What the series left here, verbatim

Four frozen documents assign work to 2c-D. Collected so the scope is a reading of them rather than a
proposal:

```text
2c-C decomposition, "Explicitly not any 2c-C sub-amendment"
    TA_B 0x0011's field table, 0x0032, the bundle-acceptance leaf — 2c-D, and
    TA_B's table must be RE-DERIVED once the leaf authenticates b.

2c-C4 §5 (Ruling R1)
    the bundle-acceptance leaf, its key, its content, or 0x0032        2c-D
    TA_B 0x0011 — its field table AND all verification of it           2c-D

2c-C4 §9
    Req 21.15 is partial until 2c-D; Req 21.16 is wholly owed by 2c-D.

2c profile §7a
    §1.4's compositional-binding argument moves to 2c-D, superseded by the
    two-conjunct rule in §9.1.
    §2 TraderAcceptance field table — 2c-D. Must be re-derived: with the leaf
    authenticating b, the coordinates and X are inside b and stop being
    separate fields.
```

Two things are **already settled** and this amendment does not reopen them. They are restated here
only so an implementer does not mistake a derivation for a decision:

- **2c-C2's leaf-key derivation family is class-dispatched and open**, precisely so `0x0032`'s key
  can be added without reopening C2. Adding a fifth arm is the mechanism working as designed.
- **§9.3 already assigns the numbers**: `0x0031` the substrate accepted-successor evidence (landed
  with 2c-B), `0x0032` the bundle-acceptance leaf. `0x0032` is unallocated and held in prose; the
  registry says it *"receives a row when 2c-D lands"*. This is that row.

---

## §2 — Blocker 1's required fix is the whole object

Amendment 2c §8 Blocker 1 is the security finding this amendment exists to close, and it already
states the fix. Restated exactly:

> `TA_B` carries **no signature of its own**, so putting `b` in field 1 only makes `b` part of that
> artifact's own content hash. It does not prove the trader's accepted economic state committed that
> bundle. […] `B` holds a **set** of vault transitions and a route may fan out across distinct DLVs,
> while §2 gives `TA_B` exactly one per-vault settlement receipt leaf and one Merkle path. One vault
> receipt cannot authenticate realization of a multi-vault bundle.
>
> **Required fix — one change closes both.** Do not bloat the existing settlement-payment leaf.
> Define a **bundle-acceptance economic leaf** under `R_T^+` whose *authenticated* content commits
> at least `b`.

The chain it specifies, unchanged:

```text
B binding-final
  -> exact trader successor accepted
  -> validated R_T^+
  -> L_B UNDER R_T^+ authenticates the exact bundle b
  -> TA_B packages b + proof of that authenticated L_B
  -> realization
```

The join becomes part of authenticated economic state rather than an assertion about it. One
bundle-level `L_B` per `B` covers however many DLVs the settlement consumed, because `b` already
commits `X`, the trader coordinates, the selected route and every `T_v`.

---

## §3 — Owner rulings (2026-09-10)

Two questions were put before any of this was written, because writing the object against a stale
table and repairing the specification afterward is the exact failure 2c-E was created to avoid. A
third, **ruling D3**, is in §5: it was taken when implementation exposed that §4's original operand
sat one step behind the economic layer's own abstraction boundary, and it was taken **before** the
leaf was implemented, for the same reason.

### Ruling D1 — `trader_genesis` survives the re-derivation

The re-derivation was blocked on a factual error in §7a. Checked at source: `X`, `trader_parent`,
`trader_successor` and `trader_devid` *are* recoverable from `b`, but `trader_genesis` is **not**.
`b` is `{market_terms, transitions}` and carries no trader genesis anywhere; `G` enters only through
`sigma_dsm`, whose signing digest is `H_dom(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖
operation_digest)`. A verifier can therefore *check* a candidate `G` against `b` but cannot
*recover* it — and the walk needs `G` to derive the leaf key.

> **One premise put to the owner was right in its conclusion and wrong in its route, and the
> correction is recorded rather than quietly applied.** `trader_devid` was offered as recoverable
> from `MarketTerms.recovery_material.counterparty_devid`, on the ground that a market settle
> advances the trader's self-loop and so the counterparty *is* the trader. That holds for bundles
> this software produces and is **not verified for a foreign one** (§12). The conclusion survives
> on a different and sound route: `trader_devid` is `operation_bytes.settler_devid`, a field of the
> frozen `DlvSettleOperationPreimageV1` grammar that G1 decodes and G2 requires to re-encode
> canonically. `b` therefore yields the trader's DevID under checks that already run, for any
> bundle. §7 step 2 carries the extra conjunct this route makes necessary.

> ```text
> RULING: Option 1.
>
> Keep trader_genesis G in the re-derived TA_B.
>
> Drop only the four coordinates actually recoverable from the authenticated
> settlement bundle b:
>
>     X
>     trader_parent
>     trader_successor
>     trader_devid
>
> Do NOT drop G merely because §7a used the blanket phrase "inside b."
>
> G is not inside b and cannot be reconstructed from b. The verifier needs G
> to derive the relevant leaf key.
>
> G is nevertheless NOT trusted merely because TA_B carries it.
>
> Its authentication is:
>
>     carried G
>         -> reconstruct the frozen sigma_dsm signing digest
>         -> verify sigma_dsm under the independently established trader AK
>         -> only then use authenticated G in the leaf-key derivation
>
> Thus G is a carried authenticated witness, not an authoritative coordinate.
>
> Retain the other genuinely non-b-derived TA_B material required by the
> acceptance proof, including the economic-position locator as non-authoritative
> where specified, acceptance_leaf, and acceptance_path.
>
> Amend §7a narrowly:
> "drop fields recoverable from the authenticated settlement bundle b"
> rather than
> "drop fields that are inside b"
> if the latter wording implies G must disappear.
>
> Do NOT:
>
> - resolve G through an external genesis lookup;
> - make TA_B verification depend on online or external state merely to recover G;
> - move G into DsmSuccessorEvidence;
> - bump 0x0031 / 0x0033 / 0x000E;
> - regenerate the market identity again for this issue.
> ```

The two rejected options are recorded with their reasons, because a later reader will propose them
again. Resolving `G` by external lookup *"introduces an unnecessary external lookup dependency into
an artifact that can otherwise carry the evidence necessary for verification — particularly
undesirable for the offline composition walk."* Moving `G` into `0x0031` is *"worse: it changes an
already-frozen canonical object merely to make an imprecise sentence literally true, causing another
transitive identity cut for no security benefit."*

The rule generalised, in the owner's words: **remove duplication with `b`; retain indispensable
non-duplicated witnesses, and authenticate them rather than trusting them.**

### Ruling D2 — `TA_B` drops field 1

> ```text
> RULING: Drop TA_B field 1 (`bundle b`).
>
> The authenticated bundle-acceptance leaf is authoritative for b.
>
> Verification order is:
>
>     supplied acceptance_leaf
>         -> verify canonical leaf encoding
>         -> verify acceptance_path to the independently validated economic root
>         -> obtain authenticated b from the leaf
>         -> require that b equals the settlement bundle being composed/verified
>
> TA_B must not carry a second canonical copy of b merely as a locator.
>
> Once the leaf is authenticated, its b commitment is the single source of
> truth. Carrying b separately would create two representations of the same
> coordinate and require an unnecessary equality check between them.
>
> If an implementation needs b before decoding/verifying TA_B for lookup or
> routing purposes, that may exist as non-authoritative transport/index metadata
> outside the canonical TA_B object. It must not become another hashed
> authoritative field.
>
> So the re-derived TA_B retains only material that cannot be recovered from
> the authenticated bundle/acceptance-leaf chain and is actually required to
> verify the acceptance proof.
>
> This does NOT mean trusting an unverified leaf:
>     b is authoritative only after the leaf and its path have been validated
>     against the independently established economic root.
>
> Do not preserve field 1 for convenience.
> Do not introduce a second b locator into the canonical object.
> Do not alter 0x0032 to compensate.
> ```

The invariant both rulings share, stated once: **one authoritative source per coordinate wherever
derivation permits it.** `G` survives because derivation does not permit it. `b` goes because it
does.

---

## §4 — `EconomicBundleAcceptanceState` — class `0x0032`, schema 1

A **substrate leaf state, nested in `0x001E` `EconomicLeafMutation`** — the same position in the
namespace its four siblings `0x001F`–`0x0022` occupy. It is a fifth arm of the economic state
family, not a new mechanism beside it.

| # | Field | Type | Notes |
|---|-------|------|-------|
| 1 | `bundle` (`b`) | `digest32` | the exact `SettlementBundle` this acceptance realizes |
| 2 | `economic_operation_id` | `digest32` | the authenticated economic operation identity this acceptance belongs to. **Not caller-authoritative** — §7 requires it to equal `witness.economic_operation_id`, which is itself recomputed from `(G, DevID, C_dsm+)` |

**No field 3.** §9.1 requires the authenticated content to commit *"at least `b`"*; ruling D2's
invariant forbids adding anything recoverable from `b`, and `b` commits `X`, the trader coordinates,
the selected route and every `T_v`. In particular the leaf does **not** carry `C_dsm+`: the
abstraction boundary between DSM transition context and the economic tree is
`economic_operation_id` (ruling D3), and reaching back through it to restate the raw successor
would be the second representation ruling D2 refuses.

Field 2 follows the `0x0022 EconomicConsumedSourceState` precedent exactly: that leaf carries
`consumer_economic_operation_id` and the verifier requires it to equal the witness's, which is what
turns a bare marker into an attributable one. Here it does the same job **and** fixes the position.

**Validity, stated as rejections.** A bundle-acceptance leaf is invalid if `bundle` is all-zero, if
`economic_operation_id` is all-zero, or if its CCB does not re-encode canonically to the bytes
presented.

---

## §5 — The leaf key: position stays operation-derived

Amendment 2c §9.1 fixes this and it is transcribed, not decided:

> **And the leaf's POSITION stays operation-derived even though its CONTENT cannot be.** The key is
> keyed to the authenticated economic operation identity, not to `b` and not to anything a caller
> chooses. Content commits `b`; position remains structurally tied to the exact accepted economic
> transition, preserving as much of the "key derived, never supplied" doctrine as the cycle allows.

### Ruling D3 — the identity is `economic_operation_id`, and it is the abstraction boundary

An earlier revision of this section read *"the identity of the exact accepted economic transition is
`C_dsm+`"* and had the key take the raw successor. The reasoning was right and the operand was one
step too far back. **`economic_operation_id` already IS that identity, canonically**, and §9.1's own
words name it: *"keyed to the authenticated economic operation identity"*.

```text
economic_operation_id = H_dom(DSM/economic-operation-id/dsm/v2, G ‖ DevID ‖ C_dsm+)
```

It is a field of `0x001D`, and it is **recomputed and required to match** — never trusted. Its own
definition makes exactly the argument the earlier revision made from scratch: *"the id names WHICH
authenticated successor performed the operation; the operation digest names WHAT was performed. Two
successors can carry byte-identical operation bytes, so an id derived from the digest could not tell
them apart."* Choosing `operation_digest` instead would still name the operation but not the
transition, and would still let one operation applied to two parents collide.

> ```text
> RULING: Option 1.
>
> Amend the bundle-acceptance leaf to two fields:
>
>     bundle
>     economic_operation_id
>
> and derive its SMT position from:
>
>     bundle_acceptance_key(G, DevID, economic_operation_id)
>
> This is a normative correction to 2c-D §4/§5 and the corresponding
> registry entry. Amend the frozen text BEFORE implementing the leaf.
>
> Verification must require:
>
>     leaf.economic_operation_id
>         == witness.economic_operation_id
>         == recompute(G, DevID, C_dsm+)
>
> before the acceptance leaf can certify the bundle.
>
> The carried operation id is therefore not caller-authoritative.
> Its value is constrained by the independently verified transition.
>
> This preserves the intended property:
>
>     exact economic transition
>         -> exact economic_operation_id
>         -> exact acceptance-leaf position
>         -> exact accepted bundle b
>
> A different C_dsm+ produces a different operation id and therefore a
> different leaf position.
> ```

```text
bundle_acceptance_key(G, DevID, economic_operation_id)
    = H_dom(DSM/economic-bundle-acceptance-key/v1, G ‖ DevID ‖ economic_operation_id)
```

`position_material` is `(0x0032, [economic_operation_id])`, matching the family's shape — and unlike
the earlier revision, it can be answered from the state itself, which is what the family's method
signature requires.

**Why not thread `C_dsm+` through the leaf-key API.** `EconomicLeafState::leaf_key` takes
`(genesis, device_id)` and is called from 26 sites across six files. Adding the raw successor would
give four of five arms a parameter they ignore and would oblige every caller — including
`proof_artifact.rs` and the SDK admission flow — to acquire DSM transition context it otherwise has
no reason to hold. In the owner's words: *"`economic_operation_id` is the abstraction boundary.
`C_dsm+` establishes it; the economic SMT consumes it. The acceptance leaf should not reach backward
through that boundary and make every generic leaf-key caller understand DSM transition context."*
Having callers pass the operation id *separately* was also refused: it recreates the threading
problem and leaves the leaf body unable to state which operation identity it claims.

**Trade-off recorded by §9.1, unchanged:** keying on `b` would have made Req 21.17's mandatory
forged-root vector cheaper, because the expected leaf position would be computable from `B` alone.
Doctrine wins — a caller-chooseable position is a worse defect than a more expensive test fixture.

---

## §6 — `TraderAcceptance` — class `0x0011`, schema 1, re-derived

`ta_B = H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`. The `/v2` is the tag Rev 15 reserves
for this artifact and is **not** a schema version; the CCB schema is 1. **8,308 bytes**: 4 envelope
+ 32 `G` + 8 position + the 68-byte nested `0x0032` + 4 sequence count + 256×32 siblings. An earlier
revision of this section said 8,276, computed while `0x0032` still had one field; ruling D3 gave it a
second, and a nested object's size is the enclosing object's size. This class has never been
produced — the registry status is *"blocked — 2c-D"* — so this is a **first freezing, not an
amendment to frozen bytes**, and no schema is burned.

The artifact carries no signature of its own. §2.9's *"the signature is not a field"* applies
vacuously: there is no SoFi acceptance payload and no signing round to exclude.

| # | Field | Type | Notes |
|---|-------|------|-------|
| 1 | `trader_genesis` (`G`) | `digest32` | **carried authenticated witness.** Not recoverable from `b`; authenticated by reconstructing the `sigma_dsm` signing digest and verifying it under the independently established trader AK (ruling D1). Never authority before that check |
| 2 | `economic_position` | `u64` | **untrusted locator.** Where to begin the validity walk, never authority for its result |
| 3 | `acceptance_leaf` (`L_B`) | nested `0x0032` schema 1 | complete CCB per §2.7, with its own class and schema |
| 4 | `acceptance_path` (`π_B`) | sequence of `digest32` | exactly 256 siblings, leaf-to-root; a §2.5 sequence because position is tree depth and duplicates are legal |

**No field 5.** The five members of the superseded nine-field draft are gone for two distinct
reasons, and the distinction is the point:

```text
DROPPED — recoverable from the authenticated bundle b
    route_set_commitment (X)   MarketTerms.route_set_commitment
    trader_parent              MarketTerms.trader_parent
    trader_successor           MarketTerms.trader_successor
    trader_devid               operation_bytes.settler_devid — a field of the
                               frozen DlvSettleOperationPreimageV1 grammar that
                               G1 decodes and G2 re-encodes canonically.
                               NOT recovery_material.counterparty_devid: that is
                               only the trader's under a self-loop shape nothing
                               verifies (§12)

DROPPED — recoverable from the authenticated acceptance leaf
    bundle (b)                 acceptance_leaf.bundle, ruling D2
```

The draft's two negative rules survive verbatim and are strengthened by ruling D2 rather than
weakened:

- There is **no `ta_B` field and no receipt field**: the Def 14.2 public Receipt binds `ta_B`, so a
  reciprocal field here would be circular — `TA_B` would hash `L_B` while `L_B` contained a hash of
  `TA_B`.
- There is **no `post_economic_root` field**. The root is *derived* by the walk from fields 1–2;
  carrying it would invite a verifier to read the carried value instead of deriving it, which is the
  entire failure Req 21.17 tests for. Ruling D2 applies exactly that reasoning to `b`.

**Validity, stated as rejections.** A `TA_B` is invalid if `acceptance_path` is not exactly 256
elements; if `acceptance_leaf` does not decode as a canonical `0x0032` schema 1 leaf; or if
`trader_genesis` is all-zero.

Note what is *no longer* a validity rule: the draft's `acceptance_leaf.x != route_set_commitment`
check is gone with both operands. `X` is inside `b`, `b` is inside the leaf, and the leaf is
authenticated under the root — the equality is established by the chain rather than asserted by the
wrapper, which is Blocker 1's whole complaint.

### Producer adoption — `TA_B` becomes reachable (owner ruling, 2026-09-10)

The owner ruling on producer reachability decomposes the remaining work into three changes, and this
is the second:

```text
PR A   bundle-aware settle write set; the 0x0032 leaf becomes mandatory
       -> the acceptance leaf is guaranteed to EXIST
PR B   construct and publish TA_B from the resulting economic post-state
       -> TA_B is guaranteed to be CONSTRUCTIBLE and REACHABLE
PR C   the realization / fence-release cutover
       -> live realization is ALLOWED to consume it
```

**Where the path comes from, and where it must not.** `TA_B` proves the acceptance leaf's inclusion
under `R_T^+`, so its path is the one that holds in the FINAL economic post-state. A mutation's own
captured siblings are not that path: the write set captures mutation `i`'s siblings with mutations
`0..i` applied, and the acceptance leaf's key is a hash, so nothing places it last. The producer
therefore reads the finished tree — the same single snapshot whose root was registered, with no
second read and no window in which the tree could move — and refuses when that tree is not the one
the register committed.

```text
economic post-state containing 0x0032 obtained
    -> ordered inclusion path for that leaf under R_T^+
    -> TA_B built from the already-authenticated settlement facts
    -> published through the durable publication path
```

**The identities are consumed, never chosen.** `b` and `economic_operation_id` arrive inside the
emitted leaf, lifted out of the witness; there is no parameter through which a caller could supply
either. `trader_genesis` is the authenticated local identity and `economic_position` the position
the register just committed. A producer that reconstructed any of these would be asserting a second
time what the transition already fixed.

**What producing `TA_B` does not do.** It publishes an artifact. It does not call
`CompleteValidity::from_market_witness`, release the trader fence, mark the settlement realized,
advance the realized frontier, or publish a final realized receipt — and it constructs no
`BundleAcceptanceWitness`, whose only constructor is §7's verifier and which additionally requires
the composed bundle and an independently established trader AK. Those remain the dedicated
behaviour-changing cutover, for the reason §11's boundary note gives: one change, so that *"nothing
released before it"* stays checkable rather than argued.

---

---

## §7 — Verification obligations, in order, all conjunctive

The order is normative. Each step may only use facts the steps above it established.

1. **Decode and shape.** `TA_B` decodes canonically; `acceptance_path` is exactly 256; the nested
   `0x0032` re-encodes to the bytes presented; `trader_genesis` is non-zero.

2. **Authenticate `G`.** Recover `DevID` as `operation_bytes.settler_devid` and `C_dsm+` as
   `MarketTerms.trader_successor` from the bundle under verification — both already checked by
   G1–G4, so neither is a fresh trust. Reconstruct
   `H_dom(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖ operation_digest)` from the carried
   `G` and the bundle's own `0x0031`, and verify `sigma_dsm` under the **independently established**
   trader AK. `G` is a supplied value until this succeeds and an authenticated one after
   (ruling D1). A failure here is INVALID, never INCOMPLETE.

   **The DevID conjunct this route makes necessary.** The `DevID` in the signing digest and
   `operation_bytes.settler_devid` are two different appearances of the trader, and G1–G4 do not
   relate them: G4 recomputes the chain tip from `counterparty_devid`, not from `settler_devid`, and
   the signature would still verify if the signing digest named a DevID other than the one being
   credited. So step 2 **must** require the DevID it reconstructs the digest with to be exactly
   `operation_bytes.settler_devid`, and reject otherwise. Without that conjunct a signature over one
   identity would authenticate a leaf key derived for another.

3. **Derive `R_T^+`.** Walk validity for `(G, DevID, economic_position)` per 2c-C2 §1.2, with `G`
   authenticated by step 2 and `economic_position` treated as an untrusted locator throughout. A walk
   that cannot complete is INCOMPLETE — retryable — **never** invalid.

4. **Require the accepted successor.** The walk's authenticated successor is exactly the bundle's
   `trader_successor`, from exactly its `trader_parent`. Both operands come from the bundle; neither
   is carried by `TA_B` any longer.

5. **Bind the operation identity, then fold the path.** Require

   ```text
   acceptance_leaf.economic_operation_id
       == witness.economic_operation_id
       == dsm_economic_operation_id(G, DevID, C_dsm+)
   ```

   with `G` authenticated by step 2 and `C_dsm+` the walk's own from step 4 — never anything `TA_B`
   supplies. Only then recompute the leaf key as
   `bundle_acceptance_key(G, DevID, economic_operation_id)`, take the leaf value from
   `CCB(acceptance_leaf)`, fold `acceptance_path`, and require the result to equal `R_T^+`.

   The three-way equality is what keeps the carried id from being caller-authoritative (ruling D3).
   Checking the leaf against the witness alone would not suffice: the witness's own id is only
   authoritative because it is itself recomputed against `C_dsm+`, and the middle term is what ties
   the acceptance to *this* transition rather than to any transition the witness happens to
   describe.

6. **Obtain `b` and bind it.** Read `b` from the now-authenticated `acceptance_leaf.bundle` and
   require it to equal the settlement bundle being composed or verified (ruling D2). `b` is
   authoritative only after steps 1–5; before them it is leaf bytes.

7. **Bind the economics.** `B`'s selected route and every `T_v` equal the authenticated settlement
   effects the walk validated.

A `TA_B` satisfying all seven realizes `B` — **and only together with `B` being binding-final.**
Acceptance is a precondition of realization, never its trigger.

---

## §8 — The two-conjunct rule is the security boundary

Amendment 2c §9.1 is the reason this object is checked for presence and shape and nothing more, and
it is transcribed here because it is the one rule an implementer will otherwise weaken invisibly:

> **`b` becomes the first economic post-state fact that is not derivable from `Operation::DlvSettle`
> itself.** […] Every existing economic leaf has its content bound to the operation by
> `verify_operation_write_set`. This one structurally cannot be. It can be checked for **presence
> and shape** (`pre: None`, write-once) and nothing more.

```text
Economic validity establishes:
    exact accepted DlvSettle successor
    + exact operation-derived balance effects
    + exact per-vault settlement receipt(s)
    + exactly ONE bundle-acceptance leaf associated with this economic operation

TA_B realization separately establishes:
    recompute canonical B -> exact b
    + establish B is binding-final
    + bundle-acceptance leaf.value == b
    + B.trader_parent/successor == authenticated accepted successor
    + B's selected route / T_v economics == the authenticated settlement effects
```

### Producer adoption — the cardinality transition (owner ruling, 2026-09-10)

The rule tightens when, and only when, its input starts existing. Recorded explicitly rather than
narrowed silently, so the history stays coherent:

```text
#845, TRANSITIONAL:   market BundleAcceptanceLeaf cardinality <= 1
producer adoption:    every qualifying market DlvSettle produces EXACTLY ONE
other operations:     cardinality == 0 unless separately specified
```

#845 deliberately established the admission machinery **without** changing existing settles: a
settle carrying no acceptance leaf stayed valid, because nothing could yet produce one and a
mandatory rule would have invalidated every settle already shipped. That was the right rule for
that moment and the wrong rule to keep. Leaving it at *at most one* after a producer exists
preserves a legal execution that can never obtain a `TA_B` — a nominally valid market settlement
that becomes permanently `PartialPendingRealization` for no protocol reason.

The producer emits

```text
BundleAcceptanceLeaf { bundle: b, economic_operation_id: recompute(G, DevID, C_dsm+) }
    at bundle_acceptance_key(G, DevID, economic_operation_id)
```

**Where `b` comes from, and where it must not.** `b` is not intrinsic to the DLV operation; it is
the identity of the exact settlement bundle being composed *around* that operation. It enters
economic write-set construction through a settlement-specific typed context, established upstream
from the canonical `B`:

```text
canonical B established -> derive exact b -> DlvSettle write context { bundle_id: b }
    -> build_write_set -> the acceptance leaf
```

The builder must **not** derive `b` itself, fetch it from Class N, read it from the operation bytes
or the authenticated operation facts, accept it as an optional digest a caller may omit on a market
settle, or reconstruct a second `B` to recover it. Threading it through every call site is the
point: it forces each producer of economic state to account for whether it has settlement-bundle
context.

`economic_operation_id` stays independently derived from the authenticated transition. Threading
`b` in must not make the operation identity caller-authoritative — the three-way relation of ruling
D3 depends on those two facts having different origins.

**Neither conjunct is sufficient alone**, and the write-set half must say so in the code rather than
imply it. `verify_operation_write_set` gains a `0x0032` arm that requires `pre: None`, requires
`economic_operation_id` to equal the enclosing witness's, requires the key to equal
`bundle_acceptance_key(G, DevID, economic_operation_id)`, and requires **exactly one** such leaf per
economic operation. It must **not** attempt to validate
`bundle`: it structurally cannot, and an arm that appears to check the content is worse than one
that visibly declines to.

---

## §9 — `BundleAcceptanceWitness` gains its only constructor

2c-C4 shipped `BundleAcceptanceWitness` as a `PhantomData` with no constructor and
`IndependentRealization::from_parts` waiting on it. That seam is this amendment's:

```text
BundleAcceptanceWitness
    constructible ONLY by completing §7 steps 1-7 against a binding-final B
    private fields; no public constructor; no Default; no Clone-from-parts path
```

Holding one **is** the fact that §7 succeeded, in the same way holding a
`MarketCorrespondence` is the fact that the correspondence check returned. C4's boundary is then
satisfied by construction rather than by discipline:

```text
    C3 validity
        -> C4 accepted successor / realization predicate
            -> 2c-D exact-b binding witness          <- HERE
                -> constructible IndependentRealization
                    -> realized market frontier
```

Ruling R1's prohibition still binds everything above this line: a market fold **must not** be
promoted to realized from correspondence alone, and nothing outside §7 may mint the witness.

---

## §10 — §7a's wording, corrected

Per ruling D1, amendment 2c §7a's row for the `TraderAcceptance` field table is corrected from

> Must be re-derived: with the leaf authenticating `b`, the coordinates and `X` are inside `b` and
> stop being separate fields.

to

> Must be re-derived: drop fields **recoverable from the authenticated settlement bundle `b`** —
> `X`, `trader_parent`, `trader_successor` and `trader_devid`. `trader_genesis` is **not**
> recoverable from `b` and is retained as a carried authenticated witness (2c-D ruling D1).

The old wording is not merely imprecise: taken literally it deletes the one coordinate the walk
cannot proceed without.

---

## §11 — What the adopting change owes

```text
1  registry: a §3 row and a §5 section for 0x0032; the 0x0011 row moves from
   "blocked — 2c-D" to defined, with the four-field table of §6.
   0x0032 leaves the "claimed in prose" list. Nothing is burned: 0x0011 has
   never been produced and 0x0032 has never existed.

2  the domain tag DSM/economic-bundle-acceptance-key/v1, added to all_tags()
   so `all_tags_are_unique` and `all_tags_have_expected_prefixes` cover it.

3  EconomicBundleAcceptanceState: the CCB object, a fifth EconomicState arm,
   its class()/position_material()/leaf_key()/encode() rows.

4  verify_operation_write_set's 0x0032 arm, per §8 — presence and shape only,
   with the "exactly one per economic operation" cardinality enforced.

5  TraderAcceptance: the CCB object and the §7 verifier, in that order,
   returning the frozen INVALID / INCOMPLETE split (step 2 invalid,
   step 3 incomplete).

6  BundleAcceptanceWitness's constructor, reachable only from §7's success;
   the compile_fail doctests in successor_validity.rs updated, since the
   type they assert is unconstructible now has a constructor and the
   assertion must move to "not constructible except through §7".

7  class-1 conformance vectors for 0x0032 and 0x0011 from an INDEPENDENT
   encoder, never the production encoder under test.

8  Req 21.15's realize half and Req 21.16 in full. Req 21.16 verifies the
   published Receipt's facts as the EconomicSettlementReceiptState leaf the
   settle write set committed, included under the INDEPENDENTLY VALIDATED
   economic root `R_T^+` — never under a root the Receipt itself carries, and
   never under the legacy device-SMT `post_root`, which has no independent
   source (2c-C4 §9, D4 as corrected 2026-09-11). §7 and Req 21.16 read two
   different leaves under one validated root.

9  the fifteenth Lean module's successor, or an extension of
   DSMAcceptedSuccessorWalk, discharging §7's ordering and the two-conjunct
   rule; the CI pin moves with it.

10 mutation controls, each showing a NAMED test go red by performing the
   forbidden action:
   - a leaf at a caller-chosen key -> rejected;
   - leaf.economic_operation_id != witness.economic_operation_id -> rejected;
   - a witness id not equal to recompute(G, DevID, C_dsm+) -> rejected,
     even when the leaf agrees with the witness;
   - two bundle-acceptance leaves in one operation -> rejected;
   - a leaf whose bundle != the composed B -> realization refused at §7.6;
   - G supplied but sigma_dsm not verified -> §7.2 must refuse;
   - a valid TA_B against a B that is NOT binding-final -> no realization;
   - a sigma_dsm signing digest whose DevID != operation_bytes.settler_devid
     -> §7.2 must refuse, even though the signature itself verifies;
   - a witness minted anywhere but §7 -> must not compile.
```

### The boundary between item 8 and the cutover (owner ruling, 2026-09-10)

**Item 8 completes the realization predicate. It does not make realization live.**

#847 made `BundleAcceptanceWitness` constructible once §7 succeeds. Item 8 —
Req 21.15's realize half and Req 21.16's independently-rooted receipt
verification — finishes the *evidence*: after it, everything
`IndependentRealization` requires is checkable. Nothing about that changes what
the system does.

```text
Req 21.15 realize-half + Req 21.16          verification machinery
        |
        v
all evidence required for IndependentRealization is CHECKABLE
        |
        v
realization / fence-release cutover         the behavioural change
        |
        v
the live composition walk may actually realize,
release the trader fence, and permit final receipt publication
```

**Why this is a rule and not a preference.** If the first live behaviour change
is smeared across two changes, it stops being provable that nothing releases
early — a reviewer would have to establish the negative across both, and the
one PR that flips market settlement from bound-but-unrealized to realized would
no longer be identifiable. Keeping the cutover to exactly one change is what
makes "nothing released before it" checkable rather than argued.

So item 8 must add no fence release, no receipt publication, no promotion of a
market fold out of `PartialPendingRealization`, and no call site that
constructs an `IndependentRealization`. It adds the last verifier, and stops.

---

## §12 — Scope

**Not in this amendment.** `verify_market_leg_policies` and the SoFi Def 4.1 / Req 4.4 / Req 4.6
token-policy conjunct — reached from inside the walk and belonging to neither 2c-C nor 2c-D. The
`0x000E` / `0x000F` / `0x0033` / `0x000B` / `0x0031` field tables, permanently frozen by 2c-A and
2c-B under §2.8 and untouched here. `TokenPolicyValid` and exactly-once owner credit remain declared
external obligations.

**No schema moves.** Ruling D1 forbids bumping `0x0031`, `0x0033` or `0x000E` for the `G` question,
and nothing else here nests into them. No market vector constant is regenerated by this amendment,
and 2c-E §8.4's one-time genuine-producer regeneration was consumed by the 5c-2 producer and is not
reopened.

**Formal-model coverage.** Not claimed by this document. It is owed by §11 item 9.

### An observation recorded, deliberately not depended on

`market_producer.rs` states as fact that *"a market settle advances the trader's self-loop and the
vault owner never signs it"*. **Nothing verifies it.** `check_market_evidence`'s G4 recomputes
`relationship_chain_tip_v2` from the carried `rel_key`, `embedded_parent` and `counterparty_devid`
and requires the result to equal `trader_successor` — that makes the tuple self-consistent and binds
`counterparty_devid` to the successor, but it does not establish that `rel_key` is
`compute_smt_key(d, d)` for the settler `d`, so a bundle whose counterparty is some other device
satisfies G1–G4.

Whether market settlement *must* be a self-loop is a question this amendment does not answer and
does not need to: 2c-D routes the trader's DevID through `operation_bytes.settler_devid` precisely
so that no part of §7 rests on the unverified shape. Recorded here because the producer's comment
asserts it as a property, and because a later change that *does* depend on it would be depending on
a convention rather than a check.

---

## §13 — Verification this document's adopting change must pass

```text
cargo test --locked --workspace --exclude dsm_storage_node --release \
    -- --nocapture --test-threads=1
make lint                                  (repo root, pinned 1.98.0)
bash ci/production_safety_checks.sh
lean -DwarningAsError=true on every module, with the CI pin updated
```

Class-1 conformance is per 2c-C2 ruling D: expected bytes produced by an independent encoder.
`ccb_conformance.rs` is an independent-encoder cross-check with zero frozen byte literals and is
therefore **not** a class-1 source — but its `live_schemas_match_the_registry_and_none_is_burned`
pins live `(class, schema)` pairs, and adding `0x0032` without updating that table is how a green
branch reddens `main`. That has happened once already (#829, corrected by #830): the sweep looked
for tests pinning BYTES and missed the one pinning SCHEMA NUMBERS.

---

## §14 — The realization cutover (C2): owner rulings, 2026-09-11

PR C is split in two. C1 (#854) corrected Req 21.16's root (2c-C4 §9, D4 as corrected). C2 is the
one behavioural change: the first change that may move a bound market settlement from
bound-but-unrealized to realized. Before any live path was edited, a source survey answered the two
questions the cutover could not assume, and the owner ruled on the answers.

**What the survey established.**

```text
receipt objects
    TraderSettlementReceiptV1   the ONLY receipt-shaped object in code; stored at
                                sofi/vault-receipt/{vault}/{x}; NO production producer;
                                three live consumers, all on the legacy self-verifying check:
                                  the walk's 5-c-1 gate, dlv_reconcile (owner apply),
                                  unapplied_settlements_for_vault (owner display)
    Def 14.2 public receipt     binds ta_B; NOT implemented; the Rev 15 text is not in-repo
CORR.4                          frozen as semantics only; the two digests carrying it have
                                no production producer, so CORR.4 is unreachable live
Tier-1 intent satisfaction      NOT enforced on any live path; the 5-c-1 RouteCommit gate
                                C2 deletes is its only enforcement point
storage_put_bytes               returns Ok when ONE node accepts; not quorum-durable
```

`dlv_reconcile` is a live receipt-as-authority path independent of C2: a forged, internally
consistent V1 that prices correctly against the owner's composed parent would drive an owner
`DlvOwnerApplyV2`, move the owner's reserves (no economic admission runs on that path), and consume
the generation's consume-once claim. It is latent only because nothing produces V1 live. C2 would
make V1 live, so C2 closes it.

### Ruling C2-R1 — post-certification receipt handling

> ```text
> RULING — C2-R1: post-certification receipt handling
>
> TraderSettlementReceiptV1 (SignedTraderSettlementReceipt) is the existing
> Req 21.16 correspondence artifact stored at
> sofi/vault-receipt/{vault}/{x}.
>
> It is NOT identified with the Def 14.2 public receipt. Def 14.2 remains a
> separate owed publication artifact because its frozen construction binds ta_B
> and no such construction presently exists in production code.
>
> For C2:
>
> 1. The settling trader may construct TraderSettlementReceiptV1 locally before
>    publication solely so the composition walk can run Req 21.16 against the
>    independently validated R_T^+.
>
> 2. The walk remains the only certifier. The locally constructed receipt is
>    evidence to Req 21.16, never authority and never self-certification.
>
> 3. A market fold may reach may_certify() only after Req 21.16 and every other
>    required correspondence/validity predicate succeeds.
>
> 4. After may_certify(), TraderSettlementReceiptV1 MUST be durably published
>    before the trader fence is released or the realized/composed frontier is
>    allowed to advance past the settlement.
>
>    Publication failure therefore leaves the settlement bound but unrealized
>    and the fence held. A receipt already published before a crash is harmless:
>    it carries no independent authority and another walk must still certify it.
>
> 5. A foreign walk with no published V1 returns ABSENT / pending realization,
>    not INVALID and not realized.
>
> 6. No live consumer may treat V1 as settlement authority:
>       composition walk                Req 21.16 evidence only
>       dlv_reconcile                   exact certified fold only
>       unapplied_settlements_for_vault certified-but-unapplied folds only
>
>    Receipt existence alone MUST NOT constitute "certified". Certification must
>    originate from the validated composition walk or from a durable local cache
>    whose contents are tied to that exact certified fold and are not themselves
>    authority.
>
> 7. The legacy V1 fields post_root, smt_siblings, trader_public_key and
>    trader_signature may remain populated for compatibility, but C2 validity
>    does not depend on them after #854.
>
> 8. verify_trader_settlement_receipt is removed from the authority path.
>    fetch_verified_receipt becomes transport/decoding only:
>    Absent / Unavailable / Malformed / Decoded.
>
> 9. The Def 14.2 receipt and Q publication remain separately owed and C2 must
>    not claim that publishing V1 satisfies those requirements.
> ```

**Why publication precedes release (point 4).** A same-step publish-and-release is not atomic across
a distributed boundary. If the fence released and the process died before V1 became discoverable,
every foreign composer would lose the evidence R1 itself requires. Publishing first is safe because
the receipt is non-authoritative; a crash afterward leaves a discoverable receipt and a still-held
fence, which recovery can finish.

### Ruling C2-R2 — CORR.4, typed

> ```text
> RULING — C2-R2: CORR.4, typed
>
> CORR.4 compares typed values, not digests. effects_digest and
> route_effects_digest are removed from AcceptedTransition and BundleCoordinates.
> No domain tag is added.
>
> LEFT (the accepted operation's balance effects): the DlvSettle returned by the
> lineage walk (ValidatedPeerTransition.verified_operation). It is never taken
> from the bundle's recovery_material and never from the published receipt.
>
> RIGHT (the selected route's T_v economics): in beta (2c-A ruling 3) the route
> must be exactly one RouteLeg::Single(alloc), and |{T_v}| must be 1. Any other
> shape is INVALID, as not specified for this profile.
>
> CORR.4 requires each of these equalities separately:
>     alloc.parent_binding  == op.parent_binding == T_v.parent_binding
>     alloc.delta_in        == op.input_amount
>     alloc.delta_out       == op.output_amount
>     alloc.fee_policy bps  == op.fee_bps
>
> Before successor derivation succeeds:
>
>     {op.input_policy_commit, op.output_policy_commit}
>     MUST equal the cursor's canonical market pair in one permitted orientation,
>     and derive_direction MUST succeed for that exact orientation.
>
>     No unknown asset, same-side asset, reversed-disallowed direction, or foreign
>     policy commitment may reach successor comparison.
>
> Pricing and the T_v movement belong to CORR.5, through the existing
> derivation:
>     expected = derive_market_successor(cursor, c_n,
>                  { op.input_policy_commit, op.output_policy_commit,
>                    op.input_amount, cursor.fee_bps })
>     op.fee_bps          == cursor.fee_bps
>     op.parent_sequence  == cursor.generation
>     derived output      == op.output_amount
>     Canon(expected)     == T_v.successor bytes          (10.a)
>
> CORR.4 ties the operation to the route; CORR.5 ties the operation to T_v.
> Neither one alone establishes "priced as B's route says."
>
> Intent satisfaction is not part of CORR.4.
>
> However, may_certify() MUST remain unreachable unless the existing Req 14.x
> Tier-1 intent-satisfaction predicate has succeeded for the authenticated
> TradeIntent and selected route.
>
> If that predicate is already live in the composition walk, C2 reuses it.
> If deleting 5-c-1 removes its only live enforcement point, C2 MUST re-source
> it before enabling realization.
>
> Lean: 2c-C4's balanceEffects == routeEconomics over abstract values is
> unchanged, because typed field equality refines it. No Lean change.
> ```

**The owner-apply boundary.** The owner's apply bypassing economic admission may remain separately
owed only if C2 proves it cannot invent or modify economics: it may do nothing except apply the exact
already-certified fold. C2 carries a regression test for that invariant even though the admission
refactor itself stays outside C2.

### Determinations under these rulings (source facts, not new rulings)

**D-a. Tier 1 is re-sourced.** No live path enforces intent satisfaction; the 5-c-1 RouteCommit gate
C2 deletes is its only enforcement point. Under C2-R2's conditional clause C2 therefore re-sources it,
and the predicate is 2c-E §6's SAT.1–SAT.6 transcribed — not 2c-A's original Tier 1, whose
`min_out`, `max_fee`, `max_hops`, `max_fanout` and `k` 2c-E removed from `TradeIntent`. The signed
RouteCommit SAT.2–SAT.4 read is the lineage-verified operation's own `route_commit_bytes`, which
`sigma_dsm` covers — never a RouteCommit fetched under a storage key.

**D-b. "Durably published" is quorum publication.** `storage_put_bytes` returns `Ok` when one node
accepts, so it cannot discharge C2-R1 point 4. V1 is frozen as a publication artifact under
`sofi/vault-receipt/{vault}/{x}` for the vault's canonical storage set, and is durably published when
`is_artifact_published` holds — at least `set.quorum()` members of that set accepted the exact bytes.
The fence is not released before that.

**D-c. `TA_B` is located, not named.** `B` is bound before `TA_B` exists, so the walk locates it
through a non-authoritative locator keyed by `b`, carrying `ta_B` and the address of the admission's
economic proof artifact (which holds both the acceptance leaf and the settlement-receipt leaf with
their paths under `R_T^+`). It is frozen with `TA_B` at admission. It is evidence for finding the
artifacts, not the receipt publication §7 of 2c-C4 gates, and a locator naming wrong bytes fails at
§7 or at Req 21.16 rather than being believed.

**D-d. `PartialPendingRealization` is deleted.** Its only constructor was the 5-c-1 market arm C2
deletes. The walk folds only what `may_certify()`: a market parent whose evidence is absent or
unavailable is the bound-but-unrealized frontier, not a provisional fold, and present-and-failing
evidence is INVALID. `may_fold()`, which differed from `may_certify()` only on that variant, goes
with it, and `C3Verdict::class()` becomes total.

**D-e. The self-referential receipt verifier is deleted.** C2-R1 point 8 takes it off the authority
path and no other path calls it, so `verify_trader_settlement_receipt` is removed together with the
two `ReceiptError` variants only it produced. `fetch_receipt` is the one read of V1 — Absent /
Unavailable / Malformed / Decoded — and Req 21.16 (`verify_published_receipt`) is the only receipt
verifier.

**D-f. The completion resumes; it never retries.** A settlement whose V1 misses quorum returns
bound-unrealized with its fence held. `resume_settlement_completion` finishes that SAME settlement and
nothing else. Its work list is this device's fences whose binding COMMITTED and whose exact successor
is not yet released (`list_acceptance_pending_fences`), run from the storage sync beside the
close-intent resume. For each it re-reads the fence at exactly (chain, parent, `tx_id`), fetches the
bound bundle by `b` and re-hashes it (digest = `b`, address = the fence's `value_addr`), requires the
bundle's own parent and successor to be the fence's, and takes the trade from the bound operation —
never from a receipt. Completion then runs the one path the settle route runs: the exact frozen V1 is
recovered when one exists and built once otherwise; the walk re-certifies with it as Req 21.16's
evidence; V1 reaches quorum, and an exact V1 already at quorum is not re-sent; only then is the exact
fence released, and releasing a fence already released is not an error.

The resume creates no binding round, no transition, no admission and no other settlement, changes no
fact, and never releases on a cached status or a timeout: the fence row locates the work and is not
authority. Receipt publication precedes fence release on both paths. Absent, unavailable or
below-quorum evidence leaves the fence held and the outcome pending — never INVALID; coordinates or
facts that do not match are refused, and the fence stays held. The ordering, idempotence and exactness are
machine-checked in `lean4/DSMSettlementCompletion.lean`.

**D-g. Later generations draw reserve provenance from the composed frontier (conformance repair).**
This is not a new protocol rule; it restores the normative SoFi composed-state model, in which the
current DLV state is the latest authenticated owner baseline plus every subsequently realized market
successor, folded in order, and the LP need not return between generations. The implementation had
drifted from it: `DlvReserveConsumption` provenance accepted only owner vault-reserve leaves at
exactly the consumed generation, and only the owner's own admitted apply produces those, so a
delegated market could not advance past generation 0 while its LP was absent. The same rule now
holds at every generation: the owner's proof backs the reserves at ONE baseline generation `g`; at
`g` the parent states exactly those reserves; past `g` the parent must be exactly the state the
composition walk reaches at its commitment from that baseline, passing through `g` with the owner's
reserves, one linked generation at a time. The walk folds a market successor only once the full C2
certification boundary holds, so an uncertified, merely bound or merely published successor never
authorizes the next generation. Composition for this purpose stops AT the requested state and never
reads the binding there, so the provenance of settlement n never depends on settlement n: certifying
settlement n establishes `V_{n+1}`, admitting settlement n+1 consumes it, and the recursion runs
strictly down the generations. Owner catch-up remains optional synchronization of already-realized
history; it authorizes nothing. The rule, its soundness, each conjunct's necessity and the stop-at-target
composition are machine-checked in `lean4/DSMComposedReserveProvenance.lean`, and
`lean4/DSMAcceptedSuccessorWalk.lean` now states that the walk folds exactly what certifies (D-d).

The settle route runs that one rule — `check_composed_reserve_provenance` — BEFORE `bind_settlement`,
over the same owner proof and the same composed history, and refuses there. Previously the route
bound first and only then discovered that admission would refuse, leaving the generation bound with
no admissible continuation. A qualifying COMMIT, once reached, remains authoritative; the preflight
only ensures one is never reached for a trade admission would deterministically refuse.
