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
for this artifact and is **not** a schema version; the CCB schema is 1. This class has never been
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

8  Req 21.15's realize half and Req 21.16 in full.

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
