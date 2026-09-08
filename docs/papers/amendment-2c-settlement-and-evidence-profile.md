# Amendment 2c — Settlement and evidence profile (decomposition)

Status: **DECOMPOSED. Do not begin an encoder from this document.** 2026-09-07.

2c is four amendments — 2c-A through 2c-D — in the order §0a fixes. This document is the
decomposition, the shared findings, and the routing of already-researched material to the
sub-amendment that owns it. It claims neither encoding closure nor verification closure (§0b),
and does not claim formal-model coverage (§0c).

Normative and encoder-free, per the registry preamble.

> **Field-path shorthand.** In diagrams and code blocks below, `B.trader_parent` /
> `B.trader_successor` / `B.selected_route` / `B.route_set_commitment` abbreviate
> `B.market_terms.*` under 2c-A: they are members of `MarketTerms` (`0x0033`), not of
> `SettlementBundle`, and an **owner close carries none of them**.
Governs `docs/papers/ccb-object-registry.md` classes `0x000E`, `0x0033`, `0x000F`, `0x0010`, `0x0011`,
and implements the already-defined `0x000B`.

Written for the 5c-2 implementation
(`docs/plans/2026-09-07-5c-2-market-realization-acceptance-artifact.md`). §7 of the registry
requires amendments in order and not combined; 2a and 2b are complete, so this is next.

**Spec first, encoder second.** §6 of the registry: *"None of them should be resolved by
writing an encoder."* Nothing below is derived from a Rust type. Where a shipping type exists
it is cited as evidence of what the implementation does, never as authority over what the
protocol is (§7).

---

## 0a. This is a decomposition, not a single amendment

Review and five research passes established that 2c cannot be written as one document. The
dependency graph is doing useful work here: it shows **which identities must be frozen before
downstream evidence can have stable meaning at all**, which is exactly what "spec first, encoder
second" was meant to expose.

2c is therefore four amendments, in this order and not combined. Each becomes its own document;
this one is the decomposition and the shared findings.

| | Amendment | Freezes | Why it must precede the next |
|---|---|---|---|
| **2c-A** — **WRITTEN** ([doc](amendment-2c-a-bundle-and-transition.md)) | Bundle and transition | `0x000E` and `0x0033 MarketTerms` **A-stage frozen**; `0x000F` and `0x0010` fully defined; real `I` `0x000B`; and **`b`'s derivation and outer canonical structure fixed** | Everything downstream names `b`. Until `b`'s derivation and structure stop moving, no evidence object that commits it has stable meaning. **A conforming market `b` is NOT constructible from 2c-A alone** — `MarketTerms` field 6 is mandatory and its nested class is 2c-B's. The owner-close shape IS complete. |
| **2c-B** — **WRITTEN** ([doc](amendment-2c-b-accepted-successor-and-recovery.md)) | Core accepted-successor prerequisite | a substrate class for the exact accepted-successor / recovery preimage | `TA_B` and `recovery_material` both reference it. It must not be the existing prost bytes canonized. ~~It is now also the sole blocker on complete market `Canon(B)`~~ — **CLOSED by 2c-B**: substrate `0x0031` (registry §5.23) fills `MarketTerms` field 6, and a conformant market `b` is constructible. §6.3's `c_dsm_plus` row is superseded by 2c-B ruling 1; §6.2's "disclosure already made and shipped" is corrected by 2c-B ruling 4. |
| **2c-C** — **DECOMPOSED into C1–C4** ([doc](amendment-2c-c-verification-closure-decomposition.md)) | Economic substrate closure | the namespace record, plus the transitive verification closure `TA_B` actually needs | `TA_B`'s verifier runs this walk. Assigning class numbers is *encoding* closure, not *verification* closure. **A four-dimension source audit found ~26 open decisions and §2 framework extensions required before the economic classes can be expressed, so 2c-C ships as C1 framework+namespace, C2 verification substrate, C3 `ValidDlvSuccessor`, C4 the `TA_B` closure — C4 consuming C3 as well as C1/C2.** |
| **2c-D** | Realization | `TA_B` `0x0011` + the bundle-acceptance leaf | Depends on all three above being stable. |

**2c-C's scope is deliberately asymmetric.** Record *every* already-allocated class number so
accidental reallocation becomes impossible — but do not fully specify every unrelated economic
class. Fully specify only the transitive closure `TA_B` verification actually reaches: the root
claim, manifest, witness, mutations, the relevant leaf states, the relevant provenance
descriptors, the addressing rules, the SMT rules, register resolution, and P0–P6 verification.

### 0b. Two closure statuses, and this amendment claims neither

A single "closed / open" label has been hiding a real distinction:

```text
CCB encoding closure
    Can two independent implementations derive identical committed bytes?

Verification closure
    Can two independent implementations independently establish the same validity
    result from those bytes and the specified evidence?
```

For the full realization path this document currently has **neither**. After 2c-C's class tables
land it may have encoding closure while verification closure remains open on root resolution,
P0–P6, immutable addressing, SMT bit ordering and similar algorithms. Each sub-amendment states
its own two statuses; none may claim closure it has not demonstrated.

### 0c. Formal-model coverage

No current formal model covers the economic-admission lineage, bundle-acceptance state, or the
`TA_B` realization predicate. **This amendment therefore does not claim formal-model coverage for
that layer.** Conformance, mutation and crash-recovery vectors are the current executable
assurance mechanisms; formalization remains a separate assurance item.

This is stated rather than left implicit because the repository's standing rule is to align the
formal models in the same change as the code, and a silent omission would read as a skipped step
rather than an absent model. Absence of the model is not by itself a blocker to 5c-2 unless the
release gate requires it.

### 0d. The single-vault / multi-vault question — **SETTLED by 2c-A ruling 3**

> **Resolution.** The beta market `SettlementBundle` carries **exactly one `T_v`**, and the field
> remains a §2.4 **set** so plural `{T_v}` needs no schema bump later. Because `B` carries the DLV
> continuations it realizes, one `T_v` also forces the beta market route to exactly one leg holding
> one bare `0x0015` Allocation — single-hop, fanout 1. This narrows what one bundle makes
> binding-final; it does not narrow what the routing layer may discover or reason about.
>
> **Unblock condition, stated normatively:** enabling multi-DLV atomic settlement requires a
> separately specified ordinary-DSM operation whose authenticated trader successor and economic
> write set cover every `T_v` in the bundle. See
> [`amendment-2c-a-bundle-and-transition.md`](amendment-2c-a-bundle-and-transition.md) ruling 3.

The original statement of the question is retained below as the record of what was open.

Production `DlvSettle` is **one-vault**: one `vault_id`, one parent generation, one input/output
pair. The live market bundle carries exactly one transition. But the normative bundle and routing
model permits plural `{T_v}` and allocation fanout.

A bundle-level acceptance leaf fixes the **evidence** problem — one authenticated bundle identity
however many DLVs were consumed — but it does **not** explain how one singular trader successor
economically executes several `T_v`. That mismatch must not hide behind the `b` commitment.

2c-A must make exactly one of these normative:

```text
beta SettlementBundle market shape = exactly one T_v

    -- or --

one accepted trader successor has a canonical multi-vault settlement operation
whose write set covers every T_v in B

    -- or some other explicitly specified atomic construction --
```

---

## 0. Scope, and one thing this amendment must not do

Rev 15 Def 6.26 and Def 14.1 describe the trader-acceptance artifact `TA_B` in terms of an
ordinary DSM accepted-successor commitment `C_T^+` that itself commits a post-advance
authenticated state root `R_T^+`.

DSM has no such commitment. `relationship_chain_tip_v2` — the one canonical successor
commitment — commits the relationship key, the consumed parent, the counterparty, the operation
bytes and the entropy. It does **not** commit any state root, and the successor evidence's
signature digest does not cover one either.

There are two wrong ways out of this, and this amendment takes neither:

- **Do not extend ordinary DSM successor commitments for SoFi's benefit.** DSM already has a
  purpose-built authenticated economic-root layer. Bending the substrate to match SoFi prose
  would put a SoFi requirement inside a Core commitment every non-SoFi path also computes.
- **Do not paper over the mismatch.** Writing an artifact that merely *looks* like Def 6.26 —
  carrying a signed root claim and calling it `R_T^+` — reintroduces the exact attack Req 21.17
  makes a mandatory test vector.

§1 therefore states the correspondence explicitly, as the registry's §7 already anticipated it
would have to be:

> **Prerequisite inside 2c.** … If ordinary DSM successor CCB is not normatively specified
> elsewhere, it must be opened as a **Core canonical-successor encoding prerequisite** and
> referenced from SoFi — never restated ad hoc inside a SoFi amendment.

---

## 1. The Core accepted-successor authentication (substrate)

**This section is substrate.** It is excluded from Rev 15's closure accounting, per the
registry's ruling that non-SoFi canonical material belongs "here, in this namespace, marked
substrate", never restated inside a SoFi amendment and never in a second registry.

### 1.1 What "accepted under ordinary DSM" authenticates, and what it does not

The ordinary DSM accepted-successor primitive is the triple

```
C_dsm+          = relationship_chain_tip_v2(rel_key, embedded_parent, counterparty_devid,
                                            operation_bytes, entropy, encapsulated_entropy)
operation_digest = H_dom(<operation domain>, operation_bytes)
sigma_dsm        = Sign(AK, H_dom(DSM/economic-substrate-sign/v1,
                                  G ‖ DevID ‖ C_dsm+ ‖ operation_digest))
```

A foreign verifier recomputes `C_dsm+` from the preimage through the one canonical helper,
recomputes the operation digest from the embedded operation bytes, and checks `sigma_dsm` under
the **P0–P6-proven** authority key — not under a key the artifact names.

This authenticates: *this identity accepted exactly this operation as exactly this successor to
exactly this parent.* It authenticates **no state root**, and it deliberately carries no balance
effect.

### 1.2 `R_T^+` is the VALIDATED post-economic root, and validated is not registered

The authenticated post-advance root SoFi needs is the trader's **validated** economic root.

The distinction is the load-bearing one in the whole economic design, and it is enforced by the
type system rather than by discipline. Registering a root into the write-once economic register
establishes **non-equivocation and nothing else**: this identity named one root at this position
and can never name a second. A malicious trader registers an arbitrary root perfectly
consistently, and the register accepts it — members check signature, attribution and set
membership, never transition validity.

So the following is **not** a valid derivation of `R_T^+`, and an implementation that does this
has reintroduced the forged-root attack in a new costume:

```
signed EconomicRootClaimBody  ->  R_T^+          ✗ WRONG
```

The correct derivation is the full validity walk, every step recomputed and nothing taken from
the claimant:

```
previously VALIDATED R_econ (this verifier's own earlier conclusion, or the
                            canonical empty activation root — never a network value)
  -> register winner at (G, DevID, position), self-verifying and non-equivocal
  -> admission manifest, by content address, with address equality re-derived
  -> authority evidence: P0-P6 recovers the proven AK and the committed network
       - the claim's signing key must BE the proven AK
       - the register set must be the committed network's canonical set
  -> transition witness + accepted substrate, by content address
       - substrate = the ordinary accepted successor of §1.1
       - sigma_dsm verified under the proven AK
  -> advance_validated: the derived root is recomputed from the pre-root and the
     write set, and required to equal the registered one
  -> VALIDATED R_T^+
```

`R_T^+` is the **derived** root, never the **claimed** one. The two must agree, and the
derivation is what is carried forward.

### 1.3 The correspondence, stated

Def 6.26 asserts a single commitment `C_T^+` that contains `R_T^+`, authenticated by one
signature `σ_T^+` over that commitment. The construction above is instead a **cryptographically
linked pair**:

```
sigma_dsm                     -> C_dsm+ + operation_digest        (the successor)
signed EconomicRootClaimBody  -> post_economic_root + manifest    (the root claim)
        -> manifest -> substrate -> the exact DsmSuccessorEvidence carrying that same C_dsm+
        -> advance_validated -> the DERIVED root, required equal to the claimed one
```

The link is not narrative. It is enforced at three points: the manifest's substrate slot must
name the exact evidence address the acceptance used (same-kind and same-address); the witness
and the accepted substrate must bind the **same** operation digest; and the economic operation
id is derived as `H(G ‖ DevID ‖ C_dsm+)`, so the economic transition cannot describe a different
successor than the one authenticated.

**Normative statement.** For SoFi, the ordinary accepted-successor authentication required by
Def 6.26 IS this linked construction. `C_T^+` is not a single object; a conforming verifier
establishes the same fact by verifying `sigma_dsm` over `C_dsm+` **and** deriving `R_T^+`
through the validity walk that binds that exact `C_dsm+`. Rev 15's prose, which reads as though
one commitment contains the root, is corrected accordingly: **the relationship chain tip does
not and must not contain the economic root.**

### 1.4 What `L_B` binds, and the second correction

Def 6.26 item 5 says the verifier "verifies that `L_B` binds the exact
`(trader_parent, trader_successor, b, X)` committed by `B`."

The settlement/acceptance leaf that exists — and that the sibling credit source already proves
into a validated root — binds `vault_id`, `receipt_id`, `X`, both generations, and both legs
with their amounts. Its **key** additionally binds `G ‖ DevID`, so the leaf is unforgeable into
another identity's tree. It does **not** bind `b`, `trader_parent` or `trader_successor`.

Extending it would mean a schema bump on a shipped class to carry facts that are already bound
elsewhere — the alias the registry's whole anti-duplication doctrine exists to prevent. So the
binding is **compositional**, and this amendment says so rather than restating the prose:

```
L_B                binds X and the exact trade quantities
R_T^+              binds the successor, because the admission whose root this is
                   has that exact C_dsm+ as its substrate
TA_B               binds b, and asserts the join
```

A conforming verifier therefore checks the conjunction, not a single leaf. **`L_B` alone is not
required to bind all four**, and an implementation that adds `b` or the trader coordinates to
the leaf has duplicated a commitment rather than strengthened one.

---

## 2. `TraderAcceptance` — class `0x0011`, schema 1

`ta_B = H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`.

The `/v2` in the domain is the tag Rev 15 reserves for this artifact and is not a schema
version; the CCB schema is 1. The artifact carries no signature of its own — SoFi adds no
acceptance payload and no signing round — so §2.9's "the signature is not a field" applies
vacuously: there is no SoFi signature to exclude.

Def 6.26 enumerates the members; Def 14.1 fixes the digest and the publication duty.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `bundle` (`b`) | `digest32` | the exact SettlementBundle this acceptance realizes |
| 2 | `route_set_commitment` (`X`) | `digest32` | must equal `B.market_terms.route_set_commitment` |
| 3 | `trader_parent` | `digest32` | the ordinary-DSM relationship parent; must equal `B.market_terms.trader_parent` |
| 4 | `trader_successor` (`C_dsm+`) | `digest32` | must equal `B.market_terms.trader_successor` |
| 5 | `trader_genesis` (`G`) | `digest32` | whose economic tree `L_B` and `R_T^+` belong to |
| 6 | `trader_devid` (`DevID`) | `digest32` | |
| 7 | `economic_position` | `u64` | **untrusted locator.** Where to begin the validity walk, never authority for its result |
| 8 | `acceptance_leaf` (`L_B`) | `EconomicSettlementReceiptState` | nested inline per §2.7, complete CCB with its own class and schema |
| 9 | `acceptance_path` (`π_B`) | sequence of `digest32` | exactly 256 siblings, leaf-to-root; §2.5 sequence because position is the tree depth and duplicates are legal |

No field 10. In particular there is **no `ta_B` field and no receipt field**: the Def 14.2 public
Receipt binds `ta_B`, so a reciprocal field here would be circular — `TA_B` hashes `L_B` while
`L_B` contained a hash of `TA_B`.

There is also no `post_economic_root` field. The root is **derived** by the walk from fields
5–7; carrying it would invite a verifier to read the carried value instead of deriving it, which
is the entire failure Req 21.17 tests for.

**Validity, stated as rejections.** A `TA_B` is invalid if `acceptance_path` is not exactly 256
elements; if `acceptance_leaf` does not decode as a canonical settlement-receipt leaf; if
`acceptance_leaf.x != route_set_commitment`; or if any of fields 1–6 is all-zero.

**Verification obligations**, in order, all conjunctive:

1. Derive `R_T^+` for `(trader_genesis, trader_devid, economic_position)` through §1.2's
   validity walk. A walk that cannot complete is INCOMPLETE — retryable — never invalid.
2. Require the walk's authenticated successor to be exactly `trader_successor`, from exactly
   `trader_parent`.
3. Recompute the leaf key from `(G, DevID, vault_id, receipt_id)` and the leaf value from
   `CCB(acceptance_leaf)`, fold `acceptance_path`, and require the result to equal `R_T^+`.
4. Require `bundle` and `route_set_commitment` to equal `B`'s own, and `acceptance_leaf`'s trade
   quantities to equal the transition `B` commits for that vault.

A `TA_B` that satisfies all four realizes `B`, and only together with `B` being binding-final.

---

## 3. `DlvProofMaterial` — class `0x0010`, schema 1

`P_v` is nested in `0x000F` (see §4), so it has no digest of its own.

Rev 15 supplies one gloss: *"proof material required to verify and later compose that DLV
continuation."* §6 of the registry adds that the contents are entirely unspecified and are
"likely a witness family rather than a flat record".

### 3.1 The boundary

```
T_v   the complete DLV successor (nested V_{n+1}) and the required witnesses
P_v   ONLY the irreducible witness material a foreign Class K verifier needs to
      re-check the exact selected continuation
```

**Nothing already committed by `V_n`, `T_v`, the selected route or `X` may appear in `P_v`.** In
particular the reserve, input and output magnitudes are derivable from the authenticated parent
plus the complete `V_{n+1}` in `T_v` field 2, and therefore do not belong here. `P_v` is proof, not a second
description of the trade.

### 3.2 In the beta profile, `P_v` is empty

Applying that boundary to the beta market profile: a verifier holding the authenticated parent
`V_n`, the selected route and `X`, and `T_v`'s complete `V_{n+1}`, can re-run the
constant-product check with no further material. The route is inside the bundle, so no live
fetch is required; the parent is authenticated by the composition; the deltas are committed by
`T_v`.

There is therefore **no irreducible extra witness material in this profile**, and `P_v` is the
empty object. This is a finding, not a placeholder: fields are not manufactured so that `P_v`
is nonempty.

| # | Field | Type | Notes |
|---|---|---|---|
| — | — | — | no fields in schema 1 |

A schema-1 `P_v` is exactly its four-byte envelope, `u16_be(0x0010) ‖ u16_be(0x0001)`.

**Why an empty object rather than an absent one.** A future profile — a non-constant-product
curve, an oracle-referenced fulfillment, a multi-hop continuation whose intermediate state is
not derivable — will need witness material, and §6's "likely a witness family" is the right
shape for it. Reserving the class now with an empty schema 1 means that profile adds
`schema 2` rather than discovering that the enclosing bundle has nowhere to put it. §2.8 makes
that a mechanical, transitive bump; it does not make it a redesign.

### 3.3 Cardinality, association and the empty encoding

The registry's §2.4/§2.5 require a field table to choose set or sequence, and the two are
byte-identical, so the choice must be explicit. The shipping wire form carries `T_v` and `P_v`
as two parallel `repeated` fields; that form is not normative (§2.10) and **must not** be
mirrored here, because two parallel collections leave the *i*-th proof unbound to the *i*-th
transition. That is precisely the disagreement surface the registry rejects elsewhere.

**`P_v` is a field of `ConsumedDlvTransition`, not a sibling collection in `SettlementBundle`.**
One transition, one proof, paired structurally. There is no pairing rule to get wrong because
there is no pairing.

Consequently there is no cardinality question and no "zero-material" encoding question at the
bundle level: `0x000E` has no `P_v` field at all.

> **Corrected by 2c-A §5.21.** This paragraph originally made `P_v` a **non-optional** nested
> object always emitted as the four-byte empty envelope. That is a byte-level divergence from the
> frozen table: `0x000F` field 3 is an **optional** nested `0x0010` under §2.3, and the beta
> profile encodes it **absent** — a single `0x00`, not `00 10 00 01`. The registry §5.22 and
> 2c-A agree on the absent encoding.

---

## 4. `ConsumedDlvTransition` `0x000F` and `SettlementBundle` `0x000E`

Both are named by Def 6.14; §6 records that they block on member *types* and on `0x0010`. With
§3 above, `0x0010` is unblocked, so their tables can be completed — but they are the largest
remaining piece and they are deliberately **not** written in this draft. They need the same
treatment §6a gave `Route` before its field numbers were frozen: an opening audit, because
§2.8 makes field numbers permanent.

What §3 settles for them:

- `0x000F` gains a `P_v` field (nested inline, §2.7).
- `0x000E` gains no `P_v` field.
- `0x000E`'s `transitions` is a §2.4 **set** ordered by complete element CCB, not a
  sequence ordered by an in-element `vault_id` — §5.11's precedent, where exactly that argument
  was retired.

---

## 5. `TradeIntent` `0x000B` — already defined, never produced

`I = H_dom(DSM/intent, CCB(TradeIntent))`, over the nine fields §5.5 already fixes. This
amendment adds nothing to that class; it records that **no producer exists**.

The CCB encoder deliberately omits the routing and settlement classes, and there is no Rust or
proto type for `TradeIntent` anywhere. The only appearance of `I` in shipping code is
`SettlementBundleV1.intent_commitment`, a 32-byte field that is width-checked and never read —
and which the market settle path currently sets equal to `X`.

**That alias is non-conforming.** `I` and `X` are distinct commitments over distinct objects.
5c-2 implements `0x000B`, computes `I` from the intent the quote was priced against, and
verifies at bundle construction and in third-party verification that the selected route
satisfies that exact `I`.

---

## 6. `MarketTerms.recovery_material` — normative semantics

> **Corrected by 2c-A ruling 6.** `recovery_material` is `MarketTerms` (`0x0033`) field 6, not a
> `SettlementBundle` field, and it is **mandatory** there.

The proto has carried this field since the bundle shipped and has never given it meaning. 5c-2
gives it one, because the acceptance-continuation worker cannot exist without it.

### 6.1 Why a 32-byte target is not reconstruction material

After `B` is binding-final, a crash may occur before the trader's successor is accepted. A
worker must then finish the **exact** already-prepared successor — not an equivalent one.
`B.market_terms.trader_successor` states what the answer must be; it says nothing about how to reproduce it.

Reconstructing the operation from committed coordinates — the pattern the owner-close
authorization uses — is **not available here**. That pattern's own rule is that reconstruction
must stay total, and that the moment one field becomes free the bundle must carry the canonical
bytes instead. A market settle fails that test on **eight** fields. Four are derivable
only by re-composing the vault — `owner_public_key`, `owner_devid`, `owner_genesis`, and
`fee_bps`, which comes from the vault's fulfillment mechanism and cannot be inverted out of a
hash. Four are free: `sigma`, `settler_public_key`, `settler_devid`, and the SPHINCS+
`signature` itself. The signature is inside the chain-tip preimage, so a field-wise rebuild that differs
anywhere produces a different successor.

**`recovery_material` therefore carries bytes, not coordinates.**

### 6.2 Nothing in the preimage is secret

The successor commitment is

```
C_dsm+ = relationship_chain_tip_v2(rel_key, embedded_parent, counterparty_devid,
                                   operation_bytes, entropy, encapsulated_entropy)
```

The only input whose name suggests secrecy is `entropy`, and it is not random. It is a pure
hash-chain fold:

```
entropy_n = H_dom(DSM/state-entropy, entropy_{n-1} ‖ operation_bytes ‖ h_{n-1})
```

with no RNG anywhere in its derivation, and a foreign verifier already recomputes and re-checks
it during ordinary transition verification. A value a third party is expected to recompute is
not a secret.

More decisively: **this repository already publishes all six inputs together**, as the
successor-evidence object pushed to storage nodes for every admitted operation. Carrying them in
`B` is not a new disclosure decision; it is the disclosure decision already made and shipped.

### 6.3 Contents

For `BundleShape::Market`, `recovery_material` is the canonical bytes of the accepted-successor
evidence object of §1.1 — the six preimage inputs, the resulting `C_dsm+`, and `sigma_dsm`.

| Field | Why it must be present |
|---|---|
| `rel_key` | not derivable from the RouteCommit: `DevID = H(tag ‖ AK_pk ‖ AttA)` and `AttA` is not in the route |
| `embedded_parent` | must equal `B.market_terms.trader_parent` once the coordinates are corrected; carried so the equality is checkable rather than assumed |
| `counterparty_devid` | same as `rel_key` — the settling device's identity is not public in `B` |
| `operation_bytes` | reconstruction is not total (§6.1), and the signature is inside the preimage |
| `entropy` | deterministic, but folded from the device's prior tip; carrying it makes the successor recomputable **by anyone**, not only by the device that crashed |
| `encapsulated_entropy` | absent on this path — but the preimage distinguishes absent from present-and-empty, so the absence must be encoded faithfully, never flattened |
| `c_dsm_plus` | the worker's equality gate |
| `sigma_dsm` | makes the material foreign-verifiable rather than merely self-consistent |

**Deliberately excluded as redundant:** `vault_id`, `parent_sequence`, `parent_binding`,
`route_commit_bytes`, `external_commitment_x`, both policy commits, both amounts and
`settlement_receipt_id`. Every one is already recoverable from `B.market_terms.selected_route` and
`B.transitions`, and all of them are inside `operation_bytes` regardless. Restating them
would be the alias this registry's doctrine exists to prevent.

For an owner close there is **no slot at all**, not an empty one: a close carries no
`MarketTerms`, hence no `recovery_material` field. An "empty recovery material for OwnerClose"
would be exactly the dummy-value pattern 2c-A ruling 6 rejects.

### 6.4 The rules that make it load-bearing

**Validity, at the canonical layer.** A market bundle is invalid unless `recovery_material`
decodes, re-encodes to itself, and satisfies both:

```
relationship_chain_tip_v2(<its six inputs>) == B.trader_successor
its embedded_parent                          == B.trader_parent
```

The bundle's structural validation checks neither today — it width-checks the two successor
fields and never reads `recovery_material` at all. Without this rule the field is decoration.

**Reconstruction is verified, never trusted.** Before committing anything, the
acceptance-continuation worker recomputes the successor from `recovery_material` and requires
exactly `B.trader_parent -> B.trader_successor`. A mismatch is a refusal, not a repair.

**Identity comes from `recovery_material`, never from the operation body.** `settler_devid` and
`settler_public_key` inside `DlvSettle` are caller-supplied and are never compared to the
settling device's own id — the canonical advance deliberately ignores them and verifies against
the device's own key instead, on the principle that a key travelling inside the material it
authorizes proves nothing. A worker that derived `rel_key` from the operation body would inherit
that hole. It derives identity from `rel_key` and `counterparty_devid` only.

## 7. Registry defects found while writing this

Recorded, not fixed — each needs its own decision.

1. **Three broken §5 cross-references.** §3 cites `§5.6` for `0x000E` and `0x000F` and `§5.7`
   for `0x0011`. Those sections are `MarketBounds` and `MarketPolicy`. There are no §5 sections
   for `0x000E`, `0x000F` or `0x0011` at all; the correct citation for all three is `§6`.
2. **§4 count contradiction** — "15 are fully specified" against "the ten specified objects".
3. **Stale blocked list** — the closing section names five blocked classes including `0x000C`,
   `0x000D` (both defined) and `0x0014` (burned). Two are blocked.
4. **Wrong symbol** — `P_M` is used as the example of an object named without its contents;
   `P_M` is fully specified. It should read `P_v`.
5. **`0x0012 TradeDigest`'s amendment is ambiguous** — assigned to 2c in one place, omitted from
   2c's membership list in another, and included in the superseded 2b framing in a third.
6. **`I`'s derivation has no home** — §5.5 is the only fully-specified section with no
   derivation line; `I` is defined only in a §3 status cell and a §5.12 notes cell.
7. **§3 is behind the shipping encoder by sixteen class numbers** — `0x001B`–`0x001F` (5),
   `0x0020`–`0x0029` (10) and `0x0030` (1) are allocated in code but absent from §3, which the
   registry's own single-namespace rule makes a live double-allocation risk. Per §8 blocker 3
   this is no longer merely a defect to record: 2c now depends on those classes normatively.

---

## 7a. Where the material below belongs

This document was drafted as one amendment. Its researched sections are retained and are routed
as follows; each sub-amendment inherits its rows and nothing else.

| Section | Owner | Note |
|---|---|---|
| §1 Core accepted-successor authentication | **2c-B** | The correspondence and the validated-root walk. §1.4's compositional-binding argument moves to 2c-D, superseded by the two-conjunct rule in §9.1. |
| §2 `TraderAcceptance` field table | **2c-D** | Must be re-derived: with the leaf authenticating `b`, the coordinates and `X` are inside `b` and stop being separate fields. |
| §3 `DlvProofMaterial` | **2c-A** | The empty-in-beta finding and the "`P_v` is a field of `0x000F`" structural fix. |
| §4 `0x000E` / `0x000F` | **2c-A** | Plus §0d and §9.4. |
| §5 `TradeIntent` / real `I` | **2c-A** | Plus the deterministic satisfaction predicate. |
| §6 `recovery_material` | **2c-B** | Contents stand; the carrier becomes the 2c-B substrate class, not canonized prost bytes. |
| §7 Registry defects | **2c-C** | Absorption is normative design, not transcription. |
| §9 Research outcome | shared | The corrections apply to whichever amendment inherits each finding. |

## 8. Review blockers — what this draft must resolve before an encoder

Recorded verbatim from review so the second pass cannot quietly drop one.

### Blocker 1 (security) — `b` is not authenticated, and one receipt cannot cover a multi-vault bundle

§1.4 and §2 as written have `TA_B` "assert the join". But `TA_B` carries **no signature of its
own**, so putting `b` in field 1 only makes `b` part of that artifact's own content hash. It does
not prove the trader's accepted economic state committed that bundle. Def 6.26 is stricter for a
reason: the acceptance leaf must bind the exact bundle relationship, not have an unsigned wrapper
assert it.

The same spot hides a second defect. `B` holds a **set** of vault transitions and a route may fan
out across distinct DLVs, while §2 gives `TA_B` exactly one per-vault settlement receipt leaf and
one Merkle path. One vault receipt cannot authenticate realization of a multi-vault bundle.

**Required fix — one change closes both.** Do not bloat the existing settlement-payment leaf.
Define a **bundle-acceptance economic leaf** under `R_T^+` whose *authenticated* content commits
at least `b`. Because `b` already commits `X`, the trader coordinates, the selected route and
every `T_v`, that single authenticated bundle identity covers the entire settlement however many
DLVs it consumed. `TA_B` then proves **that** leaf under the validated root:

```
B binding-final
  -> exact trader successor accepted
  -> validated R_T^+
  -> L_B UNDER R_T^+ authenticates the exact bundle b
  -> TA_B packages b + proof of that authenticated L_B
  -> realization
```

The join becomes part of authenticated economic state rather than an assertion about it — and it
yields one bundle-level `L_B` per `B`, which is closer to what Def 6.26 was reaching for.

### Blocker 2 (security) — the Core prerequisite is announced but not specified

§1.1 describes the shipping successor-evidence construction without assigning a substrate class
or a field table, and §6.3 then defines `recovery_material` as its "canonical bytes". That is
protobuf-as-CCB, which the registry forbids: protobuf is transport and must never become CCB
merely because an implementation serializes it consistently.

**Required fix.** Open the prerequisite for real — allocate an *audited* substrate CCB class for
the ordinary accepted-successor evidence / recovery preimage, give it a field table, and have
`recovery_material` carry **that CCB object**. The protobuf remains its transport carrier.

Also under review: whether `c_dsm_plus` belongs in that object at all. It is derived from the
preimage and already appears as `B.market_terms.trader_successor`, so the canonical object can recompute it
rather than restate it — and restating a derived value is the alias this registry exists to
prevent.

### Blocker 3 (completeness) — the economic classes are a dependency now, not a defect

`TA_B` nests an economic leaf, and §1.2's walk depends on the root claim, manifest, witness,
mutation and leaf objects. The shipping namespace has allocated `0x001B` onward; the normative
table stops before them. **A second implementation cannot perform the §1.2 walk from this
amendment plus the registry as they stand.**

**Required fix.** Absorb the economic substrate classes into the normative namespace before 2c
claims cross-implementation closure. Listing the discrepancy in §7 is no longer sufficient.

### Blocker 4 (completeness) — the two tables that define `B`, and the `I` predicate

§4 defers `0x000E` and `0x000F` pending an opening audit. That caution is right, and it also
means the normative phase is **not finished**. Freeze both tables first.

§5 correctly says `I != X` but leaves "the selected route satisfies that exact `I`" as prose.
Either cite the Rev-15 sections that already specify every comparison, or spell out the
deterministic predicate over the eight non-nonce fields — `token_in`, `amount_in`, `token_out`,
`min_out`, `max_fee`, `max_hops`, `max_fanout`, `k` — stating for each which route quantity it is
compared against and how. `nonce` remains commitment identity and is not a route property.

---

## 9. Research outcome — the four blockers are not four decisions

Five parallel research passes (four per blocker, one adversarial seam pass) resolved every
*researchable* question and surfaced roughly thirty normative decisions that research cannot
settle, plus five findings that change the shape of the amendment. Recorded here so the next
pass starts from the real problem rather than the one this draft assumed.

### 9.1 The first economic post-state fact not derivable from the operation

Earlier drafts of this finding called it a hash cycle. That is the wrong name: if `b` is supplied
*after* the successor has been prepared it is not necessarily a cryptographic fixed-point.

The real problem is sharper and worth stating in its own terms. **`b` becomes the first economic
post-state fact that is not derivable from `Operation::DlvSettle` itself.** Today the verifier is
deliberately much stronger than "the leaf is well-formed": a settle must be exactly one input
debit, one output credit and one receipt insertion, and that receipt must equal the settlement
facts derived from the operation. A bundle-acceptance leaf is the first content that rule cannot
reach — `b` commits `trader_successor`, which is the chain tip over `operation_bytes`, so the
operation cannot name it.

Every existing economic leaf has its content bound to the operation by
`verify_operation_write_set`. This one structurally cannot be. It can be checked for **presence
and shape** (`pre: None`, write-once) and nothing more.

So the replacement security rule must be **written down explicitly**, not left to weaken that
invariant invisibly. Two conjuncts, neither sufficient alone:

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

**And the leaf's POSITION stays operation-derived even though its CONTENT cannot be.** The key is
keyed to the authenticated economic operation identity, not to `b` and not to anything a caller
chooses. Content commits `b`; position remains structurally tied to the exact accepted economic
transition, preserving as much of the "key derived, never supplied" doctrine as the cycle allows.

*Trade-off recorded:* keying on `b` would have made Req 21.17's mandatory forged-root vector
cheaper, because the expected leaf position would be computable from `B` alone. Doctrine wins —
a caller-chooseable position is a worse defect than a more expensive test fixture.

### 9.2 `b` is currently a protobuf digest

Registry §3 says `b = H(DSM/settlement-bundle ‖ CCB)`. The shipped implementation hashes **prost
protobuf bytes**. A leaf whose purpose is to commit `b` would therefore commit a value whose byte
definition is still open, and freezing `0x000E` changes `b`.

**Correction to an earlier statement of this finding.** The QuorumBind resource key is *not*
`b`. `K(B)` is derived from each DLV parent `c_n` (Def 6.17), and `b` is the transaction/value
identity — `tx_id = value_digest = b`. So changing `b` changes the **bound candidate identity and
its immutable address**; it does not change the DLV resource key, and the occupancy mechanism
5c-1 landed is not keyed on a transport digest. The blast radius is real but narrower than first
written.

The same defect exists in a second place: a canonical validity conjunct in the provenance path
hashes a serialized `TokenPolicyV3` to derive a policy commitment.

### 9.3 Two blockers collide on one class number

Blockers 1 and 2 independently allocate `0x0031`, inside an amendment that cites the
single-namespace rule. Both must be allocated in **one** table edit with a stated order.
Recommended: `0x0031` = the substrate accepted-successor evidence (it is the prerequisite the
registry already opened), `0x0032` = the bundle-acceptance leaf.

### 9.4 Blocker 4's ruling breaks blocker 1's evidence

Honouring Def 6.14 by dropping `vault_id` and `parent_generation` from `0x000F` breaks the chain
`is_close_transition → shape_of → validate → canon → b`, and breaks the provenance arm's
`.find(|t| t.vault_id == vault)` and its generation equality — a **live security conjunct**.
Recovering vault identity by dereferencing `c_n → V_n` would put a FETCH inside `Canon(B)`'s
validity condition, hence inside `b`, which Req 6.15 forbids. The per-transition authorization
field is therefore not a tidiness improvement; it supplies the signature-to-transition mapping by
construction.

> **Corrected by 2c-A ruling 6.** An earlier clause here called it *"the only way to keep shape
> derivable from the bundle's own bytes"*. That is withdrawn: nesting the complete `V_{n+1}` puts
> `vault_id` and the generation back in the bundle's bytes, and the bundle-shape discriminator is
> `0x000E` field 1, `market_terms`. Field 4 of `0x000F` is the per-transition **authorization**
> marker.

Related: Rev 15 §18.5's "reuses a DLV" clause does **not** license two transitions on one vault
in one bundle — a bound-but-unrealized settlement does not advance the parent, so a second leg
has no parent to consume. If `{T_v}` becomes a §2.4 set ordered by element CCB, the vault
uniqueness the old sort enforced is lost and must be restored by an explicit clause.

### 9.5 Absorption does not buy closure

Absorbing `0x001B`–`0x0030` makes the **objects** decodable. It does not make the **walk**
reproducible: roughly ten further things remain unspecified, including the register cell format
and winner selection, the P0–P6 procedure, the `immutable_inner`/`immutable_addr` construction,
and the economic SMT's bit order and leaf/node construction. Several are conjuncts of
`advance_validated` and none is a CCB class.

Worse, the registry's §7 explicitly refuses an "absorb as shipped" tier, and three shipped
encodings cannot be expressed in the current framework at all: a fixed-count array with no count
prefix, ordering predicates §2.4/§2.5 cannot state, and mutually-exclusive optionals including
one whose type is a union of classes. Absorption is a normative-design act, not transcription.

### 9.6 Scale, stated plainly

Adding the acceptance leaf is ~10 core dispatch sites (not the 5 first estimated), plus one in
the SDK — `leaf_is_externally_citable`, which must return true, making this the first leaf whose
citer is a third party rather than a counterparty. Three further sites produce **no compile
error** and must be swept by hand.

Confirmed clear: one leaf per bundle does **not** break the existing per-vault receipt. Both
leaves coexist with a stated division of authority — the `0x0021` receipt is owner-facing (it
funds the settlement-payment credit and makes reserve consumption non-reusable); the acceptance
leaf is third-party-facing (it makes realization checkable and funds nothing). Neither may be
consolidated into the other.

One positive argument for keying the leaf on `b` alone, which no researcher made and which is
worth keeping: it makes Req 21.17's mandatory forged-root vector **cheaper**, because "the
expected settlement leaf" becomes a computable position rather than a value the harness must be
told.
