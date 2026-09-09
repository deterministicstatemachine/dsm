# Amendment 2c-C3 — `ValidDlvSuccessorCore`

Governs the successor-validity predicate for a DLV continuation.

Status: **SPECIFICATION FROZEN.** The predicate, its outcome taxonomy, its input contract and its
four Rev 15 errata corrections are normative here. Lean statements and production Rust follow this
document; neither precedes it.

Prior: 2c-C1 (framework + namespace), 2c-C2 (verification substrate). Next: 2c-C4 (`TA_B` closure
walk), 2c-D (`0x0011`, the bundle-acceptance leaf).

---

# What this amendment decides

C2 froze *how a verifier obtains and authenticates* the substrate. It deliberately did not decide
*what makes a DLV continuation valid*. C3 decides exactly that, and nothing beyond it.

```text
C3 DECIDES        the complete successor-validity predicate for one transition
                  V_n --operation--> V_{n+1}

C3 DOES NOT       the ordered evidence walk to ValidatedEconomicRoot   (C4)
                  the TA_B acceptance closure                          (C4/2c-D)
                  token policy validity                                (declared, §Ruling H)
                  the exactly-once owner credit on terminal close       (declared, §Ruling G)
                  any encoder change                                    (the CCB cut, 2c-A)
```

This amendment is **reconciliation, not invention**. Every clause below is traced to Rev 15 or to a
prior amendment. Where Rev 15 is defective, the defect is stated, the correction is given as an exact
predicate, and the reason the literal text cannot be used is recorded.

---

# Why the specification precedes the implementation here

The owner imposed a formal-specification-first ordering for this sub-amendment: complete the
read-only source reconciliation, freeze every clause, write the normative predicate, declare the
theorem statements and assumption boundaries, and define an outcome for every clause — *before* any
production change. That ordering produced findings that an implement-first pass would have buried in
code:

- **The expected "15-clause predicate" does not exist in the normative source.** Rev 15's only
  enumeration (Def 6.1) is ten common checks plus kind-specific tails — sixteen items at the
  document's own granularity, or seventeen if the compound tenth is split, and roughly thirty-four
  once decomposed atomically. **Fifteen is the `VaultStateV2` tuple arity and the revision number.**
  A predicate written to hit fifteen would have been written to a number, not to the specification.

- **Four defects in Rev 15**, two of which make the predicate *unformulable* as written. A verifier
  implemented literally from Def 6.1 and §7.1 rejects every valid beta market successor. All four are
  corrected below.

- **There is no declared successor on the wire at all.** This corrects an earlier draft of this
  amendment, which said `vault_state_composition.rs:572` *"binds the bundle's declared successor and
  discards it"* and that *"both values are live at that point"*. Only the trivial half was true.
  `VaultTransitionV1.successor_ccb` is 32 bytes that are **not a successor commitment**: production
  market bundles write the route-set commitment `x` (`dlv_routes.rs:3249`, whose own comment says
  *"there is no such commitment to name, so it carries the trade identity and nothing reads it as a
  successor"*), and production closes write `x_close` (`settlement_bind.rs:161`), a pure function of
  `(vault_id, parent_generation)` that commits nothing about reserves. Both composition arms
  **derive** the successor locally (`:470` market, `:479` close). So `VDS.COMMON.10.a` has no second
  operand today — see the blocking note under its clause.

- **A whole successor-validity condition was missing from every draft.** §8's Req 8.1 — *"A claim is
  consumed at most once and its exact removal must be visible in the successor state"* — is a
  condition on the successor, not background. It surfaced only because Phase A was finished before
  the statements were written. See Ruling F.

- **One condition C3 structurally cannot express.** Def 6.1's terminal-close tail requires crediting
  released reserves to ordinary owner balance *exactly once*. That is a property of the owner's
  balance, not of `V_{n+1}`, so no predicate over the vault successor can see it. See Ruling G.

The last two are the argument for the ordering, not decoration: both were invisible to a
clause-by-clause transcription and both change what the predicate must contain.

---

# Ruling A — hierarchical granularity; the clause count is not a protocol fact

> The predicate is specified at **two levels**. Level 1 preserves Rev 15's own grouping — common,
> market tail, release/close tail, terminal close. Level 2 decomposes each into atomic conjuncts with
> stable identifiers. **No clause count is normative**, and no implementation conforms or fails by
> reproducing one.

The "exact 15-clause predicate" framing is **REVOKED**. It was erroneous: fifteen is the arity of the
`VaultStateV2` tuple and the number of the specification revision, and neither is a count of
validity conditions. Where Def 6.1 states a compound item, the grouping is preserved and the
compound is split at Level 2 rather than renumbered at Level 1.

Stable identifiers are the interface. `VDS.COMMON.3`, `VDS.MARKET.1.b` and so on are cited by the
Lean statements, the conformance rows and the Rust outcome codes alike, so a clause can be traced
across all four artifacts without depending on an ordinal that a later revision may shift.

---

# Ruling B — derive-and-compare, with a typed partial derivation

> The authoritative test of **successor-state correspondence** is
> `Canon(expected) = Canon(supplied)`, where `expected` is derived from the authenticated parent and
> the authorized operation. A verifier **derives** the successor it would accept and compares
> canonical bytes. It does not walk a field checklist against a supplied structure.

## Correspondence is one conjunct, not the whole predicate

This is the point most easily mis-stated, so it is stated flatly:

```text
VDS.CORRESPONDENCE  is  the SINGLE authoritative successor-state correspondence test.

It is NOT the whole of ValidDlvSuccessorCore. Authority, signatures, the parent
relationship, binding finality and evidence validity are INDEPENDENT conjuncts
standing alongside it.
```

A successor whose bytes match a correctly derived expectation can still be invalid — the operation
may be unauthorized, the parent unauthenticated, the binding not final. Correspondence answers
*"is this the right successor for that operation?"*, and answers nothing else.

## The derivation is typed and partial

```text
DeriveExpected(V_n, operation, inputs)
    ->  Derived(V_{n+1})
     |  Invalid(reason)
     |  Incomplete(reason)
     |  SafetyViolation(reason)

VDS.CORRESPONDENCE  :=  match DeriveExpected(V_n, operation, inputs) with
                          Derived(e)  =>  Canon(e) = Canon(supplied)
                          other       =>  propagate that class and reason
```

A total function returning `V_{n+1}` would hide failed arithmetic, unavailable evidence and invalid
authorization inside an apparently successful call, and the caller would then compare bytes against
a value that should never have been produced. The comparison happens **only** on the `Derived` arm.

This is the `ApplyDlvTransition` of the decomposition's routing table, renamed: it derives an
*expected* successor and applies nothing to live state.

## Preserved and mutated fields are DERIVED consequences

```text
VDS.CORRESPONDENCE  ->  every preserved field of V_{n+1} equals V_n's
VDS.CORRESPONDENCE  ->  every mutated field equals its deterministic derived value
```

These are **theorems, not acceptance conjuncts**. Keeping them as conjuncts would make the
independence obligation of Ruling I unsatisfiable for them: they cannot be removed without a
counterexample, because they follow from the conjunct that remains.

## The bridge, stated rather than assumed

The two lines above are meaningless unless canonical equality implies structural equality:

```text
CanonVault(x) = CanonVault(y)  ->  x = y
```

This is an obligation of the encoding, discharged as a Lean theorem over the modelled encoder. It is
named here because omitting it would let the derived consequences carry an unstated assumption.

## The comparison is over BYTES, and the reason is not stylistic

```text
NORMATIVE:  the acceptance condition is equality of the CANONICAL BYTES

    encode_canonical(expected)  ==  the exact supplied canonical bytes

FORBIDDEN as a substitute:

    decode(supplied) == expected            -- compares objects, not bytes
    encode(decode(supplied)) == encode(expected)
                                            -- launders non-canonical input
                                               through the decoder
```

**Semantic successor equality and canonical-byte equality are different conditions**, and here they
genuinely come apart. `decode_vault_state` (`dsm/src/ccb/decode.rs`) **normalizes rather than
refuses**: `StorageSetMembers::new` sorts by `member_id` and `EncumbranceSet::new` sorts by element
encoding, and both reject only *duplicates*, never bad *order*. CCB has no decode/re-encode equality
check, although roughly ten sibling modules in the same crate apply exactly that discipline and one
of them names it *"the settlement-wire discipline"*. So two distinct byte strings decode to one
`VaultStateV2`, and any implementation that compares decoded objects — or re-encodes a decoded object
— **accepts non-canonical supplied bytes**.

A decode/re-encode round trip may stand in for the byte comparison **only** when the encoder
performing it is itself the frozen normative encoder. That encoder does not exist yet: repository-wide
there is exactly one `fn canon`, in `dsm/src/dlv/settlement_bundle.rs`, and it is protobuf. **There is
no `canon()` for `VaultStateV2`.** Phase D must build it, not call it.

The decoder's own comment (`decode.rs:271-272`) claims *"duplicate or misordered input is refused by
the constructor, not repaired."* The `misordered` half is false, and is recorded here as an
implementation debt rather than repaired in a documentation amendment.

## Why derive-and-compare rather than a checklist

There is **no boundary today**. The successor is produced by `clone()` plus four mutations, so every
"preserved field" is a property of the producer's construction path and not of any check. A field
checklist inherits that shape: it can only assert about fields someone remembered to list, and a
field added to `VaultStateV2` in a later schema is preserved-by-omission with nothing to notice.
Canonical equality is closed under the tuple — a new field is covered the moment it is encoded.

---

# Ruling C — Rev 15 errata, corrected as exact predicates

Four defects. Each is stated, then replaced by a predicate a verifier can execute.

## D1 — the parent reserves digest operand does not exist

Def 6.1 requires Class K to verify *"the exact vault ID, parent generation, parent state commitment,
parent reserves digest"*. The parent reserves digest was a component of the `p_v` projection, which
Req 6.6 **burned**. Def 6.14 settles what replaced it:

> the vault identifier, parent generation, parent state commitment and parent reserves digest
> *"are not separately carried because they are already committed by `V_n`."*

```text
CORRECTED:  There is no separate parent-reserves-digest operand.

            c_n = H_dom(DSM/vault-state, CCB(V_n)) commits the WHOLE tuple,
            reserve fields included. The obligation is discharged by
            authenticating V_n against c_n -- once -- and reading the fields
            from the authenticated state.

            The checklist item is a residue of the deleted p_v projection and
            is RETIRED. A verifier that looks for a separate digest operand is
            looking for a burned object.
```

Note the shipped proto still width-checks a `parent_reserves_digest` field
(`dsm/src/dlv/settlement_bundle.rs:110`) and carries it inside `b`. That is a proto/spec divergence
owned by the CCB cut, not by C3 — see Ruling D.

## D2 — "terminal/retired" has no tuple field

Def 6.1's terminal-close tail requires the successor to *"mark the DLV terminal/retired so no later
market successor may compose from the retired parent."* `VaultStateV2` has no such field, and adding
one would be a schema burn for a fact the state already determines.

§5.1's release family drains **both** reserve legs to zero and retires the vault. A market successor
can never reach both-zero: market admissibility forbids `a = 0`, so `R'_in = R_in + a > 0` always,
leaving at least one strictly positive leg. Both-zero is therefore reachable only by the close
family, and is an unambiguous marker.

```text
CORRECTED:  Retired(V)  :=  V.reserve_a = 0  ∧  V.reserve_b = 0

            No new field, no schema bump. Unambiguous BECAUSE market
            admissibility forbids a = 0.

            Composition from a retired parent is refused:
                Retired(V_n)  ->  no market successor of V_n is valid.
```

The shipped code already agrees — `device_state.rs:2491-2495` refuses with *"this vault is already
closed (both reserves are zero)"*. The correction records a rule the implementation had already
adopted without the specification stating it.

## D3 — §7.1's conservation identity does not hold for beta as written

§7.1 states, per token:

```text
Σ R^(n+1)  +  Σ out  =  Σ R^(n)  +  Σ in  −  fee_t
```

§5.1 says of the beta market fee that it *"is not withheld, not routed elsewhere, and not represented
anywhere in the successor: it remains inside the DLV reserves."* Substituting the beta successor:

```text
token_in :   (R_in  + a)       +  0       =  R_in  + a + 0  −  fee_in    =>  fee_in  = 0
token_out:   (R_out − output)  +  output  =  R_out + 0       −  fee_out   =>  fee_out = 0
```

```text
CORRECTED:  For the beta market family,  fee_t ≡ 0  in §7.1's identity.

            §7.1's − fee_t describes a family that EXTRACTS a fee from the
            conserved quantity. Beta does not have one: the fee shifts the
            constant-product curve and stays in the reserves, so it is inside
            Σ R^(n+1), not subtracted from it.

            A verifier applying §7.1 with a non-zero fee_t REJECTS EVERY VALID
            BETA MARKET SUCCESSOR.
```

This is the sharpest of the four: the literal text is not merely under-specified, it is actively
wrong for the only market family beta defines.

## D4 — `direction` is carried nowhere and must be derived

The constant-product update needs to know which reserve leg is the input. `direction` is a member of
neither `T_v`, nor `Allocation`, nor `V_n`. `P_M.family_parameters` is the ordered pair
`(token_a_policy_commit, token_b_policy_commit)`; the operation carries `input_policy_commit` and
`output_policy_commit`.

```text
CORRECTED:  require  { op.input_policy_commit, op.output_policy_commit }
                   = { P_M.token_a_policy_commit, P_M.token_b_policy_commit }

            then

            direction := if op.input_policy_commit = P_M.token_a_policy_commit
                         then  A→B    (x := R_A,  y := R_B)
                         else  B→A    (x := R_B,  y := R_A)

            Deterministic, TOTAL, and no new field.
```

**Totality is proved, not asserted.** `MarketPolicy::beta_constant_product`
(`dsm/src/ccb/state.rs:234-238`) **refuses** `token_a_policy_commit >= token_b_policy_commit` —
*"the order is a validity condition, and swapping would map two distinct logical inputs onto one
encoding"* — so `token_a < token_b` strictly, by construction. The set-equality check therefore also
refutes `input = output`: equal commits collapse the normalized pair to two equal values, which can
never equal a strictly ordered `(token_a, token_b)`. Every case surviving the membership check has
exactly one branch. The check is already shipped at
`dsm/src/economic/provenance.rs:1062-1071`.

---

# Ruling D — `successor_ccb` and the bundle identity

## The finding

`SettlementBundleV1` carries a `successor_ccb` field. Two facts about it were established from
source, and they point in opposite directions from the obvious reading.

**It is frozen wire today.** `canon()` (`dsm/src/dlv/settlement_bundle.rs:193-199`) is
`b.encode_to_vec()` with a decode/re-encode equality check, so

```text
b  =  H(DSM/settlement-bundle ‖ Canon(B))   where Canon(B) IS THE PROTOBUF ENCODING
```

`successor_ccb` therefore participates in the bundle identity. Removing it changes `b`.

**It is not merely redundant.** `is_close_transition` (`dsm/src/dlv/settlement_bundle.rs:135-146`)
uses it as the **bundle-shape discriminator**, comparing it against
`close_slot_commitment(vault_id, parent_generation)`; on a market transition it carries `x`.

## The ruling

> The field is **not** deleted from a frozen encoding. **The encoding containing it is superseded in
> full**, and 2c-A already prohibits the field in as many words.

2c-A's governing sentence:

> **"Do not carry both the complete successor and a second independently encoded successor digest."**

2c-A replaces `Canon(B)` with `CCB(0x000E)`; makes the optional nested `MarketTerms` (`0x0033`)
field 1 the shape discriminator — *"The decoder learns the bundle shape from `0x000E` field 1"*,
*"presence marker always emitted; present iff Market"* — and makes `0x000F` field 2 the **complete
nested `0x0001` schema 4** successor, from which
`c_{n+1} = H_dom(DSM/vault-state, CCB(T_v.successor))` is derived.

```text
successor_ccb            dies with the CCB cut. Its discriminator role is
                         already assumed by MarketTerms presence, frozen by 2c-A.

parent_reserves_digest   the same. Width-checked in validate() and carried in b
                         today, while Def 6.14 says it is not carried (D1).

b over prost bytes       a RECORDED §2.10 DEFECT of the shipped encoder. §2.10
                         says a serialized protobuf is never a valid CCB blob
                         and must never be hashed as if it were; the shipped
                         bundle identity does exactly that. Owned by the
                         encoder change, NOT by C3.
```

**C3's predicate is stated over the CCB form.** No proto change belongs to this amendment, and no
conditional survives: the proto fields and the comments that describe them
(`dsm_app.proto:1745,1761`) die with the cut. Until the cut lands, `b` violates §2.10, and this
amendment records that rather than depending on it.

---

# Ruling E — the outcome taxonomy: two layers, totality over applicable outcomes

> Every atomic conjunct maps to exactly one **class** and one **reason**. There is no catch-all
> outcome, no error-to-absence conversion, and no unmapped branch.

```text
LAYER 1   class    VALID | INVALID | INCOMPLETE | SAFETY_VIOLATION
LAYER 2   reason   an exact code; Rev 15's own names are used where they exist.
                   Layer 2 REFINES layer 1 and never competes with it.

per atomic conjunct:
    holds                         ->  VALID contribution
    decidably false               ->  INVALID          + exact reason
    evidence genuinely missing    ->  INCOMPLETE       + exact reason
    proven safety contradiction   ->  SAFETY_VIOLATION + exact reason
```

**Totality is over applicable outcomes only.** A purely structural conjunct — one computed entirely
from bytes already in hand — has no `INCOMPLETE` branch, and inventing one to satisfy a symmetry
would be a lie about what can happen. The requirement is that every branch a conjunct *can* take is
mapped, not that every conjunct takes every branch.

## The three classes that are not INVALID

`INCOMPLETE` is the C2 distinction carried forward: a verifier that cannot obtain evidence has not
learned that a claim is false. Req 6.25's `DLV_BINDING_EVIDENCE_UNAVAILABLE` is the canonical
instance — candidate validity and binding finality are different questions.

`SAFETY_VIOLATION` is reserved for a proven contradiction in the storage substrate, not for a failed
check. Duplicate binding finality at one DLV parent is the defined case, and Req 6.3's five
obligations attach:

```text
1. report STORAGE_SAFETY_VIOLATION
2. quarantine that parent AND every descendant depending on either continuation
3. refuse new market execution involving the affected lineage
4. preserve BOTH evidence objects
5. NEVER tie-break
```

Tie-breaking is forbidden because either continuation may already have been relied upon; picking one
converts a detected safety failure into a silent, blessed fork.

**Obligations 2, 3 and 4 have no mechanism in the repository.** Their trigger, scope, persistence,
effects, the absence of any clearing path and the denial-of-service boundary are frozen by
[amendment 2c-C3.1](amendment-2c-c3-1-lineage-quarantine.md), which also records that the
single-read `Conflict` arm is arithmetically unreachable at the canonical quorum, so the
contradiction this class names is observable by one verifier only across reads.

## What this forbids in the implementation

```text
FORBIDDEN   a catch-all "other" arm
FORBIDDEN   .ok() / .ok()? / .ok().flatten() over a fallible VERIFICATION step
FORBIDDEN   mapping an error to an absence
FORBIDDEN   mapping a FAILED SIGNATURE to an absence
FORBIDDEN   any branch without a (class, reason)
```

The fourth is listed separately because the shipped code does exactly that, and does it deliberately:
`fetch_verified_receipt` discards a failed SPHINCS+ receipt verification with `.ok()?`, and its doc
comment defends the collapse on the ground that *"the only decision downstream is whether the pointer
may be folded, and every one of these says it may not."* That reasoning is sound about **folding** and
wrong about **classification** — the fold stops either way, but a forged receipt and an absent one are
not the same fact, and the resulting `MarketRealization::Absent` returns `Ok(...)` rather than any
error at all. Under this ruling a failed verification is `INVALID`, never an absence.

---

# Ruling F — field disposition, including the encumbrance rule

Every member of the fifteen-tuple has a disposition, and the table below is the whole of it. The
routed-open questions are then answered as exact rules rather than deferred.

## The complete field disposition

`P` preserved · `M` mutated deterministically · `R` ruled below. Fields are Def 4.1's order, as
frozen in registry §5.1.

| # | Field | Market successor | Release/close successor |
|---|---|---|---|
| 1 | `owner_genesis_id` (`g_o`) | `P` | `P` |
| 2 | `owner_device_id` (`d_o`) | `P` | `P` |
| 3 | `vault_id` | `P` — fixed at creation | `P` |
| 4 | `generation` (`n`) | `M` `n + 1` | `M` `n + 1` |
| 5 | `reserve_a` (`R_A`) | `M` per `direction` (D4) and the constant-product update | `M` `0` |
| 6 | `reserve_b` (`R_B`) | `M` per `direction` (D4) and the constant-product update | `M` `0` |
| 7 | `market_policy` (`P_M`) | `P` | `P` |
| 8 | `release_policy` (`P_R`) | `P` | `P` |
| 9 | `fee_policy` (`Φ`) | `P` | `P` |
| 10 | `encumbrances` (`E`) | `R` — removal rule | `R` — removal rule |
| 11 | `iteration_budget` (`β`) | `R` — decrement rule | `R` — decrement rule |
| 12 | `parent_state_commitment` (`h_n`) | `M` `c_n` | `M` `c_n` |
| 13 | `owner_authority_transition_digest` (`r_o`) | `P` | `P` — `R` |
| 14 | `storage_set` (`S`) | `P` | `P` — `R` |
| 15 | `quorum` (`q`) | `P` | `P` — `R` |

Exactly one field pair — 5 and 6 — differs in *kind* between the two successor families: the market
update moves value between the legs, the close drains both to zero. That is what makes `Retired`
(D2) a sound marker, and it is why `VDS.MARKET.3` must refuse a market successor of a retired parent.

**These dispositions are derived consequences, not acceptance conjuncts** (Ruling B). They are what
`DeriveExpected` computes; `VDS.COMMON.10.a` is what checks them, all at once, as bytes.

## Owner authority (field 13, `r_o`)

Rev 15 asserts invariance across a *market* successor and says that changing it *"requires an
explicit owner-authorized successor family, which the beta profile does not define."* The only close
family is `OWNER_LOCAL_FULL_CLOSE`, which takes **no parameters** — *"there is nothing left to
parameterise"* — so it cannot express an authority change either.

```text
RULED:  V_{n+1}.r_o = V_n.r_o  on BOTH successor kinds.
        Market: by the explicit invariance rule.
        Close:  because no beta family can express a change.
```

## Storage set and quorum (fields 14, 15)

2c-A froze equality unconditioned on kind; the decomposition's routing table nonetheless sends the
close case here. Answered affirmatively rather than by restating 2c-A: the close family drains and
retires, touching neither membership nor threshold, and Req 6.10/6.11 bind `q` to the committed set
for the vault's life.

```text
RULED:  the close is NOT an exception.
        V_{n+1}.storage_set = V_n.storage_set   and
        V_{n+1}.quorum      = V_n.quorum        on both kinds.
```

The quorum is additionally required to be the canonical strict majority `n/2 + 1`, checked as exact
equality in both directions (C2). A smaller committed quorum lets two disjoint claim sets each reach
threshold, which is two winners for one generation.

## The iteration budget `β` (field 11)

`β` is optional, and absence is the common case — which §13's `β_{n+1} = β_n − 1` does not
contemplate. Under derive-and-compare a change to the presence marker is a **byte** change, so
presence must itself be derivable:

```text
RULED:  absent in V_n            ->  absent in V_{n+1}      (nothing to decrement)
        present, β_n > 0         ->  present, β_{n+1} = β_n − 1
        present, β_n = 0         ->  INADMISSIBLE; no successor exists
        introduction or removal  ->  FORBIDDEN; not derivable from the transition

        Req 13.1 stands: failed verification, retries, unavailable routes and
        failed settlement acquisition consume NOTHING.
```

## The encumbrance set `E` (field 10)

§8 is a source of successor-validity conditions, not background. Req 8.1 states one directly:

> *"A claim is consumed at most once and its **exact removal must be visible in the successor
> state**."*

Def 9.1's allocation is `(parent_binding, Δin, Δout, e, Φ)`, and Rev 15 fixes `e`'s type precisely:
*"`c_n` AUTHENTICATES the parent's whole encumbrance state, while `e` SELECTS the one claim that
allocation spends."* `E` is a member of `V_n`, so `c_n` commits it — the same pattern as D1.

```text
RULED:  V_{n+1}.encumbrances = V_n.encumbrances \ {e}   when the allocation names e
        V_{n+1}.encumbrances = V_n.encumbrances         otherwise

        INTRODUCING a claim is FORBIDDEN on both kinds: it is not derivable from
        the transition, and Req 8.1 licenses removal only.

        Req 8.2 solvency, checked on the SUCCESSOR: for every token,
            Σ_{e ∈ E_t} amount(e)  ≤  R_t.
```

**The general rule is stated, not beta's instance.** `EncumbranceSet::empty()` is the only value ever
constructed (`dsm/src/ccb/mod.rs:631`, `dsm/src/types/device_state.rs:3187`); there is no
add/release/compare path anywhere; and **no `Allocation` type exists in Rust at all**, so `e` is
spec-only today. Writing *"E is preserved"* as the normative rule would silently narrow Req 8.1 to
the empty case of an unimplemented mechanism and bake that into the predicate — a beta accident
promoted to protocol, which is what this registry exists to prevent.

Because beta's `E` is always empty, a green suite around this conjunct proves nothing about it. The
mutation controls are therefore mandatory: a successor that **adds** a claim, and a successor that
**drops** one with no consuming allocation, must each be rejected by a named test.

---

# Ruling G — the terminal-close owner credit is declared, not discharged

Def 6.1's terminal-close tail carries two obligations:

> *"credit the released DLV reserves to ordinary owner balance **exactly once** and mark the DLV
> terminal/retired so no later market successor may compose from the retired parent."*

The retirement half is D2 and is C3's. The credit half **is not a property of `V_{n+1}` at all** — it
is a property of the owner's ordinary DSM balance state. No predicate over the vault successor can
express it, and derive-and-compare cannot see it.

```text
RULED:  C3 discharges the DLV-side condition:
            both legs zero, Retired(V_{n+1}), and no market successor composes
            from the retired parent.

        The exactly-once owner credit is an ATOMICITY obligation ACROSS TWO
        STATE OBJECTS. C3 DECLARES it and does NOT discharge it.

        It must not be dropped merely because it is invisible to the successor
        predicate. A close that retires the vault without crediting the owner
        destroys value; a close that credits twice creates it.
```

---

# Ruling H — token policy is a declared external dependency

```text
ValidDlvSuccessor       :=  ValidDlvSuccessorCore  ∧  TokenPolicyValid

ValidDlvSuccessorCore   :=  what C3 proves
TokenPolicyValid        :=  DECLARED external dependency; owner named;
                            NOT discharged by C3
```

The 2c-C decomposition excludes token policy validity from every 2c-C sub-amendment. The rename
exists so that no artifact of this amendment can be read as having closed a dependency it
deliberately does not own: a theorem named `ValidDlvSuccessor` would make exactly that claim by its
name alone.

---

# Ruling I — the settler's identity is derived authority, never self-assertion

An operation carries `settler_public_key` and `settler_devid`. Whether the verifier must compare
them against externally resolved values has been recorded inconsistently — 2c-B calls the
non-comparison a hole; the parent 2c document calls it doctrine.

```text
RULED:  BOTH readings hold, because they answer different questions.

        op.settler_public_key   MUST equal the externally resolved proven_ak
        op.settler_devid        MUST equal the DevID established by ordinary
                                DSM authority resolution
        signature verification  MUST use the EXTERNALLY PROVEN authority key

        The embedded fields are CORRESPONDENCE CLAIMS. They are never their own
        authority source.
```

**Pinning is commitment, not authority validation.** The fields exist so that the operation commits
to which authority it was constructed under — that is the doctrine. Comparing them to the resolved
authority is what makes the commitment checkable — that is the hole. Verifying a signature with a key
the object supplies about itself proves only that the object is internally consistent.

---

# Ruling J — the C3 input contract: typed prerequisite results

C3 owns `INVALID` / `INCOMPLETE` / `SAFETY_VIOLATION` classification. It therefore **cannot** receive
success-only facts: an input shape that admits only established successes makes C3 blind to the very
outcomes it is defined to classify.

```text
C3Input {
    parent_authentication : Established(V_n)
                          | Invalid(reason) | Incomplete(reason)

    authority_resolution  : Resolved(proven_ak, network_id)
                          | Invalid(reason) | Incomplete(reason)

    binding_observation   : Free | BoundFinal(..) | Conflict(..)
                          | Undetermined(..) | Unavailable(..)

    operation             : Canonical(..) | Invalid(reason)

    economic_facts        : Established(..)
                          | Invalid(reason) | Incomplete(reason)
}
```

```text
C4  OBTAINS and PROVES those observations from the ordered evidence walk.
C3  ASSIGNS their normative meaning for successor validity.
```

## The binding observation has FIVE arms, not four

An earlier draft of this amendment described `binding_observation` as *"C2's four-valued
`CellObservation`, unchanged"*. **That named the wrong type.** Two distinct observation types exist
over two distinct key spaces, and only one of them is C2's:

```text
CellObservation      dsm::economic::cell_observation      FOUR arms
                     the ECONOMIC REGISTER cell
                     Claimed | EmptyAtQuorum | Conflict | Unavailable
                     frozen by 2c-C2; C3 does not consume it here

BindingObservation   dsm::dlv::binding_observation        FIVE arms
                     the DLV PARENT-BINDING slot
                     Free | BoundFinal | Conflict | Undetermined | Unavailable
                     this is what the settle path actually reads
```

C3 consumes the **five-valued** one and preserves every arm. The mapping is normative:

| arm | class | reason |
|---|---|---|
| `Free` | `INVALID` | `NO_BINDING_ESTABLISHED` |
| `BoundFinal(chosen)` | — | proceeds to `VDS.COMMON.10.a` |
| `Conflict { distinct }` | `SAFETY_VIOLATION` | `DUPLICATE_BINDING_FINALITY` (Req 6.3) |
| `Undetermined { attributed, .. }` | `INCOMPLETE` | `BINDING_UNDETERMINED` |
| `Unavailable { attributed, required }` | `INCOMPLETE` | `BINDING_EVIDENCE_UNAVAILABLE` |

Two facts about this table are easy to get backwards, and the module that defines the type says so
in its own header.

**`Undetermined` is neither emptiness nor forgery.** Two quorums intersect, but one *read* need not
see the intersection: a value already chosen behind a down member lands here. Reading it as `Free`
composes past a bind that is mid-flight; reading it as invalid *"would make every concurrent settle
permanently invalid."* It is retryable evidence and nothing else — which is why it takes `INCOMPLETE`
with its **own** reason, distinct from `Unavailable`'s.

**`Free` is `INVALID`, not `INCOMPLETE`.** A quorum of authenticated explicit absences is positive
evidence: if a value were chosen, `q` members would hold it and any `q`-subset would intersect them.
So `Free` proves this successor never won exclusivity over the parent it names — decidably false,
not unlearned. Req 6.25's distinction is between *candidate validity* and *binding finality*; it does
not license treating a proven absence as an unanswered question.

The boundary is preserved — C3 still does not perform the walk — while the taxonomy stays coherent
across all five arms.

---

# The clause inventory

## Level 1 — Rev 15's own grouping

Def 6.1 groups the conditions as a kind-specific **completion gate**, ten **common** checks, and
three tails. This level preserves that grouping exactly, including its compound tenth item.

```text
GATE       kind-specific composability      Def 6.1(a), Def 6.1(b)
COMMON     ten checks for either kind       Def 6.1
MARKET     two additional                   Def 6.1 market tail
CLOSE      two additional                   Def 6.1 release/close tail
TERMINAL   two additional                   Def 6.1 terminal-close tail
```

Sixteen items at this granularity; seventeen if `COMMON.10`'s compound is split. **Neither number is
normative** — see Ruling A.

## Level 2 — atomic conjuncts

`D` marks a **derived** consequence rather than an acceptance conjunct (Ruling B). `∅` marks a
retired item. Classes are the failing outcome; every conjunct contributes `VALID` when it holds.

### Gate

| id | condition | source | on failure |
|---|---|---|---|
| `VDS.GATE.M.1` | the complete `SettlementBundle` is binding-final | Def 6.1(a), Def 6.24 | `INCOMPLETE` unresolved · `SAFETY_VIOLATION` if two distinct bundles are binding-final at one parent (Req 6.3) |
| `VDS.GATE.M.2` | the exact initiating trader successor has a verified acceptance artifact `A_B` | Def 6.1(a), Def 6.26 | `INCOMPLETE` absent · `INVALID` present and not verifying |
| `VDS.GATE.C.1` | the exact release/close candidate is binding-final for the current parent | Def 6.1(b) | `INCOMPLETE` · `SAFETY_VIOLATION` on duplicate |
| `VDS.GATE.C.2` | the successor verifies under Req 4.6, token policy, conservation and owner authority Def 5.1(a) | Def 6.1(b) | `INVALID`; token policy per Ruling H |

`VDS.GATE.C.*` requires **no** `A_B` and no owner-side post-binding acceptance artifact. The two gate
arms are **disjoint and exhaustive** over the successor kinds; a market successor evaluated under the
close arm is `INVALID`, never accidentally accepted.

### Common

| id | condition | source | on failure |
|---|---|---|---|
| `VDS.COMMON.1` | `V_n` authenticates against `c_n = H_dom(DSM/vault-state, CCB(V_n))` | Req 6.6, D1 | `INVALID` mismatch · `INCOMPLETE` if `V_n` unobtainable |
| `VDS.COMMON.1.a` | the operation's named vault equals `V_n.vault_id` | Def 6.1 | `INVALID` |
| `VDS.COMMON.2` | the operation's parent generation equals `V_n.generation` | Def 6.1 | `INVALID` |
| `VDS.COMMON.3` | the successor's parent reference equals `c_n` | Def 6.1, Thm 6.7 | `INVALID` stale or forged parent |
| `VDS.COMMON.4` | ∅ **RETIRED** — parent reserves digest | D1 | — |
| `VDS.COMMON.5` | `V_{n+1}.storage_set = V_n.storage_set`, and `storage_set_id` re-derives from it | Def 6.1, Ruling F | `INVALID` |
| `VDS.COMMON.6` | `V_{n+1}.quorum = V_n.quorum`, and equals the canonical `n/2 + 1` | Def 6.1, Req 6.10/6.11, C2 | `INVALID` |
| `VDS.COMMON.7.a` | `V_{n+1}.E = V_n.E \ {e}` when the allocation names `e`, else `V_n.E` | Req 8.1, Ruling F | `INVALID` |
| `VDS.COMMON.7.b` | no claim is introduced | Req 8.1, Ruling F | `INVALID` |
| `VDS.COMMON.7.c` | solvency on the successor: `Σ amount(e) ≤ R_t` per token | Req 8.2 | `INVALID` |
| `VDS.COMMON.8.a` | `direction` derives from the policy-commit set equality | D4 | `INVALID` if the pair is not `V_n`'s market pair |
| `VDS.COMMON.8.b` | the seven admissibility conditions hold | §5.1, market admissibility | `INVALID`, each with its own reason |
| `VDS.COMMON.8.c` | checked arithmetic; the single floor division is the only rounding | §5.1 | `INVALID` on overflow |
| `VDS.COMMON.9` | conservation with `fee_t = 0` | §7.1, D3 | `INVALID` |
| `VDS.COMMON.10.a` | **`VDS.CORRESPONDENCE`** — `Canon(expected) = Canon(supplied)` — **IMPLEMENTATION-BLOCKED**, see below | Def 6.1, Ruling B | class and reason propagated from `DeriveExpected` |
| `VDS.COMMON.10.b` | the proof material selected by the binding decision is byte-identical | Def 6.1 | `INVALID` |
| `VDS.COMMON.11` | the advancing party's signature verifies over the concrete successor CCB | §5.2 item 1 | `INVALID` |
| `VDS.COMMON.12` | settler identity correspondence against externally resolved authority | Ruling I | `INVALID` mismatch · `INCOMPLETE` unresolved authority |
| `VDS.COMMON.13` | `β` presence and value per Ruling F | §13, Req 13.1 | `INVALID` |
| `VDS.COMMON.14` | `V_{n+1}.r_o = V_n.r_o` | §4, Ruling F | `INVALID` |
| `D` | every preserved field of `V_{n+1}` equals `V_n`'s | Ruling B | derived from `VDS.COMMON.10.a` |
| `D` | every mutated field equals its deterministic derived value | Ruling B | derived from `VDS.COMMON.10.a` |

### `VDS.COMMON.10.a` — normative, and implementation-blocked

```text
NORMATIVE                YES
FORMALLY SPECIFIED       YES   -- Ruling B; lean4/DSMValidDlvSuccessor.lean
PRODUCTION IMPLEMENTED   NO
BLOCKED ON               the 2c-A canonical encoder cut
```

**The exact blocker.** The conjunct needs two operands. The first, `expected`, is derivable today.
The second does not exist: no authoritative canonical successor bytes are carried on the wire.
`VaultTransitionV1.successor_ccb` holds the route-set commitment on a market bundle and
`close_slot_commitment(vault_id, parent_generation)` on a close — neither commits the successor
state, and the market writer's own comment says nothing reads it as a successor.

**What unblocks it.** 2c-A freezes `0x000F` field 2 as the **complete nested `0x0001` schema 4**
successor, from which `c_{n+1} = H_dom(DSM/vault-state, CCB(T_v.successor))` derives. Once that
encoder cut lands, the supplied operand exists and the comparison is implementable as stated.

**Owning prerequisite:** 2c-A. This amendment adds no class and changes no encoding, so C3 must not
absorb that cut, and Phase D must not manufacture a surrogate operand — not protobuf re-encoding, not
`successor_ccb`, not a newly invented field, not producer-derived bytes.

**What "blocked" must not mean.** It must not mean *accept without it*. Until the byte comparison has
actually been performed against authoritative supplied bytes, a verifier **must not** report full
`ValidDlvSuccessorCore = VALID` for any path whose validity requires this conjunct. Phase D therefore
exposes the gap explicitly as **implementation/deployment status** — a component that can report
`BlockedOnCanonicalSuccessorEncoding` — and **never** as a protocol reason code. The normative
`INVALID / INCOMPLETE / SAFETY_VIOLATION` taxonomy is not contaminated because a development
prerequisite has not landed.

`VDS.COMMON.11`–`14` are **not** from Def 6.1's ten. They come from §5.2's completion witness and
from the field-disposition rulings, and are numbered after the ten so that Def 6.1's own list stays
readable against the source.

### Market tail

| id | condition | source | on failure |
|---|---|---|---|
| `VDS.MARKET.1.a` | every allocation names `c_n` as its `parent_binding` | Def 9.1 | `INVALID` |
| `VDS.MARKET.1.b` | route-set membership holds for the bundle | Def 6.1 market tail | `INVALID` |
| `VDS.MARKET.1.c` | the `X` route-commitment check holds | Def 6.1 market tail | `INVALID` |
| `VDS.MARKET.2` | the live trader signatures ordinary DSM requires verify | Def 6.1 market tail | `INVALID` |
| `VDS.MARKET.3` | `¬Retired(V_n)` | D2, Def 6.1 terminal tail | `INVALID` — composition from a retired parent |

### Release/close tail

| id | condition | source | on failure |
|---|---|---|---|
| `VDS.CLOSE.1` | owner-local `P_R` is satisfied | Req 4.6 | `INVALID` |
| `VDS.CLOSE.2` | the concrete owner signature over the exact release successor verifies, against the 2c-B byte grammar | Def 6.1 close tail, 2c-B ruling 2 | `INVALID` |

`VDS.CLOSE.2`'s preimage is `CloseAuthorizationPreimageV1` as 2c-B froze it — **a byte grammar, never
a Rust function name**. A conformance vector produced by calling `Operation::to_bytes` would test the
implementation against itself.

### Terminal close

| id | condition | source | on failure |
|---|---|---|---|
| `VDS.TERMINAL.1` | `Retired(V_{n+1})` — both reserve legs zero | D2 | `INVALID` |
| `VDS.TERMINAL.2` | the released reserves credit ordinary owner balance **exactly once** | Def 6.1 terminal tail | **DECLARED, NOT DISCHARGED** — Ruling G |

---

# Implementation debts this amendment records

C3 is documentation. The changes that adopt it inherit these, and each must carry the conformance
vectors published under C2 ruling D.

**The comparison has no second operand.** `vault_state_composition.rs:572` discards a
`&VaultTransitionV1` with `let _ = transition;`, and that value is **not** a declared successor —
its `successor_ccb` carries `x` on a market bundle and `close_slot_commitment(vault_id, generation)`
on a close. Both arms derive the successor locally and there is nothing to compare against, so
`VDS.COMMON.10.a` is not merely unimplemented: it is **unimplementable against the current
encoding**. See its blocking note.

**Nor can `successor_ccb` simply be repurposed.** `is_close_transition`
(`dsm/src/dlv/settlement_bundle.rs:136-146`) derives `BundleShape` from exactly that field, and the
shape drives the arm selection at `vault_state_composition.rs:470`. Writing a genuine successor
commitment into it would silently reclassify every close bundle as `Market`. The field's disposition
belongs to 2c-A (Ruling D), and the shape discriminator must move first.

**A failed signature is not an absence.** `fetch_verified_receipt`
(`dsm_sdk/src/sdk/settlement_receipt_codec.rs:141`) converts a **failed SPHINCS+ receipt
verification** into `None` via `.ok()?`. That becomes `MarketRealization::Absent`, which `break`s the
fold and returns **`Ok(ComposedVaultState)`** — so a forged receipt is not an error at all, and never
reaches the error taxonomy for a split to correct. This is a larger hole than the two named below and
is an `INVALID` fact classified as an absence, which Ruling E forbids.

**The taxonomy collapses at the boundary.** `ParentOccupancy::Unresolvable`
(`vault_state_composition.rs:439-440`) funnels forged successors — wrong parent state, wrong
generation, wrong storage set, a non-canonical bundle — into
`CompositionError::BindingEvidenceUnavailable`, which is an `INCOMPLETE`-shaped name for an `INVALID`
fact. `MarketRealization::Contradicts` routes to the same place (`:551`), and its own comment says
*"A divergence is never an absence"* while the code makes it one. A `VerificationOutcome { class,
reason }` must replace it so the compiler forces the distinction.

**`advance_validated` has no `VaultStateV2` in its signature**, so C4's walk cannot consume a
`ValidDlvSuccessorCore` result even once one exists.

**Dead code and false comments.** `parent_state_commitment_for_successor_of` has zero callers. The
proto comments at `dsm_app.proto:1745,1761` describe `successor_ccb` and `parent_reserves_digest` in
terms Def 6.14 and 2c-A contradict; they die with the CCB cut (Ruling D).

## Discharge record (Phase F, 2026-09-09)

The line numbers above are those of the tree this amendment was written against and are kept as
written; each debt's disposition is recorded here rather than by rewriting the debt.

```text
the comparison has no second operand        OPEN         2c-A encoder cut
successor_ccb cannot be repurposed          OPEN         2c-A (shape discriminator moves first)
a failed signature is not an absence        DISCHARGED   #789: ReceiptFetch is four classes;
                                                         a present-but-failing receipt is
                                                         REALIZATION_EVIDENCE_INVALID, with a
                                                         corrupted-signature control
the taxonomy collapses at the boundary      DISCHARGED   #789: SuccessorInvalid / SafetyViolation
                                                         carry (reason, class); the sixteen
                                                         Unresolvable sites route by class
advance_validated has no VaultStateV2       DISCHARGED   #790: the return carries
  IN SHAPE                                               SuccessorValidity; the verdict slot on
                                                         that path is empty by design, C4 fills it
dead code                                   DISCHARGED   parent_state_commitment_for_successor_of
                                                         deleted (Phase F)
false proto comments                        OPEN         die with the CCB cut (2c-A)
```

---

# Registry and cross-document edits

- **§3 status pointers.** Mark 2c-C3 written and record that `ValidDlvSuccessorCore` is frozen while
  `TokenPolicyValid` is not (Ruling H).
- **§7.** Add the 2c-C3 bullet, recording the four Rev 15 errata and the two declared-undischarged
  conjuncts.
- **No new §2 primitives and no field-table changes.** C3 adds no class, changes no encoding and
  burns nothing; the counts in §4 do not move. The `successor_ccb` disposition is 2c-A's to execute.

---

# Closure status

```text
C3 predicate                       FROZEN
C3 Lean structure                  FROZEN / PROVED AS CLAIMED — 21 results, per-theorem
                                   axiom report, two mutation controls executed
VDS.COMMON.10.a                    NORMATIVE, IMPLEMENTATION-BLOCKED ON THE
                                   2c-A ENCODER CUT
Production ValidDlvSuccessorCore   IMPLEMENTED for every presently-evaluable conjunct
                                   (#788–#791, #795, #796); every fold carries
                                   PartialPendingEncoderCut; Valid is unconstructible
Req 6.3 containment (2, 3, 4)      FROZEN BY 2c-C3.1, IMPLEMENTED (client-local)
Owner-close C3 completion          needs 10.a only
Market C3 completion               needs 10.a AND the C4 realization fact
TokenPolicyValid                   EXTERNAL (Ruling H)
VDS.TERMINAL.2 owner credit        EXTERNAL (Ruling G)

C3 overall                         CLOSED EXCEPT 10.a — which is NOT "DLV succession
                                   verified": two conjuncts are external and one is
                                   blocked, and every fold today says so as a value
```

**Successor validity — FROZEN** as `ValidDlvSuccessorCore`: the clause inventory, the derivation
contract, the outcome taxonomy, the field dispositions and the input contract. **Frozen is not the
same as presently implementable** — `VDS.COMMON.10.a` is normative and blocked, as recorded above.

**Two conjuncts are DECLARED AND UNDISCHARGED**, named so that "C3 is closed" can never be read as
"DLV succession is fully verified":

```text
TokenPolicyValid           Ruling H   external dependency, owner named
VDS.TERMINAL.2             Ruling G   cross-object atomicity, inexpressible here
```

**Rev 15 errata — CORRECTED, four of them**, two of which made the predicate unformulable as
written. A verifier built literally from Def 6.1 and §7.1 rejects every valid beta market successor.

**The evidence walk — NOT C3's.** How results compose into an accepted-successor proof remains
2c-C4's; `TA_B` and the bundle-acceptance leaf remain 2c-D's.

**Implementation — DONE for every presently-evaluable conjunct (Phase F report, 2026-09-09).**
Phase D landed the core module and typed derivation (#788), the taxonomy split and receipt classes
(#789), the settler-identity seam, the widened `advance_validated` (#790) and both composition arms
deriving through the predicate (#791); Phase E landed the class-1 vectors (#792), the lineage
quarantine that 2c-C3.1 froze (#793, #795) and the forced-partial control (#796). The predicate's
central comparison still does not exist — `VDS.COMMON.10.a` waits on 2c-A — and every fold records
`PartialPendingEncoderCut` rather than an absence, so the withheld claim is a value a caller must
confront. `C3Verdict::Valid` cannot be constructed anywhere; `compile_fail` doctests pin it.

**Formal coverage — PROVED AS CLAIMED.** `DSMValidDlvSuccessor.lean` carries proof bodies for every
statement, a per-theorem `#print axioms` report (no result depends on `sorryAx` or
`Classical.choice`), and two executed mutation controls; `DSMLineageQuarantine.lean` (2c-C3.1) adds
twenty results and four executed controls. CI kernel-checks all thirteen modules with the count
pinned. "Axiom-free" remains a per-theorem statement, never a blanket one.

# Scope

**Documentation only. No Rust, no proto, no tests.** The one exception in the adopting sequence is
that C2's owed registry edits land first, as a separate commit, because C3 cites the registry.

# Verification

1. **Every clause was traced to source before it entered the inventory**, and the four errata were
   each derived rather than asserted: D1 from Def 6.14's own sentence, D2 from market admissibility
   forbidding `a = 0`, D3 by substituting the beta successor into §7.1 in both token directions, D4
   from `beta_constant_product`'s refusal of an unordered pair.
2. **D4's totality was proved, not assumed.** The `token_a < token_b` strictness that makes the
   direction derivation single-branched is enforced at construction
   (`dsm/src/ccb/state.rs:234-238`), and the same set-equality check refutes `input = output`.
3. **The `successor_ccb` investigation reversed an earlier draft.** `canon()` was read at source and
   found to be `encode_to_vec()`, making the field frozen wire and a shape discriminator rather than
   dead weight — the opposite of the draft's assumption. The ruling follows 2c-A's explicit
   prohibition instead of the draft's reasoning.
4. **Phase A was completed before any statement was written**, which is what surfaced Req 8.1 as a
   successor condition (Ruling F) and the owner credit as inexpressible (Ruling G). Neither was in
   any earlier draft.
5. **The 2c-B verifier claim was checked rather than cited.**
   `dsm/src/economic/successor_evidence.rs:164-174` recomputes via `relationship_chain_tip_v2` and
   returns `CommitmentMismatch`, so the carried value genuinely is not accepted as authority.
6. **Research ran read-only and was proved so** — `git status --porcelain` and `git diff
   --exit-code` clean before and after — under the rule adopted after a subagent silently repaired
   the defects it had been sent to audit during 2c-C1.
7. **Self-contradiction sweep** for `no / never / always / only / every / single`, and specifically
   that no sentence claims `Canon(expected) = Canon(supplied)` is the whole predicate, that no
   sentence claims C3 discharges token policy or the owner credit, and that no clause count is
   presented as normative.

# Corrections made to this amendment before it merged

A read-only survey of the Rust surface, run before any production code was written, found three
defects in the first draft of this document. They are recorded rather than silently rewritten,
because the draft was circulated for review and because two of them were confident, specific and
wrong.

**The production-debt statement was false.** The draft said line 572 binds *"the bundle's declared
successor"*. No declared successor exists on the wire; `successor_ccb` carries the route-set
commitment or a slot commitment, and both composition arms derive the successor locally. Corrected,
and `VDS.COMMON.10.a` is now marked implementation-blocked on the 2c-A encoder cut rather than merely
unimplemented.

**Ruling J named the wrong observation type.** The draft said the binding observation is C2's
four-valued `CellObservation`. The settle path reads the five-valued
`dsm::dlv::binding_observation::BindingObservation`, whose extra arm — `Undetermined` — is the one its
own module header calls easy to get backwards. All five arms are now mapped, and the Lean module was
corrected to match before this document was.

**The correspondence condition needed a byte-level statement.** The draft said
`Canon(expected) = Canon(supplied)` without excluding a decode/re-encode substitute. Because
`decode_vault_state` normalizes rather than refuses, that substitute silently accepts non-canonical
bytes. Now stated as byte equality, with the round-trip permitted only under the frozen normative
encoder — which does not yet exist.

The first two would have become normative authority had this merged unreviewed. That is the argument
for the ordering, not an argument against it: the survey ran before Phase D, and the cost of all three
was one corrective commit rather than a retraction against shipped code.
