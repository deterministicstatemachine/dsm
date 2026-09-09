# Amendment 2c-C4 — Accepted-successor closure: the ordered evidence walk and the realization fact

Governs how far a third party can carry a binding-final market `SettlementBundle` toward
realization: the ordered evidence walk that produces the facts `ValidDlvSuccessorCore` consumes, the
accepted-successor / economic-root correspondence, and the definition of the realization fact whose
final conjunct only 2c-D can supply.

Status: **SPECIFICATION FROZEN.** The numbered walk, the correspondence theorem, the shape of
`IndependentRealization` and the boundaries it unlocks are normative here. The Lean module and the
production Rust follow this document; neither precedes it.

Prior: 2c-C1 (framework + namespace), 2c-C2 (verification substrate), 2c-C3 (`ValidDlvSuccessorCore`,
CLOSED), 2c-C3.1 (lineage quarantine), 2c-A/2c-A.1 (the canonical bundle and the encoder cut),
2c-B (the accepted-successor substrate `0x0031` and the two foreign grammars).
Next: 2c-D, which defines the bundle-acceptance leaf and `0x0011` `TraderAcceptance`, and is the
**only** amendment that can make this document's realization fact constructible.

**C4 allocates no class number and changes no encoding.**

---

# What this amendment decides, and what it deliberately cannot

C3 froze the predicate and closed every conjunct it could evaluate. Its market arm ends at a
verdict that says, in a type, that one fact is missing:

```text
C3Verdict::PartialPendingRealization(CorrespondenceWitness)
```

C4 says what that missing fact **is**, how a verifier obtains it without write authority over the
trader's chain, and where it is constructed. It does not make it constructible. That distinction is
the owner ruling this document is built on, and §5 states it as a rule rather than as a status.

```text
C4 DECIDES
    the trusted start and the ordered economic walk, position by position
    the accepted-successor / economic-root correspondence, as a theorem
    the definition of IndependentRealization, parameterised by a witness it cannot make
    which seam constructs the market verdict, and the disposition of the seam that does not
    which boundaries a Valid market verdict unlocks, as preconditions

C4 DOES NOT DECIDE
    the bundle-acceptance leaf, its key, its content, or 0x0032          2c-D
    TA_B 0x0011 — its field table AND all verification of it            2c-D
    TokenPolicyValid, VDS.TERMINAL.2 owner credit                        external (C3 rulings H, G)
    quarantine trigger, scope or clearing                                2c-C3.1 (C4 consumes it)
    walk budgets; vector CLASSES and independent-encoder provenance      2c-C2 (rulings C, D)
    the market producer's ordering                                       5c-2 Step 2/3
    identity-scoped reprovision                                          deployment (2c-A.1 ruling 4)
```

---

# §1 — Corrections C4 builds on

These are restated, not re-ruled. Each was fixed by an earlier amendment whose text stands; Rev 15's
own prose is unamended, so a verifier built literally from the paper builds the wrong object. C4
cites the correction at every point it relies on one.

## 1.1 `C_T^+` does not commit `R_T^+`, and the authentication is a linked pair

Rev 15 Def 6.26 requires the accepted-successor commitment to commit *"the trader relationship/chain
identity, the exact accepted `trader_parent → trader_successor` transition, and the post-advance
authenticated state root `R_T^+`"*, and Req 21.17's mandatory forged-root vector is written against
exactly that shape: verification fails *"because no valid ordinary DSM successor-state authentication
`σ_T^+` verifies directly over that forged `C_T^+`"*.

**DSM has no such commitment.** 2c-B established that `relationship_chain_tip_v2` commits `rel_key`,
`embedded_parent`, `counterparty_devid`, `operation_bytes`, `entropy` and `encapsulated_entropy` —
succession facts only — and that *"the relationship chain tip does not and must not contain the
economic root."* 2c-B labels its own section *"a spec correction, not a transcription"*.

The replacement, which C4 uses throughout, is 2c-B's **linked pair**:

```text
sigma_dsm over C_dsm+                     the ordinary DSM successor-state authentication
        AND
the validated-root walk that binds        the economic side, derived and never read
    that exact C_dsm+ to R_T^+
```

**Req 21.17 survives the correction and changes mechanism.** The forged-root attack is still
mandatory and still fails, but not because a signature refuses to verify over a root-bearing
commitment. It fails because the walk **derives** `R_T^+` and never reads a carried or claimed one,
so an attacker-chosen post-root has nothing to attach to. §3 states the derivation and §9 restates
the vector — **both of its arms** — in the corrected terms.

## 1.2 The acceptance leaf is not required to bind all four coordinates

Rev 15 Def 6.26 has the verifier check *"that `L_B` binds the exact
`(trader_parent, trader_successor, b, X)` committed by `B`."* Amendment 2c §1.4 says the opposite —
*"`L_B` alone is not required to bind all four, and an implementation that adds `b` or the trader
coordinates to the leaf has duplicated a commitment rather than strengthened one"* — and §9.1
replaces both with the two-conjunct rule under which the **bundle-acceptance** leaf binds `b` and the
conjunction carries the rest. The shipped settlement-payment leaf binds `X` and the quantities, never
`b`; the bundle-acceptance leaf is a distinct object, and 2c §8 Blocker 1 is where it is required.

**The live rule is §9.1's conjunction.** C4 depends on the **bundle-acceptance** leaf binding `b` and
on nothing else about its content, which is what keeps its design entirely inside 2c-D.

## 1.3 Symbols and operands corrected elsewhere

```text
A_B  ->  TA_B (0x0011, digest ta_B)      registry §6a Finding 4; bare A_B retained for neither
A_B  ->  AB_{A→B} (0x0016)               the allocation bundle, the other former A_B
Def 6.14 "and generation"                deleted — no generation counter in B (2c-A ruling 4)
parent-reserves-digest operand           retired (2c-C3 ruling C)
the settlement receipt                   a trader's self-attested claim, NOT proof value moved
                                         (settlement_receipt_leaf's own module header)
P0-P6                                    NOT a normative interface; 2c-C2 ruling A freezes the
                                         authority-resolver CONTRACT, which returns proven_ak and
                                         network_id. C4 names the contract, never the numbering.
```

---

# §2 — Inputs, and the shapes C4 may assume

C4 restates no primitive. It consumes these, and a change to any of them is an amendment to the
document that froze it, not to this one.

**Three coordinate families, and they are not interchangeable:** the economic lineage
`(G, DevID, p)`, the vault cursor `(V, c_n, g)`, and the trader's DSM pair
`(trader_parent, trader_successor = C_dsm+)`. §3 walks the first, §6 the second, and §4 is the only
place a value from one family is compared against a value from another.

| input | frozen by | what C4 assumes |
|---|---|---|
| `0x000E` / `0x0033` coordinates | 2c-A, 2c-A.1 | `trader_parent` is the exact ordinary-DSM bilateral parent commitment; `trader_successor` is the exact prepared `C_dsm+`; `K(B)` is derived from the DLV `c_n` |
| `0x0031` `DsmSuccessorEvidence` | 2c-B | seven fields; `c_dsm_plus` recomputed, never carried; `embedded_parent == trader_parent` enforced at `SettlementBundle::market` and `market_terms_at` — **landing with PR #800, not yet on `main` at the time of writing** |
| the grammar and chain-tip conjuncts | 2c-B, split by owner ruling 2026-09-09 | **not yet enforced anywhere.** They are stated in §2.1 as the preconditions C4 consumes, and land with 5c-2 Step 2/3. C4 must not become the first place they exist |
| per-position primitives, failure taxonomy | 2c-C2 | register winner; admission manifest by content address; the **authority-resolver contract's** `proven_ak` and `network_id` (2c-C2 ruling A) |
| `C3Input`, `C3Verdict`, `may_fold` / `may_certify`, `CorrespondenceWitness` | 2c-C3, 2c-A.1 ruling 12 | the witness exists only because `Canon(expected)` equalled the supplied field-2 span; `c_{n+1}` comes from the supplied bytes |
| quarantine state, its trigger and its five effects | 2c-C3.1 | consumed at the composition cursor per §6 Ruling C3; nothing clears it |

## 2.1 2c-B's deferred conjuncts, and what they do and do not gate

Named here so no reader mistakes their absence for an oversight. Each is 2c-B's, deferred to 5c-2
Step 2/3 by owner ruling. The prefix is deliberately not `P`, which 2c-C2 retired (§1.3):

```text
G1  operation_bytes decodes under DlvSettleOperationPreimageV1, consuming ALL bytes
G2  re-encode(decode(operation_bytes)) == operation_bytes
G3  discriminator == 26 and mode == Unilateral
G4  relationship_chain_tip_v2(<its six inputs>) == B.market_terms.trader_successor
```

**`G1`–`G4` gate the BUNDLE's structural validity, not this walk.** The walk of §3 obtains the
accepted transition from the trader's own validated economic lineage and never parses `B`'s carried
`operation_bytes`, so it has no dependency on them; a C4 verifier treats those bytes as opaque. What
`G1`–`G4` add, when they land, is that a bundle whose carried evidence disagrees with itself is
refused before any verifier reads it.

**Nothing may fabricate these operands to make a current vector pass** (owner ruling, 2026-09-09).

**`sigma_dsm` is verified under the authority resolver's proven `proven_ak`**, never under a key the
artifact or the operation body names. Identity derives from `rel_key` and `counterparty_devid` only.
A mismatch is a refusal, not a repair.

---

# §3 — The economic walk

The walk answers one question per economic position: *what did this trader's chain actually accept,
and does this verifier believe it?* It ends at a validated economic root, and that is where C4's
chain stops.

**This walk is keyed on `(G, DevID, p)`.** It is not the DLV composition walk, which is keyed on a
vault cursor `(V, c_n, g)`. Neither walk may take a *step operand* from the other; §4 is the only
place a value from one is compared against a value from the other, and §6 carries every cursor-keyed
rule outside that join, including the quarantine.

## Ruling W1 — the trusted start

> Position 0 for **any** lineage, including a foreign one, is the canonical empty activation root.
> A verifier may start from its own earlier conclusion — a completed, validated walk it performed —
> and from nothing else. A pinned checkpoint, an operator-supplied root, and the register winner at
> `p-1` are all **network or operator values** and are refused as starting points.

This is amendment 2c §1.2's rule made explicit for the foreign case: *"previously VALIDATED `R_econ`
(this verifier's own earlier conclusion, or the canonical empty activation root — **never a network
value**)"*. Registration is not validation; the register establishes non-equivocation and nothing
about transition validity, so the winner at `p-1` is a locator, never a start.

A verifier's own memo — its cache of walks it completed — may **shorten** a walk and may never change
a verdict. A memo obtained from anyone else is a network value and is refused by this ruling.

## Ruling W2 — the offline arm is beta-refused, with a named exit condition

> Economic evidence presented outside live storage yields `INCOMPLETE`, with the reason naming the
> live-storage requirement. This is a **beta profile boundary**, not a permanent property.

Req 6.25 says that, in the beta profile, independently establishing binding Finality *"may require
live authenticated binding evidence from the DLV's committed storage set"*, and names the way out:
*"A future profile may define a portable cryptographic quorum certificate or equivalent witness to
reduce live storage dependencies or to admit market-derived state into an offline/bearer path."*
C4 makes the requirement **categorical for the walk's economic evidence** — the spec's "may" is
permissive about mechanism, not about whether the fact must be established — and refuses rather than
degrades, because a degraded acceptance is an acceptance. The exit condition is exactly the portable
certificate Req 6.25 names; when a profile defines one, W2 is lifted by that profile and not locally.

## The ordered chain

`WALK.0` runs once, at the walk's start. `WALK.1`–`WALK.7` run per position `p`, in this order. A
failure at any step yields that step's frozen class and stops the walk; nothing later runs on an
unvalidated earlier step.

```text
WALK.0   trusted start                    empty activation root, or this verifier's own
                                          completed validated conclusion (Ruling W1)

WALK.1   register winner at (G, DevID, p) self-verifying and non-equivocal. Its root claim is a
                                          LOCATOR and an EQUALITY TARGET, never a validated
                                          value: registration is not validation

WALK.2   admission manifest               fetched by content address, address equality re-derived
                                          from the bytes, never trusted from the fetcher

WALK.3   authority evidence               the authority resolver recovers the proven AK and the
                                          committed network id (2c-C2 ruling A). The claim's
                                          signing key must BE the proven AK; the register set must
                                          be the committed network's canonical set

WALK.4   transition witness + accepted     both by content address: the 0x0031 evidence at the
         substrate                        address the manifest's substrate slot names — same
                                          kind, same address

WALK.5   sigma_dsm                        verified over C_dsm+ under the WALK.3 proven AK

WALK.6   derived root                     recomputed from the pre-root — WALK.7's validated root at
                                          p-1, or WALK.0 at the first position — and the write set,
                                          and REQUIRED TO EQUAL the claim recorded at WALK.1

WALK.7   validated economic root at p     the walk's only output. R_T^+ is DERIVED, never claimed
```

**WALK.6 is where Req 21.17 dies.** The derived root is recomputed and compared against the
registered claim; a forged attacker-chosen post-root is never *read as* a root, so a valid inclusion
path under it proves membership in a tree nobody validated.

## The three enforcement points that link the pair

Amendment 2c §1.3 fixes these and C4 enforces them as written:

```text
1. the manifest's substrate slot names the EXACT evidence address the acceptance used
       same kind, same address
2. the witness and the accepted substrate bind the SAME operation digest
3. the economic operation id is H(G ‖ DevID ‖ C_dsm+)
```

Without (1) a verifier may validate one transition and read another's evidence; without (2) the
economic effects and the DSM succession describe different operations; (3) binds the economic
operation id to the exact authenticated DSM successor at one identity, so the economic transition
cannot describe a different successor than the one `sigma_dsm` authenticated.

---

# §4 — The correspondence, as a theorem

This is the statement C4's charter calls *"the economic accepted-successor/root correspondence"*.

Given a validated economic root at `(G, DevID, p)` from §3 and the accepted `DlvSettle` it validated,
C4 extracts the accepted substrate pair and requires:

```text
CORR.1   accepted (embedded_parent, C_dsm+)  ==  B.market_terms.(trader_parent, trader_successor)
CORR.2   the accepted DlvSettle's external_commitment_x  ==  B.market_terms.route_set_commitment
CORR.3   the accepted DlvSettle's parent_binding         ==  the vault cursor's c_n
CORR.4   the accepted operation's balance effects        ==  the selected route's T_v economics
CORR.5   the cursor's CorrespondenceWitness holds        (VDS.COMMON.10.a, 2c-C3 / 2c-A.1)
```

**CORR.1 is C4's own cross-object check and is not P4.** It compares the pair the *walk validated*
against the coordinates `B` carries. P4 (§2.1) compares a recomputed tip against `B`'s own carried
bytes and is 2c-B's, deferred. The two can hold or fail independently, and C4 relies only on CORR.1.

CORR.1 is the pair equality Def 6.26 demands — *"requires that it commits the exact trader
relationship, `trader_parent`, and `trader_successor` already carried by `B`"* — restated against the
linked pair of §1.1 rather than against a root-bearing commitment.

**None of CORR.1–CORR.5 establishes that this acceptance realizes THIS bundle `b`.** They establish
that the trader accepted the exact transition `B` names, priced as `B`'s route says, consuming the
cursor `B`'s transition names. The step from *"the right transition happened"* to *"…for this exact
`b`"* is §5's, and it is the step C4 cannot take alone.

---

# §5 — `IndependentRealization`

## Ruling R1 — the fact is witness-parameterised, and C4 cannot construct it

> `IndependentRealization` — the placeholder type C3's adopting change shipped with a private field
> and no constructor — is **given its definition here and remains unconstructible when C4 lands**.
> C4 owns and freezes the complete predicate up through the independently validated
> accepted-successor / economic-root chain, and its constructor takes an abstract
> `BundleAcceptanceWitness` that C4 has no means to produce. 2c-D defines the canonical
> bundle-acceptance leaf, binds the accepted economic result to the exact `b`, and instantiates that
> witness. Only then is the fact constructible.
>
> After C4 and before 2c-D: accepted-successor verification may succeed and validated economic
> admission may succeed — and a market fold remains `PartialPendingRealization`. It **MUST NOT** be
> promoted to realized from correspondence alone.

The C-series charter names C4 *"Accepted-successor / `TA_B` verification closure"*. C4 closes the
accepted-successor and realization halves. **`TA_B` verification moves with its field table to
2c-D**, because an amendment cannot specify the verification of an object whose fields another
amendment defines; Req 21.16 goes with it (§9).

```text
IndependentRealization :=
        validated economic root at (G, DevID, p)        §3
    AND CORR.1 .. CORR.5                                §4
    AND BundleAcceptanceWitness(b)                      2c-D — no constructor here
```

The boundary, stated once:

```text
    C3 validity
        -> C4 accepted successor / realization predicate
            -> 2c-D exact-b binding witness
                -> constructible IndependentRealization
                    -> realized market frontier
```

**Do not** amend 2c §9.1 to weaken the leaf requirement, move `0x0032` or the leaf into C4, or
duplicate the leaf here. Option "correspondence alone is the fact" was considered and refused: it
lets *"the right trader transition happened"* stand in for *"…for this exact `b`"*, which is the
binding gap 2c-D exists to close, and it is the door amendment 2c §8 Blocker 1 was written against.

**A considered alternative, recorded.** The witness could instead be a conjunct supplied at each
call site rather than a constructor parameter. The parameterised form was chosen because a parameter
cannot be forgotten at a call site the way a conjunction can, and because the leaf is the final
conjunct of *this* fact rather than an external obligation of a different kind.

## Ruling R2 — the fact is position-bound

> `IndependentRealization` names the economic position `p` whose walk validated it. It is never a
> claim about a trader's current tip. A tip moves; a validated position does not.

---

# §6 — Composition into the frontier

Composition, and every cursor-keyed rule outside the §4 join, lives here. The composition walk
carries `(V, c_n, g)`; §3's economic walk carries `(G, DevID, p)`.

The composition walk folds forward on `may_fold` (2c-A.1 ruling 12); only realized-frontier
advancement waits on `may_certify`.

## Ruling C1 — kind-gating is unchanged, and C4 adds no owner-side analogue

> Market: binding-final (Def 6.24) **and** realization (Def 6.26). Owner close: binding Finality
> alone realizes it (Req 6.30), with no acceptance artifact, no owner-side fence and no
> owner-bound-but-unrealized state. C4 introduces nothing on the close arm.

Req 6.30 states the asymmetry and its reason: *"A market trade has a second sovereign trader chain
whose acceptance the DLV cannot infer from DLV binding alone… Owner release/close has no such remote
leg in the beta profile."*

## Ruling C2 — `Free` has two scopes and they must not be merged

> 2c-C3 ruling J's `Free → INVALID` judges **a candidate**: a successor that names a parent it never
> won exclusivity over is decidably false. The walk's `Free` at the **cursor** is a termination: no
> binding is observable at this frontier now, so no candidate exists and the predicate is never
> evaluated. Wiring ruling J's table into the walk's cursor arm breaks the frontier.

Both readings are correct and neither may be deleted; C4 pins the scope so an implementer cannot
collapse them.

## Ruling C3 — the quarantine is consulted at the cursor, before its first register read

> C4 consumes 2c-C3.1 Ruling B check (i) unchanged: *"AT EVERY CURSOR of the composition walk — the
> baseline included, BEFORE its first register read — refuse if the cursor's `(V, c_n)` is a root, or
> if the cursor's generation is `>= g` for any root of `V`."* The refusal is `SAFETY_VIOLATION` and
> reaches no economic walk: a quarantined cursor never produces a `(G, DevID, p)` to walk.

C4 adds no quarantine rule and weakens none. It records the ordering because the economic walk of §3
is new and must not be mistaken for a place the check belongs.

---

# §7 — What a `Valid` market verdict unlocks

Preconditions only. Every producer named here belongs to 5c-2. Req 6.27's completion gate enumerates
the actions Class K must not take until realization is established; all four appear below.

```text
market output spendability             requires may_certify()      Req 6.27
route displayed as successful          requires may_certify()      Req 6.27
receipt publication                    requires may_certify()      Req 6.27, Req 14.4
folding any DLV successor from B       requires may_certify()      Req 6.27
    (advancing the REALIZED frontier)
accepted-successor finality            requires may_certify()
fence release                          requires may_certify()
```

## Ruling V1 — the market verdict is constructed at the ordered composition walk

> The constructor lives in **core**, and the ordered third-party composition walk calls it. A verdict
> pre-filled by the trader's own admission path is self-attestation, not evidence: a foreign verifier
> must re-derive the facts it relies on. `advance_validated` may return typed intermediate facts and
> **must not** be the authoritative source of a market verdict for third-party composition.

Def 6.26 requires that *"a conforming verifier must be able to verify `A_B` without write authority
over the trader's chain"*, which the walk satisfies and the trader's own admission path does not.
Only the walk holds both halves the fact needs: the vault cursor's `CorrespondenceWitness` and the
trader's validated transition.

## Ruling V2 — the `advance_validated` verdict slot is DELETED

> `SuccessorValidity::DlvTransition` carries `kind` only. The verdict slot is removed, not filled.
>
> Filling it would require threading `V_n` into a function whose own record says it does not hold
> one — a signature change in service of a value no third-party verifier may trust, since V1 makes
> the walk the only authoritative constructor. A slot that carries a verdict invites exactly the
> self-attestation V1 forbids, and an empty slot documented as "C4 fills it" is the no-op the ruling
> was issued to end. The typed intermediate fact V1 permits is the **kind**, which survives.

## Ruling V3 — fence release is gated on the fact, not on a name

> The terminal fence event fires only on a verdict that certifies. Its name must not tempt anyone to
> move release beside the advance outcome. Whether the event is renamed is 5c-2's choice; **the
> typed gate is C4's**, and a mutation control proving that release on a non-certifying verdict goes
> red is mandatory.
>
> Recorded consequence: because a market verdict cannot certify until 2c-D (Ruling R1), **market
> fence release is unreachable until 2c-D**. That is the intended state, not an oversight.

---

# §8 — Formal model

## Ruling F1 — C4 lands the fourteenth Lean module

> C4 ships `lean4/DSMAcceptedSuccessorWalk.lean` and moves the CI module-count pin from 13 to 14 in
> the same change. Self-contained: no imports, no Mathlib, restated types, and the header shape the
> sibling modules use — what the module machine-checks, what it does NOT claim, and the executed
> mutation controls with their results.

Scope:

```text
1. accepted-successor correspondence                                     §4
2. ordered evidence-walk invariants                                      §3
3. construction of the prerequisite facts ValidDlvSuccessorCore consumes §3
4. correspondence between accepted trader successor, validated economic
   root and exact bundle facts, UP TO the 2c-D boundary                  §4, §5
5. IndependentRealization with the bundle-acceptance requirement as an
   ABSTRACT Prop / witness parameter                                     §5 Ruling R1
```

C4 proves: *if all C4 prerequisites hold and the abstract bundle-acceptance witness holds, then
`IndependentRealization` follows.* C4 **must not** prove or instantiate the 2c-D leaf.
`TokenPolicyValid` and `VDS.TERMINAL.2` stay named and undischarged on C3's terms, not assumed away.

Required of the module: per-theorem `#print axioms` reporting, and at least two **executed** mutation
controls recorded in the header — the strongest available result being the kernel proving the
negation of a named theorem, not merely a broken proof.

**No TLA+.** C4's obligations are correspondence and ordered-proof structure, not a new concurrent
register protocol. Adding a spec for symmetry would model nothing.

---

# §9 — Verification obligations

## Class-1 vectors

Expected values produced **without** the production encoder, decoder, canonicalization helper or
digest-construction helper under test (2c-C2 ruling D). Byte arrays, never hex.

```text
positive   a trader lineage with a DlvSettle admitted at position p — validated root,
           manifest, 0x0031 by CCB address, witness — and the bound bundle whose
           MarketTerms coordinates equal the accepted pair

negative   Req 21.17 acceptance-root-auth, BOTH ARMS. (a) an attacker-chosen post-root
           with a VALID inclusion path under it must fail, because WALK.6 derives the
           root; and (b) replacing the forgery with the accepted successor's real
           C_dsm+ and its valid sigma_dsm must make the SAME inclusion evidence
           eligible to pass all remaining checks. Without (b) a verifier that refuses
           every input satisfies the obligation

negative   a REGISTERED BUT UNVALIDATED root claim must fail — registration is not
           validation (WALK.1 is a locator and an equality target only)

negative   CORR.1  accepted (embedded_parent, C_dsm+) != B's (trader_parent, trader_successor)
negative   CORR.2  external_commitment_x != route_set_commitment
negative   CORR.3  the accepted parent_binding != the cursor's c_n
negative   CORR.4  balance effects != the selected route's T_v economics
negative   CORR.5  the cursor's CorrespondenceWitness absent

negative   a walk seeded from the register winner at p-1, or from an operator-supplied
           root, must refuse — neither is a trusted start (Ruling W1)

negative   economic evidence presented outside live storage returns INCOMPLETE with the
           reason naming the live-storage requirement (Ruling W2)

negative   a manifest substrate slot naming a different address, or a different kind,
           must fail (enforcement point 1)

negative   a witness and an accepted substrate binding DIFFERENT operation digests must
           fail (enforcement point 2)

negative   a lineage whose cursor is quarantined yields SAFETY_VIOLATION with NO
           register read (§6 Ruling C3)
negative   a non-certifying verdict at the fence-release seam does not release (Ruling V3)
```

## Lifecycle controls (class 2)

These claim no independent-encoder provenance. Req 21.15 is **partial until 2c-D**; Req 21.16 is
**wholly owed by 2c-D**, because their terminal act requires an acceptance artifact whose field table
and verification are 2c-D's (§5) and a realization Ruling R1 says is unconstructible here.

```text
Req 21.15 half-completion — THE WITHHOLD HALF, owed here: bind, withhold the
    acceptance, and prove reserves and generation unchanged, the trader output
    unspendable, the DLV parent blocked, the owner close blocked, AND that a second
    identity cannot quote or settle from the fictitious post-trade reserve state.
    The remaining half — "supplying the exact valid A_B … must then realize and fold
    the committed successor exactly once" — lands with 2c-D.

Req 21.16 receipt-verifier — OWED BY 2c-D in full: no TA_B can be parsed here.
    When it lands it must establish, from the published receipt set alone: retrieve
    and verify TA_B; prove the commitment carries the exact bundled trader
    parent/successor; verify sigma_dsm directly over it; verify the inclusion proof
    under the DERIVED root (§1.1's correction); match (b, X); and reproduce the DLV
    reserve deltas — with removal or substitution of TA_B, C_dsm+, sigma_dsm or the
    inclusion proof each failing closed.
```

## Mutation controls

Each disabled in turn, with a **named** test going red by performing the forbidden action, then
restored. Classified by the named `FAILED` line, never by the presence of "error" in the output.

```text
M1  skip the realization fact           -> the half-completion withhold control red
M2  trust WALK.1's registered claim
    instead of the derived root         -> the registered-but-unvalidated negative red
M3  skip CORR.1's pair equality         -> the CORR.1 negative red
M4  skip CORR.2 / CORR.3 / CORR.4 /
    CORR.5 in turn                      -> the matching CORR negative red
M5  skip the cursor quarantine consult  -> the quarantined-cursor negative red
M6  release the fence on a
    non-certifying verdict              -> the fence-release negative red
M7  read a carried root instead of
    deriving it at WALK.6               -> Req 21.17 arm (a) red
M8  accept an operator-supplied or
    register-winner start               -> the trusted-start negative red
M9  skip the same-kind/same-address
    substrate check                     -> the substrate-slot negative red
M10 skip the shared operation digest    -> the operation-digest negative red
```

## Integration controls and the dependent sweep

```text
- SuccessorValidity::DlvTransition loses its verdict slot (Ruling V2). The dependents are
  the field's readers, not advance_validated's callers: `SuccessorValidity::may_certify`
  is its ONLY reader and is deleted with it — §7's gates read `C3Verdict::may_certify` on
  the walk's verdict; the two construction sites in lineage.rs and their "C4 fills it"
  comment, and the enum's doc comment, are updated; and the two named tests that pin the
  slot are deleted. All four advance_validated call sites — two in src/ and two in
  dsm/tests/economic_admission_lifecycle.rs — destructure the result and discard the
  validity, so the tuple shape is unchanged and they need no edit; the sweep confirms
  that rather than assuming it
- realize_market_successor_5c1 and MarketRealization are NOT deleted here — see the
  correction below. Every dependent of both symbols is grepped and listed when 5c-2
  removes them
- absence claims re-verified against origin/main with `git show`, never a working tree
- lean -DwarningAsError=true lean4/DSMAcceptedSuccessorWalk.lean, the ci.yml lean job's
  expected= raised 13 -> 14 in the same commit, and the per-theorem #print axioms output
  recorded in the amendment's adopting-change record
- targeted tests per edited module, then the board, at the repo root (ci.yml's rust job
  sets no working-directory):
      cargo test --locked --workspace --exclude dsm_storage_node --release \
          -- --nocapture --test-threads=1
      cargo test --locked -p dsm_storage_node --release --no-default-features \
          --features local-dev,strict -- --nocapture
  both lines, as ci.yml runs them, redirected to a file and grepped, never tailed;
  plus `make lint` AND `ci/production_safety_checks.sh` at the repo root on the
  pinned toolchain
```

---

# §10 — Transcription obligations

Applied in the adopting change or filed as named issues; not left to drift.

```text
RETARGET BY KIND, not by section. A bare "verification closure is 2c-C's" -> C4;
a "ValidDlvSuccessor is 2c-C's" -> 2c-C3, which froze it.

registry §4, and §5.20's FIRST clause  "Verification closure … remain[s] 2c-C's" -> C4
registry §5.20's SECOND clause,        the ValidDlvSuccessor gating -> 2c-C3
  §5.21, §5.23, §6's gate
registry §5.19                         carries no attribution to retarget
registry §3 row for 0x0011             "blocked — 2c-B/2c-C/2c-D" -> 2c-D (2c-B disclaims it)
registry §6 0x0011 paragraph           the referenced-vs-restated question is answered by
                                       0x0031; and "Owned by 2c-B/2c-C/2c-D" -> 2c-D, as in §3
2c-B :551                             the namespace re-audit's "0x0031 is free" — falsified by
                                      merged #799; transcription pending in open #800
C3 doc "thirteen modules"             -> fourteen, with the CI pin, in the same commit
C3 doc closure, "needs the C4          -> "needs the C4 predicate, whose last conjunct is
  realization fact only"                  2c-D's"
5c-2 plan                             the sentences the encoder cut falsified, listed in its own
                                      status block rather than silently rewritten
```

---

# Scope

**Documentation only. No Rust, no Lean, no proto in this document.** The adopting change carries the
fourteenth Lean module (Ruling F1), the Rust deletions Ruling V2 requires, and §9's controls.

---

# Verification of this document

1. **Every Rev 15 reference was read at source**, not carried from a summary. Quoted: Def 6.26,
   Req 6.25, Req 6.30, Req 21.15, Req 21.16, Req 21.17. Cited without quotation: Def 6.24, Req 6.27,
   Req 14.4. The spec file hard-wraps symbols across lines, so comparisons were made on normalized
   text.
2. **Both Rev 15 contradictions were confirmed on both sides** before §1 restated either: Def 6.26's
   root-bearing `C_T^+` against 2c-B's correction, and Def 6.26's four-coordinate leaf against
   amendment 2c §1.4 and §9.1.
3. **Req 6.25 was quoted rather than paraphrased** after a first draft overstated it as a
   live-storage-only rule; the requirement says *"may require"* and names the portable quorum
   certificate that lifts it, which became Ruling W2's exit condition.
4. **The quarantine's operand was checked against 2c-C3.1 Ruling B**, which moved the consult out of
   §3's economic chain — where it had no cursor to name — into §6, where the cursor lives.
5. **"P0–P6" was removed** after 2c-C2 ruling A was read: C2 explicitly does not freeze that
   numbering, and using it normatively would have reintroduced code-local terminology into a frozen
   walk.
6. **The draft was adversarially verified** by six independent read-only checkers over quotations,
   ruling fidelity, internal consistency, code and Lean facts, and the executability of §9, with
   their findings adjudicated and applied. The research tree was proven unmodified: `git status
   --porcelain` clean and `git diff --exit-code` before and after every fan-out.
7. **Self-contradiction sweep** for `never / only / every / always`, and specifically that no
   sentence claims the Lean module exists, that no sentence claims the realization fact is
   constructible, and that no obligation in §9 requires an artifact §5 says cannot be built.

---

# Closure status

```text
Encoding closure                    N/A — C4 allocates nothing and changes no encoding
The ordered economic walk           FROZEN here
Accepted-successor correspondence   FROZEN here; proof obligation on the fourteenth Lean
                                    module (Ruling F1), which does not exist until the
                                    adopting change
IndependentRealization              DEFINED here, NOT CONSTRUCTIBLE until 2c-D (Ruling R1)
Market C3 completion                needs the 2c-D witness. G1-G4 (§2.1) gate the bundle's
                                    structural validity, not this walk, and land with
                                    5c-2 Step 2/3
Owner-close C3 completion           COMPLETE since the 2c-A.1 adopting change
Market fence release                UNREACHABLE until 2c-D, by construction (Ruling V3)
Live market producer                FAIL-CLOSED until 5c-2 Step 2/3
Req 21.15                           withhold half owed here; realize half owed by 2c-D
Req 21.16                           owed by 2c-D in full, with TA_B verification (§5)
TokenPolicyValid, VDS.TERMINAL.2    EXTERNAL, unchanged
Formal coverage                     the fourteenth module, with the 2c-D leaf abstract
```

**Frozen is not implemented.** This document specifies; the adopting change implements, and its
record belongs at the end of this file the way 2c-A.1's does.

---

# Adopting-change record (2026-09-09)

Four PRs on top of the specification (#801), each based on main and independent of the others.

1. **The fourteenth Lean module** (#802). `lean4/DSMAcceptedSuccessorWalk.lean`, with the CI
   module-count pin moved 13 → 14 in the same commit and 2c-C3's closure paragraph updated with it.
   It machine-checks START, DERIVED, LINK, ORDER, CORRESPOND, REALIZE and WITHHOLD, with the 2c-D
   leaf as an abstract `Prop` parameter so every realization theorem is an implication the module
   cannot discharge. No theorem depends on `sorryAx`; the samples use kernel `decide` rather than
   `native_decide`, so none depends on `Lean.ofReduceBool` or `Lean.trustCompiler`. Two mutation
   controls executed, each producing the kernel proving a named theorem FALSE.
2. **Ruling V2** (#803). `SuccessorValidity::DlvTransition` carries `kind` only;
   `SuccessorValidity::may_certify`, its only reader, is deleted with it. All four
   `advance_validated` call sites already discard the validity, so the tuple shape is unchanged.
3. **The registry transcriptions** (#804), retargeted BY KIND: a bare "verification closure is
   2c-C's" → C4; a "`ValidDlvSuccessor` is 2c-C's" → 2c-C3, which froze it. A blanket retarget would
   have moved the second group to the wrong amendment.
4. **The correspondence and the realization type** (this change). `check_market_correspondence`
   implements `CORR.1`–`CORR.5` sans-IO and returns a `MarketCorrespondence` whose only constructor
   it is. `IndependentRealization::from_parts` takes that plus a `BundleAcceptanceWitness` — a type
   with a private field and **no constructor**, which 2c-D owns. The impossibility moved one level
   down rather than away, exactly as Ruling R1 requires. No `Reason` code was added: every
   correspondence failure maps onto the frozen inventory, so the Lean model needed no extension.

**Mutation controls, all executed and red on a named test:** one per correspondence conjunct
(`CORR.1`–`CORR.5`), each removed in turn from `check_market_correspondence`.

**Deliberately not wired into the composition walk.** The market arm would call
`check_market_correspondence` and then have nothing to do with the result: the fact it feeds cannot
be constructed until 2c-D, so the call would compute a value that can never reach `Valid`. The types
are foreign-verifiable and tested on their own; wiring them is 5c-2/2c-D's, with the producer that
makes the fact reachable.

---

# Corrected 2026-09-09, while implementing this document

Two defects in §9, both found by writing the adopting change rather than by reading. They are
recorded rather than silently rewritten, because this document was merged before they surfaced.

## The 5c-1 scaffolding deletion is 5c-2's, not C4's

§9's integration block required `realize_market_successor_5c1` and `MarketRealization` to be deleted
by C4's adopting change. **That obligation was wrong and is withdrawn.**

The symbols' own banners have assigned their removal to 5c-2 since 5c-1 landed — *"TEMPORARY
SCAFFOLDING (5c-1). DELETED IN 5c-2"*, twice — and C4 has nothing to put in their place. The
`Absent` arm is what makes a bound-but-unrealized market parent hold its reserves and generation at
the composed parent, which is exactly Req 21.15's expected state. Delete it and a market bundle
either folds without realization, violating Req 21.15, or never folds at all, taking the market path
dark for two amendments. Neither is what C4 decided; C4 gates **certification**, and the arm that
gates the **cursor** is 5c-2's to replace when `TA_B` becomes producible.

## `may_fold` for a market successor does not advance the reserve cursor

§6 says the composition walk folds forward on `may_fold`, and §7 gates realized-frontier advancement
on `may_certify`. Read together those are consistent, but §6's sentence alone invites the reading
that a market fold advances reserves, which Req 21.15 forbids while the acceptance is withheld.
Stated explicitly: **for a market successor, `may_fold` permits the walk to compute forward; the
reserve cursor and the generation stay at the composed parent until realization is established.**
The frontier a withheld market bundle produces is bound-but-unrealized, not advanced.
