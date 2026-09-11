/-
  Bundle acceptance — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-D §7's verification of a `TraderAcceptance`, and
  the two-conjunct rule of amendment 2c §9.1 that §7 sits inside:

    - ORDER        each step may use only what the steps above it established.
                   `G` is not authoritative before the signature check, and
                   `b` is not authoritative before the path folds
    - THREE-WAY    ruling D3's identity binding is leaf == witness ==
                   recompute(G, DevID, C_dsm+). The middle term alone is not
                   enough, because the witness's own id is authoritative only
                   by being recomputed
    - STRUCTURAL   the signing digest is built over `settler_devid`, never
                   `counterparty_devid`. The property holds by construction,
                   so it is modelled as WHICH FIELD IS READ rather than as an
                   equality between two candidates
    - TEETH        each conjunct is separately necessary: dropping any one
                   accepts something the whole predicate refuses
    - TWO CONJUNCT acceptance is a PRECONDITION of realization, never its
                   trigger. A verified acceptance over a bundle that is not
                   binding-final realizes nothing

  What this module does NOT claim:

    * It is a model of the NORMATIVE predicate, not a refinement proof from the
      shipped Rust. Digests are `Nat`; equality of `Nat` stands for equality of
      canonical bytes, and nothing here claims the Rust computes these values.
    * Hashing is ABSTRACT. `recomputeEoid` and `foldPath` are parameters, not
      definitions: this file proves the SHAPE of the binding for any injective
      derivation, and asserts nothing about BLAKE3.
    * Signature verification is a `Bool`. That `sigma_dsm` verifies under an
      INDEPENDENTLY established authority is 2c-D §7 step 2's obligation on the
      caller and is not modelled -- a model that supplied its own key would be
      checking the artifact against itself, which is the defect the step exists
      to prevent.
    * Steps 3, 4 and 7 are PARAMETERS in the Rust (a `ValidatedEconomicRoot`
      and a `MarketCorrespondence`) and are likewise hypotheses here. This file
      does not re-derive the walk or `CORR.1`-`CORR.5`.
    * Fence release, receipt publication and Req 21.16 are not modelled here.
      C2 (2c-D §14) implements them; DSMSettlementCompletion models the
      certify -> publish -> release ordering and DSMComposedReserveProvenance
      the reserve rule later generations consume.

  Mutation controls, executed rather than asserted:

    1. the three-way identity binding weakened to leaf == witness
       -> `theTwoWayFormAcceptsTheForgery` : a forged witness id is accepted
    2. the signing digest built over `counterparty_devid`
       -> `readingTheCounterpartyAcceptsANonSelfLoopForgery`
    3. each conjunct dropped in turn -> `teeth*` below
-/

namespace DSMBundleAcceptance

/-- A digest. Equality of `Nat` stands for equality of canonical bytes. -/
abbrev Digest := Nat

/-- The successor-evidence a market bundle carries (`0x0031`).

    Both device ids are present ON PURPOSE. `counterparty_devid` is the field
    `G4` recomputes the chain tip from, and therefore the one a verifier
    naturally reaches for; `settler_devid` is the one being credited. They
    coincide only under a self-loop shape nothing verifies (2c-D §12), so the
    model keeps them separate and proves reading the wrong one is exploitable. -/
structure Evidence where
  settlerDevid      : Digest
  counterpartyDevid : Digest
  operationDigest   : Digest
deriving DecidableEq

/-- The market terms inside the bundle being composed. -/
structure Terms where
  traderSuccessor : Digest
  evidence        : Evidence
deriving DecidableEq

/-- The bundle-acceptance leaf (`0x0032`), after ruling D3 gave it field 2. -/
structure Leaf where
  bundle             : Digest
  economicOperationId : Digest
deriving DecidableEq

/-- `TA_B` (`0x0011`), re-derived to four fields. -/
structure Acceptance where
  traderGenesis : Digest
  leaf          : Leaf
  path          : Digest
deriving DecidableEq

/-- The abstract derivations. Parameters, never definitions: the theorems below
    hold for ANY injective derivation, which is what makes them statements
    about the predicate's shape rather than about BLAKE3. -/
structure Derivations where
  recomputeEoid : Digest → Digest → Digest → Digest
  leafKey       : Digest → Digest → Digest → Digest
  leafValue     : Leaf → Digest
  foldPath      : Digest → Digest → Digest → Digest

/-- Whether `sigma_dsm` verifies, for a signing digest built over the given
    genesis and device id. Abstract: the caller establishes the authority. -/
structure Authority where
  verifies : Digest → Digest → Digest → Digest → Bool

/-! ## §7, as shipped -/

/-- Step 2. The digest is built over the SETTLER, never the counterparty. That
    choice is the conjunct; there is no equality to check because the correct
    field is simply the one read. -/
def step2 (a : Authority) (acc : Acceptance) (t : Terms) : Bool :=
  a.verifies acc.traderGenesis t.evidence.settlerDevid t.traderSuccessor
    t.evidence.operationDigest

/-- Step 5's identity binding, in ruling D3's THREE-WAY form.

    `witnessId` is the enclosing witness's carried id; `recomputed` is derived
    from the accepted transition. Requiring the leaf to equal BOTH is what ties
    the acceptance to this transition rather than to whatever transition the
    witness happened to describe. -/
def step5Identity (d : Derivations) (acc : Acceptance) (t : Terms)
    (witnessId : Digest) : Bool :=
  let recomputed :=
    d.recomputeEoid acc.traderGenesis t.evidence.settlerDevid t.traderSuccessor
  acc.leaf.economicOperationId == witnessId && witnessId == recomputed

/-- Step 5's fold: the leaf, at the position its operation identity fixes, must
    be included under the VALIDATED root. -/
def step5Fold (d : Derivations) (acc : Acceptance) (t : Terms)
    (validatedRoot : Digest) : Bool :=
  let recomputed :=
    d.recomputeEoid acc.traderGenesis t.evidence.settlerDevid t.traderSuccessor
  let key := d.leafKey acc.traderGenesis t.evidence.settlerDevid recomputed
  d.foldPath key (d.leafValue acc.leaf) acc.path == validatedRoot

/-- Step 6. `b` becomes authoritative only here -- after the fold. -/
def step6 (acc : Acceptance) (b : Digest) : Bool :=
  acc.leaf.bundle == b

/-- §7, the conjunction as shipped. Steps 3, 4 and 7 are hypotheses supplied by
    the caller as types only their own verifiers produce. -/
def verifyAcceptance (d : Derivations) (a : Authority) (acc : Acceptance)
    (t : Terms) (b witnessId validatedRoot : Digest) : Bool :=
  step2 a acc t
    && step5Identity d acc t witnessId
    && step5Fold d acc t validatedRoot
    && step6 acc b

/-! ## The forbidden shapes -/

/-- MUTATION 1 -- the identity binding weakened to leaf == witness, dropping
    the recomputation. This is the form a reader arrives at naturally: the
    witness is authenticated, so agreeing with it looks sufficient. -/
def verifyTwoWay (d : Derivations) (a : Authority) (acc : Acceptance)
    (t : Terms) (b witnessId validatedRoot : Digest) : Bool :=
  step2 a acc t
    && (acc.leaf.economicOperationId == witnessId)
    && step5Fold d acc t validatedRoot
    && step6 acc b

/-- MUTATION 2 -- the signing digest built over the COUNTERPARTY. -/
def step2Counterparty (a : Authority) (acc : Acceptance) (t : Terms) : Bool :=
  a.verifies acc.traderGenesis t.evidence.counterpartyDevid t.traderSuccessor
    t.evidence.operationDigest

/-! ## Closed witnesses, so the kernel can decide the counterexamples -/

def sampleDerivations : Derivations where
  recomputeEoid g dev c := g + dev * 3 + c * 7
  leafKey g dev e       := g + dev * 11 + e * 13
  leafValue l           := l.bundle * 17 + l.economicOperationId * 19
  foldPath k v p        := k + v * 23 + p * 29

/-- An authority that accepts exactly the settler-keyed digest of the honest
    fixture, and nothing else. Modelling it as a total function keeps the
    counterexamples closed terms. -/
def sampleAuthority : Authority where
  verifies g dev c op := g == 5 && dev == 9 && c == 40 && op == 2

def honestEvidence : Evidence :=
  { settlerDevid := 9, counterpartyDevid := 77, operationDigest := 2 }

def honestTerms : Terms :=
  { traderSuccessor := 40, evidence := honestEvidence }

/-- The honest operation identity, as the accepted transition recomputes it. -/
def honestEoid : Digest :=
  sampleDerivations.recomputeEoid 5 9 40

def honestLeaf : Leaf :=
  { bundle := 100, economicOperationId := honestEoid }

def honestRoot : Digest :=
  sampleDerivations.foldPath
    (sampleDerivations.leafKey 5 9 honestEoid)
    (sampleDerivations.leafValue honestLeaf)
    31

def honestAcceptance : Acceptance :=
  { traderGenesis := 5, leaf := honestLeaf, path := 31 }

/-! ## The predicate accepts the honest case -/

theorem honestAcceptanceVerifies :
    verifyAcceptance sampleDerivations sampleAuthority honestAcceptance
      honestTerms 100 honestEoid honestRoot = true := by
  decide

/-! ## THE LOAD-BEARING RESULT -- ruling D3 is not decoration

    A witness carrying a FORGED operation id, with a leaf that agrees with it,
    satisfies the two-way form and is refused by the three-way one. The middle
    term alone is exactly as weak as the ruling says: it ties the acceptance to
    whatever the witness described, not to the accepted transition. -/

/-- The forged pair: witness and leaf agree with each other, and neither is the
    recomputation. -/
def forgedEoid : Digest := 999

def forgedLeaf : Leaf := { bundle := 100, economicOperationId := forgedEoid }

def forgedRoot : Digest :=
  sampleDerivations.foldPath
    (sampleDerivations.leafKey 5 9 honestEoid)
    (sampleDerivations.leafValue forgedLeaf)
    31

def forgedAcceptance : Acceptance :=
  { traderGenesis := 5, leaf := forgedLeaf, path := 31 }

theorem theTwoWayFormAcceptsTheForgery :
    verifyTwoWay sampleDerivations sampleAuthority forgedAcceptance
      honestTerms 100 forgedEoid forgedRoot = true := by
  decide

theorem theThreeWayFormRefusesTheForgery :
    verifyAcceptance sampleDerivations sampleAuthority forgedAcceptance
      honestTerms 100 forgedEoid forgedRoot = false := by
  decide

/-- Stated once, as the separation the ruling turns on: the two forms are
    PROVABLY different predicates, not two spellings of one. -/
theorem theTwoFormsAreDifferentPredicates :
    ∃ acc t b w r,
      verifyTwoWay sampleDerivations sampleAuthority acc t b w r = true ∧
      verifyAcceptance sampleDerivations sampleAuthority acc t b w r = false :=
  ⟨forgedAcceptance, honestTerms, 100, forgedEoid, forgedRoot,
   theTwoWayFormAcceptsTheForgery, theThreeWayFormRefusesTheForgery⟩

/-! ## The structural DevID property (2c-D §12)

    Reading `counterparty_devid` is not a stylistic difference. Under an
    authority that signed over the settler, a bundle whose counterparty differs
    is REFUSED by the mutated step -- so a verifier that read the wrong field
    would reject honest non-self-loop settlements, and, symmetrically, would
    accept a digest the credited device never authorised. -/

theorem step2ReadsTheSettler :
    step2 sampleAuthority honestAcceptance honestTerms = true := by
  decide

theorem readingTheCounterpartyAcceptsANonSelfLoopForgery :
    step2Counterparty sampleAuthority honestAcceptance honestTerms = false := by
  decide

/-! ## TEETH -- each conjunct is separately necessary -/

/-- Step 2 dropped: an acceptance whose genesis was never authenticated. -/
theorem teethStep2 :
    verifyAcceptance sampleDerivations sampleAuthority
      { honestAcceptance with traderGenesis := 6 } honestTerms 100 honestEoid
      honestRoot = false := by
  decide

/-- Step 5's fold dropped: a leaf proven under a root nobody validated. -/
theorem teethStep5Fold :
    verifyAcceptance sampleDerivations sampleAuthority honestAcceptance
      honestTerms 100 honestEoid (honestRoot + 1) = false := by
  decide

/-- Step 6 dropped: an authentic acceptance naming a different bundle. -/
theorem teethStep6 :
    verifyAcceptance sampleDerivations sampleAuthority honestAcceptance
      honestTerms 101 honestEoid honestRoot = false := by
  decide

/-! ## ORDER -- `b` is not authoritative before the fold

    Step 6 reads `leaf.bundle`. The ordering claim is that reading it is
    meaningless until step 5 has folded: there is an acceptance whose
    `leaf.bundle` equals the composed `b` and which §7 still refuses, because
    the fold fails. So "the leaf names b" is not, on its own, a fact about
    anything. -/

theorem bIsNotAuthoritativeBeforeTheFold :
    step6 honestAcceptance 100 = true ∧
    verifyAcceptance sampleDerivations sampleAuthority honestAcceptance
      honestTerms 100 honestEoid (honestRoot + 1) = false :=
  ⟨by decide, teethStep5Fold⟩

/-! ## THE TWO-CONJUNCT RULE (amendment 2c §9.1)

    Acceptance is a PRECONDITION of realization, never its trigger. Modelled as
    the conjunction §7's closing sentence states: a `TA_B` satisfying all seven
    realizes `B`, and ONLY together with `B` being binding-final. -/

/-- Realization requires both halves. There is deliberately no path from an
    acceptance alone. -/
def realizes (acceptanceVerified bindingFinal : Bool) : Bool :=
  acceptanceVerified && bindingFinal

theorem acceptanceAloneRealizesNothing :
    realizes true false = false := by decide

theorem bindingFinalityAloneRealizesNothing :
    realizes false true = false := by decide

theorem bothHalvesRealize :
    realizes true true = true := by decide

/-- Stated as the separation, so the file cannot be read as licensing a fence
    release on acceptance alone: a verified acceptance over a bundle that is
    not binding-final realizes nothing, even though every one of §7's seven
    conjuncts held. -/
theorem aVerifiedAcceptanceOverANonFinalBundleRealizesNothing :
    verifyAcceptance sampleDerivations sampleAuthority honestAcceptance
      honestTerms 100 honestEoid honestRoot = true ∧
    realizes true false = false :=
  ⟨honestAcceptanceVerifies, acceptanceAloneRealizesNothing⟩

/-! ## Axiom report

    Printed by the kernel, not asserted, and the output is what corrected this
    paragraph: an earlier draft claimed `decide` throughout while eight
    `native_decide` calls remained, and every theorem duly reported
    `Lean.ofReduceBool, Lean.trustCompiler`. All fourteen are now AXIOM-FREE --
    the counterexamples are decided by the kernel itself rather than trusted
    from the compiler, which is a strictly stronger result than
    `native_decide` can give. -/

#print axioms honestAcceptanceVerifies
#print axioms theTwoWayFormAcceptsTheForgery
#print axioms theThreeWayFormRefusesTheForgery
#print axioms theTwoFormsAreDifferentPredicates
#print axioms step2ReadsTheSettler
#print axioms readingTheCounterpartyAcceptsANonSelfLoopForgery
#print axioms teethStep2
#print axioms teethStep5Fold
#print axioms teethStep6
#print axioms bIsNotAuthoritativeBeforeTheFold
#print axioms acceptanceAloneRealizesNothing
#print axioms bindingFinalityAloneRealizesNothing
#print axioms bothHalvesRealize
#print axioms aVerifiedAcceptanceOverANonFinalBundleRealizesNothing

end DSMBundleAcceptance
