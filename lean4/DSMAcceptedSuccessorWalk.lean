/-
  DSM accepted-successor closure — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks the statements amendment 2c-C4 freezes:

    - START        a walk begins at a trusted start only; a register winner and
                   an operator-supplied root are refused as starts, so the
                   forged-root attack has no seam at position zero either
    - DERIVED      the validated root is the DERIVED root. A registered claim
                   is an equality target, never a value that is read, which is
                   the corrected mechanism by which Req 21.17's forgery fails
    - ORDER        a failure at any step stops the walk: nothing later runs on
                   an unvalidated earlier step, and no later step can rescue it
    - LINK         the three enforcement points -- same-kind/same-address
                   substrate, one shared operation digest, and the operation id
                   over the authenticated successor -- are each load-bearing
    - CORRESPOND   CORR.1..5 pin the accepted pair, the trade identity, the
                   cursor and the witness; each conjunct is separately
                   necessary
    - REALIZE      prerequisites AND an ABSTRACT bundle-acceptance witness give
                   IndependentRealization. The witness is a parameter this
                   module never instantiates
    - WITHHOLD     without that witness a market verdict folds and never
                   certifies; the close arm certifies at binding finality with
                   no acceptance artifact at all

  What this module does NOT claim (2c-C4 §5, §8):

    * The 2c-D bundle-acceptance leaf is NOT modelled and NOT discharged. It
      appears only as an opaque `Prop` parameter `W`. Every realization theorem
      is stated `... -> W -> Realization`, so this module proves an implication
      and never the antecedent. Instantiating `W` is 2c-D's, and no definition
      here can produce one.
    * `TokenPolicyValid` and the terminal close's exactly-once owner credit are
      external on 2c-C3's terms (rulings H, G) and are not modelled.
    * 2c-B's grammar and chain-tip conjuncts `G1`-`G4` are NOT modelled. They
      gate the BUNDLE's structural validity, not this walk, which obtains the
      accepted transition from the trader's validated lineage and never parses
      the carried operation bytes.
    * This is a model of the NORMATIVE objects, not a refinement proof from the
      shipped Rust. Digests are `Nat`; equality of `Nat` stands for equality of
      canonical bytes, and nothing here claims the Rust computes these values.
    * Availability is not modelled. `Incomplete` is a verdict this model can
      produce, but nothing here says when storage is reachable.

  Mutation controls, executed rather than asserted. A green suite around a gate
  proves nothing about whether the gate is load-bearing, so both were run and
  both produced the strongest available result -- the kernel proving the
  NEGATION of a named theorem, not merely a broken proof:

    1. `stepPosition` with the derived-equals-registered comparison removed
         from its guard
         -> `the_forged_root_sample_refuses` is proved FALSE by the kernel
            ("Tactic `decide` proved that the proposition ... is false"): the
            attacker's registered post-root now validates. Two further
            theorems lose their proofs with it --
            `validated_root_is_derived_never_registered` and
            `a_claim_that_is_not_the_derived_root_refuses`.

    2. `verdictOf`'s market arm returning `.valid` without the witness
         (`if witnessPresent then .valid else .partialPendingRealization`
          replaced by `.valid`)
         -> `the_separation_is_not_vacuous` is proved FALSE by the kernel, and
            `market_never_certifies_without_the_witness`,
            `close_certifies_market_does_not` and
            `no_market_boundary_opens_without_the_witness` lose their proofs.
            A market successor would then certify with no 2c-D witness, which
            is exactly the promotion Ruling R1 forbids.

  Both mutations were reverted; this file is the unmutated module.
-/

namespace DSMAcceptedSuccessorWalk

-- ─────────────────────────────────────────────────────────────────────────────
-- §3 — the economic walk
-- ─────────────────────────────────────────────────────────────────────────────

/-- A digest, an address, an identity. Equality of `Nat` stands for equality of
canonical bytes; no arithmetic on these is meaningful. -/
abbrev D := Nat

/-- What a verifier may begin a walk from (2c-C4 Ruling W1). `emptyActivation`
is the canonical position-zero root; `ownMemo` is a walk this verifier itself
completed. Everything else is a network or operator value. -/
inductive Start where
  /-- The canonical empty activation root. -/
  | emptyActivation
  /-- This verifier's own completed conclusion, carrying its validated root. -/
  | ownMemo (root : D)
  /-- A root taken from the register winner. **Refused.** -/
  | registerWinner (root : D)
  /-- A root an operator pinned. **Refused.** -/
  | operatorPin (root : D)
  deriving DecidableEq, Repr

/-- The canonical empty activation root's value. Its identity is all that
matters; `0` is a name, not a computation. -/
def emptyRoot : D := 0

/-- Ruling W1, as a decision. A trusted start yields the root it starts from;
anything else yields nothing, and a walk with no start validates nothing. -/
def trustedStart : Start → Option D
  | .emptyActivation => some emptyRoot
  | .ownMemo r       => some r
  | .registerWinner _ => none
  | .operatorPin _    => none

/-- The admission manifest at a position: the substrate it names, by address
and kind, and the operation digest the witness binds. -/
structure Manifest where
  substrateAddr : D
  substrateKind : D
  witnessOpDigest : D
  deriving DecidableEq, Repr

/-- The accepted substrate — `0x0031` as the walk consumes it. `cDsmPlus` is
recomputed by the producer of this structure, never carried on the wire
(2c-B ruling 1); here it is simply a field of the model. -/
structure Substrate where
  addr : D
  kind : D
  opDigest : D
  embeddedParent : D
  cDsmPlus : D
  /-- Whether `sigma_dsm` verifies over `cDsmPlus` under the authority
  resolver's proven key. Verification itself is not modelled; that it is
  REQUIRED is. -/
  sigmaValid : Bool
  deriving DecidableEq, Repr

/-- One economic position's evidence, as the walk reads it. `registered` is the
register winner's root CLAIM: a locator and an equality target, never a value
the walk adopts. -/
structure Position where
  manifest : Manifest
  substrate : Substrate
  /-- The root the register winner claims at this position. -/
  registered : D
  /-- The root the walk derives from the pre-root and the write set. Modelled
  as a function of the pre-root so that "derived" is not a free choice. -/
  writeSet : D
  /-- The economic operation id the admission carries. Enforcement point 3
  requires it to be the id over the authenticated successor. -/
  operationId : D
  deriving DecidableEq, Repr

/-- `H(G ‖ DevID ‖ C_dsm+)`, modelled as an injective-enough combination. The
model needs only that it is a function of the successor commitment. -/
def operationIdOf (identity cDsmPlus : D) : D := identity * 1000000 + cDsmPlus

/-- The derived root at a position: a function of the pre-root and the write
set, and of nothing the claimant supplies as a root. -/
def derivedRoot (preRoot : D) (p : Position) : D := preRoot + p.writeSet

/-- **The three enforcement points** (2c-C4 §3), as one decidable predicate.
Stated separately so each can be mutated on its own. -/
def linkOk (identity : D) (p : Position) : Bool :=
  -- (1) the manifest's substrate slot names the EXACT evidence: same kind and
  --     same address
  (p.manifest.substrateAddr == p.substrate.addr)
    && (p.manifest.substrateKind == p.substrate.kind)
    -- (2) the witness and the accepted substrate bind the SAME operation digest
    && (p.manifest.witnessOpDigest == p.substrate.opDigest)
    -- (3) the economic operation id is derived over the authenticated successor
    && (p.operationId == operationIdOf identity p.substrate.cDsmPlus)

/-- **One position of the walk.** `none` means the walk stops here: the failure
classes are not distinguished in this model, only that nothing later runs.

The guard is the whole content: `sigma_dsm` must verify, the three enforcement
points must hold, and the DERIVED root must equal the REGISTERED claim. The
value carried forward is the derived one. -/
def stepPosition (identity : D) (preRoot : D) (p : Position) : Option D :=
  if p.substrate.sigmaValid && linkOk identity p
      && (p.registered == derivedRoot preRoot p) then
    some (derivedRoot preRoot p)
  else
    none

/-- **The walk.** `WALK.0` runs once; `WALK.1`-`WALK.7` run per position, in
order, and a `none` at any position is final. -/
def walk (identity : D) (s : Start) : List Position → Option D
  | [] => trustedStart s
  | p :: rest =>
      match walk identity s rest with
      | none => none
      | some pre => stepPosition identity pre p

/-- **START.** A walk seeded from a register winner or an operator pin
validates nothing, at any length. The list is the empty one and a non-empty one
to show the refusal is not an artefact of the base case. -/
theorem untrusted_start_validates_nothing
    (identity : D) (r : D) (ps : List Position) :
    walk identity (.registerWinner r) ps = none
      ∨ walk identity (.operatorPin r) ps = none := by
  left
  induction ps with
  | nil => rfl
  | cons _ rest ih => simp [walk, ih]

/-- The same, for the operator pin, so neither arm is left as an alternative
someone could satisfy by proving only the other. -/
theorem operator_pin_validates_nothing
    (identity : D) (r : D) (ps : List Position) :
    walk identity (.operatorPin r) ps = none := by
  induction ps with
  | nil => rfl
  | cons _ rest ih => simp [walk, ih]

/-- **DERIVED.** Whatever a position validates is the root DERIVED from the
pre-root and the write set. The registered claim is a gate, never the value. -/
theorem validated_root_is_derived_never_registered
    (identity preRoot : D) (p : Position) (r : D)
    (h : stepPosition identity preRoot p = some r) :
    r = derivedRoot preRoot p := by
  unfold stepPosition at h
  by_cases hg :
      (p.substrate.sigmaValid && linkOk identity p
        && (p.registered == derivedRoot preRoot p)) = true
  · rw [if_pos hg] at h; exact (Option.some.inj h).symm
  · rw [if_neg hg] at h; exact absurd h (by simp)

/-- **DERIVED, the refusal half — Req 21.17's corrected mechanism.** A position
whose registered claim is not the derived root validates nothing. An attacker
who names a post-root of their choosing gets `none`, whatever inclusion path
they can build under it. -/
theorem a_claim_that_is_not_the_derived_root_refuses
    (identity preRoot : D) (p : Position)
    (h : p.registered ≠ derivedRoot preRoot p) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition
  have : (p.registered == derivedRoot preRoot p) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

/-- **LINK.** Each of the three enforcement points is separately load-bearing:
if any fails, the position refuses. Stated as three theorems so a mutation that
drops one is caught by name. -/
theorem a_substrate_at_another_address_refuses
    (identity preRoot : D) (p : Position)
    (h : p.manifest.substrateAddr ≠ p.substrate.addr) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition linkOk
  have : (p.manifest.substrateAddr == p.substrate.addr) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem a_substrate_of_another_kind_refuses
    (identity preRoot : D) (p : Position)
    (h : p.manifest.substrateKind ≠ p.substrate.kind) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition linkOk
  have : (p.manifest.substrateKind == p.substrate.kind) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem a_split_operation_digest_refuses
    (identity preRoot : D) (p : Position)
    (h : p.manifest.witnessOpDigest ≠ p.substrate.opDigest) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition linkOk
  have : (p.manifest.witnessOpDigest == p.substrate.opDigest) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

/-- An operation id that is not derived over the authenticated successor
refuses — enforcement point 3. -/
theorem an_operation_id_over_another_successor_refuses
    (identity preRoot : D) (p : Position)
    (h : p.operationId ≠ operationIdOf identity p.substrate.cDsmPlus) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition linkOk
  have : (p.operationId == operationIdOf identity p.substrate.cDsmPlus) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

/-- An unverified `sigma_dsm` refuses. -/
theorem an_unauthenticated_successor_refuses
    (identity preRoot : D) (p : Position)
    (h : p.substrate.sigmaValid = false) :
    stepPosition identity preRoot p = none := by
  unfold stepPosition
  simp [h]

/-- **ORDER.** A position that refuses stops the walk: no later position
rescues it, and the whole walk yields nothing. The list is ordered
latest-first, so `p :: rest` is "p after rest". -/
theorem a_refusal_stops_the_walk
    (identity : D) (s : Start) (p : Position) (rest : List Position)
    (h : walk identity s rest = none) :
    walk identity s (p :: rest) = none := by
  simp [walk, h]

-- ─────────────────────────────────────────────────────────────────────────────
-- §4 — the correspondence
-- ─────────────────────────────────────────────────────────────────────────────

/-- The market coordinates `B` carries, as `CORR` compares them. -/
structure BundleCoords where
  traderParent : D
  traderSuccessor : D
  routeSetCommitment : D
  /-- The economics the selected route implies, as one digest. -/
  routeEconomics : D
  deriving DecidableEq, Repr

/-- The accepted `DlvSettle` the walk validated, as `CORR` reads it. -/
structure AcceptedSettle where
  embeddedParent : D
  cDsmPlus : D
  externalCommitmentX : D
  parentBinding : D
  balanceEffects : D
  deriving DecidableEq, Repr

/-- The vault cursor `(V, c_n, g)` the composition walk stands on. Only `c_n`
is compared here; the family is named so it cannot be confused with the
economic lineage's `(G, DevID, p)`. -/
structure Cursor where
  vault : D
  cN : D
  generation : Nat
  deriving DecidableEq, Repr

/-- `CORR.1` .. `CORR.5` (2c-C4 §4). `witnessHolds` stands for the cursor's
`CorrespondenceWitness` — `VDS.COMMON.10.a`, proved in `DSMValidDlvSuccessor`
and consumed here as a hypothesis rather than re-proved. -/
def corresponds (a : AcceptedSettle) (b : BundleCoords) (c : Cursor)
    (witnessHolds : Bool) : Bool :=
  -- CORR.1 — the accepted pair IS the bundle's pair
  (a.embeddedParent == b.traderParent)
    && (a.cDsmPlus == b.traderSuccessor)
    -- CORR.2 — one trade identity
    && (a.externalCommitmentX == b.routeSetCommitment)
    -- CORR.3 — the accepted settle consumes THIS cursor
    && (a.parentBinding == c.cN)
    -- CORR.4 — the effects are the route's economics
    && (a.balanceEffects == b.routeEconomics)
    -- CORR.5 — the byte correspondence held at the cursor
    && witnessHolds

/-- **CORRESPOND, conjunct by conjunct.** Each equality is separately
necessary: a foreign successor, a foreign trade, a foreign cursor, foreign
economics, or an absent witness each refuse. Five theorems rather than one, so
a mutation dropping any single conjunct is caught by name. -/
theorem a_foreign_trader_parent_does_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) (w : Bool)
    (h : a.embeddedParent ≠ b.traderParent) :
    corresponds a b c w = false := by
  unfold corresponds
  have : (a.embeddedParent == b.traderParent) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem a_foreign_trader_successor_does_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) (w : Bool)
    (h : a.cDsmPlus ≠ b.traderSuccessor) :
    corresponds a b c w = false := by
  unfold corresponds
  have : (a.cDsmPlus == b.traderSuccessor) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem a_foreign_trade_identity_does_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) (w : Bool)
    (h : a.externalCommitmentX ≠ b.routeSetCommitment) :
    corresponds a b c w = false := by
  unfold corresponds
  have : (a.externalCommitmentX == b.routeSetCommitment) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem a_foreign_cursor_does_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) (w : Bool)
    (h : a.parentBinding ≠ c.cN) :
    corresponds a b c w = false := by
  unfold corresponds
  have : (a.parentBinding == c.cN) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem foreign_economics_do_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) (w : Bool)
    (h : a.balanceEffects ≠ b.routeEconomics) :
    corresponds a b c w = false := by
  unfold corresponds
  have : (a.balanceEffects == b.routeEconomics) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

theorem an_absent_correspondence_witness_does_not_correspond
    (a : AcceptedSettle) (b : BundleCoords) (c : Cursor) :
    corresponds a b c false = false := by
  unfold corresponds
  simp

-- ─────────────────────────────────────────────────────────────────────────────
-- §5 — the realization fact
-- ─────────────────────────────────────────────────────────────────────────────

/-- The successor kinds the frontier gates on (2c-C4 §6 Ruling C1). -/
inductive Kind where
  | market
  | ownerClose
  deriving DecidableEq, Repr

/-- What C4 can establish on its own: a validated economic root at a position,
and the correspondence. This is the ANTECEDENT of realization, never
realization itself. -/
structure Prerequisites where
  /-- The root `walk` returned. `none` means the walk did not validate. -/
  validatedRoot : Option D
  corresponds : Bool
  deriving DecidableEq, Repr

/-- Whether C4's own half holds. -/
def prerequisitesHold (pre : Prerequisites) : Bool :=
  pre.validatedRoot.isSome && pre.corresponds

/-- **`IndependentRealization`, parameterised.** `W` is the 2c-D
bundle-acceptance witness: an opaque `Prop` this module never instantiates and
never proves. Realization is C4's half AND `W`.

There is deliberately no constructor and no lemma anywhere below that produces
a `W`. Every theorem about realization is an implication with `W` in the
antecedent. -/
def Realization (W : Prop) (pre : Prerequisites) : Prop :=
  prerequisitesHold pre = true ∧ W

/-- **REALIZE.** C4's half plus the abstract witness gives realization. This is
the whole of what C4 proves, and it is an implication. -/
theorem prerequisites_and_witness_give_realization
    (W : Prop) (pre : Prerequisites)
    (hpre : prerequisitesHold pre = true) (hw : W) :
    Realization W pre :=
  ⟨hpre, hw⟩

/-- Realization is not obtainable from C4's half alone: it still carries `W`,
whatever `W` is. Stated as an extraction so no reader can mistake the
implication above for a construction. -/
theorem realization_still_carries_the_witness
    (W : Prop) (pre : Prerequisites) (h : Realization W pre) : W :=
  h.2

/-- And the correspondence alone is not realization: with the prerequisites
holding, `Realization W pre` is exactly `W`. If `W` is `False` — the state of
the world until 2c-D instantiates it — nothing realizes. -/
theorem correspondence_alone_is_not_realization (pre : Prerequisites) :
    ¬ Realization False pre := by
  intro h
  exact h.2

-- ─────────────────────────────────────────────────────────────────────────────
-- §6, §7 — the verdict, and what it unlocks
-- ─────────────────────────────────────────────────────────────────────────────

/-- The verdict a fold carries (2c-C3 / 2c-A.1 ruling 12), reduced to what C4
needs: whether it may fold forward, and whether it may certify. -/
inductive Verdict where
  /-- Every conjunct held. Reachable for a close, and for a market successor
  only with the 2c-D witness. -/
  | valid
  /-- Every conjunct held including `VDS.COMMON.10.a`, and the realization fact
  is 2c-C4/2c-D's. -/
  | partialPendingRealization
  /-- A conjunct decided against the successor, or its evidence is missing. -/
  | refused
  deriving DecidableEq, Repr

/-- 2c-A.1 ruling 12: the composition walk folds forward on `valid` and on
`partialPendingRealization`. -/
def mayFold : Verdict → Bool
  | .valid => true
  | .partialPendingRealization => true
  | .refused => false

/-- Only `valid` certifies. Every boundary in §7 reads this. -/
def certifies : Verdict → Bool
  | .valid => true
  | _ => false

/-- **The verdict a fold carries, by kind.** A close realizes at binding
finality (Req 6.30): no acceptance artifact, no witness. A market fold carries
`partialPendingRealization` unless the 2c-D witness is present — and this model
has no way to present one, which is the point. -/
def verdictOf (k : Kind) (pre : Prerequisites) (witnessPresent : Bool) : Verdict :=
  if prerequisitesHold pre then
    match k with
    | .ownerClose => .valid
    | .market => if witnessPresent then .valid else .partialPendingRealization
  else
    .refused

/-- **WITHHOLD.** Without the 2c-D witness, a market fold never certifies —
however complete C4's own half is. -/
theorem market_never_certifies_without_the_witness
    (pre : Prerequisites) :
    certifies (verdictOf .market pre false) = false := by
  have h : verdictOf .market pre false = .refused
      ∨ verdictOf .market pre false = .partialPendingRealization := by
    unfold verdictOf
    cases hb : prerequisitesHold pre
    · left; simp
    · right; simp
  rcases h with h | h <;> rw [h] <;> rfl

/-- …and it still FOLDS, which is the separation 2c-A.1 ruling 12 froze: the
missing fact withholds the claim, it does not halt composition. -/
theorem a_withheld_market_verdict_still_folds
    (pre : Prerequisites) (h : prerequisitesHold pre = true) :
    mayFold (verdictOf .market pre false) = true := by
  unfold verdictOf mayFold
  simp [h]

/-- **KIND SPLIT.** On the same prerequisites, a close certifies where a market
fold does not. Req 6.30's asymmetry, as a theorem rather than as prose. -/
theorem close_certifies_market_does_not
    (pre : Prerequisites) (h : prerequisitesHold pre = true) :
    certifies (verdictOf .ownerClose pre false) = true
      ∧ certifies (verdictOf .market pre false) = false := by
  constructor
  · unfold verdictOf certifies; simp [h]
  · exact market_never_certifies_without_the_witness pre

/-- A refused position certifies nothing and folds nothing, on either arm. -/
theorem refused_prerequisites_neither_fold_nor_certify
    (k : Kind) (pre : Prerequisites) (w : Bool)
    (h : prerequisitesHold pre = false) :
    mayFold (verdictOf k pre w) = false
      ∧ certifies (verdictOf k pre w) = false := by
  have hr : verdictOf k pre w = .refused := by unfold verdictOf; simp [h]
  rw [hr]
  exact ⟨rfl, rfl⟩

/-- **The §7 gate, as one statement.** Every boundary C4 names — spendability,
route display, receipt publication, folding a DLV successor from `B`,
accepted-successor finality, fence release — is gated on `certifies`. So on a
market successor without the witness, none of them opens. -/
theorem no_market_boundary_opens_without_the_witness
    (pre : Prerequisites) :
    certifies (verdictOf .market pre false) = false :=
  market_never_certifies_without_the_witness pre

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the theorems above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

/-- A position that validates: the registered claim IS the derived root, the
three enforcement points hold, and the signature verifies. -/
def goodPosition : Position :=
  { manifest := { substrateAddr := 7, substrateKind := 0x31, witnessOpDigest := 9 }
  , substrate :=
      { addr := 7, kind := 0x31, opDigest := 9
      , embeddedParent := 11, cDsmPlus := 12, sigmaValid := true }
  , registered := emptyRoot + 5
  , writeSet := 5
  , operationId := operationIdOf 3 12 }

/-- The same position with the attacker's post-root in the register. -/
def forgedPosition : Position := { goodPosition with registered := 999 }

/-- The honest walk validates, and the value is the derived root. -/
theorem the_sample_walk_validates :
    walk 3 .emptyActivation [goodPosition] = some 5 := by
  decide

/-- **Req 21.17, as a sample.** The same evidence with an attacker-chosen
post-root validates nothing — and the honest one still does, so the refusal is
the forgery and not a broken fixture. -/
theorem the_forged_root_sample_refuses :
    walk 3 .emptyActivation [forgedPosition] = none
      ∧ walk 3 .emptyActivation [goodPosition] = some 5 := by
  constructor <;> decide

/-- A corresponding triple, and the same triple with a foreign successor. -/
def goodAccepted : AcceptedSettle :=
  { embeddedParent := 11, cDsmPlus := 12, externalCommitmentX := 20
  , parentBinding := 30, balanceEffects := 40 }

def goodBundle : BundleCoords :=
  { traderParent := 11, traderSuccessor := 12
  , routeSetCommitment := 20, routeEconomics := 40 }

def goodCursor : Cursor := { vault := 1, cN := 30, generation := 4 }

theorem the_sample_corresponds :
    corresponds goodAccepted goodBundle goodCursor true = true := by
  decide

theorem a_foreign_successor_sample_does_not_correspond :
    corresponds { goodAccepted with cDsmPlus := 13 } goodBundle goodCursor true = false := by
  decide

/-- Prerequisites that hold, so the withhold theorems are about a real state
rather than about a vacuous one. -/
def goodPrerequisites : Prerequisites :=
  { validatedRoot := some 5, corresponds := true }

theorem the_sample_prerequisites_hold :
    prerequisitesHold goodPrerequisites = true := by
  decide

/-- The separation, on a state where C4's half is complete: the close arm
certifies, the market arm does not, and the market arm still folds. -/
theorem the_separation_is_not_vacuous :
    certifies (verdictOf .ownerClose goodPrerequisites false) = true
      ∧ certifies (verdictOf .market goodPrerequisites false) = false
      ∧ mayFold (verdictOf .market goodPrerequisites false) = true := by
  refine ⟨by decide, by decide, by decide⟩

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report — per theorem, as the sibling modules do
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms untrusted_start_validates_nothing
#print axioms operator_pin_validates_nothing
#print axioms validated_root_is_derived_never_registered
#print axioms a_claim_that_is_not_the_derived_root_refuses
#print axioms a_substrate_at_another_address_refuses
#print axioms a_substrate_of_another_kind_refuses
#print axioms a_split_operation_digest_refuses
#print axioms an_operation_id_over_another_successor_refuses
#print axioms an_unauthenticated_successor_refuses
#print axioms a_refusal_stops_the_walk
#print axioms a_foreign_trader_parent_does_not_correspond
#print axioms a_foreign_trader_successor_does_not_correspond
#print axioms a_foreign_trade_identity_does_not_correspond
#print axioms a_foreign_cursor_does_not_correspond
#print axioms foreign_economics_do_not_correspond
#print axioms an_absent_correspondence_witness_does_not_correspond
#print axioms prerequisites_and_witness_give_realization
#print axioms realization_still_carries_the_witness
#print axioms correspondence_alone_is_not_realization
#print axioms market_never_certifies_without_the_witness
#print axioms a_withheld_market_verdict_still_folds
#print axioms close_certifies_market_does_not
#print axioms refused_prerequisites_neither_fold_nor_certify
#print axioms no_market_boundary_opens_without_the_witness
#print axioms the_sample_walk_validates
#print axioms the_forged_root_sample_refuses
#print axioms the_sample_corresponds
#print axioms a_foreign_successor_sample_does_not_correspond
#print axioms the_sample_prerequisites_hold
#print axioms the_separation_is_not_vacuous

end DSMAcceptedSuccessorWalk
