/-
  DSM `ValidDlvSuccessorCore` — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks the statements amendment 2c-C3 freezes:

    - BRIDGE       canonical equality implies structural equality, so the
                   derive-and-compare test really does pin every field
    - ENCODING     the two variable-length points -- the encumbrance count
                   prefix and the `beta` presence marker -- are LOAD-BEARING,
                   shown by exhibiting the collision that appears without them
    - DIRECTION    2c-C3 erratum D4's derivation is total, and the membership
                   check that establishes it also refutes `input = output`
    - DERIVED      preserved and mutated field equalities follow FROM
                   correspondence; they are theorems, not acceptance conjuncts
    - DISPATCH     the market and release/close tails are disjoint
    - TAXONOMY     a failed derivation propagates its class; there is no arm
                   that silently becomes success
    - TEETH        a successor differing ONLY in a preserved field is rejected;
                   a successor that ADDS an encumbrance claim is rejected;
                   a market successor is not accepted under the close tail

  What this module does NOT claim (2c-C3 rulings G, H):

    * `TokenPolicyValid` is NOT modelled and NOT discharged. The complete
      protocol predicate is `ValidDlvSuccessor := ValidDlvSuccessorCore ∧
      TokenPolicyValid`; only the first conjunct is here.
    * The terminal close's exactly-once owner credit is NOT modelled. It is a
      property of the OWNER'S balance, not of `V_{n+1}`, so no predicate over
      the successor -- here or in Rust -- can express it.
    * `VDS.COMMON.10.a` -- the correspondence conjunct these theorems are built
      around -- is NORMATIVE and PROVED HERE, but is IMPLEMENTATION-BLOCKED on
      2c-A's canonical encoder cut. No authoritative canonical successor bytes
      exist on the wire today: `successor_ccb` carries the route-set commitment
      on a market bundle and a slot commitment on a close, and both composition
      arms derive the successor locally. Proving it here does not make it
      implementable there, and production must not report VALID for a path whose
      validity requires it until the byte comparison is actually performed.
    * The acceptance condition is equality of canonical BYTES. A decode/re-encode
      round trip is NOT a substitute unless the encoder performing it is the
      frozen normative encoder -- `decode_vault_state` normalizes rather than
      refuses, so the substitute would launder non-canonical input.
    * This is a model of the NORMATIVE objects, not a refinement proof from the
      shipped Rust. `canonVault` is an injective encoding with the same two
      variable-length hazards as CCB; it is not CCB.
    * `Nat` is unbounded, so overflow cannot arise on its own. The overflow
      admissibility arm is therefore an EXPLICIT bound guard, not an emergent
      property -- see `noOverflow`.

  Mutation controls, executed rather than asserted. A green suite around a gate
  proves nothing about whether the gate is load-bearing, so both were run and
  both produced the strongest available result -- the kernel proving the
  NEGATION of a named theorem, not merely a broken proof:

    1. `encList` stripped of its count prefix
         -> `canonVault_injective` falls back on `sorryAx`
         -> `canonVault_separates_the_samples` is proved FALSE: the two
            sample states genuinely collide under the real encoding.

    2. the byte comparison removed from `correspondence`
         -> `preserved_field_mutation_is_rejected`,
            `encumbrance_introduction_is_rejected`,
            `budget_introduction_is_rejected` and
            `market_successor_not_accepted_under_close`
            are each proved FALSE.

  Zero `axiom` and zero `opaque` declarations. `#print axioms` runs on every
  headline result at the bottom and the output is REPORTED, not summarised: no
  result depends on `sorryAx` or `Classical.choice`; several depend on `propext`
  and `Quot.sound`, which are part of Lean's logic rather than assumptions this
  module adds. Six results depend on no axioms at all.
-/

-- ============================================================
-- The state
-- ============================================================

/-- `P_M`. The token pair, whose ordering is a validity condition:
    `MarketPolicy::beta_constant_product` refuses an unordered or equal pair. -/
structure MarketPolicy where
  tokenA : Nat
  tokenB : Nat
  deriving Repr, DecidableEq

/-- Registry §5.1 requires `token_a < token_b` strictly, refused at
    construction rather than normalized by swapping. -/
def MarketPolicy.wellFormed (p : MarketPolicy) : Prop := p.tokenA < p.tokenB

/-- `V_n` — the fifteen members of the Def 4.1 tuple, in that order. -/
structure VaultState where
  ownerGenesis   : Nat            -- 1  g_o
  ownerDevice    : Nat            -- 2  d_o
  vaultId        : Nat            -- 3
  generation     : Nat            -- 4  n
  reserveA       : Nat            -- 5  R_A
  reserveB       : Nat            -- 6  R_B
  marketPolicy   : MarketPolicy   -- 7  P_M
  releasePolicy  : Nat            -- 8  P_R
  feePolicy      : Nat            -- 9  Φ
  encumbrances   : List Nat       -- 10 E
  beta           : Option Nat     -- 11 β
  parentCommit   : Nat            -- 12 h_n
  ownerAuthority : Nat            -- 13 r_o
  storageSet     : Nat            -- 14 S
  quorum         : Nat            -- 15 q
  deriving Repr, DecidableEq

-- ============================================================
-- Canonical encoding, and why its two length disciplines matter
-- ============================================================

/-- The `β` presence marker of §2.3: absent emits `0`, present emits `1 ‖ v`. -/
def encOpt : Option Nat → List Nat
  | none   => [0]
  | some b => [1, b]

/-- The §2.4 set encoding: `u32_be(count) ‖ elements`. -/
def encList (l : List Nat) : List Nat := l.length :: l

/-- `CanonVault`. The encumbrance set sits at field 10, in the MIDDLE of the
    tuple, exactly as Def 4.1 orders it — which is what makes its count prefix
    load-bearing rather than decorative. -/
def canonVault (v : VaultState) : List Nat :=
  [v.ownerGenesis, v.ownerDevice, v.vaultId, v.generation, v.reserveA, v.reserveB,
   v.marketPolicy.tokenA, v.marketPolicy.tokenB, v.releasePolicy, v.feePolicy]
  ++ encList v.encumbrances
  ++ encOpt v.beta
  ++ [v.parentCommit, v.ownerAuthority, v.storageSet, v.quorum]

/-- A count-prefixed segment is recoverable: equal encodings with equal tails
    force both the list and the tail to agree. -/
theorem encList_inj {l₁ l₂ r₁ r₂ : List Nat}
    (h : encList l₁ ++ r₁ = encList l₂ ++ r₂) : l₁ = l₂ ∧ r₁ = r₂ := by
  simp only [encList, List.cons_append, List.cons.injEq] at h
  obtain ⟨hlen, htail⟩ := h
  exact List.append_inj htail hlen

/-- The presence marker is recoverable the same way. -/
theorem encOpt_inj {a b : Option Nat} {r₁ r₂ : List Nat}
    (h : encOpt a ++ r₁ = encOpt b ++ r₂) : a = b ∧ r₁ = r₂ := by
  cases a <;> cases b <;>
    simp_all [encOpt]

/-- **BRIDGE.** Canonical equality implies structural equality.

    Without this, "every preserved field equals `V_n`" derived from a byte
    comparison would carry an unstated assumption. 2c-C3 ruling B names it for
    exactly that reason. -/
theorem canonVault_injective {x y : VaultState}
    (h : canonVault x = canonVault y) : x = y := by
  obtain ⟨a1,a2,a3,a4,a5,a6,⟨ta,tb⟩,a8,a9,ae,ab,a12,a13,a14,a15⟩ := x
  obtain ⟨b1,b2,b3,b4,b5,b6,⟨ua,ub⟩,b8,b9,be,bb,b12,b13,b14,b15⟩ := y
  simp only [canonVault, List.cons_append, List.cons.injEq, List.nil_append,
    List.append_assoc] at h
  obtain ⟨e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,rest⟩ := h
  obtain ⟨heq, rest⟩ := encList_inj rest
  obtain ⟨hbeta, rest⟩ := encOpt_inj rest
  simp only [List.cons.injEq, and_true] at rest
  subst e1; subst e2; subst e3; subst e4; subst e5; subst e6
  subst e7; subst e8; subst e9; subst e10; subst heq; subst hbeta
  simp_all

/-- **ENCODING TEETH — the count prefix is load-bearing.** Drop it and the
    encoding collides: a claim list can borrow a byte from the field that
    follows it. This is the concrete failure `encList` prevents. -/
def canonVaultNoCount (v : VaultState) : List Nat :=
  [v.ownerGenesis, v.ownerDevice, v.vaultId, v.generation, v.reserveA, v.reserveB,
   v.marketPolicy.tokenA, v.marketPolicy.tokenB, v.releasePolicy, v.feePolicy]
  ++ v.encumbrances
  ++ encOpt v.beta
  ++ [v.parentCommit, v.ownerAuthority, v.storageSet, v.quorum]

/-- No claims, but a budget of `0` present. Encodes its `β` as `1 ‖ 0`. -/
def sampleBudgetNoClaims : VaultState :=
  ⟨0,0,0,0,0,0,⟨0,1⟩,0,0,[], some 0, 0,0,0,0⟩

/-- One claim, numbered `1`, and no budget. Encodes its `β` as the bare `0`. -/
def sampleClaimNoBudget : VaultState :=
  ⟨0,0,0,0,0,0,⟨0,1⟩,0,0,[1], none, 0,0,0,0⟩

/-- The two states are genuinely different: one is encumbered, the other has a
    live iteration budget. Under 2c-C3 ruling F they are not interchangeable —
    one may consume a claim, the other may take a market step. -/
theorem samples_differ : sampleBudgetNoClaims ≠ sampleClaimNoBudget := by decide

/-- **…yet without the count prefix their encodings are byte-identical.**

    The claim list borrows the presence marker's byte:

        no claims, β = some 0   ->   [] ‖ (1 ‖ 0)   =   [1, 0]
        claim [1], β = none     ->   [1] ‖ (0)      =   [1, 0]

    A verifier comparing these bytes would accept a successor that silently
    converted a budget into an encumbrance claim. This is the concrete failure
    the §2.4 count prefix prevents, and it is why the prefix is a validity
    condition rather than a framing convenience. -/
theorem canonVaultNoCount_collides :
    canonVaultNoCount sampleBudgetNoClaims = canonVaultNoCount sampleClaimNoBudget := by
  decide

/-- The real encoding separates them, because the count is emitted first. -/
theorem canonVault_separates_the_samples :
    canonVault sampleBudgetNoClaims ≠ canonVault sampleClaimNoBudget := by decide

-- ============================================================
-- Erratum D4 — `direction` is derived, and the derivation is total
-- ============================================================

inductive Direction where
  | AtoB
  | BtoA
  deriving Repr, DecidableEq

/-- The operation's declared token commitments. -/
structure MarketOp where
  inputCommit   : Nat
  outputCommit  : Nat
  amountIn      : Nat
  feeBps        : Nat
  consumedClaim : Option Nat
  deriving Repr, DecidableEq

/-- 2c-C3 erratum D4. `direction` is carried by neither `T_v`, `Allocation`
    nor `V_n`; it is derived from the policy-commit set equality. -/
def deriveDirection (p : MarketPolicy) (op : MarketOp) : Option Direction :=
  if op.inputCommit = p.tokenA ∧ op.outputCommit = p.tokenB then some .AtoB
  else if op.inputCommit = p.tokenB ∧ op.outputCommit = p.tokenA then some .BtoA
  else none

/-- **DIRECTION — totality.** On a well-formed policy the set-equality check
    that establishes membership ALSO refutes `input = output`: equal commits
    would force `tokenA = tokenB`, which construction already refused. So every
    case that survives the check has exactly one branch. -/
theorem direction_refutes_equal_commitments
    {p : MarketPolicy} {op : MarketOp} {d : Direction}
    (hwf : p.wellFormed) (h : deriveDirection p op = some d) :
    op.inputCommit ≠ op.outputCommit := by
  unfold deriveDirection at h
  intro heq
  split at h
  · next hc =>
    obtain ⟨h1, h2⟩ := hc
    rw [heq] at h1
    rw [h1] at h2
    exact absurd h2 (Nat.ne_of_lt hwf)
  · split at h
    · next _ hc =>
      obtain ⟨h1, h2⟩ := hc
      rw [heq] at h1
      rw [h1] at h2
      exact absurd h2.symm (Nat.ne_of_lt hwf)
    · exact Option.noConfusion h

/-- The derivation is a function, so it is single-valued: there is no state in
    which two directions are both derivable. -/
theorem direction_is_unique {p : MarketPolicy} {op : MarketOp} {d e : Direction}
    (h₁ : deriveDirection p op = some d) (h₂ : deriveDirection p op = some e) :
    d = e := by
  rw [h₁] at h₂; exact Option.some.inj h₂

-- ============================================================
-- The outcome taxonomy (2c-C3 ruling E)
-- ============================================================

/-- Layer 1. Four classes, and nothing else — no catch-all. -/
inductive Cls where
  | valid
  | invalid
  | incomplete
  | safetyViolation
  deriving Repr, DecidableEq

/-- Layer 2. Exact reasons; they REFINE a class and never compete with it.
    Two distinct reasons map to `incomplete` on purpose: Req 6.25's point is
    that "no binding exists" and "I could not find out" are different facts. -/
inductive Reason where
  | parentUnauthenticated
  | vaultMismatch
  | generationMismatch
  | staleParent
  | pairNotVaultPair
  | inputAmountZero
  | reserveInZero
  | reserveOutZero
  | feeAtOrAboveDenominator
  | outputZero
  | outputExceedsReserve
  | arithmeticOverflow
  | budgetExhausted
  | claimNotHeld
  | solvencyViolated
  | correspondenceMismatch
  | composeFromRetiredParent
  | settlerKeyMismatch
  | noBindingEstablished
  | bindingUndetermined
  | bindingEvidenceUnavailable
  | duplicateBindingFinality
  -- Three reasons the amendment's clause table assigns INVALID to and this
  -- model originally omitted -- found when the Rust implementation had to
  -- choose a code for each and there was none. NONE is a field equality
  -- Ruling B derives from correspondence; each is an independent conjunct.
  /-- `VDS.COMMON.11` / `VDS.CLOSE.2`: the advancing party's signature over
      the concrete successor does not verify. A signature is not a field
      equality, so it is independent of `10.a`. -/
  | successorSignatureInvalid
  /-- Ruling J's `operation : Invalid(reason)` arm: the bound bundle yields
      no canonical operation -- it does not decode, re-encode, hash to the
      record's identity, or has no valid shape. -/
  | bundleNotCanonical
  /-- `VDS.COMMON.5`'s "and `storage_set_id` re-derives from it" and
      `VDS.COMMON.6`'s "and equals the canonical `n/2 + 1`": the bundle was
      bound under a set or quorum this vault did not commit. These are the
      SECOND clauses of those rows -- consistency checks on the bundle -- and
      are distinct from the field equalities in the first clauses, which
      Ruling B derives from `10.a` alone. -/
  | bundleForeignToVault
  /-- Ruling J's `economic_facts : Invalid(reason)` arm: realization evidence
      that is PRESENT and fails verification -- a receipt whose signature does
      not verify, a RouteCommit that does not recompute the bundle's `X`, a
      claimed output the state's curve does not yield. This is `INVALID`, never
      absence: a fetched-but-forged receipt is not the same fact as no receipt,
      and mapping it to absence let a forged receipt fold as "not settled yet".
      It is deliberately NOT a safety violation -- a bad signature establishes
      invalid evidence, not a substrate contradiction, and quarantining on it
      would let anyone who can inject a forged receipt force a denial-of-service
      quarantine. -/
  | realizationEvidenceInvalid
  deriving Repr, DecidableEq

/-- 2c-C3 ruling B: the derivation is TYPED AND PARTIAL. A total function
    returning `VaultState` would hide failed arithmetic, unavailable evidence
    and invalid authorization inside an apparently successful call. -/
inductive DeriveResult where
  | derived (v : VaultState)
  | invalid (r : Reason)
  | incomplete (r : Reason)
  | safetyViolation (r : Reason)
  deriving Repr, DecidableEq

def DeriveResult.cls : DeriveResult → Cls
  | .derived _         => .valid
  | .invalid _         => .invalid
  | .incomplete _      => .incomplete
  | .safetyViolation _ => .safetyViolation

-- ============================================================
-- The derivation
-- ============================================================

def bpsDenominator : Nat := 10000

/-- `Nat` is unbounded, so overflow cannot arise on its own. The admissibility
    arm is therefore an EXPLICIT guard against the u64 ceiling, not an emergent
    property — stated so the model does not quietly prove a bound the real
    arithmetic must check. -/
def maxU64 : Nat := 18446744073709551615

/-- 2c-C3 erratum D2. No tuple field; both legs zero is the marker, and it is
    unambiguous BECAUSE market admissibility forbids `a = 0`. -/
def Retired (v : VaultState) : Prop := v.reserveA = 0 ∧ v.reserveB = 0

instance : DecidablePred Retired := fun v => by
  unfold Retired; infer_instance

/-- 2c-C3 ruling F. Absent stays absent; present decrements; present-at-zero is
    inadmissible; introduction and removal are both unreachable. -/
def nextBudget : Option Nat → Option (Option Nat)
  | none       => some none
  | some 0     => none
  | some (n+1) => some (some n)

/-- 2c-C3 ruling F / Req 8.1: a consumed claim's exact removal must be visible,
    and a claim the parent does not hold cannot be consumed. -/
def consumeClaim (e : List Nat) : Option Nat → Option (List Nat)
  | none   => some e
  | some c => if e.contains c then some (e.erase c) else none

/-- **Every successor this module derives is built here.** Routing all derived
    arms through one constructor is what makes the preserved-field theorems
    below `rfl` rather than a case analysis repeated per field. -/
def mkSuccessor (v : VaultState) (cn rA rB : Nat)
    (enc : List Nat) (b : Option Nat) : VaultState :=
  { v with generation := v.generation + 1, reserveA := rA, reserveB := rB,
           encumbrances := enc, beta := b, parentCommit := cn }

/-- The beta market family: constant product with a fee that stays in the
    reserves. The single floor division is the only rounding, and the
    fee-adjusted input is NOT rounded first. -/
def deriveMarket (v : VaultState) (cn : Nat) (op : MarketOp) : DeriveResult :=
  if v.reserveA = 0 ∧ v.reserveB = 0 then .invalid .composeFromRetiredParent else
  match deriveDirection v.marketPolicy op with
  | none => .invalid .pairNotVaultPair
  | some dir =>
    let x := match dir with | .AtoB => v.reserveA | .BtoA => v.reserveB
    let y := match dir with | .AtoB => v.reserveB | .BtoA => v.reserveA
    if op.amountIn = 0 then .invalid .inputAmountZero
    else if x = 0 then .invalid .reserveInZero
    else if y = 0 then .invalid .reserveOutZero
    else if bpsDenominator ≤ op.feeBps then .invalid .feeAtOrAboveDenominator
    else
      let eff := op.amountIn * (bpsDenominator - op.feeBps)
      let num := eff * y
      let den := x * bpsDenominator + eff
      let output := num / den
      if maxU64 < num ∨ maxU64 < den ∨ maxU64 < x + op.amountIn then
        .invalid .arithmeticOverflow
      else if output = 0 then .invalid .outputZero
      else if y < output then .invalid .outputExceedsReserve
      else
        match consumeClaim v.encumbrances op.consumedClaim with
        | none => .invalid .claimNotHeld
        | some enc =>
          match nextBudget v.beta with
          | none => .invalid .budgetExhausted
          | some b =>
            match dir with
            | .AtoB => .derived (mkSuccessor v cn (v.reserveA + op.amountIn)
                                   (v.reserveB - output) enc b)
            | .BtoA => .derived (mkSuccessor v cn (v.reserveA - output)
                                   (v.reserveB + op.amountIn) enc b)

/-- `OWNER_LOCAL_FULL_CLOSE`: drains BOTH legs and retires the vault. -/
def deriveClose (v : VaultState) (cn : Nat) : DeriveResult :=
  if v.reserveA = 0 ∧ v.reserveB = 0 then .invalid .composeFromRetiredParent
  else match nextBudget v.beta with
    | none   => .invalid .budgetExhausted
    | some b => .derived (mkSuccessor v cn 0 0 v.encumbrances b)

inductive Operation where
  | market (op : MarketOp)
  | ownerClose
  /-- Ruling J's `operation : Invalid(reason)` arm, which an earlier draft of
      this model omitted. The bundle a binding resolved to yielded no canonical
      operation for this vault; no successor can be derived from it. -/
  | invalid (r : Reason)
  deriving Repr, DecidableEq

def deriveExpected (v : VaultState) (cn : Nat) : Operation → DeriveResult
  | .market op => deriveMarket v cn op
  | .ownerClose => deriveClose v cn
  | .invalid r => .invalid r

-- ============================================================
-- Every derived successor came from `mkSuccessor`
-- ============================================================

theorem derived_is_mkSuccessor {v e : VaultState} {cn : Nat} {o : Operation}
    (h : deriveExpected v cn o = .derived e) :
    ∃ rA rB enc b, e = mkSuccessor v cn rA rB enc b := by
  cases o with
  | invalid r => exact DeriveResult.noConfusion h
  | ownerClose =>
    simp only [deriveExpected, deriveClose] at h
    repeat' split at h
    all_goals first
      | exact DeriveResult.noConfusion h
      | exact ⟨_, _, _, _, by injection h with h; exact h.symm⟩
  | market op =>
    simp only [deriveExpected, deriveMarket] at h
    repeat' split at h
    all_goals first
      | exact DeriveResult.noConfusion h
      | exact ⟨_, _, _, _, by injection h with h; exact h.symm⟩

-- ============================================================
-- DERIVED consequences (2c-C3 ruling B)
--
-- These are THEOREMS, not acceptance conjuncts. Keeping them as conjuncts
-- would make the independence obligation unsatisfiable for them: they cannot
-- be removed without a counterexample, because they follow from the conjunct
-- that remains.
-- ============================================================

/-- The nine fields `mkSuccessor` does not touch. Registry §5.1 numbering. -/
theorem mkSuccessor_preserves (v : VaultState) (cn rA rB : Nat)
    (enc : List Nat) (b : Option Nat) :
    let e := mkSuccessor v cn rA rB enc b
    e.ownerGenesis   = v.ownerGenesis   ∧      -- 1
    e.ownerDevice    = v.ownerDevice    ∧      -- 2
    e.vaultId        = v.vaultId        ∧      -- 3
    e.marketPolicy   = v.marketPolicy   ∧      -- 7
    e.releasePolicy  = v.releasePolicy  ∧      -- 8
    e.feePolicy      = v.feePolicy      ∧      -- 9
    e.ownerAuthority = v.ownerAuthority ∧      -- 13
    e.storageSet     = v.storageSet     ∧      -- 14
    e.quorum         = v.quorum :=             -- 15
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Generation always advances by exactly one, on both successor kinds. -/
theorem mkSuccessor_advances_generation (v : VaultState) (cn rA rB : Nat)
    (enc : List Nat) (b : Option Nat) :
    (mkSuccessor v cn rA rB enc b).generation = v.generation + 1 := rfl

/-- `h_{n+1} = c_n`: the successor's parent reference is the authenticated
    parent commitment the verifier already holds. Modelling it as an INPUT
    rather than a hash of `V_n` is deliberate — C3's input contract supplies
    `c_n` with the established parent, so no hash assumption enters here. -/
theorem mkSuccessor_binds_parent (v : VaultState) (cn rA rB : Nat)
    (enc : List Nat) (b : Option Nat) :
    (mkSuccessor v cn rA rB enc b).parentCommit = cn := rfl

/-- Field 13 `r_o` is invariant on BOTH kinds — market by the explicit rule,
    close because no beta family can express an authority change. -/
theorem derived_preserves_owner_authority {v e : VaultState} {cn : Nat}
    {o : Operation} (h : deriveExpected v cn o = .derived e) :
    e.ownerAuthority = v.ownerAuthority := by
  obtain ⟨_, _, _, _, rfl⟩ := derived_is_mkSuccessor h; rfl

/-- Fields 14 and 15: the close is NOT an exception. -/
theorem derived_preserves_storage_set_and_quorum {v e : VaultState} {cn : Nat}
    {o : Operation} (h : deriveExpected v cn o = .derived e) :
    e.storageSet = v.storageSet ∧ e.quorum = v.quorum := by
  obtain ⟨_, _, _, _, rfl⟩ := derived_is_mkSuccessor h; exact ⟨rfl, rfl⟩

theorem derived_preserves_vault_identity {v e : VaultState} {cn : Nat}
    {o : Operation} (h : deriveExpected v cn o = .derived e) :
    e.vaultId = v.vaultId ∧ e.ownerGenesis = v.ownerGenesis ∧
    e.ownerDevice = v.ownerDevice ∧ e.marketPolicy = v.marketPolicy := by
  obtain ⟨_, _, _, _, rfl⟩ := derived_is_mkSuccessor h
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem derived_advances_generation {v e : VaultState} {cn : Nat}
    {o : Operation} (h : deriveExpected v cn o = .derived e) :
    e.generation = v.generation + 1 := by
  obtain ⟨_, _, _, _, rfl⟩ := derived_is_mkSuccessor h; rfl

-- ============================================================
-- DISPATCH — the two tails are disjoint (2c-C3 erratum D2)
-- ============================================================

/-- A close successor is retired: both legs drained. -/
theorem close_derives_retired {v e : VaultState} {cn : Nat}
    (h : deriveExpected v cn .ownerClose = .derived e) : Retired e := by
  simp only [deriveExpected, deriveClose] at h
  repeat' split at h
  all_goals first
    | exact DeriveResult.noConfusion h
    | (injection h with h; subst h; exact ⟨rfl, rfl⟩)

/-- **A market successor is NEVER retired.** This is the whole argument for
    erratum D2: market admissibility forbids `a = 0`, so the input leg is
    `R_in + a > 0` and at least one leg is strictly positive. Both-zero is
    therefore reachable ONLY by the close family, which is what makes
    `Retired` an unambiguous marker with no new tuple field. -/
theorem market_never_derives_retired {v e : VaultState} {cn : Nat} {op : MarketOp}
    (h : deriveExpected v cn (.market op) = .derived e) : ¬ Retired e := by
  simp only [deriveExpected, deriveMarket] at h
  repeat' split at h
  all_goals first
    | exact DeriveResult.noConfusion h
    | (injection h with h; subst h; rintro ⟨ha, hb⟩; simp only [mkSuccessor] at ha hb; omega)

/-- Consequently the two families can never produce the same successor. -/
theorem close_and_market_successors_differ
    {v ec em : VaultState} {cn : Nat} {op : MarketOp}
    (hc : deriveExpected v cn .ownerClose = .derived ec)
    (hm : deriveExpected v cn (.market op) = .derived em) : ec ≠ em := by
  intro heq
  exact market_never_derives_retired hm (heq ▸ close_derives_retired hc)

/-- Composition from a retired parent is refused on the market path. -/
theorem retired_parent_refuses_market (v : VaultState) (cn : Nat) (op : MarketOp)
    (h : Retired v) : deriveExpected v cn (.market op) = .invalid .composeFromRetiredParent := by
  unfold Retired at h
  simp only [deriveExpected, deriveMarket, if_pos h]

-- ============================================================
-- VDS.CORRESPONDENCE — ONE conjunct, not the whole predicate
-- ============================================================

/-- 2c-C3 ruling B. The byte comparison happens ONLY on the `derived` arm;
    every other arm propagates its own class and reason unchanged. -/
def correspondence (v : VaultState) (cn : Nat) (o : Operation)
    (supplied : VaultState) : Cls × Option Reason :=
  match deriveExpected v cn o with
  | .derived e =>
      if canonVault e = canonVault supplied then (.valid, none)
      else (.invalid, some .correspondenceMismatch)
  | .invalid r         => (.invalid, some r)
  | .incomplete r      => (.incomplete, some r)
  | .safetyViolation r => (.safetyViolation, some r)

/-- **TAXONOMY.** A failed derivation propagates its EXACT class and reason.
    There is no arm on which a failure becomes a success, and no arm on which
    a reason is replaced by a generic one. Stated per constructor, because
    "propagates its class" is precisely the claim that must not be approximate. -/
theorem correspondence_propagates_invalid
    (v : VaultState) (cn : Nat) (o : Operation) (supplied : VaultState) (r : Reason)
    (h : deriveExpected v cn o = .invalid r) :
    correspondence v cn o supplied = (.invalid, some r) := by
  simp only [correspondence, h]

theorem correspondence_propagates_incomplete
    (v : VaultState) (cn : Nat) (o : Operation) (supplied : VaultState) (r : Reason)
    (h : deriveExpected v cn o = .incomplete r) :
    correspondence v cn o supplied = (.incomplete, some r) := by
  simp only [correspondence, h]

theorem correspondence_propagates_safety_violation
    (v : VaultState) (cn : Nat) (o : Operation) (supplied : VaultState) (r : Reason)
    (h : deriveExpected v cn o = .safetyViolation r) :
    correspondence v cn o supplied = (.safetyViolation, some r) := by
  simp only [correspondence, h]

/-- A non-canonical operation input NEVER derives a successor, and propagates
    its own reason unchanged. This is Ruling J's `Invalid(reason)` arm made
    explicit; before it existed here, the model could not express a bundle that
    fails to decode, and the Rust had to choose a code with nothing to mirror. -/
theorem invalid_operation_never_derives
    (v e : VaultState) (cn : Nat) (r : Reason) :
    deriveExpected v cn (.invalid r) ≠ .derived e := by
  simp [deriveExpected]

theorem invalid_operation_propagates_its_reason
    (v supplied : VaultState) (cn : Nat) (r : Reason) :
    correspondence v cn (.invalid r) supplied = (.invalid, some r) := by
  simp [correspondence, deriveExpected]

/-- On the DERIVED arm — and only there — the outcome turns on the bytes.
    Note this is NOT "the class always agrees with the derivation's class": a
    successful derivation whose bytes do not match is `invalid`, so the derived
    arm can downgrade `valid` to `invalid`. That asymmetry is the whole point of
    the comparison, and stating it as agreement would be false. -/
theorem correspondence_valid_iff_bytes_match
    {v e supplied : VaultState} {cn : Nat} {o : Operation}
    (hd : deriveExpected v cn o = .derived e) :
    correspondence v cn o supplied = (.valid, none) ↔ canonVault e = canonVault supplied := by
  simp only [correspondence, hd]
  split <;> simp_all

/-- Correspondence can only be `valid` via the derived arm, and then it PINS
    the supplied state to the derived one. This is the bridge in use. -/
theorem correspondence_valid_pins_successor
    {v supplied e : VaultState} {cn : Nat} {o : Operation}
    (hd : deriveExpected v cn o = .derived e)
    (hv : correspondence v cn o supplied = (.valid, none)) :
    supplied = e := by
  simp only [correspondence, hd] at hv
  split at hv
  · next hc => exact (canonVault_injective hc).symm
  · exact absurd hv (by simp)

/-- **DERIVED — preserved fields.** Every field the operation does not touch
    equals `V_n`'s, obtained FROM correspondence rather than checked beside it. -/
theorem correspondence_implies_preserved_fields
    {v supplied e : VaultState} {cn : Nat} {o : Operation}
    (hd : deriveExpected v cn o = .derived e)
    (hv : correspondence v cn o supplied = (.valid, none)) :
    supplied.ownerAuthority = v.ownerAuthority ∧
    supplied.storageSet     = v.storageSet     ∧
    supplied.quorum         = v.quorum         ∧
    supplied.vaultId        = v.vaultId        ∧
    supplied.marketPolicy   = v.marketPolicy := by
  have hpin := correspondence_valid_pins_successor hd hv
  subst hpin
  obtain ⟨hs, hq⟩ := derived_preserves_storage_set_and_quorum hd
  obtain ⟨hvid, _, _, hmp⟩ := derived_preserves_vault_identity hd
  exact ⟨derived_preserves_owner_authority hd, hs, hq, hvid, hmp⟩

/-- **DERIVED — mutated fields.** Generation and the parent binding equal their
    deterministic derived values. -/
theorem correspondence_implies_mutated_fields
    {v supplied e : VaultState} {cn : Nat} {o : Operation}
    (hd : deriveExpected v cn o = .derived e)
    (hv : correspondence v cn o supplied = (.valid, none)) :
    supplied.generation = v.generation + 1 ∧ supplied.parentCommit = cn := by
  have hpin := correspondence_valid_pins_successor hd hv
  subst hpin
  refine ⟨derived_advances_generation hd, ?_⟩
  obtain ⟨_, _, _, _, rfl⟩ := derived_is_mkSuccessor hd; rfl

/-- **TEETH, general form.** Any successor other than the derived one is
    rejected — not merely successors that differ in a field someone listed. -/
theorem correspondence_rejects_any_other_successor
    {v e bad : VaultState} {cn : Nat} {o : Operation}
    (hd : deriveExpected v cn o = .derived e) (hne : bad ≠ e) :
    correspondence v cn o bad = (.invalid, some .correspondenceMismatch) := by
  simp only [correspondence, hd]
  rw [if_neg]
  intro hc
  exact hne (canonVault_injective hc).symm

-- ============================================================
-- A concrete transition, so the teeth are not vacuous
-- ============================================================

def sampleParent : VaultState :=
  ⟨1, 2, 3, 0, 1000, 1000, ⟨10, 20⟩, 4, 5, [], none, 6, 7, 8, 9⟩

def sampleOp : MarketOp :=
  { inputCommit := 10, outputCommit := 20, amountIn := 100,
    feeBps := 30, consumedClaim := none }

/-- `output = (a·(D−f)·y) / (x·D + a·(D−f)) = 997000000 / 10997000 = 90`,
    one floor division and no other rounding. Checked by the kernel. -/
def sampleSuccessor : VaultState :=
  ⟨1, 2, 3, 1, 1100, 910, ⟨10, 20⟩, 4, 5, [], none, 42, 7, 8, 9⟩

theorem sample_derives :
    deriveExpected sampleParent 42 (.market sampleOp) = .derived sampleSuccessor := by
  decide

/-- The derivation is not degenerate: it moves value, and the successor really
    does differ from its parent. -/
theorem sample_is_not_a_noop : sampleSuccessor ≠ sampleParent := by decide

theorem sample_correspondence_accepts :
    correspondence sampleParent 42 (.market sampleOp) sampleSuccessor = (.valid, none) := by
  decide

/-- **HEADLINE TEETH.** A successor differing ONLY in the preserved field
    `r_o` is rejected. Under the pre-C3 implementation this successor is
    accepted, because `vault_state_composition.rs:572` discards the declared
    successor and folds its own derivation instead — nothing ever compares
    them. -/
theorem preserved_field_mutation_is_rejected :
    correspondence sampleParent 42 (.market sampleOp)
      { sampleSuccessor with ownerAuthority := 99 }
    = (.invalid, some .correspondenceMismatch) := by
  decide

/-- **TEETH — encumbrance introduction.** 2c-C3 ruling F forbids introducing a
    claim. Because beta's `E` is always empty, no beta-shaped test can exercise
    this; the control has to be stated at the model level or it is not tested
    anywhere. -/
theorem encumbrance_introduction_is_rejected :
    correspondence sampleParent 42 (.market sampleOp)
      { sampleSuccessor with encumbrances := [7] }
    = (.invalid, some .correspondenceMismatch) := by
  decide

/-- **TEETH — budget introduction.** Likewise for `β`: a successor that
    materializes a budget the parent did not carry is rejected, because the
    presence marker is part of the compared bytes. -/
theorem budget_introduction_is_rejected :
    correspondence sampleParent 42 (.market sampleOp)
      { sampleSuccessor with beta := some 5 }
    = (.invalid, some .correspondenceMismatch) := by
  decide

/-- **TEETH — the tails do not cross.** The market successor is not accepted
    when the operation is an owner close. -/
theorem market_successor_not_accepted_under_close :
    correspondence sampleParent 42 .ownerClose sampleSuccessor
    = (.invalid, some .correspondenceMismatch) := by
  decide

/-- …and the close derives a retired successor from the same parent. -/
theorem sample_close_retires :
    deriveExpected sampleParent 42 .ownerClose
      = .derived ⟨1, 2, 3, 1, 0, 0, ⟨10, 20⟩, 4, 5, [], none, 42, 7, 8, 9⟩ := by
  decide

-- ============================================================
-- The C3 input contract (2c-C3 ruling J)
--
-- Typed prerequisite RESULTS, not success-only facts. A component that owns
-- INVALID / INCOMPLETE / SAFETY_VIOLATION cannot be handed only established
-- successes; it would be blind to the outcomes it classifies.
-- ============================================================

inductive ParentAuth where
  | established (v : VaultState) (cn : Nat)
  | invalid (r : Reason)
  | incomplete (r : Reason)
  deriving Repr, DecidableEq

inductive AuthorityResolution where
  | resolved (provenAk networkId : Nat)
  | invalid (r : Reason)
  | incomplete (r : Reason)
  deriving Repr, DecidableEq

/-- The DLV parent-binding observation, consumed UNCHANGED. C3 assigns its
    normative meaning; it never redefines it.

    NOTE -- this is `dsm::dlv::binding_observation::BindingObservation`, which
    has FIVE arms. It is NOT the four-valued `CellObservation` of the economic
    register (`dsm::economic::cell_observation`), and an earlier draft of the C3
    input contract named that one by mistake. The two are different types over
    different keys, and the arm that only the binding observation has --
    `undetermined` -- is precisely the one its module header calls easy to get
    backwards. -/
inductive BindingObservation where
  | free
  | boundFinal (chosen : Nat)
  | conflict (distinct : Nat)
  | undetermined (attributed : Nat)
  | unavailable (attributed required : Nat)
  deriving Repr, DecidableEq

/-- Ruling J's `economic_facts` input. An earlier draft of this model omitted
    it, so a present-but-invalid realization evidence had no arm to land in. -/
inductive EconomicFacts where
  | established
  | invalid (r : Reason)
  | incomplete (r : Reason)
  deriving Repr, DecidableEq

structure C3Input where
  parentAuth    : ParentAuth
  authority     : AuthorityResolution
  binding       : BindingObservation
  operation     : Operation
  economicFacts : EconomicFacts
  settlerKey    : Nat
  supplied      : VaultState
  deriving Repr, DecidableEq

/-- Every branch carries a (class, reason). No catch-all, no error-to-absence. -/
def classify (i : C3Input) : Cls × Option Reason :=
  match i.parentAuth with
  | .invalid r    => (.invalid, some r)
  | .incomplete r => (.incomplete, some r)
  | .established v cn =>
    match i.authority with
    | .invalid r    => (.invalid, some r)
    | .incomplete r => (.incomplete, some r)
    | .resolved ak _ =>
      -- Ruling I: the embedded settler key is a CORRESPONDENCE CLAIM checked
      -- against the externally resolved authority, never its own source.
      if i.settlerKey ≠ ak then (.invalid, some .settlerKeyMismatch)
      else match i.binding with
        -- A quorum of members each explicitly hold NOTHING at this key. That IS
        -- evidence, and it says this settle never won exclusivity over the
        -- parent it names -- so it is decidably false, not unlearned.
        | .free            => (.invalid, some .noBindingEstablished)
        | .conflict _      => (.safetyViolation, some .duplicateBindingFinality)
        -- THE ARM THAT IS EASY TO GET BACKWARDS. A promise in flight, or a
        -- chosen value sitting behind a down member, lands here: two quorums
        -- intersect, but one READ need not see the intersection. Reading it as
        -- `free` composes past a live bind; reading it as a forgery makes every
        -- concurrent settle permanently invalid. It is retryable evidence.
        | .undetermined _  => (.incomplete, some .bindingUndetermined)
        | .unavailable _ _ => (.incomplete, some .bindingEvidenceUnavailable)
        -- Ruling J's economic_facts arm sits between binding and the
        -- successor comparison: evidence that is present and wrong is INVALID,
        -- evidence that could not be obtained is INCOMPLETE, and only
        -- established facts reach the derivation.
        | .boundFinal _    =>
          match i.economicFacts with
          | .invalid r     => (.invalid, some r)
          | .incomplete r  => (.incomplete, some r)
          | .established   => correspondence v cn i.operation i.supplied

/-- What C3 proves. -/
def ValidDlvSuccessorCore (i : C3Input) : Prop := classify i = (.valid, none)

/-- The complete protocol predicate. `TokenPolicyValid` is a PARAMETER because
    C3 does not discharge it (ruling H). -/
def ValidDlvSuccessor (i : C3Input) (TokenPolicyValid : C3Input → Prop) : Prop :=
  ValidDlvSuccessorCore i ∧ TokenPolicyValid i

-- ============================================================
-- What the input contract buys
-- ============================================================

/-- Neither `unavailable` nor `undetermined` can ever produce a valid
    successor. Both are `INCOMPLETE` rather than `INVALID` — not learning a fact
    is not learning its negation (Req 6.25). -/
theorem unavailable_is_incomplete_never_valid (i : C3Input) (a r : Nat)
    (h : i.binding = .unavailable a r) :
    classify i = (.valid, none) → False := by
  unfold classify
  split
  · intro hc; exact absurd hc (by simp)
  · intro hc; exact absurd hc (by simp)
  · split
    · intro hc; exact absurd hc (by simp)
    · intro hc; exact absurd hc (by simp)
    · split
      · intro hc; exact absurd hc (by simp)
      · rw [h]; intro hc; exact absurd hc (by simp)

/-- **The arm that is easy to get backwards.** `undetermined` is retryable
    evidence: a value already chosen behind a down member lands here, because
    two quorums intersect but one READ need not see the intersection. Mapping it
    to `INVALID` would make every concurrent settle permanently invalid; mapping
    it to `free` would compose past a live bind. It is neither. -/
theorem undetermined_is_incomplete_never_valid_never_invalid
    (i : C3Input) (v : VaultState) (cn ak nid a : Nat)
    (hp : i.parentAuth = .established v cn)
    (ha : i.authority = .resolved ak nid)
    (hk : i.settlerKey = ak)
    (hb : i.binding = .undetermined a) :
    classify i = (.incomplete, some .bindingUndetermined) := by
  unfold classify
  rw [hp, ha, hb, hk]
  simp

/-- `free` is the opposite case and is deliberately NOT incomplete: a quorum of
    authenticated explicit absences is positive evidence that nothing is chosen,
    so the successor decidably never won exclusivity over the parent it names. -/
theorem free_is_invalid_not_incomplete
    (i : C3Input) (v : VaultState) (cn ak nid : Nat)
    (hp : i.parentAuth = .established v cn)
    (ha : i.authority = .resolved ak nid)
    (hk : i.settlerKey = ak)
    (hb : i.binding = .free) :
    classify i = (.invalid, some .noBindingEstablished) := by
  unfold classify
  rw [hp, ha, hb, hk]
  simp

/-- A `Conflict` is a SAFETY_VIOLATION, never a tie to be broken and never a
    plain rejection. Req 6.3 forbids tie-breaking because either continuation
    may already have been relied upon. -/
theorem conflict_is_a_safety_violation
    (i : C3Input) (v : VaultState) (cn ak nid d : Nat)
    (hp : i.parentAuth = .established v cn)
    (ha : i.authority = .resolved ak nid)
    (hk : i.settlerKey = ak)
    (hb : i.binding = .conflict d) :
    classify i = (.safetyViolation, some .duplicateBindingFinality) := by
  unfold classify
  rw [hp, ha, hb, hk]
  simp

/-- Layer 2 REFINES layer 1. The five binding arms collapse to three classes,
    and the two that share `INCOMPLETE` remain distinguishable by reason.
    Collapsing them would lose the distinction between "the bind is mid-flight"
    and "I could not reach a quorum to find out" — and collapsing either into
    `free` would lose the distinction between both and "nothing is bound". -/
theorem the_two_incomplete_reasons_are_distinct :
    Reason.bindingUndetermined ≠ Reason.bindingEvidenceUnavailable := by decide

theorem no_binding_is_distinct_from_both_incomplete_reasons :
    Reason.noBindingEstablished ≠ Reason.bindingUndetermined ∧
    Reason.noBindingEstablished ≠ Reason.bindingEvidenceUnavailable := by decide

/-- The sample transition, carried through the full input contract. -/
def sampleInput : C3Input :=
  { parentAuth := .established sampleParent 42
    authority  := .resolved 77 1
    binding    := .boundFinal 0
    operation  := .market sampleOp
    economicFacts := .established
    settlerKey := 77
    supplied   := sampleSuccessor }

theorem sample_input_is_core_valid : ValidDlvSuccessorCore sampleInput := by
  unfold ValidDlvSuccessorCore; decide

/-- **TEETH — settler correspondence.** The same transition with a settler key
    that does not match the externally resolved authority is rejected. The
    embedded field is a claim, not a source. -/
theorem settler_key_mismatch_is_rejected :
    classify { sampleInput with settlerKey := 78 }
      = (.invalid, some .settlerKeyMismatch) := by
  decide

/-- **TEETH — an unavailable cell does not become an absent one.** Same
    transition, evidence unobtainable: `INCOMPLETE`, never `INVALID`, and never
    silently valid. -/
theorem unavailable_binding_is_incomplete :
    classify { sampleInput with binding := .unavailable 1 2 }
      = (.incomplete, some .bindingEvidenceUnavailable) := by
  decide

/-- …and the mid-flight arm is a THIRD outcome, distinct from both. -/
theorem undetermined_binding_is_its_own_outcome :
    classify { sampleInput with binding := .undetermined 2 }
      = (.incomplete, some .bindingUndetermined) := by
  decide

theorem free_binding_is_invalid :
    classify { sampleInput with binding := .free }
      = (.invalid, some .noBindingEstablished) := by
  decide

/-- **TEETH — a forged receipt is INVALID, never absence, never a safety
    violation.** Present-but-failing realization evidence refuses the fold
    with its own reason. Under the shipped code this exact input became
    `Absent` and composition returned `Ok(...)`. -/
theorem forged_realization_evidence_is_invalid_not_absent :
    classify { sampleInput with economicFacts := .invalid .realizationEvidenceInvalid }
      = (.invalid, some .realizationEvidenceInvalid) := by
  decide

/-- …and evidence that could not be obtained is a DIFFERENT class from
    evidence that was obtained and is wrong. -/
theorem unobtainable_realization_evidence_is_incomplete :
    classify { sampleInput with economicFacts := .incomplete .bindingEvidenceUnavailable }
      = (.incomplete, some .bindingEvidenceUnavailable) := by
  decide

/-- **RULING H, formalized.** `ValidDlvSuccessorCore` does NOT discharge token
    policy: there is an input that satisfies the core predicate while the
    complete predicate fails. C3's closure is therefore not DLV succession's
    closure, and the module cannot be read as claiming otherwise. -/
theorem core_does_not_discharge_token_policy :
    ∃ (i : C3Input) (T : C3Input → Prop),
      ValidDlvSuccessorCore i ∧ ¬ ValidDlvSuccessor i T := by
  refine ⟨sampleInput, fun _ => False, sample_input_is_core_valid, ?_⟩
  rintro ⟨_, hfalse⟩
  exact hfalse

-- ============================================================
-- Axiom report (2c-C3: per-theorem, never a blanket claim)
-- ============================================================

#print axioms canonVault_injective
#print axioms canonVaultNoCount_collides
#print axioms direction_refutes_equal_commitments
#print axioms market_never_derives_retired
#print axioms close_derives_retired
#print axioms correspondence_valid_pins_successor
#print axioms correspondence_implies_preserved_fields
#print axioms correspondence_implies_mutated_fields
#print axioms correspondence_rejects_any_other_successor
#print axioms preserved_field_mutation_is_rejected
#print axioms encumbrance_introduction_is_rejected
#print axioms market_successor_not_accepted_under_close
#print axioms unavailable_is_incomplete_never_valid
#print axioms conflict_is_a_safety_violation
#print axioms undetermined_is_incomplete_never_valid_never_invalid
#print axioms free_is_invalid_not_incomplete
#print axioms core_does_not_discharge_token_policy
#print axioms invalid_operation_never_derives
#print axioms invalid_operation_propagates_its_reason
#print axioms forged_realization_evidence_is_invalid_not_absent
#print axioms unobtainable_realization_evidence_is_incomplete
