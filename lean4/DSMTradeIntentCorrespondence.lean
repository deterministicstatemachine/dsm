/-
  Trade-intent correspondence — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks the satisfaction predicate amendment 2c-E §6 freezes, for the
  schema-2 exact-output `TradeIntent`:

    - SHAPE        the intent is the six SIGNED members. The four schema-1
                   members `min_out`, `max_fee`, `max_fanout` and `k` are not
                   modelled anywhere in this file, because they no longer
                   exist: RouteCommit v2 deleted the model they belonged to
    - AGREE        every member is checked against the canonical RouteCommit
                   the trader actually signed, under a verified signature
    - INDEPENDENT  SAT.5 checks `exact_out` against the market policy evaluated
                   on the AUTHENTICATED `V_n`, never against the route's own
                   account of itself
    - TEETH        a disagreement is REFUSED, one conjunct at a time. Each of
                   the six is separately necessary
    - NOT VACUOUS  the forbidden shape -- SAT.5's operand taken from the route
                   instead of the authenticated state -- ACCEPTS a trade this
                   predicate refuses. That is the whole reason SAT.5 is worded
                   the way it is, and it is proved here rather than asserted

  What this module does NOT claim:

    * It is a model of the NORMATIVE objects, not a refinement proof from the
      shipped Rust. Digests and amounts are `Nat`; equality of `Nat` stands for
      equality of canonical bytes, and nothing here claims the Rust computes
      these values.
    * The market policy is a PARAMETER. This module does not fix the
      constant-product rule, its rounding, or its admissibility conditions; it
      proves the SHAPE of the correspondence for any policy. `samplePolicy`
      exists only to make the counterexamples closed terms the kernel can
      decide.
    * Signature verification is a `Bool` here. That `sigma` verifies under the
      authority resolver's proven key is 2c-E §2's obligation and is not
      modelled.
    * `G1`-`G4` (2c-B's grammar and chain-tip conjuncts) are NOT modelled. They
      gate the bundle's structural validity and arrive with the 5c-2 producer.
    * Nothing here lifts the market emission refusal or bears on realization,
      which stays unreachable until 2c-D.

  Mutation controls, executed rather than asserted, and reported from the
  kernel's actual output:

    1. SAT.5's operand replaced by the route's own claim
         (`i.exactOut == policy v i.amountIn` -> `i.exactOut == r.exactOut`)
         -> TWO named theorems are proved FALSE by the kernel, not merely
            broken: `a_forged_output_is_refused` ("Tactic `decide` proved that
            the proposition ... is false") and, with it,
            `the_predicate_is_not_the_tautological_one` -- the two forms having
            become the same predicate, so their inequality is refutable. An
            intent whose output the authenticated state does not reproduce now
            passes, because it is compared against the route that asserted it.
            `a_disagreeing_output_never_satisfies` additionally loses its proof
            (unsolved goals), since `policy` stops being consulted at all.

    2. SAT.6 removed from the conjunction (`i.feeBps == v.feeBps` dropped)
         -> `a_fee_that_is_not_the_vaults_is_refused` is proved FALSE by the
            kernel. The trader's signed rate would then stand alone, with the
            vault's own fee policy -- the authority -- unconsulted.

  Both mutations were reverted; this file is the unmutated module.

  Per-theorem axiom report (`#print axioms`), so "sorry-free" is not the only
  claim being made:

    a_forged_output_is_refused                  no axioms
    the_tautological_form_accepts_the_forgery   no axioms
    the_predicate_is_not_the_tautological_one   no axioms
    a_fee_that_is_not_the_vaults_is_refused     no axioms
    the_honest_case_satisfies                   no axioms
    a_disagreeing_output_never_satisfies        propext, Quot.sound

  The counterexamples are closed `decide` terms and carry nothing. Only the
  general theorem reaches `simp`, and it takes propositional extensionality and
  quotient soundness -- the two standard Lean axioms, neither of which is
  `sorryAx`. `decide` is used throughout in preference to `native_decide`,
  which would add `Lean.ofReduceBool` and `Lean.trustCompiler` and move the
  proof out of the kernel.
-/

namespace DSMTradeIntent

/-- Digests and amounts alike are `Nat`. -/
abbrev D := Nat

/-- `0x000B` schema 2 (2c-E §4): the six members the trader signs.

    There is deliberately no `minOut`, `maxFee`, `maxHops`, `maxFanout` or `k`.
    Four of them had no source on the wire at all, and a bound read out of the
    intent it bounds is not a bound. -/
structure Intent where
  tokenIn  : D
  amountIn : Nat
  tokenOut : D
  exactOut : Nat
  feeBps   : Nat
  nonce    : D
deriving DecidableEq, Repr

/-- The canonical `RouteCommit` (version 2) the trader signs with its signature
    zeroed. `sigValid` stands for that signature verifying. -/
structure SignedRoute where
  tokenIn  : D
  amountIn : Nat
  tokenOut : D
  exactOut : Nat
  feeBps   : Nat
  nonce    : D
  legCount : Nat
  sigValid : Bool
deriving DecidableEq, Repr

/-- The AUTHENTICATED `V_n` that `c_n` names. The fee here is the vault's own
    policy, which is the authority the settle is checked against. -/
structure VaultState where
  feeBps     : Nat
  reserveIn  : Nat
  reserveOut : Nat
deriving DecidableEq, Repr

/-- The legs actually carried in `B.selected_route`. -/
structure Route where
  legCount : Nat
deriving DecidableEq, Repr

/-- SAT.1-SAT.6 of 2c-E §6.

    `policy` is the market rule evaluated on the AUTHENTICATED state. Passing it
    as a parameter is the point: SAT.5's operand must come from somewhere the
    route cannot choose. -/
def satisfies (policy : VaultState → Nat → Nat)
    (i : Intent) (r : SignedRoute) (v : VaultState) (rt : Route) : Bool :=
  r.sigValid                                -- SAT.2
    && (i.tokenIn == r.tokenIn)             -- SAT.3
    && (i.tokenOut == r.tokenOut)
    && (i.amountIn == r.amountIn)
    && (i.exactOut == r.exactOut)
    && (i.feeBps == r.feeBps)
    && (i.nonce == r.nonce)
    && (rt.legCount == r.legCount)          -- SAT.4
    && (i.exactOut == policy v i.amountIn)  -- SAT.5  the independent fact
    && (i.feeBps == v.feeBps)               -- SAT.6

/-- THE FORBIDDEN SHAPE, modelled so it can be refuted rather than merely
    warned against: SAT.5's operand taken from the route's own claim. Every
    other conjunct is identical. -/
def satisfiesTautological
    (i : Intent) (r : SignedRoute) (v : VaultState) (rt : Route) : Bool :=
  r.sigValid
    && (i.tokenIn == r.tokenIn)
    && (i.tokenOut == r.tokenOut)
    && (i.amountIn == r.amountIn)
    && (i.exactOut == r.exactOut)
    && (i.feeBps == r.feeBps)
    && (i.nonce == r.nonce)
    && (rt.legCount == r.legCount)
    && (i.exactOut == r.exactOut)           -- the route asserting itself
    && (i.feeBps == v.feeBps)

/-- A closed, decidable stand-in for the market rule. Its shape is irrelevant;
    what matters is that it reads the AUTHENTICATED state and not the route. -/
def samplePolicy : VaultState → Nat → Nat :=
  fun v a => v.reserveOut * a / (v.reserveIn + a)

/-- The authenticated vault: 30 bps, reserves 1000 / 500. -/
def vn : VaultState := { feeBps := 30, reserveIn := 1000, reserveOut := 500 }

/-- `samplePolicy vn 100 = 500 * 100 / 1100 = 45`. -/
theorem the_authenticated_output_is_fortyfive : samplePolicy vn 100 = 45 := by decide

def honestRoute : SignedRoute :=
  { tokenIn := 1, amountIn := 100, tokenOut := 2, exactOut := 45,
    feeBps := 30, nonce := 7, legCount := 1, sigValid := true }

def honestIntent : Intent :=
  { tokenIn := 1, amountIn := 100, tokenOut := 2, exactOut := 45,
    feeBps := 30, nonce := 7 }

def oneLeg : Route := { legCount := 1 }

theorem the_honest_case_satisfies :
    satisfies samplePolicy honestIntent honestRoute vn oneLeg = true := by decide

/-- TEETH, and the load-bearing one. The trader signs an output the
    authenticated state does not reproduce -- the route and the intent agree
    with each other perfectly -- and it is REFUSED. -/
def forgedIntent : Intent := { honestIntent with exactOut := 400 }
def forgedRoute : SignedRoute := { honestRoute with exactOut := 400 }

theorem a_forged_output_is_refused :
    satisfies samplePolicy forgedIntent forgedRoute vn oneLeg = false := by decide

/-- NOT VACUOUS. The same forgery PASSES the tautological form. The two
    predicates are therefore different predicates, and SAT.5's wording is doing
    work rather than restating SAT.3. -/
theorem the_tautological_form_accepts_the_forgery :
    satisfiesTautological forgedIntent forgedRoute vn oneLeg = true := by decide

theorem the_predicate_is_not_the_tautological_one :
    satisfies samplePolicy forgedIntent forgedRoute vn oneLeg
      ≠ satisfiesTautological forgedIntent forgedRoute vn oneLeg := by decide

/-- Each remaining conjunct, separately necessary. -/
theorem an_unsigned_route_is_refused :
    satisfies samplePolicy honestIntent { honestRoute with sigValid := false } vn oneLeg
      = false := by decide

theorem an_intent_naming_another_input_token_is_refused :
    satisfies samplePolicy { honestIntent with tokenIn := 99 } honestRoute vn oneLeg
      = false := by decide

theorem an_intent_naming_another_output_token_is_refused :
    satisfies samplePolicy { honestIntent with tokenOut := 99 } honestRoute vn oneLeg
      = false := by decide

theorem an_amount_the_trader_did_not_sign_is_refused :
    satisfies samplePolicy { honestIntent with amountIn := 101 } honestRoute vn oneLeg
      = false := by decide

theorem a_nonce_the_trader_did_not_sign_is_refused :
    satisfies samplePolicy { honestIntent with nonce := 8 } honestRoute vn oneLeg
      = false := by decide

/-- SAT.4. The legs must correspond to the SIGNED hops; this is the check that
    replaced schema 1's `max_hops`, and it reads a signed fact rather than a
    bound carried in the intent. -/
theorem a_leg_count_that_is_not_the_signed_one_is_refused :
    satisfies samplePolicy honestIntent honestRoute vn { legCount := 2 }
      = false := by decide

/-- SAT.6. The vault's fee is the authority; the signed rate is the trader's
    acknowledgement of it, and the two must agree. -/
theorem a_fee_that_is_not_the_vaults_is_refused :
    satisfies samplePolicy { honestIntent with feeBps := 25 }
      { honestRoute with feeBps := 25 } vn oneLeg = false := by decide

/-- The general statement behind the counterexamples: whenever the signed
    output disagrees with the policy on the authenticated state, the predicate
    is false — for ANY policy, not merely the sample. -/
theorem a_disagreeing_output_never_satisfies
    (policy : VaultState → Nat → Nat) (i : Intent) (r : SignedRoute)
    (v : VaultState) (rt : Route)
    (h : i.exactOut ≠ policy v i.amountIn) :
    satisfies policy i r v rt = false := by
  unfold satisfies
  have : (i.exactOut == policy v i.amountIn) = false := by
    simp [beq_eq_false_iff_ne, h]
  simp [this]

end DSMTradeIntent
