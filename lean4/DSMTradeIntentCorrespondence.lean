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

-- ─────────────────────────────────────────────────────────────────────────────
-- Amendment 2c-H H11, SAT-R: a route of N legs, each certified at its OWN vault
--
-- SAT.5-R: at vault k, the leg's input re-simulated against vault k's
-- AUTHENTICATED state reproduces the leg's output exactly. SAT.6-R: each leg is
-- priced at its vault's rate, and the intent's rate is the sum of the legs'.
-- The intent's exact output is the LAST leg's; RC.2 carries every intermediate
-- output into the next leg (DSMRouteConservation).
--
-- Mutation control, executed rather than asserted: the per-vault conjunct
-- (`legs.all legSatisfies`) dropped from `routeSatisfies`
--   -> `a_leg_its_own_vault_does_not_reproduce_is_refused` is proved FALSE by
--      the kernel ("Tactic `decide` proved that the proposition ... is false"),
--      and `every_vault_reproduces_its_own_leg` loses its proof (the
--      conjunction it projects no longer exists). Reverted; this is the
--      unmutated module.
-- ─────────────────────────────────────────────────────────────────────────────

/-- One route leg as SAT-R reads it at its vault. -/
structure RouteLeg where
  amountIn  : Nat
  amountOut : Nat
  feeBps    : Nat
deriving DecidableEq, Repr

/-- SAT.5-R and the per-vault half of SAT.6-R, at ONE vault. -/
def legSatisfies (policy : VaultState → Nat → Nat) (leg : RouteLeg) (v : VaultState) : Bool :=
  (leg.amountOut == policy v leg.amountIn) && (leg.feeBps == v.feeBps)

/-- SAT-R route-wide: every vault certifies its own leg (2c-H H13), the
    intent's exact output is the last leg's, and its rate is the legs' sum. -/
def routeSatisfies (policy : VaultState → Nat → Nat) (i : Intent)
    (legs : List (RouteLeg × VaultState)) : Bool :=
  legs.all (fun p => legSatisfies policy p.1 p.2)
    && (match legs.getLast? with
        | some p => i.exactOut == p.1.amountOut
        | none => false)
    && (i.feeBps == (legs.map (fun p => p.1.feeBps)).foldl (· + ·) 0)

/-- For ANY route: a satisfied intent has every vault reproducing its own leg
    from its own authenticated state. No vault's certification stands in for
    another's. -/
theorem every_vault_reproduces_its_own_leg
    (policy : VaultState → Nat → Nat) (i : Intent) (legs : List (RouteLeg × VaultState))
    (h : routeSatisfies policy i legs = true) :
    ∀ p ∈ legs, legSatisfies policy p.1 p.2 = true := by
  unfold routeSatisfies at h
  simp only [Bool.and_eq_true, List.all_eq_true] at h
  exact h.1.1

/-- Vault B: 30 bps, reserves 900 / 800. `samplePolicy vb 45 = 800 * 45 / 945 = 38`. -/
def vb : VaultState := { feeBps := 30, reserveIn := 900, reserveOut := 800 }

theorem the_second_vault_output_is_thirtyeight : samplePolicy vb 45 = 38 := by decide

def legA : RouteLeg := { amountIn := 100, amountOut := 45, feeBps := 30 }
def legB : RouteLeg := { amountIn := 45, amountOut := 38, feeBps := 30 }
def routeIntent : Intent :=
  { tokenIn := 1, amountIn := 100, tokenOut := 3, exactOut := 38, feeBps := 60, nonce := 7 }

theorem the_honest_route_satisfies :
    routeSatisfies samplePolicy routeIntent [(legA, vn), (legB, vb)] = true := by decide

/-- SAT.5-R at vault B alone. The intent and the forged leg agree with each
    other and vault A certifies — refused, because vault B's own state does not
    reproduce its leg. -/
theorem a_leg_its_own_vault_does_not_reproduce_is_refused :
    routeSatisfies samplePolicy { routeIntent with exactOut := 40 }
      [(legA, vn), ({ legB with amountOut := 40 }, vb)] = false := by decide

/-- SAT.6-R: the signed rate is the SUM of the legs' rates. -/
theorem a_rate_that_is_not_the_legs_sum_is_refused :
    routeSatisfies samplePolicy { routeIntent with feeBps := 30 }
      [(legA, vn), (legB, vb)] = false := by decide

/-- The exact output is the last leg's, never an intermediate one. -/
theorem an_intermediate_output_as_the_exact_output_is_refused :
    routeSatisfies samplePolicy { routeIntent with exactOut := 45 }
      [(legA, vn), (legB, vb)] = false := by decide

#print axioms every_vault_reproduces_its_own_leg
#print axioms the_honest_route_satisfies
#print axioms a_leg_its_own_vault_does_not_reproduce_is_refused
#print axioms a_rate_that_is_not_the_legs_sum_is_refused
#print axioms an_intermediate_output_as_the_exact_output_is_refused

end DSMTradeIntent
