/-
  Route conservation — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-H H8 (route conservation RC.1–RC.5) and the
  trader-side effect H3/H4 of a route-wide settle (`DlvRouteSettle`, grammar
  33), as `DeviceState::advance`'s conservation arm states it:

    - RC.1/RC.2   each leg hands its output asset and exact output to the next
                  leg's input
    - RC.3        the route does not return to its own input asset
    - RC.4        no leg converts an asset to itself or moves a zero amount
    - RC.5        no two legs consume the same vault state
    - ENDS        the trader's accepted movement is exactly two positional
                  deltas: the first leg's input debited, the last leg's output
                  credited. An intermediate asset is never a trader delta.

  What this module does NOT claim:

    * It is a model of the normative predicate, not a refinement proof from the
      shipped Rust. Assets, vaults and parent states are `Nat`; equality of
      `Nat` stands for equality of 32-byte commitments.
    * Pricing is not modelled. Whether each leg's output is what its vault's
      curve yields is SAT.5-R's (DSMTradeIntentCorrespondence), at that vault.
    * Binding, the write set and admission are not modelled.

  Mutation controls, executed rather than asserted, reported from the kernel's
  actual output:

    1. the chain check dropped from `conserves`
         -> `an_amount_chain_break_is_refused` and
            `an_asset_chain_break_is_refused` are proved FALSE
    2. the distinct-parent check dropped from `conserves`
         -> `a_vault_state_consumed_twice_is_refused` is proved FALSE

  Both mutations were reverted; this file is the unmutated module.
-/

namespace DSMRouteConservation

/-- One route leg as the signed operation states it. -/
structure Leg where
  parent    : Nat
  tokenIn   : Nat
  tokenOut  : Nat
  amountIn  : Nat
  amountOut : Nat
deriving DecidableEq, Repr

/-- RC.1 and RC.2 between every pair of consecutive legs. -/
def chained : List Leg → Bool
  | a :: b :: rest =>
      (a.tokenOut == b.tokenIn) && (a.amountOut == b.amountIn) && chained (b :: rest)
  | _ => true

/-- RC.4 for one leg. -/
def legOk (l : Leg) : Bool :=
  (l.tokenIn != l.tokenOut) && (l.amountIn != 0) && (l.amountOut != 0)

/-- RC.5: no parent state named twice. -/
def distinctParents : List Leg → Bool
  | [] => true
  | l :: rest => rest.all (fun r => r.parent != l.parent) && distinctParents rest

/-- RC.1–RC.5 over a route of at least two legs. -/
def conserves (legs : List Leg) : Bool :=
  match legs.head?, legs.getLast? with
  | some first, some last =>
      decide (2 ≤ legs.length) && chained legs && legs.all legOk
        && (first.tokenIn != last.tokenOut) && distinctParents legs
  | _, _ => false

/-- A trader balance delta: the asset, whether it is a debit, and the amount. -/
structure Delta where
  token  : Nat
  debit  : Bool
  amount : Nat
deriving DecidableEq, Repr

/-- The conservation arm: a conserving route, and exactly the two positional
    deltas at its ends. -/
def accepts (legs : List Leg) (ds : List Delta) : Bool :=
  match legs.head?, legs.getLast?, ds with
  | some f, some l, [d0, d1] =>
      conserves legs
        && (d0 == { token := f.tokenIn, debit := true, amount := f.amountIn })
        && (d1 == { token := l.tokenOut, debit := false, amount := l.amountOut })
  | _, _, _ => false

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- Whatever the route, an accepted movement is exactly two deltas: no third
    delta, and so no intermediate asset, can ride along. -/
theorem an_accepted_route_moves_exactly_two_balances
    (legs : List Leg) (ds : List Delta) (h : accepts legs ds = true) :
    ds.length = 2 := by
  unfold accepts at h
  split at h <;> simp_all

/-- An accepted route conserves. -/
theorem an_accepted_route_conserves
    (legs : List Leg) (ds : List Delta) (h : accepts legs ds = true) :
    conserves legs = true := by
  unfold accepts at h
  split at h <;> simp_all

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — `ERA(1) → MID(5) → SOFI(2)`, 1000 in, 453 between, 560 out
-- ─────────────────────────────────────────────────────────────────────────────

def l0 : Leg := { parent := 11, tokenIn := 1, tokenOut := 5, amountIn := 1000, amountOut := 453 }
def l1 : Leg := { parent := 12, tokenIn := 5, tokenOut := 2, amountIn := 453, amountOut := 560 }
def route : List Leg := [l0, l1]
def debitIn : Delta := { token := 1, debit := true, amount := 1000 }
def creditOut : Delta := { token := 2, debit := false, amount := 560 }

theorem the_honest_route_conserves : conserves route = true := by decide

theorem the_routes_ends_are_accepted : accepts route [debitIn, creditOut] = true := by decide

/-- ENDS: crediting the intermediate asset instead of the final output. -/
theorem an_intermediate_credit_is_refused :
    accepts route [debitIn, { token := 5, debit := false, amount := 453 }] = false := by decide

/-- ENDS: an intermediate delta riding along with the honest pair. -/
theorem an_intermediate_delta_riding_along_is_refused :
    accepts route [debitIn, { token := 5, debit := false, amount := 453 }, creditOut]
      = false := by decide

/-- ENDS: positional — the honest pair reordered. -/
theorem reordered_ends_are_refused : accepts route [creditOut, debitIn] = false := by decide

/-- RC.2 -/
theorem an_amount_chain_break_is_refused :
    conserves [l0, { l1 with amountIn := 454 }] = false := by decide

/-- RC.1 -/
theorem an_asset_chain_break_is_refused :
    conserves [l0, { l1 with tokenIn := 6 }] = false := by decide

/-- RC.3 -/
theorem a_route_back_to_its_input_is_refused :
    conserves [l0, { l1 with tokenOut := 1 }] = false := by decide

/-- RC.4 -/
theorem a_self_pair_is_refused :
    conserves [{ l0 with tokenOut := 1 }, { l1 with tokenIn := 1 }] = false := by decide

theorem a_zero_amount_is_refused :
    conserves [{ l0 with amountIn := 0 }, l1] = false := by decide

/-- RC.5 -/
theorem a_vault_state_consumed_twice_is_refused :
    conserves [l0, { l1 with parent := 11 }] = false := by decide

/-- A route settle names at least two legs. -/
theorem one_leg_is_not_a_route : conserves [l0] = false := by decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms an_accepted_route_moves_exactly_two_balances
#print axioms an_accepted_route_conserves
#print axioms the_honest_route_conserves
#print axioms the_routes_ends_are_accepted
#print axioms an_intermediate_credit_is_refused
#print axioms an_intermediate_delta_riding_along_is_refused
#print axioms reordered_ends_are_refused
#print axioms an_amount_chain_break_is_refused
#print axioms an_asset_chain_break_is_refused
#print axioms a_route_back_to_its_input_is_refused
#print axioms a_self_pair_is_refused
#print axioms a_zero_amount_is_refused
#print axioms a_vault_state_consumed_twice_is_refused
#print axioms one_leg_is_not_a_route

end DSMRouteConservation
