/-
  The admitted terminal close — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-G's G4 ruling over one vault: a close is admitted
  at exactly the caught-up composed frontier, or it writes nothing.

    - CAUGHT UP        a close requires the owner's admitted generation to be
                       the composed frontier: no close from a stale baseline
    - EXACT PARENT     a close consumes exactly the frontier generation: no
                       skipped generation, no already-consumed parent
    - EXACT RESERVES   it drains exactly the frontier's reserves
    - NOT HELD         a parent another candidate holds unrealized — an
                       uncertified predecessor — refuses the close
    - NOTHING WRITTEN  a refused close leaves the vault exactly as it was
    - NEVER ERASES     the realized history survives a close as a prefix
    - TERMINAL         a second close is refused
    - CATCH-UP FIRST   caught up to a free frontier, the exact close is
                       admitted

  The model. `history` is the composed vault's reserves at each generation,
  oldest first; its last entry is the frontier's. `applied` is the owner's
  admitted generation — where `R_econ`'s reserve leaves stand. `binding` is the
  frontier's binding. The close's two checks are the implementation's two
  layers: `planOk` is `close_plan` (every fact read off the composition) and
  `admitOk` is the admission's write set (the reserve leaves at exactly the
  parent generation).

  What this module does NOT claim:

    * Close authority, QuorumBind and the accepted-successor rules. Unchanged
      by G4, and modelled where they live (DSMValidDlvSuccessor,
      DSMSettlementCompletion); here the close is already authorized and bound.
    * Catch-up itself. DSMOwnerCatchUp owns it; here it is `applied := frontier`.
    * Reserves as two legs. One number per generation carries the argument.

  Mutation controls, executed rather than asserted — the kernel proving the
  NEGATION of a named sample theorem:

    1. the admission's caught-up precondition dropped
         -> `a_close_of_an_uncaught_frontier_is_refused` is proved FALSE
    2. the held-parent check dropped
         -> `a_held_parent_refuses_the_close_sample` is proved FALSE
    3. any parent at or below the frontier accepted, at its own reserves
         -> `a_close_of_the_consumed_generation_is_refused` is proved FALSE

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMAdmittedClose

inductive Binding where
  | free
  | ours
  | heldByOther
  deriving DecidableEq, Repr

structure Vault where
  /-- The composed reserves at each generation, oldest first. -/
  history : List Nat
  /-- The owner's admitted generation. -/
  applied : Nat
  /-- The frontier's binding. -/
  binding : Binding
  closed : Bool
  deriving DecidableEq, Repr

structure Close where
  parent : Nat
  amount : Nat
  deriving DecidableEq, Repr

def frontier (v : Vault) : Nat := v.history.length - 1

def frontierReserves (v : Vault) : Nat := v.history.getLastD 0

/-- `close_plan`: the parent is the frontier, nobody else holds it, and the
amount is the frontier's. -/
def planOk (v : Vault) (c : Close) : Bool :=
  !v.closed && c.parent == frontier v && v.binding != .heldByOther &&
    c.amount == frontierReserves v

/-- The admission: `R_econ` holds exactly the parent generation. -/
def admitOk (v : Vault) (c : Close) : Bool := v.applied == c.parent

def closeOk (v : Vault) (c : Close) : Bool := planOk v c && admitOk v c

/-- The one close commit: a terminal zero generation appended, or nothing. -/
def commitClose (v : Vault) (c : Close) : Vault :=
  if closeOk v c then
    { v with history := v.history ++ [0], applied := c.parent + 1, closed := true }
  else v

-- ─────────────────────────────────────────────────────────────────────────────
-- Lemmas
-- ─────────────────────────────────────────────────────────────────────────────

theorem take_length_append (l₁ l₂ : List Nat) : (l₁ ++ l₂).take l₁.length = l₁ := by
  induction l₁ with
  | nil => simp
  | cons a t ih => simp [ih]

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- NOTHING WRITTEN: a refused close leaves the vault exactly as it was. -/
theorem a_refused_close_writes_nothing (v : Vault) (c : Close)
    (h : closeOk v c = false) : commitClose v c = v := by
  simp [commitClose, h]

/-- CAUGHT UP: an admitted close means the owner stood at the frontier. -/
theorem a_close_requires_the_owner_caught_up (v : Vault) (c : Close)
    (h : closeOk v c = true) : v.applied = frontier v := by
  simp [closeOk, planOk, admitOk] at h
  omega

/-- EXACT PARENT: no skipped generation, no already-consumed parent. -/
theorem a_close_consumes_exactly_the_frontier (v : Vault) (c : Close)
    (h : closeOk v c = true) : c.parent = frontier v := by
  simp [closeOk, planOk] at h
  exact h.1.1.1.2

/-- EXACT RESERVES. -/
theorem a_close_drains_exactly_the_frontier_reserves (v : Vault) (c : Close)
    (h : closeOk v c = true) : c.amount = frontierReserves v := by
  simp [closeOk, planOk] at h
  exact h.1.2

/-- NOT HELD: an uncertified predecessor refuses the close. -/
theorem a_held_parent_refuses_the_close (v : Vault) (c : Close)
    (h : v.binding = .heldByOther) : closeOk v c = false := by
  simp [closeOk, planOk, h]

/-- NEVER ERASES: the realized history survives a close as a prefix. -/
theorem a_close_never_erases_realized_history (v : Vault) (c : Close) :
    (commitClose v c).history.take v.history.length = v.history := by
  unfold commitClose
  split
  · exact take_length_append v.history [0]
  · simp

/-- TERMINAL: once a close is admitted, no further close is. -/
theorem a_second_close_is_refused (v : Vault) (c c' : Close)
    (h : closeOk v c = true) : closeOk (commitClose v c) c' = false := by
  have hc : commitClose v c =
      { v with history := v.history ++ [0], applied := c.parent + 1, closed := true } := by
    unfold commitClose
    rw [if_pos h]
  rw [hc]
  simp [closeOk, planOk]

/-- CATCH-UP FIRST: caught up to a free frontier, the exact close is admitted. -/
theorem a_caught_up_exact_close_is_admitted (v : Vault)
    (hc : v.closed = false) (hb : v.binding ≠ .heldByOther) :
    closeOk { v with applied := frontier v } ⟨frontier v, frontierReserves v⟩ = true := by
  simp [closeOk, planOk, admitOk, frontier, frontierReserves, hc, hb]

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

/-- Born at 100, moved to 120 by one realized market generation; the owner's
admitted generation is still 0. -/
def traded : Vault := ⟨[100, 120], 0, .free, false⟩

theorem a_close_of_an_uncaught_frontier_is_refused :
    closeOk traded ⟨1, 120⟩ = false := by decide

theorem a_close_of_the_consumed_generation_is_refused :
    closeOk traded ⟨0, 100⟩ = false := by decide

theorem a_held_parent_refuses_the_close_sample :
    closeOk { traded with applied := 1, binding := .heldByOther } ⟨1, 120⟩ = false := by
  decide

theorem a_caught_up_close_is_admitted_sample :
    closeOk { traded with applied := 1 } ⟨1, 120⟩ = true := by decide

theorem a_skipped_generation_is_refused :
    closeOk { traded with applied := 2 } ⟨2, 0⟩ = false := by decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms a_refused_close_writes_nothing
#print axioms a_close_requires_the_owner_caught_up
#print axioms a_close_consumes_exactly_the_frontier
#print axioms a_close_drains_exactly_the_frontier_reserves
#print axioms a_held_parent_refuses_the_close
#print axioms a_close_never_erases_realized_history
#print axioms a_second_close_is_refused
#print axioms a_caught_up_exact_close_is_admitted

end DSMAdmittedClose
