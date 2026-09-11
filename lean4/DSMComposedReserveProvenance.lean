/-
  Composed reserve provenance — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-D §14 D-g: the SoFi composed-state rule applied to
  the reserves a market settlement consumes.

      current composed DLV state = latest authenticated owner baseline
                                 + every later realized successor, in order

    - BASELINE     at the owner's backing generation the parent states exactly
                   the owner's reserves
    - COMPOSED     past it, the parent is exactly the last state of a history
                   that starts at the backing generation with the owner's
                   reserves and advances one linked generation at a time
    - LP ABSENT    parents one and two generations past the backing are
                   provenanced with no owner action in between
    - TEETH        each conjunct -- ends at the parent, consecutive
                   generations, parent links, baseline reserves, baseline not
                   past the parent -- is separately necessary
    - WELL-FOUNDED composition for provenance stops AT the target, so the
                   provenance of generation n never includes the state the
                   settlement consuming n produces

  What this module does NOT claim:

    * Certification. A history here is the composition walk's, and that the
      walk folds only certified successors is DSMAcceptedSuccessorWalk's and
      C2's. It is a hypothesis of this model, not a result of it.
    * Currency. That the parent is the CURRENT frontier is the binding
      register's exclusivity at `k(c_n)`, not this rule.
    * The commitment. `commitOf` is a model encoding; nothing here claims the
      Rust's `vault_state_commitment` computes it. Equality of `Nat` stands for
      equality of canonical bytes.

  Mutation controls, executed rather than asserted -- each run against this
  file, each producing the strongest available result, the kernel proving the
  NEGATION of a named sample theorem:

    1. `linked` dropped from `provenanced`
         -> `an_unlinked_state_is_refused` is proved FALSE
    2. the ends-at-the-parent conjunct (`h.getLast? == some parent`) dropped
         -> `a_history_that_stops_early_provenances_nothing` is proved FALSE
    3. the generation step dropped from `linkedStep`
         -> `a_leaping_generation_is_refused` is proved FALSE
    4. `composeUntil` no longer stopping at the target
         -> `composition_for_provenance_never_reaches_the_consuming_settlement`
            is proved FALSE

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMComposedReserveProvenance

/-- A digest. Equality of `Nat` stands for equality of canonical bytes. -/
abbrev D := Nat

/-- A DLV state, reduced to what the reserve rule reads. -/
structure VState where
  gen : Nat
  /-- `parent_state_commitment`: the commitment of the state this one follows. -/
  parent : D
  ra : Nat
  rb : Nat
  deriving DecidableEq, Repr

/-- A model commitment. Not the Rust's; see the module header. -/
def commitOf (s : VState) : D :=
  ((s.gen * 1009 + s.parent) * 1013 + s.ra) * 1019 + s.rb

/-- The owner's economic backing: both reserve legs at ONE generation. -/
structure Backing where
  gen : Nat
  ra : Nat
  rb : Nat
  deriving DecidableEq, Repr

/-- One composed step: the next generation, naming its predecessor as parent. -/
def linkedStep (prev next : VState) : Bool :=
  next.gen == prev.gen + 1 && next.parent == commitOf prev

/-- A history that advances one linked generation at a time. -/
def linked : List VState → Bool
  | [] => true
  | [_] => true
  | a :: b :: rest => linkedStep a b && linked (b :: rest)

/-- The history from the owner's backing generation on. -/
def fromBaseline (g : Nat) (h : List VState) : List VState :=
  h.dropWhile (fun s => s.gen != g)

/-- **The reserve-provenance rule** (`check_composed_reserve_provenance`). -/
def provenanced (b : Backing) (parent : VState) (history : Option (List VState)) : Bool :=
  if b.gen > parent.gen then false
  else if b.gen = parent.gen then parent.ra == b.ra && parent.rb == b.rb
  else
    match history with
    | none => false
    | some h =>
      match fromBaseline b.gen h with
      | [] => false
      | start :: rest =>
        start.ra == b.ra && start.rb == b.rb
          && linked (start :: rest)
          && h.getLast? == some parent

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- A backing past the parent never provenances it, whatever the history. -/
theorem a_backing_past_the_parent_never_provenances
    (b : Backing) (parent : VState) (history : Option (List VState))
    (h : b.gen > parent.gen) :
    provenanced b parent history = false := by
  simp [provenanced, h]

/-- Past the baseline, no history means no provenance. -/
theorem past_the_baseline_no_history_no_provenance
    (b : Backing) (parent : VState) (h : b.gen < parent.gen) :
    provenanced b parent none = false := by
  have h1 : ¬ b.gen > parent.gen := Nat.not_lt.mpr (Nat.le_of_lt h)
  have h2 : b.gen ≠ parent.gen := Nat.ne_of_lt h
  simp [provenanced, h1, h2]

/-- At the baseline the history is irrelevant: only the owner's reserves decide. -/
theorem at_the_baseline_only_the_backing_decides
    (b : Backing) (parent : VState) (h₁ h₂ : Option (List VState))
    (h : b.gen = parent.gen) :
    provenanced b parent h₁ = provenanced b parent h₂ := by
  simp [provenanced, h]

/-- **SOUNDNESS.** Past the baseline, an accepted parent is exactly the last
state of a linked history that starts at the backing generation with the
owner's reserves -- the composed state, and nothing else. -/
theorem provenanced_past_the_baseline_is_the_composed_state
    (b : Backing) (parent : VState) (h : List VState)
    (hlt : b.gen < parent.gen)
    (hp : provenanced b parent (some h) = true) :
    ∃ start rest,
      fromBaseline b.gen h = start :: rest
        ∧ start.ra = b.ra ∧ start.rb = b.rb
        ∧ linked (start :: rest) = true
        ∧ h.getLast? = some parent := by
  have h1 : ¬ b.gen > parent.gen := Nat.not_lt.mpr (Nat.le_of_lt hlt)
  have h2 : b.gen ≠ parent.gen := Nat.ne_of_lt hlt
  simp only [provenanced, if_neg h1, if_neg h2] at hp
  cases hfb : fromBaseline b.gen h with
  | nil =>
    rw [hfb] at hp
    simp at hp
  | cons start rest =>
    rw [hfb] at hp
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨start, rest, rfl, hp.1.1.1, hp.1.1.2, hp.1.2, hp.2⟩

-- ─────────────────────────────────────────────────────────────────────────────
-- Composition stops AT the target
-- ─────────────────────────────────────────────────────────────────────────────

/-- The walk, stopped AT the requested state (`compose_vault_history_until`):
the chain up to and including the first state committed as `target`, and never
past it. -/
def composeUntil (target : D) : List VState → List VState
  | [] => []
  | s :: rest => if commitOf s == target then [s] else s :: composeUntil target rest

/-- Composition for provenance only ever reads a PREFIX of the composed chain. -/
theorem compose_until_is_a_prefix (target : D) :
    ∀ chain : List VState, composeUntil target chain <+: chain
  | [] => by simp [composeUntil]
  | s :: rest => by
    unfold composeUntil
    split
    · exact ⟨rest, rfl⟩
    · exact List.cons_prefix_cons.mpr ⟨rfl, compose_until_is_a_prefix target rest⟩

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

def v0 : VState := { gen := 0, parent := 4, ra := 10000, rb := 5000 }
def v1 : VState := { gen := 1, parent := commitOf v0, ra := 11000, rb := 4547 }
def v2 : VState := { gen := 2, parent := commitOf v1, ra := 11700, rb := 4276 }
def backing0 : Backing := { gen := 0, ra := 10000, rb := 5000 }

/-- BASELINE: generation 0 by the owner's backing alone. -/
theorem the_baseline_is_provenanced_by_its_backing_alone :
    provenanced backing0 v0 none = true := by decide

/-- LP ABSENT: generations 1 and 2, the owner's backing still at 0. -/
theorem later_generations_are_provenanced_with_the_lp_absent :
    provenanced backing0 v1 (some [v0, v1]) = true
      ∧ provenanced backing0 v2 (some [v0, v1, v2]) = true := by
  constructor <;> decide

/-- A successor the walk did not fold authorizes nothing. -/
theorem a_history_that_stops_early_provenances_nothing :
    provenanced backing0 v2 (some [v0, v1]) = false
      ∧ provenanced backing0 v2 (some [v0, v1, v2]) = true := by
  constructor <;> decide

/-- A state that names its predecessor but skips a generation number. -/
def leaped : VState := { v1 with gen := 2 }

theorem a_leaping_generation_is_refused :
    provenanced backing0 leaped (some [v0, leaped]) = false := by decide

/-- A state that does not name its predecessor as parent. -/
def unlinked : VState := { v1 with parent := 999 }

theorem an_unlinked_state_is_refused :
    provenanced backing0 unlinked (some [v0, unlinked]) = false := by decide

/-- Reserves that are not the composed state's, and a backing that is not the
baseline's. -/
theorem altered_reserves_are_refused :
    provenanced backing0 { v2 with rb := v2.rb + 1 } (some [v0, v1, v2]) = false
      ∧ provenanced { backing0 with rb := 5001 } v2 (some [v0, v1, v2]) = false := by
  constructor <;> decide

/-- A history that does not reach back to the owner's baseline. -/
theorem a_history_missing_the_baseline_is_refused :
    provenanced backing0 v2 (some [v1, v2]) = false := by decide

/-- A backing past the parent. -/
theorem a_backing_past_the_parent_is_refused :
    provenanced { backing0 with gen := 3 } v2 (some [v0, v1, v2]) = false := by decide

/-- **WELL-FOUNDED.** Composing up to `c_1` yields exactly `[v0, v1]`: `v2`,
the state the settlement consuming `v1` produces, is never read. -/
theorem composition_for_provenance_never_reaches_the_consuming_settlement :
    composeUntil (commitOf v1) [v0, v1, v2] = [v0, v1] := by decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms a_backing_past_the_parent_never_provenances
#print axioms past_the_baseline_no_history_no_provenance
#print axioms at_the_baseline_only_the_backing_decides
#print axioms provenanced_past_the_baseline_is_the_composed_state
#print axioms compose_until_is_a_prefix
#print axioms the_baseline_is_provenanced_by_its_backing_alone
#print axioms later_generations_are_provenanced_with_the_lp_absent
#print axioms a_history_that_stops_early_provenances_nothing
#print axioms a_leaping_generation_is_refused
#print axioms an_unlinked_state_is_refused
#print axioms altered_reserves_are_refused
#print axioms a_history_missing_the_baseline_is_refused
#print axioms a_backing_past_the_parent_is_refused
#print axioms composition_for_provenance_never_reaches_the_consuming_settlement

end DSMComposedReserveProvenance
