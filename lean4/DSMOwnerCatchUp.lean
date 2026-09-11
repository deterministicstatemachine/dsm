/-
  Owner catch-up — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-G's rulings G1 + G2 over one vault: the owner's
  invariant "owner catch-up consumes certified history; it never creates
  certified history", and the engine both entrypoints share.

    - CREATES NONE     a catch-up never changes the certified history
    - CERTIFIED ONLY   the owner never applies past what was certified
    - ORDERED          the applied record is a prefix of the certified history,
                       and a catch-up only ever extends it
    - FRONTIER         a catch-up to the frontier ends exactly there
    - THROUGH x        an explicit catch-up ends exactly after x; one naming no
                       certified settlement writes nothing
    - SAME ENGINE      through the last certified settlement IS the frontier
    - RESUMABLE        interrupted after b1 applies and resumed for b2, it ends
                       where one uninterrupted run of b1 + b2 would
    - IDEMPOTENT       a second catch-up changes nothing

  The model. `certified` is the certified market folds the composition walk
  produced, oldest first — settlement identities in generation order. `applied`
  is how many of them the owner has materialized: its reserve generation above
  the baseline. The applied RECORD is `certified.take applied`, so an owner
  state that names a settlement outside the certified history, or out of its
  order, is not representable — which is the point: ORDERED is structural here,
  and what the theorems pin is that no catch-up moves `applied` past what was
  certified, backwards, or on a target that names nothing.

  `budget` is how many applies a run completes before it is interrupted. An
  uninterrupted run is any budget at least as large as what is owed.

  What this module does NOT claim:

    * Certification. `certified` is the walk's output, an input here; that the
      walk installs nothing uncertified is 2c-C3/2c-D's, modelled in
      DSMValidDlvSuccessor and DSMAcceptedSuccessorWalk.
    * The apply's validity. That each apply is exactly its certified fold —
      the 0x0027 arm, the write set, the core curve and parent checks — is
      the implementation's, pinned by its tests; here an apply is an index.
    * Admission liveness. A run refused inside one apply is `budget = n`.

  Mutation controls, executed rather than asserted — the kernel proving the
  NEGATION of a named sample theorem:

    1. a target naming no certified settlement is read as the frontier
         -> `an_uncertified_target_applies_nothing` is proved FALSE
    2. the goal clamp removed (a run applies its whole budget)
         -> `a_catch_up_stops_at_the_frontier` is proved FALSE
    3. consume-once removed (an applied settlement is applied again)
         -> `a_second_catch_up_changes_nothing_sample` is proved FALSE

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMOwnerCatchUp

/-- One vault, as the owner's catch-up sees it. -/
structure Vault where
  /-- The certified market settlements, oldest first. -/
  certified : List Nat
  /-- How many of them the owner has applied. -/
  applied : Nat
  deriving DecidableEq, Repr

/-- Where a catch-up stops. -/
inductive Target where
  | frontier
  | through (x : Nat)
  deriving DecidableEq, Repr

/-- The index of `x` in the certified history, if it is there. -/
def position (x : Nat) : List Nat → Option Nat
  | [] => none
  | y :: ys => if y = x then some 0 else (position x ys).map (· + 1)

/-- One past the last settlement a catch-up to `t` applies, or `none` when
`t` names no certified settlement. -/
def goal (h : List Nat) : Target → Option Nat
  | .frontier => some h.length
  | .through x => (position x h).map (· + 1)

/-- Advance `a` applied settlements toward goal `g`, completing at most `b`
applies. Already past the goal: nothing is owed and nothing moves. -/
def advanceTo (a g b : Nat) : Nat :=
  if g ≤ a then a else if a + b ≤ g then a + b else g

/-- THE engine: a target that names nothing writes nothing; otherwise the
owed prefix is applied oldest first, up to the goal. -/
def catchUp (t : Target) (b : Nat) (v : Vault) : Vault :=
  match goal v.certified t with
  | none => v
  | some g => { v with applied := advanceTo v.applied g b }

/-- The owner's applied record: the certified prefix it has materialized. -/
def appliedRecord (v : Vault) : List Nat :=
  v.certified.take v.applied

-- ─────────────────────────────────────────────────────────────────────────────
-- Lemmas
-- ─────────────────────────────────────────────────────────────────────────────

theorem position_lt (x : Nat) : ∀ (h : List Nat) (i : Nat),
    position x h = some i → i < h.length
  | [], i, hp => by simp [position] at hp
  | y :: ys, i, hp => by
    unfold position at hp
    split at hp
    · simp at hp
      subst hp
      simp
    · cases hq : position x ys with
      | none => simp [hq] at hp
      | some j =>
        simp [hq] at hp
        have := position_lt x ys j hq
        simp
        omega

theorem goal_le_length (h : List Nat) (t : Target) (g : Nat)
    (hg : goal h t = some g) : g ≤ h.length := by
  cases t with
  | frontier => simp [goal] at hg; omega
  | through x =>
    simp [goal] at hg
    obtain ⟨i, hi, rfl⟩ := hg
    have := position_lt x h i hi
    omega

theorem advanceTo_ge (a g b : Nat) : a ≤ advanceTo a g b := by
  unfold advanceTo
  repeat' split
  all_goals omega

theorem advanceTo_le (a g b : Nat) (ha : a ≤ g) : advanceTo a g b ≤ g := by
  unfold advanceTo
  repeat' split
  all_goals omega

theorem advanceTo_resume (a g b1 b2 : Nat) :
    advanceTo (advanceTo a g b1) g b2 = advanceTo a g (b1 + b2) := by
  unfold advanceTo
  repeat' split
  all_goals omega

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- CREATES NONE: the certified history after a catch-up is the certified
history before it. -/
theorem catch_up_creates_no_certified_history (t : Target) (b : Nat) (v : Vault) :
    (catchUp t b v).certified = v.certified := by
  unfold catchUp
  split <;> rfl

/-- CERTIFIED ONLY: an owner that has applied nothing uncertified never
applies past the certified history. -/
theorem the_owner_never_applies_past_what_was_certified (t : Target) (b : Nat) (v : Vault)
    (hv : v.applied ≤ v.certified.length) :
    (catchUp t b v).applied ≤ (catchUp t b v).certified.length := by
  unfold catchUp
  split
  · exact hv
  · rename_i g hg
    have := goal_le_length v.certified t g hg
    show advanceTo v.applied g b ≤ v.certified.length
    unfold advanceTo
    repeat' split
    all_goals omega

/-- ORDERED: a catch-up only ever extends the applied record — it never
un-applies, and the record is always a certified prefix. -/
theorem a_catch_up_only_extends_the_record (t : Target) (b : Nat) (v : Vault) :
    v.applied ≤ (catchUp t b v).applied ∧
    appliedRecord (catchUp t b v) = v.certified.take (catchUp t b v).applied := by
  unfold catchUp appliedRecord
  split
  · exact ⟨Nat.le_refl _, rfl⟩
  · exact ⟨advanceTo_ge _ _ _, rfl⟩

/-- FRONTIER: an uninterrupted catch-up to the frontier ends exactly at the
composed frontier. -/
theorem the_frontier_catch_up_ends_at_the_frontier (b : Nat) (v : Vault)
    (hv : v.applied ≤ v.certified.length)
    (hb : v.certified.length ≤ v.applied + b) :
    (catchUp .frontier b v).applied = v.certified.length := by
  show advanceTo v.applied v.certified.length b = v.certified.length
  unfold advanceTo
  repeat' split
  all_goals omega

/-- THROUGH x: an uninterrupted explicit catch-up ends exactly after `x`. -/
theorem the_explicit_catch_up_ends_after_its_settlement (x i b : Nat) (v : Vault)
    (hp : position x v.certified = some i)
    (hv : v.applied ≤ i + 1)
    (hb : i + 1 ≤ v.applied + b) :
    (catchUp (.through x) b v).applied = i + 1 := by
  unfold catchUp
  simp only [goal, hp, Option.map_some]
  show advanceTo v.applied (i + 1) b = i + 1
  unfold advanceTo
  repeat' split
  all_goals omega

/-- A target naming no certified settlement writes nothing. -/
theorem an_uncertified_target_writes_nothing (x b : Nat) (v : Vault)
    (hp : position x v.certified = none) :
    catchUp (.through x) b v = v := by
  unfold catchUp
  simp only [goal, hp, Option.map_none]

/-- SAME ENGINE: through the last certified settlement is the frontier. -/
theorem through_the_last_settlement_is_the_frontier (x b : Nat) (v : Vault)
    (hp : position x v.certified = some (v.certified.length - 1)) :
    catchUp (.through x) b v = catchUp .frontier b v := by
  have hlt := position_lt x v.certified _ hp
  unfold catchUp
  simp only [goal, hp, Option.map_some]
  have : v.certified.length - 1 + 1 = v.certified.length := by omega
  rw [this]

/-- RESUMABLE: interrupted after `b1` applies and resumed for `b2`, a catch-up
ends where one uninterrupted run of `b1 + b2` would. -/
theorem an_interrupted_catch_up_resumes_to_the_same_state (t : Target) (b1 b2 : Nat)
    (v : Vault) :
    catchUp t b2 (catchUp t b1 v) = catchUp t (b1 + b2) v := by
  unfold catchUp
  cases hg : goal v.certified t with
  | none => simp [hg]
  | some g => simp [hg, advanceTo_resume]

/-- IDEMPOTENT: once caught up, a second catch-up changes nothing. -/
theorem a_second_catch_up_changes_nothing (t : Target) (b b' : Nat) (v : Vault)
    (hb : v.certified.length ≤ v.applied + b) :
    catchUp t b' (catchUp t b v) = catchUp t b v := by
  unfold catchUp
  cases hg : goal v.certified t with
  | none => simp [hg]
  | some g =>
    have := goal_le_length v.certified t g hg
    simp only [hg]
    congr 1
    unfold advanceTo
    repeat' split
    all_goals omega

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

/-- Three certified settlements; the owner, back from offline, has applied none. -/
def back : Vault := ⟨[10, 11, 12], 0⟩

theorem an_uncertified_target_applies_nothing :
    catchUp (.through 99) 10 back = back := by decide

theorem a_catch_up_stops_at_the_frontier :
    (catchUp .frontier 10 back).applied = 3 := by decide

theorem an_explicit_catch_up_applies_the_older_ones_first :
    appliedRecord (catchUp (.through 11) 10 back) = [10, 11] := by decide

theorem an_interrupted_sample_resumes :
    catchUp .frontier 10 (catchUp .frontier 1 back) = catchUp .frontier 10 back := by
  decide

theorem a_second_catch_up_changes_nothing_sample :
    catchUp .frontier 10 (catchUp .frontier 10 back) = catchUp .frontier 10 back := by
  decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms catch_up_creates_no_certified_history
#print axioms the_owner_never_applies_past_what_was_certified
#print axioms a_catch_up_only_extends_the_record
#print axioms the_frontier_catch_up_ends_at_the_frontier
#print axioms the_explicit_catch_up_ends_after_its_settlement
#print axioms an_uncertified_target_writes_nothing
#print axioms through_the_last_settlement_is_the_frontier
#print axioms an_interrupted_catch_up_resumes_to_the_same_state
#print axioms a_second_catch_up_changes_nothing

end DSMOwnerCatchUp
