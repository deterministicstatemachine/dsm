/-
  The fresh owner baseline — self-contained Lean 4 (no Mathlib, no imports)

  Machine-checks amendment 2c-G's G3 ruling and its three implementation
  rulings over one vault.

    - MONOTONE         a refresh never moves the baseline backwards
    - MATERIALIZED     it anchors only a generation the owner has applied and
                       the walk has certified
    - IDEMPOTENT       a second refresh changes nothing
    - PENDING          a freshly frozen baseline is not yet published
    - NEVER EARLY      a pending baseline never becomes the advertised one
    - ANCHOR ≤ PROOF   every advertisement names an anchor its proof reaches —
                       the order a trader's provenance requires
    - SAME FRONTIER    composition reaches the same frontier from any
                       certified baseline
    - HISTORY          a history walk that must include generation g starts at
                       the current anchor when it is at or before g, else at the
                       immutable birth anchor — so it always reaches g, and a
                       baseline that moved never strands an earlier settle
                       (the G3 blocker ruling)

  The model. `certified` is the certified chain of states, oldest first, from
  the owner's old baseline to the frontier; it is the walk's output and never
  changes here. `materialized` is the owner's admitted generation. `baseline`
  is the record's; `published` says whether its objects are quorum-durable.
  `adAnchor` and `adProof` are the generations the advertisement names.

  What this module does NOT claim:

    * The presentation's authority. P0–P6 is the identity layer's
      (DSMCertChain); here a baseline is a generation.
    * Catch-up. DSMOwnerCatchUp owns `materialized`.
    * Publication itself. `publish` is an input event.

  Mutation controls, executed rather than asserted — the kernel proving the
  NEGATION of a named sample theorem:

    1. the backwards guard dropped (refresh anchors whatever is materialized)
         -> `a_refresh_never_moves_the_baseline_backwards_sample` is proved FALSE
    2. the quorum gate dropped (advertise a pending baseline)
         -> `a_pending_baseline_is_never_advertised` is proved FALSE
    3. anchor past the materialized generation (anchor the frontier)
         -> `a_partial_catch_up_anchors_what_it_applied` is proved FALSE
    4. the birth fallback dropped (history always starts at the current anchor)
         -> `an_earlier_settle_is_reconstructed_from_birth` is proved FALSE

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMFreshBaseline

structure Owner where
  /-- The certified chain, oldest first; its length - 1 is the frontier. -/
  certified : List Nat
  materialized : Nat
  baseline : Nat
  published : Bool
  adAnchor : Nat
  adProof : Nat
  deriving DecidableEq, Repr

/-- G3: anchor the materialized generation when it is ahead of the baseline
and certified; the switch is local, so the new baseline starts unpublished. -/
def refresh (o : Owner) : Owner :=
  if o.baseline < o.materialized ∧ o.materialized < o.certified.length then
    { o with baseline := o.materialized, published := false }
  else o

/-- The fleet reaches quorum on the baseline's objects. -/
def publish (o : Owner) : Owner := { o with published := true }

/-- The advertisement moves to the baseline — anchor and proof together, the
proof at the baseline's own generation — only once it is published. -/
def advertise (o : Owner) : Owner :=
  if o.published then { o with adAnchor := o.baseline, adProof := o.baseline } else o

/-- Where a history walk that must include generation `g` starts: the current
anchor when it is at or before `g`, else the immutable birth anchor (0). -/
def historyStart (anchor g : Nat) : Nat := if anchor ≤ g then anchor else 0

/-- Composition from baseline `b`: the states from `b` on; its frontier is the
last of them. -/
def frontierFrom (b : Nat) (certified : List Nat) : Option Nat :=
  (certified.drop b).getLast?

-- ─────────────────────────────────────────────────────────────────────────────
-- Lemmas
-- ─────────────────────────────────────────────────────────────────────────────

theorem getLast?_drop (l : List Nat) : ∀ b, b < l.length → (l.drop b).getLast? = l.getLast? := by
  induction l with
  | nil => intro b h; simp at h
  | cons x t ih =>
    intro b h
    cases b with
    | zero => simp
    | succ b =>
      have hb : b < t.length := by simp at h; omega
      rw [List.drop_succ_cons, ih b hb]
      cases t with
      | nil => simp at hb
      | cons y u => simp [List.getLast?_cons_cons]

-- ─────────────────────────────────────────────────────────────────────────────
-- General statements
-- ─────────────────────────────────────────────────────────────────────────────

/-- MONOTONE: a refresh never moves the baseline backwards. -/
theorem a_refresh_never_moves_the_baseline_backwards (o : Owner) :
    o.baseline ≤ (refresh o).baseline := by
  unfold refresh
  split
  · rename_i h; exact Nat.le_of_lt h.1
  · exact Nat.le_refl _

/-- MATERIALIZED: a refresh that moved the baseline anchored exactly the
materialized generation, which the walk certified. -/
theorem a_refresh_anchors_only_the_materialized_certified_generation (o : Owner)
    (h : (refresh o).baseline ≠ o.baseline) :
    (refresh o).baseline = o.materialized ∧ o.materialized < o.certified.length := by
  by_cases hc : o.baseline < o.materialized ∧ o.materialized < o.certified.length
  · exact ⟨by simp [refresh, hc], hc.2⟩
  · simp [refresh, hc] at h

/-- IDEMPOTENT: a second refresh changes nothing. -/
theorem a_second_refresh_changes_nothing (o : Owner) :
    refresh (refresh o) = refresh o := by
  unfold refresh
  split
  · rename_i h
    simp only [Nat.lt_irrefl, false_and, if_false]
  · rfl

/-- PENDING: a baseline that moved is not published. -/
theorem a_fresh_baseline_is_pending (o : Owner)
    (h : (refresh o).baseline ≠ o.baseline) : (refresh o).published = false := by
  by_cases hc : o.baseline < o.materialized ∧ o.materialized < o.certified.length
  · simp [refresh, hc]
  · simp [refresh, hc] at h

/-- NEVER EARLY: an unpublished baseline never moves the advertisement. -/
theorem an_unpublished_baseline_never_moves_the_advertisement (o : Owner)
    (h : o.published = false) : advertise o = o := by
  simp [advertise, h]

/-- ANCHOR ≤ PROOF is preserved by every step. -/
theorem every_advertisement_names_an_anchor_its_proof_reaches (o : Owner)
    (h : o.adAnchor ≤ o.adProof) :
    (refresh o).adAnchor ≤ (refresh o).adProof ∧
    (publish o).adAnchor ≤ (publish o).adProof ∧
    (advertise o).adAnchor ≤ (advertise o).adProof := by
  refine ⟨?_, h, ?_⟩
  · unfold refresh; split <;> exact h
  · unfold advertise; split
    · exact Nat.le_refl _
    · exact h

/-- SAME FRONTIER: composition from any certified baseline reaches the
frontier composition from the oldest one reaches. -/
theorem composition_reaches_the_same_frontier_from_any_baseline (certified : List Nat)
    (b : Nat) (h : b < certified.length) :
    frontierFrom b certified = frontierFrom 0 certified := by
  simp only [frontierFrom, List.drop_zero]
  exact getLast?_drop certified b h

/-- HISTORY: a history walk always starts at or before the generation it must
include — whatever the current anchor. -/
theorem a_history_walk_always_reaches_its_generation (anchor g : Nat) :
    historyStart anchor g ≤ g := by
  unfold historyStart
  split <;> omega

/-- HISTORY: and it prefers the current anchor whenever that suffices. -/
theorem a_history_walk_prefers_the_current_anchor (anchor g : Nat) (h : anchor ≤ g) :
    historyStart anchor g = anchor := by
  simp [historyStart, h]

-- ─────────────────────────────────────────────────────────────────────────────
-- Samples — the statements above are not vacuous
-- ─────────────────────────────────────────────────────────────────────────────

/-- Anchored at 0 and advertised there; three certified generations beyond. -/
def owner0 : Owner := ⟨[10, 11, 12, 13], 3, 0, true, 0, 0⟩

theorem a_caught_up_refresh_anchors_the_frontier :
    (refresh owner0).baseline = 3 := by decide

theorem a_pending_baseline_is_never_advertised :
    (advertise (refresh owner0)).adAnchor = 0 := by decide

theorem a_published_baseline_moves_the_advertisement_with_its_proof :
    advertise (publish (refresh owner0)) =
      { refresh owner0 with published := true, adAnchor := 3, adProof := 3 } := by
  decide

theorem a_partial_catch_up_anchors_what_it_applied :
    (refresh { owner0 with materialized := 1 }).baseline = 1 := by decide

theorem an_earlier_settle_is_reconstructed_from_birth :
    historyStart 3 0 = 0 := by decide

theorem a_refresh_never_moves_the_baseline_backwards_sample :
    (refresh { owner0 with baseline := 3, materialized := 1 }).baseline = 3 := by decide

-- ─────────────────────────────────────────────────────────────────────────────
-- Axiom report
-- ─────────────────────────────────────────────────────────────────────────────

#print axioms a_refresh_never_moves_the_baseline_backwards
#print axioms a_refresh_anchors_only_the_materialized_certified_generation
#print axioms a_second_refresh_changes_nothing
#print axioms a_fresh_baseline_is_pending
#print axioms an_unpublished_baseline_never_moves_the_advertisement
#print axioms every_advertisement_names_an_anchor_its_proof_reaches
#print axioms composition_reaches_the_same_frontier_from_any_baseline
#print axioms a_history_walk_always_reaches_its_generation
#print axioms a_history_walk_prefers_the_current_anchor

end DSMFreshBaseline
