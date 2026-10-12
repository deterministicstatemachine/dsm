/-
  Route-chain finality at one cell; self-contained Lean 4 (no Mathlib, no imports).
  Storage spec §9, §12.6; DSM Amendment A6; SoFi Amendment S4;
  `dsm/src/route_chain.rs`. Replaces the copy rule ("LeaderHeld and two other
  members hold x") the successor-cell and reserve models used (G15).

    - ROUTE         a cell's route is r0..r4 over the committed set; r0 is the
                    leader. A writer writes leader first, and every copy after
                    the leader carries the chain so far.
    - LEADER LINK   valid for the first value that reached the leader, and for
                    no other: every later copy carries the leader's record, so a
                    loser's copies are links of nothing.
    - STATES        LeaderHeld: a valid leader link. Preserved: and one further
                    valid link. Final: and two further valid links.
    - APPEND ONLY   a node stores what it is given, in arrival order, and
                    removes nothing: a cell only grows.

  Proved here: chain uniqueness (MR-STOR-0143), and stability of LeaderHeld
  and Final under growth (MR-DSM-0270, MR-STOR-0127). Stated for the
  verification step, beside the TLA+ model `tla/DSM_RouteChain.tla` that
  checks it: survival of a final value under two lost seats (§12.6).
-/

namespace DSMRouteChain

/-- The four route positions after the leader (r1..r4). -/
def laterPositions : List (Fin 4) := [⟨0, by decide⟩, ⟨1, by decide⟩, ⟨2, by decide⟩, ⟨3, by decide⟩]

/-- A cell as a verifier reads it: the leader's arrivals in order, and for each
    later route position the values whose copy that seat holds. -/
structure Cell (V : Type) where
  arrivals : List V
  copies   : Fin 4 → List V

variable {V : Type}

/-- x has a valid leader link: x is the first value that reached the leader. -/
def LeaderHeld (c : Cell V) (x : V) : Prop := c.arrivals.head? = some x

/-- The later seats holding a copy of x. -/
def furtherLinks [DecidableEq V] (c : Cell V) (x : V) : Nat :=
  (laterPositions.filter (fun i => (c.copies i).contains x)).length

/-- A value's valid links, the leader's included: none without a leader link. -/
def validLinks [DecidableEq V] (c : Cell V) (x : V) : Nat :=
  match c.arrivals.head? with
  | some y => if y = x then 1 + furtherLinks c x else 0
  | none   => 0

def Preserved [DecidableEq V] (c : Cell V) (x : V) : Prop := validLinks c x ≥ 2
def Final     [DecidableEq V] (c : Cell V) (x : V) : Prop := validLinks c x ≥ 3

/-- A node only appends: c' extends every list c holds. -/
def Grows (c c' : Cell V) : Prop :=
  (∃ t, c'.arrivals = c.arrivals ++ t) ∧ ∀ i, ∃ t, c'.copies i = c.copies i ++ t

/-- MR-STOR-0143: at most one value has a valid leader link at a cell. -/
theorem chain_uniqueness (c : Cell V) (x y : V)
    (hx : LeaderHeld c x) (hy : LeaderHeld c y) : x = y := by
  unfold LeaderHeld at hx hy
  rw [hx] at hy
  exact Option.some.inj hy

/-- MR-DSM-0270 / MR-STOR-0127: a leader link, once held, is held on every
    later read of the cell, because a node only appends. -/
theorem leader_held_stable (c c' : Cell V) (x : V)
    (hg : Grows c c') (hx : LeaderHeld c x) : LeaderHeld c' x := by
  obtain ⟨⟨t, ht⟩, _⟩ := hg
  unfold LeaderHeld at hx ⊢
  rw [ht]
  cases h : c.arrivals with
  | nil => rw [h] at hx; simp at hx
  | cons a rest =>
    rw [h] at hx
    simp at hx
    subst hx
    rfl

/-- A filter over one list keeps at least as many elements under a predicate
    implied by the first. -/
theorem length_filter_le_of_imp {α : Type} (l : List α) (p q : α → Bool)
    (h : ∀ a, p a = true → q a = true) :
    (l.filter p).length ≤ (l.filter q).length := by
  induction l with
  | nil => simp
  | cons a l ih =>
    by_cases hp : p a = true
    · have hq := h a hp
      simp only [List.filter_cons, hp, hq]
      exact Nat.succ_le_succ ih
    · cases hq : q a
      · simp only [List.filter_cons, hp, hq]
        exact ih
      · simp only [List.filter_cons, hp, hq]
        exact Nat.le_succ_of_le ih

/-- A copy a seat holds is held on every later read: a node only appends. -/
theorem contains_of_grows [DecidableEq V] (l t : List V) (x : V)
    (h : l.contains x = true) : (l ++ t).contains x = true := by
  have hm : x ∈ l := List.mem_of_elem_eq_true h
  exact List.elem_eq_true_of_mem (List.mem_append_left t hm)

/-- The further links of a value never decrease as the cell grows. -/
theorem further_links_mono [DecidableEq V] (c c' : Cell V) (x : V)
    (hg : Grows c c') : furtherLinks c x ≤ furtherLinks c' x := by
  unfold furtherLinks
  apply length_filter_le_of_imp
  intro i hi
  obtain ⟨t, ht⟩ := hg.2 i
  rw [ht]
  exact contains_of_grows _ _ _ hi

/-- MR-DSM-0270: a final value stays final as the cell grows. -/
theorem final_stable [DecidableEq V] (c c' : Cell V) (x : V)
    (hg : Grows c c') (hx : Final c x) : Final c' x := by
  have hl : LeaderHeld c x := by
    unfold Final validLinks at hx
    unfold LeaderHeld
    cases h : c.arrivals.head? with
    | none => rw [h] at hx; simp at hx
    | some y =>
      rw [h] at hx
      by_cases hy : y = x
      · rw [hy]
      · simp [hy] at hx
  have hl' : LeaderHeld c' x := leader_held_stable c c' x hg hl
  unfold Final validLinks at hx ⊢
  unfold LeaderHeld at hl hl'
  rw [hl] at hx
  rw [hl']
  simp only [if_true] at hx ⊢
  have := further_links_mono c c' x hg
  omega

/-- §12.6, for the verification step: with at most two of the five seats lost,
    some holder of a final value's chain survives. `lost p` says the seat at
    route position p (0 the leader) is lost. -/
def FinalSurvivesTwoLosses [DecidableEq V] : Prop :=
  ∀ (c : Cell V) (x : V) (lost : Fin 5 → Bool),
    ((List.range 5).filter (fun p => if h : p < 5 then lost ⟨p, h⟩ else false)).length ≤ 2 →
    Final c x →
    lost ⟨0, by decide⟩ = false ∨
      ∃ i ∈ laterPositions, (c.copies i).contains x = true ∧ lost ⟨i.val + 1, Nat.succ_lt_succ i.isLt⟩ = false

end DSMRouteChain
