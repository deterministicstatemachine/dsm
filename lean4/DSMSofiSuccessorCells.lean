/-
  SoFi v8 successor cells, registers and the attempt walk — self-contained Lean 4
  (no Mathlib, no imports)

  Machine-checks the storage and walk layer of the v8 market settlement (plan
  revision 10.3: F0, F2's registers, F4–F7) and its fault model:

    - WRITE-ONCE        a held cell never changes; holders only grow
    - FINALITY          three matching cells of five; one final value per key, in
                        this store and every later one
    - ARITHDEAD         `max + #Empty + #Unknown < 3` on a PARTIAL read is sound: no
                        store compatible with the read — any value in an unread
                        cell, any later fill — is final, now or later; a final key
                        is never dead
    - GARBAGE           a malformed or unverifiable reply is Unknown and stays in
                        the count; dropping it makes a final key look dead
    - F0                one equivocating member, or permanent loss of two stores,
                        breaks 3-of-5 (counterexamples)
    - RECORDS           every Dead record chain bottoms out in an observation, and
                        no record contradicts a later store
    - ROUTE OUTCOME     Complete or Abort only: one value, never a Dead state
    - REGISTERS         at most one registered fulfillment per position across
                        every reachable pair of states;
                        FulfillmentRegistered(q, F) ∧ EconomicRootRegistered(q, C)
                        ⇒ C = C_q; an incompatible trader transition blocks the
                        fulfillment forever; no successor cell or outcome exists
                        before registration; publication to one member is not
                        exercise
    - THE WALK          one consumer per parent across all attempts, with
                        AttemptLive load-bearing; a final leg of an impossible route
                        is skippable with no Complete premise (R7-17), and gating it
                        on Complete wedges a withheld leg; Unavailable never
                        establishes impossibility; skips are permanent; a chunked
                        walk equals one walk
    - ORDERING          no numeric holes in attempt indices; counters never wrap
    - STORAGEREACHABLE  a noncanonical DAG whose producer is (parent, E) — never the
                        attempt; reachable is not canonical

  Modelling premises:

    * Members are positions of the frozen five-member set. F0: crash and omission
      only — peers are read truthfully and stores are never lost.
    * Values (E, FulfillmentId, claims) are opaque naturals. Hashing and object
      identity are DSMSofiAtomicity's.
    * The walk's per-key facts (final value, Dead, validation, orphan, rival
      consumption, route outcome, the trader parent's branch) are inputs;
      `Coherent` restates what the cell layer above proves about them.
    * Those semantic facts are keyed by E, while `K_out(F)` is keyed by
      FulfillmentId. That is sound and NOT an assumption that E determines F:
      E is scoped to one trader position (P15-1), at most one fulfillment ever
      registers there (`at_most_one_registered_fulfillment_per_position`), and a
      cell or an outcome exists only for a registered fulfillment
      (`fulfillment_registration_is_exercise_boundary`). So for any E a verifier
      reads these facts about, the fulfillment they belong to is that unique
      registered one. Several CANDIDATE fulfillments may share one E; none of
      them writes anything (R15-2).

  What this module does NOT claim:

    * Semantic validity of any E, or the resolution of a trader position
      (DSMSofiAtomicity). Arm (iv) enters here as the input
      `traderParentImpossible`; WHY a trader parent is terminal is the ladder's
      business, not this module's.
    * That the member's ingress code enforces `RStep`. `RStep` is the rule; the
      member is Phase E.
    * Liveness: nothing here says a key ever becomes final or dead.

  Finding:

    * Under the ruled formula Empty and Unknown count identically toward `u`
      (`empty_and_unknown_are_arithmetically_equal`). Reading garbage as Empty
      (mutation 4) therefore breaks no soundness theorem; only the classification
      theorem itself goes red. Dropping garbage from the count is the unsound
      mutation (`dropping_garbage_breaks_soundness`).

  Mutation controls, executed rather than asserted. Each gate was removed and the
  named theorem went red — its proof rejected by the kernel, or `#print axioms`
  showing it now rests on `sorryAx`:

     1. a held cell may be overwritten        -> `held_cell_cannot_change`
     2. finality at two cells                 -> `final_unique_on_key`
     3. Unknown dropped from `u`              -> `arith_dead_sound_with_unread`
     4. garbage read as Empty                 -> `garbage_is_never_empty` only (finding)
     5. Dead at `≤ 3` instead of `< 3`        -> `arith_dead_sound_with_unread`
     6. a Dead record from nothing            -> `dead_record_chain_has_observational_base`
     7. K_ful written without K_root(q)       -> `fulfillment_and_root_registration_agree`
     8. cells admitted on holding F           -> `fulfillment_registration_is_exercise_boundary`,
                                                 `final_e_at_a_leg_implies_registered`
     9. registration record on one holder     -> `fulfillment_registration_is_exercise_boundary`
    10. K_ful overwritable                    -> `at_most_one_registered_fulfillment_per_position`
    11. K_root(q) overwritable                -> `incompatible_trader_transition_blocks_fulfillment`
    12. exercise read as one member holding F -> `one_member_publication_is_not_exercise`
    13. outcome written without the record    -> `outcome_final_implies_registered`
    14. AttemptLive removed from consumption  -> `walk_consumes_at_most_once`
    15. route-leg skip gated on Complete      -> `route_impossible_final_leg_is_skippable`,
                                                 `withheld_leg_recovers_under_R7_17`
    16. Unavailable counted as impossibility  -> `route_impossibility_is_permanent`,
                                                 `unavailable_never_establishes_route_impossibility`
    17. `a > 0 ⇒ record(a − 1)` removed       -> `storage_forbids_numeric_holes`
    18. a chunk restarting the walk cursor    -> `walk_chunking_preserves_result`
    19. a counter wrapping at u64::MAX        -> `checked_counters_never_wrap`
    20. the attempt inside producer identity  -> `storage_reachable_producer_identity_excludes_attempt`
    21. arm (iv) dropped from RouteImpossible -> `trader_parent_impossible_makes_a_final_route_skippable`

  All mutations were reverted; this file is the unmutated module.
-/

namespace DSMSofiSuccessorCells

abbrev Val := Nat
abbrev Cells := List (Option Val)

def putCell : Option Val → Val → Option Val
  | none, v => some v
  | some u, _ => some u

def modifyAt (f : Option Val → Option Val) : Nat → Cells → Cells
  | _, [] => []
  | 0, x :: xs => f x :: xs
  | n+1, x :: xs => x :: modifyAt f n xs

def cellAt : Nat → Cells → Option (Option Val)
  | _, [] => none
  | 0, x :: _ => some x
  | n+1, _ :: xs => cellAt n xs

theorem cellAt_modifyAt (f : Option Val → Option Val) :
    ∀ (i j : Nat) (cs : Cells),
      cellAt j (modifyAt f i cs) = if i = j then (cellAt j cs).map f else cellAt j cs := by
  intro i j cs
  induction cs generalizing i j with
  | nil => cases i <;> cases j <;> simp [modifyAt, cellAt]
  | cons x xs ih =>
    cases i with
    | zero => cases j <;> simp [modifyAt, cellAt]
    | succ i =>
      cases j with
      | zero => simp [modifyAt, cellAt]
      | succ j => simp [modifyAt, cellAt, ih]

def holders (v : Val) : Cells → Nat
  | [] => 0
  | x :: xs => (if x = some v then 1 else 0) + holders v xs

theorem length_modifyAt (f) : ∀ i (cs : Cells), (modifyAt f i cs).length = cs.length := by
  intro i cs
  induction cs generalizing i with
  | nil => cases i <;> rfl
  | cons x xs ih => cases i <;> simp [modifyAt, ih]


/-- One member write: position `i` receives `v` under the write-once rule. -/
def Step (cs cs' : Cells) : Prop := ∃ i v, cs' = modifyAt (fun c => putCell c v) i cs

inductive Reachable : Cells → Cells → Prop
  | refl (cs : Cells) : Reachable cs cs
  | tail {a b c : Cells} : Reachable a b → Step b c → Reachable a c

theorem held_cell_cannot_change {cs cs' : Cells} {j : Nat} {u : Val}
    (hheld : cellAt j cs = some (some u)) (hr : Reachable cs cs') :
    cellAt j cs' = some (some u) := by
  induction hr with
  | refl => exact hheld
  | tail _ hstep ih =>
    obtain ⟨i, v, rfl⟩ := hstep
    rw [cellAt_modifyAt]
    split
    · rw [ih]; rfl
    · exact ih

theorem holders_step_mono (x : Val) :
    ∀ (i : Nat) (v : Val) (cs : Cells), holders x cs ≤ holders x (modifyAt (fun c => putCell c v) i cs) := by
  intro i v cs
  induction cs generalizing i with
  | nil => cases i <;> simp [modifyAt, holders]
  | cons c xs ih =>
    cases i with
    | zero =>
      cases c with
      | none => simp only [modifyAt, putCell, holders]; split <;> split <;> simp_all
      | some u => simp [modifyAt, putCell, holders]
    | succ i => simp only [modifyAt, holders]; have := ih i; omega

theorem holders_reachable_mono {cs cs' : Cells} (x : Val) (hr : Reachable cs cs') :
    holders x cs ≤ holders x cs' := by
  induction hr with
  | refl => exact Nat.le_refl _
  | tail _ hstep ih =>
    obtain ⟨i, v, rfl⟩ := hstep
    exact Nat.le_trans ih (holders_step_mono x i v _)

theorem length_reachable {cs cs' : Cells} (hr : Reachable cs cs') : cs'.length = cs.length := by
  induction hr with
  | refl => rfl
  | tail _ hstep ih => obtain ⟨i, v, rfl⟩ := hstep; rw [length_modifyAt]; exact ih

/-- Distinct values have disjoint holder sets in one state. -/
theorem holders_disjoint {a b : Val} (hne : a ≠ b) :
    ∀ cs : Cells, holders a cs + holders b cs ≤ cs.length := by
  intro cs
  induction cs with
  | nil => simp [holders]
  | cons x xs ih =>
    simp only [holders, List.length_cons]
    cases x with
    | none => simp; omega
    | some u =>
      by_cases hua : u = a
      · subst hua
        have hub : u ≠ b := hne
        simp [hub]; omega
      · by_cases hub : u = b
        · subst hub; simp [hua]; omega
        · simp [hua, hub]; omega

def STORAGE_MEMBERS : Nat := 5
def FINALITY : Nat := 3

/-- A key is final with `v` when three committed members hold it. -/
def FinalWith (cs : Cells) (v : Val) : Prop := FINALITY ≤ holders v cs

instance (cs : Cells) (v : Val) : Decidable (FinalWith cs v) :=
  inferInstanceAs (Decidable (FINALITY ≤ holders v cs))

theorem final_unique_on_key {cs : Cells} (hlen : cs.length = STORAGE_MEMBERS) {a b : Val}
    (ha : FinalWith cs a) (hb : FinalWith cs b) : a = b := by
  apply Classical.byContradiction
  intro hne
  have := holders_disjoint hne cs
  simp [FinalWith, FINALITY, STORAGE_MEMBERS] at ha hb hlen
  omega

theorem final_unique_across_reachable_states {cs cs' : Cells} (hlen : cs.length = STORAGE_MEMBERS)
    {a b : Val} (ha : FinalWith cs a) (hr : Reachable cs cs') (hb : FinalWith cs' b) : a = b :=
  final_unique_on_key (by rw [length_reachable hr]; exact hlen)
    (Nat.le_trans ha (holders_reachable_mono a hr)) hb


theorem Reachable.trans {a b c : Cells} (h1 : Reachable a b) (h2 : Reachable b c) : Reachable a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hs ih => exact Reachable.tail ih hs

-- ── observations ──────────────────────────────────────────────────────────

inductive Obs where
  | held (v : Val)
  | empty
  | unknown
  deriving DecidableEq, Repr

def obsHolders (v : Val) : List Obs → Nat
  | [] => 0
  | o :: os => (if o = .held v then 1 else 0) + obsHolders v os

def obsOpen : List Obs → Nat
  | [] => 0
  | .held _ :: os => obsOpen os
  | _ :: os => 1 + obsOpen os

def maxHeld (all : List Obs) : List Obs → Nat
  | [] => 0
  | .held v :: os => max (obsHolders v all) (maxHeld all os)
  | _ :: os => maxHeld all os

def Dead (os : List Obs) : Prop := maxHeld os os + obsOpen os < FINALITY

instance (os : List Obs) : Decidable (Dead os) :=
  inferInstanceAs (Decidable (maxHeld os os + obsOpen os < FINALITY))

theorem obsHolders_zero_of_not_mem (x : Val) :
    ∀ os : List Obs, Obs.held x ∉ os → obsHolders x os = 0 := by
  intro os
  induction os with
  | nil => intro _; rfl
  | cons o os ih =>
    intro hnm
    have hne : o ≠ .held x := fun h => hnm (h ▸ List.mem_cons_self)
    have hrest : Obs.held x ∉ os := fun h => hnm (List.mem_cons_of_mem _ h)
    simp [obsHolders, hne, ih hrest]

theorem le_maxHeld (all : List Obs) (x : Val) :
    ∀ rest : List Obs, Obs.held x ∈ rest → obsHolders x all ≤ maxHeld all rest := by
  intro rest
  induction rest with
  | nil => intro h; cases h
  | cons o os ih =>
    intro hm
    cases o with
    | held v =>
      simp only [maxHeld]
      rcases List.mem_cons.mp hm with h | h
      · cases h; exact Nat.le_max_left _ _
      · exact Nat.le_trans (ih h) (Nat.le_max_right _ _)
    | empty =>
      simp only [maxHeld]
      rcases List.mem_cons.mp hm with h | h
      · cases h
      · exact ih h
    | unknown =>
      simp only [maxHeld]
      rcases List.mem_cons.mp hm with h | h
      · cases h
      · exact ih h

theorem obsHolders_le_maxHeld (os : List Obs) (x : Val) : obsHolders x os ≤ maxHeld os os := by
  by_cases hm : Obs.held x ∈ os
  · exact le_maxHeld os x os hm
  · rw [obsHolders_zero_of_not_mem x os hm]; exact Nat.zero_le _

/-- An observation is compatible with a store when every HELD observation is
the member's actual cell. Empty and unknown observations constrain nothing:
an unread member may hold anything, and an empty cell may since have filled. -/
def Compatible : List Obs → Cells → Prop
  | [], [] => True
  | .held v :: os, c :: cs => c = some v ∧ Compatible os cs
  | .empty :: os, _ :: cs => Compatible os cs
  | .unknown :: os, _ :: cs => Compatible os cs
  | _, _ => False

instance instDecCompatible : (os : List Obs) → (cs : Cells) → Decidable (Compatible os cs)
  | [], [] => inferInstanceAs (Decidable True)
  | [], _ :: _ => inferInstanceAs (Decidable False)
  | .held _ :: _, [] => inferInstanceAs (Decidable False)
  | .empty :: _, [] => inferInstanceAs (Decidable False)
  | .unknown :: _, [] => inferInstanceAs (Decidable False)
  | .held v :: os, c :: cs =>
    haveI := instDecCompatible os cs
    inferInstanceAs (Decidable (c = some v ∧ Compatible os cs))
  | .empty :: os, _ :: cs => instDecCompatible os cs
  | .unknown :: os, _ :: cs => instDecCompatible os cs

theorem holders_le_of_compatible (x : Val) :
    ∀ (os : List Obs) (cs : Cells), Compatible os cs → holders x cs ≤ obsHolders x os + obsOpen os := by
  intro os
  induction os with
  | nil => intro cs h; cases cs with
    | nil => simp [holders, obsHolders, obsOpen]
    | cons _ _ => simp [Compatible] at h
  | cons o os ih =>
    intro cs h
    cases cs with
    | nil => cases o <;> simp [Compatible] at h
    | cons c cs =>
      cases o with
      | held v =>
        obtain ⟨hc, hrest⟩ := h
        have := ih cs hrest
        subst hc
        by_cases hv : v = x
        · subst hv; simp [holders, obsHolders, obsOpen]; omega
        · have h1 : ¬ (some v = some x) := fun e => hv (Option.some.inj e)
          have h2 : ¬ (Obs.held v = Obs.held x) := fun e => hv (by cases e; rfl)
          simp only [holders, obsHolders, obsOpen, h1, h2, if_false]; omega
      | empty =>
        have := ih cs h
        simp only [holders, obsHolders, obsOpen]; split <;> simp <;> omega
      | unknown =>
        have := ih cs h
        simp only [holders, obsHolders, obsOpen]; split <;> simp <;> omega

/-- SOUNDNESS of a Dead verdict on a partial read: no store compatible with the
observation — any value in any unread cell, any later fill of an empty one —
holds a final value. -/
theorem arith_dead_sound_with_unread {os : List Obs} {cs : Cells}
    (hdead : Dead os) (hc : Compatible os cs) (x : Val) : ¬ FinalWith cs x := by
  intro hf
  have h1 := holders_le_of_compatible x os cs hc
  have h2 := obsHolders_le_maxHeld os x
  simp [Dead, FinalWith, FINALITY] at hdead hf
  omega

theorem compatible_step (v : Val) :
    ∀ (i : Nat) (os : List Obs) (cs : Cells),
      Compatible os cs → Compatible os (modifyAt (fun c => putCell c v) i cs) := by
  intro i os
  induction os generalizing i with
  | nil => intro cs h; cases cs with
    | nil => cases i <;> simp [modifyAt, Compatible]
    | cons _ _ => simp [Compatible] at h
  | cons o os ih =>
    intro cs h
    cases cs with
    | nil => cases o <;> simp [Compatible] at h
    | cons c cs =>
      cases i with
      | zero =>
        cases o with
        | held w => obtain ⟨hc, hr⟩ := h; subst hc; exact ⟨rfl, hr⟩
        | empty => exact h
        | unknown => exact h
      | succ i =>
        cases o with
        | held w => obtain ⟨hc, hr⟩ := h; exact ⟨hc, ih i cs hr⟩
        | empty => exact ih i cs h
        | unknown => exact ih i cs h

theorem compatible_persists {os : List Obs} {cs cs' : Cells}
    (hc : Compatible os cs) (hr : Reachable cs cs') : Compatible os cs' := by
  induction hr with
  | refl => exact hc
  | tail _ hs ih => obtain ⟨i, v, rfl⟩ := hs; exact compatible_step v i os _ ih

/-- A key proven dead stays dead: cells only fill. -/
theorem arith_dead_persists {os : List Obs} {cs cs' : Cells}
    (hdead : Dead os) (hc : Compatible os cs) (hr : Reachable cs cs') (x : Val) :
    ¬ FinalWith cs' x :=
  arith_dead_sound_with_unread hdead (compatible_persists hc hr) x

/-- A final key is never dead, whatever a verifier observed of it. -/
theorem final_key_never_dead {os : List Obs} {cs : Cells} {x : Val}
    (hf : FinalWith cs x) (hc : Compatible os cs) : ¬ Dead os :=
  fun hdead => arith_dead_sound_with_unread hdead hc x hf

-- non-vacuity witnesses
theorem two_two_one_is_dead : Dead [.held 1, .held 1, .held 2, .held 2, .held 3] := by decide
theorem two_two_unknown_is_not_dead : ¬ Dead [.held 1, .held 1, .held 2, .held 2, .unknown] := by decide


-- ── responses, garbage, and the two fault-model counterexamples ───────────

inductive Resp where
  | value (v : Val)
  | emptyRead
  | malformed
  | noReply
  deriving DecidableEq, Repr

/-- The only classification. A malformed or unverifiable response from a
contacted member is UnknownOccupied: it stays in the count as `u`. -/
def classify : Resp → Obs
  | .value v => .held v
  | .emptyRead => .empty
  | .malformed => .unknown
  | .noReply => .unknown

theorem garbage_is_never_empty : classify .malformed = .unknown ∧ classify .malformed ≠ .empty := by
  decide

/-- Every response contributes exactly one observation, so garbage never
leaves the count. -/
theorem classify_keeps_every_member (rs : List Resp) : (rs.map classify).length = rs.length := by
  simp

/-- Why garbage must stay in the count: dropping two malformed responses from
members that actually hold `1` makes a final key look dead. -/
theorem dropping_garbage_breaks_soundness :
    Dead [.held 1, .held 2, .held 3]
      ∧ FinalWith [some 1, some 1, some 1, some 2, some 3] 1
      ∧ ¬ Dead ([Resp.value 1, .malformed, .malformed, .value 2, .value 3].map classify) := by
  decide

/-- Under the ruled formula Empty and Unknown count identically toward `u`.
Swapping them never changes a Dead verdict. -/
theorem empty_and_unknown_are_arithmetically_equal :
    ∀ os : List Obs, obsOpen os = obsOpen (os.map fun o => match o with
      | .empty => .unknown
      | o => o) := by
  intro os
  induction os with
  | nil => rfl
  | cons o os ih => cases o <;> simp [obsOpen, ih]

/-- NON-EQUIVOCATION IS LOAD-BEARING. If member index 2 answers `1` to one
reader and `2` to another, the two readers see two different finals on the
same key. 3-of-5 tolerates zero equivocators. -/
theorem equivocating_member_breaks_three_of_five :
    FinalWith [some 1, some 1, some 1, some 2, some 2] 1
      ∧ FinalWith [some 1, some 1, some 2, some 2, some 2] 2
      ∧ (∀ j, j ≠ 2 →
          cellAt j [some 1, some 1, some 1, some 2, some 2]
            = cellAt j [some 1, some 1, some 2, some 2, some 2]) := by
  refine ⟨by decide, by decide, ?_⟩
  intro j hj
  match j with
  | 0 => rfl
  | 1 => rfl
  | 2 => exact absurd rfl hj
  | 3 => rfl
  | 4 => rfl
  | _ + 5 => rfl

/-- DURABILITY IS LOAD-BEARING. `1` was final on members 0,1,2. After members
0 and 1 are permanently lost, the surviving observation is also compatible
with a store in which `1` was never final, and it is not Dead either: history
can no longer be re-established. -/
theorem permanent_store_loss_breaks_historical_finality :
    FinalWith [some 1, some 1, some 1, none, none] 1
      ∧ Compatible [.unknown, .unknown, .held 1, .empty, .empty] [some 1, some 1, some 1, none, none]
      ∧ Compatible [.unknown, .unknown, .held 1, .empty, .empty] [some 2, some 3, some 1, none, none]
      ∧ ¬ FinalWith [some 2, some 3, some 1, none, none] 1
      ∧ ¬ Dead [.unknown, .unknown, .held 1, .empty, .empty] := by
  decide

-- ── resolution records ────────────────────────────────────────────────────

/-- A Dead record for the key whose current cells are `cs`. Every derivation
bottoms out in a DIRECT observation of an earlier store from which `cs` is
reachable; three records from peers are themselves derivations. There is no
constructor for a record from nothing. -/
inductive DeadEvidence : Cells → Prop
  | direct {cs : Cells} (os : List Obs) (c0 : Cells)
      (hdead : Dead os) (hc : Compatible os c0) (hr : Reachable c0 cs) : DeadEvidence cs
  | fromRecords {cs : Cells} (r1 r2 r3 : DeadEvidence cs) : DeadEvidence cs

theorem dead_record_chain_has_observational_base {cs : Cells} (e : DeadEvidence cs) :
    ∃ os c0, Dead os ∧ Compatible os c0 ∧ Reachable c0 cs := by
  induction e with
  | direct os c0 hdead hc hr => exact ⟨os, c0, hdead, hc, hr⟩
  | fromRecords _ _ _ ih1 _ _ => exact ih1

/-- Records never contradict later state: a Dead record rules out every final,
now and in every descendant store. -/
theorem resolution_record_sound {cs cs' : Cells} (e : DeadEvidence cs) (hr : Reachable cs cs')
    (x : Val) : ¬ FinalWith cs' x := by
  obtain ⟨os, c0, hdead, hc, hr0⟩ := dead_record_chain_has_observational_base e
  exact arith_dead_persists hdead hc (Reachable.trans hr0 hr) x

/-- A Final record, once established on an earlier store, stays final. -/
theorem final_record_persists {cs cs' : Cells} {x : Val} (hf : FinalWith cs x)
    (hr : Reachable cs cs') : FinalWith cs' x :=
  Nat.le_trans hf (holders_reachable_mono x hr)

-- ── route outcome register ────────────────────────────────────────────────

/-- Outcome cells hold Complete (`true`) or Abort (`false`). With five filled
cells one value always has three copies, so no Dead state exists here. -/
def countB (b : Bool) : List Bool → Nat
  | [] => 0
  | x :: xs => (if x = b then 1 else 0) + countB b xs

theorem countB_sum : ∀ l : List Bool, countB true l + countB false l = l.length := by
  intro l
  induction l with
  | nil => rfl
  | cons x xs ih => cases x <;> simp [countB] <;> omega

theorem outcome_register_has_no_dead_state (l : List Bool) (h : l.length = STORAGE_MEMBERS) :
    FINALITY ≤ countB true l ∨ FINALITY ≤ countB false l := by
  have := countB_sum l
  simp [STORAGE_MEMBERS, FINALITY] at h ⊢
  omega

theorem route_outcome_unique (l : List Bool) (h : l.length = STORAGE_MEMBERS) :
    ¬ (FINALITY ≤ countB true l ∧ FINALITY ≤ countB false l) := by
  have := countB_sum l
  simp [STORAGE_MEMBERS, FINALITY] at h ⊢
  omega

-- ── the fulfillment register K_ful(q), the root register K_root(q) ────────

/-- Per-member lists at ONE trader position `q`: the `K_ful(q)` cells, the
`K_root(q)` cells, each member's `Registered(F)` record, one successor key of
the fulfillment's attempt vector, and its outcome register `K_out(F)`. -/
structure Regs where
  kful : Cells
  kroot : Cells
  record : Cells
  cell : Cells
  outcome : Cells

def e5 : Cells := [none, none, none, none, none]

def emptyRegs : Regs := ⟨e5, e5, e5, e5, e5⟩

section Registers

/- `cq f` is the conditional claim `C_q` that fulfillment `f` installs; `ev f`
is the E that `f`'s precommit binds. -/
variable (cq ev : Val → Val)

/-- Member ingress at position `q`. Every write is a single member's local
transaction; peers are read truthfully (F0: no equivocation). -/
inductive RStep : Regs → Regs → Prop
  /-- F ingress: ONE transaction writes `K_ful ↦ f` and `K_root(q) ↦ C_q`;
  a conflicting value in either cell refuses. -/
  | fulfill (s : Regs) (i : Nat) (f : Val)
      (hf : cellAt i s.kful = some none ∨ cellAt i s.kful = some (some f))
      (hr : cellAt i s.kroot = some none ∨ cellAt i s.kroot = some (some (cq f))) :
      RStep s { s with kful := modifyAt (fun c => putCell c f) i s.kful,
                       kroot := modifyAt (fun c => putCell c (cq f)) i s.kroot }
  /-- Any other claim kind at `K_root(q)`: write-once. -/
  | root (s : Regs) (i : Nat) (c : Val) (h : cellAt i s.kroot = some none) :
      RStep s { s with kroot := modifyAt (fun x => putCell x c) i s.kroot }
  /-- A `Registered(F)` record, written after authenticated reads of three holders. -/
  | record (s : Regs) (i : Nat) (f : Val) (h : FinalWith s.kful f) :
      RStep s { s with record := modifyAt (fun x => putCell x f) i s.record }
  /-- A successor cell: admitted only on the member's local registration record,
  and its value is exactly the E of that fulfillment. -/
  | cell (s : Regs) (i : Nat) (f : Val) (h : cellAt i s.record = some (some f)) :
      RStep s { s with cell := modifyAt (fun x => putCell x (ev f)) i s.cell }
  /-- The outcome register: its ingress requires the registration record. -/
  | outcome (s : Regs) (i : Nat) (f b : Val) (h : cellAt i s.record = some (some f)) :
      RStep s { s with outcome := modifyAt (fun x => putCell x b) i s.outcome }

inductive RReach : Regs → Regs → Prop
  | refl (s : Regs) : RReach s s
  | tail {a b c : Regs} : RReach a b → RStep cq ev b c → RReach a c

structure RegInv (s : Regs) : Prop where
  len_kful : s.kful.length = STORAGE_MEMBERS
  len_kroot : s.kroot.length = STORAGE_MEMBERS
  claim_installed : ∀ i f, cellAt i s.kful = some (some f) → cellAt i s.kroot = some (some (cq f))
  record_sound : ∀ i f, cellAt i s.record = some (some f) → FinalWith s.kful f
  cell_sound : ∀ i e, cellAt i s.cell = some (some e) → ∃ f, FinalWith s.kful f ∧ ev f = e
  outcome_sound : ∀ i b, cellAt i s.outcome = some (some b) → ∃ f, FinalWith s.kful f

end Registers


theorem RReach.trans' {cq ev : Val → Val} {a b c : Regs} (h1 : RReach cq ev a b)
    (h2 : RReach cq ev b c) : RReach cq ev a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hs ih => exact RReach.tail ih hs

theorem cellAt_put_some {cs : Cells} {i j : Nat} {v u : Val}
    (h : cellAt j (modifyAt (fun c => putCell c v) i cs) = some (some u)) :
    cellAt j cs = some (some u) ∨ (i = j ∧ cellAt j cs = some none ∧ u = v) := by
  rw [cellAt_modifyAt] at h
  by_cases hij : i = j
  · rw [if_pos hij] at h
    cases hc : cellAt j cs with
    | none => rw [hc] at h; cases h
    | some c =>
      rw [hc] at h
      cases c with
      | none => exact Or.inr ⟨hij, rfl, (Option.some.inj (Option.some.inj h)).symm⟩
      | some w => exact Or.inl h
  · rw [if_neg hij] at h
    exact Or.inl h

theorem final_step_mono {cs : Cells} {x : Val} (i : Nat) (v : Val) (h : FinalWith cs x) :
    FinalWith (modifyAt (fun c => putCell c v) i cs) x :=
  Nat.le_trans h (holders_step_mono x i v cs)

theorem RegInv.step {cq ev : Val → Val} {s s' : Regs} (hi : RegInv cq ev s)
    (hs : RStep cq ev s s') : RegInv cq ev s' := by
  cases hs with
  | fulfill i f hf hr =>
    refine ⟨by simp [length_modifyAt, hi.len_kful], by simp [length_modifyAt, hi.len_kroot], ?_,
      fun j g hj => final_step_mono i f (hi.record_sound j g hj),
      fun j e hj => (hi.cell_sound j e hj).elim fun g ⟨hg, he⟩ => ⟨g, final_step_mono i f hg, he⟩,
      fun j b hj => (hi.outcome_sound j b hj).elim fun g hg => ⟨g, final_step_mono i f hg⟩⟩
    intro j g hj
    rcases cellAt_put_some hj with hold | ⟨hij, _, hg⟩
    · have hroot := hi.claim_installed j g hold
      rw [cellAt_modifyAt]
      split
      · rw [hroot]; rfl
      · exact hroot
    · subst hij; subst hg
      rw [cellAt_modifyAt, if_pos rfl]
      rcases hr with h0 | h1
      · rw [h0]; rfl
      · rw [h1]; rfl
  | root i c h =>
    refine ⟨hi.len_kful, by simp [length_modifyAt, hi.len_kroot], ?_,
      hi.record_sound, hi.cell_sound, hi.outcome_sound⟩
    intro j g hj
    have hroot := hi.claim_installed j g hj
    rw [cellAt_modifyAt]
    split
    · rename_i hij; subst hij; rw [h] at hroot; cases hroot
    · exact hroot
  | record i f h =>
    refine ⟨hi.len_kful, hi.len_kroot, hi.claim_installed, ?_, hi.cell_sound, hi.outcome_sound⟩
    intro j g hj
    rcases cellAt_put_some hj with hold | ⟨_, _, hg⟩
    · exact hi.record_sound j g hold
    · subst hg; exact h
  | cell i f h =>
    refine ⟨hi.len_kful, hi.len_kroot, hi.claim_installed, hi.record_sound, ?_, hi.outcome_sound⟩
    intro j e hj
    rcases cellAt_put_some hj with hold | ⟨_, _, he⟩
    · exact hi.cell_sound j e hold
    · exact ⟨f, hi.record_sound i f h, he.symm⟩
  | outcome i f b h =>
    refine ⟨hi.len_kful, hi.len_kroot, hi.claim_installed, hi.record_sound, hi.cell_sound, ?_⟩
    intro j b' hj
    rcases cellAt_put_some hj with hold | ⟨_, _, _⟩
    · exact hi.outcome_sound j b' hold
    · exact ⟨f, hi.record_sound i f h⟩

theorem cellAt_e5_none : ∀ j, cellAt j e5 = some none ∨ cellAt j e5 = none := by
  intro j
  match j with
  | 0 => exact Or.inl rfl
  | 1 => exact Or.inl rfl
  | 2 => exact Or.inl rfl
  | 3 => exact Or.inl rfl
  | 4 => exact Or.inl rfl
  | _ + 5 => exact Or.inr (by simp [e5, cellAt])

theorem not_some_some_e5 (j : Nat) (u : Val) : cellAt j e5 ≠ some (some u) := by
  rcases cellAt_e5_none j with h | h <;> rw [h] <;> simp

theorem regInv_empty (cq ev : Val → Val) : RegInv cq ev emptyRegs :=
  ⟨rfl, rfl, fun j _ h => absurd h (not_some_some_e5 j _),
    fun j _ h => absurd h (not_some_some_e5 j _),
    fun j _ h => absurd h (not_some_some_e5 j _),
    fun j _ h => absurd h (not_some_some_e5 j _)⟩

theorem RegInv.reach {cq ev : Val → Val} {s s' : Regs} (hi : RegInv cq ev s)
    (hr : RReach cq ev s s') : RegInv cq ev s' := by
  induction hr with
  | refl => exact hi
  | tail _ hs ih => exact ih.step hs

theorem kful_final_persists {cq ev : Val → Val} {s s' : Regs} {f : Val}
    (hr : RReach cq ev s s') (h : FinalWith s.kful f) : FinalWith s'.kful f := by
  induction hr with
  | refl => exact h
  | tail _ hs ih =>
    cases hs with
    | fulfill i g _ _ => exact final_step_mono i g ih
    | root => exact ih
    | record => exact ih
    | cell => exact ih
    | outcome => exact ih

theorem kroot_final_persists {cq ev : Val → Val} {s s' : Regs} {c : Val}
    (hr : RReach cq ev s s') (h : FinalWith s.kroot c) : FinalWith s'.kroot c := by
  induction hr with
  | refl => exact h
  | tail _ hs ih =>
    cases hs with
    | fulfill i g _ _ => exact final_step_mono i (cq g) ih
    | root i d _ => exact final_step_mono i d ih
    | record => exact ih
    | cell => exact ih
    | outcome => exact ih

theorem holders_pos_mem : ∀ (cs : Cells) (v : Val), 0 < holders v cs →
    ∃ j, cellAt j cs = some (some v) := by
  intro cs v
  induction cs with
  | nil => intro h; simp [holders] at h
  | cons c cs ih =>
    intro h
    by_cases hc : c = some v
    · exact ⟨0, by simp [cellAt, hc]⟩
    · simp only [holders, hc, if_false, Nat.zero_add] at h
      obtain ⟨j, hj⟩ := ih h
      exact ⟨j + 1, hj⟩

/-- Two quorums on two registers of the same five members share a member. -/
theorem common_holder : ∀ (xs ys : Cells) (a b : Val), xs.length = ys.length →
    xs.length < holders a xs + holders b ys →
    ∃ j, cellAt j xs = some (some a) ∧ cellAt j ys = some (some b) := by
  intro xs
  induction xs with
  | nil =>
    intro ys a b hl h
    cases ys with
    | nil => simp [holders] at h
    | cons _ _ => simp at hl
  | cons x xs ih =>
    intro ys a b hl h
    cases ys with
    | nil => simp at hl
    | cons y ys =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hl
      by_cases hx : x = some a
      · by_cases hy : y = some b
        · exact ⟨0, by simp [cellAt, hx], by simp [cellAt, hy]⟩
        · simp only [holders, hx, hy, if_true, if_false, List.length_cons] at h
          obtain ⟨j, h1, h2⟩ := ih ys a b hl (by omega)
          exact ⟨j + 1, h1, h2⟩
      · simp only [holders, hx, if_false, List.length_cons] at h
        have hy1 : (if y = some b then 1 else 0) ≤ 1 := by split <;> omega
        obtain ⟨j, h1, h2⟩ := ih ys a b hl (by omega)
        exact ⟨j + 1, h1, h2⟩

/-- AT MOST ONE REGISTERED FULFILLMENT PER POSITION, across every reachable
pair of states (K_ful intersection and write-once). -/
theorem at_most_one_registered_fulfillment_per_position {cq ev : Val → Val} {s s' : Regs}
    (h0 : RReach cq ev emptyRegs s) (hr : RReach cq ev s s') {f f' : Val}
    (h1 : FinalWith s.kful f) (h2 : FinalWith s'.kful f') : f = f' :=
  final_unique_on_key ((regInv_empty cq ev).reach (RReach.trans' h0 hr)).len_kful
    (kful_final_persists hr h1) h2

/-- MUTUAL EXCLUSION: `FulfillmentRegistered(q, F) ∧ EconomicRootRegistered(q, C) ⇒ C = C_q`. -/
theorem fulfillment_and_root_registration_agree {cq ev : Val → Val} {s : Regs}
    (h0 : RReach cq ev emptyRegs s) {f c : Val} (hf : FinalWith s.kful f)
    (hc : FinalWith s.kroot c) : c = cq f := by
  have hi := (regInv_empty cq ev).reach h0
  have hl : s.kful.length = s.kroot.length := by rw [hi.len_kful, hi.len_kroot]
  have hlt : s.kful.length < holders f s.kful + holders c s.kroot := by
    simp [FinalWith, FINALITY] at hf hc; rw [hi.len_kful]; simp [STORAGE_MEMBERS]; omega
  obtain ⟨j, h1, h2⟩ := common_holder s.kful s.kroot f c hl hlt
  rw [hi.claim_installed j f h1] at h2
  exact (Option.some.inj (Option.some.inj h2)).symm

/-- An incompatible trader transition registered at `q` makes every fulfillment
at `q` permanently unregistrable. -/
theorem incompatible_trader_transition_blocks_fulfillment {cq ev : Val → Val} {s s' : Regs}
    (h0 : RReach cq ev emptyRegs s) {c f : Val} (hc : FinalWith s.kroot c) (hne : c ≠ cq f)
    (hr : RReach cq ev s s') : ¬ FinalWith s'.kful f := fun hf =>
  hne (fulfillment_and_root_registration_agree (RReach.trans' h0 hr) hf (kroot_final_persists hr hc))

/-- Exercise is registration: three members hold F. -/
def Exercised (s : Regs) (f : Val) : Prop := FinalWith s.kful f

/-- A registered rival excludes a fulfillment forever. -/
theorem registered_rival_excludes_forever {cq ev : Val → Val} {s s' : Regs}
    (h0 : RReach cq ev emptyRegs s) {f f' : Val} (h' : FinalWith s.kful f') (hne : f ≠ f')
    (hr : RReach cq ev s s') : ¬ FinalWith s'.kful f := fun hf =>
  hne (at_most_one_registered_fulfillment_per_position h0 hr h' hf).symm

/-- THE EXERCISE BOUNDARY, storage side: no successor cell and no outcome
exists anywhere before the fulfillment is registered, and a cell's value is
exactly the registered fulfillment's E. -/
theorem fulfillment_registration_is_exercise_boundary {cq ev : Val → Val} {s : Regs}
    (h0 : RReach cq ev emptyRegs s) :
    (∀ e, 0 < holders e s.cell → ∃ f, FinalWith s.kful f ∧ ev f = e)
      ∧ (∀ b, 0 < holders b s.outcome → ∃ f, FinalWith s.kful f) := by
  have hi := (regInv_empty cq ev).reach h0
  refine ⟨fun e he => ?_, fun b hb => ?_⟩
  · obtain ⟨j, hj⟩ := holders_pos_mem s.cell e he
    exact hi.cell_sound j e hj
  · obtain ⟨j, hj⟩ := holders_pos_mem s.outcome b hb
    exact hi.outcome_sound j b hj

theorem final_e_at_a_leg_implies_registered {cq ev : Val → Val} {s : Regs}
    (h0 : RReach cq ev emptyRegs s) {e : Val} (h : FinalWith s.cell e) :
    ∃ f, FinalWith s.kful f ∧ ev f = e :=
  (fulfillment_registration_is_exercise_boundary h0).1 e (by simp [FinalWith, FINALITY] at h; omega)

theorem outcome_final_implies_registered {cq ev : Val → Val} {s : Regs}
    (h0 : RReach cq ev emptyRegs s) {b : Val} (h : FinalWith s.outcome b) :
    ∃ f, FinalWith s.kful f :=
  (fulfillment_registration_is_exercise_boundary h0).2 b (by simp [FinalWith, FINALITY] at h; omega)

/-- Holding F is not registration: a member holding F and cells gated on that
alone would admit E for a fulfillment that a rival beat. -/
theorem holding_f_is_not_registration :
    cellAt 0 [some 1, some 2, some 2, some 2, none] = some (some 1)
      ∧ FinalWith [some 1, some 2, some 2, some 2, none] 2
      ∧ ¬ FinalWith [some 1, some 2, some 2, some 2, none] 1 := by
  decide

/-- ONE-MEMBER PUBLICATION IS NOT EXERCISE (R11-4). F reaches one member; a
conflicting F′ from the same T0 registers on three others; F never registers. -/
theorem one_member_publication_is_not_exercise :
    ∃ s s', RReach id id emptyRegs s ∧ holders 1 s.kful = 1
      ∧ RReach id id s s' ∧ Exercised s' 2
      ∧ ∀ s'', RReach id id s' s'' → ¬ Exercised s'' 1 := by
  let s1 : Regs := { emptyRegs with kful := modifyAt (fun c => putCell c 1) 0 e5,
                                    kroot := modifyAt (fun c => putCell c 1) 0 e5 }
  let s2 : Regs := { s1 with kful := modifyAt (fun c => putCell c 2) 1 s1.kful,
                             kroot := modifyAt (fun c => putCell c 2) 1 s1.kroot }
  let s3 : Regs := { s2 with kful := modifyAt (fun c => putCell c 2) 2 s2.kful,
                             kroot := modifyAt (fun c => putCell c 2) 2 s2.kroot }
  let s4 : Regs := { s3 with kful := modifyAt (fun c => putCell c 2) 3 s3.kful,
                             kroot := modifyAt (fun c => putCell c 2) 3 s3.kroot }
  have r1 : RReach id id emptyRegs s1 :=
    .tail (.refl _) (RStep.fulfill emptyRegs 0 1 (Or.inl rfl) (Or.inl rfl))
  have r4 : RReach id id s1 s4 :=
    .tail (.tail (.tail (.refl _) (RStep.fulfill s1 1 2 (Or.inl rfl) (Or.inl rfl)))
      (RStep.fulfill s2 2 2 (Or.inl rfl) (Or.inl rfl))) (RStep.fulfill s3 3 2 (Or.inl rfl) (Or.inl rfl))
  have hf4 : FinalWith s4.kful 2 := by decide
  refine ⟨s1, s4, r1, by decide, r4, hf4, ?_⟩
  intro s'' hr
  unfold Exercised
  exact registered_rival_excludes_forever (RReach.trans' r1 r4) hf4 (by decide) hr

-- ── the attempt walk ──────────────────────────────────────────────────────

inductive Validation where
  | valid
  | invalid
  | unavailable
  deriving DecidableEq, Repr

/-- The facts about ONE vault parent's attempt chain that a verifier has
established. Storage facts (`keyFinal`, `keyDead`, outcomes) and semantic facts
(`validation`, `orphanLeg`, `consumedElsewhere`) are separate fields; nothing
here is a clock. -/
structure World where
  keyFinal : Nat → Option Val
  keyDead : Nat → Bool
  isRoute : Val → Bool
  validation : Val → Validation
  orphanLeg : Val → Bool
  consumedElsewhere : Val → Bool
  outcomeComplete : Val → Bool
  outcomeAbort : Val → Bool
  /-- Arm (iv), P15-3/R17-3: the operation's own TRADER parent at `p` is
  terminal on another branch, or on none. It is a fact about the trader's
  lineage, not about this vault, and it reads no validation evidence. -/
  traderParentImpossible : Val → Bool := fun _ => false
  canonicalParent : Bool

/-- Storage coherence the cell layer proves: a final key is never dead, and an
outcome register holds at most one final value. -/
structure Coherent (w : World) : Prop where
  final_not_dead : ∀ a e, w.keyFinal a = some e → w.keyDead a = false
  outcome_unique : ∀ e, ¬ (w.outcomeComplete e = true ∧ w.outcomeAbort e = true)

/-- R7-17 / P9-2: permanent proof that a route can never be consumed.
Only Invalid counts; Unavailable never does. Arm (iv) is the trader parent
(P15-3), which likewise needs no evidence. -/
def RouteImpossible (w : World) (e : Val) : Bool :=
  w.validation e == .invalid || w.orphanLeg e || w.consumedElsewhere e
    || w.traderParentImpossible e

/-- A storage-final E at a DLV key is skippable only on objective evidence. -/
def finalSkippable (w : World) (e : Val) : Bool :=
  if w.isRoute e then RouteImpossible w e || w.outcomeAbort e
  else w.validation e == .invalid

def Skipped (w : World) (a : Nat) : Bool :=
  w.keyDead a || (w.keyFinal a).any (finalSkippable w)

def AttemptLive (w : World) (a : Nat) : Prop := ∀ b, b < a → Skipped w b = true

def Consumed (w : World) (a : Nat) (e : Val) : Prop :=
  w.canonicalParent = true ∧ AttemptLive w a ∧ w.keyFinal a = some e
    ∧ w.validation e = .valid
    ∧ (w.isRoute e = true →
        w.outcomeComplete e = true ∧ w.orphanLeg e = false ∧ w.consumedElsewhere e = false
          ∧ w.traderParentImpossible e = false)

theorem consumed_not_skipped {w : World} (hc : Coherent w) {a : Nat} {e : Val}
    (h : Consumed w a e) : Skipped w a = false := by
  obtain ⟨_, _, hf, hv, hr⟩ := h
  have hd := hc.final_not_dead a e hf
  have hfs : finalSkippable w e = false := by
    unfold finalSkippable
    by_cases hroute : w.isRoute e = true
    · obtain ⟨hcomp, horph, hce, htp⟩ := hr hroute
      have hab : w.outcomeAbort e = false := by
        cases hx : w.outcomeAbort e
        · rfl
        · exact absurd ⟨hcomp, hx⟩ (hc.outcome_unique e)
      rw [if_pos hroute]
      simp [RouteImpossible, hv, horph, hce, hab, htp]
    · rw [if_neg hroute, hv]
      decide
  show (w.keyDead a || (w.keyFinal a).any (finalSkippable w)) = false
  rw [hd, hf]
  exact hfs

/-- ONE CONSUMER PER PARENT across the whole attempt chain. -/
theorem walk_consumes_at_most_once {w : World} (hc : Coherent w) {a1 a2 : Nat} {e1 e2 : Val}
    (h1 : Consumed w a1 e1) (h2 : Consumed w a2 e2) : a1 = a2 ∧ e1 = e2 := by
  have hlt : ∀ {x y ex ey}, Consumed w x ex → Consumed w y ey → ¬ x < y := by
    intro x y ex ey hx hy hxy
    have hs := hy.2.1 x hxy
    rw [consumed_not_skipped hc hx] at hs
    exact Bool.false_ne_true hs
  have ha : a1 = a2 := by
    rcases Nat.lt_trichotomy a1 a2 with h | h | h
    · exact absurd h (hlt h1 h2)
    · exact h
    · exact absurd h (hlt h2 h1)
  subst ha
  have := h1.2.2.1.symm.trans h2.2.2.1
  exact ⟨rfl, Option.some.inj this⟩

theorem consumed_requires_attempt_live {w : World} {a : Nat} {e : Val}
    (h : Consumed w a e) : AttemptLive w a := h.2.1

/-- The same predicate without `AttemptLive` consumes one parent twice: a valid
final at attempt 0 and another final at attempt 1. -/
def ConsumedNoLive (w : World) (a : Nat) (e : Val) : Prop :=
  w.canonicalParent = true ∧ w.keyFinal a = some e ∧ w.validation e = .valid ∧ w.isRoute e = false

def twoFinals : World where
  keyFinal := fun a => if a = 0 then some 10 else if a = 1 then some 11 else none
  keyDead := fun _ => false
  isRoute := fun _ => false
  validation := fun _ => .valid
  orphanLeg := fun _ => false
  consumedElsewhere := fun _ => false
  outcomeComplete := fun _ => false
  outcomeAbort := fun _ => false
  canonicalParent := true

theorem attempt_live_is_load_bearing :
    ConsumedNoLive twoFinals 0 10 ∧ ConsumedNoLive twoFinals 1 11 ∧ (10 : Val) ≠ 11 := by
  simp [ConsumedNoLive, twoFinals]

theorem objective_rejection_implies_skipped (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e)
    (hobj : (w.isRoute e = false ∧ w.validation e = .invalid)
      ∨ (w.isRoute e = true ∧ RouteImpossible w e = true)) :
    Skipped w a = true := by
  have hfs : finalSkippable w e = true := by
    unfold finalSkippable
    rcases hobj with ⟨hr, hv⟩ | ⟨hr, hi⟩
    · rw [if_neg (by rw [hr]; decide), hv]
      decide
    · rw [if_pos hr, hi]
      rfl
  show (w.keyDead a || (w.keyFinal a).any (finalSkippable w)) = true
  rw [hf]
  show (w.keyDead a || finalSkippable w e) = true
  rw [hfs, Bool.or_true]

/-- R7-17: a finalized leg of an impossible route is skippable with NO
Complete premise. -/
theorem route_impossible_final_leg_is_skippable (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hroute : w.isRoute e = true)
    (himp : RouteImpossible w e = true) : Skipped w a = true :=
  objective_rejection_implies_skipped w a e hf (Or.inr ⟨hroute, himp⟩)

/-- ARM (iv) (P15-3, R17-3): a storage-final route cell whose TRADER parent is
terminal on another branch — or on none — is skippable, with NO validation
evidence and no Complete premise. Nothing rolls back: the cell was never an
execution of its own, and the trader position is Invalid by the ladder's rung 2
rather than Void. -/
theorem trader_parent_impossible_makes_a_final_route_skippable (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hroute : w.isRoute e = true)
    (htp : w.traderParentImpossible e = true)
    -- Deliberately unused: the arm decides with the evidence still missing.
    (_hun : w.validation e = .unavailable) : Skipped w a = true :=
  route_impossible_final_leg_is_skippable w a e hf hroute (by simp [RouteImpossible, htp])

/-- The rejected alternative: gating route skip on Complete. -/
def SkippedGated (w : World) (a : Nat) : Bool :=
  w.keyDead a || (w.keyFinal a).any (fun e =>
    if w.isRoute e then (RouteImpossible w e && w.outcomeComplete e) || w.outcomeAbort e
    else w.validation e == .invalid)

/-- A withheld leg: attempt 0 holds route E whose other leg's parent was consumed
elsewhere, and whose outcome never resolves. -/
def withheld : World where
  keyFinal := fun a => if a = 0 then some 20 else if a = 1 then some 21 else none
  keyDead := fun _ => false
  isRoute := fun e => e == 20
  validation := fun _ => .valid
  orphanLeg := fun _ => false
  consumedElsewhere := fun e => e == 20
  outcomeComplete := fun _ => false
  outcomeAbort := fun _ => false
  canonicalParent := true

theorem withheld_leg_recovers_under_R7_17 :
    Skipped withheld 0 = true ∧ Consumed withheld 1 21 := by
  refine ⟨by decide, ?_⟩
  refine ⟨rfl, ?_, rfl, rfl, ?_⟩
  · intro b hb
    have : b = 0 := by omega
    subst this; decide
  · intro h; simp [withheld] at h

theorem withheld_leg_wedges_if_gated_on_complete :
    SkippedGated withheld 0 = false := by decide

-- ── evolution: facts only become more resolved ────────────────────────────

def ValidationRefines : Validation → Validation → Prop
  | .unavailable, _ => True
  | v, v' => v = v'

structure Evolves (w w' : World) : Prop where
  final_stays : ∀ a e, w.keyFinal a = some e → w'.keyFinal a = some e
  dead_stays : ∀ a, w.keyDead a = true → w'.keyDead a = true
  route_fixed : ∀ e, w'.isRoute e = w.isRoute e
  validation_refines : ∀ e, ValidationRefines (w.validation e) (w'.validation e)
  orphan_stays : ∀ e, w.orphanLeg e = true → w'.orphanLeg e = true
  consumed_elsewhere_stays : ∀ e, w.consumedElsewhere e = true → w'.consumedElsewhere e = true
  abort_stays : ∀ e, w.outcomeAbort e = true → w'.outcomeAbort e = true
  /-- A terminal trader parent never retracts. -/
  trader_parent_stays : ∀ e, w.traderParentImpossible e = true →
    w'.traderParentImpossible e = true := by intro _ h; exact h

theorem invalid_stays {w w' : World} (hev : Evolves w w') {e : Val}
    (h : w.validation e = .invalid) : w'.validation e = .invalid := by
  have := hev.validation_refines e
  rw [h] at this
  exact this.symm

theorem route_impossibility_is_permanent {w w' : World} (hev : Evolves w w') {e : Val}
    (h : RouteImpossible w e = true) : RouteImpossible w' e = true := by
  unfold RouteImpossible at *
  simp only [Bool.or_eq_true, beq_iff_eq] at *
  rcases h with ((h | h) | h) | h
  · exact Or.inl (Or.inl (Or.inl (invalid_stays hev h)))
  · exact Or.inl (Or.inl (Or.inr (hev.orphan_stays e h)))
  · exact Or.inl (Or.inr (hev.consumed_elsewhere_stays e h))
  · exact Or.inr (hev.trader_parent_stays e h)

theorem final_skippable_is_monotone {w w' : World} (hev : Evolves w w') {e : Val}
    (h : finalSkippable w e = true) : finalSkippable w' e = true := by
  unfold finalSkippable at *
  rw [hev.route_fixed e]
  by_cases hr : w.isRoute e = true
  · rw [if_pos hr] at h ⊢
    rcases Bool.or_eq_true_iff.mp h with hi | ha
    · rw [route_impossibility_is_permanent hev hi, Bool.true_or]
    · rw [hev.abort_stays e ha, Bool.or_true]
  · rw [if_neg hr] at h ⊢
    exact beq_iff_eq.mpr (invalid_stays hev (beq_iff_eq.mp h))

theorem rejected_final_is_monotone {w w' : World} (hev : Evolves w w') {a : Nat}
    (h : Skipped w a = true) : Skipped w' a = true := by
  unfold Skipped at *
  rcases Bool.or_eq_true_iff.mp h with hd | hm
  · rw [hev.dead_stays a hd, Bool.true_or]
  · cases hf : w.keyFinal a with
    | none => rw [hf] at hm; exact absurd hm Bool.false_ne_true
    | some e =>
      rw [hf] at hm
      rw [hev.final_stays a e hf]
      show (w'.keyDead a || finalSkippable w' e) = true
      rw [final_skippable_is_monotone hev hm, Bool.or_true]

theorem unavailable_never_establishes_route_impossibility (w : World) (e : Val)
    (hu : w.validation e = .unavailable) (ho : w.orphanLeg e = false)
    (hc : w.consumedElsewhere e = false) (htp : w.traderParentImpossible e = false) :
    RouteImpossible w e = false := by
  simp [RouteImpossible, hu, ho, hc, htp]

theorem validation_unavailable_never_implies_rejection (w : World) (a : Nat) (e : Val)
    (hf : w.keyFinal a = some e) (hsingle : w.isRoute e = false)
    (hnd : w.keyDead a = false) (hu : w.validation e = .unavailable) :
    Skipped w a = false := by
  show (w.keyDead a || (w.keyFinal a).any (finalSkippable w)) = false
  rw [hnd, hf]
  show finalSkippable w e = false
  unfold finalSkippable
  rw [if_neg (by rw [hsingle]; decide), hu]
  decide

-- ── the walk and its computational budget ─────────────────────────────────

inductive WalkResult where
  | consumed (a : Nat)
  | unresolved (a : Nat)
  | continueAt (a : Nat)
  deriving DecidableEq, Repr

def walkFrom (consumable skipped : Nat → Bool) : Nat → Nat → WalkResult
  | 0, a => .continueAt a
  | fuel + 1, a =>
    if consumable a then .consumed a
    else if skipped a then walkFrom consumable skipped fuel (a + 1)
    else .unresolved a

def resume (consumable skipped : Nat → Bool) (m : Nat) : WalkResult → WalkResult
  | .continueAt c => walkFrom consumable skipped m c
  | r => r

/-- WALK_MAX_ATTEMPTS is a budget only: two chunks of `n` and `m` equal one walk
of `n + m`. -/
theorem walk_chunking_preserves_result (consumable skipped : Nat → Bool) :
    ∀ n m a, resume consumable skipped m (walkFrom consumable skipped n a)
      = walkFrom consumable skipped (n + m) a := by
  intro n
  induction n with
  | zero => intro m a; simp [walkFrom, resume]
  | succ n ih =>
    intro m a
    rw [Nat.succ_add]
    simp only [walkFrom]
    split
    · rfl
    · split
      · exact ih m (a + 1)
      · rfl

-- ── storage ordering projection: no numeric holes ─────────────────────────

/-- Storage admits a cell at attempt `a > 0` only when it holds a resolution
record for `a - 1`, and a record exists only where cells were written. -/
structure StorageOrdering (written record : Nat → Bool) : Prop where
  admit : ∀ a, written (a + 1) = true → record a = true
  record_needs_cells : ∀ a, record a = true → written a = true

theorem storage_forbids_numeric_holes {written record : Nat → Bool}
    (h : StorageOrdering written record) :
    ∀ a, written a = true → ∀ b, b ≤ a → written b = true := by
  intro a
  induction a with
  | zero => intro hw b hb; have : b = 0 := by omega
            subst this; exact hw
  | succ a ih =>
    intro hw b hb
    rcases Nat.lt_or_eq_of_le hb with hlt | heq
    · exact ih (h.record_needs_cells a (h.admit a hw)) b (by omega)
    · subst heq; exact hw

/-- Without the projection, a write at a huge attempt index exists with nothing
before it. -/
theorem index_skip_without_projection :
    ∃ written : Nat → Bool, written 500000 = true ∧ written 0 = false :=
  ⟨fun a => a == 500000, by decide, by decide⟩

-- ── checked counters ──────────────────────────────────────────────────────

def U64_MAX : Nat := 2 ^ 64 - 1

def checkedNext (p : Nat) : Option Nat := if p < U64_MAX then some (p + 1) else none

theorem checked_counters_never_wrap :
    (∀ p q, checkedNext p = some q → q = p + 1 ∧ q ≤ U64_MAX) ∧ checkedNext U64_MAX = none := by
  refine ⟨?_, by simp [checkedNext]⟩
  intro p q h
  unfold checkedNext at h
  split at h
  · cases h; constructor
    · rfl
    · omega
  · cases h

-- ── StorageReachable: a noncanonical DAG, never authority ─────────────────

/-- Roots as terms. A child root is determined by its parent and E; the attempt
index is routing metadata and is not an input. -/
inductive Root where
  | genesis (vault : Nat)
  | child (parent : Root) (e : Val)
  deriving DecidableEq, Repr

def generation : Root → Nat
  | .genesis _ => 0
  | .child p _ => generation p + 1

inductive StorageReachable (finalAt : Root → Val → Prop) : Root → Prop
  | genesis (v : Nat) : StorageReachable finalAt (.genesis v)
  | child {r : Root} {e : Val} : StorageReachable finalAt r → finalAt r e →
      StorageReachable finalAt (.child r e)

/-- The producer of a root, from `(parent, E)` only. -/
def produce (parent : Root) (_attempt : Nat) (e : Val) : Root := .child parent e

theorem storage_reachable_producer_identity_excludes_attempt (r : Root) (e : Val) (a a' : Nat) :
    produce r a e = produce r a' e := rfl

theorem storage_reachable_producer_unique {r r' : Root} {e e' : Val}
    (h : Root.child r e = Root.child r' e') : r = r' ∧ e = e' := by
  cases h; exact ⟨rfl, rfl⟩

theorem storage_reachable_generation_acyclic (r : Root) (e : Val) :
    generation (.child r e) = generation r + 1 ∧ Root.child r e ≠ r := by
  refine ⟨rfl, ?_⟩
  intro h
  have := congrArg generation h
  simp [generation] at this

/-- Two storage-final candidates at one parent both produce StorageReachable
roots; at most one of them is canonical. -/
theorem storage_reachable_does_not_imply_canonical :
    let finalAt : Root → Val → Prop := fun r e => r = .genesis 0 ∧ (e = 1 ∨ e = 2)
    StorageReachable finalAt (.child (.genesis 0) 1)
      ∧ StorageReachable finalAt (.child (.genesis 0) 2)
      ∧ Root.child (.genesis 0) 1 ≠ Root.child (.genesis 0) 2 := by
  refine ⟨.child (.genesis 0) ⟨rfl, Or.inl rfl⟩, .child (.genesis 0) ⟨rfl, Or.inr rfl⟩, ?_⟩
  decide

#print axioms cellAt_modifyAt
#print axioms length_modifyAt
#print axioms held_cell_cannot_change
#print axioms holders_step_mono
#print axioms holders_reachable_mono
#print axioms length_reachable
#print axioms holders_disjoint
#print axioms final_unique_on_key
#print axioms final_unique_across_reachable_states
#print axioms Reachable.trans
#print axioms obsHolders_zero_of_not_mem
#print axioms le_maxHeld
#print axioms obsHolders_le_maxHeld
#print axioms holders_le_of_compatible
#print axioms arith_dead_sound_with_unread
#print axioms compatible_step
#print axioms compatible_persists
#print axioms arith_dead_persists
#print axioms final_key_never_dead
#print axioms two_two_one_is_dead
#print axioms two_two_unknown_is_not_dead
#print axioms garbage_is_never_empty
#print axioms classify_keeps_every_member
#print axioms dropping_garbage_breaks_soundness
#print axioms empty_and_unknown_are_arithmetically_equal
#print axioms equivocating_member_breaks_three_of_five
#print axioms permanent_store_loss_breaks_historical_finality
#print axioms dead_record_chain_has_observational_base
#print axioms resolution_record_sound
#print axioms final_record_persists
#print axioms countB_sum
#print axioms outcome_register_has_no_dead_state
#print axioms route_outcome_unique
#print axioms RReach.trans'
#print axioms cellAt_put_some
#print axioms final_step_mono
#print axioms RegInv.step
#print axioms cellAt_e5_none
#print axioms not_some_some_e5
#print axioms regInv_empty
#print axioms RegInv.reach
#print axioms kful_final_persists
#print axioms kroot_final_persists
#print axioms holders_pos_mem
#print axioms common_holder
#print axioms at_most_one_registered_fulfillment_per_position
#print axioms fulfillment_and_root_registration_agree
#print axioms incompatible_trader_transition_blocks_fulfillment
#print axioms registered_rival_excludes_forever
#print axioms fulfillment_registration_is_exercise_boundary
#print axioms final_e_at_a_leg_implies_registered
#print axioms outcome_final_implies_registered
#print axioms holding_f_is_not_registration
#print axioms one_member_publication_is_not_exercise
#print axioms consumed_not_skipped
#print axioms walk_consumes_at_most_once
#print axioms consumed_requires_attempt_live
#print axioms attempt_live_is_load_bearing
#print axioms objective_rejection_implies_skipped
#print axioms route_impossible_final_leg_is_skippable
#print axioms trader_parent_impossible_makes_a_final_route_skippable
#print axioms withheld_leg_recovers_under_R7_17
#print axioms withheld_leg_wedges_if_gated_on_complete
#print axioms invalid_stays
#print axioms route_impossibility_is_permanent
#print axioms final_skippable_is_monotone
#print axioms rejected_final_is_monotone
#print axioms unavailable_never_establishes_route_impossibility
#print axioms validation_unavailable_never_implies_rejection
#print axioms walk_chunking_preserves_result
#print axioms storage_forbids_numeric_holes
#print axioms index_skip_without_projection
#print axioms checked_counters_never_wrap
#print axioms storage_reachable_producer_identity_excludes_attempt
#print axioms storage_reachable_producer_unique
#print axioms storage_reachable_generation_acyclic
#print axioms storage_reachable_does_not_imply_canonical

end DSMSofiSuccessorCells
