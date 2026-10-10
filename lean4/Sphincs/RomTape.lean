-- SPDX-License-Identifier: MIT OR Apache-2.0

/- Random tapes for the random-oracle model (ROM). An idealized random
   oracle answers each fresh request with the next entry of a uniformly random
   tape. `tsum R Q F` is the sum of `F` over all `R^Q` tapes of `Q` entries in
   `[0, R)`; a probability is a count divided by `R^Q`. Everything here is
   exact counting over Nat, Lean core only. This module models an idealized
   oracle, not BLAKE3. -/
namespace DSM.Rom

/-- Sum of `F` over every tape of `Q` entries, each in `[0, R)`. -/
def tsum (R : Nat) : Nat → (List Nat → Nat) → Nat
  | 0, F => F []
  | Q+1, F => ((List.range R).map (fun y => tsum R Q (fun t => F (y :: t)))).sum

/-! List sums. -/

theorem sum_map_le {α : Type} (l : List α) {f g : α → Nat} (h : ∀ a ∈ l, f a ≤ g a) :
    (l.map f).sum ≤ (l.map g).sum := by
  induction l with
  | nil => simp
  | cons a l ih =>
    simp only [List.map_cons, List.sum_cons]
    exact Nat.add_le_add (h a (by simp)) (ih (fun b hb => h b (by simp [hb])))

theorem sum_map_add {α : Type} (l : List α) (f g : α → Nat) :
    (l.map (fun a => f a + g a)).sum = (l.map f).sum + (l.map g).sum := by
  induction l with
  | nil => simp
  | cons a l ih => simp only [List.map_cons, List.sum_cons, ih]; omega

theorem sum_map_mul {α : Type} (l : List α) (c : Nat) (f : α → Nat) :
    (l.map (fun a => c * f a)).sum = c * (l.map f).sum := by
  induction l with
  | nil => simp
  | cons a l ih => simp only [List.map_cons, List.sum_cons, ih, Nat.mul_add]

theorem sum_map_const {α : Type} (l : List α) (c : Nat) :
    (l.map (fun _ => c)).sum = l.length * c := by
  induction l with
  | nil => simp
  | cons a l ih => simp only [List.map_cons, List.sum_cons, ih, List.length_cons, Nat.succ_mul]; omega

theorem sum_map_zero {α : Type} (l : List α) : (l.map (fun _ => (0 : Nat))).sum = 0 := by
  rw [sum_map_const]; simp

theorem len_filter_eq_sum {β : Type} (C : List β) (f : β → Bool) :
    (C.filter f).length = (C.map (fun c => if f c then 1 else 0)).sum := by
  induction C with
  | nil => simp
  | cons c C ih =>
    simp only [List.filter_cons, List.map_cons, List.sum_cons]
    split <;> simp [ih] <;> omega

/-- Double counting: matches of each `y` against a list, summed over `y`, is
    the same as matches of each list element, summed over the list. -/
theorem double_count {α β : Type} (Y : List α) (C : List β) (P : α → β → Bool) :
    (Y.map (fun y => (C.filter (P y)).length)).sum =
      (C.map (fun c => (Y.filter (fun y => P y c)).length)).sum := by
  induction Y with
  | nil => simp only [List.map_nil, List.sum_nil, List.filter_nil, List.length_nil]; rw [sum_map_zero]
  | cons y Y ih =>
    simp only [List.map_cons, List.sum_cons]
    have step : ∀ c, ((List.filter (fun y => P y c) (y :: Y)).length) =
        (if P y c then 1 else 0) + (Y.filter (fun y => P y c)).length := by
      intro c; simp only [List.filter_cons]; split <;> simp <;> omega
    simp only [step, sum_map_add]
    rw [ih, len_filter_eq_sum C (P y)]

/-! Basic facts about `tsum`. -/

theorem tsum_mono (R : Nat) : ∀ (Q : Nat) {F G : List Nat → Nat}, (∀ t, F t ≤ G t) →
    tsum R Q F ≤ tsum R Q G
  | 0, _, _, h => h []
  | Q+1, _, _, h => sum_map_le _ (fun y _ => tsum_mono R Q (fun t => h (y :: t)))

theorem tsum_add (R : Nat) : ∀ (Q : Nat) (F G : List Nat → Nat),
    tsum R Q (fun t => F t + G t) = tsum R Q F + tsum R Q G
  | 0, _, _ => rfl
  | Q+1, F, G => by
    simp only [tsum]
    rw [← sum_map_add]
    congr 1
    apply List.map_congr_left
    intro y _
    exact tsum_add R Q (fun t => F (y :: t)) (fun t => G (y :: t))

theorem tsum_mul (R : Nat) (c : Nat) : ∀ (Q : Nat) (F : List Nat → Nat),
    tsum R Q (fun t => c * F t) = c * tsum R Q F
  | 0, _ => rfl
  | Q+1, F => by
    simp only [tsum]
    rw [← sum_map_mul]
    congr 1
    apply List.map_congr_left
    intro y _
    exact tsum_mul R c Q (fun t => F (y :: t))

theorem tsum_const (R c : Nat) : ∀ (Q : Nat), tsum R Q (fun _ => c) = R^Q * c
  | 0 => by simp [tsum]
  | Q+1 => by
    simp only [tsum, tsum_const R c Q, sum_map_const, List.length_range, Nat.pow_succ]
    rw [Nat.mul_comm (R^Q) R, Nat.mul_assoc, Nat.mul_comm R]

theorem tsum_list (R : Nat) (Q : Nat) {α : Type} (l : List α) (F : α → List Nat → Nat) :
    tsum R Q (fun t => (l.map (fun a => F a t)).sum) = (l.map (fun a => tsum R Q (F a))).sum := by
  induction l with
  | nil => simp only [List.map_nil, List.sum_nil]; rw [tsum_const]; simp
  | cons a l ih =>
    simp only [List.map_cons, List.sum_cons]
    rw [tsum_add, ih]

/-! One fresh entry against values fixed before it is drawn. -/

/-- Among `R` consecutive values starting at 0, at most `R / M` have a given
    residue mod `M` (when `M ∣ R`). -/
theorem count_mod (M c : Nat) (hM : 0 < M) : ∀ d : Nat,
    ((List.range (M*d)).filter (fun y => y % M == c % M)).length ≤ d
  | 0 => by simp
  | d+1 => by
    have split : M * (d+1) = M*d + M := by rw [Nat.mul_succ]
    rw [split, List.range_add, List.filter_append, List.length_append]
    have ih := count_mod M c hM d
    have one : (((List.range M).map (fun z => M*d + z)).filter (fun y => y % M == c % M)).length ≤ 1 := by
      rw [List.filter_map, List.length_map]
      have hz : ∀ z ∈ List.range M, ((fun y => y % M == c % M) ∘ (fun z => M*d + z)) z = (z == c % M) := by
        intro z hz
        have hz' : z < M := List.mem_range.mp hz
        simp only [Function.comp, Nat.mul_add_mod, Nat.mod_eq_of_lt hz']
      rw [List.filter_congr hz]
      have nd := List.nodup_range (n := M)
      generalize List.range M = l at nd
      induction l with
      | nil => simp
      | cons x l ihl =>
        rw [List.nodup_cons] at nd
        simp only [List.filter_cons]
        split
        · next hx =>
          have hx' : x = c % M := by simpa using hx
          have : l.filter (fun z => z == c % M) = [] := by
            rw [List.filter_eq_nil_iff]
            intro z hz hzc
            have : z = c % M := by simpa using hzc
            exact nd.1 (hx' ▸ this ▸ hz)
          simp [this]
        · exact ihl nd.2
    omega

/-- The weighted fresh-entry bound: the entry at position `j` matches, mod
    `M`, one of the targets `G` computed from the entries before it, at most a
    `1/M` fraction of the time per target. -/
theorem fresh_hits (R M : Nat) (hM : 0 < M) (hMR : M ∣ R) : ∀ (j Q : Nat), j < Q →
    ∀ (G : List Nat → List Nat),
    tsum R Q (fun t => ((G (t.take j)).filter (fun c => (t.getD j 0) % M == c % M)).length) * M
      ≤ tsum R Q (fun t => (G (t.take j)).length)
  | _, 0, h, _ => absurd h (Nat.not_lt_zero _)
  | 0, Q+1, _, G => by
    simp only [tsum, List.take_zero, List.getD_cons_zero, tsum_const]
    rw [sum_map_mul, sum_map_mul, sum_map_const, List.length_range, double_count]
    obtain ⟨d, hd⟩ := hMR
    have each : ∀ c, ((List.range R).filter (fun y => y % M == c % M)).length * M ≤ R := by
      intro c
      rw [hd]
      have := count_mod M c hM d
      calc _ ≤ d * M := Nat.mul_le_mul_right _ this
        _ = M * d := Nat.mul_comm _ _
    have key : ((G []).map (fun c => ((List.range R).filter (fun y => y % M == c % M)).length)).sum * M
        ≤ R * (G []).length := by
      generalize G [] = C
      induction C with
      | nil => simp
      | cons c C ih =>
        simp only [List.map_cons, List.sum_cons, Nat.add_mul, List.length_cons, Nat.mul_succ]
        have := each c
        omega
    calc R^Q * _ * M = R^Q * (_ * M) := Nat.mul_assoc _ _ _
      _ ≤ R^Q * (R * (G []).length) := Nat.mul_le_mul_left _ key
  | j+1, Q+1, h, G => by
    simp only [tsum]
    rw [Nat.mul_comm, ← sum_map_mul]
    apply sum_map_le
    intro y _
    have ih := fresh_hits R M hM hMR j Q (by omega) (fun p => G (y :: p))
    rw [Nat.mul_comm]
    simpa only [List.take_succ_cons, List.getD_cons_succ] using ih

theorem le_sum_of_mem {l : List Nat} {a : Nat} (h : a ∈ l) : a ≤ l.sum := by
  induction l with
  | nil => simp at h
  | cons b l ih =>
    simp only [List.sum_cons]
    rcases List.mem_cons.mp h with e | m
    · subst e; omega
    · have := ih m; omega

theorem getD_take {t : List Nat} {i j : Nat} (h : i < j) : (t.take j).getD i 0 = t.getD i 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_take, h, if_true]

/-- Partner hits: each fresh entry `j` is compared, mod `M`, with the earlier
    entries `S j` names (chosen from the entries before it). The fraction of
    tapes where any comparison matches is at most `B / M`, where `B` bounds
    the total number of comparisons on every tape. -/
theorem partner_hits (R M Q B : Nat) (hM : 0 < M) (hMR : M ∣ R)
    (S : Nat → List Nat → List Nat) (hS : ∀ j p i, i ∈ S j p → i < j)
    (hB : ∀ t : List Nat, ((List.range Q).map (fun j => (S j (t.take j)).length)).sum ≤ B) :
    tsum R Q (fun t => if (List.range Q).any (fun j => (S j (t.take j)).any
        (fun i => t.getD j 0 % M == t.getD i 0 % M)) then 1 else 0) * M ≤ R^Q * B := by
  let G : Nat → List Nat → List Nat := fun j p => (S j p).map (fun i => p.getD i 0)
  have point : ∀ t : List Nat, (if (List.range Q).any (fun j => (S j (t.take j)).any
        (fun i => t.getD j 0 % M == t.getD i 0 % M)) then 1 else 0) ≤
      ((List.range Q).map (fun j => ((G j (t.take j)).filter
        (fun c => t.getD j 0 % M == c % M)).length)).sum := by
    intro t
    split
    · next h =>
      obtain ⟨j, hj, hany⟩ := List.any_eq_true.mp h
      obtain ⟨i, hi, heq⟩ := List.any_eq_true.mp hany
      have hij := hS j _ i hi
      have mem : (t.take j).getD i 0 ∈ (G j (t.take j)).filter (fun c => t.getD j 0 % M == c % M) := by
        rw [List.mem_filter]
        refine ⟨List.mem_map.mpr ⟨i, hi, rfl⟩, ?_⟩
        rw [getD_take hij]; exact heq
      have pos : 1 ≤ ((G j (t.take j)).filter (fun c => t.getD j 0 % M == c % M)).length :=
        List.length_pos_of_mem mem
      exact Nat.le_trans pos (le_sum_of_mem (List.mem_map.mpr ⟨j, hj, rfl⟩))
    · exact Nat.zero_le _
  calc _ ≤ tsum R Q (fun t => ((List.range Q).map (fun j => ((G j (t.take j)).filter
          (fun c => t.getD j 0 % M == c % M)).length)).sum) * M :=
        Nat.mul_le_mul_right _ (tsum_mono R Q point)
    _ = ((List.range Q).map (fun j => tsum R Q (fun t => ((G j (t.take j)).filter
          (fun c => t.getD j 0 % M == c % M)).length) * M)).sum := by
        rw [tsum_list, Nat.mul_comm, ← sum_map_mul]
        congr 1; apply List.map_congr_left; intro j _; exact Nat.mul_comm _ _
    _ ≤ ((List.range Q).map (fun j => tsum R Q (fun t => (G j (t.take j)).length))).sum := by
        apply sum_map_le
        intro j hj
        exact fresh_hits R M hM hMR j Q (List.mem_range.mp hj) (G j)
    _ = tsum R Q (fun t => ((List.range Q).map (fun j => (S j (t.take j)).length)).sum) := by
        rw [tsum_list]; congr 1; apply List.map_congr_left; intro j _
        congr 1; funext t; simp [G]
    _ ≤ tsum R Q (fun _ => B) := tsum_mono R Q hB
    _ = R^Q * B := tsum_const R B Q

theorem filter_eq_le_one (l : List Nat) (nd : l.Nodup) (e : Nat) : (l.filter (· == e)).length ≤ 1 := by
  induction l with
  | nil => simp
  | cons x l ihl =>
    rw [List.nodup_cons] at nd
    simp only [List.filter_cons]
    split
    · next hx =>
      have hx' : x = e := by simpa using hx
      have : l.filter (· == e) = [] := by
        rw [List.filter_eq_nil_iff]
        intro z hz hze
        have : z = e := by simpa using hze
        exact nd.1 (hx' ▸ this ▸ hz)
      simp [this]
    · exact ihl nd.2

/-- Guessing a secret: a uniformly random `k < K`, independent of the tape,
    lies in a list of guesses computed from the tape at most `|guesses| / K`
    of the time. -/
theorem guess_bound (R Q K : Nat) (Guess : List Nat → List Nat) :
    ((List.range K).map (fun k => tsum R Q (fun t => if (Guess t).contains k then 1 else 0))).sum
      ≤ tsum R Q (fun t => (Guess t).length) := by
  rw [← tsum_list]
  apply tsum_mono
  intro t
  calc ((List.range K).map (fun k => if (Guess t).contains k then 1 else 0)).sum
      ≤ ((List.range K).map (fun k => ((Guess t).filter (fun g => k == g)).length)).sum := by
        apply sum_map_le
        intro k _
        split
        · next h =>
          have hm : k ∈ Guess t := by simpa using h
          have : k ∈ (Guess t).filter (fun g => k == g) := List.mem_filter.mpr ⟨hm, by simp⟩
          exact List.length_pos_of_mem this
        · exact Nat.zero_le _
    _ = ((Guess t).map (fun g => ((List.range K).filter (fun k => k == g)).length)).sum :=
        double_count _ _ _
    _ ≤ ((Guess t).map (fun _ => 1)).sum := by
        apply sum_map_le; intro g _; exact filter_eq_le_one _ List.nodup_range g
    _ = (Guess t).length := by rw [sum_map_const]; simp

#print axioms fresh_hits
#print axioms partner_hits
#print axioms guess_bound

end DSM.Rom
