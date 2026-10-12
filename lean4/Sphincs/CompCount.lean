-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompGames

/- Modular proof, milestone 3 (support): counting tools for the reductions.

   * `count_le_of_inj`: an injection from the tickets of one event into the
     tickets of another bounds its count.
   * `tape_set_sum`: resampling one position of a challenger tape. For
     `j < q`, `|S| · Σ_xs g xs = Σ_xs Σ_{x ∈ S} g (xs.set j x)`.
   * `sum_by_index`: splitting an event by the value of an index in `[0, t)`.
   * `Bijective` experiments (each value exactly once) and `uniformBytes`.
   * Interaction-tree glue: `OT.bind`, its run, and agreement of two stateful
     oracles off one query (`run_agree_off`).

   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-! ## Injections bound counts -/

theorem nodup_subset_length {β : Type} [DecidableEq β] :
    ∀ (L M : List β), L.Nodup → (∀ b ∈ L, b ∈ M) → L.length ≤ M.length
  | [], _, _, _ => Nat.zero_le _
  | a :: L, M, hn, hs => by
    have ha : a ∈ M := hs a (List.mem_cons_self ..)
    have hn' := List.nodup_cons.mp hn
    have ih := nodup_subset_length L (M.erase a) hn'.2 (fun b hb => by
      have hne : b ≠ a := fun e => hn'.1 (e ▸ hb)
      exact (List.mem_erase_of_ne hne).mpr (hs b (List.mem_cons_of_mem _ hb)))
    rw [List.length_erase_of_mem ha] at ih
    have : 0 < M.length := List.length_pos_of_mem ha
    simp only [List.length_cons]; omega

theorem countP_le_of_inj {α β : Type} [DecidableEq β] (l : List α) (m : List β) (hl : l.Nodup)
    (φ : α → β) (E : α → Bool) (T : β → Bool)
    (hmem : ∀ a ∈ l, E a = true → φ a ∈ m ∧ T (φ a) = true)
    (inj : ∀ a ∈ l, ∀ b ∈ l, E a = true → E b = true → φ a = φ b → a = b) :
    l.countP E ≤ m.countP T := by
  rw [List.countP_eq_length_filter, List.countP_eq_length_filter]
  have hnd : ((l.filter E).map φ).Nodup := by
    have key : ∀ k : List α, k.Nodup → (∀ a ∈ k, a ∈ l ∧ E a = true) → (k.map φ).Nodup := by
      intro k
      induction k with
      | nil => intros; exact List.nodup_nil
      | cons a k ih =>
        intro hk hkl
        rw [List.map_cons, List.nodup_cons]
        have hk' := List.nodup_cons.mp hk
        refine ⟨?_, ih hk'.2 (fun b hb => hkl b (List.mem_cons_of_mem _ hb))⟩
        intro hm
        obtain ⟨b, hb, he⟩ := List.mem_map.mp hm
        have ha := hkl a (List.mem_cons_self ..)
        have hb' := hkl b (List.mem_cons_of_mem _ hb)
        have := inj b hb'.1 a ha.1 hb'.2 ha.2 he
        exact hk'.1 (this ▸ hb)
    exact key _ (hl.filter _) (fun a ha => by
      rw [List.mem_filter] at ha; exact ha)
  have hle := nodup_subset_length _ (m.filter T) hnd (fun b hb => by
    obtain ⟨a, ha, rfl⟩ := List.mem_map.mp hb
    rw [List.mem_filter] at ha
    have := hmem a ha.1 ha.2
    exact List.mem_filter.mpr this)
  rwa [List.length_map] at hle

/-! ## Experiments that list every value once -/

/-- Every value of `X` is the outcome of exactly one ticket. -/
def Bijective {X : Type} (S : FiniteExperiment X) : Prop :=
  (∀ i j, S.sample i = S.sample j → i = j) ∧ ∀ x, ∃ i, S.sample i = x

theorem uniformBytes_bijective (w : Nat) : Bijective (uniformBytes w) := by
  constructor
  · intro i j h
    apply Fin.ext
    have := congrArg (fun x : Wire w => toInt x.val) h
    simp only [uniformBytes] at this
    rwa [be_roundtrip _ _ i.isLt, be_roundtrip _ _ j.isLt] at this
  · intro x
    have bound := toInt_bound x.val
    rw [x.property] at bound
    refine ⟨⟨toInt x.val, bound⟩, ?_⟩
    apply Subtype.ext
    change be w (toInt x.val) = x.val
    have := be_decoded_bytes x.val
    rwa [x.property] at this

theorem eventMass_countP {α : Type} (e : α → Bool) :
    ∀ xs : List α, eventMass xs e = xs.countP e
  | [] => rfl
  | x :: xs => by
    rw [List.countP_cons, ← eventMass_countP e xs]
    simp only [eventMass]; cases e x <;> simp <;> omega

theorem sum_ind_countP {α : Type} (S : FiniteExperiment α) (e : α → Bool) :
    S.sum (fun x => if e x then 1 else 0) = (List.ofFn S.sample).countP e := by
  rw [← numerator_sum]; exact eventMass_countP e _

theorem nodup_ofFn_inj {α : Type} : ∀ {n : Nat} (f : Fin n → α), (∀ i j, f i = f j → i = j) →
    (List.ofFn f).Nodup
  | 0, _, _ => by simp
  | n+1, f, h => by
    rw [List.ofFn_succ, List.nodup_cons]
    refine ⟨fun hm => ?_, nodup_ofFn_inj (fun i => f i.succ) (fun i j e => Fin.succ_inj.mp (h _ _ e))⟩
    obtain ⟨i, hi⟩ := List.mem_ofFn.mp hm
    exact Fin.succ_ne_zero i (h _ _ hi)

/-- On a bijective experiment, an injection between two events bounds the
    first event's count by the second's. -/
theorem sum_le_of_inj {X : Type} [DecidableEq X] (S : FiniteExperiment X) (hS : Bijective S)
    (E T : X → Bool) (φ : X → X) (hφ : ∀ x, E x = true → T (φ x) = true)
    (inj : ∀ x y, E x = true → E y = true → φ x = φ y → x = y) :
    S.sum (fun x => if E x then 1 else 0) ≤ S.sum (fun x => if T x then 1 else 0) := by
  rw [sum_ind_countP, sum_ind_countP]
  apply countP_le_of_inj _ _ (nodup_ofFn_inj _ hS.1) φ E T
  · intro a _ he
    obtain ⟨i, hi⟩ := hS.2 (φ a)
    exact ⟨List.mem_ofFn.mpr ⟨i, hi⟩, hφ a he⟩
  · intro a _ b _ ha hb he; exact inj a b ha hb he

/-! ## Resampling one position of a tape -/

theorem tape_set_sum {X : Type} (S : FiniteExperiment X) :
    ∀ (q j : Nat), j < q → ∀ g : List X → Nat,
      S.cardinality * (S.tape q).sum g = (S.tape q).sum (fun xs => S.sum (fun x => g (xs.set j x)))
  | 0, _, h, _ => absurd h (Nat.not_lt_zero _)
  | q+1, 0, _, g => by
    change S.cardinality * (independentProduct S (S.tape q)).sum (fun p => g (p.1 :: p.2)) =
      (independentProduct S (S.tape q)).sum (fun p => S.sum (fun x => g ((p.1 :: p.2).set 0 x)))
    rw [product_sum, product_sum]
    simp only [List.set_cons_zero]
    rw [sum_comm (S.tape q) S]
    rw [show (S.sum fun x => S.sum fun y => (S.tape q).sum fun z => g (y :: z)) =
      S.sum (fun _ => S.sum fun y => (S.tape q).sum fun z => g (y :: z)) from rfl]
    rw [sum_const]
  | q+1, j+1, h, g => by
    change S.cardinality * (independentProduct S (S.tape q)).sum (fun p => g (p.1 :: p.2)) =
      (independentProduct S (S.tape q)).sum (fun p => S.sum (fun x => g ((p.1 :: p.2).set (j+1) x)))
    rw [product_sum, product_sum, sum_mul_left]
    apply sum_congr; intro i
    simp only [List.set_cons_succ]
    exact tape_set_sum S q j (by omega) (fun rest => g (S.sample i :: rest))

/-! ## Splitting by an index -/

theorem rsum_indicator (t i : Nat) (h : i < t) : rsum t (fun j => if i = j then 1 else 0) = 1 := by
  induction t with
  | zero => omega
  | succ t ih =>
    rw [rsum_succ]
    by_cases e : i = t
    · subst e
      rw [rsum_congr (G := fun _ => 0) (fun j hj => by simp; omega), rsum_const]; simp
    · rw [ih (by omega)]; simp [e]

theorem sum_rsum_comm {X : Type} (S : FiniteExperiment X) (t : Nat) (F : X → Nat → Nat) :
    S.sum (fun x => rsum t (fun j => F x j)) = rsum t (fun j => S.sum (fun x => F x j)) := by
  unfold FiniteExperiment.sum
  rw [← rsum_comm]
  apply rsum_congr; intro i hi
  simp only [hi, dif_pos]

/-- An event that fixes an index below `t` is the sum of its slices. -/
theorem sum_by_index {X : Type} (S : FiniteExperiment X) (t : Nat) (E : X → Bool) (ix : X → Nat)
    (h : ∀ x, E x = true → ix x < t) :
    S.sum (fun x => if E x then 1 else 0) =
      rsum t (fun j => S.sum (fun x => if E x && ix x == j then 1 else 0)) := by
  rw [← sum_rsum_comm]
  apply sum_congr; intro i
  by_cases e : E (S.sample i) = true
  · rw [if_pos e]
    refine (rsum_indicator t _ (h _ e)).symm.trans (rsum_congr (fun j _ => ?_))
    simp [e]
  · rw [if_neg e, rsum_congr (G := fun _ => 0) (fun j _ => by simp [e]), rsum_const]; simp

/-! ## Interaction trees: sequencing and agreement -/

namespace OT
variable {Q A α β σ : Type}

def bind : OT Q A α → (α → OT Q A β) → OT Q A β
  | .done a, k => k a
  | .ask q c, k => .ask q (fun y => bind (c y) k)

theorem run_bind (o : σ → Q → A × σ) (k : α → OT Q A β) :
    ∀ (T : OT Q A α) (s : σ), (T.bind k).run o s = (k (T.run o s).1).run o (T.run o s).2
  | .done _, _ => rfl
  | .ask q c, s => by simp only [bind, run]; exact run_bind o k (c (o s q).1) (o s q).2

theorem within_mono : ∀ (T : OT Q A β) (a b : Nat), a ≤ b → T.Within a → T.Within b
  | .done _, _, _, _, _ => trivial
  | .ask _ _, 0, _, _, h => absurd h (by simp [Within])
  | .ask _ _, _+1, 0, hab, _ => absurd hab (by omega)
  | .ask _ c, a+1, b+1, hab, h => fun y => within_mono (c y) a b (by omega) (h y)

theorem within_bind (k : α → OT Q A β) (m n : Nat) (hk : ∀ a, (k a).Within n) :
    ∀ (T : OT Q A α), T.Within m → (T.bind k).Within (m + n)
  | .done a, _ => within_mono (k a) n (m + n) (by omega) (hk a)
  | .ask q c, h => by
    cases m with
    | zero => exact absurd h (by simp [Within])
    | succ m =>
      rw [show m + 1 + n = (m + n) + 1 by omega]
      exact fun y => within_bind k m n hk (c y) (h y)

/-- A logging oracle's log only grows. -/
theorem run_log_prefix (ans : Q → A) :
    ∀ (T : OT Q A α) (l : List Q), ∃ e, (T.run (fun s q => (ans q, s ++ [q])) l).2 = l ++ e
  | .done _, l => ⟨[], by simp [run]⟩
  | .ask q c, l => by
    obtain ⟨e, he⟩ := run_log_prefix ans (c (ans q)) (l ++ [q])
    exact ⟨q :: e, by simp only [run]; rw [he]; simp⟩

/-- Two logging oracles that differ only at query `j`: if the first run never
    asks `j`, the second run is the same run. -/
theorem run_agree_off [DecidableEq Q] (a₁ a₂ : Q → A) (j : Q) (h : ∀ q, q ≠ j → a₁ q = a₂ q) :
    ∀ (T : OT Q A α) (l : List Q), j ∉ (T.run (fun s q => (a₁ q, s ++ [q])) l).2 →
      T.run (fun s q => (a₂ q, s ++ [q])) l = T.run (fun s q => (a₁ q, s ++ [q])) l
  | .done _, _, _ => rfl
  | .ask q c, l, hj => by
    simp only [run] at hj ⊢
    have hq : q ≠ j := by
      intro e
      obtain ⟨e', he'⟩ := run_log_prefix a₁ (c (a₁ q)) (l ++ [q])
      rw [he'] at hj; exact hj (by simp [e])
    rw [← h q hq]
    exact run_agree_off a₁ a₂ j h (c (a₁ q)) (l ++ [q]) hj
end OT

#print axioms countP_le_of_inj
#print axioms sum_le_of_inj
#print axioms uniformBytes_bijective
#print axioms tape_set_sum
#print axioms sum_by_index
#print axioms OT.run_agree_off
end DSM.Sphincs.Comp
