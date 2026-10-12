-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomTape

/- Predictable sampling. A run reads a uniform tape entry by entry; before
   reading entry `i` it decides, from the entries before it, whether that
   entry goes to an output slot and which one (`slot (t.take i)`). Entries
   are stored as value+1, so 0 marks an empty slot. If every run fills
   distinct slots of `S` and the event `H` can only grow when an empty slot
   is filled, then the event's probability under the adaptive run is at most
   its probability when every slot of `S` holds an independent uniform value
   (`sample`). This is the step from a static bound to a bound under an
   adaptive selection: the selection decides which uniform values count, but
   each value is uniform when it is read. -/
namespace DSM.Rom

def shift (slot : List Nat → Option Nat) (y : Nat) : List Nat → Option Nat := fun p => slot (y :: p)

def place (slot : List Nat → Option Nat) (out : List Nat) (y : Nat) : List Nat :=
  match slot [] with
  | some s => out.set s (y+1)
  | none => out

/-- The slots after an adaptive run over the tape. -/
def fill (slot : List Nat → Option Nat) (out : List Nat) : List Nat → List Nat
  | [] => out
  | y :: t => fill (shift slot y) (place slot out y) t

/-- The slots an adaptive run assigns, in order. -/
def assigned (slot : List Nat → Option Nat) : List Nat → List Nat
  | [] => []
  | y :: t => (slot []).toList ++ assigned (shift slot y) t

/-- Every slot of `S` filled independently and uniformly. -/
def tsumOver (R : Nat) (H : List Nat → Nat) : List Nat → List Nat → Nat
  | [], out => H out
  | s :: S, out => ((List.range R).map (fun y => tsumOver R H S (out.set s (y+1)))).sum

theorem sum_comm {β γ : Type} (l₁ : List β) (l₂ : List γ) (f : β → γ → Nat) :
    (l₁.map (fun a => (l₂.map (fun b => f a b)).sum)).sum =
      (l₂.map (fun b => (l₁.map (fun a => f a b)).sum)).sum := by
  induction l₁ with
  | nil => simp only [List.map_nil, List.sum_nil]; exact (sum_map_zero l₂).symm
  | cons a l ih =>
    simp only [List.map_cons, List.sum_cons, ih]
    exact (sum_map_add l₂ (fun b => f a b) (fun b => (l.map (fun a => f a b)).sum)).symm

theorem sum_mul_right {β : Type} (l : List β) (f : β → Nat) (c : Nat) :
    (l.map f).sum * c = (l.map (fun a => f a * c)).sum := by
  rw [Nat.mul_comm, ← sum_map_mul]; congr 1; apply List.map_congr_left; intro a _; exact Nat.mul_comm _ _

theorem tsumOver_perm (R : Nat) (H : List Nat → Nat) {S S' : List Nat} (hp : S.Perm S') :
    S.Nodup → ∀ out, tsumOver R H S out = tsumOver R H S' out := by
  induction hp with
  | nil => intro _ _; rfl
  | cons x _ ih =>
    intro nd out
    simp only [tsumOver]
    congr 1; apply List.map_congr_left; intro y _
    exact ih (List.nodup_cons.mp nd).2 _
  | swap x y l =>
    intro nd out
    have hxy : y ≠ x := fun h => (List.nodup_cons.mp nd).1 (by simp [h])
    simp only [tsumOver]
    rw [sum_comm]
    congr 1; apply List.map_congr_left; intro a _
    congr 1; apply List.map_congr_left; intro b _
    rw [List.set_comm _ _ hxy]
  | trans h₁ _ ih₁ ih₂ =>
    intro nd out
    rw [ih₁ nd out, ih₂ (h₁.nodup_iff.mp nd) out]

theorem tsumOver_ge (R : Nat) (H : List Nat → Nat)
    (hmono : ∀ out s y, out.getD s 0 = 0 → H out ≤ H (out.set s (y+1))) :
    ∀ (S out : List Nat), S.Nodup → (∀ s ∈ S, out.getD s 0 = 0) →
      R^S.length * H out ≤ tsumOver R H S out
  | [], out, _, _ => by simp [tsumOver]
  | s :: S, out, nd, emp => by
    simp only [tsumOver, List.length_cons]
    have hs : s ∉ S := (List.nodup_cons.mp nd).1
    have step : ∀ y, R^S.length * H out ≤ tsumOver R H S (out.set s (y+1)) := by
      intro y
      have emp' : ∀ s' ∈ S, (out.set s (y+1)).getD s' 0 = 0 := by
        intro s' hs'
        have hne : s ≠ s' := fun h => hs (h ▸ hs')
        simp only [List.getD_eq_getElem?_getD, List.getElem?_set_ne hne]
        have := emp s' (by simp [hs'])
        simpa [List.getD_eq_getElem?_getD] using this
      exact Nat.le_trans (Nat.mul_le_mul_left _ (hmono out s y (emp s (by simp))))
        (tsumOver_ge R H hmono S _ (List.nodup_cons.mp nd).2 emp')
    calc R^(S.length+1) * H out = ((List.range R).map (fun _ => R^S.length * H out)).sum := by
          rw [sum_map_const, List.length_range, Nat.pow_succ]; ac_rfl
      _ ≤ _ := sum_map_le _ (fun y _ => step y)

theorem replicate_len (M : Nat) : (List.replicate M 0).length = M := List.length_replicate

/-- Predictable sampling (see the header). -/
theorem sample (R : Nat) (H : List Nat → Nat)
    (hmono : ∀ out s y, out.getD s 0 = 0 → H out ≤ H (out.set s (y+1))) :
    ∀ (M : Nat) (slot : List Nat → Option Nat) (S out : List Nat), S.Nodup →
      (∀ s ∈ S, out.getD s 0 = 0) →
      (∀ t : List Nat, t.length = M → (assigned slot t).Nodup ∧ ∀ s ∈ assigned slot t, s ∈ S) →
      tsum R M (fun t => H (fill slot out t)) * R^S.length ≤ R^M * tsumOver R H S out
  | 0, slot, S, out, nd, emp, _ => by
    simp only [tsum, fill, Nat.pow_zero, Nat.one_mul]
    rw [Nat.mul_comm]
    exact tsumOver_ge R H hmono S out nd emp
  | M+1, slot, S, out, nd, emp, hA => by
    simp only [tsum, fill]
    cases hs : slot [] with
    | none =>
      have ih : ∀ y, tsum R M (fun t => H (fill (shift slot y) (place slot out y) t)) * R^S.length ≤
          R^M * tsumOver R H S out := by
        intro y
        have hp : place slot out y = out := by simp [place, hs]
        rw [hp]
        apply sample R H hmono M (shift slot y) S out nd emp
        intro t ht
        have := hA (y :: t) (by simp [ht])
        simpa [assigned, hs] using this
      rw [sum_mul_right]
      calc _ ≤ ((List.range R).map (fun _ => R^M * tsumOver R H S out)).sum := sum_map_le _ (fun y _ => ih y)
        _ = R^(M+1) * tsumOver R H S out := by
          rw [sum_map_const, List.length_range, Nat.pow_succ]; ac_rfl
    | some s0 =>
      have h0 := hA (List.replicate (M+1) 0) (replicate_len _)
      have hs0 : s0 ∈ S := h0.2 s0 (by simp [List.replicate_succ, assigned, hs])
      have hlen : S.length = (S.erase s0).length + 1 := by
        rw [List.length_erase_of_mem hs0]; have := List.length_pos_of_mem hs0; omega
      have nd' : (S.erase s0).Nodup := nd.erase s0
      have ih : ∀ y, tsum R M (fun t => H (fill (shift slot y) (place slot out y) t)) * R^S.length ≤
          R^M * tsumOver R H (S.erase s0) (out.set s0 (y+1)) * R := by
        intro y
        have hp : place slot out y = out.set s0 (y+1) := by simp [place, hs]
        rw [hp, hlen, Nat.pow_succ, ← Nat.mul_assoc]
        apply Nat.mul_le_mul_right
        apply sample R H hmono M (shift slot y) (S.erase s0) (out.set s0 (y+1)) nd'
        · intro s hsm
          have hne : s0 ≠ s := fun h => (List.Nodup.not_mem_erase nd) (h ▸ hsm)
          have hsS : s ∈ S := List.mem_of_mem_erase hsm
          simp only [List.getD_eq_getElem?_getD, List.getElem?_set_ne hne]
          have := emp s hsS
          simpa [List.getD_eq_getElem?_getD] using this
        · intro t ht
          have := hA (y :: t) (by simp [ht])
          simp only [assigned, hs, Option.toList_some, List.singleton_append, List.nodup_cons,
            List.mem_cons, forall_eq_or_imp] at this
          obtain ⟨⟨hni, hnd⟩, _, hall⟩ := this
          refine ⟨hnd, fun s hsm => ?_⟩
          have hne : s ≠ s0 := fun h => hni (h ▸ hsm)
          exact (List.mem_erase_of_ne hne).mpr (hall s hsm)
      rw [sum_mul_right]
      calc _ ≤ ((List.range R).map (fun y => R^M * tsumOver R H (S.erase s0) (out.set s0 (y+1)) * R)).sum :=
            sum_map_le _ (fun y _ => ih y)
        _ = R^(M+1) * tsumOver R H (s0 :: S.erase s0) out := by
          simp only [tsumOver]
          rw [← sum_map_mul]
          congr 1; apply List.map_congr_left; intro y _
          rw [Nat.pow_succ]; ac_rfl
        _ = R^(M+1) * tsumOver R H S out := by
          rw [tsumOver_perm R H (List.perm_cons_erase hs0).symm
            ((List.perm_cons_erase hs0).nodup_iff.mp nd) out]

#print axioms sample
end DSM.Rom
