-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomTape

/- Hitting a value at a tape coordinate the weight does not depend on. If a
   weight `w` does not change when tape entry `c` changes, and a target `g`
   does not change where the weight is nonzero, then entry `c` agrees with the
   target mod `M` on at most a `1/M` fraction of the weight. This is the
   counting fact behind "a value the run never read is independent of
   everything the run did" (`RomHidden`): the run is invariant under changing
   that entry. `hits_sum` sums a family of such hits. -/
namespace DSM.Rom

theorem count_res (R M c : Nat) (hM : 0 < M) (hMR : M ∣ R) :
    ((List.range R).map (fun y => if y % M == c % M then 1 else 0)).sum * M ≤ R := by
  obtain ⟨d, hd⟩ := hMR
  rw [← len_filter_eq_sum, hd]
  calc _ ≤ d * M := Nat.mul_le_mul_right _ (count_mod M c hM d)
    _ = M * d := Nat.mul_comm _ _

theorem set_cons_zero (y z : Nat) (t : List Nat) : (z :: t).set 0 y = y :: t := rfl
theorem set_cons_succ (y z c : Nat) (t : List Nat) : (z :: t).set (c+1) y = z :: t.set c y := rfl

/-- Fixed coordinate. -/
theorem coord_hit (R M : Nat) (hM : 0 < M) (hMR : M ∣ R) : ∀ (c N : Nat), c < N →
    ∀ (w g : List Nat → Nat), (∀ t y, w (t.set c y) = w t) → (∀ t y, g (t.set c y) = g t) →
    tsum R N (fun t => w t * (if t.getD c 0 % M == g t % M then 1 else 0)) * M ≤ tsum R N w
  | _, 0, h, _, _, _, _ => absurd h (Nat.not_lt_zero _)
  | 0, N+1, _, w, g, hw, hg => by
    have w0 : ∀ y t, w (y :: t) = w (0 :: t) := fun y t => by
      have := hw (0 :: t) y; rw [set_cons_zero] at this; exact this
    have g0 : ∀ y t, g (y :: t) = g (0 :: t) := fun y t => by
      have := hg (0 :: t) y; rw [set_cons_zero] at this; exact this
    simp only [tsum, List.getD_cons_zero]
    simp only [w0, g0]
    have e := tsum_list R N (List.range R)
      (fun y t => w (0 :: t) * (if y % M == g (0 :: t) % M then 1 else 0))
    rw [← e]
    simp only [sum_map_mul, sum_map_const, List.length_range]
    rw [Nat.mul_comm, ← tsum_mul]
    apply Nat.le_trans (tsum_mono R N (G := fun t => R * w (0 :: t)) _)
    · rw [tsum_mul]; exact Nat.le_refl _
    · intro t
      calc M * (w (0 :: t) * ((List.range R).map (fun y => if y % M == g (0 :: t) % M then 1 else 0)).sum)
          = w (0 :: t) * (((List.range R).map (fun y => if y % M == g (0 :: t) % M then 1 else 0)).sum * M) := by
            ac_rfl
        _ ≤ w (0 :: t) * R := Nat.mul_le_mul_left _ (count_res R M _ hM hMR)
        _ = R * w (0 :: t) := Nat.mul_comm _ _
  | c+1, N+1, h, w, g, hw, hg => by
    simp only [tsum, List.getD_cons_succ]
    rw [Nat.mul_comm, ← sum_map_mul]
    apply sum_map_le
    intro y _
    have ih := coord_hit R M hM hMR c N (by omega) (fun t => w (y :: t)) (fun t => g (y :: t))
      (fun t z => by have := hw (y :: t) z; rw [set_cons_succ] at this; exact this)
      (fun t z => by have := hg (y :: t) z; rw [set_cons_succ] at this; exact this)
    rw [Nat.mul_comm]; exact ih

theorem getD_set_self (t : List Nat) (c y : Nat) (hc : c < t.length) : (t.set c y).getD c 0 = y := by
  simp [List.getD_eq_getElem?_getD, hc]

theorem set_set_back (t : List Nat) (c y : Nat) : (t.set c y).set c (t.getD c 0) = t := by
  apply List.ext_getElem?
  intro i
  simp only [List.getElem?_set, List.length_set]
  by_cases hi : c = i
  · subst hi
    by_cases hc : c < t.length
    · simp [hc, List.getD_eq_getElem?_getD]
    · simp [hc]
  · simp [hi]

/-- Fixed coordinate, with the target only required to be invariant where the
    weight is nonzero. -/
theorem coord_hit' (R M : Nat) (hM : 0 < M) (hMR : M ∣ R) (c N : Nat) (hc : c < N)
    (w g : List Nat → Nat) (hw : ∀ t y, w (t.set c y) = w t)
    (hg : ∀ t y, w t ≠ 0 → g (t.set c y) = g t) :
    tsum R N (fun t => w t * (if t.getD c 0 % M == g t % M then 1 else 0)) * M ≤ tsum R N w := by
  have hg' : ∀ t y, (if w (t.set c y) = 0 then 0 else g (t.set c y)) = (if w t = 0 then 0 else g t) := by
    intro t y
    rw [hw]
    by_cases h : w t = 0
    · simp [h]
    · simp [h, hg t y h]
  have e : (fun t => w t * (if t.getD c 0 % M == g t % M then 1 else 0)) =
      (fun t => w t * (if t.getD c 0 % M == (if w t = 0 then 0 else g t) % M then 1 else 0)) := by
    funext t
    by_cases h : w t = 0
    · simp [h]
    · simp [h]
  rw [e]
  exact coord_hit R M hM hMR c N hc w (fun t => if w t = 0 then 0 else g t) hw hg'

/-- A family of fixed-coordinate hits, summed. Each index `i` names a tape
    coordinate `c i`, a weight and a target; the total hit weight times `M` is
    at most the total weight. -/
theorem hits_sum {ι : Type} (R M N : Nat) (hM : 0 < M) (hMR : M ∣ R) (Ix : List ι)
    (c : ι → Nat) (hc : ∀ i ∈ Ix, c i < N) (w g : ι → List Nat → Nat)
    (hw : ∀ i ∈ Ix, ∀ t y, w i (t.set (c i) y) = w i t)
    (hg : ∀ i ∈ Ix, ∀ t y, w i t ≠ 0 → g i (t.set (c i) y) = g i t) :
    tsum R N (fun t => (Ix.map (fun i => w i t *
        (if t.getD (c i) 0 % M == g i t % M then 1 else 0))).sum) * M
      ≤ tsum R N (fun t => (Ix.map (fun i => w i t)).sum) := by
  rw [tsum_list, tsum_list, Nat.mul_comm, ← sum_map_mul]
  apply sum_map_le
  intro i hi
  rw [Nat.mul_comm]
  exact coord_hit' R M hM hMR (c i) N (hc i hi) (w i) (g i) (hw i hi) (hg i hi)

end DSM.Rom
