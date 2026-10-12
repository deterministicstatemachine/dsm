-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs

/- The WOTS checksum argument, deterministically: two digit vectors produced
   by `wotsDigits` that differ have a position where the second is strictly
   smaller than the first. The first 2n digits are the nibbles of the message,
   the last three the big-endian base-16 digits of the checksum
   C = Σ (15 - d). If the second vector dominated the first everywhere, its
   message digits would make its checksum no larger, and its checksum digits
   would make it no smaller, so the checksums, hence the message digits, and
   hence the whole vectors would coincide. -/
namespace DSM.Sphincs

/-- `base2b` with 4-bit digits reads nibbles, high nibble first. -/
theorem base2b_nibble (x : Bytes) (count i : Nat) (hi : i < count) :
    (base2b x 4 count)[i]? = some (if i%2 = 0 then (x[i/2]?.getD 0).toNat / 16
      else (x[i/2]?.getD 0).toNat % 16) := by
  simp only [base2b, List.getElem?_map, List.getElem?_range hi, Option.map_some]
  rw [show List.range 4 = [0,1,2,3] from rfl]
  simp only [List.foldl]
  rw [show (i*4+0)/8 = i/2 by omega, show (i*4+1)/8 = i/2 by omega,
    show (i*4+2)/8 = i/2 by omega, show (i*4+3)/8 = i/2 by omega]
  have hb : (x[i/2]?.getD 0).toNat < 256 := UInt8.toNat_lt _
  generalize (x[i/2]?.getD 0).toNat = b at hb ⊢
  rcases Nat.mod_two_eq_zero_or_one i with h | h
  · rw [show (i*4+0)%8 = 0 by omega, show (i*4+1)%8 = 1 by omega,
      show (i*4+2)%8 = 2 by omega, show (i*4+3)%8 = 3 by omega, if_pos h]
    simp only [Option.some.injEq]
    omega
  · rw [show (i*4+0)%8 = 4 by omega, show (i*4+1)%8 = 5 by omega,
      show (i*4+2)%8 = 6 by omega, show (i*4+3)%8 = 7 by omega, if_neg (by omega)]
    simp only [Option.some.injEq]
    omega
theorem base2b_length (x : Bytes) (b count : Nat) : (base2b x b count).length = count := by
  simp [base2b]

/-- The three checksum digits are the base-16 digits of C, most significant first. -/
theorem checksum_digits (C : Nat) (hC : C < 4096) :
    base2b (be 2 (C*16)) 4 3 = [C/256, C/16%16, C%16] := by
  apply List.ext_getElem?
  intro i
  by_cases hi : i < 3
  · rw [base2b_nibble _ _ _ hi]
    rcases i with _ | _ | _ | i
    · simp [be]; omega
    · simp [be]; omega
    · simp [be]; omega
    · omega
  · rw [List.getElem?_eq_none (by rw [base2b_length]; omega),
      List.getElem?_eq_none (by simp; omega)]

/-- The total "remaining steps" Σ (15 - d) of a digit list. -/
def remainingSteps (D : List Nat) : Nat := (D.map (15 - ·)).sum

theorem checksum_fold (D : List Nat) (hb : ∀ d ∈ D, d ≤ 15) (acc : Nat) :
    D.foldl (fun s d => s+15-d) acc = acc + remainingSteps D := by
  induction D generalizing acc with
  | nil => simp [remainingSteps]
  | cons d D ih =>
    have hd : d ≤ 15 := hb d (by simp)
    simp only [List.foldl_cons, ih (fun x hx => hb x (by simp [hx])), remainingSteps,
      List.map_cons, List.sum_cons]
    omega

theorem base2b_nibble_le (x : Bytes) (count : Nat) : ∀ d ∈ base2b x 4 count, d ≤ 15 := by
  intro d hd
  have := base2b_digit_bound x 4 count d hd
  omega

theorem remainingSteps_le (D : List Nat) : remainingSteps D ≤ 15 * D.length := by
  induction D with
  | nil => simp [remainingSteps]
  | cons d D ih =>
    simp only [remainingSteps, List.map_cons, List.sum_cons, List.length_cons] at ih ⊢
    omega

/-- Pointwise domination of digits ≤ 15 lowers the remaining steps, and
    leaves them unchanged only when the digit lists are equal. -/
theorem remainingSteps_mono (D D' : List Nat) (hlen : D.length = D'.length)
    (hb : ∀ d ∈ D, d ≤ 15) (hb' : ∀ d ∈ D', d ≤ 15)
    (hge : ∀ i, i < D.length → D.getD i 0 ≤ D'.getD i 0) :
    remainingSteps D' ≤ remainingSteps D ∧ (remainingSteps D' = remainingSteps D → D' = D) := by
  induction D generalizing D' with
  | nil =>
    cases D' with
    | nil => exact ⟨Nat.le_refl _, fun _ => rfl⟩
    | cons _ _ => simp at hlen
  | cons d D ih =>
    cases D' with
    | nil => simp at hlen
    | cons d' D' =>
      have h0 : d ≤ d' := by simpa using hge 0 (by simp)
      have hd : d ≤ 15 := hb d (by simp)
      have hd' : d' ≤ 15 := hb' d' (by simp)
      obtain ⟨hle, heq⟩ := ih D' (by simpa using hlen) (fun x hx => hb x (by simp [hx]))
        (fun x hx => hb' x (by simp [hx]))
        (fun i hi => by simpa using hge (i+1) (by simp; omega))
      simp only [remainingSteps, List.map_cons, List.sum_cons] at hle heq ⊢
      refine ⟨by omega, fun e => ?_⟩
      have hT := heq (by omega)
      rw [show d' = d by omega, hT]

theorem wots_digits_split (p : Params) (m : Bytes) :
    wotsDigits p m = base2b m 4 (2*p.n) ++
      base2b (be 2 (remainingSteps (base2b m 4 (2*p.n))*16)) 4 3 := by
  simp only [wotsDigits, Id.run, checksum_fold _ (base2b_nibble_le m (2*p.n)), Nat.zero_add]
  rfl

/-- WOTS checksum: for any parameters whose checksum fits three base-16
    digits, distinct digit vectors have a position where the second is
    strictly smaller. -/
theorem wots_checksum_decreases_of (p : Params) (hn : 2*p.n*15 < 4096) (m m' : Bytes)
    (h : wotsDigits p m ≠ wotsDigits p m') :
    ∃ i, i < p.len ∧ (wotsDigits p m').getD i 0 < (wotsDigits p m).getD i 0 := by
  apply Classical.byContradiction
  intro hno
  have hge : ∀ i, i < p.len → (wotsDigits p m).getD i 0 ≤ (wotsDigits p m').getD i 0 :=
    fun i hi => Nat.le_of_not_lt (fun hlt => hno ⟨i, hi, hlt⟩)
  rw [wots_digits_split, wots_digits_split] at hge h
  generalize hD : base2b m 4 (2*p.n) = D at hge h
  generalize hD' : base2b m' 4 (2*p.n) = D' at hge h
  have lD : D.length = 2*p.n := by rw [← hD, base2b_length]
  have lD' : D'.length = 2*p.n := by rw [← hD', base2b_length]
  have bD : ∀ d ∈ D, d ≤ 15 := by
    intro d hd; rw [← hD] at hd; have := base2b_digit_bound m 4 (2*p.n) d hd; omega
  have bD' : ∀ d ∈ D', d ≤ 15 := by
    intro d hd; rw [← hD'] at hd; have := base2b_digit_bound m' 4 (2*p.n) d hd; omega
  have cD := remainingSteps_le D
  have cD' := remainingSteps_le D'
  rw [checksum_digits _ (by rw [lD] at cD; omega),
    checksum_digits _ (by rw [lD'] at cD'; omega)] at hge h
  have hmsg : ∀ i, i < D.length → D.getD i 0 ≤ D'.getD i 0 := by
    intro i hi
    have := hge i (by simp only [Params.len]; omega)
    simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left hi,
      List.getElem?_append_left (show i < D'.length by omega)] at this ⊢
    exact this
  have hck : ∀ k, k < 3 → ([remainingSteps D/256, remainingSteps D/16%16, remainingSteps D%16] : List Nat).getD k 0 ≤
      ([remainingSteps D'/256, remainingSteps D'/16%16, remainingSteps D'%16] : List Nat).getD k 0 := by
    intro k hk
    have := hge (2*p.n+k) (by simp only [Params.len]; omega)
    simp only [List.getD_eq_getElem?_getD, List.getElem?_append_right (show D.length ≤ 2*p.n+k by omega),
      List.getElem?_append_right (show D'.length ≤ 2*p.n+k by omega), lD, lD',
      Nat.add_sub_cancel_left] at this ⊢
    exact this
  have c0 := hck 0 (by decide)
  have c1 := hck 1 (by decide)
  have c2 := hck 2 (by decide)
  simp only [List.getD_cons_zero, List.getD_cons_succ] at c0 c1 c2
  obtain ⟨hle, heq⟩ := remainingSteps_mono D D' (by omega) bD bD' hmsg
  have hsame : remainingSteps D' = remainingSteps D := by omega
  have hDD := heq hsame
  exact h (by rw [hDD])

/-- WOTS checksum for every supported variant. -/
theorem wots_checksum_decreases (v : Variant) (m m' : Bytes)
    (h : wotsDigits (params v) m ≠ wotsDigits (params v) m') :
    ∃ i, i < (params v).len ∧
      (wotsDigits (params v) m').getD i 0 < (wotsDigits (params v) m).getD i 0 :=
  wots_checksum_decreases_of (params v) (by have := (checksum_width_three v).2; omega) m m' h

/-- The message digits determine an n-byte message. -/
theorem wots_digits_injective (p : Params) (m m' : Bytes) (hm : m.length = p.n)
    (hm' : m'.length = p.n) (h : wotsDigits p m = wotsDigits p m') : m = m' := by
  rw [wots_digits_split, wots_digits_split] at h
  have hD := (List.append_inj h (by rw [base2b_length, base2b_length])).1
  have byte : ∀ k, k < p.n → (m[k]?.getD 0).toNat = (m'[k]?.getD 0).toNat := by
    intro k hk
    have hi : ∀ x : Bytes, (base2b x 4 (2*p.n))[2*k]? = some ((x[k]?.getD 0).toNat / 16) := by
      intro x
      rw [base2b_nibble _ _ _ (by omega), if_pos (by omega), show (2*k)/2 = k by omega]
    have lo : ∀ x : Bytes, (base2b x 4 (2*p.n))[2*k+1]? = some ((x[k]?.getD 0).toNat % 16) := by
      intro x
      rw [base2b_nibble _ _ _ (by omega), if_neg (by omega), show (2*k+1)/2 = k by omega]
    have e0 := hi m
    have e1 := lo m
    rw [hD, hi m'] at e0
    rw [hD, lo m'] at e1
    simp only [Option.some.injEq] at e0 e1
    omega
  apply List.ext_getElem?
  intro k
  by_cases hk : k < p.n
  · have hb := byte k hk
    rw [List.getElem?_eq_getElem (by omega), List.getElem?_eq_getElem (by omega)] at hb ⊢
    simp only [Option.getD_some] at hb
    rw [UInt8.toNat_inj.mp hb]
  · rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]

/-- Distinct n-byte messages: some WOTS digit of the second is strictly smaller. -/
theorem wots_checksum_decreases_of_ne (v : Variant) (m m' : Bytes)
    (hm : m.length = (params v).n) (hm' : m'.length = (params v).n) (hne : m ≠ m') :
    ∃ i, i < (params v).len ∧
      (wotsDigits (params v) m').getD i 0 < (wotsDigits (params v) m).getD i 0 :=
  wots_checksum_decreases v m m' (fun h => hne (wots_digits_injective _ m m' hm hm' h))

#print axioms base2b_nibble
#print axioms checksum_digits
#print axioms wots_checksum_decreases_of
#print axioms wots_checksum_decreases
#print axioms wots_digits_injective
#print axioms wots_checksum_decreases_of_ne
end DSM.Sphincs
