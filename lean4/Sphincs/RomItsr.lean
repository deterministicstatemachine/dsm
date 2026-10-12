-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomTape

/- ITSR in the random-oracle model. A message digest selects a hypertree leaf
   (one of `L`) and `k` FORS indices (each in `[0, t)`). After `q` signatures
   whose digests fall on uniformly random leaves (their FORS indices are
   arbitrary here, chosen by anyone), a fresh uniform digest is "covered" when
   at its leaf each of its `k` indices was already used by some signature.
   `itsr_static` bounds the covered fraction exactly in Nat arithmetic:

     Pr[covered] ≤ Σ_{g=1..G} (g^k − (g−1)^k) · q^g / (g! · L^g · t^k)
                   + q^(G+1) / ((G+1)! · L^(G+1)).

   The leaves and target indices are independent and uniform: that is the
   random-oracle idealization of h_msg, not a property of BLAKE3. -/
namespace DSM.Rom

def fact : Nat → Nat
  | 0 => 1
  | n+1 => (n+1) * fact n

theorem fact_pos : ∀ n, 0 < fact n
  | 0 => by decide
  | n+1 => Nat.mul_pos (Nat.succ_pos n) (fact_pos n)

/-- Signatures (by position in `ℓ`) that fell on leaf `a`. -/
def countEq (ℓ : List Nat) (a : Nat) : Nat := (ℓ.filter (· == a)).length

theorem countEq_cons (y : Nat) (ℓ : List Nat) (a : Nat) :
    countEq (y :: ℓ) a = (if y == a then 1 else 0) + countEq ℓ a := by
  unfold countEq; simp only [List.filter_cons]; split <;> simp <;> omega

theorem pow_two_terms (q : Nat) : ∀ g, q^(g+1) + (g+1) * q^g ≤ (q+1)^(g+1)
  | 0 => by simp
  | g+1 => by
    have ih := pow_two_terms q g
    have e1 : q^(g+1+1) = q^(g+1) * q := Nat.pow_succ _ _
    have e2 : q^(g+1) = q^g * q := Nat.pow_succ _ _
    have e3 : (q+1)^(g+1+1) = (q+1)^(g+1) * (q+1) := Nat.pow_succ _ _
    have e4 : (g+1+1) * q^(g+1) = (g+1) * q^(g+1) + q^(g+1) := Nat.succ_mul _ _
    have e5 : (q^(g+1) + (g+1) * q^g) * q = q^(g+1) * q + (g+1) * q^(g+1) := by
      rw [Nat.add_mul, Nat.mul_assoc, ← e2]
    rw [e4, e3, e1]
    calc q^(g+1) * q + ((g+1) * q^(g+1) + q^(g+1))
        ≤ (q^(g+1) + (g+1) * q^g) * q + (q^(g+1) + (g+1) * q^g) := by rw [e5]; omega
      _ = (q^(g+1) + (g+1) * q^g) * (q+1) := by rw [Nat.mul_succ]
      _ ≤ (q+1)^(g+1) * (q+1) := Nat.mul_le_mul_right _ ih

theorem count_eq_one (L a : Nat) : ((List.range L).filter (· == a)).length ≤ 1 :=
  filter_eq_le_one _ List.nodup_range a

/-- Union over `g`-subsets of signatures: at least `g` of `q` uniform leaves
    equal a fixed leaf `a` on at most a `q^g / (g! L^g)` fraction. -/
theorem many_on_leaf (L a : Nat) : ∀ (q g : Nat),
    tsum L q (fun ℓ => if g ≤ countEq ℓ a then 1 else 0) * (L^g * fact g) ≤ q^g * L^q
  | q, 0 => by
    simp only [Nat.zero_le, if_true, Nat.pow_zero, fact, Nat.mul_one, Nat.one_mul]
    rw [tsum_const]; simp
  | 0, g+1 => by simp [tsum, countEq]
  | q+1, g+1 => by
    simp only [tsum]
    have split : ∀ y, tsum L q (fun ℓ => if g+1 ≤ countEq (y :: ℓ) a then 1 else 0) ≤
        (if y == a then tsum L q (fun ℓ => if g ≤ countEq ℓ a then 1 else 0) else 0) +
        tsum L q (fun ℓ => if g+1 ≤ countEq ℓ a then 1 else 0) := by
      intro y
      cases hy : (y == a)
      · simp only [Bool.false_eq_true, if_false, Nat.zero_add]
        apply tsum_mono; intro ℓ; rw [countEq_cons, hy]; simp
      · simp only [if_true]
        apply Nat.le_trans _ (Nat.le_add_right _ _)
        apply tsum_mono; intro ℓ; rw [countEq_cons, hy]; simp only [if_true]
        split <;> split <;> omega
    let A := tsum L q (fun ℓ => if g ≤ countEq ℓ a then 1 else 0)
    let B := tsum L q (fun ℓ => if g+1 ≤ countEq ℓ a then 1 else 0)
    have hsum : ((List.range L).map (fun y => tsum L q (fun ℓ => if g+1 ≤ countEq (y :: ℓ) a then 1 else 0))).sum
        ≤ A + L * B := by
      calc _ ≤ ((List.range L).map (fun y => (if y == a then A else 0) + B)).sum :=
            sum_map_le _ (fun y _ => split y)
        _ = ((List.range L).map (fun y => if y == a then A else 0)).sum + L * B := by
            rw [sum_map_add, sum_map_const, List.length_range]
        _ ≤ A + L * B := by
            apply Nat.add_le_add_right
            have : ((List.range L).map (fun y => if y == a then A else 0)).sum =
                ((List.range L).filter (· == a)).length * A := by
              rw [len_filter_eq_sum, Nat.mul_comm, ← sum_map_mul]
              congr 1; apply List.map_congr_left; intro y _; split <;> simp
            rw [this]
            calc _ ≤ 1 * A := Nat.mul_le_mul_right _ (count_eq_one L a)
              _ = A := Nat.one_mul _
    have hA := many_on_leaf L a q g
    have hB := many_on_leaf L a q (g+1)
    have ef : fact (g+1) = (g+1) * fact g := rfl
    have eg : L^(g+1) = L^g * L := Nat.pow_succ _ _
    have eq : L^(q+1) = L^q * L := Nat.pow_succ _ _
    calc _ ≤ (A + L * B) * (L^(g+1) * fact (g+1)) := Nat.mul_le_mul_right _ hsum
      _ = ((g+1) * L) * (A * (L^g * fact g)) + L * (B * (L^(g+1) * fact (g+1))) := by
          rw [Nat.add_mul, ef, eg]; ac_rfl
      _ ≤ ((g+1) * L) * (q^g * L^q) + L * (q^(g+1) * L^q) :=
          Nat.add_le_add (Nat.mul_le_mul_left _ hA) (Nat.mul_le_mul_left _ hB)
      _ = (q^(g+1) + (g+1) * q^g) * L^(q+1) := by rw [eq, Nat.add_mul (q^(g+1)) ((g+1) * q^g)]; ac_rfl
      _ ≤ (q+1)^(g+1) * L^(q+1) := Nat.mul_le_mul_right _ (pow_two_terms q g)

/-! The target digest's indices. -/

theorem count_mem_le (K : Nat) (G : List Nat) :
    ((List.range K).map (fun k => if G.contains k then 1 else 0)).sum ≤ G.length := by
  calc ((List.range K).map (fun k => if G.contains k then 1 else 0)).sum
      ≤ ((List.range K).map (fun k => (G.filter (fun g => k == g)).length)).sum := by
        apply sum_map_le
        intro k _
        split
        · next h =>
          have hm : k ∈ G := by simpa using h
          exact List.length_pos_of_mem (List.mem_filter.mpr ⟨hm, by simp⟩)
        · exact Nat.zero_le _
    _ = (G.map (fun g => ((List.range K).filter (fun k => k == g)).length)).sum := double_count _ _ _
    _ ≤ (G.map (fun _ => 1)).sum := by
        apply sum_map_le; intro g _; exact filter_eq_le_one _ List.nodup_range g
    _ = G.length := by rw [sum_map_const]; simp

/-- Tapes of `k` entries in `[0, t)` whose `i`-th entry lies in `C i`, with
    every `C i` of length at most `m`: at most `m^k` of them. -/
theorem product_count (t m : Nat) : ∀ (k : Nat) (C : Nat → List Nat), (∀ i, (C i).length ≤ m) →
    tsum t k (fun x => if (List.range k).all (fun i => (C i).contains (x.getD i 0)) then 1 else 0) ≤ m^k
  | 0, _, _ => by simp [tsum]
  | k+1, C, hC => by
    simp only [tsum]
    have step : ∀ y, tsum t k (fun x => if (List.range (k+1)).all
          (fun i => (C i).contains ((y :: x).getD i 0)) then 1 else 0) ≤
        (if (C 0).contains y then 1 else 0) * m^k := by
      intro y
      have ih := product_count t m k (fun i => C (i+1)) (fun i => hC (i+1))
      rw [List.range_succ_eq_map]
      simp only [List.all_cons, List.all_map, List.getD_cons_zero]
      cases (C 0).contains y
      · simp only [Bool.false_and, Bool.false_eq_true, if_false, Nat.zero_mul]; rw [tsum_const]; simp
      · simpa only [Bool.true_and, if_true, Nat.one_mul] using ih
    calc _ ≤ ((List.range t).map (fun y => (if (C 0).contains y then 1 else 0) * m^k)).sum :=
          sum_map_le _ (fun y _ => step y)
      _ = ((List.range t).map (fun y => if (C 0).contains y then 1 else 0)).sum * m^k := by
          rw [Nat.mul_comm, ← sum_map_mul]; congr 1; apply List.map_congr_left; intro y _
          exact Nat.mul_comm _ _
      _ ≤ m * m^k := Nat.mul_le_mul_right _ (Nat.le_trans (count_mem_le t (C 0)) (hC 0))
      _ = m^(k+1) := by rw [Nat.pow_succ, Nat.mul_comm]

/-- Positions of `ℓ` holding leaf `a`. -/
def onLeaf (ℓ : List Nat) (a : Nat) : List Nat := (List.range ℓ.length).filter (fun s => ℓ.getD s 0 == a)

theorem onLeaf_length : ∀ (ℓ : List Nat) (a : Nat), (onLeaf ℓ a).length = countEq ℓ a
  | [], _ => rfl
  | y :: ℓ, a => by
    unfold onLeaf
    rw [List.length_cons, List.range_succ_eq_map, List.filter_cons, countEq_cons]
    simp only [List.getD_cons_zero, List.filter_map]
    have ih := onLeaf_length ℓ a
    unfold onLeaf at ih
    have : (List.range ℓ.length).filter ((fun s => (y :: ℓ).getD s 0 == a) ∘ Nat.succ) =
        (List.range ℓ.length).filter (fun s => ℓ.getD s 0 == a) := by
      apply List.filter_congr; intro s _; simp [Function.comp]
    rw [this]
    by_cases hy : (y == a) = true
    · simp only [hy, if_true, List.length_cons, List.length_map, ih]; omega
    · simp only [hy, Bool.false_eq_true, if_false, List.length_map, ih]; omega

/-- The covered event: at leaf `a`, each of the target's `k` indices was used
    by some signature on that leaf (`xs s` are signature `s`'s indices). -/
def covered (ℓ : List Nat) (a : Nat) (xs : Nat → List Nat) (k : Nat) (x0 : List Nat) : Bool :=
  (List.range k).all (fun i => (List.range ℓ.length).any
    (fun s => ℓ.getD s 0 == a && (xs s).getD i 0 == x0.getD i 0))

theorem covered_count (t : Nat) (ℓ : List Nat) (a : Nat) (xs : Nat → List Nat) (k : Nat) :
    tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0) ≤ (countEq ℓ a)^k := by
  let C : Nat → List Nat := fun i => (onLeaf ℓ a).map (fun s => (xs s).getD i 0)
  have hC : ∀ i, (C i).length ≤ countEq ℓ a := fun i => by simp [C, onLeaf_length]
  refine Nat.le_trans (tsum_mono t k ?_) (product_count t _ k C hC)
  intro x0
  split
  · next h =>
    unfold covered at h
    have : (List.range k).all (fun i => (C i).contains (x0.getD i 0)) = true := by
      rw [List.all_eq_true] at h ⊢
      intro i hi
      obtain ⟨s, hs, hm⟩ := List.any_eq_true.mp (h i hi)
      simp only [Bool.and_eq_true, beq_iff_eq] at hm
      simp only [C, List.contains_iff_mem, List.mem_map]
      exact ⟨s, List.mem_filter.mpr ⟨hs, beq_iff_eq.mpr hm.1⟩, hm.2⟩
    rw [if_pos this]
    exact Nat.le_refl 1
  · exact Nat.zero_le _

theorem covered_count_le_all (t : Nat) (ℓ : List Nat) (a : Nat) (xs : Nat → List Nat) (k : Nat) :
    tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0) ≤ t^k := by
  calc _ ≤ tsum t k (fun _ => 1) := tsum_mono t k (fun x0 => by split <;> simp)
    _ = t^k := by rw [tsum_const]; simp

/-! Telescoping and the ITSR bound. -/

theorem range_succ_sum' (L : Nat) (f : Nat → Nat) :
    ((List.range (L+1)).map f).sum = ((List.range L).map f).sum + f L := by
  rw [List.range_succ, List.map_append]
  generalize (List.range L).map f = l
  induction l with
  | nil => simp
  | cons a l ih => simp only [List.cons_append, List.sum_cons, ih]; omega

theorem telescope (k γ : Nat) (hk : 0 < k) : ∀ G,
    ((List.range G).map (fun g => ((g+1)^k - g^k) * (if g+1 ≤ γ then 1 else 0))).sum = (min γ G)^k
  | 0 => by simp [Nat.zero_pow hk]
  | G+1 => by
    rw [range_succ_sum', telescope k γ hk G]
    have mono : G^k ≤ (G+1)^k := Nat.pow_le_pow_left (Nat.le_succ G) k
    by_cases h : G + 1 ≤ γ
    · rw [if_pos h, Nat.mul_one, Nat.min_eq_right (by omega), Nat.min_eq_right h]; omega
    · rw [if_neg h, Nat.mul_zero, Nat.add_zero, Nat.min_eq_left (by omega), Nat.min_eq_left (by omega)]

theorem fact_dvd : ∀ {g n : Nat}, g ≤ n → fact g ∣ fact n
  | g, 0, h => by have : g = 0 := by omega
                  subst this; exact Nat.dvd_refl _
  | g, n+1, h => by
    by_cases e : g = n + 1
    · subst e; exact Nat.dvd_refl _
    · exact Nat.dvd_trans (fact_dvd (by omega)) (Nat.dvd_mul_left _ _)

/-- The ITSR numerator over the common denominator `(G+1)! · L^(G+1) · t^k`. -/
def itsrNum (L t k q G : Nat) : Nat :=
  ((List.range G).map (fun g =>
    ((g+1)^k - g^k) * q^(g+1) * L^(G-g) * (fact (G+1) / fact (g+1)))).sum + t^k * q^(G+1)

/-- The static ITSR bound: over `q` uniform signature leaves and a uniform
    target index vector, the covered fraction at any leaf `a`, for any
    signature indices, is at most `itsrNum / ((G+1)! · L^(G+1) · t^k)`. -/
theorem itsr_static (L t k q G a : Nat) (xs : Nat → List Nat) (hk : 0 < k) :
    tsum L q (fun ℓ => tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0)) *
      (fact (G+1) * L^(G+1)) ≤ L^q * itsrNum L t k q G := by
  let N : Nat → Nat := fun g => tsum L q (fun ℓ => if g ≤ countEq ℓ a then 1 else 0)
  let Δ : Nat → Nat := fun g => (g+1)^k - g^k
  have point : ∀ ℓ, tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0) ≤
      ((List.range G).map (fun g => Δ g * (if g+1 ≤ countEq ℓ a then 1 else 0))).sum +
      t^k * (if G+1 ≤ countEq ℓ a then 1 else 0) := by
    intro ℓ
    simp only [Δ]
    rw [telescope k _ hk]
    by_cases h : G + 1 ≤ countEq ℓ a
    · rw [if_pos h, Nat.mul_one]
      exact Nat.le_trans (covered_count_le_all t ℓ a xs k) (Nat.le_add_left _ _)
    · rw [if_neg h, Nat.mul_zero, Nat.add_zero, Nat.min_eq_left (by omega)]
      exact covered_count t ℓ a xs k
  have total : tsum L q (fun ℓ => tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0)) ≤
      ((List.range G).map (fun g => Δ g * N (g+1))).sum + t^k * N (G+1) := by
    refine Nat.le_trans (tsum_mono L q point) ?_
    rw [tsum_add, tsum_list, tsum_mul]
    apply Nat.le_of_eq
    congr 1
    congr 1; apply List.map_congr_left; intro g _
    exact tsum_mul L (Δ g) q _
  have term : ∀ g, g < G → N (g+1) * (fact (G+1) * L^(G+1)) ≤
      q^(g+1) * L^q * (L^(G-g) * (fact (G+1) / fact (g+1))) := by
    intro g hg
    have hdiv : fact (G+1) = fact (g+1) * (fact (G+1) / fact (g+1)) :=
      (Nat.mul_div_cancel' (fact_dvd (by omega))).symm
    have hpow : L^(G+1) = L^(g+1) * L^(G-g) := by rw [← Nat.pow_add]; congr 1; omega
    calc N (g+1) * (fact (G+1) * L^(G+1))
        = (N (g+1) * (L^(g+1) * fact (g+1))) * (L^(G-g) * (fact (G+1) / fact (g+1))) := by
          conv => lhs; rw [hdiv, hpow]
          ac_rfl
      _ ≤ (q^(g+1) * L^q) * (L^(G-g) * (fact (G+1) / fact (g+1))) :=
          Nat.mul_le_mul_right _ (many_on_leaf L a q (g+1))
  have last : N (G+1) * (fact (G+1) * L^(G+1)) ≤ q^(G+1) * L^q := by
    have := many_on_leaf L a q (G+1)
    calc N (G+1) * (fact (G+1) * L^(G+1)) = N (G+1) * (L^(G+1) * fact (G+1)) := by rw [Nat.mul_comm (fact _)]
      _ ≤ _ := this
  calc _ ≤ (((List.range G).map (fun g => Δ g * N (g+1))).sum + t^k * N (G+1)) * (fact (G+1) * L^(G+1)) :=
        Nat.mul_le_mul_right _ total
    _ = ((List.range G).map (fun g => Δ g * (N (g+1) * (fact (G+1) * L^(G+1))))).sum +
          t^k * (N (G+1) * (fact (G+1) * L^(G+1))) := by
        rw [Nat.add_mul, Nat.mul_comm, ← sum_map_mul, Nat.mul_assoc]
        congr 1; congr 1; apply List.map_congr_left; intro g _; ac_rfl
    _ ≤ ((List.range G).map (fun g => Δ g * (q^(g+1) * L^q * (L^(G-g) * (fact (G+1) / fact (g+1)))))).sum +
          t^k * (q^(G+1) * L^q) := by
        apply Nat.add_le_add
        · apply sum_map_le; intro g hg
          exact Nat.mul_le_mul_left _ (term g (List.mem_range.mp hg))
        · exact Nat.mul_le_mul_left _ last
    _ = L^q * itsrNum L t k q G := by
        unfold itsrNum
        rw [Nat.mul_add, ← sum_map_mul]
        congr 1
        · congr 1; apply List.map_congr_left; intro g _; simp only [Δ]; ac_rfl
        · ac_rfl

/-- From a cross-multiplied numeric check to a probability bound `2^-b`. -/
theorem itsr_bits (L t k q G a b : Nat) (xs : Nat → List Nat) (hL : 0 < L) (hk : 0 < k)
    (check : itsrNum L t k q G * 2^b ≤ fact (G+1) * L^(G+1) * t^k) :
    tsum L q (fun ℓ => tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0)) * 2^b ≤ L^q * t^k := by
  have hD : 0 < fact (G+1) * L^(G+1) := Nat.mul_pos (fact_pos _) (Nat.pow_pos hL)
  apply Nat.le_of_mul_le_mul_right _ hD
  calc _ = (tsum L q (fun ℓ => tsum t k (fun x0 => if covered ℓ a xs k x0 then 1 else 0)) *
        (fact (G+1) * L^(G+1))) * 2^b := by ac_rfl
    _ ≤ (L^q * itsrNum L t k q G) * 2^b := Nat.mul_le_mul_right _ (itsr_static L t k q G a xs hk)
    _ = L^q * (itsrNum L t k q G * 2^b) := by ac_rfl
    _ ≤ L^q * (fact (G+1) * L^(G+1) * t^k) := Nat.mul_le_mul_left _ check
    _ = L^q * t^k * (fact (G+1) * L^(G+1)) := by ac_rfl

/-! The deployed parameter sets, at `q_s = 2^64` signatures (`G = 40`).
    SPX128f: `L = 2^66` hypertree leaves, `t = 2^6`, `k = 33`.
    SPX256f: `L = 2^68`, `t = 2^9`, `k = 35`. -/

theorem itsr_check_128f : itsrNum (2^66) 64 33 (2^64) 40 * 2^128 ≤ fact 41 * (2^66)^41 * 64^33 := by
  decide

theorem itsr_check_256f : itsrNum (2^68) 512 35 (2^64) 40 * 2^255 ≤ fact 41 * (2^68)^41 * 512^35 := by
  decide

theorem itsrNum_mono (L t k G : Nat) {q Q : Nat} (h : q ≤ Q) : itsrNum L t k q G ≤ itsrNum L t k Q G := by
  unfold itsrNum
  apply Nat.add_le_add
  · apply sum_map_le; intro g _
    exact Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _
      (Nat.mul_le_mul_left _ (Nat.pow_le_pow_left h _)))
  · exact Nat.mul_le_mul_left _ (Nat.pow_le_pow_left h _)

/-- SPX128f: per fresh digest, after at most `2^64` signatures, covered with
    probability at most `2^-128` (random-oracle model). -/
theorem itsr_spx128f (q : Nat) (hq : q ≤ 2^64) (a : Nat) (xs : Nat → List Nat) :
    tsum (2^66) q (fun ℓ => tsum 64 33 (fun x0 => if covered ℓ a xs 33 x0 then 1 else 0)) * 2^128
      ≤ (2^66)^q * 64^33 :=
  itsr_bits (2^66) 64 33 q 40 a 128 xs (by decide) (by decide)
    (Nat.le_trans (Nat.mul_le_mul_right _ (itsrNum_mono _ _ _ _ hq)) itsr_check_128f)

/-- SPX256f: per fresh digest, after at most `2^64` signatures, covered with
    probability at most `2^-255` (random-oracle model). -/
theorem itsr_spx256f (q : Nat) (hq : q ≤ 2^64) (a : Nat) (xs : Nat → List Nat) :
    tsum (2^68) q (fun ℓ => tsum 512 35 (fun x0 => if covered ℓ a xs 35 x0 then 1 else 0)) * 2^255
      ≤ (2^68)^q * 512^35 :=
  itsr_bits (2^68) 512 35 q 40 a 255 xs (by decide) (by decide)
    (Nat.le_trans (Nat.mul_le_mul_right _ (itsrNum_mono _ _ _ _ hq)) itsr_check_256f)

#print axioms many_on_leaf
#print axioms itsr_static
#print axioms itsr_spx128f
#print axioms itsr_spx256f

end DSM.Rom
