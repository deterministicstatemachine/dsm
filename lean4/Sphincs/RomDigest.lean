-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomTape
import Sphincs.RomRoles
import Sphincs.WotsChecksum
import Sphincs.RomSample
import Sphincs.RomItsrA
/- DSM's h_msg digests are ITSR-uniform. A digest `be m v` splits into the
   md bytes, tree bytes and leaf bytes (`be_split`, `split_three`); the FORS
   indices are the top `k·a` bits of the md part read `a` bits at a time
   (`base2b_be`), so over uniform `v` every (hypertree leaf, index vector)
   pair occurs equally often (`digest_fiber`). With `itsr_adaptive` this
   gives the adaptive ITSR bound for DSM's own digests at the deployed
   parameters: at most 2^-128 (SPX128f) and 2^-255 (SPX256f) per target,
   after at most 2^64 signature digests selected adaptively. -/
namespace DSM.Rom
open DSM.Sphincs

theorem sum_range_mul (f : Nat → Nat) (B : Nat) : ∀ A : Nat,
    ((List.range (A*B)).map f).sum = ((List.range A).map (fun x => ((List.range B).map (fun y => f (x*B+y))).sum)).sum
  | 0 => by simp
  | A+1 => by
    rw [Nat.succ_mul, List.range_add, List.map_append, sum_append', sum_range_mul f B A, range_succ_sum,
      List.map_map]
    rfl

theorem sum_mod_periodic (G : Nat → Nat) (M c : Nat) :
    ((List.range (c*M)).map (fun v => G (v % M))).sum = c * ((List.range M).map G).sum := by
  rw [sum_range_mul]
  have e : ∀ x, ((List.range M).map (fun y => G ((x*M+y) % M))).sum = ((List.range M).map G).sum := by
    intro x; congr 1; apply List.map_congr_left; intro y hy
    rw [Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt (List.mem_range.mp hy)]
  simp only [e, sum_map_const, List.length_range]

theorem be_split (a : Nat) : ∀ (b x y : Nat), y < 256^b → be (a+b) (x*256^b + y) = be a x ++ be b y
  | 0, x, y, hy => by
    have : y = 0 := by simp at hy; omega
    subst this; simp [be]
  | b+1, x, y, hy => by
    show be ((a+b)+1) _ = _
    simp only [be]
    have h1 : (x*256^(b+1) + y)/256 = x*256^b + y/256 := by
      rw [Nat.pow_succ, ← Nat.mul_assoc, Nat.mul_comm (x*256^b) 256, Nat.add_comm, Nat.add_mul_div_left _ _ (by decide)]
      omega
    have h2 : (x*256^(b+1) + y) % 256 = y % 256 := by
      rw [Nat.pow_succ, ← Nat.mul_assoc, Nat.add_comm, Nat.add_mul_mod_self_right]
    have hy' : y/256 < 256^b := by
      rw [Nat.pow_succ] at hy; exact Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hy)
    rw [h1, h2, be_split a b x (y/256) hy', List.append_assoc]

theorem be_getElem? : ∀ (B x j : Nat), j < B → (be B x)[j]? = some (UInt8.ofNat (x / 256^(B-1-j) % 256))
  | 0, _, _, h => absurd h (Nat.not_lt_zero _)
  | B+1, x, j, h => by
    simp only [be]
    by_cases hj : j < B
    · rw [List.getElem?_append_left (by rw [be_width]; exact hj), be_getElem? B (x/256) j hj,
        Nat.div_div_eq_div_mul, ← Nat.pow_succ', show B + 1 - 1 - j = B - 1 - j + 1 by omega]
    · have hjB : j = B := by omega
      subst hjB
      rw [List.getElem?_append_right (by simp [be_width]), be_width]
      simp

theorem divmod_bit (a i : Nat) : a / 2^i % 2 = if a.testBit i then 1 else 0 := by
  rw [Nat.testBit_eq_decide_div_mod_eq]
  rcases Nat.mod_two_eq_zero_or_one (a / 2^i) with h | h <;> simp [h]

theorem be_bit (B x n : Nat) (hn : n < 8*B) :
    (((be B x)[n/8]?.getD 0).toNat / 2^(7 - n%8)) % 2 = x / 2^(8*B-1-n) % 2 := by
  have hto : ∀ m : Nat, (UInt8.ofNat m).toNat = m % 256 := fun m => by simp
  rw [be_getElem? B x (n/8) (by omega), Option.getD_some, hto, Nat.mod_mod]
  rw [show (256:Nat) = 2^8 from rfl, ← Nat.pow_mul, divmod_bit, divmod_bit, Nat.testBit_mod_two_pow,
    Nat.testBit_div_two_pow]
  have h7 : 7 - n % 8 < 8 := by omega
  simp only [h7, decide_true, Bool.true_and]
  rw [show 7 - n % 8 + 8 * (B - 1 - n / 8) = 8 * B - 1 - n by omega]

theorem fold_bits (X E : Nat) (g : Nat → Nat) : ∀ b, b ≤ E+1 → (∀ j, j < b → g j = X / 2^(E-j) % 2) →
    (List.range b).foldl (fun acc j => acc*2 + g j) 0 = X / 2^(E+1-b) % 2^b
  | 0, _, _ => by simp [Nat.mod_one]
  | b+1, hb, hg => by
    rw [List.range_succ, List.foldl_append, fold_bits X E g b (by omega) (fun j hj => hg j (by omega))]
    simp only [List.foldl_cons, List.foldl_nil]
    rw [hg b (by omega)]
    have e1 : E + 1 - b = (E - b) + 1 := by omega
    rw [e1, Nat.pow_succ, ← Nat.div_div_eq_div_mul, show E + 1 - (b+1) = E - b by omega,
      Nat.pow_succ', Nat.mod_mul]
    omega

/-- The `i`-th `b`-bit digit of the big-endian encoding of `x`. -/
theorem base2b_be (B x b count i : Nat) (hb : 0 < b) (hi : i < count) (hcb : count*b ≤ 8*B) :
    (base2b (be B x) b count).getD i 0 = x / 2^(8*B - (i+1)*b) % 2^b := by
  unfold base2b
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hi]
  simp only [Option.map_some, Option.getD_some]
  have hib : (i+1)*b ≤ 8*B := Nat.le_trans (Nat.mul_le_mul_right _ hi) hcb
  rw [Nat.succ_mul] at hib
  rw [fold_bits x (8*B-1-i*b) _ b (by omega)]
  · have e : (i+1)*b = i*b + b := Nat.succ_mul i b
    rw [show 8*B - 1 - i*b + 1 - b = 8*B - (i+1)*b by rw [e]; omega]
  · intro j hj
    have hn : i*b + j < 8*B := by omega
    rw [be_bit B x (i*b+j) hn, show 8*B - 1 - i*b - j = 8*B - 1 - (i*b+j) by omega]

theorem base2b_be_list (B x b count : Nat) (hb : 0 < b) (hcb : count*b ≤ 8*B) :
    base2b (be B x) b count = (List.range count).map (fun i => x / 2^(8*B - (i+1)*b) % 2^b) := by
  apply List.ext_getElem?
  intro i
  by_cases hi : i < count
  · have := base2b_be B x b count i hb hi hcb
    rw [List.getD_eq_getElem?_getD] at this
    rw [List.getElem?_map, List.getElem?_range hi]
    have hl : i < (base2b (be B x) b count).length := by rw [base2b_length]; exact hi
    rw [List.getElem?_eq_getElem hl] at this ⊢
    simp only [Option.getD_some] at this
    simp [this]
  · rw [List.getElem?_eq_none (by rw [base2b_length]; omega), List.getElem?_eq_none (by simp; omega)]

/-- Most-significant-first base-`T` digits. -/
def digitsT (T k D : Nat) : List Nat := (List.range k).map (fun i => D / T^(k-1-i) % T)

theorem digitsT_cons (T k y D : Nat) (hT : 0 < T) (hy : y < T) (hD : D < T^k) :
    digitsT T (k+1) (y*T^k + D) = y :: digitsT T k D := by
  unfold digitsT
  rw [List.range_succ_eq_map, List.map_cons, List.map_map]
  congr 1
  · rw [show k + 1 - 1 - 0 = k by omega, Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos hT),
      Nat.div_eq_of_lt hD, Nat.zero_add, Nat.mod_eq_of_lt hy]
  · apply List.map_congr_left
    intro i hi
    have hik : i < k := List.mem_range.mp hi
    simp only [Function.comp]
    have hp : T^k = T^(k-1-i) * T^(i+1) := by rw [← Nat.pow_add]; congr 1; omega
    rw [show k + 1 - 1 - (i+1) = k-1-i by omega, hp, Nat.mul_comm (T^(k-1-i)), ← Nat.mul_assoc,
      Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos hT), Nat.pow_succ, ← Nat.mul_assoc,
      Nat.add_mul_mod_self_right]

theorem sum_digitsT (T : Nat) (hT : 0 < T) : ∀ (k : Nat) (F : List Nat → Nat),
    ((List.range (T^k)).map (fun D => F (digitsT T k D))).sum = tsum T k F
  | 0, F => by simp [digitsT, tsum]
  | k+1, F => by
    rw [Nat.pow_succ', sum_range_mul]
    simp only [tsum]
    apply congrArg List.sum; apply List.map_congr_left; intro y hy
    rw [← sum_digitsT T hT k (fun t => F (y :: t))]
    congr 1; apply List.map_congr_left; intro D hD
    rw [digitsT_cons T k y D hT (List.mem_range.mp hy) (List.mem_range.mp hD)]

/-- The FORS digits of a uniform md part: every digit vector occurs equally often. -/
theorem sum_md_digits (mdB a k : Nat) (ha : 0 < a) (hka : k*a ≤ 8*mdB) (F : List Nat → Nat) :
    ((List.range (256^mdB)).map (fun x => F (base2b (be mdB x) a k))).sum =
      2^(8*mdB - k*a) * tsum (2^a) k F := by
  have h256 : 256^mdB = 2^(k*a) * 2^(8*mdB - k*a) := by
    rw [← Nat.pow_add, show k*a + (8*mdB - k*a) = 8*mdB by omega, Nat.pow_mul]
  rw [h256, sum_range_mul]
  have e : ∀ D, D < 2^(k*a) → ∀ low, low < 2^(8*mdB - k*a) →
      base2b (be mdB (D * 2^(8*mdB - k*a) + low)) a k = digitsT (2^a) k D := by
    intro D hD low hlow
    rw [base2b_be_list mdB _ a k ha hka]
    unfold digitsT
    apply List.map_congr_left
    intro i hi
    have hik : i < k := List.mem_range.mp hi
    have ex : 8*mdB - (i+1)*a = (8*mdB - k*a) + (k-1-i)*a := by
      have : (i+1)*a + (k-1-i)*a = k*a := by rw [← Nat.add_mul]; congr 1; omega
      omega
    rw [ex, Nat.pow_add, ← Nat.div_div_eq_div_mul, Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
      Nat.div_eq_of_lt hlow, Nat.zero_add, ← Nat.pow_mul, Nat.mul_comm (k-1-i) a]
  have e2 : ∀ D, D ∈ List.range (2^(k*a)) →
      ((List.range (2^(8*mdB - k*a))).map (fun low => F (base2b (be mdB (D * 2^(8*mdB - k*a) + low)) a k))).sum =
        2^(8*mdB - k*a) * F (digitsT (2^a) k D) := by
    intro D hD
    rw [List.map_congr_left (fun low hl => by rw [e D (List.mem_range.mp hD) low (List.mem_range.mp hl)]),
      sum_map_const, List.length_range]
  rw [List.map_congr_left e2, sum_map_mul,
    show (2:Nat)^(k*a) = (2^a)^k by rw [← Nat.pow_mul, Nat.mul_comm], sum_digitsT _ (Nat.pow_pos (by decide))]

/-- The hypertree leaf (tree·2^hp + leaf) of the digest `be m v`. -/
def dLeaf (p : Params) (v : Nat) : Nat :=
  (splitDigest p (be p.m v)).tree * 2^p.hp + (splitDigest p (be p.m v)).leaf
/-- The FORS indices of the digest `be m v`. -/
def dIdx (p : Params) (v : Nat) : List Nat := base2b (splitDigest p (be p.m v)).md p.a p.k

theorem split_three (p : Params) (x y z : Nat) (hy : y < 256^p.treeBytes) (hz : z < 256^p.leafBytes) :
    splitDigest p (be p.mdBytes x ++ (be p.treeBytes y ++ be p.leafBytes z)) =
      ⟨be p.mdBytes x, y % 2^(p.h-p.hp), z % 2^p.hp⟩ := by
  unfold splitDigest
  have h1 : (be p.mdBytes x ++ (be p.treeBytes y ++ be p.leafBytes z)).take p.mdBytes = be p.mdBytes x :=
    List.take_left' (be_width _ _)
  have h2 : slice (be p.mdBytes x ++ (be p.treeBytes y ++ be p.leafBytes z)) p.mdBytes p.treeBytes =
      be p.treeBytes y := by
    unfold slice; rw [List.drop_left' (be_width _ _)]; exact List.take_left' (be_width _ _)
  have h3 : slice (be p.mdBytes x ++ (be p.treeBytes y ++ be p.leafBytes z)) (p.mdBytes + p.treeBytes)
      p.leafBytes = be p.leafBytes z := by
    unfold slice
    rw [← List.append_assoc, List.drop_left' (by simp [be_width])]
    exact List.take_of_length_le (by simp [be_width])
  rw [h1, h2, h3, be_roundtrip _ _ hy, be_roundtrip _ _ hz]

theorem be_three (p : Params) (x y z : Nat) (hy : y < 256^p.treeBytes) (hz : z < 256^p.leafBytes) :
    be p.m (x * 256^(p.treeBytes + p.leafBytes) + (y * 256^p.leafBytes + z)) =
      be p.mdBytes x ++ (be p.treeBytes y ++ be p.leafBytes z) := by
  have hw : y * 256^p.leafBytes + z < 256^(p.treeBytes + p.leafBytes) := by
    rw [Nat.pow_add]
    calc y * 256^p.leafBytes + z < y * 256^p.leafBytes + 256^p.leafBytes := by omega
      _ = (y+1) * 256^p.leafBytes := by rw [Nat.succ_mul]
      _ ≤ 256^p.treeBytes * 256^p.leafBytes := Nat.mul_le_mul_right _ hy
  rw [show p.m = p.mdBytes + (p.treeBytes + p.leafBytes) by unfold Params.m; omega,
    be_split _ _ _ _ hw, be_split _ _ _ _ hz]

/-- Uniform h_msg outputs give uniform (hypertree leaf, FORS indices): every
    pair occurs equally often among the digests `be m v`, `v < c·256^m`. -/
theorem digest_fiber (p : Params) (c : Nat) (ha : 0 < p.a) (hka : p.k*p.a ≤ 8*p.mdBytes)
    (hh : p.hp ≤ p.h) (hA : 2^(p.h-p.hp) ∣ 256^p.treeBytes) (hB : 2^p.hp ∣ 256^p.leafBytes)
    (F : Nat → List Nat → Nat) :
    ((List.range (c * 256^p.m)).map (fun v => F (dLeaf p v) (dIdx p v))).sum * (2^p.h * (2^p.a)^p.k) =
      (c * 256^p.m) * ((List.range (2^p.h)).map (fun l => tsum (2^p.a) p.k (F l))).sum := by
  obtain ⟨cA, hcA⟩ := hA
  obtain ⟨cB, hcB⟩ := hB
  let G : Nat → Nat := fun u => F (dLeaf p u) (dIdx p u)
  have hper : ∀ v, G v = G (v % 256^p.m) := by
    intro v; simp only [G, dLeaf, dIdx]; rw [be_mod p.m v]
  have s1 : ((List.range (c * 256^p.m)).map G).sum = c * ((List.range (256^p.m)).map G).sum := by
    rw [List.map_congr_left (fun v _ => hper v)]; exact sum_mod_periodic G _ c
  have hm : 256^p.m = 256^p.mdBytes * (256^p.treeBytes * 256^p.leafBytes) := by
    rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; unfold Params.m; omega
  -- inner sum over (tree, leaf) bytes for a fixed md part
  have inner : ∀ x, ((List.range (256^p.treeBytes * 256^p.leafBytes)).map
      (fun w => G (x * (256^p.treeBytes * 256^p.leafBytes) + w))).sum =
      cA * cB * ((List.range (2^p.h)).map (fun l => F l (base2b (be p.mdBytes x) p.a p.k))).sum := by
    intro x
    rw [sum_range_mul]
    have e : ∀ y, y ∈ List.range (256^p.treeBytes) → ∀ z, z ∈ List.range (256^p.leafBytes) →
        G (x * (256^p.treeBytes * 256^p.leafBytes) + (y * 256^p.leafBytes + z)) =
          F ((y % 2^(p.h-p.hp)) * 2^p.hp + z % 2^p.hp) (base2b (be p.mdBytes x) p.a p.k) := by
      intro y hy z hz
      simp only [G, dLeaf, dIdx]
      rw [← Nat.pow_add, be_three p x y z (List.mem_range.mp hy) (List.mem_range.mp hz),
        split_three p x y z (List.mem_range.mp hy) (List.mem_range.mp hz)]
    rw [List.map_congr_left (fun y hy => by
      rw [List.map_congr_left (fun z hz => e y hy z hz)])]
    have ez : ∀ t, ((List.range (256^p.leafBytes)).map
        (fun z => F (t * 2^p.hp + z % 2^p.hp) (base2b (be p.mdBytes x) p.a p.k))).sum =
        cB * ((List.range (2^p.hp)).map (fun l => F (t * 2^p.hp + l) (base2b (be p.mdBytes x) p.a p.k))).sum := by
      intro t
      rw [hcB, Nat.mul_comm (2^p.hp) cB]
      exact sum_mod_periodic (fun l => F (t * 2^p.hp + l) (base2b (be p.mdBytes x) p.a p.k)) _ cB
    simp only [ez]
    rw [sum_map_mul, hcA, Nat.mul_comm (2^(p.h-p.hp)) cA,
      sum_mod_periodic (fun t => ((List.range (2^p.hp)).map
        (fun l => F (t * 2^p.hp + l) (base2b (be p.mdBytes x) p.a p.k))).sum) _ cA]
    have hr := sum_range_mul (fun l => F l (base2b (be p.mdBytes x) p.a p.k)) (2^p.hp) (2^(p.h-p.hp))
    simp only at hr
    rw [← hr, ← Nat.pow_add, show p.h - p.hp + p.hp = p.h by omega]
    ac_rfl
  rw [s1, hm, sum_range_mul]
  rw [List.map_congr_left (fun x _ => inner x), sum_map_mul, sum_comm]
  have hmd : ∀ l, ((List.range (256^p.mdBytes)).map (fun x => F l (base2b (be p.mdBytes x) p.a p.k))).sum =
      2^(8*p.mdBytes - p.k*p.a) * tsum (2^p.a) p.k (F l) :=
    fun l => sum_md_digits p.mdBytes p.a p.k ha hka (F l)
  simp only [hmd]
  rw [sum_map_mul]
  have h256 : 256^p.mdBytes = 2^(8*p.mdBytes - p.k*p.a) * (2^p.a)^p.k := by
    rw [← Nat.pow_mul, ← Nat.pow_add, show 8*p.mdBytes - p.k*p.a + p.a*p.k = 8*p.mdBytes by
      rw [Nat.mul_comm p.a]; omega, Nat.pow_mul]
  have h2h : 2^p.h = 2^(p.h-p.hp) * 2^p.hp := by rw [← Nat.pow_add]; congr 1; omega
  rw [h256, hcA, hcB, h2h]
  ac_rfl

theorem digest_params (v : Variant) (hv : v = .spx128f ∨ v = .spx256f) :
    0 < (params v).a ∧ (params v).k*(params v).a ≤ 8*(params v).mdBytes ∧ (params v).hp ≤ (params v).h ∧
    2^((params v).h-(params v).hp) ∣ 256^(params v).treeBytes ∧ 2^(params v).hp ∣ 256^(params v).leafBytes := by
  rcases hv with rfl | rfl <;> decide

/-- Adaptive ITSR for DSM's digests, SPX128f: under any adaptive selection
    of a target and at most `q ≤ 2^64` signature digests among uniform tape
    entries (`R = c·256^m`), the target is covered with probability at most
    `2^-128`. -/
theorem itsr_dsm_128f (c N q : Nat) (hc : 0 < c) (hq : q ≤ 2^64) (slot : List Nat → Option Nat)
    (hA : ∀ t : List Nat, t.length = N → (assigned slot t).Nodup ∧ ∀ s ∈ assigned slot t, s < q+1) :
    tsum (c * 256^(params .spx128f).m) N (fun t =>
      if covA (dLeaf (params .spx128f)) (dIdx (params .spx128f)) 33 q
        (fill slot (List.replicate (q+1) 0) t) then 1 else 0) * 2^128 ≤ (c * 256^(params .spx128f).m)^N := by
  obtain ⟨ha, hka, hh, hA', hB'⟩ := digest_params .spx128f (Or.inl rfl)
  have hR : 0 < c * 256^(params .spx128f).m := Nat.mul_pos hc (Nat.pow_pos (by decide))
  have main := itsr_adaptive (c * 256^(params .spx128f).m) N (2^66) 64 33 q 40 (dLeaf (params .spx128f))
    (dIdx (params .spx128f)) (by decide) hR (by decide) (by decide)
    (fun F => digest_fiber (params .spx128f) c ha hka hh hA' hB' F) slot hA
  have chk := Nat.le_trans (Nat.mul_le_mul_right _ (itsrNum_mono (2^66) 64 33 40 hq)) itsr_check_128f
  have hD : 0 < 64^33 * (fact 41 * (2^66)^41) := Nat.mul_pos (by decide) (Nat.mul_pos (fact_pos _) (by decide))
  apply Nat.le_of_mul_le_mul_right _ hD
  calc _ = (tsum (c * 256^(params .spx128f).m) N (fun t =>
      if covA (dLeaf (params .spx128f)) (dIdx (params .spx128f)) 33 q
        (fill slot (List.replicate (q+1) 0) t) then 1 else 0) * (64^33 * (fact 41 * (2^66)^41))) * 2^128 := by ac_rfl
    _ ≤ ((c * 256^(params .spx128f).m)^N * itsrNum (2^66) 64 33 q 40) * 2^128 := Nat.mul_le_mul_right _ main
    _ = (c * 256^(params .spx128f).m)^N * (itsrNum (2^66) 64 33 q 40 * 2^128) := by ac_rfl
    _ ≤ (c * 256^(params .spx128f).m)^N * (fact 41 * (2^66)^41 * 64^33) := Nat.mul_le_mul_left _ chk
    _ = _ := by ac_rfl

/-- Adaptive ITSR for DSM's digests, SPX256f: at most `2^-255`. -/
theorem itsr_dsm_256f (c N q : Nat) (hc : 0 < c) (hq : q ≤ 2^64) (slot : List Nat → Option Nat)
    (hA : ∀ t : List Nat, t.length = N → (assigned slot t).Nodup ∧ ∀ s ∈ assigned slot t, s < q+1) :
    tsum (c * 256^(params .spx256f).m) N (fun t =>
      if covA (dLeaf (params .spx256f)) (dIdx (params .spx256f)) 35 q
        (fill slot (List.replicate (q+1) 0) t) then 1 else 0) * 2^255 ≤ (c * 256^(params .spx256f).m)^N := by
  obtain ⟨ha, hka, hh, hA', hB'⟩ := digest_params .spx256f (Or.inr rfl)
  have hR : 0 < c * 256^(params .spx256f).m := Nat.mul_pos hc (Nat.pow_pos (by decide))
  have main := itsr_adaptive (c * 256^(params .spx256f).m) N (2^68) 512 35 q 40 (dLeaf (params .spx256f))
    (dIdx (params .spx256f)) (by decide) hR (by decide) (by decide)
    (fun F => digest_fiber (params .spx256f) c ha hka hh hA' hB' F) slot hA
  have chk := Nat.le_trans (Nat.mul_le_mul_right _ (itsrNum_mono (2^68) 512 35 40 hq)) itsr_check_256f
  have hD : 0 < 512^35 * (fact 41 * (2^68)^41) := Nat.mul_pos (by decide) (Nat.mul_pos (fact_pos _) (by decide))
  apply Nat.le_of_mul_le_mul_right _ hD
  calc _ = (tsum (c * 256^(params .spx256f).m) N (fun t =>
      if covA (dLeaf (params .spx256f)) (dIdx (params .spx256f)) 35 q
        (fill slot (List.replicate (q+1) 0) t) then 1 else 0) * (512^35 * (fact 41 * (2^68)^41))) * 2^255 := by ac_rfl
    _ ≤ ((c * 256^(params .spx256f).m)^N * itsrNum (2^68) 512 35 q 40) * 2^255 := Nat.mul_le_mul_right _ main
    _ = (c * 256^(params .spx256f).m)^N * (itsrNum (2^68) 512 35 q 40 * 2^255) := by ac_rfl
    _ ≤ (c * 256^(params .spx256f).m)^N * (fact 41 * (2^68)^41 * 512^35) := Nat.mul_le_mul_left _ chk
    _ = _ := by ac_rfl

#print axioms digest_fiber
#print axioms itsr_dsm_128f
#print axioms itsr_dsm_256f
end DSM.Rom
