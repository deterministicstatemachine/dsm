-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomItsr
import Sphincs.RomSample
import Sphincs.RomSym

/- ITSR under adaptive signing (link 4). The static bound `itsr_static`
   fixes the signature leaves as independent uniform values. Here a run
   decides, from the tape entries already read, which entry is the target
   digest and which are signature digests (`RomSample`): each digest is
   uniform when it is read, but which ones count is adaptive. `itsr_gen`
   generalizes the static bound to digests that decode to a leaf through a
   map with equal fibers and to arbitrary signature indices; `itsr_adaptive`
   bounds the covered probability under any such adaptive selection of at
   most `q` signature digests by the same static numerator. -/
namespace DSM.Rom

/-- The pointwise ITSR bound, as a function of the signature leaves only. -/
def itsrP (T k G a : Nat) (ℓ : List Nat) : Nat :=
  ((List.range G).map (fun g => ((g+1)^k - g^k) * (if g+1 ≤ countEq ℓ a then 1 else 0))).sum +
    T^k * (if G+1 ≤ countEq ℓ a then 1 else 0)

theorem itsr_point (T k G a : Nat) (hk : 0 < k) (ℓ : List Nat) (xs : Nat → List Nat) :
    tsum T k (fun x0 => if covered ℓ a xs k x0 then 1 else 0) ≤ itsrP T k G a ℓ := by
  unfold itsrP
  rw [telescope k _ hk]
  by_cases h : G + 1 ≤ countEq ℓ a
  · rw [if_pos h, Nat.mul_one]
    exact Nat.le_trans (covered_count_le_all T ℓ a xs k) (Nat.le_add_left _ _)
  · rw [if_neg h, Nat.mul_zero, Nat.add_zero, Nat.min_eq_left (by omega)]
    exact covered_count T ℓ a xs k

/-- The static ITSR numerator bounds the pointwise bound summed over uniform
    leaves. -/
theorem itsrP_sum (L T k q G a : Nat) :
    tsum L q (itsrP T k G a) * (fact (G+1) * L^(G+1)) ≤ L^q * itsrNum L T k q G := by
  let N : Nat → Nat := fun g => tsum L q (fun ℓ => if g ≤ countEq ℓ a then 1 else 0)
  let Δ : Nat → Nat := fun g => (g+1)^k - g^k
  have total : tsum L q (itsrP T k G a) =
      ((List.range G).map (fun g => Δ g * N (g+1))).sum + T^k * N (G+1) := by
    unfold itsrP
    rw [tsum_add, tsum_list, tsum_mul]
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
  rw [total]
  calc (((List.range G).map (fun g => Δ g * N (g+1))).sum + T^k * N (G+1)) * (fact (G+1) * L^(G+1))
      = ((List.range G).map (fun g => Δ g * (N (g+1) * (fact (G+1) * L^(G+1))))).sum +
          T^k * (N (G+1) * (fact (G+1) * L^(G+1))) := by
        rw [Nat.add_mul, Nat.mul_comm, ← sum_map_mul, Nat.mul_assoc]
        congr 1; congr 1; apply List.map_congr_left; intro g _; ac_rfl
    _ ≤ ((List.range G).map (fun g => Δ g * (q^(g+1) * L^q * (L^(G-g) * (fact (G+1) / fact (g+1)))))).sum +
          T^k * (q^(G+1) * L^q) := by
        apply Nat.add_le_add
        · apply sum_map_le; intro g hg
          exact Nat.mul_le_mul_left _ (term g (List.mem_range.mp hg))
        · exact Nat.mul_le_mul_left _ last
    _ = L^q * itsrNum L T k q G := by
        unfold itsrNum
        rw [Nat.mul_add, ← sum_map_mul]
        congr 1
        · congr 1; apply List.map_congr_left; intro g _; simp only [Δ]; ac_rfl
        · ac_rfl

/-- Transport of a uniform map: if `lf` has equal fibers over `[0, L)`, a
    function of the images of `q` uniform values sums as over `q` uniform
    leaves. -/
theorem tsum_map (R L : Nat) (lf : Nat → Nat)
    (hfib : ∀ F : Nat → Nat, ((List.range R).map (fun v => F (lf v))).sum * L = R * ((List.range L).map F).sum) :
    ∀ (q : Nat) (P : List Nat → Nat), tsum R q (fun ws => P (ws.map lf)) * L^q = R^q * tsum L q P
  | 0, P => by simp [tsum]
  | q+1, P => by
    simp only [tsum, List.map_cons]
    have ih : ∀ v, tsum R q (fun ws => P (lf v :: ws.map lf)) * L^q = R^q * tsum L q (fun ℓ => P (lf v :: ℓ)) :=
      fun v => tsum_map R L lf hfib q (fun ℓ => P (lf v :: ℓ))
    rw [Nat.pow_succ, ← Nat.mul_assoc, sum_mul_right]
    rw [List.map_congr_left (fun v _ => ih v), sum_map_mul, Nat.mul_assoc]
    have hf := hfib (fun a => tsum L q (fun ℓ => P (a :: ℓ)))
    simp only at hf
    rw [hf, ← Nat.mul_assoc, ← Nat.pow_succ, ← sum_map_mul]

/-- Generalized static ITSR: signature values uniform in `[0, R)`, their
    leaves through `lf` (equal fibers over `[0, L)`), their indices
    arbitrary functions `ix` of the values. -/
theorem itsr_gen (R L T k q G a : Nat) (lf : Nat → Nat) (ix : Nat → List Nat) (hk : 0 < k)
    (hfib : ∀ F : Nat → Nat, ((List.range R).map (fun v => F (lf v))).sum * L = R * ((List.range L).map F).sum) :
    tsum R q (fun ws => tsum T k (fun x0 => if covered (ws.map lf) a (fun s => ix (ws.getD s 0)) k x0 then 1 else 0)) *
      (fact (G+1) * L^(G+1)) * L^q ≤ R^q * (L^q * itsrNum L T k q G) := by
  have h1 : tsum R q (fun ws => tsum T k (fun x0 =>
      if covered (ws.map lf) a (fun s => ix (ws.getD s 0)) k x0 then 1 else 0)) ≤
      tsum R q (fun ws => itsrP T k G a (ws.map lf)) :=
    tsum_mono R q (fun ws => itsr_point T k G a hk _ _)
  calc _ ≤ tsum R q (fun ws => itsrP T k G a (ws.map lf)) * (fact (G+1) * L^(G+1)) * L^q :=
        Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ h1)
    _ = (tsum R q (fun ws => itsrP T k G a (ws.map lf)) * L^q) * (fact (G+1) * L^(G+1)) := by ac_rfl
    _ = R^q * (tsum L q (itsrP T k G a) * (fact (G+1) * L^(G+1))) := by
        rw [tsum_map R L lf hfib q (itsrP T k G a), Nat.mul_assoc]
    _ ≤ R^q * (L^q * itsrNum L T k q G) := Nat.mul_le_mul_left _ (itsrP_sum L T k q G a)

/-! Adaptive selection. -/

/-- The covered event on output slots (values stored +1, 0 = empty): slot 0
    holds the target, slots 1..q signatures. -/
def covA (lf : Nat → Nat) (ix : Nat → List Nat) (k q : Nat) (out : List Nat) : Bool :=
  out.getD 0 0 != 0 && (List.range k).all (fun i => (List.range q).any (fun s =>
    out.getD (s+1) 0 != 0 && (lf (out.getD (s+1) 0 - 1) == lf (out.getD 0 0 - 1) &&
    (ix (out.getD (s+1) 0 - 1)).getD i 0 == (ix (out.getD 0 0 - 1)).getD i 0)))

theorem covA_mono (lf : Nat → Nat) (ix : Nat → List Nat) (k q : Nat) (out : List Nat) (s y : Nat)
    (h0 : out.getD s 0 = 0) :
    (if covA lf ix k q out then 1 else 0) ≤ (if covA lf ix k q (out.set s (y+1)) then 1 else 0) := by
  cases hc : covA lf ix k q out
  · simp
  · have g : ∀ j, out.getD j 0 ≠ 0 → (out.set s (y+1)).getD j 0 = out.getD j 0 := by
      intro j hj
      exact getD_set_ne out s j (y+1) (fun e => hj (e ▸ h0))
    have : covA lf ix k q (out.set s (y+1)) = true := by
      simp only [covA, Bool.and_eq_true, bne_iff_ne, ne_eq, List.all_eq_true, List.any_eq_true,
        beq_iff_eq] at hc ⊢
      obtain ⟨hne, hall⟩ := hc
      rw [g 0 hne]
      refine ⟨hne, fun i hi => ?_⟩
      obtain ⟨s', hs', hw⟩ := hall i hi
      exact ⟨s', hs', by rw [g (s'+1) hw.1]; exact hw⟩
    simp [this]

/-- Write values (+1) into consecutive slots from `j`. -/
def wr : List Nat → Nat → List Nat → List Nat
  | out, _, [] => out
  | out, j, y :: vs => wr (out.set j (y+1)) (j+1) vs

theorem tsumOver_range' (R : Nat) (H : List Nat → Nat) : ∀ (n : Nat) (out : List Nat) (j : Nat),
    tsumOver R H (List.range' j n) out = tsum R n (fun vs => H (wr out j vs))
  | 0, out, j => by simp [tsumOver, tsum, wr]
  | n+1, out, j => by
    simp only [List.range'_succ, tsumOver, tsum, wr]
    congr 1; apply List.map_congr_left; intro y _
    exact tsumOver_range' R H n _ _

theorem set_append_len (pre l : List Nat) (z : Nat) : (pre ++ l).set pre.length z = pre ++ l.set 0 z := by
  induction pre with
  | nil => rfl
  | cons a pre ih => simp only [List.cons_append, List.length_cons, List.set_cons_succ, ih]

theorem wr_full : ∀ (vs pre : List Nat) (n : Nat),
    wr (pre ++ List.replicate (vs.length + n) 0) pre.length vs = pre ++ vs.map (·+1) ++ List.replicate n 0
  | [], pre, n => by simp [wr]
  | y :: vs, pre, n => by
    simp only [wr, List.length_cons]
    rw [show vs.length + 1 + n = (vs.length + n) + 1 by omega, List.replicate_succ, set_append_len]
    have := wr_full vs (pre ++ [y+1]) n
    simp only [List.length_append, List.length_singleton, List.append_assoc, List.singleton_append] at this
    simp only [List.set_cons_zero]
    rw [this]; simp

theorem tsum_congr_len (R : Nat) : ∀ (n : Nat) (F G : List Nat → Nat),
    (∀ t : List Nat, t.length = n → F t = G t) → tsum R n F = tsum R n G
  | 0, F, G, h => h [] rfl
  | n+1, F, G, h => by
    simp only [tsum]
    congr 1; apply List.map_congr_left; intro y _
    exact tsum_congr_len R n _ _ (fun t ht => h (y :: t) (by simp [ht]))

theorem tsum_mono_len (R : Nat) : ∀ (n : Nat) {F G : List Nat → Nat},
    (∀ t : List Nat, t.length = n → F t ≤ G t) → tsum R n F ≤ tsum R n G
  | 0, _, _, h => h [] rfl
  | n+1, _, _, h => sum_map_le _ (fun y _ => tsum_mono_len R n (fun t ht => h (y :: t) (by simp [ht])))

theorem covA_full (lf : Nat → Nat) (ix : Nat → List Nat) (k : Nat) (v0 : Nat) (ws : List Nat) :
    covA lf ix k ws.length ((v0 :: ws).map (·+1)) = true →
    covered (ws.map lf) (lf v0) (fun s => ix (ws.getD s 0)) k (ix v0) = true := by
  intro h
  simp only [covA, Bool.and_eq_true, List.all_eq_true, List.any_eq_true, beq_iff_eq] at h
  simp only [covered, List.all_eq_true, List.any_eq_true, Bool.and_eq_true, beq_iff_eq, List.length_map]
  intro i hi
  obtain ⟨s, hs, hw⟩ := h.2 i hi
  have hsl : s < ws.length := List.mem_range.mp hs
  refine ⟨s, hs, ?_⟩
  have e1 : ((v0 :: ws).map (·+1)).getD (s+1) 0 = ws.getD s 0 + 1 := by
    simp [List.getD_eq_getElem?_getD, hsl]
  have e0 : ((v0 :: ws).map (·+1)).getD 0 0 = v0 + 1 := by simp
  rw [e1, e0] at hw
  simp only [Nat.add_sub_cancel] at hw
  refine ⟨?_, hw.2.2⟩
  have e2 : (ws.map lf).getD s 0 = lf (ws.getD s 0) := by simp [List.getD_eq_getElem?_getD, hsl]
  rw [e2]; exact hw.2.1

/-- Adaptive ITSR. A run reads uniform tape entries and, before each read,
    decides from the entries already read whether that entry is the target
    digest (slot 0), a signature digest (slots 1..q), or neither. If each
    digest decodes to a leaf `lf v` and indices `ix v` with equal fibers,
    the probability that the target is covered by the signature digests at
    its leaf is at most the static ITSR bound `itsrNum / ((G+1)! L^(G+1) T^k)`. -/
theorem itsr_adaptive (R N L T k q G : Nat) (lf : Nat → Nat) (ix : Nat → List Nat)
    (hk : 0 < k) (hR : 0 < R) (hL : 0 < L) (hT : 0 < T)
    (hfib : ∀ F : Nat → List Nat → Nat,
      ((List.range R).map (fun v => F (lf v) (ix v))).sum * (L * T^k) =
        R * ((List.range L).map (fun a => tsum T k (F a))).sum)
    (slot : List Nat → Option Nat)
    (hA : ∀ t : List Nat, t.length = N → (assigned slot t).Nodup ∧ ∀ s ∈ assigned slot t, s < q+1) :
    tsum R N (fun t => if covA lf ix k q (fill slot (List.replicate (q+1) 0) t) then 1 else 0) *
      (T^k * (fact (G+1) * L^(G+1))) ≤ R^N * itsrNum L T k q G := by
  let H : List Nat → Nat := fun out => if covA lf ix k q out then 1 else 0
  have hmono : ∀ out s y, out.getD s 0 = 0 → H out ≤ H (out.set s (y+1)) :=
    fun out s y h => covA_mono lf ix k q out s y h
  -- leaf fibers
  have hfib1 : ∀ F : Nat → Nat, ((List.range R).map (fun v => F (lf v))).sum * L =
      R * ((List.range L).map F).sum := by
    intro F
    have h := hfib (fun a _ => F a)
    simp only [tsum_const] at h
    have hTk : 0 < T^k := Nat.pow_pos hT
    apply Nat.eq_of_mul_eq_mul_right hTk
    calc _ = ((List.range R).map (fun v => F (lf v))).sum * (L * T^k) := by ac_rfl
      _ = R * ((List.range L).map (fun a => T^k * F a)).sum := h
      _ = _ := by rw [sum_map_mul]; ac_rfl
  have hS : (List.range (q+1)).Nodup := List.nodup_range
  have hemp : ∀ s ∈ List.range (q+1), (List.replicate (q+1) 0).getD s 0 = 0 := by
    intro s _
    rw [List.getD_eq_getElem?_getD]
    cases h : (List.replicate (q+1) 0)[s]? with
    | none => rfl
    | some x => exact List.eq_of_mem_replicate (mem_of_getElem? h)
  have step1 := sample R H hmono N slot (List.range (q+1)) (List.replicate (q+1) 0) hS hemp
    (fun t ht => ⟨(hA t ht).1, fun s hs => List.mem_range.mpr ((hA t ht).2 s hs)⟩)
  rw [List.length_range, List.range_eq_range', tsumOver_range'] at step1
  -- the full assignment
  let cov : Nat → List Nat → Nat := fun v0 ws =>
    if covered (ws.map lf) (lf v0) (fun s => ix (ws.getD s 0)) k (ix v0) then 1 else 0
  have hY : tsum R (q+1) (fun vs => H (wr (List.replicate (q+1) 0) 0 vs)) ≤
      tsum R q (fun ws => ((List.range R).map (fun v0 => cov v0 ws)).sum) := by
    rw [tsum_congr_len R (q+1) _ (fun vs => H (vs.map (·+1))) (fun vs hv => by
      have := wr_full vs [] 0
      simp only [List.nil_append, List.length_nil, Nat.add_zero, List.replicate_zero, List.append_nil, hv] at this
      show H _ = H _
      rw [this])]
    rw [tsum_list]
    simp only [tsum]
    apply sum_map_le
    intro v0 _
    apply tsum_mono_len R q
    intro ws hws
    show H ((v0 :: ws).map (·+1)) ≤ cov v0 ws
    simp only [H, cov]
    cases hc : covA lf ix k q ((v0 :: ws).map (·+1))
    · simp
    · rw [← hws] at hc
      rw [if_pos (covA_full lf ix k v0 ws hc)]
      simp
  let C' : Nat → List Nat → Nat := fun a ws =>
    tsum T k (fun x0 => if covered (ws.map lf) a (fun s => ix (ws.getD s 0)) k x0 then 1 else 0)
  have hZ : tsum R q (fun ws => ((List.range R).map (fun v0 => cov v0 ws)).sum) * (L * T^k) =
      R * ((List.range L).map (fun a => tsum R q (C' a))).sum := by
    rw [Nat.mul_comm, ← tsum_mul]
    have e : ∀ ws, L * T^k * ((List.range R).map (fun v0 => cov v0 ws)).sum =
        R * ((List.range L).map (fun a => C' a ws)).sum := by
      intro ws
      have := hfib (fun a x0 => if covered (ws.map lf) a (fun s => ix (ws.getD s 0)) k x0 then 1 else 0)
      rw [Nat.mul_comm]; exact this
    simp only [e]
    rw [tsum_mul, tsum_list]
  have hW : ((List.range L).map (fun a => tsum R q (C' a))).sum * (fact (G+1) * L^(G+1)) * L^q ≤
      L * (R^q * (L^q * itsrNum L T k q G)) := by
    rw [Nat.mul_assoc, sum_mul_right]
    calc _ ≤ ((List.range L).map (fun _ => R^q * (L^q * itsrNum L T k q G))).sum := by
          apply sum_map_le; intro a _
          rw [← Nat.mul_assoc]
          exact itsr_gen R L T k q G a lf ix hk hfib1
      _ = _ := by rw [sum_map_const, List.length_range]
  have hpos : 0 < R^(q+1) * (L * T^k) * L^q := by
    have := Nat.pow_pos (n := q+1) hR
    have := Nat.pow_pos (n := k) hT
    have := Nat.pow_pos (n := q) hL
    exact Nat.mul_pos (Nat.mul_pos (by assumption) (Nat.mul_pos hL (by assumption))) (by assumption)
  apply Nat.le_of_mul_le_mul_right _ hpos
  calc tsum R N (fun t => H (fill slot (List.replicate (q+1) 0) t)) * (T^k * (fact (G+1) * L^(G+1))) *
        (R^(q+1) * (L * T^k) * L^q)
      = (tsum R N (fun t => H (fill slot (List.replicate (q+1) 0) t)) * R^(q+1)) *
          ((L * T^k) * (T^k * (fact (G+1) * L^(G+1))) * L^q) := by ac_rfl
    _ ≤ (R^N * tsum R (q+1) (fun vs => H (wr (List.replicate (q+1) 0) 0 vs))) *
          ((L * T^k) * (T^k * (fact (G+1) * L^(G+1))) * L^q) := Nat.mul_le_mul_right _ step1
    _ ≤ (R^N * tsum R q (fun ws => ((List.range R).map (fun v0 => cov v0 ws)).sum)) *
          ((L * T^k) * (T^k * (fact (G+1) * L^(G+1))) * L^q) :=
        Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ hY)
    _ = R^N * T^k * R * (((List.range L).map (fun a => tsum R q (C' a))).sum * (fact (G+1) * L^(G+1)) * L^q) := by
        rw [show R^N * tsum R q (fun ws => ((List.range R).map (fun v0 => cov v0 ws)).sum) *
            ((L * T^k) * (T^k * (fact (G+1) * L^(G+1))) * L^q) =
            R^N * T^k * (tsum R q (fun ws => ((List.range R).map (fun v0 => cov v0 ws)).sum) * (L * T^k)) *
              ((fact (G+1) * L^(G+1)) * L^q) by ac_rfl, hZ]
        ac_rfl
    _ ≤ R^N * T^k * R * (L * (R^q * (L^q * itsrNum L T k q G))) := Nat.mul_le_mul_left _ hW
    _ = R^N * itsrNum L T k q G * (R^(q+1) * (L * T^k) * L^q) := by
        rw [Nat.pow_succ]; ac_rfl

#print axioms itsr_adaptive
#print axioms itsr_gen
end DSM.Rom
