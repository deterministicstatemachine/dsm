-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.KeyScheduleHop

/- C69 with its assumptions named.

   `ks1_forge_256f` carries five advantages as defined quantities. Here each is a
   hypothesis with an explicit bound `εᵢ/2^256`, and the conclusion is the forgery
   probability as one number:

     (A1) Extract of the wallet seed:    ΔExt_w   ≤ ε₁/2^256
     (A2) Expand under PRK_w:            ΔPRF_w   ≤ ε₂/2^256
     (A3) Extract of s0:                 ΔExt_s0  ≤ ε₃/2^256
     (A4) Expand under PRK_s0:           ΔPRF_s0  ≤ ε₄/2^256
     (A5) keyed BLAKE3 under Smaster (C67's PRF, for every disclosed value)
                                         Adv_C67  ≤ ε₅/2^256

     Pr[forgery] ≤ (ε₁ + ε₂ + ε₃ + ε₄ + ε₅ + qn·(27·Q + 368023))/2^256.

   Each advantage is written in counts at its own scale (`Pr = count/(sample
   space)`), exactly as `ks1_forge_256f` defines it. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- The arithmetic: the hybrid chain with each advantage bounded. -/
theorem named_arith (h0 h1 h2 h2' h3 h4 S m mL d b e1 e2 e3 e4 e5 : Nat) (hm : 0 < m) (hmL : 0 < mL)
    (hc : h0 * m^8 * mL * 2^256 ≤ ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2' - h3) * m + (h3 * m - h4)) * mL * 2^256
      + S * 2^256 + m^9 * mL * (d * b))
    (a1 : (h0 - h1) * 2^256 ≤ e1 * (m * d)) (a2 : (h1 * m^7 - h2) * 2^256 ≤ e2 * (m^8 * d))
    (a3 : (h2' - h3) * 2^256 ≤ e3 * (m^8 * d)) (a4 : (h3 * m - h4) * 2^256 ≤ e4 * (m^9 * d))
    (a5 : S * 2^256 ≤ e5 * (m^9 * mL * d)) :
    h0 * 2^256 ≤ (e1 + e2 + e3 + e4 + e5 + b) * (m * d) := by
  generalize hT : (2:Nat)^256 = T at *
  have p8 : m^8 = m^7 * m := Nat.pow_succ ..
  have p9 : m^9 = m^8 * m := Nat.pow_succ ..
  have b1 : (h0 - h1) * m^8 * T ≤ e1 * (m * d) * m^8 := by
    rw [Nat.mul_right_comm]; exact Nat.mul_le_mul_right _ a1
  have b2 : (h1 * m^7 - h2) * m * T ≤ e2 * (m^8 * d) * m := by
    rw [Nat.mul_right_comm]; exact Nat.mul_le_mul_right _ a2
  have b3 : (h2' - h3) * m * T ≤ e3 * (m^8 * d) * m := by
    rw [Nat.mul_right_comm]; exact Nat.mul_le_mul_right _ a3
  have key : h0 * T * (m^8 * mL) ≤ (e1 + e2 + e3 + e4 + e5 + b) * (m * d) * (m^8 * mL) := by
    have lhs : h0 * T * (m^8 * mL) = h0 * m^8 * mL * T := by ac_rfl
    have mid : ((h0 - h1) * m^8 + (h1 * m^7 - h2) * m + (h2' - h3) * m + (h3 * m - h4)) * mL * T =
        ((h0 - h1) * m^8 * T + (h1 * m^7 - h2) * m * T + (h2' - h3) * m * T + (h3 * m - h4) * T) * mL := by
      simp only [Nat.add_mul]; ac_rfl
    have sum4 : (h0 - h1) * m^8 * T + (h1 * m^7 - h2) * m * T + (h2' - h3) * m * T + (h3 * m - h4) * T ≤
        (e1 + e2 + e3 + e4) * (m^9 * d) := by
      have := Nat.add_le_add (Nat.add_le_add (Nat.add_le_add b1 b2) b3) a4
      calc _ ≤ _ := this
        _ = (e1 + e2 + e3 + e4) * (m^9 * d) := by rw [p9, p8]; simp only [Nat.add_mul]; ac_rfl
    calc h0 * T * (m^8 * mL) = h0 * m^8 * mL * T := lhs
      _ ≤ _ := hc
      _ = ((h0 - h1) * m^8 * T + (h1 * m^7 - h2) * m * T + (h2' - h3) * m * T + (h3 * m - h4) * T) * mL
            + S * T + m^9 * mL * (d * b) := by rw [mid]
      _ ≤ (e1 + e2 + e3 + e4) * (m^9 * d) * mL + e5 * (m^9 * mL * d) + m^9 * mL * (d * b) :=
          Nat.add_le_add_right (Nat.add_le_add (Nat.mul_le_mul_right _ sum4) a5) _
      _ = (e1 + e2 + e3 + e4 + e5 + b) * (m * d) * (m^8 * mL) := by
          rw [p9]; simp only [Nat.add_mul]; ac_rfl
  exact Nat.le_of_mul_le_mul_right key (Nat.mul_pos (Nat.pow_pos hm) hmL)

/-- **C69 with named assumptions, SPX256f.** With the five advantages of
    `ks1_forge_256f` bounded by `εᵢ/2^256` (A1–A5 above), the forgery probability
    `H0/(M·R^N)` of the DSM game with Smaster derived by KS1 from the wallet seed is at most
    `(ε₁ + ε₂ + ε₃ + ε₄ + ε₅ + qn·(27·Q + 368023))/2^256`. -/
theorem ks1_forge_256f_named (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)
    (bip : Nat → Bytes) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (cc : Nat) (hc : 0 < cc)
    (e1 e2 e3 e4 e5 : Nat) :
    let R := cc * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
    let N := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1
    let M := 256^32
    let L := qn + ql
    let W := fun T : QT MOut => tsum R N (fun t => ind ((run t T []).1.win = true))
    let H0 := ((List.range M).map (fun e => W (fromWallet limits A pubOf c (bip e)))).sum
    let H1 := ((List.range M).map (fun p => W (resF (expand32 (be 32 p)) (distW limits A pubOf c)))).sum
    let H2 := tsum M 8 (fun ss => W (resL [] ss (distW limits A pubOf c)))
    let H2' := tsum M 7 (fun a => ((List.range M).map (fun u =>
        W (fromS0 limits A pubOf c (hkdfExtract saltS0 (be 32 u)) (a.map (be 32))))).sum)
    let H3 := tsum M 7 (fun a => ((List.range M).map (fun q =>
        W (resF (expand32 (be 32 q)) (distS limits A pubOf c (a.map (be 32)))))).sum)
    let H4 := tsum M 7 (fun a => tsum M 2 (fun ss => W (resL [] ss (distS limits A pubOf c (a.map (be 32))))))
    let realW := fun (a : List Nat) (r : Nat) => ((List.range M).map (fun K =>
        W (resF (dsmF K) (dplay .spx256f limits [] [] [] (A (pubOf (a.map (be 32) ++ [be 32 r]))))))).sum
    let idealW := fun (a : List Nat) (r : Nat) => ((List.range M).map (fun _ => tsum M L (fun ss =>
        W (resL [] ss (dplay .spx256f limits [] [] [] (A (pubOf (a.map (be 32) ++ [be 32 r])))))))).sum
    -- (A1)–(A5)
    (H0 - H1) * 2^256 ≤ e1 * (M * R^N) →
    (H1 * M^7 - H2) * 2^256 ≤ e2 * (M^8 * R^N) →
    (H2' - H3) * 2^256 ≤ e3 * (M^8 * R^N) →
    (H3 * M - H4) * 2^256 ≤ e4 * (M^9 * R^N) →
    (∀ a r, (realW a r * M^L - idealW a r) * 2^256 ≤ e5 * (M * M^L * R^N)) →
    H0 * 2^256 ≤ (e1 + e2 + e3 + e4 + e5 + qn * (27 * mQ (params .spx256f) qh qn qs + 368023)) * (M * R^N) := by
  intro R N M L W H0 H1 H2 H2' H3 H4 realW idealW a1 a2 a3 a4 a5
  have hc := (ks1_forge_256f limits A pubOf c bip qh qn ql qs hA hqs cc hc).2.2
  have hM : 0 < M := Nat.pow_pos (by decide)
  generalize hD : R^N = D at *
  generalize hb : qn * (27 * mQ (params .spx256f) qh qn qs + 368023) = b at *
  have a5s : tsum M 7 (fun a => ((List.range M).map (fun r => realW a r * M^L - idealW a r)).sum) * 2^256 ≤
      e5 * (M^9 * M^L * D) := by
    rw [Nat.mul_comm, ← tsum_mul]
    calc _ ≤ tsum M 7 (fun _ => M * (e5 * (M * M^L * D))) := tsum_mono _ _ (fun a => by
          rw [← sum_map_mul]
          calc _ ≤ ((List.range M).map (fun _ => e5 * (M * M^L * D))).sum :=
                sum_map_le _ (fun r _ => by rw [Nat.mul_comm]; exact a5 a r)
            _ = _ := by rw [sum_map_const, List.length_range])
      _ = e5 * (M^9 * M^L * D) := by
        rw [tsum_const]
        have : M^9 = M^7 * M * M := by simp only [Nat.pow_succ]
        rw [this]; ac_rfl
  exact named_arith H0 H1 H2 H2' H3 H4 _ M (M^L) D b e1 e2 e3 e4 e5 hM (Nat.pow_pos hM) hc a1 a2 a3 a4 a5s

end DSM.Rom
