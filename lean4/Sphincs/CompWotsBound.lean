-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompWotsPre
import Sphincs.CompWotsTcr

/- Modular proof, milestone 3, obligation 8 (part 6): the WOTS-TW bound.

   For every adversary of the multi-instance WOTS-TW game G, with the three
   explicit reductions (UD-C with a uniformly guessed hybrid index, TCR-C,
   PRE-C), over exact fractions:

     Pr[G] ≤ (w − 2) · Adv^{SM-DT-UD-C}(B_ud) + Pr^{SM-DT-TCR-C}(B_tcr)
             + Pr^{SM-DT-PRE-C}(B_pre)

   (EasyCrypt `M_EUF_GCMA_WOTSTWESNPRF` bound). The three primitive terms
   are not bounded here. No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- Exact fraction arithmetic of the Game 3 split. -/
theorem frac_g3 (Hn T3 P3 tN pN Dg Dt : Nat) (h1 : Hn ≤ T3 + P3) (h2 : T3 ≤ tN) (h3 : Dt * P3 ≤ pN) :
    fle (Hn, Dg) (fadd (tN, Dg) (pN, Dt * Dg)) := by
  unfold fle fadd
  simp only
  calc Hn * (Dg * (Dt * Dg)) ≤ (T3 + P3) * (Dg * (Dt * Dg)) := Nat.mul_le_mul_right _ h1
    _ = T3 * (Dt * Dg) * Dg + (Dt * P3) * Dg * Dg := by rw [Nat.add_mul]; congr 1 <;> ac_rfl
    _ ≤ tN * (Dt * Dg) * Dg + pN * Dg * Dg :=
        Nat.add_le_add (Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ h2))
          (Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ h3))
    _ = (tN * (Dt * Dg) + pN * Dg) * Dg := by rw [Nat.add_mul]

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-- **Game 3 is bounded by TCR-C and PRE-C:**
    Pr[Hyb_{w−2}] ≤ Pr^{TCR-C}(B_tcr) + Pr^{PRE-C}(B_pre). -/
theorem g3_bound [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c tT tP : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a)
    (hT : c * (W.len * (W.w - 1)) ≤ tT) (hP : c * W.len ≤ tP) :
    fle (W.hybProb x0 c P Din As (W.w - 2)).frac
      (fadd (tcrProb P W.f W.fc tT (W.tcrCoins c x0 Din As)).frac
        (preProb P Din x0 W.f W.fc tP (W.preCoins c x0 Din As)).frac) := by
  have h1 := W.hyb_split x0 c P Din As hdig
  have h2 := W.tcr_num x0 c tT P Din As hc hlen hdig htwo hinj hinst hT
  have h3 := W.pre_num x0 c tP P Din As hc hlen hdig htwo hinj hinst hP
  have d2 := W.tcr_den x0 c tT P Din As
  have d3 := W.pre_den x0 c tP P Din As
  unfold Probability.frac
  rw [d2, d3]
  exact frac_g3 _ _ _ _ _ _ _ h1 h2 h3

/-- **The WOTS-TW bound** (EasyCrypt `M_EUF_GCMA_WOTSTWESNPRF`), as exact
    fractions: Pr[G] ≤ (w − 2) · Adv^{UD-C}(B_ud) + Pr^{TCR-C}(B_tcr) +
    Pr^{PRE-C}(B_pre), for target bounds `t_ud ≥ c · len`,
    `t_tcr ≥ c · len · (w − 1)`, `t_pre ≥ c · len`. -/
theorem wots_bound [DecidableEq Tw] [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (x0 : X) (c tU tT tP : Nat) (P : FiniteExperiment PP) (Din : FiniteExperiment X)
    (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) (hn : 0 < W.w - 2)
    (hc : ∀ pp tw x, W.fc pp tw (W.embed x) = W.f pp tw x)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (hinj : ∀ a a' j j' h h', j < W.len → j' < W.len → h < W.w → h' < W.w →
      W.twk a j h = W.twk a' j' h' → a = a' ∧ j = j' ∧ h = h')
    (hinst : ∀ a j h, W.inst (W.twk a j h) = a)
    (hU : c * W.len ≤ tU) (hT : c * (W.len * (W.w - 1)) ≤ tT) (hP : c * W.len ≤ tP) :
    fle (W.gameProb x0 c P Din As).frac
      (fadd (fadd (tcrProb P W.f W.fc tT (W.tcrCoins c x0 Din As)).frac
          (preProb P Din x0 W.f W.fc tP (W.preCoins c x0 Din As)).frac)
        ((W.w - 2) * (udAdv P Din x0 Din x0 W.f W.fc tU (W.udCoins c x0 Din As (W.w - 2) hn)).1,
         (udAdv P Din x0 Din x0 W.f W.fc tU (W.udCoins c x0 Din As (W.w - 2) hn)).2)) := by
  have hud := W.ud_step_frac c tU x0 P Din As hn hc hlen hdig hinj hinst hU
  have hg3 := W.g3_bound x0 c tT tP P Din As hc hlen hdig htwo hinj hinst hT hP
  refine fle_trans ?_ hud (fadd_mono _ hg3)
  exact Nat.mul_pos (W.hybProb x0 c P Din As (W.w - 2)).positive
    (Nat.mul_pos (udRealProb P Din x0 W.f W.fc tU (W.udCoins c x0 Din As (W.w - 2) hn)).positive
      (udIdealProb P Din x0 W.fc tU (W.udCoins c x0 Din As (W.w - 2) hn)).positive)

end WotsSetting

#print axioms frac_g3
#print axioms WotsSetting.g3_bound
#print axioms WotsSetting.wots_bound
end DSM.Sphincs.Comp
