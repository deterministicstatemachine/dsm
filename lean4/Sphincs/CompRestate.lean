-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompGames
import Sphincs.CompPrfDomain

/- Modular proof, milestone 2 (part 5): C11, C15 and C16 restated as
   advantages in the PRG and PRF games of `CompGames` (map §9, obligation 5).

   Each hop's real and ideal probabilities are shown EQUAL (same success count,
   same number of tickets) to the real and ideal probabilities of a PRG or PRF
   game, played by the hop's own distinguisher with the rest of its
   randomness moved into its coins:

   | hop | game | primitive | distinguisher's coins |
   | --- | --- | --- | --- |
   | C11 seed | PRG | ChaCha20Rng, 32 B → 3n B | the forger's |
   | C15 2a | PRG | derive_key("…/prf", ·), n B → 32 B | SK.prf ‖ PK.seed, the forger's |
   | C15 2b | PRF, domain PK.seed ‖ ADRS | keyed BLAKE3 | SK.prf ‖ PK.seed, the forger's |
   | C16 3a | PRG | derive_key("…/prf-msg", ·) | PK.seed, the SKG function, the forger's |
   | C16 3b | PRF, domain PK.seed ‖ M | keyed BLAKE3 | PK.seed, the SKG function, the forger's |

   The PRF games restrict the real oracle to the PRF domain, so that a query
   of another shape cannot tell the worlds apart; `CompPrfDomain` proves the
   hop distinguishers never ask one. `euf_cma_named` is C31 with these named
   primitive advantages. It does not say any of them is small: those are the
   PRG and PRF assumptions on ChaCha20 and BLAKE3, kept explicit, as the
   review requires. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

section
variable (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy)

/-! ## The distinguishers, with their auxiliary randomness as coins -/

def seedD : FiniteExperiment (Bytes → Bool) :=
  coins.map (fun s y => seedDistinguisher v limits s o y)

def keyD : FiniteExperiment (Bytes → Bool) :=
  (independentProduct (uniformBytes (2*(params v).n)) coins).map
    (fun p K => keyDistinguisher v limits p.2 o p.1.val K)

def funcD : FiniteExperiment ((Bytes × Nat → Bytes) → Bool) :=
  (independentProduct (uniformBytes (2*(params v).n)) coins).map
    (fun p f => functionDistinguisher v limits p.2 o p.1.val (fun x len => f (x, len)))

def msgKeyD : FiniteExperiment (Bytes → Bool) :=
  (independentProduct (independentProduct (uniformBytes (params v).n)
      (randomFunction ((params v).n+32) (params v).n)) coins).map
    (fun p L => msgKeyDistinguisher v limits p.2 o p.1.2 p.1.1.val L)

def msgFuncD : FiniteExperiment ((Bytes × Nat → Bytes) → Bool) :=
  (independentProduct (independentProduct (uniformBytes (params v).n)
      (randomFunction ((params v).n+32) (params v).n)) coins).map
    (fun p f => msgFunctionDistinguisher v limits p.2 o p.1.2 p.1.1.val (fun x len => f (x, len)))
end

/-! ## Sums over the key material -/

theorem expansion_sum (v : Variant) (g : Bytes → Nat) :
    (uniformExpansion v).sum (fun e => g e.val) =
      (uniformBytes (params v).n).sum (fun x =>
        (uniformBytes (2*(params v).n)).sum (fun y => g (x.val ++ y.val))) := by
  show (uniformBytes (3*(params v).n)).sum (fun e => g e.val) = _
  rw [show 3*(params v).n = (params v).n + 2*(params v).n by omega, split_sum]

theorem double_sum (n : Nat) (g : Bytes → Nat) :
    (uniformBytes (2*n)).sum (fun e => g e.val) =
      (uniformBytes n).sum (fun x => (uniformBytes n).sum (fun y => g (x.val ++ y.val))) := by
  rw [show 2*n = n + n by omega, split_sum]

theorem bool_one (b c : Bool) (h : b = c) : (if b then 1 else 0) = (if c then 1 else 0) := by rw [h]

theorem ub_sum (w : Nat) (g : Bytes → Nat) : (ub w).sum g = (uniformBytes w).sum (fun x => g x.val) := rfl

theorem uncurried_sum (S : FiniteExperiment (Bytes → Nat → Bytes)) (g : (Bytes × Nat → Bytes) → Nat) :
    (uncurried S).sum g = S.sum (fun F => g (fun q => F q.1 q.2)) := rfl

theorem card_product {α β : Type} (a : FiniteExperiment α) (b : FiniteExperiment β) :
    (independentProduct a b).cardinality = a.cardinality * b.cardinality := rfl

theorem card_map {α β : Type} (S : FiniteExperiment α) (f : α → β) :
    (S.map f).cardinality = S.cardinality := rfl

/-! ## C11: the seed hop is a PRG advantage -/

theorem c11_real (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    realSeedChallengeProbability v limits o coins =
      realP uniformMasterSeed (seedExpansion o v) (seedD v limits o coins) := by
  unfold realSeedChallengeProbability realP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum]; rfl
  · rfl

theorem c11_ideal (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealSeedChallengeProbability v limits o coins =
      idealP ((uniformExpansion v).map Subtype.val) (seedD v limits o coins) := by
  unfold idealSeedChallengeProbability idealP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum]; rfl
  · rfl

theorem c11_adv (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    advantage (realSeedChallengeProbability v limits o coins) (idealSeedChallengeProbability v limits o coins) =
      dsmPrgAdv o v (seedD v limits o coins) := by
  rw [c11_real, c11_ideal]; rfl

/-! ## C15 hop 2a: the SKG key derivation is a PRG advantage -/

theorem c15a_real (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    realPrfKeyProbability v limits o coins =
      realP (ub (params v).n) (deriveKey o "DSM/sphincs/v2/prf") (keyD v limits o coins) := by
  unfold realPrfKeyProbability realP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, ub_sum]
    rw [expansion_sum v (fun e => coins.sum (fun s => if keyDistinguisher v limits s o (e.drop (params v).n)
      (deriveKey o "DSM/sphincs/v2/prf" (e.take (params v).n)) then 1 else 0))]
    apply sum_congr; intro i
    unfold keyD
    rw [sum_map_product]
    apply sum_congr; intro j
    have hx := ((uniformBytes (params v).n).sample i).property
    simp only [List.drop_left' hx, List.take_left' hx]
  · rw [probability_denominator, probability_denominator, card_product, card_product]
    unfold keyD ub
    rw [card_map, card_map, card_product]
    change 256^(3*(params v).n) * coins.cardinality =
      256^(params v).n * (256^(2*(params v).n) * coins.cardinality)
    rw [← Nat.mul_assoc, ← Nat.pow_add]; congr 2; omega

theorem c15a_ideal (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealPrfKeyProbability v limits o coins =
      idealP (uniformMasterSeed.map Subtype.val) (keyD v limits o coins) := by
  unfold idealPrfKeyProbability idealP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, map_sum]
    rw [sum_comm (uniformBytes (2*(params v).n)) uniformMasterSeed]
    apply sum_congr; intro i
    unfold keyD
    rw [sum_map_product]
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product]
    unfold keyD
    rw [card_map, card_map, card_product]
    generalize (uniformBytes (2*(params v).n)).cardinality = A
    generalize uniformMasterSeed.cardinality = B
    generalize coins.cardinality = C
    rw [Nat.mul_comm A B, Nat.mul_assoc]

theorem c15a_adv (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    advantage (realPrfKeyProbability v limits o coins) (idealPrfKeyProbability v limits o coins) =
      dsmKdfAdv o v "DSM/sphincs/v2/prf" (keyD v limits o coins) := by
  rw [c15a_real, c15a_ideal]; rfl

/-! ## C15 hop 2b: the SKG keyed hash is a PRF advantage -/

theorem c15b_real (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    realPrfFunctionProbability v limits o coins =
      realP (uniformMasterSeed.map Subtype.val) (fun K => mask (skgDom v) [] (keyedFn o K))
        (funcD v limits o coins) := by
  unfold realPrfFunctionProbability realP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, map_sum]
    rw [sum_comm (uniformBytes (2*(params v).n)) uniformMasterSeed]
    apply sum_congr; intro i
    unfold funcD
    rw [sum_map_product]
    apply sum_congr; intro j
    apply sum_congr; intro k
    apply bool_one
    exact function_distinguisher_dom v limits _ o widths _ ((uniformBytes (2*(params v).n)).sample j).property
      _ _ (fun x hx => by simp [mask, skgDom, keyedFn, hx])
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product]
    unfold funcD
    rw [card_map, card_map, card_product]
    generalize (uniformBytes (2*(params v).n)).cardinality = A
    generalize uniformMasterSeed.cardinality = B
    generalize coins.cardinality = C
    rw [Nat.mul_comm A B, Nat.mul_assoc]

theorem c15b_ideal (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealPrfFunctionProbability v limits o coins =
      idealP (uncurried (randomFunction ((params v).n + 32) (params v).n)) (funcD v limits o coins) := by
  unfold idealPrfFunctionProbability idealP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, uncurried_sum]
    rw [sum_comm (uniformBytes (2*(params v).n)) (randomFunction ((params v).n + 32) (params v).n)]
    apply sum_congr; intro i
    unfold funcD
    rw [sum_map_product]
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product]
    unfold funcD uncurried
    rw [card_map, card_map, card_product]
    generalize (uniformBytes (2*(params v).n)).cardinality = A
    generalize (randomFunction ((params v).n + 32) (params v).n).cardinality = B
    generalize coins.cardinality = C
    rw [Nat.mul_comm A B, Nat.mul_assoc]

theorem c15b_adv (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    advantage (realPrfFunctionProbability v limits o coins) (idealPrfFunctionProbability v limits o coins) =
      dsmSkgPrfAdv o v (funcD v limits o coins) := by
  rw [c15b_real v limits o widths, c15b_ideal]; rfl

/-! ## C16 hop 3a: the MKG key derivation is a PRG advantage -/

theorem c16a_real (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    realMsgKeyProbability v limits o coins =
      realP (ub (params v).n) (deriveKey o "DSM/sphincs/v2/prf-msg") (msgKeyD v limits o coins) := by
  unfold realMsgKeyProbability realP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, ub_sum]
    rw [double_sum (params v).n (fun e => (randomFunction ((params v).n+32) (params v).n).sum (fun F =>
      coins.sum (fun s => if msgKeyDistinguisher v limits s o F (e.drop (params v).n)
        (deriveKey o "DSM/sphincs/v2/prf-msg" (e.take (params v).n)) then 1 else 0)))]
    apply sum_congr; intro i
    unfold msgKeyD
    rw [sum_map_product, product_sum]
    apply sum_congr; intro j
    have hx := ((uniformBytes (params v).n).sample i).property
    simp only [List.drop_left' hx, List.take_left' hx]
  · simp only [probability_denominator, card_product, card_map, ub, msgKeyD]
    change 256^(2*(params v).n) * (randomFunction ((params v).n+32) (params v).n).cardinality *
        coins.cardinality = 256^(params v).n * (256^(params v).n *
        (randomFunction ((params v).n+32) (params v).n).cardinality * coins.cardinality)
    generalize (randomFunction ((params v).n+32) (params v).n).cardinality = B
    generalize coins.cardinality = C
    rw [show 2*(params v).n = (params v).n + (params v).n by omega, Nat.pow_add]
    generalize 256^(params v).n = A
    ac_rfl

theorem c16a_ideal (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealMsgKeyProbability v limits o coins =
      idealP (uniformMasterSeed.map Subtype.val) (msgKeyD v limits o coins) := by
  unfold idealMsgKeyProbability idealP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, product_sum, map_sum]
    rw [sum_comm (uniformBytes (params v).n) uniformMasterSeed]
    apply sum_congr; intro i
    unfold msgKeyD
    rw [sum_map_product, product_sum]
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product,
      card_product]
    unfold msgKeyD
    rw [card_map, card_map, card_product, card_product]
    generalize (uniformBytes (params v).n).cardinality = A
    generalize uniformMasterSeed.cardinality = B
    generalize (randomFunction ((params v).n+32) (params v).n).cardinality = R
    generalize coins.cardinality = C
    ac_rfl

theorem c16a_adv (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    advantage (realMsgKeyProbability v limits o coins) (idealMsgKeyProbability v limits o coins) =
      dsmKdfAdv o v "DSM/sphincs/v2/prf-msg" (msgKeyD v limits o coins) := by
  rw [c16a_real, c16a_ideal]; rfl

/-! ## C16 hop 3b: the MKG keyed hash is a PRF advantage -/

theorem c16b_real (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    realMsgFunctionProbability v limits o coins =
      realP (uniformMasterSeed.map Subtype.val)
        (fun L => mask (mkgDom v limits.maxMessageBytes) [] (keyedFn o L)) (msgFuncD v limits o coins) := by
  unfold realMsgFunctionProbability realP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, product_sum, map_sum]
    rw [sum_comm (uniformBytes (params v).n) uniformMasterSeed]
    apply sum_congr; intro i
    unfold msgFuncD
    rw [sum_map_product, product_sum]
    apply sum_congr; intro j
    apply sum_congr; intro F
    apply sum_congr; intro k
    apply bool_one
    exact msg_function_distinguisher_dom v limits _ o widths _ _
      ((uniformBytes (params v).n).sample j).property _ _
      (fun x hx => by simp [mask, mkgDom, keyedFn, hx])
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product,
      card_product]
    unfold msgFuncD
    rw [card_map, card_map, card_product, card_product]
    generalize (uniformBytes (params v).n).cardinality = A
    generalize uniformMasterSeed.cardinality = B
    generalize (randomFunction ((params v).n+32) (params v).n).cardinality = R
    generalize coins.cardinality = C
    ac_rfl

theorem c16b_ideal (v : Variant) (limits : Limits) (o : Oracle Id) (coins : FiniteExperiment Strategy) :
    idealMsgFunctionProbability v limits o coins =
      idealP (uncurried (randomFunctionUpTo ((params v).n + limits.maxMessageBytes) (params v).n))
        (msgFuncD v limits o coins) := by
  unfold idealMsgFunctionProbability idealP
  apply probability_ext
  · rw [numerator_sum, numerator_sum, product_sum, product_sum, product_sum, product_sum, uncurried_sum]
    rw [sum_comm (uniformBytes (params v).n)
      (randomFunctionUpTo ((params v).n + limits.maxMessageBytes) (params v).n)]
    apply sum_congr; intro i
    unfold msgFuncD
    rw [sum_map_product, product_sum]
  · rw [probability_denominator, probability_denominator, card_product, card_product, card_product,
      card_product]
    unfold msgFuncD uncurried
    rw [card_map, card_map, card_product, card_product]
    generalize (uniformBytes (params v).n).cardinality = A
    generalize (randomFunctionUpTo ((params v).n + limits.maxMessageBytes) (params v).n).cardinality = B
    generalize (randomFunction ((params v).n+32) (params v).n).cardinality = R
    generalize coins.cardinality = C
    ac_rfl

theorem c16b_adv (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    advantage (realMsgFunctionProbability v limits o coins) (idealMsgFunctionProbability v limits o coins) =
      dsmMkgPrfAdv o v limits.maxMessageBytes (msgFuncD v limits o coins) := by
  rw [c16b_real v limits o widths, c16b_ideal]; rfl

/-! ## C31 with named primitive advantages -/

/-- C31 (`euf_cma_reduction`), with each hop's term replaced by the advantage
    of the hop's distinguisher in a PRG or PRF game on the named primitive.
    The four event terms are C31's own; splitting them into the modular
    theorem's terms is milestone 5. -/
theorem euf_cma_named (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    fle (eufCmaProbability v limits o coins).frac
      (fadd (fadd (fadd (fadd (fadd
        ((probability (finalSpace v limits coins) (collisionEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (wotsPreimageEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsSecretEvent v limits o)).numerator +
         (probability (finalSpace v limits coins) (forsCoveredEvent v limits o)).numerator,
         (finalSpace v limits coins).cardinality)
        (dsmMkgPrfAdv o v limits.maxMessageBytes (msgFuncD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf-msg" (msgKeyD v limits o coins)))
        (dsmSkgPrfAdv o v (funcD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf" (keyD v limits o coins)))
        (dsmPrgAdv o v (seedD v limits o coins))) := by
  rw [← c16b_adv v limits o widths, ← c16a_adv, ← c15b_adv v limits o widths, ← c15a_adv, ← c11_adv]
  exact euf_cma_reduction v limits o widths coins

#print axioms c11_adv
#print axioms c15a_adv
#print axioms c15b_adv
#print axioms c16a_adv
#print axioms c16b_adv
#print axioms euf_cma_named
end DSM.Sphincs.Comp
