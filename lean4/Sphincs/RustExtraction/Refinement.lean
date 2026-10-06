-- SPDX-License-Identifier: MIT OR Apache-2.0
import DsmSphincs.Funs
import Sphincs.Model
open Aeneas Aeneas.Std
namespace DSMSphincsRust
 theorem next_layer_success (p : Params) (tree : U64) (bounded : p.hp.val ≤ 9) :
    next_layer p tree ⦃ result =>
      result.1.val = tree.val % 2^p.hp.val ∧ result.2.val = tree.val/2^p.hp.val ⦄ := by
  unfold next_layer
  step*
  all_goals
    have powBound : 2^p.hp.val < 2^64 := Nat.pow_lt_pow_right (by decide) (by omega)
    simp only [Nat.shiftLeft_eq,Nat.one_mul,U64.size,U64.numBits,UScalarTy.numBits] at i_post
    rw [Nat.mod_eq_of_lt powBound] at i_post
  · rw [i_post]
    change 1 ≤ 2^p.hp.val
    have positive : 0 < 2^p.hp.val := Nat.pow_pos (by decide)
    omega
  · rw [i3_post,UScalar.cast_val_eq,i2_post,UScalar.val_and,i1_post,i_post]
    simp only [Nat.and_two_pow_sub_one_eq_mod,UScalarTy.numBits]
    have leafBound : tree.val % 2^p.hp.val < 2^32 := by
      have small : 2^p.hp.val ≤ 2^32 := Nat.pow_le_pow_right (by decide) (by omega)
      exact lt_of_lt_of_le (Nat.mod_lt _ (Nat.pow_pos (by decide))) small
    constructor
    · exact Nat.mod_eq_of_lt leafBound
    · simpa [Nat.shiftRight_eq_div_pow] using i4_post

 theorem next_layer_refines (p : Params) (model : DSM.Sphincs.Params) (tree : U64)
    (hp : p.hp.val = model.hp) (bounded : p.hp.val ≤ 9) :
    next_layer p tree ⦃ result =>
      (result.1.val, result.2.val) = DSM.Sphincs.nextLayer model tree.val ⦄ := by
  apply WP.spec_mono (next_layer_success p tree bounded)
  intro result matched
  simp only [DSM.Sphincs.nextLayer, ← hp, matched.1, matched.2]

#print axioms next_layer_success
#print axioms next_layer_refines
end DSMSphincsRust
