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

 theorem type_clear_correct (self : Adrs) (t : U32) :
    self.set_type_and_clear t ⦃ result =>
      result.w.val = (((self.w.val.set 4 t).set 5 0#u32).set 6 0#u32).set 7 0#u32 ⦄ := by
  unfold Adrs.set_type_and_clear
  step*
  all_goals simp_all

 theorem tree_set_correct (self : Adrs) (tree : U64) :
    self.set_tree tree ⦃ result =>
      ∃ hi : U64, hi.val = tree.val / 2^32 ∧
        result.w.val = ((self.w.val.set 1 0#u32).set 2
          (UScalar.cast .U32 hi)).set 3 (UScalar.cast .U32 tree) ⦄ := by
  unfold Adrs.set_tree
  step*
  all_goals try simp_all
  refine ⟨i, ?_, ?_⟩
  · simpa [Nat.shiftRight_eq_div_pow] using i_post
  · simp_all

 theorem byte_refill_body (x : Slice U8) (input b : Usize)
    (width : 0 < b.val ∧ b.val ≤ 8)
    (bound : input.val < x.val.length) :
    base_2b_loop0_loop0.body x b input 0#usize 0#u64 ⦃ result =>
      ∃ next : Usize, ∃ total : U64,
        result = .cont (next,8#usize,total) ∧ next.val = input.val+1 ∧
        total.val = x.val[input.val].val ⦄ := by
  unfold base_2b_loop0_loop0.body
  simp only [lift, bind_ok]
  step*
  all_goals simp_all
  all_goals scalar_tac


 theorem refill_step (x : Slice U8) (input b bits : Usize) (total : U64)
    (need : bits.val < b.val) (bitsBound : bits.val ≤ 15)
    (bound : input.val < x.val.length) :
    base_2b_loop0_loop0.body x b input bits total ⦃ result =>
      ∃ next : Usize, ∃ nextBits : Usize, ∃ nextTotal : U64,
        result = .cont (next,nextBits,nextTotal) ∧
        next.val = input.val+1 ∧ nextBits.val = bits.val+8 ∧
        nextTotal.bv = (total.bv <<< 8) |||
          (core.convert.num.FromU64U8.from x.val[input.val]).bv ⦄ := by
  unfold base_2b_loop0_loop0.body
  simp only [lift, bind_ok]
  step*
  all_goals simp_all
 theorem refill_ready (x : Slice U8) (b input bits : Usize) (total : U64)
    (ready : b.val ≤ bits.val) :
    base_2b_loop0_loop0 x b input bits total = Result.ok (input,bits,total) := by
  have notNeeded : ¬bits < b := by scalar_tac
  unfold base_2b_loop0_loop0
  rw [loop]
  simp [base_2b_loop0_loop0.body, notNeeded, bind_ok]

 theorem byte_refill_complete (x : Slice U8) (input b : Usize)
    (width : 0 < b.val ∧ b.val ≤ 8) (bound : input.val < x.val.length) :
    base_2b_loop0_loop0 x b input 0#usize 0#u64 ⦃ result =>
      result.1.val = input.val+1 ∧ result.2.1.val = 8 ∧
      result.2.2.val = x.val[input.val].val ⦄ := by
  unfold base_2b_loop0_loop0
  rw [loop]
  apply WP.spec_bind (byte_refill_body x input b width bound)
  intro result matched
  obtain ⟨next,total,equal,nextVal,totalVal⟩ := matched
  subst result
  change loop _ (next,8#usize,total) ⦃ _ ⦄
  change base_2b_loop0_loop0 x b next 8#usize total ⦃ _ ⦄
  rw [refill_ready x b next 8#usize total (by simpa using width.2)]
  simp [nextVal,totalVal]


def refillReads (b bits : Nat) : Nat :=
  if b ≤ bits then 0 else if b ≤ bits+8 then 1 else 2

 theorem refill_complete (x : Slice U8) (input b bits : Usize) (total : U64)
    (width : 0 < b.val ∧ b.val ≤ 14) (residual : bits.val ≤ 7)
    (buffered : input.val + refillReads b.val bits.val ≤ x.val.length) :
    base_2b_loop0_loop0 x b input bits total ⦃ result =>
      result.1.val = input.val + refillReads b.val bits.val ∧
      result.2.1.val = bits.val + 8 * refillReads b.val bits.val ∧
      b.val ≤ result.2.1.val ∧ result.2.1.val < b.val+8 ⦄ := by
  by_cases ready : b.val ≤ bits.val
  · rw [refill_ready x b input bits total ready]
    simp [refillReads,ready]
    omega
  by_cases one : b.val ≤ bits.val+8
  · have reads : refillReads b.val bits.val = 1 := by simp [refillReads,ready,one]
    unfold base_2b_loop0_loop0
    rw [loop]
    apply WP.spec_bind (refill_step x input b bits total (by omega) (by omega) (by omega))
    intro result matched
    obtain ⟨next,nextBits,nextTotal,equal,nextVal,nextBitsVal,_⟩ := matched
    subst result
    change base_2b_loop0_loop0 x b next nextBits nextTotal ⦃ _ ⦄
    rw [refill_ready x b next nextBits nextTotal (by omega)]
    simp [nextVal,nextBitsVal,reads]
    omega
  · have reads : refillReads b.val bits.val = 2 := by simp [refillReads,ready,one]
    unfold base_2b_loop0_loop0
    rw [loop]
    apply WP.spec_bind (refill_step x input b bits total (by omega) (by omega) (by omega))
    intro result matched
    obtain ⟨next,nextBits,nextTotal,equal,nextVal,nextBitsVal,_⟩ := matched
    subst result
    change base_2b_loop0_loop0 x b next nextBits nextTotal ⦃ _ ⦄
    unfold base_2b_loop0_loop0
    rw [loop]
    apply WP.spec_bind (refill_step x next b nextBits nextTotal (by omega) (by omega) (by omega))
    intro second matchedSecond
    obtain ⟨last,lastBits,lastTotal,equal,lastVal,lastBitsVal,_⟩ := matchedSecond
    subst second
    change base_2b_loop0_loop0 x b last lastBits lastTotal ⦃ _ ⦄
    rw [refill_ready x b last lastBits lastTotal (by omega)]
    simp [lastVal,lastBitsVal,nextVal,nextBitsVal,reads]
    omega


 theorem refill_read_count_noninterference (x y : Slice U8)
    (input b bits : Usize) (totalX totalY : U64)
    (width : 0 < b.val ∧ b.val ≤ 14) (residual : bits.val ≤ 7)
    (bufferX : input.val + refillReads b.val bits.val ≤ x.val.length)
    (bufferY : input.val + refillReads b.val bits.val ≤ y.val.length) :
    base_2b_loop0_loop0 x b input bits totalX ⦃ left =>
      base_2b_loop0_loop0 y b input bits totalY ⦃ right =>
        left.1.val = right.1.val ∧ left.2.1.val = right.2.1.val ⦄ ⦄ := by
  apply WP.spec_mono (refill_complete x input b bits totalX width residual bufferX)
  intro left leftPost
  apply WP.spec_mono (refill_complete y input b bits totalY width residual bufferY)
  intro right rightPost
  exact ⟨leftPost.1.trans rightPost.1.symm, leftPost.2.1.trans rightPost.2.1.symm⟩

#print axioms refill_read_count_noninterference
#print axioms refill_complete
#print axioms byte_refill_complete
#print axioms refill_ready

#print axioms type_clear_correct
#print axioms tree_set_correct
#print axioms next_layer_success
#print axioms next_layer_refines
end DSMSphincsRust
