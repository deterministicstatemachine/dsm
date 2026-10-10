-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ForgeryExtract

/- Address range for the extracted break events: every thash collision that
   `XmssBreakAt`, `HtBreak` and `ForsBreakAt` exhibit is at an `InRange`
   address, so it is a `ThashCollision` under the honest thash key. -/
namespace DSM.Sphincs

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem xmssBreak_collision (layer tree leaf : Nat) (M wsig : Bytes)
    (hl : layer < 256^4) (ht : tree < 256^8) (hleaf : leaf < 2^p.hp) (hH : 2^p.hp ≤ 256^4)
    (hlen : p.len ≤ 256^4)
    (h : XmssBreakAt o p tk prfKey seed {layer := layer, tree := tree} leaf M wsig) :
    ThashCollision o p tk ∨
      WotsPreimageAt o p tk prfKey seed
        {({layer := layer, tree := tree} : Adrs).setType 0 with keypair := leaf} M wsig := by
  have hhp : p.hp < 2^p.hp := Nat.lt_two_pow_self
  rcases h with ⟨j, hj, c⟩ | c | ⟨i, j, hi, hj, c⟩ | w
  · have hd : leaf/2^(j+1) ≤ leaf := Nat.div_le_self _ _
    exact Or.inl (c.collision (by inrange))
  · exact Or.inl (c.collision (by inrange))
  · exact Or.inl (c.collision (by inrange))
  · exact Or.inr w
end

theorem htBreak_collision (o : Oracle Id) (v : Variant) (tk prfKey seed S : Bytes)
    (h : HtBreak o (params v) tk prfKey seed S) :
    ThashCollision o (params v) tk ∨
      ∃ layer tree leaf, layer < (params v).d ∧
        tree < 2^((params v).hp*((params v).d-1-layer)) ∧ leaf < 2^(params v).hp ∧
        WotsPreimageAt o (params v) tk prfKey seed
          {({layer := layer, tree := tree} : Adrs).setType 0 with keypair := leaf}
          (htMsg o (params v) tk prfKey seed layer tree leaf)
          (((S.drop (layer*(params v).layerBytes)).take (params v).layerBytes).take
            ((params v).len*(params v).n)) := by
  obtain ⟨layer, tree, leaf, hl, ht, hleaf, b⟩ := h
  obtain ⟨hlen, hH, hd, _, _, hT⟩ := variant_bounds v
  obtain ⟨_, hexp⟩ := supported_layer_bounds v
  have ht' : tree < 256^8 := by
    have h1 : 2^((params v).hp*((params v).d-1-layer)) ≤ 2^((params v).hp*((params v).d-1)) :=
      Nat.pow_le_pow_right (by decide) (Nat.mul_le_mul_left _ (by omega))
    rw [hexp] at h1
    omega
  rcases xmssBreak_collision layer tree leaf _ _ (by omega) ht' hleaf hH hlen b with c | w
  · exact Or.inl c
  · exact Or.inr ⟨layer, tree, leaf, hl, ht, hleaf, w⟩

theorem forsBreak_collision (o : Oracle Id) (v : Variant) (tk : Bytes) (tree leaf : Nat) (md : Bytes)
    (ht : tree < 2^((params v).h-(params v).hp)) (hleaf : leaf < 2^(params v).hp)
    (h : ForsBreakAt o (params v) tk tree leaf md) : ThashCollision o (params v) tk := by
  obtain ⟨hlen, hH, hd, hMA, hA, hT⟩ := variant_bounds v
  have ht' : tree < 256^8 := by omega
  have hleaf' : leaf < 256^4 := by omega
  rcases h with c | ⟨i, hi, c | c⟩
  · exact c.collision (by unfold forsAdrs; inrange)
  · obtain ⟨j, hj, c⟩ := c
    have hdig : forsDigit (params v) md i < 2^(params v).a := by
      unfold forsDigit
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [base2b_length]; exact hi),
        Option.getD_some]
      exact base2b_digit_bound md _ _ _ (List.getElem_mem _)
    have hg := Nat.lt_of_lt_of_le (offset_lt hi hdig) hMA
    have hdv : (i*2^(params v).a + forsDigit (params v) md i)/2^(j+1) ≤
        i*2^(params v).a + forsDigit (params v) md i := Nat.div_le_self _ _
    exact c.collision (by unfold forsAdrs; inrange)
  · have hdig : forsDigit (params v) md i < 2^(params v).a := by
      unfold forsDigit
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by rw [base2b_length]; exact hi),
        Option.getD_some]
      exact base2b_digit_bound md _ _ _ (List.getElem_mem _)
    have hg := Nat.lt_of_lt_of_le (offset_lt hi hdig) hMA
    exact c.collision (by unfold forsAdrs; inrange)

#print axioms xmssBreak_collision
#print axioms htBreak_collision
#print axioms forsBreak_collision
end DSM.Sphincs
