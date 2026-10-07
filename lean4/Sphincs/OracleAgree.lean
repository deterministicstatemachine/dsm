-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs

/- Oracle agreement for the signer. The PRF key enters the construction only
   through `prf`, i.e. keyed requests under that key. If two oracles answer
   every keyed request alike, except that key `M` under the first answers as
   key `K` under the second, then every signer and verifier component computed
   with `M` under the first equals the same component computed with `K` under
   the second. This is the simulation step of the PRF hybrids; it uses no
   cryptographic premise. -/
namespace DSM.Sphincs

structure KeyedAgree (o₁ o₂ : Oracle Id) (M K : Bytes) : Prop where
  other : ∀ key input len, key ≠ M → o₁ ⟨1,"",key,input,len⟩ = o₂ ⟨1,"",key,input,len⟩
  renamed : ∀ input len, o₁ ⟨1,"",M,input,len⟩ = o₂ ⟨1,"",K,input,len⟩

/-- Agreement at the two keys a signer component uses: its public hash key `tk`
    (asked alike in both worlds) and the PRF key (`M` in the first world
    answering as `K` in the second). Nothing is required of any other key. -/
structure KeyedAgreeAt (o₁ o₂ : Oracle Id) (tk M K : Bytes) : Prop where
  thash : ∀ input len, o₁ ⟨1,"",tk,input,len⟩ = o₂ ⟨1,"",tk,input,len⟩
  renamed : ∀ input len, o₁ ⟨1,"",M,input,len⟩ = o₂ ⟨1,"",K,input,len⟩

theorem KeyedAgree.at {o₁ o₂ : Oracle Id} {M K : Bytes} (h : KeyedAgree o₁ o₂ M K) {tk : Bytes}
    (htk : tk = M → M = K) : KeyedAgreeAt o₁ o₂ tk M K := by
  refine ⟨fun input len => ?_, h.renamed⟩
  by_cases e : tk = M
  · have k := htk e
    subst e; subst k
    exact h.renamed _ _
  · exact h.other _ _ _ e

section
variable {o₁ o₂ : Oracle Id} {M K : Bytes} {p : Params} {tk : Bytes} (h : KeyedAgreeAt o₁ o₂ tk M K)
include h

theorem thash_agree (a : Adrs) (input : Bytes) :
    thash o₁ p tk a input = thash o₂ p tk a input := h.thash _ _

theorem chain_agree (a : Adrs) (x : Bytes) (start steps : Nat) :
    chain o₁ p tk a x start steps = chain o₂ p tk a x start steps := by
  induction steps generalizing x start with
  | zero => rfl
  | succ s ih => simp only [chain, thash_agree h, ih]

theorem wotsCompress_agree (a : Adrs) (tops : Bytes) :
    wotsCompress o₁ p tk a tops = wotsCompress o₂ p tk a tops := by
  simp only [wotsCompress, thash_agree h]

theorem wotsPkFromSig_agree (a : Adrs) (sig msg : Bytes) :
    wotsPkFromSig o₁ p tk a sig msg = wotsPkFromSig o₂ p tk a sig msg := by
  simp only [wotsPkFromSig, chain_agree h, wotsCompress_agree h]

theorem authWalk_agree (a : Adrs) (localIndex globalIndex : Nat) (node auth : Bytes)
    (level remaining : Nat) :
    authWalk o₁ p tk a localIndex globalIndex node auth level remaining =
      authWalk o₂ p tk a localIndex globalIndex node auth level remaining := by
  induction remaining generalizing localIndex globalIndex node level with
  | zero => rfl
  | succ r ih => simp only [authWalk, thash_agree h, ih]

theorem authRoot_agree (a : Adrs) (localIndex globalIndex : Nat) (node auth : Bytes)
    (height : Nat) :
    authRoot o₁ p tk a localIndex globalIndex node auth height =
      authRoot o₂ p tk a localIndex globalIndex node auth height := by
  simp only [authRoot, authWalk_agree h]

theorem xmssPkFromSig_agree (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    xmssPkFromSig o₁ p tk a idx sig msg = xmssPkFromSig o₂ p tk a idx sig msg := by
  simp only [xmssPkFromSig, wotsPkFromSig_agree h, authRoot_agree h]

theorem htRootTail_agree (layer tree : Nat) (node sig : Bytes) (remaining : Nat) :
    htRootTail o₁ p tk layer tree node sig remaining =
      htRootTail o₂ p tk layer tree node sig remaining := by
  induction remaining generalizing layer tree node sig with
  | zero => rfl
  | succ r ih => simp only [htRootTail, xmssPkFromSig_agree h, ih]

theorem htRoot_agree (sig msg : Bytes) (idxTree idxLeaf : Nat) :
    htRoot o₁ p tk sig msg idxTree idxLeaf = htRoot o₂ p tk sig msg idxTree idxLeaf := by
  simp only [htRoot, xmssPkFromSig_agree h, htRootTail_agree h]

theorem forsPkFromSig_agree (a : Adrs) (sig md : Bytes) :
    forsPkFromSig o₁ p tk a sig md = forsPkFromSig o₂ p tk a sig md := by
  simp only [forsPkFromSig, thash_agree h, authRoot_agree h]

theorem prf_agree (seed : Bytes) (a : Adrs) :
    prf o₁ p M seed a = prf o₂ p K seed a := h.renamed _ _

theorem wotsSign_agree (seed : Bytes) (a : Adrs) (msg : Bytes) :
    wotsSign o₁ p tk M seed a msg = wotsSign o₂ p tk K seed a msg := by
  simp only [wotsSign, prf_agree h, chain_agree h]

theorem wotsPkgen_agree (seed : Bytes) (a : Adrs) :
    wotsPkgen o₁ p tk M seed a = wotsPkgen o₂ p tk K seed a := by
  simp only [wotsPkgen, prf_agree h, chain_agree h, wotsCompress_agree h]

theorem xmssNode_agree (seed : Bytes) (a : Adrs) (idx height : Nat) :
    xmssNode o₁ p tk M seed a idx height = xmssNode o₂ p tk K seed a idx height := by
  induction height generalizing idx with
  | zero => simp only [xmssNode, wotsPkgen_agree h]
  | succ r ih => simp only [xmssNode, ih, thash_agree h]

theorem xmssSign_agree (seed : Bytes) (a : Adrs) (idx : Nat) (msg : Bytes) :
    xmssSign o₁ p tk M seed a idx msg = xmssSign o₂ p tk K seed a idx msg := by
  simp only [xmssSign, xmssNode_agree h, wotsSign_agree h]

theorem htSignTail_agree (seed : Bytes) (layer tree : Nat) (node : Bytes) (remaining : Nat) :
    htSignTail o₁ p tk M seed layer tree node remaining =
      htSignTail o₂ p tk K seed layer tree node remaining := by
  induction remaining generalizing layer tree node with
  | zero => rfl
  | succ r ih => simp only [htSignTail, xmssSign_agree h, xmssPkFromSig_agree h, ih]

theorem htSign_agree (seed msg : Bytes) (idxTree idxLeaf : Nat) :
    htSign o₁ p tk M seed msg idxTree idxLeaf = htSign o₂ p tk K seed msg idxTree idxLeaf := by
  simp only [htSign, xmssSign_agree h, xmssPkFromSig_agree h, htSignTail_agree h]

theorem forsSecret_agree (seed : Bytes) (a : Adrs) (idx : Nat) :
    forsSecret o₁ p M seed a idx = forsSecret o₂ p K seed a idx := by
  simp only [forsSecret, prf_agree h]

theorem forsNode_agree (seed : Bytes) (a : Adrs) (idx height : Nat) :
    forsNode o₁ p tk M seed a idx height = forsNode o₂ p tk K seed a idx height := by
  induction height generalizing idx with
  | zero => simp only [forsNode, forsSecret_agree h, thash_agree h]
  | succ r ih => simp only [forsNode, ih, thash_agree h]

theorem forsSign_agree (seed : Bytes) (a : Adrs) (md : Bytes) :
    forsSign o₁ p tk M seed a md = forsSign o₂ p tk K seed a md := by
  simp only [forsSign, forsSecret_agree h, forsNode_agree h]

end

#print axioms forsSign_agree
#print axioms htSign_agree
#print axioms htRoot_agree
#print axioms xmssNode_agree
end DSM.Sphincs
