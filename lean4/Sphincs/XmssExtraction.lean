-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.WotsExtraction

/- Forgery extraction, stage 2, XMSS layer. The honest XMSS instance at
   address `a` has root `xmssNode … a 0 hp`; its WOTS key at leaf `idx` is the
   one at `{a.setType 0 with keypair := idx}`. A forged XMSS signature of an
   n-byte value `m'` that reconstructs the honest root either carries the
   honestly signed value `M` itself, or exhibits one of the break events in
   `XmssBreakAt`, each located at an address of this XMSS instance. -/
namespace DSM.Sphincs

/-- The forged WOTS signature bytes `wsig` contain, in the slot of chain `i`,
    the honest chain value at a position `d` strictly below the position the
    honest signature of `M` reveals for that chain. -/
def WotsPreimageAt (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (wa : Adrs)
    (M wsig : Bytes) : Prop :=
  ∃ i d, i < p.len ∧ d < (wotsDigits p M).getD i 0 ∧
    slice wsig (i*p.n) p.n = wotsChainValue o p tk prfKey seed wa i d

/-- Break events of the XMSS instance at `a`, leaf `leaf`, whose WOTS key
    honestly signs `M`; `wsig` is the forged WOTS signature. -/
def XmssBreakAt (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (leaf : Nat)
    (M wsig : Bytes) : Prop :=
  (∃ j, j < p.hp ∧
    ThashCollisionAt o p tk {a.setType 2 with chain := j+1, hash := leaf/2^(j+1)}) ∨
  ThashCollisionAt o p tk {({a.setType 0 with keypair := leaf} : Adrs).setType 1 with
    keypair := ({a.setType 0 with keypair := leaf} : Adrs).keypair} ∨
  (∃ i j, i < p.len ∧ j < 15 ∧
    ThashCollisionAt o p tk {{({a.setType 0 with keypair := leaf} : Adrs) with chain := i} with hash := j}) ∨
  WotsPreimageAt o p tk prfKey seed {a.setType 0 with keypair := leaf} M wsig

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem wotsPkFromSig_width (widths : OutputWidths o) (a : Adrs) (sig msg : Bytes) :
    (wotsPkFromSig o p tk a sig msg).length = p.n := by
  rw [wots_verify_blocks]
  exact thash_width o widths p tk _ _

theorem layer_take_width (sig : Bytes) (hsig : sig.length = p.layerBytes) :
    (sig.take (p.len*p.n)).length = p.len*p.n := by
  simp only [List.length_take, hsig, Params.layerBytes, Nat.add_mul]
  omega

/-- XMSS layer extraction: a forged XMSS signature (one layer, `layerBytes`
    long) of an n-byte `m'` that reconstructs the honest root at the honest
    leaf index either signs the honestly signed n-byte value `M`, or yields
    an XMSS break at this instance. -/
theorem xmss_forgery_extract (widths : OutputWidths o) (hn : 2*p.n*15 < 4096)
    (a : Adrs) (idx : Nat) (hidx : idx < 2^p.hp) (M m' sig' : Bytes)
    (hM : M.length = p.n) (hm' : m'.length = p.n) (hsig : sig'.length = p.layerBytes)
    (hroot : xmssPkFromSig o p tk a idx sig' m' = xmssNode o p tk prfKey seed a 0 p.hp) :
    m' = M ∨ XmssBreakAt o p tk prfKey seed a idx M (sig'.take (p.len*p.n)) := by
  have honest : authRoot o p tk (a.setType 2) idx idx (xmssNode o p tk prfKey seed a idx 0)
      (((List.range p.hp).map fun j =>
        (xmssNode o p tk prfKey seed a (Nat.xor (idx/2^j) 1) j : Bytes)).flatten) p.hp =
      xmssNode o p tk prfKey seed a 0 p.hp := by
    have h := xmss_signer_tree_path o p tk prfKey seed a idx _
      (fun j hj => xmss_auth_bytes o widths p tk prfKey seed a idx j hj)
    rwa [Nat.div_eq_of_lt hidx] at h
  have hroot' : authRoot o p tk (a.setType 2) idx idx
      (wotsPkFromSig o p tk {a.setType 0 with keypair := idx} (sig'.take (p.len*p.n)) m')
      (sig'.drop (p.len*p.n)) p.hp =
      authRoot o p tk (a.setType 2) idx idx (xmssNode o p tk prfKey seed a idx 0)
      (((List.range p.hp).map fun j =>
        (xmssNode o p tk prfKey seed a (Nat.xor (idx/2^j) 1) j : Bytes)).flatten) p.hp := by
    rw [honest]; exact hroot
  by_cases hL : wotsPkFromSig o p tk {a.setType 0 with keypair := idx} (sig'.take (p.len*p.n)) m' =
      xmssNode o p tk prfKey seed a idx 0
  · by_cases hmM : m' = M
    · exact Or.inl hmM
    · right
      have hd : wotsDigits p M ≠ wotsDigits p m' :=
        fun h => hmM (wots_digits_injective p M m' hM hm' h).symm
      rcases wots_forgery_extract_of widths hn {a.setType 0 with keypair := idx} M m'
        (sig'.take (p.len*p.n)) (layer_take_width sig' hsig) hd hL with h | h | h
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr (Or.inl h))
      · obtain ⟨i, hi, hlt, e⟩ := h
        exact Or.inr (Or.inr (Or.inr ⟨i, _, hi, hlt, e⟩))
  · right
    obtain ⟨j, hj, hc⟩ := auth_root_extract_general widths (a.setType 2) _ _ idx idx p.hp _ _
      (by rw [wotsPkFromSig_width widths, xmss_node_width o widths]) hroot' (Or.inl hL)
    exact Or.inl ⟨j, hj, hc⟩
end

#print axioms xmss_forgery_extract
end DSM.Sphincs
