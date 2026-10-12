-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.ForgeryExtractExp

/- Extraction at the verifier's own positions. `forgery_extract_exp` states
   the WOTS-preimage event existentially over every hypertree position; here
   it is located on the verifier's path (the positions its digest selects,
   layer by layer), with the honest chain value at the forged digit appearing
   as the input of a thash request in the verifier's log. The FORS-secret
   event likewise carries the verifier's leaf request, whose input is the
   honest FORS secret. These are the facts the hidden-value argument needs:
   the honest successor request and the verifier's request coincide. -/
namespace DSM.Sphincs.Security
open DSM.Sphincs

/-- The WOTS key address at hypertree position (layer, tree, leaf). -/
def wA (layer tree leaf : Nat) : Adrs := {({layer := layer, tree := tree} : Adrs).setType 0 with keypair := leaf}

/-- The verifier's log `L` hashes, at chain `i` of the honest WOTS key at
    (layer, tree, leaf), the honest chain value at a step `j` below the digit
    the honest key signs there. -/
def WotsHit (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (L : List Request)
    (layer tree leaf : Nat) : Prop :=
  ∃ i j, i < p.len ∧ j < (wotsDigits p (htMsg o p tk prfKey seed layer tree leaf)).getD i 0 ∧
    thashReq p tk {({wA layer tree leaf with chain := i} : Adrs) with hash := j}
      (wotsChainValue o p tk prfKey seed (wA layer tree leaf) i j) ∈ L

theorem WotsHit.mono {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes} {L L' : List Request}
    {layer tree leaf : Nat} (h : WotsHit o p tk prfKey seed L layer tree leaf) (sub : ∀ r ∈ L, r ∈ L') :
    WotsHit o p tk prfKey seed L' layer tree leaf := by
  obtain ⟨i, j, hi, hj, hm⟩ := h
  exact ⟨i, j, hi, hj, sub _ hm⟩

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem wots_req_mem (wa : Adrs) (sig msg : Bytes) (i : Nat) (hi : i < p.len)
    (h15 : (wotsDigits p msg).getD i 0 < 15) :
    thashReq p tk {({wa with chain := i} : Adrs) with hash := (wotsDigits p msg).getD i 0}
      (slice sig (i*p.n) p.n) ∈ wotsPkFromSigLog o p tk wa sig msg := by
  obtain ⟨hmem, _⟩ := digit_mem (p := p) msg i hi
  unfold wotsPkFromSigLog
  refine List.mem_append_left _ (List.mem_flatMap.mpr ⟨_, hmem, ?_⟩)
  have : 15 - (wotsDigits p msg).getD i 0 = (15 - (wotsDigits p msg).getD i 0 - 1) + 1 := by omega
  simp only
  rw [this]
  simp [chainLog]

theorem fors_leaf_mem (a : Adrs) (sig md : Bytes) (i : Nat) (hi : i < p.k) :
    thashReq p tk {a with chain := 0, hash := i*2^p.a + forsDigit p md i}
      ((slice sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n) ∈ forsPkFromSigLog o p tk a sig md := by
  have hlen : i < (base2b md p.a p.k).length := by rw [base2b_length]; exact hi
  have hmem := getD_mem_zipIdx _ i hlen
  unfold forsPkFromSigLog
  exact List.mem_append_left _ (List.mem_flatMap.mpr ⟨_, hmem, List.mem_cons_self ..⟩)

theorem fors_leaf_mem' (a : Adrs) (sig md : Bytes) (i : Nat) (hi : i < p.k) (x : Bytes)
    (hx : slice sig (i*((p.a+1)*p.n)) p.n = x) :
    thashReq p tk {a with chain := 0, hash := i*2^p.a + forsDigit p md i} x ∈
      forsPkFromSigLog o p tk a sig md := by
  rw [← hx, ← slice_take_prefix sig (i*((p.a+1)*p.n)) ((p.a+1)*p.n) p.n
    (by rw [Nat.add_mul, Nat.one_mul]; omega)]
  exact fors_leaf_mem a sig md i hi

/-- XMSS layer extraction, keeping the verifier's request at the forged digit. -/
theorem xmss_extract_log2 (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096)
    (layer tr : Nat) (hl : layer < 256^4) (ht : tr < 256^8) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (idx : Nat) (hidx : idx < 2^p.hp) (m' sig' : Bytes)
    (hm' : m'.length = p.n) (hsig : sig'.length = p.layerBytes)
    (hroot : xmssPkFromSig o p tk {layer := layer, tree := tr} idx sig' m' =
      xmssNode o p tk prfKey seed {layer := layer, tree := tr} 0 p.hp) :
    m' = htMsg o p tk prfKey seed layer tr idx ∨
      CanonCollIn o p tk prfKey seed (xmssPkFromSigLog o p tk {layer := layer, tree := tr} idx sig' m') ∨
      WotsHit o p tk prfKey seed (xmssPkFromSigLog o p tk {layer := layer, tree := tr} idx sig' m') layer tr idx := by
  have hhp : p.hp < 2^p.hp := Nat.lt_two_pow_self
  have hwalk : authWalk o p tk (({layer := layer, tree := tr} : Adrs).setType 2) idx idx
      (wotsPkFromSig o p tk {({layer := layer, tree := tr} : Adrs).setType 0 with keypair := idx}
        (sig'.take (p.len*p.n)) m')
      (sig'.drop (p.len*p.n)) 0 p.hp =
      (fun lv i => xmssNode o p tk prfKey seed {layer := layer, tree := tr} i lv) (0+p.hp) (idx/2^p.hp) := by
    rw [Nat.zero_add, Nat.div_eq_of_lt hidx]; exact hroot
  by_cases hL : wotsPkFromSig o p tk {({layer := layer, tree := tr} : Adrs).setType 0 with keypair := idx}
      (sig'.take (p.len*p.n)) m' = xmssNode o p tk prfKey seed {layer := layer, tree := tr} idx 0
  · by_cases hmM : m' = htMsg o p tk prfKey seed layer tr idx
    · exact Or.inl hmM
    · have hd : wotsDigits p (htMsg o p tk prfKey seed layer tr idx) ≠ wotsDigits p m' :=
        fun h => hmM (wots_digits_injective p _ m' (htMsg_w tw _ _ _) hm' h).symm
      rcases wots_extract_log tw pw hseed hn {layer := layer, tree := tr} idx hl ht (by omega) hlen
        (htMsg o p tk prfKey seed layer tr idx) m' _ (layer_take_width sig' hsig) hd hL with c | w
      · exact Or.inr (Or.inl (c.mono (fun r hr => List.mem_append_left _ hr)))
      · obtain ⟨i, hi, hlt, e⟩ := w
        have h15 := (digit_mem (p := p) (htMsg o p tk prfKey seed layer tr idx) i hi).2
        refine Or.inr (Or.inr ⟨i, _, hi, hlt, ?_⟩)
        have hm := wots_req_mem (o := o) (tk := tk)
          {({layer := layer, tree := tr} : Adrs).setType 0 with keypair := idx}
          (sig'.take (p.len*p.n)) m' i hi (by omega)
        rw [e] at hm
        exact List.mem_append_left _ hm
  · obtain ⟨j, inp, hj, hm, hne, he⟩ := auth_walk_extract_log tw (({layer := layer, tree := tr} : Adrs).setType 2)
      (fun lv i => xmssNode o p tk prfKey seed {layer := layer, tree := tr} i lv)
      (fun lv i => xmssNode_w tw _ i lv)
      (fun lv i => xmss_node_parent o p tk prfKey seed _ lv i) _ p.hp 0 idx idx _
      (wotsPkFromSig_w tw _ _ _) (fun _ _ => rfl) hwalk hL
    have hc : canon o p tk prfKey seed
        {({layer := layer, tree := tr} : Adrs).setType 2 with chain := 0+j+1, hash := idx/2^(j+1)} =
        List.append (xmssNode (m := Id) o p tk prfKey seed {layer := layer, tree := tr} (2*(idx/2^(j+1))) (0+j))
          (xmssNode (m := Id) o p tk prfKey seed {layer := layer, tree := tr} (2*(idx/2^(j+1))+1) (0+j)) := by
      rw [canon_kind2 (a := {({layer := layer, tree := tr} : Adrs).setType 2 with chain := 0+j+1, hash := idx/2^(j+1)}) rfl]
      dsimp only [Adrs.setType]
      rw [Nat.add_sub_cancel]
    have hd : idx/2^(j+1) ≤ idx := Nat.div_le_self _ _
    refine Or.inr (Or.inl ⟨{({layer := layer, tree := tr} : Adrs).setType 2 with chain := 0+j+1, hash := idx/2^(j+1)}, inp, ?_, List.mem_append_right _ hm, by rw [hc]; exact hne, by rw [hc]; exact he⟩)
    simp only [Adrs.InRange, Adrs.setType]; omega

theorem path_div (tree k hp : Nat) : tree / 2^(hp*(k+1)) = tree / 2^hp / 2^(hp*k) := by
  rw [Nat.div_div_eq_div_mul, ← Nat.pow_add]
  congr 2
  rw [Nat.mul_succ, Nat.add_comm]

/-- Hypertree tail extraction on the verifier's path. -/
theorem ht_tail_extract_log2 (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hdd : p.d ≤ 256^4) (htop : 2^(p.hp*(p.d-1)) ≤ 256^8)
    (S : Bytes) (hS : S.length = p.d*p.layerBytes) :
    ∀ r layer tree (node : Bytes), layer + r + 1 = p.d → tree < 2^(p.hp*(r+1)) →
      node.length = p.n →
      htRootTail o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1) =
        xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp →
      node = htMsg o p tk prfKey seed layer (tree/2^p.hp) (tree%2^p.hp) ∨
        CanonCollIn o p tk prfKey seed (htRootTailLog o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1)) ∨
        ∃ k, k ≤ r ∧ WotsHit o p tk prfKey seed
          (htRootTailLog o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1))
          (layer+k) (tree/2^(p.hp*k)/2^p.hp) (tree/2^(p.hp*k)%2^p.hp) := by
  intro r
  induction r with
  | zero =>
    intro layer tree node hl ht hnode h
    rw [ht_root_tail_succ] at h
    have hnext : (nextLayer p tree).2 = 0 := Nat.div_eq_of_lt (by simpa using ht)
    have top : ({layer := p.d-1} : Adrs) = {layer := layer, tree := (nextLayer p tree).2} := by
      rw [hnext, show p.d-1 = layer by omega]
    rw [top] at h
    have hleaf := next_layer_leaf_bounded p tree
    rcases xmss_extract_log2 tw pw hseed hn layer _ (by omega)
      (by rw [hnext]; exact Nat.pos_of_ne_zero (by simp)) hlen hH _ hleaf _ _ hnode
      (layer_part_width S hS layer (by omega)) h with e | c | w
    · exact Or.inl e
    · exact Or.inr (Or.inl (c.mono (fun r hr => by
        simp only [htRootTailLog]; exact List.mem_append_left _ hr)))
    · refine Or.inr (Or.inr ⟨0, Nat.le_refl _, ?_⟩)
      simp only [Nat.mul_zero, Nat.pow_zero, Nat.div_one, Nat.add_zero]
      exact w.mono (fun r hr => by simp only [htRootTailLog]; exact List.mem_append_left _ hr)
  | succ r ih =>
    intro layer tree node hl ht hnode h
    rw [ht_root_tail_succ, List.drop_drop, show layer*p.layerBytes+p.layerBytes =
      (layer+1)*p.layerBytes by rw [Nat.succ_mul]] at h
    have split : 2^(p.hp*(r+1+1)) = 2^(p.hp*(r+1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    have hnext : (nextLayer p tree).2 < 2^(p.hp*(r+1)) :=
      (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 (by rw [← split]; exact ht)
    have hnext' : (nextLayer p tree).2 < 256^8 :=
      tree_inRange htop layer _ (by rw [show p.d-1-layer = r+1 by omega]; exact hnext)
    have hleaf := next_layer_leaf_bounded p tree
    have hlog : htRootTailLog o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1+1) =
        xmssPkFromSigLog o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
          ((S.drop (layer*p.layerBytes)).take p.layerBytes) node ++
        htRootTailLog o p tk (layer+1) (nextLayer p tree).2
          (xmssPkFromSig o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
            ((S.drop (layer*p.layerBytes)).take p.layerBytes) node)
          (S.drop ((layer+1)*p.layerBytes)) (r+1) := by
      rw [htRootTailLog, List.drop_drop, show layer*p.layerBytes+p.layerBytes =
        (layer+1)*p.layerBytes by rw [Nat.succ_mul]]
    rw [hlog]
    rcases ih (layer+1) _ _ (by omega) hnext (xmssPkFromSig_width' tw _ _ _ _) h with e | c | w
    · have root : htMsg o p tk prfKey seed (layer+1) ((nextLayer p tree).2/2^p.hp)
          ((nextLayer p tree).2%2^p.hp) =
          xmssNode o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2} 0 p.hp := by
        simp only [htMsg, Nat.add_one_ne_zero, if_false, Nat.add_sub_cancel]
        rw [Nat.mul_comm, Nat.div_add_mod]
      rw [root] at e
      rcases xmss_extract_log2 tw pw hseed hn layer _ (by omega) hnext' hlen hH _ hleaf _ _ hnode
        (layer_part_width S hS layer (by omega)) e with e' | c' | w'
      · exact Or.inl e'
      · exact Or.inr (Or.inl (c'.mono (fun r hr => List.mem_append_left _ hr)))
      · refine Or.inr (Or.inr ⟨0, Nat.zero_le _, ?_⟩)
        simp only [Nat.mul_zero, Nat.pow_zero, Nat.div_one, Nat.add_zero]
        exact w'.mono (fun r hr => List.mem_append_left _ hr)
    · exact Or.inr (Or.inl (c.mono (fun r hr => List.mem_append_right _ hr)))
    · obtain ⟨k, hk, w⟩ := w
      refine Or.inr (Or.inr ⟨k+1, by omega, ?_⟩)
      rw [path_div, show layer + (k+1) = layer + 1 + k by omega]
      exact w.mono (fun r hr => List.mem_append_right _ hr)

/-- Hypertree extraction on the verifier's path. -/
theorem ht_extract_log2 (tw : ∀ x, (o ⟨1,"",tk,x,p.n⟩).length = p.n)
    (pw : ∀ x, x.length = p.n+32 → (o ⟨1,"",prfKey,x,p.n⟩).length = p.n)
    (hseed : seed.length = p.n) (hn : 2*p.n*15 < 4096) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hdd : p.d ≤ 256^4) (htop : 2^(p.hp*(p.d-1)) ≤ 256^8) (hd : 1 ≤ p.d)
    (S msg : Bytes) (tree leaf : Nat) (hS : S.length = p.d*p.layerBytes)
    (hmsg : msg.length = p.n) (htree : tree < 2^(p.hp*(p.d-1))) (hleaf : leaf < 2^p.hp)
    (h : htRoot o p tk S msg tree leaf = xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp) :
    msg = honestForsPk o p tk prfKey seed tree leaf ∨
      CanonCollIn o p tk prfKey seed (htRootLog o p tk S msg tree leaf) ∨
      ∃ k, k < p.d ∧ WotsHit o p tk prfKey seed (htRootLog o p tk S msg tree leaf)
        k ((tree*2^p.hp+leaf)/2^(p.hp*k)/2^p.hp) ((tree*2^p.hp+leaf)/2^(p.hp*k)%2^p.hp) := by
  rw [ht_root_as_tail S msg tree leaf hd hleaf] at h
  have hT : tree*2^p.hp+leaf < 2^(p.hp*(p.d-1+1)) := by
    have e : 2^(p.hp*(p.d-1+1)) = 2^(p.hp*(p.d-1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    rw [e]
    have := Nat.mul_le_mul_right (2^p.hp) (show tree+1 ≤ 2^(p.hp*(p.d-1)) by omega)
    rw [Nat.succ_mul] at this
    omega
  have h' : htRootTail o p tk 0 (tree*2^p.hp+leaf) msg (S.drop (0*p.layerBytes)) (p.d-1+1) =
      xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp := by
    rw [Nat.zero_mul, List.drop_zero, show p.d-1+1 = p.d by omega]; exact h
  rw [ht_root_log_as_tail S msg tree leaf hleaf]
  rcases ht_tail_extract_log2 tw pw hseed hn hlen hH hdd htop S hS (p.d-1) 0 _ msg (by omega) hT hmsg h'
    with e | c | w
  · left
    have hq : (tree*2^p.hp+leaf)/2^p.hp = tree := by
      rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
        Nat.div_eq_of_lt hleaf, Nat.zero_add]
    have hr : (tree*2^p.hp+leaf)%2^p.hp = leaf := by
      rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hleaf]
    rw [e, hq, hr]
    simp only [htMsg, if_true]
  · exact Or.inr (Or.inl c)
  · obtain ⟨k, hk, w⟩ := w
    refine Or.inr (Or.inr ⟨k, by omega, ?_⟩)
    rw [Nat.zero_add] at w
    exact w
end

section
variable (O : Oracle Id) (v : Variant)

/-- The forged WOTS preimage, on the verifier's path. -/
def WotsPath (e msg' sig' : Bytes) : Prop :=
  ∃ k, k < (params v).d ∧ WotsHit O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
    (verifyLog O v (keypairFromExpansion O v e).1 msg' sig') k
    (((splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree*2^(params v).hp +
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf) /
        2^((params v).hp*k) / 2^(params v).hp)
    (((splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree*2^(params v).hp +
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf) /
        2^((params v).hp*k) % 2^(params v).hp)

/-- The forged FORS secret: an unrevealed index whose honest secret the
    verifier hashes into the leaf. -/
def ForsPath (e msg' sig' : Bytes) (signed : List Bytes) : Prop :=
  ∃ i, i < (params v).k ∧
    ¬ RevealedBy O v (keypairFromExpansion O v e).2 signed
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf i
      (forsDigit (params v) (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i) ∧
    thashReq (params v) (expTk O v e)
      {forsAdrs (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
        (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf with
        chain := 0, hash := i*2^(params v).a +
          forsDigit (params v) (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i}
      (forsSecret O (params v) (expPrf O v e) (expSeed v e)
        (forsAdrs (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).tree
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).leaf)
        (i*2^(params v).a +
          forsDigit (params v) (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')).md i))
      ∈ verifyLog O v (keypairFromExpansion O v e).1 msg' sig'
end

/-- Full-signature extraction on the verifier's own positions. -/
theorem forgery_extract_path (O : Oracle Id) (v : Variant) (e : Bytes)
    (he : e.length = 3*(params v).n)
    (tw : ∀ x, (O ⟨1,"",expTk O v e,x,(params v).n⟩).length = (params v).n)
    (pw : ∀ x, x.length = (params v).n+32 →
      (O ⟨1,"",expPrf O v e,x,(params v).n⟩).length = (params v).n)
    (signed : List Bytes) (msg' sig' : Bytes)
    (hv : verify O v (keypairFromExpansion O v e).1 msg' sig' = some true) :
    CanonCollIn O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        (verifyLog O v (keypairFromExpansion O v e).1 msg' sig') ∨
    WotsPath O v e msg' sig' ∨ ForsPath O v e msg' sig' signed ∨
    CoveredBy O v (keypairFromExpansion O v e).2 signed
      (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')) := by
  obtain ⟨hpklen, hsiglen⟩ := accepted_requires_exact_lengths O v _ msg' sig' hv
  have hne : msg'.isEmpty = false := by
    cases ee : msg'.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp ee, verify_empty] at hv; cases hv
  have hseedlen : (expSeed v e).length = (params v).n := by
    simp only [expSeed, slice, List.length_take, List.length_drop, he]; omega
  have hpk : (keypairFromExpansion O v e).1 = List.append (expSeed v e)
      (xmssNode O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        {layer := (params v).d-1} 0 (params v).hp) := rfl
  have htake : (keypairFromExpansion O v e).1.take (params v).n = expSeed v e := by
    rw [hpk]; exact List.take_left' hseedlen
  have hdrop : (keypairFromExpansion O v e).1.drop (params v).n =
      xmssNode O (params v) (expTk O v e) (expPrf O v e) (expSeed v e)
        {layer := (params v).d-1} 0 (params v).hp := by
    rw [hpk]; exact List.drop_left' hseedlen
  have htk : deriveKey O "DSM/sphincs/v2/thash" ((keypairFromExpansion O v e).1.take (params v).n) =
      expTk O v e := by rw [htake]; rfl
  have hacc := (verification_structure O v _ msg' sig' hne hpklen hsiglen).mp hv
  dsimp only at hacc
  rw [htk] at hacc
  replace hacc := hacc.trans hdrop
  have hlogs := (verify_exact O v _ msg' sig' hne hpklen hsiglen).run_empty.2
  rw [htk] at hlogs
  have hlogs' : verifyLog O v (keypairFromExpansion O v e).1 msg' sig' = _ := hlogs
  obtain ⟨hlen, hH, hdd, hMA, hA, hT⟩ := variant_bounds v
  obtain ⟨hd2, hexp⟩ := supported_layer_bounds v
  have hn : 2*(params v).n*15 < 4096 := by have := (checksum_width_three v).2; omega
  have htop : 2^((params v).hp*((params v).d-1)) ≤ 256^8 := by rw [hexp]; exact hT
  have hS : (sig'.drop ((params v).n + (params v).forsBytes)).length =
      (params v).d*(params v).layerBytes := by
    simp only [List.length_drop, hsiglen, Params.sigBytes]; omega
  have htree := digest_tree_bounded (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')
  have hleaf := digest_leaf_bounded (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig')
  have htree' := htree
  rw [← hexp] at htree'
  have hfw : ∀ (a : Adrs) (s md : Bytes),
      (forsPkFromSig O (params v) (expTk O v e) a s md).length = (params v).n := by
    intro a s md; rw [fors_verify_blocks]; exact thash_w tw _ _
  rcases ht_extract_log2 tw pw hseedlen hn hlen hH hdd htop (by omega) _ _ _ _ hS
    (hfw _ _ _) htree' hleaf hacc with hf | c | w
  · rcases fors_extract_log (prfKey := expPrf O v e) (seed := expSeed v e) tw _ _ (Nat.lt_of_lt_of_le htree hT)
      (Nat.lt_of_lt_of_le hleaf hH) hMA hA _ _ hf with c | hs
    · left
      exact c.mono (fun r hr => by
        rw [hlogs']; exact List.mem_append_left _ (List.mem_append_right _ hr))
    · right; right
      by_cases hcov : CoveredBy O v (keypairFromExpansion O v e).2 signed
          (splitDigest (params v) (verifyDigest O v (keypairFromExpansion O v e).1 msg' sig'))
      · exact Or.inr hcov
      · left
        apply Classical.byContradiction
        intro hno
        apply hcov
        intro i hi
        apply Classical.byContradiction
        intro hrev
        apply hno
        refine ⟨i, hi, hrev, ?_⟩
        rw [hlogs']
        exact List.mem_append_left _ (List.mem_append_right _ (fors_leaf_mem' _ _ _ i hi _ (hs i hi)))
  · left
    exact c.mono (fun r hr => by rw [hlogs']; exact List.mem_append_right _ hr)
  · obtain ⟨k, hk, w⟩ := w
    exact Or.inr (Or.inl ⟨k, hk, w.mono (fun r hr => by rw [hlogs']; exact List.mem_append_right _ hr)⟩)

#print axioms forgery_extract_path
end DSM.Sphincs.Security
