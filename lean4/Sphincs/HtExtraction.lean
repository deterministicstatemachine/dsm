-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.XmssExtraction

/- Forgery extraction, stage 2, hypertree. The honest WOTS key at hypertree
   position (layer, tree, leaf) only ever signs one value, `htMsg`: at layer 0
   the honest FORS public key of (tree, leaf), above it the honest root of
   the child XMSS tree (tree*2^hp+leaf) one layer down. Walking a forged
   hypertree signature that reaches the honest public root from the top
   layer down, either every layer's signed value equals the honest one, so
   the forged FORS public key is the honest one, or some layer exhibits an
   XMSS break (`HtBreak`) at an honest address of the key. -/
namespace DSM.Sphincs

/-- The honest FORS address of hypertree leaf (tree, leaf). -/
def forsAdrs (tree leaf : Nat) : Adrs := {tree := tree, kind := 3, keypair := leaf}

/-- The honest FORS public key at (tree, leaf): what the signer computes for
    every digest selecting that position. -/
def honestForsPk (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (tree leaf : Nat) : Bytes :=
  thash o p tk {(forsAdrs tree leaf).setType 4 with keypair := (forsAdrs tree leaf).keypair}
    (((List.range p.k).map fun i =>
      (forsNode o p tk prfKey seed (forsAdrs tree leaf) i p.a : Bytes)).flatten)

/-- The one value the honest WOTS key at hypertree position (layer, tree,
    leaf) signs. -/
def htMsg (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (layer tree leaf : Nat) : Bytes :=
  if layer = 0 then honestForsPk o p tk prfKey seed tree leaf
  else xmssNode o p tk prfKey seed {layer := layer-1, tree := tree*2^p.hp+leaf} 0 p.hp

/-- An XMSS break at an honest hypertree position (layer < d, tree index
    below 2^(hp·(d-1-layer)), leaf below 2^hp), against the value the honest
    key signs there; `S` is the forged hypertree signature. -/
def HtBreak (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (S : Bytes) : Prop :=
  ∃ layer tree leaf, layer < p.d ∧ tree < 2^(p.hp*(p.d-1-layer)) ∧ leaf < 2^p.hp ∧
    XmssBreakAt o p tk prfKey seed {layer := layer, tree := tree} leaf
      (htMsg o p tk prfKey seed layer tree leaf)
      (((S.drop (layer*p.layerBytes)).take p.layerBytes).take (p.len*p.n))

section
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

theorem ht_root_tail_succ (layer tree : Nat) (node sig : Bytes) (r : Nat) :
    htRootTail o p tk layer tree node sig (r+1) =
      htRootTail o p tk (layer+1) (nextLayer p tree).2
        (xmssPkFromSig o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
          (sig.take p.layerBytes) node) (sig.drop p.layerBytes) r := rfl

theorem authWalk_width (widths : OutputWidths o) (a : Adrs) (li gi : Nat) (node auth : Bytes)
    (level r : Nat) (hn : node.length = p.n) :
    (authWalk o p tk a li gi node auth level r).length = p.n := by
  induction r generalizing li gi node level with
  | zero => exact hn
  | succ r ih => exact ih _ _ _ _ (thash_width o widths p tk _ _)

theorem xmssPkFromSig_width (widths : OutputWidths o) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    (xmssPkFromSig o p tk a idx sig msg).length = p.n :=
  authWalk_width widths _ _ _ _ _ _ _ (wotsPkFromSig_width widths _ _ _)

theorem htMsg_width (widths : OutputWidths o) (layer tree leaf : Nat) :
    (htMsg o p tk prfKey seed layer tree leaf).length = p.n := by
  unfold htMsg
  split
  · exact thash_width o widths p tk _ _
  · exact xmss_node_width o widths p tk prfKey seed _ _ _

theorem layer_part_width (S : Bytes) (hS : S.length = p.d*p.layerBytes) (layer : Nat)
    (hl : layer < p.d) : ((S.drop (layer*p.layerBytes)).take p.layerBytes).length = p.layerBytes := by
  have h := Nat.mul_le_mul_right p.layerBytes (show layer+1 ≤ p.d by omega)
  rw [Nat.succ_mul] at h
  simp only [List.length_take, List.length_drop, hS]
  omega

/-- The honest signer's messages, made explicit: the FORS public key it
    signs at layer 0 is `honestForsPk` for every digest at (tree, leaf). -/
theorem honest_fors_pk (widths : OutputWidths o) (tree leaf : Nat) (md : Bytes) :
    forsPkFromSig o p tk (forsAdrs tree leaf) (forsSign o p tk prfKey seed (forsAdrs tree leaf) md) md =
      honestForsPk o p tk prfKey seed tree leaf :=
  fors_sign_correct o widths p tk prfKey seed _ md

/-- ...and above layer 0 the value passed up (and signed by the next layer)
    is the honest XMSS root, i.e. `htMsg` of the next position. -/
theorem honest_tail_message (widths : OutputWidths o) (layer tree : Nat) (node : Bytes)
    (count : Nat) (hc : count ≠ 0) :
    htSignTail (m := Id) o p tk prfKey seed layer tree node (count+1) =
      List.append (xmssSign (m := Id) o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2}
        (nextLayer p tree).1 node)
      (htSignTail (m := Id) o p tk prfKey seed (layer+1) (nextLayer p tree).2
        (htMsg o p tk prfKey seed (layer+1) ((nextLayer p tree).2/2^p.hp)
          ((nextLayer p tree).2%2^p.hp)) count) := by
  rw [ht_sign_tail_step o p tk prfKey seed layer tree count node hc]
  dsimp only
  rw [xmss_sign_correct o widths, next_layer_leaf_quotient]
  simp only [htMsg, Nat.add_one_ne_zero, if_false, Nat.add_sub_cancel]
  rw [Nat.mul_comm, Nat.div_add_mod]
  rfl

/-- Hypertree extraction over the upper part of a forged signature `S`
    (layers `layer` … d-1), by induction on the number of layers. -/
theorem ht_tail_extract (widths : OutputWidths o) (hn : 2*p.n*15 < 4096)
    (S : Bytes) (hS : S.length = p.d*p.layerBytes) :
    ∀ r layer tree (node : Bytes), layer + r + 1 = p.d → tree < 2^(p.hp*(r+1)) →
      node.length = p.n →
      htRootTail o p tk layer tree node (S.drop (layer*p.layerBytes)) (r+1) =
        xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp →
      node = htMsg o p tk prfKey seed layer (tree/2^p.hp) (tree%2^p.hp) ∨
        HtBreak o p tk prfKey seed S := by
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
    rcases xmss_forgery_extract widths hn _ _ hleaf _ _ _ (htMsg_width widths _ _ _) hnode
      (layer_part_width S hS layer (by omega)) h with e | b
    · exact Or.inl e
    · refine Or.inr ⟨layer, _, _, by omega, ?_, hleaf, b⟩
      rw [hnext]; exact Nat.pos_of_ne_zero (by simp)
  | succ r ih =>
    intro layer tree node hl ht hnode h
    rw [ht_root_tail_succ, List.drop_drop, show layer*p.layerBytes+p.layerBytes =
      (layer+1)*p.layerBytes by rw [Nat.succ_mul]] at h
    have split : 2^(p.hp*(r+1+1)) = 2^(p.hp*(r+1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    have hnext : (nextLayer p tree).2 < 2^(p.hp*(r+1)) :=
      (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 (by rw [← split]; exact ht)
    have hleaf := next_layer_leaf_bounded p tree
    rcases ih (layer+1) _ _ (by omega) hnext (xmssPkFromSig_width widths _ _ _ _) h with e | b
    · have root : htMsg o p tk prfKey seed (layer+1) ((nextLayer p tree).2/2^p.hp)
          ((nextLayer p tree).2%2^p.hp) =
          xmssNode o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2} 0 p.hp := by
        simp only [htMsg, Nat.add_one_ne_zero, if_false, Nat.add_sub_cancel]
        rw [Nat.mul_comm, Nat.div_add_mod]
      rw [root] at e
      rcases xmss_forgery_extract widths hn _ _ hleaf _ _ _ (htMsg_width widths _ _ _) hnode
        (layer_part_width S hS layer (by omega)) e with e' | b'
      · exact Or.inl e'
      · refine Or.inr ⟨layer, _, _, by omega, ?_, hleaf, b'⟩
        rw [show p.d-1-layer = r+1 by omega]; exact hnext
    · exact Or.inr b

theorem ht_root_as_tail (S msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) (hleaf : leaf < 2^p.hp) :
    htRoot o p tk S msg tree leaf = htRootTail o p tk 0 (tree*2^p.hp+leaf) msg S p.d := by
  have hnl : nextLayer p (tree*2^p.hp+leaf) = (leaf, tree) := by
    simp only [nextLayer, Prod.mk.injEq]
    constructor
    · rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hleaf]
    · rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
        Nat.div_eq_of_lt hleaf, Nat.zero_add]
  rw [show p.d = (p.d-1)+1 by omega, ht_root_tail_succ, hnl]
  rfl

/-- Hypertree extraction: a forged hypertree signature `S` (d layers) of an
    n-byte value `msg` at hypertree index (tree, leaf) that reconstructs the
    honest public root either signs the honest FORS public key of (tree,
    leaf), or exhibits an XMSS break at an honest hypertree position. -/
theorem ht_forgery_extract (widths : OutputWidths o) (hn : 2*p.n*15 < 4096) (hd : 1 ≤ p.d)
    (S msg : Bytes) (tree leaf : Nat) (hS : S.length = p.d*p.layerBytes)
    (hmsg : msg.length = p.n) (htree : tree < 2^(p.hp*(p.d-1))) (hleaf : leaf < 2^p.hp)
    (h : htRoot o p tk S msg tree leaf = xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp) :
    msg = honestForsPk o p tk prfKey seed tree leaf ∨ HtBreak o p tk prfKey seed S := by
  rw [ht_root_as_tail S msg tree leaf hd hleaf] at h
  have hT : tree*2^p.hp+leaf < 2^(p.hp*(p.d-1+1)) := by
    have e : 2^(p.hp*(p.d-1+1)) = 2^(p.hp*(p.d-1))*2^p.hp := by
      rw [← Nat.pow_add]; congr 1
    rw [e]
    have := Nat.mul_le_mul_right (2^p.hp) (show tree+1 ≤ 2^(p.hp*(p.d-1)) by omega)
    rw [Nat.succ_mul] at this
    omega
  have hq : (tree*2^p.hp+leaf)/2^p.hp = tree := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide)),
      Nat.div_eq_of_lt hleaf, Nat.zero_add]
  have hr : (tree*2^p.hp+leaf)%2^p.hp = leaf := by
    rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hleaf]
  have h' : htRootTail o p tk 0 (tree*2^p.hp+leaf) msg (S.drop (0*p.layerBytes)) (p.d-1+1) =
      xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp := by
    rw [Nat.zero_mul, List.drop_zero, show p.d-1+1 = p.d by omega]; exact h
  rcases ht_tail_extract widths hn S hS (p.d-1) 0 _ msg (by omega) hT hmsg h' with e | b
  · left
    rw [e, hq, hr]
    simp only [htMsg, if_true]
  · exact Or.inr b
end

#print axioms honest_fors_pk
#print axioms honest_tail_message
#print axioms ht_tail_extract
#print axioms ht_forgery_extract
end DSM.Sphincs
