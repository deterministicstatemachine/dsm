-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Proofs
namespace DSM.Sphincs
 theorem gather {α : Type} (xs : List α) (f : α → Bytes) (acc : Bytes) :
 (forIn xs acc (fun x a => (pure (.yield (a++f x)) : Id (ForInStep Bytes))) : Id Bytes) = acc++(xs.map f).flatten := by
 induction xs generalizing acc with
 | nil => simp [List.forIn_nil,Id.instMonad]
 | cons x xs ih =>
   simp only [List.forIn_cons,Id.instMonad,bind,List.map_cons,List.flatten_cons]
   simpa [Id.instMonad,pure,List.append_assoc] using ih (acc++f x)
 theorem gather_raw {α : Type} (xs : List α) (f : α → Bytes) (acc : Bytes) :
 (forIn xs acc (fun x a => (.yield (a++f x) : Id (ForInStep Bytes))) : Id Bytes) =
   acc++(xs.map f).flatten := by
  simpa only [Id.instMonad,pure] using gather xs f acc
 theorem wots_sign_blocks (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (msg : Bytes) :
 wotsSign o p tk prfKey seed a msg =
 ((wotsDigits p msg).zipIdx.map fun (digit,i) => (chain o p tk {a with chain := i}
 (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 digit : Bytes)).flatten := by
 simp only [wotsSign,Id.instMonad,bind,pure]
 exact gather _ _ []

 theorem uniform_blocks_length (blocks : List Bytes) (n : Nat)
    (widths : ∀ block ∈ blocks, block.length = n) : blocks.flatten.length = blocks.length*n := by
  induction blocks with
  | nil => simp
  | cons block rest ih =>
    have head := widths block (by simp)
    have tail := ih (fun b hb => widths b (by simp [hb]))
    simp only [List.flatten_cons,List.length_append,List.length_cons]
    rw [head,tail,Nat.add_mul]
    omega

 theorem uniform_block_at (blocks : List Bytes) (n i : Nat)
    (widths : ∀ block ∈ blocks, block.length = n) (bound : i < blocks.length) :
    slice blocks.flatten (i*n) n = blocks[i] := by
  induction blocks generalizing i with
  | nil => simp at bound
  | cons block rest ih =>
    have head := widths block (by simp)
    have tail : ∀ b ∈ rest, b.length = n := fun b hb => widths b (by simp [hb])
    cases i with
    | zero => simp [slice,head]
    | succ i =>
      have small : i < rest.length := by simpa using bound
      simp only [List.flatten_cons,slice,Nat.succ_mul,List.drop_append,head]
      have gone : block.drop (i*n+n) = [] := List.drop_eq_nil_of_le (by rw [head]; omega)
      rw [gone]
      simp only [List.nil_append,Nat.add_sub_cancel]
      simpa [slice] using ih i tail small
 theorem wots_pkgen_blocks (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes) (a : Adrs) :
 wotsPkgen o p tk prfKey seed a = wotsCompress o p tk a
 ((List.range p.len).map fun i => (chain o p tk {a with chain := i}
 (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 15 : Bytes)).flatten := by
 simp only [wotsPkgen,Id.instMonad,bind,pure]
 congr 1
 exact gather _ _ []

 theorem wots_verify_blocks (o : Oracle Id) (p : Params) (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
 wotsPkFromSig o p tk a sig msg = wotsCompress o p tk a
 ((wotsDigits p msg).zipIdx.map fun (digit,i) =>
 (chain o p tk {a with chain := i} (slice sig (i*p.n) p.n) digit (15-digit) : Bytes)).flatten := by
 simp only [wotsPkFromSig,Id.instMonad,bind,pure]
 congr 1
 exact gather _ _ []

 theorem serialized_map_block {α : Type} (items : List α) (block : α → Bytes) (n i : Nat)
    (widths : ∀ item ∈ items, (block item).length = n) (bound : i < items.length) :
    slice (items.map block).flatten (i*n) n = block items[i] := by
  have result := uniform_block_at (items.map block) n i
    (by intro b hb; obtain ⟨x,hx,rfl⟩ := List.mem_map.mp hb; exact widths x hx)
    (by simpa using bound)
  simpa using result

 theorem wots_sign_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (msg : Bytes) :
    (wotsSign o p tk prfKey seed a msg).length = p.len*p.n := by
  rw [wots_sign_blocks]
  have result := uniform_blocks_length
    ((wotsDigits p msg).zipIdx.map fun (digit,i) =>
      (chain o p tk {a with chain := i}
       (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 digit : Bytes)) p.n
    (by
      intro b hb
      obtain ⟨⟨digit,i⟩,_,rfl⟩ := List.mem_map.mp hb
      exact chain_width o widths p tk _ _ 0 digit (prf_width o widths p prfKey seed _))
  simpa [wots_digit_count] using result

set_option maxHeartbeats 800000 in
 theorem wots_sign_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (msg : Bytes) :
    wotsPkFromSig o p tk a (wotsSign o p tk prfKey seed a msg) msg =
    wotsPkgen o p tk prfKey seed a := by
  let digits := (wotsDigits p msg).zipIdx
  let part : Nat × Nat → Bytes := fun (digit,i) =>
    chain o p tk {a with chain := i}
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 digit
  let top : Nat → Bytes := fun i =>
    chain o p tk {a with chain := i}
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 15
  have partWidths : ∀ x ∈ digits, (part x).length = p.n := by
    intro x _
    exact chain_width o widths p tk _ _ 0 x.1 (prf_width o widths p prfKey seed _)
  have mapTops : digits.map (fun x =>
      (chain o p tk {a with chain := x.2}
       (slice (digits.map part).flatten (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)) =
      digits.map (fun x => top x.2) := by
    apply List.map_congr_left
    intro x hx
    have lookup := List.mem_zipIdx_iff_getElem?.mp hx
    obtain ⟨bound,value⟩ := List.getElem?_eq_some_iff.mp lookup
    have indexed : digits[x.2]'(by simpa [digits] using bound) = x := by
      simp [digits,List.getElem_zipIdx,value]
    have recovered := serialized_map_block digits part p.n x.2 partWidths
      (by simpa [digits] using bound)
    rw [indexed] at recovered
    rw [recovered]
    exact wots_generated_digit_recovers o p tk _ _ msg x.1 (List.mem_of_getElem? lookup)
  have indexList : digits.map Prod.snd = List.range p.len := by
    simp [digits,List.zipIdx_map_snd,wots_digit_count,List.range_eq_range']
  rw [wots_verify_blocks,wots_sign_blocks,wots_pkgen_blocks]
  change wotsCompress o p tk a (digits.map (fun x =>
    chain o p tk {a with chain := x.2}
      (slice (digits.map part).flatten (x.2*p.n) p.n) x.1 (15-x.1))).flatten = _
  rw [mapTops]
  have topMap : digits.map (fun x => top x.2) = (List.range p.len).map top := by
    simpa only [List.map_map,Function.comp_def] using congrArg (List.map top) indexList
  exact congrArg (fun blocks : List Bytes => wotsCompress o p tk a blocks.flatten) topMap

 theorem xmss_sign_blocks (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (index : Nat) (msg : Bytes) :
    xmssSign o p tk prfKey seed a index msg =
      List.append (wotsSign (m := Id) o p tk prfKey seed {a.setType 0 with keypair := index} msg)
      (((List.range p.hp).map fun j =>
        (xmssNode o p tk prfKey seed a (Nat.xor (index/2^j) 1) j : Bytes)).flatten) := by
  simp only [xmssSign,Id.instMonad,bind,pure]
  congr 1
  exact gather _ _ []

 theorem xmss_auth_bytes (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (index j : Nat) (bound : j < p.hp) :
    slice ((List.range p.hp).map fun level =>
      (xmssNode o p tk prfKey seed a (Nat.xor (index/2^level) 1) level : Bytes)).flatten
      (j*p.n) p.n = xmssNode o p tk prfKey seed a (siblingIndex (index/2^j)) j := by
  have extracted := serialized_map_block (List.range p.hp)
    (fun level => (xmssNode o p tk prfKey seed a (Nat.xor (index/2^level) 1) level : Bytes))
    p.n j (fun _ _ => xmss_node_width o widths p tk prfKey seed a _ _) (by simpa using bound)
  simpa [xor_one_is_sibling] using extracted

set_option maxHeartbeats 800000 in
 theorem xmss_sign_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (index : Nat) (msg : Bytes) :
    xmssPkFromSig o p tk a index (xmssSign o p tk prfKey seed a index msg) msg =
      xmssNode o p tk prfKey seed a (index/2^p.hp) p.hp := by
  let wa := {a.setType 0 with keypair := index}
  let auth : Bytes := ((List.range p.hp).map fun j =>
    (xmssNode o p tk prfKey seed a (Nat.xor (index/2^j) 1) j : Bytes)).flatten
  let ws : Bytes := wotsSign o p tk prfKey seed wa msg
  have width := wots_sign_width o widths p tk prfKey seed wa msg
  rw [xmss_sign_blocks]
  simp only [xmssPkFromSig,Id.instMonad,bind]
  change authRoot o p tk (a.setType 2) index index
    (wotsPkFromSig o p tk wa
      ((ws++auth).take (p.len*p.n)) msg)
    ((ws++auth).drop (p.len*p.n)) p.hp = _
  have wsWidth : ws.length = p.len*p.n := width
  rw [← wsWidth,List.take_left,List.drop_left]
  change authRoot o p tk (a.setType 2) index index
    (wotsPkFromSig o p tk wa (wotsSign o p tk prfKey seed wa msg) msg) auth p.hp = _
  rw [wots_sign_correct o widths]
  exact xmss_signer_tree_path o p tk prfKey seed a index _
    (fun j hj => xmss_auth_bytes o widths p tk prfKey seed a index j hj)

def forsPart (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (entry : Nat × Nat) : Bytes :=
  List.append (forsSecret (m := Id) o p prfKey seed a (entry.2*2^p.a+entry.1))
    (((List.range p.a).map fun j =>
      (forsNode o p tk prfKey seed a (entry.2*2^(p.a-j)+Nat.xor (entry.1/2^j) 1) j : Bytes)).flatten)

 theorem fors_sign_blocks (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (md : Bytes) :
    forsSign o p tk prfKey seed a md =
      ((base2b md p.a p.k).zipIdx.map (forsPart o p tk prfKey seed a)).flatten := by
  simp only [forsSign,Id.instMonad,bind,pure,gather_raw,List.append_assoc]
  rfl

 theorem fors_part_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (entry : Nat × Nat) :
    (forsPart o p tk prfKey seed a entry).length = (p.a+1)*p.n := by
  have authWidth := uniform_blocks_length
    ((List.range p.a).map fun j =>
      (forsNode o p tk prfKey seed a (entry.2*2^(p.a-j)+Nat.xor (entry.1/2^j) 1) j : Bytes)) p.n
    (by intro b hb; obtain ⟨j,_,rfl⟩ := List.mem_map.mp hb
        exact fors_node_width o widths p tk prfKey seed a _ _)
  simp only [List.length_map,List.length_range] at authWidth
  let sk : Bytes := forsSecret o p prfKey seed a (entry.2*2^p.a+entry.1)
  let auth : Bytes := ((List.range p.a).map fun j => (forsNode o p tk prfKey seed a
    (entry.2*2^(p.a-j)+Nat.xor (entry.1/2^j) 1) j : Bytes)).flatten
  change (sk++auth).length = _
  rw [List.length_append]
  have aw : auth.length = p.a*p.n := authWidth
  rw [aw]
  have secretWidth := prf_width o widths p prfKey seed
    {a.setType 6 with keypair := a.keypair,hash := entry.2*2^p.a+entry.1}
  have sw : sk.length = p.n := secretWidth
  rw [sw]
  change p.n + p.a*p.n = (p.a+1)*p.n
  rw [Nat.add_mul]
  omega

 theorem even_offset_sibling (offset x : Nat) (even : offset%2 = 0) :
    offset+siblingIndex x = siblingIndex (offset+x) := by
  by_cases he : x%2 = 0
  · simp [siblingIndex,Nat.add_mod,even,he,Nat.add_assoc]
  · simp [siblingIndex,Nat.add_mod,even,he]
    omega

 theorem fors_offset_sibling (tree leaf height level : Nat) (within : level < height) :
    tree*2^(height-level)+Nat.xor (leaf/2^level) 1 =
    siblingIndex ((tree*2^height+leaf)/2^level) := by
  have power : 2^height = 2^(height-level)*2^level := by
    rw [← Nat.pow_add]
    congr 1
    omega
  have div : (tree*2^height+leaf)/2^level = tree*2^(height-level)+leaf/2^level := by
    rw [power,← Nat.mul_assoc,Nat.add_comm,Nat.add_mul_div_right _ _ (Nat.pow_pos (by decide))]
    omega
  rw [div,xor_one_is_sibling]
  have even : (tree*2^(height-level))%2 = 0 := by
    obtain ⟨r,hr⟩ := Nat.exists_eq_succ_of_ne_zero (show height-level ≠ 0 by omega)
    rw [hr,Nat.pow_succ,← Nat.mul_assoc]
    simp
  exact even_offset_sibling _ _ even

 theorem fors_part_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (tree leaf : Nat) (bound : leaf < 2^p.a) :
    let part := forsPart o p tk prfKey seed a (leaf,tree)
    authRoot o p tk a leaf (tree*2^p.a+leaf)
      (thash o p tk {a with chain := 0,hash := tree*2^p.a+leaf} (part.take p.n))
      (part.drop p.n) p.a = forsNode o p tk prfKey seed a tree p.a := by
  have secretWidth := prf_width o widths p prfKey seed
    {a.setType 6 with keypair := a.keypair,hash := tree*2^p.a+leaf}
  let sk : Bytes := forsSecret o p prfKey seed a (tree*2^p.a+leaf)
  let auth : Bytes := ((List.range p.a).map fun j => (forsNode o p tk prfKey seed a
    (tree*2^(p.a-j)+Nat.xor (leaf/2^j) 1) j : Bytes)).flatten
  change authRoot o p tk a leaf (tree*2^p.a+leaf)
    (thash o p tk {a with chain := 0,hash := tree*2^p.a+leaf} ((sk++auth).take p.n))
    ((sk++auth).drop p.n) p.a = _
  have fsWidth : (forsSecret o p prfKey seed a (tree*2^p.a+leaf)).length = p.n := secretWidth
  have skWidth : sk.length = p.n := fsWidth
  rw [← skWidth,List.take_left,List.drop_left]
  apply fors_signer_tree_path o p tk prfKey seed a tree leaf _ bound
  intro j hj
  have extracted := serialized_map_block (List.range p.a)
    (fun level => (forsNode o p tk prfKey seed a
      (tree*2^(p.a-level)+Nat.xor (leaf/2^level) 1) level : Bytes)) p.n j
    (fun _ _ => fors_node_width o widths p tk prfKey seed a _ _) (by simpa using hj)
  simpa [fors_offset_sibling tree leaf p.a j hj] using extracted

 theorem serialized_indexed_block {α : Type} (items : List α) (block : α × Nat → Bytes)
    (n : Nat) (entry : α × Nat) (member : entry ∈ items.zipIdx)
    (widths : ∀ x ∈ items.zipIdx, (block x).length = n) :
    slice (items.zipIdx.map block).flatten (entry.2*n) n = block entry := by
  have lookup := List.mem_zipIdx_iff_getElem?.mp member
  obtain ⟨bound,value⟩ := List.getElem?_eq_some_iff.mp lookup
  have indexed : items.zipIdx[entry.2]'(by simpa using bound) = entry := by
    simp [List.getElem_zipIdx,value]
  have extracted := serialized_map_block items.zipIdx block n entry.2 widths (by simpa using bound)
  rw [indexed] at extracted
  exact extracted

 theorem fors_verify_blocks (o : Oracle Id) (p : Params) (tk : Bytes)
    (a : Adrs) (sig md : Bytes) :
    forsPkFromSig o p tk a sig md = thash o p tk {a.setType 4 with keypair := a.keypair}
      (((base2b md p.a p.k).zipIdx.map fun x =>
        (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
          (thash o p tk {a with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice sig (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes)).flatten) := by
  simp only [forsPkFromSig,Id.instMonad,bind,pure]
  congr 1
  exact gather _ _ []

 theorem fors_sign_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (md : Bytes) :
    forsPkFromSig o p tk a (forsSign o p tk prfKey seed a md) md =
      thash o p tk {a.setType 4 with keypair := a.keypair}
        (((List.range p.k).map fun i => (forsNode o p tk prfKey seed a i p.a : Bytes)).flatten) := by
  let digits := (base2b md p.a p.k).zipIdx
  let parts := forsPart o p tk prfKey seed a
  let top : Nat → Bytes := fun i => forsNode o p tk prfKey seed a i p.a
  have partWidths : ∀ x ∈ digits, (parts x).length = (p.a+1)*p.n := by
    intro x _
    exact fors_part_width o widths p tk prfKey seed a x
  have roots : digits.map (fun x => (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
        (thash o p tk {a with chain := 0,hash := x.2*2^p.a+x.1}
          ((slice (digits.map parts).flatten (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
        ((slice (digits.map parts).flatten (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes)) =
      digits.map (fun x => top x.2) := by
    apply List.map_congr_left
    intro x hx
    have block := serialized_indexed_block (base2b md p.a p.k) parts ((p.a+1)*p.n) x hx partWidths
    rw [block]
    have lookup := List.mem_zipIdx_iff_getElem?.mp hx
    exact fors_part_correct o widths p tk prfKey seed a x.2 x.1
      (base2b_digit_bound md p.a p.k x.1 (List.mem_of_getElem? lookup))
  have indexList : digits.map Prod.snd = List.range p.k := by
    simp [digits,List.zipIdx_map_snd,base2b,List.range_eq_range']
  rw [fors_verify_blocks,fors_sign_blocks]
  change thash o p tk {a.setType 4 with keypair := a.keypair}
    (digits.map (fun x => (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
        (thash o p tk {a with chain := 0,hash := x.2*2^p.a+x.1}
          ((slice (digits.map parts).flatten (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
        ((slice (digits.map parts).flatten (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n) p.a : Bytes))).flatten = _
  rw [roots]
  have topMap : digits.map (fun x => top x.2) = (List.range p.k).map top := by
    simpa only [List.map_map,Function.comp_def] using congrArg (List.map top) indexList
  exact congrArg (fun blocks : List Bytes => thash o p tk {a.setType 4 with keypair := a.keypair} blocks.flatten) topMap

 theorem xmss_sign_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (index : Nat) (msg : Bytes) :
    (xmssSign o p tk prfKey seed a index msg).length = p.layerBytes := by
  let ws : Bytes := wotsSign o p tk prfKey seed {a.setType 0 with keypair := index} msg
  let auth : Bytes := ((List.range p.hp).map fun j =>
    (xmssNode o p tk prfKey seed a (Nat.xor (index/2^j) 1) j : Bytes)).flatten
  rw [xmss_sign_blocks]
  change (ws++auth).length = _
  have sw : ws.length = p.len*p.n := wots_sign_width o widths p tk prfKey seed _ msg
  have aw : auth.length = p.hp*p.n := by
    have h := uniform_blocks_length
      ((List.range p.hp).map fun j =>
        (xmssNode o p tk prfKey seed a (Nat.xor (index/2^j) 1) j : Bytes)) p.n
      (by intro b hb; obtain ⟨j,_,rfl⟩ := List.mem_map.mp hb
          exact xmss_node_width o widths p tk prfKey seed a _ _)
    simpa [auth] using h
  simp only [List.length_append,sw,aw,Params.layerBytes,Nat.add_mul]

 theorem ht_sign_tail_step (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)
    (layer tree count : Nat) (node : Bytes) (nonzero : count ≠ 0) :
    htSignTail o p tk prfKey seed layer tree node (count+1) =
      let leaf := (nextLayer p tree).1
      let next := (nextLayer p tree).2
      let a : Adrs := {layer := layer,tree := next}
      let part : Bytes := xmssSign o p tk prfKey seed a leaf node
      let root : Bytes := xmssPkFromSig o p tk a leaf part node
      let tail : Bytes := htSignTail o p tk prfKey seed (layer+1) next root count
      part ++ tail := by
  rw [htSignTail]
  simp only [if_neg nonzero,Id.instMonad,bind,pure]

 theorem ht_sign_tail_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (layer tree : Nat) (node : Bytes) (count : Nat) :
    (htSignTail o p tk prfKey seed layer tree node count).length = count*p.layerBytes := by
  induction count generalizing layer tree node with
  | zero => simp [htSignTail,Id.instMonad]
  | succ count ih =>
    by_cases hz : count = 0
    · subst count
      simp [htSignTail,Id.instMonad,xmss_sign_width o widths]
    · rw [ht_sign_tail_step o p tk prfKey seed layer tree count node hz]
      dsimp only
      rw [List.length_append,xmss_sign_width o widths,ih,Nat.succ_mul]
      omega

 theorem ht_root_tail_cons (o : Oracle Id) (p : Params) (tk : Bytes)
    (layer tree count : Nat) (node part tail : Bytes) (width : part.length = p.layerBytes) :
    htRootTail o p tk layer tree node (part++tail) (count+1) =
      htRootTail o p tk (layer+1) (nextLayer p tree).2
        (xmssPkFromSig o p tk {layer := layer,tree := (nextLayer p tree).2}
          (nextLayer p tree).1 part node) tail count := by
  simp only [htRootTail,Id.instMonad,bind]
  rw [← width,List.take_left,List.drop_left]

 theorem next_layer_leaf_quotient (p : Params) (tree : Nat) :
    (nextLayer p tree).1/2^p.hp = 0 := by
  exact Nat.div_eq_of_lt (next_layer_leaf_bounded p tree)

 theorem ht_tail_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (layer tree : Nat) (node : Bytes) (count : Nat) :
    htRootTail o p tk layer tree node
      (htSignTail o p tk prfKey seed layer tree node (count+1)) (count+1) =
      xmssNode o p tk prfKey seed
        {layer := layer+count,tree := tree/2^(p.hp*(count+1))} 0 p.hp := by
  induction count generalizing layer tree node with
  | zero =>
    let part : Bytes := xmssSign o p tk prfKey seed
      {layer := layer,tree := (nextLayer p tree).2} (nextLayer p tree).1 node
    have width := xmss_sign_width o widths p tk prfKey seed
      {layer := layer,tree := (nextLayer p tree).2} (nextLayer p tree).1 node
    rw [htSignTail]
    simp only [Id.instMonad,bind,pure]
    change htRootTail o p tk layer tree node part 1 = _
    have h := ht_root_tail_cons o p tk layer tree 0 node part [] width
    simp only [List.append_nil] at h
    rw [h]
    change xmssPkFromSig o p tk _ _ (xmssSign o p tk prfKey seed _ _ node) node = _
    rw [xmss_sign_correct o widths,next_layer_leaf_quotient]
    simp [nextLayer]
  | succ count ih =>
    rw [ht_sign_tail_step o p tk prfKey seed layer tree (count+1) node (by omega)]
    dsimp only
    rw [ht_root_tail_cons o p tk _ _ _ _ _ _ (xmss_sign_width o widths p tk prfKey seed _ _ node)]
    rw [ih]
    congr 2
    · omega
    · simp only [nextLayer,Nat.div_div_eq_div_mul]
      congr 1
      rw [← Nat.pow_add]
      congr 1
      simp [Nat.mul_add,Nat.add_comm]

 theorem ht_sign_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (msg : Bytes) (tree leaf : Nat) (positive : 0 < p.d) :
    (htSign o p tk prfKey seed msg tree leaf).length = p.d*p.layerBytes := by
  simp only [htSign,Id.instMonad,bind,pure,List.length_append]
  rw [xmss_sign_width o widths,ht_sign_tail_width o widths]
  have total : p.d = (p.d-1)+1 := by omega
  calc
    p.layerBytes+(p.d-1)*p.layerBytes = ((p.d-1)+1)*p.layerBytes := by
      rw [Nat.add_mul]; simp [Nat.add_comm]
    _ = p.d*p.layerBytes := by rw [← total]

 theorem ht_sign_correct (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (msg : Bytes) (tree leaf : Nat)
    (layers : 2 ≤ p.d) (bounded : tree < 2^(p.hp*(p.d-1))) :
    htRoot o p tk (htSign o p tk prfKey seed msg tree leaf) msg tree leaf =
      xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp := by
  let first : Bytes := xmssSign o p tk prfKey seed {tree := tree} leaf msg
  let root : Bytes := xmssPkFromSig o p tk {tree := tree} leaf first msg
  let tail : Bytes := htSignTail o p tk prfKey seed 1 tree root (p.d-1)
  have fw : first.length = p.layerBytes := xmss_sign_width o widths p tk prfKey seed _ leaf msg
  simp only [htSign,htRoot,Id.instMonad,bind,pure]
  change htRootTail o p tk 1 tree
    (xmssPkFromSig o p tk {tree := tree} leaf ((first++tail).take p.layerBytes) msg)
    ((first++tail).drop p.layerBytes) (p.d-1) = _
  rw [← fw,List.take_left,List.drop_left]
  change htRootTail o p tk 1 tree root (htSignTail o p tk prfKey seed 1 tree root (p.d-1)) (p.d-1) = _
  have count : p.d-1 = (p.d-2)+1 := by omega
  rw [count,ht_tail_correct o widths]
  have topLayer : 1+(p.d-2) = p.d-1 := by omega
  have topTree : tree/2^(p.hp*((p.d-2)+1)) = 0 := by
    rw [← count]
    exact Nat.div_eq_of_lt bounded
  rw [topLayer,topTree,← count]

 theorem supported_layer_bounds (v : Variant) :
    2 ≤ (params v).d ∧ (params v).hp*((params v).d-1) = (params v).h-(params v).hp := by
  cases v <;> decide

 theorem supported_ht_sign_correct (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (tk prfKey seed msg digest : Bytes) :
    htRoot o (params v) tk
      (htSign o (params v) tk prfKey seed msg (splitDigest (params v) digest).tree
        (splitDigest (params v) digest).leaf) msg (splitDigest (params v) digest).tree
        (splitDigest (params v) digest).leaf =
      xmssNode o (params v) tk prfKey seed {layer := (params v).d-1} 0 (params v).hp := by
  obtain ⟨layers,exponent⟩ := supported_layer_bounds v
  apply ht_sign_correct o widths _ tk prfKey seed msg _ _ layers
  rw [exponent]
  exact digest_tree_bounded _ digest

 theorem fors_sign_width (o : Oracle Id) (widths : OutputWidths o)
    (p : Params) (tk prfKey seed : Bytes) (a : Adrs) (md : Bytes) :
    (forsSign o p tk prfKey seed a md).length = p.forsBytes := by
  rw [fors_sign_blocks]
  have result := uniform_blocks_length
    ((base2b md p.a p.k).zipIdx.map (forsPart o p tk prfKey seed a)) ((p.a+1)*p.n)
    (by intro b hb; obtain ⟨x,_,rfl⟩ := List.mem_map.mp hb
        exact fors_part_width o widths p tk prfKey seed a x)
  simpa [base2b,Params.forsBytes,Nat.mul_assoc] using result

-- A valid stored key has the exact layout and the root generated from its seeds.
-- This is a functional invariant; it makes no secrecy or entropy assertion.
def ValidSecretKey (o : Oracle Id) (v : Variant) (sk : Bytes) : Prop :=
  let p := params v
  let seed := slice sk (2*p.n) p.n
  sk.length = 4*p.n ∧ sk.drop (3*p.n) =
    xmssNode o p (deriveKey o "DSM/sphincs/v2/thash" seed)
      (deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)) seed {layer := p.d-1} 0 p.hp

 theorem signer_correct (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (sk msg : Bytes) (valid : ValidSecretKey o v sk)
    (nonempty : msg.isEmpty = false) :
    ∃ sig : Bytes, sign o v sk msg = some sig ∧
      sig.length = (params v).sigBytes ∧
      verify o v (slice sk (2*(params v).n) (params v).n ++ sk.drop (3*(params v).n)) msg sig = some true := by
  let p := params v
  let seed := slice sk (2*p.n) p.n
  let root := sk.drop (3*p.n)
  let tk : Bytes := deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey : Bytes := deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)
  let msgKey : Bytes := deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk p.n p.n)
  let r : Bytes := keyed o p.n msgKey (seed++msg)
  let digest : Bytes := hmsg o p r seed root msg
  let indices := splitDigest p digest
  let a : Adrs := {tree := indices.tree,kind := 3,keypair := indices.leaf}
  let fs : Bytes := forsSign o p tk prfKey seed a indices.md
  let fpk : Bytes := forsPkFromSig o p tk a fs indices.md
  let hs : Bytes := htSign o p tk prfKey seed fpk indices.tree indices.leaf
  have keyLen : sk.length = 4*p.n := valid.1
  have rootEq : root = xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp := valid.2
  have actual : htRoot o p tk hs fpk indices.tree indices.leaf = root := by
    exact (supported_ht_sign_correct o widths v tk prfKey seed fpk digest).trans rootEq.symm
  have rLen : r.length = p.n := widths _
  have fLen : fs.length = p.forsBytes := fors_sign_width o widths p tk prfKey seed a indices.md
  have hLen : hs.length = p.d*p.layerBytes := ht_sign_width o widths p tk prfKey seed fpk _ _
    (by have h : 2 ≤ p.d := (supported_layer_bounds v).1; omega)
  let sig : Bytes := r++fs++hs
  have sigLen : sig.length = p.sigBytes := by simp only [sig,List.length_append,rLen,fLen,hLen,Params.sigBytes]
  have signed : sign o v sk msg = some sig := by
    have guard : (msg.isEmpty || sk.length != 4*(params v).n) = false := by simp [nonempty,keyLen,p]
    simp only [sign,guard,Bool.false_eq_true,if_false,Id.instMonad,bind,pure]
    change (if bne (α := Bytes) (htRoot o p tk hs fpk indices.tree indices.leaf) root then none else some sig) = some sig
    rw [actual]
    simp
  have seedLen : seed.length = p.n := by
    simp only [seed,slice,List.length_take,List.length_drop,keyLen]
    omega
  have rootLen : root.length = p.n := by rw [rootEq]; exact xmss_node_width o widths p tk prfKey seed _ _ _
  have pkLen : (seed++root).length = 2*p.n := by simp only [List.length_append,seedLen,rootLen]; omega
  have rTake : sig.take p.n = r := by
    simp only [sig,List.append_assoc]
    change (r++(fs++hs)).take p.n = r
    rw [← rLen,List.take_left]
  have fSlice : slice sig p.n p.forsBytes = fs := by
    simp only [sig,List.append_assoc,slice]
    change ((r++(fs++hs)).drop p.n).take p.forsBytes = fs
    rw [← rLen,List.drop_left,← fLen,List.take_left]
  have hDrop : sig.drop (p.n+p.forsBytes) = hs := by
    simp only [sig,List.append_assoc]
    change (r++(fs++hs)).drop (p.n+p.forsBytes) = hs
    rw [← List.drop_drop,← rLen,List.drop_left,← fLen,List.drop_left]
  refine ⟨sig,signed,sigLen,?_⟩
  change verify o v (seed++root) msg sig = some true
  have takeSeed : (seed++root).take p.n = seed := by rw [← seedLen,List.take_left]
  have dropSeed : (seed++root).drop p.n = root := by rw [← seedLen,List.drop_left]
  apply (verification_structure o v (seed++root) msg sig nonempty pkLen sigLen).2
  dsimp only
  rw [takeSeed,dropSeed,rTake,fSlice,hDrop]
  exact actual

 theorem slice_append_prefix (headBytes tailBytes : Bytes) (start len : Nat)
    (inside : start+len ≤ headBytes.length) :
    slice (headBytes++tailBytes) start len = slice headBytes start len := by
  unfold slice
  rw [List.drop_append_of_le_length (by omega)]
  rw [List.take_append_of_le_length (by simp only [List.length_drop]; omega)]

 theorem generated_key_valid (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32) :
    let pair : Bytes × Bytes := generateKeypair o v seed32
    ValidSecretKey o v pair.2 ∧ pair.1 =
      slice pair.2 (2*(params v).n) (params v).n ++ pair.2.drop (3*(params v).n) := by
  let p := params v
  let expanded : Bytes := o ⟨3,"ChaCha20Rng",[],seed32.val,3*p.n⟩
  let seed := slice expanded (2*p.n) p.n
  let tk : Bytes := deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey : Bytes := deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
  let root : Bytes := xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp
  have expandedLen : expanded.length = 3*p.n := widths _
  have rootLen : root.length = p.n := xmss_node_width o widths p tk prfKey seed _ _ _
  have seedSame : slice (expanded++root) (2*p.n) p.n = seed := by
    exact slice_append_prefix expanded root _ _ (by rw [expandedLen]; omega)
  have secretSame : (expanded++root).take p.n = expanded.take p.n := by
    exact List.take_append_of_le_length (by rw [expandedLen]; omega)
  have rootSame : (expanded++root).drop (3*p.n) = root := by rw [← expandedLen,List.drop_left]
  change ValidSecretKey o v (expanded++root) ∧ seed++root =
    slice (expanded++root) (2*p.n) p.n ++ (expanded++root).drop (3*p.n)
  constructor
  · change (expanded++root).length = 4*p.n ∧ _
    constructor
    · simp only [List.length_append,expandedLen,rootLen]; omega
    · change (expanded++root).drop (3*p.n) =
        xmssNode o p (deriveKey o "DSM/sphincs/v2/thash" (slice (expanded++root) (2*p.n) p.n))
          (deriveKey o "DSM/sphincs/v2/prf" ((expanded++root).take p.n))
          (slice (expanded++root) (2*p.n) p.n) {layer := p.d-1} 0 p.hp
      rw [rootSame,seedSame,secretSame]
  · rw [seedSame,rootSame]

 theorem keygen_sign_verify (o : Oracle Id) (widths : OutputWidths o)
    (v : Variant) (seed32 : Wire 32) (msg : Bytes) (nonempty : msg.isEmpty = false) :
    let pair : Bytes × Bytes := generateKeypair o v seed32
    ∃ sig : Bytes, sign o v pair.2 msg = some sig ∧
      sig.length = (params v).sigBytes ∧ verify o v pair.1 msg sig = some true := by
  obtain ⟨valid,publicLayout⟩ := generated_key_valid o widths v seed32
  obtain ⟨sig,signed,length,verified⟩ := signer_correct o widths v _ msg valid nonempty
  refine ⟨sig,signed,length,?_⟩
  rw [publicLayout]
  exact verified

#print axioms keygen_sign_verify
#print axioms signer_correct
#print axioms supported_ht_sign_correct
#print axioms ht_tail_correct
#print axioms fors_sign_correct
#print axioms xmss_sign_correct
#print axioms wots_sign_correct
end DSM.Sphincs
