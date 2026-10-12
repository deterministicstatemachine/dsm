-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RequestLog
import Sphincs.AddressInjective
import Sphincs.Signer

/- Address range and canonical tweak inputs for the signer and key generation.
   Each model function is run in the request-logging monad (`RequestLog`) and
   related to its `Id` run by `Good`: same result, and every request it issues
   is a keyed thash request at an `InRange` address, a keyed PRF request at an
   `InRange` address, or (at top level) an unkeyed request or the single
   message-PRF request. For thash requests the classification also records
   that, under fixed-width oracle outputs, the hashed value is
   `canon o p tk prfKey seed a`, a function of the key material and the
   address only; `TweakUse` turns this into tweak single use.

   Index bounds are threaded as hypotheses (tree < 2^(h-hp) ≤ 256^8, leaves
   < 2^hp, FORS global indices i*2^a+idx < k*2^a, chain index < len, chain
   step ≤ 15, heights ≤ hp or a) and discharged for every `params v` by
   `variant_bounds`. Nothing here assumes widths for the range statements:
   `sign_requests_in_range` and `keygen_requests_in_range` hold for every
   oracle. -/
namespace DSM.Sphincs

section Canon
variable (o : Oracle Id) (p : Params) (tk prfKey seed : Bytes)

/-- The WOTS secret of a chain address (PRF at type 5, same keypair/chain). -/
def wotsSecretAt (a : Adrs) : Bytes :=
  prf o p prfKey seed {a.setType 5 with keypair := a.keypair, chain := a.chain}

/-- The concatenated chain tops of the WOTS key whose address is `w`. -/
def wotsTopsAt (w : Adrs) : Bytes :=
  ((List.range p.len).map fun i => (chain o p tk {w with chain := i}
    (prf o p prfKey seed {w.setType 5 with keypair := w.keypair, chain := i}) 0 15 : Bytes)).flatten

/-- The canonical tweakable-hash input at an address: the one value the honest
    key generation / signing computation hashes under that address. -/
def canon (a : Adrs) : Bytes :=
  if a.kind = 0 then chain o p tk a (wotsSecretAt o p prfKey seed a) 0 a.hash
  else if a.kind = 1 then wotsTopsAt o p tk prfKey seed {layer := a.layer, tree := a.tree, keypair := a.keypair}
  else if a.kind = 2 then
    List.append (xmssNode o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*a.hash) (a.chain-1))
      (xmssNode o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*a.hash+1) (a.chain-1))
  else if a.kind = 3 then
    if a.chain = 0 then forsSecret o p prfKey seed {a with hash := 0} a.hash
    else List.append (forsNode o p tk prfKey seed {a with chain := 0, hash := 0} (2*a.hash) (a.chain-1))
      (forsNode o p tk prfKey seed {a with chain := 0, hash := 0} (2*a.hash+1) (a.chain-1))
  else if a.kind = 4 then
    ((List.range p.k).map fun i =>
      (forsNode o p tk prfKey seed {a with kind := 3, chain := 0, hash := 0} i p.a : Bytes)).flatten
  else []

/-- A keyed thash request at an in-range address; under fixed-width outputs
    its hashed value is the canonical one for that address. -/
def ThashReq (r : Request) : Prop :=
  ∃ (a : Adrs) (x : Bytes), a.InRange ∧ r = ⟨1,"",tk,a.bytes ++ x,p.n⟩ ∧
    (OutputWidths o → x = canon o p tk prfKey seed a)

/-- A keyed PRF request at an in-range address. -/
def PrfReq (r : Request) : Prop :=
  ∃ a : Adrs, a.InRange ∧ r = ⟨1,"",prfKey,seed ++ a.bytes,p.n⟩

def KReq (r : Request) : Prop :=
  ThashReq o p tk prfKey seed r ∨ PrfReq p prfKey seed r
end Canon

section Components
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

local notation "K" => KReq o p tk prfKey seed
local notation "LO" => logOracle o

theorem thash_good (a : Adrs) (ha : a.InRange) (x : Bytes)
    (hx : OutputWidths o → x = canon o p tk prfKey seed a) :
    Good K (thash LO p tk a x) (thash o p tk a x) :=
  Good.oracle o (Or.inl ⟨a, x, ha, rfl, hx⟩)

theorem prf_good (a : Adrs) (ha : a.InRange) :
    Good K (prf LO p prfKey seed a) (prf o p prfKey seed a) :=
  Good.oracle o (Or.inr ⟨a, ha, rfl⟩)

theorem chain_hash_irrel (a : Adrs) (h : Nat) (x : Bytes) (start steps : Nat) :
    chain o p tk {a with hash := h} x start steps = chain o p tk a x start steps := by
  induction steps generalizing x start with
  | zero => rfl
  | succ s ih => simp only [chain, id_bind, ih]

theorem chain_step (a : Adrs) (x : Bytes) (j : Nat) :
    chain o p tk a x 0 (j+1) = thash o p tk {a with hash := j} (chain o p tk a x 0 j) := by
  have h := chain_composes o p tk a x 0 j 1
  rw [h]
  simp only [Nat.zero_add, chain, id_bind]
  rfl

theorem canon_kind0 {a : Adrs} (h : a.kind = 0) :
    canon o p tk prfKey seed a = chain o p tk a (wotsSecretAt o p prfKey seed a) 0 a.hash := by
  simp only [canon, h, if_true]

theorem chain_good (a : Adrs) (hk : a.kind = 0) (hl : a.layer < 256^4) (ht : a.tree < 256^8)
    (hkp : a.keypair < 256^4) (hc : a.chain < 256^4) (x : Bytes) (start steps : Nat)
    (hb : start + steps ≤ 256^4)
    (hx : OutputWidths o → x = chain o p tk a (wotsSecretAt o p prfKey seed a) 0 start) :
    Good K (chain LO p tk a x start steps) (chain o p tk a x start steps) := by
  induction steps generalizing x start with
  | zero => exact Good.pure' x
  | succ s ih =>
    simp only [chain]
    apply Good.bind_id
    · have hr : ({a with hash := start} : Adrs).InRange :=
        ⟨hl, ht, by rw [hk]; exact Nat.pos_of_ne_zero (by decide), hkp, hc,
          show start < 256^4 by omega⟩
      apply thash_good _ hr
      intro w
      rw [canon_kind0 (a := {a with hash := start}) hk, chain_hash_irrel]
      exact hx w
    · apply ih _ _ (by omega)
      intro w
      rw [chain_step, hx w]
theorem chain_good0 (a : Adrs) (sk : Bytes) (steps : Nat) (hk : a.kind = 0)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8)
    (hkp : a.keypair < 256^4) (hc : a.chain < 256^4)
    (hsk : sk = wotsSecretAt o p prfKey seed a) (hs : steps ≤ 256^4) :
    Good K (chain LO p tk a sk 0 steps) (chain o p tk a sk 0 steps) :=
  chain_good a hk hl ht hkp hc sk 0 steps (by omega) (fun _ => hsk)

/-- Membership in an indexed digit list: the index is below the length. -/
theorem zipIdx_mem {l : List Nat} {x : Nat × Nat} (h : x ∈ l.zipIdx) :
    x.1 ∈ l ∧ x.2 < l.length := by
  have lookup := List.mem_zipIdx_iff_getElem?.mp h
  obtain ⟨bound, _⟩ := List.getElem?_eq_some_iff.mp lookup
  exact ⟨List.mem_of_getElem? lookup, by simpa using bound⟩

macro "inrange" : tactic =>
  `(tactic| (refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> dsimp only [Adrs.setType] <;> omega))

macro "good_tail" : tactic =>
  `(tactic| repeat (first | exact Good.pure_id _ | exact Good.pure' _ |
      apply Good.bind_id (Good.pure_id _)))

theorem wotsSign_good (b : Adrs) (idx : Nat) (msg : Bytes)
    (hl : b.layer < 256^4) (ht : b.tree < 256^8) (hidx : idx < 256^4) (hlen : p.len ≤ 256^4) :
    Good K (wotsSign LO p tk prfKey seed {b.setType 0 with keypair := idx} msg)
      (wotsSign o p tk prfKey seed {b.setType 0 with keypair := idx} msg) := by
  simp only [wotsSign]
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro x hx acc
  obtain ⟨hd, hi⟩ := zipIdx_mem hx
  have hd' := wots_digit_bound p msg _ hd
  rw [wots_digit_count] at hi
  apply Good.bind_id (prf_good _ (by inrange))
  refine Good.bind_id (chain_good0 _ _ _ ?_ ?_ ?_ ?_ ?_ ?_ ?_) ?_
  · rfl
  · exact hl
  · exact ht
  · exact hidx
  · dsimp only; omega
  · rfl
  · omega
  · good_tail
theorem canon_kind1 {a : Adrs} (h : a.kind = 1) :
    canon o p tk prfKey seed a =
      wotsTopsAt o p tk prfKey seed {layer := a.layer, tree := a.tree, keypair := a.keypair} := by
  simp only [canon, h]
  rfl

theorem wotsCompress_good (b : Adrs) (idx : Nat) (tops : Bytes)
    (hl : b.layer < 256^4) (ht : b.tree < 256^8) (hidx : idx < 256^4)
    (htops : OutputWidths o →
      tops = wotsTopsAt o p tk prfKey seed {layer := b.layer, tree := b.tree, keypair := idx}) :
    Good K (wotsCompress LO p tk {b.setType 0 with keypair := idx} tops)
      (wotsCompress o p tk {b.setType 0 with keypair := idx} tops) := by
  apply thash_good _ (by inrange)
  intro w
  rw [canon_kind1 rfl]
  exact htops w

theorem wotsPkgen_good (b : Adrs) (idx : Nat)
    (hl : b.layer < 256^4) (ht : b.tree < 256^8) (hidx : idx < 256^4) (hlen : p.len ≤ 256^4) :
    Good K (wotsPkgen LO p tk prfKey seed {b.setType 0 with keypair := idx})
      (wotsPkgen o p tk prfKey seed {b.setType 0 with keypair := idx}) := by
  simp only [wotsPkgen]
  apply Good.bind_id
  · apply Good.forIn'
    intro i hi acc
    have hi' : i < p.len := by simpa using hi
    apply Good.bind_id (prf_good _ (by inrange))
    refine Good.bind_id (chain_good0 _ _ _ ?_ ?_ ?_ ?_ ?_ ?_ ?_) ?_
    · rfl
    · exact hl
    · exact ht
    · exact hidx
    · dsimp only; omega
    · rfl
    · omega
    · good_tail
  · apply wotsCompress_good b idx _ hl ht hidx
    intro _
    simp only [Id.instMonad, bind, pure]
    exact gather _ _ []

theorem wots_sign_slice (widths : OutputWidths o) (a : Adrs) (msg : Bytes) (x : Nat × Nat)
    (hx : x ∈ (wotsDigits p msg).zipIdx) :
    slice (wotsSign o p tk prfKey seed a msg) (x.2*p.n) p.n =
      chain o p tk {a with chain := x.2}
        (prf o p prfKey seed {a.setType 5 with keypair := a.keypair, chain := x.2}) 0 x.1 := by
  rw [wots_sign_blocks]
  exact serialized_indexed_block (wotsDigits p msg) (fun (digit,i) => (chain o p tk {a with chain := i}
    (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 digit : Bytes))
    p.n x hx (fun y _ => chain_width o widths p tk _ _ 0 y.1 (prf_width o widths p prfKey seed _))

theorem wots_sign_tops (widths : OutputWidths o) (a : Adrs) (msg : Bytes) :
    ((wotsDigits p msg).zipIdx.map fun x => (chain o p tk {a with chain := x.2}
      (slice (wotsSign o p tk prfKey seed a msg) (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)).flatten =
    ((List.range p.len).map fun i => (chain o p tk {a with chain := i}
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair, chain := i}) 0 15 : Bytes)).flatten := by
  let digits := (wotsDigits p msg).zipIdx
  let top : Nat → Bytes := fun i =>
    chain o p tk {a with chain := i}
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair,chain := i}) 0 15
  have mapTops : digits.map (fun x =>
      (chain o p tk {a with chain := x.2}
       (slice (wotsSign o p tk prfKey seed a msg) (x.2*p.n) p.n) x.1 (15-x.1) : Bytes)) =
      digits.map (fun x => top x.2) := by
    apply List.map_congr_left
    intro x hx
    rw [wots_sign_slice widths a msg x hx]
    exact wots_generated_digit_recovers o p tk _ _ msg x.1 (zipIdx_mem hx).1
  have indexList : digits.map Prod.snd = List.range p.len := by
    simp [digits,List.zipIdx_map_snd,wots_digit_count,List.range_eq_range']
  have topMap : digits.map (fun x => top x.2) = (List.range p.len).map top := by
    simpa only [List.map_map,Function.comp_def] using congrArg (List.map top) indexList
  change (digits.map (fun x => (chain o p tk {a with chain := x.2}
       (slice (wotsSign o p tk prfKey seed a msg) (x.2*p.n) p.n) x.1 (15-x.1) : Bytes))).flatten = _
  rw [mapTops, topMap]

theorem wotsPkFromSig_good (b : Adrs) (idx : Nat) (sig msg : Bytes)
    (hl : b.layer < 256^4) (ht : b.tree < 256^8) (hidx : idx < 256^4) (hlen : p.len ≤ 256^4)
    (hsig : OutputWidths o → sig = wotsSign o p tk prfKey seed {b.setType 0 with keypair := idx} msg) :
    Good K (wotsPkFromSig LO p tk {b.setType 0 with keypair := idx} sig msg)
      (wotsPkFromSig o p tk {b.setType 0 with keypair := idx} sig msg) := by
  simp only [wotsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x hx acc
    obtain ⟨hd, hi⟩ := zipIdx_mem hx
    have hd' := wots_digit_bound p msg _ hd
    rw [wots_digit_count] at hi
    refine Good.bind_id (chain_good _ ?_ ?_ ?_ ?_ ?_ _ _ _ ?_ ?_) ?_
    · rfl
    · exact hl
    · exact ht
    · exact hidx
    · dsimp only; omega
    · dsimp only; omega
    · intro w
      rw [hsig w, wots_sign_slice w _ msg x hx]
      rfl
    · good_tail
  · apply wotsCompress_good b idx _ hl ht hidx
    intro w
    simp only [Id.instMonad, bind, pure]
    refine (gather _ _ []).trans ?_
    rw [List.nil_append, hsig w]
    exact (wots_sign_tops w ({b.setType 0 with keypair := idx} : Adrs) msg).trans rfl
theorem canon_kind2 {a : Adrs} (h : a.kind = 2) :
    canon o p tk prfKey seed a =
      List.append (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*a.hash) (a.chain-1))
        (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*a.hash+1) (a.chain-1)) := by
  simp only [canon, h]
  rfl

/-- An XMSS node depends on its address only through layer and tree. -/
theorem xmssNode_base (a : Adrs) (idx h : Nat) :
    xmssNode (m := Id) o p tk prfKey seed a idx h =
      xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} idx h := by
  induction h generalizing idx with
  | zero => rfl
  | succ h ih => simp only [xmssNode, ih]; rfl

theorem pow_sub_succ (H h : Nat) (hh : h + 1 ≤ H) : 2^(H-h) = 2^(H-(h+1))*2 := by
  rw [← Nat.pow_succ]; congr 1; omega

theorem xmssNode_good (a : Adrs) (H : Nat) (hH : 2^H ≤ 256^4)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hlen : p.len ≤ 256^4)
    (h idx : Nat) (hh : h ≤ H) (hidx : idx < 2^(H-h)) :
    Good K (xmssNode LO p tk prfKey seed a idx h) (xmssNode o p tk prfKey seed a idx h) := by
  induction h generalizing idx with
  | zero =>
    have : idx < 256^4 := by simp at hidx; omega
    exact wotsPkgen_good a idx hl ht this hlen
  | succ h ih =>
    simp only [xmssNode]
    have e := pow_sub_succ H h hh
    have hle : 2^(H-(h+1)) ≤ 2^H := Nat.pow_le_pow_right (by decide) (by omega)
    have hlt : h + 1 < 2^H := Nat.lt_of_lt_of_le (Nat.lt_two_pow_self) (Nat.pow_le_pow_right (by decide) hh)
    apply Good.bind_id (ih (2*idx) (by omega) (by omega))
    apply Good.bind_id (ih (2*idx+1) (by omega) (by omega))
    apply thash_good _ (by inrange)
    intro _
    rw [canon_kind2 (a := {a.setType 2 with chain := h+1, hash := idx}) rfl]
    show List.append _ _ = List.append (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*idx) h)
      (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*idx+1) h)
    rw [← xmssNode_base, ← xmssNode_base]

theorem walk_input (N : Nat → Nat → Bytes) (level gi li : Nat) (node sib : Bytes)
    (hnode : node = N level gi) (hsib : sib = N level (siblingIndex gi)) (hpar : li%2 = gi%2) :
    (if li%2 = 0 then node++sib else sib++node) =
      List.append (N level (2*(gi/2))) (N level (2*(gi/2)+1)) := by
  subst hnode hsib
  rw [hpar]
  by_cases even : gi%2 = 0
  · have left : 2*(gi/2) = gi := by omega
    have right : 2*(gi/2)+1 = siblingIndex gi := by simp [siblingIndex,even]; omega
    rw [if_pos even, right, left]
    rfl
  · have right : 2*(gi/2)+1 = gi := by omega
    have left : 2*(gi/2) = siblingIndex gi := by simp [siblingIndex,even]; omega
    rw [if_neg even, right, left]
    rfl

theorem authWalk_good (a : Adrs) (N : Nat → Nat → Bytes)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hk : a.kind < 256^4) (hkp : a.keypair < 256^4)
    (hcanon : ∀ lv i, canon o p tk prfKey seed {a with chain := lv+1, hash := i} =
      List.append (N lv (2*i)) (N lv (2*i+1)))
    (hpar : ∀ lv i, thash o p tk {a with chain := lv+1, hash := i}
      (List.append (N lv (2*i)) (N lv (2*i+1))) = N (lv+1) i)
    (remaining level localIndex globalIndex : Nat) (node auth : Bytes)
    (hrem : level + remaining < 256^4) (hg : globalIndex < 256^4)
    (orient : ∀ j, j < remaining → (localIndex/2^j)%2 = (globalIndex/2^j)%2)
    (hnode : OutputWidths o → node = N level globalIndex)
    (hsib : OutputWidths o → ∀ j, j < remaining →
      slice auth ((level+j)*p.n) p.n = N (level+j) (siblingIndex (globalIndex/2^j))) :
    Good K (authWalk LO p tk a localIndex globalIndex node auth level remaining)
      (authWalk o p tk a localIndex globalIndex node auth level remaining) := by
  induction remaining generalizing level localIndex globalIndex node with
  | zero => exact Good.pure' _
  | succ remaining ih =>
    simp only [authWalk]
    have parity : localIndex%2 = globalIndex%2 := by simpa using orient 0 (by omega)
    have input : OutputWidths o →
        (if localIndex%2 = 0 then node++slice auth (level*p.n) p.n
          else slice auth (level*p.n) p.n++node) =
          List.append (N level (2*(globalIndex/2))) (N level (2*(globalIndex/2)+1)) := by
      intro w
      apply walk_input N level globalIndex localIndex _ _ (hnode w) _ parity
      simpa using hsib w 0 (by omega)
    apply Good.bind_id
    · apply thash_good _ (by inrange)
      intro w
      rw [input w, hcanon]
    · apply ih (level+1) (localIndex/2) (globalIndex/2) _ (by omega) (by omega)
      · intro j hj
        have h := orient (j+1) (by omega)
        simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm] using h
      · intro w
        rw [input w, hpar]
      · intro w j hj
        have h := hsib w (j+1) (by omega)
        simpa [Nat.pow_succ,Nat.div_div_eq_div_mul,Nat.mul_comm,Nat.add_assoc,Nat.add_comm,Nat.add_left_comm] using h
theorem xmss_sig_take (widths : OutputWidths o) (a : Adrs) (idx : Nat) (msg : Bytes) :
    (xmssSign o p tk prfKey seed a idx msg).take (p.len*p.n) =
      wotsSign o p tk prfKey seed {a.setType 0 with keypair := idx} msg := by
  rw [xmss_sign_blocks]
  rw [← wots_sign_width o widths p tk prfKey seed {a.setType 0 with keypair := idx} msg]
  exact List.take_left

theorem xmss_sig_drop (widths : OutputWidths o) (a : Adrs) (idx : Nat) (msg : Bytes) :
    (xmssSign o p tk prfKey seed a idx msg).drop (p.len*p.n) =
      ((List.range p.hp).map fun j =>
        (xmssNode o p tk prfKey seed a (Nat.xor (idx/2^j) 1) j : Bytes)).flatten := by
  rw [xmss_sign_blocks]
  rw [← wots_sign_width o widths p tk prfKey seed {a.setType 0 with keypair := idx} msg]
  exact List.drop_left

theorem xmssPkFromSig_good (a : Adrs) (idx : Nat) (sig msg : Bytes)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hidx : idx < 2^p.hp)
    (hsig : OutputWidths o → sig = xmssSign o p tk prfKey seed a idx msg) :
    Good K (xmssPkFromSig LO p tk a idx sig msg) (xmssPkFromSig o p tk a idx sig msg) := by
  simp only [xmssPkFromSig]
  have hlt : p.hp < 2^p.hp := Nat.lt_two_pow_self
  apply Good.bind_id (wotsPkFromSig_good a idx _ msg hl ht (by omega) hlen ?_)
  · simp only [authRoot]
    apply authWalk_good (a.setType 2) (fun lv i => xmssNode o p tk prfKey seed a i lv) hl ht
      (by dsimp only [Adrs.setType]; omega) (by dsimp only [Adrs.setType]; omega)
    · intro lv i
      rw [canon_kind2 (a := {a.setType 2 with chain := lv+1, hash := i}) rfl]
      show List.append (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*i) lv)
        (xmssNode (m := Id) o p tk prfKey seed {layer := a.layer, tree := a.tree} (2*i+1) lv) = _
      rw [← xmssNode_base, ← xmssNode_base]
    · intro lv i
      exact xmss_node_parent o p tk prfKey seed a lv i
    · omega
    · omega
    · intro _ _; rfl
    · intro w
      rw [hsig w, xmss_sig_take w]
      exact wots_sign_correct o w p tk prfKey seed _ msg
    · intro w j hj
      rw [hsig w, xmss_sig_drop w, Nat.zero_add]
      exact xmss_auth_bytes o w p tk prfKey seed a idx j hj
  · intro w
    rw [hsig w, xmss_sig_take w]

theorem sibling_bound (H level idx : Nat) (hidx : idx < 2^H) (hl : level < H) :
    Nat.xor (idx/2^level) 1 < 2^(H-level) := by
  rw [xor_one_is_sibling]
  have split : 2^H = 2^(H-level)*2^level := by rw [← Nat.pow_add]; congr 1; omega
  have hq : idx/2^level < 2^(H-level) :=
    (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 (by rw [← split]; exact hidx)
  have even : 2^(H-level) % 2 = 0 := by
    obtain ⟨r, hr⟩ := Nat.exists_eq_succ_of_ne_zero (show H-level ≠ 0 by omega)
    rw [hr, Nat.pow_succ]; simp
  by_cases he : (idx/2^level) % 2 = 0
  · have e : siblingIndex (idx/2^level) = idx/2^level + 1 := by simp [siblingIndex, he]
    rw [e]; omega
  · have e : siblingIndex (idx/2^level) = idx/2^level - 1 := by simp [siblingIndex, he]
    rw [e]; exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) hq

theorem xmssSign_good (a : Adrs) (idx : Nat) (msg : Bytes)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hlen : p.len ≤ 256^4)
    (hH : 2^p.hp ≤ 256^4) (hidx : idx < 2^p.hp) :
    Good K (xmssSign LO p tk prfKey seed a idx msg) (xmssSign o p tk prfKey seed a idx msg) := by
  simp only [xmssSign]
  apply Good.bind_id
  · apply Good.forIn'
    intro level hlev acc
    have hlev' : level < p.hp := by simpa using hlev
    apply Good.bind_id (xmssNode_good a p.hp hH hl ht hlen level _ (by omega)
      (sibling_bound p.hp level idx hidx hlev'))
    good_tail
  · apply Good.bind_id (wotsSign_good a idx msg hl ht (by omega) hlen)
    good_tail
theorem next_tree_le (tree : Nat) : (nextLayer p tree).2 ≤ tree := Nat.div_le_self _ _

theorem htSignTail_good (hlen : p.len ≤ 256^4) (hH : 2^p.hp ≤ 256^4)
    (remaining layer tree : Nat) (node : Bytes)
    (hl : layer + remaining < 256^4) (ht : tree < 256^8) :
    Good K (htSignTail LO p tk prfKey seed layer tree node (remaining+1))
      (htSignTail o p tk prfKey seed layer tree node (remaining+1)) := by
  induction remaining generalizing layer tree node with
  | zero =>
    simp only [htSignTail]
    apply Good.bind_id (xmssSign_good _ _ node (by dsimp only; omega)
      (by dsimp only; have := next_tree_le (p := p) tree; omega) hlen hH (next_layer_leaf_bounded p tree))
    apply Good.ite' (fun _ => Good.pure' _)
    intro hne; exact (hne trivial).elim
  | succ r ih =>
    simp only [htSignTail]
    have hn := next_tree_le (p := p) tree
    apply Good.bind_id (xmssSign_good _ _ node (by dsimp only; omega)
      (by dsimp only; omega) hlen hH (next_layer_leaf_bounded p tree))
    apply Good.ite' (fun _ => Good.pure' _)
    intro _
    apply Good.bind_id (Good.pure_id _)
    apply Good.bind_id (xmssPkFromSig_good _ _ _ node (by dsimp only; omega)
      (by dsimp only; omega) hlen hH (next_layer_leaf_bounded p tree) (fun _ => rfl))
    apply Good.bind_id (ih _ _ _ (by omega) (by omega))
    exact Good.pure' _

theorem ht_sign_tail_one (layer tree : Nat) (node : Bytes) :
    htSignTail o p tk prfKey seed layer tree node 1 =
      xmssSign o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2}
        (nextLayer p tree).1 node := rfl

theorem htRootTail_good (hlen : p.len ≤ 256^4) (hH : 2^p.hp ≤ 256^4)
    (remaining layer tree : Nat) (node sig : Bytes)
    (hl : layer + remaining ≤ 256^4) (ht : tree < 256^8)
    (hsig : OutputWidths o → sig = htSignTail o p tk prfKey seed layer tree node remaining) :
    Good K (htRootTail LO p tk layer tree node sig remaining)
      (htRootTail o p tk layer tree node sig remaining) := by
  induction remaining generalizing layer tree node sig with
  | zero => exact Good.pure' _
  | succ r ih =>
    simp only [htRootTail]
    have hn := next_tree_le (p := p) tree
    have split : OutputWidths o →
        sig.take p.layerBytes = xmssSign o p tk prfKey seed
          {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1 node ∧
        sig.drop p.layerBytes = htSignTail o p tk prfKey seed (layer+1) (nextLayer p tree).2
          (xmssPkFromSig o p tk {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1
            (xmssSign o p tk prfKey seed {layer := layer, tree := (nextLayer p tree).2}
              (nextLayer p tree).1 node) node) r := by
      intro w
      have width := xmss_sign_width o w p tk prfKey seed
        {layer := layer, tree := (nextLayer p tree).2} (nextLayer p tree).1 node
      rw [hsig w]
      by_cases hr : r = 0
      · subst hr
        rw [ht_sign_tail_one]
        refine ⟨List.take_of_length_le (by omega), ?_⟩
        rw [List.drop_of_length_le (by omega)]
        rfl
      · rw [ht_sign_tail_step o p tk prfKey seed layer tree r node hr]
        dsimp only
        rw [← width]
        exact ⟨List.take_left, List.drop_left⟩
    apply Good.bind_id (xmssPkFromSig_good _ _ _ node (by dsimp only; omega)
      (by dsimp only; omega) hlen hH (next_layer_leaf_bounded p tree) (fun w => (split w).1))
    apply ih _ _ _ _ (by omega) (by omega)
    intro w
    rw [(split w).2, (split w).1]

theorem htSign_good (hlen : p.len ≤ 256^4) (hH : 2^p.hp ≤ 256^4)
    (msg : Bytes) (tree leaf : Nat) (hd : p.d ≤ 256^4) (ht : tree < 256^8) (hleaf : leaf < 2^p.hp) :
    Good K (htSign LO p tk prfKey seed msg tree leaf) (htSign o p tk prfKey seed msg tree leaf) := by
  simp only [htSign]
  apply Good.bind_id (xmssSign_good _ _ msg (by dsimp only; omega) ht hlen hH hleaf)
  apply Good.bind_id (xmssPkFromSig_good _ _ _ msg (by dsimp only; omega) ht hlen hH hleaf
    (fun _ => rfl))
  cases hdc : p.d - 1 with
  | zero => exact Good.bind_id (Good.pure' _) (Good.pure' _)
  | succ r =>
    apply Good.bind_id (htSignTail_good hlen hH r 1 tree _ (by omega) ht)
    exact Good.pure' _

theorem htRoot_good (hlen : p.len ≤ 256^4) (hH : 2^p.hp ≤ 256^4)
    (sig msg : Bytes) (tree leaf : Nat) (hd : p.d ≤ 256^4) (ht : tree < 256^8) (hleaf : leaf < 2^p.hp)
    (hsig : OutputWidths o → sig = htSign o p tk prfKey seed msg tree leaf) :
    Good K (htRoot LO p tk sig msg tree leaf) (htRoot o p tk sig msg tree leaf) := by
  simp only [htRoot]
  have split : OutputWidths o →
      sig.take p.layerBytes = xmssSign o p tk prfKey seed {tree := tree} leaf msg ∧
      sig.drop p.layerBytes = htSignTail o p tk prfKey seed 1 tree
        (xmssPkFromSig o p tk {tree := tree} leaf
          (xmssSign o p tk prfKey seed {tree := tree} leaf msg) msg) (p.d-1) := by
    intro w
    have width := xmss_sign_width o w p tk prfKey seed {tree := tree} leaf msg
    rw [hsig w]
    simp only [htSign, id_bind, id_pure]
    rw [← width]
    exact ⟨List.take_left, List.drop_left⟩
  apply Good.bind_id (xmssPkFromSig_good _ _ _ msg (by dsimp only; omega) ht hlen hH hleaf
    (fun w => (split w).1))
  apply htRootTail_good hlen hH _ _ _ _ _ (by omega) ht
  intro w
  rw [(split w).2, (split w).1]
theorem canon_kind3_leaf {a : Adrs} (h : a.kind = 3) (hc : a.chain = 0) :
    canon o p tk prfKey seed a = forsSecret (m := Id) o p prfKey seed {a with hash := 0} a.hash := by
  simp only [canon, h, hc]
  rfl

theorem canon_kind3_node {a : Adrs} (c : Nat) (h : a.kind = 3) (hc : a.chain = c+1) :
    canon o p tk prfKey seed a =
      List.append (forsNode (m := Id) o p tk prfKey seed {a with chain := 0, hash := 0} (2*a.hash) c)
        (forsNode (m := Id) o p tk prfKey seed {a with chain := 0, hash := 0} (2*a.hash+1) c) := by
  simp only [canon, h, hc]
  rfl

theorem canon_kind4 {a : Adrs} (h : a.kind = 4) :
    canon o p tk prfKey seed a = ((List.range p.k).map fun i =>
      (forsNode o p tk prfKey seed {a with kind := 3, chain := 0, hash := 0} i p.a : Bytes)).flatten := by
  simp only [canon, h]
  rfl

/-- A FORS node depends on its address only through layer, tree, type and keypair. -/
theorem forsNode_base (a : Adrs) (idx h : Nat) :
    forsNode (m := Id) o p tk prfKey seed a idx h =
      forsNode (m := Id) o p tk prfKey seed {a with chain := 0, hash := 0} idx h := by
  induction h generalizing idx with
  | zero => rfl
  | succ h ih => simp only [forsNode, ih]

theorem offset_lt {i M j X : Nat} (hi : i < M) (hj : j < X) : i*X + j < M*X := by
  have h : (i+1)*X ≤ M*X := Nat.mul_le_mul_right _ hi
  rw [Nat.succ_mul] at h
  omega

theorem forsSecret_good (a : Adrs) (idx : Nat)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hkp : a.keypair < 256^4) (hidx : idx < 256^4) :
    Good K (forsSecret LO p prfKey seed a idx) (forsSecret o p prfKey seed a idx) :=
  prf_good _ (by inrange)

theorem forsNode_good (a : Adrs) (hk : a.kind = 3)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hkp : a.keypair < 256^4)
    (M A : Nat) (hMA : M*2^A ≤ 256^4) (hA : A < 256^4)
    (h idx : Nat) (hh : h ≤ A) (hidx : idx < M*2^(A-h)) :
    Good K (forsNode LO p tk prfKey seed a idx h) (forsNode o p tk prfKey seed a idx h) := by
  have hle : M*2^(A-h) ≤ 256^4 :=
    Nat.le_trans (Nat.mul_le_mul_left _ (Nat.pow_le_pow_right (by decide) (by omega))) hMA
  induction h generalizing idx with
  | zero =>
    simp only [forsNode]
    apply Good.bind_id (forsSecret_good a idx hl ht hkp (by omega))
    apply thash_good _ (by inrange)
    intro _
    rw [canon_kind3_leaf (a := {a with chain := 0, hash := idx}) hk rfl]
    rfl
  | succ h ih =>
    simp only [forsNode]
    have e : M*2^(A-h) = M*2^(A-(h+1))*2 := by rw [pow_sub_succ A h hh, Nat.mul_assoc]
    have hle' : M*2^(A-h) ≤ 256^4 :=
      Nat.le_trans (Nat.mul_le_mul_left _ (Nat.pow_le_pow_right (by decide) (by omega))) hMA
    apply Good.bind_id (ih (2*idx) (by omega) (by omega) hle')
    apply Good.bind_id (ih (2*idx+1) (by omega) (by omega) hle')
    apply thash_good _ (by inrange)
    intro _
    rw [canon_kind3_node (a := {a with chain := h+1, hash := idx}) h hk rfl]
    show _ = List.append (forsNode (m := Id) o p tk prfKey seed {a with chain := 0, hash := 0} (2*idx) h)
        (forsNode (m := Id) o p tk prfKey seed {a with chain := 0, hash := 0} (2*idx+1) h)
    rw [← forsNode_base, ← forsNode_base]
    rfl

theorem forsSign_good (l t kp : Nat) (md : Bytes)
    (hl : l < 256^4) (ht : t < 256^8) (hkp : kp < 256^4)
    (hMA : p.k*2^p.a ≤ 256^4) (hA : p.a < 256^4) :
    Good K (forsSign LO p tk prfKey seed {layer := l, tree := t, kind := 3, keypair := kp} md)
      (forsSign o p tk prfKey seed {layer := l, tree := t, kind := 3, keypair := kp} md) := by
  simp only [forsSign]
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro x hx acc
  obtain ⟨hd, hi⟩ := zipIdx_mem hx
  have hd' := base2b_digit_bound md p.a p.k _ hd
  have hi' : x.2 < p.k := by simpa [base2b] using hi
  apply Good.bind_id (forsSecret_good _ _ hl ht hkp
    (Nat.lt_of_lt_of_le (offset_lt hi' hd') hMA))
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro level hlev acc'
  have hlev' : level < p.a := by simpa using hlev
  apply Good.bind_id (forsNode_good _ rfl hl ht hkp p.k p.a hMA hA level _ (by omega)
    (offset_lt hi' (sibling_bound p.a level x.1 hd' hlev')))
  good_tail
theorem authRoot_good (a : Adrs) (N : Nat → Nat → Bytes)
    (hl : a.layer < 256^4) (ht : a.tree < 256^8) (hk : a.kind < 256^4) (hkp : a.keypair < 256^4)
    (hcanon : ∀ lv i, canon o p tk prfKey seed {a with chain := lv+1, hash := i} =
      List.append (N lv (2*i)) (N lv (2*i+1)))
    (hpar : ∀ lv i, thash o p tk {a with chain := lv+1, hash := i}
      (List.append (N lv (2*i)) (N lv (2*i+1))) = N (lv+1) i)
    (localIndex globalIndex : Nat) (node auth : Bytes) (height : Nat)
    (hrem : height < 256^4) (hg : globalIndex < 256^4)
    (orient : ∀ j, j < height → (localIndex/2^j)%2 = (globalIndex/2^j)%2)
    (hnode : OutputWidths o → node = N 0 globalIndex)
    (hsib : OutputWidths o → ∀ j, j < height →
      slice auth (j*p.n) p.n = N j (siblingIndex (globalIndex/2^j))) :
    Good K (authRoot LO p tk a localIndex globalIndex node auth height)
      (authRoot o p tk a localIndex globalIndex node auth height) := by
  simp only [authRoot]
  exact authWalk_good a N hl ht hk hkp hcanon hpar height 0 localIndex globalIndex node auth
    (by omega) hg orient hnode (fun w j hj => by rw [Nat.zero_add]; exact hsib w j hj)

theorem fors_part_take (widths : OutputWidths o) (a : Adrs) (x : Nat × Nat) :
    (forsPart o p tk prfKey seed a x).take p.n = forsSecret o p prfKey seed a (x.2*2^p.a+x.1) := by
  have sw : (forsSecret (m := Id) o p prfKey seed a (x.2*2^p.a+x.1)).length = p.n := widths _
  unfold forsPart
  rw [← sw]
  exact List.take_left

theorem fors_part_drop (widths : OutputWidths o) (a : Adrs) (x : Nat × Nat) :
    (forsPart o p tk prfKey seed a x).drop p.n = ((List.range p.a).map fun j =>
      (forsNode o p tk prfKey seed a (x.2*2^(p.a-j)+Nat.xor (x.1/2^j) 1) j : Bytes)).flatten := by
  have sw : (forsSecret (m := Id) o p prfKey seed a (x.2*2^p.a+x.1)).length = p.n := widths _
  unfold forsPart
  rw [← sw]
  exact List.drop_left

theorem fors_sign_part (widths : OutputWidths o) (a : Adrs) (md : Bytes) (x : Nat × Nat)
    (hx : x ∈ (base2b md p.a p.k).zipIdx) :
    slice (forsSign o p tk prfKey seed a md) (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n) =
      forsPart o p tk prfKey seed a x := by
  rw [fors_sign_blocks]
  exact serialized_indexed_block (base2b md p.a p.k) (forsPart o p tk prfKey seed a)
    ((p.a+1)*p.n) x hx (fun y _ => fors_part_width o widths p tk prfKey seed a y)

theorem fors_sign_roots (widths : OutputWidths o) (a : Adrs) (md : Bytes) :
    ((base2b md p.a p.k).zipIdx.map fun x =>
        (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
          (thash o p tk {a with chain := 0,hash := x.2*2^p.a+x.1}
            ((slice (forsSign o p tk prfKey seed a md) (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
          ((slice (forsSign o p tk prfKey seed a md) (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n)
          p.a : Bytes)).flatten =
      ((List.range p.k).map fun i => (forsNode o p tk prfKey seed a i p.a : Bytes)).flatten := by
  let digits := (base2b md p.a p.k).zipIdx
  let top : Nat → Bytes := fun i => forsNode o p tk prfKey seed a i p.a
  have roots : digits.map (fun x => (authRoot o p tk a x.1 (x.2*2^p.a+x.1)
        (thash o p tk {a with chain := 0,hash := x.2*2^p.a+x.1}
          ((slice (forsSign o p tk prfKey seed a md) (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).take p.n))
        ((slice (forsSign o p tk prfKey seed a md) (x.2*((p.a+1)*p.n)) ((p.a+1)*p.n)).drop p.n)
          p.a : Bytes)) =
      digits.map (fun x => top x.2) := by
    apply List.map_congr_left
    intro x hx
    rw [fors_sign_part widths a md x hx]
    exact fors_part_correct o widths p tk prfKey seed a x.2 x.1
      (base2b_digit_bound md p.a p.k x.1 (zipIdx_mem hx).1)
  have indexList : digits.map Prod.snd = List.range p.k := by
    simp [digits,List.zipIdx_map_snd,base2b,List.range_eq_range']
  have topMap : digits.map (fun x => top x.2) = (List.range p.k).map top := by
    simpa only [List.map_map,Function.comp_def] using congrArg (List.map top) indexList
  change (digits.map _).flatten = _
  rw [roots, topMap]

theorem forsPkFromSig_good (l t kp : Nat) (sig md : Bytes)
    (hl : l < 256^4) (ht : t < 256^8) (hkp : kp < 256^4)
    (hMA : p.k*2^p.a ≤ 256^4) (hA : p.a < 256^4)
    (hsig : OutputWidths o →
      sig = forsSign o p tk prfKey seed {layer := l, tree := t, kind := 3, keypair := kp} md) :
    Good K (forsPkFromSig LO p tk {layer := l, tree := t, kind := 3, keypair := kp} sig md)
      (forsPkFromSig o p tk {layer := l, tree := t, kind := 3, keypair := kp} sig md) := by
  simp only [forsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x hx acc
    obtain ⟨hd, hi⟩ := zipIdx_mem hx
    have hd' := base2b_digit_bound md p.a p.k _ hd
    have hi' : x.2 < p.k := by simpa [base2b] using hi
    have hg := Nat.lt_of_lt_of_le (offset_lt hi' hd') hMA
    refine Good.bind_id (thash_good _ ?_ _ ?_) ?_
    · inrange
    · intro w
      rw [canon_kind3_leaf (a := {({layer := l, tree := t, kind := 3, keypair := kp} : Adrs) with
        chain := 0, hash := x.2*2^p.a+x.1}) rfl rfl]
      rw [hsig w, fors_sign_part w _ md x hx, fors_part_take w]
    · apply Good.bind_id (authRoot_good _
        (fun lv i => forsNode o p tk prfKey seed {layer := l, tree := t, kind := 3, keypair := kp} i lv)
        hl ht (by dsimp only; omega) hkp ?_ ?_ _ _ _ _ _ hA hg ?_ ?_ ?_)
      · good_tail
      · intro lv i
        rw [canon_kind3_node (a := {({layer := l, tree := t, kind := 3, keypair := kp} : Adrs) with
          chain := lv+1, hash := i}) lv rfl rfl]
      · intro lv i
        exact fors_node_parent o p tk prfKey seed _ lv i
      · intro j hj
        exact fors_orientation x.2 x.1 p.a j hj
      · intro w
        rw [hsig w, fors_sign_part w _ md x hx, fors_part_take w]
        rfl
      · intro w j hj
        rw [hsig w, fors_sign_part w _ md x hx, fors_part_drop w]
        have extracted := serialized_map_block (List.range p.a)
          (fun level => (forsNode o p tk prfKey seed {layer := l, tree := t, kind := 3, keypair := kp}
            (x.2*2^(p.a-level)+Nat.xor (x.1/2^level) 1) level : Bytes)) p.n j
          (fun _ _ => fors_node_width o w p tk prfKey seed _ _ _) (by simpa using hj)
        simpa [fors_offset_sibling x.2 x.1 p.a j hj] using extracted
  · apply thash_good _ (by inrange)
    intro w
    rw [canon_kind4 rfl]
    simp only [Id.instMonad, bind, pure]
    refine (gather _ _ []).trans ?_
    rw [List.nil_append, hsig w]
    exact (fors_sign_roots w _ md).trans rfl
end Components

/-- Index-width facts for every supported variant. -/
theorem variant_bounds (v : Variant) :
    (params v).len ≤ 256^4 ∧ 2^(params v).hp ≤ 256^4 ∧ (params v).d ≤ 256^4 ∧
    (params v).k*2^(params v).a ≤ 256^4 ∧ (params v).a < 256^4 ∧
    2^((params v).h-(params v).hp) ≤ 256^8 := by
  cases v <;> decide

/-- Requests a signing run may issue: unkeyed (derive_key, h_msg), the single
    message-PRF request, or a keyed thash/PRF request at an in-range address. -/
def SignReq (o : Oracle Id) (v : Variant) (sk msg : Bytes) (r : Request) : Prop :=
  r.mode ≠ 1 ∨
  r = ⟨1,"",deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n),
        slice sk (2*(params v).n) (params v).n ++ msg,(params v).n⟩ ∨
  KReq o (params v) (deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n)) (slice sk (2*(params v).n) (params v).n) r

theorem sign_good (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    Good (SignReq o v sk msg) (sign (logOracle o) v sk msg) (sign o v sk msg) := by
  obtain ⟨hlen, hH, hd, hMA, hA, hT⟩ := variant_bounds v
  have lift : ∀ r, KReq o (params v)
      (deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
      (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
      (slice sk (2*(params v).n) (params v).n) r → SignReq o v sk msg r :=
    fun r h => Or.inr (Or.inr h)
  simp only [sign]
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  apply Good.bind_id (Good.pure_id _)
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  refine Good.bind_id (Good.oracle o (Or.inr (Or.inl rfl))) ?_
  refine Good.bind_id (Good.oracle o (Or.inl (by show (2:Nat) ≠ 1; decide))) ?_
  have ht := Nat.lt_of_lt_of_le (digest_tree_bounded (params v) (hmsg o (params v)
    (keyed o (params v).n (deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (List.drop (3*(params v).n) sk) msg)) hT
  have hleaf := digest_leaf_bounded (params v) (hmsg o (params v)
    (keyed o (params v).n (deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (List.drop (3*(params v).n) sk) msg)
  have hleaf' := Nat.lt_of_lt_of_le hleaf hH
  apply Good.bind_id (Good.mono lift (forsSign_good 0 _ _ _ (by decide) ht hleaf' hMA hA))
  apply Good.bind_id (Good.mono lift (forsPkFromSig_good 0 _ _ _ _ (by decide) ht hleaf' hMA hA
    (fun _ => rfl)))
  apply Good.bind_id (Good.mono lift (htSign_good hlen hH _ _ _ hd ht hleaf))
  apply Good.bind_id (Good.mono lift (htRoot_good hlen hH _ _ _ _ hd ht hleaf (fun _ => rfl)))
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  good_tail

/-- Requests a key generation run may issue: unkeyed (ChaCha expansion,
    derive_key), or a keyed thash/PRF request at an in-range address. -/
def KeygenReq (o : Oracle Id) (v : Variant) (seed32 : Wire 32) (r : Request) : Prop :=
  r.mode ≠ 1 ∨
  KReq o (params v)
    (deriveKey o "DSM/sphincs/v2/thash"
      (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (deriveKey o "DSM/sphincs/v2/prf" ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
    (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) r

theorem keygen_good (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    Good (KeygenReq o v seed32) (generateKeypair (logOracle o) v seed32) (generateKeypair o v seed32) := by
  obtain ⟨hlen, hH, hd, _, _, _⟩ := variant_bounds v
  simp only [generateKeypair]
  refine Good.bind_id (Good.oracle o (Or.inl (by show (3:Nat) ≠ 1; decide))) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  apply Good.bind_id (Good.mono (fun r h => Or.inr h)
    (xmssNode_good _ (params v).hp hH (by dsimp only; omega) (by show 0 < 256^8; decide) hlen _ 0 (Nat.le_refl _)
      (by simp)))
  exact Good.pure' _

/-- Every keyed request issued while signing, under any oracle, is the
    message-PRF request, a thash request whose input starts with an in-range
    address, or a PRF request whose input ends with an in-range address. The
    instrumented run returns exactly the model signature. -/
theorem sign_requests_in_range (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    let p := params v
    let seed := slice sk (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)
    let msgKey := deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk p.n p.n)
    ((sign (logOracle o) v sk msg).run []).1 = sign o v sk msg ∧
    ∀ r ∈ ((sign (logOracle o) v sk msg).run []).2, r.mode = 1 →
      r = ⟨1,"",msgKey,seed ++ msg,p.n⟩ ∨
      (∃ (a : Adrs) (x : Bytes), a.InRange ∧ r = ⟨1,"",tk,a.bytes ++ x,p.n⟩) ∨
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",prfKey,seed ++ a.bytes,p.n⟩) := by
  intro p seed tk prfKey msgKey
  obtain ⟨hval, hlog⟩ := (sign_good o v sk msg).run_empty
  refine ⟨hval, fun r hr hm => ?_⟩
  rcases hlog r hr with h | h | h | h
  · exact absurd hm h
  · exact Or.inl h
  · obtain ⟨a, x, ha, e, _⟩ := h
    exact Or.inr (Or.inl ⟨a, x, ha, e⟩)
  · exact Or.inr (Or.inr h)

/-- Every keyed request issued by key generation, under any oracle, is a
    thash request whose input starts with an in-range address or a PRF
    request whose input ends with an in-range address. -/
theorem keygen_requests_in_range (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    let p := params v
    let expanded := o ⟨3,"ChaCha20Rng",[],seed32.val,3*p.n⟩
    let seed := slice expanded (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
    ((generateKeypair (logOracle o) v seed32).run []).1 = generateKeypair o v seed32 ∧
    ∀ r ∈ ((generateKeypair (logOracle o) v seed32).run []).2, r.mode = 1 →
      (∃ (a : Adrs) (x : Bytes), a.InRange ∧ r = ⟨1,"",tk,a.bytes ++ x,p.n⟩) ∨
      (∃ a : Adrs, a.InRange ∧ r = ⟨1,"",prfKey,seed ++ a.bytes,p.n⟩) := by
  intro p expanded seed tk prfKey
  obtain ⟨hval, hlog⟩ := (keygen_good o v seed32).run_empty
  refine ⟨hval, fun r hr hm => ?_⟩
  rcases hlog r hr with h | h | h
  · exact absurd hm h
  · obtain ⟨a, x, ha, e, _⟩ := h
    exact Or.inl ⟨a, x, ha, e⟩
  · exact Or.inr h

/-- The prefix-closed (`AllReq`) form of the signing invariant. -/
theorem sign_allReq (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    AllReq (SignReq o v sk msg) (sign (logOracle o) v sk msg) :=
  (sign_good o v sk msg).allReq

theorem keygen_allReq (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    AllReq (KeygenReq o v seed32) (generateKeypair (logOracle o) v seed32) :=
  (keygen_good o v seed32).allReq

#print axioms sign_good
#print axioms keygen_good
#print axioms sign_requests_in_range
#print axioms keygen_requests_in_range
#print axioms sign_allReq
#print axioms keygen_allReq
end DSM.Sphincs
