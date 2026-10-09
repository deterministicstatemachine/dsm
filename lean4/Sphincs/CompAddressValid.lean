-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.AddressRange
import Sphincs.CompAddress

/- Modular proof, strategy revision (map §13, item T4): every address DSM's
   signer and key generation issue is valid for its type in EasyCrypt's
   address space.

   C18 (`AddressRange`) shows that every keyed request is at an `InRange`
   address. This module runs the same request-logging argument (`Good`) with
   a stronger request predicate, `EReq`:

   * a keyed thash request is at an address `a` with `EcValid p (ecIdx a)`
     (EasyCrypt's `valid_adrsidxs`, transcribed in C74), and
   * a keyed PRF request is at `prfAdr b` for an EcValid address `b` that is
     a chain address with hash index 0 or a FORS leaf address (height 0): the
     addresses at which EasyCrypt's `skg` is called. `prfAdr` sets type 0 to
     5 and type 3 to 6 and keeps the other fields; it is injective on those
     addresses (`prfAdr_inj`).

   The index ranges are threaded as hypotheses (chain hash index < 15, chain
   index < len, key pair < 2^h', tree < nr_trees(layer), layer < d, XMSS
   breadth < 2^(h'-height), FORS breadth < k*2^(a-height)) and discharged for
   every `params v`. The instrumented runs return the model values, under
   every oracle. Nothing here is about the hashed values. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- The DSM PRF address of an EasyCrypt `skg` address. -/
def prfAdr (a : Adrs) : Adrs :=
  if a.kind = 0 then {a with kind := 5} else if a.kind = 3 then {a with kind := 6} else a

theorem prfAdr_inj {b b' : Adrs} (hb : b.kind = 0 ∨ b.kind = 3) (hb' : b'.kind = 0 ∨ b'.kind = 3)
    (e : prfAdr b = prfAdr b') : b = b' := by
  cases b; cases b'
  simp only at hb hb'
  rcases hb with h | h <;> rcases hb' with h' | h' <;> subst h h' <;>
    simp_all [prfAdr]

section
variable (p : Params) (tk prfKey seed : Bytes)

/-- A keyed thash request at an EasyCrypt-valid address. -/
def EThash (r : Request) : Prop :=
  ∃ (a : Adrs) (x : Bytes), EcValid p (ecIdx a) ∧ r = ⟨1,"",tk,a.bytes ++ x,p.n⟩

/-- A keyed PRF request at the DSM image of an EasyCrypt `skg` address. -/
def EPrf (r : Request) : Prop :=
  ∃ b : Adrs, EcValid p (ecIdx b) ∧ (b.kind = 0 ∧ b.hash = 0 ∨ b.kind = 3 ∧ b.chain = 0) ∧
    r = ⟨1,"",prfKey,seed ++ (prfAdr b).bytes,p.n⟩

def EReq (r : Request) : Prop := EThash p tk r ∨ EPrf p prfKey seed r
end

/-! EasyCrypt validity of one address, per type. -/
section
variable {p : Params}

theorem ev0 {a : Adrs} (hk : a.kind = 0) (hh : a.hash < 15) (hc : a.chain < p.len)
    (hkp : a.keypair < 2^p.hp) (ht : a.tree < nrTrees p a.layer) (hl : a.layer < p.d) :
    EcValid p (ecIdx a) := ⟨rfl, Or.inl ⟨hh, hc, hkp, hk, ht, hl⟩⟩
theorem ev1 {a : Adrs} (hh : a.hash = 0) (hc : a.chain = 0) (hkp : a.keypair < 2^p.hp)
    (hk : a.kind = 1) (ht : a.tree < nrTrees p a.layer) (hl : a.layer < p.d) :
    EcValid p (ecIdx a) := ⟨rfl, Or.inr (Or.inl ⟨hh, hc, hkp, hk, ht, hl⟩)⟩
theorem ev2 {a : Adrs} (hh : a.hash < 2^(p.hp - a.chain)) (hc : a.chain ≤ p.hp)
    (hkp : a.keypair = 0) (hk : a.kind = 2) (ht : a.tree < nrTrees p a.layer) (hl : a.layer < p.d) :
    EcValid p (ecIdx a) := ⟨rfl, Or.inr (Or.inr (Or.inl ⟨hh, hc, hkp, hk, ht, hl⟩))⟩
theorem ev3 {a : Adrs} (hh : a.hash < p.k * 2^(p.a - a.chain)) (hc : a.chain ≤ p.a)
    (hkp : a.keypair < 2^p.hp) (hk : a.kind = 3) (ht : a.tree < nrTrees p a.layer)
    (hl : a.layer = 0) : EcValid p (ecIdx a) :=
  ⟨rfl, Or.inr (Or.inr (Or.inr (Or.inl ⟨hh, hc, hkp, hk, ht, hl⟩)))⟩
theorem ev4 {a : Adrs} (hh : a.hash = 0) (hc : a.chain = 0) (hkp : a.keypair < 2^p.hp)
    (hk : a.kind = 4) (ht : a.tree < nrTrees p a.layer) (hl : a.layer = 0) :
    EcValid p (ecIdx a) := ⟨rfl, Or.inr (Or.inr (Or.inr (Or.inr ⟨hh, hc, hkp, hk, ht, hl⟩)))⟩

/-- Trees of layer `layer` are the parents of the trees of layer `layer - 1`. -/
theorem next_tree_ev (layer tree : Nat) (hl : layer < p.d) (h1 : 1 ≤ layer)
    (ht : tree < nrTrees p (layer-1)) : (nextLayer p tree).2 < nrTrees p layer := by
  unfold nrTrees at *
  simp only [nextLayer]
  have e : p.hp * (p.d - (layer-1) - 1) = p.hp * (p.d - layer - 1) + p.hp := by
    rw [show p.d - (layer-1) - 1 = (p.d - layer - 1) + 1 by omega, Nat.mul_succ]
  rw [e, Nat.pow_add] at ht
  exact (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 ht
end

macro "fld" : tactic =>
  `(tactic| ((try dsimp only [Adrs.setType]) <;> first | rfl | assumption | omega |
      (simp only [Nat.sub_zero, Nat.one_mul] <;> first | assumption | omega)))

section Components
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

local notation "E" => EReq p tk prfKey seed
local notation "LO" => logOracle o

theorem thash_ev (a : Adrs) (ha : EcValid p (ecIdx a)) (x : Bytes) :
    Good E (thash LO p tk a x) (thash o p tk a x) :=
  Good.oracle o (Or.inl ⟨a, x, ha, rfl⟩)

theorem prf_chain_ev (a : Adrs) (i : Nat) (hk : a.kind = 0) (hh : a.hash = 0) (hi : i < p.len)
    (hkp : a.keypair < 2^p.hp) (ht : a.tree < nrTrees p a.layer) (hl : a.layer < p.d) :
    Good E (prf LO p prfKey seed {a.setType 5 with keypair := a.keypair, chain := i})
      (prf o p prfKey seed {a.setType 5 with keypair := a.keypair, chain := i}) := by
  have e : prfAdr {a with chain := i} = {a.setType 5 with keypair := a.keypair, chain := i} := by
    cases a
    simp only at hk hh
    subst hk hh
    first | rfl | simp [prfAdr, Adrs.setType]
  refine Good.oracle o (Or.inr ⟨{a with chain := i}, ?_, Or.inl ⟨hk, hh⟩, ?_⟩)
  · exact ev0 hk (by dsimp only; omega) hi hkp ht hl
  · exact congrArg (fun z : Adrs => (⟨1,"",prfKey,seed ++ z.bytes,p.n⟩ : Request)) e.symm

theorem chain_ev (a : Adrs) (hk : a.kind = 0) (hc : a.chain < p.len) (hkp : a.keypair < 2^p.hp)
    (ht : a.tree < nrTrees p a.layer) (hl : a.layer < p.d) (x : Bytes) (start steps : Nat)
    (hb : start + steps ≤ 15) :
    Good E (chain LO p tk a x start steps) (chain o p tk a x start steps) := by
  induction steps generalizing x start with
  | zero => exact Good.pure' x
  | succ s ih =>
    simp only [chain]
    apply Good.bind_id (thash_ev _ (ev0 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _)
    exact ih _ _ (by omega)

theorem wotsSign_ev (b : Adrs) (idx : Nat) (msg : Bytes)
    (hl : b.layer < p.d) (ht : b.tree < nrTrees p b.layer) (hidx : idx < 2^p.hp) :
    Good E (wotsSign LO p tk prfKey seed {b.setType 0 with keypair := idx} msg)
      (wotsSign o p tk prfKey seed {b.setType 0 with keypair := idx} msg) := by
  simp only [wotsSign]
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro x hx acc
  obtain ⟨hd, hi⟩ := zipIdx_mem hx
  have hd' := wots_digit_bound p msg _ hd
  rw [wots_digit_count] at hi
  apply Good.bind_id (prf_chain_ev ({b.setType 0 with keypair := idx} : Adrs) _
    (by fld) (by fld) hi (by fld) (by fld) (by fld))
  apply Good.bind_id (chain_ev {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
    (by fld) (by fld) (by fld) (by fld) (by fld)
    _ 0 _ (by omega))
  good_tail

theorem wotsCompress_ev (b : Adrs) (idx : Nat) (tops : Bytes)
    (hl : b.layer < p.d) (ht : b.tree < nrTrees p b.layer) (hidx : idx < 2^p.hp) :
    Good E (wotsCompress LO p tk {b.setType 0 with keypair := idx} tops)
      (wotsCompress o p tk {b.setType 0 with keypair := idx} tops) :=
  thash_ev _ (ev1 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _

theorem wotsPkgen_ev (b : Adrs) (idx : Nat)
    (hl : b.layer < p.d) (ht : b.tree < nrTrees p b.layer) (hidx : idx < 2^p.hp) :
    Good E (wotsPkgen LO p tk prfKey seed {b.setType 0 with keypair := idx})
      (wotsPkgen o p tk prfKey seed {b.setType 0 with keypair := idx}) := by
  simp only [wotsPkgen]
  apply Good.bind_id
  · apply Good.forIn'
    intro i hi acc
    have hi' : i < p.len := by simpa using hi
    apply Good.bind_id (prf_chain_ev ({b.setType 0 with keypair := idx} : Adrs) _
      (by fld) (by fld) hi' (by fld) (by fld) (by fld))
    apply Good.bind_id (chain_ev {({b.setType 0 with keypair := idx} : Adrs) with chain := i}
      (by fld) (by fld) (by fld) (by fld) (by fld)
      _ 0 _ (by omega))
    good_tail
  · exact wotsCompress_ev b idx _ hl ht hidx

theorem wotsPkFromSig_ev (b : Adrs) (idx : Nat) (sig msg : Bytes)
    (hl : b.layer < p.d) (ht : b.tree < nrTrees p b.layer) (hidx : idx < 2^p.hp) :
    Good E (wotsPkFromSig LO p tk {b.setType 0 with keypair := idx} sig msg)
      (wotsPkFromSig o p tk {b.setType 0 with keypair := idx} sig msg) := by
  simp only [wotsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x hx acc
    obtain ⟨hd, hi⟩ := zipIdx_mem hx
    have hd' := wots_digit_bound p msg _ hd
    rw [wots_digit_count] at hi
    apply Good.bind_id (chain_ev {({b.setType 0 with keypair := idx} : Adrs) with chain := x.2}
      (by fld) (by fld) (by fld) (by fld) (by fld)
      _ _ _ (by omega))
    good_tail
  · exact wotsCompress_ev b idx _ hl ht hidx

theorem xmssNode_ev (a : Adrs) (hl : a.layer < p.d) (ht : a.tree < nrTrees p a.layer)
    (h idx : Nat) (hh : h ≤ p.hp) (hidx : idx < 2^(p.hp-h)) :
    Good E (xmssNode LO p tk prfKey seed a idx h) (xmssNode o p tk prfKey seed a idx h) := by
  induction h generalizing idx with
  | zero => exact wotsPkgen_ev a idx hl ht (by simpa using hidx)
  | succ h ih =>
    simp only [xmssNode]
    have e := pow_sub_succ p.hp h hh
    apply Good.bind_id (ih (2*idx) (by omega) (by omega))
    apply Good.bind_id (ih (2*idx+1) (by omega) (by omega))
    exact thash_ev _ (ev2 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _

/-- The authentication walk, for XMSS (`M = 1`, `A = h'`) and FORS (`M = k`,
    `A = a`): the node at height `lv+1` has breadth index below
    `M * 2^(A-(lv+1))`. -/
theorem authWalk_ev (a : Adrs) (M A : Nat)
    (hv : ∀ lv i, lv + 1 ≤ A → i < M * 2^(A-(lv+1)) →
      EcValid p (ecIdx {a with chain := lv+1, hash := i}))
    (remaining level localIndex globalIndex : Nat) (node auth : Bytes)
    (hrem : level + remaining ≤ A) (hg : globalIndex < M * 2^(A-level)) :
    Good E (authWalk LO p tk a localIndex globalIndex node auth level remaining)
      (authWalk o p tk a localIndex globalIndex node auth level remaining) := by
  induction remaining generalizing level localIndex globalIndex node with
  | zero => exact Good.pure' _
  | succ r ih =>
    simp only [authWalk]
    have e : M*2^(A-level) = M*2^(A-(level+1))*2 := by
      rw [pow_sub_succ A level (by omega), Nat.mul_assoc]
    have hg' : globalIndex/2 < M*2^(A-(level+1)) := by omega
    apply Good.bind_id (thash_ev _ (hv level _ (by omega) hg') _)
    exact ih (level+1) _ _ _ (by omega) hg'

theorem xmssPkFromSig_ev (a : Adrs) (idx : Nat) (sig msg : Bytes)
    (hl : a.layer < p.d) (ht : a.tree < nrTrees p a.layer) (hidx : idx < 2^p.hp) :
    Good E (xmssPkFromSig LO p tk a idx sig msg) (xmssPkFromSig o p tk a idx sig msg) := by
  simp only [xmssPkFromSig]
  apply Good.bind_id (wotsPkFromSig_ev a idx _ msg hl ht hidx)
  simp only [authRoot]
  apply authWalk_ev (a.setType 2) 1 p.hp _ _ 0 _ _ _ _ (by omega) (by simpa using hidx)
  intro lv i h1 h2
  exact ev2 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)

theorem xmssSign_ev (a : Adrs) (idx : Nat) (msg : Bytes)
    (hl : a.layer < p.d) (ht : a.tree < nrTrees p a.layer) (hidx : idx < 2^p.hp) :
    Good E (xmssSign LO p tk prfKey seed a idx msg) (xmssSign o p tk prfKey seed a idx msg) := by
  simp only [xmssSign]
  apply Good.bind_id
  · apply Good.forIn'
    intro level hlev acc
    have hlev' : level < p.hp := by simpa using hlev
    apply Good.bind_id (xmssNode_ev a hl ht level _ (by omega)
      (sibling_bound p.hp level idx hidx hlev'))
    good_tail
  · apply Good.bind_id (wotsSign_ev a idx msg hl ht hidx)
    good_tail

theorem htSignTail_ev (remaining layer tree : Nat) (node : Bytes)
    (h1 : 1 ≤ layer) (hl : layer + remaining < p.d) (ht : tree < nrTrees p (layer-1)) :
    Good E (htSignTail LO p tk prfKey seed layer tree node (remaining+1))
      (htSignTail o p tk prfKey seed layer tree node (remaining+1)) := by
  induction remaining generalizing layer tree node with
  | zero =>
    simp only [htSignTail]
    have hn := next_tree_ev layer tree (by omega) h1 ht
    apply Good.bind_id (xmssSign_ev _ _ node (by dsimp only; omega)
      (by dsimp only; exact hn) (next_layer_leaf_bounded p tree))
    apply Good.ite' (fun _ => Good.pure' _)
    intro hne; exact (hne trivial).elim
  | succ r ih =>
    simp only [htSignTail]
    have hn := next_tree_ev layer tree (by omega) h1 ht
    apply Good.bind_id (xmssSign_ev _ _ node (by dsimp only; omega)
      (by dsimp only; exact hn) (next_layer_leaf_bounded p tree))
    apply Good.ite' (fun _ => Good.pure' _)
    intro _
    apply Good.bind_id (Good.pure_id _)
    apply Good.bind_id (xmssPkFromSig_ev _ _ _ node (by dsimp only; omega)
      (by dsimp only; exact hn) (next_layer_leaf_bounded p tree))
    apply Good.bind_id (ih _ _ _ (by omega) (by omega) (by simpa using hn))
    exact Good.pure' _

theorem htRootTail_ev (remaining layer tree : Nat) (node sig : Bytes)
    (h1 : 1 ≤ layer) (hl : layer + remaining ≤ p.d) (ht : tree < nrTrees p (layer-1)) :
    Good E (htRootTail LO p tk layer tree node sig remaining)
      (htRootTail o p tk layer tree node sig remaining) := by
  induction remaining generalizing layer tree node sig with
  | zero => exact Good.pure' _
  | succ r ih =>
    simp only [htRootTail]
    have hn := next_tree_ev layer tree (by omega) h1 ht
    apply Good.bind_id (xmssPkFromSig_ev _ _ _ node (by dsimp only; omega)
      (by dsimp only; exact hn) (next_layer_leaf_bounded p tree))
    exact ih _ _ _ _ (by omega) (by omega) (by simpa using hn)

theorem htSign_ev (msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) (ht : tree < nrTrees p 0)
    (hleaf : leaf < 2^p.hp) :
    Good E (htSign LO p tk prfKey seed msg tree leaf) (htSign o p tk prfKey seed msg tree leaf) := by
  simp only [htSign]
  apply Good.bind_id (xmssSign_ev _ _ msg (by dsimp only; omega) ht hleaf)
  apply Good.bind_id (xmssPkFromSig_ev _ _ _ msg (by dsimp only; omega) ht hleaf)
  cases hdc : p.d - 1 with
  | zero => exact Good.bind_id (Good.pure' _) (Good.pure' _)
  | succ r =>
    apply Good.bind_id (htSignTail_ev r 1 tree _ (Nat.le_refl _) (by omega) ht)
    exact Good.pure' _

theorem htRoot_ev (sig msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) (ht : tree < nrTrees p 0)
    (hleaf : leaf < 2^p.hp) :
    Good E (htRoot LO p tk sig msg tree leaf) (htRoot o p tk sig msg tree leaf) := by
  simp only [htRoot]
  apply Good.bind_id (xmssPkFromSig_ev _ _ _ msg (by dsimp only; omega) ht hleaf)
  exact htRootTail_ev _ 1 tree _ _ (Nat.le_refl _) (by omega) ht

/-! FORS, at the layer-0 address `(tree t, type 3, key pair kp)`. -/

theorem forsSecret_ev (t kp idx : Nat) (ht : t < nrTrees p 0) (hkp : kp < 2^p.hp)
    (hidx : idx < p.k * 2^p.a) :
    Good E (forsSecret LO p prfKey seed {tree := t, kind := 3, keypair := kp} idx)
      (forsSecret o p prfKey seed {tree := t, kind := 3, keypair := kp} idx) := by
  have e : prfAdr ({tree := t, kind := 3, keypair := kp, hash := idx} : Adrs) =
      {({tree := t, kind := 3, keypair := kp} : Adrs).setType 6 with keypair := kp, hash := idx} := by
    first | rfl | simp [prfAdr, Adrs.setType]
  refine Good.oracle o (Or.inr ⟨{tree := t, kind := 3, keypair := kp, hash := idx}, ?_,
    Or.inr ⟨rfl, rfl⟩, ?_⟩)
  · exact ev3 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)
  · exact congrArg (fun z : Adrs => (⟨1,"",prfKey,seed ++ z.bytes,p.n⟩ : Request)) e.symm

theorem forsNode_ev (t kp : Nat) (ht : t < nrTrees p 0) (hkp : kp < 2^p.hp)
    (h idx : Nat) (hh : h ≤ p.a) (hidx : idx < p.k * 2^(p.a-h)) :
    Good E (forsNode LO p tk prfKey seed {tree := t, kind := 3, keypair := kp} idx h)
      (forsNode o p tk prfKey seed {tree := t, kind := 3, keypair := kp} idx h) := by
  induction h generalizing idx with
  | zero =>
    simp only [forsNode]
    apply Good.bind_id (forsSecret_ev t kp idx ht hkp (by simpa using hidx))
    exact thash_ev _ (ev3 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _
  | succ h ih =>
    simp only [forsNode]
    have e : p.k*2^(p.a-h) = p.k*2^(p.a-(h+1))*2 := by
      rw [pow_sub_succ p.a h hh, Nat.mul_assoc]
    apply Good.bind_id (ih (2*idx) (by omega) (by omega))
    apply Good.bind_id (ih (2*idx+1) (by omega) (by omega))
    exact thash_ev _ (ev3 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _

theorem forsSign_ev (t kp : Nat) (md : Bytes) (ht : t < nrTrees p 0) (hkp : kp < 2^p.hp) :
    Good E (forsSign LO p tk prfKey seed {tree := t, kind := 3, keypair := kp} md)
      (forsSign o p tk prfKey seed {tree := t, kind := 3, keypair := kp} md) := by
  simp only [forsSign]
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro x hx acc
  obtain ⟨hd, hi⟩ := zipIdx_mem hx
  have hd' := base2b_digit_bound md p.a p.k _ hd
  have hi' : x.2 < p.k := by simpa [base2b] using hi
  apply Good.bind_id (forsSecret_ev t kp _ ht hkp (offset_lt hi' hd'))
  apply Good.bind_id _ (Good.pure' _)
  apply Good.forIn'
  intro level hlev acc'
  have hlev' : level < p.a := by simpa using hlev
  apply Good.bind_id (forsNode_ev t kp ht hkp level _ (by omega)
    (offset_lt hi' (sibling_bound p.a level x.1 hd' hlev')))
  good_tail

theorem forsPkFromSig_ev (t kp : Nat) (sig md : Bytes) (ht : t < nrTrees p 0) (hkp : kp < 2^p.hp) :
    Good E (forsPkFromSig LO p tk {tree := t, kind := 3, keypair := kp} sig md)
      (forsPkFromSig o p tk {tree := t, kind := 3, keypair := kp} sig md) := by
  simp only [forsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x hx acc
    obtain ⟨hd, hi⟩ := zipIdx_mem hx
    have hd' := base2b_digit_bound md p.a p.k _ hd
    have hi' : x.2 < p.k := by simpa [base2b] using hi
    have hg := offset_lt hi' hd'
    apply Good.bind_id (thash_ev _ (ev3 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _)
    apply Good.bind_id (authWalk_ev _ p.k p.a ?_ _ 0 _ _ _ _ (by omega) (by simpa using hg))
    · good_tail
    · intro lv i h1 h2
      exact ev3 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)
  · exact thash_ev _ (ev4 (by fld) (by fld) (by fld) (by fld) (by fld) (by fld)) _
end Components

/-- Layer-0 trees and the hypertree depth, for every DSM variant. -/
theorem variant_ec_layers (v : Variant) : 1 ≤ (params v).d := by cases v <;> decide

/-- Requests a signing run may issue: unkeyed, the message-PRF request, or a
    keyed thash/PRF request at an EasyCrypt-valid address. -/
def SignEReq (o : Oracle Id) (v : Variant) (sk msg : Bytes) (r : Request) : Prop :=
  r.mode ≠ 1 ∨
  r = ⟨1,"",deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n),
        slice sk (2*(params v).n) (params v).n ++ msg,(params v).n⟩ ∨
  EReq (params v) (deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
    (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n)) (slice sk (2*(params v).n) (params v).n) r

theorem sign_ev (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    Good (SignEReq o v sk msg) (sign (logOracle o) v sk msg) (sign o v sk msg) := by
  have hd := variant_ec_layers v
  have lift : ∀ r, EReq (params v)
      (deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
      (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
      (slice sk (2*(params v).n) (params v).n) r → SignEReq o v sk msg r :=
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
  have ht : ∀ dg, (splitDigest (params v) dg).tree < nrTrees (params v) 0 := fun dg => by
    rw [nrTrees_zero]; exact digest_tree_bounded _ _
  have hleaf : ∀ dg, (splitDigest (params v) dg).leaf < 2^(params v).hp := fun dg =>
    digest_leaf_bounded _ _
  apply Good.bind_id (Good.mono lift (forsSign_ev _ _ _ (ht _) (hleaf _)))
  apply Good.bind_id (Good.mono lift (forsPkFromSig_ev _ _ _ _ (ht _) (hleaf _)))
  apply Good.bind_id (Good.mono lift (htSign_ev _ _ _ hd (ht _) (hleaf _)))
  apply Good.bind_id (Good.mono lift (htRoot_ev _ _ _ _ hd (ht _) (hleaf _)))
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  good_tail

/-- Requests a key generation run may issue: unkeyed, or a keyed thash/PRF
    request at an EasyCrypt-valid address. -/
def KeygenEReq (o : Oracle Id) (v : Variant) (seed32 : Wire 32) (r : Request) : Prop :=
  r.mode ≠ 1 ∨
  EReq (params v)
    (deriveKey o "DSM/sphincs/v2/thash"
      (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n))
    (deriveKey o "DSM/sphincs/v2/prf" ((o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩).take (params v).n))
    (slice (o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩) (2*(params v).n) (params v).n) r

theorem keygen_ev (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    Good (KeygenEReq o v seed32) (generateKeypair (logOracle o) v seed32)
      (generateKeypair o v seed32) := by
  have hd := variant_ec_layers v
  simp only [generateKeypair]
  refine Good.bind_id (Good.oracle o (Or.inl (by show (3:Nat) ≠ 1; decide))) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  refine Good.bind_id (Good.oracle o (Or.inl Nat.zero_ne_one)) ?_
  apply Good.bind_id (Good.mono (fun r h => Or.inr h)
    (xmssNode_ev _ (by dsimp only; omega) (by unfold nrTrees; exact Nat.pow_pos (by decide))
      _ 0 (Nat.le_refl _) (by simp)))
  exact Good.pure' _

/-- Every keyed request issued while signing, under any oracle, is the
    message-PRF request, a thash request at an EasyCrypt-valid address, or a
    PRF request at the DSM image of an EasyCrypt `skg` address. The
    instrumented run returns exactly the model signature. -/
theorem sign_requests_ec_valid (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    let p := params v
    let seed := slice sk (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)
    let msgKey := deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk p.n p.n)
    ((sign (logOracle o) v sk msg).run []).1 = sign o v sk msg ∧
    ∀ r ∈ ((sign (logOracle o) v sk msg).run []).2, r.mode = 1 →
      r = ⟨1,"",msgKey,seed ++ msg,p.n⟩ ∨ EThash p tk r ∨ EPrf p prfKey seed r := by
  intro p seed tk prfKey msgKey
  obtain ⟨hval, hlog⟩ := (sign_ev o v sk msg).run_empty
  refine ⟨hval, fun r hr hm => ?_⟩
  rcases hlog r hr with h | h | h | h
  · exact absurd hm h
  · exact Or.inl h
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr h)

/-- Every keyed request issued by key generation, under any oracle, is a thash
    request at an EasyCrypt-valid address or a PRF request at the DSM image
    of an EasyCrypt `skg` address. -/
theorem keygen_requests_ec_valid (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    let p := params v
    let expanded := o ⟨3,"ChaCha20Rng",[],seed32.val,3*p.n⟩
    let seed := slice expanded (2*p.n) p.n
    let tk := deriveKey o "DSM/sphincs/v2/thash" seed
    let prfKey := deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
    ((generateKeypair (logOracle o) v seed32).run []).1 = generateKeypair o v seed32 ∧
    ∀ r ∈ ((generateKeypair (logOracle o) v seed32).run []).2, r.mode = 1 →
      EThash p tk r ∨ EPrf p prfKey seed r := by
  intro p expanded seed tk prfKey
  obtain ⟨hval, hlog⟩ := (keygen_ev o v seed32).run_empty
  refine ⟨hval, fun r hr hm => ?_⟩
  rcases hlog r hr with h | h
  · exact absurd hm h
  · exact h

#print axioms prfAdr_inj
#print axioms sign_requests_ec_valid
#print axioms keygen_requests_ec_valid
end DSM.Sphincs.Comp
