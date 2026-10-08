-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSim
import Sphincs.RomBound

/- DSM's signer as a symbolic program. Each model function has a symbolic
   twin over symbolic bytes (`SB`, lists of literal bytes and handles); every
   oracle request is a challenger step whose answer is a handle. Control flow
   that depends on a hash output (the h_msg digest, the WOTS message digits
   of a root, the signer's self-check) first reveals the value. `sim_*`:
   the real run of each twin simulates the model function itself, run as a
   query tree against the lazy random oracle, with resolved results equal. -/
namespace DSM.Rom
open DSM.Sphincs

abbrev SB := List SV

theorem sres_append (t : List Nat) : ∀ (x y : SB), sres t (x ++ y) = sres t x ++ sres t y
  | [], _ => rfl
  | v :: x, y => by simp only [List.cons_append, sres, sres_append t x y, List.append_assoc]

/-- Resolved symbolic bytes equal concrete bytes. -/
def RB (t : List Nat) (x : SB) (b : Bytes) : Prop := sres t x = b

def wid : SV → Nat
  | .lit b => b.length
  | .hid _ w => w

/-- Every element is `n` bytes wide. -/
def WN (n : Nat) (x : SB) : Prop := ∀ v ∈ x, wid v = n
/-- Resolved and `n`-byte elements. -/
def RBn (t : List Nat) (n : Nat) (x : SB) (b : Bytes) : Prop := sres t x = b ∧ WN n x

theorem res_len (t : List Nat) (v : SV) : (v.res t).length = wid v := by
  cases v <;> simp [SV.res, wid, be_width]

theorem WN_append {n : Nat} {x y : SB} (hx : WN n x) (hy : WN n y) : WN n (x ++ y) := by
  intro v hv; rcases List.mem_append.mp hv with h | h; exact hx v h; exact hy v h
theorem WN_take {n : Nat} {x : SB} (k : Nat) (hx : WN n x) : WN n (x.take k) :=
  fun v hv => hx v (List.mem_of_mem_take hv)
theorem WN_drop {n : Nat} {x : SB} (k : Nat) (hx : WN n x) : WN n (x.drop k) :=
  fun v hv => hx v (List.mem_of_mem_drop hv)
theorem WN_nil (n : Nat) : WN n [] := fun _ h => by cases h

theorem sres_take (t : List Nat) (n : Nat) : ∀ (x : SB) (k : Nat), WN n x →
    sres t (x.take k) = (sres t x).take (k*n)
  | [], k, _ => by simp [sres]
  | v :: x, 0, _ => by simp [sres]
  | v :: x, k+1, hw => by
    have hv : (v.res t).length = n := by rw [res_len]; exact hw v (by simp)
    simp only [List.take_succ_cons, sres]
    rw [sres_take t n x k (fun u hu => hw u (by simp [hu])), List.take_append,
      List.take_of_length_le (l := v.res t) (by rw [hv, Nat.succ_mul]; omega), hv]
    congr 2; rw [Nat.succ_mul]; omega

theorem sres_drop (t : List Nat) (n : Nat) : ∀ (x : SB) (k : Nat), WN n x →
    sres t (x.drop k) = (sres t x).drop (k*n)
  | [], k, _ => by simp [sres]
  | v :: x, 0, _ => by simp [sres]
  | v :: x, k+1, hw => by
    have hv : (v.res t).length = n := by rw [res_len]; exact hw v (by simp)
    simp only [List.drop_succ_cons, sres]
    rw [sres_drop t n x k (fun u hu => hw u (by simp [hu])), List.drop_append,
      List.drop_eq_nil_of_le (as := v.res t) (by rw [hv, Nat.succ_mul]; omega), hv, List.nil_append]
    congr 1; rw [Nat.succ_mul]; omega

/-- Symbolic slice, in elements. -/
def sSlice (x : SB) (i k : Nat) : SB := (x.drop i).take k

theorem sres_sSlice (t : List Nat) (n : Nat) (x : SB) (i k : Nat) (hw : WN n x) :
    sres t (sSlice x i k) = slice (sres t x) (i*n) (k*n) := by
  unfold sSlice slice
  rw [sres_take t n _ k (WN_drop i hw), sres_drop t n x i hw]

theorem RBn_sSlice {t : List Nat} {n : Nat} {x : SB} {b : Bytes} (h : RBn t n x b) (i k : Nat) :
    RBn t n (sSlice x i k) (slice b (i*n) (k*n)) :=
  ⟨by rw [sres_sSlice t n x i k h.2, h.1], WN_take k (WN_drop i h.2)⟩

theorem RBn_take {t : List Nat} {n : Nat} {x : SB} {b : Bytes} (h : RBn t n x b) (k : Nat) :
    RBn t n (x.take k) (b.take (k*n)) := ⟨by rw [sres_take t n x k h.2, h.1], WN_take k h.2⟩

theorem RBn_drop {t : List Nat} {n : Nat} {x : SB} {b : Bytes} (h : RBn t n x b) (k : Nat) :
    RBn t n (x.drop k) (b.drop (k*n)) := ⟨by rw [sres_drop t n x k h.2, h.1], WN_drop k h.2⟩

theorem RBn_append {t : List Nat} {n : Nat} {x y : SB} {a b : Bytes} (hx : RBn t n x a) (hy : RBn t n y b) :
    RBn t n (x ++ y) (a ++ b) := ⟨by rw [sres_append, hx.1, hy.1], WN_append hx.2 hy.2⟩

def sAsk (r : SReq) : Prog SB := .askC r (fun v => .done [v])
def sDeriveKey (context : String) (input : SB) : Prog SB := sAsk ⟨0, context, [], input, 32⟩
def sKeyed (n : Nat) (key input : SB) : Prog SB := sAsk ⟨1, "", key, input, n⟩
def sThash (p : Params) (tk : SB) (a : Adrs) (x : SB) : Prog SB := sKeyed p.n tk (.lit a.bytes :: x)
def sPrf (p : Params) (key seed : SB) (a : Adrs) : Prog SB := sKeyed p.n key (seed ++ [.lit a.bytes])
def sHmsg (p : Params) (r seed root : SB) (msg : Bytes) : Prog SB :=
  sAsk ⟨2, "DSM/sphincs/v2/h-msg", [], r ++ seed ++ root ++ [.lit msg], p.m⟩

section
variable {t : List Nat}

theorem sim_ask (r : SReq) (q : Request) (hq : r.res t = q) :
    Sim t (sAsk r) (challengerOracle q) (RBn t r.outLen) := by
  subst hq
  exact Sim.askC r _ _ (fun i => Sim.pure' ⟨by simp [sres, SV.res], fun v hv => by simp at hv; subst hv; rfl⟩)

theorem sim_deriveKey (c : String) (x : SB) (x' : Bytes) (hx : RB t x x') :
    Sim t (sDeriveKey c x) (deriveKey challengerOracle c x') (RBn t 32) :=
  sim_ask _ _ (by simp only [RB] at hx; simp [SReq.res, sres, hx])

theorem sim_keyed (n : Nat) (k i : SB) (k' i' : Bytes) (hk : RB t k k') (hi : RB t i i') :
    Sim t (sKeyed n k i) (keyed challengerOracle n k' i') (RBn t n) :=
  sim_ask _ _ (by simp only [RB] at hk hi; simp [SReq.res, hk, hi])

theorem sim_thash (p : Params) (tk : SB) (tk' : Bytes) (a : Adrs) (x : SB) (x' : Bytes)
    (htk : RB t tk tk') (hx : RB t x x') :
    Sim t (sThash p tk a x) (thash challengerOracle p tk' a x') (RBn t p.n) :=
  sim_keyed _ _ _ _ _ htk (by simp only [RB] at hx ⊢; simp [sres, SV.res, hx])

theorem sim_prf (p : Params) (k s : SB) (k' s' : Bytes) (a : Adrs) (hk : RB t k k') (hs : RB t s s') :
    Sim t (sPrf p k s a) (prf challengerOracle p k' s' a) (RBn t p.n) :=
  sim_keyed _ _ _ _ _ hk (by simp only [RB] at hs ⊢; simp [sres_append, sres, SV.res, hs])

theorem sim_hmsg (p : Params) (r s o : SB) (r' s' o' : Bytes) (msg : Bytes)
    (hr : RB t r r') (hs : RB t s s') (ho : RB t o o') :
    Sim t (sHmsg p r s o msg) (hmsg challengerOracle p r' s' o' msg) (RBn t p.m) :=
  sim_ask _ _ (by simp only [RB] at hr hs ho; simp [SReq.res, sres_append, sres, SV.res, hr, hs, ho])
end


def sChain (p : Params) (tk : SB) (a : Adrs) (x : SB) (start : Nat) : Nat → Prog SB
  | 0 => pure x
  | steps+1 => do
      let y ← sThash p tk {a with hash := start} x
      sChain p tk a y (start+1) steps

def sWotsCompress (p : Params) (tk : SB) (a : Adrs) (tops : SB) : Prog SB :=
  sThash p tk {a.setType 1 with keypair := a.keypair} tops

def sWotsPkFromSig (p : Params) (tk : SB) (a : Adrs) (sig : SB) (msg : Bytes) : Prog SB := do
  let mut tops : SB := []
  for (digit,i) in (wotsDigits p msg).zipIdx do
    let top ← sChain p tk {a with chain := i} (sSlice sig i 1) digit (15-digit)
    tops := tops ++ top
  sWotsCompress p tk a tops

def sAuthWalk (p : Params) (tk : SB) (a : Adrs) (localIndex globalIndex : Nat) (node auth : SB)
    (level : Nat) : Nat → Prog SB
  | 0 => pure node
  | remaining+1 => do
      let sibling := sSlice auth level 1
      let index := globalIndex/2
      let address := {a with chain := level+1, hash := index}
      let next ← sThash p tk address (if localIndex%2 = 0 then node++sibling else sibling++node)
      sAuthWalk p tk a (localIndex/2) index next auth (level+1) remaining

def sAuthRoot (p : Params) (tk : SB) (a : Adrs) (localIndex globalIndex : Nat) (node auth : SB)
    (height : Nat) : Prog SB :=
  sAuthWalk p tk a localIndex globalIndex node auth 0 height

def sXmssPkFromSig (p : Params) (tk : SB) (a : Adrs) (idx : Nat) (sig : SB) (msg : Bytes) : Prog SB := do
  let wa := {a.setType 0 with keypair := idx}
  let node ← sWotsPkFromSig p tk wa (sig.take p.len) msg
  sAuthRoot p tk (a.setType 2) idx idx node (sig.drop p.len) p.hp

def sHtRootTail (p : Params) (tk : SB) (layer tree : Nat) (node sig : SB) : Nat → Prog SB
  | 0 => pure node
  | remaining+1 => do
      let (leaf,next) := nextLayer p tree
      let a : Adrs := {layer := layer,tree := next}
      let root ← Prog.reveal node (fun nb => sXmssPkFromSig p tk a leaf (sig.take (p.len+p.hp)) nb)
      sHtRootTail p tk (layer+1) next root (sig.drop (p.len+p.hp)) remaining

def sHtRoot (p : Params) (tk : SB) (sig msg : SB) (idxTree idxLeaf : Nat) : Prog SB := do
  let node ← Prog.reveal msg (fun mb => sXmssPkFromSig p tk {tree := idxTree} idxLeaf (sig.take (p.len+p.hp)) mb)
  sHtRootTail p tk 1 idxTree node (sig.drop (p.len+p.hp)) (p.d-1)

def sForsPkFromSig (p : Params) (tk : SB) (a : Adrs) (sig : SB) (md : Bytes) : Prog SB := do
  let mut roots : SB := []
  for (idx,i) in (base2b md p.a p.k).zipIdx do
    let globalIndex := i*2^p.a+idx
    let part := sSlice sig (i*(p.a+1)) (p.a+1)
    let leaf ← sThash p tk {a with chain := 0, hash := globalIndex} (part.take 1)
    let root ← sAuthRoot p tk a idx globalIndex leaf (part.drop 1) p.a
    roots := roots++root
  sThash p tk {a.setType 4 with keypair := a.keypair} roots

def sWotsSign (p : Params) (tk prfKey seed : SB) (a : Adrs) (msg : Bytes) : Prog SB := do
  let mut sig : SB := []
  for (digit,i) in (wotsDigits p msg).zipIdx do
    let sa := {a.setType 5 with keypair := a.keypair, chain := i}
    let sk ← sPrf p prfKey seed sa
    let part ← sChain p tk {a with chain := i} sk 0 digit
    sig := sig++part
  return sig

def sWotsPkgen (p : Params) (tk prfKey seed : SB) (a : Adrs) : Prog SB := do
  let mut tops : SB := []
  for i in List.range p.len do
    let sa := {a.setType 5 with keypair := a.keypair, chain := i}
    let sk ← sPrf p prfKey seed sa
    let top ← sChain p tk {a with chain := i} sk 0 15
    tops := tops++top
  sWotsCompress p tk a tops

def sXmssNode (p : Params) (tk prfKey seed : SB) (a : Adrs) (idx : Nat) : Nat → Prog SB
  | 0 => sWotsPkgen p tk prfKey seed {a.setType 0 with keypair := idx}
  | height+1 => do
      let left ← sXmssNode p tk prfKey seed a (2*idx) height
      let right ← sXmssNode p tk prfKey seed a (2*idx+1) height
      sThash p tk {a.setType 2 with chain := height+1, hash := idx} (left++right)

def sXmssSign (p : Params) (tk prfKey seed : SB) (a : Adrs) (idx : Nat) (msg : Bytes) : Prog SB := do
  let mut auth : SB := []
  for level in List.range p.hp do
    let sibling := Nat.xor (idx / 2^level) 1
    let node ← sXmssNode p tk prfKey seed a sibling level
    auth := auth++node
  let sig ← sWotsSign p tk prfKey seed {a.setType 0 with keypair := idx} msg
  return sig++auth

def sHtSignTail (p : Params) (tk prfKey seed : SB) (layer tree : Nat) (node : SB) : Nat → Prog SB
  | 0 => pure []
  | remaining+1 => Prog.reveal node (fun nb => do
      let (leaf,next) := nextLayer p tree
      let a : Adrs := {layer := layer,tree := next}
      let part ← sXmssSign p tk prfKey seed a leaf nb
      if remaining = 0 then return part
      let root ← sXmssPkFromSig p tk a leaf part nb
      let tail ← sHtSignTail p tk prfKey seed (layer+1) next root remaining
      return part++tail)

def sHtSign (p : Params) (tk prfKey seed : SB) (msg : SB) (idxTree idxLeaf : Nat) : Prog SB :=
  Prog.reveal msg (fun mb => do
    let a : Adrs := {tree := idxTree}
    let first ← sXmssSign p tk prfKey seed a idxLeaf mb
    let root ← sXmssPkFromSig p tk a idxLeaf first mb
    let tail ← sHtSignTail p tk prfKey seed 1 idxTree root (p.d-1)
    return first++tail)

def sForsSecret (p : Params) (prfKey seed : SB) (a : Adrs) (idx : Nat) : Prog SB :=
  sPrf p prfKey seed {a.setType 6 with keypair := a.keypair, hash := idx}

def sForsNode (p : Params) (tk prfKey seed : SB) (a : Adrs) (idx : Nat) : Nat → Prog SB
  | 0 => do
      let sk ← sForsSecret p prfKey seed a idx
      sThash p tk {a with chain := 0, hash := idx} sk
  | height+1 => do
      let left ← sForsNode p tk prfKey seed a (2*idx) height
      let right ← sForsNode p tk prfKey seed a (2*idx+1) height
      sThash p tk {a with chain := height+1, hash := idx} (left++right)

def sForsSign (p : Params) (tk prfKey seed : SB) (a : Adrs) (md : Bytes) : Prog SB := do
  let mut sig : SB := []
  for (idx,i) in (base2b md p.a p.k).zipIdx do
    let sk ← sForsSecret p prfKey seed a (i*2^p.a+idx)
    sig := sig++sk
    for level in List.range p.a do
      let sibling := Nat.xor (idx / 2^level) 1
      let node ← sForsNode p tk prfKey seed a (i*2^(p.a-level)+sibling) level
      sig := sig++node
  return sig

/-! Simulation proofs. -/

section
variable {t : List Nat} (p : Params) (tk : SB) (tk' : Bytes) (htk : RB t tk tk')
include htk

theorem sim_chain (a : Adrs) : ∀ (steps : Nat) (x : SB) (x' : Bytes) (start : Nat), RBn t p.n x x' →
    Sim t (sChain p tk a x start steps) (chain challengerOracle p tk' a x' start steps) (RBn t p.n)
  | 0, _, _, _, hx => Sim.pure' hx
  | steps+1, x, x', start, hx => by
    simp only [sChain, chain]
    exact Sim.bind (sim_thash p tk tk' _ x x' htk hx.1)
      (fun y y' hy => sim_chain a steps y y' (start+1) hy)

theorem sim_wotsPkFromSig (a : Adrs) (sig : SB) (sig' : Bytes) (hs : RBn t p.n sig sig') (msg : Bytes) :
    Sim t (sWotsPkFromSig p tk a sig msg) (wotsPkFromSig challengerOracle p tk' a sig' msg) (RBn t p.n) := by
  simp only [sWotsPkFromSig, wotsPkFromSig, sWotsCompress, wotsCompress]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩)
  · intro tops tops' h
    exact sim_thash p tk tk' _ tops tops' htk h.1
  · intro x _ s s' hss
    obtain ⟨digit, i⟩ := x
    have hsl := RBn_sSlice hs i 1
    rw [Nat.one_mul] at hsl
    exact Sim.bind (sim_chain p tk tk' htk _ (15-digit) _ _ digit hsl)
      (fun top top' h2 => Sim.pure' (RBn_append hss h2))

theorem sim_authWalk (a : Adrs) (auth : SB) (auth' : Bytes) (ha : RBn t p.n auth auth') :
    ∀ (remaining li gi level : Nat) (node : SB) (node' : Bytes), RBn t p.n node node' →
    Sim t (sAuthWalk p tk a li gi node auth level remaining)
      (authWalk challengerOracle p tk' a li gi node' auth' level remaining) (RBn t p.n)
  | 0, _, _, _, _, _, hn => Sim.pure' hn
  | remaining+1, li, gi, level, node, node', hn => by
    simp only [sAuthWalk, authWalk]
    have hsl := RBn_sSlice ha level 1
    rw [Nat.one_mul] at hsl
    have hin : RB t (if li%2 = 0 then node++sSlice auth level 1 else sSlice auth level 1++node)
        (if li%2 = 0 then node'++slice auth' (level*p.n) p.n else slice auth' (level*p.n) p.n++node') := by
      split
      · exact (RBn_append hn hsl).1
      · exact (RBn_append hsl hn).1
    exact Sim.bind (sim_thash p tk tk' _ _ _ htk hin)
      (fun y y' hy => sim_authWalk a auth auth' ha remaining _ _ _ y y' hy)

theorem sim_xmssPkFromSig (a : Adrs) (idx : Nat) (sig : SB) (sig' : Bytes) (hs : RBn t p.n sig sig')
    (msg : Bytes) :
    Sim t (sXmssPkFromSig p tk a idx sig msg) (xmssPkFromSig challengerOracle p tk' a idx sig' msg)
      (RBn t p.n) := by
  simp only [sXmssPkFromSig, xmssPkFromSig, sAuthRoot, authRoot]
  exact Sim.bind (sim_wotsPkFromSig p tk tk' htk _ _ _ (RBn_take hs p.len) msg)
    (fun node node' hn => sim_authWalk p tk tk' htk _ _ _ (RBn_drop hs p.len) _ _ _ _ _ _ hn)

theorem sim_htRootTail : ∀ (remaining layer tree : Nat) (node sig : SB) (node' sig' : Bytes),
    RBn t p.n node node' → RBn t p.n sig sig' →
    Sim t (sHtRootTail p tk layer tree node sig remaining)
      (htRootTail challengerOracle p tk' layer tree node' sig' remaining) (RBn t p.n)
  | 0, _, _, _, _, _, _, hn, _ => Sim.pure' hn
  | remaining+1, layer, tree, node, sig, node', sig', hn, hs => by
    simp only [sHtRootTail, htRootTail]
    apply Sim.bind (Sim.reveal _ _ _ ?_)
    · intro root root' hr
      exact sim_htRootTail remaining _ _ root _ root' _ hr (RBn_drop hs _)
    · rw [hn.1]
      exact sim_xmssPkFromSig p tk tk' htk _ _ _ _ (RBn_take hs _) _

theorem sim_htRoot (sig msg : SB) (sig' msg' : Bytes) (hs : RBn t p.n sig sig') (hm : RB t msg msg')
    (idxTree idxLeaf : Nat) :
    Sim t (sHtRoot p tk sig msg idxTree idxLeaf) (htRoot challengerOracle p tk' sig' msg' idxTree idxLeaf)
      (RBn t p.n) := by
  simp only [sHtRoot, htRoot]
  apply Sim.bind (Sim.reveal _ _ _ ?_)
  · intro node node' hn
    exact sim_htRootTail p tk tk' htk _ _ _ node _ node' _ hn (RBn_drop hs _)
  · rw [hm]
    exact sim_xmssPkFromSig p tk tk' htk _ _ _ _ (RBn_take hs _) _

theorem sim_forsPkFromSig (a : Adrs) (sig : SB) (sig' : Bytes) (hs : RBn t p.n sig sig') (md : Bytes) :
    Sim t (sForsPkFromSig p tk a sig md) (forsPkFromSig challengerOracle p tk' a sig' md) (RBn t p.n) := by
  simp only [sForsPkFromSig, forsPkFromSig]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩)
  · intro roots roots' h
    exact sim_thash p tk tk' _ roots roots' htk h.1
  · intro x _ s s' hss
    obtain ⟨idx, i⟩ := x
    have hpart := RBn_sSlice hs (i*(p.a+1)) (p.a+1)
    rw [Nat.mul_assoc] at hpart
    have h1 := RBn_take hpart 1
    rw [Nat.one_mul] at h1
    have h2 := RBn_drop hpart 1
    rw [Nat.one_mul] at h2
    exact Sim.bind (sim_thash p tk tk' _ _ _ htk h1.1)
      (fun leaf leaf' hl => Sim.bind (sim_authWalk p tk tk' htk _ _ _ h2 _ _ _ _ _ _ hl)
        (fun root root' hr => Sim.pure' (RBn_append hss hr)))

variable (prfKey seed : SB) (prfKey' seed' : Bytes) (hk : RB t prfKey prfKey') (hsd : RB t seed seed')
include hk hsd

theorem sim_wotsSign (a : Adrs) (msg : Bytes) :
    Sim t (sWotsSign p tk prfKey seed a msg) (wotsSign challengerOracle p tk' prfKey' seed' a msg)
      (RBn t p.n) := by
  simp only [sWotsSign, wotsSign]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩) (fun a b h => Sim.pure' h)
  intro x _ s s' hss
  obtain ⟨digit, i⟩ := x
  exact Sim.bind (sim_prf p prfKey seed prfKey' seed' _ hk hsd)
    (fun sk sk' h1 => Sim.bind (sim_chain p tk tk' htk _ digit sk sk' 0 h1)
      (fun part part' h2 => Sim.pure' (RBn_append hss h2)))

theorem sim_wotsPkgen (a : Adrs) :
    Sim t (sWotsPkgen p tk prfKey seed a) (wotsPkgen challengerOracle p tk' prfKey' seed' a) (RBn t p.n) := by
  simp only [sWotsPkgen, wotsPkgen, sWotsCompress, wotsCompress]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩)
  · intro tops tops' h
    exact sim_thash p tk tk' _ tops tops' htk h.1
  · intro i _ s s' hss
    exact Sim.bind (sim_prf p prfKey seed prfKey' seed' _ hk hsd)
      (fun sk sk' h1 => Sim.bind (sim_chain p tk tk' htk _ 15 sk sk' 0 h1)
        (fun top top' h2 => Sim.pure' (RBn_append hss h2)))

theorem sim_xmssNode (a : Adrs) : ∀ (height idx : Nat),
    Sim t (sXmssNode p tk prfKey seed a idx height) (xmssNode challengerOracle p tk' prfKey' seed' a idx height)
      (RBn t p.n)
  | 0, idx => by
    simp only [sXmssNode, xmssNode]
    exact sim_wotsPkgen p tk tk' htk prfKey seed prfKey' seed' hk hsd _
  | height+1, idx => by
    simp only [sXmssNode, xmssNode]
    exact Sim.bind (sim_xmssNode a height (2*idx))
      (fun l l' hl => Sim.bind (sim_xmssNode a height (2*idx+1))
        (fun r r' hr => sim_thash p tk tk' _ _ _ htk (RBn_append hl hr).1))

theorem sim_xmssSign (a : Adrs) (idx : Nat) (msg : Bytes) :
    Sim t (sXmssSign p tk prfKey seed a idx msg) (xmssSign challengerOracle p tk' prfKey' seed' a idx msg)
      (RBn t p.n) := by
  simp only [sXmssSign, xmssSign]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩)
  · intro auth auth' ha
    exact Sim.bind (sim_wotsSign p tk tk' htk prfKey seed prfKey' seed' hk hsd _ msg)
      (fun sig sig' hs => Sim.pure' (RBn_append hs ha))
  · intro level _ s s' hss
    exact Sim.bind (sim_xmssNode p tk tk' htk prfKey seed prfKey' seed' hk hsd a _ _)
      (fun node node' hn => Sim.pure' (RBn_append hss hn))

theorem sim_htSignTail : ∀ (remaining layer tree : Nat) (node : SB) (node' : Bytes), RB t node node' →
    Sim t (sHtSignTail p tk prfKey seed layer tree node remaining)
      (htSignTail challengerOracle p tk' prfKey' seed' layer tree node' remaining) (RBn t p.n)
  | 0, _, _, _, _, _ => Sim.pure' ⟨rfl, WN_nil _⟩
  | remaining+1, layer, tree, node, node', hn => by
    simp only [sHtSignTail, htSignTail]
    apply Sim.reveal
    rw [hn]
    apply Sim.bind (sim_xmssSign p tk tk' htk prfKey seed prfKey' seed' hk hsd _ _ _)
    intro part part' hp
    apply Sim.ite
    · intro _; exact Sim.pure' hp
    · intro _
      exact Sim.bind Sim.unit (fun _ _ _ => Sim.bind (sim_xmssPkFromSig p tk tk' htk _ _ _ _ hp _)
        (fun root root' hr => Sim.bind (sim_htSignTail remaining _ _ root root' hr.1)
          (fun tail tail' ht => Sim.pure' (RBn_append hp ht))))

theorem sim_htSign (msg : SB) (msg' : Bytes) (hm : RB t msg msg') (idxTree idxLeaf : Nat) :
    Sim t (sHtSign p tk prfKey seed msg idxTree idxLeaf)
      (htSign challengerOracle p tk' prfKey' seed' msg' idxTree idxLeaf) (RBn t p.n) := by
  simp only [sHtSign, htSign]
  apply Sim.reveal
  rw [hm]
  exact Sim.bind (sim_xmssSign p tk tk' htk prfKey seed prfKey' seed' hk hsd _ _ _)
    (fun first first' hf => Sim.bind (sim_xmssPkFromSig p tk tk' htk _ _ _ _ hf _)
      (fun root root' hr => Sim.bind (sim_htSignTail p tk tk' htk prfKey seed prfKey' seed' hk hsd _ _ _ root root' hr.1)
        (fun tail tail' ht => Sim.pure' (RBn_append hf ht))))

theorem sim_forsNode (a : Adrs) : ∀ (height idx : Nat),
    Sim t (sForsNode p tk prfKey seed a idx height) (forsNode challengerOracle p tk' prfKey' seed' a idx height)
      (RBn t p.n)
  | 0, idx => by
    simp only [sForsNode, forsNode, sForsSecret, forsSecret]
    exact Sim.bind (sim_prf p prfKey seed prfKey' seed' _ hk hsd)
      (fun sk sk' h => sim_thash p tk tk' _ _ _ htk h.1)
  | height+1, idx => by
    simp only [sForsNode, forsNode]
    exact Sim.bind (sim_forsNode a height (2*idx))
      (fun l l' hl => Sim.bind (sim_forsNode a height (2*idx+1))
        (fun r r' hr => sim_thash p tk tk' _ _ _ htk (RBn_append hl hr).1))

theorem sim_forsSign (a : Adrs) (md : Bytes) :
    Sim t (sForsSign p tk prfKey seed a md) (forsSign challengerOracle p tk' prfKey' seed' a md) (RBn t p.n) := by
  simp only [sForsSign, forsSign, sForsSecret, forsSecret]
  apply Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ [] [] ⟨rfl, WN_nil _⟩) (fun a b h => Sim.pure' h)
  intro x _ s s' hss
  obtain ⟨idx, i⟩ := x
  apply Sim.bind (sim_prf p prfKey seed prfKey' seed' _ hk hsd)
  intro sk sk' hsk
  refine Sim.bind (Sim.forIn _ _ _ (RBn t p.n) ?_ _ _ (RBn_append hss hsk))
    (fun a b h => Sim.bind Sim.unit (fun _ _ _ =>
      Sim.pure' (show Sim.StepRel (RBn t p.n) (.yield a) (.yield b) from h)))
  intro level _ u u' huu
  exact Sim.bind (sim_forsNode p tk tk' htk prfKey seed prfKey' seed' hk hsd a _ _)
    (fun node node' hn => Sim.bind Sim.unit (fun _ _ _ => Sim.pure' (RBn_append huu hn)))
end

theorem sres_length (t : List Nat) (n : Nat) : ∀ (x : SB), WN n x → (sres t x).length = x.length * n
  | [], _ => by simp [sres]
  | v :: x, hw => by
    simp only [sres, List.length_append, List.length_cons, res_len]
    rw [sres_length t n x (fun u hu => hw u (by simp [hu])), hw v (by simp), Nat.succ_mul]; omega

/-- Optional symbolic bytes resolve to optional concrete bytes. -/
def ROpt (t : List Nat) (x : Option SB) (y : Option Bytes) : Prop := x.map (sres t) = y

/-- Key generation after the seed expansion, as in `generateKeypair`. -/
def kgTail [Monad m] (o : Oracle m) (v : Variant) (expanded : Bytes) : m (Bytes × Bytes) := do
  let p := params v
  let seed := slice expanded (2*p.n) p.n
  let tk ← deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey ← deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
  let root ← xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp
  return (seed++root,expanded++root)

theorem generateKeypair_split {m : Type → Type} [Monad m] (o : Oracle m) (v : Variant) (seed32 : Wire 32) :
    generateKeypair o v seed32 = o ⟨3,"ChaCha20Rng",[],seed32.val,3*(params v).n⟩ >>= kgTail o v := rfl

def sKgTail (v : Variant) (expanded : SB) : Prog (SB × SB) := do
  let p := params v
  let seed := sSlice expanded 2 1
  let tk ← sDeriveKey "DSM/sphincs/v2/thash" seed
  let prfKey ← sDeriveKey "DSM/sphincs/v2/prf" (expanded.take 1)
  let root ← sXmssNode p tk prfKey seed {layer := p.d-1} 0 p.hp
  return (seed++root,expanded++root)

def sSign (v : Variant) (sk : SB) (msg : Bytes) : Prog (Option SB) := do
  let p := params v
  if msg.isEmpty || sk.length != 4 then return none
  let seed := sSlice sk 2 1
  let root := sk.drop 3
  let tk ← sDeriveKey "DSM/sphincs/v2/thash" seed
  let prfKey ← sDeriveKey "DSM/sphincs/v2/prf" (sk.take 1)
  let msgKey ← sDeriveKey "DSM/sphincs/v2/prf-msg" (sSlice sk 1 1)
  let r ← sKeyed p.n msgKey (seed ++ [.lit msg])
  let digest ← sHmsg p r seed root msg
  Prog.reveal digest (fun dg => do
    let indices := splitDigest p dg
    let a : Adrs := {tree := indices.tree,kind := 3,keypair := indices.leaf}
    let fs ← sForsSign p tk prfKey seed a indices.md
    let fpk ← sForsPkFromSig p tk a fs indices.md
    let hs ← sHtSign p tk prfKey seed fpk indices.tree indices.leaf
    let actual ← sHtRoot p tk hs fpk indices.tree indices.leaf
    Prog.reveal actual (fun ab => Prog.reveal root (fun rb => do
      if ab != rb then return none
      return some (r++fs++hs))))

theorem sim_kgTail {t : List Nat} (v : Variant) (ex : SB) (ex' : Bytes) (hex : RBn t (params v).n ex ex') :
    Sim t (sKgTail v ex) (kgTail challengerOracle v ex')
      (fun x y => RBn t (params v).n x.1 y.1 ∧ RBn t (params v).n x.2 y.2) := by
  simp only [sKgTail, kgTail]
  have hseed := RBn_sSlice hex 2 1
  rw [Nat.one_mul] at hseed
  have hpre := RBn_take hex 1
  rw [Nat.one_mul] at hpre
  exact Sim.bind (sim_deriveKey _ _ _ hseed.1)
    (fun tk tk' htk => Sim.bind (sim_deriveKey _ _ _ hpre.1)
      (fun pk pk' hpk => Sim.bind (sim_xmssNode (params v) tk tk' htk.1 pk _ pk' _ hpk.1 hseed.1 _ _ _)
        (fun root root' hr => Sim.pure' ⟨RBn_append hseed hr, RBn_append hex hr⟩)))

theorem params_n_pos (v : Variant) : 0 < (params v).n := by cases v <;> decide

theorem sim_sign {t : List Nat} (v : Variant) (sk : SB) (sk' : Bytes) (hsk : RBn t (params v).n sk sk')
    (msg : Bytes) :
    Sim t (sSign v sk msg) (sign challengerOracle v sk' msg) (ROpt t) := by
  have hcond : (msg.isEmpty || sk'.length != 4*(params v).n) = (msg.isEmpty || sk.length != 4) := by
    rw [← hsk.1, sres_length t _ sk hsk.2]
    have hn := params_n_pos v
    by_cases h : sk.length = 4
    · simp [h]
    · have h' : sk.length * (params v).n ≠ 4 * (params v).n :=
        fun e => h (Nat.eq_of_mul_eq_mul_right hn e)
      rw [bne_iff_ne.mpr h', bne_iff_ne.mpr h]
  have hseed := RBn_sSlice hsk 2 1
  rw [Nat.one_mul] at hseed
  have hroot := RBn_drop hsk 3
  have hpre := RBn_take hsk 1
  rw [Nat.one_mul] at hpre
  have hprf := RBn_sSlice hsk 1 1
  rw [Nat.one_mul] at hprf
  have hin : RB t (sSlice sk 2 1 ++ [.lit msg]) (slice sk' (2*(params v).n) (params v).n ++ msg) := by
    simp only [RB, sres_append, hseed.1, sres, SV.res, List.append_nil]
  simp only [sSign, sign, hcond]
  apply Sim.ite
  · intro _; exact Sim.pure' rfl
  · intro _
    refine Sim.bind Sim.unit (fun _ _ _ => ?_)
    refine Sim.bind (sim_deriveKey _ _ _ hseed.1) (fun tk tk' htk => ?_)
    refine Sim.bind (sim_deriveKey _ _ _ hpre.1) (fun pk pk' hpk => ?_)
    refine Sim.bind (sim_deriveKey _ _ _ hprf.1) (fun mk mk' hmk => ?_)
    refine Sim.bind (sim_keyed _ _ _ _ _ hmk.1 hin) (fun r r' hr => ?_)
    refine Sim.bind (sim_hmsg _ _ _ _ _ _ _ msg hr.1 hseed.1 hroot.1) (fun dg dg' hdg => ?_)
    apply Sim.reveal
    rw [hdg.1]
    refine Sim.bind (sim_forsSign _ tk tk' htk.1 pk _ pk' _ hpk.1 hseed.1 _ _) (fun fs fs' hfs => ?_)
    refine Sim.bind (sim_forsPkFromSig _ tk tk' htk.1 _ fs fs' hfs _) (fun fpk fpk' hfpk => ?_)
    refine Sim.bind (sim_htSign _ tk tk' htk.1 pk _ pk' _ hpk.1 hseed.1 fpk fpk' hfpk.1 _ _)
      (fun hs hs' hhs => ?_)
    refine Sim.bind (sim_htRoot _ tk tk' htk.1 hs fpk hs' fpk' hhs hfpk.1 _ _) (fun ac ac' hac => ?_)
    apply Sim.reveal
    apply Sim.reveal
    rw [hac.1, hroot.1]
    apply Sim.ite
    · intro _; exact Sim.pure' rfl
    · intro _
      exact Sim.bind Sim.unit (fun _ _ _ => Sim.pure' (by simp [ROpt, sres_append, hr.1, hfs.1, hhs.1]))

#print axioms sim_sign
#print axioms sim_kgTail

#print axioms sim_htSign
#print axioms sim_forsSign
end DSM.Rom
