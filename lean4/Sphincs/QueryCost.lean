-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.AddressRange
import Sphincs.WotsChecksum
import Sphincs.SecurityGames

/- Primitive-request cost of the construction. Every model function is run in
   the request-logging monad (`RequestLog`); `Cost x c` says that a run of `x`
   only appends to the log and appends at most `c` requests, from any log and
   for every oracle. The bounds below are explicit functions of the parameter
   set and hold for every message, key and oracle answer: the only
   data-dependent loop bounds are WOTS chain lengths, bounded by digit ≤ 15.
   This is the query accounting a concrete reduction needs (the reduction's
   overhead over the adversary is the challenger's requests); it is not a
   runtime model of BLAKE3 or of the adversary. -/
namespace DSM.Sphincs

/-- `x` only appends to the request log, and appends at most `c` requests. -/
def Cost {α : Type} (x : LogM α) (c : Nat) : Prop :=
  ∀ s, ∃ L, (x.run s).2 = s ++ L ∧ L.length ≤ c

namespace Cost

theorem pure_le {α : Type} (a : α) (n : Nat) : Cost (pure a : LogM α) n :=
  fun s => ⟨[], by rw [List.append_nil]; rfl, Nat.zero_le _⟩

theorem pure' {α : Type} (a : α) : Cost (pure a : LogM α) 0 := pure_le a 0

theorem mono {α : Type} {x : LogM α} {a b : Nat} (hx : Cost x a) (h : a ≤ b) : Cost x b := by
  intro s
  obtain ⟨L, e, c⟩ := hx s
  exact ⟨L, e, Nat.le_trans c h⟩

theorem bind' {α β : Type} {x : LogM α} {f : α → LogM β} {a b : Nat}
    (hx : Cost x a) (hf : ∀ v, Cost (f v) b) : Cost (x >>= f) (a + b) := by
  intro s
  obtain ⟨L₁, e₁, c₁⟩ := hx s
  obtain ⟨L₂, e₂, c₂⟩ := hf (x.run s).1 (s ++ L₁)
  refine ⟨L₁ ++ L₂, ?_, ?_⟩
  · rw [logM_run_bind, e₁]
    simpa [List.append_assoc] using e₂
  · rw [List.length_append]; omega

/-- Bind in the form used below: the continuation is charged what is left. -/
theorem bind_sub {α β : Type} {x : LogM α} {f : α → LogM β} {a n : Nat}
    (hx : Cost x a) (hf : ∀ v, Cost (f v) (n - a)) (h : a ≤ n) : Cost (x >>= f) n :=
  mono (bind' hx hf) (by omega)

theorem oracle (o : Oracle Id) (r : Request) : Cost (logOracle o r) 1 :=
  fun s => ⟨[r], by rw [logOracle_run], Nat.le_refl _⟩

theorem ite' {α : Type} {c : Prop} [Decidable c] {x y : LogM α} {n : Nat}
    (hx : c → Cost x n) (hy : ¬c → Cost y n) : Cost (if c then x else y) n := by
  by_cases h : c
  · simp only [h, if_true]; exact hx h
  · simp only [h, if_false]; exact hy h

theorem forIn' {α β : Type} (l : List α) (init : β) {f : α → β → LogM (ForInStep β)}
    (c : α → Nat) (hf : ∀ a ∈ l, ∀ b, Cost (f a b) (c a)) :
    Cost (forIn l init f) (l.map c).sum := by
  induction l generalizing init with
  | nil => exact pure' init
  | cons a l ih =>
    rw [List.forIn_cons, List.map_cons, List.sum_cons]
    apply bind' (hf a (by simp) init)
    intro step
    cases step with
    | done b => exact pure_le b _
    | yield b => exact ih b (fun a' h b' => hf a' (by simp [h]) b')

theorem sum_const {α : Type} (l : List α) (b : Nat) :
    (l.map fun _ => b).sum = l.length * b := by
  induction l with
  | nil => simp
  | cons a l ih => rw [List.map_cons, List.sum_cons, ih, List.length_cons, Nat.succ_mul]; omega

theorem forIn_const {α β : Type} (l : List α) (init : β) {f : α → β → LogM (ForInStep β)}
    (b : Nat) (hf : ∀ a ∈ l, ∀ s, Cost (f a s) b) :
    Cost (forIn l init f) (l.length * b) := by
  have h := forIn' l init (fun _ => b) hf
  rwa [sum_const] at h

end Cost

macro "cost_tail" : tactic =>
  `(tactic| repeat (first | exact Cost.pure_le _ _ |
      refine Cost.bind_sub (Cost.pure' _) (fun _ => ?_) (Nat.zero_le _)))

/-! Explicit request counts. -/

def wotsVerifyCost (p : Params) : Nat := p.len*15 + 1
def wotsSignCost (p : Params) : Nat := p.len*16
def wotsPkgenCost (p : Params) : Nat := p.len*16 + 1
def xmssNodeCost (p : Params) : Nat → Nat
  | 0 => wotsPkgenCost p
  | h+1 => 2*xmssNodeCost p h + 1
def xmssVerifyCost (p : Params) : Nat := wotsVerifyCost p + p.hp
def xmssSignCost (p : Params) : Nat :=
  ((List.range p.hp).map (xmssNodeCost p)).sum + wotsSignCost p
def htSignTailCost (p : Params) : Nat → Nat
  | 0 => 0
  | r+1 => xmssSignCost p + (if r = 0 then 0 else xmssVerifyCost p + htSignTailCost p r)
def htSignCost (p : Params) : Nat :=
  xmssSignCost p + xmssVerifyCost p + htSignTailCost p (p.d-1)
def htVerifyCost (p : Params) : Nat := xmssVerifyCost p + (p.d-1)*xmssVerifyCost p
def forsNodeCost (p : Params) : Nat → Nat
  | 0 => 2
  | h+1 => 2*forsNodeCost p h + 1
def forsSignCost (p : Params) : Nat :=
  p.k*(1 + ((List.range p.a).map (forsNodeCost p)).sum)
def forsVerifyCost (p : Params) : Nat := p.k*(1 + p.a) + 1

/-- Requests issued by one signing call (3 key derivations, the message PRF,
    H_msg, FORS signing and its self-recomputation, hypertree signing and the
    signer's root self-check). -/
def signCost (v : Variant) : Nat :=
  5 + forsSignCost (params v) + forsVerifyCost (params v) +
    htSignCost (params v) + htVerifyCost (params v)
def verifyCost (v : Variant) : Nat :=
  2 + forsVerifyCost (params v) + htVerifyCost (params v)
def keygenCost (v : Variant) : Nat := 3 + xmssNodeCost (params v) (params v).hp

section Components
variable {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes}

local notation "LO" => logOracle o

theorem chain_cost (a : Adrs) (x : Bytes) (start steps : Nat) :
    Cost (chain LO p tk a x start steps) steps := by
  induction steps generalizing x start with
  | zero => exact Cost.pure' x
  | succ s ih =>
    simp only [chain]
    exact Cost.bind_sub (Cost.oracle o _) (fun y => Cost.mono (ih y (start+1)) (by omega))
      (by omega)

theorem wotsPkFromSig_cost (a : Adrs) (sig msg : Bytes) :
    Cost (wotsPkFromSig LO p tk a sig msg) (wotsVerifyCost p) := by
  simp only [wotsPkFromSig]
  have hl : (wotsDigits p msg).zipIdx.length = p.len := by simp [wots_digit_count]
  refine Cost.bind_sub (a := p.len*15) ?_ (fun _ => Cost.mono (Cost.oracle o _) ?_) ?_
  · refine Cost.mono (Cost.forIn_const _ _ 15 ?_) (by rw [hl]; exact Nat.le_refl _)
    intro x _ acc
    refine Cost.bind_sub (chain_cost _ _ _ _) (fun _ => ?_) (by omega)
    cost_tail
  · simp only [wotsVerifyCost]; omega
  · simp only [wotsVerifyCost]; omega

theorem wotsSign_cost (a : Adrs) (msg : Bytes) :
    Cost (wotsSign LO p tk prfKey seed a msg) (wotsSignCost p) := by
  simp only [wotsSign]
  have hl : (wotsDigits p msg).zipIdx.length = p.len := by simp [wots_digit_count]
  refine Cost.bind_sub (a := p.len*16) ?_ (fun _ => Cost.pure_le _ _) (by simp [wotsSignCost])
  refine Cost.mono (Cost.forIn_const _ _ 16 ?_) (by rw [hl]; exact Nat.le_refl _)
  intro x hx acc
  have hd := wots_digit_bound p msg _ (zipIdx_mem hx).1
  refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (chain_cost _ _ _ _) (fun _ => ?_) (by omega)
  cost_tail

theorem wotsPkgen_cost (a : Adrs) :
    Cost (wotsPkgen LO p tk prfKey seed a) (wotsPkgenCost p) := by
  simp only [wotsPkgen]
  refine Cost.bind_sub (a := p.len*16) ?_ (fun _ => Cost.mono (Cost.oracle o _) ?_) ?_
  · refine Cost.mono (Cost.forIn_const _ _ 16 ?_) (by rw [List.length_range]; exact Nat.le_refl _)
    intro i _ acc
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (chain_cost _ _ _ _) (fun _ => ?_) (by omega)
    cost_tail
  · simp only [wotsPkgenCost]; omega
  · simp only [wotsPkgenCost]; omega

theorem xmssNode_cost (a : Adrs) (idx h : Nat) :
    Cost (xmssNode LO p tk prfKey seed a idx h) (xmssNodeCost p h) := by
  induction h generalizing idx with
  | zero => exact wotsPkgen_cost _
  | succ h ih =>
    simp only [xmssNode, xmssNodeCost]
    refine Cost.bind_sub (ih (2*idx)) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (ih (2*idx+1)) (fun _ => ?_) (by omega)
    exact Cost.mono (Cost.oracle o _) (by omega)

theorem authWalk_cost (a : Adrs) (li gi : Nat) (node auth : Bytes) (level remaining : Nat) :
    Cost (authWalk LO p tk a li gi node auth level remaining) remaining := by
  induction remaining generalizing li gi node level with
  | zero => exact Cost.pure' _
  | succ r ih =>
    simp only [authWalk]
    exact Cost.bind_sub (Cost.oracle o _) (fun _ => Cost.mono (ih _ _ _ _) (by omega)) (by omega)

theorem xmssPkFromSig_cost (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Cost (xmssPkFromSig LO p tk a idx sig msg) (xmssVerifyCost p) := by
  simp only [xmssPkFromSig, authRoot]
  exact Cost.bind_sub (wotsPkFromSig_cost _ _ _)
    (fun _ => Cost.mono (authWalk_cost _ _ _ _ _ _ _) (by simp only [xmssVerifyCost]; omega))
    (by simp only [xmssVerifyCost]; omega)

theorem htRootTail_cost (layer tree : Nat) (node sig : Bytes) (remaining : Nat) :
    Cost (htRootTail LO p tk layer tree node sig remaining) (remaining * xmssVerifyCost p) := by
  induction remaining generalizing layer tree node sig with
  | zero => exact Cost.pure_le _ _
  | succ r ih =>
    simp only [htRootTail, nextLayer]
    exact Cost.bind_sub (xmssPkFromSig_cost _ _ _ _)
      (fun _ => Cost.mono (ih _ _ _ _) (by rw [Nat.succ_mul]; omega))
      (by rw [Nat.succ_mul]; omega)

theorem htRoot_cost (sig msg : Bytes) (tree leaf : Nat) :
    Cost (htRoot LO p tk sig msg tree leaf) (htVerifyCost p) := by
  simp only [htRoot]
  exact Cost.bind_sub (xmssPkFromSig_cost _ _ _ _)
    (fun _ => Cost.mono (htRootTail_cost _ _ _ _ _) (by simp only [htVerifyCost]; omega))
    (by simp only [htVerifyCost]; omega)

theorem forsNode_cost (a : Adrs) (idx h : Nat) :
    Cost (forsNode LO p tk prfKey seed a idx h) (forsNodeCost p h) := by
  induction h generalizing idx with
  | zero =>
    simp only [forsNode, forsNodeCost]
    exact Cost.bind_sub (Cost.oracle o _) (fun _ => Cost.mono (Cost.oracle o _) (by omega))
      (by omega)
  | succ h ih =>
    simp only [forsNode, forsNodeCost]
    refine Cost.bind_sub (ih (2*idx)) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (ih (2*idx+1)) (fun _ => ?_) (by omega)
    exact Cost.mono (Cost.oracle o _) (by omega)

theorem forsSign_cost (a : Adrs) (md : Bytes) :
    Cost (forsSign LO p tk prfKey seed a md) (forsSignCost p) := by
  simp only [forsSign]
  have hl : (base2b md p.a p.k).zipIdx.length = p.k := by simp [base2b_length]
  refine Cost.bind_sub (a := forsSignCost p) ?_ (fun _ => Cost.pure_le _ _) (Nat.le_refl _)
  refine Cost.mono (Cost.forIn_const _ _ (1 + ((List.range p.a).map (forsNodeCost p)).sum) ?_)
    (by rw [hl]; exact Nat.le_refl _)
  intro x _ acc
  refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (Cost.forIn' _ _ (forsNodeCost p) ?_) (fun _ => ?_) (by omega)
  · intro level _ acc'
    refine Cost.bind_sub (forsNode_cost _ _ _) (fun _ => ?_) (Nat.le_refl _)
    cost_tail
  · cost_tail

theorem forsPkFromSig_cost (a : Adrs) (sig md : Bytes) :
    Cost (forsPkFromSig LO p tk a sig md) (forsVerifyCost p) := by
  simp only [forsPkFromSig]
  have hl : (base2b md p.a p.k).zipIdx.length = p.k := by simp [base2b_length]
  refine Cost.bind_sub (a := p.k*(1+p.a)) ?_ (fun _ => Cost.mono (Cost.oracle o _) ?_) ?_
  · refine Cost.mono (Cost.forIn_const _ _ (1+p.a) ?_) (by rw [hl]; exact Nat.le_refl _)
    intro x _ acc
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    simp only [authRoot]
    refine Cost.bind_sub (authWalk_cost _ _ _ _ _ _ _) (fun _ => ?_) (by omega)
    cost_tail
  · simp only [forsVerifyCost]; omega
  · simp only [forsVerifyCost]; omega

theorem xmssSign_cost (a : Adrs) (idx : Nat) (msg : Bytes) :
    Cost (xmssSign LO p tk prfKey seed a idx msg) (xmssSignCost p) := by
  simp only [xmssSign, xmssSignCost]
  refine Cost.bind_sub (Cost.forIn' _ _ (xmssNodeCost p) ?_) (fun _ => ?_) (by omega)
  · intro level _ acc
    refine Cost.bind_sub (xmssNode_cost _ _ _) (fun _ => ?_) (Nat.le_refl _)
    cost_tail
  · refine Cost.bind_sub (wotsSign_cost _ _) (fun _ => ?_) (by omega)
    cost_tail

theorem htSignTail_cost (layer tree : Nat) (node : Bytes) (remaining : Nat) :
    Cost (htSignTail LO p tk prfKey seed layer tree node remaining)
      (htSignTailCost p remaining) := by
  induction remaining generalizing layer tree node with
  | zero => exact Cost.pure' _
  | succ r ih =>
    simp only [htSignTail, nextLayer, htSignTailCost]
    refine Cost.bind_sub (xmssSign_cost _ _ _) (fun _ => ?_) (by omega)
    apply Cost.ite'
    · intro _; exact Cost.pure_le _ _
    · intro hr
      rw [if_neg hr]
      cost_tail
      refine Cost.bind_sub (xmssPkFromSig_cost _ _ _ _) (fun _ => ?_) (by omega)
      refine Cost.bind_sub (ih _ _ _) (fun _ => ?_) (by omega)
      cost_tail

theorem htSign_cost (msg : Bytes) (tree leaf : Nat) :
    Cost (htSign LO p tk prfKey seed msg tree leaf) (htSignCost p) := by
  simp only [htSign, htSignCost]
  refine Cost.bind_sub (xmssSign_cost _ _ _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (xmssPkFromSig_cost _ _ _ _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (htSignTail_cost _ _ _ _) (fun _ => ?_) (by omega)
  cost_tail

end Components

theorem sign_cost (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    Cost (sign (logOracle o) v sk msg) (signCost v) := by
  simp only [sign, signCost]
  apply Cost.ite'
  · intro _; exact Cost.pure_le _ _
  · intro _
    cost_tail
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (forsSign_cost _ _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (forsPkFromSig_cost _ _ _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (htSign_cost _ _ _) (fun _ => ?_) (by omega)
    refine Cost.bind_sub (htRoot_cost _ _ _ _) (fun _ => ?_) (by omega)
    apply Cost.ite' <;> intro _ <;> cost_tail

theorem verify_cost (o : Oracle Id) (v : Variant) (pk msg sig : Bytes) :
    Cost (verify (logOracle o) v pk msg sig) (verifyCost v) := by
  simp only [verify, verifyCost]
  apply Cost.ite'
  · intro _; exact Cost.pure_le _ _
  · intro _
    apply Cost.ite'
    · intro _; exact Cost.pure_le _ _
    · intro _
      cost_tail
      refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
      refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
      refine Cost.bind_sub (forsPkFromSig_cost _ _ _) (fun _ => ?_) (by omega)
      refine Cost.bind_sub (htRoot_cost _ _ _ _) (fun _ => ?_) (by omega)
      cost_tail

theorem keygen_cost (o : Oracle Id) (v : Variant) (seed32 : Wire 32) :
    Cost (generateKeypair (logOracle o) v seed32) (keygenCost v) := by
  simp only [generateKeypair, keygenCost]
  refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (Cost.oracle o _) (fun _ => ?_) (by omega)
  refine Cost.bind_sub (xmssNode_cost _ _ _) (fun _ => ?_) (by omega)
  cost_tail

/-- The two deployed variants, evaluated. -/
theorem deployed_request_bounds :
    signCost .spx128f = 127858 ∧ verifyCost .spx128f = 11872 ∧ keygenCost .spx128f = 4498 ∧
    signCost .spx256f = 379087 ∧ verifyCost .spx256f = 17523 ∧ keygenCost .spx256f = 17186 := by
  decide

/-! Verification run in the logging monad returns the model value. -/

/-- No restriction on logged requests: `Good Any x v` is plain simulation. -/
def AnyReq (_ : Request) : Prop := True

section Sim
variable {o : Oracle Id} {p : Params} {tk : Bytes}

local notation "LO" => logOracle o

theorem chain_sim (a : Adrs) (x : Bytes) (start steps : Nat) :
    Good AnyReq (chain LO p tk a x start steps) (chain o p tk a x start steps) := by
  induction steps generalizing x start with
  | zero => exact Good.pure' x
  | succ s ih =>
    simp only [chain]
    exact Good.bind_id (Good.oracle o trivial) (ih _ _)

theorem wotsPkFromSig_sim (a : Adrs) (sig msg : Bytes) :
    Good AnyReq (wotsPkFromSig LO p tk a sig msg) (wotsPkFromSig o p tk a sig msg) := by
  simp only [wotsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x _ acc
    apply Good.bind_id (chain_sim _ _ _ _)
    good_tail
  · exact Good.oracle o trivial

theorem authWalk_sim (a : Adrs) (li gi : Nat) (node auth : Bytes) (level remaining : Nat) :
    Good AnyReq (authWalk LO p tk a li gi node auth level remaining)
      (authWalk o p tk a li gi node auth level remaining) := by
  induction remaining generalizing li gi node level with
  | zero => exact Good.pure' _
  | succ r ih =>
    simp only [authWalk]
    exact Good.bind_id (Good.oracle o trivial) (ih _ _ _ _)

theorem xmssPkFromSig_sim (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Good AnyReq (xmssPkFromSig LO p tk a idx sig msg) (xmssPkFromSig o p tk a idx sig msg) := by
  simp only [xmssPkFromSig, authRoot]
  exact Good.bind_id (wotsPkFromSig_sim _ _ _) (authWalk_sim _ _ _ _ _ _ _)

theorem htRootTail_sim (layer tree : Nat) (node sig : Bytes) (remaining : Nat) :
    Good AnyReq (htRootTail LO p tk layer tree node sig remaining)
      (htRootTail o p tk layer tree node sig remaining) := by
  induction remaining generalizing layer tree node sig with
  | zero => exact Good.pure' _
  | succ r ih =>
    simp only [htRootTail, nextLayer]
    exact Good.bind_id (xmssPkFromSig_sim _ _ _ _) (ih _ _ _ _)

theorem htRoot_sim (sig msg : Bytes) (tree leaf : Nat) :
    Good AnyReq (htRoot LO p tk sig msg tree leaf) (htRoot o p tk sig msg tree leaf) := by
  simp only [htRoot]
  exact Good.bind_id (xmssPkFromSig_sim _ _ _ _) (htRootTail_sim _ _ _ _ _)

theorem forsPkFromSig_sim (a : Adrs) (sig md : Bytes) :
    Good AnyReq (forsPkFromSig LO p tk a sig md) (forsPkFromSig o p tk a sig md) := by
  simp only [forsPkFromSig]
  apply Good.bind_id
  · apply Good.forIn'
    intro x _ acc
    apply Good.bind_id (Good.oracle o trivial)
    simp only [authRoot]
    apply Good.bind_id (authWalk_sim _ _ _ _ _ _ _)
    good_tail
  · exact Good.oracle o trivial

end Sim

theorem verify_sim (o : Oracle Id) (v : Variant) (pk msg sig : Bytes) :
    Good AnyReq (verify (logOracle o) v pk msg sig) (verify o v pk msg sig) := by
  simp only [verify]
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  apply Good.bind_id (Good.pure_id _)
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  apply Good.bind_id (Good.pure_id _)
  apply Good.bind_id (Good.oracle o trivial)
  apply Good.bind_id (Good.oracle o trivial)
  apply Good.bind_id (forsPkFromSig_sim _ _ _)
  apply Good.bind_id (htRoot_sim _ _ _ _)
  exact Good.pure' _

/-! The EUF-CMA challenger, run with request logging. -/
namespace Security

/-- One signing reply in the logging monad: only a legal message is signed,
    exactly as `reply` does. -/
def signReply (limits : Limits) (signM : Bytes → LogM (Option Bytes)) (m : Bytes) :
    LogM (Option Bytes) :=
  if legal limits m then signM m else pure none

/-- `run` with the signing replies produced in the logging monad. -/
def runM (limits : Limits) (signM : Bytes → LogM (Option Bytes)) (strategy : Strategy) :
    Nat → View → LogM Outcome
  | 0, view => match strategy view with
    | .forge m s => pure (.forgery view m s)
    | .query _ => pure (.exhausted view)
  | fuel+1, view => match strategy view with
    | .forge m s => pure (.forgery view m s)
    | .query m => do
        let sig ← signReply limits signM m
        runM limits signM strategy fuel {view with replies := view.replies ++ [⟨m, sig⟩]}

theorem runM_good {P : Request → Prop} (limits : Limits) (signM : Bytes → LogM (Option Bytes))
    (signId : Bytes → Option Bytes) (hs : ∀ m, Good P (signM m) (signId m))
    (strategy : Strategy) (fuel : Nat) (view : View) :
    Good P (runM limits signM strategy fuel view) (run limits signId strategy fuel view) := by
  induction fuel generalizing view with
  | zero =>
    simp only [runM, run]
    cases strategy view <;> exact Good.pure' _
  | succ fuel ih =>
    simp only [runM, run]
    cases strategy view with
    | forge m s => exact Good.pure' _
    | query m =>
      have hr : Good P (signReply limits signM m) (if legal limits m then signId m else none) := by
        unfold signReply
        exact Good.ite' (fun _ => hs m) (fun _ => Good.pure' none)
      exact Good.bind' hr (ih (advance limits signId view m))

theorem runM_cost (limits : Limits) (signM : Bytes → LogM (Option Bytes)) (c : Nat)
    (hs : ∀ m, Cost (signM m) c) (strategy : Strategy) (fuel : Nat) (view : View) :
    Cost (runM limits signM strategy fuel view) (fuel * c) := by
  induction fuel generalizing view with
  | zero =>
    simp only [runM]
    cases strategy view <;> exact Cost.pure_le _ _
  | succ fuel ih =>
    simp only [runM]
    cases strategy view with
    | forge m s => exact Cost.pure_le _ _
    | query m =>
      refine Cost.bind_sub (a := c) ?_ (fun _ => Cost.mono (ih _) ?_) ?_
      · unfold signReply
        exact Cost.ite' (fun _ => hs m) (fun _ => Cost.pure_le _ _)
      · rw [Nat.succ_mul]; omega
      · rw [Nat.succ_mul]; omega

/-- The whole experiment in the logging monad: key generation, the adaptive
    signing phase, and verification of the final forgery. The challenger only
    verifies a legal, fresh forgery (otherwise the bit is already false). -/
def forgeEventM (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) :
    LogM Bool := do
  let keys ← generateKeypair (logOracle world.oracle) v world.seed
  let outcome ← runM limits (fun m => sign (logOracle world.oracle) v keys.2 m) strategy
    limits.signingAttempts ⟨keys.1, []⟩
  match outcome with
  | .exhausted _ => pure false
  | .forgery view m s =>
    if (legal limits m && fresh limits view m) = true then do
      let r ← verify (logOracle world.oracle) v keys.1 m s
      pure (r.getD false)
    else pure false

theorem forgeEvent_keys (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) :
    forgeEvent v limits strategy world =
      wins limits (fun m s => (verify world.oracle v
          (run limits (fun m => sign world.oracle v (generateKeypair world.oracle v world.seed).2 m)
            strategy limits.signingAttempts ⟨(generateKeypair world.oracle v world.seed).1, []⟩).view.publicKey
          m s).getD false)
        (run limits (fun m => sign world.oracle v (generateKeypair world.oracle v world.seed).2 m)
          strategy limits.signingAttempts ⟨(generateKeypair world.oracle v world.seed).1, []⟩) := rfl

theorem forgeEventM_good (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) :
    Good AnyReq (forgeEventM v limits strategy world) (forgeEvent v limits strategy world) := by
  rw [forgeEvent_keys]
  simp only [forgeEventM]
  apply Good.bind' (Good.mono (fun _ _ => trivial) (keygen_good world.oracle v world.seed))
  apply Good.bind' (runM_good limits _ _
    (fun m => Good.mono (fun _ _ => trivial) (sign_good world.oracle v _ m)) _ _ _)
  have hpk := run_preserves_public_key limits
    (fun m => sign world.oracle v (generateKeypair world.oracle v world.seed).2 m)
    strategy limits.signingAttempts ⟨(generateKeypair world.oracle v world.seed).1, []⟩
  generalize run limits (fun m => sign world.oracle v (generateKeypair world.oracle v world.seed).2 m)
    strategy limits.signingAttempts ⟨(generateKeypair world.oracle v world.seed).1, []⟩ = O at hpk ⊢
  cases O with
  | exhausted view => exact Good.pure' _
  | forgery view m s =>
    simp only [Outcome.view] at hpk
    simp only [wins, Outcome.view, hpk]
    cases (legal limits m && fresh limits view m)
    · exact Good.pure' _
    · exact Good.bind' (verify_sim _ _ _ _ _) (Good.pure' _)

theorem forgeEventM_cost (v : Variant) (limits : Limits) (strategy : Strategy) (world : World) :
    Cost (forgeEventM v limits strategy world)
      (keygenCost v + limits.signingAttempts * signCost v + verifyCost v) := by
  simp only [forgeEventM]
  refine Cost.bind_sub (keygen_cost _ _ _) (fun keys => ?_) (by omega)
  refine Cost.bind_sub (runM_cost limits _ _ (fun m => sign_cost _ _ _ m) _ _ _)
    (fun O => ?_) (by omega)
  cases O with
  | exhausted _ => exact Cost.pure_le _ _
  | forgery view m s =>
    apply Cost.ite'
    · intro _
      exact Cost.mono (Cost.bind' (verify_cost _ _ _ _ _) (fun _ => Cost.pure' _)) (by omega)
    · intro _; exact Cost.pure_le _ _

/-- The challenger's primitive budget. Running the EUF-CMA experiment with
    every primitive request logged returns exactly the forgery bit of
    `forgeEvent`, and issues at most one key generation's, `q_s` signing
    calls' and one verification's worth of requests. -/
theorem challenger_request_budget (v : Variant) (limits : Limits) (strategy : Strategy)
    (world : World) :
    ((forgeEventM v limits strategy world).run []).1 = forgeEvent v limits strategy world ∧
    ((forgeEventM v limits strategy world).run []).2.length ≤
      keygenCost v + limits.signingAttempts * signCost v + verifyCost v := by
  refine ⟨(forgeEventM_good v limits strategy world).run_empty.1, ?_⟩
  obtain ⟨L, e, c⟩ := forgeEventM_cost v limits strategy world []
  rw [e]
  simpa using c

end Security

#print axioms Security.challenger_request_budget
#print axioms deployed_request_bounds
#print axioms sign_cost
#print axioms verify_cost
#print axioms keygen_cost
#print axioms verify_sim

end DSM.Sphincs
