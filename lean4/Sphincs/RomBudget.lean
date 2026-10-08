-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomCanon

/- The query budget.

   The counting theorems of H1 and H1' are stated against budget hypotheses: a
   step bound `S` and an adversary-step bound `AA` on the symbolic traces of
   H1', and the draw counts `N`, `q`, `JA` of H1's run. Here they are derived
   from the adversary's query budget: `qh` hash queries and `qs` signing queries
   on every path of its strategy tree (`Budget`).

   `Cost P K A C`: on every tape and from every state, the symbolic trace of `P`
   has at most `K` steps, of which at most `A` are adversary steps, and both runs
   (real and symbolic) append at most `K` entries, at most `A` of them adversary
   entries and at most `C` challenger `h_msg` entries. Costs compose (`bind`,
   `forIn`) and are computed for every routine of the signer, the verifier, key
   generation and the extension, giving closed-form bounds in the parameters. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- Challenger `h_msg` entries. -/
def cntH (l : List (Bool × SReq)) : Nat := (l.filter (fun e => !e.1 && e.2.mode == 2)).length

/-- Step and entry cost of a symbolic program, uniformly over tapes, states and runs. -/
def Cost {α : Type} (P : Prog α) (K A C : Nat) : Prop :=
  ∀ t st, (strace t P st).length ≤ K ∧ ((strace t P st).filter isAev).length ≤ A ∧
    ∀ real, (xrun real t P st).2.ents.length ≤ st.ents.length + K ∧
      cntT (xrun real t P st).2.ents ≤ cntT st.ents + A ∧
      cntH (xrun real t P st).2.ents ≤ cntH st.ents + C

namespace Cost

theorem mono {α : Type} {P : Prog α} {K A C K' A' C' : Nat} (h : Cost P K A C) (hK : K ≤ K') (hA : A ≤ A')
    (hC : C ≤ C') : Cost P K' A' C' := fun t st =>
  let ⟨h1, h2, h3⟩ := h t st
  ⟨by omega, by omega, fun real => let ⟨a, b, c⟩ := h3 real; ⟨by omega, by omega, by omega⟩⟩

theorem done {α : Type} (a : α) : Cost (.done a) 0 0 0 := fun t st =>
  ⟨by simp [strace], by simp [strace], fun real => by simp [xrun]⟩

theorem pure {α : Type} (a : α) : Cost (pure a : Prog α) 0 0 0 := done a

theorem askC_gen {α : Type} (r : SReq) {k : SV → Prog α} {K A C : Nat} (hk : ∀ v, Cost (k v) K A C) :
    Cost (.askC r k) (K+1) A (C + if r.mode = 2 then 1 else 0) := by
  intro t st
  obtain ⟨h1, h2, -⟩ := hk (.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen) t
    (addC st (firstIdx (mC false t st.rev r) st.ents) r)
  refine ⟨by simp only [strace, List.length_cons]; omega,
    by simp only [strace, List.filter_cons, isAev, Bool.false_eq_true, if_false]; exact h2, fun real => ?_⟩
  simp only [xrun]
  generalize firstIdx (mC real t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have e : addC st i r = st := by simp [addC, hl]
    rw [e]
    obtain ⟨a, b, c⟩ := (hk (.hid i r.outLen) t st).2.2 real
    exact ⟨by omega, b, by split <;> omega⟩
  · have e : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [e]
    obtain ⟨a, b, c⟩ := (hk (.hid i r.outLen) t ⟨st.ents ++ [(false, r)], st.rev⟩).2.2 real
    simp only [List.length_append, List.length_singleton] at a
    have hb : cntT (st.ents ++ [(false, r)]) = cntT st.ents := by simp [cntT, List.filter_append]
    have hc : cntH (st.ents ++ [(false, r)]) = cntH st.ents + if r.mode = 2 then 1 else 0 := by
      simp only [cntH, List.filter_append, List.length_append]
      by_cases hm : r.mode = 2 <;> simp [hm]
    simp only at b c
    rw [hb] at b; rw [hc] at c
    exact ⟨by omega, b, by omega⟩

theorem askC {α : Type} (r : SReq) {k : SV → Prog α} {K A C : Nat} (hk : ∀ v, Cost (k v) K A C)
    (hm : r.mode ≠ 2) : Cost (.askC r k) (K+1) A C := by
  have := askC_gen r hk
  rwa [if_neg hm, Nat.add_zero] at this

theorem askC2 {α : Type} (r : SReq) {k : SV → Prog α} {K A C : Nat} (hk : ∀ v, Cost (k v) K A C) :
    Cost (.askC r k) (K+1) A (C+1) :=
  (askC_gen r hk).mono (Nat.le_refl _) (Nat.le_refl _) (by split <;> omega)

theorem askA {α : Type} (q : Request) {k : Bytes → Prog α} {K A C : Nat} (hk : ∀ b, Cost (k b) K A C) :
    Cost (.askA q k) (K+1) (A+1) C := by
  intro t st
  obtain ⟨h1, h2, -⟩ := hk (be q.outLen (t.getD (firstIdx (mA false t st.rev q) st.ents) 0)) t
    (addA st (firstIdx (mA false t st.rev q) st.ents) q)
  refine ⟨by simp only [strace, List.length_cons]; omega,
    by simp only [strace, List.filter_cons, isAev, if_true, List.length_cons]; omega, fun real => ?_⟩
  simp only [xrun]
  generalize firstIdx (mA real t st.rev q) st.ents = i
  by_cases hl : i < st.ents.length
  · have e : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
    rw [e]
    obtain ⟨a, b, c⟩ := (hk (be q.outLen (t.getD i 0)) t ⟨st.ents, i :: st.rev⟩).2.2 real
    simp only at a b c
    exact ⟨by omega, by omega, c⟩
  · have e : addA st i q = ⟨st.ents ++ [(true, lift q)], i :: st.rev⟩ := by simp [addA, hl]
    rw [e]
    obtain ⟨a, b, c⟩ := (hk (be q.outLen (t.getD i 0)) t ⟨st.ents ++ [(true, lift q)], i :: st.rev⟩).2.2 real
    simp only [List.length_append, List.length_singleton] at a b c
    have hb : cntT (st.ents ++ [(true, lift q)]) = cntT st.ents + 1 := by simp [cntT, List.filter_append]
    have hc : cntH (st.ents ++ [(true, lift q)]) = cntH st.ents := by simp [cntH, List.filter_append]
    rw [hb] at b; rw [hc] at c
    exact ⟨by omega, by omega, c⟩

theorem reveal {α : Type} (x : List SV) {k : Bytes → Prog α} {K A C : Nat} (hk : ∀ b, Cost (k b) K A C) :
    Cost (.reveal x k) (K+1) A C := by
  intro t st
  obtain ⟨h1, h2, -⟩ := hk (sres t x) t ⟨st.ents, shids x ++ st.rev⟩
  refine ⟨by simp only [strace, List.length_cons]; omega,
    by simp only [strace, List.filter_cons, isAev, Bool.false_eq_true, if_false]; exact h2, fun real => ?_⟩
  simp only [xrun]
  obtain ⟨a, b, c⟩ := (hk (sres t x) t ⟨st.ents, shids x ++ st.rev⟩).2.2 real
  simp only at a b c
  exact ⟨by omega, b, c⟩

theorem bind {α β : Type} {P : Prog α} {f : α → Prog β} {K1 A1 C1 K2 A2 C2 : Nat} (hP : Cost P K1 A1 C1)
    (hf : ∀ a, Cost (f a) K2 A2 C2) : Cost (P >>= f) (K1+K2) (A1+A2) (C1+C2) := by
  intro t st
  rw [prog_bind_eq]
  obtain ⟨p1, p2, p3⟩ := hP t st
  obtain ⟨f1, f2, -⟩ := hf (xrun false t P st).1 t (xrun false t P st).2
  refine ⟨by rw [strace_bind, List.length_append]; omega,
    by rw [strace_bind, List.filter_append, List.length_append]; omega, fun real => ?_⟩
  rw [xrun_bind]
  obtain ⟨a, b, c⟩ := p3 real
  obtain ⟨a', b', c'⟩ := (hf (xrun real t P st).1 t (xrun real t P st).2).2.2 real
  exact ⟨by omega, by omega, by omega⟩

theorem pbind {α β : Type} (a : α) {f : α → Prog β} {K A C : Nat} (h : Cost (f a) K A C) :
    Cost (Pure.pure a >>= f) K A C := h

theorem ite {α : Type} {b : Prop} [Decidable b] {P Q : Prog α} {K A C : Nat} (hP : b → Cost P K A C)
    (hQ : ¬b → Cost Q K A C) : Cost (if b then P else Q) K A C := by
  by_cases h : b
  · rw [if_pos h]; exact hP h
  · rw [if_neg h]; exact hQ h

/-- A loop over `l` costs at most `l.length` times the per-iteration cost. -/
theorem forIn {ι σ : Type} {K A C : Nat} (f : ι → σ → Prog (ForInStep σ)) :
    ∀ (l : List ι), (∀ x ∈ l, ∀ s, Cost (f x s) K A C) →
      ∀ s, Cost (forIn l s f) (l.length * K) (l.length * A) (l.length * C)
  | [], _, s => by simp only [List.forIn_nil, List.length_nil, Nat.zero_mul]; exact Cost.pure s
  | x :: l, hf, s => by
    rw [List.forIn_cons]
    refine (bind (f := fun r => match r with
        | ForInStep.done b => Pure.pure b
        | ForInStep.yield b => ForIn.forIn l b f)
      (K2 := l.length * K) (A2 := l.length * A) (C2 := l.length * C) (hf x (by simp) s) ?_).mono ?_ ?_ ?_
    · intro r
      cases r with
      | done b => exact (Cost.pure b).mono (Nat.zero_le _) (Nat.zero_le _) (Nat.zero_le _)
      | yield b => exact forIn f l (fun y hy => hf y (by simp [hy])) b
    all_goals simp [Nat.succ_mul]; omega

end Cost

/-! The signer's routines. -/

section
variable (p : Params)

theorem cost_ask (r : SReq) (hm : r.mode ≠ 2) : Cost (sAsk r) 1 0 0 :=
  Cost.askC r (fun _ => Cost.done _) hm

theorem cost_derive (ctx : String) (x : SB) : Cost (sDeriveKey ctx x) 1 0 0 :=
  cost_ask _ (by simp)

theorem cost_keyed (n : Nat) (k x : SB) : Cost (sKeyed n k x) 1 0 0 := cost_ask _ (by simp)

theorem cost_thash (tk : SB) (a : Adrs) (x : SB) : Cost (sThash p tk a x) 1 0 0 := cost_keyed _ _ _

theorem cost_prf (k sd : SB) (a : Adrs) : Cost (sPrf p k sd a) 1 0 0 := cost_keyed _ _ _

theorem cost_hmsg (r sd root : SB) (m : Bytes) : Cost (sHmsg p r sd root m) 1 0 1 :=
  Cost.askC2 _ (fun _ => Cost.done _)

theorem cost_chain (tk : SB) (a : Adrs) : ∀ (steps start : Nat) (x : SB),
    Cost (sChain p tk a x start steps) steps 0 0
  | 0, _, x => Cost.pure x
  | steps+1, start, x => by
    simp only [sChain]
    exact (Cost.bind (cost_thash p tk _ x) (fun y => cost_chain tk a steps (start+1) y)).mono
      (by omega) (Nat.le_refl _) (Nat.le_refl _)

theorem cost_wotsPkgen (tk k sd : SB) (a : Adrs) : Cost (sWotsPkgen p tk k sd a) (16 * p.len + 1) 0 0 := by
  simp only [sWotsPkgen, sWotsCompress]
  refine (Cost.bind (Cost.forIn (K := 16) (A := 0) (C := 0) _ (List.range p.len) (fun i _ s => ?_) [])
    (fun tops => cost_thash p tk _ tops)).mono (by simp; omega) (by simp) (by simp)
  exact (Cost.bind (cost_prf p k sd _) (fun sk => Cost.bind (cost_chain p tk _ 15 0 sk)
    (fun top => Cost.bind (Cost.pure _) (fun _ => Cost.pure _)))).mono (by omega) (by omega) (by omega)

end

/-- Steps of an XMSS node of height `h`. -/
def xC (p : Params) : Nat → Nat
  | 0 => 16 * p.len + 1
  | h+1 => 2 * xC p h + 1

/-- Steps of a FORS node of height `h`. -/
def fC : Nat → Nat
  | 0 => 2
  | h+1 => 2 * fC h + 1

theorem xC_mono (p : Params) : ∀ {h h' : Nat}, h ≤ h' → xC p h ≤ xC p h'
  | _, 0, hle => by rw [Nat.le_zero.mp hle]; exact Nat.le_refl _
  | h, h'+1, hle => by
    rcases Nat.lt_or_eq_of_le hle with hlt | rfl
    · have := xC_mono p (show h ≤ h' by omega); simp only [xC]; omega
    · exact Nat.le_refl _

theorem fC_mono : ∀ {h h' : Nat}, h ≤ h' → fC h ≤ fC h'
  | _, 0, hle => by rw [Nat.le_zero.mp hle]; exact Nat.le_refl _
  | h, h'+1, hle => by
    rcases Nat.lt_or_eq_of_le hle with hlt | rfl
    · have := fC_mono (show h ≤ h' by omega); simp only [fC]; omega
    · exact Nat.le_refl _

/-- Steps of an XMSS signature and of the root recomputation from one. -/
def xsC (p : Params) : Nat := p.hp * xC p p.hp + 16 * p.len
def xpC (p : Params) : Nat := 15 * p.len + 1 + p.hp

section
variable (p : Params)

theorem cost_xmssNode (tk k sd : SB) (a : Adrs) : ∀ (h idx : Nat), Cost (sXmssNode p tk k sd a idx h) (xC p h) 0 0
  | 0, idx => by simp only [sXmssNode, xC]; exact cost_wotsPkgen p tk k sd _
  | h+1, idx => by
    simp only [sXmssNode, xC]
    exact (Cost.bind (cost_xmssNode tk k sd a h _) (fun l => Cost.bind (cost_xmssNode tk k sd a h _)
      (fun r => cost_thash p tk _ _))).mono (by omega) (by omega) (by omega)

theorem digit_le {msg : Bytes} {x : Nat × Nat} (hx : x ∈ (wotsDigits p msg).zipIdx) : x.1 ≤ 15 := by
  have hx' := List.mem_zipIdx_iff_getElem?.mp hx
  have := digits_le15 p msg x.2
  rw [List.getD_eq_getElem?_getD, hx'] at this
  simpa using this

theorem cost_wotsSign (tk k sd : SB) (a : Adrs) (msg : Bytes) : Cost (sWotsSign p tk k sd a msg) (16 * p.len) 0 0 := by
  simp only [sWotsSign]
  refine (Cost.bind (Cost.forIn (K := 16) (A := 0) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun sig => Cost.pure _)).mono (by simp [wots_digit_count]; omega) (by simp) (by simp)
  have := digit_le p hx
  exact (Cost.bind (cost_prf p k sd _) (fun sk => Cost.bind (cost_chain p tk _ x.1 0 sk)
    (fun part => Cost.bind (Cost.pure _) (fun _ => Cost.pure _)))).mono (by omega) (by omega) (by omega)

theorem cost_xmssSign (tk k sd : SB) (a : Adrs) (idx : Nat) (msg : Bytes) :
    Cost (sXmssSign p tk k sd a idx msg) (xsC p) 0 0 := by
  simp only [sXmssSign, xsC]
  refine (Cost.bind (Cost.forIn (K := xC p p.hp) (A := 0) (C := 0) _ _ (fun l hl s => ?_) [])
    (fun auth => Cost.bind (cost_wotsSign p tk k sd _ msg) (fun sig => Cost.pure _))).mono
    (by simp) (by simp) (by simp)
  have hl' := List.mem_range.mp hl
  exact (Cost.bind (cost_xmssNode p tk k sd a l _) (fun node => Cost.bind (Cost.pure _)
    (fun _ => Cost.pure _))).mono (by have := xC_mono p (show l ≤ p.hp by omega); omega) (by omega) (by omega)

theorem cost_authWalk (tk : SB) (a : Adrs) (auth : SB) : ∀ (r li gi : Nat) (node : SB) (level : Nat),
    Cost (sAuthWalk p tk a li gi node auth level r) r 0 0
  | 0, _, _, node, _ => Cost.pure node
  | r+1, li, gi, node, level => by
    simp only [sAuthWalk]
    exact (Cost.bind (cost_thash p tk _ _) (fun y => cost_authWalk tk a auth r _ _ y _)).mono
      (by omega) (Nat.le_refl _) (Nat.le_refl _)

theorem cost_wotsPkFromSig (tk : SB) (a : Adrs) (sig : SB) (msg : Bytes) :
    Cost (sWotsPkFromSig p tk a sig msg) (15 * p.len + 1) 0 0 := by
  simp only [sWotsPkFromSig, sWotsCompress]
  refine (Cost.bind (Cost.forIn (K := 15) (A := 0) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun tops => cost_thash p tk _ tops)).mono (by simp [wots_digit_count]; omega) (by simp) (by simp)
  exact (Cost.bind (cost_chain p tk _ (15 - x.1) x.1 _) (fun top => Cost.bind (Cost.pure _)
    (fun _ => Cost.pure _))).mono (by omega) (by omega) (by omega)

theorem cost_xmssPkFromSig (tk : SB) (a : Adrs) (idx : Nat) (sig : SB) (msg : Bytes) :
    Cost (sXmssPkFromSig p tk a idx sig msg) (xpC p) 0 0 := by
  simp only [sXmssPkFromSig, sAuthRoot, xpC]
  exact (Cost.bind (cost_wotsPkFromSig p tk _ _ msg) (fun node => cost_authWalk p tk _ _ p.hp _ _ node 0)).mono
    (Nat.le_refl _) (Nat.le_refl _) (Nat.le_refl _)

theorem cost_htRootTail (tk : SB) : ∀ (r layer tree : Nat) (node sig : SB),
    Cost (sHtRootTail p tk layer tree node sig r) (r * (1 + xpC p)) 0 0
  | 0, _, _, node, _ => (Cost.pure node).mono (by simp) (Nat.le_refl _) (Nat.le_refl _)
  | r+1, layer, tree, node, sig => by
    simp only [sHtRootTail]
    exact (Cost.bind (Cost.reveal _ (fun nb => cost_xmssPkFromSig p tk _ _ _ nb))
      (fun root => cost_htRootTail tk r _ _ root _)).mono (by rw [Nat.succ_mul]; omega) (by omega) (by omega)

theorem cost_htRoot (tk : SB) (sig msg : SB) (tree leaf : Nat) (hd : 1 ≤ p.d) :
    Cost (sHtRoot p tk sig msg tree leaf) (p.d * (1 + xpC p)) 0 0 := by
  simp only [sHtRoot]
  refine (Cost.bind (Cost.reveal _ (fun mb => cost_xmssPkFromSig p tk _ _ _ mb))
    (fun node => cost_htRootTail p tk (p.d - 1) _ _ node _)).mono ?_ (by omega) (by omega)
  obtain ⟨d', hd'⟩ : ∃ d', p.d = d' + 1 := ⟨p.d - 1, by omega⟩
  rw [hd', Nat.add_sub_cancel, Nat.succ_mul]; omega

theorem cost_htSignTail (tk k sd : SB) : ∀ (r layer tree : Nat) (node : SB),
    Cost (sHtSignTail p tk k sd layer tree node r) (r * (1 + xsC p + xpC p)) 0 0
  | 0, _, _, _ => (Cost.pure _).mono (by simp) (Nat.le_refl _) (Nat.le_refl _)
  | r+1, layer, tree, node => by
    simp only [sHtSignTail]
    refine (Cost.reveal (K := xsC p + (xpC p + r * (1 + xsC p + xpC p))) (A := 0) (C := 0) _
      (fun nb => ?_)).mono (by rw [Nat.succ_mul]; omega) (by omega) (by omega)
    refine (Cost.bind (K2 := xpC p + r * (1 + xsC p + xpC p)) (A2 := 0) (C2 := 0)
      (cost_xmssSign p tk k sd _ _ nb) (fun part => ?_)).mono (by omega) (by omega) (by omega)
    refine Cost.ite (fun _ => (Cost.pure _).mono (Nat.zero_le _) (Nat.le_refl _) (Nat.le_refl _)) (fun _ => ?_)
    exact (Cost.bind (cost_xmssPkFromSig p tk _ _ part nb) (fun root => Cost.bind
      (cost_htSignTail tk k sd r _ _ root) (fun tail => Cost.pure _))).mono (by omega) (by omega) (by omega)

theorem cost_htSign (tk k sd : SB) (msg : SB) (tree leaf : Nat) (hd : 1 ≤ p.d) :
    Cost (sHtSign p tk k sd msg tree leaf) (p.d * (1 + xsC p + xpC p)) 0 0 := by
  simp only [sHtSign]
  refine (Cost.reveal _ (fun mb => (Cost.bind (cost_xmssSign p tk k sd _ _ mb) (fun first =>
    Cost.bind (cost_xmssPkFromSig p tk _ _ first mb) (fun root =>
      Cost.bind (cost_htSignTail p tk k sd (p.d - 1) _ _ root) (fun tail => Cost.pure _)))))).mono ?_
    (by omega) (by omega)
  obtain ⟨d', hd'⟩ : ∃ d', p.d = d' + 1 := ⟨p.d - 1, by omega⟩
  rw [hd', Nat.add_sub_cancel, Nat.succ_mul]; omega

theorem cost_forsNode (tk k sd : SB) (a : Adrs) : ∀ (h idx : Nat), Cost (sForsNode p tk k sd a idx h) (fC h) 0 0
  | 0, idx => by
    simp only [sForsNode, sForsSecret, fC]
    exact (Cost.bind (cost_prf p k sd _) (fun sk => cost_thash p tk _ sk)).mono (by omega) (by omega) (by omega)
  | h+1, idx => by
    simp only [sForsNode, fC]
    exact (Cost.bind (cost_forsNode tk k sd a h _) (fun l => Cost.bind (cost_forsNode tk k sd a h _)
      (fun r => cost_thash p tk _ _))).mono (by omega) (by omega) (by omega)

theorem cost_forsSign (tk k sd : SB) (a : Adrs) (md : Bytes) :
    Cost (sForsSign p tk k sd a md) (p.k * (1 + p.a * fC p.a)) 0 0 := by
  simp only [sForsSign]
  refine (Cost.bind (Cost.forIn (K := 1 + p.a * fC p.a) (A := 0) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun sig => Cost.pure _)).mono (by simp [base2b_length]) (by simp) (by simp)
  refine (Cost.bind (K2 := p.a * fC p.a) (A2 := 0) (C2 := 0) (cost_prf p k sd _) (fun sk => ?_)).mono
    (Nat.le_refl _) (by omega) (by omega)
  refine (Cost.bind (Cost.forIn (K := fC p.a) (A := 0) (C := 0) _ _ (fun l hl s' => ?_) _)
    (fun r => Cost.pure _)).mono (by simp) (by simp) (by simp)
  have hl' := List.mem_range.mp hl
  exact (Cost.bind (cost_forsNode p tk k sd a l _) (fun node => Cost.bind (Cost.pure _)
    (fun _ => Cost.pure _))).mono (by have := fC_mono (show l ≤ p.a by omega); omega) (by omega) (by omega)

theorem cost_forsPkFromSig (tk : SB) (a : Adrs) (sig : SB) (md : Bytes) :
    Cost (sForsPkFromSig p tk a sig md) (p.k * (1 + p.a) + 1) 0 0 := by
  simp only [sForsPkFromSig, sAuthRoot]
  refine (Cost.bind (Cost.forIn (K := 1 + p.a) (A := 0) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun roots => cost_thash p tk _ roots)).mono (by simp [base2b_length]) (by simp) (by simp)
  exact (Cost.bind (cost_thash p tk _ _) (fun leaf => Cost.bind (cost_authWalk p tk _ _ p.a _ _ leaf 0)
    (fun root => Cost.bind (Cost.pure _) (fun _ => Cost.pure _)))).mono (by omega) (by omega) (by omega)

end

/-! The adversary-side verification, key generation, signing and the extension. -/

def signC (p : Params) : Nat :=
  8 + p.k * (1 + p.a * fC p.a) + (p.k * (1 + p.a) + 1) + p.d * (1 + xsC p + xpC p) + p.d * (1 + xpC p)
def verC (p : Params) : Nat := 2 + (p.k * (1 + p.a) + 1) + p.d * xpC p
def kgC (p : Params) : Nat := 2 + xC p p.hp
def extC (p : Params) : Nat :=
  4 + p.k * 2 + p.d * (16 * p.len + 1) + (p.k * fC p.a + 1 + p.d * xC p p.hp)

section
variable (p : Params)

theorem cost_adv (q : Request) : Cost (advP q) 1 1 0 := Cost.askA q (fun b => Cost.done b)

theorem cost_vchain (tk : Bytes) (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    Cost (chain advP p tk a x start steps) steps steps 0
  | 0, x, _ => Cost.pure x
  | steps+1, x, start => by
    simp only [chain]
    exact (Cost.bind (cost_adv _) (fun y => cost_vchain tk a steps y (start+1))).mono
      (by omega) (by omega) (Nat.le_refl _)

theorem cost_vauthWalk (tk : Bytes) (a : Adrs) (auth : Bytes) :
    ∀ (r li gi level : Nat) (node : Bytes), Cost (authWalk advP p tk a li gi node auth level r) r r 0
  | 0, _, _, _, node => Cost.pure node
  | r+1, li, gi, level, node => by
    simp only [authWalk]
    exact (Cost.bind (cost_adv _) (fun y => cost_vauthWalk tk a auth r _ _ _ y)).mono
      (by omega) (by omega) (Nat.le_refl _)

theorem cost_vwotsPkFromSig (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
    Cost (wotsPkFromSig advP p tk a sig msg) (15 * p.len + 1) (15 * p.len + 1) 0 := by
  simp only [wotsPkFromSig, wotsCompress]
  refine (Cost.bind (Cost.forIn (K := 15) (A := 15) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun tops => cost_adv _)).mono (by simp [wots_digit_count]; omega) (by simp [wots_digit_count]; omega) (by simp)
  obtain ⟨digit, i⟩ := x
  exact (Cost.bind (cost_vchain p tk _ (15 - digit) _ digit) (fun top => Cost.pure _)).mono
    (by omega) (by omega) (by omega)

theorem cost_vxmssPkFromSig (tk : Bytes) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Cost (xmssPkFromSig advP p tk a idx sig msg) (xpC p) (xpC p) 0 := by
  simp only [xmssPkFromSig, authRoot, xpC]
  exact (Cost.bind (cost_vwotsPkFromSig p tk _ _ _) (fun node => cost_vauthWalk p tk _ _ p.hp _ _ 0 node)).mono
    (Nat.le_refl _) (Nat.le_refl _) (Nat.le_refl _)

theorem cost_vhtRootTail (tk : Bytes) : ∀ (r layer tree : Nat) (node sig : Bytes),
    Cost (htRootTail advP p tk layer tree node sig r) (r * xpC p) (r * xpC p) 0
  | 0, _, _, node, _ => (Cost.pure node).mono (by simp) (by simp) (Nat.le_refl _)
  | r+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact (Cost.bind (cost_vxmssPkFromSig p tk _ _ _ _) (fun root => cost_vhtRootTail tk r _ _ root _)).mono
      (by rw [Nat.succ_mul]; omega) (by rw [Nat.succ_mul]; omega) (Nat.le_refl _)

theorem cost_vhtRoot (tk sig msg : Bytes) (tree leaf : Nat) (hd : 1 ≤ p.d) :
    Cost (htRoot advP p tk sig msg tree leaf) (p.d * xpC p) (p.d * xpC p) 0 := by
  simp only [htRoot]
  have e : xpC p + (p.d - 1) * xpC p = p.d * xpC p := by
    obtain ⟨d', hd'⟩ : ∃ d', p.d = d' + 1 := ⟨p.d - 1, by omega⟩
    rw [hd', Nat.add_sub_cancel, Nat.succ_mul]; omega
  exact (Cost.bind (cost_vxmssPkFromSig p tk _ _ _ _) (fun node => cost_vhtRootTail p tk (p.d - 1) _ _ node _)).mono
    (Nat.le_of_eq e) (Nat.le_of_eq e) (Nat.le_refl _)

theorem cost_vforsPkFromSig (tk : Bytes) (a : Adrs) (sig md : Bytes) :
    Cost (forsPkFromSig advP p tk a sig md) (p.k * (1 + p.a) + 1) (p.k * (1 + p.a) + 1) 0 := by
  simp only [forsPkFromSig, authRoot]
  refine (Cost.bind (Cost.forIn (K := 1 + p.a) (A := 1 + p.a) (C := 0) _ _ (fun x hx s => ?_) [])
    (fun roots => cost_adv _)).mono (by simp [base2b_length]) (by simp [base2b_length]) (by simp)
  obtain ⟨idx, i⟩ := x
  exact (Cost.bind (cost_adv _) (fun leaf => Cost.bind (cost_vauthWalk p tk _ _ p.a _ _ 0 leaf)
    (fun root => Cost.pure _))).mono (by omega) (by omega) (by omega)

theorem cost_verify (v : Variant) (pk msg sig : Bytes) :
    Cost (verify advP v pk msg sig) (verC (params v)) (verC (params v)) 0 := by
  have hd : 1 ≤ (params v).d := by cases v <;> decide
  simp only [verify, verC]
  refine Cost.ite (fun _ => (Cost.pure _).mono (Nat.zero_le _) (Nat.zero_le _) (Nat.le_refl _)) (fun _ => ?_)
  refine Cost.pbind _ ?_
  refine Cost.ite (fun _ => (Cost.pure _).mono (Nat.zero_le _) (Nat.zero_le _) (Nat.le_refl _)) (fun _ => ?_)
  refine Cost.pbind _ ?_
  exact (Cost.bind (cost_adv _) (fun tk => Cost.bind (cost_adv _) (fun dg =>
    Cost.bind (cost_vforsPkFromSig _ tk _ _ _) (fun fpk => Cost.bind (cost_vhtRoot _ tk _ _ _ _ hd)
      (fun ac => Cost.pure _))))).mono (by omega) (by omega) (by omega)

theorem cost_sign (v : Variant) (sk : SB) (msg : Bytes) : Cost (sSign v sk msg) (signC (params v)) 0 1 := by
  have hd : 1 ≤ (params v).d := by cases v <;> decide
  simp only [sSign, signC]
  refine Cost.ite (fun _ => (Cost.pure _).mono (Nat.zero_le _) (Nat.le_refl _) (Nat.zero_le _)) (fun _ => ?_)
  refine Cost.pbind _ ?_
  refine (Cost.bind (cost_derive _ _) (fun tk => Cost.bind (cost_derive _ _) (fun pk =>
    Cost.bind (cost_derive _ _) (fun mk => Cost.bind (cost_keyed _ _ _) (fun r =>
      Cost.bind (cost_hmsg _ _ _ _ _) (fun dg => Cost.reveal
        (K := (params v).k * (1 + (params v).a * fC (params v).a) +
          (((params v).k * (1 + (params v).a) + 1) + ((params v).d * (1 + xsC (params v) + xpC (params v)) +
          ((params v).d * (1 + xpC (params v)) + 2)))) (A := 0) (C := 0) _ (fun dgb => ?_))))))).mono
    (by omega) (by omega) (by omega)
  exact (Cost.bind (cost_forsSign _ _ _ _ _ _) (fun fs => Cost.bind (cost_forsPkFromSig _ _ _ fs _)
    (fun fpk => Cost.bind (cost_htSign _ _ _ _ fpk _ _ hd) (fun hs => Cost.bind (cost_htRoot _ _ hs fpk _ _ hd)
      (fun ac => Cost.reveal _ (fun _ => Cost.reveal _ (fun _ =>
        Cost.ite (fun _ => Cost.pure _) (fun _ => Cost.pbind _ (Cost.pure _))))))))).mono
    (by omega) (by omega) (by omega)

theorem cost_kgTail (v : Variant) (ex : SB) : Cost (sKgTail v ex) (kgC (params v)) 0 0 := by
  simp only [sKgTail, kgC]
  exact (Cost.bind (cost_derive _ _) (fun tk => Cost.bind (cost_derive _ _) (fun pk =>
    Cost.bind (cost_xmssNode _ _ _ _ _ (params v).hp 0) (fun root => Cost.pure _)))).mono
    (by omega) (by omega) (by omega)

theorem cost_extTail (tk k sd : SB) (I : Indices) :
    Cost (sExtTail p tk k sd I) (p.k * fC p.a + 1 + p.d * xC p p.hp) 0 0 := by
  simp only [sExtTail]
  refine (Cost.bind (Cost.forIn (K := fC p.a) (A := 0) (C := 0) _ (List.range p.k) (fun i _ s => ?_) [])
    (fun roots => Cost.bind (cost_thash p tk _ roots) (fun _ =>
      Cost.bind (Cost.forIn (K := xC p p.hp) (A := 0) (C := 0) _ (List.range p.d) (fun l _ s => ?_) PUnit.unit)
        (fun _ => Cost.pure _)))).mono
    (by simp; omega) (by simp) (by simp)
  · exact (Cost.bind (cost_forsNode p tk k sd _ p.a i) (fun r => Cost.pbind _ (Cost.pure _))).mono
      (by omega) (by omega) (by omega)
  · exact (Cost.bind (cost_xmssNode p tk k sd _ p.hp 0) (fun _ => Cost.pbind _ (Cost.pure _))).mono
      (by omega) (by omega) (by omega)

theorem cost_extW (v : Variant) (sk : SB) (msg sig : Bytes) : Cost (sExtW v sk msg sig) (extC (params v)) 1 0 := by
  simp only [sExtW, extC]
  refine (Cost.bind (cost_derive _ _) (fun tk => Cost.bind (cost_derive _ _) (fun pk =>
    Cost.bind (Cost.reveal _ (fun sr => cost_adv _)) (fun dg =>
      Cost.bind (Cost.forIn (K := 2) (A := 0) (C := 0) _ _ (fun i _ s => ?_) PUnit.unit) (fun _ =>
        Cost.bind (Cost.forIn (K := 16 * (params v).len + 1) (A := 0) (C := 0) _ _ (fun l _ s => ?_) PUnit.unit)
          (fun _ => cost_extTail _ _ _ _ _)))))).mono (by simp; omega) (by simp) (by simp)
  · exact (Cost.bind (cost_forsNode _ _ _ _ _ 0 _) (fun _ => Cost.bind (Cost.pure _)
      (fun _ => Cost.pure _))).mono (by simp [fC]) (by omega) (by omega)
  · exact (Cost.bind (cost_wotsPkgen _ _ _ _ _) (fun _ => Cost.bind (Cost.pure _)
      (fun _ => Cost.pure _))).mono (by omega) (by omega) (by omega)

end

/-! The adversary's budget and the game's cost. -/

/-- The adversary's query budget: on every path of its strategy tree, at most
    `qh` hash queries and at most `qs` signing queries (legal or not). The
    final output is free. -/
def Budget : RAdv → Nat → Nat → Prop
  | .hq _ k, qh, qs => 0 < qh ∧ ∀ b, Budget (k b) (qh - 1) qs
  | .sq _ k, qh, qs => 0 < qs ∧ ∀ o, Budget (k o) qh (qs - 1)
  | .out _ _, _, _ => True

/-- Steps of the game after key generation. -/
def playK (p : Params) (qh qs : Nat) : Nat := qh + qs * (signC p + 1) + verC p
/-- Steps of H1'. -/
def stepB (p : Params) (qh qs : Nat) : Nat := kgC p + (1 + (playK p qh qs + extC p))

theorem cost_playS (v : Variant) (limits : Limits) (pk : Bytes) (sk : SB) :
    ∀ (B : RAdv) (qh qs : Nat) (signed : List Bytes), Budget B qh qs →
      Cost (playS v limits pk sk B signed) (playK (params v) qh qs) (qh + verC (params v)) qs
  | .hq r k, qh, qs, signed, hB => by
    obtain ⟨hpos, hk⟩ := hB
    simp only [playS, playK]
    exact (Cost.askA r (fun b => cost_playS v limits pk sk (k b) (qh - 1) qs signed (hk b))).mono
      (by simp only [playK]; omega) (by omega) (Nat.le_refl _)
  | .sq m k, qh, qs, signed, hB => by
    obtain ⟨hpos, hk⟩ := hB
    obtain ⟨qs', rfl⟩ : ∃ q', qs = q' + 1 := ⟨qs - 1, by omega⟩
    simp only [Nat.add_sub_cancel] at hk
    have e : (qs' + 1) * (signC (params v) + 1) = qs' * (signC (params v) + 1) + (signC (params v) + 1) :=
      Nat.succ_mul _ _
    simp only [playS]
    refine Cost.ite (fun _ => ?_) (fun _ => (cost_playS v limits pk sk (k none) qh qs' signed (hk none)).mono
      (by simp only [playK]; omega) (Nat.le_refl _) (by omega))
    refine (Cost.bind (K2 := playK (params v) qh qs' + 1) (A2 := qh + verC (params v)) (C2 := qs')
      (cost_sign v sk m) (fun s => ?_)).mono (by simp only [playK]; omega) (by omega) (by omega)
    cases s with
    | none =>
      exact (cost_playS v limits pk sk (k none) qh qs' _ (hk none)).mono
        (by omega) (Nat.le_refl _) (Nat.le_refl _)
    | some sg =>
      exact Cost.reveal _ (fun sb => cost_playS v limits pk sk (k (some sb)) qh qs' _ (hk _))
  | .out m s, qh, qs, signed, _ => by
    simp only [playS, playK]
    exact (Cost.bind (cost_verify v pk m s) (fun ok => Cost.done _)).mono (by omega) (by omega) (Nat.zero_le _)

theorem cost_gameS (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : SB) (qh qs : Nat)
    (hB : ∀ pk, Budget (A pk) qh qs) :
    Cost (gameS v limits A ex) (kgC (params v) + (1 + playK (params v) qh qs)) (qh + verC (params v)) qs := by
  unfold gameS
  exact (Cost.bind (cost_kgTail v ex) (fun ks => Cost.reveal _ (fun pk =>
    cost_playS v limits pk ks.2 (A pk) qh qs [] (hB pk)))).mono (by omega) (by omega) (by omega)

theorem cost_gameS' (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : SB) (qh qs : Nat)
    (hB : ∀ pk, Budget (A pk) qh qs) :
    Cost (gameS' v limits A ex) (stepB (params v) qh qs) (qh + verC (params v) + 1) qs := by
  unfold gameS' stepB
  exact (Cost.bind (cost_kgTail v ex) (fun ks => Cost.reveal _ (fun pk =>
    Cost.bind (cost_playS v limits pk ks.2 (A pk) qh qs [] (hB pk)) (fun out =>
      Cost.bind (cost_extW v ks.2 out.msg out.sig) (fun _ => Cost.done out))))).mono
    (by omega) (by omega) (by omega)

/-! From costs to the counting hypotheses. -/

theorem addC_len (st : St) (i : Nat) (r : SReq) : (addC st i r).ents.length ≤ st.ents.length + 1 := by
  unfold addC; split <;> simp

theorem addA_len (st : St) (i : Nat) (q : Request) : (addA st i q).ents.length ≤ st.ents.length + 1 := by
  unfold addA; split <;> simp

/-- Every step adds at most one entry. -/
theorem strace_ents {α : Type} (t : List Nat) : ∀ (P : Prog α) (st : St) (s : Nat) (stp : St × Ev),
    (strace t P st)[s]? = some stp → stp.1.ents.length ≤ st.ents.length + s
  | .done _, _, _, _, hs => by simp [strace] at hs
  | .askC _ _, st, 0, stp, hs => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs; subst hs; simp
  | .askA _ _, st, 0, stp, hs => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs; subst hs; simp
  | .reveal _ _, st, 0, stp, hs => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs; subst hs; simp
  | .askC r k, st, s+1, stp, hs => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have h1 := strace_ents t _ _ s stp hs
    have h2 := addC_len st (firstIdx (mC false t st.rev r) st.ents) r
    omega
  | .askA q k, st, s+1, stp, hs => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have h1 := strace_ents t _ _ s stp hs
    have h2 := addA_len st (firstIdx (mA false t st.rev q) st.ents) q
    omega
  | .reveal x k, st, s+1, stp, hs => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have h1 := strace_ents t _ _ s stp hs
    simp only at h1
    omega

theorem filter_len_mono {β : Type} (p q : β → Bool) (h : ∀ x, p x = true → q x = true) :
    ∀ l : List β, (l.filter p).length ≤ (l.filter q).length
  | [] => Nat.le_refl _
  | x :: l => by
    have := filter_len_mono p q h l
    simp only [List.filter_cons]
    by_cases hp : p x = true
    · simp [hp, h x hp]; omega
    · by_cases hq : q x = true <;> simp [hp, hq] <;> omega

theorem resD_len (t : List Nat) (st : St) : (resD t st).length = st.ents.length := by simp [resD]

theorem resD_isC (t : List Nat) (st : St) : ((resD t st).filter isC).length = cntH st.ents := by
  simp only [resD, cntH, List.filter_map, List.length_map]
  congr 2

theorem resD_isA (t : List Nat) (st : St) : ((resD t st).filter isA).length ≤ cntT st.ents := by
  simp only [resD, cntT, List.filter_map, List.length_map]
  exact filter_len_mono _ _ (fun e he => by simp [isA] at he; exact he.1) _

theorem coinSt_cnt (n : Nat) : (coinSt n).ents.length = 3 ∧ cntT (coinSt n).ents = 0 ∧
    cntH (coinSt n).ents = 0 := by
  simp [coinSt, coin, cntT, cntH]

theorem runG_draws (v : Variant) (limits : Limits) (A : Bytes → RAdv) (t : List Nat) : (runG v limits A t).2 =
    resD t (xrun true t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 :=
  (sim_game (t := t) v limits A (coinSt (params v).n)).2

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv) (qh qs : Nat) (hB : ∀ pk, Budget (A pk) qh qs)
include hB

theorem budget_N (N : Nat) (hN : stepB (params v) qh qs + 3 ≤ N) (t : List Nat) :
    (runG v limits A t).2.length ≤ N := by
  rw [runG_draws v limits A, resD_len]
  have := ((cost_gameS v limits A (coinEx (params v).n) qh qs hB) t (coinSt (params v).n)).2.2 true
  have h3 := (coinSt_cnt (params v).n).1
  simp only [stepB] at hN
  omega

theorem budget_C (q : Nat) (hq : qs ≤ q) (t : List Nat) :
    ((runG v limits A t).2.filter isC).length ≤ q := by
  rw [runG_draws v limits A, resD_isC]
  have := ((cost_gameS v limits A (coinEx (params v).n) qh qs hB) t (coinSt (params v).n)).2.2 true
  have h3 := (coinSt_cnt (params v).n).2.2
  omega

theorem budget_J (JA : Nat) (hJ : qh + verC (params v) ≤ JA) (t : List Nat) :
    ((runG v limits A t).2.filter isA).length ≤ JA := by
  rw [runG_draws v limits A]
  have h1 := resD_isA t (xrun true t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).2
  have := ((cost_gameS v limits A (coinEx (params v).n) qh qs hB) t (coinSt (params v).n)).2.2 true
  have h3 := (coinSt_cnt (params v).n).2.1
  omega

theorem budget_S (S : Nat) (hS : stepB (params v) qh qs + 3 ≤ S) :
    ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S := by
  intro t s stp hs
  have hl := ((cost_gameS' v limits A (coinEx (params v).n) qh qs hB) t (coinSt (params v).n)).1
  obtain ⟨hlt, -⟩ := List.getElem?_eq_some_iff.mp hs
  have he := strace_ents t _ _ s stp hs
  have h3 := (coinSt_cnt (params v).n).1
  omega

theorem budget_A (AA : Nat) (hA : qh + verC (params v) + 1 ≤ AA) (t : List Nat) :
    ((strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).filter isAev).length ≤ AA := by
  have := ((cost_gameS' v limits A (coinEx (params v).n) qh qs hB) t (coinSt (params v).n)).2.1
  omega

end

/-! The explicit bound for SPHINCS+-128f. -/

theorem verC_128f : verC (params .spx128f) = 11872 := by decide
theorem signC_128f : signC (params .spx128f) + 1 = 370402 := by decide
theorem kgC_128f : kgC (params .spx128f) = 4497 := by decide
theorem extC_128f : extC (params .spx128f) = 117606 := by decide

theorem stepB_128f (qh qs : Nat) : stepB (params .spx128f) qh qs = qh + 370402 * qs + 133976 := by
  simp only [stepB, playK, verC_128f, signC_128f, kgC_128f, extC_128f]
  omega

/-- The forgery bound for SPHINCS+-128f from the adversary's query budget
    alone: `qh` hash queries and `qs` signing queries on every path. With
    `R = c * 256^m` and tape length `N = qh + 370402 qs + 133980`, dividing by
    `R^N * 2^384` reads
      Pr[won] ≤ (JA + 11 AA + 6) / 2^128 + (2 S^2 + 3 N^2) / 2^256
    with `JA = qh + 11872`, `AA = qh + 11873`, `S = qh + 370402 qs + 133979`. -/
theorem rom_win_budget_128f (limits : Limits) (A : Bytes → RAdv) (c qh qs : Nat) (hc : 0 < c)
    (hqs : qs ≤ 2^64) (hB : ∀ pk, Budget (A pk) qh qs) :
    tsum (c * 256^(params .spx128f).m) (qh + 370402 * qs + 133980) (fun t => ind ((runG .spx128f limits A t).1.win = true)) *
        (256^16 * (256^16 * 256^16)) ≤
      (qh + 11872) * (c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * (256^16 * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * (5 * (qh + 11873)) * (256^16 * 256^16)) +
      2 * ((c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * ((qh + 370402 * qs + 133979) * (qh + 370402 * qs + 133979)) * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * 3 * (256^16 * 256^16) +
        (c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * ((qh + 370402 * qs + 133980) * (qh + 370402 * qs + 133980)) * 256^16) +
      (c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * (qh + 11873) * (256^16 * 256^16) +
      (c * 256^(params .spx128f).m)^(qh + 370402 * qs + 133980) * ((qh + 370402 * qs + 133980) * (qh + 370402 * qs + 133980)) * 256^16 := by
  have e := stepB_128f qh qs
  have hv := verC_128f
  exact rom_win_full_128f limits A c (qh + 370402 * qs + 133980) qs (qh + 11872) (qh + 370402 * qs + 133979)
    (qh + 11873) hc hqs
    (fun t _ => budget_N .spx128f limits A qh qs hB _ (by omega) t)
    (fun t _ => budget_C .spx128f limits A qh qs hB _ (Nat.le_refl _) t)
    (fun t _ => budget_J .spx128f limits A qh qs hB _ (by omega) t)
    (budget_S .spx128f limits A qh qs hB _ (by omega))
    (budget_A .spx128f limits A qh qs hB _ (by omega))
    (by omega) (by omega)

end DSM.Rom
