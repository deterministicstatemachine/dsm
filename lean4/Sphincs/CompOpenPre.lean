-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompCount

/- Modular proof, milestone 3, obligation 7: Theorem 2 of the EasyCrypt
   development (`OpenPRE_From_TCR_DSPR_THF.eca`, `OpenPRE_From_DSPR_TCR`) on
   DSM's finite framework:

     Pr[SM-DT-OpenPRE(A)] + Pr[SM-DT-SPprob(B_dspr)]
       ≤ Pr[SM-DT-DSPR(B_dspr)] + 3 · Pr[SM-DT-TCR(B_tcr)],

   i.e. Adv^OpenPRE ≤ max(0, Pr[DSPR] − Pr[SPprob]) + 3 · Adv^TCR, for every
   adversary A, with the reductions B_tcr and B_dspr built explicitly
   (`tcrRed`, `dsprRed`, EasyCrypt's `R_TCR_OpenPRE` and `R_DSPR_OpenPRE`).
   It is stated generically, for the collection variants too (the plain games
   are the case `Xc = Empty`), and instantiated for DSM's F
   (`dsm_openpre_bound`).

   The proof is exact counting over the same tickets, (pp, inputs, A's coins):
   a pointwise inequality (`pointwise`), and the swap argument (`swap_bound`):
   when A succeeds with x' = x_i at an unopened target with a second preimage,
   replacing x_i by another preimage leaves A's whole run unchanged and turns
   the ticket into a TCR win; at most one ticket of each such class has
   x' = x_i, so these tickets are no more than the TCR wins.

   Resources of both reductions (map §7, decision): one run of each phase of
   A; A's collection queries forwarded unchanged; at most t target queries;
   no hash evaluation of their own (their definitions take no hash function);
   t fresh inputs sampled; the state is A's state plus at most t inputs and t
   images. Loss: 1 (DSPR) and 3 (TCR). `tcrRed_within` proves the query
   bound.

   Hypotheses: the input distribution lists every input exactly once
   (EasyCrypt's `din` uniform and full), and `sp` decides `spexists`. No
   axiom, no `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

section Generic
variable {PP Tw X Xc Y σ : Type}


/-! ## Lifting pointwise inequalities through sums -/

theorem sum_le5 {α : Type} (S : FiniteExperiment α) (s p d tt e : α → Nat)
    (h : ∀ x, s x + p x ≤ d x + tt x + 2 * e x) :
    S.sum s + S.sum p ≤ S.sum d + S.sum tt + 2 * S.sum e := by
  rw [sum_fun_add, sum_fun_add, sum_mul_left, sum_fun_add]
  exact sum_le S (fun i => h _)

theorem lift2 {α β : Type} (P : FiniteExperiment α) (A : FiniteExperiment β) (F G H K : α → β → Nat)
    (h : ∀ x y, F x y + G x y ≤ H x y + 3 * K x y) :
    P.sum (fun x => A.sum (F x)) + P.sum (fun x => A.sum (G x)) ≤
      P.sum (fun x => A.sum (H x)) + 3 * P.sum (fun x => A.sum (K x)) := by
  have inner : ∀ x, A.sum (F x) + A.sum (G x) ≤ A.sum (H x) + 3 * A.sum (K x) := by
    intro x
    rw [sum_fun_add, sum_mul_left, sum_fun_add]
    exact sum_le A (fun i => h _ _)
  rw [sum_fun_add, sum_mul_left, sum_fun_add]
  exact sum_le P (fun i => inner _)

/-! ## The reductions -/

/-- Forward the adversary's collection queries. -/
def fwdCol {α : Type} : OT (Tw × Xc) Y α → OT ((Tw × X) ⊕ (Tw × Xc)) Y α
  | .done a => .done a
  | .ask q k => .ask (.inr q) (fun y => fwdCol (k y))

/-- Submit `(tw_i, x_i)` as targets, in order, collecting the images. -/
def submit : List (Tw × X) → List Y → OT ((Tw × X) ⊕ (Tw × Xc)) Y (List Y)
  | [], ys => .done ys
  | q :: qs, ys => .ask (.inl q) (fun y => submit qs (ys ++ [y]))

/-- Both reductions' first phase: run A's first phase, then submit its first
    `t` tweaks with the reduction's own inputs `xs` as targets. -/
def redPick (t : Nat) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) :
    OT ((Tw × X) ⊕ (Tw × Xc)) Y (σ × List X × List Y) :=
  (fwdCol a.pick).bind (fun r =>
    (submit (r.2.take t |>.zip (xs.take (r.2.take t).length)) []).bind (fun ys =>
      .done (r.1, xs.take (r.2.take t).length, ys)))

/-- A's second phase, its openings answered from the reduction's inputs. -/
def openRun (x0 : X) (a : OpenPreAdv PP Tw X Xc Y σ) (s : σ × List X × List Y) (pp : PP) :
    (Nat × X) × List Nat :=
  (a.find s.1 pp s.2.2).run (fun (opened : List Nat) i => (s.2.1.getD i x0, opened ++ [i])) []

/-- `R_TCR_OpenPRE`: A's answer is the second input. -/
def tcrRed (t : Nat) (x0 : X) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) :
    TcrAdv PP Tw X Xc Y (σ × List X × List Y) :=
  ⟨redPick t a xs, fun s pp => (openRun x0 a s pp).1⟩

/-- `R_DSPR_OpenPRE`: guess "a second preimage exists" iff A's answer differs
    from the target's input or the target was opened. -/
def dsprRed [DecidableEq X] (t : Nat) (x0 : X) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) :
    DsprAdv PP Tw X Xc Y (σ × List X × List Y) :=
  ⟨redPick t a xs, fun s pp =>
    let fr := openRun x0 a s pp
    (fr.1.1, decide (s.2.1.getD fr.1.1 x0 ≠ fr.1.2) || fr.2.contains fr.1.1)⟩

/-- The reductions' coins: A's coins and `t` fresh inputs. -/
def tcrRedCoins (t : Nat) (x0 : X) (A : FiniteExperiment (OpenPreAdv PP Tw X Xc Y σ))
    (Din : FiniteExperiment X) : FiniteExperiment (TcrAdv PP Tw X Xc Y (σ × List X × List Y)) :=
  (independentProduct A (Din.tape t)).map (fun p => tcrRed t x0 p.1 p.2)

def dsprRedCoins [DecidableEq X] (t : Nat) (x0 : X) (A : FiniteExperiment (OpenPreAdv PP Tw X Xc Y σ))
    (Din : FiniteExperiment X) : FiniteExperiment (DsprAdv PP Tw X Xc Y (σ × List X × List Y)) :=
  (independentProduct A (Din.tape t)).map (fun p => dsprRed t x0 p.1 p.2)

/-! ## Resources -/

theorem fwdCol_within {α : Type} : ∀ (T : OT (Tw × Xc) Y α) (m : Nat), T.Within m →
    (fwdCol (X := X) T).Within m
  | .done _, _, _ => trivial
  | .ask _ _, 0, h => absurd h (by simp [OT.Within])
  | .ask _ k, m+1, h => fun y => fwdCol_within (k y) m (h y)

theorem submit_within : ∀ (qs : List (Tw × X)) (ys : List Y),
    (submit (Xc := Xc) qs ys).Within qs.length
  | [], _ => trivial
  | _ :: qs, ys => fun y => submit_within qs (ys ++ [y])

/-- The reductions ask A's collection queries and at most `t` target
    queries. -/
theorem tcrRed_within (t : Nat) (x0 : X) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) (m : Nat)
    (h : a.pick.Within m) : (tcrRed t x0 a xs).pick.Within (m + t) := by
  apply OT.within_bind _ m t _ _ (fwdCol_within _ m h)
  intro r
  refine OT.within_mono _ (_ + 0) t ?_ (OT.within_bind _ _ 0 ?_ _ (submit_within _ []))
  · simp only [List.length_zip, List.length_take]; omega
  · intro _; trivial

/-! ## Simulation: what the reductions' first phase produces -/

theorem run_fwdCol {α : Type} (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (pp : PP) :
    ∀ (T : OT (Tw × Xc) Y α) (tg : List (Tw × X)) (cl : List Tw),
      (fwdCol T).run (tcrOracle f fc pp) ⟨tg, cl⟩ =
        ((T.run (fun (cols : List Tw) q => (fc pp q.1 q.2, cols ++ [q.1])) cl).1,
         ⟨tg, (T.run (fun (cols : List Tw) q => (fc pp q.1 q.2, cols ++ [q.1])) cl).2⟩)
  | .done _, _, _ => rfl
  | .ask q k, tg, cl => by
    simp only [fwdCol, OT.run, tcrOracle, colAnswer]
    exact run_fwdCol f fc pp (k (fc pp q.1 q.2)) tg (cl ++ [q.1])

theorem run_submit (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (pp : PP) :
    ∀ (qs : List (Tw × X)) (ys : List Y) (tg : List (Tw × X)) (cl : List Tw),
      (submit qs ys).run (tcrOracle f fc pp) ⟨tg, cl⟩ =
        (ys ++ qs.map (fun q => f pp q.1 q.2), ⟨tg ++ qs, cl⟩)
  | [], _, _, _ => by simp [submit, OT.run]
  | q :: qs, ys, tg, cl => by
    simp only [submit, OT.run, tcrOracle]
    rw [run_submit f fc pp qs (ys ++ [f pp q.1 q.2]) (tg ++ [q]) cl]
    simp

/-! ## The ticket and its events -/

variable [DecidableEq Tw] [DecidableEq X] [DecidableEq Y]
variable (f : PP → Tw → X → Y) (fc : PP → Tw → Xc → Y) (x0 : X) (t : Nat)

/-- A's first phase on public parameter `pp`. -/
def opPick (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) : (σ × List Tw) × List Tw :=
  a.pick.run (fun (cols : List Tw) q => (fc pp q.1 q.2, cols ++ [q.1])) []

/-- A's second phase on targets with inputs `xsT`. -/
def opFind (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ) (tws : List Tw) (xsT : List X) :
    (Nat × X) × List Nat :=
  (a.find st pp ((tws.zip xsT).map (fun q => f pp q.1 q.2))).run
    (fun (opened : List Nat) i => (xsT.getD i x0, opened ++ [i])) []

/-- An event at target `i`, if there is one. -/
def evAt (tws : List Tw) (i : Nat) (k : Tw → Bool) : Bool :=
  match tws[i]? with
  | some tw => k tw
  | none => false

section Events
variable (pp : PP) (tws cols : List Tw) (xsT : List X) (fr : (Nat × X) × List Nat)

/-- OpenPRE: an unopened target inverted. -/
def eS : Bool := evAt tws fr.1.1 (fun tw =>
  !fr.2.contains fr.1.1 && tweaksOk tws cols && f pp tw fr.1.2 == f pp tw (xsT.getD fr.1.1 x0))
/-- TCR: a different input with the same image. -/
def eT : Bool := evAt tws fr.1.1 (fun tw =>
  tweaksOk tws cols && xsT.getD fr.1.1 x0 != fr.1.2 && f pp tw (xsT.getD fr.1.1 x0) == f pp tw fr.1.2)
/-- DSPR, with the guess of `dsprRed`. -/
def eD (sp : PP → Tw → X → Bool) : Bool := evAt tws fr.1.1 (fun tw =>
  tweaksOk tws cols && sp pp tw (xsT.getD fr.1.1 x0) ==
    (decide (xsT.getD fr.1.1 x0 ≠ fr.1.2) || fr.2.contains fr.1.1))
/-- SPprob. -/
def eP (sp : PP → Tw → X → Bool) : Bool := evAt tws fr.1.1 (fun tw =>
  tweaksOk tws cols && sp pp tw (xsT.getD fr.1.1 x0))
/-- The swap event: a second preimage exists, A answered with the target's own
    input, and the target is unopened. -/
def eE (sp : PP → Tw → X → Bool) : Bool := evAt tws fr.1.1 (fun tw =>
  tweaksOk tws cols && sp pp tw (xsT.getD fr.1.1 x0) && xsT.getD fr.1.1 x0 == fr.1.2 &&
    !fr.2.contains fr.1.1)

theorem pointwise (sp : PP → Tw → X → Bool) :
    (if eS f x0 pp tws cols xsT fr then 1 else 0) + (if eP x0 pp tws cols xsT fr sp then 1 else 0) ≤
      (if eD x0 pp tws cols xsT fr sp then 1 else 0) + (if eT f x0 pp tws cols xsT fr then 1 else 0) +
        2 * (if eE x0 pp tws cols xsT fr sp then 1 else 0) := by
  unfold eS eT eD eP eE evAt
  cases tws[fr.1.1]? with
  | none => simp
  | some tw =>
    simp only
    by_cases h1 : tweaksOk tws cols = true <;> by_cases h2 : sp pp tw (xsT.getD fr.1.1 x0) = true <;>
      by_cases h3 : fr.2.contains fr.1.1 = true <;>
      by_cases hx : xsT.getD fr.1.1 x0 = fr.1.2 <;>
      by_cases hy : f pp tw fr.1.2 = f pp tw (xsT.getD fr.1.1 x0) <;>
      simp_all
end Events

/-! ## Facts about the ticket -/

theorem zip_map_get {α β γ : Type} (g : α × β → γ) (b0 : β) : ∀ (as : List α) (bs : List β),
    bs.length = as.length → ∀ i, ((as.zip bs).map g)[i]? = (as[i]?).map (fun a => g (a, bs.getD i b0))
  | [], [], _, _ => by simp
  | _ :: _, _ :: _, _, 0 => by simp
  | _ :: as, _ :: bs, h, i+1 => by
    simp only [List.zip_cons_cons, List.map_cons, List.getElem?_cons_succ, List.getD_cons_succ]
    exact zip_map_get g b0 as bs (by simpa using h) i
  | [], _ :: _, h, _ => by simp at h
  | _ :: _, [], h, _ => by simp at h

omit [DecidableEq Tw] in
theorem evAt_lt {tws : List Tw} {i : Nat} {k : Tw → Bool} (h : evAt tws i k = true) : i < tws.length := by
  unfold evAt at h
  cases e : tws[i]? with
  | none => rw [e] at h; exact absurd h (by simp)
  | some _ => exact (List.getElem?_eq_some_iff.mp e).1

theorem ind_congr {b c : Bool} (h : b = c) : (if b then 1 else 0) = (if c then 1 else 0) := by rw [h]

/-! ## The swap argument -/

section Swap
variable {f} {x0}

omit [DecidableEq X] in
/-- Inputs `xs` with position `j` replaced by `x`, truncated to the targets. -/
theorem set_take_getD (xs : List X) (n j : Nat) (x : X) (hj : j < n) (hn : n ≤ xs.length) :
    ((xs.set j x).take n).getD j x0 = x := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos hj, List.getElem?_set_self (by omega)]
  rfl

omit [DecidableEq X] in
theorem set_take_getD_ne (xs : List X) (n j q : Nat) (x y : X) (hq : q ≠ j) :
    ((xs.set j x).take n).getD q x0 = ((xs.set j y).take n).getD q x0 := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_take, List.getElem?_take]
  split
  · rw [List.getElem?_set_ne (Ne.symm hq), List.getElem?_set_ne (Ne.symm hq)]
  · rfl

omit [DecidableEq Tw] [DecidableEq X] [DecidableEq Y] in
/-- If target `j` is never opened, changing its input to another preimage of
    the same image changes nothing in A's second phase. -/
theorem opFind_swap (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ) (tws : List Tw) (xs : List X)
    (j : Nat) (hj : j < tws.length) (hn : tws.length ≤ xs.length) (x y : X)
    (himg : f pp tws[j] x = f pp tws[j] y)
    (hop : j ∉ (opFind f x0 pp a st tws ((xs.set j x).take tws.length)).2) :
    opFind f x0 pp a st tws ((xs.set j y).take tws.length) =
      opFind f x0 pp a st tws ((xs.set j x).take tws.length) := by
  have hlx : ((xs.set j x).take tws.length).length = tws.length := by simp; omega
  have hly : ((xs.set j y).take tws.length).length = tws.length := by simp; omega
  have hys : (tws.zip ((xs.set j y).take tws.length)).map (fun q => f pp q.1 q.2) =
      (tws.zip ((xs.set j x).take tws.length)).map (fun q => f pp q.1 q.2) := by
    apply List.ext_getElem?; intro k
    rw [zip_map_get _ x0 _ _ hly, zip_map_get _ x0 _ _ hlx]
    by_cases hk : k = j
    · subst hk
      rw [List.getElem?_eq_getElem hj]
      simp only [Option.map_some]
      rw [set_take_getD xs _ k y hj hn, set_take_getD xs _ k x hj hn, himg]
    · rw [set_take_getD_ne xs _ j k y x hk]
  unfold opFind at hop ⊢
  rw [hys]
  exact OT.run_agree_off _ _ j (fun q hq => set_take_getD_ne xs _ j q x y hq) _ [] hop

variable (f) (x0)

/-- The swap events at target `j`, inputs `xs` with position `j` set to `x`. -/
def sliceE (sp : PP → Tw → X → Bool) (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ)
    (tws cols : List Tw) (xs : List X) (j : Nat) (x : X) : Bool :=
  let L := (xs.set j x).take tws.length
  let F := opFind f x0 pp a st tws L
  eE x0 pp tws cols L F sp && F.1.1 == j

def sliceT (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ) (tws cols : List Tw) (xs : List X)
    (j : Nat) (x : X) : Bool :=
  let L := (xs.set j x).take tws.length
  let F := opFind f x0 pp a st tws L
  eT f x0 pp tws cols L F && F.1.1 == j

theorem slice_bound (Din : FiniteExperiment X) (hD : Bijective Din) (sp : PP → Tw → X → Bool)
    (hsp : SpDecides f sp) (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ) (tws cols : List Tw)
    (xs : List X) (j : Nat) (hj : j < tws.length) (hn : tws.length ≤ xs.length) :
    Din.sum (fun x => if sliceE f x0 sp pp a st tws cols xs j x then 1 else 0) ≤
      Din.sum (fun x => if sliceT f x0 pp a st tws cols xs j x then 1 else 0) := by
  classical
  let tw := tws[j]
  have htw : tws[j]? = some tw := List.getElem?_eq_getElem hj
  let φ : X → X := fun x => if h : ∃ y, y ≠ x ∧ f pp tw y = f pp tw x then Classical.choose h else x
  -- unpacking a swap event
  have unE : ∀ x, sliceE f x0 sp pp a st tws cols xs j x = true →
      let F := opFind f x0 pp a st tws ((xs.set j x).take tws.length)
      F.1.1 = j ∧ tweaksOk tws cols = true ∧ sp pp tw x = true ∧ x = F.1.2 ∧ j ∉ F.2 := by
    intro x h
    simp only [sliceE, eE, Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨h1, h2⟩ := h
    rw [h2] at h1
    unfold evAt at h1
    rw [htw, set_take_getD xs _ j x hj hn] at h1
    simp only [Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at h1
    obtain ⟨⟨⟨hok, hsp'⟩, hx⟩, hop⟩ := h1
    refine ⟨h2, hok, hsp', hx, ?_⟩
    intro hm
    have : (opFind f x0 pp a st tws ((xs.set j x).take tws.length)).2.contains j = true :=
      List.contains_iff_mem.mpr hm
    rw [hop] at this; exact absurd this (by simp)
  have partner : ∀ x, sp pp tw x = true → φ x ≠ x ∧ f pp tw (φ x) = f pp tw x := by
    intro x hs
    have hex := (hsp pp tw x).mp hs
    simp only [φ, dif_pos hex]
    exact Classical.choose_spec hex
  apply sum_le_of_inj Din hD _ _ φ
  · intro x hx
    obtain ⟨hi, hok, hs, hxe, hop⟩ := unE x hx
    obtain ⟨hne, himg⟩ := partner x hs
    have hsame := opFind_swap pp a st tws xs j hj hn x (φ x) himg.symm hop
    simp only [sliceT, Bool.and_eq_true, beq_iff_eq]
    rw [hsame]
    refine ⟨?_, hi⟩
    unfold eT evAt
    rw [hi, htw, set_take_getD xs _ j (φ x) hj hn]
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq]
    refine ⟨⟨hok, ?_⟩, ?_⟩
    · rw [← hxe]; exact hne
    · rw [← hxe]; exact himg
  · intro x y hx hy he
    obtain ⟨_, _, hsx, hxe, hopx⟩ := unE x hx
    obtain ⟨_, _, hsy, hye, _⟩ := unE y hy
    have imgs : f pp tw x = f pp tw y := by
      rw [← (partner x hsx).2, ← (partner y hsy).2, he]
    have hsame := opFind_swap pp a st tws xs j hj hn x y imgs hopx
    rw [hxe, hye, hsame]
end Swap


/-- The swap tickets are no more than the TCR wins, for every first phase. -/
theorem swap_bound (Din : FiniteExperiment X) (hD : Bijective Din) (sp : PP → Tw → X → Bool)
    (hsp : SpDecides f sp) (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (st : σ) (tws cols : List Tw)
    (hn : tws.length ≤ t) :
    (Din.tape t).sum (fun xs => if eE x0 pp tws cols (xs.take tws.length)
        (opFind f x0 pp a st tws (xs.take tws.length)) sp then 1 else 0) ≤
      (Din.tape t).sum (fun xs => if eT f x0 pp tws cols (xs.take tws.length)
        (opFind f x0 pp a st tws (xs.take tws.length)) then 1 else 0) := by
  have e1 := sum_by_index (Din.tape t) t
    (fun xs => eE x0 pp tws cols (xs.take tws.length) (opFind f x0 pp a st tws (xs.take tws.length)) sp)
    (fun xs => (opFind f x0 pp a st tws (xs.take tws.length)).1.1)
    (fun xs h => Nat.lt_of_lt_of_le (evAt_lt h) hn)
  have e2 := sum_by_index (Din.tape t) t
    (fun xs => eT f x0 pp tws cols (xs.take tws.length) (opFind f x0 pp a st tws (xs.take tws.length)))
    (fun xs => (opFind f x0 pp a st tws (xs.take tws.length)).1.1)
    (fun xs h => Nat.lt_of_lt_of_le (evAt_lt h) hn)
  dsimp only at e1 e2
  rw [e1, e2]
  apply rsum_le; intro j hj
  apply Nat.le_of_mul_le_mul_left _ Din.positive
  rw [tape_set_sum Din t j hj, tape_set_sum Din t j hj]
  apply sum_le; intro k
  have hlen := tape_length Din t k
  by_cases hjn : j < tws.length
  · exact slice_bound f x0 Din hD sp hsp pp a st tws cols _ j hjn (by omega)
  · apply sum_le; intro m
    by_cases hc : (eE x0 pp tws cols (((Din.tape t).sample k).set j (Din.sample m) |>.take tws.length)
        (opFind f x0 pp a st tws (((Din.tape t).sample k).set j (Din.sample m) |>.take tws.length)) sp &&
        (opFind f x0 pp a st tws (((Din.tape t).sample k).set j (Din.sample m) |>.take tws.length)).1.1
          == j) = true
    · simp only [Bool.and_eq_true, beq_iff_eq] at hc
      exact absurd (hc.2 ▸ evAt_lt hc.1) hjn
    · rw [if_neg hc]; exact Nat.zero_le _

/-! ## The games' counts as sums over (pp, A's coins, inputs) -/

section Counts
variable (P : FiniteExperiment PP) (Din : FiniteExperiment X) (A : FiniteExperiment (OpenPreAdv PP Tw X Xc Y σ))

/-- The ticket's events, from A's first phase and the inputs. -/
def tk (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) :
    List Tw × List Tw × List X × ((Nat × X) × List Nat) :=
  let r := opPick fc pp a
  let tws := r.1.2.take t
  (tws, r.2, xs.take tws.length, opFind f x0 pp a r.1.1 tws (xs.take tws.length))

omit [DecidableEq Tw] [DecidableEq X] [DecidableEq Y] in
theorem tk_len (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) (h : xs.length = t) :
    (tk f fc x0 t pp a xs).2.2.1.length = (tk f fc x0 t pp a xs).1.length := by
  simp only [tk, List.length_take]; omega

omit [DecidableEq X] in
theorem openPre_match (pp : PP) (tws cols : List Tw) (xsT : List X) (hl : xsT.length = tws.length)
    (fr : (Nat × X) × List Nat) :
    (match tws[fr.1.1]?, ((tws.zip xsT).map (fun q => f pp q.1 q.2))[fr.1.1]? with
     | some tw, some y => !fr.2.contains fr.1.1 && tweaksOk tws cols && f pp tw fr.1.2 == y
     | _, _ => false) = eS f x0 pp tws cols xsT fr := by
  rw [zip_map_get _ x0 _ _ hl]; unfold eS evAt; cases tws[fr.1.1]? <;> rfl

omit [DecidableEq X] in
theorem openPre_num :
    (openPreProb P Din x0 f fc t A).numerator = P.sum (fun pp => A.sum (fun a => (Din.tape t).sum (fun xs =>
      let k := tk f fc x0 t pp a xs
      if eS f x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 then 1 else 0))) := by
  unfold openPreProb
  rw [numerator_sum, product_sum, product_sum]
  apply sum_congr; intro i
  rw [sum_comm (Din.tape t) A]
  apply sum_congr; intro j
  apply sum_congr; intro k
  have hl := tk_len f fc x0 t (P.sample i) (A.sample j) _ (tape_length Din t k)
  apply ind_congr
  exact openPre_match f x0 _ _ _ _ hl _


theorem zip_get {α β : Type} (b0 : β) (as : List α) (bs : List β) (h : bs.length = as.length) (i : Nat) :
    (as.zip bs)[i]? = (as[i]?).map (fun a => (a, bs.getD i b0)) := by
  have := zip_map_get id b0 as bs h i
  rwa [List.map_id] at this

omit [DecidableEq Tw] [DecidableEq X] [DecidableEq Y] in
theorem redPick_run (pp : PP) (a : OpenPreAdv PP Tw X Xc Y σ) (xs : List X) :
    (redPick t a xs).run (tcrOracle f fc pp) ⟨[], []⟩ =
      (((opPick fc pp a).1.1, xs.take ((opPick fc pp a).1.2.take t).length,
        (((opPick fc pp a).1.2.take t).zip (xs.take ((opPick fc pp a).1.2.take t).length)).map
          (fun q => f pp q.1 q.2)),
       ⟨((opPick fc pp a).1.2.take t).zip (xs.take ((opPick fc pp a).1.2.take t).length),
        (opPick fc pp a).2⟩) := by
  unfold redPick
  rw [OT.run_bind, run_fwdCol, OT.run_bind, run_submit]
  simp [OT.run, opPick]

omit [DecidableEq Tw] [DecidableEq X] in
theorem tgt_facts (tws : List Tw) (xsT : List X) (hl : xsT.length = tws.length) (hn : tws.length ≤ t) :
    decide ((tws.zip xsT).length ≤ t) = true ∧ (tws.zip xsT).map Prod.fst = tws := by
  refine ⟨by simp [List.length_zip]; omega, List.map_fst_zip (by omega)⟩

theorem tcrWin_eq (pp : PP) (tws cols : List Tw) (xsT : List X) (hl : xsT.length = tws.length)
    (hn : tws.length ≤ t) (fr : (Nat × X) × List Nat) :
    tcrWin f pp t ⟨tws.zip xsT, cols⟩ fr.1.1 fr.1.2 = eT f x0 pp tws cols xsT fr := by
  obtain ⟨h1, h2⟩ := tgt_facts t tws xsT hl hn
  unfold tcrWin eT evAt
  simp only [h1, h2, zip_get x0 tws xsT hl, Bool.true_and]
  cases tws[fr.1.1]? <;> rfl

omit [DecidableEq X] in
theorem dsprRun_eq (tws cols : List Tw) (xsT : List X) (hl : xsT.length = tws.length)
    (hn : tws.length ≤ t) (i : Nat) (win : Tw → X → Bool) :
    (match (tws.zip xsT)[i]? with
     | none => false
     | some (tw, x) => decide ((tws.zip xsT).length ≤ t) && tweaksOk ((tws.zip xsT).map Prod.fst) cols &&
         win tw x) = evAt tws i (fun tw => tweaksOk tws cols && win tw (xsT.getD i x0)) := by
  obtain ⟨h1, h2⟩ := tgt_facts t tws xsT hl hn
  simp only [h1, h2, zip_get x0 tws xsT hl, Bool.true_and]
  unfold evAt
  cases tws[i]? <;> rfl

theorem tcr_num :
    (tcrProb P f fc t (tcrRedCoins t x0 A Din)).numerator = P.sum (fun pp => A.sum (fun a =>
      (Din.tape t).sum (fun xs =>
        let k := tk f fc x0 t pp a xs
        if eT f x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 then 1 else 0))) := by
  unfold tcrProb tcrRedCoins
  rw [numerator_sum, product_sum]
  apply sum_congr; intro i
  rw [sum_map_product]
  apply sum_congr; intro j
  apply sum_congr; intro k
  have hl := tk_len f fc x0 t (P.sample i) (A.sample j) _ (tape_length Din t k)
  apply ind_congr
  dsimp only [tcrRed]
  simp only [redPick_run]
  exact tcrWin_eq f x0 t _ _ _ _ hl (List.length_take_le _ _) _

omit [DecidableEq Y] in
theorem dspr_num (sp : PP → Tw → X → Bool) :
    (dsprProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator = P.sum (fun pp => A.sum (fun a =>
      (Din.tape t).sum (fun xs =>
        let k := tk f fc x0 t pp a xs
        if eD x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0))) := by
  unfold dsprProb dsprRun dsprRedCoins
  rw [numerator_sum, product_sum]
  apply sum_congr; intro i
  rw [sum_map_product]
  apply sum_congr; intro j
  apply sum_congr; intro k
  have hl := tk_len f fc x0 t (P.sample i) (A.sample j) _ (tape_length Din t k)
  apply ind_congr
  dsimp only [dsprRed]
  simp only [redPick_run]
  exact dsprRun_eq x0 t _ _ _ hl (List.length_take_le _ _) _ _

omit [DecidableEq Y] in
theorem sp_num (sp : PP → Tw → X → Bool) :
    (spProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator = P.sum (fun pp => A.sum (fun a =>
      (Din.tape t).sum (fun xs =>
        let k := tk f fc x0 t pp a xs
        if eP x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0))) := by
  unfold spProb dsprRun dsprRedCoins
  rw [numerator_sum, product_sum]
  apply sum_congr; intro i
  rw [sum_map_product]
  apply sum_congr; intro j
  apply sum_congr; intro k
  have hl := tk_len f fc x0 t (P.sample i) (A.sample j) _ (tape_length Din t k)
  apply ind_congr
  dsimp only [dsprRed]
  simp only [redPick_run]
  exact dsprRun_eq x0 t _ _ _ hl (List.length_take_le _ _) _ _


/-- Theorem 2 (EasyCrypt's `OpenPRE_From_DSPR_TCR`), as exact counts over the
    same tickets: `#OpenPRE + #SPprob ≤ #DSPR + 3 · #TCR`. -/
theorem openpre_from_dspr_tcr (hD : Bijective Din) (sp : PP → Tw → X → Bool) (hsp : SpDecides f sp) :
    (openPreProb P Din x0 f fc t A).numerator + (spProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator ≤
      (dsprProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator +
        3 * (tcrProb P f fc t (tcrRedCoins t x0 A Din)).numerator := by
  rw [openPre_num, sp_num, dspr_num, tcr_num]
  apply lift2
  intro pp a
  have hsw : (Din.tape t).sum (fun xs => let k := tk f fc x0 t pp a xs
        if eE x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0) ≤
      (Din.tape t).sum (fun xs => let k := tk f fc x0 t pp a xs
        if eT f x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 then 1 else 0) :=
    swap_bound f x0 t Din hD sp hsp pp a (opPick fc pp a).1.1 ((opPick fc pp a).1.2.take t)
      (opPick fc pp a).2 (List.length_take_le _ _)
  have hpt := sum_le5 (Din.tape t)
    (fun xs => let k := tk f fc x0 t pp a xs; if eS f x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 then 1 else 0)
    (fun xs => let k := tk f fc x0 t pp a xs; if eP x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0)
    (fun xs => let k := tk f fc x0 t pp a xs; if eD x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0)
    (fun xs => let k := tk f fc x0 t pp a xs; if eT f x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 then 1 else 0)
    (fun xs => let k := tk f fc x0 t pp a xs; if eE x0 pp k.1 k.2.1 k.2.2.1 k.2.2.2 sp then 1 else 0)
    (fun xs => pointwise f x0 pp _ _ _ _ sp)
  omega

/-- All four games count the same tickets. -/
theorem openpre_denominators (sp : PP → Tw → X → Bool) :
    (openPreProb P Din x0 f fc t A).denominator = (tcrProb P f fc t (tcrRedCoins t x0 A Din)).denominator ∧
    (dsprProb P f fc sp t (dsprRedCoins t x0 A Din)).denominator =
      (tcrProb P f fc t (tcrRedCoins t x0 A Din)).denominator ∧
    (spProb P f fc sp t (dsprRedCoins t x0 A Din)).denominator =
      (tcrProb P f fc t (tcrRedCoins t x0 A Din)).denominator := by
  refine ⟨?_, rfl, rfl⟩
  show P.cardinality * (Din.tape t).cardinality * A.cardinality =
    P.cardinality * (A.cardinality * (Din.tape t).cardinality)
  rw [Nat.mul_assoc, Nat.mul_comm (Din.tape t).cardinality]

/-- The published form, over the common ticket count:
    `#OpenPRE ≤ max(0, #DSPR − #SPprob) + 3 · #TCR`. -/
theorem openpre_bound (hD : Bijective Din) (sp : PP → Tw → X → Bool) (hsp : SpDecides f sp) :
    (openPreProb P Din x0 f fc t A).numerator ≤
      ((dsprProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator -
        (spProb P f fc sp t (dsprRedCoins t x0 A Din)).numerator) +
      3 * (tcrProb P f fc t (tcrRedCoins t x0 A Din)).numerator := by
  have := openpre_from_dspr_tcr f fc x0 t P Din A hD sp hsp
  omega

end Counts
end Generic



/-- Counts over a common ticket number, as fractions. -/
theorem frac_of_counts (op d sp tc : Probability) (h1 : op.denominator = tc.denominator)
    (h2 : d.denominator = tc.denominator) (h3 : sp.denominator = tc.denominator)
    (key : op.numerator ≤ (d.numerator - sp.numerator) + 3 * tc.numerator) :
    fle op.frac (fadd (d.numerator * sp.denominator - sp.numerator * d.denominator,
      d.denominator * sp.denominator) (3 * tc.numerator, tc.denominator)) := by
  unfold fle fadd Probability.frac
  simp only
  rw [h1, h2, h3, ← Nat.sub_mul]
  generalize tc.denominator = N at *
  calc op.numerator * (N * N * N)
      ≤ ((d.numerator - sp.numerator) + 3 * tc.numerator) * (N * N * N) := Nat.mul_le_mul_right _ key
    _ = ((d.numerator - sp.numerator) * N * N + 3 * tc.numerator * (N * N)) * N := by
      rw [Nat.add_mul, Nat.add_mul]; ac_rfl

/-! ## DSM's F (FORS leaves): Theorem 2 instantiated -/

section Dsm
variable (o : Oracle Id) (v : Variant)

/-- A default n-byte input (used only outside the targets' range). -/
def dsmX0 : Wire (params v).n := ⟨be (params v).n 0, be_width _ _⟩

/-- Theorem 2 for DSM's F = keyed BLAKE3 under derive_key("…/thash", PK.seed)
    on n-byte inputs, uniform inputs, against every OpenPRE adversary. -/
theorem dsm_openpre_bound {σ : Type} (t : Nat)
    (A : FiniteExperiment (OpenPreAdv Bytes Tweak (Wire (params v).n) Empty Bytes σ)) :
    (dsmOpenPre o v t A).numerator ≤
      ((dsprProb (ppSpace v) (thf o v (params v).n) noCol (thfSp o v (params v).n) t
          (dsprRedCoins t (dsmX0 v) A (uniformBytes (params v).n))).numerator -
        (spProb (ppSpace v) (thf o v (params v).n) noCol (thfSp o v (params v).n) t
          (dsprRedCoins t (dsmX0 v) A (uniformBytes (params v).n))).numerator) +
      3 * (dsmTcrF o v t (tcrRedCoins t (dsmX0 v) A (uniformBytes (params v).n))).numerator :=
  openpre_bound (thf o v (params v).n) noCol (dsmX0 v) t (ppSpace v) (uniformBytes (params v).n) A
    (uniformBytes_bijective _) (thfSp o v (params v).n) (thfSp_decides o v (params v).n)

/-- The same bound as fractions: Pr[OpenPRE] ≤ Adv^DSPR + 3 · Pr[TCR]. -/
theorem dsm_openpre_frac {σ : Type} (t : Nat)
    (A : FiniteExperiment (OpenPreAdv Bytes Tweak (Wire (params v).n) Empty Bytes σ)) :
    fle (dsmOpenPre o v t A).frac
      (fadd (dsmDsprAdv o v t (dsprRedCoins t (dsmX0 v) A (uniformBytes (params v).n)))
        (3 * (dsmTcrF o v t (tcrRedCoins t (dsmX0 v) A (uniformBytes (params v).n))).numerator,
          (dsmTcrF o v t (tcrRedCoins t (dsmX0 v) A (uniformBytes (params v).n))).denominator)) := by
  obtain ⟨h1, h2, h3⟩ := openpre_denominators (thf o v (params v).n) noCol (dsmX0 v) t (ppSpace v)
    (uniformBytes (params v).n) A (thfSp o v (params v).n)
  exact frac_of_counts _ _ _ _ h1 h2 h3 (dsm_openpre_bound o v t A)
end Dsm

#print axioms pointwise
#print axioms slice_bound
#print axioms tcrRed_within
#print axioms openpre_from_dspr_tcr
#print axioms openpre_bound
#print axioms dsm_openpre_bound
#print axioms dsm_openpre_frac
end DSM.Sphincs.Comp
