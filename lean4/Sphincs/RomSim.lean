-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomHidden

/- Simulation between symbolic programs and query trees. `Sim t P T Rel`:
   on tape `t`, from any oracle state, the real run of the symbolic program
   `P` and the lazy-oracle run of the query tree `T` (from the resolved
   entries) return related results and leave the same resolved oracle table.
   Combinators for pure, bind, the three kinds of step, `if` and `for`
   loops let a symbolic version of a model function be checked against the
   model function itself, run as a query tree (`RomOracle.run`). -/
namespace DSM.Rom
open DSM.Sphincs

theorem req_beq_unfold (m c k i o m' c' k' i') (o' : Nat) :
    (Request.mk m c k i o == Request.mk m' c' k' i' o') =
      (m == m' && (c == c' && (k == k' && (i == i' && o == o')))) := rfl

theorem req_beq_iff (a b : Request) : (a == b) = true ↔ a = b := by
  cases a; cases b
  rw [req_beq_unfold]
  simp only [Bool.and_eq_true, beq_iff_eq, Request.mk.injEq]

def Prog.bind {α β : Type} : Prog α → (α → Prog β) → Prog β
  | .done a, f => f a
  | .askC r k, f => .askC r (fun v => Prog.bind (k v) f)
  | .askA q k, f => .askA q (fun b => Prog.bind (k b) f)
  | .reveal x k, f => .reveal x (fun b => Prog.bind (k b) f)

instance : Monad Prog where
  pure := .done
  bind := Prog.bind

theorem xrun_bind {α β : Type} (real : Bool) (t : List Nat) : ∀ (P : Prog α) (f : α → Prog β) (st : St),
    xrun real t (P.bind f) st = xrun real t (f (xrun real t P st).1) (xrun real t P st).2
  | .done _, _, _ => rfl
  | .askC _ _, f, _ => by simp only [Prog.bind, xrun]; exact xrun_bind real t _ f _
  | .askA _ _, f, _ => by simp only [Prog.bind, xrun]; exact xrun_bind real t _ f _
  | .reveal _ _, f, _ => by simp only [Prog.bind, xrun]; exact xrun_bind real t _ f _

theorem run_bind {α β : Type} (t : List Nat) : ∀ (T : QT α) (f : α → QT β) (d : List Draw),
    run t (T.bind f) d = run t (f (run t T d).1) (run t T d).2
  | .done _, _, _ => rfl
  | .ask g r k, f, d => by
    simp only [QT.bind, run]
    cases findDraw d r with
    | some i => exact run_bind t _ f _
    | none => exact run_bind t _ f _

/-- The resolved oracle table of a state. -/
def resD (t : List Nat) (st : St) : List Draw := st.ents.map (fun e => (e.1, e.2.res t))

theorem firstIdx_le {β : Type} (p : β → Bool) : ∀ l : List β, firstIdx p l ≤ l.length
  | [] => Nat.le_refl 0
  | b :: l => by
    simp only [firstIdx, List.length_cons]
    split
    · omega
    · have := firstIdx_le p l; omega

theorem findDraw_map (t : List Nat) (q : Request) : ∀ (l : List (Bool × SReq)),
    findDraw (l.map (fun e => (e.1, e.2.res t))) q =
      if firstIdx (fun e => decide (e.2.res t = q)) l < l.length
      then some (firstIdx (fun e => decide (e.2.res t = q)) l) else none
  | [] => rfl
  | e :: l => by
    simp only [List.map_cons, findDraw, firstIdx, List.length_cons]
    by_cases h : e.2.res t = q
    · have hq : (q == q) = true := (req_beq_iff q q).mpr rfl
      simp [h, hq]
    · have hb : (e.2.res t == q) = false := by
        cases hh : (e.2.res t == q)
        · rfl
        · exact absurd ((req_beq_iff _ _).mp hh) h
      simp only [hb, h, decide_false, Bool.false_eq_true, if_false]
      rw [findDraw_map t q l]
      by_cases hl : firstIdx (fun e => decide (e.2.res t = q)) l < l.length
      · simp [hl]
      · simp [hl]

theorem mC_true (t rev : List Nat) (r : SReq) :
    mC true t rev r = fun e => decide (e.2.res t = r.res t) := by
  funext e; simp [mC]

theorem mA_true (t rev : List Nat) (q : Request) :
    mA true t rev q = fun e => decide (e.2.res t = q) := by
  funext e; simp [mA]

theorem lift_res (t : List Nat) (q : Request) : (lift q).res t = q := by
  cases q; simp [lift, SReq.res, sres, SV.res]

/-- Simulation judgment (see the header). -/
def Sim {α β : Type} (t : List Nat) (P : Prog α) (T : QT β) (Rel : α → β → Prop) : Prop :=
  ∀ st, Rel (xrun true t P st).1 (run t T (resD t st)).1 ∧
    (run t T (resD t st)).2 = resD t (xrun true t P st).2

namespace Sim
variable {t : List Nat}

theorem pure' {α β : Type} {Rel : α → β → Prop} {a : α} {b : β} (h : Rel a b) :
    Sim t (.done a) (.done b) Rel := fun _ => ⟨h, rfl⟩

theorem unit : Sim t (pure PUnit.unit : Prog PUnit) (pure PUnit.unit : QT PUnit) (fun _ _ => True) :=
  pure' trivial

theorem bind' {α β γ δ : Type} {P : Prog α} {T : QT β} {f : α → Prog γ} {g : β → QT δ}
    {R₁ : α → β → Prop} {R₂ : γ → δ → Prop} (hP : Sim t P T R₁)
    (hf : ∀ a b, R₁ a b → Sim t (f a) (g b) R₂) : Sim t (P.bind f) (T.bind g) R₂ := by
  intro st
  rw [xrun_bind, run_bind]
  obtain ⟨h₁, h₂⟩ := hP st
  rw [h₂]
  exact hf _ _ h₁ _

theorem bind {α β γ δ : Type} {P : Prog α} {T : QT β} {f : α → Prog γ} {g : β → QT δ}
    {R₁ : α → β → Prop} {R₂ : γ → δ → Prop} (hP : Sim t P T R₁)
    (hf : ∀ a b, R₁ a b → Sim t (f a) (g b) R₂) : Sim t (P >>= f) (T >>= g) R₂ :=
  bind' hP hf

theorem askC {α β : Type} {Rel : α → β → Prop} (r : SReq) (k : SV → Prog α) (k' : Bytes → QT β)
    (hk : ∀ i, Sim t (k (.hid i r.outLen)) (k' (be r.outLen (t.getD i 0))) Rel) :
    Sim t (.askC r k) (.ask false (r.res t) k') Rel := by
  intro st
  simp only [xrun, run, resD]
  rw [findDraw_map, mC_true]
  by_cases hl : firstIdx (fun e => decide (e.2.res t = r.res t)) st.ents < st.ents.length
  · rw [if_pos hl]
    have ha : addC st (firstIdx (fun e => decide (e.2.res t = r.res t)) st.ents) r = st := by
      simp [addC, hl]
    rw [ha]
    exact hk _ st
  · rw [if_neg hl]
    have he : firstIdx (fun e => decide (e.2.res t = r.res t)) st.ents = st.ents.length :=
      Nat.le_antisymm (firstIdx_le _ _) (Nat.le_of_not_lt hl)
    rw [he, List.length_map]
    have ha : addC st st.ents.length r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC]
    rw [ha]
    have := hk st.ents.length ⟨st.ents ++ [(false, r)], st.rev⟩
    simpa [resD] using this

theorem askA {α β : Type} {Rel : α → β → Prop} (q : Request) (k : Bytes → Prog α) (k' : Bytes → QT β)
    (hk : ∀ i, Sim t (k (be q.outLen (t.getD i 0))) (k' (be q.outLen (t.getD i 0))) Rel) :
    Sim t (.askA q k) (.ask true q k') Rel := by
  intro st
  simp only [xrun, run, resD]
  rw [findDraw_map, mA_true]
  by_cases hl : firstIdx (fun e => decide (e.2.res t = q)) st.ents < st.ents.length
  · rw [if_pos hl]
    have := hk (firstIdx (fun e => decide (e.2.res t = q)) st.ents)
      (addA st (firstIdx (fun e => decide (e.2.res t = q)) st.ents) q)
    simpa [resD, addA, hl] using this
  · rw [if_neg hl]
    have he : firstIdx (fun e => decide (e.2.res t = q)) st.ents = st.ents.length :=
      Nat.le_antisymm (firstIdx_le _ _) (Nat.le_of_not_lt hl)
    rw [he, List.length_map]
    have := hk st.ents.length (addA st st.ents.length q)
    simpa [resD, addA, lift_res] using this

theorem reveal {α β : Type} {Rel : α → β → Prop} (x : List SV) (k : Bytes → Prog α) (T : QT β)
    (hk : Sim t (k (sres t x)) T Rel) : Sim t (.reveal x k) T Rel := by
  intro st
  simp only [xrun]
  exact hk ⟨st.ents, shids x ++ st.rev⟩

theorem ite {α β : Type} {Rel : α → β → Prop} {c : Prop} [Decidable c] {P₁ P₂ : Prog α} {T₁ T₂ : QT β}
    (h₁ : c → Sim t P₁ T₁ Rel) (h₂ : ¬c → Sim t P₂ T₂ Rel) :
    Sim t (if c then P₁ else P₂) (if c then T₁ else T₂) Rel := by
  by_cases h : c
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

/-- Related loop states step to related loop states. -/
def StepRel {σ σ' : Type} (R : σ → σ' → Prop) : ForInStep σ → ForInStep σ' → Prop
  | .done a, .done b => R a b
  | .yield a, .yield b => R a b
  | _, _ => False

theorem forIn {ι σ σ' : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ))
    (g : ι → σ' → QT (ForInStep σ')) (R : σ → σ' → Prop)
    (hf : ∀ i ∈ l, ∀ s s', R s s' → Sim t (f i s) (g i s') (StepRel R)) :
    ∀ (s : σ) (s' : σ'), R s s' → Sim t (forIn l s f) (forIn l s' g) R := by
  induction l with
  | nil => intro s s' h; exact pure' h
  | cons a l ih =>
    intro s s' h
    rw [List.forIn_cons, List.forIn_cons]
    apply bind (hf a (by simp) s s' h)
    intro x y hxy
    cases x with
    | done a' =>
      cases y with
      | done b' => exact pure' hxy
      | yield b' => exact absurd hxy (by simp [StepRel])
    | yield a' =>
      cases y with
      | done b' => exact absurd hxy (by simp [StepRel])
      | yield b' => exact ih (fun i hi => hf i (by simp [hi])) a' b' hxy

end Sim

#print axioms Sim.askC
#print axioms Sim.forIn
end DSM.Rom
