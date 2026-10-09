-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompCount

/- Modular proof, milestone 3 (support): processes that draw fresh values.

   A reduction and the game it plays draw fresh uniform values from more than
   one source: the challenger's tape and the reduction's own coins. The
   hybrid it is compared with draws the same values from one tape. A process
   is an interaction tree whose queries are draws, labelled by their source
   (`Bool`); each source is a tape consumed in order.

   * `tape_merge`: for a process that draws at most `a` values from source
     `true` and `b` from source `false` on every path, summing over two
     independent tapes of lengths `a` and `b` is summing over one tape of
     length `a + b` read in draw order: the two results agree ticket count
     for ticket count. Each value is fresh and uniform whichever tape it
     comes from.
   * `OT.interp`: running an interaction tree against a handler that may
     itself draw; `run_interp` relates it to an ordinary stateful run.
   * Budgets: `OT.WithinP` (draws, with a postcondition on the unused
     budget), `WithinI` (oracle queries of a program with free own draws),
     `OT.within_interp_mul` (per-step cost times the adversary's queries).
   * `OT.interp_doom`: two handlers that agree until a monotone bad state
     give equal runs, or runs that both end bad.

   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

theorem card_tape {X : Type} (S : FiniteExperiment X) :
    ∀ q, (S.tape q).cardinality = S.cardinality ^ q
  | 0 => rfl
  | q+1 => by
    show S.cardinality * (S.tape q).cardinality = _
    rw [card_tape S q, Nat.pow_succ, Nat.mul_comm]

/-! ## Labelled draws -/

section Draws
variable {X α : Type} (x0 : X)

/-- One tape, read in order. -/
def tape1 : List X → Unit → X × List X := fun T _ => (T.headD x0, T.tail)

/-- Two tapes, the label choosing which one to read. -/
def tape2 : List X × List X → Bool → X × (List X × List X)
  | (T1, T2), true => (T1.headD x0, (T1.tail, T2))
  | (T1, T2), false => (T2.headD x0, (T1, T2.tail))

/-- At most `a` draws labelled `true` and `b` labelled `false` on every path. -/
def WithinL : OT Bool X α → Nat → Nat → Prop
  | .done _, _, _ => True
  | .ask true k, a, b => match a with
    | 0 => False
    | a+1 => ∀ x, WithinL (k x) a b
  | .ask false k, a, b => match b with
    | 0 => False
    | b+1 => ∀ x, WithinL (k x) a b

/-- Forget the labels: every draw reads the one tape. -/
def unlabel : OT Bool X α → OT Unit X α
  | .done r => .done r
  | .ask _ k => .ask () (fun x => unlabel (k x))

theorem tape_merge (S : FiniteExperiment X) (g : α → Nat) :
    ∀ (P : OT Bool X α) (a b : Nat), WithinL P a b →
      (S.tape a).sum (fun T1 => (S.tape b).sum (fun T2 => g (P.run (tape2 x0) (T1, T2)).1)) =
        (S.tape (a + b)).sum (fun T => g ((unlabel P).run (tape1 x0) T).1)
  | .done r, a, b, _ => by
    simp only [OT.run, unlabel]
    rw [sum_const, sum_const, sum_const, card_tape, card_tape, card_tape, Nat.pow_add, Nat.mul_assoc]
  | .ask true k, a, b, h => by
    cases a with
    | zero => exact absurd h (by simp [WithinL])
    | succ a =>
      change (independentProduct S (S.tape a)).sum (fun p => (S.tape b).sum (fun T2 =>
          g ((OT.ask true k).run (tape2 x0) (p.1 :: p.2, T2)).1)) = _
      rw [show a + 1 + b = (a + b) + 1 by omega]
      change _ = (independentProduct S (S.tape (a + b))).sum (fun p =>
          g ((unlabel (OT.ask true k)).run (tape1 x0) (p.1 :: p.2)).1)
      rw [product_sum, product_sum]
      apply sum_congr; intro i
      simp only [OT.run, tape2, tape1, unlabel, List.headD_cons, List.tail_cons]
      exact tape_merge S g (k (S.sample i)) a b (h _)
  | .ask false k, a, b, h => by
    cases b with
    | zero => exact absurd h (by simp [WithinL])
    | succ b =>
      change (S.tape a).sum (fun T1 => (independentProduct S (S.tape b)).sum (fun p =>
          g ((OT.ask false k).run (tape2 x0) (T1, p.1 :: p.2)).1)) = _
      change _ = (independentProduct S (S.tape (a + b))).sum (fun p =>
          g ((unlabel (OT.ask false k)).run (tape1 x0) (p.1 :: p.2)).1)
      rw [product_sum]
      have : ∀ T1 : List X, (independentProduct S (S.tape b)).sum (fun p =>
          g ((OT.ask false k).run (tape2 x0) (T1, p.1 :: p.2)).1) =
          S.sum (fun x => (S.tape b).sum (fun T2 => g ((k x).run (tape2 x0) (T1, T2)).1)) := by
        intro T1; rw [product_sum]; rfl
      simp only [this]
      rw [sum_comm (S.tape a) S]
      apply sum_congr; intro i
      simp only [unlabel, OT.run, tape1, List.headD_cons, List.tail_cons]
      exact tape_merge S g (k (S.sample i)) a b (h _)

/-- Label every draw `true`. -/
def relabel : OT Unit X α → OT Bool X α
  | .done r => .done r
  | .ask _ k => .ask true (fun x => relabel (k x))

theorem withinL_relabel : ∀ (P : OT Unit X α) (a b : Nat), P.Within a → WithinL (relabel P) a b
  | .done _, _, _, _ => trivial
  | .ask _ _, 0, _, h => absurd h (by simp [OT.Within])
  | .ask _ k, a+1, b, h => fun x => withinL_relabel (k x) a b (h x)

theorem unlabel_relabel : ∀ (P : OT Unit X α), unlabel (relabel P) = P
  | .done _ => rfl
  | .ask () k => by simp only [relabel, unlabel]; congr; funext x; exact unlabel_relabel (k x)

theorem run_relabel : ∀ (P : OT Unit X α) (T1 T2 : List X),
    ((relabel P).run (tape2 x0) (T1, T2)).1 = (P.run (tape1 x0) T1).1
  | .done _, _, _ => rfl
  | .ask () k, T1, T2 => by
    simp only [relabel, OT.run, tape2, tape1]
    exact run_relabel (k _) _ _

/-- A process with every draw from one source: padding the tape multiplies
    the count by the number of extra tapes. -/
theorem tape_pad (S : FiniteExperiment X) (g : α → Nat) (P : OT Unit X α) (a b : Nat)
    (h : P.Within a) :
    S.cardinality ^ b * (S.tape a).sum (fun T => g (P.run (tape1 x0) T).1) =
      (S.tape (a + b)).sum (fun T => g (P.run (tape1 x0) T).1) := by
  have hm := tape_merge x0 S g (relabel P) a b (withinL_relabel P a b h)
  rw [unlabel_relabel] at hm
  rw [← hm, sum_mul_left]
  apply sum_congr; intro i
  rw [sum_congr (S.tape b) (g' := fun _ => g (P.run (tape1 x0) ((S.tape a).sample i)).1)
    (fun j => by rw [run_relabel]), sum_const, card_tape, Nat.mul_comm]

end Draws


/-! ## Interpreting queries by handlers that may draw -/

namespace OT
variable {Q A α L B S σ : Type}

/-- Answer each query with the handler `h`, itself an interaction tree. -/
def interp (h : S → Q → OT L B (A × S)) : OT Q A α → S → OT L B (α × S)
  | .done a, s => .done (a, s)
  | .ask q k, s => (h s q).bind (fun r => interp h (k r.1) r.2)

/-- Running an interpreted tree is running the tree against the handler run
    as an oracle. -/
theorem run_interp (h : S → Q → OT L B (A × S)) (o : σ → L → B × σ) :
    ∀ (T : OT Q A α) (s : S) (τ : σ),
      (interp h T s).run o τ =
        let r := T.run (fun (st : S × σ) q =>
          let x := (h st.1 q).run o st.2
          (x.1.1, (x.1.2, x.2))) (s, τ)
        ((r.1, r.2.1), r.2.2)
  | .done _, _, _ => rfl
  | .ask q k, s, τ => by
    simp only [interp, run]
    rw [run_bind]
    exact run_interp h o (k ((h s q).run o τ).1.1) _ _

theorem withinL_bind {X β : Type} (k : α → OT Bool X β) (a2 b2 : Nat) (hk : ∀ r, WithinL (k r) a2 b2) :
    ∀ (P : OT Bool X α) (a1 b1 : Nat), WithinL P a1 b1 → WithinL (P.bind k) (a1 + a2) (b1 + b2)
  | .done r, a1, b1, _ => withinL_mono (k r) a2 b2 (a1 + a2) (b1 + b2) (by omega) (by omega) (hk r)
  | .ask true c, a1, b1, h => by
    cases a1 with
    | zero => exact absurd h (by simp [WithinL])
    | succ a1 =>
      simp only [bind]
      rw [show a1 + 1 + a2 = (a1 + a2) + 1 by omega]
      exact fun x => withinL_bind k a2 b2 hk (c x) a1 b1 (h x)
  | .ask false c, a1, b1, h => by
    cases b1 with
    | zero => exact absurd h (by simp [WithinL])
    | succ b1 =>
      simp only [bind]
      rw [show b1 + 1 + b2 = (b1 + b2) + 1 by omega]
      exact fun x => withinL_bind k a2 b2 hk (c x) a1 b1 (h x)
where
  withinL_mono : ∀ (P : OT Bool X β) (a b a' b' : Nat), a ≤ a' → b ≤ b' → WithinL P a b → WithinL P a' b'
    | .done _, _, _, _, _, _, _, _ => trivial
    | .ask true _, 0, _, _, _, _, _, h => absurd h (by simp [WithinL])
    | .ask true c, a+1, b, a', b', ha, hb, h => by
      cases a' with
      | zero => omega
      | succ a' => exact fun x => withinL_mono (c x) a b a' b' (by omega) hb (h x)
    | .ask false _, _, 0, _, _, _, _, h => absurd h (by simp [WithinL])
    | .ask false c, a, b+1, a', b', ha, hb, h => by
      cases b' with
      | zero => omega
      | succ b' => exact fun x => withinL_mono (c x) a b a' b' ha (by omega) (h x)
end OT


namespace OT
variable {Q A α β L B S σ : Type}

/-- Two stateful oracles related by `R`: equal answers, related successors. -/
theorem run_rel {σ₁ σ₂ : Type} (o₁ : σ₁ → Q → A × σ₁) (o₂ : σ₂ → Q → A × σ₂) (R : σ₁ → σ₂ → Prop)
    (h : ∀ s₁ s₂ q, R s₁ s₂ → (o₁ s₁ q).1 = (o₂ s₂ q).1 ∧ R (o₁ s₁ q).2 (o₂ s₂ q).2) :
    ∀ (T : OT Q A α) (s₁ : σ₁) (s₂ : σ₂), R s₁ s₂ →
      (T.run o₁ s₁).1 = (T.run o₂ s₂).1 ∧ R (T.run o₁ s₁).2 (T.run o₂ s₂).2
  | .done _, _, _, hr => ⟨rfl, hr⟩
  | .ask q k, s₁, s₂, hr => by
    obtain ⟨ha, hr'⟩ := h s₁ s₂ q hr
    simp only [run]
    rw [ha]
    exact run_rel o₁ o₂ R h (k (o₂ s₂ q).1) _ _ hr'

/-- Every result of the tree satisfies `p`. -/
def All (p : α → Prop) : OT Q A α → Prop
  | .done a => p a
  | .ask _ k => ∀ y, All p (k y)

theorem all_run (p : α → Prop) (o : σ → Q → A × σ) : ∀ (T : OT Q A α) (s : σ), T.All p → p (T.run o s).1
  | .done _, _, h => h
  | .ask q k, s, h => all_run p o (k (o s q).1) _ (h _)

theorem all_bind (p : α → Prop) (p' : β → Prop) (k : α → OT Q A β) (hk : ∀ a, p a → (k a).All p') :
    ∀ (T : OT Q A α), T.All p → (T.bind k).All p'
  | .done a, h => hk a h
  | .ask _ c, h => fun y => all_bind p p' k hk (c y) (h y)

theorem all_interp (I : S → Prop) (h : S → Q → OT L B (A × S))
    (hh : ∀ s q, I s → (h s q).All (fun r => I r.2)) :
    ∀ (T : OT Q A α) (s : S), I s → (interp h T s).All (fun r => I r.2)
  | .done _, _, hs => hs
  | .ask q k, s, hs => all_bind _ _ _ (fun r hr => all_interp I h hh (k r.1) r.2 hr) _ (hh s q hs)

theorem all_mono (p p' : α → Prop) (hp : ∀ a, p a → p' a) : ∀ (T : OT Q A α), T.All p → T.All p'
  | .done a, h => hp a h
  | .ask _ k, h => fun y => all_mono p p' hp (k y) (h y)

theorem all_done (p : α → Prop) (a : α) (h : p a) : (OT.done a : OT Q A α).All p := h

theorem all_and (p p' : α → Prop) : ∀ (T : OT Q A α), T.All p → T.All p' → T.All (fun a => p a ∧ p' a)
  | .done _, h, h' => ⟨h, h'⟩
  | .ask _ k, h, h' => fun y => all_and p p' (k y) (h y) (h' y)

theorem all_true : ∀ (T : OT Q A α), T.All (fun _ => True)
  | .done _ => trivial
  | .ask _ k => fun y => all_true (k y)
end OT


/-! ## Own draws inside a reduction -/

section Own
variable {Q X α : Type} (x0 : X)

/-- Answer the reduction's own draws (`inr ()`) from its tape, in order. -/
def resolveS : OT (Q ⊕ Unit) X α → List X → OT Q X (α × List X)
  | .done a, R => .done (a, R)
  | .ask (.inl q) k, R => .ask q (fun y => resolveS (k y) R)
  | .ask (.inr ()) k, R => resolveS (k (R.headD x0)) R.tail
end Own


namespace OT
variable {Q A α β γ : Type}

theorem bind_assoc (k : α → OT Q A β) (k' : β → OT Q A γ) :
    ∀ (P : OT Q A α), (P.bind k).bind k' = P.bind (fun a => (k a).bind k')
  | .done _ => rfl
  | .ask q c => by simp only [bind]; congr; funext y; exact bind_assoc k k' (c y)

theorem bind_done : ∀ (P : OT Q A α), P.bind (fun a => .done a) = P
  | .done _ => rfl
  | .ask q c => by simp only [bind]; congr; funext y; exact bind_done (c y)

theorem bind_congr (P : OT Q A α) (k k' : α → OT Q A β) (h : ∀ a, k a = k' a) : P.bind k = P.bind k' := by
  have : k = k' := funext h
  rw [this]
end OT

section Unlabel
variable {X α β : Type}

theorem unlabel_bind (k : α → OT Bool X β) :
    ∀ (P : OT Bool X α), unlabel (P.bind k) = (unlabel P).bind (fun a => unlabel (k a))
  | .done _ => rfl
  | .ask _ c => by simp only [OT.bind, unlabel]; congr; funext y; exact unlabel_bind k (c y)

theorem unlabel_interp {Q A S : Type} (h : S → Q → OT Bool X (A × S)) :
    ∀ (T : OT Q A α) (s : S), unlabel (OT.interp h T s) = OT.interp (fun s q => unlabel (h s q)) T s
  | .done _, _ => rfl
  | .ask q k, s => by
    simp only [OT.interp]
    rw [unlabel_bind]
    congr; funext r; exact unlabel_interp h (k r.1) r.2
end Unlabel


namespace OT
/-- Two interpretations of the same tree, related step by step. -/
theorem interp_run_rel {Q A α S₁ S₂ L₁ L₂ B σ₁ σ₂ : Type}
    (h₁ : S₁ → Q → OT L₁ B (A × S₁)) (o₁ : σ₁ → L₁ → B × σ₁)
    (h₂ : S₂ → Q → OT L₂ B (A × S₂)) (o₂ : σ₂ → L₂ → B × σ₂) (R : S₁ × σ₁ → S₂ × σ₂ → Prop)
    (hs : ∀ s₁ τ₁ s₂ τ₂ q, R (s₁, τ₁) (s₂, τ₂) →
      ((h₁ s₁ q).run o₁ τ₁).1.1 = ((h₂ s₂ q).run o₂ τ₂).1.1 ∧
      R (((h₁ s₁ q).run o₁ τ₁).1.2, ((h₁ s₁ q).run o₁ τ₁).2) (((h₂ s₂ q).run o₂ τ₂).1.2, ((h₂ s₂ q).run o₂ τ₂).2)) :
    ∀ (T : OT Q A α) (s₁ : S₁) (τ₁ : σ₁) (s₂ : S₂) (τ₂ : σ₂), R (s₁, τ₁) (s₂, τ₂) →
      ((interp h₁ T s₁).run o₁ τ₁).1.1 = ((interp h₂ T s₂).run o₂ τ₂).1.1 ∧
      R (((interp h₁ T s₁).run o₁ τ₁).1.2, ((interp h₁ T s₁).run o₁ τ₁).2)
        (((interp h₂ T s₂).run o₂ τ₂).1.2, ((interp h₂ T s₂).run o₂ τ₂).2)
  | .done _, _, _, _, _, hr => ⟨rfl, hr⟩
  | .ask q k, s₁, τ₁, s₂, τ₂, hr => by
    obtain ⟨ha, hr'⟩ := hs s₁ τ₁ s₂ τ₂ q hr
    simp only [interp]
    rw [run_bind, run_bind, ha]
    exact interp_run_rel h₁ o₁ h₂ o₂ R hs (k _) _ _ _ _ hr'
end OT


theorem ind_of_eq {b c : Bool} (h : b = c) : (if b then 1 else 0 : Nat) = if c then 1 else 0 := by
  rw [h]

/-! ## Budgets with a postcondition, and doomed runs -/

namespace OT
variable {Q A α β L B S σ : Type}

/-- At most `n` queries on every path; `post` holds of each result and the
    unused budget. -/
def WithinP (post : α → Nat → Prop) : OT Q A α → Nat → Prop
  | .done r, n => post r n
  | .ask _ _, 0 => False
  | .ask _ k, n+1 => ∀ y, WithinP post (k y) n

theorem withinP_within (post : α → Nat → Prop) :
    ∀ (T : OT Q A α) (n : Nat), T.WithinP post n → T.Within n
  | .done _, _, _ => trivial
  | .ask _ _, 0, h => absurd h (by simp [WithinP])
  | .ask _ k, n+1, h => fun y => withinP_within post (k y) n (h y)

theorem withinP_bind (post : α → Nat → Prop) (post' : β → Nat → Prop) (k : α → OT Q A β)
    (hk : ∀ r m, post r m → (k r).WithinP post' m) :
    ∀ (T : OT Q A α) (n : Nat), T.WithinP post n → (T.bind k).WithinP post' n
  | .done r, n, h => hk r n h
  | .ask _ _, 0, h => absurd h (by simp [WithinP])
  | .ask _ c, n+1, h => fun y => withinP_bind post post' k hk (c y) n (h y)

/-- A budget invariant preserved by every handler step bounds the
    interpreted tree. -/
theorem withinP_interp (Inv : S → Nat → Prop) (h : S → Q → OT L B (A × S))
    (hs : ∀ s q n, Inv s n → (h s q).WithinP (fun r m => Inv r.2 m) n) :
    ∀ (T : OT Q A α) (s : S) (n : Nat), Inv s n → (interp h T s).WithinP (fun r m => Inv r.2 m) n
  | .done _, _, _, hi => hi
  | .ask q k, s, n, hi => withinP_bind _ _ _ (fun r m hr => withinP_interp Inv h hs (k r.1) r.2 m hr)
      (h s q) n (hs s q n hi)

/-- Two handlers that agree until a monotone `bad` state: the interpreted runs
    are equal, or both end bad. -/
theorem interp_doom (h₁ h₂ : S → Q → OT L B (A × S)) (o : σ → L → B × σ) (bad : S → Prop)
    (hagree : ∀ s q, ¬ bad s → h₁ s q = h₂ s q ∨
      ((h₁ s q).All (fun r => bad r.2) ∧ (h₂ s q).All (fun r => bad r.2)))
    (hstay₁ : ∀ s q, bad s → (h₁ s q).All (fun r => bad r.2))
    (hstay₂ : ∀ s q, bad s → (h₂ s q).All (fun r => bad r.2)) :
    ∀ (T : OT Q A α) (s : S) (τ : σ),
      (interp h₁ T s).run o τ = (interp h₂ T s).run o τ ∨
        (bad ((interp h₁ T s).run o τ).1.2 ∧ bad ((interp h₂ T s).run o τ).1.2)
  | .done _, _, _ => Or.inl rfl
  | .ask q k, s, τ => by
    have tail : ∀ (h : S → Q → OT L B (A × S)), (∀ s q, bad s → (h s q).All (fun r => bad r.2)) →
        (h s q).All (fun r => bad r.2) → bad ((interp h (.ask q k) s).run o τ).1.2 := by
      intro h hst ha
      exact all_run (fun r : α × S => bad r.2) o _ τ
        (all_bind (fun r : A × S => bad r.2) (fun r : α × S => bad r.2) _
          (fun r hr => all_interp bad h hst (k r.1) r.2 hr) (h s q) ha)
    by_cases hb : bad s
    · exact Or.inr ⟨tail h₁ hstay₁ (hstay₁ s q hb), tail h₂ hstay₂ (hstay₂ s q hb)⟩
    · rcases hagree s q hb with he | ⟨a1, a2⟩
      · simp only [interp]
        rw [run_bind, run_bind, he]
        exact interp_doom h₁ h₂ o bad hagree hstay₁ hstay₂ (k _) _ _
      · exact Or.inr ⟨tail h₁ hstay₁ a1, tail h₂ hstay₂ a2⟩
end OT

/-- A labelled process drawing at most `n` values in all draws at most `n`
    from each source. -/
theorem withinL_of_unlabel {X α : Type} :
    ∀ (P : OT Bool X α) (n a b : Nat), (unlabel P).Within n → n ≤ a → n ≤ b → WithinL P a b
  | .done _, _, _, _, _, _, _ => trivial
  | .ask _ _, 0, _, _, h, _, _ => absurd h (by simp [unlabel, OT.Within])
  | .ask true _, _+1, 0, _, _, ha, _ => absurd ha (by omega)
  | .ask true k, n+1, a+1, b, h, ha, hb => fun x =>
      withinL_of_unlabel (k x) n a b (h x) (by omega) (by omega)
  | .ask false _, _+1, _, 0, _, _, hb => absurd hb (by omega)
  | .ask false k, n+1, a, b+1, h, ha, hb => fun x =>
      withinL_of_unlabel (k x) n a b (h x) (by omega) (by omega)


/-! ## Query budgets of programs with own draws -/

section OwnBudget
variable {Q X α β : Type}

/-- At most `n` oracle queries (`inl`) on every path; own draws (`inr`) are
    free; `post` holds of each result and the unused budget. -/
def WithinI (post : α → Nat → Prop) : OT (Q ⊕ Unit) X α → Nat → Prop
  | .done r, n => post r n
  | .ask (.inl _) _, 0 => False
  | .ask (.inl _) k, n+1 => ∀ y, WithinI post (k y) n
  | .ask (.inr ()) k, n => ∀ y, WithinI post (k y) n

theorem withinI_bind (post : α → Nat → Prop) (post' : β → Nat → Prop) (k : α → OT (Q ⊕ Unit) X β)
    (hk : ∀ r m, post r m → WithinI post' (k r) m) :
    ∀ (P : OT (Q ⊕ Unit) X α) (n : Nat), WithinI post P n → WithinI post' (P.bind k) n
  | .done r, n, h => hk r n h
  | .ask (.inl _) _, 0, h => absurd h (by simp [WithinI])
  | .ask (.inl _) c, n+1, h => fun y => withinI_bind post post' k hk (c y) n (h y)
  | .ask (.inr ()) c, n, h => fun y => withinI_bind post post' k hk (c y) n (h y)

theorem withinI_mono (post post' : α → Nat → Prop) (hp : ∀ r m, post r m → post' r m) :
    ∀ (P : OT (Q ⊕ Unit) X α) (n : Nat), WithinI post P n → WithinI post' P n
  | .done r, n, h => hp r n h
  | .ask (.inl _) _, 0, h => absurd h (by simp [WithinI])
  | .ask (.inl _) c, n+1, h => fun y => withinI_mono post post' hp (c y) n (h y)
  | .ask (.inr ()) c, n, h => fun y => withinI_mono post post' hp (c y) n (h y)

/-- Resolving own draws leaves the oracle queries. -/
theorem withinI_resolve (x0 : X) (post : α → Nat → Prop) :
    ∀ (P : OT (Q ⊕ Unit) X α) (R : List X) (n : Nat), WithinI post P n →
      (resolveS x0 P R).WithinP (fun r m => post r.1 m) n
  | .done _, _, _, h => h
  | .ask (.inl _) _, _, 0, h => absurd h (by simp [WithinI])
  | .ask (.inl _) c, R, n+1, h => fun y => withinI_resolve x0 post (c y) R n (h y)
  | .ask (.inr ()) c, R, n, h => withinI_resolve x0 post (c (R.headD x0)) R.tail n (h _)
end OwnBudget

/-- Each handler step costs at most `K` queries: an adversary of `q` queries
    is interpreted with at most `q · K`. -/
theorem OT.within_interp_mul {Q A α L B S : Type} (h : S → Q → OT L B (A × S)) (K : Nat)
    (hs : ∀ s q n, K ≤ n → (h s q).WithinP (fun _ m => n ≤ m + K) n) :
    ∀ (T : OT Q A α) (q : Nat) (s : S) (n : Nat), T.Within q → q * K ≤ n →
      (OT.interp h T s).WithinP (fun _ _ => True) n
  | .done _, _, _, _, _, _ => trivial
  | .ask _ _, 0, _, _, hT, _ => absurd hT (by simp [OT.Within])
  | .ask qq k, q+1, s, n, hT, hn => by
    simp only [OT.interp]
    refine OT.withinP_bind _ _ _ (fun r m hm => ?_) _ n (hs s qq n (by rw [Nat.succ_mul] at hn; omega))
    exact OT.within_interp_mul h K hs (k r.1) q r.2 m (hT _) (by rw [Nat.succ_mul] at hn; omega)

#print axioms tape_merge
#print axioms tape_pad
#print axioms OT.interp_doom
#print axioms withinL_of_unlabel
#print axioms withinI_resolve
#print axioms OT.within_interp_mul
end DSM.Sphincs.Comp
