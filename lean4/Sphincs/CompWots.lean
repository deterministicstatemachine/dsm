-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompProc

/- Modular proof, milestone 3, obligation 8 (part 1): the multi-instance
   WOTS-TW game of EasyCrypt's `WOTS_TW_ES.ec` (M-EUF-GCMA, without PRF) on
   DSM's finite framework, and its hybrids.

   The game: `pp` is sampled; the adversary adaptively asks for a public key
   and a signature of a message of its choice under fresh WOTS instances
   (each with a fresh uniform secret key), and may query the collection
   oracle; it then receives `pp` and outputs an index, a message and a
   signature. It wins if the signature verifies against that instance's
   public key, the message is fresh for it, at most `c` instances were used,
   the instances are distinct, and no collection tweak lies in a signed
   instance.

   Fresh values are drawn from one tape in order (`CompProc`). Hybrid `k`
   (`hybHandler`) computes the chain value at depth `e = digit − 1` from a
   uniform value at depth `min k e`; hybrid 0 is the real game (`real_eq_hyb0`)
   and hybrid `w − 2` is EasyCrypt's Game 3 (a signature element is one hash
   step from a uniform value). No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- Signing queries `(instance, message)` and collection queries `(tweak, input)`. -/
abbrev WotsQuery (Tw I M Xc : Type) := (I × M) ⊕ (Tw × Xc)
/-- Signing answers `(pk, sig)` and collection answers. -/
abbrev WotsAnswer (X : Type) := (List X × List X) ⊕ X

structure WotsAdv (PP Tw I M X Xc σ : Type) where
  choose : OT (WotsQuery Tw I M Xc) (WotsAnswer X) σ
  forge : σ → PP → Nat × M × List X

/-- Signed instances with their message, public key and signature; collection
    tweaks. -/
structure WotsState (Tw I M X : Type) where
  qs : List (I × M × List X × List X)
  cols : List Tw

/-- The data of a WOTS-TW setting: Winternitz parameter, chain count, message
    encoding, tweaks of chain positions, the instance a tweak belongs to, the
    chain function, the collection and its embedding of chain values. -/
structure WotsSetting (PP Tw I M X Xc : Type) where
  w : Nat
  len : Nat
  enc : M → List Nat
  twk : I → Nat → Nat → Tw
  inst : Tw → I
  f : PP → Tw → X → X
  fc : PP → Tw → Xc → X
  embed : X → Xc

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-- `k` steps of chain `c` of instance `a`, starting at depth `s`. -/
def chain (pp : PP) (a : I) (c : Nat) : X → Nat → Nat → X
  | x, _, 0 => x
  | x, s, k+1 => chain pp a c (W.f pp (W.twk a c s) x) (s+1) k

theorem chain_add (pp : PP) (a : I) (c : Nat) :
    ∀ (k₁ k₂ : Nat) (x : X) (s : Nat),
      W.chain pp a c x s (k₁ + k₂) = W.chain pp a c (W.chain pp a c x s k₁) (s + k₁) k₂
  | 0, k₂, x, s => by simp [chain]
  | k₁+1, k₂, x, s => by
    rw [show k₁ + 1 + k₂ = (k₁ + k₂) + 1 by omega]
    simp only [chain]
    rw [chain_add pp a c k₁ k₂ _ (s+1), show s + 1 + k₁ = s + (k₁ + 1) by omega]

theorem chain_succ (pp : PP) (a : I) (c : Nat) (x : X) (s k : Nat) :
    W.chain pp a c x s (k + 1) = W.f pp (W.twk a c (s + k)) (W.chain pp a c x s k) := by
  rw [chain_add W pp a c k 1]; rfl

/-- Public-key tops recomputed from a signature. -/
def tops (pp : PP) (a : I) (m : M) (sig : List X) : List X :=
  ((W.enc m).zipIdx.zip sig).map (fun q => W.chain pp a q.1.2 q.2 q.1.1 (W.w - 1 - q.1.1))

def verify [DecidableEq X] (pp : PP) (a : I) (m : M) (sig pk : List X) : Bool :=
  sig.length == W.len && W.tops pp a m sig == pk

/-- EasyCrypt's winning condition. -/
def win [DecidableEq X] [DecidableEq I] [DecidableEq M] (c : Nat) (pp : PP) (s : WotsState Tw I M X)
    (out : Nat × M × List X) : Bool :=
  match s.qs[out.1]? with
  | none => false
  | some (a, m, pk, _) =>
      decide (s.qs.length ≤ c) && decide (s.qs.map (·.1)).Nodup &&
        s.cols.all (fun tw => !(s.qs.map (·.1)).contains (W.inst tw)) &&
        W.verify pp a out.2.1 out.2.2 pk && !(out.2.1 == m)

/-! ## Signing oracles, drawing fresh values -/

/-- Chain-by-chain signing: `elem c digit` gives (pk element, sig element). -/
def signFrom {Q : Type} (elem : Nat → Nat → OT Q X (X × X)) : Nat → List Nat → OT Q X (List X × List X)
  | _, [] => .done ([], [])
  | c, d :: ds => (elem c d).bind (fun e => (signFrom elem (c+1) ds).bind (fun r =>
      .done (e.1 :: r.1, e.2 :: r.2)))

/-- The real signer: a uniform secret per chain; sig = chain to the digit,
    pk = chain to `w − 1`. -/
def realElem (pp : PP) (a : I) (c d : Nat) : OT Unit X (X × X) :=
  .ask () (fun sk => .done (W.chain pp a c sk 0 (W.w - 1), W.chain pp a c sk 0 d))

/-- Hybrid `k`: for digit `d = e + 1`, the value at depth `e` starts uniform at
    depth `min k e`; sig = one more step; pk from sig. For digit 0, sig is
    uniform. -/
def hybElem (k : Nat) (pp : PP) (a : I) (c : Nat) : Nat → OT Unit X (X × X)
  | 0 => .ask () (fun x => .done (W.chain pp a c x 0 (W.w - 1), x))
  | e+1 => .ask () (fun x =>
      let v := W.chain pp a c x (min k e) (e - min k e)
      let sig := W.f pp (W.twk a c e) v
      .done (W.chain pp a c sig (e+1) (W.w - 1 - (e+1)), sig))

/-- A challenger: signing with `elem`, the collection oracle unchanged. -/
def handler (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (pp : PP) :
    WotsState Tw I M X → WotsQuery Tw I M Xc → OT Unit X (WotsAnswer X × WotsState Tw I M X)
  | s, .inl (a, m) => (signFrom (elem pp a) 0 (W.enc m)).bind (fun r =>
      .done (.inl r, ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩))
  | s, .inr (tw, x) => .done (.inr (W.fc pp tw x), ⟨s.qs, s.cols ++ [tw]⟩)

/-- The game as a process: interpret the adversary's first phase with the
    challenger `hd`, then judge its forgery. -/
def proc [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (hd : WotsState Tw I M X → WotsQuery Tw I M Xc → OT Unit X (WotsAnswer X × WotsState Tw I M X))
    (c : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) : OT Unit X Bool :=
  (OT.interp hd A.choose (⟨[], []⟩ : WotsState Tw I M X)).bind (fun r =>
    .done (W.win c pp r.2 (A.forge r.1 pp)))

/-- Success count over `pp`, the adversary's coins and a tape of `L` values. -/
def count [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X)
    (hd : PP → WotsState Tw I M X → WotsQuery Tw I M Xc → OT Unit X (WotsAnswer X × WotsState Tw I M X))
    (c L : Nat) (P : FiniteExperiment PP)
    (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) : Nat :=
  P.sum (fun pp => As.sum (fun A => (Din.tape L).sum (fun T =>
    if ((W.proc (hd pp) c pp A).run (tape1 x0) T).1 then 1 else 0)))

/-- The M-EUF-GCMA game (EasyCrypt `M_EUF_GCMA_WOTSTWESNPRF`), as a probability:
    `pp`, the adversary's coins, and `c · len` fresh secret values (enough for
    every winning run; a run with more than `c` signing queries loses). -/
def gameProb [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ)) :
    Probability :=
  ⟨W.count x0 (fun pp => W.handler (fun pp a => W.realElem pp a) pp) c (c * W.len) P Din As,
   P.cardinality * (As.cardinality * (Din.tape (c * W.len)).cardinality),
   Nat.mul_pos P.positive (Nat.mul_pos As.positive (by rw [card_tape]; exact Nat.pow_pos Din.positive)),
   by
    unfold count
    calc _ ≤ P.sum (fun _ => As.sum (fun _ => (Din.tape (c * W.len)).sum (fun _ => 1))) :=
          sum_le P (fun _ => sum_le As (fun _ => sum_le _ (fun _ => by split <;> omega)))
      _ = _ := by simp only [sum_const, Nat.mul_one]⟩

/-- A challenger capped at `c` signing queries: further signing queries are
    recorded (so the adversary loses) and answered with nothing. -/
def capH {Q : Type} (c : Nat)
    (h : WotsState Tw I M X → WotsQuery Tw I M Xc → OT Q X (WotsAnswer X × WotsState Tw I M X)) :
    WotsState Tw I M X → WotsQuery Tw I M Xc → OT Q X (WotsAnswer X × WotsState Tw I M X)
  | s, .inl (a, m) => if s.qs.length < c then h s (.inl (a, m)) else
      .done (.inl ([], []), ⟨s.qs ++ [(a, m, [], [])], s.cols⟩)
  | s, .inr q => h s (.inr q)

/-! ## Hybrid 0 is the real game -/

theorem realElem_eq_hyb0 (pp : PP) (a : I) (c d : Nat) (hd : d ≤ W.w - 1) :
    W.realElem pp a c d = W.hybElem 0 pp a c d := by
  cases d with
  | zero => rfl
  | succ e =>
    simp only [realElem, hybElem, Nat.zero_min, Nat.sub_zero]
    congr; funext x
    have h1 : W.chain pp a c x 0 (e + 1) = W.f pp (W.twk a c e) (W.chain pp a c x 0 e) := by
      rw [chain_succ, Nat.zero_add]
    have h2 : W.chain pp a c x 0 (W.w - 1) =
        W.chain pp a c (W.chain pp a c x 0 (e + 1)) (e + 1) (W.w - 1 - (e + 1)) := by
      rw [show W.w - 1 = (e + 1) + (W.w - 1 - (e + 1)) by omega, chain_add, Nat.zero_add,
        show e + 1 + (W.w - 1 - (e + 1)) - (e + 1) = W.w - 1 - (e + 1) by omega]
    rw [h2, h1]

theorem signFrom_congr {Q : Type} (e₁ e₂ : Nat → Nat → OT Q X (X × X)) (B : Nat) :
    ∀ (ds : List Nat) (c : Nat), (∀ d ∈ ds, d ≤ B) → (∀ c d, d ≤ B → e₁ c d = e₂ c d) →
      signFrom e₁ c ds = signFrom e₂ c ds
  | [], _, _, _ => rfl
  | d :: ds, c, hd, he => by
    simp only [signFrom]
    rw [he c d (hd d (List.mem_cons_self ..)),
      signFrom_congr e₁ e₂ B ds (c+1) (fun d h => hd d (List.mem_cons_of_mem _ h)) he]


/-! ## Draw budgets of the capped challengers -/

/-- `e` draws exactly one value and returns. -/
def OneDraw (e : Nat → Nat → OT Unit X (X × X)) : Prop :=
  ∀ c d, ∃ g : X → X × X, e c d = .ask () (fun x => .done (g x))

theorem signFrom_withinP (elem : Nat → Nat → OT Unit X (X × X)) (he : OneDraw elem) :
    ∀ (ds : List Nat) (c n : Nat), ds.length ≤ n →
      (signFrom elem c ds).WithinP (fun _ m => n ≤ m + ds.length) n
  | [], _, n, _ => by simp [signFrom, OT.WithinP]
  | d :: ds, c, n, hn => by
    obtain ⟨g, hg⟩ := he c d
    cases n with
    | zero => simp at hn
    | succ n =>
      simp only [signFrom, hg, OT.bind, OT.WithinP]
      intro x
      exact OT.withinP_bind _ _ _ (fun r m hr => by simp only [OT.WithinP, List.length_cons]; omega) _ n
        (signFrom_withinP elem he ds (c+1) n (by simp at hn; omega))

/-- Budget invariant: the unused budget covers the remaining signing queries. -/
def capInv (c : Nat) (s : WotsState Tw I M X) (n : Nat) : Prop := (c - s.qs.length) * W.len ≤ n

theorem capH_withinP (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (he : ∀ pp a, OneDraw (elem pp a))
    (hlen : ∀ m, (W.enc m).length = W.len) (pp : PP) (c : Nat) (s : WotsState Tw I M X)
    (q : WotsQuery Tw I M Xc) (n : Nat) (hi : W.capInv c s n) :
    (capH c (W.handler elem pp) s q).WithinP (fun r m => W.capInv c r.2 m) n := by
  match q with
  | .inl (a, msg) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, handler]
      have hk : c - s.qs.length = (c - (s.qs.length + 1)) + 1 := by omega
      unfold capInv at hi
      rw [hk, Nat.succ_mul] at hi
      refine OT.withinP_bind _ _ _ (fun r m hr => ?_) _ n
        (signFrom_withinP (elem pp a) (he pp a) (W.enc msg) 0 n (by rw [hlen]; omega))
      simp only [OT.WithinP, capInv, List.length_append, List.length_singleton]
      rw [hlen] at hr
      omega
    · simp only [capH, if_neg hlt, OT.WithinP, capInv, List.length_append, List.length_singleton]
      rw [Nat.sub_eq_zero_of_le (by omega), Nat.zero_mul]
      exact Nat.zero_le _
  | .inr (tw, x) =>
    simp only [capH, handler, OT.WithinP]
    exact hi

/-- A capped game draws at most `c · len` values. -/
theorem proc_within [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (he : ∀ pp a, OneDraw (elem pp a))
    (hlen : ∀ m, (W.enc m).length = W.len) (c : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) :
    (W.proc (capH c (W.handler elem pp)) c pp A).Within (c * W.len) := by
  unfold proc
  apply OT.withinP_within (fun _ _ => True)
  exact OT.withinP_bind _ _ _ (fun _ _ _ => by simp [OT.WithinP]) _ _
    (OT.withinP_interp (fun s n => W.capInv c s n) _
      (fun s q n h => W.capH_withinP elem he hlen pp c s q n h) A.choose ⟨[], []⟩ (c * W.len)
      (by simp [capInv]))

theorem hyb_oneDraw (k : Nat) (pp : PP) (a : I) : OneDraw (W.hybElem k pp a) := by
  intro c d
  cases d with
  | zero => exact ⟨_, rfl⟩
  | succ e => exact ⟨_, rfl⟩

/-! ## Capping loses nothing -/

theorem win_of_bad [DecidableEq X] [DecidableEq I] [DecidableEq M] (c : Nat) (pp : PP)
    (s : WotsState Tw I M X) (out : Nat × M × List X) (h : c < s.qs.length) : W.win c pp s out = false := by
  unfold win
  split
  · rfl
  · simp [show ¬ s.qs.length ≤ c by omega]

theorem handler_sign_len (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (pp : PP)
    (s : WotsState Tw I M X) (a : I) (m : M) :
    (W.handler elem pp s (.inl (a, m))).All (fun r => r.2.qs.length = s.qs.length + 1) := by
  simp only [handler]
  exact OT.all_bind _ _ _ (fun r _ => by simp [OT.All]) _ (OT.all_true _)

/-- The game capped at `c` signing queries wins exactly when the uncapped one
    does: the two agree until the `(c+1)`-th signing query, after which both
    lose. -/
theorem proc_cap_eq [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X)
    (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (c : Nat) (pp : PP)
    (A : WotsAdv PP Tw I M X Xc σ) (T : List X) :
    ((W.proc (capH c (W.handler elem pp)) c pp A).run (tape1 x0) T).1 =
      ((W.proc (W.handler elem pp) c pp A).run (tape1 x0) T).1 := by
  have hagree : ∀ (s : WotsState Tw I M X) q, ¬ c < s.qs.length →
      capH c (W.handler elem pp) s q = W.handler elem pp s q ∨
        ((capH c (W.handler elem pp) s q).All (fun r => c < r.2.qs.length) ∧
          (W.handler elem pp s q).All (fun r => c < r.2.qs.length)) := by
    intro s q hb
    match q with
    | .inl (a, m) =>
      by_cases hlt : s.qs.length < c
      · left; simp only [capH, if_pos hlt]
      · right
        refine ⟨?_, OT.all_mono _ _ (fun r hr => by omega) _ (W.handler_sign_len elem pp s a m)⟩
        simp only [capH, if_neg hlt, OT.All, List.length_append, List.length_singleton]
        omega
    | .inr q => left; rfl
  have hstay₁ : ∀ (s : WotsState Tw I M X) q, c < s.qs.length →
      (capH c (W.handler elem pp) s q).All (fun r => c < r.2.qs.length) := by
    intro s q hb
    match q with
    | .inl (a, m) =>
      simp only [capH, if_neg (show ¬ s.qs.length < c by omega), OT.All, List.length_append,
        List.length_singleton]
      omega
    | .inr (tw, x) => simp only [capH, handler, OT.All]; exact hb
  have hstay₂ : ∀ (s : WotsState Tw I M X) q, c < s.qs.length →
      (W.handler elem pp s q).All (fun r => c < r.2.qs.length) := by
    intro s q hb
    match q with
    | .inl (a, m) => exact OT.all_mono _ _ (fun r hr => by omega) _ (W.handler_sign_len elem pp s a m)
    | .inr (tw, x) => simp only [handler, OT.All]; exact hb
  unfold proc
  rw [OT.run_bind, OT.run_bind]
  rcases OT.interp_doom _ _ (tape1 x0) (fun s : WotsState Tw I M X => c < s.qs.length) hagree hstay₁
    hstay₂ A.choose ⟨[], []⟩ T with he | ⟨b1, b2⟩
  · rw [he]
  · simp only [OT.run]
    rw [W.win_of_bad c pp _ _ b1, W.win_of_bad c pp _ _ b2]

/-- The real challenger is hybrid 0 (all digits are at most `w − 1`). -/
theorem handler_real_hyb0 (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1) (pp : PP) :
    W.handler (fun pp a => W.realElem pp a) pp = W.handler (fun pp a => W.hybElem 0 pp a) pp := by
  funext s q
  match q with
  | .inl (a, m) =>
    simp only [handler]
    rw [signFrom_congr (W.realElem pp a) (W.hybElem 0 pp a) (W.w - 1) (W.enc m) 0 (hdig m)
      (fun c d hd => W.realElem_eq_hyb0 pp a c d hd)]
  | .inr _ => rfl

/-- Success count of hybrid `k`, capped at `c` signing queries, on `c · len` values. -/
def hybCount [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (k : Nat) : Nat :=
  W.count x0 (fun pp => capH c (W.handler (fun pp a => W.hybElem k pp a) pp)) c (c * W.len) P Din As

/-- The M-EUF-GCMA game counts as capped hybrid 0. -/
theorem game_hyb0 [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1) :
    (W.gameProb x0 c P Din As).numerator = W.hybCount x0 c P Din As 0 := by
  unfold gameProb hybCount count
  dsimp only
  apply sum_congr; intro i
  apply sum_congr; intro j
  apply sum_congr; intro k
  rw [W.proc_cap_eq x0 (fun pp a => W.hybElem 0 pp a) c, ← W.handler_real_hyb0 hdig]


/-- Capped hybrid `k` as a probability, on the game's ticket space. -/
def hybProb [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (k : Nat) : Probability :=
  ⟨W.hybCount x0 c P Din As k,
   P.cardinality * (As.cardinality * (Din.tape (c * W.len)).cardinality),
   Nat.mul_pos P.positive (Nat.mul_pos As.positive (by rw [card_tape]; exact Nat.pow_pos Din.positive)),
   by
    unfold hybCount count
    calc _ ≤ P.sum (fun _ => As.sum (fun _ => (Din.tape (c * W.len)).sum (fun _ => 1))) :=
          sum_le P (fun _ => sum_le As (fun _ => sum_le _ (fun _ => by split <;> omega)))
      _ = _ := by simp only [sum_const, Nat.mul_one]⟩

end WotsSetting

#print axioms DSM.Sphincs.Comp.WotsSetting.chain_add
#print axioms DSM.Sphincs.Comp.WotsSetting.realElem_eq_hyb0
#print axioms DSM.Sphincs.Comp.WotsSetting.proc_within
#print axioms DSM.Sphincs.Comp.WotsSetting.game_hyb0
end DSM.Sphincs.Comp
