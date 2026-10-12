-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompWotsUd

/- Modular proof, milestone 3, obligation 8 (part 3): EasyCrypt's Game 3 of
   WOTS-TW and the analysis of a winning forgery in it.

   In Game 3 (hybrid `w − 2`) each signature element at digit `d = e + 1` is
   `F` applied at depth `e` to a fresh uniform value, and the element at
   digit 0 is itself uniform (`g3Elem`, `handler_hyb_g3`); the public key is
   the chain from the signature to depth `w − 1` (`Honest`, `honest_step`).

   A winning forgery `(m', σ')` against a signed `(m, σ, pk)` has, by the
   encoding's `two_encodings` property, a first chain `j` with
   `d'_j < d_j`; climbing `σ'_j` from `d'_j` to `d_j` gives `y`, and `y`
   and `σ_j` meet at depth `w − 1` (`forge_facts`). Either `y = σ_j`
   (`preEv`: the value one step below is a preimage of `σ_j`) or `y ≠ σ_j`
   (`tcrEv`: the two chains collide at some depth, `findCol_spec`).
   No assumption, axiom or `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

theorem getElem?_idxOf {α : Type} [BEq α] [LawfulBEq α] : ∀ (l : List α) (a : α), a ∈ l → l[l.idxOf a]? = some a
  | [], _, h => absurd h (by simp)
  | b :: l, a, h => by
    by_cases hb : b = a
    · subst hb; simp
    · have ha : a ∈ l := by
        rcases List.mem_cons.mp h with h | h
        · exact absurd h.symm hb
        · exact h
      rw [List.idxOf_cons]
      have : (b == a) = false := by simp [hb]
      rw [this]
      simpa using getElem?_idxOf l a ha

/-- The first position where the first list's digit is smaller. -/
def firstLess : List Nat → List Nat → Nat
  | d' :: ds', d :: ds => if d' < d then 0 else firstLess ds' ds + 1
  | _, _ => 0

theorem firstLess_spec : ∀ (ds' ds : List Nat) (j : Nat), j < ds'.length → j < ds.length →
    ds'.getD j 0 < ds.getD j 0 →
      firstLess ds' ds < ds'.length ∧ firstLess ds' ds < ds.length ∧
        ds'.getD (firstLess ds' ds) 0 < ds.getD (firstLess ds' ds) 0
  | [], _, _, h, _, _ => absurd h (by simp)
  | _ :: _, [], _, _, h, _ => absurd h (by simp)
  | d' :: ds', d :: ds, j, h1, h2, h3 => by
    by_cases h : d' < d
    · simp [firstLess, h]
    · cases j with
      | zero => simp at h3; omega
      | succ j =>
        simp only [List.length_cons] at h1 h2
        simp only [List.getD_cons_succ] at h3
        have := firstLess_spec ds' ds j (by omega) (by omega) h3
        simp only [firstLess, if_neg h, List.length_cons, List.getD_cons_succ]
        omega

namespace WotsSetting
variable {PP Tw I M X Xc : Type} (W : WotsSetting PP Tw I M X Xc)

/-! ## Game 3 -/

/-- Game 3's signer: digit 0 uniform; digit `e + 1` is `F` at depth `e` of a
    uniform value; the public key climbs the signature to depth `w − 1`. -/
def g3Elem (pp : PP) (a : I) (c : Nat) : Nat → OT Unit X (X × X)
  | 0 => .ask () (fun x => .done (W.chain pp a c x 0 (W.w - 1), x))
  | e+1 => .ask () (fun x =>
      let sig := W.f pp (W.twk a c e) x
      .done (W.chain pp a c sig (e+1) (W.w - 1 - (e+1)), sig))

theorem hyb_g3 (pp : PP) (a : I) (c d : Nat) (hd : d ≤ W.w - 1) :
    W.hybElem (W.w - 2) pp a c d = W.g3Elem pp a c d := by
  cases d with
  | zero => rfl
  | succ e =>
    simp only [hybElem, g3Elem]
    rw [show min (W.w - 2) e = e by omega, Nat.sub_self]
    rfl

theorem handler_hyb_g3 (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1) (pp : PP) :
    W.handler (fun pp a => W.hybElem (W.w - 2) pp a) pp = W.handler (fun pp a => W.g3Elem pp a) pp := by
  funext s q
  match q with
  | .inl (a, m) =>
    simp only [handler]
    rw [signFrom_congr (W.hybElem (W.w - 2) pp a) (W.g3Elem pp a) (W.w - 1) (W.enc m) 0 (hdig m)
      (fun c d hd => W.hyb_g3 pp a c d hd)]
  | .inr _ => rfl

theorem g3_oneDraw (pp : PP) (a : I) : OneDraw (W.g3Elem pp a) := by
  intro c d
  cases d with
  | zero => exact ⟨_, rfl⟩
  | succ e => exact ⟨_, rfl⟩

/-! ## Public keys of Game 3 -/

/-- The chain tops of a signature, chain by chain from chain `c`. -/
def topsFrom (pp : PP) (a : I) : Nat → List Nat → List X → List X
  | c, d :: ds, x :: xs => W.chain pp a c x d (W.w - 1 - d) :: topsFrom pp a (c+1) ds xs
  | _, _, _ => []

theorem tops_from (pp : PP) (a : I) : ∀ (ds : List Nat) (sig : List X) (c : Nat),
    ((ds.zipIdx c).zip sig).map (fun q => W.chain pp a q.1.2 q.2 q.1.1 (W.w - 1 - q.1.1)) =
      W.topsFrom pp a c ds sig
  | [], _, _ => by simp [topsFrom]
  | _ :: _, [], _ => by simp [topsFrom]
  | d :: ds, x :: xs, c => by
    rw [List.zipIdx_cons, List.zip_cons_cons, List.map_cons, tops_from pp a ds xs (c+1)]
    rfl

theorem tops_eq (pp : PP) (a : I) (m : M) (sig : List X) :
    W.tops pp a m sig = W.topsFrom pp a 0 (W.enc m) sig := W.tops_from pp a _ _ 0

theorem topsFrom_getD (pp : PP) (a : I) (x0 : X) : ∀ (ds : List Nat) (sig : List X) (c j : Nat),
    j < ds.length → j < sig.length →
      (W.topsFrom pp a c ds sig).getD j x0 =
        W.chain pp a (c + j) (sig.getD j x0) (ds.getD j 0) (W.w - 1 - ds.getD j 0)
  | [], _, _, _, h, _ => absurd h (by simp)
  | _ :: _, [], _, _, _, h => absurd h (by simp)
  | d :: ds, x :: xs, c, 0, _, _ => by simp [topsFrom]
  | d :: ds, x :: xs, c, j+1, h1, h2 => by
    simp only [topsFrom, List.getD_cons_succ]
    rw [topsFrom_getD pp a x0 ds xs (c+1) j (by simp at h1; omega) (by simp at h2; omega)]
    rw [show c + 1 + j = c + (j + 1) by omega]

theorem g3Elem_all (pp : PP) (a : I) (c d : Nat) :
    (W.g3Elem pp a c d).All (fun e => e.1 = W.chain pp a c e.2 d (W.w - 1 - d)) := by
  cases d with
  | zero => intro x; simp only [OT.All, Nat.sub_zero]
  | succ e => intro x; rfl

theorem signFrom_g3 (pp : PP) (a : I) : ∀ (ds : List Nat) (c : Nat),
    (signFrom (W.g3Elem pp a) c ds).All (fun r => r.2.length = ds.length ∧ r.1 = W.topsFrom pp a c ds r.2)
  | [], _ => ⟨rfl, rfl⟩
  | d :: ds, c => by
    simp only [signFrom]
    refine OT.all_bind _ _ _ (fun e he => ?_) _ (W.g3Elem_all pp a c d)
    refine OT.all_bind _ _ _ (fun r hr => ?_) _ (signFrom_g3 pp a ds (c+1))
    show (e.2 :: r.2).length = (d :: ds).length ∧ e.1 :: r.1 = W.topsFrom pp a c (d :: ds) (e.2 :: r.2)
    exact ⟨by simp [hr.1], by simp only [topsFrom, he, hr.2]⟩

/-- The signed entries (up to the cap) carry honest public keys. -/
def Honest (pp : PP) (c : Nat) (s : WotsState Tw I M X) : Prop :=
  ∀ e ∈ s.qs.take c, e.2.2.1 = W.tops pp e.1 e.2.1 e.2.2.2 ∧ e.2.2.2.length = W.len

theorem honest_step (hlen : ∀ m, (W.enc m).length = W.len) (pp : PP) (c : Nat)
    (s : WotsState Tw I M X) (q : WotsQuery Tw I M Xc) (h : W.Honest pp c s) :
    (capH c (W.handler (fun pp a => W.g3Elem pp a) pp) s q).All (fun r => W.Honest pp c r.2) := by
  match q with
  | .inl (a, m) =>
    by_cases hlt : s.qs.length < c
    · simp only [capH, if_pos hlt, handler]
      refine OT.all_bind _ _ _ (fun r hr => ?_) _ (W.signFrom_g3 pp a (W.enc m) 0)
      show W.Honest pp c ⟨s.qs ++ [(a, m, r.1, r.2)], s.cols⟩
      have ht1 : (s.qs ++ [(a, m, r.1, r.2)]).take c = s.qs ++ [(a, m, r.1, r.2)] :=
        List.take_of_length_le (by simp; omega)
      have ht0 : s.qs.take c = s.qs := List.take_of_length_le (by omega)
      unfold Honest at h ⊢
      rw [ht0] at h
      simp only [ht1]
      intro e he
      rcases List.mem_append.mp he with he | he
      · exact h e he
      · rw [List.mem_singleton] at he
        subst he
        exact ⟨by rw [tops_eq]; exact hr.2, by rw [hr.1, hlen]⟩
    · simp only [capH, if_neg hlt, OT.All]
      show W.Honest pp c ⟨s.qs ++ [(a, m, [], [])], s.cols⟩
      unfold Honest at h ⊢
      rw [List.take_append_of_le_length (by omega)]
      exact h
  | .inr (tw, x) =>
    simp only [capH, handler, OT.All]
    exact h

/-! ## A winning forgery -/

/-- `σ'_j` climbed from `d'_j` to `d_j`, at the first chain `j` with `d'_j < d_j`. -/
def forgeY (x0 : X) (pp : PP) (a : I) (m : M) (out : Nat × M × List X) : X :=
  let j := firstLess (W.enc out.2.1) (W.enc m)
  W.chain pp a j (out.2.2.getD j x0) ((W.enc out.2.1).getD j 0)
    ((W.enc m).getD j 0 - (W.enc out.2.1).getD j 0)

/-- The forgery climbs onto the signed value: a preimage below it. -/
def preEv [DecidableEq X] (x0 : X) (pp : PP) (s : WotsState Tw I M X) (out : Nat × M × List X) : Bool :=
  match s.qs[out.1]? with
  | none => false
  | some (a, m, _, sig) => W.forgeY x0 pp a m out == sig.getD (firstLess (W.enc out.2.1) (W.enc m)) x0

/-- The forgery climbs onto a different value: the chains collide above it. -/
def tcrEv [DecidableEq X] (x0 : X) (pp : PP) (s : WotsState Tw I M X) (out : Nat × M × List X) : Bool :=
  match s.qs[out.1]? with
  | none => false
  | some (a, m, _, sig) => !(W.forgeY x0 pp a m out == sig.getD (firstLess (W.enc out.2.1) (W.enc m)) x0)

theorem win_split [DecidableEq X] [DecidableEq I] [DecidableEq M] (x0 : X) (c : Nat) (pp : PP)
    (s : WotsState Tw I M X) (out : Nat × M × List X) :
    (if W.win c pp s out then 1 else 0) ≤
      (if W.win c pp s out && W.tcrEv x0 pp s out then 1 else 0) +
        (if W.win c pp s out && W.preEv x0 pp s out then 1 else 0) := by
  unfold tcrEv preEv
  cases h : s.qs[out.1]? with
  | none =>
    have hw : W.win c pp s out = false := by unfold win; rw [h]
    simp [hw]
  | some e =>
    obtain ⟨a, m, pk, sig⟩ := e
    simp only
    cases W.win c pp s out <;> simp <;> split <;> omega

/-- What a winning forgery gives in Game 3. -/
theorem forge_facts [DecidableEq X] [DecidableEq I] [DecidableEq M] (x0 : X) (c : Nat) (pp : PP)
    (hlen : ∀ m, (W.enc m).length = W.len) (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1)
    (htwo : ∀ m m' : M, m ≠ m' → ∃ j, j < W.len ∧ (W.enc m').getD j 0 < (W.enc m).getD j 0)
    (s : WotsState Tw I M X) (out : Nat × M × List X) (hH : W.Honest pp c s) (hw : W.win c pp s out = true)
    (a : I) (m : M) (pk sig : List X) (he : s.qs[out.1]? = some (a, m, pk, sig))
    (j : Nat) (hj : j = firstLess (W.enc out.2.1) (W.enc m)) :
    (a, m, pk, sig) ∈ s.qs ∧ s.qs.length ≤ c ∧ j < W.len ∧
      (W.enc out.2.1).getD j 0 < (W.enc m).getD j 0 ∧ (W.enc m).getD j 0 ≤ W.w - 1 ∧
      sig.length = W.len ∧ out.2.2.length = W.len ∧
      W.chain pp a j (W.forgeY x0 pp a m out) ((W.enc m).getD j 0) (W.w - 1 - (W.enc m).getD j 0) =
        W.chain pp a j (sig.getD j x0) ((W.enc m).getD j 0) (W.w - 1 - (W.enc m).getD j 0) := by
  unfold win at hw
  rw [he] at hw
  simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true', beq_eq_false_iff_ne, ne_eq] at hw
  obtain ⟨⟨⟨⟨hc, _⟩, _⟩, hv⟩, hm⟩ := hw
  have hmem : (a, m, pk, sig) ∈ s.qs := List.mem_of_getElem? he
  have hH' := hH (a, m, pk, sig) (by rw [List.take_of_length_le hc]; exact hmem)
  obtain ⟨hpk, hsl⟩ := hH'
  simp only at hpk hsl
  unfold verify at hv
  simp only [Bool.and_eq_true, beq_iff_eq] at hv
  obtain ⟨hl', ht'⟩ := hv
  obtain ⟨j0, hj0, hlt⟩ := htwo m out.2.1 (fun h => hm h.symm)
  have hs := firstLess_spec (W.enc out.2.1) (W.enc m) j0 (by rw [hlen]; exact hj0)
    (by rw [hlen]; exact hj0) hlt
  rw [← hj] at hs
  have hjl : j < W.len := by rw [← hlen m]; exact hs.2.1
  have hd : (W.enc m).getD j 0 ≤ W.w - 1 := hdig m _ (by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hs.2.1, Option.getD_some]
    exact List.getElem_mem _)
  refine ⟨hmem, hc, hjl, hs.2.2, hd, hsl, hl', ?_⟩
  have e1 := congrArg (fun l => l.getD j x0) ht'
  rw [hpk] at e1
  simp only [tops_eq] at e1
  rw [W.topsFrom_getD pp a x0 _ _ 0 j hs.1 (by rw [hl']; exact hjl),
    W.topsFrom_getD pp a x0 _ _ 0 j hs.2.1 (by rw [hsl]; exact hjl), Nat.zero_add] at e1
  rw [← e1]
  simp only [forgeY, ← hj]
  have h2 := hs.2.2
  generalize (W.enc m).getD j 0 = D at h2 hd ⊢
  generalize (W.enc out.2.1).getD j 0 = D' at h2 hd ⊢
  rw [show W.w - 1 - D' = (D - D') + (W.w - 1 - D) by omega, chain_add, show D' + (D - D') = D by omega]

/-! ## Collisions between two chains -/

/-- The first depth at which two chains, different so far, collide. -/
def findCol [DecidableEq X] (pp : PP) (a : I) (c : Nat) : X → X → Nat → Nat → Option (Nat × X × X)
  | _, _, _, 0 => none
  | x1, x2, s, n+1 =>
    if W.f pp (W.twk a c s) x1 = W.f pp (W.twk a c s) x2 then some (s, x1, x2)
    else findCol pp a c (W.f pp (W.twk a c s) x1) (W.f pp (W.twk a c s) x2) (s+1) n

theorem findCol_spec [DecidableEq X] (pp : PP) (a : I) (c : Nat) : ∀ (n : Nat) (x1 x2 : X) (s : Nat),
    x1 ≠ x2 → W.chain pp a c x1 s n = W.chain pp a c x2 s n →
      ∃ k y1 y2, W.findCol pp a c x1 x2 s n = some (k, y1, y2) ∧ s ≤ k ∧ k < s + n ∧ y1 ≠ y2 ∧
        W.f pp (W.twk a c k) y1 = W.f pp (W.twk a c k) y2 ∧ y2 = W.chain pp a c x2 s (k - s)
  | 0, _, _, _, hne, he => absurd he hne
  | n+1, x1, x2, s, hne, he => by
    by_cases hf : W.f pp (W.twk a c s) x1 = W.f pp (W.twk a c s) x2
    · exact ⟨s, x1, x2, by simp [findCol, hf], Nat.le_refl _, by omega, hne, hf, by simp [chain]⟩
    · obtain ⟨k, y1, y2, h1, h2, h3, h4, h5, h6⟩ := findCol_spec pp a c n _ _ (s+1) hf he
      refine ⟨k, y1, y2, by simp [findCol, hf, h1], by omega, by omega, h4, h5, ?_⟩
      rw [h6, show k - s = (k - (s + 1)) + 1 by omega]
      rfl


/-! ## Shapes of challenger steps -/

theorem handler_sign_shape (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (pp : PP)
    (s : WotsState Tw I M X) (a : I) (m : M) :
    (W.handler elem pp s (.inl (a, m))).All (fun r =>
      ∃ pk sig, r.1 = .inl (pk, sig) ∧ r.2 = ⟨s.qs ++ [(a, m, pk, sig)], s.cols⟩) := by
  simp only [handler]
  exact OT.all_bind (fun _ => True) _ _ (fun r _ => by exact ⟨r.1, r.2, rfl, rfl⟩) _ (OT.all_true _)

/-- Game 3 with a final event: the run wins and `ev` holds. -/
def procEv [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (hd : WotsState Tw I M X → WotsQuery Tw I M Xc → OT Unit X (WotsAnswer X × WotsState Tw I M X))
    (c : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (ev : WotsState Tw I M X → Nat × M × List X → Bool) : OT Unit X Bool :=
  (OT.interp hd A.choose (⟨[], []⟩ : WotsState Tw I M X)).bind (fun r =>
    .done (W.win c pp r.2 (A.forge r.1 pp) && ev r.2 (A.forge r.1 pp)))

theorem procEv_within [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type}
    (elem : PP → I → Nat → Nat → OT Unit X (X × X)) (he : ∀ pp a, OneDraw (elem pp a))
    (hlen : ∀ m, (W.enc m).length = W.len) (c : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ)
    (ev : WotsState Tw I M X → Nat × M × List X → Bool) :
    (W.procEv (capH c (W.handler elem pp)) c pp A ev).Within (c * W.len) := by
  unfold procEv
  apply OT.withinP_within (fun _ _ => True)
  exact OT.withinP_bind _ _ _ (fun _ _ _ => by simp [OT.WithinP]) _ _
    (OT.withinP_interp (fun s n => W.capInv c s n) _
      (fun s q n h => W.capH_withinP elem he hlen pp c s q n h) A.choose ⟨[], []⟩ (c * W.len)
      (by simp [capInv]))

/-- Game 3's wins split into the TCR and the PRE case, ticket by ticket. -/
theorem proc_split [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X)
    (hd : WotsState Tw I M X → WotsQuery Tw I M Xc → OT Unit X (WotsAnswer X × WotsState Tw I M X))
    (c : Nat) (pp : PP) (A : WotsAdv PP Tw I M X Xc σ) (T : List X) :
    (if ((W.proc hd c pp A).run (tape1 x0) T).1 then 1 else 0) ≤
      (if ((W.procEv hd c pp A (W.tcrEv x0 pp)).run (tape1 x0) T).1 then 1 else 0) +
        (if ((W.procEv hd c pp A (W.preEv x0 pp)).run (tape1 x0) T).1 then 1 else 0) := by
  unfold proc procEv
  simp only [OT.run_bind, OT.run]
  exact W.win_split x0 c pp _ _


/-- Game 3's count of wins with event `ev`. -/
def g3EvCount [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (ev : PP → WotsState Tw I M X → Nat × M × List X → Bool) : Nat :=
  P.sum (fun pp => As.sum (fun A => (Din.tape (c * W.len)).sum (fun T =>
    if ((W.procEv (capH c (W.handler (fun pp a => W.g3Elem pp a) pp)) c pp A (ev pp)).run (tape1 x0) T).1
    then 1 else 0)))

/-- Game 3 (capped hybrid `w − 2`) splits into its TCR and PRE cases. -/
theorem hyb_split [DecidableEq X] [DecidableEq I] [DecidableEq M] {σ : Type} (x0 : X) (c : Nat)
    (P : FiniteExperiment PP) (Din : FiniteExperiment X) (As : FiniteExperiment (WotsAdv PP Tw I M X Xc σ))
    (hdig : ∀ m, ∀ d ∈ W.enc m, d ≤ W.w - 1) :
    W.hybCount x0 c P Din As (W.w - 2) ≤
      W.g3EvCount x0 c P Din As (W.tcrEv x0) + W.g3EvCount x0 c P Din As (W.preEv x0) := by
  unfold hybCount count g3EvCount
  simp only [W.handler_hyb_g3 hdig]
  rw [sum_fun_add]
  apply sum_le; intro i
  rw [sum_fun_add]
  apply sum_le; intro j
  rw [sum_fun_add]
  apply sum_le; intro k
  exact W.proc_split x0 _ c _ _ _

end WotsSetting

#print axioms getElem?_idxOf
#print axioms firstLess_spec
#print axioms WotsSetting.honest_step
#print axioms WotsSetting.forge_facts
#print axioms WotsSetting.findCol_spec
end DSM.Sphincs.Comp
