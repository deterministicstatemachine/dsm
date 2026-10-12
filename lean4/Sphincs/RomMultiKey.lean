-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomMulti
import Sphincs.RomQCost

/- Multi-key unforgeability from the single-key real bound.

   The multi-key game `mplay` lets the adversary create keys adaptively
   (`newKey`, key `j` from seed `sd j`), sign under any created key, hash, and
   finally claim a forgery against one key. For a target index `i`:

   1. `mplay_split`: the game is `X >>= (if created then Ygen >>= Z else Z')`,
      where `X = mUntil` runs until the adversary asks for key `i`; when it does
      is chosen by the adversary from everything it has seen.
   2. `reorder` (RomMulti) moves the target's key generation `Ygen` to the
      front, on all tapes except the overlap event `Ov`, bounded by `ov_count`.
   3. The reordered game is the single-key real game against the reduction
      `simB`, which simulates the other keys (key generation, signing,
      verification of a claim against another key) with its own hash queries,
      receives the target's public key when the target is created, and forwards
      the target's signing queries and forgery (`sim_target`).
   4. `real_win_256f` (C65) bounds the reduction's winning probability with its
      budget, which counts every simulated request (`budget_simB`).

   The target's seed is sampled independently of `X`: the sum over `s` ranges
   over the seed at index `i` only, and `X` reads only seeds below `i`. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! Query trees: associativity, leaves, and runs that agree up to tags. -/

theorem QT.bind_assoc {α β γ : Type} : ∀ (T : QT α) (f : α → QT β) (g : β → QT γ),
    (T.bind f).bind g = T.bind (fun a => (f a).bind g)
  | .done _, _, _ => rfl
  | .ask g0 r k, f, g => by
    simp only [QT.bind]
    congr 1; funext b; exact QT.bind_assoc (k b) f g

theorem QT.bind_done {α : Type} : ∀ (T : QT α), T.bind QT.done = T
  | .done _ => rfl
  | .ask g r k => by simp only [QT.bind]; congr 1; funext b; exact QT.bind_done (k b)

/-- Every result of `T` satisfies `Q`. -/
def Leaves {α : Type} (Q : α → Prop) : QT α → Prop
  | .done a => Q a
  | .ask _ _ k => ∀ b, Leaves Q (k b)

theorem leaves_run {α : Type} (Q : α → Prop) (t : List Nat) : ∀ (T : QT α) (D : List Draw),
    Leaves Q T → Q (run t T D).1
  | .done _, _, h => h
  | .ask g r k, D, h => by
    simp only [run]
    split
    · exact leaves_run Q t _ D (h _)
    · exact leaves_run Q t _ _ (h _)

theorem leaves_true {α : Type} : ∀ (T : QT α), Leaves (fun _ => True) T
  | .done _ => trivial
  | .ask _ _ k => fun b => leaves_true (k b)

theorem leaves_bind {α β : Type} (Q1 : α → Prop) (Q : β → Prop) : ∀ (T : QT α) (f : α → QT β),
    Leaves Q1 T → (∀ a, Q1 a → Leaves Q (f a)) → Leaves Q (T.bind f)
  | .done a, _, h, hf => hf a h
  | .ask _ _ k, f, h, hf => fun b => leaves_bind Q1 Q (k b) f (h b) hf

/-- Two query trees that ask the same requests in lockstep (tags may differ) and
    whose results are related by `R`. -/
inductive TagRel {α β : Type} (R : α → β → Prop) : QT α → QT β → Prop
  | done {a : α} {b : β} : R a b → TagRel R (.done a) (.done b)
  | ask {g g' : Bool} {r : Request} {k : Bytes → QT α} {k' : Bytes → QT β} :
      (∀ x, TagRel R (k x) (k' x)) → TagRel R (.ask g r k) (.ask g' r k')

theorem findDraw_snd : ∀ (D D' : List Draw) (r : Request), D.map Prod.snd = D'.map Prod.snd →
    findDraw D r = findDraw D' r
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp at h
  | _ :: _, [], _, h => by simp at h
  | e :: D, e' :: D', r, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    simp only [findDraw, h.1, findDraw_snd D D' r h.2]

theorem run_tagRel {α β : Type} {R : α → β → Prop} (t : List Nat) {T : QT α} {T' : QT β}
    (h : TagRel R T T') : ∀ (D D' : List Draw), D.map Prod.snd = D'.map Prod.snd →
    R (run t T D).1 (run t T' D').1 ∧ (run t T D).2.map Prod.snd = (run t T' D').2.map Prod.snd := by
  induction h with
  | done hab => intro D D' hD; exact ⟨hab, hD⟩
  | @ask g g' r k k' _ ih =>
    intro D D' hD
    have hl : D.length = D'.length := by
      have := congrArg List.length hD; simpa using this
    simp only [run]
    rw [findDraw_snd D D' r hD]
    cases findDraw D' r with
    | some i => exact ih _ D D' hD
    | none =>
      rw [hl]
      exact ih _ _ _ (by simp [hD])

theorem tagRel_refl {α : Type} : ∀ (T : QT α), TagRel Eq T T
  | .done _ => .done rfl
  | .ask _ _ k => .ask (fun x => tagRel_refl (k x))

theorem tagRel_bind {α α' β β' : Type} {R1 : α → α' → Prop} {R : β → β' → Prop} {T : QT α} {T' : QT α'}
    (h : TagRel R1 T T') {f : α → QT β} {f' : α' → QT β'} (hf : ∀ a a', R1 a a' → TagRel R (f a) (f' a')) :
    TagRel R (T.bind f) (T'.bind f') := by
  induction h with
  | done hab => exact hf _ _ hab
  | ask _ ih => exact .ask (fun x => ih x)

/-! Translating a query tree into adversary hash queries. -/

/-- Run `T` through the adversary's hash queries, then continue with `g`. -/
def qtA {α : Type} : QT α → (α → RAdv) → RAdv
  | .done a, g => g a
  | .ask _ r k, g => .hq r (fun b => qtA (k b) g)

theorem play_qtA {α β : Type} (v : Variant) (limits : Limits) (pk sk : Bytes) (signed : List Bytes)
    {R : β → Out → Prop} (Q : α → Prop) (H : α → QT β) (g : α → RAdv)
    (hg : ∀ a, Q a → TagRel R (H a) (playQT v limits pk sk (g a) signed)) :
    ∀ (T : QT α), Leaves Q T → TagRel R (T.bind H) (playQT v limits pk sk (qtA T g) signed)
  | .done a, hl => hg a hl
  | .ask _ r k, hl => by
    show TagRel R (.ask _ r (fun b => (k b).bind H)) (.ask true r (fun b => playQT v limits pk sk (qtA (k b) g) signed))
    exact .ask (fun x => play_qtA v limits pk sk signed Q H g hg (k x) (hl x))

theorem budget_mono : ∀ (B : RAdv) {qh qs qh' qs' : Nat}, Budget B qh qs → qh ≤ qh' → qs ≤ qs' → Budget B qh' qs'
  | .hq _ k, _, _, _, _, ⟨h1, h2⟩, hh, hs => ⟨by omega, fun b => budget_mono (k b) (h2 b) (by omega) hs⟩
  | .sq _ k, _, _, _, _, ⟨h1, h2⟩, hh, hs => ⟨by omega, fun o => budget_mono (k o) (h2 o) hh (by omega)⟩
  | .out _ _, _, _, _, _, _, _, _ => trivial

theorem budget_qtA {α : Type} (g : α → RAdv) (q qs : Nat) (hg : ∀ a, Budget (g a) q qs) :
    ∀ (T : QT α) (n : Nat), Cnt allR T n → Budget (qtA T g) (n + q) qs
  | .done a, n, _ => budget_mono _ (hg a) (by omega) (Nat.le_refl _)
  | .ask _ r k, n, h => by
    simp only [Cnt, allR, if_true] at h
    refine ⟨by omega, fun b => ?_⟩
    exact budget_mono _ (budget_qtA g q qs hg (k b) (n - 1) (h.2 b)) (by omega) (Nat.le_refl _)

/-! The multi-key game. -/

/-- A multi-key adversary: hash queries, key creation (answered with the new
    public key), signing queries under key `j`, and a claimed forgery against key `j`. -/
inductive MAdv where
  | hq (r : Request) (k : Bytes → MAdv)
  | newKey (k : Bytes → MAdv)
  | sq (j : Nat) (m : Bytes) (k : Option Bytes → MAdv)
  | out (j : Nat) (m s : Bytes)

structure MOut where
  key : Nat
  win : Bool

/-- At most `qh` hash queries, `qk` keys and `qs` signing queries on every path. -/
def MBudget : MAdv → Nat → Nat → Nat → Prop
  | .hq _ k, qh, qk, qs => 0 < qh ∧ ∀ b, MBudget (k b) (qh - 1) qk qs
  | .newKey k, qh, qk, qs => 0 < qk ∧ ∀ b, MBudget (k b) qh (qk - 1) qs
  | .sq _ _ k, qh, qk, qs => 0 < qs ∧ ∀ o, MBudget (k o) qh qk (qs - 1)
  | .out _ _ _, _, _, _ => True

abbrev Key := Bytes × Bytes
def kAt (keys : List Key) (j : Nat) : Key := keys.getD j ([], [])

/-- Key `i` forged. -/
def forge (i : Nat) (o : MOut) : Prop := o.key = i ∧ o.win = true

section
variable (v : Variant) (limits : Limits)

/-- The verdict on a claimed forgery `(m, s)` against key `j`. -/
def mOut (keys : List Key) (sg : List (Nat × Bytes)) (j : Nat) (m s : Bytes) : QT MOut :=
  if j < keys.length then QT.bind (verify advQ v (kAt keys j).1 m s)
    (fun ok => .done ⟨j, legal limits m && !sg.contains (j, m) && ok.getD false⟩)
  else .done ⟨j, false⟩

/-- The multi-key game: key `j` is generated from seed `sd j` when created;
    `sg` records the signed (key, message) pairs. -/
def mplay (sd : Nat → Nat) : List Key → List (Nat × Bytes) → MAdv → QT MOut
  | keys, sg, .hq r k => .ask true r (fun b => mplay sd keys sg (k b))
  | keys, sg, .newKey k => QT.bind (generateKeypair challengerOracle v (seedW (sd keys.length)))
      (fun ks => mplay sd (keys ++ [ks]) sg (k ks.1))
  | keys, sg, .sq j m k => if j < keys.length ∧ legal limits m = true then
      QT.bind (sign challengerOracle v (kAt keys j).2 m) (fun s => mplay sd keys (sg ++ [(j, m)]) (k s))
    else mplay sd keys sg (k none)
  | keys, sg, .out j m s => mOut v limits keys sg j m s

/-- The game suspended when the adversary asks for key `i`. -/
inductive Susp where
  | fin (o : MOut)
  | paused (keys : List Key) (sg : List (Nat × Bytes)) (k : Bytes → MAdv)

/-- The game until the adversary asks for key `i` (or ends without doing so). -/
def mUntil (sd : Nat → Nat) (i : Nat) : List Key → List (Nat × Bytes) → MAdv → QT Susp
  | keys, sg, .hq r k => .ask true r (fun b => mUntil sd i keys sg (k b))
  | keys, sg, .newKey k => if keys.length = i then .done (.paused keys sg k) else
      QT.bind (generateKeypair challengerOracle v (seedW (sd keys.length)))
        (fun ks => mUntil sd i (keys ++ [ks]) sg (k ks.1))
  | keys, sg, .sq j m k => if j < keys.length ∧ legal limits m = true then
      QT.bind (sign challengerOracle v (kAt keys j).2 m) (fun s => mUntil sd i keys (sg ++ [(j, m)]) (k s))
    else mUntil sd i keys sg (k none)
  | keys, sg, .out j m s => QT.bind (mOut v limits keys sg j m s) (fun o => .done (.fin o))

def created : Susp → Bool
  | .fin _ => false
  | .paused _ _ _ => true

/-- After the target `y` is created. -/
def contT (sd : Nat → Nat) : Susp → Key → QT MOut
  | .paused keys sg k, y => mplay v limits sd (keys ++ [y]) sg (k y.1)
  | .fin o, _ => .done o

def finT : Susp → QT MOut
  | .fin o => .done o
  | .paused _ _ _ => .done ⟨0, false⟩

/-- Seed `s` at index `i`. -/
def upd (sd : Nat → Nat) (i s : Nat) : Nat → Nat := fun k => if k = i then s else sd k

/-- **Split at the target's creation.** -/
theorem mplay_split (sd : Nat → Nat) (i s : Nat) : ∀ (M : MAdv) (keys : List Key) (sg : List (Nat × Bytes)),
    keys.length ≤ i →
    mplay v limits (upd sd i s) keys sg M =
      gameOrd (mUntil v limits sd i keys sg M) (Ygen v s) (contT v limits (upd sd i s)) (finT) created
  | .hq r k, keys, sg, hl => by
    simp only [mplay, mUntil, gameOrd, QT.bind]
    congr 1; funext b
    exact mplay_split sd i s (k b) keys sg hl
  | .newKey k, keys, sg, hl => by
    simp only [mplay, mUntil, gameOrd]
    by_cases he : keys.length = i
    · rw [if_pos he]
      simp only [QT.bind, created, if_true, Ygen, upd, he]
      rfl
    · rw [if_neg he, QT.bind_assoc]
      have hs : upd sd i s keys.length = sd keys.length := by simp [upd, he]
      rw [hs]
      congr 1; funext ks
      have := mplay_split sd i s (k ks.1) (keys ++ [ks]) sg (by simp; omega)
      rw [this]; rfl
  | .sq j m k, keys, sg, hl => by
    simp only [mplay, mUntil]
    split
    · rw [gameOrd, QT.bind_assoc]
      congr 1; funext o
      exact mplay_split sd i s (k o) keys _ hl
    · exact mplay_split sd i s (k none) keys sg hl
  | .out j m o, keys, sg, hl => by
    simp only [mplay, mUntil, gameOrd]
    rw [QT.bind_assoc]
    simp only [QT.bind, created, Bool.false_eq_true, if_false, finT]
    exact (QT.bind_done _).symm

/-- A claim the game accepts names a key it has created. -/
theorem leaves_mOut (keys : List Key) (sg : List (Nat × Bytes)) (j : Nat) (m s : Bytes) :
    Leaves (fun o : MOut => o.win = true → o.key < keys.length) (mOut v limits keys sg j m s) := by
  unfold mOut
  split
  · rename_i hj
    exact leaves_bind (fun _ => True) _ _ _ (leaves_true _) (fun ok _ => fun _ => hj)
  · intro h; simp at h

/-- Before the target is created, every accepted claim names an earlier key. -/
theorem leaves_mUntil (sd : Nat → Nat) (i : Nat) : ∀ (M : MAdv) (keys : List Key) (sg : List (Nat × Bytes)),
    keys.length ≤ i →
    Leaves (fun x => match x with | .fin o => o.win = true → o.key < i | .paused _ _ _ => True)
      (mUntil v limits sd i keys sg M)
  | .hq r k, keys, sg, hl => fun b => leaves_mUntil sd i (k b) keys sg hl
  | .newKey k, keys, sg, hl => by
    simp only [mUntil]
    split
    · trivial
    · exact leaves_bind (fun _ => True) _ _ _ (leaves_true _)
        (fun ks _ => leaves_mUntil sd i (k ks.1) (keys ++ [ks]) sg (by simp; omega))
  | .sq j m k, keys, sg, hl => by
    simp only [mUntil]
    split
    · exact leaves_bind (fun _ => True) _ _ _ (leaves_true _) (fun o _ => leaves_mUntil sd i (k o) keys _ hl)
    · exact leaves_mUntil sd i (k none) keys sg hl
  | .out j m o, keys, sg, hl => by
    simp only [mUntil]
    exact leaves_bind _ _ _ _ (leaves_mOut v limits keys sg j m o) (fun a ha => fun h => by have := ha h; omega)

end

/-! The reduction to the single-key game. -/

section
variable (v : Variant) (limits : Limits)

/-- The reduction against target `i` with public key `pk`: it simulates every
    other key with its own hash queries (key generation, signing, and the
    verification of a claim against another key), takes `pk` as key `i`, and
    forwards key `i`'s signing queries and a forgery against key `i`. -/
def simB (sd : Nat → Nat) (i : Nat) (pk : Bytes) : List Key → List (Nat × Bytes) → MAdv → RAdv
  | keys, sg, .hq r k => .hq r (fun b => simB sd i pk keys sg (k b))
  | keys, sg, .newKey k => if keys.length = i then simB sd i pk (keys ++ [(pk, [])]) sg (k pk) else
      qtA (generateKeypair challengerOracle v (seedW (sd keys.length)))
        (fun ks => simB sd i pk (keys ++ [ks]) sg (k ks.1))
  | keys, sg, .sq j m k => if j = i ∧ i < keys.length then
        .sq m (fun s => simB sd i pk keys (if legal limits m = true then sg ++ [(i, m)] else sg) (k s))
      else if j < keys.length ∧ legal limits m = true then
        qtA (sign challengerOracle v (kAt keys j).2 m) (fun s => simB sd i pk keys (sg ++ [(j, m)]) (k s))
      else simB sd i pk keys sg (k none)
  | keys, _, .out j m s => if j = i ∧ i < keys.length then .out m s
      else if j < keys.length then qtA (verify advQ v (kAt keys j).1 m s) (fun _ => .out [] [])
      else .out [] []

/-- Messages signed under key `i`. -/
def proj (i : Nat) (sg : List (Nat × Bytes)) : List Bytes := (sg.filter (fun e => e.1 == i)).map Prod.snd

theorem proj_contains (i : Nat) (m : Bytes) : ∀ (sg : List (Nat × Bytes)), sg.contains (i, m) = (proj i sg).contains m
  | [] => rfl
  | e :: sg => by
    obtain ⟨j, m'⟩ := e
    by_cases hj : j = i
    · subst hj
      simp only [proj, List.filter_cons, beq_self_eq_true, if_true, List.map_cons, List.contains_cons]
      rw [← proj, ← proj_contains j m sg]
      by_cases hm : m = m'
      · simp [hm]
      · rw [beq_false_of_ne (fun h => hm (Prod.mk.inj h).2), beq_false_of_ne hm]
    · have : (j == i) = false := by simp [hj]
      simp only [proj, List.filter_cons, this, Bool.false_eq_true, if_false, List.contains_cons]
      rw [← proj, ← proj_contains i m sg]
      simp [Prod.ext_iff, Ne.symm hj]

theorem proj_snoc_ne (i j : Nat) (m : Bytes) (sg : List (Nat × Bytes)) (h : j ≠ i) :
    proj i (sg ++ [(j, m)]) = proj i sg := by
  simp [proj, List.filter_append, h]

theorem proj_snoc_eq (i : Nat) (m : Bytes) (sg : List (Nat × Bytes)) : proj i (sg ++ [(i, m)]) = proj i sg ++ [m] := by
  simp [proj, List.filter_append]

theorem proj_nil (i : Nat) (sg : List (Nat × Bytes)) (h : ∀ e ∈ sg, e.1 < i) : proj i sg = [] := by
  simp only [proj, List.map_eq_nil_iff, List.filter_eq_nil_iff, beq_iff_eq]
  intro e he h'; have := h e he; omega

/-- The output relation: a forgery against key `i` is a win of the reduction. -/
def Rf (i : Nat) (o : MOut) (o' : Out) : Prop := forge i o → o'.win = true

theorem kAt_append_lt (keys : List Key) (ks : Key) (j : Nat) (h : j < keys.length) : kAt (keys ++ [ks]) j = kAt keys j := by
  simp [kAt, List.getD_eq_getElem?_getD, List.getElem?_append_left h]

theorem kAt_append_eq (keys : List Key) (ks : Key) : kAt (keys ++ [ks]) keys.length = ks := by
  simp [kAt, List.getD_eq_getElem?_getD]

theorem kAt_ge (keys : List Key) (j : Nat) (h : keys.length ≤ j) : kAt keys j = ([], []) := by
  simp [kAt, List.getD_eq_getElem?_getD, List.getElem?_eq_none h]

/-- The game's keys and the reduction's keys: equal except the target's secret key. -/
def KR (i : Nat) (pk sk : Bytes) (keys keysS : List Key) : Prop :=
  keys.length = keysS.length ∧ i < keys.length ∧ kAt keys i = (pk, sk) ∧ (kAt keysS i).1 = pk ∧
    ∀ j, j ≠ i → kAt keysS j = kAt keys j

theorem KR_snoc (i : Nat) (pk sk : Bytes) (keys keysS : List Key) (h : KR i pk sk keys keysS) (ks : Key) :
    KR i pk sk (keys ++ [ks]) (keysS ++ [ks]) := by
  obtain ⟨hl, hi, hk, hp, hj⟩ := h
  refine ⟨by simp [hl], by simp; omega, by rw [kAt_append_lt _ _ _ hi]; exact hk,
    by rw [kAt_append_lt _ _ _ (by omega)]; exact hp, fun j hj' => ?_⟩
  by_cases hlt : j < keys.length
  · rw [kAt_append_lt _ _ _ hlt, kAt_append_lt _ _ _ (by omega)]; exact hj j hj'
  · by_cases he : j = keys.length
    · subst he; rw [hl, kAt_append_eq, ← hl, kAt_append_eq]
    · rw [kAt_ge _ _ (by simp; omega), kAt_ge _ _ (by simp; omega)]

theorem play_out_nil (pk sk : Bytes) (signed : List Bytes) :
    ∃ o, playQT v limits pk sk (.out [] []) signed = .done o := by
  simp only [playQT, verify, List.isEmpty_nil, if_true]
  exact ⟨_, rfl⟩

theorem tagRel_out_nil (i : Nat) (pk sk : Bytes) (signed : List Bytes) (o : MOut) (h : ¬ forge i o) :
    TagRel (Rf i) (.done o) (playQT v limits pk sk (.out [] []) signed) := by
  obtain ⟨o', ho⟩ := play_out_nil v limits pk sk signed
  rw [ho]; exact .done (fun hf => absurd hf h)

/-- **After the target is created** the game and the reduction's single-key game
    ask the same requests, and a forgery against key `i` is a win. -/
theorem sim_after (sd : Nat → Nat) (i s : Nat) (pk sk : Bytes) :
    ∀ (M : MAdv) (keys keysS : List Key) (sg : List (Nat × Bytes)), KR i pk sk keys keysS →
    TagRel (Rf i) (mplay v limits (upd sd i s) keys sg M)
      (playQT v limits pk sk (simB v limits sd i pk keysS sg M) (proj i sg))
  | .hq r k, keys, keysS, sg, h => by
    simp only [mplay, simB, playQT]
    exact .ask (fun b => sim_after sd i s pk sk (k b) keys keysS sg h)
  | .newKey k, keys, keysS, sg, h => by
    have hne : keysS.length ≠ i := by have := h.1; have := h.2.1; omega
    simp only [mplay, simB, if_neg hne]
    have hs : upd sd i s keys.length = sd keysS.length := by
      rw [← h.1]; simp [upd]; intro h'; have := h.2.1; omega
    rw [hs, ← h.1]
    exact play_qtA v limits pk sk _ (fun _ => True) _ _
      (fun ks _ => sim_after sd i s pk sk (k ks.1) _ _ sg (KR_snoc i pk sk keys keysS h ks)) _ (leaves_true _)
  | .sq j m k, keys, keysS, sg, h => by
    obtain ⟨hl, hi, hk, hp, hj⟩ := h
    by_cases hji : j = i
    · subst hji
      simp only [simB, mplay, show j < keysS.length by omega, and_self, if_true, playQT]
      by_cases hleg : legal limits m = true
      · simp only [hleg, and_self, if_true, show j < keys.length from hi]
        rw [hk]
        refine tagRel_bind (tagRel_refl _) (fun a a' he => ?_)
        subst he
        rw [← proj_snoc_eq]
        exact sim_after sd j s pk sk (k a) keys keysS _ ⟨hl, hi, hk, hp, hj⟩
      · simp only [hleg, and_false, if_false, Bool.false_eq_true]
        exact sim_after sd j s pk sk (k none) keys keysS sg ⟨hl, hi, hk, hp, hj⟩
    · simp only [simB, mplay, ← hl, hj j hji, hji, false_and, if_false]
      split
      · rw [← proj_snoc_ne i j m sg hji]
        exact play_qtA v limits pk sk _ (fun _ => True) _ _
          (fun a _ => sim_after sd i s pk sk (k a) keys keysS _ ⟨hl, hi, hk, hp, hj⟩) _ (leaves_true _)
      · exact sim_after sd i s pk sk (k none) keys keysS sg ⟨hl, hi, hk, hp, hj⟩
  | .out j m o, keys, keysS, sg, h => by
    obtain ⟨hl, hi, hk, hp, hj⟩ := h
    by_cases hji : j = i
    · subst hji
      simp only [simB, mplay, mOut, show j < keysS.length by omega, and_self, if_true, hi, playQT, hk]
      refine tagRel_bind (tagRel_refl _) (fun a a' he => ?_)
      subst he
      refine .done (fun hf => ?_)
      have hw := hf.2
      simp only at hw ⊢
      rw [proj_contains] at hw
      exact hw
    · simp only [simB, mplay, mOut, ← hl, hj j hji, hji, false_and, if_false]
      split
      · exact play_qtA v limits pk sk _ (fun _ => True) _ _
          (fun a _ => by refine tagRel_out_nil v limits i pk sk _ _ ?_; intro hf; exact hji hf.1) _ (leaves_true _)
      · refine tagRel_out_nil v limits i pk sk _ _ ?_; intro hf; simp [forge] at hf

end

section
variable (v : Variant) (limits : Limits)

/-- **Before the target is created**, with the target key `y` already drawn
    (the reordered game), the game and the reduction's single-key game ask the
    same requests, and a forgery against key `i` is a win. -/
theorem sim_before (sd : Nat → Nat) (i s : Nat) (y : Key) :
    ∀ (M : MAdv) (keys : List Key) (sg : List (Nat × Bytes)), keys.length ≤ i → (∀ e ∈ sg, e.1 < i) →
    TagRel (Rf i)
      ((mUntil v limits sd i keys sg M).bind
        (fun x => if created x = true then contT v limits (upd sd i s) x y else finT x))
      (playQT v limits y.1 y.2 (simB v limits sd i y.1 keys sg M) [])
  | .hq r k, keys, sg, hl, hs => by
    simp only [mUntil, simB, playQT, QT.bind]
    exact .ask (fun b => sim_before sd i s y (k b) keys sg hl hs)
  | .newKey k, keys, sg, hl, hs => by
    simp only [mUntil, simB]
    by_cases he : keys.length = i
    · simp only [he, if_true, QT.bind, created, contT]
      rw [← proj_nil i sg hs]
      refine sim_after v limits sd i s y.1 y.2 (k y.1) _ _ sg ⟨by simp, by simp; omega, ?_, ?_, fun j hj => ?_⟩
      · rw [← he, kAt_append_eq]
      · rw [← he, kAt_append_eq]
      · by_cases hlt : j < keys.length
        · rw [kAt_append_lt _ _ _ hlt, kAt_append_lt _ _ _ hlt]
        · rw [kAt_ge _ _ (by simp; omega), kAt_ge _ _ (by simp; omega)]
    · simp only [he, if_false]
      rw [QT.bind_assoc]
      exact play_qtA v limits y.1 y.2 _ (fun _ => True) _ _
        (fun ks _ => sim_before sd i s y (k ks.1) (keys ++ [ks]) sg (by simp; omega) hs) _ (leaves_true _)
  | .sq j m k, keys, sg, hl, hs => by
    have hn : ¬ (j = i ∧ i < keys.length) := fun h' => by omega
    simp only [mUntil, simB, if_neg hn]
    split
    · rename_i hc
      rw [QT.bind_assoc]
      exact play_qtA v limits y.1 y.2 _ (fun _ => True) _ _
        (fun a _ => sim_before sd i s y (k a) keys _ hl (fun e he' => by
          rcases List.mem_append.mp he' with h1 | h1
          · exact hs e h1
          · simp at h1; subst h1; simp; omega)) _ (leaves_true _)
    · exact sim_before sd i s y (k none) keys sg hl hs
  | .out j m o, keys, sg, hl, hs => by
    have hn : ¬ (j = i ∧ i < keys.length) := fun h' => by omega
    simp only [mUntil, simB, if_neg hn, mOut]
    split
    · rename_i hj
      rw [QT.bind_assoc, QT.bind_assoc]
      simp only [QT.bind, created, Bool.false_eq_true, if_false, finT]
      exact play_qtA v limits y.1 y.2 _ (fun _ => True) _ _
        (fun a _ => by refine tagRel_out_nil v limits i y.1 y.2 _ _ ?_; intro hf; have h1 := hf.1; simp only at h1; omega)
        _ (leaves_true _)
    · simp only [QT.bind, created, Bool.false_eq_true, if_false, finT]
      refine tagRel_out_nil v limits i y.1 y.2 _ _ ?_; intro hf; simp [forge] at hf

/-- The reduction against target `i`: a single-key adversary. It does not depend
    on the target's seed. -/
def redB (sd : Nat → Nat) (i : Nat) (M : MAdv) : Bytes → RAdv := fun pk => simB v limits sd i pk [] [] M

/-- **The reordered game is the single-key real game against the reduction.** -/
theorem sim_target (sd : Nat → Nat) (i s : Nat) (M : MAdv) :
    TagRel (Rf i) (gameRe (mUntil v limits sd i [] [] M) (Ygen v s) (contT v limits (upd sd i s)) finT created)
      (realQT v limits (redB v limits sd i M) s) := by
  unfold gameRe realQT
  exact tagRel_bind (tagRel_refl _) (fun a a' he => by
    subst he; exact sim_before v limits sd i s a M [] [] (Nat.zero_le _) (by simp))

end

/-! Budgets: the multi-key game's requests and the reduction's queries. -/

/-- Requests of the multi-key game with `qh` hash queries, `qk` keys and `qs`
    signing queries: each key generation `kgC + 1`, each signature `signC`, and
    one verification `verC`. This is also the reduction's hash-query budget. -/
def mQ (p : Params) (qh qk qs : Nat) : Nat := qh + qk * (kgC p + 1) + qs * signC p + verC p

theorem challenger_tagO : challengerOracle = tagO false := rfl
theorem advQ_tagO : advQ = tagO true := rfl

theorem mQ_hq (p : Params) (qh qk qs : Nat) (h : 0 < qh) : mQ p (qh - 1) qk qs + 1 = mQ p qh qk qs := by
  unfold mQ; omega
theorem mQ_key (p : Params) (qh qk qs : Nat) (h : 0 < qk) : (kgC p + 1) + mQ p qh (qk - 1) qs = mQ p qh qk qs := by
  obtain ⟨q, rfl⟩ : ∃ q, qk = q + 1 := ⟨qk - 1, by omega⟩
  unfold mQ; rw [Nat.add_sub_cancel, Nat.succ_mul]; omega
theorem mQ_sig (p : Params) (qh qk qs : Nat) (h : 0 < qs) : signC p + mQ p qh qk (qs - 1) = mQ p qh qk qs := by
  obtain ⟨q, rfl⟩ : ∃ q, qs = q + 1 := ⟨qs - 1, by omega⟩
  unfold mQ; rw [Nat.add_sub_cancel, Nat.succ_mul]; omega
theorem mQ_mono (p : Params) {qh qk qs qh' qk' qs' : Nat} (h1 : qh ≤ qh') (h2 : qk ≤ qk') (h3 : qs ≤ qs') :
    mQ p qh qk qs ≤ mQ p qh' qk' qs' := by
  unfold mQ
  have := Nat.mul_le_mul_right (kgC p + 1) h2
  have := Nat.mul_le_mul_right (signC p) h3
  omega
theorem verC_le_mQ (p : Params) (qh qk qs : Nat) : verC p ≤ mQ p qh qk qs := by unfold mQ; omega

section
variable (v : Variant) (limits : Limits)

theorem cnt_mOut (keys : List Key) (sg : List (Nat × Bytes)) (j : Nat) (m s : Bytes) :
    Cnt allR (mOut v limits keys sg j m s) (verC (params v)) := by
  unfold mOut
  split
  · rw [advQ_tagO]; exact Cnt.bindm (a_verify true v _ _ _) (fun _ => Cnt.pure _) (by omega)
  · exact Cnt.pureN _ _

/-- The game before the target is created asks at most `mQ` requests. -/
theorem cnt_mUntil (sd : Nat → Nat) (i : Nat) : ∀ (M : MAdv) (qh qk qs : Nat), MBudget M qh qk qs →
    ∀ (keys : List Key) (sg : List (Nat × Bytes)), Cnt allR (mUntil v limits sd i keys sg M) (mQ (params v) qh qk qs)
  | .hq r k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [mUntil, Cnt, allR, if_true]
    refine ⟨by unfold mQ; omega, fun b => Cnt.mono (cnt_mUntil sd i (k b) _ _ _ (h2 b) keys sg) ?_⟩
    have := mQ_hq (params v) qh qk qs h1; omega
  | .newKey k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [mUntil]
    split
    · exact Cnt.pureN _ _
    · rw [challenger_tagO]
      exact Cnt.bindm (a_keygen false v _) (fun ks => cnt_mUntil sd i (k ks.1) _ _ _ (h2 _) _ sg)
        (Nat.le_of_eq (mQ_key (params v) qh qk qs h1))
  | .sq j m k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [mUntil]
    split
    · rw [challenger_tagO]
      exact Cnt.bindm (a_sign false v _ _) (fun o => cnt_mUntil sd i (k o) _ _ _ (h2 o) keys _)
        (Nat.le_of_eq (mQ_sig (params v) qh qk qs h1))
    · exact Cnt.mono (cnt_mUntil sd i (k none) _ _ _ (h2 none) keys sg) (mQ_mono _ (Nat.le_refl _) (Nat.le_refl _) (by omega))
  | .out j m o, qh, qk, qs, _, keys, sg => by
    simp only [mUntil]
    exact Cnt.bindm (cnt_mOut v limits keys sg j m o) (fun _ => Cnt.pure _) (by have := verC_le_mQ (params v) qh qk qs; omega)

/-- The reduction asks at most `mQ` hash queries and `qs` signing queries. -/
theorem budget_simB (sd : Nat → Nat) (i : Nat) (pk : Bytes) : ∀ (M : MAdv) (qh qk qs : Nat), MBudget M qh qk qs →
    ∀ (keys : List Key) (sg : List (Nat × Bytes)), Budget (simB v limits sd i pk keys sg M) (mQ (params v) qh qk qs) qs
  | .hq r k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [simB, Budget]
    refine ⟨by unfold mQ; omega, fun b => budget_mono _ (budget_simB sd i pk (k b) _ _ _ (h2 b) keys sg) ?_ (Nat.le_refl _)⟩
    have := mQ_hq (params v) qh qk qs h1; omega
  | .newKey k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [simB]
    split
    · exact budget_mono _ (budget_simB sd i pk (k pk) _ _ _ (h2 pk) _ sg)
        (mQ_mono _ (Nat.le_refl _) (by omega) (Nat.le_refl _)) (Nat.le_refl _)
    · rw [challenger_tagO]
      refine budget_mono _ (budget_qtA _ _ _ (fun ks => budget_simB sd i pk (k ks.1) _ _ _ (h2 _) _ sg) _ _
        (a_keygen false v _)) (Nat.le_of_eq (mQ_key (params v) qh qk qs h1)) (Nat.le_refl _)
  | .sq j m k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [simB]
    split
    · exact ⟨h1, fun o => budget_mono _ (budget_simB sd i pk (k o) _ _ _ (h2 o) keys _)
        (mQ_mono _ (Nat.le_refl _) (Nat.le_refl _) (by omega)) (Nat.le_refl _)⟩
    · split
      · rw [challenger_tagO]
        exact budget_mono _ (budget_qtA _ _ _ (fun o => budget_simB sd i pk (k o) _ _ _ (h2 o) keys _) _ _
          (a_sign false v _ _)) (Nat.le_of_eq (mQ_sig (params v) qh qk qs h1)) (by omega)
      · exact budget_mono _ (budget_simB sd i pk (k none) _ _ _ (h2 none) keys sg)
          (mQ_mono _ (Nat.le_refl _) (Nat.le_refl _) (by omega)) (by omega)
  | .out j m o, qh, qk, qs, _, keys, sg => by
    simp only [simB]
    split
    · trivial
    · split
      · rw [advQ_tagO]
        exact budget_mono _ (budget_qtA (fun _ => RAdv.out [] []) 0 qs (fun _ => trivial) _ _ (a_verify true v _ _ _))
          (by have := verC_le_mQ (params v) qh qk qs; omega) (Nat.le_refl _)
      · trivial

end

/-! The bound for one target key. -/

section
variable (limits : Limits)

theorem filter_allR (l : List Draw) : l.filter (fun e => allR e.2) = l := by
  induction l with
  | nil => rfl
  | cons e l ih => rw [List.filter_cons]; exact congrArg (e :: ·) ih

theorem draws_le {α : Type} (T : QT α) (n : Nat) (h : Cnt allR T n) (t : List Nat) : (run t T []).2.length ≤ n := by
  have := run_cnt allR t T [] n h
  rw [filter_allR, filter_allR] at this
  simpa using this

theorem n256f : (params .spx256f).n = 32 := rfl

/-- **One target, SPX256f.** Against a multi-key adversary with `qh` hash
    queries, `qk` keys and `qs` signing queries, the probability that it forges
    under key `i` — averaged over key `i`'s seed, for any seeds of the other
    keys — is at most `(22 Q + 368023)/2^256` (the single-key bound C65 at the
    reduction's budget `Q = mQ`) plus `5 Q / 2^256` (the overlap bound, with
    `Q` bounding the requests before the target is created):

        Σ_s Pr_t[forge_i] ≤ 256^32 · (27 Q + 368023) / 2^256,

    `Q = qh + 17186·qk + 1704961·qs + 17523` (`mQ` at SPX256f). -/
theorem forge_target_256f (M : MAdv) (qh qk qs : Nat) (hM : MBudget M qh qk qs) (hqs : qs ≤ 2^64)
    (c : Nat) (hc : 0 < c) (sd : Nat → Nat) (i : Nat) :
    ((List.range (256^32)).map (fun s =>
        tsum (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)
          ((mQ (params .spx256f) qh qk qs + 1704962 * qs + 398862) + 1)
          (fun t => ind (forge i (run t (mplay .spx256f limits (upd sd i s) [] [] M) []).1)))).sum ≤
      (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m) ^
          ((mQ (params .spx256f) qh qk qs + 1704962 * qs + 398862) + 1) *
        (27 * mQ (params .spx256f) qh qk qs + 368023) := by
  have hR : 256^(3*(params .spx256f).n) ∣ c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m :=
    Nat.dvd_mul_right_of_dvd (Nat.dvd_mul_left _ c) _
  have hR32 : 256^32 ∣ c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m :=
    Nat.dvd_trans (Nat.pow_dvd_pow 256 (by rw [n256f]; omega)) hR
  have hRpos : 0 < c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m :=
    Nat.mul_pos (Nat.mul_pos hc (Nat.pow_pos (by decide))) (Nat.pow_pos (by decide))
  have h0 := real_win_256f limits (redB .spx256f limits sd i M) c (mQ (params .spx256f) qh qk qs) qs hc hqs
    (fun pk => budget_simB .spx256f limits sd i pk M qh qk qs hM [] [])
  generalize hRdef : c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m = R at hR hR32 hRpos h0 ⊢
  generalize hQ : mQ (params .spx256f) qh qk qs = Q at h0 ⊢
  have hkg : kgC (params .spx256f) + 1 = 17186 := by decide
  have hQk : Q + 17186 ≤ Q + 1704962 * qs + 398862 + 1 := by omega
  -- the part before the target, independent of the target's seed
  let X := mUntil .spx256f limits sd i [] [] M
  have hA : ∀ t, aX X t ≤ Q := fun t => by
    rw [← hQ]; exact draws_le _ _ (cnt_mUntil .spx256f limits sd i M qh qk qs hM [] []) t
  have hB : ∀ s t, bY (Ygen .spx256f s) t ≤ 17186 := fun s t => by
    rw [← hkg]; exact draws_le _ _ (a_keygen false .spx256f _) t
  -- per seed: forge ≤ reduction wins + overlap
  have hs : ∀ s, tsum R ((Q + 1704962 * qs + 398862) + 1)
        (fun t => ind (forge i (run t (mplay .spx256f limits (upd sd i s) [] [] M) []).1)) ≤
      tsum R ((Q + 1704962 * qs + 398862) + 1) (fun u => ind ((runR .spx256f limits (redB .spx256f limits sd i M) s u).1.win = true)) +
      tsum R ((Q + 1704962 * qs + 398862) + 1) (fun t => ind (Ov X (Ygen .spx256f s) t)) := by
    intro s
    have hsplit := mplay_split .spx256f limits sd i s M [] [] (Nat.zero_le _)
    have hre := reorder X (Ygen .spx256f s) (contT .spx256f limits (upd sd i s)) finT created Q 17186 hA (hB s)
      R _ hQk (forge i)
    refine Nat.le_trans (tsum_mono R _ (fun t => ?_)) (Nat.le_trans hre (Nat.add_le_add_right
      (tsum_mono R _ (fun t => ?_)) _))
    · -- a forgery against key `i` means the target was created
      rw [hsplit]
      by_cases hf : forge i (run t (gameOrd X (Ygen .spx256f s) (contT .spx256f limits (upd sd i s)) finT created) []).1
      · rw [ind_of hf]
        refine Nat.le_of_eq (ind_of ⟨?_, hf⟩).symm
        cases hx : (run t X []).1 with
        | paused _ _ _ => rfl
        | fin o =>
          exfalso
          have hl := leaves_run _ t X [] (leaves_mUntil .spx256f limits sd i M [] [] (Nat.zero_le _))
          rw [hx] at hl
          unfold gameOrd at hf
          rw [run_bind, hx] at hf
          simp only [created, Bool.false_eq_true, if_false, finT, run] at hf
          have := hl hf.2; rw [hf.1] at this; omega
      · rw [ind_of_not hf]; exact Nat.zero_le _
    · -- the reordered game is the reduction's single-key game
      have := (run_tagRel t (sim_target .spx256f limits sd i s M) [] [] rfl).1
      by_cases hf : forge i (run t (gameRe X (Ygen .spx256f s) (contT .spx256f limits (upd sd i s)) finT created) []).1
      · rw [ind_of hf]; simp only [runR]; rw [ind_of (this hf)]; exact Nat.le_refl 1
      · rw [ind_of_not hf]; exact Nat.zero_le _
  -- sum over the target's seed
  have hsum := sum_map_le (List.range (256^32)) (fun s _ => hs s)
  rw [sum_map_add] at hsum
  -- the reduction: C65
  have hW : ((List.range (256^32)).map (fun s => tsum R ((Q + 1704962 * qs + 398862) + 1)
      (fun u => ind ((runR .spx256f limits (redB .spx256f limits sd i M) s u).1.win = true)))).sum ≤
      R ^ ((Q + 1704962 * qs + 398862) + 1) * (22 * Q + 368023) := by
    generalize ((List.range (256^32)).map (fun s => tsum R ((Q + 1704962 * qs + 398862) + 1)
      (fun u => ind ((runR .spx256f limits (redB .spx256f limits sd i M) s u).1.win = true)))).sum = W at h0 ⊢
    generalize Q + 1704962 * qs + 398862 = K at h0 ⊢
    have e : R ^ (K + 3) = R ^ (K + 1) * (R * R) := by rw [show K + 3 = (K + 1) + 2 by omega, Nat.pow_add, Nat.pow_two]
    rw [e] at h0
    have hpos : 0 < R * R * 256^32 := Nat.mul_pos (Nat.mul_pos hRpos hRpos) (Nat.pow_pos (by decide))
    refine Nat.le_of_mul_le_mul_right ?_ hpos
    calc W * (R * R * 256^32) = W * (R * R) * 256^32 := by ac_rfl
      _ ≤ 256^32 * (R ^ (K + 1) * (R * R)) * (22 * Q + 368023) := h0
      _ = R ^ (K + 1) * (22 * Q + 368023) * (R * R * 256^32) := by ac_rfl
  -- the overlap
  have hO := ov_count X .spx256f Q ((Q + 1704962 * qs + 398862) + 1) R hA (by omega) hR hR32
  rw [n256f] at hO
  have hO' : ((List.range (256^32)).map (fun s => tsum R ((Q + 1704962 * qs + 398862) + 1)
      (fun t => ind (Ov X (Ygen .spx256f s) t)))).sum ≤ R ^ ((Q + 1704962 * qs + 398862) + 1) * Q * 5 := by
    refine Nat.le_of_mul_le_mul_right (c := 256^32) ?_ (Nat.pow_pos (by decide))
    refine Nat.le_trans hO (Nat.le_of_eq ?_)
    rw [show 3 * 256^32 + 2 * 256^32 = 5 * 256^32 by omega, Nat.mul_assoc (R ^ _ * Q) 5]
  calc _ ≤ _ := hsum
    _ ≤ R ^ ((Q + 1704962 * qs + 398862) + 1) * (22 * Q + 368023) + R ^ ((Q + 1704962 * qs + 398862) + 1) * Q * 5 :=
        Nat.add_le_add hW hO'
    _ = R ^ ((Q + 1704962 * qs + 398862) + 1) * (27 * Q + 368023) := by
        rw [Nat.mul_assoc, ← Nat.mul_add]; congr 1; omega

end

/-! All keys. -/

/-- Averaging over one coordinate: if, for every setting of the other
    coordinates, the sum over coordinate `c` is at most `C`, the total over all
    `M^L` vectors is at most `M^(L-1) · C`. -/
theorem coord_avg (M C : Nat) : ∀ (c L : Nat), c < L → ∀ (G : List Nat → Nat),
    (∀ ss : List Nat, c < ss.length → ((List.range M).map (fun y => G (ss.set c y))).sum ≤ C) →
    tsum M L G * M ≤ M^L * C
  | _, 0, h, _, _ => absurd h (Nat.not_lt_zero _)
  | 0, L+1, _, G, hG => by
    simp only [tsum]
    rw [← tsum_list M L (List.range M) (fun y t => G (y :: t))]
    have : tsum M L (fun t => ((List.range M).map (fun y => G (y :: t))).sum) ≤ tsum M L (fun _ => C) :=
      tsum_mono M L (fun t => by
        have := hG (0 :: t) (by simp)
        simpa only [set_cons_zero] using this)
    rw [tsum_const] at this
    rw [Nat.pow_succ]
    calc _ ≤ M^L * C * M := Nat.mul_le_mul_right _ this
      _ = M^L * M * C := by ac_rfl
  | c+1, L+1, h, G, hG => by
    simp only [tsum]
    rw [Nat.mul_comm, ← sum_map_mul]
    calc _ ≤ ((List.range M).map (fun _ => M^L * C)).sum := sum_map_le _ (fun y _ => by
          rw [Nat.mul_comm]
          exact coord_avg M C c L (by omega) (fun t => G (y :: t)) (fun ss hs => by
            have := hG (y :: ss) (by simp; omega)
            simpa only [set_cons_succ] using this))
      _ = M^(L+1) * C := by rw [sum_map_const, List.length_range, Nat.pow_succ]; ac_rfl

theorem leaves_mono {α : Type} (Q Q' : α → Prop) : ∀ (T : QT α), Leaves Q T → (∀ a, Q a → Q' a) → Leaves Q' T
  | .done a, h, hq => hq a h
  | .ask _ _ k, h, hq => fun b => leaves_mono Q Q' (k b) (h b) hq

section
variable (v : Variant) (limits : Limits)

/-- Every accepted claim names one of the at most `qk` keys created. -/
theorem leaves_mplay (sd : Nat → Nat) : ∀ (M : MAdv) (qh qk qs : Nat), MBudget M qh qk qs →
    ∀ (keys : List Key) (sg : List (Nat × Bytes)),
    Leaves (fun o : MOut => o.win = true → o.key < keys.length + qk) (mplay v limits sd keys sg M)
  | .hq r k, qh, qk, qs, ⟨_, h2⟩, keys, sg => fun b => leaves_mplay sd (k b) _ _ _ (h2 b) keys sg
  | .newKey k, qh, qk, qs, ⟨h1, h2⟩, keys, sg => by
    simp only [mplay]
    exact leaves_bind (fun _ => True) _ _ _ (leaves_true _) (fun ks _ =>
      leaves_mono _ _ _ (leaves_mplay sd (k ks.1) _ _ _ (h2 _) (keys ++ [ks]) sg)
        (fun o h hw => by have := h hw; simp at this; omega))
  | .sq j m k, qh, qk, qs, ⟨_, h2⟩, keys, sg => by
    simp only [mplay]
    split
    · exact leaves_bind (fun _ => True) _ _ _ (leaves_true _) (fun o _ => leaves_mplay sd (k o) _ _ _ (h2 o) keys _)
    · exact leaves_mplay sd (k none) _ _ _ (h2 none) keys sg
  | .out j m o, _, _, _, _, keys, sg => by
    simp only [mplay]
    exact leaves_mono _ _ _ (leaves_mOut v limits keys sg j m o) (fun a ha hw => by have := ha hw; omega)

end

/-- Seeds of the keys, as a vector. -/
def sdOf (ss : List Nat) : Nat → Nat := fun k => ss.getD k 0

theorem sdOf_set (ss : List Nat) (i y : Nat) (h : i < ss.length) : sdOf (ss.set i y) = upd (sdOf ss) i y := by
  funext k
  simp only [sdOf, upd]
  by_cases hk : k = i
  · subst hk; rw [if_pos rfl]; simp [List.getD_eq_getElem?_getD, h]
  · rw [if_neg hk, getD_set_ne ss i k y hk]

theorem win_le_forge (qk : Nat) (o : MOut) (h : o.win = true → o.key < qk) :
    ind (o.win = true) ≤ ((List.range qk).map (fun i => ind (forge i o))).sum := by
  by_cases hw : o.win = true
  · rw [ind_of hw]
    have hi : o.key ∈ List.range qk := List.mem_range.mpr (h hw)
    have := le_sum_of_mem (List.mem_map.mpr ⟨o.key, hi, rfl⟩ : ind (forge o.key o) ∈ (List.range qk).map (fun i => ind (forge i o)))
    rw [ind_of ⟨rfl, hw⟩] at this; exact this
  · rw [ind_of_not hw]; exact Nat.zero_le _

/-- **All keys, SPX256f.** An adversary with `qh` hash queries, at most `qk`
    keys created adaptively from independent uniform seeds, and `qs` signing
    queries forges under some key with probability at most

        qk · (27 Q + 368023) / 2^256,   Q = qh + 17186·qk + 1704961·qs + 17523.

    Normalized: the seed vectors range over `(256^32)^qk`, the tapes over `R^N`. -/
theorem forge_any_256f (limits : Limits) (M : MAdv) (qh qk qs : Nat) (hM : MBudget M qh qk qs) (hqs : qs ≤ 2^64)
    (c : Nat) (hc : 0 < c) :
    tsum (256^32) qk (fun ss =>
        tsum (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)
          ((mQ (params .spx256f) qh qk qs + 1704962 * qs + 398862) + 1)
          (fun t => ind ((run t (mplay .spx256f limits (sdOf ss) [] [] M) []).1.win = true))) * 256^32 ≤
      (256^32)^qk * ((c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m) ^
          ((mQ (params .spx256f) qh qk qs + 1704962 * qs + 398862) + 1) *
        (qk * (27 * mQ (params .spx256f) qh qk qs + 368023))) := by
  generalize hRdef : c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m = R
  generalize hN : (mQ (params .spx256f) qh qk qs + 1704962 * qs + 398862) + 1 = N
  generalize hC : R ^ N * (27 * mQ (params .spx256f) qh qk qs + 368023) = C
  have h1 : ∀ ss : List Nat, tsum R N (fun t => ind ((run t (mplay .spx256f limits (sdOf ss) [] [] M) []).1.win = true)) ≤
      ((List.range qk).map (fun i => tsum R N (fun t => ind (forge i (run t (mplay .spx256f limits (sdOf ss) [] [] M) []).1)))).sum := by
    intro ss
    rw [← tsum_list]
    exact tsum_mono R N (fun t => win_le_forge qk _ (fun hw => by
      have := leaves_run _ t _ [] (leaves_mplay .spx256f limits (sdOf ss) M qh qk qs hM [] []) hw
      simpa using this))
  calc _ ≤ tsum (256^32) qk (fun ss => ((List.range qk).map (fun i =>
          tsum R N (fun t => ind (forge i (run t (mplay .spx256f limits (sdOf ss) [] [] M) []).1)))).sum) * 256^32 :=
        Nat.mul_le_mul_right _ (tsum_mono _ _ h1)
    _ = ((List.range qk).map (fun i => tsum (256^32) qk (fun ss =>
          tsum R N (fun t => ind (forge i (run t (mplay .spx256f limits (sdOf ss) [] [] M) []).1))) * 256^32)).sum := by
        rw [tsum_list, Nat.mul_comm, ← sum_map_mul]
        congr 1; apply List.map_congr_left; intro i _; rw [Nat.mul_comm]
    _ ≤ ((List.range qk).map (fun _ => (256^32)^qk * C)).sum := sum_map_le _ (fun i hi => by
        refine coord_avg (256^32) C i qk (List.mem_range.mp hi) _ (fun ss hs => ?_)
        have := forge_target_256f limits M qh qk qs hM hqs c hc (sdOf ss) i
        rw [hRdef, hN, hC] at this
        refine Nat.le_trans (Nat.le_of_eq ?_) this
        apply congrArg List.sum; apply List.map_congr_left; intro y _
        rw [sdOf_set ss i y hs])
    _ = (256^32)^qk * (R ^ N * (qk * (27 * mQ (params .spx256f) qh qk qs + 368023))) := by
        rw [sum_map_const, List.length_range, ← hC]
        rw [Nat.mul_left_comm (R ^ N) qk, Nat.mul_left_comm ((256^32)^qk) qk]

end DSM.Rom
