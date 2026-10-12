-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomMultiKey
import Sphincs.WrapperInjective
import Sphincs.Blake3

/- DSM's per-step seed derivation, and the PRF hybrid.

   DSM derives the seed of the per-step SPHINCS+ key as

       E = keyed-BLAKE3(Smaster, "DSM/ek/v1\0" ‖ alg_id ‖ chain_id ‖ h_n ‖ C_pre ‖ k_step)

   (`derive_ephemeral_seed`, `ekSeedInput`). This file

   1. proves the derivation input injective in the context, and separated
      from the other Smaster-keyed derivation (`DSM/kyber-coins/v1`);
   2. defines the derivation as an oracle of a game (`FQT`: query trees that
      also ask the derivation function), answered by a fixed function
      (`resF`, the real world: keyed BLAKE3 under Smaster) or by a lazily
      sampled random function (`resL`, the ideal world);
   3. proves that a lazily sampled random function on two disjoint domains is
      two independent lazily sampled random functions (`split_rf`);
   4. defines the DSM game (`dplay`): per-step keys for contexts the adversary
      chooses adaptively, a repeated context returning the existing key, the
      other Smaster-keyed derivations revealed in full, and an auxiliary
      `aux K` of Smaster (the ML-KEM public key DSM derives from it);
   5. proves the ideal DSM game is the multi-key game of C66 (`dsim`), so
      `Pr_ideal <= qn·(27 Q + 368023)/2^256` (`dsm_ideal_256f`), and with the
      real derivation `Pr_real <= Adv + qn·(27 Q + 368023)/2^256`, `Adv` the
      PRF advantage (with auxiliary input `aux`) of the game as a distinguisher
      (`dsm_forge_256f`). -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! The derivation input. -/

/-- The prefix `"DSM/ek/v1" ‖ 0x00` of every per-step derivation input. -/
def ekPrefix : Bytes := "DSM/ek/v1".toUTF8.toList ++ [0]

theorem ekPrefix_length : ekPrefix.length = 10 := by unfold ekPrefix; rw [toUTF8_toList]; decide

theorem ekSeedInput_eq (alg : Bytes) (c t p s : Wire 32) :
    ekSeedInput alg c t p s = ekPrefix ++ (alg ++ (c.val ++ (t.val ++ (p.val ++ s.val)))) := by
  simp [ekSeedInput, domainInput, ekPrefix, List.append_assoc]

/-- **Context injectivity.** Distinct contexts give distinct derivation inputs,
    for any algorithm identifiers: the four context fields have 32 bytes each,
    so the total length fixes the identifier's length. -/
theorem ekSeedInput_inj (alg alg' : Bytes) (c t p s c' t' p' s' : Wire 32)
    (h : ekSeedInput alg c t p s = ekSeedInput alg' c' t' p' s') :
    alg = alg' ∧ c = c' ∧ t = t' ∧ p = p' ∧ s = s' := by
  rw [ekSeedInput_eq, ekSeedInput_eq] at h
  have hb := List.append_cancel_left h
  have hl := congrArg List.length hb
  simp only [List.length_append, c.property, t.property, p.property, s.property,
    c'.property, t'.property, p'.property, s'.property] at hl
  obtain ⟨ha, hb2⟩ := List.append_inj hb (by omega)
  obtain ⟨hc, hb3⟩ := fixed_head_binding c c' _ _ hb2
  obtain ⟨ht, hb4⟩ := fixed_head_binding t t' _ _ hb3
  obtain ⟨hp, hs⟩ := fixed_pair_binding p p' s s' hb4
  exact ⟨ha, hc, ht, hp, hs⟩

/-- The ML-KEM coins derivation input, also keyed by Smaster. -/
def coinsInput (kalg : Bytes) (rh tip pre dev : Wire 32) : Bytes :=
  domainInput "DSM/kyber-coins/v1" (kalg ++ rh.val ++ tip.val ++ pre.val ++ dev.val)

/-- The derivation domain: inputs starting with `"DSM/ek/v1" ‖ 0x00`. -/
def ekDom (x : Bytes) : Bool := x.take 10 == ekPrefix

theorem ekDom_seed (alg : Bytes) (c t p s : Wire 32) : ekDom (ekSeedInput alg c t p s) = true := by
  rw [ekSeedInput_eq, ekDom, List.take_append_of_le_length (by rw [ekPrefix_length]; omega),
    List.take_of_length_le (by rw [ekPrefix_length]; omega)]
  simp

/-- **Domain separation.** No coins input is a per-step derivation input. -/
theorem ekDom_coins (kalg : Bytes) (rh tip pre dev : Wire 32) : ekDom (coinsInput kalg rh tip pre dev) = false := by
  unfold ekDom coinsInput domainInput ekPrefix
  rw [toUTF8_toList, toUTF8_toList, List.append_assoc, List.take_append_of_le_length (by decide)]
  decide

/-! Query trees that also ask the derivation function. -/

/-- A query tree with random-oracle requests (`ask`) and derivation requests (`fq`). -/
inductive FQT (α : Type) where
  | done (a : α)
  | ask (g : Bool) (r : Request) (k : Bytes → FQT α)
  | fq (x : Bytes) (k : Bytes → FQT α)

def FQT.bind {α β : Type} : FQT α → (α → FQT β) → FQT β
  | .done a, f => f a
  | .ask g r k, f => .ask g r (fun b => FQT.bind (k b) f)
  | .fq x k, f => .fq x (fun y => FQT.bind (k y) f)

/-- A random-oracle query tree, with no derivation requests. -/
def liftQ {α : Type} : QT α → FQT α
  | .done a => .done a
  | .ask g r k => .ask g r (fun b => liftQ (k b))

/-- The real world: derivation requests answered by a fixed function `F`. -/
def resF {α : Type} (F : Bytes → Bytes) : FQT α → QT α
  | .done a => .done a
  | .ask g r k => .ask g r (fun b => resF F (k b))
  | .fq x k => resF F (k (F x))

/-- A derivation table. -/
abbrev RTab := List (Bytes × Bytes)

def rlook : RTab → Bytes → Option Bytes
  | [], _ => none
  | (a, b) :: t, x => if a = x then some b else rlook t x

theorem rlook_snoc (x y z : Bytes) : ∀ (tab : RTab),
    rlook (tab ++ [(x, y)]) z = match rlook tab z with | some v => some v | none => if x = z then some y else none
  | [] => by simp [rlook]
  | (a, b) :: t => by
    simp only [List.cons_append, rlook]
    split
    · rfl
    · exact rlook_snoc x y z t

/-- The ideal world: a lazily sampled random function. A fresh input takes the
    next entry `y` of the vector, as `be 32 y`. -/
def resL {α : Type} : RTab → List Nat → FQT α → QT α
  | _, _, .done a => .done a
  | tab, ss, .ask g r k => .ask g r (fun b => resL tab ss (k b))
  | tab, ss, .fq x k => match rlook tab x with
    | some y => resL tab ss (k y)
    | none => resL (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail (k (be 32 (ss.headD 0)))

/-- Two independent lazily sampled random functions, on `dom` and off it. -/
def resL2 {α : Type} (dom : Bytes → Bool) : RTab → List Nat → RTab → List Nat → FQT α → QT α
  | _, _, _, _, .done a => .done a
  | t1, s1, t2, s2, .ask g r k => .ask g r (fun b => resL2 dom t1 s1 t2 s2 (k b))
  | t1, s1, t2, s2, .fq x k =>
    if dom x then
      match rlook t1 x with
      | some y => resL2 dom t1 s1 t2 s2 (k y)
      | none => resL2 dom (t1 ++ [(x, be 32 (s1.headD 0))]) s1.tail t2 s2 (k (be 32 (s1.headD 0)))
    else
      match rlook t2 x with
      | some y => resL2 dom t1 s1 t2 s2 (k y)
      | none => resL2 dom t1 s1 (t2 ++ [(x, be 32 (s2.headD 0))]) s2.tail (k (be 32 (s2.headD 0)))

/-- At most `n1` derivation requests on `dom` and `n2` off it, on every path. -/
def FC {α : Type} (dom : Bytes → Bool) : FQT α → Nat → Nat → Prop
  | .done _, _, _ => True
  | .ask _ _ k, n1, n2 => ∀ b, FC dom (k b) n1 n2
  | .fq x k, n1, n2 => if dom x then 0 < n1 ∧ ∀ y, FC dom (k y) (n1 - 1) n2 else 0 < n2 ∧ ∀ y, FC dom (k y) n1 (n2 - 1)

theorem FC.mono {α : Type} (dom : Bytes → Bool) : ∀ (T : FQT α) {n1 n2 n1' n2' : Nat}, FC dom T n1 n2 →
    n1 ≤ n1' → n2 ≤ n2' → FC dom T n1' n2'
  | .done _, _, _, _, _, _, _, _ => trivial
  | .ask _ _ k, _, _, _, _, h, h1, h2 => fun b => FC.mono dom (k b) (h b) h1 h2
  | .fq x k, _, _, _, _, h, h1, h2 => by
    simp only [FC] at h ⊢
    split
    · rename_i hd; rw [if_pos hd] at h
      exact ⟨by omega, fun y => FC.mono dom (k y) (h.2 y) (by omega) h2⟩
    · rename_i hd; rw [if_neg hd] at h
      exact ⟨by omega, fun y => FC.mono dom (k y) (h.2 y) h1 (by omega)⟩

/-- The single table agrees with the two tables, each on its domain. -/
def TabInv (dom : Bytes → Bool) (tab t1 t2 : RTab) : Prop :=
  ∀ z, rlook tab z = if dom z then rlook t1 z else rlook t2 z

theorem tabInv_snoc1 (dom : Bytes → Bool) (tab t1 t2 : RTab) (h : TabInv dom tab t1 t2) (x y : Bytes) (hx : dom x = true) :
    TabInv dom (tab ++ [(x, y)]) (t1 ++ [(x, y)]) t2 := by
  intro z
  rw [rlook_snoc, rlook_snoc, h z]
  by_cases hz : dom z = true
  · simp only [hz, if_true]
  · have : x ≠ z := fun e => hz (e ▸ hx)
    simp only [hz, Bool.false_eq_true, if_false, this]
    cases rlook t2 z <;> rfl

theorem tabInv_snoc2 (dom : Bytes → Bool) (tab t1 t2 : RTab) (h : TabInv dom tab t1 t2) (x y : Bytes) (hx : dom x = false) :
    TabInv dom (tab ++ [(x, y)]) t1 (t2 ++ [(x, y)]) := by
  intro z
  rw [rlook_snoc, rlook_snoc, h z]
  by_cases hz : dom z = true
  · have : x ≠ z := fun e => by rw [e, hz] at hx; exact absurd hx (by simp)
    simp only [hz, if_true, this]
    cases rlook t1 z <;> rfl
  · simp only [hz, Bool.false_eq_true, if_false]

/-- **Splitting a lazily sampled random function.** On a fixed oracle tape, the
    sum over one vector of `n1 + n2` entries equals the sum over two vectors of
    `n1` and `n2` entries answering the two domains separately. -/
theorem split_rf (dom : Bytes → Bool) (M : Nat) (t : List Nat) {α : Type} (G : α × List Draw → Nat) :
    ∀ (T : FQT α) (D : List Draw) (tab t1 t2 : RTab) (n1 n2 : Nat), TabInv dom tab t1 t2 → FC dom T n1 n2 →
    tsum M (n1 + n2) (fun ss => G (run t (resL tab ss T) D)) =
      tsum M n1 (fun s1 => tsum M n2 (fun s2 => G (run t (resL2 dom t1 s1 t2 s2 T) D)))
  | .done a, D, _, _, _, n1, n2, _, _ => by
    simp only [resL, resL2, run]
    rw [tsum_const, tsum_const, tsum_const, Nat.pow_add, Nat.mul_assoc]
  | .ask g r k, D, tab, t1, t2, n1, n2, hinv, hc => by
    simp only [resL, resL2, run]
    cases findDraw D r with
    | some i => exact split_rf dom M t G _ D tab t1 t2 n1 n2 hinv (hc _)
    | none => exact split_rf dom M t G _ _ tab t1 t2 n1 n2 hinv (hc _)
  | .fq x k, D, tab, t1, t2, n1, n2, hinv, hc => by
    simp only [resL, resL2]
    have hx := hinv x
    simp only [FC] at hc
    by_cases hd : dom x = true
    · rw [if_pos hd] at hx hc
      simp only [hd, if_true]
      rw [hx]
      cases hl : rlook t1 x with
      | some y => exact split_rf dom M t G _ D tab t1 t2 n1 n2 hinv (FC.mono dom _ (hc.2 y) (by omega) (Nat.le_refl _))
      | none =>
        obtain ⟨m1, rfl⟩ : ∃ m1, n1 = m1 + 1 := ⟨n1 - 1, by omega⟩
        rw [show m1 + 1 + n2 = (m1 + n2) + 1 by omega]
        simp only [tsum, List.headD_cons, List.tail_cons]
        apply congrArg List.sum; apply List.map_congr_left; intro y _
        exact split_rf dom M t G _ D _ _ t2 m1 n2 (tabInv_snoc1 dom tab t1 t2 hinv x _ hd) (hc.2 _)
    · have hd' : dom x = false := by simpa using hd
      rw [if_neg hd] at hx hc
      simp only [hd', Bool.false_eq_true, if_false]
      rw [hx]
      cases hl : rlook t2 x with
      | some y => exact split_rf dom M t G _ D tab t1 t2 n1 n2 hinv (FC.mono dom _ (hc.2 y) (Nat.le_refl _) (by omega))
      | none =>
        obtain ⟨m2, rfl⟩ : ∃ m2, n2 = m2 + 1 := ⟨n2 - 1, by omega⟩
        rw [show n1 + (m2 + 1) = (n1 + m2) + 1 by omega]
        simp only [tsum, List.headD_cons, List.tail_cons]
        symm; rw [tsum_list]; symm
        apply congrArg List.sum; apply List.map_congr_left; intro y _
        exact split_rf dom M t G _ D _ t1 _ n1 m2 (tabInv_snoc2 dom tab t1 t2 hinv x _ hd') (hc.2 _)

/-- Sums over tapes commute. -/
theorem tsum_comm (R1 R2 : Nat) : ∀ (N1 N2 : Nat) (F : List Nat → List Nat → Nat),
    tsum R1 N1 (fun a => tsum R2 N2 (fun b => F a b)) = tsum R2 N2 (fun b => tsum R1 N1 (fun a => F a b))
  | 0, N2, F => rfl
  | N1+1, N2, F => by
    simp only [tsum]
    symm; rw [tsum_list]; symm
    apply congrArg List.sum; apply List.map_congr_left; intro y _
    exact tsum_comm R1 R2 N1 N2 (fun a b => F (y :: a) b)

/-! Resolving derivation requests. -/

theorem resL2_lift {α : Type} (dom : Bytes → Bool) (t1 : RTab) (s1 : List Nat) (t2 : RTab) (s2 : List Nat) :
    ∀ (T : QT α), resL2 dom t1 s1 t2 s2 (liftQ T) = T
  | .done _ => rfl
  | .ask g r k => by
    simp only [liftQ, resL2]; congr 1; funext b; exact resL2_lift dom t1 s1 t2 s2 (k b)

theorem resL2_bind_lift {α β : Type} (dom : Bytes → Bool) (t1 : RTab) (s1 : List Nat) (t2 : RTab) (s2 : List Nat)
    (f : α → FQT β) : ∀ (T : QT α),
    resL2 dom t1 s1 t2 s2 (FQT.bind (liftQ T) f) = QT.bind T (fun a => resL2 dom t1 s1 t2 s2 (f a))
  | .done _ => rfl
  | .ask g r k => by
    simp only [liftQ, FQT.bind, resL2, QT.bind]; congr 1; funext b; exact resL2_bind_lift dom t1 s1 t2 s2 f (k b)

theorem fc_lift {α : Type} (dom : Bytes → Bool) (n1 n2 : Nat) : ∀ (T : QT α), FC dom (liftQ T) n1 n2
  | .done _ => trivial
  | .ask _ _ k => fun b => fc_lift dom n1 n2 (k b)

theorem fc_bind_lift {α β : Type} (dom : Bytes → Bool) (n1 n2 : Nat) (f : α → FQT β) (hf : ∀ a, FC dom (f a) n1 n2) :
    ∀ (T : QT α), FC dom (FQT.bind (liftQ T) f) n1 n2
  | .done a => hf a
  | .ask _ _ k => fun b => fc_bind_lift dom n1 n2 f hf (k b)

/-! The DSM game: per-step keys derived from Smaster. -/

/-- A per-step context: chain id, chain tip `h_n`, pre-commitment `C_pre`, step key `k_step`. -/
abbrev ECtx := Wire 32 × Wire 32 × Wire 32 × Wire 32

/-- `ALG_ID_SPX256F`. -/
def ALG : Bytes := "SPX256f".toUTF8.toList

/-- The derivation input of a context (`derive_ephemeral_seed`). -/
def ekIn (c : ECtx) : Bytes := ekSeedInput ALG c.1 c.2.1 c.2.2.1 c.2.2.2

theorem ekIn_inj {c c' : ECtx} (h : ekIn c = ekIn c') : c = c' := by
  obtain ⟨a1, a2, a3, a4⟩ := c
  obtain ⟨b1, b2, b3, b4⟩ := c'
  obtain ⟨_, h1, h2, h3, h4⟩ := ekSeedInput_inj _ _ _ _ _ _ _ _ _ _ h
  subst h1 h2 h3 h4; rfl

theorem ekDom_ekIn (c : ECtx) : ekDom (ekIn c) = true := ekDom_seed _ _ _ _ _

/-- The seed from the derivation's 32 output bytes. -/
def seedOf (b : Bytes) : Wire 32 := ⟨be 32 (toInt b), be_width 32 _⟩

theorem seedOf_be (y : Nat) : seedOf (be 32 y) = seedW y := by
  apply Subtype.ext
  show be 32 (toInt (be 32 y)) = be 32 y
  rw [be_mod 32 y, be_roundtrip 32 _ (Nat.mod_lt _ (Nat.pow_pos (by decide)))]

/-- Position of a context among the created ones. -/
def cidx : List ECtx → ECtx → Option Nat
  | [], _ => none
  | a :: l, c => if a = c then some 0 else (cidx l c).map (· + 1)

theorem cidx_none : ∀ (l : List ECtx) (c : ECtx), cidx l c = none → c ∉ l
  | [], _, _ => by simp
  | a :: l, c, h => by
    simp only [cidx] at h
    split at h
    · exact absurd h (by simp)
    · rename_i ha
      have := cidx_none l c (by cases hc : cidx l c <;> simp_all)
      simp only [List.mem_cons, not_or]; exact ⟨fun e => ha e.symm, this⟩

theorem rlook_none : ∀ (tab : RTab) (x : Bytes), x ∉ tab.map Prod.fst → rlook tab x = none
  | [], _, _ => rfl
  | (a, b) :: t, x, h => by
    simp only [List.map_cons, List.mem_cons, not_or] at h
    simp only [rlook, if_neg (Ne.symm h.1)]; exact rlook_none t x h.2

theorem pks_getD (keys : List Key) (j : Nat) : (keys.map Prod.fst).getD j [] = (kAt keys j).1 := by
  simp only [kAt, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases keys[j]? <;> rfl

/-- A DSM adversary: hash queries; a per-step key for a context it chooses
    (answered with the public key; a repeated context returns the existing key);
    the other Smaster-keyed derivations, such as the ML-KEM coins, revealed in
    full (`leak`, any input outside the per-step domain); signing queries under
    the `j`-th per-step key; and a claimed forgery. -/
inductive DAdv where
  | hq (r : Request) (k : Bytes → DAdv)
  | newKey (c : ECtx) (k : Bytes → DAdv)
  | leak (x : Bytes) (k : Bytes → DAdv)
  | sq (j : Nat) (m : Bytes) (k : Option Bytes → DAdv)
  | out (j : Nat) (m s : Bytes)

/-- At most `qh` hash queries, `qn` key requests, `ql` revealed derivations and `qs` signing queries. -/
def DBudget : DAdv → Nat → Nat → Nat → Nat → Prop
  | .hq _ k, qh, qn, ql, qs => 0 < qh ∧ ∀ b, DBudget (k b) (qh - 1) qn ql qs
  | .newKey _ k, qh, qn, ql, qs => 0 < qn ∧ ∀ b, DBudget (k b) qh (qn - 1) ql qs
  | .leak _ k, qh, qn, ql, qs => 0 < ql ∧ ∀ b, DBudget (k b) qh qn (ql - 1) qs
  | .sq _ _ k, qh, qn, ql, qs => 0 < qs ∧ ∀ o, DBudget (k o) qh qn ql (qs - 1)
  | .out _ _ _, _, _, _, _ => True

section
variable (v : Variant) (limits : Limits)

/-- The DSM game. The `j`-th new context's key is generated from the seed
    `derive(ekIn c)`; keys are identified by context. -/
def dplay : List ECtx → List Key → List (Nat × Bytes) → DAdv → FQT MOut
  | cs, keys, sg, .hq r k => .ask true r (fun b => dplay cs keys sg (k b))
  | cs, keys, sg, .newKey c k => match cidx cs c with
    | some j => dplay cs keys sg (k (kAt keys j).1)
    | none => .fq (ekIn c) (fun e => FQT.bind (liftQ (generateKeypair challengerOracle v (seedOf e)))
        (fun ks => dplay (cs ++ [c]) (keys ++ [ks]) sg (k ks.1)))
  | cs, keys, sg, .leak x k => if ekDom x = true then dplay cs keys sg (k []) else .fq x (fun y => dplay cs keys sg (k y))
  | cs, keys, sg, .sq j m k => if j < keys.length ∧ legal limits m = true then
      FQT.bind (liftQ (sign challengerOracle v (kAt keys j).2 m)) (fun s => dplay cs keys (sg ++ [(j, m)]) (k s))
    else dplay cs keys sg (k none)
  | _, keys, sg, .out j m s => liftQ (mOut v limits keys sg j m s)

/-- The multi-key adversary of C66 that runs a DSM adversary: it asks for a new
    key only for a new context, and answers revealed derivations from its own
    lazily sampled function (table `t2`, vector `s2`). -/
def trans : List ECtx → List Bytes → RTab → List Nat → DAdv → MAdv
  | cs, pks, t2, s2, .hq r k => .hq r (fun b => trans cs pks t2 s2 (k b))
  | cs, pks, t2, s2, .newKey c k => match cidx cs c with
    | some j => trans cs pks t2 s2 (k (pks.getD j []))
    | none => .newKey (fun pk => trans (cs ++ [c]) (pks ++ [pk]) t2 s2 (k pk))
  | cs, pks, t2, s2, .leak x k => if ekDom x = true then trans cs pks t2 s2 (k []) else
      match rlook t2 x with
      | some y => trans cs pks t2 s2 (k y)
      | none => trans cs pks (t2 ++ [(x, be 32 (s2.headD 0))]) s2.tail (k (be 32 (s2.headD 0)))
  | cs, pks, t2, s2, .sq j m k => .sq j m (fun o => trans cs pks t2 s2 (k o))
  | _, _, _, _, .out j m s => .out j m s

/-- **The ideal DSM game is the multi-key game.** With the derivation answered
    by two independent random functions (per-step domain: vector `ss1`; the rest:
    vector `s2`), the DSM game is the multi-key game with seeds `ss1` in creation
    order, against `trans`. Context injectivity makes each new context a fresh
    input of the random function. -/
theorem dsim (ss1 : List Nat) : ∀ (A : DAdv) (cs : List ECtx) (keys : List Key) (sg : List (Nat × Bytes))
    (t1 t2 : RTab) (s2 : List Nat),
    cs.length = keys.length → t1.map Prod.fst = cs.map ekIn →
    resL2 ekDom t1 (ss1.drop keys.length) t2 s2 (dplay v limits cs keys sg A) =
      mplay v limits (sdOf ss1) keys sg (trans cs (keys.map Prod.fst) t2 s2 A)
  | .hq r k, cs, keys, sg, t1, t2, s2, hl, ht => by
    simp only [dplay, trans, resL2, mplay]
    congr 1; funext b; exact dsim ss1 (k b) cs keys sg t1 t2 s2 hl ht
  | .newKey c k, cs, keys, sg, t1, t2, s2, hl, ht => by
    simp only [dplay, trans]
    cases hc : cidx cs c with
    | some j =>
      simp only [pks_getD]
      exact dsim ss1 _ cs keys sg t1 t2 s2 hl ht
    | none =>
      have hnot : ekIn c ∉ t1.map Prod.fst := by
        rw [ht]; intro hm
        obtain ⟨c', hc', he⟩ := List.mem_map.mp hm
        exact cidx_none cs c hc (ekIn_inj he ▸ hc')
      simp only [resL2, ekDom_ekIn, if_true, rlook_none t1 _ hnot, mplay]
      rw [resL2_bind_lift]
      have hh : (ss1.drop keys.length).headD 0 = sdOf ss1 keys.length := by
        simp [sdOf, List.headD_eq_head?_getD, List.head?_drop, List.getD_eq_getElem?_getD]
      rw [hh, seedOf_be]
      congr 1; funext ks
      have := dsim ss1 (k ks.1) (cs ++ [c]) (keys ++ [ks]) sg (t1 ++ [(ekIn c, be 32 (sdOf ss1 keys.length))]) t2 s2
        (by simp [hl]) (by simp [ht])
      rw [List.length_append, List.length_singleton, ← List.drop_drop, List.map_append] at this
      simp only [List.map_cons, List.map_nil] at this
      rw [← this]
      congr 1
      simp
  | .leak x k, cs, keys, sg, t1, t2, s2, hl, ht => by
    simp only [dplay, trans]
    by_cases hx : ekDom x = true
    · simp only [hx, if_true]; exact dsim ss1 _ cs keys sg t1 t2 s2 hl ht
    · have hx' : ekDom x = false := by simpa using hx
      simp only [hx', Bool.false_eq_true, if_false, resL2]
      cases rlook t2 x with
      | some y => exact dsim ss1 _ cs keys sg t1 t2 s2 hl ht
      | none => exact dsim ss1 _ cs keys sg t1 _ _ hl ht
  | .sq j m k, cs, keys, sg, t1, t2, s2, hl, ht => by
    simp only [dplay, trans, mplay]
    split
    · rw [resL2_bind_lift]; congr 1; funext o; exact dsim ss1 (k o) cs keys _ t1 t2 s2 hl ht
    · exact dsim ss1 (k none) cs keys sg t1 t2 s2 hl ht
  | .out j m o, cs, keys, sg, t1, t2, s2, _, _ => by
    simp only [dplay, trans, mplay]; exact resL2_lift _ _ _ _ _ _

end

/-! Budgets. -/

theorem mbudget_mono : ∀ (M : MAdv) {qh qk qs qh' qk' qs' : Nat}, MBudget M qh qk qs →
    qh ≤ qh' → qk ≤ qk' → qs ≤ qs' → MBudget M qh' qk' qs'
  | .hq _ k, _, _, _, _, _, _, ⟨h1, h2⟩, a, b, c => ⟨by omega, fun x => mbudget_mono (k x) (h2 x) (by omega) b c⟩
  | .newKey k, _, _, _, _, _, _, ⟨h1, h2⟩, a, b, c => ⟨by omega, fun x => mbudget_mono (k x) (h2 x) a (by omega) c⟩
  | .sq _ _ k, _, _, _, _, _, _, ⟨h1, h2⟩, a, b, c => ⟨by omega, fun x => mbudget_mono (k x) (h2 x) a b (by omega)⟩
  | .out _ _ _, _, _, _, _, _, _, _, _, _, _ => trivial

/-- The translated adversary stays within the DSM adversary's budget: at most
    `qn` keys (one per new context). -/
theorem mbudget_trans : ∀ (A : DAdv) (qh qn ql qs : Nat), DBudget A qh qn ql qs →
    ∀ (cs : List ECtx) (pks : List Bytes) (t2 : RTab) (s2 : List Nat), MBudget (trans cs pks t2 s2 A) qh qn qs
  | .hq r k, qh, qn, ql, qs, ⟨h1, h2⟩, cs, pks, t2, s2 => ⟨h1, fun b => mbudget_trans (k b) _ _ _ _ (h2 b) cs pks t2 s2⟩
  | .newKey c k, qh, qn, ql, qs, ⟨h1, h2⟩, cs, pks, t2, s2 => by
    simp only [trans]
    split
    · exact mbudget_mono _ (mbudget_trans _ _ _ _ _ (h2 _) cs pks t2 s2) (Nat.le_refl _) (by omega) (Nat.le_refl _)
    · exact ⟨h1, fun pk => mbudget_trans _ _ _ _ _ (h2 pk) _ _ t2 s2⟩
  | .leak x k, qh, qn, ql, qs, ⟨_, h2⟩, cs, pks, t2, s2 => by
    simp only [trans]
    split
    · exact mbudget_trans _ _ _ _ _ (h2 _) cs pks t2 s2
    · split
      · exact mbudget_trans _ _ _ _ _ (h2 _) cs pks t2 s2
      · exact mbudget_trans _ _ _ _ _ (h2 _) cs pks _ _
  | .sq j m k, qh, qn, ql, qs, ⟨h1, h2⟩, cs, pks, t2, s2 => ⟨h1, fun o => mbudget_trans (k o) _ _ _ _ (h2 o) cs pks t2 s2⟩
  | .out _ _ _, _, _, _, _, _, _, _, _, _ => trivial

section
variable (v : Variant) (limits : Limits)

/-- The DSM game asks at most `qn` per-step derivations and `ql` others. -/
theorem fc_dplay : ∀ (A : DAdv) (qh qn ql qs : Nat), DBudget A qh qn ql qs →
    ∀ (cs : List ECtx) (keys : List Key) (sg : List (Nat × Bytes)), FC ekDom (dplay v limits cs keys sg A) qn ql
  | .hq r k, qh, qn, ql, qs, ⟨_, h2⟩, cs, keys, sg => fun b => fc_dplay (k b) _ _ _ _ (h2 b) cs keys sg
  | .newKey c k, qh, qn, ql, qs, ⟨h1, h2⟩, cs, keys, sg => by
    simp only [dplay]
    split
    · exact FC.mono _ _ (fc_dplay _ _ _ _ _ (h2 _) cs keys sg) (by omega) (Nat.le_refl _)
    · simp only [FC, ekDom_ekIn, if_true]
      exact ⟨h1, fun e => fc_bind_lift _ _ _ _ (fun ks => fc_dplay _ _ _ _ _ (h2 _) _ _ sg) _⟩
  | .leak x k, qh, qn, ql, qs, ⟨h1, h2⟩, cs, keys, sg => by
    simp only [dplay]
    split
    · exact FC.mono _ _ (fc_dplay _ _ _ _ _ (h2 _) cs keys sg) (Nat.le_refl _) (by omega)
    · rename_i hx
      have hx' : ekDom x = false := by simpa using hx
      simp only [FC, hx', Bool.false_eq_true, if_false]
      exact ⟨h1, fun y => fc_dplay _ _ _ _ _ (h2 y) cs keys sg⟩
  | .sq j m k, qh, qn, ql, qs, ⟨_, h2⟩, cs, keys, sg => by
    simp only [dplay]
    split
    · exact fc_bind_lift _ _ _ _ (fun o => fc_dplay _ _ _ _ _ (h2 o) cs keys _) _
    · exact fc_dplay _ _ _ _ _ (h2 none) cs keys sg
  | .out j m o, _, _, _, _, _, _, keys, sg => fc_lift _ _ _ _

end

/-! The PRF hybrid and the DSM bound. -/

/-- DSM's derivation function: keyed BLAKE3 under Smaster = `be 32 K`, 32 bytes. -/
def dsmF (K : Nat) (x : Bytes) : Bytes := Blake3.keyedHash (be 32 K) x 32

/-! The real world is DSM's computation: the derivation output has 32 bytes and
    is the key-generation seed unchanged. -/

theorem be_toInt_rev : ∀ (r : Bytes), be r.length (toInt r.reverse) = r.reverse
  | [] => rfl
  | b :: r => by
    have ht : toInt (r.reverse ++ [b]) = b.toNat + 256 * toInt r.reverse := by simp [toInt, List.reverse_append]
    have hb : b.toNat < 256 := b.toNat_lt
    rw [List.reverse_cons, List.length_cons, be, ht,
      show (b.toNat + 256 * toInt r.reverse) / 256 = toInt r.reverse by omega,
      show (b.toNat + 256 * toInt r.reverse) % 256 = b.toNat by omega, be_toInt_rev r]
    simp

theorem be_toInt (x : Bytes) : be x.length (toInt x) = x := by
  have := be_toInt_rev x.reverse
  rwa [List.reverse_reverse, List.length_reverse] at this

theorem seedOf_id (b : Bytes) (h : b.length = 32) : (seedOf b).val = b := by
  have := be_toInt b; rw [h] at this; exact this

theorem d_rootBlocks_length (o : Blake3.Output) (indices : List Nat) :
    (indices.flatMap o.rootBlock).length = 64 * indices.length := by
  have hb : ∀ c, (o.rootBlock c).length = 64 := by
    intro c
    have h : ∀ (xs : List UInt32),
        (xs.flatMap fun w => (List.range 4).map (fun i => UInt8.ofNat (w.toNat/256^i))).length = 4*xs.length := by
      intro xs
      induction xs with
      | nil => simp
      | cons x xs ih => simp [ih, Nat.mul_add, Nat.add_comm]
    simp [Blake3.Output.rootBlock, Blake3.bytes, h, Blake3.compress]
  induction indices with
  | nil => simp
  | cons x xs ih => simp [hb, ih, Nat.mul_add, Nat.add_comm]

/-- The derivation output has 32 bytes, so `seedOf` passes it through. -/
theorem dsmF_length (K : Nat) (x : Bytes) : (dsmF K x).length = 32 := by
  simp only [dsmF, Blake3.keyedHash, Blake3.Output.root, List.length_take, d_rootBlocks_length, List.length_range]
  omega

theorem seedOf_dsmF (K : Nat) (x : Bytes) : (seedOf (dsmF K x)).val = dsmF K x := seedOf_id _ (dsmF_length K x)

/-- **The ideal DSM game, SPX256f.** With the per-step and the other Smaster-keyed
    derivations answered by a lazily sampled random function (`qn + ql` entries),
    and the adversary given `aux K` for an independent uniform `K`:

        Pr[forge under some per-step key] ≤ qn·(27 Q + 368023)/2^256,
        Q = qh + 17186·qn + 1704961·qs + 17523. -/
theorem dsm_ideal_256f (limits : Limits) (aux : Nat → Bytes) (A : Bytes → DAdv) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (c : Nat) (hc : 0 < c) :
    ((List.range (256^32)).map (fun K => tsum (256^32) (qn + ql) (fun ss =>
        tsum (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)
          ((mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1)
          (fun t => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true))))).sum *
        256^32 ≤
      256^32 * (256^32)^(qn + ql) * ((c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m) ^
          ((mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1) *
        (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) := by
  generalize hRdef : c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m = R
  generalize hN : (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1 = N
  generalize hC : R ^ N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023)) = C
  have hK : ∀ K, tsum (256^32) (qn + ql) (fun ss => tsum R N
        (fun t => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true))) * 256^32 ≤
      (256^32)^ql * ((256^32)^qn * C) := by
    intro K
    rw [tsum_comm]
    have e1 : ∀ t, tsum (256^32) (qn + ql)
        (fun ss => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true)) =
        tsum (256^32) qn (fun s1 => tsum (256^32) ql (fun s2 => ind ((run t (mplay .spx256f limits (sdOf s1) [] []
          (trans [] [] [] s2 (A (aux K)))) []).1.win = true))) := by
      intro t
      rw [split_rf ekDom (256^32) t (fun p => ind (p.1.win = true)) _ [] [] [] [] qn ql (fun _ => by simp [rlook])
        (fc_dplay .spx256f limits _ _ _ _ _ (hA _) [] [] [])]
      apply congrArg (tsum (256^32) qn); funext s1
      apply congrArg (tsum (256^32) ql); funext s2
      have := dsim .spx256f limits s1 (A (aux K)) [] [] [] [] [] s2 rfl rfl
      simp only [List.length_nil, List.drop_zero, List.map_nil] at this
      rw [this]
    simp only [e1]
    rw [tsum_comm]
    conv => lhs; arg 1; arg 3; ext s1; rw [tsum_comm]
    rw [tsum_comm]
    rw [Nat.mul_comm, ← tsum_mul]
    have hb := fun s2 => forge_any_256f limits (trans [] [] [] s2 (A (aux K))) qh qn qs
      (mbudget_trans _ _ _ _ _ (hA _) [] [] [] s2) hqs c hc
    rw [hRdef, hN, hC] at hb
    calc _ ≤ tsum (256^32) ql (fun _ => (256^32)^qn * C) := tsum_mono _ _ (fun s2 => by
          rw [Nat.mul_comm]; exact hb s2)
      _ = _ := tsum_const _ _ _
  calc _ = ((List.range (256^32)).map (fun K => tsum (256^32) (qn + ql) (fun ss => tsum R N
          (fun t => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true))) * 256^32)).sum := by
        rw [Nat.mul_comm, ← sum_map_mul]; apply congrArg List.sum; apply List.map_congr_left; intro K _; rw [Nat.mul_comm]
    _ ≤ ((List.range (256^32)).map (fun _ => (256^32)^ql * ((256^32)^qn * C))).sum := sum_map_le _ (fun K _ => hK K)
    _ = 256^32 * (256^32)^(qn + ql) * C := by
        rw [sum_map_const, List.length_range, Nat.pow_add]; ac_rfl

/-- **DSM, SPX256f, with the PRF hop.** `realW` is the real DSM game (per-step
    seeds from keyed BLAKE3 under a uniform Smaster `K`, adversary given `aux K`);
    `idealW` the same distinguisher against a random function. With
    `Pr_real = realW/(M·R^N)`, `Pr_ideal = idealW/(M·M^(qn+ql)·R^N)` (`M = 2^256`),
    and `Adv = Pr_real − Pr_ideal` the PRF advantage of that distinguisher:

        Pr_real ≤ Adv + qn·(27 Q + 368023)/2^256. -/
theorem dsm_forge_256f (limits : Limits) (aux : Nat → Bytes) (A : Bytes → DAdv) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (c : Nat) (hc : 0 < c) :
    let R := c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
    let N := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1
    let realW := ((List.range (256^32)).map (fun K => tsum R N
        (fun t => ind ((run t (resF (dsmF K) (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true)))).sum
    let idealW := ((List.range (256^32)).map (fun K => tsum (256^32) (qn + ql) (fun ss => tsum R N
        (fun t => ind ((run t (resL [] ss (dplay .spx256f limits [] [] [] (A (aux K)))) []).1.win = true))))).sum
    realW * (256^32)^(qn + ql) * 2^256 ≤
      (realW * (256^32)^(qn + ql) - idealW) * 2^256 +
        256^32 * (256^32)^(qn + ql) * (R ^ N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) := by
  intro R N realW idealW
  have h := dsm_ideal_256f limits aux A qh qn ql qs hA hqs c hc
  have e : (2:Nat)^256 = 256^32 := by decide
  rw [e]
  have h2 : realW * (256^32)^(qn + ql) ≤ (realW * (256^32)^(qn + ql) - idealW) + idealW := by omega
  calc realW * (256^32)^(qn + ql) * 256^32 ≤ ((realW * (256^32)^(qn + ql) - idealW) + idealW) * 256^32 :=
        Nat.mul_le_mul_right _ h2
    _ = (realW * (256^32)^(qn + ql) - idealW) * 256^32 + idealW * 256^32 := Nat.add_mul _ _ _
    _ ≤ _ := Nat.add_le_add_left h _

end DSM.Rom
