-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomWide

/- The seed hop.

   The implemented key generation (`generateKeypair`, crates/dsm-sphincs
   `generate_keypair_from_seed`) draws `3n` bytes from `ChaCha20Rng::from_seed(seed32)`
   and splits them as SK.seed ‖ SK.prf ‖ PK.seed. In the model this is one oracle
   request `⟨3, "ChaCha20Rng", [], seed32, 3n⟩` (mode 3: no BLAKE3 role uses it).
   Its answer on tape coordinate `x` is `be (3n) x`. H1 instead starts from three coin
   entries answering `be n` of three coordinates.

   * Distribution: when `256^(3n)` divides the tape range, the three `n`-byte slices of
     the expansion are jointly uniform, exactly as three independent coins
     (`expand_slices_sum`).
   * H1's coins are queryable table entries (coin 2 is the public PK.seed), so H1 is
     compared with the real game for the renamed adversary `renA A` (requests of mode
     ≥ 999 shifted up one mode). The honest routines and the verifier never ask a
     request of mode above 2 (`m_sign`, `m_verify`, `m_kgTail`), so they are unchanged.
   * Coupling (`run_couple`, `win_couple`): the real run and H1(`renA A`) agree, table
     offset 2, until H1's table holds the seed's expansion request; that names the seed
     among at most `qh` mode-3 inputs (`seedGuess_qh`).
   * `seed_hop`: Pr[real won] ≤ Pr[H1 won by renA A] + qh/2^256; `real_win_256f`:
     Pr[won] ≤ (22·qh + 368023)/2^256 for SPHINCS+-256f with real key generation. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- The `3n`-byte answer on coordinate `(a·M + b)·M + c` is the three `n`-byte answers on
    `a`, `b`, `c` (`M = 256^n`). -/
theorem be_split3 (n a b c : Nat) (hb : b < 256^n) (hc : c < 256^n) :
    be (3*n) ((a * 256^n + b) * 256^n + c) = be n a ++ be n b ++ be n c := by
  rw [show 3*n = (n+n)+n by omega, be_split (n+n) n _ c hc, be_split n n a b hb]

theorem slices_split3 (n a b c : Nat) (hb : b < 256^n) (hc : c < 256^n) :
    (be (3*n) ((a * 256^n + b) * 256^n + c)).take n = be n a ∧
    slice (be (3*n) ((a * 256^n + b) * 256^n + c)) n n = be n b ∧
    slice (be (3*n) ((a * 256^n + b) * 256^n + c)) (2*n) n = be n c := by
  rw [be_split3 n a b c hb hc]
  have wa := be_width n a
  have wb := be_width n b
  have wc := be_width n c
  refine ⟨?_, ?_, ?_⟩
  · rw [List.append_assoc, List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
  · simp only [slice]
    rw [List.append_assoc, List.drop_append_of_le_length (by omega), List.drop_of_length_le (by omega),
      List.nil_append, List.take_append_of_le_length (by omega), List.take_of_length_le (by omega)]
  · simp only [slice]
    rw [show 2*n = (be n a ++ be n b).length by simp [wa, wb]; omega, List.drop_left,
      List.take_of_length_le (by omega)]

/-- Uniformity of the expansion's slices: summing any function of the three slices over the
    `256^(3n)` expansion values equals summing it over three independent `n`-byte values. -/
theorem expand_slices_sum (n : Nat) (f : Bytes → Bytes → Bytes → Nat) :
    ((List.range (256^(3*n))).map (fun x =>
        f ((be (3*n) x).take n) (slice (be (3*n) x) n n) (slice (be (3*n) x) (2*n) n))).sum =
      ((List.range (256^n)).map (fun a => ((List.range (256^n)).map (fun b =>
        ((List.range (256^n)).map (fun c => f (be n a) (be n b) (be n c))).sum)).sum)).sum := by
  rw [show 256^(3*n) = (256^n * 256^n) * 256^n by rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega,
    sum_range_mul, sum_range_mul]
  apply congrArg List.sum; apply List.map_congr_left; intro a _
  apply congrArg List.sum; apply List.map_congr_left; intro b hb
  apply congrArg List.sum; apply List.map_congr_left; intro c hc
  obtain ⟨h1, h2, h3⟩ := slices_split3 n a b c (List.mem_range.mp hb) (List.mem_range.mp hc)
  rw [h1, h2, h3]

/-! Which requests the honest routines ask. -/

/-- Along every path of `T`, at most `n` asks satisfy `P`. -/
def Cnt {α : Type} (P : Request → Bool) : QT α → Nat → Prop
  | .done _, _ => True
  | .ask _ r k, n => if P r then 0 < n ∧ ∀ b, Cnt P (k b) (n - 1) else ∀ b, Cnt P (k b) n

namespace Cnt
variable {P : Request → Bool}

theorem mono {α : Type} : ∀ {T : QT α} {n n' : Nat}, Cnt P T n → n ≤ n' → Cnt P T n'
  | .done _, _, _, _, _ => trivial
  | .ask g r k, n, n', h, hle => by
    simp only [Cnt] at h ⊢
    split
    · rename_i hp
      rw [if_pos hp] at h
      exact ⟨by omega, fun b => mono (h.2 b) (by omega)⟩
    · rename_i hp
      rw [if_neg hp] at h
      exact fun b => mono (h b) hle

theorem pure {α : Type} (a : α) : Cnt P (Pure.pure a : QT α) 0 := trivial

theorem oracle (g : Bool) (r : Request) (h : P r = false) : Cnt P (tagO g r) 0 := by
  simp only [tagO, Cnt, h, Bool.false_eq_true, if_false]
  intro _; trivial

theorem ask1 (g : Bool) (r : Request) : Cnt P (tagO g r) 1 := by
  simp only [tagO, Cnt]
  split
  · exact ⟨by omega, fun _ => trivial⟩
  · intro _; trivial

theorem bind {α β : Type} : ∀ {T : QT α} {f : α → QT β} {n1 n2 : Nat}, Cnt P T n1 → (∀ a, Cnt P (f a) n2) →
    Cnt P (T >>= f) (n1 + n2)
  | .done a, f, n1, n2, _, hf => mono (hf a) (by omega)
  | .ask g r k, f, n1, n2, h, hf => by
    show Cnt P (.ask g r (fun b => QT.bind (k b) f)) (n1 + n2)
    simp only [Cnt] at h ⊢
    split
    · rename_i hp
      rw [if_pos hp] at h
      refine ⟨by omega, fun b => ?_⟩
      have := bind (h.2 b) hf
      exact mono this (by omega)
    · rename_i hp
      rw [if_neg hp] at h
      exact fun b => bind (h b) hf

theorem bind0 {α β : Type} {T : QT α} {f : α → QT β} (hT : Cnt P T 0) (hf : ∀ a, Cnt P (f a) 0) :
    Cnt P (T >>= f) 0 := bind hT hf

theorem ite {α : Type} {c : Prop} [Decidable c] {T₁ T₂ : QT α} {n : Nat}
    (h₁ : c → Cnt P T₁ n) (h₂ : ¬c → Cnt P T₂ n) : Cnt P (if c then T₁ else T₂) n := by
  by_cases h : c
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem forIn {ι σ : Type} (l : List ι) (G : ι → σ → QT (ForInStep σ))
    (h : ∀ i ∈ l, ∀ s, Cnt P (G i s) 0) : ∀ init, Cnt P (forIn l init G) 0 := by
  induction l with
  | nil => intro init; exact pure init
  | cons a l ih =>
    intro init
    simp only [List.forIn_cons]
    refine bind0 (h a (by simp) init) (fun r => ?_)
    cases r with
    | done b => exact pure b
    | yield b => exact ih (fun i hi s => h i (by simp [hi]) s) b

end Cnt

/-- Requests outside BLAKE3's modes 0–2. -/
def hiM (r : Request) : Bool := decide (2 < r.mode)

section
variable (g : Bool) (p : Params) (tk : Bytes)

theorem m_thash (a : Adrs) (x : Bytes) : Cnt hiM (thash (tagO g) p tk a x) 0 := Cnt.oracle g _ rfl

theorem m_chain (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    Cnt hiM (chain (tagO g) p tk a x start steps) 0
  | 0, x, _ => Cnt.pure x
  | steps+1, x, start => by
    simp only [chain]
    exact Cnt.bind0 (m_thash g p tk _ _) (fun y => m_chain a steps y (start+1))

theorem m_authWalk (a : Adrs) (auth : Bytes) : ∀ (remaining li gi level : Nat) (node : Bytes),
    Cnt hiM (authWalk (tagO g) p tk a li gi node auth level remaining) 0
  | 0, _, _, _, node => Cnt.pure node
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact Cnt.bind0 (m_thash g p tk _ _) (fun y => m_authWalk a auth remaining _ _ _ y)

theorem m_wotsPkFromSig (a : Adrs) (sig msg : Bytes) : Cnt hiM (wotsPkFromSig (tagO g) p tk a sig msg) 0 := by
  simp only [wotsPkFromSig, wotsCompress]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun tops => m_thash g p tk _ _)
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact Cnt.bind0 (m_chain g p tk _ _ _ _) (fun top => Cnt.pure _)

theorem m_xmssPkFromSig (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Cnt hiM (xmssPkFromSig (tagO g) p tk a idx sig msg) 0 := by
  simp only [xmssPkFromSig, authRoot]
  exact Cnt.bind0 (m_wotsPkFromSig g p tk _ _ _) (fun node => m_authWalk g p tk _ _ _ _ _ _ _)

theorem m_htRootTail : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    Cnt hiM (htRootTail (tagO g) p tk layer tree node sig remaining) 0
  | 0, _, _, node, _ => Cnt.pure node
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact Cnt.bind0 (m_xmssPkFromSig g p tk _ _ _ _) (fun root => m_htRootTail remaining _ _ root _)

theorem m_htRoot (sig msg : Bytes) (tree leaf : Nat) : Cnt hiM (htRoot (tagO g) p tk sig msg tree leaf) 0 := by
  simp only [htRoot]
  exact Cnt.bind0 (m_xmssPkFromSig g p tk _ _ _ _) (fun node => m_htRootTail g p tk _ _ _ node _)

theorem m_forsPkFromSig (a : Adrs) (sig md : Bytes) : Cnt hiM (forsPkFromSig (tagO g) p tk a sig md) 0 := by
  simp only [forsPkFromSig, authRoot]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun roots => m_thash g p tk _ _)
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact Cnt.bind0 (m_thash g p tk _ _) (fun leaf => Cnt.bind0 (m_authWalk g p tk _ _ _ _ _ _ leaf)
    (fun root => Cnt.pure _))

variable (prfKey seed : Bytes)

theorem m_wotsPkgen (a : Adrs) : Cnt hiM (wotsPkgen (tagO g) p tk prfKey seed a) 0 := by
  simp only [wotsPkgen, wotsCompress]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun tops => m_thash g p tk _ _)
  intro i _ s
  exact Cnt.bind0 (Cnt.oracle g _ rfl) (fun sk => Cnt.bind0 (m_chain g p tk _ _ _ _) (fun top => Cnt.pure _))

theorem m_xmssNode (a : Adrs) : ∀ (height idx : Nat), Cnt hiM (xmssNode (tagO g) p tk prfKey seed a idx height) 0
  | 0, idx => by simp only [xmssNode]; exact m_wotsPkgen g p tk prfKey seed _
  | height+1, idx => by
    simp only [xmssNode]
    exact Cnt.bind0 (m_xmssNode a height (2*idx)) (fun l => Cnt.bind0 (m_xmssNode a height (2*idx+1))
      (fun r => m_thash g p tk _ _))

theorem m_wotsSign (a : Adrs) (msg : Bytes) : Cnt hiM (wotsSign (tagO g) p tk prfKey seed a msg) 0 := by
  simp only [wotsSign]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun sig => Cnt.pure _)
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact Cnt.bind0 (Cnt.oracle g _ rfl) (fun sk => Cnt.bind0 (m_chain g p tk _ _ _ _) (fun part => Cnt.pure _))

theorem m_xmssSign (a : Adrs) (idx : Nat) (msg : Bytes) :
    Cnt hiM (xmssSign (tagO g) p tk prfKey seed a idx msg) 0 := by
  simp only [xmssSign]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun auth => Cnt.bind0 (m_wotsSign g p tk prfKey seed _ _)
    (fun sig => Cnt.pure _))
  intro level _ s
  exact Cnt.bind0 (m_xmssNode g p tk prfKey seed _ _ _) (fun node => Cnt.pure _)

theorem m_htSignTail : ∀ (remaining layer tree : Nat) (node : Bytes),
    Cnt hiM (htSignTail (tagO g) p tk prfKey seed layer tree node remaining) 0
  | 0, _, _, _ => Cnt.pure _
  | remaining+1, layer, tree, node => by
    simp only [htSignTail]
    refine Cnt.bind0 (m_xmssSign g p tk prfKey seed _ _ _) (fun part => ?_)
    refine Cnt.ite (fun _ => Cnt.pure _) (fun _ => ?_)
    exact Cnt.bind0 (Cnt.pure _) (fun _ => Cnt.bind0 (m_xmssPkFromSig g p tk _ _ _ _)
      (fun root => Cnt.bind0 (m_htSignTail remaining _ _ root) (fun tail => Cnt.pure _)))

theorem m_htSign (msg : Bytes) (tree leaf : Nat) : Cnt hiM (htSign (tagO g) p tk prfKey seed msg tree leaf) 0 := by
  simp only [htSign]
  exact Cnt.bind0 (m_xmssSign g p tk prfKey seed _ _ _) (fun first => Cnt.bind0 (m_xmssPkFromSig g p tk _ _ _ _)
    (fun root => Cnt.bind0 (m_htSignTail g p tk prfKey seed _ _ _ root) (fun tail => Cnt.pure _)))

theorem m_forsNode (a : Adrs) : ∀ (height idx : Nat), Cnt hiM (forsNode (tagO g) p tk prfKey seed a idx height) 0
  | 0, idx => by
    simp only [forsNode, forsSecret]
    exact Cnt.bind0 (Cnt.oracle g _ rfl) (fun sk => m_thash g p tk _ _)
  | height+1, idx => by
    simp only [forsNode]
    exact Cnt.bind0 (m_forsNode a height (2*idx)) (fun l => Cnt.bind0 (m_forsNode a height (2*idx+1))
      (fun r => m_thash g p tk _ _))

theorem m_forsSign (a : Adrs) (md : Bytes) : Cnt hiM (forsSign (tagO g) p tk prfKey seed a md) 0 := by
  simp only [forsSign, forsSecret]
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ []) (fun sig => Cnt.pure _)
  intro x _ s
  obtain ⟨idx, i⟩ := x
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun sk => ?_)
  refine Cnt.bind0 (Cnt.forIn _ _ ?_ _) (fun r => Cnt.bind0 (Cnt.pure _) (fun _ => Cnt.pure _))
  intro level _ u
  exact Cnt.bind0 (m_forsNode g p tk prfKey seed _ _ _) (fun node => Cnt.bind0 (Cnt.pure _) (fun _ => Cnt.pure _))

end

theorem m_sign (g : Bool) (v : Variant) (sk msg : Bytes) : Cnt hiM (sign (tagO g) v sk msg) 0 := by
  simp only [sign]
  refine Cnt.ite (fun _ => Cnt.pure _) (fun _ => ?_)
  refine Cnt.bind0 (Cnt.pure _) (fun _ => ?_)
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun tk => ?_)
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun pk => ?_)
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun mk => ?_)
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun r => ?_)
  refine Cnt.bind0 (Cnt.oracle g _ rfl) (fun dg => ?_)
  refine Cnt.bind0 (m_forsSign g _ tk pk _ _ _) (fun fs => ?_)
  refine Cnt.bind0 (m_forsPkFromSig g _ tk _ _ _) (fun fpk => ?_)
  refine Cnt.bind0 (m_htSign g _ tk pk _ _ _ _) (fun hs => ?_)
  refine Cnt.bind0 (m_htRoot g _ tk _ _ _ _) (fun ac => ?_)
  exact Cnt.ite (fun _ => Cnt.pure _) (fun _ => Cnt.bind0 (Cnt.pure _) (fun _ => Cnt.pure _))

theorem m_kgTail (g : Bool) (v : Variant) (ex : Bytes) : Cnt hiM (kgTail (tagO g) v ex) 0 := by
  simp only [kgTail]
  exact Cnt.bind0 (Cnt.oracle g _ rfl) (fun tk => Cnt.bind0 (Cnt.oracle g _ rfl)
    (fun pk => Cnt.bind0 (m_xmssNode g _ tk pk _ _ _ _) (fun root => Cnt.pure _)))

theorem m_verify (g : Bool) (v : Variant) (pk msg sig : Bytes) : Cnt hiM (verify (tagO g) v pk msg sig) 0 := by
  simp only [verify]
  refine Cnt.ite (fun _ => Cnt.pure _) (fun _ => ?_)
  refine Cnt.bind0 (Cnt.pure _) (fun _ => ?_)
  refine Cnt.ite (fun _ => Cnt.pure _) (fun _ => ?_)
  refine Cnt.bind0 (Cnt.pure _) (fun _ => ?_)
  exact Cnt.bind0 (Cnt.oracle g _ rfl) (fun tk => Cnt.bind0 (Cnt.oracle g _ rfl) (fun dg =>
    Cnt.bind0 (m_forsPkFromSig g _ tk _ _ _) (fun fpk => Cnt.bind0 (m_htRoot g _ tk _ _ _ _)
      (fun ac => Cnt.pure _))))

/-! Renaming the adversary's out-of-band requests. -/

/-- Shift every request of mode at least 999 up by one mode. Injective, length-preserving,
    the identity on DSM's modes 0–3, and never a mode-999 (coin) request. -/
def ren (r : Request) : Request := if 999 ≤ r.mode then { r with mode := r.mode + 1 } else r

theorem ren_inj {a b : Request} (h : ren a = ren b) : a = b := by
  obtain ⟨ma, ca, ka, ia, oa⟩ := a
  obtain ⟨mb, cb, kb, ib, ob⟩ := b
  simp only [ren] at h
  by_cases ha : 999 ≤ ma <;> by_cases hb : 999 ≤ mb <;>
    simp only [ha, hb, if_true, if_false, Request.mk.injEq] at h
  · simp only [Request.mk.injEq]; exact ⟨by omega, h.2.1, h.2.2.1, h.2.2.2.1, h.2.2.2.2⟩
  · omega
  · omega
  · simp only [Request.mk.injEq]; exact h

theorem ren_outLen (r : Request) : (ren r).outLen = r.outLen := by unfold ren; split <;> rfl

theorem ren_ne999 (r : Request) : (ren r).mode ≠ 999 ∨ r.mode < 999 := by
  unfold ren; split
  · left; simp; omega
  · right; omega

theorem ren_low (r : Request) (h : r.mode < 999) : ren r = r := by
  unfold ren; rw [if_neg (by omega)]

theorem ren_mode999 (r : Request) : (ren r).mode ≠ 999 := by
  unfold ren; split
  · simp; omega
  · omega

def renD (e : Draw) : Draw := (e.1, ren e.2)

theorem findDraw_cons (x : Draw) (d : List Draw) (r : Request) :
    findDraw (x :: d) r = if x.2 = r then some 0 else (findDraw d r).map (· + 1) := by
  simp only [findDraw]
  by_cases h : x.2 = r
  · rw [if_pos ((req_beq_iff _ _).mpr h), if_pos h]
  · rw [if_neg (fun h' => h ((req_beq_iff _ _).mp h')), if_neg h]

theorem findDraw_skip : ∀ (C L : List Draw) (r : Request), (∀ e ∈ C, e.2 ≠ r) →
    findDraw (C ++ L) r = (findDraw L r).map (· + C.length)
  | [], L, r, _ => by
    simp only [List.nil_append, List.length_nil]
    cases findDraw L r <;> rfl
  | x :: C, L, r, h => by
    rw [List.cons_append, findDraw_cons, if_neg (h x (by simp)), findDraw_skip C L r (fun e he => h e (by simp [he]))]
    cases findDraw L r <;> simp; omega

theorem findDraw_ren : ∀ (L : List Draw) (r : Request), findDraw (L.map renD) (ren r) = findDraw L r
  | [], _ => rfl
  | x :: L, r => by
    rw [List.map_cons, findDraw_cons, findDraw_cons, findDraw_ren L r]
    by_cases h : x.2 = r
    · rw [if_pos h, if_pos (by simp [renD, h])]
    · rw [if_neg h, if_neg (by simp only [renD]; exact fun h' => h (ren_inj h'))]

/-- `T'` is `T` with every request renamed. -/
def RenR {α : Type} : QT α → QT α → Prop
  | .done a, T' => T' = .done a
  | .ask g r k, T' => ∃ k', T' = .ask g (ren r) k' ∧ ∀ b, RenR (k b) (k' b)

theorem RenR.refl {α : Type} : ∀ {T : QT α}, Cnt hiM T 0 → RenR T T
  | .done _, _ => rfl
  | .ask g r k, h => by
    simp only [Cnt] at h
    split at h
    · exact absurd h.1 (by omega)
    · rename_i hp
      have hr : ren r = r := ren_low r (by simp [hiM] at hp; omega)
      exact ⟨k, by rw [hr], fun b => RenR.refl (h b)⟩

theorem RenR.bind {α β : Type} : ∀ {T T' : QT α} {f f' : α → QT β}, RenR T T' → (∀ a, RenR (f a) (f' a)) →
    RenR (T >>= f) (T' >>= f')
  | .done a, T', f, f', h, hf => by
    simp only [RenR] at h; subst h; exact hf a
  | .ask g r k, T', f, f', h, hf => by
    obtain ⟨k', rfl, hk⟩ := h
    exact ⟨fun b => QT.bind (k' b) f', rfl, fun b => RenR.bind (hk b) hf⟩

/-- The adversary with every hash query renamed. -/
def renAdv : RAdv → RAdv
  | .hq r k => .hq (ren r) (fun b => renAdv (k b))
  | .sq m k => .sq m (fun o => renAdv (k o))
  | .out m s => .out m s

theorem budget_ren : ∀ (B : RAdv) (qh qs : Nat), Budget B qh qs → Budget (renAdv B) qh qs
  | .hq _ k, _, _, ⟨h1, h2⟩ => ⟨h1, fun b => budget_ren (k b) _ _ (h2 b)⟩
  | .sq _ k, _, _, ⟨h1, h2⟩ => ⟨h1, fun o => budget_ren (k o) _ _ (h2 o)⟩
  | .out _ _, _, _, h => h

theorem play_ren (v : Variant) (limits : Limits) (pk sk : Bytes) :
    ∀ (B : RAdv) (signed : List Bytes), RenR (playQT v limits pk sk B signed) (playQT v limits pk sk (renAdv B) signed)
  | .hq r k, signed => ⟨_, rfl, fun b => play_ren v limits pk sk (k b) signed⟩
  | .sq m k, signed => by
    simp only [playQT, renAdv]
    split
    · exact RenR.bind (RenR.refl (m_sign false v sk m)) (fun s => play_ren v limits pk sk (k s) _)
    · exact play_ren v limits pk sk (k none) signed
  | .out m s, signed => by
    simp only [playQT, renAdv]
    exact RenR.bind (RenR.refl (m_verify true v pk m s)) (fun ok => rfl)

/-! The coupling: the real run and H1 with the renamed adversary. -/

/-- The table after key generation: the real run holds the expansion entry `E` first, H1
    holds three coin entries `C`; the rest agree up to renaming. -/
theorem run_couple {α : Type} (E : Request) (hE : E.mode < 999) (C : List Draw) (hC3 : C.length = 3)
    (hC : ∀ e ∈ C, e.2.mode = 999) (u t : List Nat) (ht : ∀ i, u.getD (i+1) 0 = t.getD (i+3) 0) :
    ∀ (T T' : QT α) (L : List Draw), RenR T T' → (∀ e ∈ L, e.2 ≠ E) →
      (∃ e ∈ (run t T' (C ++ L.map renD)).2, e.2 = E) ∨
      ((run u T ((false, E) :: L)).1 = (run t T' (C ++ L.map renD)).1 ∧
        ∃ L', (run u T ((false, E) :: L)).2 = (false, E) :: L' ∧
          (run t T' (C ++ L.map renD)).2 = C ++ L'.map renD ∧ ∀ e ∈ L', e.2 ≠ E)
  | .done a, T', L, h, hL => by
    simp only [RenR] at h; subst h
    exact Or.inr ⟨rfl, L, rfl, rfl, hL⟩
  | .ask g r k, T', L, h, hL => by
    obtain ⟨k', rfl, hk⟩ := h
    have hCr : ∀ e ∈ C, e.2 ≠ ren r := fun e he h' => ren_mode999 r (h' ▸ hC e he)
    have hfd1 : findDraw (C ++ L.map renD) (ren r) = (findDraw L r).map (· + 3) := by
      rw [findDraw_skip C _ _ hCr, findDraw_ren, hC3]
    by_cases hr : r = E
    · subst hr
      left
      have hn : findDraw L r = none := by
        cases hf : findDraw L r with
        | none => rfl
        | some j =>
          obtain ⟨e, he, her⟩ := findDraw_mem L r j hf
          exact absurd her (hL e he)
      simp only [run]
      rw [hfd1, hn, Option.map_none]
      simp only
      obtain ⟨x, hx⟩ := run_extends t (k' (be (ren r).outLen (t.getD (C ++ L.map renD).length 0)))
        ((C ++ L.map renD) ++ [(g, ren r)])
      rw [hx]
      exact ⟨(g, ren r), by simp, ren_low r hE⟩
    · have hfd0 : findDraw ((false, E) :: L) r = (findDraw L r).map (· + 1) := by
        rw [findDraw_cons, if_neg (fun h' => hr h'.symm)]
      simp only [run]
      rw [hfd0, hfd1]
      cases hf : findDraw L r with
      | some j =>
        simp only [Option.map_some]
        have hv : be (ren r).outLen (t.getD (j+3) 0) = be r.outLen (u.getD (j+1) 0) := by
          rw [ren_outLen, ht]
        rw [hv]
        exact run_couple E hE C hC3 hC u t ht (k _) (k' _) L (hk _) hL
      | none =>
        simp only [Option.map_none]
        have hl : (C ++ L.map renD).length = L.length + 3 := by simp [hC3]; omega
        have hv : be (ren r).outLen (t.getD (C ++ L.map renD).length 0) =
            be r.outLen (u.getD ((false, E) :: L).length 0) := by
          rw [ren_outLen, hl, List.length_cons, ht]
        rw [hv]
        have e1 : (false, E) :: L ++ [(g, r)] = (false, E) :: (L ++ [(g, r)]) := rfl
        have e2 : C ++ L.map renD ++ [(g, ren r)] = C ++ (L ++ [(g, r)]).map renD := by
          simp [renD]
        rw [e1, e2]
        refine run_couple E hE C hC3 hC u t ht (k _) (k' _) (L ++ [(g, r)]) (hk _) ?_
        intro e he
        rcases List.mem_append.mp he with h1 | h1
        · exact hL e h1
        · simp at h1; subst h1; exact fun h' => hr h'

/-! The real game and the coupling with H1. -/

/-- A run depends on a tape coordinate only through the answers drawn from it. -/
theorem run_congr {α : Type} (t t' : List Nat) : ∀ (T : QT α) (D : List Draw),
    (∀ (i : Nat) (e : Draw), D[i]? = some e → be e.2.outLen (t.getD i 0) = be e.2.outLen (t'.getD i 0)) →
    (∀ i, D.length ≤ i → t.getD i 0 = t'.getD i 0) → run t T D = run t' T D
  | .done _, _, _, _ => rfl
  | .ask g r k, D, hD, hr => by
    simp only [run]
    cases hf : findDraw D r with
    | some i =>
      simp only
      obtain ⟨e, he, her⟩ := findDraw_get D r i hf
      have := hD i e he
      rw [her] at this
      rw [this]
      exact run_congr t t' _ D hD hr
    | none =>
      simp only
      rw [hr D.length (Nat.le_refl _)]
      refine run_congr t t' _ _ (fun i e he => ?_) (fun i hi => hr i (by simp at hi; omega))
      by_cases hi : i < D.length
      · rw [List.getElem?_append_left hi] at he; exact hD i e he
      · have hi' : i = D.length := by
          have := (List.getElem?_eq_some_iff.mp he).1; simp at this; omega
        rw [hi', hr D.length (Nat.le_refl _)]

def seedW (s : Nat) : Wire 32 := ⟨be 32 s, be_width 32 s⟩

/-- The expansion request of seed `s`. -/
def expReq (v : Variant) (s : Nat) : Request := ⟨3, "ChaCha20Rng", [], be 32 s, 3 * (params v).n⟩

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- The real game for one key: `generateKeypair` from the 32-byte seed `be 32 s`, then the
    adversary's signing queries and forgery, all against one lazily sampled oracle. -/
def realQT (s : Nat) : QT Out :=
  QT.bind (generateKeypair challengerOracle v (seedW s)) (fun ks => playQT v limits ks.1 ks.2 (A ks.1) [])

def runR (s : Nat) (u : List Nat) : Out × List Draw := run u (realQT v limits A s) []

theorem realQT_eq (s : Nat) :
    realQT v limits A s = .ask false (expReq v s) (fun ex => gameQT v limits A ex) := by
  unfold realQT gameQT
  rw [generateKeypair_split]
  rfl

theorem runR_first (s : Nat) (u : List Nat) :
    runR v limits A s u = run u (gameQT v limits A (be (3*(params v).n) (u.getD 0 0))) [(false, expReq v s)] := by
  rw [runR, realQT_eq]
  simp only [run, findDraw]
  rfl

/-- The renamed adversary. -/
def renA : Bytes → RAdv := fun pk => renAdv (A pk)

/-- The bad event: H1's table (renamed adversary) holds the expansion request of seed `s`. -/
def SeedBad (s : Nat) (t : List Nat) : Prop := ∃ e ∈ (runG v limits (renA A) t).2, e.2 = expReq v s

theorem sres_coin (t : List Nat) (n : Nat) :
    sres t (coinEx n) = be n (t.getD 0 0) ++ be n (t.getD 1 0) ++ be n (t.getD 2 0) := by
  simp [coinEx, sres, SV.res]

theorem resD_coin_mode (t : List Nat) (n : Nat) : ∀ e ∈ resD t (coinSt n), e.2.mode = 999 := by
  intro e he
  simp only [resD, coinSt, List.map_cons, List.map_nil, List.mem_cons, List.not_mem_nil, or_false] at he
  rcases he with rfl | rfl | rfl <;> rfl

/-- Pointwise coupling: on a real tape whose first coordinate's expansion is the three H1
    coins, the real game and H1 with the renamed adversary agree unless the bad event. -/
theorem win_couple (s a b c : Nat) (rest : List Nat) (hb : b < 256^(params v).n) (hc : c < 256^(params v).n) :
    ind ((runR v limits A s ((((a * 256^(params v).n + b) * 256^(params v).n + c)) :: rest)).1.win = true) ≤
      ind ((runG v limits (renA A) (a :: b :: c :: rest)).1.win = true) + ind (SeedBad v limits A s (a :: b :: c :: rest)) := by
  rw [runR_first]
  simp only [List.getD_cons_zero]
  rw [be_split3 _ a b c hb hc]
  have hex : sres (a :: b :: c :: rest) (coinEx (params v).n) = be (params v).n a ++ be (params v).n b ++ be (params v).n c := by
    rw [sres_coin]; rfl
  have hR : RenR (gameQT v limits A (be (params v).n a ++ be (params v).n b ++ be (params v).n c))
      (gameQT v limits (renA A) (be (params v).n a ++ be (params v).n b ++ be (params v).n c)) :=
    RenR.bind (RenR.refl (m_kgTail false v _)) (fun ks => play_ren v limits ks.1 ks.2 (A ks.1) [])
  have hC3 : (resD (a :: b :: c :: rest) (coinSt (params v).n)).length = 3 := rfl
  have key := run_couple (expReq v s) (by simp [expReq]) (resD (a :: b :: c :: rest) (coinSt (params v).n)) hC3
    (resD_coin_mode _ _) ((((a * 256^(params v).n + b) * 256^(params v).n + c)) :: rest) (a :: b :: c :: rest)
    (fun i => rfl) _ _ [] hR (by simp)
  simp only [List.map_nil, List.append_nil] at key
  unfold runG
  rw [hex]
  rcases key with ⟨e, he, hee⟩ | ⟨hw, -⟩
  · have hbad : SeedBad v limits A s (a :: b :: c :: rest) := by
      refine ⟨e, ?_, hee⟩
      unfold runG; rw [hex]; exact he
    rw [ind_of hbad]
    have := ind_le_one ((run (((a * 256 ^ (params v).n + b) * 256 ^ (params v).n + c) :: rest)
      (gameQT v limits A (be (params v).n a ++ be (params v).n b ++ be (params v).n c)) [(false, expReq v s)]).1.win = true)
    omega
  · rw [hw]; omega

end

/-! The seed guess. -/

def isM3 (r : Request) : Bool := decide (r.mode = 3)

theorem Cnt.weaken {P Q : Request → Bool} (hPQ : ∀ r, P r = true → Q r = true) {α : Type} :
    ∀ {T : QT α} {n : Nat}, Cnt Q T n → Cnt P T n
  | .done _, _, _ => trivial
  | .ask g r k, n, h => by
    simp only [Cnt] at h ⊢
    by_cases hp : P r = true
    · rw [if_pos hp]
      rw [if_pos (hPQ r hp)] at h
      exact ⟨h.1, fun b => Cnt.weaken hPQ (h.2 b)⟩
    · rw [if_neg hp]
      by_cases hq : Q r = true
      · rw [if_pos hq] at h
        exact fun b => (Cnt.weaken hPQ (h.2 b)).mono (by omega)
      · rw [if_neg hq] at h
        exact fun b => Cnt.weaken hPQ (h b)

theorem m3_of_hi {α : Type} {T : QT α} (h : Cnt hiM T 0) : Cnt isM3 T 0 :=
  Cnt.weaken (fun r hr => by simp [isM3, hiM] at hr ⊢; omega) h

theorem play_m3 (v : Variant) (limits : Limits) (pk sk : Bytes) :
    ∀ (B : RAdv) (qh qs : Nat) (signed : List Bytes), Budget B qh qs →
      Cnt isM3 (playQT v limits pk sk B signed) qh
  | .hq r k, qh, qs, signed, ⟨hpos, hk⟩ => by
    simp only [playQT, Cnt]
    split
    · exact ⟨hpos, fun b => play_m3 v limits pk sk (k b) (qh - 1) qs signed (hk b)⟩
    · exact fun b => (play_m3 v limits pk sk (k b) (qh - 1) qs signed (hk b)).mono (by omega)
  | .sq m k, qh, qs, signed, ⟨_, hk⟩ => by
    simp only [playQT]
    split
    · exact Cnt.bind (m3_of_hi (m_sign false v sk m)) (fun o => by
        cases o with
        | none => exact play_m3 v limits pk sk (k none) qh (qs - 1) _ (hk none)
        | some sg => exact play_m3 v limits pk sk (k (some sg)) qh (qs - 1) _ (hk _))
        |>.mono (by omega)
    · exact play_m3 v limits pk sk (k none) qh (qs - 1) signed (hk none)
  | .out m s, qh, _, signed, _ => by
    simp only [playQT]
    exact (Cnt.bind (m3_of_hi (m_verify true v pk m s)) (fun ok => Cnt.pure (P := isM3) _)).mono (by omega)

theorem game_m3 (v : Variant) (limits : Limits) (A : Bytes → RAdv) (qh qs : Nat)
    (hB : ∀ pk, Budget (A pk) qh qs) (ex : Bytes) : Cnt isM3 (gameQT v limits A ex) qh :=
  (Cnt.bind (m3_of_hi (m_kgTail false v ex)) (fun ks => play_m3 v limits ks.1 ks.2 (A ks.1) qh qs [] (hB _))).mono
    (by omega)

theorem run_cnt (P : Request → Bool) (t : List Nat) {α : Type} : ∀ (T : QT α) (D : List Draw) (n : Nat),
    Cnt P T n → ((run t T D).2.filter (fun e => P e.2)).length ≤ (D.filter (fun e => P e.2)).length + n
  | .done _, D, n, _ => by simp [run]
  | .ask g r k, D, n, h => by
    simp only [run]
    simp only [Cnt] at h
    cases hf : findDraw D r with
    | some i =>
      simp only
      split at h
      · have := run_cnt P t (k (be r.outLen (t.getD i 0))) D (n - 1) (h.2 _); omega
      · exact run_cnt P t (k (be r.outLen (t.getD i 0))) D n (h _)
    | none =>
      simp only
      split at h
      · rename_i hp
        have := run_cnt P t (k (be r.outLen (t.getD D.length 0))) (D ++ [(g, r)]) (n - 1) (h.2 _)
        simp only [List.filter_append, List.length_append, List.filter_cons, hp, if_true, List.filter_nil,
          List.length_cons, List.length_nil] at this
        omega
      · rename_i hp
        have := run_cnt P t (k (be r.outLen (t.getD D.length 0))) (D ++ [(g, r)]) n (h _)
        simp only [List.filter_append, List.length_append, List.filter_cons, hp, List.filter_nil,
          List.length_nil, Bool.false_eq_true, if_false] at this
        omega

/-- The seeds a table's mode-3 entries name. -/
def seedGuess (D : List Draw) : List Nat :=
  D.filterMap (fun e => if e.2.mode = 3 then some (toInt e.2.input) else none)

theorem seedGuess_len : ∀ (D : List Draw), (seedGuess D).length ≤ (D.filter (fun e => isM3 e.2)).length
  | [] => by simp [seedGuess]
  | e :: D => by
    have := seedGuess_len D
    by_cases h : e.2.mode = 3
    · simp [seedGuess, h, isM3] at this ⊢; omega
    · simp [seedGuess, h, isM3] at this ⊢; omega

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

theorem seedBad_guess (s : Nat) (hs : s < 256^32) (t : List Nat) (h : SeedBad v limits A s t) :
    (seedGuess (runG v limits (renA A) t).2).contains s = true := by
  obtain ⟨e, he, hee⟩ := h
  have hm : e.2.mode = 3 := by rw [hee]; rfl
  have hi : toInt e.2.input = s := by rw [hee]; exact be_roundtrip 32 s hs
  simp only [List.contains_iff_mem, seedGuess, List.mem_filterMap]
  exact ⟨e, he, by simp [hm, hi]⟩

theorem resD_coin_m3 (t : List Nat) (n : Nat) : ((resD t (coinSt n)).filter (fun e => isM3 e.2)).length = 0 := by
  simp [resD, coinSt, coin, isM3, SReq.res]

theorem seedGuess_qh (qh qs : Nat) (hB : ∀ pk, Budget (A pk) qh qs) (t : List Nat) :
    (seedGuess (runG v limits (renA A) t).2).length ≤ qh := by
  refine Nat.le_trans (seedGuess_len _) ?_
  have := run_cnt isM3 t (gameQT v limits (renA A) (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n)) qh
    (game_m3 v limits (renA A) qh qs (fun pk => budget_ren _ _ _ (hB pk)) _)
  rw [resD_coin_m3] at this
  unfold runG
  omega

end

/-! Tape reindexing. -/

theorem sum_mod_eq (R M : Nat) (q : Nat) (hR : R = M * q) (G : Nat → Nat)
    (hG : ∀ x, G x = G (x % M)) : ((List.range R).map G).sum = q * ((List.range M).map G).sum := by
  subst hR
  rw [show (List.range (M * q)).map G = (List.range (q * M)).map (fun x => G (x % M)) by
    rw [Nat.mul_comm]; exact List.map_congr_left (fun x _ => hG x)]
  exact sum_mod_periodic G M q

theorem sum_cube (M : Nat) (G : Nat → Nat) :
    ((List.range (M * M * M)).map G).sum = ((List.range M).map (fun a => ((List.range M).map (fun b =>
      ((List.range M).map (fun c => G ((a * M + b) * M + c))).sum)).sum)).sum := by
  rw [sum_range_mul G M (M * M), sum_range_mul _ M M]

theorem tsum_three (R K : Nat) (F : List Nat → Nat) :
    tsum R (K+3) F = ((List.range R).map (fun a => ((List.range R).map (fun b => ((List.range R).map (fun c =>
      tsum R K (fun rest => F (a :: b :: c :: rest)))).sum)).sum)).sum := rfl

theorem tsum_one (R K : Nat) (F : List Nat → Nat) :
    tsum R (K+1) F = ((List.range R).map (fun x => tsum R K (fun rest => F (x :: rest)))).sum := rfl

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

theorem runR_mod (s x : Nat) (rest : List Nat) :
    runR v limits A s (x :: rest) = runR v limits A s ((x % 256^(3*(params v).n)) :: rest) := by
  rw [runR_first, runR_first]
  simp only [List.getD_cons_zero]
  rw [show be (3*(params v).n) (x % 256^(3*(params v).n)) = be (3*(params v).n) x from (be_mod _ x).symm]
  refine run_congr _ _ _ _ (fun i e he => ?_) (fun i hi => ?_)
  · cases i with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at he
      subst he
      exact be_mod _ x
    | succ i => simp at he
  · cases i with
    | zero => simp at hi
    | succ i => rfl

theorem resD_coin_eq (t : List Nat) (n : Nat) : resD t (coinSt n) =
    [(false, ⟨999, "DSM/rom/coin", [], be n (t.getD 0 0), n⟩), (false, ⟨999, "DSM/rom/coin", [], be n (t.getD 1 0), n⟩),
     (false, ⟨999, "DSM/rom/coin", [], be n (t.getD 2 0), n⟩)] := by
  simp [resD, coinSt, coin, SReq.res, sres, SV.res]

theorem runG_mod (B : Bytes → RAdv) (a b c : Nat) (rest : List Nat) :
    runG v limits B (a :: b :: c :: rest) =
      runG v limits B ((a % 256^(params v).n) :: (b % 256^(params v).n) :: (c % 256^(params v).n) :: rest) := by
  unfold runG
  rw [sres_coin, sres_coin, resD_coin_eq, resD_coin_eq]
  simp only [List.getD_cons_zero, List.getD_cons_succ]
  have ea : be (params v).n (a % 256^(params v).n) = be (params v).n a := (be_mod _ a).symm
  have eb : be (params v).n (b % 256^(params v).n) = be (params v).n b := (be_mod _ b).symm
  have ec : be (params v).n (c % 256^(params v).n) = be (params v).n c := (be_mod _ c).symm
  rw [ea, eb, ec]
  refine run_congr _ _ _ _ (fun i e he => ?_) (fun i hi => ?_)
  · rcases i with _ | _ | _ | i
    · simp only [List.getElem?_cons_zero, Option.some.injEq] at he; subst he; exact ea.symm
    · simp only [List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at he; subst he; exact eb.symm
    · simp only [List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at he; subst he; exact ec.symm
    · simp at he
  · rcases i with _ | _ | _ | i
    · simp at hi
    · simp at hi
    · simp at hi
    · rfl

end

/-! The seed hop. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- Three nested sums over `[0, M)`. -/
def sum3 (M : Nat) (f : Nat → Nat → Nat → Nat) : Nat :=
  ((List.range M).map (fun a => ((List.range M).map (fun b => ((List.range M).map (fun c => f a b c)).sum)).sum)).sum

theorem sum3_le (M : Nat) {f g : Nat → Nat → Nat → Nat}
    (h : ∀ a b c, b < M → c < M → f a b c ≤ g a b c) : sum3 M f ≤ sum3 M g :=
  sum_map_le _ (fun a _ => sum_map_le _ (fun b hb => sum_map_le _ (fun c hc =>
    h a b c (List.mem_range.mp hb) (List.mem_range.mp hc))))

theorem sum3_add (M : Nat) (f g : Nat → Nat → Nat → Nat) :
    sum3 M (fun a b c => f a b c + g a b c) = sum3 M f + sum3 M g := by
  unfold sum3
  rw [← sum_map_add]; congr 1; apply List.map_congr_left; intro a _
  rw [← sum_map_add]; congr 1; apply List.map_congr_left; intro b _
  rw [← sum_map_add]

theorem sum3_const (M x : Nat) : sum3 M (fun _ _ _ => x) = M * M * M * x := by
  simp only [sum3, sum_map_const, List.length_range]
  ac_rfl

theorem sum_sum3 (M : Nat) (l : List Nat) (f : Nat → Nat → Nat → Nat → Nat) :
    (l.map (fun s => sum3 M (f s))).sum = sum3 M (fun a b c => (l.map (fun s => f s a b c)).sum) := by
  unfold sum3
  rw [sum_comm]; congr 1; apply List.map_congr_left; intro a _
  rw [sum_comm]; congr 1; apply List.map_congr_left; intro b _
  rw [sum_comm]

/-- **The seed hop.** For every adversary within budget, the real game (key generation from a
    uniform 32-byte seed through the ChaCha20 expansion request) is won on at most the
    tapes on which H1 is won by the renamed adversary, plus `qh` seed guesses:
      Pr[real won] ≤ Pr[H1 won by renA A] + qh / 2^256
    (real tapes have `K+1` coordinates, H1 tapes `K+3`; `256^(3n)` divides the range `R`). -/
theorem seed_hop (qh qs : Nat) (hB : ∀ pk, Budget (A pk) qh qs) (R K : Nat)
    (hR : 256^(3*(params v).n) ∣ R) :
    ((List.range (256^32)).map (fun s => tsum R (K+1) (fun u => ind ((runR v limits A s u).1.win = true)))).sum *
        (R * R) ≤
      256^32 * tsum R (K+3) (fun t => ind ((runG v limits (renA A) t).1.win = true)) + R^(K+3) * qh := by
  have hM3 : 256^(3*(params v).n) = 256^(params v).n * 256^(params v).n * 256^(params v).n := by
    rw [← Nat.pow_add, ← Nat.pow_add]; congr 1; omega
  generalize hM : 256^(params v).n = M at hM3
  obtain ⟨q, hq⟩ := hR
  rw [hM3] at hq
  have hRq : R = M * (q * M * M) := by rw [hq]; ac_rfl
  generalize hq1 : q * M * M = q1 at hRq
  -- H1, reindexed
  let T1 := fun a b c => tsum R K (fun rest => ind ((runG v limits (renA A) (a :: b :: c :: rest)).1.win = true))
  have hT1 : ∀ a b c, T1 a b c = T1 (a % M) (b % M) (c % M) := by
    intro a b c
    show tsum R K _ = tsum R K _
    congr 1; funext rest
    rw [runG_mod v limits (renA A) a b c rest, runG_mod v limits (renA A) (a % M) (b % M) (c % M) rest, hM,
      Nat.mod_mod, Nat.mod_mod, Nat.mod_mod]
  have hc : ∀ a b c, T1 a b c = T1 a b (c % M) := fun a b c => by rw [hT1, hT1 a b (c % M), Nat.mod_mod]
  have hb : ∀ a b c, T1 a b c = T1 a (b % M) c := fun a b c => by rw [hT1, hT1 a (b % M) c, Nat.mod_mod]
  have ha : ∀ a b c, T1 a b c = T1 (a % M) b c := fun a b c => by rw [hT1, hT1 (a % M) b c, Nat.mod_mod]
  have h1 : tsum R (K+3) (fun t => ind ((runG v limits (renA A) t).1.win = true)) = q1 * q1 * q1 * sum3 M T1 := by
    rw [tsum_three]
    show ((List.range R).map (fun a => ((List.range R).map (fun b => ((List.range R).map (fun c => T1 a b c)).sum)).sum)).sum = _
    have e1 : ∀ a b, ((List.range R).map (fun c => T1 a b c)).sum = q1 * ((List.range M).map (fun c => T1 a b c)).sum :=
      fun a b => sum_mod_eq R M q1 hRq _ (hc a b)
    simp only [e1, sum_map_mul]
    have e2 : ∀ a, ((List.range R).map (fun b => ((List.range M).map (fun c => T1 a b c)).sum)).sum =
        q1 * ((List.range M).map (fun b => ((List.range M).map (fun c => T1 a b c)).sum)).sum :=
      fun a => sum_mod_eq R M q1 hRq _ (fun b => by
        show ((List.range M).map (fun c => T1 a b c)).sum = ((List.range M).map (fun c => T1 a (b % M) c)).sum
        congr 1; exact List.map_congr_left (fun c _ => hb a b c))
    simp only [e2, sum_map_mul]
    have e3 : ((List.range R).map (fun a => ((List.range M).map (fun b => ((List.range M).map (fun c => T1 a b c)).sum)).sum)).sum =
        q1 * sum3 M T1 :=
      sum_mod_eq R M q1 hRq _ (fun a => by
        congr 1; apply List.map_congr_left; intro b _; congr 1; exact List.map_congr_left (fun c _ => ha a b c))
    rw [e3]
    ac_rfl
  -- the real game, reindexed and coupled
  let Bs := fun s a b c => tsum R K (fun rest => ind (SeedBad v limits A s (a :: b :: c :: rest)))
  have h0 : ∀ s, tsum R (K+1) (fun u => ind ((runR v limits A s u).1.win = true)) ≤ q * (sum3 M T1 + sum3 M (Bs s)) := by
    intro s
    rw [tsum_one]
    have e : ((List.range R).map (fun x => tsum R K (fun rest => ind ((runR v limits A s (x :: rest)).1.win = true)))).sum =
        q * ((List.range (M * M * M)).map (fun x => tsum R K (fun rest => ind ((runR v limits A s (x :: rest)).1.win = true)))).sum := by
      refine sum_mod_eq R (M * M * M) q hq _ (fun x => ?_)
      congr 1; funext rest
      rw [runR_mod v limits A s x rest, hM3]
    rw [e, sum_cube, ← sum3_add]
    refine Nat.mul_le_mul_left _ (sum3_le M (fun a b c hb' hc' => ?_))
    rw [← tsum_add]
    refine tsum_mono R K (fun rest => ?_)
    have := win_couple v limits A s a b c rest (by rw [hM]; exact hb') (by rw [hM]; exact hc')
    rw [hM] at this
    exact this
  -- the seed guesses
  have hg : ∀ a b c, ((List.range (256^32)).map (fun s => Bs s a b c)).sum ≤ R^K * qh := by
    intro a b c
    calc _ ≤ ((List.range (256^32)).map (fun s => tsum R K (fun rest =>
            if (seedGuess (runG v limits (renA A) (a :: b :: c :: rest)).2).contains s then 1 else 0))).sum :=
          sum_map_le _ (fun s hs => tsum_mono R K (fun rest => by
            by_cases hb' : SeedBad v limits A s (a :: b :: c :: rest)
            · rw [ind_of hb', seedBad_guess v limits A s (List.mem_range.mp hs) _ hb']; simp
            · rw [ind_of_not hb']; exact Nat.zero_le _))
      _ ≤ tsum R K (fun rest => (seedGuess (runG v limits (renA A) (a :: b :: c :: rest)).2).length) :=
          guess_bound R K (256^32) _
      _ ≤ tsum R K (fun _ => qh) := tsum_mono R K (fun rest => seedGuess_qh v limits A qh qs hB _)
      _ = R^K * qh := tsum_const R qh K
  -- assembly
  have hqR : q * (R * R) = q1 * q1 * q1 := by rw [hq, ← hq1]; ac_rfl
  have h3 : ∀ x : Nat, x^3 = x * x * x := fun x => by
    rw [show (3:Nat) = 0+1+1+1 from rfl, Nat.pow_succ, Nat.pow_succ, Nat.pow_succ, Nat.pow_zero, Nat.one_mul]
  have hRK : q1 * q1 * q1 * (M * M * M * (R^K * qh)) = R^(K+3) * qh := by
    rw [hRq, Nat.pow_add, h3]; ac_rfl
  calc ((List.range (256^32)).map (fun s => tsum R (K+1) (fun u => ind ((runR v limits A s u).1.win = true)))).sum * (R * R)
      = ((List.range (256^32)).map (fun s => (R * R) * tsum R (K+1) (fun u => ind ((runR v limits A s u).1.win = true)))).sum := by
        rw [sum_map_mul, Nat.mul_comm]
    _ ≤ ((List.range (256^32)).map (fun s => q1 * q1 * q1 * sum3 M T1 + q1 * q1 * q1 * sum3 M (Bs s))).sum :=
        sum_map_le _ (fun s _ => by
          have := Nat.mul_le_mul_left (R * R) (h0 s)
          rw [← Nat.mul_add, ← hqR]
          calc R * R * _ ≤ R * R * (q * (sum3 M T1 + sum3 M (Bs s))) := this
            _ = q * (R * R) * (sum3 M T1 + sum3 M (Bs s)) := by ac_rfl)
    _ = 256^32 * (q1 * q1 * q1 * sum3 M T1) + q1 * q1 * q1 * ((List.range (256^32)).map (fun s => sum3 M (Bs s))).sum := by
        rw [sum_map_add, sum_map_const, sum_map_mul, List.length_range]
    _ ≤ 256^32 * (q1 * q1 * q1 * sum3 M T1) + q1 * q1 * q1 * (M * M * M * (R^K * qh)) := by
        refine Nat.add_le_add_left (Nat.mul_le_mul_left _ ?_) _
        rw [sum_sum3, ← sum3_const]
        exact sum3_le M (fun a b c _ _ => hg a b c)
    _ = 256^32 * tsum R (K+3) (fun t => ind ((runG v limits (renA A) t).1.win = true)) + R^(K+3) * qh := by
        rw [h1, hRK]

end

/-! The real SPHINCS+-256f game. -/

/-- **SPHINCS+-256f, real key generation.** For every adversary with `Budget A qh qs` and
    `qs ≤ 2^64`, the per-key game with key generation from a uniform 32-byte seed through the
    ChaCha20 expansion request satisfies
      Pr[won] ≤ (22·qh + 368023) / 2^256,
    where `Pr[won]` is the left side divided by `256^32 · R^(K+1) · R^2 · 256^32`: seeds
    `s < 256^32`, real tapes of `K+1` coordinates in `[0, R)`, `R = c·256^(3n)·256^m`. -/
theorem real_win_256f (limits : Limits) (A : Bytes → RAdv) (c qh qs : Nat) (hc : 0 < c)
    (hqs : qs ≤ 2^64) (hB : ∀ pk, Budget (A pk) qh qs) :
    ((List.range (256^32)).map (fun s => tsum (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)
        ((qh + 1704962 * qs + 398862) + 1)
        (fun u => ind ((runR .spx256f limits A s u).1.win = true)))).sum *
      ((c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m) *
        (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)) * 256^32 ≤
    256^32 * (c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m)^((qh + 1704962 * qs + 398862) + 3) *
      (22 * qh + 368023) := by
  have hR : 256^(3*(params .spx256f).n) ∣ c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m :=
    Nat.dvd_mul_right_of_dvd (Nat.dvd_mul_left _ c) _
  have h0 := seed_hop .spx256f limits A qh qs hB _ (qh + 1704962 * qs + 398862) hR
  have h1 := rom_win_budget_lin_256f limits (renA A) (c * 256^(3*(params .spx256f).n)) qh qs
    (Nat.mul_pos hc (Nat.pow_pos (by decide))) hqs (fun pk => budget_ren _ _ _ (hB pk))
  rw [show qh + 1704962 * qs + 398865 = (qh + 1704962 * qs + 398862) + 3 by omega] at h1
  generalize c * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m = R at h0 h1 ⊢
  generalize (qh + 1704962 * qs + 398862) = K at h0 h1 ⊢
  generalize tsum R (K+3) (fun t => ind ((runG .spx256f limits (renA A) t).1.win = true)) = W1 at h0 h1
  generalize ((List.range (256^32)).map (fun s => tsum R (K+1)
    (fun u => ind ((runR .spx256f limits A s u).1.win = true)))).sum = W0 at h0 ⊢
  have h0' := Nat.mul_le_mul_right (256^32) h0
  rw [Nat.add_mul] at h0'
  have e1 : 256^32 * W1 * 256^32 = 256^32 * (W1 * 256^32) := by ac_rfl
  rw [e1] at h0'
  have h1' := Nat.mul_le_mul_left (256^32) h1
  have e2 : 256^32 * R^(K+3) * (22 * qh + 368023) = 256^32 * (R^(K+3) * (21 * qh + 368023)) + R^(K+3) * qh * 256^32 := by
    have : 22 * qh + 368023 = (21 * qh + 368023) + qh := by omega
    rw [this, Nat.mul_add]
    ac_rfl
  rw [e2]
  omega

end DSM.Rom
