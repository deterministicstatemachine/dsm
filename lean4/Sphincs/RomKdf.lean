-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.KeyScheduleNamed

/- KS1 and C67 in the random-oracle model.

   C69 bounds forgery against DSM's per-step SPHINCS+ keys with five advantages
   left as assumptions (KeyScheduleNamed.lean names them): the two Extracts and two
   Expands of KS1, and C67's keyed BLAKE3 under Smaster. Here HMAC-BLAKE3 and keyed
   BLAKE3 are one random oracle (the KDF oracle) with domain-separated inputs
   (`hmIn k m` for HMAC under key `k`, `kbIn k x` for keyed BLAKE3 under key `k`),
   independent of the random oracle for SPHINCS+ hashing, and all five are proved.

   The game (`romGame`):

   * a uniform entropy `e < 2^256` and the wallet seed `bip e`;
   * KS1 as twelve requests to the KDF oracle (`ks1Rom`): Extract of the wallet seed,
     eight Expands under `PRK_w` (seven siblings and `s0`), Extract of `s0`, and
     Smaster and the at-rest key under `PRK_s0`;
   * C67's DSM game under the derived Smaster, the adversary given any function
     `pubOf` of the seven siblings (in full) and the at-rest key. Each derivation
     request `x` of that game is the KDF-oracle request `kbIn Smaster x` (keyed BLAKE3
     under Smaster), except that a request `0xff ‖ z` is the adversary's own query of
     the KDF oracle at `z` (`gIn`). DSM's own derivation inputs begin with `DSM/`, so
     the adversary reaches the KDF oracle, at any input, through C67's `leak`, and
     those queries count in `ql`.

   The proof:

   1. `resL_ks1Rom`: the twelve challenger requests are always fresh (their classes,
      HMAC key length and Expand label, are distinct), so they take the first twelve
      uniform values;
   2. `couple`: the game then agrees with C67's ideal game (every derivation request
      answered by one lazily sampled function) unless one of the requests, mapped to
      the KDF oracle, lands on a challenger request or two of them coincide;
   3. `bad_hits`: that happens only if one of the adversary's own queries is the
      Extract input of the wallet seed or of `s0`, or is keyed by `PRK_w`, `PRK_s0` or
      Smaster;
   4. `e_family`, `coord_family`: C67's ideal game reads none of those five values,
      so each query hits one with probability at most `β/2^256` (the wallet seed,
      `β` bounding how many entropies share a seed) or `1/2^256`;
   5. `href_bound`: C67's `dsm_ideal_256f` bounds the ideal game;
   6. `rom_forge_256f`: Pr[forgery] ≤ (qn·(27·Q + 368023) + (qn + ql)·(β + 4))/2^256. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! The KDF oracle's inputs. -/

/-- HMAC-BLAKE3 under key `k` at message `m`. -/
def hmIn (k m : Bytes) : Bytes := [1] ++ lp k ++ m

/-- Keyed BLAKE3 under key `k` at input `x`. -/
def kbIn (k x : Bytes) : Bytes := [0] ++ lp k ++ x

/-- The KDF-oracle input of a derivation request of C67's game under Smaster `sm`: a
    request `0xff ‖ z` is the adversary's own query at `z`; any other request `x` is the
    Smaster-keyed derivation at `x`. -/
def gIn (sm : Bytes) (x : Bytes) : Bytes := if x.head? = some 0xff then x.tail else kbIn sm x

/-! Derivation requests through a map, and the final table of a lazily sampled function. -/

def mapFQ {α : Type} (g : Bytes → Bytes) : FQT α → FQT α
  | .done a => .done a
  | .ask b r k => .ask b r (fun y => mapFQ g (k y))
  | .fq x k => .fq (g x) (fun y => mapFQ g (k y))

/-- `resL`, also returning the final table. -/
def resLlog {α : Type} : RTab → List Nat → FQT α → QT (α × RTab)
  | tab, _, .done a => .done (a, tab)
  | tab, ss, .ask g r k => .ask g r (fun b => resLlog tab ss (k b))
  | tab, ss, .fq x k => match rlook tab x with
    | some y => resLlog tab ss (k y)
    | none => resLlog (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail (k (be 32 (ss.headD 0)))

theorem run_resLlog {α : Type} (t : List Nat) : ∀ (T : FQT α) (tab : RTab) (ss : List Nat) (D : List Draw),
    (run t (resLlog tab ss T) D).1.1 = (run t (resL tab ss T) D).1 ∧
      (run t (resLlog tab ss T) D).2 = (run t (resL tab ss T) D).2
  | .done _, _, _, _ => ⟨rfl, rfl⟩
  | .ask g r k, tab, ss, D => by
    simp only [resLlog, resL, run]
    split
    · exact run_resLlog t _ tab ss D
    · exact run_resLlog t _ tab ss _
  | .fq x k, tab, ss, D => by
    simp only [resLlog, resL]
    cases rlook tab x with
    | some y => exact run_resLlog t _ tab ss D
    | none => exact run_resLlog t _ _ _ D

/-- The final table extends the table. -/
theorem resLlog_prefix {α : Type} (t : List Nat) : ∀ (T : FQT α) (tab : RTab) (ss : List Nat) (D : List Draw),
    ∃ ext, (run t (resLlog tab ss T) D).1.2 = tab ++ ext
  | .done _, tab, _, _ => ⟨[], by simp [resLlog, run]⟩
  | .ask g r k, tab, ss, D => by
    simp only [resLlog, run]
    split
    · exact resLlog_prefix t _ tab ss D
    · exact resLlog_prefix t _ tab ss _
  | .fq x k, tab, ss, D => by
    simp only [resLlog]
    cases rlook tab x with
    | some y => exact resLlog_prefix t _ tab ss D
    | none =>
      obtain ⟨e, he⟩ := resLlog_prefix t (k (be 32 (ss.headD 0))) (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail D
      exact ⟨(x, be 32 (ss.headD 0)) :: e, by rw [he, List.append_assoc]; rfl⟩

theorem rlook_some_mem : ∀ (tab : RTab) (x y : Bytes), rlook tab x = some y → x ∈ tab.map Prod.fst
  | [], _, _, h => by simp [rlook] at h
  | (a, b) :: t, x, y, h => by
    simp only [rlook] at h
    split at h
    · rename_i ha; subst ha; simp
    · simp only [List.map_cons, List.mem_cons]; exact Or.inr (rlook_some_mem t x y h)

/-- The final table extends the table, by at most the number of derivation requests. -/
theorem resLlog_ext {α : Type} (dom : Bytes → Bool) (t : List Nat) : ∀ (T : FQT α) (n1 n2 : Nat), FC dom T n1 n2 →
    ∀ (tab : RTab) (ss : List Nat) (D : List Draw),
    ∃ ext, (run t (resLlog tab ss T) D).1.2 = tab ++ ext ∧ ext.length ≤ n1 + n2
  | .done _, _, _, _, tab, _, _ => ⟨[], by simp [resLlog, run]⟩
  | .ask g r k, n1, n2, hc, tab, ss, D => by
    simp only [resLlog, run]
    split
    · exact resLlog_ext dom t _ n1 n2 (hc _) tab ss D
    · exact resLlog_ext dom t _ n1 n2 (hc _) tab ss _
  | .fq x k, n1, n2, hc, tab, ss, D => by
    simp only [FC] at hc
    simp only [resLlog]
    split
    · split at hc
      · obtain ⟨e, he, hl⟩ := resLlog_ext dom t _ (n1 - 1) n2 (hc.2 _) tab ss D
        exact ⟨e, he, by omega⟩
      · obtain ⟨e, he, hl⟩ := resLlog_ext dom t _ n1 (n2 - 1) (hc.2 _) tab ss D
        exact ⟨e, he, by omega⟩
    · split at hc
      · obtain ⟨e, he, hl⟩ := resLlog_ext dom t _ (n1 - 1) n2 (hc.2 _) _ ss.tail D
        exact ⟨(x, be 32 (ss.headD 0)) :: e, by rw [he, List.append_assoc]; rfl, by simp; omega⟩
      · obtain ⟨e, he, hl⟩ := resLlog_ext dom t _ n1 (n2 - 1) (hc.2 _) _ ss.tail D
        exact ⟨(x, be 32 (ss.headD 0)) :: e, by rw [he, List.append_assoc]; rfl, by simp; omega⟩

/-- The table with its inputs mapped. -/
def mapT (g : Bytes → Bytes) (tab : RTab) : RTab := tab.map (fun e => (g e.1, e.2))

theorem rlook_append (A B : RTab) (z : Bytes) :
    rlook (A ++ B) z = match rlook A z with | some v => some v | none => rlook B z := by
  induction A with
  | nil => rfl
  | cons a A ih =>
    simp only [List.cons_append, rlook]
    split
    · rfl
    · exact ih

theorem rlook_mapT (g : Bytes → Bytes) (x : Bytes) : ∀ (tab : RTab),
    (∀ y ∈ tab.map Prod.fst, g x = g y → x = y) → rlook (mapT g tab) (g x) = rlook tab x
  | [], _ => rfl
  | (a, b) :: t, h => by
    simp only [mapT, List.map_cons, rlook]
    by_cases ha : a = x
    · subst ha; simp
    · have hg : g a ≠ g x := fun e => ha (h a (by simp) e.symm).symm
      rw [if_neg hg, if_neg ha]
      exact rlook_mapT g x t (fun y hy e => h y (by simp [hy]) e)

/-- No mapped request lands on the challenger's table `KS`, and the map is injective on
    the requests. -/
def OK (g : Bytes → Bytes) (KS : RTab) (keys : List Bytes) : Prop :=
  ∀ x ∈ keys, g x ∉ KS.map Prod.fst ∧ ∀ y ∈ keys, g x = g y → x = y

/-- **Identical until bad.** With the requests mapped by `g` and answered by one lazily
    sampled function whose table already holds the challenger's entries `KS`, the run
    agrees with the unmapped run on a table without them unless the latter's requests
    violate `OK`. -/
theorem couple {α : Type} (P : α → Prop) (g : Bytes → Bytes) (KS : RTab) (t : List Nat) :
    ∀ (T : FQT α) (tab : RTab) (ss : List Nat) (D : List Draw),
    ind (P (run t (resL (KS ++ mapT g tab) ss (mapFQ g T)) D).1) ≤
      ind (P (run t (resLlog tab ss T) D).1.1) +
        ind (¬ OK g KS ((run t (resLlog tab ss T) D).1.2.map Prod.fst))
  | .done _, tab, _, _ => by simp only [mapFQ, resL, resLlog, run]; omega
  | .ask b r k, tab, ss, D => by
    simp only [mapFQ, resL, resLlog, run]
    split
    · exact couple P g KS t _ tab ss D
    · exact couple P g KS t _ tab ss _
  | .fq x k, tab, ss, D => by
    simp only [mapFQ, resL, resLlog]
    by_cases good : g x ∉ KS.map Prod.fst ∧ ∀ y ∈ tab.map Prod.fst, g x = g y → x = y
    · have hl : rlook (KS ++ mapT g tab) (g x) = rlook tab x := by
        rw [rlook_append, rlook_none KS (g x) good.1]
        exact rlook_mapT g x tab good.2
      rw [hl]
      cases rlook tab x with
      | some y => exact couple P g KS t _ tab ss D
      | none =>
        have := couple P g KS t (k (be 32 (ss.headD 0))) (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail D
        simpa only [mapT, List.map_append, List.map_cons, List.map_nil, List.append_assoc] using this
    · -- `x` is bad: the final table holds `x` and every earlier request.
      have key : ∀ (fin ext : RTab), fin = tab ++ ext → x ∈ (tab ++ ext).map Prod.fst →
          ind (¬ OK g KS (fin.map Prod.fst)) = 1 := by
        rintro fin ext rfl hmem
        apply ind_of
        intro hok
        apply good
        refine ⟨(hok x hmem).1, fun y hy e => (hok x hmem).2 y ?_ e⟩
        simp only [List.map_append, List.mem_append]; exact Or.inl hy
      cases h : rlook tab x with
      | some y =>
        obtain ⟨e, he⟩ := resLlog_prefix t (k y) tab ss D
        rw [key _ e he (by simp only [List.map_append, List.mem_append]; exact Or.inl (rlook_some_mem tab x y h))]
        exact Nat.le_trans (ind_le_one _) (Nat.le_add_left _ _)
      | none =>
        obtain ⟨e, he⟩ := resLlog_prefix t (k (be 32 (ss.headD 0))) (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail D
        rw [key _ ((x, be 32 (ss.headD 0)) :: e) (by rw [he, List.append_assoc]; rfl) (by simp)]
        exact Nat.le_trans (ind_le_one _) (Nat.le_add_left _ _)

/-! The challenger's KS1 requests in the random-oracle model. -/

/-- The Expands under `key`, as HMAC requests `hmIn key (info ‖ 0x01)`. -/
def kprogH {α : Type} (key : Bytes) : List KStep → List Bytes → (List Bytes → FQT α) → FQT α
  | [], outs, k => k outs
  | s :: rest, outs, k => .fq (hmIn key (s.input outs ++ [1])) (fun y => kprogH key rest (outs ++ [y]) k)

/-- KS1 as KDF-oracle requests: Extract of the wallet seed, the eight Expands under
    `PRK_w`, Extract of `s0`, the two Expands under `PRK_s0`. -/
def ks1Rom {α : Type} (c : WCtx) (ws : Bytes) (k : Bytes → List Bytes → Bytes → List Bytes → FQT α) : FQT α :=
  .fq (hmIn saltW ws) (fun pw =>
  kprogH pw (wSteps c) [] (fun wo =>
  .fq (hmIn saltS0 (wo.getD 7 [])) (fun ps =>
  kprogH ps (sSteps c (wo.take 7)) [] (fun so => k pw wo ps so))))

/-- A request's class: its HMAC key length and, for a 32-byte key, the Expand's label. -/
def keyLen (z : Bytes) : Nat := toInt (((z.drop 1).take 4).reverse)
def labelOf (z : Bytes) : Bytes := (z.drop 37).takeWhile (fun b => b != 0)
def cls (z : Bytes) : Nat × Bytes := if keyLen z = 32 then (32, labelOf z) else (keyLen z, [])

theorem keyLen_hmIn (k m : Bytes) (h : k.length < 2^32) : keyLen (hmIn k m) = k.length := by
  have e : hmIn k m = [1] ++ (le32 k.length ++ (k ++ m)) := by simp [hmIn, lp, List.append_assoc]
  unfold keyLen
  rw [e, show List.drop 1 ([1] ++ (le32 k.length ++ (k ++ m))) = le32 k.length ++ (k ++ m) from rfl,
    List.take_left' (by simp [le32_length]), le32, List.reverse_reverse]
  have e : (2:Nat)^32 = 256^4 := by decide
  exact be_roundtrip 4 _ (e ▸ h)

theorem takeWhile_nz : ∀ (a r : Bytes), (0 : UInt8) ∉ a → (a ++ 0 :: r).takeWhile (fun b => b != 0) = a
  | [], r, _ => by simp
  | b :: a, r, h => by
    have hb : b ≠ 0 := fun e => h (by simp [e])
    have ha : (0 : UInt8) ∉ a := fun e => h (by simp [e])
    simp only [List.cons_append, List.takeWhile_cons, bne_iff_ne, ne_eq, hb, not_false_eq_true, if_true]
    rw [takeWhile_nz a r ha]

theorem cls_expand (k : Bytes) (hk : k.length = 32) (l : String) (hl : l ∈ ksLabels) (f : Bytes) :
    cls (hmIn k (ksInfo l f ++ [1])) = (32, utf8 l) := by
  unfold cls
  rw [keyLen_hmIn _ _ (by omega), hk, if_pos rfl]
  congr 1
  have e : hmIn k (ksInfo l f ++ [1]) = ([1] ++ le32 k.length ++ k) ++ (utf8 l ++ 0 :: (f ++ [1])) := by
    simp [hmIn, lp, ksInfo, tagged, List.append_assoc]
  unfold labelOf
  rw [e, List.drop_left' (by simp [le32_length, hk])]
  exact takeWhile_nz _ _ (ksLabels_nul_free l hl)

theorem cls_extract (k m : Bytes) (h : k.length < 2^32) (h32 : k.length ≠ 32) :
    cls (hmIn k m) = (k.length, []) := by
  unfold cls; rw [keyLen_hmIn _ _ h, if_neg h32]

theorem rlook_fresh (tab : RTab) (x : Bytes) (h : ∀ e ∈ tab, cls e.1 ≠ cls x) : rlook tab x = none := by
  apply rlook_none
  intro hx
  obtain ⟨e, he, rfl⟩ := List.mem_map.1 hx
  exact h e he rfl

theorem resL_fq_fresh {α : Type} (tab : RTab) (ss : List Nat) (x : Bytes) (k : Bytes → FQT α)
    (h : rlook tab x = none) :
    resL tab ss (.fq x k) = resL (tab ++ [(x, be 32 (ss.headD 0))]) ss.tail (k (be 32 (ss.headD 0))) := by
  simp only [resL, h]

theorem resL_kprogH {α : Type} (key : Bytes) (hk : key.length = 32) : ∀ (steps : List KStep) (tab : RTab)
    (ss : List Nat) (outs : List Bytes) (k : List Bytes → FQT α), (∀ s ∈ steps, s.label ∈ ksLabels) →
    ((steps.map KStep.label).map utf8).Nodup → (∀ e ∈ tab, ∀ s ∈ steps, cls e.1 ≠ (32, utf8 s.label)) →
    ∃ ext : RTab, (∀ e ∈ ext, (∃ m, e.1 = hmIn key m) ∧ ∃ s ∈ steps, cls e.1 = (32, utf8 s.label)) ∧
      resL tab ss (kprogH key steps outs k) = resL (tab ++ ext) (ss.drop steps.length) (k (kideal steps outs ss))
  | [], tab, ss, outs, k, _, _, _ => ⟨[], by simp, by simp [kprogH, kideal]⟩
  | s :: rest, tab, ss, outs, k, hm, hnd, hcls => by
    have hs : s.label ∈ ksLabels := hm s (List.mem_cons_self ..)
    simp only [List.map_cons] at hnd
    have hnd' := List.nodup_cons.1 hnd
    have hx : cls (hmIn key (s.input outs ++ [1])) = (32, utf8 s.label) := cls_expand key hk _ hs _
    have hfr : rlook tab (hmIn key (s.input outs ++ [1])) = none :=
      rlook_fresh _ _ (fun e he => by rw [hx]; exact hcls e he s (List.mem_cons_self ..))
    simp only [kprogH]
    rw [resL_fq_fresh _ _ _ _ hfr]
    obtain ⟨ext, hext, heq⟩ := resL_kprogH key hk rest (tab ++ [(hmIn key (s.input outs ++ [1]), be 32 (ss.headD 0))])
      ss.tail (outs ++ [be 32 (ss.headD 0)]) k (fun s' h' => hm s' (List.mem_cons_of_mem _ h')) hnd'.2
      (by
        intro e he s' hs'
        rcases List.mem_append.1 he with he | he
        · exact hcls e he s' (List.mem_cons_of_mem _ hs')
        · simp only [List.mem_singleton] at he
          subst he
          rw [hx]
          intro heq
          apply hnd'.1
          have : utf8 s.label = utf8 s'.label := (Prod.mk.inj heq).2
          rw [this]
          exact List.mem_map_of_mem (List.mem_map_of_mem hs'))
    refine ⟨(hmIn key (s.input outs ++ [1]), be 32 (ss.headD 0)) :: ext, ?_, ?_⟩
    · intro e he
      rcases List.mem_cons.1 he with he | he
      · subst he; exact ⟨⟨_, rfl⟩, s, List.mem_cons_self .., hx⟩
      · obtain ⟨h1, s', hs', h2⟩ := hext e he
        exact ⟨h1, s', List.mem_cons_of_mem _ hs', h2⟩
    · rw [heq]
      simp only [List.append_assoc, List.singleton_append, List.length_cons, kideal]
      congr 1
      cases ss <;> simp

theorem getD_tail (l : List Nat) (i : Nat) : l.tail.getD i 0 = l.getD (i+1) 0 := by
  cases l <;> simp

theorem headD_eq_getD (l : List Nat) : l.headD 0 = l.getD 0 0 := by cases l <;> simp

theorem getD_drop' (l : List Nat) (n i : Nat) : (l.drop n).getD i 0 = l.getD (n + i) 0 := by
  simp [List.getD_eq_getElem?_getD]

theorem kideal_closed : ∀ (steps : List KStep) (outs : List Bytes) (ss : List Nat),
    kideal steps outs ss = outs ++ (List.range steps.length).map (fun i => be 32 (ss.getD i 0))
  | [], outs, _ => by simp [kideal]
  | _ :: rest, outs, ss => by
    show kideal rest (outs ++ [be 32 (ss.headD 0)]) ss.tail = _
    rw [kideal_closed rest, List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_map,
      List.append_assoc, List.singleton_append, headD_eq_getD]
    have : (List.map (fun i => be 32 (ss.tail.getD i 0)) (List.range rest.length)) =
        List.map ((fun i => be 32 (ss.getD i 0)) ∘ Nat.succ) (List.range rest.length) := by
      apply List.map_congr_left; intro i _; simp only [Function.comp, getD_tail]
    rw [this]

theorem w_s_labels_disjoint (c : WCtx) (sib : List Bytes) :
    ∀ s ∈ wSteps c, ∀ s' ∈ sSteps c sib, utf8 s.label ≠ utf8 s'.label := by
  intro s hs s' hs'
  have h1 : s.label ∈ [lNonce, lGrk, lAtta, lDevSeed, lSdk, lRecAead, lRecAuth, lS0] :=
    wSteps_labels c ▸ List.mem_map_of_mem hs
  have h2 : s'.label ∈ [lSmaster, lAtRest] := sSteps_labels c sib ▸ List.mem_map_of_mem hs'
  have hd : ∀ a ∈ [lNonce, lGrk, lAtta, lDevSeed, lSdk, lRecAead, lRecAuth, lS0],
      ∀ b ∈ [lSmaster, lAtRest], utf8 a ≠ utf8 b := by decide
  exact hd _ h1 _ h2

theorem saltW_length : saltW.length = 23 := by decide
theorem saltS0_length : saltS0.length = 19 := by decide

/-- **The challenger's twelve requests are fresh.** Against a lazily sampled function, KS1
    takes the first twelve entries of the vector: `PRK_w`, the eight Expands, `PRK_s0` and the
    two Expands; the table then holds only the challenger's own requests. -/
theorem resL_ks1Rom {α : Type} (c : WCtx) (ws : Bytes) (k : Bytes → List Bytes → Bytes → List Bytes → FQT α)
    (ss : List Nat) :
    ∃ KS : RTab, (∀ z ∈ KS.map Prod.fst, z = hmIn saltW ws ∨ z = hmIn saltS0 (be 32 (ss.getD 8 0)) ∨
        (∃ m, z = hmIn (be 32 (ss.getD 0 0)) m) ∨ (∃ m, z = hmIn (be 32 (ss.getD 9 0)) m)) ∧
      resL [] ss (ks1Rom c ws k) = resL KS (ss.drop 12)
        (k (be 32 (ss.getD 0 0)) (kideal (wSteps c) [] (ss.drop 1)) (be 32 (ss.getD 9 0))
          (kideal (sSteps c ((kideal (wSteps c) [] (ss.drop 1)).take 7)) [] (ss.drop 10))) := by
  have hw : saltW.length < 2^32 := by rw [saltW_length]; decide
  have hs0 : saltS0.length < 2^32 := by rw [saltS0_length]; decide
  have cW : cls (hmIn saltW ws) = (23, []) := by rw [cls_extract _ _ hw (by rw [saltW_length]; decide), saltW_length]
  have hwo7 : (kideal (wSteps c) [] (ss.drop 1)).getD 7 [] = be 32 (ss.getD 8 0) := by
    rw [kideal_closed, List.nil_append, show (wSteps c).length = 8 from rfl]
    simp
  have cS : cls (hmIn saltS0 ((kideal (wSteps c) [] (ss.drop 1)).getD 7 [])) = (19, []) := by
    rw [cls_extract _ _ hs0 (by rw [saltS0_length]; decide), saltS0_length]
  unfold ks1Rom
  rw [resL_fq_fresh _ _ _ _ rfl, List.nil_append]
  obtain ⟨ext1, h1, e1⟩ := resL_kprogH (be 32 (ss.headD 0)) (be_width 32 _) (wSteps c) [(hmIn saltW ws, be 32 (ss.headD 0))]
    ss.tail [] (fun wo => FQT.fq (hmIn saltS0 (wo.getD 7 [])) (fun ps =>
      kprogH ps (sSteps c (wo.take 7)) [] (fun so => k (be 32 (ss.headD 0)) wo ps so)))
    (wSteps_ok c) (wSteps_nodup c)
    (by intro e he s _; simp only [List.mem_singleton] at he; subst he; rw [cW]; simp)
  rw [e1]
  have tl1 : ss.tail = ss.drop 1 := List.drop_one.symm
  have hd : ss.headD 0 = ss.getD 0 0 := headD_eq_getD ss
  simp only [tl1, hd] at e1 h1 ⊢
  rw [show (ss.drop 1).drop (wSteps c).length = ss.drop 9 by simp [wSteps]]
  have fr2 : rlook ([(hmIn saltW ws, (be 32 (ss.getD 0 0)))] ++ ext1) (hmIn saltS0 ((kideal (wSteps c) [] (ss.drop 1)).getD 7 [])) = none := by
    apply rlook_fresh
    intro e he
    rw [cS]
    rcases List.mem_append.1 he with he | he
    · simp only [List.mem_singleton] at he; subst he; rw [cW]; decide
    · obtain ⟨_, s, _, hc⟩ := h1 e he; rw [hc]; intro h; cases h
  rw [resL_fq_fresh _ _ _ _ fr2]
  have tl9 : (ss.drop 9).tail = ss.drop 10 := by simp [List.tail_drop]
  have hd9 : (ss.drop 9).headD 0 = ss.getD 9 0 := by rw [headD_eq_getD, getD_drop']
  rw [tl9, hd9]
  obtain ⟨ext2, h2, e2⟩ := resL_kprogH (be 32 (ss.getD 9 0)) (be_width 32 _) (sSteps c ((kideal (wSteps c) [] (ss.drop 1)).take 7))
    ([(hmIn saltW ws, (be 32 (ss.getD 0 0)))] ++ ext1 ++ [(hmIn saltS0 ((kideal (wSteps c) [] (ss.drop 1)).getD 7 []), be 32 (ss.getD 9 0))])
    (ss.drop 10) [] (fun so => k (be 32 (ss.getD 0 0)) (kideal (wSteps c) [] (ss.drop 1)) (be 32 (ss.getD 9 0)) so)
    (sSteps_ok c _) (sSteps_nodup c _)
    (by
      intro e he s' hs'
      rcases List.mem_append.1 he with he | he
      · rcases List.mem_append.1 he with he | he
        · simp only [List.mem_singleton] at he; subst he; rw [cW]; intro h; cases h
        · obtain ⟨_, s, hs, hc⟩ := h1 e he
          rw [hc]; intro h
          exact w_s_labels_disjoint c _ s hs s' hs' (Prod.mk.inj h).2
      · simp only [List.mem_singleton] at he; subst he; rw [cS]; intro h; cases h)
  rw [e2]
  refine ⟨_, ?_, by rw [show (ss.drop 10).drop (sSteps c ((kideal (wSteps c) [] (ss.drop 1)).take 7)).length = ss.drop 12 by simp [sSteps]]⟩
  intro z hz
  simp only [List.map_append, List.mem_append, List.map_cons, List.map_nil, List.mem_singleton] at hz
  rcases hz with ((hz | hz) | hz) | hz
  · exact Or.inl hz
  · obtain ⟨e, he, rfl⟩ := List.mem_map.1 hz
    exact Or.inr (Or.inr (Or.inl (h1 e he).1))
  · exact Or.inr (Or.inl (by rw [hz, hwo7]))
  · obtain ⟨e, he, rfl⟩ := List.mem_map.1 hz
    exact Or.inr (Or.inr (Or.inr (h2 e he).1))

/-! The bad event, in terms of the adversary's own requests. -/

/-- The 32-byte key of a request `hmIn k m` or `kbIn k x` with `|k| = 32`. -/
def key32 (z : Bytes) : Bytes := (z.drop 5).take 32

theorem key32_hmIn (k m : Bytes) (hk : k.length = 32) : key32 (hmIn k m) = k := by
  have e : hmIn k m = ([1] ++ le32 k.length) ++ (k ++ m) := by simp [hmIn, lp, List.append_assoc]
  unfold key32; rw [e, List.drop_left' (by simp [le32_length]), List.take_left' hk]

theorem key32_kbIn (k x : Bytes) (hk : k.length = 32) : key32 (kbIn k x) = k := by
  have e : kbIn k x = ([0] ++ le32 k.length) ++ (k ++ x) := by simp [kbIn, lp, List.append_assoc]
  unfold key32; rw [e, List.drop_left' (by simp [le32_length]), List.take_left' hk]

theorem drop_hmIn (k m : Bytes) : (hmIn k m).drop (5 + k.length) = m := by
  have e : hmIn k m = ([1] ++ lp k) ++ m := by simp [hmIn]
  rw [e, List.drop_left' (by simp [lp, le32_length]; omega)]

theorem head_hmIn (k m : Bytes) : (hmIn k m).head? = some 1 := rfl
theorem head_kbIn (k x : Bytes) : (kbIn k x).head? = some 0 := rfl

theorem kbIn_inj (k x y : Bytes) (h : kbIn k x = kbIn k y) : x = y := by
  unfold kbIn at h; exact List.append_cancel_left h

theorem raw_eq (x y : Bytes) (hx : x.head? = some 0xff) (hy : y.head? = some 0xff) (h : x.tail = y.tail) : x = y := by
  cases x with
  | nil => simp at hx
  | cons a x => cases y with
    | nil => simp at hy
    | cons b y => simp only [List.head?_cons, Option.some.injEq] at hx hy; simp only [List.tail_cons] at h; subst hx hy h; rfl

/-- An adversary's request `x` that breaks `OK` is its own query `0xff ‖ z` (`raw`) at the
    Extract of the wallet seed, the Extract of `s0`, or a request keyed by `PRK_w`,
    `PRK_s0` or Smaster. -/
def hits (ws s0 pw ps sm : Bytes) (x : Bytes) : Prop :=
  x.head? = some 0xff ∧ (x.tail.drop 28 = ws ∨ x.tail.drop 24 = s0 ∨ key32 x.tail = pw ∨ key32 x.tail = ps ∨
    key32 x.tail = sm)

theorem bad_hits (ws s0 pw ps sm : Bytes) (hsm : sm.length = 32) (hpw : pw.length = 32) (hps : ps.length = 32)
    (KS : RTab) (hKS : ∀ z ∈ KS.map Prod.fst, z = hmIn saltW ws ∨ z = hmIn saltS0 s0 ∨
        (∃ m, z = hmIn pw m) ∨ (∃ m, z = hmIn ps m))
    (keys : List Bytes) (hbad : ¬ OK (gIn sm) KS keys) : ∃ x ∈ keys, hits ws s0 pw ps sm x := by
  have inKS : ∀ x, x.head? = some 0xff → x.tail ∈ KS.map Prod.fst → hits ws s0 pw ps sm x := by
    intro x hx hm
    refine ⟨hx, ?_⟩
    rcases hKS _ hm with h | h | ⟨m, h⟩ | ⟨m, h⟩
    · left; rw [h, show 28 = 5 + saltW.length by rw [saltW_length], drop_hmIn]
    · right; left; rw [h, show 24 = 5 + saltS0.length by rw [saltS0_length], drop_hmIn]
    · right; right; left; rw [h, key32_hmIn _ _ hpw]
    · right; right; right; left; rw [h, key32_hmIn _ _ hps]
  have kbNotKS : ∀ x, kbIn sm x ∉ KS.map Prod.fst := by
    intro x hm
    have h0 := head_kbIn sm x
    rcases hKS _ hm with h | h | ⟨m, h⟩ | ⟨m, h⟩ <;> rw [h, head_hmIn] at h0 <;> cases h0
  apply Classical.byContradiction
  intro hno
  apply hbad
  intro x hx
  constructor
  · intro hg
    unfold gIn at hg
    by_cases hr : x.head? = some 0xff
    · rw [if_pos hr] at hg; exact hno ⟨x, hx, inKS x hr hg⟩
    · rw [if_neg hr] at hg; exact kbNotKS x hg
  · intro y hy hg
    unfold gIn at hg
    by_cases hr : x.head? = some 0xff <;> by_cases hr' : y.head? = some 0xff
    · rw [if_pos hr, if_pos hr'] at hg; exact raw_eq x y hr hr' hg
    · rw [if_pos hr, if_neg hr'] at hg
      exact absurd ⟨x, hx, hr, Or.inr (Or.inr (Or.inr (Or.inr (by rw [hg, key32_kbIn _ _ hsm]))))⟩ hno
    · rw [if_neg hr, if_pos hr'] at hg
      exact absurd ⟨y, hy, hr', Or.inr (Or.inr (Or.inr (Or.inr (by rw [← hg, key32_kbIn _ _ hsm]))))⟩ hno
    · rw [if_neg hr, if_neg hr'] at hg; exact kbIn_inj _ _ _ hg

theorem ind_mono {P Q : Prop} (h : P → Q) : ind P ≤ ind Q := by
  by_cases hp : P
  · rw [ind_of hp, ind_of (h hp)]; exact Nat.le_refl 1
  · rw [ind_of_not hp]; exact Nat.zero_le _

theorem single_le_sum {ι : Type} (f : ι → Nat) : ∀ (l : List ι) (i : ι), i ∈ l → f i ≤ (l.map f).sum
  | [], _, h => absurd h (by simp)
  | a :: l, i, h => by
    simp only [List.map_cons, List.sum_cons]
    rcases List.mem_cons.1 h with h | h
    · subst h; omega
    · have := single_le_sum f l i h; omega

/-- A request among at most `L` that satisfies `P`: the indicator is at most the sum over positions. -/
theorem ind_exists_le (P : Bytes → Prop) (keys : List Bytes) (L : Nat) (hL : keys.length ≤ L) :
    ind (∃ x ∈ keys, P x) ≤ ((List.range L).map (fun i => ind (i < keys.length ∧ P (keys.getD i [])))).sum := by
  by_cases h : ∃ x ∈ keys, P x
  · obtain ⟨x, hx, hp⟩ := h
    rw [ind_of ⟨x, hx, hp⟩]
    obtain ⟨i, hi, hxi⟩ := List.getElem_of_mem hx
    have hg : keys.getD i [] = x := by
      rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi, Option.getD_some, hxi]
    have hterm : ind (i < keys.length ∧ P (keys.getD i [])) = 1 := ind_of ⟨hi, by rw [hg]; exact hp⟩
    calc 1 = ind (i < keys.length ∧ P (keys.getD i [])) := hterm.symm
      _ ≤ _ := single_le_sum (fun i => ind (i < keys.length ∧ P (keys.getD i []))) _ _
          (List.mem_range.2 (by omega))
  · rw [ind_of_not h]; exact Nat.zero_le _

section
variable (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)

/-- **The game in the random-oracle model.** KS1 by requests to the KDF oracle, then C67's
    DSM game under the derived Smaster, whose Smaster-keyed derivations and the adversary's
    own KDF queries (`0xff ‖ z`, through `leak`) are answered by the same oracle. -/
def romGame (ws : Bytes) : FQT MOut :=
  ks1Rom c ws (fun _ wo _ so => mapFQ (gIn (so.getD 0 []))
    (dplay .spx256f limits [] [] [] (A (pubOf (wo.take 7 ++ [so.getD 1 []])))))

/-- What the adversary is given, read from the vector: the seven siblings and the at-rest key. -/
def pubV (ss : List Nat) : Bytes :=
  pubOf ((List.range 7).map (fun i => be 32 (ss.getD (i+1) 0)) ++ [be 32 (ss.getD 11 0)])

/-- C67's DSM game with what the adversary is given. -/
def refG (ss : List Nat) : FQT MOut := dplay .spx256f limits [] [] [] (A (pubV pubOf ss))

/-- The requests of C67's ideal game, with the remaining vector. -/
def keysOf (t ss : List Nat) : List Bytes :=
  (run t (resLlog [] (ss.drop 12) (refG limits A pubOf ss)) []).1.2.map Prod.fst

theorem romGame_eq (ws : Bytes) (ss : List Nat) :
    ∃ KS : RTab, (∀ z ∈ KS.map Prod.fst, z = hmIn saltW ws ∨ z = hmIn saltS0 (be 32 (ss.getD 8 0)) ∨
        (∃ m, z = hmIn (be 32 (ss.getD 0 0)) m) ∨ (∃ m, z = hmIn (be 32 (ss.getD 9 0)) m)) ∧
      resL [] ss (romGame limits A pubOf c ws) =
        resL KS (ss.drop 12) (mapFQ (gIn (be 32 (ss.getD 10 0))) (refG limits A pubOf ss)) := by
  obtain ⟨KS, hKS, he⟩ := resL_ks1Rom c ws (fun _ wo _ so => mapFQ (gIn (so.getD 0 []))
    (dplay .spx256f limits [] [] [] (A (pubOf (wo.take 7 ++ [so.getD 1 []]))))) ss
  refine ⟨KS, hKS, ?_⟩
  unfold romGame
  rw [he]
  have hw : (kideal (wSteps c) [] (ss.drop 1)).take 7 = (List.range 7).map (fun i => be 32 (ss.getD (i+1) 0)) := by
    rw [kideal_closed, List.nil_append, show (wSteps c).length = 8 from rfl, ← List.map_take, List.take_range,
      show min 7 8 = 7 from rfl]
    apply List.map_congr_left; intro i _
    rw [getD_drop', Nat.add_comm]
  have hs : ∀ sib, kideal (sSteps c sib) [] (ss.drop 10) = [be 32 (ss.getD 10 0), be 32 (ss.getD 11 0)] := by
    intro sib
    rw [kideal_closed, List.nil_append, show (sSteps c sib).length = 2 from rfl]
    show [be 32 ((ss.drop 10).getD 0 0), be 32 ((ss.drop 10).getD 1 0)] = _
    rw [getD_drop', getD_drop']
  rw [hw, hs]
  rfl

/-- **Per tape.** The game wins only if C67's ideal game wins, or one of the adversary's own
    KDF queries hits a value derived from the wallet seed. -/
theorem rom_point (ws : Bytes) (ss t : List Nat) :
    ind ((run t (resL [] ss (romGame limits A pubOf c ws)) []).1.win = true) ≤
      ind ((run t (resL [] (ss.drop 12) (refG limits A pubOf ss)) []).1.win = true) +
        ind (∃ x ∈ keysOf limits A pubOf t ss, hits ws (be 32 (ss.getD 8 0)) (be 32 (ss.getD 0 0))
          (be 32 (ss.getD 9 0)) (be 32 (ss.getD 10 0)) x) := by
  obtain ⟨KS, hKS, he⟩ := romGame_eq limits A pubOf c ws ss
  rw [he]
  have h := couple (fun o : MOut => o.win = true) (gIn (be 32 (ss.getD 10 0))) KS t (refG limits A pubOf ss) [] (ss.drop 12) []
  simp only [mapT, List.map_nil, List.append_nil] at h
  rw [← (run_resLlog t (refG limits A pubOf ss) [] (ss.drop 12) []).1]
  refine Nat.le_trans h (Nat.add_le_add_left (ind_mono (fun hb => ?_)) _)
  exact bad_hits ws _ _ _ _ (be_width 32 _) (be_width 32 _) (be_width 32 _) KS hKS _ hb

end

/-! Counting. -/

theorem drop_set_lt : ∀ (l : List Nat) (c n y : Nat), c < n → (l.set c y).drop n = l.drop n
  | [], _, _, _, _ => by simp
  | _ :: _, _, 0, _, h => absurd h (Nat.not_lt_zero _)
  | a :: l, 0, n+1, y, _ => by simp
  | a :: l, c+1, n+1, y, h => by
    simp only [List.set_cons_succ, List.drop_succ_cons]; exact drop_set_lt l c n y (by omega)

theorem be32_count (k : Bytes) : ((List.range (256^32)).map (fun y => if be 32 y = k then 1 else 0)).sum * 256^32 ≤ 256^32 := by
  have := inj_count 32 k
  calc _ ≤ 1 * 256^32 := Nat.mul_le_mul_right _ this
    _ = 256^32 := Nat.one_mul _

/-- One family of hits on coordinate `c`: at most a `1/M` fraction, per request. -/
theorem fam_coord (N L c : Nat) (hc : c < N) (w : Nat → List Nat → Nat) (g : Nat → List Nat → Bytes)
    (hw1 : ∀ i ss, w i ss ≤ 1) (hw : ∀ i ss y, w i (ss.set c y) = w i ss) (hg : ∀ i ss y, g i (ss.set c y) = g i ss) :
    tsum (256^32) N (fun ss => ((List.range L).map (fun i => w i ss *
        (if be 32 (ss.getD c 0) = g i ss then 1 else 0))).sum) * 256^32 ≤ (256^32)^N * L := by
  have h := hitsB_sum (256^32) (256^32) N (fun y => be 32 y) be32_count (List.range L) (fun _ => c)
    (fun _ _ => hc) w g (fun i _ ss y => hw i ss y) (fun i _ ss y _ => hg i ss y)
  refine Nat.le_trans h ?_
  calc _ ≤ tsum (256^32) N (fun _ => L) := tsum_mono _ _ (fun ss => by
          calc _ ≤ ((List.range L).map (fun _ => 1)).sum := sum_map_le _ (fun i _ => hw1 i ss)
            _ = L := by rw [sum_map_const, List.length_range, Nat.mul_one])
    _ = _ := tsum_const _ _ _

section
variable (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes)

/-- What the adversary sees does not read the secret coordinates `0, 8, 9, 10`. -/
theorem pubV_set (ss : List Nat) (c y : Nat) (hc : c = 0 ∨ c = 8 ∨ c = 9 ∨ c = 10) :
    pubV pubOf (ss.set c y) = pubV pubOf ss := by
  unfold pubV
  have h11 : (ss.set c y).getD 11 0 = ss.getD 11 0 := getD_set_ne _ _ _ _ (by omega)
  have hi : ∀ i ∈ List.range 7, be 32 ((ss.set c y).getD (i+1) 0) = be 32 (ss.getD (i+1) 0) := by
    intro i hi
    have := List.mem_range.1 hi
    rw [getD_set_ne _ _ _ _ (by omega)]
  rw [List.map_congr_left hi, h11]

theorem keysOf_set (t ss : List Nat) (c y : Nat) (hc : c = 0 ∨ c = 8 ∨ c = 9 ∨ c = 10) :
    keysOf limits A pubOf t (ss.set c y) = keysOf limits A pubOf t ss := by
  unfold keysOf refG
  rw [pubV_set pubOf ss c y hc, drop_set_lt _ _ _ _ (by omega)]

theorem keysOf_length (qh qn ql qs : Nat) (hA : ∀ a, DBudget (A a) qh qn ql qs) (t ss : List Nat) :
    (keysOf limits A pubOf t ss).length ≤ qn + ql := by
  obtain ⟨ext, he, hl⟩ := resLlog_ext ekDom t (refG limits A pubOf ss) qn ql
    (fc_dplay .spx256f limits _ qh qn ql qs (hA _) [] [] []) [] (ss.drop 12) []
  unfold keysOf; rw [he]; simpa using hl

/-- The weight of request `i`: it exists and is the adversary's own KDF query. -/
noncomputable def wq (t ss : List Nat) (i : Nat) : Nat :=
  ind (i < (keysOf limits A pubOf t ss).length ∧ ((keysOf limits A pubOf t ss).getD i []).head? = some 0xff)

/-- The query itself. -/
def zq (t ss : List Nat) (i : Nat) : Bytes := ((keysOf limits A pubOf t ss).getD i []).tail

theorem ifeq (a b : Bytes) : ind (a = b) = (if a = b then 1 else 0) := by
  by_cases h : a = b
  · rw [ind_of h, if_pos h]
  · rw [ind_of_not h, if_neg h]

/-- A hit at request `i` is one of the five families. -/
theorem hit_split (ws : Bytes) (ss t : List Nat) (i : Nat) :
    ind (i < (keysOf limits A pubOf t ss).length ∧ hits ws (be 32 (ss.getD 8 0)) (be 32 (ss.getD 0 0))
        (be 32 (ss.getD 9 0)) (be 32 (ss.getD 10 0)) ((keysOf limits A pubOf t ss).getD i [])) ≤
      wq limits A pubOf t ss i * (if ws = (zq limits A pubOf t ss i).drop 28 then 1 else 0) +
      wq limits A pubOf t ss i * (if be 32 (ss.getD 8 0) = (zq limits A pubOf t ss i).drop 24 then 1 else 0) +
      wq limits A pubOf t ss i * (if be 32 (ss.getD 0 0) = key32 (zq limits A pubOf t ss i) then 1 else 0) +
      wq limits A pubOf t ss i * (if be 32 (ss.getD 9 0) = key32 (zq limits A pubOf t ss i) then 1 else 0) +
      wq limits A pubOf t ss i * (if be 32 (ss.getD 10 0) = key32 (zq limits A pubOf t ss i) then 1 else 0) := by
  by_cases h : i < (keysOf limits A pubOf t ss).length ∧ hits ws (be 32 (ss.getD 8 0)) (be 32 (ss.getD 0 0))
      (be 32 (ss.getD 9 0)) (be 32 (ss.getD 10 0)) ((keysOf limits A pubOf t ss).getD i [])
  · rw [ind_of h]
    obtain ⟨hi, hr, hh⟩ := h
    have hw : wq limits A pubOf t ss i = 1 := ind_of ⟨hi, hr⟩
    rw [hw]
    unfold zq
    rcases hh with e | e | e | e | e
    · rw [if_pos e.symm]; omega
    · rw [if_pos e.symm]; omega
    · rw [if_pos e.symm]; omega
    · rw [if_pos e.symm]; omega
    · rw [if_pos e.symm]; omega
  · rw [ind_of_not h]; exact Nat.zero_le _

end

theorem sum_comm_lists {ι κ : Type} (f : ι → κ → Nat) (l2 : List κ) : ∀ (l1 : List ι),
    (l1.map (fun a => (l2.map (fun b => f a b)).sum)).sum = (l2.map (fun b => (l1.map (fun a => f a b)).sum)).sum
  | [] => by simp only [List.map_nil, List.sum_nil]; exact (sum_map_zero l2).symm
  | a :: l1 => by
    simp only [List.map_cons, List.sum_cons]
    rw [sum_comm_lists f l2 l1, ← sum_map_add]

/-- `pubV` reads only the first twelve coordinates. -/
theorem pubV_append (pubOf : List Bytes → Bytes) (a b : List Nat) (ha : a.length = 12) :
    pubV pubOf (a ++ b) = pubV pubOf a := by
  unfold pubV
  have g : ∀ j, j < 12 → (a ++ b).getD j 0 = a.getD j 0 := by
    intro j hj
    simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left (by omega : j < a.length)]
  have hi : ∀ i ∈ List.range 7, be 32 ((a ++ b).getD (i+1) 0) = be 32 (a.getD (i+1) 0) := by
    intro i hi; rw [g _ (by have := List.mem_range.1 hi; omega)]
  rw [List.map_congr_left hi, g 11 (by omega)]

/-- **The ideal part.** Summed over the vector, C67's ideal game (`dsm_ideal_256f`) with what
    the adversary is given read from the first twelve coordinates. -/
theorem href_bound (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (qh qn ql qs : Nat)
    (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (cc : Nat) (hc : 0 < cc) :
    let R := cc * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
    let N := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1
    tsum (256^32) (12 + (qn + ql)) (fun ss => tsum R N (fun t =>
        ind ((run t (resL [] (ss.drop 12) (refG limits A pubOf ss)) []).1.win = true))) * 256^32 ≤
      (256^32)^12 * ((256^32)^(qn + ql) * (R^N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023)))) := by
  intro R N
  rw [tsum_append (256^32) 12 (qn + ql)]
  have inner : ∀ a : List Nat, a.length = 12 →
      tsum (256^32) (qn + ql) (fun b => tsum R N (fun t =>
        ind ((run t (resL [] ((a ++ b).drop 12) (refG limits A pubOf (a ++ b))) []).1.win = true))) * 256^32 ≤
      (256^32)^(qn + ql) * (R^N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) := by
    intro a ha
    have e1 : ∀ b : List Nat, (a ++ b).drop 12 = b := fun b => List.drop_left' ha
    have e2 : ∀ b : List Nat, refG limits A pubOf (a ++ b) = refG limits A pubOf a := fun b => by
      unfold refG; rw [pubV_append pubOf a b ha]
    simp only [e1, e2]
    have hI := dsm_ideal_256f limits (fun _ => []) (fun _ => A (pubV pubOf a)) qh qn ql qs (fun _ => hA _) hqs cc hc
    simp only at hI
    rw [sum_map_const, List.length_range] at hI
    unfold refG
    have hpos : 0 < 256^32 := Nat.pow_pos (by decide)
    apply Nat.le_of_mul_le_mul_left _ hpos
    calc 256^32 * (tsum (256^32) (qn + ql) (fun b => tsum R N (fun t =>
            ind ((run t (resL [] b (dplay .spx256f limits [] [] [] (A (pubV pubOf a)))) []).1.win = true))) * 256^32)
        = 256^32 * tsum (256^32) (qn + ql) (fun b => tsum R N (fun t =>
            ind ((run t (resL [] b (dplay .spx256f limits [] [] [] (A (pubV pubOf a)))) []).1.win = true))) * 256^32 :=
          (Nat.mul_assoc _ _ _).symm
      _ ≤ _ := hI
      _ = _ := by rw [Nat.mul_assoc]
  rw [Nat.mul_comm, ← tsum_mul]
  calc _ ≤ tsum (256^32) 12 (fun _ => (256^32)^(qn + ql) * (R^N * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023)))) :=
        tsum_mono_len _ _ (fun a ha => by rw [Nat.mul_comm]; exact inner a ha)
    _ = _ := tsum_const _ _ _

/-- **One secret coordinate.** The adversary's requests hit a fresh uniform 32-byte value on at
    most a `1/2^256` fraction, per request. -/
theorem coord_family (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (R N L c : Nat)
    (hc : c = 0 ∨ c = 8 ∨ c = 9 ∨ c = 10) (proj : Bytes → Bytes) :
    tsum (256^32) (12 + L) (fun ss => tsum R N (fun t => ((List.range L).map (fun i =>
        wq limits A pubOf t ss i * (if be 32 (ss.getD c 0) = proj (zq limits A pubOf t ss i) then 1 else 0))).sum)) *
      256^32 ≤ R^N * ((256^32)^(12 + L) * L) := by
  rw [tsum_comm (256^32) R (12 + L) N, Nat.mul_comm, ← tsum_mul]
  calc _ ≤ tsum R N (fun _ => (256^32)^(12 + L) * L) := tsum_mono _ _ (fun t => by
        rw [Nat.mul_comm]
        exact fam_coord (12 + L) L c (by omega) (fun i ss => wq limits A pubOf t ss i)
          (fun i ss => proj (zq limits A pubOf t ss i)) (fun _ _ => ind_le_one _)
          (fun i ss y => by
            show wq limits A pubOf t (ss.set c y) i = wq limits A pubOf t ss i
            unfold wq; rw [keysOf_set limits A pubOf t ss c y hc])
          (fun i ss y => by
            show proj (zq limits A pubOf t (ss.set c y) i) = proj (zq limits A pubOf t ss i)
            unfold zq; rw [keysOf_set limits A pubOf t ss c y hc]))
    _ = _ := tsum_const _ _ _

/-- **The wallet seed.** The adversary's requests hit the Extract input of the wallet seed on at
    most a `β/2^256` fraction, per request. -/
theorem e_family (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (bip : Nat → Bytes) (β : Nat)
    (hβ : ∀ x, ((List.range (256^32)).map (fun e => if bip e = x then 1 else 0)).sum ≤ β) (R N L : Nat) :
    ((List.range (256^32)).map (fun e => tsum (256^32) (12 + L) (fun ss => tsum R N (fun t =>
        ((List.range L).map (fun i => wq limits A pubOf t ss i *
          (if bip e = (zq limits A pubOf t ss i).drop 28 then 1 else 0))).sum)))).sum ≤
      (256^32)^(12 + L) * (R^N * (L * β)) := by
  rw [← tsum_list]
  calc _ = tsum (256^32) (12 + L) (fun ss => tsum R N (fun t => ((List.range (256^32)).map (fun e =>
          ((List.range L).map (fun i => wq limits A pubOf t ss i *
            (if bip e = (zq limits A pubOf t ss i).drop 28 then 1 else 0))).sum)).sum)) := by
        apply tsum_congr_len; intro ss _; rw [← tsum_list]
    _ ≤ tsum (256^32) (12 + L) (fun _ => tsum R N (fun _ => L * β)) := tsum_mono _ _ (fun ss => tsum_mono _ _ (fun t => by
        rw [sum_comm_lists]
        calc _ ≤ ((List.range L).map (fun _ => β)).sum := sum_map_le _ (fun i _ => by
              rw [sum_map_mul]
              calc _ ≤ 1 * β := Nat.mul_le_mul (ind_le_one _) (hβ _)
                _ = β := Nat.one_mul _)
          _ = L * β := by rw [sum_map_const, List.length_range]))
    _ = _ := by rw [tsum_const, tsum_const]

/-! The bound. -/

/-- SPX256f's tape range and length, as in C66 and C67. -/
def RR (cc : Nat) : Nat := cc * 256^(3*(params .spx256f).n) * 256^(params .spx256f).m
def NN (qh qn qs : Nat) : Nat := (mQ (params .spx256f) qh qn qs + 1704962 * qs + 398862) + 1

/-- The count of winning SPHINCS+ tapes. -/
noncomputable def winW (R N : Nat) (T : QT MOut) : Nat := tsum R N (fun t => ind ((run t T []).1.win = true))

section
variable (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)

noncomputable def Bfam (R N L c' : Nat) (proj : Bytes → Bytes) (ss : List Nat) : Nat :=
  tsum R N (fun t => ((List.range L).map (fun i =>
    wq limits A pubOf t ss i * (if be 32 (ss.getD c' 0) = proj (zq limits A pubOf t ss i) then 1 else 0))).sum)

noncomputable def Bseed (R N L : Nat) (bip : Nat → Bytes) (e : Nat) (ss : List Nat) : Nat :=
  tsum R N (fun t => ((List.range L).map (fun i =>
    wq limits A pubOf t ss i * (if bip e = (zq limits A pubOf t ss i).drop 28 then 1 else 0))).sum)

theorem rom_split (qh qn ql qs : Nat) (hA : ∀ a, DBudget (A a) qh qn ql qs) (R N : Nat) (bip : Nat → Bytes)
    (e : Nat) (ss : List Nat) :
    winW R N (resL [] ss (romGame limits A pubOf c (bip e))) ≤
      winW R N (resL [] (ss.drop 12) (refG limits A pubOf ss)) + Bseed limits A pubOf R N (qn + ql) bip e ss +
        Bfam limits A pubOf R N (qn + ql) 8 (List.drop 24) ss +
        Bfam limits A pubOf R N (qn + ql) 0 key32 ss + Bfam limits A pubOf R N (qn + ql) 9 key32 ss +
        Bfam limits A pubOf R N (qn + ql) 10 key32 ss := by
  unfold winW Bseed Bfam
  rw [← tsum_add, ← tsum_add, ← tsum_add, ← tsum_add, ← tsum_add]
  apply tsum_mono; intro t
  have h1 := rom_point limits A pubOf c (bip e) ss t
  have h2 := ind_exists_le (hits (bip e) (be 32 (ss.getD 8 0)) (be 32 (ss.getD 0 0)) (be 32 (ss.getD 9 0))
    (be 32 (ss.getD 10 0))) (keysOf limits A pubOf t ss) (qn + ql) (keysOf_length limits A pubOf qh qn ql qs hA t ss)
  have h3 := sum_map_le (List.range (qn + ql)) (fun i _ => hit_split limits A pubOf (bip e) ss t i)
  rw [sum_map_add, sum_map_add, sum_map_add, sum_map_add] at h3
  omega

end

/-- **DSM's SPHINCS+ per-step keys, with KS1, in the random-oracle model.** HMAC-BLAKE3 and keyed
    BLAKE3 are one random oracle with domain-separated inputs (`hmIn`, `kbIn`), independent of
    the random oracle for SPHINCS+ hashing. The game: a uniform entropy `e < 2^256`, the wallet
    seed `bip e`, KS1 by oracle requests, then C67's DSM game under the derived Smaster; the
    adversary is given any function `pubOf` of the seven siblings and the at-rest key, and asks
    the oracle itself through `leak` (`0xff ‖ z`, at most `ql` requests together with the
    Smaster-keyed derivations it sees). With `β` a bound on how many entropies share a wallet
    seed:

        Pr[forge under some per-step key] ≤ (qn·(27·Q + 368023) + (qn + ql)·(β + 4)) / 2^256,

    `Q = qh + 17186·qn + 1704961·qs + 17523`. No computational assumption on the KDF is left. -/
theorem rom_forge_256f (limits : Limits) (A : Bytes → DAdv) (pubOf : List Bytes → Bytes) (c : WCtx)
    (bip : Nat → Bytes) (β : Nat) (hβ : ∀ x, ((List.range (256^32)).map (fun e => if bip e = x then 1 else 0)).sum ≤ β)
    (qh qn ql qs : Nat) (hA : ∀ a, DBudget (A a) qh qn ql qs) (hqs : qs ≤ 2^64) (cc : Nat) (hc : 0 < cc) :
    ((List.range (256^32)).map (fun e => tsum (256^32) (12 + (qn + ql)) (fun ss =>
        winW (RR cc) (NN qh qn qs) (resL [] ss (romGame limits A pubOf c (bip e)))))).sum * 2^256 ≤
      256^32 * (256^32)^(12 + (qn + ql)) * (RR cc)^(NN qh qn qs) *
        (qn * (27 * mQ (params .spx256f) qh qn qs + 368023) + (qn + ql) * (β + 4)) := by
  have e256 : (2:Nat)^256 = 256^32 := by decide
  rw [e256]
  -- the five pieces
  have hW := href_bound limits A pubOf qh qn ql qs hA hqs cc hc
  simp only at hW
  have hE := e_family limits A pubOf bip β hβ (RR cc) (NN qh qn qs) (qn + ql)
  have h8 := coord_family limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 8 (by omega) (List.drop 24)
  have h0 := coord_family limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 0 (by omega) key32
  have h9 := coord_family limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 9 (by omega) key32
  have h10 := coord_family limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 10 (by omega) key32
  -- the split, summed
  have hS := sum_map_le (List.range (256^32)) (fun e _ => tsum_mono (256^32) (12 + (qn + ql))
    (fun ss => rom_split limits A pubOf c qh qn ql qs hA (RR cc) (NN qh qn qs) bip e ss))
  simp only [tsum_add, sum_map_add, sum_map_const, List.length_range] at hS
  have hW' : tsum (256 ^ 32) (12 + (qn + ql)) (fun t =>
      winW (RR cc) (NN qh qn qs) (resL [] (List.drop 12 t) (refG limits A pubOf t))) * 256^32 ≤
      (256^32)^(12 + (qn + ql)) * ((RR cc)^(NN qh qn qs) * (qn * (27 * mQ (params .spx256f) qh qn qs + 368023))) := by
    rw [Nat.pow_add, Nat.mul_assoc]; exact hW
  have hE' : ((List.range (256 ^ 32)).map (fun a =>
      tsum (256 ^ 32) (12 + (qn + ql)) (Bseed limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) bip a))).sum ≤
      (256^32)^(12 + (qn + ql)) * ((RR cc)^(NN qh qn qs) * ((qn + ql) * β)) := hE
  have h8' : tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 8 (List.drop 24)) *
      256^32 ≤ (RR cc)^(NN qh qn qs) * ((256^32)^(12 + (qn + ql)) * (qn + ql)) := h8
  have h0' : tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 0 key32) *
      256^32 ≤ (RR cc)^(NN qh qn qs) * ((256^32)^(12 + (qn + ql)) * (qn + ql)) := h0
  have h9' : tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 9 key32) *
      256^32 ≤ (RR cc)^(NN qh qn qs) * ((256^32)^(12 + (qn + ql)) * (qn + ql)) := h9
  have h10' : tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 10 key32) *
      256^32 ≤ (RR cc)^(NN qh qn qs) * ((256^32)^(12 + (qn + ql)) * (qn + ql)) := h10
  clear hW hE h8 h0 h9 h10
  generalize ((List.range (256 ^ 32)).map (fun e => tsum (256 ^ 32) (12 + (qn + ql)) (fun ss =>
    winW (RR cc) (NN qh qn qs) (resL [] ss (romGame limits A pubOf c (bip e)))))).sum = X at hS ⊢
  generalize tsum (256 ^ 32) (12 + (qn + ql)) (fun t =>
    winW (RR cc) (NN qh qn qs) (resL [] (List.drop 12 t) (refG limits A pubOf t))) = TW at hS hW'
  generalize ((List.range (256 ^ 32)).map (fun a =>
    tsum (256 ^ 32) (12 + (qn + ql)) (Bseed limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) bip a))).sum = TE at hS hE'
  generalize tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 8 (List.drop 24)) = T8 at hS h8'
  generalize tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 0 key32) = T0 at hS h0'
  generalize tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 9 key32) = T9 at hS h9'
  generalize tsum (256 ^ 32) (12 + (qn + ql)) (Bfam limits A pubOf (RR cc) (NN qh qn qs) (qn + ql) 10 key32) = T10 at hS h10'
  generalize (256^32)^(12 + (qn + ql)) = p at hW' hE' h8' h0' h9' h10' ⊢
  generalize (RR cc)^(NN qh qn qs) = D at hW' hE' h8' h0' h9' h10' ⊢
  generalize qn * (27 * mQ (params .spx256f) qh qn qs + 368023) = b at hW' ⊢
  generalize qn + ql = L at hE' h8' h0' h9' h10' ⊢
  generalize (256:Nat)^32 = m at hS hW' h8' h0' h9' h10' ⊢
  calc X * m ≤ (m * TW + TE + m * T8 + m * T0 + m * T9 + m * T10) * m := Nat.mul_le_mul_right _ hS
    _ = m * (TW * m) + TE * m + m * (T8 * m) + m * (T0 * m) + m * (T9 * m) + m * (T10 * m) := by
        simp only [Nat.add_mul]; ac_rfl
    _ ≤ m * (p * (D * b)) + p * (D * (L * β)) * m + m * (D * (p * L)) + m * (D * (p * L)) +
          m * (D * (p * L)) + m * (D * (p * L)) :=
        Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (Nat.add_le_add
          (Nat.mul_le_mul_left _ hW') (Nat.mul_le_mul_right _ hE')) (Nat.mul_le_mul_left _ h8'))
          (Nat.mul_le_mul_left _ h0')) (Nat.mul_le_mul_left _ h9')) (Nat.mul_le_mul_left _ h10')
    _ = m * p * D * (b + L * (β + 4)) := by
        have e1 : m * (p * (D * b)) = m * p * D * b := by ac_rfl
        have e2 : p * (D * (L * β)) * m = m * p * D * (L * β) := by ac_rfl
        have e3 : m * (D * (p * L)) = m * p * D * L := by ac_rfl
        rw [e1, e2, e3]
        generalize m * p * D = Q
        rw [Nat.mul_add, Nat.mul_add L β 4, Nat.mul_add, ← Nat.mul_assoc Q L 4]
        omega

end DSM.Rom
