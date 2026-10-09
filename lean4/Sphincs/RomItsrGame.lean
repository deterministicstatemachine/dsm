-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomEval
import Sphincs.RomDigest

/- ITSR in the game (link 4, game level). The candidate targets are the
   adversary-side h_msg fresh draws (every adversary h_msg query and the
   verifier's, in order); the signature digests are the challenger-side
   h_msg fresh draws. Both roles are read off the run before each tape
   entry is read (`slotJ_pred`, by `run_prefix`), so they are a predictable
   selection. On a won game whose forged digest is ITSR-covered, the
   verifier's h_msg request was first drawn adversary-side: an h_msg request
   binds its message (fixed-width randomizer, seed and root), and a
   challenger-side h_msg draw is the signing request of a signed message
   (`play_hmsg`), which the win excludes. Every covering signature's digest
   is a challenger-side fresh draw unless its h_msg request was first drawn
   by the adversary (`RG`, a guess of the hidden randomizer, bounded with
   the hidden-value events). Hence the covered event, outside `RG`, is the
   covered event of one candidate under the adaptive selection, and
   `itsr_dsm_128f` / `itsr_dsm_256f` bound it per candidate. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-- The h_msg request for randomizer `r`, public seed and root, message. -/
def hreqR (p : Params) (r seed root msg : Bytes) : Request :=
  ⟨2,"DSM/sphincs/v2/h-msg",[],r ++ seed ++ root ++ msg,p.m⟩

/-- The h_msg request `sign` issues for `msg` under `sk`. -/
def hreqOf (o : Oracle Id) (v : Variant) (sk msg : Bytes) : Request :=
  hreqR (params v)
    (keyed o (params v).n (deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (sk.drop (3*(params v).n)) msg

/-- A logging run only appends. -/
def Ext {α : Type} (x : LogM α) : Prop := ∀ s, ∃ L, (x.run s).2 = s ++ L
/-- A request is in the log after the run, from any log. -/
def Mem {α : Type} (q : Request) (x : LogM α) : Prop := ∀ s, q ∈ (x.run s).2

theorem ext_cost {α : Type} {x : LogM α} {c : Nat} (h : Cost x c) : Ext x := fun s => by
  obtain ⟨L, e, _⟩ := h s; exact ⟨L, e⟩
theorem ext_pure {α : Type} (a : α) : Ext (pure a : LogM α) := fun s => ⟨[], by simp; rfl⟩
theorem ext_bind {α β : Type} {x : LogM α} {f : α → LogM β} (hx : Ext x) (hf : ∀ a, Ext (f a)) :
    Ext (x >>= f) := fun s => by
  obtain ⟨L₁, e₁⟩ := hx s
  obtain ⟨L₂, e₂⟩ := hf (x.run s).1 (x.run s).2
  exact ⟨L₁ ++ L₂, by rw [logM_run_bind, e₂, e₁, List.append_assoc]⟩
theorem ext_ite {α : Type} {c : Prop} [Decidable c] {x y : LogM α} (hx : Ext x) (hy : Ext y) :
    Ext (if c then x else y) := by
  by_cases h : c
  · simp only [h, if_true]; exact hx
  · simp only [h, if_false]; exact hy
theorem mem_oracle_here {β : Type} (o : Oracle Id) (r : Request) (f : Bytes → LogM β) (hf : ∀ a, Ext (f a)) :
    Mem r (logOracle o r >>= f) := fun s => by
  rw [logM_run_bind, logOracle_run]
  obtain ⟨L, e⟩ := hf (o r) (s ++ [r])
  simp only at e ⊢
  rw [e]; simp
theorem mem_oracle_bind {β : Type} (o : Oracle Id) (r q : Request) (f : Bytes → LogM β) (h : Mem q (f (o r))) :
    Mem q (logOracle o r >>= f) := fun s => by
  rw [logM_run_bind, logOracle_run]; exact h _
theorem mem_pure_bind {α β : Type} (a : α) (q : Request) (f : α → LogM β) (h : Mem q (f a)) :
    Mem q ((pure a : LogM α) >>= f) := fun s => h s

theorem sign_log_mem (o : Oracle Id) (v : Variant) (sk msg : Bytes) (hne : msg.isEmpty = false)
    (hsk : sk.length = 4*(params v).n) : Mem (hreqOf o v sk msg) (sign (logOracle o) v sk msg) := by
  have hc : (msg.isEmpty || sk.length != 4*(params v).n) = false := by simp [hne, hsk]
  simp only [sign, hc, Bool.false_eq_true, if_false]
  refine mem_pure_bind _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_bind _ _ _ _ (mem_oracle_bind _ _ _ _
    (mem_oracle_bind _ _ _ _ (mem_oracle_here _ _ _ ?_)))))
  intro dg
  exact ext_bind (ext_cost (forsSign_cost _ _)) (fun fs => ext_bind (ext_cost (forsPkFromSig_cost _ _ _))
    (fun fpk => ext_bind (ext_cost (htSign_cost _ _ _)) (fun hs => ext_bind (ext_cost (htRoot_cost _ _ _ _))
      (fun ac => ext_ite (ext_pure _) (ext_bind (ext_pure _) (fun _ => ext_pure _))))))
theorem kreq_mode {o : Oracle Id} {p : Params} {tk prfKey seed : Bytes} {r : Request}
    (h : KReq o p tk prfKey seed r) : r.mode = 1 := by
  rcases h with ⟨a, x, _, rfl, _⟩ | ⟨a, _, rfl⟩ <;> rfl

/-- Every h_msg-mode request of a signing run is the one for its message. -/
theorem sign_good_h2 (o : Oracle Id) (v : Variant) (sk msg : Bytes) :
    Good (fun r => r.mode = 2 → r = hreqOf o v sk msg) (sign (logOracle o) v sk msg) (sign o v sk msg) := by
  obtain ⟨hlen, hH, hd, hMA, hA, hT⟩ := variant_bounds v
  have lift : ∀ r, KReq o (params v)
      (deriveKey o "DSM/sphincs/v2/thash" (slice sk (2*(params v).n) (params v).n))
      (deriveKey o "DSM/sphincs/v2/prf" (sk.take (params v).n))
      (slice sk (2*(params v).n) (params v).n) r → (r.mode = 2 → r = hreqOf o v sk msg) :=
    fun r h hm => absurd (kreq_mode h) (by rw [hm]; decide)
  simp only [sign]
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  apply Good.bind_id (Good.pure_id _)
  refine Good.bind_id (Good.oracle o (fun h => absurd h (by simp))) ?_
  refine Good.bind_id (Good.oracle o (fun h => absurd h (by simp))) ?_
  refine Good.bind_id (Good.oracle o (fun h => absurd h (by simp))) ?_
  refine Good.bind_id (Good.oracle o (fun h => absurd h (by simp))) ?_
  refine Good.bind_id (Good.oracle o (fun _ => rfl)) ?_
  have ht := Nat.lt_of_lt_of_le (digest_tree_bounded (params v) (hmsg o (params v)
    (keyed o (params v).n (deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (List.drop (3*(params v).n) sk) msg)) hT
  have hleaf := digest_leaf_bounded (params v) (hmsg o (params v)
    (keyed o (params v).n (deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk (params v).n (params v).n))
      (slice sk (2*(params v).n) (params v).n ++ msg))
    (slice sk (2*(params v).n) (params v).n) (List.drop (3*(params v).n) sk) msg)
  have hleaf' := Nat.lt_of_lt_of_le hleaf hH
  apply Good.bind_id (Good.mono lift (forsSign_good 0 _ _ _ (by decide) ht hleaf' hMA hA))
  apply Good.bind_id (Good.mono lift (forsPkFromSig_good 0 _ _ _ _ (by decide) ht hleaf' hMA hA
    (fun _ => rfl)))
  apply Good.bind_id (Good.mono lift (htSign_good hlen hH _ _ _ hd ht hleaf))
  apply Good.bind_id (Good.mono lift (htRoot_good hlen hH _ _ _ _ hd ht hleaf (fun _ => rfl)))
  apply Good.ite' (fun _ => Good.pure' _)
  intro _
  apply Good.bind_id (Good.pure_id _)
  exact Good.pure' _

/-- Key generation after the expansion issues no h_msg-mode request. -/
theorem kgTail_good_no2 (O : Oracle Id) (v : Variant) (ex : Bytes) :
    Good (fun r => r.mode ≠ 2) (kgTail (logOracle O) v ex) (keypairFromExpansion O v ex) := by
  obtain ⟨hlen, hH, hd, _, _, _⟩ := variant_bounds v
  refine Good.congr_val (v := kgTail O v ex) ?_ rfl
  simp only [kgTail]
  refine Good.bind_id (Good.oracle O (by simp)) ?_
  refine Good.bind_id (Good.oracle O (by simp)) ?_
  apply Good.bind_id (Good.mono (fun r h => by rw [kreq_mode h]; decide)
    (xmssNode_good _ (params v).hp hH (by dsimp only; omega) (by show 0 < 256^8; decide) hlen _ 0
      (Nat.le_refl _) (by simp)))
  exact Good.pure' _


theorem fill_keep : ∀ (t : List Nat) (slot : List Nat → Option Nat) (out : List Nat) (s : Nat),
    (∀ i, i < t.length → slot (t.take i) ≠ some s) → (fill slot out t).getD s 0 = out.getD s 0
  | [], _, _, _, _ => rfl
  | y :: t, slot, out, s, h => by
    simp only [fill]
    rw [fill_keep t (shift slot y) (place slot out y) s (fun i hi => h (i+1) (by simp; omega))]
    unfold place
    split
    · next s' hs' =>
      have hne : s' ≠ s := fun e => h 0 (by simp) (by simpa [e] using hs')
      simp [List.getD_eq_getElem?_getD, hne]
    · rfl

theorem fill_get : ∀ (t : List Nat) (slot : List Nat → Option Nat) (out : List Nat) (s i : Nat),
    (∀ i i', i < t.length → i' < t.length → slot (t.take i) = some s → slot (t.take i') = some s → i = i') →
    i < t.length → slot (t.take i) = some s → s < out.length →
    (fill slot out t).getD s 0 = t.getD i 0 + 1
  | [], _, _, _, _, _, hi, _, _ => absurd hi (by simp)
  | y :: t, slot, out, s, 0, hd, _, hs, hlen => by
    simp only [fill]
    rw [fill_keep t (shift slot y) (place slot out y) s (fun i hi e =>
      absurd (hd 0 (i+1) (by simp) (by simp; omega) hs e) (by omega))]
    simp only [List.take_zero] at hs
    simp [place, hs, List.getD_eq_getElem?_getD, hlen]
  | y :: t, slot, out, s, i+1, hd, hi, hs, hlen => by
    simp only [fill]
    rw [fill_get t (shift slot y) (place slot out y) s i
      (fun a b ha hb ea eb => by
        have := hd (a+1) (b+1) (by simp; omega) (by simp; omega) ea eb; omega)
      (by simp at hi; omega) hs (by unfold place; split <;> simp [hlen])]
    rfl

theorem assigned_eq : ∀ (t : List Nat) (slot : List Nat → Option Nat),
    assigned slot t = (List.range t.length).filterMap (fun i => slot (t.take i))
  | [], _ => rfl
  | y :: t, slot => by
    simp only [assigned, List.length_cons, List.range_succ_eq_map, List.filterMap_cons, List.take_zero]
    rw [assigned_eq t (shift slot y), List.filterMap_map]
    cases h : slot [] <;> rfl

theorem nodup_filterMap {β : Type} (f : Nat → Option β) : ∀ (l : List Nat), l.Nodup →
    (∀ a a' b, a ∈ l → a' ∈ l → f a = some b → f a' = some b → a = a') → (l.filterMap f).Nodup
  | [], _, _ => List.nodup_nil
  | a :: l, nd, h => by
    have nd' := (List.nodup_cons.mp nd)
    have ih := nodup_filterMap f l nd'.2 (fun x y b hx hy => h x y b (by simp [hx]) (by simp [hy]))
    simp only [List.filterMap_cons]
    cases hf : f a with
    | none => exact ih
    | some b =>
      refine List.nodup_cons.mpr ⟨fun hb => ?_, ih⟩
      obtain ⟨a', ha', hb'⟩ := List.mem_filterMap.mp hb
      have := h a a' b (by simp) (by simp [ha']) hf hb'
      exact nd'.1 (this ▸ ha')

theorem assigned_spec (t : List Nat) (slot : List Nat → Option Nat) (q : Nat)
    (hd : ∀ i i' s, i < t.length → i' < t.length → slot (t.take i) = some s → slot (t.take i') = some s → i = i')
    (hq : ∀ i s, i < t.length → slot (t.take i) = some s → s < q+1) :
    (assigned slot t).Nodup ∧ ∀ s ∈ assigned slot t, s < q+1 := by
  rw [assigned_eq]
  refine ⟨nodup_filterMap _ _ List.nodup_range (fun a a' b ha ha' ea eb =>
      hd a a' b (List.mem_range.mp ha) (List.mem_range.mp ha') ea eb), fun s hs => ?_⟩
  obtain ⟨i, hi, he⟩ := List.mem_filterMap.mp hs
  exact hq i s (List.mem_range.mp hi) he

/-! Draw roles and slots. -/

/-- Adversary-side h_msg draw. -/
def isA (e : Draw) : Bool := e.1 && e.2.mode == 2
/-- Challenger-side h_msg draw. -/
def isC (e : Draw) : Bool := !e.1 && e.2.mode == 2
/-- Draws before position `i` with property `P`. -/
def cnt (P : Draw → Bool) (D : List Draw) (i : Nat) : Nat := ((D.take i).filter P).length

theorem cnt_succ (P : Draw → Bool) (D : List Draw) (i : Nat) :
    cnt P D (i+1) = cnt P D i + ((D[i]?.toList).filter P).length := by
  unfold cnt; rw [List.take_succ, List.filter_append, List.length_append]

theorem cnt_mono (P : Draw → Bool) (D : List Draw) (i : Nat) : ∀ k, cnt P D i ≤ cnt P D (i+k)
  | 0 => Nat.le_refl _
  | k+1 => by rw [← Nat.add_assoc, cnt_succ]; exact Nat.le_trans (cnt_mono P D i k) (Nat.le_add_right _ _)

theorem cnt_lt (P : Draw → Bool) (D : List Draw) (i i' : Nat) (e : Draw) (he : D[i]? = some e)
    (hp : P e = true) (hii : i < i') : cnt P D i < cnt P D i' := by
  have h1 : cnt P D (i+1) = cnt P D i + 1 := by rw [cnt_succ, he]; simp [hp]
  have h2 := cnt_mono P D (i+1) (i' - (i+1))
  rw [show i + 1 + (i' - (i+1)) = i' by omega] at h2
  omega

theorem cnt_lt_total (P : Draw → Bool) (D : List Draw) (i : Nat) (e : Draw) (he : D[i]? = some e)
    (hp : P e = true) : cnt P D i < (D.filter P).length := by
  have hi : i < D.length := (List.getElem?_eq_some_iff.mp he).1
  have := cnt_lt P D i D.length e he hp hi
  unfold cnt at this; rw [List.take_length] at this; exact this

/-- The slot of position `i`: the `j`-th adversary-side h_msg draw is the
    target (slot 0); the `c`-th challenger-side h_msg draw, `c < q`, is
    signature slot `c+1`. -/
def slotOf (j q : Nat) (D : List Draw) (i : Nat) : Option Nat :=
  match D[i]? with
  | some e => if isA e then (if cnt isA D i = j then some 0 else none)
      else if isC e then (if cnt isC D i < q then some (cnt isC D i + 1) else none) else none
  | none => none

theorem slotOf_some (j q : Nat) (D : List Draw) (i s : Nat) (h : slotOf j q D i = some s) :
    ∃ e, D[i]? = some e ∧ ((isA e = true ∧ cnt isA D i = j ∧ s = 0) ∨
      (isC e = true ∧ cnt isC D i < q ∧ s = cnt isC D i + 1)) := by
  unfold slotOf at h
  cases he : D[i]? with
  | none => rw [he] at h; cases h
  | some e =>
    rw [he] at h
    refine ⟨e, rfl, ?_⟩
    simp only at h
    split at h
    · next ha => split at h
                 · next hc => exact Or.inl ⟨ha, hc, (Option.some.inj h).symm⟩
                 · cases h
    · split at h
      · next hc => split at h
                   · next hq => exact Or.inr ⟨hc, hq, (Option.some.inj h).symm⟩
                   · cases h
      · cases h

theorem isA_isC (e : Draw) (ha : isA e = true) (hc : isC e = true) : False := by
  simp only [isA, isC, Bool.and_eq_true, Bool.not_eq_true'] at ha hc
  rw [ha.1] at hc; cases hc.1

theorem slotOf_inj (j q : Nat) (D : List Draw) (i i' s : Nat) (h : slotOf j q D i = some s)
    (h' : slotOf j q D i' = some s) : i = i' := by
  obtain ⟨e, he, hc⟩ := slotOf_some j q D i s h
  obtain ⟨e', he', hc'⟩ := slotOf_some j q D i' s h'
  rcases Nat.lt_trichotomy i i' with hl | hl | hl
  · exfalso
    rcases hc with ⟨ha, hj, hs⟩ | ⟨hcc, hq, hs⟩ <;> rcases hc' with ⟨ha', hj', hs'⟩ | ⟨hcc', hq', hs'⟩
    · have := cnt_lt isA D i i' e he ha hl; omega
    · omega
    · omega
    · have := cnt_lt isC D i i' e he hcc hl; omega
  · exact hl
  · exfalso
    rcases hc with ⟨ha, hj, hs⟩ | ⟨hcc, hq, hs⟩ <;> rcases hc' with ⟨ha', hj', hs'⟩ | ⟨hcc', hq', hs'⟩
    · have := cnt_lt isA D i' i e' he' ha' hl; omega
    · omega
    · omega
    · have := cnt_lt isC D i' i e' he' hcc' hl; omega

theorem slotOf_take (j q : Nat) (D : List Draw) (i : Nat) : slotOf j q (D.take (i+1)) i = slotOf j q D i := by
  unfold slotOf cnt
  rw [List.getElem?_take, if_pos (Nat.lt_succ_self i), List.take_take, Nat.min_eq_left (Nat.le_succ i)]

/-! First draws. -/

theorem findDraw_of_mem : ∀ (D : List Draw) (r : Request), (∃ e ∈ D, e.2 = r) → ∃ i, findDraw D r = some i
  | [], _, h => by obtain ⟨e, he, _⟩ := h; cases he
  | x :: D, r, h => by
    simp only [findDraw]
    split
    · exact ⟨0, rfl⟩
    · next hx =>
      obtain ⟨e, he, hr⟩ := h
      rcases List.mem_cons.mp he with rfl | he
      · exact absurd ((req_beq_iff _ _).mpr hr) hx
      · obtain ⟨i, hi⟩ := findDraw_of_mem D r ⟨e, he, hr⟩
        exact ⟨i+1, by rw [hi]; rfl⟩

theorem findDraw_get : ∀ (D : List Draw) (r : Request) (i : Nat), findDraw D r = some i →
    ∃ e, D[i]? = some e ∧ e.2 = r
  | [], _, _, h => by simp [findDraw] at h
  | x :: D, r, i, h => by
    simp only [findDraw] at h
    split at h
    · next hx => obtain rfl := Option.some.inj h; exact ⟨x, rfl, (req_beq_iff _ _).mp hx⟩
    · cases hd : findDraw D r with
      | none => rw [hd] at h; cases h
      | some j =>
        rw [hd] at h; obtain rfl := Option.some.inj h
        exact findDraw_get D r j hd

theorem oracleOf_at (t : List Nat) (D : List Draw) (r : Request) (i : Nat) (h : findDraw D r = some i) :
    oracleOf t D r = be r.outLen (t.getD i 0) := by
  unfold oracleOf; rw [h]

/-! Challenger-side h_msg draws are signing requests of signed messages. -/

theorem drop_extend (d E E' : List Draw) : (d ++ E ++ E').drop d.length = E ++ E' := by
  rw [List.append_assoc, List.drop_left]

theorem play_hmsg (t : List Nat) (v : Variant) (limits : Limits) (pk sk : Bytes)
    (hsk : sk.length = 4*(params v).n) :
    ∀ (A : RAdv) (signed : List Bytes) (d D : List Draw),
    Pre (run t (playQT v limits pk sk A signed) d).2 D →
    (∀ m ∈ signed, m ∈ (run t (playQT v limits pk sk A signed) d).1.signed) ∧
    (∀ e ∈ (run t (playQT v limits pk sk A signed) d).2.drop d.length, e.1 = false → e.2.mode = 2 →
      ∃ m ∈ (run t (playQT v limits pk sk A signed) d).1.signed, e.2 = hreqOf (oracleOf t D) v sk m) ∧
    (∀ m ∈ (run t (playQT v limits pk sk A signed) d).1.signed, m ∉ signed →
      ∃ e ∈ (run t (playQT v limits pk sk A signed) d).2, e.2 = hreqOf (oracleOf t D) v sk m)
  | .hq r k, signed, d, D, hD => by
    simp only [playQT, run] at hD ⊢
    cases hf : findDraw d r with
    | some i =>
      simp only [hf] at hD ⊢
      exact play_hmsg t v limits pk sk hsk (k _) signed d D hD
    | none =>
      simp only [hf] at hD ⊢
      obtain ⟨h1, h2, h3⟩ := play_hmsg t v limits pk sk hsk (k _) signed (d ++ [(true, r)]) D hD
      refine ⟨h1, fun e he hg hm => ?_, h3⟩
      obtain ⟨E, hE⟩ := pre_run t (playQT v limits pk sk (k (be r.outLen (t.getD d.length 0))) signed)
        (d ++ [(true, r)])
      rw [hE, drop_extend] at he
      rcases List.mem_append.mp he with h | h
      · simp at h; rw [h] at hg; cases hg
      · apply h2 e _ hg hm
        rw [hE, List.drop_left]; exact h
  | .sq m k, signed, d, D, hD => by
    simp only [playQT] at hD ⊢
    split
    · next hl =>
      rw [if_pos hl] at hD
      rw [run_bind] at hD ⊢
      have hq : QL false t (sign challengerOracle v sk m) (fun O => sign (logOracle O) v sk m) := ql_sign false v sk m
      have hpre : Pre (run t (sign challengerOracle v sk m) d).2 D := Pre.trans (pre_run t _ _) hD
      obtain ⟨L, eL, mL, nL⟩ := hq d D hpre []
      obtain ⟨L', eL', pL'⟩ := sign_good_h2 (oracleOf t D) v sk m []
      rw [eL] at eL'
      have hLL : L = L' := by simpa using (Prod.mk.inj eL').2
      obtain ⟨h1, h2, h3⟩ := play_hmsg t v limits pk sk hsk (k _) (signed ++ [m]) _ D hD
      refine ⟨fun x hx => h1 x (List.mem_append_left _ hx), fun e he hg hm => ?_, fun x hx hn => ?_⟩
      · obtain ⟨E₁, hE₁⟩ := pre_run t (sign challengerOracle v sk m) d
        obtain ⟨E₂, hE₂⟩ := pre_run t (playQT v limits pk sk (k (run t (sign challengerOracle v sk m) d).1)
          (signed ++ [m])) (run t (sign challengerOracle v sk m) d).2
        rw [hE₂, hE₁, drop_extend] at he
        rcases List.mem_append.mp he with h | h
        · have hn := nL e (by rw [hE₁, List.drop_left]; exact h)
          refine ⟨m, h1 m (by simp), ?_⟩
          exact pL' e.2 (hLL ▸ hn.1) hm
        · apply h2 e _ hg hm
          rw [hE₂, List.drop_left]; exact h
      · by_cases hxm : x = m
        · subst hxm
          have hmem : hreqOf (oracleOf t D) v sk x ∈ L := by
            have := sign_log_mem (oracleOf t D) v sk x (by
              simp only [legal, Bool.and_eq_true, Bool.not_eq_true'] at hl; exact hl.1) hsk []
            rw [eL] at this; simpa using this
          obtain ⟨e, he, her⟩ := mL _ hmem
          obtain ⟨E₂, hE₂⟩ := pre_run t (playQT v limits pk sk (k (run t (sign challengerOracle v sk x) d).1)
            (signed ++ [x])) (run t (sign challengerOracle v sk x) d).2
          exact ⟨e, by rw [hE₂]; exact List.mem_append_left _ he, her⟩
        · exact h3 x hx (by simp [hn, hxm])
    · next hl =>
      rw [if_neg hl] at hD
      exact play_hmsg t v limits pk sk hsk (k none) signed d D hD
  | .out m s, signed, d, D, hD => by
    simp only [playQT] at hD ⊢
    rw [run_bind] at hD ⊢
    simp only [run] at hD ⊢
    refine ⟨fun x hx => hx, fun e he hg _ => ?_, fun x _ hn => absurd ‹_› hn⟩
    have hq : QL true t (verify advQ v pk m s) (fun O => verify (logOracle O) v pk m s) := ql_verify true v pk m s
    obtain ⟨L, -, -, nL⟩ := hq d D hD []
    rw [(nL e he).2] at hg; cases hg

/-! The game, its draws and its key. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- The H1 game on tape `t`, from the coin entries. -/
def runG (t : List Nat) : Out × List Draw :=
  run t (gameQT v limits A (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))

/-- The run's final oracle table. -/
def finO (t : List Nat) : Oracle Id := oracleOf t (runG v limits A t).2

/-- The honest key pair under the final table. -/
def finKey (t : List Nat) : Bytes × Bytes :=
  keypairFromExpansion (finO v limits A t) v (sres t (coinEx (params v).n))

theorem runG_split (t : List Nat) :
    runG v limits A t = run t (playQT v limits
      (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).1.1
      (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).1.2
      (A (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).1.1) [])
      (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2 := by
  show run t (QT.bind _ _) _ = _
  rw [run_bind]

theorem kg_pre (t : List Nat) :
    Pre (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2
      (runG v limits A t).2 := by
  rw [runG_split]; exact pre_run t _ _

theorem kg_value (t : List Nat) :
    (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).1 =
      finKey v limits A t := by
  have hk : QL false t (kgTail challengerOracle v (sres t (coinEx (params v).n)))
      (fun O => kgTail (logOracle O) v (sres t (coinEx (params v).n))) := ql_kgTail false v _
  exact (ql_value hk _ _ (kg_pre v limits A t) (kgTail_good (finO v limits A t) v _)).1

theorem runG_play (t : List Nat) :
    runG v limits A t = run t (playQT v limits (finKey v limits A t).1 (finKey v limits A t).2
      (A (finKey v limits A t).1) [])
      (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2 := by
  conv => lhs; rw [runG_split]
  rw [kg_value]

theorem finKey_len (t : List Nat) : (finKey v limits A t).2.length = 4*(params v).n := by
  have hw : OutputWidths (finO v limits A t) := fun r => oracleOf_len t _ r
  simp only [finKey, keypairFromExpansion, List.length_append, coinEx_len,
    xmss_node_width _ hw]
  omega

/-- Every challenger-side h_msg draw of the game is the signing request of a
    signed message, and every signed message's signing request was drawn. -/
theorem game_hmsg (t : List Nat) :
    (∀ e ∈ (runG v limits A t).2, isC e = true →
      ∃ m ∈ (runG v limits A t).1.signed, e.2 = hreqOf (finO v limits A t) v (finKey v limits A t).2 m) ∧
    (∀ m ∈ (runG v limits A t).1.signed,
      ∃ e ∈ (runG v limits A t).2, e.2 = hreqOf (finO v limits A t) v (finKey v limits A t).2 m) := by
  have hpl := play_hmsg t v limits (finKey v limits A t).1 (finKey v limits A t).2 (finKey_len v limits A t)
    (A (finKey v limits A t).1) []
    (run t (kgTail challengerOracle v (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))).2
    (runG v limits A t).2 (by rw [← runG_play]; exact ⟨[], by simp⟩)
  rw [← runG_play] at hpl
  obtain ⟨-, h2, h3⟩ := hpl
  refine ⟨fun e he hc => ?_, fun m hm => h3 m hm (by simp)⟩
  have hcm : e.1 = false ∧ e.2.mode = 2 := by
    simp only [isC, Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at hc; exact hc
  -- locate e: coins, key generation, or the play
  obtain ⟨E₁, hE₁⟩ := pre_run t (kgTail challengerOracle v (sres t (coinEx (params v).n)))
    (resD t (coinSt (params v).n))
  obtain ⟨E₂, hE₂⟩ := kg_pre v limits A t
  have hD : (runG v limits A t).2 = resD t (coinSt (params v).n) ++ E₁ ++ E₂ := by rw [hE₂, hE₁]
  rw [hD] at he
  rcases List.mem_append.mp he with h | h
  · rcases List.mem_append.mp h with h | h
    · exfalso
      simp only [resD, coinSt, List.map_cons, List.map_nil, List.mem_cons, List.not_mem_nil, or_false] at h
      rcases h with rfl | rfl | rfl <;> simp [coin, SReq.res] at hcm
    · exfalso
      have hk : QL false t (kgTail challengerOracle v (sres t (coinEx (params v).n)))
          (fun O => kgTail (logOracle O) v (sres t (coinEx (params v).n))) := ql_kgTail false v _
      obtain ⟨L, eL, -, nL⟩ := hk _ _ (kg_pre v limits A t) []
      obtain ⟨L', eL', pL'⟩ := kgTail_good_no2 (finO v limits A t) v (sres t (coinEx (params v).n)) []
      unfold finO at eL'
      rw [eL] at eL'
      have hLL : L = L' := by simpa using (Prod.mk.inj eL').2
      have hn := nL e (by rw [hE₁, List.drop_left]; exact h)
      exact pL' e.2 (hLL ▸ hn.1) hcm.2
  · apply h2 e _ hcm.1 hcm.2
    rw [hE₂, List.drop_left]; exact h

/-- On a won game: the forgery verifies under the final table against the
    honest key, the message is legal and unsigned, and the verifier's
    requests were drawn. -/
theorem game_win (t : List Nat) (hw : (runG v limits A t).1.win = true) :
    verify (finO v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg (runG v limits A t).1.sig
      = some true ∧
    (runG v limits A t).1.signed.contains (runG v limits A t).1.msg = false ∧
    ∀ r ∈ verifyLog (finO v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
      (runG v limits A t).1.sig, ∃ e ∈ (runG v limits A t).2, e.2 = r := by
  have hw' := hw
  rw [runG_play] at hw'
  have hp := play_extract t v limits (finKey v limits A t).1 (finKey v limits A t).2
    (A (finKey v limits A t).1) [] _ hw' (runG v limits A t).2 (by rw [← runG_play]; exact ⟨[], by simp⟩)
  rw [← runG_play] at hp
  obtain ⟨h1, -, h3, h4⟩ := hp
  exact ⟨h1, h3, h4⟩
end

/-! Predictable slots. -/

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- The slot of the next tape entry, read off the run on the entries so far. -/
def slotJ (j q : Nat) (pre : List Nat) : Option Nat := slotOf j q (runG v limits A pre).2 pre.length

theorem coin_take (t : List Nat) (n i : Nat) (hi : 3 ≤ i) :
    sres (t.take i) (coinEx n) = sres t (coinEx n) ∧ resD (t.take i) (coinSt n) = resD t (coinSt n) := by
  have g0 := getD_take (t := t) (show 0 < i by omega)
  have g1 := getD_take (t := t) (show 1 < i by omega)
  have g2 := getD_take (t := t) (show 2 < i by omega)
  simp only [List.getD_eq_getElem?_getD] at g0 g1 g2
  constructor
  · simp [coinEx, sres, SV.res, g0, g1, g2]
  · simp [resD, coinSt, coin, SReq.res, sres, SV.res, g0, g1, g2]

theorem slotOf_coin (j q : Nat) (t : List Nat) (n : Nat) (D : List Draw) (hD : Pre (resD t (coinSt n)) D)
    (i : Nat) (hi : i < 3) : slotOf j q D i = none := by
  obtain ⟨E, rfl⟩ := hD
  have hl : i < (resD t (coinSt n)).length := by simp [resD, coinSt]; omega
  unfold slotOf
  rw [List.getElem?_append_left hl]
  have hmode : ∀ e ∈ resD t (coinSt n), e.2.mode = 999 := by
    intro e he
    simp only [resD, coinSt, List.map_cons, List.map_nil, List.mem_cons, List.not_mem_nil, or_false] at he
    rcases he with rfl | rfl | rfl <;> rfl
  cases he : (resD t (coinSt n))[i]? with
  | none => rfl
  | some e =>
    have hm := hmode e (mem_of_getElem? he)
    have ha : isA e = false := by simp [isA, hm]
    have hc : isC e = false := by simp [isC, hm]
    simp [ha, hc]

theorem slotJ_pred (j q : Nat) (t : List Nat) (i : Nat) (hi : i ≤ t.length) :
    slotJ v limits A j q (t.take i) = slotOf j q (runG v limits A t).2 i := by
  unfold slotJ
  rw [List.length_take, Nat.min_eq_left hi]
  by_cases h3 : 3 ≤ i
  · obtain ⟨c1, c2⟩ := coin_take t (params v).n i h3
    unfold runG
    rw [c1, c2]
    have hp := run_prefix (t.take i) t i (by rw [List.take_take, Nat.min_self])
      (gameQT v limits A (sres t (coinEx (params v).n))) (resD t (coinSt (params v).n))
    rw [← slotOf_take, hp, slotOf_take]
  · rw [slotOf_coin j q (t.take i) (params v).n (runG v limits A (t.take i)).2
        (by unfold runG; exact pre_run _ _ _) i (by omega),
      slotOf_coin j q t (params v).n (runG v limits A t).2 (by unfold runG; exact pre_run _ _ _) i (by omega)]

theorem slotJ_assigned (j q : Nat) (t : List Nat) :
    (assigned (slotJ v limits A j q) t).Nodup ∧ ∀ s ∈ assigned (slotJ v limits A j q) t, s < q+1 := by
  apply assigned_spec
  · intro i i' s hi hi' h h'
    rw [slotJ_pred v limits A j q t i (by omega)] at h
    rw [slotJ_pred v limits A j q t i' (by omega)] at h'
    exact slotOf_inj j q _ i i' s h h'
  · intro i s hi h
    rw [slotJ_pred v limits A j q t i (by omega)] at h
    obtain ⟨e, -, hc⟩ := slotOf_some j q _ i s h
    rcases hc with ⟨-, -, rfl⟩ | ⟨-, hq, rfl⟩ <;> omega
end

/-! The covered event in the game. -/

/-- Classical indicator. -/
noncomputable def ind (P : Prop) : Nat := @ite _ P (Classical.propDecidable P) 1 0

theorem ind_le_one (P : Prop) : ind P ≤ 1 := by unfold ind; split <;> omega
theorem ind_of_not {P : Prop} (h : ¬P) : ind P = 0 := by unfold ind; rw [@if_neg _ (Classical.propDecidable P) h]
theorem ind_of {P : Prop} (h : P) : ind P = 1 := by unfold ind; rw [@if_pos _ (Classical.propDecidable P) h]

theorem hreqR_msg (p : Params) (r s o m r' s' o' m' : Bytes) (h : hreqR p r s o m = hreqR p r' s' o' m')
    (hl : (r ++ s ++ o).length = (r' ++ s' ++ o').length) : m = m' := by
  simp only [hreqR, Request.mk.injEq] at h
  exact (List.append_inj h.2.2.2.1 hl).2

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- No signing request of a signed message was first drawn adversary-side. -/
def NoRG (t : List Nat) : Prop :=
  ∀ m ∈ (runG v limits A t).1.signed, ∀ i, findDraw (runG v limits A t).2
    (hreqOf (finO v limits A t) v (finKey v limits A t).2 m) = some i →
    ∀ e, (runG v limits A t).2[i]? = some e → e.1 = false

/-- The forged digest is ITSR-covered by the signed messages' digests. -/
def CovG (t : List Nat) : Prop :=
  CoveredBy (finO v limits A t) v (finKey v limits A t).2 (runG v limits A t).1.signed
    (splitDigest (params v) (verifyDigest (finO v limits A t) v (finKey v limits A t).1
      (runG v limits A t).1.msg (runG v limits A t).1.sig))

/-- Pointwise: a won, covered game outside `NoRG`'s complement is the covered
    event of the `j`-th candidate under the predictable selection. -/
theorem itsr_point_game (q : Nat) (t : List Nat)
    (hN : (runG v limits A t).2.length ≤ t.length)
    (hC : ((runG v limits A t).2.filter isC).length ≤ q)
    (hw : (runG v limits A t).1.win = true) (hcov : CovG v limits A t) (hrg : NoRG v limits A t) :
    ∃ j, j < ((runG v limits A t).2.filter isA).length ∧
      covA (dLeaf (params v)) (dIdx (params v)) (params v).k q
        (fill (slotJ v limits A j q) (List.replicate (q+1) 0) t) = true := by
  have hpred : ∀ j i, i ≤ t.length → slotJ v limits A j q (t.take i) = slotOf j q (runG v limits A t).2 i :=
    fun j i hi => slotJ_pred v limits A j q t i hi
  obtain ⟨hv, hfresh, hlog⟩ := game_win v limits A t hw
  obtain ⟨hmC, hmM⟩ := game_hmsg v limits A t
  have hsk := finKey_len v limits A t
  have hOdef : finO v limits A t = oracleOf t (runG v limits A t).2 := rfl
  unfold CovG at hcov
  unfold NoRG at hrg
  generalize finO v limits A t = O at hv hlog hmC hmM hcov hrg hOdef
  generalize finKey v limits A t = K at hv hlog hmC hmM hcov hrg hsk
  generalize runG v limits A t = R at hpred hv hfresh hlog hmC hmM hcov hrg hOdef hN hC hw ⊢
  have hwid : ∀ r, (O r).length = r.outLen := by rw [hOdef]; exact fun r => oracleOf_len t _ r
  obtain ⟨hpk, hsig⟩ := accepted_requires_exact_lengths O v K.1 R.1.msg R.1.sig hv
  have hne : R.1.msg.isEmpty = false := by
    cases ee : R.1.msg.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp ee, verify_empty] at hv; cases hv
  have hex := verify_exact O v K.1 R.1.msg R.1.sig hne hpk hsig []
  have hvmem : hreqR (params v) (R.1.sig.take (params v).n) (K.1.take (params v).n) (K.1.drop (params v).n)
      R.1.msg ∈ verifyLog O v K.1 R.1.msg R.1.sig := by
    unfold verifyLog; rw [hex]; simp [hreqR]
  obtain ⟨iv, hiv⟩ := findDraw_of_mem R.2 _ (hlog _ hvmem)
  obtain ⟨ev, hev, hevr⟩ := findDraw_get R.2 _ iv hiv
  have hn := params_n_pos v
  have hsigB : (params v).n ≤ R.1.sig.length := by
    rw [hsig]; unfold Params.sigBytes; omega
  have hvlen : (R.1.sig.take (params v).n ++ K.1.take (params v).n ++ K.1.drop (params v).n).length =
      3*(params v).n := by simp [hpk]; omega
  have hevA : isA ev = true := by
    cases hg : ev.1
    · exfalso
      have hc : isC ev = true := by simp [isC, hg, hevr, hreqR]
      obtain ⟨m, hm, hmeq⟩ := hmC ev (mem_of_getElem? hev) hc
      rw [hevr] at hmeq
      unfold hreqOf at hmeq
      have hk := hwid ⟨1, "", deriveKey O "DSM/sphincs/v2/prf-msg" (slice K.2 (params v).n (params v).n),
          slice K.2 (2*(params v).n) (params v).n ++ m, (params v).n⟩
      have hmm := hreqR_msg _ _ _ _ _ _ _ _ _ hmeq (by
        rw [hvlen]; simp only [keyed, List.length_append, slice, List.length_take, List.length_drop, hsk] at hk ⊢
        rw [hk]; omega)
      rw [hmm] at hfresh
      have : R.1.signed.contains m = true := by simpa using hm
      rw [this] at hfresh; cases hfresh
    · simp [isA, hg, hevr, hreqR]
  refine ⟨cnt isA R.2 iv, cnt_lt_total isA R.2 iv ev hev hevA, ?_⟩
  have hivlt : iv < t.length := Nat.lt_of_lt_of_le (List.getElem?_eq_some_iff.mp hev).1 hN
  have hdist : ∀ j i i' s, i < t.length → i' < t.length → slotJ v limits A j q (t.take i) = some s →
      slotJ v limits A j q (t.take i') = some s → i = i' := by
    intro j i i' s hi hi' h h'
    rw [hpred j i (by omega)] at h
    rw [hpred j i' (by omega)] at h'
    exact slotOf_inj j q _ i i' s h h'
  have hout0 : (fill (slotJ v limits A (cnt isA R.2 iv) q) (List.replicate (q+1) 0) t).getD 0 0 =
      t.getD iv 0 + 1 :=
    fill_get t _ _ 0 iv (fun i i' hi hi' h h' => hdist _ i i' _ hi hi' h h') hivlt
      (by rw [hpred _ iv (by omega)]; unfold slotOf; rw [hev]; simp [hevA]) (by simp)
  have hvd : verifyDigest O v K.1 R.1.msg R.1.sig = be (params v).m (t.getD iv 0) := by
    show O _ = _
    rw [hOdef]; exact oracleOf_at t R.2 _ iv hiv
  simp only [covA, Bool.and_eq_true, bne_iff_ne, ne_eq, List.all_eq_true, List.any_eq_true, beq_iff_eq]
  rw [hout0]
  refine ⟨by omega, fun i hi => ?_⟩
  obtain ⟨m, hm, htree, hleaf, hdig⟩ := hcov i (List.mem_range.mp hi)
  obtain ⟨em, hem, hemr⟩ := hmM m hm
  obtain ⟨im, him⟩ := findDraw_of_mem R.2 _ ⟨em, hem, hemr⟩
  obtain ⟨e', he', he'r⟩ := findDraw_get _ _ im him
  have hg' := hrg m hm im him e' he'
  have hcC : isC e' = true := by simp [isC, hg', he'r, hreqOf, hreqR]
  have haC : isA e' = false := by simp [isA, hg']
  have hcq : cnt isC R.2 im < q := Nat.lt_of_lt_of_le (cnt_lt_total isC R.2 im e' he' hcC) hC
  have himlt : im < t.length := Nat.lt_of_lt_of_le (List.getElem?_eq_some_iff.mp he').1 hN
  have houtc : (fill (slotJ v limits A (cnt isA R.2 iv) q) (List.replicate (q+1) 0) t).getD
      (cnt isC R.2 im + 1) 0 = t.getD im 0 + 1 :=
    fill_get t _ _ _ im (fun i i' hi hi' h h' => hdist _ i i' _ hi hi' h h') himlt
      (by rw [hpred _ im (by omega)]; unfold slotOf; rw [he']; simp [haC, hcC, hcq]) (by simp; omega)
  have hsd : signDigest O v K.2 m = be (params v).m (t.getD im 0) := by
    show O _ = _
    have := oracleOf_at t R.2 _ im him; rw [← hOdef] at this; exact this
  rw [hsd, hvd] at htree hleaf hdig
  refine ⟨cnt isC R.2 im, List.mem_range.mpr hcq, ?_⟩
  rw [houtc]
  simp only [Nat.add_sub_cancel]
  refine ⟨by omega, ?_, ?_⟩
  · unfold dLeaf; rw [htree, hleaf]
  · exact hdig
end

/-! Summing over tapes: the game-level ITSR bound. -/

/-- The `j`-th candidate's covered event under the predictable selection. -/
def covJ (v : Variant) (limits : Limits) (A : Bytes → RAdv) (q j : Nat) (t : List Nat) : Nat :=
  if covA (dLeaf (params v)) (dIdx (params v)) (params v).k q
    (fill (slotJ v limits A j q) (List.replicate (q+1) 0) t) then 1 else 0

/-- Union over the adversary-side candidates. Every won, covered, `NoRG` run is
    charged to the unique first draw of its verifier `h_msg` request, which is
    adversary-side; the candidate count is bounded by `JA`. -/
theorem itsr_game_sum (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N q JA B : Nat)
    (hN : ∀ t : List Nat, t.length = N → (runG v limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG v limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG v limits A t).2.filter isA).length ≤ JA)
    (hj : ∀ j, tsum R N (covJ v limits A q j) * B ≤ R^N) :
    tsum R N (fun t => ind ((runG v limits A t).1.win = true ∧ CovG v limits A t ∧ NoRG v limits A t)) * B
      ≤ JA * R^N := by
  have h1 : tsum R N (fun t => ind ((runG v limits A t).1.win = true ∧ CovG v limits A t ∧ NoRG v limits A t))
      ≤ tsum R N (fun t => ((List.range JA).map (fun j => covJ v limits A q j t)).sum) := by
    apply tsum_mono_len
    intro t ht
    by_cases hP : (runG v limits A t).1.win = true ∧ CovG v limits A t ∧ NoRG v limits A t
    · rw [ind_of hP]
      obtain ⟨j, hjl, hcv⟩ := itsr_point_game v limits A q t (by rw [ht]; exact hN t ht) (hC t ht)
        hP.1 hP.2.1 hP.2.2
      have hjJ : j < JA := Nat.lt_of_lt_of_le hjl (hJ t ht)
      have h1 : covJ v limits A q j t = 1 := by unfold covJ; rw [hcv]; rfl
      rw [← h1]
      exact le_sum_of_mem (List.mem_map.mpr ⟨j, List.mem_range.mpr hjJ, rfl⟩)
    · rw [ind_of_not hP]; exact Nat.zero_le _
  rw [tsum_list] at h1
  have h2 := Nat.mul_le_mul_right B h1
  rw [sum_mul_right] at h2
  refine Nat.le_trans h2 ?_
  have h3 := sum_map_le (List.range JA) (fun j _ => hj j)
  rw [sum_map_const, List.length_range] at h3
  exact h3

/-- Game-level ITSR, SPHINCS+-128f: at most `JA · 2^-128` of the tapes. -/
theorem itsr_game_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true ∧
        CovG .spx128f limits A t ∧ NoRG .spx128f limits A t)) * 2^128
      ≤ JA * (c * 256^(params .spx128f).m)^N :=
  itsr_game_sum .spx128f limits A _ N q JA _ hN hC hJ (fun j =>
    itsr_dsm_128f c N q hc hq (slotJ .spx128f limits A j q) (fun t _ => slotJ_assigned .spx128f limits A j q t))

/-- Game-level ITSR, SPHINCS+-256f: at most `JA · 2^-255` of the tapes. -/
theorem itsr_game_256f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx256f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx256f).m) N (fun t => ind ((runG .spx256f limits A t).1.win = true ∧
        CovG .spx256f limits A t ∧ NoRG .spx256f limits A t)) * 2^255
      ≤ JA * (c * 256^(params .spx256f).m)^N :=
  itsr_game_sum .spx256f limits A _ N q JA _ hN hC hJ (fun j =>
    itsr_dsm_256f c N q hc hq (slotJ .spx256f limits A j q) (fun t _ => slotJ_assigned .spx256f limits A j q t))

end DSM.Rom
