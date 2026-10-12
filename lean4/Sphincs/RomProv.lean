-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomItsrGame

/- Provenance, disclosure and protection in DSM's symbolic game (H1).

   A Hoare-style judgment `J P Pre Q` over the symbolic run: from a state
   satisfying the invariant `Inv` and `Pre`, if no step of `P` is a
   disagreement step, the final state satisfies `Inv`, extends the initial
   entries, and the result and final state satisfy `Q`.

   `Inv` records, for a fixed tape:
   * origin: entries 0-2 are the coin entries (SK.seed, SK.prf, PK.seed);
     every handle in an entry refers to an existing entry; adversary entries
     carry no handles;
   * protection: every revealed handle is `Safe`. A `Safe` handle does not
     name an entry that mentions the coins SK.seed or SK.prf, so those coins,
     and the keys derived from them, are never revealed; and a revealed
     message randomizer R (the answer to a PRF-msg request) has its signing
     request h_msg(R, PK.seed, root, m) already drawn challenger-side;
   * order: no adversary entry precedes a challenger h_msg entry with the
     same resolution.

   Every step preserves `Inv` on a disagreement-free trace (`step_askC`,
   `step_askA`, `step_reveal`); the obligations are discharged once per
   request constructor that DSM's signer issues (derive, thash, prf, the
   PRF-msg request, h_msg) and then by the structure of the signer. The
   adversary *learning* a protected value is excluded by the invariant;
   the adversary *computing* a request that equals a hidden one is a
   disagreement step, i.e. an event of the hidden-value bound. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

theorem strace_bind {α β : Type} (t : List Nat) : ∀ (P : Prog α) (f : α → Prog β) (st : St),
    strace t (P.bind f) st = strace t P st ++ strace t (f (xrun false t P st).1) (xrun false t P st).2
  | .done _, _, _ => rfl
  | .askC _ _, f, _ => by simp only [Prog.bind, strace, xrun, List.cons_append]; rw [strace_bind t _ f _]
  | .askA _ _, f, _ => by simp only [Prog.bind, strace, xrun, List.cons_append]; rw [strace_bind t _ f _]
  | .reveal _ _, f, _ => by simp only [Prog.bind, strace, xrun, List.cons_append]; rw [strace_bind t _ f _]

theorem firstIdx_before {β : Type} (p : β → Bool) : ∀ (l : List β) (j : Nat) (b : β),
    l[j]? = some b → j < firstIdx p l → p b = false
  | [], j, b, h, _ => by simp at h
  | c :: l, 0, b, h, hj => by
    simp only [List.getElem?_cons_zero, Option.some.injEq] at h
    subst h
    by_cases hc : p c = true
    · simp [firstIdx, hc] at hj
    · simpa using hc
  | c :: l, j+1, b, h, hj => by
    simp only [List.getElem?_cons_succ] at h
    by_cases hc : p c = true
    · simp [firstIdx, hc] at hj
    · simp only [firstIdx, hc, Bool.false_eq_true, if_false] at hj
      exact firstIdx_before p l j b h (by omega)

theorem firstIdx_hit {β : Type} (p : β → Bool) : ∀ (l : List β), firstIdx p l < l.length →
    ∃ b, l[firstIdx p l]? = some b ∧ p b = true
  | [], h => by simp [firstIdx] at h
  | c :: l, h => by
    by_cases hc : p c = true
    · exact ⟨c, by simp [firstIdx, hc], hc⟩
    · simp only [firstIdx, hc, Bool.false_eq_true, if_false, List.length_cons] at h ⊢
      obtain ⟨b, hb, hpb⟩ := firstIdx_hit p l (by omega)
      exact ⟨b, by simpa using hb, hpb⟩

theorem get_snoc {β : Type} {l : List β} {x e : β} {j : Nat} (h : (l ++ [x])[j]? = some e) :
    (j < l.length ∧ l[j]? = some e) ∨ (j = l.length ∧ e = x) := by
  by_cases hj : j < l.length
  · left; rw [List.getElem?_append_left hj] at h; exact ⟨hj, h⟩
  · right
    rcases Nat.lt_or_ge j (l.length + 1) with h1 | h1
    · have hj' : j = l.length := by omega
      subst hj'
      simp at h
      exact ⟨rfl, h.symm⟩
    · have : (l ++ [x])[j]? = none := List.getElem?_eq_none (by simp; omega)
      rw [this] at h; cases h

theorem mem_shids : ∀ (x : List SV) (h : Nat), h ∈ shids x → ∃ w, SV.hid h w ∈ x
  | [], _, hm => by simp [shids] at hm
  | .lit _ :: x, h, hm => by
    simp only [shids] at hm
    obtain ⟨w, hw⟩ := mem_shids x h hm
    exact ⟨w, List.mem_cons_of_mem _ hw⟩
  | .hid i w :: x, h, hm => by
    simp only [shids, List.mem_cons] at hm
    rcases hm with rfl | hm
    · exact ⟨w, by simp⟩
    · obtain ⟨w', hw⟩ := mem_shids x h hm
      exact ⟨w', List.mem_cons_of_mem _ hw⟩

theorem lift_hids (q : Request) : (lift q).hids = [] := by simp [lift, SReq.hids, shids]

theorem open_mem {rev : List Nat} {r : SReq} (h : isOpen rev r = true) : ∀ i ∈ r.hids, i ∈ rev := by
  simpa [isOpen] using h

section
variable (t : List Nat) (n pm : Nat) (root : SB)

/-! The request constructors DSM's signer issues around the message randomizer. -/

/-- Derivation of the PRF-msg key from SK.prf (coin 1). -/
def dReq : SReq := ⟨0, "DSM/sphincs/v2/prf-msg", [], [.hid 1 n], 32⟩
/-- Derivation of the WOTS/FORS PRF key from SK.seed (coin 0). -/
def dPrf : SReq := ⟨0, "DSM/sphincs/v2/prf", [], [.hid 0 n], 32⟩
/-- The randomizer request R = PRF_msg(key j, PK.seed ‖ m). -/
def rqOf (j : Nat) (m : Bytes) : SReq := ⟨1, "", [.hid j 32], [.hid 2 n, .lit m], n⟩
/-- The signing request h_msg(R = handle i, PK.seed, root, m). -/
def hqOf (i : Nat) (m : Bytes) : SReq :=
  ⟨2, "DSM/sphincs/v2/h-msg", [], [.hid i n, .hid 2 n] ++ root ++ [.lit m], pm⟩

/-- Entry `i` mentions a protected coin (SK.seed or SK.prf). -/
def Prot (st : St) (i : Nat) : Prop := ∃ e, st.ents[i]? = some e ∧ (0 ∈ e.2.hids ∨ 1 ∈ e.2.hids)

/-- A handle that may be disclosed. -/
def Safe (st : St) (i : Nat) : Prop :=
  i < st.ents.length ∧ ¬ Prot st i ∧
  ∀ j m, st.ents[i]? = some (false, rqOf n j m) → st.ents[j]? = some (false, dReq n) →
    ∃ c : Nat, st.ents[c]? = some (false, hqOf n pm root i m)

/-- Symbolic bytes all of whose handles may be disclosed. -/
def Gd (st : St) (x : SB) : Prop := ∀ i w, SV.hid i w ∈ x → Safe n pm root st i

/-- The invariant: origin, protection/disclosure, order. -/
def Inv (st : St) : Prop :=
  (st.ents[0]? = some (false, coin n 0) ∧ st.ents[1]? = some (false, coin n 1) ∧
    st.ents[2]? = some (false, coin n 2)) ∧
  (∀ (i : Nat) (e : Bool × SReq), st.ents[i]? = some e → ∀ h ∈ e.2.hids, h < st.ents.length) ∧
  (∀ (a : Nat) (qa : SReq), st.ents[a]? = some (true, qa) → qa.hids = []) ∧
  (∀ (a c : Nat) (qa rc : SReq), a < c → st.ents[a]? = some (true, qa) → st.ents[c]? = some (false, rc) → rc.mode = 2 →
    qa.res t ≠ rc.res t) ∧
  (∀ i ∈ st.rev, Safe n pm root st i)

/-- The entries only grow. -/
def Grow (st st' : St) : Prop := ∃ L, st'.ents = st.ents ++ L

/-- Facts preserved when the entries grow. -/
def Stable (Pre : St → Prop) : Prop :=
  ∀ st st', Inv t n pm root st → Grow st st' → Pre st → Pre st'

/-- Hoare judgment on disagreement-free symbolic runs. -/
def J {α : Type} (P : Prog α) (Pre : St → Prop) (Q : α → St → Prop) : Prop :=
  ∀ st, Inv t n pm root st → Pre st → (∀ s ∈ strace t P st, dis t s = false) →
    Inv t n pm root (xrun false t P st).2 ∧ Grow st (xrun false t P st).2 ∧
      Q (xrun false t P st).1 (xrun false t P st).2
end

theorem ext_get {st st' : St} (h : Grow st st') {i : Nat} {e : Bool × SReq} (he : st.ents[i]? = some e) :
    st'.ents[i]? = some e := by
  obtain ⟨L, hL⟩ := h
  rw [hL, List.getElem?_append_left (List.getElem?_eq_some_iff.mp he).1]; exact he

theorem ext_len {st st' : St} (h : Grow st st') : st.ents.length ≤ st'.ents.length := by
  obtain ⟨L, hL⟩ := h; rw [hL]; simp

theorem ext_refl (st : St) : Grow st st := ⟨[], by simp⟩

theorem ext_trans {a b c : St} (h1 : Grow a b) (h2 : Grow b c) : Grow a c := by
  obtain ⟨L1, h1⟩ := h1; obtain ⟨L2, h2⟩ := h2; exact ⟨L1 ++ L2, by rw [h2, h1, List.append_assoc]⟩

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem safe_mono {st st' : St} (hI : Inv t n pm root st) (hx : Grow st st') {i : Nat}
    (h : Safe n pm root st i) : Safe n pm root st' i := by
  obtain ⟨hl, hp, hc⟩ := h
  obtain ⟨e, he⟩ : ∃ e, st.ents[i]? = some e := ⟨_, List.getElem?_eq_getElem hl⟩
  have he' := ext_get hx he
  refine ⟨Nat.lt_of_lt_of_le hl (ext_len hx), ?_, ?_⟩
  · rintro ⟨e2, h2, h3⟩
    obtain rfl : e = e2 := Option.some.inj (he'.symm.trans h2)
    exact hp ⟨e, he, h3⟩
  · intro j m hi hj
    have hei : e = (false, rqOf n j m) := Option.some.inj (he'.symm.trans hi)
    have hi0 : st.ents[i]? = some (false, rqOf n j m) := by rw [he, hei]
    have hjl : j < st.ents.length := hI.2.1 i _ hi0 j (by simp [rqOf, SReq.hids, shids])
    have hj0 : st.ents[j]? = some (false, dReq n) := by
      rw [← hj]; obtain ⟨L, hL⟩ := hx; rw [hL, List.getElem?_append_left hjl]
    obtain ⟨c, hc'⟩ := hc j m hi0 hj0
    exact ⟨c, ext_get hx hc'⟩

theorem good_mono {st st' : St} (hI : Inv t n pm root st) (hx : Grow st st') {x : SB}
    (h : Gd n pm root st x) : Gd n pm root st' x :=
  fun i w hm => safe_mono hI hx (h i w hm)

theorem prot_zero {st : St} (hI : Inv t n pm root st) : Prot st 0 :=
  ⟨_, hI.1.1, Or.inl (by simp [coin, SReq.hids, shids])⟩

theorem prot_one {st : St} (hI : Inv t n pm root st) : Prot st 1 :=
  ⟨_, hI.1.2.1, Or.inr (by simp [coin, SReq.hids, shids])⟩

theorem not_rev_of_prot {st : St} (hI : Inv t n pm root st) {i : Nat} (hp : Prot st i) : i ∉ st.rev :=
  fun hm => (hI.2.2.2.2 i hm).2.1 hp

theorem prot_of_dReq {st : St} {j : Nat} (h : st.ents[j]? = some (false, dReq n)) : Prot st j :=
  ⟨_, h, Or.inr (by simp [dReq, SReq.hids, shids])⟩

theorem prot_of_dPrf {st : St} {j : Nat} (h : st.ents[j]? = some (false, dPrf n)) : Prot st j :=
  ⟨_, h, Or.inl (by simp [dPrf, SReq.hids, shids])⟩

/-- An entry whose request avoids the coins and is no PRF-msg request is safe. -/
theorem safe_of_req {st : St} {i : Nat} {g : Bool} {r : SReq} (he : st.ents[i]? = some (g, r))
    (h01 : ∀ h ∈ r.hids, h ≠ 0 ∧ h ≠ 1) (hq : ∀ j m, r = rqOf n j m → st.ents[j]? ≠ some (false, dReq n)) :
    Safe n pm root st i := by
  refine ⟨(List.getElem?_eq_some_iff.mp he).1, ?_, ?_⟩
  · rintro ⟨e2, h2, h3⟩
    obtain rfl : (g, r) = e2 := Option.some.inj (he.symm.trans h2)
    rcases h3 with h3 | h3
    · exact (h01 0 h3).1 rfl
    · exact (h01 1 h3).2 rfl
  · intro j m hi hj
    have : (g, r) = (false, rqOf n j m) := Option.some.inj (he.symm.trans hi)
    exact absurd hj (hq j m (Prod.mk.inj this).2)

/-- An open entry is safe. -/
theorem safe_of_open {st : St} (hI : Inv t n pm root st) {i : Nat} {e : Bool × SReq}
    (he : st.ents[i]? = some e) (ho : isOpen st.rev e.2 = true) : Safe n pm root st i := by
  have hm := open_mem ho
  refine ⟨(List.getElem?_eq_some_iff.mp he).1, ?_, ?_⟩
  · rintro ⟨e2, h2, h3⟩
    obtain rfl : e = e2 := Option.some.inj (he.symm.trans h2)
    rcases h3 with h3 | h3
    · exact not_rev_of_prot hI (prot_zero hI) (hm 0 h3)
    · exact not_rev_of_prot hI (prot_one hI) (hm 1 h3)
  · intro j m hi hj
    have : e = (false, rqOf n j m) := Option.some.inj (he.symm.trans hi)
    subst this
    exact absurd (hm j (by simp [rqOf, SReq.hids, shids])) (not_rev_of_prot hI (prot_of_dReq hj))

/-! One step each. -/

theorem dis_c {st : St} {r : SReq} (hd : dis t (st, .c r) = false) :
    ∀ e ∈ st.ents, mC true t st.rev r e = mC false t st.rev r e := by
  intro e he
  simp only [dis, List.any_eq_false] at hd
  have := hd e he
  revert this
  cases mC true t st.rev r e <;> cases mC false t st.rev r e <;> simp

theorem step_askC (st : St) (r : SReq) (hI : Inv t n pm root st)
    (hh : ∀ h ∈ r.hids, h < st.ents.length) (hd : dis t (st, .c r) = false) :
    Inv t n pm root (addC st (firstIdx (mC false t st.rev r) st.ents) r) ∧
      Grow st (addC st (firstIdx (mC false t st.rev r) st.ents) r) := by
  generalize hi : firstIdx (mC false t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]; exact ⟨hI, ext_refl st⟩
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha]
    have hx : Grow st ⟨st.ents ++ [(false, r)], st.rev⟩ := ⟨_, rfl⟩
    refine ⟨?_, hx⟩
    have hreal : ∀ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e → mC true t st.rev r e = false := by
      intro j e he
      rw [dis_c hd e (mem_of_getElem? he)]
      exact firstIdx_before _ _ j e he (by rw [hi, hi']; exact (List.getElem?_eq_some_iff.mp he).1)
    obtain ⟨hc, hs, hadv, hord, hrev⟩ := hI
    refine ⟨⟨ext_get hx hc.1, ext_get hx hc.2.1, ext_get hx hc.2.2⟩, ?_, ?_, ?_, ?_⟩
    · intro j e he h hm
      simp only [List.length_append, List.length_singleton]
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, rfl⟩
      · exact Nat.lt_succ_of_lt (hs j e he h hm)
      · exact Nat.lt_succ_of_lt (hh h hm)
    · intro a qa he
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · cases he
    · intro a c qa rc hac ha hc' hm
      rcases get_snoc ha with ⟨hal, ha0⟩ | ⟨hal, ha0⟩
      · rcases get_snoc hc' with ⟨_, hc0⟩ | ⟨_, hc0⟩
        · exact hord a c qa rc hac ha0 hc0 hm
        · have hrc : rc = r := (Prod.mk.inj hc0).2
          have := hreal a _ ha0
          rw [hrc]
          simpa [mC] using this
      · cases ha0
    · intro j hj
      exact safe_mono ⟨hc, hs, hadv, hord, hrev⟩ hx (hrev j hj)

theorem step_askC_safe (st : St) (r : SReq) (hI : Inv t n pm root st)
    (hh : ∀ h ∈ r.hids, h < st.ents.length) (h01 : ∀ h ∈ r.hids, h ≠ 0 ∧ h ≠ 1)
    (hq : ∀ j m, r = rqOf n j m → st.ents[j]? ≠ some (false, dReq n)) :
    Safe n pm root (addC st (firstIdx (mC false t st.rev r) st.ents) r)
      (firstIdx (mC false t st.rev r) st.ents) := by
  generalize hi : firstIdx (mC false t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]
    obtain ⟨e, he, hp⟩ := firstIdx_hit _ st.ents (hi ▸ hl)
    rw [hi] at he
    simp only [mC, Bool.false_eq_true, if_false, Bool.or_eq_true, decide_eq_true_eq,
      Bool.and_eq_true] at hp
    rcases hp with hp | ⟨⟨ho, _⟩, _⟩
    · obtain ⟨g, r'⟩ := e
      simp only at hp
      subst hp
      exact safe_of_req he h01 hq
    · exact safe_of_open hI he ho
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha, hi']
    refine safe_of_req (g := false) (by simp) h01 (fun j m hr hj => ?_)
    have hjl : j < st.ents.length := hh j (by rw [hr]; simp [rqOf, SReq.hids, shids])
    rw [List.getElem?_append_left hjl] at hj
    exact hq j m hr hj

theorem step_askC_closed (st : St) (r : SReq) (hI : Inv t n pm root st) (hc : ∃ h ∈ r.hids, h ∉ st.rev) :
    (addC st (firstIdx (mC false t st.rev r) st.ents) r).ents[firstIdx (mC false t st.rev r) st.ents]? =
      some (false, r) := by
  generalize hi : firstIdx (mC false t st.rev r) st.ents = i
  obtain ⟨h, hm, hnr⟩ := hc
  have hno : isOpen st.rev r = false := by
    cases ho : isOpen st.rev r
    · rfl
    · exact absurd (open_mem ho h hm) hnr
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]
    obtain ⟨e, he, hp⟩ := firstIdx_hit _ st.ents (hi ▸ hl)
    rw [hi] at he
    simp only [mC, hno, Bool.false_eq_true, if_false, Bool.or_eq_true, decide_eq_true_eq,
      Bool.and_eq_true, Bool.and_false, false_and, or_false] at hp
    obtain ⟨g, r'⟩ := e
    simp only at hp
    subst hp
    cases g
    · exact he
    · have := hI.2.2.1 i r' he
      rw [this] at hm; cases hm
  · have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    rw [ha, hi']
    simp

theorem step_askA (st : St) (q : Request) (hI : Inv t n pm root st) :
    Inv t n pm root (addA st (firstIdx (mA false t st.rev q) st.ents) q) ∧
      Grow st (addA st (firstIdx (mA false t st.rev q) st.ents) q) := by
  generalize hi : firstIdx (mA false t st.rev q) st.ents = i
  obtain ⟨hc, hs, hadv, hord, hrev⟩ := hI
  by_cases hl : i < st.ents.length
  · have ha : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
    rw [ha]
    refine ⟨⟨hc, hs, hadv, hord, ?_⟩, ext_refl st⟩
    intro j hj
    simp only [List.mem_cons] at hj
    rcases hj with rfl | hj
    · obtain ⟨e, he, hp⟩ := firstIdx_hit _ st.ents (hi ▸ hl)
      rw [hi] at he
      simp only [mA, Bool.false_eq_true, if_false, Bool.and_eq_true] at hp
      exact safe_of_open ⟨hc, hs, hadv, hord, hrev⟩ he hp.1
    · exact hrev j hj
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addA st i q = ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ := by
      simp [addA, hi']
    rw [ha]
    have hx : Grow st ⟨st.ents ++ [(true, lift q)], st.ents.length :: st.rev⟩ := ⟨_, rfl⟩
    refine ⟨⟨⟨ext_get hx hc.1, ext_get hx hc.2.1, ext_get hx hc.2.2⟩, ?_, ?_, ?_, ?_⟩, hx⟩
    · intro j e he h hm
      simp only [List.length_append, List.length_singleton]
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, rfl⟩
      · exact Nat.lt_succ_of_lt (hs j e he h hm)
      · rw [lift_hids] at hm; cases hm
    · intro a qa he
      rcases get_snoc he with ⟨_, he⟩ | ⟨_, he⟩
      · exact hadv a qa he
      · rw [(Prod.mk.inj he).2]; exact lift_hids q
    · intro a c qa rc hac ha hc' hm
      rcases get_snoc hc' with ⟨hcl, hc'⟩ | ⟨_, hc'⟩
      · rcases get_snoc ha with ⟨_, ha⟩ | ⟨hal, _⟩
        · exact hord a c qa rc hac ha hc' hm
        · omega
      · cases hc'
    · intro j hj
      simp only [List.mem_cons] at hj
      rcases hj with rfl | hj
      · refine ⟨by simp, ?_, ?_⟩
        · rintro ⟨e2, h2, h3⟩
          simp at h2
          subst h2
          rw [lift_hids] at h3; simp at h3
        · intro j m h2; simp at h2
      · exact safe_mono ⟨hc, hs, hadv, hord, hrev⟩ hx (hrev j hj)

theorem step_reveal (st : St) (x : List SV) (hI : Inv t n pm root st) (hx : Gd n pm root st x) :
    Inv t n pm root ⟨st.ents, shids x ++ st.rev⟩ := by
  obtain ⟨hc, hs, hadv, hord, hrev⟩ := hI
  refine ⟨hc, hs, hadv, hord, ?_⟩
  intro j hj
  rcases List.mem_append.mp hj with hj | hj
  · obtain ⟨w, hw⟩ := mem_shids x j hj
    exact hx j w hw
  · exact hrev j hj
end

/-! The judgment's rules. -/

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem J.pure' {α : Type} {a : α} {Pre : St → Prop} {Q : α → St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → Q a st) : J t n pm root (.done a) Pre Q :=
  fun st hI hp _ => ⟨hI, ext_refl st, h st hI hp⟩

theorem J.bind' {α β : Type} {P : Prog α} {f : α → Prog β} {Pre : St → Prop} {Q : α → St → Prop}
    {Q' : β → St → Prop} (hP : J t n pm root P Pre Q)
    (hf : ∀ a, J t n pm root (f a) (fun st => Pre st ∧ Q a st) Q') (hs : Stable t n pm root Pre) :
    J t n pm root (P.bind f) Pre Q' := by
  intro st hI hp hnd
  rw [strace_bind] at hnd
  rw [xrun_bind]
  obtain ⟨hI1, hx1, hq1⟩ := hP st hI hp (fun s hs' => hnd s (List.mem_append_left _ hs'))
  obtain ⟨hI2, hx2, hq2⟩ := hf _ _ hI1 ⟨hs _ _ hI hx1 hp, hq1⟩
    (fun s hs' => hnd s (List.mem_append_right _ hs'))
  exact ⟨hI2, ext_trans hx1 hx2, hq2⟩

theorem J.bind {α β : Type} {P : Prog α} {f : α → Prog β} {Pre : St → Prop} {Q : α → St → Prop}
    {Q' : β → St → Prop} (hP : J t n pm root P Pre Q)
    (hf : ∀ a, J t n pm root (f a) (fun st => Pre st ∧ Q a st) Q') (hs : Stable t n pm root Pre) :
    J t n pm root (P >>= f) Pre Q' := J.bind' hP hf hs

theorem J.conseq {α : Type} {P : Prog α} {Pre Pre' : St → Prop} {Q Q' : α → St → Prop}
    (h : J t n pm root P Pre Q) (h1 : ∀ st, Inv t n pm root st → Pre' st → Pre st)
    (h2 : ∀ a st, Q a st → Q' a st) : J t n pm root P Pre' Q' := fun st hI hp hnd =>
  let ⟨a, b, c⟩ := h st hI (h1 st hI hp) hnd
  ⟨a, b, h2 _ _ c⟩

theorem J.ite {α : Type} {c : Prop} [Decidable c] {P₁ P₂ : Prog α} {Pre : St → Prop} {Q : α → St → Prop}
    (h₁ : c → J t n pm root P₁ Pre Q) (h₂ : ¬c → J t n pm root P₂ Pre Q) :
    J t n pm root (if c then P₁ else P₂) Pre Q := by
  by_cases h : c
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem J.askA {α : Type} {q : Request} {k : Bytes → Prog α} {Pre : St → Prop} {Q : α → St → Prop}
    (hk : ∀ b, J t n pm root (k b) Pre Q) (hs : Stable t n pm root Pre) :
    J t n pm root (.askA q k) Pre Q := by
  intro st hI hp hnd
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun]
  obtain ⟨hI1, hx1⟩ := step_askA st q hI
  obtain ⟨hI2, hx2, hq⟩ := hk _ _ hI1 (hs _ _ hI hx1 hp) hnd.2
  exact ⟨hI2, ext_trans hx1 hx2, hq⟩

theorem J.reveal {α : Type} {x : List SV} {k : Bytes → Prog α} {Pre : St → Prop} {Q : α → St → Prop}
    (hx : ∀ st, Inv t n pm root st → Pre st → Gd n pm root st x)
    (hk : ∀ b, J t n pm root (k b) Pre Q) (hs : Stable t n pm root Pre) :
    J t n pm root (.reveal x k) Pre Q := by
  intro st hI hp hnd
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun]
  have hI1 := step_reveal st x hI (hx st hI hp)
  have hx1 : Grow st ⟨st.ents, shids x ++ st.rev⟩ := ⟨[], by simp⟩
  obtain ⟨hI2, hx2, hq⟩ := hk _ _ hI1 (hs _ _ hI hx1 hp) hnd.2
  exact ⟨hI2, ext_trans hx1 hx2, hq⟩

/-- One challenger request, with the step's own facts. -/
theorem J.ask (r : SReq) {Pre : St → Prop} {Q : SB → St → Prop}
    (hh : ∀ st, Inv t n pm root st → Pre st → ∀ h ∈ r.hids, h < st.ents.length)
    (hq : ∀ st, Inv t n pm root st → Pre st → dis t (st, .c r) = false →
      Inv t n pm root (addC st (firstIdx (mC false t st.rev r) st.ents) r) →
      Q [.hid (firstIdx (mC false t st.rev r) st.ents) r.outLen]
        (addC st (firstIdx (mC false t st.rev r) st.ents) r)) :
    J t n pm root (sAsk r) Pre Q := by
  intro st hI hp hnd
  simp only [sAsk, strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [sAsk, xrun]
  obtain ⟨hI1, hx1⟩ := step_askC st r hI (hh st hI hp) hnd.1
  exact ⟨hI1, hx1, hq st hI hp hnd.1 hI1⟩

theorem J.ask_safe (r : SReq) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → (∀ h ∈ r.hids, h < st.ents.length ∧ h ≠ 0 ∧ h ≠ 1) ∧
      ∀ j m, r = rqOf n j m → st.ents[j]? ≠ some (false, dReq n)) :
    J t n pm root (sAsk r) Pre (fun v st => ∃ i, v = [.hid i r.outLen] ∧ Safe n pm root st i) :=
  J.ask r (fun st hI hp x hx => ((h st hI hp).1 x hx).1)
    (fun st hI hp _ _ => ⟨_, rfl, step_askC_safe st r hI (fun x hx => ((h st hI hp).1 x hx).1)
      (fun x hx => ((h st hI hp).1 x hx).2) (h st hI hp).2⟩)

theorem J.ask_closed (r : SReq) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → (∀ h ∈ r.hids, h < st.ents.length) ∧ ∃ h ∈ r.hids, h ∉ st.rev) :
    J t n pm root (sAsk r) Pre (fun v st => ∃ i, v = [.hid i r.outLen] ∧ st.ents[i]? = some (false, r)) :=
  J.ask r (fun st hI hp => (h st hI hp).1)
    (fun st hI hp _ _ => ⟨_, rfl, step_askC_closed st r hI (h st hI hp).2⟩)

/-- Loop states. -/
def SL {σ : Type} (L : σ → St → Prop) : ForInStep σ → St → Prop
  | .done a, st => L a st
  | .yield a, st => L a st

theorem stable_and {P Q : St → Prop} (hP : Stable t n pm root P) (hQ : Stable t n pm root Q) :
    Stable t n pm root (fun st => P st ∧ Q st) :=
  fun st st' hI hx h => ⟨hP st st' hI hx h.1, hQ st st' hI hx h.2⟩

theorem J.loop {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (Pre : St → Prop)
    (L : σ → St → Prop) (hs : Stable t n pm root Pre) (hL : ∀ s, Stable t n pm root (L s))
    (hf : ∀ i ∈ l, ∀ s, J t n pm root (f i s) (fun st => Pre st ∧ L s st) (SL L)) :
    ∀ s, J t n pm root (forIn l s f) (fun st => Pre st ∧ L s st) L := by
  induction l with
  | nil => intro s; exact J.pure' (fun st _ h => h.2)
  | cons a l ih =>
    intro s
    rw [List.forIn_cons]
    refine J.bind (hf a (by simp) s) (fun x => ?_) (stable_and hs (hL s))
    cases x with
    | done b => exact J.pure' (fun st _ h => h.2)
    | yield b =>
      exact J.conseq (ih (fun i hi => hf i (by simp [hi])) b) (fun st _ h => ⟨h.1.1, h.2⟩) (fun _ _ h => h)

theorem J.loop' {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) {Pre : St → Prop}
    (L : σ → St → Prop) (hs : Stable t n pm root Pre) (hL : ∀ s, Stable t n pm root (L s)) (s : σ)
    (h0 : ∀ st, Inv t n pm root st → Pre st → L s st)
    (hf : ∀ i ∈ l, ∀ s, J t n pm root (f i s) (fun st => Pre st ∧ L s st) (SL L)) :
    J t n pm root (forIn l s f) Pre L :=
  J.conseq (J.loop l f Pre L hs hL hf s) (fun st hI h => ⟨h, h0 st hI h⟩) (fun _ _ h => h)

/-! Typing facts. -/

/-- The WOTS/FORS PRF key. -/
def PK (n : Nat) (st : St) (k : SB) : Prop := ∃ i, k = [.hid i 32] ∧ st.ents[i]? = some (false, dPrf n)

theorem stable_gd (x : SB) : Stable t n pm root (fun st => Gd n pm root st x) :=
  fun _ _ hI hx h => good_mono hI hx h

theorem stable_one (w : Nat) (v : SB) :
    Stable t n pm root (fun st => ∃ i, v = [.hid i w] ∧ Safe n pm root st i) :=
  fun _ _ hI hx ⟨i, hv, h⟩ => ⟨i, hv, safe_mono hI hx h⟩

theorem stable_pk (k : SB) : Stable t n pm root (fun st => PK n st k) :=
  fun _ _ _ hx ⟨i, hk, h⟩ => ⟨i, hk, ext_get hx h⟩

theorem gd_one {st : St} {i w : Nat} (h : Safe n pm root st i) : Gd n pm root st [.hid i w] := by
  intro j w' hm
  simp only [List.mem_singleton, SV.hid.injEq] at hm
  rw [hm.1]; exact h

theorem gd_of_one {st : St} {w : Nat} {v : SB} (h : ∃ i, v = [.hid i w] ∧ Safe n pm root st i) :
    Gd n pm root st v := by
  obtain ⟨i, rfl, h⟩ := h; exact gd_one h

theorem gd_sub {st : St} {x y : SB} (hx : Gd n pm root st x) (h : ∀ v ∈ y, v ∈ x) : Gd n pm root st y :=
  fun i w hm => hx i w (h _ hm)

theorem gd_append {st : St} {x y : SB} (hx : Gd n pm root st x) (hy : Gd n pm root st y) :
    Gd n pm root st (x ++ y) := by
  intro i w hm
  rcases List.mem_append.mp hm with h | h
  · exact hx i w h
  · exact hy i w h

theorem gd_nil (st : St) : Gd n pm root st [] := fun _ _ h => by cases h

theorem gd_slice {st : St} {x : SB} (hx : Gd n pm root st x) (i k : Nat) : Gd n pm root st (sSlice x i k) :=
  gd_sub hx (fun _ hv => List.mem_of_mem_drop (List.mem_of_mem_take hv))

theorem gd_take {st : St} {x : SB} (hx : Gd n pm root st x) (k : Nat) : Gd n pm root st (x.take k) :=
  gd_sub hx (fun _ hv => List.mem_of_mem_take hv)

theorem gd_drop {st : St} {x : SB} (hx : Gd n pm root st x) (k : Nat) : Gd n pm root st (x.drop k) :=
  gd_sub hx (fun _ hv => List.mem_of_mem_drop hv)

theorem gd_ite {st : St} {c : Prop} [Decidable c] {x y : SB} (hx : Gd n pm root st x) (hy : Gd n pm root st y) :
    Gd n pm root st (if c then x else y) := by
  split
  · exact hx
  · exact hy

theorem safe_ne {st : St} (hI : Inv t n pm root st) {i : Nat} (h : Safe n pm root st i) :
    i < st.ents.length ∧ i ≠ 0 ∧ i ≠ 1 :=
  ⟨h.1, fun e => h.2.1 (e ▸ prot_zero hI), fun e => h.2.1 (e ▸ prot_one hI)⟩

theorem gd_hids {st : St} (hI : Inv t n pm root st) {x : SB} (hx : Gd n pm root st x) :
    ∀ h ∈ shids x, h < st.ents.length ∧ h ≠ 0 ∧ h ≠ 1 := by
  intro h hm
  obtain ⟨w, hw⟩ := mem_shids x h hm
  exact safe_ne hI (hx h w hw)

theorem shids_append : ∀ (x y : List SV), shids (x ++ y) = shids x ++ shids y
  | [], _ => rfl
  | .lit _ :: x, y => by simp only [List.cons_append, shids]; exact shids_append x y
  | .hid i _ :: x, y => by simp only [List.cons_append, shids, shids_append x y]

theorem pk_ne {st : St} (hI : Inv t n pm root st) {k : SB} (h : PK n st k) :
    ∀ x ∈ shids k, x < st.ents.length ∧ x ≠ 0 ∧ x ≠ 1 := by
  obtain ⟨i, rfl, hi⟩ := h
  intro x hx
  simp only [shids, List.mem_singleton] at hx
  subst hx
  refine ⟨(List.getElem?_eq_some_iff.mp hi).1, fun e => ?_, fun e => ?_⟩
  · subst e; rw [hI.1.1] at hi; simp [coin, dPrf] at hi
  · subst e; rw [hI.1.2.1] at hi; simp [coin, dPrf] at hi
end

/-! The signer's request constructors. -/

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem j_thash (p : Params) (tk : SB) (a : Adrs) (x : SB) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → Gd n pm root st tk ∧ Gd n pm root st x) :
    J t n pm root (sThash p tk a x) Pre (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i) := by
  refine J.ask_safe _ (fun st hI hp => ⟨?_, ?_⟩)
  · intro y hy
    simp only [SReq.hids, shids, List.mem_append] at hy
    rcases hy with hy | hy
    · exact gd_hids hI (h st hI hp).1 y hy
    · exact gd_hids hI (h st hI hp).2 y hy
  · intro j m hr
    simp [rqOf] at hr

theorem j_prf (p : Params) (key seed : SB) (a : Adrs) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → PK n st key ∧ Gd n pm root st seed) :
    J t n pm root (sPrf p key seed a) Pre (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i) := by
  refine J.ask_safe _ (fun st hI hp => ⟨?_, ?_⟩)
  · intro y hy
    simp only [SReq.hids, shids_append, List.mem_append] at hy
    rcases hy with hy | hy | hy
    · exact pk_ne hI (h st hI hp).1 y hy
    · exact gd_hids hI (h st hI hp).2 y hy
    · simp [shids] at hy
  · intro j m hr
    obtain ⟨i, hk, hi⟩ := (h st hI hp).1
    simp only [rqOf, SReq.mk.injEq] at hr
    rw [hk] at hr
    have hij : i = j := by simp_all
    rw [← hij, hi]
    simp [dPrf, dReq]
end

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem stable_true : Stable t n pm root (fun _ => True) := fun _ _ _ _ _ => trivial

theorem J.unit {Pre : St → Prop} : J t n pm root (pure PUnit.unit : Prog PUnit) Pre (fun _ _ => True) :=
  J.pure' (fun _ _ _ => trivial)

theorem j_chain (p : Params) (tk : SB) (a : Adrs) : ∀ (steps : Nat) (x : SB) (start : Nat) {Pre : St → Prop},
    Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st → Gd n pm root st tk ∧ Gd n pm root st x) →
    J t n pm root (sChain p tk a x start steps) Pre (fun v st => Gd n pm root st v)
  | 0, _, _, _, _, h => J.pure' (fun st hI hp => (h st hI hp).2)
  | steps+1, x, start, _, hs, h => by
    simp only [sChain]
    exact J.bind (j_thash p tk _ x h) (fun y => j_chain p tk a steps y (start+1)
      (stable_and hs (stable_one _ y)) (fun st hI hp => ⟨(h st hI hp.1).1, gd_of_one hp.2⟩)) hs

theorem j_wotsPkFromSig (p : Params) (tk : SB) (a : Adrs) (sig : SB) (msg : Bytes) {Pre : St → Prop}
    (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → Gd n pm root st tk ∧ Gd n pm root st sig) :
    J t n pm root (sWotsPkFromSig p tk a sig msg) Pre
      (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i) := by
  simp only [sWotsPkFromSig, sWotsCompress]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_)
    (fun tops => j_thash p tk _ tops (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)) hs
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact J.bind (j_chain p tk _ (15-digit) (sSlice sig i 1) digit (stable_and hs (stable_gd s))
      (fun st hI hp => ⟨(h st hI hp.1).1, gd_slice (h st hI hp.1).2 i 1⟩))
    (fun top => J.pure' (fun st _ hp => gd_append hp.1.2 hp.2)) (stable_and hs (stable_gd s))

theorem j_authWalk (p : Params) (tk : SB) (a : Adrs) (auth : SB) :
    ∀ (remaining li gi level : Nat) (node : SB) {Pre : St → Prop}, Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st →
      Gd n pm root st tk ∧ Gd n pm root st auth ∧ Gd n pm root st node) →
    J t n pm root (sAuthWalk p tk a li gi node auth level remaining) Pre (fun v st => Gd n pm root st v)
  | 0, _, _, _, _, _, _, h => J.pure' (fun st hI hp => (h st hI hp).2.2)
  | remaining+1, li, gi, level, node, _, hs, h => by
    simp only [sAuthWalk]
    exact J.bind (j_thash p tk _ _ (fun st hI hp => ⟨(h st hI hp).1,
        gd_ite (gd_append (h st hI hp).2.2 (gd_slice (h st hI hp).2.1 _ _))
          (gd_append (gd_slice (h st hI hp).2.1 _ _) (h st hI hp).2.2)⟩))
      (fun y => j_authWalk p tk a auth remaining _ _ _ y (stable_and hs (stable_one _ y))
        (fun st hI hp => ⟨(h st hI hp.1).1, (h st hI hp.1).2.1, gd_of_one hp.2⟩)) hs

theorem j_xmssPkFromSig (p : Params) (tk : SB) (a : Adrs) (idx : Nat) (sig : SB) (msg : Bytes)
    {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → Gd n pm root st tk ∧ Gd n pm root st sig) :
    J t n pm root (sXmssPkFromSig p tk a idx sig msg) Pre (fun v st => Gd n pm root st v) := by
  simp only [sXmssPkFromSig, sAuthRoot]
  exact J.bind (j_wotsPkFromSig p tk _ _ msg hs (fun st hI hp => ⟨(h st hI hp).1, gd_take (h st hI hp).2 _⟩))
    (fun node => j_authWalk p tk _ _ _ _ _ _ node (stable_and hs (stable_one _ node))
      (fun st hI hp => ⟨(h st hI hp.1).1, gd_drop (h st hI hp.1).2 _, gd_of_one hp.2⟩)) hs

theorem j_htRootTail (p : Params) (tk : SB) : ∀ (remaining layer tree : Nat) (node sig : SB) {Pre : St → Prop},
    Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st →
      Gd n pm root st tk ∧ Gd n pm root st node ∧ Gd n pm root st sig) →
    J t n pm root (sHtRootTail p tk layer tree node sig remaining) Pre (fun v st => Gd n pm root st v)
  | 0, _, _, _, _, _, _, h => J.pure' (fun st hI hp => (h st hI hp).2.1)
  | remaining+1, layer, tree, node, sig, _, hs, h => by
    simp only [sHtRootTail]
    refine J.bind (Q := fun v st => Gd n pm root st v)
      (J.reveal (fun st hI hp => (h st hI hp).2.1) (fun nb => ?_) hs) (fun r => ?_) hs
    · exact j_xmssPkFromSig p tk _ _ _ nb hs (fun st hI hp => ⟨(h st hI hp).1, gd_take (h st hI hp).2.2 _⟩)
    · exact j_htRootTail p tk remaining _ _ r _ (stable_and hs (stable_gd r))
        (fun st hI hp => ⟨(h st hI hp.1).1, hp.2, gd_drop (h st hI hp.1).2.2 _⟩)

theorem j_htRoot (p : Params) (tk sig msg : SB) (idxTree idxLeaf : Nat) {Pre : St → Prop}
    (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st →
      Gd n pm root st tk ∧ Gd n pm root st sig ∧ Gd n pm root st msg) :
    J t n pm root (sHtRoot p tk sig msg idxTree idxLeaf) Pre (fun v st => Gd n pm root st v) := by
  simp only [sHtRoot]
  refine J.bind (Q := fun v st => Gd n pm root st v)
    (J.reveal (fun st hI hp => (h st hI hp).2.2) (fun mb => ?_) hs) (fun node => ?_) hs
  · exact j_xmssPkFromSig p tk _ _ _ mb hs (fun st hI hp => ⟨(h st hI hp).1, gd_take (h st hI hp).2.1 _⟩)
  · exact j_htRootTail p tk _ _ _ node _ (stable_and hs (stable_gd node))
      (fun st hI hp => ⟨(h st hI hp.1).1, hp.2, gd_drop (h st hI hp.1).2.1 _⟩)

theorem j_forsPkFromSig (p : Params) (tk : SB) (a : Adrs) (sig : SB) (md : Bytes) {Pre : St → Prop}
    (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → Gd n pm root st tk ∧ Gd n pm root st sig) :
    J t n pm root (sForsPkFromSig p tk a sig md) Pre (fun v st => Gd n pm root st v) := by
  simp only [sForsPkFromSig, sAuthRoot]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_)
    (fun roots => J.conseq (j_thash p tk _ roots (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩))
      (fun _ _ h => h) (fun _ _ h => gd_of_one h)) hs
  intro x _ s
  obtain ⟨idx, i⟩ := x
  have hs' := stable_and hs (stable_gd s)
  exact J.bind (j_thash p tk _ _ (fun st hI hp => ⟨(h st hI hp.1).1, gd_take (gd_slice (h st hI hp.1).2 _ _) 1⟩))
    (fun leaf => J.bind (j_authWalk p tk a _ _ _ _ _ leaf (stable_and hs' (stable_one _ leaf))
        (fun st hI hp => ⟨(h st hI hp.1.1).1, gd_drop (gd_slice (h st hI hp.1.1).2 _ _) 1, gd_of_one hp.2⟩))
      (fun r => J.pure' (fun st _ hp => gd_append hp.1.1.2 hp.2)) (stable_and hs' (stable_one _ leaf))) hs'

/-! Signing-side twins: the key context. -/

/-- The signer's key context: tweak key, PRF key, public seed. -/
def KS (n pm : Nat) (root : SB) (st : St) (tk prfKey seed : SB) : Prop :=
  Gd n pm root st tk ∧ PK n st prfKey ∧ Gd n pm root st seed

theorem stable_ks (tk prfKey seed : SB) : Stable t n pm root (fun st => KS n pm root st tk prfKey seed) :=
  fun st st' hI hx h => ⟨good_mono hI hx h.1, stable_pk prfKey st st' hI hx h.2.1, good_mono hI hx h.2.2⟩

variable (p : Params) (tk prfKey seed : SB)

theorem j_wotsSign (a : Adrs) (msg : Bytes) {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) :
    J t n pm root (sWotsSign p tk prfKey seed a msg) Pre (fun v st => Gd n pm root st v) := by
  simp only [sWotsSign]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_) (fun _ => J.pure' (fun _ _ hp => hp.2)) hs
  intro x _ s
  obtain ⟨digit, i⟩ := x
  have hs' := stable_and hs (stable_gd s)
  exact J.bind (j_prf p prfKey seed _ (fun st hI hp => ⟨(h st hI hp.1).2.1, (h st hI hp.1).2.2⟩))
    (fun sk => J.bind (j_chain p tk _ digit sk 0 (stable_and hs' (stable_one _ sk))
        (fun st hI hp => ⟨(h st hI hp.1.1).1, gd_of_one hp.2⟩))
      (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.1.2 hp.2)) (stable_and hs' (stable_one _ sk))) hs'

theorem j_wotsPkgen (a : Adrs) {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) :
    J t n pm root (sWotsPkgen p tk prfKey seed a) Pre
      (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i) := by
  simp only [sWotsPkgen, sWotsCompress]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_)
    (fun tops => j_thash p tk _ tops (fun st hI hp => ⟨(h st hI hp.1).1, hp.2⟩)) hs
  intro i _ s
  have hs' := stable_and hs (stable_gd s)
  exact J.bind (j_prf p prfKey seed _ (fun st hI hp => ⟨(h st hI hp.1).2.1, (h st hI hp.1).2.2⟩))
    (fun sk => J.bind (j_chain p tk _ 15 sk 0 (stable_and hs' (stable_one _ sk))
        (fun st hI hp => ⟨(h st hI hp.1.1).1, gd_of_one hp.2⟩))
      (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.1.2 hp.2)) (stable_and hs' (stable_one _ sk))) hs'

theorem j_xmssNode (a : Adrs) : ∀ (height idx : Nat) {Pre : St → Prop}, Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) →
    J t n pm root (sXmssNode p tk prfKey seed a idx height) Pre
      (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i)
  | 0, _, _, hs, h => by simp only [sXmssNode]; exact j_wotsPkgen p tk prfKey seed _ hs h
  | height+1, idx, _, hs, h => by
    simp only [sXmssNode]
    exact J.bind (j_xmssNode a height (2*idx) hs h)
      (fun l => J.bind (j_xmssNode a height (2*idx+1) (stable_and hs (stable_one _ l))
          (fun st hI hp => h st hI hp.1))
        (fun r => j_thash p tk _ _ (fun st hI hp => ⟨(h st hI hp.1.1).1,
          gd_append (gd_of_one hp.1.2) (gd_of_one hp.2)⟩)) (stable_and hs (stable_one _ l))) hs

theorem j_xmssSign (a : Adrs) (idx : Nat) (msg : Bytes) {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) :
    J t n pm root (sXmssSign p tk prfKey seed a idx msg) Pre (fun v st => Gd n pm root st v) := by
  simp only [sXmssSign]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_)
    (fun auth => J.bind (j_wotsSign p tk prfKey seed _ msg (stable_and hs (stable_gd auth))
        (fun st hI hp => h st hI hp.1))
      (fun _ => J.pure' (fun _ _ hp => gd_append hp.2 hp.1.2)) (stable_and hs (stable_gd auth))) hs
  intro level _ s
  exact J.bind (j_xmssNode p tk prfKey seed a _ _ (stable_and hs (stable_gd s)) (fun st hI hp => h st hI hp.1))
    (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.2 (gd_of_one hp.2))) (stable_and hs (stable_gd s))

theorem j_htSignTail : ∀ (remaining layer tree : Nat) (node : SB) {Pre : St → Prop}, Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed ∧ Gd n pm root st node) →
    J t n pm root (sHtSignTail p tk prfKey seed layer tree node remaining) Pre (fun v st => Gd n pm root st v)
  | 0, _, _, _, _, _, _ => J.pure' (fun st _ _ => gd_nil st)
  | remaining+1, layer, tree, node, _, hs, h => by
    simp only [sHtSignTail]
    refine J.reveal (fun st hI hp => (h st hI hp).2) (fun nb => ?_) hs
    refine J.bind (j_xmssSign p tk prfKey seed _ _ nb hs (fun st hI hp => (h st hI hp).1)) (fun part => ?_) hs
    have hs1 := stable_and hs (stable_gd part)
    refine J.ite (fun _ => J.pure' (fun _ _ hp => hp.2)) (fun _ => ?_)
    have hs2 := stable_and hs1 stable_true
    refine J.bind J.unit (fun _ => ?_) hs1
    refine J.bind (j_xmssPkFromSig p tk _ _ part nb hs2
      (fun st hI hp => ⟨(h st hI hp.1.1).1.1, hp.1.2⟩)) (fun r => ?_) hs2
    have hs3 := stable_and hs2 (stable_gd r)
    exact J.bind (j_htSignTail remaining _ _ r hs3 (fun st hI hp => ⟨(h st hI hp.1.1.1).1, hp.2⟩))
      (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.1.1.2 hp.2)) hs3

theorem j_htSign (msg : SB) (idxTree idxLeaf : Nat) {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed ∧ Gd n pm root st msg) :
    J t n pm root (sHtSign p tk prfKey seed msg idxTree idxLeaf) Pre (fun v st => Gd n pm root st v) := by
  simp only [sHtSign]
  refine J.reveal (fun st hI hp => (h st hI hp).2) (fun mb => ?_) hs
  refine J.bind (j_xmssSign p tk prfKey seed _ _ mb hs (fun st hI hp => (h st hI hp).1)) (fun first => ?_) hs
  have hs1 := stable_and hs (stable_gd first)
  refine J.bind (j_xmssPkFromSig p tk _ _ first mb hs1 (fun st hI hp => ⟨(h st hI hp.1).1.1, hp.2⟩))
    (fun r => ?_) hs1
  have hs2 := stable_and hs1 (stable_gd r)
  exact J.bind (j_htSignTail p tk prfKey seed _ _ _ r hs2 (fun st hI hp => ⟨(h st hI hp.1.1).1, hp.2⟩))
    (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.1.2 hp.2)) hs2

theorem j_forsNode (a : Adrs) : ∀ (height idx : Nat) {Pre : St → Prop}, Stable t n pm root Pre →
    (∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) →
    J t n pm root (sForsNode p tk prfKey seed a idx height) Pre
      (fun v st => ∃ i, v = [.hid i p.n] ∧ Safe n pm root st i)
  | 0, _, _, hs, h => by
    simp only [sForsNode, sForsSecret]
    exact J.bind (j_prf p prfKey seed _ (fun st hI hp => ⟨(h st hI hp).2.1, (h st hI hp).2.2⟩))
      (fun sk => j_thash p tk _ sk (fun st hI hp => ⟨(h st hI hp.1).1, gd_of_one hp.2⟩)) hs
  | height+1, idx, _, hs, h => by
    simp only [sForsNode]
    exact J.bind (j_forsNode a height (2*idx) hs h)
      (fun l => J.bind (j_forsNode a height (2*idx+1) (stable_and hs (stable_one _ l))
          (fun st hI hp => h st hI hp.1))
        (fun r => j_thash p tk _ _ (fun st hI hp => ⟨(h st hI hp.1.1).1,
          gd_append (gd_of_one hp.1.2) (gd_of_one hp.2)⟩)) (stable_and hs (stable_one _ l))) hs

theorem j_forsSign (a : Adrs) (md : Bytes) {Pre : St → Prop} (hs : Stable t n pm root Pre)
    (h : ∀ st, Inv t n pm root st → Pre st → KS n pm root st tk prfKey seed) :
    J t n pm root (sForsSign p tk prfKey seed a md) Pre (fun v st => Gd n pm root st v) := by
  simp only [sForsSign, sForsSecret]
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs (fun s => stable_gd s) []
      (fun st _ _ => gd_nil st) ?_) (fun _ => J.pure' (fun _ _ hp => hp.2)) hs
  intro x _ s
  obtain ⟨idx, i⟩ := x
  have hs1 := stable_and hs (stable_gd s)
  refine J.bind (j_prf p prfKey seed _ (fun st hI hp => ⟨(h st hI hp.1).2.1, (h st hI hp.1).2.2⟩))
    (fun sk => ?_) hs1
  have hs2 := stable_and hs1 (stable_one p.n sk)
  refine J.bind (J.loop' _ _ (fun s st => Gd n pm root st s) hs2 (fun s => stable_gd s) _
      (fun st _ hp => gd_append hp.1.2 (gd_of_one hp.2)) ?_)
    (fun b => J.bind J.unit (fun _ => J.pure' (fun _ _ hp => hp.1.2)) (stable_and hs2 (stable_gd b))) hs2
  intro level _ u
  have hs3 := stable_and hs2 (stable_gd u)
  exact J.bind (j_forsNode p tk prfKey seed a _ _ hs3 (fun st hI hp => h st hI hp.1.1.1))
    (fun node => J.bind J.unit (fun _ => J.pure' (fun _ _ hp => gd_append hp.1.1.2 (gd_of_one hp.1.2)))
      (stable_and hs3 (stable_one _ node))) hs3
end

/-! The key derivations, the randomizer and the signing request. -/

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem J.obtain {α : Type} {P : Prog α} {Pre : St → Prop} {Q : α → St → Prop} {v : SB} {w : Nat}
    {X : Nat → St → Prop} (h : ∀ i, v = [.hid i w] → J t n pm root P (fun st => Pre st ∧ X i st) Q) :
    J t n pm root P (fun st => Pre st ∧ ∃ i, v = [.hid i w] ∧ X i st) Q :=
  fun st hI ⟨hp, i, hv, hx⟩ hnd => h i hv st hI ⟨hp, hx⟩ hnd

theorem stable_entry (i : Nat) (e : Bool × SReq) : Stable t n pm root (fun st => st.ents[i]? = some e) :=
  fun _ _ _ hx h => ext_get hx h

theorem stable_safe (i : Nat) : Stable t n pm root (fun st => Safe n pm root st i) :=
  fun _ _ hI hx h => safe_mono hI hx h

theorem safe_two {st : St} (hI : Inv t n pm root st) : Safe n pm root st 2 :=
  safe_of_req hI.1.2.2 (fun h hm => by simp [coin, SReq.hids, shids] at hm; omega)
    (fun j m hr => by simp [coin, rqOf] at hr)

theorem lt_of_entry {st : St} {i : Nat} {e : Bool × SReq} (h : st.ents[i]? = some e) : i < st.ents.length :=
  (List.getElem?_eq_some_iff.mp h).1

/-- The tweak key: derived from PK.seed, disclosable. -/
theorem ask_tk {Pre : St → Prop} :
    J t n pm root (sAsk ⟨0, "DSM/sphincs/v2/thash", [], [.hid 2 n], 32⟩) Pre
      (fun v st => ∃ i, v = [.hid i 32] ∧ Safe n pm root st i) :=
  J.ask_safe _ (fun st hI _ => ⟨fun h hm => by
      simp [SReq.hids, shids] at hm
      subst hm
      exact safe_ne hI (safe_two hI), fun j m hr => by simp [rqOf] at hr⟩)

/-- The WOTS/FORS PRF key: derived from SK.seed, never disclosed. -/
theorem ask_dPrf {Pre : St → Prop} :
    J t n pm root (sAsk (dPrf n)) Pre (fun v st => ∃ i, v = [.hid i 32] ∧ st.ents[i]? = some (false, dPrf n)) :=
  J.ask_closed _ (fun st hI _ => ⟨fun h hm => by
      simp [dPrf, SReq.hids, shids] at hm
      subst hm
      exact lt_of_entry hI.1.1,
    ⟨0, by simp [dPrf, SReq.hids, shids], not_rev_of_prot hI (prot_zero hI)⟩⟩)

/-- The PRF-msg key: derived from SK.prf, never disclosed. -/
theorem ask_dReq {Pre : St → Prop} :
    J t n pm root (sAsk (dReq n)) Pre (fun v st => ∃ i, v = [.hid i 32] ∧ st.ents[i]? = some (false, dReq n)) :=
  J.ask_closed _ (fun st hI _ => ⟨fun h hm => by
      simp [dReq, SReq.hids, shids] at hm
      subst hm
      exact lt_of_entry hI.1.2.1,
    ⟨1, by simp [dReq, SReq.hids, shids], not_rev_of_prot hI (prot_one hI)⟩⟩)

/-- The randomizer request: keyed with the undisclosed PRF-msg key, so it is never open. -/
theorem ask_rq (dk : Nat) (m : Bytes) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → st.ents[dk]? = some (false, dReq n)) :
    J t n pm root (sAsk (rqOf n dk m)) Pre
      (fun v st => ∃ i, v = [.hid i n] ∧ st.ents[i]? = some (false, rqOf n dk m)) :=
  J.ask_closed _ (fun st hI hp => ⟨fun x hx => by
      simp [rqOf, SReq.hids, shids] at hx
      rcases hx with rfl | rfl
      · exact lt_of_entry (h st hI hp)
      · exact lt_of_entry hI.1.2.2,
    ⟨dk, by simp [rqOf, SReq.hids, shids], not_rev_of_prot hI (prot_of_dReq (h st hI hp))⟩⟩)

theorem rq_ne {st : St} (hI : Inv t n pm root st) {dk : Nat} (hdk : st.ents[dk]? = some (false, dReq n)) :
    dk ≠ 0 ∧ dk ≠ 1 := by
  refine ⟨fun e => ?_, fun e => ?_⟩
  · subst e; rw [hI.1.1] at hdk; simp [coin, dReq] at hdk
  · subst e; rw [hI.1.2.1] at hdk; simp [coin, dReq] at hdk

theorem safe_rq {st : St} (hI : Inv t n pm root st) {i dk : Nat} {m : Bytes}
    (hi : st.ents[i]? = some (false, rqOf n dk m)) (hdk : st.ents[dk]? = some (false, dReq n))
    (hc : ∃ c : Nat, st.ents[c]? = some (false, hqOf n pm root i m)) : Safe n pm root st i := by
  refine ⟨lt_of_entry hi, ?_, ?_⟩
  · rintro ⟨e, he, h3⟩
    rw [hi] at he
    obtain rfl := Option.some.inj he
    have := rq_ne hI hdk
    simp [rqOf, SReq.hids, shids] at h3
    omega
  · intro j m' hj _
    rw [hi] at hj
    have := Option.some.inj hj
    simp only [Prod.mk.injEq, rqOf, SReq.mk.injEq, List.cons.injEq, SV.hid.injEq, SV.lit.injEq,
      true_and, and_true] at this
    obtain ⟨rfl, rfl⟩ := this
    exact hc

/-- The signing request: on a disagreement-free step it is drawn challenger-side (or was
    already), and afterwards the randomizer may be disclosed. -/
theorem J.hmsg (i : Nat) (m : Bytes) {Pre : St → Prop}
    (h : ∀ st, Inv t n pm root st → Pre st → ∃ dk, st.ents[i]? = some (false, rqOf n dk m) ∧
      st.ents[dk]? = some (false, dReq n) ∧ Gd n pm root st root) :
    J t n pm root (sAsk (hqOf n pm root i m)) Pre (fun v st =>
      (∃ k, v = [.hid k pm] ∧ Safe n pm root st k) ∧ Safe n pm root st i ∧
        ∃ c : Nat, st.ents[c]? = some (false, hqOf n pm root i m)) := by
  have hids : ∀ st, Inv t n pm root st → Pre st →
      ∀ x ∈ (hqOf n pm root i m).hids, x < st.ents.length ∧ x ≠ 0 ∧ x ≠ 1 := by
    intro st hI hp x hx
    obtain ⟨dk, hi, hdk, hr⟩ := h st hI hp
    have hx' : x = i ∨ x = 2 ∨ x ∈ shids root := by
      simpa [hqOf, SReq.hids, shids, shids_append] using hx
    rcases hx' with rfl | rfl | hx
    · refine ⟨lt_of_entry hi, fun e => ?_, fun e => ?_⟩
      · subst e; rw [hI.1.1] at hi; simp [coin, rqOf] at hi
      · subst e; rw [hI.1.2.1] at hi; simp [coin, rqOf] at hi
    · exact safe_ne hI (safe_two hI)
    · exact gd_hids hI hr x hx
  refine J.ask _ (fun st hI hp x hx => (hids st hI hp x hx).1) (fun st hI hp hd _ => ?_)
  obtain ⟨dk, hi, hdk, _⟩ := h st hI hp
  have hx := (step_askC st _ hI (fun x hx => (hids st hI hp x hx).1) hd).2
  have hc : ∃ c : Nat, (addC st (firstIdx (mC false t st.rev (hqOf n pm root i m)) st.ents)
      (hqOf n pm root i m)).ents[c]? = some (false, hqOf n pm root i m) := by
    by_cases hr : i ∈ st.rev
    · obtain ⟨c, hc⟩ := (hI.2.2.2.2 i hr).2.2 dk m hi hdk
      exact ⟨c, ext_get hx hc⟩
    · exact ⟨_, step_askC_closed st _ hI ⟨i, by simp [hqOf, SReq.hids, shids], hr⟩⟩
  refine ⟨⟨_, rfl, step_askC_safe st _ hI (fun x hx => (hids st hI hp x hx).1)
    (fun x hx => (hids st hI hp x hx).2) (fun j m' e => by simp [hqOf, rqOf] at e)⟩, ?_, hc⟩
  have hI' := (step_askC st _ hI (fun x hx => (hids st hI hp x hx).1) hd).1
  exact safe_rq hI' (ext_get hx hi) (ext_get hx hdk) hc
end

/-! Key generation and signing. -/

section
variable {t : List Nat}

/-- Message `m`'s signing request has a challenger entry. -/
def SymH (n pm : Nat) (root : SB) (st : St) (m : Bytes) : Prop :=
  ∃ c i : Nat, st.ents[c]? = some (false, hqOf n pm root i m)

theorem stable_symh {n pm : Nat} {root : SB} (m : Bytes) :
    Stable t n pm root (fun st => SymH n pm root st m) :=
  fun _ _ _ hx ⟨c, i, h⟩ => ⟨c, i, ext_get hx h⟩

theorem j_kgTail (v : Variant) {pm : Nat} {root : SB} :
    J t (params v).n pm root (sKgTail v (coinEx (params v).n)) (fun _ => True)
      (fun ks st => ∃ ρ, ks.1 = [.hid 2 (params v).n, .hid ρ (params v).n] ∧
        ks.2 = coinEx (params v).n ++ [.hid ρ (params v).n] ∧ Safe (params v).n pm root st ρ) := by
  simp only [sKgTail, sDeriveKey]
  refine J.bind ask_tk (fun tk => J.obtain (fun itk htk => ?_)) stable_true
  subst htk
  refine J.bind ask_dPrf (fun pk => J.obtain (fun ipk hpk => ?_)) (stable_and stable_true (stable_safe itk))
  subst hpk
  have hs := stable_and (stable_and (stable_true (t := t) (n := (params v).n) (pm := pm) (root := root))
    (stable_safe itk)) (stable_entry ipk (false, dPrf (params v).n))
  refine J.bind (j_xmssNode (params v) _ _ _ _ _ _ hs
      (fun st hI hp => ⟨gd_one hp.1.2, ⟨ipk, rfl, hp.2⟩, gd_one (safe_two hI)⟩))
    (fun r => J.obtain (fun ρ hr => ?_)) hs
  subst hr
  exact J.pure' (fun _ _ hp => ⟨ρ, rfl, rfl, hp.2⟩)

theorem j_sign (v : Variant) (ρ : Nat) (msg : Bytes) (hne : msg.isEmpty = false) :
    J t (params v).n (params v).m [.hid ρ (params v).n]
      (sSign v (coinEx (params v).n ++ [.hid ρ (params v).n]) msg)
      (fun st => Safe (params v).n (params v).m [.hid ρ (params v).n] st ρ)
      (fun res st => SymH (params v).n (params v).m [.hid ρ (params v).n] st msg ∧
        ∀ sg, res = some sg → Gd (params v).n (params v).m [.hid ρ (params v).n] st sg) := by
  simp only [sSign, sDeriveKey, sKeyed, sHmsg]
  apply J.ite
  · intro hc; exfalso; simp [hne, coinEx] at hc
  · intro _
    have s0 : Stable t (params v).n (params v).m [.hid ρ (params v).n]
        (fun st => Safe (params v).n (params v).m [.hid ρ (params v).n] st ρ) := stable_safe ρ
    refine J.bind J.unit (fun _ => ?_) s0
    have s1 := stable_and s0 stable_true
    refine J.bind ask_tk (fun tk => J.obtain (fun itk htk => ?_)) s1
    subst htk
    have s2 := stable_and s1 (stable_safe itk)
    refine J.bind ask_dPrf (fun pk => J.obtain (fun ipk hpk => ?_)) s2
    subst hpk
    have s3 := stable_and s2 (stable_entry ipk (false, dPrf (params v).n))
    refine J.bind ask_dReq (fun mk => J.obtain (fun dk hmk => ?_)) s3
    subst hmk
    have s4 := stable_and s3 (stable_entry dk (false, dReq (params v).n))
    refine J.bind (ask_rq dk msg (fun st _ hp => hp.2)) (fun r => J.obtain (fun iR hr => ?_)) s4
    subst hr
    have s5 := stable_and s4 (stable_entry iR (false, rqOf (params v).n dk msg))
    refine J.bind (J.hmsg iR msg (fun st _ hp => ⟨dk, hp.2, hp.1.2, gd_one hp.1.1.1.1.1⟩)) (fun dg => ?_) s5
    have sC := stable_and (stable_safe (t := t) (n := (params v).n) (pm := (params v).m)
      (root := [.hid ρ (params v).n]) ρ) (stable_and (stable_safe itk)
      (stable_and (stable_entry ipk (false, dPrf (params v).n)) (stable_and (stable_safe iR)
        (stable_and (stable_symh msg) (stable_gd dg)))))
    refine J.conseq (Pre := fun st => Safe (params v).n (params v).m [.hid ρ (params v).n] st ρ ∧
      Safe (params v).n (params v).m [.hid ρ (params v).n] st itk ∧
      st.ents[ipk]? = some (false, dPrf (params v).n) ∧
      Safe (params v).n (params v).m [.hid ρ (params v).n] st iR ∧
      SymH (params v).n (params v).m [.hid ρ (params v).n] st msg ∧
      Gd (params v).n (params v).m [.hid ρ (params v).n] st dg) ?_ ?_ (fun _ _ h => h)
    rotate_left
    · intro st _ hp
      obtain ⟨c, hc⟩ := hp.2.2.2
      exact ⟨hp.1.1.1.1.1.1, hp.1.1.1.1.2, hp.1.1.1.2, hp.2.2.1, ⟨c, iR, hc⟩, gd_of_one hp.2.1⟩
    refine J.reveal (fun st _ hp => hp.2.2.2.2.2) (fun dgb => ?_) sC
    refine J.bind (j_forsSign (params v) _ _ _ _ _ sC
      (fun st hI hp => ⟨gd_one hp.2.1, ⟨ipk, rfl, hp.2.2.1⟩, gd_one (safe_two hI)⟩)) (fun fs => ?_) sC
    have sC1 := stable_and sC (stable_gd fs)
    refine J.bind (j_forsPkFromSig (params v) _ _ fs _ sC1 (fun st _ hp => ⟨gd_one hp.1.2.1, hp.2⟩))
      (fun fpk => ?_) sC1
    have sC2 := stable_and sC1 (stable_gd fpk)
    refine J.bind (j_htSign (params v) _ _ _ fpk _ _ sC2
      (fun st hI hp => ⟨⟨gd_one hp.1.1.2.1, ⟨ipk, rfl, hp.1.1.2.2.1⟩, gd_one (safe_two hI)⟩, hp.2⟩))
      (fun hs => ?_) sC2
    have sC3 := stable_and sC2 (stable_gd hs)
    refine J.bind (j_htRoot (params v) _ hs fpk _ _ sC3 (fun st _ hp => ⟨gd_one hp.1.1.1.2.1, hp.2, hp.1.2⟩))
      (fun ac => ?_) sC3
    have sC4 := stable_and sC3 (stable_gd ac)
    refine J.reveal (fun st _ hp => hp.2) (fun ab => ?_) sC4
    refine J.reveal (fun st _ hp => gd_one hp.1.1.1.1.1) (fun rb => ?_) sC4
    apply J.ite
    · intro _
      exact J.pure' (fun _ _ hp => ⟨hp.1.1.1.1.2.2.2.2.1, fun sg h => by cases h⟩)
    · intro _
      refine J.bind J.unit (fun _ => J.pure' (fun _ _ hp => ⟨hp.1.1.1.1.1.2.2.2.2.1, fun sg h => ?_⟩)) sC4
      cases h
      exact gd_append (gd_append (gd_one hp.1.1.1.1.1.2.2.2.1) hp.1.1.1.1.2) hp.1.1.2
end

/-! The adversary's verification issues only adversary requests. -/

section
variable {t : List Nat} {n pm : Nat} {root : SB}

theorem jA (r : Request) {Pre : St → Prop} (hs : Stable t n pm root Pre) :
    J t n pm root (advP r) Pre (fun _ st => Pre st) :=
  J.askA (fun _ => J.pure' (fun _ _ h => h)) hs

theorem J.bindA {α β : Type} {P : Prog α} {f : α → Prog β} {Pre : St → Prop}
    (hP : J t n pm root P Pre (fun _ st => Pre st)) (hf : ∀ a, J t n pm root (f a) Pre (fun _ st => Pre st))
    (hs : Stable t n pm root Pre) : J t n pm root (P >>= f) Pre (fun _ st => Pre st) :=
  J.bind hP (fun a => J.conseq (hf a) (fun _ _ h => h.1) (fun _ _ h => h)) hs

variable {Pre : St → Prop} (hs : Stable t n pm root Pre)
include hs

theorem jA_chain (p : Params) (tk : Bytes) (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    J t n pm root (chain advP p tk a x start steps) Pre (fun _ st => Pre st)
  | 0, _, _ => J.pure' (fun _ _ h => h)
  | steps+1, x, start => by
    simp only [chain]
    exact J.bindA (jA _ hs) (fun y => jA_chain p tk a steps y (start+1)) hs

theorem jA_authWalk (p : Params) (tk : Bytes) (a : Adrs) (auth : Bytes) :
    ∀ (remaining li gi level : Nat) (node : Bytes),
    J t n pm root (authWalk advP p tk a li gi node auth level remaining) Pre (fun _ st => Pre st)
  | 0, _, _, _, _ => J.pure' (fun _ _ h => h)
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact J.bindA (jA _ hs) (fun y => jA_authWalk p tk a auth remaining _ _ _ y) hs

theorem jA_wotsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
    J t n pm root (wotsPkFromSig advP p tk a sig msg) Pre (fun _ st => Pre st) := by
  simp only [wotsPkFromSig, wotsCompress, thash, keyed]
  refine J.bindA (J.loop' _ _ (fun _ st => Pre st) hs (fun _ => hs) [] (fun _ _ h => h) ?_) (fun _ => jA _ hs) hs
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact J.bind (jA_chain (stable_and hs hs) p tk _ _ _ _) (fun _ => J.pure' (fun _ _ h => h.1.1)) (stable_and hs hs)

theorem jA_xmssPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    J t n pm root (xmssPkFromSig advP p tk a idx sig msg) Pre (fun _ st => Pre st) := by
  simp only [xmssPkFromSig, authRoot]
  exact J.bindA (jA_wotsPkFromSig hs p tk _ _ _) (fun _ => jA_authWalk hs p tk _ _ _ _ _ _ _) hs

theorem jA_htRootTail (p : Params) (tk : Bytes) : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    J t n pm root (htRootTail advP p tk layer tree node sig remaining) Pre (fun _ st => Pre st)
  | 0, _, _, _, _ => J.pure' (fun _ _ h => h)
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact J.bindA (jA_xmssPkFromSig hs p tk _ _ _ _) (fun y => jA_htRootTail p tk remaining _ _ y _) hs

theorem jA_htRoot (p : Params) (tk sig msg : Bytes) (tree leaf : Nat) :
    J t n pm root (htRoot advP p tk sig msg tree leaf) Pre (fun _ st => Pre st) := by
  simp only [htRoot]
  exact J.bindA (jA_xmssPkFromSig hs p tk _ _ _ _) (fun y => jA_htRootTail hs p tk _ _ _ y _) hs

theorem jA_forsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig md : Bytes) :
    J t n pm root (forsPkFromSig advP p tk a sig md) Pre (fun _ st => Pre st) := by
  simp only [forsPkFromSig, authRoot, thash, keyed]
  refine J.bindA (J.loop' _ _ (fun _ st => Pre st) hs (fun _ => hs) [] (fun _ _ h => h) ?_) (fun _ => jA _ hs) hs
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact J.bind (jA _ (stable_and hs hs)) (fun _ => J.bind (jA_authWalk (stable_and (stable_and hs hs)
      (stable_and hs hs)) p tk _ _ _ _ _ _ _)
    (fun _ => J.pure' (fun _ _ h => h.1.1.1)) (stable_and (stable_and hs hs) (stable_and hs hs)))
    (stable_and hs hs)

theorem jA_verify (v : Variant) (pk msg sig : Bytes) :
    J t n pm root (verify advP v pk msg sig) Pre (fun _ st => Pre st) := by
  simp only [verify]
  apply J.ite
  · intro _; exact J.pure' (fun _ _ h => h)
  · intro _
    refine J.bindA (J.pure' (fun _ _ h => h)) (fun _ => ?_) hs
    apply J.ite
    · intro _; exact J.pure' (fun _ _ h => h)
    · intro _
      refine J.bindA (J.pure' (fun _ _ h => h)) (fun _ => ?_) hs
      refine J.bindA (jA _ hs) (fun _ => ?_) hs
      refine J.bindA (jA _ hs) (fun _ => ?_) hs
      refine J.bindA (jA_forsPkFromSig hs _ _ _ _ _) (fun _ => ?_) hs
      refine J.bindA (jA_htRoot hs _ _ _ _ _ _) (fun _ => ?_) hs
      exact J.pure' (fun _ _ h => h)
end

/-! The game. -/

section
variable {t : List Nat}

theorem stable_all {n pm : Nat} {root : SB} (l : List Bytes) :
    Stable t n pm root (fun st => ∀ m ∈ l, SymH n pm root st m) :=
  fun st st' hI hx h m hm => stable_symh m st st' hI hx (h m hm)

theorem stable_res {n pm : Nat} {root : SB} (m : Bytes) (res : Option SB) :
    Stable t n pm root (fun st => SymH n pm root st m ∧ ∀ sg, res = some sg → Gd n pm root st sg) :=
  fun st st' hI hx h => ⟨stable_symh m st st' hI hx h.1, fun sg e => good_mono hI hx (h.2 sg e)⟩

theorem j_play (v : Variant) (limits : Limits) (pk : Bytes) (ρ : Nat) :
    ∀ (A : RAdv) (signed : List Bytes),
    J t (params v).n (params v).m [.hid ρ (params v).n]
      (playS v limits pk (coinEx (params v).n ++ [.hid ρ (params v).n]) A signed)
      (fun st => Safe (params v).n (params v).m [.hid ρ (params v).n] st ρ ∧
        ∀ m ∈ signed, SymH (params v).n (params v).m [.hid ρ (params v).n] st m)
      (fun out st => ∀ m ∈ out.signed, SymH (params v).n (params v).m [.hid ρ (params v).n] st m)
  | .hq r k, signed => J.askA (fun b => j_play v limits pk ρ (k b) signed)
      (stable_and (stable_safe ρ) (stable_all signed))
  | .sq m k, signed => by
    simp only [playS]
    apply J.ite
    · intro hl
      have hne : m.isEmpty = false := by
        unfold legal at hl; cases h : m.isEmpty <;> simp_all
      have hsP := stable_and (stable_safe (t := t) (n := (params v).n) (pm := (params v).m)
        (root := [.hid ρ (params v).n]) ρ) (stable_all signed)
      refine J.bind' (J.conseq (j_sign v ρ m hne) (fun _ _ h => h.1) (fun _ _ h => h)) (fun s => ?_) hsP
      cases s with
      | none =>
        refine J.conseq (j_play v limits pk ρ (k none) (signed ++ [m])) (fun st _ hp => ⟨hp.1.1, ?_⟩)
          (fun _ _ h => h)
        intro m' hm'
        rcases List.mem_append.mp hm' with h | h
        · exact hp.1.2 m' h
        · rw [List.mem_singleton.mp h]; exact hp.2.1
      | some sg =>
        refine J.reveal (fun st _ hp => hp.2.2 sg rfl) (fun sb => ?_) (stable_and hsP (stable_res m (some sg)))
        refine J.conseq (j_play v limits pk ρ (k (some sb)) (signed ++ [m])) (fun st _ hp => ⟨hp.1.1, ?_⟩)
          (fun _ _ h => h)
        intro m' hm'
        rcases List.mem_append.mp hm' with h | h
        · exact hp.1.2 m' h
        · rw [List.mem_singleton.mp h]; exact hp.2.1
    · intro _; exact j_play v limits pk ρ (k none) signed
  | .out m s, signed => by
    simp only [playS]
    exact J.bind' (jA_verify (stable_and (stable_safe ρ) (stable_all signed)) v pk m s)
      (fun _ => J.pure' (fun _ _ hp => hp.1.2)) (stable_and (stable_safe ρ) (stable_all signed))

theorem inv_coin (n pm : Nat) (root : SB) : Inv t n pm root (coinSt n) := by
  refine ⟨⟨rfl, rfl, rfl⟩, ?_, ?_, ?_, ?_⟩
  · intro i e he h hm
    simp only [coinSt] at he ⊢
    rcases i with _ | _ | _ | i <;> simp at he <;> subst he <;> simp [coin, SReq.hids, shids] at hm <;> simp [hm]
  · intro a qa he; rcases a with _ | _ | _ | a <;> simp [coinSt] at he
  · intro a c qa rc _ ha; rcases a with _ | _ | _ | a <;> simp [coinSt] at ha
  · intro i hi; simp [coinSt] at hi

/-- On a disagreement-free symbolic run of DSM's game, every signed message's signing
    request has a challenger entry, and the invariant holds at the end. -/
theorem sym_game (v : Variant) (limits : Limits) (A : Bytes → RAdv)
    (hnd : ∀ s ∈ strace t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n), dis t s = false) :
    ∃ ρ, Inv t (params v).n (params v).m [.hid ρ (params v).n]
        (xrun false t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 ∧
      ∀ m ∈ (xrun false t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.signed,
        SymH (params v).n (params v).m [.hid ρ (params v).n]
          (xrun false t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 m := by
  unfold gameS at hnd ⊢
  rw [strace_bind] at hnd
  rw [xrun_bind]
  have h1 := fun s hs => hnd s (List.mem_append_left _ hs)
  have h2 := fun s hs => hnd s (List.mem_append_right _ hs)
  obtain ⟨_, _, ρ, hk1, _, _⟩ := j_kgTail (t := t) v (pm := (params v).m) (root := []) _
    (inv_coin _ _ _) trivial h1
  obtain ⟨hI, _, ρ', hk1', hk2', hsafe⟩ := j_kgTail (t := t) v (pm := (params v).m)
    (root := [.hid ρ (params v).n]) _ (inv_coin _ _ _) trivial h1
  have hρ : ρ' = ρ := by rw [hk1] at hk1'; simp at hk1'; exact hk1'.symm
  subst hρ
  generalize xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n) = K at hk1 hk1' hk2' hI hsafe h2 ⊢
  obtain ⟨⟨ks1, ks2⟩, st⟩ := K
  simp only at hk1' hk2' hI hsafe h2 ⊢
  subst hk1' hk2'
  have := J.reveal (t := t) (Pre := fun st => Safe (params v).n (params v).m [.hid ρ' (params v).n] st ρ' ∧
      ∀ m ∈ ([] : List Bytes), SymH (params v).n (params v).m [.hid ρ' (params v).n] st m)
    (fun st hI hp => by
      intro i w hm
      simp only [List.mem_cons, SV.hid.injEq, List.not_mem_nil, or_false] at hm
      rcases hm with ⟨rfl, _⟩ | ⟨rfl, _⟩
      · exact safe_two hI
      · exact hp.1)
    (fun pk => j_play v limits pk ρ' (A pk) []) (stable_and (stable_safe ρ') (stable_all []))
    st hI ⟨hsafe, by simp⟩ h2
  exact ⟨ρ', this.1, this.2.2⟩
end

/-! Back to the real run: outside the disagreement event, `NoRG` holds. -/

theorem findDraw_min : ∀ (d : List Draw) (r : Request) (i : Nat), findDraw d r = some i →
    ∀ (j : Nat) (e : Draw), d[j]? = some e → e.2 = r → i ≤ j
  | [], _, _, h, _, _, _, _ => by simp [findDraw] at h
  | x :: d, r, i, h, j, e, hj, he => by
    simp only [findDraw] at h
    split at h
    · obtain rfl := Option.some.inj h; exact Nat.zero_le _
    · next hx =>
      cases j with
      | zero =>
        simp only [List.getElem?_cons_zero, Option.some.injEq] at hj
        subst hj
        exact absurd ((req_beq_iff _ _).mpr he) hx
      | succ j =>
        simp only [List.getElem?_cons_succ] at hj
        cases hf : findDraw d r with
        | none => rw [hf] at h; cases h
        | some k =>
          rw [hf] at h
          simp only [Option.map_some, Option.some.injEq] at h
          subst h
          exact Nat.succ_le_succ (findDraw_min d r k hf j e hj he)

theorem hq_res (t : List Nat) (v : Variant) (i ρ : Nat) (m : Bytes) :
    (hqOf (params v).n (params v).m [.hid ρ (params v).n] i m).res t =
      hreqR (params v) (be (params v).n (t.getD i 0)) (be (params v).n (t.getD 2 0))
        (be (params v).n (t.getD ρ 0)) m := by
  simp [hqOf, SReq.res, sres, SV.res, hreqR]

/-- Outside the disagreement event of the hidden-value bound, no signing request was
    first drawn by the adversary: `NoRG` holds on every tape whose symbolic run of DSM's
    game has no disagreement step. -/
theorem norg_of_nodis (v : Variant) (limits : Limits) (A : Bytes → RAdv) (t : List Nat)
    (hnd : anyDis (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false) :
    NoRG v limits A t := by
  have hnd' : ∀ s ∈ strace t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n),
      dis t s = false := by
    simp only [anyDis, List.any_eq_false] at hnd
    intro s hs; simpa using hnd s hs
  have hcp := coupling t _ _ hnd'
  obtain ⟨hrel, hdr⟩ := sim_game (t := t) v limits A (coinSt (params v).n)
  obtain ⟨ρ, hI, hsym⟩ := sym_game v limits A hnd'
  rw [← hcp] at hI hsym
  have hR1 : (runG v limits A t).1 =
      (xrun true t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).1 := hrel.symm
  have hR2 : (runG v limits A t).2 =
      resD t (xrun true t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 := hdr
  intro m hm i hi e he
  rw [hR1] at hm
  obtain ⟨c, iR, hc⟩ := hsym m hm
  have hcR : (runG v limits A t).2[c]? =
      some (false, (hqOf (params v).n (params v).m [.hid ρ (params v).n] iR m).res t) := by
    rw [hR2]; simp [resD, hc]
  obtain ⟨hmC, -⟩ := game_hmsg v limits A t
  obtain ⟨m', -, heq⟩ := hmC _ (mem_of_getElem? hcR) (by simp [isC, hqOf, SReq.res])
  have heq0 := heq
  simp only at heq
  have hmm : m = m' := by
    rw [hq_res] at heq
    unfold hreqOf at heq
    refine hreqR_msg _ _ _ _ _ _ _ _ _ heq ?_
    have hk := oracleOf_len t (runG v limits A t).2 ⟨1, "", deriveKey (finO v limits A t)
      "DSM/sphincs/v2/prf-msg" (slice (finKey v limits A t).2 (params v).n (params v).n),
      slice (finKey v limits A t).2 (2*(params v).n) (params v).n ++ m', (params v).n⟩
    have hsk := finKey_len v limits A t
    simp only [finO, slice] at hk
    simp only [List.length_append, be_width, keyed, slice, List.length_take, List.length_drop, hsk, finO,
      hk]
    omega
  subst hmm
  have hle := findDraw_min _ _ i hi c _ hcR heq0
  cases he1 : e.1
  · rfl
  · exfalso
    have hic : i ≠ c := by
      intro h; subst h; rw [hcR] at he; rw [← Option.some.inj he] at he1; cases he1
    have hlt : i < c := Nat.lt_of_le_of_ne hle hic
    obtain ⟨e', he', he'r⟩ := findDraw_get _ _ i hi
    rw [he] at he'; obtain rfl := Option.some.inj he'
    rw [hR2] at he
    simp only [resD, List.getElem?_map, Option.map_eq_some_iff] at he
    obtain ⟨⟨g, qa⟩, hqa, hge⟩ := he
    subst hge
    have hg : g = true := he1
    subst hg
    have h1 : qa.res t = hreqOf (finO v limits A t) v (finKey v limits A t).2 m := he'r
    exact hI.2.2.2.1 i c qa _ hlt hqa hc (by simp [hqOf]) (h1.trans heq0.symm)

/-! ITSR in the game with the guess of a randomizer charged to the hidden-value event. -/

theorem itsr_game_hid (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N q JA B : Nat)
    (hN : ∀ t : List Nat, t.length = N → (runG v limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG v limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG v limits A t).2.filter isA).length ≤ JA)
    (hj : ∀ j, tsum R N (covJ v limits A q j) * B ≤ R^N) :
    tsum R N (fun t => ind ((runG v limits A t).1.win = true ∧ CovG v limits A t)) * B ≤
      JA * R^N + tsum R N (fun t => if anyDis (gameS v limits A (coinEx (params v).n))
        (coinSt (params v).n) t then 1 else 0) * B := by
  have hpt : ∀ t, ind ((runG v limits A t).1.win = true ∧ CovG v limits A t) ≤
      ind ((runG v limits A t).1.win = true ∧ CovG v limits A t ∧ NoRG v limits A t) +
        (if anyDis (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) := by
    intro t
    by_cases hP : (runG v limits A t).1.win = true ∧ CovG v limits A t
    · cases hd : anyDis (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) t
      · rw [ind_of hP, ind_of ⟨hP.1, hP.2, norg_of_nodis v limits A t hd⟩]; simp
      · have := ind_le_one ((runG v limits A t).1.win = true ∧ CovG v limits A t); simp; omega
    · rw [ind_of_not hP]; exact Nat.zero_le _
  have h1 := tsum_mono R N hpt
  rw [tsum_add] at h1
  have h2 := Nat.mul_le_mul_right B h1
  rw [Nat.add_mul] at h2
  exact Nat.le_trans h2 (Nat.add_le_add_right (itsr_game_sum v limits A R N q JA B hN hC hJ hj) _)

/-- SPHINCS+-128f: won-and-covered tapes are at most `JA · 2^-128` plus the
    hidden-value disagreement tapes. -/
theorem itsr_game_hid_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true ∧
        CovG .spx128f limits A t)) * 2^128 ≤
      JA * (c * 256^(params .spx128f).m)^N +
        tsum (c * 256^(params .spx128f).m) N (fun t => if anyDis (gameS .spx128f limits A
          (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t then 1 else 0) * 2^128 :=
  itsr_game_hid .spx128f limits A _ N q JA _ hN hC hJ (fun j =>
    itsr_dsm_128f c N q hc hq (slotJ .spx128f limits A j q) (fun t _ => slotJ_assigned .spx128f limits A j q t))

/-- SPHINCS+-256f: won-and-covered tapes are at most `JA · 2^-255` plus the
    hidden-value disagreement tapes. -/
theorem itsr_game_hid_256f (limits : Limits) (A : Bytes → RAdv) (c N q JA : Nat) (hc : 0 < c) (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx256f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isA).length ≤ JA) :
    tsum (c * 256^(params .spx256f).m) N (fun t => ind ((runG .spx256f limits A t).1.win = true ∧
        CovG .spx256f limits A t)) * 2^255 ≤
      JA * (c * 256^(params .spx256f).m)^N +
        tsum (c * 256^(params .spx256f).m) N (fun t => if anyDis (gameS .spx256f limits A
          (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) t then 1 else 0) * 2^255 :=
  itsr_game_hid .spx256f limits A _ N q JA _ hN hC hJ (fun j =>
    itsr_dsm_256f c N q hc hq (slotJ .spx256f limits A j q) (fun t _ => slotJ_assigned .spx256f limits A j q t))

end DSM.Rom
