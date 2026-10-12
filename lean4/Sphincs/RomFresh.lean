-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSim

/- The hidden-value bound, charged at fresh steps only.

   `hidden_bound` charges every (step, compatible entry) pair. A challenger
   request asked again (every signature recomputes shared hypertree nodes) is
   charged again at every repetition, so its budget grows with the number of
   signing steps. Here the same bad event, `anyDis`, is charged only at
   *eligible* steps: adversary requests, and challenger requests whose
   symbolic lookup appends a new entry (fresh steps). This loses nothing:

   * before the first disagreement step, entries past the initial ones
     resolve to distinct requests (`trace_distK`);
   * so the first disagreement step is an adversary step or a fresh
     challenger step, unless two of the *initial* entries share a resolution
     (`first_dis_elig`, event `initColl`);
   * eligibility at a step depends on the tape only through revealed handles
     (`elig_set`), so the pinning argument of `hidden_bound` applies
     unchanged to the eligible probes (`hidden_bound_fresh`).

   A fresh challenger step occurs at most once per distinct challenger
   request: after it, the request has its own entry, which its lookup finds. -/
namespace DSM.Rom
open DSM.Sphincs

/-! List facts (local copies). -/

theorem fr_before {β : Type} (p : β → Bool) : ∀ (l : List β) (j : Nat) (b : β),
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
      exact fr_before p l j b h (by omega)

theorem fr_hit {β : Type} (p : β → Bool) : ∀ (l : List β), firstIdx p l < l.length →
    ∃ b, l[firstIdx p l]? = some b ∧ p b = true
  | [], h => by simp [firstIdx] at h
  | c :: l, h => by
    by_cases hc : p c = true
    · exact ⟨c, by simp [firstIdx, hc], hc⟩
    · simp only [firstIdx, hc, Bool.false_eq_true, if_false, List.length_cons] at h ⊢
      obtain ⟨b, hb, hpb⟩ := fr_hit p l (by omega)
      exact ⟨b, by simpa using hb, hpb⟩

theorem fr_snoc {β : Type} {l : List β} {x e : β} {j : Nat} (h : (l ++ [x])[j]? = some e) :
    (j < l.length ∧ l[j]? = some e) ∨ (j = l.length ∧ e = x) := by
  by_cases hj : j < l.length
  · left; rw [List.getElem?_append_left hj] at h; exact ⟨hj, h⟩
  · right
    rcases Nat.lt_or_ge j (l.length + 1) with h1 | h1
    · have hj' : j = l.length := by omega
      subst hj'
      simp at h
      exact ⟨rfl, h.symm⟩
    · rw [List.getElem?_eq_none (by simp; omega)] at h; cases h

theorem exists_min (Q : Nat → Prop) : ∀ n, Q n → ∃ m, Q m ∧ ∀ k, k < m → ¬ Q k := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro hn
    by_cases h : ∃ k, k < n ∧ Q k
    · obtain ⟨k, hk, hq⟩ := h
      exact ih k hk hq
    · exact ⟨n, hn, fun k hk hq => h ⟨k, hk, hq⟩⟩

/-! Distinct resolutions before the first disagreement. -/

/-- Every entry from index `k0` on resolves differently from every earlier entry. -/
def DistK (k0 : Nat) (t : List Nat) (st : St) : Prop :=
  ∀ (a b : Nat) (ea eb : Bool × SReq), a < b → k0 ≤ b → st.ents[a]? = some ea → st.ents[b]? = some eb →
    ea.2.res t ≠ eb.2.res t

theorem fr_dis_c {t : List Nat} {st : St} {r : SReq} (hd : dis t (st, .c r) = false) :
    ∀ e ∈ st.ents, mC true t st.rev r e = mC false t st.rev r e := by
  intro e he
  simp only [dis, List.any_eq_false] at hd
  have := hd e he
  revert this
  cases mC true t st.rev r e <;> cases mC false t st.rev r e <;> simp

theorem fr_dis_a {t : List Nat} {st : St} {q : Request} (hd : dis t (st, .a q) = false) :
    ∀ e ∈ st.ents, mA true t st.rev q e = mA false t st.rev q e := by
  intro e he
  simp only [dis, List.any_eq_false] at hd
  have := hd e he
  revert this
  cases mA true t st.rev q e <;> cases mA false t st.rev q e <;> simp

theorem distK_askC {k0 : Nat} {t : List Nat} {st : St} {r : SReq} (hD : DistK k0 t st)
    (hd : dis t (st, .c r) = false) :
    DistK k0 t (addC st (firstIdx (mC false t st.rev r) st.ents) r) := by
  generalize hi : firstIdx (mC false t st.rev r) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addC st i r = st := by simp [addC, hl]
    rw [this]; exact hD
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addC st i r = ⟨st.ents ++ [(false, r)], st.rev⟩ := by simp [addC, hl]
    rw [ha]
    have hreal : ∀ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e → mC true t st.rev r e = false := by
      intro j e he
      rw [fr_dis_c hd e (mem_of_getElem? he)]
      exact fr_before _ _ j e he (by rw [hi, hi']; exact (List.getElem?_eq_some_iff.mp he).1)
    intro a b ea eb hab hb ha' hb'
    rcases fr_snoc ha' with ⟨_, ha0⟩ | ⟨hal, _⟩
    · rcases fr_snoc hb' with ⟨_, hb0⟩ | ⟨_, hb0⟩
      · exact hD a b ea eb hab hb ha0 hb0
      · subst hb0
        have := hreal a ea ha0
        simpa [mC] using this
    · rcases fr_snoc hb' with ⟨hbl, _⟩ | ⟨hbl, _⟩ <;> omega

theorem distK_askA {k0 : Nat} {t : List Nat} {st : St} {q : Request} (hD : DistK k0 t st)
    (hd : dis t (st, .a q) = false) :
    DistK k0 t (addA st (firstIdx (mA false t st.rev q) st.ents) q) := by
  generalize hi : firstIdx (mA false t st.rev q) st.ents = i
  by_cases hl : i < st.ents.length
  · have : addA st i q = ⟨st.ents, i :: st.rev⟩ := by simp [addA, hl]
    rw [this]; exact hD
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    have ha : addA st i q = ⟨st.ents ++ [(true, lift q)], i :: st.rev⟩ := by simp [addA, hi']
    rw [ha]
    have hreal : ∀ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e → mA true t st.rev q e = false := by
      intro j e he
      rw [fr_dis_a hd e (mem_of_getElem? he)]
      exact fr_before _ _ j e he (by rw [hi, hi']; exact (List.getElem?_eq_some_iff.mp he).1)
    intro a b ea eb hab hb ha' hb'
    rcases fr_snoc ha' with ⟨_, ha0⟩ | ⟨hal, _⟩
    · rcases fr_snoc hb' with ⟨_, hb0⟩ | ⟨_, hb0⟩
      · exact hD a b ea eb hab hb ha0 hb0
      · subst hb0
        have := hreal a ea ha0
        simp only [mA, if_true, decide_eq_false_iff_not] at this
        rw [lift_res]; exact this
    · rcases fr_snoc hb' with ⟨hbl, _⟩ | ⟨hbl, _⟩ <;> omega

/-- Along a trace with no earlier disagreement, the entries past `k0` keep distinct
    resolutions and the initial entries stay a prefix. -/
theorem trace_distK {α : Type} (t : List Nat) (k0 : Nat) : ∀ (P : Prog α) (st : St),
    DistK k0 t st → k0 ≤ st.ents.length → ∀ (s : Nat) (stp : St × Ev), (strace t P st)[s]? = some stp →
    (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st)[s']? = some stp' → dis t stp' = false) →
    DistK k0 t stp.1 ∧ k0 ≤ stp.1.ents.length ∧ ∃ L, stp.1.ents = st.ents ++ L
  | .done _, _, _, _, _, _, hs, _ => by simp [strace] at hs
  | .askC r k, st, hD, hk, 0, stp, hs, _ => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs
    subst hs
    exact ⟨hD, hk, [], by simp⟩
  | .askC r k, st, hD, hk, s+1, stp, hs, hf => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have hd0 : dis t (st, .c r) = false := hf 0 _ (by omega) (by simp [strace])
    have hL : ∃ L, (addC st (firstIdx (mC false t st.rev r) st.ents) r).ents = st.ents ++ L := by
      unfold addC; split
      · exact ⟨[], by simp⟩
      · exact ⟨_, rfl⟩
    obtain ⟨L1, hL1⟩ := hL
    obtain ⟨h1, h2, L2, hL2⟩ := trace_distK t k0 _ _ (distK_askC hD hd0)
      (by rw [hL1]; simp; omega) s stp hs
      (fun s' stp' hs' hst => hf (s'+1) stp' (by omega) (by simpa [strace] using hst))
    exact ⟨h1, h2, L1 ++ L2, by rw [hL2, hL1, List.append_assoc]⟩
  | .askA q k, st, hD, hk, 0, stp, hs, _ => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs
    subst hs
    exact ⟨hD, hk, [], by simp⟩
  | .askA q k, st, hD, hk, s+1, stp, hs, hf => by
    simp only [strace, List.getElem?_cons_succ] at hs
    have hd0 : dis t (st, .a q) = false := hf 0 _ (by omega) (by simp [strace])
    have hL : ∃ L, (addA st (firstIdx (mA false t st.rev q) st.ents) q).ents = st.ents ++ L := by
      unfold addA; split
      · exact ⟨[], by simp⟩
      · exact ⟨_, rfl⟩
    obtain ⟨L1, hL1⟩ := hL
    obtain ⟨h1, h2, L2, hL2⟩ := trace_distK t k0 _ _ (distK_askA hD hd0)
      (by rw [hL1]; simp; omega) s stp hs
      (fun s' stp' hs' hst => hf (s'+1) stp' (by omega) (by simpa [strace] using hst))
    exact ⟨h1, h2, L1 ++ L2, by rw [hL2, hL1, List.append_assoc]⟩
  | .reveal x k, st, hD, hk, 0, stp, hs, _ => by
    simp only [strace, List.getElem?_cons_zero, Option.some.injEq] at hs
    subst hs
    exact ⟨hD, hk, [], by simp⟩
  | .reveal x k, st, hD, hk, s+1, stp, hs, hf => by
    simp only [strace, List.getElem?_cons_succ] at hs
    exact trace_distK t k0 _ ⟨st.ents, shids x ++ st.rev⟩ hD hk s stp hs
      (fun s' stp' hs' hst => hf (s'+1) stp' (by omega) (by simpa [strace] using hst))

/-! Eligible steps and the first disagreement. -/

/-- Adversary steps, and challenger steps whose symbolic lookup appends a new entry. -/
def elig (t : List Nat) (stp : St × Ev) : Bool :=
  match stp.2 with
  | .a _ => true
  | .c r => decide (stp.1.ents.length ≤ firstIdx (mC false t stp.1.rev r) stp.1.ents)
  | .r _ => false

/-- Two initial entries share a resolution. -/
def initColl (t : List Nat) (st0 : St) : Bool :=
  (List.range st0.ents.length).any (fun a => (List.range st0.ents.length).any (fun b =>
    decide (a < b) && (match st0.ents[a]?, st0.ents[b]? with
      | some ea, some eb => decide (ea.2.res t = eb.2.res t)
      | _, _ => false)))

theorem initColl_of {t : List Nat} {st0 : St} {a b : Nat} {ea eb : Bool × SReq} (hab : a < b)
    (ha : st0.ents[a]? = some ea) (hb : st0.ents[b]? = some eb) (h : ea.2.res t = eb.2.res t) :
    initColl t st0 = true := by
  have hbl := (List.getElem?_eq_some_iff.mp hb).1
  simp only [initColl, List.any_eq_true, List.mem_range]
  exact ⟨a, by omega, b, hbl, by simp [hab, ha, hb, h]⟩

theorem mC_false_true {t rev : List Nat} {r : SReq} {e : Bool × SReq} (h : mC false t rev r e = true) :
    e.2.res t = r.res t := by
  simp only [mC, Bool.false_eq_true, if_false, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true] at h
  rcases h with h | ⟨_, h⟩
  · rw [h]
  · exact h

/-- The first disagreement step is eligible, unless two initial entries collide. -/
theorem first_dis_elig {α : Type} (t : List Nat) (P : Prog α) (st0 : St) (s : Nat) (stp : St × Ev)
    (hs : (strace t P st0)[s]? = some stp) (hd : dis t stp = true)
    (hfirst : ∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) :
    elig t stp = true ∨ initColl t st0 = true := by
  obtain ⟨hDK, _, L, hL⟩ := trace_distK t st0.ents.length P st0
    (fun a b ea eb _ hb _ hbe => absurd (List.getElem?_eq_some_iff.mp hbe).1 (by omega)) (Nat.le_refl _)
    s stp hs hfirst
  obtain ⟨st, ev⟩ := stp
  cases ev with
  | a q => exact Or.inl rfl
  | r x => simp [dis] at hd
  | c r =>
    by_cases hc : st.ents.length ≤ firstIdx (mC false t st.rev r) st.ents
    · left; simp [elig, hc]
    · right
      obtain ⟨e0, he0, hp0⟩ := fr_hit (mC false t st.rev r) st.ents (by omega)
      have hr0 := mC_false_true hp0
      simp only [dis, List.any_eq_true] at hd
      obtain ⟨e, he, hne⟩ := hd
      have hfe : mC false t st.rev r e = false := by
        cases h : mC false t st.rev r e
        · rfl
        · exfalso
          have h' : mC true t st.rev r e = true := by
            simp only [mC, if_true, decide_eq_true_eq]; exact mC_false_true h
          rw [h, h'] at hne; simp at hne
      have hte : e.2.res t = r.res t := by
        have : mC true t st.rev r e = true := by
          cases h : mC true t st.rev r e
          · rw [h, hfe] at hne; simp at hne
          · rfl
        simpa [mC] using this
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp he
      simp only at hDK hL
      have hneq : j ≠ firstIdx (mC false t st.rev r) st.ents := by
        intro hji; rw [hji, he0] at hj; obtain rfl := Option.some.inj hj; rw [hp0] at hfe; cases hfe
      have hres : e.2.res t = e0.2.res t := hte.trans hr0.symm
      have pre : ∀ k, k < st0.ents.length → st.ents[k]? = st0.ents[k]? := by
        intro k hk; rw [hL, List.getElem?_append_left hk]
      generalize firstIdx (mC false t st.rev r) st.ents = i0 at he0 hneq
      rcases Nat.lt_or_gt_of_ne hneq with hlt | hgt
      · by_cases hk : st0.ents.length ≤ i0
        · exact absurd hres (hDK _ _ e e0 hlt hk hj he0)
        · rw [pre j (by omega)] at hj
          rw [pre i0 (by omega)] at he0
          exact initColl_of hlt hj he0 hres
      · by_cases hk : st0.ents.length ≤ j
        · exact absurd hres.symm (hDK _ _ e0 e hgt hk he0 hj)
        · rw [pre j (by omega)] at hj
          rw [pre i0 (by omega)] at he0
          exact initColl_of hgt he0 hj hres.symm


/-! Eligibility reads the tape only through revealed handles. -/

theorem mC_set (t : List Nat) (h y : Nat) (rev : List Nat) (r : SReq) (e : Bool × SReq) (hh : h ∉ rev) :
    mC false (t.set h y) rev r e = mC false t rev r e := by
  simp only [mC, Bool.false_eq_true, if_false]
  cases h1 : isOpen rev e.2
  · simp
  · cases h2 : isOpen rev r
    · simp
    · rw [open_res t h y rev e.2 h1 hh, open_res t h y rev r h2 hh]

theorem elig_set (t : List Nat) (h y : Nat) (stp : St × Ev) (hh : h ∉ stp.1.rev) :
    elig (t.set h y) stp = elig t stp := by
  obtain ⟨st, ev⟩ := stp
  cases ev with
  | a q => rfl
  | r x => rfl
  | c r =>
    simp only [elig]
    rw [firstIdx_congr _ _ _ (fun e _ => mC_set t h y st.rev r e hh)]

/-! Probes at eligible steps, with the width of the pinned handle. -/

/-- As `probeAt`, also returning the pinned handle's width. -/
def probeAtW (wmin : Nat) (t : List Nat) (stp : St × Ev) (j : Nat) : Option (Nat × Nat × Nat) :=
  match stp.1.ents[j]? with
  | none => none
  | some e => match cand t stp.1 stp.2 e with
    | none => none
    | some XY => match firstHidden stp.1.rev XY.1 with
      | none => none
      | some v => if wmin ≤ v.2.1 ∧ compat XY.1 XY.2 = true then
          some (v.1, v.2.1, toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1))
        else none

theorem probeAtW_set (wmin : Nat) (t : List Nat) (h y : Nat) (stp : St × Ev) (j : Nat)
    (hh : h ∉ stp.1.rev) : probeAtW wmin (t.set h y) stp j = probeAtW wmin t stp j := by
  have hc : ∀ e, cand (t.set h y) stp.1 stp.2 e = cand t stp.1 stp.2 e :=
    fun e => cand_set t h y stp.1 stp.2 e hh
  simp only [probeAtW, hc]

theorem probeAtW_some (wmin : Nat) (t : List Nat) (stp : St × Ev) (j : Nat) (v : Nat × Nat × Nat)
    (hp : probeAtW wmin t stp j = some v) : v.1 ∉ stp.1.rev := by
  simp only [probeAtW] at hp
  split at hp
  · cases hp
  · split at hp
    · cases hp
    · split at hp
      · cases hp
      · next fv hfv =>
        split at hp
        · obtain rfl := Option.some.inj hp
          exact (firstHidden_some _ _ fv hfv).1
        · cases hp

theorem sum_pin2 (N : Nat) (o : Option (Nat × Bool)) (b : Bool) :
    ((List.range N).map (fun h => if o = some (h, b) then 1 else 0)).sum ≤
      if o.map Prod.snd = some b then 1 else 0 := by
  cases o with
  | none => simp; exact sum_map_zero _
  | some v =>
    obtain ⟨h0, b0⟩ := v
    by_cases hb : b0 = b
    · subst hb
      simp only [Option.map_some, if_true]
      refine Nat.le_trans (sum_map_le _ (fun h _ => ?_)) (sum_pin N (some (h0, 0)))
      by_cases hh : h0 = h
      · subst hh; simp
      · simp [hh]
    · have : ∀ h, (if some (h0, b0) = some (h, b) then 1 else 0) = 0 := by
        intro h; simp [hb]
      simp only [this, sum_map_zero]; exact Nat.zero_le _

section
variable {α : Type} (wmin W : Nat) (Φ : St × Ev → Bool) (P : Prog α) (st0 : St)

/-- Probe at step `s`, entry `j`, counted only at eligible steps satisfying `Φ`. -/
def probeF (t : List Nat) (s j : Nat) : Option (Nat × Nat × Nat) :=
  ((strace t P st0)[s]?).bind (fun stp => if (elig t stp && Φ stp) = true then probeAtW wmin t stp j else none)

theorem probeF_inv (t : List Nat) (s j : Nat) (v : Nat × Nat × Nat) (y : Nat)
    (hp : probeF wmin Φ P st0 t s j = some v) : probeF wmin Φ P st0 (t.set v.1 y) s j = some v := by
  unfold probeF at hp ⊢
  cases hs : (strace t P st0)[s]? with
  | none => rw [hs] at hp; cases hp
  | some stp =>
    rw [hs] at hp
    simp only [Option.bind_some] at hp
    by_cases he : (elig t stp && Φ stp) = true
    · rw [if_pos he] at hp
      have hh := probeAtW_some wmin t stp j v hp
      have ht := strace_inv t v.1 y P st0 s stp hs hh
      have hs' : (strace (t.set v.1 y) P st0)[s]? = some stp := by
        have := congrArg (fun l => l[s]?) ht
        simp only [List.getElem?_take, Nat.lt_succ_self, if_true] at this
        rw [this, hs]
      rw [hs']
      simp only [Option.bind_some]
      rw [elig_set t v.1 y stp hh, if_pos he, probeAtW_set wmin t v.1 y stp j hh, hp]
    · rw [if_neg he] at hp; cases hp

theorem probeF_back (t : List Nat) (s j h y : Nat) (v : Nat × Nat × Nat) (hv : v.1 = h)
    (hp : probeF wmin Φ P st0 (t.set h y) s j = some v) : probeF wmin Φ P st0 t s j = some v := by
  have := probeF_inv wmin Φ P st0 (t.set h y) s j v (t.getD h 0) hp
  rwa [hv, set_set_back] at this

/-- The probe's pinned handle and width class (`true`: width at least `W`). -/
def pinC (t : List Nat) (s j : Nat) : Option (Nat × Bool) :=
  (probeF wmin Φ P st0 t s j).map (fun v => (v.1, decide (W ≤ v.2.1)))

def wtF (b : Bool) (t : List Nat) (i : Nat × Nat × Nat) : Nat :=
  if pinC wmin W Φ P st0 t i.1 i.2.1 = some (i.2.2, b) then 1 else 0

def tgF (i : Nat × Nat × Nat) (t : List Nat) : Nat :=
  ((probeF wmin Φ P st0 t i.1 i.2.1).map (fun v => v.2.2)).getD 0

theorem wtF_inv (b : Bool) (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) :
    wtF wmin W Φ P st0 b (t.set i.2.2 y) i = wtF wmin W Φ P st0 b t i := by
  unfold wtF pinC
  by_cases ha : (probeF wmin Φ P st0 t i.1 i.2.1).map (fun v => (v.1, decide (W ≤ v.2.1))) = some (i.2.2, b)
  · rw [if_pos ha]
    cases hp : probeF wmin Φ P st0 t i.1 i.2.1 with
    | none => rw [hp] at ha; cases ha
    | some v =>
      rw [hp] at ha
      have hv : v.1 = i.2.2 := (Prod.mk.inj (Option.some.inj ha)).1
      have := probeF_inv wmin Φ P st0 t i.1 i.2.1 v y hp
      rw [hv] at this
      rw [this, if_pos ha]
  · rw [if_neg ha, if_neg]
    intro hb
    apply ha
    cases hp : probeF wmin Φ P st0 (t.set i.2.2 y) i.1 i.2.1 with
    | none => rw [hp] at hb; cases hb
    | some v =>
      rw [hp] at hb
      have hv : v.1 = i.2.2 := (Prod.mk.inj (Option.some.inj hb)).1
      rw [probeF_back wmin Φ P st0 t i.1 i.2.1 i.2.2 y v hv hp]
      exact hb

theorem tgF_inv (b : Bool) (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) (hw : wtF wmin W Φ P st0 b t i ≠ 0) :
    tgF wmin Φ P st0 i (t.set i.2.2 y) = tgF wmin Φ P st0 i t := by
  unfold wtF pinC at hw
  unfold tgF
  cases hp : probeF wmin Φ P st0 t i.1 i.2.1 with
  | none => rw [hp] at hw; simp at hw
  | some v =>
    rw [hp] at hw
    have hv : v.1 = i.2.2 := by
      by_cases hne : v.1 = i.2.2
      · exact hne
      · exfalso; apply hw; simp [hne]
    have := probeF_inv wmin Φ P st0 t i.1 i.2.1 v y hp
    rw [hv] at this
    rw [this]

/-- The number of compatible (eligible step, entry) pairs below `S` in width class `b`. -/
def pairCountF (b : Bool) (S : Nat) (t : List Nat) : Nat :=
  ((List.range S).map (fun s => ((List.range S).map (fun j =>
    if (pinC wmin W Φ P st0 t s j).map Prod.snd = some b then 1 else 0)).sum)).sum

theorem idxF_sum_le (b : Bool) (S N : Nat) (t : List Nat) :
    ((idx S N).map (fun i => wtF wmin W Φ P st0 b t i)).sum ≤ pairCountF wmin W Φ P st0 b S t := by
  unfold idx pairCountF
  rw [sum_flatMap]
  apply sum_map_le; intro s _
  rw [sum_flatMap]
  apply sum_map_le; intro j _
  refine Nat.le_trans (Nat.le_of_eq ?_) (sum_pin2 N (pinC wmin W Φ P st0 t s j) b)
  rw [List.map_map]
  congr 1

/-- The total pair count bounds each class. -/
theorem pairCountF_le_sq (b : Bool) (S : Nat) (t : List Nat) : pairCountF wmin W Φ P st0 b S t ≤ S * S := by
  unfold pairCountF
  calc _ ≤ ((List.range S).map (fun _ => ((List.range S).map (fun _ => 1)).sum)).sum :=
        sum_map_le _ (fun s _ => sum_map_le _ (fun j _ => by split <;> omega))
    _ = S * S := by simp [sum_map_const]

/-- Pointwise: a disagreement is a pinned guess at an eligible step in one of the two
    width classes, a wild guess or collision, or an initial collision. -/
theorem dis_pointF (S N : Nat)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true) (t : List Nat) :
    (if anyDis P st0 t then 1 else 0) ≤
      ((idx S N).map (fun i => wtF wmin W Φ P st0 false t i *
        (if t.getD i.2.2 0 % 256^wmin == tgF wmin Φ P st0 i t % 256^wmin then 1 else 0))).sum +
      ((idx S N).map (fun i => wtF wmin W Φ P st0 true t i *
        (if t.getD i.2.2 0 % 256^W == tgF wmin Φ P st0 i t % 256^W then 1 else 0))).sum +
      (if wildColl wmin P st0 N t || initColl t st0 then 1 else 0) := by
  cases had : anyDis P st0 t
  · simp
  · simp only [if_true]
    cases hwi : (wildColl wmin P st0 N t || initColl t st0)
    · simp only [Bool.false_eq_true, if_false, Nat.add_zero]
      simp only [Bool.or_eq_false_iff] at hwi
      obtain ⟨hw, hic⟩ := hwi
      simp only [anyDis, List.any_eq_true] at had
      obtain ⟨stp0, hstp0, hd0⟩ := had
      obtain ⟨s0, hs0⟩ := List.mem_iff_getElem?.mp hstp0
      obtain ⟨s, ⟨stp, hs, hd⟩, hmin⟩ := exists_min
        (fun s => ∃ stp, (strace t P st0)[s]? = some stp ∧ dis t stp = true) s0 ⟨stp0, hs0, hd0⟩
      have hfirst : ∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' →
          dis t stp' = false := by
        intro s' stp' hlt hs'
        cases h : dis t stp'
        · rfl
        · exact absurd ⟨stp', hs', h⟩ (hmin s' hlt)
      have hel : (elig t stp && Φ stp) = true := by
        rcases first_dis_elig t P st0 s stp hs hd hfirst with h | h
        · rw [h, hΦ t s stp hs hfirst]; rfl
        · rw [hic] at h; cases h
      have hstp : stp ∈ strace t P st0 := mem_of_getElem? hs
      obtain ⟨e, he, hk⟩ := dis_entry t stp.1 stp.2 hd
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp he
      simp only [wildColl, List.any_eq_false] at hw
      have hwe := hw stp hstp
      simp only [List.any_eq_true, not_exists, not_and, Bool.or_eq_true] at hwe
      have hwe' := hwe e he
      rcases hk with ⟨XY, hc, hres⟩ | hcoll
      · have hno := cand_not_open t stp.1 stp.2 e XY hc
        obtain ⟨v, hv⟩ := firstHidden_of_not_open _ _ hno
        have hwild : wmin ≤ v.2.1 ∧ v.1 < N := by
          by_cases hn : wmin ≤ v.2.1 ∧ v.1 < N
          · exact hn
          · exfalso
            apply hwe'
            right
            simp only [wildE, hc, hv]
            simp; omega
        have hcompat := compat_of_res t XY.1 XY.2 hres
        have hpa : probeAtW wmin t stp j = some (v.1, v.2.1,
            toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1)) := by
          simp only [probeAtW, hj, hc, hv, hwild.1, hcompat, and_self, if_true]
        have hp : probeF wmin Φ P st0 t s j = some (v.1, v.2.1,
            toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1)) := by
          simp only [probeF, hs, Option.bind_some, hel, if_true, hpa]
        have hpin := guess_pins t stp.1.rev XY.1 XY.2 v hres hv
        have hbound := hS t s stp hs
        have hjlt : j < stp.1.ents.length := (List.getElem?_eq_some_iff.mp hj).1
        have hmem : (s, j, v.1) ∈ idx S N := by
          simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map]
          exact ⟨s, hbound.1, j, by omega, v.1, hwild.2, rfl⟩
        by_cases hcl : W ≤ v.2.1
        · have hdvd : 256^W ∣ 256^v.2.1 := Nat.pow_dvd_pow 256 hcl
          have hmod : t.getD v.1 0 % 256^W =
              toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1) % 256^W := by
            rw [← Nat.mod_mod_of_dvd _ hdvd, hpin, Nat.mod_mod_of_dvd _ hdvd]
          have hterm : wtF wmin W Φ P st0 true t (s, j, v.1) *
              (if t.getD (s, j, v.1).2.2 0 % 256^W == tgF wmin Φ P st0 (s, j, v.1) t % 256^W then 1 else 0) = 1 := by
            simp only [wtF, tgF, pinC, hp, Option.map_some, Option.getD_some, hmod, hcl]
            simp
          have := le_sum_of_mem (List.mem_map.mpr ⟨(s, j, v.1), hmem, hterm⟩ :
            1 ∈ (idx S N).map (fun i => wtF wmin W Φ P st0 true t i *
              (if t.getD i.2.2 0 % 256^W == tgF wmin Φ P st0 i t % 256^W then 1 else 0)))
          omega
        · have hdvd : 256^wmin ∣ 256^v.2.1 := Nat.pow_dvd_pow 256 hwild.1
          have hmod : t.getD v.1 0 % 256^wmin =
              toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1) % 256^wmin := by
            rw [← Nat.mod_mod_of_dvd _ hdvd, hpin, Nat.mod_mod_of_dvd _ hdvd]
          have hcl' : decide (W ≤ v.2.1) = false := by simp [hcl]
          have hterm : wtF wmin W Φ P st0 false t (s, j, v.1) *
              (if t.getD (s, j, v.1).2.2 0 % 256^wmin == tgF wmin Φ P st0 (s, j, v.1) t % 256^wmin then 1 else 0) = 1 := by
            simp only [wtF, tgF, pinC, hp, Option.map_some, Option.getD_some, hmod, hcl']
            simp
          have := le_sum_of_mem (List.mem_map.mpr ⟨(s, j, v.1), hmem, hterm⟩ :
            1 ∈ (idx S N).map (fun i => wtF wmin W Φ P st0 false t i *
              (if t.getD i.2.2 0 % 256^wmin == tgF wmin Φ P st0 i t % 256^wmin then 1 else 0)))
          omega
      · exfalso; exact hwe' (Or.inl hcoll)
    · rw [if_pos rfl]; omega

/-- Hidden-value bound, charged at eligible steps satisfying `Φ`, split by the width of
    the pinned handle: pins narrower than `W` cost `1/256^wmin` each, pins at least `W`
    wide cost `1/256^W`. -/
theorem hidden_bound_split (R N S Blo Bhi : Nat) (hW : wmin ≤ W) (hR : 256^W ∣ R)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true)
    (hlo : ∀ t, pairCountF wmin W Φ P st0 false S t ≤ Blo)
    (hhi : ∀ t, pairCountF wmin W Φ P st0 true S t ≤ Bhi) :
    tsum R N (fun t => if anyDis P st0 t then 1 else 0) * 256^W ≤
      R^N * Blo * 256^(W - wmin) + R^N * Bhi +
        tsum R N (fun t => if wildColl wmin P st0 N t || initColl t st0 then 1 else 0) * 256^W := by
  have hMl : 0 < 256^wmin := Nat.pow_pos (by decide)
  have hMh : 0 < 256^W := Nat.pow_pos (by decide)
  have hRl : 256^wmin ∣ R := Nat.dvd_trans (Nat.pow_dvd_pow 256 hW) hR
  have hix : ∀ i ∈ idx S N, i.2.2 < N := fun i hi => by
    simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map] at hi
    obtain ⟨_, _, _, _, h, hh, rfl⟩ := hi
    exact hh
  have hl := hits_sum R (256^wmin) N hMl hRl (idx S N) (fun i => i.2.2) hix
    (fun i t => wtF wmin W Φ P st0 false t i) (tgF wmin Φ P st0)
    (fun i _ t y => wtF_inv wmin W Φ P st0 false i t y)
    (fun i _ t y hw => tgF_inv wmin W Φ P st0 false i t y hw)
  have hh := hits_sum R (256^W) N hMh hR (idx S N) (fun i => i.2.2) hix
    (fun i t => wtF wmin W Φ P st0 true t i) (tgF wmin Φ P st0)
    (fun i _ t y => wtF_inv wmin W Φ P st0 true i t y)
    (fun i _ t y hw => tgF_inv wmin W Φ P st0 true i t y hw)
  have hsl : tsum R N (fun t => ((idx S N).map (fun i => wtF wmin W Φ P st0 false t i)).sum) ≤ R^N * Blo := by
    rw [← tsum_const]; exact tsum_mono R N (fun t => Nat.le_trans (idxF_sum_le wmin W Φ P st0 false S N t) (hlo t))
  have hsh : tsum R N (fun t => ((idx S N).map (fun i => wtF wmin W Φ P st0 true t i)).sum) ≤ R^N * Bhi := by
    rw [← tsum_const]; exact tsum_mono R N (fun t => Nat.le_trans (idxF_sum_le wmin W Φ P st0 true S N t) (hhi t))
  have hpt := tsum_mono R N (dis_pointF wmin W Φ P st0 S N hS hΦ)
  rw [tsum_add, tsum_add] at hpt
  have hsplit : 256^W = 256^wmin * 256^(W - wmin) := by rw [← Nat.pow_add]; congr 1; omega
  have e2 : tsum R N (fun t => ((idx S N).map (fun i => wtF wmin W Φ P st0 false t i *
        (if t.getD i.2.2 0 % 256^wmin == tgF wmin Φ P st0 i t % 256^wmin then 1 else 0))).sum) * 256^W ≤
      R^N * Blo * 256^(W - wmin) := by
    rw [hsplit, ← Nat.mul_assoc]
    exact Nat.mul_le_mul_right _ (Nat.le_trans hl hsl)
  have e3 := Nat.le_trans hh hsh
  calc _ ≤ (_ + _ + _) * 256^W := Nat.mul_le_mul_right _ hpt
    _ = _ * 256^W + _ * 256^W + _ * 256^W := by rw [Nat.add_mul, Nat.add_mul]
    _ ≤ _ := Nat.add_le_add (Nat.add_le_add e2 e3) (Nat.le_refl _)

end
end DSM.Rom
