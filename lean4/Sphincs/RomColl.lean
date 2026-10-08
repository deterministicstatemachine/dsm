-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomPhi

/- Collisions of independently sampled values.

   The wild-guess/collision event of `hidden_bound_split` is needed only at the
   first disagreement step. `hidden_bound_splitP` restates the bound with the
   event restricted to steps with no earlier disagreement (`wildCollP`), where
   the structural invariant of H1' holds. There:

   * no guess is wild: every handle of every entry and request is an existing
     entry, of width `n` or 32;
   * two distinct hidden challenger requests with one resolution (`collC`)
     force two of the 32-byte key entries (tweak key, PRF key, PRF-msg key)
     to agree, since the narrow shapes are skeleton-unique and PRF and
     randomizer requests are determined by key and literal.

   So the event is contained in a tape collision: two of the first three tape
   entries agree modulo `256^n`, or two entries below `N` agree modulo
   `256^32`. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

section
variable {α : Type} (wmin W : Nat) (Φ : St × Ev → Bool) (P : Prog α) (st0 : St)

/-- No disagreement among the first `s` steps. -/
def noDisB (t : List Nat) (s : Nat) : Bool := ((strace t P st0).take s).all (fun x => !dis t x)

/-- A wild guess or an unopened collision at a step with no earlier disagreement. -/
def wildCollP (N : Nat) (t : List Nat) : Bool :=
  (List.range (strace t P st0).length).any (fun s => match (strace t P st0)[s]? with
    | none => false
    | some stp => noDisB P st0 t s && stp.1.ents.any (fun e => collC t stp.1 stp.2 e || wildE wmin N t stp.1 stp.2 e))

theorem noDisB_of (t : List Nat) (s : Nat)
    (h : ∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) :
    noDisB P st0 t s = true := by
  simp only [noDisB, List.all_eq_true, Bool.not_eq_true']
  intro x hx
  obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hx
  rw [List.getElem?_take] at hk
  split at hk
  · exact h k x (by omega) hk
  · cases hk

theorem wildP_at (N : Nat) (t : List Nat) (s : Nat) (stp : St × Ev) (hs : (strace t P st0)[s]? = some stp)
    (hfirst : ∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false)
    (hw : wildCollP wmin P st0 N t = false) :
    ∀ x ∈ stp.1.ents, ¬ (collC t stp.1 stp.2 x = true ∨ wildE wmin N t stp.1 stp.2 x = true) := by
  intro x hx hc
  have hsl := (List.getElem?_eq_some_iff.mp hs).1
  simp only [wildCollP, List.any_eq_false] at hw
  have := hw s (List.mem_range.mpr hsl)
  rw [hs] at this
  simp only [noDisB_of P st0 t s hfirst, Bool.true_and, List.any_eq_true, Bool.or_eq_true, not_exists, not_and] at this
  exact this x hx hc

/-- Pointwise: a disagreement is a pinned guess at an eligible step in one of the two
    width classes, a wild guess or collision, or an initial collision. -/
theorem dis_pointP (S N : Nat)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true) (t : List Nat) :
    (if anyDis P st0 t then 1 else 0) ≤
      ((idx S N).map (fun i => wtF wmin W Φ P st0 false t i *
        (if t.getD i.2.2 0 % 256^wmin == tgF wmin Φ P st0 i t % 256^wmin then 1 else 0))).sum +
      ((idx S N).map (fun i => wtF wmin W Φ P st0 true t i *
        (if t.getD i.2.2 0 % 256^W == tgF wmin Φ P st0 i t % 256^W then 1 else 0))).sum +
      (if wildCollP wmin P st0 N t || initColl t st0 then 1 else 0) := by
  cases had : anyDis P st0 t
  · simp
  · simp only [if_true]
    cases hwi : (wildCollP wmin P st0 N t || initColl t st0)
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
      have hwe := wildP_at wmin P st0 N t s stp hs hfirst hw
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
theorem hidden_bound_splitP (R N S Blo Bhi : Nat) (hW : wmin ≤ W) (hR : 256^W ∣ R)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true)
    (hlo : ∀ t, pairCountF wmin W Φ P st0 false S t ≤ Blo)
    (hhi : ∀ t, pairCountF wmin W Φ P st0 true S t ≤ Bhi) :
    tsum R N (fun t => if anyDis P st0 t then 1 else 0) * 256^W ≤
      R^N * Blo * 256^(W - wmin) + R^N * Bhi +
        tsum R N (fun t => if wildCollP wmin P st0 N t || initColl t st0 then 1 else 0) * 256^W := by
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
  have hpt := tsum_mono R N (dis_pointP wmin W Φ P st0 S N hS hΦ)
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

/-! H1': handles exist and have width `n` or 32. -/

theorem occs_mem : ∀ (x : List SV) (o i w o' : Nat), (i, w, o') ∈ occs x o → SV.hid i w ∈ x
  | [], _, _, _, _, h => by simp [occs] at h
  | .lit b :: x, o, i, w, o', h => by
    simp only [occs] at h
    exact List.mem_cons_of_mem _ (occs_mem x _ i w o' h)
  | .hid j u :: x, o, i, w, o', h => by
    simp only [occs, List.mem_cons, Prod.mk.injEq] at h
    rcases h with ⟨rfl, rfl, _⟩ | h
    · simp
    · exact List.mem_cons_of_mem _ (occs_mem x _ i w o' h)

theorem firstHidden_mem {rev : List Nat} {r : SReq} {v : Nat × Nat × Bool × Nat} (h : firstHidden rev r = some v) :
    SV.hid v.1 v.2.1 ∈ r.key ∨ SV.hid v.1 v.2.1 ∈ r.input := by
  obtain ⟨_, hm⟩ := firstHidden_some rev r v h
  cases hb : v.2.2.1
  · right; rw [hb] at hm; exact occs_mem _ _ _ _ _ (by simpa using hm)
  · left; rw [hb] at hm; exact occs_mem _ _ _ _ _ (by simpa using hm)

theorem hid_mem_shids : ∀ (x : List SV) (i w : Nat), SV.hid i w ∈ x → i ∈ shids x
  | [], _, _, h => by simp at h
  | .lit b :: x, i, w, h => by
    simp only [shids]
    exact hid_mem_shids x i w (by simpa using h)
  | .hid j u :: x, i, w, h => by
    simp only [shids, List.mem_cons]
    simp only [List.mem_cons, SV.hid.injEq] at h
    rcases h with ⟨rfl, _⟩ | h
    · exact Or.inl rfl
    · exact Or.inr (hid_mem_shids x i w h)

section
variable {c : Ctx}

/-- Every handle of a DSM family request is an existing entry, of width `n` or 32. -/
theorem famOK_hidsW (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} (hI : InvS c st) {r : SReq}
    (hF : FamOK c st r) (i w : Nat) (hm : SV.hid i w ∈ r.key ∨ SV.hid i w ∈ r.input) :
    i < st.ents.length ∧ (w = c.n ∨ w = 32) := by
  have h2 : 2 < st.ents.length := lt_entry hI.1.2.2
  have h1 : 1 < st.ents.length := by omega
  have h0 : 0 < st.ents.length := by omega
  rcases hF with rfl | rfl | rfl | ⟨ipk, A, rfl, hk, _⟩ | ⟨dk, m, rfl, hk⟩ | ⟨iR, m, rfl, dk, hk, _, hr⟩ | ⟨d, A, hs⟩
  · simp [dTk] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨h2, Or.inl rfl⟩
  · simp [dPrf] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨h0, Or.inl rfl⟩
  · simp [dReq] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨h1, Or.inl rfl⟩
  · simp [prfReq] at hm
    rcases hm with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · exact ⟨lt_entry hk, Or.inr rfl⟩
    · exact ⟨h2, Or.inl rfl⟩
  · simp [rqOf] at hm
    rcases hm with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · exact ⟨lt_entry hk, Or.inr rfl⟩
    · exact ⟨h2, Or.inl rfl⟩
  · have hrr := hr
    rw [hroot] at hrr hm
    simp [hqOf] at hm hrr
    rcases hm with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · exact ⟨lt_entry hk, Or.inl rfl⟩
    · exact ⟨h2, Or.inl rfl⟩
    · exact ⟨(hrr _ (by simp [shids])).2, Or.inl rfl⟩
  · cases d with
    | zero => exact hs.elim
    | succ d =>
      obtain ⟨_, _, itk, hs', rfl, hitk, _, hh⟩ := hs
      simp only [List.mem_cons, SV.hid.injEq, List.not_mem_nil, or_false,
        reduceCtorEq, false_or] at hm
      rcases hm with ⟨rfl, rfl⟩ | hm
      · exact ⟨lt_entry hitk, Or.inr rfl⟩
      · obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hm
        obtain ⟨h', hx, hK⟩ := hh k (List.getElem?_eq_some_iff.mp hk).1
        rw [hk] at hx
        obtain ⟨rfl, rfl⟩ := SV.hid.inj (Option.some.inj hx)
        refine ⟨?_, Or.inl rfl⟩
        revert hK
        cases (kids (params c.v) A)[k]? with
        | none => intro h; exact h.elim
        | some K =>
          intro hK
          have : KidAt c st d i K := by cases K <;> exact hK
          obtain ⟨e, he, _⟩ := kidAt_mode this
          exact lt_entry he

theorem ent_hidsW (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} (hI : InvS c st) {j : Nat}
    {e : Bool × SReq} (he : st.ents[j]? = some e) (i w : Nat)
    (hm : SV.hid i w ∈ e.2.key ∨ SV.hid i w ∈ e.2.input) : i < st.ents.length ∧ (w = c.n ∨ w = 32) := by
  obtain ⟨b, r⟩ := e
  cases b with
  | true =>
    exfalso
    have := hI.2.1 j r he
    simp only [SReq.hids, List.append_eq_nil_iff] at this
    rcases hm with hm | hm
    · have := hid_mem_shids _ _ _ hm; simp_all
    · have := hid_mem_shids _ _ _ hm; simp_all
  | false =>
    rcases hI.2.2.2.1 j r he with hj | hF
    · have h2 : 2 < st.ents.length := lt_entry hI.1.2.2
      rcases j with _ | _ | _ | j
      · rw [hI.1.1] at he; obtain ⟨⟩ := he; simp [coin] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨by omega, Or.inl rfl⟩
      · rw [hI.1.2.1] at he; obtain ⟨⟩ := he; simp [coin] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨by omega, Or.inl rfl⟩
      · rw [hI.1.2.2] at he; obtain ⟨⟩ := he; simp [coin] at hm; obtain ⟨rfl, rfl⟩ := hm; exact ⟨by omega, Or.inl rfl⟩
      · omega
    · exact famOK_hidsW ρ hroot hI hF i w hm

end

section
variable {c : Ctx}

theorem cand_fst {t : List Nat} {st : St} {ev : Ev} {x : Bool × SReq} {XY : SReq × Request}
    (h : cand t st ev x = some XY) : XY.1 = x.2 ∨ ∃ r, ev = .c r ∧ XY.1 = r := by
  cases ev with
  | r _ => cases h
  | a q =>
    simp only [cand] at h
    split at h
    · cases h
    · obtain rfl := Option.some.inj h; exact Or.inl rfl
  | c r =>
    simp only [cand] at h
    split at h
    · cases h
    · split at h
      · split at h
        · cases h
        · obtain rfl := Option.some.inj h; exact Or.inr ⟨r, rfl, rfl⟩
      · split at h
        · obtain rfl := Option.some.inj h; exact Or.inl rfl
        · cases h

/-- At a step of H1' with no earlier disagreement, no guess is wild. -/
theorem wildE_false (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} {ev : Ev} (hI : InvS c st)
    (hS : StepOK c (st, ev)) (wmin N : Nat) (hw : wmin ≤ c.n) (hn32 : c.n ≤ 32) (hN : st.ents.length ≤ N)
    {x : Bool × SReq} (hx : x ∈ st.ents) : wildE wmin N c.t st ev x = false := by
  unfold wildE
  cases hc : cand c.t st ev x with
  | none => rfl
  | some XY =>
    simp only
    cases hf : firstHidden st.rev XY.1 with
    | none => rfl
    | some v =>
      simp only
      have hm := firstHidden_mem hf
      have hb : v.1 < st.ents.length ∧ (v.2.1 = c.n ∨ v.2.1 = 32) := by
        rcases cand_fst hc with h | ⟨r, rfl, h⟩
        · obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hx
          rw [h] at hm
          exact ent_hidsW ρ hroot hI hj _ _ hm
        · rw [h] at hm
          exact famOK_hidsW ρ hroot hI hS _ _ hm
      have h1 : wmin ≤ v.2.1 := by omega
      have h2 : v.1 < N := by omega
      simp [h1, h2]

/-- A DSM request of mode 1 is keyed by the tweak key (structured), the PRF key (a PRF
    request) or the PRF-msg key (the randomizer). -/
theorem famOK_mode1 {st : St} {r : SReq} (hF : FamOK c st r) (hm : r.mode = 1) :
    ∃ k, r.key = [.hid k 32] ∧
      ((st.ents[k]? = some (false, dTk c.n) ∧ ∃ d A, StructReq c st d r A) ∨
       (st.ents[k]? = some (false, dPrf c.n) ∧ ∃ A, r = prfReq c.n k A ∧ A.InRange) ∨
       (st.ents[k]? = some (false, dReq c.n) ∧ ∃ m, r = rqOf c.n k m)) := by
  rcases hF with rfl | rfl | rfl | ⟨ipk, A, rfl, hk, hA, _⟩ | ⟨dk, m, rfl, hk⟩ | ⟨iR, m, rfl, _⟩ | ⟨d, A, hs⟩
  · simp [dTk] at hm
  · simp [dPrf] at hm
  · simp [dReq] at hm
  · exact ⟨ipk, rfl, Or.inr (Or.inl ⟨hk, A, rfl, hA⟩)⟩
  · exact ⟨dk, rfl, Or.inr (Or.inr ⟨hk, m, rfl⟩)⟩
  · simp [hqOf] at hm
  · cases d with
    | zero => exact hs.elim
    | succ d =>
      have hs' := hs
      obtain ⟨_, _, itk, hs'', rfl, hitk, _⟩ := hs
      exact ⟨itk, rfl, Or.inl ⟨hitk, d+1, A, hs'⟩⟩

theorem sres_key32 (t : List Nat) (k : Nat) : sres t [.hid k 32] = be 32 (t.getD k 0) := by
  simp [sres, SV.res]

/-- At a step of H1' with no earlier disagreement, an unopened collision of two distinct
    challenger requests is a collision of two 32-byte key values. -/
theorem collC_key (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} {r : SReq} (hI : InvS c st)
    (hS : StepOK c (st, .c r)) {x : Bool × SReq} (hx : x ∈ st.ents) (hcol : collC c.t st (.c r) x = true) :
    ∃ a b, a < b ∧ b < st.ents.length ∧ c.t.getD a 0 % 256^32 = c.t.getD b 0 % 256^32 := by
  have hn := params_n_pos c.v
  have hF : FamOK c st r := hS
  simp only [collC, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not] at hcol
  obtain ⟨⟨⟨hne, hox⟩, hor⟩, hres⟩ := hcol
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hx
  obtain ⟨b, e⟩ := x
  simp only at hne hox hres
  cases b with
  | true =>
    exfalso
    have := hI.2.1 j e hj
    simp [isOpen, this] at hox
  | false =>
    have hmode : e.mode = r.mode := congrArg Request.mode hres
    rcases hI.2.2.2.1 j e hj with hj3 | hFe
    · exfalso
      have h999 : e.mode = 999 := by
        rcases j with _ | _ | _ | j
        · rw [hI.1.1] at hj; obtain ⟨⟩ := hj; rfl
        · rw [hI.1.2.1] at hj; obtain ⟨⟩ := hj; rfl
        · rw [hI.1.2.2] at hj; obtain ⟨⟩ := hj; rfl
        · omega
      exact goodFam_mode (famOK_good ρ hroot hI hF) (by omega)
    · have hY : compat e (r.res c.t) = true := by rw [← hres]; exact compat_of_res _ _ _ rfl
      have hY' : compat r (r.res c.t) = true := compat_of_res _ _ _ rfl
      by_cases hlo : LoShape c.n c.pm e ∧ LoShape c.n c.pm r
      · exact absurd (famOK_skel_unique ρ hroot hI hFe hF hlo.1 hlo.2 (skel_det hn hlo.1 hlo.2 hY hY')) hne
      · -- one side is a PRF or randomizer request, so both are of mode 1
        have hm1 : e.mode = 1 := by
          rcases famOK_good ρ hroot hI hFe with he | ⟨k, m, rfl, _⟩
          · rcases famOK_good ρ hroot hI hF with hr | ⟨k, m, rfl, _⟩
            · exact absurd ⟨he, hr⟩ hlo
            · rw [hmode]
          · rfl
        obtain ⟨k1, hk1, he1⟩ := famOK_mode1 hFe hm1
        obtain ⟨k2, hk2, he2⟩ := famOK_mode1 hF (by omega)
        have hkey : c.t.getD k1 0 % 256^32 = c.t.getD k2 0 % 256^32 := by
          have := congrArg Request.key hres
          simp only [SReq.res, hk1, hk2, sres_key32] at this
          exact be_eq_mod this
        have hl1 : k1 < st.ents.length := by rcases he1 with ⟨h, _⟩ | ⟨h, _⟩ | ⟨h, _⟩ <;> exact lt_entry h
        have hl2 : k2 < st.ents.length := by rcases he2 with ⟨h, _⟩ | ⟨h, _⟩ | ⟨h, _⟩ <;> exact lt_entry h
        rcases Nat.lt_trichotomy k1 k2 with hlt | heq | hgt
        · exact ⟨k1, k2, hlt, hl2, hkey⟩
        · exfalso
          subst heq
          rcases he1 with ⟨h1, d1, A1, hs1⟩ | ⟨h1, A1, rfl, hA1⟩ | ⟨h1, m1, rfl⟩ <;>
          rcases he2 with ⟨h2, d2, A2, hs2⟩ | ⟨h2, A2, rfl, hA2⟩ | ⟨h2, m2, rfl⟩ <;>
          simp only [h1, Option.some.injEq, Prod.mk.injEq, true_and] at h2
          · obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hs1
            obtain ⟨_, _, rfl, _, _⟩ := structReq_shape hs2
            exact hlo ⟨Or.inl ⟨_, _, _, rfl, adrs_bytes_len _, by assumption⟩,
              Or.inl ⟨_, _, _, rfl, adrs_bytes_len _, by assumption⟩⟩
          · simp [dTk, dPrf] at h2
          · simp [dTk, dReq] at h2
          · simp [dTk, dPrf] at h2
          · apply hne
            have := congrArg Request.input hres
            simp [SReq.res, prfReq, sres, SV.res] at this
            rw [adrs_bytes_injective A1 A2 hA1 hA2 this]
          · simp [dPrf, dReq] at h2
          · simp [dTk, dReq] at h2
          · simp [dPrf, dReq] at h2
          · apply hne
            have := congrArg Request.input hres
            simp [SReq.res, rqOf, sres, SV.res] at this
            rw [this]
        · exact ⟨k2, k1, hgt, hl1, hkey.symm⟩

end

/-! The event as a tape collision, and its count. -/

theorem initColl_coin (n : Nat) (t : List Nat) (h : initColl t (coinSt n) = true) :
    ∃ a b, a < b ∧ b < 3 ∧ t.getD a 0 % 256^n = t.getD b 0 % 256^n := by
  simp only [initColl, List.any_eq_true, List.mem_range, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨a, ha, b, hb, hab, hm⟩ := h
  have hl : (coinSt n).ents.length = 3 := rfl
  rw [hl] at ha hb
  have key : ∀ x y : Nat, x < 3 → y < 3 → (match (coinSt n).ents[x]?, (coinSt n).ents[y]? with
      | some ea, some eb => decide (ea.2.res t = eb.2.res t)
      | _, _ => false) = true → t.getD x 0 % 256^n = t.getD y 0 % 256^n := by
    intro x y hx hy hxy
    rcases x with _ | _ | _ | x <;> rcases y with _ | _ | _ | y <;>
      first | omega | (simp [coinSt, coin, SReq.res, sres, SV.res] at hxy; exact be_eq_mod hxy)
  exact ⟨a, b, hab, hb, key a b ha hb hm⟩

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

/-- The wild/collision or initial-collision event of H1' is a tape collision. -/
theorem coll_event (N S : Nat) (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S) (hSN : S ≤ N) (t : List Nat)
    (h : (wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
      initColl t (coinSt (params v).n)) = true) :
    (∃ a b, a < b ∧ b < 3 ∧ t.getD a 0 % 256^(params v).n = t.getD b 0 % 256^(params v).n) ∨
    (∃ a b, a < b ∧ b < N ∧ t.getD a 0 % 256^32 = t.getD b 0 % 256^32) := by
  rcases Bool.or_eq_true_iff.mp h with h | h
  · right
    simp only [wildCollP, List.any_eq_true, List.mem_range] at h
    obtain ⟨s, _, hs⟩ := h
    cases hst : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? with
    | none => rw [hst] at hs; cases hs
    | some stp =>
      rw [hst] at hs
      simp only [Bool.and_eq_true, List.any_eq_true, Bool.or_eq_true] at hs
      obtain ⟨hnd, x, hx, hcw⟩ := hs
      have hnd' : NoDisTo t (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)) s := by
        intro s' stp' hlt hs'
        simp only [noDisB, List.all_eq_true, Bool.not_eq_true'] at hnd
        exact hnd stp' (by
          rw [List.mem_iff_getElem?]
          exact ⟨s', by rw [List.getElem?_take, if_pos hlt]; exact hs'⟩)
      obtain ⟨ρ, hρ⟩ := kg_root_shape t v
      obtain ⟨hI, hSt⟩ := game_struct (c := structCtx t v) rfl limits A s stp hst hnd'
      have hlen := (hS t s stp hst).2
      rcases hcw with hc | hw
      · obtain ⟨st, ev⟩ := stp
        cases ev with
        | c r =>
          obtain ⟨a, b, hab, hb, he⟩ := collC_key (c := structCtx t v) ρ hρ hI hSt hx hc
          have hb' : b < st.ents.length := hb
          have hlen' : st.ents.length ≤ S := hlen
          exact ⟨a, b, hab, by omega, he⟩
        | a q => simp [collC] at hc
        | r x => simp [collC] at hc
      · exfalso
        have h0 := wildE_false (c := structCtx t v) ρ hρ hI hSt (params v).n N (Nat.le_refl _)
          (show (params v).n ≤ 32 by cases v <;> decide) (by omega) hx
        have h1 : wildE (params v).n N t stp.1 stp.2 x = false := h0
        rw [h1] at hw; cases hw
  · left; exact initColl_coin _ t h

/-- Pairs `a < b < N`. -/
def pairsBelow (N : Nat) : List (Nat × Nat) := (List.range N).flatMap (fun b => (List.range b).map (fun a => (a, b)))

theorem mem_pairsBelow {N a b : Nat} : (a, b) ∈ pairsBelow N ↔ a < b ∧ b < N := by
  simp only [pairsBelow, List.mem_flatMap, List.mem_map, List.mem_range, Prod.mk.injEq]
  constructor
  · rintro ⟨b', hb', a', ha', rfl, rfl⟩; exact ⟨ha', hb'⟩
  · rintro ⟨h1, h2⟩; exact ⟨b, h2, a, h1, rfl, rfl⟩

theorem mem_pairsBelow' {M : Nat} {i : Nat × Nat} (h : i ∈ pairsBelow M) : i.1 < i.2 ∧ i.2 < M := by
  obtain ⟨a, b⟩ := i
  exact mem_pairsBelow.mp h

theorem pairsBelow_len (N : Nat) : (pairsBelow N).length ≤ N * N := by
  simp only [pairsBelow, List.length_flatMap, List.length_map, List.length_range]
  calc ((List.range N).map (fun b => b)).sum ≤ ((List.range N).map (fun _ => N)).sum :=
        sum_map_le _ (fun b hb => by have := List.mem_range.mp hb; omega)
    _ = N * N := by rw [sum_map_const]; simp

/-- Tape collisions: a coordinate collision among the first three entries modulo `M1`,
    or among the first `N` modulo `M2`. -/
theorem tape_coll (R N M1 M2 : Nat) (h1 : 0 < M1) (h2 : 0 < M2) (hM1 : M1 ∣ R) (hM2 : M2 ∣ R) (h3 : 3 ≤ N)
    (E : List Nat → Bool)
    (hE : ∀ t, E t = true → (∃ a b, a < b ∧ b < 3 ∧ t.getD a 0 % M1 = t.getD b 0 % M1) ∨
      (∃ a b, a < b ∧ b < N ∧ t.getD a 0 % M2 = t.getD b 0 % M2)) :
    tsum R N (fun t => if E t then 1 else 0) * (M1 * M2) ≤ R^N * 3 * M2 + R^N * (N * N) * M1 := by
  let I1 : List (Nat × Nat) := pairsBelow 3
  let I2 : List (Nat × Nat) := pairsBelow N
  let S1 := fun t : List Nat => (I1.map (fun i => 1 * (if t.getD i.2 0 % M1 == t.getD i.1 0 % M1 then 1 else 0))).sum
  let S2 := fun t : List Nat => (I2.map (fun i => 1 * (if t.getD i.2 0 % M2 == t.getD i.1 0 % M2 then 1 else 0))).sum
  have hpt : ∀ t, (if E t then 1 else 0) ≤ S1 t + S2 t := by
    intro t
    simp only [S1, S2]
    split
    · rename_i he
      rcases hE t he with ⟨a, b, hab, hb, hc⟩ | ⟨a, b, hab, hb, hc⟩
      · have : 1 ∈ I1.map (fun i => 1 * (if t.getD i.2 0 % M1 == t.getD i.1 0 % M1 then 1 else 0)) :=
          List.mem_map.mpr ⟨(a, b), mem_pairsBelow.mpr ⟨hab, hb⟩, by
            show 1 * (if (t.getD b 0 % M1 == t.getD a 0 % M1) = true then 1 else 0) = 1
            rw [hc]; simp⟩
        have := le_sum_of_mem this; omega
      · have : 1 ∈ I2.map (fun i => 1 * (if t.getD i.2 0 % M2 == t.getD i.1 0 % M2 then 1 else 0)) :=
          List.mem_map.mpr ⟨(a, b), mem_pairsBelow.mpr ⟨hab, hb⟩, by
            show 1 * (if (t.getD b 0 % M2 == t.getD a 0 % M2) = true then 1 else 0) = 1
            rw [hc]; simp⟩
        have := le_sum_of_mem this; omega
    · exact Nat.zero_le _
  have hset : ∀ (M : Nat) (I : List (Nat × Nat)), (∀ i ∈ I, i.1 < i.2) → ∀ i ∈ I, ∀ t y, (fun (i : Nat × Nat) (_ : List Nat) => 1) i t ≠ 0 →
      (fun (i : Nat × Nat) (t : List Nat) => t.getD i.1 0) i (t.set i.2 y) = (fun (i : Nat × Nat) (t : List Nat) => t.getD i.1 0) i t := by
    intro M I hI i hi t y _
    exact getD_set_ne t i.2 i.1 y (by have := hI i hi; omega)
  have e1 := hits_sum R M1 N h1 hM1 I1 (fun i => i.2)
    (fun i hi => by have := (mem_pairsBelow' hi).2; show i.2 < N; omega)
    (fun _ _ => 1) (fun i t => t.getD i.1 0) (fun _ _ _ _ => rfl)
    (hset M1 I1 (fun i hi => (mem_pairsBelow' hi).1))
  have e2 := hits_sum R M2 N h2 hM2 I2 (fun i => i.2)
    (fun i hi => (mem_pairsBelow' hi).2)
    (fun _ _ => 1) (fun i t => t.getD i.1 0) (fun _ _ _ _ => rfl)
    (hset M2 I2 (fun i hi => (mem_pairsBelow' hi).1))
  have c1 : tsum R N (fun t => (I1.map (fun _ => 1)).sum) = R^N * 3 := by
    rw [sum_map_const, tsum_const]; rfl
  have c2 : tsum R N (fun t => (I2.map (fun _ => 1)).sum) ≤ R^N * (N * N) := by
    rw [sum_map_const, tsum_const, Nat.mul_one]; exact Nat.mul_le_mul_left _ (pairsBelow_len N)
  rw [c1] at e1
  have hT := tsum_mono R N hpt
  rw [tsum_add] at hT
  calc tsum R N (fun t => if E t then 1 else 0) * (M1 * M2)
      ≤ (tsum R N S1 + tsum R N S2) * (M1 * M2) := Nat.mul_le_mul_right _ hT
    _ = tsum R N S1 * M1 * M2 + tsum R N S2 * M2 * M1 := by
        rw [Nat.add_mul, ← Nat.mul_assoc, Nat.mul_comm M1 M2, ← Nat.mul_assoc]
    _ ≤ R^N * 3 * M2 + R^N * (N * N) * M1 :=
        Nat.add_le_add (Nat.mul_le_mul_right _ e1) (Nat.mul_le_mul_right _ (Nat.le_trans e2 c2))

end

/-! H1' and SPHINCS+-128f with the collision term discharged. -/

theorem rom_ext_structP (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N S AA : Nat)
    (hn32 : (params v).n ≤ 32) (hR : 256^32 ∣ R)
    (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).filter isAev).length ≤ AA) :
    tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) *
        256^32 ≤
      R^N * (5 * AA) * 256^(32 - (params v).n) + R^N * (S * S) +
        tsum R N (fun t => if wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
          initColl t (coinSt (params v).n) then 1 else 0) * 256^32 :=
  hidden_bound_splitP (params v).n 32 (phiB v) (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)
    R N S (5 * AA) (S * S) hn32 hR hS (game_phiB v limits A)
    (fun t => by
      have := narrow_count v (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n 32
        (Nat.le_refl _) t S
      rw [cntT_coin, Nat.add_zero] at this
      exact Nat.le_trans this (Nat.mul_le_mul_left _ (hA t)))
    (fun t => pairCountF_le_sq _ _ _ _ _ _ _ _)

/-- SPHINCS+-128f, H1, with the narrow-pin count and the collision term of H1' discharged.
    With `K = 2^128` and `R^N` tapes:
    `#won·K^3 ≤ #canon·K^3 + JA·R^N·K^2 + 2·5·AA·R^N·K^2 + 2·S^2·R^N·K + 2·(3·R^N·K^2 + N^2·R^N·K)`,
    i.e. `Pr[won] ≤ Pr[canon] + (JA + 10·AA + 6)/2^128 + 2·(S^2 + N^2)/2^256`.
    Conditional on the ITSR budget hypotheses, the step bound `S ≤ N` and the adversary-step
    bound `AA` of H1'. -/
theorem rom_win_coll_128f (limits : Limits) (A : Bytes → RAdv) (c N q JA S AA : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx128f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx128f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' .spx128f limits A (coinEx (params .spx128f).n))
      (coinSt (params .spx128f).n)).filter isAev).length ≤ AA)
    (hSN : S ≤ N) (h3N : 3 ≤ N) :
    tsum (c * 256^(params .spx128f).m) N (fun t => ind ((runG .spx128f limits A t).1.win = true)) *
        (256^16 * (256^16 * 256^16)) ≤
      tsum (c * 256^(params .spx128f).m) N (fun t => ind (CanonCollIn (finO' .spx128f limits A t) (params .spx128f)
        (expTk (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expPrf (finO' .spx128f limits A t) .spx128f (sres t (coinEx (params .spx128f).n)))
        (expSeed .spx128f (sres t (coinEx (params .spx128f).n)))
        (verifyLog (finO' .spx128f limits A t) .spx128f (finKey .spx128f limits A t).1
          (runG .spx128f limits A t).1.msg (runG .spx128f limits A t).1.sig))) * (256^16 * (256^16 * 256^16)) +
      JA * (c * 256^(params .spx128f).m)^N * (256^16 * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^N * (5 * AA) * (256^16 * 256^16)) +
      2 * ((c * 256^(params .spx128f).m)^N * (S * S) * 256^16) +
      2 * ((c * 256^(params .spx128f).m)^N * 3 * (256^16 * 256^16) +
        (c * 256^(params .spx128f).m)^N * (N * N) * 256^16) := by
  have h1 := rom_win_128f limits A c N q JA hc hq hN hC hJ
  have hR : 256^32 ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have hR16 : 256^16 ∣ c * 256^(params .spx128f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h2 := rom_ext_structP .spx128f limits A (c * 256^(params .spx128f).m) N S AA (by decide) hR hS hA
  have h3 := tape_coll (c * 256^(params .spx128f).m) N (256^16) (256^32) (Nat.pow_pos (by decide))
    (Nat.pow_pos (by decide)) hR16 hR h3N _ (coll_event .spx128f limits A N S hS hSN)
  rw [show 32 - (params .spx128f).n = 16 by decide] at h2
  rw [show (2:Nat)^128 = 256^16 by decide] at h1
  rw [show (256:Nat)^32 = 256^16 * 256^16 by decide] at h2 h3
  generalize (256:Nat)^16 = K at h1 h2 h3 ⊢
  generalize (c * 256^(params .spx128f).m)^N = RN at h1 h2 h3 ⊢
  generalize tsum (c * 256^(params .spx128f).m) N (fun t => if anyDis (gameS' .spx128f limits A
    (coinEx (params .spx128f).n)) (coinSt (params .spx128f).n) t then 1 else 0) = D at h1 h2
  have g1 := Nat.mul_le_mul_right (K * K) h1
  rw [Nat.add_mul, Nat.add_mul] at g1
  have g2 := Nat.mul_le_mul_right K h2
  rw [Nat.add_mul, Nat.add_mul] at g2
  have a1 : ∀ X : Nat, X * K * (K * K) = X * (K * (K * K)) := fun X => Nat.mul_assoc _ _ _
  have a2 : ∀ X : Nat, 2 * (X * K) * (K * K) = 2 * (X * (K * (K * K))) := fun X => by
    rw [Nat.mul_assoc, Nat.mul_assoc]
  have a3 : ∀ X : Nat, X * (K * K) * K = X * (K * (K * K)) := fun X => by
    rw [Nat.mul_assoc, Nat.mul_comm (K * K) K]
  have a4 : ∀ X : Nat, X * K * K = X * (K * K) := fun X => Nat.mul_assoc _ _ _
  rw [a1, a1, a2] at g1
  rw [a3, a3, a4] at g2
  omega

end DSM.Rom
