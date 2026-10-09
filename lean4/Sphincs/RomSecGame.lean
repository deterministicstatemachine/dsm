-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSecrecy

/- Secrecy in the extended game, continued: key generation, signing, the play
   loop and the extension under the judgment `J2` of `RomSecrecy`. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

section
variable {c : Ctx}

/-- A request that already has its own challenger entry is answered by that entry. -/
theorem ask_known {st : St} (hI : Inv2 c st) {r : SReq} (hr : r.mode ≠ 999) {j : Nat}
    (hj : st.ents[j]? = some (false, r)) :
    firstIdx (mC false c.t st.rev r) st.ents = j := by
  have h3 : 3 ≤ j := by
    refine Nat.le_of_not_lt (fun hlt => hr ?_)
    rcases j with _ | _ | _ | j
    · rw [hI.1.1] at hj; rw [← (Prod.mk.inj (Option.some.inj hj)).2]; rfl
    · rw [hI.1.2.1] at hj; rw [← (Prod.mk.inj (Option.some.inj hj)).2]; rfl
    · rw [hI.1.2.2] at hj; rw [← (Prod.mk.inj (Option.some.inj hj)).2]; rfl
    · omega
  have hm : mC false c.t st.rev r (false, r) = true := by simp [mC]
  have hle : firstIdx (mC false c.t st.rev r) st.ents ≤ j := by
    refine Nat.le_of_not_lt (fun hlt => ?_)
    have := firstIdx_before _ _ j _ hj hlt
    rw [hm] at this; cases this
  rcases Nat.lt_or_eq_of_le hle with hlt | heq
  · exfalso
    obtain ⟨e, he, hp⟩ := firstIdx_hit (mC false c.t st.rev r) st.ents (Nat.lt_trans hlt (lt_entry hj))
    have hres : e.2.res c.t = r.res c.t := by
      simp only [mC, Bool.false_eq_true, if_false, Bool.or_eq_true, decide_eq_true_eq,
        Bool.and_eq_true] at hp
      rcases hp with hp | ⟨_, hp⟩
      · rw [hp]
      · exact hp
    exact hI.2.2.2.1 _ j e (false, r) hlt h3 he hj hres
  · exact heq

theorem J2.reveal' {α : Type} {x : List SV} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (hx : ∀ st, Inv2 c st → P0 st → Gd2 c st x)
    (hk : J2 c (k (sres c.t x)) P0 Q) (hs : Stable2 c P0) : J2 c (.reveal x k) P0 Q :=
  JR.reveal (T := (() : Id Unit)) (Rel := fun a _ st => Q a st) hx hk hs

theorem J2.assume {α : Type} {P : Prog α} {P0 : St → Prop} {Q : α → St → Prop} {X : Prop}
    (hX : ∀ st, Inv2 c st → P0 st → X) (h : X → J2 c P P0 Q) : J2 c P P0 Q :=
  fun st hI hp hnd hD => h (hX st hI hp) st hI hp hnd hD

theorem stable_ent (i : Nat) (e : Bool × SReq) : Stable2 c (fun st => st.ents[i]? = some e) :=
  fun _ _ _ hg h => grow_get hg h

/-- A challenger request with a closed handle, or with its own entry already: the
    answer is a challenger entry for exactly this request, with its table value. -/
theorem j2_askE (r : SReq) (hmode : r.mode ≠ 2) (h999 : r.mode ≠ 999) {P0 : St → Prop}
    (hh : ∀ st, Inv2 c st → P0 st → ∀ h ∈ r.hids, h < st.ents.length)
    (hk : ∀ st, Inv2 c st → P0 st → (∃ h ∈ r.hids, h ∉ st.rev) ∨ ∃ j : Nat, st.ents[j]? = some (false, r)) :
    J2 c (sAsk r) P0 (fun v st => ∃ i, v = [.hid i r.outLen] ∧
      (st.ents[i]? = some (false, r) ∧ sres c.t [.hid i r.outLen] = c.O (r.res c.t))) := by
  refine J2.ask r hh (fun _ _ _ iR m e => absurd (congrArg SReq.mode e) (by simpa [hqOf] using hmode))
    (fun st hI hp _ hI' hD => ⟨_, rfl, ?_, ask_val st r hI' hD⟩)
  rcases hk st hI hp with hc | ⟨j, hj⟩
  · exact ask_closed2 st r hI hc
  · rw [ask_known hI h999 hj]
    have : addC st j r = st := by simp [addC, lt_entry hj]
    rw [this]; exact hj

theorem tk_val : c.O ((dTk c.n).res c.t) = expTk c.O c.v c.e := by
  show c.O ⟨0, "DSM/sphincs/v2/thash", sres c.t [], sres c.t [.hid 2 c.n], 32⟩ = _
  rw [seed_res]; rfl

theorem take_e : c.e.take c.n = sres c.t [.hid 0 c.n] := by
  show (sres c.t (coinEx (params c.v).n)).take (params c.v).n = _
  rw [coin_res, List.take_left' (be_width _ _)]; simp [sres, SV.res]

theorem pk_val : c.O ((dPrf c.n).res c.t) = expPrf c.O c.v c.e := by
  show c.O ⟨0, "DSM/sphincs/v2/prf", sres c.t [], sres c.t [.hid 0 c.n], 32⟩ = _
  rw [← take_e]; rfl

theorem dTk_ask {P0 : St → Prop}
    (hk : ∀ st, Inv2 c st → P0 st → 2 ∉ st.rev ∨ ∃ j : Nat, st.ents[j]? = some (false, dTk c.n)) :
    J2 c (sAsk (dTk c.n)) P0 (fun v st => ∃ i, v = [.hid i 32] ∧
      (st.ents[i]? = some (false, dTk c.n) ∧ sres c.t [.hid i 32] = expTk c.O c.v c.e)) := by
  refine J2.conseq (j2_askE (dTk c.n) (by simp [dTk]) (by simp [dTk]) (fun st hI _ h hh => ?_) (fun st hI hp => ?_))
    (fun _ _ h => h) (fun v st ⟨i, h1, h2, h3⟩ => ⟨i, h1, h2, h3.trans tk_val⟩)
  · simp [dTk, SReq.hids, shids] at hh; subst hh; exact lt_entry hI.1.2.2
  · rcases hk st hI hp with h | h
    · exact Or.inl ⟨2, by simp [dTk, SReq.hids, shids], h⟩
    · exact Or.inr h

theorem dPrf_ask {P0 : St → Prop} :
    J2 c (sAsk (dPrf c.n)) P0 (fun v st => ∃ i, v = [.hid i 32] ∧
      (st.ents[i]? = some (false, dPrf c.n) ∧ sres c.t [.hid i 32] = expPrf c.O c.v c.e)) := by
  refine J2.conseq (j2_askE (dPrf c.n) (by simp [dPrf]) (by simp [dPrf]) (fun st hI _ h hh => ?_) (fun st hI _ => ?_))
    (fun _ _ h => h) (fun v st ⟨i, h1, h2, h3⟩ => ⟨i, h1, h2, h3.trans pk_val⟩)
  · simp [dPrf, SReq.hids, shids] at hh; subst hh; exact lt_entry hI.1.1
  · exact Or.inl ⟨0, by simp [dPrf, SReq.hids, shids], not_rev_prot2 hI (prot0 hI)⟩

end

/-! Key generation. -/

section
variable {c : Ctx}

/-- Sequencing without framing the precondition. -/
theorem J2.bind0 {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {Q' : β → St → Prop} (hP : J2 c P P0 Q) (hf : ∀ a, J2 c (f a) (Q a) Q') : J2 c (P.bind f) P0 Q' := by
  intro st hI hp hnd hD
  rw [strace_bind] at hnd
  rw [xrun_bind] at hD ⊢
  have hD1 := pre_back c.t (xrun_grow c.t _ _) hD
  obtain ⟨hI1, hx1, hq1⟩ := hP st hI hp (fun s hs' => hnd s (List.mem_append_left _ hs')) hD1
  obtain ⟨hI2, hx2, hq2⟩ := hf _ _ hI1 hq1 (fun s hs' => hnd s (List.mem_append_right _ hs')) hD
  exact ⟨hI2, grow_trans hx1 hx2, hq2⟩

theorem j2_kgTail :
    J2 c (sKgTail c.v (coinEx c.n)) (fun st => 2 ∉ st.rev) (fun ks st => ∃ ρ itk : Nat, ks.1 = [.hid 2 c.n, .hid ρ c.n] ∧
      ks.2 = coinEx c.n ++ [.hid ρ c.n] ∧ Safe2 c st ρ ∧ st.ents[itk]? = some (false, dTk c.n) ∧
      sres c.t [.hid ρ c.n] = xmssNode c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e)
        (expSeed c.v c.e) {layer := (params c.v).d-1} 0 (params c.v).hp) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  simp only [sKgTail, sDeriveKey]
  refine J2.bind0 (dTk_ask (fun _ _ hp => Or.inl hp)) (fun tk => ?_)
  refine J2.conseq (P0 := fun st => True ∧ ∃ i, tk = [.hid i 32] ∧
    (st.ents[i]? = some (false, dTk c.n) ∧ sres c.t [.hid i 32] = expTk c.O c.v c.e)) ?_
    (fun _ _ h => ⟨trivial, h⟩) (fun _ _ h => h)
  have hs := stable2_true (c := c)
  refine J2.obtain (fun itk htk => ?_)
  subst htk
  have s1 := stable2_and hs (stable2_and (stable_ent (c := c) itk (false, dTk c.n))
    (stable_pure (c := c) (sres c.t [.hid itk 32] = expTk c.O c.v c.e)))
  refine J2.bind dPrf_ask (fun pk => ?_) s1
  refine J2.obtain (fun ipk hpk => ?_)
  subst hpk
  have s2 := stable2_and s1 (stable2_and (stable_ent (c := c) ipk (false, dPrf c.n))
    (stable_pure (c := c) (sres c.t [.hid ipk 32] = expPrf c.O c.v c.e)))
  refine J2.assume (X := Keys c [.hid itk 32] [.hid ipk 32] (expTk c.O c.v c.e) (expPrf c.O c.v c.e))
    (fun st _ hp => ⟨hp.1.2.2, hp.2.2⟩) (fun K => ?_)
  refine J2.bind (jr_xmssNode K ((params c.v).d-1) 0 (by omega) (by decide) (params c.v).hp 0 s2 (by simp)
    (fun st _ hp => ⟨⟨itk, rfl, hp.1.2.1⟩, ⟨ipk, rfl, hp.2.1⟩⟩)) (fun root => ?_) s2
  refine J2.pure' (fun st _ hp => ?_)
  obtain ⟨⟨ρ, hρ, hsafe⟩, hv⟩ := hp.2
  subst hρ
  refine ⟨ρ, itk, rfl, rfl, hsafe, hp.1.1.2.1, ?_⟩
  rw [hv, seed_res]

end

/-! Signing. -/

section
variable {c : Ctx}

theorem stable_safe2 (i : Nat) : Stable2 c (fun st => Safe2 c st i) :=
  fun _ _ hI hg h => safe2_mono hI hg h

theorem stable_sigD (k : Nat) (m : Bytes) : Stable2 c (fun st => SigD c st k m) :=
  fun _ _ _ hg ⟨iR, dk, e, hm, h1, h2, h3, h4⟩ =>
    ⟨iR, dk, e, hm, grow_get hg h1, grow_get hg h2, grow_get hg h3, h4⟩

theorem dReq_ask {P0 : St → Prop} :
    J2 c (sAsk (dReq c.n)) P0 (fun v st => ∃ i, v = [.hid i 32] ∧
      (st.ents[i]? = some (false, dReq c.n) ∧ sres c.t [.hid i 32] = c.O ((dReq c.n).res c.t))) :=
  j2_askE (dReq c.n) (by simp [dReq]) (by simp [dReq]) (fun st hI _ h hh => by
      simp [dReq, SReq.hids, shids] at hh; subst hh; exact lt_entry hI.1.2.1)
    (fun st hI _ => Or.inl ⟨1, by simp [dReq, SReq.hids, shids], not_rev_prot2 hI (prot1 hI)⟩)

theorem rq_ask (dk : Nat) (m : Bytes) {P0 : St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → st.ents[dk]? = some (false, dReq c.n)) :
    J2 c (sAsk (rqOf c.n dk m)) P0 (fun v st => ∃ i, v = [.hid i c.n] ∧
      (st.ents[i]? = some (false, rqOf c.n dk m) ∧ sres c.t [.hid i c.n] = c.O ((rqOf c.n dk m).res c.t))) :=
  j2_askE (rqOf c.n dk m) (by simp [rqOf]) (by simp [rqOf]) (fun st hI hp y hy => by
      simp [rqOf, SReq.hids, shids] at hy
      rcases hy with rfl | rfl
      · exact lt_entry (h st hI hp)
      · exact lt_entry hI.1.2.2)
    (fun st hI hp => Or.inl ⟨dk, by simp [rqOf, SReq.hids, shids],
      not_rev_prot2 hI ⟨_, h st hI hp, Or.inr (by simp [dReq, SReq.hids, shids])⟩⟩)

/-- The randomizer's handle may be disclosed. -/
theorem safe2_rq {st : St} (hI : Inv2 c st) {iR dk : Nat} {m : Bytes}
    (h1 : st.ents[iR]? = some (false, rqOf c.n dk m)) (h2 : st.ents[dk]? = some (false, dReq c.n)) :
    Safe2 c st iR := by
  have hdk := entry_ne hI h2 (by simp [dReq, coin]) (by simp [dReq, coin])
  refine ⟨lt_entry h1, ?_, ?_, ?_⟩
  · rintro ⟨e2, he2, h3⟩
    obtain rfl : (false, rqOf c.n dk m) = e2 := Option.some.inj (h1.symm.trans he2)
    simp [rqOf, SReq.hids, shids] at h3
    omega
  · intro tree leaf gi _ ⟨pk, hp1, hp2⟩
    have := (Prod.mk.inj (Option.some.inj (h1.symm.trans hp1))).2
    simp only [rqOf, prfReq, SReq.mk.injEq, List.cons.injEq, SV.hid.injEq, SV.lit.injEq] at this
    rw [← this.2.2.1.1.1, h2] at hp2
    simp [dReq, dPrf] at hp2
  · rintro ⟨L, T, F, ci, s, _, _, hlw⟩
    cases s with
    | zero =>
      obtain ⟨pk, hp1, hp2⟩ := hlw
      have := (Prod.mk.inj (Option.some.inj (h1.symm.trans hp1))).2
      simp only [rqOf, prfReq, SReq.mk.injEq, List.cons.injEq, SV.hid.injEq, SV.lit.injEq] at this
      rw [← this.2.2.1.1.1, h2] at hp2
      simp [dReq, dPrf] at hp2
    | succ s =>
      obtain ⟨itk, h', hp1, _, _⟩ := hlw
      have := (Prod.mk.inj (Option.some.inj (h1.symm.trans hp1))).2
      simp [rqOf, chReq] at this

/-- The signing request: its answer is a disclosable handle selecting by `SigD`. -/
theorem hq_ask (ρ iR dk : Nat) (m : Bytes) (hroot : c.root = [.hid ρ c.n]) {P0 : St → Prop}
    (h : ∀ st, Inv2 c st → P0 st → m ∈ c.Sg ∧ Safe2 c st ρ ∧ st.ents[iR]? = some (false, rqOf c.n dk m) ∧
      st.ents[dk]? = some (false, dReq c.n)) :
    J2 c (sAsk (hqOf c.n c.pm [.hid ρ c.n] iR m)) P0
      (fun v st => ∃ k, v = [.hid k c.pm] ∧ (SigD c st k m ∧ Safe2 c st k)) := by
  refine J2.ask _ (fun st hI hp y hy => ?_) (fun st hI hp iR' m' e => ?_)
    (fun st hI hp _ hI' hD => ⟨_, rfl, ?_, ?_⟩)
  · obtain ⟨_, hρ, h1, _⟩ := h st hI hp
    simp [hqOf, SReq.hids, shids] at hy
    rcases hy with rfl | rfl | rfl
    · exact lt_entry h1
    · exact lt_entry hI.1.2.2
    · exact hρ.1
  · rw [hroot] at e
    simp [hqOf] at e
    obtain ⟨rfl, rfl⟩ := e
    obtain ⟨hm, _, h1, h2⟩ := h st hI hp
    exact ⟨hm, dk, h1, h2⟩
  · obtain ⟨hm, _, h1, h2⟩ := h st hI hp
    obtain ⟨e, he, hres, _⟩ := ask_res (c := c) st (hqOf c.n c.pm [.hid ρ c.n] iR m)
    refine ⟨iR, dk, e, hm, grow_get (grow_addC st _) h1, grow_get (grow_addC st _) h2, he, ?_⟩
    rw [hres, hroot]
  · obtain ⟨_, hρ, h1, h2⟩ := h st hI hp
    have hR := safe2_ne hI (safe2_rq hI h1 h2)
    have hP := safe2_ne hI hρ
    refine ask_safe2 st _ hI' (grow_addC st _) (fun y hy => ?_) (fun pk A e => by simp [hqOf, prfReq] at e)
      (fun itk A h' e => by simp [hqOf, chReq] at e)
    simp [hqOf, SReq.hids, shids] at hy
    rcases hy with rfl | rfl | rfl
    · exact hR.2
    · exact ⟨by decide, by decide⟩
    · exact hP.2

end

section
variable {c : Ctx}

/-- What signing needs once the h_msg answer is known. -/
def SP (c : Ctx) (ρ itk ipk iR k : Nat) (m : Bytes) (st : St) : Prop :=
  Safe2 c st ρ ∧ (st.ents[itk]? = some (false, dTk c.n) ∧ st.ents[ipk]? = some (false, dPrf c.n)) ∧
    Safe2 c st iR ∧ SigD c st k m ∧ Safe2 c st k

theorem stable_SP (ρ itk ipk iR k : Nat) (m : Bytes) : Stable2 c (SP c ρ itk ipk iR k m) :=
  stable2_and (stable_safe2 ρ) (stable2_and (stable2_and (stable_ent itk _) (stable_ent ipk _))
    (stable2_and (stable_safe2 iR) (stable2_and (stable_sigD k m) (stable_safe2 k))))

theorem gd2_append {st : St} {x y : SB} (hx : Gd2 c st x) (hy : Gd2 c st y) : Gd2 c st (x ++ y) := by
  intro i w hm
  rcases List.mem_append.mp hm with h | h
  · exact hx i w h
  · exact hy i w h

theorem gd2_one {st : St} {i w : Nat} (h : Safe2 c st i) : Gd2 c st [.hid i w] := by
  intro j w' hm
  simp only [List.mem_singleton, SV.hid.injEq] at hm
  rw [hm.1]; exact h

end

theorem split_tree_lt (v : Variant) (dg : Bytes) : (splitDigest (params v) dg).tree < 256^8 := by
  obtain ⟨_, _, _, _, _, hb⟩ := variant_bounds v
  exact Nat.lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos _)) hb

theorem split_leaf_lt (v : Variant) (dg : Bytes) : (splitDigest (params v) dg).leaf < 2^(params v).hp :=
  Nat.mod_lt _ (Nat.two_pow_pos _)

section
variable {c : Ctx}

theorem j2_sign (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (msg : Bytes) (hne : msg.isEmpty = false)
    {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → msg ∈ c.Sg ∧ Safe2 c st ρ ∧ ∃ itk : Nat, st.ents[itk]? = some (false, dTk c.n)) :
    J2 c (sSign c.v (coinEx c.n ++ [.hid ρ c.n]) msg) P0 (fun res st => ∀ sg, res = some sg → Gd2 c st sg) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  have hn := params_n_pos c.v
  simp only [sSign, sDeriveKey, sKeyed, sHmsg]
  apply J2.ite
  · intro hc; exfalso; simp [hne, coinEx] at hc
  · intro _
    refine J2.bind J2.unit (fun _ => ?_) hs
    have s0 := stable2_and hs (stable2_true (c := c))
    refine J2.bind (dTk_ask (fun st hI hp => Or.inr (h st hI hp.1).2.2)) (fun tk => ?_) s0
    refine J2.obtain (fun itk htk => ?_)
    subst htk
    have s1 := stable2_and s0 (stable2_and (stable_ent (c := c) itk (false, dTk c.n))
      (stable_pure (c := c) (sres c.t [.hid itk 32] = expTk c.O c.v c.e)))
    refine J2.bind dPrf_ask (fun pk => ?_) s1
    refine J2.obtain (fun ipk hpk => ?_)
    subst hpk
    have s2 := stable2_and s1 (stable2_and (stable_ent (c := c) ipk (false, dPrf c.n))
      (stable_pure (c := c) (sres c.t [.hid ipk 32] = expPrf c.O c.v c.e)))
    refine J2.assume (X := Keys c [.hid itk 32] [.hid ipk 32] (expTk c.O c.v c.e) (expPrf c.O c.v c.e))
      (fun st _ hp => ⟨hp.1.2.2, hp.2.2⟩) (fun K => ?_)
    refine J2.bind dReq_ask (fun mk => ?_) s2
    refine J2.obtain (fun dk hmk => ?_)
    subst hmk
    have s3 := stable2_and s2 (stable2_and (stable_ent (c := c) dk (false, dReq c.n))
      (stable_pure (c := c) (sres c.t [.hid dk 32] = c.O ((dReq c.n).res c.t))))
    refine J2.bind (rq_ask dk msg (fun st _ hp => hp.2.1)) (fun r => ?_) s3
    refine J2.obtain (fun iR hr => ?_)
    subst hr
    have s4 := stable2_and s3 (stable2_and (stable_ent (c := c) iR (false, rqOf c.n dk msg))
      (stable_pure (c := c) (sres c.t [.hid iR c.n] = c.O ((rqOf c.n dk msg).res c.t))))
    refine J2.bind (hq_ask ρ iR dk msg hroot (fun st hI hp =>
      ⟨(h st hI hp.1.1.1.1.1).1, (h st hI hp.1.1.1.1.1).2.1, hp.2.1, hp.1.2.1⟩)) (fun dg => ?_) s4
    refine J2.obtain (fun k hk => ?_)
    subst hk
    refine J2.conseq (P0 := SP c ρ itk ipk iR k msg) ?_ (fun st hI hp =>
      ⟨(h st hI hp.1.1.1.1.1.1).2.1, ⟨hp.1.1.1.1.2.1, hp.1.1.1.2.1⟩,
        safe2_rq hI hp.1.2.1 hp.1.1.2.1, hp.2.1, hp.2.2⟩) (fun _ _ h => h)
    have sP := stable_SP (c := c) ρ itk ipk iR k msg
    refine J2.reveal' (fun st _ hp => gd2_one hp.2.2.2.2) ?_ sP
    rw [show sres c.t [.hid k c.pm] = be c.pm (c.t.getD k 0) by simp [sres, SV.res]]
    obtain ⟨hd2, _⟩ := supported_layer_bounds c.v
    generalize hI : splitDigest (params c.v) (be c.pm (c.t.getD k 0)) = I
    have ht : I.tree < 256^8 := hI ▸ split_tree_lt c.v _
    have hl : I.leaf < 2^(params c.v).hp := hI ▸ split_leaf_lt c.v _
    refine J2.bind (jr_forsSign K I.tree I.leaf ht (Nat.lt_of_lt_of_le hl hH) I.md sP
      (fun st _ hp => ⟨⟨itk, rfl, hp.2.1.1⟩, ⟨ipk, rfl, hp.2.1.2⟩⟩)
      (fun st _ hp => ⟨k, msg, hp.2.2.2.1, by rw [hI], by rw [hI], by rw [hI]⟩)) (fun fs => ?_) sP
    have S1 := stable2_and sP (stable_RG (c := c) fs (forsSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md))
    refine J2.bind (jr_forsPkFromSig K I.tree I.leaf fs _ I.md S1
      (fun st _ hp => ⟨⟨itk, rfl, hp.1.2.1.1⟩, hp.2⟩)) (fun fpk => ?_) S1
    have S2 := stable2_and S1 (stable_R1 (c := c) c.n fpk (forsPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      (forsAdrs I.tree I.leaf) (forsSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md) I.md))
    have hfpk : forsPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
        (forsAdrs I.tree I.leaf) (forsSign c.O (params c.v) (expTk c.O c.v c.e)
        (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md) I.md = c.M 0 I.tree I.leaf := by
      rw [M_eq]; simp only [htMsg, if_true]
      exact honest_fors_pk outputWidths_O I.tree I.leaf I.md
    refine J2.bind (jr_htSign K fpk _ I.tree I.leaf ht hl hfpk S2
      (fun st _ hp => ⟨⟨itk, rfl, hp.1.1.2.1.1⟩, ⟨ipk, rfl, hp.1.1.2.1.2⟩, RG_of_R1 hp.2⟩)) (fun hs => ?_) S2
    have S3 := stable2_and S2 (stable_RG (c := c) hs (htSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      (forsAdrs I.tree I.leaf) (forsSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md) I.md) I.tree I.leaf))
    refine J2.bind (jr_htRoot K hs fpk _ _ I.tree I.leaf ht hl S3
      (fun st _ hp => ⟨⟨itk, rfl, hp.1.1.1.2.1.1⟩, hp.2, RG_of_R1 hp.1.2, by
        have h1 := sres_length c.t c.n hs (allHid_WN hp.2.2.2)
        rw [hp.2.2.1, ht_sign_width c.O outputWidths_O _ _ _ _ _ _ _ (by omega)] at h1
        simp only [Params.layerBytes] at h1
        exact (Nat.eq_of_mul_eq_mul_right hn (by rw [← h1, Nat.mul_assoc])).symm⟩)) (fun actual => ?_) S3
    have S4 := stable2_and S3 (stable_RG (c := c) actual (htRoot c.O (params c.v) (expTk c.O c.v c.e)
      (htSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      (forsAdrs I.tree I.leaf) (forsSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md) I.md) I.tree I.leaf)
      (forsPkFromSig c.O (params c.v) (expTk c.O c.v c.e)
      (forsAdrs I.tree I.leaf) (forsSign c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (sres c.t [.hid 2 c.n]) (forsAdrs I.tree I.leaf) I.md) I.md) I.tree I.leaf))
    refine J2.reveal' (fun st _ hp => hp.2.1) ?_ S4
    refine J2.reveal' (fun st _ hp => gd2_one hp.1.1.1.1.1) ?_ S4
    apply J2.ite
    · intro _; exact J2.pure' (fun _ _ _ sg h => by cases h)
    · intro _
      refine J2.bind J2.unit (fun _ => J2.pure' (fun st _ hp sg h => ?_)) S4
      cases h
      exact gd2_append (gd2_append (gd2_one hp.1.1.1.1.1.2.2.1) hp.1.1.1.1.2.1) hp.1.1.2.1

end

/-! The adversary's verification: each request it issues ends with an open entry. -/

/-- Request `r` has an entry all of whose handles are disclosed. -/
def Opened (c : Ctx) (st : St) (r : Request) : Prop :=
  ∃ (j : Nat) (e : Bool × SReq), st.ents[j]? = some e ∧ e.2.res c.t = r ∧ isOpen st.rev e.2 = true

/-- The logging model computes the value, and every request it logs is opened. -/
def LogOk (c : Ctx) {α : Type} (X : LogM α) (a : α) (st : St) : Prop :=
  ∀ s, (X.run s).1 = a ∧ ∃ L, (X.run s).2 = s ++ L ∧ ∀ r ∈ L, Opened c st r

/-- A symbolic adversary-side program against its logging model. -/
def JA {α : Type} (c : Ctx) (P : Prog α) (X : LogM α) (P0 : St → Prop) : Prop :=
  J2 c P P0 (LogOk c X)

section
variable {c : Ctx}

theorem stable_opened (r : Request) : Stable2 c (fun st => Opened c st r) := by
  intro st st' _ hg ⟨j, e, he, hr, ho⟩
  refine ⟨j, e, grow_get hg he, hr, ?_⟩
  simp only [isOpen, List.all_eq_true, decide_eq_true_eq] at ho ⊢
  exact fun x hx => hg.2 x (ho x hx)

theorem stable_logOk {α : Type} (X : LogM α) (a : α) : Stable2 c (LogOk c X a) := by
  intro st st' hI hg h s
  obtain ⟨h1, L, h2, h3⟩ := h s
  exact ⟨h1, L, h2, fun r hr => stable_opened r st st' hI hg (h3 r hr)⟩

/-- After an adversary request, its answer's entry resolves to it and is open. -/
theorem askA_entry (st : St) (q : Request) :
    ∃ e, (addA st (firstIdx (mA false c.t st.rev q) st.ents) q).ents[firstIdx (mA false c.t st.rev q) st.ents]? =
      some e ∧ e.2.res c.t = q ∧
      isOpen (addA st (firstIdx (mA false c.t st.rev q) st.ents) q).rev e.2 = true := by
  generalize hi : firstIdx (mA false c.t st.rev q) st.ents = i
  by_cases hl : i < st.ents.length
  · obtain ⟨e, he, hp⟩ := firstIdx_hit (mA false c.t st.rev q) st.ents (hi ▸ hl)
    rw [hi] at he
    simp only [mA, Bool.false_eq_true, if_false, Bool.and_eq_true, decide_eq_true_eq] at hp
    refine ⟨e, by simp only [addA, if_pos hl]; exact he, hp.2, ?_⟩
    have ho := hp.1
    simp only [isOpen, List.all_eq_true, decide_eq_true_eq, addA] at ho ⊢
    exact fun x hx => List.mem_cons_of_mem _ (ho x hx)
  · have hi' : i = st.ents.length := Nat.le_antisymm (hi ▸ firstIdx_le _ _) (Nat.le_of_not_lt hl)
    refine ⟨(true, lift q), by simp [addA, hi'], lift_res _ _, ?_⟩
    simp [isOpen, lift, SReq.hids, shids]

namespace JA

theorem pure' {α : Type} {a : α} {P0 : St → Prop} : JA c (.done a) (pure a) P0 :=
  J2.pure' (fun _ _ _ s => ⟨by rw [logM_run_pure], [], by rw [logM_run_pure]; simp, by simp⟩)

theorem bind {α β : Type} {P : Prog α} {f : α → Prog β} {X : LogM α} {Y : α → LogM β} {P0 : St → Prop}
    (hP : JA c P X P0) (hf : ∀ a, JA c (f a) (Y a) P0) (hs : Stable2 c P0) :
    JA c (P >>= f) (X >>= Y) P0 := by
  refine J2.bind hP (fun a => ?_) hs
  refine J2.conseq (J2.frame (J2.conseq (hf a) (fun st _ h => h.1) (fun _ _ h => h))
    (stable2_and hs (stable_logOk X a))) (fun _ _ h => h) (fun b st h => ?_)
  intro s
  obtain ⟨h1, L1, h2, h3⟩ := h.1.2 s
  obtain ⟨h4, L2, h5, h6⟩ := h.2 (s ++ L1)
  rw [logM_run_bind, h1, h2]
  refine ⟨h4, L1 ++ L2, by rw [h5, List.append_assoc], fun r hr => ?_⟩
  rcases List.mem_append.mp hr with hr | hr
  · exact h3 r hr
  · exact h6 r hr

theorem ite {α : Type} {b : Prop} [Decidable b] {P₁ P₂ : Prog α} {X₁ X₂ : LogM α} {P0 : St → Prop}
    (h₁ : b → JA c P₁ X₁ P0) (h₂ : ¬b → JA c P₂ X₂ P0) :
    JA c (if b then P₁ else P₂) (if b then X₁ else X₂) P0 := by
  by_cases h : b
  · simp only [h, if_true]; exact h₁ h
  · simp only [h, if_false]; exact h₂ h

theorem ask (q : Request) {P0 : St → Prop} : JA c (advP q) (logOracle c.O q) P0 := by
  refine J2.askA (fun st _ _ _ => ?_)
  intro st' hI' hst _ hD
  subst hst
  obtain ⟨e, he, hres, ho⟩ := askA_entry (c := c) st q
  have hv := agree hI' hD he
  have hl : e.2.outLen = q.outLen := by rw [← hres]; rfl
  rw [hres, hl] at hv
  refine ⟨hI', grow_refl _, fun s => ⟨?_, [q], by rw [logOracle_run], fun r hr => ?_⟩⟩
  · rw [logOracle_run]; exact hv
  · rw [List.mem_singleton.mp hr]; exact ⟨_, e, he, hres, ho⟩

theorem loop {ι σ : Type} (l : List ι) (f : ι → σ → Prog (ForInStep σ)) (g : ι → σ → LogM (ForInStep σ))
    {P0 : St → Prop} (hs : Stable2 c P0) (h : ∀ i ∈ l, ∀ s, JA c (f i s) (g i s) P0) :
    ∀ s, JA c (forIn l s f) (forIn l s g) P0 := by
  induction l with
  | nil => intro s; exact JA.pure'
  | cons a l ih =>
    intro s
    rw [List.forIn_cons, List.forIn_cons]
    refine JA.bind (h a (by simp) s) (fun x => ?_) hs
    cases x with
    | done b => exact JA.pure'
    | yield b => exact ih (fun i hi => h i (by simp [hi])) b

end JA

variable {P0 : St → Prop}

theorem ja_chain (hs : Stable2 c P0) (p : Params) (tk : Bytes) (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    JA c (chain advP p tk a x start steps) (chain (logOracle c.O) p tk a x start steps) P0
  | 0, x, _ => JA.pure'
  | steps+1, x, start => by
    simp only [chain]
    exact JA.bind (JA.ask _) (fun y => ja_chain hs p tk a steps y (start+1)) hs

theorem ja_authWalk (hs : Stable2 c P0) (p : Params) (tk : Bytes) (a : Adrs) (auth : Bytes) :
    ∀ (remaining li gi level : Nat) (node : Bytes),
    JA c (authWalk advP p tk a li gi node auth level remaining)
      (authWalk (logOracle c.O) p tk a li gi node auth level remaining) P0
  | 0, _, _, _, _ => JA.pure'
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact JA.bind (JA.ask _) (fun y => ja_authWalk hs p tk a auth remaining _ _ _ y) hs

theorem ja_wotsPkFromSig (hs : Stable2 c P0) (p : Params) (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
    JA c (wotsPkFromSig advP p tk a sig msg) (wotsPkFromSig (logOracle c.O) p tk a sig msg) P0 := by
  simp only [wotsPkFromSig, wotsCompress]
  refine JA.bind (JA.loop _ _ _ hs ?_ []) (fun tops => JA.ask _) hs
  intro x _ s
  obtain ⟨digit, i⟩ := x
  exact JA.bind (ja_chain hs p tk _ _ _ _) (fun top => JA.pure') hs

theorem ja_xmssPkFromSig (hs : Stable2 c P0) (p : Params) (tk : Bytes) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    JA c (xmssPkFromSig advP p tk a idx sig msg) (xmssPkFromSig (logOracle c.O) p tk a idx sig msg) P0 := by
  simp only [xmssPkFromSig, authRoot]
  exact JA.bind (ja_wotsPkFromSig hs p tk _ _ _) (fun node => ja_authWalk hs p tk _ _ _ _ _ _ _) hs

theorem ja_htRootTail (hs : Stable2 c P0) (p : Params) (tk : Bytes) : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    JA c (htRootTail advP p tk layer tree node sig remaining)
      (htRootTail (logOracle c.O) p tk layer tree node sig remaining) P0
  | 0, _, _, _, _ => JA.pure'
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact JA.bind (ja_xmssPkFromSig hs p tk _ _ _ _) (fun root => ja_htRootTail hs p tk remaining _ _ root _) hs

theorem ja_htRoot (hs : Stable2 c P0) (p : Params) (tk sig msg : Bytes) (tree leaf : Nat) :
    JA c (htRoot advP p tk sig msg tree leaf) (htRoot (logOracle c.O) p tk sig msg tree leaf) P0 := by
  simp only [htRoot]
  exact JA.bind (ja_xmssPkFromSig hs p tk _ _ _ _) (fun node => ja_htRootTail hs p tk _ _ _ node _) hs

theorem ja_forsPkFromSig (hs : Stable2 c P0) (p : Params) (tk : Bytes) (a : Adrs) (sig md : Bytes) :
    JA c (forsPkFromSig advP p tk a sig md) (forsPkFromSig (logOracle c.O) p tk a sig md) P0 := by
  simp only [forsPkFromSig, authRoot]
  refine JA.bind (JA.loop _ _ _ hs ?_ []) (fun roots => JA.ask _) hs
  intro x _ s
  obtain ⟨idx, i⟩ := x
  exact JA.bind (JA.ask _) (fun leaf => JA.bind (ja_authWalk hs p tk _ _ _ _ _ _ leaf)
    (fun root => JA.pure') hs) hs

theorem ja_verify (hs : Stable2 c P0) (v : Variant) (pk msg sig : Bytes) :
    JA c (verify advP v pk msg sig) (verify (logOracle c.O) v pk msg sig) P0 := by
  simp only [verify]
  refine JA.ite (fun _ => JA.pure') (fun _ => ?_)
  refine JA.bind JA.pure' (fun _ => ?_) hs
  refine JA.ite (fun _ => JA.pure') (fun _ => ?_)
  refine JA.bind JA.pure' (fun _ => ?_) hs
  exact JA.bind (JA.ask _) (fun tk => JA.bind (JA.ask _) (fun dg =>
    JA.bind (ja_forsPkFromSig hs _ tk _ _ _) (fun fpk => JA.bind (ja_htRoot hs _ tk _ _ _ _)
      (fun ac => JA.pure') hs) hs) hs) hs

end

/-! Rules carrying a fact about the rest of the run (the messages it will sign). -/

section
variable {c : Ctx}

theorem J2.bindF {α β : Type} {P : Prog α} {f : α → Prog β} {P0 : St → Prop} {Q : α → St → Prop}
    {R : β → St → Prop} (F : β × St → Prop)
    (hP : J2 c P (fun st => P0 st ∧ F (xrun false c.t (P.bind f) st)) Q)
    (hf : ∀ a, J2 c (f a) (fun st => (P0 st ∧ Q a st) ∧ F (xrun false c.t (f a) st)) R) (hs : Stable2 c P0) :
    J2 c (P.bind f) (fun st => P0 st ∧ F (xrun false c.t (P.bind f) st)) R := by
  intro st hI hp hnd hD
  rw [strace_bind] at hnd
  have hF := hp.2
  rw [xrun_bind] at hD hF ⊢
  have hD1 := pre_back c.t (xrun_grow c.t _ _) hD
  obtain ⟨hI1, hx1, hq1⟩ := hP st hI hp (fun s hs' => hnd s (List.mem_append_left _ hs')) hD1
  obtain ⟨hI2, hx2, hq2⟩ := hf _ _ hI1 ⟨⟨hs _ _ hI hx1 hp.1, hq1⟩, hF⟩
    (fun s hs' => hnd s (List.mem_append_right _ hs')) hD
  exact ⟨hI2, grow_trans hx1 hx2, hq2⟩

theorem J2.askAF {α : Type} {q : Request} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (F : α × St → Prop) (hs : Stable2 c P0)
    (hk : ∀ b, J2 c (k b) (fun st => P0 st ∧ F (xrun false c.t (k b) st)) Q) :
    J2 c (.askA q k) (fun st => P0 st ∧ F (xrun false c.t (.askA q k) st)) Q := by
  refine J2.askA (fun st hI hp _ => J2.conseq (hk _) (fun st' _ hst => ?_) (fun _ _ h => h))
  subst hst
  have hx1 : Grow2 st (addA st (firstIdx (mA false c.t st.rev q) st.ents) q) := by
    have := xrun_grow c.t (.askA q (fun _ => .done ())) st
    simpa [xrun] using this
  exact ⟨hs _ _ hI hx1 hp.1, hp.2⟩

theorem J2.revealF {α : Type} {x : List SV} {k : Bytes → Prog α} {P0 : St → Prop} {Q : α → St → Prop}
    (F : α × St → Prop) (hx : ∀ st, Inv2 c st → P0 st → Gd2 c st x) (hs : Stable2 c P0)
    (hk : J2 c (k (sres c.t x)) (fun st => P0 st ∧ F (xrun false c.t (k (sres c.t x)) st)) Q) :
    J2 c (.reveal x k) (fun st => P0 st ∧ F (xrun false c.t (.reveal x k) st)) Q := by
  intro st hI hp hnd hD
  simp only [strace, List.mem_cons, forall_eq_or_imp] at hnd
  simp only [xrun] at hD ⊢
  have hI1 := step_reveal2 st x hI (hx st hI hp.1)
  have hx1 : Grow2 st ⟨st.ents, shids x ++ st.rev⟩ := ⟨⟨[], by simp⟩, fun _ h => List.mem_append_right _ h⟩
  obtain ⟨hI2, hx2, hq⟩ := hk _ hI1 ⟨hs _ _ hI hx1 hp.1, hp.2⟩ hnd.2 hD
  exact ⟨hI2, grow_trans hx1 hx2, hq⟩

end

/-! The messages a play signs end up in its output. -/

theorem signed_mono (t : List Nat) (v : Variant) (limits : Limits) (pk : Bytes) (sk : SB) :
    ∀ (A : RAdv) (signed : List Bytes) (st : St), ∀ x ∈ signed,
      x ∈ (xrun false t (playS v limits pk sk A signed) st).1.signed
  | .hq r k, signed, st, x, hx => by
    simp only [playS, xrun]
    exact signed_mono t v limits pk sk (k _) signed _ x hx
  | .sq m k, signed, st, x, hx => by
    simp only [playS]
    split
    · rw [xrun_bind]
      generalize (xrun false t (sSign v sk m) st) = R
      obtain ⟨res, st1⟩ := R
      cases res with
      | none => exact signed_mono t v limits pk sk (k none) (signed ++ [m]) st1 x (List.mem_append_left _ hx)
      | some sg =>
        simp only [xrun]
        exact signed_mono t v limits pk sk (k _) (signed ++ [m]) _ x (List.mem_append_left _ hx)
    · exact signed_mono t v limits pk sk (k none) signed st x hx
  | .out m s, signed, st, x, hx => by
    simp only [playS]
    rw [xrun_bind]
    simp only [xrun]
    exact hx

theorem mem_sq (t : List Nat) (v : Variant) (limits : Limits) (pk : Bytes) (sk : SB) (m : Bytes)
    (k : Option Bytes → RAdv) (signed : List Bytes) (st : St) (hl : legal limits m = true) :
    m ∈ (xrun false t (playS v limits pk sk (.sq m k) signed) st).1.signed := by
  simp only [playS, hl, if_true]
  rw [xrun_bind]
  generalize (xrun false t (sSign v sk m) st) = R
  obtain ⟨res, st1⟩ := R
  cases res with
  | none => exact signed_mono t v limits pk sk (k none) (signed ++ [m]) st1 m (by simp)
  | some sg =>
    simp only [xrun]
    exact signed_mono t v limits pk sk (k _) (signed ++ [m]) _ m (by simp)

/-! The play loop. -/

section
variable {c : Ctx}

/-- What the play loop needs about the key. -/
def PP (c : Ctx) (ρ : Nat) (st : St) : Prop :=
  Safe2 c st ρ ∧ ∃ itk : Nat, st.ents[itk]? = some (false, dTk c.n)

theorem stable_PP (ρ : Nat) : Stable2 c (PP c ρ) :=
  fun _ _ hI hg ⟨h1, itk, h2⟩ => ⟨safe2_mono hI hg h1, itk, grow_get hg h2⟩

/-- The future-signed condition. -/
def FS (c : Ctx) (r : Out × St) : Prop := ∀ m ∈ r.1.signed, m ∈ c.Sg

theorem j2_play (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (limits : Limits) (pk : Bytes) :
    ∀ (A : RAdv) (signed : List Bytes),
    J2 c (playS c.v limits pk (coinEx c.n ++ [.hid ρ c.n]) A signed)
      (fun st => PP c ρ st ∧ FS c (xrun false c.t (playS c.v limits pk (coinEx c.n ++ [.hid ρ c.n]) A signed) st))
      (fun out st => ∀ r ∈ verifyLog c.O c.v pk out.msg out.sig, Opened c st r)
  | .hq r k, signed => by
    simp only [playS]
    exact J2.askAF (FS c) (stable_PP ρ) (fun b => j2_play ρ hroot limits pk (k b) signed)
  | .sq m k, signed => by
    by_cases hl : legal limits m = true
    · have hne : m.isEmpty = false := by
        unfold legal at hl; cases h : m.isEmpty <;> simp_all
      refine J2.conseq (P0 := fun st => (PP c ρ st ∧ m ∈ c.Sg) ∧
          FS c (xrun false c.t (playS c.v limits pk (coinEx c.n ++ [.hid ρ c.n]) (.sq m k) signed) st)) ?_
        (fun st _ hp => ⟨⟨hp.1, hp.2 m (mem_sq _ _ _ _ _ m k signed st hl)⟩, hp.2⟩) (fun _ _ h => h)
      simp only [playS, hl, if_true]
      have hs0 := stable2_and (stable_PP (c := c) ρ) (stable_pure (c := c) (m ∈ c.Sg))
      refine J2.bindF (FS c) (J2.conseq (j2_sign ρ hroot m hne hs0
        (fun st _ hp => ⟨hp.2, hp.1.1, hp.1.2⟩)) (fun _ _ hp => hp.1) (fun _ _ h => h)) (fun s => ?_) hs0
      cases s with
      | none =>
        exact J2.conseq (j2_play ρ hroot limits pk (k none) (signed ++ [m]))
          (fun _ _ hp => ⟨hp.1.1.1, hp.2⟩) (fun _ _ h => h)
      | some sg =>
        refine J2.revealF (FS c) (fun st _ hp => hp.2 sg rfl)
          (stable2_and hs0 (fun st st' hI hg h sg' e => gd2_mono hI hg (h sg' e))) ?_
        exact J2.conseq (j2_play ρ hroot limits pk (k _) (signed ++ [m]))
          (fun _ _ hp => ⟨hp.1.1.1, hp.2⟩) (fun _ _ h => h)
    · have hl' : legal limits m = false := by cases h : legal limits m <;> simp_all
      simp only [playS, hl', Bool.false_eq_true, if_false]
      exact j2_play ρ hroot limits pk (k none) signed
  | .out m s, signed => by
    simp only [playS]
    refine J2.conseq (P0 := fun _ => True) (J2.bind' (ja_verify (stable2_true (c := c)) c.v pk m s)
      (fun ok => J2.pure' (fun st _ hp => ?_)) stable2_true) (fun _ _ _ => trivial) (fun _ _ h => h)
    intro r hr
    obtain ⟨_, L, h2, h3⟩ := hp.2 []
    apply h3
    have e : verifyLog c.O c.v pk m s = [] ++ L := h2
    rw [e] at hr
    simpa using hr

end

/-! The extension. -/

section
variable {c : Ctx}

theorem safe2_two {st : St} (hI : Inv2 c st) : Safe2 c st 2 := by
  have h2 := hI.1.2.2
  refine ⟨lt_entry h2, ?_, ?_, ?_⟩
  · rintro ⟨e, he, h3⟩
    rw [h2] at he
    obtain rfl := Option.some.inj he
    simp [coin, SReq.hids, shids] at h3
  · intro tree leaf gi _ ⟨pk, h1, _⟩
    rw [h2] at h1; simp [coin, prfReq] at h1
  · rintro ⟨L, T, F, ci, s, _, _, hlw⟩
    cases s with
    | zero => obtain ⟨pk, h1, _⟩ := hlw; rw [h2] at h1; simp [coin, prfReq] at h1
    | succ s => obtain ⟨itk, h', h1, _, _⟩ := hlw; rw [h2] at h1; simp [coin, chReq] at h1

/-- A loop that always continues establishes its per-iteration facts for every element. -/
theorem J2.loopAll {ι : Type} (l : List ι) (f : ι → PUnit → Prog (ForInStep PUnit)) {P0 : St → Prop}
    (G : ι → St → Prop) (hs : Stable2 c P0) (hG : ∀ i, Stable2 c (G i))
    (hf : ∀ i ∈ l, ∀ u, J2 c (f i u) P0 (fun r st => r = .yield PUnit.unit ∧ G i st)) :
    ∀ u, J2 c (forIn l u f) P0 (fun _ st => ∀ i ∈ l, G i st) := by
  induction l with
  | nil => intro u; exact J2.pure' (fun _ _ _ i hi => by cases hi)
  | cons a l ih =>
    intro u
    rw [List.forIn_cons]
    refine J2.bind (hf a (by simp) u) (fun x => ?_) hs
    cases x with
    | done b => exact fun st _ hp => absurd hp.2.1 (by simp)
    | yield b =>
      refine J2.conseq (J2.frame (J2.conseq (ih (fun i hi => hf i (by simp [hi])) b) (fun _ _ h => h.1)
        (fun _ _ h => h)) (stable2_and hs (stable2_and (stable_pure _) (hG a)))) (fun _ _ h => h)
        (fun _ st h i hi => ?_)
      rcases List.mem_cons.mp hi with rfl | hi
      · exact h.1.2.2
      · exact h.2 i hi

end

theorem ext_tree_le (v : Variant) (tree leaf l : Nat) (hleaf : leaf < 2^(params v).hp) :
    (tree*2^(params v).hp + leaf)/2^((params v).hp*l)/2^(params v).hp ≤ tree := by
  have hp : 0 < 2^(params v).hp := Nat.two_pow_pos _
  rw [Nat.div_div_eq_div_mul, Nat.mul_comm (2^((params v).hp*l)), ← Nat.div_div_eq_div_mul]
  have : (tree*2^(params v).hp + leaf)/2^(params v).hp = tree := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hp, Nat.div_eq_of_lt hleaf, Nat.zero_add]
  rw [this]; exact Nat.div_le_self _ _

section
variable {c : Ctx}

/-- The extension's h_msg request: the verifier's digest request. -/
def extReq (c : Ctx) (ρ : Nat) (msg sig : Bytes) : Request :=
  ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take c.n ++ sres c.t [.hid 2 c.n, .hid ρ c.n] ++ msg, c.pm⟩

def extT (v : Variant) (I : Indices) (l : Nat) : Nat :=
  (I.tree*2^(params v).hp + I.leaf)/2^((params v).hp*l)/2^(params v).hp
def extF (v : Variant) (I : Indices) (l : Nat) : Nat :=
  (I.tree*2^(params v).hp + I.leaf)/2^((params v).hp*l)%2^(params v).hp

/-- What the extension leaves: the honest FORS leaf entries at the digest's indices,
    and the honest WOTS chain entries up to the honest digits on its hypertree path. -/
def ExtPost (c : Ctx) (I : Indices) (st : St) : Prop :=
  (∀ i ∈ List.range (params c.v).k, ∃ w, LeafAt c st w I.tree I.leaf (i*2^(params c.v).a + forsDigit (params c.v) I.md i)) ∧
  (∀ l ∈ List.range (params c.v).d, ∀ ci ∈ List.range (params c.v).len, ∀ s', s' ≤ c.dgt l (extT c.v I l) (extF c.v I l) ci →
    ∃ j, LowAt c.n st j l (extT c.v I l) (extF c.v I l) ci s')

theorem stable_lowAll (L T F : Nat) : Stable2 c (fun st => ∀ ci ∈ List.range (params c.v).len, ∀ s', s' ≤ c.dgt L T F ci →
    ∃ j, LowAt c.n st j L T F ci s') :=
  fun _ _ _ hg h ci hci s' hs' => let ⟨j, hj⟩ := h ci hci s' hs'; ⟨j, lowAt_fwd hg _ hj⟩

theorem stable_leafEx (tree leaf gi : Nat) : Stable2 c (fun st => ∃ w, LeafAt c st w tree leaf gi) :=
  fun st st' hI hg ⟨w, hw⟩ => ⟨w, stable_leafAt w tree leaf gi st st' hI hg hw⟩

theorem j2_forsLeaf0 {tk pk : SB} {tk' pk' : Bytes} (K : Keys c tk pk tk' pk') (tree leaf gi : Nat)
    {P0 : St → Prop} (hs : Stable2 c P0) (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    J2 c (sForsNode (params c.v) tk pk [.hid 2 c.n] (forsAdrs tree leaf) gi 0) P0
      (fun v st => LeafAt c st v tree leaf gi) := by
  simp only [sForsNode, sForsSecret]
  exact J2.conseq (jr_forsLeaf K tree leaf gi hs h) (fun _ _ h => h) (fun _ _ h => h.2)

/-- The extension's tail keeps any stable precondition. -/
theorem j2_extTail {tk pk : SB} {tk' pk' : Bytes} (K : Keys c tk pk tk' pk') (I : Indices)
    (htI : I.tree < 256^8) (hlI : I.leaf < 2^(params c.v).hp) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → TKh c st tk ∧ PKh c st pk) :
    J2 c (sExtTail (params c.v) tk pk [.hid 2 c.n] I) P0 (fun _ st => P0 st) := by
  obtain ⟨_, hH, hd, _⟩ := variant_bounds c.v
  simp only [sExtTail]
  refine J2.bind (J2.loop' _ _ (fun r st => RG c r (sres c.t r) st) hs (fun r => stable_RG r _) []
    (fun st _ _ => RG_nil st) (fun i _ r => ?_)) (fun roots => ?_) hs
  · have hs1 := stable2_and hs (stable_RG (c := c) r (sres c.t r))
    refine J2.bind (jr_forsNode K I.tree I.leaf (params c.v).a i hs1 (fun st hI hp => h st hI hp.1))
      (fun x => ?_) hs1
    refine J2.bind J2.unit (fun _ => J2.pure' (fun st _ hp => ?_))
      (stable2_and hs1 (stable_R1 (c := c) c.n x _))
    have := RG_append hp.1.1.2 (RG_of_R1 hp.1.2)
    exact ⟨this.1, rfl, this.2.2⟩
  have hs2 := stable2_and hs (stable_RG (c := c) roots (sres c.t roots))
  refine J2.bind0 (J2.frame (jr_thash (params c.v) tk _ roots tk' (sres c.t roots) (by simp [forsAdrs, Adrs.setType])
    (by simp [forsAdrs, Adrs.setType]) K.htk (fun _ _ _ => rfl)
    (fun st hI hp => hids_tk_gd hI (h st hI hp.1).1 hp.2.1)) hs2)
    (fun z => J2.conseq (P0 := fun st => P0 st ∧ RG c roots (sres c.t roots) st) ?_ (fun _ _ h => h.1)
      (fun _ _ h => h))
  refine J2.bind (J2.loop' _ _ (fun _ _ => True) hs2 (fun _ => stable2_true) PUnit.unit (fun _ _ _ => trivial)
    (fun l hl u => ?_)) (fun _ => J2.pure' (fun st _ hp => hp.1.1)) hs2
  have hl' := List.mem_range.mp hl
  have hs4 := stable2_and hs2 (stable2_true (c := c))
  refine J2.bind0 (J2.frame (jr_xmssNode K l (pathT (params c.v) I l) (by omega)
    (Nat.lt_of_le_of_lt (ext_tree_le c.v I.tree I.leaf l hlI) htI) (params c.v).hp 0 hs4 (by simp)
    (fun st hI hp => h st hI hp.1.1)) hs4) (fun _ => ?_)
  exact J2.bind0 J2.unit (fun _ => J2.pure' (fun _ _ _ => trivial))

theorem j2_ext (ρ : Nat) (msg sig : Bytes) {P0 : St → Prop} (hs : Stable2 c P0)
    (h : ∀ st, Inv2 c st → P0 st → PP c ρ st) :
    J2 c (sExtW c.v (coinEx c.n ++ [.hid ρ c.n]) msg sig) P0
      (fun _ st => ExtPost c (splitDigest (params c.v) (c.O (extReq c ρ msg sig))) st) := by
  obtain ⟨_, hH, hd, _, _, hhb⟩ := variant_bounds c.v
  simp only [sExtW, sDeriveKey]
  refine J2.bind (dTk_ask (fun st hI hp => Or.inr (h st hI hp).2)) (fun tk => ?_) hs
  refine J2.obtain (fun itk htk => ?_)
  subst htk
  have s1 := stable2_and hs (stable2_and (stable_ent (c := c) itk (false, dTk c.n))
    (stable_pure (c := c) (sres c.t [.hid itk 32] = expTk c.O c.v c.e)))
  refine J2.bind dPrf_ask (fun pk => ?_) s1
  refine J2.obtain (fun ipk hpk => ?_)
  subst hpk
  have s2 := stable2_and s1 (stable2_and (stable_ent (c := c) ipk (false, dPrf c.n))
    (stable_pure (c := c) (sres c.t [.hid ipk 32] = expPrf c.O c.v c.e)))
  refine J2.assume (X := Keys c [.hid itk 32] [.hid ipk 32] (expTk c.O c.v c.e) (expPrf c.O c.v c.e))
    (fun st _ hp => ⟨hp.1.2.2, hp.2.2⟩) (fun K => ?_)
  refine J2.conseq (P0 := fun st => (TKh c st [.hid itk 32] ∧ PKh c st [.hid ipk 32]) ∧ PP c ρ st) ?_
    (fun st hI hp => ⟨⟨⟨itk, rfl, hp.1.2.1⟩, ⟨ipk, rfl, hp.2.1⟩⟩, h st hI hp.1.1⟩) (fun _ _ h => h)
  have sK := stable2_and (stable2_and (stable_tkh (c := c) [.hid itk 32]) (stable_pkh (c := c) [.hid ipk 32]))
    (stable_PP (c := c) ρ)
  refine J2.bind (J2.reveal' (fun st hI hp => ?_) (JA.ask (extReq c ρ msg sig)) sK) (fun dg => ?_) sK
  · intro i w hm
    have hm' : SV.hid i w ∈ [SV.hid 2 c.n, SV.hid ρ c.n] := hm
    simp only [List.mem_cons, SV.hid.injEq, List.not_mem_nil, or_false] at hm'
    rcases hm' with ⟨rfl, _⟩ | ⟨rfl, _⟩
    · exact safe2_two hI
    · exact hp.2.1
  refine J2.assume (X := dg = c.O (extReq c ρ msg sig)) (fun st _ hp => ?_) (fun hdg => ?_)
  · have := (hp.2 []).1
    rw [logOracle_run] at this
    exact this.symm
  subst hdg
  refine J2.conseq (P0 := fun st => (TKh c st [.hid itk 32] ∧ PKh c st [.hid ipk 32]) ∧ PP c ρ st) ?_
    (fun _ _ hp => hp.1) (fun _ _ h => h)
  generalize hI : splitDigest (params c.v) (c.O (extReq c ρ msg sig)) = I
  have htI : I.tree < 256^8 := hI ▸ split_tree_lt c.v _
  have hlI : I.leaf < 2^(params c.v).hp := hI ▸ split_leaf_lt c.v _
  have sFa : Stable2 c (fun st => ∀ i ∈ List.range (params c.v).k,
      ∃ w, LeafAt c st w I.tree I.leaf (i*2^(params c.v).a + forsDigit (params c.v) I.md i)) :=
    fun st st' hI' hg h i hi => stable_leafEx _ _ _ st st' hI' hg (h i hi)
  refine J2.bind (J2.loopAll _ _ (fun i st => ∃ w, LeafAt c st w I.tree I.leaf
      (i*2^(params c.v).a + forsDigit (params c.v) I.md i)) sK (fun i => stable_leafEx _ _ _)
      (fun i _ u => ?_) PUnit.unit) (fun _ => ?_) sK
  · refine J2.bind (j2_forsLeaf0 K I.tree I.leaf _ sK (fun st _ hp => hp.1)) (fun w => ?_) sK
    exact J2.bind J2.unit (fun _ => J2.pure' (fun st _ hp => ⟨rfl, w, hp.1.2⟩))
      (stable2_and sK (stable_leafAt w _ _ _))
  have sF := stable2_and sK sFa
  refine J2.bind (J2.loopAll _ _ (fun l st => ∀ ci ∈ List.range (params c.v).len, ∀ s',
      s' ≤ c.dgt l (extT c.v I l) (extF c.v I l) ci → ∃ j, LowAt c.n st j l (extT c.v I l) (extF c.v I l) ci s')
      sF (fun l => stable_lowAll _ _ _) (fun l hl u => ?_) PUnit.unit)
    (fun _ => J2.conseq (j2_extTail K I htI hlI (stable2_and sF (show Stable2 c (fun st =>
        ∀ l ∈ List.range (params c.v).d, ∀ ci ∈ List.range (params c.v).len, ∀ s',
          s' ≤ c.dgt l (extT c.v I l) (extF c.v I l) ci → ∃ j, LowAt c.n st j l (extT c.v I l) (extF c.v I l) ci s')
        from fun st st' hI' hg h l hl => stable_lowAll _ _ _ st st' hI' hg (h l hl))) (fun st _ hp => hp.1.1.1))
      (fun _ _ h => h) (fun _ _ hp => ⟨hp.1.2, hp.2⟩)) sF
  have hl' := List.mem_range.mp hl
  refine J2.bind (J2.conseq (jr_wotsPkgen K l (extT c.v I l) (extF c.v I l) (by omega)
    (Nat.lt_of_le_of_lt (ext_tree_le c.v I.tree I.leaf l hlI) htI)
    (Nat.lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos _)) hH) sF (fun st _ hp => hp.1.1))
    (fun _ _ h => h) (fun _ _ h => h.2)) (fun _ => ?_) sF
  exact J2.bind J2.unit (fun _ => J2.pure' (fun st _ hp => ⟨rfl, hp.1.2⟩)) (stable2_and sF (stable_lowAll _ _ _))

end

/-! The whole extended game. -/

theorem inv2_coin (c : Ctx) : Inv2 c (coinSt c.n) := by
  have hlen : (coinSt c.n).ents.length = 3 := rfl
  refine ⟨⟨rfl, rfl, rfl⟩, ?_, ?_, ?_, ?_, ?_⟩
  · intro i e he h hm
    rw [hlen]
    simp only [coinSt] at he
    rcases i with _ | _ | _ | i <;> simp at he <;> subst he <;> simp [coin, SReq.hids, shids] at hm <;> omega
  · intro a qa he; rcases a with _ | _ | _ | a <;> simp [coinSt, coin] at he
  · intro a b ea eb _ hb _ hbe
    have := lt_entry hbe
    omega
  · intro i hi; simp [coinSt] at hi
  · intro k iR m hk; rcases k with _ | _ | _ | k <;> simp [coinSt, coin, hqOf] at hk

/-- The game after key generation. -/
def restS (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ks : SB × SB) : Prog Out :=
  .reveal ks.1 (fun pk => Prog.bind (playS v limits pk ks.2 (A pk) [])
    (fun out => Prog.bind (sExtW v ks.2 out.msg out.sig) (fun _ => .done out)))

theorem gameS'_eq (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : SB) :
    gameS' v limits A ex = Prog.bind (sKgTail v ex) (restS v limits A) := rfl

/-- What the end of the extended game satisfies. -/
def GamePost (c : Ctx) (ρ : Nat) (out : Out) (st : St) : Prop :=
  (∀ r ∈ verifyLog c.O c.v (sres c.t [.hid 2 c.n, .hid ρ c.n]) out.msg out.sig, Opened c st r) ∧
    ExtPost c (splitDigest (params c.v) (c.O (extReq c ρ out.msg out.sig))) st

section
variable {c : Ctx}

theorem stable_verOpened (pk m s : Bytes) :
    Stable2 c (fun st => ∀ r ∈ verifyLog c.O c.v pk m s, Opened c st r) :=
  fun st st' hI hg h r hr => stable_opened r st st' hI hg (h r hr)

theorem j2_rest (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) (limits : Limits) (A : Bytes → RAdv) :
    J2 c (restS c.v limits A ([.hid 2 c.n, .hid ρ c.n], coinEx c.n ++ [.hid ρ c.n]))
      (fun st => PP c ρ st ∧ FS c (xrun false c.t (restS c.v limits A ([.hid 2 c.n, .hid ρ c.n],
        coinEx c.n ++ [.hid ρ c.n])) st))
      (GamePost c ρ) := by
  simp only [restS]
  refine J2.revealF (FS c) (fun st hI hp => ?_) (stable_PP ρ) ?_
  · intro i w hm
    simp only [List.mem_cons, SV.hid.injEq, List.not_mem_nil, or_false] at hm
    rcases hm with ⟨rfl, _⟩ | ⟨rfl, _⟩
    · exact safe2_two hI
    · exact hp.1
  refine J2.bindF (FS c) (J2.conseq (j2_play ρ hroot limits _ _ []) (fun st _ hp => ⟨hp.1, ?_⟩)
    (fun _ _ h => h)) (fun out => ?_) (stable_PP ρ)
  · intro m hm
    apply hp.2 m
    rw [xrun_bind, xrun_bind]
    exact hm
  have hs := stable2_and (stable_PP (c := c) ρ)
    (stable_verOpened (c := c) (sres c.t [.hid 2 c.n, .hid ρ c.n]) out.msg out.sig)
  exact J2.conseq (J2.bind' (j2_ext ρ out.msg out.sig hs (fun _ _ hp => hp.1))
    (fun _ => J2.pure' (fun st _ hp => ⟨hp.1.2, hp.2⟩)) hs) (fun _ _ hp => hp.1) (fun _ _ h => h)

end

/-- The run context of the extended game: its final table and signed messages. -/
def secCtx (t : List Nat) (v : Variant) (limits : Limits) (A : Bytes → RAdv) : Ctx :=
  ⟨t, v, (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).1.1.drop 1,
    resD t (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2,
    (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.signed⟩

/-- On a disagreement-free run of the extended game, the secrecy invariant holds at
    the end, every request of the final verification has an open entry, and the
    extension's honest entries are present. -/
theorem sec_game (t : List Nat) (v : Variant) (limits : Limits) (A : Bytes → RAdv)
    (hnd : ∀ s ∈ strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n), dis t s = false) :
    ∃ ρ, (secCtx t v limits A).root = [.hid ρ (params v).n] ∧
      sres t [.hid ρ (params v).n] = xmssNode (secCtx t v limits A).O (params v)
        (expTk (secCtx t v limits A).O v (secCtx t v limits A).e) (expPrf (secCtx t v limits A).O v (secCtx t v limits A).e)
        (expSeed v (secCtx t v limits A).e) {layer := (params v).d-1} 0 (params v).hp ∧
      Inv2 (secCtx t v limits A) (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 ∧
      GamePost (secCtx t v limits A) ρ (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1
        (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2 := by
  have hR : xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) =
      xrun false t (restS v limits A (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).1)
        (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).2 := by
    rw [gameS'_eq, xrun_bind]
  rw [gameS'_eq, strace_bind] at hnd
  have h1 := fun s hs => hnd s (List.mem_append_left _ hs)
  have h2 := fun s hs => hnd s (List.mem_append_right _ hs)
  have hpre : Pre (resD t (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).2)
      (secCtx t v limits A).D := ⟨[], by simp [secCtx]⟩
  have hpre1 := pre_back t (xrun_grow t _ _) (hR ▸ hpre)
  obtain ⟨hI1, -, ρ, itk, hk1, hk2, hsafe, hitk, hrootv⟩ := j2_kgTail (c := secCtx t v limits A)
    (coinSt (params v).n) (inv2_coin _) (by simp [coinSt]) h1 hpre1
  have hroot : (secCtx t v limits A).root = [.hid ρ (params v).n] := by
    exact congrArg (List.drop 1) hk1
  have hK : (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).1 =
      ([.hid 2 (params v).n, .hid ρ (params v).n], coinEx (params v).n ++ [.hid ρ (params v).n]) :=
    Prod.ext hk1 hk2
  rw [hK] at h2 hR
  have hF : FS (secCtx t v limits A) (xrun false t (restS v limits A ([.hid 2 (params v).n, .hid ρ (params v).n],
      coinEx (params v).n ++ [.hid ρ (params v).n])) (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).2) := by
    intro m hm
    show m ∈ (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.signed
    rw [hR]; exact hm
  have hpre2 : Pre (resD t (xrun false t (restS v limits A ([.hid 2 (params v).n, .hid ρ (params v).n],
      coinEx (params v).n ++ [.hid ρ (params v).n])) (xrun false t (sKgTail v (coinEx (params v).n)) (coinSt (params v).n)).2).2)
      (secCtx t v limits A).D := hR ▸ hpre
  obtain ⟨hI, -, hpost⟩ := j2_rest (c := secCtx t v limits A) ρ hroot limits A _ hI1 ⟨⟨hsafe, itk, hitk⟩, hF⟩ h2 hpre2
  refine ⟨ρ, hroot, hrootv, ?_, ?_⟩
  · rw [hR]; exact hI
  · rw [hR]; exact hpost

/-! Values of the honest entries, from the final table. -/

section
variable {c : Ctx}

theorem entry_val {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {h : Nat} {e : Bool × SReq}
    (he : st.ents[h]? = some e) : sres c.t [.hid h e.2.outLen] = c.O (e.2.res c.t) := by
  rw [agree hI hD he]; simp [sres, SV.res]

theorem be_seed : be c.n (c.t.getD 2 0) = expSeed c.v c.e := by
  have := seed_res (c := c); simpa [sres, SV.res] using this

theorem be_tk {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {itk : Nat}
    (h : st.ents[itk]? = some (false, dTk c.n)) : be 32 (c.t.getD itk 0) = expTk c.O c.v c.e := by
  have := entry_val hI hD h
  rw [tk_val] at this; simpa [sres, SV.res, dTk] using this

theorem be_pk {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {ipk : Nat}
    (h : st.ents[ipk]? = some (false, dPrf c.n)) : be 32 (c.t.getD ipk 0) = expPrf c.O c.v c.e := by
  have := entry_val hI hD h
  rw [pk_val] at this; simpa [sres, SV.res, dPrf] using this

theorem prf_val {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {h pk : Nat} {A : Adrs}
    (h1 : st.ents[h]? = some (false, prfReq c.n pk A)) (h2 : st.ents[pk]? = some (false, dPrf c.n)) :
    sres c.t [.hid h c.n] = prf c.O (params c.v) (expPrf c.O c.v c.e) (expSeed c.v c.e) A := by
  have v1 : sres c.t [.hid h c.n] = c.O ((prfReq c.n pk A).res c.t) := entry_val hI hD h1
  rw [v1]
  simp only [prfReq, SReq.res, sres, SV.res, List.append_nil]
  rw [be_pk hI hD h2, be_seed]
  rfl

theorem chReq_res {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {itk h' : Nat} (A : Adrs)
    (hi : st.ents[itk]? = some (false, dTk c.n)) :
    (chReq c.n itk A h').res c.t = thashReq (params c.v) (expTk c.O c.v c.e) A (sres c.t [.hid h' c.n]) := by
  simp only [chReq, SReq.res, sres, SV.res, List.append_nil, thashReq]
  rw [be_tk hI hD hi]

theorem lowAt_val {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) (L T F ci : Nat) :
    ∀ s h, LowAt c.n st h L T F ci s →
      sres c.t [.hid h c.n] = wotsChainValue c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e)
        (expSeed c.v c.e) (wA L T F) ci s
  | 0, h, ⟨pk, h1, h2⟩ => prf_val hI hD h1 h2
  | s+1, h, ⟨itk, h', h1, h2, h3⟩ => by
    have v1 : sres c.t [.hid h c.n] = c.O ((chReq c.n itk (A0 L T F ci s) h').res c.t) := entry_val hI hD h1
    rw [v1, chReq_res hI hD _ h2, lowAt_val hI hD L T F ci s h' h3]
    unfold wotsChainValue
    rw [chain_composes _ _ _ _ _ 0 s 1]
    simp only [chain, Nat.zero_add]
    rfl

theorem fsAt_val {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) {h tree leaf gi : Nat}
    (hf : FsAt c.n st h tree leaf gi) :
    sres c.t [.hid h c.n] = forsSecret c.O (params c.v) (expPrf c.O c.v c.e) (expSeed c.v c.e)
      (forsAdrs tree leaf) gi := by
  obtain ⟨pk, h1, h2⟩ := hf
  exact prf_val hI hD h1 h2

theorem ge3 {st : St} (hI : Inv2 c st) {h : Nat} {r : SReq} (hr : r.mode ≠ 999)
    (he : st.ents[h]? = some (false, r)) : 3 ≤ h := by
  refine Nat.le_of_not_lt (fun hlt => hr ?_)
  rcases h with _ | _ | _ | h
  · rw [hI.1.1] at he; rw [← (Prod.mk.inj (Option.some.inj he)).2]; rfl
  · rw [hI.1.2.1] at he; rw [← (Prod.mk.inj (Option.some.inj he)).2]; rfl
  · rw [hI.1.2.2] at he; rw [← (Prod.mk.inj (Option.some.inj he)).2]; rfl
  · omega

/-- An opened request resolved by an entry past the coins is opened at that entry. -/
theorem opened_at {st : St} (hI : Inv2 c st) {r : Request} (hO : Opened c st r) {h : Nat}
    {e : Bool × SReq} (he : st.ents[h]? = some e) (h3 : 3 ≤ h) (hr : e.2.res c.t = r) :
    isOpen st.rev e.2 = true := by
  obtain ⟨j, e', hj, hres, ho⟩ := hO
  rcases Nat.lt_trichotomy j h with hlt | rfl | hgt
  · exact absurd (hres.trans hr.symm) (hI.2.2.2.1 j h e' e hlt h3 hj he)
  · rw [hj] at he; obtain rfl := Option.some.inj he; exact ho
  · exact absurd (hr.trans hres.symm) (hI.2.2.2.1 h j e e' hgt (by omega) he hj)

theorem fors_digit_lt (p : Params) (md : Bytes) (i : Nat) : forsDigit p md i < 2^p.a := by
  unfold forsDigit
  by_cases hi : i < (base2b md p.a p.k).length
  · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi, Option.getD_some]
    exact base2b_digit_bound md p.a p.k _ (List.getElem_mem hi)
  · rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega), Option.getD_none]
    exact Nat.pos_of_ne_zero (by simp)

theorem digit_unique {B i j d1 d2 : Nat} (h1 : d1 < B) (h2 : d2 < B) (h : i*B + d1 = j*B + d2) :
    i = j ∧ d1 = d2 := by
  have hB : 0 < B := by omega
  have e1 : (i*B + d1) / B = i := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hB, Nat.div_eq_of_lt h1, Nat.zero_add]
  have e2 : (j*B + d2) / B = j := by
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hB, Nat.div_eq_of_lt h2, Nat.zero_add]
  have m1 : (i*B + d1) % B = d1 := by rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt h1]
  have m2 : (j*B + d2) % B = d2 := by rw [Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt h2]
  rw [h] at e1 m1
  exact ⟨e1.symm.trans e2, m1.symm.trans m2⟩

end

/-! The final step: WOTS-preimage and FORS-secret events need a disagreement step. -/

section
variable {c : Ctx}

theorem pk_eq (ρ : Nat) (hrootv : sres c.t [.hid ρ c.n] = xmssNode c.O (params c.v) (expTk c.O c.v c.e)
    (expPrf c.O c.v c.e) (expSeed c.v c.e) {layer := (params c.v).d-1} 0 (params c.v).hp) :
    (keypairFromExpansion c.O c.v c.e).1 = sres c.t [.hid 2 c.n, .hid ρ c.n] := by
  have : (keypairFromExpansion c.O c.v c.e).1 = expSeed c.v c.e ++ sres c.t [.hid ρ c.n] := by
    rw [hrootv]; rfl
  rw [this, ← seed_res]; simp [sres, SV.res]

theorem dig_eq (ρ : Nat) (hpk : (keypairFromExpansion c.O c.v c.e).1 = sres c.t [.hid 2 c.n, .hid ρ c.n])
    (msg sig : Bytes) :
    verifyDigest c.O c.v (keypairFromExpansion c.O c.v c.e).1 msg sig = c.O (extReq c ρ msg sig) := by
  rw [hpk]
  show c.O ⟨2, "DSM/sphincs/v2/h-msg", [], sig.take (params c.v).n ++
    (sres c.t [.hid 2 c.n, .hid ρ c.n]).take (params c.v).n ++
    (sres c.t [.hid 2 c.n, .hid ρ c.n]).drop (params c.v).n ++ msg, (params c.v).m⟩ = _
  rw [List.append_assoc (sig.take _), List.take_append_drop]; rfl

theorem no_wotsPath {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) (ρ : Nat) (msg sig : Bytes)
    (hpk : (keypairFromExpansion c.O c.v c.e).1 = sres c.t [.hid 2 c.n, .hid ρ c.n])
    (hV : ∀ r ∈ verifyLog c.O c.v (sres c.t [.hid 2 c.n, .hid ρ c.n]) msg sig, Opened c st r)
    (hE : ExtPost c (splitDigest (params c.v) (c.O (extReq c ρ msg sig))) st) :
    ¬ WotsPath c.O c.v c.e msg sig := by
  obtain ⟨hlen, hH, hd, _⟩ := variant_bounds c.v
  intro hw
  unfold WotsPath WotsHit at hw
  rw [dig_eq ρ hpk, hpk] at hw
  obtain ⟨k, hk, i, j, hi, hj, hm⟩ := hw
  generalize hI' : splitDigest (params c.v) (c.O (extReq c ρ msg sig)) = I at hm hj hE
  have hj1 : j + 1 ≤ c.dgt k (extT c.v I k) (extF c.v I k) i := hj
  obtain ⟨h1, itk, h', he1, hitk, hlow'⟩ := hE.2 k (List.mem_range.mpr hk) i (List.mem_range.mpr hi) (j+1) hj1
  have hres : (chReq c.n itk (A0 k (extT c.v I k) (extF c.v I k) i j) h').res c.t =
      thashReq (params c.v) (expTk c.O c.v c.e)
        {({wA k (extT c.v I k) (extF c.v I k) with chain := i} : Adrs) with hash := j}
        (wotsChainValue c.O (params c.v) (expTk c.O c.v c.e) (expPrf c.O c.v c.e) (expSeed c.v c.e)
          (wA k (extT c.v I k) (extF c.v I k)) i j) := by
    rw [chReq_res hI hD _ hitk, lowAt_val hI hD _ _ _ _ j h' hlow']; rfl
  have ho := opened_at hI (hV _ hm) he1 (ge3 hI (by simp [chReq]) he1) hres
  have hrev : h' ∈ st.rev := open_mem ho h' (by simp [chReq, SReq.hids, shids])
  have hT : extT c.v I k < 256^8 := Nat.lt_of_le_of_lt
    (ext_tree_le c.v I.tree I.leaf k (hI' ▸ split_leaf_lt c.v _)) (hI' ▸ split_tree_lt c.v _)
  have hF : extF c.v I k < 256^4 := Nat.lt_of_lt_of_le (Nat.mod_lt _ (Nat.two_pow_pos _)) hH
  have h15 := dgt_le15 (c := c) k (extT c.v I k) (extF c.v I k) i
  exact not_rev_low hI ⟨k, _, _, i, j, ⟨by omega, hT, hF, by omega, by omega⟩, hj, hlow'⟩ hrev

theorem e_slices (X : Bytes) :
    slice (c.e ++ X) c.n c.n = be c.n (c.t.getD 1 0) ∧ slice (c.e ++ X) (2*c.n) c.n = be c.n (c.t.getD 2 0) ∧
      (c.e ++ X).drop (3*c.n) = X := by
  have hA := be_width c.n (c.t.getD 0 0)
  have hB := be_width c.n (c.t.getD 1 0)
  have hC := be_width c.n (c.t.getD 2 0)
  have he : c.e = be c.n (c.t.getD 0 0) ++ (be c.n (c.t.getD 1 0) ++ (be c.n (c.t.getD 2 0) ++ [])) :=
    coin_res _ _
  rw [he]
  simp only [slice, List.append_nil, List.append_assoc]
  refine ⟨?_, ?_, ?_⟩
  · rw [List.drop_left' hA, List.take_left' hB]
  · rw [show 2*c.n = c.n + c.n by omega, ← List.drop_drop, List.drop_left' hA, List.drop_left' hB,
      List.take_left' hC]
  · rw [show 3*c.n = c.n + (c.n + c.n) by omega, ← List.drop_drop, ← List.drop_drop, List.drop_left' hA,
      List.drop_left' hB, List.drop_left' hC]

theorem sign_digest {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) (ρ : Nat)
    (hroot : c.root = [.hid ρ c.n])
    (hrootv : sres c.t [.hid ρ c.n] = xmssNode c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (expSeed c.v c.e) {layer := (params c.v).d-1} 0 (params c.v).hp)
    {k iR dk : Nat} {m : Bytes} {e : Bool × SReq}
    (hiR : st.ents[iR]? = some (false, rqOf c.n dk m)) (hdk : st.ents[dk]? = some (false, dReq c.n))
    (hek : st.ents[k]? = some e) (hres : e.2.res c.t = (hqOf c.n c.pm c.root iR m).res c.t) :
    signDigest c.O c.v (keypairFromExpansion c.O c.v c.e).2 m = be c.pm (c.t.getD k 0) := by
  have h1 := agree hI hD hek
  have hl : e.2.outLen = c.pm := by
    have := congrArg Request.outLen hres; simpa [SReq.res, hqOf] using this
  have hsk : (keypairFromExpansion c.O c.v c.e).2 = c.e ++ sres c.t [.hid ρ c.n] := by rw [hrootv]; rfl
  obtain ⟨s1, s2, s3⟩ := e_slices (c := c) (sres c.t [.hid ρ c.n])
  have vR : be c.n (c.t.getD iR 0) = keyed c.O c.n (deriveKey c.O "DSM/sphincs/v2/prf-msg"
      (be c.n (c.t.getD 1 0))) (be c.n (c.t.getD 2 0) ++ m) := by
    have v1 := entry_val hI hD hiR
    have v2 := entry_val hI hD hdk
    simp only [rqOf, dReq, SReq.res, sres, SV.res, List.append_nil] at v1 v2
    rw [v1, v2]; rfl
  unfold signDigest
  rw [hsk, s1, s2, s3, ← hl, ← h1, hres, hroot]
  simp only [hqOf, SReq.res, sres, SV.res, List.append_nil, List.cons_append, List.nil_append]
  rw [vR]
  simp only [hmsg, List.append_assoc]

theorem no_forsPath {st : St} (hI : Inv2 c st) (hD : Pre (resD c.t st) c.D) (ρ : Nat)
    (hroot : c.root = [.hid ρ c.n])
    (hrootv : sres c.t [.hid ρ c.n] = xmssNode c.O (params c.v) (expTk c.O c.v c.e)
      (expPrf c.O c.v c.e) (expSeed c.v c.e) {layer := (params c.v).d-1} 0 (params c.v).hp)
    (msg sig : Bytes)
    (hV : ∀ r ∈ verifyLog c.O c.v (sres c.t [.hid 2 c.n, .hid ρ c.n]) msg sig, Opened c st r)
    (hE : ExtPost c (splitDigest (params c.v) (c.O (extReq c ρ msg sig))) st) :
    ¬ ForsPath c.O c.v c.e msg sig c.Sg := by
  obtain ⟨_, hH, _, _, _, _⟩ := variant_bounds c.v
  have hpk := pk_eq ρ hrootv
  intro hf
  unfold ForsPath at hf
  rw [dig_eq ρ hpk, hpk] at hf
  obtain ⟨i, hi, hnrev, hm⟩ := hf
  generalize hI' : splitDigest (params c.v) (c.O (extReq c ρ msg sig)) = I at hnrev hm hE
  have hd := fors_digit_lt (params c.v) I.md i
  obtain ⟨w, hl, hs, itk, -, hfs, hitk, hor⟩ := hE.1 i (List.mem_range.mpr hi)
  have hsrev : hs ∈ st.rev := by
    rcases hor with h | hent
    · exact h
    · have hres : (chReq c.n itk (flA I.tree I.leaf (i*2^(params c.v).a + forsDigit (params c.v) I.md i)) hs).res c.t =
          thashReq (params c.v) (expTk c.O c.v c.e)
            {forsAdrs I.tree I.leaf with chain := 0, hash := i*2^(params c.v).a + forsDigit (params c.v) I.md i}
            (forsSecret c.O (params c.v) (expPrf c.O c.v c.e) (expSeed c.v c.e) (forsAdrs I.tree I.leaf)
              (i*2^(params c.v).a + forsDigit (params c.v) I.md i)) := by
        rw [chReq_res hI hD _ hitk, fsAt_val hI hD hfs]; rfl
      have ho := opened_at hI (hV _ hm) hent (ge3 hI (by simp [chReq]) hent) hres
      exact open_mem ho hs (by simp [chReq, SReq.hids, shids])
  have hsafe := hI.2.2.2.2.1 hs hsrev
  have hgi : i*2^(params c.v).a + forsDigit (params c.v) I.md i < 256^4 := by
    obtain ⟨_, _, _, hka, _, _⟩ := variant_bounds c.v
    have : (i+1)*2^(params c.v).a ≤ (params c.v).k*2^(params c.v).a := Nat.mul_le_mul_right _ hi
    rw [Nat.add_mul, Nat.one_mul] at this; omega
  obtain ⟨k', m, ⟨iR, dk, e, hmS, hiR, hdk, hek, hres⟩, hsel⟩ :=
    hsafe.2.2.1 I.tree I.leaf _ ⟨hI' ▸ split_tree_lt c.v _,
      Nat.lt_of_lt_of_le (hI' ▸ split_leaf_lt c.v _) hH, hgi⟩ hfs
  apply hnrev
  refine ⟨m, hmS, ?_⟩
  rw [sign_digest hI hD ρ hroot hrootv hiR hdk hek hres]
  obtain ⟨ht, hl', j, _, hgj⟩ := hsel
  have hd' := fors_digit_lt (params c.v) (splitDigest (params c.v) (be c.pm (c.t.getD k' 0))).md j
  obtain ⟨rfl, hdd⟩ := digit_unique hd hd' hgj
  exact ⟨ht, hl', hdd.symm⟩

end

/-! On the real run. -/

/-- Outside a disagreement step of the extended game, the forged WOTS chain value
    and the forged FORS secret events do not occur (on the extended run's table). -/
theorem no_paths (v : Variant) (limits : Limits) (A : Bytes → RAdv) (t : List Nat)
    (hnd : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = false) :
    ¬ WotsPath (finO' v limits A t) v (sres t (coinEx (params v).n)) (runG v limits A t).1.msg
        (runG v limits A t).1.sig ∧
      ¬ ForsPath (finO' v limits A t) v (sres t (coinEx (params v).n)) (runG v limits A t).1.msg
        (runG v limits A t).1.sig (runG v limits A t).1.signed := by
  have hnd' : ∀ s ∈ strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n),
      dis t s = false := by
    simp only [anyDis, List.any_eq_false] at hnd
    intro s hs; simpa using hnd s hs
  have hcp := coupling t _ _ hnd'
  obtain ⟨hrel, hdr⟩ := sim_game' (t := t) v limits A (coinSt (params v).n)
  rw [hcp] at hrel hdr
  have h1 : (runG v limits A t).1 = (xrun false t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).1 := by
    rw [← out_ext]; exact hrel.symm
  have hO : finO' v limits A t = (secCtx t v limits A).O := by
    show oracleOf t (runG' v limits A t).2 = _
    rw [show (runG' v limits A t).2 = _ from hdr]; rfl
  obtain ⟨ρ, hroot, hrootv, hI, hV, hE⟩ := sec_game t v limits A hnd'
  have hD : Pre (resD (secCtx t v limits A).t (xrun false t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n)).2) (secCtx t v limits A).D := ⟨[], by simp [secCtx]⟩
  rw [hO, h1]
  exact ⟨no_wotsPath hI hD ρ _ _ (pk_eq ρ hrootv) hV hE, no_forsPath hI hD ρ hroot hrootv _ _ hV hE⟩

/-- Path-located extraction with the secrecy step: a win is a canonical collision, an
    ITSR-covered digest, or a disagreement step of the extended game. -/
theorem rom_extract_sec (v : Variant) (limits : Limits) (A : Bytes → RAdv) (t : List Nat)
    (hw : (runG v limits A t).1.win = true) :
    CanonCollIn (finO' v limits A t) (params v) (expTk (finO' v limits A t) v (sres t (coinEx (params v).n)))
        (expPrf (finO' v limits A t) v (sres t (coinEx (params v).n))) (expSeed v (sres t (coinEx (params v).n)))
        (verifyLog (finO' v limits A t) v (finKey v limits A t).1 (runG v limits A t).1.msg
          (runG v limits A t).1.sig) ∨
      CoveredBy (finO' v limits A t) v (finKey v limits A t).2 (runG v limits A t).1.signed
        (splitDigest (params v) (verifyDigest (finO' v limits A t) v (finKey v limits A t).1
          (runG v limits A t).1.msg (runG v limits A t).1.sig)) ∨
      anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t = true := by
  rcases rom_extract_ext v limits A t hw with h | h | h | h
  · exact Or.inl h
  · cases hd : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t
    · exact absurd h (no_paths v limits A t hd).1
    · exact Or.inr (Or.inr rfl)
  · cases hd : anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t
    · exact absurd h (no_paths v limits A t hd).2
    · exact Or.inr (Or.inr rfl)
  · exact Or.inr (Or.inl h)
end DSM.Rom
