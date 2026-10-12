-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomKey

/- The wide-pin count.

   For SPHINCS+-256f every handle is 32 bytes wide, so the narrow/wide split of
   `hidden_bound_splitP` prices every pin at `2^-256`, and the trivial bound
   `B_hi ≤ S^2` is the dominant loss. Here every pin is classified.

   A probe at a challenger step can compare a hidden PRF or randomizer entry with an
   open thash request (or the reverse): the two are syntactically compatible when the
   thash input happens to end in the PRF literal. Such a probe pins the PRF or PRF-msg
   key against the tweak key's value, so a hit is a key collision (`KeyColl`). These
   probes are excluded from the count by a tape-free filter `Ψ` and charged to
   `KeyColl` instead (`hidden_bound_Q`). Every other probe involves an adversary draw:
   at most six per adversary step and at most three per adversary entry. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

/-! The hidden-value bound with a probe filter, in one width class. -/

section
variable {α : Type} (wmin : Nat) (Φ : St × Ev → Bool) (Ψ : St × Ev → Nat → Bool) (P : Prog α) (st0 : St)

/-- Probe at step `s`, entry `j`: eligible steps satisfying `Φ`, entries outside `Ψ`. -/
def probeQ (t : List Nat) (s j : Nat) : Option (Nat × Nat × Nat) :=
  ((strace t P st0)[s]?).bind (fun stp =>
    if (elig t stp && Φ stp && !Ψ stp j) = true then probeAtW wmin t stp j else none)

theorem probeQ_inv (t : List Nat) (s j : Nat) (v : Nat × Nat × Nat) (y : Nat)
    (hp : probeQ wmin Φ Ψ P st0 t s j = some v) : probeQ wmin Φ Ψ P st0 (t.set v.1 y) s j = some v := by
  unfold probeQ at hp ⊢
  cases hs : (strace t P st0)[s]? with
  | none => rw [hs] at hp; cases hp
  | some stp =>
    rw [hs] at hp
    simp only [Option.bind_some] at hp
    by_cases he : (elig t stp && Φ stp && !Ψ stp j) = true
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

theorem probeQ_back (t : List Nat) (s j h y : Nat) (v : Nat × Nat × Nat) (hv : v.1 = h)
    (hp : probeQ wmin Φ Ψ P st0 (t.set h y) s j = some v) : probeQ wmin Φ Ψ P st0 t s j = some v := by
  have := probeQ_inv wmin Φ Ψ P st0 (t.set h y) s j v (t.getD h 0) hp
  rwa [hv, set_set_back] at this

def wtQ (t : List Nat) (i : Nat × Nat × Nat) : Nat :=
  if (probeQ wmin Φ Ψ P st0 t i.1 i.2.1).map Prod.fst = some i.2.2 then 1 else 0

def tgQ (i : Nat × Nat × Nat) (t : List Nat) : Nat :=
  ((probeQ wmin Φ Ψ P st0 t i.1 i.2.1).map (fun v => v.2.2)).getD 0

theorem wtQ_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) :
    wtQ wmin Φ Ψ P st0 (t.set i.2.2 y) i = wtQ wmin Φ Ψ P st0 t i := by
  unfold wtQ
  by_cases ha : (probeQ wmin Φ Ψ P st0 t i.1 i.2.1).map Prod.fst = some i.2.2
  · rw [if_pos ha]
    cases hp : probeQ wmin Φ Ψ P st0 t i.1 i.2.1 with
    | none => rw [hp] at ha; cases ha
    | some v =>
      rw [hp] at ha
      have hv : v.1 = i.2.2 := Option.some.inj ha
      have := probeQ_inv wmin Φ Ψ P st0 t i.1 i.2.1 v y hp
      rw [hv] at this
      rw [this, if_pos ha]
  · rw [if_neg ha, if_neg]
    intro hb
    apply ha
    cases hp : probeQ wmin Φ Ψ P st0 (t.set i.2.2 y) i.1 i.2.1 with
    | none => rw [hp] at hb; cases hb
    | some v =>
      rw [hp] at hb
      have hv : v.1 = i.2.2 := Option.some.inj hb
      rw [probeQ_back wmin Φ Ψ P st0 t i.1 i.2.1 i.2.2 y v hv hp]
      exact hb

theorem tgQ_inv (i : Nat × Nat × Nat) (t : List Nat) (y : Nat) (hw : wtQ wmin Φ Ψ P st0 t i ≠ 0) :
    tgQ wmin Φ Ψ P st0 i (t.set i.2.2 y) = tgQ wmin Φ Ψ P st0 i t := by
  unfold wtQ at hw
  unfold tgQ
  cases hp : probeQ wmin Φ Ψ P st0 t i.1 i.2.1 with
  | none => rw [hp] at hw; simp at hw
  | some v =>
    rw [hp] at hw
    have hv : v.1 = i.2.2 := by
      by_cases hne : v.1 = i.2.2
      · exact hne
      · exfalso; apply hw; simp [hne]
    have := probeQ_inv wmin Φ Ψ P st0 t i.1 i.2.1 v y hp
    rw [hv] at this
    rw [this]

/-- The number of (step, entry) pairs below `S` carrying a counted probe. -/
def pairCountQ (S : Nat) (t : List Nat) : Nat :=
  ((List.range S).map (fun s => ((List.range S).map (fun j =>
    if (probeQ wmin Φ Ψ P st0 t s j).isSome then 1 else 0)).sum)).sum

theorem idxQ_sum_le (S N : Nat) (t : List Nat) :
    ((idx S N).map (fun i => wtQ wmin Φ Ψ P st0 t i)).sum ≤ pairCountQ wmin Φ Ψ P st0 S t := by
  unfold idx pairCountQ
  rw [sum_flatMap]
  apply sum_map_le; intro s _
  rw [sum_flatMap]
  apply sum_map_le; intro j _
  have h := sum_pin N ((probeQ wmin Φ Ψ P st0 t s j).map (fun v => (v.1, 0)))
  simp only [Option.map_map, Function.comp_def, Option.isSome_map] at h
  refine Nat.le_trans (Nat.le_of_eq ?_) h
  rw [List.map_map]
  rfl

/-- Pointwise: a disagreement is a counted probe that hits, a `Ψ`-probe that hits (then
    `E` holds), a wild guess or collision, or an initial collision. -/
theorem dis_pointQ (E : List Nat → Prop) (S N : Nat)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true)
    (hΨ : ∀ t s stp j e XY, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Ψ stp j = true → stp.1.ents[j]? = some e → cand t stp.1 stp.2 e = some XY → XY.1.res t = XY.2 → E t)
    (t : List Nat) :
    (if anyDis P st0 t then 1 else 0) ≤
      ((idx S N).map (fun i => wtQ wmin Φ Ψ P st0 t i *
        (if t.getD i.2.2 0 % 256^wmin == tgQ wmin Φ Ψ P st0 i t % 256^wmin then 1 else 0))).sum +
      (if wildCollP wmin P st0 N t || initColl t st0 then 1 else 0) + ind (E t) := by
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
      obtain ⟨e, he, hk⟩ := dis_entry t stp.1 stp.2 hd
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp he
      have hwe := wildP_at wmin P st0 N t s stp hs hfirst hw
      have hwe' := hwe e he
      rcases hk with ⟨XY, hc, hres⟩ | hcoll
      · by_cases hψ : Ψ stp j = true
        · rw [ind_of (hΨ t s stp j e XY hs hfirst hψ hj hc hres)]; omega
        have hel' : (elig t stp && Φ stp && !Ψ stp j) = true := by
          rw [hel]; simp [hψ]
        have hno := cand_not_open t stp.1 stp.2 e XY hc
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
        have hp : probeQ wmin Φ Ψ P st0 t s j = some (v.1, v.2.1,
            toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1)) := by
          simp only [probeQ, hs, Option.bind_some, hel', if_true, hpa]
        have hpin := guess_pins t stp.1.rev XY.1 XY.2 v hres hv
        have hbound := hS t s stp hs
        have hjlt : j < stp.1.ents.length := (List.getElem?_eq_some_iff.mp hj).1
        have hmem : (s, j, v.1) ∈ idx S N := by
          simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map]
          exact ⟨s, hbound.1, j, by omega, v.1, hwild.2, rfl⟩
        have hdvd : 256^wmin ∣ 256^v.2.1 := Nat.pow_dvd_pow 256 hwild.1
        have hmod : t.getD v.1 0 % 256^wmin =
            toInt (slice (if v.2.2.1 then XY.2.key else XY.2.input) v.2.2.2 v.2.1) % 256^wmin := by
          rw [← Nat.mod_mod_of_dvd _ hdvd, hpin, Nat.mod_mod_of_dvd _ hdvd]
        have hterm : wtQ wmin Φ Ψ P st0 t (s, j, v.1) *
            (if t.getD (s, j, v.1).2.2 0 % 256^wmin == tgQ wmin Φ Ψ P st0 (s, j, v.1) t % 256^wmin
              then 1 else 0) = 1 := by
          simp only [wtQ, tgQ, hp, Option.map_some, Option.getD_some, hmod]
          simp
        have := le_sum_of_mem (List.mem_map.mpr ⟨(s, j, v.1), hmem, hterm⟩ :
          1 ∈ (idx S N).map (fun i => wtQ wmin Φ Ψ P st0 t i *
            (if t.getD i.2.2 0 % 256^wmin == tgQ wmin Φ Ψ P st0 i t % 256^wmin then 1 else 0)))
        omega
      · exfalso; exact hwe' (Or.inl hcoll)
    · rw [if_pos rfl]; omega

/-- Hidden-value bound with a probe filter: counted probes cost `1/256^wmin` each, and a
    hit of a filtered probe is the event `E`. -/
theorem hidden_bound_Q (E : List Nat → Prop) (R N S B : Nat) (hR : 256^wmin ∣ R)
    (hS : ∀ t s stp, (strace t P st0)[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hΦ : ∀ t s stp, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Φ stp = true)
    (hΨ : ∀ t s stp j e XY, (strace t P st0)[s]? = some stp →
      (∀ (s' : Nat) (stp' : St × Ev), s' < s → (strace t P st0)[s']? = some stp' → dis t stp' = false) →
      Ψ stp j = true → stp.1.ents[j]? = some e → cand t stp.1 stp.2 e = some XY → XY.1.res t = XY.2 → E t)
    (hB : ∀ t, pairCountQ wmin Φ Ψ P st0 S t ≤ B) :
    tsum R N (fun t => if anyDis P st0 t then 1 else 0) * 256^wmin ≤
      R^N * B + tsum R N (fun t => if wildCollP wmin P st0 N t || initColl t st0 then 1 else 0) * 256^wmin +
        tsum R N (fun t => ind (E t)) * 256^wmin := by
  have hM : 0 < 256^wmin := Nat.pow_pos (by decide)
  have hix : ∀ i ∈ idx S N, i.2.2 < N := fun i hi => by
    simp only [idx, List.mem_flatMap, List.mem_range, List.mem_map] at hi
    obtain ⟨_, _, _, _, h, hh, rfl⟩ := hi
    exact hh
  have hh := hits_sum R (256^wmin) N hM hR (idx S N) (fun i => i.2.2) hix
    (fun i t => wtQ wmin Φ Ψ P st0 t i) (tgQ wmin Φ Ψ P st0)
    (fun i _ t y => wtQ_inv wmin Φ Ψ P st0 i t y)
    (fun i _ t y hw => tgQ_inv wmin Φ Ψ P st0 i t y hw)
  have hs : tsum R N (fun t => ((idx S N).map (fun i => wtQ wmin Φ Ψ P st0 t i)).sum) ≤ R^N * B := by
    rw [← tsum_const]; exact tsum_mono R N (fun t => Nat.le_trans (idxQ_sum_le wmin Φ Ψ P st0 S N t) (hB t))
  have hpt := tsum_mono R N (dis_pointQ wmin Φ Ψ P st0 E S N hS hΦ hΨ)
  rw [tsum_add, tsum_add] at hpt
  calc _ ≤ (_ + _ + _) * 256^wmin := Nat.mul_le_mul_right _ hpt
    _ = _ * 256^wmin + _ * 256^wmin + _ * 256^wmin := by rw [Nat.add_mul, Nat.add_mul]
    _ ≤ _ := Nat.add_le_add (Nat.add_le_add (Nat.le_trans hh hs) (Nat.le_refl _)) (Nat.le_refl _)

end

/-! The step predicate and the filter for H1'. -/

section
variable (v : Variant)

/-- Entry `k` is the PRF-key or the PRF-msg-key derivation. -/
def KeyIdx (st : St) (k : Nat) : Prop :=
  st.ents[k]? = some (false, dPrf (params v).n) ∨ st.ents[k]? = some (false, dReq (params v).n)

/-- `Φ` for the wide count: `PhiP`, challenger requests are entries at most once past the
    coins, and PRF-shaped requests are keyed by the PRF key or the PRF-msg key. -/
def PhiW (stp : St × Ev) : Prop :=
  PhiP v stp ∧
  (∀ (a b : Nat) (r : SReq), 3 ≤ a → 3 ≤ b → stp.1.ents[a]? = some (false, r) →
    stp.1.ents[b]? = some (false, r) → a = b) ∧
  (∀ (j k : Nat) (m : Bytes), 3 ≤ j →
    stp.1.ents[j]? = some (false, ⟨1, "", [.hid k 32], [.hid 2 (params v).n, .lit m], (params v).n⟩) →
    KeyIdx v stp.1 k) ∧
  (∀ (k : Nat) (m : Bytes), stp.2 = .c ⟨1, "", [.hid k 32], [.hid 2 (params v).n, .lit m], (params v).n⟩ →
    KeyIdx v stp.1 k)

noncomputable def phiW (stp : St × Ev) : Bool := @decide (PhiW v stp) (Classical.propDecidable _)

theorem phiW_true {stp : St × Ev} (h : phiW v stp = true) : PhiW v stp := by simpa [phiW] using h

/-- A challenger step comparing a PRF-shaped request with a thash-shaped one. -/
def KeyTh (stp : St × Ev) (j : Nat) : Prop :=
  ∃ r er, stp.2 = .c r ∧ stp.1.ents[j]? = some (false, er) ∧
    ((IsPR (params v).n er ∧ IsTh (params v).n r) ∨ (IsPR (params v).n r ∧ IsTh (params v).n er))

noncomputable def psiB (stp : St × Ev) (j : Nat) : Bool := @decide (KeyTh v stp j) (Classical.propDecidable _)

end

section
variable {c : Ctx}

/-- A PRF-shaped DSM request is keyed by the PRF key or the PRF-msg key. -/
theorem famOK_pr {st : St} {k : Nat} {m : Bytes}
    (hF : FamOK c st ⟨1, "", [.hid k 32], [.hid 2 c.n, .lit m], c.n⟩) :
    st.ents[k]? = some (false, dPrf c.n) ∨ st.ents[k]? = some (false, dReq c.n) := by
  obtain ⟨k', hk', hc⟩ := famOK_mode1 hF rfl
  simp only [List.cons.injEq, SV.hid.injEq, and_true] at hk'
  subst hk'
  rcases hc with ⟨_, d, A, hs⟩ | ⟨h, _⟩ | ⟨h, _⟩
  · obtain ⟨_, _, he, _, _⟩ := structReq_shape hs
    simp only [SReq.mk.injEq, List.cons.injEq] at he
    obtain ⟨_, _, _, ⟨h1, _⟩, _⟩ := he
    cases h1
  · exact Or.inl h
  · exact Or.inr h

/-- A thash-shaped DSM request is keyed by the tweak key. -/
theorem famOK_thK {st : St} {r : SReq} (hF : FamOK c st r) (hr : IsTh c.n r) :
    ∃ itk, r.key = [.hid itk 32] ∧ st.ents[itk]? = some (false, dTk c.n) := by
  obtain ⟨itk, b, hs, rfl, _, _⟩ := hr
  obtain ⟨k', hk', hc⟩ := famOK_mode1 hF rfl
  refine ⟨itk, rfl, ?_⟩
  simp only [List.cons.injEq, SV.hid.injEq, and_true] at hk'
  subst hk'
  rcases hc with ⟨h, _⟩ | ⟨_, A, he, _⟩ | ⟨_, m, he⟩
  · exact h
  · simp only [prfReq, SReq.mk.injEq, List.cons.injEq] at he
    obtain ⟨_, _, _, ⟨h1, _⟩, _⟩ := he
    cases h1
  · simp only [rqOf, SReq.mk.injEq, List.cons.injEq] at he
    obtain ⟨_, _, _, ⟨h1, _⟩, _⟩ := he
    cases h1

theorem phiW_of (ρ : Nat) (hroot : c.root = [.hid ρ c.n]) {st : St} {ev : Ev} (hI : InvS c st)
    (hS : StepOK c (st, ev)) : PhiW c.v (st, ev) := by
  refine ⟨phi_of ρ hroot hI hS, ?_, ?_, ?_⟩
  · intro a b r ha hb hea heb
    rcases hI.2.2.2.1 a r hea with h | hF
    · omega
    exact idx_eq_of_res hI hea heb rfl (by rw [res_mode]; exact goodFam_mode (famOK_good ρ hroot hI hF))
  · intro j k m hj he
    rcases hI.2.2.2.1 j _ he with h | hF
    · omega
    exact famOK_pr hF
  · intro k m hev
    simp only at hev
    subst hev
    exact famOK_pr (show FamOK c st _ from hS)

end

theorem cand_c (t : List Nat) (st : St) (r : SReq) (e : Bool × SReq) (XY : SReq × Request)
    (h : cand t st (.c r) e = some XY) : (XY.1 = r ∧ XY.2 = e.2.res t) ∨ (XY.1 = e.2 ∧ XY.2 = r.res t) := by
  simp only [cand] at h
  split at h
  · cases h
  · split at h
    · split at h
      · cases h
      · obtain rfl := Option.some.inj h; exact Or.inl ⟨rfl, rfl⟩
    · split at h
      · obtain rfl := Option.some.inj h; exact Or.inr ⟨rfl, rfl⟩
      · cases h

section
variable (v : Variant) (limits : Limits) (A : Bytes → RAdv)

theorem game_phiW (t : List Nat) (s : Nat) (stp : St × Ev)
    (hs : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp)
    (hnd : ∀ (s' : Nat) (stp' : St × Ev), s' < s →
      (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s']? = some stp' → dis t stp' = false) :
    phiW v stp = true := by
  obtain ⟨ρ, hρ⟩ := kg_root_shape t v
  obtain ⟨hI, hSt⟩ := game_struct (c := structCtx t v) rfl limits A s stp hs hnd
  obtain ⟨st, ev⟩ := stp
  have h := phiW_of (c := structCtx t v) ρ hρ hI hSt
  simpa [phiW] using h

/-- Two key entries of a step state with no earlier disagreement and agreeing
    coordinates are a `KeyColl`. -/
theorem keyColl_of_step (t : List Nat) (s : Nat) (stp : St × Ev)
    (hs : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp)
    (hnd : ∀ (s' : Nat) (stp' : St × Ev), s' < s →
      (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s']? = some stp' → dis t stp' = false)
    {a b : Nat} (hk : KeyEnts (params v).n stp.1 a b) (hm : t.getD a 0 % 256^32 = t.getD b 0 % 256^32) :
    KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
  obtain ⟨hab, ⟨x1, hx1, ha⟩, ⟨y1, hy1, hb⟩⟩ := hk
  obtain ⟨L, hL⟩ := trace_final t _ _ s _ hs
  have hbl : b < stp.1.ents.length := lt_entry hb
  have hfin : KeyEnts (params v).n (xrun false t (gameS' v limits A (coinEx (params v).n))
      (coinSt (params v).n)).2 a b := by
    refine ⟨hab, ⟨x1, hx1, ?_⟩, ⟨y1, hy1, ?_⟩⟩
    · rw [hL, List.getElem?_append_left (lt_entry ha)]; exact ha
    · rw [hL, List.getElem?_append_left hbl]; exact hb
  refine keyColl_of_fin v limits A t hfin hm (fun s' stp' hs' hl' => ?_)
  have hlt : s' < s := by
    apply Nat.lt_of_not_le
    intro hge
    have := len_mono _ _ t hge hs hs'
    omega
  exact fun s'' stp'' h'' hs'' => hnd s'' stp'' (by omega) hs''

/-- A filtered probe that hits is a key collision. -/
theorem game_keyTh (t : List Nat) (s : Nat) (stp : St × Ev) (j : Nat) (e : Bool × SReq) (XY : SReq × Request)
    (hs : (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp)
    (hnd : ∀ (s' : Nat) (stp' : St × Ev), s' < s →
      (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s']? = some stp' → dis t stp' = false)
    (hψ : psiB v stp j = true) (he : stp.1.ents[j]? = some e) (hc : cand t stp.1 stp.2 e = some XY)
    (hres : XY.1.res t = XY.2) :
    KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
  have hK : KeyTh v stp j := by simpa [psiB] using hψ
  obtain ⟨r, er, hr, hj, hsh⟩ := hK
  obtain ⟨hI, hSt⟩ := game_struct (c := structCtx t v) rfl limits A s stp hs hnd
  rw [hj] at he
  obtain rfl := Option.some.inj he
  obtain ⟨st, ev⟩ := stp
  simp only at hr hj hc
  subst hr
  have hF : FamOK (structCtx t v) st r := hSt
  have hFe : FamOK (structCtx t v) st er := by
    rcases hI.2.2.2.1 j er hj with h | h
    · exfalso
      have hm : er.mode = 1 := by
        rcases hsh with ⟨⟨k, m, rfl⟩, _⟩ | ⟨_, ⟨itk, b, hs', rfl, _⟩⟩ <;> rfl
      rcases j with _ | _ | _ | j
      · rw [hI.1.1] at hj; obtain ⟨⟩ := hj; simp [coin] at hm
      · rw [hI.1.2.1] at hj; obtain ⟨⟩ := hj; simp [coin] at hm
      · rw [hI.1.2.2] at hj; obtain ⟨⟩ := hj; simp [coin] at hm
      · omega
    · exact h
  -- the two requests resolve equally
  have heq : er.res t = r.res t := by
    rcases cand_c t st r (false, er) XY hc with ⟨h1, h2⟩ | ⟨h1, h2⟩
    · rw [h1, h2] at hres; exact hres.symm
    · rw [h1, h2] at hres; exact hres
  have hkey := congrArg Request.key heq
  -- the PRF-shaped one is keyed by k, the thash-shaped one by itk
  have main : ∀ (X T : SReq), FamOK (structCtx t v) st X → FamOK (structCtx t v) st T →
      IsPR (params v).n X → IsTh (params v).n T → (X.res t).key = (T.res t).key →
      KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t := by
    intro X T hFX hFT hX hT hk
    obtain ⟨k, m, rfl⟩ := hX
    have hki := famOK_pr hFX
    obtain ⟨itk, hitk, hit⟩ := famOK_thK hFT hT
    have hk' : be 32 (t.getD k 0) = be 32 (t.getD itk 0) := by
      simp only [SReq.res, hitk, sres_key32] at hk
      exact hk
    have hm := be_eq_mod hk'
    have hne : k ≠ itk := by
      intro h; subst h
      rcases hki with h | h <;> rw [h] at hit <;> simp [dPrf, dReq, dTk] at hit
    have hkx : ∃ x ∈ keyReqs (params v).n, st.ents[k]? = some (false, x) := by
      rcases hki with h | h
      · exact ⟨_, dPrf_key _, h⟩
      · exact ⟨_, dReq_key _, h⟩
    have hix : ∃ x ∈ keyReqs (params v).n, st.ents[itk]? = some (false, x) := ⟨_, dTk_key _, hit⟩
    rcases Nat.lt_or_gt_of_ne hne with hl | hl
    · exact keyColl_of_step v limits A t s _ hs hnd ⟨hl, hkx, hix⟩ hm
    · exact keyColl_of_step v limits A t s _ hs hnd ⟨hl, hix, hkx⟩ hm.symm
  rcases hsh with ⟨hX, hT⟩ | ⟨hX, hT⟩
  · exact main er r hFe hF hX hT hkey
  · exact main r er hF hFe hX hT hkey.symm

end

/-! Classifying the counted probes. -/

theorem goodFam_lo_pr {n pm : Nat} {rev : List Nat} {r : SReq} (h : GoodFam n pm rev r) :
    LoShape n pm r ∨ IsPR n r := by
  rcases h with h | ⟨k, m, rfl, _⟩
  · exact Or.inl h
  · exact Or.inr ⟨k, m, rfl⟩

theorem lo_mode_ne1 {n pm : Nat} {r : SReq} (h : LoShape n pm r) (hn : ¬ IsTh n r) : r.mode ≠ 1 := by
  rcases h with h | hD | ⟨_, _, _, rfl⟩
  · exact absurd h hn
  · rcases hD with rfl | rfl | rfl <;> simp [dTk, dPrf, dReq]
  · simp

theorem pr_mode {n : Nat} {r : SReq} (h : IsPR n r) : r.mode = 1 := by
  obtain ⟨_, _, rfl⟩ := h; rfl

/-- A counted probe at a `Φ_W`-step outside `Ψ` is charged at an adversary step against a
    challenger entry (a coin, a narrow-shaped entry or a PRF-shaped entry compatible with the
    query), or at a challenger step against an adversary entry. -/
theorem pin_class_w (v : Variant) (t : List Nat) {stp : St × Ev} (hΦ : PhiW v stp) {j : Nat}
    (hψ : ¬ KeyTh v stp j) {e : Bool × SReq} (he : stp.1.ents[j]? = some e) {XY : SReq × Request}
    (hc : cand t stp.1 stp.2 e = some XY) (hcomp : compat XY.1 XY.2 = true) :
    (∃ q, stp.2 = .a q ∧ e.1 = false ∧ (j < 3 ∨ (3 ≤ j ∧ (LoShape (params v).n (params v).m e.2 ∨
      IsPR (params v).n e.2) ∧ compat e.2 q = true))) ∨
    (∃ r, stp.2 = .c r ∧ e.1 = true ∧ (LoShape (params v).n (params v).m r ∨ IsPR (params v).n r) ∧
      compat r (e.2.res t) = true) := by
  have hn := params_n_pos v
  obtain ⟨st, ev⟩ := stp
  obtain ⟨⟨hlen, hcoin, hadv, hgood, hnd, hstep⟩, -, -, -⟩ := hΦ
  obtain ⟨b, er⟩ := e
  cases ev with
  | r x => cases hc
  | a q =>
    left
    simp only [cand] at hc
    split at hc
    · cases hc
    · next ho =>
      obtain rfl := Option.some.inj hc
      cases b with
      | true =>
        exfalso; apply ho
        simp [isOpen, hadv j er he]
      | false =>
        refine ⟨q, rfl, rfl, ?_⟩
        by_cases hj : j < 3
        · exact Or.inl hj
        · exact Or.inr ⟨by omega, goodFam_lo_pr (hgood j er (by omega) he), hcomp⟩
  | c r =>
    right
    obtain ⟨hgr, hfr⟩ := hstep r rfl
    simp only [cand] at hc
    split at hc
    · cases hc
    · next hne =>
      split at hc
      · next hoe =>
        split at hc
        · cases hc
        · obtain rfl := Option.some.inj hc
          refine ⟨r, rfl, ?_, goodFam_lo_pr hgr, hcomp⟩
          cases b with
          | true => rfl
          | false =>
            exfalso
            have hm := (compat_parts hcomp).1
            rw [res_mode] at hm
            simp only at hm
            by_cases hj : j < 3
            · have h1 := hcoin j _ hj he
              simp only at h1
              exact goodFam_mode hgr (by omega)
            · have hle := goodFam_open (hgood j er (by omega) he) hoe
              rcases goodFam_lo_pr hgr with hlr | hpr
              · exact hne (hfr hlr j er (by omega) he hle
                  (skel_det hn hle hlr (compat_of_res t er _ rfl) hcomp))
              · by_cases hth : IsTh (params v).n er
                · exact hψ ⟨r, er, rfl, he, Or.inr ⟨hpr, hth⟩⟩
                · exact lo_mode_ne1 hle hth (by rw [← hm, pr_mode hpr])
      · next hoe =>
        split at hc
        · next hor =>
          obtain rfl := Option.some.inj hc
          exfalso
          have hm := (compat_parts hcomp).1
          rw [res_mode] at hm
          simp only at hm
          cases b with
          | true => exact hoe (by simp [isOpen, hadv j er he])
          | false =>
            by_cases hj : j < 3
            · have h1 := hcoin j _ hj he
              simp only at h1
              exact goodFam_mode hgr (by omega)
            · have hlr := goodFam_open hgr hor
              rcases goodFam_lo_pr (hgood j er (by omega) he) with hle | hpr
              · exact hne (hfr hlr j er (by omega) he hle
                  (skel_det hn hle hlr hcomp (compat_of_res t r _ rfl)))
              · by_cases hth : IsTh (params v).n r
                · exact hψ ⟨r, er, rfl, he, Or.inl ⟨hpr, hth⟩⟩
                · exact lo_mode_ne1 hlr hth (by rw [← hm, pr_mode hpr])
        · cases hc

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin : Nat)

theorem of_probeQ (t : List Nat) (s j : Nat)
    (h : (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome = true) :
    ∃ stp e XY, (strace t P st0)[s]? = some stp ∧ elig t stp = true ∧ PhiW v stp ∧ ¬ KeyTh v stp j ∧
      stp.1.ents[j]? = some e ∧ cand t stp.1 stp.2 e = some XY ∧ compat XY.1 XY.2 = true := by
  cases hp : probeQ wmin (phiW v) (psiB v) P st0 t s j with
  | none => rw [hp] at h; cases h
  | some val =>
    unfold probeQ at hp
    cases hs : (strace t P st0)[s]? with
    | none => rw [hs] at hp; cases hp
    | some stp =>
      rw [hs] at hp
      simp only [Option.bind_some] at hp
      split at hp
      · rename_i hel
        simp only [Bool.and_eq_true, Bool.not_eq_true'] at hel
        unfold probeAtW at hp
        split at hp
        · cases hp
        · rename_i e he
          split at hp
          · cases hp
          · rename_i XY hXY
            split at hp
            · cases hp
            · rename_i w hw
              split at hp
              · rename_i hcond
                refine ⟨stp, e, XY, rfl, hel.1.1, phiW_true v hel.1.2, ?_, he, hXY, hcond.2⟩
                intro hk
                have : psiB v stp j = true := by simpa [psiB] using hk
                rw [this] at hel; exact absurd hel.2 (by decide)
              · cases hp
      · cases hp

end

/-! Counting the probes. -/

/-- A PRF-shaped request. -/
abbrev prQ (n k : Nat) (m : Bytes) : SReq := ⟨1, "", [.hid k 32], [.hid 2 n, .lit m], n⟩

theorem pr_compat_m {n k : Nat} {m : Bytes} {Y : Request} (h : compat (prQ n k m) Y = true) :
    m = Y.input.drop n := by
  obtain ⟨_, _, _, _, hi⟩ := compat_parts h
  obtain ⟨_, h1⟩ := pm_hid hi
  obtain ⟨h2, h3⟩ := pm_lit h1
  have h4 := pm_nil h3
  rw [← List.take_append_drop m.length (Y.input.drop n), h2, h4, List.append_nil]

theorem ge3_of_mode {v : Variant} {stp : St × Ev} (hΦ : PhiP v stp) {k : Nat} {r : SReq}
    (h : stp.1.ents[k]? = some (false, r)) (hm : r.mode ≠ 999) : 3 ≤ k := by
  apply Nat.le_of_not_lt
  intro hk
  exact hm (hΦ.2.1 k _ hk h)

theorem isPR_of {n : Nat} {r : SReq} (h : IsPR n r) : ∃ k m, r = prQ n k m := by
  obtain ⟨k, m, rfl⟩ := h; exact ⟨k, m, rfl⟩

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin : Nat)

/-- At an adversary step, at most six entries carry a counted probe: the three coins, one
    narrow-shaped entry (its skeleton is determined by the query) and one PRF-shaped entry
    per key (its literal is determined by the query). -/
theorem adv_step_w (t : List Nat) (s S : Nat) (stp : St × Ev) (q : Request)
    (hs : (strace t P st0)[s]? = some stp) (hq : stp.2 = .a q) :
    ((List.range S).map (fun j => if (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome then 1 else 0)).sum ≤ 6 := by
  have hn := params_n_pos v
  let L := fun j => ind (PhiW v stp ∧ 3 ≤ j ∧ ∃ er, stp.1.ents[j]? = some (false, er) ∧
    LoShape (params v).n (params v).m er ∧ compat er q = true)
  let K := fun (d : SReq) (j : Nat) => ind (PhiW v stp ∧ 3 ≤ j ∧ ∃ k m, stp.1.ents[j]? = some (false, prQ (params v).n k m) ∧
    compat (prQ (params v).n k m) q = true ∧ stp.1.ents[k]? = some (false, d))
  have hpt : ∀ j, (if (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome then 1 else 0) ≤
      (if j < 3 then 1 else 0) + L j + K (dPrf (params v).n) j + K (dReq (params v).n) j := by
    intro j
    split
    · rename_i hp
      obtain ⟨stp', e, XY, hs', _, hΦ, hψ, he, hc, hcomp⟩ := of_probeQ v P st0 wmin t s j hp
      rw [hs] at hs'
      obtain rfl := Option.some.inj hs'
      rcases pin_class_w v t hΦ hψ he hc hcomp with ⟨q', hq', he1, hj⟩ | ⟨r, hr, _⟩
      · rw [hq] at hq'
        cases hq'
        obtain ⟨b, er⟩ := e
        simp only at he1 hj
        subst he1
        rcases hj with hj | ⟨hj3, hlp, hcq⟩
        · rw [if_pos hj]; omega
        rcases hlp with hlo | hpr
        · have h1 : L j = 1 := ind_of ⟨hΦ, hj3, er, he, hlo, hcq⟩
          omega
        · obtain ⟨k, m, rfl⟩ := isPR_of hpr
          rcases hΦ.2.2.1 j k m hj3 he with hk | hk
          · have h1 : K (dPrf (params v).n) j = 1 := ind_of ⟨hΦ, hj3, k, m, he, hcq, hk⟩
            omega
          · have h1 : K (dReq (params v).n) j = 1 := ind_of ⟨hΦ, hj3, k, m, he, hcq, hk⟩
            omega
      · rw [hq] at hr; cases hr
    · exact Nat.zero_le _
  have hL : ((List.range S).map L).sum ≤ 1 := by
    refine sum_le_one L (fun j => ind_le_one _) (fun a b hab ha hb => ?_) S
    have ha' : PhiW v stp ∧ 3 ≤ a ∧ ∃ er, stp.1.ents[a]? = some (false, er) ∧
        LoShape (params v).n (params v).m er ∧ compat er q = true :=
      Classical.byContradiction (fun h => ha (ind_of_not h))
    have hb' : PhiW v stp ∧ 3 ≤ b ∧ ∃ er, stp.1.ents[b]? = some (false, er) ∧
        LoShape (params v).n (params v).m er ∧ compat er q = true :=
      Classical.byContradiction (fun h => hb (ind_of_not h))
    obtain ⟨hΦ, h3a, ra, hea, hla, hca⟩ := ha'
    obtain ⟨-, h3b, rb, heb, hlb, hcb⟩ := hb'
    exact hΦ.1.2.2.2.2.1 a b ra rb h3a h3b (by omega) hea heb hla hlb (skel_det hn hla hlb hca hcb)
  have hK : ∀ d, d.mode ≠ 999 → ((List.range S).map (K d)).sum ≤ 1 := by
    intro d hd
    refine sum_le_one (K d) (fun j => ind_le_one _) (fun a b hab ha hb => ?_) S
    have ha' : PhiW v stp ∧ 3 ≤ a ∧ ∃ k m, stp.1.ents[a]? = some (false, prQ (params v).n k m) ∧
        compat (prQ (params v).n k m) q = true ∧ stp.1.ents[k]? = some (false, d) :=
      Classical.byContradiction (fun h => ha (ind_of_not h))
    have hb' : PhiW v stp ∧ 3 ≤ b ∧ ∃ k m, stp.1.ents[b]? = some (false, prQ (params v).n k m) ∧
        compat (prQ (params v).n k m) q = true ∧ stp.1.ents[k]? = some (false, d) :=
      Classical.byContradiction (fun h => hb (ind_of_not h))
    obtain ⟨hΦ, h3a, k1, m1, hea, hca, hk1⟩ := ha'
    obtain ⟨-, h3b, k2, m2, heb, hcb, hk2⟩ := hb'
    have hm : m1 = m2 := by rw [pr_compat_m hca, pr_compat_m hcb]
    have hk : k1 = k2 := hΦ.2.1 k1 k2 d (ge3_of_mode hΦ.1 hk1 hd) (ge3_of_mode hΦ.1 hk2 hd) hk1 hk2
    subst hm hk
    have := hΦ.2.1 a b _ h3a h3b hea heb
    omega
  have hd1 : (dPrf (params v).n).mode ≠ 999 := by simp [dPrf]
  have hd2 : (dReq (params v).n).mode ≠ 999 := by simp [dReq]
  calc _ ≤ ((List.range S).map (fun j => (if j < 3 then 1 else 0) + L j + K (dPrf (params v).n) j +
          K (dReq (params v).n) j)).sum := sum_map_le _ (fun j _ => hpt j)
    _ = ((List.range S).map (fun j => if j < 3 then 1 else 0)).sum + ((List.range S).map L).sum +
          ((List.range S).map (K (dPrf (params v).n))).sum + ((List.range S).map (K (dReq (params v).n))).sum := by
        rw [sum_map_add, sum_map_add, sum_map_add]
    _ ≤ 3 + 1 + 1 + 1 := Nat.add_le_add (Nat.add_le_add (Nat.add_le_add (sum_lt3 S) hL) (hK _ hd1)) (hK _ hd2)

end

section
variable {α : Type} (v : Variant) (P : Prog α) (st0 : St) (wmin : Nat)

theorem adv_final (t : List Nat) {s j : Nat} {stp : St × Ev} {e : Bool × SReq}
    (hs : (strace t P st0)[s]? = some stp) (he : stp.1.ents[j]? = some e) (ht : e.1 = true) :
    ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true := by
  obtain ⟨L, hL⟩ := trace_final t P st0 s stp hs
  rw [hL, List.getElem?_append_left (lt_entry he), he]
  simp [ht]

theorem sum_le_ind (f : Nat → Nat) (hf : ∀ j, f j ≤ 1) (hu : ∀ a b, a < b → f a ≠ 0 → f b ≠ 0 → False)
    (T : Prop) [Decidable T] (hz : ∀ s, f s ≠ 0 → T) (S : Nat) :
    ((List.range S).map f).sum ≤ if T then 1 else 0 := by
  split
  · exact sum_le_one f hf hu S
  · rename_i hT
    rw [sum_zero_of _ _ (fun s _ => Classical.byContradiction (fun h => hT (hz s h)))]
    exact Nat.le_refl 0

/-- The counted probes at challenger steps against entry `j`: at most three, and only if
    `j` is an adversary entry of the end state. -/
theorem chal_entry_w (t : List Nat) (S j : Nat) :
    ((List.range S).map (fun s => if ((strace t P st0)[s]?.map isAev) = some true then 0 else
      if (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome then 1 else 0)).sum ≤
    3 * (if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0) := by
  have hn := params_n_pos v
  let Cl := fun (s : Nat) => ind (∃ (stp : St × Ev) (r : SReq) (e : Bool × SReq), (strace t P st0)[s]? = some stp ∧
    stp.2 = .c r ∧ elig t stp = true ∧ PhiW v stp ∧ stp.1.ents[j]? = some e ∧ e.1 = true ∧
    LoShape (params v).n (params v).m r ∧ compat r (e.2.res t) = true)
  let Ck := fun (d : SReq) (s : Nat) => ind (∃ (stp : St × Ev) (k : Nat) (m : Bytes) (e : Bool × SReq),
    (strace t P st0)[s]? = some stp ∧ stp.2 = .c (prQ (params v).n k m) ∧ elig t stp = true ∧ PhiW v stp ∧
    stp.1.ents[j]? = some e ∧ e.1 = true ∧ compat (prQ (params v).n k m) (e.2.res t) = true ∧
    stp.1.ents[k]? = some (false, d))
  have hpt : ∀ s, (if ((strace t P st0)[s]?.map isAev) = some true then 0 else
      if (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome then 1 else 0) ≤
      Cl s + Ck (dPrf (params v).n) s + Ck (dReq (params v).n) s := by
    intro s
    split
    · exact Nat.zero_le _
    · rename_i hna
      split
      · rename_i hp
        obtain ⟨stp, e, XY, hs, hel, hΦ, hψ, he, hc, hcomp⟩ := of_probeQ v P st0 wmin t s j hp
        rcases pin_class_w v t hΦ hψ he hc hcomp with ⟨q, hq, _⟩ | ⟨r, hr, ht, hlp, hcp⟩
        · exfalso; apply hna; rw [hs]; simp [isAev, hq]
        · rcases hlp with hlo | hpr
          · have h1 : Cl s = 1 := ind_of ⟨stp, r, e, hs, hr, hel, hΦ, he, ht, hlo, hcp⟩
            omega
          · obtain ⟨k, m, rfl⟩ := isPR_of hpr
            rcases hΦ.2.2.2 k m hr with hk | hk
            · have h1 : Ck (dPrf (params v).n) s = 1 := ind_of ⟨stp, k, m, e, hs, hr, hel, hΦ, he, ht, hcp, hk⟩
              omega
            · have h1 : Ck (dReq (params v).n) s = 1 := ind_of ⟨stp, k, m, e, hs, hr, hel, hΦ, he, ht, hcp, hk⟩
              omega
      · exact Nat.zero_le _
  -- not fresh: a request already an entry
  have notfr : ∀ {s1 s2 : Nat} {st1 : St} {r : SReq} {stp2 : St × Ev}, s1 < s2 →
      (strace t P st0)[s1]? = some (st1, .c r) → elig t (st1, .c r) = true →
      (strace t P st0)[s2]? = some stp2 → stp2.2 = .c r → elig t stp2 = true → False := by
    intro s1 s2 st1 r stp2 hlt h1 hel1 h2 hr2 hel2
    have hfe := fresh_entry t P st0 hlt h1 hel1 h2
    obtain ⟨st2, ev2⟩ := stp2
    simp only at hr2 hfe
    subst hr2
    have hfr : st2.ents.length ≤ firstIdx (mC false t st2.rev r) st2.ents := by simpa [elig] using hel2
    have hm : mC false t st2.rev r (false, r) = true := by simp [mC]
    have := fr_before (mC false t st2.rev r) st2.ents st1.ents.length (false, r) hfe
      (by have := lt_entry hfe; omega)
    rw [hm] at this; cases this
  have hCl : ((List.range S).map Cl).sum ≤ if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0 := by
    refine sum_le_ind Cl (fun _ => ind_le_one _) (fun s1 s2 hlt h1 h2 => ?_) _ (fun s h => ?_) S
    · have h1' := Classical.byContradiction (fun h => h1 (ind_of_not h))
      have h2' := Classical.byContradiction (fun h => h2 (ind_of_not h))
      obtain ⟨stp1, r1, e1, hs1, hr1, hel1, hΦ1, he1, ht1, hl1, hcp1⟩ := h1'
      obtain ⟨stp2, r2, e2, hs2, hr2, hel2, hΦ2, he2, ht2, hl2, hcp2⟩ := h2'
      have he12 : e1 = e2 := by
        have := ent_later P st0 t (Nat.le_of_lt hlt) hs1 hs2 he1
        rw [he2] at this; exact (Option.some.inj this).symm
      subst he12
      obtain ⟨st1, ev1⟩ := stp1
      simp only at hr1
      subst hr1
      have hfe := fresh_entry t P st0 hlt hs1 hel1 hs2
      have hsk := skel_det hn hl1 hl2 hcp1 hcp2
      have h3 : 3 ≤ st1.ents.length := hΦ1.1.1
      have heq := (hΦ2.1.2.2.2.2.2 r2 hr2).2 hl2 st1.ents.length r1 h3 hfe hl1 hsk
      subst heq
      exact notfr hlt hs1 hel1 hs2 hr2 hel2
    · have h' := Classical.byContradiction (fun h' => h (ind_of_not h'))
      obtain ⟨stp, _, e, hs, _, _, _, he, ht, _⟩ := h'
      exact adv_final P st0 t hs he ht
  have hCk : ∀ d, d.mode ≠ 999 → ((List.range S).map (Ck d)).sum ≤
      if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0 := by
    intro d hd
    refine sum_le_ind (Ck d) (fun _ => ind_le_one _) (fun s1 s2 hlt h1 h2 => ?_) _ (fun s h => ?_) S
    · have h1' := Classical.byContradiction (fun h => h1 (ind_of_not h))
      have h2' := Classical.byContradiction (fun h => h2 (ind_of_not h))
      obtain ⟨stp1, k1, m1, e1, hs1, hr1, hel1, hΦ1, he1, ht1, hcp1, hk1⟩ := h1'
      obtain ⟨stp2, k2, m2, e2, hs2, hr2, hel2, hΦ2, he2, ht2, hcp2, hk2⟩ := h2'
      have he12 : e1 = e2 := by
        have := ent_later P st0 t (Nat.le_of_lt hlt) hs1 hs2 he1
        rw [he2] at this; exact (Option.some.inj this).symm
      subst he12
      have hm : m1 = m2 := by rw [pr_compat_m hcp1, pr_compat_m hcp2]
      have hk1' := ent_later P st0 t (Nat.le_of_lt hlt) hs1 hs2 hk1
      have hk : k1 = k2 := hΦ2.2.1 k1 k2 d (ge3_of_mode hΦ2.1 hk1' hd) (ge3_of_mode hΦ2.1 hk2 hd) hk1' hk2
      subst hm hk
      obtain ⟨st1, ev1⟩ := stp1
      simp only at hr1
      subst hr1
      exact notfr hlt hs1 hel1 hs2 hr2 hel2
    · have h' := Classical.byContradiction (fun h' => h (ind_of_not h'))
      obtain ⟨stp, _, _, e, hs, _, _, _, he, ht, _⟩ := h'
      exact adv_final P st0 t hs he ht
  have hd1 : (dPrf (params v).n).mode ≠ 999 := by simp [dPrf]
  have hd2 : (dReq (params v).n).mode ≠ 999 := by simp [dReq]
  calc _ ≤ ((List.range S).map (fun s => Cl s + Ck (dPrf (params v).n) s + Ck (dReq (params v).n) s)).sum :=
        sum_map_le _ (fun s _ => hpt s)
    _ = ((List.range S).map Cl).sum + ((List.range S).map (Ck (dPrf (params v).n))).sum +
          ((List.range S).map (Ck (dReq (params v).n))).sum := by rw [sum_map_add, sum_map_add]
    _ ≤ _ := by
        have a1 := hCl
        have a2 := hCk _ hd1
        have a3 := hCk _ hd2
        generalize (if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0) = T at a1 a2 a3 ⊢
        omega

/-- The wide count: every counted probe involves an adversary draw, at most six per
    adversary step and at most three per adversary entry. -/
theorem wide_count (t : List Nat) (S : Nat) :
    pairCountQ wmin (phiW v) (psiB v) P st0 S t ≤
      9 * ((strace t P st0).filter isAev).length + 3 * cntT st0.ents := by
  let NA := ((strace t P st0).filter isAev).length
  let a := fun (s : Nat) => if ((strace t P st0)[s]?.map isAev) = some true then 1 else 0
  let N := fun (s j : Nat) => if (probeQ wmin (phiW v) (psiB v) P st0 t s j).isSome then 1 else 0
  let C := fun (s j : Nat) => if ((strace t P st0)[s]?.map isAev) = some true then 0 else N s j
  have h1 : ∀ s, ((List.range S).map (N s)).sum ≤ 6 * a s + ((List.range S).map (C s)).sum := by
    intro s
    by_cases ha : ((strace t P st0)[s]?.map isAev) = some true
    · have hC0 : ((List.range S).map (C s)).sum = 0 := by
        simp only [C, ha, if_true]; exact sum_map_zero _
      rw [hC0]
      simp only [a, ha, if_true]
      cases hs : (strace t P st0)[s]? with
      | none => rw [hs] at ha; cases ha
      | some stp =>
        rw [hs] at ha
        obtain ⟨st, ev⟩ := stp
        cases ev with
        | a q => exact adv_step_w v P st0 wmin t s S _ q hs rfl
        | c r => simp [isAev] at ha
        | r x => simp [isAev] at ha
    · simp only [a, C, ha, if_false, Nat.mul_zero, Nat.zero_add]; exact Nat.le_refl _
  have h2 : ((List.range S).map (fun s => ((List.range S).map (C s)).sum)).sum ≤ 3 * (NA + cntT st0.ents) := by
    rw [sum_swap (fun s j => C s j) S S]
    calc _ ≤ ((List.range S).map (fun j =>
            3 * (if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0))).sum :=
          sum_map_le _ (fun j _ => chal_entry_w v P st0 wmin t S j)
      _ = 3 * ((List.range S).map (fun j =>
            if ((xrun false t P st0).2.ents[j]?.map Prod.fst) = some true then 1 else 0)).sum := sum_map_mul _ _ _
      _ ≤ 3 * ((xrun false t P st0).2.ents.filter Prod.fst).length :=
          Nat.mul_le_mul_left _ (sum_idx_filter _ _ _)
      _ ≤ 3 * (cntT st0.ents + NA) := Nat.mul_le_mul_left _ (cnt_run t P st0)
      _ = 3 * (NA + cntT st0.ents) := by rw [Nat.add_comm]
  have h3 : ((List.range S).map a).sum ≤ NA := sum_idx_filter isAev _ _
  show ((List.range S).map (fun s => ((List.range S).map (N s)).sum)).sum ≤ 9 * NA + 3 * cntT st0.ents
  calc _ ≤ ((List.range S).map (fun s => 6 * a s + ((List.range S).map (C s)).sum)).sum := sum_map_le _ (fun s _ => h1 s)
    _ = 6 * ((List.range S).map a).sum + ((List.range S).map (fun s => ((List.range S).map (C s)).sum)).sum := by
        rw [sum_map_add, sum_map_mul]
    _ ≤ 6 * NA + 3 * (NA + cntT st0.ents) := Nat.add_le_add (Nat.mul_le_mul_left _ h3) h2
    _ = 9 * NA + 3 * cntT st0.ents := by omega

end

/-! H1' and SPHINCS+-256f with every quadratic term removed. -/

/-- The hidden-value bound for H1' with every pin counted: at most `9·AA` counted probes,
    each against `256^n`; a filtered probe that hits is a key collision. -/
theorem rom_ext_wide (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N S AA : Nat)
    (hR : 256^(params v).n ∣ R)
    (hS : ∀ t s stp, (strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)).filter isAev).length ≤ AA) :
    tsum R N (fun t => if anyDis (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) t then 1 else 0) *
        256^(params v).n ≤
      R^N * (9 * AA) +
        tsum R N (fun t => if wildCollP (params v).n (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) N t ||
          initColl t (coinSt (params v).n) then 1 else 0) * 256^(params v).n +
        tsum R N (fun t => ind (KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t)) *
          256^(params v).n :=
  hidden_bound_Q (params v).n (phiW v) (psiB v) (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n)
    (KeyColl (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n) R N S (9 * AA) hR hS
    (game_phiW v limits A)
    (fun t s stp j e XY hs hnd hψ he hc hres => game_keyTh v limits A t s stp j e XY hs hnd hψ he hc hres)
    (fun t => by
      have := wide_count v (gameS' v limits A (coinEx (params v).n)) (coinSt (params v).n) (params v).n t S
      rw [cntT_coin, Nat.mul_zero, Nat.add_zero] at this
      exact Nat.le_trans this (Nat.mul_le_mul_left _ (hA t)))

theorem arithW (w a b d d0 e kc r JA AA K H : Nat) (hK : K = 2 * H) (hH : 0 < H)
    (h1 : w * K ≤ a * K + b * K + d * K) (h2 : b * H ≤ JA * r + d0 * H) (h3 : d0 ≤ d)
    (h4 : d * K ≤ r * (9 * AA) + e * K + kc * K) (h5 : e * (K * K) ≤ r * 3 * K + r * 3 * K)
    (h6 : a * (K * K) ≤ r * AA * K + r * 3 * K) (h7 : kc * K ≤ r * 3) :
    w * K ≤ r * (2 * JA + 19 * AA + 21) := by
  have hKp : 0 < K := by omega
  have h5' : e * K ≤ r * 3 + r * 3 :=
    Nat.le_of_mul_le_mul_right (by rw [Nat.add_mul, Nat.mul_assoc]; exact h5) hKp
  have h6' : a * K ≤ r * AA + r * 3 :=
    Nat.le_of_mul_le_mul_right (by rw [Nat.add_mul, Nat.mul_assoc]; exact h6) hKp
  have hd0 : d0 * K ≤ d * K := Nat.mul_le_mul_right K h3
  have e1 : b * K = 2 * (b * H) := by rw [hK, Nat.mul_left_comm]
  have e2 : d0 * K = 2 * (d0 * H) := by rw [hK, Nat.mul_left_comm]
  have e3 : r * (9 * AA) = 9 * (r * AA) := by rw [Nat.mul_left_comm]
  have e4 : r * (2 * JA + 19 * AA + 21) = 2 * (JA * r) + 19 * (r * AA) + 21 * r := by
    rw [Nat.mul_add, Nat.mul_add, Nat.mul_left_comm r 2 JA, Nat.mul_comm r JA, Nat.mul_left_comm r 19,
      Nat.mul_comm r 21]
  rw [e3] at h4
  rw [e4]
  omega

/-- SPHINCS+-256f, H1, linear: `Pr[won] ≤ (2·JA + 19·AA + 21)/2^256`, under the ITSR
    budget hypotheses, the step bound `S < N` of H1' and its adversary-step bound `AA`.
    No term depends on `S` or `N` beyond the tape length. -/
theorem rom_win_lin_256f (limits : Limits) (A : Bytes → RAdv) (c N q JA S AA : Nat) (hc : 0 < c)
    (hq : q ≤ 2^64)
    (hN : ∀ t : List Nat, t.length = N → (runG .spx256f limits A t).2.length ≤ N)
    (hC : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isC).length ≤ q)
    (hJ : ∀ t : List Nat, t.length = N → ((runG .spx256f limits A t).2.filter isA).length ≤ JA)
    (hS : ∀ t s stp, (strace t (gameS' .spx256f limits A (coinEx (params .spx256f).n))
      (coinSt (params .spx256f).n))[s]? = some stp → s < S ∧ stp.1.ents.length ≤ S)
    (hA : ∀ t, ((strace t (gameS' .spx256f limits A (coinEx (params .spx256f).n))
      (coinSt (params .spx256f).n)).filter isAev).length ≤ AA)
    (hSN : S < N) (h3N : 3 ≤ N) :
    tsum (c * 256^(params .spx256f).m) N (fun t => ind ((runG .spx256f limits A t).1.win = true)) * 256^32 ≤
      (c * 256^(params .spx256f).m)^N * (2 * JA + 19 * AA + 21) := by
  have hR : 256^32 ∣ c * 256^(params .spx256f).m :=
    Nat.dvd_mul_left_of_dvd (Nat.pow_dvd_pow 256 (by decide)) c
  have h1 := rom_win_sum' .spx256f limits A (c * 256^(params .spx256f).m) N (256^32)
  have h2 := itsr_game_hid_256f limits A c N q JA hc hq hN hC hJ
  have h3 := anyDis_sum .spx256f limits A (c * 256^(params .spx256f).m) N
  have h4 := rom_ext_wide .spx256f limits A (c * 256^(params .spx256f).m) N S AA hR hS hA
  have h5 := coll_count_key .spx256f limits A (c * 256^(params .spx256f).m) N S hR hR hS hSN h3N
  have h6 := canon_count_key .spx256f limits A (c * 256^(params .spx256f).m) N S AA hR hR (fun t => hS t) hSN h3N hA
  have h7 := key_count (gameS' .spx256f limits A (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n)
    (params .spx256f).n (c * 256^(params .spx256f).m) N S hR (coin_not_key _) hS hSN
  rw [show (256:Nat)^(params .spx256f).n = 256^32 by decide] at h4 h5 h6
  generalize tsum (c * 256^(params .spx256f).m) N (fun t => if anyDis (gameS' .spx256f limits A
    (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) t then 1 else 0) = D at h1 h3 h4
  generalize tsum (c * 256^(params .spx256f).m) N (fun t => if anyDis (gameS .spx256f limits A
    (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) t then 1 else 0) = D0 at h2 h3
  generalize tsum (c * 256^(params .spx256f).m) N (fun t => ind (KeyColl (gameS' .spx256f limits A
    (coinEx (params .spx256f).n)) (coinSt (params .spx256f).n) (params .spx256f).n t)) = Kc at h4 h7
  exact arithW _ _ _ D D0 _ Kc _ JA AA (256^32) (2^255) (by decide) (Nat.pow_pos (by decide))
    h1 h2 h3 h4 h5 h6 h7

/-- The linear forgery bound for SPHINCS+-256f from the query budget:
      Pr[won] ≤ (21·qh + 368023) / 2^256
    for every adversary with `Budget A qh qs` and `qs ≤ 2^64`, on tapes of length
    `N = qh + 1704962·qs + 398865`. -/
theorem rom_win_budget_lin_256f (limits : Limits) (A : Bytes → RAdv) (c qh qs : Nat) (hc : 0 < c)
    (hqs : qs ≤ 2^64) (hB : ∀ pk, Budget (A pk) qh qs) :
    tsum (c * 256^(params .spx256f).m) (qh + 1704962 * qs + 398865)
        (fun t => ind ((runG .spx256f limits A t).1.win = true)) * 256^32 ≤
      (c * 256^(params .spx256f).m)^(qh + 1704962 * qs + 398865) * (21 * qh + 368023) := by
  have e := stepB_256f qh qs
  have hv := verC_256f
  have h := rom_win_lin_256f limits A c (qh + 1704962 * qs + 398865) qs (qh + 17523)
    (qh + 1704962 * qs + 398864) (qh + 17524) hc hqs
    (fun t _ => budget_N .spx256f limits A qh qs hB _ (by omega) t)
    (fun t _ => budget_C .spx256f limits A qh qs hB _ (Nat.le_refl _) t)
    (fun t _ => budget_J .spx256f limits A qh qs hB _ (by omega) t)
    (budget_S .spx256f limits A qh qs hB _ (by omega))
    (budget_A .spx256f limits A qh qs hB _ (by omega))
    (by omega) (by omega)
  refine Nat.le_trans h (Nat.mul_le_mul_left _ (Nat.le_of_eq ?_))
  omega

end DSM.Rom
