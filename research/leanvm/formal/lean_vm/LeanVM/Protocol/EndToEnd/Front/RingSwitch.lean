/-
  LeanVM.Protocol.EndToEnd.Front.RingSwitch

  The verifier program's ring switching specified in the doom calculus: from the Keccak
  reduction's 64 bit-slice claims to the switched claim, its sixteen challenges one group.
-/

module

public import LeanVM.Protocol.RingVerifier
public import LeanVM.Protocol.EndToEnd.Front.OodBind

/-!
# Ring switching as a specification

`ringSwitch claims` (`crates/verifier/src/ring_switch.rs`; Annex A; research build: a list of
claims, `QKECCAK`'s and `QFLOCK`'s, under one map) grinds
`batchGrindingBits = 13` bits, draws sixteen challenges `f_0..f_7, g_0..g_7`, and returns the
target `Σ_i x^i Φ(s_i)` and the weight of `Φ(eq(point, ·))`, `Φ = frobPhi 8 f g`
(`Ring.ringSwitch_eq`). The stacked opening's batching challenge `λ` is drawn right after, under
the same grind: the sixteen and `λ` are one group.

The bound of Annex A §A.4 holds for the sixteen jointly, not challenge by challenge (`f` is drawn
before `g`, and a single challenge can cancel a nonzero family's first pairing): slice claims
`s ≠ ẑ` meet the honest value at a fraction `2/|E|` of the challenge lists
(`Ring.ringBad_ratio_le`). So the phase is one `Spec.ofNoMove` over the sixteen, after the grind
(`Spec.grindPos`), with lead `L₀ · 2/|E|` plus the follower's (the opening's `λ`).

The specification is stated for a set `S` of candidates (the assembly passes the stack word's
candidates left by the OOD sample, `oodCands`, at most one), a predicate `G` of the claims they
must also meet, each candidate's true slices `z q`, and a reading `RC` of the returned ring claim
on a candidate, assumed to hold only at a bad challenge list (`RingClaimBad`; for the verifier's
claim on the stack, `RingFidelity.ringClaim_holds_iff`):

* `RingPre`: no candidate meets `G` with true slices equal to the claims;
* `RingPost`: no candidate meets `G` and the ring claim;
* `escRet_ring_le`: the group escapes with probability at most `L₀ · n · 2/|E|`, `n` the regions
  (a union bound: a candidate's slices are false in some region, and that region's target meets
  the honest value at a fraction `2/|E|`);
* `ringSpec`: the phase.
-/

namespace LeanVM.Protocol.EndToEnd.Front

open LeanVM.Parameters LeanVM.Protocol.Compile LeanVM.Protocol.Ring VerifierProgram
open scoped ENNReal

@[expose] public section

section Ring

variable {β : Type} (S : Set β) (G : β → Prop) {n : ℕ} (pt : Fin n → List E)
  (z : Fin n → β → Fin 64 → E) (sv : Fin n → Fin 64 → E)
  (RC : List (E × (List E → E)) → β → Prop)

/-- What `ringSwitch` returns for one claim `(point, List.ofFn sv)` at the challenge list `ch`. -/
def ringResult (point : List E) (sv : Fin 64 → E) (ch : List E) : E × (List E → E) :=
  (ringTarget (List.ofFn sv) (ch.take 8) (ch.drop 8),
    fun r' ↦ Verifier.ringWeight point r' (ringCoefficients (ch.take 8) (ch.drop 8)))

/-- The claims ring switching takes, one per region (research build: `QKECCAK`'s, then
`QFLOCK`'s): each a point and its sixty-four slice claims. -/
def ringClaims : List (List E × List E) := List.ofFn fun i ↦ (pt i, List.ofFn (sv i))

/-- What `ringSwitch (ringClaims pt sv)` returns at the challenge list `ch`: every region's
target and weight under the one map. -/
def ringResults (ch : List E) : List (E × (List E → E)) :=
  List.ofFn fun i ↦ ringResult (pt i) (sv i) ch

/-- The ring switch is the grind, then the challenges and the results. -/
theorem ringSwitch_eq_results :
    Verifier.ringSwitch (ringClaims pt sv) =
      (grindProofOfWork Whir.batchGrindingBits).bind fun _ ↦
        (sampleChallenges 16).bind fun ch ↦ ret (ringResults pt sv ch) := by
  rw [ringSwitch_eq]
  simp only [ringClaims, List.map_ofFn]
  rfl

/-- The reading of the ring claims holds only at challenge lists bad for every region. -/
def RingClaimBad : Prop :=
  ∀ q ch, ch.length = 16 → RC (ringResults pt sv ch) q →
    ∀ i, RingBad (List.ofFn (sv i)) (z i q) ch

/-- **Ring switching's precondition**: no candidate meets `G` with its true slices equal to the
claimed ones in every region. -/
def RingPre (_ : List Ev) : Prop := ∀ q ∈ S, ¬ (G q ∧ ∀ i, z i q = sv i)

/-- **Ring switching's postcondition**: no candidate meets `G` and the returned ring claims. -/
def RingPost (r : List (E × (List E → E))) (_ : List Ev) : Prop := ∀ q ∈ S, ¬ (G q ∧ RC r q)

open Classical in
/-- **The group's escape**: from `RingPre`, the sixteen challenges reach `RingPost`'s failure with
probability at most `L₀ · n · 2/|E|`, a union over the candidates and the regions of
`Ring.ringBad_ratio_le`. -/
theorem escRet_ring_le (hRC : RingClaimBad pt z sv RC) (hS : S.Finite)
    {L₀ : ℕ} (hL : S.ncard ≤ L₀) (h₀ : List Ev) (hpre : RingPre S G z sv h₀) :
    escRet (RingPost S G RC) h₀ [] ((sampleChallenges 16).bind fun ch ↦
        ret (ringResults pt sv ch))
      ≤ L₀ * (n * (2 / Fintype.card E)) := by
  unfold escRet
  rw [Whir.Sound.retExp_bind]
  have hret : (fun (ch : List E) (h : List Ev) ↦ retExp (fun a h ↦ if RingPost S G RC a h then
      (0 : ℝ≥0∞) else 1) h [] (ret (ringResults pt sv ch))) =
      fun ch _ ↦ if RingPost S G RC (ringResults pt sv ch) [] then 0 else 1 := by
    funext ch h
    simp [retExp, RingPost]
  rw [hret, Whir.Sound.retExp_sampleN]
  set T := hS.toFinset
  -- The bad event is covered by the candidates' and regions' bad events.
  have hcover : ∀ f : Fin 16 → E,
      (if RingPost S G RC (ringResults pt sv (List.ofFn f)) [] then 0 else 1 : ℝ≥0∞) ≤
        ∑ q ∈ T, ∑ i : Fin n,
          (if RingBad (List.ofFn (sv i)) (z i q) (List.ofFn f) ∧ z i q ≠ sv i then 1 else 0) := by
    intro f
    split_ifs with hp
    · exact zero_le
    · simp only [RingPost, not_forall, not_not, exists_prop] at hp
      obtain ⟨q, hq, hG, hr⟩ := hp
      obtain ⟨i, hz⟩ : ∃ i, z i q ≠ sv i :=
        not_forall.mp fun hall ↦ hpre q hq ⟨hG, hall⟩
      have hb := hRC q (List.ofFn f) (List.length_ofFn) hr i
      refine le_trans ?_ (Finset.single_le_sum (f := fun q ↦ ∑ i : Fin n,
        (if RingBad (List.ofFn (sv i)) (z i q) (List.ofFn f) ∧ z i q ≠ sv i then (1 : ℝ≥0∞)
          else 0)) (fun _ _ ↦ zero_le) (hS.mem_toFinset.2 hq))
      refine le_trans ?_ (Finset.single_le_sum (f := fun i ↦
        (if RingBad (List.ofFn (sv i)) (z i q) (List.ofFn f) ∧ z i q ≠ sv i then (1 : ℝ≥0∞)
          else 0)) (fun _ _ ↦ zero_le) (Finset.mem_univ i))
      split_ifs with h
      · exact le_rfl
      · exact absurd ⟨hb, hz⟩ h
  calc (Fintype.card E : ℝ≥0∞)⁻¹ ^ 16 * ∑ f : Fin 16 → E, _
      ≤ (Fintype.card E : ℝ≥0∞)⁻¹ ^ 16 * ∑ f : Fin 16 → E, ∑ q ∈ T, ∑ i : Fin n,
          (if RingBad (List.ofFn (sv i)) (z i q) (List.ofFn f) ∧ z i q ≠ sv i then (1 : ℝ≥0∞)
            else 0) := by
        gcongr with f; exact hcover f
    _ = ∑ q ∈ T, ∑ i : Fin n, (Fintype.card E : ℝ≥0∞)⁻¹ ^ 16 * ∑ f : Fin 16 → E,
          (if RingBad (List.ofFn (sv i)) (z i q) (List.ofFn f) ∧ z i q ≠ sv i then (1 : ℝ≥0∞)
            else 0) := by
        simp only [Finset.mul_sum]
        rw [Finset.sum_comm]
        exact Finset.sum_congr rfl fun q _ ↦ Finset.sum_comm
    _ ≤ ∑ _q ∈ T, ∑ _i : Fin n, 2 / (Fintype.card E : ℝ≥0∞) := by
        refine Finset.sum_le_sum fun q _ ↦ Finset.sum_le_sum fun i _ ↦ ?_
        by_cases hz : z i q = sv i
        · simp [hz]
        · have hz' : sv i ≠ z i q := Ne.symm hz
          simpa [hz] using ringBad_ratio_le hz'
    _ = T.card * (n * (2 / Fintype.card E)) := by
        rw [Finset.sum_const, Finset.sum_const, Finset.card_univ, Fintype.card_fin, nsmul_eq_mul,
          nsmul_eq_mul]
    _ ≤ L₀ * (n * (2 / Fintype.card E)) := by
        gcongr
        rw [← Set.ncard_eq_toFinset_card S hS]
        exact_mod_cast hL

variable {εmax T : ℝ≥0∞}

/-- **Ring switching's specification**: from `RingPre` to `RingPost`, the grind's boundary
discounting the group's escape `L₀ · n · 2/|E|` and the follower's lead `T` (the opening's `λ`).
Lead `0`. -/
noncomputable def ringSpec (hRC : RingClaimBad pt z sv RC) (hS : S.Finite)
    {L₀ : ℕ} (hL : S.ncard ≤ L₀) (he : (L₀ : ℝ≥0∞) * (n * (2 / Fintype.card E)) < 1)
    (hε : (2 : ℝ≥0∞)⁻¹ ^ Whir.batchGrindingBits * (L₀ * (n * (2 / Fintype.card E)) + T) ≤
      εmax) :
    Spec (Verifier.ringSwitch (ringClaims pt sv)) (RingPre S G z sv) (RingPost S G RC) εmax 0 T :=
  Spec.congr (ringSwitch_eq_results pt sv).symm <|
    (Spec.grindPos (Post := fun _ h ↦ RingPre S G z sv h) (by decide) (fun _ h ↦ h) hε).bind
      fun _ ↦ Spec.ofNoMove (((samplesOnly_sampleN 16).bind fun _ ↦ SamplesOnly.ret _).noMove) he
        fun h₀ hpre ↦ escRet_ring_le S G pt z sv RC hRC hS hL h₀ hpre

end Ring

end
end LeanVM.Protocol.EndToEnd.Front
