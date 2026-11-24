/-
  LeanVM.Protocol.EndToEnd.Front.FlockPhase

  Flock's phase of the verifier program (research build): what it returns, proved, and its
  soundness in the doom calculus, `FlockSound`, a named hypothesis that is NOT proved.
-/

module

public import LeanVM.Protocol.EndToEnd.Front.KeccakBridge
public import LeanVM.Protocol.EndToEnd.Front.RingFidelity
public import LeanVM.Protocol.Compile.SpecRules.Grind

/-!
# Flock's phase

`flockPhase layout` (`Statement/LeanVmVerifier.lean`) runs Flock's zerocheck and lincheck on the
`BLAKE3` table's instances and returns a point of `q_flock` and its sixty-four bit-slice claims,
which ring switching takes as its second region.

Proved here: the point has `τ_BLAKE3 + 8` coordinates and there are `64` slices
(`retOK_flockPhase_verifierLayout`).

**Not proved: `FlockSound`.** It states, for admissible sizes and any finite set `S` of at most one
candidate stack, any predicate `R` of the candidates fixed before the phase, and any follower lead
`T ≤ 2^-125`, that there is a specification of `flockPhase` in the doom calculus:

* from "no candidate of `S` meets `R` and Flock's predicate on its committed `q_flock`"
  (`FlockAuxQ`, the instance's `flockAux`: every instance of the `BLAKE3` table is accepted by
  Flock's walk);
* to "no candidate of `S` meets `R` with `q_flock`'s true slices at the returned point equal to
  the returned slices" (`FlockSlicesTrue`, the slices ring switching reads on region `QFLOCK`);
* every group of challenges at most `εmsg = 2^-125` after the grind before it, lead at most `εmsg`.

This is the soundness of Flock's reduction (the zerocheck with seven fixed `F_2`-independent
coordinates, the univariate skip, the equality sumcheck, the lincheck) together with the check that
its error terms fit `2^-125` at one candidate. Nothing in this repository proves it; the theorems
that use it take it as a hypothesis in their statements.
-/

namespace LeanVM.Protocol.EndToEnd.Front

open LeanVM.Parameters LeanVM.Semantics LeanVM.Protocol LeanVM.Protocol.Compile
open LeanVM.Protocol.Verifier LeanVM.Protocol.LeanIsa
open LeanVM.Protocol.EndToEnd.Sound (RetOK RetOK.ret RetOK.bind RetOK.bind_true RetOK.readN)
open scoped ENNReal

@[expose] public section

/-! ## What the phase returns -/

/-- `sampleChallenges n` returns `n` challenges. -/
theorem retOK_sampleChallenges : ∀ n : ℕ, RetOK (fun xs : List E ↦ xs.length = n)
    (VerifierProgram.sampleChallenges n)
  | 0 => RetOK.ret rfl
  | n + 1 => RetOK.bind_true fun _ ↦ (retOK_sampleChallenges n).bind fun xs hxs ↦
      RetOK.ret (by simp [hxs])

/-- Flock's zerocheck returns a point of `7 + (log n − 13)` coordinates. -/
theorem retOK_verifyFlockZerocheck (logN : ℕ) :
    RetOK (fun zc : FlockZerocheck ↦ zc.chi.length = 7 + (logN - flockKSkip - nFixedChallenges))
      (verifyFlockZerocheck logN) := by
  unfold verifyFlockZerocheck
  refine RetOK.bind_true fun _ ↦ (retOK_sampleChallenges _).bind fun sampled hs ↦
    RetOK.bind_true fun _ ↦ RetOK.bind_true fun _ ↦ RetOK.bind_true fun _ ↦ ?_
  refine (retOK_sumcheck 3 _ _).bind fun r hr ↦ ?_
  obtain ⟨chi, running⟩ := r
  refine RetOK.bind_true fun _ ↦ RetOK.bind_true fun _ ↦ RetOK.ret ?_
  simp only [List.length_map, List.length_append, hs] at hr
  simpa [flockFixedChallenges] using hr

/-- Flock's lincheck keeps the zerocheck's point and returns `8` round challenges and `64` slices. -/
theorem retOK_verifyFlockLincheck (zc : FlockZerocheck) :
    RetOK (fun c : FlockClaims ↦ c.chi = zc.chi ∧ c.roundChallenges.length = flockNumLincheckRounds ∧
        c.s.length = 64)
      (verifyFlockLincheck zc) := by
  unfold verifyFlockLincheck
  refine RetOK.bind_true fun _ ↦ RetOK.bind_true fun _ ↦ ?_
  refine (retOK_sumcheck 3 _ _).bind fun r hr ↦ ?_
  obtain ⟨rc, rLc⟩ := r
  refine (RetOK.readN _).bind fun s hs ↦ RetOK.bind_true fun _ ↦ RetOK.ret ?_
  simp only [List.length_replicate] at hr
  exact ⟨rfl, hr, hs⟩

/-- **Flock's phase returns a point of `h + 8` coordinates and `64` slices**, `h` the `BLAKE3`
table's announced height. -/
theorem retOK_flockPhase (layout : Verifier.Layout) :
    RetOK (fun f : List E × List E ↦
        f.1.length = layout.tableLogHeights.getD opBlake3 0 + 8 ∧ f.2.length = 64)
      (flockPhase layout) := by
  unfold flockPhase verifyFlock
  simp only [VerifierProgram.bind_eq, VerifierProgram.bind_assoc]
  refine (retOK_verifyFlockZerocheck _).bind fun zc hz ↦ (retOK_verifyFlockLincheck zc).bind
    fun c hc ↦ RetOK.ret ?_
  obtain ⟨hchi, hrc, hs⟩ := hc
  refine ⟨?_, hs⟩
  simp only [FlockClaims.point, List.length_append, List.length_drop, List.length_take,
    List.length_reverse, hrc, hchi, hz, qflockSlotBits, flockNumLincheckRounds, blake3R1csLogSize,
    flockKSkip, nFixedChallenges]
  omega

/-- The `BLAKE3` height of the verifier's layout is `τ_BLAKE3`. -/
theorem tableLogHeights_blake3 (prog : LeanIsaProgram) (s : Sizes) :
    (verifierLayout prog s).tableLogHeights.getD opBlake3 0 = s.τ 6 := by
  simp [verifierLayout, tableLogs, opBlake3]

/-- On the verifier's layout, Flock's point has `τ_BLAKE3 + 2 + 6` coordinates, `q_flock`'s
region's. -/
theorem retOK_flockPhase_verifierLayout (prog : LeanIsaProgram) (s : Sizes) :
    RetOK (fun f : List E × List E ↦ f.1.length = s.τ 6 + 2 + 6 ∧ f.2.length = 64)
      (flockPhase (verifierLayout prog s)) :=
  (retOK_flockPhase _).mono fun f hf ↦ ⟨by rw [hf.1, tableLogHeights_blake3], hf.2⟩

/-! ## The slices and the hypothesis -/

section Slices

variable (prog : LeanIsaProgram) (s : Sizes)

/-- `q_flock`'s offset on the verifier's layout. -/
abbrev qfOff : ℕ := (blocks prog s).offset (flockBlock prog s)

/-- **`q_flock`'s true slices at `pt` are the claimed ones** `sl`: region `QFLOCK`, `τ_BLAKE3 + 2`
rows of sixty-four bits (`ringLayoutHyp_flock`). -/
def FlockSlicesTrue (q : Column (verifierLayout prog s).stackLog) (pt sl : List E) : Prop :=
  ∀ i : Fin 64, sliceExt (s.τ 6 + 2) (qkAt (qfOff prog s) q) pt i = sl.getD i 0

end Slices

/-- **Flock's soundness, a named hypothesis (NOT proved).** At admissible sizes, for any finite
set `S` of at most one candidate stack, any predicate `R` of the candidates and any follower lead
`T ≤ 2^-125`, `flockPhase` has a specification from "no candidate meets `R` and Flock's predicate
`FlockAuxQ`" to "no candidate meets `R` with true `q_flock` slices at the returned point", every
group at most `2^-125` after its grind, lead at most `2^-125`. -/
def FlockSound : Prop :=
  ∀ (prog : LeanIsaProgram) (s : Sizes), s.Admissible prog →
    ∀ (S : Set (Column (verifierLayout prog s).stackLog)), S.Finite → S.ncard ≤ 1 →
    ∀ (R : Column (verifierLayout prog s).stackLog → Prop) (T : ℝ≥0∞), T ≤ εmsg →
      Nonempty (Spec (flockPhase (verifierLayout prog s))
        (fun _ ↦ ∀ q ∈ S, ¬ (R q ∧ FlockAuxQ prog s q))
        (fun f _ ↦ ∀ q ∈ S, ¬ (R q ∧ FlockSlicesTrue prog s q f.1 f.2))
        εmsg εmsg T)

end
end LeanVM.Protocol.EndToEnd.Front
