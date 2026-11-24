/-
  LeanVM.Protocol.EndToEnd.Complete.Ring

  The honest run of ring switching: no prover message, a grind and sixteen challenges, and the
  ring-switching claim the program opens on the stack is true of the honest stack and has a
  multilinear weight, for the true slices of `q_keccak`.
-/

module

public import LeanVM.Protocol.EndToEnd.Front.RingMultilinear
public import LeanVM.Protocol.EndToEnd.Front.RingFidelity
public import LeanVM.Protocol.EndToEnd.Front.FlockPhase
public import LeanVM.Protocol.RingVerifier
public import LeanVM.Protocol.Whir.Complete.Script

/-!
# Completeness of ring switching

About the transcription of `crates/verifier/src/ring_switch.rs` (`ring_psi`,
`ring_target`, `ring_coefficients`, `ring_weight`, `ring_switch`) and `lib.rs` (the ring
claim on the stack) (`Verifier.ringSwitch`, `Verifier.ringSwitchClaim`;
`crates/pcs/src/ring_switch.rs`).

`ringSwitch claims` reads nothing: after a grind it draws sixteen challenges, `f` then `g`, of
the two-stage map `Φ(v) = Σ_p f_p Ψ(v)^(2^(8p))`, `Ψ(v) = Σ_b g_b v^(2^b)`, and returns, for each
claim `(point, s)`, the target `Σ_i x^i Φ(s_i)` and the weight `W(u) = Φ(eq(point, u))`
(`Ring.ringSwitch_eq`). The program opens `⟨eqAbove · W(take), q⟩ = target` on each claim's region
of the stack (research build: `q_keccak`'s, then `q_flock`'s).

For the true slices `s_i = ẑ_i(point)` of `q_keccak` (`KeccakGkr.slicesTrue`, what the Keccak
reduction's completeness `follows_keccak` gives) the target is the pairing
`Σ_i x^i Φ(ẑ_i(point))` (`Front.ringClaim_holds_iff`, `Ring.ringTarget_eq`), so the claim holds
(`ringClaim_holds_of_slicesTrue`); its weight is multilinear (`Front.isMultilinearFn_ringWeight`).

`follows_ringSwitch_leanIsa`: the honest prover, which passes the grind and receives the
challenges, follows the program on the two claims, and the claims it returns hold of the leanISA
instance's stack with multilinear weights, for the true slices of `q_keccak` and of `q_flock`. No
mismatch.
-/

namespace LeanVM.Protocol.EndToEnd.Complete

open LeanVM.Prover (Script)

open LeanVM.Parameters LeanVM.Semantics LeanVM.Protocol.Compile LeanVM.Protocol.Verifier
open LeanVM.Protocol.LeanIsa LeanVM.Protocol.Whir.Complete LeanVM.Protocol.KeccakGkr

@[expose] public section

/-- **The ring claim of true slices holds**: when the 64 slice claims hold of the block at `off`
where the layout places `region`, the program's ring claim on `region` holds of the stack, for any
sixteen challenges. -/
theorem ringClaim_holds_of_slicesTrue {layout : Verifier.Layout} {region h₅ off μ : ℕ}
    (hpl : layout.placement region = { variableCount := h₅ + 6, index := off })
    (hal : 2 ^ (h₅ + 6) ∣ off) (hfit : off + 2 ^ (h₅ + 6) ≤ 2 ^ μ) (q : Column μ)
    {pt sv ch : List E} (hs : slicesTrue h₅ (Front.qkAt off q) pt sv) (hch : ch.length = 16) :
    StackClaim.Holds μ (ringSwitchClaim layout region (Ring.ringTarget sv (ch.take 8) (ch.drop 8))
      fun rPrime ↦ ringWeight pt rPrime (Ring.ringCoefficients (ch.take 8) (ch.drop 8))) q := by
  obtain ⟨hpt, hsv, hsl⟩ := hs
  rw [Ring.take_eq_ofFn_fOf hch, Ring.drop_eq_ofFn_gOf hch]
  refine (Front.ringClaim_holds_iff hpl hal hfit q hpt _ _ _).mpr ?_
  have hsvf : sv = List.ofFn fun i : Fin 64 ↦ Front.sliceExt h₅ (Front.qkAt off q) pt i := by
    apply List.ext_getElem (by simp [hsv])
    intro i h1 h2
    have := hsl i (by simpa using h2)
    rw [List.getD_eq_getElem _ _ h1] at this
    rw [this, List.getElem_ofFn]
    rfl
  rw [hsvf, Ring.ringTarget_eq]

/-- **The honest prover of ring switching**: it sends nothing; it passes the grind, receives the
sixteen challenges and returns what the program returns, one result per claim. -/
def hRing (claims : List (List E × List E)) : Script (List (E × (List E → E))) :=
  (Script.grindBits Whir.batchGrindingBits).bind fun _ ↦
  (Script.sampleN 16).bind fun ch ↦
  .ret (claims.map fun c ↦ (Ring.ringTarget c.2 (ch.take 8) (ch.drop 8),
    fun rPrime ↦ ringWeight c.1 rPrime (Ring.ringCoefficients (ch.take 8) (ch.drop 8))))

attribute [local irreducible] Follows in
/-- **Completeness of ring switching at the verifier's layout**, for a stack of the leanISA
instance: for the true slices of its `q_keccak` block (`τ_KECCAK + 6` variables) and of its
`q_flock` block (`τ_BLAKE3 + 8` variables), the honest prover follows `ringSwitch` for every
challenge, and the two claims the program opens on the stack hold of it with multilinear
weights. -/
theorem follows_ringSwitch_leanIsa {prog : LeanIsaProgram} {s : Sizes}
    {q : Column (leanIsaμ prog s)} (kp ks fp fs : List E)
    (hk : slicesTrue (s.τ 5) (Front.qkAt ((blocks prog s).offset (keccakBlock prog s)) q) kp ks)
    (hf : slicesTrue (s.τ 6 + 2) (Front.qkAt (Front.qfOff prog s) q) fp fs)
    (cs : Commits) :
    Follows (fun cs' a b ↦ cs' = cs ∧ a = b ∧ b.length = 2 ∧
        ∀ c ∈ Front.ringStackClaims (Front.verifierLayout prog s) b,
          StackClaim.Holds (leanIsaμ prog s) c q ∧ IsMultilinearFn (leanIsaμ prog s) c.1)
      (hRing [(kp, ks), (fp, fs)]) (ringSwitch [(kp, ks), (fp, fs)]) cs := by
  have hlk := Front.ringLayoutHyp_verifierLayout prog s
  have hlf := Front.ringLayoutHyp_flock prog s
  rw [Ring.ringSwitch_eq, hRing]
  refine Follows.bind (fun cs₀ _ _ h ↦ ?_) _ _ _ (Follows.grindBits_grindP _ cs)
  subst h
  refine Follows.bind (fun cs' a b h ↦ ?_) _ _ _ (Follows.sampleN_sampleN _ 16)
  obtain ⟨rfl, rfl, hl⟩ := h
  refine Follows.ret_ret ⟨rfl, rfl, by simp, ?_⟩
  intro c hc
  simp only [List.map_cons, List.map_nil, Front.ringStackClaims, List.zipWith_cons_cons,
    List.zipWith_nil_right, List.mem_cons, List.not_mem_nil, or_false] at hc
  rcases hc with rfl | rfl
  · exact ⟨ringClaim_holds_of_slicesTrue hlk.placement hlk.aligned
      (by have := hlk.fits; rwa [Front.stackLog_verifierLayout] at this) q hk hl,
      Front.isMultilinearFn_ringWeight _ _ _ _⟩
  · exact ⟨ringClaim_holds_of_slicesTrue hlf.placement hlf.aligned
      (by have := hlf.fits; rwa [Front.stackLog_verifierLayout] at this) q hf hl,
      Front.isMultilinearFn_ringWeight _ _ _ _⟩

end
end LeanVM.Protocol.EndToEnd.Complete
