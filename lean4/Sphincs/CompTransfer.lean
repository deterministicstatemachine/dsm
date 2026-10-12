-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.CompRestate

/- Delta strategy (map §13), obligation T4, first part: DSM's real EUF-CMA
   game reaches the final world (PRG, KDF and PRF hops done) with the five
   named primitive advantages, and nothing else.

   The final world is DSM's signer with `PK.seed` uniform, the secret PRF a
   uniformly random function on `PK.seed ‖ ADRS`, and the message key a
   uniformly random function on `PK.seed ‖ M`. This is the point at which
   the published SPHINCS+ proof (EasyCrypt `EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF`)
   takes over, after the message embedding of obligation T3. No assumption
   beyond `OutputWidths`, no axiom, no `sorry`. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs DSM.Sphincs.Security

/-- **DSM's real game to its final world.**
    Pr[real forgery] ≤ Pr[final-world forgery] + Adv^PRF_MKG + Adv^KDF_MKG
      + Adv^PRF_SKG + Adv^KDF_SKG + Adv^PRG, each the exact advantage of the
    hop's own distinguisher in a PRG or PRF game on the named primitive. -/
theorem euf_cma_final (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) :
    fle (eufCmaProbability v limits o coins).frac
      (fadd (fadd (fadd (fadd (fadd
        (idealMsgFunctionProbability v limits o coins).frac
        (dsmMkgPrfAdv o v limits.maxMessageBytes (msgFuncD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf-msg" (msgKeyD v limits o coins)))
        (dsmSkgPrfAdv o v (funcD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf" (keyD v limits o coins)))
        (dsmPrgAdv o v (seedD v limits o coins))) := by
  rw [← c16b_adv v limits o widths, ← c16a_adv, ← c15b_adv v limits o widths, ← c15a_adv, ← c11_adv]
  have h1 := hop_frac _ _ _ (seed_hybrid_real_equivalence v limits o coins).symm
    (seed_prg_hybrid_bound v limits o coins)
  have h2 := hop_frac _ _ _ (prf_key_real_equivalence v limits o coins).symm
    (prf_key_hybrid_bound v limits o coins)
  have h3 := hop_frac _ _ _ (prf_function_real_equivalence v limits o widths coins).symm
    (prf_function_hybrid_bound v limits o widths coins)
  have h4 := hop_frac _ _ _ (msg_key_real_equivalence v limits o coins).symm
    (msg_key_hybrid_bound v limits o coins)
  have h5 := hop_frac _ _ _ (msg_function_real_equivalence v limits o widths coins).symm
    (msg_function_hybrid_bound v limits o widths coins)
  have p := fun (P : Probability) => P.positive
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h1 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h2 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h3 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h4 ?_
  apply fadd_mono
  refine fle_trans (fadd_pos (p _) (adv_pos _ _)) h5 ?_
  apply fadd_mono
  exact Nat.le_refl _


/-- **The transfer theorem's shape** (obligation T4). For any bound `B` on the
    final-world forgery probability, the real game is bounded by `B` plus the
    five named primitive advantages. Under the delta strategy, `B` is the
    published SPHINCS+ bound (EasyCrypt `EUFCMA_SPHINCS_PLUS`) for the
    embedded forger, with DSM's functions instantiated as recorded in
    `SPHINCS_EC_CORRESPONDENCE.md`. That premise is a hypothesis here, never
    an axiom. -/
theorem euf_cma_transfer (v : Variant) (limits : Limits) (o : Oracle Id) (widths : OutputWidths o)
    (coins : FiniteExperiment Strategy) (B : Nat × Nat)
    (premise : fle (idealMsgFunctionProbability v limits o coins).frac B) :
    fle (eufCmaProbability v limits o coins).frac
      (fadd (fadd (fadd (fadd (fadd B
        (dsmMkgPrfAdv o v limits.maxMessageBytes (msgFuncD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf-msg" (msgKeyD v limits o coins)))
        (dsmSkgPrfAdv o v (funcD v limits o coins)))
        (dsmKdfAdv o v "DSM/sphincs/v2/prf" (keyD v limits o coins)))
        (dsmPrgAdv o v (seedD v limits o coins))) := by
  have h := euf_cma_final v limits o widths coins
  have pos : ∀ (P : Probability), 0 < P.frac.2 := fun P => P.positive
  refine fle_trans ?_ h ?_
  · exact fadd_pos (fadd_pos (fadd_pos (fadd_pos (fadd_pos (pos _) (Nat.mul_pos (Probability.positive _)
      (Probability.positive _))) (Nat.mul_pos (Probability.positive _) (Probability.positive _)))
      (Nat.mul_pos (Probability.positive _) (Probability.positive _)))
      (Nat.mul_pos (Probability.positive _) (Probability.positive _)))
      (Nat.mul_pos (Probability.positive _) (Probability.positive _))
  · exact fadd_mono _ (fadd_mono _ (fadd_mono _ (fadd_mono _ (fadd_mono _ premise))))

#print axioms euf_cma_final
#print axioms euf_cma_transfer
end DSM.Sphincs.Comp
