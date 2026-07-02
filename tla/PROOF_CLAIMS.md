# DSM TLAPS Proof Claims

This document states the exact scope of the machine-checked proof tiers for the
DSM formal models.

## Claim

Under the stated trust, fairness, and cryptographic assumptions, the DSM model's
safety core preserves:

- bounded issuance from the finite source supply,
- single-use spent JAP semantics,
- proof-artifact consistency between spent JAPs, minted proofs, and consumed proofs,
- monotone commitment growth for the modeled emission/activation path,
- tripwire fork exclusion in the concrete DSM protocol model,
- key-scoped fork exclusion for the GENERAL guarded kernel (guard family +
  derived resource consumption key), in both its static and trace-level forms.

The TLAPS milestone is implemented as machine-checked TLAPS proofs over:

- `DSM_Abstract.tla`,
- `DSM_ProtocolCore.tla`,
- `DSM.tla`.

The guarded kernel (paper Appendix A/B) is machine checked as:

- `lean4/DSMGuardedTripwire.lean`: the universal theorems
  (`realized_unique_at_key`, `guarded_tripwire_at_key`/`_exists`,
  `hardened_single_consumption`, `no_resource_local_cycle`, and companions).
  The uniqueness/tripwire core depends on NO axioms; only the paper's labeled
  cryptographic Assumptions appear as axioms, and only where the paper uses them.
- `lean4/DSMGuardedOffline.lean`: offline bearer double-spend exclusion and
  clone exclusion, with the unforgeability assumption used only where the
  paper's Theorem 13 uses it.
- `tla/DSM_Guarded.tla` + instances: TLC model checks of concrete guard
  families, including deliberate falsification. The static Theorem 2/4 form
  (`Safety`) holds for a well-formed family and is violated by a key-split
  family; the trace-level form (`RealizedHistoryUnique`) holds at any single
  honest verifier even under a malformed family (paper Prop 11).
- `tla/DSM_GuardedBilateral.tla` + instances: the same-parent multi-receiver
  fork is unconstructible in online DSM. The model encodes relationship-scoped
  derived keys (every relationship is its own straight hash chain, paper
  Sec 6, Def 27/33, Rule 2) and the bilateral single-receiver topology (the
  acceptor of a relationship step is that relationship's counterparty); TLC
  verifies that a family containing an attempted same-parent conflict cannot
  fork in any interleaving, and the structure-removed contrast instance shows
  deleting exactly those mechanisms is what re-admits the fork (expected
  violation).

Additional focused models may be checked with TLC to make narrower claims
about subsystem trust boundaries. In particular,
`DSM_dBTC_TrustReduction.tla` states the dBTC mainnet trust predicate
explicitly, but it still remains a model-level claim rather than a proof of
Bitcoin consensus or Rust implementation correctness.

## TLAPS OMITTED obligations and the Lean bridge

The TLAPS modules contain OMITTED steps for finite-set cardinality arithmetic
that the TLAPS backends (Zenon, Isabelle, Z3 as invoked) cannot discharge.
These obligations are enumerated, stated, and proved in
`lean4/DSMCardinality.lean` under the documented correspondence between TLA+
`Cardinality` over finite sets and Lean `List.length` over duplicate-free
lists; the file header carries the obligation-by-obligation map. The honest
external claim is therefore "TLAPS and Lean jointly," not "TLAPS alone." Anyone
running `tlapm` directly will see the OMITTED steps before finding the Lean
bridge; this section exists so that observation resolves to the bridge rather
than to an unexplained gap. Closing the cardinality steps natively (for
example via `FiniteSetTheorems!FS_AddElement`) remains a welcome improvement
and would not change any claim above.

## Assumptions

- Signature, hash, and KEM soundness are external assumptions.
- The TLAPS toolchain, backend provers, and local execution environment are trusted.
- The Lean 4 kernel and pinned toolchain (`lean4/lean-toolchain`) are trusted.
- The protocol proof is about the TLA+ and Lean models, not the Rust implementation.
- Finite model constants such as `DeviceIds`, `GenesisIds`, and `VaultIds` are
  interpreted as finite sets in the intended protocol configurations.

## Not Proved In This Milestone

- No cryptographic proof for SPHINCS+, ML-KEM, BLAKE3, or any quantum-resistance claim.
- No machine-checked proof for the Rust implementation or model-to-code refinement.
- No proof of Bitcoin PoW / Nakamoto consensus security from first principles.
- No full bilateral or DLV liveness proof in `DSM_BilateralLiveness.tla`.
- No TLAPS mechanization of the guarded kernel itself: the general theorems are
  Lean-proved and TLC-checked; porting them to TLAPS is future work.
- The paper's category-theoretic layer (projection functor, fiberwise thinness)
  and Section 19 multi-party authority remain paper-only.
- No claim that the entire DSM protocol is proved end-to-end.

## Intended Reading

The correct public claim after this milestone is:

"DSM has a machine-checked proof tier: TLAPS (with Lean-discharged cardinality
obligations) for the safety/refinement core, Lean 4 theorems for the general
guarded kernel including key-scoped fork exclusion, and a TLC bounded
verification suite that model-checks the kernel's static and trace-level
invariants, verifies that relationship scoping plus the bilateral
single-receiver topology make same-parent multi-receiver forks unconstructible
in online DSM, and demonstrates by deliberate falsification that guard-family
well formedness and that structure are load bearing."
