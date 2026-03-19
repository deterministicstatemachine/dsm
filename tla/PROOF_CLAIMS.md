# DSM TLAPS Proof Claims

This document states the exact scope of the first TLAPS proof milestone for the
DSM TLA+ models.

## Claim

Under the stated trust, fairness, and cryptographic assumptions, the DSM model's
safety core preserves:

- bounded issuance from the finite source supply,
- single-use spent JAP semantics,
- proof-artifact consistency between spent JAPs, minted proofs, and consumed proofs,
- monotone commitment growth for the modeled emission/activation path,
- tripwire fork exclusion in the concrete DSM protocol model.

This milestone is implemented as machine-checked TLAPS proofs over:

- `DSM_Abstract.tla`,
- `DSM_ProtocolCore.tla`,
- `DSM.tla`.

Additional focused models may be checked with TLC to make narrower claims
about subsystem trust boundaries. In particular,
`DSM_dBTC_TrustReduction.tla` states the dBTC mainnet trust predicate
explicitly, but it still remains a model-level claim rather than a proof of
Bitcoin consensus or Rust implementation correctness.

## Assumptions

- Signature, hash, and KEM soundness are external assumptions.
- The TLAPS toolchain, backend provers, and local execution environment are trusted.
- The protocol proof is about the TLA+ models, not the Rust implementation.
- Finite model constants such as `DeviceIds`, `GenesisIds`, and `VaultIds` are
  interpreted as finite sets in the intended protocol configurations.

## Not Proved In This Milestone

- No cryptographic proof for SPHINCS+, ML-KEM, BLAKE3, or any quantum-resistance claim.
- No machine-checked proof for the Rust implementation or model-to-code refinement.
- No proof of Bitcoin PoW / Nakamoto consensus security from first principles.
- No full bilateral or DLV liveness proof in `DSM_BilateralLiveness.tla`.
- No claim that the entire DSM protocol is proved end-to-end.

## Intended Reading

The correct public claim after this milestone is:

"DSM has a machine-checked TLAPS proof tier for the safety/refinement core of
the protocol model, alongside the existing TLC bounded verification suite."
