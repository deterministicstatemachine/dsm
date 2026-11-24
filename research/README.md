# Research

## `leanvm/`: per-trade vault proofs

A fork of [leanVM](https://github.com/leanEthereum/leanVM) (imported at `68b4844b`, with its own history)
built for the owner's 2026-11-22 ruling that a vault's state carries a hash-based recursive proof
per trade, so a reader checks one proof per vault and never walks history.

What it adds to leanVM:

- **A `BLAKE3` instruction**, proven by [Flock](https://eprint.iacr.org/2026/1329) (a binary-field
  prover for batches of BLAKE3 compressions) instead of bit-by-bit arithmetic.
- **The vault step** as a leanVM program: one trade's state change, checked and chained onto the
  previous proof (`crates/`, `guests/`).
- **In-VM Flock verification**, so a proof can verify its child proof.

Measured: one vault step proves in 2.28 s with 725 MB on a Samsung Galaxy A16, and a proof checks in about 95 ms.

### Tests

The Lean model's verifier accepts all 14 proofs the Rust prover made, and 3,500 mutated proofs
showed no difference between the two. The Lean prover's proofs are byte-identical to the Rust's,
and the executors agree cell for cell. Five real aggregations (up to 644,500 steps) run and match.

### Proofs (`formal/`)

Kernel-checked, with only Lean's standard axioms:

- **Knowledge soundness**: `knowledgeSoundness_holds : FlockSound → KnowledgeSoundness …`.
- **Completeness**: `completeness_holds : FlockWalk → FlockComplete → Completeness`.
- The Statement's executable prover is the specification's honest prover.

These are **conditional**. The three named hypotheses are **not proved**:

- `FlockSound`: Flock's reduction is sound.
- `FlockWalk`: Flock's BLAKE3 circuit computes the compression and keeps its inputs.
- `FlockComplete`: the honest Flock prover is accepted.

Not yet building:

- **The efficient extractor's cost bounds.** The cost machine now runs BLAKE3; the bounds for
  Flock's phase are not written.
- **The guest proofs** (the verifier as a leanVM program). Seventeen modules fail, and the 143
  functions added for Flock and the vault step have no proofs.

### In DSM

DSM's Core depends on `aggregation` and `vault_step` by path (SoFi Amendment S36,
`dsm::sofi::vault_proof`). Each swap's trader proves its vault's step once its walk establishes it,
folding the previous record's proof, and publishes a record holding the vault's whole tree and the
proof (`dsm_sdk::sdk::vault_proof_io`). A reader starts at the newest record that verifies, judges the
one consumption it names, and never walks the vault's history. The owner baseline and the vault's
history that this replaces are gone.

The theorems above are what the proofs rest on, with their three unproved hypotheses.
