# Formal Proofs: Offline Finality + Non-Interference

Date: 2026-03-21
Paper: "Statelessness Reframed" (Ramsay, Oct 2025)

## What was proved

### Claim 1: Offline Finality (Paper Theorems 4.1, 4.2)

**TLA+ spec**: `tla/DSM_OfflineFinality.tla` (2 devices, 2 sessions, MaxChain=3)
**TLC result**: 2,702 distinct states, all 7 safety invariants verified

Invariants proved:
- BilateralIrreversibility: committed transfer cannot be undone
- FullSettlement: receiver balance is spendable
- NoHalfCommit: BLE partition -> both finalize or neither
- TripwireGuaranteesUniqueness: fork exclusion (Theorem 4.2)
- TokenConservation: no value creation/destruction
- BalancesNonNegative
- TypeOK

**Lean proofs**: `lean4/DSMOfflineFinality.lean`
- committed_balance_spendable (omega)
- commit_conservation (omega)
- tripwire_tip_strictly_advances (from BLAKE3 collision resistance axiom)
- tip_advance_prevents_reuse (omega)
- no_double_commit_same_tip (omega)

### Claim 2: Additive Scaling / Theta(N) (Paper Lemma 3.1, 3.2, Theorem 3.1)

**TLA+ spec**: `tla/DSM_NonInterference.tla` (4 devices, 2 disjoint pairs)
**TLC result**: 2,369 distinct states, all 5 safety invariants verified

Invariants proved:
- NonInterference (Lemma 3.1): if no session committed on a relationship, its state equals Init
- PairIsolation (Lemma 3.2): session relationships are well-typed
- PerPairConservation: token conservation holds independently per pair
- ZeroRefreshForInactive (Theorem 3.1): device with no active sessions has unchanged state
- TypeOK

**Lean proofs**: `lean4/DSMNonInterference.lean`
- relKey_symmetric: SMT key derivation is symmetric
- relKey_normalized: output is always (min, max)
- relKey_injective: distinct pairs produce distinct keys
- operation_locality: committing on pair1 does not modify pair2
- separation_inactive_zero_refresh (Theorem 3.1): inactive user refresh = 0
- separation_refresh_bound: refresh work <= trace length
- per_pair_conservation: balance sum preserved per pair

## Assumptions (axiomatized, not proved)

- BLAKE3 domain-separated hash is collision-resistant
- SPHINCS+ signatures are message-binding (EUF-CMA)
- Successor tip function produces distinct output from input
- Both peers follow the protocol (honest-but-unreliable model)
- BLE is unreliable (modeled as nondeterministic disconnect)

## CI Integration

- `tools/vertical_validation/src/tla_runner.rs`: 2 new TlaSpec entries in standard_specs()
- `tools/vertical_validation/src/proof_runner.rs`: 2 new ProofSpec entries in standard_specs()
- Lean files follow existing standalone pattern (no Mathlib dependency)

## File inventory

| File | LOC | Status |
|------|-----|--------|
| tla/DSM_OfflineFinality.tla | ~350 | TLC green |
| tla/DSM_OfflineFinality.cfg | ~30 | - |
| tla/DSM_NonInterference.tla | ~280 | TLC green |
| tla/DSM_NonInterference.cfg | ~30 | - |
| lean4/DSMOfflineFinality.lean | ~120 | Lean green |
| lean4/DSMNonInterference.lean | ~140 | Lean green |
