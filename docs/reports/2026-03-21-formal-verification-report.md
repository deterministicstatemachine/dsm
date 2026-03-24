# DSM Formal Verification Report

| Field | Value |
|-------|-------|
| Date | 2026-03-21 |
| Git Commit | `914f745` |
| Branch | `crypt` |
| DSM Version | 0.1.0-beta.1 |
| SPHINCS+ Variant | SPX-SHAKE-256f |
| Post-Quantum KEM | ML-KEM-768 |

## Overall Verdict

**ALL PASS**

## Verification Matrix

| Check | Level | Paper Reference | Scope | Verdict |
|-------|-------|-----------------|-------|---------|
| DSM_tiny (TLC) | Abstract Model | Whitepaper §16.6 | Core DSM safety invariants | PASS |
| DSM_small (TLC) | Abstract Model | Whitepaper §16.6 | Core DSM safety invariants | PASS |
| DSM_system (TLC) | Abstract Model | Whitepaper §16.6 | Core DSM safety invariants | PASS |
| Tripwire (TLC) | Abstract Model | Whitepaper Thm 2 | Fork exclusion via atomic interlock | PASS |
| OfflineFinality (TLC) | Protocol Mechanics | Whitepaper Thm 4.1, 4.2; SR §4 | Settlement irreversibility, partition tolerance | PASS |
| NonInterference (TLC) | Protocol Mechanics | SR Lemma 3.1, 3.2, Thm 3.1 | Bilateral isolation, Θ(N) scaling core | PASS |
| state_machine_transfer_chain | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| state_machine_signature_rejection | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| state_machine_fork_divergence | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| bilateral_precommit_tripwire | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| bilateral_precomputed_finalize_hash | Implementation | Whitepaper §3.4 | Bilateral protocol mechanics | PASS |
| tripwire_parent_consumption | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| receipt_verifier_tripwire | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| djte_emission_happy_path | Implementation | Whitepaper §11–12 | DJTE emission mechanics | PASS |
| djte_repeated_emission_alignment | Implementation | Whitepaper §11–12 | DJTE emission mechanics | PASS |
| djte_supply_underflow_rejection | Implementation | Whitepaper §11–12 | DJTE emission mechanics | PASS |
| dlv_manager_inventory_consistency | Implementation | Whitepaper §13 | DLV vault lifecycle | PASS |
| token_manager_balance_replay | Implementation | Whitepaper §16.6 | Token state management | PASS |
| token_manager_overspend_rejection | Implementation | Whitepaper §16.6 | Token state management | PASS |
| bilateral_full_offline_finality | Implementation | Whitepaper Thm 4.1, 4.2 | 3-phase commit through real Rust code | PASS |
| bilateral_pair_non_interference | Implementation | SR Lemma 3.1 | Disjoint managers, state isolation | PASS |
| Property-based tests | Integration | — | Randomized state machine transitions | PASS |
| Adversarial bilateral tests | Integration | — | Replay attacks, fork attempts | PASS |
| Crypto KATs | Primitive | — | BLAKE3, SPHINCS+, ML-KEM known answers | PASS |

### Abstraction Levels

- **Mathematical Proof** — Machine-checked Lean 4 theorems. Axioms stated explicitly. No `sorry`.
- **Abstract Model** — TLA+ specs verified by bounded TLC model checking. Finite state space.
- **Protocol Mechanics** — TLA+ specs modeling specific protocol claims (finality, isolation).
- **Implementation** — Deterministic traces through real Rust code (SPHINCS+ signing, BLAKE3 hashing).
- **Integration** — Randomized and adversarial tests across the full stack.
- **Primitive** — Known-answer tests for individual cryptographic primitives.

## TLA+ Model Checking

| Spec | States | Distinct | Depth | Invariants | Linked Traces | Verdict |
|------|--------|----------|-------|------------|---------------|---------|
| DSM_tiny | 25,046 | 8,038 | 11 | 5 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_repeated_emission_alignment, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| DSM_small | 30,997 | 7,164 | 7 | 4 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| DSM_system | 119,189 | 16,447 | 6 | 4 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| Tripwire | 12,649 | 1,581 | 5 | 1 | tripwire_parent_consumption, receipt_verifier_tripwire, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash | PASS |
| OfflineFinality | 7,467 | 2,702 | 11 | 7 | bilateral_full_offline_finality | PASS |
| NonInterference | 4,841 | 2,369 | 9 | 5 | bilateral_pair_non_interference | PASS |

### Invariants Checked

**DSM_tiny**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening, SourceVaultBounded

**DSM_small**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening

**DSM_system**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening

**Tripwire**: TripwireInvariant

**OfflineFinality**: TypeOK, BilateralIrreversibility, FullSettlement, NoHalfCommit, TripwireGuaranteesUniqueness, TokenConservation, BalancesNonNegative

**NonInterference**: TypeOK, NonInterference, PairIsolation, PerPairConservation, ZeroRefreshForInactive

## Implementation Trace Replay

| Trace | Steps | Linked TLA+ Spec | Verdict | Time |
|-------|-------|-------------------|---------|------|
| state_machine_transfer_chain | 4 | DSM_system | PASS | 4.5s |
| state_machine_signature_rejection | 1 | DSM_system | PASS | 1.1s |
| state_machine_fork_divergence | 2 | — | PASS | 2.2s |
| bilateral_precommit_tripwire | 5 | Tripwire | PASS | 42.0s |
| bilateral_precomputed_finalize_hash | 4 | Tripwire | PASS | 21.9s |
| tripwire_parent_consumption | 3 | Tripwire | PASS | 0.0s |
| receipt_verifier_tripwire | 3 | Tripwire | PASS | 20.6s |
| djte_emission_happy_path | 4 | DSM_system | PASS | 0.0s |
| djte_repeated_emission_alignment | 3 | DSM_tiny | PASS | 0.0s |
| djte_supply_underflow_rejection | 2 | DSM_system | PASS | 0.0s |
| dlv_manager_inventory_consistency | 5 | DSM_system | PASS | 12.0s |
| token_manager_balance_replay | 3 | DSM_system | PASS | 3.2s |
| token_manager_overspend_rejection | 1 | DSM_system | PASS | 1.1s |
| bilateral_full_offline_finality | 5 | OfflineFinality | PASS | 61.7s |
| bilateral_pair_non_interference | 6 | NonInterference | PASS | 43.3s |

## Property-Based Tests

Seed: `42` | Total: 373.2s

| Property | Iterations | Verdict |
|----------|------------|---------|
| hash_chain_continuity | 25 | PASS |
| state_number_monotonicity | 25 | PASS |
| entropy_determinism | 25 | PASS |
| token_conservation | 100 | PASS |
| non_negative_balances | 100 | PASS |
| fork_exclusion | 25 | PASS |
| signature_binding | 20 | PASS |

## Adversarial Bilateral Tests

| Attack | Expected | Actual | Verdict |
|--------|----------|--------|---------|
| double_spend_fork_detection | different hashes (fork detected) | fork detected: different ops produce different hashes | PASS |
| forged_signature | both rejected | forged=rejected wrong_key=rejected | PASS |
| replay_attack | unique new state or rejection | replay produces new unique state chained from current tip (not the original) | PASS |
| balance_underflow | checked_sub=None, saturating_sub=0 | checked_sub=None saturating_sub=0 | PASS |
| state_number_manipulation | rejected (Ok(false) or Err) | Ok(false) | PASS |
| hash_chain_break | rejected (Ok(false) or Err) | Ok(false) | PASS |

## Cryptographic Known-Answer Tests

| Primitive | Test | Verdict |
|-----------|------|---------|
| BLAKE3 | NUL terminator in domain tag | PASS |
| BLAKE3 | determinism | PASS |
| BLAKE3 | domain tag isolation | PASS |
| BLAKE3 | data differentiation | PASS |
| SPHINCS+ | deterministic keygen from seed | PASS |
| SPHINCS+ | key and signature sizes | PASS |
| SPHINCS+ | sign-verify round trip | PASS |
| SPHINCS+ | bit-flip rejection | PASS |
| SPHINCS+ | wrong-key rejection | PASS |
| ML-KEM-768 | key sizes | PASS |
| ML-KEM-768 | encapsulation sizes | PASS |
| ML-KEM-768 | decapsulate round trip | PASS |
| ML-KEM-768 | deterministic keygen | PASS |
| Pedersen | hiding property | PASS |
| Pedersen | binding property | PASS |
| Pedersen | commit-verify round trip | PASS |

## Bilateral Throughput

| Mode | Ops/sec | P50 | P95 | P99 |
|------|---------|-----|-----|-----|
| With SPHINCS+ signing | 0.9 | 1075237µs | 1161231µs | 1302888µs |
| Without signing | 1 | 31823µs | 33858µs | 46703µs |

Keygen: 50ms | Avg sign: 1036.1ms | Avg BLAKE3: 2.1µs

## Assumptions & Scope

### What is proved

- Settlement irreversibility under honest-but-unreliable model (Whitepaper Theorems 4.1, 4.2; *Statelessness Reframed* §4)
- Bilateral non-interference / additive scaling (*Statelessness Reframed* Lemma 3.1, Theorem 3.1)
- Token conservation and fork exclusion (Whitepaper §16.6, DSM_Abstract.tla)
- dBTC bridge conservation — 11 actions (dBTC Paper §19, DSM_dBTC_Conservation.lean)
- Tripwire fork-exclusion (Whitepaper Theorem 2, DSM_Tripwire.tla)

### What is axiomatized (not proved)

- BLAKE3 collision resistance (standard assumption)
- SPHINCS+ EUF-CMA security (NIST PQC standard)
- ML-KEM-768 IND-CCA2 security (NIST PQC standard)

### What is out of scope

- Byzantine fault tolerance (honest-but-unreliable model only)
- Storage node availability / liveness
- Unbounded state space (TLC is bounded; Apalache future work)
- Network-level attacks (Sybil, eclipse)

## Paper References

| Document | Relevant Sections |
|----------|---------|
| DSM Whitepaper | §3.4 (bilateral isolation), §15.1 (CAP escape), §16.6 (forward-only chains), Thm 2 (Tripwire), Thm 4 (conservation) |
| *Statelessness Reframed* (Ramsay, 2025) | Def 2.1 (PRLSM), Lemma 3.1 (non-interference), Lemma 3.2 (locality), Thm 3.1 (separation), Thm 4.1 (pending-online lock), Thm 4.2 (atomic interlock tripwire) |
| dBTC Bridge Paper | §14 Invariant 7, §15 Property 9, §19 Property 12 (conservation) |

## Auditor Notes

_Space for reviewer comments, observations, or caveats._

| # | Note | Author | Date |
|---|------|--------|------|
| 1 | | | |
| 2 | | | |
| 3 | | | |

---

## Attestation

This report was generated automatically by `dsm_vertical_validation`.
All results reflect a single deterministic run against commit `914f745`.

**Report Body BLAKE3** (`DSM/formal-verification-report-v1`)**:** `f1750ad6e295c26f43ff694b68adbb1fb4251602b3dbab20a791519058194f35`

### Signature

```
Signer: ____________________________
Date:   ____________________________
GPG Key: ____________________________
```

_To sign: `git add` this file, then `git commit -S` and push to GitHub._
_The GPG signature is embedded in the git commit object and verifiable via `git log --show-signature`._
