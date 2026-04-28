# DSM Formal Verification Report

| Field | Value |
|-------|-------|
| Date | 2026-04-28 |
| Git Commit | `f4fc6b8` |
| Branch | `DLV-fix` |
| DSM Version | 0.1.0-beta.2 |
| Lean Toolchain | Lean (version 4.30.0-rc2, arm64-apple-darwin24.6.0, commit 3dc1a088b6d2d8eafe25a7cd7ec7b58d731bd7cc, Release) |
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
| DSMCardinality.lean | Mathematical Proof | Whitepaper §16.6 | Finite-set cardinality for TLAPS obligations | PASS |
| DSMCryptoBinding.lean | Mathematical Proof | Whitepaper §5 | Signature retargeting prevention, domain separation | PASS |
| DSMNonInterference.lean | Mathematical Proof | SR Thm 3.1 | SMT key injectivity, separation theorem | PASS |
| DSMOfflineFinality.lean | Mathematical Proof | Whitepaper Thm 4.1, 4.2 | Chain-tip monotonicity, balance conservation | PASS |
| DSM_dBTC_Conservation.lean | Mathematical Proof | dBTC Paper §19 | Bridge conservation (11 actions) | PASS |
| DSM_dBTC_TrustReduction.lean | Mathematical Proof | dBTC Paper §14–15 | Trust reduction, mainnet settlement evidence | PASS |
| state_machine_transfer_chain | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| state_machine_signature_rejection | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| state_machine_fork_divergence | Implementation | Whitepaper §16.6 | State machine transition invariants | PASS |
| bilateral_precommit_tripwire | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| bilateral_precomputed_finalize_hash | Implementation | Whitepaper §3.4 | Bilateral protocol mechanics | PASS |
| tripwire_parent_consumption | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| receipt_verifier_tripwire | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
| tripwire_first_contact_binding | Implementation | Whitepaper Thm 2 | Tripwire enforcement in real code | PASS |
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
| DSM_tiny | 10,938 | 3,444 | 10 | 5 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_repeated_emission_alignment, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| DSM_small | 35,960 | 5,727 | 8 | 4 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| DSM_system | 164,525 | 13,232 | 7 | 4 | state_machine_transfer_chain, state_machine_signature_rejection, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash, djte_emission_happy_path, djte_supply_underflow_rejection, dlv_manager_inventory_consistency, token_manager_balance_replay, token_manager_overspend_rejection | PASS |
| Tripwire | 42,793 | 4,681 | 6 | 8 | tripwire_parent_consumption, receipt_verifier_tripwire, tripwire_first_contact_binding, bilateral_precommit_tripwire, bilateral_precomputed_finalize_hash | PASS |
| OfflineFinality | 34,094 | 2,702 | 11 | 7 | bilateral_full_offline_finality | PASS |
| NonInterference | 21,693 | 2,369 | 10 | 5 | bilateral_pair_non_interference | PASS |

### Invariants Checked

**DSM_tiny**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening, SourceVaultBounded

**DSM_small**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening

**DSM_system**: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening

**Tripwire**: TripwireInvariant, ConsumedParentUniqueness, AcceptedReceiptsAdvance, ReceiptEndpointsMatchRelation, ReceiptChainContinuity, CurrentRelationshipAgreement, CurrentTipsWereAccepted, FirstContactBinding

**OfflineFinality**: TypeOK, BilateralIrreversibility, FullSettlement, NoHalfCommit, TripwireGuaranteesUniqueness, TokenConservation, BalancesNonNegative

**NonInterference**: TypeOK, NonInterference, PairIsolation, PerPairConservation, ZeroRefreshForInactive

## Lean 4 Machine-Checked Proofs

Toolchain: `Lean (version 4.30.0-rc2, arm64-apple-darwin24.6.0, commit 3dc1a088b6d2d8eafe25a7cd7ec7b58d731bd7cc, Release)`

| File | Theorems | Axioms | sorry? | Verdict |
|------|----------|--------|--------|---------|
| DSMCardinality.lean | 12 | 0 | No | PASS |
| DSMCryptoBinding.lean | 4 | 8 | No | PASS |
| DSMNonInterference.lean | 7 | 0 | No | PASS |
| DSMOfflineFinality.lean | 6 | 3 | No | PASS |
| DSM_dBTC_Conservation.lean | 23 | 0 | No | PASS |
| DSM_dBTC_TrustReduction.lean | 9 | 0 | No | PASS |

### Axioms (explicitly stated, not proved)

- `domainHash` (DSMCryptoBinding.lean) — Protocol-level cryptographic assumption
- `pkOf` (DSMCryptoBinding.lean) — Protocol-level cryptographic assumption
- `sign` (DSMCryptoBinding.lean) — Protocol-level cryptographic assumption
- `verify` (DSMCryptoBinding.lean) — Protocol-level cryptographic assumption
- `sign_verify_sound` (DSMCryptoBinding.lean) — Sign-then-verify roundtrip succeeds
- `verify_message_binding` (DSMCryptoBinding.lean) — SPHINCS+ signatures are message-binding for fixed (pk, sig)
- `domain_hash_injective` (DSMCryptoBinding.lean) — Domain separation prevents cross-tag hash collisions
- `claim_key_material_binding` (DSMCryptoBinding.lean) — dBTC claim key derivation is binding on (preimage, hash_lock)
- `domainHash` (DSMOfflineFinality.lean) — Protocol-level cryptographic assumption
- `domain_hash_injective` (DSMOfflineFinality.lean) — Domain separation prevents cross-tag hash collisions
- `successor_tip_distinct` (DSMOfflineFinality.lean) — Hash chain successor produces a value distinct from its input

### Theorem Inventory

**DSMCardinality.lean**: fresh_insert_cardinality, empty_card_zero, card_le_succ_of_le, card_succ_le_of_lt, supply_conservation_emit, commit_shape_emit, unspent_budget_emit, subset_preserved_ack, unspent_budget_init, unspent_budget_activate, emit_budget_positive, jap_in_proof_space

**DSMCryptoBinding.lean**: signed_digest_verifies, signature_retargeting_requires_same_digest, cross_domain_signature_retargeting_impossible, math_owned_claim_retargeting_impossible

**DSMNonInterference.lean**: relKey_symmetric, relKey_normalized, relKey_injective, operation_locality, separation_inactive_zero_refresh, separation_refresh_bound, per_pair_conservation

**DSMOfflineFinality.lean**: committed_balance_spendable, commit_conservation, tripwire_tip_strictly_advances, tip_advance_prevents_reuse, no_double_commit_same_tip, fail_preserves_balance

**DSM_dBTC_Conservation.lean**: fundVault_preserves_conservation, bitcoinTick_noop_preserves_conservation, bitcoinTick_confirm_preserves_conservation, transfer_preserves_conservation, transfer_sum_invariant, commit_preserves_conservation, selectVault_preserves_conservation, settle_preserves_conservation, settleFractional_preserves_conservation, fail_preserves_conservation, expire_preserves_conservation, noOp_preserves_conservation, init_safety, deposit_bounded, commit_bounded, settle_bounded, settleFractional_bounded, refund_bounded, expire_bounded, settled_monotone_settle, settled_monotone_noop, transfer_zero_sum_general, safety_preserved_if_supply_nonincreasing

**DSM_dBTC_TrustReduction.lean**: rustVerifierAccepted_implies_mainnet_finality, finalBurn_requires_mainnet_finality, finalBurn_requires_mainnet_network, non_mainnet_cannot_authorize_final_burn, applyFinalBurn_preserves_conservation, applyFinalBurn_sets_finalized, finalized_state_carries_mainnet_assumption, weakened_evidence_counterexample, weakened_evidence_does_not_reduce_to_mainnet

## Implementation Trace Replay

| Trace | Steps | Linked TLA+ Spec | Verdict | Time |
|-------|-------|-------------------|---------|------|
| state_machine_transfer_chain | 4 | DSM_system | PASS | 2.5s |
| state_machine_signature_rejection | 1 | DSM_system | PASS | 0.6s |
| state_machine_fork_divergence | 2 | — | PASS | 1.3s |
| bilateral_precommit_tripwire | 5 | Tripwire | PASS | 2.6s |
| bilateral_precomputed_finalize_hash | 4 | Tripwire | PASS | 1.3s |
| tripwire_parent_consumption | 3 | Tripwire | PASS | 0.0s |
| receipt_verifier_tripwire | 4 | Tripwire | PASS | 1.9s |
| tripwire_first_contact_binding | 3 | Tripwire | PASS | 1.9s |
| djte_emission_happy_path | 4 | DSM_system | PASS | 0.0s |
| djte_repeated_emission_alignment | 3 | DSM_tiny | PASS | 0.0s |
| djte_supply_underflow_rejection | 2 | DSM_system | PASS | 0.0s |
| dlv_manager_inventory_consistency | 5 | DSM_system | PASS | 28.2s |
| token_manager_balance_replay | 3 | DSM_system | PASS | 1.9s |
| token_manager_overspend_rejection | 1 | DSM_system | PASS | 0.6s |
| bilateral_full_offline_finality | 5 | OfflineFinality | PASS | 3.7s |
| bilateral_pair_non_interference | 6 | NonInterference | PASS | 2.5s |

## Property-Based Tests

Seed: `42` | Total: 221.7s

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
| self_hash_forgery | rejected (Ok(false) or Err) | Ok(false) | PASS |
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

## Bilateral Throughput

| Mode | Ops/sec | P50 | P95 | P99 |
|------|---------|-----|-----|-----|
| With SPHINCS+ signing | 1.6 | 624623µs | 645632µs | 649267µs |
| Without signing | 2 | 18704µs | 21030µs | 22026µs |

Keygen: 31ms | Avg sign: 603.2ms | Avg BLAKE3: 1.1µs

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
All results reflect a single deterministic run against commit `f4fc6b8`.

**Report Body BLAKE3** (`DSM/formal-verification-report-v1`)**:** `93eaa415a1d7d9ecf0793ccf34f582a979c958df3cc7113491437074b596532d`

### Signature

```
Signer: ____________________________
Date:   ____________________________
GPG Key: ____________________________
```

_To sign: `git add` this file, then `git commit -S` and push to GitHub._
_The GPG signature is embedded in the git commit object and verifiable via `git log --show-signature`._
