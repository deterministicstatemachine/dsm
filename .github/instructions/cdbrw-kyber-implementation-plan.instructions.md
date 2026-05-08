---
applyTo: '**'
---
# C-DBRW Post-Quantum Integration — Implementation Plan v4

**Context:** Solo developer, zero users, pre-beta. No migration. No backward compatibility. Rip and replace.

**Source of truth:** C-DBRW paper Rev 2.0 (with RDS formulation, quantitative bounds, UC framework, adversarial cryptanalysis, deployment safeguards).

---

## Changes From v3

v3 was correct on protocol flow, domain tags, crypto wiring, entropy health, manufacturing gates, and quantitative bounds. v4 changes scope and two key decisions:

1. **Full DBRW rip-out.** The old timing-based DBRW binding (dbrw.rs, dbrw_commitment.rs, dbrw_health.rs, DbrwHealthState.kt, DbrwValidationResult.kt, DbrwHealthNotification.tsx, dbrwHealth.ts, dbrwReportService.ts, dbrw_validation.rs, dbrw_export_report.rs, soft_vault_dbrw_integration.rs, jni/dbrw.rs) is deleted entirely. C-DBRW replaces it at every callsite. The old migration state machine is gone. C-DBRW doesn't need environment migration because the chaotic attractor is thermally resilient by construction.

2. **ML-KEM-768, not Kyber-1024.** 128-bit PQ security is sufficient for ephemeral device authentication. ML-KEM-768 is NIST's primary recommendation. **Paper Appendix B must be updated.**

3. **Genesis performance fix.** Current genesis takes 10-30 seconds. Root cause: `generate_sphincs_keypair()` defaults to `SPX256s` (slow: n=32, h=64, d=8, top tree = 256 leaves). Fix: switch to `SPX256f` (fast: n=32, h=68, d=17, top tree = 16 leaves). ~10x faster keygen. Signing is larger (49,856 vs 29,792 bytes) but genesis only signs once. **Target: genesis < 2 seconds.**

4. **Canons review items integrated.** UUID in performance.rs, PBI serialization duplication, PBT coverage for crypto primitives.

---

## Decision Log

| Decision | v3 | v4 | Rationale |
|----------|----|----|-----------|
| Kyber level | 1024 (Level 5) | **768 (Level 3)** | 128-bit PQ sufficient for ephemeral auth; NIST primary rec; -480B payload |
| Old DBRW | Keep alongside | **Delete entirely** | No users, no migration needed, C-DBRW replaces all functionality |
| SPHINCS+ genesis variant | SPX256s (default) | **SPX256f** | 10x faster keygen; genesis < 2s vs 10-30s |
| Orbit length | N=16384 | N=16384 | Unchanged |
| Entropy health | 3-condition test | 3-condition test | Unchanged |
| Compression algorithm | deflate | **LZ78** | Paper Def. 4.14 specifies LZ78; proofs bound against LZ78 rate |

---

## Phase 0 — Prerequisite Fixes (Canons Review)

**Goal:** Fix canons review issues before touching crypto.

**0a.** Replace `Uuid::new_v4()` in performance.rs with monotonic `AtomicU64` counter.

**0b.** PBI serialization duplication goes away when old DBRW is deleted. Verify after Phase 1.

**Effort: 0.5 day**

---

## Phase 1 — Delete Old DBRW + BLAKE3 in C++

**Goal:** Rip out old DBRW. Kill SHA-256 fallback. All hashing is BLAKE3 with domain separation.

### Delete List

**Rust:** `dbrw.rs`, `dbrw_commitment.rs`, `dbrw_commitment_test.rs`, `dbrw_health.rs`, `jni/dbrw.rs`, `dbrw_validation.rs`, `dbrw_export_report.rs`, `dbrw_export_report_tests.rs`, `soft_vault_dbrw_integration.rs`

**Kotlin:** `DbrwHealthState.kt`, `DbrwValidationResult.kt`

**Frontend:** `DbrwHealthNotification.tsx`, `dbrwHealth.ts`, `dbrwReportService.ts`

**Docs:** `dbrw.instructions.md`, `DBRW_HEALTH_DIAGNOSTICS_IMPLEMENTATION.md`, `DBRW_VISUALIZER_README.md`, `dbrw_drift_visualizer.py`

Use compiler errors as the exhaustive checklist after deletion.

### BLAKE3 in C++

Add `cpp/blake3/`, `cpp/dsm_domain_hash.h`, update CMakeLists, add JNI `nativeBlake3DomainHash`, delete SHA-256 fallback in SiliconFingerprint.kt.

**Effort: 2-3 days**

---

## Phase 2 — Challenge-Seeded Orbit + ACD + Orbit Length + Genesis Fix

**Goal:** Wire Alg. 1 step 1, Alg. 2 step 8. Fix genesis performance.

- Seed orbits: `x_0 = H("DSM/cdbrw-seed\0" || c || K_DBRW) mod 2^32`
- ACD: `H("DSM/attractor-commit\0" || H_bar || epsilon_intra || B || N || r)`
- N = 16384
- Threshold: `tau = (epsilon_intra + epsilon_inter) / 2`
- Switch `generate_sphincs_keypair()` from SPX256s to SPX256f
- New `crypto/cdbrw_binding.rs` replaces old dbrw.rs for K_DBRW derivation

**Effort: 2-3 days**

---

## Phase 3 — ML-KEM-768 Deterministic Encapsulation in C++

**Goal:** Deterministic Kyber encap per Alg. 3 steps 3-4. Rust already uses 768.

- Vendor pqcrystals ML-KEM-768 reference C
- Deterministic coins: `H("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)[0:32]`
- k_step: `H("DSM/kyber-ss\0" || ss)`
- `-DKYBER_K=3` in CMakeLists
- JNI bridge `CdbrwKyberNative.kt`

**Effort: 2-3 days**

---

## Phase 4 — SPHINCS+ Ephemeral Key Chain

**Goal:** Alg. 3 steps 6-8. Ephemeral key derivation + signing.

- `E_{n+1} = HKDF-BLAKE3("DSM/ek\0", h_n || C_pre || k_step || K_DBRW)`
- `(EK_sk, EK_pk) = SPHINCS+.KeyGen(E_{n+1})` using SPX256f
- `sigma = SPHINCS+.Sign(EK_sk, gamma || ct || c)`
- Add `ephemeral_key.rs`, `CdbrwEphemeralNative.kt`

**Effort: 1-2 days**

---

## Phase 5 — Entropy Health Test + Manufacturing Gate

**Goal:** Normative deployment safeguards.

- 3-condition health test before every auth: H_hat >= 0.45, |rho_hat| <= 0.3, L_hat >= 0.45
- n = 2048 thermal samples, LZ78 compression (not deflate)
- Manufacturing gate: sigma_device = std(H_bar)/max(H_bar) >= 0.04
- Add `CdbrwEntropyHealth.kt`, `cpp/cdbrw_entropy_health.cpp`

**Effort: 1-2 days**

---

## Phase 6 — Full 2-Round Verification Protocol

**Goal:** Wire complete Protocol 6.2. Verifier sends c, Device responds (gamma, ct, sigma).

- `CdbrwVerificationProtocol.kt` (device-side orchestrator)
- `CdbrwVerifier.kt` (verifier-side, steps 11-15)
- `sdk/jni/cdbrw.rs` (new JNI bridge)
- Wire into AntiCloneGate.kt

**Effort: 2-3 days**

---

## Phase 7 — Attractor Envelope Test

**Goal:** Moment commitments per Def. 6.3. m >= 8 moments with Merkle proofs.

- `CdbrwEnvelopeTest.kt`, `cpp/cdbrw_moments.cpp`

**Effort: 2 days**

---

## Phase 8 — Cross-Layer Test Vectors + PBT

**Goal:** Bit-identical outputs across C++/Kotlin/Rust. PBT for crypto primitives.

- TV-1 through TV-8 per 9.4
- PBT: ARX determinism, SPHINCS+ keygen determinism, Kyber encap determinism, histogram normalization

**Effort: 2-3 days**

---

## Paper Revisions Required

1. Appendix B: Kyber-1024 -> ML-KEM-768 / NIST Level 3
2. Appendix B: Default N=4096 -> N=16384
3. Performance Budgets: Update Kyber line
4. End-to-End Security (A4): Update Kyber reference
5. Version header: Bump to Rev 3.0
6. Def. 4.14 (C): Clarify LZ78 is normative
7. 4.5.8: Add single-device proxy note for sigma_device

---

## Dependency Graph

```
Phase 0 (UUID fix)
  |
  v
Phase 1 (Delete DBRW + BLAKE3 C++)
  |
  +---> Phase 2 (Seeding + ACD + N + tau + genesis fix)
  |       |
  |       v
  |     Phase 5 (Entropy health + mfg gate)
  |
  +---> Phase 3 (ML-KEM-768 C++)
          |
          v
        Phase 4 (SPHINCS+ ephemeral)
                |
                v
              Phase 6 (Full protocol; needs Phase 5 too)
                      |
                      v
                    Phase 7 (Envelope test)

Phase 8 (test vectors + PBT) runs incrementally
```

## Effort

| Phase | Time | Risk |
|-------|------|------|
| 0 — Canons fixes | 0.5 day | Low |
| 1 — Delete DBRW + BLAKE3 C++ | 2-3 days | Medium |
| 2 — Seeding + ACD + N + tau + genesis | 2-3 days | Low |
| 3 — ML-KEM-768 C++ | 2-3 days | Medium |
| 4 — SPHINCS+ ephemeral | 1-2 days | Low |
| 5 — Entropy health + mfg gate | 1-2 days | Low |
| 6 — Full protocol | 2-3 days | Medium |
| 7 — Envelope test | 2 days | Medium |
| 8 — Test vectors + PBT | 2-3 days | Low |

**Total: ~14-20 days**

---

## Normative Deployment Conditions

| Condition | Requirement | Enforced Where |
|-----------|-------------|---------------|
| Orbit length | N >= 16,384 | SiliconFingerprint.kt, siliconfp.cpp |
| Mfg variance | sigma_device >= 0.04 | Enrollment |
| Runtime entropy | H_hat >= 0.45, abs(rho) <= 0.3, L_hat >= 0.45 | CdbrwEntropyHealth.kt |
| Entropy rate | h_0 >= 0.5 bits/sample | Health test |
| Threshold | tau = (epsilon_intra + epsilon_inter) / 2 | AntiCloneGate.kt |
| Separation | epsilon_intra < epsilon_inter | Enrollment |
| ARX params | r >= 3, B >= 256 | Constants |

---

## Domain Separation Tags (Appendix A)

```
DSM/dbrw-bind\0          K_DBRW derivation
DSM/attractor-commit\0   ACD enrollment commitment
DSM/cdbrw-seed\0         Challenge orbit seeding
DSM/cdbrw-response\0     Verification response gamma
DSM/kyber-coins\0        Deterministic encap coins
DSM/kyber-ss\0           Shared secret derivation
DSM/kyber-static\0       Static Kyber key from master seed
DSM/moment\0             Moment commitment in envelope test
DSM/dev\0                Master seed extraction
DSM/ek\0                 Ephemeral key derivation
DSM/ek-cert\0            Ephemeral key certification
DSM/dbrw-rho\0           DBRW walk step (rho)
DSM/dbrw-step\0          DBRW walk step (chain)
```

---

## Security

- `explicit_bzero` all key material after use
- K_DBRW, S_master, E_{n+1} never serialized, logged, or committed
- `-O2` not `-O3`
- No logging of key material
- Entropy health test before every auth — no caching, no bypass
- Manufacturing variance at enrollment — hard gate, no override
- All integers little-endian
- No UUID anywhere in the codebase
- Canonical serialization exclusively in crypto module
