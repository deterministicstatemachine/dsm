# Per-Step EK Signing — Mainnet Deployment Runbook

> Whitepaper §11.1 ephemeral cert chain. Operationalizes the per-step EK
> signing work landed across commits `50bd182`, `5dc8eb6`, `f5a5415`,
> `62852d3`, `b73afc6`, `d8a6b1b`, `5d2f1dd`, `7abcc50`, `e83053d`.

## What changed

Every bilateral receipt now carries:
- `ek_pk_a` (proto field 16): the per-step ephemeral SPHINCS+ public key
  derived from `(h_n, C_pre, k_step, K_DBRW)`, used to verify `sig_a`.
- `ek_cert_a` (proto field 14): the cert chaining `EK_pk_{n+1}` back to
  the device's attested AK_pk via prior chain heads.
- `sig_a` is signed by `EK_sk_{n+1}` (NOT the wallet's long-term identity
  key).

`ek_pk_b` / `ek_cert_b` mirror the above for counter-signed receipts.

The cert chain provides AK-rooted authorization for every per-step EK.
Verifier uses `receipt.ek_pk_a` if non-empty; falls back to externally-
passed `pk_a` for legacy receipts that pre-date this work.

## Pre-mainnet state (current, default)

- `strict_cert_chain_mode = false` (the setting at
  `client_db::cert_chain::is_strict_cert_chain_mode`).
- Verifier auto-loads chain heads if present, falls back to legacy
  pubkey-only verification if absent.
- **Online wallet send** (`app_router_impl.rs:wallet.send`) produces
  receipts with full per-step EK + cert.
- **Offline bilateral (BLE) send** still uses the legacy wallet
  identity-key signing path. Receipts have empty `ek_pk_a/b` — verifiers
  fall back to externally-passed `pk_a/b`.

## Mainnet deployment checklist

### Pre-flight (development branch)

1. **Migrate offline (BLE) signing to per-step EK** —
   `bilateral_ble_handler.rs` prepare/commit/confirm phases need per-step
   EK derivation threaded through the session state machine. Same
   integration pattern as the online path (`app_router_impl.rs:1372`)
   but distributed across three protocol phases. Multi-session scope.

2. **Surface bilateral session Kyber `k_step`** (Phase F) —
   `BilateralBleSession` should expose `current_k_step() -> Option<[u8; 32]>`.
   Receipt construction passes this to `PerStepSigningInputs.k_step_override`
   instead of relying on `derive_stub_k_step_for_relationship`. Spec-
   correct fresh per-step Kyber-derived randomness per whitepaper §11.

3. **Discharge `sorry` proofs in `lean4/DSMCertChain.lean`** — three
   theorems are stated but await proof engineering: `extend_empty_chain_valid`,
   `cert_substitution_attack_resistant`, `cert_chain_first_step_anchored`.
   Either add Mathlib dependency or extend the existing axiom set.

### Deployment-day enablement

4. **Initialize cert chain for every existing relationship**:
   ```rust
   for relationship in client_db::contacts::list_all() {
       let rel_key = compute_smt_key(&local_devid, &relationship.devid);
       let (ak_pk, ak_sk) = wallet.ak_keypair_for_cert_chain()?;
       let counterparty_ak_pk = relationship.public_key;
       client_db::cert_chain::init_local_cert_chain_head_with_sk(
           &rel_key, &ak_pk, &ak_sk, &k_dbrw,
       )?;
       client_db::cert_chain::init_cert_chain_head(
           &rel_key, CertChainSide::Counterparty, &counterparty_ak_pk,
       )?;
   }
   ```
   This anchors every relationship at AK_pk. Subsequent receipts will
   walk forward from there.

5. **Enable strict mode**:
   ```rust
   client_db::cert_chain::set_strict_cert_chain_mode(true)?;
   ```
   After this, any relationship that doesn't have chain heads recorded
   will fail receipt verification with a clear error message naming
   `init_cert_chain_for_relationship`. This is the security gate Gemini
   flagged in the adversarial review of the chain-head threading commit.

6. **Verify the bilateral integration tests still pass under strict mode**:
   ```
   cargo test -p dsm --test bilateral_transaction_integration_tests
   cargo test -p dsm_sdk --lib sdk::receipts::tests::strict_mode_rejects_receipt_without_chain_heads
   cargo test -p dsm_sdk --lib sdk::receipts::tests::per_step_signing_chain_property_invariants
   ```

### Backward compatibility during the transition

The verifier accepts BOTH receipt formats during the transition window:

| Receipt has | Verifier behavior |
|---|---|
| `ek_pk_a` non-empty + `ek_cert_a` non-empty + chain heads stored | Validates cert chain AND `sig_a` against `ek_pk_a`. Spec-correct path. |
| `ek_pk_a` non-empty + `ek_cert_a` empty + strict mode OFF | Validates `sig_a` against `ek_pk_a`; cert chain check skipped. Transitional. |
| `ek_pk_a` empty (legacy) + chain heads NOT stored + strict mode OFF | Falls back to externally-passed `pk_a` (the wallet's long-term key). Pre-feature legacy path. |
| `ek_pk_a` empty + strict mode ON | **REJECTED** with "strict cert-chain mode is on and no chain heads are recorded." |
| Chain heads stored but `ek_cert_a` empty | **REJECTED** by core verifier (Phase 4 logic). |

## What changes for receipt size

Per-receipt overhead vs. legacy:
- `ek_pk_a` (~64 bytes — SPHINCS+ Cat-5 'f' pubkey)
- `ek_cert_a` (~30 KiB — one SPHINCS+ Cat-5 'f' signature)
- Same for `_b` if counter-signed

Total: ~30-60 KiB per receipt. Per §11.1 spec the 128 KiB receipt cap
absorbs this. Existing `validate_size_cap()` enforces.

## What changes for verification cost

- One extra SPHINCS+ verify per receipt (the cert).
- One SQLite point-lookup for chain head (sub-microsecond on indexed PK).

SPHINCS+ verify dominates by ~6 orders of magnitude — the SQLite cost
is in the noise. Property test `per_step_signing_chain_property_invariants`
runs 17 sequential signings + verifications in ~20s, dominated by SPHINCS+
keypair generation (signing/verification each ~1ms).

## Operational gotchas

- **`K_DBRW` regeneration** — encrypted SK material is bound to the
  device's DBRW state. If the device's hardware/environment changes
  (rare but possible during firmware update or hardware swap), encrypted
  SKs become unrecoverable. Recovery flow: tombstone+succession to
  re-anchor at a new AK; chain heads re-initialize at step 0.
- **Cold-start verification after recovery** — the recovery capsule v5
  (commit `f5ce701`) carries `cert_chain_heads` + `last_certs` so a
  resumed device has its chain heads available immediately without
  replaying history.
- **Concurrent receipts on the same relationship** — the `advance` call
  is atomic at the SQLite level (single UPDATE statement). However,
  TOCTOU between load-chain-head and advance-chain-head exists if two
  receipts arrive simultaneously on the same relationship. Currently
  documented as a low-priority follow-up; in practice bilateral sessions
  serialize per relationship via the session state machine.

## Test inventory

| Test | What it proves |
|---|---|
| `kat_dsm_ek_derivation_seed` | KAT pin for `DSM/ek` HKDF preimage |
| `kat_dsm_ek_cert` | KAT pin for `DSM/ek-cert` cert hash |
| `chain_sk_aead_*` (4 tests) | Encrypted SK round-trip + tamper resistance |
| `local_chain_head_sk_*` (4 tests) | Storage layer for SK material |
| `per_step_signing_uses_ak_fallback_when_chain_head_absent` | Step 0 AK fallback |
| `per_step_signing_chains_through_advancement` | Step 1 walks past AK |
| `per_step_signing_respects_k_step_override` | Override path for Phase F Kyber |
| `per_step_signing_errors_without_chain_head_or_fallback` | Defensive error |
| `per_step_signing_end_to_end_two_steps` | Full sign+verify+advance over 2 steps |
| `per_step_signing_chain_property_invariants` | P1-P5 over chain lengths {1,3,5,8} |
| `strict_mode_rejects_receipt_without_chain_heads` | Strict-mode security gate |

Plus `lean4/DSMCertChain.lean` formal specification (typechecks under
leanprover/lean4:v4.23.0 with 3 discharged proofs and 3 stated `sorry`s).

## Issue tracking

GitHub issue [#320](https://github.com/deterministicstatemachine/dsm/issues/320)
tracks the audit and follow-up work. See in particular the comment trail
documenting the Gemini Stage-6 adversarial review that flagged the
fail-open security model and led to the strict-mode toggle.
