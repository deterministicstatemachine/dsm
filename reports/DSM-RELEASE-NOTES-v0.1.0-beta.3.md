# DSM v0.1.0-beta.3

Third public beta. **215 commits, 525 files, +66.7k/-43.1k lines** since beta.2 — this is a major architectural release that reshapes the state model, unifies the native boundary across platforms, and purges ~10k lines of legacy code. Pre-release build — not for production use.

---

## Architectural headlines

### 1. `DeviceState` is now the canonical state model

The state machine has been rebuilt around `DeviceState` as the underlying truth; the legacy `State` is now a **derived view** computed from `DeviceState`. `StateMachine` has been stripped to the bare minimum (just `DeviceState` + `relationship_manager`). The old dispatch surface (`execute_transition`, `execute_dsm_operation`, `apply_operation`) is gone, replaced by a single uniform API:

```rust
CoreSdk::execute_on_relationship(&mut self, /* op */)
```

All operation paths — **bilateral transfers, mint, burn, fee transfers, DLV unlock, and smart commitments** — now route through `execute_on_relationship`. The `advance` path has been split into `prepare / commit / restore` semantics for cleaner recovery and settlement.

### 2. Unified ingress boundary — platform-agnostic native layer (iOS-ready)

The legacy `appRouter` dispatch is gone. All protocol traffic now flows through a single **unified ingress boundary** (`dsm_sdk::ingress`, ~1,460 LOC), with platform-specific ABI shims on top:

- **Android**: JNI bridge (`unified_protobuf_bridge`) routes envelope/router/hardware-facts calls through shared ingress
- **iOS**: C FFI surface exported via `dsm_process_envelope_protobuf` / `dsm_free_envelope_bytes`; platform scaffolding in `dsm_sdk/src/platform/ios/{bluetooth,transport}.rs`; iOS integration documented in `docs/book/11-integration-guide.md`

Two new Android bridges (`NativeBoundaryBridge`, `NativeHostBridge`) now cleanly separate *DSM native ingress* from *host-capability* requests (QR, BLE, NFC, permissions, biometric). Genesis bootstrap was rewritten to emit `BootstrapMeasurementReport` phases, collect DBRW measurements, persist salt, and finalize via ingress.

### 3. C-DBRW migrated from C/C++ to pure Rust

All DBRW native logic (histogram, Wasserstein distance, entropy health, moments, BLAKE3 fallback, JNI wrappers) has been **deleted from C/C++ and re-implemented in Rust** under `dsm_sdk/security/cdbrw_*`. Net change: -1,600 lines of native code, zero `unsafe` C surface. CMakeLists keeps only the `siliconfp` probe library.

### 4. §4.3 spec compliance — `state_number` purged from canonical hash paths

`state_number` has been **removed from the `State` struct and from every canonical hash input** across `dsm` and `dsm_sdk`. Identity logic now uses hash-based IDs. Multiple §4.3-violating call sites were deleted, including the broken `get_state_by_number` helper (5 callers migrated). The Pixel 9 faucet brick bug was traced to the §4.3 violation and fixed.

---

## Features

- **NFC recovery pipeline** — capsule v4, persisted recovery key, SMT-root capsule reuse, and full identity restore flow. NFC handling is now inlined in the bridge; standalone NFC activities were removed.
- **Storage vault summaries via `bitcoinTap`** — storage path switched to BitcoinTap-style vault summaries.
- **Recovery tombstone codec migrated to protobuf** (previously bincode) — aligns with the repo's "protobuf-only in protocol paths" invariant.
- **GATT inbound serialization** — `observeGattIdentityRead` JNI/Kotlin flow added; BLE event relay now allows callers to mark transient events droppable when the bridge is unavailable.
- **Expanded BLE hardening**:
  - Peer identity hydration from persisted contacts for stale BLE addresses
  - Multi-peer fallback address resolution with coordinator tests
  - Session-lifecycle locking (`TEST_DB_LIFECYCLE_LOCK`)
  - BLE session recovery + canonical SMT routing for all bilateral advances
  - BLE foreground service wakes on stitched-receipt cache hit
- **Contact export** — `export_contacts` now overlays persisted `chain_tip` + `ble_address` instead of dropping them behind stale in-memory state.

---

## Security

- **DLV settlement anchoring enforced** — token operations now require anchored DLV settlement.
- **C-DBRW trust gating enforced** — SDK + tests updated to fail closed on DBRW verdict mismatch.
- **Real signature checks in verification** — replaces prior placeholder paths.
- **Malformed token-id rejection** — balance-key derivation hard-fails on malformed token IDs instead of admitting ambiguous keys; duplicate hardening in balance checks.
- **Canonical identity binding** — identity store and invalidation are bound to canonical genesis IDs; prevents cross-identity contamination.
- **Sender-session persistence fail-closed** — BLE sender session registration aborts on persist errors instead of continuing in-memory-only.

---

## Legacy code purge (~10,000+ LOC deleted)

Major deletions made possible by the `DeviceState` migration:

| Area | LOC deleted |
|---|---:|
| `HashChain` infrastructure | ~3,200 |
| `BCR` heuristic detection | ~1,200 |
| `hierarchical_device_management` module | ~1,180 |
| `protocol_metrics.rs` | ~1,362 |
| `chain_tip_sync_sdk` module | ~787 |
| C/C++ C-DBRW native code | ~3,000 |
| `BilateralStateManager` dead session/chain-tip surface | ~280 |
| `StateMachine` verification helpers | ~210 |
| Assorted `State` / `RelationshipManager` / `RelationshipStatePair` dead methods | ~600+ |

Also removed: `DualModeVerifier`, `state_to_wire`, `random_walk` State helpers, `verify_trustless_identity`, `resume_relationship`, `create_token_state_transition`, `ContactManager::update_contact_from_transition`, many State struct fields (`external_data`, `hashchain_head`, `matches_parameters`, `state_type`, `value`, `commitment`), and 10+ zero-caller `State` methods.

---

## Fixes

- **Online send false "SMT proofs are invalid"** — `wallet.send` now uses `smt_proofs.pre_root` when constructing first-advance receipt commitments.
- **Pixel 9 faucet brick** — §4.3-violating monotonic `state_number` check removed.
- **Faucet phantom token row** — credits no longer render a stale ERA = 0 row.
- **SendTab error surface** — offline transfer failures now show the real reason instead of a generic "Offline transfer failed."
- **Frontend identity readiness** — `getIdentity` now waits on `dsm-identity-ready`, not `dsm-bridge-ready`, fixing startup race.
- **Settlement stale-tip cleanup** — successful bilateral settlement clears stale observed-remote-tip claims so converged relationships don't block behind old live-peer mismatches.
- **Wallet UI polish** — transaction cards show aliases + amount on its own line, expanded views keep full hashes, faucet/history cards no longer balloon.

---

## Testing & verification

- **Test coverage expansion** — new unit coverage added for: storage-node API & replication, SDK storage & bilateral, core crypto, frontend wallet/hooks/services/utils, Android bridge / BLE / security (JVM).
- **Formal verification** — vertical-validation property tests expanded; TLA+ runs (DSM_tiny, DSM_small, DSM_system, Tripwire) pass on this release commit; SPHINCS+/BLAKE3 deterministic-signing and cross-domain-digest retarget-rejection property tests added.
- **Security/verification tests** — all 10 previously-ignored tests are now fixed and passing.
- **Test isolation** — `reset_database_for_tests` serialized with `TEST_DB_LIFECYCLE_LOCK`; receipt test marked `#[serial]` to eliminate CI flakes.

---

## Tooling & CI

- **Rust toolchain switched to stable** — no more nightly dependency.
- **Guardrails rewritten for the fork architecture** — CI `enforce-guardrails` and flow assertions updated for unified ingress.
- **`caveman-compress`** plugin + tool added for docs/prose compression.
- **TS vector-flake guard** — test paths corrected.
- **Clippy clean** — `--all-targets` clean from workspace root after Phase 7.

---

## Dependency updates

tokio `1.50 → 1.51`, hyper `0.14 → 1.8`, axum `0.8.8 → 0.8.9`, axum-server `0.7.3 → 0.8.0`, rustls-native-certs `0.7.3 → 0.8.3`, tokio-postgres `0.7.16 → 0.7.17`, tokio-postgres-rustls `0.12.0 → 0.13.0`, hmac `0.12.1 → 0.13.0`, uuid `1.22 → 1.23`, mockall `0.12.1 → 0.14.0`, toml_edit `0.22.27 → 0.25.8`, handlebars `→ 4.7.9` (closed 7 Dependabot alerts). Frontend: react-dom, @types/node, @typescript-eslint/parser, copy-webpack-plugin, webpack-cli, mini-css-extract-plugin, codecov/codecov-action v6, actions/upload-artifact v7.

---

## Install

```bash
# Verify hash before installing (recommended)
shasum -a 256 dsm-wallet-v0.1.0-beta.3.apk
# Expected:
# a9b21b19b25386a7fc526d57f33fcad6bdf46694a90aba361988e6a33a6e09fb

# Regular install
adb install -r dsm-wallet-v0.1.0-beta.3.apk

# OR, on Android 11+ with the .idsig present in the same directory:
adb install --incremental dsm-wallet-v0.1.0-beta.3.apk
```

Minimum Android: 7.0 (API 24). Target SDK: 35 (Android 15).

---

## APK verification

| Field | Value |
|---|---|
| Package | `com.dsm.wallet` |
| Version | `0.1.0-beta.3` (versionCode 3) |
| Size | 218 MB (+ 1.7 MB `.idsig`) |
| **APK SHA-256** | `a9b21b19b25386a7fc526d57f33fcad6bdf46694a90aba361988e6a33a6e09fb` |
| **`.idsig` SHA-256** | `f443f2dafd073105dce9d1001c054800cfafbfae66798abac1418244410d079b` |
| Signing schemes | **v2 + v3 + v4** (JAR/v1 disabled; minSdk 24 doesn't require it) |
| Signer CN | `DSM Beta Release` |
| Signer cert SHA-256 | `5541c76aa90573e82371c2b2cb82eccb25cd90b6f3a0b4607e1a56d4aceb9817` |
| Public key SHA-256 | `d8b02db472d604276b2cd87101c7e2b274782f0be4e3c0d17a0d6eec2a3ce5bc` |
| Key algorithm | RSA 2048 |

**Fresh signing key.** The beta.3 signing key is a fresh keystore created for this release — APKs signed with earlier keys (if any were in the wild) will not upgrade in place; uninstall before installing beta.3. The v3 signature carries no rotation lineage yet (first v3 sign); future releases can attach a rotation proof signed by this key.

Manual verification:
```bash
# Full verification including v4 (point to the .idsig)
apksigner verify --verbose --print-certs \
  --in dsm-wallet-v0.1.0-beta.3.apk \
  --v4-signature-file dsm-wallet-v0.1.0-beta.3.apk.idsig
```

---

## Supply chain

`dsm-sbom-v0.1.0-beta.3.zip` (SHA-256 `00ca5c524e5fbece9593d8b9ac825999aa86698ca820da18d44eb076d2ce808e`) contains:

- Consolidated CycloneDX SBOM (`dsm-consolidated.cdx.json`, 1.5 MB, 1515 unique components)
- Per-ecosystem inventories: Rust workspace (540 components), Node lockfiles (1017), Android build manifests (33)
- `validation-evidence.json` + `logs/tla-check.log` for the TLA+ invariant runs
- Human-readable report (`DSM-SBOM-beta3-20260422.md`)

---

## Known caveats

- **iOS is scaffolded, not shipped.** The C FFI surface and `platform/ios/*` transport/bluetooth stubs are in place; no iOS app ships in this release.
- **Storage-node endpoints still default to `127.0.0.1`** — on-device pair testing via `adb reverse` is the supported topology.
- **DLV settlement metadata anchor was added and then reverted** within this window; the revert is intentional — anchor design is being revisited.

---

**Full changelog:** https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.2...v0.1.0-beta.3
