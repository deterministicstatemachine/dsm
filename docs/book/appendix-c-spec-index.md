# Appendix C — Spec Index

Index into the public, repository-owned protocol references.

---

## Public Normative Sources

Open-source contributors should treat the following repository-owned files as the public authoritative surface:

| Source | File | Scope |
|------|------|-------|
| DSM Primitive Paper | `docs/papers/dsm_primitive.pdf` | Primitive boundary, closure rule, acceptance surface, composition limits |
| Protocol Reference | `docs/book/05-protocol-reference.md` | Wire format, bridge protocol, JNI and transport-facing interfaces |
| Proto Schema | `proto/dsm_app.proto` | Envelope v3, protobuf messages, field-level wire contract |
| Storage Nodes | `docs/book/07-storage-nodes.md` | Storage-node design, local dev topology, deploy model |
| Bitcoin and dBTC | `docs/book/08-bitcoin-dbtc.md` | Signet-backed Bitcoin integration and bridge flow |
| Testing and CI | `docs/book/10-testing-and-ci.md` | CI surfaces, validation passes, enforcement points |
| Integration Guide | `docs/book/11-integration-guide.md` | Extension workflow, client integration, spec-first process |
| Security Model | `docs/book/15-security-model.md` | Trust boundaries, attacker model, protocol guarantees |
| Hard Invariants | `docs/book/appendix-b-hard-invariants.md` | Non-negotiable protocol and implementation constraints |

## Notes

- Private working notes, local instruction files, or tool-specific prompt material are not part of the public documentation surface.
- If a feature needs normative text, add or update it in the handbook, a paper under `docs/papers/`, or `proto/dsm_app.proto`.

---

## Feature → Spec → Code Map

Every feature maps to an authoritative spec and code modules across all layers.

### Hash Chains / State Transitions

- **Source:** `docs/papers/dsm_primitive.pdf`, `docs/book/05-protocol-reference.md`
- **Core:** `core/state_machine/`
- **SDK:** `sdk/chain_tip_sync_sdk.rs`
- **Frontend:** `WalletContext.tsx`

### Bilateral Transfers (3-Phase)

- **Source:** `docs/book/05-protocol-reference.md`, `docs/book/09-ble-testing.md`
- **Core:** `core/bilateral_transaction_manager.rs`
- **SDK:** `sdk/bilateral_sdk.rs`, `bluetooth/bilateral_ble_handler.rs`
- **Android:** `ble/BleCoordinator.kt`, `ble/PairingMachine.kt`
- **Frontend:** `dsmClient.ts`, `WalletContext.tsx`

### Per-Device SMT / Device Tree

- **Source:** `docs/papers/dsm_primitive.pdf`
- **Core:** `merkle/sparse_merkle_tree.rs`, `common/device_tree.rs`
- **SDK:** `security/bounded_smt.rs`

### Tripwire Fork-Exclusion

- **Source:** `docs/papers/dsm_primitive.pdf`, `docs/book/15-security-model.md`
- **Core:** `core/security/bilateral_control.rs`, `verification/proof_primitives.rs`

### Token Conservation

- **Source:** `docs/book/appendix-b-hard-invariants.md`
- **Core:** `core/token/`
- **SDK:** `sdk/token_sdk.rs`
- **Frontend:** `TokenManagementScreen.tsx`

### CPTA Token Policies

- **Source:** `docs/book/11-integration-guide.md`, `docs/book/16-code-generation.md`, `docs/book/07-storage-nodes.md`
- **Core:** `cpta/`
- **SDK:** `sdk/policy/`
- **Frontend:** `policyService.ts`

### Envelope v3 / Wire Format

- **Source:** `proto/dsm_app.proto`, `docs/book/05-protocol-reference.md`, `docs/book/appendix-b-hard-invariants.md`
- **Core:** `envelope/`, `types/proto.rs`
- **SDK:** `envelope/`, `jni/helpers.rs`
- **Android:** `BridgeEnvelopeCodec.kt`, `SinglePathWebViewBridge.kt`
- **Frontend:** `WebViewBridge.ts`, `proto/dsm_app_pb.ts`

### BLAKE3 Domain Separation

- **Source:** `docs/book/appendix-b-hard-invariants.md`, `docs/book/15-security-model.md`
- **Core:** `crypto/blake3.rs`, `crypto/hash.rs`, `common/domain_tags.rs`

### SPHINCS+ Signatures

- **Source:** `docs/book/06-cryptographic-architecture.md`
- **Core:** `crypto/sphincs.rs`

### ML-KEM-768 (Kyber)

- **Source:** `docs/book/06-cryptographic-architecture.md`
- **Core:** `crypto/kyber.rs`

### DBRW Anti-Cloning

- **Source:** `docs/book/15-security-model.md`, `docs/book/18-in-app-developer-walkthroughs.md`
- **Core:** `crypto/dbrw.rs`, `crypto/dbrw_health.rs`, `pbi.rs`
- **SDK:** `security/dbrw_validation.rs`, `jni/dbrw.rs`, `jni/bootstrap.rs`
- **Android:** `AntiCloneGate.kt`, `SiliconFingerprint.kt`

### DJTE Emissions

- **Source:** `docs/book/11-integration-guide.md`
- **Core:** `emissions.rs`
- **SDK:** `sdk/token_sdk.rs`
- **Frontend:** `TokenManagementScreen.tsx`

### DLV (Limbo Vaults)

- **Source:** `docs/book/11-integration-guide.md`, `docs/book/16-code-generation.md`, `docs/book/18-in-app-developer-walkthroughs.md`
- **Core:** `vault/dlv_manager.rs`, `vault/limbo_vault.rs`, `vault/fulfillment.rs`
- **SDK:** `sdk/dlv_sdk.rs`
- **Frontend:** `DevDlvScreen.tsx`

### Smart / External Commitments

- **Source:** `docs/book/11-integration-guide.md`
- **Core:** `commitments/smart_commitment.rs`, `commitments/external_commitment.rs`
- **SDK:** `sdk/smart_commitment_sdk.rs`, `sdk/external_commitment_sdk.rs`

### dBTC Bitcoin Bridge

- **Source:** `docs/book/08-bitcoin-dbtc.md`
- **Core:** `bitcoin/`
- **SDK:** `sdk/bitcoin_tap_sdk.rs`

### Storage Nodes

- **Source:** `docs/book/07-storage-nodes.md`
- **SDK:** `sdk/storage_node_sdk.rs`, `sdk/storage_node_health.rs`
- **Frontend:** `StorageScreen.tsx`

### Recovery

- **Source:** `docs/book/15-security-model.md`
- **Core:** `recovery/`
- **SDK:** `sdk/recovery_sdk.rs`
- **Android:** `NfcRecoveryActivity.kt`

### PBI Bootstrap

- **Source:** `docs/book/15-security-model.md`, `docs/book/18-in-app-developer-walkthroughs.md`
- **Core:** `pbi.rs`
- **SDK:** `jni/bootstrap.rs`
- **Android:** `Unified.kt`
- **Frontend:** `useAppBootstrap.ts`, `useGenesisFlow.ts`

### BLE Transport / Chunking

- **Source:** `docs/book/05-protocol-reference.md`, `docs/book/09-ble-testing.md`
- **SDK:** `bluetooth/ble_frame_coordinator.rs`
- **Android:** `ble/BleCoordinator.kt`, `ble/GattServerHost.kt`
- **Frontend:** `BleContext.tsx`

---

## Layer CLAUDE.md Files

Each layer has its own CLAUDE.md with layer-specific conventions:

| Layer | File | Scope |
|-------|------|-------|
| Rust | `dsm_client/deterministic_state_machine/CLAUDE.md` | Core logic, SDK, JNI, BLE, crypto |
| Android | `dsm_client/android/CLAUDE.md` | Kotlin, JNI, BLE actor, DBRW gate, WebView bridge |
| Frontend | `dsm_client/new_frontend/CLAUDE.md` | React UI, bridge protocol, contexts, services |

For cross-layer changes, consult all relevant CLAUDE.md files.

---

Back to [Table of Contents](README.md)
