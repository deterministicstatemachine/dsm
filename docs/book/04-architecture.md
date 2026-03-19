# Chapter 4 — Architecture

Deep dive into DSM's system design, layer boundaries, data flow, and crate structure.

---

## Four-Layer Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1: React 18 + TypeScript (StateBoy-themed UI)                 │
│    Custom router (currentScreen state, no React Router)             │
│    Contexts: WalletContext, BleContext, ContactsContext, UXContext   │
│    DsmClient → dsm/index.ts → WebViewBridge.ts                     │
│                                                                     │
│    MessagePort (ArrayBuffer): [8-byte msgId][BridgeRpcRequest]      │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Android Kotlin (API 24+, compileSdk 35)                   │
│    MainActivity.kt → handleDsmPortMessage()                         │
│    SinglePathWebViewBridge.handleBinaryRpc() → routes method names  │
│    UnifiedNativeApi.kt (87+ external JNI methods)                   │
│    BleCoordinator (actor pattern, Channel-serialized)               │
│                                                                     │
│    JNI: extern "system" fn Java_com_dsm_wallet_bridge_*             │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Rust SDK (dsm_sdk, cdylib + rlib)                        │
│    jni/unified_protobuf_bridge.rs — main RPC dispatcher             │
│    jni/bootstrap.rs — PBI bootstrap (PlatformContext in OnceLock)   │
│    bluetooth/bilateral_ble_handler.rs — 3-phase bilateral protocol  │
│    bluetooth/ble_frame_coordinator.rs — BLE chunking/reassembly     │
│    SDK_READY atomic flag gates all post-bootstrap operations        │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Core Library (dsm, pure Rust)                             │
│    crypto/ — BLAKE3, SPHINCS+, ML-KEM-768, Pedersen, ChaCha20      │
│    core/ — state machine, bilateral, token, merkle/SMT              │
│    vault/ — DLV (Limbo Vaults), fulfillment                        │
│    emissions.rs — DJTE emissions                                    │
│    cpta/ — Content-Addressed Token Policy Anchors                   │
│    bitcoin_tap_sdk.rs — dBTC bridge                                 │
│    recovery/ — capsule, tombstone, rollup                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer boundaries

- **Layer 1 → Layer 2:** Binary MessagePort channel carrying protobuf bytes. The message format is `[8-byte msgId (u64 BE)][BridgeRpcRequest proto]`.
- **Layer 2 → Layer 3:** JNI boundary. All 87+ methods are declared as `external` in `UnifiedNativeApi.kt` and implemented in Rust via `extern "system"` FFI.
- **Layer 3 → Layer 4:** Direct Rust function calls. The SDK imports core crate types and calls core functions. Core has no knowledge of JNI, Android, or I/O.

The single authoritative data path is: **UI → MessagePort → Kotlin Bridge → JNI → SDK → Core**. No side channels are permitted.

---

## Crate Structure

### `dsm` — Core Protocol (Pure Rust)

Location: `dsm_client/deterministic_state_machine/dsm/src/`

The core crate contains all protocol logic with zero I/O dependencies:

| Module | Purpose |
|--------|---------|
| `core/state_machine.rs` | State transitions, hash chain evolution |
| `core/bilateral/` | Bilateral transaction manager (3-phase commit) |
| `core/token/` | Token types, conservation checks, policy validation |
| `crypto/blake3.rs`, `crypto/hash.rs` | Domain-separated BLAKE3 hashing |
| `crypto/sphincs.rs` | SPHINCS+ post-quantum signatures |
| `crypto/kyber.rs` | ML-KEM-768 key encapsulation |
| `crypto/dbrw.rs` | DBRW anti-cloning |
| `crypto/pedersen.rs` | Pedersen commitments |
| `merkle/sparse_merkle_tree.rs` | Per-device Sparse Merkle Tree |
| `vault/dlv_manager.rs` | Deterministic Limbo Vault management |
| `vault/limbo_vault.rs` | Vault lifecycle states |
| `vault/fulfillment.rs` | DLV fulfillment mechanisms |
| `cpta/mod.rs` | Content-Addressed Token Policy Anchors |
| `emissions.rs` | DJTE (Deterministic Join-Triggered Emissions) |
| `bitcoin_tap_sdk.rs` | dBTC bridge (HTLC, deep-anchor) |
| `recovery/` | Capsule, tombstone, rollup recovery |
| `common/domain_tags.rs` | BLAKE3 domain tag constants |

### `dsm_sdk` — JNI Bridge + Platform Adapters

Location: `dsm_client/deterministic_state_machine/dsm_sdk/src/`

Wraps the core crate with platform-specific adapters:

| Module | Purpose |
|--------|---------|
| `jni/mod.rs` | JNI module root, `JNI_OnLoad` |
| `jni/unified_protobuf_bridge.rs` | Main protobuf-based RPC dispatcher |
| `jni/bootstrap.rs` | PBI bootstrap (device_id + genesis_hash + DBRW entropy) |
| `jni/create_genesis.rs` | MPC genesis creation |
| `bluetooth/bilateral_ble_handler.rs` | BLE bilateral session handler |
| `bluetooth/ble_frame_coordinator.rs` | MTU-aware chunking/reassembly |
| `bluetooth/pairing_orchestrator.rs` | Rust-driven BLE pairing flow |
| `sdk/bilateral_sdk.rs` | Bilateral transfer API |
| `sdk/token_sdk.rs` | Token/balance queries |
| `sdk/dlv_sdk.rs` | DLV vault operations |
| `sdk/bitcoin_tap_sdk.rs` | dBTC Bitcoin bridge |
| `sdk/storage_node_sdk.rs` | Storage node HTTP client |
| `security/dbrw_validation.rs` | DBRW clone detection |

Compiled by `cargo ndk` for three ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`.

### `dsm_storage_node` — Storage Node

Location: `dsm_storage_node/src/`

Index-only, clockless, signature-free HTTP server built on Axum:

| Module | Purpose |
|--------|---------|
| `main.rs` | Axum server, TLS, CLI args |
| `api/genesis.rs` | Genesis entropy endpoints |
| `api/bytecommit.rs` | ByteCommit mirroring |
| `api/dlv_slot.rs` | DLV vault slot management |
| `api/gossip.rs` | Inter-node state sync |
| `api/unilateral_api.rs` | b0x unilateral transport |
| `api/recovery_capsule.rs` | Recovery capsule CRUD |
| `replication.rs` | Replica placement (keyed Fisher-Yates) |
| `partitioning.rs` | Deterministic shard assignment |
| `db/` | PostgreSQL schema, migrations, queries |

---

## Data Flow: Bilateral Transfer

Tracing a bilateral BLE transfer through all four layers:

```
1. User taps "Send" in React UI
   └─ WalletContext dispatches via DsmClient.sendBilateral()
      └─ WebViewBridge.ts encodes BridgeRpcRequest { method: "bilateralPrepare", ... }
         └─ MessagePort.postMessage( [msgId][protobuf bytes] )

2. Kotlin Bridge receives binary message
   └─ MainActivity.handleDsmPortMessage()
      └─ SinglePathWebViewBridge.handleBinaryRpc()
         └─ Routes "bilateralPrepare" → UnifiedNativeApi.bilateralPrepare(bytes)

3. JNI crosses into Rust SDK
   └─ unified_protobuf_bridge.rs dispatches to bilateral_sdk::prepare()
      └─ bilateral_ble_handler.rs initiates BLE handshake

4. BLE handshake (between two devices)
   └─ Initiator: HELLO(pubkey, nonce) →
   └─ Responder: ← CHALLENGE(nonce2)
   └─ Initiator: RESPONSE(sig) →
   └─ Responder: ← READY
   └─ Initiator: TRANSFER(state_delta) →
   └─ Responder: apply + commit, ← ACK(new_state_hash)
   └─ Initiator: verify ACK, COMPLETE →

5. Core processes the state transition
   └─ state_machine.rs validates transition
      └─ bilateral_transaction_manager.rs executes 3-phase commit
         └─ token conservation check: B_{n+1} = B_n + Delta, B >= 0
            └─ BLAKE3 hash chain advances on both devices

6. Response flows back up
   └─ SDK returns protobuf result → JNI → Kotlin → MessagePort → React
      └─ WalletContext updates balances and transaction list
```

---

## Hash Chain Structure

Each device maintains a straight hash chain. Every state commit contains:

```
CommitN:
  parent_hash: BLAKE3("DSM/commit\0" || CommitN-1)
  device_id:   bytes[32]
  sequence:    u64
  operations:  [Operation]  (bilateral, token, DLV, etc.)
  signature:   SPHINCS+ signature over canonical bytes
```

The parent hash references the previous commit, forming an append-only chain. The Tripwire Fork-Exclusion theorem guarantees that no two valid successors can exist from the same parent — attempting to create a fork would require breaking either SPHINCS+ EUF-CMA security or BLAKE3 collision resistance.

---

## Per-Device Sparse Merkle Tree

Each device maintains a Sparse Merkle Tree (SMT) that tracks its own state. The SMT root is included in each commit, allowing efficient membership and non-membership proofs.

The Device Tree aggregates per-device SMTs into a global tree structure, enabling cross-device verification without requiring all participants to maintain the complete state of every other device.

---

## Storage Node Assignment

Clients determine which storage nodes hold their state using deterministic hashing:

```
node_set = keyed_fisher_yates_shuffle(
    key:   BLAKE3("DSM/assign\0" || identity_hash),
    count: N_total_nodes,
    pick:  N_replicas
)
```

This produces the same assignment on every client without coordination. Parameters:
- N = 6 (total replicas)
- K = 3 (minimum for durability)

---

## App State Machine

The React frontend uses a custom router based on `currentScreen` state (no React Router). The app state machine tracks:

```
INIT → BOOTSTRAPPING → GENESIS_PENDING → READY → [screens]
                                                    ├── WALLET
                                                    ├── SEND
                                                    ├── RECEIVE
                                                    ├── CONTACTS
                                                    ├── BLE_TRANSFER
                                                    ├── SETTINGS
                                                    ├── TOKEN_MANAGEMENT
                                                    └── DEV_OPTIONS
```

Bootstrap flow:
1. `useAppBootstrap.ts` initializes the bridge
2. SDK checks for existing device identity (DBRW-bound)
3. If no identity: `useGenesisFlow.ts` calls MPC genesis endpoint
4. Genesis response has `0x03` prefix — decoded via `decodeFramedEnvelopeV3()`
5. SDK_READY flag is set; all operations are now available

---

## Call-Chain Traces

Detailed order-of-operations for key flows across all four layers. All paths are protobuf/bytes-first with Envelope v3 semantics.

### Online Transfer (`wallet.send`)

1. UI calls `sendOnlineTransfer(...)` in `transactions.ts`
2. Frontend resolves recipient `to_device_id` (32 bytes), local headers via `getHeaders()` (`device_id`, `chain_tip`, `seq`), builds `OnlineTransferRequest`
3. Frontend wraps request into `ArgPack(codec=PROTO)` and invokes `appRouterInvokeBin('wallet.send', argPackBytes)`
4. `appRouterInvokeBin` in `WebViewBridge.ts` builds `BridgeRpcRequest(method='appRouterInvoke', payload=AppRouterPayload{methodName,args})`
5. MessagePort transport in `index.html` sends bytes through `sendMessageBin(...)`, correlates responses by 8-byte request id, routes async push messages to `dsm-event-bin` when not matching pending ids
6. JNI entry `appRouterInvokeFramed` in `unified_protobuf_bridge.rs` decodes `AppRouterPayload`, calls `router.invoke(AppInvoke{method,args})`
7. SDK handler in `app_router_impl.rs` (`process_online_transfer_logic`) validates 32-byte fields, generates canonical signing preimage, signs with wallet key, updates local state, attempts b0x submission for recipient inbox, returns `onlineTransferResponse`
8. Frontend decodes via `decodeFramedEnvelopeV3(...)` and maps to `GenericTxResponse`

**Single-line:** `transactions.sendOnlineTransfer` → `WebViewBridge.appRouterInvokeBin('wallet.send')` → `index.html sendMessageBin` → `JNI appRouterInvokeFramed` → `AppRouterImpl.process_online_transfer_logic` → response envelope → frontend strict decode

### Offline Bilateral (`bilateral.prepare` over BLE)

1. UI calls `offlineSend(...)` in `transactions.ts`
2. Frontend resolves recipient device id (32 bytes), BLE address, local headers; fetches contact chain tip/genesis; builds canonical operation bytes; builds `BilateralPrepareRequest`, wrapped into `Invoke(method='bilateral.prepare')` inside `UniversalTx`, inside `Envelope(version=3)`
3. Frontend calls `bilateralOfflineSendBin(envelopeBytes, bleAddress, 'prepare')`
4. `WebViewBridge.ts` packages method as `appRouterInvoke` with `AppRouterPayload(methodName='bilateralOfflineSend', args=[bleAddrLen|bleAddr|envelope])`
5. JNI entry `bilateralOfflineSend` decodes envelope, validates headers/shape, extracts `bilateral.prepare` invoke args, validates `ble_address`, `counterparty_device_id`, `operation_data`, uses BluetoothManager coordinator to create prepare chunks + commitment, emits BLE GATT chunks
6. Returns `Envelope(universalRx{OpResult...BilateralPrepareResponse...})`
7. Frontend decodes response envelope; extracts commitment hash from `UniversalRx` result body
8. Completion is event-driven: waits for `EventBridge.on('bilateral.event', ...)` with matching commitment hash, handles COMPLETE/REJECTED/FAILED states

**Single-line:** `transactions.offlineSend` → `WebViewBridge.bilateralOfflineSendBin` → `JNI bilateralOfflineSend` → Bluetooth coordinator prepare/send chunks → `UniversalRx` response + async `bilateral.event` completion

### Async Event Path (BLE + Bilateral Notifications)

1. Android `MainActivity.kt` dispatches async events with `dispatchDsmEventOnUi(topic, payload)`
2. Encodes event payload as protobuf `AppRouterPayload(method_name=topic, args=payload)` and posts bytes through WebView `MessagePort`
3. Browser bridge (`index.html`) receives message; if not a pending request response, attempts protobuf parse into `{topic,payload}`; dispatches `window` event `dsm-event-bin`
4. Frontend `EventBridge.ts` listens to `dsm-event-bin` and fans out to topic subscribers:
   - `bilateral.event` → parses `BilateralEventNotification`, emits wallet/contact refresh signals
   - `ble.envelope.bin` → parses Envelope, BLE events, identity observed, bilateral completion hints

**Single-line:** `MainActivity.dispatchDsmEventOnUi` → MessagePort → `index.html dispatchEventPayload` → `window dsm-event-bin` → `EventBridge.initializeEventBridge` subscribers

### QR/Contact Onboarding

1. Pairing QR decode path invokes router query: `contacts.handle_contact_qr_v3`
2. SDK handler in `app_router_impl.rs` decodes `ContactQrV3`, resolves counterparty via transport, persists verified contact, syncs contact into BluetoothManager (`ensure_bluetooth_manager_and_sync_contact`), returns `contactAddResponse`
3. This is the prerequisite for reliable bilateral routing (device id ↔ BLE identity/address resolution)

### Error Propagation Contract

- JNI framed router errors are returned as framed error envelopes (or reqId-prefixed framed errors in query path)
- `WebViewBridge.unwrapProtobufResponse(...)` converts `BridgeRpcResponse.error` into `BridgeError`, emits `bridge.error` events
- Feature-level handlers (`transactions.ts`) perform strict envelope case checks and convert errors to user-facing result objects
- `decodeFramedEnvelopeV3(...)` is the canonical strict transport entrypoint in the frontend decode layer

### Operational Choke Points

1. **Router readiness / bootstrap window** — `appRouterQueryFramed`/`appRouterInvokeFramed` return not-ready when router missing
2. **Envelope framing consistency** — mixed framed/unframed assumptions can break decode if `0x03` handling diverges
3. **Bilateral completion dependency on async events** — sender waits on `bilateral.event` with commitment match; event delivery loss becomes user-visible timeout
4. **Contact sync prerequisite for BLE** — offline send reliability depends on `contacts.handle_contact_qr_v3` + BluetoothManager sync path

---

## Protocol Guarantees

| Property | Mechanism |
|----------|-----------|
| No double-spend | Tripwire Fork-Exclusion: SPHINCS+ EUF-CMA + BLAKE3 collision resistance |
| No replay | Nonces and sequence counters in every message |
| Identity binding | SPHINCS+ keypair + DBRW anti-cloning (silicon + environment) |
| Offline capability | BLE transport requires no network; storage sync is eventual |
| Server blindness | Storage nodes are index-only; never sign, validate, or gate |
| Token conservation | `B_{n+1} = B_n + Delta, B >= 0` enforced at every transition |
| Determinism | Same inputs → same outputs; no randomness in state transitions |

---

Next: [Chapter 5 — Protocol Reference](05-protocol-reference.md)
