---
name: cross-layer-trace
description: Trace any DSM feature or data flow across all 4 layers (Frontend React → Android Kotlin → JNI/SDK Rust → Core Rust). Use when debugging cross-layer issues, understanding how a feature works end-to-end, or planning cross-layer changes.
---

# Cross-Layer Trace

You are an expert at tracing DSM features across all 4 architectural layers. The single authoritative path is:

```
UI/WebView → MessagePort → Kotlin Bridge → JNI → SDK → Core
```

When the user asks about a feature or flow, you trace it across every layer and show them the exact file:line where each handoff occurs.

## The 4 Layers

### Layer 1: Frontend (React 18 + TypeScript + Webpack)

**Entry points**: User interaction → React component → service/hook → bridge call

| Component | Path | Role |
|-----------|------|------|
| App router | `new_frontend/src/App.tsx` | Custom router (currentScreen state) |
| Bridge provider | `new_frontend/src/bridge/BridgeProvider.tsx` | Bridge injection |
| Bridge registry | `new_frontend/src/bridge/BridgeRegistry.ts` | Global bridge instance |
| WebView bridge | `new_frontend/src/dsm/WebViewBridge.ts` | MessagePort binary protocol |
| Event bridge | `new_frontend/src/dsm/EventBridge.ts` | Event emission layer |
| DSM client | `new_frontend/src/services/dsmClient.ts` | High-level API surface |
| Proto types | `new_frontend/src/proto/dsm_app_pb.ts` | Generated protobuf types |
| Wallet context | `new_frontend/src/contexts/WalletContext.tsx` | Balances, transactions |
| BLE context | `new_frontend/src/contexts/BleContext.tsx` | BLE scan state |
| Contacts context | `new_frontend/src/contexts/ContactsContext.tsx` | Contact management |
| UX context | `new_frontend/src/contexts/UXContext.tsx` | UI state, notifications |
| Genesis flow | `new_frontend/src/hooks/useGenesisFlow.ts` | Genesis creation |

**Wire format**: `[8-byte msgId (u64 BigEndian)][BridgeRpcRequest protobuf bytes]`

**Critical**: Always use `decodeFramedEnvelopeV3()` — strips `0x03` prefix before `Envelope.fromBinary()`.

### Layer 2: Android (Kotlin, API 24+, compileSdk 35)

**Entry point**: `MainActivity.handleDsmPortMessage()` receives MessagePort binary

| Component | Path | Role |
|-----------|------|------|
| MainActivity | `android/.../ui/MainActivity.kt` | WebView host, MessagePort |
| WebView bridge | `android/.../bridge/SinglePathWebViewBridge.kt` | Central RPC dispatcher |
| JNI facade | `android/.../bridge/Unified.kt` | `System.loadLibrary("dsm_sdk")` |
| JNI declarations | `android/.../bridge/UnifiedNativeApi.kt` | 87+ `external` methods |
| BLE coordinator | `android/.../bridge/ble/BleCoordinator.kt` | Actor pattern, Channel-serialized |
| GATT server | `android/.../bridge/ble/GattServerHost.kt` | GATT server + identity char |
| Pairing machine | `android/.../bridge/ble/PairingMachine.kt` | Pairing state machine |

**Method routing**: `SinglePathWebViewBridge.handleBinaryRpc()` dispatches by method name string.

### Layer 3: JNI / SDK (Rust, cdylib + rlib)

**Entry point**: `extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_*`

| Component | Path | Role |
|-----------|------|------|
| JNI module | `dsm_sdk/src/jni/mod.rs` | Module root, `JNI_OnLoad` |
| RPC dispatcher | `dsm_sdk/src/jni/unified_protobuf_bridge.rs` | Main protobuf dispatch |
| Bootstrap | `dsm_sdk/src/jni/bootstrap.rs` | PBI (device_id + genesis + DBRW) |
| Genesis | `dsm_sdk/src/jni/create_genesis.rs` | MPC genesis creation |
| Bilateral SDK | `dsm_sdk/src/sdk/bilateral_sdk.rs` | Bilateral transfer API |
| Token SDK | `dsm_sdk/src/sdk/token_sdk.rs` | Token/balance queries |
| DLV SDK | `dsm_sdk/src/sdk/dlv_sdk.rs` | Vault operations |
| Bitcoin SDK | `dsm_sdk/src/sdk/bitcoin_tap_sdk.rs` | dBTC bridge |
| BLE handler | `dsm_sdk/src/bluetooth/bilateral_ble_handler.rs` | 3-phase bilateral BLE |
| Frame coord | `dsm_sdk/src/bluetooth/ble_frame_coordinator.rs` | MTU-aware chunking |
| Pairing orch | `dsm_sdk/src/bluetooth/pairing_orchestrator.rs` | Rust-driven BLE pairing |
| DBRW | `dsm_sdk/src/security/dbrw_validation.rs` | DBRW clone detection |

**Gate**: `SDK_READY` atomic flag — set after PBI bootstrap completes. All post-bootstrap ops blocked until true.

### Layer 4: Core (Pure Rust — no network, no OS time, no UI, no global state)

| Component | Path | Role |
|-----------|------|------|
| State machine | `dsm/src/core/state_machine.rs` | State transitions, hash chain |
| Bilateral mgr | `dsm/src/core/bilateral_transaction_manager.rs` | Bilateral logic |
| Token types | `dsm/src/core/token/` | Conservation, policy validation |
| BLAKE3 | `dsm/src/crypto/blake3.rs`, `crypto/hash.rs` | Domain-separated hashing |
| SPHINCS+ | `dsm/src/crypto/sphincs.rs` | Post-quantum signatures |
| Kyber | `dsm/src/crypto/kyber.rs` | Key exchange |
| DBRW | `dsm/src/crypto/dbrw.rs` | Anti-cloning |
| Pedersen | `dsm/src/crypto/pedersen.rs` | Commitments |
| SMT | `dsm/src/merkle/sparse_merkle_tree.rs` | Per-device SMT |
| DLV | `dsm/src/vault/dlv_manager.rs`, `vault/limbo_vault.rs` | Vaults |
| CPTA | `dsm/src/cpta/` | Token policy anchors |
| Emissions | `dsm/src/emissions.rs` | DJTE |
| Domain tags | `dsm/src/common/domain_tags.rs` | All domain tag constants |

## How to Trace

When the user asks "how does X work end-to-end" or "trace the flow of Y":

1. **Identify the feature** from the Feature → Spec → Code map in AGENTS.md
2. **Layer 1**: Find the React component/hook/service that initiates the flow
3. **Layer 1→2**: Find the bridge call in `WebViewBridge.ts` or `dsmClient.ts`
4. **Layer 2**: Find the method routing in `SinglePathWebViewBridge.kt`
5. **Layer 2→3**: Find the JNI call in `UnifiedNativeApi.kt` → `Unified.kt`
6. **Layer 3**: Find the JNI function in `unified_protobuf_bridge.rs`
7. **Layer 3→4**: Find the SDK-to-Core call
8. **Layer 4**: Find the core logic

For each layer, provide:
- File path and function name
- What data is passed (protobuf type or raw bytes)
- What transformation happens
- Error handling / failure modes

## Common Flows to Trace

| Flow | L1 Entry | L2 Route | L3 JNI | L4 Core |
|------|----------|----------|--------|---------|
| Genesis | `useGenesisFlow.ts` | `create_genesis` | `create_genesis.rs` | `state_machine.rs` |
| Balance query | `WalletContext.tsx` | `balance.get` | `token_sdk.rs` | `token/` |
| Bilateral send | `dsmClient.ts` | `bilateral.prepare` | `bilateral_sdk.rs` | `bilateral_transaction_manager.rs` |
| BLE transfer | `BleContext.tsx` | `BleCoordinator.kt` | `bilateral_ble_handler.rs` | `bilateral_transaction_manager.rs` |
| DLV create | `DevDlvScreen.tsx` | `dlv.create` | `dlv_sdk.rs` | `dlv_manager.rs` |
| dBTC mint | — | `bitcoin.mint` | `bitcoin_tap_sdk.rs` | `bitcoin/` |
| Bootstrap | `useAppBootstrap.ts` | `sdkBootstrap` | `bootstrap.rs` | `pbi.rs` |

## Cross-Layer Invariants

When tracing, verify these hold at EVERY boundary:
1. **No JSON** — protobuf binary at every handoff
2. **No wall-clock** — no timestamps crossing any boundary
3. **No hex** — raw bytes internally, Base32 Crockford only at UI boundary
4. **Envelope v3** — `0x03` framing everywhere
5. **Single path** — no side channels bypassing the stack
