# Chapter 11 — Integration Guide

Building custom wallets, replacing the frontend, and integrating with the DSM protocol.

---

## Integration Paths

| Path | Scope | Effort |
|------|-------|--------|
| Custom React frontend | Replace the UI, keep the bridge | Medium |
| Native Android app | Use JNI directly, skip WebView | High |
| Protocol extension | Add new operations to the core | Very High |

---

## Custom Frontend (Replace React UI)

The React frontend communicates with the Rust SDK via a binary MessagePort bridge. You can replace the entire UI while keeping the same bridge protocol.

### Bridge Protocol

The frontend sends binary messages through a MessagePort channel:

```
[8-byte msgId (u64 BE)][BridgeRpcRequest protobuf bytes]
```

And receives responses in the same format:

```
[8-byte msgId (u64 BE)][BridgeRpcResponse protobuf bytes]
```

### Required Steps

1. **Generate protobuf types** for your language/framework from `proto/dsm_app.proto`
2. **Implement the MessagePort handshake** — the Android WebView sets up the port during page load
3. **Send RPC requests** as protobuf-encoded `BridgeRpcRequest` messages
4. **Handle responses** by correlating `msgId` values

If your integration also owns DLV or policy specifications, use `dsm-gen` to generate typed client builders instead of hand-rolling those structures. See [Chapter 16 — Code Generation](16-code-generation.md).

### Key RPC Methods

| Method | Purpose | Request Type | Response Type |
|--------|---------|-------------|---------------|
| `getBalance` | Query wallet balance | — | Balance info |
| `getTransactions` | List transaction history | — | Transaction list |
| `getDeviceId` | Get device identity | — | Device ID bytes |
| `bilateralPrepare` | Start a bilateral transfer | Prepare params | Prepare result |
| `bilateralAccept` | Accept incoming transfer | Accept params | Accept result |
| `bilateralCommit` | Commit the transfer | Commit params | Commit result |
| `bleCommand` | Execute BLE operation | BleCommand | BleCommandResponse |
| `dlvCreate` | Create a Limbo Vault | DLV params | DLV result |
| `bitcoinSwapInitiate` | Start BTC↔dBTC swap | Swap params | Swap result |

### Frontend Bundle Location

The built frontend must be placed in:
```
dsm_client/android/app/src/main/assets/web/
```

The `index.html` in assets root loads the bundle and sets up the MessagePort.

---

## Native Android Integration (JNI Direct)

Skip the WebView and call JNI methods directly from Kotlin/Java.

### Setup

1. Include `libdsm_sdk.so` for your target ABIs in `jniLibs/`
2. Load the library: `System.loadLibrary("dsm_sdk")`
3. Declare external methods matching `UnifiedNativeApi.kt`

### JNI Method Declaration

```kotlin
object NativeApi {
    init {
        System.loadLibrary("dsm_sdk")
    }

    // All methods accept/return protobuf byte arrays
    external fun sdkBootstrap(config: ByteArray): ByteArray
    external fun getBalance(request: ByteArray): ByteArray
    external fun bilateralPrepare(request: ByteArray): ByteArray
    // ... 87+ methods available
}
```

### Bootstrap Sequence

1. Call `sdkBootstrap` with device config (DBRW entropy, storage node URLs)
2. Wait for `SDK_READY` (poll via `sdkReady()`)
3. If no identity exists, call `createGenesis` to initialize via MPC
4. All other methods are now available

### Important Constraints

- All data exchange is protobuf-encoded bytes — no JSON
- The `0x03` framing byte appears on genesis responses — strip it before parsing
- BLE operations require Android Bluetooth permissions and the `BleCoordinator` actor
- DBRW anti-cloning binds the identity to the specific device hardware

---

## Storage Node Service Integration

Build app-specific services or operator tools that communicate with storage nodes.

This is not a public-blockchain indexer model. DSM storage nodes are replicated persistence endpoints for DSM artifacts, not a global open ledger for passive observation. In practice, a service here usually means something like:

- an app backend that submits or retrieves protocol artifacts for identities, vaults, or objects it already knows about
- an operator tool that checks node health, replication, or object availability
- a mirror, backup, or audit service for a closed set of DSM-managed users or application objects
- a domain-specific service that processes DLV, policy, inbox, or recovery artifacts for a particular product flow

### Endpoints

All operational endpoints accept protobuf (`application/octet-stream`):

```bash
# Health check (plain-text response)
curl http://localhost:8080/api/v2/health

# Submit an envelope (protobuf request)
curl -X POST http://localhost:8080/api/v2/envelope \
  -H "Content-Type: application/octet-stream" \
  --data-binary @envelope.bin

# Query identity
curl -X POST http://localhost:8080/api/v2/identity \
  -H "Content-Type: application/octet-stream" \
  --data-binary @identity_query.bin
```

### Replica Selection

Determine which nodes hold a given identity's state:

```
node_indices = keyed_fisher_yates(
    key:   BLAKE3("DSM/assign\0" || identity_hash),
    count: total_nodes,
    pick:  N_replicas  // 6
)
```

Write to all N replicas; read from K (3) replicas for durability.

### Client Libraries

The SDK includes a Rust storage node client (`sdk/storage_node_sdk.rs`). For other languages, implement the protobuf RPC contract defined in `proto/dsm_app.proto` for the specific endpoints your service needs.

For specification-driven client code, run `cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts,kotlin,swift,rust`.

---

## Protocol Extension (Advanced)

Adding new operations to the DSM protocol requires changes across all four layers.

### Checklist

1. **Spec first** — write or update the public specification in `docs/book/`, `docs/papers/`, or `proto/dsm_app.proto`
2. **Proto schema** — add message types to `proto/dsm_app.proto`
3. **Core logic** — implement validation in `dsm/src/`
4. **SDK integration** — add JNI methods in `dsm_sdk/src/jni/`
5. **Kotlin bridge** — declare external methods in `UnifiedNativeApi.kt`
6. **Frontend** — regenerate proto types (`npm run proto:gen`), add UI

### Cross-Layer Consistency

For any protocol change, consult ALL layer CLAUDE.md files:

| Layer | File |
|-------|------|
| Rust | `dsm_client/deterministic_state_machine/CLAUDE.md` |
| Android | `dsm_client/android/CLAUDE.md` |
| Frontend | `dsm_client/new_frontend/CLAUDE.md` |

### Hard Invariants

Any protocol extension must respect the 12 hard invariants (see [Chapter 1](01-introduction.md#the-12-hard-invariants)). Key constraints:

- Protobuf-only (no JSON)
- No wall-clock time in protocol logic
- All hashing uses BLAKE3 with domain separation
- Token conservation must be maintained
- Storage nodes remain index-only

---

Next: [Chapter 12 — Command Reference](12-command-reference.md)
