---
name: wire-format
description: Expert guide for DSM wire format — Envelope v3 framing, protobuf schema v2.4.0, BridgeRpc binary protocol, MessagePort encoding, and proto type reference. Use when working on serialization, bridge protocol, or wire format issues.
---

# DSM Wire Format Expert Guide

You are an expert on the DSM wire format — Envelope v3, protobuf schema v2.4.0, and the binary bridge protocol.

## Envelope v3

**Hard Invariant #1**: Envelope v3 is the sole wire container. `0x03` framing byte prefix.

### Framing

Every Envelope on the wire is prefixed with a single `0x03` byte:

```
Wire: [0x03][Envelope protobuf bytes]
```

To decode:
```typescript
// CORRECT — use decodeFramedEnvelopeV3()
function decodeFramedEnvelopeV3(data: Uint8Array): Envelope {
  if (data[0] !== 0x03) throw new Error("Not v3 framing");
  return Envelope.fromBinary(data.slice(1));
}

// WRONG — raw decode will fail on framing byte
Envelope.fromBinary(data);  // NEVER DO THIS ON WIRE DATA
```

### Envelope Proto

```protobuf
message Envelope {
  uint32 version = 1;        // Always 3
  // reserved 2;             // NEVER a wall-clock field
  Hash32 sender_device = 3;
  Hash32 recipient_device = 4;
  bytes payload = 5;
  bytes signature = 6;
  // ... additional fields
}
```

**Schema options**: `dsm_schema_semver = "2.4.0"`, `dsm_envelope_epoch = 3`

## BridgeRpc Binary Protocol

### MessagePort Wire Format

```
[8-byte msgId (u64 BigEndian)][BridgeRpcRequest protobuf bytes]
```

- `msgId`: Unique request ID, monotonically increasing u64
- Response correlates by same msgId
- Transport: `MessagePort` with `ArrayBuffer` transfer

### BridgeRpcRequest

```protobuf
message BridgeRpcRequest {
  string method = 1;     // e.g., "balance.get", "bilateral.prepare"
  bytes payload = 2;     // Method-specific protobuf payload
  string request_id = 3; // Correlating ID
}
```

### BridgeRpcResponse

```protobuf
message BridgeRpcResponse {
  bool success = 1;
  bytes payload = 2;     // Method-specific protobuf response
  string error = 3;      // Error message if !success
  string request_id = 4; // Correlating ID
}
```

### Method Routing

Frontend calls `bridge.invoke(method, payload)` → Kotlin `SinglePathWebViewBridge.handleBinaryRpc()` routes by method name → JNI → SDK.

Common method names:
| Method | Direction | Purpose |
|--------|-----------|---------|
| `balance.get` | query | Get balance for token |
| `balance.list` | query | List all balances |
| `bilateral.prepare` | invoke | Initiate bilateral send |
| `bilateral.accept` | invoke | Accept bilateral receive |
| `bilateral.commit` | invoke | Finalize bilateral |
| `bilateral.reconcile` | invoke | Auto-reconcile diverged state |
| `dlv.create` | invoke | Create DLV vault |
| `dlv.unlock` | invoke | Unlock DLV vault |
| `bitcoin.mint` | invoke | Mint dBTC |
| `bitcoin.burn` | invoke | Burn dBTC |
| `bitcoin.balance` | query | Get dBTC balance |
| `create_genesis` | invoke | Create genesis state |
| `diagnostics.metrics` | query | Get diagnostic metrics |

## Key Proto Types

### Primitives

```protobuf
message Hash32 { bytes value = 1; }  // 32-byte hash, annotated dsm_fixed_len=32
message Hash16 { bytes value = 1; }  // 16-byte hash
message U128 { bytes value = 1; }    // 128-bit unsigned (16 bytes big-endian)
message S128 { bytes value = 1; }    // 128-bit signed
```

### Bilateral Protocol

```protobuf
message BilateralPrepare {
  Hash32 sender_device = 1;
  Hash32 recipient_device = 2;
  U128 amount = 3;
  string token_type = 4;
  Hash32 parent_tip = 5;
  bytes sender_signature = 6;
}

message BilateralAccept {
  Hash32 session_id = 1;
  bytes recipient_signature = 2;
  bytes smt_proof = 3;
}

message BilateralCommit {
  Hash32 session_id = 1;
  bytes receipt_commit = 2;  // Canonical ReceiptCommit
  bytes sender_signature = 3;
  bytes recipient_signature = 4;
}
```

### ReceiptCommit (Canonical)

10 fields in strict tag order. Hash: `BLAKE3("DSM/receipt-commit\0" || canonical_bytes)`

```protobuf
message ReceiptCommit {
  Hash32 genesis = 1;
  Hash32 devid_a = 2;
  Hash32 devid_b = 3;
  Hash32 parent_tip = 4;
  Hash32 child_tip = 5;
  Hash32 parent_root = 6;
  Hash32 child_root = 7;
  bytes rel_proof_parent = 8;
  bytes rel_proof_child = 9;
  bytes dev_proof = 10;
}
```

### Transaction Types

```protobuf
enum TransactionType {
  FAUCET = 0;
  BILATERAL_OFFLINE = 1;
  BILATERAL_OFFLINE_RECOVERED = 2;
  ONLINE = 3;
  DBTC_MINT = 4;
  DBTC_BURN = 5;
}
```

### DLV / Fulfillment

```protobuf
message DlvCreate {
  Hash32 vault_id = 1;
  Hash32 device_id = 2;
  Hash32 policy_digest = 3;
  bytes precommit = 4;
  FulfillmentMechanism mechanism = 5;
}

message FulfillmentMechanism {
  // reserved 1;  // NO time-based mechanism
  oneof mechanism {
    HashPreimage hash_preimage = 2;
    MultiSig multi_sig = 3;
    ThresholdSig threshold_sig = 4;
  }
}
```

### Bitcoin / Atomic Swap

```protobuf
message BitcoinHTLC {
  uint32 min_confirmations = 1;  // Default 100 (deep-anchor)
  bytes script = 2;
  bytes preimage_hash = 3;
}

message AtomicSwapRequest { ... }
message AtomicSwapResponse { ... }
message AtomicSwapCompleteRequest { ... }
message AtomicSwapFulfillment { ... }
```

### Evidence (Clockless)

```protobuf
message EvidenceClock {
  uint64 attested_iterations = 1;  // NOT wall-clock time
  Hash32 chain_tip = 2;
}
```

## Proto Regeneration

After ANY change to `proto/dsm_app.proto`:

```bash
cd dsm_client/new_frontend && npm run proto:gen
```

This generates `src/proto/dsm_app_pb.ts`. **Never inline or duck-type proto shapes.**

## Common Pitfalls

1. **Genesis response has `0x03` prefix** — must strip before decode
2. **Bridge timeout** — default 30000ms in `index.html`
3. **MessagePort is ArrayBuffer** — not string, not JSON
4. **Proto types must be regenerated** — never use inline casts
5. **DSM-CPE encoding** — fields ascending by tag, maps sorted by key

## Spec Reference

Primary: `.github/instructions/proto.instructions.md` (full schema)
Cross-refs: `rules.instructions.md` (ban list), `storagenodes.instructions.md` §3 (DSM-CPE)
