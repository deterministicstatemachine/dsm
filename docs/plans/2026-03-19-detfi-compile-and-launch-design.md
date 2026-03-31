# DeTFi Compile & Launch — Design Document

**Date:** 2026-03-19
**Status:** Approved design, phased implementation
**Author:** Brandon + Claude

---

## Problem

DeTFi (Deterministic Finance) primitives already exist in the DSM codebase — DLVs,
external commitments, pre-commitment forking, smart commitments, token policies.
But there's no way for a developer to go from a declarative specification to a
running sovereign vault without manually orchestrating multiple SDK calls across
multiple screens. We need a compile-and-launch pipeline: write a spec, compile it,
paste it into the phone, and it's live.

## Design Principle

DSM is not a VM. It's a grammar of deterministic composition built on
relationship-local state. The compiled artifacts are not "programs" in the
imperative sense — they are **content-addressed deterministic objects** with
predicates, hashes, and proofs. Expressiveness comes from composing these objects
via pre-commitments, external commitments, and forward-linked chains, not from
general code execution.

## The Three Levels

### Level 0: Object Space — Content-Addressed Deterministic Objects

Individual cryptographic artifacts, each valid standalone:

| Object | Proto Type | Size | Content-Addressed By |
|--------|-----------|------|---------------------|
| Vault template | `DlvCreateV3` | 160 bytes (5x 32B fields) | `vault_id = BLAKE3("DSM/dlv\0" \|\| device_id \|\| policy_digest \|\| precommit)` |
| Token policy | `TokenPolicyV3` | Variable (up to 65KB) | `anchor = BLAKE3(canonical_proto_bytes)` |
| External commitment | `ExternalCommit` | Variable | `commit_id = BLAKE3("DSM/external-commit-id\0" \|\| source_id \|\| payload \|\| evidence_hash)` |

**Vault templates** have device-specific fields (device_id, precommit) left as
zeros. The phone fills them at instantiation time with the user's identity and
signs with SPHINCS+. This makes templates shareable — anyone can instantiate the
same spec on their own device.

**Token policies** are fully self-contained and immutable once published. Their
anchor hash is their identity. Compile once, reference forever.

**External commitments** are the atomic triggers — multiple objects can reference
the same commitment, and all unlock together or none do.

**Deployment modes** (per object):
- **Posted**: Object published to storage nodes. Creator goes offline. Counterparty
  fulfills against any replica. Creator's keys NOT in the fulfillment path.
- **Local**: Object lives only on creator's device. Fulfillment via bilateral
  protocol (BLE/QR/NFC). Creator must be present.

### Level 1: Composition Space — Declarative Compositions of Objects

Manifests that compose Level 0 objects with relationships:

- **Pre-commitment fork bindings**: N vaults bound to a single PreCommitment.
  Selecting one fork cryptographically invalidates all others (Tripwire guarantee).
  Use case: "If oracle says X → vault A. If oracle says Y → vault B. If timeout
  → return to owner."

- **External commitment groups**: Multiple vaults reference the same `ExtCommit(X)`.
  All unlock atomically or none do. Use case: Alice and Bob both hold vaults
  referencing the same Bitcoin HTLC preimage — reveal it, both unlock.

- **Deployment orchestration**: Which objects get published to storage nodes, which
  stay local, which external commitments need to be registered.

A composition manifest compiles down to: N DlvCreateV3 templates + PreCommitment
config + ExternalCommit registrations + deployment instructions.

### Level 2: Protocol Flow — Staged Compositions

Ordered compositions where completion of one object graph enables the next:

- **Forward-linked commitments**: `ForwardLinkedCommitment` chains C1 → C2 → C3.
  Each step is its own composition. Completion of step N cryptographically gates
  step N+1 via `next_state_hash` binding.

- **RouteSet integration**: All active vaults on the same CPTA manifold form a
  liquidity grid. Off-chain routing services compute paths; vault predicates
  reject invalid routes. If one vault is busy, re-route to next available.

- **Multi-step protocols**: Deposit → Confirm → Settle, where each phase is a
  Level 1 composition and forward links chain them into a coherent flow.

---

## Implementation Phases

### Phase 1: Object Space (Build Now)

**Goal**: `dsm-gen compile` produces atom blobs. Phone `detfi.launch` instantiates them.

#### 1a. Extend dsm-gen with `compile` subcommand

```
dsm-gen compile <spec.yaml> [--mode posted|local] [--policy-anchor <b32>] [--output <file>]
```

For `type: "vault"` specs:
1. Parse YAML through existing `VaultSpecification` schema
2. Convert `FulfillmentConditionSpec` → `FulfillmentMechanism` proto
3. Build `DlvCreateV3` with:
   - `device_id`: zeros (template placeholder)
   - `policy_digest`: from `--policy-anchor` flag or zeros
   - `precommit`: BLAKE3("DSM/dlv/precommit\0" || reveal_material) where reveal
     is derived deterministically from the spec hash
   - `vault_id`: BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)
4. Serialize to protobuf bytes
5. Prepend 2-byte header: version (1 byte) + mode flag (1 byte: 0=local, 1=posted)
6. Encode as Base32 Crockford
7. Output to stdout or file

For `type: "policy"` specs:
1. Parse YAML through existing `PolicySpecification` schema
2. Build `CanonicalPolicy` proto (author, conditions, roles)
3. Wrap in `TokenPolicyV3`
4. Serialize + Base32 encode
5. Output

**Key files to modify:**
- `dsm-gen/src/main.rs` — add `Compile` CLI subcommand
- `dsm-gen/src/schema.rs` — add `deployment_mode` field to `VaultSpecification`
  (optional, default "posted")
- New: `dsm-gen/src/compiler.rs` — compilation logic (YAML → proto bytes → Base32)

**Dependencies:** dsm-gen needs `prost` for proto encoding (already a dependency).
The `DlvCreateV3` and `TokenPolicyV3` types come from the proto build. If protoc
isn't available at build time, fall back to manual byte construction matching the
known wire format.

#### 1b. Add `detfi.launch` bridge route

New route in the AppRouter that accepts a compiled blob and instantiates it:

```
Frontend:  paste Base32 blob → appRouterInvokeBin('detfi.launch', argPackBytes)
Rust:      decode blob → check version byte → check mode flag
           → if vault: fill device_id, compute vault_id, create DLV
             → if posted: publish to storage nodes
             → if local: store locally only
           → if policy: publish policy, return anchor
           → return { type, vault_id?, policy_anchor?, mode }
Frontend:  show success with IDs
```

**Key files to modify:**
- `dsm_sdk/src/handlers/` — new `detfi_routes.rs` handler
- `dsm_sdk/src/handlers/app_router_impl.rs` — register `detfi.*` route family
- `frontend/src/dsm/` — new `detfi.ts` with `launchDeTFi()` function
- `frontend/src/components/screens/` — new `DeTFiLaunchScreen.tsx` or extend
  DevDlvScreen with a "Launch DeTFi" tab

#### 1c. Pre-loaded templates

The 4 DeTFi example vaults and 2 policies from `examples/detfi/` get pre-compiled
into Base32 blobs and embedded in the frontend. Users can select a template from
a list, see a description of what it does, and launch it with one tap.

#### 1d. Extend VaultSpecification schema

Add fields now (even if Phase 1 compiler only uses `deployment_mode`):

```rust
pub struct VaultSpecification {
    // ... existing fields ...
    pub deployment_mode: Option<DeploymentMode>,  // posted | local (default: posted)
    pub external_commits: Option<Vec<String>>,     // context strings for atomic grouping
    pub fork_group: Option<String>,                // pre-commitment group name
}

pub enum DeploymentMode {
    Posted,
    Local,
}
```

These fields are `Option` so existing YAML specs remain valid without them.

### Phase 2: Composition Space (Build Next)

**Goal**: `dsm-gen compile` handles `type: "program"` YAML with multi-vault
compositions.

#### 2a. Program YAML schema

```yaml
type: "program"
name: "AtomicSwap"
version: "1.0.0"

steps:
  - id: "alice-vault"
    type: "vault"
    deployment_mode: "posted"
    # ... full vault spec ...
    external_commits: ["swap-preimage"]

  - id: "bob-vault"
    type: "vault"
    deployment_mode: "posted"
    # ... full vault spec ...
    external_commits: ["swap-preimage"]

atomics:
  - source: "swap-preimage"
    vaults: ["alice-vault", "bob-vault"]

forks:
  - group: "outcome-selection"
    branches:
      - id: "success"
        vault: "alice-vault"
        condition: { type: "crypto_condition", ... }
      - id: "timeout"
        vault: "bob-vault"
        condition: { type: "payment", ... }
```

#### 2b. Program compiler

Compiles the program YAML into a `DeTFiProgram` proto containing:
- All vault templates (DlvCreateV3 per step)
- PreCommitment with fork bindings
- External commitment registrations
- Deployment mode per vault

#### 2c. Phone executes programs

The `detfi.launch` route handles program blobs by executing steps in order:
1. Publish any referenced policies
2. Create all vaults (fill device_id per vault)
3. Build pre-commitment with fork bindings
4. Register external commitments on storage nodes
5. Return all IDs

### Phase 3: Protocol Flow (Future)

**Goal**: Forward-linked commitment chains and route integration.

- `ForwardLinkedCommitment` support in YAML (`next_step` references)
- RouteSet discovery queries against storage nodes
- Live vault status monitoring in the UI
- Multi-step protocol execution with completion gating

---

## Proto Schema Extension

### Phase 1 (minimal)

```protobuf
// Compiled DeTFi artifact header (prepended to any proto payload)
// Byte 0: version (currently 1)
// Byte 1: mode (0 = local, 1 = posted)
// Byte 2: type (0 = vault, 1 = policy)
// Bytes 3+: proto payload
```

No new proto messages needed for Phase 1 — we reuse existing `DlvCreateV3` and
`TokenPolicyV3` with a 3-byte header prefix.

### Phase 2

```protobuf
message DeTFiProgram {
  uint32 version = 1;
  repeated DeTFiStep steps = 2;
  repeated AtomicGroup atomics = 3;
  repeated ForkGroup forks = 4;
}

message DeTFiStep {
  string id = 1;
  uint32 mode = 2;  // 0=local, 1=posted
  oneof artifact {
    DlvCreateV3 vault = 10;
    TokenPolicyV3 policy = 11;
  }
  repeated string external_commits = 20;
}

message AtomicGroup {
  string source = 1;
  repeated string vault_refs = 2;
}

message ForkGroup {
  string group_id = 1;
  repeated ForkBranch branches = 2;
}

message ForkBranch {
  string id = 1;
  string vault_ref = 2;
  FulfillmentMechanism condition = 3;
}
```

---

## Key Invariants

1. **No YAML at runtime.** Compilation happens at dev time via `dsm-gen`. The phone
   only ever sees proto bytes (Base32-encoded for transport).

2. **Posted mode: creator keys not in fulfillment path.** The creator provides
   setup (predicates, hashes, signatures). The counterparty later provides proofs
   against published data. Storage nodes only mirror evidence.

3. **Templates are device-independent.** device_id = zeros in compiled blobs. The
   phone stamps its own identity at instantiation time. Same template, different
   user, different vault.

4. **Atoms are first-class.** A single vault blob is not a degenerate program — it
   is a content-addressed deterministic object. Programs compose atoms; they don't
   replace them.

5. **Clockless throughout.** All timeouts use `duration_iterations` (hash-chain
   tick counts). No wall-clock time at any level.

---

## Verification Plan

### Phase 1

1. `dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml` → produces Base32 blob
2. `dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --mode local` → blob with mode=0
3. Blob decodes back to valid `DlvCreateV3` with device_id = zeros
4. `cargo test -p dsm-gen --test detfi_compile` — round-trip tests for all 4 vault examples
5. Phone `detfi.launch` route accepts blob, fills device_id, creates vault
6. Posted mode: vault appears on storage node
7. Local mode: vault exists only in local state
8. Pre-loaded templates selectable in UI, one-tap launch works

### Phase 2

1. Program YAML with 2 vaults + atomic group compiles to single blob
2. Phone `detfi.launch` creates both vaults + registers external commitment
3. Fulfilling the external commitment unlocks both vaults atomically
4. Pre-commitment fork selection invalidates non-selected branches

---

## File Index

| Purpose | Path |
|---------|------|
| CLI entry (add Compile) | `dsm-gen/src/main.rs` |
| YAML schema (extend) | `dsm-gen/src/schema.rs` |
| Compiler (new) | `dsm-gen/src/compiler.rs` |
| Compile tests (new) | `dsm-gen/tests/detfi_compile.rs` |
| Bridge route (new) | `dsm_sdk/src/handlers/detfi_routes.rs` |
| AppRouter registration | `dsm_sdk/src/handlers/app_router_impl.rs` |
| Frontend helper (new) | `frontend/src/dsm/detfi.ts` |
| Launch screen (new/extend) | `frontend/src/components/screens/DeTFiLaunchScreen.tsx` |
| DLV creation (existing) | `dsm/src/vault/dlv_manager.rs` |
| Pre-commitment (existing) | `dsm/src/commitments/precommit.rs` |
| External commits (existing) | `dsm/src/commitments/external_commitment.rs` |
| DLV pre-commit SDK (existing) | `dsm_sdk/src/sdk/dlv_pre_commitment_sdk.rs` |
| Storage node DLV API (existing) | `dsm_storage_node/src/api/dlv_slot.rs` |
| Proto definitions (extend Phase 2) | `proto/dsm_app.proto` |
| DeTFi examples | `examples/detfi/` |
