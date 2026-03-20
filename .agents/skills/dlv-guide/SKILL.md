---
name: dlv-guide
description: Expert guide for DLV (Deterministic Limbo Vaults) and DeTFi sovereign finance — vault lifecycle, unlock predicates, external commitments, routing, and sovereign execution. Use when working on vaults or DeTFi features.
---

# DLV / DeTFi Expert Guide

You are a DeTFi expert specializing in Deterministic Limbo Vaults (DLVs). DeTFi replaces custodial DeFi pools with per-user sovereign vaults. Liquidity stays sovereign. Settlement by math, not consensus.

## Core Concepts

### DLV Formula

```
Vault_i = DLV(R_pre, CPTA, UnlockLogic, Funds)
```

- `R_pre`: Precommitment — anchored to user's genesis commitment
- `CPTA`: Content-Addressed Token Policy Anchor — defines token rules
- `UnlockLogic`: Non-Turing-complete predicates, bounded, constant-time verifiable
- `Funds`: Token balance locked in vault

### Key Formulas

- **Vault ID**: `vault_id = BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)`
- **Unlock Key**: `sk_V = H(L || C || σ)` — infeasible before σ exists; computable by anyone once valid σ constructed
- **External Commit**: `ExtCommit(X) = BLAKE3("DSM/ext" || X)` — multiple vaults reference same X, all unlock atomically or none

### Vault State Machine

```
Created → PendingActive → Active → Burn+Sweep → PendingClosure → Claimed
```

**State Transitions:**
- `Created`: Vault ID computed, precommitment anchored
- `PendingActive`: Awaiting entry confirmation (Bitcoin burial for dBTC)
- `Active`: Fully operational, can trade, can exit
- `Burn+Sweep`: User initiated settlement
- `PendingClosure`: Awaiting exit confirmation
- `Claimed`: Vault finalized, BTC released

### DLV Operational State

```
State_n = {
  genesis_owner,     // Genesis commitment of vault creator
  DevID_owner,       // Device ID of current owner
  reservesA,         // Token A reserves
  reservesB,         // Token B reserves
  unlock_conditions, // Predicate set
  fee_structure,     // Fee parameters
  parent_tip h_n,    // Hash chain tip
  smt_root r_owner   // Per-Device SMT root
}
```

## External Commitments

`ExtCommit(X) = BLAKE3("DSM/ext" || X)`

- Multiple vaults can reference the same external commitment X
- Either ALL unlock atomically or NONE do
- No coordinator signature needed — math enforces atomicity
- Use case: multi-vault exits drawing from a liquidity grid

### Proto Types

```protobuf
message ExternalCommit {
  Hash32 source_id = 1;    // BLAKE3("DSM/external-source-id\0" || source_bytes)
  Hash32 commit_id = 2;    // BLAKE3("DSM/external-commit-id\0" || ...)
  bytes payload = 3;
}
```

## Smart Commitments

Non-Turing-complete predicates with bounded execution:
- Constant-time verification
- No loops, no recursion
- Predicate composition via AND/OR/THRESHOLD

## Routing & RouteSets

- Off-chain routing services compute paths over public data
- Router trust eliminated: vault predicates reject invalid routes
- RouteSets treat all active vaults on same CPTA manifold as liquidity grid
- If one vault is busy, exits re-route to next available vault

## Sovereign Execution

Each party verifies independently:
1. Hash adjacency (chain continuity)
2. Inclusion proofs (SMT)
3. Invariant satisfaction (token conservation, predicates)
4. External commitment existence
5. Token conservation

No validators, no consensus, no global ordering.

## MEV Mitigation

DeTFi structurally eliminates MEV through:
- Pre-commitment (hash-locked conditions)
- Bilateral settlement (no global mempool)
- External commitments (atomic multi-vault)
- No transaction ordering dependency
- Contact-gated inboxes (spam resistance)

## Threat Model

| Threat | Result |
|--------|--------|
| Storage node compromise | Cannot steal funds, execute trades, or modify conditions |
| Routing manipulation | Cannot force unlocks or steal funds |
| Vault owner compromise | Recovery via DSM protocol (capsule/tombstone) |

## Code Locations

| Component | Path |
|-----------|------|
| DLV Manager | `dsm/src/vault/dlv_manager.rs` |
| Limbo Vault | `dsm/src/vault/limbo_vault.rs` |
| Fulfillment | `dsm/src/vault/fulfillment.rs` |
| Smart Commitments | `dsm/src/commitments/smart_commitment.rs` |
| External Commitments | `dsm/src/commitments/external_commitment.rs` |
| DLV SDK | `dsm_sdk/src/sdk/dlv_sdk.rs` |
| Smart Commitment SDK | `dsm_sdk/src/sdk/smart_commitment_sdk.rs` |
| External Commitment SDK | `dsm_sdk/src/sdk/external_commitment_sdk.rs` |
| Frontend | `new_frontend/src/DevDlvScreen.tsx` |
| Proto types | `DlvCreate`, `DlvUnlock`, `FulfillmentMechanism` |

## Storage Node Interaction

Nodes store DLV data but NEVER:
- Sign vault operations
- Gate acceptance or rejection
- Affect unlock predicates
- Validate state transitions

Storage node DLV operations: `DLVCreateV3`, `DLVOpenV3` (§14-§15 in storagenodes spec)

## Spec References

- Primary: `.github/instructions/detfi.instructions.md` (§2-§8)
- Storage: `.github/instructions/storagenodes.instructions.md` (§14-§15)
- dBTC vaults: `.github/instructions/dBTC.instructions.md` (§3, §6-§8)
- Whitepaper: `.github/instructions/whitepaper.instructions.md` (§8 conservation)
