---
name: storage-guide
description: Expert guide for DSM storage nodes — index-only architecture, replica placement, ByteCommit chaining, capacity signals, PaidK spend-gate, DLV slot anchoring, and the 20-section spec. Use when working on storage node features.
---

# DSM Storage Node Expert Guide

You are a storage node expert. DSM storage nodes are **dumb** — they store, mirror, and enforce arithmetic. They NEVER sign, validate state, gate acceptance, or affect unlock predicates.

## Hard Invariant #12

**Storage nodes are index-only** — never sign, never gate acceptance, never affect unlock predicates.

## Architecture

- Index-only, clockless, signature-free, protobuf-only
- DLV slot anchoring, ByteCommit mirroring, replica placement (keyed Fisher-Yates)
- Parameters: N=6, K=3, U_up=0.85, U_down=0.35

## DSM-CPE (Deterministic Protocol Buffers) — §3

Canonical protobuf encoding rules:
- Fields ascending by tag number
- Map entries sorted by key as raw bytes
- Varints shortest form
- **No JSON, no base64, no hex, no CBOR** — ever

## Device ID — §4

```
DevID_A = BLAKE3("DSM/device\0" || pk_A || attest)
```

DBRW binding:
```
K_bind = BLAKE3("DSM/DBRW\0" || BLAKE3(HW_entropy || ENV_fp))
```

## Genesis Anchor — §5

Commit-reveal, clockless:
```
G = BLAKE3("DSM/genesis\0" || ProtoDet(A_0))
s_0 = BLAKE3("DSM/step-salt\0" || G)
```

## Replica Placement — §6

```
replicas(addr) = first N entries of Permute(BLAKE3("DSM/place\0" || addr), N)
```

- Keyed Fisher-Yates shuffle using BLAKE3 as RNG
- N=6 replicas total
- K=3 for read quorum (any K replies sufficient)
- Deterministic: same address → same replica set

## ByteCommit Chaining — §7

Each node maintains Per-Node Storage SMT. After every cycle:

```
ByteCommitV3 {
  node_id,
  cycle_index,
  smt_root,
  bytes_used,
  parent_digest = BLAKE3(B_{t-1})
}
```

Chained: each ByteCommit references hash of previous. Unforgeable history.

## Capacity Signals — §8

**UpSignal** (I want to join/grow): Emitted when utilization < U_up (0.85)
**DownSignal** (I want to shrink/leave): Emitted when utilization < U_down (0.35)

```
Position delta: ΔP = |U| − |D| over window w
```

No wall-clock time — signals measured over cycle windows.

## Registry — §9

`RegistryV3` — sorted ascending lexicographic node IDs.

Applicant ranking:
- Deterministic salt
- Rank by hash
- No VRF, no leader
- Pure deterministic selection

## Contacts — §12

```
ContactAddV3: domain "DSM/contact/add\0"
ContactAcceptV3: domain "DSM/contact/accept\0"
```

Nodes never verify SPHINCS+ signatures — client-side only.

## CPTA / Token Policies — §13

`TokenPolicyV3` + `PolicyAnchorV3`
- Nodes mirror policy bytes
- Devices MUST cache policy locally and verify compliance
- Nodes never interpret policy content

## DLV Create/Open — §14

```
DLVCreateV3:
  vault_id = BLAKE3("DSM/dlv\0" || device_id || policy_digest || precommit)

DLVOpenV3:
  verifies preimage
```

**Nodes do NOT gate, unlock, or attest vaults.**

## Stake DLV / Signature-Free Exit — §15

```
StakeDLV = BLAKE3("DSM/stake\0" || node_id || S || policy)
```

Stake unlocks when valid `DrainProof` is mirrored:
- d consecutive accepted ByteCommits
- No signatures involved — purely hash-chain based

## PaidK Spend-Gate — §16

Clockless economic gate:
- Requires payment to K distinct storage nodes
- No time-based mechanism
- Gate opens when K payments verified
- Prevents sybil without consensus

## Parameters — §19

| Parameter | Value | Purpose |
|-----------|-------|---------|
| N | 6 | Replica count |
| K | 3 | Read quorum |
| U_up | 0.85 | Join threshold |
| U_down | 0.35 | Leave threshold |
| w | (config) | Signal window size |
| G_new | (config) | Grace cycles for new nodes |

## Code Locations

| Component | Path |
|-----------|------|
| Storage node binary | `dsm_storage_node/src/` |
| Storage SDK | `dsm_sdk/src/sdk/storage_node_sdk.rs` |
| Storage health | `dsm_sdk/src/sdk/storage_node_health.rs` |
| Frontend | `new_frontend/src/StorageScreen.tsx` |
| Storage cluster service | `new_frontend/src/services/storageclusterservice.ts` |

## What Storage Nodes CANNOT Do

| Action | Allowed? |
|--------|----------|
| Store data | Yes |
| Mirror ByteCommits | Yes |
| Enforce arithmetic (capacity) | Yes |
| Sign transactions | NO |
| Validate state transitions | NO |
| Gate vault acceptance | NO |
| Affect unlock predicates | NO |
| Interpret CPTA policy | NO |
| Verify SPHINCS+ signatures | NO |

## Spec Reference

Primary: `.github/instructions/storagenodes.instructions.md` (§1-§20)
Cross-refs: `whitepaper.instructions.md` (§2 hash chains), `emissions.instructions.md` (§16 PaidK)
