---
name: emissions-guide
description: Expert guide for DJTE (Deterministic Join-Triggered Emissions) — JAP proofs, ShardCountSMT, SpentProofSMT, halving schedule, winner selection, credit bundles, and PaidK spend-gate. Use when working on token distribution or emission mechanics.
---

# DJTE Emissions Expert Guide

You are an expert on DSM's Deterministic Join-Triggered Emissions system. DJTE distributes tokens deterministically on join events — no consensus, no wall-clock time, proof-carrying objects only.

## Core Architecture

### Join Activation Proof (JAP)

```
jap_hash = BLAKE3("DJTE.JAP" || id || gate || nonce)
```

- Produced when a device unlocks the spend-gate (pays required storage replica set)
- Single-use — consumed on claim
- Tracked in SpentProofSMT

### Shard Function

```
Shard(id) = prefix_b(BLAKE3("DJTE.SHARD" || id))
```

- Partitions identities into `2^b` shards
- Deterministic mapping from identity to shard
- Used for sharded storage and winner selection descent

### ShardCountSMT

Complete binary tree over shard prefixes:
- Permits proving total `N = count(ε)` (root gives global count)
- Deterministically maps global rank `k ∈ [0,N)` to `shard + local index` in `O(b)` node proofs
- The `O(b)` descent is **information-theoretically minimal** — cannot be replaced by random walks

### SpentProofSMT

SMT mapping `jap_hash → 1` if consumed, else absent:
- Prevents double-consumption of JAPs
- Proof of non-membership proves a JAP hasn't been spent yet

## Halving Schedule

**Parameters**: `Π = (S_total, b, E=16, M_0, r_0)`

### Per-Epoch Calculation

```
Epoch i:
  M_i = 2^i × M_0           (milestone threshold doubles each epoch)
  r_i = ⌊r_0 / 2^i⌋         (reward halves each epoch)

Per emission e:
  amount_e = min(r_epoch(e), remaining_e)
  remaining_{e+1} = remaining_e - amount_e
```

**Supply cap**: `remaining` never goes negative (Lemma 1).

**E = 16 epochs** by default.

## Winner Selection

### UniformIndex(R, N)

Deterministic rejection sampling over 256-bit hash:
- Same `seed + N` → same index, always
- Uniform distribution over `[0, N)`
- No bias from modular reduction

### Shard Descent

Walk ShardCountSMT from root using `O(b)` proofs:
1. Start at root with global rank `k`
2. At each node, compare `k` against left child count
3. Descend left if `k < left_count`, else descend right with `k -= left_count`
4. Reach leaf = target shard + local index

Deterministic, globally uniform from sharded storage.

## PaidK Spend-Gate

**Clockless activation**: Requires payment to K distinct storage nodes before gate opens.

- Storage nodes: `storagenodes.instructions.md` §16
- K = 3 (default read quorum)
- No time-based gating — purely economic
- Each payment is a bilateral transfer to a storage node

## Credit Bundles

```
C_bundle = 1000 per activation
```

- Sender-pays economic rate limiting
- No wall-clock time involved
- Prevents spam without global mempool
- Contact-gated inboxes add structural spam resistance

## Hard Guarantees (§8)

1. **Determinism**: Same inputs → same emission, always
2. **Single-use JAPs**: SpentProofSMT prevents double-consumption
3. **Global uniformity**: Winner selection is uniform over all participants
4. **Non-reuse**: Consumed JAPs cannot be replayed
5. **Supply cap**: Total emissions bounded by `S_total`

## Code Locations

| Component | Path |
|-----------|------|
| Emissions logic | `dsm/src/emissions.rs` |
| Token SDK | `dsm_sdk/src/sdk/token_sdk.rs` |
| Token types | `dsm/src/core/token/` |
| CPTA policies | `dsm/src/cpta/` |
| Frontend | `new_frontend/src/TokenManagementScreen.tsx` |

## Domain Tags

| Tag | Usage |
|-----|-------|
| `"DJTE.JAP"` | Join Activation Proof hash |
| `"DJTE.SHARD"` | Shard function mapping |

Note: DJTE uses `"DJTE."` prefix, NOT `"DSM/"` — this is intentional domain separation.

## Spec Reference

Primary: `.github/instructions/emissions.instructions.md` (§3-§8, §11-§12)
Cross-refs: `storagenodes.instructions.md` (§16 PaidK), `whitepaper.instructions.md` (§8 conservation)
