---
applyTo: 'bilateral_settlement.rs, init.rs, create_genesis.rs, secondary_device.rs, recovery_impl.rs'
---

# Device Tree Root Lifecycle (§2.3.1)

## Overview

The Device Tree root `R_G` is a critical persistent value required for all bilateral transfer verification. Without it, receipt building fails silently, causing all bilateral transfers to fail settlement even though they succeed at the ledger level.

**INVARIANT**: After SDK initialization, `get_device_tree_root()` MUST return a valid 32-byte root. Violation of this invariant causes silent balance update failures.

## Computation

The Device Tree root is computed deterministically at initialization time:

```
R_G = DeviceTree::single(DevID).root()
```

Where:
- `DevID` is the 32-byte device identifier (canonical device public key hash)
- `DeviceTree::single()` creates a minimal single-device tree
- `.root()` computes the tree's Merkle root using BLAKE3 domain-separated hash

## Persistence Requirement

**MANDATORY**: `R_G` MUST be persisted to device storage (AppState) immediately after:
1. **Primary genesis creation**
2. **Secondary device addition**
3. **SDK initialization on app restart**
4. **Device recovery from encrypted capsule**

### Failure Mode If Not Persisted

| Step | Result | Impact |
|------|--------|--------|
| After genesis | `get_device_tree_root()` returns `None` | ❌ No root available |
| Bilateral prepare | `build_bilateral_receipt_with_smt()` returns `None` | ❌ No cryptographic proof |
| Settlement context | `proof_data` becomes `None` | ❌ No proof bytes in context |
| Settlement guard | Rejects: "missing proof_data" | ❌ Transfer fails at settlement |
| Balance update | Never persisted to projection | ❌ Balance stuck at pre-transfer value |
| User experience | Transfer appears to succeed, balance doesn't update | ❌ **SILENT DATA LOSS** |

## Initialization Points

### 1. Primary Genesis Creation

**File**: `jni/create_genesis.rs` lines 240-252

```rust
// Compute and persist Device Tree root (§2.3) so that
// build_bilateral_receipt_with_smt can verify DevID ∈ R_G.
// Without this, get_device_tree_root() always returns None,
// causing every bilateral receipt build to fail → proof_data None →
// settle() rejects the transfer → balance never updates.
if gc.device_id.len() == 32 {
    let mut dev_arr = [0u8; 32];
    dev_arr.copy_from_slice(&gc.device_id);
    let root = dsm::common::device_tree::DeviceTree::single(dev_arr).root();
    crate::sdk::app_state::AppState::set_device_tree_root(root);
    log::info!("[Genesis] Device tree root computed and persisted for bilateral receipt verification");
}
```

**Ensures**: Primary device gets valid R_G at account creation time.

### 2. Secondary Device Addition

**File**: `jni/secondary_device.rs` lines 120-128

```rust
// Compute and persist Device Tree root (§2.3) — same as primary genesis path.
if device_id.len() == 32 {
    let mut dev_arr = [0u8; 32];
    dev_arr.copy_from_slice(&device_id);
    let root = dsm::common::device_tree::DeviceTree::single(dev_arr).root();
    crate::sdk::app_state::AppState::set_device_tree_root(root);
    log::info!("[SecondaryDevice] Device tree root persisted for bilateral receipt verification");
}
```

**Ensures**: Each new device gets unique R_G (not shared with primary).

**Multi-Device Scenario**:
- Device A: `R_G_A = hash_leaf(DevID_A)`
- Device B: `R_G_B = hash_leaf(DevID_B)`
- Device A cannot use Device B's root

### 3. App Restart / SDK Initialization

**File**: `init.rs` lines 425-445

```rust
// Backfill Device Tree root (§2.3) for existing identities created before this was
// persisted at genesis time.  The root of a single-device tree is deterministic from
// dev_fixed, so it is always safe to recompute and overwrite.
// Without the root, build_bilateral_receipt_with_smt returns None → proof_data None →
// settle() rejects every bilateral transfer → balance never updates.
{
    let root = dsm::common::device_tree::DeviceTree::single(dev_fixed).root();
    crate::sdk::app_state::AppState::set_device_tree_root(root);
    log::info!(
        "[SDK Init] Device tree root computed and persisted (dev={})",
        crate::util::text_id::encode_base32_crockford(&dev_fixed)
    );
}
```

**Ensures**: Existing users (app restart or backward compatibility) always have valid R_G.

**Safety**: Deterministic recomputation from `device_id` guarantees consistency. Always safe to call multiple times.

### 4. Device Recovery from Capsule

**File**: `handlers/recovery_impl.rs` (recovery capsule decryption)

```rust
// Extract device_tree_root from decrypted capsule (§2.3.1)
let device_tree_root = decrypted.device_tree_root
    .ok_or_else(|| DsmError::recovery("device_tree_root missing from recovery capsule"))?;

// Restore to AppState so bilateral receipt building works post-recovery
AppState::set_device_tree_root(device_tree_root);
log::info!("[RECOVERY] Device tree root restored from capsule");
```

**Ensures**: Recovered device can build bilateral receipts immediately after recovery.

## Related Functions

| Function | Purpose | Depends On |
|----------|---------|-----------|
| `AppState::get_device_tree_root()` | Retrieve persistent R_G | None |
| `AppState::set_device_tree_root()` | Persist R_G to storage | None |
| `DeviceTree::single(device_id).root()` | Compute R_G deterministically | device_id only |
| `build_bilateral_receipt_with_smt(..., r_g, ...)` | Build bilateral proof | Requires R_G ≠ None |
| `DefaultBilateralSettlementDelegate::settle()` | Accept/reject transfer | Requires proof_data (via R_G) |

## Recovery Path Exception

**File**: `handlers/bilateral_settlement.rs` lines 208-220

```rust
// Recovery-path settlements are allowed to have None proof_data
// (BLE GATT failure scenario where receipt delivery failed).
// Only enforce proof_data presence for normal bilateral path.
let is_recovery = ctx.tx_type == "bilateral_offline_recovered";
if transfer_amount > 0 && !is_recovery {
    let has_proof = ctx.proof_data.as_ref().is_some_and(|proof| !proof.is_empty());
    if !has_proof {
        return Err("missing proof_data for bilateral transfer settlement (strict fail-closed path)".to_string());
    }
}
```

**Why**: Recovery transfers have legitimate None proof_data (receipt never delivered due to BLE failure). Without this exception, balance updates fail even though transfer is valid.

**Strict Still Applies**: Normal bilateral path still requires proof_data; only recovery path gets exception.

## Validation Hooks (Fail-Safe Recovery)

### Hook 1: Bootstrap Emergency Backfill

**File**: `init.rs` after line 445

If device_tree_root is None after normal initialization, emergency backfill from device_id. This catches edge cases where set_device_tree_root was skipped.

### Hook 2: Bilateral Prepare Gate

**File**: `handlers/app_router_impl.rs` before receipt building

Pre-flight check: if R_G is None, reject bilateral transfer immediately with clear error instead of failing silently downstream.

## Testing

**File**: `tests/device_tree_root_lifecycle_tests.rs`

Eight test cases covering:
1. Persistence at genesis
2. Uniqueness per device
3. Determinism across restarts
4. Receipt failure without root
5. Receipt success with root
6. Bootstrap backfill validation
7. Recovery capsule restoration
8. Recovery path settlement without proof_data

## Migration & Backward Compatibility

✅ **Fully backward compatible**:
- Deterministic recomputation from device_id is always safe
- Can be called multiple times without inconsistency
- Existing users get backfilled automatically on next app startup
- No data loss or migration required

## Summary

Device Tree root R_G is the critical persistent value that enables bilateral receipt verification. It is computed deterministically at each device initialization, persisted to AppState, and used by all bilateral transfer operations. Without it, transfers fail silently—balances never update.

The persistence requirement is enforced at 4 initialization points:
1. Primary genesis (new account)
2. Secondary device (multi-device)
3. App restart (existing users)
4. Recovery (post-device-loss)

Validation hooks provide fail-safe recovery if any step is skipped.
