// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable publication of `CCB(V_n)` — the first real consumer of the
//! Area 4 substrate.
//!
//! `V_n` for a given `n` never changes, so there is nothing an overwrite
//! could mean: the object is immutable by nature and the substrate makes it
//! immutable in fact. Its identity is `c_n` and its address is a computation
//! from `c_n` — no index, no discovery, no `/latest`:
//!
//! ```text
//! c_n  = H_dom(DSM/vault-state, CCB(V_n))                      # identity
//! addr = H_dom(DSM/storage-object, "DSM/vault-state" ‖ c_n)    # location
//! ```
//!
//! A verifier that holds `c_n` (from an AnchorV3, whose sole authoritative
//! content it is) resolves the exact bytes, re-hashes them against the `c_n`
//! it asked for, and refuses anything else. This module returns **verified
//! bytes**; decoding them into fields is the step-5 resolver's job.

use dsm::ccb::{vault_state_commitment, VaultStateV2};
use dsm::common::domain_tags::TAG_DSM_VAULT_STATE;
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::StorageNodeSDK;

/// Encode, derive `c_n`, and publish `CCB(V_n)` to every configured node.
///
/// Returns `(c_n, addr_b32, acks)`. The address the nodes store under is
/// checked server-side against the client's own derivation via the
/// expected-address header, so an encoder disagreement refuses loudly instead
/// of storing under a different key.
pub async fn publish_vault_state(
    sdk: &StorageNodeSDK,
    state: &VaultStateV2,
) -> Result<([u8; 32], String, u32), DsmError> {
    let ccb = state
        .encode()
        .map_err(|e| DsmError::invalid_parameter(format!("vault state encode: {e}")))?;
    let c_n = vault_state_commitment(state)
        .map_err(|e| DsmError::invalid_parameter(format!("vault state commitment: {e}")))?;
    let (addr_b32, acks) = sdk.publish_immutable(TAG_DSM_VAULT_STATE, &ccb).await?;
    Ok((c_n, addr_b32, acks))
}

/// Fetch the exact `CCB(V_n)` bytes for a known `c_n`, verified client-side.
///
/// Returns `Ok(None)` when no node holds the object (absence — a liveness
/// condition, not an error) and refuses bytes that do not re-hash to the
/// requested identity. The re-hash inside `fetch_immutable_verified` already
/// implies `H_dom(DSM/vault-state, bytes) = c_n` — the address preimage is
/// length-unambiguous, so address equality pins both the namespace and the
/// inner digest — but the property this function's callers rely on is stated
/// and checked here directly rather than inherited silently.
pub async fn fetch_vault_state_bytes(
    sdk: &StorageNodeSDK,
    c_n: &[u8; 32],
) -> Result<Option<Vec<u8>>, DsmError> {
    let Some(bytes) = sdk
        .fetch_immutable_verified(TAG_DSM_VAULT_STATE, c_n)
        .await?
    else {
        return Ok(None);
    };
    // Defence in depth, and the contract made explicit: these bytes ARE the
    // preimage of the c_n the caller asked about.
    let recomputed = dsm::storage_object::immutable_inner(TAG_DSM_VAULT_STATE, &bytes);
    if recomputed != *c_n {
        return Err(DsmError::verification(
            "vault state fetch: bytes do not hash to the requested c_n",
        ));
    }
    Ok(Some(bytes))
}
