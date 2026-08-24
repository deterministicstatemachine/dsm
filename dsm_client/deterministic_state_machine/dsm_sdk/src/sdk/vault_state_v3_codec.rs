// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verified fetch of the state-identity cut's immutable objects.
//!
//! `V_n` for a given `n` never changes, so there is nothing an overwrite
//! could mean: its identity is `c_n` and its address is a computation from
//! `c_n` — no index, no discovery, no `/latest`:
//!
//! ```text
//! c_n  = H_dom(DSM/vault-state, CCB(V_n))                      # identity
//! addr = H_dom(DSM/storage-object, "DSM/vault-state" ‖ c_n)    # location
//! ```
//!
//! Publication travels through the frozen-artifact sweep (write-once on the
//! tuple, per member of the vault's storage set); this module is the READ
//! side, on the one choke point that performs the client-side re-hash
//! against the requested identity (`storage_io::fetch_immutable_payload`).
//! Returned bytes are exact preimages; decoding them into trusted facts is
//! the P0–P6 verifier's job, never this module's.

use dsm::common::domain_tags::{TAG_DSM_ANCHOR_PRESENTATION_V1, TAG_DSM_VAULT_STATE};
use dsm::types::error::DsmError;
use prost::Message;

use crate::generated;

/// Fetch the exact `CCB(V_n)` bytes for a known `c_n`, verified client-side.
///
/// `Ok(None)` is absence — a liveness condition, not an error.
pub async fn fetch_vault_state_bytes(c_n: &[u8; 32]) -> Result<Option<Vec<u8>>, DsmError> {
    crate::sdk::storage_io::fetch_immutable_payload(TAG_DSM_VAULT_STATE, c_n).await
}

/// Fetch an `AnchorPresentationV3` by its advertised inner digest.
///
/// The transport layer's re-hash pins the exact bytes; the decode here is
/// structure only. NOTHING in the result is authenticated — the caller must
/// run it through `verify_anchor_presentation` before quoting against it.
pub async fn fetch_anchor_presentation(
    digest: &[u8; 32],
) -> Result<Option<generated::AnchorPresentationV3>, DsmError> {
    let Some(bytes) =
        crate::sdk::storage_io::fetch_immutable_payload(TAG_DSM_ANCHOR_PRESENTATION_V1, digest)
            .await?
    else {
        return Ok(None);
    };
    let p = generated::AnchorPresentationV3::decode(bytes.as_slice()).map_err(|e| {
        DsmError::verification(format!("anchor presentation fetch: decode failed: {e}"))
    })?;
    Ok(Some(p))
}
