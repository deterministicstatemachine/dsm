// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery's objects on the network's pinned set (storage spec §8.3): each
//! lives in its keyed cell, [`dsm::recovery::RecoveryCell`].
//!
//! A member stores every entry it is sent and refuses nothing (§6), so a read
//! gathers every entry any member holds, and the caller keeps what verifies.
//! Nothing a member returns is authority: every recovery object is signed, and
//! the rule that picks among verified entries is the reader's.

use dsm::recovery::RecoveryCell;
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;

fn pinned_set() -> Result<StorageSet, DsmError> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    crate::sdk::storage_set::canonical_set(&network)
}

/// Put `bytes` in `cell` at every member of the pinned set. Returns how many
/// members took it; none taking it is an error.
pub(crate) async fn put(cell: &RecoveryCell, bytes: &[u8]) -> Result<u32, DsmError> {
    let set = pinned_set()?;
    let took = SetClient::new(&set)?
        .put_cell(RecoveryCell::namespace(), &cell.key(), bytes)
        .await;
    if took == 0 {
        return Err(DsmError::network(
            "recovery store: no member of the pinned set took the write",
            None::<std::io::Error>,
        ));
    }
    Ok(took)
}

/// Every distinct entry any member holds in `cell`, members in set order and
/// each member's entries in arrival order. An error when no member answered;
/// an empty list when the members that answered hold nothing there.
pub(crate) async fn entries(cell: &RecoveryCell) -> Result<Vec<Vec<u8>>, DsmError> {
    let set = pinned_set()?;
    let reads = SetClient::new(&set)?
        .get_cell(RecoveryCell::namespace(), &cell.key())
        .await;
    if reads.iter().all(Option::is_none) {
        return Err(DsmError::network(
            "recovery store: no member of the pinned set answered the read",
            None::<std::io::Error>,
        ));
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    for held in reads.into_iter().flatten() {
        for entry in held {
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    Ok(out)
}

/// The AK of `device_id` under `genesis`, from the device's own directory
/// entry, which proves itself (`H(AK ‖ AttA)` is the device id and the entry
/// is signed by that AK).
pub(crate) async fn device_ak(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    let set = pinned_set()?;
    let read = crate::sdk::device_directory::read_entry(&set, genesis, device_id)
        .await?
        .ok_or_else(|| {
            DsmError::verification(
                "no member of the pinned set holds a directory entry for the device that \
                 proves itself",
            )
        })?;
    Ok(read.entry.body.ak_public_key)
}
