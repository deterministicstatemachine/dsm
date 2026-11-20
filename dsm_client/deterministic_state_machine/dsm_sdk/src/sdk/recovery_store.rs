// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery's objects on the network's pinned set (storage spec §8.3): each
//! lives in its keyed cell, [`dsm::recovery::RecoveryCell`].
//!
//! A recovery cell belongs to the device that writes it (owner ruling,
//! 2026-11-19): its address is its route bound to the owner's cell lock, and
//! every member keeps a write there only when that lock signed it
//! (`dsm::owned_cell`). A device writes only its own cells, under the lock it
//! derives from its master seed; a reader names whose cell it reads and finds
//! that device's lock in its self-proving directory entry. A read still keeps
//! only objects of the cell's kind ([`RecoveryCell::holds`]), and the caller
//! keeps what verifies: nothing a member returns is authority.

use dsm::recovery::{CellOwner, RecoveryCell};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;

fn pinned_set() -> Result<StorageSet, DsmError> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    crate::sdk::storage_set::canonical_set(&network)
}

/// This device's cell lock, from its master seed: the key every cell it owns
/// is bound to, and the one its directory entry publishes.
fn own_cell_lock() -> Result<dsm::crypto::sphincs::SphincsKeyPair, DsmError> {
    let seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::InvalidState("recovery store: the wallet is locked; no cell lock".into())
        })?;
    let id32 = |v: Option<Vec<u8>>, what: &str| -> Result<[u8; 32], DsmError> {
        let bytes =
            v.ok_or_else(|| DsmError::InvalidState(format!("recovery store: no {what}")))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|e| DsmError::InvalidState(format!("recovery store: {what}: {e}")))
    };
    let genesis = id32(
        crate::sdk::app_state::AppState::get_genesis_hash(),
        "genesis",
    )?;
    let device_id = id32(
        crate::sdk::app_state::AppState::get_device_id(),
        "device id",
    )?;
    let s_master = crate::init::smaster_of(seed.as_slice(), &genesis, &device_id);
    dsm::owned_cell::derive_cell_lock_keypair(&s_master, &device_id)
}

/// Put `bytes` in this device's own `cell` at every member of the pinned set,
/// signed by its cell lock. Returns how many members took it; none taking it
/// is an error.
pub(crate) async fn put(cell: &RecoveryCell, bytes: &[u8]) -> Result<u32, DsmError> {
    let set = pinned_set()?;
    let lock = own_cell_lock()?;
    let (address, proof) = dsm::owned_cell::sign_owned_cell_write(
        RecoveryCell::namespace(),
        &cell.key(),
        &lock,
        bytes,
    )?;
    let took = SetClient::new(&set)?
        .put_proven_cell(RecoveryCell::namespace(), &address, bytes, &proof)
        .await;
    if took == 0 {
        return Err(DsmError::network(
            "recovery store: no member of the pinned set took the write",
            None::<std::io::Error>,
        ));
    }
    Ok(took)
}

/// Every distinct entry any member holds in `owner`'s `cell` that is an
/// object of the cell's kind, members in set order and each member's entries
/// in arrival order. Only `owner`'s cell lock writes there. An error when the
/// owner has no directory entry that proves itself or no member answered; an
/// empty list when the members that answered hold nothing there.
pub(crate) async fn entries(
    owner: &CellOwner,
    cell: &RecoveryCell,
) -> Result<Vec<Vec<u8>>, DsmError> {
    use crate::sdk::route_seats::RouteSeats;
    let set = pinned_set()?;
    let lock = cell_lock(&owner.genesis, &owner.device_id).await?;
    let seats = crate::sdk::route_seats::NodeSeats::new(&set)?;
    let key = cell.address(&lock);
    let holds = |bytes: &[u8]| cell.holds(bytes);
    let reads = futures::future::join_all(seats.members().iter().map(|member| {
        crate::sdk::route_seats::kept_values(
            &seats,
            member,
            RecoveryCell::namespace(),
            &key,
            &holds,
        )
    }))
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

/// The self-proving directory entry of `device_id` under `genesis`.
async fn proven_entry(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<dsm::core::identity::directory::DirectoryEntry, DsmError> {
    let set = pinned_set()?;
    let read = crate::sdk::device_directory::read_entry(&set, genesis, device_id)
        .await?
        .ok_or_else(|| {
            DsmError::verification(
                "no member of the pinned set holds a directory entry for the device that \
                 proves itself",
            )
        })?;
    Ok(read.entry)
}

/// The AK of `device_id` under `genesis`, from the device's own directory
/// entry, which proves itself (`H(AK ‖ AttA)` is the device id and the entry
/// is signed by that AK).
pub(crate) async fn device_ak(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    Ok(proven_entry(genesis, device_id).await?.body.ak_public_key)
}

/// The cell lock of `device_id` under `genesis`: the key its self-proving
/// directory entry publishes, the one every cell it owns is bound to.
pub(crate) async fn cell_lock(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    Ok(proven_entry(genesis, device_id)
        .await?
        .body
        .cell_lock_public_key)
}
