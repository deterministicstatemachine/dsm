// SPDX-License-Identifier: MIT OR Apache-2.0

//! The device directory from the device's side (owner, 2026-09-23).
//!
//! This device writes its own entry — re-derived from the wallet seed, signed
//! with its AK — to its directory cell on every member of the set. To reach a
//! contact, a sender reads that contact's cell from every member and keeps the
//! entry that proves itself (`dsm::core::identity::directory::select_entry`).
//! The node stores and serves bytes; it decides nothing about whose entry is
//! whose.

use dsm::core::identity::directory::{
    directory_cell_key, select_entry, DirectoryEntry, DirectoryEntryBody, DIRECTORY_NAMESPACE,
};
use dsm::core::identity::genesis_v2::derive_atta;
use dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested;
use dsm::types::error::DsmError;

use crate::sdk::identity_presentation::OwnerIdentityInputs;
use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;

/// Build and sign this device's own entry. Everything is re-derived from the
/// wallet seed, as the anchor presentation is: nothing identity-bearing is
/// persisted. `expected_g` is the stored genesis id; a re-derivation that does
/// not land on it describes another identity and is refused.
pub fn build_own_entry(
    wallet_seed: &[u8],
    inputs: OwnerIdentityInputs<'_>,
    expected_g: &[u8; 32],
    kyber_public_key: Vec<u8>,
    counter: u64,
) -> Result<DirectoryEntry, DsmError> {
    let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
    let genesis = derive_genesis_v3_self_attested(
        wallet_seed,
        inputs.network_id,
        inputs.wallet_index,
        inputs.device_slot,
        inputs.genesis_version,
        &aph,
    )?;
    if &genesis.g != expected_g {
        return Err(DsmError::invalid_parameter(
            "device directory: the re-derived genesis is not this device's stored genesis",
        ));
    }
    let body = DirectoryEntryBody {
        genesis: genesis.g,
        device_id: genesis.devid,
        ak_public_key: genesis.ak_public.clone(),
        att_a: derive_atta(wallet_seed, &genesis.g, inputs.device_slot),
        kyber_public_key,
        counter,
    };
    let entry = DirectoryEntry::sign(body, &genesis.ak_secret)?;
    entry
        .verify()
        .map_err(|e| DsmError::verification(format!("device directory: own entry: {e}")))?;
    Ok(entry)
}

/// Write `entry` to its directory cell on every member of `set`. Which
/// members hold it is read back (`read_entry`), never inferred from the
/// write. A member keeps what it is given, so writing again is harmless.
pub async fn publish_entry(set: &StorageSet, entry: &DirectoryEntry) -> Result<(), DsmError> {
    let key = directory_cell_key(&entry.body.genesis, &entry.body.device_id);
    let taken = SetClient::new(set)?
        .put_cell(DIRECTORY_NAMESPACE, &key, &entry.encode())
        .await;
    log::debug!(
        "device directory: {taken}/{} members took the entry",
        set.len()
    );
    Ok(())
}

/// A directory entry that proves itself, and the members whose cell holds its
/// exact bytes.
#[derive(Debug, Clone)]
pub struct DirectoryRead {
    pub entry: DirectoryEntry,
    pub holders: Vec<String>,
}

/// Read `device_id`'s directory cell from every member of `set` and keep the
/// entry that proves itself, highest counter first, with the members that
/// hold it. `None` when no member holds one that does.
pub async fn read_entry(
    set: &StorageSet,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<Option<DirectoryRead>, DsmError> {
    let key = directory_cell_key(genesis, device_id);
    let client = SetClient::new(set)?;
    let reads = client.get_cell(DIRECTORY_NAMESPACE, &key).await;
    let values: Vec<&[u8]> = reads
        .iter()
        .flatten()
        .flatten()
        .map(Vec::as_slice)
        .collect();
    let Some(entry) = select_entry(genesis, device_id, values) else {
        return Ok(None);
    };
    let bytes = entry.encode();
    let holders = client
        .members()
        .iter()
        .zip(&reads)
        .filter(|(.., read)| read.as_ref().is_some_and(|held| held.contains(&bytes)))
        .map(|(member, ..)| member.member_id().to_string())
        .collect();
    Ok(Some(DirectoryRead { entry, holders }))
}
