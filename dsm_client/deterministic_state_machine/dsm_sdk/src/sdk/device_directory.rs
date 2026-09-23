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
use crate::sdk::storage_node_sdk::StorageNodeSDK;
use crate::sdk::storage_set::StorageSet;

fn cell_key_b32(genesis: &[u8; 32], device_id: &[u8; 32]) -> String {
    crate::util::text_id::encode_base32_crockford(&directory_cell_key(genesis, device_id))
}

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

/// Write `entry` to its directory cell on every member of `set`. Returns how
/// many members took it. A member keeps what it is given, so writing again is
/// harmless.
pub async fn publish_entry(
    storage: &StorageNodeSDK,
    set: &StorageSet,
    entry: &DirectoryEntry,
) -> u32 {
    let key = cell_key_b32(&entry.body.genesis, &entry.body.device_id);
    let bytes = entry.encode();
    let mut taken = 0u32;
    for member in 0..set.len() {
        match storage
            .put_cell_to_member(set, member, DIRECTORY_NAMESPACE, &key, &bytes)
            .await
        {
            Ok(_) => taken += 1,
            Err(e) => log::warn!("device directory: member {member} did not take the entry: {e}"),
        }
    }
    taken
}

/// Read `device_id`'s directory cell from every member of `set` and keep the
/// entry that proves itself, highest counter first. `None` when no member
/// holds one that does.
pub async fn read_entry(
    storage: &StorageNodeSDK,
    set: &StorageSet,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Option<DirectoryEntry> {
    let key = cell_key_b32(genesis, device_id);
    let reads = storage.get_cell_all(set, DIRECTORY_NAMESPACE, &key).await;
    let values: Vec<Vec<u8>> = reads
        .into_iter()
        .flatten()
        .flatten()
        .map(|(value, _record)| value)
        .collect();
    select_entry(genesis, device_id, values.iter().map(Vec::as_slice))
}
