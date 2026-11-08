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
/// not land on it describes another identity and is refused. The entry carries
/// the device's P0–P6 authority evidence and the transition it reaches, so a
/// reader can prove the device belongs to the genesis it names (DSM Amendment
/// A18).
pub fn build_own_entry(
    wallet_seed: &[u8],
    inputs: OwnerIdentityInputs<'_>,
    expected_g: &[u8; 32],
    kyber_public_key: Vec<u8>,
    counter: u64,
) -> Result<DirectoryEntry, DsmError> {
    let aph = dsm::core::identity::genesis_v2::genesis_authority_policy_hash();
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
    let (authority_evidence, authority_position) =
        crate::sdk::identity_presentation::build_authority_evidence(
            wallet_seed,
            inputs,
            expected_g,
        )?;
    let body = DirectoryEntryBody {
        genesis: genesis.g,
        device_id: genesis.devid,
        ak_public_key: genesis.ak_public.clone(),
        att_a: derive_atta(wallet_seed, &genesis.g, inputs.device_slot),
        kyber_public_key,
        counter,
        authority_position,
        authority_evidence,
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
    use crate::sdk::route_seats::RouteSeats;
    let key = directory_cell_key(genesis, device_id);
    let seats = crate::sdk::route_seats::NodeSeats::new(set)?;
    let members = seats.members();
    // Only an entry naming this device under this genesis is a candidate;
    // whether one proves itself is decided over the candidates, best first
    // (`select_entry`). Anything else a member holds costs the read and is
    // not kept, so junk under the predictable key wedges nothing (SA-67).
    let names_device = |bytes: &[u8]| {
        dsm::core::identity::directory::names_directory_entry(genesis, device_id, bytes)
    };
    let reads = futures::future::join_all(members.iter().map(|member| {
        crate::sdk::route_seats::kept_values(
            &seats,
            member,
            DIRECTORY_NAMESPACE,
            &key,
            &names_device,
        )
    }))
    .await;
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
    let holders = members
        .iter()
        .zip(&reads)
        .filter(|(.., read)| read.as_ref().is_some_and(|held| held.contains(&bytes)))
        .map(|(member, ..)| {
            String::from_utf8(member.clone()).map_err(|e| {
                DsmError::invalid_parameter(format!("device directory: a member id: {e}"))
            })
        })
        .collect::<Result<Vec<String>, DsmError>>()?;
    Ok(Some(DirectoryRead { entry, holders }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic_fixtures::NETWORK;
    use crate::sdk::storage_set::canonical_set;
    use crate::test_support::two_device::Pair;
    use serial_test::serial;

    /// How many members of `set` hold exactly `bytes` in the directory cell
    /// at `key`.
    async fn holding(set: &StorageSet, key: &[u8; 32], bytes: &[u8]) -> usize {
        SetClient::new(set)
            .expect("a client of the set")
            .held_at(DIRECTORY_NAMESPACE, key)
            .await
            .iter()
            .filter(|held| {
                held.as_ref()
                    .is_some_and(|values| values.iter().any(|value| value == bytes))
            })
            .count()
    }

    /// The directory entry `d`'s genesis session signed and kept.
    fn kept_entry(d: &crate::test_support::two_device::TestDevice) -> DirectoryEntry {
        d.enter();
        let bytes = crate::storage::client_db::own_directory_entry::load()
            .expect("read")
            .expect("the genesis session kept its entry");
        DirectoryEntry::decode(&bytes).expect("an entry")
    }

    /// MR-STOR-0035, storage spec §8.3, DSM §11 and Amendment A18: a device's
    /// genesis anchoring and its device-tree indexing are bytes under a key
    /// derived from its identity. B's genesis session publishes its directory
    /// entry, which every member holds in the one cell
    /// `H(DSM/device-directory-key/v1 ‖ 0x00 ‖ G ‖ DevID)`. A reads it back from
    /// the members and it proves itself: its genesis parameters recompute B's
    /// `G`, and P0–P6 on its evidence at the transition it names prove B's AK
    /// as the owner authority of a leaf of B's device tree. Beside it at every
    /// member, A then writes what it can sign with its own key: an entry
    /// naming B's genesis under A's device id, and an entry in B's own cell at
    /// a higher counter. Neither is taken: A is no device of B's account, and
    /// B's cell still reads B's entry.
    ///
    /// MUTATION CONTROL: the evidence check in `DirectoryEntry::verify`
    /// removed turns this red (A reads as a device of B's account); the
    /// signature check removed turns it red (B's cell reads A's entry).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_devices_entry_is_held_under_its_derived_key_and_proven_by_another_device() {
        let p = Pair::boot(0, 0).await;
        let set = canonical_set(NETWORK).expect("the pinned set");
        let own = kept_entry(&p.b);
        let key = {
            let mut h = blake3::Hasher::new();
            h.update(b"DSM/device-directory-key/v1");
            h.update(&[0x00]);
            h.update(&p.b.genesis);
            h.update(&p.b.device_id);
            *h.finalize().as_bytes()
        };
        assert_eq!(
            directory_cell_key(&p.b.genesis, &p.b.device_id),
            key,
            "the cell is the one the specification derives"
        );
        assert_eq!(
            holding(&set, &key, &own.encode()).await,
            set.len(),
            "every member holds B's entry in its cell"
        );

        // A reads B's entry back from the members, and checks it itself.
        p.a.enter();
        let read = read_entry(&set, &p.b.genesis, &p.b.device_id)
            .await
            .expect("read")
            .expect("B's entry proves itself");
        assert_eq!(read.entry, own);
        assert_eq!(read.holders.len(), set.len());
        let evidence = dsm::economic::authority_evidence::decode_authority_evidence(
            &read.entry.body.authority_evidence,
        )
        .expect("B's authority evidence");
        let params = dsm::ccb::decode::decode_genesis_params(&evidence.genesis_params_ccb)
            .expect("B's genesis parameters");
        assert_eq!(
            dsm::ccb::genesis::genesis_v3_commitment(&params).expect("a genesis"),
            p.b.genesis,
            "the parameters the entry carries recompute B's genesis"
        );
        let proven = dsm::economic::authority_evidence::verify_authority_evidence(
            &read.entry.body.authority_evidence,
            &p.b.genesis,
            &p.b.device_id,
            &read.entry.body.authority_position,
        )
        .expect("P0–P6 prove B's device under B's genesis");
        assert_eq!(proven.proven_ak, p.b.ak_pk);

        // What A can sign with its own key, written beside B's entry.
        let a_own = kept_entry(&p.a);
        let a_secret = crate::sdk::signing_authority::current_secret_key().expect("A's AK");
        let in_b_account = DirectoryEntry::sign(
            DirectoryEntryBody {
                genesis: p.b.genesis,
                counter: a_own.body.counter + 1,
                ..a_own.body.clone()
            },
            &a_secret,
        )
        .expect("A signs");
        let in_b_cell = DirectoryEntry::sign(
            DirectoryEntryBody {
                counter: own.body.counter + 1,
                ..own.body.clone()
            },
            &a_secret,
        )
        .expect("A signs");
        publish_entry(&set, &in_b_account).await.expect("written");
        publish_entry(&set, &in_b_cell).await.expect("written");
        let a_in_b = directory_cell_key(&p.b.genesis, &p.a.device_id);
        assert_eq!(
            holding(&set, &a_in_b, &in_b_account.encode()).await,
            set.len(),
            "every member holds A's entry naming B's genesis"
        );
        assert_eq!(
            holding(&set, &key, &in_b_cell.encode()).await,
            set.len(),
            "and A's entry in B's cell"
        );

        p.b.enter();
        let claimed = read_entry(&set, &p.b.genesis, &p.a.device_id)
            .await
            .expect("read");
        assert!(
            claimed.is_none(),
            "A is no device of B's account: {claimed:?}"
        );
        p.a.enter();
        let again = read_entry(&set, &p.b.genesis, &p.b.device_id)
            .await
            .expect("read")
            .expect("B's entry proves itself");
        assert_eq!(again.entry, own, "B's cell still reads B's entry");
    }
}
