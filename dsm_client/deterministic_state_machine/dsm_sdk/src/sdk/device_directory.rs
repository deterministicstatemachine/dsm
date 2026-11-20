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
    let s_master = crate::init::smaster_of(wallet_seed, &genesis.g, &genesis.devid);
    let first_inbox_lock = dsm::core::relationship_write_grant::derive_first_inbox_lock_keypair(
        &s_master,
        &genesis.devid,
    )?;
    let cell_lock = dsm::owned_cell::derive_cell_lock_keypair(&s_master, &genesis.devid)?;
    let body = DirectoryEntryBody {
        genesis: genesis.g,
        device_id: genesis.devid,
        ak_public_key: genesis.ak_public.clone(),
        att_a: derive_atta(wallet_seed, &genesis.g, inputs.device_slot),
        kyber_public_key,
        first_inbox_lock_public_key: first_inbox_lock.public_key.clone(),
        cell_lock_public_key: cell_lock.public_key.clone(),
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

/// Write `entry` to its directory cell on every member of `set`, with the
/// proof every member checks before it keeps it: the device's AK and AttA,
/// whose hash is the device id the cell is bound to, and `ak_secret`'s
/// signature (owner ruling, 2026-11-19: only the device writes its own
/// cell). Which members hold it is read back (`read_entry`), never inferred
/// from the write. Writing the same entry again is harmless.
pub async fn publish_entry(
    set: &StorageSet,
    entry: &DirectoryEntry,
    ak_secret: &[u8],
) -> Result<(), DsmError> {
    let bytes = entry.encode();
    let (key, proof) = dsm::owned_cell::sign_directory_cell_write(
        &entry.body.genesis,
        &entry.body.ak_public_key,
        &entry.body.att_a,
        ak_secret,
        &bytes,
    )?;
    if key != directory_cell_key(&entry.body.genesis, &entry.body.device_id) {
        return Err(DsmError::invalid_parameter(
            "device directory: the entry's AK and AttA are not its device id",
        ));
    }
    let taken = SetClient::new(set)?
        .put_proven_cell(DIRECTORY_NAMESPACE, &key, &bytes, &proof)
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
    // Of each member's values a reader keeps only an entry that names this
    // device, outranks every entry proven before it there, and proves
    // itself, ranked as `select_entry` ranks: what it holds of a member is
    // the entries that were best in turn, never everything the member holds,
    // so junk under the predictable key wedges nothing (SA-67). Each distinct
    // value is proven once across the members (SA-142).
    let verdicts: std::sync::Mutex<std::collections::BTreeMap<[u8; 32], Result<(), String>>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let proves = |entry: &DirectoryEntry| -> Result<(), String> {
        let digest = dsm::storage_cell::entry_digest(&entry.encode());
        let held = verdicts
            .lock()
            .map_err(|e| format!("the directory verdicts: {e}"))?
            .get(&digest)
            .cloned();
        let verdict = match held {
            Some(verdict) => verdict,
            None => entry.verify().map_err(|why| why.to_string()),
        };
        verdicts
            .lock()
            .map_err(|e| format!("the directory verdicts: {e}"))?
            .insert(digest, verdict.clone());
        verdict
    };
    let reads = futures::future::join_all(members.iter().map(|member| {
        let best = std::sync::Mutex::new(dsm::core::identity::directory::BestProvenEntry::new(
            genesis, device_id,
        ));
        let (proves, seats, key) = (&proves, &seats, &key);
        async move {
            let keeps_best = |bytes: &[u8]| match best.lock() {
                Ok(mut best) => matches!(
                    best.offer(bytes, proves),
                    dsm::core::identity::directory::Offered::Taken
                ),
                Err(poisoned) => matches!(
                    poisoned.into_inner().offer(bytes, proves),
                    dsm::core::identity::directory::Offered::Taken
                ),
            };
            crate::sdk::route_seats::kept_values(
                seats,
                member,
                DIRECTORY_NAMESPACE,
                key,
                &keeps_best,
            )
            .await
        }
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
        publish_entry(&set, &in_b_account, &a_secret)
            .await
            .expect("written");
        publish_entry(&set, &in_b_cell, &a_secret)
            .await
            .expect("sent");
        let a_in_b = directory_cell_key(&p.b.genesis, &p.a.device_id);
        assert_eq!(
            holding(&set, &a_in_b, &in_b_account.encode()).await,
            set.len(),
            "A writes its own device's cell, even one naming B's genesis"
        );
        // B's cell is B's (owner ruling, 2026-11-19): A's AK is not the key
        // B's device id is the hash of, so no member keeps A's write there.
        // MUTATION CONTROL: dropping the directory check in
        // `dsm::owned_cell::admit_cell_write` lets every member keep it and
        // turns this red.
        assert_eq!(
            holding(&set, &key, &in_b_cell.encode()).await,
            0,
            "no member keeps A's write in B's cell"
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
