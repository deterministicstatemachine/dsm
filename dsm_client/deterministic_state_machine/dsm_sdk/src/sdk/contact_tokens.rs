// SPDX-License-Identifier: MIT OR Apache-2.0
//! Which tokens a contact can be sent (owner, 2026-11-21).
//!
//! A device credits a token only once it has added it, so a contact that
//! sends it one it has not added is debited for a transfer the device
//! refuses, and the relationship waits on that transfer. So each wallet
//! states the tokens it has added in a list its AK signs and keeps in its
//! own directory cell on the storage nodes
//! (`dsm::core::identity::token_list`), and reads its contacts' lists from
//! the nodes when it opens. What it read is kept on the device: the Send
//! screen offers a contact only the tokens kept for it, and a send of any
//! other token is refused before anything is debited. Nothing is read from
//! the network on a send's path, except that a token missing from what is
//! kept has the contact's lists read once more before the send is refused.
//!
//! The protocol's own assets need no list: every device holds them.

use std::collections::BTreeSet;

use dsm::core::identity::directory::{directory_cell_key, DirectoryEntry, DIRECTORY_NAMESPACE};
use dsm::core::identity::token_list::{tokens_added, DeviceTokenList};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::route_seats::RouteSeats;
use crate::sdk::storage_node_sdk::SetClient;
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::contact_tokens as kept;
use crate::storage::client_db::ContactRecord;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(
        format!("contact tokens: {what}: {e}"),
        None::<std::io::Error>,
    )
}

/// Whether `policy_commit` is one of the protocol's own assets, which every
/// device holds without adding it.
fn protocol_asset(policy_commit: &[u8; 32]) -> bool {
    dsm::core::token::token_state_manager::builtin_token_id_for_policy_commit(policy_commit)
        .is_some()
}

/// The tokens this device has added: every token of its registry whose
/// adoption its committed head carries, the protocol's own assets left out.
pub(crate) fn own_added_tokens(core: &CoreSDK) -> Result<BTreeSet<[u8; 32]>, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| storage_err("own tokens", "no device head"))?;
    Ok(crate::storage::client_db::token_registry::all_tokens()
        .map_err(|e| storage_err("the token registry", e))?
        .into_iter()
        .map(|row| row.policy_commit)
        .filter(|commit| !protocol_asset(commit) && head.has_adopted(commit))
        .collect())
}

/// What publishing this device's own list came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnList {
    /// The list last published already states every token added.
    Current,
    /// A list stating every token added was signed and written to the
    /// device's directory cell at a storage quorum of members.
    Published,
    /// The device has no directory entry of its own yet: it is not published,
    /// and its list follows its entry.
    NoEntryYet,
}

/// Publish this device's list of the tokens it has added, when it has added
/// one its last published list does not state (or has published none). The
/// list goes to the device's own directory cell, beside its entry, under the
/// same proof: only the device writes there.
pub(crate) async fn publish_own_token_list(
    core: &CoreSDK,
    set: &StorageSet,
) -> Result<OwnList, DsmError> {
    let added = own_added_tokens(core)?;
    let published = kept::own_published().map_err(|e| storage_err("own list", e))?;
    if let Some(bytes) = &published {
        let stated: BTreeSet<[u8; 32]> = DeviceTokenList::decode(bytes)
            .map_err(|e| storage_err("own list", e))?
            .policy_commits
            .into_iter()
            .collect();
        if stated == added {
            return Ok(OwnList::Current);
        }
    }
    // A device that has added nothing and stated nothing has nothing to
    // state: a contact that finds no list offers it the protocol's own assets,
    // as it does a device whose list is empty.
    if added.is_empty() && published.is_none() {
        return Ok(OwnList::Current);
    }
    let Some(entry) = crate::storage::client_db::own_directory_entry::load()
        .map_err(|e| storage_err("own directory entry", e))?
    else {
        return Ok(OwnList::NoEntryYet);
    };
    let entry =
        DirectoryEntry::decode(&entry).map_err(|e| storage_err("own directory entry", e))?;
    let ak_secret = crate::sdk::signing_authority::current_secret_key()?;
    let list = DeviceTokenList::sign(entry.body.genesis, entry.body.device_id, added, &ak_secret)?;
    let bytes = list.encode();
    let (key, proof) = dsm::owned_cell::sign_directory_cell_write(
        &entry.body.genesis,
        &entry.body.ak_public_key,
        &entry.body.att_a,
        &ak_secret,
        &bytes,
    )?;
    let taken = SetClient::new(set)?
        .put_proven_cell(DIRECTORY_NAMESPACE, &key, &bytes, &proof)
        .await;
    let quorum = dsm::sofi::wire::STORAGE_FINALITY_COUNT;
    if usize::try_from(taken).map_err(|e| storage_err("members", e))? < quorum {
        return Err(storage_err(
            "own list",
            format!(
                "{taken} of {} members took it, short of {quorum}",
                set.len()
            ),
        ));
    }
    kept::store_own_published(&bytes).map_err(|e| storage_err("own list", e))?;
    log::info!(
        "[contact tokens] own list of {} token(s) published at {taken}/{} members",
        list.policy_commits.len(),
        set.len()
    );
    Ok(OwnList::Published)
}

/// The topic that tells the page a contact is now kept as having added a
/// token it was not kept as having added before. No payload.
pub(crate) const CONTACT_TOKENS_TOPIC: &str = "contact.tokens";

/// Read `contact`'s token lists from its directory cell at every member of
/// `set`, and keep the tokens they add. Answers what the lists that verify
/// under the contact's pinned AK state; `None` when the contact has stated
/// none, which keeps nothing.
pub(crate) async fn refresh_contact(
    set: &StorageSet,
    contact: &ContactRecord,
) -> Result<Option<BTreeSet<[u8; 32]>>, DsmError> {
    let genesis = <[u8; 32]>::try_from(contact.genesis_hash.as_slice())
        .map_err(|e| storage_err("the contact's genesis", e))?;
    let device_id = <[u8; 32]>::try_from(contact.device_id.as_slice())
        .map_err(|e| storage_err("the contact's device id", e))?;
    let key = directory_cell_key(&genesis, &device_id);
    let seats = crate::sdk::route_seats::NodeSeats::new(set)?;
    // A member's values are kept only when they decode as a list naming this
    // device: its directory entries, in the same cell, cost their decoding.
    let names_device = |bytes: &[u8]| {
        matches!(
            DeviceTokenList::decode(bytes),
            Ok(list) if list.genesis == genesis && list.device_id == device_id
        )
    };
    let members = seats.members();
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
    let values = reads.iter().flatten().flatten().map(Vec::as_slice);
    let Some(added) = tokens_added(&genesis, &device_id, &contact.public_key, values) else {
        return Ok(None);
    };
    let newly_kept = kept::keep_added(&device_id, &added)
        .map_err(|e| storage_err("keeping a contact's tokens", e))?;
    if newly_kept > 0 {
        // The page's contacts carry what each can be sent: it reads them again.
        crate::host::post_event(CONTACT_TOKENS_TOPIC, &[]);
    }
    Ok(Some(added))
}

/// Read every contact's token lists, each contact at once: what a wallet
/// does when it opens. Answers how many contacts stated a list, and why any
/// could not be read.
pub(crate) async fn refresh_all_contacts(set: &StorageSet) -> (u32, Vec<String>) {
    let contacts = match crate::storage::client_db::get_all_contacts() {
        Ok(contacts) => contacts,
        Err(e) => return (0, vec![format!("contact tokens: the contacts: {e}")]),
    };
    let reads =
        futures::future::join_all(contacts.iter().map(|contact| refresh_contact(set, contact)))
            .await;
    let mut stated = 0u32;
    let mut failures = Vec::new();
    for (contact, read) in contacts.iter().zip(reads) {
        match read {
            Ok(Some(_added)) => stated += 1,
            Ok(None) => {}
            Err(e) => failures.push(format!("{}: {e}", contact.alias)),
        }
    }
    (stated, failures)
}

/// Whether the contact `device_id` can be sent `policy_commit`, from what
/// this device has kept of its lists: any of the protocol's own assets, or a
/// token one of its lists states.
pub(crate) fn contact_takes(
    device_id: &[u8; 32],
    policy_commit: &[u8; 32],
) -> Result<bool, DsmError> {
    Ok(protocol_asset(policy_commit)
        || kept::added_by(device_id)
            .map_err(|e| storage_err("a contact's tokens", e))?
            .contains(policy_commit))
}

/// The protocol's own assets, by the ids `balance.list` names them with.
const PROTOCOL_ASSET_IDS: [&str; 2] = ["ERA", "dBTC"];

/// The tokens this wallet can send the contact `device_id`, by the ids
/// `balance.list` names them with: the protocol's own assets, and every
/// token of this wallet's registry kept as one the contact has added.
pub(crate) fn sendable_token_ids(device_id: &[u8; 32]) -> Result<Vec<String>, DsmError> {
    let added = kept::added_by(device_id).map_err(|e| storage_err("a contact's tokens", e))?;
    let mut ids: Vec<String> = PROTOCOL_ASSET_IDS.iter().map(|id| id.to_string()).collect();
    ids.extend(
        crate::storage::client_db::token_registry::all_tokens()
            .map_err(|e| storage_err("the token registry", e))?
            .into_iter()
            .filter(|row| added.contains(&row.policy_commit))
            .map(|row| crate::handlers::wallet_routes::canonicalize_token_id(&row.ticker)),
    );
    Ok(ids)
}

/// The wallet opened: read every contact's token lists beside whatever else
/// it is doing. A read that fails is reported and tried again at the next
/// open; a send of a token not kept for its contact reads that contact again
/// itself.
pub(crate) fn wallet_opened() {
    crate::runtime::get_runtime().spawn(async {
        let set = match crate::sdk::economic_admission_flow::committed_network_id()
            .and_then(|network| crate::sdk::storage_set::canonical_set(&network))
        {
            Ok(set) => set,
            Err(e) => {
                log::warn!("[contact tokens] not read at open: no pinned set: {e}");
                return;
            }
        };
        let (stated, failures) = refresh_all_contacts(&set).await;
        log::info!(
            "[contact tokens] read at open: {stated} contact(s) state a list; {} not read",
            failures.len()
        );
        for failure in failures {
            log::warn!("[contact tokens] not read at open: {failure}");
        }
    });
}
