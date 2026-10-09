// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity-publication lifecycle.
//!
//! Enforces the invariant:
//!
//! > **local genesis durable != identity ready**
//! > **own directory entry read back from the set = identity ready**
//!
//! `LocalGenesisCommitted -> PublicationPending -> Published`
//!
//! Genesis produces a durable local state machine. That alone leaves the device
//! unreachable: a peer reaches a device through its directory entry
//! (`sdk::device_directory`) — its AK, its birth attestation and its Kyber key,
//! signed with the AK — so an unpublished identity cannot receive online
//! sends. Publication writes this device's own entry to its directory cell on
//! every member of the network's pinned set and reads it back; the identity is
//! published once [`STORAGE_FINALITY_COUNT`] members hold the exact entry that
//! a reader keeps.
//!
//! Failure never destroys local genesis. The device parks in
//! `PublicationPending` and [`retry_pending_publications`] resumes it on the
//! next startup.

use dsm::core::identity::directory::DirectoryEntry;
use dsm::sofi::wire::STORAGE_FINALITY_COUNT;
use dsm::types::error::DsmError;

use crate::sdk::device_directory::{build_own_entry, publish_entry, read_entry};
use crate::sdk::identity_presentation::OwnerIdentityInputs;
use crate::storage::client_db::publication::{self, upsert_publication_state, PublicationState};

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

fn d32(text: &str, what: &str) -> Result<[u8; 32], DsmError> {
    crate::util::text_id::decode_base32_crockford(text)
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or_else(|| DsmError::invalid_parameter(format!("{what} is not a 32-byte id")))
}

/// What one publication established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryPublication {
    /// Members whose directory cell holds this device's exact entry, as a
    /// reader keeps it.
    pub holders: u32,
    /// Members the set has.
    pub members: u32,
    /// Holders needed to call the identity published.
    pub required: u32,
}

impl DirectoryPublication {
    pub fn is_published(&self) -> bool {
        self.holders >= self.required
    }
}

/// This device's own directory entry: the one it signed before, while it still
/// names this identity and this device's current Kyber key; otherwise a new
/// one at the next counter, re-derived from the wallet seed and kept.
fn own_entry(
    network_id: &[u8],
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<DirectoryEntry, DsmError> {
    let kyber_public_key = crate::sdk::kyber_identity::local_kyber_public_key()?;
    let previous = match crate::storage::client_db::own_directory_entry::load()
        .map_err(|e| storage_err("own directory entry", e))?
    {
        Some(bytes) => Some(
            DirectoryEntry::decode(&bytes)
                .map_err(|e| storage_err("own directory entry", format!("{e:?}")))?,
        ),
        None => None,
    };
    let counter = match &previous {
        Some(entry)
            if entry.body.genesis == *genesis
                && entry.body.device_id == *device_id
                && entry.body.kyber_public_key == kyber_public_key =>
        {
            return Ok(entry.clone())
        }
        Some(entry) => entry.body.counter.checked_add(1).ok_or_else(|| {
            DsmError::invalid_operation("own directory entry: the counter is exhausted")
        })?,
        None => 1,
    };
    let wallet_seed = crate::fetch_wallet_seed()
        .map_err(|e| DsmError::invalid_operation(format!("wallet locked: {e}")))?;
    let entry = build_own_entry(
        &wallet_seed,
        OwnerIdentityInputs::beta(network_id),
        genesis,
        kyber_public_key,
        counter,
    )?;
    if entry.body.device_id != *device_id {
        return Err(DsmError::invalid_operation(
            "own directory entry: the re-derived device id is not this device's",
        ));
    }
    crate::storage::client_db::own_directory_entry::store(&entry.encode())
        .map_err(|e| storage_err("keep own directory entry", e))?;
    Ok(entry)
}

/// Publish this device's directory entry now, read it back, and record the
/// resulting lifecycle state.
pub async fn publish_identity_now(
    device_id_b32: &str,
    genesis_hash_b32: &str,
) -> Result<DirectoryPublication, DsmError> {
    let required =
        u32::try_from(STORAGE_FINALITY_COUNT).map_err(|e| storage_err("finality count", e))?;
    let outcome = async {
        let device_id = d32(device_id_b32, "device id")?;
        let genesis = d32(genesis_hash_b32, "genesis")?;
        let network = crate::sdk::economic_admission_flow::committed_network_id()?;
        let set = crate::sdk::storage_set::canonical_set(&network)?;
        let entry = own_entry(&network, &genesis, &device_id)?;
        publish_entry(&set, &entry).await?;
        let holders = match read_entry(&set, &genesis, &device_id).await? {
            Some(read) if read.entry == entry => read.holders.len(),
            Some(..) | None => 0,
        };
        Ok::<_, DsmError>(DirectoryPublication {
            holders: u32::try_from(holders).map_err(|e| storage_err("holders", e))?,
            members: u32::try_from(set.len()).map_err(|e| storage_err("members", e))?,
            required,
        })
    }
    .await;
    match &outcome {
        Ok(report) if report.is_published() => match upsert_publication_state(
            device_id_b32,
            genesis_hash_b32,
            PublicationState::Published,
            required,
            "",
        ) {
            // The write is what makes the identity ready, so the session
            // refresh goes out beside it.
            Ok(()) => push_session_refresh(),
            Err(e) => {
                log::warn!("identity_publication: failed to persist Published state: {e}")
            }
        },
        Ok(report) => record_pending(
            device_id_b32,
            genesis_hash_b32,
            required,
            &format!(
                "{}/{} members hold the entry; {} needed",
                report.holders, report.members, report.required
            ),
        ),
        Err(e) => record_pending(device_id_b32, genesis_hash_b32, required, &e.to_string()),
    }
    outcome
}

fn record_pending(device_id_b32: &str, genesis_hash_b32: &str, required: u32, err: &str) {
    if let Err(e) = upsert_publication_state(
        device_id_b32,
        genesis_hash_b32,
        PublicationState::PublicationPending,
        required,
        err,
    ) {
        log::warn!("identity_publication: failed to persist PublicationPending state: {e}");
    }
}

/// Ask the host to republish the session snapshot.
///
/// `dsm-wallet-refresh` is the topic the Android host treats as a session hint:
/// it re-runs `publishSessionState`, which recomputes the phase from the
/// persisted publication row this module just wrote.
#[cfg(all(target_os = "android", feature = "jni"))]
fn push_session_refresh() {
    if let Err(e) = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]) {
        log::warn!("identity_publication: session refresh dispatch failed: {e}");
    }
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn push_session_refresh() {}

/// Whether this device's identity is ready to use: its directory entry was
/// read back from enough members. A durable local genesis record does NOT
/// satisfy this.
pub fn is_identity_ready(device_id_b32: &str) -> Result<bool, DsmError> {
    publication::is_published(device_id_b32).map_err(|e| storage_err("publication state", e))
}

/// Resume publication for every device that has not been read back yet.
///
/// Called on startup. Idempotent: devices already published are skipped, and a
/// republished entry is the same bytes the members already hold.
pub async fn retry_pending_publications() {
    let pending = match publication::list_unpublished() {
        Ok(p) => p,
        Err(e) => {
            log::warn!("identity_publication: cannot list unpublished identities: {e}");
            return;
        }
    };
    for rec in pending {
        let short = &rec.device_id[..8.min(rec.device_id.len())];
        match publish_identity_now(&rec.device_id, &rec.genesis_hash).await {
            Ok(report) if report.is_published() => log::info!(
                "identity_publication: device={short} now PUBLISHED ({}/{} members hold the entry)",
                report.holders,
                report.members
            ),
            Ok(report) => log::warn!(
                "identity_publication: device={short} still pending ({}/{} members hold the \
                 entry, {} needed)",
                report.holders,
                report.members,
                report.required
            ),
            Err(e) => log::warn!("identity_publication: retry failed for device={short}: {e}"),
        }
    }
}
