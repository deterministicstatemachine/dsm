// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity-publication lifecycle.
//!
//! Enforces the invariant:
//!
//! > **local genesis durable != identity ready**
//! > **published and read-back verified by quorum = identity ready**
//!
//! `LocalGenesisCommitted -> PublicationPending -> Published`
//!
//! Genesis produces a durable local state machine. That alone leaves the device
//! unreachable: peers resolve a device by looking it up on the storage fleet, so
//! an unpublished identity cannot receive online sends and every authenticated
//! write 401s. Publication is therefore a precondition of "identity created",
//! not a best-effort side effect of it.
//!
//! Failure never destroys local genesis. The device parks in
//! `PublicationPending` and [`retry_pending_publications`] resumes it on the
//! next startup — the storage screen is not, and must not be, the recovery
//! mechanism.

use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::{PublicationReport, StorageNodeConfig, StorageNodeSDK};
use crate::storage::client_db::publication::{
    self, quorum_for, upsert_publication_state, PublicationState,
};

/// Publish an identity now and record the resulting lifecycle state.
///
/// Returns the report so callers can log/branch; the persisted state is the
/// authority consulted later by [`is_identity_ready`].
pub async fn publish_identity_now(
    device_id_b32: &str,
    pubkey_b32: &str,
    genesis_hash_b32: &str,
) -> Result<PublicationReport, DsmError> {
    let cfg = match StorageNodeConfig::from_env_config().await {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("storage-node config load failed: {e:?}");
            record_pending(device_id_b32, genesis_hash_b32, 0, &msg);
            return Err(DsmError::storage(msg, None::<std::io::Error>));
        }
    };
    let required = quorum_for(cfg.node_urls.len());

    let sdk = match StorageNodeSDK::new(cfg).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("storage-node SDK init failed: {e:?}");
            record_pending(device_id_b32, genesis_hash_b32, required, &msg);
            return Err(DsmError::storage(msg, None::<std::io::Error>));
        }
    };

    let report = match sdk
        .publish_identity(device_id_b32, pubkey_b32, genesis_hash_b32)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            record_pending(
                device_id_b32,
                genesis_hash_b32,
                required,
                &format!("publish: {e}"),
            );
            return Err(e);
        }
    };

    if report.is_published() {
        if let Err(e) = upsert_publication_state(
            device_id_b32,
            genesis_hash_b32,
            PublicationState::Published,
            report.required,
            "",
        ) {
            log::warn!("identity_publication: failed to persist Published state: {e}");
        }
    } else {
        let summary = report
            .failures
            .iter()
            .map(|(node, err)| format!("{node}: {err}"))
            .collect::<Vec<_>>()
            .join("; ");
        record_pending(device_id_b32, genesis_hash_b32, report.required, &summary);
    }

    Ok(report)
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

/// Whether this device's identity is ready to use — i.e. a quorum of nodes has
/// been read-back verified. A durable local genesis record does NOT satisfy
/// this.
pub fn is_identity_ready(device_id_b32: &str) -> bool {
    publication::is_published(device_id_b32).unwrap_or(false)
}

/// Resume publication for every device that has not reached quorum.
///
/// Called on startup. Idempotent: devices already published are skipped, and a
/// device that is already registered on a node reconciles through the node's
/// 409 path rather than failing.
pub async fn retry_pending_publications() {
    // Identities created before the publication table existed have no row, so
    // they would be invisible here while still reporting unpublished — parked
    // in `publication_pending` with nothing driving them out. Backfill first so
    // the retry actually covers them.
    match publication::backfill_publication_rows_for_local_identities() {
        Ok(0) => {}
        Ok(n) => log::info!(
            "identity_publication: backfilled {n} pre-existing identity/identities for publication"
        ),
        Err(e) => log::warn!("identity_publication: backfill failed: {e}"),
    }

    let pending = match publication::list_unpublished() {
        Ok(p) => p,
        Err(e) => {
            log::warn!("identity_publication: cannot list unpublished identities: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }

    log::info!(
        "identity_publication: {} identity/identities awaiting publication — retrying",
        pending.len()
    );

    for rec in pending {
        // The AK is read from the local genesis record rather than carried in
        // the publication row, so the retry republishes exactly the identity
        // that was committed locally.
        let pubkey_b32 = match local_pubkey_b32(&rec.device_id) {
            Some(pk) => pk,
            None => {
                log::warn!(
                    "identity_publication: no local public key for device={} — cannot retry",
                    &rec.device_id[..8.min(rec.device_id.len())]
                );
                continue;
            }
        };

        match publish_identity_now(&rec.device_id, &pubkey_b32, &rec.genesis_hash).await {
            Ok(report) if report.is_published() => {
                log::info!(
                    "identity_publication: device={} now PUBLISHED ({}/{} verified)",
                    &rec.device_id[..8.min(rec.device_id.len())],
                    report.verified,
                    report.total_nodes
                );
            }
            Ok(report) => {
                log::warn!(
                    "identity_publication: device={} still pending ({}/{} verified, quorum {})",
                    &rec.device_id[..8.min(rec.device_id.len())],
                    report.verified,
                    report.total_nodes,
                    report.required
                );
            }
            Err(e) => {
                log::warn!(
                    "identity_publication: retry failed for device={}: {e}",
                    &rec.device_id[..8.min(rec.device_id.len())]
                );
            }
        }
    }
}

/// Resolve the device's own AK from the canonical local head, Base32-encoded.
fn local_pubkey_b32(device_id_b32: &str) -> Option<String> {
    let raw = crate::util::text_id::decode_base32_crockford(device_id_b32)?;
    let device_id: [u8; 32] = raw.try_into().ok()?;
    let head = crate::storage::client_db::bcr::load_bcr_device_head(&device_id).ok()??;
    Some(crate::util::text_id::encode_base32_crockford(
        head.public_key(),
    ))
}
