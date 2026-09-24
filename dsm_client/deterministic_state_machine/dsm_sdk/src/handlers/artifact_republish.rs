// SPDX-License-Identifier: MIT OR Apache-2.0

//! The sweep for frozen publication artifacts.
//!
//! Every artifact a canonical advance froze (`frozen_publication_artifact`)
//! is owed to the storage set it was frozen FOR until that set holds it as
//! `Stored` (storage spec §5 rule 6). This sweep — run at cold boot, on every
//! `storage.sync` pass, and by an admission before it registers — puts the
//! exact frozen bytes to every member of that set and reads them back. It
//! resolves the row's frozen `storage_set_id` through the local catalog and,
//! if that fails, leaves the row pending: it never substitutes another set.
//! It never signs, never rebuilds from a later head, and knows nothing about
//! what an artifact means (`purpose` is opaque).

use crate::sdk::storage_set::{StorageSet, StorageSetCatalog};
use crate::storage::client_db::frozen_publication_artifact as fpa;

/// Bounded work per pass so a large backlog cannot starve the rest of a sync.
pub(crate) const ARTIFACT_REPUBLISH_ROWS_PER_POLL: u32 = 8;

/// Put up to [`ARTIFACT_REPUBLISH_ROWS_PER_POLL`] unpublished artifacts and
/// read them back. Returns how many were established `Stored` in this pass.
/// A row that is not yet `Stored` records why on the row and never aborts the
/// pass.
pub(crate) async fn republish_unpublished_artifacts() -> Result<u32, String> {
    let rows = fpa::list_unpublished_artifacts(ARTIFACT_REPUBLISH_ROWS_PER_POLL)
        .map_err(|e| format!("list unpublished artifacts: {e}"))?;
    let stored = republish_rows(rows).await?;
    continue_route_writes().await;
    Ok(stored)
}

/// Continue this device's route-chain writes at the seats that did not
/// answer (storage spec §9 rule 8). Never a condition of anything above.
async fn continue_route_writes() {
    let catalog = match StorageSetCatalog::from_env_config() {
        Ok(catalog) => catalog,
        Err(e) => {
            log::warn!("[route continue] no storage-set catalog: {e}");
            return;
        }
    };
    match crate::sdk::route_seats::continue_recorded_writes(&catalog).await {
        Ok(0) => {}
        Ok(n) => log::info!("[route continue] {n} write(s) now linked at every seat"),
        Err(e) => log::warn!("[route continue] deferred: {e}"),
    }
}

/// Put `payload` at every member of `set` and read it back: `Ok(true)` once
/// `Stored` holds for exactly these bytes.
async fn put_and_confirm(
    set: &StorageSet,
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    addr: &[u8; 32],
    payload: &[u8],
) -> Result<bool, String> {
    let (put_addr, took) = crate::sdk::storage_io::put_immutable(set, namespace, payload)
        .await
        .map_err(|e| e.to_string())?;
    if put_addr != *addr {
        return Err("the payload is not the object at its address".into());
    }
    log::debug!(
        "[artifact republish] {took}/{} members took the object",
        set.len()
    );
    let stored = crate::sdk::storage_io::read_stored_bytes(set, addr)
        .await
        .map_err(|e| e.to_string())?;
    Ok(stored.as_deref() == Some(payload))
}

/// The pass proper, over an already-selected batch.
async fn republish_rows(rows: Vec<fpa::FrozenArtifact>) -> Result<u32, String> {
    if rows.is_empty() {
        return Ok(0);
    }
    let catalog = StorageSetCatalog::from_env_config()
        .map_err(|e| format!("storage-set catalog unavailable: {e}"))?;
    let mut stored = 0u32;
    for row in rows {
        // THE SET IS THE ROW'S, NOT OURS. An id the catalog cannot re-derive
        // means this device does not know how to reach that set; the bytes
        // stay owed, and are sent nowhere else.
        let Some(set) = catalog.resolve(&row.storage_set_id) else {
            fpa::upsert_artifact_publication_state(
                &row.object_key,
                fpa::ArtifactState::PublicationPending,
                "the frozen storage set is not resolvable through the local catalog",
            )
            .map_err(|e| e.to_string())?;
            continue;
        };
        let Some((namespace, addr)) = fpa::parse_immutable_object_key(&row.object_key) else {
            return Err(format!(
                "frozen artifact {} has a key that is not an object address",
                row.object_key
            ));
        };
        match put_and_confirm(set, namespace, &addr, &row.payload).await {
            Ok(true) => {
                fpa::upsert_artifact_publication_state(
                    &row.object_key,
                    fpa::ArtifactState::Stored,
                    "",
                )
                .map_err(|e| e.to_string())?;
                stored += 1;
                log::info!(
                    "[artifact republish] {} ({}) Stored",
                    row.object_key,
                    row.purpose
                );
            }
            Ok(false) => {
                fpa::upsert_artifact_publication_state(
                    &row.object_key,
                    fpa::ArtifactState::PublicationPending,
                    "Stored not established yet: fewer than three members return the bytes",
                )
                .map_err(|e| e.to_string())?;
            }
            Err(e) => {
                fpa::upsert_artifact_publication_state(
                    &row.object_key,
                    fpa::ArtifactState::PublicationPending,
                    &e,
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(stored)
}

/// Cold-boot / warm-swap entry: run one pass in the background. Errors are
/// logged; the `storage.sync` pass retries.
pub(crate) fn spawn_frozen_artifact_republish(origin: &'static str) {
    crate::runtime::get_runtime().spawn(async move {
        match republish_unpublished_artifacts().await {
            Ok(0) => {}
            Ok(n) => log::info!("[SDK] frozen artifact republish ({origin}): {n} Stored"),
            Err(e) => log::warn!("[SDK] frozen artifact republish ({origin}): {e}"),
        }
    });
}

/// Put an already-VERIFIED foreign evidence closure to `set` until each
/// object is `Stored` there: for each exact `(namespace, inner addr, exact
/// bytes)` the recording fetch boundary captured, put the bytes to every
/// member and read them back. Objects already recorded `Stored` are skipped;
/// each object established `Stored` is recorded. The foreign bytes are not
/// frozen locally — the frozen backlog is this device's own admission
/// evidence.
///
/// `Err` names the first object not yet `Stored`: the caller treats it as
/// incomplete (retried on the next poll), never as an attack.
pub(crate) async fn ensure_closure_stored(
    set: &StorageSet,
    closure: &[(
        dsm::crypto::domain::TaggedHashDomain<'static>,
        [u8; 32],
        Vec<u8>,
    )],
) -> Result<(), String> {
    for (namespace, inner, bytes) in closure {
        let ns = core::str::from_utf8(namespace.source_bytes())
            .map_err(|e| format!("immutable namespace: {e}"))?;
        if crate::storage::client_db::economic_lineage::is_addr_stored(ns, inner)
            .map_err(|e| format!("Stored memo read: {e}"))?
        {
            continue;
        }
        let addr = dsm::storage_object::immutable_addr_from_inner(*namespace, inner);
        if !put_and_confirm(set, *namespace, &addr, bytes).await? {
            return Err(format!(
                "evidence closure object {ns}::{} is not Stored yet — retry later",
                crate::util::text_id::encode_base32_crockford(inner)
            ));
        }
        crate::storage::client_db::economic_lineage::record_addr_stored(ns, inner)
            .map_err(|e| format!("Stored memo write: {e}"))?;
    }
    Ok(())
}
