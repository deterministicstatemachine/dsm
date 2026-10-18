// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Recovery Handler Implementation
//!
//! The recovery receipts the router's `recovery.*` routes sign and apply:
//! tombstone, succession and resume, each behind the gates those routes hold.

use crate::storage::client_db::recovery::RecoveryState;
use dsm::recovery::tombstone::{create_succession, create_tombstone};
use dsm::types::proto as gp;
use prost::Message;

pub struct RecoveryImpl;

/// The counter a recovery's tombstone carries. The capsule records none, so
/// it is 0: what the pipeline signs, and what activation re-creates byte for
/// byte (`create_tombstone` is deterministic).
const TOMBSTONE_COUNTER: u64 = 0;

/// The old device and the state its capsule sealed, as decrypting the
/// capsule staged them.
struct StagedCapsule {
    old_device_id: Vec<u8>,
    smt_root: Vec<u8>,
    rollup_hash: Vec<u8>,
}

fn staged_capsule() -> Result<StagedCapsule, String> {
    let read = |key: &str, what: &str| {
        crate::storage::client_db::recovery::get_recovery_pref(key)
            .map_err(|e| format!("Failed to read capsule {what}: {e}"))?
            .ok_or_else(|| format!("No capsule {what} found — stage a capsule first"))
    };
    let old_device_id = read("capsule_source_device_id", "source device_id")?;
    if old_device_id.len() != 32 {
        return Err(format!(
            "capsule_source_device_id must be 32 bytes, got {}",
            old_device_id.len()
        ));
    }
    Ok(StagedCapsule {
        old_device_id,
        smt_root: read("capsule_smt_root", "SMT root")?,
        rollup_hash: read("capsule_rollup_hash", "rollup hash")?,
    })
}

/// The recovery authority's secret key (KS1 `K_A`), cached when the
/// mnemonic was entered: the only key a recovery receipt is signed with. No
/// request carries a key (SA-52).
fn authority_secret_key() -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let (_pk, sk) = crate::sdk::recovery_sdk::RecoverySDK::get_cached_authority_keypair()
        .ok_or_else(|| "No recovery authority key cached — enter mnemonic first".to_string())?;
    Ok(sk)
}

/// The tombstone of the staged capsule's device, signed under `K_A`.
fn sign_staged_tombstone(
    staged: &StagedCapsule,
) -> Result<dsm::recovery::tombstone::TombstoneReceipt, String> {
    let sk = authority_secret_key()?;
    create_tombstone(
        &staged.smt_root,
        TOMBSTONE_COUNTER,
        &staged.rollup_hash,
        &crate::util::text_id::encode_base32_crockford(&staged.old_device_id),
        &sk,
    )
    .map_err(|e| format!("Tombstone creation failed: {e}"))
}

impl RecoveryImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RecoveryImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryImpl {
    pub(crate) fn handle_recovery_tombstone(
        &self,
        operation: gp::RecoveryTombstoneRequest,
    ) -> Result<gp::OpResult, String> {
        // The request names the tombstone it asks for; only the staged
        // capsule's is ever signed, so `K_A` signs nothing a caller chose.
        let staged = staged_capsule()?;
        let names_the_staged_tombstone = operation.global_root.as_ref().map(|h| &h.v)
            == Some(&staged.smt_root)
            && operation.rollup_hash.as_ref().map(|h| &h.v) == Some(&staged.rollup_hash)
            && operation.device_entropy == staged.old_device_id
            && operation.counter == TOMBSTONE_COUNTER;
        if !names_the_staged_tombstone {
            return Err(
                "the request names another tombstone than the staged capsule's; only that one \
                 is signed"
                    .to_string(),
            );
        }
        let tombstone = sign_staged_tombstone(&staged)?;

        // Build the response — store the full serialised receipt so counterparties
        // can reconstruct it for validation (not just the raw signature bytes).
        let tombstone_receipt_bytes = tombstone.to_bytes();

        // Build the response
        let response = gp::RecoveryTombstoneResponse {
            success: true,
            tombstone_hash: Some(gp::Hash32 {
                v: tombstone.tombstone_hash.clone(),
            }),
            tombstone_receipt: tombstone_receipt_bytes,
        };

        let mut body = Vec::new();
        response
            .encode(&mut body)
            .map_err(|e| format!("Failed to encode tombstone response: {}", e))?;

        Ok(gp::OpResult {
            op_id: None,
            accepted: true,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    pub(crate) fn handle_recovery_succession(
        &self,
        operation: gp::RecoverySuccessionRequest,
    ) -> Result<gp::OpResult, String> {
        // The succession of this recovery's own tombstone to this device:
        // the request must name both, and is signed under `K_A` only then.
        let tombstone_hash = crate::storage::client_db::recovery::get_tombstone_hash()
            .map_err(|e| format!("read the stored tombstone hash: {e}"))?
            .ok_or_else(|| "no tombstone was made for this recovery".to_string())?;
        let new_device_id = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| "No device identity — run genesis before recovery".to_string())?;
        if operation.tombstone_hash.as_ref().map(|h| &h.v) != Some(&tombstone_hash)
            || operation.device_entropy != new_device_id
        {
            return Err(
                "the request names another succession than this recovery's tombstone to this \
                 device; only that one is signed"
                    .to_string(),
            );
        }
        let sk = authority_secret_key()?;
        let device_id_str = crate::util::text_id::encode_base32_crockford(&new_device_id);
        let succession = create_succession(&tombstone_hash, &new_device_id, &device_id_str, &sk)
            .map_err(|e| format!("Core succession creation failed: {}", e))?;

        // Store succession receipt for later reference during resume
        if let Err(e) =
            crate::storage::client_db::recovery::store_succession_receipt(&succession.signature)
        {
            log::warn!("[RECOVERY] Failed to store succession receipt: {e}");
        }

        // Restore state from the decrypted capsule data.
        // The capsule's SMT root and counterparty chain tips were persisted
        // when `recovery.decryptCapsule` decrypted it.
        // Now bind the new device identity.
        {
            let public_key = crate::sdk::app_state::AppState::get_public_key()
                .ok_or_else(|| "the recovering device holds no signing key".to_string())?;
            let genesis_hash = succession.new_device_commitment.clone();

            // The capsule's SMT root, recorded when the capsule was decrypted.
            let smt_root =
                crate::storage::client_db::recovery::get_recovery_pref("capsule_smt_root")
                    .map_err(|e| format!("read the capsule SMT root: {e}"))?
                    .ok_or_else(|| "the capsule SMT root was not recorded".to_string())?;

            crate::sdk::app_state::AppState::set_identity_info(
                new_device_id,
                public_key,
                genesis_hash,
                smt_root,
            )
            .map_err(|e| format!("persist the recovered identity: {e}"))?;
            crate::sdk::app_state::AppState::set_has_identity(true)
                .map_err(|e| format!("persist the identity mark: {e}"))?;

            log::info!("[RECOVERY] State restored with new device binding via succession");
        }

        // Build the response
        let response = gp::RecoverySuccessionResponse {
            success: true,
            succession_hash: Some(gp::Hash32 {
                v: succession.succession_hash.clone(),
            }),
            succession_receipt: succession.signature.clone(),
            new_genesis_hash: Some(gp::Hash32 {
                v: succession.new_device_commitment.clone(),
            }),
        };

        let mut body = Vec::new();
        response
            .encode(&mut body)
            .map_err(|e| format!("Failed to encode succession response: {}", e))?;

        Ok(gp::OpResult {
            op_id: None,
            accepted: true,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    pub(crate) fn handle_recovery_resume(
        &self,
        operation: gp::RecoveryResumeRequest,
    ) -> Result<gp::OpResult, String> {
        // Recovery resume: restore bilateral relationships from recovered chain tips.
        // This is called AFTER all counterparties have acknowledged the tombstone
        // (sync gate passed in recovery_routes.rs).

        let counterparty_device_id = &operation.counterparty_device_id;
        if counterparty_device_id.len() != 32 {
            return Err(format!(
                "counterparty_device_id must be 32 bytes, got {}",
                counterparty_device_id.len()
            ));
        }

        let last_head_hash = operation
            .last_head_hash
            .as_ref()
            .map(|h| h.v.clone())
            .ok_or_else(|| "Missing last_head_hash in resume request".to_string())?;

        // Update the contact's chain tip to the recovered value.
        // This ensures the next bilateral interaction starts from the recovered state.
        {
            let device_id_b32 =
                crate::util::text_id::encode_base32_crockford(counterparty_device_id);
            let head_hash_32: [u8; 32] = if last_head_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&last_head_hash);
                arr
            } else {
                return Err(format!(
                    "last_head_hash must be 32 bytes, got {}",
                    last_head_hash.len()
                ));
            };

            // Anti-rollback floor (P3/T3.2): the resume tip MUST match the owner's
            // own sealed floor staged from the capsule. A request cannot set a
            // relationship tip that diverges from the capsule floor — this closes
            // the resume-time rollback where a counterparty-supplied tip would be
            // applied before the capsule floor is restored. Fail-closed if the
            // floor cannot be read. (Forward extension above the floor is handled
            // by the activation-seal flow with a co-signed chain proof.)
            match crate::storage::client_db::recovery::resume_tip_diverges_from_floor(
                counterparty_device_id,
                &head_hash_32,
            ) {
                Ok(true) => {
                    return Err(format!(
                        "[RECOVERY] resume tip diverges from capsule floor for {}: refusing rollback",
                        &device_id_b32[..device_id_b32.len().min(16)]
                    ));
                }
                Ok(false) => {}
                Err(e) => {
                    return Err(format!(
                        "[RECOVERY] cannot read capsule floor for resume of {}: {e}",
                        &device_id_b32[..device_id_b32.len().min(16)]
                    ));
                }
            }

            // Update contact chain tips to recovered values (both shared + local tip)
            if let Err(e) = crate::storage::client_db::restore_finalized_bilateral_chain_tip(
                counterparty_device_id,
                &head_hash_32,
            ) {
                return Err(format!(
                    "[RECOVERY] Refusing to overwrite existing chain tip for {}: {e}",
                    &device_id_b32[..device_id_b32.len().min(16)]
                ));
            } else {
                log::info!(
                    "[RECOVERY] Restored bilateral chain tip for {}",
                    &device_id_b32[..device_id_b32.len().min(16)]
                );
            }
        }

        // Clear sync status after successful resume (recovery cycle complete for this contact)
        // The full cleanup happens after ALL contacts are resumed.

        let response = gp::RecoveryResumeResponse {
            success: true,
            new_transaction_hash: Some(gp::Hash32 { v: last_head_hash }),
            transaction_receipt: vec![],
        };

        let mut body = Vec::new();
        response
            .encode(&mut body)
            .map_err(|e| format!("Failed to encode resume response: {}", e))?;

        Ok(gp::OpResult {
            op_id: None,
            accepted: true,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }
}

// ============================================================================
// Pipeline functions — called by `recovery.executePipeline` route.
// These use cached authority keys and persisted capsule data instead of
// accepting parameters from the frontend.
// ============================================================================

/// Run tombstone + succession + propagate using cached recovery authority key
/// and persisted capsule data. Returns a summary string for the frontend.
pub async fn execute_recovery_pipeline() -> Result<String, String> {
    // 1. The cached recovery authority key signs both receipts.
    let sk = authority_secret_key()?;

    // 2-3. The old device and the state its capsule sealed.
    let staged = staged_capsule()?;

    // 4. Get this device's identity (must have genesis)
    let new_device_id = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "No device identity — run genesis before recovery".to_string())?;
    if new_device_id.len() != 32 {
        return Err(format!(
            "Device ID must be 32 bytes, got {}",
            new_device_id.len()
        ));
    }

    // 5. Store recovery phase
    crate::storage::client_db::recovery::set_recovery_state(RecoveryState::Tombstoning)
        .map_err(|e| format!("Failed to record the tombstoning phase: {e}"))?;

    // 5a. P5: start this recovery cycle with a clean bearer-asset lock registry so stale
    // reconciliations from a prior cycle cannot leave an asset spendable (fail-closed).
    if let Err(e) = crate::storage::client_db::recovery::clear_asset_locks() {
        return Err(format!(
            "[RECOVERY] Failed to clear stale bearer-asset locks: {e}"
        ));
    }

    // 6. Create tombstone receipt
    let old_device_id_str = crate::util::text_id::encode_base32_crockford(&staged.old_device_id);
    let tombstone = sign_staged_tombstone(&staged)?;

    let tombstone_receipt_bytes = tombstone.to_bytes();
    let tombstone_hash_b32 =
        crate::util::text_id::encode_base32_crockford(&tombstone.tombstone_hash);

    // Persist tombstone receipt for propagation
    if let Err(e) =
        crate::storage::client_db::recovery::store_tombstone_receipt(&tombstone_receipt_bytes)
    {
        return Err(format!("Failed to store tombstone receipt: {e}"));
    }
    if let Err(e) =
        crate::storage::client_db::recovery::store_tombstone_hash(&tombstone.tombstone_hash)
    {
        return Err(format!("Failed to store tombstone hash: {e}"));
    }

    log::info!(
        "[RECOVERY] Tombstone created for device {}",
        &old_device_id_str[..old_device_id_str.len().min(16)]
    );

    // 7. Create succession receipt
    crate::storage::client_db::recovery::set_recovery_state(RecoveryState::Succession)
        .map_err(|e| format!("Failed to record the succession phase: {e}"))?;

    let new_device_id_str = crate::util::text_id::encode_base32_crockford(&new_device_id);
    let succession = create_succession(
        &tombstone.tombstone_hash,
        &new_device_id,
        &new_device_id_str,
        &sk,
    )
    .map_err(|e| format!("Succession creation failed: {e}"))?;

    // The succession receipt, whole: the tombstone notice carries it.
    crate::storage::client_db::recovery::store_succession_receipt(&succession.to_bytes())
        .map_err(|e| format!("Failed to store succession receipt: {e}"))?;

    // Bind the new device identity with capsule state
    {
        let public_key = crate::sdk::app_state::AppState::get_public_key()
            .ok_or_else(|| "the recovering device holds no signing key".to_string())?;
        let genesis_hash = succession.new_device_commitment.clone();
        let smt_root = staged.smt_root;

        crate::sdk::app_state::AppState::set_identity_info(
            new_device_id.clone(),
            public_key,
            genesis_hash,
            smt_root,
        )
        .map_err(|e| format!("persist the recovered identity: {e}"))?;
        crate::sdk::app_state::AppState::set_has_identity(true)
            .map_err(|e| format!("persist the identity mark: {e}"))?;
    }

    log::info!(
        "[RECOVERY] Succession bound new device {}",
        &new_device_id_str[..new_device_id_str.len().min(16)]
    );

    // 7b. P5 bearer-asset LOCKED_RECOVERY (spec §0.4): the capsule is a continuity hint,
    // NOT a balance oracle. Identity succession does NOT make recovered bearer assets
    // spendable — every restored bearer asset enters LockedRecovery and stays there until
    // its OWN verified frontier reconciles (generic tokens via reconcile_token_asset; dBTC
    // only via the dedicated frontier-replay pass). Lock under BOTH device ids so the
    // token-keyed registry covers whichever device the restored projections landed under.
    // Fail-closed: if we cannot lock, abort rather than leave bearer assets spendable.
    let mut locked_assets = 0usize;
    for dev_str in [&old_device_id_str, &new_device_id_str] {
        match crate::storage::client_db::recovery::lock_all_restored_bearer_assets(dev_str) {
            Ok(n) => locked_assets += n,
            Err(e) => {
                return Err(format!(
                    "[RECOVERY] Failed to lock restored bearer assets (refusing to proceed with \
                     spendable recovered assets): {e}"
                ));
            }
        }
    }
    log::info!("[RECOVERY] {locked_assets} restored bearer-asset projection(s) set LockedRecovery");

    // 8. Initialize sync gate from capsule counterparty IDs
    let counterparty_ids = crate::storage::client_db::recovery::get_capsule_counterparty_ids()
        .map_err(|e| format!("Failed to read counterparty IDs: {e}"))?;
    crate::storage::client_db::recovery::init_recovery_sync_status(&counterparty_ids)
        .map_err(|e| format!("Failed to init sync gate: {e}"))?;

    // 9. Propagate the tombstone to every counterparty's notice cell
    crate::storage::client_db::recovery::set_recovery_state(RecoveryState::Propagating)
        .map_err(|e| format!("Failed to record the propagating phase: {e}"))?;
    let propagated = propagate_tombstone().await?;

    // 10. Set phase to polling
    crate::storage::client_db::recovery::set_recovery_state(RecoveryState::Polling)
        .map_err(|e| format!("Failed to record the polling phase: {e}"))?;

    Ok(format!(
        "phase=polling,tombstone_hash={tombstone_hash_b32},{propagated}"
    ))
}

/// The notice a contact takes the tombstone in: the tombstone with the
/// recovery authority it is signed under and the succession it starts. A
/// tombstone is signed under K_A, which the old device anchored, and a contact
/// verifies it under that anchored authority; the receipt alone gave it only
/// the old device's AK, under which no tombstone verifies (SA-117).
fn tombstone_notice() -> Result<Vec<u8>, String> {
    let tombstone = crate::storage::client_db::recovery::get_tombstone_receipt()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no tombstone receipt stored; call recovery.tombstone first".to_string())?;
    let succession = crate::storage::client_db::recovery::get_succession_receipt()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no succession receipt stored; call recovery.succession first".to_string())?;
    let (authority_pubkey, ..) =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_authority_keypair().ok_or_else(|| {
            "no cached recovery-authority keypair (cache the mnemonic first)".to_string()
        })?;
    Ok(dsm::recovery::RecoverySuccessionProof {
        authority_pubkey,
        tombstone: dsm::recovery::TombstoneReceipt::from_bytes(&tombstone)
            .map_err(|e| format!("the stored tombstone: {e}"))?,
        succession: dsm::recovery::SuccessionReceipt::from_bytes(&succession)
            .map_err(|e| format!("the stored succession: {e}"))?,
    }
    .to_bytes())
}

/// Put the tombstone notice ([`tombstone_notice`]) in each unsynced
/// counterparty's notice cell. Reports `pushed`, `failed` and `total`.
pub(crate) async fn propagate_tombstone() -> Result<String, String> {
    let bytes = tombstone_notice()?;
    let unsynced = crate::storage::client_db::recovery::get_unsynced_counterparties()
        .map_err(|e| e.to_string())?;
    if unsynced.is_empty() {
        return Err("no unsynced counterparties to propagate to".to_string());
    }
    let mut pushed = 0u64;
    let mut failed = Vec::new();
    for contact_device_id in &unsynced {
        let cell = dsm::recovery::RecoveryCell::TombstoneNotice {
            contact_device_id: *contact_device_id,
        };
        match crate::sdk::recovery_store::put(&cell, &bytes).await {
            Ok(..) => pushed += 1,
            Err(e) => failed.push(format!(
                "{}: {e}",
                &crate::util::text_id::encode_base32_crockford(contact_device_id)[..16]
            )),
        }
    }
    if !failed.is_empty() {
        log::warn!("[RECOVERY] tombstone not posted for: {}", failed.join("; "));
    }
    Ok(format!(
        "pushed={pushed},failed={},total={}",
        failed.len(),
        unsynced.len()
    ))
}

/// The gate resume runs behind: every counterparty the capsule named has
/// acknowledged the tombstone (SA-20). A gate that cannot be read, or that
/// was never set up, holds resume back as one still pending does.
pub(crate) fn resume_gate() -> Result<(), String> {
    use crate::storage::client_db::recovery as db;
    let unreadable =
        |e: anyhow::Error| format!("the tombstone acknowledgement gate could not be read: {e}");
    if db::all_counterparties_synced().map_err(unreadable)? {
        return Ok(());
    }
    match db::get_sync_progress().map_err(unreadable)? {
        (_, 0) => Err(
            "no counterparty is tracked: the tombstone acknowledgement gate was never set up"
                .to_string(),
        ),
        (synced, total) => Err(format!(
            "Recovery pending: {synced}/{total} contacts synced. All counterparties must \
             acknowledge the tombstone before resume."
        )),
    }
}

/// Resume all bilateral relationships from recovered chain tips, behind
/// [`resume_gate`]. A contact that cannot be resumed is reported by name and
/// the recovery is not complete: every staged tip and the gate are kept, and
/// a retry resumes again (restoring a tip a contact already holds changes
/// nothing). Only once every contact is resumed is the staged state cleared
/// and the recovery marked complete (SA-21).
pub fn resume_all_contacts() -> Result<String, String> {
    use crate::storage::client_db::recovery as db;
    resume_gate()?;

    db::set_recovery_state(RecoveryState::Resuming)
        .map_err(|e| format!("Failed to record the resuming phase: {e}"))?;

    // Get recovered chain tips and resume each
    let tips = db::get_recovered_chain_tips()
        .map_err(|e| format!("Failed to read recovered chain tips: {e}"))?;

    let mut resumed = 0u64;
    let mut failed = Vec::new();
    for tip in &tips {
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&tip.device_id);
        let short = &device_id_b32[..device_id_b32.len().min(16)];
        match crate::storage::client_db::restore_finalized_bilateral_chain_tip(
            &tip.device_id,
            &tip.head_hash,
        ) {
            Ok(()) => {
                resumed += 1;
                log::info!("[RECOVERY] Resumed bilateral chain tip for {short}");
            }
            Err(e) => failed.push(format!("{short}: {e}")),
        }
    }

    // P5: (re)lock any restored bearer-asset projections materialized during resume
    // (INSERT-IF-ABSENT — never clobbers assets already reconciled this cycle). The capsule
    // is a continuity hint, never a balance oracle; these stay LockedRecovery until each
    // asset's frontier reconciles. Fail-closed: a locking failure aborts before cleanup.
    if let Some(dev) = crate::sdk::app_state::AppState::get_device_id() {
        let dev_str = crate::util::text_id::encode_base32_crockford(&dev);
        match db::lock_all_restored_bearer_assets(&dev_str) {
            Ok(n) => {
                log::info!("[RECOVERY] {n} restored bearer-asset projection(s) locked at resume")
            }
            Err(e) => {
                return Err(format!(
                    "[RECOVERY] Failed to lock restored bearer assets at resume (refusing to \
                     complete with spendable recovered assets): {e}"
                ));
            }
        }
    }

    if !failed.is_empty() {
        return Err(format!(
            "resumed {resumed} of {} contacts; not resumed, their tips kept for a retry: {}",
            tips.len(),
            failed.join("; ")
        ));
    }

    // Every contact resumed. The staged tips go before the gate, so a failure
    // here leaves a gate that still opens the retry.
    db::clear_recovered_chain_tips()
        .map_err(|e| format!("every contact resumed, but the staged tips were not cleared: {e}"))?;
    db::clear_recovery_sync_status().map_err(|e| {
        format!("every contact resumed, but the acknowledgement gate was not cleared: {e}")
    })?;
    db::set_recovery_state(RecoveryState::Complete)
        .map_err(|e| format!("Failed to record the complete phase: {e}"))?;

    Ok(format!("success=true,resumed={}", resumed))
}

/// The prefs a recovery stages: the tombstone, the succession and the
/// capsule it came from.
const STAGED_RECOVERY_PREFS: [&str; 6] = [
    "tombstone_receipt",
    "tombstone_hash",
    "capsule_counterparty_ids",
    "capsule_smt_root",
    "capsule_rollup_hash",
    "succession_receipt",
];

/// The terminator after every contact resumed: the staged recovery state is
/// cleared only for a recovery whose resume completed, and a clear that fails
/// is reported, never passed over (SA-20).
pub(crate) fn complete_resume() -> Result<(), String> {
    use crate::storage::client_db::recovery as db;
    let state = db::recovery_state();
    if state != RecoveryState::Complete {
        return Err(format!(
            "recovery has not resumed every contact (phase {}); nothing is cleared",
            state.as_str()
        ));
    }
    let mut failed = Vec::new();
    if let Err(e) = db::clear_recovery_sync_status() {
        failed.push(format!("the acknowledgement gate: {e}"));
    }
    if let Err(e) = db::clear_recovered_chain_tips() {
        failed.push(format!("the staged tips: {e}"));
    }
    for key in STAGED_RECOVERY_PREFS {
        if let Err(e) = db::set_recovery_pref(key, &[]) {
            failed.push(format!("{key}: {e}"));
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "the recovered state was not all cleared: {}",
            failed.join("; ")
        ));
    }
    log::info!("[RECOVERY] Recovery cycle complete — all state cleaned up");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::recovery::{self as db, RecoveredChainTip};

    /// A fresh client database with the recovery tables.
    fn recovery_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        db::ensure_recovery_tables().expect("the recovery tables");
    }

    fn short(id: &[u8; 32]) -> String {
        crate::util::text_id::encode_base32_crockford(id)[..16].to_string()
    }

    /// Resume waits for every counterparty the capsule named to acknowledge
    /// the tombstone (SA-20). A gate never set up holds it back, as does one
    /// still pending or one that cannot be read.
    #[test]
    #[serial_test::serial]
    fn the_resume_gate_holds_until_every_tracked_counterparty_acknowledged() {
        recovery_db();
        let never = resume_gate().expect_err("an empty gate was never set up");
        assert!(never.contains("never set up"), "{never}");

        let (a, b) = ([0xA1u8; 32], [0xB2u8; 32]);
        db::init_recovery_sync_status(&[a, b]).expect("the gate");
        let pending = resume_gate().expect_err("none acknowledged");
        assert!(pending.contains("0/2"), "{pending}");
        db::mark_counterparty_synced(&a).expect("a acknowledged");
        let pending = resume_gate().expect_err("one still pending");
        assert!(pending.contains("1/2"), "{pending}");
        db::mark_counterparty_synced(&b).expect("b acknowledged");
        resume_gate().expect("every tracked counterparty acknowledged");

        crate::storage::client_db::get_connection()
            .expect("the database")
            .lock()
            .expect("the connection")
            .execute_batch("DROP TABLE recovery_sync_status")
            .expect("lose the gate's table");
        let unreadable = resume_gate().expect_err("an unreadable gate holds resume back");
        assert!(unreadable.contains("could not be read"), "{unreadable}");
    }

    /// The terminator clears a recovery's staged state only once its resume
    /// completed (SA-20); before that it clears nothing.
    #[test]
    #[serial_test::serial]
    fn completing_a_recovery_clears_only_one_whose_resume_completed() {
        recovery_db();
        let tip = RecoveredChainTip {
            device_id: [0xC3; 32],
            height: 4,
            head_hash: [0x70; 32],
        };
        db::store_recovered_chain_tips(std::slice::from_ref(&tip)).expect("staged");
        db::store_tombstone_hash(&[0x7B; 32]).expect("staged");
        db::set_recovery_state(RecoveryState::Polling).expect("the phase");

        let refused = complete_resume().expect_err("not resumed yet");
        assert!(refused.contains("polling"), "{refused}");
        assert_eq!(db::get_recovered_chain_tips().expect("tips"), vec![tip]);
        assert_eq!(
            db::get_tombstone_hash().expect("the hash"),
            Some(vec![0x7B; 32])
        );

        db::set_recovery_state(RecoveryState::Complete).expect("the phase");
        complete_resume().expect("cleared");
        assert!(db::get_recovered_chain_tips().expect("tips").is_empty());
        assert_ne!(
            db::get_tombstone_hash().expect("the hash"),
            Some(vec![0x7B; 32]),
            "the tombstone hash is cleared"
        );
    }

    /// A contact whose tip cannot be restored is reported by name, and the
    /// recovery is not complete: every staged tip and the gate are kept for
    /// the retry, and the terminator still refuses (SA-21).
    #[test]
    #[serial_test::serial]
    fn resuming_all_reports_a_contact_it_could_not_resume_and_keeps_its_tip() {
        recovery_db();
        let (held, lost) = ([0xD4u8; 32], [0xE5u8; 32]);
        // The contact add path stores this one at the tip below; `lost` is no contact.
        crate::storage::client_db::store_contact_record_for_tests(held, "held");
        let tips = vec![
            RecoveredChainTip {
                device_id: held,
                height: 3,
                head_hash: [0x70; 32],
            },
            RecoveredChainTip {
                device_id: lost,
                height: 5,
                head_hash: [0x71; 32],
            },
        ];
        db::store_recovered_chain_tips(&tips).expect("staged");
        db::init_recovery_sync_status(&[held, lost]).expect("the gate");
        db::mark_counterparty_synced(&held).expect("acknowledged");
        db::mark_counterparty_synced(&lost).expect("acknowledged");

        let refused = resume_all_contacts().expect_err("a contact was not resumed");
        assert!(
            refused.contains("resumed 1 of 2") && refused.contains(&short(&lost)),
            "{refused}"
        );
        assert_eq!(
            db::get_recovered_chain_tips().expect("tips"),
            tips,
            "every tip is kept for the retry"
        );
        assert_eq!(db::get_sync_progress().expect("the gate"), (2, 2));
        assert_ne!(db::recovery_state(), RecoveryState::Complete);
        let unfinished = complete_resume().expect_err("the recovery is not complete");
        assert!(unfinished.contains("resuming"), "{unfinished}");
    }

    /// A recovery receipt is signed with the cached recovery authority key,
    /// for this recovery only (SA-52): the request carries no key, and a
    /// request naming another tombstone or succession than the staged one is
    /// not signed.
    #[test]
    #[serial_test::serial]
    fn a_recovery_receipt_is_signed_with_the_cached_key_for_the_staged_recovery_only() {
        recovery_db();
        crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(
            &crate::economic_fixtures::test_mnemonic(0x5C),
        )
        .expect("unlock");
        let (authority_pk, _) =
            crate::sdk::recovery_sdk::RecoverySDK::get_cached_authority_keypair()
                .expect("the cached authority");
        let (old_device, smt_root, rollup) = ([0x0Du8; 32], [0x5Eu8; 32], [0x7Fu8; 32]);
        db::set_recovery_pref("capsule_source_device_id", &old_device).expect("staged");
        db::set_recovery_pref("capsule_smt_root", &smt_root).expect("staged");
        db::set_recovery_pref("capsule_rollup_hash", &rollup).expect("staged");
        let handler = RecoveryImpl::new();
        let tombstone = |root: [u8; 32]| gp::RecoveryTombstoneRequest {
            global_root: Some(gp::Hash32 { v: root.to_vec() }),
            counter: TOMBSTONE_COUNTER,
            rollup_hash: Some(gp::Hash32 { v: rollup.to_vec() }),
            device_entropy: old_device.to_vec(),
        };

        let other = handler
            .handle_recovery_tombstone(tombstone([0x11; 32]))
            .expect_err("another tombstone is not signed");
        assert!(other.contains("another tombstone"), "{other}");
        let signed = handler
            .handle_recovery_tombstone(tombstone(smt_root))
            .expect("the staged tombstone is signed");
        let response =
            gp::RecoveryTombstoneResponse::decode(signed.result.expect("a result").body.as_slice())
                .expect("a tombstone response");
        let receipt =
            dsm::recovery::tombstone::TombstoneReceipt::from_bytes(&response.tombstone_receipt)
                .expect("a receipt");
        assert!(
            dsm::recovery::tombstone::verify_tombstone(&receipt, &authority_pk).expect("verified"),
            "signed under the cached recovery authority key"
        );
        assert_eq!(
            receipt.device_id,
            crate::util::text_id::encode_base32_crockford(&old_device)
        );

        db::store_tombstone_hash(&receipt.tombstone_hash).expect("the tombstone is stored");
        let this_device = [0x2Au8; 32];
        crate::sdk::app_state::AppState::set_identity_info(
            this_device.to_vec(),
            vec![0x41; 64],
            [0x2Bu8; 32].to_vec(),
            smt_root.to_vec(),
        )
        .expect("this device's identity");
        let succession = |device: [u8; 32]| gp::RecoverySuccessionRequest {
            tombstone_hash: Some(gp::Hash32 {
                v: receipt.tombstone_hash.clone(),
            }),
            device_entropy: device.to_vec(),
        };
        let other = handler
            .handle_recovery_succession(succession([0x3C; 32]))
            .expect_err("a succession to another device is not signed");
        assert!(other.contains("another succession"), "{other}");
        handler
            .handle_recovery_succession(succession(this_device))
            .expect("this recovery's succession to this device is signed");
    }
}
