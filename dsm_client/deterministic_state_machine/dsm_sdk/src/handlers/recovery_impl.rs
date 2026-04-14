//! # Recovery Handler Implementation
//!
//! Implements the [`RecoveryHandler`] trait
//! for capsule decryption and recovery session management at the SDK layer.

use dsm::core::bridge::RecoveryHandler;
use dsm::recovery::capsule::{decrypt_capsule_with_key, EncryptedCapsule};
use dsm::recovery::tombstone::{create_succession, create_tombstone};
use dsm::types::proto as gp;
use prost::Message;

pub struct RecoveryImpl;

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

impl RecoveryHandler for RecoveryImpl {
    fn handle_recovery_capsule_decrypt(
        &self,
        operation: gp::RecoveryCapsuleDecryptRequest,
    ) -> Result<gp::OpResult, String> {
        // 1. Parse encrypted capsule from bytes
        let encrypted = EncryptedCapsule::from_bytes(&operation.encrypted_capsule)
            .map_err(|e| format!("Failed to parse encrypted capsule: {}", e))?;

        // 2. Decrypt using provided key
        let decrypted = decrypt_capsule_with_key(&encrypted, &operation.mnemonic_key)
            .map_err(|e| format!("Failed to decrypt capsule: {}", e))?;

        // 3. Map to response proto
        let mut chain_tips = Vec::new();
        for (device_id_str, (height, head_hash)) in decrypted.counterparty_tips {
            // Device IDs must be canonical base32 Crockford text when represented as strings.
            // Fail-closed: do NOT fall back to UTF-8 bytes, which would break
            // encode/decode symmetry and can produce non-32B identifiers.
            let device_id_bytes = crate::util::text_id::decode_base32_crockford(&device_id_str)
                .ok_or_else(|| "Invalid counterparty device_id base32".to_string())?;

            if device_id_bytes.len() != 32 {
                return Err(format!(
                    "Invalid counterparty device_id length after base32 decode: got {}, expected 32",
                    device_id_bytes.len()
                ));
            }

            chain_tips.push(gp::ChainTip {
                counterparty_device_id: device_id_bytes,
                height,
                head_hash: Some(gp::Hash32 { v: head_hash }),
            });
        }

        // Persist capsule data for use during succession and resume.
        // Store SMT root for state restoration.
        if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
            "capsule_smt_root",
            &decrypted.smt_root,
        ) {
            log::warn!("[RECOVERY] Failed to persist capsule SMT root: {e}");
        }
        // Store rollup hash for state restoration.
        if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
            "capsule_rollup_hash",
            &decrypted.rollup_hash,
        ) {
            log::warn!("[RECOVERY] Failed to persist capsule rollup hash: {e}");
        }

        // Persist source device binding for tombstone (v4 capsule extension).
        if !decrypted.source_device_id.is_empty() {
            if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
                "capsule_source_device_id",
                &decrypted.source_device_id,
            ) {
                log::warn!("[RECOVERY] Failed to persist capsule source device_id: {e}");
            }
        }
        if !decrypted.genesis_hash.is_empty() {
            if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
                "capsule_genesis_hash",
                &decrypted.genesis_hash,
            ) {
                log::warn!("[RECOVERY] Failed to persist capsule genesis hash: {e}");
            }
        }

        // Persist counterparty device IDs for tombstone sync gate initialization.
        // These are needed later by recovery.tombstone to know which contacts must ACK.
        {
            let counterparty_ids: Vec<[u8; 32]> = chain_tips
                .iter()
                .filter_map(|ct| {
                    if ct.counterparty_device_id.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&ct.counterparty_device_id);
                        Some(arr)
                    } else {
                        None
                    }
                })
                .collect();

            if !counterparty_ids.is_empty() {
                if let Err(e) = crate::storage::client_db::recovery::store_capsule_counterparty_ids(
                    &counterparty_ids,
                ) {
                    log::warn!("[RECOVERY] Failed to persist counterparty IDs: {e}");
                } else {
                    log::info!(
                        "[RECOVERY] Persisted {} counterparty IDs from capsule",
                        counterparty_ids.len()
                    );
                }
            }
        }

        let response = gp::RecoveryCapsuleDecryptResponse {
            success: true,
            global_root: Some(gp::Hash32 {
                v: decrypted.smt_root,
            }),
            chain_tips,
            receipt_rollup: Some(gp::Hash32 {
                v: decrypted.rollup_hash,
            }),
            meta_data: vec![], // Metadata serialization if needed
        };

        // 4. Wrap in OpResult
        let mut body = Vec::new();
        response
            .encode(&mut body)
            .map_err(|e| format!("Failed to encode response: {}", e))?;

        Ok(gp::OpResult {
            op_id: None,
            accepted: true,
            post_state_hash: None,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    fn handle_nfc_tag(&self, operation: gp::ExternalCommit) -> Result<gp::OpResult, String> {
        // Just return the payload (capsule bytes) as a success result.
        // The UI will receive this and prompt the user for the mnemonic key,
        // then call RecoveryCapsuleDecryptRequest.

        let body = operation.payload;

        Ok(gp::OpResult {
            op_id: None,
            accepted: true,
            post_state_hash: None,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    fn handle_recovery_tombstone(
        &self,
        operation: gp::RecoveryTombstoneRequest,
    ) -> Result<gp::OpResult, String> {
        // Extract fields from the proto request
        let global_root = operation
            .global_root
            .as_ref()
            .map(|h| h.v.as_slice())
            .ok_or_else(|| "Missing global_root in tombstone request".to_string())?;
        let rollup_hash = operation
            .rollup_hash
            .as_ref()
            .map(|h| h.v.as_slice())
            .ok_or_else(|| "Missing rollup_hash in tombstone request".to_string())?;

        // The device_entropy serves as both the device_id identifier and the private key
        // for signing the tombstone receipt. In production, the private key would come from
        // the PlatformContext DBRW-bound key material.
        let device_id_bytes = &operation.device_entropy;
        if device_id_bytes.len() < 32 {
            return Err("device_entropy must be at least 32 bytes".to_string());
        }

        // Use environment_data as the signing key (SPHINCS+ private key material)
        let private_key = &operation.environment_data;

        // Encode device_id as base32 Crockford for the core function
        let device_id_str = crate::util::text_id::encode_base32_crockford(&device_id_bytes[..32]);

        // Create the tombstone receipt via core
        let tombstone = create_tombstone(
            global_root,
            operation.counter,
            rollup_hash,
            &device_id_str,
            private_key,
        )
        .map_err(|e| format!("Core tombstone creation failed: {}", e))?;

        // Build the response — store the full serialised receipt so counterparties
        // can reconstruct it for validation (not just the raw signature bytes).
        let tombstone_receipt_bytes = tombstone
            .to_bytes()
            .map_err(|e| format!("Failed to serialize tombstone receipt: {}", e))?;

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
            post_state_hash: None,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    fn handle_recovery_succession(
        &self,
        operation: gp::RecoverySuccessionRequest,
    ) -> Result<gp::OpResult, String> {
        let tombstone_hash = operation
            .tombstone_hash
            .as_ref()
            .map(|h| h.v.as_slice())
            .ok_or_else(|| "Missing tombstone_hash in succession request".to_string())?;

        // device_entropy is the new device commitment (DevID_new binding)
        let new_device_commitment = &operation.device_entropy;
        if new_device_commitment.len() < 32 {
            return Err(
                "device_entropy (new device commitment) must be at least 32 bytes".to_string(),
            );
        }

        // environment_data is the signing key
        let private_key = &operation.environment_data;

        // Encode new device_id for the core function
        let device_id_str =
            crate::util::text_id::encode_base32_crockford(&new_device_commitment[..32]);

        // Create the succession receipt via core
        let succession = create_succession(
            tombstone_hash,
            new_device_commitment,
            &device_id_str,
            private_key,
        )
        .map_err(|e| format!("Core succession creation failed: {}", e))?;

        // Store succession receipt for later reference during resume
        if let Err(e) =
            crate::storage::client_db::recovery::store_succession_receipt(&succession.signature)
        {
            log::warn!("[RECOVERY] Failed to store succession receipt: {e}");
        }

        // Restore state from the decrypted capsule data.
        // The capsule's SMT root and counterparty chain tips were persisted
        // during capsule decryption (handle_recovery_capsule_decrypt).
        // Now bind the new device identity.
        {
            let new_device_id = new_device_commitment[..32].to_vec();
            let public_key = crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
            let genesis_hash = succession.new_device_commitment.clone();

            // Read capsule's SMT root from recovery_prefs if available
            let smt_root =
                crate::storage::client_db::recovery::get_recovery_pref("capsule_smt_root")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| vec![0u8; 32]);

            crate::sdk::app_state::AppState::set_identity_info(
                new_device_id,
                public_key,
                genesis_hash,
                smt_root,
            );
            crate::sdk::app_state::AppState::set_has_identity(true);

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
            post_state_hash: None,
            result: Some(gp::ResultPack {
                schema_hash: None,
                codec: gp::Codec::Proto as i32,
                body,
            }),
            error: None,
        })
    }

    fn handle_recovery_resume(
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
            post_state_hash: None,
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
pub fn execute_recovery_pipeline() -> Result<String, String> {
    // 1. Get cached recovery authority keypair
    let (_pk, sk) = crate::sdk::recovery_sdk::RecoverySDK::get_cached_authority_keypair()
        .ok_or_else(|| "No recovery authority key cached — enter mnemonic first".to_string())?;

    // 2. Get old device_id from capsule
    let old_device_id =
        crate::storage::client_db::recovery::get_recovery_pref("capsule_source_device_id")
            .map_err(|e| format!("Failed to read capsule source device_id: {e}"))?
            .ok_or_else(|| {
                "No capsule_source_device_id found — stage a capsule first".to_string()
            })?;
    if old_device_id.len() != 32 {
        return Err(format!(
            "capsule_source_device_id must be 32 bytes, got {}",
            old_device_id.len()
        ));
    }

    // 3. Get capsule SMT root and rollup hash
    let capsule_smt_root =
        crate::storage::client_db::recovery::get_recovery_pref("capsule_smt_root")
            .map_err(|e| format!("Failed to read capsule SMT root: {e}"))?
            .ok_or_else(|| "No capsule SMT root found — stage a capsule first".to_string())?;
    let capsule_rollup_hash =
        crate::storage::client_db::recovery::get_recovery_pref("capsule_rollup_hash")
            .map_err(|e| format!("Failed to read capsule rollup hash: {e}"))?
            .ok_or_else(|| "No capsule rollup hash found — stage a capsule first".to_string())?;

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
    let _ =
        crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"tombstoning");

    // 6. Create tombstone receipt
    let old_device_id_str = crate::util::text_id::encode_base32_crockford(&old_device_id);
    let tombstone = create_tombstone(
        &capsule_smt_root,
        0, // counter — capsule metadata counter
        &capsule_rollup_hash,
        &old_device_id_str,
        &sk,
    )
    .map_err(|e| format!("Tombstone creation failed: {e}"))?;

    let tombstone_receipt_bytes = tombstone
        .to_bytes()
        .map_err(|e| format!("Failed to serialize tombstone receipt: {e}"))?;
    let tombstone_hash_hex =
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
    let _ = crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"succession");

    let new_device_id_str = crate::util::text_id::encode_base32_crockford(&new_device_id);
    let succession = create_succession(
        &tombstone.tombstone_hash,
        &new_device_id,
        &new_device_id_str,
        &sk,
    )
    .map_err(|e| format!("Succession creation failed: {e}"))?;

    // Store succession receipt
    if let Err(e) =
        crate::storage::client_db::recovery::store_succession_receipt(&succession.signature)
    {
        log::warn!("[RECOVERY] Failed to store succession receipt: {e}");
    }

    // Bind the new device identity with capsule state
    {
        let public_key = crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
        let genesis_hash = succession.new_device_commitment.clone();
        let smt_root = capsule_smt_root;

        crate::sdk::app_state::AppState::set_identity_info(
            new_device_id.clone(),
            public_key,
            genesis_hash,
            smt_root,
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
    }

    log::info!(
        "[RECOVERY] Succession bound new device {}",
        &new_device_id_str[..new_device_id_str.len().min(16)]
    );

    // 8. Initialize sync gate from capsule counterparty IDs
    let counterparty_ids = crate::storage::client_db::recovery::get_capsule_counterparty_ids()
        .map_err(|e| format!("Failed to read counterparty IDs: {e}"))?;
    if let Err(e) =
        crate::storage::client_db::recovery::init_recovery_sync_status(&counterparty_ids)
    {
        log::warn!("[RECOVERY] Failed to init sync gate: {e}");
    }

    // 9. Propagate tombstone to storage nodes
    let _ =
        crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"propagating");

    let mut pushed = 0u64;
    let mut failed = 0u64;
    let total = counterparty_ids.len() as u64;

    for counterparty_id in &counterparty_ids {
        let notify_key = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/tombstone-notify");
            h.update(counterparty_id);
            crate::util::text_id::encode_base32_crockford(h.finalize().as_bytes())
        };
        match crate::sdk::storage_node_sdk::put_to_storage(&notify_key, &tombstone_receipt_bytes) {
            Ok(()) => {
                pushed += 1;
                log::info!(
                    "[RECOVERY] Pushed tombstone for counterparty {}",
                    &crate::util::text_id::encode_base32_crockford(counterparty_id)[..16]
                );
            }
            Err(e) => {
                failed += 1;
                log::warn!("[RECOVERY] Failed to push tombstone for counterparty: {e}");
            }
        }
    }

    // 10. Set phase to polling
    let _ = crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"polling");

    Ok(format!(
        "phase=polling,tombstone_hash={},pushed={},failed={},total={}",
        tombstone_hash_hex, pushed, failed, total,
    ))
}

/// Resume all bilateral relationships from recovered chain tips.
/// Requires all counterparties to have ACK'd the tombstone (sync gate check).
pub fn resume_all_contacts() -> Result<String, String> {
    // Verify sync gate
    let all_synced = crate::storage::client_db::recovery::all_counterparties_synced()
        .map_err(|e| format!("Failed to check sync gate: {e}"))?;
    if !all_synced {
        let (synced, total) = crate::storage::client_db::recovery::get_sync_progress()
            .map_err(|e| format!("Failed to read sync progress: {e}"))?;
        return Err(format!(
            "Recovery pending: {}/{} contacts synced. All counterparties must acknowledge tombstone first.",
            synced, total
        ));
    }

    let _ = crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"resuming");

    // Get recovered chain tips and resume each
    let tips = crate::storage::client_db::recovery::get_recovered_chain_tips()
        .map_err(|e| format!("Failed to read recovered chain tips: {e}"))?;

    let mut resumed = 0u64;
    for tip in &tips {
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&tip.device_id);

        match crate::storage::client_db::restore_finalized_bilateral_chain_tip(
            &tip.device_id,
            &tip.head_hash,
        ) {
            Ok(()) => {
                resumed += 1;
                log::info!(
                    "[RECOVERY] Resumed bilateral chain tip for {}",
                    &device_id_b32[..device_id_b32.len().min(16)]
                );
            }
            Err(e) => {
                log::warn!(
                    "[RECOVERY] Failed to resume chain tip for {}: {e}",
                    &device_id_b32[..device_id_b32.len().min(16)]
                );
            }
        }
    }

    // Cleanup
    let _ = crate::storage::client_db::recovery::clear_recovery_sync_status();
    let _ = crate::storage::client_db::recovery::clear_recovered_chain_tips();
    let _ = crate::storage::client_db::recovery::set_recovery_pref("recovery_phase", b"complete");

    Ok(format!("success=true,resumed={}", resumed))
}
