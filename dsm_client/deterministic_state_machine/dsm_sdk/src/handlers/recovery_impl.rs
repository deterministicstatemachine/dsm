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
                if let Err(e) =
                    crate::storage::client_db::recovery::store_capsule_counterparty_ids(
                        &counterparty_ids,
                    )
                {
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

        // Build the response
        let response = gp::RecoveryTombstoneResponse {
            success: true,
            tombstone_hash: Some(gp::Hash32 {
                v: tombstone.tombstone_hash.clone(),
            }),
            tombstone_receipt: tombstone.signature.clone(),
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
        if let Err(e) = crate::storage::client_db::recovery::store_succession_receipt(
            &succession.signature,
        ) {
            log::warn!("[RECOVERY] Failed to store succession receipt: {e}");
        }

        // Restore state from the decrypted capsule data.
        // The capsule's SMT root and counterparty chain tips were persisted
        // during capsule decryption (handle_recovery_capsule_decrypt).
        // Now bind the new device identity.
        {
            let new_device_id = new_device_commitment[..32].to_vec();
            let public_key =
                crate::sdk::app_state::AppState::get_public_key().unwrap_or_default();
            let genesis_hash = succession.new_device_commitment.clone();

            // Read capsule's SMT root from recovery_prefs if available
            let smt_root = crate::storage::client_db::recovery::get_recovery_pref("capsule_smt_root")
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
            let device_id_b32 = crate::util::text_id::encode_base32_crockford(
                counterparty_device_id,
            );
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
            if let Err(e) = crate::storage::client_db::update_finalized_bilateral_chain_tip(
                counterparty_device_id,
                &head_hash_32,
            ) {
                log::warn!(
                    "[RECOVERY] Failed to update chain tip for {}: {e}",
                    &device_id_b32[..device_id_b32.len().min(16)]
                );
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
