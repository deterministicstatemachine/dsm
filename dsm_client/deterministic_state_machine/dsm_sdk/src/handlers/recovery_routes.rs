// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recovery route handlers for AppRouterImpl.
//!
//! Handles `recovery.*` query and invoke routes for the NFC ring backup system.
//! Query routes: `recovery.status`
//! Invoke routes: `recovery.enable`, `recovery.disable`, `recovery.createCapsule`,
//!                `recovery.tombstone`, `recovery.succession`, `recovery.resume`

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for `recovery.*` query routes.
    pub(crate) async fn handle_recovery_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "recovery.status" => {
                let status = crate::sdk::recovery_sdk::RecoverySDK::get_recovery_status();

                let resp = generated::AppStateResponse {
                    key: "recovery.status".to_string(),
                    value: Some(format!(
                        "enabled={},configured={},capsule_count={},last_capsule_index={}",
                        status.enabled,
                        status.configured,
                        status.capsule_count,
                        status.last_capsule_index,
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }
            "recovery.syncStatus" => {
                let (synced, total) =
                    crate::storage::client_db::recovery::get_sync_progress().unwrap_or((0, 0));
                let unsynced = crate::storage::client_db::recovery::get_unsynced_counterparties()
                    .unwrap_or_default();
                let pending_ids: Vec<String> = unsynced
                    .iter()
                    .map(|d| crate::util::text_id::encode_base32_crockford(d))
                    .collect();
                let resp = generated::AppStateResponse {
                    key: "recovery.syncStatus".to_string(),
                    value: Some(format!(
                        "synced={synced},total={total},pending={}",
                        pending_ids.join(","),
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }
            "recovery.capsulePreview" => {
                // Return latest capsule metadata from SQLite (no decryption needed)
                match crate::storage::client_db::recovery::get_latest_capsule_metadata() {
                    Ok(Some(meta)) => {
                        let smt_root_str =
                            crate::util::text_id::encode_base32_crockford(&meta.smt_root);
                        let resp = generated::AppStateResponse {
                            key: "recovery.capsulePreview".to_string(),
                            value: Some(format!(
                                "capsule_index={},smt_root={},created_tick={},counterparty_count={}",
                                meta.capsule_index,
                                &smt_root_str[..smt_root_str.len().min(16)],
                                meta.created_tick,
                                meta.counterparty_count,
                            )),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Ok(None) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.capsulePreview".to_string(),
                            value: Some("none".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.capsulePreview failed: {e}")),
                }
            }
            _ => err(format!("unknown recovery query path: {}", q.path)),
        }
    }

    /// Dispatch handler for `recovery.*` invoke routes.
    pub(crate) async fn handle_recovery_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            // -------- recovery.enable --------
            // Expects ArgPack with AppStateRequest { value: "mnemonic words..." }
            "recovery.enable" => {
                let mnemonic = match Self::decode_recovery_string_param(&i.args) {
                    Ok(m) => m,
                    Err(e) => return err(format!("recovery.enable: {e}")),
                };

                if mnemonic.split_whitespace().count() < 12 {
                    return err("recovery.enable: mnemonic must be at least 12 words".into());
                }

                // Derive and cache the recovery key in memory
                if let Err(e) =
                    crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(&mnemonic)
                {
                    return err(format!("recovery.enable key derivation failed: {e}"));
                }

                // Enable NFC backup in SQLite prefs
                if let Err(e) = crate::sdk::recovery_sdk::RecoverySDK::enable_nfc_backup() {
                    return err(format!("recovery.enable failed: {e}"));
                }

                // Create first capsule immediately
                match crate::sdk::recovery_sdk::RecoverySDK::create_capsule_from_current_state(
                    &mnemonic,
                ) {
                    Ok((idx, _bytes)) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.enable".to_string(),
                            value: Some(format!("enabled=true,first_capsule_index={idx}")),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => {
                        // Still enabled, but first capsule failed — not fatal
                        log::warn!("[RECOVERY] First capsule creation failed: {e}");
                        let resp = generated::AppStateResponse {
                            key: "recovery.enable".to_string(),
                            value: Some("enabled=true,first_capsule_index=0".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                }
            }

            // -------- recovery.disable --------
            "recovery.disable" => {
                // Clear cached key from memory first
                crate::sdk::recovery_sdk::RecoverySDK::clear_cached_key();

                if let Err(e) = crate::sdk::recovery_sdk::RecoverySDK::disable_nfc_backup() {
                    return err(format!("recovery.disable failed: {e}"));
                }

                let resp = generated::AppStateResponse {
                    key: "recovery.disable".to_string(),
                    value: Some("enabled=false".to_string()),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.createCapsule --------
            // Expects ArgPack with AppStateRequest { value: "mnemonic words..." }
            "recovery.createCapsule" => {
                let mnemonic = match Self::decode_recovery_string_param(&i.args) {
                    Ok(m) => m,
                    Err(e) => return err(format!("recovery.createCapsule: {e}")),
                };

                match crate::sdk::recovery_sdk::RecoverySDK::create_capsule_from_current_state(
                    &mnemonic,
                ) {
                    Ok((_idx, capsule_bytes)) => {
                        // Return the capsule bytes in an NfcRecoveryCapsule envelope
                        let nfc_capsule = generated::NfcRecoveryCapsule {
                            payload: capsule_bytes,
                        };
                        pack_envelope_ok(generated::envelope::Payload::NfcRecoveryCapsule(
                            nfc_capsule,
                        ))
                    }
                    Err(e) => err(format!("recovery.createCapsule failed: {e}")),
                }
            }

            // -------- recovery.tombstone --------
            // Expects binary RecoveryTombstoneRequest in args
            "recovery.tombstone" => {
                let req = match generated::RecoveryTombstoneRequest::decode(&*i.args) {
                    Ok(r) => r,
                    Err(e) => {
                        // Try ArgPack wrapper
                        match generated::ArgPack::decode(&*i.args) {
                            Ok(pack) => {
                                match generated::RecoveryTombstoneRequest::decode(&*pack.body) {
                                    Ok(r) => r,
                                    Err(e2) => return err(format!(
                                        "recovery.tombstone: decode failed: direct={e}, argpack={e2}"
                                    )),
                                }
                            }
                            Err(_) => {
                                return err(format!("recovery.tombstone: decode failed: {e}"))
                            }
                        }
                    }
                };

                let handler = crate::handlers::recovery_impl::RecoveryImpl::new();
                match dsm::core::bridge::RecoveryHandler::handle_recovery_tombstone(&handler, req) {
                    Ok(op_result) => {
                        // Extract tombstone receipt from OpResult and persist it
                        if let Some(ref rp) = op_result.result {
                            if let Ok(tombstone_resp) =
                                generated::RecoveryTombstoneResponse::decode(&*rp.body)
                            {
                                // Store tombstone receipt bytes for later relay
                                if let Err(e) =
                                    crate::storage::client_db::recovery::store_tombstone_receipt(
                                        &tombstone_resp.tombstone_receipt,
                                    )
                                {
                                    log::warn!("[RECOVERY] Failed to store tombstone receipt: {e}");
                                }

                                // Store tombstone hash
                                if let Some(ref th) = tombstone_resp.tombstone_hash {
                                    if let Err(e) =
                                        crate::storage::client_db::recovery::store_tombstone_hash(
                                            &th.v,
                                        )
                                    {
                                        log::warn!(
                                            "[RECOVERY] Failed to store tombstone hash: {e}"
                                        );
                                    }
                                }

                                // Initialize sync gate from capsule counterparty IDs
                                match crate::storage::client_db::recovery::get_capsule_counterparty_ids() {
                                    Ok(ids) if !ids.is_empty() => {
                                        if let Err(e) = crate::storage::client_db::recovery::init_recovery_sync_status(&ids) {
                                            log::warn!("[RECOVERY] Failed to init sync gate: {e}");
                                        } else {
                                            log::info!(
                                                "[RECOVERY] Sync gate initialized for {} counterparties",
                                                ids.len()
                                            );
                                        }
                                    }
                                    Ok(_) => {
                                        log::warn!("[RECOVERY] No capsule counterparty IDs found for sync gate");
                                    }
                                    Err(e) => {
                                        log::warn!("[RECOVERY] Failed to read counterparty IDs: {e}");
                                    }
                                }
                            }
                        }

                        let resp = generated::AppStateResponse {
                            key: "recovery.tombstone".to_string(),
                            value: Some("success=true".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.tombstone failed: {e}")),
                }
            }

            // -------- recovery.succession --------
            "recovery.succession" => {
                let req = match generated::RecoverySuccessionRequest::decode(&*i.args) {
                    Ok(r) => r,
                    Err(e) => match generated::ArgPack::decode(&*i.args) {
                        Ok(pack) => {
                            match generated::RecoverySuccessionRequest::decode(&*pack.body) {
                                Ok(r) => r,
                                Err(e2) => {
                                    return err(format!(
                                    "recovery.succession: decode failed: direct={e}, argpack={e2}"
                                ))
                                }
                            }
                        }
                        Err(_) => return err(format!("recovery.succession: decode failed: {e}")),
                    },
                };

                let handler = crate::handlers::recovery_impl::RecoveryImpl::new();
                match dsm::core::bridge::RecoveryHandler::handle_recovery_succession(&handler, req)
                {
                    Ok(_op_result) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.succession".to_string(),
                            value: Some("success=true".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.succession failed: {e}")),
                }
            }

            // -------- recovery.resume --------
            // Gated on full tombstone sync — all counterparties must have acknowledged
            "recovery.resume" => {
                // Check sync gate: recovery can't resume until ALL contacts have synced
                match crate::storage::client_db::recovery::all_counterparties_synced() {
                    Ok(true) => {} // All synced, proceed
                    Ok(false) => {
                        let (synced, total) =
                            crate::storage::client_db::recovery::get_sync_progress()
                                .unwrap_or((0, 0));
                        return err(format!(
                            "Recovery pending: {synced}/{total} contacts synced. \
                             All counterparties must acknowledge the tombstone before resume."
                        ));
                    }
                    Err(e) => {
                        log::warn!("[RECOVERY] Sync gate check failed: {e}");
                        // If we can't check, allow resume (table might not exist yet)
                    }
                }

                let req = match generated::RecoveryResumeRequest::decode(&*i.args) {
                    Ok(r) => r,
                    Err(e) => match generated::ArgPack::decode(&*i.args) {
                        Ok(pack) => match generated::RecoveryResumeRequest::decode(&*pack.body) {
                            Ok(r) => r,
                            Err(e2) => {
                                return err(format!(
                                    "recovery.resume: decode failed: direct={e}, argpack={e2}"
                                ))
                            }
                        },
                        Err(_) => return err(format!("recovery.resume: decode failed: {e}")),
                    },
                };

                let handler = crate::handlers::recovery_impl::RecoveryImpl::new();
                match dsm::core::bridge::RecoveryHandler::handle_recovery_resume(&handler, req) {
                    Ok(_op_result) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.resume".to_string(),
                            value: Some("success=true".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.resume failed: {e}")),
                }
            }

            // -------- recovery.generateMnemonic --------
            // Generates a cryptographically secure 24-word BIP-39 mnemonic via CSPRNG.
            // Crypto stays in Rust — TypeScript never generates mnemonics.
            "recovery.generateMnemonic" => {
                match crate::sdk::recovery_sdk::RecoverySDK::generate_mnemonic() {
                    Ok(words) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.generateMnemonic".to_string(),
                            value: Some(words),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.generateMnemonic failed: {e}")),
                }
            }

            // -------- nfc.ring.write --------
            // Validates NFC backup state (Rust is the authoritative source).
            // Returns a proper FramedEnvelopeV3 so Kotlin knows whether to launch
            // NfcWriteActivity.  Kotlin must call this route first (via
            // appRouterInvokeFramedSafe), check for an error response, and only
            // launch the NFC activity on success.
            "nfc.ring.write" => {
                // Check NFC backup is enabled.
                if !crate::sdk::recovery_sdk::RecoverySDK::is_nfc_backup_enabled() {
                    return err(
                        "NFC backup not enabled. Enable it via Settings > NFC Ring Backup first."
                            .into(),
                    );
                }

                // Check a capsule is pending (must call recovery.createCapsule first).
                if crate::sdk::recovery_sdk::RecoverySDK::get_pending_capsule().is_none() {
                    return err("No pending capsule. Call recovery.createCapsule first.".into());
                }

                // Authorization granted — Kotlin will launch NfcWriteActivity.
                let resp = generated::AppStateResponse {
                    key: "nfc.ring.write".to_string(),
                    value: Some("authorized=true".to_string()),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.propagateTombstone --------
            // Push tombstone receipt to storage nodes for each unsynced counterparty.
            // Keyed by BLAKE3("DSM/tombstone-notify\0" || counterparty_device_id).
            "recovery.propagateTombstone" => {
                let receipt = match crate::storage::client_db::recovery::get_tombstone_receipt() {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return err(
                            "No tombstone receipt stored. Call recovery.tombstone first.".into(),
                        )
                    }
                    Err(e) => return err(format!("recovery.propagateTombstone: {e}")),
                };

                let unsynced = crate::storage::client_db::recovery::get_unsynced_counterparties()
                    .unwrap_or_default();
                if unsynced.is_empty() {
                    return err("No unsynced counterparties to propagate to.".into());
                }

                let mut pushed = 0u64;
                let mut failed = 0u64;

                for device_id in &unsynced {
                    // Compute storage key: BLAKE3("DSM/tombstone-notify\0" || device_id)
                    let key = {
                        let mut hasher = dsm::crypto::blake3::Hasher::new_keyed(
                            b"DSM/tombstone-notify\0\0\0\0\0\0\0\0\0\0\0\0",
                        );
                        hasher.update(device_id);
                        let hash = hasher.finalize();
                        crate::util::text_id::encode_base32_crockford(hash.as_bytes())
                    };

                    match crate::sdk::storage_node_sdk::put_to_storage(&key, &receipt) {
                        Ok(_) => {
                            pushed += 1;
                            log::debug!(
                                "[RECOVERY] Pushed tombstone to storage for counterparty {}",
                                &crate::util::text_id::encode_base32_crockford(device_id)[..16]
                            );
                        }
                        Err(e) => {
                            failed += 1;
                            log::warn!("[RECOVERY] Failed to push tombstone for counterparty: {e}");
                        }
                    }
                }

                let resp = generated::AppStateResponse {
                    key: "recovery.propagateTombstone".to_string(),
                    value: Some(format!(
                        "pushed={pushed},failed={failed},total={}",
                        unsynced.len()
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.pollAcks --------
            // Check storage nodes for tombstone ACKs from counterparties.
            // Updates sync status for each ACK found.
            "recovery.pollAcks" => {
                let unsynced = crate::storage::client_db::recovery::get_unsynced_counterparties()
                    .unwrap_or_default();

                if unsynced.is_empty() {
                    let resp = generated::AppStateResponse {
                        key: "recovery.pollAcks".to_string(),
                        value: Some("all_synced=true".to_string()),
                    };
                    return pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp));
                }

                // Get our new device_id for ACK key computation
                let our_device_id =
                    crate::sdk::app_state::AppState::get_device_id().unwrap_or_default();

                let mut new_acks = 0u64;
                let tick = crate::util::deterministic_time::tick();

                for device_id in &unsynced {
                    // Check for ACK: BLAKE3("DSM/tombstone-ack\0" || our_device_id || counterparty_device_id)
                    let key = {
                        let mut hasher = dsm::crypto::blake3::Hasher::new_keyed(
                            b"DSM/tombstone-ack\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        );
                        hasher.update(&our_device_id);
                        hasher.update(device_id);
                        let hash = hasher.finalize();
                        crate::util::text_id::encode_base32_crockford(hash.as_bytes())
                    };

                    match crate::sdk::storage_node_sdk::get_from_storage(&key) {
                        Ok(Some(_ack_bytes)) => {
                            if let Err(e) =
                                crate::storage::client_db::recovery::mark_counterparty_synced(
                                    device_id, tick,
                                )
                            {
                                log::warn!("[RECOVERY] Failed to mark counterparty synced: {e}");
                            } else {
                                new_acks += 1;
                            }
                        }
                        Ok(None) => {} // No ACK yet
                        Err(e) => {
                            log::warn!("[RECOVERY] Failed to check ACK from storage: {e}");
                        }
                    }
                }

                let (synced, total) =
                    crate::storage::client_db::recovery::get_sync_progress().unwrap_or((0, 0));
                let all_done = synced == total && total > 0;

                let resp = generated::AppStateResponse {
                    key: "recovery.pollAcks".to_string(),
                    value: Some(format!(
                        "new_acks={new_acks},synced={synced},total={total},all_synced={all_done}"
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.checkTombstones --------
            // Counterparty-side: check storage nodes for tombstone notifications addressed to us.
            // If found, validate and ACK.
            "recovery.checkTombstones" => {
                let our_device_id =
                    crate::sdk::app_state::AppState::get_device_id().unwrap_or_default();
                if our_device_id.len() != 32 {
                    return err("Device identity not initialized".into());
                }

                // Check for tombstone notifications: BLAKE3("DSM/tombstone-notify\0" || our_device_id)
                let notify_key = {
                    let mut hasher = dsm::crypto::blake3::Hasher::new_keyed(
                        b"DSM/tombstone-notify\0\0\0\0\0\0\0\0\0\0\0\0",
                    );
                    hasher.update(&our_device_id);
                    let hash = hasher.finalize();
                    crate::util::text_id::encode_base32_crockford(hash.as_bytes())
                };

                match crate::sdk::storage_node_sdk::get_from_storage(&notify_key) {
                    Ok(Some(tombstone_receipt_bytes)) => {
                        // Validate the tombstone receipt
                        match dsm::recovery::tombstone::TombstoneReceipt::from_bytes(
                            &tombstone_receipt_bytes,
                        ) {
                            Ok(receipt) => {
                                // Look up the sender's public key from contacts
                                let sender_device_id_bytes =
                                    crate::util::text_id::decode_base32_crockford(
                                        &receipt.device_id,
                                    )
                                    .unwrap_or_default();

                                if sender_device_id_bytes.len() == 32 {
                                    let mut sender_arr = [0u8; 32];
                                    sender_arr.copy_from_slice(&sender_device_id_bytes);

                                    // Store as tombstoned device
                                    let tick = crate::util::deterministic_time::tick();
                                    if let Err(e) =
                                        crate::storage::client_db::recovery::store_tombstoned_device(
                                            &sender_arr,
                                            &receipt.tombstone_hash,
                                            tick,
                                        )
                                    {
                                        log::warn!(
                                            "[RECOVERY] Failed to store tombstoned device: {e}"
                                        );
                                    }

                                    // Write ACK to storage:
                                    // BLAKE3("DSM/tombstone-ack\0" || tombstoned_device_id || our_device_id)
                                    let ack_key = {
                                        let mut hasher = dsm::crypto::blake3::Hasher::new_keyed(
                                            b"DSM/tombstone-ack\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                                        );
                                        hasher.update(&sender_device_id_bytes);
                                        hasher.update(&our_device_id);
                                        let hash = hasher.finalize();
                                        crate::util::text_id::encode_base32_crockford(
                                            hash.as_bytes(),
                                        )
                                    };

                                    // ACK payload is just our device_id (proof we acknowledged)
                                    if let Err(e) = crate::sdk::storage_node_sdk::put_to_storage(
                                        &ack_key,
                                        &our_device_id,
                                    ) {
                                        log::warn!("[RECOVERY] Failed to write tombstone ACK: {e}");
                                    }

                                    let resp = generated::AppStateResponse {
                                        key: "recovery.checkTombstones".to_string(),
                                        value: Some(format!(
                                            "found=true,tombstoned_device={}",
                                            &receipt.device_id[..receipt.device_id.len().min(16)]
                                        )),
                                    };
                                    pack_envelope_ok(
                                        generated::envelope::Payload::AppStateResponse(resp),
                                    )
                                } else {
                                    err("Invalid tombstone sender device_id".into())
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "[RECOVERY] Invalid tombstone receipt from storage: {e}"
                                );
                                let resp = generated::AppStateResponse {
                                    key: "recovery.checkTombstones".to_string(),
                                    value: Some("found=false".to_string()),
                                };
                                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                                    resp,
                                ))
                            }
                        }
                    }
                    Ok(None) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.checkTombstones".to_string(),
                            value: Some("found=false".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!(
                        "recovery.checkTombstones: storage query failed: {e}"
                    )),
                }
            }

            // -------- recovery.completeResume --------
            // Final cleanup after all counterparties have been individually resumed.
            "recovery.completeResume" => {
                // Clear sync status table (recovery cycle complete)
                if let Err(e) = crate::storage::client_db::recovery::clear_recovery_sync_status() {
                    log::warn!("[RECOVERY] Failed to clear sync status: {e}");
                }
                // Clear tombstone-related prefs
                let _ = crate::storage::client_db::recovery::set_recovery_pref(
                    "tombstone_receipt",
                    &[],
                );
                let _ =
                    crate::storage::client_db::recovery::set_recovery_pref("tombstone_hash", &[]);
                let _ = crate::storage::client_db::recovery::set_recovery_pref(
                    "capsule_counterparty_ids",
                    &[],
                );
                let _ =
                    crate::storage::client_db::recovery::set_recovery_pref("capsule_smt_root", &[]);
                let _ = crate::storage::client_db::recovery::set_recovery_pref(
                    "capsule_rollup_hash",
                    &[],
                );
                let _ = crate::storage::client_db::recovery::set_recovery_pref(
                    "succession_receipt",
                    &[],
                );

                log::info!("[RECOVERY] Recovery cycle complete — all state cleaned up");

                let resp = generated::AppStateResponse {
                    key: "recovery.completeResume".to_string(),
                    value: Some("success=true".to_string()),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            _ => err(format!("unknown recovery invoke method: {}", i.method)),
        }
    }

    /// Decode a string parameter from an ArgPack-wrapped AppStateRequest.
    fn decode_recovery_string_param(args: &[u8]) -> Result<String, String> {
        // Try ArgPack(AppStateRequest) first
        if let Ok(pack) = generated::ArgPack::decode(args) {
            if let Ok(req) = generated::AppStateRequest::decode(&*pack.body) {
                if !req.value.is_empty() {
                    return Ok(req.value);
                }
            }
        }

        // Try bare AppStateRequest
        if let Ok(req) = generated::AppStateRequest::decode(args) {
            if !req.value.is_empty() {
                return Ok(req.value);
            }
        }

        // Try raw UTF-8
        if let Ok(s) = std::str::from_utf8(args) {
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }

        Err("expected ArgPack(AppStateRequest) or raw UTF-8 string in args".to_string())
    }
}
