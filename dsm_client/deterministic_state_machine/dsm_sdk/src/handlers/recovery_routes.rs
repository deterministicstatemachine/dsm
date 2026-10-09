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

                let auto_write = crate::storage::client_db::recovery::is_nfc_auto_write_enabled();
                let resp = generated::AppStateResponse {
                    key: "recovery.status".to_string(),
                    value: Some(format!(
                        "enabled={},configured={},pending={},capsule_count={},last_capsule_index={},auto_write={},capsule_dirty={},accepted_state_index={},capsule_state_index={}",
                        status.enabled,
                        status.configured,
                        status.pending_capsule,
                        status.capsule_count,
                        status.last_capsule_index,
                        auto_write,
                        status.capsule_dirty,
                        status.accepted_state_index,
                        status.capsule_state_index,
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
                                "capsule_index={},smt_root={},counterparty_count={}",
                                meta.capsule_index, smt_root_str, meta.counterparty_count,
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
            "recovery.phase" => {
                let phase =
                    crate::storage::client_db::recovery::get_recovery_pref("recovery_phase")
                        .unwrap_or(None)
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_else(|| "none".to_string());
                let resp = generated::AppStateResponse {
                    key: "recovery.phase".to_string(),
                    value: Some(phase),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
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

                // Mainnet recovery authority MUST encode >=256 bits of entropy
                // (24-word BIP39). 12-word phrases must NOT be the primary mainnet
                // recovery authority (spec §3.1, condition T0.2).
                if mnemonic.split_whitespace().count() < 24 {
                    return err(
                        "recovery.enable: mnemonic must be a 24-word (256-bit) phrase".into(),
                    );
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

                // Best-effort: publish the genesis-anchored recovery-authority anchor
                // (§0.5) so counterparties can later authenticate this device's
                // tombstone/succession. OFFLINE-FIRST — spawned detached so it NEVER
                // blocks enable; if the device is offline (or a conflicting anchor is
                // already bound) it is logged and left for a later online retry.
                // Bind-once is enforced server-side per genesis, so a re-publish of the
                // same anchor is idempotent.
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.spawn(async {
                        match crate::sdk::recovery_sdk::RecoverySDK::publish_authority_anchor()
                            .await
                        {
                            Ok(n) => log::info!(
                                "[RECOVERY] published recovery-authority anchor to {n} node(s)"
                            ),
                            Err(e) => log::warn!(
                                "[RECOVERY] recovery-authority anchor publish deferred \
                                 (best-effort, will retry when online): {e}"
                            ),
                        }
                        // P5 dBTC enumeration: publish the signed dBTC vault index so a future
                        // recovered device can discover this identity's vaults (best-effort).
                        match crate::sdk::recovery_sdk::RecoverySDK::publish_dbtc_vault_index()
                            .await
                        {
                            Ok(n) => {
                                log::info!("[RECOVERY] published dBTC vault index ({n} vaults)")
                            }
                            Err(e) => log::warn!(
                                "[RECOVERY] dBTC vault index publish deferred (best-effort): {e}"
                            ),
                        }
                    });
                } else {
                    log::warn!(
                        "[RECOVERY] no async runtime to publish recovery-authority anchor; \
                         deferring to a later online sync"
                    );
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

            // -------- recovery.cacheMnemonic --------
            // Derives the recovery key and keeps it in Rust memory for follow-on
            // ring decrypt/import or lazy capsule refresh.
            "recovery.cacheMnemonic" => {
                let mnemonic = match Self::decode_recovery_string_param(&i.args) {
                    Ok(m) => m,
                    Err(e) => return err(format!("recovery.cacheMnemonic: {e}")),
                };

                // Mainnet recovery authority MUST be a 24-word (256-bit) phrase
                // (spec §3.1, condition T0.2).
                if mnemonic.split_whitespace().count() < 24 {
                    return err(
                        "recovery.cacheMnemonic: mnemonic must be a 24-word (256-bit) phrase"
                            .into(),
                    );
                }

                if let Err(e) =
                    crate::sdk::recovery_sdk::RecoverySDK::derive_and_cache_key(&mnemonic)
                {
                    return err(format!("recovery.cacheMnemonic failed: {e}"));
                }

                let resp = generated::AppStateResponse {
                    key: "recovery.cacheMnemonic".to_string(),
                    value: Some("cached=true".to_string()),
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

            // -------- recovery.inspectCapsule --------
            // Decrypts a ring capsule using the cached recovery key so mnemonic
            // handling stays inside Rust, but does not stage any recovered state.
            "recovery.inspectCapsule" => {
                let capsule = match Self::decode_nfc_capsule_payload(&i.args) {
                    Ok(payload) => payload,
                    Err(e) => return err(format!("recovery.inspectCapsule: {e}")),
                };

                let decrypted =
                    match crate::sdk::recovery_sdk::RecoverySDK::decrypt_capsule_with_cached_key_bytes(
                        &capsule,
                    ) {
                        Ok(v) => v,
                        Err(e) => return err(format!("recovery.inspectCapsule failed: {e}")),
                    };

                let (chain_tips, _) =
                    match Self::map_decrypted_capsule(&decrypted, "recovery.inspectCapsule") {
                        Ok(mapped) => mapped,
                        Err(e) => return err(e),
                    };

                let resp = Self::build_capsule_decrypt_response(&decrypted, chain_tips);
                pack_envelope_ok(generated::envelope::Payload::RecoveryCapsuleDecryptResponse(resp))
            }

            // -------- recovery.decryptCapsule --------
            // Decrypts a ring capsule using the cached recovery key so mnemonic
            // handling stays inside Rust, then stages the recovered state locally.
            "recovery.decryptCapsule" => {
                let capsule = match Self::decode_nfc_capsule_payload(&i.args) {
                    Ok(payload) => payload,
                    Err(e) => return err(format!("recovery.decryptCapsule: {e}")),
                };

                let decrypted =
                    match crate::sdk::recovery_sdk::RecoverySDK::decrypt_capsule_with_cached_key_bytes(
                        &capsule,
                    ) {
                        Ok(v) => v,
                        Err(e) => return err(format!("recovery.decryptCapsule failed: {e}")),
                    };

                let (chain_tips, recovered_tips) =
                    match Self::map_decrypted_capsule(&decrypted, "recovery.decryptCapsule") {
                        Ok(mapped) => mapped,
                        Err(e) => return err(e),
                    };

                Self::clear_staged_recovery_state();

                if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
                    "capsule_smt_root",
                    &decrypted.smt_root,
                ) {
                    log::warn!("[RECOVERY] Failed to persist capsule SMT root: {e}");
                }
                if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(
                    "capsule_rollup_hash",
                    &decrypted.rollup_hash,
                ) {
                    log::warn!("[RECOVERY] Failed to persist capsule rollup hash: {e}");
                }

                if let Err(e) =
                    crate::storage::client_db::recovery::store_recovered_chain_tips(&recovered_tips)
                {
                    log::warn!("[RECOVERY] Failed to persist recovered chain tips: {e}");
                }

                let counterparty_ids: Vec<[u8; 32]> =
                    recovered_tips.iter().map(|tip| tip.device_id).collect();
                if !counterparty_ids.is_empty() {
                    if let Err(e) =
                        crate::storage::client_db::recovery::store_capsule_counterparty_ids(
                            &counterparty_ids,
                        )
                    {
                        log::warn!("[RECOVERY] Failed to persist counterparty IDs: {e}");
                    }
                }

                let resp = Self::build_capsule_decrypt_response(&decrypted, chain_tips);
                pack_envelope_ok(generated::envelope::Payload::RecoveryCapsuleDecryptResponse(resp))
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

            // -------- nfc.ring.read --------
            // Authorizes inline NFC reading.
            // No capsule validation — we are reading from the ring, not writing.
            "nfc.ring.read" => {
                let resp = generated::AppStateResponse {
                    key: "nfc.ring.read".to_string(),
                    value: Some("authorized=true".to_string()),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- nfc.ring.write --------
            // Validates NFC backup state (Rust is the authoritative source).
            // Returns a proper FramedEnvelopeV3 so Kotlin knows whether to proceed
            // with inline NFC writing.
            "nfc.ring.write" => {
                // Check NFC backup is enabled.
                let enabled = crate::sdk::recovery_sdk::RecoverySDK::is_nfc_backup_enabled();
                log::info!("[NFC_DIAG] nfc.ring.write: enabled={}", enabled);
                if !enabled {
                    log::warn!("[NFC_DIAG] nfc.ring.write: REJECTED — not enabled");
                    return err(
                        "NFC backup not enabled. Enable it via Settings > NFC Ring Backup first."
                            .into(),
                    );
                }

                // Check a latest capsule is available for transport to Kotlin.
                let pending = crate::sdk::recovery_sdk::RecoverySDK::get_pending_capsule();
                log::info!("[NFC_DIAG] nfc.ring.write: pending={}", pending.is_some());
                if pending.is_none() {
                    log::warn!("[NFC_DIAG] nfc.ring.write: REJECTED — no pending capsule");
                    return err(
                        "No recovery capsule is available. Enable backup or rebuild the latest capsule first."
                            .into(),
                    );
                }

                // Authorization granted — Kotlin will proceed with inline NFC writing.
                log::info!("[NFC_DIAG] nfc.ring.write: AUTHORIZED");
                let resp = generated::AppStateResponse {
                    key: "nfc.ring.write".to_string(),
                    value: Some("authorized=true".to_string()),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.propagateTombstone --------
            // Put the tombstone receipt in each unsynced contact's notice cell.
            "recovery.propagateTombstone" => {
                match super::recovery_impl::propagate_tombstone().await {
                    Ok(value) => pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                        generated::AppStateResponse {
                            key: "recovery.propagateTombstone".to_string(),
                            value: Some(value),
                        },
                    )),
                    Err(e) => err(format!("recovery.propagateTombstone: {e}")),
                }
            }

            // -------- recovery.pollAcks --------
            // A contact is synced once its acknowledgement verifies under its AK.
            "recovery.pollAcks" => match poll_tombstone_acks().await {
                Ok(value) => pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: "recovery.pollAcks".to_string(),
                        value: Some(value),
                    },
                )),
                Err(e) => err(format!("recovery.pollAcks: {e}")),
            },

            // -------- recovery.checkTombstones --------
            // Contact side: tombstones posted for this device, verified under the
            // tombstoned device's contact AK, recorded and acknowledged.
            "recovery.checkTombstones" => match check_tombstones().await {
                Ok(value) => pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: "recovery.checkTombstones".to_string(),
                        value: Some(value),
                    },
                )),
                Err(e) => err(format!("recovery.checkTombstones: {e}")),
            },

            // -------- recovery.completeResume --------
            // Final cleanup after all counterparties have been individually resumed.
            "recovery.completeResume" => {
                // Clear sync status table (recovery cycle complete)
                if let Err(e) = crate::storage::client_db::recovery::clear_recovery_sync_status() {
                    log::warn!("[RECOVERY] Failed to clear sync status: {e}");
                }
                if let Err(e) = crate::storage::client_db::recovery::clear_recovered_chain_tips() {
                    log::warn!("[RECOVERY] Failed to clear recovered chain tips: {e}");
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

            // -------- recovery.setAutoWrite --------
            // Toggle the auto-write-to-ring pref (persistent toast after transactions).
            "recovery.setAutoWrite" => {
                let val = match Self::decode_recovery_string_param(&i.args) {
                    Ok(v) => v,
                    Err(e) => return err(format!("recovery.setAutoWrite: {e}")),
                };
                let enabled = val.trim() == "true";
                if let Err(e) =
                    crate::storage::client_db::recovery::set_nfc_auto_write_enabled(enabled)
                {
                    return err(format!("recovery.setAutoWrite failed: {e}"));
                }
                let resp = generated::AppStateResponse {
                    key: "recovery.setAutoWrite".to_string(),
                    value: Some(format!("auto_write={enabled}")),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- recovery.executePipeline --------
            // Runs tombstone + succession + propagate using cached authority key.
            // No parameters needed — everything is in cache / recovery_prefs.
            "recovery.executePipeline" => {
                match super::recovery_impl::execute_recovery_pipeline().await {
                    Ok(summary) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.executePipeline".to_string(),
                            value: Some(summary),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.executePipeline failed: {e}")),
                }
            }

            // -------- recovery.resumeAll --------
            // Resume all bilateral relationships from recovered chain tips.
            // Gated on all counterparties having ACK'd the tombstone.
            "recovery.resumeAll" => match super::recovery_impl::resume_all_contacts() {
                Ok(summary) => {
                    let resp = generated::AppStateResponse {
                        key: "recovery.resumeAll".to_string(),
                        value: Some(summary),
                    };
                    pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                }
                Err(e) => err(format!("recovery.resumeAll failed: {e}")),
            },

            // -------- recovery.activate (spec §0.5 Phase D step 2) --------
            // Decode the persisted recovery state into a RecoveryActivationContext, then run
            // the activation orchestration: fetch A_old's + every counterparty's online-posted
            // genesis-authenticated state, assemble + verify per-counterparty cross-relationship
            // succession evidence, and feed the SOLE unlock chokepoint. The chokepoint stays
            // FAIL-CLOSED (recording disabled until the audited go-live + P5); a clean assembly
            // that hits that gate is reported as a status, not a failure, so the end-to-end path
            // is observably reachable. Genuine evidence/gate failures are surfaced as errors.
            "recovery.activate" => {
                let ctx = match crate::sdk::recovery_sdk::RecoverySDK::build_activation_context_from_persisted() {
                    Ok(c) => c,
                    Err(e) => return err(format!("recovery.activate: context: {e}")),
                };
                match crate::sdk::recovery_sdk::RecoverySDK::build_and_activate_recovery(&ctx).await
                {
                    Ok(()) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.activate".to_string(),
                            value: Some("activated".to_string()),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    // The designed fail-closed gate (no spend unlock pre-go-live): report the
                    // assembled-but-disabled state as a status so the pipeline is observably wired.
                    Err(dsm::types::error::DsmError::InvalidState(msg))
                        if msg.contains("recovery activation recording disabled") =>
                    {
                        let resp = generated::AppStateResponse {
                            key: "recovery.activate".to_string(),
                            value: Some(format!("assembled;awaiting-go-live:{msg}")),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.activate failed: {e}")),
                }
            }

            // -------- recovery.reconcileDbtc (spec §0.4 P5 — dBTC pass) --------
            // Reconcile the recovered dBTC bearer asset from posted vault advertisements.
            // Candidate vault ids are caller-supplied (comma-separated) until authenticated
            // fresh-device vault ENUMERATION exists (deferred); with none, dBTC stays
            // LockedRecovery and a "dbtc-locked;awaiting-enumeration" status is returned (not a
            // hard error). dBTC is unlocked only for vaults whose posted frontier proves it;
            // any incomplete/unverifiable evidence keeps it LockedRecovery (fail-closed).
            "recovery.reconcileDbtc" => {
                let mut candidates: Vec<String> = match Self::decode_recovery_string_param(&i.args)
                {
                    Ok(s) => s
                        .split(',')
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .collect(),
                    Err(_) => Vec::new(),
                };
                // No explicit candidates → auto-source from the posted, K_A-verified dBTC vault
                // index for A_old. If that's unavailable, candidates stay empty and the
                // reconcile returns the awaiting-enumeration status (dBTC stays locked).
                if candidates.is_empty() {
                    match crate::sdk::recovery_sdk::RecoverySDK::auto_dbtc_vault_candidates().await
                    {
                        Ok(ids) => candidates = ids,
                        Err(e) => log::debug!("[recovery.reconcileDbtc] no vault index: {e}"),
                    }
                }
                match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reconcile_dbtc_asset(&candidates)
                    .await
                {
                    Ok(state) => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.reconcileDbtc".to_string(),
                            value: Some(format!("dbtc-state={}", state.label())),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    // Deferred enumeration: report as a status, not a failure (dBTC stays locked).
                    Err(e) if e.to_string().contains("MissingDbtcVaultEnumeration") => {
                        let resp = generated::AppStateResponse {
                            key: "recovery.reconcileDbtc".to_string(),
                            value: Some(format!("dbtc-locked;awaiting-enumeration:{e}")),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("recovery.reconcileDbtc failed: {e}")),
                }
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

    fn decode_nfc_capsule_payload(args: &[u8]) -> Result<Vec<u8>, String> {
        if let Ok(msg) = generated::NfcRecoveryCapsule::decode(args) {
            if !msg.payload.is_empty() {
                return Ok(msg.payload);
            }
        }

        if let Ok(pack) = generated::ArgPack::decode(args) {
            if let Ok(msg) = generated::NfcRecoveryCapsule::decode(&*pack.body) {
                if !msg.payload.is_empty() {
                    return Ok(msg.payload);
                }
            }
        }

        Err("expected NfcRecoveryCapsule protobuf in args".to_string())
    }

    fn clear_staged_recovery_state() {
        if let Err(e) = crate::storage::client_db::recovery::clear_recovery_sync_status() {
            log::warn!("[RECOVERY] Failed to clear sync status before import: {e}");
        }
        if let Err(e) = crate::storage::client_db::recovery::clear_recovered_chain_tips() {
            log::warn!("[RECOVERY] Failed to clear recovered chain tips before import: {e}");
        }

        for key in [
            "tombstone_receipt",
            "tombstone_hash",
            "capsule_counterparty_ids",
            "capsule_smt_root",
            "capsule_rollup_hash",
            "succession_receipt",
        ] {
            if let Err(e) = crate::storage::client_db::recovery::set_recovery_pref(key, &[]) {
                log::warn!("[RECOVERY] Failed to clear recovery pref {}: {}", key, e);
            }
        }
    }

    fn map_decrypted_capsule(
        decrypted: &dsm::recovery::RecoveryCapsule,
        route_name: &str,
    ) -> Result<
        (
            Vec<generated::ChainTip>,
            Vec<crate::storage::client_db::recovery::RecoveredChainTip>,
        ),
        String,
    > {
        if decrypted.smt_root.len() != 32 {
            return Err(format!("{route_name}: invalid SMT root length"));
        }
        if decrypted.rollup_hash.len() != 32 {
            return Err(format!("{route_name}: invalid rollup hash length"));
        }

        let mut chain_tips = Vec::new();
        let mut recovered_tips = Vec::new();
        for (device_id_str, (height, head_hash)) in &decrypted.counterparty_tips {
            let device_id_bytes = crate::util::text_id::decode_base32_crockford(device_id_str)
                .ok_or_else(|| format!("{route_name}: invalid counterparty device_id"))?;

            if device_id_bytes.len() != 32 {
                return Err(format!(
                    "{route_name}: invalid counterparty device_id length"
                ));
            }
            if head_hash.len() != 32 {
                return Err(format!(
                    "{route_name}: invalid counterparty head_hash length"
                ));
            }

            let mut device_id_arr = [0u8; 32];
            device_id_arr.copy_from_slice(&device_id_bytes);
            let mut head_hash_arr = [0u8; 32];
            head_hash_arr.copy_from_slice(head_hash);
            recovered_tips.push(crate::storage::client_db::recovery::RecoveredChainTip {
                device_id: device_id_arr,
                height: *height,
                head_hash: head_hash_arr,
            });

            chain_tips.push(generated::ChainTip {
                counterparty_device_id: device_id_bytes,
                height: *height,
                head_hash: Some(generated::Hash32 {
                    v: head_hash.clone(),
                }),
            });
        }

        Ok((chain_tips, recovered_tips))
    }

    fn build_capsule_decrypt_response(
        decrypted: &dsm::recovery::RecoveryCapsule,
        chain_tips: Vec<generated::ChainTip>,
    ) -> generated::RecoveryCapsuleDecryptResponse {
        let mut metadata = Vec::with_capacity(20);
        metadata.extend_from_slice(&decrypted.metadata.version.to_le_bytes());
        metadata.extend_from_slice(&decrypted.metadata.flags.to_le_bytes());
        metadata.extend_from_slice(&decrypted.metadata.logical_time.to_le_bytes());
        metadata.extend_from_slice(&decrypted.metadata.counter.to_le_bytes());

        generated::RecoveryCapsuleDecryptResponse {
            success: true,
            global_root: Some(generated::Hash32 {
                v: decrypted.smt_root.clone(),
            }),
            chain_tips,
            receipt_rollup: Some(generated::Hash32 {
                v: decrypted.rollup_hash.clone(),
            }),
            meta_data: metadata,
        }
    }
}

fn device32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|e| format!("{what} is not 32 bytes: {e}"))
}

/// The tombstone this device's recovery produced.
fn stored_tombstone() -> Result<(Vec<u8>, dsm::recovery::TombstoneReceipt), String> {
    let bytes = crate::storage::client_db::recovery::get_tombstone_receipt()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no tombstone receipt stored; call recovery.tombstone first".to_string())?;
    let receipt = dsm::recovery::TombstoneReceipt::from_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok((bytes, receipt))
}

/// The tombstoned device a receipt names.
fn tombstoned_device(receipt: &dsm::recovery::TombstoneReceipt) -> Result<[u8; 32], String> {
    let bytes = crate::util::text_id::decode_base32_crockford(&receipt.device_id)
        .ok_or_else(|| "the tombstone's device id is not Base32 Crockford".to_string())?;
    device32(&bytes, "the tombstone's device id")
}

/// A contact's AK, as pinned when the contact was added.
fn contact_ak(device_id: &[u8; 32]) -> Result<Vec<u8>, String> {
    let contact = crate::storage::client_db::get_contact_by_device_id(device_id)
        .map_err(|e| format!("contact lookup: {e}"))?
        .ok_or_else(|| "the device is not a contact".to_string())?;
    if contact.public_key.is_empty() {
        return Err("the contact has no pinned AK".to_string());
    }
    Ok(contact.public_key)
}

async fn poll_tombstone_acks() -> Result<String, String> {
    let unsynced = crate::storage::client_db::recovery::get_unsynced_counterparties()
        .map_err(|e| e.to_string())?;
    if unsynced.is_empty() {
        return Ok("all_synced=true".to_string());
    }
    let (.., receipt) = stored_tombstone()?;
    let tombstone_hash = device32(&receipt.tombstone_hash, "the tombstone hash")?;
    let tombstoned = tombstoned_device(&receipt)?;
    let mut new_acks = 0u64;
    for contact_device_id in &unsynced {
        let ak = match contact_ak(contact_device_id) {
            Ok(ak) => ak,
            Err(e) => {
                log::warn!("[RECOVERY] cannot check an acknowledgement: {e}");
                continue;
            }
        };
        let cell = dsm::recovery::RecoveryCell::TombstoneAck {
            tombstoned_device_id: tombstoned,
            acknowledging_device_id: *contact_device_id,
        };
        let acknowledged = crate::sdk::recovery_store::entries(&cell)
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .filter_map(|bytes| dsm::recovery::ContactTombstoneAck::from_bytes(bytes).ok())
            .any(|ack| {
                ack.tombstone_hash == tombstone_hash
                    && ack.acknowledging_device_id == *contact_device_id
                    && ack.verify(&ak).is_ok()
            });
        if acknowledged {
            crate::storage::client_db::recovery::mark_counterparty_synced(contact_device_id)
                .map_err(|e| e.to_string())?;
            new_acks += 1;
        }
    }
    let (synced, total) =
        crate::storage::client_db::recovery::get_sync_progress().map_err(|e| e.to_string())?;
    Ok(format!(
        "new_acks={new_acks},synced={synced},total={total},all_synced={}",
        synced == total && total > 0
    ))
}

async fn check_tombstones() -> Result<String, String> {
    let own_device = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| "device identity not initialized".to_string())?;
    let own_device = device32(&own_device, "this device's id")?;
    let cell = dsm::recovery::RecoveryCell::TombstoneNotice {
        contact_device_id: own_device,
    };
    let secret_key =
        crate::sdk::signing_authority::current_secret_key().map_err(|e| e.to_string())?;
    let mut recorded: Vec<[u8; 32]> = Vec::new();
    for bytes in crate::sdk::recovery_store::entries(&cell)
        .await
        .map_err(|e| e.to_string())?
    {
        // Anyone can write the cell: a notice counts only once it verifies
        // under the tombstoned device's pinned contact AK.
        let Ok(receipt) = dsm::recovery::TombstoneReceipt::from_bytes(&bytes) else {
            continue;
        };
        let Ok(tombstoned) = tombstoned_device(&receipt) else {
            continue;
        };
        let Ok(ak) = contact_ak(&tombstoned) else {
            continue;
        };
        if !matches!(
            dsm::recovery::tombstone::verify_tombstone(&receipt, &ak),
            Ok(true)
        ) {
            continue;
        }
        let tombstone_hash = device32(&receipt.tombstone_hash, "the tombstone hash")?;
        crate::storage::client_db::recovery::store_tombstoned_device(
            &tombstoned,
            &receipt.tombstone_hash,
        )
        .map_err(|e| e.to_string())?;
        let ack = dsm::recovery::ContactTombstoneAck::sign(tombstone_hash, own_device, &secret_key)
            .map_err(|e| e.to_string())?;
        crate::sdk::recovery_store::put(
            &dsm::recovery::RecoveryCell::TombstoneAck {
                tombstoned_device_id: tombstoned,
                acknowledging_device_id: own_device,
            },
            &ack.to_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
        if !recorded.contains(&tombstoned) {
            recorded.push(tombstoned);
        }
    }
    Ok(match recorded.first() {
        Some(first) => format!(
            "found=true,tombstoned_device={},count={}",
            &crate::util::text_id::encode_base32_crockford(first)[..16],
            recorded.len()
        ),
        None => "found=false".to_string(),
    })
}
