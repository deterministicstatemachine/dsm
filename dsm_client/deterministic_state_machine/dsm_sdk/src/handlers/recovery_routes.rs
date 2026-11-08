// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recovery route handlers for AppRouterImpl.
//!
//! Handles the `recovery.*` query and invoke routes of the device recovery
//! pipeline: the phase and the sync gate, then tombstone, succession,
//! propagation, acknowledgements, resume, activation and dBTC reconciliation.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for `recovery.*` query routes.
    pub(crate) async fn handle_recovery_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
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
                match handler.handle_recovery_tombstone(req) {
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
                match handler.handle_recovery_succession(req) {
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
                // Recovery can't resume until ALL contacts have acknowledged the
                // tombstone; a gate that cannot be read holds it back too.
                if let Err(e) = super::recovery_impl::resume_gate() {
                    return err(format!("recovery.resume: {e}"));
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
                match handler.handle_recovery_resume(req) {
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
            // recovery authority the tombstoned device anchored, recorded and
            // acknowledged.
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
                if let Err(e) = super::recovery_impl::complete_resume() {
                    return err(format!("recovery.completeResume: {e}"));
                }
                let resp = generated::AppStateResponse {
                    key: "recovery.completeResume".to_string(),
                    value: Some("success=true".to_string()),
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
        // Anyone can write the cell: a notice counts only once its tombstone
        // verifies under the recovery authority the tombstoned device anchored
        // under the genesis this device pinned for it. The tombstone is signed
        // under K_A, never under that device's AK (SA-117).
        let Ok(notice) = dsm::recovery::RecoverySuccessionProof::from_bytes(&bytes) else {
            continue;
        };
        let tombstoned =
            match crate::sdk::recovery_sdk::RecoverySDK::predecessor_anchoring(&notice).await {
                Ok(tombstoned) => tombstoned,
                Err(e) => {
                    log::info!("[RECOVERY] a tombstone notice is passed over: {e}");
                    continue;
                }
            };
        let (receipt, ak) = (notice.tombstone, notice.authority_pubkey);
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
