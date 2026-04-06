// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral query and calibration route handlers extracted from AppRouterImpl.

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::relationship_status::{
    blocked_status, derive_local_send_status_for_contact, derive_local_send_status_for_device_id,
    status_message,
};
use super::response_helpers::{pack_envelope_ok, err};

use crate::storage::client_db::{
    get_all_bilateral_sessions, get_contact_by_device_id, deserialize_operation,
};
use std::collections::HashMap;

impl AppRouterImpl {
    pub(crate) async fn handle_bilateral_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "bilateral.pending_list" => {
                // Authoritative list of pending bilateral sessions from client_db.
                let sessions = match get_all_bilateral_sessions() {
                    Ok(v) => v,
                    Err(e) => return err(format!("bilateral.pending_list failed: {e}")),
                };

                let mut out: Vec<generated::OfflineBilateralTransaction> = Vec::new();

                for s in sessions {
                    let phase = s.phase.as_str();
                    // Include active AND terminal phases so the frontend poller
                    // can distinguish real failures from completed transfers.
                    if !matches!(
                        phase,
                        "pending_user_action"
                            | "accepted"
                            | "committed"
                            | "failed"
                            | "rejected"
                            | "confirm_pending"
                            | "preparing"
                            | "prepared"
                    ) {
                        continue;
                    }

                    if s.commitment_hash.len() != 32 || s.counterparty_device_id.len() != 32 {
                        continue;
                    }

                    let mut commitment_hash_arr = [0u8; 32];
                    commitment_hash_arr.copy_from_slice(&s.commitment_hash);

                    let mut counterparty_device_id_arr = [0u8; 32];
                    counterparty_device_id_arr.copy_from_slice(&s.counterparty_device_id);

                    let mut amount: Option<u64> = None;
                    let mut token_id: Option<Vec<u8>> = None;
                    let mut to_device_id: Option<Vec<u8>> = None;

                    if let Ok(dsm::types::operations::Operation::Transfer {
                        amount: amt,
                        token_id: tok,
                        to_device_id: to_dev,
                        ..
                    }) = deserialize_operation(&s.operation_bytes)
                    {
                        amount = Some(amt.available());
                        token_id = Some(tok);
                        to_device_id = Some(to_dev);
                    }

                    let direction = if let Some(to_dev) = &to_device_id {
                        if to_dev.len() == 32
                            && to_dev.as_slice() == self.device_id_bytes.as_slice()
                        {
                            "incoming"
                        } else {
                            "outgoing"
                        }
                    } else {
                        "incoming"
                    };

                    let (sender_id, recipient_id) = if direction == "incoming" {
                        (
                            s.counterparty_device_id.clone(),
                            self.device_id_bytes.to_vec(),
                        )
                    } else {
                        (
                            self.device_id_bytes.to_vec(),
                            s.counterparty_device_id.clone(),
                        )
                    };

                    let status = match phase {
                        "pending_user_action" => {
                            generated::OfflineBilateralTransactionStatus::OfflineTxPending
                        }
                        "committed" => {
                            generated::OfflineBilateralTransactionStatus::OfflineTxConfirmed
                        }
                        "failed" => generated::OfflineBilateralTransactionStatus::OfflineTxFailed,
                        "rejected" => {
                            generated::OfflineBilateralTransactionStatus::OfflineTxRejected
                        }
                        _ => generated::OfflineBilateralTransactionStatus::OfflineTxInProgress,
                    };

                    let mut metadata: HashMap<String, String> = HashMap::new();
                    metadata.insert("phase".to_string(), phase.to_string());
                    metadata.insert("direction".to_string(), direction.to_string());
                    metadata.insert("created_at_step".to_string(), s.created_at_step.to_string());
                    if let Some(amt) = amount {
                        metadata.insert("amount".to_string(), amt.to_string());
                    }
                    if let Some(tok) = token_id.clone() {
                        metadata.insert(
                            "token_id".to_string(),
                            String::from_utf8_lossy(&tok).into_owned(),
                        );
                    }
                    if let Some(addr) = s.sender_ble_address.clone() {
                        if !addr.is_empty() {
                            metadata.insert("sender_ble_address".to_string(), addr);
                        }
                    }
                    if let Ok(Some(contact)) = get_contact_by_device_id(&counterparty_device_id_arr)
                    {
                        if !contact.alias.is_empty() {
                            metadata.insert("counterparty_alias".to_string(), contact.alias);
                        }
                    }

                    let id = crate::util::text_id::encode_base32_crockford(&commitment_hash_arr);

                    out.push(generated::OfflineBilateralTransaction {
                        id,
                        sender_id,
                        recipient_id,
                        commitment_hash: commitment_hash_arr.to_vec(),
                        sender_state_hash: vec![0u8; 32],
                        recipient_state_hash: vec![0u8; 32],
                        status: status.into(),
                        metadata,
                    });
                }

                let resp = generated::OfflineBilateralPendingListResponse { transactions: out };
                // NEW: Return as Envelope.offlineBilateralPendingListResponse (field 36)
                pack_envelope_ok(
                    generated::envelope::Payload::OfflineBilateralPendingListResponse(resp),
                )
            }

            other => err(format!("bilateral: unknown route '{other}'")),
        }
    }
}

impl AppRouterImpl {
    fn sync_calibrated_bilateral_cache_tip(
        &self,
        counterparty_device_id: &[u8; 32],
        tip: &[u8; 32],
    ) {
        let counterparty_b32 =
            crate::util::text_id::encode_base32_crockford(counterparty_device_id);
        let tip_b32 = crate::util::text_id::encode_base32_crockford(tip);
        if let Err(e) =
            self.wallet
                .update_bilateral_chain_tip(&counterparty_b32, &tip_b32, &tip_b32, 0)
        {
            log::warn!(
                "[bilateral.reconcile] failed to sync in-memory bilateral cache for {}: {}",
                counterparty_b32.get(..8).unwrap_or("?"),
                e
            );
        }
    }

    async fn configured_storage_endpoints_for_send_calibration(&self) -> Vec<String> {
        match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
            Ok(cfg) if !cfg.node_urls.is_empty() => cfg.node_urls,
            _ => match crate::network::list_storage_endpoints() {
                Ok(endpoints) if !endpoints.is_empty() => endpoints,
                _ => self._config.storage_endpoints.clone(),
            },
        }
    }

    pub(crate) async fn calibrate_local_relationship_send_status(
        &self,
        counterparty_device_id: &[u8],
    ) -> generated::RelationshipSendStatus {
        if counterparty_device_id.len() != 32 {
            return blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!(
                    "Relationship id must be 32 bytes, got {}",
                    counterparty_device_id.len()
                ),
            );
        }

        let mut counterparty = [0u8; 32];
        counterparty.copy_from_slice(counterparty_device_id);

        let contact = match crate::storage::client_db::get_contact_by_device_id(&counterparty) {
            Ok(Some(contact)) => contact,
            Ok(None) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    "Relationship not found",
                )
            }
            Err(e) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to load relationship state: {e}"),
                )
            }
        };

        let pending = match crate::storage::client_db::get_pending_online_outbox(&counterparty) {
            Ok(v) => v,
            Err(e) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to load pending online catch-up state: {e}"),
                )
            }
        };

        let Some(pending) = pending else {
            return derive_local_send_status_for_contact(&contact);
        };

        crate::sdk::inbox_poller::resume_poller();

        let pending_parent: [u8; 32] = match pending.parent_tip.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    "Pending online catch-up parent tip is malformed",
                )
            }
        };
        let pending_next: [u8; 32] = match pending.next_tip.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    "Pending online catch-up next tip is malformed",
                )
            }
        };

        let observed_gate = crate::storage::client_db::bilateral_tip_sync::ObservedPendingGate {
            counterparty_device_id: counterparty,
            parent_tip: pending_parent,
            next_tip: pending_next,
        };

        if crate::storage::client_db::get_contact_chain_tip_raw(&counterparty) == Some(pending_next)
        {
            let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
                counterparty_device_id: counterparty,
                expected_parent_tip: pending_next,
                target_tip: pending_next,
                observed_gate: Some(observed_gate.clone()),
                clear_gate_on_success: true,
            };
            return match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(&request) {
                Ok(
                    crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { new_tip, .. }
                    | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { tip: new_tip, .. }
                    | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { tip: new_tip, .. },
                ) => {
                    self.sync_calibrated_bilateral_cache_tip(&counterparty, &new_tip);
                    derive_local_send_status_for_device_id(&counterparty)
                }
                Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::CanonicalMovedToDifferentTip { current_tip })
                | Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::ParentMismatch { current_tip }) => {
                    blocked_status(
                        generated::RelationshipSendBlockReason::StateDivergence,
                        format!(
                            "Relationship tip changed to {} while clearing a stale online gate",
                            crate::util::text_id::encode_base32_crockford(&current_tip)
                                .get(..8)
                                .unwrap_or("?")
                        ),
                    )
                }
                Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::GateMismatch) => blocked_status(
                    generated::RelationshipSendBlockReason::StateDivergence,
                    "Pending online catch-up gate changed under calibration",
                ),
                Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::InvariantViolation { message }) => blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Relationship calibration invariant failed: {message}"),
                ),
                Err(e) => blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to clear stale online gate: {e}"),
                ),
            };
        }

        let storage_endpoints = self
            .configured_storage_endpoints_for_send_calibration()
            .await;
        if storage_endpoints.is_empty() {
            return blocked_status(
                generated::RelationshipSendBlockReason::PendingCatchup,
                "Waiting for prior transfer to settle",
            );
        }

        let sender_device_id_b32 =
            crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        let mut b0x_sdk = match crate::sdk::b0x_sdk::B0xSDK::new(
            sender_device_id_b32,
            self.core_sdk.clone(),
            storage_endpoints,
        ) {
            Ok(sdk) => sdk,
            Err(e) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to initialize sender inbox status client: {e}"),
                )
            }
        };

        let recipient_caught_up = match b0x_sdk.is_message_acknowledged(&pending.message_id).await {
            Ok(acked) => acked,
            Err(e) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to verify prior transfer status: {e}"),
                )
            }
        };

        if !recipient_caught_up {
            return blocked_status(
                generated::RelationshipSendBlockReason::PendingCatchup,
                "Waiting for prior transfer to settle",
            );
        }

        let request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: counterparty,
            expected_parent_tip: pending_parent,
            target_tip: pending_next,
            observed_gate: Some(observed_gate),
            clear_gate_on_success: true,
        };

        match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(
            &request,
        ) {
            Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { new_tip, .. }
                | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { tip: new_tip, .. }
                | crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { tip: new_tip, .. },
            ) => {
                self.sync_calibrated_bilateral_cache_tip(&counterparty, &new_tip);
                derive_local_send_status_for_device_id(&counterparty)
            }
            Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::CanonicalMovedToDifferentTip {
                    current_tip,
                },
            ) => {
                if let Err(e) = crate::storage::client_db::clear_pending_online_outbox_if_matches(
                    &counterparty,
                    &pending_parent,
                    &pending_next,
                ) {
                    return blocked_status(
                        generated::RelationshipSendBlockReason::InternalError,
                        format!("Failed to clear stale online gate after confirmed catch-up: {e}"),
                    );
                }
                self.sync_calibrated_bilateral_cache_tip(&counterparty, &current_tip);
                derive_local_send_status_for_device_id(&counterparty)
            }
            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::ParentMismatch {
                current_tip,
            }) => blocked_status(
                generated::RelationshipSendBlockReason::StateDivergence,
                format!(
                    "Relationship tip changed to {} while finalizing the prior transfer",
                    crate::util::text_id::encode_base32_crockford(&current_tip)
                        .get(..8)
                        .unwrap_or("?")
                ),
            ),
            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::GateMismatch) => blocked_status(
                generated::RelationshipSendBlockReason::StateDivergence,
                "Pending online catch-up gate changed under calibration",
            ),
            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::InvariantViolation {
                message,
            }) => blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!("Relationship calibration invariant failed: {message}"),
            ),
            Err(e) => blocked_status(
                generated::RelationshipSendBlockReason::InternalError,
                format!("Failed to finalize prior transfer: {e}"),
            ),
        }
    }

    pub(crate) async fn handle_bilateral_reconcile_invoke(&self, i: AppInvoke) -> AppResult {
        use prost::Message;

        let pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("bilateral.reconcile: ArgPack decode failed: {e}")),
        };
        if pack.codec != generated::Codec::Proto as i32 {
            return err("bilateral.reconcile: ArgPack.codec must be PROTO".to_string());
        }

        let req = match generated::BilateralReconciliationRequest::decode(&*pack.body) {
            Ok(r) => r,
            Err(e) => return err(format!("bilateral.reconcile: request decode failed: {e}")),
        };

        let remote_device_id = req.remote_device_id;
        if remote_device_id.len() != 32 {
            return err(format!(
                "bilateral.reconcile: remote_device_id must be 32 bytes, got {}",
                remote_device_id.len()
            ));
        }

        let local_status = self
            .calibrate_local_relationship_send_status(&remote_device_id)
            .await;
        let remote_tip = crate::storage::client_db::get_contact_chain_tip_raw(&remote_device_id)
            .unwrap_or([0u8; 32]);
        let peer_status = None;
        let resp = generated::BilateralReconciliationResponse {
            mismatch_detected: !local_status.send_ready,
            reconciled: local_status.send_ready,
            remote_tip: remote_tip.to_vec(),
            error_message: if local_status.send_ready {
                String::new()
            } else {
                status_message(&local_status)
            },
            local_status: Some(local_status),
            peer_status,
        };
        pack_envelope_ok(generated::envelope::Payload::ReconciliationResponse(resp))
    }
}
