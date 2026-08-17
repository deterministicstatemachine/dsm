// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral query and calibration route handlers extracted from AppRouterImpl.

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::relationship_status::{
    blocked_status, derive_local_send_status_for_device_id, status_message,
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
    /// The send-status calibration a UI or the offline-send path asks for
    /// (`bilateral.reconcile` / `wallet.sendOffline`).
    ///
    /// Under the finality barrier this is READ-ONLY: it never releases the
    /// pending online gate. Historically it cleared the gate on two signals —
    /// `contacts.chain_tip == gate.next` and a storage-node "message
    /// acknowledged" answer — both of which are transport/projection facts, not
    /// finality: the tip equality is simply the normal
    /// `finalization_checkpoint_pending` state now, and an ACK proves only that
    /// the recipient consumed its spool copy. The ONE deleter is the
    /// post-quorum checkpoint sweep. What remains here: while a gate is armed,
    /// make sure the poller is running (it drives the sweep), then report the
    /// authority's status.
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
        match crate::storage::client_db::get_pending_online_outbox(counterparty_device_id) {
            Ok(Some(_)) => crate::sdk::inbox_poller::resume_poller(),
            Ok(None) => {}
            Err(e) => {
                return blocked_status(
                    generated::RelationshipSendBlockReason::InternalError,
                    format!("Failed to load pending online catch-up state: {e}"),
                )
            }
        }
        derive_local_send_status_for_device_id(counterparty_device_id)
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
