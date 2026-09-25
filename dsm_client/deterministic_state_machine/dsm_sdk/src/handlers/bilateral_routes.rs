// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral query and calibration route handlers extracted from AppRouterImpl.

use dsm::types::proto as generated;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::relationship_status::{blocked_status, derive_local_send_status_for_device_id};
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
                    // Active AND terminal phases, so the frontend poller can
                    // distinguish real failures from completed transfers.
                    use generated::OfflineBilateralTransactionStatus as Status;
                    let status = match phase {
                        "pending_user_action" => Status::OfflineTxPending,
                        "committed" => Status::OfflineTxConfirmed,
                        "failed" => Status::OfflineTxFailed,
                        "rejected" => Status::OfflineTxRejected,
                        "accepted" | "confirm_pending" | "preparing" | "prepared" => {
                            Status::OfflineTxInProgress
                        }
                        _ => continue,
                    };

                    let (Ok(commitment_hash_arr), Ok(counterparty_device_id_arr)) = (
                        <[u8; 32]>::try_from(s.commitment_hash.as_slice()),
                        <[u8; 32]>::try_from(s.counterparty_device_id.as_slice()),
                    ) else {
                        return err(format!(
                            "bilateral.pending_list: a stored session has a {}-byte commitment \
                             and a {}-byte counterparty id, not 32 and 32",
                            s.commitment_hash.len(),
                            s.counterparty_device_id.len()
                        ));
                    };

                    let (amount, token_id, to_device_id) =
                        match deserialize_operation(&s.operation_bytes) {
                            Ok(dsm::types::operations::Operation::Transfer {
                                amount,
                                token_id,
                                to_device_id,
                                ..
                            }) => (amount.available(), token_id, to_device_id),
                            Ok(other) => {
                                return err(format!(
                                    "bilateral.pending_list: a stored session carries a {} \
                                     operation, not a transfer",
                                    other.get_operation_type()
                                ))
                            }
                            Err(e) => {
                                return err(format!(
                                    "bilateral.pending_list: a stored session's operation \
                                     does not decode: {e}"
                                ))
                            }
                        };

                    let direction = if to_device_id.as_slice() == self.device_id_bytes.as_slice() {
                        "incoming"
                    } else {
                        "outgoing"
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

                    let mut metadata: HashMap<String, String> = HashMap::new();
                    metadata.insert("phase".to_string(), phase.to_string());
                    metadata.insert("direction".to_string(), direction.to_string());
                    metadata.insert("amount".to_string(), amount.to_string());
                    metadata.insert(
                        "token_id".to_string(),
                        String::from_utf8_lossy(&token_id).into_owned(),
                    );
                    if let Some(addr) = s.sender_ble_address.clone() {
                        if !addr.is_empty() {
                            metadata.insert("sender_ble_address".to_string(), addr);
                        }
                    }
                    match get_contact_by_device_id(&counterparty_device_id_arr) {
                        Ok(Some(contact)) if !contact.alias.is_empty() => {
                            metadata.insert("counterparty_alias".to_string(), contact.alias);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            return err(format!(
                                "bilateral.pending_list: counterparty contact unreadable: {e}"
                            ))
                        }
                    }

                    let id = crate::util::text_id::encode_base32_crockford(&commitment_hash_arr);

                    out.push(generated::OfflineBilateralTransaction {
                        id,
                        sender_id,
                        recipient_id,
                        commitment_hash: commitment_hash_arr.to_vec(),
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
    /// (`wallet.sendOffline`).
    ///
    /// Under the finality barrier this is READ-ONLY: it never releases the
    /// pending online gate. Neither the relationship tip reaching the gate's
    /// next tip nor a storage node's acknowledgement is finality; the one
    /// deleter is the post-quorum checkpoint sweep. While a gate is armed this
    /// makes sure the poller is running (it drives the sweep), then reports the
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
}
