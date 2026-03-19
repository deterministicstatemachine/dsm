// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral query route handlers extracted from AppRouterImpl.
//!
//! Handles `bilateral.pending_list`.

use dsm::types::proto as generated;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
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
                    if !matches!(phase, "pending_user_action" | "accepted") {
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

                    let status = if phase == "pending_user_action" {
                        generated::OfflineBilateralTransactionStatus::OfflineTxPending
                    } else {
                        generated::OfflineBilateralTransactionStatus::OfflineTxInProgress
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
    /// `bilateral.reconcile` — clear the `needs_online_reconcile` flag for a contact.
    ///
    /// Args: `ArgPack` (PROTO codec) wrapping `BilateralReconciliationRequest`.
    /// Response: `AppStateResponse { key: "bilateral.reconcile", value: Some("reconciled") }`.
    pub(crate) async fn handle_bilateral_reconcile_invoke(
        &self,
        i: crate::bridge::AppInvoke,
    ) -> crate::bridge::AppResult {
        use prost::Message;

        // Decode ArgPack wrapper (matches ble.command pattern).
        let pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("bilateral.reconcile: ArgPack decode failed: {e}")),
        };
        if pack.codec != generated::Codec::Proto as i32 {
            return err("bilateral.reconcile: ArgPack.codec must be PROTO".to_string());
        }

        // Decode inner BilateralReconciliationRequest.
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

        // Clear only the needs_online_reconcile flag — do NOT touch the chain tip.
        // Writing a zero tip here would cause the next BLE Prepare to carry
        // sender_chain_tip=0000… and be rejected by the receiver with TipMismatch.
        if let Err(e) = crate::storage::client_db::clear_contact_reconcile_flag(&remote_device_id) {
            log::warn!(
                "[bilateral.reconcile] could not clear reconcile flag for {:02x}{:02x}..: {e}",
                remote_device_id[0],
                remote_device_id[1]
            );
        }

        log::info!(
            "[bilateral.reconcile] cleared flag for {:02x}{:02x}..",
            remote_device_id[0],
            remote_device_id[1]
        );

        let resp = generated::AppStateResponse {
            key: "bilateral.reconcile".to_string(),
            value: Some("reconciled".to_string()),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}
