// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral query and calibration route handlers extracted from AppRouterImpl.

use dsm::types::proto as generated;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::relationship_status::{blocked_status, derive_local_send_status_for_device_id};
use super::response_helpers::{pack_envelope_ok, err};

use super::wallet_routes::{format_base_units_for_display, token_decimals};
use crate::bluetooth::bilateral_session;
use crate::storage::client_db::{
    get_all_bilateral_sessions, get_contact_by_device_id, deserialize_operation,
};

impl AppRouterImpl {
    pub(crate) async fn handle_bilateral_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "bilateral.pending_list" => {
                // Authoritative list of this device's bilateral sessions from client_db.
                let sessions = match get_all_bilateral_sessions() {
                    Ok(v) => v,
                    Err(e) => return err(format!("bilateral.pending_list failed: {e}")),
                };

                let mut out: Vec<generated::OfflineBilateralTransaction> = Vec::new();

                for s in sessions {
                    // Active AND terminal phases, so the frontend poller can
                    // distinguish real failures from completed transfers.
                    let phase = match bilateral_session::phase_from_str(&s.phase) {
                        Ok(phase) => phase,
                        Err(e) => return err(format!("bilateral.pending_list: {e}")),
                    };
                    let wire_phase = {
                        use bilateral_session::BilateralPhase as P;
                        use generated::OfflineBilateralPhase as W;
                        match phase {
                            P::Preparing => W::OfflinePhasePreparing,
                            P::Prepared => W::OfflinePhasePrepared,
                            P::PendingUserAction => W::OfflinePhasePendingUserAction,
                            P::Accepted => W::OfflinePhaseAccepted,
                            P::Rejected => W::OfflinePhaseRejected,
                            P::ConfirmPending => W::OfflinePhaseConfirmPending,
                            P::Committed => W::OfflinePhaseCommitted,
                            P::Failed => W::OfflinePhaseFailed,
                        }
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
                    let token_id = match String::from_utf8(token_id) {
                        Ok(token_id) => token_id,
                        Err(e) => {
                            return err(format!(
                                "bilateral.pending_list: a stored session's token id is not \
                                 text: {e}"
                            ))
                        }
                    };

                    use generated::OfflineBilateralDirection as Direction;
                    let (direction, sender_id, recipient_id) =
                        if to_device_id.as_slice() == self.device_id_bytes.as_slice() {
                            (
                                Direction::OfflineDirectionIncoming,
                                s.counterparty_device_id.clone(),
                                self.device_id_bytes.to_vec(),
                            )
                        } else {
                            (
                                Direction::OfflineDirectionOutgoing,
                                self.device_id_bytes.to_vec(),
                                s.counterparty_device_id.clone(),
                            )
                        };

                    // Rendered as a bilateral event renders it: a token whose
                    // decimals this device does not know carries only its
                    // base-unit amount.
                    let display_amount = match token_decimals(&token_id) {
                        Ok(decimals) => Some(format_base_units_for_display(amount, decimals)),
                        Err(e) => {
                            log::warn!("bilateral.pending_list {token_id}: no display amount: {e}");
                            None
                        }
                    };

                    let counterparty_alias =
                        match get_contact_by_device_id(&counterparty_device_id_arr) {
                            Ok(Some(contact)) if !contact.alias.is_empty() => Some(contact.alias),
                            Ok(_) => None,
                            Err(e) => {
                                return err(format!(
                                    "bilateral.pending_list: counterparty contact unreadable: {e}"
                                ))
                            }
                        };

                    let id = crate::util::text_id::encode_base32_crockford(&commitment_hash_arr);

                    out.push(generated::OfflineBilateralTransaction {
                        id,
                        sender_id,
                        recipient_id,
                        commitment_hash: commitment_hash_arr.to_vec(),
                        phase: wire_phase.into(),
                        direction: direction.into(),
                        amount,
                        display_amount,
                        token_id,
                        counterparty_alias,
                        sender_ble_address: s.sender_ble_address.filter(|a| !a.is_empty()),
                        // The rule `cancel_proposal` enforces, stated where
                        // the UI reads it.
                        cancellable: bilateral_session::is_cancellable_proposal_phase(&phase),
                    });
                }

                let resp = generated::OfflineBilateralPendingListResponse { transactions: out };
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

#[cfg(test)]
mod pending_list_tests {
    use crate::bridge::{AppQuery, AppRouter};
    use crate::storage::client_db::{store_bilateral_session, BilateralSessionRecord};
    use dsm::types::operations::{Operation, TransactionMode};
    use dsm::types::proto as generated;

    /// A stored outgoing transfer step to `peer` in `phase`. The list reads
    /// the step's phase, direction, amount and token and verifies nothing,
    /// so the operation here is unsigned.
    fn outgoing(peer: [u8; 32], commitment: [u8; 32], phase: &str) -> BilateralSessionRecord {
        let operation = Operation::Transfer {
            to_device_id: peer.to_vec(),
            amount: dsm::types::token_types::Balance::amount(3),
            token_id: b"ERA".to_vec(),
            policy_commit: dsm::core::token::token_state_manager::era_policy_commit(),
            mode: TransactionMode::Bilateral,
            nonce: commitment[..16].to_vec(),
            recipient: peer.to_vec(),
            to: peer.to_vec(),
            message: String::new(),
            signature: Vec::new(),
            authority_policy: None,
        };
        BilateralSessionRecord {
            commitment_hash: commitment.to_vec(),
            counterparty_device_id: peer.to_vec(),
            counterparty_genesis_hash: None,
            operation_bytes: crate::storage::codecs::serialize_operation(&operation),
            phase: phase.to_string(),
            local_signature: None,
            counterparty_signature: None,
            sender_ble_address: None,
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            parent_tip: None,
            receiver_challenge: None,
            sent_child_root: None,
            anchor_leaf_key: None,
            anchor_leaf_value: None,
            spend_anchor_bundle: None,
            spend_asset: None,
            spend_amount: None,
            owed_frame: None,
        }
    }

    async fn pending_list(
        device: &crate::test_support::one_device::Device,
    ) -> Result<generated::OfflineBilateralPendingListResponse, String> {
        let answer = device
            .router
            .query(AppQuery {
                path: "bilateral.pending_list".to_string(),
                params: Vec::new(),
            })
            .await;
        if !answer.success {
            return Err(answer.error_message.unwrap_or_default());
        }
        let env = crate::handlers::response_helpers::decode_local_envelope(&answer.data)
            .expect("a local envelope");
        match env.payload {
            Some(generated::envelope::Payload::OfflineBilateralPendingListResponse(list)) => {
                Ok(list)
            }
            Some(generated::envelope::Payload::Error(e)) => Err(e.message),
            other => panic!("bilateral.pending_list answered {other:?}"),
        }
    }

    /// The pending list states each step as its session holds it, and offers
    /// a step for cancelling exactly when `cancel_proposal` would cancel it:
    /// before its confirm. A confirmed step is listed without the offer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn only_an_unconfirmed_proposal_is_offered_for_cancelling() {
        let device = crate::test_support::one_device::Device::start(0x73).await;
        let peer = [0x74u8; 32];
        store_bilateral_session(&outgoing(peer, [0xA1; 32], "prepared")).expect("store");
        store_bilateral_session(&outgoing(peer, [0xA2; 32], "confirm_pending")).expect("store");

        let list = pending_list(&device).await.expect("the list");
        let step = |commitment: [u8; 32]| {
            list.transactions
                .iter()
                .find(|t| t.commitment_hash == commitment.to_vec())
                .cloned()
                .expect("the step is listed")
        };

        let prepared = step([0xA1; 32]);
        assert_eq!(
            prepared.phase(),
            generated::OfflineBilateralPhase::OfflinePhasePrepared
        );
        assert_eq!(
            prepared.direction(),
            generated::OfflineBilateralDirection::OfflineDirectionOutgoing
        );
        assert_eq!(prepared.recipient_id, peer.to_vec());
        assert_eq!((prepared.amount, prepared.token_id.as_str()), (3, "ERA"));
        assert_eq!(prepared.display_amount.as_deref(), Some("3"));
        assert!(prepared.cancellable, "an unconfirmed proposal is offered");

        let confirmed = step([0xA2; 32]);
        assert_eq!(
            confirmed.phase(),
            generated::OfflineBilateralPhase::OfflinePhaseConfirmPending
        );
        assert!(!confirmed.cancellable, "a confirmed step is not offered");
    }

    /// A stored step whose phase the SDK does not name is not left out of the
    /// list: the list refuses, naming the phase. The writer refuses such a
    /// phase, so the row is written past it, as a damaged database holds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_step_in_an_unnamed_phase_is_not_left_out_of_the_list() {
        let device = crate::test_support::one_device::Device::start(0x75).await;
        store_bilateral_session(&outgoing([0x76; 32], [0xA3; 32], "prepared")).expect("store");
        {
            let conn = crate::storage::client_db::get_connection().expect("the database");
            let conn = conn.lock().expect("the connection");
            let changed = conn
                .execute(
                    "UPDATE bilateral_sessions SET phase = 'half_sent' WHERE commitment_hash = ?1",
                    rusqlite::params![[0xA3u8; 32].to_vec()],
                )
                .expect("raw update");
            assert_eq!(changed, 1);
        }

        let refusal = pending_list(&device).await.expect_err("the list refuses");
        assert!(refusal.contains("half_sent"), "{refusal}");
    }
}
