//! BLE Bilateral Transaction Handler
//!
//! Implements the complete offline bilateral transaction protocol over Bluetooth Low Energy:
//! 1. Prepare phase: Create pre-commitments with validity windows
//! 2. Accept phase: Counterparty accepts/rejects the commitment
//! 3. Commit phase: Both parties finalize with dual signatures
//!
//! All messages use protobuf envelopes for deterministic serialization.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use log::{debug, info, warn, error};
use prost::Message;
use tokio::sync::RwLock;

#[cfg(all(target_os = "android", feature = "jni"))]
use crate::jni::state::DEVICE_ID_TO_ADDR;

// Re-export types from bilateral_session so existing import paths still work.
pub use super::bilateral_session::{
    BilateralBleSession, BilateralEventCallback, BilateralPhase, BilateralSettlementContext,
    BilateralSettlementDelegate, BilateralSettlementOutcome, SessionStore, is_inflight_phase,
    phase_to_str, phase_from_str, MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY,
};

/// Base32 Crockford encoding helper for logging
fn bytes_to_base32(bytes: &[u8]) -> String {
    crate::util::text_id::encode_base32_crockford(bytes)
}

use dsm::core::bilateral_transaction_manager::{
    compute_precommit, compute_successor_tip, BilateralTransactionManager,
};
// core::security module deleted (heuristic attack detectors obsolete under §2.2/§4.3).
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::generated;
// BcrStorage removed with the security module delete.
use crate::storage::client_db::{
    store_bilateral_session, get_all_bilateral_sessions, delete_bilateral_session,
    BilateralSessionRecord,
};

fn option_string_or_default(opt: Option<String>, default: &str) -> String {
    match opt {
        Some(s) if !s.is_empty() => s,
        _ => default.to_string(),
    }
}

fn sdk_send_status_from_router_status(
    status: dsm::types::proto::RelationshipSendStatus,
) -> generated::RelationshipSendStatus {
    generated::RelationshipSendStatus {
        send_ready: status.send_ready,
        send_check_state: status.send_check_state,
        send_block_reason: status.send_block_reason,
        send_block_message: status.send_block_message,
    }
}

/// Derive the local device-tree commitment for receipt construction (§2.3).
///
/// Primary source: `AppState::get_device_tree_commitment()` which is set during
/// SDK initialisation via `set_identity_info`.  Fall-back: compute directly from
/// `device_id` using a single-device Merkle tree.  For the single-device case
/// these are identical, so the fall-back is always correct.
///
/// Using the fall-back instead of returning `None` ensures BLE bilateral receipts
/// can always be built even when AppState has not yet been fully populated (e.g.,
/// on a fresh app start before the first storage.sync completes).  Without this,
/// `build_bilateral_receipt_with_smt` returns `None` → `proof_data` in the
/// settlement context is `None` → settlement fails → receiver balance and history
/// are never updated.
fn local_device_tree_commitment(
    device_id: &[u8; 32],
) -> dsm::types::receipt_types::DeviceTreeAcceptanceCommitment {
    crate::sdk::app_state::AppState::get_device_tree_commitment().unwrap_or_else(|| {
        let root = dsm::common::device_tree::DeviceTree::single(*device_id).root();
        dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(root)
    })
}

/// Bilateral BLE transaction coordinator
pub struct BilateralBleHandler {
    bilateral_tx_manager: Arc<RwLock<BilateralTransactionManager>>,
    sessions: SessionStore,
    device_id: [u8; 32],
    event_callback: Option<BilateralEventCallback>,
    /// Per-Device SMT for relationship chain tips (§2.2, §4.3).
    /// Shared singleton — same instance is used by both BLE and online transfer paths.
    per_device_smt: Arc<RwLock<dsm::merkle::sparse_merkle_tree::SparseMerkleTree>>,
    /// Application-layer settlement delegate.  Handles all token- and
    /// balance-specific logic so the transport layer stays coin-agnostic.
    settlement_delegate: Option<Arc<dyn BilateralSettlementDelegate>>,
}

impl BilateralBleHandler {
    pub async fn transition_session_to_failed(&self, commitment_hash: &[u8; 32]) {
        let pending_key = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(mut session) = sessions.remove(commitment_hash) {
                session.phase = BilateralPhase::Failed;
                session.local_commitment_hash.unwrap_or(*commitment_hash)
            } else {
                *commitment_hash
            }
        };
        // Keep failed sessions in SQLite so bilateral.pending_list can return
        // terminal status to the frontend poller. Only committed sessions are deleted.
        if let Err(e) =
            crate::storage::client_db::update_bilateral_session_phase(commitment_hash, "failed")
        {
            warn!(
                "[BLE_HANDLER] Failed to update session phase to failed: {}",
                e
            );
        }
        let mut mgr = self.bilateral_tx_manager.write().await;
        let _ = mgr.remove_pending_commitment(&pending_key);
    }

    pub async fn transition_session_to_rejected(&self, commitment_hash: &[u8; 32]) {
        let pending_key = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(mut session) = sessions.remove(commitment_hash) {
                session.phase = BilateralPhase::Rejected;
                session.local_commitment_hash.unwrap_or(*commitment_hash)
            } else {
                *commitment_hash
            }
        };
        // Keep rejected sessions in SQLite for same reason as failed.
        if let Err(e) =
            crate::storage::client_db::update_bilateral_session_phase(commitment_hash, "rejected")
        {
            warn!(
                "[BLE_HANDLER] Failed to update session phase to rejected: {}",
                e
            );
        }
        let mut mgr = self.bilateral_tx_manager.write().await;
        let _ = mgr.remove_pending_commitment(&pending_key);
    }

    pub async fn transition_session_to_committed(&self, commitment_hash: &[u8; 32]) {
        let pending_key = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(mut session) = sessions.remove(commitment_hash) {
                session.phase = BilateralPhase::Committed;
                session.local_commitment_hash.unwrap_or(*commitment_hash)
            } else {
                *commitment_hash
            }
        };
        let _ = crate::storage::client_db::delete_bilateral_session(commitment_hash);
        let mut mgr = self.bilateral_tx_manager.write().await;
        let _ = mgr.remove_pending_commitment(&pending_key);
    }

    pub fn new(
        bilateral_tx_manager: Arc<RwLock<BilateralTransactionManager>>,
        device_id: [u8; 32],
    ) -> Self {
        // Use the shared Per-Device SMT singleton (initialized during SDK bootstrap).
        // Falls back to a fresh instance if bootstrap hasn't run yet (e.g. tests).
        let per_device_smt = Arc::new(RwLock::new(
            dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256),
        ));
        Self {
            bilateral_tx_manager,
            sessions: SessionStore::new(),
            device_id,
            event_callback: None,
            per_device_smt,
            settlement_delegate: None,
        }
    }

    /// Create a handler with an explicit Per-Device SMT instance.
    ///
    /// Each physical device maintains its own Per-Device SMT (§2.2).  In
    /// production the process-wide singleton is correct because one process = one
    /// device.  In integration tests where two "devices" run in the same process,
    /// each handler MUST receive its own SMT so that leaf updates on device A do
    /// not corrupt device B's Merkle root.
    pub fn new_with_smt(
        bilateral_tx_manager: Arc<RwLock<BilateralTransactionManager>>,
        device_id: [u8; 32],
        per_device_smt: Arc<RwLock<dsm::merkle::sparse_merkle_tree::SparseMerkleTree>>,
    ) -> Self {
        Self {
            bilateral_tx_manager,
            sessions: SessionStore::new(),
            device_id,
            event_callback: None,
            per_device_smt,
            settlement_delegate: None,
        }
    }

    /// Install the application-layer settlement delegate.
    ///
    /// Must be called before the first bilateral transfer.  The delegate
    /// receives completed-transfer contexts and applies all token-specific
    /// business logic (balance updates, transaction history, wallet cache
    /// synchronisation).
    pub fn set_settlement_delegate(&mut self, delegate: Arc<dyn BilateralSettlementDelegate>) {
        self.settlement_delegate = Some(delegate);
    }

    /// Set the event callback for bilateral transaction notifications
    pub fn set_event_callback(&mut self, callback: BilateralEventCallback) {
        self.event_callback = Some(callback);
    }

    /// Add a verified contact to the internal bilateral transaction manager.
    /// This is required for the BLE handler to accept BilateralPrepare requests from this contact.
    pub async fn add_verified_contact(
        &self,
        contact: dsm::types::contact_types::DsmVerifiedContact,
    ) -> Result<(), DsmError> {
        log::warn!(
            "[BilateralBleHandler] Adding verified contact: alias={}, device_id={}",
            contact.alias,
            dsm::core::utility::labeling::hash_to_short_id(&contact.device_id)
        );
        let mut mgr = self.bilateral_tx_manager.write().await;
        let result = mgr.add_verified_contact(contact);
        if result.is_ok() {
            log::warn!("[BilateralBleHandler] ✅ Contact added successfully");
        } else {
            log::error!(
                "[BilateralBleHandler] ❌ Failed to add contact: {:?}",
                result
            );
        }
        result
    }

    /// Check if a contact exists in the internal bilateral transaction manager
    pub async fn has_verified_contact(&self, device_id: &[u8; 32]) -> bool {
        let mgr = self.bilateral_tx_manager.read().await;
        mgr.has_verified_contact(device_id)
    }

    /// Get the local signing public key for inclusion in outbound BilateralPrepare requests
    pub async fn local_signing_public_key(&self) -> Vec<u8> {
        let mgr = self.bilateral_tx_manager.read().await;
        mgr.local_signing_public_key()
    }

    /// Emit a bilateral event notification to the frontend
    fn emit_event(&self, event: &generated::BilateralEventNotification) {
        if let Some(ref callback) = self.event_callback {
            callback(&event.encode_to_vec());
        }
    }

    // record_bcr_state(...) deleted: per §2.2/§4.3, canonical state is the
    // per-relationship chain state + Per-Device SMT root. The BLE handler
    // MUST NOT write a duplicate snapshot from a derived settlement-time
    // State.
    //
    // Note: the BLE bilateral path advances the relationship chain via
    // `BilateralTransactionManager::finalize_offline_transfer_with_entropy`
    /// Reject an incoming prepare (or any active session) identified by the origin commitment hash.
    pub async fn reject_incoming_prepare(
        &self,
        origin_commitment_hash: [u8; 32],
        counterparty_device_id: [u8; 32],
        reason: Option<String>,
    ) -> Result<(), DsmError> {
        let mut sessions = self.sessions.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&origin_commitment_hash) {
            session.phase = BilateralPhase::Rejected;
            let pending_key = session
                .local_commitment_hash
                .unwrap_or(origin_commitment_hash);
            drop(sessions);

            // Emit rejection event to frontend for deterministic UI/test behavior.
            // (If no callback is installed, this is a no-op.)
            let msg = option_string_or_default(reason.clone(), "rejected");
            self.emit_event(&generated::BilateralEventNotification {
                event_type: generated::BilateralEventType::BilateralEventRejected.into(),
                counterparty_device_id: counterparty_device_id.to_vec(),
                commitment_hash: origin_commitment_hash.to_vec(),
                transaction_hash: None,
                amount: None,
                token_id: None,
                status: "rejected".to_string(),
                message: msg,
                sender_ble_address: None,
                failure_reason: Some(
                    generated::BilateralFailureReason::FailureReasonRejectedByPeer.into(),
                ),
            });

            // Remove any pending commitment in the core manager keyed by this hash
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                mgr.remove_pending_commitment(&pending_key);
            }

            // Persist rejected phase (keep session visible for frontend poller)
            if let Err(e) = crate::storage::client_db::update_bilateral_session_phase(
                &origin_commitment_hash,
                "rejected",
            ) {
                warn!(
                    "[BLE_HANDLER] Failed to update session phase to rejected: {}",
                    e
                );
            }

            self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                .await;

            info!(
                "[BLE_HANDLER] Rejected bilateral session origin={} for counterparty {} reason={:?}",
                bytes_to_base32(&origin_commitment_hash[..8]),
                bytes_to_base32(&counterparty_device_id[..8]),
                reason
            );
        } else {
            info!(
                "[BLE_HANDLER] reject_incoming_prepare: no active session found for origin={} (already cleaned up?)",
                bytes_to_base32(&origin_commitment_hash[..8])
            );
        }

        Ok(())
    }

    /// Create a reject response envelope for an incoming prepare.
    /// Returns serialized Envelope with BilateralPrepareReject payload.
    pub async fn create_prepare_reject_envelope(
        &self,
        commitment_hash: [u8; 32],
        counterparty_device_id: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        // Mark session rejected
        self.reject_incoming_prepare(
            commitment_hash,
            counterparty_device_id,
            Some(reason.clone()),
        )
        .await?;

        let send_status =
            crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                &counterparty_device_id,
            );
        let send_status = if send_status.send_ready {
            crate::handlers::relationship_status::blocked_status(
                dsm::types::proto::RelationshipSendBlockReason::StateDivergence,
                reason.clone(),
            )
        } else {
            send_status
        };
        let send_status = sdk_send_status_from_router_status(send_status);

        // Build reject message
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            reason: reason.clone(),
            rejector_device_id: self.device_id.to_vec(),
            send_status: Some(send_status),
        };

        // Wrap in envelope with per-relationship chain tip
        let tip_override = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
        };
        let envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::BilateralPrepareReject(reject),
                tip_override,
            )
            .await?;

        let mut buffer = Vec::new();
        envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error(
                "encode_prepare_reject",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        info!("Bilateral prepare reject envelope created");
        Ok(buffer)
    }

    /// Public helper to query a session's current phase (for tests / diagnostics)
    pub async fn get_session_phase(&self, commitment_hash: &[u8; 32]) -> Option<BilateralPhase> {
        let sessions = self.sessions.sessions.lock().await;
        sessions.get(commitment_hash).map(|s| s.phase.clone())
    }

    fn session_from_persisted_record(
        &self,
        record: &BilateralSessionRecord,
    ) -> Result<BilateralBleSession, DsmError> {
        let commitment_hash: [u8; 32] =
            record.commitment_hash.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation(
                    "persisted bilateral session commitment_hash must be 32 bytes",
                )
            })?;
        let counterparty_device_id: [u8; 32] = record
            .counterparty_device_id
            .as_slice()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation(
                    "persisted bilateral session counterparty_device_id must be 32 bytes",
                )
            })?;
        let counterparty_genesis_hash = match record.counterparty_genesis_hash.as_deref() {
            Some(bytes) => Some(bytes.try_into().map_err(|_| {
                DsmError::invalid_operation(
                    "persisted bilateral session counterparty_genesis_hash must be 32 bytes",
                )
            })?),
            None => None,
        };
        let operation = crate::storage::client_db::deserialize_operation(&record.operation_bytes)
            .map_err(|e| {
            DsmError::serialization_error(
                "recover_sender_commit_from_storage",
                "operation_bytes",
                Some(e.to_string()),
                None::<std::io::Error>,
            )
        })?;

        Ok(BilateralBleSession {
            commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash,
            operation,
            phase: phase_from_str(&record.phase),
            local_signature: record.local_signature.clone(),
            counterparty_signature: record.counterparty_signature.clone(),
            created_at_ticks: record.created_at_step,
            expires_at_ticks: u64::MAX,
            sender_ble_address: record.sender_ble_address.clone(),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        })
    }

    fn validate_persisted_restore_record(
        &self,
        record: &BilateralSessionRecord,
    ) -> Result<(), DsmError> {
        if record.commitment_hash.len() != 32 {
            return Err(DsmError::invalid_operation(format!(
                "persisted bilateral session commitment_hash must be 32 bytes (got {})",
                record.commitment_hash.len()
            )));
        }
        if record.counterparty_device_id.len() != 32 {
            return Err(DsmError::invalid_operation(format!(
                "persisted bilateral session counterparty_device_id must be 32 bytes (got {})",
                record.counterparty_device_id.len()
            )));
        }
        if let Some(counterparty_genesis_hash) = record.counterparty_genesis_hash.as_ref() {
            if counterparty_genesis_hash.len() != 32 {
                return Err(DsmError::invalid_operation(format!(
                    "persisted bilateral session counterparty_genesis_hash must be 32 bytes (got {})",
                    counterparty_genesis_hash.len()
                )));
            }
        }
        if record.operation_bytes.is_empty() {
            return Err(DsmError::invalid_operation(
                "persisted bilateral session operation_bytes cannot be empty",
            ));
        }
        if !matches!(
            record.phase.as_str(),
            "prepare"
                | "accept"
                | "commit"
                | "preparing"
                | "prepared"
                | "pending_user_action"
                | "accepted"
                | "rejected"
                | "confirm_pending"
                | "committed"
                | "failed"
        ) {
            return Err(DsmError::invalid_operation(format!(
                "persisted bilateral session has unsupported phase '{}'",
                record.phase
            )));
        }
        Ok(())
    }

    async fn recover_sender_commit_from_storage(
        &self,
        commitment_hash: [u8; 32],
        post_state_hash: [u8; 32],
    ) -> Result<Option<crate::sdk::transfer_hooks::TransferMeta>, DsmError> {
        let Some(record) = crate::storage::client_db::get_bilateral_session(&commitment_hash)
            .map_err(|e| {
                DsmError::invalid_operation(format!(
                    "failed to load persisted bilateral session: {e}"
                ))
            })?
        else {
            return Ok(None);
        };

        let Some((persisted_counterparty_device_id, confirm_envelope)) =
            crate::storage::client_db::get_pending_confirm_delivery(&commitment_hash).map_err(
                |e| {
                    DsmError::invalid_operation(format!(
                        "failed to load persisted confirm envelope: {e}"
                    ))
                },
            )?
        else {
            return Ok(None);
        };

        let session = self.session_from_persisted_record(&record)?;
        if persisted_counterparty_device_id.as_slice() != session.counterparty_device_id {
            return Err(DsmError::invalid_operation(
                "persisted confirm envelope counterparty mismatch",
            ));
        }

        let confirm_message =
            generated::Envelope::decode(confirm_envelope.as_slice()).map_err(|e| {
                DsmError::serialization_error(
                    "decode_persisted_confirm_envelope",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
        let confirm_request = self.extract_confirm_request(&confirm_message)?;

        let shared_chain_tip_new: [u8; 32] = confirm_request
            .shared_chain_tip_new
            .as_ref()
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "persisted confirm envelope missing shared_chain_tip_new",
                )
            })?
            .v
            .as_slice()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation(
                    "persisted confirm envelope shared_chain_tip_new must be 32 bytes",
                )
            })?;

        let receipt = generated::ReceiptCommit::decode(confirm_request.stitched_receipt.as_slice())
            .map_err(|e| {
                DsmError::serialization_error(
                    "decode_persisted_confirm_receipt",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
        let expected_parent_tip: [u8; 32] =
            receipt.parent_tip.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("persisted confirm receipt parent_tip must be 32 bytes")
            })?;
        let receipt_child_tip: [u8; 32] =
            receipt.child_tip.as_slice().try_into().map_err(|_| {
                DsmError::invalid_operation("persisted confirm receipt child_tip must be 32 bytes")
            })?;
        if receipt_child_tip != shared_chain_tip_new {
            return Err(DsmError::invalid_operation(
                "persisted confirm receipt child_tip mismatch",
            ));
        }

        let tip_sync_request = crate::storage::client_db::bilateral_tip_sync::TipSyncRequest {
            counterparty_device_id: session.counterparty_device_id,
            expected_parent_tip,
            target_tip: shared_chain_tip_new,
            observed_gate: None,
            clear_gate_on_success: false,
        };

        match crate::storage::client_db::bilateral_tip_sync::sync_bilateral_tips_atomically(
            &tip_sync_request,
        ) {
            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::Advanced { .. })
            | Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::RepairedAtTarget { .. },
            )
            | Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::AlreadyAtTarget { .. },
            ) => {}
            Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::ParentMismatch {
                    current_tip,
                },
            )
            | Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::CanonicalMovedToDifferentTip {
                    current_tip,
                },
            ) => {
                let _ = crate::storage::client_db::mark_contact_needs_online_reconcile(
                    &session.counterparty_device_id,
                );
                return Err(DsmError::invalid_operation(format!(
                    "sender recovery tip sync rejected: expected_parent={} current_tip={}",
                    bytes_to_base32(&expected_parent_tip[..8]),
                    bytes_to_base32(&current_tip[..8])
                )));
            }
            Ok(crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::GateMismatch) => {
                return Err(DsmError::invalid_operation(
                    "sender recovery tip sync encountered an unexpected gate mismatch",
                ));
            }
            Ok(
                crate::storage::client_db::bilateral_tip_sync::TipSyncOutcome::InvariantViolation {
                    message,
                },
            ) => {
                return Err(DsmError::invalid_operation(format!(
                    "sender recovery tip sync invariant violation: {message}"
                )));
            }
            Err(e) => {
                return Err(DsmError::invalid_operation(format!(
                    "sender recovery tip sync failed: {e}"
                )));
            }
        }

        if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
            &session.counterparty_device_id,
            &post_state_hash,
            crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
        ) {
            warn!(
                "[BILATERAL RECOVERY] Failed to persist observed receiver post_state_hash: {}",
                e
            );
        }

        let op_bytes = session.operation.to_bytes();
        let (event_amount_opt, event_token_id_opt) =
            if let Some(ref delegate) = self.settlement_delegate {
                delegate.operation_metadata(&op_bytes)
            } else {
                (None, None)
            };

        let _settlement_outcome = if let Some(ref delegate) = self.settlement_delegate {
            // Settlement reads the canonical DeviceState head from the bridge
            // and writes the SQLite display projection + transaction history.
            // The recovery path skips the device-head balance delta (the
            // post-restart restore from the BCR head cache already includes
            // the post-finalize balances).
            delegate
                .settle(BilateralSettlementContext {
                    local_device_id: self.device_id,
                    counterparty_device_id: session.counterparty_device_id,
                    commitment_hash,
                    transaction_hash: commitment_hash,
                    operation_bytes: op_bytes.clone(),
                    proof_data: None,
                    is_sender: true,
                    tx_type: "bilateral_offline_recovered",
                    new_chain_tip: shared_chain_tip_new,
                })
                .map_err(|e| {
                    DsmError::invalid_operation(format!("sender recovery settlement failed: {e}"))
                })?
        } else {
            BilateralSettlementOutcome::default()
        };

        if let Some(router) = crate::bridge::app_router() {
            router.sync_balance_cache();
        }

        {
            let mut sessions = self.sessions.sessions.lock().await;
            sessions.remove(&commitment_hash);
        }
        {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager.advance_chain_tip(&session.counterparty_device_id, shared_chain_tip_new);
            let _ = manager.remove_pending_commitment(&commitment_hash);
        }

        if let Err(e) = delete_bilateral_session(&commitment_hash) {
            warn!(
                "[BILATERAL RECOVERY] Failed to delete completed session from storage: {}",
                e
            );
        }

        self.prune_terminal_sessions_for_counterparty(&session.counterparty_device_id)
            .await;
        self.clear_pending_confirm_delivery(&commitment_hash);

        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: Some(commitment_hash.to_vec()),
            amount: event_amount_opt,
            token_id: event_token_id_opt.clone(),
            status: "recovered".to_string(),
            message: "Bilateral transfer recovered from persisted confirm state".to_string(),
            sender_ble_address: None,
            failure_reason: None,
        });

        Ok(Some(crate::sdk::transfer_hooks::TransferMeta {
            token_id: event_token_id_opt.unwrap_or_default(),
            amount: event_amount_opt.unwrap_or(0),
        }))
    }

    /// Persist a session to SQLite storage
    async fn persist_session(
        &self,
        session: &BilateralBleSession,
        _alias_of: Option<[u8; 32]>,
    ) -> Result<(), DsmError> {
        let operation_bytes = crate::storage::client_db::serialize_operation(&session.operation);

        let phase_str = match session.phase {
            BilateralPhase::Preparing => "preparing",
            BilateralPhase::Prepared => "prepared",
            BilateralPhase::PendingUserAction => "pending_user_action",
            BilateralPhase::Accepted => "accepted",
            BilateralPhase::Rejected => "rejected",
            BilateralPhase::ConfirmPending => "confirm_pending",
            BilateralPhase::Committed => "committed",
            BilateralPhase::Failed => "failed",
        }
        .to_string();

        let record = BilateralSessionRecord {
            commitment_hash: session.commitment_hash.to_vec(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            counterparty_genesis_hash: session
                .counterparty_genesis_hash
                .as_ref()
                .map(|h| h.to_vec()),
            operation_bytes,
            phase: phase_str,
            local_signature: session.local_signature.clone(),
            counterparty_signature: session.counterparty_signature.clone(),
            created_at_step: session.created_at_ticks,
            sender_ble_address: session.sender_ble_address.clone(),
        };

        store_bilateral_session(&record).map_err(|e| {
            DsmError::invalid_operation(format!("Failed to persist session: {}", e))
        })?;

        debug!(
            "[BLE_HANDLER] Session persisted: commitment={}",
            bytes_to_base32(&session.commitment_hash[..8])
        );
        Ok(())
    }

    /// Prune terminal sessions (committed/rejected/failed) to a bounded count per counterparty.
    async fn prune_terminal_sessions_for_counterparty(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> usize {
        // Sweep any orphaned BLE reassembly chunks for this counterparty.
        // Terminal phase (Committed/Rejected/Failed) means no more chunks will
        // arrive for this session — any persisted chunks are stale.
        if let Err(e) =
            crate::storage::client_db::delete_chunks_by_counterparty(counterparty_device_id)
        {
            warn!(
                "[BLE_HANDLER] Failed to sweep BLE reassembly chunks for counterparty: {}",
                e
            );
        }

        let records = match get_all_bilateral_sessions() {
            Ok(list) => list,
            Err(e) => {
                warn!(
                    "[BLE_HANDLER] Failed to load bilateral sessions for pruning: {}",
                    e
                );
                return 0;
            }
        };

        let counterparty_vec = counterparty_device_id.to_vec();
        let mut terminal_sessions: Vec<BilateralSessionRecord> = records
            .into_iter()
            .filter(|record| {
                record.counterparty_device_id == counterparty_vec
                    && matches!(record.phase.as_str(), "committed" | "rejected" | "failed")
            })
            .collect();

        if terminal_sessions.len() <= MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY {
            return 0;
        }

        terminal_sessions.sort_by_key(|b| std::cmp::Reverse(b.created_at_step));

        let mut pruned = 0;
        for record in terminal_sessions
            .into_iter()
            .skip(MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY)
        {
            if let Err(e) = delete_bilateral_session(&record.commitment_hash) {
                warn!("[BLE_HANDLER] Failed to prune bilateral session: {}", e);
            } else {
                pruned += 1;
            }
        }

        if pruned > 0 {
            info!(
                "[BLE_HANDLER] Pruned {} terminal sessions for counterparty {}",
                pruned,
                bytes_to_base32(&counterparty_device_id[..8])
            );
        }

        pruned
    }

    /// Restore sessions from SQLite on startup.
    ///
    /// Interrupted bilateral sessions are not resumed after restart. Any
    /// non-terminal persisted session is marked `failed` so the frontend can
    /// surface retry-required state, but no in-memory session is restored.
    /// The return value remains a compatibility no-op; callers should inspect
    /// persisted session state instead of relying on a restoration count.
    pub async fn restore_sessions_from_storage(&self) -> Result<usize, DsmError> {
        info!("[BLE_HANDLER] Restoring bilateral sessions from storage...");

        let records = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to restore sessions: {}", e))
        })?;

        let mut counterparties: HashSet<[u8; 32]> = HashSet::new();
        let mut failed_count = 0;
        let mut deleted_malformed_count = 0;

        for record in records {
            if let Err(validation_error) = self.validate_persisted_restore_record(&record) {
                warn!(
                    "[BLE_HANDLER] Deleting malformed persisted bilateral session during restore: {}",
                    validation_error
                );
                if let Err(delete_error) = delete_bilateral_session(&record.commitment_hash) {
                    warn!(
                        "[BLE_HANDLER] Failed to delete malformed persisted session during restore: {}",
                        delete_error
                    );
                } else {
                    deleted_malformed_count += 1;
                }
                continue;
            }

            if record.counterparty_device_id.len() == 32 {
                let mut counterparty_device_id = [0u8; 32];
                counterparty_device_id.copy_from_slice(&record.counterparty_device_id);
                counterparties.insert(counterparty_device_id);
            }

            if matches!(record.phase.as_str(), "committed" | "rejected" | "failed") {
                debug!(
                    "[BLE_HANDLER] Skipping terminal persisted session on restore: phase={}",
                    record.phase
                );
                continue;
            }

            if let Err(e) = crate::storage::client_db::update_bilateral_session_phase(
                &record.commitment_hash,
                "failed",
            ) {
                warn!(
                    "[BLE_HANDLER] Failed to mark interrupted session failed during restore: {}",
                    e
                );
                continue;
            }

            failed_count += 1;
        }

        for counterparty_device_id in counterparties {
            self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                .await;
        }

        if failed_count > 0 {
            info!(
                "[BLE_HANDLER] Marked {} interrupted bilateral session(s) failed during restore",
                failed_count
            );
        }
        if deleted_malformed_count > 0 {
            info!(
                "[BLE_HANDLER] Deleted {} malformed bilateral session(s) during restore",
                deleted_malformed_count
            );
        }

        Ok(0)
    }

    // Removed background maintenance loop (tokio::time based). Maintenance is now caller-driven via
    // explicit calls to cleanup_expired_sessions/reconcile_session_state/maintain_sessions.

    async fn detect_inflight_counterparty_session(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> Option<([u8; 32], BilateralPhase, Instant)> {
        let sessions = self.sessions.sessions.lock().await;
        sessions
            .iter()
            .find(|(_hash, session)| {
                session.counterparty_device_id == *counterparty_device_id
                    && is_inflight_phase(&session.phase)
            })
            .map(|(hash, session)| (*hash, session.phase.clone(), session.created_at_wall))
    }

    /// Phase 1: Prepare bilateral transaction (sender initiates)
    async fn ensure_counterparty_ready_for_prepare(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        // §6 Tripwire gate: refuse to initiate BLE transfer with bricked contact.
        if crate::storage::client_db::is_contact_bricked(counterparty_device_id) {
            return Err(DsmError::invalid_operation(
                "BLE prepare rejected: contact is permanently bricked (Tripwire fork detected)",
            ));
        }

        if let Some((existing_commitment_hash, existing_phase, created_at_wall)) = self
            .detect_inflight_counterparty_session(counterparty_device_id)
            .await
        {
            const STALE_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(120);
            let age = created_at_wall.elapsed();
            if age < STALE_THRESHOLD {
                // Session is recent — genuinely in-flight, don't supersede
                warn!(
                    "[BLE_HANDLER] Blocking new prepare for counterparty {}: in-flight session {} phase={:?} age={:.1}s",
                    bytes_to_base32(&counterparty_device_id[..8]),
                    bytes_to_base32(&existing_commitment_hash[..8]),
                    existing_phase,
                    age.as_secs_f64()
                );
                return Err(DsmError::invalid_operation(format!(
                    "Existing bilateral session in progress for this contact (phase={:?}, commitment={}, age={:.0}s). \
                     Complete or resolve it before starting another transfer. Session will auto-expire after {}s.",
                    existing_phase,
                    bytes_to_base32(&existing_commitment_hash[..8]),
                    age.as_secs_f64(),
                    STALE_THRESHOLD.as_secs()
                )));
            }
            // Session is stale — auto-supersede: mark Failed + remove from in-memory + delete from DB
            warn!(
                "[BLE_HANDLER] Auto-superseding stale session {} phase={:?} age={:.1}s for counterparty {}",
                bytes_to_base32(&existing_commitment_hash[..8]),
                existing_phase,
                age.as_secs_f64(),
                bytes_to_base32(&counterparty_device_id[..8])
            );
            self.transition_session_to_failed(&existing_commitment_hash)
                .await;
        }
        Ok(())
    }

    pub async fn prepare_bilateral_transaction(
        &self,
        counterparty_device_id: [u8; 32],
        operation: Operation,
        validity_iterations: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        info!("Preparing BLE bilateral transaction");

        self.ensure_counterparty_ready_for_prepare(&counterparty_device_id)
            .await?;

        // Ensure we have a verified contact and relationship. Allow a special-case
        // loopback path when the counterparty is the local device (test harnesses).
        if counterparty_device_id == self.device_id {
            // Loopback allowance is strictly for tests; never enabled in production builds.
            if cfg!(test) {
                let mut mgr = self.bilateral_tx_manager.write().await;
                if !mgr.has_verified_contact(&counterparty_device_id) {
                    let contact = dsm::types::contact_types::DsmVerifiedContact {
                        alias: "self".to_string(),
                        device_id: self.device_id,
                        genesis_hash: mgr.local_genesis_hash(),
                        public_key: vec![7u8; 32], // test-only placeholder; not used for signing
                        genesis_material: vec![],
                        chain_tip: None,
                        chain_tip_smt_proof: None,
                        genesis_verified_online: true,
                        verified_at_commit_height: 1,
                        added_at_commit_height: 1,
                        last_updated_commit_height: 1,
                        verifying_storage_nodes: vec![],
                        ble_address: None,
                    };
                    let _ = mgr.add_verified_contact(contact);
                }
                if mgr.get_relationship(&counterparty_device_id).is_none() {
                    let mut smt = self.per_device_smt.write().await;
                    let _ = mgr
                        .establish_relationship(&counterparty_device_id, &mut smt)
                        .await;
                }
                drop(mgr);
            } else {
                let mgr = self.bilateral_tx_manager.read().await;
                let has_contact = mgr.has_verified_contact(&counterparty_device_id);
                drop(mgr);
                if !has_contact {
                    log::warn!(
                        "[BLE_HANDLER] Self-device contact not in BTM — attempting just-in-time sync"
                    );
                    let synced = match crate::storage::client_db::get_contact_by_device_id(
                        &counterparty_device_id,
                    ) {
                        Ok(Some(record)) => {
                            if let Some(verified) = record.to_verified_contact() {
                                let mut mgr = self.bilateral_tx_manager.write().await;
                                mgr.add_verified_contact(verified).is_ok()
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };
                    if !synced {
                        return Err(DsmError::invalid_operation(
                            "Bilateral transactions require a verified contact. Please add the contact first.",
                        ));
                    }
                }
                // Auto-establish relationship if missing (one-time, after QR contact exchange)
                let mut mgr = self.bilateral_tx_manager.write().await;
                if mgr.get_relationship(&counterparty_device_id).is_none() {
                    info!("Auto-establishing bilateral relationship for self-device counterparty");
                    mgr.ensure_relationship_for_sender(&counterparty_device_id)
                        .map_err(|e| {
                            DsmError::relationship(format!(
                                "Failed to auto-establish relationship: {e}"
                            ))
                        })?;
                    // Restore persisted local chain tip (same as receiver path at handle_prepare_request).
                    // ensure_relationship_for_sender defaults local_chain_tip to initial_tip;
                    // without this, a prior receiver whose BTM was re-created would have a stale local tip.
                    if let Some(persisted_local) =
                        crate::storage::client_db::get_local_bilateral_chain_tip(
                            &counterparty_device_id,
                        )
                    {
                        info!(
                            "[BLE_HANDLER] Sender: restoring persisted local bilateral chain tip: {}",
                            bytes_to_base32(&persisted_local[..8])
                        );
                        mgr.advance_chain_tip(&counterparty_device_id, persisted_local);
                    }
                }
                drop(mgr);
            }
        } else {
            let mgr = self.bilateral_tx_manager.read().await;
            let has_contact = mgr.has_verified_contact(&counterparty_device_id);
            drop(mgr);
            if !has_contact {
                // Just-in-time sync: the in-memory BTM may not have this contact even
                // though SQLite does (e.g., init-time sync was missed). Try to load and
                // add it before failing.
                log::warn!(
                    "[BLE_HANDLER] Contact not in BTM — attempting just-in-time sync from SQLite"
                );
                let synced = match crate::storage::client_db::get_contact_by_device_id(
                    &counterparty_device_id,
                ) {
                    Ok(Some(record)) => {
                        if let Some(verified) = record.to_verified_contact() {
                            let mut mgr = self.bilateral_tx_manager.write().await;
                            match mgr.add_verified_contact(verified) {
                                Ok(_) => {
                                    log::warn!(
                                        "[BLE_HANDLER] ✅ Just-in-time contact sync succeeded"
                                    );
                                    true
                                }
                                Err(e) => {
                                    log::error!(
                                        "[BLE_HANDLER] ❌ Just-in-time contact sync failed: {e}"
                                    );
                                    false
                                }
                            }
                        } else {
                            log::error!(
                                "[BLE_HANDLER] Contact in SQLite but to_verified_contact() returned None"
                            );
                            false
                        }
                    }
                    _ => false,
                };
                if !synced {
                    return Err(DsmError::invalid_operation(
                        "Bilateral transactions require a verified contact. Please add the contact first.",
                    ));
                }
            }
            // Auto-establish relationship if missing (one-time, after QR contact exchange)
            let mut mgr = self.bilateral_tx_manager.write().await;
            if mgr.get_relationship(&counterparty_device_id).is_none() {
                info!(
                    "Auto-establishing bilateral relationship for counterparty {:?}",
                    &counterparty_device_id[..8]
                );
                mgr.ensure_relationship_for_sender(&counterparty_device_id)
                    .map_err(|e| {
                        DsmError::relationship(format!(
                            "Failed to auto-establish relationship: {e}"
                        ))
                    })?;
                // Restore persisted local chain tip (same as receiver path at handle_prepare_request).
                // ensure_relationship_for_sender defaults local_chain_tip to initial_tip;
                // without this, a prior receiver whose BTM was re-created would have a stale local tip.
                if let Some(persisted_local) =
                    crate::storage::client_db::get_local_bilateral_chain_tip(
                        &counterparty_device_id,
                    )
                {
                    info!(
                        "[BLE_HANDLER] Sender: restoring persisted local bilateral chain tip: {}",
                        bytes_to_base32(&persisted_local[..8])
                    );
                    mgr.advance_chain_tip(&counterparty_device_id, persisted_local);
                }
            }
            drop(mgr);
        }

        // CRITICAL: Sync remote_chain_tip from contact (may have been updated since relationship established).
        // Try to get the latest chain_tip from SQLite storage first (most authoritative), then use secondary path to
        // in-memory contact's chain_tip, then genesis_hash.
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(contact) = mgr.get_contact(&counterparty_device_id).cloned() {
                // Try to get chain tip from SQLite storage first (most up-to-date)
                // IMPORTANT: Use the raw variant (no genesis_hash compatibility fallback).
                // For a fresh contact, get_contact_chain_tip returns the genesis_hash as a
                // "compatibility" fallback when chain_tip is NULL, which would set
                // remote_chain_tip = B.genesis_hash.  But the receiver seeds its local tip
                // as initial_relationship_chain_tip(A,B) — a completely different value —
                // causing a guaranteed mismatch on every first transaction.
                // get_contact_chain_tip_raw returns None for NULL -> falls through to
                // initial_tip, which both sides compute identically.
                let sqlite_chain_tip =
                    crate::storage::client_db::get_contact_chain_tip_raw(&counterparty_device_id);

                let initial_tip = mgr
                    .initial_relationship_tip_for(&counterparty_device_id)
                    .unwrap_or(contact.genesis_hash);
                let resolved_tip = sqlite_chain_tip
                    .or(contact.chain_tip)
                    .unwrap_or(initial_tip);

                info!(
                    "[BLE_HANDLER] Syncing remote_chain_tip before prepare: {} (sqlite={}, contact_mem={}, using_genesis={})",
                    dsm::core::utility::labeling::hash_to_short_id(&resolved_tip),
                    sqlite_chain_tip.is_some(),
                    contact.chain_tip.is_some(),
                    sqlite_chain_tip.is_none() && contact.chain_tip.is_none()
                );

                mgr.advance_chain_tip(&counterparty_device_id, resolved_tip);
            }
        }

        // Prepare offline transfer in core
        let (pre_commitment, local_genesis_hash) = {
            let mut manager = self.bilateral_tx_manager.write().await;
            let pre_commitment = manager
                .prepare_offline_transfer(
                    &counterparty_device_id,
                    operation.clone(),
                    validity_iterations,
                )
                .await?;
            let genesis_hash = manager.local_genesis_hash();
            (pre_commitment, genesis_hash)
        };

        let counterparty_genesis_hash = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.get_contact(&counterparty_device_id)
                .map(|c| c.genesis_hash)
        };

        // Track session (sender doesn't have a BLE address from counterparty yet)
        let commit_signature = {
            let m = self.bilateral_tx_manager.read().await;
            m.sign_commitment(&pre_commitment.bilateral_commitment_hash)
        };

        let sessions = self.sessions.sessions.lock().await;
        if sessions.contains_key(&pre_commitment.bilateral_commitment_hash) {
            log::warn!(
                "[BLE_HANDLER] ⚠️ Duplicate prepare request for {}. Dropping silently.",
                bytes_to_base32(&pre_commitment.bilateral_commitment_hash)
            );
            return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));
        }
        drop(sessions);

        let session = BilateralBleSession {
            commitment_hash: pre_commitment.bilateral_commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash,
            operation: operation.clone(),
            phase: BilateralPhase::Preparing,
            local_signature: Some(commit_signature),
            counterparty_signature: None,
            created_at_ticks: pre_commitment.created_at,
            expires_at_ticks: pre_commitment.expires_at,
            sender_ble_address: None, // Sender side - no counterparty BLE address yet
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        };

        {
            let mut sessions = self.sessions.sessions.lock().await;
            sessions.insert(pre_commitment.bilateral_commitment_hash, session.clone());
        }

        // Persist session to storage
        if let Err(e) = self.persist_session(&session, None).await {
            warn!("[BLE_HANDLER] Failed to persist preparing session: {}", e);
        }

        // Build prepare request with BLE address lookup
        let expected_counterparty_state_hash = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
                .ok_or_else(|| {
                    DsmError::invalid_operation(
                        "No remote chain tip found for counterparty. Relationship required.",
                    )
                })?
        };

        // Look up BLE address from contact or in-memory map
        let ble_address = {
            let m = self.bilateral_tx_manager.read().await;
            if let Some(contact) = m.get_contact(&counterparty_device_id) {
                if let Some(addr) = &contact.ble_address {
                    addr.clone()
                } else {
                    // Contact exists but no BLE address persisted
                    // Check in-memory map and persist if found
                    #[cfg(all(target_os = "android", feature = "jni"))]
                    {
                        if let Ok(map) = DEVICE_ID_TO_ADDR.try_lock() {
                            if let Some(addr) = map.get(&counterparty_device_id) {
                                // Persist it to the contact
                                let _ = crate::storage::client_db::update_contact_ble_status(
                                    &counterparty_device_id,
                                    None, // no chain tip
                                    Some(addr),
                                );
                                debug!(
                                    "[BLE_HANDLER] Persisted BLE address from in-memory map: {}",
                                    addr
                                );
                                addr.clone()
                            } else {
                                warn!("[BLE_HANDLER] No BLE address found for counterparty device (contact exists but no address persisted or in map)");
                                String::new()
                            }
                        } else {
                            warn!("[BLE_HANDLER] DEVICE_ID_TO_ADDR lock contended, no BLE address found for counterparty device");
                            String::new()
                        }
                    }
                    #[cfg(not(all(target_os = "android", feature = "jni")))]
                    {
                        warn!("[BLE_HANDLER] No BLE address found for counterparty device (contact exists but no address persisted)");
                        String::new()
                    }
                }
            } else {
                warn!("[BLE_HANDLER] No contact found for counterparty device");
                String::new()
            }
        };

        // Get sender's signing public key for inclusion in prepare request
        let sender_signing_public_key = {
            let m = self.bilateral_tx_manager.read().await;
            m.local_signing_public_key()
        };

        // Get sender's current chain tip for the relationship
        let sender_chain_tip = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
                .unwrap_or([0u8; 32]) // use zero if no relationship established yet
        };

        debug!(
            "[BLE_HANDLER] Including sender_signing_public_key (len={}) and sender_chain_tip={} in PrepareRequest",
            sender_signing_public_key.len(),
            bytes_to_base32(&sender_chain_tip[..8])
        );

        let prepare_request = generated::BilateralPrepareRequest {
            counterparty_device_id: counterparty_device_id.to_vec(),
            operation_data: operation.to_bytes(),
            validity_iterations,
            expected_genesis_hash: Some(generated::Hash32 {
                v: local_genesis_hash.to_vec(),
            }),
            expected_counterparty_state_hash: Some(generated::Hash32 {
                v: expected_counterparty_state_hash.to_vec(),
            }),
            ble_address,
            // Include sender identity for relationship establishment
            sender_signing_public_key,
            sender_device_id: self.device_id.to_vec(),
            sender_genesis_hash: Some(generated::Hash32 {
                v: local_genesis_hash.to_vec(),
            }),
            sender_chain_tip: Some(generated::Hash32 {
                v: sender_chain_tip.to_vec(),
            }),
            // transfer_amount and token_id_hint are UI-only hints; protocol
            // correctness is carried entirely by operation_data.  The transport
            // layer does not extract token-specific fields from the Operation.
            transfer_amount: 0,
            token_id_hint: String::new(),
            memo_hint: String::new(),
            transfer_amount_display: String::new(),
        };

        let tip_override = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
        };

        let envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::UniversalTx(generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: Some(generated::Hash32 {
                            v: pre_commitment.bilateral_commitment_hash.to_vec(),
                        }),
                        actor: self.device_id.to_vec(),
                        genesis_hash: local_genesis_hash.to_vec(),
                        kind: Some(generated::universal_op::Kind::Invoke(generated::Invoke {
                            method: "bilateral.prepare".to_string(),
                            args: Some(generated::ArgPack {
                                body: prepare_request.encode_to_vec(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })),
                    }],
                    atomic: true,
                }),
                tip_override,
            )
            .await?;

        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&pre_commitment.bilateral_commitment_hash) {
                session.phase = BilateralPhase::Prepared;

                // Persist updated phase
                let sess_clone = session.clone();
                drop(sessions);
                if let Err(e) = self.persist_session(&sess_clone, None).await {
                    warn!("[BLE_HANDLER] Failed to persist prepared session: {}", e);
                }
            }
        }

        // Serialize envelope for BLE transmission
        let mut buffer = Vec::new();
        envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error(
                "encode_prepare_envelope",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        info!("Bilateral prepare request created");
        Ok((buffer, pre_commitment.bilateral_commitment_hash))
    }

    /// Prepare bilateral transaction and also return its canonical commitment hash.
    pub async fn prepare_bilateral_transaction_with_commitment(
        &self,
        counterparty_device_id: [u8; 32],
        operation: Operation,
        validity_iterations: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.prepare_bilateral_transaction(counterparty_device_id, operation, validity_iterations)
            .await
    }

    /// Cancel / fail the in-flight Prepared session for `counterparty_device_id`, if any.
    ///
    /// Called when the BLE send of the prepare message fails so that the next
    /// attempt is not blocked by a stale `Prepared` session sitting in the
    /// `active_sessions` map.
    pub async fn cancel_prepared_session_for_counterparty(&self, counterparty_device_id: [u8; 32]) {
        if let Some((commitment_hash, _phase, _created)) = self
            .detect_inflight_counterparty_session(&counterparty_device_id)
            .await
        {
            warn!(
                "[BLE_HANDLER] Cancelling stuck-prepared session {} for counterparty {} (BLE send failed)",
                crate::util::text_id::encode_base32_crockford(&commitment_hash[..8]),
                crate::util::text_id::encode_base32_crockford(&counterparty_device_id[..8]),
            );
            let pending_key = {
                let mut sessions = self.sessions.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&commitment_hash) {
                    session.phase = BilateralPhase::Failed;
                    let pending_key = session.local_commitment_hash.unwrap_or(commitment_hash);
                    sessions.remove(&commitment_hash);
                    pending_key
                } else {
                    commitment_hash
                }
            };
            // Keep failed sessions in SQLite for poller visibility
            if let Err(e) = crate::storage::client_db::update_bilateral_session_phase(
                &commitment_hash,
                "failed",
            ) {
                warn!(
                    "[BLE_HANDLER] cancel_prepared: failed to update session phase: {}",
                    e
                );
            }
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&pending_key);
            }
        }
    }

    /// Fail and remove a single in-flight session by commitment hash.
    ///
    /// Used when BLE transport definitively fails after the session has already
    /// transitioned out of `PendingUserAction` (for example, receiver-side accept
    /// send failure). This prevents stale `Accepted` / `ConfirmPending` sessions
    /// from blocking the next transfer attempt.
    pub async fn fail_session_by_commitment(
        &self,
        commitment_hash: [u8; 32],
        reason: &str,
    ) -> bool {
        let session = {
            let mut sessions = self.sessions.sessions.lock().await;
            let Some(mut session) = sessions.remove(&commitment_hash) else {
                info!(
                    "[BLE_HANDLER] fail_session_by_commitment: session {} already absent",
                    bytes_to_base32(&commitment_hash[..8])
                );
                return false;
            };

            if !is_inflight_phase(&session.phase) {
                info!(
                    "[BLE_HANDLER] fail_session_by_commitment: session {} already terminal ({:?})",
                    bytes_to_base32(&commitment_hash[..8]),
                    session.phase
                );
                sessions.insert(commitment_hash, session);
                return false;
            }

            session.phase = BilateralPhase::Failed;
            session
        };

        warn!(
            "[BLE_HANDLER] Failing session {} for counterparty {}: {}",
            bytes_to_base32(&commitment_hash[..8]),
            bytes_to_base32(&session.counterparty_device_id[..8]),
            reason
        );

        let pending_key = session.local_commitment_hash.unwrap_or(commitment_hash);
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            let _ = mgr.remove_pending_commitment(&pending_key);
            if pending_key != commitment_hash {
                let _ = mgr.remove_pending_commitment(&commitment_hash);
            }
        }

        // Keep failed sessions in SQLite for poller visibility
        if let Err(e) =
            crate::storage::client_db::update_bilateral_session_phase(&commitment_hash, "failed")
        {
            warn!(
                "[BLE_HANDLER] fail_session_by_commitment: failed to update session phase {}: {}",
                bytes_to_base32(&commitment_hash[..8]),
                e
            );
        }

        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventFailed.into(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: None,
            token_id: None,
            status: "failed".to_string(),
            message: reason.to_string(),
            sender_ble_address: session.sender_ble_address.clone(),
            failure_reason: Some(
                generated::BilateralFailureReason::FailureReasonUnspecified.into(),
            ),
        });

        self.prune_terminal_sessions_for_counterparty(&session.counterparty_device_id)
            .await;

        true
    }

    /// Phase 2: Handle incoming prepare request (receiver processes)
    ///
    /// This validates the proposal and stores it for user decision. Does NOT auto-accept.
    /// Returns empty Vec on success (user must call create_prepare_accept_envelope or
    /// create_prepare_reject_envelope to send a response).
    /// Returns auto-reject envelope bytes if hash verification fails.
    pub async fn handle_prepare_request(
        &self,
        envelope_bytes: &[u8],
        sender_ble_address: Option<String>,
    ) -> Result<(Vec<u8>, crate::sdk::transfer_hooks::TransferMeta), DsmError> {
        debug!("Handling bilateral prepare request");

        // Decode as Envelope - this is the only supported format
        let envelope = generated::Envelope::decode(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_envelope",
                "protobuf",
                Some(format!(
                    "Failed to decode Envelope: {}. Raw BilateralPrepareRequest is not supported.",
                    e
                )),
                Some(e),
            )
        })?;

        // Extract prepare request from envelope
        let prepare_request = self.extract_prepare_request(&envelope)?;

        // The SENDER's identity is in headers.device_id (who sent this prepare request)
        // The TARGET's identity is in prepare_request.counterparty_device_id (who should receive)
        // We need to verify the SENDER is a known contact!
        let sender_device_id: [u8; 32] = envelope
            .headers
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("Missing headers in envelope"))?
            .device_id
            .as_slice()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("headers.device_id must be 32 bytes"))?;

        // Log both IDs for debugging
        info!(
            "Bilateral prepare: sender={} target={}",
            bytes_to_base32(&sender_device_id[..8]),
            bytes_to_base32(
                prepare_request
                    .counterparty_device_id
                    .get(..8)
                    .unwrap_or(&[])
            )
        );

        // Use sender_device_id for contact verification, but keep counterparty_device_id for transaction tracking
        let counterparty_device_id: [u8; 32] = sender_device_id;

        // §6 Tripwire gate: reject BLE prepare from bricked contact.
        if crate::storage::client_db::is_contact_bricked(&counterparty_device_id) {
            return Err(DsmError::invalid_operation(
                "BLE prepare rejected: contact is permanently bricked (Tripwire fork detected)",
            ));
        }

        // Deserialize operation
        let operation = Operation::from_bytes(&prepare_request.operation_data)
            .map_err(|_| DsmError::invalid_operation("invalid operation payload"))?;

        // Capture transfer metadata for the orchestration layer to run hooks.
        // Delegate to the application layer so the transport stays coin-agnostic.
        let operation_bytes = operation.to_bytes();
        let (meta_amount, meta_token) = if let Some(ref d) = self.settlement_delegate {
            d.operation_metadata(&operation_bytes)
        } else {
            (None, None)
        };
        let transfer_meta = crate::sdk::transfer_hooks::TransferMeta {
            token_id: meta_token.clone().unwrap_or_default(),
            amount: meta_amount.unwrap_or(0),
        };

        info!("Received bilateral prepare request");

        // Extract commitment hash from envelope
        let origin_commitment_hash: [u8; 32] = match &envelope.payload {
            Some(generated::envelope::Payload::UniversalTx(tx)) => {
                log::warn!(
                    "[BilateralBleHandler] 🔍 UniversalTx has {} ops",
                    tx.ops.len()
                );
                if let Some(op) = tx.ops.first() {
                    let has_op_id = op.op_id.is_some();
                    let op_id_len = op.op_id.as_ref().map(|h| h.v.len()).unwrap_or(0);
                    log::warn!(
                        "[BilateralBleHandler] 🔍 op.op_id present={} len={}",
                        has_op_id,
                        op_id_len
                    );
                    if has_op_id {
                        if let Some(id) = op.op_id.as_ref() {
                            if id.v.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&id.v);
                                log::warn!(
                                    "[BilateralBleHandler] 🔍 op.op_id: {}",
                                    dsm::core::utility::labeling::hash_to_short_id(&arr)
                                );
                            }
                        }
                    }
                    op.op_id
                        .as_ref()
                        .map(|h| h.v.clone())
                        .ok_or_else(|| DsmError::invalid_operation("missing op_id in prepare"))?
                        .try_into()
                        .map_err(|_| DsmError::invalid_operation("op_id must be 32 bytes"))?
                } else {
                    return Err(DsmError::invalid_operation("no operations in transaction"));
                }
            }
            _ => {
                return Err(DsmError::invalid_operation(
                    "expected universal transaction",
                ))
            }
        };
        log::warn!(
            "[BilateralBleHandler] 🔍 origin_commitment_hash extracted: {}",
            bytes_to_base32(&origin_commitment_hash)
        );

        // Ensure contact and relationship (receiver side)
        // We verify the SENDER (counterparty_device_id) is a known contact
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            let mut is_verified = mgr.has_verified_contact(&counterparty_device_id);
            log::warn!(
                "[BilateralBleHandler] 🔍 Contact verification: device_id={} is_verified={}",
                dsm::core::utility::labeling::hash_to_short_id(&counterparty_device_id),
                is_verified
            );
            // Fallback: if not in memory, try loading from SQLite (handles boot race)
            if !is_verified {
                log::warn!(
                    "[BilateralBleHandler] 🔄 Contact not in BLE memory — checking SQLite fallback"
                );
                if let Ok(Some(record)) =
                    crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
                {
                    if let Some(verified_contact) = record.to_verified_contact() {
                        log::warn!(
                            "[BilateralBleHandler] ✅ Found contact in SQLite, syncing to BLE handler: alias={}",
                            verified_contact.alias
                        );
                        if mgr.add_verified_contact(verified_contact).is_ok() {
                            is_verified = true;
                        }
                    }
                }
            }
            if !is_verified {
                log::error!(
                    "[BilateralBleHandler] ❌ Sender device_id not found in verified contacts!"
                );
                return Err(DsmError::invalid_operation(format!(
                    "Cannot handle prepare request: Sender {} is not a verified contact.",
                    dsm::core::utility::labeling::hash_to_short_id(&counterparty_device_id)
                )));
            }

            // §5.4 Modal Synchronization Lock: reject offline if pending online for (A,B)
            {
                let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                    &self.device_id,
                    &counterparty_device_id,
                );
                let mut modal_locked =
                    crate::security::modal_sync_lock::is_pending_online(&smt_key).await;
                if modal_locked {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ §5.4 in-memory modal lock set for ({}, {}). Checking SQLite recovery before rejecting.",
                        bytes_to_base32(&self.device_id[..8]),
                        bytes_to_base32(&counterparty_device_id[..8]),
                    );
                }
                match crate::storage::client_db::get_pending_online_outbox(&counterparty_device_id)
                {
                    Ok(Some(pending)) => {
                        // Fast-path catch-up: if the chain tip already reflects the
                        // pending transition's next_tip, the gate is stale — clear it.
                        // Check three sources (in order of authority):
                        //   1. Sender's chain tip from the incoming prepare request (most current)
                        //   2. Persisted contacts.chain_tip in SQLite (may be stale)
                        //   3. The storage.sync outbox sweep handles the network ACK path
                        //      (checking is_message_acknowledged) proactively every cycle.
                        let pending_parent: Option<[u8; 32]> =
                            pending.parent_tip.as_slice().try_into().ok();

                        // Source 1: sender's self-reported chain tip from the prepare request.
                        // This is authoritative — the sender knows its own chain state.
                        let sender_reported_tip: Option<[u8; 32]> = prepare_request
                            .sender_chain_tip
                            .as_ref()
                            .and_then(|h| h.v.as_slice().try_into().ok());

                        // Source 2: our local persisted view of the sender's chain tip.
                        let persisted_tip = crate::storage::client_db::get_contact_chain_tip_raw(
                            &counterparty_device_id,
                        );

                        // The gate's parent_tip was the tip BEFORE the gated send.
                        // If the current tip != parent_tip, the chain moved forward
                        // (possibly multiple times) and the gate is stale.
                        let already_advanced = match pending_parent {
                            Some(pp) => {
                                (sender_reported_tip.is_some() && sender_reported_tip != Some(pp))
                                    || (persisted_tip.is_some() && persisted_tip != Some(pp))
                            }
                            None => true, // no parent means gate is bogus
                        };

                        if already_advanced {
                            log::info!(
                                "[BilateralBleHandler] ✅ Pending online gate stale (sender tip matches next_tip); clearing for ({}, {})",
                                bytes_to_base32(&self.device_id[..8]),
                                bytes_to_base32(&counterparty_device_id[..8]),
                            );
                            // Exact-match delete: only clears if parent_tip + next_tip match
                            let gate_parent: [u8; 32] = pending_parent.unwrap_or([0u8; 32]);
                            let gate_next: [u8; 32] =
                                pending.next_tip.as_slice().try_into().unwrap_or([0u8; 32]);
                            if let Err(e) =
                                crate::storage::client_db::clear_pending_online_outbox_if_matches(
                                    &counterparty_device_id,
                                    &gate_parent,
                                    &gate_next,
                                )
                            {
                                warn!("[BilateralBleHandler] Failed to clear stale gate: {}", e);
                            }
                            crate::security::modal_sync_lock::clear_pending_online(&smt_key).await;
                            modal_locked = false;
                        } else {
                            log::error!(
                                "[BilateralBleHandler] ❌ persisted online gate: chain tip unchanged from parent for ({}, {}). sender_tip={} parent_tip={} persisted_tip={}. Rejecting offline.",
                                bytes_to_base32(&self.device_id[..8]),
                                bytes_to_base32(&counterparty_device_id[..8]),
                                sender_reported_tip.map_or("none".to_string(), |t| bytes_to_base32(&t[..8])),
                                pending_parent.map_or("none".to_string(), |t| bytes_to_base32(&t[..8])),
                                persisted_tip.map_or("none".to_string(), |t| bytes_to_base32(&t[..8])),
                            );
                            return Err(DsmError::invalid_operation(
                                "§5.4: Cannot initiate offline transfer while a prior online transfer for this relationship is still awaiting recipient catch-up",
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::error!(
                            "[BilateralBleHandler] ❌ failed to read persisted online gate for ({}, {}): {}",
                            bytes_to_base32(&self.device_id[..8]),
                            bytes_to_base32(&counterparty_device_id[..8]),
                            e,
                        );
                        return Err(DsmError::invalid_operation(
                            "§5.4: Cannot verify whether a prior online transfer is still pending for this relationship",
                        ));
                    }
                }
                if modal_locked {
                    log::error!(
                        "[BilateralBleHandler] ❌ §5.4 modal lock: pending online projection for ({}, {}). Rejecting offline.",
                        bytes_to_base32(&self.device_id[..8]),
                        bytes_to_base32(&counterparty_device_id[..8]),
                    );
                    return Err(DsmError::invalid_operation(
                        "§5.4: Cannot initiate offline transfer while pending online projection exists for this relationship",
                    ));
                }
            }

            // =====================================================================
            // CRITICAL: Extract and store sender's signing public key from prepare request
            // This must happen BEFORE establish_relationship since that requires the key
            // =====================================================================
            log::warn!(
                "[BilateralBleHandler] 🔑 prepare_request.sender_signing_public_key.len() = {} (empty={})",
                prepare_request.sender_signing_public_key.len(),
                prepare_request.sender_signing_public_key.is_empty()
            );
            if !prepare_request.sender_signing_public_key.is_empty() {
                log::info!(
                    "[BilateralBleHandler] 🔑 Updating contact signing key from prepare request (len={})",
                    prepare_request.sender_signing_public_key.len()
                );
                // Update in-memory contact manager
                if let Err(e) = mgr.update_contact_signing_key(
                    &counterparty_device_id,
                    prepare_request.sender_signing_public_key.clone(),
                ) {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ Failed to update in-memory contact signing key: {}",
                        e
                    );
                    // Continue anyway - relationship may still work if contact already has key
                }
                // Persist to SQLite for durability across restarts
                if let Err(e) = crate::storage::client_db::update_contact_public_key(
                    &counterparty_device_id,
                    &prepare_request.sender_signing_public_key,
                ) {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ Failed to persist contact public_key to SQLite: {}",
                        e
                    );
                    // Non-fatal - in-memory update still happened
                } else {
                    log::info!("[BilateralBleHandler] ✅ Persisted contact public_key to SQLite");
                }
            } else {
                log::warn!(
                    "[BilateralBleHandler] ⚠️ No sender_signing_public_key in prepare request"
                );
            }

            // =====================================================================
            // CRITICAL: Update our view of sender's chain tip from prepare request
            // This enables proper state synchronization in multi-relationship scenarios
            // =====================================================================
            if let Some(sender_chain_tip_hash32) = &prepare_request.sender_chain_tip {
                if let Ok(sender_chain_tip_bytes) =
                    <Vec<u8> as TryInto<[u8; 32]>>::try_into(sender_chain_tip_hash32.v.clone())
                {
                    log::info!(
                        "[BilateralBleHandler] 🔄 Updating remote chain tip for sender {} to {}",
                        bytes_to_base32(&counterparty_device_id[..8]),
                        bytes_to_base32(&sender_chain_tip_bytes[..8])
                    );
                    // Update in-memory view of sender's chain tip
                    mgr.advance_chain_tip(&counterparty_device_id, sender_chain_tip_bytes);
                    // Persist to SQLite in the observed-tip namespace for
                    // durability across restarts without mutating canonical state.
                    if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                        &counterparty_device_id,
                        &sender_chain_tip_bytes,
                        crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
                    ) {
                        log::warn!(
                            "[BilateralBleHandler] ⚠️ Failed to persist observed remote chain tip to SQLite: {}",
                            e
                        );
                        // Non-fatal - in-memory update still happened
                    } else {
                        log::info!(
                            "[BilateralBleHandler] ✅ Persisted observed remote chain tip to SQLite"
                        );
                    }
                } else {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ Invalid sender_chain_tip format in prepare request"
                    );
                }
            } else {
                log::warn!(
                    "[BilateralBleHandler] ⚠️ No sender_chain_tip in prepare request - state sync may fail in multi-relationship scenarios"
                );
            }

            if mgr.get_relationship(&counterparty_device_id).is_none() {
                let mut smt = self.per_device_smt.write().await;
                mgr.establish_relationship(&counterparty_device_id, &mut smt)
                    .await
                    .map_err(|e| {
                        DsmError::relationship(format!("Failed to establish relationship: {e}"))
                    })?;
                // establish_relationship defaults local_chain_tip to initial_tip.
                // Restore the persisted value so the chain tip check doesn't mismatch.
                if let Some(persisted_local) =
                    crate::storage::client_db::get_local_bilateral_chain_tip(
                        &counterparty_device_id,
                    )
                {
                    info!(
                        "[BLE_HANDLER] Restoring persisted local bilateral chain tip: {}",
                        bytes_to_base32(&persisted_local[..8])
                    );
                    mgr.advance_chain_tip(&counterparty_device_id, persisted_local);
                }
            }
        }

        // =====================================================================
        // CRITICAL: Verify expected_counterparty_state_hash matches our local chain tip
        // If mismatch, auto-reject - the sender has stale view of our state
        // =====================================================================

        // Re-sync the BTM chain tip from SQLite before verification. An online
        // send may have advanced the tip in SQLite without updating the BTM.
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(sqlite_tip) =
                crate::storage::client_db::get_contact_chain_tip_raw(&counterparty_device_id)
            {
                let btm_tip = mgr.get_chain_tip_for(&counterparty_device_id);
                if btm_tip != Some(sqlite_tip) {
                    info!(
                        "[BLE_HANDLER] Refreshing BTM chain tip from SQLite: {}",
                        bytes_to_base32(&sqlite_tip[..8])
                    );
                    mgr.advance_chain_tip(&counterparty_device_id, sqlite_tip);
                }
            }
        }

        let our_local_chain_tip: [u8; 32] = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
                .ok_or_else(|| {
                    DsmError::invalid_operation(
                        "No local chain tip found for counterparty - relationship not established",
                    )
                })?
        };

        let sender_expected_hash: Option<[u8; 32]> = prepare_request
            .expected_counterparty_state_hash
            .as_ref()
            .and_then(|h| h.v.clone().try_into().ok());

        let hash_verified = match sender_expected_hash {
            Some(expected) => {
                let matches = expected == our_local_chain_tip;
                info!(
                    "Hash verification: sender_expected={} our_actual={} MATCH={}",
                    bytes_to_base32(&expected[..8]),
                    bytes_to_base32(&our_local_chain_tip[..8]),
                    matches
                );
                matches
            }
            None => {
                warn!("No expected_counterparty_state_hash in prepare request - cannot verify");
                false
            }
        };

        // If hash verification fails, auto-reject without creating pre-commitment
        if !hash_verified {
            let reason = format!(
                "Chain tip mismatch: sender expected {} but receiver has {}. Online reconciliation required.",
                sender_expected_hash.map(|h| bytes_to_base32(&h[..8])).unwrap_or_else(|| "none".to_string()),
                bytes_to_base32(&our_local_chain_tip[..8])
            );
            warn!("[BLE_HANDLER] Auto-rejecting proposal: {}", reason);

            if let Some(expected_tip) = sender_expected_hash {
                if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                    &counterparty_device_id,
                    &expected_tip,
                    crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
                ) {
                    warn!(
                        "[BLE_HANDLER] Failed to record observed sender tip after prepare mismatch: {}",
                        e
                    );
                }
            }

            // Emit rejection event with verification failure
            self.emit_event(&generated::BilateralEventNotification {
                event_type: generated::BilateralEventType::BilateralEventRejected.into(),
                counterparty_device_id: counterparty_device_id.to_vec(),
                commitment_hash: origin_commitment_hash.to_vec(),
                transaction_hash: None,
                amount: None,
                token_id: None,
                status: "needs_online_reconcile".to_string(),
                message: reason.clone(),
                sender_ble_address: None,
                failure_reason: Some(
                    generated::BilateralFailureReason::FailureReasonCryptoInvalid.into(),
                ),
            });

            // Build and return reject envelope (no pre-commitment created)
            let send_status =
                crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                    &counterparty_device_id,
                );
            let send_status = sdk_send_status_from_router_status(send_status);
            let reject = generated::BilateralPrepareReject {
                commitment_hash: Some(generated::Hash32 {
                    v: origin_commitment_hash.to_vec(),
                }),
                reason,
                rejector_device_id: self.device_id.to_vec(),
                send_status: Some(send_status),
            };
            let tip_override = Some(our_local_chain_tip);
            let envelope = self
                .create_envelope_with_tip(
                    generated::envelope::Payload::BilateralPrepareReject(reject),
                    tip_override,
                )
                .await?;
            let mut buffer = Vec::new();
            envelope.encode(&mut buffer).map_err(|e| {
                DsmError::serialization_error(
                    "encode_auto_reject",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
            return Ok((buffer, crate::sdk::transfer_hooks::TransferMeta::default()));
        }

        // Hash verified! Now create our own pre-commitment
        let our_pre_commitment = {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager
                .prepare_offline_transfer(
                    &counterparty_device_id,
                    operation.clone(),
                    prepare_request.validity_iterations,
                )
                .await?
        };

        let counterparty_genesis_hash = if let Some(hash) = prepare_request
            .expected_genesis_hash
            .as_ref()
            .and_then(|h| h.v.clone().try_into().ok())
        {
            Some(hash)
        } else {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.get_contact(&counterparty_device_id)
                .map(|c| c.genesis_hash)
        };

        // Track session as PendingUserAction (NOT auto-accepted)
        let commit_signature = {
            let m = self.bilateral_tx_manager.read().await;
            m.sign_commitment(&origin_commitment_hash)
        };

        let sessions = self.sessions.sessions.lock().await;
        if sessions.contains_key(&origin_commitment_hash) {
            log::warn!(
                "[BLE_HANDLER] ⚠️ Duplicate prepare request for {}. Dropping silently.",
                bytes_to_base32(&origin_commitment_hash)
            );
            return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));
        }
        drop(sessions);

        let session = BilateralBleSession {
            commitment_hash: origin_commitment_hash,
            local_commitment_hash: Some(our_pre_commitment.bilateral_commitment_hash),
            counterparty_device_id,
            counterparty_genesis_hash,
            operation,
            phase: BilateralPhase::PendingUserAction, // Awaiting user accept/reject
            local_signature: Some(commit_signature),
            counterparty_signature: None,
            created_at_ticks: our_pre_commitment.created_at,
            expires_at_ticks: our_pre_commitment.expires_at,
            sender_ble_address: sender_ble_address.clone(),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        };

        {
            let mut sessions = self.sessions.sessions.lock().await;
            log::warn!(
                "[BLE_HANDLER] 📝 STORING session with ORIGIN commitment hash: {} (local={})",
                bytes_to_base32(&origin_commitment_hash),
                bytes_to_base32(&our_pre_commitment.bilateral_commitment_hash)
            );
            sessions.insert(origin_commitment_hash, session.clone());
            log::warn!("[BLE_HANDLER] 📝 Sessions after insert: {}", sessions.len());
        }

        // Persist pending session with ORIGIN commitment hash so it can be looked up by UI.
        // Also persist alias_of so that alias mapping is restored after restart.
        let session_for_persist = session.clone();
        if let Err(e) = self
            .persist_session(
                &session_for_persist,
                Some(our_pre_commitment.bilateral_commitment_hash),
            )
            .await
        {
            warn!("[BLE_HANDLER] Failed to persist pending session: {}", e);
        }

        // Obtain event display metadata from the delegate (coin-agnostic transport).
        let op_bytes_for_event = session.operation.to_bytes();
        let (amount_opt, token_id_opt) = if let Some(ref d) = self.settlement_delegate {
            d.operation_metadata(&op_bytes_for_event)
        } else {
            (None, None)
        };

        // Emit prepare_received event to frontend with verification status and BLE address for response routing
        log::warn!(
            "[BilateralBleHandler] 🔔 EMITTING prepare_received event: commitment_hash={}, sender_ble_address={:?}, amount={:?}",
            bytes_to_base32(&origin_commitment_hash),
            sender_ble_address,
            amount_opt
        );
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventPrepareReceived.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: origin_commitment_hash.to_vec(),
            transaction_hash: None,
            amount: amount_opt,
            token_id: token_id_opt,
            status: "pending_user_action".to_string(),
            message: "Incoming bilateral transfer verified - awaiting your decision".to_string(),
            sender_ble_address,
            failure_reason: None,
        });

        info!("Bilateral prepare request validated and stored. Awaiting user decision.");

        // Return empty response + transfer metadata for orchestration layer hooks
        Ok((Vec::new(), transfer_meta))
    }

    /// Create accept envelope for a pending proposal (receiver calls after user approves)
    /// Returns the BilateralPrepareResponse envelope bytes to send over BLE
    pub async fn create_prepare_accept_envelope(
        &self,
        origin_commitment_hash: [u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let (bytes, _counterparty) = self
            .create_prepare_accept_envelope_with_counterparty(origin_commitment_hash)
            .await?;
        Ok(bytes)
    }

    /// Create accept envelope for a pending proposal (receiver calls after user approves)
    /// Returns tuple of (BilateralPrepareResponse envelope bytes, counterparty_device_id)
    /// The counterparty_device_id is needed for proper BLE chunk addressing
    pub async fn create_prepare_accept_envelope_with_counterparty(
        &self,
        origin_commitment_hash: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        log::warn!(
            "[BLE_ACCEPT] 🔍 Looking up session for origin_commitment_hash: {}",
            bytes_to_base32(&origin_commitment_hash)
        );

        // Fetch and validate session
        let (session, counterparty_device_id) = {
            let mut sessions = self.sessions.sessions.lock().await;
            let session = sessions.get_mut(&origin_commitment_hash).ok_or_else(|| {
                DsmError::not_found(
                    format!(
                        "bilateral session {}",
                        bytes_to_base32(&origin_commitment_hash[..8])
                    ),
                    Some("No pending session found for acceptance".to_string()),
                )
            })?;

            if session.phase != BilateralPhase::PendingUserAction {
                return Err(DsmError::invalid_operation(format!(
                    "Session not in PendingUserAction phase (current: {:?})",
                    session.phase
                )));
            }

            // Transition to Accepted after the pending-user-action guard above succeeds.
            session.phase = BilateralPhase::Accepted;
            (session.clone(), session.counterparty_device_id)
        };

        // Persist updated session
        if let Err(e) = self.persist_session(&session, None).await {
            warn!("[BLE_HANDLER] Failed to persist accepted session: {}", e);
        }

        // Get shared chain tip for the bilateral relationship
        let shared_chain_tip = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("No chain tip for relationship"))?
        };

        // Get local signing public key for inclusion in response
        let local_signing_key = {
            let m = self.bilateral_tx_manager.read().await;
            m.local_signing_public_key()
        };

        // Build prepare response
        let prepare_response = generated::BilateralPrepareResponse {
            commitment_hash: Some(generated::Hash32 {
                v: origin_commitment_hash.to_vec(),
            }),
            local_signature: session.local_signature.clone().unwrap_or_default(),
            expires_iterations: session.expires_at_ticks,
            counterparty_state_hash: Some(generated::Hash32 {
                v: shared_chain_tip.to_vec(),
            }),
            local_state_hash: Some(generated::Hash32 {
                v: shared_chain_tip.to_vec(),
            }),
            responder_signing_public_key: local_signing_key,
        };

        // Wrap in envelope
        let response_envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::BilateralPrepareResponse(prepare_response),
                Some(shared_chain_tip),
            )
            .await?;

        let mut buffer = Vec::new();
        response_envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error(
                "encode_prepare_response",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // Emit accept_sent event
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventAcceptSent.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: origin_commitment_hash.to_vec(),
            transaction_hash: None,
            amount: None,
            token_id: None,
            status: "accept_sent".to_string(),
            message: "Bilateral transfer accepted by user".to_string(),
            sender_ble_address: session.sender_ble_address.clone(),
            failure_reason: None,
        });

        info!(
            "Bilateral prepare accept envelope created for {} to counterparty: {}",
            bytes_to_base32(&origin_commitment_hash[..8]),
            bytes_to_base32(&counterparty_device_id[..8])
        );
        Ok((buffer, counterparty_device_id))
    }

    /// Reject a pending proposal and clean up pre-commitment (receiver calls)
    /// Returns the BilateralPrepareReject envelope bytes to send over BLE
    pub async fn create_prepare_reject_envelope_with_cleanup(
        &self,
        origin_commitment_hash: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        // Fetch session and get counterparty_device_id
        let (counterparty_device_id, pending_key) = {
            let sessions = self.sessions.sessions.lock().await;
            let session = sessions.get(&origin_commitment_hash).ok_or_else(|| {
                DsmError::not_found(
                    format!(
                        "bilateral session {}",
                        bytes_to_base32(&origin_commitment_hash[..8])
                    ),
                    Some("No pending session found for rejection".to_string()),
                )
            })?;
            let pending_key = session
                .local_commitment_hash
                .unwrap_or(origin_commitment_hash);
            (session.counterparty_device_id, pending_key)
        };

        // Clean up receiver's pending commitment from BilateralTransactionManager
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(removed) = mgr.remove_pending_commitment(&pending_key) {
                info!(
                    "[BLE_HANDLER] Cleaned up receiver pre-commitment {} on reject",
                    bytes_to_base32(&removed.bilateral_commitment_hash[..8])
                );
            }
        }

        // Use existing reject method which handles session state + event emission
        self.reject_incoming_prepare(
            origin_commitment_hash,
            counterparty_device_id,
            Some(reason.clone()),
        )
        .await?;

        let send_status =
            crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                &counterparty_device_id,
            );
        let send_status = if send_status.send_ready {
            crate::handlers::relationship_status::blocked_status(
                dsm::types::proto::RelationshipSendBlockReason::StateDivergence,
                reason.clone(),
            )
        } else {
            send_status
        };
        let send_status = sdk_send_status_from_router_status(send_status);

        // Build reject envelope
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: origin_commitment_hash.to_vec(),
            }),
            reason,
            rejector_device_id: self.device_id.to_vec(),
            send_status: Some(send_status),
        };

        let tip_override = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&counterparty_device_id)
        };
        let envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::BilateralPrepareReject(reject),
                tip_override,
            )
            .await?;

        let mut buffer = Vec::new();
        envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error("encode_reject", "protobuf", Some(e.to_string()), Some(e))
        })?;

        info!(
            "Bilateral prepare reject envelope created for {}",
            bytes_to_base32(&origin_commitment_hash[..8])
        );
        Ok(buffer)
    }

    /// Handle prepare rejection (original sender processes rejection)
    /// Marks session as rejected, cleans up pending commitment, and emits event
    pub async fn handle_prepare_reject(&self, envelope_bytes: &[u8]) -> Result<(), DsmError> {
        debug!("Handling bilateral prepare rejection");

        // Decode envelope
        let envelope = generated::Envelope::decode(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_reject",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // Extract prepare reject
        let reject = match &envelope.payload {
            Some(generated::envelope::Payload::BilateralPrepareReject(rej)) => rej,
            _ => return Err(DsmError::invalid_operation("expected prepare rejection")),
        };

        let commitment_hash: [u8; 32] = reject
            .commitment_hash
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing commitment hash"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("commitment hash must be 32 bytes"))?;

        let rejector_device_id: [u8; 32] = reject
            .rejector_device_id
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("rejector device_id must be 32 bytes"))?;

        // CRITICAL: Clean up sender's pending commitment from BilateralTransactionManager
        // This ensures the sender's chain tip stays at the previous state
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(removed) = mgr.remove_pending_commitment(&commitment_hash) {
                info!(
                    "[BLE_HANDLER] Cleaned up sender pre-commitment {} after rejection",
                    bytes_to_base32(&removed.bilateral_commitment_hash[..8])
                );
            } else {
                warn!(
                    "[BLE_HANDLER] No pending commitment found for {} to clean up",
                    bytes_to_base32(&commitment_hash[..8])
                );
            }
        }

        // Update session to rejected
        let updated_session = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&commitment_hash) {
                session.phase = BilateralPhase::Rejected;
                info!("Session moved to Rejected phase");
                session.clone()
            } else {
                return Err(DsmError::invalid_operation(
                    "no session found for commitment hash",
                ));
            }
        };

        // Persist rejected session (sender side)
        if let Err(e) = self.persist_session(&updated_session, None).await {
            warn!(
                "[BLE_HANDLER] Failed to persist rejected session (sender): {}",
                e
            );
        }

        // Persist rejected phase (keep session visible for frontend poller)
        if let Err(e) =
            crate::storage::client_db::update_bilateral_session_phase(&commitment_hash, "rejected")
        {
            warn!(
                "[BLE_HANDLER] Failed to update rejected session phase: {}",
                e
            );
        }

        self.prune_terminal_sessions_for_counterparty(&rejector_device_id)
            .await;

        // Emit rejection event
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventRejected.into(),
            counterparty_device_id: rejector_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: None,
            token_id: None,
            status: "rejected".to_string(),
            message: reject.reason.clone(),
            sender_ble_address: None,
            failure_reason: Some(
                generated::BilateralFailureReason::FailureReasonRejectedByPeer.into(),
            ),
        });

        info!(
            "Bilateral transfer rejected by recipient: {}",
            reject.reason
        );
        Ok(())
    }

    /// Phase 3 (continued): Handle prepare response (original sender processes response)
    /// Returns the commit envelope bytes to be sent back via BLE
    pub async fn handle_prepare_response(
        &self,
        envelope_bytes: &[u8],
    ) -> Result<(Vec<u8>, crate::sdk::transfer_hooks::TransferMeta), DsmError> {
        debug!("Handling bilateral prepare response");

        // Decode envelope
        let envelope = generated::Envelope::decode(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_response",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // Extract prepare response
        let prepare_response = match &envelope.payload {
            Some(generated::envelope::Payload::BilateralPrepareResponse(resp)) => resp,
            _ => return Err(DsmError::invalid_operation("expected prepare response")),
        };

        let commitment_hash: [u8; 32] = prepare_response
            .commitment_hash
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing commitment hash"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("commitment hash must be 32 bytes"))?;

        // Extract responder's signing public key and update contact if present
        if !prepare_response.responder_signing_public_key.is_empty() {
            // We need to get the counterparty device ID from the session
            let counterparty_device_id = {
                let sessions = self.sessions.sessions.lock().await;
                sessions
                    .get(&commitment_hash)
                    .map(|s| s.counterparty_device_id)
            };

            if let Some(counterparty_device_id) = counterparty_device_id {
                log::info!(
                    "[BilateralBleHandler] 🔑 handle_prepare_response: Updating contact signing key from response (len={})",
                    prepare_response.responder_signing_public_key.len()
                );

                // Update in-memory contact manager
                {
                    let mut mgr = self.bilateral_tx_manager.write().await;
                    if let Err(e) = mgr.update_contact_signing_key(
                        &counterparty_device_id,
                        prepare_response.responder_signing_public_key.clone(),
                    ) {
                        log::warn!(
                            "[BilateralBleHandler] ⚠️ Failed to update in-memory contact signing key in handle_prepare_response: {}",
                            e
                        );
                    }
                }

                // Persist to SQLite for durability across restarts
                if let Err(e) = crate::storage::client_db::update_contact_public_key(
                    &counterparty_device_id,
                    &prepare_response.responder_signing_public_key,
                ) {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ Failed to persist responder public_key to SQLite in handle_prepare_response: {}",
                        e
                    );
                } else {
                    log::info!(
                        "[BilateralBleHandler] ✅ Persisted responder public_key to SQLite (handle_prepare_response)"
                    );
                }
            } else {
                log::warn!(
                    "[BilateralBleHandler] ⚠️ No session found to extract counterparty device ID for signing key update"
                );
            }
        } else {
            log::warn!(
                "[BilateralBleHandler] ⚠️ No responder_signing_public_key in prepare response"
            );
        }

        // Update session with counterparty signature
        let updated_session = {
            let mut sessions = self.sessions.sessions.lock().await;
            info!(
                "[BLE_HANDLER] handle_prepare_response: looking up session for commitment_hash={}",
                bytes_to_base32(&commitment_hash)
            );
            info!(
                "[BLE_HANDLER] handle_prepare_response: active_sessions count={}, keys={:?}",
                sessions.len(),
                sessions
                    .keys()
                    .map(|k| bytes_to_base32(&k[..8]))
                    .collect::<Vec<_>>()
            );

            // Post-restart recovery: in-memory HashMap is rebuilt from scratch
            // on app boot. If the sender process restarted between sending
            // prepare and receiving accept, the session lives in SQLite but
            // not in memory. Restore it before lookup so the accept envelope
            // can be processed instead of dropped.
            if let std::collections::hash_map::Entry::Vacant(slot) = sessions.entry(commitment_hash)
            {
                match crate::storage::client_db::get_bilateral_session(&commitment_hash) {
                    Ok(Some(record)) => match self.session_from_persisted_record(&record) {
                        Ok(restored) => {
                            info!(
                                "[BLE_HANDLER] handle_prepare_response: restored session from SQLite for commitment={}",
                                bytes_to_base32(&commitment_hash)
                            );
                            slot.insert(restored);
                        }
                        Err(decode_err) => {
                            warn!(
                                "[BLE_HANDLER] handle_prepare_response: SQLite session decode failed for commitment={}: {}",
                                bytes_to_base32(&commitment_hash),
                                decode_err
                            );
                        }
                    },
                    Ok(None) => {
                        debug!(
                            "[BLE_HANDLER] handle_prepare_response: no SQLite session for commitment={}",
                            bytes_to_base32(&commitment_hash)
                        );
                    }
                    Err(lookup_err) => {
                        warn!(
                            "[BLE_HANDLER] handle_prepare_response: SQLite session lookup failed for commitment={}: {}",
                            bytes_to_base32(&commitment_hash),
                            lookup_err
                        );
                    }
                }
            }

            if let Some(session) = sessions.get_mut(&commitment_hash) {
                session.counterparty_signature = Some(prepare_response.local_signature.clone());
                if session.phase == BilateralPhase::Accepted
                    || session.phase == BilateralPhase::Committed
                    || session.phase == BilateralPhase::ConfirmPending
                {
                    log::warn!(
                        "[BLE_HANDLER] ⚠️ Duplicate prepare response for {}. Dropping silently.",
                        bytes_to_base32(&commitment_hash)
                    );
                    return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));
                }
                session.phase = BilateralPhase::Accepted;
                info!("Session moved to Accepted phase");
                session.clone()
            } else {
                error!(
                    "[BLE_HANDLER] handle_prepare_response: NO SESSION FOUND for commitment={} (origin={})",
                    bytes_to_base32(&commitment_hash),
                    bytes_to_base32(&commitment_hash)
                );
                return Err(DsmError::invalid_operation(
                    "no session found for commitment hash",
                ));
            }
        };

        // Persist accepted session (sender side)
        if let Err(e) = self.persist_session(&updated_session, None).await {
            warn!(
                "[BLE_HANDLER] Failed to persist accepted session (sender): {}",
                e
            );
        }

        // 3-step protocol: sender builds BilateralConfirmRequest, finalizes, and sends confirm.
        // The receiver will finalize upon receiving the confirm message.
        info!("Building bilateral confirm message (3-step protocol, step 3)");
        let (confirm_envelope, confirm_meta) = self.send_bilateral_confirm(commitment_hash).await?;

        Ok((confirm_envelope, confirm_meta))
    }

    /// 3-step protocol step 3 (sender side): Build BilateralConfirmRequest and return the
    /// confirm envelope bytes to be sent to the receiver via BLE.
    ///
    /// The sender does not finalize or settle here. `ConfirmPending` is transport state only;
    /// canonical sender mutation happens only after an explicit receiver acknowledgment arrives.
    pub async fn send_bilateral_confirm(
        &self,
        commitment_hash: [u8; 32],
    ) -> Result<(Vec<u8>, crate::sdk::transfer_hooks::TransferMeta), DsmError> {
        info!("[BILATERAL] send_bilateral_confirm: building confirm (3-step step 3)");

        // 1. Look up session
        let session = {
            let sessions = self.sessions.sessions.lock().await;
            sessions.get(&commitment_hash).cloned().ok_or_else(|| {
                DsmError::invalid_operation("send_bilateral_confirm: session not found")
            })?
        };

        if session.phase != BilateralPhase::Accepted {
            return Err(DsmError::invalid_operation("session not in accepted phase"));
        }

        let local_sig = session
            .local_signature
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing local signature (σ_A)"))?
            .clone();
        let counterparty_sig = session
            .counterparty_signature
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing counterparty signature (σ_B)"))?;

        // 2. Verify receiver's signature (σ_B)
        let counterparty_pubkey = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.get_contact(&session.counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("missing counterparty contact"))?
                .public_key
                .clone()
        };
        // §ISSUE-B4 FIX: use canonical "DSM/<domain>\0" format consistent with every
        // other domain separator in the codebase.
        let mut signature_msg = Vec::with_capacity(22 + 32);
        signature_msg.extend_from_slice(b"DSM/bilateral-sign\0");
        signature_msg.extend_from_slice(&commitment_hash);

        if !crate::crypto::signatures::SignatureKeyPair::verify_raw(
            &signature_msg,
            counterparty_sig,
            &counterparty_pubkey,
        )
        .map_err(|e| DsmError::crypto(format!("verify σ_B failed: {e}"), None::<std::io::Error>))?
        {
            return Err(DsmError::invalid_operation(
                "invalid counterparty signature (σ_B)",
            ));
        }

        // 3. Pre-generate finalize entropy
        let pre_entropy = {
            let m = self.bilateral_tx_manager.read().await;
            m.generate_entropy()?
        };

        // Store entropy in session for finalize reuse
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.pre_finalize_entropy = Some(pre_entropy);
            }
        }

        // 4. Get shared chain tip h_n and compute successor h_{n+1}
        // Re-sync from SQLite in case an online transaction advanced the tip.
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(sqlite_tip) = crate::storage::client_db::get_contact_chain_tip_raw(
                &session.counterparty_device_id,
            ) {
                let btm_tip = mgr.get_chain_tip_for(&session.counterparty_device_id);
                if btm_tip != Some(sqlite_tip) {
                    info!(
                        "[BLE_HANDLER] Refreshing BTM chain tip from SQLite before confirm: {}",
                        bytes_to_base32(&sqlite_tip[..8])
                    );
                    mgr.advance_chain_tip(&session.counterparty_device_id, sqlite_tip);
                }
            }
        }
        let h_n = {
            let m = self.bilateral_tx_manager.read().await;
            m.get_chain_tip_for(&session.counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("No chain tip for confirm"))?
        };
        let op_bytes = session.operation.to_bytes();
        // §16.6: σ = Cpre = BLAKE3("DSM/pre\0" || h_n || op || entropy) — symmetric.
        // Uses compute_precommit (domain "DSM/pre") so BLE and online paths produce the same formula.
        let receipt_digest = dsm::core::bilateral_transaction_manager::compute_precommit(
            &h_n,
            &op_bytes,
            &pre_entropy,
        );
        let h_n_plus_1 = dsm::core::bilateral_transaction_manager::compute_successor_tip(
            &h_n,
            &op_bytes,
            &pre_entropy,
            &receipt_digest,
        );

        // 5. Build sender SMT proofs via a prepare-only simulation of the
        // canonical advance (§2.2). No canonical state mutation yet — that
        // happens after the receiver ACKs, inside
        // `mark_sender_committed_with_post_state_hash`. Identical inputs
        // produce an identical outcome there, so the simulated receipt
        // proofs are byte-exact with the eventual advance.
        let sender_deltas: Vec<dsm::types::device_state::BalanceDelta> = match &session.operation {
            dsm::types::operations::Operation::Transfer {
                amount, token_id, ..
            } => {
                let tid = std::str::from_utf8(token_id).unwrap_or("");
                if tid.is_empty() {
                    Vec::new()
                } else {
                    let pc = dsm::core::token::token_state_manager::resolve_policy_commit(tid);
                    vec![dsm::types::device_state::BalanceDelta {
                        policy_commit: pc,
                        direction: dsm::types::device_state::BalanceDirection::Debit,
                        amount: amount.value(),
                    }]
                }
            }
            _ => Vec::new(),
        };
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &session.counterparty_device_id,
        );
        let router = crate::bridge::app_router().ok_or_else(|| {
            DsmError::state_machine(
                "send_bilateral_confirm: app_router not installed; cannot simulate advance",
            )
        })?;
        let sim_outcome = router.simulate_advance_for_confirm(
            rel_key,
            session.counterparty_device_id,
            session.operation.clone(),
            &sender_deltas,
            Some(h_n),
        )?;
        // `parent_r_a` is the CAS-layer device head (pre-seed root). The
        // Merkle `parent_proof` is built against the post-seed tree, so the
        // bilateral wire-level "pre_root" claim must be `smt_proofs.pre_root`
        // (post-seed) for the peer to recompute proof → root successfully.
        // Using `parent_r_a` here fails §4.3 on first-ever advances where
        // seeding changes the root.
        let pre_root = sim_outcome.smt_proofs.pre_root;
        let sender_smt_root = sim_outcome.child_r_a;
        let rel_proof_parent_bytes = sim_outcome.smt_proofs.parent_proof.to_bytes();
        let rel_proof_child_bytes = sim_outcome.smt_proofs.child_proof.to_bytes();
        // Override the receipt tips: SMT stores the asymmetric (A-side)
        // chain tips, so the receipt must carry those to satisfy §4.3
        // inclusion-proof acceptance.
        let parent_tip_receipt = sim_outcome
            .smt_proofs
            .parent_proof
            .value
            .unwrap_or([0u8; 32]);
        let child_tip_receipt = sim_outcome.new_chain_state.compute_chain_tip();

        // DIAGNOSTIC: sender self-verifies proofs before envelope assembly.
        // If this fails, the bug is upstream in proof construction / smt_replace.
        // If this passes but receiver rejects, the gremlin is in transport or deser.
        {
            let parent_ok = if !rel_proof_parent_bytes.is_empty() {
                match crate::sdk::receipts::deserialize_inclusion_proof(&rel_proof_parent_bytes) {
                    Ok(proof) => {
                        let ok = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::verify_proof_against_root(&proof, &pre_root);
                        info!(
                            "[BILATERAL][SENDER-SELFCHECK] parent_proof vs pre_root: {} (siblings={}, value={:?}, key={})",
                            if ok { "PASS" } else { "FAIL" },
                            proof.siblings.len(),
                            proof.value.map(|v| bytes_to_base32(&v[..8])),
                            bytes_to_base32(&proof.key[..8]),
                        );
                        ok
                    }
                    Err(e) => {
                        error!(
                            "[BILATERAL][SENDER-SELFCHECK] parent_proof deser failed: {}",
                            e
                        );
                        false
                    }
                }
            } else {
                info!(
                    "[BILATERAL][SENDER-SELFCHECK] parent_proof empty (first tx for relationship)"
                );
                true
            };
            let child_ok = match crate::sdk::receipts::deserialize_inclusion_proof(
                &rel_proof_child_bytes,
            ) {
                Ok(proof) => {
                    let ok = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::verify_proof_against_root(&proof, &sender_smt_root);
                    info!(
                        "[BILATERAL][SENDER-SELFCHECK] child_proof vs post_root: {} (siblings={}, value={:?}, key={})",
                        if ok { "PASS" } else { "FAIL" },
                        proof.siblings.len(),
                        proof.value.map(|v| bytes_to_base32(&v[..8])),
                        bytes_to_base32(&proof.key[..8]),
                    );
                    ok
                }
                Err(e) => {
                    error!(
                        "[BILATERAL][SENDER-SELFCHECK] child_proof deser failed: {}",
                        e
                    );
                    false
                }
            };
            info!(
                "[BILATERAL][SENDER-SELFCHECK] pre_root={} post_root={} parent_ok={} child_ok={}",
                bytes_to_base32(&pre_root[..8]),
                bytes_to_base32(&sender_smt_root[..8]),
                parent_ok,
                child_ok,
            );
        }

        // 6. Build stitched receipt with real SMT roots + proofs (§4.2).
        // Tips are A-side asymmetric (what T_A stores + what the inclusion
        // proofs prove inclusion of). The symmetric `h_n_plus_1` is still
        // sent over the wire in the confirm envelope for tripwire +
        // contacts.chain_tip alignment.
        let local_device_tree_commitment = local_device_tree_commitment(&self.device_id);
        let receipt_bytes = crate::sdk::receipts::build_bilateral_receipt_with_smt(
            self.device_id,
            session.counterparty_device_id,
            parent_tip_receipt,
            child_tip_receipt,
            pre_root,
            sender_smt_root,
            rel_proof_parent_bytes.clone(),
            rel_proof_child_bytes.clone(),
            Some(local_device_tree_commitment),
        )
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "send_bilateral_confirm: local device_tree_root required to build receipt",
            )
        })?;

        // 7. Build BilateralConfirmRequest using the simulated sender post-root.
        let confirm_request = generated::BilateralConfirmRequest {
            commitment_hash: Some(generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            sender_signature: local_sig,
            sender_smt_root: sender_smt_root.to_vec(),
            rel_proof_parent: rel_proof_parent_bytes,
            rel_proof_child: rel_proof_child_bytes,
            stitched_receipt: receipt_bytes,
            shared_chain_tip_new: Some(generated::Hash32 {
                v: h_n_plus_1.to_vec(),
            }),
            // §C1: transmit entropy so receiver can independently verify h_{n+1} (§4.1)
            pre_entropy: pre_entropy.to_vec(),
            // §4.3: transmit pre-update SMT root (r_A) so receiver can fully verify
            // π_rel_parent (h_n ∈ r_A) per whitepaper §4.3 acceptance predicate #2.
            sender_smt_root_before: pre_root.to_vec(),
        };

        // 8. Wrap in envelope
        let local_genesis = {
            let m = self.bilateral_tx_manager.read().await;
            m.local_genesis_hash()
        };
        let envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::UniversalTx(generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: Some(generated::Hash32 {
                            v: commitment_hash.to_vec(),
                        }),
                        actor: self.device_id.to_vec(),
                        genesis_hash: local_genesis.to_vec(),
                        kind: Some(generated::universal_op::Kind::Invoke(generated::Invoke {
                            method: "bilateral.confirm".to_string(),
                            args: Some(generated::ArgPack {
                                body: confirm_request.encode_to_vec(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })),
                    }],
                    atomic: true,
                }),
                Some(h_n_plus_1),
            )
            .await?;

        let mut buffer = Vec::new();
        envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error(
                "encode_confirm_envelope",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // 9. Mark session ConfirmPending and persist confirm for re-delivery.
        // Sender does NOT finalize here. Finalization happens in
        // mark_sender_committed_with_post_state_hash after delivery is confirmed.
        // The confirm envelope is persisted to pending_confirm_delivery for
        // crash-safe re-delivery if BLE drops.
        //
        // Cache the stitched receipt bytes built above (with real pre/post SMT
        // roots and proofs) so the sender's settlement can persist them verbatim.
        // Without this, settlement builds a degraded receipt from the already-
        // mutated SMT (parent_root == child_root, empty parent proof), which
        // fails §4.3 verification and renders the sender's history "Invalid".
        let sender_receipt_cache = confirm_request.stitched_receipt.clone();
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.phase = BilateralPhase::ConfirmPending;
                s.stitched_receipt_bytes = Some(sender_receipt_cache);
            }
        }
        let mut confirm_pending_session = session.clone();
        confirm_pending_session.phase = BilateralPhase::ConfirmPending;
        if let Err(e) = self.persist_session(&confirm_pending_session, None).await {
            warn!(
                "[BILATERAL] Failed to persist ConfirmPending session: {}",
                e
            );
        }

        // Persist confirm envelope for crash-safe re-delivery on reconnect
        if let Err(e) = crate::storage::client_db::store_pending_confirm_delivery(
            &commitment_hash,
            &session.counterparty_device_id,
            &buffer,
        ) {
            warn!(
                "[BILATERAL] Failed to persist confirm envelope for re-delivery: {}",
                e
            );
        }

        info!("[BILATERAL] send_bilateral_confirm: confirm envelope built ({} bytes), session ConfirmPending, confirm persisted for re-delivery", buffer.len());
        Ok((buffer, crate::sdk::transfer_hooks::TransferMeta::default()))
    }

    /// Sender-side terminal acknowledgment: finalize only after the receiver confirms it has
    /// completed its side of the bilateral transfer.
    pub async fn handle_commit_response(&self, envelope_bytes: &[u8]) -> Result<(), DsmError> {
        let envelope = generated::Envelope::decode(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_commit_response_envelope",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        let response = match envelope.payload {
            Some(generated::envelope::Payload::BilateralCommitResponse(response)) => response,
            _ => {
                return Err(DsmError::invalid_operation(
                    "missing BilateralCommitResponse payload",
                ));
            }
        };

        let commitment_hash: [u8; 32] = response
            .commitment_hash
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing commitment hash in commit ack"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation("commit ack commitment hash must be 32 bytes")
            })?;

        let phase = {
            let sessions = self.sessions.sessions.lock().await;
            sessions.get(&commitment_hash).map(|s| s.phase.clone())
        };

        let should_attempt_persisted_recovery = match phase {
            Some(BilateralPhase::ConfirmPending) => false,
            Some(BilateralPhase::Committed) => {
                info!(
                    "[BILATERAL] handle_commit_response: duplicate ack for already-committed session {}",
                    bytes_to_base32(&commitment_hash[..8])
                );
                return Ok(());
            }
            Some(BilateralPhase::Failed) | None => true,
            Some(other) => {
                return Err(DsmError::invalid_operation(format!(
                    "commit ack received for non-ConfirmPending session: {:?}",
                    other
                )));
            }
        };

        if !response.success {
            let reason = option_string_or_default(
                Some(response.message.clone()),
                "Receiver rejected bilateral commit acknowledgment",
            );
            self.fail_session_by_commitment(commitment_hash, &reason)
                .await;
            return Err(DsmError::invalid_operation(reason));
        }

        let post_state_hash: [u8; 32] = response
            .post_state_hash
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing post_state_hash in commit ack"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation("commit ack post_state_hash must be 32 bytes")
            })?;

        let meta = if should_attempt_persisted_recovery {
            match self
                .recover_sender_commit_from_storage(commitment_hash, post_state_hash)
                .await?
            {
                Some(meta) => meta,
                None => {
                    info!(
                        "[BILATERAL] handle_commit_response: session {} already absent, ignoring ack",
                        bytes_to_base32(&commitment_hash[..8])
                    );
                    return Ok(());
                }
            }
        } else {
            let meta = self
                .mark_sender_committed_with_post_state_hash(&commitment_hash, Some(post_state_hash))
                .await
                .ok_or_else(|| {
                    DsmError::invalid_operation(
                        "sender finalize failed after receiver acknowledgment",
                    )
                })?;

            // Clear the persisted confirm envelope now that the sender has finalized
            // successfully. Without this, the record would remain indefinitely and
            // the confirm would be re-delivered on every reconnect.
            self.clear_pending_confirm_delivery(&commitment_hash);
            meta
        };

        crate::sdk::transfer_hooks::post_transfer_cleanup(
            &meta.token_id,
            crate::sdk::transfer_hooks::TransferCleanupRole::SenderRemove,
            meta.amount,
        );

        Ok(())
    }

    /// 3-step protocol step 3 (receiver side): Handle BilateralConfirmRequest from sender.
    ///
    /// Verifies sender's signature, validates proofs, finalizes the receiver side
    /// (execute state transition, update balance, store history), emits transfer complete,
    /// and returns the terminal BilateralCommitResponse acknowledgment bytes.
    pub async fn handle_confirm_request(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, DsmError> {
        info!(
            "[BILATERAL] handle_confirm_request ENTERED on device={}",
            bytes_to_base32(&self.device_id[..8])
        );
        info!("[BILATERAL] handle_confirm_request: processing confirm (3-step step 3, receiver)");

        // Decode envelope
        let envelope = generated::Envelope::decode(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_confirm_envelope",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // Extract confirm request
        let confirm_request = self.extract_confirm_request(&envelope)?;

        // §11.1 strict-fail: stitched_receipt MUST be ≤128 KiB.
        const RECEIPT_SIZE_LIMIT: usize = 131_072; // 128 KiB
        if confirm_request.stitched_receipt.len() > RECEIPT_SIZE_LIMIT {
            return Err(DsmError::invalid_operation(format!(
                "stitched_receipt exceeds 128 KiB strict-fail limit (§11.1): {} bytes",
                confirm_request.stitched_receipt.len()
            )));
        }

        let commitment_hash: [u8; 32] = confirm_request
            .commitment_hash
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing commitment hash in confirm"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("commitment hash must be 32 bytes"))?;

        // Session lookup — drop guard before acquiring other locks to avoid deadlock
        let session = {
            let mut sessions = self.sessions.sessions.lock().await;
            log::info!(
                "[BLE_HANDLER][handle_confirm_request] active_sessions keys: {:?}",
                sessions
                    .keys()
                    .map(|k| bytes_to_base32(&k[..8]))
                    .collect::<Vec<_>>()
            );

            // Post-restart recovery: rebuild session from SQLite when the
            // receiver process restarted between accepting and receiving
            // the confirm. Otherwise the in-memory HashMap is empty and
            // the confirm would be silently dropped.
            if let std::collections::hash_map::Entry::Vacant(slot) = sessions.entry(commitment_hash)
            {
                match crate::storage::client_db::get_bilateral_session(&commitment_hash) {
                    Ok(Some(record)) => match self.session_from_persisted_record(&record) {
                        Ok(restored) => {
                            log::info!(
                                "[BLE_HANDLER][handle_confirm_request] restored session from SQLite for hash {}",
                                bytes_to_base32(&commitment_hash[..8])
                            );
                            slot.insert(restored);
                        }
                        Err(decode_err) => {
                            log::warn!(
                                "[BLE_HANDLER][handle_confirm_request] SQLite session decode failed for hash {}: {}",
                                bytes_to_base32(&commitment_hash[..8]),
                                decode_err
                            );
                        }
                    },
                    Ok(None) => {
                        log::debug!(
                            "[BLE_HANDLER][handle_confirm_request] no SQLite session for hash {}",
                            bytes_to_base32(&commitment_hash[..8])
                        );
                    }
                    Err(lookup_err) => {
                        log::warn!(
                            "[BLE_HANDLER][handle_confirm_request] SQLite session lookup failed for hash {}: {}",
                            bytes_to_base32(&commitment_hash[..8]),
                            lookup_err
                        );
                    }
                }
            }

            if let Some(s) = sessions.get(&commitment_hash) {
                log::info!(
                    "[BLE_HANDLER][handle_confirm_request] Found session for hash {}",
                    bytes_to_base32(&commitment_hash[..8])
                );
                s.clone()
            } else {
                log::error!(
                    "[BLE_HANDLER][handle_confirm_request] No session found for hash {}",
                    bytes_to_base32(&commitment_hash[..8])
                );
                return Err(DsmError::invalid_operation("session not found"));
            }
        };

        if session.phase != BilateralPhase::Accepted {
            return Err(DsmError::invalid_operation("session not in accepted phase"));
        }

        // Verify sender's signature (σ_A) against DSM_BILATERAL_SIGN || commitment_hash
        let counterparty_pubkey = {
            let manager = self.bilateral_tx_manager.read().await;
            manager
                .get_contact(&session.counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("missing counterparty contact"))?
                .public_key
                .clone()
        };

        // §ISSUE-B4 FIX: use canonical "DSM/<domain>\0" format.
        let mut signature_msg = Vec::with_capacity(22 + 32);
        signature_msg.extend_from_slice(b"DSM/bilateral-sign\0");
        signature_msg.extend_from_slice(&commitment_hash);

        if confirm_request.sender_signature.is_empty() {
            return Err(DsmError::invalid_operation(
                "missing sender_signature in confirm",
            ));
        }

        if !crate::crypto::signatures::SignatureKeyPair::verify_raw(
            &signature_msg,
            &confirm_request.sender_signature,
            &counterparty_pubkey,
        )
        .map_err(|e| {
            DsmError::crypto(
                format!("verify sender signature (σ_A) failed: {e}"),
                None::<std::io::Error>,
            )
        })? {
            return Err(DsmError::invalid_operation(
                "invalid sender signature (σ_A)",
            ));
        }

        // §18.7 items 2 + 4: Verify sender's SMT inclusion proofs.
        // The sender transmits π(h_{n+1} ∈ r'_A) in rel_proof_child and r'_A in
        // sender_smt_root.  Recomputing the Merkle path from the proof against the
        // claimed root catches any attempt to lie about the post-update SMT state.
        if !confirm_request.rel_proof_child.is_empty()
            && confirm_request.sender_smt_root.len() == 32
        {
            let sender_root: [u8; 32] = confirm_request
                .sender_smt_root
                .clone()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("sender_smt_root not 32 bytes"))?;

            let child_proof = crate::sdk::receipts::deserialize_inclusion_proof(
                &confirm_request.rel_proof_child,
            )?;

            if !dsm::merkle::sparse_merkle_tree::SparseMerkleTree::verify_proof_against_root(
                &child_proof,
                &sender_root,
            ) {
                return Err(DsmError::invalid_operation(
                    "sender SMT child proof verification failed: \
                     π(h_{n+1} ∈ r'_A) does not recompute to sender_smt_root",
                ));
            }

            // §4.3 acceptance predicate #2: verify π_rel_parent (h_n ∈ r_A).
            // For first-ever transactions the proof value is ZERO_LEAF with a
            // real sibling path — verify_proof_against_root handles this by
            // hashing ZERO_LEAF and walking the Merkle path to recompute r_A.
            if !confirm_request.rel_proof_parent.is_empty()
                && confirm_request.sender_smt_root_before.len() == 32
            {
                let old_root: [u8; 32] = confirm_request
                    .sender_smt_root_before
                    .clone()
                    .try_into()
                    .map_err(|_| {
                        DsmError::invalid_operation("sender_smt_root_before not 32 bytes")
                    })?;
                let parent_proof = crate::sdk::receipts::deserialize_inclusion_proof(
                    &confirm_request.rel_proof_parent,
                )?;
                if !dsm::merkle::sparse_merkle_tree::SparseMerkleTree::verify_proof_against_root(
                    &parent_proof,
                    &old_root,
                ) {
                    return Err(DsmError::invalid_operation(
                        "sender SMT parent proof verification failed: \
                         π(h_n ∈ r_A) does not recompute to sender_smt_root_before (§4.3)",
                    ));
                }
                let is_zero_leaf =
                    parent_proof.value == Some(dsm::merkle::sparse_merkle_tree::ZERO_LEAF);
                info!(
                    "[BILATERAL] §4.3 parent proof verified: π(h_n ∈ r_A) ✓ (siblings={}, first_tx={})",
                    parent_proof.siblings.len(),
                    is_zero_leaf,
                );
            } else {
                info!(
                    "[BILATERAL] §4.3 parent proof absent — skipping (empty bytes or no pre-root)"
                );
            }
        }

        // Extract h_{n+1} from confirm request
        let new_chain_tip: [u8; 32] = confirm_request
            .shared_chain_tip_new
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing shared_chain_tip_new in confirm"))?
            .v
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("shared_chain_tip_new must be 32 bytes"))?;

        // RECEIVER-SIDE FINALIZE: route through canonical advance chokepoint
        // (§2.2 Per-Device SMT, §4.3 acceptance, §8 balance binding).

        // §C1: Verify h_{n+1} = compute_successor_tip(h_n, op, pre_entropy, σ)
        // using the sender's pre_entropy. A mismatch means the sender forged
        // shared_chain_tip_new without using the agreed entropy (§4.1).
        let pre_entropy: Option<[u8; 32]> = if confirm_request.pre_entropy.is_empty() {
            None
        } else {
            Some(
                confirm_request
                    .pre_entropy
                    .clone()
                    .try_into()
                    .map_err(|_| DsmError::invalid_operation("pre_entropy must be 32 bytes"))?,
            )
        };

        let (h_n, entropy) = {
            let manager = self.bilateral_tx_manager.read().await;
            let anchor = manager
                .get_relationship(&session.counterparty_device_id)
                .ok_or_else(|| {
                    DsmError::relationship("remote device relationship not found".to_string())
                })?;
            let h_n = anchor.chain_tip;

            if let Some(pe) = pre_entropy {
                let op_bytes = session.operation.to_bytes();
                let expected_sigma = compute_precommit(&h_n, &op_bytes, &pe);
                let expected_h_next = compute_successor_tip(&h_n, &op_bytes, &pe, &expected_sigma);
                if expected_h_next != new_chain_tip {
                    return Err(DsmError::invalid_operation(
                        "h_{n+1} mismatch: pre_entropy cannot reproduce shared_chain_tip_new (§4.1)",
                    ));
                }
            }

            // Use the same entropy the sender used to derive h_{n+1}. Fresh
            // entropy only valid if the confirm omitted pre_entropy entirely.
            let entropy = match pre_entropy {
                Some(pe) => pe,
                None => manager.generate_entropy()?,
            };
            (h_n, entropy)
        };

        // Derive receiver-side credit deltas from the session operation.
        let receiver_deltas: Vec<dsm::types::device_state::BalanceDelta> = match &session.operation
        {
            Operation::Transfer {
                amount, token_id, ..
            } => {
                let tid = std::str::from_utf8(token_id).unwrap_or("");
                if tid.is_empty() {
                    Vec::new()
                } else {
                    let pc = dsm::core::token::token_state_manager::resolve_policy_commit(tid);
                    vec![dsm::types::device_state::BalanceDelta {
                        policy_commit: pc,
                        direction: dsm::types::device_state::BalanceDirection::Credit,
                        amount: amount.value(),
                    }]
                }
            }
            _ => Vec::new(),
        };

        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &session.counterparty_device_id,
        );

        let router = crate::bridge::app_router().ok_or_else(|| {
            DsmError::state_machine(
                "receiver confirm: app_router not installed; cannot commit advance",
            )
        })?;

        let outcome = router
            .execute_on_relationship_for_bilateral(
                rel_key,
                session.counterparty_device_id,
                session.operation.clone(),
                &receiver_deltas,
                Some(h_n),
            )
            .map_err(|e| {
                DsmError::state_machine(format!("receiver confirm advance failed: {e}"))
            })?;

        // Advance BTM anchor + persisted contact tip to new_chain_tip (§16.6 symmetric).
        {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager.advance_chain_tip(&session.counterparty_device_id, new_chain_tip);
        }

        // Keep entropy variable live for diagnostics — unused here beyond the
        // advance's internal use via execute_on_relationship_for_bilateral.
        let _ = entropy;

        // h_{n+1} asymmetric (A-side; here "A" is the receiver) — what T_receiver now stores.
        let h_next_asymmetric = outcome.new_chain_state.compute_chain_tip();
        // h_n asymmetric (A-side) — previous T_receiver leaf value; zeros if first advance.
        let parent_tip_asymmetric = outcome.smt_proofs.parent_proof.value.unwrap_or([0u8; 32]);
        // Transaction hash for display / events = symmetric successor tip (new_chain_tip).
        let transaction_hash = new_chain_tip;

        // Build receipt with real proofs from the canonical AdvanceOutcome (§4.2).
        let receipt_bytes = {
            let local_commitment = local_device_tree_commitment(&self.device_id);
            crate::sdk::receipts::build_bilateral_receipt_with_smt(
                self.device_id,
                session.counterparty_device_id,
                parent_tip_asymmetric,
                h_next_asymmetric,
                outcome.smt_proofs.pre_root,
                outcome.child_r_a,
                crate::sdk::receipts::serialize_inclusion_proof(&outcome.smt_proofs.parent_proof),
                crate::sdk::receipts::serialize_inclusion_proof(&outcome.smt_proofs.child_proof),
                Some(local_commitment),
            )
        };

        let pending_key = session.local_commitment_hash.unwrap_or(commitment_hash);

        // Obtain event display metadata from the delegate before settlement so
        // we can populate the failure event if settlement itself fails.
        let op_bytes = session.operation.to_bytes();
        let (amount_opt, token_id_opt) = if let Some(ref d) = self.settlement_delegate {
            d.operation_metadata(&op_bytes)
        } else {
            (None, None)
        };

        // §4.2 Full-persistence atomic boundary: delegate applies chain tip + balance +
        // history in one SQLite transaction.

        let (_confirm_outcome, persistence_error) =
            if let Some(ref delegate) = self.settlement_delegate {
                // Canonical advance via `execute_on_relationship_for_bilateral`
                // (above) already applied the receiver-side credit to the
                // DeviceState head atomically with the SMT update. The
                // delegate just materialises the SQLite balance projection
                // from `head.balance(policy_commit)` + persists the
                // transaction-history record.
                let ctx = BilateralSettlementContext {
                    local_device_id: self.device_id,
                    counterparty_device_id: session.counterparty_device_id,
                    commitment_hash,
                    transaction_hash,

                    operation_bytes: op_bytes.clone(),
                    proof_data: receipt_bytes,
                    is_sender: false,
                    tx_type: "bilateral_offline",
                    new_chain_tip,
                };
                match delegate.settle(ctx) {
                    Ok(outcome) => (outcome, None),
                    Err(e) => {
                        warn!(
                            "[BILATERAL] Receiver settlement failed (device={}, amount={:?}): {}",
                            bytes_to_base32(&self.device_id[..8]),
                            amount_opt,
                            e
                        );
                        (BilateralSettlementOutcome::default(), Some(e))
                    }
                }
            } else {
                (BilateralSettlementOutcome::default(), None)
            };

        if let Some(ref persist_error) = persistence_error {
            // Receiver settlement delegate failed (e.g. missing proof_data,
            // projection write error).  The cryptographic commitment is already
            // finalized — do NOT bail here.  Log the error, mark for reconcile,
            // but still fall through to archive state / push / sync so the
            // receiver's balance and history can still update.
            warn!(
                "[BILATERAL] Receiver settlement delegate error (non-fatal, will still archive+sync): {}",
                persist_error
            );

            if let Err(e) = crate::storage::client_db::mark_contact_needs_online_reconcile(
                &session.counterparty_device_id,
            ) {
                warn!(
                    "[BILATERAL] Failed to mark contact for reconcile after receiver persistence error: {}",
                    e
                );
            }
        }

        if let Some(router) = crate::bridge::app_router() {
            router.sync_balance_cache();
        }

        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            let _ = mgr.remove_pending_commitment(&pending_key);
        }

        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&commitment_hash) {
                if session.phase == BilateralPhase::Committed {
                    log::warn!(
                        "[BLE_HANDLER] ⚠️ Duplicate confirm request for {}. Dropping silently.",
                        bytes_to_base32(&commitment_hash)
                    );
                    return Err(DsmError::invalid_operation("silent_drop_duplicate_packet"));
                }
                session.phase = BilateralPhase::Committed;
            }
        }

        // Delete from persistent storage (transaction complete)
        if let Err(e) = delete_bilateral_session(&commitment_hash) {
            warn!(
                "[BLE_HANDLER] Failed to delete completed session from storage: {}",
                e
            );
        }

        self.prune_terminal_sessions_for_counterparty(&session.counterparty_device_id)
            .await;

        // §5.4: BLE transfer succeeded (receiver side) — clear any stale pending
        // online gate. Uses exact-match delete to prevent TOCTOU race.
        if let Ok(Some(stale_gate)) =
            crate::storage::client_db::get_pending_online_outbox(&session.counterparty_device_id)
        {
            let gate_parent: [u8; 32] = stale_gate
                .parent_tip
                .as_slice()
                .try_into()
                .unwrap_or([0u8; 32]);
            let gate_next: [u8; 32] = stale_gate
                .next_tip
                .as_slice()
                .try_into()
                .unwrap_or([0u8; 32]);
            info!(
                "[BILATERAL] Clearing stale pending_online_outbox for {} after successful BLE commit (receiver)",
                bytes_to_base32(&session.counterparty_device_id[..8]),
            );
            if let Err(e) = crate::storage::client_db::clear_pending_online_outbox_if_matches(
                &session.counterparty_device_id,
                &gate_parent,
                &gate_next,
            ) {
                warn!(
                    "[BILATERAL] Failed to clear stale pending_online_outbox for {} (receiver): {}",
                    bytes_to_base32(&session.counterparty_device_id[..8]),
                    e,
                );
            }
        }

        // Emit transfer_complete event to frontend (receiver side).
        // amount / token_id already resolved via delegate.operation_metadata() above.
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: Some(transaction_hash.to_vec()),
            amount: amount_opt,
            token_id: token_id_opt,
            status: "completed".to_string(),
            message: "Bilateral transfer completed (receiver confirmed)".to_string(),
            sender_ble_address: session.sender_ble_address.clone(),
            failure_reason: None,
        });

        // Receiver's post-state hash broadcast to sender = symmetric h_{n+1}.
        // Sender verifies this independently from (h_n, op, entropy, σ) — no
        // access to T_receiver needed (§16.6 shared-tip derivation).
        let receiver_post_state_hash = new_chain_tip;

        let ack_envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::BilateralCommitResponse(
                    generated::BilateralCommitResponse {
                        success: true,
                        post_state_hash: Some(generated::Hash32 {
                            v: receiver_post_state_hash.to_vec(),
                        }),
                        transaction_hash: Some(generated::Hash32 {
                            v: transaction_hash.to_vec(),
                        }),
                        message: "receiver finalized bilateral confirm".to_string(),
                        commitment_hash: Some(generated::Hash32 {
                            v: commitment_hash.to_vec(),
                        }),
                    },
                ),
                Some(new_chain_tip),
            )
            .await?;

        info!("[BILATERAL] handle_confirm_request: receiver finalized successfully, ack prepared");

        Ok(ack_envelope.encode_to_vec())
    }

    /// Clean up stale in-flight sessions.
    ///
    /// Transport-only timing (rules.instructions.md §36: "stale-session recovery").
    /// Sessions already have `created_at_wall: Instant` for exactly this purpose.
    /// Any in-flight session that sits idle for > 60 seconds is treated as interrupted
    /// and failed so the next attempt restarts from prepare.
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let now = std::time::Instant::now();
        let stale_threshold = std::time::Duration::from_secs(60);

        let stale_hashes: Vec<[u8; 32]> = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, session)| {
                    is_inflight_phase(&session.phase)
                        && now.duration_since(session.created_at_wall) > stale_threshold
                })
                .map(|(commitment_hash, _)| *commitment_hash)
                .collect()
        };

        let mut failed = 0;
        for commitment_hash in stale_hashes {
            if self
                .fail_session_by_commitment(
                    commitment_hash,
                    "BLE transfer timed out before terminal acknowledgment",
                )
                .await
            {
                failed += 1;
            }
        }

        failed
    }

    /// Remove all terminal sessions (Committed, ConfirmPending, or later)
    /// from the in-memory map.  Allows the next transfer to the same
    /// counterparty without hitting the "existing session" guard.
    pub async fn clear_terminal_sessions(&self) {
        let mut sessions = self.sessions.sessions.lock().await;
        sessions.retain(|_, s| {
            matches!(
                s.phase,
                BilateralPhase::Preparing
                    | BilateralPhase::Prepared
                    | BilateralPhase::PendingUserAction
            )
        });
    }

    /// Get session status with core manager reconciliation
    pub async fn get_session_status(&self, commitment_hash: &[u8; 32]) -> Option<BilateralPhase> {
        // Try direct lookup only - single hash space
        let sessions = self.sessions.sessions.lock().await;
        let session = match sessions.get(commitment_hash) {
            Some(s) => s.clone(),
            None => return None,
        };

        // Reconcile with core manager's pending commitments
        let manager = self.bilateral_tx_manager.read().await;
        let pending_key = session
            .local_commitment_hash
            .unwrap_or(session.commitment_hash);
        let core_has_commitment = manager.has_pending_commitment(&pending_key);

        if session.phase == BilateralPhase::Committed && core_has_commitment {
            warn!("Inconsistent state: BLE session committed but core has pending commitment");
        }

        Some(session.phase.clone())
    }

    /// Reconcile BLE sessions with core manager state
    pub async fn reconcile_session_state(&self) -> Result<usize, DsmError> {
        let mut sessions = self.sessions.sessions.lock().await;
        let manager = self.bilateral_tx_manager.read().await;
        let mut reconciled = 0;

        // Remove sessions for commitments that no longer exist in core
        sessions.retain(|_commitment_hash, session| {
            let pending_key = session
                .local_commitment_hash
                .unwrap_or(session.commitment_hash);
            let core_has_commitment = manager.has_pending_commitment(&pending_key);

            if !core_has_commitment && session.phase != BilateralPhase::Committed {
                debug!("Removing orphaned BLE session");
                reconciled += 1;
                false
            } else {
                true
            }
        });

        Ok(reconciled)
    }

    /// Perform comprehensive session maintenance (cleanup + reconciliation + recovery)
    pub async fn maintain_sessions(&self) -> Result<(usize, usize), DsmError> {
        let cleaned = self.cleanup_expired_sessions().await;
        let reconciled = self.reconcile_session_state().await?;
        if cleaned > 0 || reconciled > 0 {
            info!("Session maintenance: cleaned={cleaned}, reconciled={reconciled}");
        }
        Ok((cleaned, reconciled))
    }

    /// §5.3 Re-deliver any pending confirm envelopes to the given counterparty.
    /// Called on BLE reconnect and before new transfers to catch confirms that
    /// were finalized locally but never delivered over BLE (crash or disconnect).
    /// Returns the confirm envelope bytes if one was found, or None.
    pub async fn get_pending_confirm_for_counterparty(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> Option<Vec<u8>> {
        match crate::storage::client_db::get_pending_confirm_deliveries(counterparty_device_id) {
            Ok(pending) => {
                if let Some((_commitment_hash, confirm_envelope)) = pending.into_iter().next() {
                    info!(
                        "[BILATERAL] §5.3 Found pending confirm for re-delivery to {}",
                        bytes_to_base32(&counterparty_device_id[..8])
                    );
                    Some(confirm_envelope)
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(
                    "[BILATERAL] Failed to query pending confirm deliveries: {}",
                    e
                );
                None
            }
        }
    }

    /// Delete a pending confirm delivery after successful BLE send.
    pub fn clear_pending_confirm_delivery(&self, commitment_hash: &[u8; 32]) {
        if let Err(e) = crate::storage::client_db::delete_pending_confirm_delivery(commitment_hash)
        {
            warn!(
                "[BILATERAL] Failed to delete pending confirm delivery: {}",
                e
            );
        }
    }

    /// Mark any Accepted sessions as Committed (test helper)
    pub async fn mark_sender_committed_after_ack(&self) {
        let mut sessions = self.sessions.sessions.lock().await;
        for (_k, sess) in sessions.iter_mut() {
            if sess.phase == BilateralPhase::Accepted {
                sess.phase = BilateralPhase::Committed;
            }
        }
    }

    /// Precisely mark a single session committed by commitment id, optionally using
    /// a post_state_hash (for session recovery on restart).
    pub async fn mark_sender_committed_with_post_state_hash(
        &self,
        commitment_hash: &[u8; 32],
        post_state_hash: Option<[u8; 32]>,
    ) -> Option<crate::sdk::transfer_hooks::TransferMeta> {
        info!("Marking session committed and finalizing sender transaction");

        // Get session info before locking manager
        let (
            counterparty_device_id,
            counterparty_sig,
            session_operation,
            pre_entropy,
            cached_receipt,
        ) = {
            let sessions = self.sessions.sessions.lock().await;
            let sess = match sessions.get(commitment_hash) {
                Some(s) => s,
                None => {
                    warn!("No session found for provided commitment");
                    return None;
                }
            };

            let sig = match &sess.counterparty_signature {
                Some(s) => s.clone(),
                None => {
                    warn!("No counterparty signature in session");
                    return None;
                }
            };

            (
                sess.counterparty_device_id,
                sig,
                sess.operation.clone(),
                sess.pre_finalize_entropy,
                sess.stitched_receipt_bytes.clone(),
            )
        };

        // Obtain event display metadata from the delegate so we can populate
        // completion events without inspecting token-specific Operation fields.
        let op_bytes = session_operation.to_bytes();
        let (event_amount_opt, event_token_id_opt) = if let Some(ref d) = self.settlement_delegate {
            d.operation_metadata(&op_bytes)
        } else {
            (None, None)
        };

        // Phase 1: BTM prepare — §6.1 tripwire + entropy resolve. No SMT mutation.
        let prepared = {
            let mut manager = self.bilateral_tx_manager.write().await;

            // Re-sync BTM in-memory chain tip from SQLite before prepare.
            // An online transfer (wallet.send) may have advanced the SQLite tip
            // without updating the BTM, causing ParentConsumed.
            if let Some(sqlite_tip) =
                crate::storage::client_db::get_contact_chain_tip_raw(&counterparty_device_id)
            {
                manager.advance_chain_tip(&counterparty_device_id, sqlite_tip);
                info!(
                    "[BILATERAL] Re-synced BTM chain tip from SQLite before sender prepare: {}",
                    bytes_to_base32(&sqlite_tip[..8])
                );
            }

            // Derive sender-side debit deltas from the session operation.
            // The canonical advance applies these to DeviceState balances
            // atomically with the SMT leaf update (§8 balance binding).
            let sender_deltas: Vec<dsm::types::device_state::BalanceDelta> =
                match &session_operation {
                    Operation::Transfer {
                        amount, token_id, ..
                    } => {
                        let tid = std::str::from_utf8(token_id).unwrap_or("");
                        if tid.is_empty() {
                            Vec::new()
                        } else {
                            let pc =
                                dsm::core::token::token_state_manager::resolve_policy_commit(tid);
                            vec![dsm::types::device_state::BalanceDelta {
                                policy_commit: pc,
                                direction: dsm::types::device_state::BalanceDirection::Debit,
                                amount: amount.value(),
                            }]
                        }
                    }
                    _ => Vec::new(),
                };

            match manager
                .prepare_bilateral_advance(
                    &counterparty_device_id,
                    commitment_hash,
                    &counterparty_sig,
                    pre_entropy,
                    sender_deltas,
                )
                .await
            {
                Ok(p) => p,
                Err(prepare_err) => {
                    drop(manager);
                    warn!(
                        "[BILATERAL] prepare_bilateral_advance failed: {} — entering recovery path",
                        prepare_err
                    );
                    return self
                        .finalize_sender_recovery(
                            commitment_hash,
                            &counterparty_device_id,
                            post_state_hash,
                            &op_bytes,
                            event_amount_opt,
                            event_token_id_opt,
                        )
                        .await;
                }
            }
        };

        // Phase 2: commit via canonical advance chokepoint
        // (§2.2 Per-Device SMT, §4.3 acceptance, §8 balance binding).
        let router = match crate::bridge::app_router() {
            Some(r) => r,
            None => {
                error!("[BILATERAL] app_router not installed; cannot commit BLE bilateral advance");
                self.emit_event(&generated::BilateralEventNotification {
                    event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                    counterparty_device_id: counterparty_device_id.to_vec(),
                    commitment_hash: commitment_hash.to_vec(),
                    transaction_hash: None,
                    amount: event_amount_opt,
                    token_id: event_token_id_opt.clone(),
                    status: "failed".to_string(),
                    message: "App router unavailable for BLE bilateral commit".to_string(),
                    sender_ble_address: None,
                    failure_reason: Some(
                        generated::BilateralFailureReason::FailureReasonProtocolViolation as i32,
                    ),
                });
                return None;
            }
        };

        let outcome = match router.execute_on_relationship_for_bilateral(
            prepared.rel_key,
            prepared.counterparty_devid,
            prepared.operation.clone(),
            &prepared.deltas,
            Some(prepared.parent_tip),
        ) {
            Ok(o) => o,
            Err(advance_err) => {
                error!(
                    "[BILATERAL] execute_on_relationship_for_bilateral failed: {}",
                    advance_err
                );
                self.emit_event(&generated::BilateralEventNotification {
                    event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                    counterparty_device_id: counterparty_device_id.to_vec(),
                    commitment_hash: commitment_hash.to_vec(),
                    transaction_hash: None,
                    amount: event_amount_opt,
                    token_id: event_token_id_opt.clone(),
                    status: "failed".to_string(),
                    message: format!("Bilateral advance commit failed: {advance_err}"),
                    sender_ble_address: None,
                    failure_reason: Some(
                        generated::BilateralFailureReason::FailureReasonProtocolViolation as i32,
                    ),
                });
                return None;
            }
        };

        // Phase 3: post-commit — drop pending precommitment.
        {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager.consume_pre_commitment(commitment_hash);
        }

        // h_{n+1} symmetric (§16.6) — shared pair tip for contacts.chain_tip
        // + tripwire precommit + b0x addressing. Derivable by both parties.
        let receipt_sigma = compute_precommit(&prepared.parent_tip, &op_bytes, &prepared.entropy);
        let h_next_symmetric = compute_successor_tip(
            &prepared.parent_tip,
            &op_bytes,
            &prepared.entropy,
            &receipt_sigma,
        );
        // h_{n+1} asymmetric (A-side) — what T_A now stores at k_{A↔B}.
        let h_next_asymmetric = outcome.new_chain_state.compute_chain_tip();
        // h_n asymmetric (A-side) — previous T_A leaf value; zeros if first advance.
        let parent_tip_asymmetric = outcome.smt_proofs.parent_proof.value.unwrap_or([0u8; 32]);
        // Transaction hash for display / events = symmetric successor tip.
        let transaction_hash = h_next_symmetric;

        info!(
            "Sender advance committed via canonical chokepoint, tx_hash: {:?}",
            bytes_to_base32(&transaction_hash)
        );

        // Record the receiver's observed post-state tip (matches our h_{n+1} symmetric).
        if let Some(post_tip) = post_state_hash {
            info!(
                "[BILATERAL] Sender recording receiver-reported post_state_hash: {}",
                bytes_to_base32(&post_tip[..8])
            );
            if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                &counterparty_device_id,
                &post_tip,
                crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
            ) {
                warn!(
                    "[BILATERAL] Failed to persist observed receiver post_state_hash: {}",
                    e
                );
            }
        }

        // Note: contacts.chain_tip + local_bilateral_chain_tip advancement is
        // now owned by the delegate's `apply_bilateral_settlement_bundle_atomic`
        // call (Step 7) — projection + history + tip CAS in one SQL tx. The
        // old `sync_bilateral_tips_atomically` tip-write path is redundant.
        // Stale `pending_online_outbox` gate clearing still lives below after
        // settlement via `clear_pending_online_outbox_if_matches`.

        // --- DELEGATE SETTLEMENT (post-advance projection + history + tip) ---
        log::info!("[BILATERAL] Entering settlement block after advance commit");
        // Use the cached receipt from send_bilateral_confirm when available
        // (built with real pre/post SMT roots + proofs). Fall back to building
        // from the AdvanceOutcome when the session had no cached receipt
        // (e.g. restored from storage after a crash).
        let receipt_bytes: Option<Vec<u8>> = if cached_receipt.is_some() {
            cached_receipt
        } else {
            log::warn!("[BILATERAL] No cached receipt in session — building from AdvanceOutcome");
            crate::sdk::receipts::build_bilateral_receipt_with_smt(
                self.device_id,
                counterparty_device_id,
                parent_tip_asymmetric,
                h_next_asymmetric,
                outcome.smt_proofs.pre_root,
                outcome.child_r_a,
                crate::sdk::receipts::serialize_inclusion_proof(&outcome.smt_proofs.parent_proof),
                crate::sdk::receipts::serialize_inclusion_proof(&outcome.smt_proofs.child_proof),
                Some(local_device_tree_commitment(&self.device_id)),
            )
        };

        log::info!(
            "[BILATERAL] Settlement delegate present: {}",
            self.settlement_delegate.is_some()
        );
        if let Some(ref delegate) = self.settlement_delegate {
            // Canonical advance already applied sender-side debit to the
            // DeviceState head inside `StateMachine::commit_advance`. The
            // delegate here materialises the display-layer projection into
            // SQLite + records the tx_history entry. It no longer mutates
            // the canonical balance.
            let ctx = BilateralSettlementContext {
                local_device_id: self.device_id,
                counterparty_device_id,
                commitment_hash: *commitment_hash,
                transaction_hash,
                operation_bytes: op_bytes.clone(),
                proof_data: receipt_bytes,
                is_sender: true,
                tx_type: "bilateral_offline",
                new_chain_tip: h_next_symmetric,
            };
            if let Err(e) = delegate.settle(ctx) {
                log::error!(
                    "[BILATERAL] Sender settlement FAILED after advance commit: {e}. Canonical head is advanced; projection + history may lag."
                );
                self.emit_event(&generated::BilateralEventNotification {
                    event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                    counterparty_device_id: counterparty_device_id.to_vec(),
                    commitment_hash: commitment_hash.to_vec(),
                    transaction_hash: Some(transaction_hash.to_vec()),
                    amount: event_amount_opt,
                    token_id: event_token_id_opt.clone(),
                    status: "failed".to_string(),
                    message: format!("Sender settlement failed after advance commit: {e}"),
                    sender_ble_address: None,
                    failure_reason: Some(
                        generated::BilateralFailureReason::FailureReasonProtocolViolation as i32,
                    ),
                });
                return None;
            }
        }

        if let Some(router) = crate::bridge::app_router() {
            router.sync_balance_cache();
        }

        // Update session phase and cleanup storage.
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(sess) = sessions.get_mut(commitment_hash) {
                sess.phase = BilateralPhase::Committed;
                info!("Session phase updated to Committed");
            }
        }

        if let Err(e) = delete_bilateral_session(commitment_hash) {
            warn!(
                "[BLE_HANDLER] Failed to delete completed session from storage (sender): {}",
                e
            );
        }

        self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
            .await;

        // §5.4: clear stale pending_online_outbox gate on successful commit.
        if let Ok(Some(stale_gate)) =
            crate::storage::client_db::get_pending_online_outbox(&counterparty_device_id)
        {
            let gate_parent: [u8; 32] = stale_gate
                .parent_tip
                .as_slice()
                .try_into()
                .unwrap_or([0u8; 32]);
            let gate_next: [u8; 32] = stale_gate
                .next_tip
                .as_slice()
                .try_into()
                .unwrap_or([0u8; 32]);
            info!(
                "[BILATERAL] Clearing stale pending_online_outbox for {} after successful BLE commit",
                bytes_to_base32(&counterparty_device_id[..8]),
            );
            if let Err(e) = crate::storage::client_db::clear_pending_online_outbox_if_matches(
                &counterparty_device_id,
                &gate_parent,
                &gate_next,
            ) {
                warn!(
                    "[BILATERAL] Failed to clear stale pending_online_outbox for {} (sender): {}",
                    bytes_to_base32(&counterparty_device_id[..8]),
                    e,
                );
            }
        }

        // Emit transfer_complete event to frontend (sender side).
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: Some(transaction_hash.to_vec()),
            amount: event_amount_opt,
            token_id: event_token_id_opt.clone(),
            status: "completed".to_string(),
            message: "Bilateral transfer completed successfully".to_string(),
            sender_ble_address: None,
            failure_reason: None,
        });

        // Return transfer metadata for orchestration layer to run post-transfer hooks.
        // Use the metadata already resolved by the delegate.
        Some(crate::sdk::transfer_hooks::TransferMeta {
            token_id: event_token_id_opt.unwrap_or_default(),
            amount: event_amount_opt.unwrap_or(0),
        })
    }

    /// Recovery path used when BTM `prepare_bilateral_advance` fails — the
    /// usual cause is a pre-commitment that expired or was missing after an
    /// app restart. The canonical advance is skipped, but the settlement
    /// delegate is still invoked (with `proof_data: None`) so tx history and
    /// session state do not drift.
    async fn finalize_sender_recovery(
        &self,
        commitment_hash: &[u8; 32],
        counterparty_device_id: &[u8; 32],
        post_state_hash: Option<[u8; 32]>,
        op_bytes: &[u8],
        event_amount_opt: Option<u64>,
        event_token_id_opt: Option<String>,
    ) -> Option<crate::sdk::transfer_hooks::TransferMeta> {
        warn!("[BILATERAL RECOVERY] Proceeding with settlement without canonical advance commit");

        if let Some(post_tip) = post_state_hash {
            info!(
                "[BILATERAL RECOVERY] Recording receiver post_state_hash during recovery: {}",
                bytes_to_base32(&post_tip[..8])
            );
            if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                counterparty_device_id,
                &post_tip,
                crate::storage::client_db::ObservedRemoteTipSource::LivePeerClaim,
            ) {
                warn!(
                    "[BILATERAL RECOVERY] Failed to persist observed receiver post_state_hash: {}",
                    e
                );
            }
        }

        if let Some(ref delegate) = self.settlement_delegate {
            let ctx = BilateralSettlementContext {
                local_device_id: self.device_id,
                counterparty_device_id: *counterparty_device_id,
                commitment_hash: *commitment_hash,
                transaction_hash: *commitment_hash,
                operation_bytes: op_bytes.to_vec(),
                proof_data: None,
                is_sender: true,
                tx_type: "bilateral_offline_recovered",
                new_chain_tip: [0u8; 32],
            };
            match delegate.settle(ctx) {
                Ok(_outcome) => {
                    if let Some(router) = crate::bridge::app_router() {
                        router.sync_balance_cache();
                    }
                    info!("[BILATERAL RECOVERY] Transaction stored to history");
                }
                Err(e) => {
                    warn!("[BILATERAL RECOVERY] Sender settlement failed (recovery path): {e}");
                    self.emit_event(&generated::BilateralEventNotification {
                        event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                        counterparty_device_id: counterparty_device_id.to_vec(),
                        commitment_hash: commitment_hash.to_vec(),
                        transaction_hash: None,
                        amount: event_amount_opt,
                        token_id: event_token_id_opt.clone(),
                        status: "failed".to_string(),
                        message: format!("Sender settlement failed (recovery path): {e}"),
                        sender_ble_address: None,
                        failure_reason: Some(
                            generated::BilateralFailureReason::FailureReasonProtocolViolation
                                as i32,
                        ),
                    });
                    return None;
                }
            }
        }

        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(sess) = sessions.get_mut(commitment_hash) {
                sess.phase = BilateralPhase::Committed;
                info!("[BILATERAL RECOVERY] Session phase updated to Committed");
            }
        }

        if let Err(e) = delete_bilateral_session(commitment_hash) {
            warn!(
                "[BILATERAL RECOVERY] Failed to delete completed session from storage: {}",
                e
            );
        }

        self.prune_terminal_sessions_for_counterparty(counterparty_device_id)
            .await;

        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: Some(commitment_hash.to_vec()),
            amount: event_amount_opt,
            token_id: event_token_id_opt.clone(),
            status: "recovered".to_string(),
            message: "Bilateral transfer recovered from interrupted session".to_string(),
            sender_ble_address: None,
            failure_reason: None,
        });

        Some(crate::sdk::transfer_hooks::TransferMeta {
            token_id: event_token_id_opt.unwrap_or_default(),
            amount: event_amount_opt.unwrap_or(0),
        })
    }

    /// Lookup the counterparty device id for a given commitment hash
    pub async fn get_counterparty_for_commitment(
        &self,
        commitment_hash: &[u8; 32],
    ) -> Option<[u8; 32]> {
        let sessions = self.sessions.sessions.lock().await;
        sessions
            .get(commitment_hash)
            .map(|s| s.counterparty_device_id)
    }

    /// Get a complete session for a given commitment hash (including alias resolution)
    pub async fn get_session_for_commitment(
        &self,
        commitment_hash: &[u8; 32],
    ) -> Option<BilateralBleSession> {
        let sessions = self.sessions.sessions.lock().await;
        sessions.get(commitment_hash).cloned()
    }

    /// Get the bilateral transaction manager (for querying state hashes and ticks)
    pub fn bilateral_tx_manager(&self) -> &Arc<RwLock<BilateralTransactionManager>> {
        &self.bilateral_tx_manager
    }

    /// Per-Device SMT for relationship chain tips (§18.1)
    pub fn per_device_smt(
        &self,
    ) -> &Arc<RwLock<dsm::merkle::sparse_merkle_tree::SparseMerkleTree>> {
        &self.per_device_smt
    }

    /// Handle a BLE peer disconnect event for a given BLE address.
    ///
    /// When the BLE link drops, any in-flight bilateral session bound to that peer is
    /// failed so the next attempt restarts from prepare instead of resuming mid-flight.
    ///
    /// Returns the number of sessions transitioned to Failed.
    pub async fn handle_peer_disconnected(&self, ble_address: &str) -> usize {
        let candidates: Vec<([u8; 32], [u8; 32], Option<String>, BilateralPhase)> = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .iter()
                .map(|(commitment_hash, session)| {
                    (
                        *commitment_hash,
                        session.counterparty_device_id,
                        session.sender_ble_address.clone(),
                        session.phase.clone(),
                    )
                })
                .collect()
        };

        let mut failed_count = 0usize;
        for (commitment_hash, counterparty_device_id, sender_ble_address, phase) in candidates {
            if !is_inflight_phase(&phase) {
                continue;
            }

            let sender_addr_match = sender_ble_address.as_deref() == Some(ble_address);
            let counterparty_addr_match =
                crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
                    .ok()
                    .flatten()
                    .and_then(|contact| contact.ble_address)
                    .as_deref()
                    == Some(ble_address);

            if !(sender_addr_match || counterparty_addr_match) {
                continue;
            }

            if self
                .fail_session_by_commitment(
                    commitment_hash,
                    &format!("BLE link to {ble_address} dropped before terminal acknowledgment"),
                )
                .await
            {
                failed_count += 1;
            }
        }

        if failed_count > 0 {
            info!(
                "[BLE_HANDLER] Marked {} in-flight session(s) Failed on disconnect from {}",
                failed_count, ble_address
            );
        } else {
            debug!(
                "[BLE_HANDLER] Peer {} disconnected — no in-flight bilateral sessions matched",
                ble_address
            );
        }

        failed_count
    }

    /// Test helper: insert a fully constructed session (bypassing normal flow).
    /// Marked `#[doc(hidden)]` to discourage production use; primarily for
    /// integration tests that need to seed specific session states.
    #[doc(hidden)]
    pub async fn test_insert_session(&self, session: BilateralBleSession) {
        let mut sessions = self.sessions.sessions.lock().await;
        sessions.insert(session.commitment_hash, session);
    }

    /// Register a sender session for a prepared bilateral transaction.
    /// This is called by the JNI layer when the frontend initiates a bilateral send
    /// via `bilateralOfflineSend`. The session tracks the commitment hash so that
    /// when the receiver's response arrives (via BLE), we can look up the session
    /// and continue the commit phase.
    ///
    /// # Arguments
    /// * `commitment_hash` - The 32-byte commitment hash computed for this transfer
    /// * `counterparty_device_id` - The 32-byte device ID of the recipient
    /// * `operation_data` - The serialized operation (transfer details)
    /// * `validity_ticks` - Number of ticks the session is valid for
    ///
    /// Returns the canonical bilateral commitment hash computed by the manager.
    /// This hash should be injected into the UniversalOp.op_id before sending.
    pub async fn register_sender_session(
        &self,
        _commitment_hash: [u8; 32], // Ignored - we compute canonical hash from manager
        counterparty_device_id: [u8; 32],
        operation_data: &[u8],
        validity_ticks: u64,
    ) -> Result<[u8; 32], DsmError> {
        // Deserialize operation from bytes
        let operation =
            dsm::types::operations::Operation::from_bytes(operation_data).map_err(|e| {
                DsmError::serialization_error(
                    "register_sender_session",
                    "operation_data",
                    Some(format!("failed to deserialize operation: {}", e)),
                    None::<std::io::Error>,
                )
            })?;

        // Ensure relationship + create a matching pre-commitment in the core manager.
        // This ensures the core has a pending commitment (used during finalization)
        // and that relationship chain-tips exist for commit-time validation.
        let computed_hash = {
            let mut mgr = self.bilateral_tx_manager.write().await;

            // Ensure contact exists and relationship is initialized (idempotent)
            if !mgr.has_verified_contact(&counterparty_device_id) {
                // Just-in-time sync from SQLite before failing
                let synced = match crate::storage::client_db::get_contact_by_device_id(
                    &counterparty_device_id,
                ) {
                    Ok(Some(record)) => record
                        .to_verified_contact()
                        .and_then(|v| mgr.add_verified_contact(v).ok())
                        .is_some(),
                    _ => false,
                };
                if !synced {
                    return Err(DsmError::invalid_operation(
                        "Cannot register sender session without a verified contact",
                    ));
                }
                log::warn!(
                    "[BLE_HANDLER] ✅ Just-in-time contact sync for register_sender_session"
                );
            }

            // create_bilateral_precommitment now STRICTLY requires that the contact
            // contains a signing public key. Fail fast with a clear error if the
            // contact is missing the signing key rather than silently proceeding.
            if let Some(c) = mgr.get_contact(&counterparty_device_id) {
                if c.public_key.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "Cannot register sender session: remote contact missing signing key",
                    ));
                }
            } else {
                return Err(DsmError::invalid_operation(
                    "Cannot register sender session: contact lookup failed",
                ));
            }

            if mgr.get_relationship(&counterparty_device_id).is_none() {
                // Try lenient relationship initialization for sender: do not fail
                // when contact signing key is missing. This mirrors ensure_relationship_for_sender
                // in the core manager and allows sender precommitments to be created.
                match mgr.ensure_relationship_for_sender(&counterparty_device_id) {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(DsmError::relationship(format!(
                            "Failed to ensure relationship during register_sender_session: {}",
                            e
                        )));
                    }
                }
            }

            // Create a canonical precommitment inside the manager so that finalize_offline_transfer
            // can find it later. Use the provided validity_ticks. If the manager computes a different
            // commitment hash than the one supplied, we'll keep the manager's canonical one and
            // create an alias mapping so incoming responses can be resolved.
            let counterparty_genesis_from_mgr = mgr
                .get_contact(&counterparty_device_id)
                .map(|c| c.genesis_hash);

            let pre = mgr
                .create_bilateral_precommitment(
                    &counterparty_device_id,
                    operation.clone(),
                    validity_ticks,
                )
                .await
                .map_err(|e| {
                    DsmError::invalid_operation(format!("failed to create precommitment: {}", e))
                })?;

            let canonical = pre.bilateral_commitment_hash;

            // Use the signature generated during precommitment (stronger source of truth)
            // and ensure the session expiry is derived from pre.expires_at
            (
                (
                    canonical,
                    pre.local_signature.clone(),
                    pre.created_at,
                    pre.expires_at,
                ),
                counterparty_genesis_from_mgr,
            )
        };

        // computed_hash.0 = bilateral hash, .1 = local_signature, .2 = created_at, .3 = expires_at
        let (computed_hash, counterparty_genesis_from_mgr) = computed_hash;
        let (canonical_hash, local_sig, created_ticks, expires_ticks) = computed_hash;

        let counterparty_genesis_hash = counterparty_genesis_from_mgr;

        // Build sender session using the manager's canonical precommitment values.
        let session = BilateralBleSession {
            commitment_hash: canonical_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash,
            operation,
            phase: BilateralPhase::Prepared, // Sender has already prepared and is sending
            local_signature: Some(local_sig), // CRITICAL: Include signature for commit phase
            counterparty_signature: None,
            created_at_ticks: created_ticks,
            expires_at_ticks: expires_ticks,
            sender_ble_address: None, // Sender side doesn't need this
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
        };

        // Insert into active sessions
        {
            let mut sessions = self.sessions.sessions.lock().await;
            let hex_hash = bytes_to_base32(&session.commitment_hash[..8]);

            // Check if session already exists (idempotent) - use canonical hash, not input
            if sessions.contains_key(&canonical_hash) {
                info!(
                    "[BLE_HANDLER] register_sender_session: session {} already exists, skipping",
                    hex_hash
                );
                return Ok(canonical_hash);
            }

            sessions.insert(session.commitment_hash, session.clone());
            info!(
                "[BLE_HANDLER] register_sender_session: ✅ REGISTERED sender session commitment={} counterparty={} expires_at={}",
                hex_hash,
                bytes_to_base32(&counterparty_device_id[..8]),
                session.expires_at_ticks
            );
            info!(
                "[BLE_HANDLER] register_sender_session: active_sessions count={}, keys={:?}",
                sessions.len(),
                sessions
                    .keys()
                    .map(|k| bytes_to_base32(&k[..8]))
                    .collect::<Vec<_>>()
            );
        }

        // Persist session to storage
        self.persist_session(&session, None)
            .await
            .map_err(|e| DsmError::storage(format!("failed to persist session: {}", e), Some(e)))?;

        Ok(canonical_hash)
    }

    // Helper methods

    /// Create an envelope with headers derived from the core manager state.
    /// Message ID is deterministic (BLAKE3 over device/genesis/tip/ticks), not random.
    async fn create_envelope_with_tip(
        &self,
        payload: generated::envelope::Payload,
        chain_tip_override: Option<[u8; 32]>,
    ) -> Result<generated::Envelope, DsmError> {
        let (genesis_hash, ticks) = {
            let mgr = self.bilateral_tx_manager.read().await;
            (mgr.local_genesis_hash(), mgr.get_current_ticks())
        };
        super::bilateral_envelope::build_envelope(
            &self.device_id,
            &genesis_hash,
            ticks,
            chain_tip_override,
            payload,
        )
    }

    #[allow(dead_code)]
    async fn create_envelope(
        &self,
        payload: generated::envelope::Payload,
    ) -> Result<generated::Envelope, DsmError> {
        self.create_envelope_with_tip(payload, None).await
    }

    fn extract_prepare_request(
        &self,
        envelope: &generated::Envelope,
    ) -> Result<generated::BilateralPrepareRequest, DsmError> {
        super::bilateral_envelope::extract_prepare_request(envelope)
    }

    fn extract_confirm_request(
        &self,
        envelope: &generated::Envelope,
    ) -> Result<generated::BilateralConfirmRequest, DsmError> {
        super::bilateral_envelope::extract_confirm_request(envelope)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use dsm::core::contact_manager::DsmContactManager;
    use dsm::crypto::signatures::SignatureKeyPair;
    use dsm::types::identifiers::NodeId;
    use dsm::types::operations::{TransactionMode, VerificationType};
    use dsm::types::token_types::Balance;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_test_handler(
        device_id: [u8; 32],
        genesis_hash: [u8; 32],
        entropy: &[u8],
    ) -> (
        Arc<RwLock<BilateralTransactionManager>>,
        BilateralBleHandler,
    ) {
        let keypair = SignatureKeyPair::generate_from_entropy(entropy).expect("keypair");
        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);
        (bilateral_manager, handler)
    }

    #[tokio::test]
    async fn test_bilateral_ble_session_lifecycle() {
        // Setup - Generate proper cryptographic keypair based on test identity
        let device_id = [1u8; 32];
        let genesis_hash = [2u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = match SignatureKeyPair::generate_from_entropy(&key_entropy) {
            Ok(kp) => kp,
            Err(e) => panic!("keypair generation failed in test: {}", e),
        };

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));

        let handler = BilateralBleHandler::new(bilateral_manager, device_id);

        // Test session creation and cleanup
        let sessions_count = { handler.sessions.sessions.lock().await.len() };
        assert_eq!(sessions_count, 0);

        // Test cleanup of empty sessions
        let cleaned = handler.cleanup_expired_sessions().await;
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn test_core_manager_integration() {
        // Setup - Generate proper cryptographic keypair based on test identity
        let device_id = [1u8; 32];
        let genesis_hash = [2u8; 32];
        let key_entropy = [device_id.as_slice(), genesis_hash.as_slice()].concat();
        let keypair = match SignatureKeyPair::generate_from_entropy(&key_entropy) {
            Ok(kp) => kp,
            Err(e) => panic!("keypair generation failed in test: {}", e),
        };

        let counterparty_device_id = [3u8; 32];
        let counterparty_genesis = [4u8; 32];

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));

        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        // Add a test contact with all required fields
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "test_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![7u8; 32],
            genesis_material: vec![5u8; 32],
            chain_tip: Some([6u8; 32]),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1000,
            added_at_commit_height: 1000,
            last_updated_commit_height: 1000,
            verifying_storage_nodes: vec![],
            ble_address: Some(String::new()),
        };

        {
            let mut manager = bilateral_manager.write().await;
            if let Err(e) = manager.add_verified_contact(contact) {
                panic!("add_verified_contact failed in test: {}", e);
            }
        }

        // Test that prepare_bilateral_transaction calls into core manager
        let operation = Operation::Noop;

        let result = handler
            .prepare_bilateral_transaction(counterparty_device_id, operation.clone(), 1000)
            .await;

        match result {
            Ok(_) => {
                let manager = bilateral_manager.read().await;
                let pending_commitments = manager.list_pending_commitments();
                assert!(
                    !pending_commitments.is_empty(),
                    "Core manager should have pending commitment"
                );
            }
            Err(_e) => {
                // Relationship establishment may be required and fail in some environments
            }
        }

        // Test session reconciliation
        let (cleaned, reconciled) = match handler.maintain_sessions().await {
            Ok(v) => v,
            Err(e) => panic!("maintain_sessions failed in test: {}", e),
        };
        assert_eq!(cleaned, 0); // No expired sessions
        let _ = reconciled; // allow either path
    }

    #[tokio::test]
    async fn test_stale_receiver_session_cleans_local_pending_commitment() {
        let device_id = [31u8; 32];
        let genesis_hash = [32u8; 32];
        let counterparty_device_id = [33u8; 32];
        let counterparty_genesis = [34u8; 32];
        let keypair = SignatureKeyPair::generate_from_entropy(b"stale-local-pending-cleanup")
            .expect("keypair");

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "stale_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![9u8; 32],
            genesis_material: vec![8u8; 32],
            chain_tip: Some([7u8; 32]),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        {
            let mut mgr = bilateral_manager.write().await;
            mgr.add_verified_contact(contact).expect("add contact");
            let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
            mgr.establish_relationship(&counterparty_device_id, &mut smt)
                .await
                .expect("establish relationship");
        }

        let stale_op = Operation::Transfer {
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::from_state(1, [1u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "stale".to_string(),
            signature: Vec::new(),
        };
        let next_op = Operation::Transfer {
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::from_state(1, [1u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![2],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "fresh".to_string(),
            signature: Vec::new(),
        };

        let local_pending_hash = {
            let mut mgr = bilateral_manager.write().await;
            let pre = mgr
                .prepare_offline_transfer(&counterparty_device_id, stale_op.clone(), 120)
                .await
                .expect("prepare local pending");
            pre.bilateral_commitment_hash
        };
        assert!(
            bilateral_manager
                .read()
                .await
                .has_pending_commitment(&local_pending_hash),
            "receiver-local pending commitment should exist before stale cleanup"
        );

        handler
            .test_insert_session(BilateralBleSession {
                commitment_hash: [91u8; 32],
                local_commitment_hash: Some(local_pending_hash),
                counterparty_device_id,
                counterparty_genesis_hash: Some(counterparty_genesis),
                operation: stale_op,
                phase: BilateralPhase::PendingUserAction,
                local_signature: None,
                counterparty_signature: None,
                created_at_ticks: 1,
                expires_at_ticks: 2,
                sender_ble_address: None,
                created_at_wall: Instant::now() - Duration::from_secs(121),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
            })
            .await;

        handler
            .prepare_bilateral_transaction(counterparty_device_id, next_op, 120)
            .await
            .expect("fresh prepare should supersede stale session");

        assert!(
            !bilateral_manager
                .read()
                .await
                .has_pending_commitment(&local_pending_hash),
            "stale cleanup must remove the receiver-local pending commitment key"
        );
    }

    #[tokio::test]
    async fn test_fail_session_by_commitment_cleans_receiver_accepted_session() {
        let device_id = [41u8; 32];
        let genesis_hash = [42u8; 32];
        let counterparty_device_id = [43u8; 32];
        let counterparty_genesis = [44u8; 32];
        let keypair =
            SignatureKeyPair::generate_from_entropy(b"fail-accepted-session").expect("keypair");

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "accepted_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![9u8; 32],
            genesis_material: vec![8u8; 32],
            chain_tip: Some([7u8; 32]),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        };

        {
            let mut mgr = bilateral_manager.write().await;
            mgr.add_verified_contact(contact).expect("add contact");
            let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
            mgr.establish_relationship(&counterparty_device_id, &mut smt)
                .await
                .expect("establish relationship");
        }

        let accepted_op = Operation::Transfer {
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::from_state(1, [1u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1],
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "accepted".to_string(),
            signature: Vec::new(),
        };

        let local_pending_hash = {
            let mut mgr = bilateral_manager.write().await;
            let pre = mgr
                .prepare_offline_transfer(&counterparty_device_id, accepted_op.clone(), 120)
                .await
                .expect("prepare local pending");
            pre.bilateral_commitment_hash
        };
        let receiver_commitment_hash = [92u8; 32];

        handler
            .test_insert_session(BilateralBleSession {
                commitment_hash: receiver_commitment_hash,
                local_commitment_hash: Some(local_pending_hash),
                counterparty_device_id,
                counterparty_genesis_hash: Some(counterparty_genesis),
                operation: accepted_op,
                phase: BilateralPhase::Accepted,
                local_signature: Some(vec![1u8; 32]),
                counterparty_signature: None,
                created_at_ticks: 1,
                expires_at_ticks: 2,
                sender_ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
            })
            .await;

        assert!(
            handler
                .fail_session_by_commitment(
                    receiver_commitment_hash,
                    "receiver accept send failed before completion"
                )
                .await,
            "accepted receiver session should be failed"
        );

        assert!(
            handler
                .get_session_status(&receiver_commitment_hash)
                .await
                .is_none(),
            "failed session should be removed from active map"
        );
        assert!(
            !bilateral_manager
                .read()
                .await
                .has_pending_commitment(&local_pending_hash),
            "failed accepted session must remove the receiver-local pending commitment key"
        );
    }

    #[tokio::test]
    async fn test_fail_session_by_commitment_preserves_other_inflight_session_for_same_counterparty(
    ) {
        let device_id = [51u8; 32];
        let genesis_hash = [52u8; 32];
        let counterparty_device_id = [53u8; 32];
        let keypair =
            SignatureKeyPair::generate_from_entropy(b"targeted-fail-cleanup").expect("keypair");

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));
        let handler = BilateralBleHandler::new(bilateral_manager, device_id);

        let failed_commitment = [61u8; 32];
        let surviving_commitment = [62u8; 32];

        handler
            .test_insert_session(BilateralBleSession {
                commitment_hash: failed_commitment,
                local_commitment_hash: None,
                counterparty_device_id,
                counterparty_genesis_hash: Some([54u8; 32]),
                operation: Operation::Noop,
                phase: BilateralPhase::Prepared,
                local_signature: Some(vec![1u8; 32]),
                counterparty_signature: None,
                created_at_ticks: 1,
                expires_at_ticks: 2,
                sender_ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
            })
            .await;
        handler
            .test_insert_session(BilateralBleSession {
                commitment_hash: surviving_commitment,
                local_commitment_hash: None,
                counterparty_device_id,
                counterparty_genesis_hash: Some([54u8; 32]),
                operation: Operation::Noop,
                phase: BilateralPhase::Accepted,
                local_signature: Some(vec![2u8; 32]),
                counterparty_signature: Some(vec![3u8; 32]),
                created_at_ticks: 3,
                expires_at_ticks: 4,
                sender_ble_address: Some("AA:BB:CC:DD:EE:11".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
            })
            .await;

        assert!(
            handler
                .fail_session_by_commitment(
                    failed_commitment,
                    "precise cleanup should only remove the failed sender prepare"
                )
                .await,
            "targeted prepared session should be failed"
        );
        assert!(
            handler
                .get_session_status(&failed_commitment)
                .await
                .is_none(),
            "targeted session should be removed from active map"
        );
        assert_eq!(
            handler.get_session_status(&surviving_commitment).await,
            Some(BilateralPhase::Accepted),
            "other same-counterparty session must remain untouched"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_restore_sessions_marks_interrupted_failed_and_deletes_malformed_rows() {
        init_test_db();

        let (_bilateral_manager, handler) =
            make_test_handler([11u8; 32], [12u8; 32], b"restore-sessions-hardening");
        let counterparty_device_id = [13u8; 32];

        let valid_inflight = crate::storage::client_db::BilateralSessionRecord {
            commitment_hash: vec![0xA1; 32],
            counterparty_device_id: counterparty_device_id.to_vec(),
            counterparty_genesis_hash: Some(vec![0xB1; 32]),
            operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
            phase: "prepared".to_string(),
            local_signature: Some(vec![0xC1; 64]),
            counterparty_signature: None,
            created_at_step: 10,
            sender_ble_address: None,
        };
        crate::storage::client_db::store_bilateral_session(&valid_inflight)
            .expect("store inflight");

        let old_terminal = crate::storage::client_db::BilateralSessionRecord {
            commitment_hash: vec![0xA2; 32],
            counterparty_device_id: counterparty_device_id.to_vec(),
            counterparty_genesis_hash: Some(vec![0xB2; 32]),
            operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
            phase: "failed".to_string(),
            local_signature: None,
            counterparty_signature: None,
            created_at_step: 1,
            sender_ble_address: None,
        };
        crate::storage::client_db::store_bilateral_session(&old_terminal).expect("store terminal");
        let invalid_short_commitment_hash = [0xDE_u8; 31];

        {
            let conn = crate::storage::client_db::get_connection().expect("db connection");
            let conn = conn.lock().expect("db lock");
            conn.execute(
                "INSERT INTO bilateral_sessions(
                    commitment_hash, counterparty_device_id, counterparty_genesis_hash, operation_bytes, phase,
                    local_signature, counterparty_signature, created_at_step, sender_ble_address, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    invalid_short_commitment_hash.to_vec(),
                    counterparty_device_id.to_vec(),
                    Option::<Vec<u8>>::None,
                    vec![0x01_u8],
                    "prepared",
                    Option::<Vec<u8>>::None,
                    Option::<Vec<u8>>::None,
                    11_i64,
                    Option::<String>::None,
                    11_i64,
                ],
            )
            .expect("insert malformed row");
        }

        let restored = handler
            .restore_sessions_from_storage()
            .await
            .expect("restore sessions");
        assert_eq!(restored, 0, "restore remains a compatibility no-op count");

        let inflight_after = crate::storage::client_db::get_bilateral_session(&[0xA1; 32])
            .expect("load inflight")
            .expect("inflight row exists");
        assert_eq!(inflight_after.phase, "failed");

        assert!(
            crate::storage::client_db::get_bilateral_session(&invalid_short_commitment_hash)
                .expect("load malformed")
                .is_none(),
            "malformed row should be deleted during restore"
        );
        assert!(
            crate::storage::client_db::get_bilateral_session(&[0xA2; 32])
                .expect("load terminal")
                .is_some(),
            "existing terminal row should remain untouched"
        );
    }

    // Intermittently fails on CI due to a test-harness race against the
    // shared in-memory SQLite DB: non-`#[serial]` sibling tests call
    // `reset_database_for_tests()` concurrently, bumping TEST_DB_GENERATION
    // and nulling DB_CONNECTION between this test's persist and read. The
    // production persist/read path is unaffected — this is purely
    // `cargo test` infrastructure. Passes reliably locally and when run
    // in isolation. Tracking a proper harness-level fix (serialize every
    // DB accessor under `DSM_SDK_TEST_MODE`) post-release.
    #[tokio::test]
    #[serial]
    #[ignore = "harness race on shared in-memory SQLite; re-enable with DB-accessor serialization"]
    async fn test_register_sender_session_persists_canonical_sender_session() {
        init_test_db();

        let device_id = [1u8; 32];
        let counterparty_device_id = [3u8; 32];
        let counterparty_genesis = [4u8; 32];
        let (bilateral_manager, handler) =
            make_test_handler(device_id, [2u8; 32], b"register-sender-session");

        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "test_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![7u8; 32],
            genesis_material: vec![5u8; 32],
            chain_tip: Some([6u8; 32]),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1000,
            added_at_commit_height: 1000,
            last_updated_commit_height: 1000,
            verifying_storage_nodes: vec![],
            ble_address: Some(String::new()),
        };

        {
            let mut m = bilateral_manager.write().await;
            m.add_verified_contact(contact).unwrap();
        }

        // Build an operation (Noop is sufficient for this test)
        let op = Operation::Noop;
        let op_bytes = op.to_bytes();

        // Provide a bogus frontend commitment hash - register_sender_session should create
        // an internal canonical precommitment and map the frontend-provided hash -> canonical
        let frontend_hash = [9u8; 32];

        let canonical_hash = handler
            .register_sender_session(frontend_hash, counterparty_device_id, &op_bytes, 1000)
            .await
            .expect("register_sender_session failed");

        let sessions = handler.sessions.sessions.lock().await;
        assert!(
            sessions.contains_key(&canonical_hash),
            "sessions should contain the canonical sender session"
        );
        drop(sessions);

        let persisted = crate::storage::client_db::get_bilateral_session(&canonical_hash)
            .expect("load persisted")
            .expect("sender session persisted");
        assert_eq!(persisted.phase, "prepared");
        assert_eq!(
            persisted.counterparty_device_id,
            counterparty_device_id.to_vec()
        );

        let manager = bilateral_manager.read().await;
        assert!(
            manager.has_pending_commitment(&canonical_hash),
            "register_sender_session should create a pending core precommitment"
        );
    }

    // Removed background maintenance test (interval-based) to comply with deterministic, clockless spec.
}
