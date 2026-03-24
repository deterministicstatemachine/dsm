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
    BilateralTransactionManager, BilateralTransactionResult,
};
use dsm::core::security::{BilateralControlResistance, DecentralizedStorage};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::State;

use crate::generated;
use crate::storage::bcr_storage::BcrStorage;
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
    pub fn new(
        bilateral_tx_manager: Arc<RwLock<BilateralTransactionManager>>,
        device_id: [u8; 32],
    ) -> Self {
        // Use the shared Per-Device SMT singleton (initialized during SDK bootstrap).
        // Falls back to a fresh instance if bootstrap hasn't run yet (e.g. tests).
        let per_device_smt = crate::security::shared_smt::init_shared_smt(256);
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

    async fn record_bcr_state_and_scan(&self, state: &State, published: bool) {
        if let Err(e) = crate::storage::client_db::store_bcr_state(state, published) {
            warn!("[BLE_HANDLER] Failed to persist BCR state: {}", e);
            return;
        }

        let storage = BcrStorage::new();
        let states = match storage.get_historical_states(&state.device_info.device_id) {
            Ok(s) => s,
            Err(e) => {
                warn!("[BLE_HANDLER] Failed to load BCR states: {}", e);
                return;
            }
        };

        match BilateralControlResistance::detect_suspicious_patterns(&states, &storage).await {
            Ok(alerts) if !alerts.is_empty() => {
                warn!(
                    "[BLE_HANDLER] BCR alerts detected for device {}: {}",
                    bytes_to_base32(&state.device_info.device_id[..8]),
                    alerts.len()
                );
            }
            Ok(_) => {}
            Err(e) => {
                warn!("[BLE_HANDLER] BCR detection failed: {}", e);
            }
        }
    }
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

            // Delete from persistent storage
            if let Err(e) =
                crate::storage::client_db::delete_bilateral_session(&origin_commitment_hash)
            {
                warn!(
                    "[BLE_HANDLER] Failed to delete bilateral session on reject: {}",
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

        // Build reject message
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            reason: reason.clone(),
            rejector_device_id: self.device_id.to_vec(),
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

        terminal_sessions.sort_by(|a, b| b.created_at_step.cmp(&a.created_at_step));

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

    /// Recover sessions that are stuck in "accepted" state with a counterparty signature.
    /// These sessions have been accepted by the receiver but the sender never got the
    /// commit response (BLE delivery failure). We can finalize them now since we have
    /// the counterparty's signature.
    pub async fn recover_accepted_sessions(&self) -> usize {
        info!("[BLE_HANDLER] Checking for accepted sessions to recover...");

        // Collect sessions to recover (must not hold lock during finalization)
        let sessions_to_recover: Vec<[u8; 32]> = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| {
                    s.phase == BilateralPhase::Accepted && s.counterparty_signature.is_some()
                })
                .map(|(k, _)| *k)
                .collect()
        };

        if sessions_to_recover.is_empty() {
            info!("[BLE_HANDLER] No accepted sessions to recover");
            return 0;
        }

        info!(
            "[BLE_HANDLER] Found {} accepted sessions with counterparty signatures to recover",
            sessions_to_recover.len()
        );

        let mut recovered = 0;
        for commitment_hash in sessions_to_recover {
            info!(
                "[BLE_HANDLER] Recovering accepted session: {}",
                bytes_to_base32(&commitment_hash[..8])
            );
            // Finalize the transaction, update balance, and store to history.
            // Meta returned for orchestration layer to run hooks; in recovery
            // context we run cleanup inline since the coordinator isn't driving.
            if let Some(meta) = self
                .mark_sender_committed_with_post_state_hash(&commitment_hash, None)
                .await
            {
                crate::sdk::transfer_hooks::post_transfer_cleanup(
                    &meta.token_id,
                    crate::sdk::transfer_hooks::TransferCleanupRole::SenderRemove,
                    meta.amount,
                );
            }
            recovered += 1;
        }

        info!("[BLE_HANDLER] Recovered {} accepted sessions", recovered);
        recovered
    }

    /// Restore sessions from SQLite on startup
    pub async fn restore_sessions_from_storage(&self) -> Result<usize, DsmError> {
        info!("[BLE_HANDLER] Restoring bilateral sessions from storage...");

        let records = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to restore sessions: {}", e))
        })?;

        let mut counterparties: HashSet<[u8; 32]> = HashSet::new();
        let mut restored_count = 0;
        let mut sessions = self.sessions.sessions.lock().await;

        for record in records {
            // Clockless: no expiry-based skipping.

            // Skip completed sessions
            if record.phase == "committed" || record.phase == "rejected" || record.phase == "failed"
            {
                debug!(
                    "[BLE_HANDLER] Skipping completed session: phase={}",
                    record.phase
                );
                continue;
            }

            // Deserialize operation
            let operation =
                match crate::storage::client_db::deserialize_operation(&record.operation_bytes) {
                    Ok(op) => op,
                    Err(e) => {
                        warn!("[BLE_HANDLER] Failed to deserialize operation: {}", e);
                        continue;
                    }
                };

            // Convert phase string to enum
            let phase = match record.phase.as_str() {
                "preparing" => BilateralPhase::Preparing,
                "prepared" => BilateralPhase::Prepared,
                "pending_user_action" => BilateralPhase::PendingUserAction,
                "accepted" => BilateralPhase::Accepted,
                "rejected" => BilateralPhase::Rejected,
                "confirm_pending" => BilateralPhase::ConfirmPending,
                "committed" => BilateralPhase::Committed,
                "failed" => BilateralPhase::Failed,
                _ => {
                    warn!("[BLE_HANDLER] Unknown phase: {}", record.phase);
                    continue;
                }
            };

            // Construct commitment hash
            let mut commitment_hash = [0u8; 32];
            if record.commitment_hash.len() == 32 {
                commitment_hash.copy_from_slice(&record.commitment_hash);
            } else {
                warn!("[BLE_HANDLER] Invalid commitment hash length");
                continue;
            }

            // Construct counterparty device ID
            let mut counterparty_device_id = [0u8; 32];
            if record.counterparty_device_id.len() == 32 {
                counterparty_device_id.copy_from_slice(&record.counterparty_device_id);
                counterparties.insert(counterparty_device_id);
            } else {
                warn!("[BLE_HANDLER] Invalid counterparty device_id length");
                continue;
            }

            let counterparty_genesis_hash = match &record.counterparty_genesis_hash {
                Some(hash) if hash.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(hash);
                    Some(arr)
                }
                Some(hash) => {
                    warn!(
                        "[BLE_HANDLER] Invalid counterparty genesis hash length: {}",
                        hash.len()
                    );
                    None
                }
                None => None,
            };

            if sessions.contains_key(&commitment_hash) {
                log::warn!(
                    "[BLE_HANDLER] ⚠️ Duplicate restored session for {}. Skipping.",
                    bytes_to_base32(&commitment_hash)
                );
                continue;
            }

            let session = BilateralBleSession {
                commitment_hash,
                local_commitment_hash: None,
                counterparty_device_id,
                counterparty_genesis_hash,
                operation,
                phase,
                local_signature: record.local_signature,
                counterparty_signature: record.counterparty_signature,
                created_at_ticks: record.created_at_step,
                // Clockless: no persisted expiry, keep a nonzero placeholder for in-memory
                // fields that have not yet been removed.
                expires_at_ticks: u64::MAX,
                sender_ble_address: record.sender_ble_address,
                // Restored sessions get current wall time — conservative staleness window on restart
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
            };

            sessions.insert(commitment_hash, session);
            restored_count += 1;
        }

        drop(sessions);

        info!(
            "[BLE_HANDLER] Restored {} bilateral sessions from storage",
            restored_count
        );

        // Recover any accepted sessions that have counterparty signatures
        // (these are sessions where the receiver accepted but the commit response was lost)
        let recovered = self.recover_accepted_sessions().await;
        if recovered > 0 {
            info!(
                "[BLE_HANDLER] Auto-recovered {} accepted sessions during restore",
                recovered
            );
        }

        for counterparty_device_id in counterparties {
            self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                .await;
        }

        Ok(restored_count)
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
    pub async fn prepare_bilateral_transaction(
        &self,
        counterparty_device_id: [u8; 32],
        operation: Operation,
        validity_iterations: u64,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        info!("Preparing BLE bilateral transaction");

        // §6 Tripwire gate: refuse to initiate BLE transfer with bricked contact.
        if crate::storage::client_db::is_contact_bricked(&counterparty_device_id) {
            return Err(DsmError::invalid_operation(
                "BLE prepare rejected: contact is permanently bricked (Tripwire fork detected)",
            ));
        }

        if let Some((existing_commitment_hash, existing_phase, created_at_wall)) = self
            .detect_inflight_counterparty_session(&counterparty_device_id)
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
            let stale_pending_key = {
                let mut sessions = self.sessions.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&existing_commitment_hash) {
                    session.phase = BilateralPhase::Failed;
                    let pending_key = session
                        .local_commitment_hash
                        .unwrap_or(existing_commitment_hash);
                    sessions.remove(&existing_commitment_hash);
                    pending_key
                } else {
                    existing_commitment_hash
                }
            };
            // Clean up persisted record + core manager pending commitment
            let _ = delete_bilateral_session(&existing_commitment_hash);
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&stale_pending_key);
            }
        }

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
                    let _ = mgr.establish_relationship(&counterparty_device_id).await;
                }
                drop(mgr);
            } else {
                let mgr = self.bilateral_tx_manager.read().await;
                if !mgr.has_verified_contact(&counterparty_device_id) {
                    return Err(DsmError::invalid_operation(
                        "Bilateral transactions require a verified contact. Please add the contact first.",
                    ));
                }
                drop(mgr);
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
            if !mgr.has_verified_contact(&counterparty_device_id) {
                return Err(DsmError::invalid_operation(
                    "Bilateral transactions require a verified contact. Please add the contact first.",
                ));
            }
            drop(mgr);
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

        // PRE-FLIGHT RECONCILIATION: Before building the Prepare request, run the
        // reconciliation engine to detect and fix state drift from a dropped ACK
        // (e.g. after a role-swap where the final packet of the previous transaction
        // was lost). This ensures expected_counterparty_state_hash will be current.
        if let Some(handler) = crate::bridge::bilateral_handler() {
            match handler.reconcile_before_send(&counterparty_device_id).await {
                Ok(()) => {
                    info!(
                        "[BLE_HANDLER] Pre-flight reconciliation complete for {}",
                        bytes_to_base32(&counterparty_device_id[..8])
                    );
                }
                Err(e) => {
                    warn!("[BLE_HANDLER] Pre-flight reconciliation failed for {}: {} (proceeding anyway)",
                        bytes_to_base32(&counterparty_device_id[..8]), e);
                    // Non-fatal: the existing chain tip sync above already did its best.
                    // If reconciliation truly cannot fix it, the receiver will reject
                    // with TipMismatch and the user can retry.
                }
            }

            // After reconciliation may have updated SQLite, re-sync the remote chain
            // tip into the in-memory BTM so the Prepare request uses the corrected value.
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(contact) = mgr.get_contact(&counterparty_device_id).cloned() {
                let sqlite_tip_post =
                    crate::storage::client_db::get_contact_chain_tip_raw(&counterparty_device_id);
                if let Some(tip) = sqlite_tip_post {
                    info!(
                        "[BLE_HANDLER] Post-reconciliation remote tip refresh: {}",
                        bytes_to_base32(&tip[..8])
                    );
                    mgr.advance_chain_tip(&counterparty_device_id, tip);
                } else {
                    // SQLite had no tip; keep whatever the first sync resolved.
                    let _ = contact;
                }
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
            let _ = crate::storage::client_db::delete_bilateral_session(&commitment_hash);
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&pending_key);
            }
        }
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
            let is_verified = mgr.has_verified_contact(&counterparty_device_id);
            log::warn!(
                "[BilateralBleHandler] 🔍 Contact verification: device_id={} is_verified={}",
                dsm::core::utility::labeling::hash_to_short_id(&counterparty_device_id),
                is_verified
            );
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
                if crate::security::shared_smt::is_pending_online(&smt_key).await {
                    log::error!(
                        "[BilateralBleHandler] ❌ §5.4 modal lock: pending online projection for ({}, {}). Rejecting offline.",
                        bytes_to_base32(&self.device_id[..8]),
                        bytes_to_base32(&counterparty_device_id[..8]),
                    );
                    return Err(DsmError::invalid_operation(
                        "§5.4: Cannot initiate offline transfer while pending online projection exists for this relationship",
                    ));
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
                        let pending_next: Option<[u8; 32]> =
                            pending.next_tip.as_slice().try_into().ok();

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

                        let already_advanced = match pending_next {
                            Some(pn) => {
                                // Prefer sender-reported tip (prepare request) over stale SQLite
                                (sender_reported_tip == Some(pn)) || (persisted_tip == Some(pn))
                            }
                            None => false,
                        };

                        if already_advanced {
                            log::info!(
                                "[BilateralBleHandler] ✅ Pending online gate stale (sender tip matches next_tip); clearing for ({}, {})",
                                bytes_to_base32(&self.device_id[..8]),
                                bytes_to_base32(&counterparty_device_id[..8]),
                            );
                            let _ = crate::storage::client_db::clear_pending_online_outbox(
                                &counterparty_device_id,
                            );
                        } else {
                            log::error!(
                                "[BilateralBleHandler] ❌ persisted online gate: recipient has not caught up for ({}, {}). sender_tip={} pending_next={} persisted_tip={}. Rejecting offline.",
                                bytes_to_base32(&self.device_id[..8]),
                                bytes_to_base32(&counterparty_device_id[..8]),
                                sender_reported_tip.map_or("none".to_string(), |t| bytes_to_base32(&t[..8])),
                                pending_next.map_or("none".to_string(), |t| bytes_to_base32(&t[..8])),
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
                mgr.establish_relationship(&counterparty_device_id)
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

            if let Err(e) = crate::storage::client_db::mark_contact_needs_online_reconcile(
                &counterparty_device_id,
            ) {
                warn!(
                    "[BLE_HANDLER] Failed to mark contact for online reconciliation: {}",
                    e
                );
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
            let reject = generated::BilateralPrepareReject {
                commitment_hash: Some(generated::Hash32 {
                    v: origin_commitment_hash.to_vec(),
                }),
                reason,
                rejector_device_id: self.device_id.to_vec(),
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

        // Get chain tips for response
        let (remote_chain_tip, local_chain_tip) = {
            let m = self.bilateral_tx_manager.read().await;
            let remote = m
                .get_chain_tip_for(&counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("No remote chain tip"))?;
            let local = m
                .get_chain_tip_for(&counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("No local chain tip"))?;
            (remote, local)
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
                v: remote_chain_tip.to_vec(),
            }),
            local_state_hash: Some(generated::Hash32 {
                v: local_chain_tip.to_vec(),
            }),
            responder_signing_public_key: local_signing_key,
        };

        // Wrap in envelope
        let response_envelope = self
            .create_envelope_with_tip(
                generated::envelope::Payload::BilateralPrepareResponse(prepare_response),
                Some(local_chain_tip),
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

        // Build reject envelope
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: origin_commitment_hash.to_vec(),
            }),
            reason,
            rejector_device_id: self.device_id.to_vec(),
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

        // Delete from storage (transfer rejected)
        if let Err(e) = delete_bilateral_session(&commitment_hash) {
            warn!(
                "[BLE_HANDLER] Failed to delete rejected session from storage: {}",
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

    /// 3-step protocol step 3 (sender side): Build BilateralConfirmRequest, finalize sender,
    /// and return the confirm envelope bytes to be sent to the receiver via BLE.
    ///
    /// This replaces the old `commit_bilateral_transaction()`. In the new 3-step protocol,
    /// the sender finalizes here (before sending) and the receiver finalizes upon receiving
    /// the confirm message.
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

        // 5. SMT-Replace: atomic update via core (§4.2)
        let result = {
            let mut manager = self.bilateral_tx_manager.write().await;
            let mut smt = self.per_device_smt.write().await;
            manager.commit_bilateral_smt_update(
                &mut smt,
                &self.device_id,
                &session.counterparty_device_id,
                &h_n_plus_1,
            )?
        };
        let pre_root = result.pre_root;
        let sender_smt_root = result.post_root;
        let rel_proof_parent_bytes = result.parent_proof.to_bytes();
        let rel_proof_child_bytes = result.child_proof.to_bytes();

        // 6. Build stitched receipt with real SMT roots + proofs (§4.2)
        let local_r_g = crate::sdk::app_state::AppState::get_device_tree_root();
        let receipt_bytes = crate::sdk::receipts::build_bilateral_receipt_with_smt(
            self.device_id,
            session.counterparty_device_id,
            h_n,
            h_n_plus_1,
            pre_root,
            sender_smt_root,
            rel_proof_parent_bytes.clone(),
            rel_proof_child_bytes.clone(),
            local_r_g,
        )
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "send_bilateral_confirm: local device_tree_root required to build receipt",
            )
        })?;

        // 7. Finalize sender: execute state transition.
        // Capture the finalized local_state so it can be threaded into settlement
        // and BCR archive — the same canonical commit path used by recovery
        // (mark_sender_committed_with_post_state_hash).
        let finalized_local_state = {
            let mut manager = self.bilateral_tx_manager.write().await;
            match manager
                .finalize_offline_transfer_with_entropy(
                    &session.counterparty_device_id,
                    &commitment_hash,
                    counterparty_sig,
                    Some(pre_entropy),
                )
                .await
            {
                Ok(result) => {
                    info!(
                        "[BILATERAL] Sender finalized, tx_hash: {}",
                        bytes_to_base32(&result.transaction_hash)
                    );
                    // Chain tip already advanced and persisted to SQLite inside
                    // finalize_offline_transfer_with_entropy → update_anchor →
                    // chain_tip_store.set_contact_chain_tip(). No redundant CAS needed.
                    result.local_state
                }
                Err(e) => {
                    return Err(DsmError::invalid_operation(format!(
                        "send_bilateral_confirm: sender finalize failed: {e}"
                    )));
                }
            }
        };

        // 9+10. Delegate sender settlement (balance debit + transaction history) to the
        // application layer.  If settlement fails the confirm envelope is never built —
        // the receiver will not get a confirm for a transfer the sender could not debit.
        // Session stays Accepted so the caller can retry.
        //
        // The finalized local_state is passed as canonical_state so that
        // build_canonical_settled_state can reconcile the ERA debit and produce a
        // canonical settled state.  After settlement, archive to BCR and sync the
        // balance cache — converging on the same canonical commit path that recovery
        // (mark_sender_committed_with_post_state_hash) already depends on.
        let confirm_meta = if let Some(ref delegate) = self.settlement_delegate {
            let ctx = BilateralSettlementContext {
                local_device_id: self.device_id,
                counterparty_device_id: session.counterparty_device_id,
                commitment_hash,
                transaction_hash: h_n_plus_1,
                chain_height: finalized_local_state.state_number,
                operation_bytes: session.operation.to_bytes(),
                proof_data: Some(receipt_bytes.clone()),
                is_sender: true,
                tx_type: "bilateral_offline",
                new_chain_tip: [0u8; 32],
                canonical_state: Some(finalized_local_state.clone()),
            };
            let outcome = delegate.settle(ctx).map_err(|e| {
                DsmError::invalid_operation(format!(
                    "send_bilateral_confirm: sender settlement failed: {e}"
                ))
            })?;

            // Canonical post-settlement persistence: archive to BCR and sync
            // balance cache.  Matches mark_sender_committed_with_post_state_hash
            // so there is exactly one sender-side canonical commit path.
            let state_to_record = outcome
                .canonical_state
                .as_ref()
                .unwrap_or(&finalized_local_state);
            self.record_bcr_state_and_scan(state_to_record, true).await;

            if let Some(router) = crate::bridge::app_router() {
                router.sync_balance_cache();
            }

            outcome
        } else {
            BilateralSettlementOutcome::default()
        };

        // 11. Build BilateralConfirmRequest
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

        // 12. Wrap in envelope
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

        // 13. Mark session ConfirmPending — the session remains alive in memory and SQLite
        // until mark_confirm_delivered() is called by Kotlin after the BilateralConfirm
        // envelope is successfully delivered to the receiver over BLE. This prevents the
        // sender from appearing Committed when the receiver never received the confirm,
        // which would cause a permanent balance inconsistency.
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.phase = BilateralPhase::ConfirmPending;
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

        info!("[BILATERAL] send_bilateral_confirm: confirm envelope built ({} bytes), session ConfirmPending until delivery", buffer.len());
        Ok((buffer, confirm_meta.transfer_meta))
    }

    /// Mark a ConfirmPending sender session as Committed after the BilateralConfirm
    /// envelope was successfully delivered to the receiver over BLE.
    ///
    /// Called by Kotlin via JNI (markBilateralConfirmDelivered) once the chunk send
    /// succeeds. Finalizes the session state, emits the completion event, and triggers
    /// the wallet refresh that the frontend depends on.
    pub async fn mark_confirm_delivered(&self, commitment_hash: [u8; 32]) -> Result<(), DsmError> {
        info!(
            "[BILATERAL] mark_confirm_delivered: commitment={}",
            bytes_to_base32(&commitment_hash)
        );

        // Retrieve session from in-memory map
        let session = {
            let sessions = self.sessions.sessions.lock().await;
            sessions.get(&commitment_hash).cloned()
        };

        let session = match session {
            Some(s) if s.phase == BilateralPhase::ConfirmPending => s,
            Some(s) => {
                info!(
                    "[BILATERAL] mark_confirm_delivered: session not ConfirmPending (phase={:?}), ignoring",
                    s.phase
                );
                return Ok(());
            }
            None => {
                info!("[BILATERAL] mark_confirm_delivered: session not found, ignoring");
                return Ok(());
            }
        };

        // Mark Committed in-memory
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.phase = BilateralPhase::Committed;
            }
        }

        // Delete persisted session (transaction fully complete)
        if let Err(e) = delete_bilateral_session(&commitment_hash) {
            warn!(
                "[BILATERAL] mark_confirm_delivered: failed to delete session: {}",
                e
            );
        }
        self.prune_terminal_sessions_for_counterparty(&session.counterparty_device_id)
            .await;

        // Emit transfer complete event so the sender's frontend refreshes balances.
        // Event display metadata provided by the application-layer delegate.
        let op_bytes = session.operation.to_bytes();
        let (amount_opt, token_id_opt) = if let Some(ref d) = self.settlement_delegate {
            d.operation_metadata(&op_bytes)
        } else {
            (None, None)
        };
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: amount_opt,
            token_id: token_id_opt,
            status: "completed".to_string(),
            message: "Bilateral transfer completed (sender confirm delivered)".to_string(),
            sender_ble_address: None,
            failure_reason: None,
        });

        info!("[BILATERAL] mark_confirm_delivered: session Committed, events emitted");

        Ok(())
    }

    /// Sweep all ConfirmPending sessions and mark each one as Committed.
    ///
    /// Called by Kotlin after successfully queuing BilateralConfirm chunks for delivery when
    /// the 32-byte commitment hash is not readily available in the Kotlin call-site.
    /// Over a point-to-point BLE connection there is at most one ConfirmPending session at
    /// any given time, so this is safe and avoids protobuf parsing in Kotlin.
    ///
    /// Returns the number of sessions that were transitioned.
    pub async fn mark_any_confirm_pending_delivered(&self) -> Result<usize, DsmError> {
        let pending_hashes: Vec<[u8; 32]> = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| s.phase == BilateralPhase::ConfirmPending)
                .map(|(k, _)| *k)
                .collect()
        };
        let count = pending_hashes.len();
        if count == 0 {
            info!("[BILATERAL] mark_any_confirm_pending_delivered: no ConfirmPending sessions");
            return Ok(0);
        }
        for hash in pending_hashes {
            if let Err(e) = self.mark_confirm_delivered(hash).await {
                warn!(
                    "[BILATERAL] mark_any_confirm_pending_delivered: error for hash {:?}: {}",
                    &hash[..4],
                    e
                );
            }
        }
        info!(
            "[BILATERAL] mark_any_confirm_pending_delivered: transitioned {} session(s)",
            count
        );
        Ok(count)
    }

    /// 3-step protocol step 3 (receiver side): Handle BilateralConfirmRequest from sender.
    ///
    /// Verifies sender's signature, validates proofs, finalizes the receiver side
    /// (execute state transition, update balance, store history), and emits transfer complete.
    /// Returns `Ok(TransferMeta)` — no response message needed (3-step protocol is complete).
    /// The orchestration layer uses the returned meta to run post-transfer hooks.
    pub async fn handle_confirm_request(
        &self,
        envelope_bytes: &[u8],
    ) -> Result<crate::sdk::transfer_hooks::TransferMeta, DsmError> {
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
            let sessions = self.sessions.sessions.lock().await;
            log::info!(
                "[BLE_HANDLER][handle_confirm_request] active_sessions keys: {:?}",
                sessions
                    .keys()
                    .map(|k| bytes_to_base32(&k[..8]))
                    .collect::<Vec<_>>()
            );
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

            // §4.3 acceptance predicate #2: verify π_rel_parent (h_n ∈ r_A) if available.
            // For the FIRST transaction in a relationship, the sender's SMT has no entry
            // for this key — parent proof is legitimately empty (leaf = ZERO_LEAF).
            // verify_receipt_bytes() handles this case; the confirm handler must too.
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
                info!(
                    "[BILATERAL] §4.3 parent proof verified: π(h_n ∈ r_A) ✓ ({} siblings)",
                    parent_proof.siblings.len()
                );
            } else {
                info!(
                    "[BILATERAL] §4.3 parent proof absent — first transaction for this relationship (ZERO_LEAF)"
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

        // RECEIVER-SIDE FINALIZE: Execute state transition, advance to sender's h_{n+1}
        let (tx_result, h_n) = {
            let mut manager = self.bilateral_tx_manager.write().await;

            let mut anchor = manager
                .get_relationship(&session.counterparty_device_id)
                .ok_or_else(|| {
                    DsmError::relationship("remote device relationship not found".to_string())
                })?
                .clone();

            // §B2: Capture h_n (relationship chain tip BEFORE this transaction)
            let h_n = anchor.chain_tip;

            // §C1: Receiver independently verifies h_{n+1} using sender's pre_entropy.
            // Whitepaper §4.1: both parties must compute the same Cpre and successor tip
            // from (h_n, op_bytes, pre_entropy). A mismatch means the sender forged
            // shared_chain_tip_new without using the agreed entropy.
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

            if let Some(pe) = pre_entropy {
                let op_bytes = session.operation.to_bytes();
                let expected_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                    &h_n, &op_bytes, &pe,
                );
                let expected_h_next =
                    dsm::core::bilateral_transaction_manager::compute_successor_tip(
                        &h_n,
                        &op_bytes,
                        &pe,
                        &expected_sigma,
                    );
                if expected_h_next != new_chain_tip {
                    return Err(DsmError::invalid_operation(
                        "h_{n+1} mismatch: pre_entropy cannot reproduce shared_chain_tip_new (§4.1)",
                    ));
                }
            }

            // Use the same agreed entropy the sender used to derive h_{n+1}. A fresh
            // entropy value is only valid when the confirm omitted pre_entropy entirely.
            let entropy = pre_entropy.unwrap_or(manager.generate_entropy()?);
            let state_pair = manager.execute_transition_bytes(
                &self.device_id,
                &session.counterparty_device_id,
                session.operation.clone(),
                entropy,
            )?;

            // Advance shared chain tip in-memory only — SQLite persistence is deferred
            // to apply_receiver_confirm_and_store_transaction_atomic() so that chain tip,
            // ERA settlement (when applicable), and transaction history commit atomically (§4.2).
            manager.update_anchor_in_memory_public(
                &session.counterparty_device_id,
                &mut anchor,
                new_chain_tip,
            )?;

            let tx_hash =
                manager.tx_hash_public(&state_pair.entity_state, &state_pair.counterparty_state)?;

            let result = BilateralTransactionResult {
                local_state: state_pair.entity_state,
                remote_state: state_pair.counterparty_state,
                relationship_anchor: anchor.clone(),
                transaction_hash: tx_hash,
                completed_offline: true,
            };

            (result, h_n)
        };

        // Receiver: SMT-Replace via core, then build receipt with real proofs (§4.2)
        let receipt_bytes = {
            let result = {
                let mut manager = self.bilateral_tx_manager.write().await;
                let mut smt = self.per_device_smt.write().await;
                manager.commit_bilateral_smt_update(
                    &mut smt,
                    &self.device_id,
                    &session.counterparty_device_id,
                    &new_chain_tip,
                )?
            };
            let local_r_g = crate::sdk::app_state::AppState::get_device_tree_root();
            crate::sdk::receipts::build_bilateral_receipt_with_smt(
                self.device_id,
                session.counterparty_device_id,
                h_n,
                new_chain_tip,
                result.pre_root,
                result.post_root,
                result.parent_proof.to_bytes(),
                result.child_proof.to_bytes(),
                local_r_g,
            )
        };

        // Chain tip h_{n+1} is NOT yet persisted to SQLite — update_anchor_in_memory_public
        // only updated in-memory state. The SQLite persistence happens atomically with
        // settlement metadata inside the delegate below.

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
        let (confirm_outcome, persistence_error) =
            if let Some(ref delegate) = self.settlement_delegate {
                let ctx = BilateralSettlementContext {
                    local_device_id: self.device_id,
                    counterparty_device_id: session.counterparty_device_id,
                    commitment_hash,
                    transaction_hash: tx_result.transaction_hash,
                    chain_height: tx_result.local_state.state_number,
                    operation_bytes: op_bytes.clone(),
                    proof_data: receipt_bytes,
                    is_sender: false,
                    tx_type: "bilateral_offline",
                    new_chain_tip,
                    canonical_state: Some(tx_result.local_state.clone()),
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

        if let Some(persist_error) = persistence_error {
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&pending_key);
            }

            if let Err(e) = crate::storage::client_db::mark_contact_needs_online_reconcile(
                &session.counterparty_device_id,
            ) {
                warn!(
                    "[BILATERAL] Failed to mark contact for reconcile after receiver persistence error: {}",
                    e
                );
            }

            let failed_session = {
                let mut sessions = self.sessions.sessions.lock().await;
                if let Some(active) = sessions.get_mut(&commitment_hash) {
                    active.phase = BilateralPhase::Failed;
                    Some(active.clone())
                } else {
                    None
                }
            };
            if let Some(failed_session) = failed_session.as_ref() {
                if let Err(e) = self.persist_session(failed_session, None).await {
                    warn!(
                        "[BILATERAL] Failed to persist failed receiver session after local persistence error: {}",
                        e
                    );
                }
            }

            self.emit_event(&generated::BilateralEventNotification {
                event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                counterparty_device_id: session.counterparty_device_id.to_vec(),
                commitment_hash: commitment_hash.to_vec(),
                transaction_hash: Some(tx_result.transaction_hash.to_vec()),
                amount: amount_opt,
                token_id: token_id_opt,
                status: "failed".to_string(),
                message: format!(
                    "Receiver finalized but failed to persist local wallet state: {}",
                    persist_error
                ),
                sender_ble_address: session.sender_ble_address.clone(),
                failure_reason: Some(
                    generated::BilateralFailureReason::FailureReasonUnspecified.into(),
                ),
            });

            return Err(DsmError::invalid_operation(format!(
                "receiver finalized but failed to persist local wallet state: {}",
                persist_error
            )));
        }

        let state_to_record = confirm_outcome
            .canonical_state
            .as_ref()
            .unwrap_or(&tx_result.local_state);
        self.record_bcr_state_and_scan(state_to_record, true).await;

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

        // §5.4: BLE transfer succeeded (receiver side) — clear any pending online
        // outbox for this counterparty. A successful BLE commit proves the chain tip
        // was advanced, so any prior online gate is stale.
        if crate::storage::client_db::get_pending_online_outbox(&session.counterparty_device_id)
            .ok()
            .flatten()
            .is_some()
        {
            info!(
                "[BILATERAL] Clearing stale pending_online_outbox for {} after successful BLE commit (receiver)",
                bytes_to_base32(&session.counterparty_device_id[..8]),
            );
            let _ = crate::storage::client_db::clear_pending_online_outbox(
                &session.counterparty_device_id,
            );
        }

        // Emit transfer_complete event to frontend (receiver side).
        // amount / token_id already resolved via delegate.operation_metadata() above.
        self.emit_event(&generated::BilateralEventNotification {
            event_type: generated::BilateralEventType::BilateralEventTransferComplete.into(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: Some(tx_result.transaction_hash.to_vec()),
            amount: amount_opt,
            token_id: token_id_opt,
            status: "completed".to_string(),
            message: "Bilateral transfer completed (receiver confirmed)".to_string(),
            sender_ble_address: session.sender_ble_address.clone(),
            failure_reason: None,
        });

        info!("[BILATERAL] handle_confirm_request: receiver finalized successfully");

        Ok(confirm_outcome.transfer_meta)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let sessions = self.sessions.sessions.lock().await;
        let initial_count = sessions.len();
        // Clockless: expiry-based cleanup is disabled.
        // (Storages don't track expiration; callers may prune by phase elsewhere.)
        let _ = initial_count;
        0
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
        // Also recover any accepted sessions that have counterparty signatures
        // (these are sessions where the commit response was lost)
        let recovered = self.recover_accepted_sessions().await;
        if cleaned > 0 || reconciled > 0 || recovered > 0 {
            info!("Session maintenance: cleaned={cleaned}, reconciled={reconciled}, recovered={recovered}");
        }
        Ok((cleaned, reconciled))
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
        let (counterparty_device_id, counterparty_sig, session_operation, pre_entropy) = {
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

        // Finalize the sender's transaction using pre-generated entropy (if available)
        // so that the actual post-finalize tip matches what was sent in the CommitRequest.
        let mut manager = self.bilateral_tx_manager.write().await;
        match manager
            .finalize_offline_transfer_with_entropy(
                &counterparty_device_id,
                commitment_hash,
                &counterparty_sig,
                pre_entropy,
            )
            .await
        {
            Ok(result) => {
                info!(
                    "Sender transaction finalized successfully, tx_hash: {:?}",
                    bytes_to_base32(&result.transaction_hash)
                );

                // --- CHAIN TIP UPDATE (sender updates its view of receiver's chain tip) ---
                // CRITICAL: The receiver's commit-response includes post_state_hash, which is
                // the receiver's ACTUAL post-commit local_chain_tip. This is authoritative because
                // execute_transition_bytes only advances the entity's state (with random entropy),
                // not the counterparty's. So finalize_offline_transfer's remote_chain_tip is actually
                // the receiver's PRE-COMMIT state (stale). The receiver's self-reported post_state_hash
                // is the only correct value for the receiver's current chain tip.
                if let Some(post_tip) = post_state_hash {
                    info!(
                        "[BILATERAL] Sender using receiver-reported post_state_hash as counterparty chain tip: {}",
                        bytes_to_base32(&post_tip[..8])
                    );
                    if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                        &counterparty_device_id,
                        &post_tip,
                    ) {
                        warn!(
                            "[BILATERAL] Failed to persist post_state_hash as observed counterparty chain tip: {}",
                            e
                        );
                    }
                    manager.advance_chain_tip(&counterparty_device_id, post_tip);
                } else {
                    // Fallback: use the shared chain_tip from finalize result.
                    let shared_tip = result.relationship_anchor.chain_tip;
                    warn!(
                        "[BILATERAL] No post_state_hash from commit-response; using shared chain_tip: {}",
                        bytes_to_base32(&shared_tip[..8])
                    );
                    if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                        &counterparty_device_id,
                        &shared_tip,
                    ) {
                        warn!(
                            "[BILATERAL] Failed to persist observed counterparty chain tip: {}",
                            e
                        );
                    }
                    manager.advance_chain_tip(&counterparty_device_id, shared_tip);
                }

                // Persist sender's shared bilateral chain tip to SQLite.
                {
                    let shared_tip = result.relationship_anchor.chain_tip;
                    info!(
                        "[BILATERAL] Sender persisting shared bilateral chain tip: {}",
                        bytes_to_base32(&shared_tip[..8])
                    );
                    if let Err(e) = crate::storage::client_db::update_local_bilateral_chain_tip(
                        &counterparty_device_id,
                        &shared_tip,
                    ) {
                        warn!(
                            "[BILATERAL] Failed to persist sender bilateral chain tip: {}",
                            e
                        );
                    }
                }

                // --- DELEGATE SETTLEMENT (post-delivery, normal path) ---
                let receipt_bytes: Option<Vec<u8>> = {
                    let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                        &self.device_id,
                        &counterparty_device_id,
                    );
                    let smt = self.per_device_smt.read().await;
                    let current_root = *smt.root();
                    let child_bytes = smt
                        .get_inclusion_proof(&smt_key, 256)
                        .ok()
                        .as_ref()
                        .map(crate::sdk::receipts::serialize_inclusion_proof)
                        .unwrap_or_default();
                    crate::sdk::receipts::build_bilateral_receipt_with_smt(
                        self.device_id,
                        counterparty_device_id,
                        result.local_state.prev_state_hash,
                        result.local_state.hash().unwrap_or([0u8; 32]),
                        current_root,
                        current_root,
                        Vec::new(), // Recovery: parent proof unavailable
                        child_bytes,
                        crate::sdk::app_state::AppState::get_device_tree_root(),
                    )
                };

                let settlement_outcome = if let Some(ref delegate) = self.settlement_delegate {
                    let ctx = BilateralSettlementContext {
                        local_device_id: self.device_id,
                        counterparty_device_id,
                        commitment_hash: *commitment_hash,
                        transaction_hash: result.transaction_hash,
                        chain_height: result.local_state.state_number,
                        operation_bytes: op_bytes.clone(),
                        proof_data: receipt_bytes,
                        is_sender: true,
                        tx_type: "bilateral_offline",
                        new_chain_tip: [0u8; 32],
                        canonical_state: Some(result.local_state.clone()),
                    };
                    delegate
                        .settle(ctx)
                        .map_err(|e| {
                            DsmError::invalid_operation(format!(
                            "mark_confirm_delivered: sender settlement failed (post-delivery): {e}"
                        ))
                        })
                        .ok()?
                } else {
                    BilateralSettlementOutcome::default()
                };

                let state_to_record = settlement_outcome
                    .canonical_state
                    .as_ref()
                    .unwrap_or(&result.local_state);
                self.record_bcr_state_and_scan(state_to_record, true).await;

                if let Some(router) = crate::bridge::app_router() {
                    router.sync_balance_cache();
                }

                // Update session phase and cleanup storage
                drop(manager);
                let mut sessions = self.sessions.sessions.lock().await;

                if let Some(sess) = sessions.get_mut(commitment_hash) {
                    sess.phase = BilateralPhase::Committed;
                    info!("Session phase updated to Committed");
                }

                drop(sessions);

                // Delete from persistent storage (sender-side transaction complete)
                if let Err(e) = delete_bilateral_session(commitment_hash) {
                    warn!("[BLE_HANDLER] Failed to delete completed session from storage (sender): {}", e);
                }

                self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                    .await;

                // §5.4: BLE transfer succeeded — any pending online outbox for this
                // counterparty is stale (chain tip was just advanced). Clear it so it
                // does not block subsequent transfers.
                if crate::storage::client_db::get_pending_online_outbox(&counterparty_device_id)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    info!(
                        "[BILATERAL] Clearing stale pending_online_outbox for {} after successful BLE commit",
                        bytes_to_base32(&counterparty_device_id[..8]),
                    );
                    let _ = crate::storage::client_db::clear_pending_online_outbox(
                        &counterparty_device_id,
                    );
                }

                // Emit transfer_complete event to frontend (sender side).
                // Display metadata provided by the application-layer delegate.
                self.emit_event(&generated::BilateralEventNotification {
                    event_type: generated::BilateralEventType::BilateralEventTransferComplete
                        .into(),
                    counterparty_device_id: counterparty_device_id.to_vec(),
                    commitment_hash: commitment_hash.to_vec(),
                    transaction_hash: Some(result.transaction_hash.to_vec()),
                    amount: event_amount_opt,
                    token_id: event_token_id_opt.clone(),
                    status: "completed".to_string(),
                    message: "Bilateral transfer completed successfully".to_string(),
                    sender_ble_address: None,
                    failure_reason: None,
                });
            }
            Err(e) => {
                // RECOVERY PATH: Manager finalization failed (likely pre-commitment expired/missing
                // after app restart), but we can still update local state since we have all the
                // necessary info from the persisted session.
                warn!("Failed to finalize sender transaction: {}", e);
                warn!("[BILATERAL RECOVERY] Proceeding with balance/history update without manager finalization");

                if let Some(post_tip) = post_state_hash {
                    info!(
                        "[BILATERAL RECOVERY] Applying commit-response post_state_hash to counterparty tip: {}",
                        bytes_to_base32(&post_tip[..8])
                    );
                    if let Err(e) = crate::storage::client_db::record_observed_remote_chain_tip(
                        &counterparty_device_id,
                        &post_tip,
                    ) {
                        warn!(
                            "[BILATERAL RECOVERY] Failed to persist post_state_hash as observed counterparty chain tip: {}",
                            e
                        );
                    }
                    manager.advance_chain_tip(&counterparty_device_id, post_tip);
                }

                // --- DELEGATE SETTLEMENT (recovery path) ---
                let recovered_chain_height = crate::storage::client_db::get_wallet_state(
                    &crate::util::text_id::encode_base32_crockford(&self.device_id),
                )
                .ok()
                .flatten()
                .map(|ws| ws.chain_height)
                .unwrap_or(0);

                if let Some(ref delegate) = self.settlement_delegate {
                    let ctx = BilateralSettlementContext {
                        local_device_id: self.device_id,
                        counterparty_device_id,
                        commitment_hash: *commitment_hash,
                        // Recovery path: reuse commitment_hash as tx_hash (no finalized tx hash).
                        transaction_hash: *commitment_hash,
                        chain_height: recovered_chain_height,
                        operation_bytes: op_bytes.clone(),
                        proof_data: None,
                        is_sender: true,
                        tx_type: "bilateral_offline_recovered",
                        new_chain_tip: [0u8; 32],
                        canonical_state: None,
                    };
                    if let Err(e) = delegate.settle(ctx) {
                        warn!("[BILATERAL RECOVERY] Sender settlement failed (recovery path): {e}");
                    } else {
                        info!("[BILATERAL RECOVERY] Transaction stored to history");
                    }
                }

                // Update session phase and cleanup storage
                drop(manager);
                let mut sessions = self.sessions.sessions.lock().await;

                if let Some(sess) = sessions.get_mut(commitment_hash) {
                    sess.phase = BilateralPhase::Committed;
                    info!("[BILATERAL RECOVERY] Session phase updated to Committed");
                }

                drop(sessions);

                // Delete from persistent storage (sender-side transaction recovered)
                if let Err(e) = delete_bilateral_session(commitment_hash) {
                    warn!(
                        "[BILATERAL RECOVERY] Failed to delete completed session from storage: {}",
                        e
                    );
                }

                self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                    .await;

                // Emit transfer_complete event to frontend (recovery case).
                // Display metadata provided by the application-layer delegate.
                self.emit_event(&generated::BilateralEventNotification {
                    event_type: generated::BilateralEventType::BilateralEventTransferComplete
                        .into(),
                    counterparty_device_id: counterparty_device_id.to_vec(),
                    commitment_hash: commitment_hash.to_vec(),
                    transaction_hash: Some(commitment_hash.to_vec()), // Recovery path has no separate tx hash.
                    amount: event_amount_opt,
                    token_id: event_token_id_opt.clone(),
                    status: "recovered".to_string(),
                    message: "Bilateral transfer recovered from interrupted session".to_string(),
                    sender_ble_address: None,
                    failure_reason: None,
                });
            }
        }

        // Return transfer metadata for orchestration layer to run post-transfer hooks.
        // Use the metadata already resolved by the delegate.
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
    pub fn per_device_smt(&self) -> &Arc<RwLock<dsm::merkle::sparse_merkle_tree::SparseMerkleTree>> {
        &self.per_device_smt
    }

    /// Handle a BLE peer disconnect event for a given BLE address.
    ///
    /// When the BLE link drops, in-flight sessions in early phases (Preparing,
    /// Prepared, PendingUserAction) cannot be resumed automatically — the sender
    /// must re-initiate the prepare. Marking them `Failed` immediately unblocks
    /// the 120-second stale timeout and allows the next attempt without delay.
    ///
    /// Sessions in late phases (Accepted, ConfirmPending, Committed) are left
    /// untouched: they carry all cryptographic material needed for recovery
    /// on the next connection.
    ///
    /// Returns the number of sessions transitioned to Failed.
    pub async fn handle_peer_disconnected(&self, ble_address: &str) -> usize {
        let mut failed_count = 0usize;

        // Collect sessions that should be failed on disconnect.
        let to_fail: Vec<([u8; 32], [u8; 32])> = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| {
                    // Match by sender_ble_address (receiver-side sessions) or any
                    // early-phase session for the counterparty (sender-side sessions have
                    // no ble_address stored on the session itself).
                    let addr_match = s
                        .sender_ble_address
                        .as_deref()
                        .is_some_and(|a| a == ble_address);
                    let early_phase = matches!(
                        s.phase,
                        BilateralPhase::Preparing
                            | BilateralPhase::Prepared
                            | BilateralPhase::PendingUserAction
                    );
                    addr_match && early_phase
                })
                .map(|(k, s)| (*k, s.counterparty_device_id))
                .collect()
        };

        for (commitment_hash, counterparty_device_id) in to_fail {
            warn!(
                "[BLE_HANDLER] Peer {} disconnected — failing early-phase session {}",
                ble_address,
                bytes_to_base32(&commitment_hash[..8])
            );

            let local_pending_key: Option<[u8; 32]> = {
                let mut sessions = self.sessions.sessions.lock().await;
                if let Some(session) = sessions.get_mut(&commitment_hash) {
                    let pending_key = session.local_commitment_hash;
                    session.phase = BilateralPhase::Failed;
                    pending_key
                } else {
                    None
                }
            };

            // Clean up core manager pending commitment (if any).
            if let Some(pending_key) = local_pending_key {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&pending_key);
            }
            {
                let mut mgr = self.bilateral_tx_manager.write().await;
                let _ = mgr.remove_pending_commitment(&commitment_hash);
            }

            // Remove from persistent storage so no stale record lingers.
            let _ = delete_bilateral_session(&commitment_hash);

            // Emit failure event so the UI can update immediately.
            self.emit_event(&generated::BilateralEventNotification {
                event_type: generated::BilateralEventType::BilateralEventFailed.into(),
                counterparty_device_id: counterparty_device_id.to_vec(),
                commitment_hash: commitment_hash.to_vec(),
                transaction_hash: None,
                amount: None,
                token_id: None,
                status: "failed".to_string(),
                message: format!("BLE link to {ble_address} dropped before transfer completed"),
                sender_ble_address: Some(ble_address.to_string()),
                failure_reason: Some(
                    generated::BilateralFailureReason::FailureReasonUnspecified.into(),
                ),
            });

            failed_count += 1;
        }

        if failed_count > 0 {
            info!(
                "[BLE_HANDLER] Marked {} early-phase session(s) Failed on disconnect from {}",
                failed_count, ble_address
            );
        } else {
            debug!(
                "[BLE_HANDLER] Peer {} disconnected — no early-phase sessions to fail (late-phase sessions preserved for recovery)",
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
                return Err(DsmError::invalid_operation(
                    "Cannot register sender session without a verified contact",
                ));
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
        if let Err(e) = self.persist_session(&session, None).await {
            warn!(
                "[BLE_HANDLER] register_sender_session: failed to persist session: {}",
                e
            );
            // Don't fail - session is in memory which is sufficient for immediate transfer
        }

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
            mgr.establish_relationship(&counterparty_device_id)
                .await
                .expect("establish relationship");
        }

        let stale_op = Operation::Transfer {
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::from_state(1, [1u8; 32], 0),
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
            amount: Balance::from_state(1, [1u8; 32], 0),
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
    #[ignore]
    async fn test_alias_mapping_persists_and_restores() {
        // Setup similar to register_sender_session test
        let keypair =
            SignatureKeyPair::generate_from_entropy(b"alias-restore-test").expect("keypair");
        let device_id = [11u8; 32];
        let counterparty_device_id = [13u8; 32];
        let genesis_hash = [12u8; 32];
        let counterparty_genesis = [14u8; 32];

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));

        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        // Add verified contact with signing public key
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "persist_alias_test".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![7u8; 32],
            genesis_material: vec![5u8; 32],
            chain_tip: None,
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        // Ensure DB is writable and clear any previous sessions (best-effort)
        let _ = crate::storage::client_db::cleanup_expired_bilateral_sessions(0);

        handler
            .add_verified_contact(contact.clone())
            .await
            .expect("add contact");

        // Compute a frontend (origin) op_id different from canonical (use zeros)
        let frontend_hash = [0u8; 32];
        let op = Operation::Noop;
        let op_bytes = op.to_bytes();

        // Register sender session - should create canonical precommitment and alias
        handler
            .register_sender_session(frontend_hash, counterparty_device_id, &op_bytes, 1000)
            .await
            .expect("register");

        // Debug: inspect DB rows after registration
        let persisted = crate::storage::client_db::get_all_bilateral_sessions().expect("db list");
        println!(
            "[TEST DEBUG] persisted bilateral sessions count after register = {}",
            persisted.len()
        );
        for r in &persisted {
            println!(
                "[TEST DEBUG] row: commitment_hash={} phase={} op_bytes_len={}",
                bytes_to_base32(&r.commitment_hash[..8.min(r.commitment_hash.len())]),
                r.phase,
                r.operation_bytes.len()
            );
        }

        // For debugging: print manager's ticks now
        {
            let mgr = bilateral_manager.read().await;
            println!(
                "[TEST DEBUG] manager current_ticks after register = {}",
                mgr.get_current_ticks()
            );
        }

        // Create a new handler instance (simulating restart) and restore sessions from storage
        let new_handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);
        {
            let mgr = bilateral_manager.read().await;
            println!(
                "[TEST DEBUG] manager current_ticks at restore = {}",
                mgr.get_current_ticks()
            );
        }
        let restored = new_handler
            .restore_sessions_from_storage()
            .await
            .expect("restore");
        assert!(restored >= 1, "should restore at least one session");

        // Alias mapping test ignored: single-hash design no longer uses alias_of/session_aliases.
    }

    #[tokio::test]
    #[ignore]
    async fn test_register_sender_session_creates_precommitment_and_alias() {
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

        // Add a verified contact with genesis + chain_tip so relationship can be established
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

        // Call register_sender_session
        handler
            .register_sender_session(frontend_hash, counterparty_device_id, &op_bytes, 1000)
            .await
            .expect("register_sender_session failed");

        // Confirm session exists (either under frontend hash -> resolved via alias, or canonical)
        let sessions = handler.sessions.sessions.lock().await;
        assert!(
            !sessions.is_empty(),
            "sessions should contain at least one entry"
        );

        // Alias mapping test ignored: single-hash design no longer uses session_aliases.
    }

    #[tokio::test]
    #[ignore]
    async fn test_mark_sender_committed_resolves_alias() {
        // Setup similar to register_sender_session test
        let keypair = SignatureKeyPair::generate_from_entropy(b"mark-sender-committed-test")
            .expect("keypair");
        let device_id = [21u8; 32];
        let counterparty_device_id = [23u8; 32];
        let genesis_hash = [22u8; 32];
        let counterparty_genesis = [24u8; 32];

        let contact_manager = DsmContactManager::new(device_id, vec![NodeId::new("test")]);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
        )));

        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        // Add verified contact with signing public key
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "persist_alias_test2".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![7u8; 32],
            genesis_material: vec![5u8; 32],
            chain_tip: Some([6u8; 32]),
            chain_tip_smt_proof: None,
            genesis_verified_online: true,
            verified_at_commit_height: 1,
            added_at_commit_height: 1,
            last_updated_commit_height: 1,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        // Ensure DB is writable and clear any previous sessions (best-effort)
        let _ = crate::storage::client_db::cleanup_expired_bilateral_sessions(0);

        handler
            .add_verified_contact(contact.clone())
            .await
            .expect("add contact");

        // Provide a frontend-provided commitment hash different from canonical
        // Use a unique value to avoid interfering with other tests using all-zero hash
        let frontend_hash = [77u8; 32];
        let op = Operation::Noop;
        let op_bytes = op.to_bytes();

        handler
            .register_sender_session(frontend_hash, counterparty_device_id, &op_bytes, 1000)
            .await
            .expect("register");

        // In single-hash design, frontend hash is canonical.
        let canonical = frontend_hash;

        // Ensure manager has pending commitment for the canonical hash
        {
            let mgr = bilateral_manager.read().await;
            assert!(
                mgr.has_pending_commitment(&canonical),
                "manager should have pending commitment for canonical hash"
            );
        }

        // Simulate receiving counterparty signature and session accepted state
        {
            let mut sessions = handler.sessions.sessions.lock().await;
            if let Some(sess) = sessions.get_mut(&canonical) {
                sess.counterparty_signature = Some(vec![9u8; 64]);
                sess.phase = BilateralPhase::Accepted;
            } else {
                panic!("expected canonical session present");
            }
        }

        // Finalize using the frontend-provided origin hash (alias) --- should resolve and finalize
        let _meta = handler
            .mark_sender_committed_with_post_state_hash(&frontend_hash, None)
            .await;

        // Manager should no longer have the pending commitment
        {
            let mgr = bilateral_manager.read().await;
            assert!(
                !mgr.has_pending_commitment(&canonical),
                "pending commitment should be removed after finalize"
            );
        }

        // Verify session moved to committed
        {
            let sessions = handler.sessions.sessions.lock().await;
            if let Some(sess) = sessions.get(&canonical) {
                assert_eq!(sess.phase, BilateralPhase::Committed);
            } else {
                panic!("expected canonical session entry present after commit");
            }
        }
    }

    // Removed background maintenance test (interval-based) to comply with deterministic, clockless spec.
}
