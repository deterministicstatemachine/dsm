// SPDX-License-Identifier: MIT OR Apache-2.0

//! BLE Bilateral Transaction Handler
//!
//! Implements the complete offline bilateral transaction protocol over Bluetooth Low Energy:
//! 1. Prepare phase: Create pre-commitments
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

/// This device's Device Tree commitment `R_G` (§2.3), as genesis persisted it
/// in the app state. A device without one has no identity to sign receipts
/// under; no root is derived in its place.
fn local_device_tree_commitment(
) -> Result<dsm::types::receipt_types::DeviceTreeAcceptanceCommitment, DsmError> {
    crate::sdk::app_state::AppState::get_device_tree_commitment().ok_or_else(|| {
        DsmError::invalid_operation("this device holds no Device Tree commitment in its app state")
    })
}

/// Which side of a bilateral receipt the local device is signing.
///
/// In whitepaper §11.1 per-step EK signing, both parties to a bilateral
/// transition stamp their own per-step EK certificate + signature on the
/// stitched receipt. `A` is the sender's side (initiates the transfer) and
/// `B` is the receiver's side (counter-signs after acceptance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BilateralSide {
    A,
    B,
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

/// Load `device_id`'s persisted contact into the bilateral manager. The
/// in-memory manager can miss a contact the client database holds (an
/// init-time sync that raced `contacts.add`); a device that is not a contact is
/// refused.
fn sync_contact_from_storage(
    mgr: &mut BilateralTransactionManager,
    device_id: &[u8; 32],
) -> Result<(), DsmError> {
    let record = crate::storage::client_db::get_contact_by_device_id(device_id)
        .map_err(|e| DsmError::storage(format!("contact lookup: {e}"), None::<std::io::Error>))?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "Bilateral transactions require a verified contact. Please add the contact first.",
            )
        })?;
    let contact = record
        .to_verified_contact()
        .map_err(|e| DsmError::storage(format!("contact: {e}"), None::<std::io::Error>))?;
    mgr.add_verified_contact(contact)
}

/// A stored relationship tip, or why it could not be read.
fn stored_contact_tip(
    read: anyhow::Result<Option<[u8; 32]>>,
) -> Result<Option<[u8; 32]>, DsmError> {
    read.map_err(|e| DsmError::storage(format!("relationship tip: {e}"), None::<std::io::Error>))
}

impl BilateralBleHandler {
    /// The keys a peer sent must be the keys its contact record pins from its
    /// self-proving directory entry: the signing AK equal, the Kyber key equal,
    /// and the Kyber identity binding verifying under the pinned AK. Nothing
    /// sent is stored; any other key refuses the message.
    fn require_pinned_peer_keys(
        counterparty_device_id: &[u8; 32],
        wire_signing_key: &[u8],
        wire_kyber_pk: &[u8],
        wire_binding_sig: &[u8],
        label: &str,
    ) -> Result<(), DsmError> {
        let contact = crate::storage::client_db::get_contact_by_device_id(counterparty_device_id)
            .map_err(|e| {
                DsmError::storage(
                    format!("{label}: contact unreadable: {e}"),
                    None::<std::io::Error>,
                )
            })?
            .ok_or_else(|| DsmError::relationship(format!("{label}: the peer is not a contact")))?;
        if wire_signing_key != contact.public_key.as_slice() {
            return Err(DsmError::invalid_operation(format!(
                "{label}: the signing key sent is not the contact's pinned AK"
            )));
        }
        if wire_kyber_pk != contact.kyber_public_key.as_slice() {
            return Err(DsmError::invalid_operation(format!(
                "{label}: the Kyber key sent is not the contact's pinned Kyber key"
            )));
        }
        let genesis: [u8; 32] = contact.genesis_hash.as_slice().try_into().map_err(|_| {
            DsmError::invalid_operation(format!("{label}: the contact's genesis is not 32 bytes"))
        })?;
        crate::sdk::kyber_identity::verify_kyber_identity_binding(
            counterparty_device_id,
            &genesis,
            wire_kyber_pk,
            wire_binding_sig,
            &contact.public_key,
        )
        .map_err(|e| {
            DsmError::invalid_operation(format!(
                "{label}: the Kyber identity binding does not verify under the pinned AK: {e}"
            ))
        })
    }

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
        mgr.consume_pre_commitment(&pending_key);
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
        mgr.consume_pre_commitment(&pending_key);
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
        mgr.consume_pre_commitment(&pending_key);
    }

    /// Apply per-step EK signing (whitepaper §11.1) to an unsigned bilateral
    /// receipt. Looks up the counterparty's Kyber pubkey from the contact
    /// record, fetches the local AK keypair from the bilateral transaction
    /// manager, fetches the chain-head wrap key for SK encryption, runs the
    /// per-step signing helper, stamps the artifacts on the receipt's local
    /// side (A for sender, B for receiver), and advances the local chain
    /// head. Returns the full-protobuf bytes of the signed receipt.
    ///
    /// `commitment_hash` is the bilateral session's commitment hash for
    /// this transition — the session-level precommit that BOTH the
    /// per-step EK derivation context (HKDF "DSM/ek" salt input) AND the
    /// receipt challenge-response target (BLAKE3 "DSM/receipt-bind-session"
    /// preimage, whitepaper §11.1 Item 7) bind to. The whitepaper uses
    /// the symbol `C_pre` for this same value at the protocol layer; we
    /// use `commitment_hash` here to make the session-equivalence
    /// name-evident at the call sites and avoid future refactor drift.
    ///
    /// `side` selects which side of the bilateral receipt to stamp:
    ///   * `BilateralSide::A` — local device is the sender (stamps
    ///     `ek_pk_a`/`ek_cert_a`/`kyber_ct_a`/`sig_a`).
    ///   * `BilateralSide::B` — local device is the receiver counter-signing
    ///     (stamps `ek_pk_b`/`ek_cert_b`/`kyber_ct_b`/`sig_b`).
    async fn sign_receipt_with_per_step_ek_for_bilateral(
        &self,
        unsigned_receipt_bytes: Vec<u8>,
        counterparty_device_id: &[u8; 32],
        parent_tip: [u8; 32],
        commitment_hash: [u8; 32],
        side: BilateralSide,
    ) -> Result<Vec<u8>, DsmError> {
        let mut receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
            &unsigned_receipt_bytes,
        )?;
        let receipt_commitment = receipt.compute_commitment()?;

        let recipient_kyber_pk =
            match crate::storage::client_db::get_contact_by_device_id(counterparty_device_id) {
                Ok(Some(c)) if !c.kyber_public_key.is_empty() => c.kyber_public_key,
                _ => {
                    return Err(DsmError::invalid_operation(
                        "bilateral receipt: counterparty contact missing Kyber public key — \
                     re-establish contact to upgrade for per-step EK signing",
                    ));
                }
            };

        let (ak_pk, ak_sk) = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.ak_keypair_for_cert_chain()
        };

        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            counterparty_device_id,
        );

        let signing_inputs = crate::sdk::receipts::PerStepSigningInputs {
            commitment: &receipt_commitment,
            h_n: parent_tip,
            // C_pre is the precommit for this transition. In the bilateral
            // BLE flow the bilateral session's commitment_hash IS C_pre
            // (verified at the call sites); the parameter rename above
            // makes the equivalence name-evident.
            c_pre: commitment_hash,
            devid_sender: self.device_id,
            relationship_key: rel_key,
            root_ak_keypair: Some((&ak_pk, &ak_sk)),
            recipient_kyber_pk: &recipient_kyber_pk,
            // §11.1 Item 7: bind the per-step EK response to this
            // bilateral session via the BLAKE3 "DSM/receipt-bind-session"
            // domain-separated challenge-response target. Using the same
            // commitment_hash value here as in `c_pre` keeps EK derivation
            // and receipt authorization on the same proposed transition.
            session_binding: &commitment_hash,
        };
        let signing_out = crate::sdk::receipts::sign_receipt_with_per_step_ek(&signing_inputs)?;

        let at_rest_key = crate::init::current_chain_head_at_rest_key()?;
        match side {
            BilateralSide::A => {
                receipt.set_ek_pk_a(signing_out.ek_pk.clone());
                receipt.set_ek_cert_a(signing_out.ek_cert);
                receipt.set_kyber_ct_a(signing_out.kyber_ct);
                receipt.add_sig_a(signing_out.sig);

                // §11.1 sender side: DEFER the Local chain-head advance to
                // commit-response time (`mark_sender_committed_with_post_state_hash`
                // promotes it). Advancing here — at confirm BUILD — moved the
                // Local head past a step the receiver could still reject
                // (e.g. offline-bearer MissingRelease) or never see; every
                // subsequent transfer then signed a cert the receiver could
                // not chain back to its expected prior head, permanently
                // wedging the relationship. The receiver's own mirror of this
                // chain (Counterparty side) already advances only at commit;
                // stashing keeps the two in lockstep.
                crate::storage::client_db::stash_pending_local_head(
                    &rel_key,
                    &commitment_hash,
                    &signing_out.ek_pk,
                    &signing_out.ek_sk,
                    &at_rest_key,
                    signing_out.used_root_ak,
                )
                .map_err(|e| {
                    DsmError::invalid_operation(format!("stash pending local chain head: {e}"))
                })?;
                debug!(
                    "[BILATERAL] §11.1 stashed pending Local chain-head advance (used_root_ak={}) for commitment {}",
                    signing_out.used_root_ak,
                    bytes_to_base32(&commitment_hash[..8]),
                );
            }
            BilateralSide::B => {
                receipt.set_ek_pk_b(signing_out.ek_pk.clone());
                receipt.set_ek_cert_b(signing_out.ek_cert);
                receipt.set_kyber_ct_b(signing_out.kyber_ct);
                receipt.add_sig_b(signing_out.sig);

                // §11.1 receiver side: the B-side counter-sign runs AFTER
                // the canonical commit succeeded in `handle_confirm_request`,
                // so advancing immediately here is already commit-gated.
                crate::sdk::receipts::advance_local_chain_head_after_signing(
                    &rel_key,
                    &signing_out.ek_pk,
                    &signing_out.ek_sk,
                    &at_rest_key,
                    signing_out.used_root_ak,
                )?;
            }
        }

        receipt.to_full_protobuf()
    }

    pub fn new(
        bilateral_tx_manager: Arc<RwLock<BilateralTransactionManager>>,
        device_id: [u8; 32],
    ) -> Self {
        // Use the shared Per-Device SMT singleton (initialized during SDK bootstrap).
        // Falls back to a fresh instance if bootstrap hasn't run yet (e.g. tests).
        let per_device_smt = Arc::new(RwLock::new(
            dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(),
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
            // Rendered here, at the one point every emitter passes through.
            // Ten call sites construct these notifications; asking each to
            // remember the display form is how the balance path ended up
            // enriching only the rows that needed it least.
            let mut event = event.clone();
            // The display form needs the token's decimals; an event that names
            // no token, or a token whose decimals are unknown, carries only its
            // base-unit amount.
            if let (Some(amount), Some(token_id)) = (event.amount, event.token_id.as_deref()) {
                match crate::handlers::wallet_routes::token_decimals(token_id) {
                    Ok(decimals) => {
                        event.display_amount = Some(
                            crate::handlers::wallet_routes::format_base_units_for_display(
                                amount, decimals,
                            ),
                        );
                    }
                    Err(e) => warn!("bilateral event {token_id}: no display amount: {e}"),
                }
            }
            callback(&event.encode_to_vec());
        }
    }

    // record_bcr_state(...) deleted: per §2.2/§4.3, canonical state is the
    // per-relationship chain state + Per-Device SMT root. The BLE handler
    // MUST NOT write a duplicate snapshot from a derived settlement-time
    // State.
    //
    // Note: the BLE bilateral path advances the relationship chain via
    // `BilateralTransactionManager::prepare_bilateral_advance` (§6.1
    // tripwire) followed by the canonical Core advance in
    // `AppRouter::execute_on_relationship_for_bilateral`.
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
                // Rendered in emit_event, the one boundary all emitters cross.
                display_amount: None,
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
                mgr.consume_pre_commitment(&pending_key);
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

        // Build reject message, signed: the proposer abandons its proposal only
        // for a rejection this device signed.
        let rejector_signature = self
            .bilateral_tx_manager
            .read()
            .await
            .sign_rejection(&commitment_hash, &reason)?;
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            reason: reason.clone(),
            rejector_device_id: self.device_id.to_vec(),
            send_status: Some(send_status),
            rejector_signature,
        };

        // Wrap in envelope with per-relationship chain tip
        let envelope = self
            .create_envelope(generated::envelope::Payload::BilateralPrepareReject(reject))
            .await;

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
                "persisted bilateral session",
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
            sender_ble_address: record.sender_ble_address.clone(),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: record.stitched_receipt_bytes.clone(),
            receiver_challenge: None,
            anchor_leaf: None,
            anchor_sim_root: None,
            offline_spend: None,
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
            sender_ble_address: session.sender_ble_address.clone(),
            stitched_receipt_bytes: session.stitched_receipt_bytes.clone(),
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
        let terminal_sessions: Vec<BilateralSessionRecord> = records
            .into_iter()
            .filter(|record| {
                record.counterparty_device_id == counterparty_vec
                    && matches!(record.phase.as_str(), "committed" | "rejected" | "failed")
            })
            .collect();

        if terminal_sessions.len() <= MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY {
            return 0;
        }

        // Newest first: get_all_bilateral_sessions returns insertion order, descending.
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
    /// The return value is the count of sessions restored into memory. Current
    /// startup policy marks interrupted sessions failed instead of resuming them,
    /// so callers should inspect persisted session state for failure details.
    /// Restore bilateral sessions from SQLite at startup.
    ///
    /// **Concurrency invariant — startup-only entry point.**
    /// This function MUST only be called from the SDK bootstrap path
    /// (currently `bluetooth::mod.rs` inside the init-time
    /// `rt.block_on`), BEFORE any BLE handler begins processing live
    /// messages. The §11.1 Item 8b wedge-recovery sweep below mutates
    /// `cert_chain_heads.Counterparty` based on the cert-link gate; if
    /// a concurrent live-handler path also writes to the same row
    /// (e.g., a normal bilateral commit's inline advance), the result
    /// is racy.
    ///
    /// The crypto gate (verify_ek_cert under current Counterparty)
    /// makes the sweep effectively idempotent for benign double-runs
    /// in the same startup, but it does NOT serialize against
    /// concurrent writes from a live handler. Do not add a
    /// "Repair Database" UI button or a background-task entry point
    /// without first wrapping cert-chain-head writes in a SQL
    /// transaction held across the verify→advance pair.
    ///
    /// **Multi-step wedge recovery (Item 8b enhancement):** the wedge
    /// sweep iterates to a fixed point — keep running over the
    /// candidate set until a full pass produces no advances. This
    /// recovers chains of single-step wedges within one relationship
    /// (theoretical N consecutive crashes inside the inline window)
    /// and is order-independent: candidates can be processed in any
    /// SQLite-returned order and the chain still resolves. Bounded by
    /// the number of candidate rows (each pass advances at most once
    /// per row), so worst case O(N²) verify_ek_cert calls — fine for
    /// startup.
    pub async fn restore_sessions_from_storage(&self) -> Result<usize, DsmError> {
        info!("[BLE_HANDLER] Restoring bilateral sessions from storage...");

        let records = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to restore sessions: {}", e))
        })?;

        let mut counterparties: HashSet<[u8; 32]> = HashSet::new();
        let mut failed_count = 0;
        let mut deleted_malformed_count = 0;
        let mut wedge_recovered_count = 0;
        // Phase-1 pass collects wedge candidates while validating /
        // pruning the rest. We DEFER all advance_cert_chain_head calls
        // until phase 2 (fixed-point loop) so the order of records
        // doesn't matter for chained recoveries.
        let mut wedge_candidates: Vec<(
            Vec<u8>,                                      // commitment_hash (for logging)
            [u8; 32],                                     // rel_key
            dsm::types::receipt_types::StitchedReceiptV2, // decoded receipt
        )> = Vec::new();

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

            let mut counterparty_device_id_arr: Option<[u8; 32]> = None;
            if record.counterparty_device_id.len() == 32 {
                let mut counterparty_device_id = [0u8; 32];
                counterparty_device_id.copy_from_slice(&record.counterparty_device_id);
                counterparties.insert(counterparty_device_id);
                counterparty_device_id_arr = Some(counterparty_device_id);
            }

            if matches!(record.phase.as_str(), "committed" | "rejected" | "failed") {
                debug!(
                    "[BLE_HANDLER] Skipping terminal persisted session on restore: phase={}",
                    record.phase
                );
                continue;
            }

            // §11.1 Item 8b — Counterparty cert-chain-head wedge
            // recovery sweep. Phase 1: COLLECT candidates here. Phase 2
            // (fixed-point loop after this for-loop) iterates over the
            // candidate set, calling verify_ek_cert + advance, until a
            // full pass produces no advances. Deferring the advance to
            // phase 2 makes the recovery order-independent — chains of
            // single-step wedges within a relationship resolve
            // regardless of the SQLite query's row order.
            //
            // Safety: the cert-link check (in phase 2) is the gate.
            // Verification only passes when current Counterparty IS
            // the prior chain head. Receipts where Counterparty is
            // already advanced (cert chains from older key) fail the
            // check and the sweep skips. Receipts unrelated to this
            // relationship also fail. Conservative by construction —
            // never advance unless cryptographically provable.
            if record.phase == "confirm_pending" {
                if let Some(counterparty_id) = counterparty_device_id_arr {
                    if let Some(ref bytes) = record.stitched_receipt_bytes {
                        match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                            bytes,
                        ) {
                            Ok(receipt)
                                if !receipt.ek_pk_b.is_empty() && !receipt.ek_cert_b.is_empty() =>
                            {
                                let rel_key =
                                    dsm::core::bilateral_transaction_manager::compute_smt_key(
                                        &self.device_id,
                                        &counterparty_id,
                                    );
                                wedge_candidates.push((
                                    record.commitment_hash.clone(),
                                    rel_key,
                                    receipt,
                                ));
                            }
                            Ok(_) => {
                                // ek_pk_b empty — B-side never
                                // verified; this is a normal in-flight
                                // ConfirmPending session, not a wedge.
                            }
                            Err(_) => {
                                // Receipt malformed — leave to existing
                                // "mark failed" handling.
                            }
                        }
                    }
                }
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

            // §11.1 — the session is abandoned; drop any pending Local
            // chain-head advance stashed for it so the EK material does
            // not linger. The Local head itself never moved (promotion is
            // commit-gated), so the next transfer signs from the prior
            // head both sides still agree on.
            if let Some(counterparty_id) = counterparty_device_id_arr {
                if record.commitment_hash.len() == 32 {
                    let mut ch = [0u8; 32];
                    ch.copy_from_slice(&record.commitment_hash);
                    let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                        &self.device_id,
                        &counterparty_id,
                    );
                    match crate::storage::client_db::drop_pending_local_head(&rel_key, &ch) {
                        Ok(true) => {
                            debug!(
                                "[BLE_HANDLER] §11.1 dropped pending Local chain-head stash for abandoned session {}",
                                bytes_to_base32(&ch[..8])
                            );
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(
                                "[BLE_HANDLER] §11.1 failed to drop pending Local chain-head stash during restore: {}",
                                e
                            );
                        }
                    }
                }
            }

            failed_count += 1;
        }

        // §11.1 Item 8b — Phase 2: fixed-point wedge recovery.
        //
        // Iterate over `wedge_candidates` until a full pass yields no
        // advances. This handles chains of single-step wedges where
        // SQLite returns candidates in an arbitrary order: a candidate
        // for transition `n+1` whose cert chains from `EK_pk_n` may
        // appear before the candidate for transition `n` whose cert
        // chains from `EK_pk_{n-1}`. The first pass advances `n`; the
        // next pass advances `n+1` (which now verifies because
        // Counterparty advanced).
        //
        // The cert-link gate (verify_ek_cert under current
        // Counterparty) makes each advance cryptographically provable
        // and the pass-by-pass progress monotonic. Bounded by
        // `wedge_candidates.len()` outer iterations because each pass
        // advances Counterparty for AT MOST one candidate per row, so
        // after N passes either everything is recovered or no further
        // progress is possible.
        let max_passes = wedge_candidates.len();
        for _pass in 0..max_passes {
            let mut advanced_this_pass = 0usize;
            for (commitment_hash, rel_key, receipt) in &wedge_candidates {
                let current_cp_pk = match crate::storage::client_db::load_cert_chain_head_pubkey(
                    rel_key,
                    crate::storage::client_db::CertChainSide::Counterparty,
                ) {
                    Ok(Some(pk)) => pk,
                    _ => continue, // No row to advance against; skip.
                };

                // Skip if already at the target — nothing to do.
                if current_cp_pk == receipt.ek_pk_b {
                    continue;
                }

                match dsm::crypto::ephemeral_key::verify_ek_cert(
                    &current_cp_pk,
                    &receipt.ek_pk_b,
                    &receipt.parent_tip,
                    &receipt.ek_cert_b,
                ) {
                    Ok(true) => {
                        // Wedge case: current Counterparty IS the prior
                        // chain head, advance.
                        match crate::storage::client_db::advance_cert_chain_head(
                            rel_key,
                            crate::storage::client_db::CertChainSide::Counterparty,
                            &receipt.ek_pk_b,
                        ) {
                            Ok(Some(step)) => {
                                info!(
                                    "[BLE_HANDLER] §11.1 Item 8b: reconciled Counterparty wedge for commitment {} → step {}",
                                    bytes_to_base32(
                                        &commitment_hash
                                            [..8.min(commitment_hash.len())]
                                    ),
                                    step
                                );
                                wedge_recovered_count += 1;
                                advanced_this_pass += 1;
                            }
                            Ok(None) => {
                                debug!(
                                    "[BLE_HANDLER] §11.1 Item 8b: Counterparty row vanished between load and advance — skipping"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "[BLE_HANDLER] §11.1 Item 8b: failed to advance Counterparty during wedge recovery: {}",
                                    e
                                );
                            }
                        }
                    }
                    Ok(false) => {
                        // Cert link fails — Counterparty is either at
                        // an unrelated state, or this candidate's cert
                        // chains from a head NOT YET reached (will be
                        // tried again in a later pass once an earlier
                        // wedge is recovered).
                    }
                    Err(e) => {
                        debug!(
                            "[BLE_HANDLER] §11.1 Item 8b: verify_ek_cert error during wedge recovery: {} — skipping",
                            e
                        );
                    }
                }
            }
            // Fixed point reached — no further progress possible.
            if advanced_this_pass == 0 {
                break;
            }
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
        if wedge_recovered_count > 0 {
            info!(
                "[BLE_HANDLER] §11.1 Item 8b: reconciled {} Counterparty cert-chain-head wedge(s) during restore",
                wedge_recovered_count
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
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        info!("Preparing BLE bilateral transaction");

        // BLE/USB is the OFFLINE transport: value over it is bearer-tier only,
        // drawn from the offline-cash allocation. An online-tier Transfer uses
        // the network transport — refused before any session state exists
        // (owner ruling 2026-08-28; the receiver refuses the same shape in
        // `handle_prepare_request`).
        if matches!(operation, Operation::Transfer { .. })
            && !dsm::core::bilateral_transaction_manager::operation_requires_offline_bearer(
                &operation,
            )
        {
            return Err(DsmError::invalid_operation(
                "bilateral prepare refused: BLE/USB carries offline-bearer transfers only — an \
                 online-tier transfer uses the network transport",
            ));
        }

        self.ensure_counterparty_ready_for_prepare(&counterparty_device_id)
            .await?;

        // FINALITY BARRIER — same authority as `wallet.send`, BEFORE any value
        // mutation: a BLE origination is an origination. Refused while our
        // prior online send on this relationship has not reached its
        // checkpoint, or an inbound acceptance still awaits the peer's
        // certificate. (Loopback to self is a test-only path with no
        // relationship state.)
        if counterparty_device_id != self.device_id {
            match crate::handlers::relationship_status::finality_barrier_block(
                &counterparty_device_id,
            ) {
                Ok(None) => {}
                Ok(Some(blocked)) => {
                    return Err(DsmError::invalid_operation(format!(
                        "bilateral.prepare refused (finality barrier): {}",
                        blocked.send_block_message
                    )));
                }
                Err(e) => {
                    return Err(DsmError::invalid_operation(format!(
                        "bilateral.prepare: cannot evaluate the finality barrier: {e}"
                    )));
                }
            }
        }

        // The counterparty is a contact, and the relationship is established
        // over its pinned key. A self-device counterparty takes the same path as
        // any other: a real contact record, or a refusal (owner, 2026-09-23).
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if !mgr.has_verified_contact(&counterparty_device_id) {
                sync_contact_from_storage(&mut mgr, &counterparty_device_id)?;
            }
            if mgr.get_relationship(&counterparty_device_id).is_none() {
                mgr.establish_relationship(&counterparty_device_id)
                    .await
                    .map_err(|e| {
                        DsmError::relationship(format!("the relationship is not established: {e}"))
                    })?;
            }
        }

        // The relationship's persisted tip is the one the prepare builds on.
        {
            let stored_tip = stored_contact_tip(crate::storage::client_db::get_contact_chain_tip(
                &counterparty_device_id,
            ))?
            .ok_or_else(|| DsmError::relationship("the counterparty is not a contact"))?;
            let mut mgr = self.bilateral_tx_manager.write().await;
            mgr.advance_chain_tip(&counterparty_device_id, stored_tip);
        }

        // Detached ML-KEM identity binding (ADR 0002): the Kyber key and a SPHINCS+ signature
        // over binding_digest(device_id, genesis, kyber_pk) under our own AK, which the receiver
        // checks against the keys it pinned for us. Without them (locked wallet, no key) there is
        // no prepare to send, and nothing is staged.
        let (sender_kyber_public_key, sender_kyber_binding_sig) =
            crate::sdk::kyber_identity::build_local_kyber_identity_binding()?;

        // Prepare offline transfer in core
        let (pre_commitment, local_genesis_hash) = {
            let mut manager = self.bilateral_tx_manager.write().await;
            let pre_commitment = manager
                .prepare_offline_transfer(&counterparty_device_id, operation.clone())
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
            m.sign_commitment(&pre_commitment.bilateral_commitment_hash)?
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
            sender_ble_address: None, // Sender side - no counterparty BLE address yet
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
            receiver_challenge: None,
            anchor_leaf: None,
            anchor_sim_root: None,
            offline_spend: None,
        };

        // The session is durable before anything is sent; a session that could
        // not be kept is not started.
        if let Err(e) = self.persist_session(&session, None).await {
            self.bilateral_tx_manager
                .write()
                .await
                .consume_pre_commitment(&pre_commitment.bilateral_commitment_hash);
            return Err(e);
        }
        {
            let mut sessions = self.sessions.sessions.lock().await;
            sessions.insert(pre_commitment.bilateral_commitment_hash, session.clone());
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
                                // Persist it to the contact (transport state only).
                                if let Err(e) = crate::storage::client_db::update_contact_ble_status(
                                    &counterparty_device_id,
                                    None,
                                    Some(addr),
                                ) {
                                    warn!(
                                        "[BLE_HANDLER] BLE address {} not persisted for the contact: {}",
                                        addr, e
                                    );
                                }
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

        let prepare_request = generated::BilateralPrepareRequest {
            counterparty_device_id: counterparty_device_id.to_vec(),
            operation_data: operation.to_bytes(),
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
            // transfer_amount and token_id_hint are UI-only hints; protocol
            // correctness is carried entirely by operation_data.  The transport
            // layer does not extract token-specific fields from the Operation.
            transfer_amount: 0,
            token_id_hint: String::new(),
            memo_hint: String::new(),
            transfer_amount_display: String::new(),
            sender_kyber_public_key,
            sender_kyber_binding_sig,
        };

        let envelope = self
            .create_envelope(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: Some(generated::Hash32 {
                            v: pre_commitment.bilateral_commitment_hash.to_vec(),
                        }),
                        actor: self.device_id.to_vec(),
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
                },
            ))
            .await;

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
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        self.prepare_bilateral_transaction(counterparty_device_id, operation)
            .await
    }

    /// A_NEW side initiate (spec §0.5 bilateral re-establish). After identity recovery, call this
    /// — with an active BLE session to `counterparty_device_id` (a recovered contact) — to build
    /// the recovery-establish operation over C's REAL `(A_old,C)` frontier and start the ordinary
    /// bilateral prepare carrying it. The returned `(envelope_bytes, commitment_hash)` is sent
    /// over BLE exactly like any other prepare; C automatically gates co-signing on the
    /// re-establish accept-guard (see [`Self::handle_prepare_request`]).
    ///
    /// This is the symmetric counterpart to the wired accept-guard. The only device-dependent
    /// step is having a live session to C; the op construction + carry-forward are deterministic.
    /// Fail-closed: A had no sealed relationship with the counterparty, or C has no posted
    /// `(A_old,C)` leaf to source its current tip, aborts before any prepare is sent.
    pub async fn initiate_recovery_reestablish(
        &self,
        counterparty_device_id: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        let op =
            crate::sdk::RecoverySDK::begin_recovery_reestablish(&counterparty_device_id).await?;
        self.prepare_bilateral_transaction_with_commitment(counterparty_device_id, op)
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
                mgr.consume_pre_commitment(&pending_key);
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
            mgr.consume_pre_commitment(&pending_key);
            if pending_key != commitment_hash {
                mgr.consume_pre_commitment(&commitment_hash);
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
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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
        let envelope = crate::envelope::from_canonical_bytes(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_envelope",
                "protobuf",
                Some(format!(
                    "Failed to decode Envelope: {}. Raw BilateralPrepareRequest is not supported.",
                    e
                )),
                None::<std::io::Error>,
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

        // Deserialize operation
        let operation = Operation::from_bytes(&prepare_request.operation_data)
            .map_err(|_| DsmError::invalid_operation("invalid operation payload"))?;

        // BLE/USB is the OFFLINE transport: the only value it carries is the
        // bearer tier, drawn from the device-bound offline-cash allocation. An
        // online-tier Transfer has the network transport and no business here
        // — refused at the door, before any session state exists, so the
        // capability is unavailable rather than merely gated deeper in
        // `advance` (owner ruling 2026-08-28).
        if matches!(operation, Operation::Transfer { .. })
            && !dsm::core::bilateral_transaction_manager::operation_requires_offline_bearer(
                &operation,
            )
        {
            return Err(DsmError::invalid_operation(
                "bilateral prepare refused: BLE/USB carries offline-bearer transfers only — an \
                 online-tier transfer uses the network transport",
            ));
        }

        // §0.5 recovery re-establish accept-guard (gate 1 of the two-gate model). If this
        // prepare is a recovery-establish proposal (canonical marker), C MUST verify — before
        // co-signing — that A_new holds the genesis-anchored recovery authority and that the
        // carry-forward commitment bridges C's REAL CURRENT (A_old,C) frontier. This blocks a
        // non-authority forger (MITM / malicious node / C itself) and blocks ANYONE from
        // re-establishing onto a fabricated or stale frontier; it does NOT (and cannot)
        // distinguish the owner from a mnemonic thief — double-spend safety vs a recovering
        // party comes from gate 2 (P5 LOCKED_RECOVERY + frontier reconciliation). Fail-closed:
        // any failure aborts the prepare (C does not co-sign). `sender_device_id` is A_new.
        // Ordinary establishes are untouched (guard runs only for the recovery-establish marker).
        if dsm::recovery::is_recovery_establish_op(&operation) {
            crate::sdk::RecoverySDK::verify_incoming_recovery_reestablish(
                &operation,
                &sender_device_id,
            )
            .await?;
            info!(
                "Recovery re-establish accept-guard PASSED for sender={}",
                bytes_to_base32(&sender_device_id[..8])
            );
        }

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
            if !mgr.has_verified_contact(&counterparty_device_id) {
                sync_contact_from_storage(&mut mgr, &counterparty_device_id)?;
            }

            // §5.4 Modal Synchronization Lock: reject offline if pending online for (A,B)
            {
                let smt_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                    &self.device_id,
                    &counterparty_device_id,
                );
                let mut modal_locked =
                    crate::security::modal_sync_lock::is_pending_online(&smt_key);
                if modal_locked {
                    log::warn!(
                        "[BilateralBleHandler] ⚠️ §5.4 in-memory modal lock set for ({}, {}). Checking SQLite recovery before rejecting.",
                        bytes_to_base32(&self.device_id[..8]),
                        bytes_to_base32(&counterparty_device_id[..8]),
                    );
                }
                // Read, decide and delete atomically (one transaction). Under the
                // finality barrier a gate is stale ONLY when no unsettled or
                // checkpoint-pending outbox row stands behind it — the sender's
                // self-reported tip is not a release signal (after local
                // finalization the tip has moved by construction while the send
                // is still not final for the peer).
                match crate::storage::client_db::clear_stale_pending_online_gate(
                    &counterparty_device_id,
                ) {
                    Ok(outcome) => {
                        use crate::storage::client_db::StaleGateOutcome;
                        match outcome {
                            StaleGateOutcome::NoGate => {}
                            StaleGateOutcome::Cleared => {
                                log::info!(
                                    "[BilateralBleHandler] ✅ Pending online gate was stale and is cleared for ({}, {})",
                                    bytes_to_base32(&self.device_id[..8]),
                                    bytes_to_base32(&counterparty_device_id[..8]),
                                );
                                crate::security::modal_sync_lock::clear_pending_online(&smt_key);
                                modal_locked = false;
                            }
                            StaleGateOutcome::StillPending => {
                                log::error!(
                                    "[BilateralBleHandler] ❌ persisted online gate: a prior online transfer for ({}, {}) is not yet final for the peer. Rejecting offline.",
                                    bytes_to_base32(&self.device_id[..8]),
                                    bytes_to_base32(&counterparty_device_id[..8]),
                                );
                                return Err(DsmError::invalid_operation(
                                    "§5.4: Cannot initiate offline transfer while a prior online transfer for this relationship is still awaiting recipient catch-up",
                                ));
                            }
                            StaleGateOutcome::Raced => {
                                log::error!(
                                    "[BilateralBleHandler] ❌ §5.4 gate changed under the clear for ({}, {}). Rejecting offline.",
                                    bytes_to_base32(&self.device_id[..8]),
                                    bytes_to_base32(&counterparty_device_id[..8]),
                                );
                                return Err(DsmError::invalid_operation(
                                    "§5.4: the pending online gate changed while it was being cleared",
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        // Includes a malformed persisted tip, which previously became [0u8; 32]
                        // and guaranteed a delete that matched nothing.
                        log::error!(
                            "[BilateralBleHandler] ❌ failed to evaluate persisted online gate for ({}, {}): {}",
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

            Self::require_pinned_peer_keys(
                &counterparty_device_id,
                &prepare_request.sender_signing_public_key,
                &prepare_request.sender_kyber_public_key,
                &prepare_request.sender_kyber_binding_sig,
                "prepare-request",
            )?;

            if mgr.get_relationship(&counterparty_device_id).is_none() {
                mgr.establish_relationship(&counterparty_device_id)
                    .await
                    .map_err(|e| {
                        DsmError::relationship(format!("Failed to establish relationship: {e}"))
                    })?;
            }
        }

        // The sender's expectation is checked against the relationship tip this
        // device holds durably; the manager builds on the same tip. A mismatch
        // means the sender's view is stale, and the proposal is rejected.
        let our_local_chain_tip: [u8; 32] = stored_contact_tip(
            crate::storage::client_db::get_contact_chain_tip(&counterparty_device_id),
        )?
        .ok_or_else(|| DsmError::relationship("the counterparty is not a contact"))?;
        self.bilateral_tx_manager
            .write()
            .await
            .advance_chain_tip(&counterparty_device_id, our_local_chain_tip);

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
                // Rendered in emit_event, the one boundary all emitters cross.
                display_amount: None,
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
            let rejector_signature = self
                .bilateral_tx_manager
                .read()
                .await
                .sign_rejection(&origin_commitment_hash, &reason)?;
            let reject = generated::BilateralPrepareReject {
                commitment_hash: Some(generated::Hash32 {
                    v: origin_commitment_hash.to_vec(),
                }),
                reason,
                rejector_device_id: self.device_id.to_vec(),
                send_status: Some(send_status),
                rejector_signature,
            };
            let envelope = self
                .create_envelope(generated::envelope::Payload::BilateralPrepareReject(reject))
                .await;
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
                .prepare_offline_transfer(&counterparty_device_id, operation.clone())
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
            m.sign_commitment(&origin_commitment_hash)?
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
            sender_ble_address: sender_ble_address.clone(),
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
            receiver_challenge: None,
            anchor_leaf: None,
            anchor_sim_root: None,
            offline_spend: None,
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
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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

        // Receiver challenge r_R: the receiver-generated freshness
        // nonce the sender MUST bind into the offline release, so a replayed or pre-computed release
        // for a different receiver session is rejected. Fresh CSPRNG per prepare-response
        // (deterministic under a seeded test RNG). Stashed against this commitment so the confirm's
        // release can be checked to bind the same r_R.
        let receiver_challenge: [u8; 32] = dsm::crypto::rng::random_bytes(32)
            .try_into()
            .map_err(|_| DsmError::invalid_operation("random_bytes(32) wrong length"))?;
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&origin_commitment_hash) {
                s.receiver_challenge = Some(receiver_challenge);
            }
        }

        // Detached ML-KEM identity binding (ADR 0002), as on the request path. Without it there
        // is no response to send.
        let (responder_kyber_public_key, responder_kyber_binding_sig) =
            crate::sdk::kyber_identity::build_local_kyber_identity_binding()?;
        // Build prepare response
        let prepare_response = generated::BilateralPrepareResponse {
            commitment_hash: Some(generated::Hash32 {
                v: origin_commitment_hash.to_vec(),
            }),
            local_signature: session.local_signature.clone().ok_or_else(|| {
                DsmError::invalid_operation(
                    "the receiver's session holds no signature over the commitment",
                )
            })?,
            counterparty_state_hash: Some(generated::Hash32 {
                v: shared_chain_tip.to_vec(),
            }),
            local_state_hash: Some(generated::Hash32 {
                v: shared_chain_tip.to_vec(),
            }),
            responder_signing_public_key: local_signing_key,
            receiver_challenge: receiver_challenge.to_vec(),
            responder_kyber_public_key,
            responder_kyber_binding_sig,
        };

        // Wrap in envelope
        let response_envelope = self
            .create_envelope(generated::envelope::Payload::BilateralPrepareResponse(
                prepare_response,
            ))
            .await;

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
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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
            if let Some(removed) = mgr.consume_pre_commitment(&pending_key) {
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

        // Build reject envelope, signed.
        let rejector_signature = self
            .bilateral_tx_manager
            .read()
            .await
            .sign_rejection(&origin_commitment_hash, &reason)?;
        let reject = generated::BilateralPrepareReject {
            commitment_hash: Some(generated::Hash32 {
                v: origin_commitment_hash.to_vec(),
            }),
            reason,
            rejector_device_id: self.device_id.to_vec(),
            send_status: Some(send_status),
            rejector_signature,
        };

        let envelope = self
            .create_envelope(generated::envelope::Payload::BilateralPrepareReject(reject))
            .await;

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
        let envelope = crate::envelope::from_canonical_bytes(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_reject",
                "protobuf",
                Some(e.to_string()),
                None::<std::io::Error>,
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

        // A rejection ends only a proposal this device sent to the rejector, and
        // only when the rejector signed it under the key its contact pins.
        // Anything else changes nothing.
        let rejected_session = {
            let sessions = self.sessions.sessions.lock().await;
            let session = sessions.get(&commitment_hash).ok_or_else(|| {
                DsmError::invalid_operation("no session found for commitment hash")
            })?;
            if session.counterparty_device_id != rejector_device_id {
                return Err(DsmError::invalid_operation(
                    "the rejection is not from the device the proposal went to",
                ));
            }
            // Past its prepare the proposal was accepted: a rejection then is the
            // counterparty contradicting its own signature, not an answer.
            if !matches!(
                session.phase,
                BilateralPhase::Preparing | BilateralPhase::Prepared
            ) {
                return Err(DsmError::invalid_operation(
                    "a rejection answers only a proposal still awaiting its answer",
                ));
            }
            let mut rejected = session.clone();
            rejected.phase = BilateralPhase::Rejected;
            rejected
        };
        self.bilateral_tx_manager.read().await.verify_rejection(
            &rejector_device_id,
            &commitment_hash,
            &reject.reason,
            &reject.rejector_signature,
        )?;

        self.persist_session(&rejected_session, None).await?;
        if let Some(session) = self
            .sessions
            .sessions
            .lock()
            .await
            .get_mut(&commitment_hash)
        {
            session.phase = BilateralPhase::Rejected;
        }
        // The proposal is abandoned: the sender's relationship tip stays where it was.
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&commitment_hash);

        self.prune_terminal_sessions_for_counterparty(&rejector_device_id)
            .await;

        // Emit rejection event
        self.emit_event(&generated::BilateralEventNotification {
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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
        let envelope = crate::envelope::from_canonical_bytes(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_prepare_response",
                "protobuf",
                Some(e.to_string()),
                None::<std::io::Error>,
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

        // Stash the receiver's challenge r_R against our sender-side session, so the confirm's
        // offline-bearer release can bind it. Absent/short -> left None, which keeps the
        // offline-bearer send path fail-closed (no release produced).
        if let Ok(r_r) = <[u8; 32]>::try_from(prepare_response.receiver_challenge.as_slice()) {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.receiver_challenge = Some(r_r);
            }
        }

        {
            let counterparty_device_id = {
                let sessions = self.sessions.sessions.lock().await;
                sessions
                    .get(&commitment_hash)
                    .map(|s| s.counterparty_device_id)
            }
            .ok_or_else(|| {
                DsmError::invalid_operation("prepare-response: no session for this commitment")
            })?;
            Self::require_pinned_peer_keys(
                &counterparty_device_id,
                &prepare_response.responder_signing_public_key,
                &prepare_response.responder_kyber_public_key,
                &prepare_response.responder_kyber_binding_sig,
                "prepare-response",
            )?;
        }

        // Resolve session first (no mutation yet)
        let counterparty_device_id = {
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

            if let Some(session) = sessions.get(&commitment_hash) {
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
                session.counterparty_device_id
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

        // Verify receiver signature (σ_B) before mutating/persisting sender session.
        if prepare_response.local_signature.is_empty() {
            return Err(DsmError::invalid_operation(
                "missing counterparty signature (σ_B) in prepare response",
            ));
        }

        let counterparty_pubkey = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.get_contact(&counterparty_device_id)
                .ok_or_else(|| DsmError::invalid_operation("missing counterparty contact"))?
                .public_key
                .clone()
        };
        let mut signature_msg = Vec::with_capacity(22 + 32);
        signature_msg.extend_from_slice(b"DSM/bilateral-sign\0");
        signature_msg.extend_from_slice(&commitment_hash);

        if !crate::crypto::signatures::SignatureKeyPair::verify_raw(
            &signature_msg,
            &prepare_response.local_signature,
            &counterparty_pubkey,
        )
        .map_err(|e| DsmError::crypto(format!("verify σ_B failed: {e}"), None::<std::io::Error>))?
        {
            return Err(DsmError::invalid_operation(
                "invalid counterparty signature (σ_B)",
            ));
        }

        // Update session with counterparty signature after cryptographic verification.
        let updated_session = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(session) = sessions.get_mut(&commitment_hash) {
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
                session.counterparty_signature = Some(prepare_response.local_signature.clone());
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

        // 3. Get shared chain tip h_n. The transition's entropy and the
        //    successor h_{n+1} are computed AFTER the canonical prepare
        //    simulation below: the entropy is Core's derivation inside
        //    `advance` (Part VII step 3), read off the simulated outcome —
        //    nothing here chooses it.
        // Re-sync from SQLite in case an online transaction advanced the tip.
        {
            let mut mgr = self.bilateral_tx_manager.write().await;
            if let Some(sqlite_tip) = stored_contact_tip(
                crate::storage::client_db::get_contact_chain_tip(&session.counterparty_device_id),
            )? {
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

        // 4. Build sender SMT proofs via a prepare-only simulation of the
        // canonical advance (§2.2). No canonical state mutation yet — that
        // happens after the receiver ACKs, inside
        // `mark_sender_committed_with_post_state_hash`. Identical inputs
        // produce an identical outcome there, so the simulated receipt
        // proofs are byte-exact with the eventual advance.
        //
        // Sender balance deltas are ALWAYS empty on this transport: a bearer
        // Transfer draws from the offline-cash allocation (`offline_spend`
        // below), never the online balance, and a non-Transfer operation
        // moves no value. The online-tier debit arm that used to live here —
        // and the fallback that let a failed appliance staging silently
        // proceed as an online-balance debit — are deleted, not gated (owner
        // ruling 2026-08-28: online transfers use the network transport).
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &session.counterparty_device_id,
        );
        let router = crate::bridge::app_router().ok_or_else(|| {
            DsmError::state_machine(
                "send_bilateral_confirm: app_router not installed; cannot simulate advance",
            )
        })?;
        // v2 producer phase 1 (Software-Authority / Hardware-Identity): for offline-bearer
        // transfers, STAGE the next anchor transition from the appliance's active state — the
        // transition Δ, the successor frontier h_{i+1}, and the successor anchor-state leaf —
        // with NO appliance mutation yet. The leaf is fed into the advance simulation below so the
        // real device roots R_i/R_{i+1} and inclusion proofs Π_i/Π_{i+1} exist BEFORE the appliance
        // signs anything (simulate-first: the release is born with the real roots, never stamped
        // with placeholders and never re-stamped). A bearer transfer that cannot stage — no
        // receiver challenge, or an appliance failure — is REFUSED here: value over this
        // transport only ever moves allocation-backed, so there is no online-debit path to fall
        // back to. Non-Transfer operations (predicate false) stage nothing and carry no value.
        let staged_bearer =
            if dsm::core::bilateral_transaction_manager::operation_requires_offline_bearer(
                &session.operation,
            ) {
                match (session.receiver_challenge, &session.operation) {
                    (
                        Some(r_r),
                        Operation::Transfer {
                            token_id,
                            authority_policy: Some(authority_policy),
                            ..
                        },
                    ) => {
                        let object_id = dsm::crypto::blake3::domain_hash_bytes(
                            dsm::crypto::domain::TaggedHashDomain::from_static(
                                b"DSM/bearer-object/v1",
                            ),
                            token_id,
                        );
                        let payload_hash = dsm::crypto::blake3::domain_hash_bytes(
                            dsm::crypto::domain::TaggedHashDomain::from_static(
                                b"DSM/bearer-payload/v1",
                            ),
                            &op_bytes,
                        );
                        let authority_policy_hash = authority_policy.policy_id;
                        // Policy-binding trace (sender → chip PREPARE): the value the chip commits as
                        // `authority_policy_hash` MUST equal the receiver's canonical policy_id, or the
                        // proof is meaningless. Compared against the canonical value here.
                        info!(
                            "[BILATERAL][offline-bearer][sender] staging authority_policy_hash={} (canonical_match={})",
                            bytes_to_base32(&authority_policy_hash),
                            authority_policy_hash
                                == dsm::types::operations::canonical_offline_bearer_policy().policy_id
                        );
                        let staged = router
                            .stage_offline_bearer_transition(
                                rel_key,
                                session.counterparty_device_id,
                                object_id,
                                payload_hash,
                                authority_policy_hash,
                                0,
                                // action_fields: EMPTY. The operation is already bound into the transition
                                // via `payload_hash = H(op_bytes)` above, so carrying the full `op_bytes`
                                // here is redundant AND overflows the appliance's `MAX_ACTION_FIELDS` (256)
                                // once the OfflineBearerRequired policy tail is appended (~266 B). The
                                // receiver recomputes the digest from the transition carried in the
                                // release, so empty is consistent end-to-end.
                                Vec::new(),
                                r_r,
                            )
                            .map_err(|e| {
                                DsmError::invalid_operation(format!(
                                    "offline-bearer staging failed — a bearer transfer cannot \
                                     proceed without the appliance transition: {e}"
                                ))
                            })?;
                        Some((staged, r_r))
                    }
                    _ => {
                        return Err(DsmError::invalid_operation(
                            "offline-bearer transfer without a receiver challenge — the prepare \
                             exchange did not establish r_R; refusing to build the confirm",
                        ));
                    }
                }
            } else {
                None
            };
        // Offline-bearer transfer: draw value from the device-bound offline-cash allocation, not the online
        // balance. Build the allocation-spend descriptor ONCE here — it carries the anchor bundle B from the
        // staged appliance, which is NOT recoverable from anchor_leaf's H(B) key, so it is stashed on
        // the session (below) and threaded identically into the canonical commit. Empty deltas and
        // Some(offline_spend) are ONE atomic decision (empty deltas without offline_spend is rejected
        // by the conservation guard — the fail-closed case).
        let offline_spend: Option<dsm::types::device_state::OfflineSpend> =
            match (staged_bearer.as_ref(), &session.operation) {
                (
                    Some((staged, _)),
                    dsm::types::operations::Operation::Transfer {
                        amount, token_id, ..
                    },
                ) => {
                    // §9.5: independently resolve the sender's installed policy_commit.
                    // Unresolved is a REFUSAL — the deleted online-debit fallback used to
                    // stand in here, and empty deltas without a spend would only die
                    // later in the conservation guard; fail at the seam instead.
                    let asset = crate::bridge::app_router()
                        .map(|r| r.resolve_policy_commit_strict(token_id))
                        .ok_or_else(|| {
                            DsmError::state_machine(
                                "send_bilateral_confirm: app_router not installed; cannot \
                                 resolve the bearer asset",
                            )
                        })?
                        .map_err(|e| {
                            DsmError::invalid_operation(format!(
                                "bearer transfer refused: policy_commit unresolved for token {} \
                                 — {e}",
                                String::from_utf8_lossy(token_id)
                            ))
                        })?;
                    Some(dsm::types::device_state::OfflineSpend {
                        anchor_bundle_b: staged.pin.bundle,
                        asset,
                        amount: amount.value(),
                    })
                }
                _ => None,
            };
        // Sender deltas are ALWAYS empty on this transport: bearer value moves via the
        // allocation debit (`offline_spend`), and nothing else here moves value.
        let sim_outcome = router.simulate_advance_for_confirm(
            rel_key,
            session.counterparty_device_id,
            session.operation.clone(),
            &[],
            staged_bearer.as_ref().map(|(s, _)| s.anchor_leaf.clone()),
            // Bearer→allocation: draw the value from the offline-cash allocation instead of the online balance.
            // The same descriptor is stashed on the session and used at the canonical commit.
            offline_spend,
        )?;
        // The root the relationship path authenticates h_n under: the device
        // head the step starts from (the relationship was established before
        // its first step, so no seeding stands between the two).
        let pre_root = sim_outcome.smt_proofs.pre_root;
        let sender_smt_root = sim_outcome.child_r_a;

        // The one entropy of this transition (§39.2–39.3): Core derived it
        // inside the simulated `advance`; the canonical commit at finalize
        // re-derives the identical value from the identical inputs and the
        // finalize path refuses to commit if it does not. It goes into the
        // relationship tip (already, inside the outcome) and into BOTH receipt
        // hashes here; the receiver recomputes h_{n+1} from the carried value.
        let pre_entropy: [u8; 32] = sim_outcome.transition_entropy();
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.pre_finalize_entropy = Some(pre_entropy);
            }
        }
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
        // v2 producer phase 2: drive the appliance PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT →
        // FINALIZE with the REAL device roots the simulation just produced, and attach Π_i/Π_{i+1}
        // (the anchor-state inclusion proofs from the same simulation) to the release package. The
        // simulation above already folded the staged leaf into R_{i+1}, so a failed release cannot
        // ride empty (the confirm's roots would be inconsistent with the canonical commit) — it
        // FAILS the confirm build, after a best-effort cancel returns an appliance stuck between
        // PREPARE and COMMIT to Ready.
        let bearer_artifacts = match staged_bearer.as_ref() {
            None => None,
            Some((staged, r_r)) => {
                let (proof_prev, proof_next) = sim_outcome
                    .anchor_proofs
                    .as_ref()
                    .map(|p| (p.parent.clone(), p.child.clone()))
                    .ok_or_else(|| {
                        DsmError::state_machine(
                            "offline-bearer: simulation produced no anchor-state proofs (fail closed)",
                        )
                    })?;
                match router.release_offline_bearer(
                    staged,
                    *r_r,
                    pre_root,
                    sender_smt_root,
                    proof_prev,
                    proof_next,
                ) {
                    Ok(art) => Some(art),
                    Err(e) => {
                        let _ = router.cancel_offline_bearer_release();
                        return Err(DsmError::state_machine(format!(
                            "offline-bearer release failed (fail closed, no confirm sent): {e}"
                        )));
                    }
                }
            }
        };
        // Receiver-admit fold: every bearer confirm discloses the fused-anchor pin material
        // (B/anchor_id/H0/pk_host/pk_chip), bound to this transfer — never a standalone message.
        // The receiver pins it TOFU on the first transfer and verifies same-anchor on every
        // subsequent one; ordinary transfers carry no disclosure.
        let anchor_disclosure = bearer_artifacts
            .as_ref()
            .map(|art| self.build_anchor_disclosure(&art.pin, &session.operation))
            .transpose()?;
        // Stash the driven successor leaf AND the sim post-root so the canonical commit in
        // `mark_sender_committed_with_post_state_hash` applies the byte-exact same leaf the on-wire
        // proofs were built from, and can enforce both-or-neither (committed root == this sent sim
        // root). Mirrors the `pre_finalize_entropy` stash; only set for bearer transfers.
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                if let Some(art) = bearer_artifacts.as_ref() {
                    s.anchor_leaf = Some(art.anchor_leaf.clone());
                    s.anchor_sim_root = Some(sender_smt_root);
                    // Carry the allocation-spend descriptor forward (Copy) so the canonical commit debits
                    // the SAME allocation the sim did — the bundle B is not recoverable from anchor_leaf.
                    s.offline_spend = offline_spend;
                }
            }
        }
        // Override the receipt tips: SMT stores the asymmetric (A-side)
        // chain tips, so the receipt must carry those to satisfy §4.3
        // inclusion-proof acceptance.
        let parent_tip_receipt = sim_outcome.smt_proofs.parent_proof.value.ok_or_else(|| {
            DsmError::invalid_operation(
                "send_bilateral_confirm: the advance's relationship path carries no parent tip",
            )
        })?;
        let child_tip_receipt = sim_outcome.new_chain_state.compute_chain_tip();

        // 6. Build stitched receipt with real SMT roots + proofs (§4.2).
        // Tips are A-side asymmetric (what T_A stores + what the inclusion
        // proofs prove inclusion of). The symmetric `h_n_plus_1` is still
        // sent over the wire in the confirm envelope for tripwire +
        // contacts.chain_tip alignment.
        let unsigned_receipt_bytes = crate::sdk::receipts::build_bilateral_receipt_with_smt(
            self.device_id,
            session.counterparty_device_id,
            parent_tip_receipt,
            child_tip_receipt,
            pre_root,
            sender_smt_root,
            &sim_outcome.smt_proofs.parent_proof,
            &local_device_tree_commitment()?,
            pre_entropy,
        )?;

        // 6b. Per-step EK signing (whitepaper §11.1). Sign the receipt
        // commitment with a freshly-derived per-step EK, generate the cert
        // chaining it back to AK, and include the Kyber ciphertext for
        // the recipient to recover identical k_step. Sender stamps the
        // A-side fields.
        let receipt_bytes = self
            .sign_receipt_with_per_step_ek_for_bilateral(
                unsigned_receipt_bytes,
                &session.counterparty_device_id,
                parent_tip_receipt,
                commitment_hash, // bilateral commitment IS the precommit for this step
                BilateralSide::A,
            )
            .await?;

        // Cache the signed receipt on the sender's session so post-restart
        // recovery (mark_sender_committed_with_post_state_hash) can reuse the
        // already-signed bytes verbatim instead of attempting to re-sign with
        // a chain head that has since advanced past this step.
        {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&commitment_hash) {
                s.stitched_receipt_bytes = Some(receipt_bytes.clone());
            }
        }

        // 7. Build BilateralConfirmRequest using the simulated sender post-root.
        let confirm_request = generated::BilateralConfirmRequest {
            commitment_hash: Some(generated::Hash32 {
                v: commitment_hash.to_vec(),
            }),
            sender_signature: local_sig,
            // The receipt carries the step's one relationship path and both
            // roots (§4.2); the confirm repeats none of them.
            stitched_receipt: receipt_bytes,
            shared_chain_tip_new: Some(generated::Hash32 {
                v: h_n_plus_1.to_vec(),
            }),
            // §C1: transmit entropy so receiver can independently verify h_{n+1} (§4.1)
            pre_entropy: pre_entropy.to_vec(),
            // Canonical v2 offline release, emitted by the appliance with the REAL device roots in
            // its signed transcript and Π_i/Π_{i+1} attached to the package — carried VERBATIM (no
            // re-stamp; the roots were signed correct at birth). Non-Transfer operations leave it
            // empty; every Transfer on this transport is bearer and staged one above.
            offline_release: bearer_artifacts
                .as_ref()
                .map(|a| a.offline_release.clone())
                .unwrap_or_default(),
            anchor_disclosure,
        };

        // 8. Wrap in envelope
        let envelope = self
            .create_envelope(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: Some(generated::Hash32 {
                            v: commitment_hash.to_vec(),
                        }),
                        actor: self.device_id.to_vec(),
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
                },
            ))
            .await;

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

    /// Build the fused-anchor pin disclosure the sender attaches to EVERY bearer confirm.
    /// `bundle/anchor_id/H0/pk_host/pk_chip` come from the driven appliance's pin; the receiver
    /// pins it TOFU on the first transfer and verifies same-anchor on every subsequent one.
    fn build_anchor_disclosure(
        &self,
        pin: &crate::anchor::AnchorPin,
        operation: &Operation,
    ) -> Result<generated::AnchorDisclosure, DsmError> {
        let policy_hash =
            match operation {
                Operation::Transfer {
                    authority_policy: Some(ap),
                    ..
                } => ap.policy_id,
                _ => return Err(DsmError::invalid_operation(
                    "an anchor disclosure rides only a bearer transfer, which names its authority \
                     policy",
                )),
            };
        Ok(generated::AnchorDisclosure {
            bundle: pin.bundle.to_vec(),
            anchor_id: pin.anchor_id.to_vec(),
            enrolled_counter: pin.enrolled_counter,
            partition_pk: pin.partition_pk.clone(),
            policy_hash: policy_hash.to_vec(),
            pk_chip: pin.pk_chip.clone(),
        })
    }

    /// Receiver-admit fold: admit (pin) the sender's disclosed fused anchor, bound to a VERIFIED
    /// contact. `pin_admit_decision` rules: a new anchor is admitted (first-transfer TOFU); a
    /// matching disclosure is a no-op; a DIFFERING anchor is rejected and the pinned one kept
    /// (silent substitution never succeeds via a transfer). Admission is a memory of what to
    /// verify — it never implies acceptance. Malformed disclosures are ignored fail-closed.
    async fn admit_anchor_disclosure(
        &self,
        sender_device_id: [u8; 32],
        commitment_hash: [u8; 32],
        d: &generated::AnchorDisclosure,
    ) {
        let contact_verified = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.has_verified_contact(&sender_device_id)
        };
        let parsed = (|| {
            let bundle = <[u8; 32]>::try_from(d.bundle.as_slice()).ok()?;
            let anchor_id = <[u8; 32]>::try_from(d.anchor_id.as_slice()).ok()?;
            let policy = <[u8; 32]>::try_from(d.policy_hash.as_slice()).ok()?;
            // pk_chip is REQUIRED in a v2 disclosure — a pin without it cannot verify σ^chip.
            if d.pk_chip.len() != 32 {
                return None;
            }
            Some((
                policy,
                dsm::crypto::anchor_enrollment::FusedAnchorPin {
                    bundle,
                    anchor_id,
                    enrolled_counter: d.enrolled_counter,
                    partition_pk: d.partition_pk.clone(),
                    pk_chip: d.pk_chip.clone(),
                    uncompromised: true,
                },
            ))
        })();
        match (
            contact_verified,
            parsed,
            crate::bridge::anchor_enrollment_store(),
        ) {
            (true, Some((policy, disclosed)), Some(store)) => {
                let existing = store.get(&sender_device_id);
                match crate::bluetooth::anchor_accept::pin_admit_decision(
                    sender_device_id,
                    policy,
                    &disclosed,
                    existing.as_ref(),
                ) {
                    crate::bluetooth::anchor_accept::PinAdmitDecision::Admit(e) => {
                        let anchor_id = e.pin.anchor_id;
                        match store.admit(e) {
                            Ok(()) => {
                                info!(
                                    "[BILATERAL] fused anchor PINNED for {} (first-transfer TOFU admit)",
                                    bytes_to_base32(&sender_device_id[..8])
                                );
                                // Stage 4 Slice 3 (signal b): surface the first-transfer trust so the
                                // receiver UI can say "trusted anchor for <contact>". The message
                                // carries the Base32 anchor id.
                                self.emit_event(&generated::BilateralEventNotification {
                                    // Rendered in emit_event, the one boundary all emitters cross.
                                    display_amount: None,
                                    event_type:
                                        generated::BilateralEventType::BilateralEventAnchorPinned
                                            .into(),
                                    counterparty_device_id: sender_device_id.to_vec(),
                                    commitment_hash: commitment_hash.to_vec(),
                                    transaction_hash: None,
                                    amount: None,
                                    token_id: None,
                                    status: "anchor_pinned_first_transfer".to_string(),
                                    message: bytes_to_base32(&anchor_id),
                                    sender_ble_address: None,
                                    failure_reason: None,
                                });
                            }
                            Err(err) => warn!(
                                "[BILATERAL] fused anchor admit failed (continuing fail-closed): {err}"
                            ),
                        }
                    }
                    crate::bluetooth::anchor_accept::PinAdmitDecision::NoChange => {}
                    crate::bluetooth::anchor_accept::PinAdmitDecision::Reject(reason) => {
                        // A pinned anchor's identity changed on a later transfer — a security event,
                        // not a routine failure. The transfer is ALREADY rejected fail-closed by the
                        // acceptance predicate (it verifies against the PINNED anchor) and the pinned
                        // anchor is kept; here we only SURFACE it (owner directive). The log line is
                        // the audit record; the event drives a prominent security warning in the UI.
                        warn!(
                            "[BILATERAL] fused anchor disclosure REJECTED for {} ({reason}); keeping the pinned anchor",
                            bytes_to_base32(&sender_device_id[..8])
                        );
                        self.emit_event(&generated::BilateralEventNotification {
                            // Rendered in emit_event, the one boundary all emitters cross.
                            display_amount: None,
                            event_type: generated::BilateralEventType::BilateralEventAnchorChanged
                                .into(),
                            counterparty_device_id: sender_device_id.to_vec(),
                            commitment_hash: commitment_hash.to_vec(),
                            transaction_hash: None,
                            amount: None,
                            token_id: None,
                            status: "anchor_identity_changed".to_string(),
                            message: reason.to_string(),
                            sender_ble_address: None,
                            failure_reason: None,
                        });
                    }
                }
            }
            (false, _, _) => warn!(
                "[BILATERAL] fused anchor disclosure ignored: sender is not a verified contact"
            ),
            (_, None, _) => {
                warn!("[BILATERAL] fused anchor disclosure ignored: malformed fields (fail-closed)")
            }
            (_, _, None) => {}
        }
    }

    /// Sender-side terminal acknowledgment: finalize only after the receiver confirms it has
    /// completed its side of the bilateral transfer.
    pub async fn handle_commit_response(&self, envelope_bytes: &[u8]) -> Result<(), DsmError> {
        let envelope = crate::envelope::from_canonical_bytes(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_commit_response_envelope",
                "protobuf",
                Some(e.to_string()),
                None::<std::io::Error>,
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

        match phase {
            Some(BilateralPhase::ConfirmPending) => {}
            Some(BilateralPhase::Committed) => {
                info!(
                    "[BILATERAL] handle_commit_response: duplicate ack for already-committed session {}",
                    bytes_to_base32(&commitment_hash[..8])
                );
                return Ok(());
            }
            // Nothing this device is committing: the ack cannot be verified
            // against a session, so it finalizes nothing and changes nothing.
            Some(BilateralPhase::Failed) | None => {
                return Err(DsmError::invalid_operation(format!(
                    "commit ack for {}, a session this device is not committing (failed or \
                     unknown): nothing is finalized",
                    bytes_to_base32(&commitment_hash[..8])
                )));
            }
            Some(other) => {
                return Err(DsmError::invalid_operation(format!(
                    "commit ack received for non-ConfirmPending session: {:?}",
                    other
                )));
            }
        };

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

        // §11.1 sender-side B-side verification: the receiver counter-signs
        // their locally-built copy of the stitched receipt with B-side
        // per-step EK signing artifacts and ships those bytes back in
        // `counter_signed_receipt`. Verify that:
        //   1. The bytes parse as a `StitchedReceiptV2`.
        //   2. The receipt's identity fields match this transfer (anti-
        //      substitution: `devid_a` is the counterparty, `devid_b` is
        //      this sender).
        //   3. Cert chain link: `ek_cert_b` chains `ek_pk_b` back to the
        //      receiver's prior cert-chain head — loaded from
        //      `cert_chain_heads` (Local-side from the receiver's POV =
        //      Counterparty-side from this sender's POV) or falling back
        //      to the contact's AK_pk at relationship genesis.
        //   4. Receipt sig: `sig_b` verifies under `ek_pk_b` over the
        //      receipt's canonical commitment.
        // On success we replace the in-memory cached A-only receipt with
        // the fully co-signed bytes so settlement archives both sigs. A
        // commit response without a counter-signed receipt is not a valid
        // offline receipt authorization path.
        // §11.1 Item 8 (B-tight): the Counterparty chain-head advance
        // that was previously here has been moved INSIDE
        // `mark_sender_committed_with_post_state_hash`, where it sits
        // tightly adjacent to canonical commit + session deletion.
        // Sourcing `ek_pk_b` from the in-session cached receipt
        // (replaced below on B-side verify success) lets the advance
        // happen at the right SQL boundary without plumbing extra
        // context through the function call. The startup
        // reconciliation sweep covers any remaining wedge window.

        if response.counter_signed_receipt.is_empty() {
            return Err(DsmError::invalid_operation(
                "BilateralCommitResponse omits counter_signed_receipt; rejecting",
            ));
        }
        {
            // Fetch the counterparty (receiver) device_id from the session
            // store. Required for identity checks and chain-head lookup; if
            // the session is gone we skip verification (recovery path).
            let counterparty_device_id_opt: Option<[u8; 32]> = {
                let sessions = self.sessions.sessions.lock().await;
                sessions
                    .get(&commitment_hash)
                    .map(|s| s.counterparty_device_id)
            };

            if let Some(counterparty_device_id) = counterparty_device_id_opt {
                match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                    &response.counter_signed_receipt,
                ) {
                    Ok(counter_signed) => {
                        // Identity check — the receiver builds the receipt
                        // with their own device_id as devid_a and the
                        // sender's as devid_b. Anti-substitution: any
                        // counter-signed receipt for an unrelated transfer
                        // would carry mismatched ids.
                        if counter_signed.devid_a != counterparty_device_id {
                            return Err(DsmError::invalid_operation(
                                "counter_signed_receipt: devid_a does not match the counterparty \
                                 of this session — possible substitution",
                            ));
                        }
                        if counter_signed.devid_b != self.device_id {
                            return Err(DsmError::invalid_operation(
                                "counter_signed_receipt: devid_b does not match this sender \
                                 device_id — possible substitution",
                            ));
                        }

                        // The receipt this sender archives as the step's proof
                        // holds its state rules against the Device Tree
                        // commitment kept for the receiver.
                        let receiver_device_tree =
                            crate::storage::client_db::get_contact_device_tree_root(
                                &counterparty_device_id,
                            )?
                            .ok_or_else(|| {
                                DsmError::invalid_operation(
                                    "counter_signed_receipt: no Device Tree commitment is kept \
                                     for the receiver",
                                )
                            })?;
                        dsm::verification::receipt_verification::verify_receipt_state(
                            &counter_signed,
                            &dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(
                                receiver_device_tree,
                            ),
                        )?;

                        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                            &self.device_id,
                            &counterparty_device_id,
                        );
                        // From this sender's view, the RECEIVER's chain head
                        // lives in the Counterparty-side row of
                        // cert_chain_heads.
                        let prev_pk_from_chain =
                            crate::storage::client_db::load_cert_chain_head_pubkey(
                                &rel_key,
                                crate::storage::client_db::CertChainSide::Counterparty,
                            )
                            .map_err(|e| {
                                DsmError::storage(
                                    format!(
                                        "counter_signed_receipt verify: the receiver's cert-chain \
                                         head is unreadable: {e}"
                                    ),
                                    None::<std::io::Error>,
                                )
                            })?;
                        let expected_prev_pk = match prev_pk_from_chain {
                            Some(pk) => pk,
                            None => {
                                let manager = self.bilateral_tx_manager.read().await;
                                manager
                                    .get_contact(&counterparty_device_id)
                                    .ok_or_else(|| {
                                        DsmError::invalid_operation(
                                            "counter_signed_receipt verify: contact missing \
                                             for AK_pk root",
                                        )
                                    })?
                                    .public_key
                                    .clone()
                            }
                        };

                        crate::sdk::receipts::verify_per_step_ek_signing_strict_aware(
                            &counter_signed,
                            crate::sdk::receipts::BilateralSide::B,
                            &expected_prev_pk,
                            &counter_signed.parent_tip,
                            &commitment_hash,
                        )?;

                        let snapshot_for_persist: BilateralBleSession;
                        {
                            let mut sessions = self.sessions.sessions.lock().await;
                            if let Some(s) = sessions.get_mut(&commitment_hash) {
                                s.stitched_receipt_bytes =
                                    Some(response.counter_signed_receipt.clone());
                                snapshot_for_persist = s.clone();
                            } else {
                                info!(
                                    "[BILATERAL] §11.1 per-step EK B-side verification PASS for commitment {} (session vanished before persist)",
                                    bytes_to_base32(&commitment_hash[..8])
                                );
                                return Ok(());
                            }
                        }
                        if let Err(e) = self.persist_session(&snapshot_for_persist, None).await {
                            warn!(
                                "[BILATERAL] §11.1 (B-tight) failed to persist counter-signed receipt before canonical commit: {}",
                                e
                            );
                        }
                        info!(
                            "[BILATERAL] §11.1 per-step EK B-side verification PASS for commitment {}",
                            bytes_to_base32(&commitment_hash[..8])
                        );
                    }
                    Err(e) => {
                        return Err(DsmError::invalid_operation(format!(
                            "sender per-step EK verify: failed to decode \
                             counter_signed_receipt: {e}"
                        )));
                    }
                }
            } else {
                return Err(DsmError::invalid_operation(format!(
                    "commit ack for {}: the session ended before the ack was verified; nothing \
                     is finalized",
                    bytes_to_base32(&commitment_hash[..8])
                )));
            }
        }

        let meta = self
            .mark_sender_committed_with_post_state_hash(&commitment_hash, Some(post_state_hash))
            .await
            .ok_or_else(|| {
                DsmError::invalid_operation("sender finalize failed after receiver acknowledgment")
            })?;

        // Clear the persisted confirm envelope now that the sender has finalized
        // successfully. Without this, the record would remain indefinitely and
        // the confirm would be re-delivered on every reconnect.
        self.clear_pending_confirm_delivery(&commitment_hash);

        // §11.1 Counterparty chain-head advance sits INSIDE
        // `mark_sender_committed_with_post_state_hash`, adjacent to the
        // canonical commit and the session deletion.

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
        let envelope = crate::envelope::from_canonical_bytes(envelope_bytes).map_err(|e| {
            DsmError::serialization_error(
                "decode_confirm_envelope",
                "protobuf",
                Some(e.to_string()),
                None::<std::io::Error>,
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

        // The stitched receipt is the step's one statement of the sender's
        // state (§4.2–4.3): its relationship path authenticates h_n under the
        // sender's pre-root r_A, and the same siblings folded with h_{n+1} are
        // r'_A; its device proof puts the sender under the Device Tree
        // commitment this receiver kept for the contact — never one the
        // confirm supplies.
        if confirm_request.stitched_receipt.is_empty() {
            return Err(DsmError::invalid_operation(
                "incoming bilateral confirm omits stitched_receipt; rejecting",
            ));
        }
        let receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
            &confirm_request.stitched_receipt,
        )
        .map_err(|e| {
            DsmError::invalid_operation(format!(
                "bilateral confirm: the stitched receipt does not decode: {e}"
            ))
        })?;
        if receipt.devid_a != session.counterparty_device_id || receipt.devid_b != self.device_id {
            return Err(DsmError::invalid_operation(
                "bilateral confirm: the receipt is not from this session's sender to this device",
            ));
        }
        let sender_device_tree = crate::storage::client_db::get_contact_device_tree_root(
            &session.counterparty_device_id,
        )?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "bilateral confirm: no Device Tree commitment is kept for the sender",
            )
        })?;
        dsm::verification::receipt_verification::verify_receipt_state(
            &receipt,
            &dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(
                sender_device_tree,
            ),
        )?;

        // §11.1 per-step EK signing verification: the receiver checks the
        // sender's A-side artifacts on the stitched receipt before applying
        // the advance. `expected_prev_pk` is the sender's prior cert-chain
        // head if recorded (steady state), else AK_pk from the contact record
        // (relationship genesis root); ek_cert_a must chain ek_pk_a back to it
        // over h_n (= receipt.parent_tip), and sig_a must verify under ek_pk_a
        // over the receipt's commitment.
        //
        // Captured for the post-commit Counterparty chain-head advance: the
        // sender's outbound chain has moved to this EK_pk and is mirrored
        // locally so the next step's `expected_prev_pk` resolves to the fresh
        // head, not the relationship-genesis AK_pk.
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &session.counterparty_device_id,
        );
        // From the receiver's viewpoint, the SENDER is the counterparty in the
        // cert-chain-heads table.
        let prev_pk_from_chain = crate::storage::client_db::load_cert_chain_head_pubkey(
            &rel_key,
            crate::storage::client_db::CertChainSide::Counterparty,
        )
        .map_err(|e| {
            DsmError::storage(
                format!("bilateral confirm: the sender's cert-chain head is unreadable: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let had_cp_head = prev_pk_from_chain.is_some();
        let expected_prev_pk = prev_pk_from_chain.unwrap_or_else(|| counterparty_pubkey.clone());
        debug!(
            "[BILATERAL] §11.1 A-side verify: counterparty_head_row={} expected_prev_pk={} parent_tip={}",
            had_cp_head,
            bytes_to_base32(&expected_prev_pk[..8.min(expected_prev_pk.len())]),
            bytes_to_base32(&receipt.parent_tip[..8]),
        );
        crate::sdk::receipts::verify_per_step_ek_signing_strict_aware(
            &receipt,
            crate::sdk::receipts::BilateralSide::A,
            &expected_prev_pk,
            &receipt.parent_tip,
            // §11.1 Item 7: receipt's sig_a must verify under the
            // challenge-response target for this bilateral session's
            // commitment_hash.
            &commitment_hash,
        )?;
        info!(
            "[BILATERAL] §11.1 per-step EK A-side verification PASS for commitment {}",
            bytes_to_base32(&commitment_hash[..8])
        );
        let verified_a_side_ek_pk: Vec<u8> = receipt.ek_pk_a.clone();

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
        if confirm_request.pre_entropy.len() != 32 {
            return Err(DsmError::invalid_operation(
                "pre_entropy must be present and 32 bytes in confirm",
            ));
        }
        let pre_entropy: [u8; 32] = confirm_request
            .pre_entropy
            .clone()
            .try_into()
            .map_err(|_| DsmError::invalid_operation("pre_entropy must be 32 bytes"))?;

        let h_n = {
            let manager = self.bilateral_tx_manager.read().await;
            let anchor = manager
                .get_relationship(&session.counterparty_device_id)
                .ok_or_else(|| {
                    DsmError::relationship("remote device relationship not found".to_string())
                })?;
            anchor.chain_tip
        };
        let op_bytes = session.operation.to_bytes();
        let expected_sigma = compute_precommit(&h_n, &op_bytes, &pre_entropy);
        let expected_h_next = compute_successor_tip(&h_n, &op_bytes, &pre_entropy, &expected_sigma);
        if expected_h_next != new_chain_tip {
            return Err(DsmError::invalid_operation(
                "h_{n+1} mismatch: pre_entropy cannot reproduce shared_chain_tip_new (§4.1)",
            ));
        }

        // Offline-bearer acceptance (OFFLINE_BEARER_REQUIRED transfers only). Canonical predicate:
        // the v2 Software-Authority / Hardware-Identity `accept_offline` via `anchor_accept` —
        // three signatures (σ^DSM gated by the handler's rel-proof/§C1 checks above, σ^chip + σ^host
        // verified in the predicate) + the anchor-state inclusion proofs Π_i/Π_{i+1} riding IN the
        // release + the forward-only frontier pin. No counter read is on this path. Fail-closed to
        // ONLINE RECOVERY: an absent/malformed release, an un-enrolled anchor, or ANY failed
        // predicate check rejects HERE, before the value-release commit below — so no value is
        // released. Ordinary transfers are unaffected (the predicate is false for them).
        let mut adopted_anchor_state: Option<crate::bluetooth::anchor_accept::AdoptedAnchorState> =
            None;
        if dsm::core::bilateral_transaction_manager::operation_requires_offline_bearer(
            &session.operation,
        ) {
            // `expected_receiver_challenge` is the r_R this receiver generated in
            // its prepare-response and stashed against the session — the release must bind it, so a
            // release minted for a different receiver session is rejected (defense-in-depth).
            let policy_hash = match &session.operation {
                Operation::Transfer {
                    authority_policy: Some(ap),
                    ..
                } => ap.policy_id,
                _ => return Err(DsmError::invalid_operation(
                    "offline-bearer confirm: the session's operation carries no authority policy",
                )),
            };
            // Policy-binding (receiver verify): the policy_id this receiver enforces against the
            // release MUST equal the canonical value the sender bound. A mismatch means the proof
            // does not attest what we think — reject rather than "run and mean nothing".
            let canonical_policy_id =
                dsm::types::operations::canonical_offline_bearer_policy().policy_id;
            if policy_hash != canonical_policy_id {
                return Err(DsmError::invalid_operation(format!(
                    "offline-bearer policy_id {} is not the canonical well-known value {}; refusing to accept",
                    bytes_to_base32(&policy_hash),
                    bytes_to_base32(&canonical_policy_id),
                )));
            }
            let expected_receiver_challenge = session.receiver_challenge.ok_or_else(|| {
                DsmError::invalid_operation(
                    "offline-bearer confirm: this session holds no receiver challenge r_R — the \
                     prepare response that issues it was never recorded",
                )
            })?;
            // The sender's device roots as the receipt states them, verified above against the
            // one relationship path (r_A authenticates h_n; the same siblings folded with h_{n+1}
            // are r'_A). The predicate ties the release cert's roots to exactly these, so a cert
            // signed over a parallel tree is rejected.
            let sender_smt_root: [u8; 32] = receipt.child_root;
            let sender_smt_root_before: [u8; 32] = receipt.parent_root;
            // Receiver-admit fold: on the FIRST bearer transfer from this ALREADY-VERIFIED contact,
            // admit (pin) the sender's disclosed fused anchor — bound to THIS confirm's disclosure +
            // release + commitment, never standalone and never from a release alone. Existing-pin
            // rules (`pin_admit_decision`): a matching disclosure is a no-op; a DIFFERING anchor is
            // rejected and the pinned one kept (silent substitution never succeeds via a transfer).
            // Admission is a memory of what to verify — acceptance is the predicate below.
            let sender_device_id = session.counterparty_device_id;
            if let Some(d) = confirm_request.anchor_disclosure.as_ref() {
                self.admit_anchor_disclosure(sender_device_id, commitment_hash, d)
                    .await;
            }
            let pin = crate::bridge::anchor_enrollment_store()
                .and_then(|s| s.get(&sender_device_id))
                .map(|e| e.pin);
            let pinned = pin
                .as_ref()
                .map(crate::bluetooth::anchor_accept::PinnedAnchor::from_fused);
            // The frontier adopted from this holder's last ACCEPTED release. Absent row =
            // relationship genesis — the predicate adopts the release's own `prev_root` TOFU
            // (authenticated by the anchor-state proofs + the three signatures, the same trust
            // root as the pin admit).
            let accepted_root =
                crate::storage::client_db::anchor_enrollments::load_accepted_anchor_root(
                    &sender_device_id,
                )
                .map_err(|e| {
                    DsmError::storage(
                        format!(
                            "offline-bearer confirm: the accepted anchor frontier is unreadable: {e}"
                        ),
                        None::<std::io::Error>,
                    )
                })?;
            let adopted = crate::bluetooth::anchor_accept::accept_offline_release(
                &confirm_request.offline_release,
                pinned.as_ref(),
                accepted_root.as_ref().map(|(r, _)| r),
                &self.device_id,
                &expected_receiver_challenge,
                &policy_hash,
                &sender_smt_root_before,
                &sender_smt_root,
            )
            .map_err(|r| r.into_dsm_error())?;
            // Persisted AFTER the canonical commit below succeeds (deferred, like
            // the §11.1 cert-chain mirrors) — a commit failure must not move the
            // accepted lineage frontier.
            adopted_anchor_state = Some(adopted);
            info!(
                "[BILATERAL] offline-bearer release accepted (v2 predicate: σ^DSM+σ^chip+σ^host) for commitment {}",
                bytes_to_base32(&commitment_hash[..8])
            );
        }

        // Every Transfer on this transport is bearer — `handle_prepare_request`
        // refuses the online-tier shape before a session exists. Re-assert at
        // the commit seam (defense in depth: a session is the only input here,
        // and no session may smuggle the deleted capability back in).
        if matches!(session.operation, Operation::Transfer { .. })
            && !dsm::core::bilateral_transaction_manager::operation_requires_offline_bearer(
                &session.operation,
            )
        {
            return Err(DsmError::invalid_operation(
                "bilateral confirm refused: BLE/USB carries offline-bearer transfers only — an \
                 online-tier transfer uses the network transport",
            ));
        }

        // Derive receiver-side credit deltas from the session operation: the
        // bearer value received, installed in the receiver's local balance
        // representation (the sender side moved allocation, never online
        // balance).
        let receiver_deltas: Vec<dsm::types::device_state::BalanceDelta> = match &session.operation
        {
            Operation::Transfer {
                amount, token_id, ..
            } => {
                // §9.5: independently resolve the receiver's installed
                // policy_commit. Never absorb the peer's commit.
                let policy_commit = crate::bridge::app_router()
                    .ok_or_else(|| {
                        DsmError::state_machine(
                            "receiver confirm: app_router not installed; cannot resolve the \
                             credited asset",
                        )
                    })?
                    .resolve_policy_commit_strict(token_id)
                    .map_err(|e| {
                        DsmError::invalid_operation(format!(
                            "receiver confirm: policy_commit unresolved for token {}: {e}",
                            String::from_utf8_lossy(token_id)
                        ))
                    })?;
                vec![dsm::types::device_state::BalanceDelta {
                    policy_commit,
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: amount.value(),
                }]
            }
            _ => Vec::new(),
        };

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
                None, // the fused-anchor leaf is a sender-side concern
                None, // offline_spend: never — the receiver credits received bearer value, it does not spend an allocation
            )
            .map_err(|e| {
                DsmError::state_machine(format!("receiver confirm advance failed: {e}"))
            })?;

        // Offline-bearer post-commit: ADOPT the holder's successor appliance
        // root (Def. 25 "receiver adopts next_root on acceptance"). Deferred
        // to here so a canonical-commit failure never moves the accepted
        // lineage frontier past a release that delivered no value.
        if let Some(adopted) = adopted_anchor_state {
            match crate::storage::client_db::anchor_enrollments::store_accepted_anchor_root(
                &session.counterparty_device_id,
                &adopted.next_root,
                adopted.next_anchor_counter,
            ) {
                Ok(()) => info!(
                    "[BILATERAL] adopted holder appliance root (next_anchor_counter={}) for commitment {}",
                    adopted.next_anchor_counter,
                    bytes_to_base32(&commitment_hash[..8])
                ),
                Err(e) => error!(
                    "[BILATERAL] failed to persist adopted appliance root: {} — the next transfer from this holder will fail check 2 until reconciled",
                    e
                ),
            }
        }

        // §11.1 post-commit: advance the local mirror of the SENDER's
        // cert chain head (Counterparty side from receiver's POV). Done
        // *after* canonical commit succeeds — if the advance call above
        // had failed, we would have bailed before getting here, so the
        // chain head is never advanced past a transition that wasn't
        // committed canonically. The advance MUST happen for multi-step
        // bilateral correctness: at step n+1 the verifier looks up
        // `expected_prev_pk` from this row, so a stale AK_pk would
        // reject all post-step-0 transitions.
        {
            let ek_pk_a = &verified_a_side_ek_pk;
            match crate::storage::client_db::advance_cert_chain_head(
                &rel_key,
                crate::storage::client_db::CertChainSide::Counterparty,
                ek_pk_a,
            ) {
                Ok(Some(step)) => {
                    info!(
                        "[BILATERAL] §11.1 advanced Counterparty cert chain head to sender EK_pk_{step} for commitment {}",
                        bytes_to_base32(&commitment_hash[..8])
                    );
                }
                Ok(None) => {
                    // First committed transfer on this relationship — no
                    // Counterparty row exists yet. Verification chained the
                    // sender's cert to their AK_pk root above; record the
                    // sender's EK_pk_1 as the step-0 Counterparty head so the
                    // NEXT step's `expected_prev_pk` resolves to the fresh EK
                    // head instead of falling back to the AK and rejecting.
                    match crate::storage::client_db::init_cert_chain_head(
                        &rel_key,
                        crate::storage::client_db::CertChainSide::Counterparty,
                        ek_pk_a,
                    ) {
                        Ok(true) => {
                            info!(
                                "[BILATERAL] §11.1 initialized Counterparty cert chain head at sender EK_pk_1 for commitment {}",
                                bytes_to_base32(&commitment_hash[..8])
                            );
                        }
                        Ok(false) => {
                            warn!(
                                "[BILATERAL] §11.1 Counterparty cert chain head appeared concurrently — leaving existing row"
                            );
                        }
                        Err(e) => {
                            error!(
                                "[BILATERAL] §11.1 failed to initialize Counterparty cert chain head: {} — multi-step verification will degrade until reconciled",
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    // Advancement is bookkeeping; canonical commit
                    // already succeeded. Log as an error but do not
                    // unwind the canonical state.
                    error!(
                        "[BILATERAL] §11.1 failed to advance Counterparty cert chain head: {} — multi-step verification may degrade until reconciled",
                        e
                    );
                }
            }
        }

        // Advance BTM anchor + persisted contact tip to new_chain_tip (§16.6 symmetric).
        {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager.advance_chain_tip(&session.counterparty_device_id, new_chain_tip);
        }

        // h_{n+1} asymmetric (A-side; here "A" is the receiver) — what T_receiver now stores.
        let h_next_asymmetric = outcome.new_chain_state.compute_chain_tip();
        // h_n asymmetric (A-side) — the T_receiver leaf the step started from.
        let parent_tip_asymmetric = outcome.smt_proofs.parent_proof.value.ok_or_else(|| {
            DsmError::invalid_operation(
                "receiver confirm: the advance's relationship path carries no parent tip",
            )
        })?;
        // Transaction hash for display / events = symmetric successor tip (new_chain_tip).
        let transaction_hash = new_chain_tip;

        // Build receipt with real proofs from the canonical AdvanceOutcome (§4.2).
        let unsigned_receipt_bytes = crate::sdk::receipts::build_bilateral_receipt_with_smt(
            self.device_id,
            session.counterparty_device_id,
            parent_tip_asymmetric,
            h_next_asymmetric,
            outcome.smt_proofs.pre_root,
            outcome.child_r_a,
            &outcome.smt_proofs.parent_proof,
            &local_device_tree_commitment()?,
            outcome.transition_entropy(),
        )?;

        // §11.1 receiver counter-sign: stamp B-side per-step EK + cert + sig +
        // Kyber ciphertext on the local copy of the receipt before persisting.
        // This is the receiver's binding to this step's transition.
        let receipt_bytes = self
            .sign_receipt_with_per_step_ek_for_bilateral(
                unsigned_receipt_bytes,
                &session.counterparty_device_id,
                parent_tip_asymmetric,
                commitment_hash, // bilateral commitment IS the precommit for this step
                BilateralSide::B,
            )
            .await?;

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

        // 3.5b PR4 (correction 3): record BOTH signers' EK step objects for
        // this completed step — rows appended + exact bytes frozen as
        // publication debt, fully offline; the sweep publishes on
        // reconnection. Post-commit bookkeeping (the §11.1 precedent): a
        // failure is logged, and prevalidation's per-address durability
        // check fail-closes any later online bundle that would depend on a
        // missing step.
        match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(&receipt_bytes)
        {
            Ok(full) => {
                if let Err(e) =
                    crate::sdk::economic_admission_flow::record_ble_ek_steps_from_receipt(
                        &rel_key,
                        &session.counterparty_device_id,
                        &self.device_id,
                        &full,
                    )
                {
                    error!(
                        "[BILATERAL] 3.5b EK step recording failed: {e} — later online \
                         acceptance on this relationship will hold until reconciled"
                    );
                }
            }
            Err(e) => error!(
                "[BILATERAL] 3.5b EK step recording: the counter-signed receipt does not \
                 decode: {e} — later online acceptance on this relationship will hold until \
                 reconciled"
            ),
        }

        // Keep a clone of the counter-signed receipt bytes for the response
        // envelope below. The settlement context consumes its own copy.
        let counter_signed_receipt = receipt_bytes.clone();

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
                    proof_data: Some(receipt_bytes),
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
            mgr.consume_pre_commitment(&pending_key);
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

        // A BLE commit is NOT a release authority for the online gate (finality
        // barrier): only an orphaned gate — one with no unsettled or
        // checkpoint-pending online send behind it — is cleared here.
        match crate::storage::client_db::clear_stale_pending_online_gate(
            &session.counterparty_device_id,
        ) {
            Ok(outcome) => info!(
                "[BILATERAL] online gate check after BLE commit (receiver) for {}: {outcome:?}",
                bytes_to_base32(&session.counterparty_device_id[..8]),
            ),
            Err(e) => warn!(
                "[BILATERAL] online gate check after BLE commit (receiver) for {} failed: {e}",
                bytes_to_base32(&session.counterparty_device_id[..8]),
            ),
        }

        // Emit transfer_complete event to frontend (receiver side).
        // amount / token_id already resolved via delegate.operation_metadata() above.
        self.emit_event(&generated::BilateralEventNotification {
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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
            .create_envelope(generated::envelope::Payload::BilateralCommitResponse(
                generated::BilateralCommitResponse {
                    post_state_hash: Some(generated::Hash32 {
                        v: receiver_post_state_hash.to_vec(),
                    }),
                    commitment_hash: Some(generated::Hash32 {
                        v: commitment_hash.to_vec(),
                    }),
                    // §11.1: ship the receiver's locally-built copy of the
                    // stitched receipt with B-side per-step EK signing
                    // artifacts so the sender can symmetrically verify
                    // the counter-signature and persist a fully co-signed
                    // archive.
                    counter_signed_receipt,
                },
            ))
            .await;

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
        for sess in sessions.values_mut() {
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
            session_anchor_leaf,
            session_anchor_sim_root,
            session_offline_spend,
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
            // The receiver's counter-signed receipt is this step's proof: the
            // commit response replaced the confirm-time copy with it after
            // B-side verification, and the session row persists it. A session
            // without one cannot archive the step, so nothing commits — no
            // receipt is rebuilt unsigned in its place, and re-signing would
            // mint an EK the receiver never verified.
            let receipt = match &sess.stitched_receipt_bytes {
                Some(r) => r.clone(),
                None => {
                    error!("[BILATERAL] commit refused: the session holds no signed receipt");
                    return None;
                }
            };

            (
                sess.counterparty_device_id,
                sig,
                sess.operation.clone(),
                sess.pre_finalize_entropy,
                receipt,
                sess.anchor_leaf.clone(),
                sess.anchor_sim_root,
                sess.offline_spend,
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
            let stored = match stored_contact_tip(crate::storage::client_db::get_contact_chain_tip(
                &counterparty_device_id,
            )) {
                Ok(stored) => stored,
                Err(e) => {
                    error!("[BILATERAL] sender commit not finalized, nothing settled: {e}");
                    return None;
                }
            };
            if let Some(sqlite_tip) = stored {
                manager.advance_chain_tip(&counterparty_device_id, sqlite_tip);
                info!(
                    "[BILATERAL] Re-synced BTM chain tip from SQLite before sender prepare: {}",
                    bytes_to_base32(&sqlite_tip[..8])
                );
            }

            // Sender deltas are ALWAYS empty on this transport: a bearer
            // Transfer draws from the offline-cash allocation via the
            // allocation-spend descriptor the confirm-build stashed on the
            // session, and nothing else here moves value. A Transfer session
            // that reaches commit WITHOUT that descriptor is a broken
            // invariant (the confirm-build refuses to construct one), not a
            // cue to rebuild an online-balance debit — the deleted online-tier
            // arm is not gated, it is gone (owner ruling 2026-08-28).
            if matches!(session_operation, Operation::Transfer { .. })
                && session_offline_spend.is_none()
            {
                error!(
                    "[BILATERAL] commit refused: a Transfer session carries no allocation-spend \
                     descriptor — bearer value never draws from the online balance"
                );
                return None;
            }

            match manager
                .prepare_bilateral_advance(
                    &counterparty_device_id,
                    commitment_hash,
                    &counterparty_sig,
                    Vec::new(),
                    session_anchor_leaf.clone(), // bearer: the SAME successor leaf the confirm proofs used
                    session_offline_spend, // bearer→allocation: the SAME allocation debit the confirm-build sim used
                )
                .await
            {
                Ok(p) => p,
                Err(prepare_err) => {
                    drop(manager);
                    return self
                        .fail_sender_commit(
                            commitment_hash,
                            &counterparty_device_id,
                            &format!("prepare_bilateral_advance refused: {prepare_err}"),
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
                    // Rendered in emit_event, the one boundary all emitters cross.
                    display_amount: None,
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

        // Both-or-neither guard. Re-simulate the advance the canonical commit is about to perform
        // — same rel_key/operation/deltas/parent_tip and the SAME driven `anchor_leaf` — and
        // require (every transfer) its transition entropy to equal the value the confirm carried,
        // and (bearer transfers) its post-root to equal the sim root already sent to the receiver.
        // `simulate_advance_for_confirm` is prepare-only (it does NOT re-drive the appliance), so
        // this re-applies the stashed successor leaf without advancing the fused anchor. A
        // divergence (device head / relationship tip drifted between confirm and commit) means the
        // receiver verified against values we would NOT commit; abort BEFORE the canonical
        // mutation and fail closed to online recovery. Structurally this should never fire — it
        // guards against regressions that break the determinism the invariant rests on.
        // The confirm the receiver accepted carried `pre_entropy` — Core's
        // derivation from the confirm-time simulation — and the receiver
        // recomputed h_{n+1} from it. The canonical commit below derives its
        // own value from its own inputs. Before committing, re-simulate and
        // refuse unless the two are byte-identical (§39.3: ONE value in the tip
        // and in both receipt hashes). A session with no stashed entropy never
        // built a confirm and cannot commit.
        let Some(pre_entropy) = pre_entropy else {
            return self
                .fail_sender_commit(
                    commitment_hash,
                    &counterparty_device_id,
                    "the session carries no confirm-time transition entropy",
                    event_amount_opt,
                    event_token_id_opt,
                )
                .await;
        };
        {
            let resim = match router.simulate_advance_for_confirm(
                prepared.rel_key,
                prepared.counterparty_devid,
                prepared.operation.clone(),
                &prepared.deltas,
                prepared.anchor_leaf.clone(),
                // Must match the commit at execute_on_relationship_for_bilateral below EXACTLY
                // (same inputs → same root): the SAME allocation debit `prepared` carries. `OfflineSpend`
                // is Copy, so this and the commit read the identical value.
                prepared.offline_spend,
            ) {
                Ok(o) => o,
                Err(e) => {
                    return self
                        .fail_sender_commit(
                            commitment_hash,
                            &counterparty_device_id,
                            &format!("commit-time re-simulation failed: {e}"),
                            event_amount_opt,
                            event_token_id_opt,
                        )
                        .await;
                }
            };
            if resim.transition_entropy() != pre_entropy {
                return self
                    .fail_sender_commit(
                        commitment_hash,
                        &counterparty_device_id,
                        &format!(
                            "one-entropy violation: the commit-time derivation {} is not the \
                             confirm-time value {} the receiver accepted",
                            bytes_to_base32(&resim.transition_entropy()[..8]),
                            bytes_to_base32(&pre_entropy[..8]),
                        ),
                        event_amount_opt,
                        event_token_id_opt,
                    )
                    .await;
            }
            if let Some(sent_sim_root) = session_anchor_sim_root {
                let projected_root = resim.child_r_a;
                if projected_root != sent_sim_root {
                    return self
                        .fail_sender_commit(
                            commitment_hash,
                            &counterparty_device_id,
                            &format!(
                                "both-or-neither violation: the commit-time sim root {} is not \
                                 the sim root {} sent to the receiver",
                                bytes_to_base32(&projected_root[..8]),
                                bytes_to_base32(&sent_sim_root[..8]),
                            ),
                            event_amount_opt,
                            event_token_id_opt,
                        )
                        .await;
                }
            }
        }
        let outcome = match router.execute_on_relationship_for_bilateral(
            prepared.rel_key,
            prepared.counterparty_devid,
            prepared.operation.clone(),
            &prepared.deltas,
            prepared.anchor_leaf.clone(), // bearer: commit the same fused-anchor leaf as the sim proofs
            // Bearer→allocation: the SAME allocation debit the confirm-build sim and the determinism-guard sim
            // used (`prepared.offline_spend`, Copy) — `prepared.deltas` is empty for a bearer transfer,
            // so the value is drawn from the offline-cash allocation, not the online balance, and the
            // committed sender root byte-matches the sent sim root.
            prepared.offline_spend,
        ) {
            Ok(o) => o,
            Err(advance_err) => {
                error!(
                    "[BILATERAL] execute_on_relationship_for_bilateral failed: {}",
                    advance_err
                );
                self.emit_event(&generated::BilateralEventNotification {
                    // Rendered in emit_event, the one boundary all emitters cross.
                    display_amount: None,
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
        // + tripwire precommit + b0x addressing. Both parties compute it from
        // the ONE transition entropy: Core's derivation inside the committed
        // advance, which the re-simulation above proved equal to the value the
        // receiver accepted in the confirm.
        let transition_entropy = outcome.transition_entropy();
        let receipt_sigma = compute_precommit(&prepared.parent_tip, &op_bytes, &transition_entropy);
        let h_next_symmetric = compute_successor_tip(
            &prepared.parent_tip,
            &op_bytes,
            &transition_entropy,
            &receipt_sigma,
        );
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
                proof_data: Some(cached_receipt.clone()),
                is_sender: true,
                tx_type: "bilateral_offline",
                new_chain_tip: h_next_symmetric,
            };
            if let Err(e) = delegate.settle(ctx) {
                log::error!(
                    "[BILATERAL] Sender settlement FAILED after advance commit: {e}. Canonical head is advanced; projection + history may lag."
                );
                self.emit_event(&generated::BilateralEventNotification {
                    // Rendered in emit_event, the one boundary all emitters cross.
                    display_amount: None,
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

        // §11.1 — promote the PENDING Local chain-head advance stashed at
        // confirm-build time. The receiver's commit-response proves it
        // verified our A-side cert and advanced its Counterparty mirror,
        // so our Local head may now move to the EK that signed this step.
        // Doing this only here (never at build) means a rejected or lost
        // confirm leaves the Local head untouched and the relationship
        // convergent.
        {
            let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                &self.device_id,
                &counterparty_device_id,
            );
            match crate::storage::client_db::promote_pending_local_head(&rel_key, commitment_hash) {
                Ok(Some(step)) => {
                    info!(
                        "[BILATERAL] §11.1 promoted pending Local chain head to EK_pk_{step} for commitment {}",
                        bytes_to_base32(&commitment_hash[..8])
                    );
                }
                Ok(None) => {
                    warn!(
                        "[BILATERAL] §11.1 no pending Local chain head to promote for commitment {} — head not advanced (already promoted, or stash lost); next step may need reconciliation",
                        bytes_to_base32(&commitment_hash[..8])
                    );
                }
                Err(e) => {
                    error!(
                        "[BILATERAL] §11.1 failed to promote pending Local chain head: {} — next outbound step will sign from the stale head",
                        e
                    );
                }
            }
        }

        // §11.1 Item 8 (B-tight) — advance the local mirror of the
        // RECEIVER's cert chain head (Counterparty side from sender's
        // POV) immediately before deleting the session row. Sourcing
        // `ek_pk_b` from the in-session cached receipt (which
        // `handle_commit_response` already replaced with the
        // counter-signed bytes after B-side per-step EK verification)
        // keeps the advance tightly adjacent to canonical commit:
        // canonical commit → settlement → phase=Committed → advance
        // → delete. A crash inside this narrow window leaves the
        // session row visible in SQLite for the startup reconciliation
        // sweep to repair the chain head from `stitched_receipt_bytes`.
        {
            match dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                &cached_receipt,
            ) {
                Ok(receipt) if !receipt.ek_pk_b.is_empty() => {
                    let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                        &self.device_id,
                        &counterparty_device_id,
                    );
                    // 3.5b PR4 (correction 3): both signers' EK step objects
                    // for this completed step — byte-identical to the
                    // receiver's derivation, frozen as publication debt.
                    if let Err(e) =
                        crate::sdk::economic_admission_flow::record_ble_ek_steps_from_receipt(
                            &rel_key,
                            &counterparty_device_id,
                            &self.device_id,
                            &receipt,
                        )
                    {
                        error!(
                            "[BILATERAL] 3.5b EK step recording failed: {e} — later online \
                             acceptance on this relationship will hold until reconciled"
                        );
                    }
                    match crate::storage::client_db::advance_cert_chain_head(
                        &rel_key,
                        crate::storage::client_db::CertChainSide::Counterparty,
                        &receipt.ek_pk_b,
                    ) {
                        Ok(Some(step)) => {
                            info!(
                                "[BILATERAL] §11.1 (B-tight) advanced Counterparty cert chain head to receiver EK_pk_{step} for commitment {}",
                                bytes_to_base32(&commitment_hash[..8])
                            );
                        }
                        Ok(None) => {
                            // First committed transfer — no Counterparty row
                            // yet. Record the receiver's EK_pk_1 as the step-0
                            // head so the next step verifies against it
                            // instead of falling back to the AK and rejecting.
                            match crate::storage::client_db::init_cert_chain_head(
                                &rel_key,
                                crate::storage::client_db::CertChainSide::Counterparty,
                                &receipt.ek_pk_b,
                            ) {
                                Ok(true) => {
                                    info!(
                                        "[BILATERAL] §11.1 (B-tight) initialized Counterparty cert chain head at receiver EK_pk_1 for commitment {}",
                                        bytes_to_base32(&commitment_hash[..8])
                                    );
                                }
                                Ok(false) => {
                                    warn!(
                                        "[BILATERAL] §11.1 (B-tight) Counterparty cert chain head appeared concurrently — leaving existing row"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        "[BILATERAL] §11.1 (B-tight) failed to initialize Counterparty cert chain head: {} — startup reconciliation sweep will retry from session row",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "[BILATERAL] §11.1 (B-tight) failed to advance Counterparty cert chain head: {} — startup reconciliation sweep will retry from session row",
                                e
                            );
                        }
                    }
                }
                Ok(_) => {
                    error!(
                        "[BILATERAL] §11.1 (B-tight) the committed receipt carries no B-side EK — \
                         the Counterparty cert chain head is not advanced; startup reconciliation \
                         sweep will retry"
                    );
                }
                Err(e) => {
                    error!(
                        "[BILATERAL] §11.1 (B-tight) cached counter-signed receipt failed to decode for advance: {} — startup reconciliation sweep will retry",
                        e
                    );
                }
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

        // A BLE commit is NOT a release authority for the online gate (finality
        // barrier): only an orphaned gate — one with no unsettled or
        // checkpoint-pending online send behind it — is cleared here.
        match crate::storage::client_db::clear_stale_pending_online_gate(&counterparty_device_id) {
            Ok(outcome) => info!(
                "[BILATERAL] online gate check after BLE commit (sender) for {}: {outcome:?}",
                bytes_to_base32(&counterparty_device_id[..8]),
            ),
            Err(e) => warn!(
                "[BILATERAL] online gate check after BLE commit (sender) for {} failed: {e}",
                bytes_to_base32(&counterparty_device_id[..8]),
            ),
        }

        // Emit transfer_complete event to frontend (sender side).
        self.emit_event(&generated::BilateralEventNotification {
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
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

    /// A sender commit that did not pass its checks. Nothing advances,
    /// nothing settles and no tip is written: the session fails durably and
    /// the relationship is held for online reconciliation, because the
    /// receiver may already have committed its side.
    async fn fail_sender_commit(
        &self,
        commitment_hash: &[u8; 32],
        counterparty_device_id: &[u8; 32],
        reason: &str,
        event_amount_opt: Option<u64>,
        event_token_id_opt: Option<String>,
    ) -> Option<crate::sdk::transfer_hooks::TransferMeta> {
        error!("[BILATERAL] sender commit refused, nothing settled: {reason}");
        self.transition_session_to_failed(commitment_hash).await;
        if let Err(e) =
            crate::storage::client_db::mark_contact_needs_online_reconcile(counterparty_device_id)
        {
            error!(
                "[BILATERAL] the relationship with {} could not be held for reconcile: {e}",
                bytes_to_base32(&counterparty_device_id[..8])
            );
        }
        self.emit_event(&generated::BilateralEventNotification {
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
            event_type: generated::BilateralEventType::BilateralEventFailed.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: event_amount_opt,
            token_id: event_token_id_opt,
            status: "failed".to_string(),
            message: format!("Sender commit refused: {reason}"),
            sender_ble_address: None,
            failure_reason: Some(
                generated::BilateralFailureReason::FailureReasonProtocolViolation as i32,
            ),
        });
        None
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

    // Helper methods

    /// Wrap a payload in an Envelope v3 from this device, under its genesis.
    async fn create_envelope(&self, payload: generated::envelope::Payload) -> generated::Envelope {
        let genesis_hash = {
            let mgr = self.bilateral_tx_manager.read().await;
            mgr.local_genesis_hash()
        };
        super::bilateral_envelope::build_envelope(&self.device_id, &genesis_hash, payload)
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
    use dsm::types::operations::{TransactionMode};
    use dsm::types::token_types::Balance;
    use serial_test::serial;

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
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
        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);
        (bilateral_manager, handler)
    }

    /// The keys a peer sends in a prepare are refused unless they are the
    /// keys its contact pins (ADR 0002): the AK equal, the Kyber key equal and
    /// its binding verifying under the pinned AK. Every refusal says why, and
    /// nothing sent is ever written to the contact.
    #[test]
    #[serial]
    fn a_peer_is_held_to_the_keys_its_contact_pins() {
        use crate::sdk::kyber_identity::binding_digest;
        use crate::storage::client_db::{get_contact_by_device_id, store_contact, ContactRecord};
        use dsm::crypto::{kyber, sphincs};

        init_test_db();

        let device_id = [0x7Cu8; 32];
        let genesis = [0x3Du8; 32];
        let (pinned_ak, pinned_sk) = sphincs::generate_sphincs_keypair().expect("ak keypair");
        let kyber_pk = kyber::generate_kyber_keypair()
            .expect("kyber")
            .public_key
            .clone();

        let contact = ContactRecord {
            contact_id: "peer".into(),
            device_id: device_id.to_vec(),
            alias: "peer".into(),
            genesis_hash: genesis.to_vec(),
            public_key: pinned_ak.clone(),
            kyber_public_key: kyber_pk.clone(),
            current_chain_tip: Some(vec![0x71; 32]),
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "active".into(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        };
        store_contact(&contact).expect("store pinned contact");
        let valid_sig =
            sphincs::sphincs_sign(&pinned_sk, &binding_digest(&device_id, &genesis, &kyber_pk))
                .expect("sign binding");
        let check = |ak: &[u8], kyber_pk: &[u8], sig: &[u8]| {
            BilateralBleHandler::require_pinned_peer_keys(&device_id, ak, kyber_pk, sig, "test")
                .map_err(|e| e.to_string())
        };
        let refused = |r: Result<(), String>, why: &str| {
            let e = r.expect_err(why);
            assert!(e.contains(why), "refused for another reason: {e}");
        };

        check(&pinned_ak, &kyber_pk, &valid_sig).expect("the pinned keys and their binding");

        let (other_ak, other_sk) = sphincs::generate_sphincs_keypair().expect("other keypair");
        refused(
            check(&other_ak, &kyber_pk, &valid_sig),
            "not the contact's pinned AK",
        );
        refused(
            check(&[], &kyber_pk, &valid_sig),
            "not the contact's pinned AK",
        );
        let substituted = kyber::generate_kyber_keypair()
            .expect("kyber")
            .public_key
            .clone();
        refused(
            check(&pinned_ak, &substituted, &valid_sig),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(&pinned_ak, &[], &valid_sig),
            "not the contact's pinned Kyber key",
        );
        refused(
            check(&pinned_ak, &kyber_pk, &[]),
            "does not verify under the pinned AK",
        );
        let wrong_signer =
            sphincs::sphincs_sign(&other_sk, &binding_digest(&device_id, &genesis, &kyber_pk))
                .expect("sign");
        refused(
            check(&pinned_ak, &kyber_pk, &wrong_signer),
            "does not verify under the pinned AK",
        );
        let other_digest = sphincs::sphincs_sign(&pinned_sk, &[0x11u8; 32]).expect("sign");
        refused(
            check(&pinned_ak, &kyber_pk, &other_digest),
            "does not verify under the pinned AK",
        );
        refused(
            BilateralBleHandler::require_pinned_peer_keys(
                &[0xEE; 32],
                &pinned_ak,
                &kyber_pk,
                &valid_sig,
                "test",
            )
            .map_err(|e| e.to_string()),
            "not a contact",
        );

        let stored = get_contact_by_device_id(&device_id).unwrap().unwrap();
        assert_eq!(stored.public_key, pinned_ak, "nothing sent is written");
        assert_eq!(stored.kyber_public_key, kyber_pk, "nothing sent is written");
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

        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
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
    #[serial]
    async fn test_core_manager_integration() {
        // A device made as wallet creation makes one: its own identity, AK and
        // Kyber key, in a fresh database. It prepares nothing without them.
        let (identity, _core) = crate::economic_fixtures::local_device(0x11);
        let (device_id, genesis_hash) = (identity.device_id, identity.genesis);
        let keypair = identity.signing_keypair();

        let counterparty_device_id = [3u8; 32];
        let counterparty_genesis = [4u8; 32];

        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        )));

        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        // Add a test contact with all required fields
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "test_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![7u8; 32],
            chain_tip: Some([6u8; 32]),
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: Some(String::new()),
        };

        {
            let mut manager = bilateral_manager.write().await;
            crate::storage::client_db::store_contact_for_tests(&contact);
            manager
                .add_verified_contact(contact)
                .expect("add_verified_contact");
            manager
                .establish_relationship(&counterparty_device_id)
                .await
                .expect("establish relationship");
        }

        // prepare_bilateral_transaction records its precommitment in the core manager.
        handler
            .prepare_bilateral_transaction(counterparty_device_id, Operation::Noop)
            .await
            .expect("prepare on an established relationship");
        assert!(
            !bilateral_manager
                .read()
                .await
                .list_pending_commitments()
                .is_empty(),
            "the core manager holds the pending commitment"
        );

        // The prepared session is neither expired nor orphaned: maintenance keeps it.
        let (cleaned, reconciled) = handler.maintain_sessions().await.expect("maintain");
        assert_eq!(cleaned, 0);
        assert_eq!(reconciled, 0);
    }

    /// A device that cannot produce its Kyber identity binding (no wallet, so
    /// no AK secret or Kyber key) sends no prepare: the peer would refuse one
    /// without it, and nothing is staged for a message that cannot be sent.
    /// MUTATION CONTROL: falling back to an empty binding lets the prepare
    /// through and turns this red.
    #[tokio::test]
    #[serial]
    async fn a_device_without_its_kyber_binding_prepares_nothing() {
        init_test_db();
        crate::reset_sdk_context_for_testing();
        let counterparty = [0x92u8; 32];
        let (bilateral_manager, handler) =
            make_test_handler([0x91u8; 32], [0x93u8; 32], b"no-kyber-binding-sender");
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "peer".to_string(),
            device_id: counterparty,
            genesis_hash: [0x94u8; 32],
            public_key: vec![9u8; 32],
            chain_tip: Some([0x95u8; 32]),
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };
        crate::storage::client_db::store_contact_for_tests(&contact);
        bilateral_manager
            .write()
            .await
            .add_verified_contact(contact)
            .expect("add contact");

        handler
            .prepare_bilateral_transaction(counterparty, Operation::Noop)
            .await
            .expect_err("no prepare without the device's Kyber identity binding");
        assert!(
            handler.sessions.sessions.lock().await.is_empty(),
            "no session is staged for a prepare that was not sent"
        );
        assert!(
            bilateral_manager
                .read()
                .await
                .list_pending_commitments()
                .is_empty(),
            "no precommitment is held for a prepare that was not sent"
        );
    }

    /// Builds the online-tier Transfer shape (`authority_policy: None`) that
    /// the network transport carries and BLE/USB must refuse.
    fn online_tier_transfer(counterparty: [u8; 32]) -> Operation {
        Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: counterparty.to_vec(),
            amount: Balance::amount(1),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![9],
            recipient: counterparty.to_vec(),
            to: counterparty.to_vec(),
            message: "online".to_string(),
            signature: Vec::new(),
            authority_policy: None,
        }
    }

    /// Owner ruling (2026-08-28): BLE/USB is the OFFLINE transport — value
    /// over it is bearer-tier only, and the online tier uses the network.
    /// Sender door: `prepare_bilateral_transaction` refuses the online shape
    /// before any session state exists. MUTATION CONTROL: deleting the sender
    /// entry refusal lets this prepare proceed past the named error and turns
    /// this red.
    #[tokio::test]
    #[serial]
    async fn an_online_tier_transfer_cannot_enter_ble_at_the_sender_door() {
        init_test_db();
        let device_id = [0x51u8; 32];
        let counterparty = [0x52u8; 32];
        let (bilateral_manager, handler) =
            make_test_handler(device_id, [0x53u8; 32], b"online-tier-sender-door");
        {
            let mut mgr = bilateral_manager.write().await;
            let contact = dsm::types::contact_types::DsmVerifiedContact {
                alias: "peer".to_string(),
                device_id: counterparty,
                genesis_hash: [0x54u8; 32],
                public_key: vec![9u8; 32],
                chain_tip: Some([7u8; 32]),
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            };
            crate::storage::client_db::store_contact_for_tests(&contact);
            mgr.add_verified_contact(contact).expect("add contact");
            mgr.establish_relationship(&counterparty)
                .await
                .expect("establish relationship");
        }

        let msg = handler
            .prepare_bilateral_transaction(counterparty, online_tier_transfer(counterparty))
            .await
            .expect_err("the sender door must refuse the online tier")
            .to_string();
        assert!(
            msg.contains("offline-bearer transfers only"),
            "the refusal names the transport rule, got: {msg}"
        );
    }

    /// The receiver door: `handle_prepare_request` refuses the same shape
    /// before creating any session — a foreign sender does not get to open an
    /// online-tier transfer over BLE no matter what it puts on the wire.
    /// MUTATION CONTROL: deleting the receiver entry refusal moves the failure
    /// past the named error and turns this red.
    #[tokio::test]
    #[serial]
    async fn an_online_tier_transfer_cannot_enter_ble_at_the_receiver_door() {
        init_test_db();
        let device_id = [0x61u8; 32];
        let sender = [0x62u8; 32];
        let (_mgr, handler) =
            make_test_handler(device_id, [0x63u8; 32], b"online-tier-receiver-door");

        let req = generated::BilateralPrepareRequest {
            counterparty_device_id: device_id.to_vec(),
            operation_data: online_tier_transfer(device_id).to_bytes(),
            expected_genesis_hash: None,
            expected_counterparty_state_hash: None,
            ble_address: String::new(),
            sender_signing_public_key: vec![0; 64],
            sender_device_id: sender.to_vec(),
            sender_genesis_hash: None,
            transfer_amount: 0,
            token_id_hint: String::new(),
            memo_hint: String::new(),
            transfer_amount_display: String::new(),
            sender_kyber_public_key: vec![],
            sender_kyber_binding_sig: vec![],
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: Some(generated::Headers {
                device_id: sender.to_vec(),
                genesis_hash: vec![0x64u8; 32],
            }),
            message_id: vec![0x65u8; 16],
            payload: Some(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: None,
                        actor: sender.to_vec(),
                        kind: Some(generated::universal_op::Kind::Invoke(generated::Invoke {
                            program: None,
                            method: "bilateral.prepare".to_string(),
                            args: Some(generated::ArgPack {
                                schema_hash: None,
                                codec: 0,
                                body: prost::Message::encode_to_vec(&req),
                            }),
                            cosigners: vec![],
                            evidence: None,
                            nonce: None,
                        })),
                    }],
                    atomic: false,
                },
            )),
        };

        let msg = handler
            .handle_prepare_request(&crate::envelope::to_canonical_bytes(&envelope), None)
            .await
            .expect_err("the receiver door must refuse the online tier")
            .to_string();
        assert!(
            msg.contains("offline-bearer transfers only"),
            "the refusal names the transport rule, got: {msg}"
        );
    }

    /// The receiver checks a prepare's expected relationship tip against the
    /// tip it holds durably, never against its manager's cached view (which
    /// once took the sender's own claim). MUTATION CONTROL: reading the cached
    /// tip instead lets this prepare through to a precommitment and turns this
    /// red.
    #[tokio::test]
    #[serial]
    async fn a_prepare_is_checked_against_the_durable_relationship_tip() {
        init_test_db();
        let receiver = [0x81u8; 32];
        let sender = [0x82u8; 32];
        let sender_genesis = [0x84u8; 32];
        let durable_tip = [0x70u8; 32];
        let cached_tip = [0x5Au8; 32];
        let (manager, handler) =
            make_test_handler(receiver, [0x83u8; 32], b"prepare-durable-tip-receiver");
        let sender_keys = SignatureKeyPair::generate_from_entropy(b"prepare-durable-tip-sender")
            .expect("sender keys");
        let kyber_pk = vec![0x4Bu8; 1184];
        crate::storage::client_db::store_contact(&crate::storage::client_db::ContactRecord {
            contact_id: "sender".to_string(),
            device_id: sender.to_vec(),
            alias: "sender".to_string(),
            genesis_hash: sender_genesis.to_vec(),
            public_key: sender_keys.public_key().to_vec(),
            kyber_public_key: kyber_pk.clone(),
            current_chain_tip: Some(durable_tip.to_vec()),
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "verified".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        })
        .expect("persist the contact");
        {
            let mut mgr = manager.write().await;
            sync_contact_from_storage(&mut mgr, &sender).expect("load the contact");
            mgr.establish_relationship(&sender)
                .await
                .expect("establish");
            mgr.advance_chain_tip(&sender, cached_tip);
        }
        let binding_sig = sender_keys
            .sign(&crate::sdk::kyber_identity::binding_digest(
                &sender,
                &sender_genesis,
                &kyber_pk,
            ))
            .expect("binding signature");

        let req = generated::BilateralPrepareRequest {
            counterparty_device_id: receiver.to_vec(),
            operation_data: Operation::Noop.to_bytes(),
            expected_genesis_hash: None,
            expected_counterparty_state_hash: Some(generated::Hash32 {
                v: cached_tip.to_vec(),
            }),
            ble_address: String::new(),
            sender_signing_public_key: sender_keys.public_key().to_vec(),
            sender_device_id: sender.to_vec(),
            sender_genesis_hash: Some(generated::Hash32 {
                v: sender_genesis.to_vec(),
            }),
            transfer_amount: 0,
            token_id_hint: String::new(),
            memo_hint: String::new(),
            transfer_amount_display: String::new(),
            sender_kyber_public_key: kyber_pk,
            sender_kyber_binding_sig: binding_sig,
        };
        let envelope = generated::Envelope {
            version: 3,
            headers: Some(generated::Headers {
                device_id: sender.to_vec(),
                genesis_hash: sender_genesis.to_vec(),
            }),
            message_id: vec![0x85u8; 16],
            payload: Some(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: Some(generated::Hash32 {
                            v: vec![0x86u8; 32],
                        }),
                        actor: sender.to_vec(),
                        kind: Some(generated::universal_op::Kind::Invoke(generated::Invoke {
                            program: None,
                            method: "bilateral.prepare".to_string(),
                            args: Some(generated::ArgPack {
                                schema_hash: None,
                                codec: 0,
                                body: prost::Message::encode_to_vec(&req),
                            }),
                            cosigners: vec![],
                            evidence: None,
                            nonce: None,
                        })),
                    }],
                    atomic: false,
                },
            )),
        };

        let (reply, _meta) = handler
            .handle_prepare_request(&crate::envelope::to_canonical_bytes(&envelope), None)
            .await
            .expect("the prepare is answered");
        let reply = crate::envelope::from_canonical_bytes(&reply).expect("decode the reply");
        match reply.payload {
            Some(generated::envelope::Payload::BilateralPrepareReject(reject)) => assert!(
                reject.reason.contains("Chain tip mismatch"),
                "the rejection names the tip mismatch, got: {}",
                reject.reason
            ),
            other => panic!("expected a prepare rejection, got {other:?}"),
        }
        assert!(
            manager.read().await.list_pending_commitments().is_empty(),
            "no precommitment is made on a stale expectation"
        );
    }

    /// A proposal is abandoned only for a rejection its counterparty signed
    /// under the key its contact pins: an unsigned one, one signed by another
    /// key, one from another device, or one for a proposal already answered
    /// changes nothing. MUTATION CONTROL: skipping the signature check lets the
    /// unsigned rejection end the proposal and turns this red.
    #[tokio::test]
    #[serial]
    async fn a_proposal_is_abandoned_only_for_a_rejection_its_counterparty_signed() {
        init_test_db();
        let proposer = [0xA1u8; 32];
        let counterparty = [0xA2u8; 32];
        let counterparty_keys =
            SignatureKeyPair::generate_from_entropy(b"signed-reject-counterparty").expect("keys");
        let (manager, handler) =
            make_test_handler(proposer, [0xA3u8; 32], b"signed-reject-proposer");
        manager
            .write()
            .await
            .add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
                alias: "counterparty".to_string(),
                device_id: counterparty,
                genesis_hash: [0xA4u8; 32],
                public_key: counterparty_keys.public_key().to_vec(),
                chain_tip: Some([0xA5u8; 32]),
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            })
            .expect("add the counterparty");
        let session = |commitment_hash: [u8; 32], phase: BilateralPhase| BilateralBleSession {
            commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id: counterparty,
            counterparty_genesis_hash: Some([0xA4u8; 32]),
            operation: Operation::Noop,
            phase,
            local_signature: Some(vec![1u8; 32]),
            counterparty_signature: None,
            sender_ble_address: None,
            created_at_wall: Instant::now(),
            pre_finalize_entropy: None,
            stitched_receipt_bytes: None,
            receiver_challenge: None,
            anchor_leaf: None,
            anchor_sim_root: None,
            offline_spend: None,
        };
        let pending = [0xA6u8; 32];
        let answered = [0xA7u8; 32];
        handler
            .test_insert_session(session(pending, BilateralPhase::Prepared))
            .await;
        handler
            .test_insert_session(session(answered, BilateralPhase::Accepted))
            .await;

        let rejection = |commitment_hash: [u8; 32], rejector: [u8; 32], signature: Vec<u8>| {
            let reject = generated::BilateralPrepareReject {
                commitment_hash: Some(generated::Hash32 {
                    v: commitment_hash.to_vec(),
                }),
                reason: "declined".to_string(),
                rejector_device_id: rejector.to_vec(),
                send_status: None,
                rejector_signature: signature,
            };
            crate::envelope::to_canonical_bytes(&generated::Envelope {
                version: 3,
                headers: Some(generated::Headers {
                    device_id: rejector.to_vec(),
                    genesis_hash: vec![0xA4u8; 32],
                }),
                message_id: vec![0xA8u8; 16],
                payload: Some(generated::envelope::Payload::BilateralPrepareReject(reject)),
            })
        };
        let signed_by = |keys: &SignatureKeyPair, commitment_hash: [u8; 32], rejector: [u8; 32]| {
            let mut msg = b"DSM/bilateral-reject\0".to_vec();
            msg.extend_from_slice(&commitment_hash);
            msg.extend_from_slice(&rejector);
            msg.extend_from_slice(b"declined");
            keys.sign(&msg).expect("sign")
        };
        let other_keys = SignatureKeyPair::generate_from_entropy(b"signed-reject-other").unwrap();

        for (what, envelope) in [
            ("unsigned", rejection(pending, counterparty, Vec::new())),
            (
                "signed by another key",
                rejection(
                    pending,
                    counterparty,
                    signed_by(&other_keys, pending, counterparty),
                ),
            ),
            (
                "from another device",
                rejection(
                    pending,
                    [0xA9u8; 32],
                    signed_by(&counterparty_keys, pending, [0xA9u8; 32]),
                ),
            ),
            (
                "for an answered proposal",
                rejection(
                    answered,
                    counterparty,
                    signed_by(&counterparty_keys, answered, counterparty),
                ),
            ),
        ] {
            assert!(
                handler.handle_prepare_reject(&envelope).await.is_err(),
                "a rejection {what} was accepted"
            );
        }
        assert_eq!(
            handler.get_session_phase(&pending).await,
            Some(BilateralPhase::Prepared),
            "a refused rejection changed the proposal"
        );
        assert_eq!(
            handler.get_session_phase(&answered).await,
            Some(BilateralPhase::Accepted)
        );

        handler
            .handle_prepare_reject(&rejection(
                pending,
                counterparty,
                signed_by(&counterparty_keys, pending, counterparty),
            ))
            .await
            .expect("the counterparty's signed rejection ends the proposal");
        assert_eq!(
            handler.get_session_phase(&pending).await,
            Some(BilateralPhase::Rejected)
        );
    }

    /// A `bilateral.confirm` envelope from `sender` carrying `req`.
    fn confirm_envelope(sender: [u8; 32], req: &generated::BilateralConfirmRequest) -> Vec<u8> {
        let envelope = generated::Envelope {
            version: 3,
            headers: Some(generated::Headers {
                device_id: sender.to_vec(),
                genesis_hash: vec![0x74u8; 32],
            }),
            message_id: vec![0x75u8; 16],
            payload: Some(generated::envelope::Payload::UniversalTx(
                generated::UniversalTx {
                    ops: vec![generated::UniversalOp {
                        op_id: None,
                        actor: sender.to_vec(),
                        kind: Some(generated::universal_op::Kind::Invoke(generated::Invoke {
                            program: None,
                            method: "bilateral.confirm".to_string(),
                            args: Some(generated::ArgPack {
                                schema_hash: None,
                                codec: 0,
                                body: prost::Message::encode_to_vec(req),
                            }),
                            cosigners: vec![],
                            evidence: None,
                            nonce: None,
                        })),
                    }],
                    atomic: false,
                },
            )),
        };
        crate::envelope::to_canonical_bytes(&envelope)
    }

    /// The receipt of `devid_a`'s first step toward `devid_b`, built from a
    /// real Core advance: the one relationship path, both roots, and the
    /// sender's single-device Device Tree proof.
    fn first_step_receipt(
        devid_a: [u8; 32],
        devid_b: [u8; 32],
    ) -> dsm::types::receipt_types::StitchedReceiptV2 {
        let head =
            dsm::types::device_state::DeviceState::new([0x76u8; 32], devid_a, vec![0x77u8; 64])
                .establish_relationship(devid_b)
                .expect("establish");
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid_a, &devid_b);
        let outcome = head
            .advance(rel_key, devid_b, Operation::Noop, &[], None, None)
            .expect("the first step");
        let parent_tip = outcome
            .smt_proofs
            .parent_proof
            .value
            .expect("the path carries the established leaf");
        let dev_proof = dsm::common::device_tree::DeviceTree::single(devid_a)
            .proof(&devid_a)
            .expect("device proof");
        let mut receipt = dsm::types::receipt_types::StitchedReceiptV2::new(
            [0x76u8; 32],
            devid_a,
            devid_b,
            parent_tip,
            outcome.new_chain_state.compute_chain_tip(),
            outcome.smt_proofs.pre_root,
            outcome.child_r_a,
            outcome.smt_proofs.parent_proof.to_bytes(),
            dev_proof.to_bytes(),
        );
        receipt.set_transition_entropy(outcome.transition_entropy());
        receipt
    }

    /// The receiver checks the confirm's stitched receipt — that it is this
    /// session's sender's receipt toward this device, and that its one
    /// relationship path and Device Tree proof hold against the commitment
    /// kept for the sender — before the per-step EK check and before
    /// anything commits. A holding receipt reaches the EK check, which
    /// refuses it for carrying no A-side EK. MUTATION CONTROL: deleting the
    /// `verify_receipt_state` call lets the bent receipt through to the EK
    /// refusal; deleting the device binding does the same for the foreign
    /// receipt — either turns this red.
    #[tokio::test]
    #[serial]
    async fn a_confirm_whose_receipt_does_not_hold_is_refused_before_the_ek_check() {
        init_test_db();
        let receiver = [0x71u8; 32];
        let sender = [0x72u8; 32];
        let (manager, handler) =
            make_test_handler(receiver, [0x73u8; 32], b"confirm-receipt-gate-receiver");
        let sender_keys = SignatureKeyPair::generate_from_entropy(b"confirm-receipt-gate-sender")
            .expect("sender keys");
        {
            let mut mgr = manager.write().await;
            mgr.add_verified_contact(dsm::types::contact_types::DsmVerifiedContact {
                alias: "sender".to_string(),
                device_id: sender,
                genesis_hash: [0x74u8; 32],
                public_key: sender_keys.public_key().to_vec(),
                chain_tip: None,
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            })
            .expect("add contact");
        }
        crate::storage::client_db::store_contact(&crate::storage::client_db::ContactRecord {
            contact_id: "sender".to_string(),
            device_id: sender.to_vec(),
            alias: "sender".to_string(),
            genesis_hash: vec![0x74u8; 32],
            public_key: sender_keys.public_key().to_vec(),
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(vec![0x70; 32]),
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "verified".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        })
        .expect("persist the contact and its Device Tree root");

        let commitment_hash = [0x78u8; 32];
        handler
            .test_insert_session(BilateralBleSession {
                commitment_hash,
                local_commitment_hash: None,
                counterparty_device_id: sender,
                counterparty_genesis_hash: Some([0x74u8; 32]),
                operation: Operation::Noop,
                phase: BilateralPhase::Accepted,
                local_signature: None,
                counterparty_signature: None,
                sender_ble_address: None,
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
                receiver_challenge: None,
                anchor_leaf: None,
                anchor_sim_root: None,
                offline_spend: None,
            })
            .await;
        let mut signed = b"DSM/bilateral-sign\0".to_vec();
        signed.extend_from_slice(&commitment_hash);
        let sender_signature = sender_keys.sign(&signed).expect("sigma_A");
        let refusal = |receipt: &dsm::types::receipt_types::StitchedReceiptV2| {
            confirm_envelope(
                sender,
                &generated::BilateralConfirmRequest {
                    commitment_hash: Some(generated::Hash32 {
                        v: commitment_hash.to_vec(),
                    }),
                    sender_signature: sender_signature.clone(),
                    stitched_receipt: receipt.to_canonical_protobuf().expect("encode"),
                    ..Default::default()
                },
            )
        };

        let holding = first_step_receipt(sender, receiver);
        let msg = handler
            .handle_confirm_request(&refusal(&holding))
            .await
            .expect_err("a receipt with no A-side EK is refused")
            .to_string();
        assert!(
            msg.contains("per-step EK A-side artifacts"),
            "a holding receipt reaches the EK check, got: {msg}"
        );

        let mut bent = holding.clone();
        bent.child_root[0] ^= 0x01;
        let msg = handler
            .handle_confirm_request(&refusal(&bent))
            .await
            .expect_err("a receipt whose child root is not its path's fold is refused")
            .to_string();
        assert!(
            msg.contains("is not the child root"),
            "the receipt's state rules refuse it, got: {msg}"
        );

        let foreign = first_step_receipt([0x79u8; 32], receiver);
        let msg = handler
            .handle_confirm_request(&refusal(&foreign))
            .await
            .expect_err("another device's receipt is refused")
            .to_string();
        assert!(
            msg.contains("not from this session's sender"),
            "the receipt is bound to the session's devices, got: {msg}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_stale_receiver_session_cleans_local_pending_commitment() {
        let (identity, _core) = crate::economic_fixtures::local_device(0x12);
        let (device_id, genesis_hash) = (identity.device_id, identity.genesis);
        let counterparty_device_id = [33u8; 32];
        let counterparty_genesis = [34u8; 32];
        let keypair = identity.signing_keypair();

        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "stale_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![9u8; 32],
            chain_tip: Some([7u8; 32]),
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: None,
        };

        {
            let mut mgr = bilateral_manager.write().await;
            crate::storage::client_db::store_contact_for_tests(&contact);
            mgr.add_verified_contact(contact).expect("add contact");
            mgr.establish_relationship(&counterparty_device_id)
                .await
                .expect("establish relationship");
        }

        let stale_op = Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::amount(1),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1],
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "stale".to_string(),
            signature: Vec::new(),
            authority_policy: Some(dsm::types::operations::canonical_offline_bearer_policy()),
        };
        let next_op = Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::amount(1),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![2],
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "fresh".to_string(),
            signature: Vec::new(),
            authority_policy: Some(dsm::types::operations::canonical_offline_bearer_policy()),
        };

        let local_pending_hash = {
            let mut mgr = bilateral_manager.write().await;
            let pre = mgr
                .prepare_offline_transfer(&counterparty_device_id, stale_op.clone())
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
                sender_ble_address: None,
                created_at_wall: Instant::now() - Duration::from_secs(121),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
                receiver_challenge: None,
                anchor_leaf: None,
                anchor_sim_root: None,
                offline_spend: None,
            })
            .await;

        handler
            .prepare_bilateral_transaction(counterparty_device_id, next_op)
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

    /// A sender step in `ConfirmPending`, persisted, whose precommitment is
    /// not pending: the commit's prepare refuses it.
    async fn sender_step_whose_prepare_refuses(
        handler: &BilateralBleHandler,
        counterparty: [u8; 32],
        tip: [u8; 32],
        commitment: [u8; 32],
    ) {
        crate::storage::client_db::store_contact_for_tests(
            &dsm::types::contact_types::DsmVerifiedContact {
                alias: "peer".to_string(),
                device_id: counterparty,
                genesis_hash: [0x54u8; 32],
                public_key: vec![0x41; 64],
                chain_tip: Some(tip),
                genesis_verified_online: true,
                verifying_storage_nodes: vec![],
                ble_address: None,
            },
        );
        let session = BilateralBleSession {
            commitment_hash: commitment,
            local_commitment_hash: None,
            counterparty_device_id: counterparty,
            counterparty_genesis_hash: Some([0x54u8; 32]),
            operation: Operation::Transfer {
                policy_commit: [0x0Fu8; 32],
                to_device_id: counterparty.to_vec(),
                amount: Balance::amount(1),
                token_id: b"ERA".to_vec(),
                mode: TransactionMode::Bilateral,
                nonce: vec![1; 32],
                recipient: counterparty.to_vec(),
                to: counterparty.to_vec(),
                message: String::new(),
                signature: Vec::new(),
                authority_policy: Some(dsm::types::operations::canonical_offline_bearer_policy()),
            },
            phase: BilateralPhase::ConfirmPending,
            local_signature: Some(vec![1u8; 32]),
            counterparty_signature: Some(vec![2u8; 32]),
            sender_ble_address: None,
            created_at_wall: Instant::now(),
            pre_finalize_entropy: Some([3u8; 32]),
            stitched_receipt_bytes: Some(vec![4u8; 8]),
            receiver_challenge: None,
            anchor_leaf: None,
            anchor_sim_root: None,
            offline_spend: Some(dsm::types::device_state::OfflineSpend {
                anchor_bundle_b: [5u8; 32],
                asset: [0x0Fu8; 32],
                amount: 1,
            }),
        };
        handler
            .persist_session(&session, None)
            .await
            .expect("persist the session");
        handler.test_insert_session(session).await;
    }

    /// A sender commit that fails its checks settles nothing: no canonical
    /// advance, no tip write, no history, no "complete". The session fails
    /// durably and the relationship is held for online reconciliation,
    /// because the receiver may already have committed its side.
    #[tokio::test]
    #[serial]
    async fn a_sender_commit_that_fails_its_checks_settles_nothing_and_holds_the_relationship() {
        init_test_db();
        let counterparty = [0x53u8; 32];
        let tip = [0x70u8; 32];
        let commitment = [0x5Cu8; 32];
        let (_mgr, handler) = make_test_handler([0x51u8; 32], [0x52u8; 32], b"sender-refused");
        sender_step_whose_prepare_refuses(&handler, counterparty, tip, commitment).await;

        assert!(
            handler
                .mark_sender_committed_with_post_state_hash(&commitment, Some([9u8; 32]))
                .await
                .is_none(),
            "a commit whose prepare refuses finalizes nothing"
        );

        let row = crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("read the session")
            .expect("the failed session row is kept");
        assert_eq!(row.phase, "failed");
        assert!(handler.get_session_status(&commitment).await.is_none());
        let contact = crate::storage::client_db::get_contact_by_device_id(&counterparty)
            .expect("read the contact")
            .expect("the contact");
        assert!(
            contact.needs_online_reconcile,
            "the relationship is held for online reconcile"
        );
        assert_eq!(
            crate::storage::client_db::get_contact_chain_tip(&counterparty).expect("read the tip"),
            Some(tip),
            "no tip was written"
        );
        assert!(
            crate::storage::client_db::get_transaction_history(None, None)
                .expect("read the history")
                .is_empty(),
            "nothing settled"
        );
    }

    /// An acknowledgment is the receiver's counter-signed receipt. One that
    /// does not verify is not an answer: the step stays awaiting its ack
    /// (the receiver may have committed), and nothing is finalized or failed.
    /// MUTATION CONTROL: failing the session on an ack that does not verify
    /// turns this red.
    #[tokio::test]
    #[serial]
    async fn an_ack_that_does_not_verify_leaves_the_step_awaiting_its_ack() {
        init_test_db();
        let (_mgr, handler) = make_test_handler([0x68u8; 32], [0x69u8; 32], b"unverified-ack");
        let counterparty = [0x6Au8; 32];
        let commitment = [0x6Bu8; 32];
        sender_step_whose_prepare_refuses(&handler, counterparty, [0x72u8; 32], commitment).await;
        let ack = crate::envelope::to_canonical_bytes(&generated::Envelope {
            version: 3,
            headers: Some(generated::Headers {
                device_id: counterparty.to_vec(),
                genesis_hash: vec![0x54; 32],
            }),
            message_id: vec![7; 16],
            payload: Some(generated::envelope::Payload::BilateralCommitResponse(
                generated::BilateralCommitResponse {
                    commitment_hash: Some(generated::Hash32 {
                        v: commitment.to_vec(),
                    }),
                    post_state_hash: Some(generated::Hash32 { v: vec![8; 32] }),
                    counter_signed_receipt: vec![9; 16],
                },
            )),
        });

        handler
            .handle_commit_response(&ack)
            .await
            .expect_err("an ack whose receipt does not verify is refused");
        assert_eq!(
            handler.get_session_phase(&commitment).await,
            Some(BilateralPhase::ConfirmPending),
            "an unverified ack moved the step"
        );
        assert_eq!(
            crate::storage::client_db::get_bilateral_session(&commitment)
                .expect("read the session")
                .expect("kept")
                .phase,
            "confirm_pending"
        );
    }

    /// A commit ack names a session by its hash; one this device is not
    /// committing (unknown, or already failed) cannot be verified against a
    /// session, so it finalizes nothing.
    #[tokio::test]
    #[serial]
    async fn a_commit_ack_for_a_session_this_device_is_not_committing_finalizes_nothing() {
        init_test_db();
        let (_mgr, handler) = make_test_handler([0x61u8; 32], [0x62u8; 32], b"stray-ack");
        let ack = |commitment: [u8; 32]| {
            crate::envelope::to_canonical_bytes(&generated::Envelope {
                version: 3,
                headers: Some(generated::Headers {
                    device_id: vec![0x63; 32],
                    genesis_hash: vec![0x64; 32],
                }),
                message_id: vec![7; 16],
                payload: Some(generated::envelope::Payload::BilateralCommitResponse(
                    generated::BilateralCommitResponse {
                        commitment_hash: Some(generated::Hash32 {
                            v: commitment.to_vec(),
                        }),
                        post_state_hash: Some(generated::Hash32 { v: vec![8; 32] }),
                        counter_signed_receipt: vec![9; 16],
                    },
                )),
            })
        };

        let unknown = handler
            .handle_commit_response(&ack([0x65u8; 32]))
            .await
            .expect_err("an ack for an unknown session is refused");
        assert!(unknown.to_string().contains("not committing"), "{unknown}");

        let counterparty = [0x66u8; 32];
        let failed = [0x67u8; 32];
        sender_step_whose_prepare_refuses(&handler, counterparty, [0x71u8; 32], failed).await;
        assert!(handler
            .mark_sender_committed_with_post_state_hash(&failed, None)
            .await
            .is_none());
        let refused = handler
            .handle_commit_response(&ack(failed))
            .await
            .expect_err("an ack for a failed session is refused");
        assert!(refused.to_string().contains("not committing"), "{refused}");
        assert_eq!(
            crate::storage::client_db::get_bilateral_session(&failed)
                .expect("read the session")
                .expect("kept")
                .phase,
            "failed",
            "the ack did not revive or complete the failed session"
        );
        assert!(
            crate::storage::client_db::get_transaction_history(None, None)
                .expect("read the history")
                .is_empty()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_fail_session_by_commitment_cleans_receiver_accepted_session() {
        init_test_db();
        let device_id = [41u8; 32];
        let genesis_hash = [42u8; 32];
        let counterparty_device_id = [43u8; 32];
        let counterparty_genesis = [44u8; 32];
        let keypair =
            SignatureKeyPair::generate_from_entropy(b"fail-accepted-session").expect("keypair");

        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
        )));
        let handler = BilateralBleHandler::new(bilateral_manager.clone(), device_id);

        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "accepted_contact".to_string(),
            device_id: counterparty_device_id,
            genesis_hash: counterparty_genesis,
            public_key: vec![9u8; 32],
            chain_tip: Some([7u8; 32]),
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
        };

        {
            let mut mgr = bilateral_manager.write().await;
            crate::storage::client_db::store_contact_for_tests(&contact);
            mgr.add_verified_contact(contact).expect("add contact");
            mgr.establish_relationship(&counterparty_device_id)
                .await
                .expect("establish relationship");
        }

        let accepted_op = Operation::Transfer {
            policy_commit: [0u8; 32],
            to_device_id: counterparty_device_id.to_vec(),
            amount: Balance::amount(1),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1],
            recipient: counterparty_device_id.to_vec(),
            to: counterparty_device_id.to_vec(),
            message: "accepted".to_string(),
            signature: Vec::new(),
            authority_policy: Some(dsm::types::operations::canonical_offline_bearer_policy()),
        };

        let local_pending_hash = {
            let mut mgr = bilateral_manager.write().await;
            let pre = mgr
                .prepare_offline_transfer(&counterparty_device_id, accepted_op.clone())
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
                sender_ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
                receiver_challenge: None,
                anchor_leaf: None,
                anchor_sim_root: None,
                offline_spend: None,
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

        let contact_manager = DsmContactManager::new(device_id);
        let bilateral_manager = Arc::new(RwLock::new(BilateralTransactionManager::new(
            contact_manager,
            keypair,
            device_id,
            genesis_hash,
            std::sync::Arc::new(crate::sdk::chain_tip_store::SqliteChainTipStore::new()),
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
                sender_ble_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
                receiver_challenge: None,
                anchor_leaf: None,
                anchor_sim_root: None,
                offline_spend: None,
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
                sender_ble_address: Some("AA:BB:CC:DD:EE:11".to_string()),
                created_at_wall: Instant::now(),
                pre_finalize_entropy: None,
                stitched_receipt_bytes: None,
                receiver_challenge: None,
                anchor_leaf: None,
                anchor_sim_root: None,
                offline_spend: None,
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
            sender_ble_address: None,
            stitched_receipt_bytes: None,
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
            sender_ble_address: None,
            stitched_receipt_bytes: None,
        };
        crate::storage::client_db::store_bilateral_session(&old_terminal).expect("store terminal");
        let invalid_short_commitment_hash = [0xDE_u8; 31];

        {
            let conn = crate::storage::client_db::get_connection().expect("db connection");
            let conn = conn.lock().expect("db lock");
            conn.execute(
                "INSERT INTO bilateral_sessions(
                    commitment_hash, counterparty_device_id, counterparty_genesis_hash, operation_bytes, phase,
                    local_signature, counterparty_signature, sender_ble_address
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    invalid_short_commitment_hash.to_vec(),
                    counterparty_device_id.to_vec(),
                    Option::<Vec<u8>>::None,
                    vec![0x01_u8],
                    "prepared",
                    Option::<Vec<u8>>::None,
                    Option::<Vec<u8>>::None,
                    Option::<String>::None,
                ],
            )
            .expect("insert malformed row");
        }

        let restored = handler
            .restore_sessions_from_storage()
            .await
            .expect("restore sessions");
        assert_eq!(restored, 0, "interrupted sessions are marked failed");

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

    /// §11.1 Item 8b — wedge recovery: a ConfirmPending session with a
    /// counter-signed receipt whose ek_cert_b chains from the current
    /// Counterparty pubkey MUST be reconciled by advancing Counterparty
    /// to ek_pk_b during `restore_sessions_from_storage`.
    #[tokio::test]
    #[serial]
    async fn test_restore_sweep_reconciles_counterparty_wedge() {
        use crate::storage::client_db::{
            init_cert_chain_head, load_cert_chain_head_pubkey, CertChainSide,
        };
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        use dsm::types::receipt_types::StitchedReceiptV2;

        init_test_db();

        let local_device_id = [11u8; 32];
        let counterparty_device_id = [13u8; 32];
        let (_bilateral_manager, handler) =
            make_test_handler(local_device_id, [12u8; 32], b"sweep-wedge-recovery");

        // Build a counter-signed receipt where ek_cert_b chains from a
        // known prior key (= the current Counterparty pubkey we'll seed).
        let (prior_cp_pk, prior_cp_sk) = generate_ephemeral_keypair(&[0xA1; 32]).unwrap();
        let (next_ek_pk, _next_ek_sk) = generate_ephemeral_keypair(&[0xA2; 32]).unwrap();
        let h_n = [0xCA; 32];

        let cert_b =
            dsm::crypto::ephemeral_key::sign_ek_cert(&prior_cp_sk, &next_ek_pk, &h_n).unwrap();

        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],             // genesis
            counterparty_device_id, // devid_a (= receiver in their own view)
            local_device_id,        // devid_b (= sender from their view)
            h_n,                    // parent_tip
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        receipt.set_ek_pk_b(next_ek_pk.clone());
        receipt.set_ek_cert_b(cert_b);
        receipt.add_sig_b(vec![0xAA; 64]); // body sig — content irrelevant for sweep gate

        let canonical_bytes = receipt.to_canonical_protobuf().unwrap();
        // We need the FULL bytes (including ek_cert_b/ek_pk_b/sig_b) so
        // round-tripping decodes the per-step EK fields.
        let full_bytes = receipt.to_full_protobuf().unwrap();
        let _ = canonical_bytes; // ensure method compiles

        // Compute rel_key the same way the sweep does.
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &local_device_id,
            &counterparty_device_id,
        );
        // Seed Counterparty at the prior key — this is exactly the
        // wedge state (chain head behind the receipt's ek_pk_b by
        // one step).
        init_cert_chain_head(&rel_key, CertChainSide::Counterparty, &prior_cp_pk).unwrap();

        // Persist a ConfirmPending session carrying the counter-signed
        // bytes — mirrors what the in-flight flush would have left
        // behind on a crash inside mark_sender_committed.
        let record = crate::storage::client_db::BilateralSessionRecord {
            commitment_hash: vec![0xA3; 32],
            counterparty_device_id: counterparty_device_id.to_vec(),
            counterparty_genesis_hash: Some(vec![0xB3; 32]),
            operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
            phase: "confirm_pending".to_string(),
            local_signature: Some(vec![0xC3; 64]),
            counterparty_signature: Some(vec![0xD3; 64]),
            sender_ble_address: None,
            stitched_receipt_bytes: Some(full_bytes),
        };
        crate::storage::client_db::store_bilateral_session(&record).expect("persist wedge session");

        // Run the sweep.
        handler
            .restore_sessions_from_storage()
            .await
            .expect("restore");

        // Counterparty must now be at next_ek_pk (advanced).
        let after = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
            .unwrap()
            .expect("Counterparty row still exists");
        assert_eq!(
            after, next_ek_pk,
            "Item 8b sweep must advance Counterparty when cert_b chains from current head"
        );
    }

    /// §11.1 Item 8b — safety: a session whose ek_cert_b does NOT chain
    /// from the current Counterparty (e.g., Counterparty already
    /// advanced past, or unrelated cert) MUST NOT be advanced. The
    /// sweep is conservative by construction — only the cert-link
    /// check unlocks an advance.
    #[tokio::test]
    #[serial]
    async fn test_restore_sweep_does_not_advance_when_cert_does_not_chain() {
        use crate::storage::client_db::{
            init_cert_chain_head, load_cert_chain_head_pubkey, CertChainSide,
        };
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        use dsm::types::receipt_types::StitchedReceiptV2;

        init_test_db();

        let local_device_id = [21u8; 32];
        let counterparty_device_id = [23u8; 32];
        let (_bilateral_manager, handler) =
            make_test_handler(local_device_id, [22u8; 32], b"sweep-conservative-safety");

        // Cert signed by an UNRELATED key, NOT by the seeded
        // Counterparty pubkey.
        let (unrelated_pk, unrelated_sk) = generate_ephemeral_keypair(&[0xB1; 32]).unwrap();
        let (seeded_cp_pk, _seeded_cp_sk) = generate_ephemeral_keypair(&[0xB2; 32]).unwrap();
        let (next_ek_pk, _) = generate_ephemeral_keypair(&[0xB3; 32]).unwrap();
        let h_n = [0xCB; 32];

        let cert_b =
            dsm::crypto::ephemeral_key::sign_ek_cert(&unrelated_sk, &next_ek_pk, &h_n).unwrap();
        let _ = unrelated_pk;

        let mut receipt = StitchedReceiptV2::new(
            [0x01; 32],
            counterparty_device_id,
            local_device_id,
            h_n,
            [0x04; 32],
            [0x05; 32],
            [0x06; 32],
            vec![0x07; 16],
            vec![0x09; 16],
        );
        receipt.set_ek_pk_b(next_ek_pk);
        receipt.set_ek_cert_b(cert_b);
        receipt.add_sig_b(vec![0xAA; 64]);
        let full_bytes = receipt.to_full_protobuf().unwrap();

        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &local_device_id,
            &counterparty_device_id,
        );
        // Seed Counterparty at a different key — the cert was NOT signed
        // by the SK behind this pubkey, so the cert-link check must fail.
        init_cert_chain_head(&rel_key, CertChainSide::Counterparty, &seeded_cp_pk).unwrap();

        let record = crate::storage::client_db::BilateralSessionRecord {
            commitment_hash: vec![0xB4; 32],
            counterparty_device_id: counterparty_device_id.to_vec(),
            counterparty_genesis_hash: Some(vec![0xB5; 32]),
            operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
            phase: "confirm_pending".to_string(),
            local_signature: Some(vec![0xC5; 64]),
            counterparty_signature: Some(vec![0xD5; 64]),
            sender_ble_address: None,
            stitched_receipt_bytes: Some(full_bytes),
        };
        crate::storage::client_db::store_bilateral_session(&record)
            .expect("persist safety session");

        handler
            .restore_sessions_from_storage()
            .await
            .expect("restore");

        // Counterparty MUST still equal seeded_cp_pk — sweep refused to
        // advance because the cert-link check failed.
        let after = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
            .unwrap()
            .expect("Counterparty row still exists");
        assert_eq!(
            after, seeded_cp_pk,
            "Item 8b sweep must NOT advance when cert_b does not chain from current Counterparty"
        );
    }

    /// §11.1 Item 8b multi-step wedge recovery: the sweep iterates to
    /// a fixed point, so a chain of TWO single-step wedges within one
    /// relationship recovers regardless of the order in which SQLite
    /// returns the session rows.
    ///
    /// Setup: Counterparty seeded at AK_pk (= "step 0"). Two wedged
    /// sessions persisted:
    ///   - S1: receipt with ek_pk_b_1 chained from AK_pk
    ///   - S2: receipt with ek_pk_b_2 chained from ek_pk_b_1
    ///
    /// The sweep meets S2 before S1 to exercise the
    /// fixed-point loop's order-independence — without the loop,
    /// processing S2 first would fail (cert chains from ek_pk_b_1 but
    /// Counterparty is at AK_pk), then S1 would advance to ek_pk_b_1
    /// but S2 would never be retried. With the fix, two passes reach
    /// the chain head ek_pk_b_2.
    #[tokio::test]
    #[serial]
    async fn test_restore_sweep_recovers_multi_step_wedge_chain() {
        use crate::storage::client_db::{
            init_cert_chain_head, load_cert_chain_head_pubkey, CertChainSide,
        };
        use dsm::crypto::ephemeral_key::generate_ephemeral_keypair;
        use dsm::types::receipt_types::StitchedReceiptV2;

        init_test_db();

        let local_device_id = [31u8; 32];
        let counterparty_device_id = [33u8; 32];
        let (_bilateral_manager, handler) =
            make_test_handler(local_device_id, [32u8; 32], b"sweep-multi-step");

        // Build a 3-key chain: AK_pk → EK_pk_1 → EK_pk_2
        let (ak_pk, ak_sk) = generate_ephemeral_keypair(&[0xC1; 32]).unwrap();
        let (ek_pk_1, ek_sk_1) = generate_ephemeral_keypair(&[0xC2; 32]).unwrap();
        let (ek_pk_2, _ek_sk_2) = generate_ephemeral_keypair(&[0xC3; 32]).unwrap();
        let h_n_1 = [0xCA; 32];
        let h_n_2 = [0xCB; 32];

        // Cert for step 1: signed by AK_sk over (ek_pk_1, h_n_1).
        let cert_1 = dsm::crypto::ephemeral_key::sign_ek_cert(&ak_sk, &ek_pk_1, &h_n_1).unwrap();
        // Cert for step 2: signed by ek_sk_1 over (ek_pk_2, h_n_2).
        let cert_2 = dsm::crypto::ephemeral_key::sign_ek_cert(&ek_sk_1, &ek_pk_2, &h_n_2).unwrap();

        let make_session_record = |commitment_byte: u8,
                                   ek_pk: Vec<u8>,
                                   cert: Vec<u8>,
                                   parent_tip: [u8; 32]|
         -> crate::storage::client_db::BilateralSessionRecord {
            let mut receipt = StitchedReceiptV2::new(
                [0x01; 32],
                counterparty_device_id,
                local_device_id,
                parent_tip,
                [0x04; 32],
                [0x05; 32],
                [0x06; 32],
                vec![0x07; 16],
                vec![0x09; 16],
            );
            receipt.set_ek_pk_b(ek_pk);
            receipt.set_ek_cert_b(cert);
            receipt.add_sig_b(vec![0xAA; 64]);
            crate::storage::client_db::BilateralSessionRecord {
                commitment_hash: vec![commitment_byte; 32],
                counterparty_device_id: counterparty_device_id.to_vec(),
                counterparty_genesis_hash: Some(vec![0xB0; 32]),
                operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
                phase: "confirm_pending".to_string(),
                local_signature: Some(vec![0xC0; 64]),
                counterparty_signature: Some(vec![0xD0; 64]),
                sender_ble_address: None,
                stitched_receipt_bytes: Some(receipt.to_full_protobuf().unwrap()),
            }
        };

        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &local_device_id,
            &counterparty_device_id,
        );
        // Seed Counterparty at AK_pk — exactly two steps behind ek_pk_2.
        init_cert_chain_head(&rel_key, CertChainSide::Counterparty, &ak_pk).unwrap();

        // Sessions load newest first, so persisting S2 LAST makes the sweep
        // meet S2 first. The fixed-point loop must still recover both.
        let s2_record = make_session_record(0xE2, ek_pk_2.clone(), cert_2, h_n_2);
        let s1_record = make_session_record(0xE1, ek_pk_1.clone(), cert_1, h_n_1);
        crate::storage::client_db::store_bilateral_session(&s1_record).expect("persist s1");
        crate::storage::client_db::store_bilateral_session(&s2_record).expect("persist s2");
        let loaded = crate::storage::client_db::get_all_bilateral_sessions().expect("load");
        assert_eq!(
            loaded.first().map(|r| r.commitment_hash.clone()),
            Some(vec![0xE2; 32]),
            "the sweep must meet S2 first"
        );

        handler
            .restore_sessions_from_storage()
            .await
            .expect("restore");

        // Counterparty must end at ek_pk_2 — both wedges recovered.
        let after = load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
            .unwrap()
            .expect("Counterparty row still exists");
        assert_eq!(
            after, ek_pk_2,
            "Item 8b fixed-point sweep must recover BOTH steps of a chained \
             multi-step wedge regardless of SQLite row order"
        );
    }

    /// Stage 4 Slice 3 (signal b): the receiver-admit path emits the right UX events.
    /// First disclosure from a verified contact -> ANCHOR_PINNED + pin stored; an identical repeat
    /// -> NO event (NoChange); a DIFFERING anchor -> ANCHOR_CHANGED + the ORIGINAL pin retained
    /// (never overwritten). Uses a stub event callback + a fresh in-memory enrollment store.
    #[tokio::test]
    #[serial]
    async fn admit_anchor_disclosure_emits_pin_and_change_events() {
        use dsm::crypto::anchor_enrollment::InMemoryAnchorEnrollmentStore;
        use std::sync::Mutex as StdMutex;

        init_test_db();
        let device_id = [0x51u8; 32]; // receiver
        let genesis_hash = [0x52u8; 32];
        let sender = [0x53u8; 32];
        let sender_genesis = [0x54u8; 32];

        let (bilateral_manager, mut handler) =
            make_test_handler(device_id, genesis_hash, b"anchor-events");

        // Verified contact for the sender (admit requires it).
        let contact = dsm::types::contact_types::DsmVerifiedContact {
            alias: "sender".to_string(),
            device_id: sender,
            genesis_hash: sender_genesis,
            public_key: vec![7u8; 32],
            chain_tip: Some([6u8; 32]),
            genesis_verified_online: true,
            verifying_storage_nodes: vec![],
            ble_address: Some(String::new()),
        };
        {
            let mut m = bilateral_manager.write().await;
            m.add_verified_contact(contact).expect("contact");
        }

        // Fresh receiver-side enrollment store (the admit target).
        crate::bridge::install_anchor_enrollment_store(Arc::new(
            InMemoryAnchorEnrollmentStore::new(),
        ));

        // Capture emitted events by decoding them off the callback.
        let events: Arc<StdMutex<Vec<generated::BilateralEventNotification>>> =
            Arc::new(StdMutex::new(Vec::new()));
        {
            let sink = events.clone();
            handler.set_event_callback(Arc::new(move |bytes: &[u8]| {
                if let Ok(ev) = generated::BilateralEventNotification::decode(bytes) {
                    sink.lock().expect("sink").push(ev);
                }
            }));
        }

        let disclosure = |anchor_tag: u8| generated::AnchorDisclosure {
            bundle: vec![0xB1; 32],
            anchor_id: vec![anchor_tag; 32],
            enrolled_counter: 1_000,
            partition_pk: vec![0x07; 64],
            policy_hash: vec![0x9A; 32],
            pk_chip: vec![0x0C; 32],
        };
        let last_type = |events: &Arc<StdMutex<Vec<generated::BilateralEventNotification>>>| {
            events.lock().expect("evs").last().map(|e| e.event_type)
        };
        let anchor_pinned = generated::BilateralEventType::BilateralEventAnchorPinned as i32;
        let anchor_changed = generated::BilateralEventType::BilateralEventAnchorChanged as i32;

        // 1) First disclosure -> ANCHOR_PINNED + pin stored.
        handler
            .admit_anchor_disclosure(sender, [0x01; 32], &disclosure(0xA1))
            .await;
        assert_eq!(events.lock().expect("evs").len(), 1);
        assert_eq!(last_type(&events), Some(anchor_pinned));
        let pinned = crate::bridge::anchor_enrollment_store()
            .and_then(|s| s.get(&sender))
            .expect("pin stored");
        assert_eq!(pinned.pin.anchor_id, [0xA1; 32]);

        // 2) Identical repeat -> NoChange -> NO new event.
        handler
            .admit_anchor_disclosure(sender, [0x02; 32], &disclosure(0xA1))
            .await;
        assert_eq!(
            events.lock().expect("evs").len(),
            1,
            "NoChange must be silent"
        );

        // 3) Differing anchor -> ANCHOR_CHANGED + ORIGINAL pin retained (never overwritten).
        handler
            .admit_anchor_disclosure(sender, [0x03; 32], &disclosure(0xEE))
            .await;
        assert_eq!(events.lock().expect("evs").len(), 2);
        assert_eq!(last_type(&events), Some(anchor_changed));
        let still = crate::bridge::anchor_enrollment_store()
            .and_then(|s| s.get(&sender))
            .expect("pin still present");
        assert_eq!(
            still.pin.anchor_id, [0xA1; 32],
            "a differing disclosure must never overwrite the pinned anchor"
        );

        crate::bridge::uninstall_anchor_enrollment_store();
    }
}
