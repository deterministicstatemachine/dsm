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

use log::{debug, info, warn, error};
use prost::Message;
use tokio::sync::RwLock;

#[cfg(all(target_os = "android", feature = "jni"))]
use crate::jni::state::DEVICE_ID_TO_ADDR;

// Re-export types from bilateral_session so existing import paths still work.
pub use super::bilateral_session::{
    BilateralBleSession, BilateralEventCallback, BilateralPhase, BilateralSettlementDelegate,
    OfflineFrameKind, OwedFrame, SessionStore, is_inflight_phase, phase_to_str, phase_from_str,
    MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY,
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

/// The step this device holds in flight with `counterparty` — other than
/// `other_than`, when given — read from the durable rows.
fn step_in_flight_with(
    counterparty: &[u8; 32],
    other_than: Option<&[u8; 32]>,
) -> Result<Option<([u8; 32], String)>, DsmError> {
    crate::storage::client_db::bilateral_step_in_flight_with(
        counterparty,
        other_than.map(|h| h.as_slice()),
    )
    .map_err(|e| {
        DsmError::storage(
            format!("the relationship's step in flight: {e}"),
            None::<std::io::Error>,
        )
    })?
    .map(|(hash, phase)| {
        <[u8; 32]>::try_from(hash.as_slice())
            .map(|hash| (hash, phase))
            .map_err(|_| {
                DsmError::invalid_operation("a persisted step in flight has a malformed commitment")
            })
    })
    .transpose()
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

/// The per-step EK a local side signed a receipt with, for the caller to
/// install as the local cert-chain head once the step's durability allows.
struct SignedStepKey {
    rel_key: [u8; 32],
    ek_pk: Vec<u8>,
    ek_sk: Vec<u8>,
    /// The head that certified the EK; `None` when the root AK did.
    expected_prev: Option<Vec<u8>>,
    at_rest_key: [u8; 32],
    used_root_ak: bool,
}

impl BilateralBleHandler {
    /// End the step `commitment_hash`, which did not commit, as failed —
    /// durably first. `hold` names the counterparty whose relationship is held
    /// for online reconcile, when its receiver may already have committed; the
    /// hold and the failed phase are one write. Only once it is written does
    /// the step leave memory and its precommitment go: a failure that could
    /// not be recorded is an error, and the step stays as it was.
    async fn fail_session(
        &self,
        commitment_hash: &[u8; 32],
        hold: Option<&[u8; 32]>,
    ) -> Result<(), DsmError> {
        crate::storage::client_db::fail_bilateral_session(
            commitment_hash,
            hold.map(|device_id| device_id.as_slice()),
        )
        .map_err(|e| {
            DsmError::storage(
                format!("the failed step could not be recorded: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let pending_key = self
            .sessions
            .sessions
            .lock()
            .await
            .remove(commitment_hash)
            .and_then(|session| session.local_commitment_hash)
            .unwrap_or(*commitment_hash);
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&pending_key);
        Ok(())
    }

    /// Apply per-step EK signing (whitepaper §11.1) to an unsigned bilateral
    /// receipt. Looks up the counterparty's Kyber pubkey from the contact
    /// record, takes this device's AK keypair `ak` (the root of the chain on a
    /// relationship's first step), fetches the chain-head wrap key for SK
    /// encryption, runs the per-step signing helper and stamps the artifacts
    /// on the receipt's local side (A for sender, B for receiver). Returns
    /// the full-protobuf bytes of the signed receipt.
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
    ///
    /// Writes nothing: the EK it signed with is returned, and the caller
    /// installs it as the local cert-chain head where the step's durability
    /// requires — the sender stashes it until the ack, the receiver moves the
    /// head in the transaction that commits the step.
    fn sign_receipt_with_per_step_ek_for_bilateral(
        &self,
        ak: &(Vec<u8>, Vec<u8>),
        unsigned_receipt_bytes: Vec<u8>,
        counterparty_device_id: &[u8; 32],
        parent_tip: [u8; 32],
        commitment_hash: [u8; 32],
        side: BilateralSide,
    ) -> Result<(Vec<u8>, SignedStepKey), DsmError> {
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

        let (ak_pk, ak_sk) = ak;

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
            root_ak_keypair: Some((ak_pk.as_slice(), ak_sk.as_slice())),
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
        // The head that certified this EK: the root AK on the relationship's
        // first step, else the current local head.
        let expected_prev = if signing_out.used_root_ak {
            None
        } else {
            crate::storage::client_db::load_cert_chain_head_pubkey(
                &rel_key,
                crate::storage::client_db::CertChainSide::Local,
            )
            .map_err(|e| {
                DsmError::storage(
                    format!("the local cert-chain head is unreadable: {e}"),
                    None::<std::io::Error>,
                )
            })?
        };
        match side {
            BilateralSide::A => {
                receipt.set_ek_pk_a(signing_out.ek_pk.clone());
                receipt.set_ek_cert_a(signing_out.ek_cert);
                receipt.set_kyber_ct_a(signing_out.kyber_ct);
                receipt.add_sig_a(signing_out.sig);
            }
            BilateralSide::B => {
                receipt.set_ek_pk_b(signing_out.ek_pk.clone());
                receipt.set_ek_cert_b(signing_out.ek_cert);
                receipt.set_kyber_ct_b(signing_out.kyber_ct);
                receipt.add_sig_b(signing_out.sig);
            }
        }
        Ok((
            receipt.to_full_protobuf()?,
            SignedStepKey {
                rel_key,
                ek_pk: signing_out.ek_pk,
                ek_sk: signing_out.ek_sk,
                expected_prev,
                at_rest_key,
                used_root_ak: signing_out.used_root_ak,
            },
        ))
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

    /// Public helper to query a session's current phase (for tests / diagnostics)
    pub async fn get_session_phase(&self, commitment_hash: &[u8; 32]) -> Option<BilateralPhase> {
        let sessions = self.sessions.sessions.lock().await;
        sessions.get(commitment_hash).map(|s| s.phase.clone())
    }

    /// Persist a session to SQLite storage
    async fn persist_session(&self, session: &BilateralBleSession) -> Result<(), DsmError> {
        store_bilateral_session(&session.to_record()?).map_err(|e| {
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

    /// Restore bilateral sessions from SQLite at startup, as they were: a
    /// restart is not an event of the protocol, so it fails nothing. A
    /// committed step leaves no session row (its end commits with it); every
    /// in-flight row is taken up again — a sender's precommitment held again
    /// against its commitment, and a step whose verified ack the session holds
    /// finalized through the one commit path. A row that does not decode is
    /// not taken up; a sender row whose step does not hash to its commitment
    /// fails (its evidence is not what it claims), and one that had sent its
    /// confirm holds the relationship for online reconcile. Returns the number
    /// of sessions restored.
    pub async fn restore_sessions_from_storage(&self) -> Result<usize, DsmError> {
        info!("[BLE_HANDLER] Restoring bilateral sessions from storage...");
        let records = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to restore sessions: {}", e))
        })?;

        let mut counterparties: HashSet<[u8; 32]> = HashSet::new();
        let mut restored = 0;
        let mut acknowledged: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for record in records {
            let session = match BilateralBleSession::from_record(&record) {
                Ok(session) => session,
                Err(e) => {
                    warn!("[BLE_HANDLER] a persisted bilateral session does not decode; not restored: {e}");
                    continue;
                }
            };
            counterparties.insert(session.counterparty_device_id);
            if !is_inflight_phase(&session.phase) {
                continue;
            }
            if matches!(
                session.phase,
                BilateralPhase::Preparing
                    | BilateralPhase::Prepared
                    | BilateralPhase::ConfirmPending
            ) {
                if let Err(e) = self.hold_sender_step_again(&session).await {
                    warn!(
                        "[BLE_HANDLER] sender step {} is not taken up again: {e}",
                        bytes_to_base32(&session.commitment_hash[..8])
                    );
                    let confirmed = session.phase == BilateralPhase::ConfirmPending;
                    self.fail_session(
                        &session.commitment_hash,
                        confirmed.then_some(&session.counterparty_device_id),
                    )
                    .await?;
                    continue;
                }
            }
            if session.phase == BilateralPhase::ConfirmPending {
                if let Some(ack) = &session.counter_signed_receipt {
                    acknowledged.push((session.commitment_hash, ack.clone()));
                }
            }
            self.sessions
                .sessions
                .lock()
                .await
                .insert(session.commitment_hash, session);
            restored += 1;
        }

        for counterparty_device_id in counterparties {
            self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
                .await;
        }

        // A step whose ack the session holds commits now: the ack is verified
        // again, against the heads as they stand, and the step finalizes.
        for (commitment_hash, ack) in acknowledged {
            match self.record_commit_ack(commitment_hash, &ack).await {
                Ok(true) => {
                    if let Err(e) = self.finalize_sender_step(&commitment_hash).await {
                        warn!(
                            "[BLE_HANDLER] acknowledged step {} did not commit on restart: {e}",
                            bytes_to_base32(&commitment_hash[..8])
                        );
                    }
                }
                Ok(false) => {}
                Err(e) => warn!(
                    "[BLE_HANDLER] acknowledged step {} is not finalized on restart: {e}",
                    bytes_to_base32(&commitment_hash[..8])
                ),
            }
        }
        info!("[BLE_HANDLER] Restored {restored} in-flight bilateral session(s)");
        Ok(restored)
    }

    /// Hold again, after a restart, the precommitment of a sender step: the
    /// counterparty's contact and relationship loaded from storage, and the
    /// step's parent tip and operation required to hash to its commitment.
    async fn hold_sender_step_again(&self, session: &BilateralBleSession) -> Result<(), DsmError> {
        let parent_tip = session.parent_tip.ok_or_else(|| {
            DsmError::invalid_operation("the persisted sender step holds no parent tip")
        })?;
        let counterparty = session.counterparty_device_id;
        let mut mgr = self.bilateral_tx_manager.write().await;
        if !mgr.has_verified_contact(&counterparty) {
            sync_contact_from_storage(&mut mgr, &counterparty)?;
        }
        if mgr.get_relationship(&counterparty).is_none() {
            mgr.establish_relationship(&counterparty).await?;
        }
        mgr.restore_pre_commitment(
            &counterparty,
            parent_tip,
            session.operation.clone(),
            &session.commitment_hash,
        )
    }

    /// Phase 1: Prepare bilateral transaction (sender initiates). One step at
    /// a time per relationship: while a step is in flight — however long it
    /// has been, and whichever door it came through — a new one is refused.
    /// Time does not end a step; its completion, a signed rejection, invalid
    /// evidence or an explicit cancellation does. Called under
    /// [`crate::security::modal_sync_lock::STEP_DOOR`].
    fn ensure_counterparty_ready_for_prepare(
        counterparty_device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        if let Some((existing_commitment_hash, existing_phase)) =
            step_in_flight_with(counterparty_device_id, None)?
        {
            return Err(DsmError::invalid_operation(format!(
                "Existing bilateral session in progress for this contact (phase={existing_phase}, \
                 commitment={}). Complete or resolve it before starting another transfer.",
                bytes_to_base32(&existing_commitment_hash[..8]),
            )));
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

        // Through the proposer's door: the step in flight is read and the new
        // step's row written under the one door (the peer's door is the other).
        let door = crate::security::modal_sync_lock::STEP_DOOR.lock().await;
        Self::ensure_counterparty_ready_for_prepare(&counterparty_device_id)?;
        // An online send on the relationship holds it from its reservation,
        // taken under the same door.
        if crate::security::modal_sync_lock::is_pending_online(
            &dsm::core::bilateral_transaction_manager::compute_smt_key(
                &self.device_id,
                &counterparty_device_id,
            ),
        ) {
            return Err(DsmError::invalid_operation(
                "§5.4: an online send on this relationship is in progress",
            ));
        }

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

        // A step keeps its identity (its commitment) whatever became of it: the
        // same operation on the same tip is that step again, and is refused. The
        // in-flight gate above admits no live step with this counterparty, so a
        // step found here has ended, and the precommitment just made for it
        // goes.
        let known = self
            .sessions
            .sessions
            .lock()
            .await
            .contains_key(&pre_commitment.bilateral_commitment_hash)
            || crate::storage::client_db::get_bilateral_session(
                &pre_commitment.bilateral_commitment_hash,
            )
            .map_err(|e| {
                DsmError::storage(format!("the step's session: {e}"), None::<std::io::Error>)
            })?
            .is_some();
        if known {
            self.bilateral_tx_manager
                .write()
                .await
                .consume_pre_commitment(&pre_commitment.bilateral_commitment_hash);
            return Err(DsmError::invalid_operation(format!(
                "this step was already proposed ({}); a new step needs a new operation",
                bytes_to_base32(&pre_commitment.bilateral_commitment_hash[..8])
            )));
        }

        let session = BilateralBleSession {
            commitment_hash: pre_commitment.bilateral_commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash,
            operation: operation.clone(),
            phase: BilateralPhase::Preparing,
            local_signature: Some(commit_signature.clone()),
            counterparty_signature: None,
            sender_ble_address: None, // Sender side - no counterparty BLE address yet
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: Some(pre_commitment.parent_tip),
            owed_frame: None,
        };

        // The session is durable before anything is sent; a session that could
        // not be kept is not started.
        if let Err(e) = self.persist_session(&session).await {
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
        drop(door);

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
            // σ_A over the commitment: the receiver puts to its user only a
            // proposal its sender signed.
            sender_signature: commit_signature,
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

        let mut buffer = Vec::new();
        envelope.encode(&mut buffer).map_err(|e| {
            DsmError::serialization_error(
                "encode_prepare_envelope",
                "protobuf",
                Some(e.to_string()),
                Some(e),
            )
        })?;

        // The prepared phase, and the prepare it owes until it is answered,
        // are durable before the prepare is sent.
        let mut prepared = session;
        prepared.phase = BilateralPhase::Prepared;
        prepared.owed_frame = Some(buffer.clone());
        self.persist_session(&prepared).await?;
        self.sessions
            .sessions
            .lock()
            .await
            .insert(pre_commitment.bilateral_commitment_hash, prepared);

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

    /// Phase 2: the peer's proposal, at this device's door. A proposal this
    /// device already holds is answered from what it holds. A new one is held
    /// for the user (the answer is empty: the user accepts with
    /// `create_prepare_accept_envelope` or rejects with
    /// `create_prepare_reject_envelope_with_cleanup`), or refused with a
    /// signed rejection — while another step is in flight with the sender, or
    /// when it does not extend the held tip.
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

        // BLE/USB is the OFFLINE transport: the only value it carries is the
        // bearer tier. An online-tier transfer is refused at the door, before
        // any session state exists (owner ruling 2026-08-28).
        let operation =
            dsm::bilateral::offline::offline_operation(&prepare_request.operation_data)?;

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

        // Through the peer's door: the online reservation, the tip this device
        // holds and the step it holds in flight with the sender are read, Core
        // decides with them, and the proposal's row is written — all under the
        // one door this device's own proposals and online sends also take.
        let door = crate::security::modal_sync_lock::STEP_DOOR.lock().await;

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

            if mgr.get_relationship(&counterparty_device_id).is_none() {
                mgr.establish_relationship(&counterparty_device_id)
                    .await
                    .map_err(|e| {
                        DsmError::relationship(format!("Failed to establish relationship: {e}"))
                    })?;
            }
        }

        // Core decides on the proposal from the sender's pinned identity and
        // the relationship tip this device holds durably; the manager builds
        // on the same tip.
        let our_local_chain_tip: [u8; 32] = stored_contact_tip(
            crate::storage::client_db::get_contact_chain_tip(&counterparty_device_id),
        )?
        .ok_or_else(|| DsmError::relationship("the counterparty is not a contact"))?;
        self.bilateral_tx_manager
            .write()
            .await
            .advance_chain_tip(&counterparty_device_id, our_local_chain_tip);
        let sender_contact =
            crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
                .map_err(|e| {
                    DsmError::storage(format!("the sender's contact: {e}"), None::<std::io::Error>)
                })?
                .ok_or_else(|| DsmError::relationship("the sender is not a contact"))?;
        let sender_genesis: [u8; 32] =
            sender_contact
                .genesis_hash
                .as_slice()
                .try_into()
                .map_err(|_| {
                    DsmError::invalid_operation("the sender's pinned genesis is not 32 bytes")
                })?;
        let in_flight =
            step_in_flight_with(&counterparty_device_id, Some(&origin_commitment_hash))?
                .map(|(hash, _phase)| hash);
        let decision = dsm::bilateral::offline::decide_prepare(
            origin_commitment_hash,
            &operation,
            dsm::bilateral::offline::PrepareClaims {
                expected_tip: prepare_request
                    .expected_counterparty_state_hash
                    .as_ref()
                    .and_then(|h| <[u8; 32]>::try_from(h.v.as_slice()).ok()),
                credentials: dsm::bilateral::offline::PeerCredentials {
                    signing_key: &prepare_request.sender_signing_public_key,
                    kyber_public_key: &prepare_request.sender_kyber_public_key,
                    kyber_binding_sig: &prepare_request.sender_kyber_binding_sig,
                },
                signature: &prepare_request.sender_signature,
            },
            &dsm::bilateral::offline::PinnedPeer {
                device_id: counterparty_device_id,
                genesis: sender_genesis,
                signing_key: &sender_contact.public_key,
                kyber_public_key: &sender_contact.kyber_public_key,
            },
            our_local_chain_tip,
            in_flight,
        )?;

        // The proposal delivered again is answered from what this device holds
        // for it, whatever a fresh decision would be now. An acceptance answers
        // with the response it owes (the first may not have arrived); a
        // proposal this device refused, with its signed rejection. A proposal
        // still awaiting its user, or a step that ended any other way, answers
        // nothing; so does a step this device committed — its ack answers the
        // confirm, and a committed step is never refused.
        let existing = match self
            .sessions
            .sessions
            .lock()
            .await
            .get(&origin_commitment_hash)
            .cloned()
        {
            Some(session) => Some(session),
            None => crate::storage::client_db::get_bilateral_session(&origin_commitment_hash)
                .map_err(|e| {
                    DsmError::storage(format!("the step's session: {e}"), None::<std::io::Error>)
                })?
                .map(|row| BilateralBleSession::from_record(&row))
                .transpose()?,
        };
        if let Some(existing) = existing {
            let answer = existing
                .owed()
                .filter(|frame| frame.kind == OfflineFrameKind::PrepareResponse)
                .map(|frame| frame.bytes)
                .or_else(|| existing.rejection())
                .unwrap_or_default();
            return Ok((answer, crate::sdk::transfer_hooks::TransferMeta::default()));
        }
        if crate::storage::client_db::transaction_exists(
            &crate::util::text_id::encode_base32_crockford(&origin_commitment_hash),
        )
        .map_err(|e| {
            DsmError::storage(format!("the step's history: {e}"), None::<std::io::Error>)
        })? {
            return Ok((
                Vec::new(),
                crate::sdk::transfer_hooks::TransferMeta::default(),
            ));
        }

        match decision {
            dsm::bilateral::offline::PrepareDecision::Consider { .. } => {}
            // Another step is in flight with the sender: one step at a time.
            dsm::bilateral::offline::PrepareDecision::StepInFlight { in_flight } => {
                let rejection = self
                    .refuse_while_in_flight(
                        origin_commitment_hash,
                        counterparty_device_id,
                        sender_genesis,
                        operation,
                        sender_ble_address,
                        in_flight,
                    )
                    .await?;
                return Ok((
                    rejection,
                    crate::sdk::transfer_hooks::TransferMeta::default(),
                ));
            }
            // A proposal that does not extend the held tip is answered with a
            // signed rejection, and no precommitment is made.
            dsm::bilateral::offline::PrepareDecision::StaleTip {
                expected: sender_expected_hash,
                ..
            } => {
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

                // The rejection is not kept: the held tip never comes back to
                // the one the proposal extends, so the proposal delivered
                // again is refused the same way. No precommitment is made.
                let send_status = sdk_send_status_from_router_status(
                    crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                        &counterparty_device_id,
                    ),
                );
                let rejection = self
                    .signed_rejection(origin_commitment_hash, reason, Some(send_status))
                    .await?;
                return Ok((
                    rejection,
                    crate::sdk::transfer_hooks::TransferMeta::default(),
                ));
            }
        }

        // The proposal is the sender's, and it extends the held tip: this
        // device's own precommitment to the same step.
        let our_pre_commitment = {
            let mut manager = self.bilateral_tx_manager.write().await;
            manager
                .prepare_offline_transfer(&counterparty_device_id, operation.clone())
                .await?
        };

        // The sender's genesis is the one its contact pins, not one the wire names.
        let counterparty_genesis_hash = Some(sender_genesis);

        // Track session as PendingUserAction (NOT auto-accepted)
        let commit_signature = {
            let m = self.bilateral_tx_manager.read().await;
            m.sign_commitment(&origin_commitment_hash)?
        };

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
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: None,
            owed_frame: None,
        };

        // The proposal is durable before it is held: one that could not be
        // kept is not taken, and a restart still shows it to the user.
        if let Err(e) = self.persist_session(&session).await {
            self.bilateral_tx_manager
                .write()
                .await
                .consume_pre_commitment(&our_pre_commitment.bilateral_commitment_hash);
            return Err(e);
        }
        self.sessions
            .sessions
            .lock()
            .await
            .insert(origin_commitment_hash, session.clone());
        drop(door);

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
            let sessions = self.sessions.sessions.lock().await;
            let session = sessions.get(&origin_commitment_hash).ok_or_else(|| {
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

            (session.clone(), session.counterparty_device_id)
        };

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

        // The acceptance is durable before its response goes out: the phase,
        // and the challenge the confirm's release must bind.
        let mut accepted = session.clone();
        accepted.phase = BilateralPhase::Accepted;
        accepted.receiver_challenge = Some(receiver_challenge);
        accepted.owed_frame = Some(buffer.clone());
        self.persist_session(&accepted).await?;
        self.sessions
            .sessions
            .lock()
            .await
            .insert(origin_commitment_hash, accepted);

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

    /// The user's rejection of a proposal awaiting this device's decision: a
    /// signed rejection, kept with the session's end before it leaves, as the
    /// answer to the proposal delivered again. Only a proposal still awaiting
    /// its user is rejected: an accepted step may be committing on its
    /// proposer's confirm, and this device's own proposals end by cancellation
    /// ([`Self::cancel_proposal`]).
    pub async fn create_prepare_reject_envelope_with_cleanup(
        &self,
        origin_commitment_hash: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        let session = self
            .sessions
            .sessions
            .lock()
            .await
            .get(&origin_commitment_hash)
            .cloned()
            .ok_or_else(|| {
                DsmError::not_found(
                    format!(
                        "bilateral session {}",
                        bytes_to_base32(&origin_commitment_hash[..8])
                    ),
                    Some("No pending session found for rejection".to_string()),
                )
            })?;
        if session.phase != BilateralPhase::PendingUserAction {
            return Err(DsmError::invalid_operation(format!(
                "a step in {:?} is not a proposal awaiting this device's decision",
                session.phase
            )));
        }
        let counterparty_device_id = session.counterparty_device_id;

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
        let rejection = self
            .signed_rejection(
                origin_commitment_hash,
                reason.clone(),
                Some(sdk_send_status_from_router_status(send_status)),
            )
            .await?;

        let mut rejected = session;
        rejected.phase = BilateralPhase::Rejected;
        rejected.owed_frame = Some(rejection.clone());
        self.persist_session(&rejected).await?;
        let pending_key = rejected
            .local_commitment_hash
            .unwrap_or(origin_commitment_hash);
        self.sessions
            .sessions
            .lock()
            .await
            .insert(origin_commitment_hash, rejected);
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&pending_key);

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
            message: reason,
            sender_ble_address: None,
            failure_reason: Some(
                generated::BilateralFailureReason::FailureReasonRejectedByPeer.into(),
            ),
        });
        self.prune_terminal_sessions_for_counterparty(&counterparty_device_id)
            .await;
        info!(
            "Bilateral proposal {} rejected",
            bytes_to_base32(&origin_commitment_hash[..8])
        );
        Ok(rejection)
    }

    /// A signed rejection of the step `commitment_hash`, as its envelope: the
    /// receiver's refusal of a proposal, or the proposer's cancellation of its
    /// own. A step ends on a rejection only when its rejector signed it.
    async fn signed_rejection(
        &self,
        commitment_hash: [u8; 32],
        reason: String,
        send_status: Option<generated::RelationshipSendStatus>,
    ) -> Result<Vec<u8>, DsmError> {
        let rejector_signature = self
            .bilateral_tx_manager
            .read()
            .await
            .sign_rejection(&commitment_hash, &reason)?;
        let envelope = self
            .create_envelope(generated::envelope::Payload::BilateralPrepareReject(
                generated::BilateralPrepareReject {
                    commitment_hash: Some(generated::Hash32 {
                        v: commitment_hash.to_vec(),
                    }),
                    reason,
                    rejector_device_id: self.device_id.to_vec(),
                    send_status,
                    rejector_signature,
                },
            ))
            .await;
        Ok(envelope.encode_to_vec())
    }

    /// Refuse a proposal while another step is in flight with its sender
    /// ([`dsm::bilateral::offline::PrepareDecision::StepInFlight`]): a signed
    /// rejection, kept as the step's answer before it leaves. The proposal
    /// delivered again — even once the step in flight has ended — is answered
    /// the same way and never taken: its proposer has ended it on the first
    /// rejection, and would never answer an acceptance.
    async fn refuse_while_in_flight(
        &self,
        commitment_hash: [u8; 32],
        counterparty_device_id: [u8; 32],
        counterparty_genesis_hash: [u8; 32],
        operation: Operation,
        sender_ble_address: Option<String>,
        in_flight: [u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let reason = format!(
            "a step with this contact is in flight ({}): one step at a time",
            bytes_to_base32(&in_flight[..8])
        );
        let send_status = sdk_send_status_from_router_status(
            crate::handlers::relationship_status::derive_local_send_status_for_device_id(
                &counterparty_device_id,
            ),
        );
        let rejection = self
            .signed_rejection(commitment_hash, reason.clone(), Some(send_status))
            .await?;
        self.persist_session(&BilateralBleSession {
            commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash: Some(counterparty_genesis_hash),
            operation,
            phase: BilateralPhase::Rejected,
            local_signature: None,
            counterparty_signature: None,
            sender_ble_address: sender_ble_address.clone(),
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: None,
            owed_frame: Some(rejection.clone()),
        })
        .await?;
        // No pruning here: it also sweeps the contact's BLE reassembly
        // chunks, and another step with the contact is in flight.
        self.emit_event(&generated::BilateralEventNotification {
            // Rendered in emit_event, the one boundary all emitters cross.
            display_amount: None,
            event_type: generated::BilateralEventType::BilateralEventRejected.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: None,
            token_id: None,
            status: "step_in_flight".to_string(),
            message: reason,
            sender_ble_address,
            failure_reason: None,
        });
        Ok(rejection)
    }

    /// The proposer ends a proposal before it has confirmed it: until the
    /// confirm, nothing can have committed on either side. The cancellation is
    /// a rejection the proposer signs; it is kept as the answer to the
    /// receiver's next frame for the step, which ends the receiver's side, and
    /// the relationship is free for the next step. A step past its confirm
    /// cannot be cancelled: its receiver may have committed.
    pub async fn cancel_proposal(
        &self,
        commitment_hash: [u8; 32],
        reason: String,
    ) -> Result<Vec<u8>, DsmError> {
        let session = self
            .sessions
            .sessions
            .lock()
            .await
            .get(&commitment_hash)
            .cloned()
            .ok_or_else(|| DsmError::invalid_operation("no proposal with that commitment"))?;
        if !crate::bluetooth::bilateral_session::is_cancellable_proposal_phase(&session.phase) {
            return Err(match session.phase {
                BilateralPhase::ConfirmPending => DsmError::invalid_operation(
                    "a confirmed step cannot be cancelled: its receiver may have committed; it \
                     completes, or is reconciled online",
                ),
                other => DsmError::invalid_operation(format!(
                    "a step in {other:?} is not a proposal this device can cancel"
                )),
            });
        }
        let cancellation = self
            .signed_rejection(commitment_hash, reason.clone(), None)
            .await?;
        let mut cancelled = session;
        cancelled.phase = BilateralPhase::Rejected;
        cancelled.owed_frame = Some(cancellation.clone());
        self.persist_session(&cancelled).await?;
        let counterparty_device_id = cancelled.counterparty_device_id;
        self.sessions
            .sessions
            .lock()
            .await
            .insert(commitment_hash, cancelled);
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&commitment_hash);
        self.emit_event(&generated::BilateralEventNotification {
            display_amount: None,
            event_type: generated::BilateralEventType::BilateralEventRejected.into(),
            counterparty_device_id: counterparty_device_id.to_vec(),
            commitment_hash: commitment_hash.to_vec(),
            transaction_hash: None,
            amount: None,
            token_id: None,
            status: "cancelled".to_string(),
            message: reason,
            sender_ble_address: None,
            failure_reason: None,
        });
        Ok(cancellation)
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

        // A rejection ends only a step with the rejector that has not been
        // confirmed — this device's proposal the rejector refused, or the
        // rejector's proposal it cancelled — and only when the rejector signed
        // it under the key its contact pins. Anything else changes nothing.
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
            // A proposal still awaiting its answer, or — on the receiver — a
            // proposal not yet confirmed. Past the confirm the step may have
            // committed: a rejection then contradicts the rejector's own
            // signatures and ends nothing.
            if !matches!(
                session.phase,
                BilateralPhase::Preparing
                    | BilateralPhase::Prepared
                    | BilateralPhase::PendingUserAction
                    | BilateralPhase::Accepted
            ) {
                return Err(DsmError::invalid_operation(
                    "a rejection ends only a step that has not been confirmed",
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

        self.persist_session(&rejected_session).await?;
        if let Some(session) = self
            .sessions
            .sessions
            .lock()
            .await
            .get_mut(&commitment_hash)
        {
            session.phase = BilateralPhase::Rejected;
        }
        // The step is abandoned: the relationship tip stays where it was.
        let pending_key = rejected_session
            .local_commitment_hash
            .unwrap_or(commitment_hash);
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&pending_key);

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
                    Ok(Some(record)) => match BilateralBleSession::from_record(&record) {
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
        // Core decides on the response from the receiver's pinned identity:
        // its keys, its signature over the commitment, and the challenge it
        // carries. Nothing in the response is taken before it verifies.
        let receiver_contact =
            crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
                .map_err(|e| {
                    DsmError::storage(
                        format!("the receiver's contact: {e}"),
                        None::<std::io::Error>,
                    )
                })?
                .ok_or_else(|| DsmError::relationship("the receiver is not a contact"))?;
        let receiver_genesis: [u8; 32] = receiver_contact
            .genesis_hash
            .as_slice()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation("the receiver's pinned genesis is not 32 bytes")
            })?;
        let acceptance = dsm::bilateral::offline::decide_prepare_response(
            commitment_hash,
            dsm::bilateral::offline::ResponseClaims {
                commitment_hash: prepare_response
                    .commitment_hash
                    .as_ref()
                    .and_then(|h| <[u8; 32]>::try_from(h.v.as_slice()).ok()),
                credentials: dsm::bilateral::offline::PeerCredentials {
                    signing_key: &prepare_response.responder_signing_public_key,
                    kyber_public_key: &prepare_response.responder_kyber_public_key,
                    kyber_binding_sig: &prepare_response.responder_kyber_binding_sig,
                },
                signature: &prepare_response.local_signature,
                receiver_challenge: &prepare_response.receiver_challenge,
            },
            &dsm::bilateral::offline::PinnedPeer {
                device_id: counterparty_device_id,
                genesis: receiver_genesis,
                signing_key: &receiver_contact.public_key,
                kyber_public_key: &receiver_contact.kyber_public_key,
            },
        )?;

        // The acceptance is not written on its own: the confirm built from it
        // commits the session's next durable state, and until then a response
        // delivered again is taken again.
        let accepted = {
            let sessions = self.sessions.sessions.lock().await;
            let session = sessions.get(&commitment_hash).ok_or_else(|| {
                DsmError::invalid_operation("no session found for commitment hash")
            })?;
            // The response delivered again: the confirm it was answered with
            // is owed until the ack, and is the answer again.
            if session.phase == BilateralPhase::ConfirmPending {
                let owed = session
                    .owed()
                    .filter(|frame| frame.kind == OfflineFrameKind::Confirm)
                    .ok_or_else(|| {
                        DsmError::invalid_operation(
                            "a ConfirmPending session holds no confirm to deliver again",
                        )
                    })?;
                return Ok((
                    owed.bytes,
                    crate::sdk::transfer_hooks::TransferMeta::default(),
                ));
            }
            // A response for a proposal this device cancelled is answered
            // with the signed cancellation: it ends the receiver's side.
            if let Some(cancellation) = session.rejection() {
                return Ok((
                    cancellation,
                    crate::sdk::transfer_hooks::TransferMeta::default(),
                ));
            }
            if session.phase != BilateralPhase::Prepared {
                return Err(DsmError::invalid_operation(format!(
                    "a prepare response for a session in {:?}, not awaiting one",
                    session.phase
                )));
            }
            let mut accepted = session.clone();
            accepted.counterparty_signature = Some(acceptance.signature);
            accepted.receiver_challenge = acceptance.receiver_challenge;
            accepted.phase = BilateralPhase::Accepted;
            accepted
        };

        info!("Building bilateral confirm message (3-step protocol, step 3)");
        let (confirm_envelope, confirm_meta) = self.send_bilateral_confirm(accepted).await?;

        Ok((confirm_envelope, confirm_meta))
    }

    /// 3-step protocol step 3 (sender side): build the BilateralConfirmRequest
    /// for the `accepted` session (its σ_B and receiver challenge verified by
    /// `decide_prepare_response`) and return the confirm envelope bytes to be
    /// sent to the receiver.
    ///
    /// The sender does not finalize or settle here: canonical sender mutation
    /// happens only after the receiver's acknowledgment verifies. The confirm's
    /// state is durable before the envelope is returned.
    async fn send_bilateral_confirm(
        &self,
        session: BilateralBleSession,
    ) -> Result<(Vec<u8>, crate::sdk::transfer_hooks::TransferMeta), DsmError> {
        info!("[BILATERAL] send_bilateral_confirm: building confirm (3-step step 3)");
        let commitment_hash = session.commitment_hash;
        let local_sig = session
            .local_signature
            .as_ref()
            .ok_or_else(|| DsmError::invalid_operation("missing local signature (σ_A)"))?
            .clone();

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
        // `finalize_sender_step`. Identical inputs
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
        // must be this advance (its root is checked against the root sent
        // here, and the root commits the entropy). It goes into the
        // relationship tip (already, inside the outcome) and into BOTH receipt
        // hashes here; the receiver recomputes h_{n+1} from the carried value.
        let pre_entropy: [u8; 32] = sim_outcome.transition_entropy();
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
        let ak = self
            .bilateral_tx_manager
            .read()
            .await
            .ak_keypair_for_cert_chain();
        let (receipt_bytes, signed_key) = self.sign_receipt_with_per_step_ek_for_bilateral(
            &ak,
            unsigned_receipt_bytes,
            &session.counterparty_device_id,
            parent_tip_receipt,
            commitment_hash, // bilateral commitment IS the precommit for this step
            BilateralSide::A,
        )?;

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

        // 9. The confirm's state is durable before the confirm goes out, in one
        // transaction: the session in ConfirmPending with everything its commit
        // needs — σ_B, the receiver challenge, its own signed receipt, the root
        // that receipt names, a bearer step's anchor leaf and allocation spend,
        // the step's parent tip, and the confirm itself, owed until the ack —
        // and the EK it signed with, stashed until the
        // ack by compare-and-set on the head it was signed from (§11.1: the
        // Local head moves only in the step's commit). A confirm whose state
        // could not be kept is not sent.
        let mut confirm_pending = session;
        confirm_pending.phase = BilateralPhase::ConfirmPending;
        confirm_pending.stitched_receipt_bytes = Some(confirm_request.stitched_receipt.clone());
        confirm_pending.sent_child_root = Some(sender_smt_root);
        confirm_pending.owed_frame = Some(buffer.clone());
        if let Some(art) = bearer_artifacts.as_ref() {
            confirm_pending.anchor_leaf = Some(art.anchor_leaf.clone());
            // The allocation-spend descriptor (Copy): the commit debits the SAME allocation the
            // sim did — the bundle B is not recoverable from anchor_leaf.
            confirm_pending.offline_spend = offline_spend;
        }
        let durable = confirm_pending.to_record().and_then(|record| {
            let storage =
                |e: anyhow::Error| DsmError::storage(e.to_string(), None::<std::io::Error>);
            let binding = crate::storage::client_db::get_connection().map_err(storage)?;
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn
                .transaction()
                .map_err(|e| DsmError::storage(e.to_string(), None::<std::io::Error>))?;
            crate::storage::client_db::stash_pending_local_head_cas_with_conn(
                &tx,
                &signed_key.rel_key,
                &commitment_hash,
                &signed_key.ek_pk,
                &signed_key.ek_sk,
                &signed_key.at_rest_key,
                signed_key.used_root_ak,
                signed_key.expected_prev.as_deref(),
                signed_key.used_root_ak,
            )
            .map_err(storage)?;
            crate::storage::client_db::store_bilateral_session_with_conn(&tx, &record)
                .map_err(storage)?;
            tx.commit()
                .map_err(|e| DsmError::storage(e.to_string(), None::<std::io::Error>))
        });
        if let Err(e) = durable {
            if bearer_artifacts.is_some() {
                if let Err(cancel) = router.cancel_offline_bearer_release() {
                    return Err(DsmError::storage(
                        format!(
                            "the confirm's state could not be kept ({e}), and the staged \
                             offline-bearer release could not be cancelled: {cancel}"
                        ),
                        None::<std::io::Error>,
                    ));
                }
            }
            return Err(DsmError::storage(
                format!("the confirm's state could not be kept, so it is not sent: {e}"),
                None::<std::io::Error>,
            ));
        }
        self.sessions
            .sessions
            .lock()
            .await
            .insert(commitment_hash, confirm_pending);

        info!(
            "[BILATERAL] send_bilateral_confirm: confirm envelope built ({} bytes), session ConfirmPending",
            buffer.len()
        );
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

        if !self
            .record_commit_ack(commitment_hash, &response.counter_signed_receipt)
            .await?
        {
            return Ok(());
        }
        self.finalize_sender_step(&commitment_hash).await?;
        Ok(())
    }

    /// Take the receiver's acknowledgment of the step `commitment_hash` — its
    /// counter-signed receipt — for a session this device is committing: Core
    /// verifies it, and it is written into the session before the step is
    /// finalized, so a restart finalizes a step whose ack it holds. Answers
    /// `false` for an ack of a step already committed (nothing to do).
    pub(crate) async fn record_commit_ack(
        &self,
        commitment_hash: [u8; 32],
        counter_signed_receipt: &[u8],
    ) -> Result<bool, DsmError> {
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
                return Ok(false);
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

        // Core decides on the ack: it is the receiver's counter-signed receipt,
        // verified against the receiver's pinned identity, the Device Tree
        // commitment kept for it and its EK chain head on this relationship.
        let counterparty_device_id = {
            let sessions = self.sessions.sessions.lock().await;
            sessions
                .get(&commitment_hash)
                .map(|s| s.counterparty_device_id)
        }
        .ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "commit ack for {}: the session ended before the ack was verified; nothing \
                 is finalized",
                bytes_to_base32(&commitment_hash[..8])
            ))
        })?;
        let receiver_contact =
            crate::storage::client_db::get_contact_by_device_id(&counterparty_device_id)
                .map_err(|e| {
                    DsmError::storage(
                        format!("the receiver's contact: {e}"),
                        None::<std::io::Error>,
                    )
                })?
                .ok_or_else(|| DsmError::relationship("the receiver is not a contact"))?;
        let receiver_genesis: [u8; 32] = receiver_contact
            .genesis_hash
            .as_slice()
            .try_into()
            .map_err(|_| {
                DsmError::invalid_operation("the receiver's pinned genesis is not 32 bytes")
            })?;
        let receiver_device_tree =
            crate::storage::client_db::get_contact_device_tree_root(&counterparty_device_id)?
                .ok_or_else(|| {
                    DsmError::invalid_operation(
                        "counter_signed_receipt: no Device Tree commitment is kept for the \
                         receiver",
                    )
                })?;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &counterparty_device_id,
        );
        let receiver_chain_head = crate::storage::client_db::load_cert_chain_head_pubkey(
            &rel_key,
            crate::storage::client_db::CertChainSide::Counterparty,
        )
        .map_err(|e| {
            DsmError::storage(
                format!(
                    "counter_signed_receipt verify: the receiver's cert-chain head is unreadable: {e}"
                ),
                None::<std::io::Error>,
            )
        })?;
        dsm::bilateral::offline::decide_commit_ack(
            Some(commitment_hash),
            counter_signed_receipt,
            dsm::bilateral::offline::ConfirmedStep {
                commitment_hash,
                sender_device_id: self.device_id,
                receiver_device_tree_root: receiver_device_tree,
                receiver_chain_head: receiver_chain_head.as_deref(),
            },
            &dsm::bilateral::offline::PinnedPeer {
                device_id: counterparty_device_id,
                genesis: receiver_genesis,
                signing_key: &receiver_contact.public_key,
                kyber_public_key: &receiver_contact.kyber_public_key,
            },
        )?;

        // The counter-signed receipt is the step's proof: it is kept beside the
        // sender's own receipt and written before the step is finalized.
        let with_receipt = {
            let sessions = self.sessions.sessions.lock().await;
            let mut session = sessions.get(&commitment_hash).cloned().ok_or_else(|| {
                DsmError::invalid_operation(format!(
                    "commit ack for {}: the session ended before the ack was verified; nothing \
                     is finalized",
                    bytes_to_base32(&commitment_hash[..8])
                ))
            })?;
            session.counter_signed_receipt = Some(counter_signed_receipt.to_vec());
            session
        };
        self.persist_session(&with_receipt).await?;
        self.sessions
            .sessions
            .lock()
            .await
            .insert(commitment_hash, with_receipt);
        Ok(true)
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
                    Ok(Some(record)) => match BilateralBleSession::from_record(&record) {
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
                // No session: the step may be one this device already
                // committed, its confirm delivered again because the ack was
                // lost.
                drop(sessions);
                return self
                    .answer_committed_confirm(commitment_hash, &confirm_request)
                    .await;
            }
        };

        if session.phase == BilateralPhase::Committed {
            return self
                .answer_committed_confirm(commitment_hash, &confirm_request)
                .await;
        }
        if session.phase != BilateralPhase::Accepted {
            return Err(DsmError::invalid_operation("session not in accepted phase"));
        }

        // Core decides on the confirm from the sender's pinned identity, the
        // tip this device holds durably, the Device Tree commitment kept for
        // the sender and the sender's EK chain head on this relationship.
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id,
            &session.counterparty_device_id,
        );
        let sender_contact =
            crate::storage::client_db::get_contact_by_device_id(&session.counterparty_device_id)
                .map_err(|e| {
                    DsmError::storage(format!("the sender's contact: {e}"), None::<std::io::Error>)
                })?
                .ok_or_else(|| DsmError::relationship("the sender is not a contact"))?;
        let sender_genesis: [u8; 32] =
            sender_contact
                .genesis_hash
                .as_slice()
                .try_into()
                .map_err(|_| {
                    DsmError::invalid_operation("the sender's pinned genesis is not 32 bytes")
                })?;
        let held_tip = stored_contact_tip(crate::storage::client_db::get_contact_chain_tip(
            &session.counterparty_device_id,
        ))?
        .ok_or_else(|| DsmError::relationship("the sender is not a contact"))?;
        let sender_device_tree = crate::storage::client_db::get_contact_device_tree_root(
            &session.counterparty_device_id,
        )?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "bilateral confirm: no Device Tree commitment is kept for the sender",
            )
        })?;
        let sender_chain_head = crate::storage::client_db::load_cert_chain_head_pubkey(
            &rel_key,
            crate::storage::client_db::CertChainSide::Counterparty,
        )
        .map_err(|e| {
            DsmError::storage(
                format!("bilateral confirm: the sender's cert-chain head is unreadable: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let verified = dsm::bilateral::offline::decide_confirm(
            dsm::bilateral::offline::ConfirmClaims {
                signature: &confirm_request.sender_signature,
                receipt: &confirm_request.stitched_receipt,
                pre_entropy: &confirm_request.pre_entropy,
                successor_tip: confirm_request
                    .shared_chain_tip_new
                    .as_ref()
                    .and_then(|h| <[u8; 32]>::try_from(h.v.as_slice()).ok()),
            },
            dsm::bilateral::offline::AcceptedStep {
                commitment_hash,
                operation: &session.operation,
                held_tip,
                receiver_device_id: self.device_id,
                sender_device_tree_root: sender_device_tree,
                sender_chain_head: sender_chain_head.as_deref(),
            },
            &dsm::bilateral::offline::PinnedPeer {
                device_id: session.counterparty_device_id,
                genesis: sender_genesis,
                signing_key: &sender_contact.public_key,
                kyber_public_key: &sender_contact.kyber_public_key,
            },
        )?;
        let dsm::bilateral::offline::VerifiedConfirm {
            receipt,
            successor_tip: new_chain_tip,
        } = verified;
        // The sender's outbound EK chain has moved to this key; the step's
        // commit mirrors it so the next step chains from it.
        let verified_a_side_ek_pk: Vec<u8> = receipt.ek_pk_a.clone();

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

        // The receiver signs its receipt from the advance that commits: the
        // advance is prepared, its receipt is built from that outcome and
        // counter-signed before the transaction opens, with no other advance
        // in between. Everything the step writes — the credit, the
        // relationship tip, the history with its receipt, both cert-chain
        // heads, the adopted anchor frontier, the EK step objects and the
        // session's end — then commits in one transaction, before any ack.
        let ak = self
            .bilateral_tx_manager
            .read()
            .await
            .ak_keypair_for_cert_chain();
        let device_tree_commitment = local_device_tree_commitment()?;
        let ek_step_set = crate::sdk::economic_admission_flow::ble_ek_step_set_id()?;
        let settlement = crate::handlers::bilateral_settlement::StepSettlement::resolve(
            self.device_id,
            session.counterparty_device_id,
            commitment_hash,
            held_tip,
            session.operation.to_bytes(),
            false,
        )
        .map_err(|e| DsmError::invalid_operation(format!("receiver confirm: {e}")))?;
        let counterparty_device_id = session.counterparty_device_id;
        type SignedReceipt = (
            Vec<u8>,
            SignedStepKey,
            dsm::types::receipt_types::StitchedReceiptV2,
        );
        let signed: std::sync::Mutex<Option<SignedReceipt>> = std::sync::Mutex::new(None);
        let sign_step = |o: &dsm::types::device_state::AdvanceOutcome| -> Result<(), DsmError> {
            let parent_tip = o.smt_proofs.parent_proof.value.ok_or_else(|| {
                DsmError::invalid_operation(
                    "receiver confirm: the advance's relationship path carries no parent tip",
                )
            })?;
            let unsigned_receipt_bytes = crate::sdk::receipts::build_bilateral_receipt_with_smt(
                self.device_id,
                counterparty_device_id,
                parent_tip,
                o.new_chain_state.compute_chain_tip(),
                o.smt_proofs.pre_root,
                o.child_r_a,
                &o.smt_proofs.parent_proof,
                &device_tree_commitment,
                o.transition_entropy(),
            )?;
            // §11.1 receiver counter-sign: B-side per-step EK, cert, signature
            // and Kyber ciphertext on this device's copy of the receipt.
            let (receipt_bytes, signed_key) = self.sign_receipt_with_per_step_ek_for_bilateral(
                &ak,
                unsigned_receipt_bytes,
                &counterparty_device_id,
                parent_tip,
                commitment_hash, // bilateral commitment IS the precommit for this step
                BilateralSide::B,
            )?;
            let receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                &receipt_bytes,
            )?;
            *signed.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((receipt_bytes, signed_key, receipt));
            Ok(())
        };
        let commit_step = |tx: &rusqlite::Transaction<'_>,
                           o: &dsm::types::device_state::AdvanceOutcome|
         -> Result<(), DsmError> {
            let signed = signed.lock().unwrap_or_else(|p| p.into_inner());
            let (receipt_bytes, signed_key, counter_signed) = signed.as_ref().ok_or_else(|| {
                DsmError::invalid_operation(
                    "receiver confirm: the step's receipt was not signed before its commit",
                )
            })?;
            settlement.write_in_tx(tx, o, new_chain_tip, receipt_bytes)?;
            let head_moved = |what: &str,
                              outcome: crate::storage::client_db::CasHeadOutcome|
             -> Result<(), DsmError> {
                match outcome {
                    crate::storage::client_db::CasHeadOutcome::Advanced { .. }
                    | crate::storage::client_db::CasHeadOutcome::GenesisInit => Ok(()),
                    other => Err(DsmError::invalid_operation(format!(
                        "receiver confirm: {what} cert-chain head did not move from the head the \
                         step was verified against: {other:?}"
                    ))),
                }
            };
            let storage = |what: &str, e: anyhow::Error| {
                DsmError::storage(
                    format!("receiver confirm: {what}: {e}"),
                    None::<std::io::Error>,
                )
            };
            head_moved(
                "the sender's",
                crate::storage::client_db::cas_advance_counterparty_cert_chain_head_with_conn(
                    tx,
                    &rel_key,
                    sender_chain_head.as_deref(),
                    &verified_a_side_ek_pk,
                )
                .map_err(|e| storage("the sender's cert-chain head", e))?,
            )?;
            head_moved(
                "this device's",
                crate::storage::client_db::cas_advance_local_cert_chain_head_with_conn(
                    tx,
                    &signed_key.rel_key,
                    signed_key.expected_prev.as_deref(),
                    &signed_key.ek_pk,
                    &signed_key.ek_sk,
                    &signed_key.at_rest_key,
                )
                .map_err(|e| storage("this device's cert-chain head", e))?,
            )?;
            if let Some(adopted) = &adopted_anchor_state {
                crate::storage::client_db::anchor_enrollments::store_accepted_anchor_root_with_conn(
                    tx,
                    &counterparty_device_id,
                    &adopted.next_root,
                    adopted.next_anchor_counter,
                )
                .map_err(|e| storage("the adopted anchor frontier", e))?;
            }
            crate::sdk::economic_admission_flow::record_ble_ek_steps_in_tx(
                tx,
                &ek_step_set,
                &o.new_device_state.root(),
                &rel_key,
                [
                    crate::sdk::economic_admission_flow::EkStep::of_sender(
                        &counterparty_device_id,
                        &receipt,
                    ),
                    crate::sdk::economic_admission_flow::EkStep::of_receiver(
                        &self.device_id,
                        counter_signed,
                    ),
                ],
            )?;
            crate::storage::client_db::delete_bilateral_session_with_conn(tx, &commitment_hash)
                .map_err(|e| storage("the session's end", e))?;
            Ok(())
        };
        router
            .execute_on_relationship_for_bilateral(
                rel_key,
                session.counterparty_device_id,
                session.operation.clone(),
                &receiver_deltas,
                None,
                None,
                Some(&sign_step),
                &commit_step,
            )
            .map_err(|e| {
                DsmError::state_machine(format!("receiver confirm advance failed: {e}"))
            })?;
        let (counter_signed_receipt, _, _) = signed
            .into_inner()
            .unwrap_or_else(|p| p.into_inner())
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "receiver confirm: the committed step holds no signed receipt",
                )
            })?;

        // The committed tip, in the manager's view of the relationship.
        self.bilateral_tx_manager
            .write()
            .await
            .advance_chain_tip(&session.counterparty_device_id, new_chain_tip);
        // Transaction hash for display / events = symmetric successor tip.
        let transaction_hash = new_chain_tip;
        let pending_key = session.local_commitment_hash.unwrap_or(commitment_hash);
        let (amount_opt, token_id_opt) = match &self.settlement_delegate {
            Some(d) => d.operation_metadata(&session.operation.to_bytes()),
            None => (None, None),
        };
        if let Some(router) = crate::bridge::app_router() {
            router.sync_balance_cache();
        }
        self.bilateral_tx_manager
            .write()
            .await
            .consume_pre_commitment(&pending_key);
        if let Some(session) = self
            .sessions
            .sessions
            .lock()
            .await
            .get_mut(&commitment_hash)
        {
            session.phase = BilateralPhase::Committed;
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

        let ack_envelope = self
            .create_envelope(generated::envelope::Payload::BilateralCommitResponse(
                generated::BilateralCommitResponse {
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

    /// A confirm for a step this device already committed as its receiver —
    /// the session ended in that commit — delivered again because its ack was
    /// lost. Core decides from the step's pinned sender's signature
    /// (`decide_committed_confirm`); the answer is the ack the step committed,
    /// rebuilt from the receipt in this device's history row.
    async fn answer_committed_confirm(
        &self,
        commitment_hash: [u8; 32],
        confirm: &generated::BilateralConfirmRequest,
    ) -> Result<Vec<u8>, DsmError> {
        let storage = |what: &str, e: anyhow::Error| {
            DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
        };
        let row = crate::storage::client_db::get_transaction(&bytes_to_base32(&commitment_hash))
            .map_err(|e| storage("the step's history row", e))?
            .ok_or_else(|| DsmError::invalid_operation("session not found"))?;
        if row.tx_type != "bilateral_offline" || row.to_device != bytes_to_base32(&self.device_id) {
            return Err(DsmError::invalid_operation(
                "session not found: the step is not one this device received offline",
            ));
        }
        let sender: [u8; 32] = crate::util::text_id::decode_base32_crockford(&row.from_device)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| {
                DsmError::invalid_operation("the step's history names no 32-byte sender")
            })?;
        let contact = crate::storage::client_db::get_contact_by_device_id(&sender)
            .map_err(|e| storage("the sender's contact", e))?
            .ok_or_else(|| DsmError::relationship("the step's sender is not a contact"))?;
        let genesis: [u8; 32] = contact.genesis_hash.as_slice().try_into().map_err(|_| {
            DsmError::invalid_operation("the sender's pinned genesis is not 32 bytes")
        })?;
        dsm::bilateral::offline::decide_committed_confirm(
            &confirm.sender_signature,
            &commitment_hash,
            &dsm::bilateral::offline::PinnedPeer {
                device_id: sender,
                genesis,
                signing_key: &contact.public_key,
                kyber_public_key: &contact.kyber_public_key,
            },
        )?;
        let counter_signed_receipt = row.proof_data.ok_or_else(|| {
            DsmError::invalid_operation("the committed step's history row holds no receipt")
        })?;
        let ack = self
            .create_envelope(generated::envelope::Payload::BilateralCommitResponse(
                generated::BilateralCommitResponse {
                    commitment_hash: Some(generated::Hash32 {
                        v: commitment_hash.to_vec(),
                    }),
                    counter_signed_receipt,
                },
            ))
            .await;
        Ok(ack.encode_to_vec())
    }

    /// Finalize the sender's side of the step `commitment_hash` once its ack
    /// verified: the canonical advance, the settlement and the session's end.
    /// Answers the transfer it committed, or why it did not: a step that cannot
    /// be finalized yet stays awaiting its commit; one refused fails durably
    /// (see `fail_sender_commit`).
    pub async fn finalize_sender_step(
        &self,
        commitment_hash: &[u8; 32],
    ) -> Result<crate::sdk::transfer_hooks::TransferMeta, DsmError> {
        info!("Marking session committed and finalizing sender transaction");

        // Get session info before locking manager
        let (
            counterparty_device_id,
            counterparty_sig,
            session_operation,
            own_receipt,
            counter_signed_receipt,
            session_anchor_leaf,
            session_sent_child_root,
            session_offline_spend,
        ) = {
            let sessions = self.sessions.sessions.lock().await;
            let sess = match sessions.get(commitment_hash) {
                Some(s) => s,
                None => {
                    return Err(DsmError::invalid_operation(
                        "no session is committing this step",
                    ))
                }
            };

            let sig = match &sess.counterparty_signature {
                Some(s) => s.clone(),
                None => {
                    return Err(DsmError::invalid_operation(
                        "the session holds no counterparty acceptance",
                    ))
                }
            };
            // The receiver's counter-signed receipt (kept from the verified
            // ack) is this step's proof, and the sender's own receipt carries
            // its EK step; the session row persists both. A session without
            // them cannot archive the step, so nothing commits — no receipt is
            // rebuilt unsigned in its place, and re-signing would mint an EK
            // the receiver never verified.
            let (Some(own), Some(counter)) =
                (&sess.stitched_receipt_bytes, &sess.counter_signed_receipt)
            else {
                return Err(DsmError::invalid_operation(
                    "the session holds no signed receipts to commit",
                ));
            };

            (
                sess.counterparty_device_id,
                sig,
                sess.operation.clone(),
                own.clone(),
                counter.clone(),
                sess.anchor_leaf.clone(),
                sess.sent_child_root,
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
                Err(e) => return Err(e),
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
                return Err(DsmError::invalid_operation(
                    "a Transfer session carries no allocation-spend descriptor: bearer value \
                     never draws from the online balance",
                ));
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
                    return Err(self
                        .fail_sender_commit(
                            commitment_hash,
                            &counterparty_device_id,
                            &format!("prepare_bilateral_advance refused: {prepare_err}"),
                            event_amount_opt,
                            event_token_id_opt,
                        )
                        .await);
                }
            }
        };

        // Phase 2: commit via canonical advance chokepoint
        // (§2.2 Per-Device SMT, §4.3 acceptance, §8 balance binding).
        let router = crate::bridge::app_router().ok_or_else(|| {
            DsmError::invalid_operation(
                "the app router is not installed: the step stays awaiting its commit",
            )
        })?;

        // The receipt the receiver verified names the confirm-time simulated
        // post-root, and the receiver built h_{n+1} from that simulation's
        // entropy. The commit must be that advance (both-or-neither), and it is
        // checked inside the commit, against the advance that commits: the
        // committed root is the sent root. The root commits the successor
        // leaf, which commits the entropy, so the one entropy of the
        // transition (§39.3) is the value the receiver accepted. A session
        // with no sent root never built a confirm and cannot commit.
        let Some(sent_child_root) = session_sent_child_root else {
            return Err(self
                .fail_sender_commit(
                    commitment_hash,
                    &counterparty_device_id,
                    "the session carries no confirm-time root",
                    event_amount_opt,
                    event_token_id_opt,
                )
                .await);
        };
        // The step's settlement is resolved now and written in the advance's
        // transaction: the debit, the relationship tip (moved from the step's
        // parent to the successor both parties derive from the advance's one
        // transition entropy, bound to this commitment), the projection and the
        // history commit together or not at all.
        let settlement = match crate::handlers::bilateral_settlement::StepSettlement::resolve(
            self.device_id,
            counterparty_device_id,
            *commitment_hash,
            prepared.parent_tip,
            op_bytes.clone(),
            true,
        ) {
            Ok(s) => s,
            Err(e) => {
                return Err(self
                    .fail_sender_commit(
                        commitment_hash,
                        &counterparty_device_id,
                        &format!("the step's settlement cannot be resolved: {e}"),
                        event_amount_opt,
                        event_token_id_opt,
                    )
                    .await);
            }
        };
        // Everything else the step writes commits in the same transaction:
        // this device's EK chain head (the EK stashed at confirm-build), the
        // receiver's EK chain head (the key its verified ack carries, moved
        // from the head the ack was verified against), both signers' EK step
        // objects (this device's from its own receipt, the receiver's from the
        // ack) and the session's end.
        let receipts = (|| -> Result<_, DsmError> {
            Ok((
                dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                    &own_receipt,
                )?,
                dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                    &counter_signed_receipt,
                )?,
            ))
        })();
        let (own, counter_signed) = match receipts {
            Ok(receipts) => receipts,
            Err(e) => {
                return Err(self
                    .fail_sender_commit(
                        commitment_hash,
                        &counterparty_device_id,
                        &format!("the step's receipts do not decode: {e}"),
                        event_amount_opt,
                        event_token_id_opt,
                    )
                    .await);
            }
        };
        let prepared_inputs = (|| -> Result<_, DsmError> {
            let receiver_chain_head = crate::storage::client_db::load_cert_chain_head_pubkey(
                &prepared.rel_key,
                crate::storage::client_db::CertChainSide::Counterparty,
            )
            .map_err(|e| {
                DsmError::storage(
                    format!("the receiver's cert-chain head is unreadable: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            Ok((
                receiver_chain_head,
                crate::sdk::economic_admission_flow::ble_ek_step_set_id()?,
            ))
        })();
        let (receiver_chain_head, ek_step_set) = match prepared_inputs {
            Ok(v) => v,
            Err(e) => {
                return Err(self
                    .fail_sender_commit(
                        commitment_hash,
                        &counterparty_device_id,
                        &format!("the step's commit inputs are unreadable: {e}"),
                        event_amount_opt,
                        event_token_id_opt,
                    )
                    .await);
            }
        };
        let parent_tip = prepared.parent_tip;
        let rel_key = prepared.rel_key;
        let local_device_id = self.device_id;
        let settle = |tx: &rusqlite::Transaction<'_>,
                      o: &dsm::types::device_state::AdvanceOutcome|
         -> Result<(), DsmError> {
            if o.child_r_a != sent_child_root {
                return Err(DsmError::invalid_operation(format!(
                    "both-or-neither violation: the committed root {} is not the root {} the \
                     receiver verified",
                    bytes_to_base32(&o.child_r_a[..8]),
                    bytes_to_base32(&sent_child_root[..8]),
                )));
            }
            let entropy = o.transition_entropy();
            let sigma = compute_precommit(&parent_tip, settlement.operation_bytes(), &entropy);
            let child =
                compute_successor_tip(&parent_tip, settlement.operation_bytes(), &entropy, &sigma);
            settlement.write_in_tx(tx, o, child, &counter_signed_receipt)?;
            let storage = |what: &str, e: anyhow::Error| {
                DsmError::storage(
                    format!("sender commit: {what}: {e}"),
                    None::<std::io::Error>,
                )
            };
            if crate::storage::client_db::promote_pending_local_head_with_conn(
                tx,
                &rel_key,
                commitment_hash,
            )
            .map_err(|e| storage("this device's cert-chain head", e))?
            .is_none()
            {
                return Err(DsmError::invalid_operation(
                    "sender commit: no EK was stashed for this step at confirm-build",
                ));
            }
            match crate::storage::client_db::cas_advance_counterparty_cert_chain_head_with_conn(
                tx,
                &rel_key,
                receiver_chain_head.as_deref(),
                &counter_signed.ek_pk_b,
            )
            .map_err(|e| storage("the receiver's cert-chain head", e))?
            {
                crate::storage::client_db::CasHeadOutcome::Advanced { .. }
                | crate::storage::client_db::CasHeadOutcome::GenesisInit => {}
                other => {
                    return Err(DsmError::invalid_operation(format!(
                        "sender commit: the receiver's cert-chain head did not move from the \
                         head its ack was verified against: {other:?}"
                    )))
                }
            }
            crate::sdk::economic_admission_flow::record_ble_ek_steps_in_tx(
                tx,
                &ek_step_set,
                &o.new_device_state.root(),
                &rel_key,
                [
                    crate::sdk::economic_admission_flow::EkStep::of_sender(&local_device_id, &own),
                    crate::sdk::economic_admission_flow::EkStep::of_receiver(
                        &counterparty_device_id,
                        &counter_signed,
                    ),
                ],
            )?;
            crate::storage::client_db::delete_bilateral_session_with_conn(tx, commitment_hash)
                .map_err(|e| storage("the session's end", e))
        };
        let outcome = match router.execute_on_relationship_for_bilateral(
            prepared.rel_key,
            prepared.counterparty_devid,
            prepared.operation.clone(),
            &prepared.deltas,
            prepared.anchor_leaf.clone(), // bearer: commit the same fused-anchor leaf as the sim proofs
            // Bearer→allocation: the SAME allocation debit the confirm-build sim used
            // (`prepared.offline_spend`, Copy) — `prepared.deltas` is empty for a bearer transfer,
            // so the value is drawn from the offline-cash allocation, not the online balance, and the
            // committed sender root byte-matches the sent sim root.
            prepared.offline_spend,
            None,
            &settle,
        ) {
            Ok(o) => o,
            Err(advance_err) => {
                return Err(self
                    .fail_sender_commit(
                        commitment_hash,
                        &counterparty_device_id,
                        &format!("the step's commit refused: {advance_err}"),
                        event_amount_opt,
                        event_token_id_opt,
                    )
                    .await);
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
        // advance, whose root the commit held to the root the receiver
        // verified — so it is the value the receiver accepted in the confirm.
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

        // The transfer the step settled, for the post-transfer hooks.
        Ok(settlement.transfer_meta())
    }

    /// A sender commit that did not pass its checks. Nothing advances,
    /// nothing settles and no tip is written: the session fails durably and
    /// the relationship is held for online reconciliation — one write —
    /// because the receiver may already have committed its side. Answers the
    /// refusal; if the failure cannot be recorded, that is the answer instead,
    /// and the step stays with its ack, to be finalized again.
    async fn fail_sender_commit(
        &self,
        commitment_hash: &[u8; 32],
        counterparty_device_id: &[u8; 32],
        reason: &str,
        event_amount_opt: Option<u64>,
        event_token_id_opt: Option<String>,
    ) -> DsmError {
        error!("[BILATERAL] sender commit refused, nothing settled: {reason}");
        if let Err(e) = self
            .fail_session(commitment_hash, Some(counterparty_device_id))
            .await
        {
            return e;
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
        DsmError::invalid_operation(format!("sender commit refused: {reason}"))
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

    /// The frames this device owes `counterparty`: for each step in flight
    /// with it, the frame its phase owes (see [`BilateralBleSession::owed`]).
    /// A returning link delivers them; a lost link fails nothing.
    pub async fn frames_owed_to(&self, counterparty: &[u8; 32]) -> Vec<OwedFrame> {
        self.sessions
            .sessions
            .lock()
            .await
            .values()
            .filter(|session| &session.counterparty_device_id == counterparty)
            .filter_map(BilateralBleSession::owed)
            .collect()
    }

    /// Test helper: insert a fully constructed session (bypassing normal flow).
    #[cfg(test)]
    pub(crate) async fn test_insert_session(&self, session: BilateralBleSession) {
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
            sender_signature: vec![],
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
            .sign(&dsm::bilateral::identity_binding::binding_digest(
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
            sender_signature: sender_keys
                .sign(
                    &dsm::core::bilateral_transaction_manager::bilateral_sign_message(
                        &[0x86u8; 32],
                    ),
                )
                .expect("sigma_A"),
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
    /// and confirmed changes nothing. MUTATION CONTROL: skipping the signature check lets the
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
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: None,
            owed_frame: None,
        };
        let pending = [0xA6u8; 32];
        let answered = [0xA7u8; 32];
        handler
            .test_insert_session(session(pending, BilateralPhase::Prepared))
            .await;
        // Answered: the proposer confirmed it (its receiver may have committed).
        handler
            .test_insert_session(session(answered, BilateralPhase::ConfirmPending))
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
            Some(BilateralPhase::ConfirmPending)
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
                stitched_receipt_bytes: None,
                counter_signed_receipt: None,
                receiver_challenge: None,
                anchor_leaf: None,
                sent_child_root: None,
                offline_spend: None,
                parent_tip: None,
                owed_frame: None,
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

    /// One step at a time per relationship, and time does not end a step: a
    /// new prepare is refused while one is in flight, however long ago it
    /// began, and the step in flight keeps its precommitment.
    /// MUTATION CONTROL: superseding an in-flight session lets the prepare
    /// through and turns this red.
    #[tokio::test]
    #[serial]
    async fn a_step_in_flight_blocks_the_next_however_old() {
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
            "the step in flight holds its precommitment"
        );

        // The step in flight is durable, as every step is before it is held.
        let in_flight = BilateralBleSession {
            commitment_hash: [91u8; 32],
            local_commitment_hash: Some(local_pending_hash),
            counterparty_device_id,
            counterparty_genesis_hash: Some(counterparty_genesis),
            operation: stale_op,
            phase: BilateralPhase::PendingUserAction,
            local_signature: None,
            counterparty_signature: None,
            sender_ble_address: None,
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: None,
            owed_frame: None,
        };
        store_bilateral_session(&in_flight.to_record().expect("the row")).expect("persist");
        handler.test_insert_session(in_flight).await;

        let refused = handler
            .prepare_bilateral_transaction(counterparty_device_id, next_op)
            .await
            .expect_err("a step in flight blocks the next");
        assert!(
            refused.to_string().contains("in progress"),
            "unexpected refusal: {refused}"
        );
        assert!(
            bilateral_manager
                .read()
                .await
                .has_pending_commitment(&local_pending_hash),
            "the step in flight keeps its precommitment"
        );
    }

    /// A sender step in `ConfirmPending`, persisted, whose precommitment is
    /// not pending: the commit's prepare refuses it before its receipts are
    /// read.
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
            stitched_receipt_bytes: Some(vec![4u8; 8]),
            counter_signed_receipt: Some(vec![4u8; 8]),
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: Some(dsm::types::device_state::OfflineSpend {
                anchor_bundle_b: [5u8; 32],
                asset: [0x0Fu8; 32],
                amount: 1,
            }),
            parent_tip: Some(tip),
            owed_frame: None,
        };
        handler
            .persist_session(&session)
            .await
            .expect("persist the session");
        handler.test_insert_session(session).await;
    }

    /// A refused sender commit is recorded — the failed phase and the
    /// relationship's hold for reconcile, one write — or the failure to record
    /// it is the answer and nothing changes: the step stays ConfirmPending, in
    /// memory and in storage, to be finalized again. Here the contact row is
    /// gone, so the hold cannot be written.
    /// MUTATION CONTROL: writing the failed phase without the hold lets the
    /// step fail with no hold and turns this red.
    #[tokio::test]
    #[serial]
    async fn a_refusal_that_cannot_be_recorded_changes_nothing() {
        init_test_db();
        let counterparty = [0x63u8; 32];
        let tip = [0x70u8; 32];
        let commitment = [0x6Cu8; 32];
        let (_mgr, handler) = make_test_handler([0x61u8; 32], [0x62u8; 32], b"sender-unrecorded");
        sender_step_whose_prepare_refuses(&handler, counterparty, tip, commitment).await;
        {
            let binding = crate::storage::client_db::get_connection().expect("the database");
            let conn = binding.lock().expect("its lock");
            conn.execute(
                "DELETE FROM contacts WHERE device_id = ?1",
                rusqlite::params![counterparty.to_vec()],
            )
            .expect("drop the contact row");
        }

        let unrecorded = handler
            .finalize_sender_step(&commitment)
            .await
            .expect_err("the step is not finalized");
        assert!(
            unrecorded.to_string().contains("could not be recorded"),
            "a refusal that was not recorded answered as recorded: {unrecorded}"
        );
        let row = crate::storage::client_db::get_bilateral_session(&commitment)
            .expect("read the session")
            .expect("the session row");
        assert_eq!(
            row.phase, "confirm_pending",
            "the step failed without its relationship being held"
        );
        assert_eq!(
            handler.get_session_status(&commitment).await,
            Some(BilateralPhase::ConfirmPending),
            "the step left memory"
        );
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
            handler.finalize_sender_step(&commitment).await.is_err(),
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
        assert!(handler.finalize_sender_step(&failed).await.is_err());
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

    fn session_row(commitment: u8, counterparty: [u8; 32], phase: &str) -> BilateralSessionRecord {
        BilateralSessionRecord {
            commitment_hash: vec![commitment; 32],
            counterparty_device_id: counterparty.to_vec(),
            counterparty_genesis_hash: Some(vec![0xB1; 32]),
            operation_bytes: crate::storage::client_db::serialize_operation(&Operation::Noop),
            phase: phase.to_string(),
            local_signature: Some(vec![0xC1; 64]),
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

    /// A restart fails nothing it can take up: a receiver's proposal awaiting
    /// its user is held again as it was. A sender row that cannot be held
    /// again — here it names no parent tip, so its precommitment cannot be
    /// checked against its commitment — fails. A terminal row stays as it is,
    /// and a row that does not decode is left where it is, not taken up.
    /// MUTATION CONTROL: failing every in-flight row on restart (the policy
    /// this replaced) turns this red.
    #[tokio::test]
    #[serial]
    async fn a_restart_fails_nothing_it_can_take_up() {
        init_test_db();

        let (_bilateral_manager, handler) =
            make_test_handler([11u8; 32], [12u8; 32], b"restore-sessions");
        let counterparty_device_id = [13u8; 32];

        let proposal = session_row(0xA1, counterparty_device_id, "pending_user_action");
        crate::storage::client_db::store_bilateral_session(&proposal).expect("store proposal");
        let unanchored = session_row(0xA3, counterparty_device_id, "prepared");
        crate::storage::client_db::store_bilateral_session(&unanchored).expect("store sender row");
        let terminal = session_row(0xA2, counterparty_device_id, "failed");
        crate::storage::client_db::store_bilateral_session(&terminal).expect("store terminal");
        let malformed_commitment = [0xDE_u8; 31];
        {
            let conn = crate::storage::client_db::get_connection().expect("db connection");
            let conn = conn.lock().expect("db lock");
            conn.execute(
                "INSERT INTO bilateral_sessions(
                    commitment_hash, counterparty_device_id, operation_bytes, phase
                 ) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    malformed_commitment.to_vec(),
                    counterparty_device_id.to_vec(),
                    vec![0x01_u8],
                    "prepared",
                ],
            )
            .expect("insert malformed row");
        }

        let restored = handler
            .restore_sessions_from_storage()
            .await
            .expect("restore sessions");
        assert_eq!(restored, 1, "the proposal is taken up again");
        assert_eq!(
            handler.get_session_status(&[0xA1; 32]).await,
            Some(BilateralPhase::PendingUserAction)
        );
        let phase_of = |commitment: &[u8]| {
            crate::storage::client_db::get_bilateral_session(commitment)
                .expect("read")
                .expect("the row is kept")
                .phase
        };
        assert_eq!(phase_of(&[0xA1; 32]), "pending_user_action");
        assert_eq!(phase_of(&[0xA3; 32]), "failed");
        assert_eq!(phase_of(&[0xA2; 32]), "failed");
        assert_eq!(phase_of(&malformed_commitment), "prepared");
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
