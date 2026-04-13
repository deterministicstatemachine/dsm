//! Bilateral BLE session types and session store.
//!
//! This module owns the core types for the 3-phase bilateral protocol
//! (`BilateralBleSession`, `BilateralPhase`, `BilateralSettlementContext`,
//! `BilateralSettlementDelegate`) and the [`SessionStore`] that manages
//! the in-memory session map plus SQLite persistence.
//!
//! The types are transport-layer-agnostic — no coin logic, no balance
//! checks, no cross-SDK flag reads.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::State;
use log::{info, warn};
use tokio::sync::Mutex;

use crate::storage::client_db::{
    delete_bilateral_session, deserialize_operation, get_all_bilateral_sessions,
    serialize_operation, store_bilateral_session, BilateralSessionRecord,
};
use crate::util::text_id::encode_base32_crockford;

// ---------------------------------------------------------------------------
// Transport–application separation boundary
// ---------------------------------------------------------------------------

/// Context passed to [`BilateralSettlementDelegate::settle`] when the BLE
/// protocol has cryptographically completed a bilateral transfer.
///
/// The transport layer never inspects token-specific fields directly.  All
/// business decisions (balance debit/credit, token type, transaction history)
/// are delegated to the application layer via this type.
#[derive(Debug)]
pub struct BilateralSettlementContext {
    /// Local device identifier.
    pub local_device_id: [u8; 32],
    /// Remote peer's device identifier.
    pub counterparty_device_id: [u8; 32],
    /// Canonical commitment hash that uniquely identifies this session.
    pub commitment_hash: [u8; 32],
    /// Transaction hash produced by the state-machine finalization step.
    pub transaction_hash: [u8; 32],
    /// Serialised [`dsm::types::operations::Operation`] bytes.
    /// The delegate MUST parse this to determine token type, amount, and direction.
    pub operation_bytes: Vec<u8>,
    /// Optional serialised cryptographic receipt (proof data).
    pub proof_data: Option<Vec<u8>>,
    /// `true` when the local device is the sender of the transfer.
    pub is_sender: bool,
    /// Transaction type label stored in the history record
    /// (e.g. `"bilateral_offline"`, `"bilateral_offline_recovered"`).
    pub tx_type: &'static str,
    /// New bilateral chain tip required for the receiver-side atomic persistence
    /// boundary.  Set to `[0u8; 32]` on sender paths where it is not needed.
    pub new_chain_tip: [u8; 32],
    /// Canonical post-protocol state transition, when the caller has one.
    ///
    /// The application layer may merge token-balance settlement into this state
    /// so the archived BCR snapshot reflects the completed wallet settlement.
    pub canonical_state: Option<State>,
}

/// Result returned by [`BilateralSettlementDelegate::settle`].
#[derive(Debug, Default)]
pub struct BilateralSettlementOutcome {
    /// Transfer metadata used by frontend hooks and notifications.
    pub transfer_meta: crate::sdk::transfer_hooks::TransferMeta,
    /// Canonical state snapshot to archive after settlement, when available.
    pub canonical_state: Option<State>,
}

/// Application-layer callback installed on [`BilateralBleHandler`](super::BilateralBleHandler).
///
/// Implementors live **outside** the `bluetooth` module so that the BLE
/// transport layer stays completely coin-agnostic.  The canonical
/// implementation is
/// [`DefaultBilateralSettlementDelegate`](crate::handlers::bilateral_settlement::DefaultBilateralSettlementDelegate).
pub trait BilateralSettlementDelegate: Send + Sync {
    /// Extract display metadata from raw operation bytes.
    ///
    /// Returns `(amount, token_id)`.  Both values may be `None` for
    /// non-transfer operations.  Used to populate event notification fields;
    /// must not mutate any state.
    fn operation_metadata(&self, operation_bytes: &[u8]) -> (Option<u64>, Option<String>);

    /// Apply token-specific settlement after a successful protocol run.
    ///
    /// Called once per completed bilateral transfer.  The delegate is
    /// responsible for updating balances and persisting transaction history.
    /// Returns [`TransferMeta`](crate::sdk::transfer_hooks::TransferMeta) for
    /// upstream hooks, or an error string if persistence fails.
    fn settle(&self, ctx: BilateralSettlementContext)
        -> Result<BilateralSettlementOutcome, String>;
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

/// Session state for tracking bilateral transaction flow over BLE
#[derive(Debug, Clone)]
pub struct BilateralBleSession {
    /// Canonical commitment hash (origin op_id). This is the only lookup key.
    pub commitment_hash: [u8; 32],
    /// Local precommitment hash (receiver-only). Used internally for pending-commitment cleanup.
    pub local_commitment_hash: Option<[u8; 32]>,
    pub counterparty_device_id: [u8; 32],
    pub counterparty_genesis_hash: Option<[u8; 32]>,
    pub operation: Operation,
    pub phase: BilateralPhase,
    pub local_signature: Option<Vec<u8>>,
    pub counterparty_signature: Option<Vec<u8>>,
    pub created_at_ticks: u64,
    pub expires_at_ticks: u64,
    /// BLE MAC address of the sender (for response routing)
    pub sender_ble_address: Option<String>,
    /// Wall-clock creation time for staleness detection (in-memory only, not persisted)
    pub created_at_wall: Instant,
    /// Pre-generated entropy for sender finalize (sender-only).
    /// Stored during commit construction so finalize reuses the same entropy,
    /// ensuring the actual post-finalize tip matches the pre-computed
    /// `shared_chain_tip_new` sent in the BilateralConfirmRequest.
    pub pre_finalize_entropy: Option<[u8; 32]>,
    /// Stitched receipt bytes built during `send_bilateral_confirm` (sender-only).
    /// Cached here so `mark_sender_committed_with_post_state_hash` can persist
    /// the same verifiable receipt instead of building a degraded one after the
    /// Per-Device SMT has already been mutated.
    pub stitched_receipt_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BilateralPhase {
    Preparing,         // Creating pre-commitment
    Prepared,          // Pre-commitment sent, awaiting accept/reject
    PendingUserAction, // Received proposal, awaiting local user accept/reject
    Accepted,          // Counterparty accepted, ready to commit
    Rejected,          // Counterparty rejected
    ConfirmPending,    // Confirm sent; awaiting receiver acknowledgment before sender finalize
    Committed,         // Transaction finalized on both sides after receiver acknowledgment
    Failed,            // Error occurred
}

/// Event callback for bilateral transaction notifications
pub type BilateralEventCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Maximum terminal sessions (Committed/Rejected/Failed) to keep per counterparty.
pub const MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY: usize = 25;

#[inline]
pub fn is_inflight_phase(phase: &BilateralPhase) -> bool {
    matches!(
        phase,
        BilateralPhase::Preparing
            | BilateralPhase::Prepared
            | BilateralPhase::PendingUserAction
            | BilateralPhase::Accepted
            | BilateralPhase::ConfirmPending
    )
}

/// Map phase to a persistence-safe string tag.
pub fn phase_to_str(phase: &BilateralPhase) -> &'static str {
    match phase {
        BilateralPhase::Preparing => "preparing",
        BilateralPhase::Prepared => "prepared",
        BilateralPhase::PendingUserAction => "pending_user_action",
        BilateralPhase::Accepted => "accepted",
        BilateralPhase::Rejected => "rejected",
        BilateralPhase::ConfirmPending => "confirm_pending",
        BilateralPhase::Committed => "committed",
        BilateralPhase::Failed => "failed",
    }
}

/// Parse a phase string tag back to the enum.
pub fn phase_from_str(s: &str) -> BilateralPhase {
    match s {
        "preparing" => BilateralPhase::Preparing,
        "prepared" => BilateralPhase::Prepared,
        "pending_user_action" => BilateralPhase::PendingUserAction,
        "accepted" => BilateralPhase::Accepted,
        "rejected" => BilateralPhase::Rejected,
        "confirm_pending" => BilateralPhase::ConfirmPending,
        "committed" => BilateralPhase::Committed,
        _ => BilateralPhase::Failed,
    }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// Thread-safe in-memory session map with SQLite persistence.
///
/// Wraps `Arc<Mutex<HashMap<[u8;32], BilateralBleSession>>>` and provides
/// CRUD, persistence, cleanup, and recovery identification methods.
/// The handler delegates all session bookkeeping here; recovery *finalization*
/// (which needs the `BilateralTransactionManager`) stays in the handler.
pub struct SessionStore {
    /// Direct access during migration from raw `active_sessions` field.
    /// Prefer higher-level SessionStore methods where possible.
    pub(crate) sessions: Arc<Mutex<HashMap<[u8; 32], BilateralBleSession>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // -- Basic CRUD ----------------------------------------------------------

    pub async fn insert(&self, session: BilateralBleSession) {
        let key = session.commitment_hash;
        self.sessions.lock().await.insert(key, session);
    }

    pub async fn get(&self, commitment_hash: &[u8; 32]) -> Option<BilateralBleSession> {
        self.sessions.lock().await.get(commitment_hash).cloned()
    }

    pub async fn remove(&self, commitment_hash: &[u8; 32]) -> Option<BilateralBleSession> {
        self.sessions.lock().await.remove(commitment_hash)
    }

    pub async fn contains(&self, commitment_hash: &[u8; 32]) -> bool {
        self.sessions.lock().await.contains_key(commitment_hash)
    }

    pub async fn get_phase(&self, commitment_hash: &[u8; 32]) -> Option<BilateralPhase> {
        self.sessions
            .lock()
            .await
            .get(commitment_hash)
            .map(|s| s.phase.clone())
    }

    pub async fn len(&self) -> usize {
        self.sessions.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.sessions.lock().await.is_empty()
    }

    /// Run a closure with mutable access to the session map.
    /// Use sparingly — prefer dedicated methods.
    pub async fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<[u8; 32], BilateralBleSession>) -> R,
    {
        let mut guard = self.sessions.lock().await;
        f(&mut guard)
    }

    // -- Persistence ---------------------------------------------------------

    /// Serialize a session to SQLite.
    pub async fn persist_session(&self, session: &BilateralBleSession) -> Result<(), DsmError> {
        let record = BilateralSessionRecord {
            commitment_hash: session.commitment_hash.to_vec(),
            counterparty_device_id: session.counterparty_device_id.to_vec(),
            counterparty_genesis_hash: session.counterparty_genesis_hash.map(|h| h.to_vec()),
            operation_bytes: serialize_operation(&session.operation),
            phase: phase_to_str(&session.phase).to_string(),
            local_signature: session.local_signature.clone(),
            counterparty_signature: session.counterparty_signature.clone(),
            created_at_step: session.created_at_ticks,
            sender_ble_address: session.sender_ble_address.clone(),
        };
        store_bilateral_session(&record).map_err(|e| {
            DsmError::invalid_operation(format!("Failed to persist bilateral session: {e}"))
        })
    }

    // -- Collision detection -------------------------------------------------

    /// Find any in-flight session with the given counterparty.
    /// Returns `(commitment_hash, phase, wall-clock creation time)`.
    pub async fn detect_inflight_counterparty_session(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> Option<([u8; 32], BilateralPhase, Instant)> {
        let sessions = self.sessions.lock().await;
        for (hash, session) in sessions.iter() {
            if session.counterparty_device_id == *counterparty_device_id
                && is_inflight_phase(&session.phase)
            {
                return Some((*hash, session.phase.clone(), session.created_at_wall));
            }
        }
        None
    }

    // -- Cleanup & maintenance -----------------------------------------------

    /// Prune terminal sessions for a counterparty, keeping at most
    /// `MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY`.
    /// Also deletes BLE reassembly chunks for the counterparty.
    /// Returns the number of sessions pruned.
    pub async fn prune_terminal_sessions_for_counterparty(
        &self,
        counterparty_device_id: &[u8; 32],
    ) -> usize {
        // Sweep orphaned BLE reassembly chunks for this counterparty
        if let Err(e) =
            crate::storage::client_db::delete_chunks_by_counterparty(counterparty_device_id)
        {
            warn!(
                "[SessionStore] Failed to sweep BLE reassembly chunks: {}",
                e
            );
        }

        let terminal_hashes: Vec<[u8; 32]> = {
            let sessions = self.sessions.lock().await;
            sessions
                .iter()
                .filter(|(_, s)| {
                    // Only prune committed sessions. Failed/rejected sessions must
                    // persist for frontend poller visibility (bilateral.pending_list).
                    s.counterparty_device_id == *counterparty_device_id
                        && matches!(s.phase, BilateralPhase::Committed)
                })
                .map(|(h, _)| *h)
                .collect()
        };

        if terminal_hashes.len() <= MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY {
            return 0;
        }

        let excess = terminal_hashes.len() - MAX_TERMINAL_SESSIONS_PER_COUNTERPARTY;
        let to_remove = &terminal_hashes[..excess];
        let mut pruned = 0;
        {
            let mut sessions = self.sessions.lock().await;
            for hash in to_remove {
                sessions.remove(hash);
                let _ = delete_bilateral_session(hash);
                pruned += 1;
            }
        }
        if pruned > 0 {
            info!(
                "[SessionStore] Pruned {} terminal sessions for counterparty {}",
                pruned,
                encode_base32_crockford(&counterparty_device_id[..8])
            );
        }
        pruned
    }

    /// Clockless: expiry-based cleanup is disabled.
    /// Sessions are pruned by phase (terminal sessions) elsewhere.
    pub async fn cleanup_expired(&self) -> usize {
        // No tick-based expiry in clockless protocol.
        0
    }

    /// Reconcile in-memory state with SQLite. Returns count of changes applied.
    pub async fn reconcile_with_storage(&self) -> Result<usize, DsmError> {
        let db_sessions = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to load sessions for reconcile: {e}"))
        })?;
        let mut count = 0;
        let mut sessions = self.sessions.lock().await;
        for record in db_sessions {
            if record.commitment_hash.len() != 32 {
                continue;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&record.commitment_hash);
            if let std::collections::hash_map::Entry::Vacant(e) = sessions.entry(hash) {
                // Session in DB but not in memory — restore it
                if let Some(session) = self.record_to_session(&record) {
                    e.insert(session);
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Combined cleanup + reconcile. Returns (cleaned, reconciled).
    pub async fn maintain(&self) -> Result<(usize, usize), DsmError> {
        let cleaned = self.cleanup_expired().await;
        let reconciled = self.reconcile_with_storage().await?;
        Ok((cleaned, reconciled))
    }

    // -- Bootstrap restoration -----------------------------------------------

    /// Load all sessions from SQLite into the in-memory map.
    /// Returns the count of sessions restored.
    /// Does NOT run recovery finalization — the handler calls
    /// `find_recoverable_sessions()` + its own finalization logic for that.
    pub async fn restore_from_storage(&self) -> Result<usize, DsmError> {
        let records = get_all_bilateral_sessions().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to load bilateral sessions: {e}"))
        })?;

        let mut restored = 0;
        let mut sessions = self.sessions.lock().await;
        for record in records {
            if record.commitment_hash.len() != 32 {
                continue;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&record.commitment_hash);

            if let Some(session) = self.record_to_session(&record) {
                sessions.insert(hash, session);
                restored += 1;
            }
        }
        info!("[SessionStore] Restored {} sessions from storage", restored);
        Ok(restored)
    }

    // -- Recovery identification ---------------------------------------------

    /// Find sessions stuck in `Accepted` phase with a counterparty signature.
    /// These are sessions where the sender never received the commit response
    /// (e.g., BLE link dropped). Returns the list of (commitment_hash, session)
    /// pairs. The handler is responsible for running the actual finalization.
    pub async fn find_recoverable_sessions(&self) -> Vec<([u8; 32], BilateralBleSession)> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter(|(_, s)| {
                s.phase == BilateralPhase::Accepted && s.counterparty_signature.is_some()
            })
            .map(|(h, s)| (*h, s.clone()))
            .collect()
    }

    // -- Internal helpers ----------------------------------------------------

    #[cfg(test)]
    pub(crate) async fn all_sessions(&self) -> HashMap<[u8; 32], BilateralBleSession> {
        self.sessions.lock().await.clone()
    }

    fn record_to_session(&self, record: &BilateralSessionRecord) -> Option<BilateralBleSession> {
        let operation = match deserialize_operation(&record.operation_bytes) {
            Ok(op) => op,
            Err(e) => {
                warn!(
                    "[SessionStore] Failed to deserialize operation for session {}: {}",
                    encode_base32_crockford(
                        &record.commitment_hash[..record.commitment_hash.len().min(8)]
                    ),
                    e
                );
                return None;
            }
        };

        let mut commitment_hash = [0u8; 32];
        commitment_hash.copy_from_slice(&record.commitment_hash);

        let mut counterparty_device_id = [0u8; 32];
        if record.counterparty_device_id.len() == 32 {
            counterparty_device_id.copy_from_slice(&record.counterparty_device_id);
        }

        let counterparty_genesis_hash = record
            .counterparty_genesis_hash
            .as_ref()
            .filter(|h| h.len() == 32)
            .map(|h| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h);
                arr
            });

        Some(BilateralBleSession {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(commitment: [u8; 32], phase: BilateralPhase) -> BilateralBleSession {
        BilateralBleSession {
            commitment_hash: commitment,
            local_commitment_hash: None,
            counterparty_device_id: [0x01; 32],
            counterparty_genesis_hash: None,
            operation: Operation::default(),
            phase,
            local_signature: None,
            counterparty_signature: None,
            created_at_ticks: 0,
            expires_at_ticks: u64::MAX,
            sender_ble_address: None,
            created_at_wall: Instant::now(),
            stitched_receipt_bytes: None,
            pre_finalize_entropy: None,
        }
    }

    #[test]
    fn phase_to_str_covers_all_variants() {
        assert_eq!(phase_to_str(&BilateralPhase::Preparing), "preparing");
        assert_eq!(phase_to_str(&BilateralPhase::Prepared), "prepared");
        assert_eq!(
            phase_to_str(&BilateralPhase::PendingUserAction),
            "pending_user_action"
        );
        assert_eq!(phase_to_str(&BilateralPhase::Accepted), "accepted");
        assert_eq!(phase_to_str(&BilateralPhase::Rejected), "rejected");
        assert_eq!(
            phase_to_str(&BilateralPhase::ConfirmPending),
            "confirm_pending"
        );
        assert_eq!(phase_to_str(&BilateralPhase::Committed), "committed");
        assert_eq!(phase_to_str(&BilateralPhase::Failed), "failed");
    }

    #[test]
    fn phase_from_str_roundtrip() {
        let phases = [
            BilateralPhase::Preparing,
            BilateralPhase::Prepared,
            BilateralPhase::PendingUserAction,
            BilateralPhase::Accepted,
            BilateralPhase::Rejected,
            BilateralPhase::ConfirmPending,
            BilateralPhase::Committed,
            BilateralPhase::Failed,
        ];
        for phase in &phases {
            let tag = phase_to_str(phase);
            let restored = phase_from_str(tag);
            assert_eq!(&restored, phase);
        }
    }

    #[test]
    fn phase_from_str_unknown_defaults_to_failed() {
        assert_eq!(phase_from_str("nonexistent"), BilateralPhase::Failed);
        assert_eq!(phase_from_str(""), BilateralPhase::Failed);
    }

    #[test]
    fn is_inflight_phase_true_cases() {
        assert!(is_inflight_phase(&BilateralPhase::Preparing));
        assert!(is_inflight_phase(&BilateralPhase::Prepared));
        assert!(is_inflight_phase(&BilateralPhase::PendingUserAction));
        assert!(is_inflight_phase(&BilateralPhase::Accepted));
        assert!(is_inflight_phase(&BilateralPhase::ConfirmPending));
    }

    #[test]
    fn is_inflight_phase_false_cases() {
        assert!(!is_inflight_phase(&BilateralPhase::Committed));
        assert!(!is_inflight_phase(&BilateralPhase::Rejected));
        assert!(!is_inflight_phase(&BilateralPhase::Failed));
    }

    #[tokio::test]
    async fn session_store_insert_get_remove() {
        let store = SessionStore::new();
        assert!(store.is_empty().await);

        let hash = [0x42; 32];
        let session = make_session(hash, BilateralPhase::Preparing);
        store.insert(session).await;

        assert_eq!(store.len().await, 1);
        assert!(store.contains(&hash).await);

        let fetched = store.get(&hash).await.unwrap();
        assert_eq!(fetched.commitment_hash, hash);
        assert_eq!(fetched.phase, BilateralPhase::Preparing);

        let removed = store.remove(&hash).await;
        assert!(removed.is_some());
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn session_store_get_phase() {
        let store = SessionStore::new();
        let hash = [0x10; 32];
        store
            .insert(make_session(hash, BilateralPhase::Accepted))
            .await;
        assert_eq!(store.get_phase(&hash).await, Some(BilateralPhase::Accepted));
        assert_eq!(store.get_phase(&[0xFF; 32]).await, None);
    }

    #[tokio::test]
    async fn session_store_detect_inflight_counterparty() {
        let store = SessionStore::new();
        let counterparty = [0x01; 32];
        let hash = [0x20; 32];
        let mut session = make_session(hash, BilateralPhase::Prepared);
        session.counterparty_device_id = counterparty;
        store.insert(session).await;

        let found = store
            .detect_inflight_counterparty_session(&counterparty)
            .await;
        assert!(found.is_some());
        let (h, phase, _) = found.unwrap();
        assert_eq!(h, hash);
        assert_eq!(phase, BilateralPhase::Prepared);

        let not_found = store
            .detect_inflight_counterparty_session(&[0xFF; 32])
            .await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn session_store_no_inflight_for_terminal_sessions() {
        let store = SessionStore::new();
        let counterparty = [0x01; 32];
        let mut s = make_session([0x30; 32], BilateralPhase::Committed);
        s.counterparty_device_id = counterparty;
        store.insert(s).await;

        assert!(store
            .detect_inflight_counterparty_session(&counterparty)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn session_store_find_recoverable_sessions() {
        let store = SessionStore::new();

        let mut recoverable = make_session([0x40; 32], BilateralPhase::Accepted);
        recoverable.counterparty_signature = Some(vec![0xAB; 16]);
        store.insert(recoverable).await;

        let mut not_recoverable = make_session([0x41; 32], BilateralPhase::Accepted);
        not_recoverable.counterparty_signature = None;
        store.insert(not_recoverable).await;

        store
            .insert(make_session([0x42; 32], BilateralPhase::Committed))
            .await;

        let found = store.find_recoverable_sessions().await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, [0x40; 32]);
    }

    #[tokio::test]
    async fn session_store_cleanup_expired_is_noop() {
        let store = SessionStore::new();
        store
            .insert(make_session([0x50; 32], BilateralPhase::Preparing))
            .await;
        let cleaned = store.cleanup_expired().await;
        assert_eq!(cleaned, 0);
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn session_store_with_lock() {
        let store = SessionStore::new();
        store
            .insert(make_session([0x60; 32], BilateralPhase::Failed))
            .await;

        let count = store.with_lock(|map| map.len()).await;
        assert_eq!(count, 1);
    }
}
