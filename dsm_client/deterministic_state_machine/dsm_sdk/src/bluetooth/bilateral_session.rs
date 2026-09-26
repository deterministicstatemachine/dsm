// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bilateral BLE session types and session store.
//!
//! This module owns the core types for the 3-phase bilateral protocol
//! (`BilateralBleSession`, `BilateralPhase`, `BilateralSettlementDelegate`),
//! the one mapping between a session and its `bilateral_sessions` row, and the
//! [`SessionStore`] that holds the in-memory session map.
//!
//! The types are transport-layer-agnostic — no coin logic, no balance
//! checks, no cross-SDK flag reads.

use std::collections::HashMap;
use std::sync::Arc;

use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use tokio::sync::Mutex;

use crate::storage::client_db::{deserialize_operation, serialize_operation, BilateralSessionRecord};

// ---------------------------------------------------------------------------
// Transport–application separation boundary
// ---------------------------------------------------------------------------

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
    /// BLE MAC address of the sender (for response routing)
    pub sender_ble_address: Option<String>,
    /// SENDER-only: its own signed receipt of the step, built at confirm (its
    /// A-side per-step EK, cert and signature). Its EK step is recorded from
    /// it when the step commits.
    pub stitched_receipt_bytes: Option<Vec<u8>>,
    /// SENDER-only: the receiver's counter-signed receipt from the verified
    /// ack — the step's proof in the sender's history, and the receiver's EK
    /// step.
    pub counter_signed_receipt: Option<Vec<u8>>,
    /// Offline-bearer receiver challenge r_R. RECEIVER: the fresh challenge it issued in
    /// `BilateralPrepareResponse` (checked vs the release on confirm). SENDER: the challenge
    /// received from that response, bound into the appliance PREPARE. `None` for ordinary
    /// transfers.
    pub receiver_challenge: Option<[u8; 32]>,
    /// SENDER-only: the fused-anchor-state leaf update the appliance produced for this bearer
    /// transfer, stashed at confirm-build time so `finalize_sender_step`
    /// commits the SAME successor state the on-wire proofs were built from (both-or-neither). `None`
    /// for ordinary transfers and on the receiver side.
    pub anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
    /// SENDER-only: the simulated post-advance Per-Device SMT root (`child_r_a`) the confirm's
    /// receipt names, as sent to the receiver. Stashed at confirm-build time so the canonical
    /// commit can enforce both-or-neither: the committed root MUST equal it, else the sender fails
    /// closed to recovery (the receiver verified the receipt against this value). `None` on the
    /// receiver side and before a confirm is built.
    pub sent_child_root: Option<[u8; 32]>,
    /// SENDER-only: the offline-cash allocation debit for a bearer transfer, created ONCE at confirm-build
    /// and stashed here so the canonical commit draws value from the allocation identically to the sim.
    /// It carries the anchor bundle `B` — which is NOT recoverable from `anchor_leaf` (whose key is
    /// `H(B)`), so it must live as session state, never be reconstructed at commit. `Some` iff this
    /// bearer transfer is allocation-backed; `None` for ordinary transfers and on the receiver side.
    pub offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    /// SENDER-only: the relationship tip the proposed step extends — its
    /// precommitment's parent. With the operation it hashes to the
    /// commitment, which is how a restart holds the precommitment again.
    pub parent_tip: Option<[u8; 32]>,
    /// The frame this session owes its counterparty until the counterparty
    /// answers it: the sender's prepare (Prepared) or confirm
    /// (ConfirmPending), the receiver's response (Accepted) — written with
    /// the phase that owes it and delivered again whenever the link returns.
    /// A rejected step keeps the signed rejection (or cancellation) that
    /// ended it, the answer to the counterparty's next frame for the step.
    pub owed_frame: Option<Vec<u8>>,
}

/// The kind of an offline protocol frame, whatever carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFrameKind {
    Prepare,
    PrepareResponse,
    Confirm,
}

/// A frame a session owes its counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedFrame {
    pub commitment_hash: [u8; 32],
    pub kind: OfflineFrameKind,
    pub bytes: Vec<u8>,
}

impl BilateralBleSession {
    /// The frame this session owes, by the phase it is in: a proposal awaiting
    /// its answer owes the prepare, an acceptance awaiting its confirm owes the
    /// response, a confirm awaiting its ack owes the confirm. A session in any
    /// other phase owes nothing.
    /// The signed rejection or cancellation that ended this step, the answer
    /// to any frame the counterparty sends for it again.
    pub fn rejection(&self) -> Option<Vec<u8>> {
        (self.phase == BilateralPhase::Rejected)
            .then(|| self.owed_frame.clone())
            .flatten()
    }

    pub fn owed(&self) -> Option<OwedFrame> {
        let kind = match self.phase {
            BilateralPhase::Prepared => OfflineFrameKind::Prepare,
            BilateralPhase::Accepted => OfflineFrameKind::PrepareResponse,
            BilateralPhase::ConfirmPending => OfflineFrameKind::Confirm,
            _ => return None,
        };
        self.owed_frame.as_ref().map(|bytes| OwedFrame {
            commitment_hash: self.commitment_hash,
            kind,
            bytes: bytes.clone(),
        })
    }
}

fn array32(what: &str, bytes: Option<&Vec<u8>>) -> Result<Option<[u8; 32]>, DsmError> {
    bytes
        .map(|b| {
            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
                DsmError::invalid_operation(format!(
                    "persisted bilateral session: {what} must be 32 bytes (got {})",
                    b.len()
                ))
            })
        })
        .transpose()
}

impl BilateralBleSession {
    /// The session's durable row: everything a restart needs to carry the
    /// session on where it stopped.
    pub fn to_record(&self) -> Result<BilateralSessionRecord, DsmError> {
        let (spend_anchor_bundle, spend_asset, spend_amount) = match &self.offline_spend {
            Some(spend) => (
                Some(spend.anchor_bundle_b.to_vec()),
                Some(spend.asset.to_vec()),
                Some(i64::try_from(spend.amount).map_err(|_| {
                    DsmError::invalid_operation("an offline spend's amount exceeds i64::MAX")
                })?),
            ),
            None => (None, None, None),
        };
        Ok(BilateralSessionRecord {
            commitment_hash: self.commitment_hash.to_vec(),
            counterparty_device_id: self.counterparty_device_id.to_vec(),
            counterparty_genesis_hash: self.counterparty_genesis_hash.map(|h| h.to_vec()),
            operation_bytes: serialize_operation(&self.operation),
            phase: phase_to_str(&self.phase).to_string(),
            local_signature: self.local_signature.clone(),
            counterparty_signature: self.counterparty_signature.clone(),
            sender_ble_address: self.sender_ble_address.clone(),
            stitched_receipt_bytes: self.stitched_receipt_bytes.clone(),
            counter_signed_receipt: self.counter_signed_receipt.clone(),
            parent_tip: self.parent_tip.map(|t| t.to_vec()),
            receiver_challenge: self.receiver_challenge.map(|c| c.to_vec()),
            sent_child_root: self.sent_child_root.map(|r| r.to_vec()),
            anchor_leaf_key: self.anchor_leaf.as_ref().map(|l| l.key.to_vec()),
            anchor_leaf_value: self.anchor_leaf.as_ref().map(|l| l.new_value.to_vec()),
            spend_anchor_bundle,
            spend_asset,
            spend_amount,
            owed_frame: self.owed_frame.clone(),
        })
    }

    /// The session a durable row holds. A row that does not decode — a field
    /// of the wrong length, an unknown phase, half an anchor leaf or half an
    /// offline spend — is an error, never a session with a stand-in.
    pub fn from_record(record: &BilateralSessionRecord) -> Result<Self, DsmError> {
        let commitment_hash = array32("commitment_hash", Some(&record.commitment_hash))?
            .ok_or_else(|| DsmError::invalid_operation("commitment_hash is required"))?;
        let counterparty_device_id = array32(
            "counterparty_device_id",
            Some(&record.counterparty_device_id),
        )?
        .ok_or_else(|| DsmError::invalid_operation("counterparty_device_id is required"))?;
        let operation = deserialize_operation(&record.operation_bytes).map_err(|e| {
            DsmError::serialization_error(
                "persisted bilateral session",
                "operation_bytes",
                Some(e.to_string()),
                None::<std::io::Error>,
            )
        })?;
        let anchor_leaf = match (
            array32("anchor_leaf_key", record.anchor_leaf_key.as_ref())?,
            array32("anchor_leaf_value", record.anchor_leaf_value.as_ref())?,
        ) {
            (Some(key), Some(new_value)) => {
                Some(dsm::types::device_state::AnchorLeafUpdate { key, new_value })
            }
            (None, None) => None,
            _ => {
                return Err(DsmError::invalid_operation(
                    "persisted bilateral session: half an anchor leaf",
                ))
            }
        };
        let offline_spend = match (
            array32("spend_anchor_bundle", record.spend_anchor_bundle.as_ref())?,
            array32("spend_asset", record.spend_asset.as_ref())?,
            record.spend_amount,
        ) {
            (Some(anchor_bundle_b), Some(asset), Some(amount)) => {
                Some(dsm::types::device_state::OfflineSpend {
                    anchor_bundle_b,
                    asset,
                    amount: u64::try_from(amount).map_err(|_| {
                        DsmError::invalid_operation(
                            "persisted bilateral session: a negative offline spend",
                        )
                    })?,
                })
            }
            (None, None, None) => None,
            _ => {
                return Err(DsmError::invalid_operation(
                    "persisted bilateral session: half an offline spend",
                ))
            }
        };
        Ok(Self {
            commitment_hash,
            local_commitment_hash: None,
            counterparty_device_id,
            counterparty_genesis_hash: array32(
                "counterparty_genesis_hash",
                record.counterparty_genesis_hash.as_ref(),
            )?,
            operation,
            phase: phase_from_str(&record.phase)?,
            local_signature: record.local_signature.clone(),
            counterparty_signature: record.counterparty_signature.clone(),
            sender_ble_address: record.sender_ble_address.clone(),
            stitched_receipt_bytes: record.stitched_receipt_bytes.clone(),
            counter_signed_receipt: record.counter_signed_receipt.clone(),
            receiver_challenge: array32("receiver_challenge", record.receiver_challenge.as_ref())?,
            anchor_leaf,
            sent_child_root: array32("sent_child_root", record.sent_child_root.as_ref())?,
            offline_spend,
            parent_tip: array32("parent_tip", record.parent_tip.as_ref())?,
            owed_frame: record.owed_frame.clone(),
        })
    }
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

/// Parse a phase string tag back to the enum; an unknown tag is an error.
pub fn phase_from_str(s: &str) -> Result<BilateralPhase, DsmError> {
    Ok(match s {
        "preparing" => BilateralPhase::Preparing,
        "prepared" => BilateralPhase::Prepared,
        "pending_user_action" => BilateralPhase::PendingUserAction,
        "accepted" => BilateralPhase::Accepted,
        "rejected" => BilateralPhase::Rejected,
        "confirm_pending" => BilateralPhase::ConfirmPending,
        "committed" => BilateralPhase::Committed,
        "failed" => BilateralPhase::Failed,
        other => {
            return Err(DsmError::invalid_operation(format!(
                "unknown bilateral session phase '{other}'"
            )))
        }
    })
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// The in-memory map of this device's bilateral sessions, keyed by
/// commitment. Each session's durable state is its `bilateral_sessions` row
/// ([`BilateralBleSession::to_record`]).
pub struct SessionStore {
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
            sender_ble_address: None,
            stitched_receipt_bytes: None,
            counter_signed_receipt: None,
            receiver_challenge: None,
            anchor_leaf: None,
            sent_child_root: None,
            offline_spend: None,
            parent_tip: None,
            owed_frame: None,
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
            let restored = phase_from_str(tag).expect("a known phase");
            assert_eq!(&restored, phase);
        }
    }

    #[test]
    fn an_unknown_phase_is_an_error() {
        assert!(phase_from_str("nonexistent").is_err());
        assert!(phase_from_str("").is_err());
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

    /// The durable rows count a step in flight by its phase tag: exactly the
    /// tags of the phases a session in memory counts.
    #[test]
    fn the_durable_in_flight_tags_are_the_in_flight_phases() {
        for phase in [
            BilateralPhase::Preparing,
            BilateralPhase::Prepared,
            BilateralPhase::PendingUserAction,
            BilateralPhase::Accepted,
            BilateralPhase::Rejected,
            BilateralPhase::ConfirmPending,
            BilateralPhase::Committed,
            BilateralPhase::Failed,
        ] {
            assert_eq!(
                crate::storage::client_db::IN_FLIGHT_PHASE_TAGS.contains(&phase_to_str(&phase)),
                is_inflight_phase(&phase),
                "{phase:?}"
            );
        }
    }

    /// A session and its durable row carry the same state, commit inputs
    /// included: a restart continues the session it wrote.
    #[test]
    fn a_session_survives_its_row() {
        let mut session = make_session([0x42; 32], BilateralPhase::ConfirmPending);
        session.counterparty_signature = Some(vec![0x51; 64]);
        session.stitched_receipt_bytes = Some(vec![0x52; 40]);
        session.counter_signed_receipt = Some(vec![0x53; 40]);
        session.parent_tip = Some([0x54; 32]);
        session.receiver_challenge = Some([0x55; 32]);
        session.sent_child_root = Some([0x56; 32]);
        session.anchor_leaf = Some(dsm::types::device_state::AnchorLeafUpdate {
            key: [0x57; 32],
            new_value: [0x58; 32],
        });
        session.offline_spend = Some(dsm::types::device_state::OfflineSpend {
            anchor_bundle_b: [0x59; 32],
            asset: [0x5A; 32],
            amount: 7,
        });
        session.owed_frame = Some(vec![0x5B; 48]);
        let restored =
            BilateralBleSession::from_record(&session.to_record().expect("row")).expect("session");
        assert_eq!(restored.phase, session.phase);
        assert_eq!(
            restored.counterparty_signature,
            session.counterparty_signature
        );
        assert_eq!(
            restored.stitched_receipt_bytes,
            session.stitched_receipt_bytes
        );
        assert_eq!(
            restored.counter_signed_receipt,
            session.counter_signed_receipt
        );
        assert_eq!(restored.parent_tip, session.parent_tip);
        assert_eq!(restored.receiver_challenge, session.receiver_challenge);
        assert_eq!(restored.sent_child_root, session.sent_child_root);
        assert_eq!(restored.anchor_leaf, session.anchor_leaf);
        assert_eq!(restored.offline_spend, session.offline_spend);
        assert_eq!(restored.owed_frame, session.owed_frame);
        assert_eq!(
            restored.owed().map(|f| f.kind),
            Some(OfflineFrameKind::Confirm)
        );
    }

    /// A row that does not decode is an error, never a session with a
    /// stand-in: half an anchor leaf, a short field, an unknown phase.
    #[test]
    fn a_row_that_does_not_decode_is_refused() {
        let row = make_session([0x43; 32], BilateralPhase::ConfirmPending)
            .to_record()
            .expect("row");
        let mut half_leaf = row.clone();
        half_leaf.anchor_leaf_key = Some(vec![0x61; 32]);
        assert!(BilateralBleSession::from_record(&half_leaf).is_err());
        let mut short_root = row.clone();
        short_root.sent_child_root = Some(vec![0x62; 31]);
        assert!(BilateralBleSession::from_record(&short_root).is_err());
        let mut unknown_phase = row;
        unknown_phase.phase = "commit".to_string();
        assert!(BilateralBleSession::from_record(&unknown_phase).is_err());
    }
}
