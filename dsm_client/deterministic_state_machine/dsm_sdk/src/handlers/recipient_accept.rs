// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3b: canonical apply for a bound pair.
//!
//! A pair reaches here only through the ingestion boundary
//! (`recipient_dispatch`): both halves were verified when they arrived, and
//! the receipt's signed child tip is the successor recomputed from the
//! transfer's operation. What this module adds is the order in which a pair
//! becomes accepted:
//!
//! ```text
//! bound
//!   -> the signed operation re-derived from the staged bytes (SIG A again)
//!   -> canonical apply, which marks the pair accepted INSIDE its transaction
//!   -> accepted
//! ```
//!
//! The receipt's signature chain is not re-checked here against the live cert
//! head: it was checked on arrival, and the head moves when THIS pair is
//! accepted. Re-checking it against the moved head would refuse the very
//! receipt that moved it.
//!
//! If the apply does not commit, nothing is accepted and nothing is recorded
//! (DSM Amendment A1, MR-DSM-0018).

use dsm::types::operations::Operation;
use dsm::types::receipt_types::StitchedReceiptV2;

use crate::storage::client_db::recipient_staging::{self, PairState, StagedPair};

/// A bound pair, with its meaning re-derived from the staged signed material.
#[derive(Debug, Clone)]
pub struct VerifiedTransfer {
    pub pair: StagedPair,
    /// The contact whose stored key verified both halves.
    pub sender: [u8; 32],
    /// The ONLY trusted operation: re-derived from the staged canonical bytes
    /// and SIG A under the sender's stored key.
    pub signed_op: Operation,
    /// The terms that open `signed_op`'s commitment, re-opened from the
    /// staged bytes.
    pub terms: dsm::types::operations::TransferTerms,
    /// The exact signed bytes `signed_op` was bound from.
    pub canonical_operation_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    /// The receipt, decoded from the staged wire bytes.
    pub receipt: StitchedReceiptV2,
    pub evidence_bytes: Vec<u8>,
}

impl VerifiedTransfer {
    /// The accepted transfer's name: the submission id an honest sender
    /// derives from the receipt commitment, recomputed here, never read off
    /// the spool.
    pub fn transfer_name(&self) -> String {
        crate::storage::client_db::derive_submission_id(&self.pair.commitment)
    }
}

/// What a transfer moves and says: its amount from its SIGNED operation, its
/// token and memo from the terms that open the operation's commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTerms {
    pub amount: u64,
    /// The token, named by its id: as text when the id bytes are text, in
    /// Base32 when they are binary.
    pub token_id: String,
    pub memo: String,
}

impl TransferTerms {
    /// The terms a signed transfer's amount and its opened terms state.
    pub(crate) fn of(
        amount: &dsm::types::token_types::Balance,
        opened: &dsm::types::operations::TransferTerms,
    ) -> Self {
        Self {
            amount: amount.value(),
            token_id: match String::from_utf8(opened.token_id.clone()) {
                Ok(text) => text,
                Err(binary) => crate::util::text_id::encode_base32_crockford(binary.as_bytes()),
            },
            memo: opened.memo.clone(),
        }
    }
}

/// The terms of a transfer — the only ones it is shown or recorded with —
/// read from its signed operation and the terms that open it. Terms that do
/// not open the operation's commitment state nothing about it.
pub(crate) fn transfer_terms(
    op: &Operation,
    opened: &dsm::types::operations::TransferTerms,
) -> Result<TransferTerms, String> {
    opened.open(op).map_err(|e| e.to_string())?;
    match op {
        Operation::Transfer { amount, .. } => Ok(TransferTerms::of(amount, opened)),
        other => Err(format!(
            "the signed operation is a {}, not a transfer",
            other.get_operation_type()
        )),
    }
}

/// How a bound pair was accepted. A successful apply has TWO semantically
/// different outcomes and they must not collapse into one.
///
/// ```text
/// Fresh                        -> canonical apply executed      -> AcceptedFresh
/// AlreadyAppliedSameOperation  -> NO re-execution, converged     -> AcceptedDuplicate
/// Conflict                     -> not accepted
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// The canonical apply executed for the first time.
    AcceptedFresh,
    /// The exact operation identity was already applied. Nothing re-executed
    /// and nothing re-credited.
    AcceptedDuplicate,
}

/// Load a pair's staged objects and re-derive what they mean.
pub fn verified_pair(pair: &StagedPair) -> Result<VerifiedTransfer, String> {
    let store = |e: anyhow::Error| format!("the pair's staged objects are unreadable: {e}");
    let transfer = recipient_staging::get_transfer(&pair.op_id)
        .map_err(store)?
        .ok_or_else(|| "the pair's transfer is not staged".to_string())?;
    let receipt_row = recipient_staging::get_receipt(&pair.commitment)
        .map_err(store)?
        .ok_or_else(|| "the pair's receipt is not staged".to_string())?;
    if transfer.sender != receipt_row.sender {
        return Err("the pair's halves were verified under different senders".to_string());
    }
    let signed_op = super::recipient_dispatch::signed_operation_of(&transfer)?;
    let terms = super::recipient_dispatch::open_terms(&transfer.terms, &signed_op)
        .map_err(|e| format!("the staged transfer's terms: {e}"))?;
    let receipt = StitchedReceiptV2::from_canonical_protobuf(&receipt_row.evidence_bytes)
        .map_err(|e| format!("the staged receipt no longer decodes: {e}"))?;
    Ok(VerifiedTransfer {
        pair: *pair,
        sender: transfer.sender,
        signed_op,
        terms,
        canonical_operation_bytes: transfer.canonical_operation_bytes,
        signature: transfer.signature,
        receipt,
        evidence_bytes: receipt_row.evidence_bytes,
    })
}

/// Run the canonical apply for a bound pair, and only then report it
/// accepted.
///
/// The apply returns an [`ApplyOutcome`], not `()`: the canonical apply is
/// keyed on authenticated material, so replaying the same signed operation
/// returns `AlreadyAppliedSameOperation` rather than applying twice, and that
/// outcome must stay distinguishable from a fresh apply.
///
/// `Applied` means the apply's own transaction marked the pair accepted — the
/// caller's `write_acceptance` does it with
/// [`recipient_staging::mark_pair_accepted_with_conn`] — so the acceptance is
/// read back from the store rather than assumed, and the pair returned is the
/// one the store holds. `AlreadyAppliedSameOperation` ran no transaction, so
/// the pair is marked here. A `Conflict` leaves the pair bound.
///
/// [`ApplyOutcome`]: crate::sdk::apply_outcome::ApplyOutcome
pub fn accept_bound_pair<F>(
    v: &VerifiedTransfer,
    apply: F,
) -> Result<(Acceptance, StagedPair), String>
where
    F: FnOnce(&VerifiedTransfer) -> Result<crate::sdk::apply_outcome::ApplyOutcome, String>,
{
    use crate::sdk::apply_outcome::ApplyOutcome;
    let name = v.transfer_name();
    let outcome = apply(v)
        .map_err(|e| format!("canonical apply failed for {name} (not accepted, retryable): {e}"))?;
    let acceptance = match outcome {
        ApplyOutcome::Applied { .. } => Acceptance::AcceptedFresh,
        ApplyOutcome::AlreadyAppliedSameOperation { .. } => {
            let pair = recipient_staging::get_pair(&v.pair.op_id)
                .map_err(|e| format!("{name}: the pair is unreadable: {e}"))?;
            if !matches!(
                pair,
                Some(StagedPair {
                    state: PairState::Accepted,
                    ..
                })
            ) {
                recipient_staging::mark_pair_accepted(&v.pair.op_id)
                    .map_err(|e| format!("{name}: accepting the applied pair failed: {e}"))?;
            }
            Acceptance::AcceptedDuplicate
        }
        // A conflicting identity reusing this (relationship, parent) or nonce
        // cannot become valid by being retried; it stays unaccepted.
        ApplyOutcome::Conflict { reason } => {
            return Err(format!("{name}: canonical apply conflict: {reason}"));
        }
    };
    match recipient_staging::get_pair(&v.pair.op_id)
        .map_err(|e| format!("{name}: the pair is unreadable: {e}"))?
    {
        Some(
            stored @ StagedPair {
                state: PairState::Accepted,
                ..
            },
        ) => Ok((acceptance, stored)),
        other => Err(format!(
            "{name}: the apply reported {acceptance:?} but the pair is {other:?} in the store"
        )),
    }
}
