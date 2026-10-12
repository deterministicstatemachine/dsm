// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tri-state outcome of the §16.6 full-state incoming-transfer apply.

use crate::storage::client_db::CanonicalApplyRecord;

/// Outcome of [`crate::sdk::core_sdk::CoreSDK::apply_incoming_transfer_full_state`].
///
/// Both populated variants carry the durable [`CanonicalApplyRecord`] so the
/// downstream acceptance fold runs the exact same convergence steps
/// (projection sync + marker → promote → complete) regardless of whether this
/// delivery executed the transition or found it already applied.
#[derive(Debug)]
pub enum ApplyOutcome {
    /// Fresh apply — the single full-state transaction committed. `advance`
    /// carries the state-mutation outputs (SMT proofs, roots) for receipt
    /// construction on this first delivery.
    Applied {
        record: CanonicalApplyRecord,
        advance: Box<dsm::types::device_state::AdvanceOutcome>,
    },
    /// The EXACT operation identity was already applied. The record is LOADED
    /// verbatim from the durable store (never reconstructed from mutable
    /// state); there was NO re-execution and NO re-credit.
    AlreadyAppliedSameOperation { record: CanonicalApplyRecord },
    /// The request conflicts with committed state (different identity reusing
    /// the (relationship, parent) or nonce; stale parent; missing durability
    /// evidence). Fail closed: nothing mutated, do not ACK.
    Conflict { reason: String },
}
