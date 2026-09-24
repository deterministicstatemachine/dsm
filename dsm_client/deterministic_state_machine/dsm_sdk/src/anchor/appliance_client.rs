// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`AnchorAppliance`] — the producer-side appliance interface.
//!
//! Software Authority, Hardware Identity (v2): the appliance is NOT the transfer authority; it
//! contributes exactly two identity witnesses over the DSM root-advance message `M`:
//! - `σ^chip` — the TROPIC01's resident key, signing on-die;
//! - `σ^host` — BLAKE3-SPHINCS+ SPX128f, the RP2350 partition (`dsm::crypto::sphincs`, the same
//!   scheme + variant `bluetooth::anchor_accept` verifies with).
//!
//! No transport to a physical appliance exists yet; nothing implements this interface.

use anchor_core::appliance::RecoverOutcome;
use anchor_core::root_advance::Transition;

use dsm::types::error::DsmError;

/// Active state read from the appliance (`OP_STATUS`) — the inputs the producer needs to build
/// the next transition `Δ`. v2: the forward-only offline frontier `h_i` + the counter floor `u_i`.
#[derive(Clone, Debug)]
pub struct ApplianceStatus {
    /// The current offline frontier `h_i` (the transition's `prev_root`).
    pub root: [u8; 32],
    pub anchor_counter: u64,
}

/// The pin material a receiver must hold to recognize + verify this anchor's releases
/// (maps to `bluetooth::anchor_accept::PinnedAnchor` / `crypto::anchor_enrollment::FusedAnchorPin`).
#[derive(Clone, Debug)]
pub struct AnchorPin {
    pub bundle: [u8; 32],
    pub anchor_id: [u8; 32],
    pub enrolled_counter: u64,
    /// Partition public key `pk_host` (`σ^host`).
    pub partition_pk: Vec<u8>,
    /// Resident chip public key `pk_chip` (`σ^chip`, Ed25519) — pinned in `B`, verifies `σ^chip`.
    pub pk_chip: Vec<u8>,
}

/// Transport-agnostic producer interface to the anchor appliance: what an RP2350 USB-CDC/BLE
/// client implements. All ops fail closed into [`DsmError`].
pub trait AnchorAppliance {
    /// `OP_STATUS`: the active state (no mutation).
    fn status(&mut self) -> Result<ApplianceStatus, DsmError>;
    /// `OP_PREPARE`: form `M` over the DSM-supplied device roots `R_i`/`R_{i+1}` and produce
    /// `σ^chip` (on-die) + `σ^host`. The DSM layer computes the device SMT roots and passes them in.
    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DsmError>;
    /// `OP_COMMIT`: move the counter floor. Point of no return.
    fn commit(&mut self) -> Result<(), DsmError>;
    /// `OP_EMIT`: the committed release, prost-encoded as `dsm.anchor.OfflineRelease` bytes (with
    /// EMPTY SMT proofs — the SDK attaches `Π_i`/`Π_{i+1}` before it rides the confirm).
    fn emit(&mut self) -> Result<Vec<u8>, DsmError>;
    /// `OP_FINALIZE`: advance the active frontier; returns the new frontier.
    fn finalize(&mut self) -> Result<[u8; 32], DsmError>;
    /// `OP_CANCEL`: discard a prepared (uncommitted) record.
    fn cancel(&mut self) -> Result<(), DsmError>;
    /// The receiver pin material for this anchor (pinned at admission).
    fn pin(&self) -> AnchorPin;

    /// `OP_RECOVER` (§26) — OBSERVATION ONLY. Report the appliance's recovery state after a power
    /// loss / host re-attach. This NEVER cancels, commits, moves the counter, or erases a release;
    /// the host decides from the returned [`RecoverOutcome`] (see [`recovery_action`]).
    fn recover(&mut self) -> Result<RecoverOutcome, DsmError>;
}

/// The host's policy decision after OBSERVING a [`RecoverOutcome`]. `recover()` observes; this
/// decides; the caller executes. The only state auto-cancelled is an orphaned uncommitted
/// `Prepared` (no owning session, counter not moved). A committed release is re-emitted, never
/// erased (§26); anything ambiguous downgrades online.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryAction {
    Ready,
    CancelOrphanedPrepared,
    LeavePreparedForOwner,
    ReemitCommitted,
    DowngradeOnline,
}

/// Host recovery policy (§26): a PURE decision from an observed [`RecoverOutcome`] plus whether an
/// in-flight/durable session still owns the prepared record. Auto-cancel happens ONLY for an
/// orphaned uncommitted `Prepared`; `Committed`/`ReemitCommitted` is NEVER cancelled or erased.
#[must_use]
pub fn recovery_action(outcome: RecoverOutcome, prepared_owned_by_session: bool) -> RecoveryAction {
    match outcome {
        RecoverOutcome::Accept(_) => RecoveryAction::Ready,
        RecoverOutcome::ReemitCommitted(_) => RecoveryAction::ReemitCommitted,
        RecoverOutcome::AcceptPreparedCanComplete | RecoverOutcome::OnlineCancelOrResolve => {
            if prepared_owned_by_session {
                RecoveryAction::LeavePreparedForOwner
            } else {
                RecoveryAction::CancelOrphanedPrepared
            }
        }
        RecoverOutcome::DowngradeOnline
        | RecoverOutcome::FailClosed
        | RecoverOutcome::ExhaustedOnlineOnly => RecoveryAction::DowngradeOnline,
    }
}
