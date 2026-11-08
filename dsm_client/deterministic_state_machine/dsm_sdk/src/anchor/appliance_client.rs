// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`AnchorAppliance`] — the producer-side appliance interface.
//!
//! Software Authority, Hardware Identity (v2): the appliance is NOT the transfer authority; it
//! contributes exactly two identity witnesses over the DSM root-advance message `M`:
//! - `σ^chip` — the TROPIC01's resident key, signing on-die;
//! - `σ^host` — BLAKE3-SPHINCS+ SPX128f, the RP2350 partition (`dsm::crypto::sphincs`, the same
//!   scheme + variant `bluetooth::anchor_accept` verifies with).
//!
//! Implemented by the USB client of the physical appliance (`crates/dsm-android-anchor`,
//! `UsbAnchorAppliance`, installed by the Android build) and, for tests, by the real anchor-core
//! appliance on a software TROPIC01 (`test_support::appliance`).

use anchor_core::appliance::RecoverOutcome;
use anchor_core::root_advance::Transition;

use dsm::types::error::DsmError;

/// Active state read from the appliance (`OP_STATUS`) — the inputs the producer needs to build
/// the next transition `Δ`. v2: the forward-only offline frontier `h_i` + the counter floor `u_i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplianceStatus {
    /// The current offline frontier `h_i` (the transition's `prev_root`).
    pub root: [u8; 32],
    pub anchor_counter: u64,
    /// For good, or a trial that the anchor's next boot ends ([`anchor_core::enrollment::Install`]).
    pub install: anchor_core::enrollment::Install,
    /// The receive challenge the anchor holds open, if any ([`anchor_core::receive`]).
    pub open_challenge: Option<[u8; 32]>,
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
    /// The public birth commitment `S_birth` `B` commits: with the keys above, the owner's online
    /// key and device id, `B` recomputes from the pin.
    pub birth_commitment: [u8; 32],
}

/// One thing a try-run went through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TryRunStep {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Whether the anchor needs it to work, or a production install alone does.
    pub requirement: anchor_core::try_run::Requirement,
}

/// An install gone through on the anchor with its permanent parts substituted
/// ([`anchor_core::try_run`]), and what installing would make permanent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TryRunReport {
    pub passed: bool,
    pub steps: Vec<TryRunStep>,
    /// The install the anchor would make, when it ran: a trial image's is a trial.
    pub install: Option<anchor_core::enrollment::Install>,
    pub permanent: Vec<String>,
    /// Why it could not run at all, when it could not.
    pub refused: String,
}

/// The wallet's rehearsal owner: a device key derived apart from the one an anchor binds, that a
/// try-run's payment is authorized under. The anchor is born for it in its trial slots, so the
/// rehearsal goes through the same owner check a real payment does, and the wallet's own device
/// key never signs a rehearsal. The anchor holds no owner's key and never signs as one.
pub struct RehearsalOwner {
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl RehearsalOwner {
    /// Derived from this device's signing key, one way: the same device rehearses under the same
    /// key, and the key authorizes nothing but a rehearsal born for it.
    pub fn derive(device_secret_key: &[u8]) -> Result<Self, DsmError> {
        let seed = blake3::derive_key("DSM/anchor/rehearsal-owner/v1", device_secret_key);
        let kp = dsm::crypto::sphincs::generate_keypair_from_seed(
            dsm::crypto::sphincs::SphincsVariant::SPX256f,
            &seed,
        )?;
        Ok(Self {
            secret: kp.secret_key.clone(),
            public: kp.public_key.clone(),
        })
    }

    /// The key the rehearsal is born for (`rehearsal_pk` on the wire).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The rehearsal owner's authorization of the rehearsal's payment: its signature over the digest
    /// the anchor answered with.
    pub fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, DsmError> {
        dsm::crypto::sphincs::sphincs_sign(&self.secret, digest)
    }
}

/// Transport-agnostic producer interface to the anchor appliance: what an RP2350 USB-CDC/BLE
/// client implements. All ops fail closed into [`DsmError`].
pub trait AnchorAppliance {
    /// `OP_STATUS`: the active state (no mutation).
    fn status(&mut self) -> Result<ApplianceStatus, DsmError>;
    /// `OP_AUTHORIZE`: the owner's authorization of the next prepare, `signature` under this device's
    /// key over `digest`, the anchor-core `owner_authorization_digest` of that prepare. The anchor
    /// serves its owner, not whoever holds the link to it: without this, `OP_PREPARE` signs nothing.
    fn authorize(&mut self, digest: &[u8; 32], signature: &[u8]) -> Result<(), DsmError>;
    /// `OP_PREPARE`: form `M` over the DSM-supplied device roots `R_i`/`R_{i+1}` and produce
    /// `σ^chip` (on-die) + `σ^host`. The DSM layer computes the device SMT roots and passes them in.
    /// Refused unless the owner authorized this very prepare ([`Self::authorize`]).
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
    /// The pin material of the anchor as provisioned, or `None` while it was never provisioned.
    fn provisioned_pin(&mut self) -> Result<Option<AnchorPin>, DsmError>;
    /// `OP_TRY_RUN`: go through installing this anchor for the device `provisioning` names, with the
    /// permanent parts substituted. Nothing is bound and the chip is left as it was found. The
    /// rehearsal's payment is authorized by `rehearsal`, the rehearsal owner.
    fn try_run(
        &mut self,
        provisioning: &anchor_core::enrollment::Provisioning,
        rehearsal: &RehearsalOwner,
    ) -> Result<TryRunReport, DsmError>;
    /// `OP_PROVISION`: provision a never-provisioned anchor for the device `provisioning` names,
    /// once, and return its pin. Refused by an anchor already provisioned. Its try-run first, its
    /// payment authorized by `rehearsal`.
    fn provision(
        &mut self,
        provisioning: &anchor_core::enrollment::Provisioning,
        rehearsal: &RehearsalOwner,
    ) -> Result<AnchorPin, DsmError>;

    /// `OP_RECOVER` (§26) — OBSERVATION ONLY. Report the appliance's recovery state after a power
    /// loss / host re-attach. This NEVER cancels, commits, moves the counter, or erases a release;
    /// the host decides from the returned [`RecoverOutcome`] (see [`recovery_action`]).
    fn recover(&mut self) -> Result<RecoverOutcome, DsmError>;

    /// `OP_CHALLENGE`: the receiver's side of an offline payment. The anchor draws a receive challenge
    /// from both hardware sources and holds it open, in place of any open one; refused unless it holds
    /// no record.
    fn draw_challenge(&mut self) -> Result<[u8; 32], DsmError>;

    /// `OP_CHECK_PAYMENT`: the anchor checks the payer's release (its transition and certificate) and
    /// the payer's disclosed enrollment against its open challenge, itself, and holds what it checked
    /// for the receive that names it ([`anchor_core::receive::check_payment`]).
    fn check_payment(
        &mut self,
        payment: &anchor_core::root_advance::OfflineRelease,
        payer: &anchor_core::receive::PayerDisclosure,
    ) -> Result<(), DsmError>;
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
