// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`AnchorAppliance`] — the producer-side appliance interface — and
//! [`InProcessAnchorAppliance`], the activation implementation backed by a real
//! `anchor_core::appliance::Appliance` driven over an in-process secure-element mock.
//!
//! Software Authority, Hardware Identity (v2): the appliance is NOT the transfer authority; it
//! contributes exactly two identity witnesses over the DSM root-advance message `M`:
//! - `σ^chip` — a resident Ed25519 key. On real hardware the TROPIC01 signs on-die; the
//!   in-process mock here holds an `ed25519-dalek` key so the crypto is REAL and the receiver's
//!   `ChipSig` (`dsm::crypto::classical_verify::verify_ed25519`) verifies it.
//! - `σ^host` — BLAKE3-SPHINCS+ SPX128f, the RP2350 partition (`dsm::crypto::sphincs`, the same
//!   scheme + variant `bluetooth::anchor_accept` verifies with).
//!
//! Only the TROPIC01 silicon (the resident key + the down-counter floor) is mocked in process.

use prost::Message;

use ed25519_dalek::{Signer, SigningKey};

use anchor_core::appliance::{Appliance, ApplianceError, RecoverOutcome};
use anchor_core::enrollment::{birth, BirthInputs};
use anchor_core::root_advance::Transition;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};

use dsm::crypto::sphincs::SphincsVariant;
use dsm::types::error::DsmError;

/// The RP2350 partition (`σ^host`) scheme. Byte-compatible with the receiver's verifier.
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;

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

/// Transport-agnostic producer interface to the anchor appliance. The activation build uses
/// [`InProcessAnchorAppliance`]; a real RP2350 USB-CDC/BLE client implementing this trait is
/// hardware follow-on. All ops fail-closed into [`DsmError`].
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
    /// the host decides from the returned [`RecoverOutcome`] (see [`recovery_action`]). The default
    /// is the fail-safe `DowngradeOnline`.
    fn recover(&mut self) -> Result<RecoverOutcome, DsmError> {
        Ok(RecoverOutcome::DowngradeOnline)
    }
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

// --- in-process secure-element mock (silicon only; crypto is real) ---

/// In-process TROPIC01 mock: the resident chip key is a real `ed25519-dalek` `SigningKey`
/// (`chip_sign` = a real Ed25519 signature the receiver verifies) and the counter is an in-memory
/// down-counter floor. The real chip replaces only this, never the σ^chip/σ^host crypto.
struct InProcTropic {
    h: u32,
    chip: SigningKey,
}
impl Tropic for InProcTropic {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        Ok(self.h)
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        if self.h == 0 {
            return Err(TropicError::CounterExhausted);
        }
        self.h -= 1;
        Ok(())
    }
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        Ok(self.chip.sign(&message[..]).to_bytes().to_vec())
    }
}

/// BLAKE3-SPHINCS+ SPX128f partition signature scheme (`PartitionSig` = `σ^host`). Same scheme +
/// variant the receiver verifies with (`bluetooth::anchor_accept`).
struct SphincsPart;
impl PartitionSig for SphincsPart {
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        match dsm::crypto::sphincs::generate_keypair_from_seed(PART_VARIANT, seed) {
            Ok(kp) => (kp.secret_key.clone(), kp.public_key.clone()),
            Err(_) => (Vec::new(), Vec::new()),
        }
    }
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        dsm::crypto::sphincs::sign(PART_VARIANT, sk, digest).unwrap_or_default()
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        dsm::crypto::sphincs::verify(PART_VARIANT, pk, digest, sig).unwrap_or(false)
    }
}

/// Enrollment inputs for a fresh in-process appliance (the one-way birth fuse ceremony §7). The
/// SDK supplies these from the device/transfer context; for tests they are deterministic.
pub struct BirthConfig {
    pub partition_trng: [u8; 32],
    pub host_nonce: [u8; 32],
    pub device_id: [u8; 32],
    pub policy_hash: [u8; 32],
    pub partition_device_id: [u8; 32],
    pub anchor_id: [u8; 32],
    pub partition_key_seed: [u8; 32],
    pub enrolled_counter: u32,
    pub genesis_root: [u8; 32],
    /// Chip birth-witness entropy folded into the birth fuse.
    pub chip_birth_witness: [u8; 32],
    /// Seed for the resident Ed25519 chip key (`σ^chip`) — the in-process stand-in for the die key.
    pub chip_seed: [u8; 32],
    /// Online identity public key `pk_on` bound into `B` as `H(pk_on)` (placeholder in Stage 3; the
    /// real dual-identity binding + upgrade ceremony land in Stage 5).
    pub online_id_pk: Vec<u8>,
}

/// Activation appliance: a real `anchor_core` appliance over the in-process SE mock.
pub struct InProcessAnchorAppliance {
    app: Appliance<InProcTropic, SphincsPart>,
    partition_pk: Vec<u8>,
    pk_chip: Vec<u8>,
}

fn map_err(e: ApplianceError) -> DsmError {
    DsmError::invalid_operation(format!("anchor appliance: {e:?}"))
}

impl InProcessAnchorAppliance {
    /// Run the birth ceremony and construct the appliance. There is no boot fence — offline mode
    /// is enabled once born.
    pub fn birth(cfg: &BirthConfig) -> Result<Self, DsmError> {
        let chip = SigningKey::from_bytes(&cfg.chip_seed);
        let chip_pk = chip.verifying_key().to_bytes();
        let b = birth::<SphincsPart>(&BirthInputs {
            partition_trng: &cfg.partition_trng,
            chip_birth_witness: &cfg.chip_birth_witness,
            host_nonce: &cfg.host_nonce,
            device_id: &cfg.device_id,
            policy_hash: &cfg.policy_hash,
            partition_device_id: &cfg.partition_device_id,
            anchor_id: &cfg.anchor_id,
            chip_pk: &chip_pk,
            online_id_pk: &cfg.online_id_pk,
            partition_key_seed: &cfg.partition_key_seed,
            enrolled_counter: cfg.enrolled_counter,
            genesis_root: &cfg.genesis_root,
        });
        let partition_pk = b.partition_pk.clone();
        let pk_chip = b.chip_pk.clone();
        let tropic = InProcTropic {
            h: cfg.enrolled_counter,
            chip,
        };
        let app = Appliance::<_, SphincsPart>::new(
            tropic,
            cfg.enrolled_counter,
            cfg.anchor_id,
            cfg.partition_device_id,
            b,
        );
        Ok(Self {
            app,
            partition_pk,
            pk_chip,
        })
    }

    /// The pinned partition public key `pk_host`.
    pub fn partition_pk(&self) -> &[u8] {
        &self.partition_pk
    }

    /// The pinned resident chip public key `pk_chip` (Ed25519).
    pub fn pk_chip(&self) -> &[u8] {
        &self.pk_chip
    }
}

impl AnchorAppliance for InProcessAnchorAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        Ok(ApplianceStatus {
            root: self.app.active.root,
            anchor_counter: self.app.active.anchor_counter,
        })
    }

    fn prepare(
        &mut self,
        t: &Transition,
        receiver_challenge: &[u8; 32],
        sender_device_root_before: &[u8; 32],
        sender_device_root_after: &[u8; 32],
    ) -> Result<(), DsmError> {
        self.app
            .prepare(
                t,
                receiver_challenge,
                sender_device_root_before,
                sender_device_root_after,
            )
            .map_err(map_err)
    }

    fn commit(&mut self) -> Result<(), DsmError> {
        self.app.commit().map_err(map_err)
    }

    fn emit(&mut self) -> Result<Vec<u8>, DsmError> {
        let rel = self.app.emit().map_err(map_err)?;
        Ok(rel.to_pb().encode_to_vec())
    }

    fn finalize(&mut self) -> Result<[u8; 32], DsmError> {
        self.app.finalize().map_err(map_err)
    }

    fn cancel(&mut self) -> Result<(), DsmError> {
        self.app.cancel().map_err(map_err)
    }

    fn recover(&mut self) -> Result<RecoverOutcome, DsmError> {
        Ok(self.app.recover())
    }

    fn pin(&self) -> AnchorPin {
        AnchorPin {
            bundle: self.app.bundle,
            anchor_id: self.app.anchor_id,
            enrolled_counter: self.app.h0 as u64,
            partition_pk: self.partition_pk.clone(),
            pk_chip: self.pk_chip.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_core::accept::{accept_offline, DsmVerifier, VerifierContext};
    use anchor_core::proto::pb;
    use anchor_core::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
    use anchor_core::tropic::ChipSig;

    const H0: u32 = 100;
    const GENESIS: [u8; 32] = [0x11; 32];
    const POLICY: [u8; 32] = [0x33; 32];
    const RECIP: [u8; 32] = [0x44; 32];
    const RCHAL: [u8; 32] = [0x55; 32];
    const ANCHOR: [u8; 32] = [0xAA; 32];
    // Mock DSM device SMT roots the DSM layer would compute (checked by verify_smt_leaf, mocked true).
    const R_I: [u8; 32] = [0x51; 32];
    const R_NEXT: [u8; 32] = [0x52; 32];

    /// Receiver-side Ed25519 verification of `σ^chip` (the real receiver adapter, built in Slice 2).
    struct Ed25519ChipSig;
    impl ChipSig for Ed25519ChipSig {
        fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
            let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk_chip), <[u8; 64]>::try_from(sig))
            else {
                return false;
            };
            dsm::crypto::classical_verify::verify_ed25519(&pk, message, &sig).is_ok()
        }
    }

    /// Receiver DSM verifier: `σ^DSM` (verify_transition) + delivery are asserted; SMT inclusion is
    /// mocked true here (the real device-SMT proofs are produced/checked in Slice 5).
    struct TestDsm;
    impl DsmVerifier for TestDsm {
        fn verify_smt_leaf(&self, _root: &[u8; 32], _proof: &[u8], _leaf: &[u8; 32]) -> bool {
            true
        }
        fn verify_transition(&self, _d: &[u8; 32], _prev: &[u8; 32], _next: &[u8; 32]) -> bool {
            true
        }
        fn delivers_to_receiver(&self, _d: &[u8; 32], recipient: &[u8; 32]) -> bool {
            recipient == &RECIP
        }
        fn verify_upgrade_cert(&self, _bundle: &[u8; 32]) -> bool {
            true
        }
    }

    fn cfg() -> BirthConfig {
        BirthConfig {
            partition_trng: [1u8; 32],
            host_nonce: [2u8; 32],
            device_id: [3u8; 32],
            policy_hash: POLICY,
            partition_device_id: [0xBD; 32],
            anchor_id: ANCHOR,
            partition_key_seed: [0x4E; 32],
            enrolled_counter: H0,
            genesis_root: GENESIS,
            chip_birth_witness: [0xC0; 32],
            chip_seed: [0xE2; 32],
            online_id_pk: Vec::new(), // placeholder; real pk_on binding is Stage 5
        }
    }

    /// A transition advancing from `prev_frontier` at counter `u`; `next_root` is the derived
    /// frontier `H(h_i ‖ D)` (Δ° excludes it, so D is computable first).
    fn transition(prev_frontier: [u8; 32], u: u64) -> OwnedTransition {
        let mut t = OwnedTransition {
            relationship_id: [1u8; 32],
            object_id: [2u8; 32],
            sender_device_id: [3u8; 32],
            recipient_device_id: RECIP,
            prev_root: prev_frontier,
            next_root: [0u8; 32],
            anchor_counter: u,
            next_anchor_counter: u + 1,
            action_type: 0,
            action_fields: vec![0xAB, 0xCD],
            payload_hash: [9u8; 32],
            old_leaf_proof: vec![0xAA; 40],
            new_leaf_proof: vec![0xCC; 40],
            authority_policy_hash: POLICY,
        };
        let d = transition_digest(&t.as_transition(), &RCHAL);
        t.next_root = anchor_root_advance(&prev_frontier, &d);
        t
    }

    #[test]
    fn recovery_action_cancels_only_orphaned_uncommitted_prepared() {
        let root = [7u8; 32];
        assert_eq!(
            recovery_action(RecoverOutcome::Accept(root), false),
            RecoveryAction::Ready
        );
        assert_eq!(
            recovery_action(RecoverOutcome::Accept(root), true),
            RecoveryAction::Ready
        );
        assert_eq!(
            recovery_action(RecoverOutcome::ReemitCommitted(root), false),
            RecoveryAction::ReemitCommitted
        );
        assert_eq!(
            recovery_action(RecoverOutcome::ReemitCommitted(root), true),
            RecoveryAction::ReemitCommitted
        );
        assert_eq!(
            recovery_action(RecoverOutcome::AcceptPreparedCanComplete, false),
            RecoveryAction::CancelOrphanedPrepared
        );
        assert_eq!(
            recovery_action(RecoverOutcome::OnlineCancelOrResolve, false),
            RecoveryAction::CancelOrphanedPrepared
        );
        assert_eq!(
            recovery_action(RecoverOutcome::AcceptPreparedCanComplete, true),
            RecoveryAction::LeavePreparedForOwner
        );
        assert_eq!(
            recovery_action(RecoverOutcome::DowngradeOnline, false),
            RecoveryAction::DowngradeOnline
        );
        assert_eq!(
            recovery_action(RecoverOutcome::ExhaustedOnlineOnly, false),
            RecoveryAction::DowngradeOnline
        );
    }

    #[test]
    fn inprocess_release_passes_v2_predicate_with_real_ed25519() {
        let mut app = InProcessAnchorAppliance::birth(&cfg()).expect("birth");
        let pin = app.pin();
        let part_pk = pin.partition_pk.clone();
        let pk_chip = pin.pk_chip.clone();

        // The appliance starts at the genesis frontier h_0 (NOT the DSM genesis root).
        let st = app.status().expect("status");
        let h0_frontier = st.root;
        assert_eq!(st.anchor_counter, 0);

        // STATUS → PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT → FINALIZE.
        let txn = transition(h0_frontier, 0);
        let next_frontier = txn.next_root;
        app.prepare(&txn.as_transition(), &RCHAL, &R_I, &R_NEXT)
            .expect("prepare");
        app.commit().expect("commit");
        let release_bytes = app.emit().expect("emit");
        assert_eq!(app.finalize().expect("finalize"), next_frontier);

        // Decode the wire release the receiver would see and run the v2 predicate.
        let rel = pb::OfflineRelease::decode(&release_bytes[..])
            .expect("decode")
            .to_release()
            .expect("to_release");
        assert_eq!(rel.cert.sender_device_root_before, R_I);
        assert_eq!(rel.cert.sender_device_root_after, R_NEXT);

        let ctx = VerifierContext {
            pinned_bundle: &pin.bundle,
            pinned_anchor_id: &pin.anchor_id,
            pinned_pk_chip: &pk_chip,
            pinned_pk_host: &part_pk,
            accepted_frontier: &h0_frontier,
            expected_receiver_challenge: &RCHAL,
            expected_recipient: &RECIP,
            expected_policy_hash: &POLICY,
            anchor_uncompromised: true,
            is_genesis: false,
        };
        accept_offline::<_, Ed25519ChipSig, SphincsPart>(&rel, &ctx, &TestDsm)
            .expect("emitted release must pass the v2 receiver predicate with real Ed25519 σ^chip");
    }

    #[test]
    fn wrong_pinned_chip_key_is_rejected() {
        let mut app = InProcessAnchorAppliance::birth(&cfg()).expect("birth");
        let pin = app.pin();
        let part_pk = pin.partition_pk.clone();
        let h0_frontier = app.status().unwrap().root;
        let txn = transition(h0_frontier, 0);
        app.prepare(&txn.as_transition(), &RCHAL, &R_I, &R_NEXT)
            .unwrap();
        app.commit().unwrap();
        let rel = pb::OfflineRelease::decode(&app.emit().unwrap()[..])
            .unwrap()
            .to_release()
            .unwrap();
        let wrong_pk_chip = [0xEE; 32];
        let ctx = VerifierContext {
            pinned_bundle: &pin.bundle,
            pinned_anchor_id: &pin.anchor_id,
            pinned_pk_chip: &wrong_pk_chip,
            pinned_pk_host: &part_pk,
            accepted_frontier: &h0_frontier,
            expected_receiver_challenge: &RCHAL,
            expected_recipient: &RECIP,
            expected_policy_hash: &POLICY,
            anchor_uncompromised: true,
            is_genesis: false,
        };
        assert!(accept_offline::<_, Ed25519ChipSig, SphincsPart>(&rel, &ctx, &TestDsm).is_err());
    }
}
