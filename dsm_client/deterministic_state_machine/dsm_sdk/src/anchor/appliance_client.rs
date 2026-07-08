// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`AnchorAppliance`] — the producer-side appliance interface — and
//! [`InProcessAnchorAppliance`], the activation implementation backed by a real
//! `anchor_core::appliance::Appliance` driven over an in-process secure-element mock.
//!
//! The crypto is REAL (the receiver must accept it): WOTS-over-BLAKE3 witness signatures
//! (`anchor_core::sig::WotsBlake3`) and BLAKE3-SPHINCS+ SPX128f partition certificates
//! (`dsm::crypto::sphincs`, the same scheme + variant `bluetooth::anchor_accept` verifies
//! with). Only the TROPIC01 silicon (MAC-and-destroy + the down-counter) is mocked in
//! process, since the SDK has no physical-chip transport yet.

use prost::Message;

use anchor_core::appliance::{Appliance, ApplianceError};
use anchor_core::enrollment::{birth, BirthInputs};
use anchor_core::root_advance::Transition;
use anchor_core::sig::WotsBlake3;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};

use dsm::crypto::sphincs::SphincsVariant;
use dsm::types::error::DsmError;

/// The RP2350 partition certificate scheme (boot cert + per-transfer final cert).
/// Byte-compatible with the receiver's verifier in `bluetooth::anchor_accept`.
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;

/// Active fused state read from the appliance (`OP_STATUS`), the inputs the producer needs
/// to build the next transition package `Δ`.
#[derive(Clone, Debug)]
pub struct ApplianceStatus {
    pub root: [u8; 32],
    pub anchor_head: [u8; 32],
    /// The LIVE boot head `J_{b'}` (advanced by boot events; what the next transfer's cert reports
    /// as `current_boot_head` and what the successor fused state commits).
    pub boot_head: [u8; 32],
    /// The COMMITTED boot head `J_b` — the boot head the current active fused state commits to (what
    /// the next transfer's cert reports as `prev_boot_head`). Equals `boot_head` at rest, but diverges
    /// after a boot advance until the next finalize; the fused-anchor-state PREV leaf must commit THIS.
    pub committed_boot_head: [u8; 32],
    pub anchor_counter: u64,
}

/// The pin material a receiver must hold to recognize + verify this anchor's releases
/// (maps to `bluetooth::anchor_accept::PinnedAnchor` / `crypto::anchor_enrollment::FusedAnchorPin`).
#[derive(Clone, Debug)]
pub struct AnchorPin {
    pub bundle: [u8; 32],
    pub anchor_id: [u8; 32],
    pub enrolled_counter: u64,
    pub partition_pk: Vec<u8>,
}

/// Transport-agnostic producer interface to the fused-anchor appliance. The activation
/// build uses [`InProcessAnchorAppliance`]; a real RP2350 USB-CDC/BLE client implementing
/// this trait is hardware follow-on. All ops fail-closed into [`DsmError`].
pub trait AnchorAppliance {
    /// `OP_STATUS`: the active fused state (no mutation).
    fn status(&mut self) -> Result<ApplianceStatus, DsmError>;
    /// `OP_PREPARE`: one transfer-slot MAC-and-destroy witness + the full cross-bound cert.
    fn prepare(&mut self, t: &Transition, receiver_challenge: &[u8; 32]) -> Result<(), DsmError>;
    /// `OP_COMMIT`: move the counter, erase the witness key. Point of no return.
    fn commit(&mut self) -> Result<(), DsmError>;
    /// `OP_EMIT`: the committed release, prost-encoded as `dsm.anchor.OfflineRelease` bytes
    /// (ready to drop into `BilateralConfirmRequest.offline_release`).
    fn emit(&mut self) -> Result<Vec<u8>, DsmError>;
    /// `OP_FINALIZE`: advance the active fused state; returns the new active root.
    fn finalize(&mut self) -> Result<[u8; 32], DsmError>;
    /// `OP_CANCEL`: discard a prepared (uncommitted) record.
    fn cancel(&mut self) -> Result<(), DsmError>;
    /// The receiver pin material for this anchor (pinned at admission).
    fn pin(&self) -> AnchorPin;
}

// --- in-process secure-element mock (silicon only; crypto is real) ---

/// In-process TROPIC01 mock: MAC-and-destroy is a keyed BLAKE3 over `(slot ‖ input)` and the
/// counter is an in-memory down-counter. Mirrors the `anchor_core` integration-test mock; the
/// real chip replaces only this, never the witness/partition crypto.
struct InProcTropic {
    h: u32,
    secret: [u8; 32],
}
impl Tropic for InProcTropic {
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError> {
        Ok(anchor_core::hash::kdf(
            &self.secret,
            "DSM/anchor/inproc-macandd/v1",
            &[&q.to_le_bytes(), x],
        ))
    }
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
}

/// BLAKE3-SPHINCS+ SPX128f partition signature scheme (`PartitionSig`). Same scheme + variant
/// the receiver verifies with (`bluetooth::anchor_accept`), so a real partition cert this
/// appliance produces verifies receiver-side.
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

/// Enrollment inputs for a fresh in-process appliance (the one-way birth fuse ceremony §7–§9).
/// The SDK supplies these from the device/transfer context; for tests they are deterministic.
pub struct BirthConfig {
    pub partition_trng: [u8; 32],
    pub host_nonce: [u8; 32],
    pub device_id: [u8; 32],
    pub policy_hash: [u8; 32],
    pub partition_device_id: [u8; 32],
    pub anchor_id: [u8; 32],
    pub partition_key_seed: [u8; 32],
    pub enrolled_counter: u32,
    pub q_boot: u16,
    pub q_tx: u16,
    pub genesis_root: [u8; 32],
    /// Device-authoritative firmware measurement folded into the boot fence.
    pub firmware_measurement: [u8; 32],
    /// In-process secure-element arming seed (stands in for the chip's MAC-and-destroy state).
    pub se_secret: [u8; 32],
}

/// Activation appliance: a real `anchor_core` appliance over the in-process SE mock.
pub struct InProcessAnchorAppliance {
    app: Appliance<InProcTropic, WotsBlake3, SphincsPart>,
    partition_pk: Vec<u8>,
    boot_seq: u64,
    firmware_measurement: [u8; 32],
}

fn map_err(e: ApplianceError) -> DsmError {
    DsmError::invalid_operation(format!("anchor appliance: {e:?}"))
}

impl InProcessAnchorAppliance {
    /// Run the birth ceremony, construct the appliance, and advance the boot fence once so
    /// offline mode is enabled (the firmware boot-fences itself device-internally).
    pub fn birth_and_boot(cfg: &BirthConfig) -> Result<Self, DsmError> {
        let b = birth::<SphincsPart>(&BirthInputs {
            partition_trng: &cfg.partition_trng,
            tropic_birth_witness: &cfg.se_secret,
            host_nonce: &cfg.host_nonce,
            device_id: &cfg.device_id,
            policy_hash: &cfg.policy_hash,
            partition_device_id: &cfg.partition_device_id,
            tropic_anchor_id: &cfg.anchor_id,
            partition_key_seed: &cfg.partition_key_seed,
            enrolled_counter: cfg.enrolled_counter,
            q_boot: cfg.q_boot,
            q_tx: cfg.q_tx,
            genesis_root: &cfg.genesis_root,
        });
        let partition_pk = b.partition_pk.clone();
        let tropic = InProcTropic {
            h: cfg.enrolled_counter,
            secret: cfg.se_secret,
        };
        let mut app = Appliance::<_, WotsBlake3, SphincsPart>::new(
            tropic,
            cfg.enrolled_counter,
            cfg.anchor_id,
            cfg.q_boot,
            cfg.q_tx,
            cfg.partition_device_id,
            cfg.genesis_root,
            b,
        );
        // Boot fence: enable offline mode for this power cycle.
        app.boot(1, &cfg.firmware_measurement).map_err(map_err)?;
        Ok(Self {
            app,
            partition_pk,
            boot_seq: 1,
            firmware_measurement: cfg.firmware_measurement,
        })
    }

    /// The pinned partition public key (the receiver verifies boot + final certs with it).
    pub fn partition_pk(&self) -> &[u8] {
        &self.partition_pk
    }

    /// Advance the boot fence again (used after a finalize resets the boot chain).
    pub fn reboot(&mut self) -> Result<(), DsmError> {
        self.boot_seq += 1;
        self.app
            .boot(self.boot_seq, &self.firmware_measurement)
            .map(|_| ())
            .map_err(map_err)
    }
}

impl AnchorAppliance for InProcessAnchorAppliance {
    fn status(&mut self) -> Result<ApplianceStatus, DsmError> {
        Ok(ApplianceStatus {
            root: self.app.active.root,
            anchor_head: self.app.active.anchor_head,
            boot_head: self.app.active.boot_head,
            committed_boot_head: self.app.active.committed_boot_head,
            anchor_counter: self.app.active.anchor_counter,
        })
    }

    fn prepare(&mut self, t: &Transition, receiver_challenge: &[u8; 32]) -> Result<(), DsmError> {
        self.app.prepare(t, receiver_challenge).map_err(map_err)
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

    fn pin(&self) -> AnchorPin {
        AnchorPin {
            bundle: self.app.bundle,
            anchor_id: self.app.anchor_id,
            enrolled_counter: self.app.h0 as u64,
            partition_pk: self.partition_pk.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_core::accept::{accept_offline, CounterVerifier, DsmVerifier, VerifierContext};
    use anchor_core::boot::BootTicket;
    use anchor_core::proto::pb;
    use anchor_core::root_advance::{
        CounterAdvanceBinding, CounterAdvanceEvidence, CounterAdvanceReads, CounterEvidenceError,
    };

    /// The appliance stamps zero sender device roots (it cannot know them); this test
    /// pins the same zeros so an honest release binds without an SDK re-stamp.
    const ZERO_DEVROOT: [u8; 32] = [0u8; 32];

    const H0: u32 = 100;
    const GENESIS: [u8; 32] = [0x11; 32];
    const NEXT_ROOT: [u8; 32] = [0x22; 32];
    const POLICY: [u8; 32] = [0x33; 32];
    const RECIP: [u8; 32] = [0x44; 32];
    const RCHAL: [u8; 32] = [0x55; 32];
    const ANCHOR: [u8; 32] = [0xAA; 32];

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
            q_boot: 1,
            q_tx: 2,
            genesis_root: GENESIS,
            firmware_measurement: [0xF0; 32],
            se_secret: [0xC0; 32],
        }
    }

    fn transition() -> anchor_core::root_advance::OwnedTransition {
        anchor_core::root_advance::OwnedTransition {
            relationship_id: [1u8; 32],
            object_id: [2u8; 32],
            sender_device_id: [3u8; 32],
            recipient_device_id: RECIP,
            prev_root: GENESIS,
            next_root: NEXT_ROOT,
            anchor_counter: 0,
            next_anchor_counter: 1,
            action_type: 0,
            action_fields: vec![0xAB, 0xCD],
            payload_hash: [9u8; 32],
            old_leaf_proof: vec![0xAA; 40],
            new_leaf_proof: vec![0xCC; 40],
            authority_policy_hash: POLICY,
        }
    }

    /// Receiver DSM verifier: real boot-chain + partition-cert checks under the pinned key;
    /// the SMT-state checks return true (those become real inclusion checks in D3/D4).
    struct TestDsm {
        part_pk: Vec<u8>,
    }
    impl TestDsm {
        fn pv(&self, m: &[u8; 32], sig: &[u8]) -> bool {
            dsm::crypto::sphincs::verify(PART_VARIANT, &self.part_pk, m, sig).unwrap_or(false)
        }
    }
    impl DsmVerifier for TestDsm {
        fn sender_device_root_before_commits_anchor_state(
            &self,
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 32],
            _: u64,
        ) -> bool {
            true
        }
        fn verify_boot_chain(
            &self,
            bundle: &[u8; 32],
            anchor_head: &[u8; 32],
            committed_boot_head: &[u8; 32],
            current_boot_head: &[u8; 32],
            boot_chain: &[BootTicket],
        ) -> bool {
            let mut prev = *committed_boot_head;
            for tk in boot_chain {
                if &tk.anchor_bundle != bundle
                    || &tk.anchor_head != anchor_head
                    || tk.prev_boot_head != prev
                    || !self.pv(&tk.cert_message(), &tk.partition_boot_signature)
                {
                    return false;
                }
                prev = tk.next_boot_head;
            }
            &prev == current_boot_head
        }
        fn verify_partition_certificate(&self, m_p: &[u8; 32], sig: &[u8]) -> bool {
            self.pv(m_p, sig)
        }
        fn verify_transition(&self, _: &Transition) -> bool {
            true
        }
        fn delivers_to_receiver(&self, t: &Transition) -> bool {
            t.recipient_device_id == &RECIP
        }
        fn sender_device_root_after_commits_anchor_state(
            &self,
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 32],
            _: u64,
        ) -> bool {
            true
        }
    }

    /// Stand-in for the Path-B L3 reads: verifies the transition binding, then returns the
    /// FROM read `H_pre = H0 - u_i` (pre-commit) and the TO read `H_post = H0 - (u_i+1)`
    /// (post-commit).
    struct TestCounter {
        pre: u64,
        post: u64,
    }
    impl CounterVerifier for TestCounter {
        fn verify_counter_advance(
            &self,
            pinned: &[u8; 32],
            ev: &CounterAdvanceEvidence,
            binding: &CounterAdvanceBinding,
        ) -> Result<CounterAdvanceReads, CounterEvidenceError> {
            ev.check_binding(pinned, binding)?;
            Ok(CounterAdvanceReads {
                pre_raw_counter: self.pre,
                post_raw_counter: self.post,
            })
        }
    }

    #[test]
    fn inprocess_release_passes_predicate_crypto() {
        let mut app = InProcessAnchorAppliance::birth_and_boot(&cfg()).expect("birth");
        let pin = app.pin();
        let part_pk = app.partition_pk().to_vec();

        // Drive the producer flow: STATUS → PREPARE → COMMIT → EMIT → FINALIZE.
        let st = app.status().expect("status");
        assert_eq!(st.root, GENESIS);
        assert_eq!(st.anchor_counter, 0);

        let txn = transition();
        app.prepare(&txn.as_transition(), &RCHAL).expect("prepare");
        app.commit().expect("commit");
        let release_bytes = app.emit().expect("emit");
        let next_root = app.finalize().expect("finalize");
        assert_eq!(next_root, NEXT_ROOT);

        // Decode the wire release the receiver would see and run the predicate.
        let rel = pb::OfflineRelease::decode(&release_bytes[..])
            .expect("decode")
            .to_release()
            .expect("to_release");

        let ctx = VerifierContext {
            accepted_prev_root: &GENESIS,
            pinned_bundle: &pin.bundle,
            pinned_anchor_id: &pin.anchor_id,
            expected_receiver_challenge: &RCHAL,
            expected_policy_hash: &POLICY,
            enrolled_counter: pin.enrolled_counter,
            sender_device_root_before: &ZERO_DEVROOT,
            sender_device_root_after: &ZERO_DEVROOT,
            anchor_uncompromised: true,
        };
        let dsm = TestDsm { part_pk };
        // FROM read H0 - u_i = 100 - 0 = 100; TO read H0 - (u_i+1) = 100 - 1 = 99.
        let counter = TestCounter {
            pre: H0 as u64,
            post: H0 as u64 - 1,
        };

        accept_offline::<WotsBlake3, _, _>(&rel, &ctx, &dsm, &counter)
            .expect("emitted release must pass the receiver predicate");
    }

    #[test]
    fn wrong_counter_value_is_rejected() {
        let mut app = InProcessAnchorAppliance::birth_and_boot(&cfg()).expect("birth");
        let pin = app.pin();
        let part_pk = app.partition_pk().to_vec();
        let txn = transition();
        app.prepare(&txn.as_transition(), &RCHAL).expect("prepare");
        app.commit().expect("commit");
        let release_bytes = app.emit().expect("emit");
        let rel = pb::OfflineRelease::decode(&release_bytes[..])
            .unwrap()
            .to_release()
            .unwrap();
        let ctx = VerifierContext {
            accepted_prev_root: &GENESIS,
            pinned_bundle: &pin.bundle,
            pinned_anchor_id: &pin.anchor_id,
            expected_receiver_challenge: &RCHAL,
            expected_policy_hash: &POLICY,
            enrolled_counter: pin.enrolled_counter,
            sender_device_root_before: &ZERO_DEVROOT,
            sender_device_root_after: &ZERO_DEVROOT,
            anchor_uncompromised: true,
        };
        let dsm = TestDsm { part_pk };
        // A TO read off by one (not the exact post-commit H0-(u_i+1)) must be rejected. The FROM read
        // is correct, so the failure is the TO-coordinate check.
        let counter = TestCounter {
            pre: H0 as u64,
            post: H0 as u64,
        };
        assert!(accept_offline::<WotsBlake3, _, _>(&rel, &ctx, &dsm, &counter).is_err());
    }
}
