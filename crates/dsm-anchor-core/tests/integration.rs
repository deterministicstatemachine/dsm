//! End-to-end tests for the v2 **Software Authority, Hardware Identity** appliance: the
//! 3-state transfer lifecycle, the producer→receiver round trip through the Def. 12
//! acceptance predicate, §26 recovery, and the wire protocol. Uniqueness is software (the
//! DSM device SMT); the appliance supplies `σ^chip` + `σ^host` over one root-advance message.
#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]

use anchor_core::accept::{accept_offline, AcceptError, DsmVerifier, VerifierContext};
use anchor_core::appliance::{Appliance, Record, RecoverOutcome, Status};
use anchor_core::enrollment::{birth, BirthInputs};
use anchor_core::hash::h as hash;
use anchor_core::proto::{decode_response, encode_request, pb};
use anchor_core::root_advance::{
    anchor_root_advance, transition_digest, OfflineRelease, OwnedTransition,
};
use anchor_core::service::{err, handle};
use anchor_core::tropic::{ChipSig, PartitionSig, Tropic, TropicError};

const H0: u32 = 100;
const ANCHOR: [u8; 32] = [0xAA; 32];
const PART_DEV: [u8; 32] = [0xBD; 32];
const DEVICE: [u8; 32] = [0x77; 32];
const GENESIS_ROOT: [u8; 32] = [0x11; 32];
const POLICY: [u8; 32] = [0x33; 32];
const RECIP: [u8; 32] = [0x44; 32];
const RCHAL: [u8; 32] = [0x55; 32];
const ONLINE_PK: [u8; 32] = [0x66; 32];
// Sender device SMT roots supplied by the DSM layer for a transfer (the appliance signs over
// them; the receiver's DsmVerifier proves their SMT inclusion — mocked true here).
const R_I: [u8; 32] = [0x51; 32];
const R_NEXT: [u8; 32] = [0x52; 32];

type App = Appliance<MockTropic, MockPart>;

// --- mocks ---

/// A faithful TROPIC01: a monotonic down-counter + a resident chip key. The chip signature
/// is `H("mock/chip-sig" ‖ pk_chip ‖ M)` so [`MockChip::verify`] can recompute it from the
/// pinned `pk_chip`; the private half (`csk`) never leaves this struct.
struct MockTropic {
    h: u32,
    csk: [u8; 32],
}
impl MockTropic {
    fn with_h(h: u32) -> Self {
        Self { h, csk: [0xC0; 32] }
    }
    fn pk(&self) -> Vec<u8> {
        hash("mock/chip-pk", &[&self.csk]).to_vec()
    }
}
impl Tropic for MockTropic {
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
        let pk = self.pk();
        Ok(hash("mock/chip-sig", &[&pk, message]).to_vec())
    }
}

/// Receiver-side verification of the resident chip signature (`σ^chip`).
struct MockChip;
impl ChipSig for MockChip {
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        sig == hash("mock/chip-sig", &[pk_chip, message])
    }
}

/// Deterministic mock partition (`σ^host`) scheme: `sk = pk = seed`; signature = keyed hash.
struct MockPart;
impl PartitionSig for MockPart {
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        (seed.to_vec(), seed.to_vec())
    }
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        let mut k = [0u8; 32];
        k.copy_from_slice(&sk[..32]);
        anchor_core::hash::kdf(&k, "test/partsign", &[digest]).to_vec()
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        Self::part_sign(pk, digest) == sig
    }
}

/// Receiver DSM verifier: software checks are flag-controlled so individual false paths can
/// be tested. `σ^DSM` is `transition_ok`; SMT inclusion is `smt_ok`.
struct Dsm {
    smt_ok: bool,
    transition_ok: bool,
    delivers: bool,
    upgrade_ok: bool,
}
impl Dsm {
    fn ok() -> Self {
        Self {
            smt_ok: true,
            transition_ok: true,
            delivers: true,
            upgrade_ok: true,
        }
    }
}
impl DsmVerifier for Dsm {
    fn verify_smt_leaf(&self, _r: &[u8; 32], _p: &[u8], _l: &[u8; 32]) -> bool {
        self.smt_ok
    }
    fn verify_transition(&self, _d: &[u8; 32], _p: &[u8; 32], _n: &[u8; 32]) -> bool {
        self.transition_ok
    }
    fn delivers_to_receiver(&self, _d: &[u8; 32], _r: &[u8; 32]) -> bool {
        self.delivers
    }
    fn verify_upgrade_cert(&self, _b: &[u8; 32]) -> bool {
        self.upgrade_ok
    }
}

// --- helpers ---

struct Fixture {
    a: App,
    part_pk: Vec<u8>,
    chip_pk: Vec<u8>,
    bundle: [u8; 32],
    frontier0: [u8; 32],
}

fn fixture(h: u32) -> Fixture {
    let chip_pk = MockTropic::with_h(0).pk(); // deterministic (csk fixed)
    let b = birth::<MockPart>(&BirthInputs {
        partition_trng: &[0x01; 32],
        chip_birth_witness: &[0x02; 32],
        host_nonce: &[0x03; 32],
        device_id: &DEVICE,
        policy_hash: &POLICY,
        partition_device_id: &PART_DEV,
        anchor_id: &ANCHOR,
        chip_pk: &chip_pk,
        online_id_pk: &ONLINE_PK,
        partition_key_seed: &[0x04; 32],
        enrolled_counter: H0,
        genesis_root: &GENESIS_ROOT,
    });
    let part_pk = b.partition_pk.clone();
    let bundle = b.bundle;
    let frontier0 = b.genesis_frontier;
    let a = Appliance::new(MockTropic::with_h(h), H0, ANCHOR, PART_DEV, b);
    Fixture {
        a,
        part_pk,
        chip_pk,
        bundle,
        frontier0,
    }
}

/// A transition advancing from `prev_frontier` at counter `u`. `next_root` is the derived
/// frontier `H(h_i ‖ D)` (Δ° excludes it, so D is computable first).
fn make_transition(prev_frontier: [u8; 32], u: u64) -> OwnedTransition {
    let mut t = OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: [3; 32],
        recipient_device_id: RECIP,
        prev_root: prev_frontier,
        next_root: [0; 32],
        anchor_counter: u,
        next_anchor_counter: u + 1,
        action_type: 0,
        action_fields: vec![9, 9, 9],
        payload_hash: [6; 32],
        old_leaf_proof: vec![0xAB; 40],
        new_leaf_proof: vec![0xCD; 40],
        authority_policy_hash: POLICY,
    };
    let d = transition_digest(&t.as_transition(), &RCHAL);
    t.next_root = anchor_root_advance(&prev_frontier, &d);
    t
}

/// prepare → commit → emit, returning a valid release and the receiver's pin material.
fn valid_release() -> (OfflineRelease, Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    let rel = f.a.emit().unwrap().clone();
    (rel, f.part_pk, f.chip_pk, f.bundle, f.frontier0)
}

fn ctx<'a>(
    bundle: &'a [u8; 32],
    chip_pk: &'a [u8],
    part_pk: &'a [u8],
    frontier: &'a [u8; 32],
) -> VerifierContext<'a> {
    VerifierContext {
        pinned_bundle: bundle,
        pinned_anchor_id: &ANCHOR,
        pinned_pk_chip: chip_pk,
        pinned_pk_host: part_pk,
        accepted_frontier: frontier,
        expected_receiver_challenge: &RCHAL,
        expected_recipient: &RECIP,
        expected_policy_hash: &POLICY,
        anchor_uncompromised: true,
        is_genesis: false,
    }
}

// --- lifecycle ---

#[test]
fn full_lifecycle_prepare_commit_emit_finalize() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;

    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    assert_eq!(f.a.active.status, Status::Prepared);
    assert_eq!(f.a.active.root, f.frontier0); // frontier stays until finalize

    f.a.commit().unwrap();
    assert_eq!(f.a.active.status, Status::Committed);
    assert_eq!(f.a.active.anchor_counter, 1);

    let rel = f.a.emit().unwrap().clone();
    assert_eq!(rel.cert.next_frontier, next_frontier);
    assert_eq!(rel.cert.sender_device_root_before, R_I);
    assert_eq!(rel.cert.sender_device_root_after, R_NEXT);

    assert_eq!(f.a.finalize().unwrap(), next_frontier);
    assert_eq!(f.a.active.root, next_frontier);
    assert_eq!(f.a.active.anchor_counter, 1);
    assert_eq!(f.a.active.status, Status::Ready);
}

#[test]
fn two_sequential_transfers() {
    let mut f = fixture(H0);
    let t0 = make_transition(f.frontier0, 0);
    let frontier1 = t0.next_root;
    f.a.prepare(&t0.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    assert_eq!(f.a.finalize().unwrap(), frontier1);

    let t1 = make_transition(frontier1, 1);
    let frontier2 = t1.next_root;
    f.a.prepare(&t1.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    assert_eq!(f.a.active.anchor_counter, 2);
    assert_eq!(f.a.finalize().unwrap(), frontier2);
}

// --- acceptance (producer → receiver round trip) ---

#[test]
fn accept_valid_release() {
    let (rel, part_pk, chip_pk, bundle, frontier0) = valid_release();
    let c = ctx(&bundle, &chip_pk, &part_pk, &frontier0);
    accept_offline::<_, MockChip, MockPart>(&rel, &c, &Dsm::ok()).unwrap();
}

#[test]
fn accept_rejects_wrong_chip_key() {
    let (rel, part_pk, _chip_pk, bundle, frontier0) = valid_release();
    let wrong = [0xEE; 32];
    let c = ctx(&bundle, &wrong, &part_pk, &frontier0);
    assert_eq!(
        accept_offline::<_, MockChip, MockPart>(&rel, &c, &Dsm::ok()),
        Err(AcceptError::ChipSigInvalid)
    );
}

#[test]
fn accept_rejects_dsm_state_failures() {
    let (rel, part_pk, chip_pk, bundle, frontier0) = valid_release();
    let c = ctx(&bundle, &chip_pk, &part_pk, &frontier0);

    let d = Dsm {
        smt_ok: false,
        ..Dsm::ok()
    };
    assert_eq!(
        accept_offline::<_, MockChip, MockPart>(&rel, &c, &d),
        Err(AcceptError::PrevStateUncommitted)
    );
    let d = Dsm {
        transition_ok: false,
        ..Dsm::ok()
    };
    assert_eq!(
        accept_offline::<_, MockChip, MockPart>(&rel, &c, &d),
        Err(AcceptError::TransitionProofInvalid)
    );
    let d = Dsm {
        delivers: false,
        ..Dsm::ok()
    };
    assert_eq!(
        accept_offline::<_, MockChip, MockPart>(&rel, &c, &d),
        Err(AcceptError::NotDeliveredToReceiver)
    );
}

#[test]
fn accept_rejects_compromise() {
    let (rel, part_pk, chip_pk, bundle, frontier0) = valid_release();
    let mut c = ctx(&bundle, &chip_pk, &part_pk, &frontier0);
    c.anchor_uncompromised = false;
    assert_eq!(
        accept_offline::<_, MockChip, MockPart>(&rel, &c, &Dsm::ok()),
        Err(AcceptError::AnchorCompromised)
    );
}

// --- §26 recovery ---

#[test]
fn recover_ready_accepts() {
    let mut f = fixture(H0);
    assert_eq!(f.a.recover(), RecoverOutcome::Accept(f.frontier0));
}

#[test]
fn recover_downgrades_on_firmware_boundary() {
    let mut f = fixture(H0);
    f.a.firmware_boundary_invalid = true;
    assert_eq!(f.a.recover(), RecoverOutcome::DowngradeOnline);
}

#[test]
fn recover_committed_reemits() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    assert_eq!(
        f.a.recover(),
        RecoverOutcome::ReemitCommitted(next_frontier)
    );
    assert_eq!(f.a.emit().unwrap().cert.next_frontier, next_frontier);
    assert_eq!(f.a.finalize().unwrap(), next_frontier);
}

#[test]
fn recover_prepared_can_complete() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    assert_eq!(f.a.recover(), RecoverOutcome::AcceptPreparedCanComplete);
}

#[test]
fn recover_ready_stale_adopts_live_and_ahead_fails_closed() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    f.a.finalize().unwrap(); // counter at 99, u=1
    f.a.active.anchor_counter = 0; // stale (behind the chip)
    let root = f.a.active.root;
    assert_eq!(f.a.recover(), RecoverOutcome::Accept(root));
    assert_eq!(f.a.active.anchor_counter, 1); // reconciled to the live chip counter

    let mut f = fixture(H0);
    f.a.active.anchor_counter = 5; // ahead — impossible for a real down-counter
    assert_eq!(f.a.recover(), RecoverOutcome::FailClosed);
}

#[test]
fn cancel_returns_to_ready() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.cancel().unwrap();
    assert_eq!(f.a.active.status, Status::Ready);
    assert!(matches!(f.a.active.record, Record::Empty));
}

// --- wire protocol ---

#[test]
fn proto_release_roundtrip() {
    let (rel, part_pk, chip_pk, bundle, frontier0) = valid_release();
    let back = rel.to_pb().to_release().unwrap();
    assert_eq!(back.cert.sigma_chip, rel.cert.sigma_chip);
    assert_eq!(back.cert.sigma_host, rel.cert.sigma_host);
    assert_eq!(back.cert.next_frontier, rel.cert.next_frontier);
    let c = ctx(&bundle, &chip_pk, &part_pk, &frontier0);
    accept_offline::<_, MockChip, MockPart>(&back, &c, &Dsm::ok()).unwrap();
}

#[test]
fn service_handle_full_flow() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;

    let prep = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
        sender_device_root_before: R_I.to_vec(),
        sender_device_root_after: R_NEXT.to_vec(),
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&prep))).unwrap();
    assert!(r.ok, "prepare failed: {}", r.error);

    let commit = pb::ApplianceRequest {
        op: pb::Op::Commit as i32,
        ..Default::default()
    };
    assert!(
        decode_response(&handle(&mut f.a, &encode_request(&commit)))
            .unwrap()
            .ok
    );

    let emit = pb::ApplianceRequest {
        op: pb::Op::Emit as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&emit))).unwrap();
    assert!(r.ok);
    let rel = r.release.unwrap().to_release().unwrap();
    let c = ctx(&f.bundle, &f.chip_pk, &f.part_pk, &f.frontier0);
    accept_offline::<_, MockChip, MockPart>(&rel, &c, &Dsm::ok()).unwrap();

    let fin = pb::ApplianceRequest {
        op: pb::Op::Finalize as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&fin))).unwrap();
    assert_eq!(r.active_root, next_frontier.to_vec());

    let status = pb::ApplianceRequest {
        op: pb::Op::Status as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&status))).unwrap();
    assert_eq!(r.active_anchor_counter, 1);
    assert_eq!(r.status, 0);
    assert_eq!(r.pin_chip_pk, f.chip_pk);
}

#[test]
fn service_rejects_host_boot() {
    // The former OP_BOOT (wire value 1) is reserved: boot is device-internal, so a host
    // frame carrying it must be rejected as an unknown op.
    let mut f = fixture(H0);
    let req = pb::ApplianceRequest {
        op: 1,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&req))).unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, err::BAD_OP);
}
