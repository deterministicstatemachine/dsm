//! End-to-end tests for the v2 **Software Authority, Hardware Identity** appliance: the
//! 3-state transfer lifecycle, the producer→receiver round trip through the Def. 12
//! acceptance predicate, §26 recovery, and the wire protocol. Uniqueness is software (the
//! DSM device SMT); the appliance supplies `σ^chip` + `σ^host` over one root-advance message.
#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]

use anchor_core::accept::{
    accept_offline, AcceptError, DsmVerifier, OfflineStateRefused, VerifierContext,
};
use anchor_core::appliance::{
    owner_authorization_digest, Appliance, ApplianceError, BootRecoveryRefusal, Record,
    RecoverOutcome, Status,
};
use anchor_core::enrollment::{birth, BirthInputs, Install};
use anchor_core::proto::{decode_response, encode_request, pb};
use anchor_core::root_advance::{
    anchor_root_advance, transition_digest, OfflineRelease, OwnedTransition,
};
use anchor_core::service::{err, handle};
use anchor_core::tropic::{ChipSig, PartitionError, PartitionSig, Tropic, TropicError};
use ed25519_dalek::{Signer, SigningKey};

const H0: u32 = 100;
const ANCHOR: [u8; 32] = [0xAA; 32];
const PART_DEV: [u8; 32] = [0xBD; 32];
const DEVICE: [u8; 32] = [0x77; 32];
const GENESIS_ROOT: [u8; 32] = [0x11; 32];
const POLICY: [u8; 32] = [0x33; 32];
const RECIP: [u8; 32] = [0x44; 32];
const RCHAL: [u8; 32] = [0x55; 32];
// Sender device SMT roots supplied by the DSM layer for a transfer (the appliance signs over
// them; the receiver's DsmVerifier proves their SMT inclusion — mocked true here).
const R_I: [u8; 32] = [0x51; 32];
const R_NEXT: [u8; 32] = [0x52; 32];

type App = Appliance<Chip, Partition>;

const PARTITION: dsm_sphincs::SphincsVariant = dsm_sphincs::SphincsVariant::SPX128f;

// --- the appliance's parts, and the receiver's own checks ---

/// A TROPIC01 as the appliance sees it: a monotonic down-counter and a resident Ed25519 key.
/// `σ^chip` is that key's signature, which only its holder can make; the receiver verifies
/// it under the pinned `pk_chip`.
struct Chip {
    h: u32,
    start: u32,
    resident: SigningKey,
    closed_births: u32,
}
impl Chip {
    fn with_h(h: u32) -> Self {
        Self {
            h,
            start: h,
            resident: SigningKey::from_bytes(&[0xC0; 32]),
            closed_births: 0,
        }
    }
    fn pk(&self) -> Vec<u8> {
        self.resident.verifying_key().to_bytes().to_vec()
    }
}
impl Tropic for Chip {
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
        Ok(self.resident.sign(message).to_bytes().to_vec())
    }
    fn chip_signature_holds(&self, pk_chip: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        matches!(
            (<[u8; 32]>::try_from(pk_chip), <[u8; 64]>::try_from(signature)),
            (Ok(key), Ok(signature)) if matches!(
                ed25519_dalek::VerifyingKey::from_bytes(&key).and_then(|key| key
                    .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))),
                Ok(())
            )
        )
    }

    fn set_counter_back(&mut self) -> Result<(), TropicError> {
        self.h = self.start;
        Ok(())
    }

    fn rehearse_birth(&mut self) -> Vec<anchor_core::try_run::TryStep> {
        vec![anchor_core::try_run::TryStep::new(
            "this software chip's counter reads",
            self.counter_get().map(|_| ()).map_err(|e| format!("{e:?}")),
        )]
    }

    fn challenge_entropy(&mut self) -> Result<anchor_core::tropic::ChallengeEntropy, TropicError> {
        Ok(anchor_core::tropic::ChallengeEntropy {
            board: software_entropy(),
            chip: software_entropy(),
        })
    }

    fn close_birth(&mut self) -> Result<(), TropicError> {
        self.closed_births += 1;
        Ok(())
    }
}

/// Receiver-side verification of the resident chip signature (`σ^chip`), Ed25519.
struct Ed25519Chip;
impl ChipSig for Ed25519Chip {
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let key: Result<[u8; 32], _> = pk_chip.try_into();
        let signature: Result<[u8; 64], _> = sig.try_into();
        matches!(
            (key, signature),
            (Ok(key), Ok(signature)) if matches!(
                ed25519_dalek::VerifyingKey::from_bytes(&key).map(|vk| vk
                    .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))),
                Ok(Ok(()))
            )
        )
    }
}

/// The partition key (`σ^host`), BLAKE3-SPHINCS+ SPX128f as on the RP2350.
struct Partition;
impl PartitionSig for Partition {
    fn part_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError> {
        let kp =
            dsm_sphincs::generate_keypair_from_seed(PARTITION, seed).map_err(partition_error)?;
        Ok((kp.secret_key.clone(), kp.public_key.clone()))
    }
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError> {
        dsm_sphincs::sign(PARTITION, sk, digest).map_err(partition_error)
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        matches!(dsm_sphincs::verify(PARTITION, pk, digest, sig), Ok(valid) if valid)
    }
    fn owner_verify(pk_on: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        matches!(dsm_sphincs::verify(dsm_sphincs::SphincsVariant::SPX256f, pk_on, digest, sig), Ok(valid) if valid)
    }
    fn owner_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError> {
        let kp =
            dsm_sphincs::generate_keypair_from_seed(dsm_sphincs::SphincsVariant::SPX256f, seed)
                .map_err(partition_error)?;
        Ok((kp.secret_key.clone(), kp.public_key.clone()))
    }
    fn owner_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError> {
        dsm_sphincs::sign(dsm_sphincs::SphincsVariant::SPX256f, sk, digest).map_err(partition_error)
    }
}

/// The SPHINCS+ failure, as the partition reports it.
fn partition_error(e: dsm_sphincs::Error) -> PartitionError {
    match e {
        dsm_sphincs::Error::Crypto(dsm_sphincs::CryptoFailure::BadSecretKeySize) => {
            PartitionError::SecretKey
        }
        dsm_sphincs::Error::Crypto(
            dsm_sphincs::CryptoFailure::EmptySigningMessage
            | dsm_sphincs::CryptoFailure::EmptyVerificationMessage,
        ) => PartitionError::Message,
        dsm_sphincs::Error::Crypto(dsm_sphincs::CryptoFailure::SignerSelfCheck) => {
            PartitionError::SelfCheck
        }
    }
}

/// Receiver DSM verifier: software checks are flag-controlled so individual false paths can
/// be tested. `σ^DSM` is `transition_ok`; SMT inclusion is `smt_ok`.
struct Dsm {
    smt_ok: bool,
    transition_ok: bool,
}
impl Dsm {
    fn ok() -> Self {
        Self {
            smt_ok: true,
            transition_ok: true,
        }
    }
}
impl DsmVerifier for Dsm {
    fn verify_offline_state(
        &self,
        _r: &[u8; 32],
        _b: &[u8; 32],
        _f: &[u8; 32],
        _u: u64,
        _p: &[u8],
    ) -> Result<(), OfflineStateRefused> {
        if self.smt_ok {
            Ok(())
        } else {
            Err(OfflineStateRefused)
        }
    }
    fn verify_transition(&self, _d: &[u8; 32], _p: &[u8; 32], _n: &[u8; 32]) -> bool {
        self.transition_ok
    }
}

// --- helpers ---

/// The owner's device key, BLAKE3-SPHINCS+ SPX256f from a fixed seed: the key the anchors here are
/// provisioned for, whose signature authorizes a prepare.
fn owner_key() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    KEY.get_or_init(|| match Partition::owner_keygen(&[0x0A; 32]) {
        Ok(key) => key,
        Err(e) => panic!("the owner's key: {e:?}"),
    })
}

/// The owner-authorization digest of preparing `t` on `a`, under challenge `rc` with device roots
/// `before`/`after`, and the owner's signature of it.
fn owner_authorization<T: Tropic, P: PartitionSig>(
    a: &Appliance<T, P>,
    t: &OwnedTransition,
    rc: &[u8; 32],
    before: &[u8; 32],
    after: &[u8; 32],
) -> ([u8; 32], Vec<u8>) {
    let digest = owner_authorization_digest(
        &a.bundle,
        &a.active.root,
        t.anchor_counter,
        &transition_digest(&t.as_transition(), rc),
        before,
        after,
    );
    (digest, owner_sign(&digest))
}

fn owner_sign(digest: &[u8; 32]) -> Vec<u8> {
    match Partition::owner_sign(&owner_key().0, digest) {
        Ok(sig) => sig,
        Err(e) => panic!("the owner signs: {e:?}"),
    }
}

/// The owner authorizes preparing `t` on `a`: the authorization it then holds for that prepare.
fn authorize<T: Tropic, P: PartitionSig>(
    a: &mut Appliance<T, P>,
    t: &OwnedTransition,
    rc: &[u8; 32],
    before: &[u8; 32],
    after: &[u8; 32],
) {
    let (digest, signature) = owner_authorization(a, t, rc, before, after);
    a.authorize(&digest, &signature).unwrap();
}

/// An `OP_AUTHORIZE` frame as it goes over the wire: the message, then the signature after it.
fn authorize_frame(digest: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut frame = encode_request(&pb::ApplianceRequest {
        op: pb::Op::Authorize as i32,
        authorization_digest: digest.to_vec(),
        ..Default::default()
    });
    frame.extend_from_slice(signature);
    frame
}

struct Fixture {
    a: App,
    part_pk: Vec<u8>,
    chip_pk: Vec<u8>,
    bundle: [u8; 32],
    frontier0: [u8; 32],
}

fn fixture(h: u32) -> Fixture {
    let chip_pk = Chip::with_h(0).pk(); // deterministic (csk fixed)
    let b = birth::<Partition>(&BirthInputs {
        birth_entropy: &[0x01; 32],
        chip_birth_witness: &[0x02; 32],
        host_nonce: &[0x03; 32],
        device_id: &DEVICE,
        policy_hash: &POLICY,
        partition_device_id: &PART_DEV,
        anchor_id: &ANCHOR,
        chip_pk: &chip_pk,
        online_id_pk: &owner_key().1,
        partition_key_seed: &[0x04; 32],
        enrolled_counter: H0,
        genesis_root: &GENESIS_ROOT,
    })
    .expect("the anchor is born");
    let part_pk = b.partition_pk.clone();
    let bundle = b.bundle;
    let frontier0 = b.genesis_frontier;
    let a = Appliance::new(
        Chip::with_h(h),
        H0,
        ANCHOR,
        PART_DEV,
        b,
        Install::ForGood,
        owner_key().1.clone(),
    );
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
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
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
    }
}

// --- lifecycle ---

#[test]
fn full_lifecycle_prepare_commit_emit_finalize() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;

    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
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
    authorize(&mut f.a, &t0, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t0.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    assert_eq!(f.a.finalize().unwrap(), frontier1);

    let t1 = make_transition(frontier1, 1);
    let frontier2 = t1.next_root;
    authorize(&mut f.a, &t1, &RCHAL, &R_I, &R_NEXT);
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
    accept_offline::<_, Ed25519Chip, Partition>(&rel, &c, &Dsm::ok()).unwrap();
}

#[test]
fn accept_rejects_wrong_chip_key() {
    let (rel, part_pk, _chip_pk, bundle, frontier0) = valid_release();
    let wrong = [0xEE; 32];
    let c = ctx(&bundle, &wrong, &part_pk, &frontier0);
    assert_eq!(
        accept_offline::<_, Ed25519Chip, Partition>(&rel, &c, &Dsm::ok()),
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
        accept_offline::<_, Ed25519Chip, Partition>(&rel, &c, &d),
        Err(AcceptError::PrevStateUncommitted)
    );
    let d = Dsm {
        transition_ok: false,
        ..Dsm::ok()
    };
    assert_eq!(
        accept_offline::<_, Ed25519Chip, Partition>(&rel, &c, &d),
        Err(AcceptError::TransitionProofInvalid)
    );
}

// --- §26 recovery ---

#[test]
fn recover_ready_accepts() {
    let mut f = fixture(H0);
    assert_eq!(f.a.recover(), RecoverOutcome::Accept(f.frontier0));
}

#[test]
fn recover_committed_reemits() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
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
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    assert_eq!(f.a.recover(), RecoverOutcome::AcceptPreparedCanComplete);
}

#[test]
fn recover_ready_fails_closed_when_the_chip_counter_disagrees_with_the_software_counter() {
    // Chip advanced past the software counter: a transition moved the mirror that the active
    // frontier never recorded. Recovery must not pair the advanced counter with the old frontier.
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    f.a.finalize().unwrap(); // chip counter at H0 - 1, u = 1
    f.a.active.anchor_counter = 0; // software counter behind the chip mirror
    let root = f.a.active.root;
    assert_eq!(f.a.recover(), RecoverOutcome::FailClosed);
    assert_eq!(f.a.active.anchor_counter, 0);
    assert_eq!(f.a.active.root, root);
    assert_eq!(f.a.active.status, Status::Ready);
    assert!(matches!(f.a.active.record, Record::Empty));

    // Software counter ahead of the chip mirror: impossible for a real down-counter.
    let mut f = fixture(H0);
    f.a.active.anchor_counter = 5;
    assert_eq!(f.a.recover(), RecoverOutcome::FailClosed);
    assert_eq!(f.a.active.anchor_counter, 5);
    assert_eq!(f.a.active.root, f.frontier0);
    assert_eq!(f.a.active.status, Status::Ready);
    assert!(matches!(f.a.active.record, Record::Empty));
}

// --- §26 recovery at boot (a device serving the appliance itself) ---

#[test]
fn recover_at_boot_serves_a_ready_appliance_whose_counters_agree() {
    let mut f = fixture(H0);
    assert_eq!(f.a.recover_at_boot(), Ok(()));
    assert_eq!(f.a.active.root, f.frontier0);
    assert_eq!(f.a.active.status, Status::Ready);
}

#[test]
fn recover_at_boot_refuses_a_chip_counter_advanced_past_the_software_counter() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    f.a.finalize().unwrap();
    f.a.active.anchor_counter = 0;
    assert_eq!(
        f.a.recover_at_boot(),
        Err(BootRecoveryRefusal::Outcome(RecoverOutcome::FailClosed))
    );
}

/// A prepared record that would not complete is still only prepared: its counter did not move and
/// it was never exported. The boot resets it as any other, and the anchor does not die of it.
#[test]
fn recover_at_boot_resets_a_prepared_record_missing_its_signatures() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    if let Record::Prepared(p) = &mut f.a.active.record {
        p.cert.sigma_host.clear();
    }
    assert_eq!(f.a.recover(), RecoverOutcome::OnlineCancelOrResolve);
    assert_eq!(f.a.recover_at_boot(), Ok(()));
    assert_eq!(f.a.active.status, Status::Ready);
    assert!(matches!(f.a.active.record, Record::Empty));
}

#[test]
fn recover_at_boot_resets_a_prepared_record_whose_counter_did_not_move() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    assert_eq!(f.a.recover_at_boot(), Ok(()));
    assert_eq!(f.a.active.status, Status::Ready);
    assert!(matches!(f.a.active.record, Record::Empty));
    assert_eq!(f.a.active.root, f.frontier0);
    assert_eq!(f.a.active.anchor_counter, 0);
}

#[test]
fn recover_at_boot_serves_a_committed_release_for_reemission() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let next_frontier = t.next_root;
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    f.a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT)
        .unwrap();
    f.a.commit().unwrap();
    assert_eq!(f.a.recover_at_boot(), Ok(()));
    // The committed record survives for the same successor to be re-emitted and finalized.
    assert_eq!(f.a.emit().unwrap().cert.next_frontier, next_frontier);
    assert_eq!(f.a.finalize().unwrap(), next_frontier);
}

#[test]
fn cancel_returns_to_ready() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
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
    accept_offline::<_, Ed25519Chip, Partition>(&back, &c, &Dsm::ok()).unwrap();
}

/// An anchor signs nothing for a prepare its owner did not authorize, whoever holds the link to
/// it. No authorization, a stranger's signature, the owner's authorization of another payment, of
/// other device roots, or of this payment from a frontier the anchor does not stand at: each leaves
/// the prepare refused, nothing signed or recorded, the anchor Ready at its frontier with its
/// counter unmoved. Its owner's own authorization of this prepare is then taken. MUTATION CONTROL:
/// deleting the owner check in `Appliance::prepare` lets each through: red at "no authorization".
#[test]
fn a_prepare_its_owner_did_not_authorize_signs_nothing() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let (digest, _) = owner_authorization(&f.a, &t, &RCHAL, &R_I, &R_NEXT);
    let prepare = |a: &mut App| a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT);

    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "no authorization"
    );

    let (stranger, _) = match Partition::owner_keygen(&[0x0B; 32]) {
        Ok(key) => key,
        Err(e) => panic!("a stranger's key: {e:?}"),
    };
    let strangers = match Partition::owner_sign(&stranger, &digest) {
        Ok(sig) => sig,
        Err(e) => panic!("the stranger signs: {e:?}"),
    };
    assert_eq!(
        f.a.authorize(&digest, &strangers),
        Err(ApplianceError::OwnerUnauthorized),
        "a stranger's signature over the very digest authorizes nothing"
    );
    assert_eq!(prepare(&mut f.a), Err(ApplianceError::OwnerUnauthorized));

    // The owner authorized another payment: a different challenge.
    authorize(&mut f.a, &t, &[0x56; 32], &R_I, &R_NEXT);
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "an authorization of another payment"
    );
    // ... and other device roots.
    authorize(&mut f.a, &t, &RCHAL, &R_NEXT, &R_I);
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "an authorization over other device roots"
    );
    // ... and this payment from a frontier the anchor does not stand at (stale, or another anchor's).
    let elsewhere = owner_authorization_digest(
        &f.a.bundle,
        &[0x99; 32],
        0,
        &transition_digest(&t.as_transition(), &RCHAL),
        &R_I,
        &R_NEXT,
    );
    f.a.authorize(&elsewhere, &owner_sign(&elsewhere)).unwrap();
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "an authorization from another frontier"
    );

    assert_eq!(f.a.active.status, Status::Ready);
    assert_eq!(f.a.active.root, f.frontier0);
    assert!(matches!(f.a.active.record, Record::Empty));
    assert_eq!(f.a.live_index(), Ok(0), "the counter has not moved");

    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(
        prepare(&mut f.a),
        Ok(()),
        "its owner's own authorization is taken"
    );
    assert_eq!(f.a.active.status, Status::Prepared);
}

/// An authorization serves one prepare. The prepare that claims it consumes it, whether it then
/// goes through or is refused for naming another payment; a cancelled prepare does not give it
/// back; and a later one replaces an earlier one. MUTATION CONTROL: keeping the authorization after
/// a prepare (a `clone` in place of the `take`) lets the second prepare through: red at "reuse".
#[test]
fn an_authorization_serves_one_prepare_and_is_consumed_with_it() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let prepare = |a: &mut App| a.prepare(&t.as_transition(), &RCHAL, &R_I, &R_NEXT);

    // Consumed by the prepare it allowed: cancelled, the same prepare needs a new one.
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(prepare(&mut f.a), Ok(()));
    f.a.cancel().unwrap();
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "reuse"
    );

    // A prepare refused before the owner check (here its successor frontier is not the derived
    // one) leaves the authorization standing: nothing was signed and nothing consumed it.
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(
        f.a.prepare(&t.as_transition(), &[0x57; 32], &R_I, &R_NEXT),
        Err(ApplianceError::NextRootMismatch)
    );
    // Consumed by a prepare it did not allow, too: one that passes every structural check but
    // names other device roots spends it.
    assert_eq!(
        f.a.prepare(&t.as_transition(), &RCHAL, &R_NEXT, &R_I),
        Err(ApplianceError::OwnerUnauthorized),
        "another payment under the standing authorization"
    );
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "the mismatch consumed it"
    );

    // A later authorization replaces an earlier one: only the latest stands.
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    authorize(&mut f.a, &t, &[0x58; 32], &R_I, &R_NEXT);
    assert_eq!(
        prepare(&mut f.a),
        Err(ApplianceError::OwnerUnauthorized),
        "the earlier authorization no longer stands"
    );

    // One that does not verify drops the one standing.
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    let (digest, _) = owner_authorization(&f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(
        f.a.authorize(&digest, &[0u8; 8]),
        Err(ApplianceError::OwnerUnauthorized)
    );
    assert_eq!(prepare(&mut f.a), Err(ApplianceError::OwnerUnauthorized));

    // Not taken while a prepare stands: the anchor is not Ready.
    authorize(&mut f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(prepare(&mut f.a), Ok(()));
    assert_eq!(
        f.a.authorize(&digest, &owner_sign(&digest)),
        Err(ApplianceError::WrongState)
    );
}

/// Over the wire: an authorization is the message and the signature after it, verified from the
/// frame itself. A prepare without one is refused with its own code; an authorization frame with
/// no signature, a signature after any other op, and a message longer than a request's largest are
/// each refused unread. The authorized prepare then goes through.
#[test]
fn over_the_wire_an_authorization_is_the_message_and_the_signature_after_it() {
    let mut f = fixture(H0);
    let t = make_transition(f.frontier0, 0);
    let prep = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
        sender_device_root_before: R_I.to_vec(),
        sender_device_root_after: R_NEXT.to_vec(),
        ..Default::default()
    };
    let r = decode_response(&handle(&mut f.a, &encode_request(&prep))).unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, err::OWNER_UNAUTHORIZED);

    let (digest, signature) = owner_authorization(&f.a, &t, &RCHAL, &R_I, &R_NEXT);
    assert_eq!(
        signature.len(),
        anchor_core::service::OWNER_AUTHORIZATION_BYTES
    );
    let no_signature = authorize_frame(&digest, &[]);
    let r = decode_response(&handle(&mut f.a, &no_signature)).unwrap();
    assert_eq!(r.error, err::MISSING_FIELD);

    let mut signed_prepare = encode_request(&prep);
    signed_prepare.extend_from_slice(&signature);
    let r = decode_response(&handle(&mut f.a, &signed_prepare)).unwrap();
    assert_eq!(r.error, err::BAD_PROTO, "a signature after any other op");

    let mut too_long = prep.clone();
    too_long.transition = Some(make_transition(f.frontier0, 0).to_pb());
    if let Some(transition) = too_long.transition.as_mut() {
        transition.old_leaf_proof = vec![0xAB; anchor_core::service::REQUEST_HEAD_MAX];
    }
    let r = decode_response(&handle(&mut f.a, &encode_request(&too_long))).unwrap();
    assert_eq!(
        r.error,
        err::FRAME_TOO_LARGE,
        "a message longer than a request's largest"
    );

    // The same message behind a first field that names a payment check: the decoder keeps the op
    // named last, the prepare. It is not served at a payment check's size.
    let mut disguised = vec![0x08, pb::Op::CheckPayment as u8];
    disguised.extend_from_slice(&encode_request(&too_long));
    let r = decode_response(&handle(&mut f.a, &disguised)).unwrap();
    assert_eq!(
        r.error,
        err::FRAME_TOO_LARGE,
        "a prepare let in at a payment check's size"
    );
    assert_eq!(r.op, pb::Op::Prepare as i32);
    assert_eq!(f.a.active.status, Status::Ready);

    let r = decode_response(&handle(&mut f.a, &authorize_frame(&digest, &signature))).unwrap();
    assert!(r.ok, "authorize: error {}", r.error);
    assert_eq!(r.op, pb::Op::Authorize as i32);
    let r = decode_response(&handle(&mut f.a, &encode_request(&prep))).unwrap();
    assert!(r.ok, "prepare: error {}", r.error);
    assert_eq!(f.a.active.status, Status::Prepared);
}

/// The owner's authorization is one SPX256f signature: the length the frame decoder splits at is
/// the scheme's.
#[test]
fn owner_authorization_is_one_spx256f_signature() {
    assert_eq!(
        anchor_core::service::OWNER_AUTHORIZATION_BYTES,
        dsm_sphincs::signature_bytes(dsm_sphincs::SphincsVariant::SPX256f)
    );
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
    let (digest, signature) = owner_authorization(&f.a, &t, &RCHAL, &R_I, &R_NEXT);
    let r = decode_response(&handle(&mut f.a, &authorize_frame(&digest, &signature))).unwrap();
    assert!(r.ok, "authorize failed: {}", r.error);
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
    accept_offline::<_, Ed25519Chip, Partition>(&rel, &c, &Dsm::ok()).unwrap();

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

/// 32 bytes from the process's own randomness: this software chip's generator.
fn software_entropy() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    let drawn: Vec<u8> = (0..4u8)
        .flat_map(|lane| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u8(lane);
            hasher.finish().to_le_bytes()
        })
        .collect();
    match drawn.try_into() {
        Ok(bytes) => bytes,
        Err(short) => panic!("four lanes of eight bytes, not {}", short.len()),
    }
}
