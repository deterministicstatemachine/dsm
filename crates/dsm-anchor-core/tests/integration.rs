//! End-to-end tests for the Boot Fenced Fused Anchor appliance: the boot fence,
//! the 3-state transfer lifecycle, the §22 (Def. 30) 24-check receiver predicate
//! (valid + representative tampered checks), §27 recovery, and the wire protocol.
#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]

use anchor_core::accept::{
    accept_offline, AcceptError, CounterVerifier, DsmVerifier, VerifierContext,
};
use anchor_core::appliance::{Appliance, ApplianceError, Record, RecoverOutcome, Status};
use anchor_core::boot::BootTicket;
use anchor_core::enrollment::{birth, BirthInputs};
use anchor_core::proto::{decode_request, decode_response, encode_request, pb};
use anchor_core::root_advance::{
    CounterAdvanceBinding, CounterAdvanceEvidence, CounterAdvanceReads, CounterEvidenceError,
    OfflineRelease, OwnedTransition, Transition,
};
use anchor_core::service::{err, handle};
use anchor_core::sig::WotsBlake3;
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};

const H0: u32 = 100;
const ANCHOR: [u8; 32] = [0xAA; 32];
const Q_BOOT: u16 = 1;
const Q_TX: u16 = 2;
const PART_DEV: [u8; 32] = [0xBD; 32];
const DEVICE: [u8; 32] = [0x77; 32];
const ROOT0: [u8; 32] = [0x11; 32];
const ROOT1: [u8; 32] = [0x22; 32];
const POLICY: [u8; 32] = [0x33; 32];
const RECIP: [u8; 32] = [0x44; 32];
const RCHAL: [u8; 32] = [0x55; 32];
const FW: [u8; 32] = [0xF0; 32];

type App = Appliance<MockTropic, WotsBlake3, MockPart>;

// --- mocks ---

struct MockTropic {
    h: u32,
    secret: [u8; 32],
}
impl MockTropic {
    fn with_h(h: u32) -> Self {
        Self {
            h,
            secret: [0xC0; 32],
        }
    }
}
impl Tropic for MockTropic {
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError> {
        Ok(anchor_core::hash::kdf(
            &self.secret,
            "test/macandd",
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

/// Deterministic mock partition signature: `sk = pk = seed`; signature = keyed
/// hash over the digest. Exercises the cross-binding + partition-cert checks.
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

/// Receiver DSM verifier. The boot-chain and partition-cert checks are real
/// (using the pinned partition pubkey); the SMT-state checks are flag-controlled
/// so individual false paths can be tested.
struct Dsm {
    part_pk: Vec<u8>,
    prev_commits: bool,
    transition_ok: bool,
    delivers: bool,
    next_commits: bool,
}
impl Dsm {
    fn ok(part_pk: &[u8]) -> Self {
        Self {
            part_pk: part_pk.to_vec(),
            prev_commits: true,
            transition_ok: true,
            delivers: true,
            next_commits: true,
        }
    }
}
impl DsmVerifier for Dsm {
    fn sender_device_root_before_commits_anchor_state(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: u64,
    ) -> bool {
        self.prev_commits
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
            {
                return false;
            }
            if !MockPart::part_verify(
                &self.part_pk,
                &tk.cert_message(),
                &tk.partition_boot_signature,
            ) {
                return false;
            }
            prev = tk.next_boot_head;
        }
        &prev == current_boot_head
    }
    fn verify_partition_certificate(&self, m_p: &[u8; 32], sigma_partition: &[u8]) -> bool {
        MockPart::part_verify(&self.part_pk, m_p, sigma_partition)
    }
    fn verify_transition(&self, _: &Transition) -> bool {
        self.transition_ok
    }
    fn delivers_to_receiver(&self, _: &Transition) -> bool {
        self.delivers
    }
    fn sender_device_root_after_commits_anchor_state(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: &[u8; 32],
        _: u64,
    ) -> bool {
        self.next_commits
    }
}

/// A faithful chip: verifies the transition binding, then returns the two live counter
/// values the producer witnessed (`H_pre` at the FROM coordinate, `H_post` at the TO
/// coordinate) — the `attested_raw_counter` each read names (a real verifier session
/// would read the same live values off the pinned chip).
struct OkCounter;
impl CounterVerifier for OkCounter {
    fn verify_counter_advance(
        &self,
        pinned: &[u8; 32],
        ev: &CounterAdvanceEvidence,
        binding: &CounterAdvanceBinding,
    ) -> Result<CounterAdvanceReads, CounterEvidenceError> {
        ev.check_binding(pinned, binding)?;
        Ok(CounterAdvanceReads {
            pre_raw_counter: ev.pre.attested_raw_counter,
            post_raw_counter: ev.post.attested_raw_counter,
        })
    }
}

// --- helpers ---

fn app(h: u32) -> (App, Vec<u8>, [u8; 32]) {
    let b = birth::<MockPart>(&BirthInputs {
        partition_trng: &[0x01; 32],
        tropic_birth_witness: &[0x02; 32],
        host_nonce: &[0x03; 32],
        device_id: &DEVICE,
        policy_hash: &POLICY,
        partition_device_id: &PART_DEV,
        tropic_anchor_id: &ANCHOR,
        partition_key_seed: &[0x04; 32],
        enrolled_counter: H0,
        q_boot: Q_BOOT,
        q_tx: Q_TX,
        genesis_root: &ROOT0,
    });
    let part_pk = b.partition_pk.clone();
    let bundle = b.bundle;
    let a = Appliance::new(
        MockTropic::with_h(h),
        H0,
        ANCHOR,
        Q_BOOT,
        Q_TX,
        PART_DEV,
        ROOT0,
        b,
    );
    (a, part_pk, bundle)
}

fn make_transition(
    prev_root: [u8; 32],
    next_root: [u8; 32],
    anchor_counter: u64,
) -> OwnedTransition {
    OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: [3; 32],
        recipient_device_id: RECIP,
        prev_root,
        next_root,
        anchor_counter,
        next_anchor_counter: anchor_counter + 1,
        action_type: 0,
        action_fields: vec![9, 9, 9],
        payload_hash: [6; 32],
        old_leaf_proof: vec![0xAB; 40],
        new_leaf_proof: vec![0xCD; 40],
        authority_policy_hash: POLICY,
    }
}

/// boot → prepare → commit → emit, returning a valid release + the pinned pubkey
/// and bundle the receiver needs.
fn valid_release() -> (OfflineRelease, Vec<u8>, [u8; 32]) {
    let (mut a, part_pk, bundle) = app(H0);
    a.boot(1, &FW).unwrap();
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    let rel = a.emit().unwrap().clone();
    (rel, part_pk, bundle)
}

/// The sender device SMT roots the receiver binds the counter advance to. The appliance
/// stamps zero device roots (it cannot know them — see `appliance::commit`); the SDK
/// sender re-stamps with the real roots post-advance. In this self-contained test both
/// sides use zero, so an honest release binds; the `wrong sender device root` case flips
/// one on the receiver side to force a binding mismatch.
const DEVROOT_BEFORE: [u8; 32] = [0u8; 32];
const DEVROOT_AFTER: [u8; 32] = [0u8; 32];

fn ctx<'a>(bundle: &'a [u8; 32]) -> VerifierContext<'a> {
    VerifierContext {
        accepted_prev_root: &ROOT0,
        pinned_bundle: bundle,
        pinned_anchor_id: &ANCHOR,
        expected_receiver_challenge: &RCHAL,
        expected_policy_hash: &POLICY,
        enrolled_counter: H0 as u64,
        sender_device_root_before: &DEVROOT_BEFORE,
        sender_device_root_after: &DEVROOT_AFTER,
        anchor_uncompromised: true,
    }
}

fn check(rel: &OfflineRelease, c: &VerifierContext, part_pk: &[u8]) -> Result<(), AcceptError> {
    accept_offline::<WotsBlake3, _, _>(rel, c, &Dsm::ok(part_pk), &OkCounter)
}

// --- boot fence + lifecycle ---

#[test]
fn full_lifecycle_boot_prepare_commit_emit_finalize() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    assert!(a.active.boot_valid);
    let t = make_transition(ROOT0, ROOT1, 0);

    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.active.status, Status::Prepared);
    assert_eq!(a.active.root, ROOT0); // root stays until finalize

    a.commit().unwrap();
    assert_eq!(a.active.status, Status::Committed);
    assert_eq!(a.active.anchor_counter, 1);

    let rel = a.emit().unwrap().clone();
    assert_eq!(rel.cert.next_root, ROOT1);
    assert_eq!(rel.boot_chain.len(), 1);

    assert_eq!(a.finalize().unwrap(), ROOT1);
    assert_eq!(a.active.root, ROOT1);
    assert_eq!(a.active.anchor_counter, 1);
    assert_eq!(a.active.status, Status::Ready);
    assert_eq!(a.active.anchor_head, rel.cert.next_anchor_head);
}

#[test]
fn prepare_without_boot_is_rejected() {
    let (mut a, _pk, _b) = app(H0);
    let t = make_transition(ROOT0, ROOT1, 0);
    assert_eq!(
        a.prepare(&t.as_transition(), &RCHAL),
        Err(ApplianceError::NotBooted)
    );
}

#[test]
fn two_sequential_transfers_one_boot() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    let t0 = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t0.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    let a1 = a.finalize().unwrap();
    assert_eq!(a1, ROOT1);

    // No re-boot needed within the session; counter moved once so far.
    let root2 = [0x99; 32];
    let t1 = make_transition(ROOT1, root2, 1);
    a.prepare(&t1.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    assert_eq!(a.active.anchor_counter, 2);
    assert_eq!(a.finalize().unwrap(), root2);
}

// --- §22 acceptance predicate ---

#[test]
fn accept_valid_release() {
    let (rel, pk, b) = valid_release();
    check(&rel, &ctx(&b), &pk).unwrap();
}

#[test]
fn accept_rejects_noncanonical_and_unpinned() {
    let (rel, pk, b) = valid_release();
    let mut r = rel.clone();
    r.cert.next_anchor_counter += 1;
    assert_eq!(check(&r, &ctx(&b), &pk), Err(AcceptError::NonCanonical));

    let other = [0xFE; 32];
    let mut c = ctx(&b);
    c.accepted_prev_root = &other;
    assert_eq!(check(&rel, &c, &pk), Err(AcceptError::PrevRootNotAccepted));

    let mut c = ctx(&b);
    c.pinned_bundle = &other;
    assert_eq!(check(&rel, &c, &pk), Err(AcceptError::NonCanonical));
}

#[test]
fn accept_rejects_bad_boot_chain() {
    let (mut rel, pk, b) = valid_release();
    rel.boot_chain[0].partition_boot_signature[0] ^= 0xFF;
    assert_eq!(
        check(&rel, &ctx(&b), &pk),
        Err(AcceptError::BootChainInvalid)
    );
}

#[test]
fn accept_rejects_tampered_message_commit_input_pkhash_sig() {
    let (rel, pk, b) = valid_release();

    let mut r = rel.clone();
    r.cert.root_advance_message[0] ^= 0xFF;
    assert_eq!(check(&r, &ctx(&b), &pk), Err(AcceptError::MessageMismatch));

    let mut r = rel.clone();
    r.cert.partition_commitment[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::PartitionCommitMismatch)
    );

    let mut r = rel.clone();
    r.cert.tropic_transfer_input[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::WitnessInputMismatch)
    );

    let mut r = rel.clone();
    r.cert.pk_hash[0] ^= 0xFF;
    assert_eq!(check(&r, &ctx(&b), &pk), Err(AcceptError::PkHashMismatch));

    let mut r = rel.clone();
    r.cert.sigma_tropic[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::WitnessSigInvalid)
    );
}

#[test]
fn accept_rejects_partition_cert_and_next_anchor_head() {
    let (rel, pk, b) = valid_release();

    let mut r = rel.clone();
    r.cert.sigma_partition[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::PartitionCertInvalid)
    );

    let mut r = rel.clone();
    r.cert.next_anchor_head[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::NextAnchorHeadMismatch)
    );
}

#[test]
fn accept_rejects_dsm_state_failures() {
    let (rel, pk, b) = valid_release();
    let c = ctx(&b);
    let mut d = Dsm::ok(&pk);
    d.prev_commits = false;
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &d, &OkCounter),
        Err(AcceptError::PrevStateUncommitted)
    );
    let mut d = Dsm::ok(&pk);
    d.transition_ok = false;
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &d, &OkCounter),
        Err(AcceptError::TransitionProofInvalid)
    );
    let mut d = Dsm::ok(&pk);
    d.delivers = false;
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &d, &OkCounter),
        Err(AcceptError::NotDeliveredToReceiver)
    );
    let mut d = Dsm::ok(&pk);
    d.next_commits = false;
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &c, &d, &OkCounter),
        Err(AcceptError::NextStateUncommitted)
    );
}

#[test]
fn accept_rejects_counter_problems() {
    let (rel, pk, b) = valid_release();

    // Wrong post read (faithful chip returns attested_raw_counter) -> TO check fails.
    let mut r = rel.clone();
    r.counter.post.attested_raw_counter += 1;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::CounterToCoordinateInvalid)
    );

    // Wrong pre read -> FROM check fails first (the discriminating check).
    let mut r = rel.clone();
    r.counter.pre.attested_raw_counter += 1;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::CounterFromCoordinateInvalid)
    );

    // Inauthentic reads (no verifier slot / no live relay / read failed) -> evidence invalid.
    struct FailCounter;
    impl CounterVerifier for FailCounter {
        fn verify_counter_advance(
            &self,
            _: &[u8; 32],
            _: &CounterAdvanceEvidence,
            _: &CounterAdvanceBinding,
        ) -> Result<CounterAdvanceReads, CounterEvidenceError> {
            Err(CounterEvidenceError::Inauthentic)
        }
    }
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &ctx(&b), &Dsm::ok(&pk), &FailCounter),
        Err(AcceptError::CounterEvidenceInvalid)
    );

    // Breached RP2350 forges the claims, but the receiver's own chip reads disagree
    // with H0 - u_i / H0 - (u_i+1) (binding still verifies).
    struct LyingChip;
    impl CounterVerifier for LyingChip {
        fn verify_counter_advance(
            &self,
            pinned: &[u8; 32],
            ev: &CounterAdvanceEvidence,
            binding: &CounterAdvanceBinding,
        ) -> Result<CounterAdvanceReads, CounterEvidenceError> {
            ev.check_binding(pinned, binding)?;
            Ok(CounterAdvanceReads {
                pre_raw_counter: 42,
                post_raw_counter: 42,
            })
        }
    }
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &ctx(&b), &Dsm::ok(&pk), &LyingChip),
        Err(AcceptError::CounterFromCoordinateInvalid)
    );
}

/// §34.3 — the core double-spend rejection. A second release of the SAME
/// counter-positioned sender state, presented after the first commit advanced the
/// chip past `uᵢ`, fails the live FROM read (`H_pre != H0 − uᵢ`) on sight. Modeled
/// by a chip stuck one step ahead: it returns the post value for the pre read too.
#[test]
fn accept_rejects_same_from_coordinate_replay() {
    let (rel, pk, b) = valid_release();
    // The physical counter has moved to uᵢ+1 (H0-(uᵢ+1)); a replay still claims FROM
    // = uᵢ, so the receiver's live pre read no longer equals H0 - uᵢ.
    struct AdvancedChip {
        post: u64,
    }
    impl CounterVerifier for AdvancedChip {
        fn verify_counter_advance(
            &self,
            pinned: &[u8; 32],
            ev: &CounterAdvanceEvidence,
            binding: &CounterAdvanceBinding,
        ) -> Result<CounterAdvanceReads, CounterEvidenceError> {
            ev.check_binding(pinned, binding)?;
            Ok(CounterAdvanceReads {
                // The live FROM read is already at the TO coordinate — not `H0 − uᵢ`.
                pre_raw_counter: self.post,
                post_raw_counter: ev.post.attested_raw_counter,
            })
        }
    }
    let chip = AdvancedChip {
        post: rel.counter.post.attested_raw_counter,
    };
    assert_eq!(
        accept_offline::<WotsBlake3, _, _>(&rel, &ctx(&b), &Dsm::ok(&pk), &chip),
        Err(AcceptError::CounterFromCoordinateInvalid)
    );
}

/// §34.4/§34.5 — a read spliced from another transition (its `binding_hash` names a
/// different `anchor_id, r_R, D, M, R_i, R_{i+1}, hᵢ, hᵢ₊₁, uᵢ, uᵢ+1`) is rejected by the
/// binding check, even if its raw counter value is correct.
#[test]
fn accept_rejects_spliced_counter_read() {
    let (rel, pk, b) = valid_release();

    // Tampered envelope binding hash -> the receiver's recomputed binding disagrees.
    let mut r = rel.clone();
    r.counter.binding_hash[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::CounterBindingInvalid)
    );

    // Pre and post carry different bindings -> not one physical advance.
    let mut r = rel.clone();
    r.counter.pre.binding_hash[0] ^= 0xFF;
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::CounterPrePostMismatch)
    );

    // A read that names a different anchor -> not evidence for the pinned one.
    let mut r = rel.clone();
    r.counter.pre.anchor_id = [0xEE; 32];
    r.counter.post.anchor_id = [0xEE; 32];
    assert_eq!(
        check(&r, &ctx(&b), &pk),
        Err(AcceptError::CounterBindingInvalid)
    );

    // Wrong sender DEVICE root: the receiver binds the advance to the R_i it verified from
    // rel_proof_parent; a release stamped for a different device root fails closed here
    // (never conflated with the appliance frontier root).
    let mut c = ctx(&b);
    let other_dev = [0x7E; 32];
    c.sender_device_root_before = &other_dev;
    assert_eq!(check(&rel, &c, &pk), Err(AcceptError::CounterBindingInvalid));
}

#[test]
fn accept_rejects_compromise() {
    let (rel, pk, b) = valid_release();
    let mut c = ctx(&b);
    c.anchor_uncompromised = false;
    assert_eq!(check(&rel, &c, &pk), Err(AcceptError::AnchorCompromised));
}

// --- §27 recovery ---

#[test]
fn recover_ready_accepts_after_boot() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    assert_eq!(a.recover(), RecoverOutcome::Accept(ROOT0));
}

#[test]
fn recover_downgrades_without_boot() {
    let (mut a, _pk, _b) = app(H0);
    assert_eq!(a.recover(), RecoverOutcome::DowngradeOnline);
}

#[test]
fn recover_committed_reemits() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    assert_eq!(a.recover(), RecoverOutcome::ReemitCommitted(ROOT1));
    assert_eq!(a.emit().unwrap().cert.next_root, ROOT1);
    assert_eq!(a.finalize().unwrap(), ROOT1);
}

#[test]
fn recover_prepared_can_complete() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    assert_eq!(a.recover(), RecoverOutcome::AcceptPreparedCanComplete);
}

#[test]
fn recover_ready_stale_adopts_live_and_ahead_fails_closed() {
    // A Ready device whose model is BEHIND the chip (the normal state after any transfer + reboot,
    // since the counter is permanently below H0 and the appliance re-births at u=0) must ADOPT the
    // live counter — the chip is the source of truth. Adopting only shrinks the remaining budget and
    // cannot enable a double-spend.
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.commit().unwrap();
    a.finalize().unwrap(); // counter at 99, u=1
    a.active.anchor_counter = 0; // stale (behind the chip)
    let root = a.active.root;
    assert_eq!(a.recover(), RecoverOutcome::Accept(root)); // adopts live_u, ready to serve
    assert_eq!(a.active.anchor_counter, 1); // reconciled to the live chip counter

    // A device AHEAD of the chip (more spends than the down-counter shows) is impossible for a real
    // monotonic down-counter (it would have to rise) -> fail closed.
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    a.active.anchor_counter = 5; // ahead
    assert_eq!(a.recover(), RecoverOutcome::FailClosed);
}

#[test]
fn cancel_returns_to_ready() {
    let (mut a, _pk, _b) = app(H0);
    a.boot(1, &FW).unwrap();
    let t = make_transition(ROOT0, ROOT1, 0);
    a.prepare(&t.as_transition(), &RCHAL).unwrap();
    a.cancel().unwrap();
    assert_eq!(a.active.status, Status::Ready);
    assert!(matches!(a.active.record, Record::Empty));
}

// --- wire protocol ---

#[test]
fn proto_release_roundtrip() {
    let (rel, pk, b) = valid_release();
    let back = rel.to_pb().to_release().unwrap();
    assert_eq!(back.cert.sigma_tropic, rel.cert.sigma_tropic);
    assert_eq!(back.cert.sigma_partition, rel.cert.sigma_partition);
    assert_eq!(back.boot_chain.len(), 1);
    assert_eq!(back.cert.next_root, ROOT1);
    check(&back, &ctx(&b), &pk).unwrap();
}

#[test]
fn proto_request_roundtrip() {
    let t = make_transition(ROOT0, ROOT1, 0);
    let req = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
        ..Default::default()
    };
    let back = decode_request(&encode_request(&req)).unwrap();
    assert_eq!(back.op, pb::Op::Prepare as i32);
    let owned = back.transition.unwrap().to_owned_transition().unwrap();
    assert_eq!(owned.prev_root, ROOT0);
    assert_eq!(owned.next_anchor_counter, 1);
}

#[test]
fn service_handle_full_flow() {
    let (mut a, pk, b) = app(H0);

    // Boot is device-internal (device-authoritative measurement); the host wire
    // path has no boot op, so the fence is established directly.
    a.boot(1, &FW).unwrap();

    let t = make_transition(ROOT0, ROOT1, 0);
    let prep = pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: RCHAL.to_vec(),
        ..Default::default()
    };
    let r = decode_response(&handle(&mut a, &encode_request(&prep))).unwrap();
    assert!(r.ok, "prepare failed: {}", r.error);

    let commit = pb::ApplianceRequest {
        op: pb::Op::Commit as i32,
        ..Default::default()
    };
    assert!(
        decode_response(&handle(&mut a, &encode_request(&commit)))
            .unwrap()
            .ok
    );

    let emit = pb::ApplianceRequest {
        op: pb::Op::Emit as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut a, &encode_request(&emit))).unwrap();
    assert!(r.ok);
    let rel = r.release.unwrap().to_release().unwrap();
    check(&rel, &ctx(&b), &pk).unwrap();

    let fin = pb::ApplianceRequest {
        op: pb::Op::Finalize as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut a, &encode_request(&fin))).unwrap();
    assert_eq!(r.active_root, ROOT1.to_vec());

    let status = pb::ApplianceRequest {
        op: pb::Op::Status as i32,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut a, &encode_request(&status))).unwrap();
    assert_eq!(r.active_anchor_counter, 1);
    assert_eq!(r.status, 0);
    assert!(r.boot_valid);
}

#[test]
fn service_rejects_host_boot() {
    // The former OP_BOOT (wire value 1) is reserved: boot is device-internal, so a
    // host frame carrying it must be rejected as an unknown op — the host can never
    // drive a boot-head advance with an attacker-chosen firmware measurement.
    let (mut a, _pk, _b) = app(H0);
    let req = pb::ApplianceRequest {
        op: 1,
        ..Default::default()
    };
    let r = decode_response(&handle(&mut a, &encode_request(&req))).unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, err::BAD_OP);
    assert!(
        !a.active.boot_valid,
        "rejected host boot must not enable offline mode"
    );
}
