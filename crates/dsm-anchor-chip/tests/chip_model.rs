// SPDX-License-Identifier: MIT OR Apache-2.0
//! The anchor's birth, cage, spend and recovery on Tropic Square's TROPIC01 model: the code the
//! Secure monitor runs, with the chip's own access rules and reboot latch under it. See
//! `support/mod.rs` for what the model does and does not stand for.

mod support;

use anchor_chip::bring_up::{Measurement, ENROLL_H0};
use anchor_chip::session::CHIP_KEY_SLOT;
use anchor_core::accept::verify_cert_frontier_and_sigs;
use anchor_core::hash::{h, kdf};
use anchor_core::proto::pb;
use anchor_core::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use anchor_core::service::err;
use anchor_core::tropic::{ChipSig, HostSig};
use support::{
    provision_request, try_run_request, HostBoard, ModelChip, ModelCsn, ModelServer, ModelSpi,
    Served, SEALED,
};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{ActiveSession, EccCurve, Error as Fault, MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

const RECIPIENT: [u8; 32] = [0x44; 32];
const CHALLENGE: [u8; 32] = [0x55; 32];
const ROOT_BEFORE: [u8; 32] = [0x51; 32];
const ROOT_AFTER: [u8; 32] = [0x52; 32];
const POLICY: [u8; 32] = [0x33; 32];

fn booted(model: &ModelServer) -> Served {
    match model.boot() {
        Ok(anchor) => Served::new(anchor),
        Err(e) => panic!("the anchor did not come up: {e:?}"),
    }
}

fn provisioned(model: &ModelServer) -> Served {
    let mut anchor = booted(model);
    let answer = anchor.request(&provision_request());
    assert!(answer.ok, "provisioning refused: error {}", answer.error);
    anchor
}

/// The board's own pairing key, derived here from the labels the monitor derives it with.
fn own_pairing_key(chip: &mut ModelChip) -> StaticSecret {
    let chip_id = match chip.get_info_chip_id() {
        Ok(id) => h("DSM/anchor/chip-id/v1", &[id]),
        Err(e) => panic!("no chip id: {e:?}"),
    };
    let cert_store = match chip.get_info_cert_store() {
        Ok(store) => store,
        Err(e) => panic!("no certificate store: {e:?}"),
    };
    let stpub: [u8; 32] = match cert_store.public_key() {
        Ok(key) => *key,
        Err(e) => panic!("no chip key in the certificate: {e:?}"),
    };
    let root = h("DSM/anchor/chip-root/v1", &[&stpub, &chip_id]);
    StaticSecret::from(kdf(&SEALED, "DSM/anchor/pairing-key/v1", &[&root]))
}

fn ephemeral() -> StaticSecret {
    match anchor_chip::Board::random_key(&HostBoard) {
        Some(key) => StaticSecret::from(key),
        None => panic!("no entropy"),
    }
}

fn own_session(model: &ModelServer) -> Tropic01<ModelSpi, ModelCsn, ActiveSession> {
    let mut chip = model.power_cycle();
    let own = own_pairing_key(&mut chip);
    let eh = ephemeral();
    match chip.session_start(
        &X25519Dalek,
        PublicKey::from(&own),
        own,
        PublicKey::from(&eh),
        eh,
        1,
    ) {
        Ok(session) => session,
        Err((_chip, e)) => panic!("the board's own slot did not open: {e:?}"),
    }
}

fn factory_session(model: &ModelServer) -> Tropic01<ModelSpi, ModelCsn, ActiveSession> {
    let chip = model.power_cycle();
    let eh = ephemeral();
    match chip.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        PublicKey::from(&eh),
        eh,
        0,
    ) {
        Ok(session) => session,
        Err((_chip, e)) => panic!("the factory slot of an unborn chip did not open: {e:?}"),
    }
}

/// A closed birth: the factory slot does not open, and from the board's own slot the chip refuses,
/// as unauthorized, every command a second birth would use.
fn assert_birth_closed(model: &ModelServer) {
    let chip = model.power_cycle();
    let eh = ephemeral();
    match chip.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        PublicKey::from(&eh),
        eh,
        0,
    ) {
        Ok(_session) => panic!("the factory slot still opens"),
        Err((_chip, Fault::L2ResponseError(_handshake_refused))) => {}
        Err((_chip, e)) => panic!("the factory slot failed for another reason: {e:?}"),
    }

    let mut session = own_session(model);
    let key = [0x42u8; 32];
    assert!(matches!(
        session.mcounter_init(MCounterIndex::Index0, ENROLL_H0),
        Err(Fault::Unauthorized)
    ));
    assert!(matches!(
        session.mcounter_init(MCounterIndex::Index15, ENROLL_H0),
        Err(Fault::Unauthorized)
    ));
    for slot in 0u16..4 {
        assert!(
            matches!(
                session.pairing_key_write(slot.into(), &key),
                Err(Fault::Unauthorized)
            ),
            "pairing slot {slot} is still writable"
        );
        assert!(
            matches!(
                session.pairing_key_invalidate(slot.into()),
                Err(Fault::Unauthorized)
            ),
            "pairing slot {slot} can still be invalidated"
        );
    }
    for slot in [CHIP_KEY_SLOT, 8, 16, 31] {
        assert!(
            matches!(
                session.ecc_key_generate(slot.into(), EccCurve::Ed25519),
                Err(Fault::Unauthorized)
            ),
            "resident key slot {slot} can still be generated"
        );
        assert!(
            matches!(session.ecc_key_erase(slot.into()), Err(Fault::Unauthorized)),
            "resident key slot {slot} can still be erased"
        );
    }
    for register in [0x040u16, 0x150, 0x020, 0x130] {
        for bit in [0u8, 1, 8, 9] {
            assert!(
                matches!(
                    session.i_config_write(register.into(), bit),
                    Err(Fault::Unauthorized)
                ),
                "register {register:#x} bit {bit} is still writable"
            );
        }
    }
}

fn transition(prev_root: [u8; 32], counter: u64) -> OwnedTransition {
    // The digest leaves the successor root out, so it starts as the root it succeeds.
    let mut t = OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: [0x77; 32],
        recipient_device_id: RECIPIENT,
        prev_root,
        next_root: prev_root,
        anchor_counter: counter,
        next_anchor_counter: counter + 1,
        action_type: 0,
        action_fields: vec![9, 9, 9],
        payload_hash: [6; 32],
        old_leaf_proof: vec![0xAB; 40],
        new_leaf_proof: vec![0xCD; 40],
        authority_policy_hash: POLICY,
    };
    let digest = transition_digest(&t.as_transition(), &CHALLENGE);
    t.next_root = anchor_root_advance(&prev_root, &digest);
    t
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    match bytes.try_into() {
        Ok(array) => array,
        Err(e) => panic!("a 32-byte field: {e}"),
    }
}

fn prepare_request(root: [u8; 32], counter: u64) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(transition(root, counter).to_pb()),
        receiver_challenge: CHALLENGE.to_vec(),
        sender_device_root_before: ROOT_BEFORE.to_vec(),
        sender_device_root_after: ROOT_AFTER.to_vec(),
        ..Default::default()
    }
}

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

struct SphincsHost;
impl HostSig for SphincsHost {
    fn verify(pk_host: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        matches!(
            dsm_sphincs::verify(dsm_sphincs::SphincsVariant::SPX128f, pk_host, message, sig),
            Ok(valid) if valid
        )
    }
}

/// The receiver's check of the certificate an emit carried: under the keys the anchor disclosed,
/// its frontier and both signatures hold, and it pays this recipient.
fn assert_release_verifies(status: &pb::ApplianceResponse, emit: &pb::ApplianceResponse) {
    let release = match &emit.release {
        Some(release) => release,
        None => panic!("the emit carried no release"),
    };
    let release = match release.to_release() {
        Ok(release) => release,
        Err(e) => panic!("the release does not decode: {e:?}"),
    };
    assert_eq!(
        release.cert.anchor_bundle.as_slice(),
        status.anchor_bundle.as_slice(),
        "the certificate names another bundle"
    );
    assert_eq!(
        release.cert.recipient, RECIPIENT,
        "it pays another recipient"
    );
    assert_eq!(
        release.cert.receiver_challenge, CHALLENGE,
        "it answers another challenge"
    );
    if let Err(e) = verify_cert_frontier_and_sigs::<Ed25519Chip, SphincsHost>(
        &release.cert,
        &status.pin_chip_pk,
        &status.pin_partition_pk,
    ) {
        panic!("the release does not verify: {e:?}");
    }
}

#[test]
fn a_fresh_chip_answers_only_a_provisioning() {
    let model = ModelServer::start();
    let mut anchor = booted(&model);
    for op in [pb::Op::Status, pb::Op::Commit, pb::Op::Recover] {
        let answer = anchor.bare(op);
        assert_eq!(answer.error, err::NOT_PROVISIONED, "{op:?}");
    }
}

#[test]
fn a_provisioned_anchor_serves_again_after_every_power_cycle() {
    let model = ModelServer::start();
    let mut anchor = provisioned(&model);
    let first = anchor.bare(pb::Op::Status);
    assert!(first.ok, "status after provisioning: error {}", first.error);
    drop(anchor);
    for cycle in 0..3 {
        let mut anchor = booted(&model);
        let status = anchor.bare(pb::Op::Status);
        assert!(
            status.ok,
            "power cycle {cycle}: the anchor refused to serve: error {}",
            status.error
        );
        assert_eq!(
            status.anchor_bundle, first.anchor_bundle,
            "the bundle moved"
        );
        assert_eq!(status.pin_chip_pk, first.pin_chip_pk, "the chip key moved");
        assert_eq!(
            status.pin_partition_pk, first.pin_partition_pk,
            "the partition key moved"
        );
    }
}

#[test]
fn a_birth_leaves_no_way_to_a_second_birth() {
    let model = ModelServer::start();
    drop(provisioned(&model));
    assert_birth_closed(&model);
    let mut anchor = booted(&model);
    let again = anchor.request(&provision_request());
    assert_eq!(again.error, err::ALREADY_PROVISIONED);
}

#[test]
fn a_spend_on_the_chip_verifies_at_the_receiver_and_moves_the_counter_once() {
    let model = ModelServer::start();
    let mut anchor = provisioned(&model);
    for spent in 0u64..3 {
        let status = anchor.bare(pb::Op::Status);
        assert!(status.ok, "status: error {}", status.error);
        assert_eq!(status.active_anchor_counter, spent);
        let root = arr32(&status.active_root);
        let prepared = anchor.request(&prepare_request(root, spent));
        assert!(prepared.ok, "prepare: error {}", prepared.error);
        let committed = anchor.bare(pb::Op::Commit);
        assert!(committed.ok, "commit: error {}", committed.error);
        let emitted = anchor.bare(pb::Op::Emit);
        assert!(emitted.ok, "emit: error {}", emitted.error);
        assert_release_verifies(&status, &emitted);
        let finalized = anchor.bare(pb::Op::Finalize);
        assert!(finalized.ok, "finalize: error {}", finalized.error);
    }
    let status = anchor.bare(pb::Op::Status);
    assert_eq!(status.active_anchor_counter, 3);
    drop(anchor);
    let mut session = own_session(&model);
    match session.mcounter_get(MCounterIndex::Index0) {
        Ok(h) => assert_eq!(h, ENROLL_H0 - 3, "the chip's counter moved once per spend"),
        Err(e) => panic!("no counter: {e:?}"),
    }
}

/// A whole try-run is thousands of SPI transactions through the code a spend runs, and each cut is
/// a new chip and a whole install after it, so a sweep takes every `TRY_RUN_STRIDE`th of them. What
/// is permanent, the boot and the birth around it, is cut at every one.
const TRY_RUN_STRIDE: u64 = 61;

/// The transactions a boot takes, and those a try-run takes after it, on a new chip.
fn boot_and_try_run(model: &ModelServer) -> (u64, u64) {
    model.factory_reset();
    model.power.steady();
    let before = model.power.spent();
    let mut anchor = booted(model);
    let at_serve = model.power.spent();
    let run = anchor.request(&try_run_request());
    assert!(run.ok, "{:?}", run.try_run);
    let tried = model.power.spent() - at_serve;
    println!(
        "[sweep] a boot is {} transactions, a try-run {tried}",
        at_serve - before
    );
    (at_serve - before, tried)
}

/// Cut the power after every SPI transaction of a birth, each on a new chip from the factory. The
/// next boot, and a provisioning if the record never landed, always finishes a closed, serving
/// anchor: a cut never costs the chip.
#[test]
fn a_power_cut_anywhere_in_a_birth_is_finished_by_the_next_boot() {
    let model = ModelServer::start();
    let (boot, try_run) = boot_and_try_run(&model);
    let mut cut = 0u64;
    loop {
        model.factory_reset();
        model.power.cut_after(cut);
        let first_run = match model.boot() {
            Ok(anchor) => {
                let answer = Served::new(anchor).request(&provision_request());
                if answer.ok && !model.power.was_cut() {
                    FirstRun::Finished
                } else {
                    FirstRun::Cut
                }
            }
            Err(e) => {
                assert!(
                    model.power.was_cut(),
                    "cut after {cut}: the boot refused though the power held: {e:?}"
                );
                FirstRun::Cut
            }
        };
        model.power.steady();

        let mut anchor = match model.boot() {
            Ok(anchor) => Served::new(anchor),
            Err(e) => panic!("cut after {cut}: the next boot refused: {e:?}"),
        };
        let status = anchor.bare(pb::Op::Status);
        if !status.ok {
            assert_eq!(
                status.error,
                err::NOT_PROVISIONED,
                "cut after {cut}: {}",
                status.detail
            );
            let answer = anchor.request(&provision_request());
            assert!(
                answer.ok,
                "cut after {cut}: provisioning refused: error {}",
                answer.error
            );
        }
        drop(anchor);
        let mut anchor = match model.boot() {
            Ok(anchor) => Served::new(anchor),
            Err(e) => panic!("cut after {cut}: the boot after the birth refused: {e:?}"),
        };
        let status = anchor.bare(pb::Op::Status);
        assert!(
            status.ok,
            "cut after {cut}: the born anchor refused to serve: error {} {}",
            status.error, status.detail
        );
        drop(anchor);
        if cut % 25 == 0 {
            assert_birth_closed(&model);
        }
        if first_run == FirstRun::Finished {
            assert!(cut > 100, "only {cut} transactions were cut: not a birth");
            return;
        }
        cut += if cut > boot && cut < boot + try_run {
            TRY_RUN_STRIDE
        } else {
            1
        };
    }
}

/// How the run under test ended.
#[derive(PartialEq)]
enum FirstRun {
    Finished,
    Cut,
}

/// Cut the power inside a spend, at every `STRIDE`th SPI transaction, each on a new chip. The next
/// boot always serves, the same release is emitted or none was, and the counter moves once.
#[test]
fn a_power_cut_anywhere_in_a_spend_keeps_one_release_and_one_counter_step() {
    const STRIDE: u64 = 7;
    let model = ModelServer::start();
    let mut cut = 0u64;
    loop {
        model.factory_reset();
        model.power.steady();
        let mut anchor = provisioned(&model);
        let status = anchor.bare(pb::Op::Status);
        assert!(status.ok, "status: error {}", status.error);
        let root = arr32(&status.active_root);

        model.power.cut_after(cut);
        let mut survived = anchor.request(&prepare_request(root, 0)).ok;
        survived = survived && anchor.bare(pb::Op::Commit).ok;
        survived = survived && anchor.bare(pb::Op::Emit).ok;
        survived = survived && anchor.bare(pb::Op::Finalize).ok;
        let first_run = if survived && !model.power.was_cut() {
            FirstRun::Finished
        } else {
            FirstRun::Cut
        };
        model.power.steady();
        drop(anchor);

        let mut anchor = match model.boot() {
            Ok(anchor) => Served::new(anchor),
            Err(e) => panic!("cut after {cut}: the next boot refused: {e:?}"),
        };
        let after = anchor.bare(pb::Op::Status);
        assert!(after.ok, "cut after {cut}: status: error {}", after.error);
        match (after.status, after.active_anchor_counter) {
            // Nothing moved: the spend runs again from the same frontier.
            (0, 0) => {
                assert_eq!(after.active_root, status.active_root, "cut after {cut}");
                let prepared = anchor.request(&prepare_request(root, 0));
                assert!(prepared.ok, "cut after {cut}: error {}", prepared.error);
                let committed = anchor.bare(pb::Op::Commit);
                assert!(committed.ok, "cut after {cut}: error {}", committed.error);
                let emitted = anchor.bare(pb::Op::Emit);
                assert_release_verifies(&status, &emitted);
                let finalized = anchor.bare(pb::Op::Finalize);
                assert!(finalized.ok, "cut after {cut}: error {}", finalized.error);
            }
            // Committed: the same successor is emitted and finalized, nothing signed anew.
            (2, 1) => {
                let emitted = anchor.bare(pb::Op::Emit);
                assert_release_verifies(&status, &emitted);
                let finalized = anchor.bare(pb::Op::Finalize);
                assert!(finalized.ok, "cut after {cut}: error {}", finalized.error);
            }
            // Finalized before the cut.
            (0, 1) => {}
            other => panic!("cut after {cut}: state {other:?} after recovery"),
        }
        drop(anchor);
        let mut session = own_session(&model);
        match session.mcounter_get(MCounterIndex::Index0) {
            Ok(h) => assert_eq!(h, ENROLL_H0 - 1, "cut after {cut}: the counter moved twice"),
            Err(e) => panic!("cut after {cut}: no counter: {e:?}"),
        }
        drop(session);
        if first_run == FirstRun::Finished {
            assert!(cut > 500, "only {cut} transactions were cut: not a spend");
            return;
        }
        cut += STRIDE;
    }
}

/// A chip already used: its counter away from the start, its slot 1 holding another board's key.
/// Neither is caged or written further: a refusal at boot leaves it as it was.
#[test]
fn a_chip_holding_another_boards_key_is_refused_before_anything_is_written() {
    let model = ModelServer::start();
    let foreign = StaticSecret::from([0x24u8; 32]);
    let mut session = factory_session(&model);
    if let Err(e) = session.pairing_key_write(1u16.into(), PublicKey::from(&foreign).as_bytes()) {
        panic!("slot 1 did not take the other board's key: {e:?}");
    }
    drop(session);

    match model.boot() {
        Ok(_anchor) => panic!("a chip holding another board's key came up to be provisioned"),
        Err(anchor_chip::bring_up::BringUpFailure::Enroll(
            anchor_core::tropic::TropicError::Refused,
        )) => {}
        Err(e) => panic!("refused for another reason: {e:?}"),
    }
    let mut session = factory_session(&model);
    let open = session.i_config_read(0x040u16.into());
    assert!(
        matches!(open, Ok(bits) if bits & 0b10 != 0),
        "the chip was caged"
    );
    assert!(
        matches!(session.r_mem_data_read(0u16.into()), Ok(data) if data.is_empty()),
        "R-memory was written"
    );
}

/// Every step of the chip as it stands, read with the factory's slot: what a try-run promises to
/// leave as it found it.
fn chip_state(model: &ModelServer) -> Vec<String> {
    let mut session = factory_session(model);
    let mut state = Vec::new();
    state.push(format!("{:?}", session.pairing_key_read(1u16.into())));
    state.push(format!("{:?}", session.mcounter_get(MCounterIndex::Index0)));
    for register in [0x020u16, 0x028, 0x040, 0x130, 0x134, 0x13C, 0x150] {
        state.push(format!("{:?}", session.i_config_read(register.into())));
    }
    for slot in [0u16, 1, 2, 297, 298, 299, 300, 511] {
        state.push(format!("{:?}", session.r_mem_data_read(slot.into())));
    }
    state
}

/// A try-run goes through the whole install on the chip and every step passes, and the chip is as it
/// was: nothing bound, no key written, no bit of its access rules cleared, its counter at the start,
/// its memory empty. The real install then takes it.
#[test]
fn a_try_run_goes_through_the_install_and_leaves_the_chip_as_it_found_it() {
    let model = ModelServer::start();
    let mut anchor = booted(&model);
    drop(anchor.bare(pb::Op::Status));
    drop(anchor);
    let before = chip_state(&model);

    let mut anchor = booted(&model);
    let run = anchor.request(&try_run_request());
    assert!(run.ok, "the try-run: error {} {:?}", run.error, run.try_run);
    for step in &run.try_run {
        assert!(step.passed, "{}: {}", step.name, step.detail);
    }
    // A whole payment, as the anchor makes one, not a sample of it.
    for reached in [
        "first record is written",
        "sign a payment",
        "counter moves with the records",
        "release is held",
        "account advances",
        "restores from its record",
        "boot recovery accepts it",
        "the payment left",
        "own slots",
        "would take the board's pairing key",
        "would let the board close it",
        "reboots and opens a session",
    ] {
        assert!(
            run.try_run.iter().any(|step| step.name.contains(reached)),
            "it did not go through {reached:?}: {:?}",
            run.try_run
        );
    }
    // The release stays on the anchor, and an answer as long as it crosses the transport in parts.
    let carried = run.transport_check.len();
    assert!(carried > 4096, "longer than one part: {carried} bytes");
    assert_eq!(
        run.transport_check,
        anchor_core::try_run::transport_check(carried)
    );
    assert_eq!(run.permanent.len(), 4, "what installing makes permanent");
    assert_eq!(
        anchor.bare(pb::Op::Status).error,
        err::NOT_PROVISIONED,
        "a try-run provisions nothing"
    );
    drop(anchor);
    assert_eq!(chip_state(&model), before, "the chip is as it was");

    let mut anchor = booted(&model);
    let installed = anchor.request(&provision_request());
    assert!(
        installed.ok,
        "the install: error {} {}",
        installed.error, installed.detail
    );
    drop(anchor);
    assert_birth_closed(&model);
    assert_eq!(
        booted(&model).request(&try_run_request()).error,
        err::ALREADY_PROVISIONED,
        "an installed anchor has nothing to try"
    );
}

/// The install cannot go around the try-run: on a chip that fails one, the provisioning itself is
/// refused, and the chip is not bound. Here the chip refuses writes to the memory the try-run tries a
/// record in. MUTATION CONTROL: dropping the try-run from `DurableAppliance::provision` installs on
/// this chip and turns this red.
#[test]
fn a_chip_that_fails_its_try_run_is_never_installed() {
    let model = ModelServer::start();
    let mut session = factory_session(&model);
    // CFG_UAP_R_MEM_DATA_WRITE, the lane of slots 256-383, the factory slot's bit.
    if let Err(e) = session.i_config_write(0x110u16.into(), 16) {
        panic!("the access rule did not take: {e:?}");
    }
    drop(session);

    let mut anchor = booted(&model);
    let run = anchor.request(&try_run_request());
    assert_eq!(run.error, err::TRY_RUN_FAILED, "{:?}", run.try_run);
    assert!(
        run.try_run
            .iter()
            .any(|step| !step.passed && step.name.contains("record")),
        "it says where it stopped: {:?}",
        run.try_run
    );

    let refused = anchor.request(&provision_request());
    assert_eq!(refused.error, err::TRY_RUN_FAILED, "{}", refused.detail);
    assert!(refused.detail.contains("record"), "{}", refused.detail);
    drop(anchor);
    let mut session = factory_session(&model);
    assert!(
        matches!(
            session.pairing_key_read(1u16.into()),
            Err(Fault::InvalidKey | Fault::SlotEmpty)
        ),
        "the board's key was written"
    );
    assert!(
        matches!(session.r_mem_data_read(0u16.into()), Ok(data) if data.is_empty()),
        "a record was written"
    );
}

/// A power cut anywhere in a try-run costs nothing: the next boot still comes up unprovisioned, and
/// the next try-run and install both pass.
#[test]
fn a_power_cut_anywhere_in_a_try_run_costs_nothing() {
    let model = ModelServer::start();
    let mut cut = 0u64;
    loop {
        model.factory_reset();
        model.power.steady();
        let mut anchor = booted(&model);
        model.power.cut_after(cut);
        let run = anchor.request(&try_run_request());
        let first_run = if run.ok && !model.power.was_cut() {
            FirstRun::Finished
        } else {
            FirstRun::Cut
        };
        model.power.steady();
        drop(anchor);

        let mut anchor = booted(&model);
        assert_eq!(
            anchor.bare(pb::Op::Status).error,
            err::NOT_PROVISIONED,
            "cut after {cut}"
        );
        let run = anchor.request(&try_run_request());
        assert!(run.ok, "cut after {cut}: {:?}", run.try_run);
        let installed = anchor.request(&provision_request());
        assert!(
            installed.ok,
            "cut after {cut}: error {} {}",
            installed.error, installed.detail
        );
        drop(anchor);
        if first_run == FirstRun::Finished {
            assert!(cut > 100, "only {cut} transactions were cut: not a try-run");
            return;
        }
        cut += TRY_RUN_STRIDE;
    }
}

/// A board whose Non-secure image does not hash to its burned digest cannot bind its chip: the
/// provisioning is refused with the chip untouched, and every authority op with it.
#[test]
fn a_board_whose_image_differs_is_refused_before_its_chip_is_touched() {
    let model = ModelServer::start();
    let mut anchor = booted(&model);
    let refused = anchor.measured(&provision_request(), Measurement::Differs);
    assert_eq!(refused.error, err::MEASUREMENT);
    assert!(!refused.detail.is_empty(), "the refusal says why");
    for op in [
        pb::Op::Prepare,
        pb::Op::Commit,
        pb::Op::Emit,
        pb::Op::Finalize,
        pb::Op::Recover,
    ] {
        let request = pb::ApplianceRequest {
            op: op as i32,
            ..Default::default()
        };
        let refused = anchor.measured(&request, Measurement::Differs);
        assert_eq!(refused.error, err::MEASUREMENT, "{op:?}");
    }
    let status = anchor.measured(
        &pb::ApplianceRequest {
            op: pb::Op::Status as i32,
            ..Default::default()
        },
        Measurement::Differs,
    );
    assert_eq!(status.error, err::NOT_PROVISIONED, "a status moves nothing");
    drop(anchor);

    let mut session = factory_session(&model);
    assert!(
        matches!(
            session.pairing_key_read(1u16.into()),
            Err(Fault::InvalidKey | Fault::SlotEmpty)
        ),
        "the board's key was written"
    );
    assert!(
        matches!(session.r_mem_data_read(0u16.into()), Ok(data) if data.is_empty()),
        "R-memory was written"
    );
    drop(session);

    drop(provisioned(&model));
    assert_birth_closed(&model);
}

/// A power supply that keeps failing: each power-up lasts `every` transactions, over and over. When
/// the power finally holds, the birth still finishes.
#[test]
fn repeated_power_cuts_never_cost_the_chip() {
    let model = ModelServer::start();
    for every in [40u64, 90, 150, 220, 300, 400, 520, 700] {
        model.factory_reset();
        for _power_up in 0..12 {
            model.power.cut_after(every);
            if let Ok(anchor) = model.boot() {
                Served::new(anchor).request(&provision_request());
            }
        }
        model.power.steady();
        let mut anchor = booted(&model);
        let status = anchor.bare(pb::Op::Status);
        if !status.ok {
            assert_eq!(status.error, err::NOT_PROVISIONED, "every {every}");
            let answer = anchor.request(&provision_request());
            assert!(answer.ok, "every {every}: error {}", answer.error);
        }
        drop(anchor);
        let status = booted(&model).bare(pb::Op::Status);
        assert!(status.ok, "every {every}: error {}", status.error);
        assert_birth_closed(&model);
    }
}

#[test]
fn a_chip_with_a_used_counter_is_set_to_the_start_of_a_birth() {
    let model = ModelServer::start();
    let mut session = factory_session(&model);
    if let Err(e) = session.mcounter_init(MCounterIndex::Index0, 1_000) {
        panic!("the counter took no value: {e:?}");
    }
    drop(session);

    let mut anchor = provisioned(&model);
    let status = anchor.bare(pb::Op::Status);
    assert_eq!(status.active_anchor_counter, 0);
    let root = arr32(&status.active_root);
    let prepared = anchor.request(&prepare_request(root, 0));
    assert!(prepared.ok, "prepare: error {}", prepared.error);
}
