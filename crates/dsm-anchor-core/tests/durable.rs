//! The appliance's durable record (§26) across power cuts.
//!
//! A board with one supply: a TROPIC01 in software (its monotonic down-counter and a resident
//! Ed25519 key) and its R-memory, which lose power together. The partition key is BLAKE3-SPHINCS+
//! SPX128f, the scheme receivers verify `σ^host` with. The supply can be cut at a numbered record
//! write — before it lands or just after — which reaches each crash point of the commit; a reboot
//! rebuilds the appliance from its birth and restores it from what R-memory holds.

use std::cell::{Cell, RefCell};
use std::fmt::Debug;
use std::rc::Rc;

use anchor_core::anchor::Anchor as Firmware;
use anchor_core::appliance::{Appliance, RecoverOutcome, Status};
use anchor_core::durable::{
    decode_anchor, encode_active, ActiveStore, DurableAppliance, DurableBootRefusal, DurableError,
    StoreError,
};
use anchor_core::enrollment::{anchor_bundle, ChipBirth, Provisioning};
use anchor_core::proto::{decode_response, encode_request, pb};
use anchor_core::root_advance::{
    anchor_root_advance, transition_digest, OwnedTransition, Transition,
};
use anchor_core::tropic::{PartitionError, PartitionSig, Tropic, TropicError};
use ed25519_dalek::{Signer, SigningKey};

const H0: u32 = 64;
const PARTITION: dsm_sphincs::SphincsVariant = dsm_sphincs::SphincsVariant::SPX128f;

/// The board's one supply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Power {
    On,
    Off,
}

/// Where the supply is cut, counted in record writes since the board last powered up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cut {
    Never,
    /// The power goes off as write `n` starts: it does not land.
    AtWrite(u32),
    /// Write `n` lands, then the power goes off.
    AfterWrite(u32),
}

struct Supply {
    power: Power,
    cut: Cut,
    writes: u32,
}

#[derive(Clone)]
struct Board(Rc<RefCell<Supply>>);

/// The value of a step that must succeed in this test, or the test fails naming it.
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(e) => panic!("{what}: {e:?}"),
    }
}

fn some<T>(option: Option<T>, what: &str) -> T {
    match option {
        Some(value) => value,
        None => panic!("{what}: none"),
    }
}

impl Board {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(Supply {
            power: Power::On,
            cut: Cut::Never,
            writes: 0,
        })))
    }

    fn supply(&self) -> std::cell::RefMut<'_, Supply> {
        self.0.borrow_mut()
    }

    fn cut(&self, cut: Cut) {
        let mut s = self.supply();
        s.cut = cut;
        s.writes = 0;
    }

    fn power(&self) -> Power {
        self.supply().power
    }

    fn power_up(&self) {
        let mut s = self.supply();
        s.power = Power::On;
        s.cut = Cut::Never;
        s.writes = 0;
    }

    /// A record write starting: refused with the power off, or when the supply is cut as it
    /// starts.
    fn write_starts(&self) -> Result<(), StoreError> {
        let mut s = self.supply();
        if s.power == Power::Off {
            return Err(StoreError::Unavailable);
        }
        s.writes += 1;
        if s.cut == Cut::AtWrite(s.writes) {
            s.power = Power::Off;
            return Err(StoreError::Unavailable);
        }
        Ok(())
    }

    /// A record write landed; the supply may be cut just after it.
    fn write_landed(&self) {
        let mut s = self.supply();
        if s.cut == Cut::AfterWrite(s.writes) {
            s.power = Power::Off;
        }
    }

    fn powered(&self) -> Result<(), TropicError> {
        match self.power() {
            Power::On => Ok(()),
            Power::Off => Err(TropicError::Comm),
        }
    }
}

/// Whether the chip is still open to a birth, or closed to a second one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cage {
    Open,
    Closed,
}

/// The chip: its counter and its cage live on the die across reboots; its resident key never
/// leaves it.
struct Chip {
    board: Board,
    counter: Rc<Cell<u32>>,
    cage: Rc<Cell<Cage>>,
    closes: Rc<Cell<u32>>,
    resident: SigningKey,
}

impl Tropic for Chip {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.board.powered()?;
        Ok(self.counter.get())
    }

    fn counter_update(&mut self) -> Result<(), TropicError> {
        self.board.powered()?;
        let h = self.counter.get();
        self.counter
            .set(h.checked_sub(1).ok_or(TropicError::CounterExhausted)?);
        Ok(())
    }

    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        self.board.powered()?;
        Ok(self.resident.sign(message).to_bytes().to_vec())
    }

    fn close_birth(&mut self) -> Result<(), TropicError> {
        self.board.powered()?;
        if self.cage.get() == Cage::Open {
            self.cage.set(Cage::Closed);
            self.closes.set(self.closes.get() + 1);
        }
        Ok(())
    }
}

/// R-memory: one record slot on the board's supply.
#[derive(Clone)]
struct RMemory {
    board: Board,
    slot: Rc<RefCell<Option<Vec<u8>>>>,
}

impl ActiveStore for RMemory {
    fn write(&mut self, record: &[u8]) -> Result<(), StoreError> {
        self.board.write_starts()?;
        *self.slot.borrow_mut() = Some(record.to_vec());
        self.board.write_landed();
        Ok(())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        match self.board.power() {
            Power::On => Ok(self.slot.borrow().clone()),
            Power::Off => Err(StoreError::Unavailable),
        }
    }
}

/// BLAKE3-SPHINCS+ SPX128f, as the receiver verifies `σ^host`.
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

type Durable = DurableAppliance<Chip, Partition, RMemory>;

/// One anchor on its board: what its birth is made from, its chip's counter and its R-memory.
struct Anchor {
    board: Board,
    counter: Rc<Cell<u32>>,
    cage: Rc<Cell<Cage>>,
    closes: Rc<Cell<u32>>,
    rmemory: RMemory,
    seed: [u8; 32],
}

fn derive(seed: &[u8; 32], input: &str) -> [u8; 32] {
    blake3::derive_key(&format!("DSM anchor-core durable test {input}"), seed)
}

impl Anchor {
    fn new(seed: u8) -> Self {
        let board = Board::new();
        Self {
            rmemory: RMemory {
                board: board.clone(),
                slot: Rc::new(RefCell::new(None)),
            },
            board,
            counter: Rc::new(Cell::new(H0)),
            cage: Rc::new(Cell::new(Cage::Open)),
            closes: Rc::new(Cell::new(0)),
            seed: [seed; 32],
        }
    }

    fn resident(&self) -> SigningKey {
        SigningKey::from_bytes(&derive(&self.seed, "resident key"))
    }

    /// What the chip contributes to its birth: its identity, keys and entropy.
    fn chip_birth(&self) -> ChipBirth {
        ChipBirth {
            anchor_id: derive(&self.seed, "anchor id"),
            partition_device_id: derive(&self.seed, "partition device id"),
            chip_pk: self.resident().verifying_key().to_bytes().to_vec(),
            enrolled_counter: H0,
            partition_trng: derive(&self.seed, "partition trng"),
            chip_birth_witness: derive(&self.seed, "chip birth witness"),
            host_nonce: derive(&self.seed, "host nonce"),
            partition_key_seed: derive(&self.seed, "partition key seed"),
        }
    }

    /// The device this anchor is provisioned for.
    fn owner(&self) -> Provisioning {
        Provisioning {
            device_id: derive(&self.seed, "device id"),
            online_id_pk: derive(&self.seed, "online key").to_vec(),
            policy_hash: derive(&self.seed, "policy"),
            genesis_root: derive(&self.seed, "genesis root"),
        }
    }

    fn chip(&self) -> Chip {
        Chip {
            board: self.board.clone(),
            counter: self.counter.clone(),
            cage: self.cage.clone(),
            closes: self.closes.clone(),
            resident: self.resident(),
        }
    }

    /// The appliance its birth for the owner makes, before any record is applied.
    fn appliance(&self) -> Appliance<Chip, Partition> {
        Appliance::new(
            self.chip(),
            H0,
            derive(&self.seed, "anchor id"),
            derive(&self.seed, "partition device id"),
            ok(
                self.chip_birth().birth::<Partition>(&self.owner()),
                "the anchor is born",
            ),
        )
    }

    /// Provisioned for its owner.
    fn born(&self) -> Durable {
        ok(
            DurableAppliance::provision(
                &self.chip_birth(),
                self.chip(),
                self.rmemory.clone(),
                self.owner(),
            ),
            "provisioned",
        )
    }

    /// Power restored: the anchor born again from its chip and the provisioning R-memory holds,
    /// its state the record's, and §26 boot recovery deciding whether it serves.
    fn reboot(&self) -> Result<Durable, DurableBootRefusal> {
        self.board.power_up();
        let mut d = ok(
            DurableAppliance::restore(&self.chip_birth(), self.chip(), self.rmemory.clone()),
            "restored from R-memory",
        );
        d.recover_at_boot()?;
        Ok(d)
    }

    fn chip_counter(&self) -> u32 {
        self.counter.get()
    }

    fn stored(&self) -> anchor_core::appliance::Active {
        let record = some(self.rmemory.slot.borrow().clone(), "a record");
        ok(decode_anchor(&record), "the record decodes").1
    }
}

const RECIPIENT: [u8; 32] = [0x44; 32];
const CHALLENGE: [u8; 32] = [0x55; 32];
const ROOT_BEFORE: [u8; 32] = [0x61; 32];
const ROOT_AFTER: [u8; 32] = [0x62; 32];

/// The transition advancing the frontier `prev` at counter `u`. Its digest excludes the
/// successor, so the successor is derived from it.
fn transition(prev: [u8; 32], u: u64) -> OwnedTransition {
    let relationship_id = [0x01; 32];
    let object_id = [0x02; 32];
    let sender_device_id = [0x03; 32];
    let payload_hash = [0x06; 32];
    let policy = [0x07; 32];
    let core = Transition {
        relationship_id: &relationship_id,
        object_id: &object_id,
        sender_device_id: &sender_device_id,
        recipient_device_id: &RECIPIENT,
        prev_root: &prev,
        next_root: &prev,
        anchor_counter: u,
        next_anchor_counter: u + 1,
        action_type: 0,
        action_fields: &[],
        payload_hash: &payload_hash,
        old_leaf_proof: &[],
        new_leaf_proof: &[],
        authority_policy_hash: &policy,
    };
    let next = anchor_root_advance(&prev, &transition_digest(&core, &CHALLENGE));
    OwnedTransition {
        next_root: next,
        ..OwnedTransition::from(&core)
    }
}

fn prepare(d: &mut Durable) -> Result<OwnedTransition, DurableError> {
    let a = d.appliance();
    let t = transition(a.active.root, a.active.anchor_counter);
    d.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER)?;
    Ok(t)
}

/// Every record the flow writes decodes to the state it was taken of.
#[test]
fn a_record_is_the_state_it_was_taken_of() {
    let anchor = Anchor::new(0x11);
    let mut d = anchor.born();
    let ready = encode_active(&d.appliance().active);
    assert_eq!(encode_active(&anchor.stored()), ready, "born: Ready");
    ok(prepare(&mut d), "prepared");
    assert_eq!(anchor.stored().status, Status::Prepared);
    assert_eq!(
        encode_active(&anchor.stored()),
        encode_active(&d.appliance().active)
    );
    ok(d.commit(), "committed");
    assert_eq!(anchor.stored().status, Status::Committed);
    assert_eq!(
        encode_active(&anchor.stored()),
        encode_active(&d.appliance().active)
    );
    let next = ok(d.finalize(), "finalized");
    assert_eq!(anchor.stored().status, Status::Ready);
    assert_eq!(anchor.stored().root, next);
    assert_eq!(anchor.stored().anchor_counter, 1);
}

/// Crash point 1: the committed candidate is written, and the power goes off before the counter
/// moves. At boot the appliance completes the commit — the counter moves once — and emits the
/// release it prepared, never a new one.
#[test]
fn a_cut_after_the_candidate_is_written_completes_the_commit_at_boot_with_one_counter_step() {
    let anchor = Anchor::new(0x12);
    let mut d = anchor.born();
    ok(prepare(&mut d), "prepared");
    let prepared_cert = anchor.stored();
    // Writes since the cut was set: 1 the candidate.
    anchor.board.cut(Cut::AfterWrite(1));
    let cut = d.commit();
    assert!(
        matches!(cut, Err(DurableError::Appliance(_))),
        "the counter cannot move without power: {cut:?}"
    );
    assert_eq!(anchor.chip_counter(), H0, "the counter did not move");
    assert_eq!(
        anchor.stored().status,
        Status::Committed,
        "the candidate is durable"
    );
    drop(d);

    let d = ok(anchor.reboot(), "boot completes the commit and serves");
    assert_eq!(anchor.chip_counter(), H0 - 1, "the counter moved once");
    let release = ok(d.emit(), "the committed release").clone();
    let prepared = match prepared_cert.record {
        anchor_core::appliance::Record::Prepared(p) => p,
        _ => panic!("the stored record after prepare is the prepared one"),
    };
    assert_eq!(
        release.cert.root_advance_message, prepared.cert.root_advance_message,
        "the release is the one prepared"
    );
    assert_eq!(release.cert.sigma_chip, prepared.cert.sigma_chip);
    assert_eq!(anchor.stored().status, Status::Committed);

    drop(d);
    let again = ok(anchor.reboot(), "a second boot serves the same release");
    assert_eq!(
        anchor.chip_counter(),
        H0 - 1,
        "and does not move the counter again"
    );
    assert_eq!(
        ok(again.emit(), "re-emitted").cert.root_advance_message,
        prepared.cert.root_advance_message
    );
}

/// Crash point 2: the counter moved, and the power goes off as the counter-committed record is
/// written. At boot the appliance marks the commit and emits the same release without moving the
/// counter again.
#[test]
fn a_cut_after_the_counter_moved_completes_the_commit_at_boot_without_moving_it_again() {
    let anchor = Anchor::new(0x13);
    let mut d = anchor.born();
    let t = ok(prepare(&mut d), "prepared");
    // Writes since the cut was set: 1 the candidate, 2 the counter-committed record.
    anchor.board.cut(Cut::AtWrite(2));
    let cut = d.commit();
    assert!(
        matches!(cut, Err(DurableError::Store(StoreError::Unavailable))),
        "the counter-committed record did not land: {cut:?}"
    );
    assert_eq!(anchor.chip_counter(), H0 - 1, "the counter moved");
    let stored = anchor.stored();
    assert_eq!(stored.status, Status::Committed);
    assert_eq!(
        stored.anchor_counter, 0,
        "the record still holds the counter before"
    );
    assert_eq!(
        d.appliance().active.anchor_counter,
        0,
        "and the appliance in memory is what the store holds"
    );
    drop(d);

    let mut d = ok(anchor.reboot(), "boot marks the commit and serves");
    assert_eq!(
        anchor.chip_counter(),
        H0 - 1,
        "the counter did not move again"
    );
    assert_eq!(
        ok(d.emit(), "the committed release").transition.next_root,
        t.next_root
    );
    assert_eq!(ok(d.finalize(), "finalized"), t.next_root);
    assert_eq!(anchor.stored().anchor_counter, 1);
}

/// A cut while prepared, before the commit starts: at boot no session can own the prepared
/// record, so it is reset durably and the counter has not moved.
#[test]
fn a_cut_while_prepared_resets_at_boot_with_the_counter_unmoved() {
    let anchor = Anchor::new(0x14);
    let mut d = anchor.born();
    let before = d.appliance().active.root;
    ok(prepare(&mut d), "prepared");
    anchor.board.cut(Cut::AtWrite(1));
    let cut = d.commit();
    assert!(
        matches!(cut, Err(DurableError::Store(StoreError::Unavailable))),
        "the candidate's record did not land: {cut:?}"
    );
    assert_eq!(anchor.stored().status, Status::Prepared);
    drop(d);

    let d = ok(
        anchor.reboot(),
        "boot resets the prepared record and serves",
    );
    assert_eq!(anchor.chip_counter(), H0, "the counter never moved");
    assert_eq!(
        anchor.stored().status,
        Status::Ready,
        "the reset is durable"
    );
    assert_eq!(d.appliance().active.root, before);
    assert_eq!(d.appliance().active.anchor_counter, 0);
}

/// A record the store does not take is no change: the appliance in memory is again what the
/// store holds, and a reboot finds the same.
#[test]
fn a_change_whose_record_did_not_land_is_undone() {
    let anchor = Anchor::new(0x15);
    let mut d = anchor.born();
    anchor.board.cut(Cut::AtWrite(1));
    let refused = prepare(&mut d).map(|t| t.next_root);
    assert!(
        matches!(refused, Err(DurableError::Store(StoreError::Unavailable))),
        "{refused:?}"
    );
    assert_eq!(
        d.appliance().active.status,
        Status::Ready,
        "the prepare that was not written is undone"
    );
    assert_eq!(anchor.stored().status, Status::Ready);
    drop(d);
    let d = ok(anchor.reboot(), "serves");
    assert_eq!(d.appliance().active.status, Status::Ready);
}

/// A chip counter that moved with no record of it is the inconsistent row of the recovery
/// table: the appliance refuses to serve.
#[test]
fn a_counter_moved_with_no_record_of_it_refuses_to_serve() {
    let anchor = Anchor::new(0x16);
    let d = anchor.born();
    drop(d);
    anchor.counter.set(anchor.counter.get() - 1);
    let refused = anchor.reboot();
    assert!(
        matches!(
            refused,
            Err(DurableBootRefusal::Recovery(
                anchor_core::appliance::BootRecoveryRefusal::Outcome(RecoverOutcome::FailClosed)
            ))
        ),
        "{:?}",
        refused.err()
    );
}

/// The counter moves once per committed candidate: a second counter phase for the same
/// candidate is refused, and so is one whose chip counter moved under it.
#[test]
fn the_counter_moves_once_per_candidate() {
    let anchor = Anchor::new(0x17);
    let mut a = anchor.appliance();
    let t = transition(a.active.root, 0);
    ok(
        a.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER),
        "prepared",
    );
    ok(a.commit_candidate(), "candidate");
    ok(a.commit_counter(), "the counter moves");
    assert_eq!(anchor.chip_counter(), H0 - 1);
    assert_eq!(
        a.commit_counter(),
        Err(anchor_core::appliance::ApplianceError::WrongState),
        "a committed candidate does not move the counter again"
    );
    assert_eq!(anchor.chip_counter(), H0 - 1);

    let other = Anchor::new(0x18);
    let mut b = other.appliance();
    let t = transition(b.active.root, 0);
    ok(
        b.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER),
        "prepared",
    );
    ok(b.commit_candidate(), "candidate");
    other.counter.set(other.counter.get() - 1);
    assert_eq!(
        b.commit_counter(),
        Err(anchor_core::appliance::ApplianceError::CounterMismatch),
        "a counter that moved under the candidate is not moved again for it"
    );
    assert_eq!(other.chip_counter(), H0 - 1);
}

/// STATUS discloses the birth commitment, and with the other pin keys, the owner's online key
/// and the device id, `B` recomputes from what the chip discloses.
#[test]
fn the_status_discloses_what_the_bundle_recomputes_from() {
    let anchor = Anchor::new(0x19);
    let mut a = anchor.appliance();
    let frame = anchor_core::service::handle(
        &mut a,
        &encode_request(&pb::ApplianceRequest {
            op: pb::Op::Status as i32,
            ..Default::default()
        }),
    );
    let status = ok(decode_response(&frame), "a response");
    let recomputed = anchor_bundle(
        &derive(&anchor.seed, "online key"),
        &ok(<[u8; 32]>::try_from(status.pin_anchor_id.as_slice()), "32"),
        &status.pin_chip_pk,
        &status.pin_partition_pk,
        ok(u32::try_from(status.pin_enrolled_counter), "H0"),
        &derive(&anchor.seed, "device id"),
        &derive(&anchor.seed, "policy"),
        &ok(
            <[u8; 32]>::try_from(status.pin_birth_commitment.as_slice()),
            "32",
        ),
    );
    assert_eq!(recomputed.to_vec(), status.anchor_bundle);
}

/// An anchor is provisioned once: a second provisioning, for any device, is refused and the
/// record is unchanged.
#[test]
fn an_anchor_is_provisioned_once() {
    let anchor = Anchor::new(0x1A);
    let d = anchor.born();
    let record = some(anchor.rmemory.slot.borrow().clone(), "a record");
    let bundle = d.appliance().bundle;
    drop(d);
    let mut stranger = anchor.owner();
    stranger.device_id = derive(&[0x1B; 32], "device id");
    let again = Durable::provision(
        &anchor.chip_birth(),
        anchor.chip(),
        anchor.rmemory.clone(),
        stranger,
    )
    .map(|d| d.appliance().bundle)
    .map_err(|refused| refused.error);
    assert_eq!(again, Err(DurableError::AlreadyProvisioned));
    assert_eq!(
        some(anchor.rmemory.slot.borrow().clone(), "a record"),
        record,
        "the record is the first provisioning's"
    );
    let rebooted = ok(anchor.reboot(), "serves");
    assert_eq!(
        rebooted.appliance().bundle,
        bundle,
        "and its bundle is the first's"
    );
    assert_eq!(rebooted.provisioning(), &anchor.owner());
}

/// An anchor restored at boot is the one its provisioning made: the same bundle, and the bundle
/// binds the device, online key and policy it was provisioned for.
#[test]
fn a_restored_anchor_is_bound_to_the_device_it_was_provisioned_for() {
    let anchor = Anchor::new(0x1C);
    let d = anchor.born();
    let born = d.appliance().bundle;
    drop(d);
    let restored = ok(anchor.reboot(), "serves");
    let a = restored.appliance();
    assert_eq!(a.bundle, born);
    let owner = anchor.owner();
    assert_eq!(
        anchor_bundle(
            &owner.online_id_pk,
            &a.anchor_id,
            &a.chip_pk,
            &a.partition_pk,
            H0,
            &owner.device_id,
            &owner.policy_hash,
            &a.birth_commitment,
        ),
        a.bundle
    );
    assert!(
        matches!(
            Durable::restore(
                &anchor.chip_birth(),
                anchor.chip(),
                RMemory {
                    board: anchor.board.clone(),
                    slot: Rc::new(RefCell::new(None)),
                }
            )
            .map(|d| d.appliance().bundle),
            Err(DurableError::NotProvisioned)
        ),
        "an anchor never provisioned is not restored"
    );
}

/// Over the wire, an appliance that exists is provisioned: OP_PROVISION to it is refused.
#[test]
fn a_provisioned_anchor_refuses_to_be_provisioned_again_over_the_wire() {
    let anchor = Anchor::new(0x1D);
    let mut a = anchor.appliance();
    let frame = anchor_core::service::handle(
        &mut a,
        &encode_request(&pb::ApplianceRequest {
            op: pb::Op::Provision as i32,
            ..Default::default()
        }),
    );
    let answer = ok(decode_response(&frame), "a response");
    assert_eq!(answer.error, anchor_core::service::err::ALREADY_PROVISIONED);
    assert_eq!(
        answer.anchor_bundle,
        Vec::<u8>::new(),
        "and discloses nothing"
    );
}

/// A partition whose keypair is born but which never signs.
struct UnsigningPartition;

impl PartitionSig for UnsigningPartition {
    fn part_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError> {
        Partition::part_keygen(seed)
    }

    fn part_sign(_sk: &[u8], _digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError> {
        Err(PartitionError::SelfCheck)
    }

    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        Partition::part_verify(pk, digest, sig)
    }
}

/// No `σ^host` is put in place of one the partition could not make: the prepare is refused
/// with the partition's own reason, over the wire with its own code, and nothing moves.
#[test]
fn a_partition_that_cannot_sign_prepares_nothing_and_says_so() {
    let anchor = Anchor::new(0x2E);
    let mut a = Appliance::<Chip, UnsigningPartition>::new(
        anchor.chip(),
        H0,
        derive(&anchor.seed, "anchor id"),
        derive(&anchor.seed, "partition device id"),
        ok(
            anchor
                .chip_birth()
                .birth::<UnsigningPartition>(&anchor.owner()),
            "the anchor is born",
        ),
    );
    let root = a.active.root;
    let t = transition(root, a.active.anchor_counter);
    assert_eq!(
        a.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER)
            .err(),
        Some(anchor_core::appliance::ApplianceError::Partition(
            PartitionError::SelfCheck
        ))
    );
    let frame = anchor_core::service::handle(
        &mut a,
        &encode_request(&pb::ApplianceRequest {
            op: pb::Op::Prepare as i32,
            transition: Some(t.to_pb()),
            receiver_challenge: CHALLENGE.to_vec(),
            sender_device_root_before: ROOT_BEFORE.to_vec(),
            sender_device_root_after: ROOT_AFTER.to_vec(),
            ..Default::default()
        }),
    );
    let answer = ok(decode_response(&frame), "a response");
    assert_eq!(answer.error, anchor_core::service::err::PARTITION);
    assert_eq!(a.active.status, Status::Ready);
    assert_eq!(a.active.root, root);
    assert_eq!(a.active.anchor_counter, 0);
    assert_eq!(anchor.chip_counter(), H0);
}

type Booted = Firmware<Chip, Partition, RMemory>;

fn provisioning_pb(p: &Provisioning) -> pb::Provisioning {
    pb::Provisioning {
        device_id: p.device_id.to_vec(),
        online_id_pk: p.online_id_pk.clone(),
        policy_hash: p.policy_hash.to_vec(),
        genesis_root: p.genesis_root.to_vec(),
    }
}

fn frame(op: pb::Op, provision: Option<pb::Provisioning>) -> Vec<u8> {
    encode_request(&pb::ApplianceRequest {
        op: op as i32,
        provision,
        ..Default::default()
    })
}

fn served(anchor: Booted, request: &[u8]) -> (Booted, pb::ApplianceResponse) {
    let (anchor, answer) = anchor.serve(request);
    (anchor, ok(decode_response(&answer), "a response"))
}

impl Anchor {
    fn boot(&self) -> Booted {
        ok(
            Booted::boot(self.chip_birth(), self.chip(), self.rmemory.clone()),
            "booted",
        )
    }
}

/// An unprovisioned anchor answers nothing but a provisioning. The provisioning binds the bundle
/// to the device it names (its id, online key, policy and genesis), closes the chip to a second
/// birth once, and is not repeated.
#[test]
fn an_unprovisioned_anchor_answers_only_a_provisioning_and_is_bound_to_its_owner() {
    let anchor = Anchor::new(0x30);
    let booted = anchor.boot();
    let (booted, status) = served(booted, &frame(pb::Op::Status, None));
    assert_eq!(status.error, anchor_core::service::err::NOT_PROVISIONED);
    let (booted, prepare) = served(booted, &frame(pb::Op::Prepare, None));
    assert_eq!(prepare.error, anchor_core::service::err::NOT_PROVISIONED);
    assert_eq!(anchor.cage.get(), Cage::Open);

    let owner = anchor.owner();
    let (booted, provisioned) = served(
        booted,
        &frame(pb::Op::Provision, Some(provisioning_pb(&owner))),
    );
    assert_eq!(provisioned.error, anchor_core::service::err::NONE);
    assert_eq!(
        provisioned.anchor_bundle,
        anchor.appliance().bundle.to_vec()
    );
    assert_eq!((anchor.cage.get(), anchor.closes.get()), (Cage::Closed, 1));

    let mut stranger = owner;
    stranger.device_id = derive(&[0x31; 32], "device id");
    let (booted, again) = served(
        booted,
        &frame(pb::Op::Provision, Some(provisioning_pb(&stranger))),
    );
    assert_eq!(again.error, anchor_core::service::err::ALREADY_PROVISIONED);
    let (_, status) = served(booted, &frame(pb::Op::Status, None));
    assert_eq!(status.anchor_bundle, anchor.appliance().bundle.to_vec());
    assert_eq!(anchor.closes.get(), 1);
}

/// A provisioning whose first record the store does not take leaves the anchor unprovisioned,
/// holding its chip and store, and it can be provisioned again.
#[test]
fn a_provisioning_the_store_does_not_take_leaves_the_anchor_provisionable() {
    let anchor = Anchor::new(0x32);
    let booted = anchor.boot();
    anchor.board.cut(Cut::AtWrite(1));
    let request = frame(pb::Op::Provision, Some(provisioning_pb(&anchor.owner())));
    let (booted, cut) = served(booted, &request);
    assert_eq!(cut.error, anchor_core::service::err::STORE);
    assert_eq!(*anchor.rmemory.slot.borrow(), None);
    assert_eq!(anchor.cage.get(), Cage::Open);
    anchor.board.power_up();
    let (_, provisioned) = served(booted, &request);
    assert_eq!(provisioned.error, anchor_core::service::err::NONE);
    assert_eq!(anchor.cage.get(), Cage::Closed);
}

/// A provisioning that names no online key binds nothing: it is refused and nothing is born.
#[test]
fn a_provisioning_naming_no_online_key_is_refused_and_nothing_is_born() {
    let anchor = Anchor::new(0x33);
    let mut nameless = provisioning_pb(&anchor.owner());
    nameless.online_id_pk.clear();
    let (_, refused) = served(anchor.boot(), &frame(pb::Op::Provision, Some(nameless)));
    assert_eq!(refused.error, anchor_core::service::err::MISSING_FIELD);
    assert_eq!(*anchor.rmemory.slot.borrow(), None);
}

/// A power cut between the first record and the closing of the chip leaves a provisioned anchor
/// on an open chip. After the reboot it closes the chip before it answers anything.
#[test]
fn a_restored_anchor_on_an_open_chip_closes_it_before_it_serves() {
    let anchor = Anchor::new(0x34);
    drop(anchor.born());
    assert_eq!(anchor.cage.get(), Cage::Open);
    let booted = anchor.boot();
    assert_eq!(anchor.cage.get(), Cage::Open);
    let (_, status) = served(booted, &frame(pb::Op::Status, None));
    assert_eq!(status.error, anchor_core::service::err::NONE);
    assert_eq!(status.anchor_bundle, anchor.appliance().bundle.to_vec());
    assert_eq!((anchor.cage.get(), anchor.closes.get()), (Cage::Closed, 1));
}

/// A prepared record completes at recovery only if it is the record the appliance signed: a σ^host
/// that does not verify, or a σ^chip the chip did not make, is cancelled online instead.
#[test]
fn recovery_completes_only_a_prepared_record_whose_signatures_verify() {
    use anchor_core::appliance::Record;
    let anchor = Anchor::new(0x35);
    let prepared = |anchor: &Anchor| {
        let mut a = anchor.appliance();
        let t = transition(a.active.root, a.active.anchor_counter);
        ok(
            a.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER),
            "prepared",
        );
        a
    };
    let mut intact = prepared(&anchor);
    assert_eq!(intact.recover(), RecoverOutcome::AcceptPreparedCanComplete);

    let mut forged_host = prepared(&anchor);
    if let Record::Prepared(p) = &mut forged_host.active.record {
        p.cert.sigma_host[100] ^= 0x01;
    }
    assert_eq!(forged_host.recover(), RecoverOutcome::OnlineCancelOrResolve);

    let mut forged_chip = prepared(&anchor);
    if let Record::Prepared(p) = &mut forged_chip.active.record {
        p.cert.sigma_chip[7] ^= 0x01;
    }
    assert_eq!(forged_chip.recover(), RecoverOutcome::OnlineCancelOrResolve);

    let mut moved = prepared(&anchor);
    if let Record::Prepared(p) = &mut moved.active.record {
        p.cert.recipient[0] ^= 0x01;
    }
    assert_eq!(moved.recover(), RecoverOutcome::OnlineCancelOrResolve);
}

/// Over the wire, recovery answers the appliance's own outcome and the frontier it names: after a
/// commit, the committed release's successor frontier, so the host re-emits that same release.
#[test]
fn recovery_over_the_wire_names_the_committed_releases_successor_frontier() {
    let anchor = Anchor::new(0x36);
    let mut a = anchor.appliance();
    let t = transition(a.active.root, a.active.anchor_counter);
    ok(
        a.prepare(&t.as_transition(), &CHALLENGE, &ROOT_BEFORE, &ROOT_AFTER),
        "prepared",
    );
    ok(a.commit(), "committed");
    let answer = ok(
        decode_response(&anchor_core::service::handle(
            &mut a,
            &encode_request(&pb::ApplianceRequest {
                op: pb::Op::Recover as i32,
                ..Default::default()
            }),
        )),
        "a response",
    );
    assert_eq!(answer.recovery, pb::Recovery::ReemitCommitted as i32);
    assert_eq!(answer.active_root, t.next_root.to_vec());
    assert_ne!(answer.active_root, a.active.root.to_vec());
}
