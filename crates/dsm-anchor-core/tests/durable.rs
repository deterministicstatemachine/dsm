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

use anchor_core::appliance::{Appliance, RecoverOutcome, Status};
use anchor_core::durable::{
    decode_active, encode_active, ActiveStore, DurableAppliance, DurableBootRefusal, DurableError,
    StoreError,
};
use anchor_core::enrollment::{anchor_bundle, birth, Birth, BirthInputs};
use anchor_core::proto::{decode_response, encode_request, pb};
use anchor_core::root_advance::{
    anchor_root_advance, transition_digest, OwnedTransition, Transition,
};
use anchor_core::tropic::{PartitionSig, Tropic, TropicError};
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

/// The chip: its counter lives on the die across reboots; its resident key never leaves it.
struct Chip {
    board: Board,
    counter: Rc<Cell<u32>>,
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
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let kp = ok(
            dsm_sphincs::generate_keypair_from_seed(PARTITION, seed),
            "the partition keypair",
        );
        (kp.secret_key.clone(), kp.public_key.clone())
    }

    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        ok(
            dsm_sphincs::sign(PARTITION, sk, digest),
            "the partition signs",
        )
    }

    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        matches!(dsm_sphincs::verify(PARTITION, pk, digest, sig), Ok(valid) if valid)
    }
}

type Durable = DurableAppliance<Chip, Partition, RMemory>;

/// One anchor on its board: what its birth is made from, its chip's counter and its R-memory.
struct Anchor {
    board: Board,
    counter: Rc<Cell<u32>>,
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
            seed: [seed; 32],
        }
    }

    fn resident(&self) -> SigningKey {
        SigningKey::from_bytes(&derive(&self.seed, "resident key"))
    }

    fn birth(&self) -> Birth {
        let chip_pk = self.resident().verifying_key().to_bytes().to_vec();
        birth::<Partition>(&BirthInputs {
            partition_trng: &derive(&self.seed, "partition trng"),
            chip_birth_witness: &derive(&self.seed, "chip birth witness"),
            host_nonce: &derive(&self.seed, "host nonce"),
            device_id: &derive(&self.seed, "device id"),
            policy_hash: &derive(&self.seed, "policy"),
            partition_device_id: &derive(&self.seed, "partition device id"),
            anchor_id: &derive(&self.seed, "anchor id"),
            chip_pk: &chip_pk,
            online_id_pk: &derive(&self.seed, "online key"),
            partition_key_seed: &derive(&self.seed, "partition key seed"),
            enrolled_counter: H0,
            genesis_root: &derive(&self.seed, "genesis root"),
        })
    }

    /// The appliance its birth makes, before any record is applied.
    fn appliance(&self) -> Appliance<Chip, Partition> {
        Appliance::new(
            Chip {
                board: self.board.clone(),
                counter: self.counter.clone(),
                resident: self.resident(),
            },
            H0,
            derive(&self.seed, "anchor id"),
            derive(&self.seed, "partition device id"),
            self.birth(),
        )
    }

    fn born(&self) -> Durable {
        ok(
            DurableAppliance::born(self.appliance(), self.rmemory.clone()),
            "born",
        )
    }

    /// Power restored: the appliance rebuilt from its birth, restored from R-memory, and §26 boot
    /// recovery deciding whether it serves.
    fn reboot(&self) -> Result<Durable, DurableBootRefusal> {
        self.board.power_up();
        let mut d = ok(
            DurableAppliance::restore(self.appliance(), self.rmemory.clone()),
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
        ok(decode_active(&record), "the record decodes")
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
