// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline steps final at their origin cells (proposed, DSM Amendment A39 draft).
//!
//! Every step an offline account's board signs starts from one account root. The
//! origin cell of that root, `K_off = H(DSM/offline-origin/v1 ‖ B ‖ R_off)`, holds
//! the first recognized write of a step starting there; storage spec §9 decides
//! which write that is and when it is final, as it does for every cell. A step
//! once final at its cell is the one successor of its root: a second step from
//! the same root, which only a board that signs twice at one counter can make,
//! never holds the cell.
//!
//! A write proves its own authority from its own bytes. It carries the owner's
//! online key and device, and the anchor material its bundle `B` recomputes from,
//! so the board's keys are the ones `B` commits; and it carries the step in its
//! one encoding. It is recognized at the cell only when the step is the board's
//! signed advance from the cell's root and folds there ([`write_authority`]):
//! full cells, so every reader folds every write and passes over one that
//! spends what its root does not hold. Whoever holds a step may write it — its
//! payer, its receiver, a later payee that was carried it — because the writer
//! only carries it: the authority is the board's signatures under `B`, and `B`
//! binds the owner's online key.
//!
//! A receiver then settles a payment it took offline by reading the cells from
//! the account a boundary of the payer left, which it recorded before it took the
//! payment, through to its payment ([`payment_at_cells`]). Nothing the payer does
//! after the payment, and nothing the payer fails to do, enters it.
//!
//! A step is named by the root-advance message `M` its board signed. `M` binds
//! the device roots before and after the step, so two writes with one `M` are
//! one step whatever else their bytes carry.

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::{class, push_bytes, push_digest32, push_envelope, push_u64, CcbError, CcbObject};
use crate::common::domain_tags::{TAG_DSM_OFFLINE_ORIGIN_CELL, TAG_DSM_OFFLINE_ORIGIN_SEED};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::economic::offline_boundary::BoundaryAnchor;
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellFact,
    CellReading, ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use crate::types::error::DsmError;
use crate::types::offline_chain::{
    verify_account_hops, AccountHop, ChainAnchor, ChainPayment, MAX_CHAIN_HOPS,
};

type D32 = [u8; 32];

/// The schema of `0x0078 OfflineOriginWrite`.
pub const SCHEMA_V1: u16 = 1;
/// The longest online key a write carries (SPHINCS+ public keys are far shorter).
const MAX_KEY_BYTES: usize = 4 * 1024;
/// The longest step a write carries: the storage value bound with room for the
/// write's own fields.
const MAX_STEP_BYTES: usize = 300 * 1024;

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

/// `K_off = H(DSM/offline-origin/v1 ‖ B ‖ R_off)`: the cell of the offline
/// account root `R_off` of the anchor bundle `B`.
pub fn origin_key(bundle: &D32, account_root: &D32) -> D32 {
    h(TAG_DSM_OFFLINE_ORIGIN_CELL, &[bundle, account_root])
}

/// `s_off = H(DSM/offline-origin/seed/v1 ‖ K_off)`: the seed of the cell's
/// route, so a reader that knows only the key finds its leader.
pub fn origin_seed(cell: &D32) -> D32 {
    h(TAG_DSM_OFFLINE_ORIGIN_SEED, &[cell])
}

// ── 0x0078 OfflineOriginWrite ──────────────────────────────────────────────

struct OriginWriteObject;
impl CcbObject for OriginWriteObject {
    const CLASS: u16 = class::OFFLINE_ORIGIN_WRITE;
    const SCHEMA: u16 = SCHEMA_V1;
}

/// `0x0078 OfflineOriginWrite` — one step of an offline account, as its owner's
/// board signed it, with what proves it is that board's: the owner's online key
/// and device, and the anchor material the bundle recomputes from. Whether it
/// proves that is [`write_authority`]'s, not this type's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginWrite {
    /// The owner's online key `pk_on`, which `B` binds.
    pub owner_key: Vec<u8>,
    /// The owner's device id.
    pub device_id: D32,
    /// The anchor bundle `B` whose account the step moves.
    pub bundle: D32,
    /// The anchor `B` commits.
    pub anchor: BoundaryAnchor,
    /// The step's one encoding (`AccountHop::to_bytes`).
    pub step: Vec<u8>,
}

impl OriginWrite {
    /// The write of `step`, a step of the account of `bundle` owned by
    /// `(owner_key, device_id)`.
    pub fn new(
        owner_key: &[u8],
        device_id: D32,
        bundle: D32,
        anchor: &BoundaryAnchor,
        step: &AccountHop,
    ) -> Self {
        Self {
            owner_key: owner_key.to_vec(),
            device_id,
            bundle,
            anchor: anchor.clone(),
            step: step.to_bytes(),
        }
    }

    /// The write's canonical bytes, fields in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<OriginWriteObject>(&mut out);
        push_bytes(&mut out, &self.owner_key)?; // 1
        push_digest32(&mut out, &self.device_id); // 2
        push_digest32(&mut out, &self.bundle); // 3
        push_digest32(&mut out, &self.anchor.anchor_id); // 4
        push_bytes(&mut out, &self.anchor.pk_chip)?; // 5
        push_bytes(&mut out, &self.anchor.pk_host)?; // 6
        push_u64(&mut out, self.anchor.enrolled_counter); // 7
        push_digest32(&mut out, &self.anchor.birth_commitment); // 8
        push_bytes(&mut out, &self.step)?; // 9
        Ok(out)
    }

    /// Decode a write, strictly: its class, schema 1, every field, nothing after.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(OriginWriteObject::CLASS, OriginWriteObject::SCHEMA)?;
        let owner_key = bounded_bytes(&mut c, MAX_KEY_BYTES)?;
        let device_id = c.digest32()?;
        let bundle = c.digest32()?;
        let anchor_id = c.digest32()?;
        let pk_chip = bounded_bytes(&mut c, MAX_KEY_BYTES)?;
        let pk_host = bounded_bytes(&mut c, MAX_KEY_BYTES)?;
        let enrolled_counter = c.u64()?;
        let birth_commitment = c.digest32()?;
        let step = bounded_bytes(&mut c, MAX_STEP_BYTES)?;
        if c.i != bytes.len() {
            return Err(DecodeError::TrailingBytes {
                extra: bytes.len() - c.i,
            });
        }
        Ok(Self {
            owner_key,
            device_id,
            bundle,
            anchor: BoundaryAnchor {
                anchor_id,
                pk_chip,
                pk_host,
                enrolled_counter,
                birth_commitment,
            },
            step,
        })
    }
}

/// A length-prefixed field of at most `max` bytes, refused before anything is
/// allocated for it.
fn bounded_bytes(c: &mut Cursor<'_>, max: usize) -> Result<Vec<u8>, DecodeError> {
    let len = c.u32()? as usize;
    if len > max {
        return Err(DecodeError::Invalid(format!(
            "a field of {len} bytes; at most {max}"
        )));
    }
    Ok(c.take(len)?.to_vec())
}

// ── recognition ────────────────────────────────────────────────────────────

/// Why a write counts as nothing at an origin cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginRefusal {
    /// The bytes are no write, or its step is no step.
    DoesNotDecode(String),
    /// The step is not in its one encoding: a copy re-encoded around the board's
    /// signatures is not what anyone wrote.
    NotOneEncoding,
    /// The step carries no board signature (an unload of a received payment).
    NotBoardSigned,
    /// The step starts from another root, or belongs to another bundle.
    NotThisCell,
    /// The bundle does not recompute from the owner and the anchor the write
    /// carries.
    NotTheOwnersBoard(String),
    /// The board did not sign the step, or it does not fold from its root.
    DoesNotVerify(String),
}

/// A step a reader recognized at its origin cell: what its board signed, the
/// account before and after it, and the payment it made, if it was a spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginStep {
    /// `M`, the root-advance message the board signed: the step's name.
    pub message: D32,
    /// The account root the step starts from: the cell's root.
    pub before: D32,
    /// The account root the step leaves: the next cell's root.
    pub after: D32,
    /// The payment the step made, if it was a spend.
    pub payment: Option<ChainPayment>,
}

/// Whether `write` proves its own authority for the origin cell `cell`:
/// 1. its step decodes and is in its one encoding;
/// 2. its board signed it (a spend or a receive);
/// 3. the cell is the one of the bundle and the root the step starts from;
/// 4. the bundle recomputes from the owner and the anchor it carries;
/// 5. the step is the board's signed advance from that root and folds there.
///
/// No reader's position enters it, so every reader reaches the same answer.
pub fn write_authority(write: &OriginWrite, cell: &D32) -> Result<OriginStep, OriginRefusal> {
    let step = AccountHop::from_bytes(&write.step)
        .map_err(|e| OriginRefusal::DoesNotDecode(e.to_string()))?;
    if step.to_bytes() != write.step {
        return Err(OriginRefusal::NotOneEncoding);
    }
    let Some(message) = step.board_message() else {
        return Err(OriginRefusal::NotBoardSigned);
    };
    let before = step.starts_from();
    if origin_key(&write.bundle, &before) != *cell {
        return Err(OriginRefusal::NotThisCell);
    }
    crate::crypto::anchor_enrollment::require_bundle_of(
        crate::crypto::anchor_enrollment::PinKeys {
            bundle: &write.bundle,
            anchor_id: &write.anchor.anchor_id,
            pk_chip: &write.anchor.pk_chip,
            partition_pk: &write.anchor.pk_host,
            enrolled_counter: write.anchor.enrolled_counter,
        },
        crate::crypto::anchor_enrollment::BundleOwner {
            online_key: &write.owner_key,
            device_id: &write.device_id,
            policy: &crate::types::operations::canonical_offline_bearer_policy().policy_id,
            birth_commitment: &write.anchor.birth_commitment,
        },
    )
    .map_err(|e| OriginRefusal::NotTheOwnersBoard(e.to_string()))?;
    let anchor = ChainAnchor {
        bundle: write.bundle,
        anchor_id: write.anchor.anchor_id,
        pk_chip: write.anchor.pk_chip.clone(),
        pk_host: write.anchor.pk_host.clone(),
    };
    let (payments, after) = verify_account_hops(
        &before,
        &anchor,
        &write.device_id,
        core::slice::from_ref(&step),
    )
    .map_err(|e| OriginRefusal::DoesNotVerify(e.to_string()))?;
    Ok(OriginStep {
        message,
        before,
        after,
        payment: payments.into_iter().next(),
    })
}

/// The write `bytes` are, with the step it proves, when it proves its own
/// authority for the cell `cell`, or why it does not.
pub fn write_occupying(bytes: &[u8], cell: &D32) -> Result<OriginStep, OriginRefusal> {
    let write =
        OriginWrite::decode(bytes).map_err(|e| OriginRefusal::DoesNotDecode(e.to_string()))?;
    write_authority(&write, cell)
}

// ── the cell ───────────────────────────────────────────────────────────────

/// The origin cell at `K_off` as Core derives it: the key, and the route seeded
/// by `s_off` over the network's pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginCell {
    key: D32,
    cell: RoutedCell,
}

impl OriginCell {
    /// The cell of `account_root` of `bundle`. `members` must re-derive
    /// `committed_set_id`, the network's pinned storage set.
    pub fn new(
        bundle: &D32,
        account_root: &D32,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let key = origin_key(bundle, account_root);
        let routed = RoutedCell::new(
            TAG_DSM_OFFLINE_ORIGIN_CELL.source_bytes(),
            key,
            &origin_seed(&key),
            members,
            committed_set_id,
        )?;
        Ok(Self { key, cell: routed })
    }

    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }

    /// What a reader keeps of a seat's log at this cell: copies of writes that
    /// prove their authority for it. A write that proves nothing must never be
    /// what a reader keeps first (storage spec §9, route chains, rule 3).
    pub fn keeps(&self) -> impl Fn(&crate::route_chain::RouteEntry) -> bool + Sync + '_ {
        crate::route_chain::recognized_copies(&self.cell, move |bytes| {
            let refused = std::cell::RefCell::new(Vec::new());
            let recognize = step_at(&self.key, &refused);
            recognize(bytes).is_some()
        })
    }
}

/// What a reader finds at an origin cell: the storage fact, and the step
/// holding the cell with the exact bytes of its write. Built by [`resolution`]
/// and by nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginRead {
    key: D32,
    fact: CellFact,
    held: Option<(OriginStep, Vec<u8>)>,
    passed_over: Vec<OriginRefusal>,
}

impl OriginRead {
    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The step holding the cell, in whatever state its chain has reached.
    pub fn occupant(&self) -> Option<&OriginStep> {
        self.held.as_ref().map(|(step, _)| step)
    }

    /// The step once its chain is final (storage spec §9 rule 7). `None` while
    /// the cell is open or its occupant's chain has fewer than three links, so
    /// nothing settles on an occupant a later read could replace.
    pub fn settled(&self) -> Option<&OriginStep> {
        match (&self.held, self.fact) {
            (
                Some((step, _)),
                CellFact::Held {
                    state: ChainState::Final,
                    ..
                },
            ) => Some(step),
            (Some(..), CellFact::Held { .. } | CellFact::Open) | (None, _) => None,
        }
    }

    /// The exact bytes of the write holding the cell.
    pub fn value(&self) -> Option<&[u8]> {
        self.held.as_ref().map(|(_, value)| value.as_slice())
    }

    /// Why each value the leader holds ahead of the occupant counts as nothing.
    pub fn passed_over(&self) -> &[OriginRefusal] {
        &self.passed_over
    }
}

/// The recognizer of an origin cell: writes that prove their own authority for
/// its key, named by the `M` their board signed. Every value it passes over is
/// recorded in `refused` with the reason.
fn step_at<'c>(
    cell: &'c D32,
    refused: &'c std::cell::RefCell<Vec<OriginRefusal>>,
) -> impl Fn(&[u8]) -> Option<(D32, OriginStep)> + 'c {
    move |bytes| match write_occupying(bytes, cell) {
        Ok(step) => Some((step.message, step)),
        Err(refusal) => {
            refused.borrow_mut().push(refusal);
            None
        }
    }
}

/// The route-chain reading of an origin cell (storage spec §9): open, or the
/// first recognized step at its leader and how far its chain has gone, with why
/// every value ahead of it counts as nothing. Evidence that does not decide the
/// cell yet is [`Missing`], never an answer.
pub fn resolution(cell: &OriginCell, evidence: &CellEvidence) -> Result<OriginRead, Missing> {
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(&cell.cell, evidence, step_at(&cell.key, &refused))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(OriginRead {
        key: cell.key,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

/// The recognizer of the one write a read found holding the cell: its exact
/// bytes, so a completion proof built or checked with it is about the same
/// leader link.
fn held_step(read: &OriginRead) -> impl Fn(&[u8]) -> Option<(D32, OriginStep)> + '_ {
    move |bytes| match &read.held {
        Some((step, value)) if value.as_slice() == bytes => Some((step.message, step.clone())),
        Some(..) | None => None,
    }
}

/// The completion proof of the step `read` found final at the cell; `None`
/// while no chain of it has three links, or when the read found the cell open.
pub fn completion(
    cell: &OriginCell,
    read: &OriginRead,
    evidence: &CellEvidence,
) -> Result<Option<(OriginStep, CompletionProof)>, Missing> {
    completion_proof(&cell.cell, evidence, held_step(read))
}

/// Check a kept completion proof of the step `read` found at the cell against
/// the reads in `evidence`: the step it proves final.
pub fn check_completion(
    cell: &OriginCell,
    read: &OriginRead,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<OriginStep, ProofRefusal> {
    check_completion_proof(&cell.cell, evidence, proof, held_step(read))
}

// ── settling without the payer ─────────────────────────────────────────────

/// The payment `message` of the account of `bundle`, proved by its cells: from
/// `start`, the account a boundary of the payer left that the receiver
/// recorded, each read is the cell of the root the path stands at, its step is
/// final there, and the last read's step is the payment. Answers the payment.
///
/// The payer is never needed: a step final at its cell is the one successor of
/// its root for every reader, so the path the cells hold is the one history of
/// the account, and a payment off it never settles.
pub fn payment_at_cells(
    bundle: &D32,
    start: &D32,
    reads: &[OriginRead],
    message: &D32,
) -> Result<ChainPayment, DsmError> {
    if reads.len() > MAX_CHAIN_HOPS {
        return Err(DsmError::invalid_operation(format!(
            "a path of {} cells; at most {MAX_CHAIN_HOPS} steps lie between two boundaries",
            reads.len()
        )));
    }
    let mut at = *start;
    for (index, read) in reads.iter().enumerate() {
        let refused = |why: &str| {
            DsmError::invalid_operation(format!("the payer's origin cell {index}: {why}"))
        };
        if *read.key() != origin_key(bundle, &at) {
            return Err(refused("it is not the cell of the root the path stands at"));
        }
        let Some(step) = read.settled() else {
            return Err(refused("no step is final there yet"));
        };
        if step.message == *message {
            if index + 1 != reads.len() {
                return Err(refused("the path goes on past the payment"));
            }
            return step
                .payment
                .ok_or_else(|| refused("the step it names is not a payment"));
        }
        at = step.after;
    }
    Err(DsmError::invalid_operation(
        "the payer's origin cells hold another history: the payment is not on it",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_chain::fixtures;
    use crate::types::offline_chain::fixture::Payer;

    const R1: D32 = [0xB1; 32];
    const R2: D32 = [0xB2; 32];

    /// `BLAKE3(tag ‖ 0x00 ‖ parts)` with the tag typed from the draft, not read
    /// from the constants.
    fn independent(tag: &str, parts: &[&[u8]]) -> D32 {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(&[0x00]);
        for p in parts {
            hasher.update(p);
        }
        *hasher.finalize().as_bytes()
    }

    fn anchor_of(p: &Payer) -> BoundaryAnchor {
        BoundaryAnchor {
            anchor_id: p.pin.anchor_id,
            pk_chip: p.pin.pk_chip.clone(),
            pk_host: p.pin.pk_host.clone(),
            enrolled_counter: u64::from(p.enrolled_counter),
            birth_commitment: p.birth_commitment,
        }
    }

    fn write_of(p: &Payer, step: &AccountHop) -> OriginWrite {
        OriginWrite::new(
            p.head.public_key(),
            p.head.devid(),
            p.pin.bundle,
            &anchor_of(p),
            step,
        )
    }

    fn bytes_of(w: &OriginWrite) -> Vec<u8> {
        w.encode().expect("the write has an encoding")
    }

    fn cell_of(bundle: &D32, root: &D32) -> OriginCell {
        OriginCell::new(
            bundle,
            root,
            &fixtures::committed_set(),
            &fixtures::committed_set_id(),
        )
        .expect("a cell over the fixture set")
    }

    /// The cell holding `writes` in the leader's arrival order, each carried to
    /// finality, and its read.
    fn read_after(cell: &OriginCell, writes: &[&[u8]]) -> OriginRead {
        let mut seats = fixtures::Cell::at(cell.routed());
        for w in writes {
            seats.write(w, 2, &[]);
        }
        resolution(cell, &seats.evidence()).expect("the leader is read")
    }

    fn spend(p: &mut Payer, to: D32, amount: u64) -> AccountHop {
        AccountHop::Spend(p.spend(to, amount).0)
    }

    #[test]
    fn the_derivations_are_the_drafted_hashes() {
        let bundle = [0x0B; 32];
        let root = [0x0C; 32];
        let k = origin_key(&bundle, &root);
        assert_eq!(k, independent("DSM/offline-origin/v1", &[&bundle, &root]));
        assert_eq!(
            origin_seed(&k),
            independent("DSM/offline-origin/seed/v1", &[&k])
        );
        assert_ne!(origin_key(&root, &bundle), k);
    }

    #[test]
    fn a_write_has_one_encoding() {
        let mut p = Payer::loaded(0x31, 40);
        let step = spend(&mut p, R1, 10);
        let w = write_of(&p, &step);
        let bytes = bytes_of(&w);
        assert_eq!(OriginWrite::decode(&bytes).expect("decodes"), w);
        let mut longer = bytes.clone();
        longer.push(0);
        let refused = OriginWrite::decode(&longer).expect_err("a byte after the write");
        assert_eq!(refused, DecodeError::TrailingBytes { extra: 1 });
    }

    /// The receiver settles from the cells alone: the payer's spends, written by
    /// anyone holding them, hold their cells, and the path from the account the
    /// load left reaches the receiver's payment. The payer never comes back.
    #[test]
    fn a_receiver_settles_from_the_cells_without_the_payer() {
        let mut p = Payer::loaded(0x32, 40);
        let loaded = p.account_root();
        let first = spend(&mut p, R1, 10);
        let after_first = p.account_root();
        let second = spend(&mut p, R2, 15);

        let c0 = cell_of(&p.pin.bundle, &loaded);
        let c1 = cell_of(&p.pin.bundle, &after_first);
        let r0 = read_after(&c0, &[&bytes_of(&write_of(&p, &first))]);
        let r1 = read_after(&c1, &[&bytes_of(&write_of(&p, &second))]);

        let m1 = first.board_message().expect("signed");
        let m2 = second.board_message().expect("signed");
        let paid1 = payment_at_cells(&p.pin.bundle, &loaded, &[r0.clone()], &m1)
            .expect("R1's payment is final at its cell");
        assert_eq!((paid1.recipient, paid1.amount), (R1, 10));
        let paid2 = payment_at_cells(&p.pin.bundle, &loaded, &[r0, r1], &m2)
            .expect("R2's payment is final behind R1's");
        assert_eq!((paid2.recipient, paid2.amount), (R2, 15));
    }

    /// A step not yet final settles nothing: a later read could replace it.
    #[test]
    fn nothing_settles_on_a_step_that_is_not_final() {
        let mut p = Payer::loaded(0x33, 40);
        let loaded = p.account_root();
        let step = spend(&mut p, R1, 10);
        let cell = cell_of(&p.pin.bundle, &loaded);
        let mut seats = fixtures::Cell::at(cell.routed());
        seats.write(&bytes_of(&write_of(&p, &step)), 0, &[]);
        let read = resolution(&cell, &seats.evidence()).expect("read");
        assert!(read.occupant().is_some());
        assert!(read.settled().is_none());
        let m = step.board_message().expect("signed");
        let refused = payment_at_cells(&p.pin.bundle, &loaded, &[read], &m)
            .expect_err("one link is not final");
        assert!(refused.to_string().contains("no step is final there yet"), "{refused}");
    }

    /// Invalid competing steps cannot displace a legitimate payment. Ahead of the
    /// real spend at the leader: noise; the spend re-encoded around its
    /// signatures; the spend claiming another amount than the board's roots
    /// fold; the spend written as another device's; and a step of another root.
    /// Each counts as nothing, with its reason, and the real spend holds the
    /// cell and settles.
    #[test]
    fn invalid_competing_steps_never_displace_a_payment() {
        let mut p = Payer::loaded(0x34, 40);
        let loaded = p.account_root();
        let real = spend(&mut p, R1, 10);
        let after = p.account_root();
        let later = spend(&mut p, R2, 5);
        let cell = cell_of(&p.pin.bundle, &loaded);
        let good = write_of(&p, &real);

        // Re-encoded: the same step with an unknown protobuf field appended.
        let mut reencoded = good.clone();
        reencoded.step.extend_from_slice(&[0x78, 0x01]);
        // Another amount: the board's roots fold only the amount it signed.
        let AccountHop::Spend(hop) = &real else {
            panic!("a spend")
        };
        let mut wire = hop.to_proto();
        wire.amount = 30;
        let inflated = AccountHop::Spend(
            crate::types::offline_chain::SpendHop::from_proto(wire).expect("decodes"),
        );
        let inflated = write_of(&p, &inflated);
        // Another owner: the bundle does not recompute for this device.
        let mut stranger = good.clone();
        stranger.device_id = [0x5E; 32];
        // The payer's later step, sent to this root's cell.
        let elsewhere = write_of(&p, &later);

        let read = read_after(
            &cell,
            &[
                b"noise",
                &bytes_of(&reencoded),
                &bytes_of(&inflated),
                &bytes_of(&stranger),
                &bytes_of(&elsewhere),
                &bytes_of(&good),
            ],
        );
        let held = read.settled().expect("the real spend is final");
        assert_eq!(Some(held.message), real.board_message());
        assert!(matches!(
            read.passed_over(),
            [
                OriginRefusal::DoesNotDecode(_),
                OriginRefusal::NotOneEncoding,
                OriginRefusal::DoesNotVerify(_),
                OriginRefusal::NotTheOwnersBoard(_),
                OriginRefusal::NotThisCell,
            ]
        ));
        let m = real.board_message().expect("signed");
        let paid = payment_at_cells(&p.pin.bundle, &loaded, &[read], &m).expect("settles");
        assert_eq!((paid.recipient, paid.amount), (R1, 10));
        assert_ne!(after, loaded);
    }

    /// Valid conflicting steps: a board that signs twice at one counter (a clone
    /// of its keys) pays R1 and R2 from the same root, both folding. The cell
    /// holds the first written; the other receiver's payment is off the history
    /// the cells hold and never settles. One of the two payments settles, never
    /// both, so nothing is created, and the second write is no double
    /// settlement whoever writes it first or again.
    #[test]
    fn valid_conflicting_steps_settle_once() {
        let mut board = Payer::loaded(0x35, 40);
        let mut clone = Payer::loaded(0x35, 40);
        assert_eq!(board.pin.bundle, clone.pin.bundle);
        let root = board.account_root();
        assert_eq!(clone.account_root(), root);
        let to_r1 = spend(&mut board, R1, 30);
        let to_r2 = spend(&mut clone, R2, 30);
        let m1 = to_r1.board_message().expect("signed");
        let m2 = to_r2.board_message().expect("signed");
        assert_ne!(m1, m2);

        let cell = cell_of(&board.pin.bundle, &root);
        // Both are the board's valid steps from this root: each would hold the
        // cell alone.
        let one = write_authority(&write_of(&board, &to_r1), cell.key()).expect("R1's step holds alone");
        let two = write_authority(&write_of(&clone, &to_r2), cell.key()).expect("R2's step holds alone");
        assert_eq!((one.before, two.before), (root, root));

        for (first, second) in [
            (write_of(&board, &to_r1), write_of(&clone, &to_r2)),
            (write_of(&clone, &to_r2), write_of(&board, &to_r1)),
        ] {
            let read = read_after(&cell, &[&bytes_of(&first), &bytes_of(&second), &bytes_of(&first)]);
            let mut settled = Vec::new();
            let mut refused = Vec::new();
            for (m, r) in [(m1, R1), (m2, R2)] {
                match payment_at_cells(&board.pin.bundle, &root, &[read.clone()], &m) {
                    Ok(paid) => settled.push((paid.recipient, paid.amount, r)),
                    Err(why) => refused.push(why.to_string()),
                }
            }
            assert_eq!(settled.len(), 1, "exactly one of the two payments settles");
            assert_eq!(refused.len(), 1);
            assert!(refused[0].contains("another history"), "{}", refused[0]);
            let (recipient, amount, named) = settled[0];
            assert_eq!(recipient, named);
            assert!(amount <= 40, "never more than the account held");
        }
    }

    /// A payment off the path never settles, and a path that skips a cell or
    /// runs past the payment is refused: a receiver proves exactly the history
    /// from its recorded account to its own payment.
    #[test]
    fn only_the_exact_path_to_the_payment_settles() {
        let mut p = Payer::loaded(0x36, 40);
        let loaded = p.account_root();
        let first = spend(&mut p, R1, 10);
        let mid = p.account_root();
        let second = spend(&mut p, R2, 10);
        let r0 = read_after(&cell_of(&p.pin.bundle, &loaded), &[&bytes_of(&write_of(&p, &first))]);
        let r1 = read_after(&cell_of(&p.pin.bundle, &mid), &[&bytes_of(&write_of(&p, &second))]);
        let m1 = first.board_message().expect("signed");
        let m2 = second.board_message().expect("signed");

        let refusal = |reads: &[OriginRead], bundle: &D32, start: &D32, m: &D32| {
            payment_at_cells(bundle, start, reads, m)
                .expect_err("the path is not the payment's")
                .to_string()
        };
        let not_this_cell = "it is not the cell of the root the path stands at";
        // Skipping the first cell: the second cell is not the start's.
        let skipped = refusal(&[r1.clone()], &p.pin.bundle, &loaded, &m2);
        assert!(skipped.contains(not_this_cell), "{skipped}");
        // Past the payment.
        let past = refusal(&[r0.clone(), r1.clone()], &p.pin.bundle, &loaded, &m1);
        assert!(past.contains("goes on past the payment"), "{past}");
        // From another start.
        let elsewhere = refusal(&[r0.clone()], &p.pin.bundle, &mid, &m1);
        assert!(elsewhere.contains(not_this_cell), "{elsewhere}");
        // Another bundle's cells.
        let stranger = refusal(&[r0.clone()], &[0xEE; 32], &loaded, &m1);
        assert!(stranger.contains(not_this_cell), "{stranger}");
        // The right path settles.
        let paid = payment_at_cells(&p.pin.bundle, &loaded, &[r0, r1], &m2).expect("settles");
        assert_eq!((paid.recipient, paid.amount), (R2, 10));
    }
}
