// SPDX-License-Identifier: Apache-2.0

//! Application cells (DSM Amendment A35): a storage cell an application
//! names, and the one write that holds it.
//!
//! An application's state advances one cell at a time. The cell is
//! `K_app = H(DSM/app/cell/v1 ‖ application ‖ ω ‖ u32be(|name|) ‖ name)`,
//! where `ω` commits the exact set of keys that may write it. A write carries
//! the application, the name, the writer set, a payload and one writer's
//! signature over `m(p) = H(DSM/app/write/v1 ‖ K_app ‖ u32be(|p|) ‖ p)`, so it
//! proves its own authority for the cell from its own bytes and every reader
//! reaches the same answer about it.
//!
//! The canonical occupant is storage spec §9's and nothing new: the first
//! recognized write in the leader's arrival log, final once its chain has
//! three links. What arrived first at any other seat decides nothing, so two
//! readers that saw two writes in different orders still read one occupant.
//! A second write, even one validly signed by another writer of the set,
//! never becomes the cell's value.
//!
//! The payload means nothing here. Whether it is a valid step of the
//! application is the application's own check; a recognized write holds the
//! cell either way, and [`step`] commits the cell and the exact bytes that
//! hold it, so the application's next cell follows from an occupant it
//! accepts and from one it passes over alike.

use crate::ccb::decode::{Cursor, DecodeError};
use crate::ccb::genesis::sigalg;
use crate::ccb::{class, push_digest32, push_u16, push_u32};
use crate::common::domain_tags::{
    TAG_DSM_APP_CELL, TAG_DSM_APP_CELL_SEED, TAG_DSM_APP_STEP, TAG_DSM_APP_WRITE,
    TAG_DSM_APP_WRITERS,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellFact,
    CellReading, ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};

type D32 = [u8; 32];

/// The schema of `0x0077 AppCellWrite`.
pub const SCHEMA_V1: u16 = 1;
/// The longest name an application gives a cell.
pub const MAX_NAME_BYTES: usize = 64;
/// The most keys one cell's writer set holds.
pub const MAX_WRITERS: usize = 64;
/// The longest payload one write carries.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
/// The longest signature one write carries.
pub const MAX_SIGNATURE_BYTES: usize = 64 * 1024;

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

// ── the writer set ─────────────────────────────────────────────────────────

/// Why a write, a writer or a writer set has no encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppCellError {
    /// The algorithm is not one this profile declares.
    UnknownSignatureAlg { alg: u16 },
    /// The key is not the declared algorithm's width.
    KeyLength { expected: usize, got: usize },
    /// A count or a length is outside its bounds.
    OutOfBounds {
        what: &'static str,
        min: usize,
        max: usize,
        got: usize,
    },
    /// The writers are not strictly ascending by their canonical bytes: one
    /// is repeated or out of order.
    WritersNotAscending { index: usize },
    /// The signer index names no writer of the set.
    SignerNotInSet { index: u32, writers: usize },
}

impl core::fmt::Display for AppCellError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSignatureAlg { alg } => {
                write!(f, "signature algorithm {alg} is not declared")
            }
            Self::KeyLength { expected, got } => {
                write!(f, "a key of {got} bytes where the algorithm has {expected}")
            }
            Self::OutOfBounds {
                what,
                min,
                max,
                got,
            } => write!(f, "{what}: {got} is outside {min}..={max}"),
            Self::WritersNotAscending { index } => {
                write!(f, "writer {index} is not above the one before it")
            }
            Self::SignerNotInSet { index, writers } => {
                write!(f, "signer {index} names no writer of a set of {writers}")
            }
        }
    }
}

impl std::error::Error for AppCellError {}

fn bounded(what: &'static str, min: usize, max: usize, got: usize) -> Result<(), AppCellError> {
    if got < min || got > max {
        return Err(AppCellError::OutOfBounds {
            what,
            min,
            max,
            got,
        });
    }
    Ok(())
}

fn invalid(e: AppCellError) -> DecodeError {
    DecodeError::Invalid(e.to_string())
}

/// One key that may write a cell: a declared algorithm and a key of its
/// width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    signature_alg: u16,
    public_key: Vec<u8>,
}

impl Writer {
    pub fn new(signature_alg: u16, public_key: &[u8]) -> Result<Self, AppCellError> {
        let expected = sigalg::public_key_len(signature_alg)
            .ok_or(AppCellError::UnknownSignatureAlg { alg: signature_alg })?;
        if public_key.len() != expected {
            return Err(AppCellError::KeyLength {
                expected,
                got: public_key.len(),
            });
        }
        Ok(Self {
            signature_alg,
            public_key: public_key.to_vec(),
        })
    }

    pub fn signature_alg(&self) -> u16 {
        self.signature_alg
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// `u16be(alg) ‖ u32be(|key|) ‖ key`: what a writer set is ordered by and
    /// what `ω` commits for it.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.public_key.len());
        push_u16(&mut out, self.signature_alg);
        // The key is the declared algorithm's width, far below `u32::MAX`.
        push_u32(&mut out, self.public_key.len() as u32);
        out.extend_from_slice(&self.public_key);
        out
    }

    fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        let alg = c.u16()?;
        let len = c.u32()? as usize;
        // Bound the take by the declared width before touching the bytes.
        let expected = sigalg::public_key_len(alg)
            .ok_or(AppCellError::UnknownSignatureAlg { alg })
            .map_err(invalid)?;
        if len != expected {
            return Err(invalid(AppCellError::KeyLength { expected, got: len }));
        }
        Ok(Self {
            signature_alg: alg,
            public_key: c.take(len)?.to_vec(),
        })
    }
}

/// The exact set of keys that may write a cell, strictly ascending by
/// [`Writer::canonical`]. A set with a repeated key or none has no encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterSet {
    writers: Vec<Writer>,
}

impl WriterSet {
    /// `writers` in any order; a repeated key is refused.
    pub fn new(mut writers: Vec<Writer>) -> Result<Self, AppCellError> {
        writers.sort_by_key(Writer::canonical);
        Self::in_order(writers)
    }

    fn in_order(writers: Vec<Writer>) -> Result<Self, AppCellError> {
        bounded("writers", 1, MAX_WRITERS, writers.len())?;
        let keys: Vec<Vec<u8>> = writers.iter().map(Writer::canonical).collect();
        for (i, pair) in keys.windows(2).enumerate() {
            if pair[0] >= pair[1] {
                return Err(AppCellError::WritersNotAscending { index: i + 1 });
            }
        }
        Ok(Self { writers })
    }

    pub fn writers(&self) -> &[Writer] {
        &self.writers
    }

    /// Where `writer` sits in the set, if it is one of its keys.
    pub fn position(&self, writer: &Writer) -> Option<u32> {
        self.writers
            .iter()
            .position(|w| w == writer)
            .map(|at| at as u32)
    }

    /// `u32be(|W|) ‖ ⨁ canonical(w)`: what `ω` hashes and what a write
    /// carries.
    fn push(&self, out: &mut Vec<u8>) {
        push_u32(out, self.writers.len() as u32);
        for w in &self.writers {
            out.extend_from_slice(&w.canonical());
        }
    }

    fn at(c: &mut Cursor<'_>) -> Result<Self, DecodeError> {
        let n = c.u32()? as usize;
        // Refused before anything is allocated for it.
        bounded("writers", 1, MAX_WRITERS, n).map_err(invalid)?;
        let writers: Vec<Writer> = (0..n).map(|_| Writer::at(c)).collect::<Result<_, _>>()?;
        Self::in_order(writers).map_err(invalid)
    }
}

// ── derivations ────────────────────────────────────────────────────────────

/// `ω = H(DSM/app/writers/v1 ‖ u32be(|W|) ‖ ⨁ canonical(w))`.
pub fn writers_digest(writers: &WriterSet) -> D32 {
    let mut preimage = Vec::new();
    writers.push(&mut preimage);
    h(TAG_DSM_APP_WRITERS, &[&preimage])
}

/// `K_app = H(DSM/app/cell/v1 ‖ application ‖ ω ‖ u32be(|name|) ‖ name)`.
/// The name is the application's and is never read: for a lineage it commits
/// the step before it ([`step`]).
pub fn cell_key(application: &D32, writers_digest: &D32, name: &[u8]) -> D32 {
    // A name is at most MAX_NAME_BYTES long.
    let len = (name.len() as u32).to_be_bytes();
    h(TAG_DSM_APP_CELL, &[application, writers_digest, &len, name])
}

/// `s_app = H(DSM/app/cell-seed/v1 ‖ K_app)`: the seed of the cell's route,
/// so a reader that knows only the key finds its leader.
pub fn cell_seed(cell: &D32) -> D32 {
    h(TAG_DSM_APP_CELL_SEED, &[cell])
}

/// `m(p) = H(DSM/app/write/v1 ‖ K_app ‖ u32be(|p|) ‖ p)`: what a writer signs
/// to write payload `p` at the cell. It names the cell, so a signature writes
/// nothing anywhere else.
pub fn statement(cell: &D32, payload: &[u8]) -> D32 {
    // A payload is at most MAX_PAYLOAD_BYTES long.
    let len = (payload.len() as u32).to_be_bytes();
    h(TAG_DSM_APP_WRITE, &[cell, &len, payload])
}

/// `step = H(DSM/app/step/v1 ‖ K_app ‖ occupant bytes)`: the cell and the
/// exact bytes of the write that holds it. An application names its next
/// cell from this, so the lineage commits every occupant, the ones the
/// application accepts and the ones it passes over.
pub fn step(cell: &D32, occupant: &[u8]) -> D32 {
    h(TAG_DSM_APP_STEP, &[cell, occupant])
}

// ── 0x0077 AppCellWrite ────────────────────────────────────────────────────

/// `0x0077 AppCellWrite` — a write at an application cell: the application,
/// the name, the writer set, which writer signed, the payload and that
/// writer's signature over `m(payload)`. It carries the set so that it proves
/// its own authority for the cell from its own bytes; whether it does is
/// [`write_authority`]'s, not this type's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCellWrite {
    application: D32,
    name: Vec<u8>,
    writers: WriterSet,
    signer: u32,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl AppCellWrite {
    /// Refuses a name, payload or signature outside its bounds and a signer
    /// index naming no writer. It verifies nothing.
    pub fn new(
        application: D32,
        name: &[u8],
        writers: WriterSet,
        signer: u32,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Self, AppCellError> {
        bounded("name bytes", 1, MAX_NAME_BYTES, name.len())?;
        bounded("payload bytes", 1, MAX_PAYLOAD_BYTES, payload.len())?;
        bounded("signature bytes", 1, MAX_SIGNATURE_BYTES, signature.len())?;
        if signer as usize >= writers.writers.len() {
            return Err(AppCellError::SignerNotInSet {
                index: signer,
                writers: writers.writers.len(),
            });
        }
        Ok(Self {
            application,
            name: name.to_vec(),
            writers,
            signer,
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        })
    }

    pub fn application(&self) -> &D32 {
        &self.application
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn writers(&self) -> &WriterSet {
        &self.writers
    }

    /// The writer that signed: `new` and `decode` both refuse an index
    /// outside the set.
    pub fn signer(&self) -> &Writer {
        &self.writers.writers[self.signer as usize]
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The cell these bytes name.
    pub fn cell(&self) -> D32 {
        cell_key(
            &self.application,
            &writers_digest(&self.writers),
            &self.name,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_u16(&mut out, class::APP_CELL_WRITE);
        push_u16(&mut out, SCHEMA_V1);
        push_digest32(&mut out, &self.application);
        push_part(&mut out, &self.name);
        self.writers.push(&mut out);
        push_u32(&mut out, self.signer);
        push_part(&mut out, &self.payload);
        push_part(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut c = Cursor { b: bytes, i: 0 };
        c.envelope(class::APP_CELL_WRITE, SCHEMA_V1)?;
        let application = c.digest32()?;
        let name = read_part(&mut c, "name bytes", MAX_NAME_BYTES)?;
        let writers = WriterSet::at(&mut c)?;
        let signer = c.u32()?;
        let payload = read_part(&mut c, "payload bytes", MAX_PAYLOAD_BYTES)?;
        let signature = read_part(&mut c, "signature bytes", MAX_SIGNATURE_BYTES)?;
        let write = Self::new(application, &name, writers, signer, &payload, &signature)
            .map_err(invalid)?;
        if c.i != c.b.len() {
            return Err(DecodeError::TrailingBytes {
                extra: c.b.len() - c.i,
            });
        }
        Ok(write)
    }
}

/// A length-prefixed part its type already bounds, far below `u32::MAX`.
fn push_part(out: &mut Vec<u8>, part: &[u8]) {
    push_u32(out, part.len() as u32);
    out.extend_from_slice(part);
}

/// A length-prefixed byte string, bounded before it is taken.
fn read_part(c: &mut Cursor<'_>, what: &'static str, max: usize) -> Result<Vec<u8>, DecodeError> {
    let n = c.u32()? as usize;
    bounded(what, 1, max, n).map_err(invalid)?;
    Ok(c.take(n)?.to_vec())
}

// ── signing and recognition ────────────────────────────────────────────────

/// Why a write does not occupy a cell. Every variant is decided from the
/// write's own bytes and the cell's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The bytes are not a canonical `AppCellWrite`.
    DoesNotDecode(DecodeError),
    /// Its application, writer set and name derive another cell.
    NotThisCell,
    /// The signature does not verify under the writer it names, over the
    /// statement for this cell.
    SignatureDoesNotVerify,
    /// The signature could not be checked at all.
    SignatureUncheckable { why: String },
}

/// The write of `payload` at the cell `application` names `name` for
/// `writers`, signed by `writer`'s secret key. Refuses a writer outside the
/// set and a key that does not sign as the writer it names: a write that
/// would never be recognized is not one.
pub fn sign_write(
    application: D32,
    name: &[u8],
    writers: WriterSet,
    writer: &Writer,
    secret_key: &[u8],
    payload: &[u8],
) -> Result<AppCellWrite, crate::types::error::DsmError> {
    let refused = |why: String| crate::types::error::DsmError::invalid_operation(why);
    let signer = writers
        .position(writer)
        .ok_or_else(|| refused("the key is not one of the cell's writers".to_string()))?;
    bounded("name bytes", 1, MAX_NAME_BYTES, name.len()).map_err(|e| refused(e.to_string()))?;
    bounded("payload bytes", 1, MAX_PAYLOAD_BYTES, payload.len())
        .map_err(|e| refused(e.to_string()))?;
    let cell = cell_key(&application, &writers_digest(&writers), name);
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &statement(&cell, payload))?;
    let write = AppCellWrite::new(application, name, writers, signer, payload, &signature)
        .map_err(|e| refused(e.to_string()))?;
    write_authority(&write, &cell).map_err(|e| refused(format!("{e:?}")))?;
    Ok(write)
}

/// Whether `write` proves its own authority for the cell at `cell`:
/// 1. its application, writer set and name derive the cell;
/// 2. its signer is a writer of that set (its type holds this);
/// 3. the signature verifies over `m(payload)` under that writer's key.
///
/// No reader's position and no application rule enters it, so every reader
/// reaches the same answer. One signature is verified, and not before the
/// cell matches.
pub fn write_authority(write: &AppCellWrite, cell: &D32) -> Result<(), WriteRefusal> {
    if write.cell() != *cell {
        return Err(WriteRefusal::NotThisCell);
    }
    let signer = write.signer();
    match crate::crypto::sphincs::sphincs_verify(
        signer.public_key(),
        &statement(cell, &write.payload),
        &write.signature,
    ) {
        Ok(verifies) => {
            if verifies {
                Ok(())
            } else {
                Err(WriteRefusal::SignatureDoesNotVerify)
            }
        }
        Err(e) => Err(WriteRefusal::SignatureUncheckable { why: e.to_string() }),
    }
}

/// The write `bytes` are, when they prove their own authority for the cell
/// at `cell`, or why they do not: anything that does not counts as nothing
/// at the cell.
pub fn write_occupying(bytes: &[u8], cell: &D32) -> Result<AppCellWrite, WriteRefusal> {
    let write = AppCellWrite::decode(bytes).map_err(WriteRefusal::DoesNotDecode)?;
    write_authority(&write, cell)?;
    Ok(write)
}

// ── the cell ───────────────────────────────────────────────────────────────

/// The application cell at `K_app` as Core derives it: the key, and the
/// route seeded by `s_app` over the network's pinned set. Built only by
/// [`AppCell::new`], which refuses members that are not the committed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCell {
    key: D32,
    cell: RoutedCell,
}

impl AppCell {
    /// `members` must re-derive `committed_set_id`, the network's pinned
    /// storage set.
    pub fn new(
        cell: &D32,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let routed = RoutedCell::new(
            TAG_DSM_APP_CELL.source_bytes(),
            *cell,
            &cell_seed(cell),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            key: *cell,
            cell: routed,
        })
    }

    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }

    /// What a reader keeps of a seat's log at this cell: the copies of
    /// writes whose own bytes derive its key. Those its reading counts are
    /// among them, and so is every write for this cell it passes over and
    /// says why ([`AppCellRead::passed_over`]); bytes that are no write for
    /// this cell are no object naming its key, and never count (storage spec
    /// §9, route chains, rule 3).
    pub fn keeps(&self) -> impl Fn(&crate::route_chain::RouteEntry) -> bool + Sync + '_ {
        crate::route_chain::recognized_copies(&self.cell, move |bytes| {
            AppCellWrite::decode(bytes).is_ok_and(|write| write.cell() == self.key)
        })
    }

    /// The copies of writes that prove their authority for this cell: the
    /// values its reading recognizes ([`resolution`]). What a writer reads as
    /// first at the leader, so it records the cell taken only for a value
    /// that holds it.
    pub fn recognizes(&self) -> impl Fn(&crate::route_chain::RouteEntry) -> bool + Sync + '_ {
        crate::route_chain::recognized_copies(&self.cell, move |bytes| {
            let refused = std::cell::RefCell::new(Vec::new());
            let recognize = write_at(self, &refused);
            recognize(bytes).is_some()
        })
    }
}

/// What a reader finds at an application cell, bound to the key it was read
/// at: the storage fact, and the write holding the cell with its exact
/// bytes. Built by [`resolution`] over the seats' reads and by nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCellRead {
    key: D32,
    fact: CellFact,
    held: Option<(AppCellWrite, Vec<u8>)>,
    passed_over: Vec<WriteRefusal>,
}

impl AppCellRead {
    pub fn key(&self) -> &D32 {
        &self.key
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// The canonical occupant: the write holding the cell, if any, in
    /// whatever state its chain has reached.
    pub fn occupant(&self) -> Option<&AppCellWrite> {
        self.held.as_ref().map(|(write, _)| write)
    }

    /// The occupant once its chain is final (storage spec §9 rule 7): the
    /// write and its step. `None` while the cell is open or its occupant's
    /// chain has fewer than three links, so an application advances only
    /// past an occupant no later read can replace.
    pub fn settled(&self) -> Option<(&AppCellWrite, D32)> {
        match (&self.held, self.fact) {
            (
                Some((write, value)),
                CellFact::Held {
                    state: ChainState::Final,
                    ..
                },
            ) => Some((write, step(&self.key, value))),
            (Some(..), CellFact::Held { .. } | CellFact::Open) | (None, _) => None,
        }
    }

    /// Why each value the leader holds ahead of the occupant counts as
    /// nothing there, in the leader's arrival order: a write for another
    /// cell, or one whose signature does not verify under the writer it
    /// names.
    pub fn passed_over(&self) -> &[WriteRefusal] {
        &self.passed_over
    }
}

/// The recognizer of an application cell: writes that prove their own
/// authority for its key, identified by their statement `m(p)`. Every value
/// it passes over is recorded in `refused` with the reason.
fn write_at<'c>(
    cell: &'c AppCell,
    refused: &'c std::cell::RefCell<Vec<WriteRefusal>>,
) -> impl Fn(&[u8]) -> Option<(D32, AppCellWrite)> + 'c {
    move |bytes| match write_occupying(bytes, &cell.key) {
        Ok(write) => Some((statement(&cell.key, write.payload()), write)),
        Err(refusal) => {
            refused.borrow_mut().push(refusal);
            None
        }
    }
}

/// The recognizer of the one write a read found holding the cell: its exact
/// bytes. The first copy of those bytes in the leader's log is the first
/// value the read recognized there, so a completion proof built or checked
/// with it is about the same leader link.
fn held_write(read: &AppCellRead) -> impl Fn(&[u8]) -> Option<(D32, AppCellWrite)> + '_ {
    move |bytes| match &read.held {
        Some((write, value)) if value.as_slice() == bytes => {
            Some((statement(&read.key, write.payload()), write.clone()))
        }
        Some(..) | None => None,
    }
}

/// The route-chain reading of an application cell (storage spec §9): open,
/// or the first recognized write at its leader and how far its chain has
/// gone, with why every value ahead of it counts as nothing. Evidence that
/// does not decide the cell yet is [`Missing`], a network status and never
/// an answer.
pub fn resolution(cell: &AppCell, evidence: &CellEvidence) -> Result<AppCellRead, Missing> {
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(&cell.cell, evidence, write_at(cell, &refused))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(AppCellRead {
        key: cell.key,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

/// The completion proof of the write `read` found final at the cell, with
/// the write; `None` while no chain of it has three links, or when the read
/// found the cell open.
pub fn completion(
    cell: &AppCell,
    read: &AppCellRead,
    evidence: &CellEvidence,
) -> Result<Option<(AppCellWrite, CompletionProof)>, Missing> {
    completion_proof(&cell.cell, evidence, held_write(read))
}

/// Check a kept completion proof of the write `read` found at the cell
/// against the reads in `evidence`: the write it proves final.
pub fn check_completion(
    cell: &AppCell,
    read: &AppCellRead,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<AppCellWrite, ProofRefusal> {
    check_completion_proof(&cell.cell, evidence, proof, held_write(read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
    use crate::route_chain::fixtures;

    /// A writer and its secret key, from a fixed seed.
    fn party(seed: u8) -> (Writer, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("keypair");
        (
            Writer::new(ALG, &kp.public_key).expect("a declared key"),
            kp.secret_key.clone(),
        )
    }

    const APP: D32 = [0xAC; 32];
    const NAME: &[u8] = b"lineage step 7";

    struct Members {
        a: (Writer, Vec<u8>),
        b: (Writer, Vec<u8>),
        outsider: (Writer, Vec<u8>),
        set: WriterSet,
    }

    fn members() -> Members {
        let a = party(0x61);
        let b = party(0x62);
        let set = WriterSet::new(vec![a.0.clone(), b.0.clone()]).expect("two writers");
        Members {
            a,
            b,
            outsider: party(0x63),
            set,
        }
    }

    fn key_of(m: &Members) -> D32 {
        cell_key(&APP, &writers_digest(&m.set), NAME)
    }

    fn write(m: &Members, by: &(Writer, Vec<u8>), payload: &[u8]) -> AppCellWrite {
        sign_write(APP, NAME, m.set.clone(), &by.0, &by.1, payload).expect("a member signs")
    }

    fn the_cell(m: &Members) -> AppCell {
        AppCell::new(
            &key_of(m),
            &fixtures::committed_set(),
            &fixtures::committed_set_id(),
        )
        .expect("a cell over the fixture set")
    }

    /// `BLAKE3(tag ‖ 0x00 ‖ parts)` with the tag typed from the amendment,
    /// not read from the constants.
    fn independent(tag: &str, parts: &[&[u8]]) -> D32 {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(tag.as_bytes());
        hasher.update(&[0x00]);
        for p in parts {
            hasher.update(p);
        }
        *hasher.finalize().as_bytes()
    }

    #[test]
    fn the_derivations_are_the_specified_hashes() {
        let m = members();
        let mut set_bytes = (m.set.writers().len() as u32).to_be_bytes().to_vec();
        for w in m.set.writers() {
            set_bytes.extend_from_slice(&w.signature_alg().to_be_bytes());
            set_bytes.extend_from_slice(&(w.public_key().len() as u32).to_be_bytes());
            set_bytes.extend_from_slice(w.public_key());
        }
        let omega = writers_digest(&m.set);
        assert_eq!(omega, independent("DSM/app/writers/v1", &[&set_bytes]));
        let k = key_of(&m);
        assert_eq!(
            k,
            independent(
                "DSM/app/cell/v1",
                &[&APP, &omega, &(NAME.len() as u32).to_be_bytes(), NAME]
            )
        );
        assert_eq!(cell_seed(&k), independent("DSM/app/cell-seed/v1", &[&k]));
        assert_eq!(
            statement(&k, b"build"),
            independent("DSM/app/write/v1", &[&k, &5u32.to_be_bytes(), b"build"])
        );
        assert_eq!(
            step(&k, b"occupant"),
            independent("DSM/app/step/v1", &[&k, b"occupant"])
        );
    }

    /// The writer set is a set: the order it is given in changes nothing,
    /// and one more or one other key is another cell.
    #[test]
    fn a_cell_is_its_application_its_name_and_its_exact_writers() {
        let m = members();
        let reversed = WriterSet::new(vec![m.b.0.clone(), m.a.0.clone()]).expect("two writers");
        assert_eq!(reversed, m.set);
        let k = key_of(&m);

        let wider = WriterSet::new(vec![m.a.0.clone(), m.b.0.clone(), m.outsider.0.clone()])
            .expect("three writers");
        assert_ne!(cell_key(&APP, &writers_digest(&wider), NAME), k);
        let other = WriterSet::new(vec![m.a.0.clone(), m.outsider.0.clone()]).expect("two");
        assert_ne!(cell_key(&APP, &writers_digest(&other), NAME), k);
        assert_ne!(cell_key(&[0xAD; 32], &writers_digest(&m.set), NAME), k);
        assert_ne!(
            cell_key(&APP, &writers_digest(&m.set), b"lineage step 8"),
            k
        );

        assert_eq!(
            WriterSet::new(vec![m.a.0.clone(), m.a.0.clone()]),
            Err(AppCellError::WritersNotAscending { index: 1 })
        );
        assert!(matches!(
            WriterSet::new(Vec::new()),
            Err(AppCellError::OutOfBounds {
                what: "writers",
                ..
            })
        ));
    }

    #[test]
    fn a_write_has_one_encoding() {
        let m = members();
        let w = write(&m, &m.a, b"place watchtower at 4,9");
        let bytes = w.encode();
        assert_eq!(AppCellWrite::decode(&bytes).expect("decodes"), w);
        assert_eq!(w.cell(), key_of(&m));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            AppCellWrite::decode(&trailing),
            Err(DecodeError::TrailingBytes { extra: 1 })
        );
        for cut in [0, 3, 36, 40, bytes.len() - 1] {
            assert!(
                matches!(
                    AppCellWrite::decode(&bytes[..cut]),
                    Err(DecodeError::Truncated)
                ),
                "a write cut at {cut} still decoded"
            );
        }

        // A signer index naming no writer has no encoding.
        assert_eq!(
            AppCellWrite::new(APP, NAME, m.set.clone(), 2, b"p", b"s"),
            Err(AppCellError::SignerNotInSet {
                index: 2,
                writers: 2
            })
        );
        assert!(matches!(
            AppCellWrite::new(APP, b"", m.set.clone(), 0, b"p", b"s"),
            Err(AppCellError::OutOfBounds {
                what: "name bytes",
                ..
            })
        ));
        assert!(matches!(
            AppCellWrite::new(
                APP,
                NAME,
                m.set.clone(),
                0,
                &vec![7; MAX_PAYLOAD_BYTES + 1],
                b"s"
            ),
            Err(AppCellError::OutOfBounds {
                what: "payload bytes",
                ..
            })
        ));
    }

    /// Recognition is from the write's own bytes: a member's write holds its
    /// cell, and nothing else does.
    #[test]
    fn only_a_writer_of_the_set_writes_the_cell() {
        let m = members();
        let k = key_of(&m);
        let good = write(&m, &m.a, b"build");
        assert_eq!(write_occupying(&good.encode(), &k), Ok(good.clone()));

        // A key outside the set cannot produce a write at all.
        let refused = sign_write(
            APP,
            NAME,
            m.set.clone(),
            &m.outsider.0,
            &m.outsider.1,
            b"build",
        );
        assert!(
            matches!(refused, Err(e) if e.to_string().contains("not one of the cell's writers"))
        );

        // The outsider signs and claims a member's place in the set.
        let forged_sig =
            crate::crypto::sphincs::sphincs_sign(&m.outsider.1, &statement(&k, b"build"))
                .expect("signs");
        let forged = AppCellWrite::new(APP, NAME, m.set.clone(), 0, b"build", &forged_sig)
            .expect("has an encoding");
        assert_eq!(
            write_occupying(&forged.encode(), &k),
            Err(WriteRefusal::SignatureDoesNotVerify)
        );

        // The outsider adds itself to the set: validly signed, for another
        // cell.
        let wider = WriterSet::new(vec![m.a.0.clone(), m.b.0.clone(), m.outsider.0.clone()])
            .expect("three writers");
        let elsewhere = sign_write(APP, NAME, wider, &m.outsider.0, &m.outsider.1, b"build")
            .expect("signs at its own cell");
        assert_eq!(
            write_occupying(&elsewhere.encode(), &k),
            Err(WriteRefusal::NotThisCell)
        );

        // A member's signature over one payload carries no other.
        let moved = AppCellWrite::new(
            APP,
            NAME,
            m.set.clone(),
            good.signer,
            b"raze",
            good.signature(),
        )
        .expect("has an encoding");
        assert_eq!(
            write_occupying(&moved.encode(), &k),
            Err(WriteRefusal::SignatureDoesNotVerify)
        );

        // A member's write at one name is nothing at another.
        let next = cell_key(&APP, &writers_digest(&m.set), b"lineage step 8");
        assert_eq!(
            write_occupying(&good.encode(), &next),
            Err(WriteRefusal::NotThisCell)
        );

        assert!(matches!(
            write_occupying(b"not a write", &k),
            Err(WriteRefusal::DoesNotDecode(_))
        ));
    }

    /// The canonical occupant is the first recognized write in the leader's
    /// arrival log. Two members write; the later seats hold the other write
    /// first. Every reader of this evidence reads the leader's first, and the
    /// other write never holds the cell.
    #[test]
    fn the_occupant_is_the_leaders_first_write_whatever_arrived_first_elsewhere() {
        let m = members();
        let cell = the_cell(&m);
        let first = write(&m, &m.a, b"place watchtower").encode();
        let second = write(&m, &m.b, b"place wall").encode();

        let mut seats = fixtures::Cell::at(cell.routed());
        // The second write reaches seats 1 and 2 before anything else does.
        for position in [1, 2] {
            let copy = crate::route_chain::RouteEntry::at_leader(
                seats.namespace.clone(),
                seats.key,
                second.clone(),
                &seats.route,
            );
            seats.put(position, copy.encode());
        }
        // The leader takes the first write first, then the second.
        seats.write(&first, 2, &[]);
        seats.write(&second, 0, &[]);

        let read = resolution(&cell, &seats.evidence()).expect("the leader is read");
        let occupant = read.occupant().expect("the cell is held");
        assert_eq!(occupant.payload(), b"place watchtower");
        assert_eq!(occupant.signer(), &m.a.0);
        let (settled, next) = read.settled().expect("three links");
        assert_eq!(settled.payload(), b"place watchtower");
        assert_eq!(next, step(cell.key(), &first));
        assert_ne!(next, step(cell.key(), &second));
        assert!(read.passed_over().is_empty());

        // The leader's log in the other order is the other occupant: the
        // order at the leader is the only order that decides.
        let mut other = fixtures::Cell::at(cell.routed());
        other.write(&second, 2, &[]);
        other.write(&first, 2, &[]);
        let read = resolution(&cell, &other.evidence()).expect("the leader is read");
        assert_eq!(read.occupant().expect("held").payload(), b"place wall");
    }

    /// Bytes that are no recognized write take no place at the leader: an
    /// outsider's forgery and plain noise ahead of a member's write are
    /// passed over with the reason, and the member's write holds the cell.
    #[test]
    fn what_is_not_a_recognized_write_never_holds_the_cell() {
        let m = members();
        let cell = the_cell(&m);
        let k = *cell.key();
        let forged_sig =
            crate::crypto::sphincs::sphincs_sign(&m.outsider.1, &statement(&k, b"raze"))
                .expect("signs");
        let forged = AppCellWrite::new(APP, NAME, m.set.clone(), 1, b"raze", &forged_sig)
            .expect("has an encoding")
            .encode();
        let good = write(&m, &m.b, b"place wall").encode();

        let mut seats = fixtures::Cell::at(cell.routed());
        seats.write(b"noise", 4, &[]);
        seats.write(&forged, 4, &[]);
        let before = resolution(&cell, &seats.evidence()).expect("the leader is read");
        assert_eq!(before.fact(), CellFact::Open);
        assert_eq!(before.occupant(), None);
        assert_eq!(before.settled(), None);

        seats.write(&good, 2, &[]);
        let read = resolution(&cell, &seats.evidence()).expect("the leader is read");
        assert_eq!(read.occupant().expect("held").payload(), b"place wall");
        assert!(matches!(
            read.passed_over(),
            [
                WriteRefusal::DoesNotDecode(_),
                WriteRefusal::SignatureDoesNotVerify
            ]
        ));

        // A reader's own keeper drops the noise and keeps the forgery to say
        // why; its recognizer keeps only the write that holds the cell.
        let keeps = cell.keeps();
        let recognizes = cell.recognizes();
        let copy = |value: &[u8]| crate::route_chain::leader_copy(cell.routed(), value);
        assert!(!keeps(&copy(b"noise")));
        assert!(keeps(&copy(&forged)));
        assert!(keeps(&copy(&good)));
        assert!(!recognizes(&copy(&forged)));
        assert!(recognizes(&copy(&good)));
    }

    /// An application advances only past a final occupant: the leader link
    /// alone, or one further link, settles nothing yet, and the step is the
    /// same once it does.
    #[test]
    fn an_occupant_settles_at_three_links_and_not_before() {
        let m = members();
        let cell = the_cell(&m);
        let value = write(&m, &m.a, b"place watchtower").encode();

        for (last, state) in [(0, ChainState::LeaderHeld), (1, ChainState::Preserved)] {
            let mut seats = fixtures::Cell::at(cell.routed());
            seats.write(&value, last, &[]);
            let read = resolution(&cell, &seats.evidence()).expect("the leader is read");
            assert!(matches!(read.fact(), CellFact::Held { state: s, .. } if s == state));
            assert!(read.occupant().is_some());
            assert_eq!(read.settled(), None);
        }

        let mut seats = fixtures::Cell::at(cell.routed());
        seats.write(&value, 2, &[]);
        let evidence = seats.evidence();
        let read = resolution(&cell, &evidence).expect("the leader is read");
        let (_, next) = read.settled().expect("final");
        assert_eq!(next, step(cell.key(), &value));

        let (proved, proof) = completion(&cell, &read, &evidence)
            .expect("nothing missing")
            .expect("a final chain has a proof");
        assert_eq!(proved.payload(), b"place watchtower");
        assert_eq!(
            check_completion(&cell, &read, &evidence, &proof)
                .expect("the proof holds")
                .payload(),
            b"place watchtower"
        );
    }

    /// No seat stands in for the leader: without its log nothing is read,
    /// whatever the other seats hold.
    #[test]
    fn nothing_is_read_without_the_leader() {
        let m = members();
        let cell = the_cell(&m);
        let mut seats = fixtures::Cell::at(cell.routed());
        seats.write(&write(&m, &m.a, b"place watchtower").encode(), 4, &[]);
        let mut evidence = seats.evidence();
        evidence.seats[0].values = None;
        assert_eq!(resolution(&cell, &evidence), Err(Missing::LeaderUnread));
    }

    /// A cell is routed only over the committed set.
    #[test]
    fn a_cell_over_other_members_is_refused() {
        let m = members();
        assert!(matches!(
            AppCell::new(&key_of(&m), &fixtures::committed_set(), &[0x99; 32]),
            Err(CellError::NotTheCommittedSet { .. })
        ));
    }
}
