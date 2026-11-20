// SPDX-License-Identifier: MIT OR Apache-2.0

//! A wallet's sealed backups on storage nodes (DSM Amendment A40).
//!
//! What a phone holds to carry on with its contacts — each relationship's
//! chain tip and its key chain, the write grants, the device head — lives only
//! on the phone. A wallet therefore writes a backup of it to the storage nodes,
//! sealed under a key only its 24 words give, and a wallet restored from those
//! words reads the latest one back:
//!
//! ```text
//! k   = H(DSM/wallet-backup/key/v1 ‖ wallet_seed)        the seal's key
//! l   = H(DSM/wallet-backup/locator/v1 ‖ wallet_seed)    finds the cells
//! K_n,0   = H(DSM/wallet-backup/v1 ‖ l ‖ n ‖ 0)            part 0 of backup n
//! K_n,i,a = H(DSM/wallet-backup/v1 ‖ l ‖ n ‖ i ‖ a)        part i > 0, attempt a
//! s       = H(DSM/wallet-backup/seed/v1 ‖ K)               a cell's route seed
//! write   = nonce(24) ‖ XChaCha20-Poly1305(k, nonce, aad = K,
//!                                          n ‖ i ‖ parts ‖ a ‖ chunk)
//! ```
//!
//! A backup is split into parts no larger than one cell value. Each attempt at
//! writing backup `n` draws its own attempt id `a`; its later parts go to
//! cells under `a`, and part 0, which names `a` and the count of parts, goes
//! to the backup's own cell `K_n,0`, last. Each cell holds the first write
//! recognized at its leader and is final by storage §9 as every cell is. A
//! write is recognized only when it opens under `k` as its cell's own part: no
//! node and no other party can make one, and no node can tell where the next
//! backup goes, since `l` is secret. An attempt cut short leaves only cells no
//! later attempt uses, so backup `n` is written only once `n − 1`'s part 0
//! holds its cell, the backups fill `K_1,0, K_2,0, …` with no gap, and the
//! latest is the last part 0 holding its cell.
//!
//! Whether the latest backup is current is the restore's to decide: its body
//! names the register position it was taken at, and only a backup taken at the
//! position the restore re-verified is installed. An older one is never used,
//! so a node that withholds the latest backup can keep contacts from coming
//! back, but can never roll them back. What the body holds is the SDK's.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::common::domain_tags::{
    TAG_DSM_WALLET_BACKUP_CELL, TAG_DSM_WALLET_BACKUP_KEY, TAG_DSM_WALLET_BACKUP_LOCATOR,
    TAG_DSM_WALLET_BACKUP_SEED,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellFact,
    CellReading, ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use crate::types::error::DsmError;

type D32 = [u8; 32];

/// An XChaCha20 nonce.
const NONCE_LEN: usize = 24;

/// A Poly1305 tag.
const TAG_LEN: usize = 16;

/// One attempt at writing a backup: its later parts lie under it.
pub type AttemptId = [u8; 16];

/// What a part names before its bytes: the backup's number, the part's, the
/// count of parts and the attempt.
const HEADER_LEN: usize = 8 + 4 + 4 + 16;

/// A fresh attempt id, for one attempt at writing a backup.
pub fn new_attempt() -> AttemptId {
    let mut out = [0u8; 16];
    out.copy_from_slice(&crate::crypto::rng::random_bytes(16));
    out
}

/// Where a part of a backup lies: part 0 at the backup's own cell, every later
/// part under the attempt part 0 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    First,
    Later { index: u32, attempt: AttemptId },
}

impl Place {
    /// The place of part `index` of an attempt.
    pub fn of(index: u32, attempt: AttemptId) -> Self {
        match index {
            0 => Self::First,
            index => Self::Later { index, attempt },
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            Self::First => 0,
            Self::Later { index, .. } => *index,
        }
    }
}

/// The most one part of a backup carries: a sealed part is exactly one cell
/// value at its largest (`route_chain::MAX_VALUE_LEN`).
pub const MAX_PART: usize = crate::route_chain::MAX_VALUE_LEN - NONCE_LEN - TAG_LEN - HEADER_LEN;

/// Why a write is not a wallet's backup at a cell. Nothing about its bytes is
/// revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupRefusal {
    /// Shorter than a nonce and a backup number.
    Short,
    /// It does not open under this wallet's key at this cell.
    DoesNotOpen,
    /// It opens, but as another backup, part or attempt than the cell's.
    OtherBackup { named: u64, part: u32 },
    /// It names a part past its own count.
    NoSuchPart { part: u32, parts: u32 },
}

/// One part of a backup as its write opens: how many parts the backup has, and
/// this part's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub parts: u32,
    pub attempt: AttemptId,
    pub chunk: Vec<u8>,
}

/// The keys of one wallet's backups, from its wallet seed. Held only by the
/// wallet; never written anywhere.
#[derive(Clone)]
pub struct BackupKeys {
    seal: D32,
    locator: D32,
}

impl core::fmt::Debug for BackupKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BackupKeys(..)")
    }
}

impl BackupKeys {
    /// The backup keys the wallet seed (`mnemonic.to_seed("")`) gives.
    pub fn of_wallet_seed(wallet_seed: &[u8]) -> Self {
        let derive = |tag| {
            let mut h = dsm_domain_hasher(tag);
            h.update(wallet_seed);
            *h.finalize().as_bytes()
        };
        Self {
            seal: derive(TAG_DSM_WALLET_BACKUP_KEY),
            locator: derive(TAG_DSM_WALLET_BACKUP_LOCATOR),
        }
    }

    /// The cell of the part of the `n`-th backup at `place`.
    pub fn cell_key(&self, n: u64, place: &Place) -> D32 {
        let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
        h.update(&self.locator);
        h.update(&n.to_le_bytes());
        h.update(&place.index().to_le_bytes());
        if let Place::Later { attempt, .. } = place {
            h.update(attempt);
        }
        *h.finalize().as_bytes()
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.seal).into())
    }

    /// The write of `chunk` as part `part` of attempt `attempt` at the `n`-th
    /// backup, which has `parts` parts, under a fresh nonce.
    pub fn seal(
        &self,
        n: u64,
        part: u32,
        parts: u32,
        attempt: &AttemptId,
        chunk: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        if part >= parts {
            return Err(DsmError::invalid_operation(format!(
                "wallet backup: part {part} of {parts}"
            )));
        }
        // The nonce: 24 bytes from the OS, drawn a word at a time.
        let mut nonce_bytes = Vec::with_capacity(NONCE_LEN);
        while nonce_bytes.len() < NONCE_LEN {
            let word = rand::TryRngCore::try_next_u64(&mut rand::rngs::OsRng).map_err(|e| {
                DsmError::invalid_operation(format!("wallet backup: no entropy for a nonce: {e}"))
            })?;
            nonce_bytes.extend_from_slice(&word.to_le_bytes());
        }
        let nonce = XNonce::from_slice(&nonce_bytes);
        let mut plain = Vec::with_capacity(HEADER_LEN + chunk.len());
        plain.extend_from_slice(&n.to_le_bytes());
        plain.extend_from_slice(&part.to_le_bytes());
        plain.extend_from_slice(&parts.to_le_bytes());
        plain.extend_from_slice(attempt);
        plain.extend_from_slice(chunk);
        let key = self.cell_key(n, &Place::of(part, *attempt));
        let sealed = self
            .cipher()
            .encrypt(
                nonce,
                Payload {
                    msg: &plain,
                    aad: &key,
                },
            )
            .map_err(|chacha20poly1305::aead::Error| {
                DsmError::invalid_operation("wallet backup: sealing failed")
            })?;
        let mut out = nonce_bytes;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The part of the `n`-th backup at `place` as `write` holds it, or why
    /// it is not that part.
    pub fn open(&self, n: u64, place: &Place, write: &[u8]) -> Result<Opened, BackupRefusal> {
        let (nonce, sealed) = write
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(BackupRefusal::Short)?;
        let key = self.cell_key(n, place);
        let part = place.index();
        let plain = self
            .cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &key,
                },
            )
            .map_err(|chacha20poly1305::aead::Error| BackupRefusal::DoesNotOpen)?;
        let (named, rest) = plain.split_first_chunk::<8>().ok_or(BackupRefusal::Short)?;
        let (named_part, rest) = rest.split_first_chunk::<4>().ok_or(BackupRefusal::Short)?;
        let (parts, rest) = rest.split_first_chunk::<4>().ok_or(BackupRefusal::Short)?;
        let (attempt, chunk) = rest.split_first_chunk::<16>().ok_or(BackupRefusal::Short)?;
        let (named, named_part) = (u64::from_le_bytes(*named), u32::from_le_bytes(*named_part));
        let parts = u32::from_le_bytes(*parts);
        let other_attempt = matches!(place, Place::Later { attempt: a, .. } if a != attempt);
        if named != n || named_part != part || other_attempt {
            return Err(BackupRefusal::OtherBackup {
                named,
                part: named_part,
            });
        }
        if part >= parts {
            return Err(BackupRefusal::NoSuchPart { part, parts });
        }
        Ok(Opened {
            parts,
            attempt: *attempt,
            chunk: chunk.to_vec(),
        })
    }
}

/// The cell of one part of a wallet's `n`-th backup on the network's pinned
/// set.
pub struct BackupCell {
    keys: BackupKeys,
    n: u64,
    place: Place,
    cell: RoutedCell,
}

impl BackupCell {
    /// The cell of the part of backup `n` at `place`. `members` must
    /// re-derive `committed_set_id`.
    pub fn new(
        keys: &BackupKeys,
        n: u64,
        place: Place,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let key = keys.cell_key(n, &place);
        let mut seed = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_SEED);
        seed.update(&key);
        let routed = RoutedCell::new(
            TAG_DSM_WALLET_BACKUP_CELL.source_bytes(),
            key,
            seed.finalize().as_bytes(),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            keys: keys.clone(),
            n,
            place,
            cell: routed,
        })
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn place(&self) -> Place {
        self.place
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }

    /// The recognizer of a write at this cell: its body, named by the digest
    /// of the write's exact bytes. Why each other write is not one is kept in
    /// `refused`.
    fn recognize<'c>(
        &'c self,
        refused: &'c std::cell::RefCell<Vec<BackupRefusal>>,
    ) -> impl Fn(&[u8]) -> Option<(D32, Opened)> + 'c {
        move |bytes| match self.keys.open(self.n, &self.place, bytes) {
            Ok(opened) => Some((write_id(bytes), opened)),
            Err(refusal) => {
                refused.borrow_mut().push(refusal);
                None
            }
        }
    }

    /// What a reader keeps of a seat's log at this cell: copies of writes that
    /// open under the wallet's key here.
    pub fn keeps(&self) -> impl Fn(&crate::route_chain::RouteEntry) -> bool + Sync + '_ {
        crate::route_chain::recognized_copies(&self.cell, move |bytes| {
            let refused = std::cell::RefCell::new(Vec::new());
            let recognize = self.recognize(&refused);
            recognize(bytes).is_some()
        })
    }
}

/// What a reader finds at a backup cell: the storage fact, and the backup
/// holding the cell with the exact bytes of its write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRead {
    n: u64,
    fact: CellFact,
    held: Option<(Opened, Vec<u8>)>,
    passed_over: Vec<BackupRefusal>,
}

impl BackupRead {
    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn fact(&self) -> CellFact {
        self.fact
    }

    /// Why each value the leader holds ahead of the backup counts as nothing.
    pub fn passed_over(&self) -> &[BackupRefusal] {
        &self.passed_over
    }

    /// Whether no write holds the cell.
    pub fn open(&self) -> bool {
        matches!(self.fact, CellFact::Open)
    }

    /// The part once its write is final (storage spec §9 rule 7).
    pub fn settled(&self) -> Option<&Opened> {
        match (&self.held, self.fact) {
            (
                Some((opened, _)),
                CellFact::Held {
                    state: ChainState::Final,
                    ..
                },
            ) => Some(opened),
            (Some(..), CellFact::Held { .. } | CellFact::Open) | (None, _) => None,
        }
    }
}

/// A write's name at its cell: the digest of its exact bytes.
fn write_id(bytes: &[u8]) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
    h.update(bytes);
    *h.finalize().as_bytes()
}

/// The route-chain reading of a backup cell (storage spec §9): open, or the
/// first recognized write at its leader and how far its chain has gone.
/// Evidence that does not decide the cell yet is [`Missing`], never an answer.
pub fn resolution(cell: &BackupCell, evidence: &CellEvidence) -> Result<BackupRead, Missing> {
    let refused = std::cell::RefCell::new(Vec::new());
    let reading = evaluate(&cell.cell, evidence, cell.recognize(&refused))?;
    let fact = reading.fact();
    let held = match reading {
        CellReading::Held { object, value, .. } => Some((object, value)),
        CellReading::Open => None,
    };
    Ok(BackupRead {
        n: cell.n,
        fact,
        held,
        passed_over: refused.into_inner(),
    })
}

/// The recognizer of the one write a read found holding the cell, by its
/// exact bytes, so a completion proof is about the same leader link.
fn held_write(read: &BackupRead) -> impl Fn(&[u8]) -> Option<(D32, Opened)> + '_ {
    move |bytes| match &read.held {
        Some((opened, value)) if value.as_slice() == bytes => {
            Some((write_id(bytes), opened.clone()))
        }
        Some(..) | None => None,
    }
}

/// The completion proof of the backup `read` found final at the cell; `None`
/// while no chain of it has three links, or when the read found the cell open.
pub fn completion(
    cell: &BackupCell,
    read: &BackupRead,
    evidence: &CellEvidence,
) -> Result<Option<(Opened, CompletionProof)>, Missing> {
    completion_proof(&cell.cell, evidence, held_write(read))
}

/// Check a kept completion proof of the backup `read` found at the cell
/// against the reads in `evidence`.
pub fn check_completion(
    cell: &BackupCell,
    read: &BackupRead,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<Opened, ProofRefusal> {
    check_completion_proof(&cell.cell, evidence, proof, held_write(read))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(seed: u8) -> BackupKeys {
        BackupKeys::of_wallet_seed(&[seed; 64])
    }

    /// The keys are the drafted hashes of the wallet seed, and each backup has
    /// its own cell.
    #[test]
    fn the_derivations_are_the_drafted_hashes() {
        let seed = [0x5A; 64];
        let k = BackupKeys::of_wallet_seed(&seed);
        let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_LOCATOR);
        h.update(&seed);
        let locator = *h.finalize().as_bytes();
        let attempt = [0x0A; 16];
        let mut c = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
        c.update(&locator);
        c.update(&7u64.to_le_bytes());
        c.update(&2u32.to_le_bytes());
        c.update(&attempt);
        let later = Place::of(2, attempt);
        assert_eq!(k.cell_key(7, &later), *c.finalize().as_bytes());
        let mut first = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
        first.update(&locator);
        first.update(&7u64.to_le_bytes());
        first.update(&0u32.to_le_bytes());
        assert_eq!(
            k.cell_key(7, &Place::of(0, attempt)),
            *first.finalize().as_bytes(),
            "part 0 lies at the backup's own cell, whatever the attempt"
        );
        assert_ne!(
            k.cell_key(7, &later),
            k.cell_key(8, &later),
            "each backup its own cells"
        );
        assert_ne!(
            k.cell_key(7, &later),
            k.cell_key(7, &Place::of(2, [0x0B; 16])),
            "each attempt its own later cells"
        );
        assert_ne!(
            k.cell_key(7, &later),
            keys(0x5B).cell_key(7, &later),
            "another wallet's cells"
        );
    }

    /// A part opens only under its own wallet's key, at its own cell, as the
    /// backup, part and attempt it names; any other bytes, or a flipped bit,
    /// open nothing.
    #[test]
    fn a_backup_opens_only_as_itself() {
        let k = keys(1);
        let attempt = [0x0A; 16];
        let at = Place::of(1, attempt);
        let write = k
            .seal(3, 1, 2, &attempt, b"the resume set")
            .expect("sealed");
        assert_eq!(
            k.open(3, &at, &write),
            Ok(Opened {
                parts: 2,
                attempt,
                chunk: b"the resume set".to_vec()
            })
        );
        let refused = |n, place: Place, w: &[u8]| k.open(n, &place, w);
        assert_eq!(
            refused(4, at, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another backup"
        );
        assert_eq!(
            refused(3, Place::First, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another part"
        );
        assert_eq!(
            refused(3, Place::of(1, [0x0B; 16]), &write),
            Err(BackupRefusal::DoesNotOpen),
            "another attempt"
        );
        assert_eq!(
            keys(2).open(3, &at, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another key"
        );
        let mut flipped = write.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            k.open(3, &at, &flipped),
            Err(BackupRefusal::DoesNotOpen),
            "a flipped bit"
        );
        assert_eq!(k.open(3, &at, b"short"), Err(BackupRefusal::Short));
        let head = k.seal(3, 0, 2, &attempt, b"first").expect("part 0");
        assert_eq!(
            k.open(3, &Place::First, &head).map(|o| o.attempt),
            Ok(attempt),
            "part 0 names its attempt"
        );
        let past = k
            .seal(3, 2, 2, &attempt, b"x")
            .expect_err("no part past the count");
        assert!(past.to_string().contains("part 2 of 2"), "{past}");
        let full = k
            .seal(5, 0, 1, &attempt, &vec![0xAB; MAX_PART])
            .expect("a full part");
        assert_eq!(
            full.len(),
            crate::route_chain::MAX_VALUE_LEN,
            "one cell value at its largest"
        );
        let again = k
            .seal(3, 1, 2, &attempt, b"the resume set")
            .expect("sealed");
        assert_ne!(again, write, "a fresh nonce for every seal");
    }
}
