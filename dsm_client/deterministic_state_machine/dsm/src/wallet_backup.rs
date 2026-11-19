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
//! K_n,i = H(DSM/wallet-backup/v1 ‖ l ‖ n ‖ i)            part i of backup n
//! s     = H(DSM/wallet-backup/seed/v1 ‖ K_n,i)           its route's seed
//! write = nonce(24) ‖ XChaCha20-Poly1305(k, nonce, aad = K_n,i,
//!                                        n ‖ i ‖ parts ‖ chunk)
//! ```
//!
//! A backup is split into parts no larger than a node takes in one write;
//! part `i` of the `n`-th backup goes to cell `K_n,i`, which holds the first
//! write recognized at its leader and is final by storage §9 as every cell is.
//! A write is recognized only when it opens under `k` and names its cell's own
//! `n` and `i`: no node and no other party can make one, and no node can tell
//! where the next backup goes, since `l` is secret. Part 0, which says how many
//! parts there are, is written last, and a wallet writes backup `n` only once
//! backup `n − 1` is written, so the backups fill the cells in order and the
//! latest is the last whose part 0 holds its cell.
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

/// What a part names before its bytes: the backup's number, the part's and the
/// count of parts.
const HEADER_LEN: usize = 8 + 4 + 4;

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
    /// It opens, but as another backup or part than the cell's.
    OtherBackup { named: u64, part: u32 },
    /// It names a part past its own count.
    NoSuchPart { part: u32, parts: u32 },
}

/// One part of a backup as its write opens: how many parts the backup has, and
/// this part's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub parts: u32,
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

    /// `K_n,i`, the cell of part `i` of the `n`-th backup.
    pub fn cell_key(&self, n: u64, part: u32) -> D32 {
        let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
        h.update(&self.locator);
        h.update(&n.to_le_bytes());
        h.update(&part.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.seal).into())
    }

    /// The write of `chunk` as part `part` of the `n`-th backup, which has
    /// `parts` parts, under a fresh nonce.
    pub fn seal(&self, n: u64, part: u32, parts: u32, chunk: &[u8]) -> Result<Vec<u8>, DsmError> {
        if part >= parts {
            return Err(DsmError::invalid_operation(format!(
                "wallet backup: part {part} of {parts}"
            )));
        }
        let nonce_bytes = crate::crypto::rng::random_bytes(NONCE_LEN);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let mut plain = Vec::with_capacity(HEADER_LEN + chunk.len());
        plain.extend_from_slice(&n.to_le_bytes());
        plain.extend_from_slice(&part.to_le_bytes());
        plain.extend_from_slice(&parts.to_le_bytes());
        plain.extend_from_slice(chunk);
        let key = self.cell_key(n, part);
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

    /// Part `part` of the `n`-th backup as `write` holds it, or why it is not
    /// that part.
    pub fn open(&self, n: u64, part: u32, write: &[u8]) -> Result<Opened, BackupRefusal> {
        let (nonce, sealed) = write
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(BackupRefusal::Short)?;
        let key = self.cell_key(n, part);
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
        let (parts, chunk) = rest.split_first_chunk::<4>().ok_or(BackupRefusal::Short)?;
        let (named, named_part) = (u64::from_le_bytes(*named), u32::from_le_bytes(*named_part));
        let parts = u32::from_le_bytes(*parts);
        if named != n || named_part != part {
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
            chunk: chunk.to_vec(),
        })
    }
}

/// The cell of one part of a wallet's `n`-th backup on the network's pinned
/// set.
pub struct BackupCell {
    keys: BackupKeys,
    n: u64,
    part: u32,
    cell: RoutedCell,
}

impl BackupCell {
    /// The cell of part `part` of backup `n`. `members` must re-derive
    /// `committed_set_id`.
    pub fn new(
        keys: &BackupKeys,
        n: u64,
        part: u32,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let key = keys.cell_key(n, part);
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
            part,
            cell: routed,
        })
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn part(&self) -> u32 {
        self.part
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
        move |bytes| match self.keys.open(self.n, self.part, bytes) {
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
        let mut c = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_CELL);
        c.update(&locator);
        c.update(&7u64.to_le_bytes());
        c.update(&2u32.to_le_bytes());
        assert_eq!(k.cell_key(7, 2), *c.finalize().as_bytes());
        assert_ne!(
            k.cell_key(7, 2),
            k.cell_key(8, 2),
            "each backup its own cells"
        );
        assert_ne!(k.cell_key(7, 2), k.cell_key(7, 1), "each part its own cell");
        assert_ne!(
            k.cell_key(7, 2),
            keys(0x5B).cell_key(7, 2),
            "another wallet's cells"
        );
    }

    /// A part opens only under its own wallet's key, at its own cell, as the
    /// backup and part it names; any other bytes, or a flipped bit, open
    /// nothing.
    #[test]
    fn a_backup_opens_only_as_itself() {
        let k = keys(1);
        let write = k.seal(3, 1, 2, b"the resume set").expect("sealed");
        assert_eq!(
            k.open(3, 1, &write),
            Ok(Opened {
                parts: 2,
                chunk: b"the resume set".to_vec()
            })
        );
        assert_eq!(
            k.open(4, 1, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another backup"
        );
        assert_eq!(
            k.open(3, 0, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another part"
        );
        assert_eq!(
            keys(2).open(3, 1, &write),
            Err(BackupRefusal::DoesNotOpen),
            "another key"
        );
        let mut flipped = write.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            k.open(3, 1, &flipped),
            Err(BackupRefusal::DoesNotOpen),
            "a flipped bit"
        );
        assert_eq!(k.open(3, 1, b"short"), Err(BackupRefusal::Short));
        let past = k.seal(3, 2, 2, b"x").expect_err("no part past the count");
        assert!(past.to_string().contains("part 2 of 2"), "{past}");
        let full = k.seal(5, 0, 1, &vec![0xAB; MAX_PART]).expect("a full part");
        assert_eq!(
            full.len(),
            crate::route_chain::MAX_VALUE_LEN,
            "one cell value at its largest"
        );
        let again = k.seal(3, 1, 2, b"the resume set").expect("sealed");
        assert_ne!(again, write, "a fresh nonce for every seal");
    }
}
