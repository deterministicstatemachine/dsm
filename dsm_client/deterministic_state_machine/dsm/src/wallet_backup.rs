// SPDX-License-Identifier: MIT OR Apache-2.0

//! A wallet's sealed backup on storage nodes (DSM Amendment A40).
//!
//! What a phone holds to carry on with its contacts — each relationship's
//! chain tip and its key chain, the write grants, the device head — lives only
//! on the phone. A wallet therefore keeps a backup of it on the storage nodes,
//! sealed under a key only its 24 words give, and a wallet restored from those
//! words reads it back. The network's own record of every payment is the full
//! history; the backup is one per device and is written over (owner,
//! 2026-11-23: "There only should be one backup per phone, per device,
//! basically, and of course, there's the full history for the mirroring", and
//! "It should replace it. It should be a separate thing, and yes, it needs the
//! key to do such a thing"):
//!
//! ```text
//! k = H(DSM/wallet-backup/key/v1 ‖ wallet_seed)       the seal's key
//! l = H(DSM/wallet-backup/locator/v1 ‖ wallet_seed)   the slot's secret route
//! S = H(DSM/wallet-backup/slot/v1 ‖ l ‖ lock)          the device's one slot
//! part_i = nonce(24) ‖ XChaCha20-Poly1305(k, nonce, aad = S,
//!                                         g ‖ i ‖ parts ‖ chunk_i)
//! d_i = H(DSM/wallet-backup/part/v1 ‖ part_i)
//! start = l, lock, g, d_0 … d_{parts−1},
//!         sig_lock(H(DSM/wallet-backup/slot-write/v1 ‖ S ‖ g ‖ parts ‖ d_0 … ))
//! ```
//!
//! `lock` is the device's cell lock, the key its directory entry publishes and
//! its master seed alone derives. A write of the slot starts with the start,
//! naming the generation `g` and every part's digest under the lock's
//! signature; a member then takes a part only when its digest is the one the
//! start names. Each member holds one whole backup per slot and at most one
//! being written: a start with a higher generation than any it took replaces
//! the one being written (an attempt the wallet's next step cut short is
//! written over), and the one being written replaces the whole one the moment
//! the member holds its every part. Nothing else ever reaches the slot, and an
//! older start, replayed, is refused, since its generation is lower.
//!
//! Whether the backup is current is the restore's to decide: its body names
//! the register position it was taken at, and only a backup taken at the
//! position the restore re-verified is installed. An older one is never used,
//! so a member that withholds the latest backup can keep contacts from coming
//! back, but can never roll them back. What the body holds is the SDK's.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::common::domain_tags::{
    TAG_DSM_WALLET_BACKUP_KEY, TAG_DSM_WALLET_BACKUP_LOCATOR, TAG_DSM_WALLET_BACKUP_PART,
    TAG_DSM_WALLET_BACKUP_SLOT, TAG_DSM_WALLET_BACKUP_SLOT_WRITE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, SphincsKeyPair};
use crate::owned_cell::{fixed32, signed_by, strict, CellWriteRefusal, CELL_LOCK_LEN};
use crate::types::error::DsmError;
use crate::types::proto::BackupSlotStartV1;
use crate::types::receipt_types::FieldLimit;

type D32 = [u8; 32];

/// An XChaCha20 nonce.
const NONCE_LEN: usize = 24;

/// A Poly1305 tag.
const TAG_LEN: usize = 16;

/// What a part names before its bytes: the generation, the part's index and
/// the count of parts.
const HEADER_LEN: usize = 8 + 4 + 4;

/// The most one part carries, so a sealed part is no larger than one cell
/// value at its largest (`route_chain::MAX_VALUE_LEN`).
pub const MAX_PART: usize = crate::route_chain::MAX_VALUE_LEN - NONCE_LEN - TAG_LEN - HEADER_LEN;

/// The most parts one backup has: a backup is at most this many times
/// [`MAX_PART`].
pub const MAX_PARTS: usize = 64;

/// Why a part is not a wallet's backup at its slot. Nothing about its bytes is
/// revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupRefusal {
    /// Shorter than a nonce and a header.
    Short,
    /// It does not open under this wallet's key at this slot.
    DoesNotOpen,
    /// It opens, but as another generation or part than the one read.
    OtherPart { generation: u64, part: u32 },
    /// It names a part past its own count.
    NoSuchPart { part: u32, parts: u32 },
}

/// One part of a backup as it opens: how many parts the backup has, and this
/// part's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub parts: u32,
    pub chunk: Vec<u8>,
}

/// The keys of one wallet's backup, from its wallet seed. Held only by the
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

/// A device's backup slot: its secret route bound to its cell lock.
pub fn slot_address(route: &D32, lock_public_key: &[u8]) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_SLOT);
    h.update(route);
    h.update(lock_public_key);
    *h.finalize().as_bytes()
}

/// A sealed part's digest, as a start names it and a member checks it.
pub fn part_digest(part: &[u8]) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_PART);
    h.update(part);
    *h.finalize().as_bytes()
}

/// What the cell lock signs to start generation `generation` of `slot`, whose
/// parts have `digests`: `H(tag ‖ S ‖ u64be(g) ‖ u32be(parts) ‖ d_0 … )`. Every
/// field has a fixed length once the count is known, so the signed bytes have
/// one reading.
fn start_target(slot: &D32, generation: u64, digests: &[D32]) -> Result<D32, StartRefusal> {
    if digests.len() > MAX_PARTS {
        return Err(StartRefusal::TooManyParts);
    }
    let parts = u32::try_from(digests.len())
        .map_err(|e| StartRefusal::Wire(format!("the count of parts: {e}")))?;
    let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_SLOT_WRITE);
    h.update(slot);
    h.update(&generation.to_be_bytes());
    h.update(&parts.to_be_bytes());
    for d in digests {
        h.update(d);
    }
    Ok(*h.finalize().as_bytes())
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

    /// This wallet's backup slot on the device whose cell lock is
    /// `lock_public_key`.
    pub fn slot(&self, lock_public_key: &[u8]) -> D32 {
        slot_address(&self.locator, lock_public_key)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.seal).into())
    }

    /// `chunk` sealed as part `part` of the `parts` of generation `generation`
    /// at `slot`, under a fresh nonce.
    pub fn seal(
        &self,
        slot: &D32,
        generation: u64,
        part: u32,
        parts: u32,
        chunk: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        if part >= parts {
            return Err(DsmError::invalid_operation(format!(
                "wallet backup: part {part} of {parts}"
            )));
        }
        if chunk.len() > MAX_PART {
            return Err(DsmError::invalid_operation(format!(
                "wallet backup: a part of {} bytes, past {MAX_PART}",
                chunk.len()
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
        plain.extend_from_slice(&generation.to_le_bytes());
        plain.extend_from_slice(&part.to_le_bytes());
        plain.extend_from_slice(&parts.to_le_bytes());
        plain.extend_from_slice(chunk);
        let sealed = self
            .cipher()
            .encrypt(
                nonce,
                Payload {
                    msg: &plain,
                    aad: slot,
                },
            )
            .map_err(|chacha20poly1305::aead::Error| {
                DsmError::invalid_operation("wallet backup: sealing failed")
            })?;
        let mut out = nonce_bytes;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Part `part` of generation `generation` at `slot` as `sealed` holds it,
    /// or why it is not that part.
    pub fn open(
        &self,
        slot: &D32,
        generation: u64,
        part: u32,
        sealed: &[u8],
    ) -> Result<Opened, BackupRefusal> {
        let (nonce, body) = sealed
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(BackupRefusal::Short)?;
        let plain = self
            .cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: slot,
                },
            )
            .map_err(|chacha20poly1305::aead::Error| BackupRefusal::DoesNotOpen)?;
        let (named, rest) = plain.split_first_chunk::<8>().ok_or(BackupRefusal::Short)?;
        let (named_part, rest) = rest.split_first_chunk::<4>().ok_or(BackupRefusal::Short)?;
        let (parts, chunk) = rest.split_first_chunk::<4>().ok_or(BackupRefusal::Short)?;
        let (named, named_part) = (u64::from_le_bytes(*named), u32::from_le_bytes(*named_part));
        let parts = u32::from_le_bytes(*parts);
        if named != generation || named_part != part {
            return Err(BackupRefusal::OtherPart {
                generation: named,
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

    /// The start of generation `generation` of this wallet's slot on the
    /// device whose cell lock is `lock`, for parts with `digests`: the slot
    /// and the start's bytes, signed by the lock.
    pub fn start(
        &self,
        lock: &SphincsKeyPair,
        generation: u64,
        digests: &[D32],
    ) -> Result<(D32, Vec<u8>), DsmError> {
        use prost::Message;
        let slot = self.slot(&lock.public_key);
        let target = start_target(&slot, generation, digests)
            .map_err(|why| DsmError::invalid_operation(format!("wallet backup: {why}")))?;
        let start = BackupSlotStartV1 {
            route: self.locator.to_vec(),
            lock_public_key: lock.public_key.clone(),
            generation: generation.to_be_bytes().to_vec(),
            part_digests: digests.concat(),
            write_signature: sphincs_sign(&lock.secret_key, &target)?,
        };
        let bytes = start.encode_to_vec();
        admit_start(&slot, &bytes)
            .map_err(|why| DsmError::invalid_operation(format!("wallet backup: {why}")))?;
        Ok((slot, bytes))
    }
}

/// Why a member takes no start at a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartRefusal {
    /// The start is not its strict wire form, or its route or lock is not its
    /// length: why.
    Wire(String),
    /// The slot is not the route bound to the lock the start carries.
    WrongAddress,
    /// The start names no parts.
    NoParts,
    /// The start names more than [`MAX_PARTS`] parts.
    TooManyParts,
    /// Generation 0 names no backup.
    GenerationZero,
    /// The lock did not sign this start, or it could not be checked: why.
    Signature(String),
}

impl core::fmt::Display for StartRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(why) => write!(f, "the start is not its wire form: {why}"),
            Self::WrongAddress => write!(f, "the slot is not the address the start binds"),
            Self::NoParts => write!(f, "the start names no parts"),
            Self::TooManyParts => write!(f, "the start names more than {MAX_PARTS} parts"),
            Self::GenerationZero => write!(f, "generation 0 names no backup"),
            Self::Signature(why) => write!(f, "the lock did not sign the start: {why}"),
        }
    }
}

impl std::error::Error for StartRefusal {}

impl From<CellWriteRefusal> for StartRefusal {
    fn from(why: CellWriteRefusal) -> Self {
        match why {
            CellWriteRefusal::Wire(why) => Self::Wire(why),
            other => Self::Signature(other.to_string()),
        }
    }
}

fn start_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 => Some(FieldLimit::Fixed(32)),
        2 => Some(FieldLimit::Fixed(CELL_LOCK_LEN)),
        3 => Some(FieldLimit::Fixed(8)),
        4 => Some(FieldLimit::Max(32 * MAX_PARTS)),
        5 => Some(FieldLimit::Max(crate::owned_cell::SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

/// The digests `bytes` lists, 32 bytes each in order: why not when its
/// length is not a whole number of digests.
pub fn digests_of(bytes: &[u8]) -> Result<Vec<D32>, String> {
    let (whole, rest) = bytes.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(format!(
            "{} bytes of part digests are not a whole number of digests",
            bytes.len()
        ));
    }
    Ok(whole.to_vec())
}

/// A start a member takes at `slot`: the generation and the parts' digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub generation: u64,
    pub part_digests: Vec<D32>,
}

/// The one check a member runs before it takes a start at `slot`: the start
/// is its strict wire form, the slot is its route bound to its lock, it names
/// a generation and between one and [`MAX_PARTS`] parts, and the lock signed
/// exactly this. The protocol running, the same on every member, with no list
/// of owners and no state, as `dsm::owned_cell`'s check is.
pub fn admit_start(slot: &D32, bytes: &[u8]) -> Result<Start, StartRefusal> {
    let start: BackupSlotStartV1 = strict(bytes, "backup slot start", 5, start_field_limit)?;
    let route = fixed32(&start.route)?;
    if slot_address(&route, &start.lock_public_key) != *slot {
        return Err(StartRefusal::WrongAddress);
    }
    let generation = u64::from_be_bytes(
        <[u8; 8]>::try_from(start.generation.as_slice())
            .map_err(|e| StartRefusal::Wire(format!("the generation: {e}")))?,
    );
    if generation == 0 {
        return Err(StartRefusal::GenerationZero);
    }
    let part_digests = digests_of(&start.part_digests).map_err(StartRefusal::Wire)?;
    if part_digests.is_empty() {
        return Err(StartRefusal::NoParts);
    }
    if part_digests.len() > MAX_PARTS {
        return Err(StartRefusal::TooManyParts);
    }
    let target = start_target(slot, generation, &part_digests)?;
    signed_by(&start.lock_public_key, &target, &start.write_signature)?;
    Ok(Start {
        generation,
        part_digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::generate_keypair_from_seed;

    fn keys(seed: u8) -> BackupKeys {
        BackupKeys::of_wallet_seed(&[seed; 64])
    }

    fn lock(seed: u8) -> SphincsKeyPair {
        generate_keypair_from_seed(crate::owned_cell::CELL_LOCK_VARIANT, &[seed; 32])
            .expect("a lock")
    }

    /// The keys and the slot are the drafted hashes, and each wallet on each
    /// device has its own slot.
    #[test]
    fn the_derivations_are_the_drafted_hashes() {
        let seed = [0x5A; 64];
        let k = BackupKeys::of_wallet_seed(&seed);
        let mut h = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_LOCATOR);
        h.update(&seed);
        let locator = *h.finalize().as_bytes();
        let lock = [0x0C; 64];
        let mut s = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_SLOT);
        s.update(&locator);
        s.update(&lock);
        assert_eq!(k.slot(&lock), *s.finalize().as_bytes());
        assert_ne!(k.slot(&lock), keys(0x5B).slot(&lock), "another wallet");
        assert_ne!(k.slot(&lock), k.slot(&[0x0D; 64]), "another device's lock");
        let mut d = dsm_domain_hasher(TAG_DSM_WALLET_BACKUP_PART);
        d.update(b"a part");
        assert_eq!(part_digest(b"a part"), *d.finalize().as_bytes());
    }

    /// A part opens only under its own wallet's key, at its own slot, as the
    /// generation and part it names; any other bytes, or a flipped bit, open
    /// nothing.
    #[test]
    fn a_part_opens_only_as_itself() {
        let k = keys(1);
        let slot = k.slot(&[0x0C; 64]);
        let sealed = k.seal(&slot, 3, 1, 2, b"the resume set").expect("sealed");
        assert_eq!(
            k.open(&slot, 3, 1, &sealed),
            Ok(Opened {
                parts: 2,
                chunk: b"the resume set".to_vec()
            })
        );
        assert_eq!(
            k.open(&slot, 4, 1, &sealed),
            Err(BackupRefusal::OtherPart {
                generation: 3,
                part: 1
            }),
            "another generation"
        );
        assert_eq!(
            k.open(&slot, 3, 0, &sealed),
            Err(BackupRefusal::OtherPart {
                generation: 3,
                part: 1
            }),
            "another part"
        );
        assert_eq!(
            k.open(&k.slot(&[0x0D; 64]), 3, 1, &sealed),
            Err(BackupRefusal::DoesNotOpen),
            "another slot"
        );
        assert_eq!(
            keys(2).open(&slot, 3, 1, &sealed),
            Err(BackupRefusal::DoesNotOpen),
            "another key"
        );
        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            k.open(&slot, 3, 1, &flipped),
            Err(BackupRefusal::DoesNotOpen),
            "a flipped bit"
        );
        assert_eq!(k.open(&slot, 3, 1, b"short"), Err(BackupRefusal::Short));
        let past = k
            .seal(&slot, 3, 2, 2, b"x")
            .expect_err("no part past the count");
        assert!(past.to_string().contains("part 2 of 2"), "{past}");
        let full = k
            .seal(&slot, 5, 0, 1, &vec![0xAB; MAX_PART])
            .expect("a full part");
        assert_eq!(
            full.len(),
            crate::route_chain::MAX_VALUE_LEN,
            "one cell value at its largest"
        );
        let over = k
            .seal(&slot, 5, 0, 1, &vec![0xAB; MAX_PART + 1])
            .expect_err("no part past MAX_PART");
        assert!(over.to_string().contains("past"), "{over}");
        let again = k.seal(&slot, 3, 1, 2, b"the resume set").expect("sealed");
        assert_ne!(again, sealed, "a fresh nonce for every seal");
    }

    /// A member takes a start only at the slot its route and lock bind, signed
    /// by that lock over exactly its generation and digests.
    #[test]
    fn a_start_is_taken_only_as_its_lock_signed_it() {
        use prost::Message;
        let k = keys(1);
        let owner = lock(7);
        let digests = [part_digest(b"one"), part_digest(b"two")];
        let (slot, bytes) = k.start(&owner, 9, &digests).expect("a start");
        assert_eq!(slot, k.slot(&owner.public_key));
        assert_eq!(
            admit_start(&slot, &bytes),
            Ok(Start {
                generation: 9,
                part_digests: digests.to_vec()
            })
        );
        assert_eq!(
            admit_start(&k.slot(&lock(8).public_key), &bytes),
            Err(StartRefusal::WrongAddress),
            "another device's slot"
        );
        let decoded = BackupSlotStartV1::decode(bytes.as_slice()).expect("decoded");
        let tampered = |f: &dyn Fn(&mut BackupSlotStartV1)| {
            let mut s = decoded.clone();
            f(&mut s);
            admit_start(&slot, &s.encode_to_vec())
        };
        assert!(
            matches!(
                tampered(&|s| s.generation = 10u64.to_be_bytes().to_vec()),
                Err(StartRefusal::Signature(_))
            ),
            "another generation"
        );
        assert!(
            matches!(
                tampered(&|s| s.part_digests[32..].copy_from_slice(&part_digest(b"three"))),
                Err(StartRefusal::Signature(_))
            ),
            "another part"
        );
        assert!(
            matches!(
                tampered(&|s| s.part_digests.truncate(32)),
                Err(StartRefusal::Signature(_))
            ),
            "a part dropped"
        );
        let stranger = lock(8);
        let (_, theirs) = k.start(&stranger, 9, &digests).expect("their start");
        let mut forged = BackupSlotStartV1::decode(theirs.as_slice()).expect("decoded");
        forged.lock_public_key = owner.public_key.clone();
        assert!(
            matches!(
                admit_start(&slot, &forged.encode_to_vec()),
                Err(StartRefusal::Signature(_))
            ),
            "a stranger's signature under the owner's lock"
        );
        let zero = k.start(&owner, 0, &digests).expect_err("no generation 0");
        assert!(zero.to_string().contains("generation 0"), "{zero}");
        let none = k.start(&owner, 1, &[]).expect_err("no parts");
        assert!(none.to_string().contains("field 4"), "{none}");
        let many = k
            .start(&owner, 1, &vec![part_digest(b"one"); MAX_PARTS + 1])
            .expect_err("too many parts");
        assert!(many.to_string().contains("more than"), "{many}");
        assert!(matches!(
            admit_start(&slot, &[0xFF, 0x01]),
            Err(StartRefusal::Wire(_))
        ));
    }
}
