// SPDX-License-Identifier: MIT OR Apache-2.0
//! From a chip and the board's sealed secret to an anchor: the chip's identity, the session on the
//! board's own pairing slot once born, the counter and resident key, and the record in R-memory.
//!
//! Every secret the anchor's identity needs derives from the sealed secret; the public part roots
//! in the chip's fused `stpub` and `chip_id`. What the anchor is bound to (the owner's device id,
//! online key, policy and genesis) arrives once, in the owner's provisioning.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::anchor::{Anchor, AnchorBootRefusal};
use anchor_core::enrollment::ChipBirth;
use anchor_core::hash::{h, kdf};
use anchor_core::proto::{decode_request, pb};
use anchor_core::rmem::{LayoutError, SlotMemory, SlottedStore};
use anchor_core::service::{err, refusal, MAX_FRAME_LEN};
use anchor_core::tropic::{PartitionError, PartitionSig, Tropic, TropicError};
use dsm_sphincs::SphincsVariant;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use tropic01::{NoSession, Tropic01};

use crate::session::{ChipFault, ChipSession, OpenRefused, RMemSlots, RealChip};
use crate::Board;

/// σ^host scheme — MUST match the receiver (byte-compatible SPX128f).
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;
/// The counter's lifetime budget `H0` at birth: tropic01 `MCOUNTER_VALUE_MAX`.
pub const ENROLL_H0: u32 = 0xFFFF_FFFE;
/// The first R-memory data slot of the anchor's record.
const RECORD_FIRST_SLOT: u16 = 0;

/// The anchor as a board holds it, the concrete chip session erased.
pub type BoardAnchor = Anchor<Box<dyn Tropic>, SphincsPart, SlottedStore<Box<dyn SlotMemory>>>;

/// BLAKE3-SPHINCS+ SPX128f as the partition (`σ^host`) signature scheme.
pub struct SphincsPart;
impl PartitionSig for SphincsPart {
    fn part_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError> {
        let kp =
            dsm_sphincs::generate_keypair_from_seed(PART_VARIANT, seed).map_err(partition_error)?;
        Ok((kp.secret_key.clone(), kp.public_key.clone()))
    }
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError> {
        dsm_sphincs::sign(PART_VARIANT, sk, digest).map_err(partition_error)
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        matches!(dsm_sphincs::verify(PART_VARIANT, pk, digest, sig), Ok(valid) if valid)
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

/// The anchor's identity on this board.
struct ChipIdentity {
    anchor_id: [u8; 32],
    partition_device_id: [u8; 32],
    partition_key_seed: [u8; 32],
    birth_entropy: [u8; 32],
    birth_host_nonce: [u8; 32],
    birth_witness: [u8; 32],
    pairing: [u8; 32],
}
impl ChipIdentity {
    fn derive(stpub: &[u8; 32], chip_id_hash: &[u8; 32], sealed: &[u8; 32]) -> Self {
        let root = h("DSM/anchor/chip-root/v1", &[stpub, chip_id_hash]);
        Self {
            anchor_id: h("DSM/anchor/anchor-id/v1", &[&root]),
            partition_device_id: h("DSM/anchor/partition-device-id/v1", &[&root]),
            partition_key_seed: kdf(sealed, "DSM/anchor/partition-seed/v2", &[&root]),
            birth_entropy: kdf(sealed, "DSM/anchor/birth-entropy/v2", &[&root]),
            birth_host_nonce: kdf(sealed, "DSM/anchor/birth-host-nonce/v2", &[&root]),
            birth_witness: kdf(sealed, "DSM/anchor/birth-witness/v2", &[&root]),
            pairing: kdf(sealed, "DSM/anchor/pairing-key/v1", &[&root]),
        }
    }
}

/// What a fresh measurement of the Non-secure image found, against its enrolled digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Measurement {
    Matches,
    Differs,
}

/// The ops the §2 measurement seal gates. A provisioning is among them: it is irreversible, so a
/// board whose Non-secure image does not hash to its burned digest is refused before its chip is
/// bound and caged, not after.
fn op_requires_measurement(op: i32) -> bool {
    matches!(
        pb::Op::try_from(op),
        Ok(pb::Op::Provision
            | pb::Op::TryRun
            | pb::Op::Prepare
            | pb::Op::Commit
            | pb::Op::Emit
            | pb::Op::Finalize
            | pb::Op::Recover)
    )
}

/// Decode the request, apply the §2 measurement gate to the DECODED op, and serve it through the
/// anchor. Every refusal is an answer the host can read: a locked board has no debug port to ask.
pub fn serve_measured(
    anchor: BoardAnchor,
    frame: &[u8],
    measurement: Measurement,
) -> (BoardAnchor, Vec<u8>) {
    let req = match decode_request(frame) {
        Ok(req) => req,
        Err(_undecodable) => return (anchor, refusal(0, err::BAD_PROTO, "")),
    };
    if measurement == Measurement::Differs && op_requires_measurement(req.op) {
        // §7.12 measurement failure => no counter movement, no TROPIC/host signature.
        let refused = refusal(
            req.op,
            err::MEASUREMENT,
            "the Non-secure image does not match the enrolled digest",
        );
        return (anchor, refused);
    }
    anchor.serve(frame)
}

/// Why the anchor did not come up, with the cause each step reported.
pub enum BringUpFailure<F> {
    ChipId(F),
    CertStore(F),
    /// tropic01 does not export its `PublicKeyError`, so the cause is carried type-erased.
    CertStoreKey(Box<dyn core::fmt::Debug>),
    Session(OpenRefused<F>),
    /// The counter or the resident chip key.
    Enroll(TropicError),
    /// The R-memory record does not fit.
    Layout(LayoutError),
    /// The record could not be restored, or §26 recovery refused it.
    Recovery(AnchorBootRefusal),
}

impl<F: core::fmt::Debug> core::fmt::Debug for BringUpFailure<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChipId(cause) => write!(f, "ChipId: {cause:?}"),
            Self::CertStore(cause) => write!(f, "CertStore: {cause:?}"),
            Self::CertStoreKey(cause) => write!(f, "CertStoreKey: {cause:?}"),
            Self::Session(cause) => write!(f, "Session: {cause:?}"),
            Self::Enroll(cause) => write!(f, "Enroll: {cause:?}"),
            Self::Layout(cause) => write!(f, "Layout: {cause:?}"),
            Self::Recovery(cause) => write!(f, "Recovery: {cause:?}"),
        }
    }
}

/// Bring the anchor up: unprovisioned when its R-memory holds no record, otherwise restored from
/// the record through §26 recovery.
pub fn bring_up<SPI, CS, B>(
    mut chip: Tropic01<SPI, CS, NoSession>,
    sealed: &[u8; 32],
    board: B,
) -> Result<BoardAnchor, BringUpFailure<ChipFault<SPI, CS>>>
where
    SPI: SpiDevice + 'static,
    CS: OutputPin + 'static,
    B: Board + 'static,
{
    // The chip's identity (chip_id + device-cert stpub), read before session_start consumes the
    // NoSession handle. Fail closed if the chip will not disclose a real identity.
    let chip_id = chip.get_info_chip_id().map_err(BringUpFailure::ChipId)?;
    let chip_id_hash = h("DSM/anchor/chip-id/v1", &[chip_id]);
    let cert_store = chip
        .get_info_cert_store()
        .map_err(BringUpFailure::CertStore)?;
    let stpub: [u8; 32] = *cert_store
        .public_key()
        .map_err(|cause| BringUpFailure::CertStoreKey(Box::new(cause)))?;
    // Space the cert-store read from session_start's own: the chip needs a gap between back-to-back
    // L2 reads.
    board.wait_100ms();
    let ident = ChipIdentity::derive(&stpub, &chip_id_hash, sealed);

    // The authenticated L3 session, on the board's own pairing slot once born.
    let session = ChipSession::open(chip, ident.pairing, board).map_err(BringUpFailure::Session)?;
    let session = Rc::new(RefCell::new(session));

    // The counter (initialized once on a virgin chip) and the resident chip key.
    let live = session
        .borrow_mut()
        .counter_at_birth(ENROLL_H0)
        .map_err(BringUpFailure::Enroll)?;
    if live > ENROLL_H0 {
        return Err(BringUpFailure::Enroll(TropicError::Refused));
    }
    let chip_pk = session
        .borrow_mut()
        .resident_key()
        .map_err(BringUpFailure::Enroll)?;
    let birth = ChipBirth {
        anchor_id: ident.anchor_id,
        partition_device_id: ident.partition_device_id,
        chip_pk,
        enrolled_counter: ENROLL_H0,
        partition_trng: ident.birth_entropy,
        chip_birth_witness: ident.birth_witness,
        host_nonce: ident.birth_host_nonce,
        partition_key_seed: ident.partition_key_seed,
    };

    // The record in R-memory, and the anchor it describes.
    let slots: Box<dyn SlotMemory> = Box::new(RMemSlots {
        session: session.clone(),
    });
    let store = SlottedStore::new(slots, RECORD_FIRST_SLOT, MAX_FRAME_LEN)
        .map_err(BringUpFailure::Layout)?;
    let tropic: Box<dyn Tropic> = Box::new(RealChip {
        session: session.clone(),
        h0: ENROLL_H0,
    });
    let anchor = Anchor::boot(birth, tropic, store).map_err(BringUpFailure::Recovery)?;
    // No record yet: a chip that cannot take the birth is refused here, with nothing written to it,
    // rather than at a provisioning that has already bound it.
    if matches!(anchor, Anchor::Unprovisioned { .. }) {
        session
            .borrow_mut()
            .ready_for_birth(ENROLL_H0)
            .map_err(BringUpFailure::Enroll)?;
    }
    Ok(anchor)
}
