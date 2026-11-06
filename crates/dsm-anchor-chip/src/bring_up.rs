// SPDX-License-Identifier: MIT OR Apache-2.0
//! From a chip and the board's sealed secret to an anchor: the chip's identity, the session on the
//! board's own pairing slot once born, the counter and resident key, and the record in R-memory.
//!
//! Every secret the anchor's identity needs derives from the sealed secret; the public part roots
//! in the chip's fused `stpub` and `chip_id`. What the anchor is bound to (the owner's device id,
//! online key, policy and genesis) arrives once, in the owner's provisioning.

use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::anchor::{Anchor, AnchorBootRefusal};
use anchor_core::durable::ActiveStore;
use anchor_core::enrollment::ChipBirth;
use anchor_core::hash::{h, kdf};
use anchor_core::identify::{ChipReading, ChipSurvey};
use anchor_core::proto::{decode_request, pb};
use anchor_core::rmem::{LayoutError, SlotMemory, SlottedStore};
use anchor_core::service::{err, refusal, MAX_FRAME_LEN};
use anchor_core::tropic::{PartitionError, PartitionSig, Tropic, TropicError};
use anchor_core::util::zeroize;
use dsm_sphincs::SphincsVariant;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use tropic01::{NoSession, Tropic01};

use crate::session::{ChipFacts, ChipFault, ChipSession, OpenRefused, RMemSlots, RealChip, Unfit};
use crate::Board;

/// The one session, shared by the appliance's chip operations and its store.
type Shared<SPI, CS, B> = Rc<RefCell<ChipSession<SPI, CS, B>>>;

/// The chip's identity and its open session, or why bring-up stopped.
type Opened<SPI, CS, B> =
    Result<(ChipIdentity, Shared<SPI, CS, B>), BringUpFailure<ChipFault<SPI, CS>>>;

/// σ^host scheme — MUST match the receiver (byte-compatible SPX128f).
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;
/// The counter's lifetime budget `H0` at birth: tropic01 `MCOUNTER_VALUE_MAX`.
pub const ENROLL_H0: u32 = 0xFFFF_FFFE;
/// The first R-memory data slot of the anchor's record.
const RECORD_FIRST_SLOT: u16 = 0;

/// The anchor as a board holds it, the concrete chip session and store erased. A try-run drives the
/// same two trait objects over its own slots, so the firmware carries one copy of the appliance.
pub type BoardAnchor = Anchor<Box<dyn Tropic>, SphincsPart, Box<dyn ActiveStore>>;

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

impl Drop for ChipIdentity {
    /// Every field below `partition_device_id` derives from the sealed secret.
    fn drop(&mut self) {
        zeroize(&mut self.partition_key_seed);
        zeroize(&mut self.birth_entropy);
        zeroize(&mut self.birth_host_nonce);
        zeroize(&mut self.birth_witness);
        zeroize(&mut self.pairing);
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
    /// A chip that is given nothing: refused before the first write to it.
    Unfit(Unfit),
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
            Self::Unfit(cause) => write!(f, "{cause:?}"),
            Self::Enroll(cause) => write!(f, "Enroll: {cause:?}"),
            Self::Layout(cause) => write!(f, "Layout: {cause:?}"),
            Self::Recovery(cause) => write!(f, "Recovery: {cause:?}"),
        }
    }
}

/// What the chip says it is, and the hash its identity derives from. The chip needs a gap between
/// back-to-back L2 reads.
fn chip_facts<SPI, CS, B>(
    chip: &mut Tropic01<SPI, CS, NoSession>,
    board: &B,
) -> Result<(ChipFacts, [u8; 32]), ChipFault<SPI, CS>>
where
    SPI: SpiDevice,
    CS: OutputPin,
    B: Board,
{
    // A part that tests its firmware and PTRNG at start-up takes longer to answer the first time.
    let mut polls = 0u32;
    let chip_id = loop {
        match chip.get_info_chip_id() {
            Ok(id) => break id.to_vec(),
            Err(e) if polls >= 100 => return Err(e),
            Err(_booting) => {
                board.alive();
                board.wait_100ms();
                polls += 1;
            }
        }
    };
    board.wait_100ms();
    let firmware = chip.get_info_riscv_fw_ver()?.to_vec();
    board.wait_100ms();
    let ecc_firmware = chip.get_info_spect_fw_ver()?.to_vec();
    board.wait_100ms();
    Ok((
        ChipFacts::read(&chip_id, &firmware, &ecc_firmware),
        h("DSM/anchor/chip-id/v1", &[chip_id.as_slice()]),
    ))
}

/// Configure a test part's PTRNG, on a chip nothing has been bound to, and say what the chip now is.
/// The one thing the image built with `prepare_chip` does.
pub fn prepare_chip<SPI, CS, B>(
    mut chip: Tropic01<SPI, CS, NoSession>,
    pairing: [u8; 32],
    board: B,
) -> Result<ChipFacts, BringUpFailure<ChipFault<SPI, CS>>>
where
    SPI: SpiDevice,
    CS: OutputPin,
    B: Board,
{
    let (facts, _chip_id_hash) = chip_facts(&mut chip, &board).map_err(BringUpFailure::ChipId)?;
    let mut session =
        ChipSession::open(chip, pairing, facts.clone(), board).map_err(BringUpFailure::Session)?;
    session
        .configure_randomness()
        .map_err(BringUpFailure::Enroll)?;
    session.check_fit().map_err(BringUpFailure::Unfit)?;
    Ok(facts)
}

/// What the chip says it is and what it holds, read with nothing written to it: the one thing the
/// image built with `identify_chip` does. The session is opened as a bring-up opens it, on the factory
/// slot of a chip nothing has been bound to, with a key of this boot that no slot holds standing in for
/// the board's own. Only a chip that does not give its id refuses; anything after that which does not
/// read is reported with why.
pub fn identify_chip<SPI, CS, B>(
    mut chip: Tropic01<SPI, CS, NoSession>,
    board: B,
) -> Result<ChipSurvey, BringUpFailure<ChipFault<SPI, CS>>>
where
    SPI: SpiDevice,
    CS: OutputPin,
    B: Board,
{
    let (facts, _chip_id_hash) = chip_facts(&mut chip, &board).map_err(BringUpFailure::ChipId)?;
    let mut readings = vec![
        ChipReading::new("part number", Ok(facts.part_number.clone())),
        ChipReading::new("silicon", Ok(facts.silicon.clone())),
        ChipReading::new("firmware", Ok(facts.firmware.clone())),
        ChipReading::new("ECC firmware", Ok(facts.ecc_firmware.clone())),
        ChipReading::new(
            "the board's RP2350",
            Ok(format!("stepping A{}", board.silicon_revision())),
        ),
    ];
    let certificates: Vec<Vec<u8>> = match chip.get_info_cert_store() {
        Ok(store) => {
            let certificates: Vec<Vec<u8>> = (0..4)
                .map_while(|index| store.cert(index).map(<[u8]>::to_vec))
                .collect();
            readings.push(ChipReading::new(
                "certificate store",
                match store.public_key() {
                    Ok(_stpub) => Ok(format!(
                        "{} certificates, the device's holding its STPUB",
                        certificates.len()
                    )),
                    Err(e) => Err(format!("{e:?}")),
                },
            ));
            certificates
        }
        Err(e) => {
            readings.push(ChipReading::new("certificate store", Err(format!("{e:?}"))));
            Vec::new()
        }
    };
    board.wait_100ms();
    let Some(mut standing_in) = board.random_key() else {
        readings.push(ChipReading::new(
            "session",
            Err("the board's entropy did not pass its health tests".to_string()),
        ));
        return Ok(ChipSurvey {
            readings,
            certificates,
        });
    };
    match ChipSession::open(chip, standing_in, facts, board) {
        Ok(mut session) => readings.extend(session.survey()),
        Err(refused) => readings.push(ChipReading::new("session", Err(format!("{refused:?}")))),
    }
    zeroize(&mut standing_in);
    Ok(ChipSurvey {
        readings,
        certificates,
    })
}

/// The chip's identity, from its chip id and its certificate store, whose 3.8 KiB are given back here.
/// Fail closed if the chip will not disclose a real identity.
#[inline(never)]
fn identify<SPI, CS, B>(
    chip: &mut Tropic01<SPI, CS, NoSession>,
    sealed: &[u8; 32],
    board: &B,
) -> Result<(ChipFacts, ChipIdentity), BringUpFailure<ChipFault<SPI, CS>>>
where
    SPI: SpiDevice,
    CS: OutputPin,
    B: Board,
{
    let (facts, chip_id_hash) = chip_facts(chip, board).map_err(BringUpFailure::ChipId)?;
    let cert_store = chip
        .get_info_cert_store()
        .map_err(BringUpFailure::CertStore)?;
    let stpub: [u8; 32] = *cert_store
        .public_key()
        .map_err(|cause| BringUpFailure::CertStoreKey(Box::new(cause)))?;
    // Space the cert-store read from session_start's own: the chip needs a gap between back-to-back
    // L2 reads.
    board.wait_100ms();
    Ok((facts, ChipIdentity::derive(&stpub, &chip_id_hash, sealed)))
}

/// The chip's identity and its session, on the board's own pairing slot once born. Everything this
/// moves is given back on return: a cage resumed at boot runs under what is left, and it reopens the
/// session itself (`scripts/stack-bound.py`).
#[inline(never)]
fn open_chip<SPI, CS, B>(
    mut chip: Tropic01<SPI, CS, NoSession>,
    sealed: &[u8; 32],
    board: B,
) -> Opened<SPI, CS, B>
where
    SPI: SpiDevice,
    CS: OutputPin,
    B: Board,
{
    let (facts, ident) = identify(&mut chip, sealed, &board)?;
    let session =
        ChipSession::open(chip, ident.pairing, facts, board).map_err(BringUpFailure::Session)?;
    Ok((ident, Rc::new(RefCell::new(session))))
}

/// Bring the anchor up: unprovisioned when its R-memory holds no record, otherwise restored from
/// the record through §26 recovery.
pub fn bring_up<SPI, CS, B>(
    chip: Tropic01<SPI, CS, NoSession>,
    sealed: &[u8; 32],
    board: B,
) -> Result<BoardAnchor, BringUpFailure<ChipFault<SPI, CS>>>
where
    SPI: SpiDevice + 'static,
    CS: OutputPin + 'static,
    B: Board + 'static,
{
    let (ident, session) = open_chip(chip, sealed, board)?;

    // Whether this chip can be given anything, before it is given anything.
    session
        .borrow_mut()
        .check_fit()
        .map_err(BringUpFailure::Unfit)?;

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
        birth_entropy: ident.birth_entropy,
        chip_birth_witness: ident.birth_witness,
        host_nonce: ident.birth_host_nonce,
        partition_key_seed: ident.partition_key_seed,
    };

    // The record in R-memory, and the anchor it describes.
    let slots: Box<dyn SlotMemory> = Box::new(RMemSlots {
        session: session.clone(),
    });
    let store: Box<dyn ActiveStore> = Box::new(
        SlottedStore::new(slots, RECORD_FIRST_SLOT, MAX_FRAME_LEN)
            .map_err(BringUpFailure::Layout)?,
    );
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
