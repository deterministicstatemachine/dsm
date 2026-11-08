// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real appliance integration for the Secure monitor.
//!
//! This is the ONLY place the monitor touches the DSM protocol, and it does so by REUSING
//! `dsm-anchor-core`: the anchor's states (`anchor_core::anchor::Anchor`), its durable record
//! (`anchor_core::rmem::SlottedStore` over TROPIC01 R-memory) and the appliance it serves. The chip
//! (`σ^chip`) and partition (`σ^host`) leaf crypto are bound through the `Tropic` / `PartitionSig`
//! traits; the chip session itself is [`crate::chip`].
//!
//! The monitor's request entry is the NSC `sg` veneer, a hardware `bxns` it cannot thread state
//! into, so the anchor lives in a `'static` slot of a nameable type, the concrete TROPIC01 session
//! erased behind `Box<dyn Tropic>` and `Box<dyn SlotMemory>`.
//!
//! Identity: every secret the anchor's identity needs derives from the board's sealed secret
//! ([`crate::sealed`]); what the anchor is bound to (the owner's device id, online key, policy and
//! genesis) arrives once, in the owner's provisioning.

extern crate alloc;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::anchor::{Anchor, AnchorBootRefusal};
use anchor_core::enrollment::ChipBirth;
use anchor_core::hash::{h, kdf};
use anchor_core::proto::{decode_request, pb};
use anchor_core::rmem::{LayoutError, SlotMemory, SlottedStore};
use anchor_core::service::MAX_FRAME_LEN;
use anchor_core::tropic::{PartitionError, PartitionSig, Tropic, TropicError};
use dsm_sphincs::SphincsVariant;

use embedded_hal_bus::spi::ExclusiveDevice;
use hal::fugit::RateExtU32;
use hal::Clock;
use rp235x_hal as hal;
use tropic01::Tropic01;

use crate::chip::{ChipSession, OpenRefused, RMemSlots, RealChip};
use crate::sealed::{self, SealedError};
use crate::{SG_ERR_ENCODING, SG_ERR_INTERNAL, SG_ERR_MEASUREMENT};

const XTAL_HZ: u32 = 12_000_000;
/// σ^host scheme — MUST match the receiver (byte-compatible SPX128f).
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;
/// The counter's lifetime budget `H0` at birth: tropic01 `MCOUNTER_VALUE_MAX`.
const ENROLL_H0: u32 = 0xFFFF_FFFE;
/// The first R-memory data slot of the anchor's record.
const RECORD_FIRST_SLOT: u16 = 0;

type Store = SlottedStore<Box<dyn SlotMemory>>;

/// The anchor, driven by the SG handler. `'static` slot: the SG entry is a `bxns`, so the handler
/// reaches the anchor here rather than by argument. Single-threaded Secure context (no interrupt or
/// second core touches it — core1 is contained), so `static mut` access through `addr_of_mut!` is
/// sound, matching the `LAST_SEQ` / mailbox pattern in `main`.
static mut MONITOR_APP: Option<Anchor<Box<dyn Tropic>, SphincsPart, Store>> = None;

/// BLAKE3-SPHINCS+ SPX128f as the partition (`σ^host`) signature scheme — the SAME crate + contract
/// as the pico anchor, so an anchor born here verifies on the same receiver.
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
        dsm_sphincs::verify(PART_VARIANT, pk, digest, sig).unwrap_or(false)
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

/// The anchor's identity on this board. The public part roots in the chip's fused `stpub` and
/// `chip_id`; every secret derives from the sealed secret, which nothing outside this board holds.
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

/// The TROPIC01 driver error on the monitor's bus: rp235x SPI and GPIO are infallible, and the
/// driver manages no CS pin of its own (`ExclusiveDevice` owns GP17).
type ChipError = tropic01::Error<
    embedded_hal_bus::spi::DeviceError<core::convert::Infallible, core::convert::Infallible>,
    core::convert::Infallible,
>;

/// The step at which [`init`] refused. `main` reports it in `DSM_SECURE_HEARTBEAT[1]`.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum InitStage {
    Clocks = 2,
    ChipId = 3,
    CertStore = 4,
    CertStoreKey = 5,
    Session = 6,
    Enroll = 7,
    Recovery = 8,
    Sealed = 9,
    Layout = 10,
}

/// Why [`init`] refused to install the anchor: the failing stage and the cause it reported.
/// Its `Debug` rendering is what `main` copies into `DSM_SECURE_INIT_CAUSE`.
pub enum InitFailure {
    Clocks(hal::clocks::InitError),
    ChipId(ChipError),
    CertStore(ChipError),
    /// tropic01 does not export its `PublicKeyError`, so the cause is carried type-erased.
    CertStoreKey(Box<dyn core::fmt::Debug>),
    /// The board's sealed secret, or the secure boot it requires, is not there.
    Sealed(SealedError),
    Session(OpenRefused<ChipError>),
    /// The counter or the resident chip key.
    Enroll(TropicError),
    /// The R-memory record does not fit.
    Layout(LayoutError),
    /// The record could not be restored, or §26 recovery refused it.
    Recovery(AnchorBootRefusal),
}

impl InitFailure {
    pub fn stage(&self) -> InitStage {
        match self {
            Self::Clocks(_) => InitStage::Clocks,
            Self::ChipId(_) => InitStage::ChipId,
            Self::CertStore(_) => InitStage::CertStore,
            Self::CertStoreKey(_) => InitStage::CertStoreKey,
            Self::Sealed(_) => InitStage::Sealed,
            Self::Session(_) => InitStage::Session,
            Self::Enroll(_) => InitStage::Enroll,
            Self::Layout(_) => InitStage::Layout,
            Self::Recovery(_) => InitStage::Recovery,
        }
    }
}

impl core::fmt::Debug for InitFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let stage = self.stage();
        match self {
            Self::Clocks(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::ChipId(cause) | Self::CertStore(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::CertStoreKey(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::Sealed(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::Session(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::Enroll(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::Layout(cause) => write!(f, "{stage:?}: {cause:?}"),
            Self::Recovery(cause) => write!(f, "{stage:?}: {cause:?}"),
        }
    }
}

/// Bring up the TROPIC01 from Secure and install the anchor in `MONITOR_APP`: unprovisioned when
/// its R-memory holds no record, otherwise restored from the record through §26 recovery. Fail-
/// closed: any failure returns the failing stage and leaves `MONITOR_APP = None`, so the SG handler
/// refuses every request (`SG_ERR_INTERNAL`). Steals the peripherals it needs
/// (CLOCKS/PLL/XOSC/ROSC/TIMER0/SPI0 + GP16-19); `main` must not re-init clocks after.
///
/// SAFETY: single-threaded reset context, called once from `main` before the Non-secure launch.
pub unsafe fn init() -> Result<(), InitFailure> {
    let mut pac = hal::pac::Peripherals::steal();
    let mut watchdog = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .map_err(InitFailure::Clocks)?;

    // Let the TROPIC01 settle after cold power-up before the first SPI transaction (~1 s @150 MHz).
    cortex_m::asm::delay(150_000_000);

    // The ring oscillator's entropy keys each L3 handshake; the chip session keeps it to reopen.
    let rosc = hal::rosc::RingOscillator::new(pac.ROSC).initialize();

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let sck = pins.gpio18.into_function::<hal::gpio::FunctionSpi>();
    let mosi = pins.gpio19.into_function::<hal::gpio::FunctionSpi>();
    let miso = pins.gpio16.into_function::<hal::gpio::FunctionSpi>();
    let cs = pins.gpio17.into_push_pull_output();
    let spi_bus = hal::spi::Spi::<_, _, _, 8>::new(pac.SPI0, (mosi, miso, sck)).init(
        &mut pac.RESETS,
        clocks.peripheral_clock.freq(),
        1_000_000u32.Hz(),
        embedded_hal::spi::MODE_0,
    );
    // Asserting GP17 cannot fail (rp235x GPIO is infallible), so the device always forms.
    let Ok(mut spi_dev) = ExclusiveDevice::new(spi_bus, cs, timer);

    // Cold-start SPI warm-up (mirrors the pico anchor's Phase 1): clock the TROPIC01 with a few real
    // transactions so it is ready for the first L2 read after a cold power-up.
    use embedded_hal::spi::SpiDevice as _;
    for _ in 0..3 {
        let mut rx = [0u8; 4];
        let _ = spi_dev.transfer(&mut rx, &[0xAAu8, 0, 0, 0]);
        cortex_m::asm::delay(150_000_000); // ~1 s @150 MHz
    }

    // Phase 2: read the REAL chip identity (chip_id + device-cert stpub) BEFORE session_start
    // consumes the NoSession handle. Fail closed if the chip will not disclose a real identity.
    let mut tropic = Tropic01::new(spi_dev);
    let chip_id = tropic.get_info_chip_id().map_err(InitFailure::ChipId)?;
    let chip_id_hash = h("DSM/anchor/chip-id/v1", &[chip_id]);
    let cert_store = tropic
        .get_info_cert_store()
        .map_err(InitFailure::CertStore)?;
    let stpub: [u8; 32] = *cert_store
        .public_key()
        .map_err(|cause| InitFailure::CertStoreKey(Box::new(cause)))?;
    // Space the cert-store read from session_start's own internal cert read — the TROPIC needs a gap
    // between back-to-back L2 reads (the pico gets this implicitly from USB polling).
    cortex_m::asm::delay(15_000_000); // ~100 ms @150 MHz
                                      // The board's sealed secret: without it the anchor has no identity to serve under.
    let sealed = sealed::read_sealed_secret().map_err(InitFailure::Sealed)?;
    #[cfg(feature = "production")]
    sealed::assert_secure_context().map_err(InitFailure::Sealed)?;
    let ident = ChipIdentity::derive(&stpub, &chip_id_hash, &sealed);

    // Phase 3: the authenticated L3 session, on the board's own pairing slot once born.
    let session = ChipSession::open(tropic, ident.pairing, rosc).map_err(InitFailure::Session)?;
    let session = Rc::new(RefCell::new(session));

    // Phase 4: the counter (initialized once on a virgin chip) and the resident chip key.
    let live = session
        .borrow_mut()
        .counter_at_birth(ENROLL_H0)
        .map_err(InitFailure::Enroll)?;
    if live > ENROLL_H0 {
        return Err(InitFailure::Enroll(TropicError::Refused));
    }
    let chip_pk = session
        .borrow_mut()
        .resident_key()
        .map_err(InitFailure::Enroll)?;
    let chip = ChipBirth {
        anchor_id: ident.anchor_id,
        partition_device_id: ident.partition_device_id,
        chip_pk,
        enrolled_counter: ENROLL_H0,
        partition_trng: ident.birth_entropy,
        chip_birth_witness: ident.birth_witness,
        host_nonce: ident.birth_host_nonce,
        partition_key_seed: ident.partition_key_seed,
    };

    // Phase 5: the record in R-memory, and the anchor it describes.
    let slots: Box<dyn SlotMemory> = Box::new(RMemSlots {
        session: session.clone(),
    });
    let store =
        SlottedStore::new(slots, RECORD_FIRST_SLOT, MAX_FRAME_LEN).map_err(InitFailure::Layout)?;
    let tropic: Box<dyn Tropic> = Box::new(RealChip {
        session,
        h0: ENROLL_H0,
    });
    let anchor = Anchor::boot(chip, tropic, store).map_err(InitFailure::Recovery)?;
    *core::ptr::addr_of_mut!(MONITOR_APP) = Some(anchor);
    Ok(())
}

fn op_requires_measurement(op: i32) -> bool {
    matches!(
        pb::Op::try_from(op),
        Ok(pb::Op::Prepare | pb::Op::Commit | pb::Op::Emit | pb::Op::Finalize | pb::Op::Recover)
    )
}

/// Decode the Secure request copy, apply the §2 measurement gate to the DECODED op (never the
/// untrusted mailbox opcode hint), and serve it through the anchor. Returns the encoded
/// `ApplianceResponse` frame, or an `SG_ERR_*` status on a gate/decode/uninitialized failure.
///
/// SAFETY: single-threaded Secure context; the SG handler is the only caller.
pub unsafe fn service_request(frame: &[u8], measurement_ok: bool) -> Result<Vec<u8>, u32> {
    let req = decode_request(frame).map_err(|_| SG_ERR_ENCODING)?;
    if op_requires_measurement(req.op) && !measurement_ok {
        // §7.12 measurement failure => no counter movement, no TROPIC/host signature.
        return Err(SG_ERR_MEASUREMENT);
    }
    let slot = &mut *core::ptr::addr_of_mut!(MONITOR_APP);
    let anchor = slot.take().ok_or(SG_ERR_INTERNAL)?;
    let (anchor, answer) = anchor.serve(frame);
    *slot = Some(anchor);
    Ok(answer)
}
