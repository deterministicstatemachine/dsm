// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real appliance integration for the Secure monitor: this board's clocks, SPI bus and entropy, and
//! the anchor held for the SG handler.
//!
//! The chip session and the bring-up are `dsm-anchor-chip`, the same code the rehearsal runs against
//! Tropic Square's chip model. The protocol is `dsm-anchor-core`.
//!
//! The monitor's request entry is the NSC `sg` veneer, a hardware `bxns` it cannot thread state
//! into, so the anchor lives in a `'static` slot of a nameable type.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(not(feature = "prepare_chip"))]
use anchor_chip::bring_up::{bring_up, serve_measured, BoardAnchor};
use anchor_chip::bring_up::{BringUpFailure, Measurement};
use anchor_chip::Board;
use anchor_core::proto::decode_request;
use anchor_core::service::{err, refusal};

use embedded_hal_bus::spi::ExclusiveDevice;
use hal::fugit::RateExtU32;
use hal::Clock;
use rp235x_hal as hal;
use tropic01::Tropic01;

use crate::boundary;
use crate::sealed::{self, SealedError};

const XTAL_HZ: u32 = 12_000_000;

/// The anchor, driven by the SG handler. `'static` slot: the SG entry is a `bxns`, so the handler
/// reaches the anchor here rather than by argument. Single-threaded Secure context (no interrupt or
/// second core touches it — core1 is contained), so `static mut` access through `addr_of_mut!` is
/// sound, matching the `LAST_SEQ` / mailbox pattern in `main`.
static mut MONITOR_APP: Monitor = Monitor::NotBroughtUp;

/// What the handler finds in its slot.
enum Monitor {
    NotBroughtUp,
    #[cfg(not(feature = "prepare_chip"))]
    Up(BoardAnchor),
    /// Why the anchor did not come up, for the answer to any request: with debug disabled this is
    /// the only way to learn it from a locked board. Names steps and chip faults, never a secret.
    Refused(String),
}

/// The RP2350 as the chip session's board.
struct Rp2350Board<R> {
    rosc: R,
}

impl<R: core::borrow::Borrow<hal::rosc::RingOscillator<hal::rosc::Enabled>>> Board
    for Rp2350Board<R>
{
    fn random_key(&self) -> Option<[u8; 32]> {
        let mut hasher = blake3::Hasher::new_derive_key("DSM/anchor/session-entropy/v1");
        for _block in 0..TRNG_BLOCKS {
            let mut block = trng_block()?;
            hasher.update(&block);
            crate::zeroize(&mut block);
        }
        // The ring oscillator's own bits go in too, and nothing rests on them.
        for _byte in 0..32 {
            let byte = (0..8).fold(0u8, |acc, _bit| {
                (acc << 1) | u8::from(self.rosc.borrow().get_random_bit())
            });
            hasher.update(&[byte]);
        }
        Some(*hasher.finalize().as_bytes())
    }

    fn wait_100ms(&self) {
        cortex_m::asm::delay(15_000_000);
    }

    fn alive(&self) {
        boundary::feed_watchdog_in_service();
    }

    /// The bootrom's version byte: "the value 2 for A2 silicon, 3 for A3 silicon, and 4 for A4 silicon"
    /// (RP2350 datasheet, "Bootrom Contents"). It is in ROM, so a chip cannot be told otherwise by
    /// anything flash holds.
    fn silicon_revision(&self) -> u8 {
        unsafe { core::ptr::read_volatile(BOOTROM_VERSION_BYTE as *const u8) }
    }
}

/// Where the bootrom keeps its version.
const BOOTROM_VERSION_BYTE: usize = 0x0000_0013;
/// TRNG blocks of 192 bits behind each key.
const TRNG_BLOCKS: usize = 3;
/// `clk_sys` cycles between samples of the TRNG's ring oscillator. The block's documented minimum is 17.
const TRNG_SAMPLE_CYCLES: u32 = 1024;
/// A failed health test is tried again this many times before the source is called failed.
const TRNG_TRIES: usize = 8;
/// Reads of `RNG_ISR` one block may take: about 0.7 s, against the ~5 ms a block takes.
const TRNG_POLLS: u32 = 10_000_000;
/// `RNG_ISR` and `RNG_ICR`: `EHR_VALID`, `AUTOCORR_ERR`, `CRNGT_ERR`, `VN_ERR`.
const TRNG_ALL_FLAGS: u32 = 0xF;
const TRNG_HEALTH_FAILED: u32 = 0xE;

/// One 192-bit block from the RP2350's TRNG, passed by the block's own health tests (autocorrelation,
/// continuous, von Neumann). `None` when it never passes: there is no lesser source behind it.
fn trng_block() -> Option<[u8; 24]> {
    let trng = unsafe { &*hal::pac::TRNG::ptr() };
    for _try in 0..TRNG_TRIES {
        trng.rng_icr().write(|w| unsafe { w.bits(TRNG_ALL_FLAGS) });
        trng.sample_cnt1()
            .write(|w| unsafe { w.bits(TRNG_SAMPLE_CYCLES) });
        trng.rnd_source_enable().write(|w| unsafe { w.bits(1) });
        for _poll in 0..TRNG_POLLS {
            let flags = trng.rng_isr().read();
            if flags.bits() & TRNG_HEALTH_FAILED != 0 {
                break;
            }
            if flags.ehr_valid().bit_is_set() {
                let words = [
                    trng.ehr_data0().read().bits(),
                    trng.ehr_data1().read().bits(),
                    trng.ehr_data2().read().bits(),
                    trng.ehr_data3().read().bits(),
                    trng.ehr_data4().read().bits(),
                    trng.ehr_data5().read().bits(),
                ];
                trng.rnd_source_enable().write(|w| unsafe { w.bits(0) });
                let mut block = [0u8; 24];
                for (bytes, word) in block.chunks_exact_mut(4).zip(words) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
                return Some(block);
            }
        }
        trng.rnd_source_enable().write(|w| unsafe { w.bits(0) });
        trng.trng_sw_reset().write(|w| unsafe { w.bits(1) });
    }
    None
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
    Entropy = 11,
    /// A chip that is given nothing: refused before the first write to it.
    Unfit = 12,
    /// The `prepare_chip` image has done the one thing it does.
    #[cfg(feature = "prepare_chip")]
    Prepared = 13,
}

/// Why [`init`] refused to install the anchor: the failing stage and the cause it reported.
pub enum InitFailure {
    Clocks(hal::clocks::InitError),
    /// The TRNG never passed its health tests: nothing can be keyed on this board.
    Entropy,
    /// The board's sealed secret, or the secure boot it requires, is not there.
    Sealed(SealedError),
    BringUp(BringUpFailure<ChipError>),
    /// The `prepare_chip` image configured this chip: what it now says it is.
    #[cfg(feature = "prepare_chip")]
    Prepared(anchor_chip::session::ChipFacts),
}

impl InitFailure {
    pub fn stage(&self) -> InitStage {
        match self {
            Self::Clocks(_) => InitStage::Clocks,
            Self::Entropy => InitStage::Entropy,
            Self::Sealed(_) => InitStage::Sealed,
            Self::BringUp(BringUpFailure::ChipId(_)) => InitStage::ChipId,
            Self::BringUp(BringUpFailure::CertStore(_)) => InitStage::CertStore,
            Self::BringUp(BringUpFailure::CertStoreKey(_)) => InitStage::CertStoreKey,
            Self::BringUp(BringUpFailure::Session(_)) => InitStage::Session,
            Self::BringUp(BringUpFailure::Unfit(_)) => InitStage::Unfit,
            #[cfg(feature = "prepare_chip")]
            Self::Prepared(_) => InitStage::Prepared,
            Self::BringUp(BringUpFailure::Enroll(_)) => InitStage::Enroll,
            Self::BringUp(BringUpFailure::Layout(_)) => InitStage::Layout,
            Self::BringUp(BringUpFailure::Recovery(_)) => InitStage::Recovery,
        }
    }
}

impl core::fmt::Debug for InitFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Clocks(cause) => write!(f, "Clocks: {cause:?}"),
            Self::Entropy => write!(f, "the TRNG did not pass its health tests"),
            Self::Sealed(cause) => write!(f, "Sealed: {cause:?}"),
            Self::BringUp(cause) => write!(f, "{cause:?}"),
            #[cfg(feature = "prepare_chip")]
            Self::Prepared(facts) => write!(
                f,
                "{}. Its PTRNG is now configured and tested at every start-up. Load the trial image",
                facts.describe()
            ),
        }
    }
}

/// Keep why the anchor did not come up, for the answer to every request.
///
/// SAFETY: single-threaded reset context, before the Non-secure launch.
pub unsafe fn keep_refusal(failure: &InitFailure) {
    *core::ptr::addr_of_mut!(MONITOR_APP) = Monitor::Refused(format!("{failure:?}"));
}

/// Bring up the TROPIC01 from Secure and install the anchor in `MONITOR_APP`. Fail-closed: any
/// failure returns the failing stage and installs nothing, so every request is answered with the
/// refusal. The sealed secret and the secure context are checked first: a board without
/// them does nothing to its chip. Steals the peripherals it needs (CLOCKS/PLL/XOSC/ROSC/TIMER0/SPI0
/// + GP16-19); `main` must not re-init clocks after.
///
/// Never inlined: `main` does not return, so a frame of its own is held under every request served
/// after the launch. What bring-up needs is given back here, before the launch.
///
/// SAFETY: single-threaded reset context, called once from `main` before the Non-secure launch.
#[inline(never)]
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

    // The TRNG keys each L3 handshake, and is out of reset before anything needs it.
    pac.RESETS.reset().modify(|_, w| w.trng().clear_bit());
    for _read in 0..TRNG_POLLS {
        if pac.RESETS.reset_done().read().trng().bit_is_set() {
            break;
        }
    }
    let rosc = hal::rosc::RingOscillator::new(pac.ROSC).initialize();
    // A source that fails now answers every request with why, instead of a chip that will not open.
    match (Rp2350Board { rosc: &rosc }).random_key() {
        Some(mut proof) => crate::zeroize(&mut proof),
        None => return Err(InitFailure::Entropy),
    }

    // The board's sealed secret: without it the anchor has no identity to serve under.
    #[cfg(not(feature = "bench_self_enroll"))]
    let mut sealed = sealed::read_sealed_secret().map_err(InitFailure::Sealed)?;
    // A trial image reads the same OTP page and must find it blank: a real seal is never overridden.
    // Its secret is then fresh each boot and held nowhere, so nothing it derives can bind the board,
    // and it can make no install (`service_request`).
    #[cfg(feature = "bench_self_enroll")]
    let mut sealed: [u8; 32] = match sealed::read_sealed_secret() {
        Err(SealedError::Unprovisioned) => (Rp2350Board { rosc: &rosc })
            .random_key()
            .ok_or(InitFailure::Entropy)?,
        Ok(_burned) => return Err(InitFailure::Sealed(SealedError::AlreadySealed)),
        Err(cause) => return Err(InitFailure::Sealed(cause)),
    };
    #[cfg(feature = "production")]
    sealed::assert_secure_context().map_err(InitFailure::Sealed)?;

    // Let the TROPIC01 settle after cold power-up before the first SPI transaction (~1 s @150 MHz).
    cortex_m::asm::delay(150_000_000);

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

    // This image does one thing, and every request then hears how it went.
    #[cfg(feature = "prepare_chip")]
    {
        let prepared = anchor_chip::bring_up::prepare_chip(
            Tropic01::new(spi_dev),
            sealed,
            Rp2350Board { rosc },
        );
        crate::zeroize(&mut sealed);
        return Err(match prepared {
            Ok(facts) => InitFailure::Prepared(facts),
            Err(cause) => InitFailure::BringUp(cause),
        });
    }

    #[cfg(not(feature = "prepare_chip"))]
    let brought_up = bring_up(Tropic01::new(spi_dev), &sealed, Rp2350Board { rosc });
    // Everything the anchor needs derives from it, and nothing needs it again this boot.
    #[cfg(not(feature = "prepare_chip"))]
    crate::zeroize(&mut sealed);
    #[cfg(not(feature = "prepare_chip"))]
    let anchor = brought_up.map_err(InitFailure::BringUp)?;
    #[cfg(not(feature = "prepare_chip"))]
    {
        *core::ptr::addr_of_mut!(MONITOR_APP) = Monitor::Up(anchor);
        Ok(())
    }
}

/// Serve the Secure request copy through the anchor, under the measurement taken for it. An anchor
/// that did not come up answers with why.
///
/// SAFETY: single-threaded Secure context; the SG handler is the only caller.
pub unsafe fn service_request(frame: &[u8], _measurement: Measurement) -> Vec<u8> {
    #[cfg(feature = "bench_self_enroll")]
    if let Ok(req) = decode_request(frame) {
        if req.op == anchor_core::proto::pb::Op::Provision as i32 {
            return refusal(
                req.op,
                err::TRIAL_IMAGE,
                "this image tries an install and cannot make one",
            );
        }
    }
    let slot = &mut *core::ptr::addr_of_mut!(MONITOR_APP);
    match core::mem::replace(slot, Monitor::NotBroughtUp) {
        #[cfg(not(feature = "prepare_chip"))]
        Monitor::Up(anchor) => {
            let (anchor, answer) = serve_measured(anchor, frame, _measurement);
            *slot = Monitor::Up(anchor);
            answer
        }
        Monitor::Refused(reason) => {
            let answer = not_up(frame, &reason);
            *slot = Monitor::Refused(reason);
            answer
        }
        Monitor::NotBroughtUp => not_up(frame, "the anchor was not brought up"),
    }
}

/// The answer of an anchor that did not come up, to whichever op asked.
fn not_up(frame: &[u8], reason: &str) -> Vec<u8> {
    match decode_request(frame) {
        Ok(req) => refusal(req.op, err::NOT_UP, reason),
        Err(_undecodable) => refusal(0, err::NOT_UP, reason),
    }
}
