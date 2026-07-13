// SPDX-License-Identifier: MIT OR Apache-2.0
//! σ^chip — TROPIC01 resident Ed25519 signing, driven from the Secure monitor over a Secure-only
//! SPI0 (GP18 SCK / GP19 MOSI / GP16 MISO / GP17 CS). The TROPIC + its SPI are inaccessible to
//! Non-secure (proven BLOCKED). Ported from the proven `dsm-anchor-pico` integration; `eddsa_sign`
//! returns `&[u8;64]` so NO heap is required.

use embedded_hal_bus::spi::ExclusiveDevice;
use hal::fugit::RateExtU32;
use hal::Clock;
use rp235x_hal as hal;
use dsm_sphincs::SphincsVariant;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

const XTAL_HZ: u32 = 12_000_000;
const CHIP_KEY_SLOT: u16 = 0;
/// σ^host scheme — MUST match the pico anchor + the receiver (byte-compatible SPX128f).
const PART_VARIANT: SphincsVariant = SphincsVariant::SPX128f;

/// Bring up SPI0 + the TROPIC01 PROD0 session and produce σ^chip over a fixed message with the
/// resident Ed25519 key (slot 0). Returns a bitmask of the stages that succeeded. The signature is
/// on-die; the private half never leaves the chip.
pub fn sigma_chip_selftest() -> u32 {
    // Progressive result so a failure reveals HOW FAR it got:
    //   0x00 clock init failed | 0x01 clocks ok | 0x03 SPI ok | 0x07 chip id ok
    //   0x0F session ok | 0x1F σ^chip signed
    let mut pac = unsafe { hal::pac::Peripherals::steal() };
    let mut watchdog = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    let clocks = match hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    ) {
        Ok(c) => c,
        Err(_) => return 0x00,
    };
    let mut result = 0x01u32;

    // Let the TROPIC01 settle after a cold power-up before the first SPI transaction (the proven
    // probe waits ~2 s for USB enumeration, which incidentally gives the chip this time; the monitor
    // has no such wait, so an immediate chip-id read on the FIRST boot can miss). ~1 s @ 150 MHz.
    cortex_m::asm::delay(150_000_000);

    // Ephemeral X25519 keypair for the L3 handshake (ROSC entropy).
    let rosc = hal::rosc::RingOscillator::new(pac.ROSC).initialize();
    let mut eh = [0u8; 32];
    for b in eh.iter_mut() {
        let mut a = 0u8;
        for _ in 0..8 {
            a = (a << 1) | (rosc.get_random_bit() as u8);
        }
        *b = a;
    }

    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(pac.IO_BANK0, pac.PADS_BANK0, sio.gpio_bank0, &mut pac.RESETS);
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
    let spi_dev = match ExclusiveDevice::new(spi_bus, cs, timer) {
        Ok(d) => d,
        Err(_) => return result, // 0x01: clocks ok, SPI device failed
    };
    result = 0x03; // SPI up

    let mut tropic = Tropic01::new(spi_dev);
    if tropic.get_info_chip_id().is_ok() {
        result = 0x07; // chip alive
    } else {
        return result; // 0x03: SPI up, chip id read failed
    }

    let ehpriv = StaticSecret::from(eh);
    let ehpub = PublicKey::from(&ehpriv);
    let mut sess = match tropic.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        ehpub,
        ehpriv,
        0,
    ) {
        Ok(s) => {
            result = 0x0F; // session established
            s
        }
        Err(_) => return result, // 0x07: chip alive, session failed
    };

    // σ^chip: resident Ed25519 signature over a fixed 32-byte message (slot 0).
    let msg = [0x5Au8; 32];
    if let Ok(sig) = sess.eddsa_sign(CHIP_KEY_SLOT.into(), &msg[..]) {
        if sig.len() == 64 {
            result = 0x1F; // σ^chip signed
        } else {
            return result;
        }
    } else {
        return result;
    }

    // σ^host: BLAKE3-SPHINCS+ (SPX128f) — the SAME dsm-sphincs scheme + PartitionSig contract as the
    // pico anchor (dev seed here; the OTP-sealed host key is the deferred provisioning step). Proves
    // both crypto factors fit + run in the SRAM Secure monitor.
    let seed = [0x11u8; 32];
    match dsm_sphincs::generate_keypair_from_seed(PART_VARIANT, &seed) {
        Ok(kp) => {
            result = 0x3F; // keygen OK
            match dsm_sphincs::sign(PART_VARIANT, &kp.secret_key, &msg) {
                Ok(sig) => {
                    result = 0x7F; // sign OK
                    if dsm_sphincs::verify(PART_VARIANT, &kp.public_key, &msg, &sig).unwrap_or(false)
                    {
                        result = 0xFF; // σ^host verify OK — full σ^chip + σ^host
                    }
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }
    result
}
