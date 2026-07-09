//! ECC-gate probe — proves the Stage-7 silicon gates for the resident non-exportable Ed25519
//! chip key (`σ^chip`) on a fresh TROPIC01 (Pico 2 W over SPI). TWO modes:
//!
//!   DEFAULT (read-only pre-flight, writes NOTHING to the chip):
//!     GATE 0  DUMP the raw ECC slot-0 UAP config registers (generate + erase), i-config and
//!             r-config, as ground-truth bytes. NO verdict is inferred from them — the TROPIC01
//!             UAP is a 2-D session/lane bitmap and reversibility is instead PROVEN functionally
//!             in commit mode by actually attempting an erase.
//!     GATE 1  read ECC slot 0 (an empty slot MUST fail cleanly, not return bytes).
//!     Then STOP — nothing is written.
//!
//!   `--features commit` (writes to slot 0 — provisions the board; run on ONE board to
//!    characterise the whole batch):
//!     GATE 3  `ecc_key_generate(slot 0, Ed25519)` if the slot is empty.
//!     GATE 4  on-die `eddsa_sign` of a fixed message, verified OFF-CHIP against `pk_chip`.
//!     GATE 5  reversibility, PROVEN functionally: attempt `ecc_key_erase(slot 0)` then re-read —
//!             slot empty after ⇒ REVERSIBLE (then regenerate to leave the board provisioned);
//!             key persists ⇒ PERMANENT on this chip. Only runs on the boot that generated.
//!     GATE 2  power-cycle and re-run: the slot returns the SAME `pk_chip` (persistence).
//!
//! HARD invariants (both modes): touches ONLY ECC slot 0 config/keys. NEVER reads/moves the
//! monotonic counter. NO passthrough / live-verifier / MACANDD logic. Not the serving firmware.
//! The result transcript REPEATS every ~2s so a serial monitor attached anytime sees it.
//!
//! Wiring (SPI0): SCK=GP18, MOSI/SDI=GP19, MISO/SDO=GP16, CS=GP17, 3V3=p36, GND=p23.

#![no_std]
#![no_main]

extern crate alloc;

use panic_halt as _;

use rp235x_hal as hal;

use hal::clocks::Clock;
use hal::fugit::RateExtU32;
use hal::pac;
use hal::rosc::RingOscillator;

use embedded_alloc::LlffHeap as Heap;
use embedded_hal_bus::spi::ExclusiveDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Tropic01, X25519Dalek};
#[cfg(feature = "commit")]
use tropic01::EccCurve;
use x25519_dalek::{PublicKey, StaticSecret};

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "commit")]
use ed25519_dalek::{Signature, VerifyingKey};

use usb_device::class_prelude::UsbBusAllocator;
use usb_device::prelude::*;
use usb_device::UsbError;
use usbd_serial::SerialPort;

#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[global_allocator]
static HEAP: Heap = Heap::empty();

const XTAL_HZ: u32 = 12_000_000;
/// The ECC key slot the serving firmware pins as `pk_chip` — probe the exact same slot.
const CHIP_KEY_SLOT: u16 = 0;
/// TROPIC01 application-config UAP register addresses (libtropic `tropic01_application_co.h`).
const ADDR_ECC_GEN_UAP: u16 = 0x130; // CFG_UAP_ECC_KEY_GENERATE
const ADDR_ECC_ERASE_UAP: u16 = 0x13C; // CFG_UAP_ECC_KEY_ERASE
/// Fixed 32-byte message the resident key signs (reproducible across runs).
#[cfg(feature = "commit")]
const TEST_M: [u8; 32] = [0x5A; 32];

type Serial<'a> = SerialPort<'a, hal::usb::UsbBus>;
type UsbDev<'a> = UsbDevice<'a, hal::usb::UsbBus>;
type Timer = hal::Timer<hal::timer::CopyableTimer0>;

/// Base32 Crockford encode (no hex — repo constraint).
fn b32(data: &[u8]) -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &byte in data {
        acc = (acc << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 0x1f) as usize] as char);
        }
        acc &= (1u16 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn write_all(serial: &mut Serial, usb_dev: &mut UsbDev, data: &[u8]) {
    let mut sent = 0;
    while sent < data.len() {
        usb_dev.poll(&mut [serial]);
        match serial.write(&data[sent..]) {
            Ok(n) => sent += n,
            Err(UsbError::WouldBlock) => {}
            Err(_) => return,
        }
    }
}

fn emit(serial: &mut Serial, usb_dev: &mut UsbDev, t: &mut Vec<u8>, msg: &str) {
    write_all(serial, usb_dev, msg.as_bytes());
    write_all(serial, usb_dev, b"\r\n");
    t.extend_from_slice(msg.as_bytes());
    t.extend_from_slice(b"\r\n");
}

#[cfg(feature = "commit")]
fn emit_b32(serial: &mut Serial, usb_dev: &mut UsbDev, t: &mut Vec<u8>, label: &str, data: &[u8]) {
    let s = b32(data);
    write_all(serial, usb_dev, label.as_bytes());
    write_all(serial, usb_dev, s.as_bytes());
    write_all(serial, usb_dev, b"\r\n");
    t.extend_from_slice(label.as_bytes());
    t.extend_from_slice(s.as_bytes());
    t.extend_from_slice(b"\r\n");
}

/// Dump one UAP config register (raw bytes only, NO verdict — the 2-D session/lane bitmap is not
/// decoded here; reversibility is proven functionally in commit mode).
fn dump_uap(
    serial: &mut Serial,
    usb_dev: &mut UsbDev,
    t: &mut Vec<u8>,
    name: &str,
    icfg: Option<u32>,
    rcfg: Option<u32>,
) {
    let mut s = String::from("[GATE0] ");
    s.push_str(name);
    match icfg {
        Some(v) => {
            s.push_str(" i-cfg(b32)=");
            s.push_str(&b32(&v.to_le_bytes()));
        }
        None => s.push_str(" i-cfg=READ-FAILED"),
    }
    match rcfg {
        Some(v) => {
            s.push_str(" r-cfg(b32)=");
            s.push_str(&b32(&v.to_le_bytes()));
        }
        None => s.push_str(" r-cfg=READ-FAILED"),
    }
    emit(serial, usb_dev, t, &s);
}

fn repeat_forever(serial: &mut Serial, usb_dev: &mut UsbDev, timer: Timer, transcript: Vec<u8>) -> ! {
    loop {
        write_all(serial, usb_dev, b"\r\n---- ECC GATE PROBE RESULT (repeats every ~2s) ----\r\n");
        write_all(serial, usb_dev, &transcript);
        let until = timer.get_counter().ticks() + 2_000_000;
        while timer.get_counter().ticks() < until {
            usb_dev.poll(&mut [serial]);
        }
    }
}

#[hal::entry]
fn main() -> ! {
    {
        use core::mem::MaybeUninit;
        const HEAP_SIZE: usize = 64 * 1024;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    let rosc = RingOscillator::new(pac.ROSC).initialize();
    let mut eh = [0u8; 32];
    for byte in eh.iter_mut() {
        let mut acc = 0u8;
        for _ in 0..8 {
            acc = (acc << 1) | (rosc.get_random_bit() as u8);
        }
        *byte = acc;
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
    let spi_dev = ExclusiveDevice::new(spi_bus, cs, timer).unwrap();

    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));
    let mut serial = SerialPort::new(&usb_bus);
    let mut usb_dev = UsbDeviceBuilder::new(&usb_bus, UsbVidPid(0x1209, 0xd5a1))
        .strings(&[StringDescriptors::default()
            .manufacturer("DSM")
            .product("DSM ECC Gate Probe")
            .serial_number("dsm-ecc-gate-probe")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    let probe_until = timer.get_counter().ticks() + 2_000_000;
    while timer.get_counter().ticks() < probe_until {
        usb_dev.poll(&mut [&mut serial]);
    }

    let mut t: Vec<u8> = Vec::new();
    emit(&mut serial, &mut usb_dev, &mut t, "== DSM ECC-gate probe (resident Ed25519, slot 0) ==");
    if cfg!(feature = "commit") {
        emit(&mut serial, &mut usb_dev, &mut t, "MODE: COMMIT (will generate on slot 0 if empty)");
    } else {
        emit(&mut serial, &mut usb_dev, &mut t, "MODE: READ-ONLY pre-flight (nothing written)");
    }
    emit(&mut serial, &mut usb_dev, &mut t, "(ECC-only; monotonic counter NEVER touched)");

    let mut tropic = Tropic01::new(spi_dev);
    if tropic.get_info_chip_id().is_ok() {
        emit(&mut serial, &mut usb_dev, &mut t, "[T1] chip id read: OK (chip alive)");
    } else {
        emit(&mut serial, &mut usb_dev, &mut t, "[T1] chip id read: FAIL (chip not responding)");
        repeat_forever(&mut serial, &mut usb_dev, timer, t);
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
            emit(&mut serial, &mut usb_dev, &mut t, "[T2] PROD0 session: OK");
            s
        }
        Err(_) => {
            emit(&mut serial, &mut usb_dev, &mut t, "[T2] PROD0 session: FAIL");
            repeat_forever(&mut serial, &mut usb_dev, timer, t);
        }
    };

    // ---- GATE 0 (read-only): DUMP the raw ECC slot-0 UAP config registers (no verdict). ----
    emit(&mut serial, &mut usb_dev, &mut t, "[GATE0] raw ECC slot-0 UAP registers (facts; reversibility proven in commit):");
    let gen_i = sess.i_config_read(ADDR_ECC_GEN_UAP.into()).ok();
    let gen_r = sess.r_config_read(ADDR_ECC_GEN_UAP.into()).ok();
    let era_i = sess.i_config_read(ADDR_ECC_ERASE_UAP.into()).ok();
    let era_r = sess.r_config_read(ADDR_ECC_ERASE_UAP.into()).ok();
    dump_uap(&mut serial, &mut usb_dev, &mut t, "generate", gen_i, gen_r);
    dump_uap(&mut serial, &mut usb_dev, &mut t, "erase   ", era_i, era_r);

    // ---- GATE 1 (read-only, read-first): the virgin/current slot-0 read. ----
    emit(&mut serial, &mut usb_dev, &mut t, "[GATE1] reading ECC slot 0...");
    #[allow(unused_variables)]
    let slot_has_key = match sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
        Ok(res) => {
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE1] slot 0 read = Ok (a key is present)");
            let _ = &res;
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE1] INTERPRET: on a VIRGIN board => HARD-STOP (empty slot returned bytes);");
            emit(&mut serial, &mut usb_dev, &mut t, "        on a re-run after a commit generate => GATE 2 persistence (compare pk).");
            true
        }
        Err(_) => {
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE1] slot 0 read = Err => empty slot FAILED CLEANLY (GATE 1 PASS)");
            false
        }
    };

    #[cfg(not(feature = "commit"))]
    {
        emit(&mut serial, &mut usb_dev, &mut t, "[DONE] read-only pre-flight complete — NOTHING written to the chip.");
        emit(&mut serial, &mut usb_dev, &mut t, "       To provision + prove sign/verify/reversibility/persistence, reflash with --features commit.");
        repeat_forever(&mut serial, &mut usb_dev, timer, t);
    }

    #[cfg(feature = "commit")]
    {
        // Establish the resident key. On the boot that GENERATES, also prove reversibility (GATE 5)
        // functionally, then leave the board provisioned. On a re-run (key already present) just
        // read it — that path is the GATE 2 persistence check.
        let pk = if slot_has_key {
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] key already present (re-run) — reading it for the persistence check.");
            match sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
                Ok(res) => res.pub_key().to_vec(),
                Err(_) => {
                    emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] re-read: FAIL => HARD-STOP");
                    repeat_forever(&mut serial, &mut usb_dev, timer, t);
                }
            }
        } else {
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] ecc_key_generate(slot 0, Ed25519)...");
            if sess.ecc_key_generate(CHIP_KEY_SLOT.into(), EccCurve::Ed25519).is_err() {
                emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] generate: FAIL => HARD-STOP (keygen refused on PROD chip)");
                repeat_forever(&mut serial, &mut usb_dev, timer, t);
            }
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] generate: OK (PROD chip permits keygen)");
            let k1 = match sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
                Ok(res) => res.pub_key().to_vec(),
                Err(_) => {
                    emit(&mut serial, &mut usb_dev, &mut t, "[GATE3] post-generate read: FAIL => HARD-STOP");
                    repeat_forever(&mut serial, &mut usb_dev, timer, t);
                }
            };
            emit_b32(&mut serial, &mut usb_dev, &mut t, "[GATE3] pk_chip(b32)= ", &k1);

            // ---- GATE 5: reversibility PROVEN functionally — attempt erase, then re-read. ----
            emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] testing reversibility: attempt ecc_key_erase(slot 0)...");
            let erase_ret_ok = sess.ecc_key_erase(CHIP_KEY_SLOT.into()).is_ok();
            let empty_after = sess.ecc_key_read(CHIP_KEY_SLOT.into()).is_err();
            if erase_ret_ok && empty_after {
                emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] erase OK + slot now EMPTY => REVERSIBLE (proven).");
                emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] regenerating to leave the board provisioned...");
                if sess.ecc_key_generate(CHIP_KEY_SLOT.into(), EccCurve::Ed25519).is_err() {
                    emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] regenerate FAIL => slot left EMPTY (board is clean again); HARD-STOP");
                    repeat_forever(&mut serial, &mut usb_dev, timer, t);
                }
                match sess.ecc_key_read(CHIP_KEY_SLOT.into()) {
                    Ok(res) => res.pub_key().to_vec(),
                    Err(_) => {
                        emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] post-regenerate read: FAIL => HARD-STOP");
                        repeat_forever(&mut serial, &mut usb_dev, timer, t);
                    }
                }
            } else {
                emit(&mut serial, &mut usb_dev, &mut t, "[GATE5] erase failed / key persists => PERMANENT on this chip (proven). Board stays provisioned.");
                k1
            }
        };
        emit_b32(&mut serial, &mut usb_dev, &mut t, "[KEY ] final pk_chip(b32)= ", &pk);

        // ---- GATE 4: on-die sign of TEST_M, then OFF-CHIP verify against the final pk_chip. ----
        emit(&mut serial, &mut usb_dev, &mut t, "[GATE4] eddsa_sign(slot 0, TEST_M) on the die...");
        match sess.eddsa_sign(CHIP_KEY_SLOT.into(), &TEST_M[..]) {
            Ok(sig) => {
                let sig = sig.to_vec();
                emit_b32(&mut serial, &mut usb_dev, &mut t, "[GATE4] sig(b32)= ", &sig);
                let ok = (|| {
                    let pk: [u8; 32] = pk.as_slice().try_into().ok()?;
                    let sig: [u8; 64] = sig.as_slice().try_into().ok()?;
                    let vk = VerifyingKey::from_bytes(&pk).ok()?;
                    Some(vk.verify_strict(&TEST_M, &Signature::from_bytes(&sig)).is_ok())
                })()
                .unwrap_or(false);
                if ok {
                    emit(&mut serial, &mut usb_dev, &mut t, "[GATE4] off-chip Ed25519 verify: PASS (resident key real + usable)");
                } else {
                    emit(&mut serial, &mut usb_dev, &mut t, "[GATE4] off-chip Ed25519 verify: FAIL => HARD-STOP");
                }
            }
            Err(_) => emit(&mut serial, &mut usb_dev, &mut t, "[GATE4] eddsa_sign: FAIL => HARD-STOP"),
        }

        // ---- GATE 2: persistence anchor — this pk must be IDENTICAL after a power cycle. ----
        emit_b32(&mut serial, &mut usb_dev, &mut t, "[GATE2] pk_chip(b32) to compare after reboot = ", &pk);
        emit(&mut serial, &mut usb_dev, &mut t, "[GATE2] POWER-CYCLE the board and re-run (commit): pk MUST be identical.");
        emit(&mut serial, &mut usb_dev, &mut t, "== probe done ==");
        repeat_forever(&mut serial, &mut usb_dev, timer, t)
    }
}

/// Program metadata for `picotool info`.
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 3] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_program_description!(c"DSM ECC gate probe (resident Ed25519, slot 0)"),
    hal::binary_info::rp_program_build_attribute!(),
];
