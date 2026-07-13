// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM anchor RP2350 **Non-secure application** (TrustZone-M Non-secure world).
//!
//! Owns USB-CDC, protobuf, host transport, and candidate transition / SMT-proof construction. It
//! reaches the Secure monitor ONLY through the single NSC Secure Gateway `dsm_secure_dispatch(slot,
//! seq)`; a fixed Non-secure SRAM mailbox slot carries the bulk request/response bytes. It has NO
//! access to OTP, the host key, TROPIC01, the counter, or Secure state — any attempt faults (SAU).
//!
//! On the Non-secure side the gateway is a PLAIN function call to the veneer address: the veneer's
//! `sg` instruction performs the NS→S transition, so no cmse intrinsics (nightly) are needed here —
//! this crate is pure stable Rust. The veneer address is resolved by the linker (`memory.x` PROVIDE
//! at the fixed NSC region base; the two-image integration reconciles it with the monitor's stub).

#![no_std]
#![no_main]

extern crate panic_halt;

use core::sync::atomic::{compiler_fence, Ordering};
use rp235x_hal as hal;
use usb_device::class_prelude::UsbBusAllocator;
use usb_device::prelude::*;
use usb_device::UsbError;
use usbd_serial::SerialPort;

/// RP2350 crystal on the anchor board (mirrors the pico anchor).
const XTAL_HZ: u32 = 12_000_000;

// No PICOBIN boot block: this app is embedded in the Secure monitor image and copied into NS SRAM
// by the monitor's LOAD_MAP (dsm-secure-sram.x entry 3), then entered via BXNS. The monitor's boot
// block is the only one the bootrom scans.

// ── Secure Gateway ABI (mirror of the monitor / veneer/dsm_sg_abi.h) ──────────────────────────
const SG_SLOT_INDEX: u32 = 0;
const SG_SLOT_MAX_LEN: usize = 4096;
const OP_STATUS: u32 = 1;

const MB_REQUEST_READY: u32 = 1;
const MB_RESPONSE_READY: u32 = 3;

#[repr(C)]
struct Mailbox {
    state: u32,
    version: u32,
    opcode: u32,
    sequence: u32,
    req_len: u32,
    resp_cap: u32,
    resp_len: u32,
    status: u32,
    body: [u8; SG_SLOT_MAX_LEN],
}

extern "C" {
    /// The single NSC Secure Gateway entry (in the monitor's NSC region). A plain call: the veneer's
    /// `sg` does the NS→S transition, runs the Secure handler, scrubs registers, returns.
    fn dsm_secure_dispatch(slot_index: u32, sequence_number: u32) -> u32;
    /// The fixed mailbox slot in Non-secure SRAM (both images agree on this address; DMA denied).
    static mut DSM_SG_MAILBOX: Mailbox;
}

/// Non-secure sequence counter (monotonic; the Secure handler rejects a stale/replayed value).
static mut SEQ: u32 = 0;

/// Publish a bounded request into the fixed slot and invoke the Secure Gateway. Returns the Secure
/// status. `resp` receives up to `resp.len()` response bytes; the used length is returned via `out`.
fn secure_call(opcode: u32, req: &[u8], resp: &mut [u8]) -> (u32, usize) {
    if req.len() > SG_SLOT_MAX_LEN {
        return (3 /* ERR_SIZE */, 0);
    }
    let mb = unsafe { &mut *core::ptr::addr_of_mut!(DSM_SG_MAILBOX) };
    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };
    unsafe {
        core::ptr::write_volatile(&mut mb.version, 1);
        core::ptr::write_volatile(&mut mb.opcode, opcode);
        core::ptr::write_volatile(&mut mb.sequence, seq);
        core::ptr::write_volatile(&mut mb.req_len, req.len() as u32);
        core::ptr::write_volatile(&mut mb.resp_cap, resp.len().min(SG_SLOT_MAX_LEN) as u32);
        for (i, &b) in req.iter().enumerate() {
            core::ptr::write_volatile(&mut mb.body[i], b);
        }
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(&mut mb.state, MB_REQUEST_READY);
    }
    // Cross the Secure Gateway (synchronous; the Secure handler owns the slot until it returns).
    let status = unsafe { dsm_secure_dispatch(SG_SLOT_INDEX, seq) };
    // Read the bounded response.
    let mut n = 0usize;
    unsafe {
        if core::ptr::read_volatile(&mb.state) == MB_RESPONSE_READY {
            n = (core::ptr::read_volatile(&mb.resp_len) as usize).min(resp.len());
            for (i, b) in resp.iter_mut().enumerate().take(n) {
                *b = core::ptr::read_volatile(&mb.body[i]);
            }
        }
    }
    (status, n)
}

type Serial<'a> = SerialPort<'a, hal::usb::UsbBus>;
type UsbDev<'a> = UsbDevice<'a, hal::usb::UsbBus>;

/// Write every byte to USB-CDC, polling + retrying on a full buffer (mirrors the pico anchor).
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

/// Serve the anchor over USB-CDC forever: read LE32-length-prefixed protobuf request frames, cross
/// the Secure Gateway (the monitor decodes the op from the frame, applies the §2 measurement seal,
/// and drives the real appliance), and write the framed response back. Same wire protocol as the
/// pico anchor, so the host / Android transport is byte-compatible. Fixed buffers (no heap): a frame
/// is bounded by the SG mailbox slot (`SG_SLOT_MAX_LEN`).
fn serve_over_usb(serial: &mut Serial, usb_dev: &mut UsbDev) -> ! {
    let mut rx = [0u8; SG_SLOT_MAX_LEN + 4];
    let mut rx_len = 0usize;
    let mut resp = [0u8; SG_SLOT_MAX_LEN];
    // Watchdog keepalive: when idle, cross the SG at least this often so the Secure handler feeds the
    // ~2 s watchdog (a healthy idle anchor != a hung one). The loop iterates far faster than 2 s, so
    // this bounds the keepalive interval well under the timeout; a genuinely hung NS never reaches it.
    const KEEPALIVE_IDLE_ITERS: u32 = 20_000;
    let mut idle: u32 = 0;
    loop {
        usb_dev.poll(&mut [serial]);
        let mut chunk = [0u8; 64];
        let n = serial.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            idle = idle.wrapping_add(1);
            if idle >= KEEPALIVE_IDLE_ITERS {
                idle = 0;
                // Empty frame: the SG handler feeds the watchdog on entry, then decode-errors (ignored).
                let _ = secure_call(OP_STATUS, &[], &mut resp);
            }
            continue;
        }
        idle = 0;
        {
            if rx_len + n > rx.len() {
                rx_len = 0; // desync guard: drop the partial buffer and resynchronize
                continue;
            }
            rx[rx_len..rx_len + n].copy_from_slice(&chunk[..n]);
            rx_len += n;

            // Drain every complete LE32-length-prefixed frame in the buffer.
            while rx_len >= 4 {
                let len = u32::from_le_bytes([rx[0], rx[1], rx[2], rx[3]]) as usize;
                if len > SG_SLOT_MAX_LEN {
                    rx_len = 0; // oversized => cannot be a valid frame; resynchronize
                    break;
                }
                if rx_len < 4 + len {
                    break; // frame not fully received yet
                }
                // The mailbox opcode is only a hint; the monitor re-decodes the real op from the
                // frame, so pass STATUS as a benign default.
                let (_status, out) = secure_call(OP_STATUS, &rx[4..4 + len], &mut resp);
                write_all(serial, usb_dev, &(out as u32).to_le_bytes());
                write_all(serial, usb_dev, &resp[..out]);
                // Consume the frame, shift any trailing bytes down.
                let consumed = 4 + len;
                rx.copy_within(consumed..rx_len, 0);
                rx_len -= consumed;
            }
        }
    }
}

#[hal::entry]
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    // NOTE (hardware-validation): this inits the PLL/clock tree from the Non-secure world. It only
    // works if the monitor left CLOCKS/PLL/USB Non-secure-accessible via SAU/ACCESSCTRL; otherwise
    // the monitor must configure USB + its clock and grant NS access before launch. Verified on the
    // two-image bring-up.
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
            .product("DSM Anchor")
            .serial_number("dsm-anchor")])
        .unwrap()
        .max_packet_size_0(64)
        .unwrap()
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    serve_over_usb(&mut serial, &mut usb_dev)
}
