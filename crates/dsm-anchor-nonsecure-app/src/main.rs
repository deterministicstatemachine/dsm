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
const SG_ABI_VERSION: u32 = 2;
/// The largest request or response frame (anchor-core's `MAX_FRAME_LEN`, mirrored).
const SG_FRAME_MAX_LEN: usize = 64 * 1024;
const OP_KEEPALIVE: u32 = 1;
const OP_REQUEST_PART: u32 = 2;
const OP_RESPONSE_PART: u32 = 3;
const SG_OK: u32 = 0;
const SG_MORE: u32 = 9;

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
    offset: u32,
    total: u32,
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

/// What one crossing of the Secure Gateway answered: its status, the response part copied into
/// `resp`, and the whole response frame's length.
struct Crossing {
    status: u32,
    part: usize,
    total: usize,
}

/// Publish one part (`offset` into a frame of `total` bytes) into the fixed slot and cross the
/// Secure Gateway; up to `resp.len()` response bytes come back.
fn secure_call(opcode: u32, offset: usize, total: usize, part: &[u8], resp: &mut [u8]) -> Crossing {
    let mb = unsafe { &mut *core::ptr::addr_of_mut!(DSM_SG_MAILBOX) };
    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };
    unsafe {
        core::ptr::write_volatile(&mut mb.version, SG_ABI_VERSION);
        core::ptr::write_volatile(&mut mb.opcode, opcode);
        core::ptr::write_volatile(&mut mb.sequence, seq);
        core::ptr::write_volatile(&mut mb.offset, offset as u32);
        core::ptr::write_volatile(&mut mb.total, total as u32);
        core::ptr::write_volatile(&mut mb.req_len, part.len() as u32);
        core::ptr::write_volatile(&mut mb.resp_cap, resp.len().min(SG_SLOT_MAX_LEN) as u32);
        for (i, &b) in part.iter().enumerate() {
            core::ptr::write_volatile(&mut mb.body[i], b);
        }
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(&mut mb.state, MB_REQUEST_READY);
    }
    // Cross the Secure Gateway (synchronous; the Secure handler owns the slot until it returns).
    let status = unsafe { dsm_secure_dispatch(SG_SLOT_INDEX, seq) };
    let mut crossing = Crossing {
        status,
        part: 0,
        total: 0,
    };
    unsafe {
        if core::ptr::read_volatile(&mb.state) == MB_RESPONSE_READY {
            crossing.part = (core::ptr::read_volatile(&mb.resp_len) as usize).min(resp.len());
            crossing.total = core::ptr::read_volatile(&mb.total) as usize;
            for (i, b) in resp.iter_mut().enumerate().take(crossing.part) {
                *b = core::ptr::read_volatile(&mb.body[i]);
            }
        }
    }
    crossing
}

type Serial<'a> = SerialPort<'a, hal::usb::UsbBus>;
type UsbDev<'a> = UsbDevice<'a, hal::usb::UsbBus>;

/// Polls of the USB device with nothing moving between crossings of the Secure Gateway: the Secure
/// handler feeds the ~2 s watchdog on each, so an anchor waiting on its host is not a hung one.
const KEEPALIVE_IDLE_ITERS: u32 = 2_000;

/// Write every byte to USB-CDC, polling + retrying on a full buffer (mirrors the pico anchor). A host
/// that has stopped reading is waited for across keepalives, never by tripping the watchdog; a host
/// that has dropped DTR has gone, and what it asked for is abandoned.
fn write_all(serial: &mut Serial, usb_dev: &mut UsbDev, data: &[u8]) {
    let mut sent = 0;
    let mut blocked = 0u32;
    let host_was_there = serial.dtr();
    while sent < data.len() {
        usb_dev.poll(&mut [serial]);
        if host_was_there && !serial.dtr() {
            return;
        }
        match serial.write(&data[sent..]) {
            Ok(n) => {
                sent += n;
                blocked = 0;
            }
            Err(UsbError::WouldBlock) => {
                blocked += 1;
                if blocked >= KEEPALIVE_IDLE_ITERS {
                    blocked = 0;
                    secure_call(OP_KEEPALIVE, 0, 0, &[], &mut []);
                }
            }
            Err(_) => return,
        }
    }
}

/// Write a response frame to USB: its length, its first part, then each further part the Secure
/// side serves. A crossing that fails ends the frame short of its length, which the host refuses.
fn write_response(serial: &mut Serial, usb_dev: &mut UsbDev, first: &Crossing, resp: &mut [u8]) {
    write_all(serial, usb_dev, &(first.total as u32).to_le_bytes());
    write_all(serial, usb_dev, &resp[..first.part]);
    let mut sent = first.part;
    while sent < first.total {
        let next = secure_call(OP_RESPONSE_PART, sent, first.total, &[], resp);
        if next.status != SG_OK || next.part == 0 {
            return;
        }
        write_all(serial, usb_dev, &resp[..next.part]);
        sent += next.part;
    }
}

/// Serve the anchor over USB-CDC forever: read LE32-length-prefixed protobuf request frames and
/// stream each through the Secure Gateway in slot-sized parts (the monitor assembles the frame,
/// decodes the op, applies the §2 measurement seal and serves it through the anchor), then stream
/// the framed response back. Fixed buffers (no heap): one slot-sized part in each direction.
///
/// A frame larger than any frame, or a part the Secure side refuses, is answered with an empty
/// frame (the host refuses it); the bytes of the refused frame are read and dropped so the stream
/// stays in step. A host opening the port raises DTR, which starts a new frame: an app that died
/// partway through a frame leaves nothing for the next one to be read against.
fn serve_over_usb(serial: &mut Serial, usb_dev: &mut UsbDev) -> ! {
    let mut header = [0u8; 4];
    let mut header_len = 0usize;
    let mut part = [0u8; SG_SLOT_MAX_LEN];
    let mut part_len = 0usize;
    let mut resp = [0u8; SG_SLOT_MAX_LEN];
    // The frame being read: its length, how much of it has gone to the Secure side, and whether the
    // Secure side refused it (its remaining bytes are then dropped).
    let mut total = 0usize;
    let mut forwarded = 0usize;
    let mut refused = 0u8;
    let mut idle: u32 = 0;
    let mut host_there = serial.dtr();
    loop {
        usb_dev.poll(&mut [serial]);
        let dtr = serial.dtr();
        if dtr && !host_there {
            header_len = 0;
            total = 0;
            forwarded = 0;
            part_len = 0;
            refused = 0;
        }
        host_there = dtr;
        let mut chunk = [0u8; 64];
        let n = match serial.read(&mut chunk) {
            Ok(n) => n,
            Err(UsbError::WouldBlock) => 0,
            Err(_usb_fault) => 0,
        };
        if n == 0 {
            idle = idle.wrapping_add(1);
            if idle >= KEEPALIVE_IDLE_ITERS {
                idle = 0;
                secure_call(OP_KEEPALIVE, 0, 0, &[], &mut resp);
            }
            continue;
        }
        idle = 0;
        for &byte in &chunk[..n] {
            if header_len < 4 {
                header[header_len] = byte;
                header_len += 1;
                if header_len < 4 {
                    continue;
                }
                total = u32::from_le_bytes(header) as usize;
                forwarded = 0;
                part_len = 0;
                refused = u8::from(total > SG_FRAME_MAX_LEN);
                if total > 0 {
                    continue;
                }
            } else {
                if refused == 0 {
                    part[part_len] = byte;
                }
                part_len += 1;
                if part_len < SG_SLOT_MAX_LEN && forwarded + part_len < total {
                    continue;
                }
            }
            // A part is complete (a full slot, or the frame's last bytes): forward it.
            if refused == 0 {
                let crossing = secure_call(
                    OP_REQUEST_PART,
                    forwarded,
                    total,
                    &part[..part_len],
                    &mut resp,
                );
                match crossing.status {
                    SG_MORE => {}
                    SG_OK => write_response(serial, usb_dev, &crossing, &mut resp),
                    _refused => refused = 1,
                }
            }
            forwarded += part_len;
            part_len = 0;
            if forwarded >= total {
                if refused != 0 {
                    write_all(serial, usb_dev, &0u32.to_le_bytes());
                }
                header_len = 0;
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
