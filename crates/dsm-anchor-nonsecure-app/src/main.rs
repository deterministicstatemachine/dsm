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

#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::non_secure_exe();

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

#[hal::entry]
fn main() -> ! {
    // Demonstrates the dispatch path end-to-end: a read-only STATUS call across the Secure Gateway.
    // The full USB-CDC transport + protobuf + candidate/proof construction is the transport increment.
    let mut resp = [0u8; 64];
    let (_status, _n) = secure_call(OP_STATUS, &[], &mut resp);
    loop {
        cortex_m::asm::wfi();
    }
}
