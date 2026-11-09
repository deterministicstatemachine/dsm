// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Secure Gateway as the Non-secure side sees it: one fixed mailbox slot in Non-secure SRAM and
//! one call, `dsm_secure_dispatch(slot, seq)`, into the NSC veneer whose `sg` instruction makes the
//! NS→S transition. A plain function call here: the veneer address is resolved by the linker
//! (`memory.x` PROVIDE at the fixed NSC region base), so no cmse intrinsics are needed and this
//! crate is pure stable Rust.
//!
//! Every crossing is synchronous and exclusive: the Secure handler owns the slot until it returns,
//! and nothing else runs on this core meanwhile. Mirror of the monitor and `veneer/dsm_sg_abi.h`.

use core::sync::atomic::{compiler_fence, Ordering};

const SG_SLOT_INDEX: u32 = 0;
/// The largest part of a frame the slot carries at once.
pub const SG_SLOT_MAX_LEN: usize = 4096;
const SG_ABI_VERSION: u32 = 2;
/// The largest request or response frame (anchor-core's `MAX_FRAME_LEN`, mirrored).
pub const SG_FRAME_MAX_LEN: usize = 64 * 1024;
/// Keep the watchdog fed while idle; touches no frame.
const OP_KEEPALIVE: u32 = 1;
/// One part of a request frame: `total` bytes in all, this part at `offset`.
const OP_REQUEST_PART: u32 = 2;
/// One part of the response frame, from `offset`.
const OP_RESPONSE_PART: u32 = 3;
/// 32 bytes the Secure side's entropy source produced, for the radio's own addresses and tokens.
const OP_ENTROPY: u32 = 4;
pub const SG_OK: u32 = 0;
/// The request part was taken; the frame is not complete yet.
pub const SG_MORE: u32 = 9;

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
pub struct Crossing {
    pub status: u32,
    pub part: usize,
    pub total: usize,
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

/// A crossing that moves no frame: the Secure handler feeds the watchdog on it, so an anchor waiting
/// on its hosts is not a hung one. The first crossing after boot also hands the bring-up peripherals
/// back to the Secure side.
pub fn keepalive() {
    secure_call(OP_KEEPALIVE, 0, 0, &[], &mut []);
}

/// Hand one part of a request frame to the Secure side; a complete frame is served and the first
/// part of its response comes back in `resp`.
pub fn request_part(offset: usize, total: usize, part: &[u8], resp: &mut [u8]) -> Crossing {
    secure_call(OP_REQUEST_PART, offset, total, part, resp)
}

/// Fetch the response frame's part from `offset`.
pub fn response_part(offset: usize, total: usize, resp: &mut [u8]) -> Crossing {
    secure_call(OP_RESPONSE_PART, offset, total, &[], resp)
}

/// How many bytes one entropy crossing answers with.
pub const ENTROPY_BYTES: usize = 32;

/// Bytes from the Secure side's entropy source, or nothing when it refused (its source failed its
/// own health test): the caller does without, never with bytes it made up.
pub fn entropy() -> Option<[u8; ENTROPY_BYTES]> {
    let mut bytes = [0u8; ENTROPY_BYTES];
    let crossing = secure_call(OP_ENTROPY, 0, 0, &[], &mut bytes);
    if crossing.status != SG_OK || crossing.part != bytes.len() {
        return None;
    }
    Some(bytes)
}
