// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM anchor RP2350 **Secure monitor** (TrustZone-M Secure world).
//!
//! Owns OTP, the host key, `HostSign`, TROPIC01, the physical counter, durable prepare/commit/
//! recovery state, the exact measurement seal, and the ONLY Secure Gateway (the NSC veneer → this
//! handler).
//!
//! STATUS (this increment): STRUCTURAL split + SG ABI only. Both images link and the SG dispatch
//! path resolves, but the monitor + veneer are still linked as an **XIP-flash** image — there is NO
//! boot-block `LOAD_MAP` yet, so the Secure TCB does NOT run from boot-ROM-verified SRAM. The
//! target invariant (whole Secure TCB executes from SRAM, because external flash is mutable after
//! boot-time verification) is NOT physically true until the SRAM `LOAD_MAP` linker step lands;
//! `scripts/check-secure-no-xip.sh` correctly FAILS until then. The runtime security boundary
//! (SAU/MPU/ACCESSCTRL) is not configured and the Non-secure image is not launched.
//!
//! What IS wired: the veneer entry `dsm_secure_dispatch(slot, seq)` calls [`dsm_secure_handler`],
//! which runs the mailbox state machine (§4), performs a **fresh** BLAKE3 measurement of the
//! Non-secure RX image before any authority-bearing op (§2), and dispatches the narrow state
//! machine (§5). The leaf crypto (`σ^chip` via TROPIC01, `σ^host` via BLAKE3-SPHINCS+), the durable
//! store, and every authority op (`prepare`/`commit`/`emit`/`finalize`/`recover`) are behind the
//! `SecureOps` seam and return fail-closed internal errors until the `real-crypto` increment.
//! `main` (reset) is a placeholder wfi loop until the SAU/ACCESSCTRL init (step 5) and the measured
//! NS loader (step 7) land.

#![no_std]
#![no_main]

extern crate panic_halt;

use core::sync::atomic::{compiler_fence, Ordering};
use rp235x_hal as hal;
use subtle::ConstantTimeEq;

// RP2350 boot block: emitted entirely by the linker (dsm-secure-sram.x `.start_block`), NOT by
// `ImageDef`. `ImageDef::secure_exe()` carries only an IMAGE_TYPE item — it cannot express the
// LOAD_MAP whose entries need link-time LMA/VMA/size. The linker block carries IMAGE_TYPE +
// relative-source LOAD_MAP (contiguous Secure image → SRAM, NSC veneer → 0x20040000, zero-fill
// Secure BSS) + explicit SRAM VECTOR_TABLE + ENTRY_POINT items, so the immutable bootrom is
// instructed to copy the flash payload into SRAM and enter there. (Cryptographic verification of
// that payload happens only once secure boot is enabled + validated; the LOAD_MAP itself just
// describes the copy.)

// ── Secure Gateway ABI (mirror of veneer/dsm_sg_abi.h) ────────────────────────────────────────
const SG_SLOT_INDEX: u32 = 0;
const SG_SLOT_MAX_LEN: usize = 4096;
const OP_STATUS: u32 = 1;
const OP_PREPARE: u32 = 2;
const OP_COMMIT: u32 = 3;
const OP_EMIT: u32 = 4;
const OP_FINALIZE: u32 = 5;
const OP_RECOVER: u32 = 6;
const SG_OK: u32 = 0;
const SG_ERR_SLOT: u32 = 1;
const SG_ERR_SEQ: u32 = 2;
const SG_ERR_SIZE: u32 = 3;
const SG_ERR_OPCODE: u32 = 4;
const SG_ERR_ENCODING: u32 = 5;
const SG_ERR_STATE: u32 = 6;
const SG_ERR_MEASUREMENT: u32 = 7;
const SG_ERR_INTERNAL: u32 = 8;

// ── Mailbox (§4): ONE fixed slot in Non-secure SRAM. Data plane only. ─────────────────────────
const MB_EMPTY: u32 = 0;
const MB_REQUEST_READY: u32 = 1;
const MB_SECURE_PROCESSING: u32 = 2;
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
    /// The fixed mailbox, placed in the Non-secure SRAM region by the linker (both crates agree on
    /// the address + layout). DMA is denied access to this region (§4 / ACCESSCTRL).
    static mut DSM_SG_MAILBOX: Mailbox;
    /// Canonical Non-secure RX image bounds (executable + read-only-data), fixed by the signed
    /// manifest — the exact bytes measured to `mu_enrolled`. Mutable data/heap/stack/mailbox are
    /// NOT in this range (§3).
    static __ns_rx_start: u8;
    static __ns_rx_end: u8;
}

/// Monotonic gateway sequence floor (replay rejection, §4).
static mut LAST_SEQ: u32 = 0;

// ── §2 exact measurement (fresh, before authority) ────────────────────────────────────────────

/// The enrolled application digest `mu_enrolled` (OTP-sealed, secure-read; see `otp-plan.json`).
/// Fail-closed: a permission-denied / blank read yields `None` and every authority op is refused.
fn mu_enrolled() -> Option<[u8; 32]> {
    // 16 ECC rows @ page 46 (row_base 2944) — MUST match otp-plan.json + provisioning.
    const MU_ROW: usize = 46 * hal::otp::NUM_ROWS_PER_PAGE;
    let mut out = [0u8; 32];
    let mut any = false;
    for i in 0..16 {
        let w = hal::otp::read_ecc_word(MU_ROW + i).ok()?;
        out[i * 2] = (w & 0x00ff) as u8;
        out[i * 2 + 1] = ((w >> 8) & 0x00ff) as u8;
        any |= w != 0;
    }
    if any {
        Some(out)
    } else {
        None
    }
}

/// Recompute BLAKE3 over the canonical Non-secure RX image and constant-time compare to
/// `mu_enrolled`. Called FRESH before each authority-bearing op (§2) — never a cached boolean
/// (an ordinary software bool is not the seal). Non-secure execution is suspended by the SG call,
/// core 1 is disabled, and DMA cannot write the measured region, so the bytes cannot change under us.
fn measurement_ok() -> bool {
    let enrolled = match mu_enrolled() {
        Some(m) => m,
        None => return false,
    };
    // Safety: the linker fixes these bounds inside the signed image; the region is RX (immutable).
    let start = core::ptr::addr_of!(__ns_rx_start) as usize;
    let end = core::ptr::addr_of!(__ns_rx_end) as usize;
    if end <= start {
        return false;
    }
    let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
    let measured = blake3::hash(bytes);
    measured.as_bytes().ct_eq(&enrolled).into()
}

/// Which ops mint signatures / move the counter and therefore REQUIRE a fresh measurement (§2).
fn op_requires_measurement(op: u32) -> bool {
    matches!(op, OP_PREPARE | OP_COMMIT | OP_EMIT | OP_FINALIZE | OP_RECOVER)
}

// ── The Secure handler behind the NSC veneer ─────────────────────────────────────────────────

/// Called by the `-mcmse` veneer's single NSC entry `dsm_secure_dispatch`. Secure-only.
#[no_mangle]
pub extern "C" fn dsm_secure_handler(slot_index: u32, sequence_number: u32) -> u32 {
    // §4.1 validate slot + state.
    if slot_index != SG_SLOT_INDEX {
        return SG_ERR_SLOT;
    }
    let mb = unsafe { &mut *core::ptr::addr_of_mut!(DSM_SG_MAILBOX) };
    if unsafe { core::ptr::read_volatile(&mb.state) } != MB_REQUEST_READY {
        return SG_ERR_STATE;
    }
    // §4.4 sequence: must equal the register arg AND advance the monotonic floor (replay reject).
    let seq = unsafe { core::ptr::read_volatile(&mb.sequence) };
    if sequence_number != seq || seq <= unsafe { LAST_SEQ } {
        return SG_ERR_SEQ;
    }
    // §4.2 transition to SECURE_PROCESSING before reading the body (ownership barrier).
    unsafe { core::ptr::write_volatile(&mut mb.state, MB_SECURE_PROCESSING) };
    compiler_fence(Ordering::SeqCst);

    // §4.3 read the bounded length ONCE; §4.4 copy the COMPLETE request into Secure SRAM.
    let opcode = unsafe { core::ptr::read_volatile(&mb.opcode) };
    let req_len = unsafe { core::ptr::read_volatile(&mb.req_len) } as usize;
    if req_len > SG_SLOT_MAX_LEN {
        return finish(mb, seq, SG_ERR_SIZE);
    }
    let mut sreq = [0u8; SG_SLOT_MAX_LEN];
    for (i, b) in sreq.iter_mut().enumerate().take(req_len) {
        *b = unsafe { core::ptr::read_volatile(&mb.body[i]) };
    }
    // §4.5 from here we interpret ONLY the Secure copy `sreq[..req_len]` — never the mailbox.
    let request = &sreq[..req_len];

    // §2 FRESH measurement before any authority-bearing op.
    if op_requires_measurement(opcode) && !measurement_ok() {
        // §7.12 measurement failure => no counter movement, no TROPIC/host signature.
        let s = finish(mb, seq, SG_ERR_MEASUREMENT);
        zeroize(&mut sreq);
        return s;
    }

    // §5 narrow dispatch — there is NO generic sign / chip_sign / counter / OTP / memory op.
    let mut ops = SecureOps::new();
    let (status, resp) = match opcode {
        OP_STATUS => ops.status(request),
        OP_PREPARE => ops.prepare(request),
        OP_COMMIT => ops.commit(request),
        OP_EMIT => ops.emit(request),
        OP_FINALIZE => ops.finalize(request),
        OP_RECOVER => ops.recover(request),
        _ => (SG_ERR_OPCODE, Response::empty()),
    };

    // §4.7 copy the bounded response back to the NS slot.
    let resp_cap = unsafe { core::ptr::read_volatile(&mb.resp_cap) } as usize;
    let n = resp.len.min(resp_cap).min(SG_SLOT_MAX_LEN);
    for i in 0..n {
        unsafe { core::ptr::write_volatile(&mut mb.body[i], resp.bytes[i]) };
    }
    unsafe { core::ptr::write_volatile(&mut mb.resp_len, n as u32) };

    // §4.9 zeroize the Secure request copy + sensitive temporaries.
    zeroize(&mut sreq);
    finish(mb, seq, status)
}

/// Publish the status, advance the sequence floor, transition to RESPONSE_READY (ownership barrier).
fn finish(mb: &mut Mailbox, seq: u32, status: u32) -> u32 {
    unsafe {
        core::ptr::write_volatile(&mut mb.status, status);
        LAST_SEQ = seq;
    }
    compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(&mut mb.state, MB_RESPONSE_READY) };
    status
}

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Bounded Secure→NS response.
struct Response {
    bytes: [u8; SG_SLOT_MAX_LEN],
    len: usize,
}
impl Response {
    fn empty() -> Self {
        Response {
            bytes: [0u8; SG_SLOT_MAX_LEN],
            len: 0,
        }
    }
}

// ── The narrow appliance state machine (§5/§6). Leaf crypto behind this seam. ─────────────────
//
// This increment implements the STATE MACHINE + validation; the TROPIC01 σ^chip, BLAKE3-SPHINCS+
// σ^host, physical counter, and durable store are fail-closed stubs until the `real-crypto`
// increment. No path here exposes a raw signer, an arbitrary counter decrement, or memory access.
struct SecureOps {
    _priv: (),
}
impl SecureOps {
    fn new() -> Self {
        SecureOps { _priv: () }
    }

    /// Read-only appliance status: measurement_ok, state, u_i, H0. No signature, no counter move.
    fn status(&mut self, _req: &[u8]) -> (u32, Response) {
        let mut r = Response::empty();
        r.bytes[0] = measurement_ok() as u8;
        // state / u_i / H0 filled from the durable record once the store lands.
        r.len = 1;
        (SG_OK, r)
    }

    /// Recompute the canonical DSM root-advance message internally from the request inputs; persist
    /// ONE prepared record. Mints NO signature; moves NO counter (§6). Fail-closed until wired.
    fn prepare(&mut self, req: &[u8]) -> (u32, Response) {
        if req.is_empty() {
            return (SG_ERR_ENCODING, Response::empty());
        }
        // (real-crypto increment) validate parent root/frontier/counter/policy from the Secure copy,
        // recompute M internally, persist the prepared record. Fail closed until wired.
        (SG_ERR_INTERNAL, Response::empty())
    }

    /// Load the prepared record; re-pin `H0 - H == prev_u`; ONE physical counter decrement; sign
    /// σ^chip + σ^host over the record's message ONLY; refuse a second distinct commit (§6).
    fn commit(&mut self, _req: &[u8]) -> (u32, Response) {
        (SG_ERR_INTERNAL, Response::empty())
    }

    /// Export the committed release bytes from the durable record.
    fn emit(&mut self, _req: &[u8]) -> (u32, Response) {
        (SG_ERR_INTERNAL, Response::empty())
    }

    fn finalize(&mut self, _req: &[u8]) -> (u32, Response) {
        (SG_ERR_INTERNAL, Response::empty())
    }

    /// Re-emit the byte-identical committed release, OR complete the one message already fixed in
    /// the durable record, OR downgrade online. NEVER accept a new recipient/challenge/successor
    /// root/transition digest for an already-consumed counter step (§6).
    fn recover(&mut self, _req: &[u8]) -> (u32, Response) {
        (SG_ERR_INTERNAL, Response::empty())
    }
}

extern "C" {
    /// Floor of the reserved Secure stack (from dsm-secure-sram.x). MSPLIM is set here so a Secure
    /// stack overflow FAULTs instead of corrupting the monitor's own code/state below the stack.
    static __secure_stack_limit: u32;
}

/// Secure reset heartbeat, at a fixed symbol in Secure SRAM (resolve via `nm`). The unlocked-board
/// bringup reads it to confirm the Secure reset path executed from SRAM (word 0 == the sentinel and
/// word 1 incrementing means the bootrom copied the image and entered the SRAM monitor). Not an
/// authority signal — purely a boot-liveness probe removed once the NS launch (step 5) lands.
#[no_mangle]
pub static mut DSM_SECURE_HEARTBEAT: [u32; 2] = [0; 2];
const HEARTBEAT_SENTINEL: u32 = 0x4453_4d31; // "DSM1"

// ── Reset entry (placeholder until step 5 SAU init + step 7 measured loader) ──────────────────
#[hal::entry]
fn main() -> ! {
    // Arm the Secure stack guard FIRST (belt-and-suspenders with the ENTRY_POINT sp_limit word):
    // set MSPLIM to the reserved stack floor before any deep call can overflow it.
    unsafe {
        let limit = core::ptr::addr_of!(__secure_stack_limit) as u32;
        cortex_m::register::msplim::write(limit);
    }

    // Diagnostic heartbeat for the unlocked-board bringup (see DSM_SECURE_HEARTBEAT).
    unsafe {
        let hb = core::ptr::addr_of_mut!(DSM_SECURE_HEARTBEAT);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*hb)[0]), HEARTBEAT_SENTINEL);
    }

    // Next increments: init the heap; assert the secure context (secure boot + debug-disable);
    // init SAU/MPU/DMA-MPU/NVIC-target-state/ACCESSCTRL (step 5); load+measure the NS app into NS
    // SRAM, RX-lock it (step 7); launch it Non-secure. Until then, halt — the monitor never returns
    // to Non-secure without the boundary configured.
    let mut beat: u32 = 0;
    loop {
        beat = beat.wrapping_add(1);
        unsafe {
            let hb = core::ptr::addr_of_mut!(DSM_SECURE_HEARTBEAT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*hb)[1]), beat);
        }
        cortex_m::asm::wfi();
    }
}
