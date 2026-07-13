// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM anchor RP2350 **Secure monitor** (TrustZone-M Secure world).
//!
//! Owns the TROPIC01 (`σ^chip`), the BLAKE3-SPHINCS+ partition key (`σ^host`), the physical counter,
//! prepare/commit/recovery state, the exact measurement seal, and the ONLY Secure Gateway (the NSC
//! veneer → this handler).
//!
//! STATUS (this increment): SRAM-resident TCB + runtime boundary + REAL appliance, wired; silicon
//! validation of the full crypto round trip is pending (needs a clean TROPIC power cycle).
//!  * The whole Secure TCB runs from SRAM: the boot-block `LOAD_MAP` (linker-emitted) instructs the
//!    bootrom to copy the SRAM-VMA payload out of mutable external flash before entry;
//!    `scripts/check-secure-no-xip.sh` PASSES. (Cryptographic verification of that flash image is a
//!    separate secure-boot step.)
//!  * `main` (reset) programs MSPLIM, builds the real appliance ([`anchor_glue::init`]), then
//!    configures the Secure/Non-secure boundary — SAU regions, `AIRCR.BFHFNMINS = 0`, the ACCESSCTRL
//!    lock, the recovery watchdog — and BXNS-launches the Non-secure image (§5, silicon 2026-07-12).
//!  * The veneer entry `dsm_secure_dispatch(slot, seq)` calls [`dsm_secure_handler`], which runs the
//!    mailbox state machine (§4), performs a **fresh** BLAKE3 measurement of the Non-secure RX image
//!    before any authority op (§2), and dispatches through the REAL `anchor_core` appliance
//!    ([`anchor_glue::service_request`] → `anchor_core::service::dispatch`) — `σ^chip` on the
//!    TROPIC01 die, `σ^host` via `dsm-sphincs`. The protocol state machine is NOT reimplemented here;
//!    it is `anchor_core`, the same crate the `dsm-anchor-pico` binary drives.
//!  * Fail-closed: if the chip/session/enroll bring-up in `init` fails, the appliance stays
//!    uninitialized and every authority op is refused (`SG_ERR_INTERNAL`).
//!  * Standalone crypto self-test + NS-launch/measurement bring-up proofs are retained behind the
//!    (default-OFF) `SIGMA_CHIP_SELFTEST` / `BRINGUP_NS_LAUNCH_PROOF` flags for silicon triage.

#![no_std]
#![no_main]

extern crate panic_halt;

use core::sync::atomic::{compiler_fence, Ordering};
use rp235x_hal as hal;
use subtle::ConstantTimeEq;

extern crate alloc;

mod anchor_glue;
mod boundary;
mod tropic;

// Secure working-set heap (SPHINCS+ σ^host signing + release/proto Vec staging). Lives in Secure
// .bss; the Non-secure app has its own separate heap. Initialized once at reset before any alloc.
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
const SECURE_HEAP_SIZE: usize = 56 * 1024;
static mut SECURE_HEAP_MEM: [core::mem::MaybeUninit<u8>; SECURE_HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); SECURE_HEAP_SIZE];

/// Bring-up DIAGNOSTIC (default OFF): run the standalone σ^chip/σ^host self-test from Secure and
/// signal the result by reboot timing, INSTEAD of the real appliance path. Retained behind this
/// flag so a future bench session can re-probe the crypto after a clean TROPIC power cycle; the
/// default path builds the real appliance (`anchor_glue::init`) and launches Non-secure.
const SIGMA_CHIP_SELFTEST: bool = false;

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
/// Reserved transport ABI code. Unknown ops are now decoded and rejected as `BAD_PROTO` inside
/// anchor-core's dispatch (a response frame, transport status SG_OK), so the monitor no longer emits
/// this — kept for ABI stability with the Non-secure transport + spec.
#[allow(dead_code)]
const SG_ERR_OPCODE: u32 = 4;
const SG_ERR_ENCODING: u32 = 5;
const SG_ERR_STATE: u32 = 6;
const SG_ERR_MEASUREMENT: u32 = 7;
const SG_ERR_INTERNAL: u32 = 8;

// ── Mailbox (§4): ONE fixed slot in Non-secure SRAM. Data plane only. ─────────────────────────
/// Idle mailbox state. Published by the Non-secure side (which owns the slot between round trips);
/// the monitor only ever transitions REQUEST_READY → SECURE_PROCESSING → RESPONSE_READY, so it does
/// not name this — kept for ABI parity with the NS transport's state enum.
#[allow(dead_code)]
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

/// UNTRUSTED mailbox-opcode hint (monitor `OP_*` scheme) — used ONLY by the bring-up triage path to
/// decide whether to fire the measurement fail-close reboot. The AUTHORITATIVE measurement gate runs
/// on the DECODED protobuf op inside `anchor_glue::service_request`, never on this hint.
fn op_requires_measurement_hint(op: u32) -> bool {
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

    // BRING-UP PROOF (step 5b / step 6, removed with the real NS response path): reaching here means
    // the Non-secure app launched, published a STATUS request into the NS mailbox, and crossed the
    // NSC `sg` veneer into this Secure handler — which read the NS data plane (state/seq/opcode). A
    // self-reboot into BOOTSEL is the observable signal (post-boot SRAM readback is cleared on
    // BOOTSEL entry on this silicon, so it cannot be the channel).
    if BRINGUP_NS_LAUNCH_PROOF && opcode == OP_STATUS {
        // Distinctive ~13 s delay BEFORE the reboot so a pass lands at a time nothing else produces:
        // ROM rejection of the block re-enters BOOTSEL in <2 s; a failed NS launch / SG (bad BXNS,
        // fault) never reboots at all (timeout). A reboot at ~13 s therefore isolates "the handler
        // ran" = NS launched + crossed the SG + Secure read the NS mailbox. (~7M cycles/s on the
        // post-ROM clock.)
        delayed_reboot(SG_REBOOT_DELAY_CYCLES);
    }
    if req_len > SG_SLOT_MAX_LEN {
        return finish(mb, seq, SG_ERR_SIZE);
    }
    let mut sreq = [0u8; SG_SLOT_MAX_LEN];
    for (i, b) in sreq.iter_mut().enumerate().take(req_len) {
        *b = unsafe { core::ptr::read_volatile(&mb.body[i]) };
    }
    // §4.5 from here we interpret ONLY the Secure copy `sreq[..req_len]` — never the mailbox.
    let request = &sreq[..req_len];

    // BRING-UP measurement fail-close proof (retained behind the flag for silicon triage): an
    // authority op is refused because OTP `mu_enrolled` is blank on an unprovisioned board.
    // Distinctive ~25 s reboot. The real gate below applies to the DECODED op, not this hint.
    if BRINGUP_NS_LAUNCH_PROOF && op_requires_measurement_hint(opcode) && !measurement_ok() {
        delayed_reboot(180_000_000);
    }

    // §5 dispatch through the REAL appliance (dsm-anchor-core `dispatch`), NOT a reimplemented state
    // machine. `service_request` decodes the protobuf `ApplianceRequest`, applies the §2 measurement
    // seal to the DECODED op, and drives `Appliance::{prepare,commit,emit,finalize,status,cancel}`.
    // The returned frame is the encoded `ApplianceResponse`; the transport status is SG_OK unless
    // the frame could not even be produced (decode / measurement / uninitialized-appliance failure).
    let status = match unsafe { anchor_glue::service_request(request, measurement_ok()) } {
        Ok(resp) => {
            // §4.7 copy the bounded response back to the NS slot.
            let resp_cap = unsafe { core::ptr::read_volatile(&mb.resp_cap) } as usize;
            let n = resp.len().min(resp_cap).min(SG_SLOT_MAX_LEN);
            for (i, byte) in resp.iter().enumerate().take(n) {
                unsafe { core::ptr::write_volatile(&mut mb.body[i], *byte) };
            }
            unsafe { core::ptr::write_volatile(&mut mb.resp_len, n as u32) };
            SG_OK
        }
        Err(err_status) => {
            unsafe { core::ptr::write_volatile(&mut mb.resp_len, 0) };
            err_status
        }
    };

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
    // Initialize the Secure heap once, before any allocation (σ^host / release staging use it).
    unsafe {
        HEAP.init(
            core::ptr::addr_of_mut!(SECURE_HEAP_MEM) as usize,
            SECURE_HEAP_SIZE,
        );
    }

    // If the previous boot armed the watchdog and never disarmed it, a watchdog reset fired — i.e.
    // we are recovering from a Non-secure-induced hang (the NS->DMA bus stall). Recover cleanly to
    // BOOTSEL instead of re-launching NS into the same stall. reboot_bootsel disarms + clears it.
    if boundary::watchdog_recovery_pending() {
        // Recover to a safe state (BOOTSEL) instead of re-launching NS into the same hang. Proven on
        // silicon 2026-07-12: with a distinctive ~20 s recovery marker the NS->DMA stall self-rebooted
        // at 22 s (vs a permanent TIMEOUT without the watchdog); here the recovery is immediate.
        reboot_bootsel();
    }

    // Arm the Secure stack guard FIRST (belt-and-suspenders with the ENTRY_POINT sp_limit word):
    // set MSPLIM to the reserved stack floor before any deep call can overflow it.
    unsafe {
        let limit = core::ptr::addr_of!(__secure_stack_limit) as u32;
        cortex_m::register::msplim::write(limit);
    }

    // σ^chip / σ^host bring-up: drive the crypto from Secure and publish the exact result CODE in
    // watchdog SCRATCH1 (peripheral RAM survives the ROM BOOTSEL entry that wipes main SRAM), so the
    // host reads the byte directly with `picotool save` — NO timing inference. A short beat delay is
    // kept only so the board is quiescent before it drops to BOOTSEL.
    if SIGMA_CHIP_SELFTEST {
        let r = tropic::sigma_chip_selftest();
        // Timing channel with HUGE monotonic gaps so the variable TROPIC-session time (a few seconds)
        // can never push one bucket into another. 3-way headline (subdivide later if needed):
        //   ~57 s .. σ^host FULL (σ^chip + keygen + sign + verify)   r == 0xFF
        //   ~37 s .. σ^chip OK, σ^host incomplete                    r >= 0x1F
        //   ~15 s .. σ^chip FAILED (no session / sign)               r <  0x1F
        let beats: u32 = if r == 0xFF {
            50
        } else if r >= 0x1F {
            30
        } else {
            8
        };
        for _ in 0..beats {
            cortex_m::asm::delay(150_000_000); // ~1 s @150 MHz
        }
        reboot_bootsel();
    }

    // Diagnostic heartbeat for the unlocked-board bringup (see DSM_SECURE_HEARTBEAT).
    unsafe {
        let hb = core::ptr::addr_of_mut!(DSM_SECURE_HEARTBEAT);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*hb)[0]), HEARTBEAT_SENTINEL);
    }

    // Step 7: build the REAL appliance (TROPIC01 σ^chip + BLAKE3-SPHINCS+ σ^host, resident chip key,
    // one-way birth fuse) BEFORE the boundary is locked and NS launched, so the Secure-only SPI0/
    // TROPIC bring-up runs while the monitor still owns everything. Fail-closed: a chip/session/
    // enroll failure leaves the appliance uninitialized and every authority op refuses (the SG
    // handler returns SG_ERR_INTERNAL). Record readiness in heartbeat[1] for bring-up triage.
    let app_ready = unsafe { anchor_glue::init() };
    unsafe {
        let hb = core::ptr::addr_of_mut!(DSM_SECURE_HEARTBEAT);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*hb)[1]), app_ready as u32);
    }

    // Step 5: configure the Secure/Non-secure boundary BEFORE any Non-secure launch. This runs from
    // Secure SRAM; if the attribution were wrong (e.g. Secure code marked NS) the Secure world would
    // fault here and never reach the self-reboot below — so a self-reboot proves SAU enable is safe.
    boundary::assert_core1_contained();
    {
        // Single-threaded reset context; core peripherals are borrowed only here.
        let mut cp = unsafe { cortex_m::Peripherals::steal() };
        // A failed SAU program is fail-closed: halt rather than launch anything with a bad boundary.
        if boundary::configure_sau(&mut cp.SAU).is_err() {
            loop {
                cortex_m::asm::wfi();
            }
        }
    }
    // Route Non-secure-originated BusFault/HardFault/NMI to SECURE (AIRCR.BFHFNMINS = 0), so a
    // Non-secure access the bus/ACCESSCTRL denies with a bus error traps to the Secure fault handler
    // rather than a Non-secure fault the app might mishandle. VECTKEY 0x05FA in the top half; the
    // low bits (incl. PRIS) are preserved. (This does NOT change the NS->DMA case: an NS access to
    // the secure AHB/DMA peripheral stalls with no bus response rather than raising a bus error — a
    // documented RP2350 behavior — so there is no fault to route; NS is still denied, no data. It
    // DOES matter for the general case where a denied NS access does bus-error.)
    unsafe {
        let aircr = core::ptr::read_volatile(0xE000_ED0C as *const u32);
        let new = (0x05FA << 16) | (aircr & 0x0000_FFFF & !(1 << 13));
        core::ptr::write_volatile(0xE000_ED0C as *mut u32, new);
        cortex_m::asm::dsb();
    }

    // Freeze the ACCESSCTRL config so the Secure resource attribution cannot be re-opened. The bootrom
    // already locks the DMA master out (LOCK.dma, silicon 2026-07-12); this adds core1 + the debugger.
    // Reset-clearable (power cycle), NOT OTP.
    boundary::lock_accessctrl();

    // Arm the watchdog just before handing control to Non-secure: if NS hangs the core (the DMA-stall
    // BLOCKED case), no Secure path feeds the watchdog and it resets the chip -> recovered on reboot
    // (vs a permanent hang / DoS). The Secure fault + gateway paths feed it via `delayed_reboot`.
    boundary::arm_watchdog();

    // Step 5b: launch the Non-secure app. The bootrom copied its image to NS SRAM (LOAD_MAP entry 3)
    // and SAU marks that region Non-secure; this sets MSP_NS + VTOR_NS from the NS vector table and
    // BXNS into the NS reset vector. Control leaves Secure and only re-enters through the `sg`
    // veneer. (Step 7 replaces the bring-up stub with the measured real NS app; step 5 still owes
    // ACCESSCTRL/DMA/NVIC/lock.) If the launch ever returns, halt fail-closed.
    unsafe {
        launch_nonsecure(core::ptr::addr_of!(__ns_app_vector_table) as u32);
    }
}

/// Bring-up proof flag (step 5b/6, default OFF): when set, the Secure handler self-reboots into
/// BOOTSEL on a STATUS call / measurement fail so the NS→S round trip is observable on silicon.
/// Retained for triage; the default path runs the real appliance dispatch (`service_request`).
const BRINGUP_NS_LAUNCH_PROOF: bool = false;

/// Distinctive reboot timings that make silicon outcomes readable by wall-clock alone, since
/// post-boot SRAM readback is cleared on BOOTSEL entry. The two delays are far apart so re-enumeration
/// jitter + 2 s poll granularity cannot confuse them (empirically ~90M cycles ≈ 14 s):
///   ROM rejects the block ......... < 4 s   (nothing of ours ran)
///   DENIED (Secure fault fired) ... ~11 s   (a boundary violation trapped to Secure)
///   ALLOWED (NS reached the SG) ... ~50 s   (no fault; NS crossed the gateway)
///   lockup / no path .............. timeout
const FAULT_REBOOT_DELAY_CYCLES: u32 = 70_000_000; // ~11 s
const SG_REBOOT_DELAY_CYCLES: u32 = 320_000_000; // ~50 s

fn reboot_bootsel() -> ! {
    // Disarm the watchdog on any deliberate reboot so it cannot fire while the chip is in BOOTSEL.
    boundary::disarm_watchdog();
    hal::reboot::reboot(
        hal::reboot::RebootKind::BootSel {
            picoboot_disabled: false,
            msd_disabled: false,
        },
        hal::reboot::RebootArch::Normal,
    )
}

/// Spin for `cycles` while FEEDING the watchdog (so a live Secure path is never reset), then reboot.
/// Used by the bring-up timed reboots; a hung core cannot reach this, so the watchdog fires instead.
fn delayed_reboot(cycles: u32) -> ! {
    let mut remaining = cycles;
    while remaining > 0 {
        boundary::feed_watchdog();
        let d = remaining.min(1_000_000);
        cortex_m::asm::delay(d);
        remaining -= d;
    }
    reboot_bootsel()
}

/// Secure fault handler = the denial-test observable. An NS access the boundary forbids (SAU-Secure
/// SRAM, or an ACCESSCTRL-Secure peripheral that escalates here) traps to Secure; this reboots after
/// the DENIED delay. Reaching it proves the access faulted rather than returning secret data.
///
#[cortex_m_rt::exception]
unsafe fn HardFault(_ef: &cortex_m_rt::ExceptionFrame) -> ! {
    // ANY fault reaching Secure -> ~12 s reboot (feeding the watchdog so a trapped fault, unlike a
    // hang, is not treated as a stall).
    delayed_reboot(FAULT_REBOOT_DELAY_CYCLES)
}

extern "C" {
    /// The Non-secure app's 2-word vector table (`[initial NS MSP, NS reset]`), at the NS SRAM base
    /// (dsm-secure-sram.x `.ns_app`). Copied there by LOAD_MAP entry 3.
    static __ns_app_vector_table: u32;
}

/// Transfer control to Non-secure. Sets the banked NS main stack pointer and NS vector table, then
/// `BXNS` into the NS reset vector (bit 0 cleared selects the Non-secure state). Never returns:
/// Secure code runs again only when Non-secure calls the NSC `sg` veneer.
///
/// # Safety
/// `ns_vector_table` must point at a valid, SAU-Non-secure, 2-word NS vector table whose word 0 is a
/// valid NS stack top and word 1 a valid NS reset vector; SAU must already attribute the NS region.
unsafe fn launch_nonsecure(ns_vector_table: u32) -> ! {
    core::arch::asm!(
        "ldr   {sp}, [{tbl}]",        // NS initial MSP = ns_table[0]
        "msr   MSP_NS, {sp}",
        "ldr   {ent}, [{tbl}, #4]",   // NS reset vector = ns_table[1] (thumb, bit0=1)
        "movw  {vt}, #0xED08",        // SCB_NS->VTOR = 0xE002ED08
        "movt  {vt}, #0xE002",
        "str   {tbl}, [{vt}]",        // VTOR_NS = ns_table
        "bic   {ent}, {ent}, #1",     // clear bit0 so BXNS targets the Non-secure state
        "bxns  {ent}",
        tbl = in(reg) ns_vector_table,
        sp = out(reg) _,
        ent = out(reg) _,
        vt = out(reg) _,
    );
    // BXNS does not return to Secure except via the `sg` veneer; this is unreachable.
    cortex_m::asm::udf()
}
