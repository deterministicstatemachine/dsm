// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runtime Secure/Non-secure boundary configuration (SECURITY_BOUNDARY.md §5, step 5).
//!
//! Programmed by the Secure monitor at reset BEFORE any Non-secure code is launched. Establishes the
//! TrustZone-M address attribution (SAU) so that only the NSC veneer region is a legal NS→S entry and
//! the Non-secure app is confined to NS SRAM; Secure SRAM (the whole TCB, host key, Secure state),
//! the boot block, OTP, and — once wired — TROPIC01 SPI stay Secure and unreachable from NS.
//!
//! Increment status (step 5): SAU attribution + core-1 containment land here first and are silicon-
//! checked (the Secure monitor must keep running after `sau.enable()`). ACCESSCTRL peripheral
//! ownership, the DMA restrictions, NVIC target state, and the config lock are added as the TROPIC/
//! USB peripherals are wired and the Non-secure launch lands — each behind its own matrix row.

use cortex_m::peripheral::sau::{SauError, SauRegion, SauRegionAttribute};
use cortex_m::peripheral::SAU;
use rp235x_hal as hal;

// ── Watchdog: recover from a Non-secure-induced hang (e.g. the NS->DMA bus stall) ─────────────
//
// A Non-secure access to a secure AHB peripheral (DMA) is BLOCKED via a bus STALL — the core hangs
// with no fault to trap. A stall is not a leak, but a permanent hang is a DoS. The watchdog turns it
// into a recovered reset: armed before the NS launch, FED by the Secure fault/gateway paths while
// they run (so normal operation never trips it), it fires only when NO code is running for the
// period — exactly the stall — resetting the chip. The next boot detects the recovery via SCRATCH0.
const WD_CTRL: *mut u32 = 0x400d_8000 as *mut u32;
const WD_LOAD: *mut u32 = 0x400d_8004 as *mut u32;
const WD_SCRATCH0: *mut u32 = 0x400d_800c as *mut u32;
const WD_PERIOD_US: u32 = 2_000_000; // ~2 s (nominal; scales with clk_ref)
const WD_ARMED: u32 = 0x5744_4147; // "WDAG": set while armed, cleared on a deliberate reboot / power-on

/// True iff the previous boot armed the watchdog and never disarmed it — i.e. a watchdog reset fired
/// (recovery from a Non-secure hang). SCRATCH0 survives a soft/watchdog reset; `disarm_watchdog`
/// clears it on every deliberate reboot; a power-on clears it.
pub fn watchdog_recovery_pending() -> bool {
    unsafe { core::ptr::read_volatile(WD_SCRATCH0 as *const u32) == WD_ARMED }
}

/// Arm the watchdog immediately before launching Non-secure.
pub fn arm_watchdog() {
    let pac = unsafe { hal::pac::Peripherals::steal() };
    let mut wd = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    wd.enable_tick_generation(12); // ~1 us tick assuming ~12 MHz clk_ref
    wd.start(hal::fugit::MicrosDurationU32::from_ticks(WD_PERIOD_US));
    unsafe { core::ptr::write_volatile(WD_SCRATCH0, WD_ARMED) };
}

/// Reload the watchdog. Called by the Secure paths while they spin so a LIVE monitor is not reset;
/// a hung core (the stall) cannot call this, so the watchdog fires.
#[inline(always)]
pub fn feed_watchdog() {
    unsafe { core::ptr::write_volatile(WD_LOAD, WD_PERIOD_US) };
}

/// Disarm on any deliberate reboot (so it cannot fire once the chip is in BOOTSEL) and clear the
/// recovery marker.
pub fn disarm_watchdog() {
    unsafe {
        let ctrl = core::ptr::read_volatile(WD_CTRL as *const u32);
        core::ptr::write_volatile(WD_CTRL, ctrl & !(1 << 30)); // clear CTRL.ENABLE (bit 30)
        core::ptr::write_volatile(WD_SCRATCH0, 0);
    }
}

/// TrustZone domain map (must match dsm-secure-sram.x / memory.x). SAU limit addresses are the
/// INCLUSIVE last byte (low 5 bits = 1), per the cortex-m SAU API.
const NSC_BASE: u32 = 0x2004_0000;
const NSC_LIMIT: u32 = 0x2004_0FFF; // NSC veneer region [0x20040000, 0x20041000)
const NS_BASE: u32 = 0x2004_1000;
const NS_LIMIT: u32 = 0x2007_FFFF; // Non-secure SRAM [0x20041000, 0x20080000)

/// Configure SAU address attribution and enable it.
///
/// Regions defined:
/// - region 0: NSC — the single legal NS→S gateway surface (the `sg` veneer at 0x20040000).
/// - region 1: NS  — the Non-secure app's SRAM (code/data/stack + the mailbox data plane).
///
/// Everything NOT covered by an enabled NS/NSC region is Secure by default (SAU_CTRL.ALLNS=0): the
/// Secure monitor image at [0x20000000,0x20040000), the flash boot block, OTP, and all peripherals.
/// This function runs from Secure SRAM and must leave the Secure monitor executing (no Secure region
/// is marked NS), so a post-config self-reboot / continued execution is the silicon check that the
/// attribution did not fault the Secure world.
pub fn configure_sau(sau: &mut SAU) -> Result<(), SauError> {
    sau.set_region(
        0,
        SauRegion {
            base_address: NSC_BASE,
            limit_address: NSC_LIMIT,
            attribute: SauRegionAttribute::NonSecureCallable,
        },
    )?;
    sau.set_region(
        1,
        SauRegion {
            base_address: NS_BASE,
            limit_address: NS_LIMIT,
            attribute: SauRegionAttribute::NonSecure,
        },
    )?;
    // ALLNS stays 0: unmatched addresses (Secure monitor, flash, OTP, peripherals) are Secure.
    sau.enable();
    Ok(())
}

/// Freeze the ACCESSCTRL configuration so the Secure resource attribution cannot be re-opened.
///
/// ACCESSCTRL register writes require the write password `0xACCE` in the top 16 bits; a keyless write
/// is rejected with a bus fault (this is what my earlier keyless attempts hit — NOT that LOCK is
/// unwritable). With the password the monitor sets LOCK.core1 + LOCK.debug, so neither core 1 nor the
/// debugger can modify ACCESSCTRL. The bootrom already sets LOCK.dma at boot (silicon 2026-07-12: LOCK
/// reads 0b0100), so the DMA master is covered too; core 0 (the Secure monitor / TCB) is intentionally
/// left unlocked so it retains control. LOCK bits clear ONLY on a full ACCESSCTRL reset (power cycle) —
/// reset-clearable, NOT an OTP burn. Verified on silicon: the password write sets the bits (read back).
pub fn lock_accessctrl() {
    const ACCESSCTRL_WRITE_PASSWORD: u32 = 0xACCE_0000;
    const LOCK: *mut u32 = 0x4006_0000 as *mut u32;
    const LOCK_CORE1: u32 = 1 << 1;
    const LOCK_DEBUG: u32 = 1 << 3;
    unsafe {
        core::ptr::write_volatile(LOCK, ACCESSCTRL_WRITE_PASSWORD | LOCK_CORE1 | LOCK_DEBUG);
        cortex_m::asm::dsb();
    }
}
/// Core-1 containment. RP2350 core 1 does not execute until core 0 launches it via the SIO FIFO
/// vector handshake; the monitor never performs that handshake, so core 1 stays powered-down with
/// no bus master activity. v1 is deliberately single-core (no reviewed Secure multicore design), so
/// "disabled" is the absence of the launch, asserted here as an explicit invariant. A hard PSM
/// reset-hold is added when the peripheral set that could be reached by a rogue core-1 is wired.
#[inline(always)]
pub fn assert_core1_contained() {
    // No-op by construction: core 1 is never launched. Kept as a named invariant + integration seam.
}
