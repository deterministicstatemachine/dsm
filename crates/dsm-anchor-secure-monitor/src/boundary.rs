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

/// Lock the ACCESSCTRL configuration so the Secure resource attribution cannot be re-opened.
///
/// The peripherals that must never be Non-secure-reachable (OTP, SPI0/TROPIC, the DMA controller)
/// default to "Secure access from any master", and the SAU already faults every Non-secure-core
/// access to the whole non-NS-SRAM space (proven: NS reads of Secure SRAM / OTP / SPI0 all trap).
/// The one path the SAU does NOT cover is a Non-secure-driven DMA — but that is closed at the
/// source, because the DMA controller is itself Secure-only, so Non-secure code cannot program a
/// DMA at all.
///
/// This freezes that state: LOCK bits make ACCESSCTRL silently ignore writes from core 1 and the
/// debugger, so neither can re-open a Secure resource. A LOCK bit clears ONLY on a full ACCESSCTRL
/// reset (power cycle) — reset-clearable, NOT an OTP burn. Core 0 (the Secure monitor, the TCB)
/// intentionally keeps control so it can still manage the boundary as later increments assign the
/// Non-secure app its own peripherals (config-then-lock). (The DMA LOCK bit is not host-writable in
/// this PAC; the DMA-master path stays closed by the DMA controller being Secure-only.)
///
/// SILICON FINDING (2026-07-12, chip 0x430ed6d919933c8e): this LOCK **write** FAULTS (bus error ->
/// Secure fault) even though a read of the same register succeeds, and the monitor is confirmed
/// Secure + Privileged (so it is NOT the datasheet's unprivileged-write bus error). Root cause not
/// yet identified. The caller keeps this OFF (`LOCK_BOUNDARY = false`) until it is understood; the
/// boundary is proven and denies without it (SAU faults every NS access to Secure SRAM/OTP/TROPIC).
pub fn lock_accessctrl(ac: &hal::pac::ACCESSCTRL) {
    ac.lock().write(|w| w.core1().set_bit().debug().set_bit());
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
