// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runtime Secure/Non-secure boundary configuration (SECURITY_BOUNDARY.md §5, step 5).
//!
//! Programmed by the Secure monitor at reset BEFORE any Non-secure code is launched. Establishes the
//! TrustZone-M address attribution (SAU) so that only the NSC veneer region is a legal NS→S entry and
//! the Non-secure app is confined to its flash image and NS SRAM; Secure SRAM (the whole TCB, host
//! key, Secure state), the boot block, OTP, and TROPIC01 SPI stay Secure and unreachable from NS.
//!
//! The Non-secure side gets no DMA. The chip's memory permissions are per 64 KiB SRAM bank, and the
//! bank at the Secure/Non-secure boundary holds the top of the Secure region: the Secure stack. A
//! Non-secure DMA channel's reads are checked at the bank, so it could read that stack. The radio
//! the Non-secure app drives moves its bytes through the PIO FIFOs by the core.
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
// period — exactly the stall — resetting the chip. The reset boots the signed image again.
const WD_LOAD: *mut u32 = 0x400d_8004 as *mut u32;
const WD_PERIOD_US: u32 = 2_000_000; // ~2 s (nominal; scales with clk_ref)
/// While the Secure side serves a request: the register's whole 24 bits, ~16.7 s. A SPHINCS+
/// signature alone takes ~7 s on this silicon, and a record write is dozens of chip commands.
const WD_SERVICE_US: u32 = 0x00FF_FFFF;

/// Arm the watchdog immediately before launching Non-secure.
pub fn arm_watchdog() {
    let pac = unsafe { hal::pac::Peripherals::steal() };
    let mut wd = hal::watchdog::Watchdog::new(pac.WATCHDOG);
    wd.enable_tick_generation(12); // ~1 us tick assuming ~12 MHz clk_ref
    wd.start(hal::fugit::MicrosDurationU32::from_ticks(WD_PERIOD_US));
}

/// Reload the watchdog. Called by the Secure paths while they spin so a LIVE monitor is not reset;
/// a hung core (the stall) cannot call this, so the watchdog fires.
#[inline(always)]
pub fn feed_watchdog() {
    unsafe { core::ptr::write_volatile(WD_LOAD, WD_PERIOD_US) };
}

/// Reload the watchdog with the budget of a request being served: each chip command renews it, and a
/// Secure side that hangs or panics inside a serve still resets. Returning to the Non-secure side
/// takes the short budget back ([`feed_watchdog`]).
#[inline(always)]
pub fn feed_watchdog_in_service() {
    unsafe { core::ptr::write_volatile(WD_LOAD, WD_SERVICE_US) };
}

/// TrustZone domain map (must match dsm-secure-sram.x / memory.x). SAU limit addresses are the
/// INCLUSIVE last byte (low 5 bits = 1), per the cortex-m SAU API.
const NSC_BASE: u32 = 0x2006_4000;
const NSC_LIMIT: u32 = 0x2006_4FFF; // NSC veneer region [0x20064000, 0x20065000)
const NS_BASE: u32 = 0x2006_5000;
const NS_LIMIT: u32 = 0x2007_FFFF; // Non-secure SRAM [0x20065000, 0x20080000)
/// The Non-secure image's flash region, executed in place: the measured window, whole.
const NSF_BASE: u32 = 0x1010_0000;
const NSF_LIMIT: u32 = 0x1017_FFFF;
// Peripheral space made Non-secure-ADDRESSABLE so the NS app can reach the clocks + USB it needs.
// This is defense-in-depth, NOT a blanket grant: SAU only lifts the address-level Secure attribution;
// per-peripheral ACCESSCTRL (grant_ns_peripherals) still gates WHICH peripherals NS may touch, and
// every Secure peripheral (OTP 0x…60a8, SPI0 0x…6090, DMA, …) keeps its reset default NSP=0, so an
// NS access to it still bus-errors. Covers APB (0x40000000+), the USB block (0x50100000+) and
// PIO0 (0x50200000+, the radio's bus); SIO (0xd0000000) is deliberately NOT covered: the NS app
// drives its four radio pins through IO_BANK0's overrides and PIO, never SIO.
const PERIPH_BASE: u32 = 0x4000_0000;
const PERIPH_LIMIT: u32 = 0x502F_FFFF;

/// Configure SAU address attribution and enable it.
///
/// Regions defined:
/// - region 0: NSC — the single legal NS→S gateway surface (the `sg` veneer at 0x20064000).
/// - region 1: NS  — the Non-secure app's SRAM (data/stack + the mailbox data plane).
/// - region 2: the peripheral space the app may address (ACCESSCTRL gates each peripheral).
/// - region 3: NSF — the Non-secure app's flash image, executed in place (the measured window).
///
/// Everything NOT covered by an enabled NS/NSC region is Secure by default (SAU_CTRL.ALLNS=0): the
/// Secure monitor image at [0x20000000,0x20064000), the flash boot block, OTP, and all peripherals.
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
    // region 2: peripheral space — NS-addressable so the NS app can drive clocks + USB. ACCESSCTRL
    // (grant_ns_peripherals) is the fine-grained gate; Secure peripherals keep NSP=0 and stay denied.
    sau.set_region(
        2,
        SauRegion {
            base_address: PERIPH_BASE,
            limit_address: PERIPH_LIMIT,
            attribute: SauRegionAttribute::NonSecure,
        },
    )?;
    // region 3: the Non-secure image in flash. XIP_MAIN is granted below so the NS core may fetch
    // from it; every other flash address (the Secure image's storage, the boot block) stays Secure.
    sau.set_region(
        3,
        SauRegion {
            base_address: NSF_BASE,
            limit_address: NSF_LIMIT,
            attribute: SauRegionAttribute::NonSecure,
        },
    )?;
    // ALLNS stays 0: unmatched addresses (Secure monitor SRAM, flash boot block, SIO) are Secure.
    sau.enable();
    Ok(())
}

const ACCESSCTRL_BASE: u32 = 0x4006_0000;
const ACCESSCTRL_PASSWORD: u32 = 0xACCE_0000;
const NSP: u32 = 1 << 1;
const NSU: u32 = 1 << 0;
/// ACCESSCTRL per-peripheral register offsets (rp235x-pac SVD). What the Non-secure app keeps while
/// it serves: XIP_MAIN (it runs from its flash image), USBCTRL, PIO0 (the radio's bus), IO_BANK0 and
/// PADS_BANK0 (its four radio pins, and only those: `GPIO_NSMASK0`), TIMER1 (its clock; TIMER0 is
/// the monitor's).
const NS_SERVING_GRANTS: [u32; 6] = [0x18, 0x48, 0x4c, 0x68, 0x70, 0x9c];
/// `ACCESSCTRL.GPIO_NSMASK0`: which of GPIO 0..31 the Non-secure side may touch through IO_BANK0,
/// PADS_BANK0 and SIO. The radio's four: WL_ON (23), DATA (24), CS (25), CLK (29). The TROPIC01's
/// bus pins (16..19) and everything else stay Secure.
const GPIO_NSMASK0: u32 = 0x0c;
const NS_RADIO_PINS: u32 = (1 << 23) | (1 << 24) | (1 << 25) | (1 << 29);
/// What it needs only to bring up its clocks and USB: RESETS, CLOCKS, XOSC, PLL_SYS, PLL_USB, TICKS
/// (the tick generator clock init starts; SWD-confirmed BFAR 0x40108004) and WATCHDOG.
const NS_BRING_UP_GRANTS: [u32; 7] = [0x64, 0xc0, 0xc4, 0xcc, 0xd0, 0xd4, 0xd8];

/// Grant Non-secure access, via per-peripheral ACCESSCTRL, to ONLY the peripherals the NS app drives:
/// the clock tree (CLOCKS/XOSC/PLL_SYS/PLL_USB), RESETS + WATCHDOG (used by the HAL clock init), and
/// USBCTRL. Every other peripheral — critically OTP and SPI0 (the TROPIC bus) — keeps its reset
/// default NSP=0 and remains Non-secure-denied at the bus, so the SAU peripheral region does not
/// expose them. Writes are read-modify-write (preserve the existing Secure/core bits, add NSP+NSU)
/// and carry the mandatory 0xACCE password in the top 16 bits; a keyless write bus-faults. Must run
/// BEFORE lock_accessctrl and BEFORE launch_nonsecure.
///
/// Everything but USB is held only until the app's clocks and USB are up: [`revoke_ns_init_grants`]
/// takes them back at its first crossing, so nothing a USB host sends is ever parsed by a Non-secure
/// side able to reset a Secure peripheral, touch the watchdog or change a clock.
pub fn grant_ns_peripherals() {
    let keep = NS_SERVING_GRANTS.iter().chain(NS_BRING_UP_GRANTS.iter());
    for off in keep {
        let reg = (ACCESSCTRL_BASE + off) as *mut u32;
        unsafe {
            let cur = core::ptr::read_volatile(reg) & 0xFF;
            core::ptr::write_volatile(reg, ACCESSCTRL_PASSWORD | cur | NSP | NSU);
        }
    }
    // The pin mask takes no password: its 32 bits are GPIO 0..31, and nothing else goes in it.
    unsafe {
        core::ptr::write_volatile((ACCESSCTRL_BASE + GPIO_NSMASK0) as *mut u32, NS_RADIO_PINS);
    }
}

/// `NVIC_ITNS0`: the interrupts the Non-secure side handles, bit per interrupt number 0..31.
const NVIC_ITNS0: *mut u32 = 0xE000_E380 as *mut u32;
/// TIMER1_IRQ_0 (4): the Non-secure clock's alarm. PIO0_IRQ_0 (15): the radio has an event.
const NS_INTERRUPTS: u32 = (1 << 4) | (1 << 15);

/// Target the Non-secure app's two interrupts at the Non-secure state, so they vector through its
/// table and run in its world. Every other interrupt stays Secure and is never enabled. Before the
/// Non-secure launch.
pub fn target_ns_interrupts() {
    unsafe {
        let cur = core::ptr::read_volatile(NVIC_ITNS0);
        core::ptr::write_volatile(NVIC_ITNS0, cur | NS_INTERRUPTS);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}

/// Take back what the Non-secure app needed only to bring up its clocks and USB. Runs at every
/// crossing, and writes only what is still granted. Core 0 keeps the right to: `lock_accessctrl`
/// locks core 1 and the debugger out.
pub fn revoke_ns_init_grants() {
    for off in NS_BRING_UP_GRANTS {
        let reg = (ACCESSCTRL_BASE + off) as *mut u32;
        unsafe {
            let cur = core::ptr::read_volatile(reg) & 0xFF;
            if cur & (NSP | NSU) != 0 {
                core::ptr::write_volatile(reg, ACCESSCTRL_PASSWORD | (cur & !(NSP | NSU)));
                cortex_m::asm::dsb();
            }
        }
    }
}

/// This Cortex-M33 reported fewer Non-secure MPU regions than the window needs.
#[derive(Debug)]
pub struct NsMpuTooSmall;

/// The Non-secure MPU, through its Secure alias, before anything Non-secure runs: the measured window
/// `[rx_start, rx_end)` (the app's flash image) read-only and executable, and all of Non-secure SRAM
/// writable and never executed. A stray or attacker-steered write cannot change the code the digest
/// covers (flash takes no write from the Non-secure side in any case), and bytes a host or the radio
/// delivered cannot run. Peripherals stay reachable through the privileged default map, gated by
/// ACCESSCTRL. The Non-secure side runs privileged, so its own code could reprogram this; what stops
/// that is that it holds no code but the measured window.
pub fn protect_ns_window(rx_start: u32, rx_end: u32) -> Result<(), NsMpuTooSmall> {
    const MPU_TYPE: *const u32 = 0xE002_ED90 as *const u32;
    const MPU_CTRL: *mut u32 = 0xE002_ED94 as *mut u32;
    const MPU_RNR: *mut u32 = 0xE002_ED98 as *mut u32;
    const MPU_RBAR: *mut u32 = 0xE002_ED9C as *mut u32;
    const MPU_RLAR: *mut u32 = 0xE002_EDA0 as *mut u32;
    const MPU_MAIR0: *mut u32 = 0xE002_EDC0 as *mut u32;
    const CTRL_ENABLE: u32 = 1 << 0;
    const CTRL_PRIVDEFENA: u32 = 1 << 2;
    const RBAR_XN: u32 = 1 << 0;
    const RBAR_RW_ANY: u32 = 0b01 << 1;
    const RBAR_RO_ANY: u32 = 0b11 << 1;
    const RLAR_ENABLE: u32 = 1 << 0;
    /// Attribute 0: normal memory, write-back. RLAR's attribute index stays 0.
    const NORMAL_MEMORY: u32 = 0xFF;
    const LIMIT_MASK: u32 = !0x1F;

    let regions = unsafe { core::ptr::read_volatile(MPU_TYPE) >> 8 } & 0xFF;
    if regions < 2 {
        return Err(NsMpuTooSmall);
    }
    unsafe {
        core::ptr::write_volatile(MPU_CTRL, 0);
        cortex_m::asm::dsb();
        core::ptr::write_volatile(MPU_MAIR0, NORMAL_MEMORY);
        core::ptr::write_volatile(MPU_RNR, 0);
        core::ptr::write_volatile(MPU_RBAR, rx_start | RBAR_RO_ANY);
        core::ptr::write_volatile(MPU_RLAR, ((rx_end - 1) & LIMIT_MASK) | RLAR_ENABLE);
        core::ptr::write_volatile(MPU_RNR, 1);
        core::ptr::write_volatile(MPU_RBAR, NS_BASE | RBAR_RW_ANY | RBAR_XN);
        core::ptr::write_volatile(MPU_RLAR, (NS_LIMIT & LIMIT_MASK) | RLAR_ENABLE);
        core::ptr::write_volatile(MPU_CTRL, CTRL_ENABLE | CTRL_PRIVDEFENA);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
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
/// Core 1 is not held off: the power-on state machine did not report its power domain off after
/// the force-off was written.
#[derive(Debug)]
pub struct Core1NotContained;

/// How many reads of `PSM.DONE` the force-off may take to show core 1's domain off. A bounded
/// count, not a time: the domain drops within a few `clk_ref` cycles of the write.
const CORE1_OFF_READS: u32 = 1_000_000;

/// Core-1 containment. RP2350 core 1 runs only once core 0 launches it through the SIO FIFO
/// handshake, which the monitor never performs; v1 is single-core (no reviewed Secure multicore
/// design). On top of that, the power-on state machine is told to hold core 1's power domain off
/// (`PSM.FRCE_OFF.PROC1`), and the force-off is read back and the domain seen off (`PSM.DONE.PROC1`
/// clear) before the boundary is configured. A board that does not confirm both is refused here,
/// before anything Non-secure runs. Built for the RP2350; not yet run on silicon.
pub fn contain_core1() -> Result<(), Core1NotContained> {
    let psm = unsafe { &*hal::pac::PSM::ptr() };
    psm.frce_off().modify(|_, w| w.proc1().set_bit());
    cortex_m::asm::dsb();
    if psm.frce_off().read().proc1().bit_is_clear() {
        return Err(Core1NotContained);
    }
    for _ in 0..CORE1_OFF_READS {
        if psm.done().read().proc1().bit_is_clear() {
            return Ok(());
        }
    }
    Err(Core1NotContained)
}
