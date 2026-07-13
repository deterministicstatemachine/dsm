// SPDX-License-Identifier: MIT OR Apache-2.0
//! RP2350 secure-boot enforcement + OTP-sealed host-key material (feature = `secure-boot`).
//!
//! This is the production profile that REALIZES the paper's σ^host claim (`DSM_Software_Authority_
//! Hardware_Identity` §5/§7, Thm 4): the RP2350 partition (host) signing key is derived from a
//! secret that lives ONLY in OTP, provisioned with secure-read permission, and the firmware refuses
//! to enroll or serve unless secure boot + debug-disable are actually latched. Without this feature
//! the firmware runs the BENCH profile, whose partition key is an honest label derived from the
//! (public) chip identity — deterministic and chip-unique but NOT a silicon secret, so it is never a
//! production anchor and its bundle is domain-separated from any production bundle.
//!
//! ## Why this closes the "modified firmware can produce σ^host" gap
//!
//! - **Measurement gate = secure boot itself.** The RP2350 bootrom verifies the running image's
//!   hash against the enrolled signing key BEFORE executing it (RP2350 datasheet §5, secure boot).
//!   We sign ONLY the exact enrolled build, so `secure_boot_enabled()` transitively means "the
//!   image the bootrom just measured equals the enrolled firmware." Rogue/modified firmware is not
//!   signed by the enrolled key, so the bootrom will not run it.
//! - **Sealed host secret.** The host-key seed lives in an OTP page provisioned with secure-read
//!   permission (readable only by the enrolled secure firmware). Unsigned firmware cannot boot to
//!   read it; a read from a wrong-permission context returns `InvalidPermissions`. So a party that
//!   lacks the appliance (no chip, no OTP) cannot derive σ^host, and modified firmware on the
//!   appliance cannot either.
//! - **Fail-closed.** Every step here returns `Err` on any doubt; the caller halts. A production
//!   build NEVER serves the appliance on a device where secure boot / debug-disable are not latched,
//!   or where the OTP host secret is unprovisioned.
//!
//! The one-way OTP provisioning (boot-key fingerprint, `SECURE_BOOT_ENABLE`, debug-disable, the
//! host-secret page + its read permission) is performed by `scripts/anchor-secure-boot/` on the
//! physical board — it is irreversible and cannot run off-device. See that directory's RUNBOOK.

use rp235x_hal as hal;

/// OTP ECC row where the 256-bit sealed host-key secret begins. 32 bytes = 16 ECC rows (16 bits
/// each via [`hal::otp::read_ecc_word`]). MUST match `scripts/anchor-secure-boot/provision-otp.sh`.
///
/// This page is reserved for the DSM anchor host secret and provisioned with secure-read
/// permission. The exact free-page choice MUST be confirmed against the device OTP map
/// (`picotool otp list`) at provisioning — a collision with a bootrom/system page is rejected there.
pub const HOST_SECRET_ROW: usize = 48 * hal::otp::NUM_ROWS_PER_PAGE; // page 48, row 0

/// Number of ECC rows the 256-bit host secret occupies.
pub const HOST_SECRET_ROWS: usize = 16;

/// Assert the device is in a real secure-boot context. Fail-closed: returns `Err` unless secure
/// boot is enabled AND debug is disabled AND the ARM core (the one we run on) is not disabled.
/// This is the measurement gate — secure boot means the bootrom verified the running image against
/// the enrolled signing key, so only the enrolled firmware reaches this code.
pub fn assert_secure_context() -> Result<(), &'static str> {
    let crit = hal::rom_data::sys_info_api::otp_critical_register()
        .map_err(|_| "otp_critical_register call failed")?
        .ok_or("otp_critical_register unsupported by bootrom")?;
    if !crit.secure_boot_enabled() {
        return Err("secure boot not enabled in OTP (production firmware refuses to run)");
    }
    if !crit.debug_disabled() {
        return Err("debug not disabled in OTP (production firmware refuses to run)");
    }
    if crit.arm_disabled() {
        return Err("ARM core disabled in OTP");
    }
    Ok(())
}

/// Read the 256-bit OTP-sealed host-key secret. Fail-closed on any permission-denied row (this
/// context may not read the secret) or if the page is blank (unprovisioned). The returned secret is
/// the birth seed for `σ^host` — it replaces the public "honest label" the bench profile uses.
pub fn read_sealed_host_secret() -> Result<[u8; 32], &'static str> {
    let mut out = [0u8; 32];
    let mut nonzero = false;
    for i in 0..HOST_SECRET_ROWS {
        let word = hal::otp::read_ecc_word(HOST_SECRET_ROW + i)
            .map_err(|_| "sealed host secret: OTP read denied (permission or unreadable)")?;
        out[i * 2] = (word & 0x00ff) as u8;
        out[i * 2 + 1] = ((word >> 8) & 0x00ff) as u8;
        nonzero |= word != 0;
    }
    if !nonzero {
        return Err("sealed host secret: OTP page blank (unprovisioned)");
    }
    Ok(out)
}
