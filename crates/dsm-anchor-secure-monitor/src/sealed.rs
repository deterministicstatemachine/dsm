// SPDX-License-Identifier: MIT OR Apache-2.0
//! The secret only this board holds, and the boot context the appliance requires before it reads it.
//!
//! The sealed secret is 256 bits in an RP2350 OTP page provisioned with secure-read permission
//! (`scripts/anchor-secure-boot`, provisioned once per board). Every
//! secret the appliance's identity needs derives from it: the pairing key the TROPIC01 is opened
//! with, the σ^host partition key seed and the birth entropy. None derives from data the chip
//! reports to anyone who asks.

use rp235x_hal as hal;

/// OTP ECC row where the sealed secret begins: page 48, row 0. MUST match
/// `scripts/anchor-secure-boot/provision-otp.sh`.
pub const SEALED_SECRET_ROW: usize = 48 * hal::otp::NUM_ROWS_PER_PAGE;

/// ECC rows the 256-bit secret occupies (16 bits each).
pub const SEALED_SECRET_ROWS: usize = 16;

/// Why the appliance will not read its sealed secret.
pub enum SealedError {
    /// The bootrom refused the critical-register query.
    #[cfg(any(
        feature = "production",
        all(feature = "bench_self_enroll", not(feature = "identify_chip"))
    ))]
    Bootrom(hal::rom_data::BootRomApiErrorCode),
    /// This bootrom does not report the critical register.
    #[cfg(any(
        feature = "production",
        all(feature = "bench_self_enroll", not(feature = "identify_chip"))
    ))]
    Unreported,
    #[cfg(feature = "production")]
    SecureBootDisabled,
    #[cfg(feature = "production")]
    DebugEnabled,
    #[cfg(feature = "production")]
    ArmDisabled,
    /// The OTP row could not be read from this context.
    Unreadable(usize, hal::otp::Error),
    /// The OTP page was never provisioned.
    Unprovisioned,
    /// A board locked for production, a finished unit: the trial image and the prepare image stand
    /// down on it. What its secret page holds decides nothing; neither image uses or writes the page.
    #[cfg(all(feature = "bench_self_enroll", not(feature = "identify_chip")))]
    AlreadySealed,
}

impl core::fmt::Debug for SealedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(any(
                feature = "production",
                all(feature = "bench_self_enroll", not(feature = "identify_chip"))
            ))]
            Self::Bootrom(code) => write!(f, "bootrom: {code:?}"),
            #[cfg(any(
                feature = "production",
                all(feature = "bench_self_enroll", not(feature = "identify_chip"))
            ))]
            Self::Unreported => write!(f, "the bootrom does not report the critical register"),
            #[cfg(feature = "production")]
            Self::SecureBootDisabled => write!(f, "secure boot is not enabled in OTP"),
            #[cfg(feature = "production")]
            Self::DebugEnabled => write!(f, "debug is not disabled in OTP"),
            #[cfg(feature = "production")]
            Self::ArmDisabled => write!(f, "the ARM core is disabled in OTP"),
            Self::Unreadable(row, cause) => write!(f, "OTP row {row} unreadable: {cause:?}"),
            Self::Unprovisioned => write!(f, "the sealed secret's OTP page was never provisioned"),
            #[cfg(all(feature = "bench_self_enroll", not(feature = "identify_chip")))]
            Self::AlreadySealed => {
                write!(
                    f,
                    "this board is locked for production, and this image stands down on it"
                )
            }
        }
    }
}

/// The boot is the enrolled image's: secure boot enabled, debug disabled, the ARM core enabled.
#[cfg(feature = "production")]
pub fn assert_secure_context() -> Result<(), SealedError> {
    let crit = hal::rom_data::sys_info_api::otp_critical_register()
        .map_err(SealedError::Bootrom)?
        .ok_or(SealedError::Unreported)?;
    if !crit.secure_boot_enabled() {
        return Err(SealedError::SecureBootDisabled);
    }
    if !crit.debug_disabled() {
        return Err(SealedError::DebugEnabled);
    }
    if crit.arm_disabled() {
        return Err(SealedError::ArmDisabled);
    }
    Ok(())
}

/// Whether this board boots only signed images: secure boot enabled in OTP, as on every finished unit.
#[cfg(all(feature = "bench_self_enroll", not(feature = "identify_chip")))]
pub fn locked_for_production() -> Result<bool, SealedError> {
    let crit = hal::rom_data::sys_info_api::otp_critical_register()
        .map_err(SealedError::Bootrom)?
        .ok_or(SealedError::Unreported)?;
    Ok(crit.secure_boot_enabled())
}

/// The sealed secret. Refused when this context may not read the page, or when the page was never
/// provisioned: an appliance without its secret has no identity to serve under.
pub fn read_sealed_secret() -> Result<[u8; 32], SealedError> {
    let mut words = [0u16; SEALED_SECRET_ROWS];
    let secret = read_rows(&mut words).and_then(|()| {
        if words.iter().fold(0u16, |all, word| all | word) == 0 {
            return Err(SealedError::Unprovisioned);
        }
        Ok(core::array::from_fn(|i| {
            (words[i / 2] >> (8 * (i % 2))) as u8
        }))
    });
    for word in words.iter_mut() {
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    secret
}

fn read_rows(words: &mut [u16; SEALED_SECRET_ROWS]) -> Result<(), SealedError> {
    for (i, word) in words.iter_mut().enumerate() {
        let row = SEALED_SECRET_ROW + i;
        *word = hal::otp::read_ecc_word(row).map_err(|e| SealedError::Unreadable(row, e))?;
    }
    Ok(())
}
