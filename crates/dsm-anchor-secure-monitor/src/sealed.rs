// SPDX-License-Identifier: MIT OR Apache-2.0
//! The secret only this board holds, and the boot context the appliance requires before it reads it.
//!
//! The sealed secret is 256 bits in an RP2350 OTP page that the board seals itself (DSM Amendment
//! A38, owner, 2026-11-18): the production image draws it from the board's TRNG and writes it with
//! the page's lock row first (`anchor_core::seal`), so no phone or computer ever draws it or sees
//! it. It does that only when the seal command asks (`OP_SEAL_SECRET`), never because it started
//! (owner, 2026-11-18: "fix the image so it doesn't auto-write"): a boot reads the page and writes
//! nothing. Every secret the appliance's identity needs derives from it: the
//! pairing key the TROPIC01 is opened with, the σ^host partition key seed and the birth entropy. None
//! derives from data the chip reports to anyone who asks.

use anchor_core::seal::{OtpFault, SecretOtp, SecretPage, SECRET_ROWS};
use rp235x_hal as hal;

/// The page the board seals its own secret in: 49. Page 48 held a secret drawn on a computer by an
/// earlier procedure on the boards burned before A38, and is never read. MUST match
/// `SECRET_PAGE` in `dsm-android-anchor` and `scripts/anchor-secure-boot/provision-otp.sh`.
pub const SEALED_SECRET_PAGE: usize = 49;

/// OTP ECC row where the sealed secret begins: page 49, row 0.
pub const SEALED_SECRET_ROW: usize = SEALED_SECRET_PAGE * hal::otp::NUM_ROWS_PER_PAGE;

/// ECC rows the 256-bit secret occupies (16 bits each).
#[cfg(feature = "bench_self_enroll")]
pub const SEALED_SECRET_ROWS: usize = SECRET_ROWS;

/// The page's lock row, `PAGE49_LOCK1`, in page 63.
const SEALED_SECRET_LOCK_ROW: usize = 0xf80 + 2 * SEALED_SECRET_PAGE + 1;
/// The page whose soft lock guards a lock row on an A2 bootrom: the page the row sits in.
const LOCK_ROWS_PAGE: usize = 63;

/// `otp_access`'s command word: the row in bits 0-15, a write at bit 16 (`OTP_CMD_WRITE_BITS`), ECC
/// at bit 17 (`OTP_CMD_ECC_BITS`, pico-sdk `bootrom_constants.h`).
const OTP_CMD_WRITE: u32 = 0x0001_0000;
const OTP_CMD_ECC: u32 = 0x0002_0000;
/// The 24 bits a raw OTP row holds.
const RAW_ROW_MASK: u32 = 0x00ff_ffff;

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
    #[cfg(feature = "bench_self_enroll")]
    Unreadable(usize, hal::otp::Error),
    /// The OTP page was never provisioned.
    #[cfg(feature = "bench_self_enroll")]
    Unprovisioned,
    /// The board's secret page is one it may never use, or the seal command did not finish.
    #[cfg(not(feature = "bench_self_enroll"))]
    Seal(anchor_core::seal::SealError),
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
            #[cfg(feature = "bench_self_enroll")]
            Self::Unreadable(row, cause) => write!(f, "OTP row {row} unreadable: {cause:?}"),
            #[cfg(feature = "bench_self_enroll")]
            Self::Unprovisioned => write!(f, "the sealed secret's OTP page was never provisioned"),
            #[cfg(not(feature = "bench_self_enroll"))]
            Self::Seal(cause) => write!(f, "the board's own secret, OTP page 49: {cause:?}"),
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

/// The sealed secret, as the trial, prepare and identify images look at it: refused when this context
/// may not read the page, or when the page was never provisioned. They never use it.
#[cfg(feature = "bench_self_enroll")]
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

#[cfg(feature = "bench_self_enroll")]
fn read_rows(words: &mut [u16; SEALED_SECRET_ROWS]) -> Result<(), SealedError> {
    for (i, word) in words.iter_mut().enumerate() {
        let row = SEALED_SECRET_ROW + i;
        *word = hal::otp::read_ecc_word(row).map_err(|e| SealedError::Unreadable(row, e))?;
    }
    Ok(())
}

/// Page 49 as the board's Secure firmware reaches it: raw reads and the bootrom's own writes.
struct SecretPage49;

fn raw_row(row: usize) -> Result<u32, OtpFault> {
    hal::otp::read_raw_word(row)
        .map(|word| word & RAW_ROW_MASK)
        .map_err(|_unreadable| OtpFault::Unreadable)
}

impl SecretOtp for SecretPage49 {
    fn lock_row(&mut self) -> Result<u32, OtpFault> {
        raw_row(SEALED_SECRET_LOCK_ROW)
    }

    fn raw_rows(&mut self) -> Result<[u32; SECRET_ROWS], OtpFault> {
        let mut rows = [0u32; SECRET_ROWS];
        for (i, row) in rows.iter_mut().enumerate() {
            *row = raw_row(SEALED_SECRET_ROW + i)?;
        }
        Ok(rows)
    }

    fn write_lock_row(&mut self, value: u32) -> Result<(), OtpFault> {
        let mut word = value;
        // SAFETY: Secure, at a normal boot; `word` is one aligned raw row for the bootrom to read,
        // and lives for the call.
        let rc = unsafe {
            hal::rom_data::otp_access(
                core::ptr::addr_of_mut!(word).cast(),
                4,
                SEALED_SECRET_LOCK_ROW as u32 | OTP_CMD_WRITE,
            )
        };
        match rc {
            0 => Ok(()),
            refused => Err(OtpFault::Refused(refused)),
        }
    }

    fn write_secret(&mut self, words: &[u16; SECRET_ROWS]) -> Result<(), OtpFault> {
        let mut buffer = *words;
        // SAFETY: Secure, at a normal boot; `buffer` is sixteen aligned 16-bit values, one per ECC
        // row from the page's first, and lives for the call.
        let rc = unsafe {
            hal::rom_data::otp_access(
                buffer.as_mut_ptr().cast(),
                2 * SECRET_ROWS,
                SEALED_SECRET_ROW as u32 | OTP_CMD_WRITE | OTP_CMD_ECC,
            )
        };
        for word in buffer.iter_mut() {
            // SAFETY: a valid, aligned, exclusive reference.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        match rc {
            0 => Ok(()),
            refused => Err(OtpFault::Refused(refused)),
        }
    }

    fn read_secret(&mut self) -> Result<[u16; SECRET_ROWS], OtpFault> {
        let mut words = [0u16; SECRET_ROWS];
        for (i, word) in words.iter_mut().enumerate() {
            *word = hal::otp::read_ecc_word(SEALED_SECRET_ROW + i)
                .map_err(|_unreadable| OtpFault::Unreadable)?;
        }
        Ok(words)
    }

    fn bar_non_secure(&mut self) {
        // SAFETY: Secure code owns the OTP block; writes to SW_LOCK49 are OR'd into its state.
        let otp = unsafe { &*hal::pac::OTP::ptr() };
        otp.sw_lock49()
            .write(|w| unsafe { w.bits(anchor_core::seal::INACCESSIBLE << 2) });
    }

    fn make_read_only(&mut self) {
        // SAFETY: as in `bar_non_secure`.
        let otp = unsafe { &*hal::pac::OTP::ptr() };
        otp.sw_lock49()
            .write(|w| unsafe { w.bits(anchor_core::seal::READ_ONLY) });
    }
}

/// The board's own secret (DSM Amendment A38) as a boot finds it, with nothing written: read when
/// page 49 is sealed; none when the page is blank or its seal was cut before any row, and the board
/// then waits for the seal command; refused for good otherwise
/// (`anchor_core::seal::read_if_sealed`).
#[cfg(not(feature = "bench_self_enroll"))]
pub fn read_secret_if_sealed() -> Result<Option<[u8; 32]>, SealedError> {
    anchor_core::seal::read_if_sealed(&mut SecretPage49).map_err(SealedError::Seal)
}

/// The seal command's one act: the secret drawn from `draw` and sealed in page 49, lock row first,
/// for good (`anchor_core::seal::seal_on_command`). Nothing else in this image writes the page.
#[cfg(not(feature = "bench_self_enroll"))]
pub fn seal_secret(draw: impl FnOnce() -> Option<[u8; 32]>) -> Result<(), SealedError> {
    anchor_core::seal::seal_on_command(&mut SecretPage49, draw).map_err(SealedError::Seal)
}

/// Whether page 49 takes the board's own secret, read with nothing written: blank, or a seal cut
/// before any row, with Secure code free to write the page and its lock row (on an A2 bootrom page
/// 63's soft lock guards the lock row; on A3 and A4 the page's own); or sealed already. What a
/// try-run reports before anything is burned.
pub fn secret_page_takes_a_seal(silicon_revision: u8) -> Result<(), alloc::string::String> {
    use alloc::format;
    let mut page = SecretPage49;
    let lock = page
        .lock_row()
        .map_err(|e| format!("page 49's lock row: {e:?}"))?;
    let rows = page.raw_rows().map_err(|e| format!("page 49: {e:?}"))?;
    match anchor_core::seal::classify(lock, &rows) {
        SecretPage::Sealed => Ok(()),
        SecretPage::Blank | SecretPage::Begun => {
            // SAFETY: a read of the OTP block's soft-lock registers.
            let otp = unsafe { &*hal::pac::OTP::ptr() };
            let page_lock = otp.sw_lock49().read().sec().bits();
            let lock_row_lock = if silicon_revision == 2 {
                otp.sw_lock63().read().sec().bits()
            } else {
                page_lock
            };
            if page_lock != 0 || lock_row_lock != 0 {
                return Err(format!(
                    "Secure code may not write page 49 (its soft lock {page_lock}) or its lock row \
                     (soft lock {lock_row_lock}, page {LOCK_ROWS_PAGE} on A2)"
                ));
            }
            Ok(())
        }
        other => Err(format!(
            "page 49 holds what this procedure never leaves ({other:?}); a production board refuses it"
        )),
    }
}
