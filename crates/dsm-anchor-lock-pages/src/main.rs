// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM anchor **lock image**: the two page locks the burn procedure needs from page 63, written as
//! Secure code at a normal boot, for a board whose USB bootloader may not write them. The phone loads
//! it into flash and starts it once, before the lockdown; it reboots into BOOTSEL when done, and the
//! phone reads the rows back and loads the signed image again.
//!
//! An RP2350 A2's bootrom guards every OTP row by the soft lock of the page the row sits in, and a
//! page's lock row sits in page 62 or 63 (`s_varm_api_hx_otp_access`, `pico-bootrom-rp2350` tag `A2`;
//! the A3 and A4 bootroms guard a lock row by the page it locks). In BOOTSEL a page's soft lock is its
//! Secure lock advanced by its bootloader lock (`s_otp_advance_bl_to_s_value`, the only soft-lock
//! write in the bootrom); at a normal boot it is the Secure lock alone. The yellow board's page 63
//! lock row holds `0x141414`: its bootloader may not write page 63, its Secure code may
//! (CONFORMANCE_GAPS §6.158, 2026-11-11).
//!
//! It writes two rows and nothing else, to the board or the chip:
//! - the digest page's lock (`PAGE46_LOCK1`), once the digest is burned: locked before, the page
//!   would refuse the bootloader the digest itself;
//! - the rollback page's lock (`PAGE44_LOCK1`), whose Secure field stays read-write, so the bootrom's
//!   own rollback writes at a secure boot go on.
//!
//! Each only where it holds no bit outside the value the procedure burns there, through the bootrom's
//! own `otp_access`. What became of each is kept in [`DSM_LOCK_PAGES_OUTCOME`] for a debug probe; the
//! phone does not need it, as it reads the rows themselves.

#![no_std]
#![no_main]

use rp235x_hal as hal;

/// The boot block: a Secure Arm executable, which the bootrom runs from flash on a board whose secure
/// boot is not yet enabled. This image is never signed, so a locked-down board never runs it.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

const PAGE_ROWS: usize = 64;
/// Page 46, row 0: the Non-secure app's digest, sixteen rows. MUST equal `DIGEST_ROW` in
/// `dsm-android-anchor` and `provision-otp.sh`.
const DIGEST_ROW: usize = 46 * PAGE_ROWS;
const DIGEST_ROWS: usize = 16;
const DIGEST_PAGE: usize = 46;
/// The page whose rows hold the rollback version. MUST equal `ROLLBACK_ROW`'s page in `sign.sh`.
const ROLLBACK_PAGE: usize = 44;

/// `PAGEn_LOCK1`, in page 62 or 63.
const fn lock1(page: usize) -> usize {
    0xf80 + 2 * page + 1
}

const READ_WRITE: u32 = 0;
const READ_ONLY: u32 = 1;
const INACCESSIBLE: u32 = 3;

/// A `PAGEn_LOCK1` value: `LOCK_S` in bits 0-1, `LOCK_NS` in bits 2-3, `LOCK_BL` in bits 4-5, the byte
/// three times over for the row's majority vote.
const fn lock_row_value(secure: u32, non_secure: u32, bootloader: u32) -> u32 {
    (secure | (non_secure << 2) | (bootloader << 4)) * 0x0001_0101
}

/// MUST equal `DIGEST_LOCK` in `dsm-android-anchor` and `provision-otp.sh`.
const DIGEST_LOCK: u32 = lock_row_value(READ_ONLY, INACCESSIBLE, READ_ONLY);
/// MUST equal `ROLLBACK_LOCK` in `dsm-android-anchor` and `provision-otp.sh`.
const ROLLBACK_LOCK: u32 = lock_row_value(READ_WRITE, READ_ONLY, READ_ONLY);

/// `otp_access`'s command word: the row in bits 0-15, a write at bit 16 (`OTP_CMD_WRITE_BITS`).
const OTP_CMD_WRITE: u32 = 0x0001_0000;
const RAW_ROW_MASK: u32 = 0x00ff_ffff;

/// `reboot`'s flags into BOOTSEL (`REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL`), and its second parameter: no
/// BOOTSEL interface disabled, so the phone finds PICOBOOT there.
const REBOOT_TYPE_BOOTSEL: u32 = 0x0002;
const BOOTSEL_ALL_INTERFACES: u32 = 0;
const REBOOT_DELAY_MS: u32 = 500;

/// What became of a lock row, as [`DSM_LOCK_PAGES_OUTCOME`] keeps it.
#[derive(Clone, Copy)]
#[repr(u32)]
enum Outcome {
    Written = 1,
    AlreadyHeld = 2,
    /// It holds bits outside the value: not written.
    HoldsOtherBits = 3,
    /// The digest is not burned: its page is not locked.
    DigestBlank = 4,
    /// The row could not be read.
    Unreadable = 5,
    /// `otp_access` refused the write.
    Refused = 6,
    /// Read back after the write, it does not hold the value.
    ReadBackDiffers = 7,
}

/// For a debug probe: what became of the digest page's lock, the rollback page's lock, and the
/// reboot's own status (`0` until it is asked for, then the bootrom's answer). Not read by the phone.
#[no_mangle]
pub static mut DSM_LOCK_PAGES_OUTCOME: [u32; 3] = [0; 3];

fn keep(slot: usize, word: u32) {
    // SAFETY: one core, no interrupt enabled; the record is written here only.
    unsafe {
        let record = core::ptr::addr_of_mut!(DSM_LOCK_PAGES_OUTCOME);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*record)[slot]), word);
    }
}

fn read_raw(row: usize) -> Option<u32> {
    match hal::otp::read_raw_word(row) {
        Ok(word) => Some(word & RAW_ROW_MASK),
        Err(_unreadable) => None,
    }
}

/// One lock row set to `value`: never where it holds a bit outside `value`, and read back after.
fn lock_row(row: usize, value: u32) -> Outcome {
    let Some(old) = read_raw(row) else {
        return Outcome::Unreadable;
    };
    if old == value {
        return Outcome::AlreadyHeld;
    }
    if old & !value != 0 {
        return Outcome::HoldsOtherBits;
    }
    let Ok(command) = u32::try_from(row) else {
        return Outcome::Unreadable;
    };
    let mut word = value;
    // SAFETY: Secure, at a normal boot; `word` is one aligned raw row for the bootrom to read, and
    // lives for the call.
    let rc = unsafe {
        hal::rom_data::otp_access(
            core::ptr::addr_of_mut!(word).cast(),
            4,
            command | OTP_CMD_WRITE,
        )
    };
    if rc != 0 {
        return Outcome::Refused;
    }
    match read_raw(row) {
        Some(now) if now == value => Outcome::Written,
        Some(_other) => Outcome::ReadBackDiffers,
        None => Outcome::Unreadable,
    }
}

/// Whether the digest is burned: any of its sixteen rows holds a bit. A row that cannot be read
/// counts as not shown burned.
fn digest_burned() -> bool {
    (DIGEST_ROW..DIGEST_ROW + DIGEST_ROWS).any(|row| read_raw(row).is_some_and(|word| word != 0))
}

/// Into BOOTSEL, where the phone reads the rows back. A refused reboot is kept, and the board waits
/// for a replug with BOOTSEL held.
fn back_to_bootsel() -> ! {
    let status = hal::rom_data::reboot(
        REBOOT_TYPE_BOOTSEL,
        REBOOT_DELAY_MS,
        0,
        BOOTSEL_ALL_INTERFACES,
    );
    keep(2, status as u32);
    loop {
        core::hint::spin_loop();
    }
}

#[hal::entry]
fn main() -> ! {
    let digest = if digest_burned() {
        lock_row(lock1(DIGEST_PAGE), DIGEST_LOCK)
    } else {
        Outcome::DigestBlank
    };
    keep(0, digest as u32);
    keep(1, lock_row(lock1(ROLLBACK_PAGE), ROLLBACK_LOCK) as u32);
    back_to_bootsel()
}

/// A panic goes back to BOOTSEL too, where the phone reads what the rows hold.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    back_to_bootsel()
}
