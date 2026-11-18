//! The board's own secret (DSM Amendment A38, owner, 2026-11-18): drawn by the board itself, inside
//! its Secure firmware, and sealed in one OTP page whose lock row is written before any row of the
//! secret. No phone or computer draws it or sees it, so the keys derived from it — the partition key
//! `pk_host` the owner's stamp names, and the chip's pairing key — exist only inside the board.
//!
//! The board seals it only when it is told to ([`seal_on_command`], `OP_SEAL_SECRET`), never because
//! it started (owner, 2026-11-18: "fix the image so it doesn't auto-write"). A boot writes nothing to
//! the page ([`read_if_sealed`]): plugging a board in changes nothing on it.
//!
//! The page goes through three lock-row values, each only setting bits of the one before (OTP bits
//! are never cleared):
//! - `0`: blank.
//! - [`SEAL_BEGUN`]: Non-secure code and the bootloader barred from the page, Secure code still
//!   writing it. Written before any row of the secret.
//! - [`SEALED`]: Secure code may only read it.
//!
//! A lock row takes effect at the next reset; for the boot that writes it the firmware advances the
//! page's software lock itself, so Non-secure code is barred before the secret is written and Secure
//! code is read-only once it is.
//!
//! What the page holds decides what is done ([`classify`]). A page sealed is read. A blank page waits
//! for the seal command, as does a page whose seal was cut after the lock row and before any row of
//! the secret. Anything else is refused for good: a page written but not locked, a seal cut after
//! some of its rows, and a lock row this procedure never writes. None of those can be told from a
//! page someone else wrote before the board ever ran, so none is ever used or completed.

/// The rows the 256-bit secret takes: sixteen ECC rows of 16 bits.
pub const SECRET_ROWS: usize = 16;

/// What a lock field allows, as the RP2350 encodes it.
pub const READ_WRITE: u32 = 0;
pub const READ_ONLY: u32 = 1;
pub const INACCESSIBLE: u32 = 3;

/// A `PAGEn_LOCK1` value: `LOCK_S` in bits 0-1, `LOCK_NS` in bits 2-3, `LOCK_BL` in bits 4-5, the byte
/// three times over for the row's majority vote.
pub const fn lock_row_value(secure: u32, non_secure: u32, bootloader: u32) -> u32 {
    (secure | (non_secure << 2) | (bootloader << 4)) * 0x0001_0101
}

/// The seal begun: Non-secure code and the bootloader barred, Secure code still writing. `0x3c3c3c`.
pub const SEAL_BEGUN: u32 = lock_row_value(READ_WRITE, INACCESSIBLE, INACCESSIBLE);
/// The seal done: Secure code may only read the page; Non-secure code and the bootloader may not.
/// `0x3d3d3d`. It only sets bits of [`SEAL_BEGUN`].
pub const SEALED: u32 = lock_row_value(READ_ONLY, INACCESSIBLE, INACCESSIBLE);

/// The 24 bits an OTP row holds.
const RAW_ROW_BITS: u32 = 0x00ff_ffff;

/// What a boot finds in the secret's page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretPage {
    /// The lock row and every row blank: the board seals its secret when it is told to.
    Blank,
    /// The seal begun and cut before any row of the secret: the board finishes it when it is told to.
    Begun,
    /// Sealed: the board reads its secret.
    Sealed,
    /// Rows written under no lock: never used, never completed.
    WrittenUnlocked,
    /// The seal begun and cut after some of its rows: never used, never completed.
    BegunWithRows,
    /// A lock row this procedure never writes.
    Foreign(u32),
}

/// What the lock row and the sixteen rows, as raw 24-bit values, say of the page.
pub fn classify(lock_row: u32, rows: &[u32; SECRET_ROWS]) -> SecretPage {
    /// Whether any row of the secret holds a bit.
    enum Rows {
        Blank,
        Written,
    }
    let lock = lock_row & RAW_ROW_BITS;
    let rows = if rows.iter().any(|row| row & RAW_ROW_BITS != 0) {
        Rows::Written
    } else {
        Rows::Blank
    };
    match (lock, rows) {
        (0, Rows::Blank) => SecretPage::Blank,
        (0, Rows::Written) => SecretPage::WrittenUnlocked,
        (SEAL_BEGUN, Rows::Blank) => SecretPage::Begun,
        (SEAL_BEGUN, Rows::Written) => SecretPage::BegunWithRows,
        (SEALED, _) => SecretPage::Sealed,
        (other, _) => SecretPage::Foreign(other),
    }
}

/// Why the OTP did not do what was asked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OtpFault {
    /// A read the page's lock does not allow, or that the hardware refused.
    Unreadable,
    /// A write the bootrom refused, with its code.
    Refused(i32),
}

/// The secret's page, as the board's Secure firmware reaches it.
pub trait SecretOtp {
    /// The page's lock row, raw.
    fn lock_row(&mut self) -> Result<u32, OtpFault>;
    /// The sixteen rows of the secret, raw (24 bits each, ECC bits included).
    fn raw_rows(&mut self) -> Result<[u32; SECRET_ROWS], OtpFault>;
    /// Write the lock row, raw. Only ever sets bits.
    fn write_lock_row(&mut self, value: u32) -> Result<(), OtpFault>;
    /// Write the sixteen rows of the secret, ECC-protected, 16 bits each.
    fn write_secret(&mut self, words: &[u16; SECRET_ROWS]) -> Result<(), OtpFault>;
    /// The sixteen rows of the secret, ECC-checked.
    fn read_secret(&mut self) -> Result<[u16; SECRET_ROWS], OtpFault>;
    /// For the rest of this boot: Non-secure code may not reach the page.
    fn bar_non_secure(&mut self);
    /// For the rest of this boot: Secure code may only read the page.
    fn make_read_only(&mut self);
}

/// Why the board has no secret to serve under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    /// Rows written under no lock.
    WrittenUnlocked,
    /// A seal cut after some of its rows.
    BegunWithRows,
    /// A lock row this procedure never writes.
    Foreign(u32),
    /// Sealed, with nothing in it.
    SealedEmpty,
    /// A seal command to a board whose secret is sealed already: nothing was written.
    AlreadySealed,
    /// The board's randomness gave nothing that passed its health tests: nothing was written.
    NoEntropy,
    /// The OTP refused a read or a write.
    Otp(OtpFault),
    /// A row read back does not hold what was written.
    ReadBack,
}

/// What a boot does with the page, which is to read it: the board's secret when the page is sealed;
/// nothing when it is blank or its seal was cut before any of its rows, and the board then waits for
/// the seal command; refused otherwise. Nothing is written.
pub fn read_if_sealed<O: SecretOtp>(otp: &mut O) -> Result<Option<[u8; 32]>, SealError> {
    let lock = otp.lock_row().map_err(SealError::Otp)?;
    let rows = otp.raw_rows().map_err(SealError::Otp)?;
    match classify(lock, &rows) {
        SecretPage::Sealed => read_sealed(otp).map(Some),
        SecretPage::Blank | SecretPage::Begun => Ok(None),
        SecretPage::WrittenUnlocked => Err(SealError::WrittenUnlocked),
        SecretPage::BegunWithRows => Err(SealError::BegunWithRows),
        SecretPage::Foreign(value) => Err(SealError::Foreign(value)),
    }
}

/// The seal, done on the seal command and at no other time: the secret drawn from `draw` and sealed
/// when the page is blank or its seal was cut before any of its rows; refused otherwise, a page
/// sealed already included. A seal writes, in order: the lock row [`SEAL_BEGUN`], read back;
/// Non-secure code barred for this boot; the sixteen rows, read back; the lock row [`SEALED`], read
/// back; Secure code read-only for this boot. `draw` runs before anything is written, so a board
/// whose randomness fails writes nothing. The secret is not handed back: the next boot reads it.
pub fn seal_on_command<O: SecretOtp>(
    otp: &mut O,
    draw: impl FnOnce() -> Option<[u8; 32]>,
) -> Result<(), SealError> {
    let lock = otp.lock_row().map_err(SealError::Otp)?;
    let rows = otp.raw_rows().map_err(SealError::Otp)?;
    match classify(lock, &rows) {
        SecretPage::Sealed => Err(SealError::AlreadySealed),
        SecretPage::Blank => seal(otp, draw, Begin::Now),
        SecretPage::Begun => seal(otp, draw, Begin::Already),
        SecretPage::WrittenUnlocked => Err(SealError::WrittenUnlocked),
        SecretPage::BegunWithRows => Err(SealError::BegunWithRows),
        SecretPage::Foreign(value) => Err(SealError::Foreign(value)),
    }
}

/// Whether the lock row still has to be set to [`SEAL_BEGUN`].
enum Begin {
    Now,
    Already,
}

fn seal<O: SecretOtp>(
    otp: &mut O,
    draw: impl FnOnce() -> Option<[u8; 32]>,
    begin: Begin,
) -> Result<(), SealError> {
    let mut secret = draw().ok_or(SealError::NoEntropy)?;
    let mut words: [u16; SECRET_ROWS] =
        core::array::from_fn(|i| u16::from_le_bytes([secret[2 * i], secret[2 * i + 1]]));
    crate::util::zeroize(&mut secret);
    let sealed = seal_words(otp, &words, begin);
    zeroize_words(&mut words);
    sealed
}

fn seal_words<O: SecretOtp>(
    otp: &mut O,
    words: &[u16; SECRET_ROWS],
    begin: Begin,
) -> Result<(), SealError> {
    if let Begin::Now = begin {
        otp.write_lock_row(SEAL_BEGUN).map_err(SealError::Otp)?;
        if otp.lock_row().map_err(SealError::Otp)? & RAW_ROW_BITS != SEAL_BEGUN {
            return Err(SealError::ReadBack);
        }
    }
    otp.bar_non_secure();
    otp.write_secret(words).map_err(SealError::Otp)?;
    let mut held = otp.read_secret().map_err(SealError::Otp)?;
    let differs = held
        .iter()
        .zip(words.iter())
        .fold(0u16, |acc, (read, written)| acc | (read ^ written));
    zeroize_words(&mut held);
    if differs != 0 {
        return Err(SealError::ReadBack);
    }
    otp.write_lock_row(SEALED).map_err(SealError::Otp)?;
    if otp.lock_row().map_err(SealError::Otp)? & RAW_ROW_BITS != SEALED {
        return Err(SealError::ReadBack);
    }
    otp.make_read_only();
    Ok(())
}

fn read_sealed<O: SecretOtp>(otp: &mut O) -> Result<[u8; 32], SealError> {
    let mut words = otp.read_secret().map_err(SealError::Otp)?;
    let empty = words.iter().fold(0u16, |all, word| all | word) == 0;
    let secret: [u8; 32] = core::array::from_fn(|i| (words[i / 2] >> (8 * (i % 2))) as u8);
    zeroize_words(&mut words);
    if empty {
        return Err(SealError::SealedEmpty);
    }
    Ok(secret)
}

fn zeroize_words(words: &mut [u16; SECRET_ROWS]) {
    for word in words.iter_mut() {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// One OTP page and its lock row, as the RP2350 holds them across boots: bits only ever set, a
    /// write refused once the boot's soft lock forbids it, and the soft lock taken from the lock row
    /// at each boot and advanced by the firmware within it. A power cut after a given number of
    /// writes stops every write after it.
    struct Page {
        lock: u32,
        rows: [u32; SECRET_ROWS],
        /// This boot's soft locks, Secure and Non-secure.
        soft_secure: u32,
        soft_non_secure: u32,
        /// What the firmware did to the page, in order.
        writes: Vec<Event>,
        /// Writes left before the power is cut.
        power: Option<usize>,
    }

    /// One thing the firmware does to the page.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Event {
        /// The lock row written with this value.
        LockRow(u32),
        /// Row `i` of the secret written.
        Row(usize),
        /// Non-secure code barred for this boot.
        BarNonSecure,
        /// Secure code read-only for this boot.
        ReadOnly,
    }

    /// What a power cut answers.
    const CUT: OtpFault = OtpFault::Refused(-1);
    /// The bootrom's refusal of a write that would clear a bit.
    const UNSUPPORTED_MODIFICATION: OtpFault = OtpFault::Refused(-18);
    /// The bootrom's refusal under the page's lock.
    const NOT_PERMITTED: OtpFault = OtpFault::Refused(-4);

    impl Page {
        fn blank() -> Self {
            let mut page = Self {
                lock: 0,
                rows: [0; SECRET_ROWS],
                soft_secure: 0,
                soft_non_secure: 0,
                writes: Vec::new(),
                power: None,
            };
            page.boot();
            page
        }

        /// A reset: the soft locks come from the lock row, and the power is back.
        fn boot(&mut self) {
            self.soft_secure = self.lock & 3;
            self.soft_non_secure = (self.lock >> 2) & 3;
            self.power = None;
        }

        fn spend_power(&mut self) -> Result<(), OtpFault> {
            match &mut self.power {
                Some(0) => Err(CUT),
                Some(left) => {
                    *left -= 1;
                    Ok(())
                }
                None => Ok(()),
            }
        }

        fn set_bits(old: &mut u32, new: u32) -> Result<(), OtpFault> {
            if *old & !new != 0 {
                return Err(UNSUPPORTED_MODIFICATION);
            }
            *old = new;
            Ok(())
        }

        /// The ECC row the bootrom writes for `word` (any injective encoding stands in for its ECC
        /// bits here: what matters is that a written row is no longer blank).
        fn ecc_row(word: u16) -> u32 {
            u32::from(word) | (u32::from(word.count_ones() as u16 % 64) << 16) | 1 << 22
        }
    }

    impl SecretOtp for Page {
        fn lock_row(&mut self) -> Result<u32, OtpFault> {
            Ok(self.lock)
        }
        fn raw_rows(&mut self) -> Result<[u32; SECRET_ROWS], OtpFault> {
            match self.soft_secure {
                INACCESSIBLE => Err(OtpFault::Unreadable),
                _ => Ok(self.rows),
            }
        }
        fn write_lock_row(&mut self, value: u32) -> Result<(), OtpFault> {
            self.spend_power()?;
            self.writes.push(Event::LockRow(value));
            Self::set_bits(&mut self.lock, value)
        }
        fn write_secret(&mut self, words: &[u16; SECRET_ROWS]) -> Result<(), OtpFault> {
            if self.soft_secure != READ_WRITE {
                return Err(NOT_PERMITTED);
            }
            for (i, word) in words.iter().enumerate() {
                self.spend_power()?;
                self.writes.push(Event::Row(i));
                Self::set_bits(&mut self.rows[i], Self::ecc_row(*word))?;
            }
            Ok(())
        }
        fn read_secret(&mut self) -> Result<[u16; SECRET_ROWS], OtpFault> {
            match self.soft_secure {
                INACCESSIBLE => Err(OtpFault::Unreadable),
                _ => Ok(core::array::from_fn(|i| (self.rows[i] & 0xffff) as u16)),
            }
        }
        fn bar_non_secure(&mut self) {
            self.writes.push(Event::BarNonSecure);
            self.soft_non_secure |= INACCESSIBLE;
        }
        fn make_read_only(&mut self) {
            self.writes.push(Event::ReadOnly);
            self.soft_secure |= READ_ONLY;
        }
    }

    /// The secret a board's randomness gives for `seed`, in these tests.
    fn secret_of(seed: u8) -> [u8; 32] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8) | 1)
    }

    fn drawn(seed: u8) -> impl FnOnce() -> Option<[u8; 32]> {
        move || Some(secret_of(seed))
    }

    #[test]
    fn the_lock_values_only_set_bits_and_are_the_scripts() {
        assert_eq!(SEAL_BEGUN, 0x3c_3c3c);
        assert_eq!(SEALED, 0x3d_3d3d);
        assert_eq!(SEALED & SEAL_BEGUN, SEAL_BEGUN, "sealing only sets bits");
    }

    /// A boot leaves a blank page as it is, however many times the board starts: it reads no secret
    /// and writes nothing. Only the seal command writes the page.
    /// MUTATION CONTROL: a boot that seals a blank page turns this red.
    #[test]
    fn a_boot_never_writes_the_page() {
        let mut page = Page::blank();
        for _boot in 0..3 {
            page.boot();
            assert_eq!(read_if_sealed(&mut page), Ok(None));
            assert!(page.writes.is_empty(), "a boot wrote the page");
            assert_eq!(classify(page.lock, &page.rows), SecretPage::Blank);
        }
        // A seal cut after its lock row waits for the command as a blank page does.
        page.power = Some(1);
        assert!(matches!(seal_on_command(&mut page, drawn(3)), Err(_cut)));
        page.boot();
        page.writes.clear();
        assert_eq!(read_if_sealed(&mut page), Ok(None));
        assert!(page.writes.is_empty(), "a boot finished a seal");
        assert_eq!(classify(page.lock, &page.rows), SecretPage::Begun);
    }

    /// The seal command seals a blank page with the secret drawn, in this order: the lock row
    /// barring Non-secure code and the bootloader, Non-secure code barred for this boot, every row of
    /// the secret, the lock row sealed, Secure code read-only for this boot; every later boot reads
    /// that secret, and a second command is refused with nothing written.
    /// MUTATION CONTROL: writing the rows before the lock row, or before Non-secure code is barred,
    /// turns this red.
    #[test]
    fn the_command_seals_a_blank_page_lock_row_first_and_every_boot_after_reads_it() {
        let mut page = Page::blank();
        let expected = secret_of(7);
        assert_eq!(seal_on_command(&mut page, drawn(7)), Ok(()));
        let order: Vec<Event> = [Event::LockRow(SEAL_BEGUN), Event::BarNonSecure]
            .into_iter()
            .chain((0..SECRET_ROWS).map(Event::Row))
            .chain([Event::LockRow(SEALED), Event::ReadOnly])
            .collect();
        assert_eq!(page.writes, order);
        assert_eq!(page.lock, SEALED);
        assert_eq!(
            page.soft_non_secure, INACCESSIBLE,
            "Non-secure barred this boot"
        );
        assert_eq!(page.soft_secure, READ_ONLY, "Secure read-only this boot");

        for _boot in 0..3 {
            page.boot();
            page.writes.clear();
            assert_eq!(
                read_if_sealed(&mut page),
                Ok(Some(expected)),
                "a later boot reads the secret"
            );
            assert_eq!(
                seal_on_command(&mut page, drawn(8)),
                Err(SealError::AlreadySealed),
                "a second command"
            );
            assert!(page.writes.is_empty(), "and nothing is written");
        }
    }

    /// A board whose randomness gives nothing writes nothing.
    #[test]
    fn no_randomness_writes_nothing() {
        let mut page = Page::blank();
        assert_eq!(
            seal_on_command(&mut page, || None),
            Err(SealError::NoEntropy)
        );
        assert!(page.writes.is_empty());
        assert_eq!(classify(page.lock, &page.rows), SecretPage::Blank);
    }

    /// A page this procedure did not leave is never used or completed: rows under no lock, a seal
    /// with some of its rows, a foreign lock value, a seal with nothing in it. Nothing is written.
    /// MUTATION CONTROL: taking any of them as blank or sealed turns this red.
    #[test]
    fn a_page_this_procedure_did_not_leave_is_refused_and_left_as_it_is() {
        let written = {
            let mut rows = [0u32; SECRET_ROWS];
            rows[3] = 0x1234;
            rows
        };
        // What a boot says of each, and what the seal command says.
        for (lock, rows, at_boot, on_command) in [
            (
                0,
                written,
                SealError::WrittenUnlocked,
                SealError::WrittenUnlocked,
            ),
            (
                SEAL_BEGUN,
                written,
                SealError::BegunWithRows,
                SealError::BegunWithRows,
            ),
            (
                0x14_1414,
                [0; SECRET_ROWS],
                SealError::Foreign(0x14_1414),
                SealError::Foreign(0x14_1414),
            ),
            (
                SEALED,
                [0; SECRET_ROWS],
                SealError::SealedEmpty,
                SealError::AlreadySealed,
            ),
        ] {
            let mut page = Page::blank();
            page.lock = lock;
            page.rows = rows;
            page.boot();
            assert_eq!(
                seal_on_command(&mut page, drawn(9)),
                Err(on_command),
                "{lock:#x}"
            );
            assert_eq!(
                read_if_sealed(&mut page).map(|_secret| ()),
                Err(at_boot),
                "{lock:#x}: a boot"
            );
            assert!(
                page.writes.is_empty(),
                "{lock:#x}: nothing done to the page"
            );
        }
    }

    /// A power cut at every write of a seal: cut before the lock row landed, the next command seals
    /// as from blank; cut after it and before any row, the next command finishes the seal with a
    /// secret it draws then; cut after any row, the page is refused for good.
    #[test]
    fn a_seal_cut_short_is_finished_only_before_its_first_row() {
        for writes_before_cut in 0..=SECRET_ROWS + 1 {
            let mut page = Page::blank();
            page.power = Some(writes_before_cut);
            assert!(
                matches!(seal_on_command(&mut page, drawn(3)), Err(_cut)),
                "cut after {writes_before_cut} writes"
            );
            page.boot();
            let after = seal_on_command(&mut page, drawn(5));
            match writes_before_cut {
                0 | 1 => {
                    assert_eq!(after, Ok(()), "cut after {writes_before_cut}");
                    page.boot();
                    assert_eq!(read_if_sealed(&mut page), Ok(Some(secret_of(5))));
                }
                _ => assert_eq!(
                    after,
                    Err(SealError::BegunWithRows),
                    "cut after {writes_before_cut}"
                ),
            }
        }
    }
}
