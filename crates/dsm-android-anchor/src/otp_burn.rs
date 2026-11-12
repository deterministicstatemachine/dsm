// SPDX-License-Identifier: MIT OR Apache-2.0
//! A board's one-time burns, from the phone: the runbook's steps and `provision-otp.sh`'s checks, row
//! for row, through the board's own USB bootloader ([`crate::picoboot`]). Owner, 2026-11-11: "Not
//! everyone has a Mac. It has to be doable from the phone", with the phone driving the bootloader.
//!
//! What a board holds is read from its OTP every time ([`Standing`]), never remembered by the phone,
//! so a step cut short is found where it stopped. Every write is read back before its step is done:
//! for the rows picotool's JSON load writes (the boot key's hash, the lockdown flags) that is more
//! than picotool does.
//!
//! One departure from the script, for a board whose secret page is blank: the phone writes the
//! secret and locks its page in one step. The script locks it at Step 6, and its own Step 6 stops on
//! a page written and not yet locked; a page left so between steps is also one another procedure
//! could have written. A page found written and unlocked therefore stops here, as the script says
//! of any page it did not seal. The boards in hand were sealed by an earlier procedure, and their
//! secrets are kept.

use crate::picoboot::{BootselError, BootselLink, Picoboot, NOT_PERMITTED, RAW_ROW_MASK};
use crate::release::{Release, FLASH_BASE};

/// Rows in an OTP page, and pages in the OTP.
pub const PAGE_ROWS: u16 = 64;
pub const PAGES: u16 = 64;
pub const ROWS: u16 = PAGES * PAGE_ROWS;
/// The last pages, whose permissions the bootloader applies row by row: picotool reads them so.
const SPECIAL_PAGES: u16 = 3;

/// Page 48, row 0: the board's sealed secret. MUST equal `SEALED_SECRET_ROW` in the monitor.
pub const SECRET_ROW: u16 = 48 * PAGE_ROWS;
/// Page 46, row 0: the Non-secure app's digest. MUST equal `MU_ROW` in the monitor.
pub const DIGEST_ROW: u16 = 46 * PAGE_ROWS;
/// Page 44, rows 0-2: the rollback version. MUST equal `ROLLBACK_ROW` in sign.sh.
pub const ROLLBACK_ROW: u16 = 44 * PAGE_ROWS;
const ROLLBACK_ROWS: u16 = 3;
/// Rows 0x80-0x8f: boot key 0's SHA-256, two bytes a row, with error correction.
pub const BOOTKEY0_ROW: u16 = 0x80;
/// A 32-byte value in rows with error correction: sixteen rows.
const HASH_ROWS: u16 = 16;
/// `CRIT1`, kept eight times over (RBIT-8).
pub const CRIT1_ROW: u16 = 0x40;
const CRIT1_COPIES: u16 = 8;
/// `BOOT_FLAGS0` and `BOOT_FLAGS1`, each kept three times over (RBIT-3).
pub const BOOT_FLAGS0_ROW: u16 = 0x48;
pub const BOOT_FLAGS1_ROW: u16 = 0x4b;
const FLAG_COPIES: u16 = 3;

/// `CRIT1.SECURE_BOOT_ENABLE` (bit 0) and `CRIT1.DEBUG_DISABLE` (bit 2): what the lockdown sets.
const CRIT1_LOCKDOWN: u32 = (1 << 0) | (1 << 2);
/// `BOOT_FLAGS1.KEY_VALID` (bits 0-3) and `KEY_INVALID` (bits 8-11): boot key 0 valid, keys 1-3
/// invalid, so no other key can be installed later.
const KEY_FLAGS_MASK: u32 = 0x0f0f;
const KEY_FLAGS: u32 = 0x1 | (0xe << 8);
/// `BOOT_FLAGS0.ROLLBACK_REQUIRED` (bit 11): set by the first boot of a signed image, which records
/// its rollback version. The boot pages are locked only after it.
const ROLLBACK_REQUIRED: u32 = 1 << 11;

/// `PAGEn_LOCK0` and `PAGEn_LOCK1`.
#[must_use]
pub const fn lock0(page: u16) -> u16 {
    0xf80 + 2 * page
}
#[must_use]
pub const fn lock1(page: u16) -> u16 {
    0xf80 + 2 * page + 1
}

/// A lock field's values: 0x1 bars writes and 0x2 reads.
pub const READ_WRITE: u32 = 0;
pub const READ_ONLY: u32 = 1;
pub const INACCESSIBLE: u32 = 3;

/// A `PAGEn_LOCK1` value: `LOCK_S` in bits 0-1, `LOCK_NS` in bits 2-3, `LOCK_BL` in bits 4-5, the byte
/// three times over for the row's majority vote. Built from its fields, never written out.
#[must_use]
pub const fn lock_row_value(secure: u32, non_secure: u32, bootloader: u32) -> u32 {
    let byte = secure | (non_secure << 2) | (bootloader << 4);
    byte * 0x0001_0101
}
/// Secure reads and nothing writes; Non-secure and the bootloader have no access.
pub const SECRET_LOCK: u32 = lock_row_value(READ_ONLY, INACCESSIBLE, INACCESSIBLE);
/// Secure reads; the bootloader may read back the digest, which is public; Non-secure has no access.
pub const DIGEST_LOCK: u32 = lock_row_value(READ_ONLY, INACCESSIBLE, READ_ONLY);
/// The boot configuration and boot key pages: everyone reads, nothing writes.
pub const BOOT_PAGES_LOCK: u32 = lock_row_value(READ_ONLY, READ_ONLY, READ_ONLY);
/// The rollback version: the bootrom, running Secure, goes on writing it; the bootloader may not.
pub const ROLLBACK_LOCK: u32 = lock_row_value(READ_WRITE, READ_ONLY, READ_ONLY);

/// Where the bootrom names itself in ROM: `'M'`, `'u'`, the RP2350's `2`, then the version byte, "the
/// value 2 for A2 silicon, 3 for A3 silicon, and 4 for A4 silicon" (RP2350 datasheet). The bootloader
/// serves ROM reads below its secure gateway; picotool reads the same header.
pub const BOOTROM_HEADER: u32 = 0x10;
const RP2350_BOOTROM: [u8; 3] = [b'M', b'u', 2];

/// Which page's lock the bootloader applies to an OTP row, by the bootrom's own rule
/// (`s_varm_api_hx_otp_access` in `pico-bootrom-rp2350`), which changed between steppings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard {
    /// The A2 bootrom: every row by the page it sits in, a lock row in pages 62-63 included. A lock
    /// row there can be written only while page 62 or 63 itself can.
    PageItSitsIn,
    /// The A3 and A4 bootroms: a lock row by the page it locks, every other row by its own page.
    PageItLocks,
}

/// The board's bootrom, read from its ROM: its version byte and the guard rule it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bootrom {
    pub version: u8,
    pub guard: Guard,
}

impl Bootrom {
    pub fn read<L: BootselLink>(pb: &mut Picoboot<L>) -> Result<Self, String> {
        let header = pb.read(BOOTROM_HEADER, 4).map_err(|e| e.to_string())?;
        let [m, u, family, version] = header.as_slice() else {
            return Err(format!(
                "the bootrom's header read back {} bytes, not 4",
                header.len()
            ));
        };
        if [*m, *u, *family] != RP2350_BOOTROM {
            return Err("the board's ROM does not name itself an RP2350's bootrom".to_string());
        }
        let guard = match version {
            2 => Guard::PageItSitsIn,
            3 | 4 => Guard::PageItLocks,
            other => {
                let known = "the A2, A3 and A4 bootroms";
                return Err(format!(
                    "the bootrom's version byte is {other}: which page guards a lock row is known \
                     for {known} only"
                ));
            }
        };
        Ok(Self {
            version: *version,
            guard,
        })
    }

    /// The page whose lock the bootloader applies to `row`.
    #[must_use]
    pub fn guarding_page(self, row: u16) -> u16 {
        let page = row / PAGE_ROWS;
        match self.guard {
            Guard::PageItLocks if page >= 62 => (row - lock0(0)) / 2,
            Guard::PageItLocks | Guard::PageItSitsIn => page,
        }
    }

    /// What this bootrom's rule is, as the person reads it.
    #[must_use]
    pub fn words(self) -> String {
        match self.guard {
            Guard::PageItSitsIn => format!(
                "this board's bootrom is A{} (its version byte): it guards a page's lock row by \
                 the page the row sits in, 62 or 63",
                self.version
            ),
            Guard::PageItLocks => format!(
                "this board's bootrom is A{} (its version byte): it guards a page's lock row by \
                 the page the row locks",
                self.version
            ),
        }
    }
}

/// Each bit as most of a lock row's three bytes hold it: how OTP keeps a lock, so that its bits can
/// be set one at a time.
fn by_majority(row: u32) -> u32 {
    let (a, b, c) = (row & 0xff, (row >> 8) & 0xff, (row >> 16) & 0xff);
    (a & b) | (b & c) | (a & c)
}

/// `KEY_W` (bits 0-2) and `KEY_R` (bits 3-5) of `PAGEn_LOCK0`: an access key registered for the page.
const ACCESS_KEYS: u32 = 0x3f;

/// What a page's locks leave the bootloader, as the bootrom sets them on entering BOOTSEL: the page's
/// Secure lock advanced by its bootloader lock (`s_otp_advance_bl_to_s_value`), bit 0 barring writes
/// and bit 1 reads. A page with an access key registered takes no write from the bootloader, which
/// holds no key.
pub struct BootloaderAccess {
    pub page: u16,
    lock: u32,
    keys: u32,
}

impl BootloaderAccess {
    pub fn of(otp: &OtpReading, page: u16) -> Result<Self, String> {
        let row = |r: u16| {
            otp.row(r).ok_or_else(|| {
                format!("page {page}'s lock row {r:#05x} cannot be read through the bootloader")
            })
        };
        Ok(Self {
            page,
            lock: row(lock1(page))?,
            keys: row(lock0(page))?,
        })
    }

    fn held(&self) -> u32 {
        let lock = by_majority(self.lock);
        (lock & 0x3) | ((lock >> 4) & 0x3)
    }

    #[must_use]
    pub fn may_write(&self) -> bool {
        self.held() & 0x1 == 0 && by_majority(self.keys) & ACCESS_KEYS == 0
    }

    /// Whether Secure code at a normal boot may write the page: there nothing advances a soft lock,
    /// so it is the page's Secure lock alone (`LOCK_S`), with no access key registered. What the
    /// lock image (`dsm-anchor-lock-pages`) writes through.
    #[must_use]
    pub fn secure_may_write(&self) -> bool {
        by_majority(self.lock) & 0x1 == 0 && by_majority(self.keys) & ACCESS_KEYS == 0
    }

    /// The page's lock rows and what they leave the bootloader.
    #[must_use]
    pub fn words(&self) -> String {
        let reach = if by_majority(self.keys) & ACCESS_KEYS != 0 {
            "an access key is registered for it: the bootloader may not write it"
        } else {
            match self.held() {
                0 => "the bootloader may read and write it",
                1 => "the bootloader may read it and not write it",
                2 => "the bootloader may write it and not read it",
                _neither => "the bootloader may not read or write it",
            }
        };
        format!(
            "page {}'s lock rows {:#05x} and {:#05x} hold {:#x} and {:#x}: {reach}",
            self.page,
            lock0(self.page),
            lock1(self.page),
            self.keys,
            self.lock
        )
    }
}

/// The OTP as the bootloader shows it: each row's 24 raw bits, or nothing where a lock keeps the
/// row from the bootloader.
pub struct OtpReading {
    rows: Vec<Option<u32>>,
    /// The pages the bootloader refused to read (their lock keeps them from it).
    pub unreadable_pages: Vec<u16>,
}

impl OtpReading {
    /// Every row, page by page and the last pages row by row, as `picotool otp dump -r` reads them.
    pub fn read<L: BootselLink>(pb: &mut Picoboot<L>) -> Result<Self, BootselError> {
        let mut rows = vec![None; usize::from(ROWS)];
        let mut unreadable_pages = Vec::new();
        for page in 0..PAGES - SPECIAL_PAGES {
            let first = page * PAGE_ROWS;
            match pb.otp_read_raw(first, PAGE_ROWS) {
                Ok(words) => {
                    for (i, word) in words.iter().enumerate() {
                        rows[usize::from(first) + i] = Some(word & RAW_ROW_MASK);
                    }
                }
                Err(BootselError::Refused {
                    status: NOT_PERMITTED,
                    ..
                }) => unreadable_pages.push(page),
                Err(e) => return Err(e),
            }
        }
        for row in (PAGES - SPECIAL_PAGES) * PAGE_ROWS..ROWS {
            match pb.otp_read_raw(row, 1) {
                Ok(words) => rows[usize::from(row)] = words.first().map(|w| w & RAW_ROW_MASK),
                Err(BootselError::Refused {
                    status: NOT_PERMITTED,
                    ..
                }) => {
                    let page = row / PAGE_ROWS;
                    if !unreadable_pages.contains(&page) {
                        unreadable_pages.push(page);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Self {
            rows,
            unreadable_pages,
        })
    }

    /// From rows the caller holds: a reading taken elsewhere, as the tests give one.
    #[must_use]
    pub fn from_rows(rows: Vec<Option<u32>>, unreadable_pages: Vec<u16>) -> Self {
        Self {
            rows,
            unreadable_pages,
        }
    }

    /// A row's 24 bits, if the bootloader may read it.
    #[must_use]
    pub fn row(&self, row: u16) -> Option<u32> {
        self.rows.get(usize::from(row)).copied().flatten()
    }

    fn rows_in(&self, first: u16, count: u16) -> Result<Vec<u32>, String> {
        (first..first + count)
            .map(|r| {
                self.row(r)
                    .ok_or_else(|| format!("row {r:#05x} cannot be read through the bootloader"))
            })
            .collect()
    }
}

/// What the board's secret page holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretPage {
    /// Nothing, and its lock row unburned.
    Blank,
    /// A secret, burned and locked exactly as this procedure seals one: the board keeps it.
    Sealed,
}

/// The secret page, read fresh: blank or sealed, and anything else stops the procedure, as
/// `provision-otp.sh`'s `secret_page` does. The lock row decides: once it holds the sealed value the
/// bootloader has no access to the page, so its rows say nothing here.
pub fn secret_page(otp: &OtpReading) -> Result<SecretPage, String> {
    let lock = otp
        .row(lock1(48))
        .ok_or("the secret page's lock row cannot be read through the bootloader")?;
    if lock == SECRET_LOCK {
        return Ok(SecretPage::Sealed);
    }
    let rows = otp.rows_in(SECRET_ROW, HASH_ROWS)?;
    let written: Vec<String> = (SECRET_ROW..SECRET_ROW + HASH_ROWS)
        .zip(&rows)
        .filter(|(_, v)| **v != 0)
        .map(|(r, _)| format!("{r:#05x}"))
        .collect();
    if written.is_empty() && lock == 0 {
        return Ok(SecretPage::Blank);
    }
    Err(format!(
        "the secret page is neither blank nor sealed as this procedure seals it: rows written \
         {written:?}, lock row {lock:#x} (expected 0 or {SECRET_LOCK:#x}). Another procedure wrote \
         this board, or a secret was written and never locked; nothing here goes on with it"
    ))
}

/// What the read-only check found, beyond the board being blank where the procedure writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlankBoard {
    pub secret: SecretPage,
    /// Lock rows already holding bits, every one of them within what the procedure burns there.
    pub locks_already_set: Vec<String>,
}

/// Step 0, READ-ONLY: every row the procedure writes is still zero, except a secret page an earlier
/// procedure sealed as this one seals it; and every lock row it burns holds no bit outside what it
/// burns there. `provision-otp.sh --check-blank`, row for row.
pub fn check_blank(otp: &OtpReading) -> Result<BlankBoard, String> {
    let secret = secret_page(otp)?;
    let mut watched: Vec<(&str, Vec<u16>)> = vec![
        ("digest", (DIGEST_ROW..DIGEST_ROW + HASH_ROWS).collect()),
        (
            "boot key 0",
            (BOOTKEY0_ROW..BOOTKEY0_ROW + HASH_ROWS).collect(),
        ),
        ("CRIT1", (CRIT1_ROW..CRIT1_ROW + CRIT1_COPIES).collect()),
        (
            "BOOT_FLAGS1",
            (BOOT_FLAGS1_ROW..BOOT_FLAGS1_ROW + FLAG_COPIES).collect(),
        ),
        (
            "rollback version",
            (ROLLBACK_ROW..ROLLBACK_ROW + ROLLBACK_ROWS).collect(),
        ),
        (
            "BOOT_FLAGS0",
            (BOOT_FLAGS0_ROW..BOOT_FLAGS0_ROW + FLAG_COPIES).collect(),
        ),
        (
            "page locks' access keys",
            vec![lock0(1), lock0(2), lock0(44), lock0(46), lock0(48)],
        ),
    ];
    let mut locks: Vec<(&str, u16, u32)> = vec![
        ("boot configuration page lock", lock1(1), BOOT_PAGES_LOCK),
        ("boot key page lock", lock1(2), BOOT_PAGES_LOCK),
        ("rollback page lock", lock1(44), ROLLBACK_LOCK),
        ("digest page lock", lock1(46), DIGEST_LOCK),
    ];
    if secret == SecretPage::Blank {
        watched.push((
            "sealed secret",
            (SECRET_ROW..SECRET_ROW + HASH_ROWS).collect(),
        ));
        locks.push(("secret page lock", lock1(48), SECRET_LOCK));
    }
    let mut used = Vec::new();
    for (name, span) in &watched {
        let mut found = Vec::new();
        for row in span {
            match otp.row(*row) {
                Some(0) => {}
                Some(value) => found.push(format!("{row:#05x}={value:#x}")),
                None => found.push(format!("{row:#05x} unreadable")),
            }
        }
        if !found.is_empty() {
            used.push(format!("{name}: {}", found.join(", ")));
        }
    }
    for (name, row, burned) in &locks {
        match otp.row(*row) {
            Some(value) if value & !burned & RAW_ROW_MASK != 0 => used.push(format!(
                "{name}: {row:#05x} holds {value:#x}, bits outside the {burned:#x} this procedure burns"
            )),
            Some(_within) => {}
            None => used.push(format!("{name}: {row:#05x} unreadable")),
        }
    }
    if !used.is_empty() {
        return Err(format!(
            "this board is not blank where the procedure writes: {}",
            used.join("; ")
        ));
    }
    let locks_already_set = locks
        .iter()
        .filter_map(|(name, row, burned)| {
            otp.row(*row).filter(|v| *v != 0).map(|v| {
                format!(
                    "{name} already holds {v:#x}, all of it within the {burned:#x} this procedure \
                     burns there"
                )
            })
        })
        .collect();
    Ok(BlankBoard {
        secret,
        locks_already_set,
    })
}

/// A 32-byte value kept in sixteen rows with error correction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash32 {
    Blank,
    Holds([u8; 32]),
}

/// Where a board stands, read from its OTP: what of the procedure is burned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Standing {
    pub secret: SecretPage,
    pub digest: Hash32,
    pub digest_page_locked: bool,
    pub boot_key: Hash32,
    pub locked_down: bool,
    /// The signed image has booted once and recorded its rollback version.
    pub rollback_recorded: bool,
    pub boot_pages_locked: bool,
}

fn hash_rows<L: BootselLink>(
    pb: &mut Picoboot<L>,
    otp: &OtpReading,
    first: u16,
) -> Result<Hash32, String> {
    // A row whose 16 data bits are zero reads zero raw too, so a value with a zero word is not "partly
    // written": what the rows hold is read through the error correction and compared whole by
    // `next`, which stops on anything but the release's value, a burn cut short included.
    let raw = otp.rows_in(first, HASH_ROWS)?;
    if raw.iter().all(|r| *r == 0) {
        return Ok(Hash32::Blank);
    }
    let bytes = pb
        .otp_read_ecc(first, HASH_ROWS)
        .map_err(|e| e.to_string())?;
    let value: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_short| format!("{} bytes read for 32", bytes.len()))?;
    Ok(Hash32::Holds(value))
}

/// The value a redundant row's copies agree on, all of them; copies that differ stop the procedure.
fn copies_agree(otp: &OtpReading, first: u16, copies: u16) -> Result<u32, String> {
    let values = otp.rows_in(first, copies)?;
    match values.first() {
        Some(v) if values.iter().all(|c| c == v) => Ok(*v),
        _ => Err(format!(
            "the copies of row {first:#05x} differ ({values:x?}): a burn there was cut short"
        )),
    }
}

/// A row the bootrom writes and reads by majority (RBIT-3): each bit as most of its copies hold it.
fn majority(otp: &OtpReading, first: u16, copies: u16) -> Result<u32, String> {
    let values = otp.rows_in(first, copies)?;
    Ok((0..24).fold(0u32, |value, bit| {
        let set = values.iter().filter(|v| **v & (1 << bit) != 0).count();
        if set * 2 > values.len() {
            value | (1 << bit)
        } else {
            value
        }
    }))
}

/// A lock row holds every bit the procedure burns there.
fn lock_holds(otp: &OtpReading, row: u16, burned: u32) -> Result<bool, String> {
    let value = otp
        .row(row)
        .ok_or_else(|| format!("lock row {row:#05x} cannot be read through the bootloader"))?;
    Ok(value & burned == burned)
}

impl Standing {
    pub fn read<L: BootselLink>(pb: &mut Picoboot<L>, otp: &OtpReading) -> Result<Self, String> {
        let crit1 = copies_agree(otp, CRIT1_ROW, CRIT1_COPIES)?;
        // `BOOT_FLAGS0` is the bootrom's to write (its first signed boot sets `ROLLBACK_REQUIRED`), and
        // it reads the row by majority; so does this.
        let flags0 = majority(otp, BOOT_FLAGS0_ROW, FLAG_COPIES)?;
        let rollback = otp.rows_in(ROLLBACK_ROW, ROLLBACK_ROWS)?;
        Ok(Self {
            secret: secret_page(otp)?,
            digest: hash_rows(pb, otp, DIGEST_ROW)?,
            digest_page_locked: lock_holds(otp, lock1(46), DIGEST_LOCK)?,
            boot_key: hash_rows(pb, otp, BOOTKEY0_ROW)?,
            locked_down: crit1 & CRIT1_LOCKDOWN == CRIT1_LOCKDOWN,
            rollback_recorded: flags0 & ROLLBACK_REQUIRED != 0 && rollback.iter().any(|r| *r != 0),
            boot_pages_locked: lock_holds(otp, lock1(1), BOOT_PAGES_LOCK)?
                && lock_holds(otp, lock1(2), BOOT_PAGES_LOCK)?
                && lock_holds(otp, lock1(44), ROLLBACK_LOCK)?,
        })
    }
}

/// The one-time burns, in the runbook's order. Step 3, loading the signed image, is not a burn: it
/// is flash, and comes before them ([`load_image`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Burn {
    /// Step 4 with the secret half of Step 6: a blank board's secret, written and locked.
    SealSecret,
    /// Step 5: the Non-secure app's digest, page 46.
    WriteDigest,
    /// Step 6: the digest page locked.
    LockDigestPage,
    /// Step 7: boot key 0's hash.
    WriteBootKey,
    /// Step 8: secure boot on, debug off, boot key 0 valid and keys 1-3 invalid. LAST before boot.
    Lockdown,
    /// Step 9b: the boot configuration and boot key pages read-only, the rollback page closed to the
    /// bootloader. Only after the signed image has booted once.
    LockBootPages,
}

/// What a board needs next, from where it stands and the release it is to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// A burn, the next in order.
    Burn(Burn),
    /// Step 9: reboot into the signed image, so its first boot records its rollback version. The
    /// board comes back as the anchor; Step 9b needs it in BOOTSEL again.
    Boot,
    /// Every burn is done: the board goes on to its install from the wallet.
    Done,
}

/// The next step for a board that stands so, burned toward `release`. A value burned that is not the
/// release's stops the procedure: it is another release's board.
pub fn next(standing: &Standing, release: &Release) -> Result<Next, String> {
    if standing.secret == SecretPage::Blank {
        return Ok(Next::Burn(Burn::SealSecret));
    }
    match standing.digest {
        Hash32::Blank => return Ok(Next::Burn(Burn::WriteDigest)),
        Hash32::Holds(d) if d != release.digest => {
            return Err(
                "this board's firmware digest is not this release's: it was burned for another \
                 Non-secure app"
                    .to_string(),
            )
        }
        Hash32::Holds(_ours) => {}
    }
    if !standing.digest_page_locked {
        return Ok(Next::Burn(Burn::LockDigestPage));
    }
    match standing.boot_key {
        Hash32::Blank => return Ok(Next::Burn(Burn::WriteBootKey)),
        Hash32::Holds(k) if k != release.boot_key_hash => {
            return Err(
                "this board's boot key is not the one this release is signed with".to_string(),
            )
        }
        Hash32::Holds(_ours) => {}
    }
    if !standing.locked_down {
        return Ok(Next::Burn(Burn::Lockdown));
    }
    if !standing.rollback_recorded {
        return Ok(Next::Boot);
    }
    if !standing.boot_pages_locked {
        return Ok(Next::Burn(Burn::LockBootPages));
    }
    Ok(Next::Done)
}

/// The burns in the runbook's order.
const BURNS: [Burn; 6] = [
    Burn::SealSecret,
    Burn::WriteDigest,
    Burn::LockDigestPage,
    Burn::WriteBootKey,
    Burn::Lockdown,
    Burn::LockBootPages,
];

/// The burns a board standing so still needs, in order: none once every one is done.
pub fn burns_left(standing: &Standing, release: &Release) -> Result<Vec<Burn>, String> {
    Ok(match next(standing, release)? {
        Next::Burn(first) => BURNS.iter().copied().skip_while(|b| *b != first).collect(),
        Next::Boot => vec![Burn::LockBootPages],
        Next::Done => Vec::new(),
    })
}

/// The lock rows a burn sets, each with the value it burns there.
fn lock_rows(burn: Burn) -> Vec<(u16, u32)> {
    match burn {
        Burn::SealSecret => vec![(lock1(48), SECRET_LOCK)],
        Burn::LockDigestPage => vec![(lock1(46), DIGEST_LOCK)],
        Burn::LockBootPages => vec![
            (lock1(1), BOOT_PAGES_LOCK),
            (lock1(2), BOOT_PAGES_LOCK),
            (lock1(44), ROLLBACK_LOCK),
        ],
        Burn::WriteDigest | Burn::WriteBootKey | Burn::Lockdown => Vec::new(),
    }
}

/// The OTP rows a burn writes.
fn rows_written(burn: Burn) -> Vec<u16> {
    match burn {
        Burn::SealSecret => (SECRET_ROW..SECRET_ROW + HASH_ROWS)
            .chain([lock1(48)])
            .collect(),
        Burn::WriteDigest => (DIGEST_ROW..DIGEST_ROW + HASH_ROWS).collect(),
        Burn::WriteBootKey => (BOOTKEY0_ROW..BOOTKEY0_ROW + HASH_ROWS).collect(),
        Burn::Lockdown => (BOOT_FLAGS1_ROW..BOOT_FLAGS1_ROW + FLAG_COPIES)
            .chain(CRIT1_ROW..CRIT1_ROW + CRIT1_COPIES)
            .collect(),
        Burn::LockDigestPage | Burn::LockBootPages => lock_rows(burn)
            .into_iter()
            .map(|(row, _value)| row)
            .collect(),
    }
}

/// The rows a burn will write on a board that reads so: a lock row that already holds the value the
/// burn sets there is not written again ([`set_raw_row`]), so it needs no write access.
fn rows_to_write(burn: Burn, otp: &OtpReading) -> Vec<u16> {
    let held = lock_rows(burn);
    rows_written(burn)
        .into_iter()
        .filter(|row| {
            !held
                .iter()
                .any(|(lock, value)| lock == row && otp.row(*row) == Some(*value))
        })
        .collect()
}

/// The lock rows the lock image writes (`dsm-anchor-lock-pages`) and the values it writes there:
/// the digest page's lock, once the digest is burned, and the rollback page's. MUST equal its own.
pub const LOCK_IMAGE_ROWS: [(u16, u32); 2] = [(lock1(46), DIGEST_LOCK), (lock1(44), ROLLBACK_LOCK)];

/// A row the procedure has left to write that this board's bootloader may not write.
pub struct Barred {
    pub burn: Burn,
    pub row: u16,
    /// The page whose lock guards it.
    pub page: u16,
    words: String,
}

/// The rows `burns` will write that this board's bootloader may not, page by page as its bootrom
/// guards them.
pub fn barred_rows(
    otp: &OtpReading,
    bootrom: Bootrom,
    burns: &[Burn],
) -> Result<Vec<Barred>, String> {
    let mut barred = Vec::new();
    for burn in burns {
        for row in rows_to_write(*burn, otp) {
            let page = bootrom.guarding_page(row);
            let access = BootloaderAccess::of(otp, page)?;
            if !access.may_write() {
                let by = if page == row / PAGE_ROWS {
                    "the page it sits in"
                } else {
                    "the page it locks"
                };
                barred.push(Barred {
                    burn: *burn,
                    row,
                    page,
                    words: format!(
                        "{burn:?} writes row {row:#05x}, which this bootrom guards by page {page}, \
                         {by}; {}",
                        access.words()
                    ),
                });
            }
        }
    }
    Ok(barred)
}

/// Why the procedure cannot be finished from BOOTSEL: each burn and page once.
#[must_use]
pub fn barred_words(barred: &[Barred]) -> String {
    let mut lines: Vec<&str> = Vec::new();
    let mut seen: Vec<(Burn, u16)> = Vec::new();
    for b in barred {
        if !seen.contains(&(b.burn, b.page)) {
            seen.push((b.burn, b.page));
            lines.push(&b.words);
        }
    }
    format!(
        "this board's bootloader cannot write every row the procedure has left to burn, so the \
         procedure cannot be finished from BOOTSEL and nothing more is burned: {}",
        lines.join("; ")
    )
}

/// Every row `burns` write is one this board's bootloader may write, page by page as its bootrom
/// guards them. Checked for every burn left before the first of them runs, so no procedure starts
/// that cannot be finished, and for each burn's own rows before it writes one, so no step stops
/// part-written. Found on the yellow board, 2026-11-11: its A2 bootrom refused the digest page's
/// lock row, which sits in page 63, after the digest itself was burned.
pub fn bootloader_may_write(
    otp: &OtpReading,
    bootrom: Bootrom,
    burns: &[Burn],
) -> Result<(), String> {
    let barred = barred_rows(otp, bootrom, burns)?;
    if barred.is_empty() {
        return Ok(());
    }
    Err(barred_words(&barred))
}

/// Whether the lock image can write every barred row in the bootloader's place: each is a row it
/// writes, in a page whose Secure lock lets Secure code write it at a normal boot. The bootrom guards
/// a Secure write by the same page rule; at a normal boot nothing advances the soft lock.
pub fn lock_image_covers(
    otp: &OtpReading,
    bootrom: Bootrom,
    barred: &[Barred],
) -> Result<bool, String> {
    let mut covered = Vec::new();
    for b in barred {
        let image_writes = LOCK_IMAGE_ROWS.iter().any(|(row, _value)| *row == b.row);
        let secure = BootloaderAccess::of(otp, bootrom.guarding_page(b.row))?.secure_may_write();
        covered.push(image_writes && secure);
    }
    Ok(covered.iter().all(|c| *c))
}

/// What a burn wrote and read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Burned {
    pub burn: Burn,
    /// Each write, as `row: value`, confirmed by its read-back.
    pub rows: Vec<String>,
}

/// One raw row set, as `picotool otp set -r`: the bits already there stay, none is cleared, and the
/// row is read back holding the new value.
fn set_raw_row<L: BootselLink>(
    pb: &mut Picoboot<L>,
    row: u16,
    value: u32,
) -> Result<String, String> {
    let old = read_raw_row(pb, row)?;
    // Set already, by the lock image or an earlier procedure: nothing to write, and the bootloader
    // may not be allowed to write it anyway.
    if old == value & RAW_ROW_MASK {
        return Ok(format!("{row:#05x}: {old:#08x}, already held"));
    }
    if old & !value & RAW_ROW_MASK != 0 {
        return Err(format!(
            "row {row:#05x} holds {old:#x}: writing {value:#x} would clear bits, which OTP cannot"
        ));
    }
    pb.otp_write_raw(row, &[value]).map_err(|e| e.to_string())?;
    let now = read_raw_row(pb, row)?;
    if now != value & RAW_ROW_MASK {
        return Err(format!(
            "row {row:#05x} reads {now:#x} after writing {value:#x}: stop, and do not go on"
        ));
    }
    Ok(format!("{row:#05x}: {now:#08x}"))
}

fn read_raw_row<L: BootselLink>(pb: &mut Picoboot<L>, row: u16) -> Result<u32, String> {
    let words = pb.otp_read_raw(row, 1).map_err(|e| e.to_string())?;
    words
        .first()
        .map(|w| w & RAW_ROW_MASK)
        .ok_or_else(|| format!("row {row:#05x} read back nothing"))
}

/// A redundant row's every copy set to the fields the procedure burns there, keeping the bits its
/// first copy already holds outside those fields: picotool's JSON load, and then each copy read back.
fn set_redundant_row<L: BootselLink>(
    pb: &mut Picoboot<L>,
    row: u16,
    copies: u16,
    fields: u32,
    mask: u32,
) -> Result<String, String> {
    let old = read_raw_row(pb, row)?;
    let value = fields | (old & !mask & RAW_ROW_MASK);
    let all = vec![value; usize::from(copies)];
    pb.otp_write_raw(row, &all).map_err(|e| e.to_string())?;
    let now = pb.otp_read_raw(row, copies).map_err(|e| e.to_string())?;
    if now.iter().any(|w| w & RAW_ROW_MASK != value) {
        return Err(format!(
            "row {row:#05x}'s {copies} copies read {now:x?} after writing {value:#x}: stop, and do \
             not go on"
        ));
    }
    Ok(format!("{row:#05x} x{copies}: {value:#08x}"))
}

/// 32 bytes into sixteen blank rows with error correction, as `picotool otp load -e`, and read back
/// through the same error correction.
fn write_hash<L: BootselLink>(
    pb: &mut Picoboot<L>,
    row: u16,
    value: &[u8; 32],
) -> Result<String, String> {
    pb.otp_write_ecc(row, value).map_err(|e| e.to_string())?;
    let back = pb.otp_read_ecc(row, HASH_ROWS).map_err(|e| e.to_string())?;
    if back.as_slice() != value.as_slice() {
        return Err(format!(
            "rows {row:#05x}.. read back other than the 32 bytes written: stop, and do not go on"
        ));
    }
    Ok(format!("{row:#05x}..{:#05x}: 32 bytes", row + HASH_ROWS))
}

/// Burn one step, only the one the board needs next ([`next`]), and read back every row it wrote.
/// `secret` is the phone's own random source, drawn from only by [`Burn::SealSecret`]; what it gives
/// is never kept: once locked, the board holds the only copy.
pub fn burn<L: BootselLink>(
    pb: &mut Picoboot<L>,
    release: &Release,
    step: Burn,
    secret: impl FnOnce() -> Result<[u8; 32], String>,
) -> Result<Burned, String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    let standing = Standing::read(pb, &otp)?;
    match next(&standing, release)? {
        Next::Burn(due) if due == step => {}
        due => {
            return Err(format!(
                "{step:?} is not this board's next step: it needs {due:?}"
            ))
        }
    }
    bootloader_may_write(&otp, Bootrom::read(pb)?, &[step])?;
    let rows = match step {
        Burn::SealSecret => {
            check_blank(&otp)?;
            let drawn = secret()?;
            vec![
                write_hash(pb, SECRET_ROW, &drawn)?,
                set_raw_row(pb, lock1(48), SECRET_LOCK)?,
            ]
        }
        // The first burn on a board whose secret is sealed: Step 0's check stands before it.
        Burn::WriteDigest => {
            check_blank(&otp)?;
            require_image(pb, release)?;
            vec![write_hash(pb, DIGEST_ROW, &release.digest)?]
        }
        Burn::LockDigestPage => vec![set_raw_row(pb, lock1(46), DIGEST_LOCK)?],
        Burn::WriteBootKey => vec![write_hash(pb, BOOTKEY0_ROW, &release.boot_key_hash)?],
        // picotool's order: BOOT_FLAGS1 (the key valid) before CRIT1 (secure boot on), so the flag
        // that makes signatures matter is never set while no key is valid.
        Burn::Lockdown => vec![
            set_redundant_row(pb, BOOT_FLAGS1_ROW, FLAG_COPIES, KEY_FLAGS, KEY_FLAGS_MASK)?,
            set_redundant_row(pb, CRIT1_ROW, CRIT1_COPIES, CRIT1_LOCKDOWN, CRIT1_LOCKDOWN)?,
        ],
        Burn::LockBootPages => vec![
            set_raw_row(pb, lock1(1), BOOT_PAGES_LOCK)?,
            set_raw_row(pb, lock1(2), BOOT_PAGES_LOCK)?,
            set_raw_row(pb, lock1(44), ROLLBACK_LOCK)?,
        ],
    };
    Ok(Burned { burn: step, rows })
}

/// Flash is erased in 4 KiB sectors and written in 256-byte pages.
pub const SECTOR: usize = 4096;
pub const PAGE: usize = 256;

/// An image's bytes as flash holds them from its first byte: padded with zeros to whole pages, as
/// picotool leaves them.
fn padded(image: &[u8]) -> Vec<u8> {
    let mut image = image.to_vec();
    image.resize(image.len().div_ceil(PAGE) * PAGE, 0);
    image
}

/// The release's image in flash ([`padded`]).
fn padded_image(release: &Release) -> Vec<u8> {
    padded(&release.image)
}

/// Bytes into flash from its first byte, erased first in whole sectors, then read back whole.
fn write_flash<L: BootselLink>(pb: &mut Picoboot<L>, image: &[u8]) -> Result<(), String> {
    let erase = u32::try_from(image.len().div_ceil(SECTOR) * SECTOR)
        .map_err(|_too_long| "an image larger than flash".to_string())?;
    pb.exclusive().map_err(|e| e.to_string())?;
    pb.exit_xip().map_err(|e| e.to_string())?;
    pb.flash_erase(FLASH_BASE, erase)
        .map_err(|e| e.to_string())?;
    for (i, chunk) in image.chunks(SECTOR).enumerate() {
        let offset = u32::try_from(i * SECTOR).map_err(|_far| "an image larger than flash")?;
        pb.write(FLASH_BASE + offset, chunk)
            .map_err(|e| e.to_string())?;
    }
    match first_difference(pb, image)? {
        None => Ok(()),
        Some(at) => Err(format!(
            "the flash reads back other than written at {at:#010x}: stop, and do not go on"
        )),
    }
}

/// Step 3: the signed image into flash, then read back whole. Flash, not OTP: it can be loaded again
/// at any time, and after the lockdown only a signed image boots.
pub fn load_image<L: BootselLink>(pb: &mut Picoboot<L>, release: &Release) -> Result<(), String> {
    write_flash(pb, &padded_image(release))
}

/// The lock image (`dsm-anchor-lock-pages`, its flash bytes from the app) loaded into flash, read
/// back whole, and started. It sets the page locks this board's bootloader may not write, as Secure
/// code at a normal boot, and reboots into BOOTSEL; the caller reads the rows back
/// ([`lock_image_rows`]) once the board is back, and loads the signed image again. Only where it is
/// the board's next step: the digest burned, its page not yet locked, and so before the lockdown
/// (after it only a signed image boots, and this one is never signed); and only on a board whose
/// barred rows it covers ([`lock_image_covers`]).
pub fn boot_lock_image<L: BootselLink>(
    pb: &mut Picoboot<L>,
    release: &Release,
    lock_image: &[u8],
) -> Result<(), String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    let standing = Standing::read(pb, &otp)?;
    match next(&standing, release)? {
        Next::Burn(Burn::LockDigestPage) => {}
        due => {
            return Err(format!(
                "the lock image runs once the digest is burned and before its page is locked: this \
                 board needs {due:?}"
            ))
        }
    }
    let bootrom = Bootrom::read(pb)?;
    let barred = barred_rows(&otp, bootrom, &burns_left(&standing, release)?)?;
    if barred.is_empty() {
        return Err(
            "this board's bootloader may write every row the procedure has left: it needs no lock \
             image"
                .to_string(),
        );
    }
    if !lock_image_covers(&otp, bootrom, &barred)? {
        return Err(barred_words(&barred));
    }
    write_flash(pb, &padded(lock_image))?;
    pb.reboot_normal().map_err(|e| e.to_string())
}

/// An image the app carries for a board's first burn to wait on (the prepare image or the trial
/// image, their flash bytes from the app) loaded into flash, read back whole, and started. Only on a
/// board whose digest is blank and which is not locked down: neither image is signed, and the trial
/// image refuses a board whose digest is burned. Flash only, on the board: Step 3 loads the signed
/// image over it.
pub fn boot_before_the_digest<L: BootselLink>(
    pb: &mut Picoboot<L>,
    image: &[u8],
) -> Result<(), String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    let standing = Standing::read(pb, &otp)?;
    if standing.digest != Hash32::Blank || standing.locked_down {
        return Err(
            "this image runs only on a board whose firmware digest is not yet burned and which is \
             not locked down: nothing was written"
                .to_string(),
        );
    }
    write_flash(pb, &padded(image))?;
    pb.reboot_normal().map_err(|e| e.to_string())
}

/// After the lock image, back in BOOTSEL: each row it writes, read back holding its value.
pub fn lock_image_rows<L: BootselLink>(pb: &mut Picoboot<L>) -> Result<Vec<String>, String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    LOCK_IMAGE_ROWS
        .iter()
        .map(|(row, value)| match otp.row(*row) {
            Some(now) if now == *value => Ok(format!(
                "{row:#05x}: {now:#08x}, set by the lock image and read back"
            )),
            Some(now) => Err(format!(
                "the lock image did not set row {row:#05x}: it holds {now:#x}, not {value:#x}"
            )),
            None => Err(format!(
                "row {row:#05x} cannot be read through the bootloader"
            )),
        })
        .collect()
}

/// Where the changed image differs from the release's: one byte inside the code, which the signature
/// covers, well past the image's first block, which the bootrom must still find to judge the image.
const CHANGED_AT: usize = 0x1000;

/// The release's image with one byte of its code changed: an image not as signed.
fn changed_image(release: &Release) -> Result<Vec<u8>, String> {
    let mut image = padded_image(release);
    let byte = image
        .get_mut(CHANGED_AT)
        .ok_or("the image is too short to change a byte of its code")?;
    *byte ^= 0xff;
    Ok(image)
}

/// Step 9's check, after the lockdown and before the first boot: an image not as signed loaded and
/// booted. A board whose secure boot is in force refuses it, finds no image it may run, and comes
/// back in BOOTSEL; the caller sees which way the board came back, and loads the signed image again
/// ([`load_image`]). Flash only: what it changes is undone by that load.
pub fn boot_changed_image<L: BootselLink>(
    pb: &mut Picoboot<L>,
    release: &Release,
) -> Result<(), String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    let standing = Standing::read(pb, &otp)?;
    match next(&standing, release)? {
        Next::Boot => {}
        due => {
            return Err(format!(
                "the changed-image check comes after the lockdown and before the first boot: this \
                 board needs {due:?}"
            ))
        }
    }
    write_flash(pb, &changed_image(release)?)?;
    pb.reboot_normal().map_err(|e| e.to_string())
}

/// What the board's flash holds, against the release's image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnBoard {
    /// The release's image, read back whole.
    Release,
    /// Something else, from this address on.
    Differs { at: u32 },
}

/// The board's flash read back over `image`: the address of the first sector that differs, if one
/// does. A link failure is an error, never a difference. Execute-in-place is left first, as picotool
/// leaves it before every flash read: in BOOTSEL a read through it does not give the flash's bytes.
fn first_difference<L: BootselLink>(
    pb: &mut Picoboot<L>,
    image: &[u8],
) -> Result<Option<u32>, String> {
    pb.exit_xip().map_err(|e| e.to_string())?;
    for (i, chunk) in image.chunks(SECTOR).enumerate() {
        let offset = u32::try_from(i * SECTOR).map_err(|_far| "an image larger than flash")?;
        let len = u32::try_from(chunk.len()).map_err(|_long| "a chunk larger than flash")?;
        let back = pb
            .read(FLASH_BASE + offset, len)
            .map_err(|e| e.to_string())?;
        if back.as_slice() != chunk {
            return Ok(Some(FLASH_BASE + offset));
        }
    }
    Ok(None)
}

/// The board's flash, read back over the release's image.
pub fn image_on_board<L: BootselLink>(
    pb: &mut Picoboot<L>,
    release: &Release,
) -> Result<OnBoard, String> {
    Ok(match first_difference(pb, &padded_image(release))? {
        None => OnBoard::Release,
        Some(at) => OnBoard::Differs { at },
    })
}

/// The release's image must be in the board's flash before what depends on it.
fn require_image<L: BootselLink>(pb: &mut Picoboot<L>, release: &Release) -> Result<(), String> {
    match image_on_board(pb, release)? {
        OnBoard::Release => Ok(()),
        OnBoard::Differs { at } => Err(format!(
            "the board's flash differs from the release's image at {at:#010x}: load the image first"
        )),
    }
}

/// Step 9: reboot into the signed image.
pub fn boot<L: BootselLink>(pb: &mut Picoboot<L>, release: &Release) -> Result<(), String> {
    let otp = OtpReading::read(pb).map_err(|e| e.to_string())?;
    let standing = Standing::read(pb, &otp)?;
    match next(&standing, release)? {
        Next::Boot => {}
        due => {
            return Err(format!(
                "a boot is not this board's next step: it needs {due:?}"
            ))
        }
    }
    require_image(pb, release)?;
    pb.reboot_normal().map_err(|e| e.to_string())
}
