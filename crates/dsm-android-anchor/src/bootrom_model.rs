// SPDX-License-Identifier: MIT OR Apache-2.0
//! A model of the RP2350 bootloader for the burn procedure's tests: it takes the real PICOBOOT
//! command bytes and keeps OTP's own rules. A raw row's bits only ever set, and a write that would
//! clear one is refused (`PICOBOOT_UNSUPPORTED_MODIFICATION`). A row written with error correction
//! takes no second write. Each row is guarded as the bootrom guards it (`s_varm_api_hx_otp_access`,
//! `pico-bootrom-rp2350`): by the soft lock of its page, a lock row's page being the one it sits in on
//! an A2 bootrom and the one it locks on A3 and A4. The soft locks are set once, on entering BOOTSEL,
//! from each page's Secure lock advanced by its bootloader lock; a refused read or write answers
//! `PICOBOOT_NOT_PERMITTED`, as the boards in hand answer for their sealed secret page. Flash is erased
//! by sector and written by page, and a reboot into a signed image records its rollback version, as
//! the bootrom's first boot of one does.

use crate::board_setup::Carried;
use crate::otp_burn::{
    lock0, lock1, BOOTROM_HEADER, BOOT_FLAGS0_ROW, DIGEST_ROW, LOCK_IMAGE_ROWS, PAGES, PAGE_ROWS,
    ROLLBACK_ROW, ROWS,
};
use crate::picoboot::{BootselLink, COMMAND_BYTES, MAGIC, NOT_PERMITTED, RAW_ROW_MASK};
use crate::release::FLASH_BASE;

const UNSUPPORTED_MODIFICATION: u32 = 17;
const INVALID_ADDRESS: u32 = 4;
const BAD_ALIGNMENT: u32 = 5;
const INVALID_STATE: u32 = 9;
/// A soft lock's bits: 0x1 bars writes, 0x2 reads.
const WRITE_BARRED: u32 = 0x1;
const READ_BARRED: u32 = 0x2;
const FLASH_BYTES: usize = 4 * 1024 * 1024;
const ROLLBACK_REQUIRED: u32 = 1 << 11;

/// A row with error correction holds its 16 data bits; a raw read shows them with a marker in the
/// bits the code would occupy, so a raw read of a written row is never zero.
const ECC_MARKER: u32 = 0x3f << 16;

#[derive(Clone, Copy)]
enum Pending {
    Idle,
    /// A command whose data comes next on bulk OUT.
    OutData {
        id: u8,
        args: [u8; 16],
        len: usize,
    },
    /// A command whose answer goes out on bulk IN, then the host's one-byte acknowledgement.
    InData {
        len: usize,
    },
    /// The host's one-byte acknowledgement of an IN command.
    AckOut,
    /// The zero-length acknowledgement the host reads after an OUT or data-less command.
    AckIn,
}

pub struct BootromModel {
    pub raw: Vec<u32>,
    /// Rows written with error correction, and their data.
    pub ecc: Vec<Option<u16>>,
    pub flash: Vec<u8>,
    pending: Pending,
    in_answer: Vec<u8>,
    /// The last command's status.
    status: u32,
    /// The stall a refused command leaves on the endpoints until the host resets the interface.
    stall: Option<u32>,
    /// Commands seen, by id: what the tests check was or was not sent.
    pub commands: Vec<u8>,
    pub rebooted: u32,
    /// The image signed with the boot key, as flash holds it: with secure boot on, the bootrom runs
    /// it and refuses anything else. `None`: this board's bootrom runs whatever flash holds.
    pub signed_image: Option<Vec<u8>>,
    /// How the last reboot went.
    pub last_boot: LastBoot,
    /// The bootrom's version byte: 2 on the boards in hand (A2), 3 or 4 on later steppings.
    pub bootrom_version: u8,
    /// Each page's soft lock for the bootloader, set on entering BOOTSEL: bit 0 bars writes, bit 1
    /// reads. Unset until the board's first command after it comes up in BOOTSEL.
    soft_locks: Option<Vec<u32>>,
    /// The lock image's flash bytes (`dsm-anchor-lock-pages`), as the phone loads them: started from
    /// flash on a board whose secure boot is off, it does what that image does
    /// ([`Self::run_lock_image`]) and reboots into BOOTSEL.
    pub lock_image: Option<Vec<u8>>,
    /// The prepare and the trial image's flash bytes, as the phone loads them: started from flash on a
    /// board whose secure boot is off, each comes up as the DSM Anchor ([`Self::running`]).
    pub prepare_image: Option<Vec<u8>>,
    pub trial_image: Option<Vec<u8>>,
    /// Which of those two the board runs as the DSM Anchor since its last start: none after a start on
    /// anything else.
    pub running: Option<Carried>,
}

/// How a reboot went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastBoot {
    NotYet,
    /// No image it may run: it came back in BOOTSEL.
    Refused,
    /// It ran the image in flash.
    Ran,
    /// It ran the lock image, which rebooted it into BOOTSEL.
    BackToBootsel,
}

impl BootromModel {
    /// The yellow board as its A2 bootloader showed it through the 9FF phone on 2026-11-11, before
    /// its burns: [`Self::sealed_board`] with the lock pages' own lock rows as it holds them, page 62's
    /// at `0x040404` (the bootloader may write it) and page 63's at `0x141414` (the bootloader may
    /// read it and not write it); both pages' access-key rows zero.
    pub fn yellow_board() -> Self {
        let mut board = Self::sealed_board();
        board.raw[usize::from(lock1(62))] = 0x04_0404;
        board.raw[usize::from(lock1(63))] = 0x14_1414;
        board
    }

    /// A board sealed as the two in hand are: the secret page burned and locked by an earlier
    /// procedure, the boot pages' lock rows at `0x040404`, everything else blank, the lock pages'
    /// own lock rows included, as a board burned to the end from BOOTSEL needs them.
    pub fn sealed_board() -> Self {
        let mut board = Self::blank_board();
        for row in 0..PAGE_ROWS {
            board.ecc[usize::from(48 * PAGE_ROWS + row)] = Some(0xa5a5);
            board.raw[usize::from(48 * PAGE_ROWS + row)] = 0xa5a5 | ECC_MARKER;
        }
        board.raw[usize::from(lock1(48))] = crate::otp_burn::SECRET_LOCK;
        board.raw[usize::from(lock1(1))] = 0x04_0404;
        board.raw[usize::from(lock1(2))] = 0x04_0404;
        board
    }

    pub fn blank_board() -> Self {
        Self {
            raw: vec![0; usize::from(ROWS)],
            ecc: vec![None; usize::from(ROWS)],
            flash: vec![0xff; FLASH_BYTES],
            pending: Pending::Idle,
            in_answer: Vec::new(),
            status: 0,
            stall: None,
            commands: Vec::new(),
            rebooted: 0,
            signed_image: None,
            last_boot: LastBoot::NotYet,
            bootrom_version: 2,
            soft_locks: None,
            lock_image: None,
            prepare_image: None,
            trial_image: None,
            running: None,
        }
    }

    /// The prepare or the trial image, where flash starts with one.
    fn anchor_image_in_flash(&self) -> Option<Carried> {
        [
            (Carried::PrepareChip, &self.prepare_image),
            (Carried::Trial, &self.trial_image),
        ]
        .into_iter()
        .find_map(|(carried, image)| {
            image
                .as_ref()
                .filter(|bytes| self.flash.starts_with(bytes.as_slice()))
                .map(|_held| carried)
        })
    }

    /// What the lock image does, as Secure code at a normal boot: each row it writes, only where the
    /// row's guarding page has its Secure lock open and no access key (nothing advances a soft lock
    /// at a normal boot), the digest page's only once the digest is burned, and neither where it
    /// holds a bit outside the value.
    fn run_lock_image(&mut self) {
        let majority = |row: u32| {
            let (a, b, c) = (row & 0xff, (row >> 8) & 0xff, (row >> 16) & 0xff);
            (a & b) | (b & c) | (a & c)
        };
        let digest_burned = (DIGEST_ROW..DIGEST_ROW + 16).any(|r| self.raw[usize::from(r)] != 0);
        for (row, value) in LOCK_IMAGE_ROWS {
            if row == lock1(46) && !digest_burned {
                continue;
            }
            let old = self.raw[usize::from(row)];
            if old == value || old & !value != 0 {
                continue;
            }
            let page = self.guarding_page(row);
            let secure = majority(self.raw[usize::from(lock1(page))]) & WRITE_BARRED;
            let keyed = majority(self.raw[usize::from(lock0(page))]) & 0x3f;
            if secure == 0 && keyed == 0 {
                self.raw[usize::from(row)] = value;
            }
        }
    }

    /// The soft locks the bootrom sets on entering BOOTSEL: a page's Secure lock (`LOCK_S`, bits 0-1
    /// of `PAGEn_LOCK1`) advanced by its bootloader lock (`LOCK_BL`, bits 4-5), each by the majority of
    /// the row's three bytes; a page with an access key registered (`PAGEn_LOCK0` bits 0-5) takes no
    /// write.
    fn enter_bootsel(&mut self) {
        let majority = |row: u32| {
            let (a, b, c) = (row & 0xff, (row >> 8) & 0xff, (row >> 16) & 0xff);
            (a & b) | (b & c) | (a & c)
        };
        self.soft_locks = Some(
            (0..PAGES)
                .map(|page| {
                    let lock = majority(self.raw[usize::from(lock1(page))]);
                    let keyed = majority(self.raw[usize::from(lock0(page))]) & 0x3f != 0;
                    (lock & 0x3) | ((lock >> 4) & 0x3) | u32::from(keyed)
                })
                .collect(),
        );
    }

    /// The page whose soft lock guards `row`, as this bootrom guards it.
    fn guarding_page(&self, row: u16) -> u16 {
        let page = row / PAGE_ROWS;
        if self.bootrom_version >= 3 && page >= 62 {
            (row - lock0(0)) / 2
        } else {
            page
        }
    }

    /// The bootloader may touch `row` unless its guarding page's soft lock bars it: `bar` is 0x1 for a
    /// write and 0x2 for a read.
    fn bootloader_may(&self, row: u16, bar: u32) -> Result<(), u32> {
        let page = usize::from(self.guarding_page(row));
        match &self.soft_locks {
            Some(locks) if locks[page] & bar != 0 => Err(NOT_PERMITTED),
            Some(_open) => Ok(()),
            None => Err(INVALID_STATE),
        }
    }

    fn refuse(&mut self, status: u32) {
        self.status = status;
        self.stall = Some(status);
        self.pending = Pending::Idle;
    }

    fn command(&mut self, cmd: &[u8]) {
        let magic = u32::from_le_bytes([cmd[0], cmd[1], cmd[2], cmd[3]]);
        if magic != MAGIC {
            return self.refuse(1);
        }
        let id = cmd[8];
        self.commands.push(id);
        if self.soft_locks.is_none() {
            self.enter_bootsel();
        }
        let len = u32::from_le_bytes([cmd[12], cmd[13], cmd[14], cmd[15]]) as usize;
        let mut args = [0u8; 16];
        args.copy_from_slice(&cmd[16..32]);
        self.status = 0;
        match id {
            0x8c => self.otp_read(&args, len),
            0x84 => {
                let addr = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
                if addr == BOOTROM_HEADER && len == 4 {
                    self.in_answer = vec![b'M', b'u', 2, self.bootrom_version];
                    self.pending = Pending::InData { len };
                    return;
                }
                match flash_offset(addr, len) {
                    Some(at) => {
                        self.in_answer = self.flash[at..at + len].to_vec();
                        self.pending = Pending::InData { len };
                    }
                    None => self.refuse(INVALID_ADDRESS),
                }
            }
            0x0d | 0x05 => self.pending = Pending::OutData { id, args, len },
            0x03 => {
                let addr = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
                let size = u32::from_le_bytes([args[4], args[5], args[6], args[7]]) as usize;
                match flash_offset(addr, size) {
                    Some(at) if at % 4096 == 0 && size % 4096 == 0 => {
                        self.flash[at..at + size].fill(0xff);
                        self.pending = Pending::AckIn;
                    }
                    Some(_unaligned) => self.refuse(BAD_ALIGNMENT),
                    None => self.refuse(INVALID_ADDRESS),
                }
            }
            0x01 | 0x06 => self.pending = Pending::AckIn,
            0x0a => {
                self.rebooted += 1;
                self.boot_signed_image();
                // The board leaves BOOTSEL; it comes back to it, refused or replugged, with its soft
                // locks set again from what OTP then holds.
                self.soft_locks = None;
                self.pending = Pending::AckIn;
            }
            _ => self.refuse(1),
        }
    }

    /// A reboot. With secure boot on, an image other than the signed one is refused and the board
    /// comes back in BOOTSEL; the signed image's first boot records its rollback version and sets
    /// `ROLLBACK_REQUIRED`.
    fn boot_signed_image(&mut self) {
        let secure = self.raw[0x40] & 1 != 0;
        self.running = None;
        // The lock image is never signed: it runs only where secure boot is off.
        let lock_image_in_flash = self
            .lock_image
            .as_ref()
            .is_some_and(|image| self.flash.starts_with(image));
        if !secure && lock_image_in_flash {
            self.run_lock_image();
            self.last_boot = LastBoot::BackToBootsel;
            return;
        }
        // Nor are the prepare and the trial image: each comes up as the DSM Anchor.
        if let Some(started) = self.anchor_image_in_flash().filter(|_image| !secure) {
            self.running = Some(started);
            self.last_boot = LastBoot::Ran;
            return;
        }
        self.last_boot = match &self.signed_image {
            Some(signed) if secure && self.flash[..signed.len()] != signed[..] => LastBoot::Refused,
            _runs => LastBoot::Ran,
        };
        if self.last_boot == LastBoot::Refused {
            return;
        }
        if secure {
            self.raw[usize::from(ROLLBACK_ROW)] |= 0x1;
            for copy in 0..3 {
                self.raw[usize::from(BOOT_FLAGS0_ROW) + copy] |= ROLLBACK_REQUIRED;
            }
        }
    }

    fn otp_read(&mut self, args: &[u8; 16], len: usize) {
        let row = u16::from_le_bytes([args[0], args[1]]);
        let rows = u16::from_le_bytes([args[2], args[3]]);
        let ecc = args[4] != 0;
        let mut answer = Vec::new();
        for r in row..row + rows {
            if r >= ROWS {
                return self.refuse(INVALID_ADDRESS);
            }
            if let Err(status) = self.bootloader_may(r, READ_BARRED) {
                return self.refuse(status);
            }
            if ecc {
                // A blank row reads zero through the error correction; a row written raw has no
                // valid code word, and its read is refused.
                let data = match (self.ecc[usize::from(r)], self.raw[usize::from(r)]) {
                    (Some(value), _) => value,
                    (None, 0) => 0,
                    (None, _raw) => return self.refuse(15),
                };
                answer.extend_from_slice(&data.to_le_bytes());
            } else {
                answer.extend_from_slice(&self.raw[usize::from(r)].to_le_bytes());
            }
        }
        if answer.len() != len {
            return self.refuse(3);
        }
        self.in_answer = answer;
        self.pending = Pending::InData { len };
    }

    fn data_out(&mut self, id: u8, args: [u8; 16], data: &[u8]) {
        match id {
            0x0d => {
                let row = u16::from_le_bytes([args[0], args[1]]);
                let rows = usize::from(u16::from_le_bytes([args[2], args[3]]));
                let row_bytes = if args[4] != 0 { 2 } else { 4 };
                if data.len() != rows * row_bytes {
                    return self.refuse(3);
                }
                // Row by row, as the bootrom checks them: a write may stop part-way at a row its
                // guarding page bars.
                if args[4] != 0 {
                    for (at, word) in (row..).zip(data.chunks_exact(2)) {
                        let r = usize::from(at);
                        if let Err(status) = self.bootloader_may(at, WRITE_BARRED) {
                            return self.refuse(status);
                        }
                        if self.raw[r] != 0 {
                            return self.refuse(UNSUPPORTED_MODIFICATION);
                        }
                        let value = u16::from_le_bytes([word[0], word[1]]);
                        self.ecc[r] = Some(value);
                        self.raw[r] = u32::from(value) | if value == 0 { 0 } else { ECC_MARKER };
                    }
                } else {
                    for (at, word) in (row..).zip(data.chunks_exact(4)) {
                        let r = usize::from(at);
                        if let Err(status) = self.bootloader_may(at, WRITE_BARRED) {
                            return self.refuse(status);
                        }
                        let value =
                            u32::from_le_bytes([word[0], word[1], word[2], word[3]]) & RAW_ROW_MASK;
                        if self.raw[r] & !value != 0 {
                            return self.refuse(UNSUPPORTED_MODIFICATION);
                        }
                        self.raw[r] |= value;
                    }
                }
            }
            _ => {
                let addr = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
                match flash_offset(addr, data.len()) {
                    Some(at) if at % 256 == 0 && data.len() % 256 == 0 => {
                        for (i, byte) in data.iter().enumerate() {
                            self.flash[at + i] &= byte;
                        }
                    }
                    Some(_unaligned) => return self.refuse(BAD_ALIGNMENT),
                    None => return self.refuse(INVALID_ADDRESS),
                }
            }
        }
        self.pending = Pending::AckIn;
    }
}

fn flash_offset(addr: u32, len: usize) -> Option<usize> {
    let at = addr.checked_sub(FLASH_BASE)? as usize;
    (at + len <= FLASH_BYTES).then_some(at)
}

impl BootselLink for BootromModel {
    fn bulk_out(&mut self, data: &[u8]) -> Result<(), String> {
        if let Some(status) = self.stall {
            return Err(format!("endpoint stalled ({status})"));
        }
        match self.pending {
            Pending::Idle if data.len() == COMMAND_BYTES => {
                self.command(data);
                if let Some(status) = self.stall {
                    return Err(format!("endpoint stalled ({status})"));
                }
                Ok(())
            }
            Pending::OutData { id, args, len } if data.len() == len => {
                self.data_out(id, args, data);
                if let Some(status) = self.stall {
                    return Err(format!("endpoint stalled ({status})"));
                }
                Ok(())
            }
            Pending::AckOut if data.len() == 1 => {
                self.pending = Pending::Idle;
                Ok(())
            }
            _ => {
                self.refuse(8);
                Err("out of sequence".to_string())
            }
        }
    }

    fn bulk_in(&mut self, max: usize) -> Result<Vec<u8>, String> {
        if let Some(status) = self.stall {
            return Err(format!("endpoint stalled ({status})"));
        }
        match self.pending {
            Pending::InData { len } if max == len => {
                self.pending = Pending::AckOut;
                Ok(core::mem::take(&mut self.in_answer))
            }
            _ => {
                self.refuse(8);
                Err("out of sequence".to_string())
            }
        }
    }

    fn ack_in(&mut self) -> Result<(), String> {
        if let Some(status) = self.stall {
            return Err(format!("endpoint stalled ({status})"));
        }
        match self.pending {
            Pending::AckIn => {
                self.pending = Pending::Idle;
                Ok(())
            }
            _ => {
                self.refuse(8);
                Err("out of sequence".to_string())
            }
        }
    }

    fn command_status(&mut self) -> Result<[u8; 16], String> {
        let mut s = [0u8; 16];
        s[4..8].copy_from_slice(&self.status.to_le_bytes());
        Ok(s)
    }

    fn reset(&mut self) -> Result<(), String> {
        self.stall = None;
        self.pending = Pending::Idle;
        Ok(())
    }
}
