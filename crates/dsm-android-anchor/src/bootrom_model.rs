// SPDX-License-Identifier: MIT OR Apache-2.0
//! A model of the RP2350 bootloader for the burn procedure's tests: it takes the real PICOBOOT
//! command bytes and keeps OTP's own rules. A raw row's bits only ever set, and a write that would
//! clear one is refused (`PICOBOOT_UNSUPPORTED_MODIFICATION`). A row written with error correction
//! takes no second write. A page whose `LOCK_BL` bars the bootloader answers
//! `PICOBOOT_NOT_PERMITTED`, as the boards in hand answer for their sealed secret page. Flash is
//! erased by sector and written by page, and a reboot into a signed image records its rollback
//! version, as the bootrom's first boot of one does.

use crate::otp_burn::{lock1, BOOT_FLAGS0_ROW, PAGE_ROWS, ROLLBACK_ROW, ROWS};
use crate::picoboot::{BootselLink, COMMAND_BYTES, MAGIC, NOT_PERMITTED, RAW_ROW_MASK};
use crate::release::FLASH_BASE;

const UNSUPPORTED_MODIFICATION: u32 = 17;
const INVALID_ADDRESS: u32 = 4;
const BAD_ALIGNMENT: u32 = 5;
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
}

/// How a reboot went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastBoot {
    NotYet,
    /// No image it may run: it came back in BOOTSEL.
    Refused,
    /// It ran the image in flash.
    Ran,
}

impl BootromModel {
    /// A board as the two in hand stood on 2026-11-11: the secret page burned and locked by an
    /// earlier procedure, the boot pages' lock rows at `0x040404`, everything else blank.
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
        }
    }

    /// The bootloader may read this row unless its page's `LOCK_BL` (bits 4-5 of `PAGEn_LOCK1`) is
    /// "inaccessible". The lock rows' own pages are always readable.
    fn bootloader_reads(&self, row: u16) -> Result<(), u32> {
        let page = row / PAGE_ROWS;
        if page >= 62 {
            return Ok(());
        }
        match (self.raw[usize::from(lock1(page))] >> 4) & 0x3 {
            0x3 => Err(NOT_PERMITTED),
            _readable => Ok(()),
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
        let len = u32::from_le_bytes([cmd[12], cmd[13], cmd[14], cmd[15]]) as usize;
        let mut args = [0u8; 16];
        args.copy_from_slice(&cmd[16..32]);
        self.status = 0;
        match id {
            0x8c => self.otp_read(&args, len),
            0x84 => {
                let addr = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
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
            if let Err(status) = self.bootloader_reads(r) {
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
                if args[4] != 0 {
                    for (i, word) in data.chunks_exact(2).enumerate() {
                        let r = usize::from(row) + i;
                        if self.raw[r] != 0 {
                            return self.refuse(UNSUPPORTED_MODIFICATION);
                        }
                        let value = u16::from_le_bytes([word[0], word[1]]);
                        self.ecc[r] = Some(value);
                        self.raw[r] = u32::from(value) | if value == 0 { 0 } else { ECC_MARKER };
                    }
                } else {
                    for (i, word) in data.chunks_exact(4).enumerate() {
                        let r = usize::from(row) + i;
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
