// SPDX-License-Identifier: MIT OR Apache-2.0
//! The RP2350 USB bootloader's command protocol (PICOBOOT), spoken from the phone, so that a board's
//! one-time burns need nothing but the phone (owner, 2026-11-11: "Not everyone has a Mac. It has to
//! be doable from the phone").
//!
//! It is the protocol picotool speaks, byte for byte (raspberrypi/picotool 2.2.0,
//! `picoboot_connection.c`; pico-sdk `boot/picoboot.h`): a 32-byte command on the bulk OUT
//! endpoint, its data on bulk IN or OUT, then an acknowledgement in the opposite direction. A
//! command the bootloader refuses stalls the endpoint; its status is read through the interface's
//! vendor control request, and the interface is reset before anything else is sent.
//!
//! Kotlin only moves the bytes ([`BootselLink`]); every command is framed and checked here.

/// `PICOBOOT_MAGIC`, the first word of every command.
pub const MAGIC: u32 = 0x431f_d10b;
/// Bytes in a command on the wire.
pub const COMMAND_BYTES: usize = 32;
/// Bytes of one OTP row read or written with the bootloader's error correction: 16 data bits.
pub const ECC_ROW_BYTES: usize = 2;
/// Bytes of one raw OTP row: its 24 bits in a little-endian word.
pub const RAW_ROW_BYTES: usize = 4;
/// The 24 bits a raw OTP row holds.
pub const RAW_ROW_MASK: u32 = 0x00ff_ffff;
/// `PICOBOOT_NOT_PERMITTED`: what the bootloader answers for a page its lock keeps from it.
pub const NOT_PERMITTED: u32 = 10;

const PC_EXCLUSIVE_ACCESS: u8 = 0x01;
const PC_FLASH_ERASE: u8 = 0x03;
const PC_READ: u8 = 0x84;
const PC_WRITE: u8 = 0x05;
const PC_EXIT_XIP: u8 = 0x06;
const PC_REBOOT2: u8 = 0x0a;
const PC_OTP_READ: u8 = 0x8c;
const PC_OTP_WRITE: u8 = 0x0d;
/// A command whose data comes IN to the host has this bit in its id.
const IN_COMMAND: u8 = 0x80;
/// `EXCLUSIVE`: the bootloader's mass-storage side keeps off the flash while the phone writes it.
const EXCLUSIVE: u8 = 1;
/// `BOOT_TYPE_NORMAL` with `BOOT_PARTITION_NONE` (-1) and a 500 ms delay: what `picotool reboot` sends.
const BOOT_TYPE_NORMAL: u32 = 0;
const BOOT_PARTITION_NONE: u32 = u32::MAX;
const REBOOT_DELAY_MS: u32 = 500;

/// What the bootloader's status codes mean, in picotool's words.
#[must_use]
pub fn status_words(status: u32) -> &'static str {
    match status {
        0 => "ok",
        1 => "unknown cmd",
        2 => "invalid cmd length",
        3 => "invalid transfer length",
        4 => "invalid address",
        5 => "bad address alignment",
        6 => "interleaved write",
        7 => "rebooting",
        8 => "unknown error",
        9 => "invalid state",
        10 => "permission failure",
        11 => "invalid arg",
        12 => "buffer too small",
        13 => "precondition not met",
        14 => "modified data",
        15 => "data is invalid",
        16 => "not found",
        17 => "unsupported modification (attempt to clear otp bits)",
        _ => "a status the bootloader does not document",
    }
}

/// Why a command did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootselError {
    /// The USB link failed and the bootloader named no refusal: whether the command ran is unknown.
    Link(String),
    /// The bootloader refused the command, with its status.
    Refused { command: u8, status: u32 },
}

impl core::fmt::Display for BootselError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Link(why) => write!(f, "the USB link to the board's bootloader failed: {why}"),
            Self::Refused { command, status } => write!(
                f,
                "the board's bootloader refused command {command:#04x}: {} ({status})",
                status_words(*status)
            ),
        }
    }
}

/// The USB link to a board in BOOTSEL: the PICOBOOT interface's two bulk endpoints and its two vendor
/// control requests. The phone's USB stack provides it; it moves bytes and judges none of them.
pub trait BootselLink {
    /// Send these bytes on the bulk OUT endpoint, whole.
    fn bulk_out(&mut self, data: &[u8]) -> Result<(), String>;
    /// One transfer from the bulk IN endpoint of at most `max` bytes: the bytes that came.
    fn bulk_in(&mut self, max: usize) -> Result<Vec<u8>, String>;
    /// The zero-length packet on bulk IN with which the bootloader acknowledges an OUT or data-less
    /// command (picotool reads it with a one-byte buffer).
    fn ack_in(&mut self) -> Result<(), String>;
    /// `PICOBOOT_IF_CMD_STATUS`: the interface's 16-byte status of its last command.
    fn command_status(&mut self) -> Result<[u8; 16], String>;
    /// Clear both endpoints' halts and `PICOBOOT_IF_RESET` the interface.
    fn reset(&mut self) -> Result<(), String>;
}

/// The data a command moves, if any.
enum Data<'a> {
    None,
    Out(&'a [u8]),
    In(usize),
}

/// A command's 32 bytes: magic, token, id, the length of its arguments, the length of its data, and
/// its arguments zero-padded to 16 bytes (`struct picoboot_cmd`).
#[must_use]
pub fn command_bytes(token: u32, id: u8, args: &[u8], transfer_length: u32) -> [u8; COMMAND_BYTES] {
    let mut cmd = [0u8; COMMAND_BYTES];
    cmd[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    cmd[4..8].copy_from_slice(&token.to_le_bytes());
    cmd[8] = id;
    // Every argument struct is at most 16 bytes; `args` is built below and never longer.
    cmd[9] = args.len() as u8;
    cmd[12..16].copy_from_slice(&transfer_length.to_le_bytes());
    cmd[16..16 + args.len()].copy_from_slice(args);
    cmd
}

/// `struct picoboot_otp_cmd`: the first row, the number of rows, and whether the bootloader's error
/// correction applies.
fn otp_args(row: u16, rows: u16, ecc: u8) -> [u8; 5] {
    let mut args = [0u8; 5];
    args[0..2].copy_from_slice(&row.to_le_bytes());
    args[2..4].copy_from_slice(&rows.to_le_bytes());
    args[4] = ecc;
    args
}

/// `struct picoboot_range_cmd`: an address and a size.
fn range_args(addr: u32, size: u32) -> [u8; 8] {
    let mut args = [0u8; 8];
    args[0..4].copy_from_slice(&addr.to_le_bytes());
    args[4..8].copy_from_slice(&size.to_le_bytes());
    args
}

/// A connection to a board's bootloader, over the phone's USB link.
pub struct Picoboot<L: BootselLink> {
    link: L,
    token: u32,
}

impl<L: BootselLink> Picoboot<L> {
    /// The link under this connection: the tests look at the board model through it.
    #[cfg(test)]
    pub(crate) fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    /// Reset the interface first, as picotool does on every connection: a command a host left
    /// partway is not answered against this one's.
    pub fn connect(mut link: L) -> Result<Self, BootselError> {
        link.reset().map_err(BootselError::Link)?;
        Ok(Self { link, token: 1 })
    }

    /// One command: its 32 bytes out, its data, then the acknowledgement in the opposite direction.
    /// Any step that fails reads the bootloader's status (a refusal stalls the endpoint) and resets
    /// the interface, so the next command starts clean.
    fn run(&mut self, id: u8, args: &[u8], data: Data<'_>) -> Result<Vec<u8>, BootselError> {
        let token = self.token;
        self.token = self.token.wrapping_add(1);
        let transfer_length = match data {
            Data::None => 0,
            Data::Out(bytes) => bytes.len(),
            Data::In(len) => len,
        };
        let length = u32::try_from(transfer_length)
            .map_err(|_too_long| BootselError::Link("a transfer longer than 4 GiB".to_string()))?;
        let cmd = command_bytes(token, id, args, length);
        match self.exchange(id, &cmd, data) {
            Ok(received) => Ok(received),
            Err(why) => Err(self.after_failure(id, why)),
        }
    }

    fn exchange(&mut self, id: u8, cmd: &[u8], data: Data<'_>) -> Result<Vec<u8>, String> {
        self.link.bulk_out(cmd)?;
        let received = match data {
            Data::None => Vec::new(),
            Data::Out(bytes) => {
                self.link.bulk_out(bytes)?;
                Vec::new()
            }
            Data::In(len) => {
                let got = self.link.bulk_in(len)?;
                if got.len() != len {
                    return Err(format!("received {} of {len} bytes", got.len()));
                }
                got
            }
        };
        // The acknowledgement: picotool sends one byte OUT after an IN command, and reads IN after
        // any other, where the bootloader sends a zero-length packet.
        if id & IN_COMMAND != 0 {
            self.link.bulk_out(&[0u8])?;
        } else {
            self.link.ack_in()?;
        }
        Ok(received)
    }

    /// What a failed command was: refused, if the bootloader's status names a refusal; otherwise the
    /// link's own failure. The interface is reset either way.
    fn after_failure(&mut self, id: u8, why: String) -> BootselError {
        let status = self
            .link
            .command_status()
            .map(|s| u32::from_le_bytes([s[4], s[5], s[6], s[7]]));
        let reset = self.link.reset();
        log::warn!(
            "[picoboot] command {id:#04x} did not complete ({why}); status {status:?}, reset {reset:?}"
        );
        match (status, reset) {
            (Ok(code), Ok(())) if code != 0 => BootselError::Refused {
                command: id,
                status: code,
            },
            (Ok(_ok), Ok(())) => BootselError::Link(why),
            (Err(status_failed), _) => BootselError::Link(format!(
                "{why}; the bootloader's status could not be read either: {status_failed}"
            )),
            (Ok(_status), Err(reset_failed)) => BootselError::Link(format!(
                "{why}; the interface did not reset: {reset_failed}"
            )),
        }
    }

    /// Raw OTP rows from `row`: each row's word, its low 24 bits the row.
    pub fn otp_read_raw(&mut self, row: u16, rows: u16) -> Result<Vec<u32>, BootselError> {
        let bytes = self.run(
            PC_OTP_READ,
            &otp_args(row, rows, 0),
            Data::In(usize::from(rows) * RAW_ROW_BYTES),
        )?;
        Ok(bytes
            .chunks_exact(RAW_ROW_BYTES)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect())
    }

    /// OTP rows from `row` through the bootloader's error correction: two bytes a row.
    pub fn otp_read_ecc(&mut self, row: u16, rows: u16) -> Result<Vec<u8>, BootselError> {
        self.run(
            PC_OTP_READ,
            &otp_args(row, rows, 1),
            Data::In(usize::from(rows) * ECC_ROW_BYTES),
        )
    }

    /// Write raw OTP rows from `row`, one 24-bit value each. Bits only ever set: the bootloader
    /// refuses a value that would clear one.
    pub fn otp_write_raw(&mut self, row: u16, values: &[u32]) -> Result<(), BootselError> {
        let rows = u16::try_from(values.len())
            .map_err(|_too_many| BootselError::Link("more rows than OTP holds".to_string()))?;
        let mut data = Vec::with_capacity(values.len() * RAW_ROW_BYTES);
        for value in values {
            data.extend_from_slice(&(value & RAW_ROW_MASK).to_le_bytes());
        }
        self.run(PC_OTP_WRITE, &otp_args(row, rows, 0), Data::Out(&data))
            .map(|_none| ())
    }

    /// Write OTP rows from `row` with the bootloader's error correction, two bytes a row. The
    /// bootloader refuses rows that already hold a value.
    pub fn otp_write_ecc(&mut self, row: u16, data: &[u8]) -> Result<(), BootselError> {
        if data.len() % ECC_ROW_BYTES != 0 {
            return Err(BootselError::Link(format!(
                "{} bytes are not whole rows of {ECC_ROW_BYTES}",
                data.len()
            )));
        }
        let rows = u16::try_from(data.len() / ECC_ROW_BYTES)
            .map_err(|_too_many| BootselError::Link("more rows than OTP holds".to_string()))?;
        self.run(PC_OTP_WRITE, &otp_args(row, rows, 1), Data::Out(data))
            .map(|_none| ())
    }

    /// Keep the bootloader's mass-storage side off the flash while the phone writes it.
    pub fn exclusive(&mut self) -> Result<(), BootselError> {
        self.run(PC_EXCLUSIVE_ACCESS, &[EXCLUSIVE], Data::None)
            .map(|_none| ())
    }

    /// Leave execute-in-place, so the flash takes commands.
    pub fn exit_xip(&mut self) -> Result<(), BootselError> {
        self.run(PC_EXIT_XIP, &[], Data::None).map(|_none| ())
    }

    /// Erase flash from `addr`, a whole number of 4 KiB sectors.
    pub fn flash_erase(&mut self, addr: u32, len: u32) -> Result<(), BootselError> {
        self.run(PC_FLASH_ERASE, &range_args(addr, len), Data::None)
            .map(|_none| ())
    }

    /// Write `data` to flash or RAM at `addr`, in whole 256-byte pages for flash. Erases nothing.
    pub fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), BootselError> {
        let len = u32::try_from(data.len())
            .map_err(|_too_long| BootselError::Link("a write longer than 4 GiB".to_string()))?;
        self.run(PC_WRITE, &range_args(addr, len), Data::Out(data))
            .map(|_none| ())
    }

    /// Read `len` bytes of flash or RAM at `addr`.
    pub fn read(&mut self, addr: u32, len: u32) -> Result<Vec<u8>, BootselError> {
        let size = usize::try_from(len)
            .map_err(|_too_long| BootselError::Link("a read longer than memory".to_string()))?;
        self.run(PC_READ, &range_args(addr, len), Data::In(size))
    }

    /// Reboot into the normal boot path, as `picotool reboot` does.
    pub fn reboot_normal(&mut self) -> Result<(), BootselError> {
        let mut args = [0u8; 16];
        args[0..4].copy_from_slice(&BOOT_TYPE_NORMAL.to_le_bytes());
        args[4..8].copy_from_slice(&REBOOT_DELAY_MS.to_le_bytes());
        args[8..12].copy_from_slice(&BOOT_PARTITION_NONE.to_le_bytes());
        self.run(PC_REBOOT2, &args, Data::None).map(|_none| ())
    }
}
