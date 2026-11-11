// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TROPIC01 as the appliance holds it: one authenticated session, shared by the appliance's
//! chip operations and its R-memory store, and reopened when the chip reboots to latch its cage.
//!
//! An unborn chip is opened on its factory pairing slot 0, whose key is public. Closing the birth
//! writes the board's own pairing key (derived from the sealed secret) into slot 1, moves the
//! session there, invalidates slot 0, revokes from slot 1 every command a second birth would use
//! (counter initialization, pairing-key writes and invalidation, resident-key generation, storage
//! and erasure, and last the access-configuration write itself), and reboots the chip so the
//! revocation is in force. Each step is checked before it is taken, so a power cut anywhere leaves a
//! sequence the next boot completes. Every boot then proves the cage: the chip must report each
//! revocation and refuse each command as unauthorized.

use alloc::boxed::Box;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::durable::StoreError;
use anchor_core::enrollment::Install;
use anchor_core::identify::ChipReading;
use anchor_core::rmem::SlotMemory;
use anchor_core::tropic::{ChipLink, ChipRefusal, Tropic, TropicError};
use anchor_core::try_run::TryStep;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{
    ActiveSession, EccCurve, EccOrigin, Error as Fault, MCounterIndex, NoSession, StartupReq,
    Tropic01, X25519Dalek,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Board;

const COUNTER: MCounterIndex = MCounterIndex::Index0;
/// The resident Ed25519 key's ECC slot (`σ^chip`).
pub const CHIP_KEY_SLOT: u16 = 0;
/// The factory pairing slot, whose key is public.
const FACTORY_SLOT: u8 = 0;
/// The pairing slot the board's own key is written to.
const OWN_SLOT: u8 = 1;
/// Bytes one R-memory data slot holds (TROPIC01 datasheet, `R_Mem_Data_Write`).
pub const RMEM_SLOT_BYTES: usize = 444;
/// R-memory data slots, numbered from 0 (`tropic01::R_MEM_DATA_SLOT_MAX` is the last).
pub const RMEM_SLOTS: u16 = tropic01::R_MEM_DATA_SLOT_MAX + 1;

/// The lanes of an access-configuration register: one bit per pairing slot in each. Most registers
/// have four, one for each range of what they guard. `I_CONFIG_WRITE` has two, the functionality
/// objects' and the configuration objects', and the rest of it means nothing to touch.
///
/// Highest first: lane 0 of `I_CONFIG_WRITE` is what permits writing that register at all (it gates
/// the configuration objects), so it is the last bit the cage clears and the one a resumed cage
/// reads to see whether it is finished.
fn lanes_of(register: u16) -> &'static [u8] {
    if register == I_CONFIG_WRITE {
        &[8, 0]
    } else {
        &[24, 16, 8, 0]
    }
}
/// `CFG_UAP_I_CONFIG_WRITE`.
const I_CONFIG_WRITE: u16 = 0x040;
/// `CFG_UAP_PAIRING_KEY_WRITE`.
const PAIRING_KEY_WRITE: u16 = 0x020;
/// `CFG_UAP_PAIRING_KEY_INVALIDATE`.
const PAIRING_KEY_INVALIDATE: u16 = 0x028;
/// The commands a second birth would use, revoked from the board's own slot. `I_CONFIG_WRITE` is
/// last, so the slot can no longer loosen its own cage once it is closed.
const CAGE: [u16; 7] = [
    0x150, // MCOUNTER_INIT
    PAIRING_KEY_WRITE,
    PAIRING_KEY_INVALIDATE,
    0x130, // ECC_KEY_GENERATE
    0x134, // ECC_KEY_STORE
    0x13C, // ECC_KEY_ERASE
    I_CONFIG_WRITE,
];

/// `CFG_START_UP` (User API, configuration objects).
const CFG_START_UP: u16 = 0x000;
/// `CFG_SENSORS`.
const CFG_SENSORS: u16 = 0x008;
/// `CFG_START_UP[RNGTEST_DIS]`, 0 when the chip tests its PTRNG at every start-up. Erratum
/// OI_TR01_ERR_2026090100: left at 1 on some test parts the PTRNG is never configured, and what the
/// chip generates from it may not be random.
const RNGTEST_DIS_BIT: u8 = 2;
/// Every sensor of `CFG_SENSORS` (bits 0..=17), each 0 when on. Tropic Square's factory configuration
/// clears all of them in R-config on every part but its T0XX samples (catalog list, section 5).
const SENSORS_OFF: u32 = 0x0003_FFFF;

/// What the chip says it is: its part number, silicon revision and firmware versions. Reported, and
/// never a credential: the chip's own word, which a chip that lies can change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChipFacts {
    pub part_number: String,
    pub silicon: String,
    pub firmware: String,
    pub ecc_firmware: String,
    /// Below 2.0.0 the chip does not verify its own writes (OI_TR01_ERR_2025120100).
    pub verifies_writes: Verifies,
}

/// Whether the chip's firmware reads back what it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifies {
    ChipAndBoard,
    BoardOnly,
}

impl ChipFacts {
    /// `chip_id` as the chip gives it (`lt_chip_id_t`, 128 bytes), and its two firmware versions.
    pub fn read(chip_id: &[u8], firmware: &[u8], ecc_firmware: &[u8]) -> Self {
        let verifies_writes = match firmware.get(3) {
            Some(major) if *major >= 2 => Verifies::ChipAndBoard,
            Some(_) | None => Verifies::BoardOnly,
        };
        Self {
            part_number: part_number(chip_id),
            silicon: text(chip_id.get(28..32)),
            firmware: version(firmware),
            ecc_firmware: version(ecc_firmware),
            verifies_writes,
        }
    }

    /// One line for whoever is about to install on this chip.
    pub fn describe(&self) -> String {
        let writes = match self.verifies_writes {
            Verifies::ChipAndBoard => "the chip and the board each verify its writes",
            Verifies::BoardOnly => "only the board verifies its writes, as this firmware does not",
        };
        format!(
            "the chip is {}, silicon {}, firmware {}, ECC firmware {}: {writes}",
            self.part_number, self.silicon, self.firmware, self.ecc_firmware
        )
    }
}

/// The length byte and text of `part_num_data`, at offset 68 of `lt_chip_id_t`.
fn part_number(chip_id: &[u8]) -> String {
    match chip_id.get(68..84) {
        Some(field) => text(field.get(1..1 + usize::from(field[0]).min(15))),
        None => "unknown".to_string(),
    }
}

fn text(bytes: Option<&[u8]>) -> String {
    match bytes {
        Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        None => "unknown".to_string(),
    }
}

/// `[build, patch, minor, major]`, as the chip answers `Get_Info_Req`.
fn version(bytes: &[u8]) -> String {
    match <[u8; 4]>::try_from(bytes) {
        Ok([_build, patch, minor, major]) => format!("{major}.{minor}.{patch}"),
        Err(_short) => "unknown".to_string(),
    }
}

/// Why a chip is not given a key, or anything else: refused before the first write to it.
#[derive(Clone, PartialEq, Eq)]
pub enum Unfit {
    /// `CFG_START_UP[RNGTEST_DIS]` is still 1. What the chip would generate may not be random.
    RandomnessUntested(ChipFacts),
    /// A sensor of `CFG_SENSORS` is off, as on a T0XX sample.
    SensorsOff(ChipFacts, u32),
    /// The chip's configuration could not be read.
    Unread(TropicError),
}

impl core::fmt::Debug for Unfit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RandomnessUntested(facts) => write!(
                f,
                "{}. It does not test its PTRNG at start-up, so what it generates may not be random \
                 (erratum OI_TR01_ERR_2026090100). Nothing has been written to it. The prepare_chip \
                 image configures it, irreversibly",
                facts.describe()
            ),
            Self::SensorsOff(facts, off) => write!(
                f,
                "{}. Its tamper sensors {off:#x} are off, as on a sample part. Nothing has been \
                 written to it",
                facts.describe()
            ),
            Self::Unread(cause) => write!(f, "the chip's configuration did not read: {cause:?}"),
        }
    }
}

/// The driver's fault over this SPI device and chip-select.
pub type ChipFault<SPI, CS> = Fault<
    <SPI as embedded_hal::spi::ErrorType>::Error,
    <CS as embedded_hal::digital::ErrorType>::Error,
>;

/// A session start the chip refused, with the chip handed back. Boxed: the driver's handle is 4.6 KiB.
type StartRefused<SPI, CS> = Box<(Tropic01<SPI, CS, NoSession>, ChipFault<SPI, CS>)>;

/// A probe of a command the closed birth denies: proven closed only by the chip refusing it as
/// unauthorized. Any other refusal means the command got past the access check, which is an open
/// cage, as is a command it accepts; a transport failure proves nothing and is reported.
fn denied<R, ES, EG>(probe: Result<R, Fault<ES, EG>>) -> Result<(), TropicError> {
    match probe {
        Ok(_accepted) => Err(TropicError::CageOpen),
        Err(Fault::Unauthorized) => Ok(()),
        Err(e) => match fault(e) {
            TropicError::Refused(_past_the_access_check) => Err(TropicError::CageOpen),
            other => Err(other),
        },
    }
}

/// A rehearsal the chip did not pass: the chip's error, and the sentence a try-run shows for it.
struct Unrehearsed {
    error: TropicError,
    why: String,
}

impl Unrehearsed {
    /// A driver fault, said as the appliance reports it.
    fn fault<ES, EG>(e: Fault<ES, EG>) -> Self {
        let error = fault(e);
        Self {
            error,
            why: format!("{error:?}"),
        }
    }

    fn refused(refusal: ChipRefusal, why: String) -> Self {
        Self {
            error: TropicError::Refused(refusal),
            why,
        }
    }
}

/// A driver fault as the appliance reports it: the link failed, or the chip refused, and which.
pub fn fault<ES, EG>(e: Fault<ES, EG>) -> TropicError {
    match e {
        Fault::AlarmMode => TropicError::Comm(ChipLink::AlarmMode),
        Fault::BusError(..) => TropicError::Comm(ChipLink::Bus),
        Fault::ChipBusy => TropicError::Comm(ChipLink::Busy),
        Fault::Decryption(..) => TropicError::Comm(ChipLink::Decryption),
        Fault::Encryption(..) => TropicError::Comm(ChipLink::Encryption),
        Fault::GPIOError(..) => TropicError::Comm(ChipLink::ChipSelect),
        Fault::HandshakeFailed => TropicError::Comm(ChipLink::Handshake),
        Fault::InvalidChipStatus(..) => TropicError::Comm(ChipLink::ChipStatus),
        Fault::InvalidCRC => TropicError::Comm(ChipLink::Crc),
        Fault::InvalidL2Response => TropicError::Comm(ChipLink::L2Response),
        Fault::InvalidResponse => TropicError::Comm(ChipLink::Response),
        Fault::L3ResponseBufferOverflow => TropicError::Comm(ChipLink::L3Overflow),
        Fault::ParsingError(..) => TropicError::Comm(ChipLink::L3Parse),
        Fault::HardwareFail => TropicError::Comm(ChipLink::HardwareFail),
        Fault::UnexpectedResponseStatus => TropicError::Comm(ChipLink::UnexpectedStatus),
        Fault::InvalidKey => TropicError::Refused(ChipRefusal::InvalidKey),
        Fault::InvalidL3Cmd => TropicError::Refused(ChipRefusal::InvalidL3Command),
        Fault::InvalidPublicKey => TropicError::Refused(ChipRefusal::InvalidPublicKey),
        Fault::InvalidParameter => TropicError::Refused(ChipRefusal::InvalidParameter),
        Fault::L2ResponseError(..) => TropicError::Refused(ChipRefusal::L2Status),
        Fault::L3CmdFailed => TropicError::Refused(ChipRefusal::L3CommandFailed),
        Fault::RequestExceedsSize => TropicError::Refused(ChipRefusal::RequestTooLarge),
        Fault::SlotNotEmpty => TropicError::Refused(ChipRefusal::SlotNotEmpty),
        Fault::SlotExpired => TropicError::Refused(ChipRefusal::SlotExpired),
        Fault::UpdateErr => TropicError::Refused(ChipRefusal::UpdateFailed),
        Fault::CounterInvalid => TropicError::Refused(ChipRefusal::CounterInvalid),
        Fault::SlotEmpty => TropicError::Refused(ChipRefusal::SlotEmpty),
        Fault::SlotInvalid => TropicError::Refused(ChipRefusal::SlotInvalid),
        Fault::Unauthorized => TropicError::Refused(ChipRefusal::Unauthorized),
    }
}

/// Reboot the chip. Firmware up to 1.0.1 resets partway through this answer's CRC, so a bad CRC here
/// says nothing about the reboot (OI_TR01_ERR_2025091800). A corrupted request would look the same, so
/// a bad CRC asks once more, which costs a reboot and nothing else.
fn reboot_chip<SPI: SpiDevice, CS: OutputPin, B: Board>(
    chip: &mut Tropic01<SPI, CS, NoSession>,
    board: &B,
) -> Result<(), TropicError> {
    match chip.startup_req(StartupReq::Reboot) {
        Ok(()) => await_chip(chip, board),
        Err(Fault::InvalidCRC) => {
            await_chip(chip, board)?;
            match chip.startup_req(StartupReq::Reboot) {
                Ok(()) | Err(Fault::InvalidCRC) => await_chip(chip, board),
                Err(e) => Err(fault(e)),
            }
        }
        Err(e) => Err(fault(e)),
    }
}

/// Up to ~10 s for the chip to answer again.
fn await_chip<SPI: SpiDevice, CS: OutputPin, B: Board>(
    chip: &mut Tropic01<SPI, CS, NoSession>,
    board: &B,
) -> Result<(), TropicError> {
    let mut polls = 0u32;
    loop {
        match chip.get_info_chip_id() {
            Ok(_id) => return Ok(()),
            Err(e) if polls >= 100 => return Err(fault(e)),
            Err(_booting) => {
                board.alive();
                board.wait_100ms();
                polls += 1;
            }
        }
    }
}

/// Why the chip could not be opened: the board's own slot and the factory slot both refused.
pub struct OpenRefused<F> {
    pub own_slot: F,
    pub factory_slot: F,
}

impl<F: core::fmt::Debug> core::fmt::Debug for OpenRefused<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "own slot: {:?}; factory slot: {:?}",
            self.own_slot, self.factory_slot
        )
    }
}

/// The chip and its one session.
pub struct ChipSession<SPI: SpiDevice, CS: OutputPin, B: Board> {
    session: Option<Tropic01<SPI, CS, ActiveSession>>,
    /// The board's own pairing secret (derived from the sealed secret).
    pairing: [u8; 32],
    /// The pairing slot the session runs on.
    slot: u8,
    /// What the chip said it was before the session opened.
    facts: ChipFacts,
    board: B,
}

impl<SPI: SpiDevice, CS: OutputPin, B: Board> ChipSession<SPI, CS, B> {
    /// Open the chip on the board's own slot if it holds the board's key, else on the factory
    /// slot (an unborn chip).
    #[inline(never)]
    pub fn open(
        chip: Tropic01<SPI, CS, NoSession>,
        pairing: [u8; 32],
        facts: ChipFacts,
        board: B,
    ) -> Result<Self, OpenRefused<ChipFault<SPI, CS>>> {
        let mut this = Self {
            session: None,
            pairing,
            slot: OWN_SLOT,
            facts,
            board,
        };
        match this.start(chip, OWN_SLOT) {
            Ok(session) => {
                this.session = Some(session);
                Ok(this)
            }
            Err(refused) => {
                let (chip, own_slot) = *refused;
                match this.start(chip, FACTORY_SLOT) {
                    Ok(session) => {
                        this.session = Some(session);
                        this.slot = FACTORY_SLOT;
                        Ok(this)
                    }
                    Err(refused) => Err(OpenRefused {
                        own_slot,
                        factory_slot: refused.1,
                    }),
                }
            }
        }
    }

    /// Whether this chip may be given a key and a counter, read before either is written. Every boot
    /// asks, since nothing it reads depends on what the anchor has done.
    pub fn check_fit(&mut self) -> Result<(), Unfit> {
        let start_up = self
            .with(|s| s.i_config_read(CFG_START_UP.into()))
            .map_err(|e| Unfit::Unread(fault(e)))?;
        if start_up & (1u32 << RNGTEST_DIS_BIT) != 0 {
            return Err(Unfit::RandomnessUntested(self.facts.clone()));
        }
        // A sensor is on when either copy holds its bit at 0.
        let irreversible = self
            .with(|s| s.i_config_read(CFG_SENSORS.into()))
            .map_err(|e| Unfit::Unread(fault(e)))?;
        let reversible = self
            .with(|s| s.r_config_read(CFG_SENSORS.into()))
            .map_err(|e| Unfit::Unread(fault(e)))?;
        let off = irreversible & reversible & SENSORS_OFF;
        if off != 0 {
            return Err(Unfit::SensorsOff(self.facts.clone(), off));
        }
        Ok(())
    }

    /// Tropic Square's correction for a test part whose PTRNG was never configured: clear
    /// `CFG_START_UP[RNGTEST_DIS]`, irreversibly, and reboot so the chip tests it from now on. A key
    /// already on the chip came from the untested source and is erased (OI_TR01_ERR_2026090100). Only
    /// a chip still on its factory slot takes this, and only the image built to do it asks.
    pub fn configure_randomness(&mut self) -> Result<(), TropicError> {
        if self.slot != FACTORY_SLOT {
            return Err(TropicError::Refused(ChipRefusal::NotFactorySlot));
        }
        let held = self
            .with(|s| s.i_config_read(CFG_START_UP.into()))
            .map_err(fault)?;
        if held & (1u32 << RNGTEST_DIS_BIT) != 0 {
            self.with(|s| s.i_config_write(CFG_START_UP.into(), RNGTEST_DIS_BIT))
                .map_err(fault)?;
            let now = self
                .with(|s| s.i_config_read(CFG_START_UP.into()))
                .map_err(fault)?;
            if now != held & !(1u32 << RNGTEST_DIS_BIT) {
                return Err(TropicError::Refused(ChipRefusal::StartUpNotAsWritten));
            }
        }
        match self.with(|s| s.ecc_key_erase(CHIP_KEY_SLOT.into())) {
            Ok(()) | Err(Fault::SlotEmpty | Fault::SlotInvalid) => {}
            Err(e) => return Err(fault(e)),
        }
        self.reopen(FACTORY_SLOT, Reboot::Latch)
    }

    #[inline(never)]
    fn start(
        &self,
        chip: Tropic01<SPI, CS, NoSession>,
        slot: u8,
    ) -> Result<Tropic01<SPI, CS, ActiveSession>, StartRefused<SPI, CS>> {
        let Some(ephemeral) = self.board.random_key() else {
            return Err(Box::new((chip, Fault::HandshakeFailed)));
        };
        let eh = StaticSecret::from(ephemeral);
        let (shipub, shipriv) = if slot == FACTORY_SLOT {
            (
                PublicKey::from(SH0PUB_PROD0),
                StaticSecret::from(SH0PRIV_PROD0),
            )
        } else {
            let own = StaticSecret::from(self.pairing);
            (PublicKey::from(&own), own)
        };
        let ehpub = PublicKey::from(&eh);
        chip.session_start(&X25519Dalek, shipub, shipriv, ehpub, eh, slot)
            .map_err(Box::new)
    }

    fn with<R>(
        &mut self,
        op: impl FnOnce(&mut Tropic01<SPI, CS, ActiveSession>) -> Result<R, ChipFault<SPI, CS>>,
    ) -> Result<R, ChipFault<SPI, CS>> {
        self.board.alive();
        match self.session.as_mut() {
            Some(session) => op(session),
            None => Err(Fault::HandshakeFailed),
        }
    }

    /// End the session, optionally reboot the chip, and open again on `slot`. Each step moves the
    /// driver's 4.6 KiB handle in a frame of its own, given back before the next, so a reopen under a
    /// boot or a request does not hold several of them at once: `scripts/stack-bound.py`.
    fn reopen(&mut self, slot: u8, reboot: Reboot) -> Result<(), TropicError> {
        let mut chip = self.end_session()?;
        if reboot == Reboot::Latch {
            reboot_chip(&mut chip, &self.board)?;
        }
        self.start_held(chip, slot)
    }

    /// The session ended, and the chip handed back.
    #[inline(never)]
    fn end_session(&mut self) -> Result<Tropic01<SPI, CS, NoSession>, TropicError> {
        let session = self
            .session
            .take()
            .ok_or(TropicError::Comm(ChipLink::NoSession))?;
        match session.session_abort() {
            Ok(chip) => Ok(chip),
            Err((session, e)) => {
                self.session = Some(session);
                Err(fault(e))
            }
        }
    }

    /// A session on `slot`.
    #[inline(never)]
    fn start_held(
        &mut self,
        chip: Tropic01<SPI, CS, NoSession>,
        slot: u8,
    ) -> Result<(), TropicError> {
        match self.start(chip, slot) {
            Ok(session) => {
                self.session = Some(session);
                self.slot = slot;
                Ok(())
            }
            Err(refused) => Err(fault(refused.1)),
        }
    }

    /// `pk_chip`: the resident key, generated on the die if the slot is empty. A key the chip did
    /// not generate itself, or on another curve, is refused: its private half may be known.
    pub fn resident_key(&mut self) -> Result<Vec<u8>, TropicError> {
        let read = self.with(|s| {
            s.ecc_key_read(CHIP_KEY_SLOT.into())
                .map(|k| (k.curve(), k.origin(), k.pub_key().to_vec()))
        });
        let (curve, origin, pk) = match read {
            Ok(key) => key,
            Err(Fault::InvalidKey | Fault::SlotEmpty) => {
                self.with(|s| s.ecc_key_generate(CHIP_KEY_SLOT.into(), EccCurve::Ed25519))
                    .map_err(fault)?;
                self.with(|s| {
                    s.ecc_key_read(CHIP_KEY_SLOT.into())
                        .map(|k| (k.curve(), k.origin(), k.pub_key().to_vec()))
                })
                .map_err(fault)?
            }
            Err(e) => return Err(fault(e)),
        };
        if curve != EccCurve::Ed25519 || origin != EccOrigin::KeyGenerate {
            return Err(TropicError::Refused(ChipRefusal::ResidentKeyNotGenerated));
        }
        Ok(pk)
    }

    /// What the chip holds, read with nothing written: the configuration a birth depends on, the
    /// access rules a cage changes, the pairing slots, the counter, the resident key's slot and how
    /// many R-memory slots are written. What the identify image reports after the chip's own word.
    pub fn survey(&mut self) -> Vec<ChipReading> {
        let mut readings = Vec::new();
        readings.push(ChipReading::new(
            "session",
            Ok(format!("opened on pairing slot {}", self.slot)),
        ));
        for (name, register) in [("CFG_START_UP", CFG_START_UP), ("CFG_SENSORS", CFG_SENSORS)]
            .into_iter()
            .chain(CAGE.iter().map(|register| ("access rule", *register)))
        {
            let irreversible = self
                .with(|s| s.i_config_read(register.into()))
                .map(|bits| format!("{bits:#010x}"))
                .map_err(|e| format!("{e:?}"));
            readings.push(ChipReading::new(
                &format!("I-config {name} {register:#05x}"),
                irreversible,
            ));
            let reversible = self
                .with(|s| s.r_config_read(register.into()))
                .map(|bits| format!("{bits:#010x}"))
                .map_err(|e| format!("{e:?}"));
            readings.push(ChipReading::new(
                &format!("R-config {name} {register:#05x}"),
                reversible,
            ));
        }
        for slot in 0u16..4 {
            let held = match self.with(|s| s.pairing_key_read(slot.into()).copied()) {
                Ok(_key) => Ok("holds a key".to_string()),
                Err(Fault::SlotEmpty) => Ok("empty".to_string()),
                Err(Fault::SlotInvalid) => Ok("invalidated".to_string()),
                Err(e) => Err(format!("{e:?}")),
            };
            readings.push(ChipReading::new(&format!("pairing slot {slot}"), held));
        }
        let counter = match self.with(|s| s.mcounter_get(COUNTER)) {
            Ok(value) => Ok(format!("{value}")),
            Err(Fault::CounterInvalid) => Ok("never set".to_string()),
            Err(e) => Err(format!("{e:?}")),
        };
        readings.push(ChipReading::new("counter 0", counter));
        let key = match self.with(|s| {
            s.ecc_key_read(CHIP_KEY_SLOT.into())
                .map(|k| (k.curve(), k.origin()))
        }) {
            Ok((curve, origin)) => Ok(format!("{curve:?}, {origin:?}")),
            Err(Fault::InvalidKey | Fault::SlotEmpty) => Ok("empty".to_string()),
            Err(e) => Err(format!("{e:?}")),
        };
        readings.push(ChipReading::new(
            &format!("resident key slot {CHIP_KEY_SLOT}"),
            key,
        ));
        readings.push(self.written_rmem());
        readings
    }

    /// How many R-memory slots hold bytes, and the first of them.
    fn written_rmem(&mut self) -> ChipReading {
        let mut written = Vec::new();
        for slot in 0..RMEM_SLOTS {
            match self.with(|s| s.r_mem_data_read(slot.into()).map(|data| data.len())) {
                Ok(0) | Err(Fault::SlotEmpty) => {}
                Ok(_bytes) => written.push(slot),
                Err(e) => {
                    return ChipReading::new(
                        "R-memory",
                        Err(format!("slot {slot} did not read: {e:?}")),
                    )
                }
            }
        }
        let listed = match written.first() {
            Some(_first) => {
                let first: Vec<String> = written
                    .iter()
                    .take(8)
                    .map(|slot| format!("{slot}"))
                    .collect();
                format!(" (first: {})", first.join(", "))
            }
            None => String::new(),
        };
        ChipReading::new(
            "R-memory",
            Ok(format!(
                "{} of {RMEM_SLOTS} slots written{listed}",
                written.len()
            )),
        )
    }

    /// The live counter; a virgin counter (never initialized) is initialized once to `h0`.
    pub fn counter_at_birth(&mut self, h0: u32) -> Result<u32, TropicError> {
        match self.with(|s| s.mcounter_get(COUNTER)) {
            Ok(h) => Ok(h),
            Err(Fault::CounterInvalid) => {
                self.with(|s| s.mcounter_init(COUNTER, h0)).map_err(fault)?;
                self.with(|s| s.mcounter_get(COUNTER)).map_err(fault)
            }
            Err(e) => Err(fault(e)),
        }
    }

    /// Whether this chip can take a birth, checked before anything is written to it: the counter at
    /// `h0`, the board's slot free or already the board's, and the cage not begun. A counter a used
    /// chip left elsewhere is set to `h0`, which only an uncaged chip allows. A chip refused here is
    /// left exactly as it was found.
    pub fn ready_for_birth(&mut self, h0: u32) -> Result<(), TropicError> {
        let own = PublicKey::from(&StaticSecret::from(self.pairing));
        if self.slot == FACTORY_SLOT {
            match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).copied()) {
                Ok(key) if key == *own.as_bytes() => {}
                Ok(_other) => {
                    return Err(TropicError::Refused(ChipRefusal::BoardSlotHoldsAnotherKey))
                }
                Err(Fault::InvalidKey | Fault::SlotEmpty) => {}
                Err(e) => return Err(fault(e)),
            }
            let writable = self
                .with(|s| s.i_config_read(PAIRING_KEY_WRITE.into()))
                .map_err(fault)?;
            if writable & (1u32 << (8 + FACTORY_SLOT)) == 0 {
                return Err(TropicError::Refused(ChipRefusal::BoardSlotNotWritable));
            }
        }
        let config = self
            .with(|s| s.i_config_read(I_CONFIG_WRITE.into()))
            .map_err(fault)?;
        if config & (1u32 << self.slot) == 0 {
            return Err(TropicError::Refused(ChipRefusal::AccessRulesNotWritable));
        }
        let live = self.with(|s| s.mcounter_get(COUNTER)).map_err(fault)?;
        if live != h0 {
            self.with(|s| s.mcounter_init(COUNTER, h0)).map_err(fault)?;
        }
        Ok(())
    }

    /// Go through what a birth asks of this chip with its permanent parts substituted: the counter
    /// moved and set back, each permanent command checked to be one the chip would take from the slot
    /// that will send it, and the reboot that latches the cage, session and all.
    fn rehearse_birth(&mut self, h0: u32) -> Vec<TryStep> {
        let mut steps = Vec::new();
        // The board's stepping is a note, not a requirement (owner, 2026-11-06).
        steps.push(TryStep::new(
            &format!(
                "{}; the board's RP2350 is stepping A{}",
                self.facts.describe(),
                self.board.silicon_revision()
            ),
            Ok(()),
        ));
        steps.push(TryStep::production(
            "the chip tests its PTRNG at start-up",
            self.randomness_tested(),
        ));
        steps.push(TryStep::new(
            "the chip's counter moves one step and is set back to its start",
            self.rehearse_counter(h0),
        ));
        steps.push(TryStep::new(
            "the chip would take the board's pairing key",
            self.rehearse_key_write()
                .map_err(|unrehearsed| unrehearsed.why),
        ));
        steps.push(TryStep::new(
            "the chip would let the board close it",
            self.rehearse_cage().map_err(|unrehearsed| unrehearsed.why),
        ));
        steps.push(TryStep::new(
            "the chip reboots and opens a session again",
            self.reopen(self.slot, Reboot::Latch)
                .map_err(|e| format!("{e:?}")),
        ));
        steps
    }

    /// Whether the chip tests its PTRNG at start-up. A chip that does not reached a try-run only on the
    /// trial image, whose check is off until the correction: the step says what is still to do.
    fn randomness_tested(&mut self) -> Result<(), String> {
        let start_up = self
            .with(|s| s.i_config_read(CFG_START_UP.into()))
            .map_err(|e| format!("{:?}", fault(e)))?;
        match start_up & (1u32 << RNGTEST_DIS_BIT) {
            0 => Ok(()),
            _untested => Err(
                "it does not, so what it generates may not be random (erratum OI_TR01_ERR_2026090100). \
                 Tropic Square's correction is irreversible: the prepare_chip image makes it at the last \
                 step and erases the key the chip holds now. Until then no install for good passes; a trial \
                 install does"
                    .to_string(),
            ),
        }
    }

    fn rehearse_counter(&mut self, h0: u32) -> Result<(), String> {
        let read = |this: &mut Self| {
            this.with(|s| s.mcounter_get(COUNTER))
                .map_err(|e| format!("{:?}", fault(e)))
        };
        let before = read(self)?;
        if before != h0 {
            return Err(format!("the counter holds {before}, not its start {h0}"));
        }
        self.with(|s| s.mcounter_update(COUNTER))
            .map_err(|e| format!("the update: {:?}", fault(e)))?;
        let moved = read(self)?;
        self.with(|s| s.mcounter_init(COUNTER, h0))
            .map_err(|e| format!("setting it back: {:?}", fault(e)))?;
        let back = read(self)?;
        if moved != h0 - 1 || back != h0 {
            return Err(format!(
                "from {h0} the counter went to {moved}, then {back}"
            ));
        }
        Ok(())
    }

    /// In place of the key write: the slot is free or already this board's, and the session that
    /// will write it holds the right to.
    fn rehearse_key_write(&mut self) -> Result<(), Unrehearsed> {
        let own = PublicKey::from(&StaticSecret::from(self.pairing));
        if self.slot != FACTORY_SLOT {
            return Ok(());
        }
        match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).copied()) {
            Ok(key) if key == *own.as_bytes() => {}
            Ok(_other) => {
                return Err(Unrehearsed::refused(
                    ChipRefusal::BoardSlotHoldsAnotherKey,
                    "another board's key holds the slot".to_string(),
                ))
            }
            Err(Fault::InvalidKey | Fault::SlotEmpty) => {}
            Err(e) => return Err(Unrehearsed::fault(e)),
        }
        let writable = self
            .with(|s| s.i_config_read(PAIRING_KEY_WRITE.into()))
            .map_err(Unrehearsed::fault)?;
        if writable & (1u32 << (8 + FACTORY_SLOT)) == 0 {
            return Err(Unrehearsed::refused(
                ChipRefusal::BoardSlotNotWritable,
                "the factory slot may not write the board's slot".to_string(),
            ));
        }
        Ok(())
    }

    /// In place of the cage: the chip answers for every register the cage writes, and the slot that
    /// will write them still may. A bit already clear is one the cage need not write.
    fn rehearse_cage(&mut self) -> Result<(), Unrehearsed> {
        for register in CAGE {
            self.with(|s| s.i_config_read(register.into()))
                .map_err(|e| {
                    let error = fault(e);
                    Unrehearsed {
                        error,
                        why: format!("register {register:#x}: {error:?}"),
                    }
                })?;
        }
        let writes = self
            .with(|s| s.i_config_read(I_CONFIG_WRITE.into()))
            .map_err(Unrehearsed::fault)?;
        if writes & own_bits(I_CONFIG_WRITE) != own_bits(I_CONFIG_WRITE) {
            return Err(Unrehearsed::refused(
                ChipRefusal::AccessRulesNotWritable,
                format!(
                    "the access rules hold {writes:#x}: the board's slot may no longer write them"
                ),
            ));
        }
        let invalidates = self
            .with(|s| s.i_config_read(PAIRING_KEY_INVALIDATE.into()))
            .map_err(Unrehearsed::fault)?;
        if invalidates & (1u32 << OWN_SLOT) == 0 {
            return Err(Unrehearsed::refused(
                ChipRefusal::FactorySlotNotInvalidatable,
                "the board's slot may not invalidate the factory slot".to_string(),
            ));
        }
        Ok(())
    }

    fn close_birth(&mut self, h0: u32) -> Result<(), TropicError> {
        let own = PublicKey::from(&StaticSecret::from(self.pairing));
        if self.slot == FACTORY_SLOT {
            match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).copied()) {
                Ok(key) if key == *own.as_bytes() => {}
                Ok(_other) => {
                    return Err(TropicError::Refused(ChipRefusal::BoardSlotHoldsAnotherKey))
                }
                Err(Fault::InvalidKey | Fault::SlotEmpty) => {
                    self.with(|s| s.pairing_key_write(u16::from(OWN_SLOT).into(), own.as_bytes()))
                        .map_err(fault)?;
                    // Firmware below 2.0.0 does not verify this write (OI_TR01_ERR_2025120100).
                    let held = self
                        .with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).copied())
                        .map_err(fault)?;
                    if held != *own.as_bytes() {
                        return Err(TropicError::Refused(ChipRefusal::BoardKeyNotAsWritten));
                    }
                }
                Err(e) => return Err(fault(e)),
            }
            self.reopen(OWN_SLOT, Reboot::Keep)?;
        }
        // Lane 0 of I_CONFIG_WRITE is cleared last: while it holds, the cage is not finished. Once
        // it is clear these commands are revoked, so a later boot must not take them again.
        let config = self
            .with(|s| s.i_config_read(I_CONFIG_WRITE.into()))
            .map_err(fault)?;
        if config & (1u32 << OWN_SLOT) != 0 {
            // The factory slot goes before the cage begins. A cut in the cage can leave invalidation
            // already revoked, and the slot already gone: lane 0 of its register says which.
            let invalidate = self
                .with(|s| s.i_config_read(PAIRING_KEY_INVALIDATE.into()))
                .map_err(fault)?;
            if invalidate & (1u32 << OWN_SLOT) != 0 {
                match self.with(|s| s.pairing_key_invalidate(u16::from(FACTORY_SLOT).into())) {
                    Ok(()) | Err(Fault::SlotInvalid | Fault::SlotEmpty | Fault::InvalidKey) => {}
                    Err(e) => return Err(fault(e)),
                }
            }
            for register in CAGE {
                let mut held = self
                    .with(|s| s.i_config_read(register.into()))
                    .map_err(fault)?;
                for lane in lanes_of(register) {
                    let bit = lane + OWN_SLOT;
                    if held & (1u32 << bit) != 0 {
                        self.with(|s| s.i_config_write(register.into(), bit))
                            .map_err(fault)?;
                        // Firmware below 2.0.0 does not verify this write (OI_TR01_ERR_2025120100).
                        // Each bit is read back before the next is cleared.
                        held &= !(1u32 << bit);
                        let now = self
                            .with(|s| s.i_config_read(register.into()))
                            .map_err(fault)?;
                        if now != held {
                            return Err(TropicError::Refused(ChipRefusal::AccessRuleNotAsWritten));
                        }
                    }
                }
            }
            self.reopen(OWN_SLOT, Reboot::Latch)?;
        }
        // The closed birth holds. First what the chip reports, which disturbs nothing: a probe of an
        // open cage would act.
        for register in CAGE {
            let held = self
                .with(|s| s.i_config_read(register.into()))
                .map_err(fault)?;
            if held & own_bits(register) != 0 {
                return Err(TropicError::CageOpen);
            }
        }
        // Then each command it denies is refused as unauthorized.
        denied(self.with(|s| s.mcounter_init(COUNTER, h0)))?;
        denied(self.with(|s| s.pairing_key_write(2u16.into(), own.as_bytes())))?;
        denied(self.with(|s| s.ecc_key_generate(31u16.into(), EccCurve::Ed25519)))?;
        denied(self.with(|s| s.i_config_write(I_CONFIG_WRITE.into(), OWN_SLOT)))
    }
}

/// Whether a reopen reboots the chip first, so a written access configuration is in force.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reboot {
    Keep,
    Latch,
}

/// The bits of `register` the board's own slot holds.
fn own_bits(register: u16) -> u32 {
    lanes_of(register)
        .iter()
        .fold(0u32, |bits, lane| bits | (1u32 << (lane + OWN_SLOT)))
}

/// The appliance's chip operations over the shared session. A trial install closes no birth: the
/// key write and the cage are checked as a try-run checks them, and nothing is written.
pub struct RealChip<SPI: SpiDevice, CS: OutputPin, B: Board> {
    pub session: Rc<RefCell<ChipSession<SPI, CS, B>>>,
    pub h0: u32,
    pub install: Install,
}

impl<SPI: SpiDevice, CS: OutputPin, B: Board> Tropic for RealChip<SPI, CS, B> {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        self.session
            .borrow_mut()
            .with(|s| s.mcounter_get(COUNTER))
            .map_err(fault)
    }

    fn counter_update(&mut self) -> Result<(), TropicError> {
        match self
            .session
            .borrow_mut()
            .with(|s| s.mcounter_update(COUNTER))
        {
            Ok(()) => Ok(()),
            Err(Fault::UpdateErr) => Err(TropicError::CounterExhausted),
            Err(e) => Err(fault(e)),
        }
    }

    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        self.session
            .borrow_mut()
            .with(|s| {
                s.eddsa_sign(CHIP_KEY_SLOT.into(), &message[..])
                    .map(|sig| sig.to_vec())
            })
            .map_err(fault)
    }

    fn chip_signature_holds(&self, pk_chip: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        matches!(
            (<[u8; 32]>::try_from(pk_chip), <[u8; 64]>::try_from(signature)),
            (Ok(key), Ok(signature)) if matches!(
                ed25519_dalek::VerifyingKey::from_bytes(&key).and_then(|key| key
                    .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))),
                Ok(())
            )
        )
    }

    fn close_birth(&mut self) -> Result<(), TropicError> {
        let mut session = self.session.borrow_mut();
        match self.install {
            Install::ForGood => session.close_birth(self.h0),
            Install::ForTrial => match (session.rehearse_key_write(), session.rehearse_cage()) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(unrehearsed), _) | (_, Err(unrehearsed)) => Err(unrehearsed.error),
            },
        }
    }

    fn set_counter_back(&mut self) -> Result<(), TropicError> {
        let h0 = self.h0;
        self.session
            .borrow_mut()
            .with(|s| s.mcounter_init(COUNTER, h0))
            .map_err(fault)
    }

    fn rehearse_birth(&mut self) -> Vec<TryStep> {
        self.session.borrow_mut().rehearse_birth(self.h0)
    }

    /// The board's TRNG, passed by its health tests, and the chip's own generator
    /// (`Random_Value_Get`). Either failing draws nothing.
    fn challenge_entropy(&mut self) -> Result<anchor_core::tropic::ChallengeEntropy, TropicError> {
        let mut session = self.session.borrow_mut();
        let board = session.board.random_key().ok_or(TropicError::NoEntropy)?;
        let drawn = session
            .with(|s| s.get_random_value(32).map(<[u8]>::to_vec))
            .map_err(fault)?;
        let chip = <[u8; 32]>::try_from(drawn.as_slice())
            .map_err(|_short| TropicError::Refused(ChipRefusal::ShortRandom))?;
        Ok(anchor_core::tropic::ChallengeEntropy { board, chip })
    }
}

impl<SPI: SpiDevice, CS: OutputPin, B: Board> Drop for ChipSession<SPI, CS, B> {
    fn drop(&mut self) {
        anchor_core::util::zeroize(&mut self.pairing);
    }
}

/// R-memory data slots over the shared session: the store the appliance's record lives in.
pub struct RMemSlots<SPI: SpiDevice, CS: OutputPin, B: Board> {
    pub session: Rc<RefCell<ChipSession<SPI, CS, B>>>,
}

impl<SPI: SpiDevice, CS: OutputPin, B: Board> SlotMemory for RMemSlots<SPI, CS, B> {
    fn capacity(&self) -> usize {
        RMEM_SLOT_BYTES
    }

    fn slots(&self) -> u16 {
        RMEM_SLOTS
    }

    fn read(&mut self, slot: u16) -> Result<Option<Vec<u8>>, StoreError> {
        match self
            .session
            .borrow_mut()
            .with(|s| s.r_mem_data_read(slot.into()).map(|data| data.to_vec()))
        {
            // The chip answers an erased slot with no bytes (libtropic: SLOT_EMPTY on a size of 0).
            Ok(data) if data.is_empty() => Ok(None),
            Ok(data) => Ok(Some(data)),
            Err(Fault::SlotEmpty) => Ok(None),
            Err(Fault::HardwareFail | Fault::L3CmdFailed) => Err(StoreError::Unreadable),
            Err(e) => Err(StoreError::Chip(fault(e))),
        }
    }

    fn erase(&mut self, slot: u16) -> Result<(), StoreError> {
        self.session
            .borrow_mut()
            .with(|s| s.r_mem_data_erase(slot.into()))
            .map_err(|e| StoreError::Chip(fault(e)))
    }

    fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
        let written = self
            .session
            .borrow_mut()
            .with(|s| s.r_mem_data_write(slot.into(), data));
        match written {
            Ok(()) => Ok(()),
            // Firmware 2.0.0 and later says so when a write did not hold, and Tropic Square's
            // correction is an erase, to restore a known state (OI_TR01_ERR_2025120100).
            Err(Fault::HardwareFail) => {
                self.erase(slot)?;
                Err(StoreError::NotHeld)
            }
            Err(e) => Err(StoreError::Chip(fault(e))),
        }
    }
}
