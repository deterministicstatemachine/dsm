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

use alloc::format;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::durable::StoreError;
use anchor_core::rmem::SlotMemory;
use anchor_core::tropic::{Tropic, TropicError};
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

/// The driver's fault over this SPI device and chip-select.
pub type ChipFault<SPI, CS> = Fault<
    <SPI as embedded_hal::spi::ErrorType>::Error,
    <CS as embedded_hal::digital::ErrorType>::Error,
>;

/// A session start the chip refused, with the chip handed back.
type StartRefused<SPI, CS> = (Tropic01<SPI, CS, NoSession>, ChipFault<SPI, CS>);

/// A probe of a command the closed birth denies: proven closed only by the chip refusing it as
/// unauthorized. Any other refusal means the command got past the access check, which is an open
/// cage, as is a command it accepts; a transport failure proves nothing and is reported.
fn denied<R, ES, EG>(probe: Result<R, Fault<ES, EG>>) -> Result<(), TropicError> {
    match probe {
        Ok(_accepted) => Err(TropicError::CageOpen),
        Err(Fault::Unauthorized) => Ok(()),
        Err(e) => match fault(e) {
            TropicError::Refused => Err(TropicError::CageOpen),
            other => Err(other),
        },
    }
}

/// A driver fault as the appliance reports it: the transport failed, or the chip refused.
pub fn fault<ES, EG>(e: Fault<ES, EG>) -> TropicError {
    match e {
        Fault::AlarmMode
        | Fault::BusError(..)
        | Fault::ChipBusy
        | Fault::Decryption(..)
        | Fault::Encryption(..)
        | Fault::GPIOError(..)
        | Fault::HandshakeFailed
        | Fault::InvalidChipStatus(..)
        | Fault::InvalidCRC
        | Fault::InvalidL2Response
        | Fault::InvalidResponse
        | Fault::L3ResponseBufferOverflow
        | Fault::ParsingError(..)
        | Fault::HardwareFail
        | Fault::UnexpectedResponseStatus => TropicError::Comm,
        Fault::InvalidKey
        | Fault::InvalidL3Cmd
        | Fault::InvalidPublicKey
        | Fault::InvalidParameter
        | Fault::L2ResponseError(..)
        | Fault::L3CmdFailed
        | Fault::RequestExceedsSize
        | Fault::SlotNotEmpty
        | Fault::SlotExpired
        | Fault::UpdateErr
        | Fault::CounterInvalid
        | Fault::SlotEmpty
        | Fault::SlotInvalid
        | Fault::Unauthorized => TropicError::Refused,
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
    board: B,
}

impl<SPI: SpiDevice, CS: OutputPin, B: Board> ChipSession<SPI, CS, B> {
    /// Open the chip on the board's own slot if it holds the board's key, else on the factory
    /// slot (an unborn chip).
    pub fn open(
        chip: Tropic01<SPI, CS, NoSession>,
        pairing: [u8; 32],
        board: B,
    ) -> Result<Self, OpenRefused<ChipFault<SPI, CS>>> {
        let mut this = Self {
            session: None,
            pairing,
            slot: OWN_SLOT,
            board,
        };
        match this.start(chip, OWN_SLOT) {
            Ok(session) => {
                this.session = Some(session);
                Ok(this)
            }
            Err((chip, own_slot)) => match this.start(chip, FACTORY_SLOT) {
                Ok(session) => {
                    this.session = Some(session);
                    this.slot = FACTORY_SLOT;
                    Ok(this)
                }
                Err((_chip, factory_slot)) => Err(OpenRefused {
                    own_slot,
                    factory_slot,
                }),
            },
        }
    }

    fn start(
        &self,
        chip: Tropic01<SPI, CS, NoSession>,
        slot: u8,
    ) -> Result<Tropic01<SPI, CS, ActiveSession>, StartRefused<SPI, CS>> {
        let eh = StaticSecret::from(core::array::from_fn::<u8, 32, _>(|_position| {
            self.board.random_byte()
        }));
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

    /// End the session, optionally reboot the chip, and open again on `slot`.
    fn reopen(&mut self, slot: u8, reboot: Reboot) -> Result<(), TropicError> {
        let session = self.session.take().ok_or(TropicError::Comm)?;
        let mut chip = match session.session_abort() {
            Ok(chip) => chip,
            Err((session, e)) => {
                self.session = Some(session);
                return Err(fault(e));
            }
        };
        if reboot == Reboot::Latch {
            chip.startup_req(StartupReq::Reboot).map_err(fault)?;
            // Up to ~10 s for the chip to answer again.
            let mut polls = 0u32;
            loop {
                match chip.get_info_chip_id() {
                    Ok(_id) => break,
                    Err(e) if polls >= 100 => return Err(fault(e)),
                    Err(_booting) => {
                        self.board.alive();
                        self.board.wait_100ms();
                        polls += 1;
                    }
                }
            }
        }
        match self.start(chip, slot) {
            Ok(session) => {
                self.session = Some(session);
                self.slot = slot;
                Ok(())
            }
            Err((_chip, e)) => Err(fault(e)),
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
            return Err(TropicError::Refused);
        }
        Ok(pk)
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
            match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).map(|k| *k)) {
                Ok(key) if key == *own.as_bytes() => {}
                Ok(_other) => return Err(TropicError::Refused),
                Err(Fault::InvalidKey | Fault::SlotEmpty) => {}
                Err(e) => return Err(fault(e)),
            }
            let writable = self
                .with(|s| s.i_config_read(PAIRING_KEY_WRITE.into()))
                .map_err(fault)?;
            if writable & (1u32 << (8 + FACTORY_SLOT)) == 0 {
                return Err(TropicError::Refused);
            }
        }
        let config = self
            .with(|s| s.i_config_read(I_CONFIG_WRITE.into()))
            .map_err(fault)?;
        if config & (1u32 << self.slot) == 0 {
            return Err(TropicError::Refused);
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
        steps.push(TryStep::new(
            "the chip's counter moves one step and is set back to its start",
            self.rehearse_counter(h0),
        ));
        steps.push(TryStep::new(
            "the chip would take the board's pairing key",
            self.rehearse_key_write(),
        ));
        steps.push(TryStep::new(
            "the chip would let the board close it",
            self.rehearse_cage(),
        ));
        steps.push(TryStep::new(
            "the chip reboots and opens a session again",
            self.reopen(self.slot, Reboot::Latch)
                .map_err(|e| format!("{e:?}")),
        ));
        steps
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
    fn rehearse_key_write(&mut self) -> Result<(), String> {
        let own = PublicKey::from(&StaticSecret::from(self.pairing));
        if self.slot != FACTORY_SLOT {
            return Ok(());
        }
        match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).map(|k| *k)) {
            Ok(key) if key == *own.as_bytes() => {}
            Ok(_other) => return Err("another board's key holds the slot".to_string()),
            Err(Fault::InvalidKey | Fault::SlotEmpty) => {}
            Err(e) => return Err(format!("{:?}", fault(e))),
        }
        let writable = self
            .with(|s| s.i_config_read(PAIRING_KEY_WRITE.into()))
            .map_err(|e| format!("{:?}", fault(e)))?;
        if writable & (1u32 << (8 + FACTORY_SLOT)) == 0 {
            return Err("the factory slot may not write the board's slot".to_string());
        }
        Ok(())
    }

    /// In place of the cage: the chip answers for every register the cage writes, and the slot that
    /// will write them still may. A bit already clear is one the cage need not write.
    fn rehearse_cage(&mut self) -> Result<(), String> {
        for register in CAGE {
            self.with(|s| s.i_config_read(register.into()))
                .map_err(|e| format!("register {register:#x}: {:?}", fault(e)))?;
        }
        let writes = self
            .with(|s| s.i_config_read(I_CONFIG_WRITE.into()))
            .map_err(|e| format!("{:?}", fault(e)))?;
        if writes & own_bits(I_CONFIG_WRITE) != own_bits(I_CONFIG_WRITE) {
            return Err(format!(
                "the access rules hold {writes:#x}: the board's slot may no longer write them"
            ));
        }
        let invalidates = self
            .with(|s| s.i_config_read(PAIRING_KEY_INVALIDATE.into()))
            .map_err(|e| format!("{:?}", fault(e)))?;
        if invalidates & (1u32 << OWN_SLOT) == 0 {
            return Err("the board's slot may not invalidate the factory slot".to_string());
        }
        Ok(())
    }

    fn close_birth(&mut self, h0: u32) -> Result<(), TropicError> {
        let own = PublicKey::from(&StaticSecret::from(self.pairing));
        if self.slot == FACTORY_SLOT {
            match self.with(|s| s.pairing_key_read(u16::from(OWN_SLOT).into()).map(|k| *k)) {
                Ok(key) if key == *own.as_bytes() => {}
                Ok(_other) => return Err(TropicError::Refused),
                Err(Fault::InvalidKey | Fault::SlotEmpty) => self
                    .with(|s| s.pairing_key_write(u16::from(OWN_SLOT).into(), own.as_bytes()))
                    .map_err(fault)?,
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
                let held = self
                    .with(|s| s.i_config_read(register.into()))
                    .map_err(fault)?;
                for lane in lanes_of(register) {
                    let bit = lane + OWN_SLOT;
                    if held & (1u32 << bit) != 0 {
                        self.with(|s| s.i_config_write(register.into(), bit))
                            .map_err(fault)?;
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

/// The appliance's chip operations over the shared session.
pub struct RealChip<SPI: SpiDevice, CS: OutputPin, B: Board> {
    pub session: Rc<RefCell<ChipSession<SPI, CS, B>>>,
    pub h0: u32,
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
        self.session.borrow_mut().close_birth(self.h0)
    }

    fn rehearse_birth(&mut self) -> Vec<TryStep> {
        self.session.borrow_mut().rehearse_birth(self.h0)
    }
}

/// R-memory data slots over the shared session: the store the appliance's record lives in.
pub struct RMemSlots<SPI: SpiDevice, CS: OutputPin, B: Board> {
    pub session: Rc<RefCell<ChipSession<SPI, CS, B>>>,
}

fn store_fault(e: TropicError) -> StoreError {
    match e {
        TropicError::Comm => StoreError::Unavailable,
        TropicError::Refused | TropicError::CounterExhausted | TropicError::CageOpen => {
            StoreError::Refused
        }
    }
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
            Err(e) => Err(store_fault(fault(e))),
        }
    }

    fn erase(&mut self, slot: u16) -> Result<(), StoreError> {
        self.session
            .borrow_mut()
            .with(|s| s.r_mem_data_erase(slot.into()))
            .map_err(|e| store_fault(fault(e)))
    }

    fn write(&mut self, slot: u16, data: &[u8]) -> Result<(), StoreError> {
        self.session
            .borrow_mut()
            .with(|s| s.r_mem_data_write(slot.into(), data))
            .map_err(|e| store_fault(fault(e)))
    }
}
