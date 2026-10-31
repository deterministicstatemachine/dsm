// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TROPIC01 as the appliance holds it: one authenticated session, shared by the appliance's
//! chip operations and its R-memory store, and reopened when the chip reboots to latch its cage.
//!
//! An unborn chip is opened on its factory pairing slot 0, whose key is public. Closing the birth
//! writes the board's own pairing key (derived from the sealed secret) into slot 1, moves the
//! session there, invalidates slot 0, revokes from slot 1 every command a second birth would use
//! (counter initialization, pairing-key writes and invalidation, resident-key generation, storage
//! and erasure, and last the access-configuration write itself), reboots the chip so the revocation
//! is in force, and verifies it. Each step is checked before it is taken, so a power cut anywhere
//! leaves a sequence the next boot completes.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use anchor_core::durable::StoreError;
use anchor_core::rmem::SlotMemory;
use anchor_core::tropic::{Tropic, TropicError};
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiDevice;
use rp235x_hal as hal;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{
    ActiveSession, EccCurve, EccOrigin, Error as Fault, MCounterIndex, NoSession, StartupReq,
    Tropic01, X25519Dalek,
};
use x25519_dalek::{PublicKey, StaticSecret};

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

/// The access-configuration lanes: each register carries one bit per pairing slot in each lane.
const LANES: [u8; 4] = [0, 8, 16, 24];
/// The commands a second birth would use, revoked from the board's own slot. `I_CONFIG_WRITE` is
/// last, so the slot can no longer loosen its own cage once it is closed.
const CAGE: [u16; 7] = [
    0x150, // MCOUNTER_INIT
    0x020, // PAIRING_KEY_WRITE
    0x028, // PAIRING_KEY_INVALIDATE
    0x130, // ECC_KEY_GENERATE
    0x134, // ECC_KEY_STORE
    0x13C, // ECC_KEY_ERASE
    0x040, // I_CONFIG_WRITE
];

type ChipFault<SPI, CS> = Fault<
    <SPI as embedded_hal::spi::ErrorType>::Error,
    <CS as embedded_hal::digital::ErrorType>::Error,
>;

/// A session start the chip refused, with the chip handed back.
type StartRefused<SPI, CS> = (Tropic01<SPI, CS, NoSession>, ChipFault<SPI, CS>);

/// A probe of a command the closed birth denies: proven closed only by the chip's refusal. A
/// command it accepts is an open cage; a transport failure proves nothing and is reported.
fn denied<R, ES, EG>(probe: Result<R, Fault<ES, EG>>) -> Result<(), TropicError> {
    match probe {
        Ok(_accepted) => Err(TropicError::CageOpen),
        Err(e) => match fault(e) {
            TropicError::Refused => Ok(()),
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
pub struct ChipSession<SPI: SpiDevice, CS: OutputPin> {
    session: Option<Tropic01<SPI, CS, ActiveSession>>,
    /// The board's own pairing secret (derived from the sealed secret).
    pairing: [u8; 32],
    /// The pairing slot the session runs on.
    slot: u8,
    rosc: hal::rosc::RingOscillator<hal::rosc::Enabled>,
}

impl<SPI: SpiDevice, CS: OutputPin> ChipSession<SPI, CS> {
    /// Open the chip on the board's own slot if it holds the board's key, else on the factory
    /// slot (an unborn chip).
    pub fn open(
        chip: Tropic01<SPI, CS, NoSession>,
        pairing: [u8; 32],
        rosc: hal::rosc::RingOscillator<hal::rosc::Enabled>,
    ) -> Result<Self, OpenRefused<ChipFault<SPI, CS>>> {
        let mut this = Self {
            session: None,
            pairing,
            slot: OWN_SLOT,
            rosc,
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

    fn random_byte(&self, _position: usize) -> u8 {
        (0..8).fold(0u8, |acc, _bit| {
            (acc << 1) | u8::from(self.rosc.get_random_bit())
        })
    }

    fn start(
        &self,
        chip: Tropic01<SPI, CS, NoSession>,
        slot: u8,
    ) -> Result<Tropic01<SPI, CS, ActiveSession>, StartRefused<SPI, CS>> {
        let eh = StaticSecret::from(core::array::from_fn::<u8, 32, _>(|position| {
            self.random_byte(position)
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
            // ~100 ms per poll at 150 MHz, up to ~10 s for the chip to answer again.
            let mut polls = 0u32;
            loop {
                match chip.get_info_chip_id() {
                    Ok(_id) => break,
                    Err(e) if polls >= 100 => return Err(fault(e)),
                    Err(_booting) => {
                        cortex_m::asm::delay(15_000_000);
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
        match self.with(|s| s.pairing_key_invalidate(u16::from(FACTORY_SLOT).into())) {
            Ok(()) | Err(Fault::SlotInvalid | Fault::SlotEmpty | Fault::InvalidKey) => {}
            Err(e) => return Err(fault(e)),
        }
        let config_open = self
            .with(|s| s.i_config_read(0x040u16.into()))
            .map_err(fault)?;
        if config_open & own_bits() != 0 {
            for register in CAGE {
                let held = self
                    .with(|s| s.i_config_read(register.into()))
                    .map_err(fault)?;
                for lane in LANES {
                    let bit = lane + OWN_SLOT;
                    if held & (1u32 << bit) != 0 {
                        self.with(|s| s.i_config_write(register.into(), bit))
                            .map_err(fault)?;
                    }
                }
            }
        }
        self.reopen(OWN_SLOT, Reboot::Latch)?;
        // The closed birth holds: each command it denies is refused.
        denied(self.with(|s| s.mcounter_init(COUNTER, h0)))?;
        denied(self.with(|s| s.pairing_key_write(2u16.into(), own.as_bytes())))?;
        denied(self.with(|s| s.ecc_key_generate(31u16.into(), EccCurve::Ed25519)))?;
        denied(self.with(|s| s.i_config_write(0x040u16.into(), OWN_SLOT)))
    }
}

/// Whether a reopen reboots the chip first, so a written access configuration is in force.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reboot {
    Keep,
    Latch,
}

fn own_bits() -> u32 {
    LANES
        .iter()
        .fold(0u32, |bits, lane| bits | (1u32 << (lane + OWN_SLOT)))
}

/// The appliance's chip operations over the shared session.
pub struct RealChip<SPI: SpiDevice, CS: OutputPin> {
    pub session: Rc<RefCell<ChipSession<SPI, CS>>>,
    pub h0: u32,
}

impl<SPI: SpiDevice, CS: OutputPin> Tropic for RealChip<SPI, CS> {
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

    fn close_birth(&mut self) -> Result<(), TropicError> {
        self.session.borrow_mut().close_birth(self.h0)
    }
}

/// R-memory data slots over the shared session: the store the appliance's record lives in.
pub struct RMemSlots<SPI: SpiDevice, CS: OutputPin> {
    pub session: Rc<RefCell<ChipSession<SPI, CS>>>,
}

fn store_fault(e: TropicError) -> StoreError {
    match e {
        TropicError::Comm => StoreError::Unavailable,
        TropicError::Refused | TropicError::CounterExhausted | TropicError::CageOpen => {
            StoreError::Refused
        }
    }
}

impl<SPI: SpiDevice, CS: OutputPin> SlotMemory for RMemSlots<SPI, CS> {
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
