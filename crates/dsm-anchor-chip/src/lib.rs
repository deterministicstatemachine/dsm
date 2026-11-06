// SPDX-License-Identifier: MIT OR Apache-2.0
//! The anchor's TROPIC01 side, free of the RP2350: the chip session and the bring-up that turns a
//! chip and a sealed secret into an anchor.
//!
//! The Secure monitor runs this code on the board. `tests/chip_model.rs` runs the same code against
//! Tropic Square's own TROPIC01 model, so a birth, a cage and a power cut are exercised before any
//! chip is written.

#![no_std]

extern crate alloc;

pub mod bring_up;
pub mod session;

/// What a chip session needs from the board it runs on.
pub trait Board {
    /// 32 bytes no one else has seen, for one session's ephemeral key. `None` when the board's entropy
    /// source fails its own health tests: no session opens on anything less.
    fn random_key(&self) -> Option<[u8; 32]>;
    /// Wait about 100 ms: the gap the chip needs between back-to-back reads, and one poll of a chip
    /// that is rebooting.
    fn wait_100ms(&self);
    /// A chip command is about to run: the operation in progress is alive.
    fn alive(&self);
    /// The stepping of the board's RP2350: 2 for A2, 3 for A3, 4 for A4.
    fn silicon_revision(&self) -> u8;
}

/// The first RP2350 stepping an anchor is installed on. A2 and A3 can be made to run unsigned code by
/// a physical glitch at boot, with no workaround (errata RP2350-E24, and on A2 also E16, E20, E21).
pub const MIN_SILICON_REVISION: u8 = 4;

/// What a bring-up does with a chip whose PTRNG Tropic Square left untested (erratum
/// OI_TR01_ERR_2026090100, the T101 and T103 parts).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UntestedRandomness {
    /// Give it nothing: an anchor's keys come only from a PTRNG the chip tests.
    Refuse,
    /// The trial image (owner, 2026-11-06; CONFORMANCE_GAPS §6.152). Tropic Square's correction is
    /// irreversible, so it is not made until the last step: the check is off for the trial, the chip
    /// may generate the trial's key, which the correction erases, and the try-run reports the
    /// correction as not made, so no install passes. The production image always refuses.
    KeyForTrial,
}

/// The Secure heap the monitor gives the anchor. Its size is here so that the rehearsal holds every
/// operation to it.
pub const SECURE_HEAP_BYTES: usize = 160 * 1024;

/// The largest request frame the monitor takes. A prepare holds its transition several times over
/// while it signs and records it, so a larger one could exhaust the heap and halt the board. The
/// wallet's own requests are a few hundred bytes: it attaches its proofs after the emit.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024;
