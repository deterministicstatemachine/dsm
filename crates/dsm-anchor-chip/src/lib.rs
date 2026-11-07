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

/// The Secure heap the monitor gives the anchor. Its size is here so that the rehearsal holds every
/// operation to it.
pub const SECURE_HEAP_BYTES: usize = 160 * 1024;

/// The largest request frame the monitor takes but a payment check. A prepare holds its transition
/// several times over while it signs and records it, so a larger one could exhaust the heap and halt
/// the board. The wallet's own requests are a few hundred bytes: it attaches its proofs after the emit.
pub const MAX_REQUEST_BYTES: usize = anchor_core::service::MAX_REQUEST_BYTES;

/// The largest frame the monitor takes at all: a payment check, the payer's certificate with its
/// 49,856-byte `σ^host`. The anchor serves a frame this large only as a payment check, and only while
/// it holds no record ([`anchor_core::service::handle`]), so its copies never meet a record's.
pub const MAX_FRAME_BYTES: usize = anchor_core::service::MAX_PAYMENT_CHECK_BYTES;
