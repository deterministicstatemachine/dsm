//! `dsm-anchor-core` — hardware-free core of the DSM **Software Authority, Hardware
//! Identity** offline anchor (Pico 2 W / RP2350 secure partition + TROPIC01).
//!
//! Transfer uniqueness is a **software** property of the DSM device SMT: one parent device
//! root `Rᵢ` admits at most one accepted successor per receiver, and the offline frontier
//! `hᵢ → hᵢ₊₁` is forward-only, so a release claiming an already-consumed frontier is
//! rejected on sight.
//!
//! Across two receivers, nothing detects a fork, offline or later. An intact board cannot make
//! one: it prepares a payment only from its current frontier and releases it only once committed,
//! which moves the frontier on ([`appliance::Appliance::prepare`], [`appliance::Appliance::emit`]).
//! A board broken open can sign two payments from one frontier. Each receiver, checking alone
//! offline, takes its own; the payer's next boundary carries only one of them, and the other never
//! settles, with nothing raised about it.
//!
//! Hardware provides **identity**, not authority. Each root advance binds one root-advance
//! message `Mᵢ₊₁` under three independent signatures:
//! - `σ^DSM` — the seed-derived DSM device signature over the transition core `Δ°`,
//! - `σ^chip` — a **resident non-exportable Ed25519 key inside TROPIC01** (its private half
//!   never leaves the die; at-rest protection is the die's PUF), verified against `pk_chip`
//!   pinned in the anchor bundle `B`,
//! - `σ^host` — the RP2350 secure-partition key, verified against `pk_host` pinned in `B`.
//!
//! The partition key behind `σ^host` is BLAKE3-SPHINCS+ SPX128f, derived at every boot from the
//! secret the board drew and sealed in its own OTP at its first signed boot ([`seal`], DSM Amendment
//! A38): no phone or computer ever holds it.
//!
//! The TROPIC01 monotonic counter is demoted to a **non-rewind floor + offline exposure
//! cap**; it appears in acceptance only as the signed pair `(uᵢ, uᵢ+1)` and is **never read
//! by the receiver**: the verifier has no live-hardware dependency on the payer's board — it
//! verifies signed identity evidence against the enrolled public keys. Removing the live hardware
//! checks does not remove the chip and host witness requirements (§ Corollary 1).
//!
//! What a board does around that:
//! - **It signs only for its owner.** It prepares a payment only under an authorization by the owner's
//!   device key `pk_on` (SPX256f) over its bundle, frontier, the payment and a nonce it drew itself
//!   ([`appliance::owner_authorization_digest`]). It holds no owner's key.
//! - **A payment has a board on both sides** (owner, 2026-11-07). The receiver's board draws the
//!   challenge the payer's release must answer, checks that release itself, and commits the receive
//!   as a root advance of its own, whose certificate is the payer's acknowledgement ([`receive`]).
//! - **It carries the owner's stamp** (DSM Amendment A38): his signature over its `anchor_id`,
//!   `pk_host` and `pk_chip`, kept before its install and checked under the stamp keys compiled into
//!   its firmware and the wallet. A receiving board refuses a payer board without one ([`stamp`]).
//! - **It is installed once, after a try-run.** The owner's device provisions it a single time with
//!   the identity its bundle `B` binds, only after a try-run has gone through the install on the real
//!   chip with its permanent steps substituted ([`try_run`]).
//! - **Its state outlives a power cut.** Its record is kept in TROPIC01 R-memory, in two banks under
//!   two headers ([`rmem`]), written at every durable point and restored at boot through §26
//!   recovery ([`durable::DurableAppliance`]).
//!
//! This crate is `no_std` (+`alloc`) so the protocol math unit-tests on the host
//! (`cargo test -p dsm-anchor-core`) and builds for the RP2350 secure partition. It reaches the
//! chip only through [`tropic::Tropic`] and the partition scheme only through
//! [`tropic::PartitionSig`]. The board's code wires them: `dsm-anchor-chip` drives the TROPIC01
//! through Tropic Square's `tropic01` driver (the resident Ed25519 key in an ECC slot, the
//! monotonic counter, R-memory), and `dsm-anchor-secure-monitor` is the RP2350 Secure firmware that
//! runs it. Receivers verify with [`tropic::ChipSig`] + [`tropic::PartitionSig`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod accept;
pub mod anchor;
pub mod appliance;
pub mod domain;
pub mod durable;
pub mod enrollment;
pub mod hash;
pub mod identify;
pub mod proto;
pub mod receive;
pub mod rmem;
pub mod root_advance;
pub mod seal;
pub mod service;
pub mod stamp;
pub mod tropic;
pub mod try_run;
pub mod util;
