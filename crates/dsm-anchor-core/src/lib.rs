//! `dsm-anchor-core` — hardware-free core of the DSM **Software Authority, Hardware
//! Identity** offline anchor (Pico 2 W / RP2350 secure partition + TROPIC01).
//!
//! Transfer uniqueness is a **software** property of the DSM device SMT: one parent device
//! root `Rᵢ` admits at most one accepted successor per receiver, and the offline frontier
//! `hᵢ → hᵢ₊₁` is forward-only, so a release claiming an already-consumed frontier is
//! rejected on sight. Cross-receiver forks are position collisions exposed by Tripwire on
//! reconciliation (a detection bound), not prevented on the acceptance path.
//!
//! Hardware provides **identity**, not authority. Each root advance binds one root-advance
//! message `Mᵢ₊₁` under three independent signatures:
//! - `σ^DSM` — the seed-derived DSM device signature over the transition core `Δ°`,
//! - `σ^chip` — a **resident non-exportable Ed25519 key inside TROPIC01** (its private half
//!   never leaves the die; at-rest protection is the die's PUF), verified against `pk_chip`
//!   pinned in the anchor bundle `B`,
//! - `σ^host` — the RP2350 secure-partition key, verified against `pk_host` pinned in `B`.
//!
//! The TROPIC01 monotonic counter is demoted to a **non-rewind floor + offline exposure
//! cap**; it appears in acceptance only as the signed pair `(uᵢ, uᵢ+1)` and is **never read
//! by the receiver** (Corollary 1: delete every hardware component and the acceptance
//! predicate is unchanged, because the chip/host signatures verify against public keys).
//!
//! This crate is `no_std` (+`alloc`) so the protocol math unit-tests on the host
//! (`cargo test -p dsm-anchor-core`) and builds for the RP2350 secure partition. The
//! firmware wires the real libtropic `ECC_Key`/`EdDSA` (the resident chip key) and
//! `MCounter` (the floor) behind [`tropic::Tropic`], and the chosen partition scheme behind
//! [`tropic::PartitionSig`]; receivers verify with [`tropic::ChipSig`] + [`tropic::PartitionSig`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod accept;
pub mod appliance;
pub mod domain;
pub mod enrollment;
pub mod hash;
pub mod proto;
pub mod root_advance;
pub mod service;
pub mod tropic;
pub mod util;
