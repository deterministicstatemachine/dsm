//! `dsm-anchor-core` — hardware-free core of the DSM **Boot Fenced Fused Anchor**
//! offline-bearer authority (Pico 2 W / RP2350 secure partition + Secure Tropic
//! Click / TROPIC01).
//!
//! Neither the RP2350 partition nor the TROPIC01 is the transaction authorizer.
//! The authority *fuses three lineages into one non-interchangeable state* and
//! advances them together:
//!
//! - the **DSM SMT root** lineage (`hᵢ → hᵢ₊₁`, publicly verified),
//! - the **RP2350 secure partition** lineage (partition certificates, boot ratchet),
//! - the **TROPIC01** MACANDD/counter lineage (`u = H₀ − H`, hardware witness),
//!
//! bound by the **fused anchor head** `Aᵢ` and gated by a **boot fence** `J_b`:
//! offline mode is enabled only after a boot ticket chains from the DSM-committed
//! boot head, so a copied state image cannot resume offline on new hardware. A
//! **one-way birth fuse** makes enrollment non-recreatable from public data.
//!
//! This crate is `no_std` (+`alloc`) so the protocol math unit-tests on the host
//! (`cargo test -p dsm-anchor-core`) and builds for the RP2350 secure partition.
//! The firmware wires the real libtropic `MAC_And_Destroy`/`MCounter` and the
//! chosen signature schemes behind the [`tropic::Tropic`], [`tropic::WitnessSig`],
//! and [`tropic::PartitionSig`] traits.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod accept;
pub mod appliance;
pub mod boot;
pub mod domain;
pub mod enrollment;
pub mod hash;
pub mod proto;
pub mod root_advance;
pub mod service;
pub mod sig;
pub mod tropic;
pub mod util;
