// SPDX-License-Identifier: MIT OR Apache-2.0
//! `tropic01`-free SPI transport spine for driving a TROPIC01 through an opaque byte tunnel
//! (Software-Authority / Hardware-Identity).
//!
//! v2 removed the receiver-side counter relay entirely — no receiver ever reads a peer's chip.
//! What remains is the LOCAL-chip plumbing: a host (bench CLI, or the phone over its own USB
//! link to its own Pico via `OP_SPI_PASSTHROUGH`) runs the full libtropic-rs stack against its
//! OWN chip for provisioning and diagnostics. This crate provides the pieces with NO `tropic01`
//! dependency, so it builds in CI without the sibling libtropic checkout: [`RemoteSpiDevice`]
//! (the `embedded_hal::spi::SpiDevice` the driver runs on) and [`SpiRelayChannel`] (the pluggable
//! byte tunnel). The actual libtropic session drivers (counter birth, slot-0 cage, reads) live in
//! the excluded `dsm-anchor-hw-verifier` crate — the only thing that depends on `tropic01`.

// Tests use `.expect()`/`.unwrap()` freely (the workspace `.clippy.toml` disallows them in
// production; production code in this crate does not use them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod remote_spi;

pub use remote_spi::{RelayError, RemoteSpiDevice, SpiRelayChannel};
