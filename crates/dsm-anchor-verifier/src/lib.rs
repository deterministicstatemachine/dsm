// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receiver-side Path-B relay primitives for the DSM Boot Fenced Fused Anchor — the CI-tested,
//! `tropic01`-free core.
//!
//! # Trust model (Path B, L1 raw-SPI relay)
//!
//! The receiver (**Phone B**) authenticates the SENDER's TROPIC01 counter itself by running the
//! full libtropic-rs stack as if the sender's chip were locally attached, tunnelling every SPI
//! transaction:
//!
//! ```text
//! Phone B (libtropic-rs) -> Phone A -> Pico A -> TROPIC01 A
//! ```
//!
//! **Phone A and Pico A only carry raw SPI bytes** — the AES-256-GCM libtropic session that protects
//! the read lives end-to-end between Phone B and the chip. A is pure transport; B is the endpoint.
//!
//! This crate provides the transport spine that has NO `tropic01` dependency, so it builds in CI
//! without the sibling libtropic checkout: [`RemoteSpiDevice`] (the `embedded_hal::spi::SpiDevice`
//! the driver runs on), [`SpiRelayChannel`] (the pluggable byte tunnel), the sync↔async
//! [`relay_bridge`], and the exact [`counter_matches`] check. The actual libtropic session driver
//! (`read_live_counter` / `read_counter_over_relay`) lives in the excluded `dsm-anchor-hw-verifier`
//! crate, which is the only thing that depends on `tropic01` and is not built by CI.

// Tests use `.expect()`/`.unwrap()` freely (the workspace `.clippy.toml` disallows them in
// production; production code in this crate does not use them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod counter;
mod relay_bridge;
mod remote_spi;

pub use counter::counter_matches;
pub use relay_bridge::{relay_bridge, RelayChannel, RelayExchange, RelayPump};
pub use remote_spi::{RelayError, RemoteSpiDevice, SpiRelayChannel};
