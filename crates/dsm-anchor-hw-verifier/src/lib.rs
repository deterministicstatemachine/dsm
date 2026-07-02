// SPDX-License-Identifier: MIT OR Apache-2.0
//! The DSM Boot Fenced Fused Anchor Path-B HARDWARE verifier — the only crate that depends on
//! `tropic01` (the sibling libtropic-rs checkout). It is EXCLUDED from the workspace so CI builds
//! green without the sibling; build/test it directly on a machine that has the sibling checkout:
//!
//! ```text
//! cargo build -p dsm-anchor-hw-verifier
//! cargo run   -p dsm-anchor-hw-verifier --example usb_counter_read   # real board attached
//! ```
//!
//! It runs the receiver's full libtropic session — `Tropic01::new(RemoteSpiDevice)` → `session_start`
//! → `mcounter_get` — over the `tropic01`-free relay spine from `dsm-anchor-verifier`, and joins it
//! to a caller-supplied async transport round-trip ([`read_counter_over_relay`]). The DSM SDK stays
//! free of `tropic01`; the on-device layer wires its BLE round-trip into this reader.

// Tests use `.expect()`/`.unwrap()` freely (the workspace `.clippy.toml` disallows them in
// production; production code in this crate does not use them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod reader;
mod relay_driver;
mod session;

pub use reader::{derive_pairing_pubkey, RelayCounterReader, RelayRoundTrip, SeedPairingDeriver};
pub use relay_driver::read_counter_over_relay;
pub use session::{read_live_counter, VerifierError, VerifierSessionCredential};
