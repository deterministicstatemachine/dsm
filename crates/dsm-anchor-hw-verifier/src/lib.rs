// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM local-chip hardware provisioning (Software-Authority / Hardware-Identity) — the only crate
//! that depends on `tropic01` (the sibling libtropic-rs checkout). It is EXCLUDED from the
//! workspace so CI builds green without the sibling; build/test it directly on a machine that has
//! the sibling checkout:
//!
//! ```text
//! cargo build -p dsm-anchor-hw-verifier
//! cargo run   -p dsm-anchor-hw-verifier --example usb_counter_read   # real board attached
//! ```
//!
//! v2 removed every receiver-side hardware path (no relay, no peer counter read, no verifier
//! slot). What remains is device SETUP for the holder's OWN chip, over any
//! `dsm_anchor_verifier::SpiRelayChannel` (bench serial, or the phone's own USB
//! `OP_SPI_PASSTHROUGH` link): counter birth ([`init_counter_max`]), the irreversible slot-0
//! birth cage ([`birth_cage_slot0`]), and the non-destructive [`read_counter`] diagnostic.

// Tests use `.expect()`/`.unwrap()` freely (the workspace `.clippy.toml` disallows them in
// production; production code in this crate does not use them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod provisioner;

pub use provisioner::{
    birth_cage_slot0, init_counter_max, read_counter, ProvisionError, MCOUNTER_MAX,
    SLOT0_BIRTH_DENY,
};
