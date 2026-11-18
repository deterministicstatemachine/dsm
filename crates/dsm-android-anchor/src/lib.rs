// SPDX-License-Identifier: MIT OR Apache-2.0
//! On-device glue for the DSM Software-Authority / Hardware-Identity anchor: the phone's USB link
//! to its own RP2350/TROPIC01 board, for paying and for receiving offline, and the board's setup
//! from the phone, installed into the `dsm_sdk` bridge seams.
//!
//! An offline payment needs a board on both sides (owner, 2026-11-07): the payer's makes the
//! release, and the receiver's draws the challenge, checks the payer's release itself and commits
//! the receive. A phone with no stamped board of its own neither pays nor receives offline. One
//! appliance factory serves both sides (`install::install_anchor_transport` →
//! [`usb_appliance::UsbAnchorAppliance`] over the opaque Kotlin USB round-trip in [`usb_pico`]),
//! installed with the board setup. The appliance provisions itself: the phone sends `OP_PROVISION`
//! with its device's identity, then the rehearsal's `OP_AUTHORIZE` when the board asks for it, and
//! the firmware closes the chip to a second birth. No raw SPI reaches the chip from the phone.
//!
//! Dependency direction is ONE-WAY (`dsm-android-anchor` -> `dsm_sdk`); `dsm_sdk` never depends
//! back on this crate. It is built in the Android cargo-ndk pipeline.
//!
//! Fail-closed everywhere: no factory installed -> every offline-bearer send errors
//! ("offline = chips"); a USB/chip failure inside any op -> `DsmError` -> no release.

// Tests use `.unwrap()`/`.expect()` freely; production code in this crate does not (the workspace
// `.clippy.toml` disallows them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod board_setup;
#[cfg(test)]
mod bootrom_model;
pub mod install;
pub mod otp_burn;
#[cfg(test)]
mod otp_burn_tests;
pub mod picoboot;
pub mod release;
pub mod usb_appliance;
pub mod usb_pico;
pub use usb_appliance::UsbAnchorAppliance;
pub use usb_pico::UsbTransceive;
