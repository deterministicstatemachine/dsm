// SPDX-License-Identifier: MIT OR Apache-2.0
//! On-device glue for the DSM Software-Authority / Hardware-Identity anchor: the SENDER phone's
//! USB link to its own RP2350/TROPIC01 appliance, installed into the `dsm_sdk` bridge seam.
//!
//! v2 removed every receiver-side hardware path — a receiver accepts a release from three
//! signatures + the in-release SMT proofs and needs NO chip, NO relay, NO verifier slot. The one
//! device-layer install that remains is the sender's appliance factory
//! ([`install::install_anchor_transport`] → [`usb_appliance::UsbAnchorAppliance`] over the opaque
//! Kotlin USB round-trip in [`usb_pico`]). The appliance provisions itself: the phone sends one
//! `OP_PROVISION` with its device's identity, and the firmware closes the chip to a second birth.
//! No raw SPI reaches the chip from the phone.
//!
//! Dependency direction is ONE-WAY (`dsm-android-anchor` -> `dsm_sdk`); `dsm_sdk` never depends
//! back on this crate. It is built in the Android cargo-ndk pipeline.
//!
//! Fail-closed everywhere: no factory installed -> every offline-bearer send errors
//! ("offline = chips"); a USB/chip failure inside any op -> `DsmError` -> no release.

// Tests use `.unwrap()`/`.expect()` freely; production code in this crate does not (the workspace
// `.clippy.toml` disallows them).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod install;
pub mod usb_appliance;
pub mod usb_pico;
pub use usb_appliance::UsbAnchorAppliance;
pub use usb_pico::UsbTransceive;
