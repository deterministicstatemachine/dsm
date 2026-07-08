// SPDX-License-Identifier: MIT OR Apache-2.0
//! Producer-side client for the Boot Fenced Fused Anchor appliance.
//!
//! The bilateral SENDER drives the appliance (`anchor_core::appliance::Appliance`)
//! through PREPARE → COMMIT → EMIT to produce the `dsm.anchor.OfflineRelease` it then
//! carries on the bilateral confirm (`BilateralConfirmRequest.offline_release`). The
//! RECEIVER applies the 22-check predicate (`dsm_sdk::bluetooth::anchor_accept`).
//!
//! [`AnchorAppliance`] is the transport-agnostic interface. The activation build uses
//! [`appliance_client::InProcessAnchorAppliance`] (a real `anchor_core` appliance with an
//! in-process secure-element mock — real WOTS-over-BLAKE3 witness + real BLAKE3-SPHINCS+
//! SPX128f partition certs, so the receiver's existing SPHINCS+ verifier accepts it). A real
//! RP2350 USB-CDC / BLE transport implementing the same trait is hardware follow-on; nothing
//! in the SDK reaches a physical Pico today (only mock transports are wired).

pub mod appliance_client;

pub use anchor_core::appliance::RecoverOutcome;
pub use appliance_client::{
    recovery_action, AnchorAppliance, AnchorPin, ApplianceStatus, BirthConfig,
    InProcessAnchorAppliance, RecoveryAction,
};
