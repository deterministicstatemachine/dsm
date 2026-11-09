// SPDX-License-Identifier: MIT OR Apache-2.0
//! Producer-side client for the fused-anchor appliance (Software-Authority / Hardware-Identity).
//!
//! The bilateral SENDER drives the appliance (`anchor_core::appliance::Appliance`)
//! through PREPARE → COMMIT → EMIT to produce the `dsm.anchor.OfflineRelease` it then
//! carries on the bilateral confirm (`BilateralConfirmRequest.offline_release`). The
//! RECEIVER applies the 22-check predicate (`dsm_sdk::bluetooth::anchor_accept`).
//!
//! [`AnchorAppliance`] is the transport-agnostic interface; [`FramedAnchorAppliance`] is the
//! client of the physical board over any byte link the host supplies ([`Transceive`]): Android's
//! USB round-trip, iOS's Bluetooth link. A process whose host installed no link has no appliance,
//! and offline-bearer sends fail closed.

pub mod appliance_client;
pub mod framed_appliance;

pub use anchor_core::appliance::RecoverOutcome;
pub use appliance_client::{
    recovery_action, AnchorAppliance, AnchorPin, ApplianceStatus, RecoveryAction, TryRunReport,
    TryRunStep, RehearsalOwner,
};
pub use framed_appliance::{FramedAnchorAppliance, Transceive};
