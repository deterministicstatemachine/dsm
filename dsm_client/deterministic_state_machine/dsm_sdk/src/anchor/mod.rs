// SPDX-License-Identifier: MIT OR Apache-2.0
//! Producer-side client for the fused-anchor appliance (Software-Authority / Hardware-Identity).
//!
//! The bilateral SENDER drives the appliance (`anchor_core::appliance::Appliance`)
//! through PREPARE → COMMIT → EMIT to produce the `dsm.anchor.OfflineRelease` it then
//! carries on the bilateral confirm (`BilateralConfirmRequest.offline_release`). The
//! RECEIVER applies the 22-check predicate (`dsm_sdk::bluetooth::anchor_accept`).
//!
//! [`AnchorAppliance`] is the transport-agnostic interface. No transport to a physical
//! appliance exists yet, so the producer has no appliance and offline-bearer sends fail
//! closed.

pub mod appliance_client;

pub use anchor_core::appliance::RecoverOutcome;
pub use appliance_client::{
    recovery_action, AnchorAppliance, AnchorPin, ApplianceStatus, RecoveryAction,
};
