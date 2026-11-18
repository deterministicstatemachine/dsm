// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet-side client for the fused-anchor appliance (Software-Authority / Hardware-Identity).
//!
//! The bilateral SENDER drives its board (`anchor_core::appliance::Appliance`)
//! through PREPARE → COMMIT → EMIT to produce the `dsm.anchor.OfflineRelease` it then
//! carries on the bilateral confirm (`BilateralConfirmRequest.offline_release`). The
//! RECEIVER applies the 22-check predicate (`dsm_sdk::bluetooth::anchor_accept`),
//! and its own board draws the challenge, checks the release and commits the receive.
//!
//! [`AnchorAppliance`] is the transport-agnostic interface. The Android build installs
//! its USB client (`crates/dsm-android-anchor`, `UsbAnchorAppliance`); with no appliance
//! factory installed, offline-bearer sends and receives fail closed.

pub mod appliance_client;

pub use anchor_core::appliance::RecoverOutcome;

/// The stamp keys a board's stamp is checked under (DSM Amendment A38, owner, 2026-11-18): the
/// owner's, compiled into the wallet. A test build checks under its tests' stamp key instead, since
/// the owner's key never leaves his computer and no test can stamp a board with it.
pub fn board_stamp_keys() -> &'static [anchor_core::stamp::StampKey] {
    #[cfg(not(test))]
    {
        anchor_core::stamp::BOARD_STAMP_KEYS
    }
    #[cfg(test)]
    {
        crate::test_support::appliance::test_stamp_keys()
    }
}
pub use appliance_client::{
    recovery_action, AnchorAppliance, AnchorPin, ApplianceStatus, BoardIdentityReport,
    RecoveryAction, TryRunReport, TryRunStep, RehearsalOwner,
};
