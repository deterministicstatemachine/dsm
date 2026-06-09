// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: device identity domains

pub const TAG_DSM_DEVICE: &str = "DSM/device";
pub const TAG_DSM_DEVICE_ENTROPY: &str = "DSM/device-entropy";
pub const TAG_DSM_DEVICE_FINGERPRINT: &str = "DSM/device-fingerprint";
pub const TAG_DSM_DEVICE_ID_GEN: &str = "DSM/device-id-gen";
pub const TAG_DSM_DEVID: &str = "DSM/devid";
/// Canonical signing-payload domain for an `AddDeviceAdmission` (§16.3 additional-device
/// enrollment). The existing authorized device signs this digest with its device signing key.
pub const TAG_DSM_ADD_DEVICE_ADMISSION: &str = "DSM/add-device-admission";
pub const TAG_DSM_GENESIS_DEVICE_COMMIT: &str = "DSM/genesis-device-commit";
pub const TAG_DSM_GENESIS_DEVICE_ENTROPY: &str = "DSM/genesis-device-entropy";
pub const TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY: &str = "DSM/sub-genesis-device-entropy";
