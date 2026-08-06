// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: device identity domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_DEVICE: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/device");
pub const TAG_DSM_DEVICE_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/device-entropy");
pub const TAG_DSM_DEVICE_FINGERPRINT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/device-fingerprint");
pub const TAG_DSM_DEVICE_ID_GEN: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/device-id-gen");
pub const TAG_DSM_DEVID: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/devid");
/// Canonical signing-payload domain for the GATE half of an `AddDeviceAdmission` (§16.3
/// additional-device enrollment) — the existing authorized device signs this with its device key.
pub const TAG_DSM_ADD_DEVICE_ADMISSION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/add-device-admission");
/// Canonical signing-payload domain for the NEW-DEVICE self-attestation half of an
/// `AddDeviceAdmission` — the joining device signs this with its device signing key to prove
/// physical possession of its claimed identity (without revealing the raw key).
pub const TAG_DSM_ADD_DEVICE_SELF_ATTEST: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/add-device-self-attest");
pub const TAG_DSM_GENESIS_DEVICE_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/genesis-device-commit");
pub const TAG_DSM_GENESIS_DEVICE_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/genesis-device-entropy");
pub const TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/sub-genesis-device-entropy");
