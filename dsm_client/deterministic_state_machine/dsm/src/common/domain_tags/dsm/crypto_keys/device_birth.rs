// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: device-birth binding

/// Domain tag for the deterministic device-birth attestation digest `AttA`:
/// `AttA = BLAKE3(TAG || ProtoDet(DeviceBirthRecordV1))`.  Folded into the
/// per-device key derivation (whitepaper §11.1) in place of the removed
/// silicon C-DBRW binding.  Install/device-lineage binding only — NOT an
/// anti-clone proof.
pub const TAG_DSM_DEVICE_BIRTH_ATT: &str = "DSM/device-birth-att/v1";

/// Domain tag for the soft-vault at-rest device binding key (storage-encryption
/// only; not a protocol identity).  `key = BLAKE3(TAG || device_id_hint)`.
pub const TAG_DSM_SOFT_VAULT_BINDING: &str = "DSM/soft-vault-binding/v1";
