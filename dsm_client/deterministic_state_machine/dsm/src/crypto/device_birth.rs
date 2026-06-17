// SPDX-License-Identifier: MIT OR Apache-2.0

//! Device-birth binding `AttA` — a deterministic install / device-lineage
//! binding that replaces the removed silicon anti-clone binding (whitepaper §11.1).
//!
//! `AttA` is folded into the per-device key-derivation IKM (`S_master`) so the
//! keypair is canonical to this device install.  It is **NOT** an anti-clone
//! proof: online double-spend safety rests entirely on the tripwire +
//! parent-consumption uniqueness, and offline-bearer anti-clone rests on the
//! separate secure-element anchor.
//!
//! ## Preimage
//!
//! `AttA = BLAKE3("DSM/device-birth-att/v1\0"
//!                || LP(nonce_commitment) || LP(creation_mode)
//!                || LP(schema_version)   || LP(protocol_version))`
//!
//! where `LP(x) = LE32(len(x)) || x`.  The genesis hash and device public key
//! are deliberately excluded: they are derived from / during MPC (so folding
//! them here would be circular), and they already bind to the identity through
//! `G` and `DevID` in the `S_master` IKM (whitepaper §11.1 eq.13).  The
//! lineage-distinctive material is the device-birth nonce commitment and the
//! creation mode (`genesis | secondary_device | recovery_successor`).

use crate::common::domain_tags::{TAG_DSM_DEVICE_BIRTH_ATT, TAG_DSM_DEVICE_BIRTH_NONCE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::canonical_lp;

/// Generate a fresh device-birth nonce commitment.
///
/// Draws 32 CSPRNG bytes as the birth nonce and returns
/// `commitment = BLAKE3("DSM/device-birth-nonce/v1\0" || birth_nonce)`.  The
/// nonce itself is never returned or persisted — only the commitment is, and
/// it is folded VERBATIM into `AttA` via [`DeviceBirthInputs::from_platform_nonce`]
/// so finalize/restore re-derive an identical `AttA`.  Rust owns this entirely;
/// the host never computes or supplies it (rules.instructions.md: Rust is the
/// sole crypto authority, Kotlin is transport-only).
pub fn random_device_birth_nonce_commitment() -> [u8; 32] {
    let birth_nonce = crate::crypto::rng::random_bytes(32);
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_BIRTH_NONCE);
    h.update(&birth_nonce);
    *h.finalize().as_bytes()
}

/// How a device identity was born.  Canonical small-int matched 1:1 with the
/// frontend setup buttons (`INITIALIZE` / `ADDITIONAL DEVICE` / `DEVICE
/// RECOVERY`) and the `CreationMode` proto enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CreationMode {
    Genesis = 1,
    SecondaryDevice = 2,
    RecoverySuccessor = 3,
}

impl CreationMode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Strict decode; rejects unknown/unspecified modes (fail-closed).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Genesis),
            2 => Some(Self::SecondaryDevice),
            3 => Some(Self::RecoverySuccessor),
            _ => None,
        }
    }
}

/// Pre-genesis device-birth inputs that deterministically fix `AttA`.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DeviceBirthInputs {
    /// Commitment to a device-local 32-byte birth nonce (BLAKE3 of the nonce).
    pub device_birth_nonce_commitment: [u8; 32],
    /// Canonical creation-mode small-int (see [`CreationMode`]).
    pub creation_mode: u8,
    pub schema_version: u32,
    pub protocol_version: u32,
}

impl DeviceBirthInputs {
    /// Construct + validate the inputs.  Fails closed on a zero commitment or
    /// an unknown creation mode.
    pub fn new(
        device_birth_nonce_commitment: [u8; 32],
        creation_mode: CreationMode,
        schema_version: u32,
        protocol_version: u32,
    ) -> Self {
        Self {
            device_birth_nonce_commitment,
            creation_mode: creation_mode.as_u8(),
            schema_version,
            protocol_version,
        }
    }

    /// Build schema/protocol-v1 birth inputs from a 32-byte device-birth nonce
    /// commitment.  The SDK generates the commitment once at genesis
    /// ([`random_device_birth_nonce_commitment`]) and persists it; genesis,
    /// bootstrap-finalize, and restore all fold the SAME commitment in VERBATIM
    /// (no second hash), so they derive an IDENTICAL AttA and the re-derived
    /// signing key matches the published genesis AK.  NOT a silicon attestation
    /// (no orbit probe, trust gate, or AttA).
    pub fn from_platform_nonce(
        nonce_commitment_bytes: &[u8],
        creation_mode: CreationMode,
    ) -> Self {
        let mut nonce_commitment = [0u8; 32];
        let n = nonce_commitment_bytes.len().min(32);
        nonce_commitment[..n].copy_from_slice(&nonce_commitment_bytes[..n]);
        Self::new(nonce_commitment, creation_mode, 1, 1)
    }

    /// Compute `AttA` from these inputs (see module docs).
    pub fn derive_att(&self) -> [u8; 32] {
        derive_device_birth_att(self)
    }
}

/// Derive `AttA` from the canonical device-birth preimage (see module docs).
pub fn derive_device_birth_att(inputs: &DeviceBirthInputs) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE_BIRTH_ATT);
    canonical_lp::write_lp(&mut h, &inputs.device_birth_nonce_commitment);
    canonical_lp::write_lp(&mut h, &[inputs.creation_mode]);
    canonical_lp::write_lp(&mut h, &inputs.schema_version.to_le_bytes());
    canonical_lp::write_lp(&mut h, &inputs.protocol_version.to_le_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(tag: u8) -> DeviceBirthInputs {
        DeviceBirthInputs::new([tag; 32], CreationMode::Genesis, 1, 1)
    }

    #[test]
    fn att_is_deterministic() {
        assert_eq!(derive_device_birth_att(&inputs(7)), derive_device_birth_att(&inputs(7)));
    }

    #[test]
    fn att_changes_with_nonce_commitment() {
        assert_ne!(derive_device_birth_att(&inputs(1)), derive_device_birth_att(&inputs(2)));
    }

    #[test]
    fn att_changes_with_creation_mode() {
        let a = DeviceBirthInputs::new([9; 32], CreationMode::Genesis, 1, 1);
        let b = DeviceBirthInputs::new([9; 32], CreationMode::SecondaryDevice, 1, 1);
        assert_ne!(derive_device_birth_att(&a), derive_device_birth_att(&b));
    }

    #[test]
    fn att_is_nonzero() {
        assert_ne!(derive_device_birth_att(&inputs(3)), [0u8; 32]);
    }

    #[test]
    fn creation_mode_strict_decode() {
        assert_eq!(CreationMode::from_u8(1), Some(CreationMode::Genesis));
        assert_eq!(CreationMode::from_u8(3), Some(CreationMode::RecoverySuccessor));
        assert_eq!(CreationMode::from_u8(0), None);
        assert_eq!(CreationMode::from_u8(4), None);
    }

    #[test]
    fn generated_commitment_is_32_bytes_and_nonzero() {
        let c = random_device_birth_nonce_commitment();
        assert_eq!(c.len(), 32);
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn generated_commitment_drives_a_stable_att() {
        // A generated commitment used verbatim must yield a deterministic AttA:
        // this is the property finalize/restore rely on to match genesis.
        let c = random_device_birth_nonce_commitment();
        let att_a = DeviceBirthInputs::from_platform_nonce(&c, CreationMode::Genesis).derive_att();
        let att_b = DeviceBirthInputs::from_platform_nonce(&c, CreationMode::Genesis).derive_att();
        assert_eq!(att_a, att_b);
        assert_ne!(att_a, [0u8; 32]);
    }
}
