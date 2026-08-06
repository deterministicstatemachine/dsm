// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recovery-authority anchor (spec §0.5, step 5).
//!
//! The recovery-authority SPHINCS+ public key `K_A_pub` (derived from the recovery
//! mnemonic via `derive_recovery_authority_seed`) authenticates a device's
//! tombstone/succession pair during recovery. For that authentication to be a real
//! trust root it MUST be anchored to the genesis `G_A` — otherwise a verifier would
//! have to trust an arbitrary runtime-supplied pubkey (exactly the contacts-DB
//! authority confusion §0.5 removes).
//!
//! `K_A_pub` CANNOT be a genesis field: the recovery mnemonic is generated only when
//! the user enables NFC backup (`recovery_sdk::derive_and_cache_key`, reached via the
//! `recovery.enable` route), which happens AFTER genesis creation — the mnemonic is
//! not in scope when `create_genesis_via_blind_mpc*` runs. So the authority is
//! anchored by a separate **declaration chained off genesis**:
//!
//! - It is signed by the device's **genesis signing key** (`GenesisState::signing_key`),
//!   which IS genesis-authenticated and fetchable by peers via the device-tree quorum
//!   path (`fetch_quorum_device_identity` + `verify_device_tree_evidence_quorum`). That
//!   signature is the genesis binding.
//! - It commits `H(K_A_pub)` and carries a self-signature by `K_A` proving the
//!   declarant actually possesses the recovery-authority secret (it cannot commit to a
//!   pubkey it does not control).
//!
//! ## Forgery resistance (bind-once)
//!
//! A thief holding the device also holds the genesis signing key, so a signature alone
//! is not sufficient. The anchor is **bind-once per genesis**: the first declaration
//! published for a genesis wins and is immutable thereafter (mirrors R1 per-contact
//! bind-once). A user who enabled recovery before theft has `K_A_pub` anchored and the
//! thief cannot override it. A user who NEVER enabled recovery has no recovery path at
//! all (no mnemonic, no capsule), so a thief-authored first anchor grants nothing the
//! thief lacks (they already control the device), and bearer assets independently stay
//! `LOCKED_RECOVERY` until per-asset frontier reconciliation (two-gate model, P5).
//!
//! Bind-once is enforced at the storage/device-tree layer (append-once anchor leaf,
//! §0.5 step 7); THIS module provides the pure declaration type and its verification:
//! genesis-key signature, candidate-pubkey commitment binding, and authority
//! self-signature. All digests are BLAKE3 domain-separated; all signatures SPHINCS+.

use crate::crypto::domain::TaggedHashDomain;

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, RecoveryAuthorityAnchorProto};

const AUTHORITY_COMMIT_DOMAIN: TaggedHashDomain<'static> =
    crate::common::domain_tags::TAG_DSM_RECOVERY_AUTHORITY_COMMIT;
const AUTHORITY_ANCHOR_DOMAIN: TaggedHashDomain<'static> =
    crate::common::domain_tags::TAG_DSM_RECOVERY_AUTHORITY_ANCHOR;

/// Commit to a recovery-authority public key (length-prefixed, domain-separated).
pub fn compute_authority_pubkey_commit(authority_pubkey: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(AUTHORITY_COMMIT_DOMAIN);
    h.update(&(authority_pubkey.len() as u32).to_le_bytes());
    h.update(authority_pubkey);
    *h.finalize().as_bytes()
}

/// The digest both signatures cover: binds the genesis, the device, and the commitment
/// to the authority pubkey. No wall-clock, no counters — pure content binding.
fn anchor_digest(
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    authority_pubkey_commit: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(AUTHORITY_ANCHOR_DOMAIN);
    h.update(genesis_id);
    h.update(device_id);
    h.update(authority_pubkey_commit);
    *h.finalize().as_bytes()
}

/// A genesis-chained declaration that anchors a device's recovery-authority pubkey.
///
/// `device_signature` is by the genesis signing key (genesis binding); it is verified
/// against the genesis-authenticated device pubkey fetched via the device-tree quorum
/// path. `authority_signature` is by `K_A` (possession proof); it is verified against
/// the candidate authority pubkey, which must also match `authority_pubkey_commit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAuthorityAnchor {
    pub genesis_id: [u8; 32],
    pub device_id: [u8; 32],
    /// `H(K_A_pub)` — see [`compute_authority_pubkey_commit`].
    pub authority_pubkey_commit: [u8; 32],
    /// SPHINCS+ signature over [`anchor_digest`] by the genesis signing key.
    pub device_signature: Vec<u8>,
    /// SPHINCS+ signature over [`anchor_digest`] by the recovery-authority key `K_A`.
    pub authority_signature: Vec<u8>,
}

impl RecoveryAuthorityAnchor {
    /// The digest both signatures cover.
    pub fn digest(&self) -> [u8; 32] {
        anchor_digest(
            &self.genesis_id,
            &self.device_id,
            &self.authority_pubkey_commit,
        )
    }

    /// Verify the anchor (fail-closed). All four conditions must hold:
    /// 1. the anchor is for the genesis/device under recovery (`expected_*`);
    /// 2. `candidate_authority_pubkey` matches the committed `H(K_A_pub)`;
    /// 3. the genesis signing key signed the anchor (genesis binding);
    /// 4. the candidate authority key signed the anchor (possession proof).
    ///
    /// `genesis_signing_pubkey` MUST come from the device's genesis-authenticated
    /// identity (device-tree quorum), and `candidate_authority_pubkey` is the pubkey
    /// the caller intends to verify tombstone/succession under. On success the caller
    /// may safely treat `candidate_authority_pubkey` as the genesis-anchored authority.
    pub fn verify(
        &self,
        expected_genesis_id: &[u8; 32],
        expected_device_id: &[u8; 32],
        genesis_signing_pubkey: &[u8],
        candidate_authority_pubkey: &[u8],
    ) -> Result<(), DsmError> {
        if &self.genesis_id != expected_genesis_id {
            return Err(DsmError::verification(
                "authority-anchor: genesis_id does not match the genesis under recovery",
            ));
        }
        if &self.device_id != expected_device_id {
            return Err(DsmError::verification(
                "authority-anchor: device_id does not match the device under recovery",
            ));
        }
        if self.authority_pubkey_commit
            != compute_authority_pubkey_commit(candidate_authority_pubkey)
        {
            return Err(DsmError::verification(
                "authority-anchor: candidate authority pubkey does not match the anchored commitment",
            ));
        }
        let digest = self.digest();
        if !sphincs_verify(genesis_signing_pubkey, &digest, &self.device_signature)? {
            return Err(DsmError::verification(
                "authority-anchor: genesis signing-key signature invalid (genesis binding failed)",
            ));
        }
        if !sphincs_verify(
            candidate_authority_pubkey,
            &digest,
            &self.authority_signature,
        )? {
            return Err(DsmError::verification(
                "authority-anchor: authority self-signature invalid (possession proof failed)",
            ));
        }
        Ok(())
    }

    /// Serialize to canonical protobuf bytes (protobuf-only wire; no JSON, no hex).
    pub fn to_bytes(&self) -> Vec<u8> {
        RecoveryAuthorityAnchorProto {
            genesis_id: self.genesis_id.to_vec(),
            device_id: self.device_id.to_vec(),
            authority_pubkey_commit: self.authority_pubkey_commit.to_vec(),
            device_signature: self.device_signature.clone(),
            authority_signature: self.authority_signature.clone(),
        }
        .encode_to_vec()
    }

    /// Deserialize from protobuf bytes (fail-closed on length / decode errors).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = RecoveryAuthorityAnchorProto::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("RecoveryAuthorityAnchor::from_bytes: {e}"),
                "RecoveryAuthorityAnchor",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self {
            genesis_id: fixed32(&p.genesis_id, "genesis_id")?,
            device_id: fixed32(&p.device_id, "device_id")?,
            authority_pubkey_commit: fixed32(
                &p.authority_pubkey_commit,
                "authority_pubkey_commit",
            )?,
            device_signature: p.device_signature,
            authority_signature: p.authority_signature,
        })
    }
}

/// Fail-closed `Vec<u8>` → `[u8; 32]` (proto `dsm_fixed_len` is a hint, not enforced
/// by prost, so the length is validated here).
fn fixed32(b: &[u8], field: &str) -> Result<[u8; 32], DsmError> {
    <[u8; 32]>::try_from(b).map_err(|_| {
        DsmError::verification(format!(
            "authority-anchor: field `{field}` is {} bytes, expected 32",
            b.len()
        ))
    })
}

/// Create a recovery-authority anchor declaration.
///
/// `genesis_signing_sk` is the device's genesis signing secret key; `authority_sk` /
/// `authority_pubkey` are the SPHINCS+ recovery-authority keypair derived from the
/// mnemonic (`derive_recovery_authority_seed` → `generate_keypair_from_seed`).
pub fn create_recovery_authority_anchor(
    genesis_id: &[u8; 32],
    device_id: &[u8; 32],
    authority_pubkey: &[u8],
    genesis_signing_sk: &[u8],
    authority_sk: &[u8],
) -> Result<RecoveryAuthorityAnchor, DsmError> {
    let authority_pubkey_commit = compute_authority_pubkey_commit(authority_pubkey);
    let digest = anchor_digest(genesis_id, device_id, &authority_pubkey_commit);
    let device_signature = sphincs_sign(genesis_signing_sk, &digest)?;
    let authority_signature = sphincs_sign(authority_sk, &digest)?;
    Ok(RecoveryAuthorityAnchor {
        genesis_id: *genesis_id,
        device_id: *device_id,
        authority_pubkey_commit,
        device_signature,
        authority_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};

    const GENESIS: [u8; 32] = [0x6E; 32];
    const DEVICE: [u8; 32] = [0xD0; 32];

    fn kp(seed: u8) -> crate::crypto::sphincs::SphincsKeyPair {
        generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("kp")
    }

    /// (anchor, genesis_signing_pubkey, authority_pubkey)
    fn fixture() -> (RecoveryAuthorityAnchor, Vec<u8>, Vec<u8>) {
        let device_kp = kp(0x11);
        let authority_kp = kp(0x22);
        let anchor = create_recovery_authority_anchor(
            &GENESIS,
            &DEVICE,
            &authority_kp.public_key,
            &device_kp.secret_key,
            &authority_kp.secret_key,
        )
        .expect("anchor");
        (
            anchor,
            device_kp.public_key.clone(),
            authority_kp.public_key.clone(),
        )
    }

    #[test]
    fn valid_anchor_verifies() {
        let (anchor, gpk, apk) = fixture();
        anchor.verify(&GENESIS, &DEVICE, &gpk, &apk).expect("valid");
    }

    #[test]
    fn wrong_candidate_authority_pubkey_fails() {
        let (anchor, gpk, _apk) = fixture();
        let other = kp(0x99);
        // Different authority pubkey → commitment mismatch (and possession-proof fail).
        assert!(anchor
            .verify(&GENESIS, &DEVICE, &gpk, &other.public_key)
            .is_err());
    }

    #[test]
    fn tampered_commit_fails() {
        let (mut anchor, gpk, apk) = fixture();
        anchor.authority_pubkey_commit[0] ^= 0x01;
        assert!(anchor.verify(&GENESIS, &DEVICE, &gpk, &apk).is_err());
    }

    #[test]
    fn wrong_genesis_signing_pubkey_fails() {
        let (anchor, _gpk, apk) = fixture();
        let other = kp(0x55);
        // A different device-key holder cannot have produced the genesis-binding sig.
        assert!(anchor
            .verify(&GENESIS, &DEVICE, &other.public_key, &apk)
            .is_err());
    }

    #[test]
    fn wrong_expected_genesis_id_fails() {
        let (anchor, gpk, apk) = fixture();
        assert!(anchor.verify(&[0xAB; 32], &DEVICE, &gpk, &apk).is_err());
    }

    #[test]
    fn wrong_expected_device_id_fails() {
        let (anchor, gpk, apk) = fixture();
        assert!(anchor.verify(&GENESIS, &[0xCD; 32], &gpk, &apk).is_err());
    }

    #[test]
    fn tampered_device_signature_fails() {
        let (mut anchor, gpk, apk) = fixture();
        anchor.device_signature[0] ^= 0x01;
        assert!(anchor.verify(&GENESIS, &DEVICE, &gpk, &apk).is_err());
    }

    #[test]
    fn tampered_authority_signature_fails() {
        let (mut anchor, gpk, apk) = fixture();
        let n = anchor.authority_signature.len();
        anchor.authority_signature[n - 1] ^= 0x01;
        assert!(anchor.verify(&GENESIS, &DEVICE, &gpk, &apk).is_err());
    }

    #[test]
    fn forged_anchor_by_device_holder_without_mnemonic_is_distinct() {
        // A thief with the genesis device key but a DIFFERENT mnemonic produces an
        // anchor that binds a different authority pubkey — it verifies on its own terms
        // but is a DIFFERENT anchor (different commit). Bind-once at the storage layer
        // is what rejects it when a legitimate anchor already exists; here we assert the
        // two anchors are not interchangeable.
        let (legit, gpk, legit_apk) = fixture();
        let device_kp = kp(0x11); // same device key (thief has the device)
        let thief_auth = kp(0xEE); // thief's own mnemonic-derived authority
        let forged = create_recovery_authority_anchor(
            &GENESIS,
            &DEVICE,
            &thief_auth.public_key,
            &device_kp.secret_key,
            &thief_auth.secret_key,
        )
        .expect("forged");
        assert_ne!(
            legit.authority_pubkey_commit,
            forged.authority_pubkey_commit
        );
        // The legit authority pubkey does not validate against the forged anchor.
        assert!(forged.verify(&GENESIS, &DEVICE, &gpk, &legit_apk).is_err());
    }

    #[test]
    fn proto_round_trip_preserves_and_verifies() {
        let (anchor, gpk, apk) = fixture();
        let bytes = anchor.to_bytes();
        let decoded = RecoveryAuthorityAnchor::from_bytes(&bytes).expect("decode");
        assert_eq!(anchor, decoded);
        // The decoded anchor still verifies end-to-end.
        decoded
            .verify(&GENESIS, &DEVICE, &gpk, &apk)
            .expect("verify after round-trip");
        // Re-encode is byte-identical (canonical).
        assert_eq!(bytes, decoded.to_bytes());
    }

    #[test]
    fn from_bytes_rejects_wrong_length_hash() {
        let (anchor, _gpk, _apk) = fixture();
        let mut p = RecoveryAuthorityAnchorProto {
            genesis_id: anchor.genesis_id.to_vec(),
            device_id: anchor.device_id.to_vec(),
            authority_pubkey_commit: anchor.authority_pubkey_commit.to_vec(),
            device_signature: anchor.device_signature.clone(),
            authority_signature: anchor.authority_signature.clone(),
        };
        p.genesis_id.truncate(31); // not 32 bytes
        assert!(RecoveryAuthorityAnchor::from_bytes(&p.encode_to_vec()).is_err());
    }

    #[test]
    fn commit_is_deterministic_and_sensitive() {
        let a = kp(0x01);
        let b = kp(0x02);
        assert_eq!(
            compute_authority_pubkey_commit(&a.public_key),
            compute_authority_pubkey_commit(&a.public_key)
        );
        assert_ne!(
            compute_authority_pubkey_commit(&a.public_key),
            compute_authority_pubkey_commit(&b.public_key)
        );
    }
}
