// SPDX-License-Identifier: MIT OR Apache-2.0

//! Additional-device admission (§16.3) — the authorization that lets an already-trusted device
//! admit a NEW device into a genesis Device Tree.
//!
//! Doctrine (kept separate from the other two device events): the root device *creates* genesis;
//! an already-authorized device *admits* another device (this module); recovery authority
//! *replaces* a lost device after tombstone (the recovery module). Admission is signed by the
//! existing device's NORMAL device signing key (the SPHINCS+ identity key already a member of the
//! tree) — never the recovery-authority key, storage, the QR, or DBRW alone. DBRW/K_DBRW may gate
//! the signer locally, but the admission *proof* is a device signature.
//!
//! [`verify_add_device_admission`] performs the deterministic checks (1,2,4,5,6,8 of the spec).
//! The two non-deterministic checks are the caller's (SDK) responsibility: (3) the signer's
//! signing pubkey is the one genesis-authenticated for `signer_device_id` (device-tree quorum),
//! and (7) `admission_nonce` has not already been consumed (a persisted spent-nonce set). The
//! verifier is fail-closed: any failed check is an error and the insertion MUST NOT happen.

use crate::common::device_tree::DeviceTree;
use crate::common::domain_tags::{TAG_DSM_ADD_DEVICE_ADMISSION, TAG_DSM_DEVICE};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;
use crate::types::proto::{AddDeviceAdmissionV1, Message as _};

/// Canonical derivation of a secondary/Nth device id. MUST stay byte-identical to the SDK's
/// `add_secondary_device` derivation: `H("DSM/device\0" || client_entropy || genesis_hash || DBRW)`.
pub fn derive_secondary_device_id(
    client_entropy: &[u8],
    genesis_hash: &[u8; 32],
    dbrw_binding: &[u8],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE);
    h.update(client_entropy);
    h.update(genesis_hash);
    h.update(dbrw_binding);
    *h.finalize().as_bytes()
}

/// An admission authorizing the insertion of `new_device_id` into `genesis_hash`'s Device Tree,
/// signed by `signer_device_id` (an existing authorized device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddDeviceAdmission {
    pub genesis_hash: [u8; 32],
    pub signer_device_id: [u8; 32],
    pub new_device_id: [u8; 32],
    pub new_device_dbrw_commitment: [u8; 32],
    pub parent_device_tree_root: [u8; 32],
    pub parent_device_tree_version: u64,
    pub admission_nonce: [u8; 32],
    /// SPHINCS+ signature by `signer_device_id` over [`Self::signing_digest`].
    pub signature_by_signer_device: Vec<u8>,
}

impl AddDeviceAdmission {
    /// The 32-byte digest the signer signs — domain-separated over fields 1–7 (everything but the
    /// signature). Field order is fixed and canonical.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_ADD_DEVICE_ADMISSION);
        h.update(&self.genesis_hash);
        h.update(&self.signer_device_id);
        h.update(&self.new_device_id);
        h.update(&self.new_device_dbrw_commitment);
        h.update(&self.parent_device_tree_root);
        h.update(&self.parent_device_tree_version.to_le_bytes());
        h.update(&self.admission_nonce);
        *h.finalize().as_bytes()
    }

    /// Verify the signer's signature over the canonical digest (check 4).
    pub fn verify_signature(&self, signer_signing_pubkey: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(
            signer_signing_pubkey,
            &self.signing_digest(),
            &self.signature_by_signer_device,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        AddDeviceAdmissionV1 {
            genesis_hash: self.genesis_hash.to_vec(),
            signer_device_id: self.signer_device_id.to_vec(),
            new_device_id: self.new_device_id.to_vec(),
            new_device_dbrw_commitment: self.new_device_dbrw_commitment.to_vec(),
            parent_device_tree_root: self.parent_device_tree_root.to_vec(),
            parent_device_tree_version: self.parent_device_tree_version,
            admission_nonce: self.admission_nonce.to_vec(),
            signature_by_signer_device: self.signature_by_signer_device.clone(),
        }
        .encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = AddDeviceAdmissionV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("AddDeviceAdmission::from_bytes: {e}"),
                "AddDeviceAdmission",
                None::<String>,
                Some(e),
            )
        })?;
        fn f32(v: &[u8], what: &str) -> Result<[u8; 32], DsmError> {
            <[u8; 32]>::try_from(v).map_err(|_| {
                DsmError::verification(format!("AddDeviceAdmission: {what} is not 32 bytes"))
            })
        }
        if p.signature_by_signer_device.is_empty() {
            return Err(DsmError::verification("AddDeviceAdmission: empty signature"));
        }
        Ok(Self {
            genesis_hash: f32(&p.genesis_hash, "genesis_hash")?,
            signer_device_id: f32(&p.signer_device_id, "signer_device_id")?,
            new_device_id: f32(&p.new_device_id, "new_device_id")?,
            new_device_dbrw_commitment: f32(
                &p.new_device_dbrw_commitment,
                "new_device_dbrw_commitment",
            )?,
            parent_device_tree_root: f32(&p.parent_device_tree_root, "parent_device_tree_root")?,
            parent_device_tree_version: p.parent_device_tree_version,
            admission_nonce: f32(&p.admission_nonce, "admission_nonce")?,
            signature_by_signer_device: p.signature_by_signer_device,
        })
    }
}

/// Build + sign an admission with the existing device's signing key. `signer_signing_sk` is the
/// SPHINCS+ secret key for `signer_device_id` (gated locally by DBRW unlock at the call site).
#[allow(clippy::too_many_arguments)]
pub fn sign_add_device_admission(
    genesis_hash: [u8; 32],
    signer_device_id: [u8; 32],
    new_device_id: [u8; 32],
    new_device_dbrw_commitment: [u8; 32],
    parent_device_tree_root: [u8; 32],
    parent_device_tree_version: u64,
    admission_nonce: [u8; 32],
    signer_signing_sk: &[u8],
) -> Result<AddDeviceAdmission, DsmError> {
    let mut a = AddDeviceAdmission {
        genesis_hash,
        signer_device_id,
        new_device_id,
        new_device_dbrw_commitment,
        parent_device_tree_root,
        parent_device_tree_version,
        admission_nonce,
        signature_by_signer_device: Vec::new(),
    };
    a.signature_by_signer_device = sphincs_sign(signer_signing_sk, &a.signing_digest())?;
    Ok(a)
}

/// Deterministic admission verification (spec checks 1, 2, 4, 5, 6, 8). On success returns the
/// NEXT Device Tree root that results from inserting `new_device_id`. Fail-closed.
///
/// Caller (SDK) MUST additionally enforce: (3) `signer_signing_pubkey` is the genesis-authenticated
/// signing key for `admission.signer_device_id` (device-tree quorum), and (7) `admission_nonce`
/// is unspent. `new_device_client_entropy`/`new_device_dbrw` are the new device's secrets, available
/// when it applies the admission (and conveyed to the signer over the co-present link so the signer
/// can confirm derivation before signing).
pub fn verify_add_device_admission(
    admission: &AddDeviceAdmission,
    expected_genesis: &[u8; 32],
    current_tree_device_ids: &[[u8; 32]],
    current_tree_version: u64,
    signer_signing_pubkey: &[u8],
    new_device_client_entropy: &[u8],
    new_device_dbrw: &[u8],
) -> Result<[u8; 32], DsmError> {
    // 1. genesis_hash is the target identity root.
    if &admission.genesis_hash != expected_genesis {
        return Err(DsmError::verification(
            "admission: genesis_hash != target genesis",
        ));
    }
    // 2. signer is already a member of the CURRENT tree (root special case: id == genesis).
    let signer_is_member = &admission.signer_device_id == expected_genesis
        || current_tree_device_ids.contains(&admission.signer_device_id);
    if !signer_is_member {
        return Err(DsmError::verification(
            "admission: signer_device_id is not a current Device Tree member",
        ));
    }
    // 4. signature verifies over the canonical digest under the signer's signing key.
    if !admission.verify_signature(signer_signing_pubkey)? {
        return Err(DsmError::verification(
            "admission: signature does not verify under signer's device signing key",
        ));
    }
    // 5. new_device_id matches the canonical secondary derivation.
    let derived =
        derive_secondary_device_id(new_device_client_entropy, expected_genesis, new_device_dbrw);
    if derived != admission.new_device_id {
        return Err(DsmError::verification(
            "admission: new_device_id != H(DSM/device || entropy || genesis || DBRW)",
        ));
    }
    // 6. parent root + version match the current accepted frontier.
    let parent_root = DeviceTree::new(current_tree_device_ids.to_vec()).root();
    if admission.parent_device_tree_root != parent_root {
        return Err(DsmError::verification(
            "admission: parent_device_tree_root != current tree root",
        ));
    }
    if admission.parent_device_tree_version != current_tree_version {
        return Err(DsmError::verification(
            "admission: parent_device_tree_version != current tree version",
        ));
    }
    // 8. applying the insertion yields the next root (idempotent if already present).
    let mut next = current_tree_device_ids.to_vec();
    if !next.contains(&admission.new_device_id) {
        next.push(admission.new_device_id);
    }
    Ok(DeviceTree::new(next).root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};

    fn kp(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let k = generate_keypair_from_seed(SphincsVariant::SPX256f, &[seed; 32]).expect("kp");
        (k.public_key.clone(), k.secret_key.clone())
    }

    fn fixture() -> (AddDeviceAdmission, Vec<u8>, [u8; 32], Vec<[u8; 32]>, u64, Vec<u8>, Vec<u8>) {
        let genesis = [0x6E; 32]; // genesis == root device id
        let (signer_pk, signer_sk) = kp(0x11); // existing (root) device signing key
        let entropy = vec![0xAB; 32];
        let dbrw = vec![0xCD; 48];
        let new_id = derive_secondary_device_id(&entropy, &genesis, &dbrw);
        let current: Vec<[u8; 32]> = vec![genesis]; // only the root device so far
        let version = 1u64;
        let parent_root = DeviceTree::new(current.clone()).root();
        let admission = sign_add_device_admission(
            genesis,
            genesis, // signer is the root device
            new_id,
            [0x77; 32], // dbrw commitment (carried + signed)
            parent_root,
            version,
            [0x01; 32], // nonce
            &signer_sk,
        )
        .expect("sign");
        (admission, signer_pk, genesis, current, version, entropy, dbrw)
    }

    #[test]
    fn valid_admission_verifies_and_returns_next_root() {
        let (a, pk, genesis, current, version, entropy, dbrw) = fixture();
        let next = verify_add_device_admission(&a, &genesis, &current, version, &pk, &entropy, &dbrw)
            .expect("verify");
        let mut expected = current.clone();
        expected.push(a.new_device_id);
        assert_eq!(next, DeviceTree::new(expected).root());
    }

    #[test]
    fn roundtrips_through_proto() {
        let (a, ..) = fixture();
        let decoded = AddDeviceAdmission::from_bytes(&a.to_bytes()).expect("decode");
        assert_eq!(decoded, a);
        assert_eq!(decoded.to_bytes(), a.to_bytes());
    }

    #[test]
    fn tampered_field_breaks_signature() {
        let (mut a, pk, genesis, current, version, entropy, dbrw) = fixture();
        a.admission_nonce[0] ^= 0x01; // signed field changed → digest changes
        assert!(
            verify_add_device_admission(&a, &genesis, &current, version, &pk, &entropy, &dbrw)
                .is_err()
        );
    }

    #[test]
    fn wrong_signer_key_rejected() {
        let (a, _pk, genesis, current, version, entropy, dbrw) = fixture();
        let (other_pk, _other_sk) = kp(0x22);
        assert!(verify_add_device_admission(
            &a, &genesis, &current, version, &other_pk, &entropy, &dbrw
        )
        .is_err());
    }

    #[test]
    fn non_member_signer_rejected() {
        // Signer signs correctly, but is not in the current tree and isn't the genesis/root.
        let genesis = [0x6E; 32];
        let (stranger_pk, stranger_sk) = kp(0x33);
        let stranger_id = [0x44; 32];
        let entropy = vec![0xAB; 32];
        let dbrw = vec![0xCD; 48];
        let new_id = derive_secondary_device_id(&entropy, &genesis, &dbrw);
        let current: Vec<[u8; 32]> = vec![genesis];
        let parent_root = DeviceTree::new(current.clone()).root();
        let a = sign_add_device_admission(
            genesis, stranger_id, new_id, [0x77; 32], parent_root, 1, [0x01; 32], &stranger_sk,
        )
        .unwrap();
        assert!(
            verify_add_device_admission(&a, &genesis, &current, 1, &stranger_pk, &entropy, &dbrw)
                .is_err()
        );
    }

    #[test]
    fn wrong_new_device_derivation_rejected() {
        let (a, pk, genesis, current, version, _entropy, dbrw) = fixture();
        let bad_entropy = vec![0x00; 32];
        assert!(verify_add_device_admission(
            &a, &genesis, &current, version, &pk, &bad_entropy, &dbrw
        )
        .is_err());
    }

    #[test]
    fn stale_parent_frontier_rejected() {
        let (a, pk, genesis, _current, _version, entropy, dbrw) = fixture();
        // Tree advanced: a different member exists now, so parent_root/version no longer match.
        let advanced: Vec<[u8; 32]> = vec![genesis, [0x99; 32]];
        assert!(verify_add_device_admission(
            &a, &genesis, &advanced, 2, &pk, &entropy, &dbrw
        )
        .is_err());
    }
}
