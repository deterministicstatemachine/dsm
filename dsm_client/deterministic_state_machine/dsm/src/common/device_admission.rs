// SPDX-License-Identifier: MIT OR Apache-2.0

//! Additional-device admission (§16.3) — the authorization that lets an already-trusted device
//! admit a NEW device into an existing genesis Device Tree.
//!
//! Doctrine (three separate device events): the root device *creates* genesis (MPC — untouched);
//! an already-authorized device *admits* another device (this module); recovery authority
//! *replaces* a lost device after tombstone (the recovery module).
//!
//! Gate-only, two-signature, co-present. The only control added over a plain insert is a
//! **signature gate**: only a device key already in the tree may authorize the insert. The new
//! device co-signs with its own DBRW-bound key to prove physical possession (DBRW is silicon-bound
//! and cannot be cloned) WITHOUT revealing the raw DBRW. The gate signer's pubkey is obtained from
//! the QR the new device scanned in person — there is **no storage-node quorum and no external
//! verifier** (that is only needed by the recovery flow, where a remote party authenticates a
//! device it never met). Replay is prevented by the monotonic `parent_device_tree_version`: an
//! admission only applies at the exact frontier it was signed for; once applied, the version bumps.

use crate::common::device_tree::DeviceTree;
use crate::common::domain_tags::{
    TAG_DSM_ADD_DEVICE_ADMISSION, TAG_DSM_ADD_DEVICE_SELF_ATTEST, TAG_DSM_DEVICE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::types::error::DsmError;
use crate::types::proto::{AddDeviceAdmissionV1, Message as _};

/// Canonical derivation of a secondary/Nth device id — `H("DSM/device\0" || client_entropy ||
/// genesis_hash || device_secret)`. Byte-identical to the SDK's secondary-device derivation; the
/// new device uses it to compute its own `DevID` (the verifier does NOT recompute it — the new
/// device's self-attestation proves possession instead). `device_secret` is the joining device's
/// wallet-seed-rooted master seed (Genesis v2 `Smaster`); there is no C-DBRW binding.
pub fn derive_secondary_device_id(
    client_entropy: &[u8],
    genesis_hash: &[u8; 32],
    device_secret: &[u8],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_DEVICE);
    h.update(client_entropy);
    h.update(genesis_hash);
    h.update(device_secret);
    *h.finalize().as_bytes()
}

/// Sign the NEW-DEVICE self-attestation half: proof, by the joining device's wallet-seed-rooted
/// signing key (Genesis v2 AK), that it owns `new_device_id`/`new_signing_pubkey` under `genesis_hash`.
pub fn sign_self_attestation(
    genesis_hash: &[u8; 32],
    new_device_id: &[u8; 32],
    new_signing_pubkey: &[u8],
    new_signing_sk: &[u8],
) -> Result<Vec<u8>, DsmError> {
    sphincs_sign(
        new_signing_sk,
        &self_attest_digest(genesis_hash, new_device_id, new_signing_pubkey),
    )
}

/// The new-device self-attestation digest — `H(domain || genesis || new_device_id ||
/// new_signing_pubkey)`. Exposed so the SDK can sign it via the device key facility.
pub fn self_attest_digest(
    genesis_hash: &[u8; 32],
    new_device_id: &[u8; 32],
    new_signing_pubkey: &[u8],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_ADD_DEVICE_SELF_ATTEST);
    h.update(genesis_hash);
    h.update(new_device_id);
    h.update(new_signing_pubkey);
    *h.finalize().as_bytes()
}

/// Verify a new-device self-attestation signature from its parts (used by the admitting device to
/// check the incoming request before gate-signing).
pub fn verify_self_attestation_sig(
    genesis_hash: &[u8; 32],
    new_device_id: &[u8; 32],
    new_signing_pubkey: &[u8],
    signature: &[u8],
) -> Result<bool, DsmError> {
    sphincs_verify(
        new_signing_pubkey,
        &self_attest_digest(genesis_hash, new_device_id, new_signing_pubkey),
        signature,
    )
}

/// An admission authorizing the insertion of `new_device_id` into `genesis_hash`'s Device Tree.
/// Carries two signatures: the gate (existing authorized device) and the new device's self-attest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddDeviceAdmission {
    pub genesis_hash: [u8; 32],
    pub signer_device_id: [u8; 32],
    pub new_device_id: [u8; 32],
    pub new_device_signing_pubkey: Vec<u8>,
    pub parent_device_tree_root: [u8; 32],
    pub parent_device_tree_version: u64,
    /// SPHINCS+ by `signer_device_id` (the existing device) — the authorization gate.
    pub signature_by_signer_device: Vec<u8>,
    /// SPHINCS+ by the new device's DBRW-bound key — proof of physical possession.
    pub signature_by_new_device: Vec<u8>,
}

impl AddDeviceAdmission {
    /// Digest the GATE signer signs — over every field except the two signatures.
    pub fn gate_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_ADD_DEVICE_ADMISSION);
        h.update(&self.genesis_hash);
        h.update(&self.signer_device_id);
        h.update(&self.new_device_id);
        h.update(&self.new_device_signing_pubkey);
        h.update(&self.parent_device_tree_root);
        h.update(&self.parent_device_tree_version.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Verify the gate signature under the existing device's signing pubkey (from the scanned QR).
    pub fn verify_gate(&self, signer_signing_pubkey: &[u8]) -> Result<bool, DsmError> {
        sphincs_verify(
            signer_signing_pubkey,
            &self.gate_digest(),
            &self.signature_by_signer_device,
        )
    }

    /// Verify the new device's self-attestation under its own signing pubkey.
    pub fn verify_self_attestation(&self) -> Result<bool, DsmError> {
        sphincs_verify(
            &self.new_device_signing_pubkey,
            &self_attest_digest(
                &self.genesis_hash,
                &self.new_device_id,
                &self.new_device_signing_pubkey,
            ),
            &self.signature_by_new_device,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        AddDeviceAdmissionV1 {
            genesis_hash: self.genesis_hash.to_vec(),
            signer_device_id: self.signer_device_id.to_vec(),
            new_device_id: self.new_device_id.to_vec(),
            new_device_signing_pubkey: self.new_device_signing_pubkey.clone(),
            parent_device_tree_root: self.parent_device_tree_root.to_vec(),
            parent_device_tree_version: self.parent_device_tree_version,
            signature_by_signer_device: self.signature_by_signer_device.clone(),
            signature_by_new_device: self.signature_by_new_device.clone(),
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
        if p.signature_by_signer_device.is_empty() || p.signature_by_new_device.is_empty() {
            return Err(DsmError::verification(
                "AddDeviceAdmission: missing a signature",
            ));
        }
        if p.new_device_signing_pubkey.is_empty() {
            return Err(DsmError::verification(
                "AddDeviceAdmission: empty new_device_signing_pubkey",
            ));
        }
        Ok(Self {
            genesis_hash: f32(&p.genesis_hash, "genesis_hash")?,
            signer_device_id: f32(&p.signer_device_id, "signer_device_id")?,
            new_device_id: f32(&p.new_device_id, "new_device_id")?,
            new_device_signing_pubkey: p.new_device_signing_pubkey,
            parent_device_tree_root: f32(&p.parent_device_tree_root, "parent_device_tree_root")?,
            parent_device_tree_version: p.parent_device_tree_version,
            signature_by_signer_device: p.signature_by_signer_device,
            signature_by_new_device: p.signature_by_new_device,
        })
    }
}

/// Existing (authority) device: assemble the admission from the new device's attested half plus the
/// current tree frontier, and apply the GATE signature with the existing device's signing key.
/// `signature_by_new_device` is the new device's self-attestation (verified by the caller first).
#[allow(clippy::too_many_arguments)]
pub fn assemble_and_gate_sign(
    genesis_hash: [u8; 32],
    signer_device_id: [u8; 32],
    new_device_id: [u8; 32],
    new_device_signing_pubkey: Vec<u8>,
    parent_device_tree_root: [u8; 32],
    parent_device_tree_version: u64,
    signature_by_new_device: Vec<u8>,
    signer_signing_sk: &[u8],
) -> Result<AddDeviceAdmission, DsmError> {
    let mut a = AddDeviceAdmission {
        genesis_hash,
        signer_device_id,
        new_device_id,
        new_device_signing_pubkey,
        parent_device_tree_root,
        parent_device_tree_version,
        signature_by_signer_device: Vec::new(),
        signature_by_new_device,
    };
    a.signature_by_signer_device = sphincs_sign(signer_signing_sk, &a.gate_digest())?;
    Ok(a)
}

/// Verify an admission and, on success, return the NEXT Device Tree root after inserting
/// `new_device_id`. Fail-closed. `signer_signing_pubkey` is the existing device's pubkey from the
/// QR the new device scanned (NOT a quorum lookup).
pub fn verify_add_device_admission(
    admission: &AddDeviceAdmission,
    expected_genesis: &[u8; 32],
    current_tree_device_ids: &[[u8; 32]],
    current_tree_version: u64,
    signer_signing_pubkey: &[u8],
) -> Result<[u8; 32], DsmError> {
    // (a) genesis target.
    if &admission.genesis_hash != expected_genesis {
        return Err(DsmError::verification(
            "admission: genesis_hash != target genesis",
        ));
    }
    // (b) signer is already a member of the CURRENT tree (root case: id == genesis).
    let signer_is_member = &admission.signer_device_id == expected_genesis
        || current_tree_device_ids.contains(&admission.signer_device_id);
    if !signer_is_member {
        return Err(DsmError::verification(
            "admission: signer_device_id is not a current Device Tree member",
        ));
    }
    // (b) gate signature under the scanned-QR signer pubkey (the authorization).
    if !admission.verify_gate(signer_signing_pubkey)? {
        return Err(DsmError::verification(
            "admission: gate signature does not verify under signer's device key",
        ));
    }
    // (c) new device's self-attestation (proof of physical possession).
    if !admission.verify_self_attestation()? {
        return Err(DsmError::verification(
            "admission: new-device self-attestation does not verify",
        ));
    }
    // (d) parent frontier matches the current accepted tree.
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
    // (e) applying the insertion yields the next root (idempotent if already present).
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

    /// Build a valid admission for: genesis==root device (signer), admitting a new device.
    fn fixture() -> (AddDeviceAdmission, Vec<u8>, [u8; 32], Vec<[u8; 32]>, u64) {
        let genesis = [0x6E; 32]; // root device id == genesis
        let (signer_pk, signer_sk) = kp(0x11); // existing (root) device signing key
        let (new_pk, new_sk) = kp(0x22); // new device signing key (DBRW-bound)
        let entropy = vec![0xAB; 32];
        let dbrw = vec![0xCD; 48];
        let new_id = derive_secondary_device_id(&entropy, &genesis, &dbrw);
        let current: Vec<[u8; 32]> = vec![genesis];
        let version = 1u64;
        let parent_root = DeviceTree::new(current.clone()).root();

        // New device half.
        let new_sig = sign_self_attestation(&genesis, &new_id, &new_pk, &new_sk).expect("self-sig");
        // Existing device gate-signs.
        let admission = assemble_and_gate_sign(
            genesis,
            genesis,
            new_id,
            new_pk,
            parent_root,
            version,
            new_sig,
            &signer_sk,
        )
        .expect("gate-sign");
        (admission, signer_pk, genesis, current, version)
    }

    #[test]
    fn valid_admission_verifies_and_returns_next_root() {
        let (a, pk, genesis, current, version) = fixture();
        let next =
            verify_add_device_admission(&a, &genesis, &current, version, &pk).expect("verify");
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
    fn tampered_field_breaks_gate() {
        let (mut a, pk, genesis, current, version) = fixture();
        a.new_device_id[0] ^= 0x01; // gate-signed field changed
        assert!(verify_add_device_admission(&a, &genesis, &current, version, &pk).is_err());
    }

    #[test]
    fn wrong_gate_key_rejected() {
        let (a, _pk, genesis, current, version) = fixture();
        let (other_pk, _other_sk) = kp(0x33);
        assert!(verify_add_device_admission(&a, &genesis, &current, version, &other_pk).is_err());
    }

    #[test]
    fn forged_new_device_signature_rejected() {
        // Attacker keeps a valid gate but swaps in a self-attestation under a different key.
        let (mut a, pk, genesis, current, version) = fixture();
        let (evil_pk, evil_sk) = kp(0x44);
        a.signature_by_new_device = sign_self_attestation(
            &genesis,
            &a.new_device_id,
            &a.new_device_signing_pubkey,
            &evil_sk,
        )
        .unwrap();
        let _ = evil_pk;
        // Self-attestation no longer matches new_device_signing_pubkey → rejected.
        assert!(verify_add_device_admission(&a, &genesis, &current, version, &pk).is_err());
    }

    #[test]
    fn non_member_signer_rejected() {
        let genesis = [0x6E; 32];
        let (stranger_pk, stranger_sk) = kp(0x55);
        let stranger_id = [0x88; 32];
        let (new_pk, new_sk) = kp(0x22);
        let new_id = derive_secondary_device_id(&[0xAB; 32], &genesis, &[0xCD; 48]);
        let current: Vec<[u8; 32]> = vec![genesis];
        let parent_root = DeviceTree::new(current.clone()).root();
        let new_sig = sign_self_attestation(&genesis, &new_id, &new_pk, &new_sk).unwrap();
        let a = assemble_and_gate_sign(
            genesis,
            stranger_id,
            new_id,
            new_pk,
            parent_root,
            1,
            new_sig,
            &stranger_sk,
        )
        .unwrap();
        assert!(verify_add_device_admission(&a, &genesis, &current, 1, &stranger_pk).is_err());
    }

    #[test]
    fn stale_parent_frontier_rejected() {
        let (a, pk, genesis, _current, _version) = fixture();
        let advanced: Vec<[u8; 32]> = vec![genesis, [0x99; 32]];
        assert!(verify_add_device_admission(&a, &genesis, &advanced, 2, &pk).is_err());
    }
}
