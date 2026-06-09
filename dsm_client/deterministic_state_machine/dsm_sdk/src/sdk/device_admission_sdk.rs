// SPDX-License-Identifier: Apache-2.0
//
//! Secondary-device admission orchestration (§16.3) — the gate, driven by the existing device.
//!
//! Three transport-agnostic calls compose the co-present BLE handshake; all logic is here in Rust,
//! and the only on-device piece is the live two-device link that carries the two messages:
//!   1. NEW device → `build_admission_request` → (BLE) → EXISTING device
//!   2. EXISTING device → `approve_admission` (verify + gate-sign + insert) → (BLE) → NEW device
//!   3. NEW device → `adopt_admission` (verify gate under the scanned-QR pubkey + confirm membership)
//!
//! No quorum, no external verifier: the new device gets the existing device's signing pubkey from
//! the QR it scanned in person; the existing device's gate signature is the authorization (only a
//! key already in the tree can produce a verifying admission). The new device co-signs with its
//! DBRW-bound key to prove physical possession without revealing the raw DBRW.

use dsm::common::device_admission::{
    derive_secondary_device_id, self_attest_digest, verify_self_attestation_sig, AddDeviceAdmission,
};
use dsm::types::error::DsmError;
use dsm::types::proto::{AddDeviceAdmissionRequestV1, Message as _};

use crate::sdk::app_state::AppState;
use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};

pub struct DeviceAdmissionSDK;

impl DeviceAdmissionSDK {
    fn id32(v: Option<Vec<u8>>, what: &str) -> Result<[u8; 32], DsmError> {
        let v = v.ok_or_else(|| DsmError::InvalidState(format!("device admission: missing {what}")))?;
        <[u8; 32]>::try_from(v.as_slice())
            .map_err(|_| DsmError::verification(format!("device admission: {what} is not 32 bytes")))
    }

    async fn storage() -> Result<StorageNodeSDK, DsmError> {
        let cfg = StorageNodeConfig::from_env_config().await.map_err(|e| {
            DsmError::storage(format!("storage config: {e}"), None::<std::io::Error>)
        })?;
        StorageNodeSDK::new(cfg)
            .await
            .map_err(|e| DsmError::storage(format!("storage sdk: {e}"), None::<std::io::Error>))
    }

    /// NEW device: build the admission request to send to the existing device. `entropy` is 32 bytes
    /// generated at the platform boundary (as in the genesis/secondary setup, which is untouched).
    /// `genesis_hash` comes from the existing device's scanned QR. Derives `DevID_new` (unchanged
    /// derivation) and self-attests with the new device's DBRW-bound signing key.
    pub async fn build_admission_request(
        genesis_hash: [u8; 32],
        entropy: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        if entropy.len() != 32 {
            return Err(DsmError::verification(
                "admission request: entropy must be 32 bytes",
            ));
        }
        let dbrw = crate::fetch_dbrw_binding_key()?;
        let new_device_id = derive_secondary_device_id(entropy, &genesis_hash, &dbrw);
        let new_signing_pubkey = AppState::get_public_key().ok_or_else(|| {
            DsmError::InvalidState("admission request: no device signing pubkey".into())
        })?;
        let core = CoreSDK::new()?;
        let sig = core
            .sign_bytes_sphincs(&self_attest_digest(&genesis_hash, &new_device_id, &new_signing_pubkey))?;
        Ok(AddDeviceAdmissionRequestV1 {
            genesis_hash: genesis_hash.to_vec(),
            new_device_id: new_device_id.to_vec(),
            new_device_signing_pubkey: new_signing_pubkey,
            signature_by_new_device: sig,
        }
        .encode_to_vec())
    }

    /// EXISTING (authority) device: verify the new device's request, gate-sign, and insert. Returns
    /// the gate-signed `AddDeviceAdmission` bytes to send back over BLE. Fail-closed.
    pub async fn approve_admission(request_bytes: &[u8]) -> Result<Vec<u8>, DsmError> {
        let req = AddDeviceAdmissionRequestV1::decode(request_bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("admission request decode: {e}"),
                "AddDeviceAdmissionRequestV1",
                None::<String>,
                Some(e),
            )
        })?;
        let genesis = Self::id32(Some(req.genesis_hash.clone()), "genesis_hash")?;
        let new_device_id = Self::id32(Some(req.new_device_id.clone()), "new_device_id")?;
        if req.new_device_signing_pubkey.is_empty() || req.signature_by_new_device.is_empty() {
            return Err(DsmError::verification(
                "admission request: missing new-device pubkey/signature",
            ));
        }
        // The request must target THIS device's genesis identity.
        let my_genesis = Self::id32(AppState::get_genesis_hash(), "genesis_hash")?;
        if genesis != my_genesis {
            return Err(DsmError::verification(
                "admission request: genesis != this device's genesis",
            ));
        }
        // Verify the new device's DBRW-bound self-attestation (proof of physical possession).
        if !verify_self_attestation_sig(
            &genesis,
            &new_device_id,
            &req.new_device_signing_pubkey,
            &req.signature_by_new_device,
        )? {
            return Err(DsmError::verification(
                "admission request: new-device self-attestation invalid",
            ));
        }

        let signer_device_id = Self::id32(AppState::get_device_id(), "device_id")?;
        let storage = Self::storage().await?;
        let (_ids, version, parent_root) = storage.read_device_tree_state(&genesis).await?;

        // Build + gate-sign with this (existing, authorized) device's signing key.
        let mut admission = AddDeviceAdmission {
            genesis_hash: genesis,
            signer_device_id,
            new_device_id,
            new_device_signing_pubkey: req.new_device_signing_pubkey,
            parent_device_tree_root: parent_root,
            parent_device_tree_version: version,
            signature_by_signer_device: Vec::new(),
            signature_by_new_device: req.signature_by_new_device,
        };
        let core = CoreSDK::new()?;
        admission.signature_by_signer_device = core.sign_bytes_sphincs(&admission.gate_digest())?;

        // Verify (including our own gate signature) + insert + publish the updated tree.
        let signer_pubkey = AppState::get_public_key().ok_or_else(|| {
            DsmError::InvalidState("approve_admission: no device signing pubkey".into())
        })?;
        storage.apply_admitted_device(&admission, &signer_pubkey).await?;
        Ok(admission.to_bytes())
    }

    /// NEW device: adopt a gate-signed admission received from the existing device. Verifies the
    /// gate signature under the signer pubkey obtained from the scanned QR, the new-device
    /// self-attestation, and that the published tree now contains the new device — then
    /// establishes THIS device's identity as a member of the genesis tree (the gated replacement
    /// for the old self-insert's identity setup). `entropy` is the same 32 bytes used in
    /// `build_admission_request` (so the DevID and SDK context are consistent). Returns
    /// `(genesis_hash, new_device_id)`.
    pub async fn adopt_admission(
        admission_bytes: &[u8],
        signer_pubkey_from_qr: &[u8],
        entropy: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), DsmError> {
        if entropy.len() != 32 {
            return Err(DsmError::verification("adopt: entropy must be 32 bytes"));
        }
        let admission = AddDeviceAdmission::from_bytes(admission_bytes)?;
        if !admission.verify_gate(signer_pubkey_from_qr)? {
            return Err(DsmError::verification(
                "adopt: gate signature invalid under scanned-QR signer pubkey",
            ));
        }
        if !admission.verify_self_attestation()? {
            return Err(DsmError::verification(
                "adopt: new-device self-attestation invalid",
            ));
        }
        let storage = Self::storage().await?;
        let (device_ids, _version, root) =
            storage.read_device_tree_state(&admission.genesis_hash).await?;
        if !device_ids.contains(&admission.new_device_id) {
            return Err(DsmError::verification(
                "adopt: new device not present in the published Device Tree",
            ));
        }

        // Establish this device's identity as a member of the genesis tree.
        let device_id = admission.new_device_id.to_vec();
        let genesis = admission.genesis_hash.to_vec();
        let public_key = AppState::get_public_key().unwrap_or_default();
        let smt_root = dsm::merkle::sparse_merkle_tree::empty_root(
            dsm::merkle::sparse_merkle_tree::DEFAULT_SMT_HEIGHT,
        )
        .to_vec();
        AppState::set_identity_info(device_id.clone(), public_key, genesis.clone(), smt_root);
        AppState::set_has_identity(true);
        // Override the single-device root that set_identity_info auto-computes with the real
        // multi-device R_G from the published tree.
        AppState::set_device_tree_root(root);
        crate::initialize_sdk_context(device_id, genesis, entropy.to_vec())?;

        Ok((admission.genesis_hash, admission.new_device_id))
    }
}
