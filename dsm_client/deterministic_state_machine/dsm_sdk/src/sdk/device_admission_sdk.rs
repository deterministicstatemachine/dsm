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
//! device signing key to prove physical possession without revealing the raw key.

use dsm::common::device_admission::{
    derive_secondary_device_id, self_attest_digest, verify_self_attestation_sig, AddDeviceAdmission,
};
use dsm::types::error::DsmError;
use dsm::types::proto::{AddDeviceAdmissionRequestV1, Message as _};

use std::sync::Mutex;

use crate::sdk::app_state::AppState;
use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::storage_node_sdk::{StorageNodeConfig, StorageNodeSDK};

/// Co-present handshake state (SDK transport state, not protocol state). The admission round-trip
/// is two BLE messages seconds apart; these hold the small per-side context between them.
/// NEW device, set at `begin_admission`, consumed at `handle_admission_response`: (entropy,
/// signer_pubkey-from-QR).
static PENDING_OUTBOUND: Mutex<Option<(Vec<u8>, Vec<u8>)>> = Mutex::new(None);
/// EXISTING device, set at `receive_admission_request`, consumed at `approve_pending_admission`:
/// the requesting device's `AddDeviceAdmissionRequestV1` bytes + the BLE peer address to reply to,
/// held until the owner approves.
static PENDING_INBOUND: Mutex<Option<(Vec<u8>, String)>> = Mutex::new(None);

pub struct DeviceAdmissionSDK;

impl DeviceAdmissionSDK {
    fn id32(v: Option<Vec<u8>>, what: &str) -> Result<[u8; 32], DsmError> {
        let v =
            v.ok_or_else(|| DsmError::InvalidState(format!("device admission: missing {what}")))?;
        <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
            DsmError::verification(format!("device admission: {what} is not 32 bytes"))
        })
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
    /// `genesis_hash` comes from the existing device's scanned QR. Derives `DevID_new` (bound to
    /// the device's wallet-seed-rooted `Smaster`) and self-attests with the new device's Genesis v2
    /// AK signing key.
    pub async fn build_admission_request(
        genesis_hash: [u8; 32],
        entropy: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        if entropy.len() != 32 {
            return Err(DsmError::verification(
                "admission request: entropy must be 32 bytes",
            ));
        }
        let s_master = crate::init::current_smaster()?;
        let new_device_id = derive_secondary_device_id(entropy, &genesis_hash, &s_master);
        let new_signing_pubkey = AppState::get_public_key().ok_or_else(|| {
            DsmError::InvalidState("admission request: no device signing pubkey".into())
        })?;
        let core = CoreSDK::new()?;
        let sig = core.sign_bytes_sphincs(&self_attest_digest(
            &genesis_hash,
            &new_device_id,
            &new_signing_pubkey,
        ))?;
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
        let req =
            crate::generated::AddDeviceAdmissionRequestV1::decode(request_bytes).map_err(|e| {
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
        // Verify the new device's signing-key self-attestation (proof of physical possession).
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
        storage
            .apply_admitted_device(&admission, &signer_pubkey)
            .await?;
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
        let (device_ids, _version, root) = storage
            .read_device_tree_state(&admission.genesis_hash)
            .await?;
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

    // ───────────────────────── BLE handshake (Envelope v3) ─────────────────────────

    /// Wrap an admission payload in a canonical Envelope v3 for BLE transport.
    fn build_admission_envelope(
        payload: crate::generated::envelope::Payload,
        genesis: &[u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let device_id = Self::id32(AppState::get_device_id(), "device_id")?;
        let ticks = crate::util::deterministic_time::tick();
        let env = crate::bluetooth::bilateral_envelope::build_envelope(
            &device_id, genesis, ticks, None, payload,
        )?;
        Ok(crate::envelope::transport::to_canonical_bytes(&env))
    }

    /// NEW device: build the request Envelope to send as a `DEVICE_ADMISSION_REQUEST` frame, and
    /// stash the pending `(entropy, signer_pubkey)` (from the scanned QR) needed to adopt the
    /// response. Returns the canonical envelope bytes.
    pub async fn begin_admission(
        genesis: [u8; 32],
        entropy: Vec<u8>,
        signer_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, DsmError> {
        let req_bytes = Self::build_admission_request(genesis, &entropy).await?;
        let req =
            crate::generated::AddDeviceAdmissionRequestV1::decode(&*req_bytes).map_err(|e| {
                DsmError::serialization_error(
                    format!("begin_admission re-decode: {e}"),
                    "AddDeviceAdmissionRequestV1",
                    None::<String>,
                    Some(e),
                )
            })?;
        *PENDING_OUTBOUND.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((entropy, signer_pubkey));
        Self::build_admission_envelope(
            crate::generated::envelope::Payload::DeviceAdmissionRequest(req),
            &genesis,
        )
    }

    /// EXISTING device: an admission request arrived over BLE. Decode + hold it (with the BLE peer
    /// to reply to) pending the owner's approval (the gate). Returns the requesting `new_device_id`
    /// (Base32) for the UI prompt.
    pub fn receive_admission_request(
        envelope_bytes: &[u8],
        peer_address: &str,
    ) -> Result<String, DsmError> {
        let env = crate::envelope::transport::from_canonical_bytes(envelope_bytes)
            .map_err(|e| DsmError::verification(format!("admission request envelope: {e}")))?;
        let req = match env.payload {
            Some(crate::generated::envelope::Payload::DeviceAdmissionRequest(r)) => r,
            _ => {
                return Err(DsmError::verification(
                    "admission request: unexpected envelope payload",
                ))
            }
        };
        let new_id = crate::util::text_id::encode_base32_crockford(&req.new_device_id);
        *PENDING_INBOUND.lock().unwrap_or_else(|p| p.into_inner()) =
            Some((req.encode_to_vec(), peer_address.to_string()));
        Ok(new_id)
    }

    /// EXISTING device: the requesting device id (Base32) currently awaiting the owner's approval,
    /// if any. Polled by the existing device's UI to show the approve prompt.
    pub fn pending_admission_device_id() -> Option<String> {
        let g = PENDING_INBOUND.lock().unwrap_or_else(|p| p.into_inner());
        g.as_ref().and_then(|(req_bytes, _)| {
            crate::generated::AddDeviceAdmissionRequestV1::decode(req_bytes.as_slice())
                .ok()
                .map(|r| crate::util::text_id::encode_base32_crockford(&r.new_device_id))
        })
    }

    /// EXISTING device: the owner approved — gate-sign + insert the held request. Returns the
    /// `(response Envelope bytes, BLE peer address)` so the caller sends a `DEVICE_ADMISSION_RESPONSE`
    /// frame back. Clears the pending request.
    pub async fn approve_pending_admission() -> Result<(Vec<u8>, String), DsmError> {
        let (req_bytes, peer) = PENDING_INBOUND
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| {
                DsmError::InvalidState("no pending admission request to approve".into())
            })?;
        let admission_bytes = Self::approve_admission(&req_bytes).await?;
        let adm_proto =
            crate::generated::AddDeviceAdmissionV1::decode(&*admission_bytes).map_err(|e| {
                DsmError::serialization_error(
                    format!("approve_pending_admission re-decode: {e}"),
                    "AddDeviceAdmissionV1",
                    None::<String>,
                    Some(e),
                )
            })?;
        let genesis = Self::id32(Some(adm_proto.genesis_hash.clone()), "genesis_hash")?;
        let env = Self::build_admission_envelope(
            crate::generated::envelope::Payload::DeviceAdmission(adm_proto),
            &genesis,
        )?;
        Ok((env, peer))
    }

    /// NEW device: a gate-signed admission arrived over BLE. Verify (gate sig under the QR pubkey +
    /// self-attestation), adopt, and establish identity. Consumes the pending outbound state.
    /// Returns `(genesis, new_device_id)`.
    pub async fn handle_admission_response(
        envelope_bytes: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), DsmError> {
        let env = crate::envelope::transport::from_canonical_bytes(envelope_bytes)
            .map_err(|e| DsmError::verification(format!("admission response envelope: {e}")))?;
        let adm_proto = match env.payload {
            Some(crate::generated::envelope::Payload::DeviceAdmission(a)) => a,
            _ => {
                return Err(DsmError::verification(
                    "admission response: unexpected envelope payload",
                ))
            }
        };
        let admission_bytes = adm_proto.encode_to_vec();
        let (entropy, signer_pubkey) = PENDING_OUTBOUND
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| DsmError::InvalidState("no pending admission to adopt".into()))?;
        Self::adopt_admission(&admission_bytes, &signer_pubkey, &entropy).await
    }
}
