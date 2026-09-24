// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity route handlers.

use dsm::types::error::DsmError;
use dsm::types::proto as generated;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};
use crate::bridge::{AppQuery, AppResult};
use crate::sdk::app_state::AppState;

/// This device's identity as `AppState` holds it.
struct OwnIdentity {
    device_id: [u8; 32],
    genesis: [u8; 32],
    ak: Vec<u8>,
}

fn own_identity() -> Result<OwnIdentity, DsmError> {
    let device_id: [u8; 32] = AppState::get_device_id()
        .ok_or_else(|| DsmError::InvalidState("device_id not set: no identity yet".into()))?
        .as_slice()
        .try_into()
        .map_err(|e| DsmError::InvalidState(format!("device_id: {e}")))?;
    let genesis: [u8; 32] = AppState::get_genesis_hash()
        .ok_or_else(|| DsmError::InvalidState("genesis_hash not set: no identity yet".into()))?
        .as_slice()
        .try_into()
        .map_err(|e| DsmError::InvalidState(format!("genesis_hash: {e}")))?;
    let ak = AppState::get_public_key()
        .ok_or_else(|| DsmError::InvalidState("signing key not set: no identity yet".into()))?;
    if ak.len() != 64 {
        return Err(DsmError::InvalidState(format!(
            "signing key is {} bytes, not 64",
            ak.len()
        )));
    }
    Ok(OwnIdentity {
        device_id,
        genesis,
        ak,
    })
}

/// The pairing QR a peer scans to add this device: its device id, genesis and
/// AK, and the network its genesis committed. The peer resolves the device's
/// directory entry on its network's pinned set, so the QR names no nodes.
pub(crate) fn pairing_qr() -> Result<generated::ContactQrV3, DsmError> {
    let own = own_identity()?;
    let network = crate::sdk::economic_admission_flow::committed_network_id()?;
    let network = String::from_utf8(network)
        .map_err(|e| DsmError::InvalidState(format!("the committed network id: {e}")))?;
    Ok(generated::ContactQrV3 {
        device_id: own.device_id.to_vec(),
        network,
        genesis_hash: own.genesis.to_vec(),
        signing_public_key: own.ak,
        ..Default::default()
    })
}

/// `"<deviceIdBase32>@<genesisBase32>"`: this device's compact pairing string.
pub(crate) fn pairing_compact() -> Result<String, DsmError> {
    let own = own_identity()?;
    Ok(format!(
        "{}@{}",
        crate::util::text_id::encode_base32_crockford(&own.device_id),
        crate::util::text_id::encode_base32_crockford(&own.genesis)
    ))
}

impl AppRouterImpl {
    /// Dispatch handler for all `identity.*` query routes.
    pub(crate) async fn handle_identity_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // ---------- identity.transport_headers_v3 ----------
            "identity.transport_headers_v3" => match crate::get_transport_headers_v3_bytes() {
                Ok(bytes) => pack_bytes_ok(bytes),
                Err(e) => err(format!("identity.transport_headers_v3 failed: {e}")),
            },

            // -------- identity.pairing_qr (protobuf ContactQrV3) --------
            "identity.pairing_qr" => match pairing_qr() {
                Ok(qr) => pack_envelope_ok(generated::envelope::Payload::ContactQrResponse(qr)),
                Err(e) => err(format!("identity.pairing_qr failed: {e}")),
            },

            // -------- identity.pairing_compact (string: deviceId@genesisBase32) --------
            "identity.pairing_compact" => match pairing_compact() {
                Ok(s) => {
                    let resp = generated::AppStateResponse {
                        key: "pairing".into(),
                        value: Some(s),
                    };
                    pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                }
                Err(e) => err(format!("identity.pairing_compact failed: {e}")),
            },

            _ => err(format!("unknown identity query: {}", q.path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic_fixtures;

    /// The pairing QR carries exactly the identity the device holds and the
    /// network its genesis committed.
    #[test]
    #[serial_test::serial]
    fn the_pairing_qr_is_the_devices_own_identity() {
        economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let identity = economic_fixtures::create_identity(0x5A);

        let qr = pairing_qr().expect("pairing QR");
        assert_eq!(qr.device_id, identity.device_id.to_vec());
        assert_eq!(qr.genesis_hash, identity.genesis.to_vec());
        assert_eq!(qr.signing_public_key, identity.ak_public_key);
        assert_eq!(qr.network.as_bytes(), economic_fixtures::NETWORK);

        let compact = pairing_compact().expect("pairing string");
        assert_eq!(
            compact,
            format!(
                "{}@{}",
                crate::util::text_id::encode_base32_crockford(&identity.device_id),
                crate::util::text_id::encode_base32_crockford(&identity.genesis)
            )
        );
    }
}
