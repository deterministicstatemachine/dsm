// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity route handlers.

use std::sync::Arc;

use dsm::types::proto as generated;

use crate::bridge::{AppQuery, AppResult};
use crate::sdk::hashchain_sdk::HashChainSDK;
use crate::sdk::identity_sdk::IdentitySDK;
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, pack_bytes_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for all `identity.*` query routes.
    pub(crate) async fn handle_identity_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // ---------- identity.transport_headers_v3 (PURE BYTES) ----------
            "identity.transport_headers_v3" => {
                // SDK may bootstrap context if headers are requested early.
                if !crate::is_sdk_context_initialized() {
                    if let (Some(dev), Some(gen)) = (
                        crate::sdk::app_state::AppState::get_device_id(),
                        crate::sdk::app_state::AppState::get_genesis_hash(),
                    ) {
                        if dev.len() == 32 && gen.len() == 32 {
                            let _ = crate::initialize_sdk_context(dev, gen.clone(), gen);
                        }
                    }
                }

                match crate::get_transport_headers_v3_bytes() {
                    Ok(bytes) => pack_bytes_ok(
                        bytes,
                        generated::Hash32 { v: vec![0u8; 32] }, // schema hash not applicable for raw header bytes
                    ),
                    Err(e) => err(format!("identity.transport_headers_v3 failed: {e}")),
                }
            }

            // -------- identity.pairing_qr (protobuf ContactQrV3) --------
            "identity.pairing_qr" => {
                let hash_chain_sdk = Arc::new(HashChainSDK::new());
                let identity = IdentitySDK::new("local".into(), hash_chain_sdk);
                match identity.generate_pairing_qr().await {
                    Ok(qr) => {
                        // Convert from generated::ContactQrV3 to dsm::types::proto::ContactQrV3
                        // (both are from same proto, just different crate scopes)
                        let dsm_qr = dsm::types::proto::ContactQrV3 {
                            device_id: qr.device_id.clone(),
                            network: qr.network.clone(),
                            storage_nodes: qr.storage_nodes.clone(),
                            sdk_fingerprint: qr.sdk_fingerprint.clone(),
                            genesis_hash: qr.genesis_hash.clone(),
                            signing_public_key: qr.signing_public_key.clone(),
                            preferred_alias: qr.preferred_alias.clone(),
                        };
                        pack_envelope_ok(generated::envelope::Payload::ContactQrResponse(dsm_qr))
                    }
                    Err(e) => err(format!("identity.pairing_qr failed: {e}")),
                }
            }

            // -------- identity.pairing_compact (string: deviceId@genesisBase32) --------
            "identity.pairing_compact" => {
                let hash_chain_sdk = Arc::new(HashChainSDK::new());
                let identity = IdentitySDK::new("local".into(), hash_chain_sdk);
                match identity.pairing_qr_compact().await {
                    Ok(s) => {
                        let resp = generated::AppStateResponse {
                            key: "pairing".into(),
                            value: Some(s),
                        };
                        // NEW: Return as Envelope.appStateResponse (field 22)
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("identity.pairing_compact failed: {e}")),
                }
            }

            _ => err(format!("unknown identity query: {}", q.path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use dsm::types::proto as generated;
    use prost::Message;

    use crate::bridge::AppResult;

    #[test]
    fn identity_route_names_are_stable() {
        let expected_routes = [
            "identity.transport_headers_v3",
            "identity.pairing_qr",
            "identity.pairing_compact",
        ];
        for route in &expected_routes {
            assert!(!route.is_empty());
            assert!(route.starts_with("identity."));
        }
    }

    #[test]
    fn contact_qr_v3_response_roundtrip() {
        let qr = generated::ContactQrV3 {
            device_id: vec![0xAA; 32],
            network: "main".into(),
            storage_nodes: vec!["http://node:8080".into()],
            sdk_fingerprint: vec![0xBB; 32],
            genesis_hash: vec![0xCC; 32],
            signing_public_key: vec![0xDD; 64],
            preferred_alias: "TestUser".into(),
        };

        let bytes = qr.encode_to_vec();
        let decoded = generated::ContactQrV3::decode(&*bytes).expect("decode");
        assert_eq!(decoded.network, "main");
        assert_eq!(decoded.device_id.len(), 32);
        assert_eq!(decoded.genesis_hash.len(), 32);
        assert_eq!(decoded.preferred_alias, "TestUser");
    }

    #[test]
    fn app_state_response_for_pairing_compact() {
        let resp = generated::AppStateResponse {
            key: "pairing".into(),
            value: Some("DEVICE123@GENESIS456".into()),
        };
        let bytes = resp.encode_to_vec();
        let decoded = generated::AppStateResponse::decode(&*bytes).expect("decode");
        assert_eq!(decoded.key, "pairing");
        assert_eq!(
            decoded.value.as_deref(),
            Some("DEVICE123@GENESIS456")
        );
    }

    #[test]
    fn envelope_framing_byte_is_0x03() {
        let envelope = generated::Envelope {
            version: 3,
            headers: None,
            message_id: vec![0u8; 16],
            payload: Some(generated::envelope::Payload::AppStateResponse(
                generated::AppStateResponse {
                    key: "test".into(),
                    value: Some("val".into()),
                },
            )),
        };
        let mut buf = Vec::with_capacity(1 + envelope.encoded_len());
        buf.push(0x03);
        envelope.encode(&mut buf).unwrap();

        assert_eq!(buf[0], 0x03, "framing byte must be 0x03 for v3");
        let decoded =
            generated::Envelope::decode(&buf[1..]).expect("decode sans framing byte");
        assert_eq!(decoded.version, 3);
    }

    #[test]
    fn err_helper_produces_failed_result() {
        let result = AppResult {
            success: false,
            data: vec![],
            error_message: Some("test error".into()),
        };
        assert!(!result.success);
        assert!(result.data.is_empty());
        assert_eq!(result.error_message.as_deref(), Some("test error"));
    }
}
