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
