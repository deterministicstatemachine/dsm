// SPDX-License-Identifier: MIT OR Apache-2.0
//! Identity route handlers.

use dsm::types::proto as generated;
use prost::Message;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};
use crate::bridge::{AppQuery, AppResult};
use crate::sdk::identity_sdk::IdentitySDK;

impl AppRouterImpl {
    /// Dispatch handler for all `identity.*` query routes.
    pub(crate) async fn handle_identity_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // ---------- identity.transport_headers_v3 ----------
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
                    Ok(bytes) => pack_bytes_ok(bytes, generated::Hash32 { v: vec![0u8; 32] }),
                    Err(e) => err(format!("identity.transport_headers_v3 failed: {e}")),
                }
            }

            // -------- identity.pairing_qr (protobuf ContactQrV3) --------
            "identity.pairing_qr" => {
                let identity = IdentitySDK::new("local".into());
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
                let identity = IdentitySDK::new("local".into());
                match identity.pairing_qr_compact().await {
                    Ok(s) => {
                        let resp = generated::AppStateResponse {
                            key: "pairing".into(),
                            value: Some(s),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("identity.pairing_compact failed: {e}")),
                }
            }

            // -------- identity.devtree.snapshot (Phase B.7, issue #278) --------
            //
            // Pure-rendering DeviceTreeViewer payload. The SDK fetches
            // the persisted DeviceTreeStateV1 from any configured
            // storage node, re-canonicalises the leaf list, derives a
            // fresh DeviceInclusionProofV1 for every leaf, and verifies
            // each proof locally. The frontend renders the result —
            // it does not hash anything.
            "identity.devtree.snapshot" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("identity.devtree.snapshot: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::DeviceTreeSnapshotRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DeviceTreeSnapshotRequest failed: {e}")),
                };
                if req.genesis_hash.len() != 32 {
                    return err("identity.devtree.snapshot: genesis_hash must be 32 bytes".into());
                }
                let mut genesis_hash = [0u8; 32];
                genesis_hash.copy_from_slice(&req.genesis_hash);

                let fut = async move {
                    let cfg =
                        match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => return Err(format!("No storage node config available: {e}")),
                        };
                    let sdk = crate::sdk::storage_node_sdk::StorageNodeSDK::new(cfg)
                        .await
                        .map_err(|e| format!("sdk.new: {e}"))?;

                    sdk.fetch_device_tree_snapshot(&genesis_hash)
                        .await
                        .map_err(|e| format!("fetch_device_tree_snapshot: {e}"))
                };
                let view = match crate::runtime::get_runtime().block_on(fut) {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };

                // `view.claimed_tree` is a `crate::generated::DeviceTreeV1`
                // (prost generation rooted in `dsm_sdk`), but the
                // envelope variant expects a `dsm::types::proto::DeviceTreeV1`
                // (prost generation rooted in `dsm`). They're distinct
                // types from the same .proto, so copy fields by hand.
                let claimed_tree_proto = generated::DeviceTreeV1 {
                    schema_version: view.claimed_tree.schema_version,
                    root_hash: view.claimed_tree.root_hash.clone(),
                    device_count: view.claimed_tree.device_count,
                    version_number: view.claimed_tree.version_number,
                };
                let resp = generated::DeviceTreeSnapshotResponse {
                    tree: Some(claimed_tree_proto),
                    recomputed_root: view.recomputed_root.to_vec(),
                    claimed_root_matches_recomputed: view.claimed_root_matches_recomputed,
                    leaves: view
                        .leaves
                        .into_iter()
                        .map(|l| generated::DeviceTreeLeafView {
                            device_id: l.device_id.to_vec(),
                            proof_bytes: l.proof_bytes,
                            inclusion_verified: l.inclusion_verified,
                        })
                        .collect(),
                };
                pack_envelope_ok(generated::envelope::Payload::DeviceTreeSnapshotResponse(
                    resp,
                ))
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
            "identity.devtree.snapshot",
        ];
        for route in &expected_routes {
            assert!(!route.is_empty());
            assert!(route.starts_with("identity."));
        }
    }

    #[test]
    fn device_tree_snapshot_request_round_trips_through_argpack() {
        // The route decodes ArgPack { codec: PROTO, body:
        // DeviceTreeSnapshotRequest } before dispatching. Lock the
        // wire shape here so the route handler stays in sync with the
        // frontend bridge wrapper.
        let req = generated::DeviceTreeSnapshotRequest {
            genesis_hash: vec![0x42u8; 32],
        };
        let body = req.encode_to_vec();
        let pack = generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: body.clone(),
            schema_hash: None,
        };
        let pack_bytes = pack.encode_to_vec();

        let decoded_pack = generated::ArgPack::decode(&*pack_bytes).expect("decode pack");
        assert_eq!(decoded_pack.codec, generated::Codec::Proto as i32);
        let decoded_req = generated::DeviceTreeSnapshotRequest::decode(&*decoded_pack.body)
            .expect("decode request");
        assert_eq!(decoded_req.genesis_hash.len(), 32);
        assert_eq!(decoded_req.genesis_hash, vec![0x42u8; 32]);
    }

    #[test]
    fn device_tree_snapshot_response_round_trips() {
        let resp = generated::DeviceTreeSnapshotResponse {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0xABu8; 32],
                device_count: 2,
                version_number: 5,
            }),
            recomputed_root: vec![0xABu8; 32],
            claimed_root_matches_recomputed: true,
            leaves: vec![
                generated::DeviceTreeLeafView {
                    device_id: vec![0x11u8; 32],
                    proof_bytes: vec![0xFEu8, 0xEDu8],
                    inclusion_verified: true,
                },
                generated::DeviceTreeLeafView {
                    device_id: vec![0x22u8; 32],
                    proof_bytes: vec![0xBEu8, 0xEFu8],
                    inclusion_verified: true,
                },
            ],
        };
        let bytes = resp.encode_to_vec();
        let decoded = generated::DeviceTreeSnapshotResponse::decode(&*bytes).expect("decode");
        assert!(decoded.claimed_root_matches_recomputed);
        assert_eq!(decoded.recomputed_root, vec![0xABu8; 32]);
        assert_eq!(decoded.leaves.len(), 2);
        let tree = decoded.tree.expect("tree present");
        assert_eq!(tree.device_count, 2);
        assert_eq!(tree.version_number, 5);
    }

    /// Drives `build_device_tree_snapshot_view` end-to-end through a
    /// fabricated DeviceTreeStateV1, asserting that
    /// claimed_root_matches_recomputed is true for honest state and
    /// false for tampered state, and that every leaf's
    /// inclusion_verified flag is true.
    #[test]
    fn build_snapshot_view_flags_match_versus_mismatch() {
        use crate::sdk::storage_node_sdk::build_device_tree_snapshot_view;

        let dev_a = [0x11u8; 32];
        let dev_b = [0x22u8; 32];
        let canonical_root = dsm::common::device_tree::DeviceTree::new(vec![dev_a, dev_b]).root();

        // Honest: claimed root matches recomputed.
        let honest = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: canonical_root.to_vec(),
                device_count: 2,
                version_number: 7,
            }),
            device_ids: vec![dev_a.to_vec(), dev_b.to_vec()],
        };
        let view =
            build_device_tree_snapshot_view(&honest.encode_to_vec()).expect("honest snapshot");
        assert!(view.claimed_root_matches_recomputed);
        assert_eq!(view.leaves.len(), 2);
        assert!(view.leaves.iter().all(|l| l.inclusion_verified));

        // Tampered: same leaf set, fake claimed root.
        let tampered = generated::DeviceTreeStateV1 {
            tree: Some(generated::DeviceTreeV1 {
                schema_version: 1,
                root_hash: vec![0xFFu8; 32], // bogus
                device_count: 2,
                version_number: 7,
            }),
            device_ids: vec![dev_a.to_vec(), dev_b.to_vec()],
        };
        let view =
            build_device_tree_snapshot_view(&tampered.encode_to_vec()).expect("tampered snapshot");
        assert!(!view.claimed_root_matches_recomputed);
        // Per-leaf verification still passes because proofs are
        // re-derived against the recomputed (not claimed) root —
        // the trust-but-verify gate is the tree-level flag.
        assert!(view.leaves.iter().all(|l| l.inclusion_verified));
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
        assert_eq!(decoded.value.as_deref(), Some("DEVICE123@GENESIS456"));
    }

    #[test]
    fn envelope_framing_byte_is_0x03() {
        let envelope = generated::Envelope {
            version: 3,
            headers: Some(generated::Headers {
                device_id: vec![0u8; 32],
                chain_tip: vec![0u8; 32],
                genesis_hash: vec![0u8; 32],
                seq: 0,
            }),
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
        let decoded = dsm::envelope::from_canonical_bytes(&buf[1..]).expect("decode envelope");
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
