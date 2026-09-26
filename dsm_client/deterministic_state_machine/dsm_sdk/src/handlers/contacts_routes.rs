// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contact route handlers extracted from AppRouterImpl.
//!
//! Handles `contacts.list`, `contacts.readContactCode`, and `contacts.addManual`.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};

use super::app_router_impl::{resolve_counterparty_via_transport, AppRouterImpl, ResolvedCounterparty};
use crate::sdk::contact_sdk::contact_add_response;
use super::relationship_status::derive_local_send_status_for_contact;
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    async fn add_resolved_contact(
        &self,
        preferred_alias: &str,
        resolved: ResolvedCounterparty,
    ) -> AppResult {
        let device_id = resolved.entry.body.device_id;
        if let Some(existing) = self.contact_manager.get_verified_contact(device_id).await {
            if existing.genesis_hash == resolved.entry.body.genesis
                && existing.public_key == resolved.entry.body.ak_public_key
            {
                // A contact whose relationship an earlier attempt did not
                // establish is established now.
                if let Err(e) = self.core_sdk.establish_relationship(device_id) {
                    return err(format!("contacts.add: establishing the relationship: {e}"));
                }
                return pack_envelope_ok(generated::envelope::Payload::ContactAddResponse(
                    contact_add_response(&existing),
                ));
            }
            log::warn!(
                "[contacts.add] the scanned identity replaces the contact device={}",
                crate::util::text_id::encode_base32_crockford(&device_id)
                    .chars()
                    .take(8)
                    .collect::<String>(),
            );
        }

        let alias = match preferred_alias.trim() {
            "" => crate::util::text_id::encode_base32_crockford(&device_id)
                .chars()
                .take(8)
                .collect(),
            preferred => preferred.to_string(),
        };

        let mut cm = self.contact_manager.clone();
        let added = match cm
            .add_contact_from_directory(&alias, &resolved.entry, resolved.verifying_nodes)
            .await
        {
            Ok(added) => added,
            Err(e) => return err(format!("Add contact failed: {e}")),
        };
        // The relationship exists from here: its leaf enters this device's
        // tree at h_0, before any step on it (§26).
        if let Err(e) = self.core_sdk.establish_relationship(device_id) {
            return err(format!("contacts.add: establishing the relationship: {e}"));
        }

        #[cfg(all(target_os = "android", feature = "bluetooth"))]
        {
            let Some(stored) = cm.get_verified_contact(device_id).await else {
                return err("contact added, but it is not held in memory".into());
            };
            match crate::bluetooth::sync_contact_to_bluetooth_manager(stored).await {
                Ok(true) => log::info!(
                    "[contacts.add] synced contact device_id={} to the BluetoothManager",
                    dsm::core::utility::labeling::hash_to_short_id(&device_id)
                ),
                Ok(false) => log::info!(
                    "[contacts.add] no BLE stack yet: init loads the contact when it builds one"
                ),
                Err(e) => {
                    return err(format!(
                        "contact added, but syncing it to the BluetoothManager failed: {e}"
                    ))
                }
            }
        }
        // Pairing takes the new contact up now, if the session lets it run.
        crate::bluetooth::contact_added();
        pack_envelope_ok(generated::envelope::Payload::ContactAddResponse(added))
    }

    pub(crate) async fn handle_contacts_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "contacts.list" => {
                let list = match self.contact_manager.list_verified_contacts().await {
                    Ok(list) => list,
                    Err(e) => return err(format!("contacts.list: {e}")),
                };
                let mut items = Vec::with_capacity(list.len());
                for contact in &list {
                    let record = match crate::storage::client_db::get_contact_by_device_id(
                        &contact.device_id,
                    ) {
                        Ok(Some(record)) => record,
                        Ok(None) => {
                            return err(
                                "contacts.list: a listed contact has no persisted row".into()
                            )
                        }
                        Err(e) => return err(format!("contacts.list: contact lookup: {e}")),
                    };
                    let mut item = contact_add_response(contact);
                    item.send_status = Some(derive_local_send_status_for_contact(&record));
                    let session = crate::bluetooth::get_pairing_orchestrator()
                        .get_session_status(&contact.device_id)
                        .await;
                    item.pairing = crate::bluetooth::pairing_orchestrator::contact_pairing_phase(
                        record.ble_address.as_deref().is_some_and(|a| !a.is_empty()),
                        session.as_ref(),
                    ) as i32;
                    items.push(item);
                }
                let reply = generated::ContactsListResponse { contacts: items };
                pack_envelope_ok(generated::envelope::Payload::ContactsListResponse(reply))
            }

            // The card a scanned or pasted contact code carries, read by Rust:
            // the screen renders it and adds the contact through
            // `contacts.addManual`.
            "contacts.readContactCode" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("contacts.readContactCode: ArgPack.codec must be PROTO".into());
                }
                let scanned = match generated::QrScanResultPayload::decode(&*pack.body) {
                    Ok(scanned) => scanned,
                    Err(e) => {
                        return err(format!(
                            "contacts.readContactCode: decode QrScanResultPayload failed: {e}"
                        ))
                    }
                };
                match super::identity_routes::read_contact_code(&scanned.text_utf8) {
                    Ok(card) => {
                        pack_envelope_ok(generated::envelope::Payload::ContactQrResponse(card))
                    }
                    Err(e) => err(format!("contacts.readContactCode: {e}")),
                }
            }

            other => err(format!("contacts: unknown route '{other}'")),
        }
    }

    pub(crate) async fn handle_contacts_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "contacts.addManual" => {
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("contacts.addManual: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::ContactManualAddRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "contacts.addManual: decode ContactManualAddRequest failed: {e}"
                        ))
                    }
                };

                let qr = generated::ContactQrV3 {
                    device_id: req.device_id.clone(),
                    genesis_hash: req.genesis_hash.clone(),
                    signing_public_key: req.signing_public_key.clone(),
                    preferred_alias: req.alias.clone(),
                    ..Default::default()
                };
                let resolved = match resolve_counterparty_via_transport(&qr).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("contacts.addManual: resolve failed: {e}")),
                };
                self.add_resolved_contact(&req.alias, resolved).await
            }
            other => err(format!("contacts: unknown invoke '{other}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use dsm::types::proto as generated;

    #[test]
    fn argpack_codec_proto_value_matches_expected() {
        assert_eq!(generated::Codec::Proto as i32, 1);
        assert_eq!(generated::Codec::Unspecified as i32, 0);
    }

    #[test]
    fn contact_qr_v3_roundtrip() {
        let device_id = vec![0xABu8; 32];
        let genesis_hash = vec![0xCDu8; 32];
        let qr = generated::ContactQrV3 {
            device_id: device_id.clone(),
            network: "test".into(),
            genesis_hash: genesis_hash.clone(),
            signing_public_key: vec![0x22; 64],
            preferred_alias: "Alice".into(),
        };

        let encoded = qr.encode_to_vec();
        let decoded = generated::ContactQrV3::decode(&*encoded).expect("decode");

        assert_eq!(decoded.device_id, device_id);
        assert_eq!(decoded.genesis_hash, genesis_hash);
        assert_eq!(decoded.preferred_alias, "Alice");
        assert_eq!(decoded.network, "test");
        assert_eq!(decoded.signing_public_key.len(), 64);
    }

    #[test]
    fn contact_manual_add_request_roundtrip() {
        let req = generated::ContactManualAddRequest {
            alias: "Bob".into(),
            device_id: vec![0x01; 32],
            genesis_hash: vec![0x02; 32],
            signing_public_key: vec![0x03; 64],
        };

        let encoded = req.encode_to_vec();
        let decoded = generated::ContactManualAddRequest::decode(&*encoded).expect("decode");

        assert_eq!(decoded.alias, "Bob");
        assert_eq!(decoded.device_id, vec![0x01; 32]);
        assert_eq!(decoded.genesis_hash, vec![0x02; 32]);
        assert_eq!(decoded.signing_public_key, vec![0x03; 64]);
    }

    #[test]
    fn argpack_wrapping_contact_qr_v3() {
        let qr = generated::ContactQrV3 {
            device_id: vec![0xAA; 32],
            genesis_hash: vec![0xBB; 32],
            ..Default::default()
        };
        let arg_pack = generated::ArgPack {
            schema_hash: None,
            codec: generated::Codec::Proto as i32,
            body: qr.encode_to_vec(),
        };
        let pack_bytes = arg_pack.encode_to_vec();

        let decoded_pack = generated::ArgPack::decode(&*pack_bytes).expect("decode ArgPack");
        assert_eq!(decoded_pack.codec, generated::Codec::Proto as i32);
        let decoded_qr =
            generated::ContactQrV3::decode(&*decoded_pack.body).expect("decode ContactQrV3");
        assert_eq!(decoded_qr.device_id, vec![0xAA; 32]);
    }

    #[test]
    fn argpack_with_wrong_codec_is_detectable() {
        let arg_pack = generated::ArgPack {
            schema_hash: None,
            codec: generated::Codec::Unspecified as i32,
            body: vec![1, 2, 3],
        };
        assert_ne!(arg_pack.codec, generated::Codec::Proto as i32);
    }

    #[test]
    fn contact_add_response_preserves_all_fields() {
        let resp = generated::ContactAddResponse {
            alias: "Carol".into(),
            device_id: vec![0x55; 32],
            genesis_hash: Some(generated::Hash32 { v: vec![0x66; 32] }),
            chain_tip: Some(generated::Hash32 { v: vec![0x77; 32] }),
            alias_binding: None,
            genesis_verified_online: true,
            verifying_storage_nodes: vec!["node1".into(), "node2".into()],
            ble_address: "AA:BB:CC:DD:EE:FF".into(),
            signing_public_key: vec![0x88; 64],
            send_status: None,
            pairing: generated::ContactPairingPhase::Paired as i32,
        };

        let bytes = resp.encode_to_vec();
        let decoded = generated::ContactAddResponse::decode(&*bytes).expect("decode");

        assert_eq!(decoded.alias, "Carol");
        assert!(decoded.genesis_verified_online);
        assert_eq!(decoded.verifying_storage_nodes.len(), 2);
        assert_eq!(decoded.ble_address, "AA:BB:CC:DD:EE:FF");
    }
}

#[cfg(test)]
mod pairing_phase_tests {
    use crate::bridge::{AppQuery, AppRouter};
    use dsm::types::proto as generated;
    use dsm::types::proto::ContactPairingPhase as Phase;

    async fn pairing_with(
        device: &crate::test_support::two_device::TestDevice,
        peer: [u8; 32],
    ) -> Phase {
        device.enter();
        let answer = device
            .router()
            .query(AppQuery {
                path: "contacts.list".to_string(),
                params: Vec::new(),
            })
            .await;
        assert!(answer.success, "contacts.list: {:?}", answer.error_message);
        let env = crate::handlers::response_helpers::decode_local_envelope(&answer.data)
            .expect("a local answer");
        let Some(generated::envelope::Payload::ContactsListResponse(list)) = env.payload else {
            panic!("contacts.list answered {:?}", env.payload);
        };
        let contact = list
            .contacts
            .iter()
            .find(|c| c.device_id == peer.to_vec())
            .expect("the peer is listed");
        Phase::try_from(contact.pairing).expect("a named phase")
    }

    /// The contact list states where BLE pairing with each contact stands, as
    /// the SDK's pairing loop has it. The contacts screen used to infer it from
    /// raw radio events, and showed "Paired!" when a phone's identity was read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn the_contact_list_states_where_pairing_stands() {
        let pair = crate::test_support::two_device::Pair::boot(0, 0).await;
        let (a, b) = (&pair.a, &pair.b);
        let orchestrator = crate::bluetooth::get_pairing_orchestrator();

        assert_eq!(pairing_with(a, b.device_id).await, Phase::Idle);

        a.enter();
        orchestrator
            .initiate_pairing(b.device_id)
            .await
            .expect("a session for B");
        assert_eq!(pairing_with(a, b.device_id).await, Phase::Searching);

        a.enter();
        crate::storage::client_db::update_contact_ble_status(
            &b.device_id,
            None,
            Some("AA:BB:CC:DD:EE:0B"),
        )
        .expect("pairing stores the address");
        assert_eq!(pairing_with(a, b.device_id).await, Phase::Paired);

        orchestrator.cancel_pairing(&b.device_id).await;
    }
}
