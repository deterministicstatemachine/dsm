// SPDX-License-Identifier: MIT OR Apache-2.0
//! Contact route handlers extracted from AppRouterImpl.
//!
//! Handles `contacts.list`, `contacts.handle_contact_qr_v3`, and `contacts.addManual`.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};

use super::app_router_impl::{resolve_counterparty_via_transport, AppRouterImpl, ResolvedCounterparty};
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    async fn add_resolved_contact(
        &self,
        preferred_alias: &str,
        resolved: ResolvedCounterparty,
    ) -> AppResult {
        if let Some(existing) = self
            .contact_manager
            .get_verified_contact(resolved.device_id)
            .await
        {
            let genesis_matches = existing.genesis_hash == resolved.genesis_hash;
            let signing_key_matches = resolved.signing_public_key.is_empty()
                || existing.public_key.is_empty()
                || existing.public_key == resolved.signing_public_key;
            if genesis_matches && signing_key_matches {
                let resp = generated::ContactAddResponse {
                    alias: existing.alias.clone(),
                    device_id: existing.device_id.to_vec(),
                    genesis_hash: Some(generated::Hash32 {
                        v: existing.genesis_hash.to_vec(),
                    }),
                    chain_tip: existing
                        .chain_tip
                        .as_ref()
                        .map(|h| generated::Hash32 { v: h.to_vec() }),
                    chain_tip_smt_proof: None,
                    alias_binding: None,
                    genesis_verified_online: existing.genesis_verified_online,
                    verify_counter: existing.verified_at_commit_height,
                    added_counter: 0,
                    verifying_storage_nodes: existing
                        .verifying_storage_nodes
                        .iter()
                        .map(|nid| nid.to_string())
                        .collect(),
                    ble_address: existing.ble_address.clone().unwrap_or_default(),
                    signing_public_key: existing.public_key.clone(),
                };
                return pack_envelope_ok(generated::envelope::Payload::ContactAddResponse(resp));
            }

            log::warn!(
                "[contacts.add] repairing existing contact device={} genesis_match={} signing_key_match={}",
                crate::util::text_id::encode_base32_crockford(&resolved.device_id)
                    .get(..8)
                    .unwrap_or("?"),
                genesis_matches,
                signing_key_matches,
            );
        }

        let mut cm = self.contact_manager.clone();
        let alias_short: String = {
            let preferred = preferred_alias.trim().to_string();
            if !preferred.is_empty() {
                preferred
            } else {
                crate::util::text_id::encode_base32_crockford(&resolved.device_id)
                    .chars()
                    .take(8)
                    .collect()
            }
        };

        log::info!(
            "[DSM_SDK] 🔍 Contact resolution: payload_len={}, device_id_preview={:?}, genesis_hash_preview={:?}",
            resolved.genesis_payload.len(),
            &resolved.device_id[..8],
            &resolved.genesis_hash[..8]
        );

        if resolved.genesis_payload.is_empty() {
            log::info!(
                "[DSM_SDK] Contact add: using verified-hash path; alias={}, verifying_nodes={}",
                alias_short,
                resolved.verifying_nodes.len()
            );
            let verifying_nodes = resolved.verifying_nodes.clone();

            match cm
                .add_contact_with_verified_hash_from_nodes_and_signing_key(
                    resolved.device_id,
                    &alias_short,
                    resolved.genesis_hash,
                    verifying_nodes,
                    resolved.signing_public_key.clone(),
                )
                .await
            {
                Ok(verified) => {
                    let ble_contact = dsm::types::contact_types::DsmVerifiedContact {
                        alias: alias_short.clone(),
                        device_id: resolved.device_id,
                        genesis_hash: resolved.genesis_hash,
                        public_key: resolved.signing_public_key.clone(),
                        genesis_material: Vec::new(),
                        chain_tip: None,
                        chain_tip_smt_proof: None,
                        genesis_verified_online: true,
                        verified_at_commit_height: crate::util::deterministic_time::tick(),
                        added_at_commit_height: crate::util::deterministic_time::tick(),
                        last_updated_commit_height: crate::util::deterministic_time::tick(),
                        verifying_storage_nodes: Vec::new(),
                        ble_address: None,
                    };
                    match crate::bluetooth::ensure_bluetooth_manager_and_sync_contact(ble_contact)
                        .await
                    {
                        Ok(true) => {
                            log::warn!("[contacts.add] ✅ Synced contact device_id={} with public_key_len={} to BluetoothManager for BLE bilateral (verified-hash path)",
                                dsm::core::utility::labeling::hash_to_short_id(&resolved.device_id), resolved.signing_public_key.len());
                        }
                        Ok(false) => {
                            log::warn!(
                                "[contacts.add] ⚠️ BLE not available on this platform or no identity yet (verified-hash path)"
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "[contacts.add] ❌ Failed to sync contact to BluetoothManager (verified-hash path): {e}"
                            );
                        }
                    }
                    pack_envelope_ok(generated::envelope::Payload::ContactAddResponse(verified))
                }
                Err(e) => err(format!("Add contact (verified-hash) failed: {e}")),
            }
        } else {
            log::info!(
                "[DSM_SDK] Contact add: using payload+hash path; alias={}",
                alias_short
            );
            match cm
                .add_contact_with_genesis_and_hash_and_signing_key(
                    resolved.device_id,
                    &alias_short,
                    resolved.genesis_hash,
                    &resolved.genesis_payload,
                    resolved.signing_public_key.clone(),
                    resolved.verifying_nodes.clone(),
                )
                .await
            {
                Ok(verified) => {
                    let ble_contact = dsm::types::contact_types::DsmVerifiedContact {
                        alias: alias_short.clone(),
                        device_id: resolved.device_id,
                        genesis_hash: resolved.genesis_hash,
                        public_key: resolved.signing_public_key.clone(),
                        genesis_material: Vec::new(),
                        chain_tip: None,
                        chain_tip_smt_proof: None,
                        genesis_verified_online: true,
                        verified_at_commit_height: crate::util::deterministic_time::tick(),
                        added_at_commit_height: crate::util::deterministic_time::tick(),
                        last_updated_commit_height: crate::util::deterministic_time::tick(),
                        verifying_storage_nodes: Vec::new(),
                        ble_address: None,
                    };
                    match crate::bluetooth::ensure_bluetooth_manager_and_sync_contact(ble_contact)
                        .await
                    {
                        Ok(true) => {
                            log::warn!("[contacts.add] ✅ Synced contact device_id={} with public_key_len={} to BluetoothManager for BLE bilateral (genesis path)",
                                dsm::core::utility::labeling::hash_to_short_id(&resolved.device_id), resolved.signing_public_key.len());
                        }
                        Ok(false) => {
                            log::warn!(
                                "[contacts.add] ⚠️ BLE not available on this platform or no identity yet (genesis path)"
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "[contacts.add] ❌ Failed to sync contact to BluetoothManager (genesis path): {e}"
                            );
                        }
                    }
                    pack_envelope_ok(generated::envelope::Payload::ContactAddResponse(verified))
                }
                Err(e) => err(format!("Add contact (genesis+hash) failed: {e}")),
            }
        }
    }

    pub(crate) async fn handle_contacts_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "contacts.list" => {
                let list = self.contact_manager.list_verified_contacts().await;
                log::info!("[contacts.list] Returning {} contacts", list.len());
                for c in &list {
                    log::info!(
                        "[contacts.list] Contact: alias='{}' (len={}), device_id len={}, genesis_hash len={}",
                        c.alias,
                        c.alias.len(),
                        c.device_id.len(),
                        c.genesis_hash.len()
                    );
                }
                let items: Vec<generated::ContactAddResponse> = list
                    .into_iter()
                    .map(|c| generated::ContactAddResponse {
                        alias: c.alias,
                        device_id: c.device_id.to_vec(),
                        genesis_hash: Some(generated::Hash32 {
                            v: c.genesis_hash.to_vec(),
                        }),
                        chain_tip: c
                            .chain_tip
                            .as_ref()
                            .map(|h| generated::Hash32 { v: h.to_vec() }),
                        chain_tip_smt_proof: None,
                        alias_binding: None,
                        genesis_verified_online: c.genesis_verified_online,
                        verify_counter: c.verified_at_commit_height,
                        added_counter: c.added_at_commit_height,
                        verifying_storage_nodes: c
                            .verifying_storage_nodes
                            .iter()
                            .map(|nid| nid.to_string())
                            .collect(),
                        ble_address: c.ble_address.clone().unwrap_or_default(),
                        signing_public_key: c.public_key.clone(),
                    })
                    .collect();

                let reply = generated::ContactsListResponse { contacts: items };
                pack_envelope_ok(generated::envelope::Payload::ContactsListResponse(reply))
            }

            "contacts.handle_contact_qr_v3" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("contacts.handle_contact_qr_v3: ArgPack.codec must be PROTO".into());
                }
                let qr = match generated::ContactQrV3::decode(&*pack.body) {
                    Ok(qr) => qr,
                    Err(e) => return err(format!("decode ContactQrV3 failed: {e}")),
                };

                let resolved = match resolve_counterparty_via_transport(&qr).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("counterparty resolve failed: {e}")),
                };

                self.add_resolved_contact(&qr.preferred_alias, resolved)
                    .await
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
