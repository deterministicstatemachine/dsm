// SPDX-License-Identifier: MIT OR Apache-2.0
//! Inbox route handlers extracted from AppRouterImpl.
//!
//! Query: `inbox.pull` — fetch inbox items (on-demand).
//! Invoke: `inbox.startPoller` / `inbox.stopPoller` / `inbox.resume` — poller lifecycle.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};
use super::app_router_impl::{collect_tagged_inbox_addresses, RouteFreshness};

impl AppRouterImpl {
    pub(crate) async fn handle_inbox_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "inbox.pull" => {
                log::info!("[DSM_SDK] inbox.pull called");
                // Decode InboxRequest (optional limit)
                let limit: u32 = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::InboxRequest::decode(&*pack.body) {
                            Ok(req) => req.limit.clamp(1, 200), // clamp to 1-200
                            Err(_) => 100,                      // default
                        }
                    }
                    _ => 100, // default limit
                };

                // Get storage endpoints from config
                let storage_endpoints =
                    match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
                        Ok(cfg) => cfg.node_urls,
                        Err(e) => {
                            return err(format!(
                                "inbox.pull: no storage node config available: {}",
                                e
                            ));
                        }
                    };
                if storage_endpoints.is_empty() {
                    return err("inbox.pull: no storage endpoints configured".into());
                }

                // Get device identity for B0x query (MUST be base32 to match storage node auth)
                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

                // Create B0xSDK and retrieve inbox items
                let mut b0x_sdk = match crate::sdk::b0x_sdk::B0xSDK::new(
                    device_id_b32.clone(),
                    self.core_sdk.clone(),
                    storage_endpoints,
                ) {
                    Ok(sdk) => sdk,
                    Err(e) => return err(format!("inbox.pull: b0x init failed: {e}")),
                };

                // Proactively register this device on all storage endpoints to ensure
                // valid tokens before attempting any inbox retrieval. This mirrors the
                // storage.sync handler and avoids 401/InboxTokenInvalid failures when
                // storage nodes have been reset or tokens have expired.
                match b0x_sdk.register_device().await {
                    Ok(_) => log::info!(
                        "[inbox.pull] device registration succeeded on storage endpoints"
                    ),
                    Err(e) => log::warn!(
                        "[inbox.pull] device registration failed (continuing): {}",
                        e
                    ),
                }

                // §16.4: Poll per-contact rotated addresses only.
                // Mirrors the same address computation that storage.sync uses, so both
                // Transfer entries AND Generic (message) entries are discovered.
                let my_genesis: [u8; 32] = self
                    .core_sdk
                    .local_genesis_hash()
                    .await
                    .ok()
                    .and_then(|v| v.as_slice().try_into().ok())
                    .unwrap_or([0u8; 32]);

                let contacts = crate::storage::client_db::get_all_contacts().unwrap_or_default();

                let genesis_display = if my_genesis == [0u8; 32] {
                    "ZERO".to_string()
                } else {
                    let full = crate::util::text_id::encode_base32_crockford(&my_genesis);
                    full[..8.min(full.len())].to_string()
                };
                log::info!(
                    "[inbox.pull] genesis={} device_prefix={}.. contacts={} limit={}",
                    genesis_display,
                    &device_id_b32[..8.min(device_id_b32.len())],
                    contacts.len(),
                    limit,
                );

                let tagged_addresses =
                    collect_tagged_inbox_addresses(my_genesis, self.device_id_bytes, &contacts);

                log::info!(
                    "[inbox.pull] polling {} tagged b0x addresses",
                    tagged_addresses.len(),
                );
                for (i, tagged) in tagged_addresses.iter().enumerate() {
                    log::info!(
                        "[inbox.pull]   addr[{}] = {}... ({:?})",
                        i,
                        &tagged.address[..16.min(tagged.address.len())],
                        tagged.freshness,
                    );
                }

                if tagged_addresses.is_empty() {
                    log::warn!(
                        "[inbox.pull] no addresses to poll (genesis_zero={}, contacts={})",
                        my_genesis == [0u8; 32],
                        contacts.len(),
                    );
                }

                let mut all_items: Vec<(crate::sdk::b0x_sdk::B0xEntry, RouteFreshness)> =
                    Vec::new();
                let mut poll_errors: Vec<String> = Vec::new();
                for tagged in &tagged_addresses {
                    if all_items.len() >= limit as usize {
                        break;
                    }
                    let remaining = (limit as usize) - all_items.len();
                    let entries_res = match tokio::runtime::Handle::try_current() {
                        Ok(handle) => tokio::task::block_in_place(|| {
                            handle
                                .block_on(b0x_sdk.retrieve_from_b0x_v2(&tagged.address, remaining))
                        }),
                        Err(_) => {
                            if let Ok(rt) = tokio::runtime::Runtime::new() {
                                rt.block_on(
                                    b0x_sdk.retrieve_from_b0x_v2(&tagged.address, remaining),
                                )
                            } else {
                                Err(dsm::types::error::DsmError::internal(
                                    "runtime failed",
                                    None::<std::io::Error>,
                                ))
                            }
                        }
                    };
                    match entries_res {
                        Ok(items) => {
                            log::info!(
                                "[inbox.pull] addr {}...: {} items retrieved ({:?})",
                                &tagged.address[..16.min(tagged.address.len())],
                                items.len(),
                                tagged.freshness,
                            );
                            all_items.extend(items.into_iter().map(|e| (e, tagged.freshness)));
                        }
                        Err(e) => {
                            poll_errors.push(self.format_inbox_error(&e));
                            log::warn!(
                                "[inbox.pull] b0x retrieve failed for addr {}: {}",
                                &tagged.address[..16.min(tagged.address.len())],
                                e
                            );
                        }
                    }
                }

                if all_items.is_empty() && !poll_errors.is_empty() {
                    return err(format!("inbox.pull: {}", poll_errors[0]));
                }

                log::info!(
                    "[inbox.pull] total items retrieved: {} (from {} addresses, {} errors)",
                    all_items.len(),
                    tagged_addresses.len(),
                    poll_errors.len(),
                );

                let inbox_items: Vec<generated::InboxItem> = all_items
                    .iter()
                    .map(|(e, freshness)| generated::InboxItem {
                        id: e.transaction_id.clone(),
                        preview: match &e.transaction {
                            dsm::types::operations::Operation::Transfer {
                                amount,
                                token_id,
                                ..
                            } => {
                                let raw = amount.value();
                                let tid_str = if token_id.is_empty() {
                                    "ERA".to_string()
                                } else {
                                    String::from_utf8_lossy(token_id).into_owned()
                                };
                                let tid_upper = tid_str.to_uppercase();
                                let formatted = if tid_upper == "DBTC" || tid_upper == "BTC" {
                                    let scale: u64 = 100_000_000;
                                    let whole = raw / scale;
                                    let frac = raw % scale;
                                    if frac == 0 {
                                        format!("{}.0", whole)
                                    } else {
                                        let frac_str = format!("{:08}", frac);
                                        let trimmed = frac_str.trim_end_matches('0');
                                        format!("{}.{}", whole, trimmed)
                                    }
                                } else {
                                    raw.to_string()
                                };
                                format!(
                                    "From: {} Amount: {} {}",
                                    e.sender_device_id, formatted, tid_upper
                                )
                            }
                            dsm::types::operations::Operation::Generic { data, .. } => {
                                format!("From: {} message:{} bytes", e.sender_device_id, data.len())
                            }
                            _ => format!("From: {} Amount: N/A", e.sender_device_id),
                        },
                        tick: e.tick,
                        sender_id: Some(e.sender_device_id.clone()),
                        payload: vec![],
                        is_stale_route: *freshness == RouteFreshness::PreviousTip,
                    })
                    .collect();

                let resp = generated::InboxResponse { items: inbox_items };
                pack_envelope_ok(generated::envelope::Payload::InboxResponse(resp))
            }

            other => err(format!("inbox: unknown route '{other}'")),
        }
    }

    /// Dispatch handler for inbox poller lifecycle invoke routes.
    pub(crate) async fn handle_inbox_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "inbox.startPoller" => {
                log::info!("[DSM_SDK] inbox.startPoller called");
                crate::sdk::inbox_poller::start_poller();
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(
                    generated::StorageSyncResponse {
                        success: true,
                        pulled: 0,
                        processed: 0,
                        pushed: 0,
                        errors: vec![],
                    },
                ))
            }
            "inbox.stopPoller" => {
                log::info!("[DSM_SDK] inbox.stopPoller called");
                crate::sdk::inbox_poller::stop_poller();
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(
                    generated::StorageSyncResponse {
                        success: true,
                        pulled: 0,
                        processed: 0,
                        pushed: 0,
                        errors: vec![],
                    },
                ))
            }
            "inbox.resume" => {
                log::info!("[DSM_SDK] inbox.resume called");
                crate::sdk::inbox_poller::resume_poller();
                pack_envelope_ok(generated::envelope::Payload::StorageSyncResponse(
                    generated::StorageSyncResponse {
                        success: true,
                        pulled: 0,
                        processed: 0,
                        pushed: 0,
                        errors: vec![],
                    },
                ))
            }
            other => err(format!("inbox invoke: unknown method '{other}'")),
        }
    }
}
