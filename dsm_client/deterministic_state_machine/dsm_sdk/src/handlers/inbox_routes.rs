// SPDX-License-Identifier: MIT OR Apache-2.0
//! Inbox route handlers extracted from AppRouterImpl.
//!
//! Query: `inbox.pull` — fetch inbox items (on-demand).
//! Invoke: `inbox.startPoller` / `inbox.stopPoller` / `inbox.resume` — poller lifecycle.

use prost::Message;

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};
use super::app_router_impl::{collect_tagged_inbox_addresses, RouteFreshness};

/// The most items one `inbox.pull` returns.
const INBOX_PULL_MAX: u32 = 200;

impl AppRouterImpl {
    pub(crate) async fn handle_inbox_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "inbox.pull" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) => pack,
                    Err(e) => return err(format!("inbox.pull: decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("inbox.pull: ArgPack.codec must be PROTO".into());
                }
                let limit = match generated::InboxRequest::decode(&*pack.body) {
                    Ok(req) if (1..=INBOX_PULL_MAX).contains(&req.limit) => req.limit as usize,
                    Ok(req) => {
                        return err(format!(
                            "inbox.pull: limit {} is outside 1..={INBOX_PULL_MAX}",
                            req.limit
                        ))
                    }
                    Err(e) => return err(format!("inbox.pull: decode InboxRequest failed: {e}")),
                };

                let storage_endpoints = match crate::sdk::storage_set::pinned_endpoints() {
                    Ok(endpoints) => endpoints,
                    Err(e) => return err(format!("inbox.pull: no pinned storage set: {e}")),
                };
                let device_id_b32 =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                let mut b0x_sdk = match crate::sdk::b0x_sdk::B0xSDK::new(
                    device_id_b32,
                    self.core_sdk.clone(),
                    storage_endpoints,
                ) {
                    Ok(sdk) => sdk,
                    Err(e) => return err(format!("inbox.pull: b0x init failed: {e}")),
                };

                // §16.4: poll the per-contact rotated addresses — the same
                // addresses storage.sync polls, so transfers and messages are
                // both found.
                let my_genesis = match self.core_sdk.local_genesis_hash().await {
                    Ok(genesis) => match <[u8; 32]>::try_from(genesis.as_slice()) {
                        Ok(genesis) => genesis,
                        Err(e) => {
                            return err(format!("inbox.pull: local genesis is not 32 bytes: {e}"))
                        }
                    },
                    Err(e) => return err(format!("inbox.pull: local genesis unavailable: {e}")),
                };
                let contacts = match crate::storage::client_db::get_all_contacts() {
                    Ok(contacts) => contacts,
                    Err(e) => return err(format!("inbox.pull: load contacts failed: {e}")),
                };
                let tagged_addresses = match collect_tagged_inbox_addresses(
                    my_genesis,
                    self.device_id_bytes,
                    &contacts,
                ) {
                    Ok(addresses) => addresses,
                    Err(e) => return err(format!("inbox.pull: {e}")),
                };

                let mut all_items: Vec<(crate::sdk::b0x_sdk::B0xEntry, RouteFreshness)> =
                    Vec::new();
                let mut poll_errors: Vec<String> = Vec::new();
                for tagged in &tagged_addresses {
                    if all_items.len() >= limit {
                        break;
                    }
                    match b0x_sdk.retrieve_from_b0x_v2(&tagged.address).await {
                        Ok(outcome) => {
                            if let crate::sdk::b0x_sdk::SpoolCoverage::Partial {
                                responded,
                                needed,
                            } = outcome.coverage
                            {
                                poll_errors.push(format!(
                                    "{}: partial read, {responded} of {} members answered, \
                                     {needed} needed",
                                    &tagged.address[..16.min(tagged.address.len())],
                                    outcome.members
                                ));
                            }
                            let remaining = limit - all_items.len();
                            all_items.extend(
                                outcome
                                    .entries
                                    .into_iter()
                                    .take(remaining)
                                    .map(|entry| (entry, tagged.freshness)),
                            );
                        }
                        Err(e) => poll_errors.push(format!(
                            "{}: {e}",
                            &tagged.address[..16.min(tagged.address.len())]
                        )),
                    }
                }
                if all_items.is_empty() && !poll_errors.is_empty() {
                    return err(format!(
                        "inbox.pull: retrieve failed: {}",
                        poll_errors.join("; ")
                    ));
                }

                let inbox_items: Vec<generated::InboxItem> = all_items
                    .iter()
                    .map(|(e, freshness)| generated::InboxItem {
                        id: e.transaction_id.clone(),
                        preview: match &e.kind {
                            crate::sdk::b0x_sdk::B0xEntryKind::Transfer { amount, token_id } => {
                                // The amount as the request states it, in the
                                // token's own decimals when they are known.
                                match super::wallet_routes::token_decimals(token_id) {
                                    Ok(decimals) => format!(
                                        "From: {} Amount: {} {}",
                                        e.sender_device_id,
                                        super::wallet_routes::format_base_units_for_display(
                                            *amount, decimals
                                        ),
                                        token_id
                                    ),
                                    Err(_) => format!(
                                        "From: {} Amount: {} base units of {}",
                                        e.sender_device_id, amount, token_id
                                    ),
                                }
                            }
                            crate::sdk::b0x_sdk::B0xEntryKind::Message { payload_len } => {
                                format!(
                                    "From: {} message:{} bytes",
                                    e.sender_device_id, payload_len
                                )
                            }
                        },
                        sender_id: Some(e.sender_device_id.clone()),
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
                pack_bytes_ok(Vec::new())
            }
            "inbox.stopPoller" => {
                // Lifecycle stop (Activity.onStop). Declines while a transfer is
                // mid-settlement so money in flight is never blocked on the user
                // keeping the app on screen.
                log::info!("[DSM_SDK] inbox.stopPoller called (lifecycle)");
                if let Err(e) = crate::sdk::inbox_poller::stop_poller_for_lifecycle() {
                    return err(format!(
                        "inbox.stopPoller: settlement state unreadable, the poller keeps running: {e}"
                    ));
                }
                pack_bytes_ok(Vec::new())
            }
            "inbox.resume" => {
                log::info!("[DSM_SDK] inbox.resume called");
                crate::sdk::inbox_poller::resume_poller();
                pack_bytes_ok(Vec::new())
            }
            other => err(format!("inbox invoke: unknown method '{other}'")),
        }
    }
}
