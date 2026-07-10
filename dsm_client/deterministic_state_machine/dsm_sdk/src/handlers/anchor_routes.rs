// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor route handlers for the app router (offline-bearer signal (c)).
//!
//! Query routes:
//! - `anchor.status` → read-only [`AnchorStatusResponse`] diagnostics snapshot of the sender's
//!   anchor appliance (RP2350/TROPIC01). Purely observational: no staging, no counter move, no
//!   device-state mutation. When no appliance can attach it reports `anchor_connected=false`
//!   rather than failing the route.

use dsm::types::proto as generated;

use crate::bridge::{AppQuery, AppResult};

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::pack_envelope_ok;

impl AppRouterImpl {
    /// Dispatch handler for `anchor.*` query routes.
    pub(crate) async fn handle_anchor_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "anchor.status" => {
                let snap = self.core_sdk.anchor_appliance_status();
                let resp = generated::AnchorStatusResponse {
                    anchor_connected: snap.connected,
                    anchor_id: snap.anchor_id.to_vec(),
                    pk_chip: snap.pk_chip,
                    partition_pk: snap.partition_pk,
                    anchor_counter: snap.anchor_counter,
                    frontier_root: snap.frontier_root.to_vec(),
                    enrolled_counter: snap.enrolled_counter,
                    bundle: snap.bundle.to_vec(),
                    status: snap.status,
                };
                pack_envelope_ok(generated::envelope::Payload::AnchorStatusResponse(resp))
            }
            _ => super::response_helpers::err(format!("unknown anchor query: {}", q.path)),
        }
    }
}
