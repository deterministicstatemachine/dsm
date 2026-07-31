// SPDX-License-Identifier: MIT OR Apache-2.0
//! `route.*` route handlers — frontend-facing wrappers around the
//! chunk #3 SDK helpers.  These exist purely to expose the existing
//! `route_commit_sdk` surface across the JNI boundary so the React
//! UI (and any other host) can drive the routing pipeline without
//! needing to re-implement BLAKE3 / canonical encoding / storage
//! protocols in TypeScript.
//!
//! Three routes:
//!   * `route.computeExternalCommitment` (query) — pure compute.
//!     Takes raw `RouteCommitV1` bytes, returns Base32-Crockford X.
//!     No I/O.
//!   * `route.publishExternalCommitment` (invoke) — writes the
//!     storage-node anchor at `sofi/extcommit/{X_b32}`.
//!   * `route.isExternalCommitmentVisible` (query) — fetches the
//!     anchor; returns `"true"` / `"false"` in
//!     `AppStateResponse.value`.
//!
//! Wire format mirrors the posted_dlv pattern: ArgPack-wrapped raw
//! bytes for the request body, line-separated string in
//! `AppStateResponse.value` for the response.  A future commit can
//! promote any of these to typed protos without changing the call
//! surface.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

/// Unwrap an ArgPack if present, fall back to bare bytes.
/// Mirrors `dlv_routes::unwrap_argpack`.
fn unwrap_argpack(args: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(pack) = generated::ArgPack::decode(args) {
        if pack.codec != generated::Codec::Proto as i32 {
            return Err("ArgPack.codec must be PROTO".into());
        }
        Ok(pack.body)
    } else {
        Ok(args.to_vec())
    }
}

impl AppRouterImpl {
    /// Query dispatch for `route.*` read-only paths.
    pub(crate) async fn handle_route_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "route.computeExternalCommitment" => self.route_compute_external_commitment(q).await,
            "route.isExternalCommitmentVisible" => {
                self.route_is_external_commitment_visible(q).await
            }
            "route.listAdvertisementsForPair" => self.route_list_advertisements_for_pair(q).await,
            other => err(format!("unknown route query path: {other}")),
        }
    }

    /// Invoke dispatch for `route.*` mutating paths.
    pub(crate) async fn handle_route_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "route.publishExternalCommitment" => self.route_publish_external_commitment(i).await,
            "route.signRouteCommit" => self.route_sign_route_commit(i).await,
            "route.publishRoutingAdvertisement" => {
                self.route_publish_routing_advertisement(i).await
            }
            "route.syncVaultsForPair" => self.route_sync_vaults_for_pair(i).await,
            "route.findAndBindBestPath" => self.route_find_and_bind_best_path(i).await,
            other => err(format!("unknown route invoke method: {other}")),
        }
    }

    /// `route.computeExternalCommitment` — pure compute.  Decodes the
    /// raw `RouteCommitV1` bytes the caller supplied, runs the SDK's
    /// canonicalise → BLAKE3 derivation, and returns the 32-byte X
    /// as Base32 Crockford in `AppStateResponse.value`.
    ///
    /// Lets TS callers obtain X without re-implementing the
    /// signature-zeroing canonicalisation in the frontend.
    async fn route_compute_external_commitment(&self, q: AppQuery) -> AppResult {
        let bytes = match unwrap_argpack(&q.params) {
            Ok(b) => b,
            Err(e) => return err(format!("route.computeExternalCommitment: {e}")),
        };
        if bytes.is_empty() {
            return err("route.computeExternalCommitment: empty RouteCommitV1 payload".into());
        }
        let rc = match generated::RouteCommitV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "route.computeExternalCommitment: decode RouteCommitV1 failed: {e}"
                ));
            }
        };
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);
        let resp = generated::AppStateResponse {
            key: "route.computeExternalCommitment".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&x)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `route.isExternalCommitmentVisible` — fetches the anchor at
    /// `sofi/extcommit/{X_b32}` on storage nodes.  Returns
    /// `AppStateResponse.value = "true"` if the anchor exists with a
    /// matching `x` field, `"false"` otherwise.
    ///
    /// Storage errors other than "not found" surface as router
    /// errors so the caller can distinguish transient failures from
    /// "X not visible" — same fail-closed semantics as the SDK.
    async fn route_is_external_commitment_visible(&self, q: AppQuery) -> AppResult {
        let bytes = match unwrap_argpack(&q.params) {
            Ok(b) => b,
            Err(e) => return err(format!("route.isExternalCommitmentVisible: {e}")),
        };
        if bytes.len() != 32 {
            return err(format!(
                "route.isExternalCommitmentVisible: x must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes);

        match crate::sdk::route_commit_sdk::is_external_commitment_visible(&x).await {
            Ok(visible) => {
                let resp = generated::AppStateResponse {
                    key: "route.isExternalCommitmentVisible".to_string(),
                    value: Some(if visible {
                        "true".into()
                    } else {
                        "false".into()
                    }),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }
            Err(e) => err(format!(
                "route.isExternalCommitmentVisible: storage error: {e}"
            )),
        }
    }

    /// `route.signRouteCommit` — sign a `RouteCommitV1` with the
    /// local wallet's SPHINCS+ key.  Per the "all business logic
    /// stays in Rust" rule, frontend traders never hold or invoke
    /// SPHINCS+ keys directly; they hand the unsigned proto to this
    /// route, which:
    ///   1. Decodes the input.
    ///   2. Stamps `initiator_public_key` with the wallet's current
    ///      SPHINCS+ public key (overwriting whatever the caller
    ///      passed — the wallet IS the trader).
    ///   3. Computes the canonical (signature-zeroed) bytes via the
    ///      same `canonicalise_for_commitment` helper that feeds the
    ///      external commitment X.  Single source of truth: a future
    ///      edit can't drift the sign-side and verify-side
    ///      canonicalisations apart.
    ///   4. Calls `crypto::sphincs::sign` with the wallet's secret
    ///      key.
    ///   5. Re-encodes with `initiator_signature` populated and
    ///      returns the bytes for the caller to publish.
    ///
    /// Returns the signed RouteCommit bytes Base32-encoded in
    /// `AppStateResponse.value`.
    async fn route_sign_route_commit(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("route.signRouteCommit: {e}")),
        };
        if bytes.is_empty() {
            return err("route.signRouteCommit: empty RouteCommitV1 payload".into());
        }
        let mut rc = match generated::RouteCommitV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "route.signRouteCommit: decode RouteCommitV1 failed: {e}"
                ));
            }
        };

        // Wallet pk + sk.  Both must be available — strict-fail
        // otherwise so callers get a precise error rather than a
        // signed-with-empty-key result that the eligibility gate
        // would later reject.
        let pk = match crate::sdk::signing_authority::current_public_key() {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                return err("route.signRouteCommit: wallet signing public key is empty".into());
            }
            Err(e) => {
                return err(format!(
                    "route.signRouteCommit: get_current_public_key failed: {e}"
                ));
            }
        };
        let sk = match crate::sdk::signing_authority::current_secret_key() {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                return err("route.signRouteCommit: wallet signing secret key is empty".into());
            }
            Err(e) => {
                return err(format!(
                    "route.signRouteCommit: get_current_secret_key failed: {e}"
                ));
            }
        };

        // The wallet is the trader: stamp our pk on the route.  Any
        // value the caller supplied is overwritten — sign-as-this-
        // device semantics keep the verifier's check meaningful
        // (anyone could otherwise claim to sign as anyone).
        rc.initiator_public_key = pk;

        // Same canonicalisation as `compute_external_commitment`.
        let canonical = crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc);
        let canonical_bytes = canonical.encode_to_vec();
        let sig = match dsm::crypto::sphincs::sign(
            dsm::crypto::sphincs::SphincsVariant::SPX256f,
            &sk,
            &canonical_bytes,
        ) {
            Ok(s) => s,
            Err(e) => {
                return err(format!("route.signRouteCommit: sphincs sign failed: {e}"));
            }
        };
        rc.initiator_signature = sig;

        let signed_bytes = rc.encode_to_vec();
        let resp = generated::AppStateResponse {
            key: "route.signRouteCommit".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&signed_bytes)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `route.publishExternalCommitment` — writes the anchor to
    /// storage nodes.  Body MUST decode as `ExternalCommitmentV1`;
    /// the handler enforces `len(x) == 32`.
    ///
    /// `publisher_public_key` is accept-or-stamp per the same rule
    /// chunk #6 / Track C.4 use elsewhere: empty → handler stamps
    /// the wallet's current SPHINCS+ pk; non-empty → honoured as-is.
    /// Frontend trader UI passes empty bytes; routing-service
    /// integrations pass their own pk.
    async fn route_publish_external_commitment(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("route.publishExternalCommitment: {e}")),
        };
        if bytes.is_empty() {
            return err(
                "route.publishExternalCommitment: empty ExternalCommitmentV1 payload".into(),
            );
        }

        // Phase 6: the request may be either a bare `ExternalCommitmentV1`
        // (legacy callers) or a `PublishExternalCommitmentRequest` wrapper
        // (Phase 6+ trader UI that wants vault-keyed pending pointers
        // published alongside the anchor).  Try the wrapper first; on
        // decode failure or missing inner anchor, fall back to bare.
        let (mut req, signed_rc_bytes_opt): (generated::ExternalCommitmentV1, Option<Vec<u8>>) =
            match generated::PublishExternalCommitmentRequest::decode(&*bytes) {
                Ok(wrapper) => {
                    if let Some(inner) = wrapper.anchor {
                        let rc_opt = if wrapper.signed_route_commit_bytes.is_empty() {
                            None
                        } else {
                            Some(wrapper.signed_route_commit_bytes)
                        };
                        (inner, rc_opt)
                    } else {
                        // Fall back to bare ExternalCommitmentV1.
                        let bare = match generated::ExternalCommitmentV1::decode(&*bytes) {
                            Ok(r) => r,
                            Err(e) => {
                                return err(format!(
                                "route.publishExternalCommitment: decode failed (tried PublishExternalCommitmentRequest then ExternalCommitmentV1): {e}"
                            ));
                            }
                        };
                        (bare, None)
                    }
                }
                Err(_) => {
                    // Fall back to bare ExternalCommitmentV1.
                    let bare = match generated::ExternalCommitmentV1::decode(&*bytes) {
                        Ok(r) => r,
                        Err(e) => {
                            return err(format!(
                            "route.publishExternalCommitment: decode failed (tried PublishExternalCommitmentRequest then ExternalCommitmentV1): {e}"
                        ));
                        }
                    };
                    (bare, None)
                }
            };

        if req.x.len() != 32 {
            return err(format!(
                "route.publishExternalCommitment: x must be 32 bytes, got {}",
                req.x.len()
            ));
        }
        // Accept-or-stamp: empty pk → wallet pk; non-empty → caller-supplied.
        if req.publisher_public_key.is_empty() {
            match crate::sdk::signing_authority::current_public_key() {
                Ok(pk) if !pk.is_empty() => req.publisher_public_key = pk,
                Ok(_) => {
                    return err(
                        "route.publishExternalCommitment: empty publisher_public_key \
                         requested wallet stamping but the wallet signing pk is empty"
                            .into(),
                    );
                }
                Err(e) => {
                    return err(format!(
                        "route.publishExternalCommitment: empty publisher_public_key \
                         requested wallet stamping but get_current_public_key failed: {e}"
                    ));
                }
            }
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&req.x);

        // If the caller supplied the signed RouteCommit bytes, use the
        // Phase-6 helper to publish X + vault-keyed pending pointers
        // atomically.  Otherwise publish X only (legacy behaviour).
        match signed_rc_bytes_opt {
            None => {
                if let Err(e) = crate::sdk::route_commit_sdk::publish_external_commitment(
                    &x,
                    &req.publisher_public_key,
                    &req.label,
                )
                .await
                {
                    return err(format!(
                        "route.publishExternalCommitment: storage put failed: {e}"
                    ));
                }
            }
            Some(rc_bytes) => {
                let rc = match generated::RouteCommitV1::decode(&*rc_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "route.publishExternalCommitment: decode signed_route_commit_bytes failed: {e}"
                        ));
                    }
                };
                // Verify X derived from this RC matches the caller's X.
                let derived_x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);
                if derived_x != x {
                    return err(
                        "route.publishExternalCommitment: signed_route_commit_bytes does not derive the supplied x"
                            .into(),
                    );
                }
                let sk = match crate::sdk::signing_authority::current_secret_key() {
                    Ok(s) if !s.is_empty() => s,
                    Ok(_) => {
                        return err(
                            "route.publishExternalCommitment: wallet signing secret key is empty"
                                .into(),
                        );
                    }
                    Err(e) => {
                        return err(format!(
                            "route.publishExternalCommitment: get_current_secret_key failed: {e}"
                        ));
                    }
                };
                match crate::sdk::route_commit_sdk::publish_route_anchor_with_pointers(
                    &x,
                    &rc,
                    &req.publisher_public_key,
                    &sk,
                    &req.label,
                )
                .await
                {
                    Ok(pointer_errors) => {
                        for pe in &pointer_errors {
                            log::warn!(
                                "[route.publishExternalCommitment] pointer publish (best-effort) failed: {pe}"
                            );
                        }
                    }
                    Err(e) => {
                        return err(format!(
                            "route.publishExternalCommitment: anchor publish failed: {e}"
                        ));
                    }
                }
            }
        }

        let resp = generated::AppStateResponse {
            key: "route.publishExternalCommitment".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&x)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    // ─────────────────────────────────────────────────────────────────
    // Track C.3 — frontend trade-flow handlers (chunks #1, #2, #3 over
    // the bridge).  Each delegates to the audited SDK helpers; the
    // handler is a typed-input adapter, not a re-implementation.
    // ─────────────────────────────────────────────────────────────────

    /// `route.publishRoutingAdvertisement` — publish a vault's routing
    /// advertisement + its full proto mirror to storage nodes.  The
    /// handler computes the BLAKE3 digest from `vault_proto_bytes`
    /// per the chunk #1 substrate; frontend only frames the typed
    /// inputs (token pair, reserves, fee, owner pk).
    async fn route_publish_routing_advertisement(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("route.publishRoutingAdvertisement: {e}")),
        };
        let mut req = match generated::PublishRoutingAdvertisementRequest::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "route.publishRoutingAdvertisement: decode failed: {e}"
                ));
            }
        };
        if req.vault_id.len() != 32 {
            return err("route.publishRoutingAdvertisement: vault_id must be 32 bytes".into());
        }
        // Reserves are NOT taken from the request — the fields are reserved in
        // the proto. An advertisement must describe funds the owner has
        // actually encumbered, so they are read from this device's reserve
        // leaves below. A caller that could state its own liquidity could
        // advertise a vault it never funded, which is precisely the condition
        // that made every published reserve meaningless.
        if req.token_a.len() != 32 || req.token_b.len() != 32 {
            return err(
                "route.publishRoutingAdvertisement: token_a/token_b must be 32-byte policy \
                 commits — a ticker is not an identity and cannot name a reserve leaf"
                    .into(),
            );
        }
        if req.unlock_spec_digest.len() != 32 {
            return err(
                "route.publishRoutingAdvertisement: unlock_spec_digest must be 32 bytes".into(),
            );
        }

        // ENCUMBRANCE FIRST. An advertisement must describe funds the owner has
        // actually locked into this vault, so that question is settled before
        // any proto derivation or storage work — both because it is the cheaper
        // check and because a vault holding nothing should be refused ON THAT
        // BASIS, not incidentally by whichever later gate happens to trip.
        //
        // Reserves are read from this device's own leaves; the request's reserve
        // fields are reserved in the proto so a caller cannot state its own
        // liquidity and advertise a vault it never funded.
        let mut pc_a = [0u8; 32];
        pc_a.copy_from_slice(&req.token_a);
        let mut pc_b = [0u8; 32];
        pc_b.copy_from_slice(&req.token_b);
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);
        let Some(head) = self.core_sdk.device_head() else {
            return err("route.publishRoutingAdvertisement: no device head".into());
        };
        let reserve_a = head.vault_reserve(&vault_id, &pc_a);
        let reserve_b = head.vault_reserve(&vault_id, &pc_b);
        // BOTH sides, not either. `&&` here accepted a vault with one funded leg
        // and one empty one — which happens exactly when the advertised pair
        // names a different asset than the one funded, e.g. an impostor sharing
        // a ticker with the real one. The half-funded advertisement would then
        // publish with a zero on that side and describe a market that cannot
        // trade.
        if reserve_a == 0 || reserve_b == 0 {
            return err(format!(
                "route.publishRoutingAdvertisement: this vault does not hold both advertised \
                 assets (a={reserve_a}, b={reserve_b}) — fund it, and check the pair names the \
                 assets actually encumbered"
            ));
        }
        // Derive vault_proto_bytes from the local DLVManager when the
        // caller passes empty.  This is the path the SoFi test +
        // production wallet UIs use: the wallet has the canonical
        // vault state via `dlv.create`; making the caller serialise
        // VaultPostProto bytes themselves is redundant + error-prone
        // (the test was passing a UTF-8 placeholder string which then
        // failed to decode as VaultPostProto at the trader's
        // `route.syncVaultsForPair` step, leaving the trader's
        // DLVManager empty and `dlv.unlockRouted` rejecting with
        // "vault not in local DLVManager").  When the caller does
        // pass non-empty bytes (router-service integrations), we
        // honour them verbatim.
        if req.vault_proto_bytes.is_empty() {
            let dlv_manager = self.bitcoin_tap.dlv_manager();
            let mut vid_arr = [0u8; 32];
            vid_arr.copy_from_slice(&req.vault_id);
            match dlv_manager
                .create_vault_post(&vid_arr, "route.publishRoutingAdvertisement", None)
                .await
            {
                Ok(bytes) => req.vault_proto_bytes = bytes,
                Err(e) => {
                    return err(format!(
                        "route.publishRoutingAdvertisement: vault_proto_bytes empty + local DLVManager create_vault_post failed: {e}"
                    ));
                }
            }
        }
        // Accept-or-stamp: empty owner pk → wallet pk; non-empty →
        // caller-supplied.  Same pattern as chunk #6 / Track C.4 /
        // route.publishExternalCommitment above.  Frontend AMM owner
        // UI passes empty bytes; routing-service integrations pass
        // their own pk.
        if req.owner_public_key.is_empty() {
            match crate::sdk::signing_authority::current_public_key() {
                Ok(pk) if !pk.is_empty() => req.owner_public_key = pk,
                Ok(_) => {
                    return err("route.publishRoutingAdvertisement: empty owner_public_key \
                         requested wallet stamping but the wallet signing pk is empty"
                        .into());
                }
                Err(e) => {
                    return err(format!(
                        "route.publishRoutingAdvertisement: empty owner_public_key \
                         requested wallet stamping but get_current_public_key failed: {e}"
                    ));
                }
            }
        }

        let mut unlock_digest = [0u8; 32];
        unlock_digest.copy_from_slice(&req.unlock_spec_digest);

        let publish_input = crate::sdk::routing_sdk::PublishRoutingAdInput {
            vault_id: &vault_id,
            token_a: &req.token_a,
            token_b: &req.token_b,
            reserve_a,
            reserve_b,
            fee_bps: req.fee_bps,
            unlock_spec_digest: unlock_digest,
            unlock_spec_key: req.unlock_spec_key,
            owner_public_key: &req.owner_public_key,
            vault_proto_bytes: &req.vault_proto_bytes,
        };
        if let Err(e) = crate::sdk::routing_sdk::publish_active_advertisement(publish_input).await {
            return err(format!(
                "route.publishRoutingAdvertisement: SDK publish failed: {e}"
            ));
        }

        let resp = generated::AppStateResponse {
            key: "route.publishRoutingAdvertisement".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `route.listAdvertisementsForPair` — enumerate active routing-
    /// vault advertisements for a token pair.  Returns
    /// `AppStateResponse.value` as a newline-separated list of Base32-
    /// encoded `RoutingVaultAdvertisementV1` protos.  The trader
    /// frontend decodes each line to display vault liquidity.
    async fn route_list_advertisements_for_pair(&self, q: AppQuery) -> AppResult {
        let bytes = match unwrap_argpack(&q.params) {
            Ok(b) => b,
            Err(e) => return err(format!("route.listAdvertisementsForPair: {e}")),
        };
        let req = match generated::RoutingPairRequest::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "route.listAdvertisementsForPair: decode failed: {e}"
                ));
            }
        };
        let ads = match crate::sdk::routing_sdk::load_active_advertisements_for_pair(
            &req.token_a,
            &req.token_b,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return err(format!(
                    "route.listAdvertisementsForPair: SDK load failed: {e}"
                ));
            }
        };
        let lines: Vec<String> = ads
            .iter()
            .map(|p| {
                crate::util::text_id::encode_base32_crockford(&p.advertisement.encode_to_vec())
            })
            .collect();
        let resp = generated::AppStateResponse {
            key: "route.listAdvertisementsForPair".to_string(),
            value: Some(lines.join("\n")),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `route.syncVaultsForPair` — fetch + verify + mirror every
    /// active routing-vault for a token pair into the local
    /// `DLVManager` so subsequent `dlv.unlockRouted` calls have the
    /// vault state to re-simulate against.  Mirrors the
    /// `posted_dlv.sync` flow but for routing-keyspace vaults.
    /// Returns newline-separated Base32 vault_ids that were freshly
    /// inserted on this call (already-mirrored vaults are skipped).
    async fn route_sync_vaults_for_pair(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("route.syncVaultsForPair: {e}")),
        };
        let req = match generated::RoutingPairRequest::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("route.syncVaultsForPair: decode failed: {e}")),
        };
        let ads = match crate::sdk::routing_sdk::load_active_advertisements_for_pair(
            &req.token_a,
            &req.token_b,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return err(format!("route.syncVaultsForPair: SDK load failed: {e}"));
            }
        };
        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let mut newly_mirrored: Vec<[u8; 32]> = Vec::new();
        for published in ads {
            let ad = &published.advertisement;
            if ad.vault_id.len() != 32 {
                continue;
            }
            let mut vid = [0u8; 32];
            vid.copy_from_slice(&ad.vault_id);
            // Already-mirrored vaults are skipped, and their reserves are NOT
            // refreshed from the advertisement.
            //
            // This block used to copy an ad's reserves into the local vault so
            // the owner could "observe" a trader's settle. That made a
            // discovery hint the authority for the owner's own liquidity —
            // anyone who could publish an ad could restate what the owner held.
            // The owner's reserves are its own encumbered leaves, advanced only
            // by reconciling settlements it has verified.
            if dlv_manager.get_vault(&vid).await.is_ok() {
                continue;
            }
            let proto_bytes = match crate::sdk::routing_sdk::fetch_and_verify_vault_proto(ad).await
            {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "[route.syncVaultsForPair] skipping {}: digest verify failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&vid)
                    );
                    continue;
                }
            };
            let post_proto = match generated::VaultPostProto::decode(proto_bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "[route.syncVaultsForPair] decode VaultPostProto for {} failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&vid)
                    );
                    continue;
                }
            };
            let post = match dsm::vault::limbo_vault::VaultPost::try_from(&post_proto) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "[route.syncVaultsForPair] VaultPost conversion for {} failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&vid)
                    );
                    continue;
                }
            };
            let vault = match dsm::vault::limbo_vault::LimboVault::from_vault_post(&post) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!(
                        "[route.syncVaultsForPair] from_vault_post for {} failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&vid)
                    );
                    continue;
                }
            };
            if let Err(e) = dlv_manager.add_vault(vault).await {
                log::warn!(
                    "[route.syncVaultsForPair] add_vault for {} failed: {e}",
                    crate::util::text_id::encode_base32_crockford(&vid)
                );
                continue;
            }
            newly_mirrored.push(vid);
        }
        let value = newly_mirrored
            .iter()
            .map(|id| crate::util::text_id::encode_base32_crockford(id))
            .collect::<Vec<_>>()
            .join("\n");
        let resp = generated::AppStateResponse {
            key: "route.syncVaultsForPair".to_string(),
            value: Some(value),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `route.findAndBindBestPath` — run chunk #2 path search over
    /// the locally-known advertisements (caller should
    /// `syncVaultsForPair` first to refresh) and bind the chosen Path
    /// into an UNSIGNED `RouteCommitV1` (chunk #3 binder).  Returns
    /// the unsigned proto Base32-encoded; caller follows up with
    /// `route.signRouteCommit` to stamp the wallet pk + signature.
    async fn route_find_and_bind_best_path(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("route.findAndBindBestPath: {e}")),
        };
        let req = match generated::FindAndBindRouteRequest::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("route.findAndBindBestPath: decode failed: {e}")),
        };
        if req.input_amount_u128.len() != 16 {
            return err(
                "route.findAndBindBestPath: input_amount_u128 must be 16 bytes (big-endian u128)"
                    .into(),
            );
        }
        if req.nonce.len() != 32 {
            return err("route.findAndBindBestPath: nonce must be 32 bytes".into());
        }
        let mut amount_buf = [0u8; 16];
        amount_buf.copy_from_slice(&req.input_amount_u128);
        // Narrow ONCE, here, checked. Base units are u64; a request naming more
        // than that is malformed, not something to truncate at the boundary
        // where the difference would be minted.
        let Ok(input_amount) = u64::try_from(u128::from_be_bytes(amount_buf)) else {
            return err("route.findAndBindBestPath: input_amount exceeds u64 base units".into());
        };
        let max_hops = if req.max_hops == 0 {
            crate::sdk::routing_path_sdk::DEFAULT_MAX_HOPS
        } else {
            req.max_hops as usize
        };
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&req.nonce);

        // Fetch + verify ads for the canonical pair.  We trust the
        // local set: the verified-search wrapper drops any tampered
        // ads on its way through `fetch_and_verify_vault_proto`.
        let ads = match crate::sdk::routing_sdk::load_active_advertisements_for_pair(
            &req.input_token,
            &req.output_token,
        )
        .await
        {
            Ok(v) => v.into_iter().map(|p| p.advertisement).collect::<Vec<_>>(),
            Err(e) => {
                return err(format!("route.findAndBindBestPath: load ads failed: {e}"));
            }
        };

        // Phase 6: vault-state composition pass.  For each candidate
        // advertisement, fetch the owner-signed VaultStateAnchorV1 and
        // fold any published VaultPendingPointerV1 records into a
        // composed (sequence, reserves) view.  The composed reserves
        // REPLACE the advertisement's owner-signed reserves so the
        // downstream path search quotes against the canonical current
        // state — including any pending trades published since the
        // owner's last anchor refresh.
        //
        // This is the SoFi spec §2.3 / §4.1 "math speaks for itself"
        // property: concurrent traders quoting against the same vault
        // while the owner is offline see each other's pending state
        // advances and serialize on top of them, rather than all
        // colliding against the stale anchor + having Tripwire prune
        // everyone but the first.
        let mut ads_after_composition: Vec<generated::RoutingVaultAdvertisementV1> =
            Vec::with_capacity(ads.len());
        // Tier-2 anchor-state bindings, keyed by vault_id, computed from
        // each vault's composed+synced current state.  Stamped onto the
        // unsigned RouteCommit hops after binding so the signature + X
        // cover them (see `stamp_anchor_bindings`).
        let mut hop_anchor_bindings: std::collections::HashMap<
            [u8; 32],
            crate::sdk::route_commit_sdk::HopAnchorBinding,
        > = std::collections::HashMap::new();
        for mut ad in ads.into_iter() {
            if ad.vault_id.len() != 32 {
                ads_after_composition.push(ad);
                continue;
            }
            let mut vid = [0u8; 32];
            vid.copy_from_slice(&ad.vault_id);
            // The advertisement's reserves are a HINT for logging only. They
            // used to seed composition, which meant a trader quoted against
            // numbers it read out of a published record — the same
            // advertisement-as-authority shape deleted from syncVaultsForPair.
            // `compose_vault_state` now takes them out of the owner's verified
            // reserve inclusion proof instead.
            let advertised_reserve_a = ad.reserve_a;
            let advertised_reserve_b = ad.reserve_b;

            // Fetch the latest vault state anchor.  If absent, the ad
            // pre-dates the anchor flow — fall through and use the ad
            // as-is (no composition possible without a signed baseline).
            let anchor = match crate::sdk::vault_state_anchor_codec::fetch_latest_signed_anchor(
                &vid,
            )
            .await
            {
                Ok(Some(a)) => a,
                _ => {
                    ads_after_composition.push(ad);
                    continue;
                }
            };
            match crate::sdk::vault_state_composition::compose_vault_state(
                &vid,
                &anchor,
                &ad.token_a,
                &ad.token_b,
                ad.fee_bps,
            )
            .await
            {
                Ok(composed) => {
                    if composed.pending_chain_len > 0 || composed.pending_chain_skipped > 0 {
                        log::info!(
                            "[route.findAndBindBestPath] vault {} composed: advertised=({},{}) proven+composed=({},{}) chain_len={} skipped={} seq={}",
                            crate::util::text_id::encode_base32_crockford(&vid),
                            advertised_reserve_a,
                            advertised_reserve_b,
                            composed.reserves_a,
                            composed.reserves_b,
                            composed.pending_chain_len,
                            composed.pending_chain_skipped,
                            composed.sequence,
                        );
                    }
                    // A validly-signed pointer sits on the exact sequence this
                    // composition ended on and nothing witnesses it, so some
                    // trade may already have consumed the state a quote would be
                    // built against. Drop the vault rather than quote it.
                    //
                    // This is not the safety gate — the first-writer claim
                    // refuses a contested slot before any advance, so a quote
                    // built here could not settle twice. It is refusing EARLY,
                    // so the trader does not sign a RouteCommit and publish X
                    // against a parent in flight only to be refused at the claim.
                    //
                    // Keyed on the narrow signal, never on `pending_chain_skipped`:
                    // that counter sums malformed, stale and depth-exceeded
                    // pointers too, and refusing on it would let one junk pointer
                    // un-quotable a vault forever.
                    if composed.blocked_by_unreceipted_pointer_at_parent {
                        log::info!(
                            "[route.findAndBindBestPath] vault {} dropped from candidates: an unreceipted pending trade holds seq={}",
                            crate::util::text_id::encode_base32_crockford(&vid),
                            composed.sequence,
                        );
                        continue;
                    }
                    if composed.pending_chain_len
                        >= crate::sdk::vault_state_composition::MAX_PENDING_CHAIN_DEPTH
                    {
                        log::warn!(
                            "[route.findAndBindBestPath] vault {} dropped from candidates: pending chain saturated",
                            crate::util::text_id::encode_base32_crockford(&vid),
                        );
                        continue;
                    }
                    // Replace the ad's reserves with the composed values
                    // so the downstream path search builds AMM edges
                    // against the canonical current state.
                    ad.reserve_a = composed.reserves_a;
                    ad.reserve_b = composed.reserves_b;
                    ad.updated_state_number = composed.sequence;
                    // Record this vault's anchor-state binding over the
                    // SAME composed values the vault-side unlock gate will
                    // re-derive from its local `current_sequence` +
                    // `current_reserves_digest`.  A vault that advances
                    // between quote and unlock will mismatch here → the
                    // Required-policy gate fails closed (stale-state
                    // rejection).  Uses the ad's canonical token_a/token_b
                    // ordering, matching the vault's fulfillment condition.
                    let reserves_digest = dsm::dlv::vault_state_anchor::compute_reserves_digest(
                        &ad.token_a,
                        &ad.token_b,
                        composed.reserves_a,
                        composed.reserves_b,
                        ad.fee_bps,
                    );
                    let anchor_digest = dsm::dlv::vault_state_anchor::compute_anchor_digest(
                        &vid,
                        composed.sequence,
                        &reserves_digest,
                    );
                    hop_anchor_bindings.insert(
                        vid,
                        crate::sdk::route_commit_sdk::HopAnchorBinding {
                            seq: composed.sequence,
                            reserves_digest: reserves_digest.to_vec(),
                            anchor_digest: anchor_digest.to_vec(),
                        },
                    );
                    ads_after_composition.push(ad);
                }
                Err(e) => {
                    log::warn!(
                        "[route.findAndBindBestPath] vault {} dropped from candidates: composition error {e}",
                        crate::util::text_id::encode_base32_crockford(&vid),
                    );
                    continue;
                }
            }
        }
        let ads = ads_after_composition;

        // Bind the single best path. A route is ONE path to ONE anchored
        // state producing ONE exact output under ONE signature — there is
        // no N-best enumeration and no pre-signed fallback. If the vault
        // moves between quote and unlock, the gate rejects and the caller
        // re-quotes + re-signs.
        let path = match crate::sdk::routing_path_sdk::find_and_verify_best_path(
            &ads,
            &req.input_token,
            &req.output_token,
            input_amount,
            max_hops,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                return err(format!(
                    "route.findAndBindBestPath: path search rejected: {e:?}"
                ));
            }
        };
        let mut unsigned = match crate::sdk::route_commit_sdk::bind_path_to_route_commit(
            crate::sdk::route_commit_sdk::BindRouteCommitInput {
                path: &path,
                nonce,
                initiator_public_key: &[],
                initiator_signature: vec![],
            },
        ) {
            Ok(rc) => rc,
            Err(e) => {
                return err(format!("route.findAndBindBestPath: bind rejected: {e:?}"));
            }
        };
        // Stamp the anchor-state binding onto every hop BEFORE the client
        // signs, so the SPHINCS+ signature and external commitment X cover
        // it and it cannot be tampered.
        crate::sdk::route_commit_sdk::stamp_anchor_bindings(&mut unsigned, &hop_anchor_bindings);
        let unsigned_bytes = unsigned.encode_to_vec();
        let resp = generated::AppStateResponse {
            key: "route.findAndBindBestPath".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(
                &unsigned_bytes,
            )),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}

#[cfg(test)]
mod stamping_tests {
    //! Accept-or-stamp and stamp-always, proven on the ARTIFACT.
    //!
    //! Replaces greps that matched a field assignment in this file's source.
    //! An assignment being present says nothing about whether the cryptographic
    //! operation consumed the assigned value — a handler that stamped the
    //! identity AFTER signing would produce output that looks correct in every
    //! field while its signature covers the unstamped form. Only recomputing
    //! the commitment from the returned artifact and verifying against the
    //! stamped key can tell those apart.
    //!
    //! TWO DISTINCT CONTRACTS live here, and conflating them would test the
    //! wrong thing:
    //!
    //! * `route.signRouteCommit` is STAMP-ALWAYS. A caller-supplied initiator
    //!   key is discarded, deliberately: signing as this device is the whole
    //!   point, and honouring a supplied key would let anyone claim to sign as
    //!   anyone.
    //! * the publish routes are ACCEPT-OR-STAMP. Empty means "stamp me";
    //!   non-empty is honoured verbatim, because routing-service integrations
    //!   publish under their own key. That is safe because an advertisement is
    //!   a discovery hint — authority comes from the reserve inclusion proof,
    //!   which is signed by the owner and bound to the owner's device root, so
    //!   a forged owner key on an ad grants nothing.
    //!
    //! Neither route REJECTS a conflicting identity, and testing for that would
    //! assert a contract this system does not have.

    use super::*;
    use serial_test::serial;

    use crate::bridge::AppRouter;
    use crate::init::SdkConfig;

    fn install_identity() -> Vec<u8> {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        crate::storage::client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_route_stamping",
        ));
        crate::reset_sdk_context_for_testing();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (device_id, genesis_hash, binding_key) =
            (vec![0x0Au8; 32], vec![0x0Bu8; 32], vec![0x0Cu8; 32]);
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("derive signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key.clone(),
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        let _ = crate::storage::client_db::init_database();
        public_key
    }

    fn router() -> AppRouterImpl {
        AppRouterImpl::new(SdkConfig {
            node_id: "route-stamping-test".to_string(),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn pack(body: Vec<u8>) -> Vec<u8> {
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    }

    fn rc_fixture() -> generated::RouteCommitV1 {
        generated::RouteCommitV1 {
            version: 1,
            nonce: vec![0x11; 32],
            total_fee_bps: 30,
            initiator_public_key: Vec::new(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vec![0x77; 32],
                token_in: vec![0x11; 32],
                token_out: vec![0x22; 32],
                input_amount_u128: 1_000u128.to_be_bytes().to_vec(),
                expected_output_amount_u128: 970u128.to_be_bytes().to_vec(),
                vault_state_anchor_seq: 0,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn sign_through_router(
        r: &AppRouterImpl,
        rc: &generated::RouteCommitV1,
    ) -> generated::RouteCommitV1 {
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.signRouteCommit".to_string(),
                args: pack(rc.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "sign failed: {:?}", res.error_message);
        // Envelope v3: a 1-byte framing prefix, then the message.
        let env = generated::Envelope::decode(&res.data[1..]).expect("decode envelope");
        let generated::envelope::Payload::AppStateResponse(resp) = env.payload.expect("payload")
        else {
            panic!("unexpected payload")
        };
        let bytes = crate::util::text_id::decode_base32_crockford(&resp.value.expect("value"))
            .expect("decode base32");
        generated::RouteCommitV1::decode(bytes.as_slice()).expect("decode rc")
    }

    /// THE ARTIFACT, not the presentation.
    ///
    /// An empty initiator key comes back stamped with the wallet's, and the
    /// returned SIGNATURE verifies against that stamped key over the returned
    /// message's own canonical bytes. Then the stamped key is altered and
    /// verification must break — which is what distinguishes "signed over the
    /// stamped identity" from "stamped after signing".
    #[test]
    #[serial]
    fn signing_stamps_the_wallet_identity_and_signs_over_it() {
        let wallet_pk = install_identity();
        let r = router();

        let signed = sign_through_router(&r, &rc_fixture());

        assert_eq!(
            signed.initiator_public_key, wallet_pk,
            "an empty initiator key must come back stamped with the wallet's"
        );
        assert!(!signed.initiator_signature.is_empty());

        // Recompute the canonical form FROM THE RETURNED ARTIFACT and verify
        // the returned signature against the stamped key.
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&signed).encode_to_vec();
        assert!(
            dsm::crypto::sphincs::sphincs_verify(
                &signed.initiator_public_key,
                &canonical,
                &signed.initiator_signature
            )
            .expect("verify"),
            "the signature must verify over the artifact that was returned"
        );

        // MUTATION SENSITIVITY. Had the handler stamped after signing, the
        // signature would cover the unstamped form and this alteration would
        // not be detectable.
        let mut tampered = signed.clone();
        tampered.initiator_public_key[0] ^= 0xff;
        let tampered_canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&tampered).encode_to_vec();
        assert!(
            !dsm::crypto::sphincs::sphincs_verify(
                &tampered.initiator_public_key,
                &tampered_canonical,
                &tampered.initiator_signature
            )
            .unwrap_or(false),
            "altering the stamped identity must break verification"
        );

        // And X derived from the returned artifact is the canonical one, so the
        // trade's name and its signature describe the same message.
        assert_eq!(
            crate::sdk::route_commit_sdk::compute_external_commitment(&signed),
            dsm::crypto::blake3::domain_hash_bytes(
                crate::sdk::route_commit_sdk::EXT_COMMIT_DOMAIN,
                &canonical
            ),
        );
    }

    /// CROSS-LAYER AGREEMENT: the advertisement that was stored and the address
    /// it was stored under must describe the same market.
    ///
    /// Each is verifiable in isolation — a well-formed advertisement, a
    /// well-formed key — while together they say different things. A trader
    /// discovering by prefix would fetch bytes describing a market it did not
    /// ask about, with every signature and digest intact.
    ///
    /// Also pins the publish contract, which is ACCEPT-OR-STAMP rather than the
    /// stamp-always rule signing uses: empty owner key is filled from the
    /// wallet, a supplied one is honoured verbatim.
    #[test]
    #[serial]
    fn a_published_advertisement_and_its_address_describe_the_same_market() {
        use prost::Message as _;

        let wallet_pk = install_identity();
        let r = router();

        // A genuinely funded vault: publication reads the reserve leaves, so an
        // unfunded head is refused before any stamping happens.
        let v = crate::sdk::funded_vault_fixture::funded_vault(10_000, 5_000, 30);
        r.core_sdk.set_device_head_for_testing(v.head.clone());

        let req = generated::PublishRoutingAdvertisementRequest {
            vault_id: v.vault_id.to_vec(),
            token_a: v.pc_a.to_vec(),
            token_b: v.pc_b.to_vec(),
            fee_bps: v.fee_bps,
            unlock_spec_digest: vec![0x5A; 32],
            unlock_spec_key: "sofi/spec/test".to_string(),
            owner_public_key: Vec::new(), // empty → stamp me
            vault_proto_bytes: b"vault-proto".to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.publishRoutingAdvertisement".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "publish failed: {:?}", res.error_message);

        // Fetch what was actually STORED, at the address the pair and vault
        // derive, and require the record to name that same pair and vault.
        let key = crate::sdk::routing_sdk::advertisement_key(&v.pc_a, &v.pc_b, &v.vault_id);
        let stored = crate::runtime::get_runtime()
            .block_on(crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&key))
            .expect("the advertisement must be readable at its derived address");
        let ad = generated::RoutingVaultAdvertisementV1::decode(stored.as_slice())
            .expect("stored bytes must decode as the advertisement");

        assert_eq!(ad.vault_id, v.vault_id.to_vec());
        assert_eq!(ad.token_a, v.pc_a.to_vec());
        assert_eq!(ad.token_b, v.pc_b.to_vec());
        assert_eq!(
            crate::sdk::routing_sdk::advertisement_key(&ad.token_a, &ad.token_b, &v.vault_id),
            key,
            "the address must be re-derivable from the record it stores"
        );

        // ACCEPT-OR-STAMP, the empty half: the wallet key was filled in.
        assert_eq!(
            ad.owner_public_key, wallet_pk,
            "an empty owner key must be stamped from the active wallet"
        );

        // Changing the market changes the address, so a record cannot be
        // discovered under a pair it does not name.
        let mut impostor = v.pc_b;
        impostor[0] ^= 0xff;
        assert_ne!(
            crate::sdk::routing_sdk::advertisement_key(&v.pc_a, &impostor, &v.vault_id),
            key,
        );
        assert_ne!(
            crate::sdk::routing_sdk::advertisement_key(&v.pc_a, &v.pc_b, &[0x99u8; 32]),
            key,
        );
    }

    /// THE HANDLER AND THE SDK AGREE, on write and on read.
    ///
    /// Replaces positive greps asserting that this file MENTIONS
    /// `routing_sdk::publish_active_advertisement` and
    /// `routing_sdk::load_active_advertisements_for_pair`. A call site existing
    /// says nothing about whether the handler's result matches the SDK's — a
    /// handler that called the SDK and then post-processed the result, or that
    /// wrote through the SDK but read through its own query, would satisfy both
    /// greps while producing two different answers.
    ///
    /// So: publish through the route, then read the same pair BOTH ways, and
    /// require the records to be identical.
    #[test]
    #[serial]
    fn the_route_and_the_sdk_return_the_same_advertisements() {
        use prost::Message as _;

        install_identity();
        let r = router();
        let v = crate::sdk::funded_vault_fixture::funded_vault(10_000, 5_000, 30);
        r.core_sdk.set_device_head_for_testing(v.head.clone());

        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: v.vault_id.to_vec(),
            token_a: v.pc_a.to_vec(),
            token_b: v.pc_b.to_vec(),
            fee_bps: v.fee_bps,
            unlock_spec_digest: vec![0x5A; 32],
            unlock_spec_key: "sofi/spec/test".to_string(),
            owner_public_key: Vec::new(),
            vault_proto_bytes: b"vault-proto".to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.publishRoutingAdvertisement".to_string(),
                args: pack(publish.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "publish failed: {:?}", res.error_message);

        // Read via the SDK the handler is supposed to delegate to.
        let via_sdk = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::routing_sdk::load_active_advertisements_for_pair(&v.pc_a, &v.pc_b),
            )
            .expect("sdk load");
        assert_eq!(
            via_sdk.len(),
            1,
            "the advertisement published through the route must be visible to the SDK"
        );

        // Read via the production query route.
        let pair = generated::RoutingPairRequest {
            token_a: v.pc_a.to_vec(),
            token_b: v.pc_b.to_vec(),
        };
        let q = crate::runtime::get_runtime().block_on(async {
            r.query(crate::bridge::AppQuery {
                path: "route.listAdvertisementsForPair".to_string(),
                params: pack(pair.encode_to_vec()),
            })
            .await
        });
        assert!(q.success, "list failed: {:?}", q.error_message);

        // The route's answer must carry the SAME advertisement the SDK returned
        // — same vault, same pair, same reserves, same fee. A route that
        // re-derived any of these would diverge here.
        let listed = q.data;
        let sdk_ad = &via_sdk[0].advertisement;
        let encoded = sdk_ad.encode_to_vec();
        let b32 = crate::util::text_id::encode_base32_crockford(&encoded);
        let body = String::from_utf8_lossy(&listed);
        assert!(
            body.contains(&b32),
            "the route's listing must contain exactly the advertisement the SDK \
             returns; a re-derived record would differ byte for byte"
        );

        // And the shared facts are the funded ones, so agreement is not two
        // copies of the same mistake.
        assert_eq!(sdk_ad.vault_id, v.vault_id.to_vec());
        assert_eq!(sdk_ad.token_a, v.pc_a.to_vec());
        assert_eq!(sdk_ad.token_b, v.pc_b.to_vec());
        assert_eq!(
            (sdk_ad.reserve_a, sdk_ad.reserve_b),
            (
                v.head.vault_reserve(&v.vault_id, &v.pc_a),
                v.head.vault_reserve(&v.vault_id, &v.pc_b)
            ),
        );
    }

    /// ACCEPT-OR-STAMP, the non-empty half: a supplied publisher key is
    /// honoured verbatim rather than overwritten.
    ///
    /// This is the opposite of the signing rule, and correct for a different
    /// reason: an advertisement is discovery metadata. Authority comes from the
    /// owner-signed reserve inclusion proof bound to the owner's device root, so
    /// publishing under an integration's own key grants no custody and no
    /// reserve authority.
    #[test]
    #[serial]
    fn a_supplied_publisher_identity_is_honoured_not_overwritten() {
        use prost::Message as _;

        let wallet_pk = install_identity();
        let r = router();
        let v = crate::sdk::funded_vault_fixture::funded_vault(10_000, 5_000, 30);
        r.core_sdk.set_device_head_for_testing(v.head.clone());

        let integration_pk = vec![0xC3u8; 64];
        assert_ne!(integration_pk, wallet_pk);

        let req = generated::PublishRoutingAdvertisementRequest {
            vault_id: v.vault_id.to_vec(),
            token_a: v.pc_a.to_vec(),
            token_b: v.pc_b.to_vec(),
            fee_bps: v.fee_bps,
            unlock_spec_digest: vec![0x5A; 32],
            unlock_spec_key: "sofi/spec/test".to_string(),
            owner_public_key: integration_pk.clone(),
            vault_proto_bytes: b"vault-proto".to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.publishRoutingAdvertisement".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "publish failed: {:?}", res.error_message);

        let key = crate::sdk::routing_sdk::advertisement_key(&v.pc_a, &v.pc_b, &v.vault_id);
        let stored = crate::runtime::get_runtime()
            .block_on(crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&key))
            .expect("stored");
        let ad = generated::RoutingVaultAdvertisementV1::decode(stored.as_slice()).expect("decode");

        assert_eq!(
            ad.owner_public_key, integration_pk,
            "a supplied publisher key must be preserved, not replaced by the wallet's"
        );
    }

    /// STAMP-ALWAYS: a caller-supplied initiator key is discarded, not honoured
    /// and not rejected.
    ///
    /// Honouring it would let a caller obtain a signature attributed to someone
    /// else's key; the signature would then fail verification against that key,
    /// but only after a verifier had been handed a plausible-looking artifact.
    /// Overwriting keeps "the initiator key is who signed" true by construction.
    #[test]
    #[serial]
    fn signing_discards_a_caller_supplied_identity() {
        let wallet_pk = install_identity();
        let r = router();

        let mut impostor = rc_fixture();
        impostor.initiator_public_key = vec![0xEEu8; 64];
        let signed = sign_through_router(&r, &impostor);

        assert_eq!(
            signed.initiator_public_key, wallet_pk,
            "a supplied initiator key must be overwritten by the signer's own"
        );
        assert_ne!(signed.initiator_public_key, vec![0xEEu8; 64]);

        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&signed).encode_to_vec();
        assert!(
            dsm::crypto::sphincs::sphincs_verify(
                &signed.initiator_public_key,
                &canonical,
                &signed.initiator_signature
            )
            .expect("verify"),
            "and the signature covers the identity that replaced it"
        );
    }
}
