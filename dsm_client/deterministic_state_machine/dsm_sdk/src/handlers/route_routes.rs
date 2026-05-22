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
        if req.reserve_a_u128.len() != 16 || req.reserve_b_u128.len() != 16 {
            return err(
                "route.publishRoutingAdvertisement: reserves must be 16-byte big-endian u128"
                    .into(),
            );
        }
        if req.unlock_spec_digest.len() != 32 {
            return err(
                "route.publishRoutingAdvertisement: unlock_spec_digest must be 32 bytes".into(),
            );
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

        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);
        let mut reserve_a = [0u8; 16];
        reserve_a.copy_from_slice(&req.reserve_a_u128);
        let mut reserve_b = [0u8; 16];
        reserve_b.copy_from_slice(&req.reserve_b_u128);
        let mut unlock_digest = [0u8; 32];
        unlock_digest.copy_from_slice(&req.unlock_spec_digest);

        let publish_input = crate::sdk::routing_sdk::PublishRoutingAdInput {
            vault_id: &vault_id,
            token_a: &req.token_a,
            token_b: &req.token_b,
            reserve_a_u128: reserve_a,
            reserve_b_u128: reserve_b,
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
        let input_amount = u128::from_be_bytes(amount_buf);
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
        for mut ad in ads.into_iter() {
            if ad.vault_id.len() != 32
                || ad.reserve_a_u128.len() != 16
                || ad.reserve_b_u128.len() != 16
            {
                ads_after_composition.push(ad);
                continue;
            }
            let mut vid = [0u8; 32];
            vid.copy_from_slice(&ad.vault_id);
            let mut a_buf = [0u8; 16];
            a_buf.copy_from_slice(&ad.reserve_a_u128);
            let mut b_buf = [0u8; 16];
            b_buf.copy_from_slice(&ad.reserve_b_u128);
            let baseline_reserve_a = u128::from_be_bytes(a_buf);
            let baseline_reserve_b = u128::from_be_bytes(b_buf);

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
                (baseline_reserve_a, baseline_reserve_b),
                &ad.token_a,
                &ad.token_b,
                ad.fee_bps,
            )
            .await
            {
                Ok(composed) => {
                    if composed.pending_chain_len > 0 || composed.pending_chain_skipped > 0 {
                        log::info!(
                            "[route.findAndBindBestPath] vault {} composed: baseline=({},{}) composed=({},{}) chain_len={} skipped={} seq={}",
                            crate::util::text_id::encode_base32_crockford(&vid),
                            baseline_reserve_a,
                            baseline_reserve_b,
                            composed.reserves_a,
                            composed.reserves_b,
                            composed.pending_chain_len,
                            composed.pending_chain_skipped,
                            composed.sequence,
                        );
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
                    ad.reserve_a_u128 = composed.reserves_a.to_be_bytes().to_vec();
                    ad.reserve_b_u128 = composed.reserves_b.to_be_bytes().to_vec();
                    ad.updated_state_number = composed.sequence;
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

        // Tier 2 envelope: when caller asks for N-best (max_paths > 1),
        // run the verified N-best enumerator and bind primary +
        // fallbacks under one envelope. Legacy single-path callers
        // (max_paths == 0 or 1) keep the chunk #3 single-path binder
        // path so the wire format remains identical for them.
        let requested_paths = if req.max_paths == 0 {
            1
        } else {
            req.max_paths as usize
        };
        let slippage_bps = req.slippage_bps;
        let floor_bps = req.floor_bps;

        let unsigned = if requested_paths <= 1 {
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
            match crate::sdk::route_commit_sdk::bind_path_to_route_commit(
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
            }
        } else {
            let paths = match crate::sdk::routing_path_sdk::find_and_verify_n_best_paths(
                &ads,
                &req.input_token,
                &req.output_token,
                input_amount,
                max_hops,
                requested_paths,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    return err(format!(
                        "route.findAndBindBestPath: N-best path search rejected: {e:?}"
                    ));
                }
            };
            // Guaranteed non-empty by the SDK contract; first is primary,
            // rest are fallbacks.  Split safely without panic.
            let (primary, fallbacks) = match paths.split_first() {
                Some((p, rest)) => (p.clone(), rest.to_vec()),
                None => {
                    return err(
                        "route.findAndBindBestPath: N-best search returned empty set".into(),
                    );
                }
            };
            match crate::sdk::route_commit_sdk::bind_envelope_to_route_commit(
                crate::sdk::route_commit_sdk::BindRouteCommitEnvelopeInput {
                    primary: &primary,
                    fallbacks: &fallbacks,
                    nonce,
                    initiator_public_key: &[],
                    initiator_signature: vec![],
                    slippage_bps,
                    floor_bps,
                },
            ) {
                Ok(rc) => rc,
                Err(e) => {
                    return err(format!(
                        "route.findAndBindBestPath: envelope bind rejected: {e:?}"
                    ));
                }
            }
        };
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
