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
//!     storage-node anchor at `defi/extcommit/{X_b32}`.
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
            "route.computeExternalCommitment" => {
                self.route_compute_external_commitment(q).await
            }
            "route.isExternalCommitmentVisible" => {
                self.route_is_external_commitment_visible(q).await
            }
            other => err(format!("unknown route query path: {other}")),
        }
    }

    /// Invoke dispatch for `route.*` mutating paths.
    pub(crate) async fn handle_route_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "route.publishExternalCommitment" => {
                self.route_publish_external_commitment(i).await
            }
            "route.signRouteCommit" => self.route_sign_route_commit(i).await,
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
            return err(
                "route.computeExternalCommitment: empty RouteCommitV1 payload".into(),
            );
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
    /// `defi/extcommit/{X_b32}` on storage nodes.  Returns
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
                    value: Some(if visible { "true".into() } else { "false".into() }),
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
                return err(
                    "route.signRouteCommit: wallet signing public key is empty".into(),
                );
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
                return err(
                    "route.signRouteCommit: wallet signing secret key is empty".into(),
                );
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
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc);
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
    /// the handler enforces `len(x) == 32` and a non-empty publisher
    /// public key before the put.
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
        let req = match generated::ExternalCommitmentV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "route.publishExternalCommitment: decode ExternalCommitmentV1 failed: {e}"
                ));
            }
        };
        if req.x.len() != 32 {
            return err(format!(
                "route.publishExternalCommitment: x must be 32 bytes, got {}",
                req.x.len()
            ));
        }
        if req.publisher_public_key.is_empty() {
            return err(
                "route.publishExternalCommitment: publisher_public_key is required".into(),
            );
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&req.x);

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

        let resp = generated::AppStateResponse {
            key: "route.publishExternalCommitment".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&x)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}
