// SPDX-License-Identifier: MIT OR Apache-2.0
//! DeTFi route-commit binder + external-commitment storage anchor.
//!
//! Chunk #3 of the DeTFi routing pipeline.  Consumes a chosen `Path`
//! from chunk #2's path search and produces:
//!   * a typed `RouteCommitV1` proto binding every hop's vault id,
//!     advertisement digest, state number, and expected per-hop
//!     amounts;
//!   * the deterministic external commitment `X = BLAKE3("DSM/ext\0" ||
//!     canonical(RouteCommit{signature=[]}))` referenced by every
//!     vault on the route;
//!   * a storage-node anchor at `defi/extcommit/{X_b32}` carrying a
//!     minimal `ExternalCommitmentV1` proof-of-existence record.
//!
//! When the anchor is published, every vault on the route may
//! atomically unlock — the visibility of `X` is the trigger (DeTFi
//! spec §3.2, §5.1).
//!
//! This module deliberately STOPS at the anchor.  Per-hop unlock
//! handler wiring (extending the on-chain unlock op to verify a
//! RouteCommit + check the anchor exists) is the next chunk on this
//! track.  A regression guard freezes that boundary.

use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::routing_path_sdk::Path;
use crate::util::text_id::encode_base32_crockford;

/// BLAKE3 domain tag for the external commitment derivation
/// `X = BLAKE3("DSM/ext\0" || canonical(RouteCommit))`.
/// Matches DeTFi spec §3.2 `ExtCommit(X) = H("DSM/ext" || X)`.
pub(crate) const EXT_COMMIT_DOMAIN: &str = "DSM/ext";

/// Storage-node prefix for external-commitment anchors.  Each anchor
/// is stored at `defi/extcommit/{X_b32}` — the suffix doubles as the
/// existence-proof identifier.
pub(crate) const EXT_COMMIT_ROOT: &str = "defi/extcommit/";

/// Anchor key for a given `X`.
pub(crate) fn external_commitment_key(x: &[u8; 32]) -> String {
    format!("{}{}", EXT_COMMIT_ROOT, encode_base32_crockford(x))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteCommitError {
    EmptyPath,
    InvalidNonce,
    OutputAmountOverflow,
    InputAmountOverflow,
    HopAmountOverflow,
    HopVaultIdInvalid,
    HopAdvertisementDigestInvalid,
    HopUnlockSpecDigestInvalid,
}

/// Inputs for `bind_path_to_route_commit`.  Kept narrow so the binder
/// stays a pure proto constructor — the trader's signing happens in a
/// later step (signature is supplied by caller; empty is allowed for
/// test / pre-sign scenarios).
pub(crate) struct BindRouteCommitInput<'a> {
    pub path: &'a Path,
    pub nonce: [u8; 32],
    pub initiator_public_key: &'a [u8],
    /// Trader's SPHINCS+ signature over the canonical RouteCommit bytes
    /// with `initiator_signature` zeroed.  Empty allowed at build time;
    /// the verifier in chunk #4 will reject empty signatures on the
    /// settlement path.
    pub initiator_signature: Vec<u8>,
}

fn u128_to_be_bytes(n: u128) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

/// Bind a discovered `Path` into a `RouteCommitV1` proto.  Pure proto
/// construction — no I/O, no signing, no commitment hashing yet.
pub(crate) fn bind_path_to_route_commit(
    input: BindRouteCommitInput<'_>,
) -> Result<generated::RouteCommitV1, RouteCommitError> {
    if input.path.hops.is_empty() {
        return Err(RouteCommitError::EmptyPath);
    }
    // Reject the all-zero nonce — collides with default proto bytes
    // on uninitialised callers.  Replay protection only works when
    // each route picks a fresh random nonce.
    if input.nonce == [0u8; 32] {
        return Err(RouteCommitError::InvalidNonce);
    }

    let mut hops_proto: Vec<generated::RouteCommitHopV1> = Vec::with_capacity(input.path.hops.len());
    for hop in &input.path.hops {
        hops_proto.push(generated::RouteCommitHopV1 {
            vault_id: hop.vault_id.to_vec(),
            token_in: hop.token_in.clone(),
            token_out: hop.token_out.clone(),
            input_amount_u128: u128_to_be_bytes(hop.input_amount),
            expected_output_amount_u128: u128_to_be_bytes(hop.expected_output_amount),
            fee_bps: hop.fee_bps,
            advertisement_digest: hop.advertisement_digest.to_vec(),
            state_number: hop.state_number,
            unlock_spec_digest: hop.unlock_spec_digest.to_vec(),
            owner_public_key: hop.owner_public_key.clone(),
        });
    }

    Ok(generated::RouteCommitV1 {
        version: 1,
        nonce: input.nonce.to_vec(),
        input_token: input.path.input_token.clone(),
        output_token: input.path.output_token.clone(),
        input_amount_u128: u128_to_be_bytes(input.path.input_amount),
        expected_final_output_amount_u128: u128_to_be_bytes(input.path.final_output_amount),
        total_fee_bps: input.path.total_fee_bps,
        hops: hops_proto,
        initiator_public_key: input.initiator_public_key.to_vec(),
        initiator_signature: input.initiator_signature,
    })
}

/// Return a copy of the RouteCommit with `initiator_signature` cleared.
/// This is the canonical form both the SPHINCS+ signer and the
/// `compute_external_commitment` hash function consume — sign-and-
/// commit over the same bytes so the signature itself is not part of
/// the commitment input (matches `Operation::with_cleared_signature`
/// pattern in dsm/src/types/operations.rs).
pub(crate) fn canonicalise_for_commitment(
    rc: &generated::RouteCommitV1,
) -> generated::RouteCommitV1 {
    let mut out = rc.clone();
    out.initiator_signature.clear();
    out
}

/// Compute `X = BLAKE3("DSM/ext\0" || canonical_bytes)` over the
/// signature-zeroed RouteCommit.  Deterministic across encoders —
/// prost emits canonical wire bytes for a given proto message.
pub(crate) fn compute_external_commitment(
    rc: &generated::RouteCommitV1,
) -> [u8; 32] {
    let canonical = canonicalise_for_commitment(rc);
    let canonical_bytes = canonical.encode_to_vec();
    dsm::crypto::blake3::domain_hash_bytes(EXT_COMMIT_DOMAIN, &canonical_bytes)
}

/// Publish the external-commitment anchor to storage nodes.  The
/// record exists purely to make `X` visible to every vault owner on
/// the route — its mere presence at the keyspace prefix is the
/// "atomic visibility" trigger (DeTFi spec §3.2).
pub(crate) async fn publish_external_commitment(
    x: &[u8; 32],
    publisher_public_key: &[u8],
    label: &str,
) -> Result<(), dsm::types::error::DsmError> {
    let anchor = generated::ExternalCommitmentV1 {
        version: 1,
        x: x.to_vec(),
        publisher_public_key: publisher_public_key.to_vec(),
        label: label.to_string(),
    };
    let key = external_commitment_key(x);
    BitcoinTapSdk::storage_put_bytes(&key, &anchor.encode_to_vec()).await?;
    Ok(())
}

/// Fetch the external-commitment anchor for a given `X`.  Returns `Ok`
/// with the decoded anchor on success, `Err` if the anchor is absent
/// or malformed — vault-owner verifiers treat any error as
/// "commitment not visible".
pub(crate) async fn fetch_external_commitment(
    x: &[u8; 32],
) -> Result<generated::ExternalCommitmentV1, dsm::types::error::DsmError> {
    let key = external_commitment_key(x);
    let bytes = BitcoinTapSdk::storage_get_bytes(&key).await?;
    let anchor = generated::ExternalCommitmentV1::decode(bytes.as_slice()).map_err(|e| {
        dsm::types::error::DsmError::serialization_error(
            "ExternalCommitmentV1",
            "decode",
            Some(key.clone()),
            Some(e),
        )
    })?;
    if anchor.x.as_slice() != x.as_slice() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "ExternalCommitmentV1.x does not match anchor key",
        ));
    }
    Ok(anchor)
}

/// Return `Ok(true)` if the external-commitment anchor for `X` is
/// currently visible at storage nodes, `Ok(false)` if absent.  Errors
/// other than "not found" propagate so the caller can distinguish
/// transient storage failures from "commitment not visible".
pub(crate) async fn is_external_commitment_visible(
    x: &[u8; 32],
) -> Result<bool, dsm::types::error::DsmError> {
    match fetch_external_commitment(x).await {
        Ok(_) => Ok(true),
        Err(e) => {
            // The dBTC + posted-DLV mock encodes "not found" as a
            // storage error containing "object not found".  In
            // production this maps to HTTP 404 from the storage node.
            // Treat both as "not visible"; surface anything else.
            let msg = format!("{e}");
            if msg.contains("not found") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Locate a hop in the RouteCommit by `vault_id`.  Vault owners use
/// this at unlock time: given the RouteCommit the trader handed them,
/// find their own hop and verify the bound amounts / digests against
/// their live advertisement before honouring the unlock.
pub(crate) fn find_hop<'a>(
    rc: &'a generated::RouteCommitV1,
    vault_id: &[u8; 32],
) -> Option<&'a generated::RouteCommitHopV1> {
    rc.hops
        .iter()
        .find(|h| h.vault_id.as_slice() == vault_id.as_slice())
}

/// Typed failure of the routed-unlock eligibility check.  Each
/// variant maps to a distinct rejection reason so the handler can
/// surface a precise error to the caller (and the regression guards
/// can prove no panic path exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteCommitVerifyError {
    /// `route_commit_bytes` failed prost decode.
    InvalidRouteCommitEncoding,
    /// `initiator_public_key` is empty on the wire.  Without a public
    /// key the `initiator_signature` cannot be verified, and the
    /// eligibility gate fails closed.
    MissingInitiatorPublicKey,
    /// `initiator_signature` is empty OR fails SPHINCS+ verification
    /// against the canonical (signature-zeroed) RouteCommit bytes
    /// under `initiator_public_key`.  Without a valid signature an
    /// attacker could forge arbitrary RouteCommits, publish their own
    /// anchor at the resulting `X`, and trick vault owners into
    /// unlocking against unauthorised routes — chunk #5 closes this.
    InvalidInitiatorSignature,
    /// `vault_id` is not in any hop of the RouteCommit.  Either the
    /// trader handed this RouteCommit to the wrong vault owner or the
    /// route was constructed without this vault.
    VaultNotInRoute,
    /// `is_external_commitment_visible(X)` returned `Ok(false)`.  The
    /// trader has not (yet) published the anchor — vault owner
    /// rejects the unlock and waits.
    ExternalCommitmentNotVisible,
    /// Storage-side error fetching the anchor.  The vault owner
    /// cannot conclude either way, so MUST reject the unlock — better
    /// to fail closed than risk unlocking against a forged
    /// "visible" claim.
    AnchorFetchFailed(String),
    /// SPHINCS+ verifier returned a hard error (key/sig length
    /// mismatch, etc.).  Surfaced separately from
    /// `InvalidInitiatorSignature` so callers can distinguish a
    /// malformed input from a forged route.
    SignatureVerifierError(String),
}

/// Routed-unlock eligibility check.  Vault-owner devices run this
/// before honouring any `dlv.unlockRouted` request.  The five-step
/// gate (chunk #4 added the first four; chunk #5 added the SPHINCS+
/// signature verification at step 2):
///   1. Decode RouteCommitV1 from the bytes the trader supplied.
///   2. Verify the SPHINCS+ `initiator_signature` against the
///      canonical (signature-zeroed) RouteCommit bytes under
///      `initiator_public_key`.  Without this step an attacker
///      could forge a RouteCommit, publish their own X anchor, and
///      trick vault owners into unlocking against unauthorised
///      routes — chunk #5 closes that.
///   3. Locate the hop matching this vault — must exist (else the
///      RouteCommit was meant for a different vault).
///   4. Compute X from the canonical (signature-zeroed) RouteCommit
///      bytes.
///   5. Confirm the `ExternalCommitmentV1` anchor for X is visible at
///      `defi/extcommit/{X_b32}` on storage nodes — else the trader
///      has not yet published the atomic-visibility trigger.
///
/// On success, returns the bound hop so the handler has the
/// expected_input / expected_output / fee_bps the trader committed
/// to — useful for amount checks the handler may want to enforce.
pub(crate) async fn verify_route_commit_unlock_eligibility(
    route_commit_bytes: &[u8],
    vault_id: &[u8; 32],
) -> Result<generated::RouteCommitHopV1, RouteCommitVerifyError> {
    let rc = generated::RouteCommitV1::decode(route_commit_bytes)
        .map_err(|_| RouteCommitVerifyError::InvalidRouteCommitEncoding)?;

    // SPHINCS+ verification (chunk #5).  Run BEFORE every other
    // expensive check so a forged route fails fast.
    if rc.initiator_public_key.is_empty() {
        return Err(RouteCommitVerifyError::MissingInitiatorPublicKey);
    }
    if rc.initiator_signature.is_empty() {
        return Err(RouteCommitVerifyError::InvalidInitiatorSignature);
    }
    let canonical = canonicalise_for_commitment(&rc);
    let canonical_bytes = canonical.encode_to_vec();
    match dsm::crypto::sphincs::sphincs_verify(
        &rc.initiator_public_key,
        &canonical_bytes,
        &rc.initiator_signature,
    ) {
        Ok(true) => {} // good
        Ok(false) => return Err(RouteCommitVerifyError::InvalidInitiatorSignature),
        Err(e) => {
            return Err(RouteCommitVerifyError::SignatureVerifierError(format!("{e}")));
        }
    }

    let hop = match find_hop(&rc, vault_id) {
        Some(h) => h.clone(),
        None => return Err(RouteCommitVerifyError::VaultNotInRoute),
    };
    let x = compute_external_commitment(&rc);
    match is_external_commitment_visible(&x).await {
        Ok(true) => Ok(hop),
        Ok(false) => Err(RouteCommitVerifyError::ExternalCommitmentNotVisible),
        Err(e) => Err(RouteCommitVerifyError::AnchorFetchFailed(format!("{e}"))),
    }
}

#[cfg(test)]
mod tests {
    //! Chunk #3 tests.
    //!
    //! Cover the full bind → compute X → publish → fetch → verify
    //! cycle plus the determinism + signature-exclusion guarantees
    //! that make X safe to use as an atomic-visibility trigger.

    use super::*;
    use crate::sdk::routing_path_sdk::{Path, VaultHop};

    fn vid(tag: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = tag;
        v[31] = tag.wrapping_mul(7).wrapping_add(11);
        v
    }

    fn nonce(tag: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0xC0;
        v[1] = tag;
        v[31] = 0x42;
        v
    }

    fn token(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn make_hop(tag: u8, token_in: &[u8], token_out: &[u8]) -> VaultHop {
        VaultHop {
            vault_id: vid(tag),
            token_in: token_in.to_vec(),
            token_out: token_out.to_vec(),
            input_amount: 10_000,
            expected_output_amount: 9_870,
            fee_bps: 30,
            advertisement_digest: [tag; 32],
            state_number: u64::from(tag),
            unlock_spec_digest: [tag.wrapping_add(1); 32],
            owner_public_key: vec![0xABu8; 64],
        }
    }

    fn sample_path() -> Path {
        let a = token("AAA");
        let b = token("BBB");
        let c = token("CCC");
        Path {
            input_token: a.clone(),
            output_token: c.clone(),
            input_amount: 10_000,
            final_output_amount: 9_700,
            total_fee_bps: 60,
            hops: vec![make_hop(1, &a, &b), make_hop(2, &b, &c)],
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Binder
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn bind_path_carries_every_hop_field() {
        let path = sample_path();
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(1),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .expect("bind");
        assert_eq!(rc.version, 1);
        assert_eq!(rc.nonce, nonce(1).to_vec());
        assert_eq!(rc.input_token, path.input_token);
        assert_eq!(rc.output_token, path.output_token);
        assert_eq!(rc.hops.len(), path.hops.len());
        for (proto_hop, path_hop) in rc.hops.iter().zip(path.hops.iter()) {
            assert_eq!(proto_hop.vault_id, path_hop.vault_id.to_vec());
            assert_eq!(proto_hop.token_in, path_hop.token_in);
            assert_eq!(proto_hop.token_out, path_hop.token_out);
            assert_eq!(proto_hop.fee_bps, path_hop.fee_bps);
            assert_eq!(proto_hop.state_number, path_hop.state_number);
            assert_eq!(
                proto_hop.advertisement_digest,
                path_hop.advertisement_digest.to_vec()
            );
        }
    }

    #[test]
    fn bind_rejects_empty_path() {
        let path = Path {
            input_token: token("A"),
            output_token: token("B"),
            input_amount: 100,
            final_output_amount: 99,
            total_fee_bps: 0,
            hops: vec![],
        };
        match bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(1),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        }) {
            Err(RouteCommitError::EmptyPath) => {}
            other => panic!("expected EmptyPath, got {other:?}"),
        }
    }

    #[test]
    fn bind_rejects_zero_nonce() {
        let path = sample_path();
        match bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: [0u8; 32],
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        }) {
            Err(RouteCommitError::InvalidNonce) => {}
            other => panic!("expected InvalidNonce, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // External commitment determinism + signature exclusion
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn x_is_deterministic_across_repeated_runs() {
        let path = sample_path();
        let rc_1 = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(2),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let rc_2 = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(2),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        assert_eq!(
            compute_external_commitment(&rc_1),
            compute_external_commitment(&rc_2),
            "X must be deterministic for identical inputs"
        );
    }

    #[test]
    fn x_changes_with_nonce() {
        let path = sample_path();
        let rc_a = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(3),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let rc_b = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(4),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        assert_ne!(
            compute_external_commitment(&rc_a),
            compute_external_commitment(&rc_b),
            "X MUST change when nonce changes (replay protection)"
        );
    }

    #[test]
    fn x_excludes_initiator_signature() {
        // Two RouteCommits identical except for `initiator_signature`
        // MUST produce the same X — otherwise the signer can't sign
        // X-bytes (chicken-and-egg).
        let path = sample_path();
        let mut rc_unsigned = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(5),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let x_unsigned = compute_external_commitment(&rc_unsigned);

        // Pretend the trader has now signed.
        rc_unsigned.initiator_signature = vec![0xDD; 64];
        let x_signed = compute_external_commitment(&rc_unsigned);
        assert_eq!(
            x_unsigned, x_signed,
            "X must be invariant under initiator_signature changes"
        );
    }

    #[test]
    fn x_changes_with_any_hop_field() {
        let path = sample_path();
        let baseline = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(6),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let baseline_x = compute_external_commitment(&baseline);

        // Mutating any hop field must produce a different X.
        let mut tampered = baseline.clone();
        tampered.hops[0].fee_bps += 1;
        assert_ne!(compute_external_commitment(&tampered), baseline_x);

        let mut tampered2 = baseline.clone();
        tampered2.hops[0].state_number += 1;
        assert_ne!(compute_external_commitment(&tampered2), baseline_x);

        let mut tampered3 = baseline.clone();
        tampered3.hops[1].advertisement_digest[0] ^= 0xFF;
        assert_ne!(compute_external_commitment(&tampered3), baseline_x);
    }

    // ─────────────────────────────────────────────────────────────────
    // Storage anchor
    // ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn anchor_round_trip_publish_then_fetch() {
        let path = sample_path();
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x10),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let x = compute_external_commitment(&rc);

        publish_external_commitment(&x, &[0x11u8; 64], "test-route")
            .await
            .expect("publish");
        let anchor = fetch_external_commitment(&x).await.expect("fetch");
        assert_eq!(anchor.x, x.to_vec());
        assert_eq!(anchor.label, "test-route");
        assert!(
            is_external_commitment_visible(&x).await.unwrap(),
            "anchor must be visible after publish"
        );
    }

    #[tokio::test]
    async fn unpublished_x_reports_not_visible() {
        // Build a fresh RouteCommit + X but DON'T publish.
        let path = sample_path();
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x11),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let x = compute_external_commitment(&rc);

        let visible = is_external_commitment_visible(&x).await;
        match visible {
            Ok(false) => {} // correct
            other => panic!(
                "unpublished X must report Ok(false), got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn anchor_key_collision_is_rejected_on_fetch() {
        // Manually plant an anchor whose `x` field disagrees with its
        // key.  The fetch helper must reject this — otherwise a
        // malicious storage node could swap two routes' anchors.
        let path = sample_path();
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x12),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let x = compute_external_commitment(&rc);
        let key = external_commitment_key(&x);

        let bogus = generated::ExternalCommitmentV1 {
            version: 1,
            x: vec![0xFF; 32], // intentionally wrong
            publisher_public_key: vec![0x11; 64],
            label: "bogus".into(),
        };
        BitcoinTapSdk::storage_put_bytes(&key, &bogus.encode_to_vec())
            .await
            .expect("plant bogus");
        match fetch_external_commitment(&x).await {
            Err(_) => {} // correct — x mismatch detected
            Ok(_) => panic!("anchor with mismatched x must not validate"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // find_hop
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn find_hop_returns_correct_hop_or_none() {
        let path = sample_path();
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x20),
            initiator_public_key: &[0x11u8; 64],
            initiator_signature: vec![],
        })
        .unwrap();
        let hop = find_hop(&rc, &vid(1)).expect("hop 1 present");
        assert_eq!(hop.vault_id, vid(1).to_vec());
        let hop2 = find_hop(&rc, &vid(2)).expect("hop 2 present");
        assert_eq!(hop2.vault_id, vid(2).to_vec());
        assert!(find_hop(&rc, &vid(99)).is_none(), "absent vault must be None");
    }

    // ─────────────────────────────────────────────────────────────────
    // Routed-unlock eligibility (chunks #4 + #5)
    //
    // Tests use REAL SPHINCS+ keypairs because chunk #5 added a hard
    // signature-verification step at the front of the gate.  Each test
    // generates a fresh keypair, signs the canonical RouteCommit bytes,
    // and exercises the full validate-decode → verify-sig → find-hop
    // → check-X chain.
    // ─────────────────────────────────────────────────────────────────

    use dsm::crypto::sphincs::{generate_keypair, sign as sphincs_sign, SphincsVariant};

    /// Build a RouteCommit signed under a freshly-generated SPHINCS+
    /// keypair, optionally publish the X anchor, and return everything
    /// the test needs.
    async fn make_signed_route_commit(
        path: &Path,
        nonce_tag: u8,
        publish_anchor: bool,
    ) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keygen");
        let mut rc = bind_path_to_route_commit(BindRouteCommitInput {
            path,
            nonce: nonce(nonce_tag),
            initiator_public_key: &kp.public_key,
            initiator_signature: vec![],
        })
        .unwrap();
        let canonical = canonicalise_for_commitment(&rc);
        let canonical_bytes = canonical.encode_to_vec();
        let sig = sphincs_sign(SphincsVariant::SPX256f, &kp.secret_key, &canonical_bytes)
            .expect("sphincs sign");
        rc.initiator_signature = sig;
        let x = compute_external_commitment(&rc);
        if publish_anchor {
            publish_external_commitment(&x, &kp.public_key, "test-route")
                .await
                .expect("publish");
        }
        (rc.encode_to_vec(), x, kp.public_key.clone())
    }

    #[tokio::test]
    async fn eligibility_passes_when_x_visible_and_vault_in_route() {
        let path = sample_path();
        let (rc_bytes, _x, _pk) = make_signed_route_commit(&path, 0x40, true).await;

        // Vault 1 (first hop) — must pass.
        let hop = verify_route_commit_unlock_eligibility(&rc_bytes, &vid(1))
            .await
            .expect("eligible");
        assert_eq!(hop.vault_id, vid(1).to_vec());

        // Vault 2 (second hop) — must also pass; routed unlocks are
        // independent on each vault's own chain.
        let hop2 = verify_route_commit_unlock_eligibility(&rc_bytes, &vid(2))
            .await
            .expect("eligible");
        assert_eq!(hop2.vault_id, vid(2).to_vec());
    }

    #[tokio::test]
    async fn eligibility_rejects_vault_not_in_route() {
        let path = sample_path();
        let (rc_bytes, _x, _pk) = make_signed_route_commit(&path, 0x41, true).await;

        match verify_route_commit_unlock_eligibility(&rc_bytes, &vid(99)).await {
            Err(RouteCommitVerifyError::VaultNotInRoute) => {}
            other => panic!("expected VaultNotInRoute, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_when_x_not_visible() {
        let path = sample_path();
        // Build + sign but DON'T publish the anchor.
        let (rc_bytes, _x, _pk) = make_signed_route_commit(&path, 0x42, false).await;
        match verify_route_commit_unlock_eligibility(&rc_bytes, &vid(1)).await {
            Err(RouteCommitVerifyError::ExternalCommitmentNotVisible) => {}
            other => {
                panic!("expected ExternalCommitmentNotVisible, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_garbage_route_commit_bytes() {
        match verify_route_commit_unlock_eligibility(b"not-a-proto", &vid(1)).await {
            Err(RouteCommitVerifyError::InvalidRouteCommitEncoding) => {}
            other => {
                panic!("expected InvalidRouteCommitEncoding, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_when_anchor_x_does_not_match_key() {
        // Anchor exists at the right key but its `x` field disagrees —
        // a forged/swapped record.  Eligibility MUST reject.
        let path = sample_path();
        let (rc_bytes, x, pk) = make_signed_route_commit(&path, 0x43, false).await;
        let key = external_commitment_key(&x);
        let bogus = generated::ExternalCommitmentV1 {
            version: 1,
            x: vec![0xFF; 32], // intentionally wrong
            publisher_public_key: pk.clone(),
            label: "tampered".into(),
        };
        BitcoinTapSdk::storage_put_bytes(&key, &bogus.encode_to_vec())
            .await
            .expect("plant bogus");

        match verify_route_commit_unlock_eligibility(&rc_bytes, &vid(1)).await {
            Err(RouteCommitVerifyError::AnchorFetchFailed(_)) => {}
            other => panic!("expected AnchorFetchFailed, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Chunk #5 — SPHINCS+ signature validation
    // ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn eligibility_rejects_empty_initiator_signature() {
        let path = sample_path();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keygen");
        // Build but leave signature empty (chunk #5 closes this).
        let rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x50),
            initiator_public_key: &kp.public_key,
            initiator_signature: vec![],
        })
        .unwrap();
        match verify_route_commit_unlock_eligibility(&rc.encode_to_vec(), &vid(1)).await
        {
            Err(RouteCommitVerifyError::InvalidInitiatorSignature) => {}
            other => panic!(
                "expected InvalidInitiatorSignature, got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_empty_initiator_public_key() {
        let path = sample_path();
        // Construct a RouteCommit with an empty pk.  Even with a
        // signature present, the gate must reject.
        let mut rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x51),
            initiator_public_key: &[],
            initiator_signature: vec![0xAA; 100],
        })
        .unwrap();
        rc.initiator_public_key.clear(); // belt-and-suspenders
        match verify_route_commit_unlock_eligibility(&rc.encode_to_vec(), &vid(1)).await
        {
            Err(RouteCommitVerifyError::MissingInitiatorPublicKey) => {}
            other => panic!(
                "expected MissingInitiatorPublicKey, got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_signature_under_wrong_key() {
        // Two keypairs.  Sign with kp_a.secret_key but stamp the
        // RouteCommit with kp_b.public_key — the SPHINCS+ verifier
        // must reject this as a forgery.
        let path = sample_path();
        let kp_a = generate_keypair(SphincsVariant::SPX256f).expect("kp_a");
        let kp_b = generate_keypair(SphincsVariant::SPX256f).expect("kp_b");
        let mut rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x52),
            initiator_public_key: &kp_b.public_key, // wrong pk
            initiator_signature: vec![],
        })
        .unwrap();
        let canonical = canonicalise_for_commitment(&rc);
        let sig = sphincs_sign(
            SphincsVariant::SPX256f,
            &kp_a.secret_key, // signed under DIFFERENT key
            &canonical.encode_to_vec(),
        )
        .expect("sign");
        rc.initiator_signature = sig;
        match verify_route_commit_unlock_eligibility(&rc.encode_to_vec(), &vid(1)).await
        {
            Err(RouteCommitVerifyError::InvalidInitiatorSignature) => {}
            other => panic!(
                "wrong-key signature must be rejected; got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn eligibility_rejects_post_sign_tampered_route_commit() {
        // Sign correctly, then tamper with a hop field BEFORE encoding.
        // The signature was over the pre-tamper bytes, so verification
        // against the tampered canonical bytes must fail.
        let path = sample_path();
        let kp = generate_keypair(SphincsVariant::SPX256f).expect("keygen");
        let mut rc = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x53),
            initiator_public_key: &kp.public_key,
            initiator_signature: vec![],
        })
        .unwrap();
        let canonical = canonicalise_for_commitment(&rc);
        let sig = sphincs_sign(
            SphincsVariant::SPX256f,
            &kp.secret_key,
            &canonical.encode_to_vec(),
        )
        .expect("sign");
        rc.initiator_signature = sig;

        // Tamper AFTER signing.
        rc.hops[0].fee_bps += 1;

        match verify_route_commit_unlock_eligibility(&rc.encode_to_vec(), &vid(1)).await
        {
            Err(RouteCommitVerifyError::InvalidInitiatorSignature) => {}
            other => panic!(
                "post-sign tamper must invalidate signature; got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn eligibility_signature_check_runs_before_anchor_visibility() {
        // A RouteCommit with a forged signature should fail at the
        // signature step regardless of whether X is visible.  This
        // proves the gate's ordering: forged routes never even reach
        // the storage-anchor lookup, so an attacker can't spam
        // storage queries with garbage RouteCommits.
        let path = sample_path();
        let kp_real = generate_keypair(SphincsVariant::SPX256f).expect("kp_real");
        let kp_attacker = generate_keypair(SphincsVariant::SPX256f).expect("kp_attacker");
        // Build under real pk + sign (correctly) so X is real and
        // anchor publish succeeds.
        let mut rc_real = bind_path_to_route_commit(BindRouteCommitInput {
            path: &path,
            nonce: nonce(0x54),
            initiator_public_key: &kp_real.public_key,
            initiator_signature: vec![],
        })
        .unwrap();
        let canonical_real = canonicalise_for_commitment(&rc_real);
        rc_real.initiator_signature = sphincs_sign(
            SphincsVariant::SPX256f,
            &kp_real.secret_key,
            &canonical_real.encode_to_vec(),
        )
        .expect("sign real");
        let x_real = compute_external_commitment(&rc_real);
        publish_external_commitment(&x_real, &kp_real.public_key, "real")
            .await
            .expect("publish real");

        // Now build a parallel RouteCommit with attacker's pk + a
        // garbage signature.  X is the same in shape but signature
        // is bogus — must reject at sig-check before reaching anchor.
        let mut rc_attack = rc_real.clone();
        rc_attack.initiator_public_key = kp_attacker.public_key.clone();
        rc_attack.initiator_signature = vec![0xFF; 49856]; // SPX256f sig length
        match verify_route_commit_unlock_eligibility(&rc_attack.encode_to_vec(), &vid(1))
            .await
        {
            Err(RouteCommitVerifyError::InvalidInitiatorSignature)
            | Err(RouteCommitVerifyError::SignatureVerifierError(_)) => {}
            other => panic!(
                "forged signature must reject before anchor lookup; got {other:?}"
            ),
        }
    }
}
