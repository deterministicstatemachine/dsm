// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 6: vault-state composition for SoFi quote-time correctness.
//!
//! Background
//! ----------
//! SoFi spec §2.3 + §4.1 specify that once a valid σ (stitched proof of
//! completion) exists on storage, the unlock is computable by anyone and
//! "settlement executes deterministically".  In particular this implies
//! that the **next trader** quoting against a vault should derive the
//! vault's canonical current state from:
//!
//!   1. The latest owner-signed `VaultStateAnchorV1` (the baseline)
//!   2. PLUS any pending `VaultPendingPointerV1` records published since
//!      the baseline that chain forward by one sequence step
//!
//! Without this composition, traders see only the latest owner-published
//! anchor.  If the owner is offline between trades, concurrent traders
//! all build against the stale anchor and Tripwire prunes all but one of
//! them — the owner becomes a continuous-throughput bottleneck.
//!
//! What this module does
//! ---------------------
//! `compose_vault_state` takes a vault id + owner-signed baseline anchor
//! + the canonical (token_a, token_b, fee_bps) tuple. It:
//!
//! - Lists `sofi/vault-pending/{vault_id_b32}/` (lex-ordered by `new_sequence`)
//! - For each pointer: verifies the SPHINCS+ signature; fetches
//!   `sofi/extcommit/{x_b32}` to confirm the X anchor is published;
//!   fetches `sofi/extcommit-rc/{x_b32}` to obtain the signed RouteCommit;
//!   locates the hop touching this vault, verifies the hop's bound
//!   reserves digest matches the cursor, and re-simulates the AMM swap
//!   to advance both the sequence AND the reserves
//! - Stops at first pointer that fails any check, or at
//!   `MAX_PENDING_CHAIN_DEPTH`, or when a sequence gap is detected
//! - Returns the composed state (sequence + composed reserves)
//!
//! Reserve folding
//! ---------------
//! The composer walks each pointer in sequence order and applies the
//! AMM swap embedded in the corresponding signed RouteCommit (fetched
//! from `sofi/extcommit-rc/{X_b32}`).  Concretely, for each pointer:
//!
//! - Look up the hop in the RouteCommit whose `vault_id` matches.
//! - Verify the hop's `vault_state_reserves_digest` equals the cursor's
//!   current reserves digest (this is the cryptographic link between
//!   pointer and cursor state).
//! - Re-simulate `constant_product_output(input, reserve_in, reserve_out,
//!   fee_bps)` against the cursor.  The simulated output must equal the
//!   hop's claimed `expected_output_amount`; if it doesn't the pointer
//!   was signed against a different baseline and folding it is unsafe.
//! - Advance the cursor's reserves (`+input` on the input side, `-output`
//!   on the output side) and bump the sequence.
//!
//! The result is a derived state where both `sequence` AND `reserves`
//! reflect everything published so far, not just the owner-signed
//! baseline.  Path search consumes this composed view, so concurrent
//! traders quoting against the same vault while the owner is offline
//! see each other's pending trades and serialize on top of them
//! instead of all colliding against the stale anchor.

use dsm::dlv::vault_pending_pointer::{verify_vault_pending_pointer, SignedVaultPendingPointer};
use dsm::dlv::vault_state_anchor::{
    compute_reserves_digest, verify_vault_state_anchor, SignedVaultStateAnchor,
};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::sdk::route_commit_sdk::{
    compute_external_commitment, external_commitment_rc_key,
    verify_route_commit_unlock_eligibility, vault_pending_prefix,
};
use crate::sdk::routing_path_sdk::constant_product_output;

/// Maximum pending-chain depth a composer will fold before treating the
/// vault as saturated and excluding it from path search.  Caps adversarial
/// pointer-flooding cost at O(MAX_PENDING_CHAIN_DEPTH) signature verifies
/// per quote.
pub(crate) const MAX_PENDING_CHAIN_DEPTH: usize = 64;

/// Result of composing pending pointers onto an owner-signed baseline.
#[derive(Debug, Clone)]
pub(crate) struct ComposedVaultState {
    /// Latest sequence number the composer was able to verify.  This is
    /// the baseline's sequence when no valid pointers were folded; the
    /// last successfully-folded pointer's `new_sequence` otherwise.
    pub sequence: u64,
    /// Composed reserves after applying every successfully-folded
    /// pending pointer's AMM swap.  Path search consumes these for
    /// quote-time AMM math; the chunks-#7 gate verifies against the
    /// vault's local DLVManager at unlock time so the chain is
    /// authoritative for the actual settlement.
    pub reserves_a: u128,
    pub reserves_b: u128,
    /// Number of pending pointers successfully verified + chained.
    pub pending_chain_len: usize,
    /// Number of pending pointers skipped (signature invalid, X missing,
    /// out-of-sequence, beyond MAX_PENDING_CHAIN_DEPTH).  Useful for
    /// telemetry / regression tests.
    pub pending_chain_skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionError {
    /// Baseline anchor's SPHINCS+ signature failed verification.  Fail
    /// closed — without a valid baseline the entire composition is moot.
    InvalidBaselineAnchor,
    /// SoFi spec §4.1.2 / §8.4 step 2: a vault state inclusion proof
    /// was published for this vault BUT the proof's signature, SMT
    /// inclusion path, OR (vault_id, sequence, reserves_digest) tuple
    /// disagrees with the baseline anchor.  Fail closed — either the
    /// owner equivocated or someone tampered with one of the two
    /// records; both possibilities make the vault unsafe to quote.
    InvalidInclusionProof,
    /// SoFi spec §4.1.2 strict mode: NO inclusion proof was published
    /// for this vault.  The vault may pre-date the Phase-7 SMT flow
    /// (legacy advertisement) OR the owner has not yet republished
    /// after the upgrade.  Either way, strict-mode composition refuses
    /// to fold it — the trader cannot prove the vault state is in the
    /// owner's PD-SMT, which is what the spec demands.
    MissingInclusionProof,
    /// Storage listing the pending prefix failed.
    StorageListFailed(String),
    /// Decoding a pointer proto failed in a non-recoverable way.  The
    /// individual pointer is skipped; this variant fires only if the
    /// whole list page failed.
    PointerDecodeFailed(String),
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionError::InvalidBaselineAnchor => {
                write!(f, "baseline anchor signature invalid")
            }
            CompositionError::InvalidInclusionProof => {
                write!(f, "vault state inclusion proof failed verification")
            }
            CompositionError::MissingInclusionProof => {
                write!(
                    f,
                    "vault has no published VaultStateInclusionProofV1 — strict mode requires one (SoFi §4.1.2)"
                )
            }
            CompositionError::StorageListFailed(msg) => {
                write!(f, "storage list failed: {msg}")
            }
            CompositionError::PointerDecodeFailed(msg) => {
                write!(f, "pointer decode failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// Fold pending pointers onto an owner-signed baseline.
///
/// `baseline` is the latest `VaultStateAnchorV1` the owner has published
/// (typically fetched via `dlv.getVaultStateAnchor` or via the routing
/// advertisement's `state_number`).  Its signature is re-verified here
/// — fail-closed if the baseline itself is broken.
///
/// `baseline_reserves` are the (reserve_a, reserve_b) values committed
/// in the baseline's `reserves_digest`.  Caller supplies them because
/// the digest is one-way (verification re-derives + compares, but the
/// composer needs the magnitudes to compute the running cursor).
///
/// Returns the composed `(sequence, reserves_a, reserves_b)` plus
/// telemetry (`pending_chain_len` / `pending_chain_skipped`) so the
/// path search handler can log progress and drop saturated vaults
/// from the candidate set.
pub(crate) async fn compose_vault_state(
    vault_id: &[u8; 32],
    baseline: &SignedVaultStateAnchor,
    baseline_reserves: (u128, u128),
    token_a: &[u8],
    token_b: &[u8],
    fee_bps: u32,
) -> Result<ComposedVaultState, CompositionError> {
    // Verify the baseline anchor's signature.  No further composition
    // is meaningful without this.
    verify_vault_state_anchor(baseline).map_err(|_| CompositionError::InvalidBaselineAnchor)?;
    // And cross-check the supplied reserves match the baseline digest.
    let expected_digest = compute_reserves_digest(
        token_a,
        token_b,
        baseline_reserves.0,
        baseline_reserves.1,
        fee_bps,
    );
    if expected_digest != baseline.reserves_digest {
        // Caller bug — they supplied reserves that don't match the
        // signed baseline.  Surface as InvalidBaselineAnchor: the
        // baseline cannot be trusted for composition.
        return Err(CompositionError::InvalidBaselineAnchor);
    }

    // SoFi spec §4.1.2 / §8.4 step 2 — STRICT MODE.  Verify the
    // owner's PD-SMT inclusion proof for the baseline vault state.
    // The anchor signature above is *necessary* but not *sufficient*:
    // an attacker who recovered K_DBRW could forge a signed anchor.
    // The inclusion proof additionally commits the SMT root + a
    // 256-sibling Merkle path that
    // dsm::dlv::vault_smt_leaf::verify_vault_smt_inclusion recomputes
    // against the device's actual SMT — forgery requires also
    // fabricating SMT consistency, which a stateless attacker cannot.
    //
    // Strict mode: a vault with no published inclusion proof is
    // dropped from the candidate set.  This is the documented Phase-7
    // migration behaviour — legacy ads pre-dating this code do not
    // pass.
    let inclusion = crate::sdk::vault_smt_inclusion_codec::fetch_latest_inclusion_proof(vault_id)
        .await
        .map_err(|e| CompositionError::StorageListFailed(format!("inclusion fetch: {e}")))?;
    let inclusion = match inclusion {
        Some(p) => p,
        None => return Err(CompositionError::MissingInclusionProof),
    };
    // Cross-bind the inclusion proof to the baseline: same
    // (vault_id, sequence, reserves_digest) tuple.  If they disagree,
    // the owner equivocated and the vault is unsafe.
    if inclusion.vault_id != baseline.vault_id
        || inclusion.sequence != baseline.sequence
        || inclusion.reserves_digest != baseline.reserves_digest
    {
        return Err(CompositionError::InvalidInclusionProof);
    }
    // Verify the inclusion proof end-to-end (signature + SMT path).
    dsm::dlv::vault_smt_leaf::verify_vault_state_inclusion_proof(&inclusion)
        .map_err(|_| CompositionError::InvalidInclusionProof)?;

    let prefix = vault_pending_prefix(vault_id);
    let mut cursor: Option<String> = None;
    const LIST_LIMIT: u32 = 256;

    let mut pointers: Vec<SignedVaultPendingPointer> = Vec::new();
    loop {
        let resp = BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), LIST_LIMIT)
            .await
            .map_err(|e| CompositionError::StorageListFailed(format!("{e}")))?;
        for item in &resp.items {
            let bytes = match BitcoinTapSdk::storage_get_bytes(&item.key).await {
                Ok(b) => b,
                Err(e) => {
                    log::debug!(
                        "[compose_vault_state] skipping {}: fetch failed: {e}",
                        &item.key,
                    );
                    continue;
                }
            };
            let proto = match generated::VaultPendingPointerV1::decode(bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!(
                        "[compose_vault_state] skipping {}: decode failed: {e}",
                        &item.key,
                    );
                    continue;
                }
            };
            // Convert proto → typed struct for verification.
            if proto.vault_id.len() != 32
                || proto.x.len() != 32
                || proto.new_reserves_digest.len() != 32
            {
                continue;
            }
            let mut vid_arr = [0u8; 32];
            vid_arr.copy_from_slice(&proto.vault_id);
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(&proto.x);
            let mut digest_arr = [0u8; 32];
            digest_arr.copy_from_slice(&proto.new_reserves_digest);
            // Confirm the pointer references the vault we're composing.
            // (Storage prefix should already filter this, but defensive
            // re-check costs nothing.)
            if vid_arr != *vault_id {
                continue;
            }
            pointers.push(SignedVaultPendingPointer {
                vault_id: vid_arr,
                parent_sequence: proto.parent_sequence,
                new_sequence: proto.new_sequence,
                x: x_arr,
                new_reserves_digest: digest_arr,
                publisher_public_key: proto.publisher_public_key,
                publisher_signature: proto.publisher_signature,
            });
        }
        if (resp.items.len() as u32) < LIST_LIMIT {
            break;
        }
        cursor = resp.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    // Sort by new_sequence ascending so chain folding is deterministic.
    pointers.sort_by(|a, b| a.new_sequence.cmp(&b.new_sequence).then(a.x.cmp(&b.x)));

    // Fold pointers onto the baseline.  Full Phase-6 fold-rule:
    //   - Pointer's parent_sequence must equal the running cursor.
    //   - Pointer's signature must verify.
    //   - The X it references must actually exist on storage (so we
    //     never advance the cursor against a pointer for a non-published
    //     trade).
    //   - The signed RouteCommit at defi/extcommit-rc/{x_b32} must be
    //     present + decode + carry a hop touching this vault.
    //   - The hop's vault_state_reserves_digest (the digest the trader
    //     signed against) must match the running cursor's reserves +
    //     fee_bps — this ties the pointer to the cursor's actual state.
    //   - The AMM swap math against the cursor's reserves must succeed.
    //   - Up to MAX_PENDING_CHAIN_DEPTH folds total.
    //
    // Both sequence AND reserves advance.  This is the load-bearing
    // step that makes "math speaks for itself" observable: the
    // composer derives the canonical current state from published
    // proofs, not from the owner's (possibly stale) signed anchor.
    let mut cursor_seq = baseline.sequence;
    let mut cursor_reserve_a = baseline_reserves.0;
    let mut cursor_reserve_b = baseline_reserves.1;
    let mut chain_len: usize = 0;
    let mut chain_skipped: usize = 0;
    for ptr in pointers.into_iter() {
        if chain_len >= MAX_PENDING_CHAIN_DEPTH {
            chain_skipped += 1;
            continue;
        }
        if ptr.parent_sequence != cursor_seq {
            chain_skipped += 1;
            continue;
        }
        if verify_vault_pending_pointer(&ptr).is_err() {
            chain_skipped += 1;
            continue;
        }
        // Fetch the full signed RouteCommit paired with X.
        let rc_key = external_commitment_rc_key(&ptr.x);
        let rc_bytes = match BitcoinTapSdk::storage_get_bytes(&rc_key).await {
            Ok(b) => b,
            Err(_) => {
                // RC not yet published (publisher crashed between X and
                // RC writes, or publisher used the legacy bare-anchor
                // path).  Cannot fold reserves without the RC; skip.
                chain_skipped += 1;
                continue;
            }
        };
        let rc = match generated::RouteCommitV1::decode(rc_bytes.as_slice()) {
            Ok(r) => r,
            Err(_) => {
                chain_skipped += 1;
                continue;
            }
        };
        // Bind pointer.x to the canonical RouteCommit commitment.
        // Storage keys are untrusted labels, so we MUST recompute X
        // from RouteCommit bytes and require exact equality.
        let computed_x = compute_external_commitment(&rc);
        if computed_x != ptr.x {
            chain_skipped += 1;
            continue;
        }
        // Enforce routed-unlock eligibility gate:
        //   1) initiator SPHINCS+ signature valid over canonical RC bytes
        //   2) this vault is present in the route
        //   3) external commitment anchor for X is visible
        let hop = match verify_route_commit_unlock_eligibility(&rc_bytes, vault_id).await {
            Ok(h) => h,
            Err(_) => {
                chain_skipped += 1;
                continue;
            }
        };
        // Verify the hop's bound reserves_digest matches the cursor's
        // current reserves.  If it doesn't, this pointer's RC was
        // signed against a different parent state and folding it would
        // diverge from the canonical chain — skip.  Note: this is the
        // cryptographic link between pointer and cursor.
        let cursor_digest = compute_reserves_digest(
            token_a,
            token_b,
            cursor_reserve_a,
            cursor_reserve_b,
            fee_bps,
        );
        if !hop.vault_state_reserves_digest.is_empty()
            && hop.vault_state_reserves_digest.as_slice() != cursor_digest.as_slice()
        {
            chain_skipped += 1;
            continue;
        }
        // Decode the hop's input/output amounts.
        if hop.input_amount_u128.len() != 16 || hop.expected_output_amount_u128.len() != 16 {
            chain_skipped += 1;
            continue;
        }
        let mut in_buf = [0u8; 16];
        in_buf.copy_from_slice(&hop.input_amount_u128);
        let mut out_buf = [0u8; 16];
        out_buf.copy_from_slice(&hop.expected_output_amount_u128);
        let input_amount = u128::from_be_bytes(in_buf);
        let expected_output = u128::from_be_bytes(out_buf);
        // Determine trade direction against the lex-canonical vault pair.
        let input_is_a = hop.token_in.as_slice() == token_a && hop.token_out.as_slice() == token_b;
        let input_is_b = hop.token_in.as_slice() == token_b && hop.token_out.as_slice() == token_a;
        if !input_is_a && !input_is_b {
            chain_skipped += 1;
            continue;
        }
        let (cursor_in, cursor_out) = if input_is_a {
            (cursor_reserve_a, cursor_reserve_b)
        } else {
            (cursor_reserve_b, cursor_reserve_a)
        };
        // Re-simulate against the cursor.  The composer demands the
        // simulated output equals the trader's claimed expected_output
        // — anything else means the trade settled against a different
        // baseline and folding it is unsafe.
        let simulated = match constant_product_output(input_amount, cursor_in, cursor_out, fee_bps)
        {
            Some(v) => v,
            None => {
                chain_skipped += 1;
                continue;
            }
        };
        if simulated != expected_output {
            chain_skipped += 1;
            continue;
        }
        // Apply the swap to the cursor.  Saturating-sub on the output
        // side defends against malformed RCs that claim more than the
        // pool can pay; the re-sim above should already exclude these,
        // but defense-in-depth is cheap.
        let (new_a, new_b) = if input_is_a {
            (
                cursor_reserve_a.saturating_add(input_amount),
                cursor_reserve_b.saturating_sub(expected_output),
            )
        } else {
            (
                cursor_reserve_a.saturating_sub(expected_output),
                cursor_reserve_b.saturating_add(input_amount),
            )
        };
        cursor_reserve_a = new_a;
        cursor_reserve_b = new_b;
        cursor_seq = ptr.new_sequence;
        chain_len += 1;
    }

    Ok(ComposedVaultState {
        sequence: cursor_seq,
        reserves_a: cursor_reserve_a,
        reserves_b: cursor_reserve_b,
        pending_chain_len: chain_len,
        pending_chain_skipped: chain_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::crypto::sphincs::{generate_keypair, SphincsVariant};
    use dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer;
    use dsm::dlv::vault_state_anchor::sign_vault_state_anchor;

    /// Sign-only baseline anchor.  Used by negative tests that want
    /// to deliberately skip the inclusion-proof publish (so strict
    /// mode rejects the vault).
    #[allow(clippy::too_many_arguments)]
    fn make_baseline_anchor_only(
        vault_id: &[u8; 32],
        seq: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) -> SignedVaultStateAnchor {
        let digest = compute_reserves_digest(token_a, token_b, reserve_a, reserve_b, fee_bps);
        sign_vault_state_anchor(vault_id, seq, &digest, owner_pk, owner_sk).expect("sign anchor")
    }

    /// Phase-7 strict-mode-compatible baseline: sign the anchor AND
    /// publish a matching `VaultStateInclusionProofV1` so
    /// `compose_vault_state` sees a verifiable PD-SMT witness.  Most
    /// composition tests use this — it's the production-equivalent
    /// path.
    #[allow(clippy::too_many_arguments)]
    async fn make_baseline(
        vault_id: &[u8; 32],
        seq: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) -> SignedVaultStateAnchor {
        let anchor = make_baseline_anchor_only(
            vault_id, seq, token_a, token_b, reserve_a, reserve_b, fee_bps, owner_pk, owner_sk,
        );
        publish_baseline_inclusion_proof(
            vault_id, seq, token_a, token_b, reserve_a, reserve_b, fee_bps, owner_pk, owner_sk,
        )
        .await;
        anchor
    }

    /// Phase 7 test helper: publish a real
    /// `VaultStateInclusionProofV1` for the baseline `(vault_id,
    /// sequence, reserves_digest)` so strict-mode composition accepts
    /// it.  Mirrors what `publish_vault_state_inclusion_proof` does on
    /// the live `dlv.create` path, but driven from test code by
    /// building a fresh SMT and signing with the supplied owner key.
    #[allow(clippy::too_many_arguments)]
    async fn publish_baseline_inclusion_proof(
        vault_id: &[u8; 32],
        sequence: u64,
        token_a: &[u8],
        token_b: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        fee_bps: u32,
        owner_pk: &[u8],
        owner_sk: &[u8],
    ) {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let reserves_digest =
            compute_reserves_digest(token_a, token_b, reserve_a, reserve_b, fee_bps);
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(vault_id);
        let leaf_value = compute_vault_smt_value(sequence, &reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");

        let signed = sign_vault_state_inclusion_proof(
            vault_id,
            sequence,
            &reserves_digest,
            &smt_root,
            proof.siblings,
            owner_pk,
            owner_sk,
        )
        .expect("sign inclusion proof");

        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(
            vault_id,
            sequence,
            &proto_bytes,
        )
        .await
        .expect("publish inclusion proof");
    }

    fn marker_digest(x: &[u8; 32], hop_index: u32) -> [u8; 32] {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(b"DSM/pending-marker\0");
        h.update(x);
        h.update(&hop_index.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn vid_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = b;
        v[31] = b.wrapping_mul(13).wrapping_add(7);
        v
    }

    fn x_seed(b: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = 0xEC;
        v[1] = b;
        v[31] = b.wrapping_mul(31).wrapping_add(11);
        v
    }

    /// Publish the minimal ExtCommit anchor at `sofi/extcommit/{X_b32}`.
    async fn publish_extcommit(x: &[u8; 32], publisher_pk: &[u8]) {
        let anchor = generated::ExternalCommitmentV1 {
            version: 1,
            x: x.to_vec(),
            publisher_public_key: publisher_pk.to_vec(),
            label: "test".into(),
        };
        let key = crate::sdk::route_commit_sdk::external_commitment_key(x);
        BitcoinTapSdk::storage_put_bytes(&key, &anchor.encode_to_vec())
            .await
            .expect("X publish");
    }

    /// Publish a `RouteCommitV1` with a single AMM hop touching
    /// `vault_id` at `sofi/extcommit-rc/{X_b32}`.  Returns the swap's
    /// post-trade reserves plus the canonical commitment `X` so callers
    /// can publish matching anchors/pointers.  The hop's
    /// `vault_state_reserves_digest` is bound
    /// to the supplied parent reserves so the composer's
    /// cursor-vs-hop digest check passes.
    #[allow(clippy::too_many_arguments)]
    async fn publish_rc_for_swap(
        nonce_seed: &[u8; 32],
        vault_id: &[u8; 32],
        token_a: &[u8],
        token_b: &[u8],
        parent_reserve_a: u128,
        parent_reserve_b: u128,
        fee_bps: u32,
        parent_sequence: u64,
        input_is_a: bool,
        input_amount: u128,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) -> (u128, u128, [u8; 32]) {
        // Reserves cursor logic mirrors compose_vault_state.
        let (reserve_in, reserve_out) = if input_is_a {
            (parent_reserve_a, parent_reserve_b)
        } else {
            (parent_reserve_b, parent_reserve_a)
        };
        let simulated = crate::sdk::routing_path_sdk::constant_product_output(
            input_amount,
            reserve_in,
            reserve_out,
            fee_bps,
        )
        .expect("test inputs must yield a swap");
        let (new_a, new_b) = if input_is_a {
            (
                parent_reserve_a + input_amount,
                parent_reserve_b - simulated,
            )
        } else {
            (
                parent_reserve_a - simulated,
                parent_reserve_b + input_amount,
            )
        };

        // Digest the parent reserves so the composer's cursor digest
        // matches this hop's bound digest.
        let parent_digest = compute_reserves_digest(
            token_a,
            token_b,
            parent_reserve_a,
            parent_reserve_b,
            fee_bps,
        );

        let (hop_token_in, hop_token_out) = if input_is_a {
            (token_a.to_vec(), token_b.to_vec())
        } else {
            (token_b.to_vec(), token_a.to_vec())
        };
        let hop = generated::RouteCommitHopV1 {
            vault_id: vault_id.to_vec(),
            token_in: hop_token_in,
            token_out: hop_token_out,
            input_amount_u128: input_amount.to_be_bytes().to_vec(),
            expected_output_amount_u128: simulated.to_be_bytes().to_vec(),
            fee_bps,
            advertisement_digest: vec![0u8; 32],
            state_number: parent_sequence,
            unlock_spec_digest: vec![0u8; 32],
            owner_public_key: Vec::new(),
            vault_state_anchor_seq: parent_sequence,
            vault_state_reserves_digest: parent_digest.to_vec(),
            vault_state_anchor_digest: vec![0u8; 32],
            min_output_amount_u128: Vec::new(),
        };
        let rc = generated::RouteCommitV1 {
            version: 1,
            nonce: nonce_seed.to_vec(),
            input_token: token_a.to_vec(),
            output_token: token_b.to_vec(),
            input_amount_u128: input_amount.to_be_bytes().to_vec(),
            expected_final_output_amount_u128: simulated.to_be_bytes().to_vec(),
            total_fee_bps: fee_bps as u64,
            hops: vec![hop],
            initiator_public_key: trader_pk.to_vec(),
            initiator_signature: Vec::new(),
            floor_final_output_amount_u128: Vec::new(),
            fallbacks: Vec::new(),
        };
        let canonical_bytes = rc.encode_to_vec();
        let sig = dsm::crypto::sphincs::sphincs_sign(trader_sk, &canonical_bytes)
            .expect("sign route commit");
        let mut signed_rc = rc;
        signed_rc.initiator_signature = sig;
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&signed_rc);
        let rc_key = crate::sdk::route_commit_sdk::external_commitment_rc_key(&x);
        BitcoinTapSdk::storage_put_bytes(&rc_key, &signed_rc.encode_to_vec())
            .await
            .expect("signed RC publish");
        (new_a, new_b, x)
    }

    async fn publish_pointer(
        vault_id: &[u8; 32],
        parent_seq: u64,
        new_seq: u64,
        x: &[u8; 32],
        digest: &[u8; 32],
        publisher_pk: &[u8],
        publisher_sk: &[u8],
    ) {
        let signed = sign_vault_pending_pointer(
            vault_id,
            parent_seq,
            new_seq,
            x,
            digest,
            publisher_pk,
            publisher_sk,
        )
        .expect("sign pointer");
        let proto = generated::VaultPendingPointerV1 {
            vault_id: signed.vault_id.to_vec(),
            parent_sequence: signed.parent_sequence,
            new_sequence: signed.new_sequence,
            x: signed.x.to_vec(),
            new_reserves_digest: signed.new_reserves_digest.to_vec(),
            publisher_public_key: signed.publisher_public_key,
            publisher_signature: signed.publisher_signature,
        };
        let key = crate::sdk::route_commit_sdk::vault_pending_pointer_key(vault_id, new_seq, x);
        BitcoinTapSdk::storage_put_bytes(&key, &proto.encode_to_vec())
            .await
            .expect("publish pointer");
    }

    /// Combined helper that publishes the three storage records needed
    /// for one fold-able pending trade: X anchor, full RC, and the
    /// vault-keyed pointer.  Returns the swap's post-trade reserves.
    #[allow(clippy::too_many_arguments)]
    async fn publish_trade(
        vault_id: &[u8; 32],
        nonce_seed: &[u8; 32],
        token_a: &[u8],
        token_b: &[u8],
        parent_reserve_a: u128,
        parent_reserve_b: u128,
        fee_bps: u32,
        parent_sequence: u64,
        input_is_a: bool,
        input_amount: u128,
        trader_pk: &[u8],
        trader_sk: &[u8],
    ) -> (u128, u128) {
        let (new_a, new_b, x) = publish_rc_for_swap(
            nonce_seed,
            vault_id,
            token_a,
            token_b,
            parent_reserve_a,
            parent_reserve_b,
            fee_bps,
            parent_sequence,
            input_is_a,
            input_amount,
            trader_pk,
            trader_sk,
        )
        .await;
        publish_extcommit(&x, trader_pk).await;
        publish_pointer(
            vault_id,
            parent_sequence,
            parent_sequence + 1,
            &x,
            &marker_digest(&x, 0),
            trader_pk,
            trader_sk,
        )
        .await;
        (new_a, new_b)
    }

    #[tokio::test]
    async fn composes_empty_chain_returns_baseline() {
        let vault_id = vid_seed(0x10);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            5,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 5);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn folds_single_valid_pointer_advances_sequence_and_reserves() {
        let vault_id = vid_seed(0x11);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x21);
        let (expected_a, expected_b) = publish_trade(
            &vault_id,
            &x,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            0,
            true, // input is A (1000 AAA → some BBB out)
            1_000,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;

        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 1);
        assert_eq!(
            composed.reserves_a, expected_a,
            "reserve_a should grow by the trader's input"
        );
        assert_eq!(
            composed.reserves_b, expected_b,
            "reserve_b should shrink by the simulated output"
        );
        assert!(composed.reserves_a > 1_000_000);
        assert!(composed.reserves_b < 500_000);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn folds_chained_pointers_reserves_track_each_swap() {
        let vault_id = vid_seed(0x12);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // Three sequential trades.  Each picks up where the previous
        // left off so the composer sees a coherent chain.
        let mut cur_a: u128 = 1_000_000;
        let mut cur_b: u128 = 500_000;
        let mut expected_final_a = cur_a;
        let mut expected_final_b = cur_b;
        for (parent_seq, seed_byte, input_is_a, input_amount) in [
            (0u64, 0x31u8, true, 1_000u128),
            (1, 0x32, false, 500),
            (2, 0x33, true, 2_000),
        ]
        .iter()
        {
            let x = x_seed(*seed_byte);
            let (new_a, new_b) = publish_trade(
                &vault_id,
                &x,
                b"AAA",
                b"BBB",
                cur_a,
                cur_b,
                30,
                *parent_seq,
                *input_is_a,
                *input_amount,
                &trader.public_key,
                &trader.secret_key,
            )
            .await;
            cur_a = new_a;
            cur_b = new_b;
            expected_final_a = new_a;
            expected_final_b = new_b;
        }
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 3);
        assert_eq!(composed.reserves_a, expected_final_a);
        assert_eq!(composed.reserves_b, expected_final_b);
        assert_eq!(composed.pending_chain_len, 3);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn skips_pointer_with_missing_x_anchor() {
        let vault_id = vid_seed(0x13);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x41);
        // Intentionally do NOT publish the X anchor (or the RC).
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 0, "cursor stays at baseline");
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn skips_pointer_when_rc_missing_even_if_x_present() {
        // Cross-version safety: a legacy publisher might write the X
        // anchor without the paired RC bytes.  The composer must skip
        // that pointer (it can't verify the swap math without the RC)
        // and report it as skipped, not silently advance the cursor.
        let vault_id = vid_seed(0x16);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let x = x_seed(0x61);
        publish_extcommit(&x, &trader.public_key).await;
        // Skip the RC publish.
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    async fn stops_at_sequence_gap_and_preserves_partial_reserve_advance() {
        let vault_id = vid_seed(0x14);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // Publish seq=1 (chainable) and seq=3 (gap; parent=2 missing).
        // After folding, the cursor advances to seq=1 with reserves
        // reflecting that one trade and stops.
        let (after_first_a, after_first_b) = publish_trade(
            &vault_id,
            &x_seed(0x51),
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        // Orphan pointer at seq=3 (skips seq=2).
        let orphan_x = x_seed(0x53);
        publish_trade(
            &vault_id,
            &orphan_x,
            b"AAA",
            b"BBB",
            after_first_a,
            after_first_b,
            30,
            2, // parent=2, no preceding seq=2 trade
            true,
            500,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 1, "advances through seq=1 then stops");
        assert_eq!(composed.reserves_a, after_first_a);
        assert_eq!(composed.reserves_b, after_first_b);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rejects_pointer_whose_rc_hop_baseline_disagrees_with_cursor() {
        // A trader publishes a RouteCommit whose hop's
        // vault_state_reserves_digest doesn't match the composer's
        // cursor (i.e., the trader signed against the wrong baseline).
        // The composer must reject — folding would diverge from the
        // canonical chain.
        let vault_id = vid_seed(0x17);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        let nonce_seed = x_seed(0x71);
        // Build the RC with WRONG parent reserves (777, 888 instead of
        // the real 1_000_000, 500_000).
        let (_, _, x) = publish_rc_for_swap(
            &nonce_seed,
            &vault_id,
            b"AAA",
            b"BBB",
            777, // wrong parent_reserve_a
            888, // wrong parent_reserve_b
            30,
            0,
            true,
            10,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        publish_extcommit(&x, &trader.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &x,
            &marker_digest(&x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;
        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn rejects_pointer_when_route_commit_x_mismatches_pointer_x() {
        let vault_id = vid_seed(0x18);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let trader = generate_keypair(SphincsVariant::SPX256f).expect("trader kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;

        // Publish a valid signed RouteCommit and obtain its canonical X.
        let nonce_seed = x_seed(0x81);
        let (_, _, canonical_x) = publish_rc_for_swap(
            &nonce_seed,
            &vault_id,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            0,
            true,
            1_000,
            &trader.public_key,
            &trader.secret_key,
        )
        .await;

        // Copy the same RC bytes under a different storage key to simulate
        // storage-key spoofing (keys are untrusted labels).
        let spoofed_x = x_seed(0x82);
        let canonical_key = external_commitment_rc_key(&canonical_x);
        let spoofed_key = external_commitment_rc_key(&spoofed_x);
        let rc_bytes = BitcoinTapSdk::storage_get_bytes(&canonical_key)
            .await
            .expect("fetch canonical rc");
        BitcoinTapSdk::storage_put_bytes(&spoofed_key, &rc_bytes)
            .await
            .expect("publish spoofed rc");

        // Make both anchors visible; eligibility-by-signature alone would pass,
        // so only pointer.x ↔ canonical X binding should reject folding.
        publish_extcommit(&canonical_x, &trader.public_key).await;
        publish_extcommit(&spoofed_x, &trader.public_key).await;
        publish_pointer(
            &vault_id,
            0,
            1,
            &spoofed_x,
            &marker_digest(&spoofed_x, 0),
            &trader.public_key,
            &trader.secret_key,
        )
        .await;

        let composed = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect("compose succeeds");
        assert_eq!(composed.sequence, 0);
        assert_eq!(composed.reserves_a, 1_000_000);
        assert_eq!(composed.reserves_b, 500_000);
        assert_eq!(composed.pending_chain_len, 0);
        assert_eq!(composed.pending_chain_skipped, 1);
    }

    /// The headline scenario the Phase-6 plan targets: Alice (vault
    /// owner) is offline; Bob's trade has settled cryptographically
    /// (X published + RC published + pointer published); Carol comes
    /// along and computes a composed state — she should see sequence=1
    /// AND reserves shifted by Bob's exact trade.  This is the property
    /// that lets concurrent traders serialize against a vault without
    /// the owner online between trades.
    #[tokio::test]
    async fn multi_trader_serialization_without_owner_refresh() {
        let vault_id = vid_seed(0x99);
        let alice = generate_keypair(SphincsVariant::SPX256f).expect("alice kp");
        let bob = generate_keypair(SphincsVariant::SPX256f).expect("bob kp");
        let _carol = generate_keypair(SphincsVariant::SPX256f).expect("carol kp");

        // Alice publishes the baseline anchor at seq=0.  Alice's chain
        // is the authority; everyone else sees this anchor on storage.
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            10_000,
            10_000,
            30,
            &alice.public_key,
            &alice.secret_key,
        )
        .await;

        // Bob trades.  His RouteCommit settles; X + RC + pointer are
        // published.  CRUCIALLY: Alice is offline — she does NOT publish
        // a refreshed anchor at seq=1.
        let bob_x = x_seed(0xBB);
        let (after_bob_a, after_bob_b) = publish_trade(
            &vault_id,
            &bob_x,
            b"AAA",
            b"BBB",
            10_000,
            10_000,
            30,
            0,
            true, // Bob sends AAA in
            500,
            &bob.public_key,
            &bob.secret_key,
        )
        .await;

        // Carol composes.  She sees Alice's seq=0 baseline + Bob's
        // pending pointer + Bob's RC = composed cursor at seq=1 with
        // reserves reflecting Bob's exact trade.  Concurrent
        // serialization without Alice's involvement.
        let composed =
            compose_vault_state(&vault_id, &baseline, (10_000, 10_000), b"AAA", b"BBB", 30)
                .await
                .expect("compose succeeds for Carol");
        assert_eq!(
            composed.sequence, 1,
            "Carol should see Bob's pending advance even though Alice is offline",
        );
        assert_eq!(
            composed.reserves_a, after_bob_a,
            "reserve_a reflects Bob's input"
        );
        assert_eq!(
            composed.reserves_b, after_bob_b,
            "reserve_b reflects Bob's simulated output"
        );
        assert!(composed.reserves_a > 10_000);
        assert!(composed.reserves_b < 10_000);
        assert_eq!(composed.pending_chain_len, 1);
        assert_eq!(composed.pending_chain_skipped, 0);
    }

    #[tokio::test]
    async fn rejects_baseline_with_tampered_reserves_supplied() {
        let vault_id = vid_seed(0x15);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        )
        .await;
        // Supply DIFFERENT reserves than the baseline was signed over.
        let err = compose_vault_state(&vault_id, &baseline, (777_777, 888_888), b"AAA", b"BBB", 30)
            .await
            .expect_err("composition rejects mismatched baseline_reserves");
        assert!(matches!(err, CompositionError::InvalidBaselineAnchor));
    }

    // ───────────────────────────────────────────────────────────
    // Phase 7 — SoFi spec §4.1.2 / §8.4 step 2 strict-mode tests
    // ───────────────────────────────────────────────────────────

    /// Strict mode refuses to fold a vault whose owner never published
    /// a `VaultStateInclusionProofV1` — the legacy anchor alone is
    /// insufficient.  This is the K_DBRW-forgery hole closure: an
    /// attacker with the owner's key can forge a signed anchor but
    /// cannot fabricate SMT consistency.
    #[tokio::test]
    async fn strict_mode_rejects_vault_without_inclusion_proof() {
        let vault_id = vid_seed(0x80);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        // Only sign the anchor — DO NOT publish an inclusion proof.
        // make_baseline_anchor_only is the escape hatch for exactly
        // this negative-test scenario.
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );
        let err = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect_err("strict mode must refuse vault without inclusion proof");
        assert!(matches!(err, CompositionError::MissingInclusionProof));
    }

    /// Strict mode catches owner equivocation: the inclusion proof
    /// references a different (sequence, reserves_digest) than the
    /// baseline anchor.  This would happen if a compromised owner
    /// signed two records with the same key but disagreeing payloads.
    #[tokio::test]
    async fn strict_mode_rejects_inclusion_proof_disagreeing_with_baseline() {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let vault_id = vid_seed(0x81);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        // Anchor is at sequence=0 with the canonical reserves.
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );

        // Publish an inclusion proof at sequence=5 — disagreeing with
        // the baseline's sequence=0.
        let bogus_reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 1_000_000, 500_000, 30);
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(5, &bogus_reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");
        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            5, // <-- disagrees with baseline's seq=0
            &bogus_reserves_digest,
            &smt_root,
            proof.siblings,
            &owner.public_key,
            &owner.secret_key,
        )
        .expect("sign inclusion proof");
        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(&vault_id, 5, &proto_bytes)
            .await
            .expect("publish");

        let err = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect_err("strict mode must reject disagreeing inclusion proof");
        assert!(matches!(err, CompositionError::InvalidInclusionProof));
    }

    /// Strict mode catches a tampered SMT path: the inclusion proof's
    /// (vault_id, sequence, reserves_digest) match the baseline, the
    /// signature is valid (because it doesn't sign over the siblings —
    /// only over the root), but the supplied siblings DON'T hash up to
    /// the claimed root.  Verifier rejects via the SMT inclusion
    /// check.
    #[tokio::test]
    async fn strict_mode_rejects_inclusion_proof_with_tampered_siblings() {
        use dsm::dlv::vault_smt_leaf::{
            compute_vault_smt_key, compute_vault_smt_value, sign_vault_state_inclusion_proof,
        };
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let vault_id = vid_seed(0x82);
        let owner = generate_keypair(SphincsVariant::SPX256f).expect("owner kp");
        let baseline = make_baseline_anchor_only(
            &vault_id,
            0,
            b"AAA",
            b"BBB",
            1_000_000,
            500_000,
            30,
            &owner.public_key,
            &owner.secret_key,
        );

        // Build a real SMT, then corrupt one sibling before signing —
        // the signed payload (which excludes siblings, by design)
        // still verifies, but the inclusion check rejects.
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 1_000_000, 500_000, 30);
        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(0, &reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let mut proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");
        // Corrupt one sibling.
        proof.siblings[0][0] ^= 0xff;

        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &smt_root,
            proof.siblings,
            &owner.public_key,
            &owner.secret_key,
        )
        .expect("sign inclusion proof");
        let proto_bytes =
            crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
        crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(&vault_id, 0, &proto_bytes)
            .await
            .expect("publish");

        let err = compose_vault_state(
            &vault_id,
            &baseline,
            (1_000_000, 500_000),
            b"AAA",
            b"BBB",
            30,
        )
        .await
        .expect_err("strict mode must reject tampered SMT path");
        assert!(matches!(err, CompositionError::InvalidInclusionProof));
    }
}
