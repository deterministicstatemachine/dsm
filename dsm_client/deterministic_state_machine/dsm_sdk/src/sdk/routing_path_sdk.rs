// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi routing path search.
//!
//! Pure deterministic path search over a set of verified
//! `RoutingVaultAdvertisementV1` records.  Produces a typed
//! `Path = Vec<VaultHop>` whose hops bind input/output token, simulated
//! input/output amounts, fee, advertisement digest, state number, and
//! the metadata a later chunk on this track needs to bind into the
//! external commitment proto.
//!
//! This module does NOT touch atomic execution or external commitments
//! — it only computes a route candidate.  The discovery substrate
//! (publish/list/verify) lives in `routing_sdk.rs`; settlement wiring
//! lands in chunk #3.
//!
//! ## Algorithm
//!
//! Bounded enumeration with constant-product simulation, picking the
//! path that maximises output for the requested input amount.  Cost
//! function is FULL OUTPUT, not just summed fees, because two-hop
//! routes through deep reserves can beat single-hop routes through
//! shallow reserves even when total fee_bps is higher (test
//! `multi_hop_beats_direct_when_output_better`).  Pure fee-weighted
//! Dijkstra would silently mis-route in that scenario.
//!
//! Determinism:
//!   * Input ads are pre-deduplicated by (vault_id, highest
//!     state_number, lex-smallest key) — same rule as the storage
//!     selector so the search sees what `routing_sdk::list_*` would
//!     have returned.
//!   * On equal final-output paths, the lex-smaller `Vec<vault_id>`
//!     sequence wins.
//!   * No floating-point arithmetic — all math is `u128` with checked
//!     ops; an arithmetic overflow disqualifies that hop instead of
//!     panicking.

use dsm::types::proto as generated;
use std::collections::HashMap;

use crate::sdk::routing_sdk::{canonical_token_pair, fetch_and_verify_vault_proto, LIFECYCLE_ACTIVE};

/// Default search depth — three intermediate tokens is enough for the
/// liquidity topologies the spec contemplates (§5.1) and keeps the
/// enumeration cost bounded by O(|V|^MAX_HOPS) which is small for
/// realistic vault counts.  Caller can override via `find_best_path`.
pub(crate) const DEFAULT_MAX_HOPS: usize = 4;

/// One hop along a discovered route.  Carries everything chunk #3
/// needs to build the external commitment without re-fetching the
/// advertisement: vault id, the digest the ad was bound by, the
/// state number it was current at, and the policy-anchor placement
/// metadata for re-verification on the receiving end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultHop {
    /// 32-byte vault id.
    pub vault_id: [u8; 32],
    /// Token id consumed at this hop.
    pub token_in: Vec<u8>,
    /// Token id produced at this hop (= input of the next hop, if any).
    pub token_out: Vec<u8>,
    /// Amount of `token_in` flowing into this hop.
    pub input_amount: u128,
    /// Constant-product simulated output (post-fee).
    pub expected_output_amount: u128,
    /// Fee in basis points carried on the advertisement.
    pub fee_bps: u32,
    /// `BLAKE3("DSM/routing-vault-ad", vault_proto_bytes)` from the ad —
    /// downstream chunks bind this into the external commitment so the
    /// recipient can re-verify the proto without re-running BLAKE3 from
    /// scratch.
    pub advertisement_digest: [u8; 32],
    /// Ad's `updated_state_number` at search time.
    pub state_number: u64,
    /// Digest of the CPTA spec describing the vault's unlock condition.
    pub unlock_spec_digest: [u8; 32],
    /// SPHINCS+ pk of the vault owner (needed downstream to compute
    /// the per-hop expected unlock receipt).
    pub owner_public_key: Vec<u8>,
}

/// Concatenated route through one or more vaults.  `final_output_amount`
/// is the simulated amount of `output_token` after walking every hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Path {
    pub input_token: Vec<u8>,
    pub output_token: Vec<u8>,
    pub input_amount: u128,
    pub final_output_amount: u128,
    /// Sum of `fee_bps` across the path.  Informational — the cost
    /// function is `final_output_amount`, not this; downstream callers
    /// may use it for fee disclosures.
    pub total_fee_bps: u64,
    pub hops: Vec<VaultHop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoutingError {
    /// No path exists from `input_token` to `output_token` for the
    /// requested input amount within the search depth.
    NoPath {
        input_token: Vec<u8>,
        output_token: Vec<u8>,
        requested_input: u128,
    },
    /// `input_token == output_token` — caller bug.
    SameToken,
    /// Caller supplied no advertisements to search over.
    EmptyAdvertisementSet,
    /// Caller supplied `input_amount == 0`.
    ZeroInput,
}

/// Constant-product output: `(reserve_out * input_after_fee) /
/// (reserve_in + input_after_fee)`, where `input_after_fee = input *
/// (10000 - fee_bps) / 10000`.  Returns `None` on any overflow or
/// degenerate configuration (zero reserve, zero output).  A `None`
/// disqualifies the hop from the graph rather than panicking — keeps
/// the search safe against adversarial advertisements.
pub(crate) fn constant_product_output(
    input_amount: u128,
    reserve_in: u128,
    reserve_out: u128,
    fee_bps: u32,
) -> Option<u128> {
    if input_amount == 0 || reserve_in == 0 || reserve_out == 0 {
        return None;
    }
    if fee_bps >= 10_000 {
        // Fee >= 100 % is not a real AMM hop; skip rather than divide
        // a positive numerator by zero.
        return None;
    }
    let fee_complement = u128::from(10_000u32 - fee_bps);
    let input_after_fee_num = input_amount.checked_mul(fee_complement)?;
    // `reserve_in * 10000 + input_after_fee_num` (denominator).
    let denom_lhs = reserve_in.checked_mul(10_000)?;
    let denom = denom_lhs.checked_add(input_after_fee_num)?;
    let num = reserve_out.checked_mul(input_after_fee_num)?;
    let out = num / denom;
    if out == 0 {
        None
    } else {
        Some(out)
    }
}

/// Decode `reserve_*_u128` from its big-endian 16-byte wire form.  An
/// ad whose reserve fields are not 16 bytes is silently dropped during
/// graph construction.
fn u128_be(bytes: &[u8]) -> Option<u128> {
    if bytes.len() != 16 {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(bytes);
    Some(u128::from_be_bytes(buf))
}

/// Decode `vault_id` from its 32-byte wire form.
fn vid32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Some(buf)
}

/// Decode `unlock_spec_digest` / `vault_proto_digest` from a 32-byte slice.
fn digest32(bytes: &[u8]) -> Option<[u8; 32]> {
    vid32(bytes)
}

/// Internal edge representation — one ad becomes two directed edges
/// (A→B and B→A) since AMM vaults trade either direction.  `reserve_a`
/// / `reserve_b` are the on-disk lex-canonical reserves; the directed
/// edge swaps roles based on the trade direction it serves.
#[derive(Debug, Clone)]
struct DirectedEdge {
    vault_id: [u8; 32],
    /// Token consumed by this edge.
    token_in: Vec<u8>,
    /// Token produced by this edge.
    token_out: Vec<u8>,
    reserve_in: u128,
    reserve_out: u128,
    fee_bps: u32,
    advertisement_digest: [u8; 32],
    state_number: u64,
    unlock_spec_digest: [u8; 32],
    owner_public_key: Vec<u8>,
}

/// Dedupe by vault_id, keeping the ad with the highest
/// `updated_state_number` (lex-smaller token-pair tiebreaker on equal
/// state numbers — guarantees determinism even with replayed ads).
fn dedupe_by_vault_id(
    ads: &[generated::RoutingVaultAdvertisementV1],
) -> Vec<&generated::RoutingVaultAdvertisementV1> {
    let mut by_vid: HashMap<Vec<u8>, &generated::RoutingVaultAdvertisementV1> = HashMap::new();
    for ad in ads {
        if ad.lifecycle_state != LIFECYCLE_ACTIVE {
            continue;
        }
        if ad.vault_id.is_empty() {
            continue;
        }
        let key = ad.vault_id.clone();
        let replace = match by_vid.get(&key) {
            None => true,
            Some(current) => {
                ad.updated_state_number > current.updated_state_number
                    || (ad.updated_state_number == current.updated_state_number
                        && (ad.token_a.as_slice(), ad.token_b.as_slice())
                            < (current.token_a.as_slice(), current.token_b.as_slice()))
            }
        };
        if replace {
            by_vid.insert(key, ad);
        }
    }
    let mut out: Vec<&generated::RoutingVaultAdvertisementV1> = by_vid.into_values().collect();
    out.sort_by(|a, b| a.vault_id.cmp(&b.vault_id));
    out
}

/// Build the directed-edge adjacency list keyed by `token_in`.  An
/// advertisement whose reserves don't decode is silently dropped.
fn build_adjacency(
    ads: &[&generated::RoutingVaultAdvertisementV1],
) -> HashMap<Vec<u8>, Vec<DirectedEdge>> {
    let mut adj: HashMap<Vec<u8>, Vec<DirectedEdge>> = HashMap::new();
    for ad in ads {
        let vid = match vid32(&ad.vault_id) {
            Some(v) => v,
            None => continue,
        };
        let reserve_a = match u128_be(&ad.reserve_a_u128) {
            Some(v) => v,
            None => continue,
        };
        let reserve_b = match u128_be(&ad.reserve_b_u128) {
            Some(v) => v,
            None => continue,
        };
        let ad_digest = match digest32(&ad.vault_proto_digest) {
            Some(v) => v,
            None => continue,
        };
        let unlock_digest = match digest32(&ad.unlock_spec_digest) {
            Some(v) => v,
            None => continue,
        };

        // Verify the on-disk pair is canonical (lex-sorted).  An ad
        // that violates this invariant is malformed; skip it.
        let (canonical_a, canonical_b) = canonical_token_pair(&ad.token_a, &ad.token_b);
        if canonical_a != ad.token_a.as_slice() || canonical_b != ad.token_b.as_slice() {
            continue;
        }

        // Edge A → B: consume token_a, produce token_b.
        let edge_ab = DirectedEdge {
            vault_id: vid,
            token_in: ad.token_a.clone(),
            token_out: ad.token_b.clone(),
            reserve_in: reserve_a,
            reserve_out: reserve_b,
            fee_bps: ad.fee_bps,
            advertisement_digest: ad_digest,
            state_number: ad.updated_state_number,
            unlock_spec_digest: unlock_digest,
            owner_public_key: ad.owner_public_key.clone(),
        };
        // Edge B → A: consume token_b, produce token_a.
        let edge_ba = DirectedEdge {
            vault_id: vid,
            token_in: ad.token_b.clone(),
            token_out: ad.token_a.clone(),
            reserve_in: reserve_b,
            reserve_out: reserve_a,
            fee_bps: ad.fee_bps,
            advertisement_digest: ad_digest,
            state_number: ad.updated_state_number,
            unlock_spec_digest: unlock_digest,
            owner_public_key: ad.owner_public_key.clone(),
        };
        adj.entry(ad.token_a.clone()).or_default().push(edge_ab);
        adj.entry(ad.token_b.clone()).or_default().push(edge_ba);
    }
    // Sort edges deterministically so DFS visit order is reproducible.
    for edges in adj.values_mut() {
        edges.sort_by(|a, b| {
            a.vault_id
                .cmp(&b.vault_id)
                .then(a.token_out.cmp(&b.token_out))
        });
    }
    adj
}

/// Pure path search over an in-memory advertisement set.  Returns the
/// path that maximises `final_output_amount` for the requested
/// `input_amount`, or a typed `RoutingError` if no path exists.
///
/// The advertisement set is pre-deduplicated by vault_id (highest
/// state_number wins, lex-smaller token pair tiebreaker) and filtered
/// to `lifecycle_state == "active"` before search begins, so the
/// caller may pass raw output from `routing_sdk::load_*`.
pub(crate) fn find_best_path(
    advertisements: &[generated::RoutingVaultAdvertisementV1],
    input_token: &[u8],
    output_token: &[u8],
    input_amount: u128,
    max_hops: usize,
) -> Result<Path, RoutingError> {
    if input_token == output_token {
        return Err(RoutingError::SameToken);
    }
    if input_amount == 0 {
        return Err(RoutingError::ZeroInput);
    }
    if advertisements.is_empty() {
        return Err(RoutingError::EmptyAdvertisementSet);
    }
    let max_hops = max_hops.max(1);

    let deduped = dedupe_by_vault_id(advertisements);
    let adjacency = build_adjacency(&deduped);

    let mut best: Option<Path> = None;
    let mut visited_tokens: Vec<Vec<u8>> = vec![input_token.to_vec()];
    let mut current_hops: Vec<VaultHop> = Vec::new();

    enumerate(
        input_token,
        output_token,
        input_amount,
        &adjacency,
        max_hops,
        &mut visited_tokens,
        &mut current_hops,
        &mut best,
    );

    best.ok_or_else(|| RoutingError::NoPath {
        input_token: input_token.to_vec(),
        output_token: output_token.to_vec(),
        requested_input: input_amount,
    })
}

#[allow(clippy::too_many_arguments)]
fn enumerate(
    current_token: &[u8],
    output_token: &[u8],
    current_input_amount: u128,
    adjacency: &HashMap<Vec<u8>, Vec<DirectedEdge>>,
    remaining_hops: usize,
    visited_tokens: &mut Vec<Vec<u8>>,
    current_hops: &mut Vec<VaultHop>,
    best: &mut Option<Path>,
) {
    if remaining_hops == 0 {
        return;
    }
    let edges = match adjacency.get(current_token) {
        Some(v) => v,
        None => return,
    };
    for edge in edges {
        if visited_tokens.iter().any(|t| t == &edge.token_out) {
            continue; // cycle guard
        }
        let output = match constant_product_output(
            current_input_amount,
            edge.reserve_in,
            edge.reserve_out,
            edge.fee_bps,
        ) {
            Some(v) => v,
            None => continue, // overflow / insufficient reserves
        };

        let hop = VaultHop {
            vault_id: edge.vault_id,
            token_in: edge.token_in.clone(),
            token_out: edge.token_out.clone(),
            input_amount: current_input_amount,
            expected_output_amount: output,
            fee_bps: edge.fee_bps,
            advertisement_digest: edge.advertisement_digest,
            state_number: edge.state_number,
            unlock_spec_digest: edge.unlock_spec_digest,
            owner_public_key: edge.owner_public_key.clone(),
        };

        current_hops.push(hop);
        visited_tokens.push(edge.token_out.clone());

        if edge.token_out == output_token {
            // Complete path candidate.
            let total_fee_bps: u64 = current_hops.iter().map(|h| u64::from(h.fee_bps)).sum();
            let candidate = Path {
                input_token: visited_tokens.first().cloned().unwrap_or_default(),
                output_token: output_token.to_vec(),
                input_amount: current_hops.first().map(|h| h.input_amount).unwrap_or(0),
                final_output_amount: output,
                total_fee_bps,
                hops: current_hops.clone(),
            };
            replace_if_better(best, candidate);
        } else {
            enumerate(
                &edge.token_out,
                output_token,
                output,
                adjacency,
                remaining_hops - 1,
                visited_tokens,
                current_hops,
                best,
            );
        }

        current_hops.pop();
        visited_tokens.pop();
    }
}

fn replace_if_better(best: &mut Option<Path>, candidate: Path) {
    let take = match best {
        None => true,
        Some(current) => {
            if candidate.final_output_amount > current.final_output_amount {
                true
            } else if candidate.final_output_amount < current.final_output_amount {
                false
            } else {
                // Equal output — deterministic tie-break on the lex-
                // smaller vault_id sequence.
                let cand_seq: Vec<&[u8]> = candidate
                    .hops
                    .iter()
                    .map(|h| h.vault_id.as_slice())
                    .collect();
                let cur_seq: Vec<&[u8]> =
                    current.hops.iter().map(|h| h.vault_id.as_slice()).collect();
                cand_seq < cur_seq
            }
        }
    };
    if take {
        *best = Some(candidate);
    }
}

/// Storage-verified wrapper.  Fetches each advertisement's full vault
/// proto, runs the digest binding check, and only feeds surviving ads
/// into the path search.  An ad whose proto fails verification is
/// silently dropped (with a log warning) — the search proceeds with
/// what's left.
///
/// Use this from production callers; tests that need to assert on the
/// pure search semantics call `find_best_path` directly.
pub(crate) async fn find_and_verify_best_path(
    advertisements: &[generated::RoutingVaultAdvertisementV1],
    input_token: &[u8],
    output_token: &[u8],
    input_amount: u128,
    max_hops: usize,
) -> Result<Path, RoutingError> {
    let mut verified: Vec<generated::RoutingVaultAdvertisementV1> = Vec::new();
    for ad in advertisements {
        match fetch_and_verify_vault_proto(ad).await {
            Ok(_) => verified.push(ad.clone()),
            Err(e) => {
                let vid_b32 = if ad.vault_id.is_empty() {
                    "<empty>".to_string()
                } else {
                    crate::util::text_id::encode_base32_crockford(&ad.vault_id)
                };
                log::warn!("[routing.path] excluding {vid_b32}: digest verify failed: {e}");
            }
        }
    }
    find_best_path(&verified, input_token, output_token, input_amount, max_hops)
}

#[cfg(test)]
mod tests {
    //! Path-search tests.  All eight scenarios from the chunk-#2
    //! checklist exercised here, plus a constant-product unit test
    //! that nails the simulation math.

    use super::*;
    use crate::sdk::routing_sdk::{
        publish_active_advertisement, PublishRoutingAdInput, ROUTING_VAULT_AD_DOMAIN,
    };

    fn token(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn vid(tag: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = tag;
        v[31] = tag.wrapping_mul(13).wrapping_add(7);
        v
    }

    fn u128_be_arr(n: u128) -> [u8; 16] {
        n.to_be_bytes()
    }

    /// Construct a synthetic ad in canonical form.  Tests that need a
    /// non-canonical ad construct it manually.
    fn ad(
        vault_id: [u8; 32],
        token_lower: &[u8],
        token_higher: &[u8],
        reserve_lower: u128,
        reserve_higher: u128,
        fee_bps: u32,
        state_number: u64,
    ) -> generated::RoutingVaultAdvertisementV1 {
        let (a, b) = canonical_token_pair(token_lower, token_higher);
        let (ra, rb) = if a == token_lower {
            (reserve_lower, reserve_higher)
        } else {
            (reserve_higher, reserve_lower)
        };
        // Synthesise a plausible vault proto so digest binding works
        // for tests that pipe through `find_and_verify_best_path`.
        let proto_bytes: Vec<u8> = {
            let mut v = vault_id.to_vec();
            v.extend_from_slice(token_lower);
            v.extend_from_slice(token_higher);
            v.push(fee_bps as u8);
            v.push(state_number as u8);
            v
        };
        let digest = dsm::crypto::blake3::domain_hash_bytes(ROUTING_VAULT_AD_DOMAIN, &proto_bytes);
        generated::RoutingVaultAdvertisementV1 {
            version: 1,
            vault_id: vault_id.to_vec(),
            token_a: a.to_vec(),
            token_b: b.to_vec(),
            reserve_a_u128: u128_be_arr(ra).to_vec(),
            reserve_b_u128: u128_be_arr(rb).to_vec(),
            fee_bps,
            unlock_spec_digest: vec![0u8; 32],
            unlock_spec_key: "defi/spec/test".into(),
            vault_proto_key: format!("defi/vault-proto/test/{:x?}", &vault_id[..4]).into_bytes(),
            vault_proto_digest: digest.to_vec(),
            owner_public_key: vec![0xABu8; 64],
            lifecycle_state: LIFECYCLE_ACTIVE.to_string(),
            updated_state_number: state_number,
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Constant-product math (foundation for everything else)
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn constant_product_basic_swap() {
        // Reserves 1_000_000 / 1_000_000, swap 10_000 in at 30 bps.
        // input_after_fee = 10_000 * 9970 / 10000 = 9970
        // output = 1_000_000 * 9970 / (1_000_000 + 9970) = ~9871
        let out =
            constant_product_output(10_000, 1_000_000, 1_000_000, 30).expect("non-zero output");
        assert!(out > 9000 && out < 10_000, "got {out}");
        assert!(
            out < 10_000,
            "AMM must produce strictly less than 1:1 due to fee + slippage"
        );
    }

    #[test]
    fn constant_product_zero_reserve_excluded() {
        assert_eq!(constant_product_output(100, 0, 1000, 30), None);
        assert_eq!(constant_product_output(100, 1000, 0, 30), None);
    }

    #[test]
    fn constant_product_overflow_disqualifies_hop() {
        // Reserves at u128::MAX would overflow `reserve_in * 10000`.
        assert_eq!(constant_product_output(1, u128::MAX, u128::MAX, 30), None);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 1: A/B and B/A canonical pair equivalence
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn ab_and_ba_search_yield_symmetric_paths_through_same_vault() {
        let a = token("AAA");
        let b = token("BBB");
        let v = vid(1);
        let ads = vec![ad(v, &a, &b, 1_000_000, 1_000_000, 30, 1)];

        let ab = find_best_path(&ads, &a, &b, 10_000, DEFAULT_MAX_HOPS).expect("AB path");
        let ba = find_best_path(&ads, &b, &a, 10_000, DEFAULT_MAX_HOPS).expect("BA path");

        assert_eq!(ab.hops.len(), 1);
        assert_eq!(ba.hops.len(), 1);
        assert_eq!(ab.hops[0].vault_id, v);
        assert_eq!(ba.hops[0].vault_id, v);
        // Token roles flip; vault is the same.
        assert_eq!(ab.hops[0].token_in, a);
        assert_eq!(ab.hops[0].token_out, b);
        assert_eq!(ba.hops[0].token_in, b);
        assert_eq!(ba.hops[0].token_out, a);
        // Symmetric reserves → equal expected output (math symmetric).
        assert_eq!(ab.final_output_amount, ba.final_output_amount);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 2: Dedup keeps highest valid state number
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn dedup_uses_highest_state_number() {
        let a = token("AAA");
        let b = token("BBB");
        let v = vid(2);
        // Old ad with deep reserves but low state number.
        let stale = ad(v, &a, &b, 10_000_000, 10_000_000, 30, 1);
        // Fresh ad with shallow reserves but newer state number — newer
        // wins regardless of fee / reserves.
        let fresh = ad(v, &a, &b, 100_000, 100_000, 30, 99);
        let path = find_best_path(&[stale, fresh], &a, &b, 10_000, DEFAULT_MAX_HOPS).expect("path");
        assert_eq!(path.hops[0].state_number, 99);
        // Output reflects the FRESH (shallow) reserves, not the stale ones.
        let stale_only = vec![ad(v, &a, &b, 10_000_000, 10_000_000, 30, 1)];
        let stale_path =
            find_best_path(&stale_only, &a, &b, 10_000, DEFAULT_MAX_HOPS).expect("stale-only path");
        assert!(
            path.final_output_amount < stale_path.final_output_amount,
            "fresh shallow ad must produce LESS output than stale deep ad — \
             confirms dedup honoured the newer state number"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 3: Insufficient reserves excluded
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn insufficient_reserves_excluded_from_graph() {
        let a = token("AAA");
        let b = token("BBB");
        // Vault with reserves so tiny the input_amount produces zero
        // output (rounding to 0 in integer math).  Should be excluded
        // from the graph; search returns NoPath.
        let degenerate = ad(vid(3), &a, &b, 1, 1, 30, 1);
        let err = find_best_path(&[degenerate], &a, &b, 1_000_000, DEFAULT_MAX_HOPS)
            .expect_err("dust reserves must yield NoPath");
        match err {
            RoutingError::NoPath { .. } => {}
            other => panic!("expected NoPath, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 4: Invalid digest excluded from graph (storage-verified path)
    // ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn invalid_digest_excluded_from_verified_search() {
        let a = token("AAAd1");
        let b = token("BBBd1");
        let good_vid = vid(40);
        let bad_vid = vid(41);

        // Publish two ads through the storage substrate so digest
        // verification has real proto bytes to fetch.
        let good_proto = b"good-vault-proto-bytes".to_vec();
        let bad_proto = b"bad-vault-proto-bytes".to_vec();

        publish_active_advertisement(PublishRoutingAdInput {
            vault_id: &good_vid,
            token_a: &a,
            token_b: &b,
            reserve_a_u128: u128_be_arr(1_000_000),
            reserve_b_u128: u128_be_arr(1_000_000),
            fee_bps: 30,
            unlock_spec_digest: [0u8; 32],
            unlock_spec_key: "defi/spec/good".into(),
            owner_public_key: &[0xABu8; 64],
            vault_proto_bytes: &good_proto,
        })
        .await
        .expect("publish good");
        publish_active_advertisement(PublishRoutingAdInput {
            vault_id: &bad_vid,
            token_a: &a,
            token_b: &b,
            reserve_a_u128: u128_be_arr(1_000_000),
            reserve_b_u128: u128_be_arr(1_000_000),
            fee_bps: 5, // would otherwise win on fee
            unlock_spec_digest: [0u8; 32],
            unlock_spec_key: "defi/spec/bad".into(),
            owner_public_key: &[0xABu8; 64],
            vault_proto_bytes: &bad_proto,
        })
        .await
        .expect("publish bad");

        // Tamper with the bad ad's proto mirror so its digest no longer
        // binds.  The verified-path wrapper must drop it.
        let bad_proto_key = crate::sdk::routing_sdk::proto_key(&a, &b, &bad_vid);
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(
            &bad_proto_key,
            b"tampered-bytes",
        )
        .await
        .expect("tamper");

        let ads = crate::sdk::routing_sdk::load_active_advertisements_for_pair(&a, &b)
            .await
            .expect("list ads");
        let just_ads: Vec<_> = ads.into_iter().map(|p| p.advertisement).collect();
        let path = find_and_verify_best_path(&just_ads, &a, &b, 10_000, DEFAULT_MAX_HOPS)
            .await
            .expect("path");
        assert_eq!(
            path.hops[0].vault_id, good_vid,
            "tampered ad must be excluded; the surviving ad is the only choice"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 5: Fee weighting chooses cheaper path (when reserves equal)
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn lower_fee_wins_when_reserves_match() {
        let a = token("AAA");
        let b = token("BBB");
        let cheap = ad(vid(50), &a, &b, 1_000_000, 1_000_000, 5, 1);
        let pricey = ad(vid(51), &a, &b, 1_000_000, 1_000_000, 100, 1);
        let path =
            find_best_path(&[cheap, pricey], &a, &b, 10_000, DEFAULT_MAX_HOPS).expect("path");
        assert_eq!(path.hops[0].vault_id, vid(50), "cheap fee must win");
        assert_eq!(path.hops[0].fee_bps, 5);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 6: Multi-hop beats direct path when output is better
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn multi_hop_beats_direct_when_output_better() {
        let a = token("AAA");
        let b = token("BBB");
        let c = token("CCC");

        // Direct A→B with shallow reserves and low fee.
        let direct = ad(vid(60), &a, &b, 50_000, 50_000, 5, 1);
        // Two-hop A→C→B with DEEP reserves and higher fees.
        let leg_ac = ad(vid(61), &a, &c, 10_000_000, 10_000_000, 30, 1);
        let leg_cb = ad(vid(62), &c, &b, 10_000_000, 10_000_000, 30, 1);

        let path = find_best_path(&[direct, leg_ac, leg_cb], &a, &b, 100_000, DEFAULT_MAX_HOPS)
            .expect("path");
        assert_eq!(
            path.hops.len(),
            2,
            "multi-hop A→C→B must beat shallow direct A→B for a 100k-input swap"
        );
        // First hop A→C, second hop C→B.
        assert_eq!(path.hops[0].token_in, a);
        assert_eq!(path.hops[0].token_out, c);
        assert_eq!(path.hops[1].token_in, c);
        assert_eq!(path.hops[1].token_out, b);
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 7: No path returns typed failure, not panic
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn no_path_returns_typed_failure() {
        let a = token("AAA");
        let b = token("BBB");
        let c = token("CCC");
        // Only an A→B vault exists; ask for A→C.
        let unrelated = ad(vid(70), &a, &b, 1_000_000, 1_000_000, 30, 1);
        let err = find_best_path(&[unrelated], &a, &c, 10_000, DEFAULT_MAX_HOPS)
            .expect_err("no A→C path");
        match err {
            RoutingError::NoPath {
                input_token,
                output_token,
                requested_input,
            } => {
                assert_eq!(input_token, a);
                assert_eq!(output_token, c);
                assert_eq!(requested_input, 10_000);
            }
            other => panic!("expected NoPath, got {other:?}"),
        }
    }

    #[test]
    fn empty_advertisement_set_is_typed() {
        let a = token("AAA");
        let b = token("BBB");
        match find_best_path(&[], &a, &b, 100, DEFAULT_MAX_HOPS) {
            Err(RoutingError::EmptyAdvertisementSet) => {}
            other => panic!("expected EmptyAdvertisementSet, got {other:?}"),
        }
    }

    #[test]
    fn same_token_request_is_typed() {
        let a = token("AAA");
        let b = token("BBB");
        let v = ad(vid(99), &a, &b, 1_000_000, 1_000_000, 30, 1);
        match find_best_path(&[v], &a, &a, 100, DEFAULT_MAX_HOPS) {
            Err(RoutingError::SameToken) => {}
            other => panic!("expected SameToken, got {other:?}"),
        }
    }

    #[test]
    fn zero_input_is_typed() {
        let a = token("AAA");
        let b = token("BBB");
        let v = ad(vid(98), &a, &b, 1_000_000, 1_000_000, 30, 1);
        match find_best_path(&[v], &a, &b, 0, DEFAULT_MAX_HOPS) {
            Err(RoutingError::ZeroInput) => {}
            other => panic!("expected ZeroInput, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Test 8: Deterministic tie-break on equal-cost routes
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn equal_output_paths_lex_smallest_vault_sequence_wins() {
        let a = token("AAA");
        let b = token("BBB");
        // Two identical vaults — same reserves, same fee, different
        // vault_ids.  The lex-smaller vault_id must be selected
        // deterministically across runs.
        let v_low = vid(0x10);
        let v_high = vid(0x80);
        let ad_low = ad(v_low, &a, &b, 1_000_000, 1_000_000, 30, 1);
        let ad_high = ad(v_high, &a, &b, 1_000_000, 1_000_000, 30, 1);

        // Run twice in different orders — same answer either way.
        let p1 = find_best_path(
            &[ad_low.clone(), ad_high.clone()],
            &a,
            &b,
            10_000,
            DEFAULT_MAX_HOPS,
        )
        .expect("p1");
        let p2 = find_best_path(&[ad_high, ad_low], &a, &b, 10_000, DEFAULT_MAX_HOPS).expect("p2");
        assert_eq!(p1.hops[0].vault_id, v_low);
        assert_eq!(p2.hops[0].vault_id, v_low);
    }
}
