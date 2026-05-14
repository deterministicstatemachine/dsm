// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi routing-vault discovery substrate.
//!
//! Public discovery by ordered token pair: vaults are advertised at
//! `defi/vault/{token_a_b32}/{token_b_b32}/{vault_id_b32}` and their
//! full proto mirrored at `defi/vault-proto/{..}/{..}/{..}`.  Routers
//! enumerate the prefix for the (canonical) trade pair, fetch + verify
//! each vault, then feed the surviving set into a fee-weighted
//! shortest-path search (SoFi spec §3.3, §8.3).  This module owns the
//! discovery substrate ONLY — the path search and the RouteCommit
//! emission live in subsequent commits on the same SoFi-routing track.
//!
//! Pattern matches `bitcoin_tap_sdk` / `posted_dlv_sdk` one-for-one
//! (publish → list with state-number dedup → delete).  Substantive
//! differences:
//!   * Keyspace is the **token pair** (`tokenA`, `tokenB` in lex order),
//!     not a recipient PK or a manifold policy commit.
//!   * Listing always returns the full pair set; filtering by
//!     direction (A→B vs B→A) is the caller's concern — the proto
//!     stores reserves in canonical order, the path search swaps
//!     them based on requested direction.
//!   * No "claimed" lifecycle state — SoFi vaults are continuously
//!     usable until exhausted (reserves drained) or withdrawn
//!     (owner-initiated).

use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;

/// BLAKE3 domain tag binding the advertisement to the full vault proto.
pub(crate) const ROUTING_VAULT_AD_DOMAIN: &str = "DSM/routing-vault-ad";

/// Base prefix for routing-vault advertisements.
pub(crate) const ROUTING_VAULT_AD_ROOT: &str = "defi/vault/";

/// Base prefix for routing-vault full proto mirrors.
pub(crate) const ROUTING_VAULT_PROTO_ROOT: &str = "defi/vault-proto/";

pub(crate) const LIFECYCLE_ACTIVE: &str = "active";
pub(crate) const LIFECYCLE_EXHAUSTED: &str = "exhausted";
pub(crate) const LIFECYCLE_WITHDRAWN: &str = "withdrawn";

/// Compare two token-id byte slices and return `(lower, higher)` in
/// canonical lex order.  Token IDs in SoFi adverts MUST be sorted
/// — otherwise two advertisements for the same pair would split into
/// distinct prefixes and the router would only see half the liquidity.
pub(crate) fn canonical_token_pair<'a>(a: &'a [u8], b: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Storage-node key for an advertisement keyed by (canonical pair, vault_id).
pub(crate) fn advertisement_key(token_a: &[u8], token_b: &[u8], vault_id: &[u8; 32]) -> String {
    let (lower, higher) = canonical_token_pair(token_a, token_b);
    format!(
        "{prefix}{a}/{b}/{id}",
        prefix = ROUTING_VAULT_AD_ROOT,
        a = encode_base32_crockford(lower),
        b = encode_base32_crockford(higher),
        id = encode_base32_crockford(vault_id),
    )
}

/// Storage-node key for the full vault proto mirror.
pub(crate) fn proto_key(token_a: &[u8], token_b: &[u8], vault_id: &[u8; 32]) -> String {
    let (lower, higher) = canonical_token_pair(token_a, token_b);
    format!(
        "{prefix}{a}/{b}/{id}",
        prefix = ROUTING_VAULT_PROTO_ROOT,
        a = encode_base32_crockford(lower),
        b = encode_base32_crockford(higher),
        id = encode_base32_crockford(vault_id),
    )
}

/// Listing prefix for a canonical token pair.  Routers walk this to
/// enumerate all advertised vaults trading the pair.
pub(crate) fn advertisement_prefix_for_pair(token_a: &[u8], token_b: &[u8]) -> String {
    let (lower, higher) = canonical_token_pair(token_a, token_b);
    format!(
        "{prefix}{a}/{b}/",
        prefix = ROUTING_VAULT_AD_ROOT,
        a = encode_base32_crockford(lower),
        b = encode_base32_crockford(higher),
    )
}

/// Inputs for `publish_active_advertisement` — keeps the call surface
/// narrow so all dBTC / posted-DLV / routing publish paths share the
/// same shape (proto-key + ad-key + digest binding).
pub(crate) struct PublishRoutingAdInput<'a> {
    pub vault_id: &'a [u8; 32],
    pub token_a: &'a [u8],
    pub token_b: &'a [u8],
    pub reserve_a_u128: [u8; 16],
    pub reserve_b_u128: [u8; 16],
    pub fee_bps: u32,
    pub unlock_spec_digest: [u8; 32],
    pub unlock_spec_key: String,
    pub owner_public_key: &'a [u8],
    pub vault_proto_bytes: &'a [u8],
}

/// Publish an active-state advertisement + the full vault proto mirror.
///
/// Token pair is canonicalised (lex-sorted) before key construction; the
/// caller may pass `(tokenA, tokenB)` or `(tokenB, tokenA)` and end up at
/// the same key.  Reserves flow with the input order — they are written
/// into `reserve_a_u128` / `reserve_b_u128` AS THE CALLER INTENDED for
/// the lex-lower / lex-higher token, so a caller that supplied them in
/// reverse order would publish a misleading advertisement.  Helpers
/// further down the stack should normalise both at the same site.
pub(crate) async fn publish_active_advertisement(
    input: PublishRoutingAdInput<'_>,
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(input.token_a, input.token_b, input.vault_id);
    let proto_key_str = proto_key(input.token_a, input.token_b, input.vault_id);

    let digest: [u8; 32] =
        dsm::crypto::blake3::domain_hash_bytes(ROUTING_VAULT_AD_DOMAIN, input.vault_proto_bytes);

    // Canonicalise token-id ordering once so on-disk reserve_a / reserve_b
    // always describe the LEX-LOWER / LEX-HIGHER token, not whichever
    // direction the caller happened to pass.
    let (canonical_a, canonical_b) = canonical_token_pair(input.token_a, input.token_b);
    let (reserve_a, reserve_b) = if canonical_a == input.token_a {
        (input.reserve_a_u128, input.reserve_b_u128)
    } else {
        (input.reserve_b_u128, input.reserve_a_u128)
    };

    let ad = generated::RoutingVaultAdvertisementV1 {
        version: 1,
        vault_id: input.vault_id.to_vec(),
        token_a: canonical_a.to_vec(),
        token_b: canonical_b.to_vec(),
        reserve_a_u128: reserve_a.to_vec(),
        reserve_b_u128: reserve_b.to_vec(),
        fee_bps: input.fee_bps,
        unlock_spec_digest: input.unlock_spec_digest.to_vec(),
        unlock_spec_key: input.unlock_spec_key,
        vault_proto_key: proto_key_str.as_bytes().to_vec(),
        vault_proto_digest: digest.to_vec(),
        owner_public_key: input.owner_public_key.to_vec(),
        lifecycle_state: LIFECYCLE_ACTIVE.to_string(),
        updated_state_number: 1,
    };

    BitcoinTapSdk::storage_put_bytes(&proto_key_str, input.vault_proto_bytes).await?;
    BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
    Ok(())
}

/// Transition an existing advertisement to a terminal lifecycle state
/// (e.g. "exhausted" when reserves are drained, "withdrawn" when the
/// owner pulls liquidity).  Increments `updated_state_number` so the
/// dedup rule supersedes the active form.
pub(crate) async fn publish_terminal_state(
    token_a: &[u8],
    token_b: &[u8],
    vault_id: &[u8; 32],
    terminal_state: &str,
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(token_a, token_b, vault_id);
    let ad_bytes = BitcoinTapSdk::storage_get_bytes(&ad_key).await?;
    let mut ad =
        generated::RoutingVaultAdvertisementV1::decode(ad_bytes.as_slice()).map_err(|e| {
            dsm::types::error::DsmError::serialization_error(
                "RoutingVaultAdvertisementV1",
                "decode",
                Some(ad_key.clone()),
                Some(e),
            )
        })?;
    ad.lifecycle_state = terminal_state.to_string();
    ad.updated_state_number = ad.updated_state_number.saturating_add(1);
    BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
    Ok(())
}

/// Republish an existing routing-vault advertisement with new reserves
/// after a settled swap.  Reads the current ad from storage, updates
/// `reserve_a_u128` / `reserve_b_u128` to the post-trade values,
/// increments `updated_state_number` so the dedup rule supersedes the
/// pre-trade form, and writes back to the same key.  All other fields
/// (vault_id, token pair, fee_bps, vault_proto_key, vault_proto_digest,
/// owner_public_key, lifecycle_state, unlock_spec_*) are preserved
/// verbatim — the swap moves reserves, not vault identity.
///
/// Reserves are accepted in CANONICAL pair order: `new_reserve_a` is
/// the new pool of `token_a` (lex-lower), `new_reserve_b` is the pool
/// of `token_b`.  The caller (chunk #7 unlock handler) is responsible
/// for mapping its hop-direction `(reserve_in, reserve_out)` back to
/// canonical order before calling.
///
/// Best-effort failure mode: an absent advertisement (vault never
/// advertised, or the owner withdrew it) returns `Err` — caller logs
/// and continues; the post-trade vault state is already on-chain.
pub(crate) async fn republish_active_advertisement_with_reserves(
    token_a: &[u8],
    token_b: &[u8],
    vault_id: &[u8; 32],
    new_reserve_a: u128,
    new_reserve_b: u128,
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(token_a, token_b, vault_id);
    let ad_bytes = BitcoinTapSdk::storage_get_bytes(&ad_key).await?;
    let mut ad =
        generated::RoutingVaultAdvertisementV1::decode(ad_bytes.as_slice()).map_err(|e| {
            dsm::types::error::DsmError::serialization_error(
                "RoutingVaultAdvertisementV1",
                "decode",
                Some(ad_key.clone()),
                Some(e),
            )
        })?;
    ad.reserve_a_u128 = new_reserve_a.to_be_bytes().to_vec();
    ad.reserve_b_u128 = new_reserve_b.to_be_bytes().to_vec();
    ad.updated_state_number = ad.updated_state_number.saturating_add(1);
    BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct PublishedRoutingAdvertisement {
    pub key: String,
    pub advertisement: generated::RoutingVaultAdvertisementV1,
}

/// List active advertisements for a token pair.  Both `(tokenA, tokenB)`
/// and `(tokenB, tokenA)` resolve to the same canonical prefix.
pub(crate) async fn load_active_advertisements_for_pair(
    token_a: &[u8],
    token_b: &[u8],
) -> Result<Vec<PublishedRoutingAdvertisement>, dsm::types::error::DsmError> {
    let all = load_all_advertisements_for_pair(token_a, token_b).await?;
    Ok(all
        .into_iter()
        .filter(|p| p.advertisement.lifecycle_state == LIFECYCLE_ACTIVE)
        .collect())
}

/// List ALL advertisements for a token pair regardless of lifecycle
/// state.  Useful for owner-side cleanup / audit; routers should
/// prefer the active filter.
pub(crate) async fn load_all_advertisements_for_pair(
    token_a: &[u8],
    token_b: &[u8],
) -> Result<Vec<PublishedRoutingAdvertisement>, dsm::types::error::DsmError> {
    use std::collections::HashMap;
    const LIST_LIMIT: u32 = 200;

    let prefix = advertisement_prefix_for_pair(token_a, token_b);
    let mut cursor: Option<String> = None;
    let mut fetched: Vec<PublishedRoutingAdvertisement> = Vec::new();

    loop {
        let resp =
            BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), LIST_LIMIT).await?;
        let page_len = resp.items.len();
        for item in resp.items {
            let payload = match BitcoinTapSdk::storage_get_bytes(&item.key).await {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("[routing.list] skipping {}: fetch failed: {e}", &item.key);
                    continue;
                }
            };
            let advertisement =
                match generated::RoutingVaultAdvertisementV1::decode(payload.as_slice()) {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!("[routing.list] skipping {}: decode failed: {e}", &item.key);
                        continue;
                    }
                };
            fetched.push(PublishedRoutingAdvertisement {
                key: item.key,
                advertisement,
            });
        }
        if page_len < LIST_LIMIT as usize {
            break;
        }
        cursor = resp.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    fetched.sort_by(|left, right| left.key.cmp(&right.key));
    let mut deduped: HashMap<Vec<u8>, PublishedRoutingAdvertisement> = HashMap::new();
    for entry in fetched {
        let dedupe_key = if entry.advertisement.vault_id.is_empty() {
            entry.key.as_bytes().to_vec()
        } else {
            entry.advertisement.vault_id.clone()
        };
        let replace = match deduped.get(&dedupe_key) {
            None => true,
            Some(current) => {
                entry.advertisement.updated_state_number
                    > current.advertisement.updated_state_number
                    || (entry.advertisement.updated_state_number
                        == current.advertisement.updated_state_number
                        && entry.key < current.key)
            }
        };
        if replace {
            deduped.insert(dedupe_key, entry);
        }
    }

    let mut out: Vec<PublishedRoutingAdvertisement> = deduped.into_values().collect();
    out.sort_by(|left, right| {
        left.advertisement
            .vault_id
            .cmp(&right.advertisement.vault_id)
            .then(left.key.cmp(&right.key))
    });
    Ok(out)
}

/// Fetch the full vault proto referenced by an advertisement and verify
/// the digest binding matches.  Caller is expected to feed the returned
/// proto into vault-specific verification (CPTA spec, ownership, …) —
/// this helper only proves the storage-side binding holds.
pub(crate) async fn fetch_and_verify_vault_proto(
    ad: &generated::RoutingVaultAdvertisementV1,
) -> Result<Vec<u8>, dsm::types::error::DsmError> {
    let proto_key_str = std::str::from_utf8(&ad.vault_proto_key).map_err(|_| {
        dsm::types::error::DsmError::invalid_operation(
            "routing-vault advertisement vault_proto_key is not valid UTF-8",
        )
    })?;
    if proto_key_str.trim().is_empty() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "routing-vault advertisement missing vault_proto_key",
        ));
    }
    if ad.vault_proto_digest.len() != 32 {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "routing-vault advertisement vault_proto_digest must be 32 bytes",
        ));
    }
    let payload = BitcoinTapSdk::storage_get_bytes(proto_key_str).await?;
    let digest = dsm::crypto::blake3::domain_hash_bytes(ROUTING_VAULT_AD_DOMAIN, &payload);
    if digest.as_slice() != ad.vault_proto_digest.as_slice() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "routing-vault advertisement proto digest mismatch",
        ));
    }
    Ok(payload)
}

/// Best-effort delete of an advertisement + its proto mirror.  A stale
/// "withdrawn" ad is filtered out by `load_active_advertisements_for_pair`
/// so failure here just leaves garbage that the storage TTL collects.
pub(crate) async fn delete_routing_advertisement(
    token_a: &[u8],
    token_b: &[u8],
    vault_id: &[u8; 32],
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(token_a, token_b, vault_id);
    let proto_key_str = proto_key(token_a, token_b, vault_id);
    if let Err(e) = BitcoinTapSdk::storage_delete_key(&ad_key).await {
        log::warn!("[routing.prune] delete ad {ad_key} failed: {e}");
    }
    if let Err(e) = BitcoinTapSdk::storage_delete_key(&proto_key_str).await {
        log::warn!("[routing.prune] delete proto {proto_key_str} failed: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! SoFi routing-vault discovery tests.
    //!
    //! Exercises publish → list → verify → terminal-state → delete on
    //! the same in-process mock backend used by `bitcoin_tap_sdk` and
    //! `posted_dlv_sdk` (`DBTC_STORAGE_TEST_STATE`).  The mock is a
    //! flat `HashMap<String, Vec<u8>>` so multiple suites in one binary
    //! coexist as long as their keyspaces stay distinct — the
    //! `defi/vault/...` prefix used here is unique to this module.
    //!
    //! Each test uses unique token-id / vault-id pairs so suites do
    //! not poison each other.

    use super::*;
    use prost::Message;

    fn token(tag: u8) -> Vec<u8> {
        format!("TKN-{tag:02X}").into_bytes()
    }

    fn vid(tag: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = tag;
        v[31] = tag.wrapping_mul(7).wrapping_add(11);
        v
    }

    fn fake_vault_proto_bytes(tag: u8) -> Vec<u8> {
        // Routing tests don't validate inner LimboVault semantics — the
        // discovery substrate only proves the digest binding holds.
        // Caller-side LimboVault verification lives in `dlv_routes`.
        let mut out = vec![0xCAu8, 0xFE, 0xBA, 0xBE];
        out.push(tag);
        out
    }

    fn u128_be(n: u128) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in (0..16).rev() {
            out[i] = (n >> ((15 - i) * 8)) as u8;
        }
        out
    }

    async fn publish_simple(
        tag: u8,
        token_a: &[u8],
        token_b: &[u8],
        vault_id: &[u8; 32],
        reserve_a: u128,
        reserve_b: u128,
    ) -> Vec<u8> {
        let proto = fake_vault_proto_bytes(tag);
        publish_active_advertisement(PublishRoutingAdInput {
            vault_id,
            token_a,
            token_b,
            reserve_a_u128: u128_be(reserve_a),
            reserve_b_u128: u128_be(reserve_b),
            fee_bps: 30,
            unlock_spec_digest: [0u8; 32],
            unlock_spec_key: "defi/spec/test".to_string(),
            owner_public_key: &[0xABu8; 64],
            vault_proto_bytes: &proto,
        })
        .await
        .expect("publish_active_advertisement");
        proto
    }

    #[tokio::test]
    async fn lists_advertisements_for_pair_in_either_order() {
        let token_a = token(0xA0);
        let token_b = token(0xB0);
        let v1 = vid(0x01);
        publish_simple(0x01, &token_a, &token_b, &v1, 1_000, 2_000).await;

        // Forward order
        let forward = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list forward");
        assert!(
            forward
                .iter()
                .any(|p| p.advertisement.vault_id == v1.to_vec()),
            "forward listing must include published ad"
        );

        // Reverse order resolves to the same canonical prefix.
        let reverse = load_active_advertisements_for_pair(&token_b, &token_a)
            .await
            .expect("list reverse");
        let forward_ids: Vec<_> = forward
            .iter()
            .map(|p| p.advertisement.vault_id.clone())
            .collect();
        let reverse_ids: Vec<_> = reverse
            .iter()
            .map(|p| p.advertisement.vault_id.clone())
            .collect();
        assert_eq!(
            forward_ids, reverse_ids,
            "(A,B) and (B,A) must list the same canonical set"
        );
    }

    #[tokio::test]
    async fn reserves_canonicalise_to_lex_lower_token() {
        // tokens(0x01) < tokens(0xFE) lexicographically (string compare).
        let lower = token(0x01);
        let higher = token(0xFE);
        let vault_id = vid(0x02);

        // Caller passes (higher, lower) with reserves intended that way —
        // canonicalisation must FLIP reserves so the on-disk reserve_a
        // describes the lex-lower token.
        publish_active_advertisement(PublishRoutingAdInput {
            vault_id: &vault_id,
            token_a: &higher,
            token_b: &lower,
            reserve_a_u128: u128_be(7_000), // intended for `higher`
            reserve_b_u128: u128_be(3_000), // intended for `lower`
            fee_bps: 25,
            unlock_spec_digest: [0u8; 32],
            unlock_spec_key: "defi/spec/test".to_string(),
            owner_public_key: &[0xABu8; 64],
            vault_proto_bytes: &fake_vault_proto_bytes(0x02),
        })
        .await
        .expect("publish");

        let view = load_active_advertisements_for_pair(&lower, &higher)
            .await
            .expect("list");
        let ad = view
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("present");

        // After canonicalisation, ad.token_a == lex-lower, reserve_a is
        // the reserve THE CALLER INTENDED for that token (3_000).
        assert_eq!(ad.advertisement.token_a, lower);
        assert_eq!(ad.advertisement.token_b, higher);
        assert_eq!(ad.advertisement.reserve_a_u128, u128_be(3_000));
        assert_eq!(ad.advertisement.reserve_b_u128, u128_be(7_000));
    }

    #[tokio::test]
    async fn pair_isolation_no_cross_pair_leakage() {
        let token_a = token(0xA1);
        let token_b = token(0xB1);
        let token_c = token(0xC1);
        let va = vid(0x10);
        let vc = vid(0x11);

        publish_simple(0x10, &token_a, &token_b, &va, 100, 200).await;
        publish_simple(0x11, &token_a, &token_c, &vc, 300, 400).await;

        let ab = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list AB");
        let ac = load_active_advertisements_for_pair(&token_a, &token_c)
            .await
            .expect("list AC");
        let bc = load_active_advertisements_for_pair(&token_b, &token_c)
            .await
            .expect("list BC");

        assert!(ab.iter().any(|p| p.advertisement.vault_id == va.to_vec()));
        assert!(!ab.iter().any(|p| p.advertisement.vault_id == vc.to_vec()));
        assert!(ac.iter().any(|p| p.advertisement.vault_id == vc.to_vec()));
        assert!(!ac.iter().any(|p| p.advertisement.vault_id == va.to_vec()));
        assert!(
            bc.iter().all(|p| p.advertisement.vault_id != va.to_vec()
                && p.advertisement.vault_id != vc.to_vec()),
            "(B,C) prefix must not leak vaults from (A,B) or (A,C)"
        );
    }

    #[tokio::test]
    async fn digest_binds_proto_and_tamper_is_caught() {
        let token_a = token(0xA2);
        let token_b = token(0xB2);
        let vault_id = vid(0x20);
        let _proto = publish_simple(0x20, &token_a, &token_b, &vault_id, 500, 600).await;

        let view = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list");
        let ad = view[0].advertisement.clone();

        // Happy path: digest verification succeeds.
        let payload = fetch_and_verify_vault_proto(&ad).await.expect("verify ok");
        assert!(!payload.is_empty());

        // Tamper: overwrite the proto mirror with garbage; the next
        // verify must fail.
        let proto_key_str = std::str::from_utf8(&ad.vault_proto_key)
            .expect("utf8")
            .to_string();
        BitcoinTapSdk::storage_put_bytes(&proto_key_str, b"malicious-overwrite")
            .await
            .expect("tamper");
        match fetch_and_verify_vault_proto(&ad).await {
            Err(_) => {} // correct
            Ok(_) => panic!("verify must fail after proto tampering"),
        }
    }

    #[tokio::test]
    async fn terminal_state_supersedes_active_in_dedup() {
        let token_a = token(0xA3);
        let token_b = token(0xB3);
        let vault_id = vid(0x30);
        publish_simple(0x30, &token_a, &token_b, &vault_id, 1, 2).await;

        publish_terminal_state(&token_a, &token_b, &vault_id, LIFECYCLE_EXHAUSTED)
            .await
            .expect("publish exhausted");

        let active = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list active");
        assert!(
            active
                .iter()
                .all(|p| p.advertisement.vault_id != vault_id.to_vec()),
            "exhausted ads must filter out of active view"
        );

        let all = load_all_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list all");
        let entry = all
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("exhausted ad in all view");
        assert_eq!(entry.advertisement.lifecycle_state, LIFECYCLE_EXHAUSTED);
        assert_eq!(entry.advertisement.updated_state_number, 2);
    }

    #[tokio::test]
    async fn dedup_prefers_higher_state_number() {
        let token_a = token(0xA4);
        let token_b = token(0xB4);
        let vault_id = vid(0x40);
        let proto = fake_vault_proto_bytes(0x40);
        let ad_key = advertisement_key(&token_a, &token_b, &vault_id);
        let proto_key_str = proto_key(&token_a, &token_b, &vault_id);
        let digest = dsm::crypto::blake3::domain_hash_bytes(ROUTING_VAULT_AD_DOMAIN, &proto);

        let (lower, higher) = canonical_token_pair(&token_a, &token_b);
        let mut ad = generated::RoutingVaultAdvertisementV1 {
            version: 1,
            vault_id: vault_id.to_vec(),
            token_a: lower.to_vec(),
            token_b: higher.to_vec(),
            reserve_a_u128: u128_be(100).to_vec(),
            reserve_b_u128: u128_be(200).to_vec(),
            fee_bps: 30,
            unlock_spec_digest: vec![0u8; 32],
            unlock_spec_key: "defi/spec/test".into(),
            vault_proto_key: proto_key_str.clone().into_bytes(),
            vault_proto_digest: digest.to_vec(),
            owner_public_key: vec![0xABu8; 64],
            lifecycle_state: LIFECYCLE_ACTIVE.to_string(),
            updated_state_number: 5,
        };
        BitcoinTapSdk::storage_put_bytes(&proto_key_str, &proto)
            .await
            .expect("put proto");
        BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec())
            .await
            .expect("put ad v1");

        ad.updated_state_number = 99;
        BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec())
            .await
            .expect("put ad v2");

        let view = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list");
        let entry = view
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("present");
        assert_eq!(entry.advertisement.updated_state_number, 99);
    }

    #[tokio::test]
    async fn delete_removes_both_keys() {
        let token_a = token(0xA5);
        let token_b = token(0xB5);
        let vault_id = vid(0x50);
        publish_simple(0x50, &token_a, &token_b, &vault_id, 1, 1).await;

        let ad_key = advertisement_key(&token_a, &token_b, &vault_id);
        let proto_key_str = proto_key(&token_a, &token_b, &vault_id);
        assert!(BitcoinTapSdk::storage_get_bytes(&ad_key).await.is_ok());
        assert!(BitcoinTapSdk::storage_get_bytes(&proto_key_str)
            .await
            .is_ok());

        delete_routing_advertisement(&token_a, &token_b, &vault_id)
            .await
            .expect("delete");

        assert!(BitcoinTapSdk::storage_get_bytes(&ad_key).await.is_err());
        assert!(BitcoinTapSdk::storage_get_bytes(&proto_key_str)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unknown_pair_lists_empty() {
        let ghost_a = token(0xF0);
        let ghost_b = token(0xF1);
        let view = load_active_advertisements_for_pair(&ghost_a, &ghost_b)
            .await
            .expect("list");
        assert!(view.is_empty(), "pair with no ads must list empty");
    }

    #[test]
    fn canonical_pair_orders_lex_lower_first() {
        let a = b"AAA".to_vec();
        let b = b"ZZZ".to_vec();
        assert_eq!(canonical_token_pair(&a, &b), (a.as_slice(), b.as_slice()));
        assert_eq!(canonical_token_pair(&b, &a), (a.as_slice(), b.as_slice()));
    }

    // ─────────────────────────────────────────────────────────────────
    // republish_active_advertisement_with_reserves
    // ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn republish_with_reserves_bumps_state_and_updates_reserves() {
        let token_a = token(0x60);
        let token_b = token(0x61);
        let vault_id = vid(0x60);
        publish_simple(0x60, &token_a, &token_b, &vault_id, 1_000_000, 2_000_000).await;

        // Sanity baseline.
        let baseline = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("baseline list");
        let baseline_ad = baseline
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("baseline ad");
        assert_eq!(baseline_ad.advertisement.updated_state_number, 1);

        republish_active_advertisement_with_reserves(
            &token_a, &token_b, &vault_id, 1_500_000, 1_500_000,
        )
        .await
        .expect("republish");

        let after = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("after list");
        let after_ad = after
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("after ad");
        assert_eq!(after_ad.advertisement.updated_state_number, 2);
        assert_eq!(
            after_ad.advertisement.reserve_a_u128,
            u128_be(1_500_000).to_vec()
        );
        assert_eq!(
            after_ad.advertisement.reserve_b_u128,
            u128_be(1_500_000).to_vec()
        );
    }

    #[tokio::test]
    async fn republish_preserves_non_reserve_fields() {
        let token_a = token(0x70);
        let token_b = token(0x71);
        let vault_id = vid(0x70);
        publish_simple(0x70, &token_a, &token_b, &vault_id, 100, 200).await;

        let baseline = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list")
            .into_iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("baseline ad");

        republish_active_advertisement_with_reserves(&token_a, &token_b, &vault_id, 150, 175)
            .await
            .expect("republish");

        let after = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("after")
            .into_iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("after ad");

        // Token pair, fee, owner pk, lifecycle, vault_proto_*, unlock_*
        // must all stay verbatim — only reserves + state_number move.
        assert_eq!(after.advertisement.token_a, baseline.advertisement.token_a);
        assert_eq!(after.advertisement.token_b, baseline.advertisement.token_b);
        assert_eq!(after.advertisement.fee_bps, baseline.advertisement.fee_bps);
        assert_eq!(
            after.advertisement.owner_public_key,
            baseline.advertisement.owner_public_key
        );
        assert_eq!(
            after.advertisement.lifecycle_state,
            baseline.advertisement.lifecycle_state
        );
        assert_eq!(
            after.advertisement.vault_proto_key,
            baseline.advertisement.vault_proto_key
        );
        assert_eq!(
            after.advertisement.vault_proto_digest,
            baseline.advertisement.vault_proto_digest
        );
        assert_eq!(
            after.advertisement.unlock_spec_digest,
            baseline.advertisement.unlock_spec_digest
        );
        assert_eq!(
            after.advertisement.unlock_spec_key,
            baseline.advertisement.unlock_spec_key
        );
    }

    #[tokio::test]
    async fn republish_for_absent_advertisement_returns_err() {
        // Vault that was never advertised — republish must surface
        // the storage-not-found error so the caller (chunk #7
        // unlock handler) can log and continue.
        let token_a = token(0x80);
        let token_b = token(0x81);
        let vault_id = vid(0x80);
        match republish_active_advertisement_with_reserves(&token_a, &token_b, &vault_id, 1, 1)
            .await
        {
            Err(_) => {} // correct: storage GET fails
            Ok(()) => panic!("republish for absent ad must Err, got Ok"),
        }
    }

    #[tokio::test]
    async fn republish_supersedes_baseline_in_dedup() {
        // Republish must produce a higher updated_state_number so the
        // chunk-#1 dedup selector picks the post-trade ad in any
        // listing.  This test exercises the full dedup path
        // explicitly rather than just trusting the bump.
        let token_a = token(0x90);
        let token_b = token(0x91);
        let vault_id = vid(0x90);
        publish_simple(0x90, &token_a, &token_b, &vault_id, 100, 100).await;
        republish_active_advertisement_with_reserves(&token_a, &token_b, &vault_id, 110, 91)
            .await
            .expect("republish");

        let listed = load_active_advertisements_for_pair(&token_a, &token_b)
            .await
            .expect("list");
        let entry = listed
            .iter()
            .find(|p| p.advertisement.vault_id == vault_id.to_vec())
            .expect("present");
        assert_eq!(entry.advertisement.updated_state_number, 2);
        assert_eq!(entry.advertisement.reserve_a_u128, u128_be(110).to_vec());
        assert_eq!(entry.advertisement.reserve_b_u128, u128_be(91).to_vec());
    }
}
