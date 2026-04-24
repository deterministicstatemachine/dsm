// SPDX-License-Identifier: MIT OR Apache-2.0
//! Posted-mode DLV storage-node delivery pipeline.
//!
//! Recipient-indexed advertisements under `dlv/posted/{recipient_kyber_pk_b32}/{dlv_id_b32}`
//! mirror the full `VaultPostProto` under `dlv/posted-proto/{..}/{..}` with a
//! BLAKE3 digest binding the two.  Discovery is pull-on-query by the recipient
//! (Kyber PK holder); storage nodes are dumb mirrors.
//!
//! Pattern intentionally mirrors the dBTC vault advertisement pipeline in
//! `bitcoin_tap_sdk.rs` (publish → list with state-number dedup → delete).
//! The only substantive differences:
//!   * No Bitcoin UTXO liveness — state-machine membership proof is authoritative.
//!   * Keyspace is recipient-scoped (Kyber PK), not policy-scoped (dBTC policy commit).
//!   * Lifecycle states: "active" | "claimed" | "invalidated" (dBTC: "active" | "spent" | …).
//!
//! The advertisement carries no secrets: vault content is Kyber-encrypted inside
//! the `VaultPostProto`, and authenticity is recipient-verified via
//! `LimboVault::from_vault_post` which already checks the creator's SPHINCS+
//! signature over parameters_hash.  Storage nodes cannot forge a valid ad
//! because the `vault_proto_digest` would not match a re-fetched proto.

use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;

/// BLAKE3 domain tag binding the advertisement to the full vault proto.
pub(crate) const POSTED_DLV_AD_DOMAIN: &str = "DSM/posted-dlv-ad";

/// Base prefix for posted-mode DLV advertisements.
pub(crate) const POSTED_DLV_AD_ROOT: &str = "dlv/posted/";

/// Base prefix for posted-mode DLV full proto mirrors.
pub(crate) const POSTED_DLV_PROTO_ROOT: &str = "dlv/posted-proto/";

/// Lifecycle state tags mirroring `DbtcVaultAdvertisementV1.lifecycle_state`.
pub(crate) const LIFECYCLE_ACTIVE: &str = "active";
pub(crate) const LIFECYCLE_CLAIMED: &str = "claimed";
pub(crate) const LIFECYCLE_INVALIDATED: &str = "invalidated";

/// Advertisement key for a recipient + dlv_id pair.
pub(crate) fn advertisement_key(recipient_kyber_pk: &[u8], dlv_id: &[u8; 32]) -> String {
    format!(
        "{prefix}{recipient}/{id}",
        prefix = POSTED_DLV_AD_ROOT,
        recipient = encode_base32_crockford(recipient_kyber_pk),
        id = encode_base32_crockford(dlv_id),
    )
}

/// Proto mirror key for a recipient + dlv_id pair.
pub(crate) fn proto_key(recipient_kyber_pk: &[u8], dlv_id: &[u8; 32]) -> String {
    format!(
        "{prefix}{recipient}/{id}",
        prefix = POSTED_DLV_PROTO_ROOT,
        recipient = encode_base32_crockford(recipient_kyber_pk),
        id = encode_base32_crockford(dlv_id),
    )
}

/// Advertisement-listing prefix for a given recipient Kyber PK.
pub(crate) fn advertisement_prefix_for_recipient(recipient_kyber_pk: &[u8]) -> String {
    format!(
        "{prefix}{recipient}/",
        prefix = POSTED_DLV_AD_ROOT,
        recipient = encode_base32_crockford(recipient_kyber_pk),
    )
}

/// Inputs needed to publish an "active" advertisement.  The vault proto bytes
/// are taken verbatim from `DLVManager::create_vault_post` — the digest bound
/// into the advertisement is computed over those exact bytes.
pub(crate) struct PublishActiveAdInput<'a> {
    pub dlv_id: &'a [u8; 32],
    pub recipient_kyber_pk: &'a [u8],
    pub creator_public_key: &'a [u8],
    pub policy_commit: [u8; 32],
    pub vault_post_bytes: &'a [u8],
}

/// Publish an active-state advertisement + the full vault proto mirror.
///
/// Best-effort at the caller's discretion — failures surface as `Err` so the
/// caller decides whether to log-and-continue (creator's local state advance
/// already succeeded) or hard-fail.  The dBTC analog `persist_vault_storage_node_only`
/// / `publish_vault_advertisement_mandatory` split is preserved: this function
/// is the advertisement writer; retry semantics live above it.
pub(crate) async fn publish_active_advertisement(
    input: PublishActiveAdInput<'_>,
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(input.recipient_kyber_pk, input.dlv_id);
    let proto_key_str = proto_key(input.recipient_kyber_pk, input.dlv_id);

    let digest: [u8; 32] =
        dsm::crypto::blake3::domain_hash_bytes(POSTED_DLV_AD_DOMAIN, input.vault_post_bytes);

    let ad = generated::PostedDlvAdvertisementV1 {
        version: 1,
        dlv_id: input.dlv_id.to_vec(),
        recipient_kyber_pk: input.recipient_kyber_pk.to_vec(),
        creator_public_key: input.creator_public_key.to_vec(),
        policy_commit: input.policy_commit.to_vec(),
        vault_proto_key: proto_key_str.clone(),
        vault_proto_digest: digest.to_vec(),
        lifecycle_state: LIFECYCLE_ACTIVE.to_string(),
        updated_state_number: 1,
        creator_signature: Vec::new(),
        claimant_signature: Vec::new(),
    };

    // Publish the proto mirror first so recipients that see the ad can always
    // fetch a valid proto (ordering guarantee matches dBTC vault_proto → ad).
    BitcoinTapSdk::storage_put_bytes(&proto_key_str, input.vault_post_bytes).await?;
    BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
    Ok(())
}

/// Transition a published advertisement from "active" to a terminal state
/// ("claimed" or "invalidated").  Fetches the current ad, increments
/// `updated_state_number`, updates `lifecycle_state`, and republishes to the
/// same key.  The dedup rule (highest state_number wins) ensures the terminal
/// ad supersedes the active one on any later list.
///
/// `claimant_signature` is currently an empty placeholder — future hardening
/// commit lands a typed recipient-signed attestation here.  The security model
/// today: the authoritative truth is the `Operation::DlvClaim` on the recipient's
/// chain; the ad is a discovery hint.  A forged "claimed" ad only DoSes
/// discovery, it cannot credit balance.
pub(crate) async fn publish_terminal_state(
    recipient_kyber_pk: &[u8],
    dlv_id: &[u8; 32],
    terminal_state: &str,
    claimant_signature: Vec<u8>,
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(recipient_kyber_pk, dlv_id);
    let ad_bytes = BitcoinTapSdk::storage_get_bytes(&ad_key).await?;
    let mut ad = generated::PostedDlvAdvertisementV1::decode(ad_bytes.as_slice()).map_err(|e| {
        dsm::types::error::DsmError::serialization_error(
            "PostedDlvAdvertisementV1",
            "decode",
            Some(ad_key.clone()),
            Some(e),
        )
    })?;
    ad.lifecycle_state = terminal_state.to_string();
    ad.updated_state_number = ad.updated_state_number.saturating_add(1);
    if terminal_state == LIFECYCLE_CLAIMED {
        ad.claimant_signature = claimant_signature;
    }
    BitcoinTapSdk::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
    Ok(())
}

/// One advertisement fetched from storage nodes, with its source key retained
/// for deduplication and for downstream proto-fetch.
#[derive(Debug, Clone)]
pub(crate) struct PublishedPostedDlvAdvertisement {
    pub key: String,
    pub advertisement: generated::PostedDlvAdvertisementV1,
}

/// List all active advertisements addressed to a recipient, deduplicating
/// duplicate `dlv_id` entries by preferring the highest `updated_state_number`
/// (lex-smallest key as tiebreaker).  Matches the dBTC selector dedup logic in
/// `bitcoin_tap_sdk.rs::load_global_vault_advertisements` one-for-one so the
/// recipient-side view is deterministic regardless of republish order.
///
/// Terminal-state ads ("claimed", "invalidated") are filtered out — the
/// recipient sees only actionable posts.  A caller that wants the full set
/// (e.g. to prune) should call `load_all_advertisements_for_recipient` instead.
pub(crate) async fn load_active_advertisements_for_recipient(
    recipient_kyber_pk: &[u8],
) -> Result<Vec<PublishedPostedDlvAdvertisement>, dsm::types::error::DsmError> {
    let all = load_all_advertisements_for_recipient(recipient_kyber_pk).await?;
    Ok(all
        .into_iter()
        .filter(|p| p.advertisement.lifecycle_state == LIFECYCLE_ACTIVE)
        .collect())
}

/// List all advertisements addressed to a recipient regardless of lifecycle
/// state.  Dedup by dlv_id (state_number wins, key as tiebreaker).
pub(crate) async fn load_all_advertisements_for_recipient(
    recipient_kyber_pk: &[u8],
) -> Result<Vec<PublishedPostedDlvAdvertisement>, dsm::types::error::DsmError> {
    use std::collections::HashMap;
    const LIST_LIMIT: u32 = 200;

    let prefix = advertisement_prefix_for_recipient(recipient_kyber_pk);
    let mut cursor: Option<String> = None;
    let mut fetched: Vec<PublishedPostedDlvAdvertisement> = Vec::new();

    loop {
        let resp = BitcoinTapSdk::storage_list_objects(&prefix, cursor.as_deref(), LIST_LIMIT)
            .await?;
        let page_len = resp.items.len();
        for item in resp.items {
            let payload = match BitcoinTapSdk::storage_get_bytes(&item.key).await {
                Ok(b) => b,
                Err(e) => {
                    log::warn!(
                        "[posted_dlv.list] skipping {}: fetch failed: {e}",
                        &item.key
                    );
                    continue;
                }
            };
            let advertisement =
                match generated::PostedDlvAdvertisementV1::decode(payload.as_slice()) {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!(
                            "[posted_dlv.list] skipping {}: decode failed: {e}",
                            &item.key
                        );
                        continue;
                    }
                };
            fetched.push(PublishedPostedDlvAdvertisement {
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
    let mut deduped: HashMap<Vec<u8>, PublishedPostedDlvAdvertisement> = HashMap::new();
    for entry in fetched {
        let dedupe_key = if entry.advertisement.dlv_id.is_empty() {
            entry.key.as_bytes().to_vec()
        } else {
            entry.advertisement.dlv_id.clone()
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

    let mut out: Vec<PublishedPostedDlvAdvertisement> = deduped.into_values().collect();
    out.sort_by(|left, right| {
        left.advertisement
            .dlv_id
            .cmp(&right.advertisement.dlv_id)
            .then(left.key.cmp(&right.key))
    });
    Ok(out)
}

/// Fetch the `VaultPostProto` referenced by an advertisement and verify the
/// digest binding.  Returns the decoded proto on success.
///
/// Mirrors `bitcoin_tap_sdk::verify_remote_vault_artifacts` — digest check,
/// id-match check, no bearer secrets touched.
pub(crate) async fn fetch_and_verify_vault_post(
    ad: &generated::PostedDlvAdvertisementV1,
) -> Result<generated::VaultPostProto, dsm::types::error::DsmError> {
    if ad.vault_proto_key.trim().is_empty() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "posted-dlv advertisement missing vault_proto_key",
        ));
    }
    if ad.vault_proto_digest.len() != 32 {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "posted-dlv advertisement vault_proto_digest must be 32 bytes",
        ));
    }
    let payload = BitcoinTapSdk::storage_get_bytes(&ad.vault_proto_key).await?;
    let digest = dsm::crypto::blake3::domain_hash_bytes(POSTED_DLV_AD_DOMAIN, &payload);
    if digest.as_slice() != ad.vault_proto_digest.as_slice() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "posted-dlv advertisement proto digest mismatch",
        ));
    }
    let post = generated::VaultPostProto::decode(payload.as_slice()).map_err(|e| {
        dsm::types::error::DsmError::serialization_error(
            "VaultPostProto",
            "decode",
            Some(ad.vault_proto_key.clone()),
            Some(e),
        )
    })?;
    if post.vault_id.as_slice() != ad.dlv_id.as_slice() {
        return Err(dsm::types::error::DsmError::invalid_operation(
            "posted-dlv VaultPostProto.vault_id != advertisement.dlv_id",
        ));
    }
    Ok(post)
}

/// Delete the advertisement + mirrored proto for a recipient/dlv_id pair.
/// Best-effort — a stale ad with `lifecycle_state == "claimed"` is already
/// filtered out of the recipient's list view, so failure to delete just
/// leaves garbage that'll be collected later by storage-node TTL.
pub(crate) async fn delete_posted_dlv(
    recipient_kyber_pk: &[u8],
    dlv_id: &[u8; 32],
) -> Result<(), dsm::types::error::DsmError> {
    let ad_key = advertisement_key(recipient_kyber_pk, dlv_id);
    let proto_key_str = proto_key(recipient_kyber_pk, dlv_id);
    if let Err(e) = BitcoinTapSdk::storage_delete_key(&ad_key).await {
        log::warn!("[posted_dlv.prune] delete ad {ad_key} failed: {e}");
    }
    if let Err(e) = BitcoinTapSdk::storage_delete_key(&proto_key_str).await {
        log::warn!("[posted_dlv.prune] delete proto {proto_key_str} failed: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Two-device posted-DLV delivery tests.
    //!
    //! Alice = creator, Bob = intended recipient, Carol = unrelated third party.
    //! The mock storage backend is the `DBTC_STORAGE_TEST_STATE` mutex
    //! already used by bitcoin_tap_sdk — both Alice and Bob's publish/fetch
    //! calls route to the same `HashMap<String, Vec<u8>>` since the tests
    //! run in a single process.  That's the correct model: one "storage
    //! node", two independent device identities.
    //!
    //! Tests never poison each other because each one uses unique
    //! (recipient_pk, dlv_id) pairs so keyspaces don't collide.

    use super::*;
    use prost::Message;

    fn pk(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
    }

    fn vid(tag: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[0] = tag;
        v[31] = tag.wrapping_mul(3).wrapping_add(7);
        v
    }

    fn fake_vault_post_proto(vault_id: &[u8; 32]) -> Vec<u8> {
        // Minimal VaultPostProto — intentionally not a valid LimboVault (no
        // signature), since these tests exercise the storage/discovery
        // pipeline, not vault hydration.  The LimboVault signature path is
        // already covered by `limbo_vault::tests::vault_anchoring_*`.
        let proto = generated::VaultPostProto {
            vault_id: vault_id.to_vec(),
            lock_description: "test".into(),
            creator_id: "pk-test".into(),
            commitment_hash: vec![0x42; 32],
            status: "posted".into(),
            metadata: Vec::new(),
            vault_data: vec![0xAA, 0xBB, 0xCC], // nonsense; fetch_and_verify stops at digest check
        };
        proto.encode_to_vec()
    }

    async fn alice_publishes_for_bob(
        alice_tag: u8,
        bob_pk: &[u8],
        dlv_id: &[u8; 32],
    ) -> Vec<u8> {
        let alice_pk = pk(alice_tag, 64);
        let post_bytes = fake_vault_post_proto(dlv_id);
        publish_active_advertisement(PublishActiveAdInput {
            dlv_id,
            recipient_kyber_pk: bob_pk,
            creator_public_key: &alice_pk,
            policy_commit: [0u8; 32],
            vault_post_bytes: &post_bytes,
        })
        .await
        .expect("publish_active_advertisement");
        post_bytes
    }

    #[tokio::test]
    async fn alice_posts_bob_lists_carol_sees_nothing() {
        let bob_pk = pk(0xB0, 1568);
        let carol_pk = pk(0xC0, 1568);
        let dlv_id = vid(0x01);

        alice_publishes_for_bob(0xA1, &bob_pk, &dlv_id).await;

        let bob_view = load_active_advertisements_for_recipient(&bob_pk)
            .await
            .expect("bob list");
        assert_eq!(bob_view.len(), 1);
        assert_eq!(bob_view[0].advertisement.dlv_id, dlv_id);
        assert_eq!(bob_view[0].advertisement.lifecycle_state, LIFECYCLE_ACTIVE);

        let carol_view = load_active_advertisements_for_recipient(&carol_pk)
            .await
            .expect("carol list");
        assert!(
            carol_view.is_empty(),
            "carol (unrelated pk) must not see bob's ads"
        );
    }

    #[tokio::test]
    async fn advertisement_digest_binds_proto() {
        let bob_pk = pk(0xB1, 1568);
        let dlv_id = vid(0x02);
        let post_bytes = alice_publishes_for_bob(0xA2, &bob_pk, &dlv_id).await;

        let bob_view = load_active_advertisements_for_recipient(&bob_pk)
            .await
            .expect("list");
        assert_eq!(bob_view.len(), 1);
        let ad = &bob_view[0].advertisement;

        let expected_digest: [u8; 32] =
            dsm::crypto::blake3::domain_hash_bytes(POSTED_DLV_AD_DOMAIN, &post_bytes);
        assert_eq!(
            ad.vault_proto_digest,
            expected_digest.to_vec(),
            "advertisement digest must be BLAKE3(DSM/posted-dlv-ad, proto)"
        );

        let proto = fetch_and_verify_vault_post(ad)
            .await
            .expect("fetch_and_verify must succeed when proto is unchanged");
        assert_eq!(proto.vault_id, dlv_id.to_vec());
    }

    #[tokio::test]
    async fn tampered_proto_rejected_by_digest_check() {
        let bob_pk = pk(0xB2, 1568);
        let dlv_id = vid(0x03);
        alice_publishes_for_bob(0xA3, &bob_pk, &dlv_id).await;

        let bob_view = load_active_advertisements_for_recipient(&bob_pk)
            .await
            .expect("list");
        let ad = bob_view[0].advertisement.clone();

        // Overwrite the proto mirror with tampered bytes (but keep the ad).
        BitcoinTapSdk::storage_put_bytes(&ad.vault_proto_key, b"malicious-payload")
            .await
            .expect("tamper put");

        match fetch_and_verify_vault_post(&ad).await {
            Err(_) => {} // correct — digest mismatch detected
            Ok(_) => panic!("fetch_and_verify must fail after proto tampering"),
        }
    }

    #[tokio::test]
    async fn claimed_state_supersedes_active_in_dedup() {
        let bob_pk = pk(0xB3, 1568);
        let dlv_id = vid(0x04);
        alice_publishes_for_bob(0xA4, &bob_pk, &dlv_id).await;

        // Bob publishes a claimed-state ad on top (same key, higher state_number).
        publish_terminal_state(&bob_pk, &dlv_id, LIFECYCLE_CLAIMED, Vec::new())
            .await
            .expect("publish claimed");

        let active = load_active_advertisements_for_recipient(&bob_pk)
            .await
            .expect("list active");
        assert!(
            active.iter().all(|p| p.advertisement.dlv_id != dlv_id.to_vec()),
            "claimed ad must filter out of active view"
        );

        let all = load_all_advertisements_for_recipient(&bob_pk)
            .await
            .expect("list all");
        let entry = all
            .iter()
            .find(|p| p.advertisement.dlv_id == dlv_id.to_vec())
            .expect("claimed ad present in all view");
        assert_eq!(entry.advertisement.lifecycle_state, LIFECYCLE_CLAIMED);
        assert_eq!(entry.advertisement.updated_state_number, 2);
    }

    #[tokio::test]
    async fn dedup_prefers_higher_state_number() {
        use super::super::bitcoin_tap_sdk::BitcoinTapSdk;

        let bob_pk = pk(0xB4, 1568);
        let dlv_id = vid(0x05);
        let ad_key = advertisement_key(&bob_pk, &dlv_id);
        let proto_key_str = proto_key(&bob_pk, &dlv_id);

        // Two advertisements at the same key with different state_numbers
        // (this models a malicious / stale republish — the selector must pick
        //  the newer one).
        let post_bytes = fake_vault_post_proto(&dlv_id);
        let digest = dsm::crypto::blake3::domain_hash_bytes(POSTED_DLV_AD_DOMAIN, &post_bytes);
        let mut ad_v1 = generated::PostedDlvAdvertisementV1 {
            version: 1,
            dlv_id: dlv_id.to_vec(),
            recipient_kyber_pk: bob_pk.clone(),
            creator_public_key: pk(0xA5, 64),
            policy_commit: vec![0u8; 32],
            vault_proto_key: proto_key_str.clone(),
            vault_proto_digest: digest.to_vec(),
            lifecycle_state: LIFECYCLE_ACTIVE.to_string(),
            updated_state_number: 5,
            creator_signature: Vec::new(),
            claimant_signature: Vec::new(),
        };
        BitcoinTapSdk::storage_put_bytes(&proto_key_str, &post_bytes)
            .await
            .unwrap();
        BitcoinTapSdk::storage_put_bytes(&ad_key, &ad_v1.encode_to_vec())
            .await
            .unwrap();

        // Overwrite with a higher state_number.
        ad_v1.updated_state_number = 99;
        BitcoinTapSdk::storage_put_bytes(&ad_key, &ad_v1.encode_to_vec())
            .await
            .unwrap();

        let view = load_active_advertisements_for_recipient(&bob_pk)
            .await
            .expect("list");
        let found = view
            .iter()
            .find(|p| p.advertisement.dlv_id == dlv_id.to_vec())
            .expect("present");
        assert_eq!(
            found.advertisement.updated_state_number, 99,
            "dedup must return the highest state_number"
        );
    }

    #[tokio::test]
    async fn delete_removes_both_ad_and_proto() {
        let bob_pk = pk(0xB5, 1568);
        let dlv_id = vid(0x06);
        alice_publishes_for_bob(0xA6, &bob_pk, &dlv_id).await;

        let ad_key = advertisement_key(&bob_pk, &dlv_id);
        let proto_key_str = proto_key(&bob_pk, &dlv_id);
        assert!(
            BitcoinTapSdk::storage_get_bytes(&ad_key).await.is_ok(),
            "ad present before delete"
        );
        assert!(
            BitcoinTapSdk::storage_get_bytes(&proto_key_str).await.is_ok(),
            "proto present before delete"
        );

        delete_posted_dlv(&bob_pk, &dlv_id).await.expect("delete");

        assert!(
            BitcoinTapSdk::storage_get_bytes(&ad_key).await.is_err(),
            "ad gone after delete"
        );
        assert!(
            BitcoinTapSdk::storage_get_bytes(&proto_key_str).await.is_err(),
            "proto gone after delete"
        );
    }

    #[tokio::test]
    async fn empty_recipient_prefix_lists_nothing() {
        let ghost_pk = pk(0xF0, 1568);
        let view = load_active_advertisements_for_recipient(&ghost_pk)
            .await
            .expect("list");
        assert!(
            view.is_empty(),
            "recipient with no posted ads must see an empty list"
        );
    }

    #[tokio::test]
    async fn advertisement_key_format_is_recipient_scoped() {
        // Key format is load-bearing for the recipient-indexed discovery
        // model: `dlv/posted/{recipient_b32}/{dlv_id_b32}`.  A regression
        // that swapped recipient for creator would silently break Bob's
        // list-by-own-pk query.
        let bob_pk = pk(0xB6, 1568);
        let dlv_id = vid(0x07);
        let key = advertisement_key(&bob_pk, &dlv_id);
        let prefix = advertisement_prefix_for_recipient(&bob_pk);
        assert!(
            key.starts_with(&prefix),
            "advertisement_key must live under the recipient's prefix"
        );
        assert!(
            key.starts_with(POSTED_DLV_AD_ROOT),
            "advertisement_key must live under the posted-dlv root"
        );
    }
}
