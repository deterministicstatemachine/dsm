// SPDX-License-Identifier: MIT OR Apache-2.0
//! Token route handlers for AppRouterImpl.
//!
//! Handles: `token.create`, `tokens.publishPolicy`, `tokens.getPolicy`, `tokens.listCachedPolicies`

use std::collections::{BTreeSet, HashMap};

use dsm::types::proto as generated;
use dsm::types::token_types::{TokenMetadata, TokenType};
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

// The token policy — its constants, its rules and its one parser — is Core's
// (`dsm::economic::token_policy`), so no two readers can disagree about one
// blob. This module keeps the one packer (SoFi §47).
use dsm::economic::token_policy::{
    ReleaseRule, ALLOWLIST_KIND_INLINE, ALLOWLIST_KIND_NONE, MAX_POLICY_SIGNERS,
    POLICY_FLAG_ALLOWLIST, POLICY_FLAG_BURN, POLICY_FLAG_TRANSFERABLE, SUPPLY_CLASS_NATIVE,
    TOKEN_KIND_FUNGIBLE, TOKEN_POLICY_VERSION,
};

/// A committed token policy, as Core parses it.
pub(crate) type ParsedTokenPolicy = dsm::economic::token_policy::TokenPolicy;

/// Pack the canonical v3 policy blob.
///
/// This is the SOLE packer for the token-policy format (SoFi §47). It lives in
/// Rust because the blob is protocol — it is hashed into the CPTA anchor and
/// fixes the token's supply and rules. No other layer may construct it. It
/// parses its own output with Core's one parser before returning it, so it
/// can never produce a blob Core refuses.
///
/// Layout (all integers big-endian; the authority is
/// `dsm::economic::token_policy`):
/// ```text
///   u8   version = 3
///   u8   kind = 0 (FUNGIBLE)
///   u8   supply_class = 0 (NATIVE; externally backed is refused until its
///        backing rule has an encoding)
///   u8   flags: 0x01 burn | 0x02 transferable | 0x04 allowlist
///   u8   release_rule: 0 all-at-creation | 1 faucet
///   32B  creator_genesis              (SoFi Amendment S8)
///   32B  creator_device_id
///   u8   threshold k                  (1..=n)
///   u8   signer_count n               (1..=16)
///   n x  { u16 pk_len, pk }
///   u8   ticker_len,  ticker
///   u16  alias_len,   alias
///   u8   decimals
///   u128 genesis_supply               (> 0)
///   u16  description_len, description
///   u16  icon_url_len,    icon_url
///   u8   allowlist_kind (0 NONE | 1 INLINE)
///   u16  allowlist_count, count x 32B device_id
/// ```
pub(crate) fn build_policy_v3_bytes(p: &ParsedTokenPolicy) -> Result<Vec<u8>, String> {
    if p.signers.is_empty() || p.signers.len() > MAX_POLICY_SIGNERS {
        return Err(format!(
            "policy: signer count must be 1..={MAX_POLICY_SIGNERS}, got {}",
            p.signers.len()
        ));
    }
    if p.threshold == 0 || (p.threshold as usize) > p.signers.len() {
        return Err(format!(
            "policy: threshold {} must be 1..={} (the signer count)",
            p.threshold,
            p.signers.len()
        ));
    }
    if p.genesis_supply == 0 {
        return Err("policy: a token's genesis supply must be positive".into());
    }

    let ticker = p.ticker.as_bytes();
    let alias = p.alias.as_bytes();
    let desc = p.description.as_deref().unwrap_or("").as_bytes();
    let icon = p.icon_url.as_deref().unwrap_or("").as_bytes();

    if ticker.len() > u8::MAX as usize {
        return Err("policy: ticker too long".into());
    }
    for (label, field) in [("alias", alias), ("description", desc), ("icon_url", icon)] {
        if field.len() > u16::MAX as usize {
            return Err(format!("policy: {label} too long"));
        }
    }
    if p.allowlist_device_ids.len() > u16::MAX as usize {
        return Err("policy: allowlist too long".into());
    }

    let mut flags = 0u8;
    if p.burn_enabled {
        flags |= POLICY_FLAG_BURN;
    }
    if p.transferable {
        flags |= POLICY_FLAG_TRANSFERABLE;
    }
    if !p.allowlist_device_ids.is_empty() {
        flags |= POLICY_FLAG_ALLOWLIST;
    }

    let mut out = vec![
        TOKEN_POLICY_VERSION,
        TOKEN_KIND_FUNGIBLE,
        SUPPLY_CLASS_NATIVE,
        flags,
        p.release_rule.code(),
    ];
    out.extend_from_slice(&p.creator_genesis);
    out.extend_from_slice(&p.creator_device_id);
    out.push(p.threshold);
    out.push(p.signers.len() as u8);
    for pk in &p.signers {
        if pk.len() > u16::MAX as usize {
            return Err("policy: signer public key too long".into());
        }
        out.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        out.extend_from_slice(pk);
    }
    out.push(ticker.len() as u8);
    out.extend_from_slice(ticker);
    out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    out.extend_from_slice(alias);
    out.push(p.decimals as u8);
    out.extend_from_slice(&p.genesis_supply.to_be_bytes());
    out.extend_from_slice(&(desc.len() as u16).to_be_bytes());
    out.extend_from_slice(desc);
    out.extend_from_slice(&(icon.len() as u16).to_be_bytes());
    out.extend_from_slice(icon);
    if p.allowlist_device_ids.is_empty() {
        out.push(ALLOWLIST_KIND_NONE);
        out.extend_from_slice(&0u16.to_be_bytes());
    } else {
        out.push(ALLOWLIST_KIND_INLINE);
        out.extend_from_slice(&(p.allowlist_device_ids.len() as u16).to_be_bytes());
        for id in &p.allowlist_device_ids {
            out.extend_from_slice(id);
        }
    }
    // One definition: the packer's output must parse under Core's parser.
    dsm::economic::token_policy::parse_token_policy_blob(&out)
        .map_err(|e| format!("policy: packed blob refused by Core: {e}"))?;
    Ok(out)
}

/// Parse a canonical v3 policy with Core's one parser. Fail-closed on every
/// field: a policy that cannot be fully validated is not a policy.
pub(crate) fn parse_token_policy(raw_proto: &[u8]) -> Option<ParsedTokenPolicy> {
    dsm::economic::token_policy::parse_token_policy(raw_proto).ok()
}

/// The network's pinned storage set, where token policies live as immutable
/// objects under `TAG_DSM_POLICY`.
fn policy_set() -> Result<crate::sdk::storage_set::StorageSet, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("no committed network: {e}"))?;
    crate::sdk::storage_set::canonical_set(&network).map_err(|e| format!("no pinned set: {e}"))
}

/// Where a policy publication stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    /// Three members return the exact bytes (storage spec §5 rule 6).
    Stored,
    /// Not `Stored` yet, and why. Publication resumes at startup
    /// (`republish_owned_policies`).
    NotStoredYet(String),
}

/// Put policy bytes on the network's pinned set as the immutable object whose
/// identity is their anchor, and read them back.
///
/// The anchor is content-addressed by definition —
/// `BLAKE3(TAG_DSM_POLICY, policy_bytes)` — and it is the object's identity
/// in the store, so no member can name it: a member that served other bytes
/// would be serving an object at another address.
async fn publish_policy_to_network(body: &[u8], expected_anchor: &[u8; 32]) -> PublishOutcome {
    let tag = dsm::common::domain_tags::TAG_DSM_POLICY;
    if dsm::crypto::blake3::domain_hash_bytes(tag, body) != *expected_anchor {
        return PublishOutcome::NotStoredYet("the bytes are not the policy at this anchor".into());
    }
    let set = match policy_set() {
        Ok(set) => set,
        Err(e) => return PublishOutcome::NotStoredYet(e),
    };
    if let Err(e) = crate::sdk::storage_io::put_immutable(&set, tag, body).await {
        return PublishOutcome::NotStoredYet(format!("put: {e}"));
    }
    let addr = dsm::storage_object::immutable_addr_from_inner(tag, expected_anchor);
    match crate::sdk::storage_io::read_stored_bytes(&set, &addr).await {
        Ok(Some(stored)) if stored == body => PublishOutcome::Stored,
        Ok(Some(..) | None) => {
            PublishOutcome::NotStoredYet("fewer than three members return the bytes yet".into())
        }
        Err(e) => PublishOutcome::NotStoredYet(format!("read back: {e}")),
    }
}

/// The policy at `anchor` from the network's pinned set: the bytes a member
/// serves at its address, which re-hash to it. `None` when no member holds
/// it.
pub(crate) async fn try_fetch_policy_from_network(
    anchor: &[u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    let set = policy_set()?;
    crate::sdk::storage_io::fetch_immutable(&set, dsm::common::domain_tags::TAG_DSM_POLICY, anchor)
        .await
        .map_err(|e| e.to_string())
}

/// Build the enforcer's `PolicyFile` from a parsed policy.
///
/// SOLE constructor. It is a pure function of the parsed (and therefore of the
/// anchored) policy, so every device that fetches the same policy bytes
/// reconstructs a byte-identical `PolicyFile`. Creation and restart
/// rehydration both call this — there is no second place that decides what a
/// token's policy means.
pub(crate) fn derive_policy_file(
    ticker: &str,
    parsed: &ParsedTokenPolicy,
) -> dsm::types::policy_types::PolicyFile {
    use dsm::types::policy_types::PolicyCondition;

    // Semantic version — the validator rejects a bare "1".
    let mut pf = dsm::types::policy_types::PolicyFile::new(ticker, "1.0.0", "dsm_token_route");
    if let Some(desc) = parsed.description.as_ref() {
        pf.description = Some(desc.clone());
    }

    // CONDITIONS, not metadata. `PolicyFile::metadata` is documented as
    // "UI/ops only" and is EXCLUDED from `canonical_bytes` — anything put
    // there is neither committed in the anchor nor read by the enforcer, which
    // is why the previous transferable/allowed_operations metadata was inert.
    // Conditions are both committed and evaluated.
    // The whole supply exists from creation (SoFi §51): no unit is issued
    // after it.
    pf.add_condition(PolicyCondition::SupplyCap {
        max_supply: parsed.genesis_supply,
    });
    // What each flag governs (SoFi §49, §54): `transferable` every transfer
    // (vault creation and SoFi legs are refused in Core, at genesis
    // acceptance and route validation), `burn_enabled` burns only. Creation
    // is always the creator's own (Amendment S8, checked at the genesis
    // release). The signer set the blob carries authorizes only what the
    // policy's own rules name, and the standard release rule names none
    // (§47), so no condition is built from it.
    pf.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: permitted_operations(parsed.transferable, parsed.burn_enabled),
    });

    pf.add_metadata("created_by", "dsm_token_route")
        .add_metadata("token_name", ticker);
    pf
}

/// The operations a token's policy permits, from its two flags.
pub(crate) fn permitted_operations(transferable: bool, burn_enabled: bool) -> Vec<String> {
    let mut ops = vec!["create_token".to_string()];
    if transferable {
        ops.extend(["transfer", "lock", "unlock"].map(String::from));
    }
    if burn_enabled {
        ops.push("burn".to_string());
    }
    ops
}

/// Tell the WebView its token set changed.
///
/// Emitted from Rust beside the registry write, because the write is what made
/// it true. The screen reloads from the persisted registry rather than trusting
/// optimistic frontend state — an adopted token that exists only in React is a
/// token this device cannot actually hold.
#[cfg(all(target_os = "android", feature = "jni"))]
fn push_wallet_refresh() {
    let _ = crate::jni::event_dispatch::post_event_to_webview("dsm-wallet-refresh", &[]);
}

#[cfg(not(all(target_os = "android", feature = "jni")))]
fn push_wallet_refresh() {
    // No-op on host builds; there is no WebView to notify.
}

/// Scheme prefix for a token-adoption payload.
///
/// Versioned like the contact payload (`dsm:contact/v3:`) so a future shape is a
/// different scheme rather than a guess about what the bytes mean.
const TOKEN_ADOPTION_URI_PREFIX: &str = "dsm:token/v1:";

/// What a user pasted into the adopt field, resolved to an anchor.
///
/// Two forms are accepted because both exist in the wild: the bare Base32
/// anchor a person reads off a screen, and the versioned payload a camera
/// scans. Parsing lives here, in Rust, so there is one decoder — the last time
/// an anchor was encoded outside this module the padding was wrong and the
/// result was a plausible 52-character string that resolved to nothing.
#[derive(Debug)]
pub struct ParsedAdoptionInput {
    pub anchor: [u8; 32],
    /// Present only for the versioned payload: what the payload CLAIMS this
    /// anchor resolves to. Checked against the fetched policy, never trusted.
    pub claimed_ticker: Option<String>,
    pub claimed_token_id: Option<String>,
}

pub fn parse_adoption_input(text: &str) -> Result<ParsedAdoptionInput, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("adopt: nothing to read — paste an anchor or scan a code".into());
    }

    // Case is normalised HERE, not by the field. Crockford Base32 is
    // case-insensitive and canonically uppercase, so the adopt input used to
    // uppercase what the user typed — which silently destroyed the lowercase
    // `dsm:token/v1:` prefix and made every scanned payload parse as a bare
    // anchor, then fail as invalid Base32. Transforming input is the decoder's
    // job, and the decoder is here.
    let lowered = text.to_ascii_lowercase();
    let stripped = lowered.strip_prefix(TOKEN_ADOPTION_URI_PREFIX).map(|_| {
        text[TOKEN_ADOPTION_URI_PREFIX.len()..]
            .trim()
            .to_ascii_uppercase()
    });

    let Some(body) = stripped else {
        // Bare anchor.
        let upper = text.to_ascii_uppercase();
        let bytes = crate::util::text_id::decode_base32_crockford(&upper)
            .ok_or_else(|| "adopt: not valid Base32 Crockford".to_string())?;
        let anchor: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "adopt: an anchor is 32 bytes, this decoded to {}",
                bytes.len()
            )
        })?;
        return Ok(ParsedAdoptionInput {
            anchor,
            claimed_ticker: None,
            claimed_token_id: None,
        });
    };

    let payload = crate::util::text_id::decode_base32_crockford(&body)
        .ok_or_else(|| "adopt: the code's payload is not valid Base32 Crockford".to_string())?;
    let qr = generated::TokenAdoptionQrV1::decode(&*payload)
        .map_err(|e| format!("adopt: the code is not a v1 token payload: {e}"))?;
    let anchor: [u8; 32] = qr
        .policy_anchor
        .as_slice()
        .try_into()
        .map_err(|_| "adopt: the code carries a malformed anchor".to_string())?;
    Ok(ParsedAdoptionInput {
        anchor,
        claimed_ticker: Some(qr.ticker),
        claimed_token_id: Some(qr.token_id),
    })
}

/// Assemble the complete adoption URI. Rust owns the framing.
pub fn build_adoption_uri(anchor: &[u8; 32], ticker: &str, token_id: &str) -> String {
    let payload = generated::TokenAdoptionQrV1 {
        policy_anchor: anchor.to_vec(),
        ticker: ticker.to_string(),
        token_id: token_id.to_string(),
    }
    .encode_to_vec();
    format!(
        "{TOKEN_ADOPTION_URI_PREFIX}{}",
        crate::util::text_id::encode_base32_crockford(&payload)
    )
}

impl AppRouterImpl {
    /// Re-register every persisted token's policy after a restart.
    ///
    /// The policy system is in-memory, and it fails closed for an unregistered
    /// token — so without this a token created before the restart could not be
    /// transferred, and `dlv.create` (which resolves the pair's policy commit
    /// and fails closed) could not build a vault for it. The durable tables are
    /// the source; this only rebuilds the derived in-memory view.
    /// Install the durable-storage policy resolver used by the enforcer on a
    /// cache miss.
    ///
    /// The enforcer's token→anchor map is process-local, so after a restart it
    /// is empty and every created or adopted token looked policy-less: on
    /// device that surfaced as "Token policy violation for RIGB: No policy
    /// registered for token" while the committed policy sat in
    /// `token_policies` the whole time. Startup warming alone does not fix
    /// that — any row added later, or any warm-up that skipped a row,
    /// reproduces it exactly. So the miss itself consults durable storage.
    ///
    /// Resolution uses the SAME pieces as creation and adoption:
    /// `load_policy_verified` (which re-derives BLAKE3(TAG_DSM_POLICY, bytes)
    /// and treats a mismatch as absent), the one strict `parse_token_policy`,
    /// and the one `derive_policy_file` constructor. There is no second parser
    /// and no second notion of what a policy is.
    pub fn install_policy_resolver(&self) {
        self.core_sdk.set_policy_resolver(std::sync::Arc::new(
            |identifier: &str| -> Option<(
                dsm::types::policy_types::PolicyFile,
                dsm::types::policy_types::PolicyAnchor,
            )> {
                // Accept the canonical id or a registered ticker, same as the
                // resolver the send path uses.
                let row = crate::storage::client_db::token_registry::get_token(identifier)
                    .ok()
                    .flatten()
                    .or_else(|| {
                        crate::storage::client_db::token_registry::get_token_by_ticker(identifier)
                            .ok()
                            .flatten()
                    })?;

                // Anchor equality is enforced inside load_policy_verified: a
                // row whose bytes do not hash to their recorded commitment is
                // reported ABSENT rather than returned.
                let raw = crate::storage::client_db::token_registry::load_policy_verified(
                    &row.policy_commit,
                )
                .ok()
                .flatten()?;

                let parsed = parse_token_policy(&raw)?;
                Some((
                    derive_policy_file(&row.ticker, &parsed),
                    dsm::types::policy_types::PolicyAnchor::from_bytes(row.policy_commit),
                ))
            },
        ));
    }

    /// Keep this device's OWN tokens fetchable by peers.
    ///
    /// Creation now refuses unless the policy reaches a storage node, but a
    /// token created before that rule — or one whose node later lost it —
    /// leaves the network unable to serve a policy this device still holds.
    /// Nobody can adopt such a token, so nobody can receive it, and the
    /// failure appears on the RECEIVER as POLICY_NOT_FOUND long after the
    /// creating device stopped looking.
    ///
    /// So: for each token this device owns, if the network cannot serve the
    /// policy and this device has the bytes, publish them. Content-addressed,
    /// so republishing is idempotent and cannot assert anything false — the
    /// node re-derives the anchor from the bytes, and a mismatch is discarded
    /// by `try_publish_policy_to_network`.
    pub async fn republish_owned_policies(&self) {
        let tokens = match crate::storage::client_db::token_registry::all_tokens() {
            Ok(tokens) => tokens,
            Err(e) => {
                log::warn!("[token] republish: the token registry is unreadable: {e}");
                return;
            }
        };
        let me = self.core_sdk.get_device_identity().device_id;
        for row in tokens.into_iter().filter(|t| t.creator_device_id == me) {
            // Only republish what the network genuinely cannot serve.
            if matches!(
                try_fetch_policy_from_network(&row.policy_commit).await,
                Ok(Some(..))
            ) {
                continue;
            }
            let Ok(Some(bytes)) =
                crate::storage::client_db::token_registry::load_policy_verified(&row.policy_commit)
            else {
                continue;
            };
            let anchor_b32 = crate::util::text_id::encode_base32_crockford(&row.policy_commit);
            match publish_policy_to_network(&bytes, &row.policy_commit).await {
                PublishOutcome::Stored => log::info!(
                    "[token] republished policy {anchor_b32} for owned token {} — peers can \
                     adopt it again",
                    row.ticker
                ),
                PublishOutcome::NotStoredYet(why) => log::warn!(
                    "[token] policy {anchor_b32} for owned token {} is not Stored ({why}); \
                     peers cannot adopt it until a republish succeeds",
                    row.ticker
                ),
            }
        }
    }

    pub async fn rehydrate_token_registry(&self) {
        let tokens = match crate::storage::client_db::token_registry::all_tokens() {
            Ok(t) => t,
            Err(e) => {
                log::warn!("[token] registry rehydrate: cannot read token_registry: {e}");
                return;
            }
        };
        if tokens.is_empty() {
            return;
        }

        let mut restored = 0usize;
        for row in tokens {
            // Seed the display resolver first and unconditionally: even if the
            // policy is momentarily unavailable, the wallet can still NAME the
            // balance rather than omitting it.
            dsm::core::token::register_policy_commit_ticker(row.policy_commit, &row.ticker);

            let Ok(Some(raw_proto)) =
                crate::storage::client_db::token_registry::load_policy_verified(&row.policy_commit)
            else {
                log::warn!(
                    "[token] registry rehydrate: policy missing/corrupt for {}; it stays \
                     unusable until the policy is re-fetched",
                    row.token_id
                );
                continue;
            };
            let Some(parsed) = parse_token_policy(&raw_proto) else {
                log::warn!(
                    "[token] registry rehydrate: policy for {} no longer parses",
                    row.token_id
                );
                continue;
            };

            {
                let mut cache = self.policy_cache.lock().await;
                cache.insert(row.policy_commit, raw_proto);
            }

            let policy_file = derive_policy_file(&row.ticker, &parsed);
            if let Err(e) = self
                .core_sdk
                .register_token_policy_with_anchor(&row.token_id, policy_file, row.policy_commit)
                .await
            {
                log::warn!(
                    "[token] registry rehydrate: register failed for {}: {e}",
                    row.token_id
                );
                continue;
            }

            // Re-seed the metadata cache so strict policy-commit resolution
            // works without a chain scan.
            let anchor_b32 = crate::util::text_id::encode_base32_crockford(&row.policy_commit);
            let mut fields = HashMap::new();
            fields.insert("genesis_supply".to_string(), row.genesis_supply.to_string());
            fields.insert("policy_anchor".to_string(), anchor_b32.clone());
            fields.insert("kind".to_string(), "FUNGIBLE".to_string());
            let metadata = TokenMetadata {
                token_id: row.token_id.clone(),
                name: row.alias.clone(),
                symbol: row.ticker.clone(),
                description: parsed.description.clone(),
                icon_url: parsed.icon_url.clone(),
                decimals: row.decimals.min(18) as u8,
                token_type: TokenType::Created,
                owner_id: row.creator_device_id,
                metadata_uri: None,
                policy_anchor: Some(format!("dsm:policy:{anchor_b32}")),
                fields,
            };
            if let Err(e) = self.wallet.token_sdk.cache_token_metadata_strict(metadata) {
                log::warn!(
                    "[token] registry rehydrate: metadata cache failed for {}: {e}",
                    row.token_id
                );
                continue;
            }
            restored += 1;
        }

        if restored > 0 {
            log::info!("[token] registry rehydrate: restored {restored} token(s) after restart");
        }
    }

    /// Persist an anchored policy, then cache it. `token_policies` is the
    /// durable store, so a policy survives restart; the in-memory map only
    /// ever holds what the store holds.
    async fn cache_policy_bytes(
        &self,
        anchor: [u8; 32],
        policy_bytes: Vec<u8>,
    ) -> Result<(), String> {
        crate::storage::client_db::token_registry::upsert_policy(&anchor, &policy_bytes)
            .map_err(|e| format!("failed to persist policy: {e}"))?;
        self.policy_cache.lock().await.insert(anchor, policy_bytes);
        Ok(())
    }

    /// Resolve policy bytes: memory cache → durable table → storage nodes.
    ///
    /// The table read re-verifies that the bytes hash to the anchor; a
    /// corrupted row, or a table that cannot be read, is an error.
    async fn load_policy_bytes(&self, anchor: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        if let Some(bytes) = self.policy_cache.lock().await.get(&anchor).cloned() {
            return Ok(Some(bytes));
        }

        if let Some(bytes) =
            crate::storage::client_db::token_registry::load_policy_verified(&anchor)
                .map_err(|e| format!("the token policy table is unreadable: {e}"))?
        {
            self.policy_cache.lock().await.insert(anchor, bytes.clone());
            return Ok(Some(bytes));
        }

        if let Some(bytes) = try_fetch_policy_from_network(&anchor).await? {
            self.cache_policy_bytes(anchor, bytes.clone()).await?;
            return Ok(Some(bytes));
        }

        Ok(None)
    }

    // ── Token Queries ────────────────────────────────────────────────────────
    pub(crate) async fn handle_token_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // The anchor a creator hands to a peer, as a scannable payload.
            //
            // Params are the ticker or token id, UTF-8. The reply carries the
            // complete URI plus the fields a screen shows beside it, so the
            // frontend renders strings and derives nothing.
            "token.adoptionQr" => {
                let key = String::from_utf8_lossy(&q.params).trim().to_string();
                if key.is_empty() {
                    return err("token.adoptionQr: params must name a ticker or token id".into());
                }
                if crate::policy::builtin_policy_commit(&key).is_some() {
                    return err(format!(
                        "token.adoptionQr: {key} is a protocol asset — every device already has it"
                    ));
                }
                let row = match crate::storage::client_db::token_registry::get_token(&key) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        match crate::storage::client_db::token_registry::get_token_by_ticker(&key) {
                            Ok(Some(r)) => r,
                            Ok(None) => {
                                return err(format!("token.adoptionQr: no token named {key} here"))
                            }
                            Err(e) => return err(format!("token.adoptionQr: registry read: {e}")),
                        }
                    }
                    Err(e) => return err(format!("token.adoptionQr: registry read: {e}")),
                };
                let anchor_b32 = crate::util::text_id::encode_base32_crockford(&row.policy_commit);
                pack_envelope_ok(generated::envelope::Payload::TokenAdoptionQrResponse(
                    generated::TokenAdoptionQrResponse {
                        uri: build_adoption_uri(&row.policy_commit, &row.ticker, &row.token_id),
                        ticker: row.ticker,
                        token_id: row.token_id,
                        anchor_fingerprint: anchor_b32.chars().take(8).collect(),
                        policy_anchor_b32: anchor_b32,
                    },
                ))
            }

            "tokens.getPolicy" => {
                if q.params.len() != 32 {
                    return err(
                        "tokens.getPolicy: params must be exactly 32 bytes (policy anchor)".into(),
                    );
                }
                let anchor: [u8; 32] = match q.params[..].try_into() {
                    Ok(a) => a,
                    Err(_) => return err("tokens.getPolicy: invalid anchor length".into()),
                };

                match self.load_policy_bytes(anchor).await {
                    Ok(Some(raw_bytes)) => AppResult {
                        success: true,
                        data: raw_bytes,
                        error_message: None,
                    },
                    Ok(None) => err("tokens.getPolicy: policy not found".into()),
                    Err(e) => err(format!("tokens.getPolicy failed: {e}")),
                }
            }

            // Adopt a token created by someone else, by its CPTA anchor.
            //
            // A device cannot hold or move a token whose policy it does not
            // have: balances are keyed by policy commitment, and the enforcer
            // needs the committed rules to decide anything. Creating a token
            // registers it on the creator's device only — every other device
            // has to ADD it, which is this route. Without it a freshly created
            // token can never be received, which is exactly how a transfer to
            // a second device fails with nothing obviously wrong.
            //
            // This is a local registration, not a state transition: no advance,
            // no balance change, and no fee. Only the creator burns the fee.
            //
            // The anchor is re-derived from the fetched bytes and must match
            // what was asked for. That is the same rule creation enforces, and
            // for the same reason: a storage node that could hand back
            // arbitrary bytes under a requested anchor would be defining the
            // policy this device then enforces.
            "tokens.addByAnchor" => {
                // Params are the TEXT the user supplied — a bare Base32 anchor
                // or a `dsm:token/v1:` payload from a scan. Both are decoded
                // here rather than in the client, so there is one decoder and
                // one place that decides what a pasted string means.
                let input = match parse_adoption_input(&String::from_utf8_lossy(&q.params)) {
                    Ok(v) => v,
                    Err(e) => return err(format!("tokens.addByAnchor: {e}")),
                };
                let anchor = input.anchor;

                let policy_bytes = match self.load_policy_bytes(anchor).await {
                    Ok(Some(b)) if !b.is_empty() => b,
                    Ok(_) => {
                        return err(
                            "POLICY_NOT_FOUND: no policy is published under that anchor".into()
                        )
                    }
                    Err(e) => return err(format!("tokens.addByAnchor: {e}")),
                };

                let mut ah = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_DSM_POLICY,
                );
                ah.update(&policy_bytes);
                let derived: [u8; 32] = *ah.finalize().as_bytes();
                if derived != anchor {
                    return err(
                        "tokens.addByAnchor: fetched policy does not hash to the requested anchor"
                            .into(),
                    );
                }

                let Some(parsed) = parse_token_policy(&policy_bytes) else {
                    return err(
                        "tokens.addByAnchor: policy is not a readable v3 token policy".into(),
                    );
                };

                let mut id_hasher = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_DSM_TOKEN_ID,
                );
                id_hasher.update(&anchor);
                id_hasher.update(parsed.ticker.as_bytes());
                let token_id =
                    crate::util::text_id::encode_base32_crockford(id_hasher.finalize().as_bytes());

                // A scanned payload CLAIMS what it resolves to. The anchor
                // already had to hash the fetched policy, so the claims cannot
                // change which token is adopted — but a payload that names a
                // different ticker than the policy carries is either corrupt or
                // is trying to get a user to accept something other than what
                // they were shown. Refuse rather than silently adopt the real
                // one under a name the user did not read.
                if let Some(claimed) = input.claimed_ticker.as_deref() {
                    if !claimed.eq_ignore_ascii_case(&parsed.ticker) {
                        return err(format!(
                            "tokens.addByAnchor: the code says {claimed} but the published policy \
                             is {}. Refusing — check the anchor with whoever sent it.",
                            parsed.ticker
                        ));
                    }
                }
                if let Some(claimed) = input.claimed_token_id.as_deref() {
                    if claimed != token_id {
                        return err(
                            "tokens.addByAnchor: the code's token id does not match the one its \
                             own anchor derives. Refusing."
                                .into(),
                        );
                    }
                }

                // Adding the same token twice is a no-op, not an error — a user
                // who taps twice, or adds a token they already hold, has done
                // nothing wrong. A DIFFERENT token claiming the ticker is a
                // conflict and is refused.
                match crate::storage::client_db::token_registry::get_token_by_ticker(&parsed.ticker)
                {
                    Ok(Some(row)) if row.token_id != token_id => {
                        return err(format!(
                            "TICKER_CONFLICT: {} is already held by a different token on this \
                             device; adopting this one would make the ticker ambiguous",
                            parsed.ticker
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => return err(format!("tokens.addByAnchor: registry read failed: {e}")),
                }

                // THE AUTHENTICATED PART OF ADDING A TOKEN (owner ruling
                // 2026-09-13). The registry rows below are local bookkeeping;
                // the adoption LEAF is what every later credit of this token is
                // checked against in `DeviceState::advance`, so the device can
                // validate what it accepts from its OWN committed state — with
                // no connectivity at the moment of receipt. No fee, no balance
                // delta; committed first, so nothing is registered that the
                // state does not stand behind. Idempotent: an adopted token is
                // not re-advanced.
                {
                    let Some(head) = self.core_sdk.device_head() else {
                        return err(
                            "tokens.addByAnchor: no device head; adoption must be committed to \
                             state before the token can be held"
                                .into(),
                        );
                    };
                    if !head.has_adopted(&anchor) {
                        let dev_id = self.device_id_bytes;
                        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                            &dev_id, &dev_id,
                        );
                        let unsigned = dsm::types::operations::Operation::AdoptToken {
                            policy_commit: anchor,
                            signature: Vec::new(),
                        };
                        let signed = match self.core_sdk.sign_operation_sphincs(unsigned) {
                            Ok(s) => s,
                            Err(e) => {
                                return err(format!(
                                    "tokens.addByAnchor: adoption could not be signed: {e}"
                                ))
                            }
                        };
                        if let Err(e) = self.core_sdk.execute_on_relationship_guarded(
                            rel_key,
                            dev_id,
                            signed,
                            &[],
                            None,
                            None,
                        ) {
                            return err(format!(
                                "tokens.addByAnchor: adoption could not be committed to state: {e}"
                            ));
                        }
                    }
                }

                if let Err(e) =
                    crate::storage::client_db::token_registry::upsert_policy(&anchor, &policy_bytes)
                {
                    return err(format!("tokens.addByAnchor: could not store policy: {e}"));
                }
                let row = crate::storage::client_db::token_registry::TokenRegistryRow {
                    token_id: token_id.clone(),
                    policy_commit: anchor,
                    ticker: parsed.ticker.clone(),
                    alias: parsed.alias.clone(),
                    decimals: parsed.decimals,
                    genesis_supply: parsed.genesis_supply,
                    creator_device_id: parsed.creator_device_id,
                };
                if let Err(e) = crate::storage::client_db::token_registry::insert_token(&row) {
                    // Already present is the idempotent case, not a failure.
                    if crate::storage::client_db::token_registry::get_token(&token_id)
                        .ok()
                        .flatten()
                        .is_none()
                    {
                        return err(format!("tokens.addByAnchor: could not register token: {e}"));
                    }
                }

                dsm::core::token::register_policy_commit_ticker(anchor, &parsed.ticker);

                // Tell the wallet its token set changed, from HERE — the
                // registry write is what made it true, so the notification
                // belongs beside it. The screen then reloads from the
                // persisted registry rather than trusting anything the caller
                // believes; an adopted token that is only in frontend state is
                // a token this device cannot actually hold.
                push_wallet_refresh();

                pack_envelope_ok(generated::envelope::Payload::TokenCreateResponse(
                    generated::TokenCreateResponse {
                        success: true,
                        token_id,
                        policy_anchor: anchor.to_vec(),
                        message: format!("Added {}", parsed.ticker),
                    },
                ))
            }

            "tokens.listCachedPolicies" => {
                // The durable table is the source of truth; the in-memory map
                // is only a read cache and can add nothing it does not have.
                let mut anchors: BTreeSet<[u8; 32]> =
                    match crate::storage::client_db::token_registry::all_policies() {
                        Ok(rows) => rows.into_iter().map(|(commit, _)| commit).collect(),
                        Err(e) => {
                            return err(format!("tokens.listCachedPolicies failed: {e}"));
                        }
                    };
                {
                    let cache = self.policy_cache.lock().await;
                    for anchor in cache.keys() {
                        anchors.insert(*anchor);
                    }
                }

                let mut policies = Vec::new();
                for anchor in anchors {
                    let policy_bytes = match self.load_policy_bytes(anchor).await {
                        Ok(Some(bytes)) => bytes,
                        Ok(None) => continue,
                        Err(e) => return err(format!("tokens.listCachedPolicies failed: {e}")),
                    };
                    // Skip anything that no longer parses rather than listing a
                    // blank row — an unreadable policy is not a policy.
                    let Some(meta) = parse_token_policy(&policy_bytes) else {
                        continue;
                    };
                    policies.push(generated::TokenPolicyCacheEntry {
                        policy_commit: anchor.to_vec(),
                        policy_bytes,
                        ticker: meta.ticker,
                        alias: meta.alias,
                        decimals: meta.decimals,
                        max_supply: meta.genesis_supply.to_string(),
                    });
                }

                let reply = generated::TokenPolicyListResponse { policies };
                pack_envelope_ok(generated::envelope::Payload::TokenPolicyListResponse(reply))
            }

            "tokens.getFeeSchedule" => {
                // Reads the same core constant the conservation guard
                // validates against, so the displayed fee can never disagree
                // with the fee actually charged.
                pack_envelope_ok(generated::envelope::Payload::TokenFeeScheduleResponse(
                    generated::TokenFeeScheduleResponse {
                        token_creation_era: dsm::core::token::TOKEN_CREATION_FEE_ERA,
                    },
                ))
            }

            other => err(format!("unknown token query path: {other}")),
        }
    }

    // ── Token Invokes ────────────────────────────────────────────────────────
    pub(crate) async fn handle_token_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "token.create" => {
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("token.create: ArgPack.codec must be PROTO".into());
                }

                let req = match generated::TokenCreateRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode TokenCreateRequest failed: {e}")),
                };

                let ticker = req.ticker.trim().to_uppercase();
                if ticker.len() < 2 || ticker.len() > 8 {
                    return err("token.create: ticker must be 2-8 chars".into());
                }
                if req.alias.trim().is_empty() {
                    return err("token.create: alias required".into());
                }
                if req.decimals > 18 {
                    return err("token.create: decimals must be 0..18".into());
                }
                if req.genesis_supply_u128.len() != 16 {
                    return err("token.create: genesis_supply_u128 must be 16 bytes".into());
                }
                let be_u128 = |b: &[u8]| -> u128 {
                    let mut v = 0u128;
                    for x in b {
                        v = (v << 8) | (*x as u128);
                    }
                    v
                };
                // Canonical amounts are integer BASE UNITS; the wizard speaks
                // display units. Conversion happens exactly once, here, before
                // anything commits to a number: policy serialization and anchor
                // derivation, CreateToken, conservation validation, registry
                // persistence, and the supply cap all take the converted value.
                //
                // Creation used to skip this while the send path applied it, so
                // a token created with "1,000" at decimals=2 held 1_000 base
                // units (10.00) while a send of "250" correctly debited 25_000
                // — and the transfer failed with a balance underflow on a
                // balance the UI displayed as 1000. The two sides disagreed
                // about what a unit was.
                //
                // The CPTA anchor therefore commits the base-unit cap. A policy
                // that committed a display number would mean the cap enforced
                // depends on how a UI chose to render it.
                let scale = 10u128
                    .checked_pow(req.decimals)
                    .ok_or_else(|| "token.create: decimals too large to scale".to_string());
                let scale = match scale {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let to_base = |display: u128, what: &str| -> Result<u128, String> {
                    display.checked_mul(scale).ok_or_else(|| {
                        format!(
                            "token.create: {what} overflows at {} decimals",
                            req.decimals
                        )
                    })
                };
                // The genesis supply: the whole supply that will ever exist
                // (SoFi §47, §51). In beta a user-created token releases all of
                // it to its creator in the transition that creates it
                // (`ReleaseRule::AllAtCreation`, owner 2026-09-23). Nothing is
                // minted afterwards, and no supply is unlimited.
                let genesis_supply =
                    match to_base(be_u128(&req.genesis_supply_u128), "genesis supply") {
                        Ok(v) => v,
                        Err(e) => return err(e),
                    };
                if genesis_supply == 0 {
                    return err("token.create: the genesis supply must be positive".into());
                }

                let mut allowlist_device_ids: Vec<[u8; 32]> = Vec::new();
                for id in &req.allowlist_device_ids {
                    match <[u8; 32]>::try_from(id.as_slice()) {
                        Ok(v) => allowlist_device_ids.push(v),
                        Err(_) => {
                            return err(
                                "token.create: allowlist device ids must be 32 bytes".into()
                            );
                        }
                    }
                }

                // The policy's signer set. The creating device is the sole
                // member by default — the client never supplies a key, so it
                // cannot name a signer it does not control. The set authorizes
                // only what the policy's own rules name, and never issuance.
                //
                // The signing authority's public key, not the AppState
                // identity blob: the blob commits the creator's own key, and
                // a release rule that names the signer set (none does in beta)
                // would verify against it.
                let creator_pk = match crate::sdk::signing_authority::current_public_key() {
                    Ok(pk) => pk,
                    Err(e) => {
                        return err(format!("token.create: signing identity unavailable: {e}"));
                    }
                };
                // The client's threshold, as it asked: a value the policy cannot
                // hold is refused, never moved into range.
                let threshold = match u8::try_from(req.threshold) {
                    Ok(t) if t >= 1 => t,
                    Ok(..) | Err(..) => {
                        return err(format!(
                            "token.create: threshold {} is not in 1..=255",
                            req.threshold
                        ))
                    }
                };
                // The creator the policy binds (SoFi Amendment S8): this device,
                // from its head.
                let Some(head) = self.core_sdk.device_head() else {
                    return err("token.create: no device head".into());
                };
                let (creator_genesis, creator_device_id) = (head.genesis_digest(), head.devid());
                let parsed = ParsedTokenPolicy {
                    creator_genesis,
                    creator_device_id,
                    ticker: ticker.clone(),
                    alias: req.alias.trim().to_string(),
                    decimals: req.decimals,
                    genesis_supply,
                    release_rule: ReleaseRule::AllAtCreation,
                    description: Some(req.description.trim().to_string()).filter(|s| !s.is_empty()),
                    icon_url: Some(req.icon_url.trim().to_string()).filter(|s| !s.is_empty()),
                    burn_enabled: req.burn_enabled,
                    transferable: req.transferable,
                    threshold,
                    signers: vec![creator_pk],
                    allowlist_device_ids,
                };

                // Pack the canonical policy HERE. The blob is protocol: it is
                // hashed into the CPTA anchor and fixes the token's supply and
                // rules, so Rust is the only layer permitted to construct it.
                let policy_bytes = match build_policy_v3_bytes(&parsed) {
                    Ok(b) => b,
                    Err(e) => return err(format!("token.create: {e}")),
                };
                let raw_proto = generated::TokenPolicyV3 {
                    policy_bytes: policy_bytes.clone(),
                }
                .encode_to_vec();

                // Round-trip the blob before committing to it: what we enforce
                // must be exactly what we packed, and it must satisfy every
                // parse invariant a remote verifier will apply.
                let Some(parsed) = parse_token_policy(&raw_proto) else {
                    return err(
                        "token.create: packed policy failed its own validation — refusing to \
                         create a token whose policy cannot be re-read"
                            .into(),
                    );
                };

                // The anchor is the content hash of those exact bytes.
                let policy_anchor: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
                    dsm::common::domain_tags::TAG_DSM_POLICY,
                    &raw_proto,
                );

                // A new token may NEVER be issued under an existing asset's
                // policy commit. The anchor becomes the `policy_commit` on the
                // issuance BalanceDelta, so a colliding anchor would credit a
                // builtin asset (e.g. real ERA) instead of the new token.
                if let Some(builtin) =
                    dsm::core::token::builtin_token_id_for_policy_commit(&policy_anchor)
                {
                    return err(format!(
                        "token.create: policy_anchor collides with builtin asset {builtin}"
                    ));
                }

                let anchor_b32 = crate::util::text_id::encode_base32_crockford(&policy_anchor);

                // Mirror the policy so peers can fetch it. Adoption is
                // online-only by design — a peer fetches these bytes from a
                // storage node and caches them, and that cache is what makes
                // the token usable offline afterwards — so a policy no node
                // holds is a token nobody can ever adopt or receive.
                //
                // Creation does NOT refuse when the mirror fails. DSM is
                // offline-first, and a device with no reachable node is the
                // ordinary case, not an error; refusing would make creating a
                // token require connectivity that nothing else here requires.
                // Convergence is handled instead: `republish_owned_policies`
                // runs at every startup and publishes any owned policy the
                // network cannot serve, so the token becomes adoptable as soon
                // as this device is online. What is NOT acceptable is silence,
                // because the failure otherwise surfaces only on a peer, as
                // POLICY_NOT_FOUND, long afterwards.
                match publish_policy_to_network(&raw_proto, &policy_anchor).await {
                    PublishOutcome::Stored => {}
                    PublishOutcome::NotStoredYet(why) => log::warn!(
                        "[token.create] policy {anchor_b32} is not Stored ({why}); peers cannot \
                         adopt this token until a later startup republishes it"
                    ),
                }
                if let Err(e) = self
                    .cache_policy_bytes(policy_anchor, raw_proto.clone())
                    .await
                {
                    return err(format!("token.create: {e}"));
                }

                let mut id_hasher = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_DSM_TOKEN_ID,
                );
                id_hasher.update(&policy_anchor);
                id_hasher.update(ticker.as_bytes());
                let token_id =
                    crate::util::text_id::encode_base32_crockford(id_hasher.finalize().as_bytes());

                // ── Canonical reconciliation, before anything is spent ──────
                //
                // `token_id` is BLAKE3(TAG_DSM_TOKEN_ID, policy_anchor ‖ ticker)
                // and `policy_anchor` is the content address of the whole
                // policy, so this id IS the creation commitment: identical
                // inputs can only produce it, and any changed field produces a
                // different one. That makes "has this exact creation already
                // happened?" a lookup rather than a guess.
                //
                // It has to be a lookup, because a caller cannot tell a
                // creation that failed from one that succeeded with its reply
                // lost. On device the first attempt committed — fee burned,
                // supply credited — while the reply never arrived, and the
                // wizard reported "Token creation failed". Retrying then hit
                // the registry's UNIQUE constraint and failed again, so a
                // successful creation looked like two failures.
                //
                // A repeated submission of the SAME commitment is therefore
                // answered from canonical state: success, no second advance,
                // and no second fee. A different commitment claiming a taken
                // ticker is a hard conflict, never silently accepted.
                match crate::storage::client_db::token_registry::get_token(&token_id) {
                    Ok(Some(row)) if row.policy_commit == policy_anchor => {
                        log::info!(
                            "[token.create] {ticker} already exists with this exact commitment; \
                             reporting the existing token rather than creating a second one"
                        );
                        return pack_envelope_ok(
                            generated::envelope::Payload::TokenCreateResponse(
                                generated::TokenCreateResponse {
                                    success: true,
                                    token_id,
                                    policy_anchor: policy_anchor.to_vec(),
                                    message: "Token already created".to_string(),
                                },
                            ),
                        );
                    }
                    Ok(Some(_)) => {
                        // Same derived id, different committed policy. The hash
                        // makes this unreachable without a collision; refuse
                        // rather than pretend it is the caller's token.
                        return err(format!(
                            "token.create: {ticker} exists under a different committed policy"
                        ));
                    }
                    Ok(None) => {}
                    Err(e) => return err(format!("token.create: registry read failed: {e}")),
                }
                match crate::storage::client_db::token_registry::get_token_by_ticker(&ticker) {
                    Ok(Some(row)) if row.token_id != token_id => {
                        return err(format!(
                            "token.create: ticker {ticker} is already held by a different token \
                             created with different parameters"
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => return err(format!("token.create: registry read failed: {e}")),
                }

                let mut fields = HashMap::new();
                fields.insert(
                    "genesis_supply".to_string(),
                    parsed.genesis_supply.to_string(),
                );
                fields.insert("policy_anchor".to_string(), anchor_b32.clone());
                fields.insert("kind".to_string(), "FUNGIBLE".to_string());
                fields.insert("burn_enabled".to_string(), parsed.burn_enabled.to_string());
                fields.insert("transferable".to_string(), parsed.transferable.to_string());
                fields.insert("threshold".to_string(), parsed.threshold.to_string());

                let metadata = TokenMetadata {
                    token_id: token_id.clone(),
                    name: req.alias.clone(),
                    symbol: ticker.clone(),
                    description: parsed.description.clone(),
                    icon_url: parsed.icon_url.clone(),
                    decimals: (req.decimals as u8).min(18),
                    token_type: TokenType::Created,
                    owner_id: self.device_id_bytes,
                    metadata_uri: None,
                    policy_anchor: Some(format!("dsm:policy:{}", anchor_b32)),
                    fields,
                };

                // Single source of truth for what the policy means — the
                // same function restart rehydration uses.
                let policy_file = derive_policy_file(&ticker, &parsed);

                // Register policy mapping under the derived anchor so
                // token_id -> policy_commit stays stable.
                if let Err(e) = self
                    .core_sdk
                    .register_token_policy_with_anchor(&token_id, policy_file, policy_anchor)
                    .await
                {
                    return err(format!("token.create: register_token_policy failed: {e}"));
                }
                let policy_commit: [u8; 32] = policy_anchor;

                // Cache authoritative TokenMetadata (no Generic shim op).
                if let Err(e) = self
                    .wallet
                    .token_sdk
                    .cache_token_metadata_strict(metadata.clone())
                {
                    return err(format!("token.create: metadata cache failed: {e}"));
                }

                // ── Creation: ONE canonical advance carrying both legs ──
                //
                // The fee burn and the release of the whole genesis supply to
                // the creator land in a single DeviceState::advance — one SMT
                // root, one CAS — so either the token exists with its supply
                // released and the fee paid, or none of it happened
                // (`ReleaseRule::AllAtCreation`, SoFi §51, owner 2026-09-23).
                let genesis_u64: u64 = match u64::try_from(parsed.genesis_supply) {
                    Ok(v) => v,
                    Err(_) => {
                        return err(
                            "token.create: genesis supply exceeds u64::MAX (Balance is u64)".into(),
                        );
                    }
                };

                let fee_amount = dsm::core::token::TOKEN_CREATION_FEE_ERA;
                let dev_id = creator_device_id;
                let device_txt = crate::util::text_id::encode_base32_crockford(&dev_id);

                // Reject insufficient ERA BEFORE anything is committed. The
                // advance's checked_sub is the backstop; this is the clear
                // error the caller can act on.
                if fee_amount > 0 {
                    let era_commit = match dsm::core::token::builtin_policy_commit_for_token("ERA")
                    {
                        Some(c) => c,
                        None => return err("token.create: ERA policy commit missing".into()),
                    };
                    let era_balance = head.balance(&era_commit);
                    if era_balance < fee_amount {
                        return err(format!(
                            "token.create: insufficient ERA for the {fee_amount} ERA creation fee \
                             (have {era_balance}) — claim from the faucet and retry"
                        ));
                    }
                }

                let create_op = dsm::types::operations::Operation::CreateToken {
                    token_id: token_id.as_bytes().to_vec(),
                    initial_supply: dsm::types::token_types::Balance::amount(genesis_u64),
                    policy_commit,
                    fee_amount,
                    name: parsed.alias.clone(),
                    symbol: ticker.clone(),
                    decimals: parsed.decimals.min(18) as u8,
                    metadata_uri: Some(format!("dsm:policy:{anchor_b32}")),
                    // No verifier reads a self-loop operation's signature:
                    // the creating transition is what the device signs, and
                    // the creator is bound by the policy (Amendment S8).
                    // Empty, rather than 50 KB nothing checks.
                    signature: Vec::new(),
                };

                // Positional, exactly as the conservation guard requires:
                // [0] the ERA fee debit, [1] the release of the whole genesis
                // supply to the creator.
                let mut deltas: Vec<dsm::types::device_state::BalanceDelta> = Vec::new();
                if fee_amount > 0 {
                    let era_commit = match dsm::core::token::builtin_policy_commit_for_token("ERA")
                    {
                        Some(c) => c,
                        None => return err("token.create: ERA policy commit missing".into()),
                    };
                    deltas.push(dsm::types::device_state::BalanceDelta {
                        policy_commit: era_commit,
                        direction: dsm::types::device_state::BalanceDirection::Debit,
                        amount: fee_amount,
                    });
                }
                deltas.push(dsm::types::device_state::BalanceDelta {
                    policy_commit,
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: genesis_u64,
                });

                // The registry row lands INSIDE the advance transaction. A
                // failed creation therefore leaves no row, and a concurrent
                // duplicate hits PRIMARY KEY(token_id) / UNIQUE(ticker) and
                // rolls the ENTIRE advance back — exactly-once against the
                // database and canonical state together, not merely
                // idempotent-looking.
                let registry_row = crate::storage::client_db::token_registry::TokenRegistryRow {
                    token_id: token_id.clone(),
                    policy_commit: policy_anchor,
                    ticker: ticker.clone(),
                    alias: parsed.alias.clone(),
                    decimals: parsed.decimals,
                    genesis_supply: parsed.genesis_supply,
                    creator_device_id,
                };
                let insert_registry = |tx: &rusqlite::Transaction<'_>,
                                       &dsm::types::device_state::AdvanceOutcome { .. }: &dsm::types::device_state::AdvanceOutcome|
                 -> Result<(), dsm::types::error::DsmError> {
                    crate::storage::client_db::token_registry::insert_token_with_conn(
                        tx,
                        &registry_row,
                    )
                    .map_err(|e| {
                        dsm::types::error::DsmError::invalid_operation(format!(
                            "token {} already exists or conflicts with an existing token: {e}",
                            registry_row.ticker
                        ))
                    })
                };

                // Creation is always an ADMITTED economic transition: it writes
                // the creator's credit of the whole genesis supply, funded by the
                // genesis release (`0x005F`), beside the ERA fee debit, as one
                // write set (SoFi §51). The registry row rides the SAME
                // transaction via the composed in-tx writer.
                let outcome =
                    match crate::sdk::economic_admission_flow::admitted_self_loop_operation(
                        &self.core_sdk,
                        create_op,
                        &deltas,
                        dsm::economic::write_set::CreditSourceFacts::GenesisRelease,
                        Vec::new(),
                        Some(&insert_registry),
                    )
                    .await
                    {
                        Ok((o, ..)) => o,
                        Err(e) => return err(format!("token.create: {e}")),
                    };

                // Projections for BOTH assets the advance moved.
                {
                    if let Err(e) =
                        crate::storage::client_db::build_balance_projection_from_device_head(
                            &device_txt,
                            &ticker,
                            &policy_commit,
                            &outcome.new_device_state,
                            genesis_u64,
                            0,
                        )
                        .and_then(|record| {
                            crate::storage::client_db::upsert_balance_projection(&record)
                        })
                    {
                        log::warn!(
                            "[token.create] projection write failed for {ticker} (canonical state \
                             is correct; a repair sweep will reconcile): {e}"
                        );
                    }
                }
                if fee_amount > 0 {
                    if let Some(era_commit) =
                        dsm::core::token::builtin_policy_commit_for_token("ERA")
                    {
                        let era_after = outcome.new_device_state.balance(&era_commit);
                        if let Err(e) = crate::storage::client_db::get_locked_balance(
                            &device_txt,
                            "ERA",
                        )
                        .and_then(|locked| {
                            crate::storage::client_db::build_balance_projection_from_device_head(
                                &device_txt,
                                "ERA",
                                &era_commit,
                                &outcome.new_device_state,
                                era_after,
                                locked,
                            )
                        })
                        .and_then(|record| {
                            crate::storage::client_db::upsert_balance_projection(&record)
                        }) {
                            log::warn!("[token.create] ERA projection write failed: {e}");
                        }
                    }
                }

                let resp = generated::TokenCreateResponse {
                    success: true,
                    token_id,
                    policy_anchor: policy_anchor.to_vec(),
                    message: "Token created".to_string(),
                };
                pack_envelope_ok(generated::envelope::Payload::TokenCreateResponse(resp))
            }

            "tokens.publishPolicy" => {
                let body: &[u8] = i.args.as_slice();
                if body.is_empty() {
                    return err("tokens.publishPolicy: empty body".into());
                }
                // Only a policy Core's one parser accepts is published: the
                // network holds it under the anchor devices adopt a token by.
                if let Err(e) = dsm::economic::token_policy::parse_token_policy(body) {
                    return err(format!("tokens.publishPolicy: not a token policy: {e}"));
                }

                // The anchor is the content hash, always. Publication is
                // best-effort mirroring and can never change it.
                let anchor: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
                    dsm::common::domain_tags::TAG_DSM_POLICY,
                    body,
                );
                if let Err(e) = self.cache_policy_bytes(anchor, body.to_vec()).await {
                    return err(format!("tokens.publishPolicy: {e}"));
                }
                // Kept locally either way, and republished at startup; the
                // route answers what happened on the network.
                match publish_policy_to_network(body, &anchor).await {
                    PublishOutcome::Stored => AppResult {
                        success: true,
                        data: anchor.to_vec(),
                        error_message: None,
                    },
                    PublishOutcome::NotStoredYet(why) => err(format!(
                        "tokens.publishPolicy: the policy is not Stored on the network ({why}); \
                         it is kept on this device and republished at startup"
                    )),
                }
            }

            "token.forget" => self.handle_token_forget(i).await,
            "token.burn" => self.handle_token_burn(i).await,

            other => err(format!("unknown token invoke method: {other}")),
        }
    }

    /// Forget a token's IDENTITY on this device.
    ///
    /// A ticker names one token, so adopting a token whose ticker is already
    /// claimed by a DIFFERENT one is refused — otherwise "RIGB" would be
    /// ambiguous and a transfer could credit the wrong asset. That guard is
    /// right, but with no way to drop a superseded identity it was also a
    /// dead end: a device that had adopted a token could never adopt any
    /// other token with that ticker, ever, and the wallet offered no way out.
    ///
    /// Forgetting removes the NAMING only, and is refused while the balance is
    /// non-zero — a device must not be able to make an asset it still holds
    /// unnameable. Builtins are not forgettable at all: they are protocol
    /// assets, not adopted ones.
    ///
    /// This loses nothing recoverable. The policy is content-addressed and
    /// adoption is online, so the same token can be adopted again from its
    /// anchor.
    async fn handle_token_forget(&self, i: AppInvoke) -> AppResult {
        let arg_pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("token.forget: decode ArgPack failed: {e}")),
        };
        let req = match generated::TokenForgetRequest::decode(&*arg_pack.body) {
            Ok(r) => r,
            Err(e) => return err(format!("token.forget: decode request failed: {e}")),
        };
        let key = req.token_id.trim();
        if key.is_empty() {
            return err("token.forget: token_id is required".into());
        }

        if crate::policy::builtin_policy_commit(key).is_some() {
            return err(format!(
                "token.forget: {key} is a protocol asset and cannot be forgotten"
            ));
        }

        let row = match crate::storage::client_db::token_registry::get_token(key) {
            Ok(Some(r)) => r,
            Ok(None) => match crate::storage::client_db::token_registry::get_token_by_ticker(key) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return err(format!("token.forget: no token named {key} on this device"))
                }
                Err(e) => return err(format!("token.forget: registry read failed: {e}")),
            },
            Err(e) => return err(format!("token.forget: registry read failed: {e}")),
        };

        // Canonical state decides whether anything is held — not the registry.
        // The router is built only over a device head (`AppRouterImpl::new`),
        // so this is never `None` on a live router; were it, the balance is
        // unknown, never zero.
        let held =
            match self.core_sdk.device_head() {
                Some(h) => h.balance(&row.policy_commit),
                None => return err(
                    "token.forget: no device state is loaded, so the balance cannot be established"
                        .into(),
                ),
            };
        if held != 0 {
            return err(format!(
                "token.forget: {} still holds {} base units; send or burn them first",
                row.ticker, held
            ));
        }

        match crate::storage::client_db::token_registry::delete_token(&row.token_id) {
            Ok(Some(removed)) => {
                log::info!(
                    "[token.forget] dropped identity {} ({}) — its ticker is adoptable again",
                    removed.ticker,
                    removed.token_id
                );
                push_wallet_refresh();
                pack_envelope_ok(generated::envelope::Payload::TokenForgetResponse(
                    generated::TokenForgetResponse {
                        success: true,
                        token_id: removed.token_id,
                        message: format!("{} forgotten", removed.ticker),
                    },
                ))
            }
            Ok(None) => err(format!(
                "token.forget: {key} vanished before it was removed"
            )),
            Err(e) => err(format!("token.forget: could not remove {key}: {e}")),
        }
    }

    /// Resolve a token to its committed policy commit, failing closed.
    fn resolve_token_for_value_op(&self, token_id: &str) -> Result<[u8; 32], String> {
        self.wallet
            .token_sdk
            .resolve_policy_commit_strict(token_id)
            .map_err(|e| format!("unknown token {token_id}: {e}"))
    }

    /// The burn `req` asks for, as this device signs it: the operation and its
    /// one debit of the token's committed policy.
    pub(crate) fn burn_operation(
        &self,
        req: &generated::TokenBurnRequest,
    ) -> Result<
        (
            dsm::types::operations::Operation,
            [dsm::types::device_state::BalanceDelta; 1],
        ),
        String,
    > {
        if req.amount == 0 {
            return Err("amount must be > 0".into());
        }
        let policy_commit = self.resolve_token_for_value_op(&req.token_id)?;
        let op = dsm::types::operations::Operation::Burn {
            amount: dsm::types::token_types::Balance::amount(req.amount),
            token_id: req.token_id.as_bytes().to_vec(),
            policy_commit,
            message: req.message.clone(),
        };
        let deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit,
            direction: dsm::types::device_state::BalanceDirection::Debit,
            amount: req.amount,
        }];
        Ok((op, deltas))
    }

    async fn handle_token_burn(&self, i: AppInvoke) -> AppResult {
        let arg_pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("decode ArgPack failed: {e}")),
        };
        let req = match generated::TokenBurnRequest::decode(&*arg_pack.body) {
            Ok(r) => r,
            Err(e) => return err(format!("decode TokenBurnRequest failed: {e}")),
        };
        let (op, deltas) = match self.burn_operation(&req) {
            Ok(built) => built,
            Err(e) => return err(format!("token.burn: {e}")),
        };
        let policy_commit = deltas[0].policy_commit;
        let dev_id = self.device_id_bytes;

        // Burn > balance is refused by the conservation guard's checked_sub,
        // which runs before the durable write — no pre-check can be more
        // authoritative than that, so the error is surfaced verbatim.
        //
        // 3.5b: the burn is an ADMITTED economic debit — the fence-coupled
        // advance, evidence publication, registration and validation all run
        // before this route reports success. An unadmitted local burn would
        // leave the validated R_econ value intact for an adversarial
        // producer while the units disappear locally.
        let outcome = match crate::sdk::economic_admission_flow::admitted_self_loop_operation(
            &self.core_sdk,
            op,
            &deltas,
            dsm::economic::write_set::CreditSourceFacts::None,
            Vec::new(),
            None,
        )
        .await
        {
            Ok((o, ..)) => o,
            Err(e) => return err(format!("token.burn: {e}")),
        };

        let new_balance = outcome.new_device_state.balance(&policy_commit);
        self.write_token_projection(
            &dev_id,
            &req.token_id,
            &policy_commit,
            &outcome,
            new_balance,
        );

        pack_envelope_ok(generated::envelope::Payload::TokenBurnResponse(
            generated::TokenBurnResponse {
                success: true,
                token_id: req.token_id,
                new_balance,
                message: "Burned".to_string(),
            },
        ))
    }

    /// Refresh a token's balance projection from the canonical head an advance
    /// produced. Best-effort: canonical state is already correct, and a repair
    /// sweep reconciles a missed write.
    fn write_token_projection(
        &self,
        dev_id: &[u8; 32],
        token_id: &str,
        policy_commit: &[u8; 32],
        outcome: &dsm::types::device_state::AdvanceOutcome,
        balance: u64,
    ) {
        let device_txt = crate::util::text_id::encode_base32_crockford(dev_id);
        if let Err(e) = crate::storage::client_db::get_locked_balance(&device_txt, token_id)
            .and_then(|locked| {
                crate::storage::client_db::build_balance_projection_from_device_head(
                    &device_txt,
                    token_id,
                    policy_commit,
                    &outcome.new_device_state,
                    balance,
                    locked,
                )
            })
            .and_then(|record| crate::storage::client_db::upsert_balance_projection(&record))
        {
            log::warn!("[token] projection write failed for {token_id}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn v3_policy(p: &ParsedTokenPolicy) -> Vec<u8> {
        generated::TokenPolicyV3 {
            policy_bytes: build_policy_v3_bytes(p).expect("the packer accepts the fixture"),
        }
        .encode_to_vec()
    }

    fn fungible_fixture() -> ParsedTokenPolicy {
        ParsedTokenPolicy {
            creator_genesis: [0x31; 32],
            creator_device_id: [0x32; 32],
            ticker: "DSM".into(),
            alias: "DSM Token".into(),
            decimals: 8,
            genesis_supply: 1_000_000,
            release_rule: ReleaseRule::AllAtCreation,
            description: Some("A test token".into()),
            icon_url: Some("dsm:icon".into()),
            burn_enabled: true,
            transferable: true,
            threshold: 1,
            signers: vec![vec![0xAB; 64]],
            allowlist_device_ids: Vec::new(),
        }
    }

    /// SoFi §49, §54: a token's operation restriction is exactly its two
    /// flags — transfers (and the lock operation types) when transferable,
    /// burns when burn-enabled, creation always — and the signer set builds
    /// no condition, because the standard release rule names it for nothing
    /// (§47).
    #[test]
    fn the_policy_permits_exactly_what_its_flags_name() {
        use dsm::types::policy_types::PolicyCondition;
        for (transferable, burn_enabled) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let parsed = ParsedTokenPolicy {
                transferable,
                burn_enabled,
                ..fungible_fixture()
            };
            let pf = derive_policy_file("T", &parsed);
            let restrictions: Vec<&Vec<String>> = pf
                .conditions
                .iter()
                .filter_map(|c| match c {
                    PolicyCondition::OperationRestriction { allowed_operations } => {
                        Some(allowed_operations)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                restrictions.len(),
                1,
                "one restriction ({transferable}, {burn_enabled})"
            );
            let ops = restrictions[0];
            let has = |op: &str| ops.iter().any(|o| o == op);
            assert!(has("create_token"));
            assert_eq!(has("transfer"), transferable);
            assert_eq!(has("lock"), transferable);
            assert_eq!(has("unlock"), transferable);
            assert_eq!(has("burn"), burn_enabled);
            assert_eq!(
                pf.conditions.len(),
                2,
                "the supply cap and the restriction, and nothing built from the signer set"
            );
        }
    }

    // ── The one packer against Core's one parser ─────────────────────

    #[test]
    fn the_packed_policy_parses_to_every_field_it_was_packed_from() {
        let src = fungible_fixture();
        let parsed = parse_token_policy(&v3_policy(&src)).expect("Core parses the packed policy");
        assert_eq!(parsed, src);
    }

    #[test]
    fn an_inline_allowlist_round_trips() {
        let src = ParsedTokenPolicy {
            allowlist_device_ids: vec![[0x11; 32], [0x22; 32]],
            ..fungible_fixture()
        };
        let parsed = parse_token_policy(&v3_policy(&src)).expect("parses");
        assert_eq!(parsed.allowlist_device_ids, src.allowlist_device_ids);
    }

    #[test]
    fn a_multi_signer_threshold_round_trips() {
        let src = ParsedTokenPolicy {
            threshold: 2,
            signers: vec![vec![0x01; 64], vec![0x02; 64], vec![0x03; 64]],
            ..fungible_fixture()
        };
        let parsed = parse_token_policy(&v3_policy(&src)).expect("parses");
        assert_eq!(parsed.threshold, 2);
        assert_eq!(parsed.signers, src.signers);
    }

    #[test]
    fn unset_flags_round_trip_as_unset() {
        let src = ParsedTokenPolicy {
            burn_enabled: false,
            transferable: false,
            description: None,
            icon_url: None,
            ..fungible_fixture()
        };
        let parsed = parse_token_policy(&v3_policy(&src)).expect("parses");
        assert_eq!(parsed, src);
    }

    /// Two identical keys would let one signer satisfy a 2-of-2 threshold.
    /// The packer packs them; Core's parser refuses them, so the packer
    /// refuses its own output.
    #[test]
    fn duplicate_signers_are_refused() {
        let src = ParsedTokenPolicy {
            threshold: 2,
            signers: vec![vec![0x07; 64], vec![0x07; 64]],
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&src).is_err());
    }

    #[test]
    fn a_zero_genesis_supply_is_refused() {
        let src = ParsedTokenPolicy {
            genesis_supply: 0,
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&src).is_err());
    }

    #[test]
    fn a_bad_ticker_or_decimals_is_refused() {
        let short = ParsedTokenPolicy {
            ticker: "X".into(),
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&short).is_err(), "1-char ticker");
        let deep = ParsedTokenPolicy {
            decimals: 19,
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&deep).is_err(), "decimals > 18");
    }

    #[test]
    fn an_unsatisfiable_threshold_is_refused() {
        let bad = ParsedTokenPolicy {
            threshold: 3,
            signers: vec![vec![0x01; 64]],
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&bad).is_err());
        let zero = ParsedTokenPolicy {
            threshold: 0,
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&zero).is_err());
    }

    #[test]
    fn an_empty_or_oversized_signer_set_is_refused() {
        let none = ParsedTokenPolicy {
            signers: Vec::new(),
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&none).is_err());

        let too_many = ParsedTokenPolicy {
            threshold: 1,
            signers: (0..(MAX_POLICY_SIGNERS + 1))
                .map(|i| vec![i as u8; 64])
                .collect(),
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&too_many).is_err());
    }

    /// Only bytes Core's one parser accepts as a token policy are published;
    /// anything else is refused before it is kept or sent anywhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn bytes_that_are_not_a_token_policy_are_not_published() {
        use crate::bridge::{AppInvoke, AppRouter};
        let device = crate::test_support::one_device::Device::start(0x77).await;
        let anchor_of = |body: &[u8]| {
            dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, body)
        };
        let publish = |body: Vec<u8>| {
            device.router.invoke(AppInvoke {
                method: "tokens.publishPolicy".to_string(),
                args: body,
            })
        };

        let not_a_policy = b"not a policy".to_vec();
        let refused = publish(not_a_policy.clone()).await;
        assert!(!refused.success);
        assert!(
            refused
                .error_message
                .as_deref()
                .unwrap_or_default()
                .contains("not a token policy"),
            "{:?}",
            refused.error_message
        );
        let anchor = anchor_of(&not_a_policy);
        assert!(device
            .router
            .policy_cache
            .lock()
            .await
            .get(&anchor)
            .is_none());
        assert!(
            crate::storage::client_db::token_registry::load_policy_verified(&anchor)
                .expect("the policy table")
                .is_none()
        );

        // A policy Core accepts passes the check: it is kept, whatever the
        // network answers.
        let policy = v3_policy(&fungible_fixture());
        let answer = publish(policy.clone()).await;
        assert!(
            !answer
                .error_message
                .as_deref()
                .unwrap_or_default()
                .contains("not a token policy"),
            "{:?}",
            answer.error_message
        );
        assert_eq!(
            device
                .router
                .policy_cache
                .lock()
                .await
                .get(&anchor_of(&policy)),
            Some(&policy)
        );
    }

    #[test]
    fn a_proto_that_is_not_a_policy_does_not_parse() {
        let empty = generated::TokenPolicyV3 {
            policy_bytes: Vec::new(),
        }
        .encode_to_vec();
        assert!(parse_token_policy(&empty).is_none());
        assert!(parse_token_policy(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    /// The request carries the user's INTENT only. It must not carry a policy
    /// anchor — Rust derives that from the bytes it packs, so a client can
    /// never name the commit that binds the creation's asset.
    #[test]
    fn token_create_request_round_trips() {
        let req = generated::TokenCreateRequest {
            ticker: "ERA".into(),
            alias: "Era Token".into(),
            decimals: 8,
            genesis_supply_u128: 1_000u128.to_be_bytes().to_vec(),
            burn_enabled: true,
            transferable: true,
            threshold: 1,
            description: "desc".into(),
            icon_url: "dsm:icon".into(),
            allowlist_device_ids: vec![vec![0x44; 32]],
        };
        let decoded =
            generated::TokenCreateRequest::decode(req.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, req);
    }
}
