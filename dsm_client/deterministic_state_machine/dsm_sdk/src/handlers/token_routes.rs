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

/// Canonical token-policy blob version. There is exactly one supported
/// version: the blob is the anchored, content-addressed definition of a
/// token, so a second parseable shape would be a second definition of the
/// same thing. Older shapes are rejected, never migrated.
const TOKEN_POLICY_VERSION: u8 = 3;

/// Only fungible tokens exist. The kind byte is a discriminant, not an enum
/// with unimplemented members: any other value is a hard parse error, so a
/// policy claiming semantics the protocol does not enforce cannot be created.
const TOKEN_KIND_FUNGIBLE: u8 = 0;

const POLICY_FLAG_MINT_BURN: u8 = 0x01;
const POLICY_FLAG_TRANSFERABLE: u8 = 0x02;
const POLICY_FLAG_ALLOWLIST: u8 = 0x04;
const POLICY_FLAG_UNLIMITED_SUPPLY: u8 = 0x08;

const ALLOWLIST_KIND_NONE: u8 = 0;
const ALLOWLIST_KIND_INLINE: u8 = 1;

/// Upper bound on the mint/burn signer set. Bounded so a policy blob cannot
/// be used to force unbounded work at parse or verification time.
const MAX_POLICY_SIGNERS: usize = 16;

#[derive(Debug, Clone, Default)]
struct ParsedTokenPolicy {
    ticker: String,
    alias: String,
    decimals: u32,
    max_supply: u128,
    initial_alloc: u128,
    description: Option<String>,
    icon_url: Option<String>,
    mint_burn_enabled: bool,
    transferable: bool,
    unlimited_supply: bool,
    /// Signatures required to authorize a mint or burn (`k` in k-of-n).
    mint_burn_threshold: u8,
    /// The `n` in k-of-n: raw SPHINCS+ public keys permitted to mint/burn.
    signers: Vec<Vec<u8>>,
    /// Inline allowlist of 32-byte device ids; empty when not restricted.
    allowlist_device_ids: Vec<[u8; 32]>,
}

/// Byte-cursor over a policy blob. Every read is bounds-checked and the blob
/// must be consumed exactly — trailing bytes are an error, so a truncated or
/// padded policy can never parse as a valid one.
struct PolicyReader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> PolicyReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, off: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.off)?;
        self.off += 1;
        Some(v)
    }
    fn u16be(&mut self) -> Option<usize> {
        let hi = *self.b.get(self.off)? as usize;
        let lo = *self.b.get(self.off + 1)? as usize;
        self.off += 2;
        Some((hi << 8) | lo)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.off..self.off + n)?;
        self.off += n;
        Some(s)
    }
    fn u128be(&mut self) -> Option<u128> {
        let s = self.bytes(16)?;
        let mut v = 0u128;
        for b in s {
            v = (v << 8) | (*b as u128);
        }
        Some(v)
    }
    fn utf8(&mut self, n: usize) -> Option<String> {
        String::from_utf8(self.bytes(n)?.to_vec()).ok()
    }
    fn finished(&self) -> bool {
        self.off == self.b.len()
    }
}

/// Pack the canonical v3 policy blob.
///
/// This is the SOLE packer for the token-policy format. It lives in Rust
/// because the blob is protocol — it is hashed into the CPTA anchor, it binds
/// the issuance delta's asset, and it carries the mint/burn signer set. No
/// other layer may construct it.
///
/// Layout (all integers big-endian):
/// ```text
///   u8   version = 3
///   u8   kind = 0 (FUNGIBLE)
///   u8   flags: 0x01 mint_burn | 0x02 transferable | 0x04 allowlist | 0x08 unlimited
///   u8   mint_burn_threshold k        (1..=255)
///   u8   signer_count n               (1..=16)
///   n x  { u16 pk_len, pk }
///   u8   ticker_len,  ticker
///   u16  alias_len,   alias
///   u8   decimals
///   u128 max_supply
///   u128 initial_alloc
///   u16  description_len, description
///   u16  icon_url_len,    icon_url
///   u8   allowlist_kind (0 NONE | 1 INLINE)
///   u16  allowlist_count, count x 32B device_id
/// ```
fn build_policy_v3_bytes(p: &ParsedTokenPolicy) -> Result<Vec<u8>, String> {
    if p.signers.is_empty() || p.signers.len() > MAX_POLICY_SIGNERS {
        return Err(format!(
            "policy: signer count must be 1..={MAX_POLICY_SIGNERS}, got {}",
            p.signers.len()
        ));
    }
    if p.mint_burn_threshold == 0 || (p.mint_burn_threshold as usize) > p.signers.len() {
        return Err(format!(
            "policy: threshold {} must be 1..={} (the signer count)",
            p.mint_burn_threshold,
            p.signers.len()
        ));
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
    if p.mint_burn_enabled {
        flags |= POLICY_FLAG_MINT_BURN;
    }
    if p.transferable {
        flags |= POLICY_FLAG_TRANSFERABLE;
    }
    if !p.allowlist_device_ids.is_empty() {
        flags |= POLICY_FLAG_ALLOWLIST;
    }
    if p.unlimited_supply {
        flags |= POLICY_FLAG_UNLIMITED_SUPPLY;
    }

    let mut out = vec![
        TOKEN_POLICY_VERSION,
        TOKEN_KIND_FUNGIBLE,
        flags,
        p.mint_burn_threshold,
        p.signers.len() as u8,
    ];
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
    out.extend_from_slice(&p.max_supply.to_be_bytes());
    out.extend_from_slice(&p.initial_alloc.to_be_bytes());
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
    Ok(out)
}

/// Parse a canonical v3 policy blob. Fail-closed on every field: a policy
/// that cannot be fully validated is not a policy, because it is the anchored
/// definition of an asset's rules.
fn parse_token_policy(raw_proto: &[u8]) -> Option<ParsedTokenPolicy> {
    let policy = generated::TokenPolicyV3::decode(raw_proto).ok()?;
    let mut r = PolicyReader::new(&policy.policy_bytes);

    if r.u8()? != TOKEN_POLICY_VERSION {
        return None;
    }
    // Fungible only. NFT/SBT would need a per-item ownership primitive the
    // protocol does not have; accepting them would mint a fungible balance
    // under a policy claiming semantics nothing enforces.
    if r.u8()? != TOKEN_KIND_FUNGIBLE {
        return None;
    }
    let flags = r.u8()?;
    let mint_burn_threshold = r.u8()?;
    if mint_burn_threshold == 0 {
        return None;
    }

    let signer_count = r.u8()? as usize;
    if signer_count == 0 || signer_count > MAX_POLICY_SIGNERS {
        return None;
    }
    if (mint_burn_threshold as usize) > signer_count {
        // An unsatisfiable k-of-n token could never mint or burn again.
        return None;
    }
    let mut signers: Vec<Vec<u8>> = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let pk_len = r.u16be()?;
        if pk_len == 0 {
            return None;
        }
        let pk = r.bytes(pk_len)?.to_vec();
        if signers.contains(&pk) {
            // Duplicate signers would let one key satisfy a k>1 threshold.
            return None;
        }
        signers.push(pk);
    }

    let ticker_len = r.u8()? as usize;
    let ticker = r.utf8(ticker_len)?;
    if ticker.len() < 2 || ticker.len() > 8 {
        return None;
    }
    let alias_len = r.u16be()?;
    let alias = r.utf8(alias_len)?;
    if alias.trim().is_empty() {
        return None;
    }

    let decimals = r.u8()? as u32;
    if decimals > 18 {
        return None;
    }

    let max_supply = r.u128be()?;
    let initial_alloc = r.u128be()?;
    let unlimited_supply = flags & POLICY_FLAG_UNLIMITED_SUPPLY != 0;
    if unlimited_supply {
        // One canonical representation: an unlimited token carries no cap and
        // no pre-allocation, so the two encodings can never disagree.
        if max_supply != 0 || initial_alloc != 0 {
            return None;
        }
    } else {
        if max_supply == 0 {
            return None;
        }
        if initial_alloc > max_supply {
            return None;
        }
    }

    let desc_len = r.u16be()?;
    let description = r.utf8(desc_len).filter(|s| !s.is_empty());
    let icon_len = r.u16be()?;
    let icon_url = r.utf8(icon_len).filter(|s| !s.is_empty());

    let allowlist_kind = r.u8()?;
    let allowlist_count = r.u16be()?;
    let mut allowlist_device_ids = Vec::with_capacity(allowlist_count);
    match allowlist_kind {
        ALLOWLIST_KIND_NONE => {
            if allowlist_count != 0 {
                return None;
            }
        }
        ALLOWLIST_KIND_INLINE => {
            if allowlist_count == 0 {
                return None;
            }
            for _ in 0..allowlist_count {
                let id: [u8; 32] = r.bytes(32)?.try_into().ok()?;
                allowlist_device_ids.push(id);
            }
        }
        _ => return None,
    }
    // The flag and the payload must agree; otherwise a reader that trusts the
    // flag and one that trusts the payload disagree about the policy.
    let flag_claims_allowlist = flags & POLICY_FLAG_ALLOWLIST != 0;
    let payload_has_allowlist = !allowlist_device_ids.is_empty();
    if flag_claims_allowlist != payload_has_allowlist {
        return None;
    }

    // Exact consumption: no trailing bytes.
    if !r.finished() {
        return None;
    }

    Some(ParsedTokenPolicy {
        ticker,
        alias,
        decimals,
        max_supply,
        initial_alloc,
        description,
        icon_url,
        mint_burn_enabled: flags & POLICY_FLAG_MINT_BURN != 0,
        transferable: flags & POLICY_FLAG_TRANSFERABLE != 0,
        unlimited_supply,
        mint_burn_threshold,
        signers,
        allowlist_device_ids,
    })
}

/// Publish policy bytes to the storage nodes.
///
/// The policy anchor is content-addressed BY DEFINITION —
/// `BLAKE3(TAG_DSM_POLICY, policy_bytes)` — so it is ALWAYS derived locally
/// and a node has no authority to name it. A node's 32-byte reply is treated
/// purely as an echo: it must equal the locally derived anchor, otherwise
/// that node is lying (or broken) and its answer is discarded.
///
/// This is load-bearing for value safety. The anchor becomes the
/// `policy_commit` on a `BalanceDelta`, so a node that could name it could
/// name an EXISTING asset's commit (e.g. ERA) and mint real balance on this
/// device. The anchor never leaves local derivation.
///
/// Returns `true` when at least one node stored the bytes and echoed the
/// correct anchor. Publication is best-effort: `false` only means the policy
/// is not yet mirrored, never that the anchor is in doubt.
async fn try_publish_policy_to_network(body: &[u8], expected_anchor: &[u8; 32]) -> bool {
    let urls = match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
        Ok(cfg) => cfg.node_urls,
        Err(e) => {
            log::warn!("[tokens.publishPolicy] No storage node config: {}", e);
            return false;
        }
    };
    if urls.is_empty() {
        return false;
    }

    let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
    let mut published = false;
    let mut last_err: Option<String> = None;

    for url in urls {
        let endpoint = format!("{}/api/v2/policy", url.trim_end_matches('/'));
        match client
            .post(&endpoint)
            .header("content-type", "application/octet-stream")
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) if bytes.as_ref() == expected_anchor.as_slice() => {
                    published = true;
                }
                Ok(bytes) => {
                    // The node named a different anchor than the content
                    // hash. Discard it — never adopt a node-supplied commit.
                    last_err = Some(format!(
                        "storage node echoed a policy anchor that is not the content hash \
                         (len {}); discarding that node's answer",
                        bytes.len()
                    ));
                }
                Err(e) => last_err = Some(format!("read publish response failed: {e}")),
            },
            Ok(resp) => {
                last_err = Some(format!("publish HTTP {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
    }

    if let Some(msg) = last_err {
        log::warn!("[tokens.publishPolicy] Network publish issue: {}", msg);
    }
    published
}

async fn try_fetch_policy_from_network(anchor: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
    let urls = match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
        Ok(cfg) => cfg.node_urls,
        Err(e) => {
            log::warn!("[tokens.getPolicy] No storage node config: {}", e);
            return Ok(None);
        }
    };
    if urls.is_empty() {
        return Ok(None);
    }

    let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
    let mut last_err: Option<String> = None;

    for url in urls {
        let endpoint = format!("{}/api/v2/policy/get", url.trim_end_matches('/'));
        match client
            .post(&endpoint)
            .header("content-type", "application/octet-stream")
            .body(anchor.to_vec())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) if !bytes.is_empty() => return Ok(Some(bytes.to_vec())),
                Ok(_) => last_err = Some("empty policy response".to_string()),
                Err(e) => last_err = Some(format!("read policy response failed: {e}")),
            },
            Ok(resp) => {
                last_err = Some(format!("fetch HTTP {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
    }

    if let Some(msg) = last_err {
        log::warn!("[tokens.getPolicy] Network fetch failed: {}", msg);
    }
    Ok(None)
}

/// Build the enforcer's `PolicyFile` from a parsed policy.
///
/// SOLE constructor. It is a pure function of the parsed (and therefore of the
/// anchored) policy, so every device that fetches the same policy bytes
/// reconstructs a byte-identical `PolicyFile`. Creation and restart
/// rehydration both call this — there is no second place that decides what a
/// token's policy means.
fn derive_policy_file(
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
    pf.add_condition(PolicyCondition::TokenAuthority {
        signers: parsed.signers.clone(),
        threshold: parsed.mint_burn_threshold as u32,
    });
    pf.add_condition(PolicyCondition::SupplyCap {
        max_supply: parsed.max_supply,
        unlimited: parsed.unlimited_supply,
    });
    if !parsed.transferable {
        // A non-transferable fungible token may still be minted and burned.
        pf.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec!["mint".to_string(), "burn".to_string()],
        });
    }

    pf.add_metadata("created_by", "dsm_token_route")
        .add_metadata("token_name", ticker);
    pf
}

impl AppRouterImpl {
    /// Re-register every persisted token's policy after a restart.
    ///
    /// The policy system is in-memory, and it fails closed for an unregistered
    /// token — so without this a token created before the restart could not be
    /// transferred, and `dlv.create` (which resolves the pair's policy commit
    /// and fails closed) could not build a vault for it. The durable tables are
    /// the source; this only rebuilds the derived in-memory view.
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
            fields.insert("max_supply".to_string(), row.max_supply.to_string());
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
                owner_id: row.owner_device_id,
                creation_tick: crate::util::deterministic_time::tick(),
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

    /// Persist an anchored policy. The in-memory map is only a read cache;
    /// `token_policies` is the durable store, so a policy survives restart.
    async fn cache_policy_bytes(&self, anchor: [u8; 32], policy_bytes: Vec<u8>) {
        {
            let mut cache = self.policy_cache.lock().await;
            cache.insert(anchor, policy_bytes.clone());
        }
        if let Err(e) =
            crate::storage::client_db::token_registry::upsert_policy(&anchor, &policy_bytes)
        {
            log::error!("[token] failed to persist policy: {e}");
        }
    }

    /// Resolve policy bytes: memory cache → durable table → storage nodes.
    ///
    /// The table read re-verifies that the bytes hash to the anchor, so a
    /// corrupted row reads as absent rather than yielding a policy that is not
    /// the one the anchor names.
    async fn load_policy_bytes(&self, anchor: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        if let Some(bytes) = self.policy_cache.lock().await.get(&anchor).cloned() {
            return Ok(Some(bytes));
        }

        match crate::storage::client_db::token_registry::load_policy_verified(&anchor) {
            Ok(Some(bytes)) => {
                let mut cache = self.policy_cache.lock().await;
                cache.insert(anchor, bytes.clone());
                return Ok(Some(bytes));
            }
            Ok(None) => {}
            Err(e) => log::warn!("[token] policy table read failed: {e}"),
        }

        if let Some(bytes) = try_fetch_policy_from_network(&anchor).await? {
            self.cache_policy_bytes(anchor, bytes.clone()).await;
            return Ok(Some(bytes));
        }

        Ok(None)
    }

    // ── Token Queries ────────────────────────────────────────────────────────
    pub(crate) async fn handle_token_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
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
                        max_supply: meta.max_supply.to_string(),
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
                if req.max_supply_u128.len() != 16 {
                    return err("token.create: max_supply_u128 must be 16 bytes".into());
                }
                if req.initial_alloc_u128.len() != 16 {
                    return err("token.create: initial_alloc_u128 must be 16 bytes".into());
                }
                let be_u128 = |b: &[u8]| -> u128 {
                    let mut v = 0u128;
                    for x in b {
                        v = (v << 8) | (*x as u128);
                    }
                    v
                };
                let max_supply = be_u128(&req.max_supply_u128);
                let initial_alloc = be_u128(&req.initial_alloc_u128);

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

                // The mint/burn signer set. The creating device is the sole
                // authority by default — the client never supplies a key, so
                // it cannot name an authority it does not control.
                //
                // This MUST be the signing authority's public key, not the
                // AppState identity blob: the authority condition verifies a
                // signature made with `current_secret_key()`, so naming any
                // other key would produce a policy whose own creator cannot
                // satisfy it.
                let creator_pk = match crate::sdk::signing_authority::current_public_key() {
                    Ok(pk) => pk,
                    Err(e) => {
                        return err(format!("token.create: signing identity unavailable: {e}"));
                    }
                };
                let threshold = req.mint_burn_threshold.clamp(1, u8::MAX as u32) as u8;
                let creator_pk_for_sig = creator_pk.clone();

                let parsed = ParsedTokenPolicy {
                    ticker: ticker.clone(),
                    alias: req.alias.trim().to_string(),
                    decimals: req.decimals,
                    max_supply,
                    initial_alloc,
                    description: Some(req.description.trim().to_string()).filter(|s| !s.is_empty()),
                    icon_url: Some(req.icon_url.trim().to_string()).filter(|s| !s.is_empty()),
                    mint_burn_enabled: req.mint_burn_enabled,
                    transferable: req.transferable,
                    unlimited_supply: req.unlimited_supply,
                    mint_burn_threshold: threshold,
                    signers: vec![creator_pk],
                    allowlist_device_ids,
                };

                // Pack the canonical policy HERE. The blob is protocol: it is
                // hashed into the CPTA anchor and binds the issuance asset, so
                // Rust is the only layer permitted to construct it.
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

                // Mirror the policy so other devices can fetch it, then cache
                // locally. Mirroring is best-effort; the anchor is already
                // authoritative because it is content-addressed.
                let mirrored = try_publish_policy_to_network(&raw_proto, &policy_anchor).await;
                if !mirrored {
                    log::warn!(
                        "[token.create] policy {anchor_b32} not mirrored to any storage node; \
                         remote verifiers may not be able to fetch it yet"
                    );
                }
                self.cache_policy_bytes(policy_anchor, raw_proto.clone())
                    .await;

                let mut id_hasher = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_DSM_TOKEN_ID,
                );
                id_hasher.update(&policy_anchor);
                id_hasher.update(ticker.as_bytes());
                let token_id =
                    crate::util::text_id::encode_base32_crockford(id_hasher.finalize().as_bytes());

                let mut fields = HashMap::new();
                fields.insert("max_supply".to_string(), parsed.max_supply.to_string());
                fields.insert("policy_anchor".to_string(), anchor_b32.clone());
                fields.insert("kind".to_string(), "FUNGIBLE".to_string());
                fields.insert(
                    "mint_burn_enabled".to_string(),
                    parsed.mint_burn_enabled.to_string(),
                );
                fields.insert("transferable".to_string(), parsed.transferable.to_string());
                fields.insert(
                    "unlimited_supply".to_string(),
                    parsed.unlimited_supply.to_string(),
                );
                fields.insert(
                    "mint_burn_threshold".to_string(),
                    parsed.mint_burn_threshold.to_string(),
                );

                let metadata = TokenMetadata {
                    token_id: token_id.clone(),
                    name: req.alias.clone(),
                    symbol: ticker.clone(),
                    description: parsed.description.clone(),
                    icon_url: parsed.icon_url.clone(),
                    decimals: (req.decimals as u8).min(18),
                    token_type: TokenType::Created,
                    owner_id: self.device_id_bytes,
                    creation_tick: crate::util::deterministic_time::tick(),
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
                // The fee burn and the issuance land in a single
                // DeviceState::advance — one SMT root, one CAS — so either the
                // token exists and the fee was paid, or neither happened. The
                // advance is performed even when initial_alloc == 0: creation
                // is a canonical event, and skipping it would leave the token
                // absent from the chain and unresolvable after a restart.
                let initial_alloc_u64: u64 = match u64::try_from(parsed.initial_alloc) {
                    Ok(v) => v,
                    Err(_) => {
                        return err(
                            "token.create: initial_alloc exceeds u64::MAX (Balance is u64)".into(),
                        );
                    }
                };

                let fee_amount = dsm::core::token::TOKEN_CREATION_FEE_ERA;
                let dev_id = self.device_id_bytes;
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
                    let era_balance = self
                        .core_sdk
                        .device_head()
                        .map(|h| h.balance(&era_commit))
                        .unwrap_or(0);
                    if era_balance < fee_amount {
                        return err(format!(
                            "token.create: insufficient ERA for the {fee_amount} ERA creation fee                              (have {era_balance}) — claim from the faucet and retry"
                        ));
                    }
                }

                let rel_key =
                    dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
                let init_tip =
                    dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                        &dev_id, &dev_id,
                    );
                let ref_hash = self
                    .core_sdk
                    .device_head()
                    .map(|s| s.genesis_digest())
                    .unwrap_or([0u8; 32]);

                // Sign the creation with the device key — the sole signer in
                // the policy we just packed. The authority condition verifies
                // against the POLICY's signer list, so an unsigned creation is
                // correctly refused.
                let auth_preimage =
                    dsm::core::token::policy::policy_enforcement::token_authorization_preimage(
                        &policy_commit,
                        "create_token",
                        token_id.as_bytes(),
                        initial_alloc_u64,
                        &[],
                    );
                let signing_key = match crate::sdk::signing_authority::current_secret_key() {
                    Ok(k) => k,
                    Err(e) => return err(format!("token.create: signing key unavailable: {e}")),
                };
                let create_sig =
                    match dsm::crypto::sphincs::sphincs_sign(&signing_key, &auth_preimage) {
                        Ok(sig) => sig,
                        Err(e) => return err(format!("token.create: signing failed: {e}")),
                    };
                // Witness record: (u32 pk_len, pk, u32 sig_len, sig).
                let mut authorization = Vec::new();
                authorization.extend_from_slice(&(creator_pk_for_sig.len() as u32).to_le_bytes());
                authorization.extend_from_slice(&creator_pk_for_sig);
                authorization.extend_from_slice(&(create_sig.len() as u32).to_le_bytes());
                authorization.extend_from_slice(&create_sig);

                let create_op = dsm::types::operations::Operation::CreateToken {
                    token_id: token_id.as_bytes().to_vec(),
                    initial_supply: dsm::types::token_types::Balance::from_state(
                        initial_alloc_u64,
                        ref_hash,
                    ),
                    policy_commit,
                    fee_amount,
                    name: parsed.alias.clone(),
                    symbol: ticker.clone(),
                    decimals: parsed.decimals.min(18) as u8,
                    metadata_uri: Some(format!("dsm:policy:{anchor_b32}")),
                    signature: authorization,
                };

                // Positional, exactly as the conservation guard requires:
                // [0] the ERA fee debit, [1] the issuance credit (if any).
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
                if initial_alloc_u64 > 0 {
                    deltas.push(dsm::types::device_state::BalanceDelta {
                        policy_commit,
                        direction: dsm::types::device_state::BalanceDirection::Credit,
                        amount: initial_alloc_u64,
                    });
                }

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
                    max_supply: parsed.max_supply,
                    owner_device_id: dev_id,
                };
                let insert_registry = |tx: &rusqlite::Transaction<'_>,
                                       _outcome: &dsm::types::device_state::AdvanceOutcome|
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

                let outcome = match self.core_sdk.execute_on_relationship_guarded(
                    rel_key,
                    dev_id,
                    create_op,
                    &deltas,
                    Some(init_tip),
                    Some(&insert_registry),
                ) {
                    Ok((_state, outcome)) => outcome,
                    Err(e) => {
                        // Nothing was committed: the guard and the balance
                        // arithmetic both run before the durable write, so a
                        // failed creation burns nothing.
                        return err(format!("token.create: canonical creation failed: {e}"));
                    }
                };

                // Projections for BOTH assets the advance moved.
                if initial_alloc_u64 > 0 {
                    if let Err(e) =
                        crate::storage::client_db::build_balance_projection_from_device_head(
                            &device_txt,
                            &ticker,
                            &policy_commit,
                            &outcome.new_device_state,
                            initial_alloc_u64,
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
                        let locked =
                            crate::storage::client_db::get_locked_balance(&device_txt, "ERA")
                                .unwrap_or(0);
                        if let Err(e) =
                            crate::storage::client_db::build_balance_projection_from_device_head(
                                &device_txt,
                                "ERA",
                                &era_commit,
                                &outcome.new_device_state,
                                era_after,
                                locked,
                            )
                            .and_then(|record| {
                                crate::storage::client_db::upsert_balance_projection(&record)
                            })
                        {
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

                // The anchor is the content hash, always. Publication is
                // best-effort mirroring and can never change it.
                let anchor: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
                    dsm::common::domain_tags::TAG_DSM_POLICY,
                    body,
                );
                let mirrored = try_publish_policy_to_network(body, &anchor).await;
                if !mirrored {
                    log::warn!(
                        "[tokens.publishPolicy] policy not mirrored to any storage node; \
                         anchor is still valid (content-addressed) but remote fetch may fail"
                    );
                }

                self.cache_policy_bytes(anchor, body.to_vec()).await;
                AppResult {
                    success: true,
                    data: anchor.to_vec(),
                    error_message: None,
                }
            }

            "token.mint" => self.handle_token_mint(i).await,
            "token.burn" => self.handle_token_burn(i).await,

            other => err(format!("unknown token invoke method: {other}")),
        }
    }

    /// Sign a mint/burn authorization with the device key.
    ///
    /// The witness is `(u32 pk_len, pk, u32 sig_len, sig)`; the enforcer
    /// matches the key against the policy's signer list and rebuilds the
    /// preimage itself, so this cannot authorize anything but the operation
    /// actually being executed.
    /// `authorized_by` MUST equal what the enforcement context will carry for
    /// this operation, since the enforcer rebuilds the preimage from that
    /// context. A mismatch here is indistinguishable from a forged signature —
    /// which is precisely how it should behave.
    fn sign_token_authorization(
        policy_commit: &[u8; 32],
        op: &str,
        token_id: &str,
        amount: u64,
        authorized_by: &[u8],
    ) -> Result<Vec<u8>, String> {
        let preimage = dsm::core::token::policy::policy_enforcement::token_authorization_preimage(
            policy_commit,
            op,
            token_id.as_bytes(),
            amount,
            authorized_by,
        );
        let pk = crate::sdk::signing_authority::current_public_key()
            .map_err(|e| format!("signing identity unavailable: {e}"))?;
        let sk = crate::sdk::signing_authority::current_secret_key()
            .map_err(|e| format!("signing key unavailable: {e}"))?;
        let sig = dsm::crypto::sphincs::sphincs_sign(&sk, &preimage)
            .map_err(|e| format!("signing failed: {e}"))?;

        let mut witness = Vec::new();
        witness.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        witness.extend_from_slice(&pk);
        witness.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        witness.extend_from_slice(&sig);
        Ok(witness)
    }

    /// Resolve a token to its committed policy commit, failing closed.
    fn resolve_token_for_value_op(&self, token_id: &str) -> Result<[u8; 32], String> {
        self.wallet
            .token_sdk
            .resolve_policy_commit_strict(token_id)
            .map_err(|e| format!("unknown token {token_id}: {e}"))
    }

    async fn handle_token_mint(&self, i: AppInvoke) -> AppResult {
        let arg_pack = match generated::ArgPack::decode(&*i.args) {
            Ok(p) => p,
            Err(e) => return err(format!("decode ArgPack failed: {e}")),
        };
        let req = match generated::TokenMintRequest::decode(&*arg_pack.body) {
            Ok(r) => r,
            Err(e) => return err(format!("decode TokenMintRequest failed: {e}")),
        };
        if req.amount == 0 {
            return err("token.mint: amount must be > 0".into());
        }
        let policy_commit = match self.resolve_token_for_value_op(&req.token_id) {
            Ok(c) => c,
            Err(e) => return err(format!("token.mint: {e}")),
        };
        let dev_id = self.device_id_bytes;
        let authorization = match Self::sign_token_authorization(
            &policy_commit,
            "mint",
            &req.token_id,
            req.amount,
            &dev_id,
        ) {
            Ok(w) => w,
            Err(e) => return err(format!("token.mint: {e}")),
        };
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id, &dev_id,
        );
        let ref_hash = self
            .core_sdk
            .device_head()
            .map(|s| s.genesis_digest())
            .unwrap_or([0u8; 32]);

        let op = dsm::types::operations::Operation::Mint {
            amount: dsm::types::token_types::Balance::from_state(req.amount, ref_hash),
            token_id: req.token_id.as_bytes().to_vec(),
            policy_commit,
            authorized_by: dev_id.to_vec(),
            proof_of_authorization: authorization,
            message: req.message.clone(),
        };
        let deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit,
            direction: dsm::types::device_state::BalanceDirection::Credit,
            amount: req.amount,
        }];

        let outcome = match self.core_sdk.execute_on_relationship(
            rel_key,
            dev_id,
            op,
            &deltas,
            Some(init_tip),
        ) {
            Ok((_s, o)) => o,
            Err(e) => return err(format!("token.mint: {e}")),
        };

        let new_balance = outcome.new_device_state.balance(&policy_commit);
        self.write_token_projection(
            &dev_id,
            &req.token_id,
            &policy_commit,
            &outcome,
            new_balance,
        );

        pack_envelope_ok(generated::envelope::Payload::TokenMintResponse(
            generated::TokenMintResponse {
                success: true,
                token_id: req.token_id,
                new_balance,
                message: "Minted".to_string(),
            },
        ))
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
        if req.amount == 0 {
            return err("token.burn: amount must be > 0".into());
        }
        let policy_commit = match self.resolve_token_for_value_op(&req.token_id) {
            Ok(c) => c,
            Err(e) => return err(format!("token.burn: {e}")),
        };
        let authorization = match Self::sign_token_authorization(
            &policy_commit,
            "burn",
            &req.token_id,
            req.amount,
            &[],
        ) {
            Ok(w) => w,
            Err(e) => return err(format!("token.burn: {e}")),
        };

        let dev_id = self.device_id_bytes;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &dev_id, &dev_id,
        );
        let ref_hash = self
            .core_sdk
            .device_head()
            .map(|s| s.genesis_digest())
            .unwrap_or([0u8; 32]);

        let op = dsm::types::operations::Operation::Burn {
            amount: dsm::types::token_types::Balance::from_state(req.amount, ref_hash),
            token_id: req.token_id.as_bytes().to_vec(),
            policy_commit,
            proof_of_ownership: authorization,
            message: req.message.clone(),
        };
        let deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit,
            direction: dsm::types::device_state::BalanceDirection::Debit,
            amount: req.amount,
        }];

        // Burn > balance is refused by the conservation guard's checked_sub,
        // which runs before the durable write — no pre-check can be more
        // authoritative than that, so the error is surfaced verbatim.
        let outcome = match self.core_sdk.execute_on_relationship(
            rel_key,
            dev_id,
            op,
            &deltas,
            Some(init_tip),
        ) {
            Ok((_s, o)) => o,
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
        let locked =
            crate::storage::client_db::get_locked_balance(&device_txt, token_id).unwrap_or(0);
        if let Err(e) = crate::storage::client_db::build_balance_projection_from_device_head(
            &device_txt,
            token_id,
            policy_commit,
            &outcome.new_device_state,
            balance,
            locked,
        )
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

    /// Build a canonical v3 policy via the SOLE production packer, so the
    /// tests exercise the real format rather than a hand-rolled replica that
    /// could drift from it.
    fn v3_policy(p: ParsedTokenPolicy) -> Vec<u8> {
        let bytes = build_policy_v3_bytes(&p).expect("packer should accept the fixture");
        generated::TokenPolicyV3 {
            policy_bytes: bytes,
        }
        .encode_to_vec()
    }

    fn fungible_fixture() -> ParsedTokenPolicy {
        ParsedTokenPolicy {
            ticker: "DSM".into(),
            alias: "DSM Token".into(),
            decimals: 8,
            max_supply: 1_000_000,
            initial_alloc: 1_000,
            description: Some("A test token".into()),
            icon_url: None,
            mint_burn_enabled: true,
            transferable: true,
            unlimited_supply: false,
            mint_burn_threshold: 1,
            signers: vec![vec![0xAB; 64]],
            allowlist_device_ids: Vec::new(),
        }
    }

    // ── v3 round trip ────────────────────────────────────────────────

    #[test]
    fn v3_round_trips_every_field() {
        let src = fungible_fixture();
        let parsed = parse_token_policy(&v3_policy(src.clone())).expect("should parse v3");
        assert_eq!(parsed.ticker, src.ticker);
        assert_eq!(parsed.alias, src.alias);
        assert_eq!(parsed.decimals, src.decimals);
        assert_eq!(parsed.max_supply, src.max_supply);
        assert_eq!(parsed.initial_alloc, src.initial_alloc);
        assert_eq!(parsed.description, src.description);
        assert!(parsed.mint_burn_enabled);
        assert!(parsed.transferable);
        assert!(!parsed.unlimited_supply);
        assert_eq!(parsed.mint_burn_threshold, 1);
        assert_eq!(parsed.signers, src.signers);
        assert!(parsed.allowlist_device_ids.is_empty());
    }

    #[test]
    fn v3_round_trips_unlimited_supply_and_allowlist() {
        let src = ParsedTokenPolicy {
            unlimited_supply: true,
            max_supply: 0,
            initial_alloc: 0,
            allowlist_device_ids: vec![[0x11; 32], [0x22; 32]],
            ..fungible_fixture()
        };
        let parsed = parse_token_policy(&v3_policy(src)).expect("should parse");
        assert!(parsed.unlimited_supply);
        assert_eq!(parsed.max_supply, 0);
        assert_eq!(parsed.allowlist_device_ids.len(), 2);
    }

    #[test]
    fn v3_round_trips_multi_signer_threshold() {
        let src = ParsedTokenPolicy {
            mint_burn_threshold: 2,
            signers: vec![vec![0x01; 64], vec![0x02; 64], vec![0x03; 64]],
            ..fungible_fixture()
        };
        let parsed = parse_token_policy(&v3_policy(src)).expect("should parse");
        assert_eq!(parsed.mint_burn_threshold, 2);
        assert_eq!(parsed.signers.len(), 3);
    }

    // ── fail-closed rejections ───────────────────────────────────────

    /// Mutate one byte of a valid v3 blob and assert it no longer parses.
    fn assert_rejected_with(mutate: impl Fn(&mut Vec<u8>), why: &str) {
        let bytes = build_policy_v3_bytes(&fungible_fixture()).expect("pack");
        let mut mutated = bytes;
        mutate(&mut mutated);
        let proto = generated::TokenPolicyV3 {
            policy_bytes: mutated,
        }
        .encode_to_vec();
        assert!(parse_token_policy(&proto).is_none(), "{why}");
    }

    #[test]
    fn v3_rejects_wrong_version() {
        assert_rejected_with(|b| b[0] = 2, "v2 is deleted, not migrated");
        assert_rejected_with(|b| b[0] = 4, "unknown future version must not parse");
    }

    /// NFT and SBT are not merely unsupported — the kind byte is a
    /// discriminant, so a policy claiming those semantics cannot exist.
    #[test]
    fn v3_rejects_non_fungible_kinds() {
        assert_rejected_with(|b| b[1] = 1, "NFT kind must be rejected");
        assert_rejected_with(|b| b[1] = 2, "SBT kind must be rejected");
        assert_rejected_with(|b| b[1] = 9, "unknown kind must be rejected");
    }

    #[test]
    fn v3_rejects_zero_threshold_and_zero_signers() {
        assert_rejected_with(|b| b[3] = 0, "threshold 0 is unsatisfiable");
        assert_rejected_with(
            |b| b[4] = 0,
            "a token with no authority cannot mint or burn",
        );
    }

    /// k > n would produce a token that can never mint or burn again.
    #[test]
    fn v3_rejects_threshold_greater_than_signer_count() {
        assert_rejected_with(|b| b[3] = 2, "k=2 with n=1 must be rejected");
    }

    #[test]
    fn v3_rejects_duplicate_signers() {
        // Two identical keys would let one signer satisfy a 2-of-2 threshold.
        let src = ParsedTokenPolicy {
            mint_burn_threshold: 2,
            signers: vec![vec![0x07; 64], vec![0x07; 64]],
            ..fungible_fixture()
        };
        let bytes = build_policy_v3_bytes(&src).expect("packer does not dedupe");
        let proto = generated::TokenPolicyV3 {
            policy_bytes: bytes,
        }
        .encode_to_vec();
        assert!(
            parse_token_policy(&proto).is_none(),
            "duplicate signers must be rejected at parse"
        );
    }

    /// Trailing bytes are the classic way a truncated/padded blob sneaks
    /// through a length-prefixed parser.
    #[test]
    fn v3_rejects_trailing_bytes() {
        assert_rejected_with(|b| b.push(0x00), "trailing byte must be rejected");
    }

    #[test]
    fn v3_rejects_truncated_blob() {
        assert_rejected_with(
            |b| {
                b.truncate(6);
            },
            "truncated blob must be rejected",
        );
    }

    #[test]
    fn v3_rejects_empty_and_garbage() {
        let empty = generated::TokenPolicyV3 {
            policy_bytes: Vec::new(),
        }
        .encode_to_vec();
        assert!(parse_token_policy(&empty).is_none());
        assert!(parse_token_policy(&[0xFF, 0xFF, 0xFF]).is_none());
    }

    /// `unlimited_supply` has exactly one canonical encoding, so a blob
    /// carrying both a cap and the unlimited flag cannot parse.
    #[test]
    fn v3_rejects_unlimited_with_a_cap() {
        let src = ParsedTokenPolicy {
            unlimited_supply: true,
            max_supply: 5,
            initial_alloc: 0,
            ..fungible_fixture()
        };
        let bytes = build_policy_v3_bytes(&src).expect("pack");
        let proto = generated::TokenPolicyV3 {
            policy_bytes: bytes,
        }
        .encode_to_vec();
        assert!(parse_token_policy(&proto).is_none());
    }

    #[test]
    fn v3_rejects_initial_alloc_over_max_supply() {
        let src = ParsedTokenPolicy {
            max_supply: 100,
            initial_alloc: 101,
            ..fungible_fixture()
        };
        let bytes = build_policy_v3_bytes(&src).expect("pack");
        let proto = generated::TokenPolicyV3 {
            policy_bytes: bytes,
        }
        .encode_to_vec();
        assert!(
            parse_token_policy(&proto).is_none(),
            "allocation above the cap must be rejected in Rust, not just in the UI"
        );
    }

    #[test]
    fn v3_rejects_bad_ticker_and_decimals() {
        let short = ParsedTokenPolicy {
            ticker: "X".into(),
            ..fungible_fixture()
        };
        let bytes = build_policy_v3_bytes(&short).expect("pack");
        let proto = generated::TokenPolicyV3 {
            policy_bytes: bytes,
        }
        .encode_to_vec();
        assert!(parse_token_policy(&proto).is_none(), "1-char ticker");

        assert_rejected_with(
            |b| {
                // decimals sits after: ver,kind,flags,k,n, [u16 pk_len + 64B pk],
                // ticker_len + 3, alias_len(2) + 9
                let idx = 5 + 2 + 64 + 1 + 3 + 2 + 9;
                b[idx] = 19;
            },
            "decimals > 18 must be rejected",
        );
    }

    // ── packer guards ────────────────────────────────────────────────

    #[test]
    fn packer_rejects_unsatisfiable_threshold() {
        let bad = ParsedTokenPolicy {
            mint_burn_threshold: 3,
            signers: vec![vec![0x01; 64]],
            ..fungible_fixture()
        };
        assert!(
            build_policy_v3_bytes(&bad).is_err(),
            "packer must refuse to build a token that can never mint or burn"
        );
    }

    #[test]
    fn packer_rejects_empty_and_oversized_signer_set() {
        let none = ParsedTokenPolicy {
            signers: Vec::new(),
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&none).is_err());

        let too_many = ParsedTokenPolicy {
            signers: (0..(MAX_POLICY_SIGNERS + 1))
                .map(|i| vec![i as u8; 64])
                .collect(),
            ..fungible_fixture()
        };
        assert!(build_policy_v3_bytes(&too_many).is_err());
    }
    // ── Token validation constants ────────────────────────────────────

    #[test]
    fn token_route_constants() {
        assert_eq!(TOKEN_POLICY_VERSION, 3);
        assert_eq!(TOKEN_KIND_FUNGIBLE, 0);
        assert_eq!(MAX_POLICY_SIGNERS, 16);
    }

    #[test]
    fn ticker_validation_logic() {
        let valid_tickers = ["AB", "ERA", "DSMT", "ABCDEFGH"];
        for t in &valid_tickers {
            let ticker = t.trim().to_uppercase();
            assert!(
                ticker.len() >= 2 && ticker.len() <= 8,
                "ticker '{}' should be valid",
                t
            );
        }

        let invalid_tickers = ["A", "", "ABCDEFGHI"];
        for t in &invalid_tickers {
            let ticker = t.trim().to_uppercase();
            assert!(
                ticker.len() < 2 || ticker.len() > 8,
                "ticker '{}' should be invalid",
                t
            );
        }
    }

    /// The request carries the user's INTENT only. It must not carry a policy
    /// anchor — Rust derives that from the bytes it packs, so a client can
    /// never name the commit that binds the issuance delta's asset.
    #[test]
    fn token_create_request_roundtrip() {
        let req = generated::TokenCreateRequest {
            ticker: "ERA".into(),
            alias: "Era Token".into(),
            decimals: 8,
            max_supply_u128: 1_000u128.to_be_bytes().to_vec(),
            initial_alloc_u128: 250u128.to_be_bytes().to_vec(),
            mint_burn_enabled: true,
            transferable: true,
            unlimited_supply: false,
            mint_burn_threshold: 1,
            description: "desc".into(),
            icon_url: String::new(),
            allowlist_device_ids: Vec::new(),
        };
        let bytes = req.encode_to_vec();
        let decoded = generated::TokenCreateRequest::decode(&*bytes).expect("decode");
        assert_eq!(decoded.ticker, "ERA");
        assert_eq!(decoded.alias, "Era Token");
        assert_eq!(decoded.decimals, 8);
        assert_eq!(decoded.max_supply_u128.len(), 16);
        assert_eq!(decoded.initial_alloc_u128.len(), 16);
        assert!(decoded.mint_burn_enabled);
        assert_eq!(decoded.mint_burn_threshold, 1);
    }
}
