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

const POLICY_INDEX_KEY: &str = "dsm.policy.index";
const POLICY_PREFIX: &str = "dsm.policy.";

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

fn app_state_get(key: &str) -> String {
    crate::sdk::app_state::AppState::handle_app_state_request(key, "get", "")
}

fn app_state_set(key: &str, value: &str) {
    let _ = crate::sdk::app_state::AppState::handle_app_state_request(key, "set", value);
}

fn load_policy_from_pref(anchor_b32: &str) -> Option<Vec<u8>> {
    let raw = app_state_get(&format!("{POLICY_PREFIX}{anchor_b32}"));
    if raw.is_empty() {
        return None;
    }
    crate::util::text_id::decode_base32_crockford(&raw)
}

fn list_cached_policy_ids_from_prefs() -> BTreeSet<String> {
    app_state_get(POLICY_INDEX_KEY)
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn persist_policy_to_prefs(anchor_b32: &str, policy_bytes: &[u8]) {
    let key = format!("{POLICY_PREFIX}{anchor_b32}");
    let encoded = crate::util::text_id::encode_base32_crockford(policy_bytes);
    app_state_set(&key, &encoded);

    let mut ids = list_cached_policy_ids_from_prefs();
    ids.insert(anchor_b32.to_string());
    let joined = ids.into_iter().collect::<Vec<_>>().join(",");
    app_state_set(POLICY_INDEX_KEY, &joined);
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
    if (flags & POLICY_FLAG_ALLOWLIST != 0) != !allowlist_device_ids.is_empty() {
        // The flag and the payload must agree; otherwise a reader that trusts
        // the flag and one that trusts the payload disagree about the policy.
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

impl AppRouterImpl {
    async fn cache_policy_bytes(&self, anchor: [u8; 32], policy_bytes: Vec<u8>) {
        let anchor_b32 = crate::util::text_id::encode_base32_crockford(&anchor);
        {
            let mut cache = self.policy_cache.lock().await;
            cache.insert(anchor, policy_bytes.clone());
        }
        persist_policy_to_prefs(&anchor_b32, &policy_bytes);
    }

    async fn load_policy_bytes(&self, anchor: [u8; 32]) -> Result<Option<Vec<u8>>, String> {
        if let Some(bytes) = self.policy_cache.lock().await.get(&anchor).cloned() {
            return Ok(Some(bytes));
        }

        let anchor_b32 = crate::util::text_id::encode_base32_crockford(&anchor);
        if let Some(bytes) = load_policy_from_pref(&anchor_b32) {
            let mut cache = self.policy_cache.lock().await;
            cache.insert(anchor, bytes.clone());
            return Ok(Some(bytes));
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
                let mut anchors = list_cached_policy_ids_from_prefs();
                {
                    let cache = self.policy_cache.lock().await;
                    for anchor in cache.keys() {
                        anchors.insert(crate::util::text_id::encode_base32_crockford(anchor));
                    }
                }

                let mut policies = Vec::new();
                for anchor_b32 in anchors {
                    let Some(anchor_bytes) =
                        crate::util::text_id::decode_base32_crockford(&anchor_b32)
                    else {
                        continue;
                    };
                    if anchor_bytes.len() != 32 {
                        continue;
                    }
                    let anchor: [u8; 32] = match anchor_bytes[..].try_into() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
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
                let Some(creator_pk) = crate::sdk::app_state::AppState::get_public_key() else {
                    return err("token.create: local signing identity unavailable".into());
                };
                let threshold = req.mint_burn_threshold.clamp(1, u8::MAX as u32) as u8;

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

                // Build a PolicyFile matching parsed policy bytes, then bind it
                // to the externally supplied policy_anchor commitment.
                let policy_file = {
                    let transferable = parsed.transferable;
                    let description = parsed.description.clone();
                    let mut pf =
                        // Semantic version — the policy validator rejects a
                        // bare "1", which silently broke every token create.
                        dsm::types::policy_types::PolicyFile::new(
                            &ticker,
                            "1.0.0",
                            "dsm_token_route",
                        );
                    if let Some(desc) = description.as_ref() {
                        pf.description = Some(desc.clone());
                    }
                    pf.add_metadata("created_by", "dsm_token_route")
                        .add_metadata("token_name", &ticker)
                        .add_metadata("transferable", if transferable { "true" } else { "false" });
                    if !transferable {
                        pf.add_metadata("transfer_restricted", "true")
                            .add_metadata("allowed_operations", "mint,burn");
                    }
                    pf
                };

                // Register policy mapping using the explicit anchor from the
                // request so token_id -> policy_commit remains stable.
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

                // Materialise initial supply via a self-loop Mint, if any.
                let initial_alloc = parsed.initial_alloc;
                if initial_alloc > 0 {
                    let initial_alloc_u64: u64 = match u64::try_from(initial_alloc) {
                        Ok(v) => v,
                        Err(_) => {
                            return err(
                                "token.create: initial_alloc exceeds u64::MAX (Balance is u64)"
                                    .into(),
                            );
                        }
                    };

                    let dev_id = self.device_id_bytes;
                    let rel_key =
                        dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
                    let init_tip =
                        dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                            &dev_id, &dev_id,
                        );

                    // Reference state hash for the Balance token (§4.3 positioning).
                    let ref_hash = self
                        .core_sdk
                        .device_head()
                        .map(|s| s.genesis_digest())
                        .unwrap_or([0u8; 32]);

                    let mint_op = dsm::types::operations::Operation::Mint {
                        amount: dsm::types::token_types::Balance::from_state(
                            initial_alloc_u64,
                            ref_hash,
                        ),
                        token_id: token_id.as_bytes().to_vec(),
                        authorized_by: dev_id.to_vec(),
                        proof_of_authorization: policy_commit.to_vec(),
                        message: format!("initial allocation for {ticker}"),
                    };

                    let deltas = [dsm::types::device_state::BalanceDelta {
                        policy_commit,
                        direction: dsm::types::device_state::BalanceDirection::Credit,
                        amount: initial_alloc_u64,
                    }];

                    if let Err(e) = self.core_sdk.execute_on_relationship(
                        rel_key,
                        dev_id,
                        mint_op,
                        &deltas,
                        Some(init_tip),
                    ) {
                        return err(format!("token.create: initial-allocation Mint failed: {e}"));
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

            other => err(format!("unknown token invoke method: {other}")),
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
    #[test]
    fn list_cached_splits_comma_separated() {
        // Since list_cached_policy_ids_from_prefs calls app_state_get which
        // depends on global state, we test the splitting logic directly.
        let input = "abc123, def456 ,ghi789";
        let ids: std::collections::BTreeSet<String> = input
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains("abc123"));
        assert!(ids.contains("def456"));
        assert!(ids.contains("ghi789"));
    }

    #[test]
    fn list_cached_empty_string_returns_empty_set() {
        let input = "";
        let ids: std::collections::BTreeSet<String> = input
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        assert!(ids.is_empty());
    }

    // ── Token validation constants ────────────────────────────────────

    #[test]
    fn token_route_constants() {
        assert_eq!(POLICY_INDEX_KEY, "dsm.policy.index");
        assert!(POLICY_PREFIX.starts_with("dsm.policy."));
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
