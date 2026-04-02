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
const TOKEN_PREFIX: &str = "dsm.token.";

#[derive(Debug, Clone, Default)]
struct ParsedTokenPolicy {
    ticker: String,
    alias: String,
    decimals: u32,
    max_supply: Option<String>,
    kind: Option<String>,
    description: Option<String>,
    icon_url: Option<String>,
    mint_burn_enabled: bool,
    transferable: bool,
    unlimited_supply: bool,
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

fn parse_token_policy(raw_proto: &[u8]) -> Option<ParsedTokenPolicy> {
    let policy = generated::TokenPolicyV3::decode(raw_proto).ok()?;
    let pb = policy.policy_bytes;
    let version = *pb.first()?;

    match version {
        1 => {
            let mut off = 1usize;
            let ticker_len = *pb.get(off)? as usize;
            off += 1;
            let ticker = String::from_utf8(pb.get(off..off + ticker_len)?.to_vec()).ok()?;
            off += ticker_len;

            let alias_len = ((*pb.get(off)? as usize) << 8) | (*pb.get(off + 1)? as usize);
            off += 2;
            let alias = String::from_utf8(pb.get(off..off + alias_len)?.to_vec()).ok()?;
            off += alias_len;

            let decimals = *pb.get(off)? as u32;
            Some(ParsedTokenPolicy {
                ticker,
                alias,
                decimals,
                ..Default::default()
            })
        }
        2 => {
            let mut off = 1usize;
            let kind_byte = *pb.get(off)?;
            off += 1;
            let flags = *pb.get(off)?;
            off += 1;
            off += 1; // mintBurnThreshold

            let ticker_len = *pb.get(off)? as usize;
            off += 1;
            let ticker = String::from_utf8(pb.get(off..off + ticker_len)?.to_vec()).ok()?;
            off += ticker_len;

            let alias_len = ((*pb.get(off)? as usize) << 8) | (*pb.get(off + 1)? as usize);
            off += 2;
            let alias = String::from_utf8(pb.get(off..off + alias_len)?.to_vec()).ok()?;
            off += alias_len;

            let decimals = *pb.get(off)? as u32;
            off += 1;

            let max_supply_bytes = pb.get(off..off + 16)?;
            let mut max_supply = 0u128;
            for b in max_supply_bytes {
                max_supply = (max_supply << 8) | (*b as u128);
            }
            off += 16;
            off += 16; // initialAlloc

            let desc_len = ((*pb.get(off)? as usize) << 8) | (*pb.get(off + 1)? as usize);
            off += 2;
            let description = String::from_utf8(pb.get(off..off + desc_len)?.to_vec())
                .ok()
                .filter(|s| !s.is_empty());
            off += desc_len;

            let icon_len = ((*pb.get(off)? as usize) << 8) | (*pb.get(off + 1)? as usize);
            off += 2;
            let icon_url = String::from_utf8(pb.get(off..off + icon_len)?.to_vec())
                .ok()
                .filter(|s| !s.is_empty());

            let kind = match kind_byte {
                0 => Some("FUNGIBLE".to_string()),
                1 => Some("NFT".to_string()),
                2 => Some("SBT".to_string()),
                _ => None,
            };

            Some(ParsedTokenPolicy {
                ticker,
                alias,
                decimals,
                max_supply: Some(max_supply.to_string()),
                kind,
                description,
                icon_url,
                mint_burn_enabled: flags & 0x01 != 0,
                transferable: flags & 0x02 != 0,
                unlimited_supply: flags & 0x08 != 0,
            })
        }
        _ => None,
    }
}

async fn try_publish_policy_to_network(body: &[u8]) -> Result<Option<[u8; 32]>, String> {
    let urls = match crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config().await {
        Ok(cfg) => cfg.node_urls,
        Err(e) => {
            log::warn!("[tokens.publishPolicy] No storage node config: {}", e);
            return Ok(None);
        }
    };
    if urls.is_empty() {
        return Ok(None);
    }

    let client = crate::sdk::storage_node_sdk::build_ca_aware_client();
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
                Ok(bytes) if bytes.len() == 32 => {
                    let mut anchor = [0u8; 32];
                    anchor.copy_from_slice(&bytes);
                    return Ok(Some(anchor));
                }
                Ok(bytes) => {
                    last_err = Some(format!(
                        "storage node returned invalid policy anchor length {}",
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
        log::warn!("[tokens.publishPolicy] Network publish failed: {}", msg);
    }
    Ok(None)
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
                    let meta = parse_token_policy(&policy_bytes).unwrap_or_default();
                    policies.push(generated::TokenPolicyCacheEntry {
                        policy_commit: anchor.to_vec(),
                        policy_bytes,
                        ticker: meta.ticker,
                        alias: meta.alias,
                        decimals: meta.decimals,
                        max_supply: meta.max_supply.unwrap_or_default(),
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
                if req.policy_anchor.len() != 32 {
                    return err("token.create: policy_anchor must be 32 bytes".into());
                }

                let mut max_supply: u128 = 0;
                for b in &req.max_supply_u128 {
                    max_supply = (max_supply << 8) | (*b as u128);
                }

                let mut id_hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/token-id");
                id_hasher.update(&req.policy_anchor);
                id_hasher.update(ticker.as_bytes());
                let token_id =
                    crate::util::text_id::encode_base32_crockford(id_hasher.finalize().as_bytes());

                let anchor_b32 = crate::util::text_id::encode_base32_crockford(&req.policy_anchor);
                let mut fields = HashMap::new();
                fields.insert("max_supply".to_string(), max_supply.to_string());
                fields.insert("policy_anchor".to_string(), anchor_b32.clone());

                let parsed = self
                    .load_policy_bytes(req.policy_anchor[..].try_into().unwrap_or([0u8; 32]))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|raw_proto| parse_token_policy(&raw_proto));

                if let Some(ref m) = parsed {
                    if let Some(kind) = &m.kind {
                        fields.insert("kind".to_string(), kind.clone());
                    }
                    fields.insert(
                        "mint_burn_enabled".to_string(),
                        m.mint_burn_enabled.to_string(),
                    );
                    fields.insert("transferable".to_string(), m.transferable.to_string());
                    fields.insert(
                        "unlimited_supply".to_string(),
                        m.unlimited_supply.to_string(),
                    );
                }

                let metadata = TokenMetadata {
                    token_id: token_id.clone(),
                    name: req.alias.clone(),
                    symbol: ticker.clone(),
                    description: parsed.as_ref().and_then(|m| m.description.clone()),
                    icon_url: parsed.as_ref().and_then(|m| m.icon_url.clone()),
                    decimals: (req.decimals as u8).min(18),
                    token_type: TokenType::Created,
                    owner_id: self.device_id_bytes,
                    creation_tick: crate::util::deterministic_time::tick(),
                    metadata_uri: None,
                    policy_anchor: Some(format!("dsm:policy:{}", anchor_b32)),
                    fields,
                };

                if let Err(e) = self
                    .wallet
                    .import_token_metadata(token_id.clone(), metadata)
                    .await
                {
                    return err(format!("token.create: metadata import failed: {e}"));
                }

                app_state_set(&format!("{TOKEN_PREFIX}{token_id}"), &anchor_b32);

                let resp = generated::TokenCreateResponse {
                    success: true,
                    token_id,
                    policy_anchor: req.policy_anchor,
                    message: "Token created".to_string(),
                };
                pack_envelope_ok(generated::envelope::Payload::TokenCreateResponse(resp))
            }

            "tokens.publishPolicy" => {
                let body: &[u8] = i.args.as_slice();
                if body.is_empty() {
                    return err("tokens.publishPolicy: empty body".into());
                }

                let fallback_anchor: [u8; 32] =
                    dsm::crypto::blake3::domain_hash_bytes("DSM/policy", body);
                let anchor = match try_publish_policy_to_network(body).await {
                    Ok(Some(network_anchor)) => network_anchor,
                    Ok(None) => fallback_anchor,
                    Err(e) => return err(format!("tokens.publishPolicy failed: {e}")),
                };

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

    /// Build a V1 policy_bytes blob: [version=1][ticker_len][ticker][alias_len_be16][alias][decimals]
    fn build_v1_policy_bytes(ticker: &str, alias: &str, decimals: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(1); // version
        buf.push(ticker.len() as u8);
        buf.extend_from_slice(ticker.as_bytes());
        let alias_len = alias.len() as u16;
        buf.push((alias_len >> 8) as u8);
        buf.push((alias_len & 0xFF) as u8);
        buf.extend_from_slice(alias.as_bytes());
        buf.push(decimals);
        buf
    }

    /// Build a V2 policy_bytes blob with the full field layout.
    #[allow(clippy::too_many_arguments)]
    fn build_v2_policy_bytes(
        kind_byte: u8,
        flags: u8,
        ticker: &str,
        alias: &str,
        decimals: u8,
        max_supply: u128,
        description: &str,
        icon_url: &str,
    ) -> Vec<u8> {
        let mut buf = vec![2, kind_byte, flags, 0]; // version, kind, flags, mintBurnThreshold

        buf.push(ticker.len() as u8);
        buf.extend_from_slice(ticker.as_bytes());

        let alias_len = alias.len() as u16;
        buf.push((alias_len >> 8) as u8);
        buf.push((alias_len & 0xFF) as u8);
        buf.extend_from_slice(alias.as_bytes());

        buf.push(decimals);

        // max_supply: 16 bytes big-endian
        for i in (0..16).rev() {
            buf.push(((max_supply >> (i * 8)) & 0xFF) as u8);
        }
        // initialAlloc: 16 bytes zeros
        buf.extend_from_slice(&[0u8; 16]);

        let desc_len = description.len() as u16;
        buf.push((desc_len >> 8) as u8);
        buf.push((desc_len & 0xFF) as u8);
        buf.extend_from_slice(description.as_bytes());

        let icon_len = icon_url.len() as u16;
        buf.push((icon_len >> 8) as u8);
        buf.push((icon_len & 0xFF) as u8);
        buf.extend_from_slice(icon_url.as_bytes());

        buf
    }

    fn wrap_as_token_policy_v3(policy_bytes: Vec<u8>) -> Vec<u8> {
        let msg = generated::TokenPolicyV3 { policy_bytes };
        msg.encode_to_vec()
    }

    // ── parse_token_policy tests ─────────────────────────────────────

    #[test]
    fn parse_v1_basic() {
        let raw = build_v1_policy_bytes("ERA", "Era Token", 8);
        let proto = wrap_as_token_policy_v3(raw);

        let parsed = parse_token_policy(&proto).expect("should parse V1");
        assert_eq!(parsed.ticker, "ERA");
        assert_eq!(parsed.alias, "Era Token");
        assert_eq!(parsed.decimals, 8);
    }

    #[test]
    fn parse_v1_empty_ticker() {
        let raw = build_v1_policy_bytes("", "Tok", 2);
        let proto = wrap_as_token_policy_v3(raw);

        let parsed = parse_token_policy(&proto).expect("should parse V1 with empty ticker");
        assert_eq!(parsed.ticker, "");
        assert_eq!(parsed.alias, "Tok");
    }

    #[test]
    fn parse_v2_fungible() {
        let raw = build_v2_policy_bytes(
            0,    // FUNGIBLE
            0x03, // mint_burn_enabled | transferable
            "DSM",
            "DSM Token",
            18,
            1_000_000,
            "A test token",
            "https://example.com/icon.png",
        );
        let proto = wrap_as_token_policy_v3(raw);

        let parsed = parse_token_policy(&proto).expect("should parse V2 fungible");
        assert_eq!(parsed.ticker, "DSM");
        assert_eq!(parsed.alias, "DSM Token");
        assert_eq!(parsed.decimals, 18);
        assert_eq!(parsed.kind.as_deref(), Some("FUNGIBLE"));
        assert!(parsed.mint_burn_enabled);
        assert!(parsed.transferable);
        assert!(!parsed.unlimited_supply);
        assert_eq!(parsed.max_supply.as_deref(), Some("1000000"));
        assert_eq!(parsed.description.as_deref(), Some("A test token"));
        assert_eq!(
            parsed.icon_url.as_deref(),
            Some("https://example.com/icon.png")
        );
    }

    #[test]
    fn parse_v2_nft_with_unlimited_supply() {
        let raw = build_v2_policy_bytes(
            1,    // NFT
            0x0A, // transferable(0x02) | unlimited_supply(0x08)
            "MYNFT", "My NFT", 0, 0, "", "",
        );
        let proto = wrap_as_token_policy_v3(raw);

        let parsed = parse_token_policy(&proto).expect("should parse V2 NFT");
        assert_eq!(parsed.kind.as_deref(), Some("NFT"));
        assert!(!parsed.mint_burn_enabled);
        assert!(parsed.transferable);
        assert!(parsed.unlimited_supply);
        assert!(
            parsed.description.is_none(),
            "empty description should be None"
        );
        assert!(parsed.icon_url.is_none(), "empty icon_url should be None");
    }

    #[test]
    fn parse_v2_sbt() {
        let raw = build_v2_policy_bytes(2, 0x00, "SBT1", "Soul Bound", 0, 1, "", "");
        let proto = wrap_as_token_policy_v3(raw);

        let parsed = parse_token_policy(&proto).expect("should parse V2 SBT");
        assert_eq!(parsed.kind.as_deref(), Some("SBT"));
        assert!(!parsed.mint_burn_enabled);
        assert!(!parsed.transferable);
    }

    #[test]
    fn parse_unknown_version_returns_none() {
        let mut raw = vec![99u8]; // unknown version
        raw.extend_from_slice(&[0; 20]);
        let proto = wrap_as_token_policy_v3(raw);

        assert!(parse_token_policy(&proto).is_none());
    }

    #[test]
    fn parse_empty_bytes_returns_none() {
        assert!(parse_token_policy(&[]).is_none());
    }

    #[test]
    fn parse_truncated_v1_returns_none() {
        let proto = wrap_as_token_policy_v3(vec![1]); // version only, no ticker
        assert!(parse_token_policy(&proto).is_none());
    }

    // ── list_cached_policy_ids_from_prefs ─────────────────────────────

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
        assert!(TOKEN_PREFIX.starts_with("dsm.token."));
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

    #[test]
    fn token_create_request_roundtrip() {
        let req = generated::TokenCreateRequest {
            ticker: "ERA".into(),
            alias: "Era Token".into(),
            decimals: 8,
            max_supply_u128: vec![0u8; 16],
            policy_anchor: vec![0xAA; 32],
        };
        let bytes = req.encode_to_vec();
        let decoded = generated::TokenCreateRequest::decode(&*bytes).expect("decode");
        assert_eq!(decoded.ticker, "ERA");
        assert_eq!(decoded.alias, "Era Token");
        assert_eq!(decoded.decimals, 8);
        assert_eq!(decoded.max_supply_u128.len(), 16);
        assert_eq!(decoded.policy_anchor.len(), 32);
    }
}
