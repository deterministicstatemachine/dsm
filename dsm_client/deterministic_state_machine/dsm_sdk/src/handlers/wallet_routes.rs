// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet and balance route handlers for AppRouterImpl.
//!
//! Handles: `balance.get`, `balance.list`, `wallet.history`, `wallet.send`, `wallet.sendSmart`,
//! `wallet.sendOffline`

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::{relationship_tip_for_contact_restore, AppRouterImpl};
use super::response_helpers::{pack_envelope_ok, err};

#[derive(Debug, Clone)]
struct CachedPolicyMetadata {
    ticker: String,
    alias: String,
    decimals: u32,
}

fn parse_cached_policy_metadata(policy_bytes: &[u8]) -> Option<CachedPolicyMetadata> {
    let policy = generated::TokenPolicyV3::decode(policy_bytes).ok()?;
    let bytes = policy.policy_bytes;
    if bytes.is_empty() {
        return None;
    }

    let mut off = 0usize;
    let version = *bytes.get(off)?;
    off += 1;

    match version {
        1 => {
            let ticker_len = *bytes.get(off)? as usize;
            off += 1;
            let ticker = String::from_utf8(bytes.get(off..off + ticker_len)?.to_vec()).ok()?;
            off += ticker_len;

            let alias_len = ((*bytes.get(off)? as usize) << 8) | (*bytes.get(off + 1)? as usize);
            off += 2;
            let alias = String::from_utf8(bytes.get(off..off + alias_len)?.to_vec()).ok()?;
            off += alias_len;

            let decimals = *bytes.get(off)? as u32;
            Some(CachedPolicyMetadata {
                ticker,
                alias,
                decimals,
            })
        }
        2 => {
            off += 3; // kind + flags + threshold

            let ticker_len = *bytes.get(off)? as usize;
            off += 1;
            let ticker = String::from_utf8(bytes.get(off..off + ticker_len)?.to_vec()).ok()?;
            off += ticker_len;

            let alias_len = ((*bytes.get(off)? as usize) << 8) | (*bytes.get(off + 1)? as usize);
            off += 2;
            let alias = String::from_utf8(bytes.get(off..off + alias_len)?.to_vec()).ok()?;
            off += alias_len;

            let decimals = *bytes.get(off)? as u32;
            Some(CachedPolicyMetadata {
                ticker,
                alias,
                decimals,
            })
        }
        _ => None,
    }
}

fn enrich_balance_metadata(reply: &mut generated::BalanceGetResponse) {
    let token_id = reply.token_id.trim().to_uppercase();
    match token_id.as_str() {
        "ERA" => {
            reply.symbol = "ERA".to_string();
            reply.decimals = 0;
            reply.token_name = "ERA".to_string();
            return;
        }
        "DBTC" => {
            reply.token_id = "dBTC".to_string();
            reply.symbol = "dBTC".to_string();
            reply.decimals = 8;
            reply.token_name = "dBTC".to_string();
            return;
        }
        _ => {}
    }

    let anchor_b32 = crate::sdk::app_state::AppState::handle_app_state_request(
        &format!("dsm.token.{}", reply.token_id),
        "get",
        "",
    );
    if anchor_b32.is_empty() {
        return;
    }

    let policy_b32 = crate::sdk::app_state::AppState::handle_app_state_request(
        &format!("dsm.policy.{anchor_b32}"),
        "get",
        "",
    );
    if policy_b32.is_empty() {
        return;
    }

    let Some(policy_bytes) = crate::util::text_id::decode_base32_crockford(&policy_b32) else {
        return;
    };
    let Some(meta) = parse_cached_policy_metadata(&policy_bytes) else {
        return;
    };

    if !meta.ticker.is_empty() {
        reply.symbol = meta.ticker;
    }
    if !meta.alias.is_empty() {
        reply.token_name = meta.alias;
    }
    reply.decimals = meta.decimals;
}

fn ensure_default_visible_balances(items: &mut Vec<generated::BalanceGetResponse>) {
    for token_id in ["ERA", "dBTC"] {
        if items
            .iter()
            .any(|item| item.token_id.eq_ignore_ascii_case(token_id))
        {
            continue;
        }

        let mut reply = generated::BalanceGetResponse {
            token_id: token_id.to_string(),
            available: 0,
            locked: 0,
            ..Default::default()
        };
        enrich_balance_metadata(&mut reply);
        items.push(reply);
    }
}

pub(crate) fn canonicalize_token_id(token_id: &str) -> String {
    let trimmed = token_id.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match trimmed.to_ascii_uppercase().as_str() {
        "ERA" => "ERA".to_string(),
        "DBTC" => "dBTC".to_string(),
        _ => trimmed.to_string(),
    }
}

pub(crate) fn resolve_token_decimals(token_id: &str) -> u32 {
    match canonicalize_token_id(token_id).as_str() {
        "ERA" => 0,
        "dBTC" => 8,
        other => {
            let anchor_b32 = crate::sdk::app_state::AppState::handle_app_state_request(
                &format!("dsm.token.{other}"),
                "get",
                "",
            );
            if anchor_b32.is_empty() {
                return 0;
            }

            let policy_b32 = crate::sdk::app_state::AppState::handle_app_state_request(
                &format!("dsm.policy.{anchor_b32}"),
                "get",
                "",
            );
            if policy_b32.is_empty() {
                return 0;
            }

            let Some(policy_bytes) = crate::util::text_id::decode_base32_crockford(&policy_b32)
            else {
                return 0;
            };
            parse_cached_policy_metadata(&policy_bytes)
                .map(|meta| meta.decimals)
                .unwrap_or(0)
        }
    }
}

pub(crate) fn parse_display_amount_to_base_units(
    amount_str: &str,
    decimals: u32,
) -> Result<u64, String> {
    let trimmed = amount_str.trim();
    if trimmed.is_empty() {
        return Err("amount is required".to_string());
    }
    if trimmed.starts_with('-') {
        return Err("amount must be non-negative".to_string());
    }

    let mut parts = trimmed.split('.');
    let whole = parts.next().unwrap_or_default();
    let frac = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err("amount has too many decimal separators".to_string());
    }
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err("amount must be a decimal string".to_string());
    }
    if !frac.is_empty() && !frac.bytes().all(|b| b.is_ascii_digit()) {
        return Err("amount must be a decimal string".to_string());
    }
    if frac.len() > decimals as usize {
        return Err(format!("amount exceeds {} fractional digits", decimals));
    }

    let whole_norm = whole.trim_start_matches('0');
    let whole_digits = if whole_norm.is_empty() {
        "0"
    } else {
        whole_norm
    };
    let frac_padded = if decimals == 0 {
        if !frac.is_empty() {
            return Err("token does not support fractional amounts".to_string());
        }
        String::new()
    } else {
        let mut frac_buf = frac.to_string();
        while frac_buf.len() < decimals as usize {
            frac_buf.push('0');
        }
        frac_buf
    };

    let joined = format!("{}{}", whole_digits, frac_padded);
    let normalized = joined.trim_start_matches('0');
    let canonical = if normalized.is_empty() {
        "0"
    } else {
        normalized
    };
    canonical
        .parse::<u64>()
        .map_err(|e| format!("amount out of range: {e}"))
}

fn encode_offline_transfer_operation_canonical(
    to_device_id: &[u8; 32],
    amount: u64,
    token_id: &str,
    memo: &str,
) -> Vec<u8> {
    let mut out = Vec::new();

    let push_u8 = |out: &mut Vec<u8>, v: u8| out.push(v);
    let push_u32 = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_le_bytes());
    let push_bytes = |out: &mut Vec<u8>, bytes: &[u8]| {
        push_u32(out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    };
    let push_str = |out: &mut Vec<u8>, value: &str| push_bytes(out, value.as_bytes());

    push_u8(&mut out, 3); // Operation::Transfer tag
    push_bytes(&mut out, to_device_id);

    let mut balance_bytes = Vec::with_capacity(24);
    balance_bytes.extend_from_slice(&amount.to_le_bytes());
    balance_bytes.extend_from_slice(&0u64.to_le_bytes());
    balance_bytes.extend_from_slice(&0u64.to_le_bytes());
    push_bytes(&mut out, &balance_bytes);

    let canonical_token_id = canonicalize_token_id(token_id);
    push_str(&mut out, &canonical_token_id);
    push_u8(&mut out, 0); // TransactionMode::Bilateral
    push_bytes(&mut out, &[]);
    push_u8(&mut out, 2); // VerificationType::Bilateral
    push_u8(&mut out, 0); // pre_commit: None
    push_bytes(&mut out, to_device_id);
    push_str(
        &mut out,
        &crate::util::text_id::encode_base32_crockford(to_device_id),
    );
    push_str(&mut out, memo);
    push_bytes(&mut out, &[]);

    out
}

impl AppRouterImpl {
    pub(crate) async fn handle_wallet_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "balance.get" => {
                if self.core_sdk.get_current_state().is_err() {
                    if let Err(e) = self.core_sdk.restore_latest_archived_state_for_device() {
                        log::warn!("[balance.get] cold-start archive refresh failed: {}", e);
                    }
                }
                let token_id_opt: Option<String> = match generated::ArgPack::decode(&*q.params) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        if pack.body.is_empty() {
                            None
                        } else {
                            match std::str::from_utf8(&pack.body) {
                                Ok(s) if !s.is_empty() => Some(s.to_string()),
                                _ => return err("balance.get: token_id must be UTF-8".into()),
                            }
                        }
                    }
                    _ => return err("balance.get: expected ArgPack(codec=PROTO)".into()),
                };

                // Default to ERA when no token_id is provided; canonicalize for consistent balance lookup.
                let token_for_query_raw = token_id_opt.as_deref().unwrap_or("ERA");
                let token_for_query_owned = canonicalize_token_id(token_for_query_raw);
                let token_for_query = if token_for_query_owned.is_empty() {
                    token_for_query_raw
                } else {
                    &token_for_query_owned
                };

                // Use the wallet lane router, which prefers validated canonical projection rows
                // for non-ERA tokens and falls back to canonical state.
                match self.wallet.get_balance(Some(token_for_query)) {
                    Ok(bal) => {
                        let mut reply = generated::BalanceGetResponse {
                            token_id: token_for_query.to_string(),
                            available: bal.available(),
                            locked: bal.locked(),
                            ..Default::default()
                        };
                        enrich_balance_metadata(&mut reply);
                        pack_envelope_ok(generated::envelope::Payload::BalanceGetResponse(reply))
                    }
                    Err(e) => err(format!("balance.get failed: {e}")),
                }
            }

            // -------- wallet.history --------
            "wallet.history" => {
                // Require ArgPack(codec=PROTO) with body = [limit_le_u64 | offset_le_u64].
                let (limit, _offset): (Option<usize>, Option<usize>) =
                    match generated::ArgPack::decode(&*q.params) {
                        Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                            if pack.body.len() >= 16 {
                                let mut l = [0u8; 8];
                                l.copy_from_slice(&pack.body[0..8]);
                                let mut o = [0u8; 8];
                                o.copy_from_slice(&pack.body[8..16]);
                                (
                                    Some(u64::from_le_bytes(l) as usize),
                                    Some(u64::from_le_bytes(o) as usize),
                                )
                            } else {
                                (None, None)
                            }
                        }
                        _ => return err("wallet.history: expected ArgPack(codec=PROTO)".into()),
                    };

                let my_device_id_str =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

                // CRITICAL: Read from SQLite client_db - this is where bilateral transfers store transactions
                let sqlite_txs = crate::storage::client_db::get_transaction_history(
                    Some(&my_device_id_str),
                    limit,
                )
                .unwrap_or_default();

                // Debug: log what we got from SQLite
                log::info!(
                    "[wallet.history] Got {} transactions from SQLite for device {}",
                    sqlite_txs.len(),
                    my_device_id_str
                );
                for (i, t) in sqlite_txs.iter().enumerate().take(3) {
                    log::info!(
                        "[wallet.history] tx[{}]: id={}, amount={}, tx_type={}",
                        i,
                        t.tx_id,
                        t.amount,
                        t.tx_type
                    );
                }

                // Build a lookup map from device_id text to alias for resolving transaction counterparties
                // Use sync contact lookup from SQLite storage
                let alias_lookup: std::collections::HashMap<String, String> =
                    crate::storage::client_db::get_all_contacts()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|c| {
                            let device_txt =
                                crate::util::text_id::encode_base32_crockford(&c.device_id);
                            (device_txt, c.alias)
                        })
                        .collect();

                let txs: Vec<generated::TransactionInfo> = sqlite_txs
                    .into_iter()
                    .map(|t| {
                        // PROTO SAFETY:
                        // TransactionInfo.id is a `string` in dsm_app.proto and must be valid UTF-8.
                        // Some older records may contain non-UTF8 bytes (or otherwise invalid)
                        // which will cause strict protobuf decoders (TS) to fail.
                        // Prefer the stored tx_id, but deterministically fall back to tx_hash
                        // (canonical base32) if tx_id is not valid UTF-8.
                        // Deterministic protobuf safety: always use a known-good ASCII identifier.
                        // `tx_hash` is canonical base32 text in SQLite and is always UTF-8.
                        // Prefix to avoid ambiguity with other ids and keep stable format.
                        let safe_id: String = format!("tx_{}", t.tx_hash);

                        // Compute signed amount: positive if incoming, negative if outgoing
                        let amount_signed: i64 = if t.to_device == my_device_id_str {
                            t.amount as i64 // incoming: positive
                        } else {
                            -(t.amount as i64) // outgoing: negative
                        };

                        // Determine recipient/sender for UI display - resolve aliases
                        let recipient = if t.tx_type == "dbtc_mint" || t.tx_type == "dbtc_burn" {
                            "Bitcoin Network".to_string()
                        } else if t.to_device == my_device_id_str {
                            // Incoming: show who sent it
                            if t.tx_type == "faucet" {
                                "FAUCET".to_string()
                            } else {
                                // Try to resolve alias from from_device
                                alias_lookup
                                    .get(&t.from_device)
                                    .cloned()
                                    .unwrap_or_else(|| t.from_device.clone())
                            }
                        } else {
                            // Outgoing: show who received it - try to resolve alias
                            alias_lookup
                                .get(&t.to_device)
                                .cloned()
                                .unwrap_or_else(|| t.to_device.clone())
                        };

                        // Convert string tx_type to enum value
                        let tx_type_enum = match t.tx_type.as_str() {
                            "faucet" => generated::TransactionType::TxTypeFaucet,
                            "bilateral_offline" => {
                                generated::TransactionType::TxTypeBilateralOffline
                            }
                            "bilateral_offline_recovered" => {
                                generated::TransactionType::TxTypeBilateralOfflineRecovered
                            }
                            "online" => generated::TransactionType::TxTypeOnline,
                            "dbtc_mint" => generated::TransactionType::TxTypeDbtcMint,
                            "dbtc_burn" => generated::TransactionType::TxTypeDbtcBurn,
                            _ => generated::TransactionType::TxTypeUnspecified,
                        };

                        generated::TransactionInfo {
                            id: safe_id,
                            // Protocol/UI contract: device ids are binary 32-byte values.
                            // We store canonical base32 in SQLite for indexing, but must return bytes here.
                            from_device_id: crate::util::text_id::decode_base32_crockford(&t.from_device)
                                .filter(|b| b.len() == 32)
                                .unwrap_or_default(),
                            to_device_id: crate::util::text_id::decode_base32_crockford(&t.to_device)
                                .filter(|b| b.len() == 32)
                                .unwrap_or_default(),
                            token_id: canonicalize_token_id(
                                &t.metadata
                                    .get("token_id")
                                    .and_then(|b| String::from_utf8(b.clone()).ok())
                                    .unwrap_or_else(|| "ERA".to_string()),
                            ),
                            amount: t.amount,
                            fee: 0,
                            logical_index: t.chain_height,
                            // tx_hash is stored as canonical base32 text in SQLite.
                            tx_hash: crate::util::text_id::decode_base32_crockford(&t.tx_hash)
                                .filter(|b| b.len() == 32)
                                .unwrap_or_default(),
                            amount_signed,
                            tx_type: tx_type_enum as i32,
                            status: t.status.clone(),
                            recipient,
                            stitched_receipt: { t.proof_data.clone().unwrap_or_default() },
                            created_at: t.created_at,
                            memo: t
                                .metadata
                                .get("memo")
                                .map(|b| String::from_utf8_lossy(b).to_string())
                                .unwrap_or_default(),
                            // §4.3#3: Derive R_G from the stored receipt's devid_a for
                            // display-only consistency check. This is historical UI display
                            // only; protocol acceptance already enforced at ingest time.
                            receipt_verified: t
                                .proof_data
                                .as_ref()
                                .map(|b| {
                                    let r_g = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(b)
                                        .ok()
                                        .map(|r| crate::sdk::receipts::DeviceTreeAcceptanceCommitment::from_root(
                                            dsm::common::device_tree::DeviceTree::single(r.devid_a).root(),
                                        ));
                                    crate::sdk::receipts::verify_receipt_bytes(b, r_g)
                                })
                                .unwrap_or(false),
                        }
                    })
                    .collect();

                let reply = generated::WalletHistoryResponse { transactions: txs };
                // NEW: Return as Envelope.walletHistoryResponse (field 38)
                pack_envelope_ok(generated::envelope::Payload::WalletHistoryResponse(reply))
            }

            // -------- balance.list --------
            "balance.list" => {
                let current_state = match self.ensure_authoritative_wallet_state("balance.list") {
                    Ok(state) => Some(state),
                    Err(e) => {
                        log::warn!("[balance.list] authoritative state refresh failed: {}", e);
                        self.core_sdk.get_current_state().ok()
                    }
                };
                log::debug!("[balance.list] query handler entered");

                // Log the restored BCR state for debugging
                if let Some(cs) = current_state.as_ref() {
                    let era_balance = cs
                        .token_balances
                        .values()
                        .find_map(|b| if b.value() > 0 { Some(b.value()) } else { None })
                        .unwrap_or(0);
                    log::info!(
                        "[balance.list] restored BCR state hash={} state_number={} era_balance={}",
                        crate::util::text_id::encode_base32_crockford(&cs.hash),
                        cs.state_number,
                        era_balance
                    );
                } else {
                    log::warn!("[balance.list] no current state after restore");
                }

                // Enumerate token balances from the canonical token cache/projection path.
                let mut items: Vec<generated::BalanceGetResponse> = Vec::new();

                let device_id_txt =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                let current_state_number = current_state.as_ref().map(|cs| cs.state_number);
                let current_state_hash = current_state
                    .as_ref()
                    .and_then(|cs| cs.hash().ok())
                    .map(|hash| crate::util::text_id::encode_base32_crockford(&hash));

                // Seed from canonical state first.
                if let Some(cs) = current_state.as_ref() {
                    for (token_key, balance) in &cs.token_balances {
                        let token_id = canonicalize_token_id(&if let Some((_, t)) =
                            token_key.split_once('|')
                        {
                            t.to_string()
                        } else {
                            token_key.clone()
                        });
                        if token_id.chars().any(|c| c.is_control() || (c as u32) > 126) {
                            continue;
                        }
                        if !items.iter().any(|i| i.token_id == token_id) {
                            items.push(generated::BalanceGetResponse {
                                token_id,
                                available: balance.available(),
                                locked: balance.locked(),
                                ..Default::default()
                            });
                        }
                    }
                }

                // Merge canonical projection rows.
                if let Ok(projected) =
                    crate::storage::client_db::list_balance_projections(&device_id_txt)
                {
                    for record in projected {
                        let tok_id = canonicalize_token_id(&record.token_id);
                        if tok_id == "BTC_CHAIN" {
                            continue;
                        }
                        let projection_matches_current_state =
                            match (current_state_number, current_state_hash.as_ref()) {
                                (Some(state_number), Some(state_hash)) => {
                                    record.source_state_number == state_number
                                        && record.source_state_hash == *state_hash
                                }
                                _ => true,
                            };

                        if let Some(existing) = items.iter_mut().find(|i| i.token_id == tok_id) {
                            if projection_matches_current_state {
                                existing.available = record.available;
                                existing.locked = record.locked;
                            }
                        } else {
                            items.push(generated::BalanceGetResponse {
                                token_id: tok_id,
                                available: record.available,
                                locked: record.locked,
                                ..Default::default()
                            });
                        }
                    }
                }

                // Ensure built-in tokens always appear (even at zero balance).
                for builtin in &["ERA", "dBTC"] {
                    if !items.iter().any(|i| i.token_id == *builtin) {
                        items.push(generated::BalanceGetResponse {
                            token_id: builtin.to_string(),
                            available: 0,
                            locked: 0,
                            ..Default::default()
                        });
                    }
                }

                ensure_default_visible_balances(&mut items);

                // Deterministic order by token_id
                for item in &mut items {
                    enrich_balance_metadata(item);
                }
                items.sort_by(|a, b| a.token_id.cmp(&b.token_id));

                // Critical debug: log what we're actually returning
                log::debug!("[balance.list] returning {} balance items", items.len());
                for item in &items {
                    log::debug!(
                        "[balance.list] item: token_id={} available={} locked={}",
                        item.token_id,
                        item.available,
                        item.locked
                    );
                }

                let resp = generated::BalancesListResponse { balances: items };

                // Return as Envelope.balancesListResponse (field 34)
                let result =
                    pack_envelope_ok(generated::envelope::Payload::BalancesListResponse(resp));
                log::debug!(
                    "[balance.list] pack_envelope_ok success={} data_len={}",
                    result.success,
                    result.data.len()
                );
                result
            }

            _ => err(format!("unknown wallet query path: {}", q.path)),
        }
    }

    pub(crate) async fn handle_wallet_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "wallet.send" => {
                // Decode ArgPack from args
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("wallet.send: ArgPack.codec must be PROTO".into());
                }

                // Decode OnlineTransferRequest
                let transfer_req = match generated::OnlineTransferRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode OnlineTransferRequest failed: {e}")),
                };

                self.process_online_transfer_logic(transfer_req).await
            }

            "wallet.sendOffline" => {
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("wallet.sendOffline: ArgPack.codec must be PROTO".into());
                }
                let req = match generated::BilateralPrepareRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "wallet.sendOffline: decode BilateralPrepareRequest failed: {e}"
                        ))
                    }
                };
                if req.counterparty_device_id.len() != 32 {
                    return err(
                        "wallet.sendOffline: counterparty_device_id must be 32 bytes".into(),
                    );
                }

                let counterparty_device_id: [u8; 32] = match req.counterparty_device_id[..]
                    .try_into()
                {
                    Ok(v) => v,
                    Err(_) => {
                        return err(
                            "wallet.sendOffline: counterparty_device_id must be 32 bytes".into(),
                        )
                    }
                };
                let ble_address = if !req.ble_address.trim().is_empty() {
                    req.ble_address.trim().to_string()
                } else {
                    match crate::storage::client_db::get_contact_by_device_id(
                        &req.counterparty_device_id,
                    ) {
                        Ok(Some(contact)) => contact.ble_address.unwrap_or_default(),
                        Ok(None) => String::new(),
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: failed to resolve counterparty contact: {e}"
                            ))
                        }
                    }
                };
                if ble_address.is_empty() {
                    return err(
                        "wallet.sendOffline: ble_address unavailable for counterparty".into(),
                    );
                }

                let operation_bytes = if req.operation_data.is_empty() {
                    let token_id = if req.token_id_hint.trim().is_empty() {
                        "ERA".to_string()
                    } else {
                        canonicalize_token_id(&req.token_id_hint)
                    };
                    let transfer_amount = if req.transfer_amount_display.trim().is_empty() {
                        req.transfer_amount
                    } else {
                        let decimals = resolve_token_decimals(&token_id);
                        match parse_display_amount_to_base_units(
                            &req.transfer_amount_display,
                            decimals,
                        ) {
                            Ok(amount) => amount,
                            Err(e) => {
                                return err(format!(
                                    "wallet.sendOffline: invalid display amount: {e}"
                                ))
                            }
                        }
                    };
                    encode_offline_transfer_operation_canonical(
                        &counterparty_device_id,
                        transfer_amount,
                        &token_id,
                        req.memo_hint.trim(),
                    )
                } else {
                    req.operation_data.clone()
                };
                let operation =
                    match dsm::types::operations::Operation::from_bytes(&operation_bytes) {
                        Ok(op) => op,
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: failed to parse transfer operation: {e}"
                            ))
                        }
                    };

                #[cfg(all(target_os = "android", feature = "bluetooth", feature = "jni"))]
                {
                    let validity_iterations = if req.validity_iterations == 0 {
                        100
                    } else {
                        req.validity_iterations
                    };
                    // Try to get the adapter; if not yet injected, trigger on-demand
                    // injection via ensure_bluetooth_manager_and_sync_contact. This
                    // handles the race where the frontend fires sendOffline immediately
                    // after pairing finalized but before the Kotlin-side 15s pairing
                    // timeout fires the bilateral preconditions check.
                    let transport_adapter = match crate::bridge::get_ble_transport_adapter().await {
                        Ok(adapter) => adapter,
                        Err(_) => {
                            log::warn!(
                                "[wallet.sendOffline] BLE transport adapter not yet injected; attempting on-demand injection"
                            );
                            // Build a minimal contact from SQLite to trigger late-init
                            match crate::storage::client_db::get_contact_by_device_id(
                                &counterparty_device_id,
                            ) {
                                Ok(Some(contact_record)) => {
                                    let verified_contact =
                                        dsm::types::contact_types::DsmVerifiedContact {
                                            alias: contact_record.alias.clone(),
                                            device_id: counterparty_device_id,
                                            genesis_hash: {
                                                let mut gh = [0u8; 32];
                                                if contact_record.genesis_hash.len() == 32 {
                                                    gh.copy_from_slice(
                                                        &contact_record.genesis_hash,
                                                    );
                                                }
                                                gh
                                            },
                                            public_key: contact_record.public_key.clone(),
                                            genesis_material: Vec::new(),
                                            chain_tip: None,
                                            chain_tip_smt_proof: None,
                                            genesis_verified_online: true,
                                            verified_at_commit_height: 0,
                                            added_at_commit_height: 0,
                                            last_updated_commit_height: 0,
                                            verifying_storage_nodes: Vec::new(),
                                            ble_address: contact_record.ble_address.clone(),
                                        };
                                    if let Err(e) =
                                        crate::bluetooth::ensure_bluetooth_manager_and_sync_contact(
                                            verified_contact,
                                        )
                                        .await
                                    {
                                        log::warn!(
                                            "[wallet.sendOffline] On-demand BLE init failed: {e}"
                                        );
                                    }
                                }
                                _ => {
                                    log::warn!("[wallet.sendOffline] Cannot trigger on-demand BLE init: contact not found in SQLite");
                                }
                            }
                            // Retry after on-demand injection
                            match crate::bridge::get_ble_transport_adapter().await {
                                Ok(adapter) => adapter,
                                Err(e) => {
                                    return err(format!(
                                        "wallet.sendOffline: BLE transport adapter not ready after on-demand injection attempt: {e}"
                                    ))
                                }
                            }
                        }
                    };
                    let coordinator = match crate::bridge::get_ble_coordinator().await {
                        Ok(c) => c,
                        Err(_) => {
                            // Same pattern: coordinator should have been injected alongside adapter
                            log::warn!("[wallet.sendOffline] BLE coordinator not yet injected; retrying after brief yield");
                            tokio::task::yield_now().await;
                            match crate::bridge::get_ble_coordinator().await {
                                Ok(c) => c,
                                Err(e) => {
                                    return err(format!(
                                        "wallet.sendOffline: BLE coordinator not ready: {e}"
                                    ))
                                }
                            }
                        }
                    };
                    // Just-in-time contact sync: if the BTM doesn't have this contact
                    // but SQLite does, load it now. This covers cases where the init-time
                    // sync was missed (e.g., race between contacts.add and BLE init).
                    if !transport_adapter
                        .bilateral_handler()
                        .has_verified_contact(&counterparty_device_id)
                        .await
                    {
                        log::warn!(
                            "[wallet.sendOffline] Contact not in BTM — attempting just-in-time sync from SQLite"
                        );
                        if let Ok(Some(record)) =
                            crate::storage::client_db::get_contact_by_device_id(
                                &counterparty_device_id,
                            )
                        {
                            if let Some(verified) = record.to_verified_contact() {
                                match transport_adapter
                                    .bilateral_handler()
                                    .add_verified_contact(verified)
                                    .await
                                {
                                    Ok(_) => log::warn!(
                                        "[wallet.sendOffline] ✅ Just-in-time contact sync succeeded"
                                    ),
                                    Err(e) => log::error!(
                                        "[wallet.sendOffline] ❌ Just-in-time contact sync failed: {e}"
                                    ),
                                }
                            } else {
                                log::error!(
                                    "[wallet.sendOffline] Contact in SQLite but to_verified_contact() returned None (bad field lengths)"
                                );
                            }
                        } else {
                            log::error!(
                                "[wallet.sendOffline] Contact not found in SQLite either — user must add contact first"
                            );
                        }
                    }
                    let (prepare_envelope, commitment_hash) = match transport_adapter
                        .create_prepare_message_with_commitment(
                            counterparty_device_id,
                            operation,
                            validity_iterations,
                        )
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: failed to author bilateral prepare: {e}"
                            ))
                        }
                    };
                    let chunks = match coordinator.encode_message(
                        crate::bluetooth::BleFrameType::BilateralPrepare,
                        &prepare_envelope,
                    ) {
                        Ok(chunks) => chunks,
                        Err(e) => {
                            transport_adapter
                                .cancel_prepared_session_for_counterparty(counterparty_device_id)
                                .await;
                            return err(format!(
                                "wallet.sendOffline: failed to frame BLE prepare payload: {e}"
                            ));
                        }
                    };

                    use crate::jni::jni_common::get_java_vm_borrowed;
                    let vm = match get_java_vm_borrowed() {
                        Some(vm) => vm,
                        None => {
                            transport_adapter
                                .cancel_prepared_session_for_counterparty(counterparty_device_id)
                                .await;
                            return err(
                                "wallet.sendOffline: Java VM unavailable for BLE dispatch".into()
                            );
                        }
                    };
                    // JNI AttachGuard is !Send — do all JNI work in a sync block,
                    // drop the guard, THEN handle errors with async.
                    //
                    // Send the bilateral prepare chunks via the single BLE dispatch path.
                    let ble_send_result: Result<bool, String> = (|| {
                        let mut jni_env = vm.attach_current_thread().map_err(|e| {
                            format!("wallet.sendOffline: attach_current_thread failed: {e}")
                        })?;
                        crate::jni::unified_protobuf_bridge::send_ble_chunks_via_unified(
                            &mut jni_env,
                            &ble_address,
                            &chunks,
                        )
                        .map_err(|e| format!("wallet.sendOffline: BLE dispatch failed: {e}"))
                    })();
                    // jni_env is dropped here — safe to .await below
                    match ble_send_result {
                        Ok(true) => {}
                        Ok(false) => {
                            transport_adapter
                                .cancel_prepared_session_for_counterparty(counterparty_device_id)
                                .await;
                            return err(
                                "wallet.sendOffline: BLE bridge rejected the prepared chunks"
                                    .into(),
                            );
                        }
                        Err(e) => {
                            transport_adapter
                                .cancel_prepared_session_for_counterparty(counterparty_device_id)
                                .await;
                            return err(e);
                        }
                    }

                    let resp = generated::BilateralPrepareResponse {
                        commitment_hash: Some(generated::Hash32 {
                            v: commitment_hash.to_vec(),
                        }),
                        expires_iterations: validity_iterations,
                        ..Default::default()
                    };
                    pack_envelope_ok(generated::envelope::Payload::BilateralPrepareResponse(resp))
                }

                #[cfg(not(all(target_os = "android", feature = "bluetooth", feature = "jni")))]
                {
                    let _ = (counterparty_device_id, ble_address, operation);
                    err("wallet.sendOffline is only available on Android BLE builds".into())
                }
            }

            "wallet.sendSmart" => {
                use crate::storage::client_db::get_contact_by_alias;

                // Decode ArgPack from args
                let arg_pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if arg_pack.codec != generated::Codec::Proto as i32 {
                    return err("wallet.sendSmart: ArgPack.codec must be PROTO".into());
                }

                // Decode OnlineTransferSmartRequest
                let smart_req = match generated::OnlineTransferSmartRequest::decode(&*arg_pack.body)
                {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode OnlineTransferSmartRequest failed: {e}")),
                };

                // 1. Resolve Recipient (Crockford Base32 device_id OR Alias)
                // Try base32 decode first — only accept if it produces exactly 32 bytes
                // (a valid device ID). Otherwise fall through to alias lookup, since
                // short aliases like "ej8w2khr" are valid base32 but decode to <32 bytes.
                let to_device_id_vec = {
                    let as_device_id =
                        crate::util::text_id::decode_base32_crockford(&smart_req.recipient)
                            .filter(|b| b.len() == 32);

                    if let Some(bytes) = as_device_id {
                        bytes
                    } else {
                        match get_contact_by_alias(&smart_req.recipient) {
                            Ok(Some(c)) if c.device_id.len() == 32 => c.device_id.clone(),
                            Ok(Some(c)) => {
                                return err(format!(
                                    "Contact {} has invalid device ID length: {}",
                                    smart_req.recipient,
                                    c.device_id.len()
                                ))
                            }
                            _ => {
                                return err(format!(
                                "Recipient not found (not a valid device id or known alias): {}",
                                smart_req.recipient
                            ))
                            }
                        }
                    }
                };

                // 2. Resolve Chain Tip from Contact
                let local_genesis: [u8; 32] = match self
                    .core_sdk
                    .local_genesis_hash()
                    .await
                    .ok()
                    .and_then(|v| v.as_slice().try_into().ok())
                {
                    Some(genesis) => genesis,
                    None => {
                        return err(
                            "wallet.sendSmart: local genesis unavailable for canonical relationship routing"
                                .into(),
                        )
                    }
                };
                let chain_tip_vec =
                    match crate::storage::client_db::get_contact_by_device_id(&to_device_id_vec) {
                        Ok(Some(c)) => match relationship_tip_for_contact_restore(
                            self.device_id_bytes,
                            local_genesis,
                            &c,
                        ) {
                            Some(tip) => tip.to_vec(),
                            None => {
                                return err(
                                    "wallet.sendSmart: recipient relationship tip is unavailable or invalid"
                                        .into(),
                                )
                            }
                        },
                        Ok(None) => {
                            return err(
                                "wallet.sendSmart: recipient must be an added contact before online send"
                                    .into(),
                            )
                        }
                        Err(e) => {
                            return err(format!(
                                "wallet.sendSmart: failed to load recipient contact: {e}"
                            ))
                        }
                    };

                // 3. Parse display amount into canonical base units in the backend.
                let canonical_token_id = canonicalize_token_id(&smart_req.token_id);
                let token_decimals = resolve_token_decimals(&canonical_token_id);
                let amount: u64 =
                    match parse_display_amount_to_base_units(&smart_req.amount, token_decimals) {
                        Ok(v) => v,
                        Err(e) => return err(format!("Invalid amount: {}", e)),
                    };

                // 4. Fetch Sequence (from current state)
                let seq = match self.core_sdk.get_current_state() {
                    Ok(s) => s.state_number + 1,
                    _ => 1,
                };

                // 5. Construct OnlineTransferRequest with deterministic nonce
                let mut inner_req = generated::OnlineTransferRequest {
                    token_id: canonical_token_id,
                    to_device_id: to_device_id_vec.clone(),
                    amount,
                    memo: smart_req.memo,
                    nonce: vec![], // Deterministic nonce computed below from request content
                    signature: vec![],
                    from_device_id: self.device_id_bytes.to_vec(),
                    chain_tip: chain_tip_vec.clone(),
                    seq,
                    receipt_commit: Vec::new(), // ReceiptCommit built in process_online_transfer_logic
                    canonical_operation_bytes: Vec::new(),
                };

                // Compute deterministic nonce: Hash(domain || sender_id || receiver_id || prev_tip || seq || payload_digest)
                let mut payload_bytes = Vec::new();
                if let Err(e) = inner_req.encode(&mut payload_bytes) {
                    return err(format!(
                        "Failed to encode OnlineTransferRequest for nonce computation: {e}"
                    ));
                }
                let payload_digest =
                    dsm::crypto::blake3::domain_hash("DSM/payload-digest", &payload_bytes);

                let sender_id = match <[u8; 32]>::try_from(&self.device_id_bytes[..]) {
                    Ok(v) => v,
                    Err(_) => return err("Invalid sender device ID length".into()),
                };
                let receiver_id = match <[u8; 32]>::try_from(&to_device_id_vec[..]) {
                    Ok(v) => v,
                    Err(_) => return err("Invalid receiver device ID length".into()),
                };
                let prev_tip = match <[u8; 32]>::try_from(&chain_tip_vec[..]) {
                    Ok(v) => v,
                    Err(_) => return err("Invalid chain tip length".into()),
                };

                let nonce = dsm::crypto::generate_online_transfer_nonce(
                    &sender_id,
                    &receiver_id,
                    &prev_tip,
                    seq,
                    payload_digest.as_bytes(),
                );
                inner_req.nonce = nonce.to_vec();

                self.process_online_transfer_logic(inner_req).await
            }

            _ => err(format!("unknown wallet invoke method: {}", i.method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_token_id, encode_offline_transfer_operation_canonical,
        ensure_default_visible_balances, parse_display_amount_to_base_units,
    };
    use dsm::types::proto as generated;
    use dsm::types::operations::Operation;

    #[test]
    fn canonicalize_token_id_maps_dbtc_aliases() {
        assert_eq!(canonicalize_token_id("DBTC"), "dBTC");
        assert_eq!(canonicalize_token_id("dbtc"), "dBTC");
        assert_eq!(canonicalize_token_id(" dBTC "), "dBTC");
        assert_eq!(canonicalize_token_id("ERA"), "ERA");
    }

    #[test]
    fn parse_display_amount_to_base_units_handles_fractional_tokens() {
        assert_eq!(parse_display_amount_to_base_units("1.25", 2).unwrap(), 125);
        assert_eq!(
            parse_display_amount_to_base_units("1", 8).unwrap(),
            100000000
        );
        assert_eq!(
            parse_display_amount_to_base_units("0.00000001", 8).unwrap(),
            1
        );
    }

    #[test]
    fn parse_display_amount_to_base_units_rejects_overprecision() {
        assert!(parse_display_amount_to_base_units("1.001", 2).is_err());
        assert!(parse_display_amount_to_base_units("abc", 0).is_err());
    }

    #[test]
    fn parse_display_amount_to_base_units_rejects_fractional_whole_tokens() {
        assert!(parse_display_amount_to_base_units("1.5", 0).is_err());
    }

    #[test]
    fn offline_transfer_operation_encodes_canonical_dbtc_token_id() {
        let to_device_id = [0xabu8; 32];
        let bytes = encode_offline_transfer_operation_canonical(&to_device_id, 42, "DBTC", "memo");

        let op = Operation::from_bytes(&bytes).expect("transfer op should decode");
        match op {
            Operation::Transfer { token_id, .. } => {
                assert_eq!(String::from_utf8(token_id).unwrap(), "dBTC");
            }
            other => panic!("expected transfer op, got {other:?}"),
        }
    }

    #[test]
    fn ensure_default_visible_balances_adds_era_and_dbtc() {
        let mut items = Vec::<generated::BalanceGetResponse>::new();
        ensure_default_visible_balances(&mut items);

        assert!(items.iter().any(|item| item.token_id == "ERA"));
        assert!(items.iter().any(|item| item.token_id == "dBTC"));
    }
}
