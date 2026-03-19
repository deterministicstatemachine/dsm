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

fn canonicalize_token_id(token_id: &str) -> String {
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

                // Default to ERA when no token_id provided; canonicalize for consistent SQLite lookups.
                let token_for_query_raw = token_id_opt.as_deref().unwrap_or("ERA");
                let token_for_query_owned = canonicalize_token_id(token_for_query_raw);
                let token_for_query = if token_for_query_owned.is_empty() {
                    token_for_query_raw
                } else {
                    &token_for_query_owned
                };

                // For non-ERA tokens, prefer SQLite (authoritative after bilateral transfers).
                // Bilateral send/recv update SQLite only, not the in-memory wallet cache.
                if token_for_query != "ERA" {
                    let device_id_txt =
                        crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                    if let Ok(Some((available, locked))) =
                        crate::storage::client_db::get_token_balance(
                            &device_id_txt,
                            token_for_query,
                        )
                    {
                        let mut reply = generated::BalanceGetResponse {
                            token_id: token_for_query.to_string(),
                            available,
                            locked,
                            ..Default::default()
                        };
                        enrich_balance_metadata(&mut reply);
                        return pack_envelope_ok(generated::envelope::Payload::BalanceGetResponse(
                            reply,
                        ));
                    }
                }

                // Fall through to in-memory path for ERA or when SQLite has no row.
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
                                        .map(|r| dsm::common::device_tree::DeviceTree::single(r.devid_a).root());
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
                log::debug!("[balance.list] query handler entered");

                // Enumerate token balances - check client_db first (authoritative for offline bilateral),
                // then fall back to core state for other tokens.
                let mut items: Vec<generated::BalanceGetResponse> = Vec::new();

                // CRITICAL: Check client_db wallet_state first - this is where bilateral transfers update balance.
                // Must use encode_base32_crockford to match the key used by all balance write paths.
                let device_id_txt =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

                // Ensure wallet state exists before querying (creates with balance 0 if missing)
                if let Err(e) =
                    crate::storage::client_db::ensure_wallet_state_for_device(&device_id_txt)
                {
                    log::warn!(
                        "balance.list: failed to ensure wallet state for {}: {}",
                        device_id_txt,
                        e
                    );
                }

                log::debug!(
                    "[balance.list] Querying SQLite wallet_state for device_id={}",
                    device_id_txt
                );
                let sqlite_balance = crate::storage::client_db::get_wallet_state(&device_id_txt)
                    .ok()
                    .flatten()
                    .map(|ws| {
                        log::debug!(
                            "[balance.list] SQLite wallet_state found: balance={} updated_at={}",
                            ws.balance,
                            ws.updated_at
                        );
                        ws.balance
                    });

                if sqlite_balance.is_none() {
                    log::debug!(
                        "[balance.list] SQLite wallet_state not found for device_id={}",
                        device_id_txt
                    );
                }

                // Prefer SQLite balance as authoritative for ERA (bilateral transfers update here).
                // In unit tests and early bootstrap, SQLite may not be initialized yet; fall back
                // to the in-memory wallet/core balance to avoid false zeros.
                let era_available = match sqlite_balance {
                    Some(bal) => Some(bal),
                    None => self.wallet.get_balance(Some("ERA")).ok().map(|b| b.value()),
                };
                if let Some(bal) = era_available {
                    items.push(generated::BalanceGetResponse {
                        token_id: "ERA".to_string(),
                        available: bal,
                        locked: 0,
                        ..Default::default()
                    });
                }

                // Extract unique non-ERA token IDs from state and query each via the lane router.
                // No dedup needed — each lane does exactly one canonical key lookup.
                if let Ok(cs) = self.core_sdk.get_current_state() {
                    let mut seen_tokens: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    for k in cs.token_balances.keys() {
                        let token_id =
                            canonicalize_token_id(&if let Some((_, t)) = k.split_once('|') {
                                t.to_string()
                            } else {
                                k.clone()
                            });
                        if token_id == "ERA" {
                            continue;
                        }
                        if token_id.chars().any(|c| c.is_control() || (c as u32) > 126) {
                            continue;
                        }
                        seen_tokens.insert(token_id);
                    }

                    for token_id in &seen_tokens {
                        if !items.iter().any(|i| i.token_id == *token_id) {
                            if let Ok(bal) = self.wallet.get_balance(Some(token_id)) {
                                items.push(generated::BalanceGetResponse {
                                    token_id: token_id.clone(),
                                    available: bal.available(),
                                    locked: bal.locked(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }

                // Seed-on-read: flush any in-memory-only token balances into SQLite so that the
                // bilateral debit path (which reads from SQLite) always has a valid baseline.
                // This runs before the SQLite merge below so that the seeded rows are immediately
                // visible if merged back in the same pass.
                // ERA is excluded because it uses the separate wallet_state.balance column.
                for item in items.iter() {
                    if item.token_id == "ERA" || item.available == 0 {
                        continue;
                    }
                    match crate::storage::client_db::get_token_balance(
                        &device_id_txt,
                        &item.token_id,
                    ) {
                        Ok(None) => {
                            // No SQLite row yet — seed it from the in-memory value.
                            if let Err(e) = crate::storage::client_db::upsert_token_balance(
                                &device_id_txt,
                                &item.token_id,
                                item.available,
                                item.locked,
                            ) {
                                log::warn!(
                                    "[balance.list] Failed to seed SQLite row for {}:{}: {}",
                                    device_id_txt,
                                    item.token_id,
                                    e
                                );
                            } else {
                                log::info!(
                                    "[balance.list] Seeded SQLite row for {}:{} balance={}",
                                    device_id_txt,
                                    item.token_id,
                                    item.available
                                );
                            }
                        }
                        Ok(Some(_)) => {} // Row already exists — SQLite merge below handles it.
                        Err(e) => {
                            log::warn!(
                                "[balance.list] DB error checking seed for {}:{}: {}",
                                device_id_txt,
                                item.token_id,
                                e
                            );
                        }
                    }
                }

                // Merge persisted token balances from SQLite (authoritative for bilateral transfers).
                // The bilateral send path always writes to SQLite and never updates the in-memory
                // wallet, so SQLite wins unconditionally for any token it has a row for.
                // ERA is excluded because it uses the separate wallet_state.balance column.
                if let Ok(persisted) = crate::storage::client_db::get_token_balances(&device_id_txt)
                {
                    for (tok_id, available, locked) in persisted {
                        if tok_id == "ERA" {
                            continue;
                        }
                        // BTC_CHAIN is native on-chain Bitcoin — not a DSM token.
                        // It is only served via the bitcoin.wallet.balance endpoint
                        // and must NOT appear in the DSM token balance list.
                        if tok_id == "BTC_CHAIN" {
                            continue;
                        }
                        if let Some(existing) = items.iter_mut().find(|i| i.token_id == tok_id) {
                            // SQLite is authoritative — always overwrite the in-memory value.
                            existing.available = available;
                            existing.locked = locked;
                        } else {
                            items.push(generated::BalanceGetResponse {
                                token_id: tok_id,
                                available,
                                locked,
                                ..Default::default()
                            });
                        }
                    }
                }

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
                    encode_offline_transfer_operation_canonical(
                        &counterparty_device_id,
                        req.transfer_amount,
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

                if let Some(handler) = crate::bridge::bilateral_handler() {
                    if let Err(e) = handler
                        .reconcile_before_send(&req.counterparty_device_id)
                        .await
                    {
                        log::warn!(
                            "[wallet.sendOffline] reconcile_before_send failed for {}: {}",
                            crate::util::text_id::encode_base32_crockford(
                                &req.counterparty_device_id
                            ),
                            e
                        );
                    }
                }

                #[cfg(all(target_os = "android", feature = "bluetooth", feature = "jni"))]
                {
                    let validity_iterations = if req.validity_iterations == 0 {
                        100
                    } else {
                        req.validity_iterations
                    };
                    let coordinator = match crate::bridge::get_ble_coordinator().await {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: BLE coordinator not ready: {e}"
                            ))
                        }
                    };
                    let (chunks, commitment_hash) = match coordinator
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

                    use crate::jni::jni_common::get_java_vm_borrowed;
                    let vm = match get_java_vm_borrowed() {
                        Some(vm) => vm,
                        None => {
                            coordinator
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
                    // Step 1: Prime BLE transport — start GATT server + advertising
                    // so the peer can reconnect if the session dropped after pairing.
                    let _ble_primed: Result<bool, String> = (|| {
                        let mut jni_env = vm.attach_current_thread().map_err(|e| {
                            format!("wallet.sendOffline: attach for BLE prime failed: {e}")
                        })?;
                        let ready = crate::jni::unified_protobuf_bridge::ensure_ble_transport_ready(
                            &mut jni_env,
                            &ble_address,
                        );
                        if let Ok(false) = &ready {
                            log::warn!(
                                "[wallet.sendOffline] BLE transport not ready for {} — will try send anyway",
                                &ble_address
                            );
                        }
                        ready
                    })();
                    // Step 2: Send the bilateral prepare chunks via BLE.
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
                            coordinator
                                .cancel_prepared_session_for_counterparty(counterparty_device_id)
                                .await;
                            return err(
                                "wallet.sendOffline: BLE bridge rejected the prepared chunks"
                                    .into(),
                            );
                        }
                        Err(e) => {
                            coordinator
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

                // 3. Parse Amount
                let amount: u64 = match smart_req.amount.parse() {
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
                    token_id: canonicalize_token_id(&smart_req.token_id),
                    to_device_id: to_device_id_vec.clone(),
                    amount,
                    memo: smart_req.memo,
                    nonce: vec![], // Deterministic nonce computed below from request content
                    signature: vec![],
                    from_device_id: self.device_id_bytes.to_vec(),
                    chain_tip: chain_tip_vec.clone(),
                    seq,
                    receipt_commit: Vec::new(), // ReceiptCommit built in process_online_transfer_logic
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
    use super::{canonicalize_token_id, encode_offline_transfer_operation_canonical};
    use dsm::types::operations::Operation;

    #[test]
    fn canonicalize_token_id_maps_dbtc_aliases() {
        assert_eq!(canonicalize_token_id("DBTC"), "dBTC");
        assert_eq!(canonicalize_token_id("dbtc"), "dBTC");
        assert_eq!(canonicalize_token_id(" dBTC "), "dBTC");
        assert_eq!(canonicalize_token_id("ERA"), "ERA");
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
}
