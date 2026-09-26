// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet and balance route handlers for AppRouterImpl.
//!
//! Handles: `balance.get`, `balance.list`, `wallet.history`, `wallet.send`, `wallet.sendSmart`,
//! `wallet.sendOffline`

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::relationship_status::status_message;
use super::response_helpers::{pack_envelope_ok, err};

/// The token's decimal places, from the authority for that token.
///
/// ERA and dBTC are protocol-defined; everything else is a created or adopted
/// token whose decimals live in the registry. There is no hardcoded table:
/// one existed in TypeScript, knew only dBTC, and silently rendered every
/// custom token as whole units.
///
/// A token the registry cannot be read for, or holds no entry for, has no
/// known decimals: that is an error, never 0, because a wrong scale moves
/// value when a display amount is parsed back into base units.
pub fn token_decimals(token_id: &str) -> Result<u32, String> {
    let canonical = canonicalize_token_id(token_id);
    match canonical.to_ascii_uppercase().as_str() {
        "" => Err("a token's decimals were asked for with no token named".to_string()),
        "ERA" => Ok(0),
        "DBTC" | "BTC" => Ok(8),
        _ => crate::storage::client_db::token_registry::get_token_by_ticker(&canonical)
            .map_err(|e| format!("token registry unreadable for {canonical}: {e}"))?
            .map(|row| row.decimals)
            .ok_or_else(|| {
                format!("no registry entry for token {canonical}; its decimals are unknown")
            }),
    }
}

/// A signed amount rendered for display, sign included.
///
/// Transaction history shows outgoing amounts negative. The magnitude is
/// converted by the same function that renders balances, so a transfer and the
/// balance it moved can never disagree about what a unit is.
pub fn format_signed_base_units_for_display(amount: i64, decimals: u32) -> String {
    let magnitude = amount.unsigned_abs();
    let rendered = format_base_units_for_display(magnitude, decimals);
    if amount < 0 {
        format!("-{rendered}")
    } else {
        rendered
    }
}

/// Render a transaction's amount for display, from the token's own decimals.
///
/// `amount` and `amount_signed` remain canonical base units; this only adds
/// the string a UI prints. Amounts that predate signed accounting carry
/// `amount_signed == 0`, so fall back to the unsigned magnitude rather than
/// rendering every historical row as zero.
pub fn enrich_transaction_display(tx: &mut generated::TransactionInfo) -> Result<(), String> {
    let decimals = token_decimals(&tx.token_id)?;
    tx.display_amount = if tx.amount_signed != 0 {
        format_signed_base_units_for_display(tx.amount_signed, decimals)
    } else {
        format_base_units_for_display(tx.amount, decimals)
    };
    Ok(())
}

pub(crate) fn enrich_balance_metadata(
    reply: &mut generated::BalanceGetResponse,
) -> Result<(), String> {
    let token_id = reply.token_id.trim().to_uppercase();
    match token_id.as_str() {
        "ERA" => {
            reply.symbol = "ERA".to_string();
            reply.decimals = 0;
            reply.token_name = "ERA".to_string();
            reply.display_amount = format_base_units_for_display(reply.available, 0);
            if let Some(c) = crate::policy::builtin_policy_commit("ERA") {
                set_anchor(reply, &c);
            }
            // The protocol defines ERA, and its supply is the native reserve's,
            // from which every unit in circulation was released. ERA's policy
            // blob does not exist yet (§6.32), so nothing is stated about what
            // it permits: absent, never a defaulted "not permitted".
            reply.protocol_defined = true;
            reply.genesis_supply_display = format_base_units_for_display(
                dsm::economic::native_reserve::ERA_RESERVE_GENESIS_SUPPLY,
                0,
            );
            reply.permissions = None;
        }
        "DBTC" => {
            reply.token_id = "dBTC".to_string();
            reply.symbol = "dBTC".to_string();
            reply.decimals = 8;
            reply.token_name = "dBTC".to_string();
            reply.display_amount = format_base_units_for_display(reply.available, 8);
            if let Some(c) = crate::policy::builtin_policy_commit("dBTC") {
                set_anchor(reply, &c);
            }
            reply.protocol_defined = true;
        }
        // Created and adopted tokens carry their own decimals, and the wire
        // amount is BASE UNITS. Leaving decimals at the default meant a
        // consumer had no way to render 100_000 base units as "1,000.00" —
        // on device the wallet showed "100000 RIGB" for a token whose
        // canonical allocation was correct. The registry is authoritative for
        // this mapping, so read it rather than defaulting.
        _ => {
            let row =
                crate::storage::client_db::token_registry::get_token_by_ticker(&reply.token_id)
                    .map_err(|e| format!("token registry unreadable for {}: {e}", reply.token_id))?
                    .ok_or_else(|| {
                        format!(
                            "no registry entry for token {}; its balance cannot be named",
                            reply.token_id
                        )
                    })?;
            let policy = registered_policy(&row)?;
            reply.symbol = row.ticker.clone();
            reply.token_name = if row.alias.is_empty() {
                row.ticker
            } else {
                row.alias
            };
            reply.decimals = row.decimals;
            reply.canonical_token_id = row.token_id.clone();
            set_anchor(reply, &row.policy_commit);
            reply.icon_url = policy.icon_url.unwrap_or_default();
            reply.display_amount = format_base_units_for_display(reply.available, reply.decimals);
            // A device created this token; its committed policy fixes the
            // supply and says what holders may do with it.
            reply.protocol_defined = false;
            reply.genesis_supply_display =
                format_supply_for_display(policy.genesis_supply, reply.decimals);
            reply.permissions = Some(generated::TokenPolicyPermissions {
                burn_enabled: policy.burn_enabled,
                transferable: policy.transferable,
            });
        }
    }
    Ok(())
}

/// A registered token's committed policy: the bytes stored under its anchor,
/// verified against it, read by Core's one parser, and in agreement with the
/// row that names them.
///
/// A registered token's policy is stored with it, so a policy that is missing
/// or does not parse is an error. The row's ticker, alias, decimals and genesis
/// supply were copied from this policy at registration; a row that disagrees
/// with the bytes its own commit names is corrupt, and the wallet reports
/// nothing from either side rather than pick one.
fn registered_policy(
    row: &crate::storage::client_db::token_registry::TokenRegistryRow,
) -> Result<super::token_routes::ParsedTokenPolicy, String> {
    let anchor = crate::util::text_id::encode_base32_crockford(&row.policy_commit);
    let bytes = crate::storage::client_db::token_registry::load_policy_verified(&row.policy_commit)
        .map_err(|e| format!("policy {anchor} unreadable: {e}"))?
        .ok_or_else(|| format!("policy {anchor} of a registered token is not stored"))?;
    let policy = super::token_routes::parse_token_policy(&bytes)
        .ok_or_else(|| format!("stored policy {anchor} does not parse"))?;
    if policy.ticker != row.ticker
        || policy.alias != row.alias
        || policy.decimals != row.decimals
        || policy.genesis_supply != row.genesis_supply
    {
        return Err(format!(
            "registry row for {} disagrees with its policy {anchor}",
            row.ticker
        ));
    }
    Ok(policy)
}

/// How much of an anchor is enough to compare by eye.
///
/// Long enough that two anchors are not going to agree on it by accident, short
/// enough to actually read off a screen. It is a comparison aid and never an
/// identifier: nothing resolves a token by fingerprint.
const ANCHOR_FINGERPRINT_LEN: usize = 8;

/// Render a token's CPTA policy anchor onto the wire record.
///
/// A creator could not see the anchor of a token it had created — the adoption
/// card showed one, the creator's screen showed nothing — so handing it to a
/// peer meant deriving it by hand, off-device. Base32 Crockford, encoded by the
/// canonical encoder, because a second encoder gets the trailing-group padding
/// wrong and produces a plausible string that resolves to nothing.
fn set_anchor(reply: &mut generated::BalanceGetResponse, policy_commit: &[u8; 32]) {
    let b32 = crate::util::text_id::encode_base32_crockford(policy_commit);
    reply.anchor_fingerprint = b32.chars().take(ANCHOR_FINGERPRINT_LEN).collect();
    reply.policy_anchor_b32 = b32;
}

fn ensure_default_visible_balances(
    items: &mut Vec<generated::BalanceGetResponse>,
) -> Result<(), String> {
    let push_zero = |items: &mut Vec<generated::BalanceGetResponse>, token_id: &str| {
        if items
            .iter()
            .any(|item| item.token_id.eq_ignore_ascii_case(token_id))
        {
            return;
        }
        items.push(generated::BalanceGetResponse {
            token_id: token_id.to_string(),
            available: 0,
            locked: 0,
            ..Default::default()
        });
    };

    for token_id in ["ERA", "dBTC"] {
        push_zero(items, token_id);
    }

    // Every token in the registry is visible, held or not: registry
    // membership, not balance, is what makes a token yours to hold, and a
    // token you cannot see is one you cannot receive.
    let rows = crate::storage::client_db::token_registry::all_tokens()
        .map_err(|e| format!("token registry unreadable: {e}"))?;
    for row in rows {
        push_zero(items, &row.ticker);
    }
    Ok(())
}

/// Merge canonical projection rows over the head-synthesized `State` seed.
///
/// Both inputs descend from the canonical `DeviceState` head, but they are not
/// equivalent. `StateMachine::current_state()` synthesizes a compat `State`
/// directly from the head, and `Balance::from_state` hardcodes `locked: 0` — so
/// the seed carries the head's GROSS balance and no lock accounting whatsoever.
/// `balance_projections` is the settled view: `available` is already net of
/// `locked` (for dBTC, the sats committed to an in-flight withdrawal burn), and
/// a receiver's fresh credit is written ahead of the head, which does not
/// auto-credit until that device's next own operation. Where both name a token,
/// the projection is the one to report.
///
/// This merge used to be gated on the projection "matching the current state":
///
/// ```text
/// record.source_state_number == 0 && record.source_state_hash == State::hash()
/// ```
///
/// Neither half could hold. `build_balance_projection_from_device_head` stamps
/// `source_state_hash` with the device head root `r_A`; `State::hash()` digests
/// a different structure, so the two were never equal. The `State`-derived
/// writers stamped `source_state_number` with `state.hash[0]` — the first byte
/// of a BLAKE3 digest standing in for a counter that §4.3 says does not exist.
///
/// The gate was therefore false for every head-derived row, and `balance.list`
/// reported gross balances with `locked: 0`, overstating what was actually
/// spendable, and withheld incoming credits until the receiver's next own
/// operation. The startup reconcile rebuilt the projection from the head and the
/// read path threw it away.
///
/// There is no freshness comparison to restore — §4.3 leaves no counter and the
/// two hashes are not commensurable — and none is needed: the projection is by
/// construction the more complete of the two.
fn merge_balance_projections(
    items: &mut Vec<generated::BalanceGetResponse>,
    projections: Vec<crate::storage::client_db::BalanceProjectionRecord>,
) {
    for record in projections {
        let tok_id = canonicalize_token_id(&record.token_id);
        // dBTC is projected under its own token id; BTC_CHAIN is the on-chain
        // wallet view and is not a DSM balance.
        if tok_id == "BTC_CHAIN" {
            continue;
        }
        match items.iter_mut().find(|i| i.token_id == tok_id) {
            Some(existing) => {
                existing.available = record.available;
                existing.locked = record.locked;
            }
            None => items.push(generated::BalanceGetResponse {
                token_id: tok_id,
                available: record.available,
                locked: record.locked,
                ..Default::default()
            }),
        }
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

/// Render canonical base units as a display amount. The inverse of
/// [`parse_display_amount_to_base_units`], and deliberately its neighbour:
/// amount conversion has ONE owner, in Rust, in both directions.
///
/// Integer/string arithmetic — the digits are split, never divided — so a large
/// balance stays exact where floating point would round it.
pub fn format_base_units_for_display(base_units: u64, decimals: u32) -> String {
    format_digits_for_display(base_units.to_string(), decimals)
}

/// The same rule over a policy's genesis supply, which is `u128` in the
/// policy blob and the registry (SoFi §47).
pub(crate) fn format_supply_for_display(base_units: u128, decimals: u32) -> String {
    format_digits_for_display(base_units.to_string(), decimals)
}

fn format_digits_for_display(digits: String, decimals: u32) -> String {
    if decimals == 0 {
        return digits;
    }
    let d = decimals as usize;
    if digits.len() <= d {
        format!("0.{}", "0".repeat(d - digits.len()) + &digits)
    } else {
        let (whole, frac) = digits.split_at(digits.len() - d);
        format!("{whole}.{frac}")
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
    policy_commit: &[u8; 32],
) -> Vec<u8> {
    // Offline mode is HARD-REQUIRED to be chip-attested ("offline = chips"):
    // the canonical offline-bearer authority policy rides on the transfer so
    // `operation_requires_offline_bearer` fires and the send drives the
    // physical anchor (fail-closed if no chip).
    let policy = dsm::types::operations::canonical_offline_bearer_policy();
    log::info!(
        "[wallet.sendOffline] offline-bearer authority policy bound: policy_id={}",
        crate::util::text_id::encode_base32_crockford(&policy.policy_id)
    );
    dsm::types::operations::Operation::Transfer {
        to_device_id: to_device_id.to_vec(),
        amount: dsm::types::token_types::Balance::amount(amount),
        token_id: canonicalize_token_id(token_id).into_bytes(),
        policy_commit: *policy_commit,
        mode: dsm::types::operations::TransactionMode::Bilateral,
        nonce: Vec::new(),
        recipient: to_device_id.to_vec(),
        to: crate::util::text_id::encode_base32_crockford(to_device_id).into_bytes(),
        message: memo.to_string(),
        signature: Vec::new(),
        authority_policy: Some(policy),
    }
    .to_bytes()
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
                match self.wallet.get_balance(token_for_query) {
                    Ok(bal) => {
                        let mut reply = generated::BalanceGetResponse {
                            token_id: token_for_query.to_string(),
                            available: bal.available(),
                            locked: bal.locked(),
                            ..Default::default()
                        };
                        if let Err(e) = enrich_balance_metadata(&mut reply) {
                            return err(format!("balance.get: {e}"));
                        }
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
                let sqlite_txs = match crate::storage::client_db::get_transaction_history(
                    Some(&my_device_id_str),
                    limit,
                ) {
                    Ok(txs) => txs,
                    Err(e) => return err(format!("wallet.history: history unreadable: {e}")),
                };

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
                let contacts = match crate::storage::client_db::get_all_contacts() {
                    Ok(contacts) => contacts,
                    Err(e) => return err(format!("wallet.history: contacts unreadable: {e}")),
                };
                let alias_lookup: std::collections::HashMap<String, String> = contacts
                    .into_iter()
                    .map(|c| {
                        let device_txt =
                            crate::util::text_id::encode_base32_crockford(&c.device_id);
                        (device_txt, c.alias)
                    })
                    .collect();

                // A stored row is this device's own record: a device id or hash
                // that does not decode, or a transfer with no token, is a
                // corrupt row and an error, never an empty field.
                let bytes32 = |what: &str, text: &str| -> Result<Vec<u8>, String> {
                    crate::util::text_id::decode_base32_crockford(text)
                        .filter(|b| b.len() == 32)
                        .ok_or_else(|| format!("wallet.history: a stored {what} is not 32 bytes"))
                };
                let txs: Result<Vec<generated::TransactionInfo>, String> = sqlite_txs
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
                        let recipient = if t.tx_type == "faucet" {
                            "ERA reserve (faucet)".to_string()
                        } else if t.tx_type == "dbtc_mint" || t.tx_type == "dbtc_burn" {
                            "Bitcoin Network".to_string()
                        } else if t.to_device == my_device_id_str {
                            // Incoming: show who sent it - try to resolve alias
                            alias_lookup
                                .get(&t.from_device)
                                .cloned()
                                .unwrap_or_else(|| t.from_device.clone())
                        } else {
                            // Outgoing: show who received it - try to resolve alias
                            alias_lookup
                                .get(&t.to_device)
                                .cloned()
                                .unwrap_or_else(|| t.to_device.clone())
                        };

                        // The types this device writes. A stored type the wire
                        // does not name is a row this history cannot report,
                        // never an unspecified one.
                        let tx_type_enum = match t.tx_type.as_str() {
                            "faucet" => generated::TransactionType::TxTypeFaucet,
                            "bilateral_offline" => {
                                generated::TransactionType::TxTypeBilateralOffline
                            }
                            "online" => generated::TransactionType::TxTypeOnline,
                            "dbtc_mint" => generated::TransactionType::TxTypeDbtcMint,
                            "dbtc_burn" => generated::TransactionType::TxTypeDbtcBurn,
                            other => {
                                return Err(format!(
                                    "wallet.history: transaction {} has type {other:?}, which the \
                                     wire does not name",
                                    t.tx_id
                                ))
                            }
                        };

                        let token_id = t
                            .metadata
                            .get("token_id")
                            .and_then(|b| String::from_utf8(b.clone()).ok())
                            .ok_or_else(|| {
                                format!("wallet.history: transaction {} names no token", t.tx_id)
                            })?;
                        Ok(generated::TransactionInfo {
                            // Filled at the encoding boundary by enrich_transaction_display.
                            display_amount: String::new(),
                            id: safe_id,
                            // Protocol/UI contract: device ids are binary 32-byte values.
                            // We store canonical base32 in SQLite for indexing, but must return bytes here.
                            // A faucet row names no sender device: its source is the
                            // reserve, and a stored faucet row that names one is corrupt.
                            from_device_id: if t.tx_type == "faucet" {
                                if !t.from_device.is_empty() {
                                    return Err(format!(
                                        "wallet.history: faucet claim {} names a sender device",
                                        t.tx_id
                                    ));
                                }
                                Vec::new()
                            } else {
                                bytes32("sender device id", &t.from_device)?
                            },
                            to_device_id: bytes32("recipient device id", &t.to_device)?,
                            token_id: canonicalize_token_id(&token_id),
                            amount: t.amount,
                            // tx_hash is stored as canonical base32 text in SQLite.
                            tx_hash: bytes32("transaction hash", &t.tx_hash)?,
                            amount_signed,
                            tx_type: tx_type_enum as i32,
                            status: t.status.clone(),
                            recipient,
                            stitched_receipt: t.proof_data.clone().unwrap_or_default(),
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
                                .is_some_and(|b| receipt_state_holds(b)),
                        })
                    })
                    .collect();
                let txs = match txs {
                    Ok(txs) => txs,
                    Err(e) => return err(e),
                };

                // Rendered at the encoding boundary, for the same reason
                // balances are: a producer that builds a row without the
                // display form is easy to add and impossible to notice, and
                // the frontend has nothing to fall back on but a guess.
                let mut txs = txs;
                for tx in txs.iter_mut() {
                    if let Err(e) = enrich_transaction_display(tx) {
                        return err(format!("wallet.history: {e}"));
                    }
                }
                let reply = generated::WalletHistoryResponse { transactions: txs };
                // NEW: Return as Envelope.walletHistoryResponse (field 38)
                pack_envelope_ok(generated::envelope::Payload::WalletHistoryResponse(reply))
            }

            // -------- balance.list --------
            "balance.list" => {
                let current_state = match self.ensure_authoritative_wallet_state("balance.list") {
                    Ok(state) => state,
                    Err(e) => return err(format!("balance.list: authoritative state: {e}")),
                };

                let mut items: Vec<generated::BalanceGetResponse> = Vec::new();
                let device_id_txt =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                // Seed from the head's compat view; the projection merge below
                // overrides it wherever the settled view names a token.
                for (token_key, balance) in &current_state.token_balances {
                    let Some((_, ticker)) = token_key.split_once('|') else {
                        return err(format!(
                            "balance.list: balance key {token_key:?} is not a canonical \
                             {{prefix}}|{{token}} key"
                        ));
                    };
                    let token_id = canonicalize_token_id(ticker);
                    if token_id.is_empty()
                        || token_id.chars().any(|c| c.is_control() || (c as u32) > 126)
                    {
                        return err(format!(
                            "balance.list: balance key {token_key:?} names no printable token"
                        ));
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

                match crate::storage::client_db::list_balance_projections(&device_id_txt) {
                    Ok(projected) => merge_balance_projections(&mut items, projected),
                    Err(e) => return err(format!("balance.list: balance projections: {e}")),
                }

                // Built-in and registered tokens appear even at zero balance.
                if let Err(e) = ensure_default_visible_balances(&mut items) {
                    return err(format!("balance.list: {e}"));
                }

                // Every row carries its metadata, however it got here:
                // enrichment belongs at the encoding boundary, where it cannot
                // be skipped by whichever path produced a row.
                for item in items.iter_mut() {
                    if let Err(e) = enrich_balance_metadata(item) {
                        return err(format!("balance.list: {e}"));
                    }
                }
                items.sort_by(|a, b| a.token_id.cmp(&b.token_id));

                let resp = generated::BalancesListResponse { balances: items };
                pack_envelope_ok(generated::envelope::Payload::BalancesListResponse(resp))
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
                let req = match generated::OfflineTransferRequest::decode(&*arg_pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "wallet.sendOffline: decode OfflineTransferRequest failed: {e}"
                        ))
                    }
                };
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
                // Where the counterparty's phone is over BLE is the SDK's to know:
                // the address its contact holds, else the one its identity was
                // seen at this session.
                let ble_address = match crate::bluetooth::peer_address::counterparty_address(
                    &counterparty_device_id,
                ) {
                    Ok(Some(address)) => address,
                    Ok(None) => {
                        return err("wallet.sendOffline: no BLE address is known for the \
                             counterparty: the phones have not met over BLE"
                            .into())
                    }
                    Err(e) => return err(format!("wallet.sendOffline: {e}")),
                };

                let send_status = self
                    .calibrate_local_relationship_send_status(&counterparty_device_id)
                    .await;
                if !send_status.send_ready {
                    let message = status_message(&send_status);
                    let counterparty_b32 =
                        crate::util::text_id::encode_base32_crockford(&counterparty_device_id);
                    log::warn!(
                        "[wallet.sendOffline] refusing BLE dispatch for {}: {}",
                        counterparty_b32.get(..8).unwrap_or("?"),
                        message
                    );
                    return err(format!("wallet.sendOffline: {message}"));
                }

                // The token is named exactly: an omitted token is not ERA.
                let token_id = canonicalize_token_id(&req.token_id);
                if token_id.is_empty() {
                    return err("wallet.sendOffline: the request names no token".into());
                }
                let decimals = match token_decimals(&token_id) {
                    Ok(d) => d,
                    Err(e) => return err(format!("wallet.sendOffline: {e}")),
                };
                let transfer_amount =
                    match parse_display_amount_to_base_units(&req.amount, decimals) {
                        Ok(amount) => amount,
                        Err(e) => return err(format!("wallet.sendOffline: invalid amount: {e}")),
                    };
                let policy_commit = match self
                    .core_sdk
                    .resolve_policy_commit_strict(token_id.as_bytes())
                {
                    Ok(pc) => pc,
                    Err(e) => {
                        return err(format!(
                            "wallet.sendOffline: policy_commit resolve failed: {e}"
                        ))
                    }
                };
                let operation_bytes = encode_offline_transfer_operation_canonical(
                    &counterparty_device_id,
                    transfer_amount,
                    &token_id,
                    req.memo.trim(),
                    &policy_commit,
                );
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
                    // The live BLE stack carries the step; `init_dsm_sdk` builds it
                    // once the identity exists, and nothing builds a second one.
                    let contact = match crate::storage::client_db::get_contact_by_device_id(
                        &counterparty_device_id,
                    ) {
                        Ok(Some(record)) => match record.to_verified_contact() {
                            Ok(contact) => contact,
                            Err(e) => return err(format!("wallet.sendOffline: {e}")),
                        },
                        Ok(None) => {
                            return err(
                                "wallet.sendOffline: the counterparty is not a contact".into()
                            )
                        }
                        Err(e) => return err(format!("wallet.sendOffline: contact lookup: {e}")),
                    };
                    let transport_adapter = match crate::bridge::get_ble_transport_adapter().await {
                        Ok(adapter) => adapter,
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: the BLE stack is not live yet: {e}"
                            ))
                        }
                    };
                    let coordinator = match crate::bridge::get_ble_coordinator().await {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!(
                                "wallet.sendOffline: the BLE stack is not live yet: {e}"
                            ))
                        }
                    };
                    // Just-in-time contact sync: the BLE handler may have missed
                    // the init-time sync (a race between contacts.add and BLE init).
                    if !transport_adapter
                        .bilateral_handler()
                        .has_verified_contact(&counterparty_device_id)
                        .await
                    {
                        if let Err(e) = transport_adapter
                            .bilateral_handler()
                            .add_verified_contact(contact)
                            .await
                        {
                            return err(format!(
                                "wallet.sendOffline: just-in-time contact sync failed: {e}"
                            ));
                        }
                    }
                    let (prepare_envelope, commitment_hash) = match transport_adapter
                        .create_prepare_message_with_commitment(counterparty_device_id, operation)
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
                        // A prepare that cannot be framed can never be sent: the
                        // proposal, which reached no one, is cancelled — signed and
                        // kept, as any proposal its proposer ends before its
                        // confirm.
                        Err(e) => {
                            let cancelled = transport_adapter
                                .bilateral_handler()
                                .cancel_proposal(
                                    commitment_hash,
                                    "the prepare could not be framed for BLE".to_string(),
                                )
                                .await;
                            return err(match cancelled {
                                Ok(_) => format!(
                                    "wallet.sendOffline: failed to frame BLE prepare payload \
                                     (the proposal is cancelled): {e}"
                                ),
                                Err(cancel) => format!(
                                    "wallet.sendOffline: failed to frame BLE prepare payload: \
                                     {e}; the proposal is not cancelled: {cancel}"
                                ),
                            });
                        }
                    };

                    use crate::jni::jni_common::get_java_vm_borrowed;
                    // From here the proposal is prepared and its prepare is owed:
                    // a send that does not complete fails nothing, and the prepare
                    // is sent again when the link returns.
                    let vm = match get_java_vm_borrowed() {
                        Some(vm) => vm,
                        None => {
                            return err(
                                "wallet.sendOffline: Java VM unavailable for BLE dispatch; the \
                                 prepare is sent when the link returns"
                                    .into(),
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
                            return err(
                                "wallet.sendOffline: BLE bridge rejected the prepared chunks; the \
                                 prepare is sent again when the link returns"
                                    .into(),
                            );
                        }
                        Err(e) => {
                            return err(format!(
                                "{e}; the prepare is sent again when the link returns"
                            ));
                        }
                    }

                    let resp = generated::BilateralPrepareResponse {
                        commitment_hash: Some(generated::Hash32 {
                            v: commitment_hash.to_vec(),
                        }),
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

                // 2. Parse display amount into canonical base units in the backend.
                // The token is named exactly: an omitted token is not ERA.
                let token_id = smart_req.token_id.clone();
                if token_id.is_empty() {
                    return err("wallet.sendSmart: the request names no token".into());
                }
                let token_decimals = match token_decimals(&token_id) {
                    Ok(d) => d,
                    Err(e) => return err(format!("wallet.sendSmart: {e}")),
                };
                let amount: u64 =
                    match parse_display_amount_to_base_units(&smart_req.amount, token_decimals) {
                        Ok(v) => v,
                        Err(e) => return err(format!("Invalid amount: {}", e)),
                    };

                // 3. The request process_online_transfer_logic signs. It derives
                // the relationship tip and the nonce itself.
                let inner_req = generated::OnlineTransferRequest {
                    token_id,
                    to_device_id: to_device_id_vec.clone(),
                    amount,
                    memo: smart_req.memo,
                    nonce: vec![],
                    signature: vec![],
                    from_device_id: self.device_id_bytes.to_vec(),
                    canonical_operation_bytes: Vec::new(),
                    receipt_evidence_digest: Vec::new(),
                    sender_economic_position: 0,
                    sender_debit_mutation_index: 0,
                };

                self.process_online_transfer_logic(inner_req).await
            }

            _ => err(format!("unknown wallet invoke method: {}", i.method)),
        }
    }
}

/// Whether a stored receipt's state rules hold against the sender's
/// AUTHENTICATED Device Tree commitment: this device's own, or the one kept
/// for the contact. A root derived from the receipt itself is never used, so
/// a receipt from a sender with no kept commitment is not shown as verified.
fn receipt_state_holds(receipt_bytes: &[u8]) -> bool {
    let Ok(receipt) =
        dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(receipt_bytes)
    else {
        return false;
    };
    let own = crate::sdk::app_state::AppState::get_device_id()
        .is_some_and(|id| id.as_slice() == receipt.devid_a.as_slice());
    let commitment = if own {
        crate::sdk::app_state::AppState::get_device_tree_commitment()
    } else {
        match crate::storage::client_db::get_contact_device_tree_root(&receipt.devid_a) {
            Ok(root) => {
                root.map(dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root)
            }
            Err(e) => {
                log::error!("[wallet] receipt verification: the sender's Device Tree root is unreadable: {e}");
                return false;
            }
        }
    };
    commitment.is_some_and(|c| {
        dsm::verification::receipt_verification::verify_receipt_state(&receipt, &c).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        canonicalize_token_id, encode_offline_transfer_operation_canonical,
        ensure_default_visible_balances, format_base_units_for_display,
        format_signed_base_units_for_display, merge_balance_projections,
        parse_display_amount_to_base_units, token_decimals,
    };
    use crate::storage::client_db::BalanceProjectionRecord;
    use dsm::types::proto as generated;
    use dsm::types::operations::Operation;

    /// Rendering is exact at the magnitudes a hand-rolled conversion gets
    /// wrong, in both directions of sign.
    #[test]
    fn rendering_is_exact_at_the_awkward_magnitudes() {
        // Fewer digits than decimals: the leading zeros are produced.
        assert_eq!(format_base_units_for_display(5, 8), "0.00000005");
        assert_eq!(format_base_units_for_display(0, 2), "0.00");
        assert_eq!(format_base_units_for_display(100, 2), "1.00");
        // No fractional part is still written out, so the scale is visible.
        assert_eq!(format_base_units_for_display(100_000, 2), "1000.00");
        // Whole-unit tokens get no decimal point.
        assert_eq!(format_base_units_for_display(750, 0), "750");
        assert_eq!(
            format_base_units_for_display(u64::MAX, 2),
            "184467440737095516.15"
        );
        assert_eq!(
            format_signed_base_units_for_display(-100_000, 2),
            "-1000.00"
        );
        assert_eq!(format_signed_base_units_for_display(0, 2), "0.00");
        // i64::MIN cannot be negated in place.
        assert_eq!(
            format_signed_base_units_for_display(i64::MIN, 0),
            "-9223372036854775808"
        );
    }

    /// A projection row as `build_balance_projection_from_device_head` writes it:
    /// `source_state_hash` is the device head root `r_A`, NOT a `State::hash()`.
    fn head_projection(token_id: &str, available: u64, locked: u64) -> BalanceProjectionRecord {
        BalanceProjectionRecord {
            balance_key: format!("bk-{token_id}"),
            device_id: "DEV".to_string(),
            token_id: token_id.to_string(),
            policy_commit: format!("pc-{token_id}"),
            available,
            locked,
            // A device head root. Nothing in the read path may compare this to a
            // legacy `State::hash()` — they digest different structures.
            source_state_hash: "HEADROOT0000000000000000000000000".to_string(),
        }
    }

    fn seed(token_id: &str, available: u64, locked: u64) -> generated::BalanceGetResponse {
        generated::BalanceGetResponse {
            token_id: token_id.to_string(),
            available,
            locked,
            ..Default::default()
        }
    }

    /// THE DEFECT, in the shape that costs money: the head-synthesized seed
    /// reports a GROSS 300 with `locked: 0` (`Balance::from_state` hardcodes it),
    /// while the projection holds the settled 275 available / 25 locked.
    ///
    /// The old gate required `record.source_state_hash == State::hash()`, which a
    /// head-derived row (stamped with the head root `r_A`) can never satisfy — so
    /// the projection was discarded and `balance.list` told the user 300 was
    /// spendable when 25 of it was committed to an in-flight withdrawal burn.
    /// Restore that gate and this test goes red.
    #[test]
    fn projection_locked_accounting_overrides_the_gross_seed() {
        let mut items = vec![seed("dBTC", 300, 0)];
        merge_balance_projections(&mut items, vec![head_projection("dBTC", 275, 25)]);

        assert_eq!(items.len(), 1, "the seeded row is updated, not duplicated");
        assert_eq!(
            items[0].available, 275,
            "spendable must be net of locked, not the head's gross balance"
        );
        assert_eq!(
            items[0].locked, 25,
            "the seed has no lock accounting at all; only the projection does"
        );
    }

    /// A receiver's credit is written to the projection ahead of the head, which
    /// does not auto-credit until that device's next own operation. Under the old
    /// gate the credit was discarded and an incoming payment simply did not
    /// appear.
    #[test]
    fn projection_shows_a_receiver_credit_the_head_has_not_applied_yet() {
        let mut items = vec![seed("ERA", 100, 0)];
        merge_balance_projections(&mut items, vec![head_projection("ERA", 125, 0)]);

        assert_eq!(
            items[0].available, 125,
            "the fresh credit must be visible before the receiver's next own op"
        );
    }

    /// A token the legacy state never knew about still reaches the wallet.
    #[test]
    fn projection_only_token_is_added() {
        let mut items = vec![seed("ERA", 10, 0)];
        merge_balance_projections(&mut items, vec![head_projection("RIGB", 4_200, 0)]);

        let rigb = items
            .iter()
            .find(|i| i.token_id == "RIGB")
            .expect("projection-only token appears");
        assert_eq!(rigb.available, 4_200);
        assert_eq!(items.len(), 2);
    }

    /// A seeded token with no projection row is left exactly as it was — the
    /// merge overrides, it never blanks.
    #[test]
    fn seed_without_a_projection_is_untouched() {
        let mut items = vec![seed("ERA", 10, 3)];
        merge_balance_projections(&mut items, vec![head_projection("dBTC", 500, 0)]);

        let era = items.iter().find(|i| i.token_id == "ERA").unwrap();
        assert_eq!((era.available, era.locked), (10, 3));
    }

    /// The projection's token id is canonicalized before matching, so a `dbtc`
    /// row updates the seeded `dBTC` entry instead of adding a second one.
    #[test]
    fn projection_token_id_is_canonicalized_before_matching() {
        let mut items = vec![seed("dBTC", 1, 0)];
        merge_balance_projections(&mut items, vec![head_projection("dbtc", 90_000, 0)]);

        assert_eq!(items.len(), 1, "no duplicate dBTC row");
        assert_eq!(items[0].token_id, "dBTC");
        assert_eq!(items[0].available, 90_000);
    }

    /// `BTC_CHAIN` is the on-chain wallet view, not a DSM balance, and must not
    /// surface as a token row.
    #[test]
    fn btc_chain_projection_is_not_a_balance_row() {
        let mut items = vec![seed("ERA", 10, 0)];
        merge_balance_projections(&mut items, vec![head_projection("BTC_CHAIN", 999, 0)]);

        assert_eq!(items.len(), 1);
        assert!(!items.iter().any(|i| i.token_id == "BTC_CHAIN"));
    }

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
        let bytes = encode_offline_transfer_operation_canonical(
            &to_device_id,
            42,
            "DBTC",
            "memo",
            &[0u8; 32],
        );

        let op = Operation::from_bytes(&bytes).expect("transfer op should decode");
        match op {
            Operation::Transfer { token_id, .. } => {
                assert_eq!(String::from_utf8(token_id).unwrap(), "dBTC");
            }
            other => panic!("expected transfer op, got {other:?}"),
        }
    }

    /// A display amount is parsed back into base units with the token's
    /// decimals, so an unknown scale is an error: read as 0, "10" of a
    /// 2-decimal token would move 10 base units, a hundredth of what was meant.
    #[test]
    #[serial_test::serial]
    fn a_token_without_a_registry_entry_has_no_decimals() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        assert_eq!(token_decimals("ERA"), Ok(0));
        assert_eq!(token_decimals("dbtc"), Ok(8));
        let unknown = token_decimals("NOPE").expect_err("no registry entry");
        assert!(unknown.contains("no registry entry"), "{unknown}");
        assert!(token_decimals("  ").is_err(), "no token named");
    }

    #[test]
    #[serial_test::serial]
    fn ensure_default_visible_balances_adds_era_and_dbtc() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let mut items = Vec::<generated::BalanceGetResponse>::new();
        ensure_default_visible_balances(&mut items).expect("the registry reads");

        assert!(items.iter().any(|item| item.token_id == "ERA"));
        assert!(items.iter().any(|item| item.token_id == "dBTC"));
    }

    fn fresh_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    /// A created token's committed policy, packed by the one packer and stored
    /// under its anchor, as creation and adoption store it.
    fn store_created_policy(
        ticker: &str,
        decimals: u32,
        genesis_supply: u128,
        burn_enabled: bool,
        transferable: bool,
    ) -> (super::super::token_routes::ParsedTokenPolicy, [u8; 32]) {
        use prost::Message;
        let (signer_pk, _secret) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("a signer key");
        let policy = super::super::token_routes::ParsedTokenPolicy {
            creator_genesis: [0x11; 32],
            creator_device_id: [0x22; 32],
            ticker: ticker.to_string(),
            alias: format!("{ticker} token"),
            decimals,
            genesis_supply,
            release_rule: dsm::economic::token_policy::ReleaseRule::AllAtCreation,
            description: None,
            icon_url: Some("dsm:coin:v1:ABC".to_string()),
            burn_enabled,
            transferable,
            threshold: 1,
            signers: vec![signer_pk],
            allowlist_device_ids: vec![],
        };
        let bytes = generated::TokenPolicyV3 {
            policy_bytes: super::super::token_routes::build_policy_v3_bytes(&policy)
                .expect("the policy packs"),
        }
        .encode_to_vec();
        let commit = dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_POLICY,
            &bytes,
        );
        crate::storage::client_db::token_registry::upsert_policy(&commit, &bytes)
            .expect("the policy is stored under its anchor");
        (policy, commit)
    }

    /// The registry row adoption writes for a stored policy, with the supply
    /// it records.
    fn register(
        policy: &super::super::token_routes::ParsedTokenPolicy,
        commit: [u8; 32],
        genesis_supply: u128,
    ) {
        crate::storage::client_db::token_registry::insert_token(
            &crate::storage::client_db::token_registry::TokenRegistryRow {
                token_id: format!("token-{}", policy.ticker),
                policy_commit: commit,
                ticker: policy.ticker.clone(),
                alias: policy.alias.clone(),
                decimals: policy.decimals,
                genesis_supply,
                creator_device_id: policy.creator_device_id,
            },
        )
        .expect("the token is registered");
    }

    /// A protocol asset is one on Rust's word, not its ticker's. ERA's supply
    /// is the reserve's; its policy blob does not exist yet (§6.32), so
    /// nothing is stated about what it permits.
    #[test]
    #[serial_test::serial]
    fn era_is_protocol_defined_with_the_reserve_supply_and_no_stated_permissions() {
        fresh_db();
        let mut era = seed("ERA", 264, 0);
        super::enrich_balance_metadata(&mut era).expect("ERA is named");
        assert!(era.protocol_defined);
        assert_eq!(era.genesis_supply_display, "80000000000");
        assert_eq!(era.permissions, None, "no policy blob: nothing stated");
        let mut dbtc = seed("dBTC", 0, 0);
        super::enrich_balance_metadata(&mut dbtc).expect("dBTC is named");
        assert!(dbtc.protocol_defined);
    }

    /// A created token's facts are its committed policy's, read from bytes
    /// verified against the anchor: the supply in display units, what holders
    /// may do, the icon.
    #[test]
    #[serial_test::serial]
    fn a_registered_token_reports_its_policy_supply_and_permissions() {
        fresh_db();
        let (policy, commit) = store_created_policy("RIGB", 2, 100_000, true, false);
        register(&policy, commit, 100_000);
        let mut row = seed("RIGB", 5, 0);
        super::enrich_balance_metadata(&mut row).expect("a registered token is named");
        assert!(!row.protocol_defined);
        assert_eq!(row.genesis_supply_display, "1000.00");
        assert_eq!(
            row.permissions,
            Some(generated::TokenPolicyPermissions {
                burn_enabled: true,
                transferable: false,
            })
        );
        assert_eq!(row.icon_url, "dsm:coin:v1:ABC");
        assert_eq!(row.symbol, "RIGB");
        assert_eq!(row.display_amount, "0.05");
    }

    /// A row that disagrees with the bytes its own commit names is corrupt:
    /// refused, with nothing from either side reported.
    #[test]
    #[serial_test::serial]
    fn a_registry_row_that_disagrees_with_its_policy_is_refused() {
        fresh_db();
        let (policy, commit) = store_created_policy("DISA", 0, 10, true, true);
        register(&policy, commit, 11);
        let mut row = seed("DISA", 0, 0);
        let refused = super::enrich_balance_metadata(&mut row)
            .expect_err("a row disagreeing with its policy is refused");
        assert!(refused.contains("disagrees with its policy"), "{refused}");
        assert!(
            row.permissions.is_none(),
            "nothing reported from the policy"
        );
        assert!(
            row.genesis_supply_display.is_empty(),
            "nothing reported from the row"
        );
    }
}

#[cfg(test)]
mod history_tests {
    use crate::bridge::{AppQuery, AppRouter};
    use crate::handlers::app_router_impl::AppRouterImpl;
    use crate::storage::client_db::{store_transaction, TransactionRecord};
    use dsm::types::proto as generated;
    use prost::Message;

    /// `wallet.history` as the frontend asks for it: limit 16, offset 0.
    async fn history_of(
        router: &AppRouterImpl,
    ) -> Result<generated::WalletHistoryResponse, String> {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&16u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        let answer = router
            .query(AppQuery {
                path: "wallet.history".to_string(),
                params: generated::ArgPack {
                    codec: generated::Codec::Proto as i32,
                    body,
                    ..Default::default()
                }
                .encode_to_vec(),
            })
            .await;
        if !answer.success {
            return Err(answer.error_message.unwrap_or_default());
        }
        let env = crate::handlers::response_helpers::decode_local_envelope(&answer.data)?;
        match env.payload {
            Some(generated::envelope::Payload::WalletHistoryResponse(history)) => Ok(history),
            other => Err(format!("wallet.history answered {other:?}")),
        }
    }

    /// A faucet claim's row names no sender device — its source is the ERA
    /// reserve — and is reported as such: type FAUCET, an empty sender, the
    /// reserve as the counterparty label, the payout incoming. A stored
    /// faucet row that names a sender is corrupt and refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn history_reports_a_faucet_claim_from_the_reserve_with_no_sender_device() {
        let device = crate::test_support::one_device::Device::start(0x73).await;
        let me = crate::util::text_id::encode_base32_crockford(&device.router.device_id_bytes);
        let faucet_row = |id: &str, from: &str| TransactionRecord {
            tx_id: id.to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&[0x64; 32]),
            from_device: from.to_string(),
            to_device: me.clone(),
            amount: 100,
            tx_type: "faucet".to_string(),
            status: "confirmed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata: [("token_id".to_string(), b"ERA".to_vec())]
                .into_iter()
                .collect(),
        };

        store_transaction(&faucet_row("claim", "")).expect("store the faucet row");
        let reported = history_of(&device.router).await.expect("the history");
        assert_eq!(reported.transactions.len(), 1);
        let claim = &reported.transactions[0];
        assert_eq!(
            claim.tx_type,
            generated::TransactionType::TxTypeFaucet as i32
        );
        assert!(
            claim.from_device_id.is_empty(),
            "a claim names no sender device"
        );
        assert_eq!(claim.to_device_id, device.router.device_id_bytes.to_vec());
        assert_eq!(claim.recipient, "ERA reserve (faucet)");
        assert_eq!(claim.amount_signed, 100, "incoming");
        assert_eq!(claim.display_amount, "100");
        assert_eq!(claim.token_id, "ERA");

        let peer = crate::util::text_id::encode_base32_crockford(&[0x74u8; 32]);
        store_transaction(&faucet_row("corrupt", &peer)).expect("store the corrupt row");
        let refused = history_of(&device.router)
            .await
            .expect_err("a faucet row naming a sender is refused");
        assert!(
            refused.contains("corrupt") && refused.contains("names a sender device"),
            "{refused}"
        );
    }

    /// A history row is reported only as one of the types the wire names. A
    /// stored row of any other type is refused by name: it is never sent as
    /// "unspecified" for the frontend to relabel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn history_refuses_a_row_of_a_type_the_wire_does_not_name() {
        let device = crate::test_support::one_device::Device::start(0x71).await;
        let me = crate::util::text_id::encode_base32_crockford(&device.router.device_id_bytes);
        let peer = crate::util::text_id::encode_base32_crockford(&[0x72u8; 32]);
        let row = |id: &str, tx_type: &str, hash: u8| TransactionRecord {
            tx_id: id.to_string(),
            tx_hash: crate::util::text_id::encode_base32_crockford(&[hash; 32]),
            from_device: peer.clone(),
            to_device: me.clone(),
            amount: 7,
            tx_type: tx_type.to_string(),
            status: "confirmed".to_string(),
            commitment_hash: None,
            proof_data: None,
            metadata: [("token_id".to_string(), b"ERA".to_vec())]
                .into_iter()
                .collect(),
        };

        store_transaction(&row("known", "online", 0x61)).expect("store the online row");
        let reported = history_of(&device.router).await.expect("the history");
        assert_eq!(reported.transactions.len(), 1);
        let online = &reported.transactions[0];
        assert_eq!(
            online.tx_type,
            generated::TransactionType::TxTypeOnline as i32
        );
        assert_eq!(online.status, "confirmed");
        assert_eq!(online.amount_signed, 7, "incoming");
        assert_eq!(online.recipient, peer, "no contact: the sender's device id");

        store_transaction(&row("unnamed", "unilateral_send", 0x62)).expect("store the row");
        let refused = history_of(&device.router)
            .await
            .expect_err("a row of an unnamed type is refused");
        assert!(
            refused.contains("unnamed") && refused.contains("unilateral_send"),
            "{refused}"
        );
    }
}

#[cfg(test)]
mod send_offline_tests {
    use crate::bridge::{AppInvoke, AppRouter};
    use crate::handlers::app_router_impl::AppRouterImpl;
    use crate::storage::client_db::{store_contact, update_contact_ble_status, ContactRecord};
    use dsm::types::proto as generated;
    use prost::Message;

    /// `wallet.sendOffline` as the frontend asks for it: the user's intent.
    async fn send_offline(router: &AppRouterImpl, counterparty: [u8; 32]) -> Result<(), String> {
        let answer = router
            .invoke(AppInvoke {
                method: "wallet.sendOffline".to_string(),
                args: generated::ArgPack {
                    codec: generated::Codec::Proto as i32,
                    body: generated::OfflineTransferRequest {
                        counterparty_device_id: counterparty.to_vec(),
                        token_id: "ERA".to_string(),
                        amount: "1".to_string(),
                        memo: String::new(),
                    }
                    .encode_to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            })
            .await;
        if answer.success {
            Ok(())
        } else {
            Err(answer.error_message.unwrap_or_default())
        }
    }

    /// Where the counterparty's phone is over BLE is the SDK's to know; the
    /// request names no address. A send to a contact whose phone the SDK has
    /// not met is refused, saying so; once the contact holds an address, the
    /// send goes past that refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_offline_send_goes_where_the_sdk_has_seen_the_phone() {
        let device = crate::test_support::one_device::Device::start(0x75).await;
        let peer = [0x76u8; 32];
        store_contact(&ContactRecord {
            contact_id: crate::util::text_id::encode_base32_crockford(&peer),
            device_id: peer.to_vec(),
            alias: "peer".to_string(),
            genesis_hash: vec![0x77; 32],
            public_key: vec![0x78; 64],
            kyber_public_key: vec![0x4B; 1184],
            current_chain_tip: Some(vec![0x79; 32]),
            verified: true,
            verification_proof: None,
            metadata: std::collections::HashMap::new(),
            ble_address: None,
            status: "OnlineCapable".to_string(),
            needs_online_reconcile: false,
            previous_chain_tip: None,
        })
        .expect("store the contact");

        let refused = send_offline(&device.router, peer)
            .await
            .expect_err("the phones have not met");
        assert!(
            refused.contains("no BLE address is known for the counterparty"),
            "{refused}"
        );

        update_contact_ble_status(&peer, None, Some("AA:BB:CC:DD:EE:FF"))
            .expect("pairing persists the address");
        // A host build has no BLE: the send stops only at the dispatch, past
        // the address, the relationship's send status, the token, the amount
        // and its policy.
        assert_eq!(
            send_offline(&device.router, peer).await,
            Err("wallet.sendOffline is only available on Android BLE builds".to_string())
        );
    }
}
