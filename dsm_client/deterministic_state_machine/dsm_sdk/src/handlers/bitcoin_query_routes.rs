// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bitcoin query route handlers for AppRouterImpl.
//!
//! Handles all `bitcoin.*` query paths: address derivation, deposit status,
//! balance queries, wallet listing, health checks, tx status, and vault info.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};

impl AppRouterImpl {
    /// Dispatch handler for all `bitcoin.*` query routes.
    pub(crate) async fn handle_bitcoin_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- Bitcoin Tap (dBTC) queries --------
            "bitcoin.address" => {
                match crate::storage::client_db::get_active_bitcoin_account() {
                    Ok(Some(active_account)) => {
                        let secret = match String::from_utf8(active_account.secret_material.clone()) {
                            Ok(s) => s,
                            Err(_) => return err("bitcoin.address: secret is not UTF-8".into()),
                        };
                        let network = Self::bitcoin_network_from_u32(active_account.network);
                        let idx = active_account.active_receive_index;

                        // Derive address and pubkey from active_receive_index (single source of truth)
                        let (address, compressed_pubkey) = if active_account.import_kind == "wif" {
                            match Self::wif_address_and_pubkey(&secret, network) {
                                Ok((addr, pk)) => (addr, pk.to_vec()),
                                Err(e) => return err(format!("bitcoin.address: {e}")),
                            }
                        } else {
                            match Self::keystore_from_import(&active_account.import_kind, &secret, network) {
                                Ok(ks) => match ks.peek_receive_address(idx) {
                                    Ok((addr, pk)) => (addr, pk.to_vec()),
                                    Err(e) => return err(format!("bitcoin.address: {e}")),
                                },
                                Err(e) => return err(format!("bitcoin.address: {e}")),
                            }
                        };

                        let resp_index = if active_account.import_kind == "wif" { 0 } else { idx };
                        log::info!("[bitcoin.address] import_kind={}, index={}, address={}…", active_account.import_kind, resp_index, &address[..address.len().min(12)]);
                        pack_envelope_ok(generated::envelope::Payload::BitcoinAddressResponse(
                            generated::BitcoinAddressResponse {
                                address,
                                index: resp_index,
                                compressed_pubkey,
                            },
                        ))
                    }
                    Ok(None) => err("bitcoin.address: no Bitcoin account imported. Please import a wallet first.".into()),
                    Err(e) => err(format!("bitcoin.address: DB error: {e}")),
                }
            }

            "bitcoin.address.peek" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinAddressRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinAddressRequest failed: {e}")),
                };

                match crate::storage::client_db::get_active_bitcoin_account() {
                    Ok(Some(active_account)) => {
                        let secret = match String::from_utf8(active_account.secret_material.clone())
                        {
                            Ok(s) => s,
                            Err(_) => {
                                return err("bitcoin.address.peek: secret is not UTF-8".into())
                            }
                        };
                        let network = Self::bitcoin_network_from_u32(active_account.network);

                        let (address, compressed_pubkey, index) =
                            if active_account.import_kind == "wif" {
                                // WIF: single key — index is ignored, always returns the one address
                                match Self::wif_address_and_pubkey(&secret, network) {
                                    Ok((addr, pk)) => (addr, pk.to_vec(), 0u32),
                                    Err(e) => return err(format!("bitcoin.address.peek: {e}")),
                                }
                            } else {
                                match Self::keystore_from_import(
                                    &active_account.import_kind,
                                    &secret,
                                    network,
                                ) {
                                    Ok(ks) => match ks.peek_receive_address(req.index) {
                                        Ok((addr, pk)) => (addr, pk.to_vec(), req.index),
                                        Err(e) => {
                                            return err(format!(
                                                "bitcoin.address.peek: index {} out of range: {e}",
                                                req.index
                                            ))
                                        }
                                    },
                                    Err(e) => return err(format!("bitcoin.address.peek: {e}")),
                                }
                            };

                        pack_envelope_ok(generated::envelope::Payload::BitcoinAddressResponse(
                            generated::BitcoinAddressResponse {
                                address,
                                index,
                                compressed_pubkey,
                            },
                        ))
                    }
                    Ok(None) => err("bitcoin.address.peek: no Bitcoin account imported.".into()),
                    Err(e) => err(format!("bitcoin.address.peek: DB error: {e}")),
                }
            }

            "bitcoin.deposit.list" => {
                let vault_records = self.bitcoin_tap.list_vault_records().await;
                let entries: Vec<generated::BitcoinDepositEntry> = vault_records
                    .iter()
                    .map(|(id, record)| generated::BitcoinDepositEntry {
                        vault_op_id: id.clone(),
                        direction: match record.direction {
                            crate::sdk::bitcoin_tap_sdk::VaultDirection::BtcToDbtc => {
                                "btc_to_dbtc".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc => {
                                "dbtc_to_btc".to_string()
                            }
                        },
                        status: match record.state {
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::Initiated => {
                                "initiated".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation => {
                                "awaiting_confirmation".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::Claimable => {
                                "claimable".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::Completed => {
                                "completed".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::Expired => {
                                "expired".to_string()
                            }
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::Refunded => {
                                "refunded".to_string()
                            }
                        },
                        btc_amount_sats: record.btc_amount_sats,
                        htlc_address: record.htlc_address.clone().unwrap_or_default(),
                        vault_id: record.vault_id.clone().unwrap_or_default(),
                        is_fractional_successor: record.is_fractional_successor,
                        funding_txid: record.funding_txid.clone().unwrap_or_default(),
                    })
                    .collect();
                pack_envelope_ok(generated::envelope::Payload::BitcoinDepositListResponse(
                    generated::BitcoinDepositListResponse { deposits: entries },
                ))
            }

            "bitcoin.deposit.status" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::DepositStatusRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DepositStatusRequest failed: {e}")),
                };
                match self.bitcoin_tap.get_vault_op_status(&req.vault_op_id).await {
                    Ok(status) => pack_envelope_ok(generated::envelope::Payload::DepositResponse(
                        generated::DepositResponse {
                            vault_op_id: req.vault_op_id,
                            status: match status {
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::Initiated => {
                                    "initiated".to_string()
                                }
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation => {
                                    "awaiting_confirmation".to_string()
                                }
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::Claimable => {
                                    "claimable".to_string()
                                }
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::Completed => {
                                    "completed".to_string()
                                }
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::Expired => {
                                    "expired".to_string()
                                }
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::Refunded => {
                                    "refunded".to_string()
                                }
                            },
                            vault_id: String::new(),
                            external_commitment: vec![],
                            hash_lock: vec![],
                            htlc_script: vec![],
                            htlc_address: String::new(),
                            message: String::new(),
                            funding_txid: String::new(),
                        },
                    )),
                    Err(e) => err(format!("bitcoin.deposit.status failed: {e}")),
                }
            }

            "bitcoin.deposit.check_confirmations" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::DepositStatusRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DepositStatusRequest failed: {e}")),
                };

                let record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.check_confirmations: deposit not found: {e}"
                        ))
                    }
                };

                let funding_txid = match &record.funding_txid {
                    Some(t) if !t.is_empty() => t.clone(),
                    _ => {
                        // For DbtcToBtc exit deposits, auto-retry the claim broadcast.
                        // The initial broadcast in bitcoin.full.sweep may have failed
                        // (no UTXO, mempool unreachable, etc). The poll loop self-heals
                        // by re-attempting each cycle until the HTLC UTXO appears.
                        if record.direction
                            == crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc
                        {
                            let network = match crate::storage::client_db::list_bitcoin_accounts() {
                                Ok(accounts) => accounts
                                    .into_iter()
                                    .find(|a| a.active)
                                    .map(|a| Self::bitcoin_network_from_u32(a.network))
                                    .unwrap_or_else(
                                        crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                                    ),
                                Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                            };
                            let expected_policy_commit = crate::storage::client_db::find_withdrawal_by_exit_vault_op_id(&req.vault_op_id)
                                .ok()
                                .flatten()
                                .and_then(|withdrawal| {
                                    if withdrawal.policy_commit.len() != 32 {
                                        log::warn!(
                                            "[CHECK_CONFIRMATIONS] exit {} has non-32-byte withdrawal policy_commit ({} bytes); skipping policy-bound auto-claim check",
                                            req.vault_op_id,
                                            withdrawal.policy_commit.len()
                                        );
                                        return None;
                                    }
                                    let mut policy_commit = [0u8; 32];
                                    policy_commit.copy_from_slice(&withdrawal.policy_commit);
                                    Some(policy_commit)
                                });
                            match super::bitcoin_invoke_routes::try_claim_full_sweep_exit(
                                &self.bitcoin_tap,
                                &req.vault_op_id,
                                &record,
                                network,
                                expected_policy_commit,
                            )
                            .await
                            {
                                Ok(txid) => {
                                    log::info!(
                                        "[CHECK_CONFIRMATIONS] Auto-retry claim succeeded: {txid}"
                                    );
                                    txid
                                }
                                Err(e) => {
                                    log::warn!(
                                        "[CHECK_CONFIRMATIONS] Auto-retry claim failed: {e}"
                                    );
                                    let params = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
                                    return pack_envelope_ok(
                                        generated::envelope::Payload::DepositResponse(
                                            generated::DepositResponse {
                                                vault_op_id: req.vault_op_id,
                                                status: "claim_pending".to_string(),
                                                message: format!("0/{}", params.min_confirmations),
                                                vault_id: String::new(),
                                                external_commitment: vec![],
                                                hash_lock: vec![],
                                                htlc_script: vec![],
                                                htlc_address: String::new(),
                                                funding_txid: String::new(),
                                            },
                                        ),
                                    );
                                }
                            }
                        } else {
                            return pack_envelope_ok(
                                generated::envelope::Payload::DepositResponse(
                                    generated::DepositResponse {
                                        vault_op_id: req.vault_op_id,
                                        status: "no_funding_tx".to_string(),
                                        message: "0/0".to_string(),
                                        vault_id: String::new(),
                                        external_commitment: vec![],
                                        hash_lock: vec![],
                                        htlc_script: vec![],
                                        htlc_address: String::new(),
                                        funding_txid: String::new(),
                                    },
                                ),
                            );
                        }
                    }
                };

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let mempool =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.deposit.check_confirmations: mempool client init: {e}"
                            ))
                        }
                    };

                let params = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
                let mut required = params.min_confirmations;

                // Prefer the vault's stored min_confirmations over the runtime config.
                // The vault records the value from when it was created; the header-chain
                // depth check in verify_bitcoin_htlc enforces the vault's value.
                if let Some(vault_id) = &record.vault_id {
                    match self.bitcoin_tap.dlv_manager().get_vault(vault_id).await {
                        Ok(vault_lock) => {
                            let vault = vault_lock.lock().await;
                            if let dsm::vault::fulfillment::FulfillmentMechanism::BitcoinHTLC {
                                min_confirmations,
                                ..
                            } = &vault.fulfillment_condition
                            {
                                required = *min_confirmations;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "[CHECK_CONFIRMATIONS] Could not load vault {}: {} — using params required={}",
                                vault_id, e, required
                            );
                        }
                    }
                }

                let status = match mempool.tx_status(&funding_txid).await {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.check_confirmations: tx_status failed: {e}"
                        ))
                    }
                };

                let confs = if status.confirmed {
                    if let Some(block_height) = status.block_height {
                        match mempool.chain_tip_height().await {
                            Ok(tip) => tip.saturating_sub(block_height) + 1,
                            Err(_) => 1, // confirmed but tip query failed — at least 1
                        }
                    } else {
                        1
                    }
                } else {
                    0
                };

                let ready = confs >= required;
                let status_str = if ready { "confirmed" } else { "pending" };

                pack_envelope_ok(generated::envelope::Payload::DepositResponse(
                    generated::DepositResponse {
                        vault_op_id: req.vault_op_id,
                        status: status_str.to_string(),
                        message: format!("{confs}/{required}"),
                        vault_id: String::new(),
                        external_commitment: vec![],
                        hash_lock: vec![],
                        htlc_script: vec![],
                        htlc_address: String::new(),
                        // Carry the resolved funding_txid so the frontend can
                        // show the explorer link even if the initial listDeposits()
                        // had an empty funding_txid (full sweep auto-retry).
                        funding_txid: funding_txid.clone(),
                    },
                ))
            }

            "bitcoin.balance" => {
                // dBTC Invariant 7 + Property 9: auto-resolve any in-flight withdrawals
                // while we're online. Piggybacks on balance query lifecycle — fires every
                // time the wallet screen loads. No explicit frontend trigger needed.
                self.auto_resolve_pending_withdrawals().await;

                let token_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;

                // Prefer canonical projection/state-backed wallet balance.
                let (available, raw_locked) = match self.wallet.get_balance(Some(token_id)) {
                    Ok(bal) => (bal.available(), bal.locked()),
                    Err(_) => (0, 0),
                };
                // Defensive: if locked > available, the value is corrupted (e.g. negative i64
                // cast to u64). Clamp to 0 to prevent garbage display.
                let locked = if raw_locked > available {
                    0
                } else {
                    raw_locked
                };

                pack_envelope_ok(generated::envelope::Payload::BalanceGetResponse(
                    generated::BalanceGetResponse {
                        token_id: token_id.to_string(),
                        available,
                        locked,
                        symbol: "dBTC".to_string(),
                        decimals: 8,
                        token_name: "dBTC".to_string(),
                    },
                ))
            }

            "bitcoin.wallet.list" => {
                let accounts = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(a) => a,
                    Err(e) => return err(format!("bitcoin.wallet.list failed: {e}")),
                };
                let active_account_id = accounts
                    .iter()
                    .find(|a| a.active)
                    .map(|a| a.account_id.clone())
                    .unwrap_or_default();
                let entries = accounts
                    .into_iter()
                    .map(|a| generated::BitcoinWalletAccount {
                        account_id: a.account_id,
                        label: a.label,
                        import_kind: a.import_kind,
                        network: a.network,
                        active: a.active,
                        first_address: a.first_address.unwrap_or_default(),
                        active_receive_index: a.active_receive_index,
                    })
                    .collect();
                pack_envelope_ok(generated::envelope::Payload::BitcoinWalletListResponse(
                    generated::BitcoinWalletListResponse {
                        accounts: entries,
                        active_account_id,
                    },
                ))
            }

            "bitcoin.wallet.balance" => {
                let active_account = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts.into_iter().find(|a| a.active),
                    Err(_) => None,
                };

                let mut chain_addresses: Vec<String> = Vec::new();

                // For WIF accounts, derive the address from the key material
                // (same derivation as bitcoin.address handler) so the balance
                // matches the address shown in the UI.
                if let Some(acct) = &active_account {
                    if acct.import_kind == "wif" {
                        if let Ok(secret) = String::from_utf8(acct.secret_material.clone()) {
                            let network = Self::bitcoin_network_from_u32(acct.network);
                            if let Ok((wif_addr, _)) =
                                Self::wif_address_and_pubkey(&secret, network)
                            {
                                chain_addresses.push(wif_addr);
                            }
                        }
                    } else if let Some(addr) = &acct.first_address {
                        if !addr.trim().is_empty() {
                            chain_addresses.push(addr.clone());
                        }
                    }
                }

                let keys = self.bitcoin_keys.lock().await;
                // Scan a 5-address gap from the highest known index.
                // Funds can exist at ANY derived index, not just the active one.
                let db_idx = match crate::storage::client_db::get_active_bitcoin_account() {
                    Ok(Some(a)) => a.active_receive_index,
                    Ok(None) => 0,
                    Err(e) => {
                        log::error!("[bitcoin] failed to read active bitcoin account: {e}");
                        0
                    }
                };
                let high = keys.current_receive_index().max(db_idx);
                let scan_limit = high.saturating_add(5).min(20);
                for i in 0..=scan_limit {
                    if let Ok((addr, _pk)) = keys.peek_receive_address(i) {
                        if !chain_addresses.iter().any(|a| a == &addr) {
                            chain_addresses.push(addr);
                        }
                    }
                }
                // Also scan change addresses — funding TXs send change here.
                let change_high = keys.current_change_index();
                let change_limit = change_high.saturating_add(5).min(20);
                for i in 0..=change_limit {
                    if let Ok((addr, _pk)) = keys.peek_change_address(i) {
                        if !chain_addresses.iter().any(|a| a == &addr) {
                            chain_addresses.push(addr);
                        }
                    }
                }
                drop(keys);

                let records = self.bitcoin_tap.list_vault_records().await;

                // Track BTC locked in pending deposits (HTLC not yet settled)
                let mut outgoing_locked: u64 = 0;

                for (_id, rec) in records {
                    if !matches!(
                        rec.direction,
                        crate::sdk::bitcoin_tap_sdk::VaultDirection::BtcToDbtc
                    ) {
                        continue;
                    }
                    match &rec.state {
                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Initiated
                        | crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation
                        | crate::sdk::bitcoin_tap_sdk::VaultOpState::Claimable => {
                            outgoing_locked = outgoing_locked.saturating_add(rec.btc_amount_sats);
                        }
                        _ => {}
                    }
                }

                let network = active_account
                    .as_ref()
                    .map(|a| Self::bitcoin_network_from_u32(a.network))
                    .unwrap_or_else(crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network);

                const BTC_CHAIN_TOKEN_ID: &str = "BTC_CHAIN";

                let mempool =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.wallet.balance: mempool client init failed: {e}"
                            ))
                        }
                    };
                let (chain_balance, unconfirmed_balance) =
                    match mempool.addresses_balance_sats(&chain_addresses).await {
                        Ok(v) => v,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.wallet.balance: mempool.space query failed: {e}"
                            ));
                        }
                    };

                if unconfirmed_balance > 0 {
                    log::info!(
                        "[bitcoin.wallet.balance] confirmed={} unconfirmed={} (network={:?})",
                        chain_balance,
                        unconfirmed_balance,
                        network
                    );
                }

                // Native BTC "available" should reflect confirmed, spendable chain
                // balance only. Unconfirmed incoming is real Bitcoin activity, but it
                // is not final and should not be surfaced as spendable balance.
                let available = chain_balance;

                pack_envelope_ok(generated::envelope::Payload::BalanceGetResponse(
                    generated::BalanceGetResponse {
                        token_id: BTC_CHAIN_TOKEN_ID.to_string(),
                        available,
                        locked: outgoing_locked,
                        symbol: "BTC".to_string(),
                        decimals: 8,
                        token_name: "Bitcoin".to_string(),
                    },
                ))
            }

            "bitcoin.wallet.health" => {
                let active_account = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts.into_iter().find(|a| a.active),
                    Err(_) => None,
                };

                let mut chain_addresses: Vec<String> = Vec::new();
                if let Some(acct) = &active_account {
                    if let Some(addr) = &acct.first_address {
                        if !addr.trim().is_empty() {
                            chain_addresses.push(addr.clone());
                        }
                    }
                }

                let keys = self.bitcoin_keys.lock().await;
                // Use ..=idx (inclusive) so the address at the current receive index
                // is also scanned. The HTLC claim destination is peek_receive_address(idx)
                // and without this inclusive range that UTXO would never be found.
                // Use DB active_receive_index as floor to survive restart.
                let db_idx = match crate::storage::client_db::get_active_bitcoin_account() {
                    Ok(Some(a)) => a.active_receive_index,
                    Ok(None) => 0,
                    Err(e) => {
                        log::error!("[bitcoin] failed to read active bitcoin account: {e}");
                        0
                    }
                };
                let idx = keys.current_receive_index().max(db_idx).min(64);
                for i in 0..=idx {
                    if let Ok((addr, _pk)) = keys.peek_receive_address(i) {
                        if !chain_addresses.iter().any(|a| a == &addr) {
                            chain_addresses.push(addr);
                        }
                    }
                }
                drop(keys);

                let network = active_account
                    .as_ref()
                    .map(|a| Self::bitcoin_network_from_u32(a.network))
                    .unwrap_or_else(crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network);
                let network_str = match network {
                    dsm::bitcoin::types::BitcoinNetwork::Mainnet => "mainnet",
                    dsm::bitcoin::types::BitcoinNetwork::Testnet => "testnet",
                    dsm::bitcoin::types::BitcoinNetwork::Signet => "signet",
                };

                let rpc_url =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c.base_url().to_string(),
                        Err(_) => "https://mempool.space".to_string(),
                    };

                let rpc_url_masked = if let Some(pos) = rpc_url.find("://") {
                    let (scheme, rest) = rpc_url.split_at(pos + 3);
                    let host = rest.split('/').next().unwrap_or_default();
                    format!("{}{}", scheme, host)
                } else if rpc_url.is_empty() {
                    String::new()
                } else {
                    rpc_url.clone()
                };

                let addr_count = chain_addresses.len() as u32;

                let health_result: Result<(), String> =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(mempool) => match mempool.chain_tip_height().await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(e),
                    };

                let (source_label, reachable, reason) = match health_result {
                    Ok(()) => ("MEMPOOL", true, String::new()),
                    Err(e) => ("UNKNOWN", false, e),
                };

                let resp = generated::BitcoinWalletHealthResponse {
                    network: network_str.to_string(),
                    reachable,
                    source: source_label.to_string(),
                    reason,
                    rpc_url: rpc_url_masked,
                    tracked_addresses: addr_count,
                };

                pack_envelope_ok(generated::envelope::Payload::BitcoinWalletHealthResponse(
                    resp,
                ))
            }

            "bitcoin.tx.status" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinTxStatusRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinTxStatusRequest failed: {e}")),
                };
                if req.txid.len() != 32 {
                    return err(format!(
                        "bitcoin.tx.status: txid must be 32 bytes (got {})",
                        req.txid.len()
                    ));
                }

                let mut txid = [0u8; 32];
                txid.copy_from_slice(&req.txid);

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let (confirmations, in_mempool) = match self.query_tx_status(&txid, network).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.tx.status failed: {e}")),
                };

                let resp = generated::BitcoinTxStatusResponse {
                    confirmations,
                    in_mempool,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinTxStatusResponse(resp))
            }

            // ── Vault monitor ────────────────────────────────────────────
            "bitcoin.vault.list" => {
                let dlv = self.bitcoin_tap.dlv_manager();
                let vault_ids = match dlv.list_vaults().await {
                    Ok(ids) => ids,
                    Err(e) => return err(format!("bitcoin.vault.list failed: {e}")),
                };

                // Cross-reference with vault records for amount/direction/htlc
                let vault_records = self.bitcoin_tap.list_vault_records().await;
                let deposit_by_vault: std::collections::HashMap<
                    String,
                    &crate::sdk::bitcoin_tap_sdk::VaultOperation,
                > = vault_records
                    .iter()
                    .filter_map(|(_sid, rec)| rec.vault_id.as_ref().map(|vid| (vid.clone(), rec)))
                    .collect();

                let mut summaries = Vec::with_capacity(vault_ids.len());
                for vid in &vault_ids {
                    let vault_guard = match dlv.get_vault(vid).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let vault = vault_guard.lock().await;
                    let (amount_sats, direction, htlc_address) =
                        if let Some(rec) = deposit_by_vault.get(vid) {
                            (
                                rec.btc_amount_sats,
                                match rec.direction {
                                    crate::sdk::bitcoin_tap_sdk::VaultDirection::BtcToDbtc => {
                                        "btc_to_dbtc"
                                    }
                                    crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc => {
                                        "dbtc_to_btc"
                                    }
                                },
                                rec.htlc_address.clone().unwrap_or_default(),
                            )
                        } else {
                            (0, "unknown", String::new())
                        };

                    summaries.push(generated::BitcoinVaultSummary {
                        vault_id: vid.clone(),
                        state: match &vault.state {
                            dsm::vault::VaultState::Limbo => "limbo",
                            dsm::vault::VaultState::Active => "active",
                            dsm::vault::VaultState::Unlocked { .. } => "unlocked",
                            dsm::vault::VaultState::Claimed { .. } => "claimed",
                            dsm::vault::VaultState::Invalidated { .. } => "invalidated",
                        }
                        .to_string(),
                        amount_sats,
                        direction: direction.to_string(),
                        htlc_address,
                        entry_header: vault.entry_header.map(|h| h.to_vec()).unwrap_or_default(),
                    });
                }

                let resp = generated::BitcoinVaultListResponse { vaults: summaries };
                pack_envelope_ok(generated::envelope::Payload::BitcoinVaultListResponse(resp))
            }

            "bitcoin.vault.get" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinVaultGetRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinVaultGetRequest failed: {e}")),
                };
                if req.vault_id.is_empty() {
                    return err("bitcoin.vault.get: vault_id is required".to_string());
                }

                let dlv = self.bitcoin_tap.dlv_manager();
                let vault_guard = match dlv.get_vault(&req.vault_id).await {
                    Ok(v) => v,
                    Err(e) => return err(format!("bitcoin.vault.get: vault not found: {e}")),
                };
                let vault = vault_guard.lock().await;

                // Find associated deposit
                let vault_records = self.bitcoin_tap.list_vault_records().await;
                let deposit_rec = vault_records
                    .iter()
                    .find(|(_sid, rec)| rec.vault_id.as_deref() == Some(&req.vault_id));

                let (amount_sats, direction, htlc_address, vault_op_id) = if let Some((sid, rec)) =
                    deposit_rec
                {
                    (
                        rec.btc_amount_sats,
                        match rec.direction {
                            crate::sdk::bitcoin_tap_sdk::VaultDirection::BtcToDbtc => "btc_to_dbtc",
                            crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc => "dbtc_to_btc",
                        },
                        rec.htlc_address.clone().unwrap_or_default(),
                        sid.clone(),
                    )
                } else {
                    (0, "unknown", String::new(), String::new())
                };

                let resp = generated::BitcoinVaultGetResponse {
                    vault_id: req.vault_id,
                    state: match &vault.state {
                        dsm::vault::VaultState::Limbo => "limbo",
                        dsm::vault::VaultState::Active => "active",
                        dsm::vault::VaultState::Unlocked { .. } => "unlocked",
                        dsm::vault::VaultState::Claimed { .. } => "claimed",
                        dsm::vault::VaultState::Invalidated { .. } => "invalidated",
                    }
                    .to_string(),
                    amount_sats,
                    direction: direction.to_string(),
                    htlc_address,
                    entry_header: vault.entry_header.map(|h| h.to_vec()).unwrap_or_default(),
                    created_at_state: vault.created_at_state,
                    content_commitment: vault.content_commitment.commitment_hash.clone(),
                    vault_op_id,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinVaultGetResponse(resp))
            }

            // ── Fee estimation ────────────────────────────────────────────
            "bitcoin.fee.estimate" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinFeeEstimateRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinFeeEstimateRequest failed: {e}")),
                };
                if req.vault_op_id.trim().is_empty() {
                    return err("bitcoin.fee.estimate: vault_op_id is required".to_string());
                }

                let record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.fee.estimate: deposit not found: {e}")),
                };

                let fee_rate = req.fee_rate_sat_vb.max(1);
                let vsize = if req.is_fractional {
                    crate::sdk::bitcoin_tx_builder::ESTIMATED_SWEEP_VSIZE
                } else {
                    crate::sdk::bitcoin_tx_builder::ESTIMATED_CLAIM_VSIZE
                };
                let estimated_fee = fee_rate * vsize;
                let output_amount = record.btc_amount_sats.saturating_sub(estimated_fee);

                let resp = generated::BitcoinFeeEstimateResponse {
                    estimated_fee_sats: estimated_fee,
                    estimated_vsize: vsize,
                    output_amount_sats: output_amount,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinFeeEstimateResponse(
                    resp,
                ))
            }

            "bitcoin.withdraw.plan" => {
                let pack = match generated::ArgPack::decode(&*q.params) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinWithdrawalPlanRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!("decode BitcoinWithdrawalPlanRequest failed: {e}"))
                    }
                };

                if let Err(message) = self
                    .ensure_withdrawal_bridge_sync("bitcoin.withdraw.plan")
                    .await
                {
                    return err(message);
                }

                let plan = match self
                    .bitcoin_tap
                    .plan_withdrawal(
                        req.requested_net_sats,
                        &req.destination_address,
                        &self.device_id_bytes,
                    )
                    .await
                {
                    Ok(plan) => plan,
                    Err(e) => return err(format!("bitcoin.withdraw.plan failed: {e}")),
                };

                // Cache the plan so execute can look it up by plan_id.
                // All routing data stays in Rust — frontend only sends plan_id to confirm.
                if !plan.plan_id.is_empty() && !plan.legs.is_empty() {
                    self.cache_withdrawal_plan(
                        plan.plan_id.clone(),
                        plan.clone(),
                        req.destination_address.clone(),
                    )
                    .await;
                }

                #[allow(deprecated)]
                let resp = generated::BitcoinWithdrawalPlanResponse {
                    plan_id: plan.plan_id,
                    plan_class: plan.plan_class,
                    requested_net_sats: plan.requested_net_sats,
                    planned_net_sats: plan.planned_net_sats,
                    total_gross_exit_sats: plan.total_gross_exit_sats,
                    total_fee_sats: plan.total_fee_sats,
                    shortfall_sats: plan.shortfall_sats,
                    legs: plan
                        .legs
                        .into_iter()
                        .map(|leg| generated::BitcoinWithdrawalPlanLeg {
                            vault_id: leg.vault_id,
                            kind: leg.kind.as_str().to_string(),
                            source_amount_sats: leg.source_amount_sats,
                            gross_exit_sats: leg.gross_exit_sats,
                            estimated_fee_sats: leg.estimated_fee_sats,
                            estimated_net_sats: leg.estimated_net_sats,
                            remainder_sats: leg.remainder_sats,
                            successor_depth_after: leg.successor_depth_after,
                        })
                        .collect(),
                    blocked_vaults: plan
                        .blocked_vaults
                        .into_iter()
                        .map(|vault| generated::BitcoinWithdrawalBlockedVault {
                            vault_id: vault.vault_id,
                            amount_sats: vault.amount_sats,
                            reason: vault.reason,
                        })
                        .collect(),
                    route_commitment_id: vec![],
                    route_commitment_key: String::new(),
                    selector_snapshot_hash: vec![],
                    policy_commit: plan.policy_commit.to_vec(),
                    available_dbtc_sats: plan.available_dbtc_sats,
                };

                pack_envelope_ok(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(
                    resp,
                ))
            }

            _ => err(format!("unknown bitcoin query path: {}", q.path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use prost::Message;
    use serial_test::serial;

    use super::*;
    use crate::bridge::{AppQuery, AppRouter as _};
    use crate::handlers::bitcoin_helpers::set_withdrawal_bridge_sync_test_results;
    use crate::init::SdkConfig;
    use crate::storage::client_db;

    fn install_test_identity(device_id: Vec<u8>, genesis_hash: Vec<u8>, binding_key: Vec<u8>) {
        crate::reset_sdk_context_for_testing();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (public_key, _secret_key) =
            crate::sdk::signing_authority::derive_signing_keys_for_testing(
                &device_id,
                &genesis_hash,
                &binding_key,
            )
            .expect("derive canonical signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key,
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
    }

    fn init_withdrawal_query_test_router(test_name: &str) -> AppRouterImpl {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(PathBuf::from(format!(
            "./.dsm_testdata_{test_name}"
        )));
        install_test_identity(vec![0xAA; 32], vec![0xCC; 32], vec![0xDD; 32]);
        client_db::init_database().expect("init db");
        set_withdrawal_bridge_sync_test_results(Vec::new());
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reset_dbtc_storage_test_state();

        AppRouterImpl::new(SdkConfig {
            node_id: format!("withdraw-query-{test_name}"),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn pack_proto<T: Message>(message: &T) -> Vec<u8> {
        generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: message.encode_to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn decode_framed_envelope(bytes: &[u8], route: &str) -> generated::Envelope {
        assert!(!bytes.is_empty(), "{route}: empty response bytes");
        assert_eq!(bytes[0], 0x03, "{route}: expected FramedEnvelopeV3 prefix");
        generated::Envelope::decode(&bytes[1..])
            .unwrap_or_else(|e| panic!("{route}: failed to decode envelope: {e}"))
    }

    fn put_active_vault(vault_id: &str, amount_sats: u64) {
        let proto = generated::LimboVaultProto {
            id: vault_id.to_string(),
            fulfillment_condition: Some(generated::FulfillmentMechanism {
                kind: Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(
                    generated::BitcoinHtlc {
                        hash_lock: vec![0x11; 32],
                        refund_hash_lock: vec![0x22; 32],
                        refund_iterations: 42,
                        bitcoin_pubkey: vec![0x03; 33],
                        expected_btc_amount_sats: amount_sats,
                        network: 0,
                        min_confirmations: 1,
                    },
                )),
            }),
            ..Default::default()
        }
        .encode_to_vec();

        client_db::put_vault(vault_id, &proto, "active", &[0x44; 80], amount_sats)
            .expect("store vault");
    }

    fn put_active_vault_record(vault_id: &str, amount_sats: u64) {
        client_db::upsert_vault_record(&client_db::PersistedVaultRecord {
            vault_op_id: format!("deposit-{vault_id}"),
            direction: "btc_to_dbtc".to_string(),
            vault_state: "completed".to_string(),
            hash_lock: vec![0x33; 32],
            deposit_nonce: Some(vec![0x55; 32]),
            vault_id: Some(vault_id.to_string()),
            btc_amount_sats: amount_sats,
            btc_pubkey: vec![0x03; 33],
            htlc_script: Some(vec![0x66; 64]),
            htlc_address: Some("tb1qtest".to_string()),
            external_commitment: None,
            refund_iterations: 42,
            created_at_state: 1,
            entry_header: Some(vec![0x44; 80]),
            parent_vault_id: None,
            successor_depth: 0,
            is_fractional_successor: false,
            refund_hash_lock: vec![0x22; 32],
            destination_address: None,
            funding_txid: None,
            exit_amount_sats: 0,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
        })
        .expect("store vault record");
    }

    #[tokio::test]
    #[serial]
    #[ignore]
    async fn bitcoin_withdraw_plan_fails_when_bridge_sync_fails() {
        let router = init_withdrawal_query_test_router("withdraw_plan_sync_fail");
        set_withdrawal_bridge_sync_test_results(vec![Err("fatal failure".to_string())]);

        let res = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats: 100_000,
                    destination_address: "tb1qdest".to_string(),
                }),
            })
            .await;

        assert!(
            !res.success,
            "bitcoin.withdraw.plan should fail closed on bridge sync failure"
        );
        let err = res.error_message.expect("expected bridge sync error");
        assert!(
            err.contains("bridge sync failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_plan_fails_when_global_catalog_listing_fails() {
        let router = init_withdrawal_query_test_router("withdraw_plan_list_fail");
        let requested_net_sats = 150_000;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        put_active_vault("vault-list-fail", requested_net_sats + full_fee);
        put_active_vault_record("vault-list-fail", requested_net_sats + full_fee);

        set_withdrawal_bridge_sync_test_results(vec![Ok(generated::StorageSyncResponse {
            success: true,
            pulled: 0,
            processed: 0,
            pushed: 0,
            errors: Vec::new(),
        })]);
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::set_dbtc_storage_list_results(vec![Err(
            "catalog unavailable".to_string(),
        )]);

        let res = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats,
                    destination_address: "tb1qdest".to_string(),
                }),
            })
            .await;

        assert!(
            !res.success,
            "planning should fail closed when listing fails"
        );
        let err = res.error_message.expect("expected listing error");
        assert!(
            err.contains("catalog unavailable"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_plan_caches_plan_for_execute() {
        let router = init_withdrawal_query_test_router("withdraw_plan_caches");
        let requested_net_sats = 150_000;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        put_active_vault("vault-cache-test", requested_net_sats + full_fee);
        put_active_vault_record("vault-cache-test", requested_net_sats + full_fee);

        set_withdrawal_bridge_sync_test_results(vec![Ok(generated::StorageSyncResponse {
            success: true,
            pulled: 0,
            processed: 0,
            pushed: 0,
            errors: Vec::new(),
        })]);

        let res = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats,
                    destination_address: "tb1qdest".to_string(),
                }),
            })
            .await;

        assert!(
            res.success,
            "planning should succeed: {:?}",
            res.error_message
        );
        let env = decode_framed_envelope(&res.data, "bitcoin.withdraw.plan");
        let resp = match env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(resp)) => resp,
            other => panic!("unexpected plan payload: {other:?}"),
        };
        assert!(!resp.plan_id.is_empty());
        assert!(!resp.legs.is_empty());

        let cached = router.take_cached_withdrawal_plan(&resp.plan_id).await;
        assert!(cached.is_some(), "plan should be cached after query");
        let cached = cached.expect("cached plan");
        assert_eq!(cached.destination_address, "tb1qdest");
        assert_eq!(cached.plan.plan_id, resp.plan_id);
    }
}
