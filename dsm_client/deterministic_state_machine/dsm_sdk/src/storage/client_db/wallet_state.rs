// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet state persistence (balance, chain tip, status).

use anyhow::Result;
use log::{debug, info, warn};
use rusqlite::{
    params,
    types::{Type, ValueRef},
    OptionalExtension,
};

use super::get_connection;
use super::upsert_token_balance;
use super::types::WalletState;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

fn seed_builtin_token_rows_for_device(device_id: &str) -> Result<()> {
    // dBTC is treated as a canonical built-in token. Seed a zero row early so
    // downstream balance reads and bilateral debit paths never depend on a
    // missing SQLite row.
    upsert_token_balance(device_id, "dBTC", 0, 0)
}

fn read_hashish_column_as_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    label: &str,
) -> rusqlite::Result<String> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(String::new()),
        ValueRef::Text(text) => String::from_utf8(text.to_vec())
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(e))),
        ValueRef::Blob(bytes) => {
            if bytes.is_empty() {
                Ok(String::new())
            } else {
                Ok(crate::util::text_id::encode_base32_crockford(bytes))
            }
        }
        value => Err(rusqlite::Error::InvalidColumnType(
            index,
            label.to_string(),
            value.data_type(),
        )),
    }
}

/// Ensure a wallet_state row exists for `device_id` (base32). If none exists, create one
/// with a zero balance. Useful during genesis/application bootstrap to guarantee the
/// `get_all_balances_strict` fast-path succeeds.
pub fn ensure_wallet_state_for_device(device_id: &str) -> Result<()> {
    match get_wallet_state(device_id) {
        Ok(Some(_)) => {
            debug!(
                "ensure_wallet_state_for_device: wallet exists for {}",
                device_id
            );
            seed_builtin_token_rows_for_device(device_id)
        }
        Ok(None) => {
            debug!(
                "ensure_wallet_state_for_device: creating wallet for {}",
                device_id
            );
            update_wallet_balance(device_id, 0)?;
            seed_builtin_token_rows_for_device(device_id)
        }
        Err(e) => Err(e),
    }
}

pub fn update_wallet_balance(device_id: &str, new_balance: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    debug!(
        "[DB] update_wallet_balance called for device={} new_balance={}",
        device_id, new_balance
    );
    // First try UPDATE
    let updated = match conn.execute(
        "UPDATE wallet_state SET balance = ?1, updated_at = ?2 WHERE device_id = ?3",
        params![new_balance as i64, tick() as i64, device_id],
    ) {
        Ok(u) => u,
        Err(e) => {
            warn!(
                "UPDATE wallet_state error for device={} err={}",
                device_id, e
            );
            return Err(e.into());
        }
    };
    debug!(
        "update_wallet_balance UPDATE rows_affected={} (device={})",
        updated, device_id
    );

    // If no row existed, INSERT a new one
    if updated == 0 {
        let now = tick();
        let zero_tip = crate::util::text_id::encode_base32_crockford(&[0u8; 32]);
        // Avoid re-entrant DB lock: query genesis using the same connection.
        let genesis_id = conn
            .query_row(
                "SELECT genesis_id, device_id FROM genesis_records ORDER BY created_at DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|(genesis_id, gen_device_id)| {
                if gen_device_id == device_id {
                    Some(genesis_id)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| device_id.to_string());
        let inserted = match conn.execute(
            "INSERT INTO wallet_state (wallet_id, device_id, genesis_id, chain_tip, chain_height, merkle_root, balance, created_at, updated_at, status, metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                format!("wallet_{}", device_id),
                device_id,
                genesis_id,
                zero_tip,
                0i64,
                "",
                new_balance as i64,
                now as i64,
                now as i64,
                "active",
                Vec::<u8>::new(),
            ],
        ) {
            Ok(i) => i,
            Err(e) => {
                warn!("INSERT wallet_state error for device={} err={}", device_id, e);
                return Err(e.into());
            }
        };
        debug!(
            "update_wallet_balance INSERT rows_affected={} (device={})",
            inserted, device_id
        );
        info!(
            "Wallet state created with balance: device={} -> {}",
            device_id, new_balance
        );
    } else {
        info!(
            "Wallet balance updated: device={} -> {}",
            device_id, new_balance
        );
    }
    Ok(())
}

pub fn get_wallet_state(device_id: &str) -> Result<Option<WalletState>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    // NOTE: ensure spaces before FROM and WHERE; previous build concatenated tokens causing
    // a runtime syntax error like: "metadataFROM wallet_stateWHERE". Keep explicit spaces.

    let state = conn.query_row(
        "SELECT wallet_id, device_id, genesis_id, chain_tip, chain_height, merkle_root, balance, created_at, updated_at, status, metadata FROM wallet_state WHERE device_id = ?1",
        params![device_id],
        |row| {
                let meta_blob: Vec<u8> = row.get(10)?;
                let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
                Ok(WalletState {
                    wallet_id: row.get(0)?,
                    device_id: row.get(1)?,
                    genesis_id: row.get(2)?,
                    chain_tip: read_hashish_column_as_text(row, 3, "chain_tip")?,
                    chain_height: row.get::<_, i64>(4)? as u64,
                    merkle_root: read_hashish_column_as_text(row, 5, "merkle_root")?,
                    balance: row.get::<_, i64>(6)? as u64,
                    created_at: row.get::<_, i64>(7)? as u64,
                    updated_at: row.get::<_, i64>(8)? as u64,
                    status: row.get(9)?,
                    metadata,
                })
            },
        )
        .optional()?;
    Ok(state)
}

pub fn store_wallet_state(wallet_state: &WalletState) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO wallet_state (
            wallet_id, device_id, genesis_id, chain_tip, chain_height,
            merkle_root, balance, created_at, updated_at, status, metadata
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            wallet_state.wallet_id,
            wallet_state.device_id,
            wallet_state.genesis_id,
            wallet_state.chain_tip,
            wallet_state.chain_height as i64,
            wallet_state.merkle_root,
            wallet_state.balance as i64,
            wallet_state.created_at as i64,
            wallet_state.updated_at as i64,
            wallet_state.status,
            meta_to_blob(&wallet_state.metadata),
        ],
    )?;
    Ok(())
}
