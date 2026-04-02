// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet state persistence for wallet metadata only.

use anyhow::Result;
use log::{debug, info, warn};
use rusqlite::{
    params,
    types::{Type, ValueRef},
    OptionalExtension,
};

use super::get_connection;
use super::types::WalletState;
use crate::storage::codecs::{meta_from_blob, meta_to_blob};
use crate::util::deterministic_time::tick;

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

fn insert_wallet_state_row_if_missing(
    conn: &rusqlite::Connection,
    device_id: &str,
) -> Result<bool> {
    let now = tick();
    let zero_tip = crate::util::text_id::encode_base32_crockford(&[0u8; 32]);
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

    let inserted = conn.execute(
        "INSERT INTO wallet_state (wallet_id, device_id, genesis_id, chain_tip, chain_height, merkle_root, balance, created_at, updated_at, status, metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            format!("wallet_{}", device_id),
            device_id,
            genesis_id,
            zero_tip,
            0i64,
            "",
            0i64,
            now as i64,
            now as i64,
            "active",
            Vec::<u8>::new(),
        ],
    )?;

    Ok(inserted > 0)
}

/// Ensure a wallet_state row exists for `device_id` (base32). If none exists, create a
/// metadata row. Token balances remain canonical-state/projection derived and never come
/// from `wallet_state.balance`.
pub fn ensure_wallet_state_for_device(device_id: &str) -> Result<()> {
    match get_wallet_state(device_id) {
        Ok(Some(_)) => {
            debug!(
                "ensure_wallet_state_for_device: wallet exists for {}",
                device_id
            );
            Ok(())
        }
        Ok(None) => {
            debug!(
                "ensure_wallet_state_for_device: creating wallet metadata row for {}",
                device_id
            );
            let binding = get_connection()?;
            let conn = binding.lock().unwrap_or_else(|poisoned| {
                log::warn!("DB lock poisoned, recovering");
                poisoned.into_inner()
            });
            let inserted = insert_wallet_state_row_if_missing(&conn, device_id)?;
            if inserted {
                info!(
                    "Wallet metadata row created: device={} balance_authority=canonical_state",
                    device_id
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
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
                let legacy_balance = row.get::<_, i64>(6)? as u64;
                if legacy_balance != 0 {
                    debug!(
                        "Ignoring legacy wallet_state.balance={} for device={}; canonical state/projections are authoritative",
                        legacy_balance,
                        device_id
                    );
                }
                let meta_blob: Vec<u8> = row.get(10)?;
                let metadata = meta_from_blob(&meta_blob).unwrap_or_default();
                Ok(WalletState {
                    wallet_id: row.get(0)?,
                    device_id: row.get(1)?,
                    genesis_id: row.get(2)?,
                    chain_tip: read_hashish_column_as_text(row, 3, "chain_tip")?,
                    chain_height: row.get::<_, i64>(4)? as u64,
                    merkle_root: read_hashish_column_as_text(row, 5, "merkle_root")?,
                    balance: 0,
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
    if wallet_state.balance != 0 {
        warn!(
            "store_wallet_state ignoring non-zero balance={} for device={}; wallet_state is metadata-only",
            wallet_state.balance,
            wallet_state.device_id
        );
    }
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
            0i64,
            wallet_state.created_at as i64,
            wallet_state.updated_at as i64,
            wallet_state.status,
            meta_to_blob(&wallet_state.metadata),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_wallet_state(device_id: &str) -> WalletState {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), b"value1".to_vec());
        WalletState {
            wallet_id: format!("wallet_{}", device_id),
            device_id: device_id.to_string(),
            genesis_id: Some("gen-1".to_string()),
            chain_tip: "tip000".to_string(),
            chain_height: 0,
            merkle_root: "merkle000".to_string(),
            balance: 0,
            created_at: 100,
            updated_at: 100,
            status: "active".to_string(),
            metadata,
        }
    }

    #[test]
    #[serial]
    fn store_and_get_wallet_state_roundtrip() {
        init_test_db();
        let ws = make_wallet_state("dev-ws-1");
        store_wallet_state(&ws).unwrap();

        let loaded = get_wallet_state("dev-ws-1").unwrap().unwrap();
        assert_eq!(loaded.wallet_id, "wallet_dev-ws-1");
        assert_eq!(loaded.device_id, "dev-ws-1");
        assert_eq!(loaded.genesis_id.as_deref(), Some("gen-1"));
        assert_eq!(loaded.status, "active");
        assert_eq!(loaded.balance, 0);
    }

    #[test]
    #[serial]
    fn get_wallet_state_returns_none_when_missing() {
        init_test_db();
        assert!(get_wallet_state("missing-dev").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn store_wallet_state_forces_balance_zero() {
        init_test_db();
        let mut ws = make_wallet_state("dev-bal");
        ws.balance = 999;
        store_wallet_state(&ws).unwrap();

        let loaded = get_wallet_state("dev-bal").unwrap().unwrap();
        assert_eq!(loaded.balance, 0);
    }

    #[test]
    #[serial]
    fn ensure_wallet_state_for_device_creates_when_missing() {
        init_test_db();
        ensure_wallet_state_for_device("dev-ensure").unwrap();
        let loaded = get_wallet_state("dev-ensure").unwrap().unwrap();
        assert_eq!(loaded.wallet_id, "wallet_dev-ensure");
        assert_eq!(loaded.status, "active");
    }

    #[test]
    #[serial]
    fn ensure_wallet_state_for_device_is_idempotent() {
        init_test_db();
        ensure_wallet_state_for_device("dev-idem").unwrap();
        ensure_wallet_state_for_device("dev-idem").unwrap();
        let loaded = get_wallet_state("dev-idem").unwrap().unwrap();
        assert_eq!(loaded.wallet_id, "wallet_dev-idem");
    }

    #[test]
    #[serial]
    fn store_wallet_state_metadata_roundtrips() {
        init_test_db();
        let ws = make_wallet_state("dev-meta");
        store_wallet_state(&ws).unwrap();
        let loaded = get_wallet_state("dev-meta").unwrap().unwrap();
        assert_eq!(
            loaded.metadata.get("key1").map(|v| v.as_slice()),
            Some(b"value1".as_ref())
        );
    }

    #[test]
    #[serial]
    fn store_wallet_state_upserts_on_conflict() {
        init_test_db();
        let mut ws = make_wallet_state("dev-ups");
        store_wallet_state(&ws).unwrap();

        ws.status = "suspended".to_string();
        ws.chain_height = 42;
        ws.chain_tip = "newtip".to_string();
        store_wallet_state(&ws).unwrap();

        let loaded = get_wallet_state("dev-ups").unwrap().unwrap();
        assert_eq!(loaded.status, "suspended");
        assert_eq!(loaded.chain_height, 42);
        assert_eq!(loaded.chain_tip, "newtip");
    }

    #[test]
    #[serial]
    fn ensure_wallet_state_does_not_overwrite_existing() {
        init_test_db();
        let mut ws = make_wallet_state("dev-noow");
        ws.status = "custom_status".to_string();
        store_wallet_state(&ws).unwrap();

        ensure_wallet_state_for_device("dev-noow").unwrap();

        let loaded = get_wallet_state("dev-noow").unwrap().unwrap();
        assert_eq!(loaded.status, "custom_status");
    }

    #[test]
    #[serial]
    fn wallet_state_genesis_id_roundtrips() {
        init_test_db();
        let ws = make_wallet_state("dev-gen");
        store_wallet_state(&ws).unwrap();

        let loaded = get_wallet_state("dev-gen").unwrap().unwrap();
        assert_eq!(loaded.genesis_id.as_deref(), Some("gen-1"));
    }
}
