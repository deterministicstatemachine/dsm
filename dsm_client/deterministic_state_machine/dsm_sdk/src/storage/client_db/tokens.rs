// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-ERA token balance persistence.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceProjectionRecord {
    pub balance_key: String,
    pub device_id: String,
    pub token_id: String,
    pub policy_commit: String,
    pub available: u64,
    pub locked: u64,
    pub source_state_hash: String,
    pub source_state_number: u64,
    pub updated_at: u64,
}

fn validate_projection_identity(
    existing: &BalanceProjectionRecord,
    incoming: &BalanceProjectionRecord,
) -> Result<()> {
    if existing.policy_commit != incoming.policy_commit {
        return Err(anyhow::anyhow!(
            "policy_commit is immutable for {}:{} (existing={}, incoming={})",
            incoming.device_id,
            incoming.token_id,
            existing.policy_commit,
            incoming.policy_commit,
        ));
    }
    if existing.balance_key != incoming.balance_key {
        return Err(anyhow::anyhow!(
            "balance_key is immutable for {}:{} (existing={}, incoming={})",
            incoming.device_id,
            incoming.token_id,
            existing.balance_key,
            incoming.balance_key,
        ));
    }
    Ok(())
}

pub fn upsert_balance_projection(record: &BalanceProjectionRecord) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());

    upsert_balance_projection_with_conn(&conn, record)
}

pub(crate) fn upsert_balance_projection_with_conn(
    conn: &Connection,
    record: &BalanceProjectionRecord,
) -> Result<()> {

    let existing = conn
        .query_row(
            "SELECT balance_key, device_id, token_id, policy_commit,
                    available, locked, source_state_hash, source_state_number, updated_at
             FROM balance_projections
             WHERE device_id = ?1 AND token_id = ?2",
            params![record.device_id, record.token_id],
            |row| {
                Ok(BalanceProjectionRecord {
                    balance_key: row.get(0)?,
                    device_id: row.get(1)?,
                    token_id: row.get(2)?,
                    policy_commit: row.get(3)?,
                    available: row.get::<_, i64>(4)? as u64,
                    locked: row.get::<_, i64>(5)? as u64,
                    source_state_hash: row.get(6)?,
                    source_state_number: row.get::<_, i64>(7)? as u64,
                    updated_at: row.get::<_, i64>(8)? as u64,
                })
            },
        )
        .optional()?;

    if let Some(existing) = existing {
        validate_projection_identity(&existing, record)?;
    }

    conn.execute(
        "INSERT INTO balance_projections (
            balance_key, device_id, token_id, policy_commit,
            available, locked, source_state_hash, source_state_number, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(balance_key) DO UPDATE SET
            available = excluded.available,
            locked = excluded.locked,
            source_state_hash = excluded.source_state_hash,
            source_state_number = excluded.source_state_number,
            updated_at = excluded.updated_at",
        params![
            record.balance_key,
            record.device_id,
            record.token_id,
            record.policy_commit,
            record.available as i64,
            record.locked as i64,
            record.source_state_hash,
            record.source_state_number as i64,
            record.updated_at as i64,
        ],
    )?;
    Ok(())
}

pub fn build_balance_projection_from_state(
    device_id: &str,
    token_id: &str,
    policy_commit: &[u8; 32],
    state: &dsm::types::state_types::State,
    locked: u64,
) -> Result<BalanceProjectionRecord> {
    let balance_key = dsm::core::token::derive_canonical_balance_key(
        policy_commit,
        &state.device_info.public_key,
        token_id,
    );
    let state_hash = state.hash()?;
    let balance = state
        .token_balances
        .get(&balance_key)
        .cloned()
        .unwrap_or_else(dsm::types::token_types::Balance::zero);
    let spendable = balance.available().saturating_sub(locked);

    Ok(BalanceProjectionRecord {
        balance_key,
        device_id: device_id.to_string(),
        token_id: token_id.to_string(),
        policy_commit: crate::util::text_id::encode_base32_crockford(policy_commit),
        available: spendable,
        locked,
        source_state_hash: crate::util::text_id::encode_base32_crockford(&state_hash),
        source_state_number: state.state_number,
        updated_at: tick(),
    })
}

pub fn get_balance_projection(
    device_id: &str,
    token_id: &str,
) -> Result<Option<BalanceProjectionRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let result = conn.query_row(
        "SELECT balance_key, device_id, token_id, policy_commit,
                available, locked, source_state_hash, source_state_number, updated_at
         FROM balance_projections
         WHERE device_id = ?1 AND token_id = ?2",
        params![device_id, token_id],
        |row| {
            Ok(BalanceProjectionRecord {
                balance_key: row.get(0)?,
                device_id: row.get(1)?,
                token_id: row.get(2)?,
                policy_commit: row.get(3)?,
                available: row.get::<_, i64>(4)? as u64,
                locked: row.get::<_, i64>(5)? as u64,
                source_state_hash: row.get(6)?,
                source_state_number: row.get::<_, i64>(7)? as u64,
                updated_at: row.get::<_, i64>(8)? as u64,
            })
        },
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn get_validated_balance_projection(
    device_id: &str,
    token_id: &str,
    expected_balance_key: &str,
    expected_policy_commit: &str,
) -> Result<Option<BalanceProjectionRecord>> {
    match get_balance_projection(device_id, token_id)? {
        Some(record) => {
            validate_projection_identity(
                &record,
                &BalanceProjectionRecord {
                    balance_key: expected_balance_key.to_string(),
                    device_id: device_id.to_string(),
                    token_id: token_id.to_string(),
                    policy_commit: expected_policy_commit.to_string(),
                    available: record.available,
                    locked: record.locked,
                    source_state_hash: record.source_state_hash.clone(),
                    source_state_number: record.source_state_number,
                    updated_at: record.updated_at,
                },
            )?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

pub fn list_balance_projections(device_id: &str) -> Result<Vec<BalanceProjectionRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT balance_key, device_id, token_id, policy_commit,
                available, locked, source_state_hash, source_state_number, updated_at
         FROM balance_projections
         WHERE device_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![device_id], |row| {
            Ok(BalanceProjectionRecord {
                balance_key: row.get(0)?,
                device_id: row.get(1)?,
                token_id: row.get(2)?,
                policy_commit: row.get(3)?,
                available: row.get::<_, i64>(4)? as u64,
                locked: row.get::<_, i64>(5)? as u64,
                source_state_hash: row.get(6)?,
                source_state_number: row.get::<_, i64>(7)? as u64,
                updated_at: row.get::<_, i64>(8)? as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

pub fn get_locked_balance(device_id: &str, token_id: &str) -> Result<u64> {
    if token_id == crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID {
        return super::sum_active_withdrawal_burns(device_id, token_id);
    }

    if let Some(record) = get_balance_projection(device_id, token_id)? {
        return Ok(record.locked);
    }

    Ok(0)
}

pub fn delete_balance_projection(device_id: &str, token_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "DELETE FROM balance_projections WHERE device_id = ?1 AND token_id = ?2",
        params![device_id, token_id],
    )?;
    Ok(())
}

pub fn sync_token_projection_from_state(
    device_id: &str,
    token_id: &str,
    policy_commit: &[u8; 32],
    state: &dsm::types::state_types::State,
    locked: u64,
) -> Result<BalanceProjectionRecord> {
    let record = build_balance_projection_from_state(device_id, token_id, policy_commit, state, locked)?;

    upsert_balance_projection(&record)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn balance_projection_round_trips_latest_freshness() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");

        let binding = crate::storage::client_db::get_connection().expect("connection");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute("DELETE FROM balance_projections", [])
            .expect("clear balance projections");
        drop(conn);

        let first = BalanceProjectionRecord {
            balance_key: "123|dBTC".to_string(),
            device_id: "device-a".to_string(),
            token_id: "dBTC".to_string(),
            policy_commit: "policy-a".to_string(),
            available: 5,
            locked: 1,
            source_state_hash: "state-1".to_string(),
            source_state_number: 7,
            updated_at: 11,
        };
        upsert_balance_projection(&first).expect("insert projection");

        let second = BalanceProjectionRecord {
            available: 9,
            locked: 2,
            source_state_hash: "state-2".to_string(),
            source_state_number: 8,
            updated_at: 12,
            ..first.clone()
        };
        upsert_balance_projection(&second).expect("update projection");

        let stored = get_balance_projection("device-a", "dBTC")
            .expect("load projection")
            .expect("projection exists");
        assert_eq!(stored, second);
    }

    #[test]
    fn balance_projection_rejects_policy_mutation() {
        let first = BalanceProjectionRecord {
            balance_key: "123|dBTC".to_string(),
            device_id: "device-a".to_string(),
            token_id: "dBTC".to_string(),
            policy_commit: "policy-a".to_string(),
            available: 5,
            locked: 0,
            source_state_hash: "state-1".to_string(),
            source_state_number: 7,
            updated_at: 11,
        };
        let err = validate_projection_identity(
            &first,
            &BalanceProjectionRecord {
                policy_commit: "policy-b".to_string(),
                source_state_hash: "state-2".to_string(),
                source_state_number: 8,
                updated_at: 12,
                ..first.clone()
            },
        )
        .expect_err("policy mutation must fail");

        assert!(err.to_string().contains("policy_commit is immutable"));
    }
}
