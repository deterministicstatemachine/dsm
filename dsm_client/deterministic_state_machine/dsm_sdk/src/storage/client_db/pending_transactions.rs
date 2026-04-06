// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pending transaction management.

use anyhow::Result;
use log::warn;
use rusqlite::{params, Row};

use super::get_connection;
use super::types::PendingTransaction;
use crate::util::deterministic_time::tick;

pub fn store_pending_transaction(tx_id: &str, payload: &[u8]) -> Result<()> {
    let now = tick();
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in store_pending_transaction, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO pending_transactions(tx_id,payload,state,created_at,updated_at)
         VALUES(?1,?2,'CREATED',?3,?3)",
        params![tx_id, payload, now as i64],
    )?;
    Ok(())
}

pub fn mark_pending_transaction_state(tx_id: &str, new_state: &str) -> Result<()> {
    let now = tick();
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in mark_pending_transaction_state, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE pending_transactions
           SET state=?1,retry_count=retry_count+1,updated_at=?2
         WHERE tx_id=?3",
        params![new_state, now as i64, tx_id],
    )?;
    Ok(())
}

pub fn get_pending_transactions(filter: Option<&str>) -> Result<Vec<PendingTransaction>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let map_row = |row: &Row| -> rusqlite::Result<PendingTransaction> {
        Ok(PendingTransaction {
            tx_id: row.get::<_, String>(0)?,
            payload: row.get::<_, Vec<u8>>(1)?,
            state: row.get::<_, String>(2)?,
            retry_count: row.get::<_, i32>(3)? as u32,
            created_at: row.get::<_, i64>(4)? as u64,
            updated_at: row.get::<_, i64>(5)? as u64,
        })
    };

    let out = if let Some(state_filter) = filter {
        let mut stmt = conn.prepare(
            "SELECT tx_id,payload,state,retry_count,created_at,updated_at
               FROM pending_transactions WHERE state=?1",
        )?;
        let mut v = Vec::new();
        // Keep the owned param alive while consuming the iterator
        let owned = state_filter.to_string();
        let iter = stmt.query_map(params![owned], map_row)?;
        for r in iter {
            v.push(r?);
        }
        v
    } else {
        let mut stmt = conn.prepare(
            "SELECT tx_id,payload,state,retry_count,created_at,updated_at
               FROM pending_transactions",
        )?;
        let mut v = Vec::new();
        let iter = stmt.query_map([], map_row)?;
        for r in iter {
            v.push(r?);
        }
        v
    };

    Ok(out)
}

pub fn recover_pending_transactions() -> Result<()> {
    for p in get_pending_transactions(Some("CREATED"))? {
        warn!("Recovering pending tx {}", p.tx_id);
    }
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

    #[test]
    #[serial]
    fn store_and_get_pending_transaction() {
        init_test_db();

        store_pending_transaction("tx-pend-1", b"payload-data").expect("store");

        let all = get_pending_transactions(None).expect("get all");
        assert!(all.iter().any(|p| p.tx_id == "tx-pend-1"));

        let found = all.iter().find(|p| p.tx_id == "tx-pend-1").unwrap();
        assert_eq!(found.payload, b"payload-data");
        assert_eq!(found.state, "CREATED");
        assert_eq!(found.retry_count, 0);
    }

    #[test]
    #[serial]
    fn mark_state_increments_retry_count() {
        init_test_db();

        store_pending_transaction("tx-retry-1", b"data").expect("store");
        mark_pending_transaction_state("tx-retry-1", "SUBMITTED").expect("mark submitted");

        let all = get_pending_transactions(Some("SUBMITTED")).expect("get");
        let found = all.iter().find(|p| p.tx_id == "tx-retry-1").unwrap();
        assert_eq!(found.state, "SUBMITTED");
        assert_eq!(found.retry_count, 1);

        mark_pending_transaction_state("tx-retry-1", "FAILED").expect("mark failed");
        let all2 = get_pending_transactions(Some("FAILED")).expect("get");
        let found2 = all2.iter().find(|p| p.tx_id == "tx-retry-1").unwrap();
        assert_eq!(found2.retry_count, 2);
    }

    #[test]
    #[serial]
    fn filter_returns_only_matching_state() {
        init_test_db();

        store_pending_transaction("tx-filter-a", b"a").expect("store a");
        store_pending_transaction("tx-filter-b", b"b").expect("store b");
        mark_pending_transaction_state("tx-filter-b", "COMMITTED").expect("mark committed");

        let created = get_pending_transactions(Some("CREATED")).expect("get created");
        assert!(created.iter().any(|p| p.tx_id == "tx-filter-a"));
        assert!(!created.iter().any(|p| p.tx_id == "tx-filter-b"));

        let committed = get_pending_transactions(Some("COMMITTED")).expect("get committed");
        assert!(committed.iter().any(|p| p.tx_id == "tx-filter-b"));
    }

    #[test]
    #[serial]
    fn store_pending_transaction_upserts() {
        init_test_db();

        store_pending_transaction("tx-upsert", b"first").expect("store first");
        store_pending_transaction("tx-upsert", b"second").expect("store second");

        let all = get_pending_transactions(None).expect("get all");
        let matches: Vec<_> = all.iter().filter(|p| p.tx_id == "tx-upsert").collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].payload, b"second");
    }

    #[test]
    #[serial]
    fn recover_pending_transactions_does_not_error_on_empty() {
        init_test_db();
        recover_pending_transactions().expect("recover should succeed on empty table");
    }
}
