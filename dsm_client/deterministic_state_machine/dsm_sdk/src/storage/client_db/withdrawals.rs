// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-flight withdrawal persistence (dBTC paper §13: execution metadata + final burn)
//!
//! State machine:
//!   Executing → Committed | Failed | Finalized | Refunded
//!
//! This table is metadata only. Token accounting is handled by DSM state
//! transitions, not direct SQLite balance mutation.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// In-flight withdrawal record.
#[derive(Debug, Clone)]
pub struct InFlightWithdrawal {
    pub withdrawal_id: String,
    pub device_id: String,
    pub amount_sats: u64,
    pub dest_address: String,
    pub policy_commit: Vec<u8>,
    pub state: String,
    pub redemption_txid: Option<String>,
    pub vault_content_hash: Option<Vec<u8>>,
    pub burn_token_id: Option<String>,
    pub burn_amount_sats: u64,
    pub settlement_poll_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Persisted per-leg execution metadata for a withdrawal.
#[derive(Debug, Clone)]
pub struct InFlightWithdrawalLeg {
    pub withdrawal_id: String,
    pub leg_index: u32,
    pub vault_id: String,
    pub leg_kind: String,
    pub amount_sats: u64,
    pub estimated_fee_sats: u64,
    pub estimated_net_sats: u64,
    pub sweep_txid: Option<String>,
    pub successor_vault_id: Option<String>,
    pub successor_vault_op_id: Option<String>,
    pub exit_vault_op_id: Option<String>,
    pub state: String,
    pub proof_digest: Option<Vec<u8>>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Parameters for creating a withdrawal entry.
pub struct CreateWithdrawalParams<'a> {
    pub withdrawal_id: &'a str,
    pub device_id: &'a str,
    pub amount_sats: u64,
    pub dest_address: &'a str,
    pub policy_commit: &'a [u8],
    pub state: &'a str,
    pub burn_token_id: Option<&'a str>,
    pub burn_amount_sats: u64,
}

/// Insert a new in-flight withdrawal metadata row in the provided state.
pub fn create_withdrawal(params: CreateWithdrawalParams) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();

    conn.execute(
        "INSERT INTO in_flight_withdrawals(
            withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
            state, burn_token_id, burn_amount_sats, created_at, updated_at
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
        params![
            params.withdrawal_id,
            params.device_id,
            params.amount_sats as i64,
            params.dest_address,
            params.policy_commit,
            params.state,
            params.burn_token_id,
            params.burn_amount_sats as i64,
            now as i64
        ],
    )?;

    log::info!(
        "[withdrawal] created metadata row: id={} state={} amount={} dest={}",
        params.withdrawal_id,
        params.state,
        params.amount_sats,
        params.dest_address
    );
    Ok(())
}

/// Update the lifecycle state of an in-flight withdrawal.
pub fn set_withdrawal_state(withdrawal_id: &str, state: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();
    conn.execute(
        "UPDATE in_flight_withdrawals SET state = ?2, updated_at = ?3
         WHERE withdrawal_id = ?1",
        params![withdrawal_id, state, now as i64],
    )?;
    Ok(())
}

/// Sum unresolved withdrawal burn reservations for a device/token pair.
///
/// `executing` and `committed` rows define the dBTC in-flight set.
pub fn sum_active_withdrawal_burns(device_id: &str, token_id: &str) -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let total: Option<i64> = conn.query_row(
        "SELECT SUM(burn_amount_sats)
         FROM in_flight_withdrawals
         WHERE device_id = ?1
           AND burn_token_id = ?2
           AND (state = 'executing' OR state = 'committed')",
        params![device_id, token_id],
        |row| row.get(0),
    )?;
    Ok(total.unwrap_or(0).max(0) as u64)
}

/// Record the redemption txid set after broadcast.
pub fn set_withdrawal_redemption_txids(
    withdrawal_id: &str,
    redemption_txids_csv: &str,
    vault_content_hash: Option<&[u8]>,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();
    conn.execute(
        "UPDATE in_flight_withdrawals SET redemption_txid = ?2, vault_content_hash = COALESCE(?3, vault_content_hash), updated_at = ?4
         WHERE withdrawal_id = ?1",
        params![
            withdrawal_id,
            redemption_txids_csv,
            vault_content_hash,
            now as i64
        ],
    )?;
    Ok(())
}

/// Insert or update a per-leg execution row for a withdrawal.
pub fn upsert_withdrawal_leg(leg: &InFlightWithdrawalLeg) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();
    conn.execute(
        "INSERT OR REPLACE INTO in_flight_withdrawal_legs(
            withdrawal_id, leg_index, vault_id, leg_kind, amount_sats,
            estimated_fee_sats, estimated_net_sats, sweep_txid, successor_vault_id,
            successor_vault_op_id, exit_vault_op_id, state, proof_digest,
            created_at, updated_at
        ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            leg.withdrawal_id,
            leg.leg_index as i64,
            leg.vault_id,
            leg.leg_kind,
            leg.amount_sats as i64,
            leg.estimated_fee_sats as i64,
            leg.estimated_net_sats as i64,
            leg.sweep_txid,
            leg.successor_vault_id,
            leg.successor_vault_op_id,
            leg.exit_vault_op_id,
            leg.state,
            leg.proof_digest,
            leg.created_at as i64,
            now as i64
        ],
    )?;
    Ok(())
}

/// List persisted execution legs for a withdrawal.
pub fn list_withdrawal_legs(withdrawal_id: &str) -> Result<Vec<InFlightWithdrawalLeg>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        r#"
        SELECT withdrawal_id, leg_index, vault_id, leg_kind, amount_sats,
                estimated_fee_sats, estimated_net_sats, sweep_txid, successor_vault_id,
                successor_vault_op_id, exit_vault_op_id, state, proof_digest,
                created_at, updated_at
         FROM in_flight_withdrawal_legs
         WHERE withdrawal_id = ?1
         ORDER BY leg_index ASC
    "#,
    )?;
    let rows = stmt
        .query_map(params![withdrawal_id], |row| {
            Ok(InFlightWithdrawalLeg {
                withdrawal_id: row.get(0)?,
                leg_index: row.get::<_, i64>(1)? as u32,
                vault_id: row.get(2)?,
                leg_kind: row.get(3)?,
                amount_sats: row.get::<_, i64>(4)? as u64,
                estimated_fee_sats: row.get::<_, i64>(5)? as u64,
                estimated_net_sats: row.get::<_, i64>(6)? as u64,
                sweep_txid: row.get(7)?,
                successor_vault_id: row.get(8)?,
                successor_vault_op_id: row.get(9)?,
                exit_vault_op_id: row.get(10)?,
                state: row.get(11)?,
                proof_digest: row.get(12)?,
                created_at: row.get::<_, i64>(13)? as u64,
                updated_at: row.get::<_, i64>(14)? as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Atomically increment the settlement poll counter and return the new value.
pub fn increment_settlement_poll_count(withdrawal_id: &str) -> Result<u32> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick();
    conn.execute(
        "UPDATE in_flight_withdrawals SET settlement_poll_count = settlement_poll_count + 1, updated_at = ?2
         WHERE withdrawal_id = ?1",
        params![withdrawal_id, now as i64],
    )?;
    let count: i64 = conn.query_row(
        "SELECT settlement_poll_count FROM in_flight_withdrawals WHERE withdrawal_id = ?1",
        params![withdrawal_id],
        |row| row.get(0),
    )?;
    Ok(count as u32)
}

/// Finalize a committed withdrawal (burn finalized, Bitcoin redemption confirmed).
///
/// Metadata only: marks the recorded withdrawal as finalized.
pub fn finalize_withdrawal(withdrawal_id: &str) -> Result<()> {
    set_withdrawal_state(withdrawal_id, "finalized")
}

/// Get a withdrawal by ID.
pub fn get_withdrawal(withdrawal_id: &str) -> Result<Option<InFlightWithdrawal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
                    state, redemption_txid, vault_content_hash, burn_token_id,
                    burn_amount_sats, settlement_poll_count, created_at, updated_at
             FROM in_flight_withdrawals WHERE withdrawal_id = ?1",
            params![withdrawal_id],
            |row| {
                Ok(InFlightWithdrawal {
                    withdrawal_id: row.get(0)?,
                    device_id: row.get(1)?,
                    amount_sats: row.get::<_, i64>(2)? as u64,
                    dest_address: row.get(3)?,
                    policy_commit: row.get(4)?,
                    state: row.get(5)?,
                    redemption_txid: row.get(6)?,
                    vault_content_hash: row.get(7)?,
                    burn_token_id: row.get(8)?,
                    burn_amount_sats: row.get::<_, i64>(9).unwrap_or(0) as u64,
                    settlement_poll_count: row.get::<_, i64>(10).unwrap_or(0) as u32,
                    created_at: row.get::<_, i64>(11)? as u64,
                    updated_at: row.get::<_, i64>(12)? as u64,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// List all committed (in-flight) withdrawals for a device.
pub fn list_committed_withdrawals(device_id: &str) -> Result<Vec<InFlightWithdrawal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
                state, redemption_txid, vault_content_hash, burn_token_id,
                burn_amount_sats, settlement_poll_count, created_at, updated_at
         FROM in_flight_withdrawals WHERE device_id = ?1 AND state = 'committed'
         ORDER BY created_at ASC ",
    )?;
    let rows = stmt
        .query_map(params![device_id], |row| {
            Ok(InFlightWithdrawal {
                withdrawal_id: row.get(0)?,
                device_id: row.get(1)?,
                amount_sats: row.get::<_, i64>(2)? as u64,
                dest_address: row.get(3)?,
                policy_commit: row.get(4)?,
                state: row.get(5)?,
                redemption_txid: row.get(6)?,
                vault_content_hash: row.get(7)?,
                burn_token_id: row.get(8)?,
                burn_amount_sats: row.get::<_, i64>(9).unwrap_or(0) as u64,
                settlement_poll_count: row.get::<_, i64>(10).unwrap_or(0) as u32,
                created_at: row.get::<_, i64>(11)? as u64,
                updated_at: row.get::<_, i64>(12)? as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// List all unresolved withdrawals for auto-resolution.
///
/// Only rows with recorded or potentially recorded Bitcoin execution remain here.
pub fn list_unresolved_withdrawals(device_id: &str) -> Result<Vec<InFlightWithdrawal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
               "SELECT withdrawal_id, device_id, amount_sats, dest_address, policy_commit,
                     state, redemption_txid, vault_content_hash, burn_token_id,
                     burn_amount_sats, settlement_poll_count, created_at, updated_at
                FROM in_flight_withdrawals
                WHERE device_id = ?1
                 AND (
                     state = 'committed'
                     OR (state = 'executing' AND redemption_txid IS NOT NULL AND redemption_txid != '')
                 )
                ORDER BY created_at ASC "
            )?;
    let rows = stmt
        .query_map(params![device_id], |row| {
            Ok(InFlightWithdrawal {
                withdrawal_id: row.get(0)?,
                device_id: row.get(1)?,
                amount_sats: row.get::<_, i64>(2)? as u64,
                dest_address: row.get(3)?,
                policy_commit: row.get(4)?,
                state: row.get(5)?,
                redemption_txid: row.get(6)?,
                vault_content_hash: row.get(7)?,
                burn_token_id: row.get(8)?,
                burn_amount_sats: row.get::<_, i64>(9).unwrap_or(0) as u64,
                settlement_poll_count: row.get::<_, i64>(10).unwrap_or(0) as u32,
                created_at: row.get::<_, i64>(11)? as u64,
                updated_at: row.get::<_, i64>(12)? as u64,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Look up the withdrawal row associated with a persisted exit deposit.
pub fn find_withdrawal_by_exit_vault_op_id(
    exit_vault_op_id: &str,
) -> Result<Option<InFlightWithdrawal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT w.withdrawal_id, w.device_id, w.amount_sats, w.dest_address, w.policy_commit,
                    w.state, w.redemption_txid, w.vault_content_hash, w.burn_token_id,
                    w.burn_amount_sats, w.settlement_poll_count, w.created_at, w.updated_at
             FROM in_flight_withdrawals w
             INNER JOIN in_flight_withdrawal_legs l
                 ON l.withdrawal_id = w.withdrawal_id
             WHERE l.exit_vault_op_id = ?1
             ORDER BY w.created_at DESC
             LIMIT 1",
            params![exit_vault_op_id],
            |row| {
                Ok(InFlightWithdrawal {
                    withdrawal_id: row.get(0)?,
                    device_id: row.get(1)?,
                    amount_sats: row.get::<_, i64>(2)? as u64,
                    dest_address: row.get(3)?,
                    policy_commit: row.get(4)?,
                    state: row.get(5)?,
                    redemption_txid: row.get(6)?,
                    vault_content_hash: row.get(7)?,
                    burn_token_id: row.get(8)?,
                    burn_amount_sats: row.get::<_, i64>(9).unwrap_or(0) as u64,
                    settlement_poll_count: row.get::<_, i64>(10).unwrap_or(0) as u32,
                    created_at: row.get::<_, i64>(11)? as u64,
                    updated_at: row.get::<_, i64>(12)? as u64,
                })
            },
        )
        .optional()?;
    Ok(row)
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

    fn make_withdrawal_params<'a>(
        withdrawal_id: &'a str,
        device_id: &'a str,
        dest_address: &'a str,
    ) -> CreateWithdrawalParams<'a> {
        CreateWithdrawalParams {
            withdrawal_id,
            device_id,
            amount_sats: 50_000,
            dest_address,
            policy_commit: &[0xAA; 32],
            state: "executing",
            burn_token_id: Some("dbtc"),
            burn_amount_sats: 50_000,
        }
    }

    #[test]
    #[serial]
    fn create_and_get_withdrawal() {
        init_test_db();
        let params = make_withdrawal_params("w-1", "dev-a", "bc1qtest");
        create_withdrawal(params).expect("create");

        let w = get_withdrawal("w-1").expect("get").expect("should exist");
        assert_eq!(w.withdrawal_id, "w-1");
        assert_eq!(w.device_id, "dev-a");
        assert_eq!(w.amount_sats, 50_000);
        assert_eq!(w.dest_address, "bc1qtest");
        assert_eq!(w.state, "executing");
        assert_eq!(w.burn_amount_sats, 50_000);
        assert_eq!(w.settlement_poll_count, 0);
    }

    #[test]
    #[serial]
    fn set_withdrawal_state_transitions() {
        init_test_db();
        let params = make_withdrawal_params("w-2", "dev-b", "bc1qaddr");
        create_withdrawal(params).unwrap();

        set_withdrawal_state("w-2", "committed").unwrap();
        let w = get_withdrawal("w-2").unwrap().unwrap();
        assert_eq!(w.state, "committed");

        finalize_withdrawal("w-2").unwrap();
        let w = get_withdrawal("w-2").unwrap().unwrap();
        assert_eq!(w.state, "finalized");
    }

    #[test]
    #[serial]
    fn increment_settlement_poll_count_works() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-3", "dev-c", "addr")).unwrap();

        let c1 = increment_settlement_poll_count("w-3").unwrap();
        assert_eq!(c1, 1);
        let c2 = increment_settlement_poll_count("w-3").unwrap();
        assert_eq!(c2, 2);
    }

    #[test]
    #[serial]
    fn sum_active_withdrawal_burns_counts_executing_and_committed() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-sum-1", "dev-d", "a")).unwrap();
        create_withdrawal(CreateWithdrawalParams {
            withdrawal_id: "w-sum-2",
            device_id: "dev-d",
            amount_sats: 30_000,
            dest_address: "b",
            policy_commit: &[0; 32],
            state: "committed",
            burn_token_id: Some("dbtc"),
            burn_amount_sats: 30_000,
        })
        .unwrap();
        create_withdrawal(CreateWithdrawalParams {
            withdrawal_id: "w-sum-3",
            device_id: "dev-d",
            amount_sats: 20_000,
            dest_address: "c",
            policy_commit: &[0; 32],
            state: "finalized",
            burn_token_id: Some("dbtc"),
            burn_amount_sats: 20_000,
        })
        .unwrap();

        let total = sum_active_withdrawal_burns("dev-d", "dbtc").unwrap();
        assert_eq!(total, 80_000);
    }

    #[test]
    #[serial]
    fn set_withdrawal_redemption_txids_persists() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-rtx", "dev-e", "addr")).unwrap();
        set_withdrawal_redemption_txids("w-rtx", "txid1,txid2", Some(&[0xBB; 32])).unwrap();

        let w = get_withdrawal("w-rtx").unwrap().unwrap();
        assert_eq!(w.redemption_txid.as_deref(), Some("txid1,txid2"));
        assert_eq!(w.vault_content_hash.as_deref(), Some([0xBBu8; 32].as_ref()));
    }

    #[test]
    #[serial]
    fn list_committed_withdrawals_filters_by_state() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-lc1", "dev-f", "a")).unwrap();
        set_withdrawal_state("w-lc1", "committed").unwrap();
        create_withdrawal(CreateWithdrawalParams {
            withdrawal_id: "w-lc2",
            device_id: "dev-f",
            amount_sats: 10_000,
            dest_address: "b",
            policy_commit: &[0; 32],
            state: "finalized",
            burn_token_id: None,
            burn_amount_sats: 0,
        })
        .unwrap();

        let committed = list_committed_withdrawals("dev-f").unwrap();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].withdrawal_id, "w-lc1");
    }

    #[test]
    #[serial]
    fn get_nonexistent_withdrawal_returns_none() {
        init_test_db();
        assert!(get_withdrawal("nonexistent").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn upsert_and_list_withdrawal_legs() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-leg", "dev-g", "a")).unwrap();
        let leg = InFlightWithdrawalLeg {
            withdrawal_id: "w-leg".to_string(),
            leg_index: 0,
            vault_id: "vault-1".to_string(),
            leg_kind: "sweep".to_string(),
            amount_sats: 50_000,
            estimated_fee_sats: 500,
            estimated_net_sats: 49_500,
            sweep_txid: Some("txid-sweep".to_string()),
            successor_vault_id: None,
            successor_vault_op_id: None,
            exit_vault_op_id: Some("exit-op-1".to_string()),
            state: "pending".to_string(),
            proof_digest: None,
            created_at: 100,
            updated_at: 100,
        };
        upsert_withdrawal_leg(&leg).unwrap();

        let legs = list_withdrawal_legs("w-leg").unwrap();
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].vault_id, "vault-1");
        assert_eq!(legs[0].estimated_net_sats, 49_500);
    }

    #[test]
    #[serial]
    fn list_unresolved_withdrawals_includes_committed() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-ur1", "dev-h", "a")).unwrap();
        set_withdrawal_state("w-ur1", "committed").unwrap();

        create_withdrawal(CreateWithdrawalParams {
            withdrawal_id: "w-ur2",
            device_id: "dev-h",
            amount_sats: 10_000,
            dest_address: "b",
            policy_commit: &[0; 32],
            state: "finalized",
            burn_token_id: None,
            burn_amount_sats: 0,
        })
        .unwrap();

        let unresolved = list_unresolved_withdrawals("dev-h").unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].withdrawal_id, "w-ur1");
    }

    #[test]
    #[serial]
    fn list_unresolved_includes_executing_with_txid() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-ur3", "dev-i", "a")).unwrap();
        set_withdrawal_redemption_txids("w-ur3", "txid-1", None).unwrap();

        let unresolved = list_unresolved_withdrawals("dev-i").unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].withdrawal_id, "w-ur3");
    }

    #[test]
    #[serial]
    fn list_unresolved_excludes_executing_without_txid() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-ur4", "dev-j", "a")).unwrap();

        let unresolved = list_unresolved_withdrawals("dev-j").unwrap();
        assert!(unresolved.is_empty());
    }

    #[test]
    #[serial]
    fn find_withdrawal_by_exit_vault_op_id_roundtrip() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-exit", "dev-k", "a")).unwrap();
        let leg = InFlightWithdrawalLeg {
            withdrawal_id: "w-exit".to_string(),
            leg_index: 0,
            vault_id: "vault-x".to_string(),
            leg_kind: "exit".to_string(),
            amount_sats: 50_000,
            estimated_fee_sats: 200,
            estimated_net_sats: 49_800,
            sweep_txid: None,
            successor_vault_id: None,
            successor_vault_op_id: None,
            exit_vault_op_id: Some("exit-op-abc".to_string()),
            state: "pending".to_string(),
            proof_digest: None,
            created_at: 100,
            updated_at: 100,
        };
        upsert_withdrawal_leg(&leg).unwrap();

        let found = find_withdrawal_by_exit_vault_op_id("exit-op-abc")
            .unwrap()
            .unwrap();
        assert_eq!(found.withdrawal_id, "w-exit");
    }

    #[test]
    #[serial]
    fn find_withdrawal_by_exit_vault_op_id_returns_none() {
        init_test_db();
        assert!(find_withdrawal_by_exit_vault_op_id("nonexistent")
            .unwrap()
            .is_none());
    }

    #[test]
    #[serial]
    fn upsert_withdrawal_leg_replaces_on_conflict() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-repl", "dev-l", "a")).unwrap();
        let leg = InFlightWithdrawalLeg {
            withdrawal_id: "w-repl".to_string(),
            leg_index: 0,
            vault_id: "vault-old".to_string(),
            leg_kind: "sweep".to_string(),
            amount_sats: 10_000,
            estimated_fee_sats: 100,
            estimated_net_sats: 9_900,
            sweep_txid: None,
            successor_vault_id: None,
            successor_vault_op_id: None,
            exit_vault_op_id: None,
            state: "pending".to_string(),
            proof_digest: None,
            created_at: 100,
            updated_at: 100,
        };
        upsert_withdrawal_leg(&leg).unwrap();

        let mut updated = leg.clone();
        updated.state = "confirmed".to_string();
        updated.sweep_txid = Some("txid-sweep-new".to_string());
        upsert_withdrawal_leg(&updated).unwrap();

        let legs = list_withdrawal_legs("w-repl").unwrap();
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].state, "confirmed");
        assert_eq!(legs[0].sweep_txid.as_deref(), Some("txid-sweep-new"));
    }

    #[test]
    #[serial]
    fn multiple_legs_ordered_by_index() {
        init_test_db();
        create_withdrawal(make_withdrawal_params("w-multi", "dev-m", "a")).unwrap();
        for i in (0..3).rev() {
            let leg = InFlightWithdrawalLeg {
                withdrawal_id: "w-multi".to_string(),
                leg_index: i,
                vault_id: format!("vault-{}", i),
                leg_kind: "sweep".to_string(),
                amount_sats: 10_000,
                estimated_fee_sats: 100,
                estimated_net_sats: 9_900,
                sweep_txid: None,
                successor_vault_id: None,
                successor_vault_op_id: None,
                exit_vault_op_id: None,
                state: "pending".to_string(),
                proof_digest: None,
                created_at: 100,
                updated_at: 100,
            };
            upsert_withdrawal_leg(&leg).unwrap();
        }

        let legs = list_withdrawal_legs("w-multi").unwrap();
        assert_eq!(legs.len(), 3);
        assert_eq!(legs[0].leg_index, 0);
        assert_eq!(legs[1].leg_index, 1);
        assert_eq!(legs[2].leg_index, 2);
    }
}
