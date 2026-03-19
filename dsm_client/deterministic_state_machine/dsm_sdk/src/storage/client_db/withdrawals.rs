// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-flight withdrawal persistence (dBTC paper §13: execution metadata + settlement)
//!
//! State machine:
//!   Executing → Committed | PartialFailure | Failed | Settled | Refunded
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

/// Settle a committed withdrawal (burn finalized, Bitcoin redemption confirmed).
///
/// Metadata only: marks the recorded withdrawal as settled.
pub fn settle_withdrawal(withdrawal_id: &str) -> Result<()> {
    set_withdrawal_state(withdrawal_id, "settled")
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
                     state IN ('committed', 'partial_failure')
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
