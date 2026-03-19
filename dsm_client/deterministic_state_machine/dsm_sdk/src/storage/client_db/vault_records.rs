// SPDX-License-Identifier: MIT OR Apache-2.0
//! Vault record persistence — tracks vault lifecycle for deposits and fractional exits.
//! Per dBTC spec §4 (Deposits), §8 (Vault Advertisements), §15 (Fractional Exit).

use anyhow::Result;
use rusqlite::{params, OptionalExtension, Row};

use super::get_connection;

/// Column list shared by all SELECT queries (24 columns, no preimage — Invariant 5).
const VAULT_COLS: &str = "vault_op_id, direction, vault_state, hash_lock, vault_id, \
    btc_amount_sats, btc_pubkey, htlc_script, htlc_address, external_commitment, \
    refund_iterations, created_at_state, entry_header, parent_vault_id, \
    successor_depth, is_fractional_successor, destination_address, funding_txid, \
    refund_hash_lock, exit_amount_sats, exit_header, exit_confirm_depth, entry_txid, deposit_nonce";

/// Persisted vault record from SQLite — plain types, no domain enums.
/// Each row represents a vault in the collateral grid (spec Definition 4).
///
/// SECURITY INVARIANT (dBTC §10.1, Invariant 5 — Bearer Witness Is Never at Rest):
/// The HTLC preimage is never stored in this table. It is derived on demand from:
///   η = BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce)
///   preimage = BLAKE3("DSM/dbtc-preimage\0" || η)
/// Only `deposit_nonce` (public) is stored. `manifold_seed` lives in a separate,
/// access-controlled table. A local SQLite compromise does NOT expose sweep authority.
#[derive(Debug, Clone)]
pub struct PersistedVaultRecord {
    pub vault_op_id: String,
    pub direction: String,
    pub vault_state: String,
    pub hash_lock: Vec<u8>,
    pub vault_id: Option<String>,
    pub btc_amount_sats: u64,
    pub btc_pubkey: Vec<u8>,
    pub htlc_script: Option<Vec<u8>>,
    pub htlc_address: Option<String>,
    pub external_commitment: Option<Vec<u8>>,
    pub refund_iterations: u64,
    pub created_at_state: u64,
    pub entry_header: Option<Vec<u8>>,
    pub parent_vault_id: Option<String>,
    pub successor_depth: u32,
    pub is_fractional_successor: bool,
    /// Refund hashlock h_r for dual-hashlock HTLC (path (b)).
    pub refund_hash_lock: Vec<u8>,
    pub destination_address: Option<String>,
    pub funding_txid: Option<String>,
    /// Exit amount in sats for fractional exits (used by crash recovery to know how much to unlock).
    pub exit_amount_sats: u64,
    /// Bitcoin block header cached at exit time (80 bytes, dBTC §6.4.3).
    pub exit_header: Option<Vec<u8>>,
    /// Confirmation depth achieved for the exit anchor (dBTC §12.1.3).
    pub exit_confirm_depth: u32,
    /// Bitcoin txid that funded this vault's HTLC (32 bytes, internal byte order).
    /// Published on the vault advertisement; withdrawer verifies against Bitcoin directly.
    pub entry_txid: Option<Vec<u8>>,
    /// Random 32-byte nonce per vault — published in advertisements.
    /// η is derived deterministically: BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce).
    /// Any bearer with manifold_seed can compute η → preimage → sweep.
    pub deposit_nonce: Option<Vec<u8>>,
}

/// Insert or update a vault record.
pub fn upsert_vault_record(rec: &PersistedVaultRecord) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in upsert_vault_record, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO vault_records(
            vault_op_id, direction, vault_state, hash_lock,
            vault_id, btc_amount_sats, btc_pubkey, htlc_script, htlc_address,
            external_commitment, refund_iterations, created_at_state, entry_header,
            parent_vault_id, successor_depth, is_fractional_successor,
            destination_address, funding_txid, refund_hash_lock, exit_amount_sats,
            exit_header, exit_confirm_depth, entry_txid, deposit_nonce
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
        params![
            rec.vault_op_id,
            rec.direction,
            rec.vault_state,
            rec.hash_lock,
            rec.vault_id,
            rec.btc_amount_sats as i64,
            rec.btc_pubkey,
            rec.htlc_script,
            rec.htlc_address,
            rec.external_commitment,
            rec.refund_iterations as i64,
            rec.created_at_state as i64,
            rec.entry_header,
            rec.parent_vault_id,
            rec.successor_depth as i64,
            if rec.is_fractional_successor {
                1i32
            } else {
                0i32
            },
            rec.destination_address,
            rec.funding_txid,
            rec.refund_hash_lock,
            rec.exit_amount_sats as i64,
            rec.exit_header,
            rec.exit_confirm_depth as i64,
            rec.entry_txid,
            rec.deposit_nonce,
        ],
    )?;
    Ok(())
}

/// Get a vault record by operation ID.
pub fn get_vault_record_by_id(vault_op_id: &str) -> Result<Option<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_vault_record_by_id, recovering");
        poisoned.into_inner()
    });
    let sql = format!("SELECT {VAULT_COLS} FROM vault_records WHERE vault_op_id = ?1");
    let row = conn
        .query_row(&sql, params![vault_op_id], read_persisted_vault_record)
        .optional()?;
    Ok(row)
}

/// Get a vault record by vault ID.
pub fn get_vault_record_by_vault_id(vault_id: &str) -> Result<Option<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_vault_record_by_vault_id, recovering");
        poisoned.into_inner()
    });
    let sql = format!(
        "SELECT {VAULT_COLS} FROM vault_records WHERE vault_id = ?1 ORDER BY created_at_state DESC LIMIT 1"
    );
    let row = conn
        .query_row(&sql, params![vault_id], read_persisted_vault_record)
        .optional()?;
    Ok(row)
}

pub fn list_vault_records_db() -> Result<Vec<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_vault_records_db, recovering");
        poisoned.into_inner()
    });
    let sql = format!("SELECT {VAULT_COLS} FROM vault_records ORDER BY created_at_state DESC");
    let mut stmt = conn.prepare(&sql)?;
    let iter = stmt.query_map([], read_persisted_vault_record)?;
    let mut out = Vec::new();
    for r in iter {
        out.push(r?);
    }
    Ok(out)
}

/// Set the destination address on an existing vault record.
pub fn set_vault_record_destination_address(vault_op_id: &str, destination: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in set_vault_record_destination_address, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET destination_address = ?2 WHERE vault_op_id = ?1",
        params![vault_op_id, destination],
    )?;
    Ok(())
}

/// Update the funding_txid on an existing vault record.
/// Called after the sweep tx is broadcast for fractional successors.
pub fn update_vault_record_funding_txid(vault_op_id: &str, txid: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_record_funding_txid, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET funding_txid = ?1 WHERE vault_op_id = ?2",
        params![txid, vault_op_id],
    )?;
    Ok(())
}

/// Update the vault_state on an existing vault record.
pub fn update_vault_record_state(vault_op_id: &str, new_state: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_record_state, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET vault_state = ?1 WHERE vault_op_id = ?2",
        params![new_state, vault_op_id],
    )?;
    Ok(())
}

/// Update the exit_amount_sats on an existing vault record.
/// Used to persist how much was locked for crash recovery.
pub fn update_vault_record_exit_amount(vault_op_id: &str, exit_amount_sats: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_record_exit_amount, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET exit_amount_sats = ?1 WHERE vault_op_id = ?2",
        params![exit_amount_sats as i64, vault_op_id],
    )?;
    Ok(())
}

/// Store the exit anchor data on a vault record (dBTC §6.4.3, §12.1.3).
/// Called after the sweep/claim tx is buried under sufficient blocks.
pub fn update_vault_record_exit_anchor(
    vault_op_id: &str,
    exit_header: &[u8],
    exit_confirm_depth: u32,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_record_exit_anchor, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET exit_header = ?1, exit_confirm_depth = ?2 WHERE vault_op_id = ?3",
        params![exit_header, exit_confirm_depth as i64, vault_op_id],
    )?;
    Ok(())
}

/// Find successor records in intermediate sweep/burn states (crash recovery candidates).
/// Returns records where `is_fractional_successor=true` AND `vault_state` is one of
/// 'SweepPending' or 'BurnPending'.
pub fn list_pending_exit_burns() -> Result<Vec<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_pending_exit_burns, recovering");
        poisoned.into_inner()
    });
    let sql = format!(
        "SELECT {VAULT_COLS} FROM vault_records \
         WHERE is_fractional_successor = 1 AND vault_state IN ('SweepPending', 'BurnPending') \
         ORDER BY rowid ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let iter = stmt.query_map([], read_persisted_vault_record)?;
    let mut out = Vec::new();
    for r in iter {
        out.push(r?);
    }
    Ok(out)
}

/// List orphaned fractional successors: `is_fractional_successor=true`, `funding_txid IS NULL`,
/// `vault_state='Initiated'`. These are sweeps that were never broadcast (crash recovery candidates).
pub fn list_orphaned_fractional_successors() -> Result<Vec<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_orphaned_fractional_successors, recovering");
        poisoned.into_inner()
    });
    let sql = format!(
        "SELECT {VAULT_COLS} FROM vault_records \
         WHERE is_fractional_successor = 1 AND funding_txid IS NULL AND vault_state = 'Initiated'"
    );
    let mut stmt = conn.prepare(&sql)?;
    let iter = stmt.query_map([], read_persisted_vault_record)?;
    let mut out = Vec::new();
    for r in iter {
        out.push(r?);
    }
    Ok(out)
}

pub fn delete_vault_record(vault_op_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in delete_vault_record, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "DELETE FROM vault_records WHERE vault_op_id = ?1",
        params![vault_op_id],
    )?;
    Ok(())
}

/// Find the most recent fractional successor for a given parent vault.
/// Returns the vault record where is_fractional_successor=1 and parent_vault_id matches.
/// Used by `update_successor_entry_txid_and_publish_ad` to stamp entry_txid = txid(txsweep)
/// after the sweep tx reaches dmin confirmations (spec §10.4 Step 7, §7 Remark 2).
pub fn get_fractional_successor_by_parent(
    parent_vault_id: &str,
) -> Result<Option<PersistedVaultRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_fractional_successor_by_parent, recovering");
        poisoned.into_inner()
    });
    let sql = format!(
        "SELECT {VAULT_COLS} FROM vault_records \
         WHERE parent_vault_id = ?1 AND is_fractional_successor = 1 \
         ORDER BY created_at_state DESC LIMIT 1"
    );
    let row = conn
        .query_row(&sql, params![parent_vault_id], read_persisted_vault_record)
        .optional()?;
    Ok(row)
}

/// Store the entry txid on a vault record.
/// Called after deposit or sweep creates the HTLC UTXO.
pub fn update_vault_record_entry_txid(vault_op_id: &str, entry_txid: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in update_vault_record_entry_txid, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE vault_records SET entry_txid = ?1 WHERE vault_op_id = ?2",
        params![entry_txid, vault_op_id],
    )?;
    Ok(())
}

/// Find a vault's anchor material (deposit_nonce + entry_txid) for a given amount.
/// Used by the bridge layer for withdrawal planning and vault discovery.
/// Returns (vault_id, deposit_nonce, entry_txid) — caller derives η from manifold_seed + deposit_nonce.
pub fn find_vault_anchor_for_amount(min_sats: u64) -> Result<Option<(String, Vec<u8>, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in find_vault_anchor_for_amount, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT vault_id, deposit_nonce, entry_txid FROM vault_records \
             WHERE direction = 'btc_to_dbtc' \
               AND vault_state = 'completed' \
               AND deposit_nonce IS NOT NULL \
               AND vault_id IS NOT NULL \
               AND btc_amount_sats >= ?1 \
             ORDER BY btc_amount_sats ASC LIMIT 1",
            params![min_sats as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                ))
            },
        )
        .optional()?;
    Ok(row)
}

// Column indices (24 columns, 0-based):
// 0:vault_op_id  1:direction  2:vault_state  3:hash_lock  4:vault_id
// 5:btc_amount_sats  6:btc_pubkey  7:htlc_script  8:htlc_address  9:external_commitment
// 10:refund_iterations  11:created_at_state  12:entry_header  13:parent_vault_id
// 14:successor_depth  15:is_fractional_successor  16:destination_address  17:funding_txid
// 18:refund_hash_lock  19:exit_amount_sats  20:exit_header  21:exit_confirm_depth
// 22:entry_txid  23:deposit_nonce
fn read_persisted_vault_record(row: &Row) -> rusqlite::Result<PersistedVaultRecord> {
    Ok(PersistedVaultRecord {
        vault_op_id: row.get(0)?,
        direction: row.get(1)?,
        vault_state: row.get(2)?,
        hash_lock: row.get(3)?,
        vault_id: row.get(4)?,
        btc_amount_sats: row.get::<_, i64>(5)? as u64,
        btc_pubkey: row.get(6)?,
        htlc_script: row.get(7)?,
        htlc_address: row.get(8)?,
        external_commitment: row.get(9)?,
        refund_iterations: row.get::<_, i64>(10)? as u64,
        created_at_state: row.get::<_, i64>(11)? as u64,
        entry_header: row.get(12)?,
        parent_vault_id: row.get(13)?,
        successor_depth: row.get::<_, i64>(14)? as u32,
        is_fractional_successor: row.get::<_, i32>(15)? != 0,
        destination_address: row.get(16)?,
        funding_txid: row.get(17)?,
        refund_hash_lock: row.get::<_, Option<Vec<u8>>>(18)?.unwrap_or_default(),
        exit_amount_sats: row.get::<_, Option<i64>>(19)?.unwrap_or(0) as u64,
        exit_header: row.get(20)?,
        exit_confirm_depth: row.get::<_, Option<i64>>(21)?.unwrap_or(0) as u32,
        entry_txid: row.get(22)?,
        deposit_nonce: row.get(23)?,
    })
}
