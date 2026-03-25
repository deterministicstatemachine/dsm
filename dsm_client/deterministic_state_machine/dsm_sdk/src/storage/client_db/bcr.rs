// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral control resistance (BCR) state persistence.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use dsm::types::state_types::State;
use dsm::types::token_types::Balance;
use log::warn;
use rusqlite::{params, Connection};

use super::get_connection;
use crate::storage::codecs::{read_len_u32, read_string, read_u64, read_u8, read_vec};
use crate::util::deterministic_time::tick;

/// Store a compact suspicious-activity report (bytes-only).
pub fn store_bcr_report(report: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();

    conn.execute(
        "INSERT INTO bcr_reports(report, created_at) VALUES (?1, ?2)",
        params![report, now as i64],
    )?;

    Ok(())
}

/// Persist a state snapshot for bilateral control resistance checks.
pub fn store_bcr_state(state: &State, published: bool) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();

    store_bcr_state_with_conn(&conn, state, published, now)
}

pub(crate) fn store_bcr_state_with_conn(
    conn: &Connection,
    state: &State,
    published: bool,
    now: u64,
) -> Result<()> {

    let state_bytes = state
        .to_bytes()
        .map_err(|e| anyhow!("bcr state serialize failed: {e}"))?;

    let state_hash = if state.hash != [0u8; 32] {
        state.hash
    } else {
        state
            .compute_hash()
            .map_err(|e| anyhow!("bcr compute hash failed: {e}"))?
    };

    conn.execute(
        "INSERT OR REPLACE INTO bcr_states(
            device_id, state_number, state_hash, prev_state_hash, state_bytes, published, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            state.device_info.device_id,
            state.state_number as i64,
            state_hash,
            state.prev_state_hash,
            state_bytes,
            if published { 1i32 } else { 0i32 },
            now as i64,
        ],
    )?;

    Ok(())
}

/// Load archived BCR states for a device (optionally published-only).
pub fn get_bcr_states(device_id: &[u8], published_only: bool) -> Result<Vec<State>> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length: {}", device_id.len()));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = if published_only {
        conn.prepare(
            "SELECT state_bytes FROM bcr_states WHERE device_id = ?1 AND published = 1 ORDER BY state_number ASC",
        )?
    } else {
        conn.prepare(
            "SELECT state_bytes FROM bcr_states WHERE device_id = ?1 ORDER BY state_number ASC",
        )?
    };

    let iter = stmt.query_map(params![device_id], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in iter {
        let bytes = row?;
        match decode_bcr_state_from_bytes(&bytes) {
            Ok(state) => out.push(state),
            Err(e) => warn!("[client_db] Skipping invalid BCR state bytes: {}", e),
        }
    }

    Ok(out)
}

fn decode_bcr_state_from_bytes(bytes: &[u8]) -> Result<State> {
    use dsm::types::operations::Operation;
    use dsm::types::state_types::{DeviceInfo, SparseIndex, StateParams};

    let mut cursor = bytes;

    let _version = read_u8(&mut cursor).map_err(|e| anyhow!("state version: {e}"))?;
    let state_number = read_u64(&mut cursor).map_err(|e| anyhow!("state_number: {e}"))?;

    let prev_state_hash_bytes = read_vec(&mut cursor).map_err(|e| anyhow!("prev_hash: {e}"))?;
    if prev_state_hash_bytes.len() != 32 {
        return Err(anyhow!("prev_state_hash must be 32 bytes"));
    }
    let mut prev_state_hash = [0u8; 32];
    prev_state_hash.copy_from_slice(&prev_state_hash_bytes);

    let entropy = read_vec(&mut cursor).map_err(|e| anyhow!("entropy: {e}"))?;

    let has_encapsulated = read_u8(&mut cursor).map_err(|e| anyhow!("encapsulated flag: {e}"))?;
    let encapsulated_entropy = if has_encapsulated == 1 {
        Some(read_vec(&mut cursor).map_err(|e| anyhow!("encapsulated: {e}"))?)
    } else {
        None
    };

    let op_bytes = read_vec(&mut cursor).map_err(|e| anyhow!("operation bytes: {e}"))?;
    let operation =
        Operation::from_bytes(&op_bytes).map_err(|e| anyhow!("operation decode failed: {e}"))?;

    let device_id_bytes = read_vec(&mut cursor).map_err(|e| anyhow!("device_id: {e}"))?;
    if device_id_bytes.len() != 32 {
        return Err(anyhow!("device_id must be 32 bytes"));
    }
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&device_id_bytes);

    let public_key = read_vec(&mut cursor).map_err(|e| anyhow!("public_key: {e}"))?;
    let metadata = read_vec(&mut cursor).map_err(|e| anyhow!("device metadata: {e}"))?;
    let device_info = DeviceInfo {
        device_id,
        public_key,
        metadata,
    };

    let has_forward = read_u8(&mut cursor).map_err(|e| anyhow!("forward_commit flag: {e}"))?;
    if has_forward == 1 {
        let _ = read_vec(&mut cursor).map_err(|e| anyhow!("forward_commit: {e}"))?;
    }

    let balance_count =
        read_len_u32(&mut cursor).map_err(|e| anyhow!("token balance count: {e}"))?;
    let mut token_balances = HashMap::with_capacity(balance_count);
    for _ in 0..balance_count {
        let key = read_string(&mut cursor).map_err(|e| anyhow!("token_id: {e}"))?;
        let bal_bytes = read_vec(&mut cursor).map_err(|e| anyhow!("balance bytes: {e}"))?;
        if bal_bytes.len() < 24 {
            return Err(anyhow!("balance bytes too short"));
        }
        let value = u64::from_le_bytes(bal_bytes[0..8].try_into().unwrap_or([0u8; 8]));
        let locked = u64::from_le_bytes(bal_bytes[8..16].try_into().unwrap_or([0u8; 8]));
        let last_updated_tick =
            u64::from_le_bytes(bal_bytes[16..24].try_into().unwrap_or([0u8; 8]));
        let state_hash = if bal_bytes.len() >= 56 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&bal_bytes[24..56]);
            Some(h)
        } else {
            None
        };
        let hash_for_balance = state_hash.unwrap_or([0u8; 32]);
        let mut bal = Balance::from_state(value, hash_for_balance, last_updated_tick);
        if locked > 0 {
            let _ = bal.lock(locked);
        }
        token_balances.insert(key, bal);
    }

    let matches_parameters =
        read_u8(&mut cursor).map_err(|e| anyhow!("matches_parameters: {e}"))? == 1;
    let state_type = read_string(&mut cursor).map_err(|e| anyhow!("state_type: {e}"))?;

    let mut params = StateParams::new(state_number, entropy, operation, device_info);
    params.prev_state_hash = prev_state_hash;
    params.encapsulated_entropy = encapsulated_entropy;
    params.matches_parameters = matches_parameters;
    params.state_type = state_type;
    params.sparse_index = SparseIndex::default();

    let mut state = State::new(params);
    state.token_balances = token_balances;

    let hash = state.compute_hash().unwrap_or(state.hash);
    state.hash = hash;

    Ok(state)
}
