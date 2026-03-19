// SPDX-License-Identifier: MIT OR Apache-2.0
//! Auth token storage for storage-node endpoints.

use anyhow::Result;
use log::{info, warn};
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// Ensure auth tokens are consistent with the current identity binding.
///
/// Root cause fixed: tokens were being reused across identity mutations (genesis/device-id overwrite
/// or restore) or storage-node resets. Since storage-node auth is tied to the authorization
/// device id and genesis, a binding change makes previously persisted tokens invalid.
///
/// This function stores the current binding and purges all auth tokens if it changes.
pub fn ensure_auth_tokens_bound_to_identity(device_id_b32: &str, genesis_b32: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let current = format!("{}|{}", device_id_b32.trim(), genesis_b32.trim());
    let key = "auth_binding_v2";
    let prev = super::settings_get(&conn, key)?;
    if let Some(prev_val) = prev {
        if prev_val != current {
            warn!(
                "Identity binding changed ({} -> {}). Purging persisted auth tokens.",
                prev_val, current
            );
            conn.execute("DELETE FROM auth_tokens", [])?;
        }
    }
    super::settings_set(&conn, key, &current)?;
    Ok(())
}

/// Store auth token for a storage endpoint, bound to device_id + genesis.
pub fn store_auth_token(
    endpoint: &str,
    device_id: &str,
    genesis: &str,
    token: &str,
) -> Result<(), String> {
    let binding = get_connection().map_err(|e| e.to_string())?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();
    conn.execute(
        "INSERT OR REPLACE INTO auth_tokens (endpoint, device_id, genesis, token, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![endpoint, device_id, genesis, token, now as i64],
    ).map_err(|e| e.to_string())?;
    info!(
        "Stored auth token for {} ({}) at {}",
        device_id, genesis, endpoint
    );
    Ok(())
}

/// Retrieve auth token for a storage endpoint + device_id + genesis
pub fn get_auth_token(
    endpoint: &str,
    device_id: &str,
    genesis: &str,
) -> Result<Option<String>, String> {
    let binding = get_connection().map_err(|e| e.to_string())?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let result: Option<String> = conn
        .query_row(
            "SELECT token FROM auth_tokens WHERE endpoint = ?1 AND device_id = ?2 AND genesis = ?3",
            params![endpoint, device_id, genesis],
            |row| row.get(0),
        )
        .ok();
    Ok(result)
}

/// Return the first genesis (if any) stored for (endpoint, device_id) that does NOT match the provided genesis.
pub fn get_mismatched_genesis(
    endpoint: &str,
    device_id: &str,
    genesis: &str,
) -> Result<Option<String>, String> {
    let binding = get_connection().map_err(|e| e.to_string())?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let mut stmt = conn.prepare(
        "SELECT genesis FROM auth_tokens WHERE endpoint = ?1 AND device_id = ?2 AND genesis != ?3 LIMIT 1",
    ).map_err(|e| e.to_string())?;
    let row = stmt
        .query_row(params![endpoint, device_id, genesis], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(row)
}

/// Delete a stored auth token for a given endpoint/device/genesis triplet
pub fn delete_auth_token(endpoint: &str, device_id: &str, genesis: &str) -> Result<(), String> {
    let binding = get_connection().map_err(|e| e.to_string())?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "DELETE FROM auth_tokens WHERE endpoint = ?1 AND device_id = ?2 AND genesis = ?3",
        params![endpoint, device_id, genesis],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
