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
    fn store_and_get_auth_token() {
        init_test_db();
        store_auth_token("https://node.example", "dev-1", "gen-1", "tok-abc").unwrap();

        let token = get_auth_token("https://node.example", "dev-1", "gen-1")
            .unwrap()
            .unwrap();
        assert_eq!(token, "tok-abc");
    }

    #[test]
    #[serial]
    fn get_auth_token_returns_none_when_missing() {
        init_test_db();
        let token = get_auth_token("https://node.example", "dev-x", "gen-x").unwrap();
        assert!(token.is_none());
    }

    #[test]
    #[serial]
    fn delete_auth_token_removes_entry() {
        init_test_db();
        store_auth_token("https://n.example", "dev-2", "gen-2", "tok-del").unwrap();
        delete_auth_token("https://n.example", "dev-2", "gen-2").unwrap();

        let token = get_auth_token("https://n.example", "dev-2", "gen-2").unwrap();
        assert!(token.is_none());
    }

    #[test]
    #[serial]
    fn store_auth_token_upserts_on_conflict() {
        init_test_db();
        store_auth_token("https://ep", "d1", "g1", "old-token").unwrap();
        store_auth_token("https://ep", "d1", "g1", "new-token").unwrap();

        let token = get_auth_token("https://ep", "d1", "g1").unwrap().unwrap();
        assert_eq!(token, "new-token");
    }

    #[test]
    #[serial]
    fn get_mismatched_genesis_detects_stale_token() {
        init_test_db();
        store_auth_token("https://ep", "d1", "gen-old", "tok").unwrap();

        let mismatch = get_mismatched_genesis("https://ep", "d1", "gen-new")
            .unwrap()
            .unwrap();
        assert_eq!(mismatch, "gen-old");
    }

    #[test]
    #[serial]
    fn get_mismatched_genesis_returns_none_when_matching() {
        init_test_db();
        store_auth_token("https://ep", "d1", "gen-same", "tok").unwrap();

        let result = get_mismatched_genesis("https://ep", "d1", "gen-same").unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[serial]
    fn ensure_auth_tokens_bound_to_identity_purges_on_change() {
        init_test_db();
        ensure_auth_tokens_bound_to_identity("dev-a", "gen-a").unwrap();
        store_auth_token("https://ep", "dev-a", "gen-a", "tok-1").unwrap();

        ensure_auth_tokens_bound_to_identity("dev-b", "gen-b").unwrap();

        let token = get_auth_token("https://ep", "dev-a", "gen-a").unwrap();
        assert!(
            token.is_none(),
            "tokens should be purged after identity change"
        );
    }

    #[test]
    #[serial]
    fn ensure_auth_tokens_bound_to_identity_idempotent_same_identity() {
        init_test_db();
        ensure_auth_tokens_bound_to_identity("dev-c", "gen-c").unwrap();
        store_auth_token("https://ep", "dev-c", "gen-c", "tok-keep").unwrap();

        ensure_auth_tokens_bound_to_identity("dev-c", "gen-c").unwrap();

        let token = get_auth_token("https://ep", "dev-c", "gen-c")
            .unwrap()
            .unwrap();
        assert_eq!(token, "tok-keep");
    }

    #[test]
    #[serial]
    fn multiple_endpoints_store_independently() {
        init_test_db();
        store_auth_token("https://ep1", "dev-m", "gen-m", "tok-1").unwrap();
        store_auth_token("https://ep2", "dev-m", "gen-m", "tok-2").unwrap();

        assert_eq!(
            get_auth_token("https://ep1", "dev-m", "gen-m")
                .unwrap()
                .unwrap(),
            "tok-1"
        );
        assert_eq!(
            get_auth_token("https://ep2", "dev-m", "gen-m")
                .unwrap()
                .unwrap(),
            "tok-2"
        );
    }

    #[test]
    #[serial]
    fn delete_auth_token_does_not_affect_other_endpoints() {
        init_test_db();
        store_auth_token("https://ep1", "dev-n", "gen-n", "tok-a").unwrap();
        store_auth_token("https://ep2", "dev-n", "gen-n", "tok-b").unwrap();

        delete_auth_token("https://ep1", "dev-n", "gen-n").unwrap();

        assert!(get_auth_token("https://ep1", "dev-n", "gen-n")
            .unwrap()
            .is_none());
        assert_eq!(
            get_auth_token("https://ep2", "dev-n", "gen-n")
                .unwrap()
                .unwrap(),
            "tok-b"
        );
    }

    #[test]
    #[serial]
    fn get_mismatched_genesis_returns_none_when_no_tokens() {
        init_test_db();
        let result = get_mismatched_genesis("https://ep", "dev-z", "gen-z").unwrap();
        assert!(result.is_none());
    }
}
