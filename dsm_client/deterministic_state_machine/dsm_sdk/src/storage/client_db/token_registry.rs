// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable token registry and anchored policy store.
//!
//! Before this existed, a created token lived only in `RwLock<HashMap>`s: the
//! metadata cache in `TokenSDK` and the policy map in `TokenPolicySystem`.
//! Both are dropped on process exit, so after a restart the token's policy was
//! gone, `resolve_policy_commit_strict` failed, the wallet showed the balance
//! as `"?"`, and `dlv.create` — which resolves the pair's policy commit and
//! fails closed — could not build a vault for it. A token that cannot survive
//! a restart is not a token.
//!
//! Two tables with deliberately separate lifetimes:
//!
//! * `token_policies` — anchored policy bytes, keyed by their own content hash
//!   (`BLAKE3(TAG_DSM_POLICY, policy_bytes)`). A policy can exist without a
//!   token; the developer paste-raw-bytes path publishes one on its own. The
//!   table is self-verifying: a row whose bytes do not hash to its key is
//!   detectable with no external authority, which is what
//!   [`load_policy_verified`] enforces on every read.
//! * `token_registry` — tokens created on this device.
//!
//! **There is intentionally no circulating-supply column.** Circulating supply
//! is derived from the canonical chain, never cached: a mutable counter would
//! be a second authority, and a restored snapshot could disagree with the
//! canonical history — enforcing a supply cap against the wrong number.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// A token as recorded at creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRegistryRow {
    pub token_id: String,
    pub policy_commit: [u8; 32],
    pub ticker: String,
    pub alias: String,
    pub decimals: u32,
    /// Big-endian u128. `0` together with the policy's unlimited flag means
    /// "uncapped"; the policy bytes remain the authority on that distinction.
    pub max_supply: u128,
    pub owner_device_id: [u8; 32],
}

fn row_to_registry(r: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRegistryRow> {
    let commit: Vec<u8> = r.get(1)?;
    let owner: Vec<u8> = r.get(6)?;
    let max_supply_be: Vec<u8> = r.get(5)?;
    let mut commit32 = [0u8; 32];
    let mut owner32 = [0u8; 32];
    if commit.len() == 32 {
        commit32.copy_from_slice(&commit);
    }
    if owner.len() == 32 {
        owner32.copy_from_slice(&owner);
    }
    let mut max_supply = 0u128;
    for b in &max_supply_be {
        max_supply = (max_supply << 8) | (*b as u128);
    }
    Ok(TokenRegistryRow {
        token_id: r.get(0)?,
        policy_commit: commit32,
        ticker: r.get(2)?,
        alias: r.get(3)?,
        decimals: r.get::<_, i64>(4)? as u32,
        max_supply,
        owner_device_id: owner32,
    })
}

const SELECT_COLS: &str =
    "token_id, policy_commit, ticker, alias, decimals, max_supply, owner_device_id";

// ── policies ────────────────────────────────────────────────────────────────

/// Store anchored policy bytes under their content hash.
///
/// Takes the commit explicitly rather than recomputing it so the caller's
/// derivation is the one recorded; [`load_policy_verified`] re-checks it on
/// read, so a mismatch cannot go unnoticed.
pub fn upsert_policy_with_conn(
    conn: &Connection,
    policy_commit: &[u8; 32],
    policy_bytes: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO token_policies(policy_commit, policy_bytes, created_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(policy_commit) DO NOTHING",
        params![policy_commit.as_slice(), policy_bytes, tick() as i64],
    )?;
    Ok(())
}

pub fn upsert_policy(policy_commit: &[u8; 32], policy_bytes: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    upsert_policy_with_conn(&conn, policy_commit, policy_bytes)
}

/// Load policy bytes and verify they still hash to the commit they are stored
/// under. A row that fails this check is corrupt, so it is treated as absent
/// rather than returned — the anchor is the definition of the policy, and
/// bytes that do not match it are not that policy.
pub fn load_policy_verified(policy_commit: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT policy_bytes FROM token_policies WHERE policy_commit = ?1",
            params![policy_commit.as_slice()],
            |r| r.get(0),
        )
        .optional()?;

    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let derived =
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &bytes);
    if derived != *policy_commit {
        log::error!(
            "[token_registry] stored policy does not hash to its own commit — treating as absent"
        );
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Every stored policy, verified. Used to rehydrate the in-memory policy
/// system at startup.
pub fn all_policies() -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare("SELECT policy_commit, policy_bytes FROM token_policies")?;
    let rows = stmt.query_map([], |r| {
        let c: Vec<u8> = r.get(0)?;
        let b: Vec<u8> = r.get(1)?;
        Ok((c, b))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (c, b) = row?;
        if c.len() != 32 {
            continue;
        }
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&c);
        let derived =
            dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &b);
        if derived != commit {
            log::error!("[token_registry] skipping policy whose bytes do not match its commit");
            continue;
        }
        out.push((commit, b));
    }
    Ok(out)
}

// ── registry ────────────────────────────────────────────────────────────────

/// Record a created token.
///
/// `PRIMARY KEY(token_id)` plus `UNIQUE(policy_commit)` and `UNIQUE(ticker)`
/// mean a duplicate creation fails here. When this runs inside the creating
/// advance's transaction, that failure rolls the whole advance back — which is
/// what makes creation exactly-once against both the database and canonical
/// state, rather than merely idempotent-looking.
pub fn insert_token_with_conn(conn: &Connection, row: &TokenRegistryRow) -> Result<()> {
    conn.execute(
        "INSERT INTO token_registry(
             token_id, policy_commit, ticker, alias, decimals, max_supply,
             owner_device_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.token_id,
            row.policy_commit.as_slice(),
            row.ticker,
            row.alias,
            row.decimals as i64,
            row.max_supply.to_be_bytes().to_vec(),
            row.owner_device_id.as_slice(),
            tick() as i64,
        ],
    )?;
    Ok(())
}

pub fn insert_token(row: &TokenRegistryRow) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    insert_token_with_conn(&conn, row)
}

/// Drop a token's identity row and its anchored policy.
///
/// The CALLER is responsible for refusing when the token is still held —
/// canonical state, not this table, knows the balance. This only removes the
/// naming, which is exactly what makes a superseded ticker adoptable again.
/// The policy is content-addressed, so it can always be re-fetched.
pub fn delete_token(token_id: &str) -> Result<Option<TokenRegistryRow>> {
    let Some(row) = get_token(token_id)? else {
        return Ok(None);
    };
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "DELETE FROM token_registry WHERE token_id = ?1",
        params![row.token_id],
    )?;
    conn.execute(
        "DELETE FROM token_policies WHERE policy_commit = ?1",
        params![row.policy_commit.as_slice()],
    )?;
    Ok(Some(row))
}

pub fn get_token(token_id: &str) -> Result<Option<TokenRegistryRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {SELECT_COLS} FROM token_registry WHERE token_id = ?1"),
            params![token_id],
            row_to_registry,
        )
        .optional()?)
}

/// Reverse lookup used by the balance projection: a 32-byte `policy_commit` is
/// the canonical key for a balance, but the wallet needs the ticker to display
/// it.
pub fn get_token_by_policy_commit(policy_commit: &[u8; 32]) -> Result<Option<TokenRegistryRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {SELECT_COLS} FROM token_registry WHERE policy_commit = ?1"),
            params![policy_commit.as_slice()],
            row_to_registry,
        )
        .optional()?)
}

pub fn get_token_by_ticker(ticker: &str) -> Result<Option<TokenRegistryRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {SELECT_COLS} FROM token_registry WHERE ticker = ?1"),
            params![ticker],
            row_to_registry,
        )
        .optional()?)
}

pub fn all_tokens() -> Result<Vec<TokenRegistryRow>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLS} FROM token_registry ORDER BY created_at"
    ))?;
    let rows = stmt.query_map([], row_to_registry)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::reset_database_for_tests;

    fn policy_bytes(tag: u8) -> Vec<u8> {
        vec![tag; 48]
    }

    fn commit_of(bytes: &[u8]) -> [u8; 32] {
        dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, bytes)
    }

    fn row(tag: u8, ticker: &str) -> TokenRegistryRow {
        let bytes = policy_bytes(tag);
        TokenRegistryRow {
            token_id: format!("TOKEN{tag}"),
            policy_commit: commit_of(&bytes),
            ticker: ticker.to_string(),
            alias: "Test Token".into(),
            decimals: 8,
            max_supply: 1_000_000,
            owner_device_id: [0xAA; 32],
        }
    }

    #[test]
    #[serial_test::serial]
    fn policy_round_trips_and_survives_reopen() {
        reset_database_for_tests();
        let bytes = policy_bytes(0x11);
        let commit = commit_of(&bytes);
        upsert_policy(&commit, &bytes).unwrap();

        assert_eq!(load_policy_verified(&commit).unwrap(), Some(bytes.clone()));
        // Rehydration source must see it too.
        let all = all_policies().unwrap();
        assert!(all.iter().any(|(c, b)| *c == commit && *b == bytes));
    }

    /// The table is self-verifying: bytes that no longer hash to their key are
    /// not that policy, so they must read as absent rather than be returned.
    #[test]
    #[serial_test::serial]
    fn tampered_policy_bytes_read_as_absent() {
        reset_database_for_tests();
        let bytes = policy_bytes(0x22);
        let commit = commit_of(&bytes);
        upsert_policy(&commit, &bytes).unwrap();

        // Corrupt the stored bytes behind the commit's back.
        {
            let binding = get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "UPDATE token_policies SET policy_bytes = ?1 WHERE policy_commit = ?2",
                params![vec![0xFFu8; 48], commit.as_slice()],
            )
            .unwrap();
        }

        assert_eq!(
            load_policy_verified(&commit).unwrap(),
            None,
            "bytes that do not hash to the commit are not that policy"
        );
        assert!(
            all_policies().unwrap().is_empty(),
            "rehydration must not resurrect a corrupt policy"
        );
    }

    #[test]
    #[serial_test::serial]
    fn token_round_trips_by_id_commit_and_ticker() {
        reset_database_for_tests();
        let r = row(0x33, "AAA");
        insert_token(&r).unwrap();

        assert_eq!(get_token(&r.token_id).unwrap().as_ref(), Some(&r));
        assert_eq!(
            get_token_by_policy_commit(&r.policy_commit)
                .unwrap()
                .as_ref(),
            Some(&r)
        );
        assert_eq!(get_token_by_ticker("AAA").unwrap().as_ref(), Some(&r));
        assert_eq!(all_tokens().unwrap().len(), 1);
    }

    /// Duplicate identity must fail at the database, so that when the insert
    /// runs inside the creating advance the whole advance rolls back.
    #[test]
    #[serial_test::serial]
    fn duplicate_token_id_commit_or_ticker_is_rejected() {
        reset_database_for_tests();
        let first = row(0x44, "BBB");
        insert_token(&first).unwrap();

        assert!(insert_token(&first).is_err(), "same token_id");

        let same_commit = TokenRegistryRow {
            token_id: "OTHER".into(),
            ticker: "CCC".into(),
            ..first.clone()
        };
        assert!(insert_token(&same_commit).is_err(), "same policy_commit");

        let same_ticker = TokenRegistryRow {
            token_id: "OTHER2".into(),
            policy_commit: commit_of(&policy_bytes(0x55)),
            ..first.clone()
        };
        assert!(insert_token(&same_ticker).is_err(), "same ticker");
    }
}
