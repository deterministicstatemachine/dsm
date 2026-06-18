// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recovery capsule persistence and preferences.
//!
//! Tables:
//! - `recovery_capsules`: stores encrypted capsule bytes indexed by capsule_index
//! - `recovery_prefs`: key/value store for recovery settings (enabled, configured, etc.)

use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::params;

use super::get_connection;
use crate::util::deterministic_time::tick;
use dsm::recovery::BearerAssetLockState;
use dsm::types::operations::{EgressAsset, Operation};

const PENDING_CAPSULE_INDEX_KEY: &str = "pending_capsule_index";

/// Ensure the recovery tables exist (called from schema migration path).
pub fn ensure_recovery_tables() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recovery_capsules(
            capsule_index     INTEGER PRIMARY KEY,
            encrypted_bytes   BLOB NOT NULL,
            smt_root          BLOB NOT NULL,
            created_tick      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_prefs(
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_sync_status(
            device_id   BLOB NOT NULL PRIMARY KEY,
            synced      INTEGER NOT NULL DEFAULT 0,
            sync_tick   INTEGER
        );

        CREATE TABLE IF NOT EXISTS recovered_chain_tips(
            device_id   BLOB NOT NULL PRIMARY KEY,
            height      INTEGER NOT NULL,
            head_hash   BLOB NOT NULL
        );

        -- P5 bearer-asset reconciliation registry (spec §0.4). Keyed by token_id.
        -- state: BearerAssetLockState wire tag (1..=6). frontier_cap: reconciled spendable
        -- cap (used for Reduced). is_dbtc: 1 marks an asset that MUST NOT be reconciled via
        -- the generic token path (stays LockedRecovery until the dedicated dBTC replay pass).
        CREATE TABLE IF NOT EXISTS recovery_locked_assets(
            token_id     BLOB NOT NULL PRIMARY KEY,
            state        INTEGER NOT NULL,
            frontier_cap INTEGER NOT NULL DEFAULT 0,
            is_dbtc      INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )?;

    Ok(())
}

/// Store an encrypted recovery capsule.
pub fn store_recovery_capsule(
    capsule_index: u64,
    encrypted_bytes: &[u8],
    smt_root: &[u8],
) -> Result<()> {
    if encrypted_bytes.is_empty() {
        return Err(anyhow!("encrypted_bytes cannot be empty"));
    }
    if smt_root.len() != 32 {
        return Err(anyhow!("smt_root must be 32 bytes, got {}", smt_root.len()));
    }

    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let now = tick();

    conn.execute(
        "INSERT OR REPLACE INTO recovery_capsules(capsule_index, encrypted_bytes, smt_root, created_tick)
         VALUES (?1, ?2, ?3, ?4)",
        params![capsule_index as i64, encrypted_bytes, smt_root, now as i64],
    )?;

    debug!(
        "[CLIENT_DB] Stored recovery capsule index={}",
        capsule_index
    );
    Ok(())
}

/// Get the latest (highest capsule_index) recovery capsule.
pub fn get_latest_recovery_capsule() -> Result<Option<(u64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT capsule_index, encrypted_bytes FROM recovery_capsules
         ORDER BY capsule_index DESC LIMIT 1",
    )?;

    let result = stmt
        .query_row([], |row| {
            let idx: i64 = row.get(0)?;
            let bytes: Vec<u8> = row.get(1)?;
            Ok((idx as u64, bytes))
        })
        .optional()?;

    Ok(result)
}

/// Mark a stored capsule as pending for the next NFC write.
pub fn mark_pending_recovery_capsule(capsule_index: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_capsules WHERE capsule_index = ?1",
        params![capsule_index as i64],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Err(anyhow!(
            "cannot mark missing recovery capsule {} as pending",
            capsule_index
        ));
    }

    drop(conn);
    set_recovery_pref(PENDING_CAPSULE_INDEX_KEY, &capsule_index.to_le_bytes())
}

/// Clear the pending NFC-write capsule marker.
pub fn clear_pending_recovery_capsule() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "DELETE FROM recovery_prefs WHERE key = ?1",
        params![PENDING_CAPSULE_INDEX_KEY],
    )?;
    Ok(())
}

/// Get the exact capsule currently pending for NFC write.
pub fn get_pending_recovery_capsule() -> Result<Option<(u64, Vec<u8>)>> {
    let Some(bytes) = get_recovery_pref(PENDING_CAPSULE_INDEX_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != 8 {
        return Err(anyhow!(
            "pending capsule index pref must be 8 bytes, got {}",
            bytes.len()
        ));
    }
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&bytes);
    let capsule_index = u64::from_le_bytes(idx_bytes);

    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let capsule = conn
        .query_row(
            "SELECT encrypted_bytes FROM recovery_capsules WHERE capsule_index = ?1",
            params![capsule_index as i64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    if let Some(encrypted_bytes) = capsule {
        return Ok(Some((capsule_index, encrypted_bytes)));
    }

    drop(conn);
    clear_pending_recovery_capsule()?;
    Ok(None)
}

/// Metadata about a stored capsule (for dashboard display, no decryption).
pub struct CapsuleMetadata {
    pub capsule_index: u64,
    pub smt_root: Vec<u8>,
    pub created_tick: u64,
    pub counterparty_count: u64,
}

/// Get metadata for the latest capsule (no decryption needed).
pub fn get_latest_capsule_metadata() -> Result<Option<CapsuleMetadata>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let result = conn
        .query_row(
            "SELECT capsule_index, smt_root, created_tick FROM recovery_capsules
             ORDER BY capsule_index DESC LIMIT 1",
            [],
            |row| {
                let idx: i64 = row.get(0)?;
                let smt_root: Vec<u8> = row.get(1)?;
                let tick: i64 = row.get(2)?;
                Ok(CapsuleMetadata {
                    capsule_index: idx as u64,
                    smt_root,
                    created_tick: tick as u64,
                    // Counterparty count is inside the encrypted capsule; we store it
                    // as a separate column or derive from the recovery_sync_status table.
                    // For now, use sync status table count as a proxy.
                    counterparty_count: 0, // Filled below
                })
            },
        )
        .optional()?;

    match result {
        Some(mut meta) => {
            let stored_count: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT value FROM recovery_prefs WHERE key = 'latest_capsule_counterparty_count'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .unwrap_or(None);

            if let Some(bytes) = stored_count {
                if bytes.len() == 8 {
                    if let Ok(arr) = <[u8; 8]>::try_from(bytes.as_slice()) {
                        meta.counterparty_count = u64::from_le_bytes(arr);
                        return Ok(Some(meta));
                    }
                }
            }

            // Fall back to staged recovered tips if present, then verified contacts.
            let staged_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM recovered_chain_tips", [], |row| {
                    row.get(0)
                })
                .unwrap_or(0);
            if staged_count > 0 {
                meta.counterparty_count = staged_count as u64;
                return Ok(Some(meta));
            }

            let contacts: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM contacts WHERE verified = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            meta.counterparty_count = contacts as u64;
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

/// Get the total number of stored capsules.
pub fn get_capsule_count() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_capsules", [], |row| {
        row.get(0)
    })?;

    Ok(count as u64)
}

/// Get the highest capsule index, or 0 if no capsules exist.
pub fn get_max_capsule_index() -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let idx: i64 = conn.query_row(
        "SELECT COALESCE(MAX(capsule_index), 0) FROM recovery_capsules",
        [],
        |row| row.get(0),
    )?;

    Ok(idx as u64)
}

/// Set a recovery preference (binary value).
pub fn set_recovery_pref(key: &str, value: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "INSERT OR REPLACE INTO recovery_prefs(key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;

    Ok(())
}

/// Get a recovery preference.
pub fn get_recovery_pref(key: &str) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let result: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM recovery_prefs WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;

    Ok(result)
}

/// Typed recovery lifecycle state.
///
/// Persisted in `recovery_prefs["recovery_phase"]` as the canonical lowercase
/// ASCII strings used since the string-phase implementation, so this is a
/// drop-in typed replacement with no on-disk migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// No recovery in progress and device was not recovered.
    None,
    /// Tombstone being created.
    Tombstoning,
    /// Succession receipt being created / new device being bound.
    Succession,
    /// Tombstone being propagated to counterparties.
    Propagating,
    /// Awaiting all-contact tombstone acknowledgement.
    Polling,
    /// Resuming bilateral relationships from recovered tips.
    Resuming,
    /// Identity recovery finished (current lifecycle terminal).
    Complete,
    /// Recovery aborted.
    Failed,
}

impl RecoveryState {
    /// Canonical on-disk string (stable wire/storage representation).
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryState::None => "none",
            RecoveryState::Tombstoning => "tombstoning",
            RecoveryState::Succession => "succession",
            RecoveryState::Propagating => "propagating",
            RecoveryState::Polling => "polling",
            RecoveryState::Resuming => "resuming",
            RecoveryState::Complete => "complete",
            RecoveryState::Failed => "failed",
        }
    }

    /// Parse from on-disk bytes. Unknown/empty parses to `None` (fail-safe to
    /// "no recovery in progress").
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"tombstoning" => RecoveryState::Tombstoning,
            b"succession" => RecoveryState::Succession,
            b"propagating" => RecoveryState::Propagating,
            b"polling" => RecoveryState::Polling,
            b"resuming" => RecoveryState::Resuming,
            b"complete" => RecoveryState::Complete,
            b"failed" => RecoveryState::Failed,
            _ => RecoveryState::None,
        }
    }

    /// Recovery is actively running through its identity-succession lifecycle.
    /// During these states there is no spend-authoritative device, so any value
    /// egress could open a split-acceptance double-spend window (spec vector V1).
    pub fn is_identity_recovery_in_progress(self) -> bool {
        matches!(
            self,
            RecoveryState::Tombstoning
                | RecoveryState::Succession
                | RecoveryState::Propagating
                | RecoveryState::Polling
                | RecoveryState::Resuming
        )
    }
}

/// Read the current typed recovery state.
pub fn recovery_state() -> RecoveryState {
    match get_recovery_pref("recovery_phase") {
        Ok(Some(bytes)) => RecoveryState::from_bytes(&bytes),
        _ => RecoveryState::None,
    }
}

/// Persist the typed recovery state.
pub fn set_recovery_state(state: RecoveryState) -> Result<()> {
    set_recovery_pref("recovery_phase", state.as_str().as_bytes())
}

/// Fail-closed value-egress gate (Phase 0 / spec condition R3).
///
/// Returns `Some(reason)` when a value-bearing transition MUST be refused
/// because identity recovery is in progress. While recovery is running there is
/// no single spend-authoritative device, so any egress could create the
/// split-acceptance recovery double-spend window (spec vector V1).
///
/// This is the in-progress portion of the Phase 0 gate. The post-completion
/// successor freeze and per-asset `LOCKED_RECOVERY` checks land with the
/// identity activation seal (Phase 4) and bearer-asset reconciliation
/// (Phase 5); at that point the only paths that re-open spend are the audited
/// chokepoints. Every value-egress path MUST route through this gate.
pub fn value_egress_block_reason() -> Option<&'static str> {
    const UNREADABLE: &str = "recovery state unreadable: value egress blocked (fail-closed)";

    // Fail-closed read policy: a genuine DB read error means we CANNOT prove the
    // spend is safe, so we block. A legitimately-unset pref (`Ok(None)`) means
    // "no recovery configured" and does NOT block — that distinction avoids
    // bricking devices that never enabled recovery on a transient glitch.
    match get_recovery_pref("recovery_phase") {
        Ok(Some(bytes)) => {
            if RecoveryState::from_bytes(&bytes).is_identity_recovery_in_progress() {
                return Some(
                    "device recovery in progress: value egress is blocked until recovery resolves",
                );
            }
        }
        Ok(None) => {}
        Err(_) => return Some(UNREADABLE),
    }

    // T4.4 (spec §6.9, vector V1): a device produced by a recovery succession
    // (a successor) MUST NOT egress value until a VALID recovery activation seal
    // has been verified and recorded — the sole place that flips
    // `recovery_activated` is the audited verify-and-record chokepoint. Until
    // then the successor is frozen: safe (cannot create a split-acceptance
    // double-spend), incomplete for usability. Fail-closed on read error.
    let recovered_successor = match get_recovery_pref(RECOVERED_SUCCESSOR_KEY) {
        Ok(v) => v.as_deref() == Some(&[1u8][..]),
        Err(_) => return Some(UNREADABLE),
    };
    if recovered_successor {
        let activated = match get_recovery_pref(RECOVERY_ACTIVATED_KEY) {
            Ok(v) => v.as_deref() == Some(&[1u8][..]),
            Err(_) => return Some(UNREADABLE),
        };
        if !activated {
            return Some(
                "recovered device not yet activated: value egress blocked until a valid recovery activation seal is recorded",
            );
        }
    }

    // R2′ (spec §5 — durable-persist-before-value): when recovery is enabled, the
    // recovery capsule MUST capture the latest accepted state before value
    // egress, so a lost/destroyed device is always recoverable to a frontier at
    // or beyond any spend. The egress chokepoint attempts a best-effort re-seal
    // first; if it still cannot seal (e.g. no cached key), egress is refused.
    //
    // NOTE: this enforces capsule *seal* currency. Confirmation of durable write
    // to the external recovery medium (NFC tag / storage-node publish) is the
    // stronger form tracked separately as the durable-capsule index.
    let enabled = match get_recovery_pref("nfc_backup_enabled") {
        Ok(v) => v.as_deref() == Some(&[1u8][..]),
        Err(_) => return Some(UNREADABLE),
    };
    if enabled {
        let accepted = match read_u64_pref_checked(ACCEPTED_STATE_INDEX_KEY) {
            Ok(v) => v,
            Err(_) => return Some(UNREADABLE),
        };
        let sealed = match read_u64_pref_checked(CAPSULE_STATE_INDEX_KEY) {
            Ok(v) => v,
            Err(_) => return Some(UNREADABLE),
        };
        if sealed < accepted {
            return Some(
                "recovery capsule is stale (latest accepted state not yet sealed): refresh recovery before value egress",
            );
        }
    }
    None
}

/// Convenience guard: errors when value egress is currently blocked.
pub fn precheck_value_egress() -> Result<()> {
    if let Some(reason) = value_egress_block_reason() {
        return Err(anyhow!(reason));
    }
    Ok(())
}

const ACCEPTED_STATE_INDEX_KEY: &str = "accepted_state_index";
const CAPSULE_STATE_INDEX_KEY: &str = "capsule_state_index";
const RECOVERED_SUCCESSOR_KEY: &str = "recovered_successor";
const RECOVERY_ACTIVATED_KEY: &str = "recovery_activated";

/// Read an 8-byte u64 pref, propagating DB read errors. A missing/short row is
/// `Ok(0)` (legitimately unset); only a genuine DB error is `Err`. The gate uses
/// this so it can fail CLOSED on an unreadable DB while still treating "never
/// set" as allow.
fn read_u64_pref_checked(key: &str) -> Result<u64> {
    match get_recovery_pref(key)? {
        Some(bytes) if bytes.len() == 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&bytes);
            Ok(u64::from_le_bytes(a))
        }
        _ => Ok(0),
    }
}

fn read_u64_pref(key: &str) -> u64 {
    read_u64_pref_checked(key).unwrap_or(0)
}

/// Device-level monotone count of accepted frontier-changing transitions
/// (capsule currency anchor, spec §5.1). 0 if unset.
pub fn accepted_state_index() -> u64 {
    read_u64_pref(ACCEPTED_STATE_INDEX_KEY)
}

/// Increment and return the accepted-state index. Called on every accepted
/// frontier-changing transition. A bump marks the recovery capsule dirty until
/// the next successful seal records the new index via `set_capsule_state_index`.
pub fn bump_accepted_state_index() -> Result<u64> {
    let next = accepted_state_index().saturating_add(1);
    set_recovery_pref(ACCEPTED_STATE_INDEX_KEY, &next.to_le_bytes())?;
    Ok(next)
}

/// Increment `accepted_state_index` using an EXISTING connection/transaction so
/// the bump is ATOMIC with the caller's state-commit transaction: if the
/// surrounding tx rolls back the bump rolls back too, and if the bump fails the
/// whole advance fails closed. This removes the post-commit fail-OPEN window
/// where a missed bump leaves the capsule un-dirtied on already-committed state.
///
/// MUST be passed the connection that owns the open transaction — do NOT open a
/// new connection here (it would deadlock on the connection mutex).
pub fn bump_accepted_state_index_with_conn(conn: &rusqlite::Connection) -> Result<u64> {
    let current: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM recovery_prefs WHERE key = ?1",
            params![ACCEPTED_STATE_INDEX_KEY],
            |row| row.get(0),
        )
        .optional()?;
    let cur = match current {
        Some(b) if b.len() == 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b);
            u64::from_le_bytes(a)
        }
        _ => 0,
    };
    let next = cur.saturating_add(1);
    conn.execute(
        "INSERT OR REPLACE INTO recovery_prefs(key, value) VALUES (?1, ?2)",
        params![ACCEPTED_STATE_INDEX_KEY, &next.to_le_bytes()[..]],
    )?;
    Ok(next)
}

/// The accepted-state index captured by the latest successful capsule seal.
pub fn capsule_state_index() -> u64 {
    read_u64_pref(CAPSULE_STATE_INDEX_KEY)
}

/// Record that a capsule has sealed the given accepted-state index. Clears the
/// dirty condition up to that point (spec §5.2).
pub fn set_capsule_state_index(index: u64) -> Result<()> {
    set_recovery_pref(CAPSULE_STATE_INDEX_KEY, &index.to_le_bytes())
}

/// Capsule currency check (spec §5.2):
/// `CapsuleCurrent ⟺ capsule_state_index == accepted_state_index`.
///
/// The capsule is dirty when the latest sealed capsule does not capture the
/// latest accepted state. While dirty, the exported recovery artifact does not
/// represent the latest accepted device frontier; the wallet surfaces this, and
/// (R2′, Phase 1 follow-up) value egress is refused until it is current.
pub fn is_capsule_dirty() -> bool {
    capsule_state_index() < accepted_state_index()
}

/// True if this device was produced by a recovery succession (it replaced an old
/// device). Such a device is spend-frozen until a valid recovery activation seal
/// is recorded (T4.4). Defaults to false (swallow read errors here; the gate
/// re-reads fail-closed).
pub fn is_recovered_successor() -> bool {
    matches!(get_recovery_pref(RECOVERED_SUCCESSOR_KEY), Ok(Some(v)) if v == [1u8])
}

/// Mark (or clear) this device as a recovery successor.
pub fn set_recovered_successor(value: bool) -> Result<()> {
    set_recovery_pref(RECOVERED_SUCCESSOR_KEY, &[u8::from(value)])
}

/// True once a valid `RecoveryActivationSeal` has been verified and recorded.
pub fn is_recovery_activated() -> bool {
    matches!(get_recovery_pref(RECOVERY_ACTIVATED_KEY), Ok(Some(v)) if v == [1u8])
}

/// Record recovery activation. The ONLY caller is the audited verify-and-record
/// chokepoint, after `validate_activation_seal` succeeds (T4.4).
pub fn set_recovery_activated(value: bool) -> Result<()> {
    set_recovery_pref(RECOVERY_ACTIVATED_KEY, &[u8::from(value)])
}

/// Anti-rollback floor check for the recovery resume path (P3/T3.2).
///
/// Returns `Ok(true)` if a capsule floor is staged for `counterparty_device_id`
/// and `proposed_tip` DIVERGES from it — a resume-time rollback/divergence that
/// MUST be refused (a request must not set a relationship tip different from the
/// owner's own sealed floor). Returns `Ok(false)` when no floor is staged for
/// that counterparty or the tip confirms the floor. Forward extension above the
/// floor is handled by the seal flow with a co-signed chain proof, not here.
pub fn resume_tip_diverges_from_floor(
    counterparty_device_id: &[u8],
    proposed_tip: &[u8; 32],
) -> Result<bool> {
    for t in get_recovered_chain_tips()? {
        if t.device_id.as_slice() == counterparty_device_id {
            return Ok(&t.head_hash != proposed_tip);
        }
    }
    Ok(false)
}

/// Store an encrypted recovery key blob (device-bound encryption).
pub fn store_encrypted_recovery_key(blob: &[u8]) -> Result<()> {
    set_recovery_pref("encrypted_recovery_key", blob)
}

/// Load the encrypted recovery key blob.
pub fn load_encrypted_recovery_key() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("encrypted_recovery_key")
}

/// Delete the persisted encrypted recovery key.
pub fn delete_encrypted_recovery_key() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "DELETE FROM recovery_prefs WHERE key = ?1",
        params!["encrypted_recovery_key"],
    )?;
    Ok(())
}

/// Check if NFC backup is enabled.
pub fn is_nfc_backup_enabled() -> bool {
    get_recovery_pref("nfc_backup_enabled")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Check if NFC backup was ever configured (mnemonic was set up).
pub fn is_nfc_backup_configured() -> bool {
    get_recovery_pref("nfc_backup_configured")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Set NFC backup enabled state.
pub fn set_nfc_backup_enabled(enabled: bool) -> Result<()> {
    set_recovery_pref("nfc_backup_enabled", &[if enabled { 1u8 } else { 0u8 }])
}

/// Set NFC backup configured state.
pub fn set_nfc_backup_configured(configured: bool) -> Result<()> {
    set_recovery_pref(
        "nfc_backup_configured",
        &[if configured { 1u8 } else { 0u8 }],
    )
}

/// Check if NFC auto-write-on-transaction is enabled.
pub fn is_nfc_auto_write_enabled() -> bool {
    get_recovery_pref("nfc_auto_write_prompt")
        .ok()
        .flatten()
        .map(|v| v == [1u8])
        .unwrap_or(false)
}

/// Set NFC auto-write-on-transaction enabled state.
pub fn set_nfc_auto_write_enabled(enabled: bool) -> Result<()> {
    set_recovery_pref("nfc_auto_write_prompt", &[if enabled { 1u8 } else { 0u8 }])
}

/// Store the exact counterparty count for the latest capsule preview.
pub fn set_latest_capsule_counterparty_count(count: u64) -> Result<()> {
    set_recovery_pref("latest_capsule_counterparty_count", &count.to_le_bytes())
}

/// Delete all capsules except the latest N (cleanup).
pub fn prune_old_capsules(keep_latest_n: u64) -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let deleted = conn.execute(
        "DELETE FROM recovery_capsules WHERE capsule_index NOT IN (
            SELECT capsule_index FROM recovery_capsules ORDER BY capsule_index DESC LIMIT ?1
        )",
        params![keep_latest_n as i64],
    )?;

    let pending_pref: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM recovery_prefs WHERE key = ?1",
            params![PENDING_CAPSULE_INDEX_KEY],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(bytes) = pending_pref {
        if bytes.len() == 8 {
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&bytes);
            let pending_index = u64::from_le_bytes(idx_bytes);
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM recovery_capsules WHERE capsule_index = ?1",
                params![pending_index as i64],
                |row| row.get(0),
            )?;
            if exists == 0 {
                drop(conn);
                clear_pending_recovery_capsule()?;
                return Ok(deleted as u64);
            }
        }
    }

    Ok(deleted as u64)
}

use rusqlite::OptionalExtension;

// ============================================================================
// Recovery Sync Gate — tombstone must reach ALL contacts before resume
// ============================================================================

/// Ensure the recovery_sync_status table exists.
pub fn ensure_recovery_sync_table() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recovery_sync_status(
            device_id   BLOB NOT NULL PRIMARY KEY,
            synced      INTEGER NOT NULL DEFAULT 0,
            sync_tick   INTEGER
        );
        "#,
    )?;

    Ok(())
}

/// Initialize sync tracking for all counterparties from a recovered capsule.
/// Sets all to synced=0 (pending).
pub fn init_recovery_sync_status(counterparty_device_ids: &[[u8; 32]]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    // Clear any existing sync status
    conn.execute("DELETE FROM recovery_sync_status", [])?;

    let mut stmt = conn.prepare(
        "INSERT INTO recovery_sync_status(device_id, synced, sync_tick) VALUES (?1, 0, NULL)",
    )?;

    for device_id in counterparty_device_ids {
        stmt.execute(params![device_id.as_slice()])?;
    }

    debug!(
        "[CLIENT_DB] Initialized recovery sync status for {} counterparties",
        counterparty_device_ids.len()
    );
    Ok(())
}

/// Mark a counterparty as having synced the tombstone.
pub fn mark_counterparty_synced(device_id: &[u8; 32], sync_tick_val: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "UPDATE recovery_sync_status SET synced = 1, sync_tick = ?1 WHERE device_id = ?2",
        params![sync_tick_val as i64, device_id.as_slice()],
    )?;

    debug!(
        "[CLIENT_DB] Marked counterparty as tombstone-synced at tick {}",
        sync_tick_val
    );
    Ok(())
}

/// Get all counterparty DevIDs that have NOT yet synced the tombstone.
pub fn get_unsynced_counterparties() -> Result<Vec<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare("SELECT device_id FROM recovery_sync_status WHERE synced = 0")?;

    let rows = stmt.query_map([], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        Ok(bytes)
    })?;

    let mut result = Vec::new();
    for bytes in rows.flatten() {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            result.push(arr);
        }
    }

    Ok(result)
}

/// Check if ALL counterparties have synced the tombstone.
/// Returns true only when every entry has synced=1.
/// Returns true if the table is empty (no counterparties to sync).
pub fn all_counterparties_synced() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let unsynced_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_sync_status WHERE synced = 0",
        [],
        |row| row.get(0),
    )?;

    Ok(unsynced_count == 0)
}

/// Get sync progress: (synced_count, total_count).
pub fn get_sync_progress() -> Result<(u64, u64)> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let total: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_sync_status", [], |row| {
        row.get(0)
    })?;

    let synced: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_sync_status WHERE synced = 1",
        [],
        |row| row.get(0),
    )?;

    Ok((synced as u64, total as u64))
}

/// Clear all sync status (for reset or new recovery cycle).
pub fn clear_recovery_sync_status() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute("DELETE FROM recovery_sync_status", [])?;
    Ok(())
}

/// Staged recovered chain tip used for crash-safe tombstone/resume recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredChainTip {
    pub device_id: [u8; 32],
    pub height: u64,
    pub head_hash: [u8; 32],
}

/// Replace the staged recovered chain tips with the newly imported capsule tips.
pub fn store_recovered_chain_tips(tips: &[RecoveredChainTip]) -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let tx = conn.transaction()?;
    tx.execute("DELETE FROM recovered_chain_tips", [])?;

    if !tips.is_empty() {
        let mut stmt = tx.prepare(
            "INSERT INTO recovered_chain_tips(device_id, height, head_hash) VALUES (?1, ?2, ?3)",
        )?;
        for tip in tips {
            stmt.execute(params![
                tip.device_id.as_slice(),
                tip.height as i64,
                tip.head_hash.as_slice()
            ])?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Return all staged recovered chain tips from the most recently imported capsule.
pub fn get_recovered_chain_tips() -> Result<Vec<RecoveredChainTip>> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    let mut stmt = conn.prepare(
        "SELECT device_id, height, head_hash FROM recovered_chain_tips ORDER BY device_id ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        let device_id: Vec<u8> = row.get(0)?;
        let height: i64 = row.get(1)?;
        let head_hash: Vec<u8> = row.get(2)?;
        Ok((device_id, height, head_hash))
    })?;

    let mut tips = Vec::new();
    for row in rows {
        let (device_id, height, head_hash) = row?;
        if device_id.len() != 32 {
            return Err(anyhow!(
                "recovered_chain_tips.device_id must be 32 bytes, got {}",
                device_id.len()
            ));
        }
        if head_hash.len() != 32 {
            return Err(anyhow!(
                "recovered_chain_tips.head_hash must be 32 bytes, got {}",
                head_hash.len()
            ));
        }

        let mut device_id_arr = [0u8; 32];
        device_id_arr.copy_from_slice(&device_id);
        let mut head_hash_arr = [0u8; 32];
        head_hash_arr.copy_from_slice(&head_hash);

        tips.push(RecoveredChainTip {
            device_id: device_id_arr,
            height: height as u64,
            head_hash: head_hash_arr,
        });
    }

    Ok(tips)
}

/// Clear all staged recovered chain tips.
pub fn clear_recovered_chain_tips() -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute("DELETE FROM recovered_chain_tips", [])?;
    Ok(())
}

// ============================================================================
// Tombstone Persistence — store receipts and track tombstoned devices
// ============================================================================

/// Ensure the tombstoned_devices table exists (called from schema migration path).
pub fn ensure_tombstone_tables() -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS tombstoned_devices(
            device_id       BLOB NOT NULL PRIMARY KEY,
            tombstone_hash  BLOB NOT NULL,
            discovered_tick INTEGER NOT NULL
        );
        "#,
    )?;

    Ok(())
}

/// Store the tombstone receipt bytes for later relay to counterparties.
pub fn store_tombstone_receipt(receipt_bytes: &[u8]) -> Result<()> {
    set_recovery_pref("tombstone_receipt", receipt_bytes)
}

/// Get the stored tombstone receipt bytes.
pub fn get_tombstone_receipt() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("tombstone_receipt")
}

/// Store the counterparty device IDs extracted from a decrypted capsule.
/// Device IDs are stored as concatenated 32-byte arrays.
pub fn store_capsule_counterparty_ids(device_ids: &[[u8; 32]]) -> Result<()> {
    let mut blob = Vec::with_capacity(device_ids.len() * 32);
    for id in device_ids {
        blob.extend_from_slice(id);
    }
    set_recovery_pref("capsule_counterparty_ids", &blob)
}

/// Get the counterparty device IDs stored during capsule decryption.
pub fn get_capsule_counterparty_ids() -> Result<Vec<[u8; 32]>> {
    let blob = get_recovery_pref("capsule_counterparty_ids")?.unwrap_or_default();
    if blob.len() % 32 != 0 {
        return Err(anyhow!(
            "capsule_counterparty_ids blob length {} not divisible by 32",
            blob.len()
        ));
    }
    let mut ids = Vec::with_capacity(blob.len() / 32);
    for chunk in blob.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        ids.push(arr);
    }
    Ok(ids)
}

/// Store the tombstone hash for the recovering device (our old device).
pub fn store_tombstone_hash(tombstone_hash: &[u8]) -> Result<()> {
    set_recovery_pref("tombstone_hash", tombstone_hash)
}

/// Get the stored tombstone hash.
pub fn get_tombstone_hash() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("tombstone_hash")
}

/// Store a succession receipt for the new device.
pub fn store_succession_receipt(receipt_bytes: &[u8]) -> Result<()> {
    set_recovery_pref("succession_receipt", receipt_bytes)
}

/// Get the stored succession receipt.
pub fn get_succession_receipt() -> Result<Option<Vec<u8>>> {
    get_recovery_pref("succession_receipt")
}

/// Record a device ID as tombstoned (rejected for future bilateral interactions).
pub fn store_tombstoned_device(
    device_id: &[u8; 32],
    tombstone_hash: &[u8],
    tick: u64,
) -> Result<()> {
    ensure_tombstone_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;

    conn.execute(
        "INSERT OR REPLACE INTO tombstoned_devices(device_id, tombstone_hash, discovered_tick)
         VALUES (?1, ?2, ?3)",
        params![device_id.as_slice(), tombstone_hash, tick as i64],
    )?;

    debug!("[CLIENT_DB] Stored tombstoned device at tick {}", tick);
    Ok(())
}

/// Check if a device ID has been tombstoned.
pub fn is_device_tombstoned(device_id: &[u8; 32]) -> bool {
    let result = (|| -> Result<bool> {
        ensure_tombstone_tables()?;
        let binding = get_connection()?;
        let conn = binding
            .lock()
            .map_err(|_| anyhow!("Database lock poisoned"))?;

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tombstoned_devices WHERE device_id = ?1",
            params![device_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    })();
    result.unwrap_or(false)
}

// ════════════════════════════════════════════════════════════════════════════
// P5 — Bearer-asset reconciliation registry + per-asset egress gate (spec §0.4).
//
// The two-gate model: identity succession does NOT make recovered bearer assets
// spendable. Every capsule-restored bearer asset enters LockedRecovery and stays
// there until its OWN verified frontier reconciles it. This per-asset gate is in
// ADDITION to the identity-level `value_egress_block_reason` and persists AFTER
// recovery activation. dBTC is excluded from the generic reconcile path — it stays
// LockedRecovery until the dedicated dBTC frontier-replay pass.
// ════════════════════════════════════════════════════════════════════════════

/// True iff `token_id` names the dBTC bearer asset (canonical `DBTC_TOKEN_ID = "dBTC"`).
/// dBTC MUST NOT be reconciled via the generic token path (spec §0.4 P5 cut). Matched
/// case-insensitively so spelling variants stay conservatively locked.
pub fn is_dbtc_token_id(token_id: &[u8]) -> bool {
    token_id.eq_ignore_ascii_case(b"dbtc")
}

/// One bearer-asset lock registry entry.
#[derive(Debug, Clone, Copy)]
pub struct BearerAssetLock {
    pub state: BearerAssetLockState,
    pub frontier_cap: u64,
    pub is_dbtc: bool,
}

/// Upsert a bearer-asset lock entry (keyed by `token_id`).
pub fn set_asset_lock(
    token_id: &[u8],
    state: BearerAssetLockState,
    frontier_cap: u64,
    is_dbtc: bool,
) -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "INSERT INTO recovery_locked_assets(token_id, state, frontier_cap, is_dbtc)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(token_id) DO UPDATE SET
            state = excluded.state,
            frontier_cap = excluded.frontier_cap,
            is_dbtc = excluded.is_dbtc",
        params![
            token_id,
            state.to_wire() as i64,
            frontier_cap as i64,
            is_dbtc as i64
        ],
    )?;
    Ok(())
}

/// Read a bearer-asset lock entry. `Ok(None)` = not under recovery lock. Fail-CLOSED on a
/// corrupt/invalid state tag (returns `Err`; the gate treats `Err` as "locked").
pub fn get_asset_lock(token_id: &[u8]) -> Result<Option<BearerAssetLock>> {
    use rusqlite::OptionalExtension;
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let row = conn
        .query_row(
            "SELECT state, frontier_cap, is_dbtc FROM recovery_locked_assets WHERE token_id = ?1",
            params![token_id],
            |r| {
                let state: i64 = r.get(0)?;
                let cap: i64 = r.get(1)?;
                let is_dbtc: i64 = r.get(2)?;
                Ok((state, cap, is_dbtc))
            },
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((state, cap, is_dbtc)) => {
            let tag = u8::try_from(state).map_err(|_| anyhow!("lock state tag out of range"))?;
            let state = BearerAssetLockState::from_wire(tag)
                .map_err(|e| anyhow!("invalid bearer-asset lock state: {e}"))?;
            Ok(Some(BearerAssetLock {
                state,
                frontier_cap: cap.max(0) as u64,
                is_dbtc: is_dbtc != 0,
            }))
        }
    }
}

/// Mark a capsule-restored bearer asset `LockedRecovery` — INSERT-IF-ABSENT, so it NEVER
/// clobbers an entry already reconciled this cycle (Spendable/Reduced/…). dBTC is
/// auto-flagged. The capsule is a continuity hint, NEVER a balance oracle — a restored asset
/// is not spendable until reconciled. Idempotent; safe to re-run as balances materialize.
/// (A NEW recovery cycle starts with [`clear_asset_locks`] so stale reconciliations don't
/// carry over.)
pub fn lock_restored_bearer_asset(token_id: &[u8]) -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute(
        "INSERT INTO recovery_locked_assets(token_id, state, frontier_cap, is_dbtc)
         VALUES (?1, ?2, 0, ?3)
         ON CONFLICT(token_id) DO NOTHING",
        params![
            token_id,
            BearerAssetLockState::LockedRecovery.to_wire() as i64,
            is_dbtc_token_id(token_id) as i64
        ],
    )?;
    Ok(())
}

/// Clear the entire bearer-asset lock registry. Called at the START of a recovery cycle so a
/// fresh recovery re-locks everything and stale reconciliations from a prior cycle don't
/// leave an asset spendable.
pub fn clear_asset_locks() -> Result<()> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    conn.execute("DELETE FROM recovery_locked_assets", [])?;
    Ok(())
}

/// Whether any bearer asset is still recovery-locked (state != `Spendable`). Used by the gate
/// for egress ops whose asset can't be identified — fail closed while anything is locked.
pub fn any_recovery_locked_assets() -> Result<bool> {
    ensure_recovery_tables()?;
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned"))?;
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM recovery_locked_assets WHERE state != ?1",
        params![BearerAssetLockState::Spendable.to_wire() as i64],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Per-asset egress gate (spec §0.4 P5). Returns a block reason for the egress `op`, or
/// `None` if it may proceed. Fail-CLOSED: any DB read error blocks. This is checked IN
/// ADDITION to the identity-level [`value_egress_block_reason`] and persists per-asset after
/// recovery activation.
pub fn asset_egress_block_reason(op: &Operation) -> Option<String> {
    const UNREADABLE: &str = "bearer-asset lock state unreadable: egress blocked (fail-closed)";
    match op.egress_asset() {
        EgressAsset::NotEgress => None,
        EgressAsset::Unidentified => match any_recovery_locked_assets() {
            Ok(true) => Some(
                "egress operation's bearer asset cannot be identified while recovery locks are \
                 active: blocked (fail-closed)"
                    .to_string(),
            ),
            Ok(false) => None,
            Err(_) => Some(UNREADABLE.to_string()),
        },
        EgressAsset::Asset { token_id, amount } => match get_asset_lock(&token_id) {
            Ok(None) => None,
            Ok(Some(lock)) => {
                if !lock.state.permits_egress() {
                    return Some(format!(
                        "bearer asset is {} (recovery): egress refused until reconciled",
                        lock.state.label()
                    ));
                }
                if lock.state.is_frontier_capped() && amount > lock.frontier_cap {
                    return Some(format!(
                        "bearer-asset egress {amount} exceeds reconciled frontier {} (Reduced): \
                         refused",
                        lock.frontier_cap
                    ));
                }
                None
            }
            Err(_) => Some(UNREADABLE.to_string()),
        },
    }
}

/// Reconcile an ORDINARY token asset against its independently-VERIFIED frontier (spec §0.4
/// P5 generic path): `verified >= hint` → `Spendable`; `verified < hint` → `Reduced` capped
/// at `verified`. Returns the new state. Fail-CLOSED for dBTC: it stays `LockedRecovery`
/// until the dedicated dBTC frontier-replay pass (a `MissingDbtcFrontierReplay` error).
pub fn reconcile_token_asset(
    token_id: &[u8],
    hint: u64,
    verified: u64,
) -> Result<BearerAssetLockState> {
    if is_dbtc_token_id(token_id) {
        return Err(anyhow!(
            "MissingDbtcFrontierReplay: dBTC must not be reconciled via the generic token path; \
             it stays LockedRecovery until the dedicated dBTC frontier-replay pass"
        ));
    }
    // Defense-in-depth: honor a stored is_dbtc flag even if the token_id check ever misses.
    if let Some(lock) = get_asset_lock(token_id)? {
        if lock.is_dbtc {
            return Err(anyhow!(
                "MissingDbtcFrontierReplay: asset flagged dBTC; generic reconciliation refused"
            ));
        }
    }
    let (state, cap) = dsm::recovery::reconcile_token_frontier(hint, verified);
    set_asset_lock(token_id, state, cap, false)?;
    Ok(state)
}

/// Recovery-time locking: mark every bearer asset in `device_id_str`'s balance projections
/// `LockedRecovery` (spec §0.4 — the capsule is a continuity hint, not a balance oracle).
/// Returns the count locked. Call for BOTH the old and new device ids on recovery so the
/// token-keyed registry covers whichever device the restored projections landed under.
/// Idempotent on token_id. (Post-recovery ingress creates fresh, unlocked projections.)
pub fn lock_all_restored_bearer_assets(device_id_str: &str) -> Result<usize> {
    let projections = crate::storage::client_db::list_balance_projections(device_id_str)?;
    let mut n = 0usize;
    for p in &projections {
        lock_restored_bearer_asset(p.token_id.as_bytes())?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn setup_test_db() {
        // Use in-memory DB for tests
        std::env::set_var("DSM_SDK_TEST_MODE", "1");
        crate::storage::client_db::reset_database_for_tests();
        if let Err(e) = crate::storage::client_db::init_database() {
            let msg = e.to_string();
            if !msg.contains("duplicate column name: device_tree_root") {
                panic!("init db: {e}");
            }
        }
        ensure_recovery_tables().expect("ensure recovery tables");
    }

    #[test]
    #[serial]
    fn test_store_and_retrieve_capsule() {
        setup_test_db();
        let smt_root = [42u8; 32];
        let capsule_bytes = b"encrypted_capsule_data";

        store_recovery_capsule(1, capsule_bytes, &smt_root).expect("store");

        let latest = get_latest_recovery_capsule().expect("get latest");
        assert!(latest.is_some());
        let (idx, bytes) = latest.expect("should have capsule");
        assert_eq!(idx, 1);
        assert_eq!(bytes, capsule_bytes);
    }

    #[test]
    #[serial]
    fn test_capsule_count_and_max_index() {
        setup_test_db();
        let smt_root = [42u8; 32];

        assert_eq!(get_capsule_count().expect("count"), 0);
        assert_eq!(get_max_capsule_index().expect("max"), 0);

        store_recovery_capsule(5, b"cap5", &smt_root).expect("store");
        store_recovery_capsule(10, b"cap10", &smt_root).expect("store");

        assert_eq!(get_capsule_count().expect("count"), 2);
        assert_eq!(get_max_capsule_index().expect("max"), 10);
    }

    #[test]
    #[serial]
    fn test_pending_capsule_marker_clears_without_deleting_capsule() {
        setup_test_db();
        let smt_root = [7u8; 32];

        store_recovery_capsule(1, b"cap1", &smt_root).expect("store cap1");
        store_recovery_capsule(2, b"cap2", &smt_root).expect("store cap2");
        mark_pending_recovery_capsule(2).expect("mark pending");

        let pending = get_pending_recovery_capsule().expect("read pending");
        assert_eq!(pending, Some((2, b"cap2".to_vec())));

        clear_pending_recovery_capsule().expect("clear pending");
        assert!(get_pending_recovery_capsule()
            .expect("pending cleared")
            .is_none());

        let latest = get_latest_recovery_capsule().expect("latest");
        assert_eq!(latest, Some((2, b"cap2".to_vec())));
    }

    #[test]
    #[serial]
    fn test_recovery_prefs() {
        setup_test_db();

        assert!(!is_nfc_backup_enabled());
        assert!(!is_nfc_backup_configured());

        set_nfc_backup_enabled(true).expect("set enabled");
        set_nfc_backup_configured(true).expect("set configured");

        assert!(is_nfc_backup_enabled());
        assert!(is_nfc_backup_configured());

        set_nfc_backup_enabled(false).expect("set disabled");
        assert!(!is_nfc_backup_enabled());
        assert!(is_nfc_backup_configured()); // configured stays true
    }

    #[test]
    fn test_recovery_state_string_roundtrip() {
        // Every state round-trips through its on-disk string.
        let all = [
            RecoveryState::None,
            RecoveryState::Tombstoning,
            RecoveryState::Succession,
            RecoveryState::Propagating,
            RecoveryState::Polling,
            RecoveryState::Resuming,
            RecoveryState::Complete,
            RecoveryState::Failed,
        ];
        for s in all {
            assert_eq!(RecoveryState::from_bytes(s.as_str().as_bytes()), s);
        }
        // Unknown / empty parse to None (fail-safe to "no recovery").
        assert_eq!(RecoveryState::from_bytes(b""), RecoveryState::None);
        assert_eq!(RecoveryState::from_bytes(b"garbage"), RecoveryState::None);

        // Only the in-progress lifecycle states gate value egress.
        for s in [
            RecoveryState::Tombstoning,
            RecoveryState::Succession,
            RecoveryState::Propagating,
            RecoveryState::Polling,
            RecoveryState::Resuming,
        ] {
            assert!(
                s.is_identity_recovery_in_progress(),
                "{s:?} must block egress"
            );
        }
        for s in [
            RecoveryState::None,
            RecoveryState::Complete,
            RecoveryState::Failed,
        ] {
            assert!(
                !s.is_identity_recovery_in_progress(),
                "{s:?} must not block egress via the in-progress gate"
            );
        }
    }

    #[test]
    #[serial]
    fn test_value_egress_gate_blocks_during_recovery() {
        setup_test_db();

        // No recovery in progress: egress is allowed.
        assert_eq!(recovery_state(), RecoveryState::None);
        assert!(value_egress_block_reason().is_none());
        assert!(precheck_value_egress().is_ok());

        // Each in-progress phase blocks value egress (fail-closed).
        for s in [
            RecoveryState::Tombstoning,
            RecoveryState::Succession,
            RecoveryState::Propagating,
            RecoveryState::Polling,
            RecoveryState::Resuming,
        ] {
            set_recovery_state(s).expect("set state");
            assert_eq!(recovery_state(), s);
            assert!(value_egress_block_reason().is_some(), "{s:?} must block");
            assert!(precheck_value_egress().is_err(), "{s:?} must block");
        }

        // Terminal states do not block via this in-progress gate; the
        // post-completion successor freeze + per-asset LOCKED_RECOVERY checks
        // land with the identity activation seal (Phase 4) and bearer-asset
        // reconciliation (Phase 5).
        for s in [
            RecoveryState::Complete,
            RecoveryState::Failed,
            RecoveryState::None,
        ] {
            set_recovery_state(s).expect("set state");
            assert!(
                value_egress_block_reason().is_none(),
                "{s:?} must not block via the in-progress gate"
            );
        }
    }

    #[test]
    #[serial]
    fn test_capsule_currency_dirty_tracking() {
        setup_test_db();

        // Fresh: no transitions, no seals → current (not dirty).
        assert_eq!(accepted_state_index(), 0);
        assert_eq!(capsule_state_index(), 0);
        assert!(!is_capsule_dirty());

        // Accepted transitions advance the accepted-state index → dirty.
        assert_eq!(bump_accepted_state_index().expect("bump"), 1);
        assert_eq!(bump_accepted_state_index().expect("bump"), 2);
        assert_eq!(accepted_state_index(), 2);
        assert!(is_capsule_dirty());

        // Sealing a capsule that captured index 2 clears dirty.
        set_capsule_state_index(2).expect("seal");
        assert!(!is_capsule_dirty());

        // A further accepted transition re-dirties.
        assert_eq!(bump_accepted_state_index().expect("bump"), 3);
        assert!(is_capsule_dirty());

        // A seal that only captured an older index does NOT clear dirty.
        set_capsule_state_index(2).expect("stale seal");
        assert!(is_capsule_dirty());
    }

    #[test]
    #[serial]
    fn test_r2prime_dirty_capsule_blocks_egress_only_when_recovery_enabled() {
        setup_test_db();
        set_recovery_state(RecoveryState::None).expect("state");

        // Make the capsule dirty (an accepted transition occurred, not yet sealed).
        bump_accepted_state_index().expect("bump");
        assert!(is_capsule_dirty());

        // Recovery NOT enabled: a dirty capsule does not gate egress — there is no
        // recovery contract for this device.
        assert!(!is_nfc_backup_enabled());
        assert!(value_egress_block_reason().is_none());

        // Recovery enabled + dirty capsule: egress is refused (R2′).
        set_nfc_backup_enabled(true).expect("enable");
        assert!(value_egress_block_reason().is_some());
        assert!(precheck_value_egress().is_err());

        // Sealing the latest accepted state clears the block.
        set_capsule_state_index(accepted_state_index()).expect("seal");
        assert!(!is_capsule_dirty());
        assert!(value_egress_block_reason().is_none());
        assert!(precheck_value_egress().is_ok());
    }

    #[test]
    #[serial]
    fn test_bump_accepted_state_index_with_conn_increments_atomically() {
        setup_test_db();
        assert_eq!(accepted_state_index(), 0);
        {
            // Mirrors the dual-write path: bump using the same connection that
            // owns the transaction (never opening a new one).
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            assert_eq!(
                bump_accepted_state_index_with_conn(&conn).expect("bump1"),
                1
            );
            assert_eq!(
                bump_accepted_state_index_with_conn(&conn).expect("bump2"),
                2
            );
        } // release the connection lock before reading via a fresh connection
        assert_eq!(accepted_state_index(), 2);
    }

    #[test]
    #[serial]
    fn test_recovered_successor_frozen_until_activated() {
        setup_test_db();
        set_recovery_state(RecoveryState::None).expect("state");

        // Normal (non-recovered) device: the successor-freeze branch does not apply.
        assert!(!is_recovered_successor());
        assert!(value_egress_block_reason().is_none());

        // A recovery successor that has not been activated is spend-frozen (T4.4).
        set_recovered_successor(true).expect("mark successor");
        assert!(is_recovered_successor());
        assert!(!is_recovery_activated());
        assert!(value_egress_block_reason().is_some());
        assert!(precheck_value_egress().is_err());

        // Only after a valid activation seal is recorded is egress permitted.
        set_recovery_activated(true).expect("activate");
        assert!(is_recovery_activated());
        assert!(value_egress_block_reason().is_none());
        assert!(precheck_value_egress().is_ok());
    }

    #[test]
    #[serial]
    fn test_resume_tip_diverges_from_floor() {
        setup_test_db();
        let cp = [0xC1u8; 32];
        let floor_tip = [0xF0u8; 32];

        // No floor staged for this counterparty → never reported as divergent.
        assert!(!resume_tip_diverges_from_floor(&cp, &floor_tip).expect("no floor"));

        store_recovered_chain_tips(&[RecoveredChainTip {
            device_id: cp,
            height: 7,
            head_hash: floor_tip,
        }])
        .expect("stage floor");

        // Tip confirming the floor is accepted.
        assert!(!resume_tip_diverges_from_floor(&cp, &floor_tip).expect("confirm"));
        // A different tip for a staged counterparty is a rollback/divergence.
        assert!(resume_tip_diverges_from_floor(&cp, &[0x11u8; 32]).expect("diverge"));
        // A counterparty without a staged floor is not gated here.
        assert!(!resume_tip_diverges_from_floor(&[0xC2u8; 32], &[0x11u8; 32]).expect("other cp"));
    }

    #[test]
    #[serial]
    fn test_store_and_clear_recovered_chain_tips() {
        setup_test_db();

        let tips = vec![
            RecoveredChainTip {
                device_id: [1u8; 32],
                height: 7,
                head_hash: [2u8; 32],
            },
            RecoveredChainTip {
                device_id: [3u8; 32],
                height: 9,
                head_hash: [4u8; 32],
            },
        ];

        store_recovered_chain_tips(&tips).expect("store tips");
        let stored = get_recovered_chain_tips().expect("read tips");
        assert_eq!(stored, tips);

        clear_recovered_chain_tips().expect("clear tips");
        assert!(get_recovered_chain_tips().expect("read cleared").is_empty());
    }

    // ── P5 bearer-asset reconciliation ─────────────────────────────────────

    use dsm::types::operations::{Operation, TransactionMode};
    use dsm::types::token_types::Balance;

    fn transfer_of(token_id: &[u8], amount: u64) -> Operation {
        Operation::Transfer {
            to_device_id: vec![0xCC; 32],
            amount: Balance::from_state(amount, [0u8; 32]),
            token_id: token_id.to_vec(),
            policy_commit: [0u8; 32],
            mode: TransactionMode::Unilateral,
            nonce: vec![],
            verification: dsm::types::operations::VerificationType::Standard,
            pre_commit: None,
            recipient: vec![],
            to: vec![],
            message: String::new(),
            signature: vec![],
            authority_policy: None,
        }
    }

    #[test]
    #[serial]
    fn restored_asset_is_locked_and_blocks_egress() {
        setup_test_db();
        let tok = b"ERA";
        lock_restored_bearer_asset(tok).expect("lock");
        let lock = get_asset_lock(tok).expect("read").expect("present");
        assert_eq!(lock.state, BearerAssetLockState::LockedRecovery);
        // Egress of a LockedRecovery asset is refused.
        assert!(asset_egress_block_reason(&transfer_of(tok, 5)).is_some());
        // An UNTOUCHED asset (no lock entry) is not gated.
        assert!(asset_egress_block_reason(&transfer_of(b"OTHER", 5)).is_none());
    }

    #[test]
    #[serial]
    fn token_reconciliation_unlocks_or_reduces() {
        setup_test_db();
        let tok = b"ERA";
        lock_restored_bearer_asset(tok).expect("lock");

        // Verified frontier >= hint → Spendable → egress allowed.
        assert_eq!(
            reconcile_token_asset(tok, 100, 100).expect("reconcile"),
            BearerAssetLockState::Spendable
        );
        assert!(asset_egress_block_reason(&transfer_of(tok, 100)).is_none());

        // Verified frontier < hint → Reduced, capped at the verified amount.
        assert_eq!(
            reconcile_token_asset(tok, 100, 40).expect("reconcile"),
            BearerAssetLockState::Reduced
        );
        assert!(asset_egress_block_reason(&transfer_of(tok, 40)).is_none()); // within cap
        assert!(asset_egress_block_reason(&transfer_of(tok, 41)).is_some()); // exceeds cap
    }

    #[test]
    #[serial]
    fn dbtc_cannot_be_reconciled_via_generic_path() {
        setup_test_db();
        let dbtc = b"dBTC";
        lock_restored_bearer_asset(dbtc).expect("lock");
        let lock = get_asset_lock(dbtc).expect("read").expect("present");
        assert!(lock.is_dbtc, "dBTC must be auto-flagged");
        // Generic reconciliation is refused with MissingDbtcFrontierReplay.
        let err = reconcile_token_asset(dbtc, 100, 100)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MissingDbtcFrontierReplay"), "got: {err}");
        // dBTC stays LockedRecovery → egress still blocked.
        assert_eq!(
            get_asset_lock(dbtc).expect("read").expect("present").state,
            BearerAssetLockState::LockedRecovery
        );
        assert!(asset_egress_block_reason(&transfer_of(dbtc, 1)).is_some());
        // Lowercase / mixed-case variants are also treated as dBTC (conservative).
        assert!(is_dbtc_token_id(b"dbtc") && is_dbtc_token_id(b"DBTC"));
    }

    #[test]
    #[serial]
    fn corrupt_lock_state_fails_closed() {
        setup_test_db();
        let tok = b"ERA";
        // Write an invalid state tag (0) directly; the gate must fail closed (block).
        {
            let binding = get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            conn.execute(
                "INSERT INTO recovery_locked_assets(token_id, state, frontier_cap, is_dbtc)
                 VALUES (?1, 0, 0, 0)",
                params![tok.as_slice()],
            )
            .expect("insert corrupt");
        }
        assert!(get_asset_lock(tok).is_err(), "invalid tag must error");
        assert!(
            asset_egress_block_reason(&transfer_of(tok, 1)).is_some(),
            "corrupt lock state must fail closed (block egress)"
        );
    }

    #[test]
    #[serial]
    fn relock_does_not_clobber_reconciled_and_clear_resets() {
        setup_test_db();
        let tok = b"ERA";
        lock_restored_bearer_asset(tok).expect("lock");
        reconcile_token_asset(tok, 100, 100).expect("reconcile"); // → Spendable
                                                                  // Re-locking (e.g. resume re-run) must NOT clobber the reconciled Spendable state.
        lock_restored_bearer_asset(tok).expect("re-lock");
        assert_eq!(
            get_asset_lock(tok).expect("read").expect("present").state,
            BearerAssetLockState::Spendable
        );
        // A new cycle clears the registry → the asset is no longer reconciled (re-locks fresh).
        clear_asset_locks().expect("clear");
        assert!(get_asset_lock(tok).expect("read").is_none());
        lock_restored_bearer_asset(tok).expect("re-lock fresh");
        assert_eq!(
            get_asset_lock(tok).expect("read").expect("present").state,
            BearerAssetLockState::LockedRecovery
        );
    }

    #[test]
    #[serial]
    fn unidentified_egress_blocked_only_while_locks_present() {
        setup_test_db();
        // A vault-keyed DLV claim cannot name its asset.
        let claim = Operation::DlvClaim {
            vault_id: vec![1, 2, 3],
            claim_proof: vec![],
            claimant_public_key: vec![],
            signature: vec![],
            mode: TransactionMode::Unilateral,
        };
        // No locks present → allowed.
        assert!(asset_egress_block_reason(&claim).is_none());
        // A locked asset present → unidentified egress is blocked (fail-closed).
        lock_restored_bearer_asset(b"ERA").expect("lock");
        assert!(asset_egress_block_reason(&claim).is_some());
    }
}
