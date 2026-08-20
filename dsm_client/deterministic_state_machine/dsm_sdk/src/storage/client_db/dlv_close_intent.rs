// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable pre-claim intent for `dlv.close`.
//!
//! A close is a multi-step, externally-visible operation: it publishes a
//! discovery pointer, claims the vault's parent in the quorum register, and
//! only then commits the canonical close that makes the value spendable. A
//! crash between any two of those steps must not leave the vault wedged with
//! nobody able to say what was intended, and must not let a restart re-sign a
//! DIFFERENT claim for the same parent (the register compares exact bytes).
//!
//! So the intent — the exact bytes this device will publish, claim and advance
//! — is written BEFORE anything external happens, and recovery resumes from it.
//!
//! RECOVERY ORCHESTRATION ONLY, NEVER AUTHORITY. This row never decides that a
//! vault is closed: the canonical state does. Recovery re-establishes the
//! storage-set invariant, re-runs the claim with the SAME frozen bytes, and
//! either completes the canonical close or abandons — it never infers closure
//! from a published pointer or a held claim.
//!
//! Terminal publication is likewise NOT a state here: "published" is derived
//! from the five terminal artifacts in `frozen_publication_artifact`.
//!
//! No clock columns: ordering is by the local monotonic insertion ordinal.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;

/// Where a close sits between "decided" and "canonically committed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseIntentState {
    /// The bytes are frozen; the pointer/claim may or may not have landed.
    PreparedClose,
    /// A quorum of the vault's storage set accepted this claim.
    ClaimPublished,
    /// The canonical close advance committed: the value is spendable and the
    /// terminal artifacts are frozen. Nothing left but publication.
    CanonicalCloseCommitted,
    /// Contested, or the advance was refused (the owner reconciled meanwhile).
    /// Terminal: the vault stays open and encumbered.
    Abandoned,
}

impl CloseIntentState {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseIntentState::PreparedClose => "prepared_close",
            CloseIntentState::ClaimPublished => "claim_published",
            CloseIntentState::CanonicalCloseCommitted => "canonical_close_committed",
            CloseIntentState::Abandoned => "abandoned",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "claim_published" => CloseIntentState::ClaimPublished,
            "canonical_close_committed" => CloseIntentState::CanonicalCloseCommitted,
            "abandoned" => CloseIntentState::Abandoned,
            // Unknown ⇒ least-committed: resume from the safe pre-commit point.
            _ => CloseIntentState::PreparedClose,
        }
    }
}

/// One close in flight (or terminal), with the exact bytes it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseIntent {
    pub vault_id: [u8; 32],
    pub parent_sequence: u64,
    pub state: CloseIntentState,
    /// The signed canonical `Operation::DlvClose`, byte-for-byte.
    pub op_bytes: Vec<u8>,
    /// The deterministic close commitment naming this close in the slot.
    pub x_close: [u8; 32],
    /// The discovery pointer this close publishes, and where.
    pub pointer_key: String,
    pub pointer_bytes: Vec<u8>,
    /// The vault's birth-bound storage set, as VERIFIED at decision time.
    pub storage_set_id: [u8; 32],
    pub insertion_ordinal: i64,
}

/// Write the intent before anything external happens. Idempotent per
/// `(vault_id, parent_sequence)`: a retry of the same close reuses the first
/// row.
///
/// The claim envelope is deliberately NOT stored here. It lives in exactly one
/// place — `settlement_slot_claim_local` — reachable only through
/// `FrozenClaimEnvelope::load`, so there is never a second copy that could
/// disagree with it or be submitted in its place.
pub fn put_intent_with_conn(conn: &Connection, intent: &CloseIntent) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO dlv_close_intent
            (vault_id, parent_sequence, state, op_bytes, x_close,
             pointer_key, pointer_bytes, storage_set_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            intent.vault_id.as_slice(),
            intent.parent_sequence as i64,
            intent.state.as_str(),
            intent.op_bytes,
            intent.x_close.as_slice(),
            intent.pointer_key,
            intent.pointer_bytes,
            intent.storage_set_id.as_slice(),
        ],
    )?;
    Ok(())
}

/// Same, on the shared connection.
pub fn put_intent(intent: &CloseIntent) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    put_intent_with_conn(&conn, intent)
}

/// Advance the intent's state. `abandoned` and `canonical_close_committed` are
/// terminal: neither regresses.
pub fn set_state_with_conn(
    conn: &Connection,
    vault_id: &[u8; 32],
    parent_sequence: u64,
    state: CloseIntentState,
) -> Result<bool> {
    let n = conn.execute(
        "UPDATE dlv_close_intent SET state = ?3
          WHERE vault_id = ?1 AND parent_sequence = ?2
            AND state NOT IN ('abandoned', 'canonical_close_committed')",
        params![vault_id.as_slice(), parent_sequence as i64, state.as_str()],
    )?;
    Ok(n > 0)
}

pub fn set_state(
    vault_id: &[u8; 32],
    parent_sequence: u64,
    state: CloseIntentState,
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    set_state_with_conn(&conn, vault_id, parent_sequence, state)
}

fn row_to_intent(r: &rusqlite::Row<'_>) -> rusqlite::Result<CloseIntent> {
    let fixed = |v: Vec<u8>| -> [u8; 32] {
        let mut o = [0u8; 32];
        if v.len() == 32 {
            o.copy_from_slice(&v);
        }
        o
    };
    Ok(CloseIntent {
        vault_id: fixed(r.get::<_, Vec<u8>>(0)?),
        parent_sequence: r.get::<_, i64>(1)? as u64,
        state: CloseIntentState::from_str(&r.get::<_, String>(2)?),
        op_bytes: r.get(3)?,
        x_close: fixed(r.get::<_, Vec<u8>>(4)?),
        pointer_key: r.get(5)?,
        pointer_bytes: r.get(6)?,
        storage_set_id: fixed(r.get::<_, Vec<u8>>(7)?),
        insertion_ordinal: r.get(8)?,
    })
}

const COLS: &str = "vault_id, parent_sequence, state, op_bytes, x_close, \
                    pointer_key, pointer_bytes, storage_set_id, insertion_ordinal";

pub fn get_intent(vault_id: &[u8; 32], parent_sequence: u64) -> Result<Option<CloseIntent>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM dlv_close_intent
                  WHERE vault_id = ?1 AND parent_sequence = ?2"
            ),
            params![vault_id.as_slice(), parent_sequence as i64],
            row_to_intent,
        )
        .optional()?;
    Ok(row)
}

/// Every close that has not reached a terminal state, oldest first — the work
/// list recovery resumes from.
pub fn list_unfinished_intents() -> Result<Vec<CloseIntent>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM dlv_close_intent
          WHERE state IN ('prepared_close', 'claim_published')
          ORDER BY insertion_ordinal ASC"
    ))?;
    let rows = stmt
        .query_map([], row_to_intent)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn intent(v: u8, seq: u64) -> CloseIntent {
        CloseIntent {
            vault_id: [v; 32],
            parent_sequence: seq,
            state: CloseIntentState::PreparedClose,
            op_bytes: b"signed-op".to_vec(),
            x_close: [0xC1; 32],
            pointer_key: "sofi/vault-pending/V/1/X".to_string(),
            pointer_bytes: b"pointer".to_vec(),
            storage_set_id: [0x6B; 32],
            insertion_ordinal: 0,
        }
    }

    fn init() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
    }

    #[test]
    #[serial]
    fn the_first_bytes_are_the_intent_and_a_retry_never_replaces_them() {
        init();
        let a = intent(0x11, 3);
        put_intent(&a).unwrap();
        let mut b = a.clone();
        b.op_bytes = b"DIFFERENT".to_vec();
        put_intent(&b).unwrap();
        let got = get_intent(&[0x11; 32], 3).unwrap().expect("row");
        assert_eq!(got.op_bytes, b"signed-op".to_vec());
        assert_eq!(got.state, CloseIntentState::PreparedClose);
    }

    #[test]
    #[serial]
    fn state_advances_forward_only_and_terminal_states_stick() {
        init();
        put_intent(&intent(0x22, 1)).unwrap();
        assert!(set_state(&[0x22; 32], 1, CloseIntentState::ClaimPublished).unwrap());
        assert!(set_state(&[0x22; 32], 1, CloseIntentState::CanonicalCloseCommitted).unwrap());
        // Terminal: no further transition, in either direction.
        assert!(!set_state(&[0x22; 32], 1, CloseIntentState::Abandoned).unwrap());
        assert!(!set_state(&[0x22; 32], 1, CloseIntentState::PreparedClose).unwrap());
        assert_eq!(
            get_intent(&[0x22; 32], 1).unwrap().unwrap().state,
            CloseIntentState::CanonicalCloseCommitted
        );
        // Committed and abandoned closes are not resumable work.
        put_intent(&intent(0x33, 1)).unwrap();
        assert!(set_state(&[0x33; 32], 1, CloseIntentState::Abandoned).unwrap());
        put_intent(&intent(0x44, 7)).unwrap();
        let open: Vec<[u8; 32]> = list_unfinished_intents()
            .unwrap()
            .into_iter()
            .map(|i| i.vault_id)
            .collect();
        assert_eq!(open, vec![[0x44u8; 32]], "only unfinished closes resume");
    }
}
