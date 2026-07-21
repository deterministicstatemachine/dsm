// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical sender proposal (§16.6 proposal authority).
//!
//! ONE persisted record, written by the sender's online-send flow immediately
//! after the canonical advance, is the single authority feeding every
//! downstream artifact of that send:
//!
//!   - the signed receipt's parent/child (ASYMMETRIC canonical pair);
//!   - the pending online gate (SYMMETRIC projection pair);
//!   - the storage-node wire entry's routing metadata (SYMMETRIC pair);
//!   - ACK finalization (gate release keys off the proposal, not ad-hoc rows);
//!   - rollback and recovery.
//!
//! After canonical preparation begins, the sender NEVER rereads
//! `contacts.chain_tip` to stamp protocol artifacts — that column is a
//! display/discovery projection. The two formula-spaces live side by side here
//! ON PURPOSE: `canonical_*` is the DeviceState-embedded (asymmetric) lineage
//! the signed receipt carries; `projection_*` is the symmetric routing/
//! addressing lineage the gate and b0x addressing use. They must never be
//! compared across.
//!
//! Lifecycle: proposed → submitted → finalized | rolled_back.
//! A `proposed` row with no message_id after a crash is repaired (or rolled
//! back) by the startup proposal sweep from durable canonical evidence (BCR).

use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

pub const PROPOSAL_PROPOSED: &str = "proposed";
pub const PROPOSAL_SUBMITTED: &str = "submitted";
pub const PROPOSAL_FINALIZED: &str = "finalized";
pub const PROPOSAL_ROLLED_BACK: &str = "rolled_back";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderOnlineProposal {
    pub relationship_key: [u8; 32],
    /// ASYMMETRIC canonical parent the sender's advance consumed — what the
    /// signed receipt's `parent_tip` carries.
    pub canonical_parent: [u8; 32],
    /// ASYMMETRIC canonical child the advance produced — the receipt's
    /// `child_tip`.
    pub canonical_child: [u8; 32],
    /// SYMMETRIC projection parent (gate parent / wire `sender_chain_tip`).
    pub projection_parent: [u8; 32],
    /// SYMMETRIC projection successor (gate next / wire `next_chain_tip`).
    pub projection_target: [u8; 32],
    /// Receipt commitment (finalize binding for the returned countersigned
    /// artifact).
    pub commitment: [u8; 32],
    pub operation_digest: [u8; 32],
    pub nonce_hash: [u8; 32],
    /// b0x message id — set when the wire submission assigns it.
    pub message_id: Option<String>,
    pub tx_id: String,
    pub counterparty_device_id: [u8; 32],
    pub amount: u64,
    pub token_id: String,
    pub status: String,
    pub created_at: u64,
}

const COLS: &str = "relationship_key, canonical_parent, canonical_child, projection_parent, \
     projection_target, commitment, operation_digest, nonce_hash, message_id, tx_id, \
     counterparty_device_id, amount, token_id, status, created_at";

fn row_to_proposal(row: &rusqlite::Row) -> rusqlite::Result<SenderOnlineProposal> {
    let g = |i: usize| -> rusqlite::Result<Vec<u8>> { row.get::<_, Vec<u8>>(i) };
    let to32 = |v: Vec<u8>| -> [u8; 32] {
        let mut a = [0u8; 32];
        let n = v.len().min(32);
        a[..n].copy_from_slice(&v[..n]);
        a
    };
    Ok(SenderOnlineProposal {
        relationship_key: to32(g(0)?),
        canonical_parent: to32(g(1)?),
        canonical_child: to32(g(2)?),
        projection_parent: to32(g(3)?),
        projection_target: to32(g(4)?),
        commitment: to32(g(5)?),
        operation_digest: to32(g(6)?),
        nonce_hash: to32(g(7)?),
        message_id: row.get::<_, Option<String>>(8)?,
        tx_id: row.get::<_, String>(9)?,
        counterparty_device_id: to32(g(10)?),
        amount: row.get::<_, i64>(11)? as u64,
        token_id: row.get::<_, String>(12)?,
        status: row.get::<_, String>(13)?,
        created_at: row.get::<_, i64>(14)? as u64,
    })
}

/// Insert a fresh proposal (status `proposed`). Idempotent for the identical
/// identity; FAILS CLOSED if a DIFFERENT proposal already consumed this
/// (relationship, canonical_parent) — one canonical step yields exactly one
/// proposal.
pub fn insert_sender_proposal(p: &SenderOnlineProposal) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    insert_sender_proposal_with_conn(&conn, p)
}

/// Same insert, INSIDE a caller-owned transaction.
///
/// §16.6 defect zero: the proposal is committed together with the canonical
/// advance, the gate, the pending EK head, and the outbox row — one
/// transaction, before anything is deliverable. Takes `&Connection` (a
/// `&Transaction` derefs to one) and never calls `get_connection()`: the
/// advance already holds the single global connection mutex.
pub fn insert_sender_proposal_with_conn(
    conn: &rusqlite::Connection,
    p: &SenderOnlineProposal,
) -> Result<()> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT canonical_child, commitment FROM sender_online_proposal
             WHERE relationship_key = ?1 AND canonical_parent = ?2",
            params![p.relationship_key.as_slice(), p.canonical_parent.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((child, commitment)) = existing {
        if child.as_slice() == p.canonical_child.as_slice()
            && commitment.as_slice() == p.commitment.as_slice()
        {
            return Ok(()); // idempotent re-entry
        }
        return Err(anyhow!(
            "a DIFFERENT sender proposal already consumed this (relationship, canonical_parent) — \
             refusing a second proposal for one canonical step"
        ));
    }
    conn.execute(
        &format!(
            "INSERT INTO sender_online_proposal ({COLS}) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        ),
        params![
            p.relationship_key.as_slice(),
            p.canonical_parent.as_slice(),
            p.canonical_child.as_slice(),
            p.projection_parent.as_slice(),
            p.projection_target.as_slice(),
            p.commitment.as_slice(),
            p.operation_digest.as_slice(),
            p.nonce_hash.as_slice(),
            p.message_id.as_deref(),
            p.tx_id,
            p.counterparty_device_id.as_slice(),
            p.amount as i64,
            p.token_id,
            p.status,
            tick() as i64,
        ],
    )?;
    Ok(())
}

pub fn get_sender_proposal(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
) -> Result<Option<SenderOnlineProposal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    Ok(conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM sender_online_proposal \
                 WHERE relationship_key = ?1 AND canonical_parent = ?2"
            ),
            params![relationship_key.as_slice(), canonical_parent.as_slice()],
            row_to_proposal,
        )
        .optional()?)
}

pub fn get_sender_proposal_by_message_id(message_id: &str) -> Result<Option<SenderOnlineProposal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {COLS} FROM sender_online_proposal WHERE message_id = ?1"),
            params![message_id],
            row_to_proposal,
        )
        .optional()?)
}

/// Look up the proposal a returned acceptance receipt answers.
///
/// The commitment is the ONLY identifier shared by both sides of the reply
/// window: the recipient countersigns it and echoes it back, and the sender
/// bound it at canonical preparation. Matching on it (rather than on any tip)
/// keeps the lookup inside a single formula space.
pub fn get_sender_proposal_by_commitment(
    commitment: &[u8; 32],
) -> Result<Option<SenderOnlineProposal>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    Ok(conn
        .query_row(
            &format!("SELECT {COLS} FROM sender_online_proposal WHERE commitment = ?1"),
            params![commitment.as_slice()],
            row_to_proposal,
        )
        .optional()?)
}

/// Terminally finalize by canonical identity — the reply window keys off the
/// canonical step, not the wire message id. Idempotent: a second call after
/// finalization returns `Ok(false)`.
pub fn mark_sender_proposal_finalized_by_canonical(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_online_proposal SET status = ?3
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND status != ?3",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            PROPOSAL_FINALIZED
        ],
    )?;
    Ok(n > 0)
}

/// Bind the b0x message id and mark `submitted`. Refuses to rebind a DIFFERENT
/// id (one proposal = one wire submission identity).
pub fn mark_sender_proposal_submitted(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
    message_id: &str,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let existing: Option<Option<String>> = conn
        .query_row(
            "SELECT message_id FROM sender_online_proposal
             WHERE relationship_key = ?1 AND canonical_parent = ?2",
            params![relationship_key.as_slice(), canonical_parent.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        None => return Err(anyhow!("no sender proposal for this canonical step")),
        Some(Some(existing_id)) if existing_id != message_id => {
            return Err(anyhow!(
                "sender proposal already bound to a different message id — refusing rebind"
            ));
        }
        _ => {}
    }
    conn.execute(
        "UPDATE sender_online_proposal SET message_id = ?3, status = ?4
         WHERE relationship_key = ?1 AND canonical_parent = ?2",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            message_id,
            PROPOSAL_SUBMITTED,
        ],
    )?;
    Ok(())
}

/// Terminal transitions. `finalized` only from `submitted`; `rolled_back` from
/// any non-finalized state.
pub fn mark_sender_proposal_finalized(message_id: &str) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_online_proposal SET status = ?2
         WHERE message_id = ?1 AND status = ?3",
        params![message_id, PROPOSAL_FINALIZED, PROPOSAL_SUBMITTED],
    )?;
    Ok(n > 0)
}

pub fn mark_sender_proposal_rolled_back(
    relationship_key: &[u8; 32],
    canonical_parent: &[u8; 32],
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_online_proposal SET status = ?3
         WHERE relationship_key = ?1 AND canonical_parent = ?2 AND status != ?4",
        params![
            relationship_key.as_slice(),
            canonical_parent.as_slice(),
            PROPOSAL_ROLLED_BACK,
            PROPOSAL_FINALIZED,
        ],
    )?;
    Ok(n > 0)
}

/// Rollback marking by (relationship, tx_id) — the rollback path knows the
/// wallet transaction, not the canonical parent. Never touches `finalized`.
pub fn mark_sender_proposals_rolled_back_for_tx(
    relationship_key: &[u8; 32],
    tx_id: &str,
) -> Result<usize> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
    let n = conn.execute(
        "UPDATE sender_online_proposal SET status = ?3
         WHERE relationship_key = ?1 AND tx_id = ?2 AND status != ?4",
        params![
            relationship_key.as_slice(),
            tx_id,
            PROPOSAL_ROLLED_BACK,
            PROPOSAL_FINALIZED,
        ],
    )?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn fixture() -> SenderOnlineProposal {
        SenderOnlineProposal {
            relationship_key: [0x11u8; 32],
            canonical_parent: [0x22u8; 32],
            canonical_child: [0x33u8; 32],
            projection_parent: [0x44u8; 32],
            projection_target: [0x55u8; 32],
            commitment: [0x66u8; 32],
            operation_digest: [0x77u8; 32],
            nonce_hash: [0x88u8; 32],
            message_id: None,
            tx_id: "tx:test".into(),
            counterparty_device_id: [0x99u8; 32],
            amount: 15,
            token_id: "ERA".into(),
            status: PROPOSAL_PROPOSED.into(),
            created_at: 0,
        }
    }

    #[test]
    #[serial]
    fn proposal_lifecycle_and_one_per_canonical_step() {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().unwrap();
        let p = fixture();
        insert_sender_proposal(&p).unwrap();
        insert_sender_proposal(&p).unwrap(); // idempotent identical

        // A DIFFERENT proposal for the same canonical step fails closed.
        let mut p2 = fixture();
        p2.canonical_child = [0x3Au8; 32];
        assert!(insert_sender_proposal(&p2).is_err());

        // Submit binds the message id exactly once.
        mark_sender_proposal_submitted(&p.relationship_key, &p.canonical_parent, "MSG1").unwrap();
        assert!(
            mark_sender_proposal_submitted(&p.relationship_key, &p.canonical_parent, "MSG2")
                .is_err()
        );
        let loaded = get_sender_proposal_by_message_id("MSG1").unwrap().unwrap();
        assert_eq!(loaded.status, PROPOSAL_SUBMITTED);
        assert_eq!(loaded.canonical_child, p.canonical_child);

        // Finalize only from submitted; rolled_back refused after finalize.
        assert!(mark_sender_proposal_finalized("MSG1").unwrap());
        assert!(!mark_sender_proposal_finalized("MSG1").unwrap());
        assert!(
            !mark_sender_proposal_rolled_back(&p.relationship_key, &p.canonical_parent).unwrap()
        );
    }
}
