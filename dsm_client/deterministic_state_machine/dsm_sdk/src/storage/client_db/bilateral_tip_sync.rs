// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic bilateral chain tip synchronization and stale-gate clearing.
//!
//! Non-negotiable invariant: for every successful tip mutation, persisted
//! `chain_tip == local_bilateral_chain_tip`, both written in the same
//! committed SQLite transaction. No caller outside this module may perform
//! follow-up writes to "finish" a repair.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;

// ── Types ─────────────────────────────────────────────────────────────────

/// Identity of an observed pending online gate. Used for exact-match delete
/// to prevent TOCTOU races where a BLE cleanup could delete a newer gate.
#[derive(Debug, Clone)]
pub struct ObservedPendingGate {
    pub counterparty_device_id: [u8; 32],
    pub parent_tip: [u8; 32],
    pub next_tip: [u8; 32],
}

/// Request to advance or repair bilateral chain tips atomically.
#[derive(Debug, Clone)]
pub struct TipSyncRequest {
    pub counterparty_device_id: [u8; 32],
    pub expected_parent_tip: [u8; 32],
    pub target_tip: [u8; 32],
    /// If supplied, the helper validates this exact gate exists before clearing.
    pub observed_gate: Option<ObservedPendingGate>,
    /// If true, clear the exact observed gate on success outcomes only.
    pub clear_gate_on_success: bool,
}

/// Outcome of an atomic tip sync operation.
#[derive(Debug, Clone)]
pub enum TipSyncOutcome {
    /// Canonical was at expected_parent; both tips advanced to target in one tx.
    Advanced {
        new_tip: [u8; 32],
        gate_cleared: bool,
    },
    /// Canonical was already at target, local was stale — repaired in same tx.
    RepairedAtTarget { tip: [u8; 32], gate_cleared: bool },
    /// Both tips already equal target. No mutation needed.
    AlreadyAtTarget { tip: [u8; 32], gate_cleared: bool },
    /// Canonical is not at expected_parent (still behind or at a different value).
    ParentMismatch { current_tip: [u8; 32] },
    /// Canonical already moved, but not to the requested target.
    CanonicalMovedToDifferentTip { current_tip: [u8; 32] },
    /// Supplied observed gate does not match persisted gate.
    GateMismatch,
    /// Persisted state is malformed or helper detected impossible state.
    InvariantViolation { message: String },
}

/// Outcome of atomically recording a new pending online gate.
#[derive(Debug, Clone)]
pub enum RecordPendingGateOutcome {
    /// New gate inserted.
    Recorded,
    /// Identical gate already exists (idempotent).
    AlreadyExistsSameGate,
    /// A different gate for this counterparty already exists.
    ConflictingGateExists,
    /// chain_tip != expected_parent — cannot create gate.
    ParentMismatch { current_tip: [u8; 32] },
}

// ── Atomic tip sync ───────────────────────────────────────────────────────

/// The sole success path for bilateral tip repair/advance.
///
/// One SQLite write transaction. On success, guaranteed postcondition:
/// `chain_tip == local_bilateral_chain_tip == target_tip`.
///
/// No caller outside this function may write to bilateral tip columns.
pub fn sync_bilateral_tips_atomically(request: &TipSyncRequest) -> Result<TipSyncOutcome> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let tx = conn.transaction()?;

    // Step 1: Load current bilateral row
    let (chain_tip, local_tip): (Vec<u8>, Vec<u8>) = {
        let mut stmt = tx.prepare(
            "SELECT chain_tip, local_bilateral_chain_tip FROM contacts WHERE device_id = ?1",
        )?;
        match stmt.query_row(params![&request.counterparty_device_id[..]], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
            ))
        }) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Ok(TipSyncOutcome::InvariantViolation {
                    message: "No contact row for counterparty".to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        }
    };

    let chain_tip_arr: [u8; 32] = match chain_tip.as_slice().try_into() {
        Ok(a) => a,
        Err(_) if chain_tip.is_empty() || chain_tip == vec![0u8; 32] => [0u8; 32],
        Err(_) => {
            return Ok(TipSyncOutcome::InvariantViolation {
                message: format!("chain_tip is {} bytes, expected 32", chain_tip.len()),
            });
        }
    };

    let local_tip_arr: [u8; 32] = match local_tip.as_slice().try_into() {
        Ok(a) => a,
        Err(_) if local_tip.is_empty() || local_tip == vec![0u8; 32] => [0u8; 32],
        Err(_) => {
            return Ok(TipSyncOutcome::InvariantViolation {
                message: format!(
                    "local_bilateral_chain_tip is {} bytes, expected 32",
                    local_tip.len()
                ),
            });
        }
    };

    // Step 2: Validate observed gate if supplied
    let gate_matched = if let Some(ref observed) = request.observed_gate {
        let persisted: Option<(Vec<u8>, Vec<u8>)> = tx
            .prepare(
                "SELECT parent_tip, next_tip FROM pending_online_outbox WHERE counterparty_device_id = ?1",
            )?
            .query_row(params![&observed.counterparty_device_id[..]], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                ))
            })
            .optional()?;

        match persisted {
            Some((p_parent, p_next)) => {
                if p_parent.as_slice() == &observed.parent_tip[..]
                    && p_next.as_slice() == &observed.next_tip[..]
                {
                    true // exact match
                } else {
                    // Gate exists but different values — mismatch
                    tx.rollback().ok();
                    return Ok(TipSyncOutcome::GateMismatch);
                }
            }
            None => {
                // No gate persisted — can't match, but this is not an error
                // if clear_gate_on_success is false. If it is true, we simply
                // won't clear anything (gate already gone).
                false
            }
        }
    } else {
        false
    };

    // Step 3: Branch on canonical/local state
    let target = &request.target_tip;
    let parent = &request.expected_parent_tip;

    let outcome = if chain_tip_arr == *target {
        // Case A: canonical already at target
        if local_tip_arr == *target {
            // Both already aligned — no mutation needed
            let gc = if request.clear_gate_on_success && gate_matched {
                clear_gate_in_tx(
                    &tx,
                    &request.counterparty_device_id,
                    request.observed_gate.as_ref(),
                )?
            } else {
                false
            };
            TipSyncOutcome::AlreadyAtTarget {
                tip: *target,
                gate_cleared: gc,
            }
        } else {
            // Canonical at target but local is stale — repair local
            tx.execute(
                "UPDATE contacts SET local_bilateral_chain_tip = ?1 WHERE device_id = ?2",
                params![&target[..], &request.counterparty_device_id[..]],
            )?;
            let gc = if request.clear_gate_on_success && gate_matched {
                clear_gate_in_tx(
                    &tx,
                    &request.counterparty_device_id,
                    request.observed_gate.as_ref(),
                )?
            } else {
                false
            };
            TipSyncOutcome::RepairedAtTarget {
                tip: *target,
                gate_cleared: gc,
            }
        }
    } else if chain_tip_arr == *parent || (chain_tip_arr == [0u8; 32] && *parent == [0u8; 32]) {
        // Case B: canonical at expected parent — advance both atomically
        let tick_val = crate::util::deterministic_time::tick() as i64;
        tx.execute(
            "UPDATE contacts SET \
                previous_chain_tip = chain_tip, \
                chain_tip = ?1, \
                local_bilateral_chain_tip = ?1, \
                observed_remote_chain_tip = NULL, \
                observed_remote_tip_updated_at = NULL, \
                needs_online_reconcile = 0, \
                last_seen_online_counter = ?2 \
             WHERE device_id = ?3",
            params![&target[..], tick_val, &request.counterparty_device_id[..]],
        )?;
        let gc = if request.clear_gate_on_success && gate_matched {
            clear_gate_in_tx(
                &tx,
                &request.counterparty_device_id,
                request.observed_gate.as_ref(),
            )?
        } else {
            false
        };
        TipSyncOutcome::Advanced {
            new_tip: *target,
            gate_cleared: gc,
        }
    } else {
        // Case C: canonical is somewhere else
        // Distinguish ParentMismatch from CanonicalMovedToDifferentTip
        if chain_tip_arr != [0u8; 32] && chain_tip_arr != *parent {
            tx.rollback().ok();
            return Ok(TipSyncOutcome::CanonicalMovedToDifferentTip {
                current_tip: chain_tip_arr,
            });
        }
        tx.rollback().ok();
        return Ok(TipSyncOutcome::ParentMismatch {
            current_tip: chain_tip_arr,
        });
    };

    // Postcondition assertion (debug builds)
    #[cfg(debug_assertions)]
    {
        if matches!(
            outcome,
            TipSyncOutcome::Advanced { .. } | TipSyncOutcome::RepairedAtTarget { .. }
        ) {
            let check: (Vec<u8>, Vec<u8>) = tx
                .prepare("SELECT chain_tip, local_bilateral_chain_tip FROM contacts WHERE device_id = ?1")?
                .query_row(params![&request.counterparty_device_id[..]], |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                        row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
                    ))
                })?;
            assert_eq!(
                check.0, check.1,
                "sync_bilateral_tips_atomically postcondition violated: chain_tip != local_bilateral_chain_tip"
            );
        }
    }

    tx.commit()?;
    Ok(outcome)
}

/// Atomically record a new pending online gate. One SQLite write transaction.
/// Only inserts if chain_tip == expected_parent and no conflicting gate exists.
pub fn record_pending_online_transition_atomically(
    counterparty_device_id: &[u8; 32],
    expected_parent_tip: &[u8; 32],
    next_tip: &[u8; 32],
    message_id: &str,
    payload: &[u8],
) -> Result<RecordPendingGateOutcome> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let tx = conn.transaction()?;

    // Step 1: Read current chain_tip
    let chain_tip: Vec<u8> = tx
        .prepare("SELECT chain_tip FROM contacts WHERE device_id = ?1")?
        .query_row(params![&counterparty_device_id[..]], |row| {
            Ok(row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default())
        })
        .unwrap_or_default();

    let chain_tip_arr: [u8; 32] = chain_tip.as_slice().try_into().unwrap_or([0u8; 32]);

    if chain_tip_arr != *expected_parent_tip {
        tx.rollback().ok();
        return Ok(RecordPendingGateOutcome::ParentMismatch {
            current_tip: chain_tip_arr,
        });
    }

    // Step 2: Check existing gate
    let existing: Option<(Vec<u8>, Vec<u8>)> = tx
        .prepare("SELECT parent_tip, next_tip FROM pending_online_outbox WHERE counterparty_device_id = ?1")?
        .query_row(params![&counterparty_device_id[..]], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .optional()?;

    match existing {
        Some((p, n))
            if p.as_slice() == &expected_parent_tip[..] && n.as_slice() == &next_tip[..] =>
        {
            tx.rollback().ok();
            return Ok(RecordPendingGateOutcome::AlreadyExistsSameGate);
        }
        Some(_) => {
            tx.rollback().ok();
            return Ok(RecordPendingGateOutcome::ConflictingGateExists);
        }
        None => {}
    }

    // Step 3: Insert new gate
    let tick_val = crate::util::deterministic_time::tick() as i64;
    tx.execute(
        "INSERT INTO pending_online_outbox (counterparty_device_id, message_id, parent_tip, next_tip, payload, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &counterparty_device_id[..],
            message_id,
            &expected_parent_tip[..],
            &next_tip[..],
            payload,
            tick_val,
        ],
    )?;

    tx.commit()?;
    Ok(RecordPendingGateOutcome::Recorded)
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Delete the exact observed gate inside an existing transaction.
fn clear_gate_in_tx(
    tx: &rusqlite::Transaction<'_>,
    counterparty_device_id: &[u8; 32],
    observed: Option<&ObservedPendingGate>,
) -> Result<bool> {
    let Some(gate) = observed else {
        return Ok(false);
    };
    let rows = tx.execute(
        "DELETE FROM pending_online_outbox WHERE counterparty_device_id = ?1 AND parent_tip = ?2 AND next_tip = ?3",
        params![&counterparty_device_id[..], &gate.parent_tip[..], &gate.next_tip[..]],
    )?;
    Ok(rows > 0)
}
