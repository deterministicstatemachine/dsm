// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic bilateral chain tip synchronization.
//!
//! Non-negotiable invariant: for every successful tip mutation, persisted
//! `chain_tip == local_bilateral_chain_tip`, both written in the same
//! committed SQLite transaction. No caller outside this module may perform
//! follow-up writes to "finish" a repair.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::{get_connection, ObservedRemoteTipRecord, ObservedRemoteTipSource};

// ── Types ─────────────────────────────────────────────────────────────────

/// Request to advance or repair bilateral chain tips atomically.
#[derive(Debug, Clone)]
pub struct TipSyncRequest {
    pub counterparty_device_id: [u8; 32],
    pub expected_parent_tip: [u8; 32],
    pub target_tip: [u8; 32],
}

/// Outcome of an atomic tip sync operation.
#[derive(Debug, Clone)]
pub enum TipSyncOutcome {
    /// Canonical was at expected_parent; both tips advanced to target in one tx.
    Advanced { new_tip: [u8; 32] },
    /// Canonical was already at target, local was stale — repaired in same tx.
    RepairedAtTarget { tip: [u8; 32] },
    /// Both tips already equal target. No mutation needed.
    AlreadyAtTarget { tip: [u8; 32] },
    /// Canonical is not at expected_parent (still behind or at a different value).
    ParentMismatch { current_tip: [u8; 32] },
    /// Canonical already moved, but not to the requested target.
    CanonicalMovedToDifferentTip { current_tip: [u8; 32] },
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
    sync_projection_with_optional_acceptance(request, None)
}

/// §16.6: synchronize the `contacts.chain_tip` PROJECTION and insert the
/// immutable `accepted_transition` marker in ONE client-db transaction.
///
/// The name is deliberate — this is PROJECTION synchronization, not a second
/// canonical state transition. The canonical relationship tip already committed
/// inside the full-state apply transaction; parent/child here come from the
/// durable `CanonicalApplyRecord`, never derived from the projection. This
/// function must NOT create BCR state, recompute a successor, touch balances,
/// or mutate the authenticated `DeviceState`. Semantics:
///   projection == record.parent → update to record.child → insert/check marker
///   projection == record.child  → already synchronized  → insert/check marker (idempotent)
///   projection == third value   → fail closed (no writes) → reconciliation
/// The marker insert runs in the SAME transaction on both committing cases; an
/// existing DIFFERENT marker for the consumed parent aborts the whole tx.
pub fn sync_tip_projection_and_record_acceptance_atomic(
    request: &TipSyncRequest,
    marker: &super::recipient_receipt_fold::AcceptedTransition,
) -> Result<TipSyncOutcome> {
    sync_projection_with_optional_acceptance(request, Some(marker))
}

fn sync_projection_with_optional_acceptance(
    request: &TipSyncRequest,
    acceptance: Option<&super::recipient_receipt_fold::AcceptedTransition>,
) -> Result<TipSyncOutcome> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let tx = conn.transaction()?;
    let outcome = sync_tip_projections_in_tx(&tx, request, acceptance)?;
    match outcome {
        TipSyncOutcome::Advanced { .. }
        | TipSyncOutcome::RepairedAtTarget { .. }
        | TipSyncOutcome::AlreadyAtTarget { .. } => {
            tx.commit()?;
        }
        _ => {
            // Non-committing outcome — nothing may persist (marker included).
            tx.rollback().ok();
        }
    }
    Ok(outcome)
}

/// The single transactional impl — ONE copy of the CAS logic; both public APIs
/// delegate here (no cloned CAS to drift). PROJECTION-ONLY: touches
/// `contacts.chain_tip` / `local_bilateral_chain_tip` / the pending gate /
/// the acceptance marker — never BCR state, balances, or `DeviceState`.
/// Performs NO commit/rollback; the wrapper commits only the committing
/// outcomes (`Advanced` / `RepairedAtTarget` / `AlreadyAtTarget`).
pub(crate) fn sync_tip_projections_in_tx(
    tx: &rusqlite::Transaction<'_>,
    request: &TipSyncRequest,
    acceptance: Option<&super::recipient_receipt_fold::AcceptedTransition>,
) -> Result<TipSyncOutcome> {
    // Step 1: Load current bilateral row
    let (chain_tip, local_tip, observed_remote_tip, observed_remote_tip_source): (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<i64>,
    ) = {
        let mut stmt = tx.prepare(
            "SELECT chain_tip, local_bilateral_chain_tip, observed_remote_chain_tip, observed_remote_tip_source
               FROM contacts WHERE device_id = ?1",
        )?;
        match stmt.query_row(params![&request.counterparty_device_id[..]], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<i64>>(3)?,
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

    let observed_remote_tip_record = match observed_remote_tip {
        Some(tip) if tip.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&tip);
            Some(ObservedRemoteTipRecord {
                tip: arr,
                updated_at: 0,
                source: ObservedRemoteTipSource::from_db(observed_remote_tip_source),
            })
        }
        Some(tip) => {
            return Ok(TipSyncOutcome::InvariantViolation {
                message: format!(
                    "observed_remote_chain_tip is {} bytes, expected 32",
                    tip.len()
                ),
            });
        }
        None => None,
    };

    // Step 3: Branch on canonical/local state
    let target = &request.target_tip;
    let parent = &request.expected_parent_tip;
    let clear_observed_tip_on_success =
        should_clear_observed_tip_after_success(observed_remote_tip_record.as_ref(), target);

    let outcome = if chain_tip_arr == *target {
        // Case A: canonical already at target
        if local_tip_arr == *target {
            // Both already aligned — no mutation needed
            clear_observed_remote_tip_in_tx(
                tx,
                &request.counterparty_device_id,
                clear_observed_tip_on_success,
            )?;
            TipSyncOutcome::AlreadyAtTarget { tip: *target }
        } else {
            // Canonical at target but local is stale — repair local
            tx.execute(
                "UPDATE contacts
                    SET local_bilateral_chain_tip = ?1,
                        needs_online_reconcile = 0
                  WHERE device_id = ?2",
                params![&target[..], &request.counterparty_device_id[..]],
            )?;
            clear_observed_remote_tip_in_tx(
                tx,
                &request.counterparty_device_id,
                clear_observed_tip_on_success,
            )?;
            TipSyncOutcome::RepairedAtTarget { tip: *target }
        }
    } else if chain_tip_arr == *parent || (chain_tip_arr == [0u8; 32] && *parent == [0u8; 32]) {
        // Case B: canonical at expected parent — advance both atomically
        let tick_val = crate::util::deterministic_time::tick() as i64;
        tx.execute(
            "UPDATE contacts SET \
                previous_chain_tip = chain_tip, \
                chain_tip = ?1, \
                local_bilateral_chain_tip = ?1, \
                needs_online_reconcile = 0, \
                last_seen_online_counter = ?2 \
             WHERE device_id = ?3",
            params![&target[..], tick_val, &request.counterparty_device_id[..]],
        )?;
        clear_observed_remote_tip_in_tx(
            tx,
            &request.counterparty_device_id,
            clear_observed_tip_on_success,
        )?;
        TipSyncOutcome::Advanced { new_tip: *target }
    } else {
        // Case C: canonical is somewhere else — fail closed, no writes
        // (wrapper rolls back). Distinguish ParentMismatch from
        // CanonicalMovedToDifferentTip.
        if chain_tip_arr != [0u8; 32] && chain_tip_arr != *parent {
            return Ok(TipSyncOutcome::CanonicalMovedToDifferentTip {
                current_tip: chain_tip_arr,
            });
        }
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

    // §16.6 acceptance marker: SAME transaction, committing cases only (all
    // non-committing outcomes returned early above). Idempotent for an
    // identical existing marker; a DIFFERENT existing marker for this consumed
    // parent errors — the wrapper then rolls the whole tx back (fail closed,
    // the projection sync does not persist either).
    if let Some(marker) = acceptance {
        super::recipient_receipt_fold::record_accepted_transition_in_tx(tx, marker)?;
    }

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

fn should_clear_observed_tip_after_success(
    observed: Option<&ObservedRemoteTipRecord>,
    target_tip: &[u8; 32],
) -> bool {
    match observed {
        Some(record) if record.tip == *target_tip => true,
        Some(record) if !record.source.blocks_send_without_local_corroboration() => true,
        _ => false,
    }
}

fn clear_observed_remote_tip_in_tx(
    tx: &rusqlite::Transaction<'_>,
    counterparty_device_id: &[u8; 32],
    should_clear: bool,
) -> Result<()> {
    if !should_clear {
        return Ok(());
    }

    tx.execute(
        "UPDATE contacts
            SET observed_remote_chain_tip = NULL,
                observed_remote_tip_updated_at = NULL,
                observed_remote_tip_source = NULL
          WHERE device_id = ?1",
        params![&counterparty_device_id[..]],
    )?;
    Ok(())
}
