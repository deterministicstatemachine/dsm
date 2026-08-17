// SPDX-License-Identifier: MIT OR Apache-2.0
//! The ONE authority for a peer's canonical relationship head.
//!
//! A relationship chain tip is a per-device value: each side's local lineage
//! advances on BOTH its own sends and its applies of the peer's sends. So the
//! head a peer will sign under next is not derivable from what this device
//! applied — it must be learned from the peer, authenticated, on every
//! generation, and advanced from BOTH roles:
//!
//! - **inbound apply** (this device is recipient): the signed A pair
//!   `parent → child` — the sender's head advances to the child it signed;
//! - **sender finalize** (this device is sender): the delta's B pair
//!   `b_parent → b_child`, authenticated by `sig_b` (B-canonical target) —
//!   the recipient's head advances to the child it applied under.
//!
//! Every write is a compare-and-swap inside the caller's transaction:
//! `Advanced` (row at `expected` → `target`), `GenesisInit` (no row AND
//! `expected == genesis seed` — the relationship's first step from either
//! side), `AlreadyAtTarget` (the same step re-applied: tip AND source
//! commitment match — never a silent no-op for a different step at the same
//! tip), `Conflict { current }` (anything else; the caller aborts).
//!
//! The recipient's pin (`pinned_counterparty_a_head`) reads THIS table. The
//! history-derived query it replaced could not see the peer's head advance
//! while the peer was applying (the role-reversal failure) and forked at
//! generation three; this table is one lineage per relationship, advanced by
//! whichever role learned the next step.

use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

/// Outcome of one canonical-head compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasCanonicalHeadOutcome {
    /// Row was at `expected`; now at `target`.
    Advanced,
    /// No row existed and `expected` was the genesis seed; row created at `target`.
    GenesisInit,
    /// Row already at `target` for the SAME source commitment — the same step,
    /// re-applied. Idempotent success.
    AlreadyAtTarget,
    /// The row's current head is neither `expected` nor (`target` for this
    /// commitment). `current` is `None` when there is no row and `expected`
    /// was not the genesis seed.
    Conflict { current: Option<[u8; 32]> },
}

fn col32(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    let v: Vec<u8> = row.get(idx)?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

/// The peer's pinned canonical head for `relationship_key`, if any step has
/// been learned yet. `None` ⇔ no row (a fresh relationship under beta reset).
pub fn load_counterparty_canonical_head_with_conn(
    conn: &rusqlite::Connection,
    relationship_key: &[u8; 32],
) -> Result<Option<[u8; 32]>> {
    Ok(conn
        .query_row(
            "SELECT head_tip FROM counterparty_canonical_heads WHERE relationship_key = ?1",
            params![relationship_key.as_slice()],
            |r| col32(r, 0),
        )
        .optional()?)
}

pub fn load_counterparty_canonical_head(relationship_key: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    load_counterparty_canonical_head_with_conn(&conn, relationship_key)
}

/// CAS the peer's canonical head from `expected_parent` to `target_child`
/// inside the caller's transaction (see the module doc for the outcome rules).
///
/// `expected_parent` is the head the step was signed under (the signed A parent
/// on inbound apply; the delta's `b_parent_tip` on sender finalize).
/// `source_commitment` names the step (the recipient's canonical apply id, or
/// the sender's receipt commitment) so a re-application of the SAME step is
/// `AlreadyAtTarget` while a different step landing on the same tip is a
/// `Conflict`. `genesis_seed` is `initial_chain_tip_from_device_ids(self, peer)`.
#[allow(clippy::too_many_arguments)]
pub fn cas_advance_counterparty_canonical_head_with_conn(
    conn: &rusqlite::Connection,
    relationship_key: &[u8; 32],
    counterparty_device_id: &[u8; 32],
    expected_parent: &[u8; 32],
    target_child: &[u8; 32],
    source_commitment: &[u8; 32],
    genesis_seed: &[u8; 32],
) -> Result<CasCanonicalHeadOutcome> {
    let current: Option<([u8; 32], [u8; 32], [u8; 32])> = conn
        .query_row(
            "SELECT head_tip, prev_tip, source_commitment FROM counterparty_canonical_heads \
             WHERE relationship_key = ?1",
            params![relationship_key.as_slice()],
            |r| Ok((col32(r, 0)?, col32(r, 1)?, col32(r, 2)?)),
        )
        .optional()?;

    match current {
        None => {
            if expected_parent != genesis_seed {
                return Ok(CasCanonicalHeadOutcome::Conflict { current: None });
            }
            conn.execute(
                "INSERT INTO counterparty_canonical_heads \
                 (relationship_key, counterparty_device_id, head_tip, prev_tip, \
                  source_commitment, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    relationship_key.as_slice(),
                    counterparty_device_id.as_slice(),
                    target_child.as_slice(),
                    expected_parent.as_slice(),
                    source_commitment.as_slice(),
                    tick() as i64,
                ],
            )?;
            Ok(CasCanonicalHeadOutcome::GenesisInit)
        }
        Some((head, prev, source)) => {
            if &head == target_child && &prev == expected_parent && &source == source_commitment {
                return Ok(CasCanonicalHeadOutcome::AlreadyAtTarget);
            }
            if &head != expected_parent {
                return Ok(CasCanonicalHeadOutcome::Conflict {
                    current: Some(head),
                });
            }
            let n = conn.execute(
                "UPDATE counterparty_canonical_heads \
                 SET head_tip = ?3, prev_tip = ?2, source_commitment = ?4, updated_at = ?5 \
                 WHERE relationship_key = ?1 AND head_tip = ?2",
                params![
                    relationship_key.as_slice(),
                    expected_parent.as_slice(),
                    target_child.as_slice(),
                    source_commitment.as_slice(),
                    tick() as i64,
                ],
            )?;
            if n != 1 {
                return Err(anyhow!(
                    "counterparty canonical head CAS updated {n} rows (expected 1) — aborting"
                ));
            }
            Ok(CasCanonicalHeadOutcome::Advanced)
        }
    }
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

    fn with_conn<T>(f: impl FnOnce(&rusqlite::Connection) -> Result<T>) -> T {
        let binding = crate::storage::client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        f(&conn).unwrap()
    }

    const REL: [u8; 32] = [0x01u8; 32];
    const CP: [u8; 32] = [0x02u8; 32];
    const SEED: [u8; 32] = [0xA0u8; 32];

    /// One lineage, both roles: genesis init from the seed, then advances from
    /// whichever role learned the next step, each CAS'd on the exact head.
    #[test]
    #[serial]
    fn genesis_init_then_advance_from_either_role_is_one_lineage() {
        init_test_db();
        assert_eq!(load_counterparty_canonical_head(&REL).unwrap(), None);
        // A wrong first step (expected != seed, no row) is a Conflict{None}.
        let out = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &[0xEEu8; 32],
                &[0xB1u8; 32],
                &[0x11u8; 32],
                &SEED,
            )
        });
        assert_eq!(out, CasCanonicalHeadOutcome::Conflict { current: None });
        assert_eq!(load_counterparty_canonical_head(&REL).unwrap(), None);

        // Genesis init (learned as recipient: A's signed pair seed→A1).
        let out = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &SEED,
                &[0xB1u8; 32],
                &[0x11u8; 32],
                &SEED,
            )
        });
        assert_eq!(out, CasCanonicalHeadOutcome::GenesisInit);
        assert_eq!(
            load_counterparty_canonical_head(&REL).unwrap(),
            Some([0xB1u8; 32])
        );
        // Advance (learned as sender: the delta's B pair B1→B2).
        let out = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &[0xB1u8; 32],
                &[0xB2u8; 32],
                &[0x22u8; 32],
                &SEED,
            )
        });
        assert_eq!(out, CasCanonicalHeadOutcome::Advanced);
        assert_eq!(
            load_counterparty_canonical_head(&REL).unwrap(),
            Some([0xB2u8; 32])
        );
    }

    /// Idempotency is per STEP: the same (parent→child, commitment) again is
    /// AlreadyAtTarget; a stale parent, or the same tip claimed by a different
    /// step, is a Conflict carrying the current head — never a silent no-op.
    #[test]
    #[serial]
    fn same_step_is_idempotent_but_stale_or_foreign_steps_conflict() {
        init_test_db();
        with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &SEED,
                &[0xB1u8; 32],
                &[0x11u8; 32],
                &SEED,
            )
        });
        with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &[0xB1u8; 32],
                &[0xB2u8; 32],
                &[0x22u8; 32],
                &SEED,
            )
        });
        // Same step again.
        let again = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &[0xB1u8; 32],
                &[0xB2u8; 32],
                &[0x22u8; 32],
                &SEED,
            )
        });
        assert_eq!(again, CasCanonicalHeadOutcome::AlreadyAtTarget);
        // Same tip, different step: Conflict.
        let foreign = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &[0xB1u8; 32],
                &[0xB2u8; 32],
                &[0x33u8; 32],
                &SEED,
            )
        });
        assert_eq!(
            foreign,
            CasCanonicalHeadOutcome::Conflict {
                current: Some([0xB2u8; 32])
            }
        );
        // Stale parent (the role-reversal shape: signing under an old head).
        let stale = with_conn(|c| {
            cas_advance_counterparty_canonical_head_with_conn(
                c,
                &REL,
                &CP,
                &SEED,
                &[0xB9u8; 32],
                &[0x44u8; 32],
                &SEED,
            )
        });
        assert_eq!(
            stale,
            CasCanonicalHeadOutcome::Conflict {
                current: Some([0xB2u8; 32])
            }
        );
        assert_eq!(
            load_counterparty_canonical_head(&REL).unwrap(),
            Some([0xB2u8; 32]),
            "no conflicting write moved the head"
        );
    }
}
