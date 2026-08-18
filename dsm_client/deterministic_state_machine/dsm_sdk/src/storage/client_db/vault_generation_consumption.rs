// SPDX-License-Identifier: MIT OR Apache-2.0
//! The durable "consume-once" claim for a vault generation.
//!
//! A vault's generation is authoritatively the reserve-leaf `sequence` committed
//! into the owner's device root; the core `advance` refuses any settlement that
//! does not consume the CURRENT generation (device_state.rs `ApplySettlement`).
//! That closes the value double-spend. This table adds the missing dimension the
//! device root does not carry — WHICH settlement consumed each generation — so the
//! reconcile route can tell an idempotent replay of the settlement that actually
//! won (`AlreadyConsumedSameSettlement`, report success and re-fold nothing) from a
//! DIFFERENT settlement racing the same parent (`Conflict`, refuse with a typed
//! signal that can never be mistaken for a successful fold).
//!
//! It is the reserve analog of `canonical_apply_identity`'s
//! `UNIQUE(relationship_key, parent_tip)` tripwire: `UNIQUE(vault_id,
//! parent_sequence)` is the authority, checked AT the INSERT (never
//! `INSERT OR IGNORE`), and `source_commitment` (the settlement receipt id) names
//! the step so the same step re-applied is idempotent while a foreign step at the
//! same generation is a conflict. The write happens INSIDE the fold's advance
//! transaction (via `in_tx_extra`), so the claim and the reserve move commit
//! together or not at all — no drift between this table and the device root.

use super::get_connection;
use crate::util::deterministic_time::tick;
use anyhow::Result;
use rusqlite::{params, OptionalExtension};

/// The consumer recorded for one `(vault_id, parent_sequence)` generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultGenerationConsumer {
    /// The successor generation this settlement produced (`parent_sequence + 1`).
    pub child_sequence: u64,
    /// The settlement receipt id that consumed the parent generation — the step
    /// name. Same id ⇒ idempotent replay; a different id ⇒ a foreign consumer.
    pub source_commitment: [u8; 32],
}

/// Outcome of one consume-once claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultGenerationConsumeOutcome {
    /// `(vault_id, parent_sequence)` was not yet consumed — this INSERT owns it.
    Consumed,
    /// The exact `(vault_id, parent_sequence, source_commitment)` row already
    /// exists — the SAME settlement re-applied. Idempotent success; fold nothing.
    AlreadyConsumedSameSettlement,
    /// `(vault_id, parent_sequence)` was already consumed by a DIFFERENT
    /// settlement. Fail closed — a second trade cannot consume the same parent.
    Conflict { current: VaultGenerationConsumer },
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

fn load_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &[u8; 32],
    parent_sequence: u64,
) -> Result<Option<VaultGenerationConsumer>> {
    Ok(conn
        .query_row(
            "SELECT child_sequence, source_commitment FROM vault_generation_consumption \
             WHERE vault_id = ?1 AND parent_sequence = ?2",
            params![vault_id.as_slice(), parent_sequence as i64],
            |r| {
                Ok(VaultGenerationConsumer {
                    child_sequence: r.get::<_, i64>(0)? as u64,
                    source_commitment: col32(r, 1)?,
                })
            },
        )
        .optional()?)
}

/// The consumer of `(vault_id, parent_sequence)`, if the generation has been
/// consumed. `None` ⇔ still open. Read on its own connection — used by the
/// reconcile route to classify a receipt BEFORE it advances.
pub fn load_vault_generation_consumer(
    vault_id: &[u8; 32],
    parent_sequence: u64,
) -> Result<Option<VaultGenerationConsumer>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    load_with_conn(&conn, vault_id, parent_sequence)
}

/// Claim `(vault_id, parent_sequence)` for `source_commitment` INSIDE the caller's
/// transaction — the same transaction that writes the successor reserve leaves, so
/// the claim and the value move are one atomic unit.
///
/// `UNIQUE(vault_id, parent_sequence)` is the authority. The pre-SELECT classifies
/// the common cases; the bare INSERT is what actually decides a race, and a losing
/// racer's `ConstraintViolation` is caught and re-read (NEVER `INSERT OR IGNORE`,
/// which would collapse `AlreadyConsumedSameSettlement` and `Conflict` into a
/// silent no-op). The caller maps `Conflict` to an error so the whole advance rolls
/// back.
pub fn cas_consume_vault_generation_with_conn(
    conn: &rusqlite::Connection,
    vault_id: &[u8; 32],
    parent_sequence: u64,
    child_sequence: u64,
    source_commitment: &[u8; 32],
) -> Result<VaultGenerationConsumeOutcome> {
    if let Some(existing) = load_with_conn(conn, vault_id, parent_sequence)? {
        return Ok(classify_existing(existing, source_commitment));
    }
    match conn.execute(
        "INSERT INTO vault_generation_consumption \
         (vault_id, parent_sequence, child_sequence, source_commitment, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            vault_id.as_slice(),
            parent_sequence as i64,
            child_sequence as i64,
            source_commitment.as_slice(),
            tick() as i64,
        ],
    ) {
        Ok(_) => Ok(VaultGenerationConsumeOutcome::Consumed),
        // Losing racer: another writer took (vault_id, parent_sequence) between the
        // pre-SELECT and here. The UNIQUE constraint is the authority — re-read to
        // classify the winner's row.
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            match load_with_conn(conn, vault_id, parent_sequence)? {
                Some(existing) => Ok(classify_existing(existing, source_commitment)),
                None => Err(anyhow::anyhow!(
                    "vault generation consume: constraint violation with no row — aborting"
                )),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn classify_existing(
    existing: VaultGenerationConsumer,
    source_commitment: &[u8; 32],
) -> VaultGenerationConsumeOutcome {
    if &existing.source_commitment == source_commitment {
        VaultGenerationConsumeOutcome::AlreadyConsumedSameSettlement
    } else {
        VaultGenerationConsumeOutcome::Conflict { current: existing }
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

    const VAULT: [u8; 32] = [0x5A; 32];
    const WINNER: [u8; 32] = [0x77; 32];
    const LOSER: [u8; 32] = [0x99; 32];

    /// The consume-once claim: the first settlement to consume a generation wins;
    /// a DIFFERENT settlement at the same generation is a typed Conflict, never a
    /// silent success; the SAME settlement re-applied is idempotent.
    #[test]
    #[serial]
    fn one_generation_is_consumed_once_and_a_foreign_settlement_conflicts() {
        init_test_db();
        assert_eq!(load_vault_generation_consumer(&VAULT, 0).unwrap(), None);

        // Winner consumes generation 0 → 1.
        let out = with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &WINNER));
        assert_eq!(out, VaultGenerationConsumeOutcome::Consumed);
        assert_eq!(
            load_vault_generation_consumer(&VAULT, 0).unwrap(),
            Some(VaultGenerationConsumer {
                child_sequence: 1,
                source_commitment: WINNER
            })
        );

        // A DIFFERENT settlement racing the SAME parent generation → Conflict,
        // carrying the winner it lost to. Never a silent success.
        let out = with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &LOSER));
        assert_eq!(
            out,
            VaultGenerationConsumeOutcome::Conflict {
                current: VaultGenerationConsumer {
                    child_sequence: 1,
                    source_commitment: WINNER
                }
            }
        );

        // The loser wrote nothing: generation 0 still belongs to the winner.
        assert_eq!(
            load_vault_generation_consumer(&VAULT, 0)
                .unwrap()
                .unwrap()
                .source_commitment,
            WINNER
        );
    }

    /// Replay of the winner is idempotent; replay of the loser stays a Conflict —
    /// the two never collapse, however many times either is retried.
    #[test]
    #[serial]
    fn winner_replay_is_idempotent_and_loser_replay_stays_rejected() {
        init_test_db();
        with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &WINNER));

        // Winner again: idempotent success, no second consume.
        let again = with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &WINNER));
        assert_eq!(
            again,
            VaultGenerationConsumeOutcome::AlreadyConsumedSameSettlement
        );

        // Loser again: still a Conflict, not a late success.
        let loser_again =
            with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &LOSER));
        assert!(matches!(
            loser_again,
            VaultGenerationConsumeOutcome::Conflict { .. }
        ));
    }

    /// Distinct generations of one vault each hold their own consumer — the claim
    /// is per `(vault, generation)`, so a later generation is not blocked by an
    /// earlier one.
    #[test]
    #[serial]
    fn successive_generations_each_hold_their_own_consumer() {
        init_test_db();
        let g0 = with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 0, 1, &WINNER));
        let g1 = with_conn(|c| cas_consume_vault_generation_with_conn(c, &VAULT, 1, 2, &LOSER));
        assert_eq!(g0, VaultGenerationConsumeOutcome::Consumed);
        assert_eq!(g1, VaultGenerationConsumeOutcome::Consumed);
        assert_eq!(
            load_vault_generation_consumer(&VAULT, 1)
                .unwrap()
                .unwrap()
                .child_sequence,
            2
        );
    }
}
