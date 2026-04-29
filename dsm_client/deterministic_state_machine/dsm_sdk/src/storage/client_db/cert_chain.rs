// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-relationship cert chain head storage (whitepaper §11.1 ek-cert chain).
//!
//! Each bilateral relationship maintains TWO chain heads:
//! - `Side::Local` — the SPHINCS+ public key the local device used to sign
//!   the most recent outbound cert. At step 0 this is `AK_pk` (the device's
//!   long-term attested key). At step n > 0 this is the per-step `EK_pk_n`.
//! - `Side::Counterparty` — the corresponding chain head pubkey for the
//!   counterparty, used by the local device to verify incoming certs.
//!
//! Chain head advancement happens after a receipt is accepted: the new
//! `EK_pk_{n+1}` (which signed the receipt body) becomes the new chain head
//! for whichever side produced that receipt.
//!
//! This module provides storage primitives only. Higher-level wiring
//! (initializing chain heads at relationship establishment, signing certs
//! during receipt creation, advancing heads after acceptance) lives in
//! `dsm_sdk::sdk::receipts` and the bilateral session handlers.
//!
//! Storage: `cert_chain_heads` table — see `client_db::create_schema`.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// Which side of a bilateral relationship a chain head belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertChainSide {
    /// The local device's outbound cert chain head.
    Local,
    /// The counterparty's outbound cert chain head (verified by us).
    Counterparty,
}

impl CertChainSide {
    fn as_i64(self) -> i64 {
        match self {
            CertChainSide::Local => 0,
            CertChainSide::Counterparty => 1,
        }
    }
}

/// Snapshot of a chain head row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertChainHead {
    pub relationship_key: Vec<u8>,
    pub side: CertChainSide,
    pub chain_head_pubkey: Vec<u8>,
    pub step_count: u64,
    pub updated_at: u64,
}

/// Initialize a chain head for a relationship. Idempotent: if a row already
/// exists for `(relationship_key, side)` it is left unchanged. Returns `true`
/// if a new row was inserted, `false` if the row already existed.
///
/// At relationship establishment (step 0), this is called with
/// `chain_head_pubkey = AK_pk` for both Local (the local device's AK) and
/// Counterparty (the peer's AK, looked up via Device Tree inclusion).
pub fn init_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
    chain_head_pubkey: &[u8],
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO cert_chain_heads
            (relationship_key, side, chain_head_pubkey, step_count, updated_at)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![
            relationship_key.as_slice(),
            side.as_i64(),
            chain_head_pubkey,
            now
        ],
    )?;
    Ok(inserted > 0)
}

/// Advance the chain head to a new pubkey after a receipt is accepted.
/// Bumps `step_count` by one and sets `chain_head_pubkey` to `new_pubkey`.
/// Returns the new step count, or `None` if no row exists for that
/// (relationship_key, side) pair.
pub fn advance_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
    new_pubkey: &[u8],
) -> Result<Option<u64>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let updated = conn.execute(
        "UPDATE cert_chain_heads
         SET chain_head_pubkey = ?1,
             step_count = step_count + 1,
             updated_at = ?2
         WHERE relationship_key = ?3 AND side = ?4",
        params![new_pubkey, now, relationship_key.as_slice(), side.as_i64()],
    )?;
    if updated == 0 {
        return Ok(None);
    }
    let step_count: i64 = conn
        .query_row(
            "SELECT step_count FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok(Some(step_count as u64))
}

/// Load the current chain head pubkey for a relationship + side. Returns
/// `None` if no chain head has been initialized for that pair (relationship
/// has not yet been established, or pre-feature legacy data).
pub fn load_cert_chain_head_pubkey(
    relationship_key: &[u8; 32],
    side: CertChainSide,
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let pk: Option<Vec<u8>> = conn
        .query_row(
            "SELECT chain_head_pubkey FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(pk)
}

/// Initialize both sides of a relationship's cert chain in one call.
/// This is the common entry point invoked when a relationship is first
/// established: local side anchored at the device's `AK_pk`, counterparty
/// side anchored at the peer's `AK_pk` (looked up via Device Tree
/// inclusion at receipt-verification time).
///
/// Idempotent: returns `(local_inserted, cp_inserted)` indicating whether
/// each side actually wrote a new row. Existing rows are left unchanged.
pub fn init_cert_chain_for_relationship(
    relationship_key: &[u8; 32],
    local_ak_pubkey: &[u8],
    counterparty_ak_pubkey: &[u8],
) -> Result<(bool, bool)> {
    let local_inserted = init_cert_chain_head(
        relationship_key,
        CertChainSide::Local,
        local_ak_pubkey,
    )?;
    let cp_inserted = init_cert_chain_head(
        relationship_key,
        CertChainSide::Counterparty,
        counterparty_ak_pubkey,
    )?;
    Ok((local_inserted, cp_inserted))
}

/// Advance both sides of a relationship's cert chain after a co-signed
/// receipt has been accepted. `local_new_pubkey` is the EK_pk that signed
/// our outbound sig_a (when we were sender) or sig_b (when we were
/// receiver). `counterparty_new_pubkey` is the corresponding EK_pk from
/// the other side.
///
/// Returns `Some((local_step, cp_step))` with the new step counts if both
/// sides were advanced, or `None` if either side had no row to advance
/// (relationship not yet initialized via `init_cert_chain_for_relationship`).
pub fn advance_cert_chain_for_relationship(
    relationship_key: &[u8; 32],
    local_new_pubkey: &[u8],
    counterparty_new_pubkey: &[u8],
) -> Result<Option<(u64, u64)>> {
    let local_step = advance_cert_chain_head(
        relationship_key,
        CertChainSide::Local,
        local_new_pubkey,
    )?;
    let cp_step = advance_cert_chain_head(
        relationship_key,
        CertChainSide::Counterparty,
        counterparty_new_pubkey,
    )?;
    match (local_step, cp_step) {
        (Some(l), Some(c)) => Ok(Some((l, c))),
        _ => Ok(None),
    }
}

/// Load the full chain head record (pubkey + step_count + timestamp).
pub fn load_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
) -> Result<Option<CertChainHead>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT chain_head_pubkey, step_count, updated_at
             FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| {
                let pk: Vec<u8> = row.get(0)?;
                let step: i64 = row.get(1)?;
                let ts: i64 = row.get(2)?;
                Ok((pk, step, ts))
            },
        )
        .optional()?;
    Ok(row.map(|(pk, step, ts)| CertChainHead {
        relationship_key: relationship_key.to_vec(),
        side,
        chain_head_pubkey: pk,
        step_count: step as u64,
        updated_at: ts as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::reset_database_for_tests;

    fn rel(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    #[serial_test::serial]
    fn init_inserts_then_idempotent() {
        reset_database_for_tests();
        let r = rel(0xAA);
        let pk_v1 = vec![0x01; 64];
        let pk_v2 = vec![0x02; 64];

        // First init inserts.
        assert!(init_cert_chain_head(&r, CertChainSide::Local, &pk_v1).unwrap());

        // Second init for the same (key, side) is idempotent — does NOT
        // overwrite. Use advance_cert_chain_head to change the pubkey.
        assert!(!init_cert_chain_head(&r, CertChainSide::Local, &pk_v2).unwrap());

        let head = load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(head, pk_v1, "init must not overwrite existing head");
    }

    #[test]
    #[serial_test::serial]
    fn local_and_counterparty_are_independent() {
        reset_database_for_tests();
        let r = rel(0xBB);
        let local_pk = vec![0x11; 64];
        let cp_pk = vec![0x22; 64];

        init_cert_chain_head(&r, CertChainSide::Local, &local_pk).unwrap();
        init_cert_chain_head(&r, CertChainSide::Counterparty, &cp_pk).unwrap();

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_pk
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_pk
        );
    }

    #[test]
    #[serial_test::serial]
    fn advance_bumps_step_and_replaces_pubkey() {
        reset_database_for_tests();
        let r = rel(0xCC);
        let ak_pk = vec![0xAA; 64];
        let ek1_pk = vec![0xBB; 64];
        let ek2_pk = vec![0xCC; 64];

        init_cert_chain_head(&r, CertChainSide::Local, &ak_pk).unwrap();
        let head0 = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(head0.chain_head_pubkey, ak_pk);
        assert_eq!(head0.step_count, 0);

        let step1 = advance_cert_chain_head(&r, CertChainSide::Local, &ek1_pk)
            .unwrap()
            .unwrap();
        assert_eq!(step1, 1);

        let step2 = advance_cert_chain_head(&r, CertChainSide::Local, &ek2_pk)
            .unwrap()
            .unwrap();
        assert_eq!(step2, 2);

        let final_head = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(final_head.chain_head_pubkey, ek2_pk);
        assert_eq!(final_head.step_count, 2);
    }

    #[test]
    #[serial_test::serial]
    fn advance_returns_none_when_no_row_exists() {
        reset_database_for_tests();
        let r = rel(0xDD);
        let pk = vec![0xEE; 64];
        // No init first — advance should be a no-op and return None.
        let result = advance_cert_chain_head(&r, CertChainSide::Local, &pk).unwrap();
        assert!(result.is_none(), "advance without init must return None");
    }

    #[test]
    #[serial_test::serial]
    fn load_returns_none_for_unknown_relationship() {
        reset_database_for_tests();
        let r = rel(0xFE);
        assert!(load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .is_none());
        assert!(load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .is_none());
    }

    /// `init_cert_chain_for_relationship` initializes both sides of a
    /// relationship from a single call. Subsequent advancement on each side
    /// is independent.
    #[test]
    #[serial_test::serial]
    fn init_for_relationship_seeds_both_sides() {
        reset_database_for_tests();
        let r = rel(0xA1);
        let local_ak = vec![0x01; 64];
        let cp_ak = vec![0x02; 64];

        let (li, ci) = init_cert_chain_for_relationship(&r, &local_ak, &cp_ak).unwrap();
        assert!(li, "local side must be inserted on first call");
        assert!(ci, "counterparty side must be inserted on first call");

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_ak
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_ak
        );

        // Second call is idempotent.
        let (li2, ci2) = init_cert_chain_for_relationship(&r, &local_ak, &cp_ak).unwrap();
        assert!(!li2);
        assert!(!ci2);
    }

    /// `advance_cert_chain_for_relationship` advances both sides atomically
    /// after a co-signed receipt is accepted, returning `(local_step, cp_step)`.
    #[test]
    #[serial_test::serial]
    fn advance_for_relationship_bumps_both_sides() {
        reset_database_for_tests();
        let r = rel(0xA2);
        init_cert_chain_for_relationship(&r, &vec![0xAA; 64], &vec![0xBB; 64]).unwrap();

        let local_ek1 = vec![0xCC; 64];
        let cp_ek1 = vec![0xDD; 64];

        let steps = advance_cert_chain_for_relationship(&r, &local_ek1, &cp_ek1)
            .unwrap()
            .unwrap();
        assert_eq!(steps, (1, 1));

        let local_ek2 = vec![0xEE; 64];
        let cp_ek2 = vec![0xFF; 64];
        let steps2 = advance_cert_chain_for_relationship(&r, &local_ek2, &cp_ek2)
            .unwrap()
            .unwrap();
        assert_eq!(steps2, (2, 2));

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_ek2
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_ek2
        );
    }

    /// `advance_cert_chain_for_relationship` returns `None` when the
    /// relationship has never been initialized — caller is expected to
    /// init first.
    #[test]
    #[serial_test::serial]
    fn advance_for_relationship_requires_init() {
        reset_database_for_tests();
        let r = rel(0xA3);
        let result =
            advance_cert_chain_for_relationship(&r, &vec![0xAA; 64], &vec![0xBB; 64]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn different_relationships_isolated() {
        reset_database_for_tests();
        let r1 = rel(0x01);
        let r2 = rel(0x02);
        let pk1 = vec![0x11; 64];
        let pk2 = vec![0x22; 64];

        init_cert_chain_head(&r1, CertChainSide::Local, &pk1).unwrap();
        init_cert_chain_head(&r2, CertChainSide::Local, &pk2).unwrap();

        assert_eq!(
            load_cert_chain_head_pubkey(&r1, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk1
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r2, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk2
        );
        // Advance r1 doesn't touch r2.
        advance_cert_chain_head(&r1, CertChainSide::Local, &vec![0xAB; 64]).unwrap();
        assert_eq!(
            load_cert_chain_head_pubkey(&r2, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk2
        );
    }
}
