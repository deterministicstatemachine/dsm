// SPDX-License-Identifier: MIT OR Apache-2.0
//! Spent transfer nonces (replay prevention), each scoped to the relationship
//! that carries it.

use anyhow::{anyhow, Result};
use rusqlite::params;

/// `H(DSM/relationship-nonce/v1 ‖ relationship_key ‖ nonce)`: the key a
/// transfer nonce is spent under.
///
/// A nonce is unique within the relationship that carries it. The replay rule
/// itself is the relationship's own (relationship, parent) record
/// (MR-DSM-0170); this is the nonce check beside it, and it must not reach
/// across relationships. A sender's nonce derives from public inputs, so with
/// a nonce spent across every relationship, another contact could spend this
/// relationship's next nonce first and have its transfer dropped as decided
/// (security pre-audit item 5).
pub fn relationship_nonce_hash(relationship_key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = dsm::crypto::blake3::dsm_domain_hasher(
        dsm::common::domain_tags::TAG_DSM_RELATIONSHIP_NONCE,
    );
    h.update(relationship_key);
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// Whether `nonce` is spent in the relationship `relationship_key`, read
/// INSIDE the single full-state apply transaction (§16.6 single-commit apply).
/// `&rusqlite::Transaction` derefs to `&Connection`, so pass `&tx`.
pub fn is_nonce_spent_with_conn(
    conn: &rusqlite::Connection,
    relationship_key: &[u8; 32],
    nonce: &[u8],
) -> Result<bool> {
    if nonce.is_empty() {
        return Err(anyhow!("an empty nonce is not a nonce"));
    }
    let nonce_hash = relationship_nonce_hash(relationship_key, nonce);
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM spent_nonces WHERE nonce_hash = ?1",
        params![&nonce_hash[..]],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Spend `nonce` in the relationship `relationship_key` against a
/// caller-supplied connection/transaction: the consumption commits (or rolls
/// back) WITH the rest of the full-state apply transaction, never as a
/// separate durability boundary. A nonce already spent in this relationship
/// is refused.
pub fn mark_nonce_spent_with_conn(
    conn: &rusqlite::Connection,
    relationship_key: &[u8; 32],
    nonce: &[u8],
    tx_id: &str,
    sender_id: &[u8],
    amount: u64,
) -> Result<()> {
    if nonce.is_empty() {
        return Err(anyhow!("Cannot mark empty nonce as spent"));
    }
    let nonce_hash = relationship_nonce_hash(relationship_key, nonce);
    let result = conn.execute(
        "INSERT INTO spent_nonces(nonce_hash, tx_id, sender_id, amount) VALUES(?1, ?2, ?3, ?4)",
        params![&nonce_hash[..], tx_id, sender_id, amount as i64],
    );
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(anyhow!("Replay attack detected: nonce already spent"))
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const REL_A: [u8; 32] = [0xA1; 32];
    const REL_B: [u8; 32] = [0xB2; 32];
    /// Each relationship's chain tip, one of the public inputs its next
    /// transfer's nonce derives from.
    const TIP_A: [u8; 32] = [0xA7; 32];
    const TIP_B: [u8; 32] = [0xB7; 32];

    /// The nonce the next transfer of `amount` ERA carries in a relationship
    /// whose chain tip is `tip`, as the SDK derives it (§4.1).
    fn next_nonce(tip: &[u8; 32], amount: u64) -> Vec<u8> {
        crate::handlers::app_router_impl::transfer_nonce(tip, amount, "ERA", &[0xD1; 32])
    }

    fn init_test_db() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    #[test]
    #[serial]
    fn an_empty_nonce_is_refused() {
        init_test_db();
        let binding = crate::storage::client_db::get_connection().expect("db");
        let conn = binding.lock().expect("db lock");
        let err = mark_nonce_spent_with_conn(&conn, &REL_A, &[], "tx-1", b"sender", 100)
            .expect_err("an empty nonce is not spendable");
        assert!(err.to_string().contains("empty nonce"));
        let err = is_nonce_spent_with_conn(&conn, &REL_A, &[]).expect_err("nor checkable");
        assert!(err.to_string().contains("empty nonce"));
    }

    #[test]
    #[serial]
    fn a_nonce_is_spent_once_in_its_relationship() {
        init_test_db();
        let binding = crate::storage::client_db::get_connection().expect("db");
        let conn = binding.lock().expect("db lock");
        let nonce = next_nonce(&TIP_A, 500);
        assert!(!is_nonce_spent_with_conn(&conn, &REL_A, &nonce).expect("read"));
        mark_nonce_spent_with_conn(&conn, &REL_A, &nonce, "tx-42", b"sender-a", 500)
            .expect("mark spent");
        assert!(is_nonce_spent_with_conn(&conn, &REL_A, &nonce).expect("read"));
        let err = mark_nonce_spent_with_conn(&conn, &REL_A, &nonce, "tx-again", b"sender-a", 500)
            .expect_err("a second spend in the relationship is a replay");
        assert!(err.to_string().contains("Replay attack"));
    }

    /// Security pre-audit item 5: the same nonce bytes spent in one
    /// relationship are not spent in another, so a contact cannot spend
    /// another contact's predicted nonce first and have its transfer dropped.
    /// The nonce is the one relationship B's next transfer carries, derived
    /// from B's public inputs; contact Y spends those bytes in A first.
    #[test]
    #[serial]
    fn a_nonce_spent_in_one_relationship_is_not_spent_in_another() {
        init_test_db();
        let binding = crate::storage::client_db::get_connection().expect("db");
        let conn = binding.lock().expect("db lock");
        let predicted = next_nonce(&TIP_B, 100);
        mark_nonce_spent_with_conn(&conn, &REL_A, &predicted, "tx-a", b"contact-y", 1)
            .expect("spent in A");
        assert!(!is_nonce_spent_with_conn(&conn, &REL_B, &predicted).expect("read"));
        mark_nonce_spent_with_conn(&conn, &REL_B, &predicted, "tx-b", b"contact-x", 100)
            .expect("still spendable in B");
        assert_ne!(
            relationship_nonce_hash(&REL_A, &predicted),
            relationship_nonce_hash(&REL_B, &predicted)
        );
    }
}
