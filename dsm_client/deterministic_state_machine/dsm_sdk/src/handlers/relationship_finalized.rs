// SPDX-License-Identifier: MIT OR Apache-2.0
//! Recipient side of the bilateral finality barrier: consuming the sender's
//! `RelationshipFinalizedV1` certificate.
//!
//! The recipient journaled its acceptance (with the pair `sig_b` authenticated)
//! and replied; from then on its local finality barrier for that relationship
//! is UNRESOLVED — it may not originate — until the sender's certificate for
//! that exact transition verifies here. The certificate proves the sender
//! finalized on this recipient's countersignature and pinned this recipient's
//! head, so the next step from either side has one agreed predecessor.
//!
//! Verification is entirely against DURABLE local state — the journal named by
//! `(relationship, commitment)` — never against current heads: the signature
//! is checked under the journal's `new_counterparty_a_head` (the sender's
//! per-step EK for that transition, which the sender signed the certificate
//! with), NOT the live Counterparty EK head, which moves on the next inbound
//! apply, on this device's own finalize, or on a cert resync.

use crate::storage::client_db::{
    self as cdb, RecipientAcceptanceJournal, STATUS_COMPLETE, STATUS_REJECTED,
};
use dsm::types::proto::RelationshipFinalizedV1;
use dsm::types::receipt_types::{
    decode_relationship_finalized_wire, relationship_finalized_signing_target,
};

/// What one polled certificate did here. ACK on the polled route only for
/// `Applied` / `AlreadyFinalized` / `NoJournal` (nothing this device could
/// ever use it for); everything else leaves it spooled for the next poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationshipFinalizedOutcome {
    /// Verified; `peer_finalized` flipped to 1 for that transition.
    Applied,
    /// The transition was already marked finalized — idempotent re-serve.
    AlreadyFinalized,
    /// The named journal exists but has not completed its fold yet; retry.
    NotYetComplete,
    /// No journal for `(relationship, commitment)` on this device — not ours
    /// (a certificate can only exist after this device's delta, which requires
    /// a complete journal). Dropped.
    NoJournal,
    /// Not a canonical `RelationshipFinalizedV1` on the wire.
    WireRejected(String),
    /// A well-formed certificate that does not match the journal or whose
    /// signature does not verify under the journal's A head. Left spooled;
    /// nothing written.
    Rejected(String),
}

fn arr32(v: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(v).map_err(|_| format!("{what} is not 32 bytes"))
}

/// Pure check of a decoded certificate against the journal it names. Returns
/// the rejection reason, if any.
fn check_against_journal(
    cert: &RelationshipFinalizedV1,
    journal: &RecipientAcceptanceJournal,
    local_device: &[u8; 32],
) -> Result<(), String> {
    if cert.sender_device_id.as_slice() != journal.counterparty_device_id.as_slice() {
        return Err("certificate sender is not the journal's counterparty".into());
    }
    if cert.recipient_device_id.as_slice() != local_device.as_slice() {
        return Err("certificate recipient is not this device".into());
    }
    if cert.sender_child_tip_a.as_slice() != journal.child_tip.as_slice() {
        return Err("certificate sender_child_tip_a != journaled signed child".into());
    }
    if cert.recipient_parent_tip_b.as_slice() != journal.applied_parent_tip_b.as_slice()
        || cert.recipient_child_tip_b.as_slice() != journal.applied_child_tip_b.as_slice()
    {
        return Err("certificate recipient pair != the pair this device journaled".into());
    }
    if journal.new_counterparty_a_head.is_empty() {
        return Err("journal carries no sender per-step EK head to verify under".into());
    }
    let target = relationship_finalized_signing_target(cert);
    match dsm::crypto::sphincs::sphincs_verify(
        &journal.new_counterparty_a_head,
        &target,
        &cert.signature_a,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => {
            Err("certificate signature_a does not verify under the journal's sender EK head".into())
        }
        Err(e) => Err(format!("certificate signature verify error: {e}")),
    }
}

/// Consume one polled certificate. Runs under the relationship lock (the
/// same exclusion the acceptance sequence holds).
pub async fn apply_relationship_finalized(body: &[u8]) -> RelationshipFinalizedOutcome {
    let cert = match decode_relationship_finalized_wire(body) {
        Ok(c) => c,
        Err(e) => return RelationshipFinalizedOutcome::WireRejected(e.to_string()),
    };
    let rel = match arr32(&cert.relationship_key, "relationship_key") {
        Ok(r) => r,
        Err(e) => return RelationshipFinalizedOutcome::WireRejected(e),
    };
    let commitment = match arr32(&cert.transition_commitment, "transition_commitment") {
        Ok(c) => c,
        Err(e) => return RelationshipFinalizedOutcome::WireRejected(e),
    };
    let Some(local_device) = crate::sdk::app_state::AppState::get_device_id()
        .and_then(|d| <[u8; 32]>::try_from(d.as_slice()).ok())
    else {
        return RelationshipFinalizedOutcome::Rejected("local device_id unavailable".into());
    };

    let lock = crate::handlers::recipient_receipt::relationship_lock(&rel);
    let _guard = lock.lock_owned().await;

    let journal = match cdb::get_acceptance_journal_by_commitment(&rel, &commitment) {
        Ok(Some(j)) => j,
        Ok(None) => return RelationshipFinalizedOutcome::NoJournal,
        Err(e) => return RelationshipFinalizedOutcome::Rejected(format!("journal lookup: {e}")),
    };
    if journal.status == STATUS_REJECTED {
        return RelationshipFinalizedOutcome::Rejected(
            "journal for this transition is rejected".into(),
        );
    }
    if journal.peer_finalized {
        return RelationshipFinalizedOutcome::AlreadyFinalized;
    }
    if journal.status != STATUS_COMPLETE {
        return RelationshipFinalizedOutcome::NotYetComplete;
    }
    if let Err(reason) = check_against_journal(&cert, &journal, &local_device) {
        return RelationshipFinalizedOutcome::Rejected(reason);
    }

    let flipped = (|| -> anyhow::Result<bool> {
        let binding = cdb::get_connection()?;
        let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction()?;
        let flipped = cdb::mark_peer_finalized_with_conn(&tx, &rel, &commitment)?;
        tx.commit()?;
        Ok(flipped)
    })();
    match flipped {
        Ok(true) => RelationshipFinalizedOutcome::Applied,
        Ok(false) => RelationshipFinalizedOutcome::AlreadyFinalized,
        Err(e) => RelationshipFinalizedOutcome::Rejected(format!("peer_finalized write: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{
        insert_prepared_acceptance_journal, RecipientAcceptanceJournal, STATUS_PREPARED,
    };
    use prost::Message;
    use serial_test::serial;

    const REL: [u8; 32] = [0x71u8; 32];
    const CP: [u8; 32] = [0x0Au8; 32];
    const LOCAL: [u8; 32] = [0x0Bu8; 32];
    const COMMITMENT: [u8; 32] = [0x64u8; 32];
    const A_CHILD: [u8; 32] = [0x32u8; 32];
    const B_PAIR: ([u8; 32], [u8; 32]) = ([0xE3u8; 32], [0xE4u8; 32]);

    fn init() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        crate::sdk::app_state::AppState::set_identity_info(
            LOCAL.to_vec(),
            vec![0x02; 32],
            vec![0x03; 32],
            vec![0x04; 32],
        );
    }

    /// A complete journal for the transition, with a REAL sender EK head.
    fn seed_complete_journal(ek_pk_a: Vec<u8>) {
        insert_prepared_acceptance_journal(&RecipientAcceptanceJournal {
            relationship_key: REL,
            parent_tip: [0x31u8; 32],
            child_tip: A_CHILD,
            counterparty_device_id: CP,
            commitment: COMMITMENT,
            receipt_parent_root_a: [0u8; 32],
            receipt_child_root_a: [0u8; 32],
            precommit_digest: [0u8; 32],
            prepared_receipt_artifact_hash: [0u8; 32],
            expected_local_b_head: None,
            new_local_b_head: vec![0xBBu8; 40],
            new_local_b_sk_enc: None,
            expected_counterparty_a_head: None,
            new_counterparty_a_head: ek_pk_a,
            receipt_bytes: b"RECEIPT".to_vec(),
            projection_parent_tip: [0xE1u8; 32],
            projection_target_tip: [0xE2u8; 32],
            applied_parent_tip_b: B_PAIR.0,
            applied_child_tip_b: B_PAIR.1,
            peer_finalized: false,
            status: STATUS_PREPARED.to_string(),
            created_at: 0,
        })
        .expect("journal");
        let binding = cdb::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "UPDATE acceptance_fold_journal SET status = 'complete' WHERE commitment = ?1",
            rusqlite::params![COMMITMENT.as_slice()],
        )
        .expect("complete");
    }

    fn signed_certificate(ek_sk_a: &[u8]) -> RelationshipFinalizedV1 {
        let mut cert = RelationshipFinalizedV1 {
            relationship_key: REL.to_vec(),
            transition_commitment: COMMITMENT.to_vec(),
            sender_device_id: CP.to_vec(),
            recipient_device_id: LOCAL.to_vec(),
            sender_child_tip_a: A_CHILD.to_vec(),
            recipient_parent_tip_b: B_PAIR.0.to_vec(),
            recipient_child_tip_b: B_PAIR.1.to_vec(),
            signature_a: Vec::new(),
        };
        let target = relationship_finalized_signing_target(&cert);
        cert.signature_a = dsm::crypto::sphincs::sphincs_sign(ek_sk_a, &target).expect("sign");
        cert
    }

    /// The certificate releases the recipient exactly once, is idempotent on
    /// re-serve, and every substituted field or foreign signature is refused
    /// with `peer_finalized` untouched.
    #[tokio::test]
    #[serial]
    async fn a_verified_certificate_flips_peer_finalized_once_and_forgeries_do_not() {
        init();
        let (ek_pk_a, ek_sk_a) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("ek a");
        let (_other_pk, other_sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("ek x");
        seed_complete_journal(ek_pk_a.clone());
        assert!(cdb::relationship_awaits_peer_finalization(&REL).unwrap());

        // Forgeries first (positive control follows in the same fixture).
        let good = signed_certificate(&ek_sk_a);
        for (label, mutate) in [
            ("child_a", 0usize),
            ("pair_parent", 1usize),
            ("pair_child", 2usize),
            ("recipient", 3usize),
            ("sender", 4usize),
        ] {
            let mut c = good.clone();
            match mutate {
                0 => c.sender_child_tip_a[0] ^= 1,
                1 => c.recipient_parent_tip_b[0] ^= 1,
                2 => c.recipient_child_tip_b[0] ^= 1,
                3 => c.recipient_device_id[0] ^= 1,
                _ => c.sender_device_id[0] ^= 1,
            }
            // Re-sign the mutated body under the RIGHT key so the check that
            // trips is the field comparison, not the signature.
            let target = relationship_finalized_signing_target(&c);
            c.signature_a = dsm::crypto::sphincs::sphincs_sign(&ek_sk_a, &target).unwrap();
            let out = apply_relationship_finalized(&c.encode_to_vec()).await;
            assert!(
                matches!(out, RelationshipFinalizedOutcome::Rejected(_)),
                "{label}: {out:?}"
            );
            assert!(cdb::relationship_awaits_peer_finalization(&REL).unwrap());
        }
        // Right fields, wrong signer (a key that is not the journal's A head).
        let forged = signed_certificate(&other_sk);
        let out = apply_relationship_finalized(&forged.encode_to_vec()).await;
        match out {
            RelationshipFinalizedOutcome::Rejected(r) => assert!(r.contains("signature"), "{r}"),
            other => panic!("foreign signer must be rejected, got {other:?}"),
        }
        assert!(cdb::relationship_awaits_peer_finalization(&REL).unwrap());
        // A delta body on the certificate method is refused at the wire.
        assert!(matches!(
            apply_relationship_finalized(&[0x0Au8; 40]).await,
            RelationshipFinalizedOutcome::WireRejected(_)
        ));

        // Positive: the honest certificate releases the recipient.
        assert_eq!(
            apply_relationship_finalized(&good.encode_to_vec()).await,
            RelationshipFinalizedOutcome::Applied
        );
        assert!(!cdb::relationship_awaits_peer_finalization(&REL).unwrap());
        assert_eq!(
            apply_relationship_finalized(&good.encode_to_vec()).await,
            RelationshipFinalizedOutcome::AlreadyFinalized,
            "re-serve is idempotent"
        );
    }

    /// A certificate naming a transition this device never journaled is
    /// dropped as not-ours; one naming an incomplete journal is left for a
    /// later poll (nothing written either way).
    #[tokio::test]
    #[serial]
    async fn unknown_or_incomplete_journals_do_not_flip() {
        init();
        let (ek_pk_a, ek_sk_a) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("ek a");
        let good = signed_certificate(&ek_sk_a);
        assert_eq!(
            apply_relationship_finalized(&good.encode_to_vec()).await,
            RelationshipFinalizedOutcome::NoJournal
        );
        // Journal present but still `prepared`.
        seed_complete_journal(ek_pk_a);
        {
            let binding = cdb::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "UPDATE acceptance_fold_journal SET status = 'prepared' WHERE commitment = ?1",
                rusqlite::params![COMMITMENT.as_slice()],
            )
            .expect("prepared");
        }
        assert_eq!(
            apply_relationship_finalized(&good.encode_to_vec()).await,
            RelationshipFinalizedOutcome::NotYetComplete
        );
        assert!(cdb::relationship_awaits_peer_finalization(&REL).unwrap());
    }
}
