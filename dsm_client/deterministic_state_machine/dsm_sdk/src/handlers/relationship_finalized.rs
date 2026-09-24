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
    use crate::test_support::arrivals::arrivals_for;
    use crate::test_support::two_device::{Pair, TestDevice};
    use prost::Message;
    use serial_test::serial;

    /// A sent B 10, B applied and replied, A finalized and shipped its
    /// certificate. The certificate as B's poll reads it, with B entered.
    async fn certified() -> (Pair, Vec<u8>) {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        let finalized = p.a.sync().await;
        assert!(finalized.success, "{:?}", finalized.errors);
        let certificate = arrivals_for(&p.b, &p.fleet)
            .await
            .certificates
            .pop()
            .expect("A's certificate is on the members")
            .body;
        p.b.enter();
        (p, certificate)
    }

    fn awaiting(p: &Pair) -> bool {
        cdb::relationship_awaits_peer_finalization(&p.a.rel_key_with(&p.b)).expect("await")
    }

    /// The certificate releases the recipient exactly once and is idempotent
    /// on re-serve; a substituted field, a foreign body on the certificate
    /// method, or a signature under a key that is not the journal's A head is
    /// refused with `peer_finalized` untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_verified_certificate_releases_the_recipient_once_and_forgeries_do_not() {
        let (p, body) = certified().await;
        assert!(awaiting(&p), "B awaits A's finality");
        let good = RelationshipFinalizedV1::decode(body.as_slice()).expect("the certificate");

        for (label, edit) in [
            ("sender child", 0usize),
            ("recipient parent", 1),
            ("recipient child", 2),
            ("recipient", 3),
            ("sender", 4),
        ] {
            let mut forged = good.clone();
            match edit {
                0 => forged.sender_child_tip_a[0] ^= 1,
                1 => forged.recipient_parent_tip_b[0] ^= 1,
                2 => forged.recipient_child_tip_b[0] ^= 1,
                3 => forged.recipient_device_id[0] ^= 1,
                _ => forged.sender_device_id[0] ^= 1,
            }
            let out = apply_relationship_finalized(&forged.encode_to_vec()).await;
            assert!(
                matches!(
                    out,
                    RelationshipFinalizedOutcome::Rejected(_)
                        | RelationshipFinalizedOutcome::NoJournal
                ),
                "{label}: {out:?}"
            );
            assert!(awaiting(&p), "{label}: B still awaits");
        }

        // The right fields signed by a key that is not A's head for the step.
        let foreign_sk = dsm::crypto::sphincs::generate_sphincs_keypair()
            .expect("a foreign key")
            .1;
        let mut foreign = good.clone();
        foreign.signature_a = dsm::crypto::sphincs::sphincs_sign(
            &foreign_sk,
            &relationship_finalized_signing_target(&foreign),
        )
        .expect("sign");
        match apply_relationship_finalized(&foreign.encode_to_vec()).await {
            RelationshipFinalizedOutcome::Rejected(r) => assert!(r.contains("signature"), "{r}"),
            other => panic!("a foreign signer must be rejected, got {other:?}"),
        }
        assert!(awaiting(&p));

        // A body that is not a certificate is refused at the wire.
        assert!(matches!(
            apply_relationship_finalized(&good.sender_child_tip_a).await,
            RelationshipFinalizedOutcome::WireRejected(_)
        ));

        assert_eq!(
            apply_relationship_finalized(&body).await,
            RelationshipFinalizedOutcome::Applied
        );
        assert!(!awaiting(&p), "the honest certificate released B");
        assert_eq!(
            apply_relationship_finalized(&body).await,
            RelationshipFinalizedOutcome::AlreadyFinalized,
            "re-serve is idempotent"
        );
    }

    /// A certificate for a transition this device never journaled is not
    /// its: dropped as not-ours, nothing written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_certificate_for_a_transition_never_journaled_is_not_ours() {
        let (p, body) = certified().await;
        let mut c = TestDevice::create("C", 0x0C);
        c.boot(&p.fleet).await;
        c.enter();
        assert_eq!(
            apply_relationship_finalized(&body).await,
            RelationshipFinalizedOutcome::NoJournal
        );
    }
}
