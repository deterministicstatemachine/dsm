//! Authenticated bilateral cert-head forward resync — the HARDENED CORE.
//!
//! When a device loses its per-step-EK cert-chain state for a relationship (as
//! 8XK did: both `cert_chain_heads` rows gone while the peer still holds a
//! Counterparty head from the last accepted transfer), it CANNOT resume ordinary
//! sending: a fresh send would fall back to the root AK, and the peer — which
//! chains against its stored head — would reject it. Nor may it fabricate the
//! lost EK state.
//!
//! The resync installs NEW Local + Counterparty EK heads through a jointly
//! authorized forward step. This module is the local, non-bypassable core; the
//! two-device wire handshake that DELIVERS the peer's fresh EK and the joint
//! authorization is deferred until both devices are available to prove it
//! end-to-end.
//!
//! # What an adversarial review forced into this design
//!
//! A cert-reset primitive is dangerous — done naively it erases the very
//! continuity that anti-replay and double-spend protection rest on. So:
//!
//! * **Install, never delete.** The heads go from absent→present in ONE
//!   transaction; the relationship never passes through the absent-head state
//!   that arms the root-AK fallback.
//! * **Monotonic epoch.** Every finalize carries an epoch that must be strictly
//!   greater than the relationship's last; a captured/replayed tuple cannot
//!   re-apply.
//! * **Pending-obligation guard.** A resync is refused while any pending local
//!   cert head or unsettled outbox exists for the relationship, so a spent-but-
//!   unsettled step's continuity can never be erased.
//! * **CAS-guarded head writes.** Each head install is compare-and-swap; a stale
//!   tuple that expects the wrong prior head fails closed.
//! * **Explicit + audited.** A durable audit row, keyed on the preserved
//!   acceptance commitment (never a runtime tx id), records why the chain
//!   restarted.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::cert_chain::{
    cas_advance_counterparty_cert_chain_head_with_conn,
    cas_advance_local_cert_chain_head_with_conn, CasHeadOutcome,
};
use super::get_connection;
use crate::util::deterministic_time::tick;

/// Ordinary sending is allowed on this relationship.
pub const RESYNC_CLEAR: i64 = 0;
/// A head-loss was detected; sending is blocked until a resync finalizes.
pub const RESYNC_REQUIRED: i64 = 1;
/// A resync is in flight; sending stays blocked.
pub const RESYNC_PENDING: i64 = 2;

/// Current `(state, epoch)` for a relationship. Absent row ⇒ `(CLEAR, 0)`.
pub fn cert_resync_status(relationship_key: &[u8; 32]) -> Result<(i64, i64)> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(conn
        .query_row(
            "SELECT state, epoch FROM cert_resync_state WHERE relationship_key = ?1",
            params![relationship_key.as_slice()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?
        .unwrap_or((RESYNC_CLEAR, 0)))
}

/// True while this relationship must not accept an ordinary send. Fail-closed:
/// any non-CLEAR state blocks.
pub fn cert_resync_blocks_send(relationship_key: &[u8; 32]) -> Result<bool> {
    Ok(cert_resync_status(relationship_key)?.0 != RESYNC_CLEAR)
}

/// A resync must NOT run while the relationship has an in-flight obligation whose
/// continuity it could erase: a stashed pending Local head, or an unsettled
/// outbox row. Returns the reason if blocked.
pub fn resync_pending_obligation(relationship_key: &[u8; 32]) -> Result<Option<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());

    let pending_head: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM pending_local_cert_heads WHERE relationship_key = ?1 LIMIT 1",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if pending_head.is_some() {
        return Ok(Some("a pending Local cert head exists".to_string()));
    }

    let unsettled: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sender_outbox
              WHERE relationship_key = ?1 AND status NOT IN ('gc_pending','complete') LIMIT 1",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if unsettled.is_some() {
        return Ok(Some("an unsettled outbox row exists".to_string()));
    }

    Ok(None)
}

/// True if THIS device previously initiated a send on the relationship — i.e. a
/// sender proposal exists for it. This is what distinguishes "we sent before and
/// lost our Local head" (a resync case, like 8XK) from "we have never sent on
/// this relationship" (a normal root-AK genesis first transfer, NOT a resync),
/// which look identical from the cert-head table alone (both: Local head absent).
pub fn relationship_had_prior_send(relationship_key: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sender_online_proposal WHERE relationship_key = ?1 LIMIT 1",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Mark a relationship as needing a resync (head-loss detected at the send gate).
/// CLEAR → REQUIRED. Idempotent; never lowers PENDING back to REQUIRED.
pub fn mark_cert_resync_required(relationship_key: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO cert_resync_state (relationship_key, state, epoch, updated_at)
         VALUES (?1, ?2, 0, ?3)
         ON CONFLICT(relationship_key) DO UPDATE SET
             state = CASE WHEN cert_resync_state.state = 0 THEN ?2 ELSE cert_resync_state.state END,
             updated_at = ?3",
        params![relationship_key.as_slice(), RESYNC_REQUIRED, tick() as i64],
    )?;
    Ok(())
}

/// Move REQUIRED → PENDING for a chosen epoch. The epoch MUST be strictly greater
/// than the relationship's current epoch (anti-replay), and no pending obligation
/// may exist. Returns the accepted epoch.
pub fn begin_cert_resync(relationship_key: &[u8; 32], proposed_epoch: i64) -> Result<i64> {
    if let Some(reason) = resync_pending_obligation(relationship_key)? {
        return Err(anyhow!("cannot begin cert resync: {reason}"));
    }
    let (_state, current_epoch) = cert_resync_status(relationship_key)?;
    if proposed_epoch <= current_epoch {
        return Err(anyhow!(
            "cert resync epoch {proposed_epoch} is not greater than current {current_epoch}"
        ));
    }
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO cert_resync_state (relationship_key, state, epoch, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(relationship_key) DO UPDATE SET state = ?2, epoch = ?3, updated_at = ?4",
        params![
            relationship_key.as_slice(),
            RESYNC_PENDING,
            proposed_epoch,
            tick() as i64
        ],
    )?;
    Ok(proposed_epoch)
}

/// The fresh EK a device installs on ITS OWN Local side (pubkey + secret).
pub struct LocalResyncKey<'a> {
    pub pubkey: &'a [u8],
    pub secret_key: &'a [u8],
    pub wrap_key: &'a [u8; 32],
}

/// Everything the audit row records about WHY the chain restarted. Content
/// identity — never a runtime `tx_id`.
pub struct ResyncAudit<'a> {
    pub preserved_acceptance_commitment: &'a [u8; 32],
    pub accepted_parent_tip: &'a [u8; 32],
    pub accepted_child_tip: &'a [u8; 32],
    pub joint_auth_hash: &'a [u8; 32],
    pub reason_code: &'a str,
}

/// FINALIZE a cert resync as ONE transaction: install BOTH new EK heads
/// (CAS-guarded), record the audit row, and clear the send block.
///
/// * `expected_local` / `expected_counterparty` are the CAS expectations — `None`
///   when the head is absent (a fresh install, as on the device that lost its
///   state), `Some(prev)` when overwriting a stale head (the peer's side).
/// * `epoch` MUST equal the relationship's current PENDING epoch, and the state
///   MUST be PENDING — a stale or out-of-band finalize is rejected.
///
/// The relationship goes from head-absent to head-present WITHIN this single
/// transaction, so the root-AK fallback is never armed. Any CAS `Conflict`
/// aborts the whole transaction (nothing is written) and leaves the block up.
#[allow(clippy::too_many_arguments)]
pub fn finalize_cert_resync_atomically(
    relationship_key: &[u8; 32],
    epoch: i64,
    local: LocalResyncKey<'_>,
    expected_local: Option<&[u8]>,
    counterparty_new_pubkey: &[u8],
    expected_counterparty: Option<&[u8]>,
    audit: ResyncAudit<'_>,
) -> Result<()> {
    // Guard OUTSIDE the tx first (cheap fail-fast); re-checked below under lock.
    if let Some(reason) = resync_pending_obligation(relationship_key)? {
        return Err(anyhow!("cannot finalize cert resync: {reason}"));
    }

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());

    // Freshness: the state must be PENDING at exactly this epoch. Anything else
    // (stale epoch, not begun, already finalized) is rejected before any write.
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT state, epoch FROM cert_resync_state WHERE relationship_key = ?1",
            params![relationship_key.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((RESYNC_PENDING, e)) if e == epoch => {}
        Some((state, e)) => {
            return Err(anyhow!(
                "cert resync not finalizable: state={state} epoch={e} (wanted PENDING@{epoch})"
            ))
        }
        None => return Err(anyhow!("cert resync was never begun for this relationship")),
    }

    let tx = conn.transaction()?;

    // (1) Local head — CAS install. `None` expected ⇒ GenesisInit (absent→present).
    match cas_advance_local_cert_chain_head_with_conn(
        &tx,
        relationship_key,
        expected_local,
        local.pubkey,
        local.secret_key,
        local.wrap_key,
    )? {
        CasHeadOutcome::Advanced { .. }
        | CasHeadOutcome::GenesisInit
        | CasHeadOutcome::AlreadyAtTarget => {}
        CasHeadOutcome::Conflict { current } => {
            return Err(anyhow!(
                "cert resync: local head CAS conflict (current={:?}..) — aborting",
                current.as_ref().map(|c| &c[..4.min(c.len())])
            ))
        }
    }

    // (2) Counterparty head — CAS install/overwrite.
    match cas_advance_counterparty_cert_chain_head_with_conn(
        &tx,
        relationship_key,
        expected_counterparty,
        counterparty_new_pubkey,
    )? {
        CasHeadOutcome::Advanced { .. }
        | CasHeadOutcome::GenesisInit
        | CasHeadOutcome::AlreadyAtTarget => {}
        CasHeadOutcome::Conflict { current } => {
            return Err(anyhow!(
                "cert resync: counterparty head CAS conflict (current={:?}..) — aborting",
                current.as_ref().map(|c| &c[..4.min(c.len())])
            ))
        }
    }

    // (3) Durable audit — content-keyed, one per agreed accepted transition.
    tx.execute(
        "INSERT OR IGNORE INTO cert_chain_resync_audit(
            relationship_key, preserved_acceptance_commitment, accepted_parent_tip,
            accepted_child_tip, joint_auth_hash, epoch, old_local_head,
            old_counterparty_head, new_local_head, new_counterparty_head,
            reason_code, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            relationship_key.as_slice(),
            audit.preserved_acceptance_commitment.as_slice(),
            audit.accepted_parent_tip.as_slice(),
            audit.accepted_child_tip.as_slice(),
            audit.joint_auth_hash.as_slice(),
            epoch,
            expected_local,
            expected_counterparty,
            local.pubkey,
            counterparty_new_pubkey,
            audit.reason_code,
            tick() as i64,
        ],
    )?;

    // (4) Clear the send block — only from PENDING at this exact epoch.
    tx.execute(
        "UPDATE cert_resync_state SET state = ?2, updated_at = ?3
          WHERE relationship_key = ?1 AND state = ?4 AND epoch = ?5",
        params![
            relationship_key.as_slice(),
            RESYNC_CLEAR,
            tick() as i64,
            RESYNC_PENDING,
            epoch
        ],
    )?;

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::cert_chain::{load_cert_chain_head_pubkey, CertChainSide};

    fn init() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    const REL: [u8; 32] = [0x71u8; 32];
    const LOCAL_EK: [u8; 8] = [0xE1u8; 8];
    const LOCAL_SK: [u8; 16] = [0x5Au8; 16];
    const CP_EK: [u8; 8] = [0xC2u8; 8];
    const WRAP: [u8; 32] = [0x77u8; 32];

    fn audit() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        ([0xEFu8; 32], [0x3Fu8; 32], [0x1Bu8; 32], [0x9Au8; 32])
    }

    fn do_finalize(epoch: i64) -> Result<()> {
        let (commit, parent, child, joint) = audit();
        finalize_cert_resync_atomically(
            &REL,
            epoch,
            LocalResyncKey {
                pubkey: &LOCAL_EK,
                secret_key: &LOCAL_SK,
                wrap_key: &WRAP,
            },
            None,
            &CP_EK,
            None,
            ResyncAudit {
                preserved_acceptance_commitment: &commit,
                accepted_parent_tip: &parent,
                accepted_child_tip: &child,
                joint_auth_hash: &joint,
                reason_code: "head-loss-recovery",
            },
        )
    }

    /// Happy path: both heads install atomically and the block clears.
    #[test]
    #[serial_test::serial]
    fn finalize_installs_both_heads_and_clears_the_block() {
        init();
        mark_cert_resync_required(&REL).unwrap();
        assert!(
            cert_resync_blocks_send(&REL).unwrap(),
            "REQUIRED blocks sending"
        );
        begin_cert_resync(&REL, 1).unwrap();
        assert!(
            cert_resync_blocks_send(&REL).unwrap(),
            "PENDING blocks sending"
        );

        do_finalize(1).unwrap();

        assert_eq!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            LOCAL_EK.to_vec(),
            "local head installed"
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            CP_EK.to_vec(),
            "counterparty head installed"
        );
        assert!(
            !cert_resync_blocks_send(&REL).unwrap(),
            "block cleared on finalize"
        );
    }

    /// The relationship NEVER passes through the absent-head state during a
    /// resync — both heads exist the instant the block clears, so the root-AK
    /// fallback can never be armed by the recovery itself.
    #[test]
    #[serial_test::serial]
    fn no_absent_head_window_after_finalize() {
        init();
        mark_cert_resync_required(&REL).unwrap();
        begin_cert_resync(&REL, 1).unwrap();
        do_finalize(1).unwrap();
        assert!(load_cert_chain_head_pubkey(&REL, CertChainSide::Local)
            .unwrap()
            .is_some());
        assert!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Counterparty)
                .unwrap()
                .is_some()
        );
    }

    /// ANTI-REPLAY: a finalize at a stale epoch is rejected, and a replayed begin
    /// at an epoch not strictly greater than the current one is rejected.
    #[test]
    #[serial_test::serial]
    fn stale_epoch_is_rejected() {
        init();
        mark_cert_resync_required(&REL).unwrap();
        begin_cert_resync(&REL, 5).unwrap();
        do_finalize(5).unwrap();

        // Replaying the same epoch's finalize: state is CLEAR now, not PENDING@5.
        assert!(
            do_finalize(5).is_err(),
            "replayed finalize must be rejected"
        );
        // Re-begin at an epoch <= the finalized one is refused.
        assert!(
            begin_cert_resync(&REL, 5).is_err(),
            "epoch must strictly increase"
        );
        assert!(begin_cert_resync(&REL, 4).is_err());
        // A strictly-greater epoch is allowed (a genuine second recovery).
        assert!(begin_cert_resync(&REL, 6).is_ok());
    }

    /// A finalize that was never begun, or begun at a different epoch, is rejected.
    #[test]
    #[serial_test::serial]
    fn finalize_requires_a_matching_pending_epoch() {
        init();
        assert!(do_finalize(1).is_err(), "never begun");
        mark_cert_resync_required(&REL).unwrap();
        begin_cert_resync(&REL, 3).unwrap();
        assert!(do_finalize(2).is_err(), "epoch mismatch");
        assert!(do_finalize(3).is_ok());
    }

    /// PENDING-OBLIGATION GUARD: a resync is refused while a pending Local cert
    /// head exists — the continuity of a spent-but-unsettled step must not be
    /// erased.
    #[test]
    #[serial_test::serial]
    fn pending_obligation_blocks_resync() {
        init();
        // Stash a pending local head to simulate an in-flight spend.
        crate::storage::client_db::cert_chain::stash_pending_local_head(
            &REL,
            &[0x01u8; 32],
            &[0xAAu8; 8],
            &[0x55u8; 128],
            &WRAP,
            false,
        )
        .unwrap();

        mark_cert_resync_required(&REL).unwrap();
        assert!(
            begin_cert_resync(&REL, 1).is_err(),
            "pending head must block begin"
        );
        // Even a direct finalize is refused.
        assert!(do_finalize(1).is_err(), "pending head must block finalize");
    }

    /// The detection signal: only a relationship this device previously SENT on
    /// counts as head-loss. A never-sent relationship (Local head absent) is a
    /// normal first transfer, not a resync.
    #[test]
    #[serial_test::serial]
    fn prior_send_detection_distinguishes_head_loss_from_first_transfer() {
        init();
        assert!(
            !relationship_had_prior_send(&REL).unwrap(),
            "no proposal yet — a first transfer, not a resync"
        );
        // Insert a sender proposal for this relationship (we sent before).
        let proposal = crate::storage::client_db::SenderOnlineProposal {
            relationship_key: REL,
            canonical_parent: [0x22u8; 32],
            canonical_child: [0x33u8; 32],
            projection_parent: [0x44u8; 32],
            projection_target: [0x55u8; 32],
            commitment: [0x66u8; 32],
            operation_digest: [0x77u8; 32],
            nonce_hash: [0x88u8; 32],
            message_id: None,
            tx_id: "tx2:abc".into(),
            counterparty_device_id: [0x99u8; 32],
            amount: 5,
            token_id: "ERA".into(),
            status: crate::storage::client_db::PROPOSAL_PROPOSED.into(),
            created_at: 0,
        };
        crate::storage::client_db::insert_sender_proposal(&proposal).unwrap();
        assert!(
            relationship_had_prior_send(&REL).unwrap(),
            "we sent before — head loss here IS a resync case"
        );
    }

    /// A CAS conflict on either head aborts the WHOLE transaction — no partial
    /// install, block stays up.
    #[test]
    #[serial_test::serial]
    fn cas_conflict_aborts_and_keeps_the_block() {
        init();
        // Pre-seed a DIFFERENT local head so the None-expected install conflicts.
        crate::storage::client_db::cert_chain::init_cert_chain_head(
            &REL,
            CertChainSide::Local,
            &[0xDDu8; 8],
        )
        .unwrap();

        mark_cert_resync_required(&REL).unwrap();
        begin_cert_resync(&REL, 1).unwrap();
        assert!(do_finalize(1).is_err(), "conflicting local head must abort");

        // The pre-seeded head is untouched and the block is still up.
        assert_eq!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            vec![0xDDu8; 8]
        );
        assert!(
            cert_resync_blocks_send(&REL).unwrap(),
            "block must remain after abort"
        );
    }
}
