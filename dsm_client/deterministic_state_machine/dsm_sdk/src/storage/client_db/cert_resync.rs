// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authenticated bilateral cert-head forward resync — the HARDENED CORE.
//!
//! When a device loses its per-step-EK cert-chain state for a relationship (as
//! 8XK did: both `cert_chain_heads` rows gone while the peer still holds a
//! Counterparty head from the last accepted transfer), it CANNOT resume ordinary
//! sending: a fresh send would fall back to the root AK, and the peer — which
//! chains against its stored head — would reject it. Nor may it fabricate the
//! lost EK state.
//!
//! The resync continues the lost chain through a restart step both AKs sign
//! (DSM Amendment A20), and installs the new Local + Counterparty EK heads with
//! it. This module is the device's local, non-bypassable half: the head writes,
//! the restart step recorded as the next step of the restarting device's chain,
//! the epoch record, the guards, the audit row and the relationship's latest
//! accepted step. The statements both AKs sign, the restart step's bytes, the
//! signature and chain checks and the epoch rule are Core's
//! (`dsm::bilateral::cert_resync`, `dsm::economic::peer_acceptance`); the
//! two-device handshake is `handlers::cert_resync_flow`.
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

/// Whether a per-step EK this device signed with waits, pending, for its
/// transition's finalization on this relationship: the head of a step in
/// flight, not a lost one.
pub fn pending_local_head_exists(relationship_key: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM pending_local_cert_heads WHERE relationship_key = ?1 LIMIT 1",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// True if this device took part in a step of the relationship: it proposed a
/// send on it, or it accepted a step its counterparty sent. Every accepted
/// step leaves both devices a cert head, so a Local head absent after one is
/// lost (a resync case, like 8XK); with none, the Local head is absent because
/// the relationship has no step yet (a normal root-AK genesis first transfer,
/// NOT a resync). The two look identical from the cert-head table alone.
pub fn relationship_had_prior_step(relationship_key: &[u8; 32]) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sender_online_proposal WHERE relationship_key = ?1
             UNION ALL
             SELECT 1 FROM acceptance_fold_journal
              WHERE relationship_key = ?1 AND status IN (?2, ?3)
             LIMIT 1",
            params![
                relationship_key.as_slice(),
                super::recipient_receipt_fold::STATUS_APPLIED,
                super::recipient_receipt_fold::STATUS_COMPLETE
            ],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// The relationship's latest accepted step as this device records it (DSM
/// Amendment A20): the step, sent and finalized or received and applied,
/// whose projection target is `current_tip`, the relationship's current tip.
/// `None` when no accepted step reaches that tip. Two records of it that
/// disagree are an unusable store, never a choice.
pub fn latest_accepted_step(
    relationship_key: &[u8; 32],
    current_tip: &[u8; 32],
) -> Result<Option<dsm::bilateral::cert_resync::AgreedStep>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the store's lock is poisoned: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT commitment, canonical_parent FROM sender_online_proposal
          WHERE relationship_key = ?1 AND status = ?2 AND projection_target = ?3
         UNION
         SELECT commitment, parent_tip FROM acceptance_fold_journal
          WHERE relationship_key = ?1 AND status IN (?4, ?5) AND projection_target_tip = ?3",
    )?;
    let rows = stmt
        .query_map(
            params![
                relationship_key.as_slice(),
                super::sender_proposal::PROPOSAL_FINALIZED,
                current_tip.as_slice(),
                super::recipient_receipt_fold::STATUS_APPLIED,
                super::recipient_receipt_fold::STATUS_COMPLETE
            ],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match rows.as_slice() {
        [] => Ok(None),
        [(commitment, receipt_parent)] => Ok(Some(dsm::bilateral::cert_resync::AgreedStep {
            tip: *current_tip,
            commitment: <[u8; 32]>::try_from(commitment.as_slice())
                .map_err(|e| anyhow!("the accepted step's commitment is not 32 bytes: {e}"))?,
            receipt_parent: <[u8; 32]>::try_from(receipt_parent.as_slice())
                .map_err(|e| anyhow!("the accepted step's receipt parent is not 32 bytes: {e}"))?,
        })),
        more => Err(anyhow!(
            "{} different accepted steps reach the relationship's current tip",
            more.len()
        )),
    }
}

/// Mark a relationship as needing a resync (head-loss detected at the send gate).
/// CLEAR → REQUIRED. Idempotent; never lowers PENDING back to REQUIRED.
pub fn mark_cert_resync_required(relationship_key: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO cert_resync_state (relationship_key, state, epoch)
         VALUES (?1, ?2, 0)
         ON CONFLICT(relationship_key) DO UPDATE SET
             state = CASE WHEN cert_resync_state.state = 0 THEN ?2 ELSE cert_resync_state.state END",
        params![relationship_key.as_slice(), RESYNC_REQUIRED],
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
    dsm::bilateral::cert_resync::cert_resync_epoch_advances(proposed_epoch, current_epoch)
        .map_err(|e| anyhow!("cannot begin cert resync: {e}"))?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO cert_resync_state (relationship_key, state, epoch)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(relationship_key) DO UPDATE SET state = ?2, epoch = ?3",
        params![relationship_key.as_slice(), RESYNC_PENDING, proposed_epoch],
    )?;
    Ok(proposed_epoch)
}

/// Relationships currently in REQUIRED state (detected head-loss, resync not yet
/// initiated). The poller drives these to PENDING by sending a request.
pub fn relationships_requiring_resync() -> Result<Vec<[u8; 32]>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    // REQUIRED (never started) AND PENDING (started but not finalized — a lost ack
    // or a stale-format peer). Re-initiating bumps the epoch, so a retry is a fresh
    // request the peer accepts; a stranded resync self-heals.
    let mut stmt =
        conn.prepare("SELECT relationship_key FROM cert_resync_state WHERE state IN (?1, ?2)")?;
    let rows = stmt
        .query_map(params![RESYNC_REQUIRED, RESYNC_PENDING], |r| {
            r.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .collect())
}

/// Outcome of the tagged-hash-cut preflight. Total, so a caller cannot read it
/// as a bare bool and proceed on an ambiguous answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CutPreflight {
    /// Nothing outstanding: no relationship owes a resync and no unacked spool
    /// row exists. Safe to upgrade.
    Clear,
    /// Relationships are mid-resync. Their in-flight restart statements were
    /// derived under the pre-cut digest and cannot be reproduced after it.
    OutstandingResyncs(usize),
}

impl CutPreflight {
    /// Only `Clear` permits the upgrade.
    pub fn may_upgrade(&self) -> bool {
        matches!(self, CutPreflight::Clear)
    }
}

/// Deployment preflight for the canonical tagged-hash cut — executable, not
/// prose. See `docs/adr/0001-impact-table.md`.
///
/// Covers B3: a resync already in flight cannot be completed across the cut,
/// because the digest moves and the two sides would derive different restart
/// statements. The B5/B6 message ids need no drain: the node's spool keeps
/// every entry and deduplicates none (storage spec §8), and the recipient's
/// replay check is keyed by what it decodes.
///
/// **This check is only meaningful while producers are disabled.** Run it as
/// step 3 of the documented sequence — disable producers and retries, let
/// deliveries settle, THEN call this, and keep producers disabled through the
/// upgrade. Called with traffic live it samples a moving target.
pub fn tagged_hash_cut_preflight() -> Result<CutPreflight> {
    let outstanding = relationships_requiring_resync()?;
    if !outstanding.is_empty() {
        return Ok(CutPreflight::OutstandingResyncs(outstanding.len()));
    }

    Ok(CutPreflight::Clear)
}

/// True while any relationship owes a resync (REQUIRED or PENDING). Keeps the
/// poller alive so the recovery actually runs.
pub fn has_outstanding_cert_resync() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM cert_resync_state WHERE state IN (?1, ?2) LIMIT 1",
            params![RESYNC_REQUIRED, RESYNC_PENDING],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// The fresh EK a device installs on ITS OWN Local side (pubkey + secret).
pub struct LocalResyncKey<'a> {
    pub pubkey: &'a [u8],
    pub secret_key: &'a [u8],
    pub wrap_key: &'a [u8; 32],
}

/// Everything the audit row records about WHY the chain restarted: the
/// restart statement both AKs signed, its facts and nothing either side would
/// have to supply from its own partial record.
pub struct ResyncAudit<'a> {
    /// The restart's own epoch. The restarting device may have asked again
    /// under a later one before the confirmation of this one arrived.
    pub epoch: i64,
    pub preserved_acceptance_commitment: &'a [u8; 32],
    pub agreed_tip: &'a [u8; 32],
    pub restart_statement: &'a [u8; 32],
    pub reason_code: &'a str,
}

/// One step a finalize records in a signer's chain: the restart step in the
/// restarting device's chain, and on that device the counterparty's latest
/// step when its own record of the counterparty's chain was lost with its
/// heads.
pub struct ResyncStep<'a> {
    pub signer: [u8; 32],
    pub addr: [u8; 32],
    pub key: &'a [u8],
}

/// FINALIZE a cert resync as ONE transaction: install BOTH new EK heads
/// (CAS-guarded), record `steps` in their signers' chains, record the audit
/// row, and clear the send block.
///
/// * `expected_local` / `expected_counterparty` are the CAS expectations — `None`
///   when the head is absent (a fresh install, as on the device that lost its
///   state), `Some(prev)` when overwriting a stale head (the peer's side).
/// * `epoch` MUST equal the relationship's current PENDING epoch, and the state
///   MUST be PENDING — a stale or out-of-band finalize is rejected. The
///   restart's own epoch, at or below it, is the audit's.
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
    steps: &[ResyncStep<'_>],
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

    // (3) The restart step (and the counterparty's step, when this device's
    // record of it was lost) in their signers' chains: the next acceptance
    // bundle names the restart step as this device's predecessor.
    for step in steps {
        super::economic_lineage::append_ek_step_with_conn(
            &tx,
            relationship_key,
            &step.signer,
            &step.addr,
            step.key,
        )?;
    }

    // (4) Durable audit, one row per epoch.
    tx.execute(
        "INSERT INTO cert_chain_resync_audit(
            relationship_key, preserved_acceptance_commitment, agreed_tip,
            joint_auth_hash, epoch, old_local_head, old_counterparty_head,
            new_local_head, new_counterparty_head, reason_code)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            relationship_key.as_slice(),
            audit.preserved_acceptance_commitment.as_slice(),
            audit.agreed_tip.as_slice(),
            audit.restart_statement.as_slice(),
            audit.epoch,
            expected_local,
            expected_counterparty,
            local.pubkey,
            counterparty_new_pubkey,
            audit.reason_code,
        ],
    )?;

    // (5) Clear the send block — only from PENDING at this exact epoch.
    tx.execute(
        "UPDATE cert_resync_state SET state = ?2
          WHERE relationship_key = ?1 AND state = ?3 AND epoch = ?4",
        params![
            relationship_key.as_slice(),
            RESYNC_CLEAR,
            RESYNC_PENDING,
            epoch
        ],
    )?;

    tx.commit()?;
    Ok(())
}

/// Responder-side finalize (the HEALTHY peer, e.g. D3). ASYMMETRIC: it does NOT
/// touch its own Local head — it CAS-advances the STALE Counterparty head it
/// holds for the initiator to the initiator's fresh EK, records the restart
/// step as the next step of the initiator's chain, records the epoch, and
/// audits. One transaction.
///
/// The healthy side is never blocked from sending, so there is no send-gate to
/// clear here — but the epoch is still recorded and must strictly increase, so a
/// replayed request cannot re-drive it.
#[allow(clippy::too_many_arguments)]
pub fn finalize_cert_resync_responder_atomically(
    relationship_key: &[u8; 32],
    epoch: i64,
    counterparty_new_pubkey: &[u8],
    expected_counterparty: Option<&[u8]>,
    restart_step: ResyncStep<'_>,
    audit: ResyncAudit<'_>,
    responder_local_head: &[u8],
) -> Result<()> {
    if let Some(reason) = resync_pending_obligation(relationship_key)? {
        return Err(anyhow!("responder cannot finalize cert resync: {reason}"));
    }
    let (_state, current_epoch) = cert_resync_status(relationship_key)?;
    dsm::bilateral::cert_resync::cert_resync_epoch_advances(epoch, current_epoch)
        .map_err(|e| anyhow!("responder cannot finalize cert resync: {e}"))?;

    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;

    // Counterparty head only — CAS-advance the stale head to the initiator's EK.
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
                "responder cert resync: counterparty CAS conflict (current={:?}..)",
                current.as_ref().map(|c| &c[..4.min(c.len())])
            ))
        }
    }

    super::economic_lineage::append_ek_step_with_conn(
        &tx,
        relationship_key,
        &restart_step.signer,
        &restart_step.addr,
        restart_step.key,
    )?;

    tx.execute(
        "INSERT INTO cert_chain_resync_audit(
            relationship_key, preserved_acceptance_commitment, agreed_tip,
            joint_auth_hash, epoch, old_local_head, old_counterparty_head,
            new_local_head, new_counterparty_head, reason_code)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            relationship_key.as_slice(),
            audit.preserved_acceptance_commitment.as_slice(),
            audit.agreed_tip.as_slice(),
            audit.restart_statement.as_slice(),
            audit.epoch,
            responder_local_head, // old_local_head == kept (unchanged)
            expected_counterparty,
            responder_local_head, // new_local_head == same (asymmetric: untouched)
            counterparty_new_pubkey,
            audit.reason_code,
        ],
    )?;

    // Record the epoch (state stays CLEAR — the responder is not blocked).
    tx.execute(
        "INSERT INTO cert_resync_state (relationship_key, state, epoch)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(relationship_key) DO UPDATE SET epoch = ?3",
        params![relationship_key.as_slice(), RESYNC_CLEAR, epoch],
    )?;

    tx.commit()?;
    Ok(())
}

// ---- wire framing (rides ArgPack.body; no proto change) ----

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}
/// The length-prefixed field at `*off` in `b`, advancing `*off` past it. The
/// length is the sender's: every offset is computed checked, so a length that
/// would run past the body (or past `usize` on a 32-bit device) is a body
/// that does not decode, never an overflow.
fn take_bytes<'a>(b: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let len_end = off.checked_add(4)?;
    let &[l0, l1, l2, l3] = b.get(*off..len_end)? else {
        return None;
    };
    // A u32 always fits a usize on the targets DSM builds for (32 and 64 bit).
    let end = len_end.checked_add(u32::from_le_bytes([l0, l1, l2, l3]) as usize)?;
    let s = b.get(len_end..end)?;
    *off = end;
    Some(s)
}

/// The 32-byte field at `*off`, advancing past it; `None` past the body.
fn take_fixed(b: &[u8], off: &mut usize) -> Option<[u8; 32]> {
    let field = *b.get(*off..)?.first_chunk::<32>()?;
    *off = off.checked_add(32)?;
    Some(field)
}

/// The little-endian epoch at `*off`, advancing past it; `None` past the body.
fn take_epoch(b: &[u8], off: &mut usize) -> Option<i64> {
    let field = i64::from_le_bytes(*b.get(*off..)?.first_chunk::<8>()?);
    *off = off.checked_add(8)?;
    Some(field)
}

/// MSG1 — initiator → responder. Asks for a restart under the initiator's AK:
/// the agreed accepted tip and its commitment, the epoch and the new key
/// (`restart_request_statement`). The predecessor is the responder's to
/// supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertResyncRequest {
    pub relationship_key: [u8; 32],
    pub agreed_tip: [u8; 32],
    pub epoch: i64,
    pub preserved_acceptance_commitment: [u8; 32],
    /// The tip the INITIATOR actually polls for its inbox — the responder MUST
    /// address its answers here, or they strand (the initiator's own
    /// relationship tip may have diverged from `agreed_tip`).
    pub reply_to_tip: [u8; 32],
    pub new_key: Vec<u8>,
    pub request_sig: Vec<u8>,
}

impl CertResyncRequest {
    pub fn to_body(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.relationship_key);
        o.extend_from_slice(&self.agreed_tip);
        o.extend_from_slice(&self.epoch.to_le_bytes());
        o.extend_from_slice(&self.preserved_acceptance_commitment);
        o.extend_from_slice(&self.reply_to_tip);
        put_bytes(&mut o, &self.new_key);
        put_bytes(&mut o, &self.request_sig);
        o
    }
    pub fn from_body(b: &[u8]) -> Option<Self> {
        let mut off = 0;
        let relationship_key = take_fixed(b, &mut off)?;
        let agreed_tip = take_fixed(b, &mut off)?;
        let epoch = take_epoch(b, &mut off)?;
        let preserved_acceptance_commitment = take_fixed(b, &mut off)?;
        let reply_to_tip = take_fixed(b, &mut off)?;
        let new_key = take_bytes(b, &mut off)?.to_vec();
        let request_sig = take_bytes(b, &mut off)?.to_vec();
        Some(Self {
            relationship_key,
            agreed_tip,
            epoch,
            preserved_acceptance_commitment,
            reply_to_tip,
            new_key,
            request_sig,
        })
    }
}

/// MSG2 — responder → initiator. The predecessor (the initiator's latest step
/// as the responder holds it), the responder's own latest step, and the
/// responder's AK signature over the restart statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertResyncOffer {
    pub relationship_key: [u8; 32],
    pub epoch: i64,
    pub predecessor: [u8; 32],
    pub counterparty_step: [u8; 32],
    pub counterparty_sig: Vec<u8>,
}

impl CertResyncOffer {
    pub fn to_body(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.relationship_key);
        o.extend_from_slice(&self.epoch.to_le_bytes());
        o.extend_from_slice(&self.predecessor);
        o.extend_from_slice(&self.counterparty_step);
        put_bytes(&mut o, &self.counterparty_sig);
        o
    }
    pub fn from_body(b: &[u8]) -> Option<Self> {
        let mut off = 0;
        let relationship_key = take_fixed(b, &mut off)?;
        let epoch = take_epoch(b, &mut off)?;
        let predecessor = take_fixed(b, &mut off)?;
        let counterparty_step = take_fixed(b, &mut off)?;
        let counterparty_sig = take_bytes(b, &mut off)?.to_vec();
        Some(Self {
            relationship_key,
            epoch,
            predecessor,
            counterparty_step,
            counterparty_sig,
        })
    }
}

/// MSG3 — initiator → responder. The address of the restart step, both
/// signatures in it, published before this is sent; and where to answer.
/// The step travels by its address: two SPHINCS+ signatures alone come near
/// the spool's envelope cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertResyncConfirm {
    pub relationship_key: [u8; 32],
    pub reply_to_tip: [u8; 32],
    pub restart_step: [u8; 32],
}

impl CertResyncConfirm {
    pub fn to_body(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.relationship_key);
        o.extend_from_slice(&self.reply_to_tip);
        o.extend_from_slice(&self.restart_step);
        o
    }
    pub fn from_body(b: &[u8]) -> Option<Self> {
        let mut off = 0;
        let relationship_key = take_fixed(b, &mut off)?;
        let reply_to_tip = take_fixed(b, &mut off)?;
        let restart_step = take_fixed(b, &mut off)?;
        Some(Self {
            relationship_key,
            reply_to_tip,
            restart_step,
        })
    }
}

/// MSG4 — responder → initiator. The address of the restart step the
/// responder recorded, its own latest step, and its AK signature over both
/// addresses (`restart_done_statement`). The initiator takes the restart only
/// on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertResyncDone {
    pub relationship_key: [u8; 32],
    pub restart_step: [u8; 32],
    pub counterparty_step: [u8; 32],
    pub done_sig: Vec<u8>,
}

impl CertResyncDone {
    pub fn to_body(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.relationship_key);
        o.extend_from_slice(&self.restart_step);
        o.extend_from_slice(&self.counterparty_step);
        put_bytes(&mut o, &self.done_sig);
        o
    }
    pub fn from_body(b: &[u8]) -> Option<Self> {
        let mut off = 0;
        let relationship_key = take_fixed(b, &mut off)?;
        let restart_step = take_fixed(b, &mut off)?;
        let counterparty_step = take_fixed(b, &mut off)?;
        let done_sig = take_bytes(b, &mut off)?.to_vec();
        Some(Self {
            relationship_key,
            restart_step,
            counterparty_step,
            done_sig,
        })
    }
}

/// Wire method discriminators (ride existing UniversalTx tag 10; client-side only).
pub const CERT_RESYNC_REQUEST_METHOD: &str = "wallet.certResyncRequest";
pub const CERT_RESYNC_OFFER_METHOD: &str = "wallet.certResyncOffer";
pub const CERT_RESYNC_CONFIRM_METHOD: &str = "wallet.certResyncConfirm";
pub const CERT_RESYNC_DONE_METHOD: &str = "wallet.certResyncDone";

/// Every cert-resync method, in the order the handshake runs.
pub const CERT_RESYNC_METHODS: [&str; 4] = [
    CERT_RESYNC_REQUEST_METHOD,
    CERT_RESYNC_OFFER_METHOD,
    CERT_RESYNC_CONFIRM_METHOD,
    CERT_RESYNC_DONE_METHOD,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// SA-146. A contact's request can set this relationship's epoch to the
    /// largest there is. The next resync this device starts on it then has no
    /// epoch, which is refused for this relationship; it used to overflow and
    /// panic the storage sync before any route's inbox was taken in.
    /// MUTATION CONTROL: computing the next epoch with an unchecked `+ 1`
    /// turns this red (it panics).
    #[test]
    #[serial_test::serial]
    fn a_relationship_whose_epochs_are_spent_cannot_be_resynced_and_panics_nothing() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
        let rel = [0x61u8; 32];
        begin_cert_resync(&rel, i64::MAX).expect("a contact's request at the largest epoch");
        let refused = crate::handlers::cert_resync_flow::next_resync_epoch(&rel)
            .expect_err("no epoch follows the largest");
        assert!(
            refused.to_string().contains("epochs are spent"),
            "{refused}"
        );
        assert_eq!(
            crate::handlers::cert_resync_flow::next_resync_epoch(&[0x62u8; 32])
                .expect("a fresh one"),
            1
        );
    }

    use crate::storage::client_db::cert_chain::{load_cert_chain_head_pubkey, CertChainSide};

    fn init() {
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    const REL: [u8; 32] = [0x71u8; 32];
    const LOCAL_EK: [u8; 8] = [0xE1u8; 8];
    const LOCAL_SK: [u8; 16] = [0x5Au8; 16];
    const CP_EK: [u8; 8] = [0xC2u8; 8];
    const WRAP: [u8; 32] = [0x77u8; 32];

    fn audit() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([0xEFu8; 32], [0x1Bu8; 32], [0x9Au8; 32])
    }

    const SELF_DEV: [u8; 32] = [0x7Au8; 32];
    const PEER_DEV: [u8; 32] = [0x7Bu8; 32];
    const RESTART_ADDR: [u8; 32] = [0x7Cu8; 32];

    fn do_finalize(epoch: i64) -> Result<()> {
        let (commit, agreed_tip, statement) = audit();
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
            &[ResyncStep {
                signer: SELF_DEV,
                addr: RESTART_ADDR,
                key: &LOCAL_EK,
            }],
            ResyncAudit {
                epoch,
                preserved_acceptance_commitment: &commit,
                agreed_tip: &agreed_tip,
                restart_statement: &statement,
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
        assert_eq!(
            super::super::economic_lineage::latest_ek_step(&REL, &SELF_DEV).unwrap(),
            Some((0, RESTART_ADDR, LOCAL_EK.to_vec())),
            "the restart step is this device's latest step"
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

    /// Wire framing round-trips exactly (it rides ArgPack.body), and a body
    /// cut short anywhere decodes to nothing, never a panic.
    #[test]
    fn every_resync_message_frames_round_trip() {
        let req = CertResyncRequest {
            relationship_key: [0x11u8; 32],
            agreed_tip: [0x22u8; 32],
            epoch: 7,
            preserved_acceptance_commitment: [0xEFu8; 32],
            reply_to_tip: [0x3Bu8; 32],
            new_key: vec![0xA1u8; 64],
            request_sig: vec![0x5Au8; 128],
        };
        let offer = CertResyncOffer {
            relationship_key: [0x11u8; 32],
            epoch: 7,
            predecessor: [0x44u8; 32],
            counterparty_step: [0x45u8; 32],
            counterparty_sig: vec![0xC3u8; 128],
        };
        let confirm = CertResyncConfirm {
            relationship_key: [0x11u8; 32],
            reply_to_tip: [0x3Bu8; 32],
            restart_step: [0x46u8; 32],
        };
        let done = CertResyncDone {
            relationship_key: [0x11u8; 32],
            restart_step: [0x46u8; 32],
            counterparty_step: [0x45u8; 32],
            done_sig: vec![0xC4u8; 128],
        };
        assert_eq!(
            CertResyncRequest::from_body(&req.to_body()),
            Some(req.clone())
        );
        assert_eq!(
            CertResyncOffer::from_body(&offer.to_body()),
            Some(offer.clone())
        );
        assert_eq!(
            CertResyncConfirm::from_body(&confirm.to_body()),
            Some(confirm.clone())
        );
        assert_eq!(
            CertResyncDone::from_body(&done.to_body()),
            Some(done.clone())
        );
        for cut in [0, 31, 100, 135] {
            assert_eq!(
                CertResyncRequest::from_body(&req.to_body()[..cut]),
                None,
                "{cut}"
            );
        }
        let offer_body = offer.to_body();
        assert_eq!(
            CertResyncOffer::from_body(&offer_body[..offer_body.len() - 1]),
            None
        );
        let confirm_body = confirm.to_body();
        assert_eq!(CertResyncConfirm::from_body(&confirm_body[..95]), None);
        let done_body = done.to_body();
        assert_eq!(
            CertResyncDone::from_body(&done_body[..done_body.len() - 1]),
            None
        );
    }

    /// SA-53. A field's length is the sender's. On a 32-bit device
    /// (armeabi-v7a) `offset + length` from a large prefix wraps the address
    /// space, and the old framing panicked on it — on every sync, since the
    /// message was read again. The end of the address space is where that
    /// sum lands on any device, so it is checked here: a field that runs past
    /// the body, or past `usize`, does not decode.
    /// MUTATION CONTROL: unchecked offset arithmetic panics here and turns
    /// this red.
    #[test]
    fn a_field_length_past_the_body_or_the_address_space_does_not_decode() {
        let body = [0xFFu8; 8];
        for start in [usize::MAX - 2, usize::MAX - 5, 0, 4] {
            let mut off = start;
            assert_eq!(take_bytes(&body, &mut off), None, "from offset {start}");
            assert_eq!(off, start, "a refused field moves nothing");
        }

        let req = CertResyncRequest {
            relationship_key: [0x11u8; 32],
            agreed_tip: [0x22u8; 32],
            epoch: 7,
            preserved_acceptance_commitment: [0xEFu8; 32],
            reply_to_tip: [0x3Bu8; 32],
            new_key: vec![0xA1u8; 64],
            request_sig: vec![0x5Au8; 128],
        };
        let mut hostile = req.to_body();
        hostile[136..140].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(CertResyncRequest::from_body(&hostile), None);
    }

    /// The RESPONDER leg (asymmetric): CAS-advances only the stale Counterparty
    /// head, leaves its own Local head untouched, records the epoch, and never
    /// blocks its own sending.
    #[test]
    #[serial_test::serial]
    fn responder_advances_counterparty_only_and_keeps_local() {
        init();
        use crate::storage::client_db::cert_chain::{
            init_cert_chain_head, load_cert_chain_head_pubkey, CertChainSide,
        };
        // Healthy responder: has its own Local head P_D3 and a stale Counterparty EK_N.
        init_cert_chain_head(&REL, CertChainSide::Local, &[0xD3u8; 8]).unwrap();
        init_cert_chain_head(&REL, CertChainSide::Counterparty, &[0xE0u8; 8]).unwrap();
        let (commit, agreed_tip, statement) = audit();

        finalize_cert_resync_responder_atomically(
            &REL,
            1,
            &[0xA1u8; 8],
            Some(&[0xE0u8; 8]),
            ResyncStep {
                signer: PEER_DEV,
                addr: RESTART_ADDR,
                key: &[0xA1u8; 8],
            },
            ResyncAudit {
                epoch: 1,
                preserved_acceptance_commitment: &commit,
                agreed_tip: &agreed_tip,
                restart_statement: &statement,
                reason_code: "peer-head-loss",
            },
            &[0xD3u8; 8],
        )
        .unwrap();
        assert_eq!(
            super::super::economic_lineage::latest_ek_step(&REL, &PEER_DEV).unwrap(),
            Some((0, RESTART_ADDR, vec![0xA1u8; 8])),
            "the restart step is the initiator's latest step"
        );

        assert_eq!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            vec![0xD3u8; 8],
            "responder Local head UNTOUCHED (asymmetric)"
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&REL, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            vec![0xA1u8; 8],
            "counterparty advanced to the initiator's fresh EK"
        );
        assert!(
            !cert_resync_blocks_send(&REL).unwrap(),
            "responder is never blocked"
        );
        // Replay at the same epoch is rejected.
        assert!(finalize_cert_resync_responder_atomically(
            &REL,
            1,
            &[0xA1u8; 8],
            Some(&[0xA1u8; 8]),
            ResyncStep {
                signer: PEER_DEV,
                addr: RESTART_ADDR,
                key: &[0xA1u8; 8],
            },
            ResyncAudit {
                epoch: 1,
                preserved_acceptance_commitment: &commit,
                agreed_tip: &agreed_tip,
                restart_statement: &statement,
                reason_code: "x"
            },
            &[0xD3u8; 8]
        )
        .is_err());
    }

    /// The detection signal: only a relationship that has had a step counts as
    /// head-loss. One with no step yet (Local head absent) is a normal first
    /// transfer, not a resync.
    #[test]
    #[serial_test::serial]
    fn prior_step_detection_distinguishes_head_loss_from_first_transfer() {
        init();
        assert!(
            !relationship_had_prior_step(&REL).unwrap(),
            "no step yet — a first transfer, not a resync"
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
        };
        crate::storage::client_db::insert_sender_proposal(&proposal).unwrap();
        assert!(
            relationship_had_prior_step(&REL).unwrap(),
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

    /// Finality barrier: a send that is finalized locally but whose checkpoint
    /// has not reached quorum (`finalization_checkpoint_pending`) is an
    /// UNSETTLED obligation for cert resync — the relationship still owes the
    /// peer a certificate signed by its current per-step lineage.
    #[test]
    #[serial_test::serial]
    fn a_checkpoint_pending_send_is_a_pending_obligation() {
        init();
        {
            let binding = crate::storage::client_db::get_connection().expect("conn");
            let conn = binding.lock().expect("lock");
            conn.execute(
                "INSERT INTO sender_outbox (relationship_key, canonical_parent, canonical_child, \
                 commitment, projection_parent, projection_target, routing_address, submission_id, \
                 envelope_bytes, proposal_nonce, local_expected_prev, is_first_ek_step, status, \
                 message_ids) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'R', 'SID', X'00', ?7, \
                 NULL, 1, ?8, NULL)",
                rusqlite::params![
                    REL.as_slice(),
                    vec![0x01u8; 32],
                    vec![0x02u8; 32],
                    vec![0x03u8; 32],
                    vec![0x04u8; 32],
                    vec![0x05u8; 32],
                    vec![0x06u8; 32],
                    crate::storage::client_db::OUTBOX_FINALIZATION_CHECKPOINT_PENDING,
                ],
            )
            .expect("seed row");
        }
        assert!(
            resync_pending_obligation(&REL).expect("query").is_some(),
            "finalization_checkpoint_pending must count as an unsettled outbox row"
        );
    }
}
