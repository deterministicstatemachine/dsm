// SPDX-License-Identifier: MIT OR Apache-2.0
//! ADR 0003 step 3: the recipient's durable staging area.
//!
//! > **Transport may be multi-message; acceptance remains atomic.**
//!
//! A split transfer arrives as two independent artifacts — the small semantic
//! transfer, and the ~118 KB A-side receipt evidence it references by digest.
//! Neither half alone authorises anything.
//!
//! ```text
//! no transfer + no evidence            -> absent (no row)
//! transfer only                        -> staged_transfer
//! evidence only                        -> staged_evidence
//! both present, unverified             -> ready_to_verify
//! digest mismatch                      -> terminal_reject
//! verified + canonical apply committed -> accepted
//! ```
//!
//! Four properties are structural rather than remembered:
//!
//! 1. **Arrival order is not identity.** The row is keyed by the logical
//!    transfer correlation id; whichever half arrives first creates it.
//! 2. **Frozen bytes.** Both halves are stored exactly as received. Pairing and
//!    verification operate on those bytes, never on a protobuf re-encoded from
//!    them — a re-encode is how "the bytes I verified" quietly stops being "the
//!    bytes that arrived".
//! 3. **Idempotent, but fail-closed.** Re-inserting identical bytes is a no-op.
//!    The same key with *different* bytes or a different digest is an error, not
//!    a silent overwrite.
//! 4. **`terminal_reject` is sticky.** A digest mismatch is a decision. It must
//!    never decay back into "still waiting for the other half", because that
//!    would let a mismatched pair be retried until something eventually matched.
//!
//! This module deliberately contains **no acceptance cryptography and no ACK**.
//! Verification and apply are wired on top of it, and no ACK-producing path is
//! reachable from a single-half state.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// Where a staged transfer sits. `Absent` is the lack of a row, never a stored
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingState {
    Absent,
    StagedTransfer,
    StagedEvidence,
    ReadyToVerify,
    TerminalReject,
    Accepted,
}

impl StagingState {
    pub fn as_str(self) -> &'static str {
        match self {
            StagingState::Absent => "absent",
            StagingState::StagedTransfer => "staged_transfer",
            StagingState::StagedEvidence => "staged_evidence",
            StagingState::ReadyToVerify => "ready_to_verify",
            StagingState::TerminalReject => "terminal_reject",
            StagingState::Accepted => "accepted",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "staged_transfer" => StagingState::StagedTransfer,
            "staged_evidence" => StagingState::StagedEvidence,
            "ready_to_verify" => StagingState::ReadyToVerify,
            "terminal_reject" => StagingState::TerminalReject,
            "accepted" => StagingState::Accepted,
            other => return Err(anyhow!("unknown recipient_staging.state: {other}")),
        })
    }

    /// Terminal states are never left. Reaping may only ever consider these.
    pub fn is_terminal(self) -> bool {
        matches!(self, StagingState::TerminalReject | StagingState::Accepted)
    }

    /// Whether an ACK may be emitted. Only a completed acceptance qualifies —
    /// a staged half is a local durability fact, never a protocol
    /// acknowledgement.
    pub fn may_ack(self) -> bool {
        matches!(self, StagingState::Accepted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingRecord {
    pub correlation_key: String,
    pub state: StagingState,
    pub transfer_bytes: Option<Vec<u8>>,
    pub expected_evidence_digest: Option<[u8; 32]>,
    pub evidence_bytes: Option<Vec<u8>>,
    pub evidence_digest: Option<[u8; 32]>,
    pub reject_reason: Option<String>,
}

impl StagingRecord {
    /// Re-derive the state from the stored halves rather than trusting the
    /// stored string, with terminal states sticky.
    ///
    /// The row and its halves are written together, but deriving keeps a
    /// corrupted or stale `state` column from promoting a transfer that the
    /// data does not support.
    fn derived_state(&self) -> StagingState {
        if self.state.is_terminal() {
            return self.state;
        }
        match (self.transfer_bytes.is_some(), self.evidence_bytes.is_some()) {
            (true, true) => StagingState::ReadyToVerify,
            (true, false) => StagingState::StagedTransfer,
            (false, true) => StagingState::StagedEvidence,
            (false, false) => StagingState::Absent,
        }
    }
}

fn to32(v: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v).map_err(|_| anyhow!("expected a 32-byte digest, got {}", v.len()))
}

fn load(conn: &rusqlite::Connection, key: &str) -> Result<Option<StagingRecord>> {
    let rec = conn
        .query_row(
            "SELECT correlation_key, state, transfer_bytes, expected_evidence_digest,
                    evidence_bytes, evidence_digest, reject_reason
             FROM recipient_staging WHERE correlation_key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;

    match rec {
        None => Ok(None),
        Some((k, state, tb, eed, eb, ed, reason)) => Ok(Some(StagingRecord {
            correlation_key: k,
            state: StagingState::from_str(&state)?,
            transfer_bytes: tb,
            expected_evidence_digest: eed.as_deref().map(to32).transpose()?,
            evidence_bytes: eb,
            evidence_digest: ed.as_deref().map(to32).transpose()?,
            reject_reason: reason,
        })),
    }
}

/// Current state of a staged transfer. `Absent` when nothing has arrived.
pub fn staging_state(correlation_key: &str) -> Result<StagingState> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(load(&conn, correlation_key)?
        .map(|r| r.derived_state())
        .unwrap_or(StagingState::Absent))
}

pub fn get_staging(correlation_key: &str) -> Result<Option<StagingRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    Ok(load(&conn, correlation_key)?.map(|mut r| {
        r.state = r.derived_state();
        r
    }))
}

/// Stage the transfer half.
///
/// Idempotent for identical bytes and an identical evidence reference. A second
/// arrival carrying DIFFERENT bytes, or referencing a different evidence digest,
/// fails closed rather than overwriting: the two cannot both be the transfer
/// this key names, and silently keeping the newer one would let a later message
/// redefine an earlier commitment.
pub fn stage_transfer_half(
    correlation_key: &str,
    transfer_bytes: &[u8],
    expected_evidence_digest: &[u8; 32],
) -> Result<StagingState> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;

    if let Some(existing) = load(&conn, correlation_key)? {
        if existing.state == StagingState::TerminalReject {
            return Err(anyhow!(
                "recipient_staging: {correlation_key} is terminally rejected \
                 ({}); a rejected pair must not be re-staged",
                existing
                    .reject_reason
                    .as_deref()
                    .unwrap_or("no reason recorded")
            ));
        }
        if let Some(prior) = existing.transfer_bytes.as_deref() {
            if prior != transfer_bytes {
                return Err(anyhow!(
                    "recipient_staging: {correlation_key} already holds a DIFFERENT transfer \
                     half ({} bytes stored, {} incoming); refusing to overwrite",
                    prior.len(),
                    transfer_bytes.len()
                ));
            }
            if existing.expected_evidence_digest.as_ref() != Some(expected_evidence_digest) {
                return Err(anyhow!(
                    "recipient_staging: {correlation_key} already references a DIFFERENT \
                     evidence digest; refusing to overwrite"
                ));
            }
            return reconcile(&conn, correlation_key);
        }
        conn.execute(
            "UPDATE recipient_staging
             SET transfer_bytes = ?2, expected_evidence_digest = ?3, updated_at = ?4
             WHERE correlation_key = ?1",
            params![
                correlation_key,
                transfer_bytes,
                expected_evidence_digest.as_slice(),
                now
            ],
        )?;
    } else {
        conn.execute(
            "INSERT INTO recipient_staging(
                correlation_key, state, transfer_bytes, expected_evidence_digest,
                created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                correlation_key,
                StagingState::StagedTransfer.as_str(),
                transfer_bytes,
                expected_evidence_digest.as_slice(),
                now
            ],
        )?;
    }
    reconcile(&conn, correlation_key)
}

/// Stage the evidence half.
///
/// The digest is computed over the EXACT received bytes under the A role, never
/// taken from the artifact's self-description — an artifact that names its own
/// address is convenient for correlation, not authority.
pub fn stage_evidence_half(correlation_key: &str, evidence_bytes: &[u8]) -> Result<StagingState> {
    let digest = super::sender_outbox::evidence_content_digest(
        super::sender_outbox::ArtifactRole::EvidenceA,
        evidence_bytes,
    );
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;

    if let Some(existing) = load(&conn, correlation_key)? {
        if existing.state == StagingState::TerminalReject {
            return Err(anyhow!(
                "recipient_staging: {correlation_key} is terminally rejected \
                 ({}); a rejected pair must not be re-staged",
                existing
                    .reject_reason
                    .as_deref()
                    .unwrap_or("no reason recorded")
            ));
        }
        if let Some(prior) = existing.evidence_bytes.as_deref() {
            if prior != evidence_bytes {
                return Err(anyhow!(
                    "recipient_staging: {correlation_key} already holds a DIFFERENT evidence \
                     half ({} bytes stored, {} incoming); refusing to overwrite",
                    prior.len(),
                    evidence_bytes.len()
                ));
            }
            return reconcile(&conn, correlation_key);
        }
        conn.execute(
            "UPDATE recipient_staging
             SET evidence_bytes = ?2, evidence_digest = ?3, updated_at = ?4
             WHERE correlation_key = ?1",
            params![correlation_key, evidence_bytes, digest.as_slice(), now],
        )?;
    } else {
        conn.execute(
            "INSERT INTO recipient_staging(
                correlation_key, state, evidence_bytes, evidence_digest,
                created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                correlation_key,
                StagingState::StagedEvidence.as_str(),
                evidence_bytes,
                digest.as_slice(),
                now
            ],
        )?;
    }
    reconcile(&conn, correlation_key)
}

/// Recompute the stored state from the halves, and bind the digest once both
/// are present.
///
/// A mismatch here is TERMINAL. It is not "keep waiting": the transfer named an
/// evidence object and something else arrived, and letting that decay back into
/// a waiting state would allow retrying until something eventually matched.
fn reconcile(conn: &rusqlite::Connection, correlation_key: &str) -> Result<StagingState> {
    let rec = load(conn, correlation_key)?
        .ok_or_else(|| anyhow!("recipient_staging: {correlation_key} vanished mid-reconcile"))?;
    if rec.state.is_terminal() {
        return Ok(rec.state);
    }

    let next = match (rec.expected_evidence_digest, rec.evidence_digest) {
        (Some(expected), Some(actual)) if expected != actual => {
            let reason = format!(
                "evidence digest mismatch: transfer references {}, evidence hashes to {}",
                crate::util::text_id::encode_base32_crockford(&expected),
                crate::util::text_id::encode_base32_crockford(&actual)
            );
            conn.execute(
                "UPDATE recipient_staging SET state = ?2, reject_reason = ?3, updated_at = ?4
                 WHERE correlation_key = ?1",
                params![
                    correlation_key,
                    StagingState::TerminalReject.as_str(),
                    reason,
                    tick() as i64
                ],
            )?;
            return Ok(StagingState::TerminalReject);
        }
        _ => rec.derived_state(),
    };

    conn.execute(
        "UPDATE recipient_staging SET state = ?2, updated_at = ?3 WHERE correlation_key = ?1",
        params![correlation_key, next.as_str(), tick() as i64],
    )?;
    Ok(next)
}

/// Mark a staged transfer accepted. Only legal from `ready_to_verify`, and only
/// after the caller has verified and committed the canonical apply — this is the
/// single point from which an ACK becomes permissible.
pub fn mark_accepted(correlation_key: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let rec = load(&conn, correlation_key)?
        .ok_or_else(|| anyhow!("recipient_staging: cannot accept absent {correlation_key}"))?;
    let derived = rec.derived_state();
    if derived != StagingState::ReadyToVerify {
        return Err(anyhow!(
            "recipient_staging: cannot accept {correlation_key} from state {}; \
             acceptance requires both halves present and digest-bound",
            derived.as_str()
        ));
    }
    conn.execute(
        "UPDATE recipient_staging SET state = ?2, updated_at = ?3 WHERE correlation_key = ?1",
        params![
            correlation_key,
            StagingState::Accepted.as_str(),
            tick() as i64
        ],
    )?;
    Ok(())
}

/// Record a terminal rejection. Sticky by construction.
pub fn mark_rejected(correlation_key: &str, reason: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "UPDATE recipient_staging SET state = ?2, reject_reason = ?3, updated_at = ?4
         WHERE correlation_key = ?1",
        params![
            correlation_key,
            StagingState::TerminalReject.as_str(),
            reason,
            tick() as i64
        ],
    )?;
    Ok(())
}

/// Keys eligible for reaping: TERMINAL only.
///
/// Deliberately not age-based. Reaping an incomplete half converts "waiting" into
/// permanent limbo — the transfer is forward-only, so the sender will not reissue
/// a new logical send — and wall-clock in this path is prohibited repo-wide
/// besides. Unbounded-but-correct beats bounded-but-lossy for value transfer; if
/// growth becomes a real problem the answer is an explicit terminal tombstone,
/// not a timer.
pub fn reapable_keys() -> Result<Vec<String>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT correlation_key FROM recipient_staging
         WHERE state IN ('terminal_reject', 'accepted')",
    )?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn fresh_db() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn evidence(n: u8) -> Vec<u8> {
        vec![n; 4096]
    }

    fn digest_of(bytes: &[u8]) -> [u8; 32] {
        super::super::sender_outbox::evidence_content_digest(
            super::super::sender_outbox::ArtifactRole::EvidenceA,
            bytes,
        )
    }

    /// Transfer first, then a restart, then evidence. The staged half must
    /// survive the restart and the pair must become ready.
    #[test]
    #[serial]
    fn transfer_then_restart_then_evidence_reaches_ready_to_verify() {
        fresh_db();
        let key = "XFER-1";
        let ev = evidence(0xA1);

        assert_eq!(staging_state(key).expect("state"), StagingState::Absent);
        assert_eq!(
            stage_transfer_half(key, b"transfer-bytes", &digest_of(&ev)).expect("stage transfer"),
            StagingState::StagedTransfer
        );

        // "Restart": drop every in-memory handle and re-read from storage.
        assert_eq!(
            staging_state(key).expect("state after restart"),
            StagingState::StagedTransfer,
            "a staged half must be durable across a restart"
        );

        assert_eq!(
            stage_evidence_half(key, &ev).expect("stage evidence"),
            StagingState::ReadyToVerify
        );
    }

    /// The mirror image. Arrival order must not be part of identity.
    #[test]
    #[serial]
    fn evidence_then_restart_then_transfer_reaches_ready_to_verify() {
        fresh_db();
        let key = "XFER-2";
        let ev = evidence(0xB2);

        assert_eq!(
            stage_evidence_half(key, &ev).expect("stage evidence"),
            StagingState::StagedEvidence
        );
        assert_eq!(
            staging_state(key).expect("state after restart"),
            StagingState::StagedEvidence
        );
        assert_eq!(
            stage_transfer_half(key, b"transfer-bytes", &digest_of(&ev)).expect("stage transfer"),
            StagingState::ReadyToVerify
        );
    }

    /// Duplicates are idempotent: N arrivals of the same half leave one.
    #[test]
    #[serial]
    fn duplicate_halves_are_idempotent() {
        fresh_db();
        let key = "XFER-3";
        let ev = evidence(0xC3);
        let d = digest_of(&ev);

        for _ in 0..5 {
            assert_eq!(
                stage_transfer_half(key, b"transfer-bytes", &d).expect("dup transfer"),
                StagingState::StagedTransfer
            );
        }
        for _ in 0..5 {
            let st = stage_evidence_half(key, &ev).expect("dup evidence");
            assert_eq!(st, StagingState::ReadyToVerify);
        }

        let rec = get_staging(key).expect("load").expect("row");
        assert_eq!(rec.transfer_bytes.as_deref(), Some(&b"transfer-bytes"[..]));
        assert_eq!(rec.evidence_bytes.as_deref(), Some(ev.as_slice()));
    }

    /// Same key, mutated bytes -> fail closed. Neither half may be silently
    /// redefined by a later message.
    #[test]
    #[serial]
    fn same_key_with_mutated_bytes_fails_closed() {
        fresh_db();
        let key = "XFER-4";
        let ev = evidence(0xD4);
        let d = digest_of(&ev);

        stage_transfer_half(key, b"transfer-bytes", &d).expect("stage transfer");
        let err = stage_transfer_half(key, b"DIFFERENT-bytes", &d)
            .expect_err("a different transfer half must be refused");
        assert!(err.to_string().contains("DIFFERENT transfer half"), "{err}");

        // A different evidence reference for the same transfer is equally refused.
        let err = stage_transfer_half(key, b"transfer-bytes", &[0x00; 32])
            .expect_err("a different evidence reference must be refused");
        assert!(
            err.to_string().contains("DIFFERENT evidence digest"),
            "{err}"
        );

        stage_evidence_half(key, &ev).expect("stage evidence");
        let err = stage_evidence_half(key, &evidence(0xEE))
            .expect_err("a different evidence half must be refused");
        assert!(err.to_string().contains("DIFFERENT evidence half"), "{err}");

        // The originals survive untouched.
        let rec = get_staging(key).expect("load").expect("row");
        assert_eq!(rec.transfer_bytes.as_deref(), Some(&b"transfer-bytes"[..]));
        assert_eq!(rec.evidence_bytes.as_deref(), Some(ev.as_slice()));
    }

    /// Both halves present but the digest does not bind -> TERMINAL reject,
    /// and it must never decay back into "waiting for the other half".
    #[test]
    #[serial]
    fn both_halves_with_a_wrong_digest_reject_terminally() {
        fresh_db();
        let key = "XFER-5";
        let real = evidence(0xE5);
        let impostor = evidence(0xF6);

        stage_transfer_half(key, b"transfer-bytes", &digest_of(&real)).expect("stage transfer");
        let st = stage_evidence_half(key, &impostor).expect("stage impostor evidence");
        assert_eq!(
            st,
            StagingState::TerminalReject,
            "a digest that does not bind must reject, not wait"
        );

        let rec = get_staging(key).expect("load").expect("row");
        assert!(rec
            .reject_reason
            .as_deref()
            .is_some_and(|r| r.contains("digest mismatch")));

        // Sticky: re-staging either half cannot revive it.
        assert!(
            stage_evidence_half(key, &real).is_err(),
            "must stay rejected"
        );
        assert!(
            stage_transfer_half(key, b"transfer-bytes", &digest_of(&real)).is_err(),
            "must stay rejected"
        );
        assert_eq!(
            staging_state(key).expect("state"),
            StagingState::TerminalReject
        );
        assert!(
            !StagingState::TerminalReject.may_ack(),
            "a rejected pair must never be ACK-able"
        );
    }

    /// One half forever: no apply, no ACK, and not reapable.
    #[test]
    #[serial]
    fn one_half_forever_never_applies_or_acks() {
        fresh_db();
        let key = "XFER-6";
        stage_transfer_half(key, b"transfer-bytes", &digest_of(&evidence(0x11)))
            .expect("stage transfer");

        let st = staging_state(key).expect("state");
        assert_eq!(st, StagingState::StagedTransfer);
        assert!(!st.may_ack(), "a single half must never be ACK-able");
        assert!(!st.is_terminal());

        // Acceptance is unreachable from a single-half state.
        let err = mark_accepted(key).expect_err("acceptance must be refused");
        assert!(err.to_string().contains("requires both halves"), "{err}");

        // And it is NOT reapable: reaping an incomplete forward-only transfer
        // converts waiting into permanent limbo.
        assert!(
            !reapable_keys()
                .expect("reapable")
                .contains(&key.to_string()),
            "an incomplete transfer must never be reaped"
        );
    }

    /// Acceptance is legal only from ready_to_verify, and only then may an ACK
    /// be emitted.
    #[test]
    #[serial]
    fn acceptance_requires_both_halves_and_gates_the_ack() {
        fresh_db();
        let key = "XFER-7";
        let ev = evidence(0x77);

        assert!(
            mark_accepted(key).is_err(),
            "cannot accept an absent transfer"
        );
        stage_evidence_half(key, &ev).expect("stage evidence");
        assert!(
            mark_accepted(key).is_err(),
            "cannot accept with only the evidence half"
        );

        stage_transfer_half(key, b"transfer-bytes", &digest_of(&ev)).expect("stage transfer");
        assert_eq!(
            staging_state(key).expect("state"),
            StagingState::ReadyToVerify
        );
        assert!(
            !StagingState::ReadyToVerify.may_ack(),
            "ready_to_verify is not yet ACK-able -- verification and apply come first"
        );

        mark_accepted(key).expect("accept");
        let st = staging_state(key).expect("state");
        assert_eq!(st, StagingState::Accepted);
        assert!(st.may_ack(), "only a completed acceptance is ACK-able");
        assert!(reapable_keys()
            .expect("reapable")
            .contains(&key.to_string()));
    }
}
