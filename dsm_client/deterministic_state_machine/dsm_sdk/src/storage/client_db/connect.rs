// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Connect (DSM Amendment A11): what this device keeps about the
//! applications it is connected to, and, on an application's own account,
//! about the wallets connected to it.
//!
//! The wallet's side:
//! - `connect_previews`: an offer fetched and verified for the approval
//!   screen, until the player approves it.
//! - `connect_sessions`: one row per connected application, with the accept
//!   body the wallet signed (its grant) and `last_seq`, the highest request
//!   processed: the replay guard. Requests are processed strictly in order.
//! - `connect_spent`: what each grant has spent of each token, counted by the
//!   wallet itself.
//! - `connect_pending`: a request outside its grant, waiting for the player.
//! - `connect_log`: what the wallet did with each request it processed, and
//!   the signed answer it owes the application until the answer is
//!   delivered. An answer is re-sent, never the request re-run.
//!
//! The application's side:
//! - `connect_app_offers`, `connect_app_sessions`: offers it signed and the
//!   wallets that accepted them.
//! - `connect_app_requests`: every request it signed and the wallet's signed
//!   answer, which is a notification and never evidence.
//! - `connect_app_facts`: the DSM facts (an accepted transfer) it granted on,
//!   each answering at most one request.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::{column_32, get_connection};

const CONNECTED: &str = "connected";
const DISCONNECTED: &str = "disconnected";

// ------------------------------- wallet side -------------------------------

/// An offer the wallet fetched and verified, held for the approval screen.
#[derive(Debug, Clone)]
pub struct PreviewRow {
    pub endpoint: String,
    pub cert_pin: [u8; 32],
    pub offer: Vec<u8>,
}

pub fn put_preview(offer_digest: &[u8; 32], row: &PreviewRow) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT OR REPLACE INTO connect_previews(offer_digest, endpoint, cert_pin, offer) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            offer_digest.as_slice(),
            row.endpoint,
            row.cert_pin.as_slice(),
            row.offer
        ],
    )?;
    Ok(())
}

pub fn preview(offer_digest: &[u8; 32]) -> Result<Option<PreviewRow>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT endpoint, cert_pin, offer FROM connect_previews WHERE offer_digest = ?1",
            params![offer_digest.as_slice()],
            |r| {
                Ok(PreviewRow {
                    endpoint: r.get(0)?,
                    cert_pin: column_32(r, 1)?,
                    offer: r.get(2)?,
                })
            },
        )
        .optional()?)
}

/// A connected (or once connected) application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSession {
    pub session_id: [u8; 32],
    pub app_device_id: [u8; 32],
    pub app_genesis: [u8; 32],
    pub app_ak: Vec<u8>,
    pub display_name: String,
    pub endpoint: String,
    pub cert_pin: [u8; 32],
    pub offer_digest: [u8; 32],
    /// The `AppConnectAcceptBodyV1` bytes the wallet signed: its grant.
    pub accept_body: Vec<u8>,
    pub last_seq: u64,
    pub connected: SessionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Connected,
    Disconnected,
}

fn status_text(s: SessionStatus) -> &'static str {
    match s {
        SessionStatus::Connected => CONNECTED,
        SessionStatus::Disconnected => DISCONNECTED,
    }
}

fn status_of(text: &str) -> rusqlite::Result<SessionStatus> {
    match text {
        CONNECTED => Ok(SessionStatus::Connected),
        DISCONNECTED => Ok(SessionStatus::Disconnected),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("session status {other:?}").into(),
        )),
    }
}

fn u64_of(r: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<u64> {
    let v: i64 = r.get(i)?;
    u64::try_from(v).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Integer, e.into())
    })
}

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|e| anyhow!("{v} does not fit a database integer: {e}"))
}

const SESSION_COLUMNS: &str = "session_id, app_device_id, app_genesis, app_ak, display_name, \
     endpoint, cert_pin, offer_digest, accept_body, last_seq, status";

fn session_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<WalletSession> {
    let status: String = r.get(10)?;
    Ok(WalletSession {
        session_id: column_32(r, 0)?,
        app_device_id: column_32(r, 1)?,
        app_genesis: column_32(r, 2)?,
        app_ak: r.get(3)?,
        display_name: r.get(4)?,
        endpoint: r.get(5)?,
        cert_pin: column_32(r, 6)?,
        offer_digest: column_32(r, 7)?,
        accept_body: r.get(8)?,
        last_seq: u64_of(r, 9)?,
        connected: status_of(&status)?,
    })
}

/// Record a new connection, and drop the preview it came from. A session id
/// already connected is refused: one offer, one wallet, one session.
pub fn insert_session(s: &WalletSession) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let existing: Option<String> = tx
        .query_row(
            "SELECT status FROM connect_sessions WHERE session_id = ?1",
            params![s.session_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_deref() == Some(CONNECTED) {
        return Err(anyhow!("this application is already connected"));
    }
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO connect_sessions({SESSION_COLUMNS}) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        ),
        params![
            s.session_id.as_slice(),
            s.app_device_id.as_slice(),
            s.app_genesis.as_slice(),
            s.app_ak,
            s.display_name,
            s.endpoint,
            s.cert_pin.as_slice(),
            s.offer_digest.as_slice(),
            s.accept_body,
            i64_of(s.last_seq)?,
            status_text(s.connected),
        ],
    )?;
    tx.execute(
        "DELETE FROM connect_previews WHERE offer_digest = ?1",
        params![s.offer_digest.as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn sessions() -> Result<Vec<WalletSession>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM connect_sessions ORDER BY display_name, session_id"
    ))?;
    let rows = stmt
        .query_map([], session_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn session(session_id: &[u8; 32]) -> Result<Option<WalletSession>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            &format!("SELECT {SESSION_COLUMNS} FROM connect_sessions WHERE session_id = ?1"),
            params![session_id.as_slice()],
            session_row,
        )
        .optional()?)
}

pub fn disconnect(session_id: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let changed = tx.execute(
        "UPDATE connect_sessions SET status = ?2 WHERE session_id = ?1",
        params![session_id.as_slice(), DISCONNECTED],
    )?;
    if changed != 1 {
        return Err(anyhow!("no such connected application"));
    }
    tx.execute(
        "DELETE FROM connect_pending WHERE session_id = ?1",
        params![session_id.as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

/// What the grant of `session_id` has spent of `policy_commit`.
pub fn spent(session_id: &[u8; 32], policy_commit: &[u8; 32]) -> Result<u64> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let found: Option<i64> = conn
        .query_row(
            "SELECT spent FROM connect_spent WHERE session_id = ?1 AND policy_commit = ?2",
            params![session_id.as_slice(), policy_commit.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    match found {
        Some(v) => u64::try_from(v).map_err(|e| anyhow!("a negative spend is stored: {e}")),
        None => Ok(0),
    }
}

pub fn spent_all(session_id: &[u8; 32]) -> Result<Vec<([u8; 32], u64)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT policy_commit, spent FROM connect_spent WHERE session_id = ?1 \
         ORDER BY policy_commit",
    )?;
    let rows = stmt
        .query_map(params![session_id.as_slice()], |r| {
            Ok((column_32(r, 0)?, u64_of(r, 1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// A request waiting for the player.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRow {
    pub session_id: [u8; 32],
    pub seq: u64,
    /// The `AppRequestV1` bytes, verified when they arrived.
    pub request: Vec<u8>,
    pub reason: String,
}

/// Hold `seq` for the player. Only the next request after `last_seq` can
/// wait: requests are processed in order.
pub fn put_pending(row: &PendingRow) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let last: Option<i64> = tx
        .query_row(
            "SELECT last_seq FROM connect_sessions WHERE session_id = ?1 AND status = ?2",
            params![row.session_id.as_slice(), CONNECTED],
            |r| r.get(0),
        )
        .optional()?;
    let last = last.ok_or_else(|| anyhow!("no such connected application"))?;
    if i64_of(row.seq)? != last + 1 {
        return Err(anyhow!(
            "request {} is not the next one after {last}",
            row.seq
        ));
    }
    tx.execute(
        "INSERT OR IGNORE INTO connect_pending(session_id, seq, request, reason) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            row.session_id.as_slice(),
            i64_of(row.seq)?,
            row.request,
            row.reason
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn pending_all() -> Result<Vec<PendingRow>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT session_id, seq, request, reason FROM connect_pending ORDER BY session_id, seq",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(PendingRow {
                session_id: column_32(r, 0)?,
                seq: u64_of(r, 1)?,
                request: r.get(2)?,
                reason: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn pending(session_id: &[u8; 32], seq: u64) -> Result<Option<PendingRow>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT session_id, seq, request, reason FROM connect_pending \
             WHERE session_id = ?1 AND seq = ?2",
            params![session_id.as_slice(), i64_of(seq)?],
            |r| {
                Ok(PendingRow {
                    session_id: column_32(r, 0)?,
                    seq: u64_of(r, 1)?,
                    request: r.get(2)?,
                    reason: r.get(3)?,
                })
            },
        )
        .optional()?)
}

/// One processed request, as the Apps screen lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRow {
    pub seq: u64,
    pub summary: String,
    pub outcome: i32,
    pub detail: String,
}

const UNSENT: &str = "unsent";
const SENT: &str = "sent";

/// Record that `seq` of `session_id` was processed: it becomes the replay
/// guard, its spend (if it was carried out under the grant) is counted, it
/// leaves the pending list, and its log row is written, all at once. A `seq`
/// that is not the next one after the guard is refused: nothing is processed
/// twice and nothing is skipped.
pub fn record_processed(
    session_id: &[u8; 32],
    spend: Option<([u8; 32], u64)>,
    log: &LogRow,
    response: &[u8],
) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let last: Option<i64> = tx
        .query_row(
            "SELECT last_seq FROM connect_sessions WHERE session_id = ?1 AND status = ?2",
            params![session_id.as_slice(), CONNECTED],
            |r| r.get(0),
        )
        .optional()?;
    let last = last.ok_or_else(|| anyhow!("no such connected application"))?;
    let seq = i64_of(log.seq)?;
    if seq != last + 1 {
        return Err(anyhow!(
            "request {} is not the next one after {last}: never processed twice, never skipped",
            log.seq
        ));
    }
    tx.execute(
        "UPDATE connect_sessions SET last_seq = ?2 WHERE session_id = ?1",
        params![session_id.as_slice(), seq],
    )?;
    if let Some((policy_commit, amount)) = spend {
        let before: Option<i64> = tx
            .query_row(
                "SELECT spent FROM connect_spent WHERE session_id = ?1 AND policy_commit = ?2",
                params![session_id.as_slice(), policy_commit.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let before = match before {
            Some(v) => u64::try_from(v).map_err(|e| anyhow!("a negative spend is stored: {e}"))?,
            None => 0,
        };
        let after = before
            .checked_add(amount)
            .ok_or_else(|| anyhow!("the grant's spend overflows"))?;
        tx.execute(
            "INSERT OR REPLACE INTO connect_spent(session_id, policy_commit, spent) \
             VALUES (?1, ?2, ?3)",
            params![
                session_id.as_slice(),
                policy_commit.as_slice(),
                i64_of(after)?
            ],
        )?;
    }
    tx.execute(
        "DELETE FROM connect_pending WHERE session_id = ?1 AND seq = ?2",
        params![session_id.as_slice(), seq],
    )?;
    tx.execute(
        "INSERT INTO connect_log(session_id, seq, summary, outcome, detail, response, delivery) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session_id.as_slice(),
            seq,
            log.summary,
            log.outcome,
            log.detail,
            response,
            UNSENT
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn log(session_id: &[u8; 32]) -> Result<Vec<LogRow>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT seq, summary, outcome, detail FROM connect_log WHERE session_id = ?1 \
         ORDER BY seq DESC",
    )?;
    let rows = stmt
        .query_map(params![session_id.as_slice()], |r| {
            Ok(LogRow {
                seq: u64_of(r, 0)?,
                summary: r.get(1)?,
                outcome: r.get(2)?,
                detail: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The signed answers of `session_id` not yet delivered, in order.
pub fn undelivered(session_id: &[u8; 32]) -> Result<Vec<(u64, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT seq, response FROM connect_log WHERE session_id = ?1 AND delivery = ?2 \
         ORDER BY seq",
    )?;
    let rows = stmt
        .query_map(params![session_id.as_slice(), UNSENT], |r| {
            Ok((u64_of(r, 0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn mark_delivered(session_id: &[u8; 32], seq: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "UPDATE connect_log SET delivery = ?3 WHERE session_id = ?1 AND seq = ?2",
        params![session_id.as_slice(), i64_of(seq)?, SENT],
    )?;
    Ok(())
}

// ----------------------------- application side -----------------------------

pub fn app_put_offer(offer_digest: &[u8; 32], code: &str, offer: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT OR IGNORE INTO connect_app_offers(offer_digest, code, offer) VALUES (?1, ?2, ?3)",
        params![offer_digest.as_slice(), code, offer],
    )?;
    Ok(())
}

/// An offer this account made: its code and its signed bytes.
pub fn app_offer(offer_digest: &[u8; 32]) -> Result<Option<(String, Vec<u8>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT code, offer FROM connect_app_offers WHERE offer_digest = ?1",
            params![offer_digest.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// A wallet connected to this application's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSession {
    pub session_id: [u8; 32],
    pub offer_digest: [u8; 32],
    pub wallet_device_id: [u8; 32],
    pub wallet_genesis: [u8; 32],
    pub wallet_ak: Vec<u8>,
    /// The `AppConnectAcceptV1` bytes, verified when they arrived.
    pub accept: Vec<u8>,
    pub next_seq: u64,
}

const APP_SESSION_COLUMNS: &str =
    "session_id, offer_digest, wallet_device_id, wallet_genesis, wallet_ak, accept, next_seq";

fn app_session_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AppSession> {
    Ok(AppSession {
        session_id: column_32(r, 0)?,
        offer_digest: column_32(r, 1)?,
        wallet_device_id: column_32(r, 2)?,
        wallet_genesis: column_32(r, 3)?,
        wallet_ak: r.get(4)?,
        accept: r.get(5)?,
        next_seq: u64_of(r, 6)?,
    })
}

/// Record an accepted session. The same accept arriving again changes
/// nothing; another accept for a session already held is refused.
pub fn app_insert_session(s: &AppSession) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let held: Option<Vec<u8>> = tx
        .query_row(
            "SELECT accept FROM connect_app_sessions WHERE session_id = ?1",
            params![s.session_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    match held {
        Some(accept) if accept == s.accept => return Ok(()),
        Some(..) => return Err(anyhow!("this session holds another accept")),
        None => {}
    }
    tx.execute(
        &format!(
            "INSERT INTO connect_app_sessions({APP_SESSION_COLUMNS}) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        ),
        params![
            s.session_id.as_slice(),
            s.offer_digest.as_slice(),
            s.wallet_device_id.as_slice(),
            s.wallet_genesis.as_slice(),
            s.wallet_ak,
            s.accept,
            i64_of(s.next_seq)?,
        ],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn app_sessions() -> Result<Vec<AppSession>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {APP_SESSION_COLUMNS} FROM connect_app_sessions ORDER BY session_id"
    ))?;
    let rows = stmt
        .query_map([], app_session_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn app_session(session_id: &[u8; 32]) -> Result<Option<AppSession>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            &format!(
                "SELECT {APP_SESSION_COLUMNS} FROM connect_app_sessions WHERE session_id = ?1"
            ),
            params![session_id.as_slice()],
            app_session_row,
        )
        .optional()?)
}

/// Take the session's next sequence number and store the request `make`
/// signs for it, in one transaction.
pub fn app_append_request(
    session_id: &[u8; 32],
    make: impl FnOnce(u64) -> Result<Vec<u8>, String>,
) -> Result<u64> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let next: Option<i64> = tx
        .query_row(
            "SELECT next_seq FROM connect_app_sessions WHERE session_id = ?1",
            params![session_id.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let next = next.ok_or_else(|| anyhow!("no such session"))?;
    let seq =
        u64::try_from(next).map_err(|e| anyhow!("a negative sequence number is stored: {e}"))?;
    let request = make(seq).map_err(|e| anyhow!(e))?;
    tx.execute(
        "INSERT INTO connect_app_requests(session_id, seq, request, response) \
         VALUES (?1, ?2, ?3, NULL)",
        params![session_id.as_slice(), next, request],
    )?;
    tx.execute(
        "UPDATE connect_app_sessions SET next_seq = ?2 WHERE session_id = ?1",
        params![session_id.as_slice(), next + 1],
    )?;
    tx.commit()?;
    Ok(seq)
}

/// Every request of `session_id` above `after`, in order.
pub fn app_requests_after(session_id: &[u8; 32], after: u64) -> Result<Vec<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let mut stmt = conn.prepare(
        "SELECT request FROM connect_app_requests WHERE session_id = ?1 AND seq > ?2 \
         ORDER BY seq",
    )?;
    let rows = stmt
        .query_map(params![session_id.as_slice(), i64_of(after)?], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<Vec<u8>>>>()?;
    Ok(rows)
}

/// A request and the answer stored for it.
pub fn app_request(session_id: &[u8; 32], seq: u64) -> Result<Option<(Vec<u8>, Option<Vec<u8>>)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT request, response FROM connect_app_requests WHERE session_id = ?1 AND seq = ?2",
            params![session_id.as_slice(), i64_of(seq)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// Store the wallet's verified answer to `seq`. One answer per request: the
/// same one again changes nothing, another is refused.
pub fn app_store_response(session_id: &[u8; 32], seq: u64, response: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let mut conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let tx = conn.transaction()?;
    let held: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT response FROM connect_app_requests WHERE session_id = ?1 AND seq = ?2",
            params![session_id.as_slice(), i64_of(seq)?],
            |r| r.get(0),
        )
        .optional()?;
    match held {
        None => return Err(anyhow!("no request {seq} in this session")),
        Some(Some(stored)) if stored == response => return Ok(()),
        Some(Some(..)) => return Err(anyhow!("request {seq} already has another answer")),
        Some(None) => {}
    }
    tx.execute(
        "UPDATE connect_app_requests SET response = ?3 WHERE session_id = ?1 AND seq = ?2",
        params![session_id.as_slice(), i64_of(seq)?, response],
    )?;
    tx.commit()?;
    Ok(())
}

/// Replace the stored answer to `seq`. The caller has decided the stored
/// one was interim (awaiting the player).
pub fn app_replace_response(session_id: &[u8; 32], seq: u64, response: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    let changed = conn.execute(
        "UPDATE connect_app_requests SET response = ?3 WHERE session_id = ?1 AND seq = ?2",
        params![session_id.as_slice(), i64_of(seq)?, response],
    )?;
    if changed != 1 {
        return Err(anyhow!("no request {seq} in this session"));
    }
    Ok(())
}

/// The fact `seq` was granted on, if any.
pub fn app_fact_of(session_id: &[u8; 32], seq: u64) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT fact_id FROM connect_app_facts WHERE session_id = ?1 AND seq = ?2",
            params![session_id.as_slice(), i64_of(seq)?],
            |r| r.get(0),
        )
        .optional()?)
}

/// Whether `fact_id` already answers some request.
pub fn app_fact_used(fact_id: &[u8]) -> Result<Option<(Vec<u8>, u64)>> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    Ok(conn
        .query_row(
            "SELECT session_id, seq FROM connect_app_facts WHERE fact_id = ?1",
            params![fact_id],
            |r| Ok((r.get(0)?, u64_of(r, 1)?)),
        )
        .optional()?)
}

/// Record that `fact_id` answers `seq`: insert-only, so one fact answers one
/// request and one request is answered by one fact.
pub fn app_record_fact(fact_id: &[u8], session_id: &[u8; 32], seq: u64) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|e| anyhow!("the client database lock: {e}"))?;
    conn.execute(
        "INSERT INTO connect_app_facts(fact_id, session_id, seq) VALUES (?1, ?2, ?3)",
        params![fact_id, session_id.as_slice(), i64_of(seq)?],
    )
    .map_err(|e| anyhow!("the fact is already granted on: {e}"))?;
    Ok(())
}
