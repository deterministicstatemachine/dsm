// SPDX-License-Identifier: Apache-2.0

//! Durable storage for the ERA faucet claim flow (client-DB schema v8).
//!
//! Three kinds of state, three disciplines:
//!
//! - **Frozen envelopes** (ticket claim, root claim): exact signed bytes,
//!   written BEFORE the first external write, `INSERT OR IGNORE`d so a retry
//!   can never replace them, loaded verbatim forever after. Deterministic
//!   SPHINCS+ signing means a regenerated envelope is indistinguishable from
//!   a replayed one — so regeneration is made impossible, not discouraged.
//! - **The admitted coordinate**: one row, written in the SAME transaction
//!   that clears the pending admission.
//! - **The leaf cache**: strategy A of the producer-SMT persistence. A cache,
//!   never an authority — the loader recomputes its root and discards the
//!   whole cache on mismatch, falling back to witness replay.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;

fn digest32(v: Vec<u8>, what: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| anyhow!("{what} is not 32 bytes"))
}

/// Freeze a ticket-claim envelope. `INSERT OR IGNORE`: the FIRST bytes win
/// forever, exactly like the register cell they will be sent to.
pub fn put_frozen_ticket_claim(
    faucet_id: &[u8; 32],
    ticket_index: u64,
    envelope: &[u8],
    now: i64,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR IGNORE INTO faucet_ticket_claim_local
           (faucet_id, ticket_index, envelope, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            faucet_id.as_slice(),
            i64::try_from(ticket_index).map_err(|_| anyhow!("ticket_index overflow"))?,
            envelope,
            now
        ],
    )?;
    Ok(())
}

/// The frozen ticket-claim envelope, exact bytes.
pub fn get_frozen_ticket_claim(faucet_id: &[u8; 32], ticket_index: u64) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT envelope FROM faucet_ticket_claim_local
              WHERE faucet_id = ?1 AND ticket_index = ?2",
            params![
                faucet_id.as_slice(),
                i64::try_from(ticket_index).map_err(|_| anyhow!("ticket_index overflow"))?
            ],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(row)
}
