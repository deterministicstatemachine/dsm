//! Durable "reconcile forward" queue for post-commit projection failures.
//!
//! Once the canonical advance and the durable send bundle commit, nothing
//! downstream may fail the send — the transfer is real and deliverable. But the
//! derived state it left behind (the balance projection, the local history row,
//! the in-memory cache) can still fail to write.
//!
//! A log line is not a repair. If the process dies before anyone reads it, the
//! projection stays wrong forever and the wallet shows a balance that disagrees
//! with canonical state — exactly the shape of the 8XK wound. So the intent to
//! repair is itself persisted, in its own additive table, and a startup sweep
//! drains it by rebuilding from canonical BCR state.
//!
//! The queue is an INTENT, never an authority. It records "this projection is
//! stale"; the rebuild always reads the value back out of the canonical device
//! head. Losing a row costs a stale projection until the next write, never a
//! wrong balance.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// A projection the process failed to write after its transaction committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRepair {
    pub device_id: String,
    pub token_id: String,
    /// Why it was queued — diagnostic only, never branched on.
    pub reason: String,
    pub created_at: u64,
}

/// Record that a projection needs rebuilding from canonical state.
///
/// Idempotent: re-queuing the same `(device_id, token_id)` refreshes the reason
/// rather than piling up rows. Callers are post-commit paths that must NOT fail,
/// so this returns `Result` only so the caller can log it — never to abort a
/// committed transfer.
pub fn enqueue_projection_repair(device_id: &str, token_id: &str, reason: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT INTO projection_repair_queue (device_id, token_id, reason, created_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device_id, token_id) DO UPDATE SET reason = excluded.reason",
        params![device_id, token_id, reason, tick() as i64],
    )?;
    Ok(())
}

/// Every projection still awaiting rebuild.
pub fn pending_projection_repairs() -> Result<Vec<ProjectionRepair>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn.prepare(
        "SELECT device_id, token_id, reason, created_at
           FROM projection_repair_queue ORDER BY created_at",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(ProjectionRepair {
                device_id: r.get(0)?,
                token_id: r.get(1)?,
                reason: r.get(2)?,
                created_at: r.get::<_, i64>(3)? as u64,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Drop a repair once its projection has been rebuilt from canonical state.
pub fn clear_projection_repair(device_id: &str, token_id: &str) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n = conn.execute(
        "DELETE FROM projection_repair_queue WHERE device_id = ?1 AND token_id = ?2",
        params![device_id, token_id],
    )?;
    Ok(n > 0)
}

/// True while this device owes a projection rebuild.
pub fn has_pending_projection_repairs() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let found: Option<i64> = conn
        .query_row("SELECT 1 FROM projection_repair_queue LIMIT 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(found.is_some())
}

/// Drain the queue by rebuilding each stale projection from CANONICAL state.
///
/// The queue says only *which* projection is stale. The value always comes back
/// out of the canonical BCR device head, so a wrong or stale queue row can never
/// install a wrong balance — the worst it can do is trigger a redundant rebuild.
///
/// A repair that cannot be completed (no canonical head yet, unresolvable policy)
/// is LEFT in the queue for the next sweep rather than dropped.
///
/// Returns `(repaired, remaining)`.
pub fn drain_projection_repairs(
    device_id_bytes: &[u8; 32],
    resolve_policy_commit: impl Fn(&str) -> Option<[u8; 32]>,
) -> Result<(usize, usize)> {
    let pending = pending_projection_repairs()?;
    if pending.is_empty() {
        return Ok((0, 0));
    }

    let head = match super::load_bcr_device_head(device_id_bytes)? {
        Some(h) => h,
        None => {
            log::warn!(
                "[projection-repair] {} pending, but no canonical device head yet — retaining",
                pending.len()
            );
            return Ok((0, pending.len()));
        }
    };
    let self_txt = crate::util::text_id::encode_base32_crockford(device_id_bytes);

    let mut repaired = 0usize;
    for item in &pending {
        // Only this device's own projections are rebuildable from this head.
        if item.device_id != self_txt {
            continue;
        }
        let Some(policy_commit) = resolve_policy_commit(&item.token_id) else {
            log::warn!(
                "[projection-repair] cannot resolve policy for {} — retaining",
                item.token_id
            );
            continue;
        };
        let effective = head.balance(&policy_commit);
        let locked = super::get_locked_balance(&item.device_id, &item.token_id).unwrap_or(0);

        match super::build_balance_projection_from_device_head(
            &item.device_id,
            &item.token_id,
            &policy_commit,
            &head,
            effective,
            locked,
        )
        .and_then(|record| super::upsert_balance_projection(&record))
        {
            Ok(()) => {
                let _ = clear_projection_repair(&item.device_id, &item.token_id);
                repaired += 1;
                log::info!(
                    "[projection-repair] rebuilt {}:{} from canonical head (available={})",
                    item.device_id,
                    item.token_id,
                    effective.saturating_sub(locked)
                );
            }
            Err(e) => log::warn!(
                "[projection-repair] rebuild failed for {}:{} ({e}) — retaining",
                item.device_id,
                item.token_id
            ),
        }
    }
    let remaining = pending_projection_repairs()?.len();
    Ok((repaired, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    /// The whole point: the intent to repair outlives the process that formed it.
    #[test]
    #[serial]
    fn a_queued_repair_survives_and_is_drainable() {
        init();
        assert!(!has_pending_projection_repairs().unwrap());

        enqueue_projection_repair("devA", "ERA", "post-commit projection sync failed").unwrap();
        assert!(has_pending_projection_repairs().unwrap());

        let pending = pending_projection_repairs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].device_id, "devA");
        assert_eq!(pending[0].token_id, "ERA");

        assert!(clear_projection_repair("devA", "ERA").unwrap());
        assert!(!has_pending_projection_repairs().unwrap());
        assert!(
            !clear_projection_repair("devA", "ERA").unwrap(),
            "clearing twice is a no-op, not an error"
        );
    }

    /// A repair that cannot be completed yet must be RETAINED, never dropped —
    /// dropping it silently restores the "stale projection forever" failure the
    /// queue exists to prevent.
    #[test]
    #[serial]
    fn an_uncompletable_repair_is_retained_not_dropped() {
        init();
        let device = [0x5Au8; 32];
        let self_txt = crate::util::text_id::encode_base32_crockford(&device);
        enqueue_projection_repair(&self_txt, "ERA", "post-commit sync failed").unwrap();

        // No canonical device head exists in this fixture, so nothing is
        // rebuildable — but the intent must survive for the next sweep.
        let (repaired, remaining) = drain_projection_repairs(&device, |_| Some([7u8; 32])).unwrap();
        assert_eq!(
            repaired, 0,
            "nothing could be rebuilt without a canonical head"
        );
        assert_eq!(remaining, 1, "the repair MUST be retained");
        assert!(has_pending_projection_repairs().unwrap());

        // Unresolvable policy is also a retain, not a drop.
        let (repaired, remaining) = drain_projection_repairs(&device, |_| None).unwrap();
        assert_eq!((repaired, remaining), (0, 1));
    }

    /// A queued repair for a DIFFERENT device is not rebuildable from this
    /// device's canonical head and must be left alone.
    #[test]
    #[serial]
    fn another_devices_repair_is_never_rebuilt_from_our_head() {
        init();
        let device = [0x5Au8; 32];
        enqueue_projection_repair("SOMEONEELSE", "ERA", "not ours").unwrap();
        let (repaired, remaining) = drain_projection_repairs(&device, |_| Some([7u8; 32])).unwrap();
        assert_eq!(repaired, 0);
        assert_eq!(
            remaining, 1,
            "left for its owner, never rebuilt from our head"
        );
    }

    /// A retry storm must not produce a queue that grows without bound.
    #[test]
    #[serial]
    fn requeuing_the_same_projection_is_idempotent() {
        init();
        enqueue_projection_repair("devA", "ERA", "first failure").unwrap();
        enqueue_projection_repair("devA", "ERA", "second failure").unwrap();
        enqueue_projection_repair("devA", "dBTC", "other token").unwrap();

        let pending = pending_projection_repairs().unwrap();
        assert_eq!(pending.len(), 2, "one row per (device, token)");
        let era = pending.iter().find(|p| p.token_id == "ERA").unwrap();
        assert_eq!(
            era.reason, "second failure",
            "the latest reason wins — it is diagnostic, never authority"
        );
    }
}
