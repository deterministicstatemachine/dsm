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

/// STARTUP RECONCILE — rebuild any projection that diverges from the canonical head.
///
/// The queue above only catches projections a live send FAILED to write. It does
/// NOT catch a projection that was blanked out-of-band (e.g. by the deleted
/// destructive rollback, which is how 8XK ended up with an empty
/// `balance_projections` while its head still held 275). This sweep is the
/// belt-and-braces: for every token the CANONICAL head carries, ensure the
/// projection row exists and equals the head's balance; rebuild it from the head
/// if missing or divergent.
///
/// The head is never touched — it is the authority; the projection is the cache.
/// Idempotent and cheap (one row per token), so it is safe to run every startup.
/// Returns `(rebuilt, checked)`.
pub fn reconcile_projections_against_head(device_id_bytes: &[u8; 32]) -> Result<(usize, usize)> {
    let Some(head) = super::load_bcr_device_head(device_id_bytes)? else {
        return Ok((0, 0));
    };
    let device_txt = crate::util::text_id::encode_base32_crockford(device_id_bytes);

    let mut rebuilt = 0usize;
    let mut checked = 0usize;
    for (policy_commit, head_balance) in head.balances_snapshot() {
        // Only builtin tokens have a stable ticker resolvable from the policy
        // commit alone; the projection is keyed by that ticker.
        let Some(token_id) = dsm::core::token::builtin_token_id_for_policy_commit(policy_commit)
        else {
            continue;
        };
        checked += 1;

        let locked = super::get_locked_balance(&device_txt, token_id).unwrap_or(0);
        let expected_available = head_balance.saturating_sub(locked);

        let current = super::get_balance_projection(&device_txt, token_id)?;
        let matches = current
            .as_ref()
            .map(|r| r.available == expected_available && r.locked == locked)
            .unwrap_or(false);
        if matches {
            continue;
        }

        match super::build_balance_projection_from_device_head(
            &device_txt,
            token_id,
            policy_commit,
            &head,
            *head_balance,
            locked,
        )
        .and_then(|record| super::upsert_balance_projection(&record))
        {
            Ok(()) => {
                rebuilt += 1;
                log::info!(
                    "[projection-reconcile] {device_txt}:{token_id} rebuilt from canonical head (available={expected_available})"
                );
            }
            Err(e) => log::warn!(
                "[projection-reconcile] {device_txt}:{token_id} rebuild failed ({e}) — head unchanged"
            ),
        }
    }
    Ok((rebuilt, checked))
}

/// EVIDENCE-BASED TIP RECONCILE — converge a relationship's symmetric projection
/// tips when they diverged by exactly one ACCEPTED transition.
///
/// The original defect-1 incident could leave `contacts.chain_tip` stuck at an
/// accepted transition's projection_parent while `local_bilateral_chain_tip`
/// correctly advanced to its projection_target (8XK's residue). A send from the
/// stale `chain_tip` then fails the gate's "would overwrite a divergent local
/// bilateral chain tip" check. `finalize_on_acceptance_atomically` prevents this
/// going forward; this heals PRE-EXISTING data.
///
/// It converges ONLY when a FINALIZED proposal attests the exact
/// (chain_tip -> local_bilateral) advance — never a guess. Returns rows healed.
pub fn reconcile_diverged_projection_tips() -> Result<usize> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let n = conn.execute(
        "UPDATE contacts
            SET chain_tip = local_bilateral_chain_tip, needs_online_reconcile = 0
          WHERE needs_online_reconcile != 0
            AND local_bilateral_chain_tip IS NOT NULL
            AND chain_tip IS NOT NULL
            AND chain_tip != local_bilateral_chain_tip
            AND EXISTS (
                SELECT 1 FROM sender_online_proposal p
                 WHERE p.status = 'finalized'
                   AND p.projection_parent = contacts.chain_tip
                   AND p.projection_target = contacts.local_bilateral_chain_tip
            )",
        [],
    )?;
    if n > 0 {
        log::info!("[tip-reconcile] converged {n} diverged projection tip(s) from finalized-proposal evidence");
    }
    Ok(n)
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

    fn with_conn<T>(f: impl FnOnce(&rusqlite::Connection) -> T) -> T {
        let binding = crate::storage::client_db::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn)
    }

    /// Build a canonical head carrying `amount` ERA via a self-mint advance, and
    /// return (devid, head).
    fn head_with_era(amount: u64) -> ([u8; 32], dsm::types::device_state::DeviceState) {
        use dsm::types::device_state::{BalanceDelta, BalanceDirection};
        let devid = [0x8Cu8; 32];
        let base = dsm::types::device_state::DeviceState::new(devid, devid, vec![0xAAu8; 32], 64);
        let policy = crate::policy::builtin_policy_commit("ERA").unwrap();
        let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid, &devid);
        let init = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &devid, &devid,
        );
        let outcome = base
            .advance(
                rel,
                devid,
                dsm::types::operations::Operation::Mint {
                    amount: dsm::types::token_types::Balance::from_state(amount, [0u8; 32]),
                    token_id: b"ERA".to_vec(),
                    authorized_by: b"self".to_vec(),
                    proof_of_authorization: Vec::new(),
                    message: "mint".to_string(),
                },
                vec![0x11u8; 32],
                None,
                &[BalanceDelta {
                    policy_commit: policy,
                    direction: BalanceDirection::Credit,
                    amount,
                }],
                Some(init),
                None,
                None,
            )
            .expect("mint advance");
        (devid, outcome.new_device_state)
    }

    /// THE 8XK CASE. Head intact at 275, projection empty (blanked out-of-band, no
    /// repair ever queued). The startup reconcile must rebuild the projection from
    /// the head WITHOUT touching the head.
    #[test]
    #[serial]
    fn reconcile_rebuilds_a_projection_blanked_out_of_band() {
        init();
        let (devid, head) = head_with_era(275);
        crate::storage::client_db::update_bcr_device_head(&head).expect("write head");
        let root_before = head.root();

        let devid_txt = crate::util::text_id::encode_base32_crockford(&devid);
        assert!(
            crate::storage::client_db::get_balance_projection(&devid_txt, "ERA")
                .unwrap()
                .is_none(),
            "precondition: projection is empty, like 8XK"
        );
        // Nothing was ever queued — the queue-driven drain cannot help here.
        assert!(!has_pending_projection_repairs().unwrap());

        let (rebuilt, checked) = reconcile_projections_against_head(&devid).unwrap();
        assert_eq!((rebuilt, checked), (1, 1));

        let proj = crate::storage::client_db::get_balance_projection(&devid_txt, "ERA")
            .unwrap()
            .expect("projection rebuilt");
        assert_eq!(
            proj.available, 275,
            "projection rebuilt to the head's balance"
        );

        // The head is the authority and must be byte-identical after reconcile.
        let head_after = crate::storage::client_db::load_bcr_device_head(&devid)
            .unwrap()
            .unwrap();
        assert_eq!(
            head_after.root(),
            root_before,
            "reconcile must NOT touch the head"
        );
        assert_eq!(head_after.balances_snapshot(), head.balances_snapshot());
    }

    /// Evidence-based tip reconcile heals a diverged (chain_tip, local_bilateral)
    /// pair ONLY when a finalized proposal attests the exact advance.
    #[test]
    #[serial]
    fn tip_reconcile_converges_from_finalized_proposal_evidence() {
        init();
        let parent = [0x28u8; 32];
        let target = [0x63u8; 32];
        let devd = [0xB1u8; 32];
        // A contact stuck: chain_tip at the parent, local_bilateral at the target.
        with_conn(|c| {
            c.execute(
                "INSERT INTO contacts (contact_id, device_id, alias, genesis_hash, chain_tip,
                     added_at, verified, status, needs_online_reconcile,
                     last_seen_online_counter, last_seen_ble_counter, local_bilateral_chain_tip)
                 VALUES ('c1', ?1, 'peer', X'00', ?2, 0, 1, 'active', 1, 0, 0, ?3)",
                rusqlite::params![&devd[..], &parent[..], &target[..]],
            )
            .unwrap();
        });
        // No evidence yet → no heal.
        assert_eq!(reconcile_diverged_projection_tips().unwrap(), 0);

        // A finalized proposal attesting parent -> target.
        let proposal = crate::storage::client_db::SenderOnlineProposal {
            relationship_key: [0x11u8; 32],
            canonical_parent: [0x22u8; 32],
            canonical_child: [0x33u8; 32],
            projection_parent: parent,
            projection_target: target,
            commitment: [0x44u8; 32],
            operation_digest: [0x55u8; 32],
            nonce_hash: [0x66u8; 32],
            message_id: None,
            tx_id: "tx2:x".into(),
            counterparty_device_id: devd,
            amount: 6,
            token_id: "ERA".into(),
            status: crate::storage::client_db::PROPOSAL_FINALIZED.into(),
            created_at: 0,
        };
        crate::storage::client_db::insert_sender_proposal(&proposal).unwrap();

        assert_eq!(
            reconcile_diverged_projection_tips().unwrap(),
            1,
            "healed with evidence"
        );
        let (ct, lt, recon): (Vec<u8>, Vec<u8>, i64) = with_conn(|c| {
            c.query_row("SELECT chain_tip, local_bilateral_chain_tip, needs_online_reconcile FROM contacts WHERE device_id=?1",
                rusqlite::params![&devd[..]], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        });
        assert_eq!(ct, lt, "chain_tip converged to local_bilateral");
        assert_eq!(recon, 0, "reconcile flag cleared");
    }

    /// A projection that already matches the head is left alone (idempotent, cheap).
    #[test]
    #[serial]
    fn reconcile_is_a_noop_when_projection_matches() {
        init();
        let (devid, head) = head_with_era(100);
        crate::storage::client_db::update_bcr_device_head(&head).expect("write head");
        assert_eq!(reconcile_projections_against_head(&devid).unwrap(), (1, 1));
        // Second pass: already matches → nothing rebuilt.
        assert_eq!(reconcile_projections_against_head(&devid).unwrap(), (0, 1));
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
