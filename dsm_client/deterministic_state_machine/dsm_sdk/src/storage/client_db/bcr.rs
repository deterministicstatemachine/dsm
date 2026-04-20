// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bilateral control resistance (BCR) state persistence.
//!
//! Canonical storage layout (whitepaper §2.2/§4.2/§8 aligned):
//!
//! - `bcr_chain_states` — per-relationship [`RelationshipChainState`] archive
//!   keyed by `(device_id, chain_tip)`. Authoritative per-advance history.
//! - `bcr_device_heads` — UPSERTed [`DeviceState`] head cache keyed by
//!   `device_id`. Non-authoritative latest snapshot of the canonical SMT
//!   root, balances, and per-relationship tips.
//!
//! Both tables are written from the producer chokepoint in
//! `CoreSDK::execute_on_relationship` so every advance produces a chain-state
//! row and refreshes the head-cache row in a single SQLite transaction.
//!
//! The legacy device-monolith `bcr_states` table and its `State`-shaped APIs
//! were removed in the Phase 4.1 cleanup — there is no counter, no monolithic
//! per-device snapshot, and no `state_number` anywhere in this module.
//!
//! Codecs match the **real** field layout in `dsm/src/types/device_state.rs`
//! byte-for-byte. The hash-input prefix of [`RelationshipChainState`] mirrors
//! `compute_chain_tip()` exactly so a decoder can recompute and assert digest
//! equality with the stored `chain_tip` column. Signatures are appended
//! outside the hashed prefix.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use dsm::types::device_state::{DeviceState, RelChainTip, RelationshipChainState};
use dsm::types::operations::Operation;
use log::warn;
use rusqlite::{params, Connection, OptionalExtension};

use super::get_connection;
use crate::storage::codecs::{read_len_u32, read_u8, read_vec, take};
use crate::util::deterministic_time::tick;

/// Store a compact suspicious-activity report (bytes-only).
pub fn store_bcr_report(report: &[u8]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();

    conn.execute(
        "INSERT INTO bcr_reports(report, created_at) VALUES (?1, ?2)",
        params![report, now as i64],
    )?;

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// RelationshipChainState + DeviceState codecs and storage.
//
// These codecs are byte-exact for the real types in
// `dsm/src/types/device_state.rs`. The hashed prefix of a RelationshipChainState
// matches `compute_chain_tip()` (rel_key ‖ embedded_parent ‖ counterparty_devid
// ‖ op(len+bytes) ‖ entropy(len+bytes) ‖ encap_flag+optional ‖ dbrw_flag+
// optional fixed 32B (NO length prefix) ‖ witness count + (policy_commit ‖
// value u64 le) sorted). Sigs are appended outside the hashed prefix.
// ──────────────────────────────────────────────────────────────────────────

const REL_CHAIN_STATE_VERSION: u8 = 0x02;
const DEVICE_STATE_VERSION: u8 = 0x01;

#[inline]
fn put_len_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

#[inline]
fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    put_len_u32(out, v.len());
    out.extend_from_slice(v);
}

/// Encode a [`RelationshipChainState`] for archive storage.
///
/// Layout: a leading version byte, then the hash-input prefix mirroring
/// `compute_chain_tip()` byte-for-byte, then the two optional signatures
/// (which are NOT part of the hash). Decoder can recompute the chain tip
/// over the prefix and assert equality with the stored column.
pub fn encode_rel_chain_state(state: &RelationshipChainState) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.push(REL_CHAIN_STATE_VERSION);

    // ── hash-input prefix (matches compute_chain_tip) ─────────────────
    out.extend_from_slice(&state.rel_key);
    out.extend_from_slice(&state.embedded_parent);
    out.extend_from_slice(&state.counterparty_devid);

    let op_bytes = state.operation.to_bytes();
    put_vec(&mut out, &op_bytes);

    put_vec(&mut out, &state.entropy);

    match &state.encapsulated_entropy {
        Some(enc) => {
            out.push(1u8);
            put_vec(&mut out, enc);
        }
        None => out.push(0u8),
    }

    match &state.dbrw_summary_hash {
        Some(d) => {
            out.push(1u8);
            // Fixed 32 bytes, NO length prefix — mirrors compute_chain_tip().
            out.extend_from_slice(d);
        }
        None => out.push(0u8),
    }

    // BTreeMap iteration is sorted by key; balance_witness is keyed by 32B
    // policy_commit so the iteration order matches the canonical hash.
    put_len_u32(&mut out, state.balance_witness.len());
    for (policy_commit, value) in &state.balance_witness {
        out.extend_from_slice(policy_commit);
        out.extend_from_slice(&value.to_le_bytes());
    }

    // ── sigs appended after hashed prefix (NOT part of hash) ──────────
    match &state.entity_sig {
        Some(s) => {
            out.push(1u8);
            put_vec(&mut out, s);
        }
        None => out.push(0u8),
    }
    match &state.counterparty_sig {
        Some(s) => {
            out.push(1u8);
            put_vec(&mut out, s);
        }
        None => out.push(0u8),
    }

    out
}

/// Decode a [`RelationshipChainState`] from canonical bytes produced by
/// [`encode_rel_chain_state`]. Returns the recomputed `chain_tip` so callers
/// can sanity-check against the stored column.
pub fn decode_rel_chain_state(bytes: &[u8]) -> Result<(RelationshipChainState, [u8; 32])> {
    let mut cursor = bytes;

    let version = read_u8(&mut cursor).map_err(|e| anyhow!("rel_chain_state version: {e}"))?;
    if version != REL_CHAIN_STATE_VERSION {
        return Err(anyhow!(
            "rel_chain_state unknown version {version} (expected {REL_CHAIN_STATE_VERSION})"
        ));
    }

    let rel_key: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("rel_key: {e}"))?;
    let embedded_parent: [u8; 32] =
        take::<32>(&mut cursor).map_err(|e| anyhow!("embedded_parent: {e}"))?;
    let counterparty_devid: [u8; 32] =
        take::<32>(&mut cursor).map_err(|e| anyhow!("counterparty_devid: {e}"))?;

    let op_bytes = read_vec(&mut cursor).map_err(|e| anyhow!("operation bytes: {e}"))?;
    let operation =
        Operation::from_bytes(&op_bytes).map_err(|e| anyhow!("operation decode failed: {e}"))?;

    let entropy = read_vec(&mut cursor).map_err(|e| anyhow!("entropy: {e}"))?;

    let encap_flag = read_u8(&mut cursor).map_err(|e| anyhow!("encap_flag: {e}"))?;
    let encapsulated_entropy = match encap_flag {
        0 => None,
        1 => Some(read_vec(&mut cursor).map_err(|e| anyhow!("encap entropy: {e}"))?),
        other => return Err(anyhow!("encap_flag invalid: {other}")),
    };

    let dbrw_flag = read_u8(&mut cursor).map_err(|e| anyhow!("dbrw_flag: {e}"))?;
    let dbrw_summary_hash = match dbrw_flag {
        0 => None,
        1 => Some(take::<32>(&mut cursor).map_err(|e| anyhow!("dbrw summary: {e}"))?),
        other => return Err(anyhow!("dbrw_flag invalid: {other}")),
    };

    let witness_count = read_len_u32(&mut cursor).map_err(|e| anyhow!("witness count: {e}"))?;
    let mut balance_witness: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for _ in 0..witness_count {
        let pc: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("witness pc: {e}"))?;
        let val_bytes: [u8; 8] =
            take::<8>(&mut cursor).map_err(|e| anyhow!("witness value: {e}"))?;
        balance_witness.insert(pc, u64::from_le_bytes(val_bytes));
    }

    // ── sigs (after hashed prefix) ─────────────────────────────────────
    let entity_sig_flag = read_u8(&mut cursor).map_err(|e| anyhow!("entity_sig_flag: {e}"))?;
    let entity_sig = match entity_sig_flag {
        0 => None,
        1 => Some(read_vec(&mut cursor).map_err(|e| anyhow!("entity_sig: {e}"))?),
        other => return Err(anyhow!("entity_sig_flag invalid: {other}")),
    };
    let cp_sig_flag = read_u8(&mut cursor).map_err(|e| anyhow!("cp_sig_flag: {e}"))?;
    let counterparty_sig = match cp_sig_flag {
        0 => None,
        1 => Some(read_vec(&mut cursor).map_err(|e| anyhow!("counterparty_sig: {e}"))?),
        other => return Err(anyhow!("cp_sig_flag invalid: {other}")),
    };

    let state = RelationshipChainState {
        rel_key,
        embedded_parent,
        counterparty_devid,
        operation,
        entropy,
        encapsulated_entropy,
        balance_witness,
        entity_sig,
        counterparty_sig,
        dbrw_summary_hash,
    };
    let chain_tip = state.compute_chain_tip();
    Ok((state, chain_tip))
}

/// Encode a [`DeviceState`] for the head cache.
///
/// Layout matches the real `DeviceState` struct: genesis, devid, public_key
/// (length-prefixed), smt_root sanity-check digest, optional legacy_anchor,
/// balances `(policy_commit ‖ u64 le)` sorted by `policy_commit`, and tips
/// `(rel_key ‖ chain_tip ‖ counterparty_devid ‖ optional state)` sorted by
/// `rel_key`. The optional tip state, when present, is itself a
/// [`RelationshipChainState`] encoded with [`encode_rel_chain_state`] and
/// length-prefixed so the decoder can skip it cleanly if it ever needs to.
pub fn encode_device_state(head: &DeviceState) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.push(DEVICE_STATE_VERSION);

    out.extend_from_slice(&head.genesis_digest());
    out.extend_from_slice(&head.devid());

    let pk = head.public_key();
    put_vec(&mut out, pk);

    out.extend_from_slice(&head.root());

    match head.legacy_anchor() {
        Some(a) => {
            out.push(1u8);
            out.extend_from_slice(&a);
        }
        None => out.push(0u8),
    }

    let balances = head.balances_snapshot();
    put_len_u32(&mut out, balances.len());
    for (pc, val) in balances {
        out.extend_from_slice(pc);
        out.extend_from_slice(&val.to_le_bytes());
    }

    // Tips: iterate over the relationship_keys() set sorted by rel_key.
    let rel_keys = head.relationship_keys();
    put_len_u32(&mut out, rel_keys.len());
    for rk in &rel_keys {
        let Some(tip) = head.rel_chain_tip(rk) else {
            #[allow(clippy::panic)]
            {
                panic!("rel_key listed in keys must have a RelChainTip");
            }
        };

        out.extend_from_slice(rk);
        out.extend_from_slice(&tip.chain_tip);
        out.extend_from_slice(&tip.counterparty_devid);

        match tip.state.as_ref() {
            Some(s) => {
                out.push(1u8);
                let inner = encode_rel_chain_state(s);
                put_vec(&mut out, &inner);
            }
            None => out.push(0u8),
        }
    }

    out
}

/// Decode a [`DeviceState`] from bytes produced by [`encode_device_state`].
///
/// Returns the decoded state and the stored `smt_root` sanity-check value;
/// the caller asserts `decoded.root() == stored_smt_root`.
pub fn decode_device_state(bytes: &[u8]) -> Result<(DeviceState, [u8; 32])> {
    let mut cursor = bytes;

    let version = read_u8(&mut cursor).map_err(|e| anyhow!("device_state version: {e}"))?;
    if version != DEVICE_STATE_VERSION {
        return Err(anyhow!(
            "device_state unknown version {version} (expected {DEVICE_STATE_VERSION})"
        ));
    }

    let genesis: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("genesis: {e}"))?;
    let devid: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("devid: {e}"))?;
    let public_key = read_vec(&mut cursor).map_err(|e| anyhow!("public_key: {e}"))?;
    let smt_root: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("smt_root: {e}"))?;

    let anchor_flag = read_u8(&mut cursor).map_err(|e| anyhow!("anchor_flag: {e}"))?;
    let legacy_anchor = match anchor_flag {
        0 => None,
        1 => Some(take::<32>(&mut cursor).map_err(|e| anyhow!("legacy_anchor: {e}"))?),
        other => return Err(anyhow!("anchor_flag invalid: {other}")),
    };

    let bal_count = read_len_u32(&mut cursor).map_err(|e| anyhow!("bal count: {e}"))?;
    let mut balances: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for _ in 0..bal_count {
        let pc: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("bal pc: {e}"))?;
        let val_bytes: [u8; 8] = take::<8>(&mut cursor).map_err(|e| anyhow!("bal val: {e}"))?;
        balances.insert(pc, u64::from_le_bytes(val_bytes));
    }

    let tip_count = read_len_u32(&mut cursor).map_err(|e| anyhow!("tip count: {e}"))?;
    let mut tips_in_order: Vec<([u8; 32], RelChainTip)> = Vec::with_capacity(tip_count);
    for _ in 0..tip_count {
        let rk: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("tip rk: {e}"))?;
        let chain_tip: [u8; 32] =
            take::<32>(&mut cursor).map_err(|e| anyhow!("tip chain_tip: {e}"))?;
        let cp_devid: [u8; 32] =
            take::<32>(&mut cursor).map_err(|e| anyhow!("tip cp_devid: {e}"))?;
        let state_flag = read_u8(&mut cursor).map_err(|e| anyhow!("tip state flag: {e}"))?;
        let state = match state_flag {
            0 => None,
            1 => {
                let inner = read_vec(&mut cursor).map_err(|e| anyhow!("tip state bytes: {e}"))?;
                let (decoded, recomputed_tip) = decode_rel_chain_state(&inner)?;
                if recomputed_tip != chain_tip {
                    return Err(anyhow!(
                        "tip cached state digest mismatch: encoded {} != recomputed {}",
                        crate::util::text_id::encode_base32_crockford(&chain_tip),
                        crate::util::text_id::encode_base32_crockford(&recomputed_tip)
                    ));
                }
                Some(decoded)
            }
            other => return Err(anyhow!("tip state_flag invalid: {other}")),
        };
        tips_in_order.push((
            rk,
            RelChainTip {
                chain_tip,
                counterparty_devid: cp_devid,
                state,
            },
        ));
    }

    // Replay tips into the SMT to rebuild the canonical root.
    let head = DeviceState::restore(
        genesis,
        devid,
        public_key,
        legacy_anchor,
        balances,
        tips_in_order,
        1024,
    )
    .map_err(|e| anyhow!("DeviceState::restore failed: {e}"))?;

    if head.root() != smt_root {
        return Err(anyhow!(
            "device_state SMT root mismatch: encoded {} != recomputed {}",
            crate::util::text_id::encode_base32_crockford(&smt_root),
            crate::util::text_id::encode_base32_crockford(&head.root())
        ));
    }

    Ok((head, smt_root))
}

// ──────────────────────────────────────────────────────────────────────────
// Storage APIs for the new tables.
// ──────────────────────────────────────────────────────────────────────────

/// Persist one accepted [`RelationshipChainState`] in `bcr_chain_states`
/// for the supplied `device_id`.
///
/// `RelationshipChainState` itself doesn't carry a `device_id` field — the
/// owning device is implicit in the SMT root that contains this leaf — so
/// the caller passes it explicitly. The chokepoint
/// `CoreSDK::execute_on_relationship` reads
/// `outcome.new_device_state.devid()` for this argument.
pub fn store_bcr_chain_state(
    device_id: &[u8; 32],
    state: &RelationshipChainState,
    published: bool,
) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();
    store_bcr_chain_state_with_conn(&conn, device_id, state, published, now)
}

pub(crate) fn store_bcr_chain_state_with_conn(
    conn: &Connection,
    device_id: &[u8; 32],
    state: &RelationshipChainState,
    published: bool,
    now: u64,
) -> Result<()> {
    let chain_tip = state.compute_chain_tip();
    let bytes = encode_rel_chain_state(state);

    conn.execute(
        "INSERT OR REPLACE INTO bcr_chain_states(
            device_id, rel_key, chain_tip, embedded_parent, state_bytes,
            published, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            device_id.as_slice(),
            state.rel_key.as_slice(),
            chain_tip.as_slice(),
            state.embedded_parent.as_slice(),
            bytes,
            if published { 1i32 } else { 0i32 },
            now as i64,
        ],
    )?;

    Ok(())
}

/// Load all archived [`RelationshipChainState`]s for a device, ordered by
/// insertion time. Optionally filter to published-only.
pub fn get_bcr_chain_states(
    device_id: &[u8],
    published_only: bool,
) -> Result<Vec<RelationshipChainState>> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length: {}", device_id.len()));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = if published_only {
        conn.prepare(
            "SELECT state_bytes, chain_tip FROM bcr_chain_states
             WHERE device_id = ?1 AND published = 1
             ORDER BY created_at ASC, rowid ASC",
        )?
    } else {
        conn.prepare(
            "SELECT state_bytes, chain_tip FROM bcr_chain_states
             WHERE device_id = ?1
             ORDER BY created_at ASC, rowid ASC",
        )?
    };

    let iter = stmt.query_map(params![device_id], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        let tip: Vec<u8> = row.get(1)?;
        Ok((bytes, tip))
    })?;
    let mut out = Vec::new();
    for row in iter {
        let (bytes, expected_tip) = row?;
        match decode_rel_chain_state(&bytes) {
            Ok((state, recomputed_tip)) => {
                if expected_tip.len() == 32 && recomputed_tip.as_slice() != expected_tip.as_slice()
                {
                    warn!("[client_db] bcr_chain_states tip mismatch (corruption?), skipping row");
                    continue;
                }
                out.push(state);
            }
            Err(e) => warn!("[client_db] Skipping invalid bcr_chain_states row: {e}"),
        }
    }

    Ok(out)
}

/// Load all archived chain states for a specific relationship `rel_key`,
/// ordered by insertion time.
pub fn get_bcr_chain_states_for_rel(
    device_id: &[u8],
    rel_key: &[u8; 32],
) -> Result<Vec<RelationshipChainState>> {
    if device_id.len() != 32 {
        return Err(anyhow!("Invalid device_id length: {}", device_id.len()));
    }

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let mut stmt = conn.prepare(
        "SELECT state_bytes, chain_tip FROM bcr_chain_states
         WHERE device_id = ?1 AND rel_key = ?2
         ORDER BY created_at ASC, rowid ASC",
    )?;

    let iter = stmt.query_map(params![device_id, rel_key.as_slice()], |row| {
        let bytes: Vec<u8> = row.get(0)?;
        let tip: Vec<u8> = row.get(1)?;
        Ok((bytes, tip))
    })?;

    let mut out = Vec::new();
    for row in iter {
        let (bytes, expected_tip) = row?;
        match decode_rel_chain_state(&bytes) {
            Ok((state, recomputed_tip)) => {
                if expected_tip.len() == 32 && recomputed_tip.as_slice() != expected_tip.as_slice()
                {
                    warn!("[client_db] bcr_chain_states tip mismatch (corruption?), skipping row");
                    continue;
                }
                out.push(state);
            }
            Err(e) => warn!("[client_db] Skipping invalid bcr_chain_states row: {e}"),
        }
    }

    Ok(out)
}

/// UPSERT the device head cache (`bcr_device_heads`).
pub fn update_bcr_device_head(head: &DeviceState) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    let now = tick();
    update_bcr_device_head_with_conn(&conn, head, now)
}

pub(crate) fn update_bcr_device_head_with_conn(
    conn: &Connection,
    head: &DeviceState,
    now: u64,
) -> Result<()> {
    let smt_root = head.root();
    let bytes = encode_device_state(head);
    let devid = head.devid();

    conn.execute(
        "INSERT INTO bcr_device_heads(device_id, smt_root, head_bytes, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device_id) DO UPDATE SET
            smt_root = excluded.smt_root,
            head_bytes = excluded.head_bytes,
            updated_at = excluded.updated_at",
        params![devid.as_slice(), smt_root.as_slice(), bytes, now as i64,],
    )?;

    Ok(())
}

/// Load the cached [`DeviceState`] head for a device, if any.
///
/// Returns `Ok(None)` for an unknown device. Returns `Err` only on a database
/// or codec failure (corrupt row, root mismatch).
pub fn load_bcr_device_head(device_id: &[u8; 32]) -> Result<Option<DeviceState>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT head_bytes FROM bcr_device_heads WHERE device_id = ?1",
            params![device_id.as_slice()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;

    match row {
        None => Ok(None),
        Some(bytes) => {
            let (head, _root) = decode_device_state(&bytes)?;
            Ok(Some(head))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
    use dsm::types::operations::{Operation, TransactionMode, VerificationType};
    use dsm::types::token_types::Balance as TokenBalance;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn sample_operation(tag: &[u8], amount: u64) -> Operation {
        Operation::Transfer {
            to_device_id: vec![0xBB; 32],
            amount: TokenBalance::from_state(amount, [0u8; 32]),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![0xCC; 8],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: vec![0xDD; 64],
            to: tag.to_vec(),
            message: String::from_utf8_lossy(tag).into_owned(),
            signature: vec![0xEE; 64],
        }
    }

    fn sample_device_and_rel() -> (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        RelationshipChainState,
        DeviceState,
    ) {
        let device_id = [0xA1; 32];
        let counterparty = [0xB2; 32];
        let rel_key = [0xC3; 32];
        let policy_commit = [0xD4; 32];
        let device = DeviceState::new([0x11; 32], device_id, vec![0x22; 64], 1024);
        let outcome = device
            .advance(
                rel_key,
                counterparty,
                sample_operation(b"rel-1", 7),
                vec![0x33; 32],
                Some(vec![0x44; 48]),
                &[BalanceDelta {
                    policy_commit,
                    direction: BalanceDirection::Credit,
                    amount: 7,
                }],
                Some([0x55; 32]),
                Some([0x66; 32]),
            )
            .expect("advance relationship");

        let mut rel = outcome.new_chain_state.clone();
        rel.entity_sig = Some(vec![0x77; 64]);
        rel.counterparty_sig = Some(vec![0x88; 64]);

        let tips = outcome.new_device_state.relationship_keys();
        assert_eq!(tips, vec![rel_key]);

        let head = DeviceState::restore(
            outcome.new_device_state.genesis_digest(),
            outcome.new_device_state.devid(),
            outcome.new_device_state.public_key().to_vec(),
            Some([0x99; 32]),
            outcome.new_device_state.balances_snapshot().clone(),
            vec![(
                rel_key,
                RelChainTip {
                    chain_tip: rel.compute_chain_tip(),
                    counterparty_devid: counterparty,
                    state: Some(rel.clone()),
                },
            )],
            1024,
        )
        .expect("restore head with signed rel state");

        (device_id, counterparty, rel_key, rel, head)
    }

    fn head_with_state_less_tip() -> ([u8; 32], [u8; 32], DeviceState) {
        let device_id = [0xA9; 32];
        let rel_key = [0xBC; 32];
        let counterparty = [0xCD; 32];
        let chain_tip = [0xDE; 32];
        let head = DeviceState::restore(
            [0xEF; 32],
            device_id,
            vec![0xAB; 64],
            None,
            BTreeMap::new(),
            vec![(
                rel_key,
                RelChainTip {
                    chain_tip,
                    counterparty_devid: counterparty,
                    state: None,
                },
            )],
            1024,
        )
        .expect("restore head with state-less tip");
        (device_id, rel_key, head)
    }

    #[test]
    #[serial]
    fn store_and_get_bcr_report() {
        init_test_db();
        let report = b"suspicious-activity-report-data";
        store_bcr_report(report).unwrap();
    }

    #[test]
    #[serial]
    fn store_multiple_bcr_reports() {
        init_test_db();
        store_bcr_report(b"report-1").unwrap();
        store_bcr_report(b"report-2").unwrap();
        store_bcr_report(b"report-3").unwrap();
    }

    #[test]
    fn rel_chain_state_codec_roundtrip() {
        let (_, _, _, rel, _) = sample_device_and_rel();
        let bytes = encode_rel_chain_state(&rel);
        let (decoded, tip) = decode_rel_chain_state(&bytes).expect("decode rel state");

        assert_eq!(tip, rel.compute_chain_tip());
        assert_eq!(decoded.rel_key, rel.rel_key);
        assert_eq!(decoded.embedded_parent, rel.embedded_parent);
        assert_eq!(decoded.counterparty_devid, rel.counterparty_devid);
        assert_eq!(decoded.operation.to_bytes(), rel.operation.to_bytes());
        assert_eq!(decoded.entropy, rel.entropy);
        assert_eq!(decoded.encapsulated_entropy, rel.encapsulated_entropy);
        assert_eq!(decoded.balance_witness, rel.balance_witness);
        assert_eq!(decoded.entity_sig, rel.entity_sig);
        assert_eq!(decoded.counterparty_sig, rel.counterparty_sig);
        assert_eq!(decoded.dbrw_summary_hash, rel.dbrw_summary_hash);
    }

    #[test]
    fn device_head_codec_roundtrip_preserves_tip_and_root() {
        let (_, _, rel_key, rel, head) = sample_device_and_rel();
        let bytes = encode_device_state(&head);
        let (decoded, stored_root) = decode_device_state(&bytes).expect("decode device head");

        assert_eq!(stored_root, head.root());
        assert_eq!(decoded.root(), head.root());
        assert_eq!(decoded.genesis_digest(), head.genesis_digest());
        assert_eq!(decoded.devid(), head.devid());
        assert_eq!(decoded.legacy_anchor(), head.legacy_anchor());
        assert_eq!(decoded.balances_snapshot(), head.balances_snapshot());
        assert_eq!(decoded.chain_tip(&rel_key), Some(rel.compute_chain_tip()));
        assert_eq!(
            decoded
                .rel_chain_tip(&rel_key)
                .map(|t| t.counterparty_devid),
            Some(rel.counterparty_devid)
        );
        assert!(decoded.tip_state(&rel_key).is_some());
    }

    #[test]
    fn device_head_codec_preserves_state_less_tip_counterparty() {
        let (_, rel_key, head) = head_with_state_less_tip();
        let bytes = encode_device_state(&head);
        let (decoded, _) = decode_device_state(&bytes).expect("decode device head");

        let original_tip = head.rel_chain_tip(&rel_key).expect("original rel tip");
        let decoded_tip = decoded.rel_chain_tip(&rel_key).expect("decoded rel tip");
        assert_eq!(decoded_tip.chain_tip, original_tip.chain_tip);
        assert_eq!(
            decoded_tip.counterparty_devid,
            original_tip.counterparty_devid
        );
        assert!(decoded_tip.state.is_none());
    }

    #[test]
    #[serial]
    fn bcr_chain_state_store_load_and_filters() {
        let (device_id, counterparty, rel_key, rel0, head0) = sample_device_and_rel();
        init_test_db();

        store_bcr_chain_state(&device_id, &rel0, true).expect("store published rel state");

        let outcome1 = head0
            .advance(
                rel_key,
                counterparty,
                sample_operation(b"rel-2", 9),
                vec![0x45; 32],
                None,
                &[BalanceDelta {
                    policy_commit: [0xD4; 32],
                    direction: BalanceDirection::Credit,
                    amount: 2,
                }],
                None,
                None,
            )
            .expect("second advance");
        store_bcr_chain_state(&device_id, &outcome1.new_chain_state, false)
            .expect("store unpublished rel state");

        let published = get_bcr_chain_states(&device_id, true).expect("load published rel states");
        let all = get_bcr_chain_states(&device_id, false).expect("load all rel states");
        let per_rel = get_bcr_chain_states_for_rel(&device_id, &rel_key).expect("load rel");

        assert_eq!(published.len(), 1);
        assert_eq!(all.len(), 2);
        assert_eq!(per_rel.len(), 2);
        assert_eq!(published[0].compute_chain_tip(), rel0.compute_chain_tip());
        assert_eq!(
            all[1].compute_chain_tip(),
            outcome1.new_chain_state.compute_chain_tip()
        );
    }

    #[test]
    #[serial]
    fn bcr_device_head_upsert_roundtrip() {
        let (device_id, _, rel_key, rel0, head0) = sample_device_and_rel();
        init_test_db();

        update_bcr_device_head(&head0).expect("store head0");
        let cached0 = load_bcr_device_head(&device_id)
            .expect("load head0")
            .expect("head0 exists");
        assert_eq!(cached0.root(), head0.root());
        assert_eq!(cached0.chain_tip(&rel_key), Some(rel0.compute_chain_tip()));

        let outcome1 = head0
            .advance(
                rel_key,
                rel0.counterparty_devid,
                sample_operation(b"rel-3", 11),
                vec![0x56; 32],
                None,
                &[BalanceDelta {
                    policy_commit: [0xD4; 32],
                    direction: BalanceDirection::Credit,
                    amount: 4,
                }],
                None,
                Some([0xAA; 32]),
            )
            .expect("third advance");
        update_bcr_device_head(&outcome1.new_device_state).expect("upsert head1");

        let cached1 = load_bcr_device_head(&device_id)
            .expect("load head1")
            .expect("head1 exists");
        assert_eq!(cached1.root(), outcome1.new_device_state.root());
        assert_eq!(
            cached1.chain_tip(&rel_key),
            Some(outcome1.new_chain_state.compute_chain_tip())
        );
    }
}
