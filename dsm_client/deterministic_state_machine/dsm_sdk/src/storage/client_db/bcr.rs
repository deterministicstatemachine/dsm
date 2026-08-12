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
use dsm::types::device_state::{
    DeviceState, OfflineAllocation, RelChainTip, RelationshipChainState, ValueCapability,
    VaultReserve,
};
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
// ‖ op(len+bytes) ‖ entropy(len+bytes) ‖ encap_flag+optional ‖ witness count
// + (policy_commit ‖ value u64 le) sorted). Sigs are appended outside the
// hashed prefix.
// ──────────────────────────────────────────────────────────────────────────

const REL_CHAIN_STATE_VERSION: u8 = 0x02;
// v0x02 (spec §0.5 gap 13): adds the canonical per-tip `value_capability` byte. This is a
// BREAKING bump with NO back-compat reader by design (no-legacy directive) — an older blob
// is rejected by `decode_device_state`; the device head is re-derived from the authoritative
// BCR chain-state archive / re-initialized. There is no default-false and no silent fallback.
// v0x03 adds the non-tip `extra_leaves` section (offline-bearer anchor-state + SoFi vault-state
// leaves) so a state with any such leaf round-trips: without it, restore replayed only tips and
// recomputed a mismatched root, bricking the wallet after one offline-bearer transfer.
// v0x05 adds the `vault_reserves` section — the extractable (amount, sequence) behind each
// vault-reserve leaf. Same reasoning as v0x04: the leaf HASH commits into the root and is
// already in `extra_leaves`, but the amount is not recoverable from it. Without this section a
// funded vault reloads with its reserves absent, recomputes a different root, and the wallet
// refuses to start — after the owner has already had value debited into the vault. Breaking
// bump with NO back-compat reader, per the no-legacy directive.
// v0x06 replaces the per-tip cached `RelationshipChainState` with the 32-byte `tip_entropy`.
// The cached state cost ~50 KB per relationship (its operation embeds a 49,856-byte SPHINCS+
// signature) while only two values were ever read back: `entropy`, and a chain-tip
// recomputation this codec already forced to equal the stored `chain_tip`. Heads therefore
// grew ~50 KB per counterparty, and the b0x envelope — which carries the head — overran the
// storage node's 128 KiB MAX_ENVELOPE_BYTES, deterministically 413-ing every transfer once a
// device had two relationships. `root()` is unaffected: the SMT leaf has always been
// `rel_key -> chain_tip`, never the state. Breaking bump with NO back-compat reader.
const DEVICE_STATE_VERSION: u8 = 0x06;

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
        // Canonical value-capability (R4): 1=Yes, 2=No, 3=Unknown. Always explicit.
        out.push(tip.value_capability.commit_tag());

        // v0x06: the tip's entropy, length-prefixed. Empty is legal and means a
        // digest-only tip (recovery-capsule restore) whose next advance falls
        // back to the SMT-root derivation.
        put_vec(&mut out, &tip.tip_entropy);
    }

    // v0x03: non-tip SMT leaves (offline-bearer anchor-state + SoFi vault-state), sorted by key
    // (BTreeMap iteration is already sorted). These commit into `root()` and MUST be persisted so
    // `restore` replays them; otherwise the recomputed root diverges from the stored one.
    let extra = head.extra_leaves_snapshot();
    put_len_u32(&mut out, extra.len());
    for (key, value) in extra {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }

    // v0x04: offline-cash allocations — the extractable (amount, sequence) behind each allocation leaf.
    // The leaf HASH is already in `extra_leaves` (commits into the root); this section carries the
    // amounts, which are not recoverable from the hash. BTreeMap iteration is sorted.
    let allocations = head.offline_allocations_snapshot();
    put_len_u32(&mut out, allocations.len());
    for (key, alloc) in allocations {
        out.extend_from_slice(key);
        out.extend_from_slice(&alloc.amount.to_le_bytes());
        out.extend_from_slice(&alloc.sequence.to_le_bytes());
    }

    // v0x05: vault reserves — the extractable (amount, sequence) behind each vault-reserve leaf.
    // Encumbered value: not in `balances`, not recoverable from the leaf hash.
    let reserves = head.vault_reserves_snapshot();
    put_len_u32(&mut out, reserves.len());
    for (key, reserve) in reserves {
        out.extend_from_slice(&key);
        out.extend_from_slice(&reserve.amount.to_le_bytes());
        out.extend_from_slice(&reserve.sequence.to_le_bytes());
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
        // Canonical value-capability (R4) — fail-closed: an absent/invalid byte (e.g. a
        // legacy v0x01 layout, which lacked it) is REJECTED, never read as `No`.
        let vc_byte = read_u8(&mut cursor).map_err(|e| anyhow!("tip value_capability: {e}"))?;
        let value_capability = ValueCapability::from_wire(vc_byte as i32)
            .ok_or_else(|| anyhow!("tip value_capability invalid byte: {vc_byte}"))?;
        let tip_entropy = read_vec(&mut cursor).map_err(|e| anyhow!("tip entropy: {e}"))?;
        tips_in_order.push((
            rk,
            RelChainTip {
                chain_tip,
                counterparty_devid: cp_devid,
                tip_entropy,
                value_capability,
            },
        ));
    }

    // v0x03: non-tip SMT leaves (offline-bearer anchor-state + SoFi vault-state).
    let extra_count = read_len_u32(&mut cursor).map_err(|e| anyhow!("extra_leaf count: {e}"))?;
    let mut extra_leaves: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    for _ in 0..extra_count {
        let key: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("extra_leaf key: {e}"))?;
        let value: [u8; 32] =
            take::<32>(&mut cursor).map_err(|e| anyhow!("extra_leaf value: {e}"))?;
        extra_leaves.insert(key, value);
    }

    // v0x04: offline-cash allocations — extractable (amount, sequence) behind each allocation leaf.
    let allocation_count =
        read_len_u32(&mut cursor).map_err(|e| anyhow!("allocation count: {e}"))?;
    let mut offline_allocations: BTreeMap<[u8; 32], OfflineAllocation> = BTreeMap::new();
    for _ in 0..allocation_count {
        let key: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("allocation key: {e}"))?;
        let amount_bytes: [u8; 8] =
            take::<8>(&mut cursor).map_err(|e| anyhow!("allocation amount: {e}"))?;
        let seq_bytes: [u8; 8] =
            take::<8>(&mut cursor).map_err(|e| anyhow!("allocation sequence: {e}"))?;
        offline_allocations.insert(
            key,
            OfflineAllocation {
                amount: u64::from_le_bytes(amount_bytes),
                sequence: u64::from_le_bytes(seq_bytes),
            },
        );
    }

    // v0x05: vault reserves — extractable (amount, sequence) behind each vault-reserve leaf.
    let reserve_count = read_len_u32(&mut cursor).map_err(|e| anyhow!("reserve count: {e}"))?;
    let mut vault_reserves: BTreeMap<[u8; 32], VaultReserve> = BTreeMap::new();
    for _ in 0..reserve_count {
        let key: [u8; 32] = take::<32>(&mut cursor).map_err(|e| anyhow!("reserve key: {e}"))?;
        let amount_bytes: [u8; 8] =
            take::<8>(&mut cursor).map_err(|e| anyhow!("reserve amount: {e}"))?;
        let seq_bytes: [u8; 8] =
            take::<8>(&mut cursor).map_err(|e| anyhow!("reserve sequence: {e}"))?;
        vault_reserves.insert(
            key,
            VaultReserve {
                amount: u64::from_le_bytes(amount_bytes),
                sequence: u64::from_le_bytes(seq_bytes),
            },
        );
    }

    // Replay tips + non-tip leaves into the SMT to rebuild the canonical root.
    let head = DeviceState::restore(
        genesis,
        devid,
        public_key,
        legacy_anchor,
        balances,
        tips_in_order,
        extra_leaves,
        offline_allocations,
        vault_reserves,
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
    let dropped = DroppedCounter::reset();
    let mut out = Vec::new();
    for row in iter {
        let (bytes, expected_tip) = row?;
        match decode_rel_chain_state(&bytes) {
            Ok((state, recomputed_tip)) => {
                if expected_tip.len() == 32 && recomputed_tip.as_slice() != expected_tip.as_slice()
                {
                    warn!("[client_db] bcr_chain_states tip mismatch (corruption?), skipping row");
                    dropped.set(dropped.get() + 1);
                    continue;
                }
                out.push(state);
            }
            Err(e) => {
                warn!("[client_db] Skipping invalid bcr_chain_states row: {e}");
                dropped.set(dropped.get() + 1);
            }
        }
    }

    Ok(out)
}

/// How many rows the last `get_bcr_chain_states` call on this thread dropped.
///
/// Skipping an unreadable row is right for display — one bad row should not
/// blank the history. It is wrong for anything that DERIVES AN AMOUNT from that
/// history: a dropped `Mint` silently lowers the total, and a supply cap
/// checked against a total that is too low permits a mint it should refuse.
/// That is a fail-open, so callers computing an authority figure must ask
/// whether the history they just read was complete and refuse to answer when it
/// was not. Thread-local because the read and the question are the same call
/// chain; the value is reset at the start of every load.
pub fn last_load_dropped_rows() -> u32 {
    DROPPED_ROWS.with(|d| d.get())
}

thread_local! {
    static DROPPED_ROWS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Handle over the per-thread dropped-row counter for one load.
struct DroppedCounter;

impl DroppedCounter {
    fn reset() -> Self {
        DROPPED_ROWS.with(|d| d.set(0));
        Self
    }

    fn get(&self) -> u32 {
        DROPPED_ROWS.with(|d| d.get())
    }

    fn set(&self, n: u32) {
        DROPPED_ROWS.with(|d| d.set(n));
    }
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

    // Recipient-credit transfer on device [0xA1] bound to policy_commit [0xD4],
    // consistent with the conservation guard (to_device_id == device => Credit).
    fn sample_operation(tag: &[u8], amount: u64) -> Operation {
        Operation::Transfer {
            policy_commit: [0xD4; 32],
            to_device_id: vec![0xA1; 32],
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
            authority_policy: None,
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
                None,
                None,
                None,
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
                    tip_entropy: rel.entropy.clone(),
                    value_capability: ValueCapability::Unknown,
                },
            )],
            outcome.new_device_state.extra_leaves_snapshot().clone(),
            outcome
                .new_device_state
                .offline_allocations_snapshot()
                .clone(),
            outcome.new_device_state.vault_reserves_snapshot().clone(),
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
                    tip_entropy: Vec::new(),
                    value_capability: ValueCapability::Unknown,
                },
            )],
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
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
        // The tip retains the entropy the next advance consumes -- and ONLY that.
        assert_eq!(
            decoded.tip_entropy(&rel_key),
            Some(rel.entropy.as_slice()),
            "tip entropy must round-trip: it is the sole input the next advance reads"
        );
        // Canonical value_capability round-trips (the sample tip is Unknown).
        assert_eq!(
            decoded.rel_chain_tip(&rel_key).map(|t| t.value_capability),
            head.rel_chain_tip(&rel_key).map(|t| t.value_capability)
        );
    }

    /// Regression for the reload-brick bug: an offline-bearer transfer adds a non-tip anchor-state
    /// leaf to the device SMT. Before v0x03, that leaf committed into the STORED root but was never
    /// persisted/replayed, so decode recomputed a different root → `root mismatch` → the wallet
    /// failed to load after one such transfer. Assert the leaf now round-trips and the root matches.
    #[test]
    fn device_head_codec_roundtrip_preserves_anchor_state_leaf() {
        let (_, _, _, _, head0) = sample_device_and_rel();
        let key = [0x11u8; 32];
        let value = [0x22u8; 32];
        let head = head0
            .with_anchor_state_leaf(&key, &value)
            .expect("add anchor-state leaf");
        assert_ne!(
            head.root(),
            head0.root(),
            "the anchor-state leaf must change the device root"
        );

        let bytes = encode_device_state(&head);
        let (decoded, stored_root) =
            decode_device_state(&bytes).expect("decode device head with anchor-state leaf");

        // The load-time sanity check (encoded root == recomputed root) is exactly what bricked
        // before the fix; it must now pass.
        assert_eq!(stored_root, head.root());
        assert_eq!(
            decoded.root(),
            head.root(),
            "reloaded root must equal the stored root (the reload-brick regression)"
        );
        assert_eq!(decoded.extra_leaves_snapshot().get(&key), Some(&value));
    }

    /// The offline-cash allocation amount is not recoverable from the leaf hash, so v0x04 persists it
    /// A FUNDED VAULT MUST SURVIVE A RESTART.
    ///
    /// The reserve LEAF hash commits into the root and rides along in
    /// `extra_leaves`, but the amount behind it does not — the hash is not
    /// reversible. Without the v0x05 section a funded vault reloads with its
    /// reserves absent, recomputes a different root, and the wallet refuses to
    /// start, after the owner has already had value debited into the vault.
    #[test]
    fn device_head_codec_roundtrip_preserves_vault_reserves() {
        let (_, _, _, _, head0) = sample_device_and_rel();
        let token = [0xD4u8; 32]; // funded with 7 by sample_device_and_rel
        let vault = [0x5Eu8; 32];

        let head = head0
            .fund_vault_reserves(&vault, &[(token, 5)], 0)
            .expect("encumber 5 into the vault")
            .new_device_state;
        assert_ne!(head.root(), head0.root(), "funding must advance the root");

        let bytes = encode_device_state(&head);
        let (decoded, stored_root) =
            decode_device_state(&bytes).expect("decode device head with vault reserves");

        assert_eq!(stored_root, head.root());
        assert_eq!(
            decoded.root(),
            head.root(),
            "reloaded root must equal the stored root (reserve leaf replayed)"
        );
        assert_eq!(
            decoded.vault_reserve(&vault, &token),
            5,
            "the encumbered amount must survive reload"
        );
        assert_eq!(
            decoded
                .vault_reserve_entry(&vault, &token)
                .map(|r| r.sequence),
            Some(0),
            "and so must the vault sequence it was written at"
        );
        // The spendable side was debited by the funding (7 -> 2) and stays so.
        assert_eq!(decoded.balance(&token), 2);
    }

    /// Several vaults and several assets all round-trip independently.
    #[test]
    fn device_head_codec_roundtrip_preserves_many_reserves() {
        let (_, _, _, _, head0) = sample_device_and_rel();
        let token = [0xD4u8; 32];
        let (v1, v2) = ([0x11u8; 32], [0x22u8; 32]);

        let head = head0
            .fund_vault_reserves(&v1, &[(token, 3)], 0)
            .expect("v1")
            .new_device_state
            .fund_vault_reserves(&v2, &[(token, 2)], 0)
            .expect("v2")
            .new_device_state;

        let bytes = encode_device_state(&head);
        let (decoded, _) = decode_device_state(&bytes).expect("decode");
        assert_eq!(decoded.vault_reserve(&v1, &token), 3);
        assert_eq!(decoded.vault_reserve(&v2, &token), 2);
        assert_eq!(decoded.root(), head.root());
    }

    /// A v0x04 blob is REJECTED, never read with reserves defaulted to absent.
    ///
    /// Defaulting would silently drop encumbered value: the root would not
    /// match, and a reader that shrugged at that would be reconstructing a
    /// state in which the owner's vault liquidity had ceased to exist.
    #[test]
    fn a_pre_reserve_device_head_blob_is_rejected() {
        let (_, _, _, _, head) = sample_device_and_rel();
        let mut bytes = encode_device_state(&head);
        assert_eq!(bytes[0], 0x06, "current device-head version");

        bytes[0] = 0x05;
        let err = decode_device_state(&bytes)
            .expect_err("an older device-head version must not be readable");
        let msg = format!("{err}");
        assert!(
            msg.contains("version") || msg.contains("0x04") || msg.contains('4'),
            "the refusal should name the version, got: {msg}"
        );
    }

    /// separately. Assert a loaded allocation survives an encode/decode and the root still matches.
    #[test]
    fn device_head_codec_roundtrip_preserves_offline_allocation() {
        let (_, _, _, _, head0) = sample_device_and_rel();
        let token = [0xD4u8; 32]; // funded with 7 by sample_device_and_rel
        let bundle = [0x7Bu8; 32];
        let head = head0
            .load_offline_cash(&bundle, &token, 3)
            .expect("load 3 offline")
            .new_device_state;
        assert_ne!(
            head.root(),
            head0.root(),
            "load must advance the device root"
        );

        let bytes = encode_device_state(&head);
        let (decoded, stored_root) =
            decode_device_state(&bytes).expect("decode device head with offline allocation");
        assert_eq!(stored_root, head.root());
        assert_eq!(
            decoded.root(),
            head.root(),
            "reloaded root must equal the stored root (allocation leaf replayed)"
        );

        let key = dsm::types::offline_allocation_leaf::offline_allocation_key(
            &head.genesis_digest(),
            &head.devid(),
            &bundle,
            &token,
        );
        assert_eq!(
            decoded.offline_allocation(&key),
            3,
            "allocation amount must survive reload"
        );
        // And the online balance was debited by the load (7 -> 4).
        assert_eq!(decoded.balances_snapshot().get(&token), Some(&4));
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
        assert!(
            decoded_tip.tip_entropy.is_empty(),
            "a digest-only tip carries no entropy and must decode as such"
        );
        assert_eq!(decoded_tip.value_capability, original_tip.value_capability);
    }

    #[test]
    fn device_head_codec_rejects_invalid_value_capability_byte() {
        // An entropy-less tip serializes as [..value_capability, entropy_len:u32],
        // followed by one u32 count per trailing section — v0x03 extra_leaves, v0x04
        // offline-allocations, v0x05 vault-reserves — all empty here. Derived from those
        // counts rather than hardcoded, so adding the next section is a one-line change
        // instead of a puzzling off-by-four in an unrelated test.
        const TRAILING_COUNT_SECTIONS: usize = 3;
        const TRAILING: usize = TRAILING_COUNT_SECTIONS * 4;
        // v0x06: the tip tail is value_capability(1) + entropy length prefix(4).
        const TIP_TAIL: usize = 1 + 4;

        let (_, _rel_key, head) = head_with_state_less_tip();
        let bytes = encode_device_state(&head);
        let n = bytes.len();
        let vc = n - TRAILING - TIP_TAIL; // value_capability
        assert!(
            bytes[n - TRAILING..].iter().all(|b| *b == 0),
            "every trailing section count should be 0"
        );
        assert!(
            bytes[vc + 1..vc + 1 + 4].iter().all(|b| *b == 0),
            "entropy length should be 0 for an entropy-less tip"
        );
        assert_eq!(bytes[vc], 3, "value_capability should be Unknown(3)");

        // Corrupt to UNSPECIFIED(0): decode MUST reject — never silently read as `No`.
        let mut zeroed = bytes.clone();
        zeroed[vc] = 0;
        assert!(
            decode_device_state(&zeroed).is_err(),
            "UNSPECIFIED value_capability must be rejected, never read as No"
        );
        // Out-of-range value is also rejected.
        let mut oob = bytes;
        oob[vc] = 9;
        assert!(decode_device_state(&oob).is_err());
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
                    amount: 9,
                }],
                None,
                None,
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
                    amount: 11,
                }],
                None,
                None,
                None,
                None,
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
