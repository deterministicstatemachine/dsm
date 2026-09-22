// SPDX-License-Identifier: MIT OR Apache-2.0
//! State export / import (binary backup) and state info query.

use std::collections::HashMap;

use anyhow::Result;

use dsm::types::serialization::{put_bytes, put_str, put_u32, put_u64, put_u8};
use super::contacts::get_all_contacts;
use super::genesis::get_verified_genesis_record;
use super::tokens::get_balance_projection;
use super::transactions::get_transaction_history;
use super::wallet_state::get_wallet_state;
use crate::generated;
use crate::sdk::app_state::AppState;

const BACKUP_MAGIC: &[u8] = b"DSMBKP\0";

/// Export a deterministic binary snapshot of local state for backup.
/// Layout (little-endian):
/// [backup magic bytes "DSMBKP\0"]
/// [u8 version=1]
/// [genesis_present u8]
///   if 1 => `[len genesis_bytes u32][genesis_bytes]`
/// [wallet_present u8]
///   if 1 => wallet record fields as: `[wallet_id][device_id][genesis_id?][chain_tip][merkle_root][balance u64][chain_height u64]`
/// [contacts_count u32] then for each:
///   `[contact_id][device_id][alias][genesis_hash][chain_tip?][added_at u64][verified u8]`
/// [tx_count u32] then for each:
///   `[tx_id][tx_hash][from_device][to_device][amount u64][tx_type][status][chain_height u64][step_index u64]`
/// [prefs_count u32] then for each: `[key][value]`
pub fn export_state_blob() -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4096);
    // magic & version
    out.extend_from_slice(BACKUP_MAGIC);
    put_u8(&mut out, 1);

    // genesis
    if let Some(gen) = get_verified_genesis_record()? {
        put_u8(&mut out, 1);
        let mut g = Vec::new();
        put_str(&mut g, &gen.genesis_id);
        put_str(&mut g, &gen.device_id);
        put_str(&mut g, &gen.mpc_proof);
        put_str(&mut g, &gen.device_birth_binding);
        put_str(&mut g, &gen.merkle_root);
        put_u32(&mut g, gen.participant_count);
        put_str(&mut g, &gen.progress_marker);
        put_str(&mut g, &gen.publication_hash);
        put_str(&mut g, &gen.storage_nodes.join(","));
        put_str(&mut g, &gen.entropy_hash);
        put_str(&mut g, &gen.protocol_version);
        put_bytes(&mut g, gen.hash_chain_proof.as_deref().unwrap_or(&[]));
        put_bytes(&mut g, gen.smt_proof.as_deref().unwrap_or(&[]));
        put_u64(&mut g, gen.verification_step.unwrap_or(0));
        put_bytes(&mut out, &g);
    } else {
        put_u8(&mut out, 0);
    }

    // wallet (derive via genesis device_id if present)
    if let Some(gen) = get_verified_genesis_record()? {
        if let Some(ws) = get_wallet_state(&gen.device_id)? {
            let era_projection = get_balance_projection(&gen.device_id, "ERA")?;
            put_u8(&mut out, 1);
            let mut w = Vec::new();
            put_str(&mut w, &ws.wallet_id);
            put_str(&mut w, &ws.device_id);
            put_str(&mut w, &ws.genesis_id.unwrap_or_default());
            put_str(&mut w, &ws.chain_tip);
            put_str(&mut w, &ws.merkle_root);
            put_u64(&mut w, era_projection.map(|r| r.available).unwrap_or(0));
            put_u64(&mut w, ws.chain_height);
            put_bytes(&mut out, &w);
        } else {
            put_u8(&mut out, 0);
        }
    } else {
        put_u8(&mut out, 0);
    }

    // contacts (bytes-only export)
    let contacts = get_all_contacts().unwrap_or_default();
    put_u32(&mut out, contacts.len() as u32);
    for c in contacts {
        put_str(&mut out, &c.contact_id);
        put_bytes(&mut out, &c.device_id); // Raw bytes, not string
        put_str(&mut out, &c.alias);
        put_bytes(&mut out, &c.genesis_hash); // Raw bytes, not string
        put_bytes(&mut out, c.current_chain_tip.as_deref().unwrap_or(&[])); // Raw bytes
        put_u64(&mut out, c.added_at);
        put_u8(&mut out, if c.verified { 1 } else { 0 });
    }

    // transactions (limit 500 for export determinism)
    let txs = get_transaction_history(None, Some(500)).unwrap_or_default();
    put_u32(&mut out, txs.len() as u32);
    for t in txs {
        put_str(&mut out, &t.tx_id);
        put_str(&mut out, &t.tx_hash);
        put_str(&mut out, &t.from_device);
        put_str(&mut out, &t.to_device);
        put_u64(&mut out, t.amount);
        put_str(&mut out, &t.tx_type);
        put_str(&mut out, &t.status);
        put_u64(&mut out, t.chain_height);
        put_u64(&mut out, t.step_index);
    }

    // preferences (string K/V only via AppState handler)
    let mut prefs_map: HashMap<String, Vec<u8>> = HashMap::new();
    for k in [
        "has_identity",
        "sdk_initialized",
        // optional extras (harmless if missing)
        "theme",
        "default_token",
        "qr_sound",
        "notifications_enabled",
    ] {
        let v = AppState::handle_app_state_request(k, "get", "");
        prefs_map.insert(k.to_string(), v.into_bytes());
    }
    put_u32(&mut out, prefs_map.len() as u32);
    for (k, v) in prefs_map {
        put_str(&mut out, &k);
        put_bytes(&mut out, &v);
    }

    Ok(out)
}

/// Produce a structured state summary for state.info QueryOp
pub fn export_state_info() -> Result<generated::StateInfoResponse> {
    let (has_genesis, has_wallet) = if let Some(gen) = get_verified_genesis_record()? {
        let wallet = get_wallet_state(&gen.device_id)?.is_some();
        (true, wallet)
    } else {
        (false, false)
    };
    let contacts = get_all_contacts().unwrap_or_default().len();
    let txs = get_transaction_history(None, Some(500))
        .unwrap_or_default()
        .len();
    let mut prefs_non_empty = 0usize;
    for k in [
        "has_identity",
        "sdk_initialized",
        "theme",
        "default_token",
        "qr_sound",
        "notifications_enabled",
    ] {
        let v = AppState::handle_app_state_request(k, "get", "");
        if !v.is_empty() {
            prefs_non_empty += 1;
        }
    }
    Ok(generated::StateInfoResponse {
        has_genesis,
        has_wallet,
        contacts_count: contacts as u64,
        transactions_count: txs as u64,
        preferences_count: prefs_non_empty as u64,
    })
}
