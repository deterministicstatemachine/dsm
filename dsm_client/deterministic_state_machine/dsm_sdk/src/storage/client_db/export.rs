// SPDX-License-Identifier: MIT OR Apache-2.0
//! State export / import (binary backup) and state info query.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use log::warn;

use dsm::types::serialization::{put_bytes, put_str, put_u32, put_u64, put_u8};
use super::contacts::{get_all_contacts, store_contact};
use super::genesis::get_verified_genesis_record;
use super::tokens::get_balance_projection;
use super::transactions::{get_transaction_history, store_transaction};
use super::wallet_state::{ensure_wallet_state_for_device, get_wallet_state};
use super::types::{ContactRecord, TransactionRecord};
use crate::generated;
use crate::sdk::app_state::AppState;
use crate::storage::codecs::{read_len_u32, read_string, read_u64, read_u8, read_vec};

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
        put_str(&mut g, &gen.dbrw_binding);
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

/// Import a previously exported blob. Partial application allowed.
pub fn import_state_blob(blob: &[u8]) -> Result<(bool, String)> {
    let mut r = blob;
    if r.len() < BACKUP_MAGIC.len() + 1 {
        return Ok((false, "blob_too_small".into()));
    }
    if &r[..BACKUP_MAGIC.len()] != BACKUP_MAGIC {
        return Ok((false, "bad_magic".into()));
    }
    r = &r[BACKUP_MAGIC.len()..];
    let _version = read_u8(&mut r).map_err(|e| anyhow!("version: {e}"))?;

    let mut applied_any = false;
    // genesis
    let genesis_present = read_u8(&mut r).map_err(|e| anyhow!("gen_present: {e}"))? == 1;
    if genesis_present {
        let _g_bytes = read_vec(&mut r).map_err(|e| anyhow!("gen_bytes: {e}"))?;
        // For now we do not re-import genesis (immutable). Just acknowledge.
        applied_any = true; // treat as recognized
    }

    // wallet
    let wallet_present = read_u8(&mut r).map_err(|e| anyhow!("wallet_present: {e}"))? == 1;
    if wallet_present {
        let w_bytes = read_vec(&mut r).map_err(|e| anyhow!("wallet_bytes: {e}"))?;
        let mut wr = &w_bytes[..];
        let _wallet_id = read_string(&mut wr).unwrap_or_default();
        let _device_id = read_string(&mut wr).unwrap_or_default();
        let _genesis_id = read_string(&mut wr).unwrap_or_default();
        let _chain_tip = read_string(&mut wr).unwrap_or_default();
        let _merkle_root = read_string(&mut wr).unwrap_or_default();
        let imported_balance = read_u64(&mut wr).unwrap_or(0);
        let _chain_height = read_u64(&mut wr).unwrap_or(0);
        if let Some(gen) = get_verified_genesis_record()? {
            let dev_id = gen.device_id;
            let had_wallet = get_wallet_state(&dev_id)?.is_some();
            ensure_wallet_state_for_device(&dev_id)?;
            if imported_balance != 0 {
                warn!(
                    "Ignoring imported wallet balance={} for device={}; balance rebuild must come from canonical state/projection sync",
                    imported_balance,
                    dev_id
                );
            }
            applied_any = applied_any || had_wallet || imported_balance != 0;
        }
    } else {
        // Ensure a wallet metadata row for the genesis device (if any).
        if let Some(gen) = get_verified_genesis_record()? {
            let _ = ensure_wallet_state_for_device(&gen.device_id);
        }
    }

    // contacts (bytes-only, no hex string support)
    let contacts_count = read_len_u32(&mut r).map_err(|e| anyhow!("contacts_count: {e}"))?;
    for _ in 0..contacts_count {
        let contact_id = read_string(&mut r).unwrap_or_default();
        let device_id_bytes = read_vec(&mut r).unwrap_or_default();
        let alias = read_string(&mut r).unwrap_or_default();
        let genesis_hash_bytes = read_vec(&mut r).unwrap_or_default();
        let chain_tip_bytes = read_vec(&mut r).unwrap_or_default();
        let added_at = read_u64(&mut r).unwrap_or(0);
        let verified = read_u8(&mut r).unwrap_or(0) == 1;

        // Validate byte arrays are correct size (32 bytes for device_id and genesis_hash)
        if device_id_bytes.len() != 32 || genesis_hash_bytes.len() != 32 {
            warn!(
                "Skipping contact with invalid byte array sizes: device_id={}, genesis_hash={}",
                device_id_bytes.len(),
                genesis_hash_bytes.len()
            );
            continue;
        }

        // Skip if exists (device_id uniqueness enforced)
        let existing: Vec<ContactRecord> = get_all_contacts()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.device_id == device_id_bytes)
            .collect();

        if existing.is_empty() {
            let rec = ContactRecord {
                contact_id: if contact_id.is_empty() {
                    let h = crate::util::domain_helpers::device_id_hash_bytes(&device_id_bytes);
                    // Use first 8 bytes of hash as numeric contact_id
                    let num = u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8]));
                    format!("c_{}", num)
                } else {
                    contact_id
                },
                device_id: device_id_bytes,
                alias: if alias.is_empty() {
                    "contact".into()
                } else {
                    alias
                },
                genesis_hash: genesis_hash_bytes,
                current_chain_tip: if chain_tip_bytes.is_empty() {
                    None
                } else if chain_tip_bytes.len() == 32 {
                    Some(chain_tip_bytes)
                } else {
                    warn!("Invalid chain_tip size: {}", chain_tip_bytes.len());
                    None
                },
                added_at,
                verified,
                verification_proof: None,
                metadata: HashMap::new(),
                ble_address: None,
                status: "Created".to_string(),
                needs_online_reconcile: false,
                last_seen_online_counter: 0,
                last_seen_ble_counter: 0,
                public_key: Vec::new(), // Will be populated during BLE prepare exchange
                previous_chain_tip: None,
            };
            let _ = store_contact(&rec);
            applied_any = true;
        }
    }

    // transactions
    let tx_count = read_len_u32(&mut r).map_err(|e| anyhow!("tx_count: {e}"))?;
    for _ in 0..tx_count {
        let tx_id = read_string(&mut r).unwrap_or_default();
        let tx_hash = read_string(&mut r).unwrap_or_default();
        let from_dev = read_string(&mut r).unwrap_or_default();
        let to_dev = read_string(&mut r).unwrap_or_default();
        let amount = read_u64(&mut r).unwrap_or(0);
        let tx_type = read_string(&mut r).unwrap_or_default();
        let status = read_string(&mut r).unwrap_or_default();
        let chain_height = read_u64(&mut r).unwrap_or(0);
        let step_index = read_u64(&mut r).unwrap_or(0);
        if !tx_id.is_empty() {
            let rec = TransactionRecord {
                tx_id,
                tx_hash,
                from_device: from_dev,
                to_device: to_dev,
                amount,
                tx_type,
                status,
                chain_height,
                step_index,
                commitment_hash: None,
                proof_data: None,
                metadata: HashMap::new(),
                created_at: 0,
            };
            let _ = store_transaction(&rec);
            applied_any = true;
        }
    }

    // preferences
    let prefs_count = read_len_u32(&mut r).map_err(|e| anyhow!("prefs_count: {e}"))?;
    for _ in 0..prefs_count {
        let key = read_string(&mut r).unwrap_or_default();
        let val_bytes = read_vec(&mut r).unwrap_or_default();
        let val = String::from_utf8(val_bytes).unwrap_or_default();
        if !key.is_empty() {
            let _ = AppState::handle_app_state_request(&key, "set", &val);
            applied_any = true;
        }
    }

    Ok((
        applied_any,
        if applied_any {
            "ok".into()
        } else {
            "no_changes".into()
        },
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::{
        get_balance_projection, initialize_wallet_from_verified_genesis,
        reset_database_for_tests, store_genesis_record_with_verification, GenesisRecord,
    };
    use serial_test::serial;

    #[test]
    #[serial]
    fn import_wallet_backup_does_not_seed_unverifiable_balance_projection() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");

        let gen = GenesisRecord {
            genesis_id: "gid-import".into(),
            device_id: "did-import".into(),
            mpc_proof: "mpc".into(),
            dbrw_binding: "bind".into(),
            merkle_root: "root".into(),
            participant_count: 2,
            progress_marker: "P".into(),
            publication_hash: "pub".into(),
            storage_nodes: vec!["n1".into()],
            entropy_hash: "ent".into(),
            protocol_version: "1.0".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
        };
        store_genesis_record_with_verification(&gen).expect("store genesis");
        initialize_wallet_from_verified_genesis(&gen).expect("init wallet");

        let mut blob = Vec::new();
        blob.extend_from_slice(BACKUP_MAGIC);
        put_u8(&mut blob, 1);
        put_u8(&mut blob, 0);
        put_u8(&mut blob, 1);

        let mut wallet = Vec::new();
        put_str(&mut wallet, "wallet_did-import");
        put_str(&mut wallet, &gen.device_id);
        put_str(&mut wallet, &gen.genesis_id);
        put_str(&mut wallet, "tip");
        put_str(&mut wallet, "root");
        put_u64(&mut wallet, 777);
        put_u64(&mut wallet, 9);
        put_bytes(&mut blob, &wallet);
        put_u32(&mut blob, 0);
        put_u32(&mut blob, 0);
        put_u32(&mut blob, 0);

        let (applied, status) = import_state_blob(&blob).expect("import blob");
        assert!(applied, "wallet metadata import should be recognized");
        assert_eq!(status, "ok");
        assert!(
            get_balance_projection(&gen.device_id, "ERA")
                .expect("read ERA projection")
                .is_none(),
            "wallet backup must not seed an unverifiable balance projection"
        );
        assert_eq!(
            get_wallet_state(&gen.device_id)
                .expect("read wallet state")
                .expect("wallet row")
                .balance,
            0,
            "wallet_state balance must remain metadata-only after import"
        );
    }
}
