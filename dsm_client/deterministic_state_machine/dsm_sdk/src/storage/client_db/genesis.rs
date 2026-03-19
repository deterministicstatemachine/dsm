// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genesis record persistence and verification.

use anyhow::Result;
use log::warn;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::GenesisRecord;
use crate::storage::codecs::{
    encode_genesis_record_bytes, generate_hash_chain_proof_bytes, smt_proof_bytes,
};
use crate::util::deterministic_time::tick;

pub fn store_genesis_record_with_verification(record: &GenesisRecord) -> Result<()> {
    let enc = encode_genesis_record_bytes(record);
    let proof_bytes = generate_hash_chain_proof_bytes(&enc);
    let smt_bytes = smt_proof_bytes(record.merkle_root.as_bytes(), &enc);
    let ts = tick();

    let storage_nodes_text = record.storage_nodes.join(",");

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "INSERT OR REPLACE INTO genesis_records(
             genesis_id,device_id,mpc_proof,dbrw_binding,merkle_root,
             participant_count,chain_tip,publication_hash,storage_nodes,
             entropy_hash,protocol_version,hash_chain_proof,smt_proof,
             verification_step,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            record.genesis_id,
            record.device_id,
            record.mpc_proof,
            record.dbrw_binding,
            record.merkle_root,
            record.participant_count as i32,
            record.progress_marker,
            record.publication_hash,
            storage_nodes_text,
            record.entropy_hash,
            record.protocol_version,
            &proof_bytes as &[u8],
            &smt_bytes as &[u8],
            ts as i64,
            ts as i64,
        ],
    )?;
    Ok(())
}

pub fn get_verified_genesis_record() -> Result<Option<GenesisRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_verified_genesis_record, recovering");
        poisoned.into_inner()
    });

    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        i32,
        String,
        String,
        String,
        String,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    )> = conn
        .query_row(
            "SELECT genesis_id,device_id,mpc_proof,dbrw_binding,merkle_root,
                    participant_count,chain_tip,publication_hash,storage_nodes,
                    entropy_hash,protocol_version,hash_chain_proof,smt_proof,
                    verification_step
               FROM genesis_records
           ORDER BY created_at DESC
              LIMIT 1",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                ))
            },
        )
        .optional()?;

    if let Some((
        id,
        dev,
        mpc,
        bind,
        root,
        parts,
        ts,
        pub_hash,
        nodes_csv,
        ent_hash,
        proto,
        hash_proof,
        smt_proof,
        v_ts,
    )) = row
    {
        let storage_nodes: Vec<String> = if nodes_csv.is_empty() {
            Vec::new()
        } else {
            nodes_csv.split(",").map(|s| s.trim().to_string()).collect()
        };

        let rec = GenesisRecord {
            genesis_id: id.clone(),
            device_id: dev,
            mpc_proof: mpc,
            dbrw_binding: bind,
            merkle_root: root.clone(),
            participant_count: parts as u32,
            progress_marker: ts,
            publication_hash: pub_hash,
            storage_nodes,
            entropy_hash: ent_hash,
            protocol_version: proto,
            hash_chain_proof: hash_proof.clone(),
            smt_proof,
            verification_step: v_ts.map(|v| v as u64),
        };

        if let Some(proof) = hash_proof {
            let enc = encode_genesis_record_bytes(&rec);
            let recomputed = generate_hash_chain_proof_bytes(&enc);
            if proof.as_slice() != recomputed.as_slice() {
                warn!("Genesis hash-chain proof FAILED");
            }
        }
        return Ok(Some(rec));
    }
    Ok(None)
}
