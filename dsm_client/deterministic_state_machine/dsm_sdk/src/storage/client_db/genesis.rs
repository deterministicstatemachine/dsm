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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn sample_genesis() -> GenesisRecord {
        GenesisRecord {
            genesis_id: "gen-test-001".into(),
            device_id: "dev-test-001".into(),
            mpc_proof: "mpc-proof-data".into(),
            dbrw_binding: "binding-data".into(),
            merkle_root: "merkle-root-hash".into(),
            participant_count: 5,
            progress_marker: "PM".into(),
            publication_hash: "pub-hash".into(),
            storage_nodes: vec!["node-a".into(), "node-b".into(), "node-c".into()],
            entropy_hash: "entropy".into(),
            protocol_version: "2.0.0".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
        }
    }

    #[test]
    fn encode_genesis_record_bytes_is_deterministic() {
        let rec = sample_genesis();
        let enc1 = encode_genesis_record_bytes(&rec);
        let enc2 = encode_genesis_record_bytes(&rec);
        assert_eq!(enc1, enc2);
        assert!(!enc1.is_empty());
    }

    #[test]
    fn hash_chain_proof_matches_recomputed() {
        let rec = sample_genesis();
        let enc = encode_genesis_record_bytes(&rec);
        let proof = generate_hash_chain_proof_bytes(&enc);
        let recomputed = generate_hash_chain_proof_bytes(&enc);
        assert_eq!(proof, recomputed);
        assert_ne!(proof, [0u8; 32]);
    }

    #[test]
    fn smt_proof_uses_both_root_and_data() {
        let rec = sample_genesis();
        let enc = encode_genesis_record_bytes(&rec);
        let proof1 = smt_proof_bytes(rec.merkle_root.as_bytes(), &enc);
        let proof2 = smt_proof_bytes(b"different-root", &enc);
        assert_ne!(proof1, proof2);
    }

    #[test]
    #[serial]
    fn store_and_retrieve_genesis_record() {
        init_test_db();

        let rec = sample_genesis();
        store_genesis_record_with_verification(&rec).expect("store genesis");

        let loaded = get_verified_genesis_record()
            .expect("query")
            .expect("genesis record exists");
        assert_eq!(loaded.genesis_id, "gen-test-001");
        assert_eq!(loaded.device_id, "dev-test-001");
        assert_eq!(loaded.participant_count, 5);
        assert_eq!(loaded.protocol_version, "2.0.0");
        assert_eq!(loaded.storage_nodes, vec!["node-a", "node-b", "node-c"]);
        assert!(loaded.hash_chain_proof.is_some());
        assert!(loaded.smt_proof.is_some());
    }

    #[test]
    #[serial]
    fn stored_genesis_hash_chain_proof_verifies() {
        init_test_db();

        let rec = sample_genesis();
        store_genesis_record_with_verification(&rec).expect("store genesis");

        let loaded = get_verified_genesis_record()
            .expect("query")
            .expect("genesis record exists");

        let enc = encode_genesis_record_bytes(&loaded);
        let recomputed = generate_hash_chain_proof_bytes(&enc);
        assert_eq!(
            loaded.hash_chain_proof.as_deref(),
            Some(recomputed.as_slice())
        );
    }
}
