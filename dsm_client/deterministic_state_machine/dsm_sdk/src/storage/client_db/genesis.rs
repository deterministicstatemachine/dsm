// SPDX-License-Identifier: MIT OR Apache-2.0
//! Genesis record persistence and verification.

use anyhow::Result;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use super::types::GenesisRecord;
use crate::storage::codecs::{
    encode_genesis_record_bytes, generate_hash_chain_proof_bytes, smt_proof_bytes,
};

pub fn store_genesis_record_with_verification(record: &GenesisRecord) -> Result<()> {
    let enc = encode_genesis_record_bytes(record);
    let proof_bytes = generate_hash_chain_proof_bytes(&enc);
    let smt_bytes = smt_proof_bytes(record.merkle_root.as_bytes(), &enc);

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    conn.execute(
        "INSERT OR REPLACE INTO genesis_records(
             genesis_id,device_id,device_birth_binding,merkle_root,
             chain_tip,publication_hash,
             entropy_hash,protocol_version,hash_chain_proof,smt_proof,
             verification_step,genesis_nonce,genesis_profile,network_id)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            record.genesis_id,
            record.device_id,
            record.device_birth_binding,
            record.merkle_root,
            record.progress_marker,
            record.publication_hash,
            record.entropy_hash,
            record.protocol_version,
            &proof_bytes as &[u8],
            &smt_bytes as &[u8],
            record.verification_step.map(|v| v as i64),
            record.genesis_nonce,
            record.genesis_profile,
            record.network_id,
        ],
    )?;
    Ok(())
}

/// Read the genesis record for one exact genesis id — the identity the
/// caller actually holds — rather than "the latest row". Devices sharing a
/// process (tests, multi-profile) each keep their own row; picking by
/// recency would hand one identity another's derivation inputs.
pub fn get_genesis_record_by_id(genesis_id_b32: &str) -> Result<Option<GenesisRecord>> {
    get_verified_genesis_record_where("WHERE genesis_id = ?1", rusqlite::params![genesis_id_b32])
}

pub fn get_verified_genesis_record() -> Result<Option<GenesisRecord>> {
    get_verified_genesis_record_where("", rusqlite::params![])
}

fn get_verified_genesis_record_where(
    filter: &str,
    filter_params: &[&dyn rusqlite::ToSql],
) -> Result<Option<GenesisRecord>> {
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
        String,
        String,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        String,
        String,
        String,
    )> = conn
        .query_row(
            &format!(
                "SELECT genesis_id,device_id,device_birth_binding,merkle_root,
                        chain_tip,publication_hash,
                        entropy_hash,protocol_version,hash_chain_proof,smt_proof,
                        verification_step,genesis_nonce,genesis_profile,network_id
                   FROM genesis_records
                 {filter}
               ORDER BY rowid DESC
                  LIMIT 1"
            ),
            filter_params,
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
        bind,
        root,
        ts,
        pub_hash,
        ent_hash,
        proto,
        hash_proof,
        smt_proof,
        v_ts,
        genesis_nonce,
        genesis_profile,
        network_id,
    )) = row
    {
        let rec = GenesisRecord {
            genesis_id: id.clone(),
            device_id: dev,
            device_birth_binding: bind,
            merkle_root: root.clone(),
            progress_marker: ts,
            publication_hash: pub_hash,
            entropy_hash: ent_hash,
            protocol_version: proto,
            hash_chain_proof: hash_proof.clone(),
            smt_proof,
            verification_step: v_ts.map(|v| v as u64),
            genesis_nonce,
            genesis_profile,
            network_id,
        };

        if let Some(proof) = hash_proof {
            let enc = encode_genesis_record_bytes(&rec);
            let recomputed = generate_hash_chain_proof_bytes(&enc);
            if proof.as_slice() != recomputed.as_slice() {
                return Err(anyhow::anyhow!(
                    "genesis record {id}: its stored hash-chain proof does not recompute"
                ));
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
        crate::economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn sample_genesis() -> GenesisRecord {
        GenesisRecord {
            genesis_id: "gen-test-001".into(),
            device_id: "dev-test-001".into(),
            device_birth_binding: "binding-data".into(),
            merkle_root: "merkle-root-hash".into(),
            progress_marker: "PM".into(),
            publication_hash: "pub-hash".into(),
            entropy_hash: "entropy".into(),
            protocol_version: "2.0.0".into(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
            genesis_nonce: String::new(),
            genesis_profile: String::new(),
            network_id: "dsm-test".into(),
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
        assert_eq!(loaded.protocol_version, "2.0.0");
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
