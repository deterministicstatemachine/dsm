// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet metadata initialization from verified genesis and wallet verification.

use std::collections::HashMap;

use anyhow::Result;
use log::{info, warn};
use rusqlite::{
    params,
    types::{Type, ValueRef},
    OptionalExtension,
};

use super::get_connection;
use super::types::{GenesisRecord, VerificationResult, WalletState};
use crate::storage::codecs::{generate_hash_chain_proof_bytes, meta_to_blob, smt_proof_bytes};
use crate::util::deterministic_time::tick;

fn read_hashish_column_as_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    label: &str,
) -> rusqlite::Result<String> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(String::new()),
        ValueRef::Text(text) => String::from_utf8(text.to_vec())
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(e))),
        ValueRef::Blob(bytes) => {
            if bytes.is_empty() {
                Ok(String::new())
            } else {
                Ok(crate::util::text_id::encode_base32_crockford(bytes))
            }
        }
        value => Err(rusqlite::Error::InvalidColumnType(
            index,
            label.to_string(),
            value.data_type(),
        )),
    }
}

#[derive(Debug, Clone)]
pub struct WalletInitInfo {
    pub wallet_id: String,
    pub genesis_id: Option<String>,
    pub device_id: String,
    pub initialized_at: u64,
    pub status: String,
    pub merkle_root: String,
    pub protocol_version: String,
    pub chain_height: u64,
    pub balance: u64,
}

pub fn initialize_wallet_from_verified_genesis(gen: &GenesisRecord) -> Result<WalletInitInfo> {
    info!("Initializing wallet from Genesis - ID: {}", gen.genesis_id);

    let wallet_id = format!("wallet_{}", gen.device_id);
    let now = tick();

    let mut metadata: HashMap<String, Vec<u8>> = HashMap::new();
    metadata.insert(
        "protocol_version".to_string(),
        gen.protocol_version.as_bytes().to_vec(),
    );
    metadata.insert(
        "genesis_progress".to_string(),
        gen.progress_marker.as_bytes().to_vec(),
    );

    let wallet_state = WalletState {
        wallet_id: wallet_id.clone(),
        device_id: gen.device_id.clone(),
        genesis_id: Some(gen.genesis_id.clone()),
        chain_tip: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
        chain_height: 0,
        merkle_root: gen.merkle_root.clone(),
        balance: 0,
        created_at: now,
        updated_at: now,
        status: "initialized_from_genesis".to_string(),
        metadata,
    };

    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "INSERT OR REPLACE INTO wallet_state (
            wallet_id, device_id, genesis_id, chain_tip, chain_height,
            merkle_root, balance, created_at, updated_at, status, metadata
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            wallet_state.wallet_id,
            wallet_state.device_id,
            wallet_state.genesis_id,
            wallet_state.chain_tip,
            wallet_state.chain_height as i64,
            wallet_state.merkle_root,
            0i64,
            wallet_state.created_at as i64,
            wallet_state.updated_at as i64,
            wallet_state.status,
            meta_to_blob(&wallet_state.metadata),
        ],
    )?;

    info!("Wallet initialized successfully");
    Ok(WalletInitInfo {
        wallet_id: wallet_state.wallet_id,
        genesis_id: wallet_state.genesis_id,
        device_id: wallet_state.device_id,
        initialized_at: wallet_state.created_at,
        status: wallet_state.status,
        merkle_root: wallet_state.merkle_root,
        protocol_version: gen.protocol_version.clone(),
        chain_height: wallet_state.chain_height,
        balance: wallet_state.balance,
    })
}

pub fn verify_wallet_against_stored_genesis() -> Result<VerificationResult> {
    info!("Verifying wallet against stored Genesis");
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned, recovering");
        poisoned.into_inner()
    });

    let row_opt: Option<(String, String, Option<String>, String, String)> = conn
        .query_row(
            "SELECT wallet_id, device_id, genesis_id, chain_tip, merkle_root
               FROM wallet_state
           ORDER BY updated_at DESC
              LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    read_hashish_column_as_text(row, 3, "chain_tip")?,
                    read_hashish_column_as_text(row, 4, "merkle_root")?,
                ))
            },
        )
        .optional()?;

    if let Some((wallet_id, device_id, Some(genesis_id), chain_tip, wallet_merkle_root)) = row_opt {
        let gen_row: Option<(String, String)> = conn
            .query_row(
                "SELECT genesis_id, merkle_root FROM genesis_records WHERE genesis_id = ?1",
                params![genesis_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        if let Some((_, genesis_merkle_root)) = gen_row {
            let verified = wallet_merkle_root == genesis_merkle_root;
            let wallet_hash = generate_hash_chain_proof_bytes(wallet_id.as_bytes());
            let genesis_hash = generate_hash_chain_proof_bytes(genesis_id.as_bytes());
            let merkle_proof =
                smt_proof_bytes(genesis_merkle_root.as_bytes(), chain_tip.as_bytes());

            let mut details = HashMap::new();
            details.insert(
                "status".to_string(),
                if verified {
                    b"verified".to_vec()
                } else {
                    b"failed".to_vec()
                },
            );
            details.insert("device_id".to_string(), device_id.into_bytes());
            details.insert("chain_tip".to_string(), chain_tip.into_bytes());

            info!("Wallet verification completed");
            return Ok(VerificationResult {
                verified,
                genesis_hash: Some(genesis_hash.to_vec()),
                wallet_hash: Some(wallet_hash.to_vec()),
                merkle_proof: Some(merkle_proof.to_vec()),
                verification_step: tick(),
                details,
            });
        }
    }

    warn!("No wallet or Genesis record found");
    let mut details = HashMap::new();
    details.insert("status".to_string(), b"no_wallet_or_genesis".to_vec());
    Ok(VerificationResult {
        verified: false,
        genesis_hash: None,
        wallet_hash: None,
        merkle_proof: None,
        verification_step: tick(),
        details,
    })
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

    fn make_genesis() -> GenesisRecord {
        GenesisRecord {
            genesis_id: "gen-test-001".to_string(),
            device_id: "dev-test-001".to_string(),
            mpc_proof: "proof".to_string(),
            dbrw_binding: "binding".to_string(),
            merkle_root: "root123".to_string(),
            participant_count: 1,
            progress_marker: "complete".to_string(),
            publication_hash: "pubhash".to_string(),
            storage_nodes: vec!["node1".to_string()],
            entropy_hash: "entropy".to_string(),
            protocol_version: "1.0".to_string(),
            hash_chain_proof: None,
            smt_proof: None,
            verification_step: None,
        }
    }

    #[test]
    #[serial]
    fn initialize_wallet_from_genesis_produces_correct_info() {
        init_test_db();
        let gen = make_genesis();
        let info = initialize_wallet_from_verified_genesis(&gen).unwrap();

        assert_eq!(info.wallet_id, "wallet_dev-test-001");
        assert_eq!(info.genesis_id.as_deref(), Some("gen-test-001"));
        assert_eq!(info.device_id, "dev-test-001");
        assert_eq!(info.status, "initialized_from_genesis");
        assert_eq!(info.protocol_version, "1.0");
        assert_eq!(info.chain_height, 0);
        assert_eq!(info.balance, 0);
        assert_eq!(info.merkle_root, "root123");
    }

    #[test]
    #[serial]
    fn verify_wallet_with_no_data_returns_unverified() {
        init_test_db();
        let result = verify_wallet_against_stored_genesis().unwrap();
        assert!(!result.verified);
        assert!(result.genesis_hash.is_none());
        assert!(result.wallet_hash.is_none());
        let status = result.details.get("status").unwrap();
        assert_eq!(status, b"no_wallet_or_genesis");
    }

    #[test]
    #[serial]
    fn initialize_wallet_sets_zero_chain_height() {
        init_test_db();
        let gen = make_genesis();
        let info = initialize_wallet_from_verified_genesis(&gen).unwrap();
        assert_eq!(info.chain_height, 0);
    }

    #[test]
    #[serial]
    fn wallet_id_is_deterministic_from_device_id() {
        init_test_db();
        let gen = make_genesis();
        let info1 = initialize_wallet_from_verified_genesis(&gen).unwrap();
        let info2 = initialize_wallet_from_verified_genesis(&gen).unwrap();
        assert_eq!(info1.wallet_id, info2.wallet_id);
        assert_eq!(info1.wallet_id, "wallet_dev-test-001");
    }

    #[test]
    #[serial]
    fn verify_wallet_with_matching_genesis_returns_verified() {
        init_test_db();
        let gen = make_genesis();

        let binding = get_connection().unwrap();
        let conn = binding.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO genesis_records (
                genesis_id, device_id, mpc_proof, dbrw_binding, merkle_root,
                participant_count, chain_tip, publication_hash, storage_nodes,
                entropy_hash, protocol_version, created_at
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            rusqlite::params![
                gen.genesis_id,
                gen.device_id,
                gen.mpc_proof,
                gen.dbrw_binding,
                gen.merkle_root,
                gen.participant_count as i64,
                gen.progress_marker,
                gen.publication_hash,
                "node1",
                gen.entropy_hash,
                gen.protocol_version,
                100i64,
            ],
        )
        .unwrap();
        drop(conn);

        initialize_wallet_from_verified_genesis(&gen).unwrap();
        let result = verify_wallet_against_stored_genesis().unwrap();
        assert!(result.verified);
        assert!(result.genesis_hash.is_some());
        assert!(result.wallet_hash.is_some());
        assert!(result.merkle_proof.is_some());
    }

    #[test]
    #[serial]
    fn initialize_wallet_different_devices_produce_different_ids() {
        init_test_db();
        let gen1 = make_genesis();
        let info1 = initialize_wallet_from_verified_genesis(&gen1).unwrap();

        let mut gen2 = make_genesis();
        gen2.device_id = "dev-test-002".to_string();
        gen2.genesis_id = "gen-test-002".to_string();
        let info2 = initialize_wallet_from_verified_genesis(&gen2).unwrap();

        assert_ne!(info1.wallet_id, info2.wallet_id);
        assert_eq!(info1.wallet_id, "wallet_dev-test-001");
        assert_eq!(info2.wallet_id, "wallet_dev-test-002");
    }

    #[test]
    #[serial]
    fn initialize_wallet_metadata_contains_protocol_version() {
        init_test_db();
        let gen = make_genesis();
        let info = initialize_wallet_from_verified_genesis(&gen).unwrap();
        assert_eq!(info.protocol_version, "1.0");
    }
}
