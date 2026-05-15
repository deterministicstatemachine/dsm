// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stitched receipt persistence (§4.2).
//!
//! Every accepted online receive produces a `StitchedReceipt` that is persisted here.
//! `sig_a` = sender's SPHINCS+ signature over the receipt commitment hash (fields 1-11).
//! `sig_b` = receiver's counter-signature over the same commitment hash.

use anyhow::{bail, Result};
use log::info;
use rusqlite::params;

use super::get_connection;

/// A stitched receipt as defined in §4.2.
/// `tx_hash` is the BLAKE3 commitment of the receipt body (fields 1-11), used as the
/// primary key so each receipt is stored exactly once per transition.
#[derive(Debug, Clone)]
pub struct StitchedReceipt {
    /// BLAKE3 commitment of the receipt body — primary key.
    pub tx_hash: [u8; 32],
    /// Relationship chain tip before this transition (h_n).
    pub h_n: [u8; 32],
    /// Relationship chain tip after this transition (h_{n+1}).
    pub h_n1: [u8; 32],
    /// Sender device identifier (DevID_A).
    pub device_id_a: [u8; 32],
    /// Receiver device identifier (DevID_B).
    pub device_id_b: [u8; 32],
    /// Sender SPHINCS+ signature over the receipt commitment hash (sig_a, §4.2). REQUIRED.
    pub sig_a: Vec<u8>,
    /// Receiver SPHINCS+ signature over the receipt commitment hash (sig_b, §4.2). REQUIRED.
    pub sig_b: Vec<u8>,
    /// Canonical ReceiptCommit protobuf bytes (fields 1-11, unsigned of sig fields).
    pub receipt_commit: Vec<u8>,
    /// Per-Device SMT root before the SMT-Replace (r_A).
    pub smt_root_pre: Option<[u8; 32]>,
    /// Per-Device SMT root after the SMT-Replace (r'_A).
    pub smt_root_post: Option<[u8; 32]>,
}

/// Persist a stitched receipt.
///
/// Returns an error unless both bilateral signatures are present.
/// Uses `INSERT OR IGNORE` so retries are idempotent.
pub fn store_stitched_receipt(r: &StitchedReceipt) -> Result<()> {
    if r.sig_a.is_empty() {
        bail!("store_stitched_receipt: sig_a is empty — sender signature required for non-repudiation");
    }
    if r.sig_b.is_empty() {
        bail!("store_stitched_receipt: sig_b is empty — receiver signature required for bilateral acceptance");
    }

    let conn_lock = get_connection()?;
    let conn = conn_lock.lock().unwrap_or_else(|p| p.into_inner());

    conn.execute(
        "INSERT OR IGNORE INTO stitched_receipts (
            tx_hash, h_n, h_n1, device_id_a, device_id_b,
            sig_a, sig_b, receipt_commit, smt_root_pre, smt_root_post
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            r.tx_hash.as_slice(),
            r.h_n.as_slice(),
            r.h_n1.as_slice(),
            r.device_id_a.as_slice(),
            r.device_id_b.as_slice(),
            r.sig_a.as_slice(),
            r.sig_b.as_slice(),
            r.receipt_commit.as_slice(),
            r.smt_root_pre.as_ref().map(|a| a.as_slice()),
            r.smt_root_post.as_ref().map(|a| a.as_slice()),
        ],
    )?;

    info!(
        "[stitched_receipts] §4.2 receipt stored: tx_hash_b32={} sig_a_len={} sig_b_len={}",
        crate::util::text_id::encode_base32_crockford(&r.tx_hash)
            .get(..8)
            .unwrap_or("?"),
        r.sig_a.len(),
        r.sig_b.len()
    );

    Ok(())
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

    fn make_receipt() -> StitchedReceipt {
        StitchedReceipt {
            tx_hash: [0x11; 32],
            h_n: [0x22; 32],
            h_n1: [0x33; 32],
            device_id_a: [0x44; 32],
            device_id_b: [0x55; 32],
            sig_a: vec![0xAA; 64],
            sig_b: vec![0xBB; 64],
            receipt_commit: vec![0xCC; 128],
            smt_root_pre: Some([0xDD; 32]),
            smt_root_post: Some([0xEE; 32]),
        }
    }

    #[test]
    fn store_stitched_receipt_rejects_empty_sig_a() {
        let mut r = make_receipt();
        r.sig_a = vec![];
        let err = store_stitched_receipt(&r).unwrap_err();
        assert!(err.to_string().contains("sig_a is empty"));
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_succeeds_with_valid_data() {
        init_test_db();
        let r = make_receipt();
        store_stitched_receipt(&r).unwrap();
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_is_idempotent() {
        init_test_db();
        let r = make_receipt();
        store_stitched_receipt(&r).unwrap();
        store_stitched_receipt(&r).unwrap();
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_rejects_empty_sig_b() {
        let mut r = make_receipt();
        r.sig_b = vec![];
        let err = store_stitched_receipt(&r).unwrap_err();
        assert!(err.to_string().contains("sig_b is empty"));
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_without_smt_roots() {
        init_test_db();
        let mut r = make_receipt();
        r.tx_hash = [0xFE; 32];
        r.smt_root_pre = None;
        r.smt_root_post = None;
        store_stitched_receipt(&r).unwrap();
    }

    #[test]
    #[serial]
    fn different_tx_hash_stored_independently() {
        init_test_db();
        let mut r1 = make_receipt();
        r1.tx_hash = [0x01; 32];
        r1.sig_a = vec![0xA1; 64];
        store_stitched_receipt(&r1).unwrap();

        let mut r2 = make_receipt();
        r2.tx_hash = [0x02; 32];
        r2.sig_a = vec![0xA2; 64];
        store_stitched_receipt(&r2).unwrap();
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_with_minimal_sig_a() {
        init_test_db();
        let mut r = make_receipt();
        r.tx_hash = [0xFD; 32];
        r.sig_a = vec![0x01]; // minimal non-empty
        store_stitched_receipt(&r).unwrap();
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_ignore_does_not_overwrite() {
        init_test_db();
        let mut r1 = make_receipt();
        r1.tx_hash = [0xFC; 32];
        r1.sig_a = vec![0xAA; 64];
        store_stitched_receipt(&r1).unwrap();

        let mut r2 = make_receipt();
        r2.tx_hash = [0xFC; 32];
        r2.sig_a = vec![0xBB; 64];
        store_stitched_receipt(&r2).unwrap();
    }

    #[test]
    #[serial]
    fn store_stitched_receipt_with_different_device_ids() {
        init_test_db();
        let mut r = make_receipt();
        r.tx_hash = [0xFB; 32];
        r.device_id_a = [0x01; 32];
        r.device_id_b = [0x02; 32];
        store_stitched_receipt(&r).unwrap();
    }
}
