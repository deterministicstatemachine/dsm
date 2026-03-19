// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stitched receipt persistence (§4.2).
//!
//! Every accepted online receive produces a `StitchedReceipt` that is persisted here.
//! `sig_a` = sender's SPHINCS+ signature over the receipt commitment hash (fields 1-11).
//! `sig_b` = receiver's counter-signature over the same commitment hash (optional).
//!
//! Solo-signature model: like Ethereum/Bitcoin, each party's hash chain advancement IS
//! the receipt. Tripwire fork-exclusion + hash adjacency prevent double-spend without
//! requiring a counter-signature. sig_a is mandatory (sender non-repudiation); sig_b is
//! stored when available but not required for receipt validity.

use anyhow::{bail, Result};
use log::info;
use rusqlite::params;

use super::get_connection;

/// A stitched receipt as defined in §4.2.
/// `tx_hash` is the BLAKE3 commitment of the receipt body (fields 1-11), used as the
/// primary key so each receipt is stored exactly once per transition.
///
/// Solo-signature model: sig_a (sender) is mandatory. sig_b (receiver counter-signature)
/// is optional — stored when available for additional non-repudiation evidence, but the
/// receipt is valid with sig_a alone. Hash chain adjacency and Tripwire fork-exclusion
/// provide double-spend prevention independent of counter-signatures.
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
    /// Receiver SPHINCS+ signature over the receipt commitment hash (sig_b, §4.2). OPTIONAL.
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
/// Returns an error if `sig_a` is empty — a receipt without the sender's signature
/// has no non-repudiation value and MUST NOT be stored.
/// `sig_b` is optional: stored when available, NULL/empty when not.
/// Uses `INSERT OR IGNORE` so retries are idempotent.
pub fn store_stitched_receipt(r: &StitchedReceipt) -> Result<()> {
    if r.sig_a.is_empty() {
        bail!("store_stitched_receipt: sig_a is empty — sender signature required for non-repudiation");
    }

    let conn_lock = get_connection()?;
    let conn = conn_lock.lock().unwrap_or_else(|p| p.into_inner());

    // sig_b may be empty (solo-signature model); store as-is.
    let sig_b_val: Option<&[u8]> = if r.sig_b.is_empty() {
        None
    } else {
        Some(r.sig_b.as_slice())
    };

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
            sig_b_val,
            r.receipt_commit.as_slice(),
            r.smt_root_pre.as_ref().map(|a| a.as_slice()),
            r.smt_root_post.as_ref().map(|a| a.as_slice()),
        ],
    )?;

    info!(
        "[stitched_receipts] §4.2 receipt stored: tx_hash={:02x}{:02x}{:02x}{:02x}.. \
         sig_a_len={} sig_b_len={}",
        r.tx_hash[0],
        r.tx_hash[1],
        r.tx_hash[2],
        r.tx_hash[3],
        r.sig_a.len(),
        r.sig_b.len()
    );

    Ok(())
}
