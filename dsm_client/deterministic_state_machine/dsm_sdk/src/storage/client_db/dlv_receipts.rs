// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV receipt persistence (§7.3, §18.4).

use anyhow::Result;
use rusqlite::{params, Row};

use super::get_connection;
use super::types::DlvReceiptRecord;
use crate::util::deterministic_time::tick;

pub fn store_dlv_receipt(rec: &DlvReceiptRecord) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in store_dlv_receipt, recovering");
        poisoned.into_inner()
    });
    let now = tick();
    conn.execute(
        "INSERT OR REPLACE INTO dlv_receipts(sigma, vault_id, genesis, devid_a, devid_b, receipt_cbor, sig_a, sig_b, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &rec.sigma[..],
            rec.vault_id,
            &rec.genesis[..],
            &rec.devid_a[..],
            &rec.devid_b[..],
            rec.receipt_cbor,
            rec.sig_a,
            rec.sig_b,
            now as i64,
        ],
    )?;
    Ok(())
}

pub fn get_dlv_receipt_by_vault(vault_id: &str) -> Result<Option<DlvReceiptRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_dlv_receipt_by_vault, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT sigma, vault_id, genesis, devid_a, devid_b, receipt_cbor, sig_a, sig_b, created_at FROM dlv_receipts WHERE vault_id = ?1",
            params![vault_id],
            dlv_receipt_from_row,
        )
        .optional()?;
    Ok(row)
}

pub fn get_dlv_receipt_by_sigma(sigma: &[u8; 32]) -> Result<Option<DlvReceiptRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_dlv_receipt_by_sigma, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT sigma, vault_id, genesis, devid_a, devid_b, receipt_cbor, sig_a, sig_b, created_at FROM dlv_receipts WHERE sigma = ?1",
            params![&sigma[..]],
            dlv_receipt_from_row,
        )
        .optional()?;
    Ok(row)
}

fn dlv_receipt_from_row(row: &Row) -> rusqlite::Result<DlvReceiptRecord> {
    let sigma_vec: Vec<u8> = row.get(0)?;
    let genesis_vec: Vec<u8> = row.get(2)?;
    let devid_a_vec: Vec<u8> = row.get(3)?;
    let devid_b_vec: Vec<u8> = row.get(4)?;
    let mut sigma = [0u8; 32];
    let mut genesis = [0u8; 32];
    let mut devid_a = [0u8; 32];
    let mut devid_b = [0u8; 32];
    if sigma_vec.len() == 32 {
        sigma.copy_from_slice(&sigma_vec);
    }
    if genesis_vec.len() == 32 {
        genesis.copy_from_slice(&genesis_vec);
    }
    if devid_a_vec.len() == 32 {
        devid_a.copy_from_slice(&devid_a_vec);
    }
    if devid_b_vec.len() == 32 {
        devid_b.copy_from_slice(&devid_b_vec);
    }
    Ok(DlvReceiptRecord {
        sigma,
        vault_id: row.get(1)?,
        genesis,
        devid_a,
        devid_b,
        receipt_cbor: row.get(5)?,
        sig_a: row.get(6)?,
        sig_b: row.get(7)?,
        created_at: row.get::<_, i64>(8)? as u64,
    })
}

use rusqlite::OptionalExtension;
