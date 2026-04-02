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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    fn make_receipt(sigma_byte: u8, vault_id: &str) -> DlvReceiptRecord {
        DlvReceiptRecord {
            sigma: [sigma_byte; 32],
            vault_id: vault_id.to_string(),
            genesis: [0xAA; 32],
            devid_a: [0xBB; 32],
            devid_b: [0xCC; 32],
            receipt_cbor: vec![0xDD; 64],
            sig_a: vec![0xEE; 48],
            sig_b: vec![0xFF; 48],
            created_at: 0,
        }
    }

    #[test]
    #[serial]
    fn store_and_get_dlv_receipt_by_vault() {
        init_test_db();
        let rec = make_receipt(0x11, "vault-dlv-1");
        store_dlv_receipt(&rec).unwrap();

        let loaded = get_dlv_receipt_by_vault("vault-dlv-1").unwrap().unwrap();
        assert_eq!(loaded.vault_id, "vault-dlv-1");
        assert_eq!(loaded.sigma, [0x11; 32]);
        assert_eq!(loaded.genesis, [0xAA; 32]);
        assert_eq!(loaded.devid_a, [0xBB; 32]);
        assert_eq!(loaded.devid_b, [0xCC; 32]);
    }

    #[test]
    #[serial]
    fn store_and_get_dlv_receipt_by_sigma() {
        init_test_db();
        let rec = make_receipt(0x22, "vault-dlv-2");
        store_dlv_receipt(&rec).unwrap();

        let sigma = [0x22u8; 32];
        let loaded = get_dlv_receipt_by_sigma(&sigma).unwrap().unwrap();
        assert_eq!(loaded.vault_id, "vault-dlv-2");
    }

    #[test]
    #[serial]
    fn get_dlv_receipt_returns_none_when_missing() {
        init_test_db();
        assert!(get_dlv_receipt_by_vault("nonexistent").unwrap().is_none());
        assert!(get_dlv_receipt_by_sigma(&[0x99; 32]).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn store_dlv_receipt_upserts_on_conflict() {
        init_test_db();
        let rec = make_receipt(0x33, "vault-dlv-3");
        store_dlv_receipt(&rec).unwrap();

        let mut rec2 = make_receipt(0x33, "vault-dlv-3");
        rec2.sig_a = vec![0x00; 48];
        store_dlv_receipt(&rec2).unwrap();

        let loaded = get_dlv_receipt_by_vault("vault-dlv-3").unwrap().unwrap();
        assert_eq!(loaded.sig_a, vec![0x00; 48]);
    }

    #[test]
    #[serial]
    fn multiple_receipts_stored_independently() {
        init_test_db();
        let rec1 = make_receipt(0x44, "vault-dlv-4");
        let rec2 = make_receipt(0x55, "vault-dlv-5");
        store_dlv_receipt(&rec1).unwrap();
        store_dlv_receipt(&rec2).unwrap();

        let loaded1 = get_dlv_receipt_by_vault("vault-dlv-4").unwrap().unwrap();
        let loaded2 = get_dlv_receipt_by_vault("vault-dlv-5").unwrap().unwrap();
        assert_eq!(loaded1.sigma, [0x44; 32]);
        assert_eq!(loaded2.sigma, [0x55; 32]);
    }

    #[test]
    #[serial]
    fn dlv_receipt_preserves_all_fields() {
        init_test_db();
        let rec = make_receipt(0x66, "vault-dlv-6");
        store_dlv_receipt(&rec).unwrap();

        let loaded = get_dlv_receipt_by_sigma(&[0x66; 32]).unwrap().unwrap();
        assert_eq!(loaded.vault_id, "vault-dlv-6");
        assert_eq!(loaded.genesis, [0xAA; 32]);
        assert_eq!(loaded.devid_a, [0xBB; 32]);
        assert_eq!(loaded.devid_b, [0xCC; 32]);
        assert_eq!(loaded.receipt_cbor, vec![0xDD; 64]);
        assert_eq!(loaded.sig_a, vec![0xEE; 48]);
        assert_eq!(loaded.sig_b, vec![0xFF; 48]);
    }

    #[test]
    #[serial]
    fn get_dlv_receipt_by_sigma_vs_vault_consistency() {
        init_test_db();
        let rec = make_receipt(0x77, "vault-dlv-7");
        store_dlv_receipt(&rec).unwrap();

        let by_vault = get_dlv_receipt_by_vault("vault-dlv-7").unwrap().unwrap();
        let by_sigma = get_dlv_receipt_by_sigma(&[0x77; 32]).unwrap().unwrap();
        assert_eq!(by_vault.sigma, by_sigma.sigma);
        assert_eq!(by_vault.vault_id, by_sigma.vault_id);
    }
}
