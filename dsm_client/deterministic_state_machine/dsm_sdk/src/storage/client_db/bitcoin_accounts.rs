// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bitcoin account persistence with at-rest encryption for secret material.
//!
//! `secret_material` is encrypted with XChaCha20-Poly1305 using a key derived
//! from the DBRW binding key via BLAKE3 domain separation:
//!   enc_key = BLAKE3("DSM/btc-key-enc\0" || dbrw_binding_key)
//!
//! Storage format: `[24-byte nonce][ciphertext + 16-byte Poly1305 tag]`

use anyhow::Result;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{params, OptionalExtension, Row};

use super::get_connection;
use crate::util::deterministic_time::tick;

/// AEAD nonce size for XChaCha20-Poly1305 (24 bytes).
const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag size (16 bytes).
const TAG_LEN: usize = 16;
/// Minimum length of encrypted blob: nonce + at least 1 byte plaintext + tag.
const MIN_ENCRYPTED_LEN: usize = NONCE_LEN + 1 + TAG_LEN;

/// Derive a 32-byte encryption key from the DBRW binding key.
fn derive_enc_key(dbrw_binding_key: &[u8]) -> [u8; 32] {
    *dsm::crypto::blake3::domain_hash("DSM/btc-key-enc", dbrw_binding_key).as_bytes()
}

/// Encrypt `plaintext` with XChaCha20-Poly1305 using a BLAKE3-derived deterministic nonce.
/// Returns `[24-byte nonce][ciphertext + tag]`.
fn encrypt_secret(enc_key: &[u8; 32], account_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(enc_key)
        .map_err(|e| anyhow::anyhow!("XChaCha20 key init: {e}"))?;

    // Deterministic nonce: BLAKE3("DSM/btc-nonce\0" || account_id || tick)[0..24]
    // Using tick ensures a new nonce on each re-encryption (e.g., migration).
    let mut h = dsm::crypto::blake3::dsm_domain_hasher("DSM/btc-nonce");
    h.update(account_id.as_bytes());
    h.update(&tick().to_le_bytes());
    let hash = h.finalize();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("XChaCha20 encrypt: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `blob` (expected format: `[nonce 24B][ciphertext + tag]`).
fn decrypt_secret(enc_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MIN_ENCRYPTED_LEN {
        anyhow::bail!("Encrypted blob too short: {} bytes", blob.len());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);
    let nonce = XNonce::from(nonce_arr);
    let cipher = XChaCha20Poly1305::new_from_slice(enc_key)
        .map_err(|e| anyhow::anyhow!("XChaCha20 key init: {e}"))?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("XChaCha20 decrypt: {e}"))
}

/// Get the DBRW-derived encryption key.
fn get_enc_key() -> Result<[u8; 32]> {
    let dbrw = crate::fetch_dbrw_binding_key()
        .map_err(|e| anyhow::anyhow!("DBRW binding key unavailable: {e}"))?;
    Ok(derive_enc_key(&dbrw))
}

/// Persisted Bitcoin wallet account import material.
#[derive(Debug, Clone)]
pub struct BitcoinAccountRecord {
    pub account_id: String,
    pub label: String,
    pub import_kind: String,
    pub secret_material: Vec<u8>,
    pub network: u32,
    pub first_address: Option<String>,
    pub active: bool,
    pub active_receive_index: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

pub fn upsert_bitcoin_account(rec: &BitcoinAccountRecord) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in upsert_bitcoin_account, recovering");
        poisoned.into_inner()
    });
    let now = tick();

    // Encrypt secret_material before writing to SQLite.
    let key = get_enc_key()?;
    let stored_material = encrypt_secret(&key, &rec.account_id, &rec.secret_material)?;

    conn.execute(
        "INSERT OR REPLACE INTO bitcoin_accounts(
            account_id, label, import_kind, secret_material, network, first_address,
            active, active_receive_index, created_at, updated_at
        ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            rec.account_id,
            rec.label,
            rec.import_kind,
            stored_material,
            rec.network as i64,
            rec.first_address,
            if rec.active { 1i32 } else { 0i32 },
            rec.active_receive_index as i64,
            rec.created_at as i64,
            now as i64,
        ],
    )?;
    Ok(())
}

pub fn list_bitcoin_accounts() -> Result<Vec<BitcoinAccountRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in list_bitcoin_accounts, recovering");
        poisoned.into_inner()
    });
    let mut stmt =
        conn.prepare("SELECT account_id, label, import_kind, secret_material, network, first_address, active, active_receive_index, created_at, updated_at FROM bitcoin_accounts ORDER BY created_at ASC")?;
    let iter = stmt.query_map([], read_bitcoin_account_row)?;
    let mut out = Vec::new();
    for r in iter {
        let mut rec = r?;
        decrypt_secret_material(&mut rec)?;
        out.push(rec);
    }
    Ok(out)
}

pub fn get_bitcoin_account(account_id: &str) -> Result<Option<BitcoinAccountRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_bitcoin_account, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT account_id, label, import_kind, secret_material, network, first_address, active, active_receive_index, created_at, updated_at FROM bitcoin_accounts WHERE account_id = ?1",
            params![account_id],
            read_bitcoin_account_row,
        )
        .optional()?;
    match row {
        Some(mut rec) => {
            decrypt_secret_material(&mut rec)?;
            Ok(Some(rec))
        }
        None => Ok(None),
    }
}

pub fn set_active_bitcoin_account(account_id: &str) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in set_active_bitcoin_account, recovering");
        poisoned.into_inner()
    });
    conn.execute("UPDATE bitcoin_accounts SET active = 0", [])?;
    conn.execute(
        "UPDATE bitcoin_accounts SET active = 1 WHERE account_id = ?1",
        params![account_id],
    )?;
    Ok(())
}

pub fn get_active_bitcoin_account() -> Result<Option<BitcoinAccountRecord>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in get_active_bitcoin_account, recovering");
        poisoned.into_inner()
    });
    let row = conn
        .query_row(
            "SELECT account_id, label, import_kind, secret_material, network, first_address, active, active_receive_index, created_at, updated_at FROM bitcoin_accounts WHERE active = 1 LIMIT 1",
            [],
            read_bitcoin_account_row,
        )
        .optional()?;
    match row {
        Some(mut rec) => {
            decrypt_secret_material(&mut rec)?;
            Ok(Some(rec))
        }
        None => Ok(None),
    }
}

pub fn set_active_receive_index(account_id: &str, index: u32) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|poisoned| {
        log::warn!("DB lock poisoned in set_active_receive_index, recovering");
        poisoned.into_inner()
    });
    conn.execute(
        "UPDATE bitcoin_accounts SET active_receive_index = ?1 WHERE account_id = ?2",
        params![index as i64, account_id],
    )?;
    Ok(())
}

/// Decrypt `secret_material` in-place.
fn decrypt_secret_material(rec: &mut BitcoinAccountRecord) -> Result<()> {
    let enc_key = get_enc_key()?;

    let blob = &rec.secret_material;
    if blob.is_empty() {
        return Ok(());
    }

    if blob.len() < MIN_ENCRYPTED_LEN {
        anyhow::bail!(
            "Refusing to load unencrypted bitcoin secret material for account {}",
            rec.account_id
        );
    }

    rec.secret_material = decrypt_secret(&enc_key, blob).map_err(|e| {
        anyhow::anyhow!(
            "Failed to decrypt bitcoin secret material for account {}: {}",
            rec.account_id,
            e
        )
    })?;
    Ok(())
}

fn read_bitcoin_account_row(row: &Row) -> rusqlite::Result<BitcoinAccountRecord> {
    Ok(BitcoinAccountRecord {
        account_id: row.get(0)?,
        label: row.get(1)?,
        import_kind: row.get(2)?,
        secret_material: row.get(3)?,
        network: row.get::<_, i64>(4)? as u32,
        first_address: row.get(5)?,
        active: row.get::<_, i32>(6)? != 0,
        active_receive_index: row.get::<_, i64>(7)? as u32,
        created_at: row.get::<_, i64>(8)? as u64,
        updated_at: row.get::<_, i64>(9)? as u64,
    })
}
