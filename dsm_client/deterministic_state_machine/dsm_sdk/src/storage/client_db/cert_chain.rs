// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-relationship cert chain head storage (whitepaper §11.1 ek-cert chain).
//!
//! Each bilateral relationship maintains TWO chain heads:
//! - `Side::Local` — the SPHINCS+ public key the local device used to sign
//!   the most recent outbound cert. At step 0 this is `AK_pk` (the device's
//!   long-term attested key). At step n > 0 this is the per-step `EK_pk_n`.
//! - `Side::Counterparty` — the corresponding chain head pubkey for the
//!   counterparty, used by the local device to verify incoming certs.
//!
//! Chain head advancement happens after a receipt is accepted: the new
//! `EK_pk_{n+1}` (which signed the receipt body) becomes the new chain head
//! for whichever side produced that receipt.
//!
//! This module provides storage primitives only. Higher-level wiring
//! (initializing chain heads at relationship establishment, signing certs
//! during receipt creation, advancing heads after acceptance) lives in
//! `dsm_sdk::sdk::receipts` and the bilateral session handlers.
//!
//! Storage: `cert_chain_heads` table — see `client_db::create_schema`.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

// =================== Encrypted chain-head SK helpers (§11.1) ===================
//
// The local device's chain-head secret key is needed at receipt construction
// time to sign cert_{n+1}. Persisting it in plaintext would defeat its
// "ephemeral" property; persisting it under an OS keystore is platform-
// specific. We persist it AEAD-encrypted under a key derived from K_DBRW so:
//
// 1. Extracted ciphertext is useless on a different device — K_DBRW binds
//    decryption to hardware/environment per whitepaper §12.
// 2. The SK lifetime is bounded: encrypted at receipt-build time for step n,
//    used at receipt-build time for step n+1, then wiped (overwritten with
//    NULL) when chain head advances.
// 3. We use XChaCha20-Poly1305 (matching the recovery capsule choice in
//    §16.10) for nonce-misuse resistance and consistency.
//
// AEAD AD: a fixed domain marker. Per-blob random 24-byte nonce is prepended
// to the ciphertext on disk so each encryption is independent.

const CERT_CHAIN_SK_AAD: &[u8] = b"DSM/cert-chain-sk-aead-v1\0";

/// Derive the AEAD key for cert-chain SK encryption from the device's
/// `K_DBRW`. Whitepaper §12 binds this key to hardware/environment.
fn derive_chain_sk_aead_key(k_dbrw: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher("DSM/cert-chain-sk-aead");
    hasher.update(k_dbrw);
    *hasher.finalize().as_bytes()
}

/// AEAD-encrypt a chain-head secret key.
///
/// Output layout: `nonce(24) || ciphertext_with_tag`.
pub fn encrypt_chain_sk(plain_sk: &[u8], k_dbrw: &[u8; 32]) -> Result<Vec<u8>> {
    let key = derive_chain_sk_aead_key(k_dbrw);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("XChaCha20Poly1305 init: {e}"))?;
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plain_sk,
                aad: CERT_CHAIN_SK_AAD,
            },
        )
        .map_err(|_| anyhow!("cert-chain SK encryption failed"))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AEAD-decrypt a chain-head secret key. Returns `Err` if the ciphertext
/// is tampered or if `k_dbrw` doesn't match what was used at encryption.
pub fn decrypt_chain_sk(ciphertext: &[u8], k_dbrw: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 + 16 {
        return Err(anyhow!(
            "cert-chain SK ciphertext too short ({} bytes, need >= 40)",
            ciphertext.len()
        ));
    }
    let key = derive_chain_sk_aead_key(k_dbrw);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("XChaCha20Poly1305 init: {e}"))?;
    let (nonce_bytes, ct_with_tag) = ciphertext.split_at(24);
    cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: ct_with_tag,
                aad: CERT_CHAIN_SK_AAD,
            },
        )
        .map_err(|_| anyhow!("cert-chain SK decryption failed (tamper or wrong K_DBRW)"))
}

/// Setting key for strict cert-chain verification mode.
///
/// When set to `"1"`, the verification path FAILS CLOSED if a relationship
/// has no recorded chain heads — i.e., absence of chain heads becomes a
/// rejection rather than a silent skip. Default `"0"` (transitional /
/// fail-open) for pre-mainnet development; mainnet deployments MUST set
/// this to `"1"` so that relationships established without `init_cert_chain_for_relationship`
/// cannot silently bypass cert verification.
const STRICT_CERT_CHAIN_KEY: &str = "strict_cert_chain_mode";

/// Read the strict cert-chain mode flag. Returns `false` (fail-open transitional)
/// by default if the setting has never been written.
pub fn is_strict_cert_chain_mode() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let val: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![STRICT_CERT_CHAIN_KEY],
            |row| row.get(0),
        )
        .optional()?;
    Ok(val.as_deref() == Some("1"))
}

/// Enable or disable strict cert-chain mode. Mainnet deployments MUST call
/// `set_strict_cert_chain_mode(true)` before accepting any production traffic.
pub fn set_strict_cert_chain_mode(enabled: bool) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    conn.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?1, ?2)",
        params![STRICT_CERT_CHAIN_KEY, if enabled { "1" } else { "0" }],
    )?;
    Ok(())
}

/// Which side of a bilateral relationship a chain head belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertChainSide {
    /// The local device's outbound cert chain head.
    Local,
    /// The counterparty's outbound cert chain head (verified by us).
    Counterparty,
}

impl CertChainSide {
    fn as_i64(self) -> i64 {
        match self {
            CertChainSide::Local => 0,
            CertChainSide::Counterparty => 1,
        }
    }
}

/// Snapshot of a chain head row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertChainHead {
    pub relationship_key: Vec<u8>,
    pub side: CertChainSide,
    pub chain_head_pubkey: Vec<u8>,
    pub step_count: u64,
    pub updated_at: u64,
}

/// Initialize a chain head for a relationship. Idempotent: if a row already
/// exists for `(relationship_key, side)` it is left unchanged. Returns `true`
/// if a new row was inserted, `false` if the row already existed.
///
/// At relationship establishment (step 0), this is called with
/// `chain_head_pubkey = AK_pk` for both Local (the local device's AK) and
/// Counterparty (the peer's AK, looked up via Device Tree inclusion).
pub fn init_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
    chain_head_pubkey: &[u8],
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO cert_chain_heads
            (relationship_key, side, chain_head_pubkey, step_count, updated_at)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![
            relationship_key.as_slice(),
            side.as_i64(),
            chain_head_pubkey,
            now
        ],
    )?;
    Ok(inserted > 0)
}

/// Advance the chain head to a new pubkey after a receipt is accepted.
/// Bumps `step_count` by one and sets `chain_head_pubkey` to `new_pubkey`.
/// Returns the new step count, or `None` if no row exists for that
/// (relationship_key, side) pair.
pub fn advance_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
    new_pubkey: &[u8],
) -> Result<Option<u64>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let updated = conn.execute(
        "UPDATE cert_chain_heads
         SET chain_head_pubkey = ?1,
             step_count = step_count + 1,
             updated_at = ?2
         WHERE relationship_key = ?3 AND side = ?4",
        params![new_pubkey, now, relationship_key.as_slice(), side.as_i64()],
    )?;
    if updated == 0 {
        return Ok(None);
    }
    let step_count: i64 = conn
        .query_row(
            "SELECT step_count FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok(Some(step_count as u64))
}

/// Load the current chain head pubkey for a relationship + side. Returns
/// `None` if no chain head has been initialized for that pair (relationship
/// has not yet been established, or pre-feature legacy data).
pub fn load_cert_chain_head_pubkey(
    relationship_key: &[u8; 32],
    side: CertChainSide,
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let pk: Option<Vec<u8>> = conn
        .query_row(
            "SELECT chain_head_pubkey FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(pk)
}

/// Initialize a chain head with both pubkey and encrypted secret key
/// (Local side only; counterparty rows have no SK to store). Used at
/// relationship establishment when seeding from `AK_pk` / `AK_sk`.
///
/// Idempotent: if a row already exists for `(relationship_key, side)`,
/// it is left unchanged. Returns `true` on insert, `false` on existing.
pub fn init_local_cert_chain_head_with_sk(
    relationship_key: &[u8; 32],
    chain_head_pubkey: &[u8],
    chain_head_secret_key: &[u8],
    k_dbrw: &[u8; 32],
) -> Result<bool> {
    let encrypted_sk = encrypt_chain_sk(chain_head_secret_key, k_dbrw)?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO cert_chain_heads
            (relationship_key, side, chain_head_pubkey, chain_head_sk_encrypted, step_count, updated_at)
         VALUES (?1, 0, ?2, ?3, 0, ?4)",
        params![
            relationship_key.as_slice(),
            chain_head_pubkey,
            encrypted_sk,
            now
        ],
    )?;
    Ok(inserted > 0)
}

/// Advance the local chain head to a new pubkey + secret key after a
/// receipt is accepted. Encrypts the new SK under `K_DBRW`. Returns the
/// new step count, or `None` if no row exists for that relationship.
pub fn advance_local_cert_chain_head_with_sk(
    relationship_key: &[u8; 32],
    new_pubkey: &[u8],
    new_secret_key: &[u8],
    k_dbrw: &[u8; 32],
) -> Result<Option<u64>> {
    let encrypted_sk = encrypt_chain_sk(new_secret_key, k_dbrw)?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    let updated = conn.execute(
        "UPDATE cert_chain_heads
         SET chain_head_pubkey = ?1,
             chain_head_sk_encrypted = ?2,
             step_count = step_count + 1,
             updated_at = ?3
         WHERE relationship_key = ?4 AND side = 0",
        params![new_pubkey, encrypted_sk, now, relationship_key.as_slice()],
    )?;
    if updated == 0 {
        return Ok(None);
    }
    let step: i64 = conn
        .query_row(
            "SELECT step_count FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = 0",
            params![relationship_key.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok(Some(step as u64))
}

/// Load and decrypt the local chain head's secret key. Returns `None` if
/// no row exists, or if the row exists but has no SK material (Counterparty
/// rows always, or Local rows initialized via the legacy pubkey-only path).
pub fn load_local_chain_head_sk(
    relationship_key: &[u8; 32],
    k_dbrw: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let ct: Option<Vec<u8>> = conn
        .query_row(
            "SELECT chain_head_sk_encrypted FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = 0",
            params![relationship_key.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    match ct {
        Some(ciphertext) if !ciphertext.is_empty() => {
            decrypt_chain_sk(&ciphertext, k_dbrw).map(Some)
        }
        _ => Ok(None),
    }
}

/// Wipe the local chain head's secret key after consumption. Sets
/// `chain_head_sk_encrypted` to NULL. Pubkey and step_count are
/// untouched — only the SK is removed.
pub fn wipe_local_chain_head_sk(relationship_key: &[u8; 32]) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    conn.execute(
        "UPDATE cert_chain_heads
         SET chain_head_sk_encrypted = NULL, updated_at = ?1
         WHERE relationship_key = ?2 AND side = 0",
        params![now, relationship_key.as_slice()],
    )?;
    Ok(())
}

/// Initialize both sides of a relationship's cert chain in one call.
/// This is the common entry point invoked when a relationship is first
/// established: local side anchored at the device's `AK_pk`, counterparty
/// side anchored at the peer's `AK_pk` (looked up via Device Tree
/// inclusion at receipt-verification time).
///
/// Idempotent: returns `(local_inserted, cp_inserted)` indicating whether
/// each side actually wrote a new row. Existing rows are left unchanged.
pub fn init_cert_chain_for_relationship(
    relationship_key: &[u8; 32],
    local_ak_pubkey: &[u8],
    counterparty_ak_pubkey: &[u8],
) -> Result<(bool, bool)> {
    let local_inserted = init_cert_chain_head(
        relationship_key,
        CertChainSide::Local,
        local_ak_pubkey,
    )?;
    let cp_inserted = init_cert_chain_head(
        relationship_key,
        CertChainSide::Counterparty,
        counterparty_ak_pubkey,
    )?;
    Ok((local_inserted, cp_inserted))
}

/// Advance both sides of a relationship's cert chain after a co-signed
/// receipt has been accepted. `local_new_pubkey` is the EK_pk that signed
/// our outbound sig_a (when we were sender) or sig_b (when we were
/// receiver). `counterparty_new_pubkey` is the corresponding EK_pk from
/// the other side.
///
/// Returns `Some((local_step, cp_step))` with the new step counts if both
/// sides were advanced, or `None` if either side had no row to advance
/// (relationship not yet initialized via `init_cert_chain_for_relationship`).
pub fn advance_cert_chain_for_relationship(
    relationship_key: &[u8; 32],
    local_new_pubkey: &[u8],
    counterparty_new_pubkey: &[u8],
) -> Result<Option<(u64, u64)>> {
    let local_step = advance_cert_chain_head(
        relationship_key,
        CertChainSide::Local,
        local_new_pubkey,
    )?;
    let cp_step = advance_cert_chain_head(
        relationship_key,
        CertChainSide::Counterparty,
        counterparty_new_pubkey,
    )?;
    match (local_step, cp_step) {
        (Some(l), Some(c)) => Ok(Some((l, c))),
        _ => Ok(None),
    }
}

/// Load the full chain head record (pubkey + step_count + timestamp).
pub fn load_cert_chain_head(
    relationship_key: &[u8; 32],
    side: CertChainSide,
) -> Result<Option<CertChainHead>> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let row = conn
        .query_row(
            "SELECT chain_head_pubkey, step_count, updated_at
             FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = ?2",
            params![relationship_key.as_slice(), side.as_i64()],
            |row| {
                let pk: Vec<u8> = row.get(0)?;
                let step: i64 = row.get(1)?;
                let ts: i64 = row.get(2)?;
                Ok((pk, step, ts))
            },
        )
        .optional()?;
    Ok(row.map(|(pk, step, ts)| CertChainHead {
        relationship_key: relationship_key.to_vec(),
        side,
        chain_head_pubkey: pk,
        step_count: step as u64,
        updated_at: ts as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::reset_database_for_tests;

    fn rel(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    #[serial_test::serial]
    fn init_inserts_then_idempotent() {
        reset_database_for_tests();
        let r = rel(0xAA);
        let pk_v1 = vec![0x01; 64];
        let pk_v2 = vec![0x02; 64];

        // First init inserts.
        assert!(init_cert_chain_head(&r, CertChainSide::Local, &pk_v1).unwrap());

        // Second init for the same (key, side) is idempotent — does NOT
        // overwrite. Use advance_cert_chain_head to change the pubkey.
        assert!(!init_cert_chain_head(&r, CertChainSide::Local, &pk_v2).unwrap());

        let head = load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(head, pk_v1, "init must not overwrite existing head");
    }

    #[test]
    #[serial_test::serial]
    fn local_and_counterparty_are_independent() {
        reset_database_for_tests();
        let r = rel(0xBB);
        let local_pk = vec![0x11; 64];
        let cp_pk = vec![0x22; 64];

        init_cert_chain_head(&r, CertChainSide::Local, &local_pk).unwrap();
        init_cert_chain_head(&r, CertChainSide::Counterparty, &cp_pk).unwrap();

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_pk
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_pk
        );
    }

    #[test]
    #[serial_test::serial]
    fn advance_bumps_step_and_replaces_pubkey() {
        reset_database_for_tests();
        let r = rel(0xCC);
        let ak_pk = vec![0xAA; 64];
        let ek1_pk = vec![0xBB; 64];
        let ek2_pk = vec![0xCC; 64];

        init_cert_chain_head(&r, CertChainSide::Local, &ak_pk).unwrap();
        let head0 = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(head0.chain_head_pubkey, ak_pk);
        assert_eq!(head0.step_count, 0);

        let step1 = advance_cert_chain_head(&r, CertChainSide::Local, &ek1_pk)
            .unwrap()
            .unwrap();
        assert_eq!(step1, 1);

        let step2 = advance_cert_chain_head(&r, CertChainSide::Local, &ek2_pk)
            .unwrap()
            .unwrap();
        assert_eq!(step2, 2);

        let final_head = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(final_head.chain_head_pubkey, ek2_pk);
        assert_eq!(final_head.step_count, 2);
    }

    #[test]
    #[serial_test::serial]
    fn advance_returns_none_when_no_row_exists() {
        reset_database_for_tests();
        let r = rel(0xDD);
        let pk = vec![0xEE; 64];
        // No init first — advance should be a no-op and return None.
        let result = advance_cert_chain_head(&r, CertChainSide::Local, &pk).unwrap();
        assert!(result.is_none(), "advance without init must return None");
    }

    #[test]
    #[serial_test::serial]
    fn load_returns_none_for_unknown_relationship() {
        reset_database_for_tests();
        let r = rel(0xFE);
        assert!(load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .is_none());
        assert!(load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .is_none());
    }

    /// `init_cert_chain_for_relationship` initializes both sides of a
    /// relationship from a single call. Subsequent advancement on each side
    /// is independent.
    #[test]
    #[serial_test::serial]
    fn init_for_relationship_seeds_both_sides() {
        reset_database_for_tests();
        let r = rel(0xA1);
        let local_ak = vec![0x01; 64];
        let cp_ak = vec![0x02; 64];

        let (li, ci) = init_cert_chain_for_relationship(&r, &local_ak, &cp_ak).unwrap();
        assert!(li, "local side must be inserted on first call");
        assert!(ci, "counterparty side must be inserted on first call");

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_ak
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_ak
        );

        // Second call is idempotent.
        let (li2, ci2) = init_cert_chain_for_relationship(&r, &local_ak, &cp_ak).unwrap();
        assert!(!li2);
        assert!(!ci2);
    }

    /// `advance_cert_chain_for_relationship` advances both sides atomically
    /// after a co-signed receipt is accepted, returning `(local_step, cp_step)`.
    #[test]
    #[serial_test::serial]
    fn advance_for_relationship_bumps_both_sides() {
        reset_database_for_tests();
        let r = rel(0xA2);
        init_cert_chain_for_relationship(&r, &vec![0xAA; 64], &vec![0xBB; 64]).unwrap();

        let local_ek1 = vec![0xCC; 64];
        let cp_ek1 = vec![0xDD; 64];

        let steps = advance_cert_chain_for_relationship(&r, &local_ek1, &cp_ek1)
            .unwrap()
            .unwrap();
        assert_eq!(steps, (1, 1));

        let local_ek2 = vec![0xEE; 64];
        let cp_ek2 = vec![0xFF; 64];
        let steps2 = advance_cert_chain_for_relationship(&r, &local_ek2, &cp_ek2)
            .unwrap()
            .unwrap();
        assert_eq!(steps2, (2, 2));

        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            local_ek2
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Counterparty)
                .unwrap()
                .unwrap(),
            cp_ek2
        );
    }

    /// `advance_cert_chain_for_relationship` returns `None` when the
    /// relationship has never been initialized — caller is expected to
    /// init first.
    #[test]
    #[serial_test::serial]
    fn advance_for_relationship_requires_init() {
        reset_database_for_tests();
        let r = rel(0xA3);
        let result =
            advance_cert_chain_for_relationship(&r, &vec![0xAA; 64], &vec![0xBB; 64]).unwrap();
        assert!(result.is_none());
    }

    // ── Encrypted SK helpers (Phase C) ──

    /// SK round-trip: encrypt → decrypt yields the original secret.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_round_trip() {
        let plain = vec![0xABu8; 64]; // SPHINCS+ secret keys are larger; test with 64 bytes
        let k_dbrw = [0xCD; 32];
        let ct = encrypt_chain_sk(&plain, &k_dbrw).unwrap();
        // Nonce(24) + ciphertext(>=plain.len()) + tag(16) = at least 40 + plain.len()
        assert!(ct.len() >= 24 + plain.len() + 16);
        let recovered = decrypt_chain_sk(&ct, &k_dbrw).unwrap();
        assert_eq!(recovered, plain);
    }

    /// Two encryptions of the same plaintext under the same key produce
    /// distinct ciphertexts (random nonce per encryption).
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_random_nonce_per_encryption() {
        let plain = vec![0x11u8; 32];
        let k_dbrw = [0x22; 32];
        let ct1 = encrypt_chain_sk(&plain, &k_dbrw).unwrap();
        let ct2 = encrypt_chain_sk(&plain, &k_dbrw).unwrap();
        assert_ne!(ct1, ct2, "fresh nonce per encryption");
    }

    /// Tampering with the ciphertext fails decryption.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_tamper_fails() {
        let plain = vec![0x33u8; 64];
        let k_dbrw = [0x44; 32];
        let mut ct = encrypt_chain_sk(&plain, &k_dbrw).unwrap();
        // Flip a bit in the ciphertext payload (after the 24-byte nonce).
        ct[30] ^= 0x01;
        assert!(decrypt_chain_sk(&ct, &k_dbrw).is_err());
    }

    /// Decrypting with a different K_DBRW (different device) fails.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_wrong_k_dbrw_fails() {
        let plain = vec![0x55u8; 64];
        let k_dbrw_a = [0x77; 32];
        let k_dbrw_b = [0x88; 32];
        let ct = encrypt_chain_sk(&plain, &k_dbrw_a).unwrap();
        assert!(decrypt_chain_sk(&ct, &k_dbrw_b).is_err());
    }

    /// Init-with-SK round-trip: encrypted SK survives the storage layer
    /// and decrypts cleanly under the right K_DBRW.
    #[test]
    #[serial_test::serial]
    fn local_chain_head_sk_init_load_round_trip() {
        reset_database_for_tests();
        let r = rel(0xB1);
        let pk = vec![0xAA; 64];
        let sk = vec![0xBB; 96];
        let k_dbrw = [0xCC; 32];

        let inserted = init_local_cert_chain_head_with_sk(&r, &pk, &sk, &k_dbrw).unwrap();
        assert!(inserted);

        let loaded = load_local_chain_head_sk(&r, &k_dbrw).unwrap();
        assert_eq!(loaded, Some(sk.clone()));

        // Decrypting with wrong K_DBRW fails.
        let bad = load_local_chain_head_sk(&r, &[0xDD; 32]);
        assert!(bad.is_err(), "wrong K_DBRW must fail decryption");
    }

    /// Advance-with-SK round-trip: after advancing, the new SK is what
    /// load returns; old SK is no longer recoverable.
    #[test]
    #[serial_test::serial]
    fn local_chain_head_sk_advance_round_trip() {
        reset_database_for_tests();
        let r = rel(0xB2);
        let pk0 = vec![0x10; 64];
        let sk0 = vec![0x11; 96];
        let pk1 = vec![0x20; 64];
        let sk1 = vec![0x22; 96];
        let k_dbrw = [0x33; 32];

        init_local_cert_chain_head_with_sk(&r, &pk0, &sk0, &k_dbrw).unwrap();
        let step1 =
            advance_local_cert_chain_head_with_sk(&r, &pk1, &sk1, &k_dbrw)
                .unwrap()
                .unwrap();
        assert_eq!(step1, 1);

        let loaded_sk = load_local_chain_head_sk(&r, &k_dbrw).unwrap().unwrap();
        assert_eq!(loaded_sk, sk1);
        // Old SK is not recoverable post-advance.
        assert_ne!(loaded_sk, sk0);

        let loaded_pk = load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(loaded_pk, pk1);
    }

    /// Wipe-after-consumption nulls out the SK column without touching
    /// the pubkey or step count. Subsequent loads return None.
    #[test]
    #[serial_test::serial]
    fn local_chain_head_sk_wipe_clears_only_sk() {
        reset_database_for_tests();
        let r = rel(0xB3);
        let pk = vec![0x44; 64];
        let sk = vec![0x55; 96];
        let k_dbrw = [0x66; 32];

        init_local_cert_chain_head_with_sk(&r, &pk, &sk, &k_dbrw).unwrap();
        assert!(load_local_chain_head_sk(&r, &k_dbrw).unwrap().is_some());

        wipe_local_chain_head_sk(&r).unwrap();

        // SK is gone.
        assert!(load_local_chain_head_sk(&r, &k_dbrw).unwrap().is_none());
        // Pubkey is still there.
        let pk_after = load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(pk_after, pk);
    }

    /// Advance fails (returns None) if the relationship has no init'd row.
    #[test]
    #[serial_test::serial]
    fn local_chain_head_sk_advance_requires_init() {
        reset_database_for_tests();
        let r = rel(0xB4);
        let result = advance_local_cert_chain_head_with_sk(
            &r,
            &vec![0x77; 64],
            &vec![0x88; 96],
            &[0x99; 32],
        )
        .unwrap();
        assert!(result.is_none());
    }

    /// Strict mode defaults to disabled (transitional pre-mainnet).
    #[test]
    #[serial_test::serial]
    fn strict_mode_default_off() {
        reset_database_for_tests();
        assert!(!is_strict_cert_chain_mode().unwrap());
    }

    /// Strict mode toggles round-trip cleanly through the settings store.
    #[test]
    #[serial_test::serial]
    fn strict_mode_set_and_read() {
        reset_database_for_tests();
        // Initially off.
        assert!(!is_strict_cert_chain_mode().unwrap());

        // Enable.
        set_strict_cert_chain_mode(true).unwrap();
        assert!(is_strict_cert_chain_mode().unwrap());

        // Re-enable is idempotent.
        set_strict_cert_chain_mode(true).unwrap();
        assert!(is_strict_cert_chain_mode().unwrap());

        // Disable.
        set_strict_cert_chain_mode(false).unwrap();
        assert!(!is_strict_cert_chain_mode().unwrap());
    }

    #[test]
    #[serial_test::serial]
    fn different_relationships_isolated() {
        reset_database_for_tests();
        let r1 = rel(0x01);
        let r2 = rel(0x02);
        let pk1 = vec![0x11; 64];
        let pk2 = vec![0x22; 64];

        init_cert_chain_head(&r1, CertChainSide::Local, &pk1).unwrap();
        init_cert_chain_head(&r2, CertChainSide::Local, &pk2).unwrap();

        assert_eq!(
            load_cert_chain_head_pubkey(&r1, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk1
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r2, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk2
        );
        // Advance r1 doesn't touch r2.
        advance_cert_chain_head(&r1, CertChainSide::Local, &vec![0xAB; 64]).unwrap();
        assert_eq!(
            load_cert_chain_head_pubkey(&r2, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk2
        );
    }
}
