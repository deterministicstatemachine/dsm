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
use rand::rngs::OsRng;
use rusqlite::{params, OptionalExtension};

use super::get_connection;
use crate::util::deterministic_time::tick;

// =================== Encrypted chain-head SK helpers (§11.1) ===================
//
// The local device's chain-head secret key is needed at receipt construction
// time to sign cert_{n+1}. Persisting it in plaintext would defeat its
// "ephemeral" property; persisting it under an OS keystore is platform-
// specific. We persist it AEAD-encrypted under a key derived from the
// chain-head wrap key (the per-step EK / chain-head key provided by the
// caller) so:
//
// 1. Extracted ciphertext is useless without the chain-head wrap key — the
//    wrapping binds decryption to possession of that key.
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
/// chain-head wrap key.
fn derive_chain_sk_aead_key(chain_head_wrap_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = dsm::crypto::blake3::dsm_domain_hasher(
        dsm::common::domain_tags::TAG_DSM_CERT_CHAIN_SK_AEAD,
    );
    hasher.update(chain_head_wrap_key);
    *hasher.finalize().as_bytes()
}

/// AEAD-encrypt a chain-head secret key.
///
/// Output layout: `nonce(24) || ciphertext_with_tag`.
pub fn encrypt_chain_sk(plain_sk: &[u8], chain_head_wrap_key: &[u8; 32]) -> Result<Vec<u8>> {
    let key = derive_chain_sk_aead_key(chain_head_wrap_key);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow!("XChaCha20Poly1305 init: {e}"))?;
    let mut nonce_bytes = [0u8; 24];
    rand::TryRngCore::try_fill_bytes(&mut OsRng, &mut nonce_bytes)
        .map_err(|e| anyhow!("OsRng entropy failure: {e}"))?;
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
/// is tampered or if `chain_head_wrap_key` doesn't match what was used at encryption.
pub fn decrypt_chain_sk(ciphertext: &[u8], chain_head_wrap_key: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 + 16 {
        return Err(anyhow!(
            "cert-chain SK ciphertext too short ({} bytes, need >= 40)",
            ciphertext.len()
        ));
    }
    let key = derive_chain_sk_aead_key(chain_head_wrap_key);
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
        .map_err(|_| {
            anyhow!("cert-chain SK decryption failed (tamper or wrong chain-head wrap key)")
        })
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
/// has not yet been established).
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
    chain_head_wrap_key: &[u8; 32],
) -> Result<bool> {
    let encrypted_sk = encrypt_chain_sk(chain_head_secret_key, chain_head_wrap_key)?;
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
/// receipt is accepted. Encrypts the new SK under `chain-head wrap key`. Returns the
/// new step count, or `None` if no row exists for that relationship.
pub fn advance_local_cert_chain_head_with_sk(
    relationship_key: &[u8; 32],
    new_pubkey: &[u8],
    new_secret_key: &[u8],
    chain_head_wrap_key: &[u8; 32],
) -> Result<Option<u64>> {
    let encrypted_sk = encrypt_chain_sk(new_secret_key, chain_head_wrap_key)?;
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

/// Outcome of a compare-and-swap local cert-head advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasHeadOutcome {
    /// The head matched `expected_current` and was advanced to `new_pubkey`.
    Advanced { step: u64 },
    /// No head existed and `expected_current` was `None` (genesis): the head
    /// was initialized at `new_pubkey`.
    GenesisInit,
    /// The head was already at `new_pubkey` — idempotent no-op (phase complete
    /// on a recovery re-run).
    AlreadyAtTarget,
    /// The head holds a THIRD value (neither `expected_current` nor
    /// `new_pubkey`), or a head was expected but none exists. Corruption or a
    /// concurrent mutation — the caller MUST fail closed. No write performed.
    Conflict { current: Option<Vec<u8>> },
}

/// Compare-and-swap advance of the LOCAL (side 0) cert-chain head.
///
/// Advances the head to `new_pubkey` ONLY if the current head equals
/// `expected_current` (or, when `expected_current` is `None`, only if no head
/// exists yet — relationship genesis). If the head is already at `new_pubkey`
/// this is an idempotent [`CasHeadOutcome::AlreadyAtTarget`] (so a crash-recovery
/// re-run converges). Any third value is a [`CasHeadOutcome::Conflict`] and no
/// write is performed — the caller must fail closed.
///
/// This is the phase-CAS the finalization/acceptance journal requires: "advance
/// the head only if current == expected; target-present ⇒ done; third value ⇒
/// fail closed."
pub fn cas_advance_local_cert_chain_head_with_sk(
    relationship_key: &[u8; 32],
    expected_current: Option<&[u8]>,
    new_pubkey: &[u8],
    new_secret_key: &[u8],
    chain_head_wrap_key: &[u8; 32],
) -> Result<CasHeadOutcome> {
    // Atomic CAS advance via a predicated UPDATE (only matches when the stored
    // head equals `expected_current`). Try it first so there is no read/modify
    // TOCTOU window on the advance itself.
    if let Some(expected) = expected_current {
        let encrypted_sk = encrypt_chain_sk(new_secret_key, chain_head_wrap_key)?;
        let binding = get_connection()?;
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let now = tick() as i64;
        let updated = conn.execute(
            "UPDATE cert_chain_heads
             SET chain_head_pubkey = ?1,
                 chain_head_sk_encrypted = ?2,
                 step_count = step_count + 1,
                 updated_at = ?3
             WHERE relationship_key = ?4 AND side = 0 AND chain_head_pubkey = ?5",
            params![new_pubkey, encrypted_sk, now, relationship_key.as_slice(), expected],
        )?;
        if updated == 1 {
            let step: i64 = conn
                .query_row(
                    "SELECT step_count FROM cert_chain_heads WHERE relationship_key = ?1 AND side = 0",
                    params![relationship_key.as_slice()],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            return Ok(CasHeadOutcome::Advanced { step: step as u64 });
        }
    }

    // The CAS did not advance (no expected, or head != expected). Classify.
    let current = load_cert_chain_head_pubkey(relationship_key, CertChainSide::Local)?;
    match current {
        Some(cur) if cur.as_slice() == new_pubkey => Ok(CasHeadOutcome::AlreadyAtTarget),
        Some(cur) => Ok(CasHeadOutcome::Conflict { current: Some(cur) }),
        None => {
            if expected_current.is_some() {
                // Expected a prior head but none exists — fail closed.
                return Ok(CasHeadOutcome::Conflict { current: None });
            }
            // Genesis: no head and none expected — initialize.
            init_local_cert_chain_head_with_sk(
                relationship_key,
                new_pubkey,
                new_secret_key,
                chain_head_wrap_key,
            )?;
            Ok(CasHeadOutcome::GenesisInit)
        }
    }
}

/// Compare-and-swap advance of the COUNTERPARTY (side 1) cert-chain head — the
/// A-side head the recipient tracks. No secret key (counterparty rows never carry
/// one). Same semantics as [`cas_advance_local_cert_chain_head_with_sk`]:
/// advance only if current == `expected_current` (or genesis when `None`);
/// already-at-`new_pubkey` is idempotent; a third value is a fail-closed Conflict.
pub fn cas_advance_counterparty_cert_chain_head(
    relationship_key: &[u8; 32],
    expected_current: Option<&[u8]>,
    new_pubkey: &[u8],
) -> Result<CasHeadOutcome> {
    if let Some(expected) = expected_current {
        let binding = get_connection()?;
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let now = tick() as i64;
        let updated = conn.execute(
            "UPDATE cert_chain_heads
             SET chain_head_pubkey = ?1, step_count = step_count + 1, updated_at = ?2
             WHERE relationship_key = ?3 AND side = 1 AND chain_head_pubkey = ?4",
            params![new_pubkey, now, relationship_key.as_slice(), expected],
        )?;
        if updated == 1 {
            let step: i64 = conn
                .query_row(
                    "SELECT step_count FROM cert_chain_heads WHERE relationship_key = ?1 AND side = 1",
                    params![relationship_key.as_slice()],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            return Ok(CasHeadOutcome::Advanced { step: step as u64 });
        }
    }

    let current = load_cert_chain_head_pubkey(relationship_key, CertChainSide::Counterparty)?;
    match current {
        Some(cur) if cur.as_slice() == new_pubkey => Ok(CasHeadOutcome::AlreadyAtTarget),
        Some(cur) => Ok(CasHeadOutcome::Conflict { current: Some(cur) }),
        None => {
            if expected_current.is_some() {
                return Ok(CasHeadOutcome::Conflict { current: None });
            }
            init_cert_chain_head(relationship_key, CertChainSide::Counterparty, new_pubkey)?;
            Ok(CasHeadOutcome::GenesisInit)
        }
    }
}

/// Load and decrypt the local chain head's secret key. Returns `None` if
/// no row exists, or if the row exists but has no SK material (Counterparty
/// rows always).
pub fn load_local_chain_head_sk(
    relationship_key: &[u8; 32],
    chain_head_wrap_key: &[u8; 32],
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
            decrypt_chain_sk(&ciphertext, chain_head_wrap_key).map(Some)
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
    let local_inserted =
        init_cert_chain_head(relationship_key, CertChainSide::Local, local_ak_pubkey)?;
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
    let local_step =
        advance_cert_chain_head(relationship_key, CertChainSide::Local, local_new_pubkey)?;
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

/// Stash a freshly-derived per-step EK as a PENDING Local chain-head
/// advance for one bilateral commitment (§11.1 sender side). The SK is
/// AEAD-encrypted under the same chain-head wrap key scheme as
/// `cert_chain_heads`. Nothing in `cert_chain_heads` changes until
/// `promote_pending_local_head` runs at commit-response time — a confirm
/// the receiver rejects or never sees therefore never moves the Local
/// head, and the next transfer signs from the same prior head the
/// receiver still expects.
///
/// Idempotent per commitment: a rebuild of the same confirm re-derives
/// the same deterministic EK and simply replaces the row.
pub fn stash_pending_local_head(
    relationship_key: &[u8; 32],
    commitment_hash: &[u8; 32],
    ek_pubkey: &[u8],
    ek_secret_key: &[u8],
    chain_head_wrap_key: &[u8; 32],
    is_init: bool,
) -> Result<()> {
    let encrypted_sk = encrypt_chain_sk(ek_secret_key, chain_head_wrap_key)?;
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let now = tick() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO pending_local_cert_heads
            (relationship_key, commitment_hash, ek_pubkey, ek_sk_encrypted, is_init, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            relationship_key.as_slice(),
            commitment_hash.as_slice(),
            ek_pubkey,
            encrypted_sk,
            is_init as i64,
            now
        ],
    )?;
    Ok(())
}

/// Promote a pending Local chain-head advance into `cert_chain_heads`
/// after the receiver's commit-response proves the step was accepted.
/// The encrypted SK blob moves verbatim (it is never decrypted here).
/// Returns the resulting step count, or `None` if no pending row exists
/// for that (relationship, commitment) pair — e.g. already promoted, or
/// dropped by a failure path.
pub fn promote_pending_local_head(
    relationship_key: &[u8; 32],
    commitment_hash: &[u8; 32],
) -> Result<Option<u64>> {
    let binding = get_connection()?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn.transaction()?;
    let row: Option<(Vec<u8>, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT ek_pubkey, ek_sk_encrypted, is_init FROM pending_local_cert_heads
             WHERE relationship_key = ?1 AND commitment_hash = ?2",
            params![relationship_key.as_slice(), commitment_hash.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((ek_pk, sk_ct, is_init)) = row else {
        return Ok(None);
    };
    let now = tick() as i64;
    if is_init != 0 {
        // Relationship genesis: the sign fell back to the root AK because
        // no Local row existed. Record EK_1 as the step-0 head. If a row
        // appeared in the interim (should not happen — sign-time load and
        // this promote are serialized per relationship), the INSERT is
        // ignored and the UPDATE below advances instead.
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO cert_chain_heads
                (relationship_key, side, chain_head_pubkey, chain_head_sk_encrypted, step_count, updated_at)
             VALUES (?1, 0, ?2, ?3, 0, ?4)",
            params![relationship_key.as_slice(), ek_pk, sk_ct, now],
        )?;
        if inserted == 0 {
            tx.execute(
                "UPDATE cert_chain_heads
                 SET chain_head_pubkey = ?1, chain_head_sk_encrypted = ?2,
                     step_count = step_count + 1, updated_at = ?3
                 WHERE relationship_key = ?4 AND side = 0",
                params![ek_pk, sk_ct, now, relationship_key.as_slice()],
            )?;
        }
    } else {
        tx.execute(
            "UPDATE cert_chain_heads
             SET chain_head_pubkey = ?1, chain_head_sk_encrypted = ?2,
                 step_count = step_count + 1, updated_at = ?3
             WHERE relationship_key = ?4 AND side = 0",
            params![ek_pk, sk_ct, now, relationship_key.as_slice()],
        )?;
    }
    tx.execute(
        "DELETE FROM pending_local_cert_heads
         WHERE relationship_key = ?1 AND commitment_hash = ?2",
        params![relationship_key.as_slice(), commitment_hash.as_slice()],
    )?;
    let step: Option<i64> = tx
        .query_row(
            "SELECT step_count FROM cert_chain_heads
             WHERE relationship_key = ?1 AND side = 0",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    tx.commit()?;
    Ok(step.map(|s| s as u64))
}

/// Promote the most-recent pending Local head for `relationship_key` — the
/// online counterpart to [`promote_pending_local_head`], for callers that know
/// the relationship (e.g. the sender's storage-sync ACK sweep, which has the
/// counterparty but not the receipt commitment).
///
/// The in-flight online transfer per relationship is unique (the modal §5.4 lock
/// admits one, and `pending_online_outbox` is keyed by counterparty), so the
/// most-recent pending row is the one just acknowledged. Older pending rows are
/// superseded attempts that were never accepted and are dropped. Returns the
/// resulting step count, or `None` if no pending row exists.
pub fn promote_pending_local_head_by_relationship(
    relationship_key: &[u8; 32],
) -> Result<Option<u64>> {
    let commitment: Option<Vec<u8>> = {
        let binding = get_connection()?;
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT commitment_hash FROM pending_local_cert_heads
             WHERE relationship_key = ?1 ORDER BY created_at DESC LIMIT 1",
            params![relationship_key.as_slice()],
            |r| r.get(0),
        )
        .optional()?
    };
    let Some(commitment) = commitment else {
        return Ok(None);
    };
    let commitment_arr: [u8; 32] = commitment
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pending head commitment_hash is not 32 bytes"))?;
    // Drop superseded (older) pending rows for this relationship before promoting.
    {
        let binding = get_connection()?;
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "DELETE FROM pending_local_cert_heads
             WHERE relationship_key = ?1 AND commitment_hash != ?2",
            params![relationship_key.as_slice(), commitment_arr.as_slice()],
        )?;
    }
    promote_pending_local_head(relationship_key, &commitment_arr)
}

/// Drop a pending Local chain-head advance whose confirm terminally
/// failed (receiver rejected, or the session was abandoned on restore).
/// Returns `true` if a row was deleted.
pub fn drop_pending_local_head(
    relationship_key: &[u8; 32],
    commitment_hash: &[u8; 32],
) -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let deleted = conn.execute(
        "DELETE FROM pending_local_cert_heads
         WHERE relationship_key = ?1 AND commitment_hash = ?2",
        params![relationship_key.as_slice(), commitment_hash.as_slice()],
    )?;
    Ok(deleted > 0)
}

/// Drop every pending Local head for a relationship — used on a terminal
/// send-failure rollback where the specific commitment isn't threaded through
/// but the in-flight transfer for this relationship is being abandoned. Leaves
/// the committed `cert_chain_heads` row untouched. Returns rows deleted.
pub fn drop_pending_local_heads_for_relationship(relationship_key: &[u8; 32]) -> Result<usize> {
    let binding = get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let deleted = conn.execute(
        "DELETE FROM pending_local_cert_heads WHERE relationship_key = ?1",
        params![relationship_key.as_slice()],
    )?;
    Ok(deleted)
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
        init_cert_chain_for_relationship(&r, &[0xAA; 64], &[0xBB; 64]).unwrap();

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
        let result = advance_cert_chain_for_relationship(&r, &[0xAA; 64], &[0xBB; 64]).unwrap();
        assert!(result.is_none());
    }

    // ── Encrypted SK helpers (Phase C) ──

    /// SK round-trip: encrypt → decrypt yields the original secret.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_round_trip() {
        let plain = vec![0xABu8; 64]; // SPHINCS+ secret keys are larger; test with 64 bytes
        let chain_head_wrap_key = [0xCD; 32];
        let ct = encrypt_chain_sk(&plain, &chain_head_wrap_key).unwrap();
        // Nonce(24) + ciphertext(>=plain.len()) + tag(16) = at least 40 + plain.len()
        assert!(ct.len() >= 24 + plain.len() + 16);
        let recovered = decrypt_chain_sk(&ct, &chain_head_wrap_key).unwrap();
        assert_eq!(recovered, plain);
    }

    /// Two encryptions of the same plaintext under the same key produce
    /// distinct ciphertexts (random nonce per encryption).
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_random_nonce_per_encryption() {
        let plain = vec![0x11u8; 32];
        let chain_head_wrap_key = [0x22; 32];
        let ct1 = encrypt_chain_sk(&plain, &chain_head_wrap_key).unwrap();
        let ct2 = encrypt_chain_sk(&plain, &chain_head_wrap_key).unwrap();
        assert_ne!(ct1, ct2, "fresh nonce per encryption");
    }

    /// Tampering with the ciphertext fails decryption.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_tamper_fails() {
        let plain = vec![0x33u8; 64];
        let chain_head_wrap_key = [0x44; 32];
        let mut ct = encrypt_chain_sk(&plain, &chain_head_wrap_key).unwrap();
        // Flip a bit in the ciphertext payload (after the 24-byte nonce).
        ct[30] ^= 0x01;
        assert!(decrypt_chain_sk(&ct, &chain_head_wrap_key).is_err());
    }

    /// Decrypting with a different chain-head wrap key (different device) fails.
    #[test]
    #[serial_test::serial]
    fn chain_sk_aead_wrong_chain_head_wrap_key_fails() {
        let plain = vec![0x55u8; 64];
        let chain_head_wrap_key_a = [0x77; 32];
        let chain_head_wrap_key_b = [0x88; 32];
        let ct = encrypt_chain_sk(&plain, &chain_head_wrap_key_a).unwrap();
        assert!(decrypt_chain_sk(&ct, &chain_head_wrap_key_b).is_err());
    }

    /// Init-with-SK round-trip: encrypted SK survives the storage layer
    /// and decrypts cleanly under the right chain-head wrap key.
    #[test]
    #[serial_test::serial]
    fn local_chain_head_sk_init_load_round_trip() {
        reset_database_for_tests();
        let r = rel(0xB1);
        let pk = vec![0xAA; 64];
        let sk = vec![0xBB; 96];
        let chain_head_wrap_key = [0xCC; 32];

        let inserted =
            init_local_cert_chain_head_with_sk(&r, &pk, &sk, &chain_head_wrap_key).unwrap();
        assert!(inserted);

        let loaded = load_local_chain_head_sk(&r, &chain_head_wrap_key).unwrap();
        assert_eq!(loaded, Some(sk.clone()));

        // Decrypting with wrong chain-head wrap key fails.
        let bad = load_local_chain_head_sk(&r, &[0xDD; 32]);
        assert!(
            bad.is_err(),
            "wrong chain-head wrap key must fail decryption"
        );
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
        let chain_head_wrap_key = [0x33; 32];

        init_local_cert_chain_head_with_sk(&r, &pk0, &sk0, &chain_head_wrap_key).unwrap();
        let step1 = advance_local_cert_chain_head_with_sk(&r, &pk1, &sk1, &chain_head_wrap_key)
            .unwrap()
            .unwrap();
        assert_eq!(step1, 1);

        let loaded_sk = load_local_chain_head_sk(&r, &chain_head_wrap_key)
            .unwrap()
            .unwrap();
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
        let chain_head_wrap_key = [0x66; 32];

        init_local_cert_chain_head_with_sk(&r, &pk, &sk, &chain_head_wrap_key).unwrap();
        assert!(load_local_chain_head_sk(&r, &chain_head_wrap_key)
            .unwrap()
            .is_some());

        wipe_local_chain_head_sk(&r).unwrap();

        // SK is gone.
        assert!(load_local_chain_head_sk(&r, &chain_head_wrap_key)
            .unwrap()
            .is_none());
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
        let result =
            advance_local_cert_chain_head_with_sk(&r, &[0x77; 64], &[0x88; 96], &[0x99; 32])
                .unwrap();
        assert!(result.is_none());
    }

    // ── Pending (deferred) Local chain-head advance (§11.1 sender side) ──

    /// Genesis flow: stash (is_init) leaves cert_chain_heads untouched;
    /// promote creates the step-0 Local row with the EK and its SK; the
    /// pending row is consumed.
    #[test]
    #[serial_test::serial]
    fn pending_local_head_stash_promote_genesis() {
        reset_database_for_tests();
        let r = rel(0xC1);
        let commitment = [0xD1; 32];
        let ek_pk = vec![0x10; 64];
        let ek_sk = vec![0x11; 96];
        let wrap = [0x12; 32];

        stash_pending_local_head(&r, &commitment, &ek_pk, &ek_sk, &wrap, true).unwrap();
        // Nothing promoted yet — the Local head must be unchanged (absent).
        assert!(load_cert_chain_head_pubkey(&r, CertChainSide::Local)
            .unwrap()
            .is_none());

        let step = promote_pending_local_head(&r, &commitment).unwrap();
        assert_eq!(step, Some(0), "genesis promote records EK_1 at step 0");
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ek_pk
        );
        // The SK ciphertext moved verbatim and still decrypts.
        assert_eq!(
            load_local_chain_head_sk(&r, &wrap).unwrap(),
            Some(ek_sk.clone())
        );
        // Pending row consumed — second promote is a no-op.
        assert_eq!(promote_pending_local_head(&r, &commitment).unwrap(), None);
    }

    /// Steady-state flow: with an existing Local row, promote advances it
    /// (step + 1, new pubkey + SK).
    #[test]
    #[serial_test::serial]
    fn pending_local_head_promote_advances_existing_row() {
        reset_database_for_tests();
        let r = rel(0xC2);
        let wrap = [0x21; 32];
        init_local_cert_chain_head_with_sk(&r, &[0xA0; 64], &[0xA1; 96], &wrap).unwrap();

        let commitment = [0xD2; 32];
        let ek_pk = vec![0xB0; 64];
        let ek_sk = vec![0xB1; 96];
        stash_pending_local_head(&r, &commitment, &ek_pk, &ek_sk, &wrap, false).unwrap();

        let step = promote_pending_local_head(&r, &commitment).unwrap();
        assert_eq!(step, Some(1));
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ek_pk
        );
        assert_eq!(load_local_chain_head_sk(&r, &wrap).unwrap(), Some(ek_sk));
    }

    /// Rejected confirm: drop removes the pending row and the Local head
    /// never moves — the divergence-on-failure hazard this table exists
    /// to prevent.
    #[test]
    #[serial_test::serial]
    fn pending_local_head_drop_on_failure_leaves_head_untouched() {
        reset_database_for_tests();
        let r = rel(0xC3);
        let wrap = [0x31; 32];
        let ak_pk = vec![0xA0; 64];
        init_local_cert_chain_head_with_sk(&r, &ak_pk, &[0xA1; 96], &wrap).unwrap();

        let commitment = [0xD3; 32];
        stash_pending_local_head(&r, &commitment, &[0xB0; 64], &[0xB1; 96], &wrap, false).unwrap();
        assert!(drop_pending_local_head(&r, &commitment).unwrap());

        // Head unchanged; promote after drop is a no-op.
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ak_pk
        );
        assert_eq!(promote_pending_local_head(&r, &commitment).unwrap(), None);
        // Dropping again reports nothing deleted.
        assert!(!drop_pending_local_head(&r, &commitment).unwrap());
    }

    /// Re-stash for the same commitment replaces the row (idempotent
    /// rebuild of the same confirm).
    #[test]
    #[serial_test::serial]
    fn pending_local_head_restash_replaces() {
        reset_database_for_tests();
        let r = rel(0xC4);
        let wrap = [0x41; 32];
        let commitment = [0xD4; 32];
        stash_pending_local_head(&r, &commitment, &[0x50; 64], &[0x51; 96], &wrap, true).unwrap();
        let ek_pk2 = vec![0x60; 64];
        stash_pending_local_head(&r, &commitment, &ek_pk2, &[0x61; 96], &wrap, true).unwrap();

        promote_pending_local_head(&r, &commitment).unwrap();
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ek_pk2
        );
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
        advance_cert_chain_head(&r1, CertChainSide::Local, &[0xAB; 64]).unwrap();
        assert_eq!(
            load_cert_chain_head_pubkey(&r2, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            pk2
        );
    }

    // ── §11.1 lockstep: stash-at-sign / promote-on-ACK / drop-on-fail ──
    //
    // Invariant under test: the COMMITTED Local head (`cert_chain_heads`) never
    // advances at sign time — only stashing happens. It advances solely on
    // promote (acceptance ACK), and a drop (failure) returns the relationship
    // to its pre-send cert-chain state. This is what stops a lost PREPARE, lost
    // acceptance, rejection, timeout, or BLE failure from running the sender's
    // chain ahead of the receiver.

    fn ek(n: u8) -> Vec<u8> {
        vec![0xE0u8.wrapping_add(n); 64]
    }
    fn commit(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn pending_count(r: &[u8; 32]) -> i64 {
        let binding = get_connection().unwrap();
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            "SELECT count(*) FROM pending_local_cert_heads WHERE relationship_key = ?1",
            params![r.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn stash_does_not_advance_committed_head() {
        reset_database_for_tests();
        let r = rel(0xE0);
        let wrap = [0x77u8; 32];
        // No committed Local head exists (relationship genesis).
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, true).unwrap();
        // Stashing MUST NOT create or advance the committed head.
        assert!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .is_none(),
            "stash must not touch cert_chain_heads"
        );
        assert_eq!(pending_count(&r), 1, "pending row must exist");
    }

    #[test]
    #[serial_test::serial]
    fn promote_by_relationship_genesis_seeds_head() {
        reset_database_for_tests();
        let r = rel(0xE1);
        let wrap = [0x77u8; 32];
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, true).unwrap();
        let step = promote_pending_local_head_by_relationship(&r).unwrap();
        assert_eq!(step, Some(0), "genesis promote makes EK the step-0 head");
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ek(1)
        );
        assert_eq!(pending_count(&r), 0, "pending cleared after promote");
    }

    #[test]
    #[serial_test::serial]
    fn promote_by_relationship_steady_state_bumps_step() {
        reset_database_for_tests();
        let r = rel(0xE2);
        let wrap = [0x77u8; 32];
        let ak = vec![0xA0u8; 64];
        init_cert_chain_head(&r, CertChainSide::Local, &ak).unwrap();
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, false).unwrap();
        assert_eq!(
            promote_pending_local_head_by_relationship(&r).unwrap(),
            Some(1)
        );
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ek(1)
        );
        assert_eq!(pending_count(&r), 0);
    }

    #[test]
    #[serial_test::serial]
    fn promote_by_relationship_none_leaves_head_unchanged() {
        // Lost PREPARE / no stash: nothing to promote, committed head untouched.
        reset_database_for_tests();
        let r = rel(0xE3);
        let ak = vec![0xA0u8; 64];
        init_cert_chain_head(&r, CertChainSide::Local, &ak).unwrap();
        assert!(promote_pending_local_head_by_relationship(&r)
            .unwrap()
            .is_none());
        assert_eq!(
            load_cert_chain_head_pubkey(&r, CertChainSide::Local)
                .unwrap()
                .unwrap(),
            ak
        );
    }

    #[test]
    #[serial_test::serial]
    fn drop_for_relationship_leaves_committed_head() {
        // Rejection / timeout / BLE failure: drop the stash, committed head stays.
        reset_database_for_tests();
        let r = rel(0xE4);
        let wrap = [0x77u8; 32];
        let ak = vec![0xA0u8; 64];
        init_cert_chain_head(&r, CertChainSide::Local, &ak).unwrap();
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, false).unwrap();
        assert_eq!(drop_pending_local_heads_for_relationship(&r).unwrap(), 1);
        assert_eq!(pending_count(&r), 0);
        let h = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(h.chain_head_pubkey, ak, "committed head must be untouched");
        assert_eq!(h.step_count, 0);
    }

    #[test]
    #[serial_test::serial]
    fn promote_twice_is_idempotent_no_double_advance() {
        // Duplicate acceptance ACK must not double-advance the committed head.
        reset_database_for_tests();
        let r = rel(0xE5);
        let wrap = [0x77u8; 32];
        let ak = vec![0xA0u8; 64];
        init_cert_chain_head(&r, CertChainSide::Local, &ak).unwrap();
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, false).unwrap();
        assert_eq!(
            promote_pending_local_head_by_relationship(&r).unwrap(),
            Some(1)
        );
        assert!(
            promote_pending_local_head_by_relationship(&r)
                .unwrap()
                .is_none(),
            "second promote finds no pending row"
        );
        let h = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(h.step_count, 1, "must NOT double-advance");
        assert_eq!(h.chain_head_pubkey, ek(1));
    }

    #[test]
    #[serial_test::serial]
    fn promote_by_relationship_clears_superseded_no_double_advance() {
        // Multiple retry attempts each stash a pending head. A single acceptance
        // promotes exactly one step and clears all pending rows (no double-spend
        // of chain steps from superseded attempts).
        reset_database_for_tests();
        let r = rel(0xE6);
        let wrap = [0x77u8; 32];
        let ak = vec![0xA0u8; 64];
        init_cert_chain_head(&r, CertChainSide::Local, &ak).unwrap();
        stash_pending_local_head(&r, &commit(1), &ek(1), &[0x55u8; 128], &wrap, false).unwrap();
        stash_pending_local_head(&r, &commit(2), &ek(2), &[0x55u8; 128], &wrap, false).unwrap();
        assert_eq!(pending_count(&r), 2);
        assert_eq!(
            promote_pending_local_head_by_relationship(&r).unwrap(),
            Some(1),
            "exactly one advance regardless of how many attempts were stashed"
        );
        assert_eq!(pending_count(&r), 0, "all pending rows cleared");
        let h = load_cert_chain_head(&r, CertChainSide::Local)
            .unwrap()
            .unwrap();
        assert_eq!(h.step_count, 1);
    }
}
