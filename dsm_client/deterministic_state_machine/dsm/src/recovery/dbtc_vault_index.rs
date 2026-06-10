// SPDX-License-Identifier: MIT OR Apache-2.0

//! Posted dBTC vault index (spec §0.4 P5 — dBTC enumeration).
//!
//! A fresh recovered device has no local `vault_store`, so it cannot list its dBTC vaults.
//! The healthy device therefore posts a `K_A`-signed index of its dBTC vault ids; the
//! recovering device fetches it as the **candidate set** for [`crate::recovery`] dBTC
//! reconciliation.
//!
//! Authentication mirrors [`crate::recovery::PostedPdsmtHead`]: the index carries its
//! `authority_pubkey`, and [`PostedDbtcVaultIndex::verify`] requires
//! `H(authority_pubkey) == authority_pubkey_commit == the genesis-anchored commit`, plus a
//! valid signature over the digest. Enumeration completeness is NOT a safety property — the
//! per-vault Bitcoin-backing check ([`crate::recovery::classify_dbtc_backing`]) is the unlock
//! gate — so a forged or partial index can only yield Bitcoin-verify-out (extra ids) or a
//! locked deadlock (missing ids), never a double-spend. Storage is availability-only.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::recovery::authority_anchor::compute_authority_pubkey_commit;
use crate::types::error::DsmError;
use crate::types::proto::{Message as _, PostedDbtcVaultIndexV1};

const VAULT_INDEX_DOMAIN: &str = crate::common::domain_tags::TAG_DSM_RECOVERY_DBTC_VAULT_INDEX;

fn fixed32(b: &[u8], field: &str) -> Result<[u8; 32], DsmError> {
    b.try_into().map_err(|_| {
        DsmError::verification(format!(
            "dbtc-vault-index: field `{field}` is {} bytes, expected 32",
            b.len()
        ))
    })
}

/// A device's signed dBTC vault index — the candidate vault-id set for recovery dBTC
/// reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedDbtcVaultIndex {
    pub genesis_id: [u8; 32],
    pub device_id: [u8; 32],
    /// Base32 Crockford vault ids (sorted+deduped on build for a canonical digest).
    pub vault_ids: Vec<String>,
    /// `H(K_A_pub)` — bound to the genesis via the device's `RecoveryAuthorityAnchor`.
    pub authority_pubkey_commit: [u8; 32],
    /// Raw `K_A_pub` (carried so a third party can verify without a separate source; checked
    /// against `authority_pubkey_commit`).
    pub authority_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl PostedDbtcVaultIndex {
    /// The digest the signature covers (every field except the signature). `vault_ids` are
    /// hashed in their stored order — [`build_dbtc_vault_index`] sorts+dedups them so the
    /// digest is canonical regardless of enumeration order.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(VAULT_INDEX_DOMAIN);
        h.update(&self.genesis_id);
        h.update(&self.device_id);
        h.update(&self.authority_pubkey_commit);
        h.update(&(self.vault_ids.len() as u32).to_le_bytes());
        for v in &self.vault_ids {
            let b = v.as_bytes();
            h.update(&(b.len() as u32).to_le_bytes());
            h.update(b);
        }
        *h.finalize().as_bytes()
    }

    /// Verify end-to-end against a GENESIS-ANCHORED authority commitment (caller supplies it
    /// from the device's anchor + device-tree quorum). Fail-closed at every step.
    pub fn verify(&self, anchored_authority_commit: &[u8; 32]) -> Result<(), DsmError> {
        if self.authority_pubkey.is_empty() {
            return Err(DsmError::verification(
                "dbtc-vault-index: no authority_pubkey",
            ));
        }
        if compute_authority_pubkey_commit(&self.authority_pubkey) != self.authority_pubkey_commit {
            return Err(DsmError::verification(
                "dbtc-vault-index: authority_pubkey does not hash to authority_pubkey_commit",
            ));
        }
        if &self.authority_pubkey_commit != anchored_authority_commit {
            return Err(DsmError::verification(
                "dbtc-vault-index: authority_pubkey_commit != genesis-anchored authority commit",
            ));
        }
        if !sphincs_verify(&self.authority_pubkey, &self.digest(), &self.signature)? {
            return Err(DsmError::verification(
                "dbtc-vault-index: signature invalid under the anchored authority",
            ));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        PostedDbtcVaultIndexV1 {
            genesis_id: self.genesis_id.to_vec(),
            device_id: self.device_id.to_vec(),
            vault_ids: self.vault_ids.clone(),
            authority_pubkey_commit: self.authority_pubkey_commit.to_vec(),
            authority_pubkey: self.authority_pubkey.clone(),
            signature: self.signature.clone(),
        }
        .encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        let p = PostedDbtcVaultIndexV1::decode(bytes).map_err(|e| {
            DsmError::serialization_error(
                format!("PostedDbtcVaultIndex::from_bytes: {e}"),
                "PostedDbtcVaultIndex",
                None::<String>,
                Some(e),
            )
        })?;
        Ok(Self {
            genesis_id: fixed32(&p.genesis_id, "genesis_id")?,
            device_id: fixed32(&p.device_id, "device_id")?,
            vault_ids: p.vault_ids,
            authority_pubkey_commit: fixed32(
                &p.authority_pubkey_commit,
                "authority_pubkey_commit",
            )?,
            authority_pubkey: p.authority_pubkey,
            signature: p.signature,
        })
    }
}

/// Build + sign a dBTC vault index for `device_id` under `genesis_id`. `vault_ids` are
/// sorted+deduped for a canonical digest. `authority_sk`/`authority_pubkey` are the device's
/// genesis-anchored recovery-authority `K_A` keypair.
pub fn build_dbtc_vault_index(
    genesis_id: [u8; 32],
    device_id: [u8; 32],
    mut vault_ids: Vec<String>,
    authority_pubkey: &[u8],
    authority_sk: &[u8],
) -> Result<PostedDbtcVaultIndex, DsmError> {
    vault_ids.sort();
    vault_ids.dedup();
    let mut idx = PostedDbtcVaultIndex {
        genesis_id,
        device_id,
        vault_ids,
        authority_pubkey_commit: compute_authority_pubkey_commit(authority_pubkey),
        authority_pubkey: authority_pubkey.to_vec(),
        signature: Vec::new(),
    };
    idx.signature = sphincs_sign(authority_sk, &idx.digest())?;
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};

    fn anchored(pk: &[u8]) -> [u8; 32] {
        compute_authority_pubkey_commit(pk)
    }

    fn sample() -> (PostedDbtcVaultIndex, Vec<u8>) {
        let kp = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x42; 32]).expect("kp");
        let idx = build_dbtc_vault_index(
            [0x6E; 32],
            [0xA0; 32],
            // intentionally unsorted + duplicate → build canonicalizes.
            vec!["VAULTB".into(), "VAULTA".into(), "VAULTB".into()],
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("build");
        (idx, kp.public_key.clone())
    }

    #[test]
    fn build_canonicalizes_and_verifies() {
        let (idx, pk) = sample();
        assert_eq!(
            idx.vault_ids,
            vec!["VAULTA".to_string(), "VAULTB".to_string()]
        );
        idx.verify(&anchored(&pk)).expect("verify");
    }

    #[test]
    fn round_trips() {
        let (idx, _pk) = sample();
        let decoded = PostedDbtcVaultIndex::from_bytes(&idx.to_bytes()).expect("decode");
        assert_eq!(decoded, idx);
        assert_eq!(idx.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn rejects_wrong_anchored_commit() {
        let (idx, _pk) = sample();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).unwrap();
        assert!(idx.verify(&anchored(&other.public_key)).is_err());
    }

    #[test]
    fn rejects_carried_pubkey_not_matching_commit() {
        let (mut idx, pk) = sample();
        let other = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x99; 32]).unwrap();
        idx.authority_pubkey = other.public_key.clone();
        assert!(idx.verify(&anchored(&pk)).is_err());
    }

    #[test]
    fn rejects_tampered_vault_ids() {
        let (mut idx, pk) = sample();
        idx.vault_ids.push("VAULTC".into()); // digest no longer matches the signature
        assert!(idx.verify(&anchored(&pk)).is_err());
    }
}
