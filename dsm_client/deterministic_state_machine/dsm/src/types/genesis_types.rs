//! Genesis Types - DSM Genesis State Structures (binary-only digests).
//!
//! Deterministic, protobuf-first core types for Genesis state creation,
//! verification, and integrity checks. Canonical hashing uses BLAKE3 with
//! explicit domain separators. No hex/json/base64/serde anywhere.
//!
//! IMPORTANT: `created_at` is *non-canonical* and intentionally excluded from
//! the Genesis hash to preserve determinism and our "no wall clock in protocol"
//! rule. Treat it as UI/ops metadata only.

use std::collections::HashMap;

use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};

use crate::types::error::DsmError;

/// Fixed-length digest (BLAKE3).
pub type Digest32 = [u8; 32];

/// Sub-domain separators for intra-hash field isolation within `recompute_genesis_hash`.
/// These are fed as data delimiters inside an already domain-separated hasher
/// (`dsm_domain_hasher("DSM/genesis")`), preventing cross-field collisions.
const DOMAIN_KEYS: &[u8] = b"DSM/genesis/keys\0";
const DOMAIN_MPC: &[u8] = b"DSM/genesis/mpc\0";
const DOMAIN_DBRW: &[u8] = b"DSM/genesis/dbrw\0";

/// Genesis state structure
#[derive(Clone, Debug)]
pub struct GenesisState {
    /// Device ID that owns this Genesis state
    pub device_id: [u8; 32],
    /// Genesis hash (canonical BLAKE3 over canonical fields)
    pub genesis_hash: Digest32,
    /// MPC contributions used in Genesis creation
    pub mpc_contributions: Vec<MPCContribution>,
    /// DBRW proof for device binding
    pub dbrw_proof: DBRWProof,
    /// Public keys associated with this Genesis
    pub public_keys: GenesisPublicKeys,
    /// Non-canonical creation time (UI/ops only; NOT used in hashing)
    pub created_at: u64,
    /// Arbitrary metadata (UI/ops only; NOT used in hashing)
    pub metadata: HashMap<String, String>,
}

/// MPC contribution in Genesis creation
#[derive(Clone, Debug)]
pub struct MPCContribution {
    /// ID of the contributing party (storage node or client)
    pub contributor_id: String,
    /// Cryptographic contribution (32-byte digest)
    pub contribution_hash: Digest32,
    /// Signature over the contribution (verification handled upstream)
    pub signature: Vec<u8>,
    /// Non-canonical tick of contribution (UI/ops only)
    pub tick: u64,
}

/// DBRW (Dual-Binding Random Walk) proof
#[derive(Clone, Debug)]
pub struct DBRWProof {
    /// Device fingerprint used in DBRW (binds to hardware/TPM/TEE/etc.)
    pub device_fingerprint: Vec<u8>,
    /// Environmental state hash (`domain_hash("DSM/genesis/dbrw-env", proof_data)`)
    pub env_state_hash: Digest32,
    /// Raw random-walk proof bytes (large; not included directly in genesis hash)
    pub proof_data: Vec<u8>,
    /// DBRW verification hash (compact attestation result)
    pub verification_hash: Digest32,
}

/// Public keys in Genesis state
#[derive(Clone, Debug)]
pub struct GenesisPublicKeys {
    /// Signing public key (SPHINCS+)
    pub signing_key: Vec<u8>,
    /// Key encapsulation public key (Kyber/ML-KEM)
    pub encapsulation_key: Vec<u8>,
    /// Canonical hash of the key bundle (BLAKE3)
    pub key_hash: Digest32,
}

impl GenesisState {
    /// Create a new Genesis state (does NOT auto-compute `genesis_hash`).
    /// Call `recompute_genesis_hash()` and set it on the struct in your constructor flow.
    pub fn new(
        device_id: [u8; 32],
        genesis_hash: Digest32,
        mpc_contributions: Vec<MPCContribution>,
        dbrw_proof: DBRWProof,
        public_keys: GenesisPublicKeys,
        created_at: u64,
    ) -> Self {
        Self {
            device_id,
            genesis_hash,
            mpc_contributions,
            dbrw_proof,
            public_keys,
            created_at,
            metadata: HashMap::new(),
        }
    }

    /// Verify Genesis state integrity with deterministic rules only.
    ///
    /// Checks performed:
    /// - Non-empty MPC set and keys present
    /// - DBRW env hash matches proof_data
    /// - Key bundle hash matches `key_hash`
    /// - Canonical recomputed genesis hash equals stored `genesis_hash`
    ///
    /// Returns:
    /// - Ok(true)  => passes all checks
    /// - Ok(false) => any check fails (deterministic fail; no partial passes)
    pub fn verify_integrity(&self) -> Result<bool, DsmError> {
        // Basic presence checks
        if self.mpc_contributions.is_empty() {
            return Ok(false);
        }
        if self.public_keys.signing_key.is_empty() || self.public_keys.encapsulation_key.is_empty()
        {
            return Ok(false);
        }
        if self.dbrw_proof.device_fingerprint.is_empty() {
            return Ok(false);
        }

        // DBRW env hash must be domain-separated BLAKE3(proof_data)
        let env_calc = domain_hash("DSM/genesis/dbrw-env", &self.dbrw_proof.proof_data);
        if !ct_eq(env_calc.as_bytes(), &self.dbrw_proof.env_state_hash) {
            return Ok(false);
        }

        // Public key bundle hash must match
        let expected_key_hash = GenesisPublicKeys::compute_key_hash(
            &self.public_keys.signing_key,
            &self.public_keys.encapsulation_key,
        );
        if !ct_eq(&expected_key_hash, &self.public_keys.key_hash) {
            return Ok(false);
        }

        // Canonical Genesis hash must match
        let computed = self.recompute_genesis_hash()?;
        if !ct_eq(&computed, &self.genesis_hash) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Recompute the canonical Genesis hash (BLAKE3 -> 32 bytes).
    ///
    /// Canonical inputs (in order):
    /// - Domain prefix via `dsm_domain_hasher("DSM/genesis")`
    /// - device_id (UTF-8 bytes)
    /// - MPC contributions (sorted by `contribution_hash`, then contributor_id)
    ///   Each contribution folded as: DOMAIN_MPC || contribution_hash (32 bytes)
    /// - DBRW fold: DOMAIN_DBRW || device_fingerprint || verification_hash (32 bytes)
    /// - Keys fold: DOMAIN_KEYS || signing_key || encapsulation_key || key_hash (32 bytes)
    ///
    /// Excluded: `created_at`, `metadata`, `DBRW.proof_data`, `DBRW.env_state_hash`
    pub fn recompute_genesis_hash(&self) -> Result<Digest32, DsmError> {
        let mut h = dsm_domain_hasher("DSM/genesis");
        h.update(&self.device_id);

        // MPC contributions: deterministic order by (contribution_hash, contributor_id)
        let mut contributions = self.mpc_contributions.clone();
        contributions.sort_by(|a, b| {
            let hcmp = a.contribution_hash.cmp(&b.contribution_hash);
            if hcmp == std::cmp::Ordering::Equal {
                a.contributor_id.cmp(&b.contributor_id)
            } else {
                hcmp
            }
        });
        for c in &contributions {
            h.update(DOMAIN_MPC);
            h.update(&c.contribution_hash);
        }

        // DBRW (compact attestation only)
        h.update(DOMAIN_DBRW);
        h.update(&self.dbrw_proof.device_fingerprint);
        h.update(&self.dbrw_proof.verification_hash);

        // Keys (include key_hash for belt-and-suspenders binding)
        h.update(DOMAIN_KEYS);
        h.update(&self.public_keys.signing_key);
        h.update(&self.public_keys.encapsulation_key);
        h.update(&self.public_keys.key_hash);

        let digest = h.finalize();
        Ok(*digest.as_bytes())
    }
}

impl MPCContribution {
    /// Create a new MPC contribution (does not verify signature content here).
    pub fn new(
        contributor_id: String,
        contribution_hash: Digest32,
        signature: Vec<u8>,
        tick: u64,
    ) -> Self {
        Self {
            contributor_id,
            contribution_hash,
            signature,
            tick,
        }
    }
}

impl DBRWProof {
    /// Create a new DBRW proof. `env_state_hash` must equal `domain_hash("DSM/genesis/dbrw-env", proof_data)`.
    pub fn new(
        device_fingerprint: Vec<u8>,
        env_state_hash: Digest32,
        proof_data: Vec<u8>,
        verification_hash: Digest32,
    ) -> Self {
        Self {
            device_fingerprint,
            env_state_hash,
            proof_data,
            verification_hash,
        }
    }
}

impl GenesisPublicKeys {
    /// Create new Genesis public keys; computes and sets `key_hash` deterministically.
    pub fn new(signing_key: Vec<u8>, encapsulation_key: Vec<u8>) -> Self {
        let key_hash = Self::compute_key_hash(&signing_key, &encapsulation_key);
        Self {
            signing_key,
            encapsulation_key,
            key_hash,
        }
    }

    /// Deterministic key bundle hash (BLAKE3 -> 32 bytes).
    #[inline]
    pub fn compute_key_hash(signing_key: &[u8], encapsulation_key: &[u8]) -> Digest32 {
        let mut h = dsm_domain_hasher("DSM/genesis/keys");
        h.update(signing_key);
        h.update(encapsulation_key);
        *h.finalize().as_bytes()
    }
}

/// Constant-time byte equality (branchless XOR-accumulate).
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hash_is_stable() {
        let pk = GenesisPublicKeys::new(b"sign".to_vec(), b"kem".to_vec());
        let expected = GenesisPublicKeys::compute_key_hash(b"sign", b"kem");
        assert!(ct_eq(&pk.key_hash, &expected));
    }

    #[test]
    fn genesis_hash_excludes_created_at() {
        let keys = GenesisPublicKeys::new(b"S+".to_vec(), b"KEM".to_vec());

        let proof_data = b"walk".to_vec();
        let env = blake3::hash(&proof_data);
        let dbrw = DBRWProof::new(
            vec![1, 2, 3],
            *env.as_bytes(),
            proof_data,
            *blake3::hash(b"att").as_bytes(),
        );

        let mpc = vec![
            MPCContribution::new("n1".into(), *blake3::hash(b"aa").as_bytes(), vec![9], 0),
            MPCContribution::new("n2".into(), *blake3::hash(b"ab").as_bytes(), vec![9], 0),
        ];

        let device_id = blake3::hash(b"dev").into();

        let s1 = GenesisState::new(
            device_id,
            [0u8; 32],
            mpc.clone(),
            dbrw.clone(),
            keys.clone(),
            1,
        );
        let h1 = s1.recompute_genesis_hash().unwrap();

        let s2 = GenesisState::new(device_id, [0u8; 32], mpc, dbrw, keys, 9_999_999);
        let h2 = s2.recompute_genesis_hash().unwrap();

        assert!(ct_eq(&h1, &h2), "created_at must not affect canonical hash");
    }

    #[test]
    fn integrity_verifies_when_consistent() {
        use crate::crypto::blake3::domain_hash as dh;
        let keys = GenesisPublicKeys::new(b"S+".to_vec(), b"KEM".to_vec());
        let proof_data = b"walk".to_vec();
        let env_hash = *dh("DSM/genesis/dbrw-env", &proof_data).as_bytes();
        let dbrw = DBRWProof::new(
            vec![7, 7, 7],
            env_hash,
            proof_data,
            *blake3::hash(b"attest").as_bytes(),
        );
        let mpc = vec![
            MPCContribution::new("a".into(), *blake3::hash(b"01").as_bytes(), vec![1], 0),
            MPCContribution::new("b".into(), *blake3::hash(b"02").as_bytes(), vec![2], 0),
        ];

        let device_id = blake3::hash(b"devX").into();
        let mut gs = GenesisState::new(device_id, [0u8; 32], mpc, dbrw, keys, 0);
        let computed = gs.recompute_genesis_hash().unwrap();
        gs.genesis_hash = computed;

        assert!(gs.verify_integrity().unwrap());
    }
}
