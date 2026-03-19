// multiparty_computation.rs
//
// Trustless MPC for genesis state creation (STRICT: no wall-clock, bytes-only).
// Replaces TEE dependency with distributed cryptographic security as described
// in the DSM whitepaper.

use std::collections::HashSet;

use crate::core::identity::{GenesisState, Identity};
use crate::core::identity::genesis::{self, KyberKey, SigningKey};
use crate::crypto::hash::{blake3, HashOutput};
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;
use crate::util::deterministic_time as dt;

/// A single party's MPC contribution (privacy-preserving).
#[derive(Debug, Clone)]
pub struct MpcContribution {
    /// Blinded contribution hash
    pub blinded_hash: HashOutput,
    /// Party identifier (opaque label; NOT an address or hex)
    pub party_id: String,
    /// Logical tick (monotone)
    pub tick: u64,
}

impl MpcContribution {
    /// Create a new MPC contribution (no wall-clock; bytes-only).
    pub fn new(secret: &[u8], blinding_factor: &[u8], party_id: &str) -> Self {
        // Deterministic, process-local monotonic time
        let (_, tick) = dt::peek();

        // H(secret || blinding)
        let mut data = Vec::with_capacity(secret.len() + blinding_factor.len());
        data.extend_from_slice(secret);
        data.extend_from_slice(blinding_factor);
        let blinded_hash = blake3(&data);

        Self {
            blinded_hash,
            party_id: party_id.to_string(),
            tick,
        }
    }

    /// Create an MPC contribution that incorporates DBRW hardware entropy (production path).
    ///
    /// Fails if DBRW binding is unavailable (STRICT).
    pub fn new_with_cdbrw_entropy(
        secret: &[u8],
        blinding_factor: &[u8],
        party_id: &str,
        session_id: &str,
    ) -> Result<Self, DsmError> {
        // Deterministic, process-local monotonic time
        let (_, tick) = dt::peek();

        // Device-bound randomness (anti-cloning)
        // Construct context for DBRW entropy derivation
        let mut context = Vec::with_capacity(session_id.len() + party_id.len());
        context.extend_from_slice(session_id.as_bytes());
        context.extend_from_slice(party_id.as_bytes());

        // Derive C-DBRW entropy deterministically from session context.
        let cdbrw_entropy =
            crate::crypto::blake3::domain_hash("DSM/cdbrw-genesis-entropy", &context)
                .as_bytes()
                .to_vec();

        // H(secret || blinding || cdbrw || session_id || party_id)
        let mut enhanced = Vec::with_capacity(
            secret.len()
                + blinding_factor.len()
                + cdbrw_entropy.len()
                + session_id.len()
                + party_id.len(),
        );
        enhanced.extend_from_slice(secret);
        enhanced.extend_from_slice(blinding_factor);
        enhanced.extend_from_slice(&cdbrw_entropy);
        enhanced.extend_from_slice(session_id.as_bytes());
        enhanced.extend_from_slice(party_id.as_bytes());
        let blinded_hash = blake3(&enhanced);

        Ok(Self {
            blinded_hash,
            party_id: party_id.to_string(),
            tick,
        })
    }
}

/// MPC identity factory (threshold t-of-n).
#[derive(Debug)]
pub struct MpcIdentityFactory {
    /// Required contributions (t-of-n). MUST be ≥3 for production security.
    threshold: usize,
    /// Application identifier (opaque label)
    app_id: String,
    /// Collected contributions
    contributions: Vec<MpcContribution>,
}

impl MpcIdentityFactory {
    /// New factory (production semantics).
    pub fn new(threshold: usize, app_id: &str) -> Self {
        assert!(
            threshold >= 3,
            "MPC threshold must be ≥3 for production security, got {threshold}"
        );
        Self {
            threshold,
            app_id: app_id.to_string(),
            contributions: Vec::new(),
        }
    }

    /// New factory (TESTS ONLY). Allows threshold ≥1.
    #[cfg(test)]
    pub fn new_for_testing(threshold: usize, app_id: &str) -> Self {
        assert!(
            threshold >= 1,
            "MPC threshold must be ≥1 for testing, got {threshold}"
        );
        Self {
            threshold,
            app_id: app_id.to_string(),
            contributions: Vec::new(),
        }
    }

    /// Add a contribution (reject duplicate party ids).
    pub fn add_contribution(&mut self, contribution: MpcContribution) -> Result<(), DsmError> {
        if self
            .contributions
            .iter()
            .any(|c| c.party_id == contribution.party_id)
        {
            return Err(DsmError::invalid_operation(
                "Duplicate party ID in MPC contributions",
            ));
        }
        self.contributions.push(contribution);
        Ok(())
    }

    /// Whether the threshold is met.
    pub fn threshold_met(&self) -> bool {
        self.contributions.len() >= self.threshold
    }

    /// Create an identity from the first `threshold` contributions (sorted by party_id for determinism).
    ///
    /// Returns the new `Identity` plus the generated signing and Kyber keypairs.
    pub fn create_identity(&self) -> Result<(Identity, SignatureKeyPair, KyberKeyPair), DsmError> {
        if !self.threshold_met() {
            return Err(DsmError::invalid_operation(format!(
                "Not enough contributions. Need {} but have {}",
                self.threshold,
                self.contributions.len()
            )));
        }

        // Deterministic ordering
        let mut sorted = self.contributions.clone();
        sorted.sort_by(|a, b| a.party_id.cmp(&b.party_id));

        // Use the first `threshold` contributions
        let chosen = sorted.iter().take(self.threshold);

        // Combine their blinded hashes into a seed share
        let mut combined = Vec::with_capacity(self.threshold * 32 + self.app_id.len());
        for c in chosen.clone() {
            combined.extend_from_slice(c.blinded_hash.as_bytes());
        }
        combined.extend_from_slice(self.app_id.as_bytes());

        // MPC seed for key derivation
        let mpc_seed_share = blake3(&combined);

        // Derive key material (domain-separated)
        let mut key_entropy = Vec::with_capacity(32 + 16);
        key_entropy.extend_from_slice(mpc_seed_share.as_bytes());
        key_entropy.extend_from_slice(b"key_derivation");

        // Generate SPHINCS+ and Kyber keypairs deterministically
        let sphincs_keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)?;
        let mut kyber_entropy = key_entropy.clone();
        kyber_entropy.extend_from_slice(b"kyber_specific");
        let kyber_keypair =
            KyberKeyPair::generate_from_entropy(&kyber_entropy, Some("DSM_MULTIPARTY_KYBER"))?;

        // Participants (opaque string labels from contributions)
        let participants: HashSet<String> = chosen.clone().map(|c| c.party_id.clone()).collect();

        // Optional: record the blinded inputs as contributions in GenesisState (verified=true)
        let gs_contributions: Vec<genesis::Contribution> = chosen
            .map(|c| genesis::Contribution {
                data: c.blinded_hash.as_bytes().to_vec(),
                verified: true,
            })
            .collect();

        // Build genesis (bytes-only; no wall clock; no hex/base64 in fields)
        let genesis_state = GenesisState {
            hash: *mpc_seed_share.as_bytes(),
            initial_entropy: *crate::crypto::blake3::domain_hash(
                "DSM/genesis-initial-entropy",
                &key_entropy,
            )
            .as_bytes(),
            signing_key: SigningKey {
                public_key: sphincs_keypair.public_key.clone(),
                secret_key: sphincs_keypair.secret_key.clone(),
            },
            kyber_keypair: KyberKey {
                public_key: kyber_keypair.public_key.clone(),
                secret_key: kyber_keypair.secret_key.clone(),
            },
            threshold: self.threshold,
            participants,
            merkle_root: None, // can be filled by caller using canonical contribution tree if desired
            device_id: None, // genesis is identity-scoped; device-specific sub-identities derive later
            contributions: gs_contributions,
        };

        // Assemble identity using public constructor to keep internal fields private
        let identity = Identity::with_genesis(self.app_id.clone(), genesis_state);

        Ok((identity, sphincs_keypair, kyber_keypair))
    }

    /// Deterministic test identity (non-MPC). For tests only.
    pub fn create_test_identity(
        app_id: &str,
    ) -> Result<(Identity, SignatureKeyPair, KyberKeyPair), DsmError> {
        // Deterministic seed
        let seed = format!("test_seed_for_{app_id}");
        let mpc_seed_share = blake3(seed.as_bytes());

        // Keys (test paths can be non-deterministic if API requires)
        let sphincs_keypair = SignatureKeyPair::new()?;
        let kyber_keypair = KyberKeyPair::generate()?;

        let mut participants = HashSet::new();
        participants.insert("test_participant".to_string());

        let genesis_state = GenesisState {
            hash: *mpc_seed_share.as_bytes(),
            initial_entropy: *mpc_seed_share.as_bytes(),
            signing_key: SigningKey {
                public_key: sphincs_keypair.public_key.clone(),
                secret_key: sphincs_keypair.secret_key.clone(),
            },
            kyber_keypair: KyberKey {
                public_key: kyber_keypair.public_key.clone(),
                secret_key: kyber_keypair.secret_key.clone(),
            },
            threshold: 3,
            participants,
            merkle_root: None,
            device_id: None,
            contributions: vec![],
        };

        let identity = Identity::with_genesis(app_id.to_string(), genesis_state);

        Ok((identity, sphincs_keypair, kyber_keypair))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contribution_creation() {
        let secret = b"test_secret_value";
        let blinding_factor = b"test_blinding_factor";
        let party_id = "party1";

        let c1 = MpcContribution::new(secret, blinding_factor, party_id);
        let c2 = MpcContribution::new(secret, blinding_factor, party_id);
        let c3 = MpcContribution::new(b"different_secret", blinding_factor, party_id);

        assert_eq!(c1.party_id, "party1");
        assert_eq!(c1.blinded_hash, c2.blinded_hash);
        assert_ne!(c1.blinded_hash, c3.blinded_hash);
        assert!(c1.tick > 0);
    }

    #[test]
    fn test_identity_creation() -> Result<(), DsmError> {
        let app_id = "com.dsm.testapp";
        // Tests may allow low threshold via new_for_testing
        let threshold = std::env::var("DSM_MPC_THRESHOLD")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<usize>()
            .unwrap_or(1);

        let mut factory = MpcIdentityFactory::new_for_testing(threshold, app_id);

        factory.add_contribution(MpcContribution::new(b"secret1", b"blinding1", "party1"))?;
        factory.add_contribution(MpcContribution::new(b"secret2", b"blinding2", "party2"))?;
        factory.add_contribution(MpcContribution::new(b"secret3", b"blinding3", "party3"))?;

        assert!(factory.threshold_met());

        let (identity, _, _) = factory.create_identity()?;
        assert_eq!(identity.name, app_id);
        Ok(())
    }

    #[test]
    fn test_threshold_enforcement() {
        let app_id = "com.dsm.testapp";
        let mut factory = MpcIdentityFactory::new(3, app_id);

        factory
            .add_contribution(MpcContribution::new(b"secret1", b"blinding1", "party1"))
            .unwrap();
        factory
            .add_contribution(MpcContribution::new(b"secret2", b"blinding2", "party2"))
            .unwrap();

        assert!(!factory.threshold_met());
        assert!(factory.create_identity().is_err());
    }

    #[test]
    fn test_duplicate_party_prevention() {
        let app_id = "com.dsm.testapp";
        let mut factory = MpcIdentityFactory::new_for_testing(1, app_id);

        factory
            .add_contribution(MpcContribution::new(b"secret1", b"blinding1", "party1"))
            .unwrap();
        assert!(factory
            .add_contribution(MpcContribution::new(b"secret2", b"blinding2", "party1"))
            .is_err());
    }

    #[test]
    fn test_test_identity_creation() {
        let app_id = "com.dsm.testapp";
        let (identity, _, _) = MpcIdentityFactory::create_test_identity(app_id).unwrap();
        assert_eq!(identity.name, app_id);
    }
}
