// quantum_resistant_binding.rs
//
// Implementation of quantum-resistant device binding without hardware-specific features,
// using pure cryptographic guarantees as described in the DSM whitepaper.

use crate::crypto::hash::{blake3, HashOutput};
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::signatures::{Signature, SignatureKeyPair};
use crate::types::error::DsmError;
use crate::utils::time; // tick-based deterministic time

#[inline]
fn now_tick() -> u64 {
    time::now()
}

#[inline]
#[allow(dead_code)]
fn elapsed_ticks_since(start_tick: u64) -> u64 {
    now_tick().saturating_sub(start_tick)
}

/// Represents a quantum-resistant device binding attestation
#[derive(Debug, Clone)]
pub struct DeviceAttestation {
    /// Attestation tick (deterministic)
    pub tick: u64,
    /// Device identifier hash
    pub device_hash: HashOutput,
    /// SPHINCS+ signature over attestation data
    pub signature: Signature,
    /// Kyber encapsulated state (for secure communication)
    pub encapsulated_state: Vec<u8>,
    /// Additional entropy for verification
    pub verification_entropy: HashOutput,
}

/// Quantum-resistant device binding mechanism
#[derive(Debug)]
pub struct QuantumResistantBinding {
    /// Device identifier
    device_hash: HashOutput,
    /// SPHINCS+ public key for signatures
    sphincs_public_key: Vec<u8>,
    /// Kyber public key for key encapsulation
    kyber_public_key: Vec<u8>,
    /// Application identifier
    app_id: String,
    /// Device-specific salt
    device_salt: Vec<u8>,
}

impl QuantumResistantBinding {
    /// Create a new quantum-resistant device binding
    ///
    /// This implements the hardware binding approach described in whitepaper Section 25.1,
    /// using post-quantum cryptography instead of hardware-specific features.
    ///
    /// # Arguments
    /// * `app_id` - Application identifier
    /// * `mpc_seed_share` - Multi-party computation seed share
    /// * `sphincs_keypair` - SPHINCS+ keypair for signatures
    /// * `kyber_keypair` - Kyber keypair for key encapsulation
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - New binding or error
    pub fn new(
        app_id: &str,
        mpc_seed_share: &[u8],
        sphincs_keypair: &SignatureKeyPair,
        kyber_keypair: &KyberKeyPair,
    ) -> Result<Self, DsmError> {
        // Generate device-specific salt
        let device_salt = Self::generate_device_salt();

        // Calculate device hash from inputs
        let mut device_data = Vec::new();
        device_data.extend_from_slice(mpc_seed_share);
        device_data.extend_from_slice(app_id.as_bytes());
        device_data.extend_from_slice(&device_salt);

        let device_hash = blake3(&device_data);

        Ok(Self {
            device_hash,
            sphincs_public_key: sphincs_keypair.public_key.clone(),
            kyber_public_key: kyber_keypair.public_key.clone(),
            app_id: app_id.to_string(),
            device_salt,
        })
    }
    /// Generate device-specific salt for uniqueness
    ///
    /// # Returns
    /// * `Vec<u8>` - Device salt
    fn generate_device_salt() -> Vec<u8> {
        // Use runtime characteristics that are unique to the device
        let mut salt_data = Vec::new();

        // Add tick for entropy (deterministic)
        let tick = now_tick();
        salt_data.extend_from_slice(&tick.to_be_bytes());

        // Add process and thread IDs
        let pid = std::process::id();
        salt_data.extend_from_slice(&pid.to_be_bytes());

        // Add random entropy
        let mut random_bytes = [0u8; 32];
        getrandom::fill(&mut random_bytes).unwrap_or_default();
        salt_data.extend_from_slice(&random_bytes);

        // Hash everything together for the final salt
        blake3(&salt_data).as_bytes().to_vec()
    }

    /// Create an attestation to prove device authenticity
    ///
    /// This implements the attestation mechanism described in whitepaper Section 25.2,
    /// providing cryptographic proof of device authenticity without TEE dependencies.
    ///
    /// # Arguments
    /// * `sphincs_keypair` - SPHINCS+ keypair for signing
    /// * `kyber_keypair` - Kyber keypair for key encapsulation
    /// * `additional_entropy` - Extra entropy for attestation
    ///
    /// # Returns
    /// * `Result<DeviceAttestation, DsmError>` - Attestation or error
    pub fn create_attestation(
        &self,
        sphincs_keypair: &SignatureKeyPair,
        kyber_keypair: &KyberKeyPair,
        additional_entropy: &[u8],
    ) -> Result<DeviceAttestation, DsmError> {
        // Get current tick
        let tick = now_tick();

        // Create attestation data
        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(&tick.to_be_bytes());
        attestation_data.extend_from_slice(self.device_hash.as_bytes());
        attestation_data.extend_from_slice(additional_entropy);

        // Create verification entropy
        let verification_entropy = blake3(&attestation_data);

        // Sign the attestation data using SPHINCS+
        let signature = sphincs_keypair.sign(&attestation_data)?;

        // Prepare encapsulated state using Kyber
        let self_encapsulation = kyber_keypair.encapsulate()?;
        // Clone the ciphertext rather than moving it out of the structure
        let encapsulated_state = self_encapsulation.ciphertext.clone();

        Ok(DeviceAttestation {
            tick,
            device_hash: self.device_hash,
            signature,
            encapsulated_state,
            verification_entropy,
        })
    }

    /// Verify an attestation for device authenticity
    ///
    /// # Arguments
    /// * `attestation` - Attestation to verify
    /// * `public_key` - SPHINCS+ public key
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether attestation is valid
    pub fn verify_attestation(
        &self,
        attestation: &DeviceAttestation,
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        // Verify device hash
        if attestation.device_hash != self.device_hash {
            return Ok(false);
        }

        // Rebuild attestation data
        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(&attestation.tick.to_be_bytes());
        attestation_data.extend_from_slice(attestation.device_hash.as_bytes());

        // Derive expected verification entropy
        let expected_verification = blake3(&attestation_data);

        // Verify entropy matches
        if attestation.verification_entropy != expected_verification {
            return Ok(false);
        }

        // Verify signature using SPHINCS+ (construct a transient verifier with provided public key)
        let mut verifier = SignatureKeyPair::new()?;
        verifier.public_key = public_key.to_vec();
        verifier.verify(&attestation_data, &attestation.signature)
    }

    /// Verify that this binding matches expected parameters
    ///
    /// # Arguments
    /// * `app_id` - Expected application ID
    /// * `mpc_seed_share` - Expected MPC seed share
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether verification passed
    pub fn verify(&self, app_id: &str, mpc_seed_share: &[u8]) -> Result<bool, DsmError> {
        // Calculate expected device hash
        let mut device_data = Vec::new();
        device_data.extend_from_slice(mpc_seed_share);
        device_data.extend_from_slice(app_id.as_bytes());
        device_data.extend_from_slice(&self.device_salt);

        let expected_device_hash = blake3(&device_data);

        // Check device hash matches
        if self.device_hash != expected_device_hash {
            return Ok(false);
        }

        // Check app ID matches
        if self.app_id != app_id {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the device hash
    ///
    /// # Returns
    /// * `HashOutput` - Device hash
    pub fn device_hash(&self) -> &HashOutput {
        &self.device_hash
    }

    /// Get the genesis hash derived from public keys
    ///
    /// # Returns
    /// * `HashOutput` - Genesis hash
    pub fn genesis_hash(&self) -> HashOutput {
        let mut genesis_data = Vec::new();
        genesis_data.extend_from_slice(&self.kyber_public_key);
        genesis_data.extend_from_slice(&self.sphincs_public_key);

        blake3(&genesis_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kyber::generate_kyber_keypair;

    fn make_keypairs() -> (SignatureKeyPair, KyberKeyPair) {
        let sphincs = SignatureKeyPair::new().unwrap();
        let kyber = generate_kyber_keypair().unwrap();
        (sphincs, kyber)
    }

    #[test]
    fn test_binding_creation_succeeds() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed-share", &sphincs, &kyber);
        assert!(binding.is_ok());
    }

    #[test]
    fn test_device_hash_is_deterministic_for_instance() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();
        let h1 = *binding.device_hash();
        let h2 = *binding.device_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_verify_with_correct_params() {
        let (sphincs, kyber) = make_keypairs();
        let binding =
            QuantumResistantBinding::new("app-1", b"seed-share", &sphincs, &kyber).unwrap();

        let valid = binding.verify("app-1", b"seed-share").unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_with_wrong_app_id_fails() {
        let (sphincs, kyber) = make_keypairs();
        let binding =
            QuantumResistantBinding::new("app-1", b"seed-share", &sphincs, &kyber).unwrap();

        let valid = binding.verify("app-WRONG", b"seed-share").unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_with_wrong_seed_fails() {
        let (sphincs, kyber) = make_keypairs();
        let binding =
            QuantumResistantBinding::new("app-1", b"seed-share", &sphincs, &kyber).unwrap();

        let valid = binding.verify("app-1", b"wrong-seed").unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_genesis_hash_differs_for_different_keys() {
        let (sphincs1, kyber1) = make_keypairs();
        let (sphincs2, kyber2) = make_keypairs();

        let b1 = QuantumResistantBinding::new("app", b"seed", &sphincs1, &kyber1).unwrap();
        let b2 = QuantumResistantBinding::new("app", b"seed", &sphincs2, &kyber2).unwrap();

        assert_ne!(b1.genesis_hash(), b2.genesis_hash());
    }

    #[test]
    fn test_create_attestation_succeeds() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let attestation = binding.create_attestation(&sphincs, &kyber, b"entropy");
        assert!(attestation.is_ok());
        let att = attestation.unwrap();
        assert_eq!(att.device_hash, *binding.device_hash());
        assert!(!att.encapsulated_state.is_empty());
        assert!(!att.signature.is_empty());
    }

    #[test]
    fn test_verify_own_attestation() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let att = binding.create_attestation(&sphincs, &kyber, b"").unwrap();
        let valid = binding
            .verify_attestation(&att, &sphincs.public_key)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_attestation_wrong_device_hash() {
        let (sphincs1, kyber1) = make_keypairs();
        let (sphincs2, kyber2) = make_keypairs();

        let binding1 = QuantumResistantBinding::new("app", b"s1", &sphincs1, &kyber1).unwrap();
        let binding2 = QuantumResistantBinding::new("app", b"s2", &sphincs2, &kyber2).unwrap();

        let att = binding1
            .create_attestation(&sphincs1, &kyber1, b"")
            .unwrap();
        let valid = binding2
            .verify_attestation(&att, &sphincs1.public_key)
            .unwrap();
        assert!(
            !valid,
            "attestation from a different binding should fail device hash check"
        );
    }

    #[test]
    fn test_different_entropy_produces_different_verification_entropy() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let att1 = binding
            .create_attestation(&sphincs, &kyber, b"entropy-A")
            .unwrap();
        let att2 = binding
            .create_attestation(&sphincs, &kyber, b"entropy-B")
            .unwrap();

        assert_ne!(att1.verification_entropy, att2.verification_entropy);
    }
}
