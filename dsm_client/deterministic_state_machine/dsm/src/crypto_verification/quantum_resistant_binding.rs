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

/// Represents a quantum-resistant device binding attestation.
///
/// **Issue #185 Findings #1 + #4 resolution.** Earlier versions of this
/// struct omitted both `additional_entropy` (the freshness/challenge
/// nonce signed at attestation time) and authenticated coverage of
/// `encapsulated_state` from the signed payload. Without those, the
/// freshness challenge feature was unusable (verifier couldn't
/// reconstruct the signed message) and an attacker could swap the
/// Kyber ciphertext without invalidating the SPHINCS+ signature.
///
/// The signed payload now covers ALL of:
///   * `tick` (8 bytes BE)
///   * `device_hash`
///   * `additional_entropy` (length-prefixed)
///   * `encapsulated_state` (length-prefixed)
///
/// All four are stored on the struct so `verify_attestation` can
/// reconstruct the exact byte string the signer signed over.
#[derive(Debug, Clone)]
pub struct DeviceAttestation {
    /// Attestation tick (deterministic)
    pub tick: u64,
    /// Device identifier hash
    pub device_hash: HashOutput,
    /// SPHINCS+ signature over the canonical attestation message
    /// (see `serialize_attestation_message`).
    pub signature: Signature,
    /// Kyber encapsulated state (for secure communication). NOW signed.
    pub encapsulated_state: Vec<u8>,
    /// Additional freshness/challenge entropy passed to
    /// `create_attestation`. Stored here so the verifier can
    /// reconstruct the signed message; previously omitted, which made
    /// any non-empty challenge unverifiable (Issue #185 Finding #1).
    pub additional_entropy: Vec<u8>,
    /// Domain-separated digest of the attestation message, retained
    /// for backward-compatible callers that wanted a quick integrity
    /// check without re-running SPHINCS+ verify. NOT a substitute for
    /// signature verification.
    pub verification_entropy: HashOutput,
}

/// Serialize the canonical attestation message that gets signed (and
/// re-derived during verification). Length-prefixed to prevent any
/// ambiguity between the variable-length fields.
///
/// Layout:
///   "DSM/device-attestation\0"
///   || tick (8 bytes BE)
///   || device_hash (32 bytes)
///   || u32_be(additional_entropy.len()) || additional_entropy
///   || u32_be(encapsulated_state.len()) || encapsulated_state
fn serialize_attestation_message(
    tick: u64,
    device_hash: &HashOutput,
    additional_entropy: &[u8],
    encapsulated_state: &[u8],
) -> Vec<u8> {
    const TAG: &[u8] = b"DSM/device-attestation\0";
    let mut buf = Vec::with_capacity(
        TAG.len() + 8 + 32 + 4 + additional_entropy.len() + 4 + encapsulated_state.len(),
    );
    buf.extend_from_slice(TAG);
    buf.extend_from_slice(&tick.to_be_bytes());
    buf.extend_from_slice(device_hash.as_bytes());
    buf.extend_from_slice(&(additional_entropy.len() as u32).to_be_bytes());
    buf.extend_from_slice(additional_entropy);
    buf.extend_from_slice(&(encapsulated_state.len() as u32).to_be_bytes());
    buf.extend_from_slice(encapsulated_state);
    buf
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

        // Prepare encapsulated state using Kyber FIRST so it can be
        // included in the signed attestation message (Issue #185 F4).
        let self_encapsulation = kyber_keypair.encapsulate()?;
        let encapsulated_state = self_encapsulation.ciphertext.clone();

        // Build the canonical signed payload covering tick, device_hash,
        // additional_entropy (freshness challenge), AND encapsulated_state
        // (Issue #185 F1+F4).
        let attestation_data = serialize_attestation_message(
            tick,
            &self.device_hash,
            additional_entropy,
            &encapsulated_state,
        );

        // Verification-entropy digest retained for backward-compat
        // callers; the authoritative integrity check is the SPHINCS+
        // signature below.
        let verification_entropy = blake3(&attestation_data);

        // Sign the canonical attestation data using SPHINCS+
        let signature = sphincs_keypair.sign(&attestation_data)?;

        Ok(DeviceAttestation {
            tick,
            device_hash: self.device_hash,
            signature,
            encapsulated_state,
            additional_entropy: additional_entropy.to_vec(),
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
        // Verify device hash matches this binding's identity.
        if attestation.device_hash != self.device_hash {
            return Ok(false);
        }

        // Reconstruct the EXACT canonical attestation message the
        // signer signed. Now covers `additional_entropy` and
        // `encapsulated_state` from the stored fields (Issue #185
        // F1+F4).
        let attestation_data = serialize_attestation_message(
            attestation.tick,
            &attestation.device_hash,
            &attestation.additional_entropy,
            &attestation.encapsulated_state,
        );

        // Cross-check verification_entropy digest matches the
        // canonical message. Fail-fast for tampered structs before
        // burning a SPHINCS+ verify.
        let expected_verification = blake3(&attestation_data);
        if attestation.verification_entropy != expected_verification {
            return Ok(false);
        }

        // Authoritative check: SPHINCS+ verify under the supplied
        // public key. Because the signed bytes include
        // `additional_entropy` and `encapsulated_state`, any tampering
        // with either field rejects here.
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

    /// Issue #185 Finding #1 regression: an attestation created with
    /// non-empty `additional_entropy` MUST verify successfully. Before
    /// the fix, `verify_attestation` reconstructed the signed message
    /// without `additional_entropy`, so any non-empty challenge made
    /// verification fail unconditionally — the freshness/challenge
    /// feature was unusable.
    #[test]
    fn test_verify_attestation_succeeds_with_non_empty_challenge_entropy() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let challenge_nonce = b"freshness-nonce-from-verifier-12";
        let att = binding
            .create_attestation(&sphincs, &kyber, challenge_nonce)
            .unwrap();
        // Pre-fix this would fail; post-fix it must succeed because
        // `additional_entropy` is now stored on `att` and threaded into
        // the canonical signed-message reconstruction.
        let valid = binding
            .verify_attestation(&att, &sphincs.public_key)
            .unwrap();
        assert!(
            valid,
            "Issue #185 F1: attestation with non-empty challenge entropy must verify"
        );
        // Sanity: the entropy round-trips through the struct.
        assert_eq!(att.additional_entropy, challenge_nonce);
    }

    /// Issue #185 Finding #4 regression: tampering with
    /// `encapsulated_state` MUST invalidate the attestation. Before
    /// the fix, the Kyber ciphertext was carried in the struct but
    /// not covered by the SPHINCS+ signature, so an attacker could
    /// swap it without invalidating attestation.
    #[test]
    fn test_verify_attestation_rejects_encapsulated_state_tamper() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let mut att = binding
            .create_attestation(&sphincs, &kyber, b"any")
            .unwrap();

        // Replace the encapsulated_state with arbitrary bytes —
        // mirrors a MITM substitution.
        att.encapsulated_state = vec![0xAA; att.encapsulated_state.len()];

        let valid = binding
            .verify_attestation(&att, &sphincs.public_key)
            .unwrap();
        assert!(
            !valid,
            "Issue #185 F4: tampered encapsulated_state must invalidate attestation"
        );
    }

    /// Issue #185 Finding #1 regression (negative): tampering with the
    /// stored `additional_entropy` MUST invalidate the attestation,
    /// since it's now part of the signed canonical message.
    #[test]
    fn test_verify_attestation_rejects_additional_entropy_tamper() {
        let (sphincs, kyber) = make_keypairs();
        let binding = QuantumResistantBinding::new("app-1", b"seed", &sphincs, &kyber).unwrap();

        let mut att = binding
            .create_attestation(&sphincs, &kyber, b"original-nonce")
            .unwrap();

        att.additional_entropy = b"tampered-nonce".to_vec();

        let valid = binding
            .verify_attestation(&att, &sphincs.public_key)
            .unwrap();
        assert!(
            !valid,
            "Issue #185 F1: tampered additional_entropy must invalidate attestation"
        );
    }
}
