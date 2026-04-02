// dsm/src/crypto/signatures.rs
//! Enhanced signature implementation using pure cryptographic guarantees,
//! wrapping the BLAKE3-only SPHINCS+ engine in `crate::crypto::sphincs`.
//!
//! - Protobuf-only (no JSON/base64 transports in this layer).
//! - Clockless (no wall-clock markers; ordering is not time-based).
//! - Default parameter set: SPX256s (robust, future-proof).
//!
//! Public API surface (stable):
//!     - struct SignatureKeyPair { public_key, secret_key, params }
//!     - type Signature = `Vec<u8>`
//!     - free fns: sign_message, sign_message_with_params,
//!                 verify_message, verify_message_with_params, verify_signature
//!
//! Internally delegates to:
//!   sphincs::{generate_keypair, generate_keypair_from_seed, sign, verify}

use crate::crypto::sphincs;
pub use crate::crypto::sphincs::SphincsVariant as ParameterSet;

use crate::types::error::DsmError;
use zeroize::Zeroize;

/// SPX256s: 256-bit post-quantum security (29,792 byte signatures).
/// BLE bilateral transfers compress the envelope before chunking to reduce
/// the chunk count from 168 to ~50-60 for acceptable transfer times.
const DEFAULT_PARAMS: ParameterSet = ParameterSet::SPX256s;

/// Signature bytes alias
pub type Signature = Vec<u8>;

/// Quantum-resistant SPHINCS+ key pair for DSM signatures
#[derive(Debug, Clone, Zeroize)]
pub struct SignatureKeyPair {
    /// Public key for signature verification (pub_seed || root)
    pub public_key: Vec<u8>,
    /// Secret key for signature creation (sk_seed || sk_prf || pub_seed || root)
    pub secret_key: Vec<u8>,
    /// Parameter set used to produce this keypair (non-sensitive)
    pub params: ParameterSet,
}

impl Drop for SignatureKeyPair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl SignatureKeyPair {
    /// Generate a new SPHINCS+ key pair with the default DSM parameter set.
    pub fn new() -> Result<Self, DsmError> {
        Self::generate_with_params(DEFAULT_PARAMS)
    }

    /// Generate a new SPHINCS+ key pair for a chosen parameter set.
    pub fn generate_with_params(params: ParameterSet) -> Result<Self, DsmError> {
        let kp = sphincs::generate_keypair(params)?;
        Ok(Self {
            public_key: kp.public_key.clone(),
            secret_key: kp.secret_key.clone(),
            params,
        })
    }

    /// Deterministic keypair generation from caller entropy (default params).
    pub fn generate_from_entropy(entropy: &[u8]) -> Result<Self, DsmError> {
        Self::generate_from_entropy_with_params(entropy, DEFAULT_PARAMS)
    }

    /// Deterministic keypair generation from caller entropy (explicit params).
    pub fn generate_from_entropy_with_params(
        entropy: &[u8],
        params: ParameterSet,
    ) -> Result<Self, DsmError> {
        if entropy.is_empty() {
            return Err(DsmError::crypto(
                "Entropy must not be empty.",
                None::<std::io::Error>,
            ));
        }
        // Derive a fixed 32-byte seed deterministically.
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(
            crate::crypto::blake3::domain_hash("DSM/sphincs-seed", entropy).as_bytes(),
        );
        let kp = sphincs::generate_keypair_from_seed(params, &seed32)?;
        Ok(Self {
            public_key: kp.public_key.clone(),
            secret_key: kp.secret_key.clone(),
            params,
        })
    }

    /// Sign arbitrary data using SPHINCS+ (uses this key's params).
    pub fn sign(&self, data: &[u8]) -> Result<Signature, DsmError> {
        self.sign_with_params(data, self.params)
    }

    /// Sign arbitrary data using explicit parameter set.
    pub fn sign_with_params(
        &self,
        data: &[u8],
        params: ParameterSet,
    ) -> Result<Signature, DsmError> {
        if data.is_empty() {
            return Err(DsmError::crypto(
                "Data to sign cannot be empty.",
                None::<std::io::Error>,
            ));
        }
        sphincs::sign(params, &self.secret_key, data)
    }

    /// Verify a signature against provided data (uses this key's params).
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool, DsmError> {
        self.verify_with_params(data, signature, self.params)
    }

    /// Verify a signature using explicit parameter set.
    pub fn verify_with_params(
        &self,
        data: &[u8],
        signature: &Signature,
        params: ParameterSet,
    ) -> Result<bool, DsmError> {
        if data.is_empty() || signature.is_empty() {
            return Err(DsmError::crypto(
                "Data and signature cannot be empty.",
                None::<std::io::Error>,
            ));
        }
        sphincs::verify(params, &self.public_key, data, signature)
    }

    /// Convenience accessor
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Test-only convenience: generate a keypair quickly for unit tests and the `testing` feature.
    #[cfg(any(test, feature = "testing"))]
    pub fn generate_for_testing() -> Result<Self, DsmError> {
        Self::new()
    }

    /// Back-compat: static-style verifier matching historical call sites.
    pub fn verify_raw(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        super::verify_signature(public_key, message, signature)
    }
}

/* -------------------------------------------------------------------------
 * Canonical free-function wrappers.
 * These intentionally have no `self` receiver; they are pure functions.
 * ----------------------------------------------------------------------*/

/// Sign a message with a raw secret key (default params).
pub fn sign_message(secret_key: &[u8], message: &[u8]) -> Result<Signature, DsmError> {
    sign_message_with_params(secret_key, message, DEFAULT_PARAMS)
}

/// Sign a message with explicit parameter set.
pub fn sign_message_with_params(
    secret_key: &[u8],
    message: &[u8],
    params: ParameterSet,
) -> Result<Signature, DsmError> {
    if message.is_empty() {
        return Err(DsmError::crypto(
            "Data to sign cannot be empty.",
            None::<std::io::Error>,
        ));
    }
    sphincs::sign(params, secret_key, message)
}

/// Verify a message with a raw public key (default params).
pub fn verify_message(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, DsmError> {
    verify_message_with_params(public_key, message, signature, DEFAULT_PARAMS)
}

/// Verify a message with explicit parameter set.
pub fn verify_message_with_params(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    params: ParameterSet,
) -> Result<bool, DsmError> {
    if message.is_empty() || signature.is_empty() || public_key.is_empty() {
        return Err(DsmError::crypto(
            "Data, signature, and public key must not be empty.",
            None::<std::io::Error>,
        ));
    }
    sphincs::verify(params, public_key, message, signature)
}

/// Alias retained for convenience in call sites that say `verify_signature(...)`.
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, DsmError> {
    verify_message(public_key, message, signature)
}

/// Back-compat helper used across modules: verify a raw message/signature with a raw public key.
/// Order of arguments mirrors historical call sites.
pub fn verify_raw(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, DsmError> {
    verify_signature(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params_fast() -> ParameterSet {
        if cfg!(debug_assertions) {
            ParameterSet::SPX128s
        } else {
            ParameterSet::SPX256s
        }
    }

    fn test_keypair_fast() -> SignatureKeyPair {
        SignatureKeyPair::generate_with_params(test_params_fast()).expect("keygen")
    }
    use crate::crypto::sphincs;

    #[test]
    fn verify_with_empty_public_key_fails() {
        let kp = SignatureKeyPair::new().expect("keygen");
        let msg = b"test message";
        let sig = kp.sign(msg).expect("sign");
        let result = verify_message(&[], msg, &sig);
        assert!(result.is_err(), "Empty public key should error");
    }

    #[test]
    fn sign_with_empty_secret_key_fails() {
        let msg = b"test message";
        let result = sign_message(&[], msg);
        assert!(result.is_err(), "Empty secret key should error");
    }

    #[test]
    fn verify_with_truncated_signature_fails() {
        let kp = SignatureKeyPair::new().expect("keygen");
        let msg = b"test message";
        let sig = kp.sign(msg).expect("sign");
        let truncated_vec = sig[..sig.len() / 2].to_vec();
        let result = kp.verify(msg, &truncated_vec);
        assert!(
            result.is_err() || !result.unwrap(),
            "Truncated signature should fail"
        );
    }

    #[test]
    fn verify_with_corrupted_signature_fails() {
        let kp = test_keypair_fast();
        let msg = b"test message";
        let mut sig = kp.sign(msg).expect("sign");
        if let Some(b) = sig.get_mut(0) {
            *b ^= 0xFF;
        }
        let result = kp.verify(msg, &sig);
        assert!(
            result.is_ok() && !result.unwrap(),
            "Corrupted signature should not verify"
        );
    }

    #[test]
    fn serialization_roundtrip() {
        let kp = test_keypair_fast();
        let msg = b"serialize me";
        let sig = kp.sign(msg).expect("sign");
        // Simulate serialization/deserialization (just clone for Vec<u8>)
        let sig2: Vec<u8> = sig.clone();
        let ok = kp.verify(msg, &sig2).expect("verify");
        assert!(ok);
    }

    #[test]
    fn cross_param_sign_verify_fails() {
        let kp1 = SignatureKeyPair::generate_with_params(ParameterSet::SPX128s).expect("gen1");
        let kp2 = SignatureKeyPair::generate_with_params(ParameterSet::SPX256s).expect("gen2");
        let msg = b"cross param";
        let sig1 = kp1.sign(msg).expect("sign1");
        let ok = kp2.verify(msg, &sig1);
        assert!(
            ok.is_ok() && !ok.unwrap(),
            "Signature from different param set should not verify"
        );
    }

    #[test]
    fn keypair_roundtrip_default() {
        let kp = SignatureKeyPair::new().expect("keygen");
        let msg = b"DSM signatures sanity check";
        let sig = kp.sign(msg).expect("sign");
        let ok = kp.verify(msg, &sig).expect("verify");
        assert!(ok);
    }

    #[test]
    fn deterministic_keypair_generation_all_params() {
        let ent = b"strong entropy source";
        let sets: &[ParameterSet] = if cfg!(debug_assertions) {
            &[ParameterSet::SPX128s, ParameterSet::SPX256s]
        } else {
            &[
                ParameterSet::SPX128s,
                ParameterSet::SPX128f,
                ParameterSet::SPX192s,
                ParameterSet::SPX192f,
                ParameterSet::SPX256s,
                ParameterSet::SPX256f,
            ]
        };
        for &p in sets {
            let kp1 = SignatureKeyPair::generate_from_entropy_with_params(ent, p).expect("det kp1");
            let kp2 = SignatureKeyPair::generate_from_entropy_with_params(ent, p).expect("det kp2");
            assert_eq!(kp1.public_key, kp2.public_key);
            assert_eq!(kp1.secret_key, kp2.secret_key);
        }
    }

    #[test]
    fn free_function_wrappers_default() {
        let kp = SignatureKeyPair::new().expect("gen");
        let msg = b"wrapper test";
        let sig = sign_message(&kp.secret_key, msg).expect("sign");
        let ok = verify_message(&kp.public_key, msg, &sig).expect("verify");
        assert!(ok);
    }

    #[test]
    fn free_function_wrappers_explicit_params() {
        let params = ParameterSet::SPX192s;
        let kp = SignatureKeyPair::generate_with_params(params).expect("gen");
        let msg = b"wrapper explicit params";
        let sig = sign_message_with_params(&kp.secret_key, msg, params).expect("sign");
        let ok = verify_message_with_params(&kp.public_key, msg, &sig, params).expect("verify");
        assert!(ok);
    }

    #[test]
    fn deterministic_entropy_rejects_empty() {
        let err = SignatureKeyPair::generate_from_entropy(b"").err();
        assert!(err.is_some(), "empty entropy must be rejected");
    }

    #[test]
    fn sign_empty_message_rejected() {
        let kp = test_keypair_fast();
        let err = kp.sign(b"").err();
        assert!(err.is_some(), "signing empty message must error");
    }

    #[test]
    fn key_sizes_match_param_helpers() {
        let sets: &[ParameterSet] = if cfg!(debug_assertions) {
            &[ParameterSet::SPX128s, ParameterSet::SPX256s]
        } else {
            &[
                ParameterSet::SPX128s,
                ParameterSet::SPX128f,
                ParameterSet::SPX192s,
                ParameterSet::SPX192f,
                ParameterSet::SPX256s,
                ParameterSet::SPX256f,
            ]
        };
        for &p in sets {
            let kp = SignatureKeyPair::generate_with_params(p).expect("gen");
            assert_eq!(kp.public_key.len(), sphincs::public_key_bytes(p));
            assert_eq!(kp.secret_key.len(), sphincs::secret_key_bytes(p));
            // basic sign/verify to ensure keys are usable
            let msg = b"size check message";
            let sig = kp.sign_with_params(msg, p).expect("sign");
            assert_eq!(sig.len(), sphincs::signature_bytes(p));
            let ok = kp.verify_with_params(msg, &sig, p).expect("verify");
            assert!(ok);
        }
    }

    #[test]
    fn cross_variant_verification_fails() {
        let signer_params = ParameterSet::SPX256s;
        let kp = SignatureKeyPair::generate_with_params(signer_params).expect("gen");
        let msg = b"cross variant test";
        let sig = kp.sign(msg).expect("sign");
        // Try verifying with a different parameter set
        let verify_params = ParameterSet::SPX192s;
        let ok = kp
            .verify_with_params(msg, &sig, verify_params)
            .expect("verify call should succeed but return false");
        assert!(!ok, "verification with different params must fail");
    }
}
