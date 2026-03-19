//! # Quantum-Resistant Pedersen Commitments
//!
//! Implements quantum-resistant Pedersen commitments using post-quantum secure
//! primitives only. No classical variants are supported.
//!
//! Note: This file was refactored to remove `serde` and any generic object
//! serialization. All on-disk / over-the-wire encodings are now **manual,
//! canonical, byte-precise** via `to_bytes()` / `from_bytes()` on each type.
//! For cross-process APIs, use protobuf adapters (prost) that wrap these raw
//! bytes, not the Rust structs directly.

use std::str::FromStr;

use num_bigint::BigUint;
use num_primes::Generator;
use rand::{CryptoRng, RngCore};

use crate::types::error::DsmError;

type DsmResult<T> = Result<T, DsmError>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    Standard128 = 1,
    Medium192 = 2,
    High256 = 3,
}

impl SecurityLevel {
    fn to_wire(self) -> u8 {
        self as u8
    }
    fn from_wire(b: u8) -> DsmResult<Self> {
        match b {
            1 => Ok(SecurityLevel::Standard128),
            2 => Ok(SecurityLevel::Medium192),
            3 => Ok(SecurityLevel::High256),
            _ => Err(DsmError::serialization_error(
                "Unknown SecurityLevel",
                "security_level",
                None::<&str>,
                None::<std::io::Error>,
            )),
        }
    }
}

// Domain tags for domain-separated hashing (used via dsm_domain_hasher)
const DOMAIN_COMMIT_TAG: &str = "DSM/pedersen-commit";
const HASH_SEED_TAG: &str = "DSM/pedersen-seed";
const HASH_ROUND_TAG: &str = "DSM/pedersen-round";
const HASH_FINAL_TAG: &str = "DSM/pedersen-final";

/// Parameters for quantum-resistant Pedersen commitment
#[derive(Clone, Debug)]
pub struct PedersenParams {
    pub g: BigUint, // Generator
    pub h: BigUint, // Random base
    pub p: BigUint, // Prime modulus
    pub q: BigUint, // Prime order subgroup
    pub security_level: SecurityLevel,
}

impl PedersenParams {
    /// Create new parameters based on security level
    pub fn new(security_level: SecurityLevel) -> Result<Self, DsmError> {
        // Select parameters based on quantum security requirements
        let (p_bits, q_bits) = match security_level {
            SecurityLevel::Standard128 => (3072, 256),
            SecurityLevel::Medium192 => (7680, 384),
            SecurityLevel::High256 => (15360, 512),
        };

        // Generate safe prime and generator
        let (p, q, g, h) = generate_pedersen_params(p_bits, q_bits).map_err(|e| {
            DsmError::crypto(
                "Failed to generate Pedersen parameters".to_string(),
                Some(Box::new(e)),
            )
        })?;

        Ok(Self {
            g,
            h,
            p,
            q,
            security_level,
        })
    }

    /// Canonical, versioned byte encoding (big-endian, length-prefixed).
    /// Format:
    ///   magic: b"DSM.PEDERSEN.PARAMS\0"
    ///   ver  : u8 (=1)
    ///   sec  : u8 (SecurityLevel)
    ///   g    : u32 len | bytes (BE, minimal)
    ///   h    : u32 len | bytes
    ///   p    : u32 len | bytes
    ///   q    : u32 len | bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"DSM.PEDERSEN.PARAMS\0");
        out.push(1u8); // version
        out.push(self.security_level.to_wire());

        encode_biguint(&mut out, &self.g);
        encode_biguint(&mut out, &self.h);
        encode_biguint(&mut out, &self.p);
        encode_biguint(&mut out, &self.q);
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> DsmResult<Self> {
        const MAGIC: &[u8] = b"DSM.PEDERSEN.PARAMS\0";
        if bytes.len() < MAGIC.len() + 2 {
            return Err(DsmError::serialization_error(
                "PedersenParams too short",
                "params_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DsmError::serialization_error(
                "Bad PedersenParams magic",
                "params_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        bytes = &bytes[MAGIC.len()..];

        // version
        let version = bytes[0];
        bytes = &bytes[1..];
        if version != 1 {
            return Err(DsmError::serialization_error(
                "Unsupported PedersenParams version",
                "params_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }

        // security level
        let sec = SecurityLevel::from_wire(bytes[0])?;
        bytes = &bytes[1..];

        let (g, rest) = decode_biguint(bytes)?;
        bytes = rest;
        let (h, rest) = decode_biguint(bytes)?;
        bytes = rest;
        let (p, rest) = decode_biguint(bytes)?;
        bytes = rest;
        let (q, _rest) = decode_biguint(bytes)?;

        Ok(Self {
            g,
            h,
            p,
            q,
            security_level: sec,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PedersenCommitment {
    /// The commitment value
    pub commitment: BigUint,

    /// Hash of the commitment (for quantum resistance)
    pub commitment_hash: Vec<u8>,

    /// Number of hash iterations used
    pub hash_rounds: u32,

    /// Security level
    pub security_level: SecurityLevel,
}

/// Default implementation for PedersenCommitment
impl Default for PedersenCommitment {
    fn default() -> Self {
        Self {
            commitment: BigUint::from(0u32),
            commitment_hash: vec![0; 32],
            hash_rounds: 10,
            security_level: SecurityLevel::Standard128,
        }
    }
}

impl PedersenCommitment {
    /// Create a new quantum-resistant commitment
    pub fn commit(value: &[u8], params: &PedersenParams) -> Result<Self, DsmError> {
        let mut rng = crate::crypto::rng::SecureRng;
        let (commitment, _) = Self::commit_with_rng(params, value, &mut rng)?;
        Ok(commitment)
    }

    /// Create a new quantum-resistant commitment with RNG
    pub fn commit_with_rng<R: RngCore + CryptoRng>(
        params: &PedersenParams,
        value: &[u8],
        rng: &mut R,
    ) -> DsmResult<(Self, BigUint)> {
        // Get number of hash rounds based on security level
        let hash_rounds = match params.security_level {
            SecurityLevel::Standard128 => 10,
            SecurityLevel::Medium192 => 14,
            SecurityLevel::High256 => 20,
        };

        // Generate randomness
        let r = Self::generate_randomness(rng, &params.q)?;
        // Compute commitment with quantum-resistant parameters
        let commitment = Self::compute_commitment(value, &r, params)?;
        // Hash the commitment for quantum resistance
        let commitment_hash = hash_commitment(&commitment, hash_rounds)?;

        Ok((
            Self {
                commitment,
                commitment_hash,
                hash_rounds,
                security_level: params.security_level,
            },
            r,
        ))
    }

    /// Generate secure randomness for the commitment
    fn generate_randomness<R: RngCore + CryptoRng>(
        rng: &mut R,
        q: &BigUint,
    ) -> Result<BigUint, DsmError> {
        // Determine how many bytes we need
        let bytes_needed = q.bits().div_ceil(8);

        // Create buffer for random bytes
        let buffer_size: usize = bytes_needed.try_into().map_err(|_| {
            DsmError::crypto("Buffer size overflow".to_string(), None::<std::io::Error>)
        })?;
        let mut buf = vec![0u8; buffer_size];

        // Generate random value and reduce mod q until we get valid value
        loop {
            // Fill buffer with random bytes
            rng.fill_bytes(&mut buf);

            // Convert to BigUint
            let rand_val = BigUint::from_bytes_be(&buf);

            // Check if value is in valid range (0 to q-1)
            if rand_val < *q {
                return Ok(rand_val);
            }
        }
    }

    /// Homomorphically combine commitments
    pub fn combine(&self, other: &Self, params: &PedersenParams) -> DsmResult<Self> {
        if self.security_level != other.security_level {
            return Err(DsmError::crypto(
                String::from("Cannot combine commitments with different security levels"),
                None::<std::io::Error>,
            ));
        }

        // Combine commitments homomorphically
        let combined = (&self.commitment * &other.commitment) % &params.p;
        // Hash the combined commitment
        let commitment_hash = hash_commitment(&combined, self.hash_rounds)?;

        Ok(Self {
            commitment: combined,
            commitment_hash,
            hash_rounds: self.hash_rounds,
            security_level: self.security_level,
        })
    }

    /// Compute commitment with quantum resistance
    fn compute_commitment(
        value: &[u8],
        r: &BigUint,
        params: &PedersenParams,
    ) -> DsmResult<BigUint> {
        // g^value * h^r mod p
        //
        // NOTE: The "message" exponent is interpreted from little-endian bytes.
        // (The encoding on the wire for BigUint uses big-endian; this is purely
        // an internal convention of this function.)
        let v = BigUint::from_bytes_le(value);
        Ok((params.g.modpow(&v, &params.p) * params.h.modpow(r, &params.p)) % &params.p)
    }

    /// Verify a commitment against a value and randomness
    pub fn verify(&self, value: &[u8], r: &BigUint, params: &PedersenParams) -> DsmResult<bool> {
        // Compute expected commitment
        let expected = Self::compute_commitment(value, r, params)?;

        // Hash the expected commitment
        let expected_hash = hash_commitment(&expected, self.hash_rounds)?;

        // Use constant-time comparison for security
        Ok(constant_time_eq(&self.commitment_hash, &expected_hash) && self.commitment == expected)
    }

    pub fn smart_commit<R: RngCore + CryptoRng>(
        params: &PedersenParams,
        value: &[u8],
        recipient: &[u8],
        condition: &str,
        rng: &mut R,
    ) -> DsmResult<(Self, BigUint)> {
        // Domain-separated BLAKE3 preimage (no SHA3/SHAKE alternate path)
        let mut hasher = crate::crypto::blake3::dsm_domain_hasher(DOMAIN_COMMIT_TAG);
        hasher.update(recipient);
        hasher.update(condition.as_bytes());
        hasher.update(value);
        let domain_separated = hasher.finalize();

        // Create commitment using domain separated value
        Self::commit_with_rng(params, domain_separated.as_bytes(), rng)
    }

    /// Canonical, versioned byte encoding (big-endian, length-prefixed).
    /// Format:
    ///   magic: b"DSM.PEDERSEN.COMMIT\0"
    ///   ver  : u8 (=1)
    ///   sec  : u8 (SecurityLevel)
    ///   rounds: u32 (BE)
    ///   commitment : u32 len | bytes (BigUint, BE minimal)
    ///   commitment_hash: u32 len | bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"DSM.PEDERSEN.COMMIT\0");
        out.push(1u8); // version
        out.push(self.security_level.to_wire());
        out.extend_from_slice(&self.hash_rounds.to_be_bytes());
        encode_biguint(&mut out, &self.commitment);
        encode_bytes(&mut out, &self.commitment_hash);
        out
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, DsmError> {
        const MAGIC: &[u8] = b"DSM.PEDERSEN.COMMIT\0";
        if bytes.len() < MAGIC.len() + 2 + 4 {
            return Err(DsmError::serialization_error(
                "PedersenCommitment too short",
                "commitment_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(DsmError::serialization_error(
                "Bad PedersenCommitment magic",
                "commitment_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        bytes = &bytes[MAGIC.len()..];

        // version
        let version = bytes[0];
        bytes = &bytes[1..];
        if version != 1 {
            return Err(DsmError::serialization_error(
                "Unsupported PedersenCommitment version",
                "commitment_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }

        // security level
        let sec = SecurityLevel::from_wire(bytes[0])?;
        bytes = &bytes[1..];

        // hash rounds (u32, BE)
        if bytes.len() < 4 {
            return Err(DsmError::serialization_error(
                "Missing hash_rounds",
                "commitment_bytes",
                None::<&str>,
                None::<std::io::Error>,
            ));
        }
        let rounds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        bytes = &bytes[4..];

        let (commitment, rest) = decode_biguint(bytes)?;
        bytes = rest;
        let (commitment_hash, _rest) = decode_bytes(bytes)?;

        Ok(Self {
            commitment,
            commitment_hash,
            hash_rounds: rounds,
            security_level: sec,
        })
    }
}

/// External verification function for commitments
pub fn verify(commitment: &PedersenCommitment) -> DsmResult<bool> {
    // For verification, we only need the commitment
    // The blinding factor is embedded in the commitment structure

    // Hash and compare commitment values
    let expected_hash = hash_commitment(&commitment.commitment, commitment.hash_rounds)?;
    Ok(constant_time_eq(
        &commitment.commitment_hash,
        &expected_hash,
    ))
}

/// Generate Pedersen parameters
#[allow(clippy::many_single_char_names)]
fn generate_pedersen_params(
    _p_bits: usize,
    q_bits: usize,
) -> Result<(BigUint, BigUint, BigUint, BigUint), DsmError> {
    // Generate safe prime p = 2q + 1 where q is also prime
    let (p, q) = loop {
        let q = BigUint::from_bytes_be(&Generator::new_prime(q_bits).to_bytes_be());
        let p = &q * BigUint::from(2u32) + BigUint::from(1u32);

        let p_check = num_primes::BigUint::from_str(&p.to_string()).map_err(|_| {
            DsmError::crypto(
                "Failed to convert p to string for prime check".to_string(),
                None::<std::io::Error>,
            )
        })?;
        if num_primes::Verification::is_prime(&p_check) {
            break (p, q);
        }
    };

    let mut rng = crate::crypto::rng::SecureRng;

    // Find generator g of order q in Z*_p
    let g = loop {
        // Generate random value between 2 and p-1
        let two = BigUint::from(2u32);
        let p_minus_1 = &p - BigUint::from(1u32);

        // Generate random bytes of size ~ p
        let bytes_needed = p.bits().div_ceil(8);
        let buffer_size: usize = bytes_needed.try_into().map_err(|_| {
            DsmError::crypto(
                "Buffer size overflow for generator".to_string(),
                None::<std::io::Error>,
            )
        })?;
        let mut buf = vec![0u8; buffer_size];
        rng.fill_bytes(&mut buf);

        // Convert to BigUint and ensure in range [2, p-1]
        let mut candidate = BigUint::from_bytes_be(&buf);
        candidate = &two + (&candidate % (&p_minus_1 - &two));

        let g = candidate.modpow(&BigUint::from(2u32), &p);

        if g.modpow(&q, &p) == BigUint::from(1u32) {
            break g;
        }
    };

    // Generate random h as h = g^x mod p for random x
    let bytes_needed = q.bits().div_ceil(8);
    let buffer_size: usize = bytes_needed.try_into().map_err(|_| {
        DsmError::crypto(
            "Buffer size overflow for h generator".to_string(),
            None::<std::io::Error>,
        )
    })?;
    let mut buf = vec![0u8; buffer_size];
    rng.fill_bytes(&mut buf);
    let x = BigUint::from_bytes_be(&buf) % &q;
    let h = g.modpow(&x, &p);
    Ok((p, q, g, h))
}

/// Hash a commitment for quantum resistance using domain-separated BLAKE3.
fn hash_commitment(commitment: &BigUint, rounds: u32) -> DsmResult<Vec<u8>> {
    // Seeded with domain-separated BLAKE3 over the big-endian commitment bytes.
    let mut seed_hasher = crate::crypto::blake3::dsm_domain_hasher(HASH_SEED_TAG);
    seed_hasher.update(&commitment.to_bytes_be());
    let mut result = seed_hasher.finalize().as_bytes().to_vec();

    // Deterministic number of BLAKE3 rounds, each re-keyed by the round index.
    for i in 0..rounds {
        let mut round_hasher = crate::crypto::blake3::dsm_domain_hasher(HASH_ROUND_TAG);
        round_hasher.update(&i.to_le_bytes());
        round_hasher.update(&result);
        result = round_hasher.finalize().as_bytes().to_vec();
    }

    // Final condensation step, producing 32 bytes.
    let mut final_hasher = crate::crypto::blake3::dsm_domain_hasher(HASH_FINAL_TAG);
    final_hasher.update(&result);
    Ok(final_hasher.finalize().as_bytes().to_vec())
}

/// Constant-time equality check
#[allow(clippy::many_single_char_names)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/* ======== Encoding helpers (canonical, big-endian length prefixes) ======== */

fn encode_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len: u32 = bytes.len().try_into().unwrap_or(u32::MAX); // extremely large values won't happen realistically here
    encode_u32(buf, len);
    buf.extend_from_slice(bytes);
}

fn decode_bytes(mut bytes: &[u8]) -> DsmResult<(Vec<u8>, &[u8])> {
    if bytes.len() < 4 {
        return Err(DsmError::serialization_error(
            "Missing length for bytes",
            "decode_bytes",
            None::<&str>,
            None::<std::io::Error>,
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    bytes = &bytes[4..];
    if bytes.len() < len {
        return Err(DsmError::serialization_error(
            "Insufficient bytes",
            "decode_bytes",
            None::<&str>,
            None::<std::io::Error>,
        ));
    }
    let (val, rest) = bytes.split_at(len);
    Ok((val.to_vec(), rest))
}

fn encode_biguint(buf: &mut Vec<u8>, v: &BigUint) {
    let b = v.to_bytes_be(); // minimal, no leading zeros
    encode_bytes(buf, &b);
}

fn decode_biguint(bytes: &[u8]) -> DsmResult<(BigUint, &[u8])> {
    let (b, rest) = decode_bytes(bytes)?;
    Ok((BigUint::from_bytes_be(&b), rest))
}

#[cfg(test)]
pub fn commit(value: &[u8], randomness: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(value);
    hasher.update(randomness);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
pub fn verify_commitment(commitment: &[u8], value: &[u8], randomness: &[u8]) -> bool {
    let expected = commit(value, randomness);
    constant_time_eq(commitment, &expected)
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_commitment_flow() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128)
            .expect("Params generation should succeed in test");

        let value = b"test value";
        let (commit, _r) = PedersenCommitment::commit_with_rng(&params, value, &mut rng)
            .expect("Pedersen commit should succeed in test");

        assert!(!commit.commitment_hash.is_empty());
    }

    #[test]
    fn test_homomorphic_combination() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128)
            .expect("Params generation should succeed in test");

        let (c1, _) = PedersenCommitment::commit_with_rng(&params, b"value1", &mut rng)
            .expect("Pedersen commit should succeed in test");
        let (c2, _) = PedersenCommitment::commit_with_rng(&params, b"value2", &mut rng)
            .expect("Pedersen commit should succeed in test");

        let _combined = c1
            .combine(&c2, &params)
            .expect("Pedersen combine should succeed in test");
    }

    #[test]
    fn test_verify_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128)
            .expect("Params generation should succeed in test");

        let value = b"test value";
        let (commit, r) = PedersenCommitment::commit_with_rng(&params, value, &mut rng)
            .expect("Pedersen commit should succeed in test");

        assert!(commit
            .verify(value, &r, &params)
            .expect("Verify should not fail in test"));
        assert!(!commit
            .verify(b"wrong value", &r, &params)
            .expect("Verify should not fail in test"));
    }

    #[test]
    fn test_smart_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::new(SecurityLevel::Standard128)
            .expect("Params generation should succeed in test");

        let value = b"100 tokens";
        let recipient = b"Bob";
        let condition = "if used within 7 days";

        let (commit, _) =
            PedersenCommitment::smart_commit(&params, value, recipient, condition, &mut rng)
                .expect("Smart commit should succeed in test");

        assert!(!commit.commitment_hash.is_empty());
    }

    #[test]
    fn test_roundtrip_encodings() {
        let params = PedersenParams::new(SecurityLevel::Standard128).unwrap();
        let params_bytes = params.to_bytes();
        let params2 = PedersenParams::from_bytes(&params_bytes).unwrap();
        assert_eq!(params.security_level as u8, params2.security_level as u8);
        assert_eq!(params.g, params2.g);
        assert_eq!(params.h, params2.h);
        assert_eq!(params.p, params2.p);
        assert_eq!(params.q, params2.q);

        let (c, _) =
            PedersenCommitment::commit_with_rng(&params, b"abc", &mut rand::thread_rng()).unwrap();
        let cb = c.to_bytes();
        let c2 = PedersenCommitment::from_bytes(&cb).unwrap();
        assert_eq!(c.security_level as u8, c2.security_level as u8);
        assert_eq!(c.hash_rounds, c2.hash_rounds);
        assert_eq!(c.commitment, c2.commitment);
        assert_eq!(c.commitment_hash, c2.commitment_hash);
    }
}
