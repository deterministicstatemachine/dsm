//! C-DBRW (Challenge-seeded Dual-Binding Random Walk) binding module.
//!
//! Replaces the old timing-based DBRW with the challenge-seeded protocol
//! from C-DBRW paper Rev 2.0. All canonical serialization and key derivation
//! live exclusively in this module — PBI only validates inputs then delegates here.
//!
//! # Domain Tags
//!
//! | Tag | Usage |
//! |-----|-------|
//! | `DSM/dbrw-bind\0` | K_DBRW binding key derivation |
//! | `DSM/cdbrw-seed\0` | Challenge-seeded orbit starting point |
//! | `DSM/attractor-commit\0` | ACD (Attractor Commitment Digest) |
//! | `DSM/cdbrw-response\0` | Verification response gamma |
//!
//! # Canonical Serialization
//!
//! All inputs use length-prefixed encoding (LE u32 length + raw bytes).
//! This is the **single source of truth** for DBRW canonical forms.
//! No other module may implement its own serialization for these derivations.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::canonical_lp;
use crate::types::error::DsmError;

/// Orbit length for conservative autocorrelated thermal model (Remark 4.6).
/// Spec default is N = 4096 (Appendix B); this value provides FAR ≤ 10⁻⁸
/// (Corollary 4.20) and strong mixing under autocorrelated thermal noise.
pub const ORBIT_LENGTH: u32 = 16_384;

/// Spec default orbit length (Appendix B): minimum for basic authentication.
/// FRR ≤ 0.16, FAR ≤ 0.013 at this length.
pub const ORBIT_LENGTH_MIN: u32 = 4_096;

/// Minimum ARX rotation parameter.
pub const ARX_MIN_ROUNDS: u32 = 3;

/// Minimum ARX arena size in bytes.
pub const ARX_MIN_ARENA: u32 = 256;

/// Manufacturing variance threshold: sigma_device >= 0.04.
pub const MFG_VARIANCE_THRESHOLD: f64 = 0.04;

/// Entropy health: minimum normalized entropy.
pub const HEALTH_MIN_ENTROPY: f64 = 0.45;

/// Entropy health: maximum autocorrelation absolute value.
pub const HEALTH_MAX_AUTOCORR: f64 = 0.3;

/// Entropy health: minimum LZ78 compression ratio.
pub const HEALTH_MIN_LZ78_RATIO: f64 = 0.45;

/// Derive the C-DBRW binding key K_DBRW from hardware entropy, environment
/// fingerprint, and salt.
///
/// Formula: `K_DBRW = BLAKE3("DSM/dbrw-bind\0" || LP(hw) || LP(env) || LP(salt))`
///
/// where `LP(x) = LE32(len(x)) || x` (length-prefixed canonical encoding).
///
/// This is the **sole** implementation of K_DBRW derivation. PBI must
/// delegate here after input validation.
pub fn derive_cdbrw_binding_key(
    hw_entropy: &[u8],
    env_fingerprint: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], DsmError> {
    if hw_entropy.is_empty() {
        return Err(DsmError::Validation {
            context: "C-DBRW: hw_entropy must not be empty".into(),
            source: None,
        });
    }
    if env_fingerprint.is_empty() {
        return Err(DsmError::Validation {
            context: "C-DBRW: env_fingerprint must not be empty".into(),
            source: None,
        });
    }
    if salt.is_empty() {
        return Err(DsmError::Validation {
            context: "C-DBRW: salt must not be empty".into(),
            source: None,
        });
    }

    let mut hasher = dsm_domain_hasher("DSM/dbrw-bind");
    canonical_lp::write_lp(&mut hasher, hw_entropy)?;
    canonical_lp::write_lp(&mut hasher, env_fingerprint)?;
    canonical_lp::write_lp(&mut hasher, salt)?;
    Ok(*hasher.finalize().as_bytes())
}

/// Seed a challenge orbit: `x_0 = H("DSM/cdbrw-seed\0" || c || K_DBRW) mod 2^32`.
///
/// Given a verifier challenge `c` and the binding key `K_DBRW`, produces the
/// deterministic starting index for the ARX pointer-chasing orbit.
pub fn seed_orbit(challenge: &[u8], k_dbrw: &[u8; 32]) -> u32 {
    let mut hasher = dsm_domain_hasher("DSM/cdbrw-seed");
    hasher.update(challenge);
    hasher.update(k_dbrw);
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Compute the Attractor Commitment Digest (ACD) at enrollment (Alg. 2, step 8).
///
/// `ACD = H("DSM/attractor-commit\0" || H_bar || epsilon_intra_le || B_le || N_le || r_le)`
///
/// - `h_bar`: normalized histogram (IEEE 754 f64 LE per bin)
/// - `epsilon_intra`: intra-device Wasserstein-1 distance (f64 LE)
/// - `bin_count`: histogram bin count B (paper: B in {256, 512, 1024})
/// - `orbit_len`: orbit length N (default 16384)
/// - `rotation_bits`: ARX rotation parameter r (paper: r in {5, 7, 8, 11, 13})
pub fn compute_acd(
    h_bar: &[f64],
    epsilon_intra: f64,
    bin_count: u32,
    orbit_len: u32,
    rotation_bits: u32,
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/attractor-commit");
    for &val in h_bar {
        hasher.update(&val.to_le_bytes());
    }
    hasher.update(&epsilon_intra.to_le_bytes());
    hasher.update(&bin_count.to_le_bytes());
    hasher.update(&orbit_len.to_le_bytes());
    hasher.update(&rotation_bits.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the verification response gamma (Alg. 3, step 2).
///
/// `gamma = H("DSM/cdbrw-response\0" || H_bar || c)`
///
/// Per paper Protocol 6.2 (V3) and Algorithm 3:
/// gamma commits the orbit histogram and the challenge. ACD is checked
/// separately in the attractor envelope test (step V6d).
pub fn compute_response(h_bar: &[f64], challenge: &[u8]) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/cdbrw-response");
    for &val in h_bar {
        hasher.update(&val.to_le_bytes());
    }
    hasher.update(challenge);
    *hasher.finalize().as_bytes()
}

/// Compute the acceptance threshold tau from intra/inter device distances.
///
/// `tau = (epsilon_intra + epsilon_inter) / 2`
pub fn compute_threshold(epsilon_intra: f64, epsilon_inter: f64) -> f64 {
    (epsilon_intra + epsilon_inter) / 2.0
}

/// Verify that the manufacturing variance meets the minimum threshold.
///
/// `sigma_device = std(H_bar) / max(H_bar) >= 0.04`
///
/// Returns `Ok(sigma)` if the gate passes, `Err` if insufficient variance.
pub fn check_manufacturing_variance(h_bar: &[f64]) -> Result<f64, DsmError> {
    if h_bar.is_empty() {
        return Err(DsmError::Validation {
            context: "C-DBRW: histogram must not be empty".into(),
            source: None,
        });
    }
    let max_val = h_bar.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max_val <= 0.0 {
        return Err(DsmError::Validation {
            context: "C-DBRW: histogram max must be positive".into(),
            source: None,
        });
    }
    let mean = h_bar.iter().sum::<f64>() / h_bar.len() as f64;
    let variance = h_bar.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / h_bar.len() as f64;
    let std_dev = variance.sqrt();
    let sigma_device = std_dev / max_val;

    if sigma_device < MFG_VARIANCE_THRESHOLD {
        return Err(DsmError::Validation {
            context: format!(
                "C-DBRW manufacturing gate failed: sigma_device={sigma_device:.4} < {MFG_VARIANCE_THRESHOLD}"
            ),
            source: None,
        });
    }
    Ok(sigma_device)
}

// ================================= Tests ====================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_key_deterministic() {
        let hw = b"hw_entropy_sample";
        let env = b"env_fingerprint_sample";
        let salt = b"salt_sample";
        let k1 = derive_cdbrw_binding_key(hw, env, salt).expect("valid");
        let k2 = derive_cdbrw_binding_key(hw, env, salt).expect("valid");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn binding_key_rejects_empty_inputs() {
        assert!(derive_cdbrw_binding_key(b"", b"env", b"salt").is_err());
        assert!(derive_cdbrw_binding_key(b"hw", b"", b"salt").is_err());
        assert!(derive_cdbrw_binding_key(b"hw", b"env", b"").is_err());
    }

    #[test]
    fn orbit_seed_deterministic() {
        let k = [0xABu8; 32];
        let challenge = b"test_challenge";
        let s1 = seed_orbit(challenge, &k);
        let s2 = seed_orbit(challenge, &k);
        assert_eq!(s1, s2);
    }

    #[test]
    fn acd_deterministic() {
        let h_bar = vec![0.1, 0.2, 0.3, 0.15, 0.25];
        let a1 = compute_acd(&h_bar, 0.05, 256, ORBIT_LENGTH, 7);
        let a2 = compute_acd(&h_bar, 0.05, 256, ORBIT_LENGTH, 7);
        assert_eq!(a1, a2);
    }

    #[test]
    fn response_deterministic() {
        let h_bar = vec![0.1, 0.2, 0.3, 0.15, 0.25];
        let challenge = b"c";
        let r1 = compute_response(&h_bar, challenge);
        let r2 = compute_response(&h_bar, challenge);
        assert_eq!(r1, r2);
    }

    #[test]
    fn threshold_computation() {
        let tau = compute_threshold(0.02, 0.08);
        assert!((tau - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn manufacturing_variance_pass() {
        let h_bar = vec![0.1, 0.4, 0.2, 0.5, 0.3, 0.6, 0.15, 0.45];
        let sigma = check_manufacturing_variance(&h_bar).expect("should pass");
        assert!(sigma >= MFG_VARIANCE_THRESHOLD);
    }

    #[test]
    fn manufacturing_variance_fail() {
        // Uniform histogram: std/max is very small.
        let h_bar = vec![0.5; 100];
        assert!(check_manufacturing_variance(&h_bar).is_err());
    }

    // =========================================================================
    // Cross-layer test vectors (TV-1 through TV-8, per §9.4).
    // These are canonical: C++/Kotlin/Rust must produce bit-identical outputs.
    // =========================================================================

    /// TV-1: BLAKE3 domain hash — empty data.
    /// H("DSM/dbrw-bind\0" || "")
    #[test]
    fn tv1_domain_hash_empty() {
        let hasher = dsm_domain_hasher("DSM/dbrw-bind");
        let digest = hasher.finalize();
        assert_eq!(digest.as_bytes().len(), 32, "BLAKE3-256 must be 32 bytes");
        // Non-zero output (domain tag alone produces a real hash)
        assert_ne!(*digest.as_bytes(), [0u8; 32]);
        // Deterministic: same call always same output
        let hasher2 = dsm_domain_hasher("DSM/dbrw-bind");
        assert_eq!(hasher.finalize().as_bytes(), hasher2.finalize().as_bytes());
    }

    /// TV-2: BLAKE3 domain hash — known input.
    /// H("DSM/cdbrw-seed\0" || 0x00..0x1F || 0xAB * 32)
    #[test]
    fn tv2_domain_hash_known_input() {
        let challenge: Vec<u8> = (0..32).collect();
        let k_dbrw = [0xABu8; 32];

        let mut hasher = dsm_domain_hasher("DSM/cdbrw-seed");
        hasher.update(&challenge);
        hasher.update(&k_dbrw);
        let d1 = *hasher.finalize().as_bytes();

        // Same inputs via seed_orbit API
        let x0 = seed_orbit(&challenge, &k_dbrw);
        assert_eq!(
            u32::from_le_bytes([d1[0], d1[1], d1[2], d1[3]]),
            x0,
            "seed_orbit must use first 4 LE bytes"
        );
    }

    /// TV-3: K_DBRW derivation with canonical inputs.
    #[test]
    fn tv3_k_dbrw_derivation() -> Result<(), DsmError> {
        let hw = [0x01u8; 16];
        let env = [0x02u8; 16];
        let salt = [0x03u8; 16];

        let k = derive_cdbrw_binding_key(&hw, &env, &salt)?;

        // Verify LP encoding: LE32(16) || 0x01*16 || LE32(16) || 0x02*16 || LE32(16) || 0x03*16
        let mut expected_hasher = dsm_domain_hasher("DSM/dbrw-bind");
        canonical_lp::write_lp(&mut expected_hasher, &hw)?;
        canonical_lp::write_lp(&mut expected_hasher, &env)?;
        canonical_lp::write_lp(&mut expected_hasher, &salt)?;
        let expected = *expected_hasher.finalize().as_bytes();
        assert_eq!(k, expected);
        Ok(())
    }

    /// TV-4: ACD computation with all-zero histogram (B=256 bins per paper default).
    #[test]
    fn tv4_acd_zero_histogram() {
        let h_bar = vec![0.0; 256];
        let acd = compute_acd(&h_bar, 0.0, 256, ORBIT_LENGTH, 7);
        assert_eq!(acd.len(), 32);
        // Verify determinism
        let acd2 = compute_acd(&h_bar, 0.0, 256, ORBIT_LENGTH, 7);
        assert_eq!(acd, acd2);
    }

    /// TV-5: Response gamma — H("DSM/cdbrw-response\0" || H_bar || c) per Alg. 3 step 2.
    #[test]
    fn tv5_response_gamma() {
        let h_bar = vec![1.0 / 8.0; 8]; // Uniform 8-bin
        let challenge = [0xFFu8; 32];
        let gamma = compute_response(&h_bar, &challenge);
        // Verify determinism
        let gamma2 = compute_response(&h_bar, &challenge);
        assert_eq!(gamma, gamma2);
        // Verify gamma changes with different challenge
        let gamma3 = compute_response(&h_bar, &[0x00u8; 32]);
        assert_ne!(gamma, gamma3);
        // Verify gamma changes with different histogram
        let h_bar2 = vec![1.0 / 4.0; 4];
        let gamma4 = compute_response(&h_bar2, &challenge);
        assert_ne!(gamma, gamma4);
    }

    /// TV-6: Seed orbit mod 2^32 with known inputs.
    #[test]
    fn tv6_seed_orbit_range() {
        let k = [0x00u8; 32];
        let c = [0x00u8; 32];
        let x0 = seed_orbit(&c, &k);
        // x0 is u32, always in range

        // Different challenge → different seed
        let c2 = [0x01u8; 32];
        let x1 = seed_orbit(&c2, &k);
        assert_ne!(x0, x1, "different challenges should yield different seeds");
    }

    /// TV-7: K_DBRW input sensitivity (avalanche).
    #[test]
    fn tv7_k_dbrw_avalanche() {
        let hw = [0x01u8; 16];
        let env = [0x02u8; 16];
        let salt = [0x03u8; 16];
        let k1 = derive_cdbrw_binding_key(&hw, &env, &salt).expect("valid");

        // Flip one bit in hw
        let mut hw2 = hw;
        hw2[0] ^= 0x01;
        let k2 = derive_cdbrw_binding_key(&hw2, &env, &salt).expect("valid");
        assert_ne!(k1, k2, "single bit flip must change output");

        // Count differing bytes
        let diff = k1.iter().zip(k2.iter()).filter(|(a, b)| a != b).count();
        assert!(
            diff > 8,
            "avalanche: expected >8 differing bytes, got {diff}"
        );
    }

    /// TV-8: All domain tags produce distinct hashes for same data.
    #[test]
    fn tv8_domain_tag_isolation() {
        let data = [0xAA; 64];
        let tags = [
            "DSM/dbrw-bind",
            "DSM/cdbrw-seed",
            "DSM/attractor-commit",
            "DSM/cdbrw-response",
            "DSM/kyber-coins",
            "DSM/kyber-ss",
            "DSM/ek",
            "DSM/moment",
        ];
        let mut hashes = Vec::new();
        for tag in &tags {
            let mut h = dsm_domain_hasher(tag);
            h.update(&data);
            hashes.push(*h.finalize().as_bytes());
        }
        // All pairs must be distinct
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "tags {} and {} must produce distinct hashes",
                    tags[i], tags[j]
                );
            }
        }
    }
}
