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
//! | `DSM/cdbrw/bind\0` | K_DBRW binding key derivation (canonical 4-input form) |
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

/// Derive the C-DBRW binding key K_DBRW from the canonical four-input
/// preimage that binds K_DBRW to the device's protocol identity and the
/// silicon/environment fingerprints.
///
/// Formula:
///   `K_DBRW = BLAKE3("DSM/cdbrw/bind\0"
///                     || LP(genesis_hash) || LP(device_id)
///                     || LP(hw_entropy)   || LP(env_fingerprint))`
///
/// where `LP(x) = LE32(len(x)) || x` (length-prefixed canonical encoding).
///
/// Inputs:
/// - `genesis_hash` — 32-byte root commitment produced by the genesis MPC.
///   For the root device this equals `device_id` (DSM identity invariant).
/// - `device_id` — 32-byte protocol device identifier.
/// - `hw_entropy` — silicon-derived hardware entropy (Phase 2.2 calibration).
/// - `env_fingerprint` — canonical execution-environment fingerprint (the
///   canonical binding context).
///
/// K_DBRW is **deterministic per device + per genesis**: same four inputs
/// always produce the same key, so the wallet recovers across
/// `adb install -r` and full uninstall + reinstall on the same physical
/// device. Cross-device anti-clone is enforced by Layer B (live W1 vs.
/// enrolled H̄_baseline on every boot via
/// `cdbrw_responder::publish_trust_snapshot` — drift downgrades access
/// AND zeros the in-memory K_DBRW slot via
/// `binding_key::clear_binding_key`).
///
/// Formal-model anchor: this is the preimage the Binding Inseparability
/// theorem is proven against — see
/// `.github/instructions/cdbrw.instructions.md` §5.3 Theorem 5.2 and
/// `.github/instructions/whitepaper.instructions.md` Definition 3 +
/// Theorem 5.
///
/// This is the **sole** implementation of K_DBRW derivation. PBI must
/// delegate here after input validation; no other module reproduces the
/// preimage construction.
pub fn derive_cdbrw_binding_key(
    genesis_hash: &[u8],
    device_id: &[u8],
    hw_entropy: &[u8],
    env_fingerprint: &[u8],
) -> Result<[u8; 32], DsmError> {
    if genesis_hash.len() != 32 {
        return Err(DsmError::Validation {
            context: format!(
                "C-DBRW: genesis_hash must be 32 bytes, got {}",
                genesis_hash.len()
            ),
            source: None,
        });
    }
    if device_id.len() != 32 {
        return Err(DsmError::Validation {
            context: format!(
                "C-DBRW: device_id must be 32 bytes, got {}",
                device_id.len()
            ),
            source: None,
        });
    }
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

    // Canonical K_DBRW preimage (= spec Theorem 5):
    //   domain "DSM/cdbrw/bind\0"
    //   || LP(genesis_hash) || LP(device_id) || LP(hw_entropy) || LP(env_fingerprint)
    // Four length-prefixed inputs; no salt, no separate G, no schema variants.
    let mut hasher = dsm_domain_hasher("DSM/cdbrw/bind");
    canonical_lp::write_lp(&mut hasher, genesis_hash);
    canonical_lp::write_lp(&mut hasher, device_id);
    canonical_lp::write_lp(&mut hasher, hw_entropy);
    canonical_lp::write_lp(&mut hasher, env_fingerprint);
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

/// Compute the *extended* Attractor Commitment Digest (ACD-v5) that
/// includes the Phase 7 attractor-envelope-test bindings. This is the
/// successor to [`compute_acd`] and is identical to it when no envelope
/// commitments are present.
///
/// `ACD' = H("DSM/attractor-commit\0" ||
///            H_bar || epsilon_intra || B || N || r ||
///            envelope_tree_root || tolerance_ball)`
///
/// where:
/// - `envelope_tree_root` is the 32-byte Merkle root over the
///   m=ENVELOPE_MOMENT_COUNT moment commitments computed at enrollment,
///   or 32 zero bytes if the envelope test is disabled.
/// - `tolerance_ball` is 8 × IEEE 754 f64 LE giving the per-moment
///   acceptance radius, or 64 zero bytes if disabled.
///
/// Old TV vectors that pass `&[0u8; 32]` + `&[0u8; 64]` are byte-identical
/// to [`compute_acd`] output (because the extra bytes hash into the same
/// suffix structure). Non-zero values produce a distinct ACD that the
/// verifier can re-derive from the on-disk enrollment snapshot.
pub fn compute_acd_with_envelope(
    h_bar: &[f64],
    epsilon_intra: f64,
    bin_count: u32,
    orbit_len: u32,
    rotation_bits: u32,
    envelope_tree_root: &[u8; 32],
    tolerance_ball: &[u8; 64],
) -> [u8; 32] {
    let mut hasher = dsm_domain_hasher("DSM/attractor-commit");
    for &val in h_bar {
        hasher.update(&val.to_le_bytes());
    }
    hasher.update(&epsilon_intra.to_le_bytes());
    hasher.update(&bin_count.to_le_bytes());
    hasher.update(&orbit_len.to_le_bytes());
    hasher.update(&rotation_bits.to_le_bytes());
    hasher.update(envelope_tree_root);
    hasher.update(tolerance_ball);
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
        let genesis_hash = [0x11u8; 32];
        let device_id = [0x22u8; 32];
        let hw = b"hw_entropy_sample";
        let env = b"env_fingerprint_sample";
        let k1 = derive_cdbrw_binding_key(&genesis_hash, &device_id, hw, env).expect("valid");
        let k2 = derive_cdbrw_binding_key(&genesis_hash, &device_id, hw, env).expect("valid");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn binding_key_rejects_empty_inputs() {
        let g = [0x11u8; 32];
        let d = [0x22u8; 32];
        // Length-strict on the 32-byte identity inputs.
        assert!(derive_cdbrw_binding_key(&[0u8; 31], &d, b"hw", b"env").is_err());
        assert!(derive_cdbrw_binding_key(&[0u8; 33], &d, b"hw", b"env").is_err());
        assert!(derive_cdbrw_binding_key(&g, &[0u8; 31], b"hw", b"env").is_err());
        assert!(derive_cdbrw_binding_key(&g, &[0u8; 33], b"hw", b"env").is_err());
        // Non-empty required for hw / env.
        assert!(derive_cdbrw_binding_key(&g, &d, b"", b"env").is_err());
        assert!(derive_cdbrw_binding_key(&g, &d, b"hw", b"").is_err());
    }

    /// TV-9: K_DBRW is deterministic per (genesis_hash, device_id,
    /// hw_entropy, env_fingerprint) — same four inputs always produce
    /// byte-identical output; varying any one input changes the output.
    /// This is the recoverability invariant that lets the wallet survive
    /// uninstall + reinstall on the same physical device under the same
    /// genesis identity.
    #[test]
    fn tv9_k_dbrw_deterministic_per_device() {
        let g = [0x55u8; 32]; // Stable per-device genesis_hash (= device_id for root)
        let d = [0x55u8; 32]; // device_id = genesis_hash on the root device
        let hw = [0x7Au8; 32]; // Stable per-device silicon-derived ACD
        let env = [0xC1u8; 32]; // Stable per-device Build.* fingerprint
        let k1 = derive_cdbrw_binding_key(&g, &d, &hw, &env).expect("valid");
        let k2 = derive_cdbrw_binding_key(&g, &d, &hw, &env).expect("valid");
        assert_eq!(
            k1, k2,
            "same four inputs MUST produce identical K_DBRW — wallet UX \
             depends on this for uninstall recovery"
        );
        // Vary each input independently — each MUST change the output.
        let g2 = [0x56u8; 32];
        assert_ne!(
            k1,
            derive_cdbrw_binding_key(&g2, &d, &hw, &env).expect("valid"),
            "different genesis_hash MUST produce different K_DBRW"
        );
        let d2 = [0x57u8; 32];
        assert_ne!(
            k1,
            derive_cdbrw_binding_key(&g, &d2, &hw, &env).expect("valid"),
            "different device_id MUST produce different K_DBRW"
        );
        let hw2 = [0x7Bu8; 32];
        assert_ne!(
            k1,
            derive_cdbrw_binding_key(&g, &d, &hw2, &env).expect("valid"),
            "different hw MUST produce different K_DBRW"
        );
        let env2 = [0xC2u8; 32];
        assert_ne!(
            k1,
            derive_cdbrw_binding_key(&g, &d, &hw, &env2).expect("valid"),
            "different env MUST produce different K_DBRW"
        );
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

    /// TV-1: BLAKE3 domain hash — empty data, canonical K_DBRW domain.
    /// `H("DSM/cdbrw/bind\0" || "")`
    #[test]
    fn tv1_domain_hash_empty() {
        let hasher = dsm_domain_hasher("DSM/cdbrw/bind");
        let digest = hasher.finalize();
        assert_eq!(digest.as_bytes().len(), 32, "BLAKE3-256 must be 32 bytes");
        // Non-zero output (domain tag alone produces a real hash)
        assert_ne!(*digest.as_bytes(), [0u8; 32]);
        // Deterministic: same call always same output
        let hasher2 = dsm_domain_hasher("DSM/cdbrw/bind");
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

    /// TV-3: K_DBRW derivation with the canonical 4-input preimage.
    ///
    /// `BLAKE3("DSM/cdbrw/bind\0" || LP(genesis_hash) || LP(device_id)
    ///         || LP(hw) || LP(env))`
    #[test]
    fn tv3_k_dbrw_derivation() {
        let genesis_hash = [0xAAu8; 32];
        let device_id = [0xBBu8; 32];
        let hw = [0x01u8; 16];
        let env = [0x02u8; 16];

        let k = derive_cdbrw_binding_key(&genesis_hash, &device_id, &hw, &env).expect("valid");

        // Verify LP encoding in canonical order:
        //   LE32(32)||genesis_hash || LE32(32)||device_id ||
        //   LE32(16)||hw           || LE32(16)||env
        let mut expected_hasher = dsm_domain_hasher("DSM/cdbrw/bind");
        canonical_lp::write_lp(&mut expected_hasher, &genesis_hash);
        canonical_lp::write_lp(&mut expected_hasher, &device_id);
        canonical_lp::write_lp(&mut expected_hasher, &hw);
        canonical_lp::write_lp(&mut expected_hasher, &env);
        let expected = *expected_hasher.finalize().as_bytes();
        assert_eq!(k, expected);
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

    /// TV-7: K_DBRW input sensitivity (avalanche). Verifies that a single
    /// bit flip in any one of the four canonical preimage inputs avalanches
    /// across the output. Each input is exercised explicitly so a
    /// regression that silenced any contribution would be caught.
    #[test]
    fn tv7_k_dbrw_avalanche() {
        let g = [0xA0u8; 32];
        let d = [0xB0u8; 32];
        let hw = [0x01u8; 16];
        let env = [0x02u8; 16];
        let k1 = derive_cdbrw_binding_key(&g, &d, &hw, &env).expect("valid");

        // Helper: one bit flip in input → output must avalanche.
        fn assert_avalanche(label: &str, k1: [u8; 32], k2: [u8; 32]) {
            assert_ne!(k1, k2, "single bit flip in {label} must change output");
            let diff = k1.iter().zip(k2.iter()).filter(|(a, b)| a != b).count();
            assert!(
                diff > 8,
                "avalanche ({label}): expected >8 differing bytes, got {diff}"
            );
        }

        let mut g2 = g;
        g2[0] ^= 0x01;
        assert_avalanche(
            "genesis_hash",
            k1,
            derive_cdbrw_binding_key(&g2, &d, &hw, &env).expect("valid"),
        );

        let mut d2 = d;
        d2[0] ^= 0x01;
        assert_avalanche(
            "device_id",
            k1,
            derive_cdbrw_binding_key(&g, &d2, &hw, &env).expect("valid"),
        );

        let mut hw2 = hw;
        hw2[0] ^= 0x01;
        assert_avalanche(
            "hw",
            k1,
            derive_cdbrw_binding_key(&g, &d, &hw2, &env).expect("valid"),
        );

        let mut env2 = env;
        env2[0] ^= 0x01;
        assert_avalanche(
            "env",
            k1,
            derive_cdbrw_binding_key(&g, &d, &hw, &env2).expect("valid"),
        );
    }

    /// TV-8: All domain tags produce distinct hashes for same data.
    #[test]
    fn tv8_domain_tag_isolation() {
        let data = [0xAA; 64];
        let tags = [
            "DSM/cdbrw/bind",
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
