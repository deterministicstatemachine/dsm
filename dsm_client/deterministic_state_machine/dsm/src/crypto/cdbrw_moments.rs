// SPDX-License-Identifier: MIT OR Apache-2.0
//! C-DBRW Attractor Envelope Test — spec §6.3 / Definition 6.3.
//!
//! The envelope test binds the response commitment γ to the enrollment
//! commitment ACD via m moments of the response histogram + a Merkle
//! tree over their commitments. The verifier checks each moment is
//! within a tolerance ball pre-committed in ACD at enrollment time.
//!
//! Without this, an attacker who recovers K_DBRW can forge γ that
//! passes signature verification (because γ is just BLAKE3 of (H̄ ‖ c)
//! and they can craft any H̄ they like). With it, γ must correspond to
//! a histogram whose moments match the device's enrolled attractor
//! shape — and silicon-substrate moments can't be fabricated without
//! actually running an orbit on the enrolled hardware.
//!
//! # Spec mapping (cdbrw.instructions.md §6.3)
//!
//! ```text
//! π_env := (μ̂_i, H_{DSM/moment}(μ̂_i ‖ i ‖ c))_{i=1..m}                  Eq. 12
//! ```
//!
//! Spec normative: `m ≥ 8` moments. Default 8 = mean, variance,
//! skewness, kurtosis, Q1, median, Q3, P95.
//!
//! # Determinism
//!
//! All moment math is deterministic over the f32 bin-density vector and
//! the bin-index u32 ordinal. No floating-point ordering ambiguity
//! because (a) the input is a histogram already normalized to sum to 1.0
//! by `build_histogram`, (b) the sums and weighted bin-index products
//! are all f64 with explicit ordering, (c) quantiles use the bin-index
//! domain (integer comparisons) with linear interpolation only on the
//! result.

use crate::crypto::blake3::dsm_domain_hasher;

/// Number of moments committed in the envelope (spec normative ≥ 8).
pub const ENVELOPE_MOMENT_COUNT: usize = 8;

/// Eight statistical moments of a normalized histogram, in canonical
/// order: mean, variance, skewness, kurtosis, Q1, median, Q3, P95.
///
/// All values are f64 to keep enough precision for cumulants of the
/// 32-bin distributions C-DBRW produces.
pub type MomentVector = [f64; ENVELOPE_MOMENT_COUNT];

/// Compute the eight canonical moments of a normalized histogram.
///
/// The histogram is treated as a probability distribution over bin
/// indices `0..bins`. Moments are computed in the bin-index domain
/// (not the underlying timing domain) so the result is invariant under
/// the min/max bucketing that `build_histogram` applies — only the
/// SHAPE of the histogram contributes to the moment vector.
///
/// Returns the zero vector for an empty or degenerate histogram so
/// callers can treat "no data" as "all moments at zero distance from
/// each other" rather than panicking.
pub fn compute_moments(hist: &[f32]) -> MomentVector {
    let mut out: MomentVector = [0.0; ENVELOPE_MOMENT_COUNT];
    if hist.is_empty() {
        return out;
    }
    let n = hist.len() as f64;

    // Normalize defensively — if the caller passed something that
    // doesn't sum to 1.0, treat it as a probability distribution
    // anyway by re-normalizing. Same-shape histograms then produce
    // the same moments regardless of trivial sum drift.
    let total: f64 = hist.iter().map(|&v| v as f64).sum();
    if total <= 0.0 {
        return out;
    }

    // Central moments: compute mean first, then the higher moments in
    // a single second pass.
    let mut mean = 0.0_f64;
    for (i, &v) in hist.iter().enumerate() {
        mean += (i as f64) * (v as f64 / total);
    }
    let mut m2 = 0.0_f64;
    let mut m3 = 0.0_f64;
    let mut m4 = 0.0_f64;
    for (i, &v) in hist.iter().enumerate() {
        let p = v as f64 / total;
        let d = i as f64 - mean;
        let d2 = d * d;
        m2 += p * d2;
        m3 += p * d2 * d;
        m4 += p * d2 * d2;
    }
    // Population skewness and kurtosis (NOT sample-corrected — the
    // histogram is the entire population by construction).
    let stddev = m2.sqrt();
    let skewness = if stddev > 0.0 { m3 / (stddev * stddev * stddev) } else { 0.0 };
    let kurtosis = if m2 > 0.0 { m4 / (m2 * m2) } else { 0.0 };

    // Quantiles via the CDF over bin indices. With normalized hist[i]
    // as PMF, the CDF is a step function; we return the smallest bin
    // index whose CDF ≥ target quantile. Same convention as numpy
    // default 'lower' interpolation, but expressed in bin-index units
    // for determinism.
    let mut cdf = 0.0_f64;
    let mut q1 = (n - 1.0).floor();
    let mut q2 = q1;
    let mut q3 = q1;
    let mut p95 = q1;
    let mut q1_done = false;
    let mut q2_done = false;
    let mut q3_done = false;
    let mut p95_done = false;
    for (i, &v) in hist.iter().enumerate() {
        cdf += v as f64 / total;
        if !q1_done && cdf >= 0.25 {
            q1 = i as f64;
            q1_done = true;
        }
        if !q2_done && cdf >= 0.50 {
            q2 = i as f64;
            q2_done = true;
        }
        if !q3_done && cdf >= 0.75 {
            q3 = i as f64;
            q3_done = true;
        }
        if !p95_done && cdf >= 0.95 {
            p95 = i as f64;
            p95_done = true;
        }
    }

    out[0] = mean;
    out[1] = m2;
    out[2] = skewness;
    out[3] = kurtosis;
    out[4] = q1;
    out[5] = q2;
    out[6] = q3;
    out[7] = p95;
    out
}

/// Per-moment commitment hash per spec Eq. 12:
/// `H_{DSM/moment}(μ̂_i ‖ i ‖ c)`.
///
/// Each moment is serialized as IEEE 754 f64 little-endian (8 bytes).
/// The index is u32 little-endian (4 bytes). The challenge is appended
/// raw. This is the binder that ties each moment to a specific
/// position in the vector AND to the specific verifier challenge,
/// preventing replay across challenges.
pub fn moment_commitment(moment: f64, index: u32, challenge: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/moment");
    h.update(&moment.to_le_bytes());
    h.update(&index.to_le_bytes());
    h.update(challenge);
    *h.finalize().as_bytes()
}

/// Build a Merkle root over the m moment commitments.
///
/// The tree is a balanced binary Merkle tree over m=8 leaves. Internal
/// nodes are computed as `H_{DSM/moment-node}(left ‖ right)` so the
/// node hash domain is distinct from the leaf-commitment domain. This
/// is the root that gets folded into ACD at enrollment.
///
/// Returns the Merkle root and the m leaf hashes (so the responder can
/// build the per-leaf Merkle paths without recomputing).
pub fn build_moment_tree(moments: &MomentVector, challenge: &[u8]) -> ([u8; 32], [[u8; 32]; ENVELOPE_MOMENT_COUNT]) {
    // Leaves.
    let mut leaves: [[u8; 32]; ENVELOPE_MOMENT_COUNT] = [[0u8; 32]; ENVELOPE_MOMENT_COUNT];
    for i in 0..ENVELOPE_MOMENT_COUNT {
        leaves[i] = moment_commitment(moments[i], i as u32, challenge);
    }
    // Layer 1: 4 nodes from 8 leaves.
    let layer1 = [
        merkle_node(&leaves[0], &leaves[1]),
        merkle_node(&leaves[2], &leaves[3]),
        merkle_node(&leaves[4], &leaves[5]),
        merkle_node(&leaves[6], &leaves[7]),
    ];
    // Layer 2: 2 nodes.
    let layer2 = [
        merkle_node(&layer1[0], &layer1[1]),
        merkle_node(&layer1[2], &layer1[3]),
    ];
    // Root.
    let root = merkle_node(&layer2[0], &layer2[1]);
    (root, leaves)
}

/// Verify a Merkle path for moment `index` against a known root.
///
/// `path` is the 3 sibling hashes from leaf to root, ordered
/// innermost-first (layer 0 sibling, layer 1 sibling, layer 2 sibling).
/// Returns `true` iff the reconstructed root matches `expected_root`.
pub fn verify_moment_path(
    leaf_hash: &[u8; 32],
    index: u32,
    path: &[[u8; 32]; 3],
    expected_root: &[u8; 32],
) -> bool {
    let mut node = *leaf_hash;
    let mut idx = index;
    for sibling in path.iter() {
        node = if idx % 2 == 0 {
            merkle_node(&node, sibling)
        } else {
            merkle_node(sibling, &node)
        };
        idx /= 2;
    }
    &node == expected_root
}

/// Extract the Merkle path for leaf `index` from the full leaf array.
pub fn extract_moment_path(
    leaves: &[[u8; 32]; ENVELOPE_MOMENT_COUNT],
    index: usize,
) -> [[u8; 32]; 3] {
    debug_assert!(index < ENVELOPE_MOMENT_COUNT);
    // Sibling at layer 0
    let layer0_sibling = leaves[index ^ 1];
    // Layer 1 nodes (we need the sibling of our pair's node at layer 1)
    let layer1 = [
        merkle_node(&leaves[0], &leaves[1]),
        merkle_node(&leaves[2], &leaves[3]),
        merkle_node(&leaves[4], &leaves[5]),
        merkle_node(&leaves[6], &leaves[7]),
    ];
    let l1_idx = index / 2;
    let layer1_sibling = layer1[l1_idx ^ 1];
    // Layer 2: which pair are we in?
    let layer2 = [
        merkle_node(&layer1[0], &layer1[1]),
        merkle_node(&layer1[2], &layer1[3]),
    ];
    let l2_idx = l1_idx / 2;
    let layer2_sibling = layer2[l2_idx ^ 1];
    [layer0_sibling, layer1_sibling, layer2_sibling]
}

fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/moment-node");
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Check that every live moment lies within `baseline ± tolerance`.
///
/// This is the verifier's envelope check (spec §6.3 Def 6.3). Returns
/// `Ok(())` when every moment passes; `Err(i)` with the failing moment
/// index on the first violation. The verifier MUST reject the response
/// if this returns Err.
pub fn check_envelope(
    live: &MomentVector,
    baseline: &MomentVector,
    tolerance: &MomentVector,
) -> Result<(), usize> {
    for i in 0..ENVELOPE_MOMENT_COUNT {
        let delta = (live[i] - baseline[i]).abs();
        if delta > tolerance[i] {
            return Err(i);
        }
    }
    Ok(())
}

/// Compute the per-moment tolerance ball from K enrollment trials.
///
/// For each moment i, the tolerance is set to the maximum absolute
/// deviation from the per-trial median, scaled by a safety factor of
/// 1.5 to absorb thermal drift between enrollment and verification.
///
/// At verification time, the verifier checks
///   `|moments_now[i] - moments_baseline[i]| ≤ tolerance[i]`
/// for every moment i; any moment outside its ball rejects the
/// response.
pub fn tolerance_ball(per_trial_moments: &[MomentVector]) -> MomentVector {
    let mut out: MomentVector = [0.0; ENVELOPE_MOMENT_COUNT];
    if per_trial_moments.is_empty() {
        return out;
    }
    // Per-moment median across trials.
    for i in 0..ENVELOPE_MOMENT_COUNT {
        let mut vals: Vec<f64> = per_trial_moments.iter().map(|m| m[i]).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = vals[vals.len() / 2];
        // Max absolute deviation × 1.5.
        let max_dev = vals
            .iter()
            .map(|v| (v - median).abs())
            .fold(0.0_f64, f64::max);
        out[i] = max_dev * 1.5;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a normalized histogram with mass at known positions.
    fn make_hist(mass_at: &[(usize, f32)], bins: usize) -> Vec<f32> {
        let mut h = vec![0.0_f32; bins];
        for &(idx, v) in mass_at {
            h[idx] = v;
        }
        h
    }

    #[test]
    fn moments_of_single_spike_at_bin_zero() {
        let h = make_hist(&[(0, 1.0)], 32);
        let m = compute_moments(&h);
        assert!((m[0] - 0.0).abs() < 1e-9, "mean should be 0, got {}", m[0]);
        assert!((m[1] - 0.0).abs() < 1e-9, "variance should be 0, got {}", m[1]);
        assert_eq!(m[5], 0.0, "median should be bin 0");
    }

    #[test]
    fn moments_of_uniform_hist() {
        let bins = 32;
        let h = vec![1.0_f32 / bins as f32; bins];
        let m = compute_moments(&h);
        // Mean of uniform on [0,31] is 15.5.
        assert!((m[0] - 15.5).abs() < 1e-6, "mean got {}", m[0]);
        // Variance of uniform on 32 integer bins = (32² - 1)/12 = 85.25.
        assert!((m[1] - 85.25).abs() < 1e-6, "variance got {}", m[1]);
        // Median (Q2) for uniform: smallest bin where cdf ≥ 0.5. After
        // 16 bins (0..=15) cdf = 16/32 = 0.5 exactly, so Q2 = bin 15.
        assert_eq!(m[5], 15.0);
    }

    #[test]
    fn moments_determinism() {
        let h = make_hist(&[(0, 0.4), (15, 0.3), (31, 0.3)], 32);
        let m1 = compute_moments(&h);
        let m2 = compute_moments(&h);
        for i in 0..ENVELOPE_MOMENT_COUNT {
            assert_eq!(m1[i].to_bits(), m2[i].to_bits());
        }
    }

    #[test]
    fn moments_different_histograms_differ() {
        let h_a = make_hist(&[(0, 0.95), (31, 0.05)], 32);
        let h_b = make_hist(&[(0, 0.50), (31, 0.50)], 32);
        let m_a = compute_moments(&h_a);
        let m_b = compute_moments(&h_b);
        let differing = (0..ENVELOPE_MOMENT_COUNT)
            .filter(|&i| (m_a[i] - m_b[i]).abs() > 1e-6)
            .count();
        assert!(differing >= 4, "expected >=4 moments to differ, got {}", differing);
    }

    #[test]
    fn moment_commitment_distinct_per_index() {
        let c = [0xABu8; 32];
        let h1 = moment_commitment(3.14, 0, &c);
        let h2 = moment_commitment(3.14, 1, &c);
        assert_ne!(h1, h2);
    }

    #[test]
    fn moment_commitment_distinct_per_challenge() {
        let c1 = [0x01u8; 32];
        let c2 = [0x02u8; 32];
        let h1 = moment_commitment(3.14, 0, &c1);
        let h2 = moment_commitment(3.14, 0, &c2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn merkle_tree_root_deterministic() {
        let moments: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let c = [0xCCu8; 32];
        let (r1, _) = build_moment_tree(&moments, &c);
        let (r2, _) = build_moment_tree(&moments, &c);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_tree_root_differs_on_different_moments() {
        let m_a: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let mut m_b = m_a;
        m_b[3] = 4.0001;
        let c = [0xCCu8; 32];
        let (r_a, _) = build_moment_tree(&m_a, &c);
        let (r_b, _) = build_moment_tree(&m_b, &c);
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn merkle_paths_verify_for_every_leaf() {
        let moments: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let c = [0xCCu8; 32];
        let (root, leaves) = build_moment_tree(&moments, &c);
        for i in 0..ENVELOPE_MOMENT_COUNT {
            let path = extract_moment_path(&leaves, i);
            assert!(
                verify_moment_path(&leaves[i], i as u32, &path, &root),
                "path for leaf {i} did not verify"
            );
        }
    }

    #[test]
    fn merkle_path_rejects_tampered_leaf() {
        let moments: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let c = [0xCCu8; 32];
        let (root, leaves) = build_moment_tree(&moments, &c);
        let path = extract_moment_path(&leaves, 3);
        let mut tampered_leaf = leaves[3];
        tampered_leaf[0] ^= 0x01;
        assert!(!verify_moment_path(&tampered_leaf, 3, &path, &root));
    }

    #[test]
    fn merkle_path_rejects_wrong_index() {
        let moments: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let c = [0xCCu8; 32];
        let (root, leaves) = build_moment_tree(&moments, &c);
        let path = extract_moment_path(&leaves, 3);
        // Submit leaf 3 but claim index 4: must not validate against
        // the layer-0 sibling chain for that position.
        assert!(!verify_moment_path(&leaves[3], 4, &path, &root));
    }

    #[test]
    fn envelope_accepts_within_tolerance() {
        let baseline: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let tolerance: MomentVector = [0.5; 8];
        // Live moments all within 0.3 of baseline.
        let live: MomentVector = [1.3, 1.8, 3.2, 3.7, 5.4, 5.6, 7.1, 8.3];
        assert!(check_envelope(&live, &baseline, &tolerance).is_ok());
    }

    #[test]
    fn envelope_rejects_outside_tolerance() {
        let baseline: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let tolerance: MomentVector = [0.5; 8];
        // Moment index 3 is 1.2 away from baseline 4.0 — exceeds tolerance 0.5.
        let live: MomentVector = [1.0, 2.0, 3.0, 5.2, 5.0, 6.0, 7.0, 8.0];
        assert_eq!(check_envelope(&live, &baseline, &tolerance), Err(3));
    }

    #[test]
    fn envelope_rejects_first_violation_only() {
        let baseline: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let tolerance: MomentVector = [0.1; 8];
        // Both moment 2 and 5 fail; verifier returns the first.
        let live: MomentVector = [1.0, 2.0, 4.0, 4.0, 5.0, 7.0, 7.0, 8.0];
        assert_eq!(check_envelope(&live, &baseline, &tolerance), Err(2));
    }

    #[test]
    fn envelope_zero_tolerance_requires_exact_match() {
        let baseline: MomentVector = [1.0; 8];
        let tolerance: MomentVector = [0.0; 8];
        assert!(check_envelope(&baseline, &baseline, &tolerance).is_ok());
        let mut perturbed = baseline;
        perturbed[7] = 1.0001;
        assert_eq!(check_envelope(&perturbed, &baseline, &tolerance), Err(7));
    }

    #[test]
    fn tolerance_ball_zero_for_identical_trials() {
        let m: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let trials = vec![m; 5];
        let t = tolerance_ball(&trials);
        for v in t.iter() {
            assert!((v - 0.0).abs() < 1e-12);
        }
    }

    #[test]
    fn tolerance_ball_grows_with_trial_spread() {
        let base: MomentVector = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let mut shifted = base;
        shifted[0] = 1.5;
        let trials = vec![base, base, shifted, base, base];
        let t = tolerance_ball(&trials);
        assert!(t[0] > 0.0, "tolerance for moment 0 should be > 0");
        assert!(t[1].abs() < 1e-12, "tolerance for moment 1 should be 0 (no spread)");
    }
}
