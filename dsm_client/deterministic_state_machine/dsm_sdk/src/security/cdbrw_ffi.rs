// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure-Rust C-DBRW entropy-health math.
//!
//! History: this module used to be a safe FFI wrapper around
//! `dsm_client/android/app/src/main/cpp/cdbrw_entropy_health.{c,h}` that was
//! compiled into `libdsm_sdk.so` by `build.rs` via the `cc` crate. Those C
//! sources were removed with the Protocol 6.2 single-path collapse — every
//! histogram/entropy/autocorrelation/LZ78 computation now runs in pure Rust
//! so there is exactly one implementation to audit. The public API and
//! behaviour are preserved byte-for-byte against the old C reference so
//! existing callers (`cdbrw_enrollment_writer`, `cdbrw_responder`, ...) do
//! not need to change.
//!
//! ## Spec references
//!
//! - 3-condition health test (C-DBRW §4.5.7 Definition 4.15):
//!   Ĥ ≥ 0.45, |ρ̂| ≤ 0.3, L̂ ≥ 0.45
//! - Manufacturing gate (§6.1): σ_device = std(H̄) / max(H̄) ≥ 0.04
//! - Default sample size: `thresholds::HEALTH_N = 2048`

/// Normative thresholds from C-DBRW §4.5.7 / §6.1.
pub mod thresholds {
    /// Minimum normalized Shannon entropy.
    pub const H_HAT_MIN: f32 = 0.45;
    /// Maximum absolute lag-1 autocorrelation.
    pub const RHO_HAT_MAX: f32 = 0.30;
    /// Minimum normalized LZ78 compressibility metric.
    pub const L_HAT_MIN: f32 = 0.45;
    /// Minimum device variance for manufacturing gate.
    pub const SIGMA_DEV_MIN: f32 = 0.04;
    /// Default orbit length for health-test probe.
    pub const HEALTH_N: usize = 2048;
}

/// Result of the 3-condition entropy health test.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthResult {
    pub h_hat: f32,
    pub rho_hat: f32,
    pub l_hat: f32,
    pub passed: bool,
}

/// Result of the manufacturing-gate variance check.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MfgGateResult {
    pub sigma_device: f32,
    pub passed: bool,
}

/// Normalized Shannon entropy H̄ ∈ [0, 1] of a histogram.
///
/// Rejects histograms with fewer than 2 bins (trivially zero entropy per spec).
pub fn shannon_entropy(histogram: &[f32]) -> f32 {
    if histogram.len() < 2 {
        return 0.0;
    }
    let mut entropy: f64 = 0.0;
    for &p in histogram {
        let p64 = p as f64;
        if p64 > 1e-12 {
            entropy -= p64 * p64.log2();
        }
    }
    let max_entropy = (histogram.len() as f64).log2();
    if max_entropy < 1e-12 {
        return 0.0;
    }
    ((entropy / max_entropy).clamp(0.0, 1.0)) as f32
}

/// Lag-1 autocorrelation ρ̂ ∈ [−1, 1] of timing samples.
pub fn lag1_autocorrelation(samples: &[i64]) -> f32 {
    let n = samples.len();
    if n < 3 {
        return 0.0;
    }
    let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;

    let mut var = 0.0f64;
    let mut cov = 0.0f64;
    for i in 0..n {
        let d = samples[i] as f64 - mean;
        var += d * d;
        if i > 0 {
            let d_prev = samples[i - 1] as f64 - mean;
            cov += d * d_prev;
        }
    }
    if var < 1e-12 {
        return 0.0;
    }
    ((cov / var).clamp(-1.0, 1.0)) as f32
}

/// LZ78 compressibility metric L̂ ∈ [0, 1].
///
/// Samples are quantized to 8-bit symbols via a min/max rescale, then fed to
/// a bounded LZ78 phrase counter. The returned value is `1 - phrases/n`,
/// so perfectly compressible input (one repeating symbol) approaches 1 and
/// an incompressible random stream approaches 0.
pub fn lz78_compressibility(samples: &[i64]) -> f32 {
    let n = samples.len();
    if n == 0 {
        return 0.0;
    }

    // Quantize samples to u8 using a min/max rescale.
    let mut min_val = samples[0];
    let mut max_val = samples[0];
    for &s in samples.iter().skip(1) {
        if s < min_val {
            min_val = s;
        }
        if s > max_val {
            max_val = s;
        }
    }
    let range = (max_val - min_val).max(1) as i128;
    let symbols: Vec<u8> = samples
        .iter()
        .map(|&s| {
            let normalized = ((s - min_val) as i128 * 255) / range;
            normalized.clamp(0, 255) as u8
        })
        .collect();

    // LZ78 phrase counting with a bounded trie.
    //
    // The reference C implementation caps the pool at `u16::MAX` nodes and
    // each node owns a `[u16; 256]` child index table. We allocate nodes on
    // demand into a `Vec` so small inputs don't pay for the full pool.
    const MAX_NODES: usize = u16::MAX as usize;
    let cap = (n + 1).min(MAX_NODES);
    let mut pool: Vec<[u16; 256]> = Vec::with_capacity(cap);
    pool.push([0u16; 256]); // root = index 0

    let mut phrases: usize = 0;
    let mut current: usize = 0;

    for &sym in &symbols {
        let child = pool[current][sym as usize];
        if child != 0 {
            current = child as usize;
        } else {
            phrases += 1;
            if pool.len() < cap {
                let new_idx = pool.len() as u16;
                pool[current][sym as usize] = new_idx;
                pool.push([0u16; 256]);
            }
            current = 0;
        }
    }
    if current != 0 {
        phrases += 1;
    }

    let l_hat = 1.0f32 - (phrases as f32 / n as f32);
    l_hat.clamp(0.0, 1.0)
}

/// Full 3-condition health test over raw orbit timings.
///
/// `bins` must be at least 2 and should match the enrollment histogram bin
/// count (typically 256). `samples.len()` should equal
/// [`thresholds::HEALTH_N`] for canonical probes, though shorter slices are
/// still processed for short-probe diagnostic use.
pub fn health_test(samples: &[i64], bins: usize) -> HealthResult {
    if samples.is_empty() || bins < 2 {
        return HealthResult {
            h_hat: 0.0,
            rho_hat: 0.0,
            l_hat: 0.0,
            passed: false,
        };
    }

    // Build histogram from raw samples using min/max binning.
    let mut min_val = samples[0];
    let mut max_val = samples[0];
    for &s in samples.iter().skip(1) {
        if s < min_val {
            min_val = s;
        }
        if s > max_val {
            max_val = s;
        }
    }
    let range = (max_val - min_val).max(1) as i128;
    let last_bin = (bins as i128) - 1;

    let mut hist = vec![0.0f32; bins];
    for &s in samples {
        let idx = ((s - min_val) as i128 * last_bin) / range;
        let idx = idx.clamp(0, last_bin) as usize;
        hist[idx] += 1.0;
    }
    let inv_n = 1.0 / samples.len() as f32;
    for h in hist.iter_mut() {
        *h *= inv_n;
    }

    let h_hat = shannon_entropy(&hist);
    let rho_hat = lag1_autocorrelation(samples);
    let l_hat = lz78_compressibility(samples);

    let passed = h_hat >= thresholds::H_HAT_MIN
        && rho_hat.abs() <= thresholds::RHO_HAT_MAX
        && l_hat >= thresholds::L_HAT_MIN;

    HealthResult {
        h_hat,
        rho_hat,
        l_hat,
        passed,
    }
}

/// Manufacturing gate over K enrollment per-trial entropy values H̄_D.
///
/// Returns σ_device = std(H̄) / max(H̄) (sample variance, n−1 denominator)
/// and whether it meets [`thresholds::SIGMA_DEV_MIN`]. Used by the enrollment
/// writer to decide whether a device's silicon variability is acceptable
/// per §6.1. Fewer than 2 trials is rejected outright (no variance possible).
pub fn manufacturing_gate(h_bars: &[f32]) -> MfgGateResult {
    let n = h_bars.len();
    if n < 2 {
        return MfgGateResult {
            sigma_device: 0.0,
            passed: false,
        };
    }

    let mut mean = 0.0f64;
    let mut max_h = h_bars[0];
    for &h in h_bars {
        mean += h as f64;
        if h > max_h {
            max_h = h;
        }
    }
    mean /= n as f64;

    let mut var = 0.0f64;
    for &h in h_bars {
        let d = h as f64 - mean;
        var += d * d;
    }
    var /= (n - 1) as f64;
    let std_dev = var.sqrt();

    let max_h64 = max_h as f64;
    if max_h64 < 1e-12 {
        return MfgGateResult {
            sigma_device: 0.0,
            passed: false,
        };
    }

    let sigma_device = (std_dev / max_h64) as f32;
    MfgGateResult {
        sigma_device,
        passed: sigma_device >= thresholds::SIGMA_DEV_MIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_empty_histogram_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[1.0]), 0.0);
    }

    #[test]
    fn shannon_entropy_uniform_histogram_is_one() {
        let hist = vec![0.25f32; 4];
        let h = shannon_entropy(&hist);
        assert!((h - 1.0).abs() < 1e-5, "uniform H should be 1.0, got {h}");
    }

    #[test]
    fn shannon_entropy_delta_histogram_is_zero() {
        let mut hist = vec![0.0f32; 16];
        hist[3] = 1.0;
        let h = shannon_entropy(&hist);
        assert!(h < 1e-5, "delta H should be 0.0, got {h}");
    }

    #[test]
    fn lag1_autocorrelation_short_input_is_zero() {
        assert_eq!(lag1_autocorrelation(&[]), 0.0);
        assert_eq!(lag1_autocorrelation(&[1, 2]), 0.0);
    }

    #[test]
    fn lag1_autocorrelation_alternating_is_negative() {
        let samples: Vec<i64> = (0..128).map(|i| if i % 2 == 0 { 100 } else { -100 }).collect();
        let rho = lag1_autocorrelation(&samples);
        assert!(rho < -0.9, "alternating samples should have rho ~ -1, got {rho}");
    }

    #[test]
    fn lz78_compressibility_empty_is_zero() {
        assert_eq!(lz78_compressibility(&[]), 0.0);
    }

    #[test]
    fn health_test_short_input_rejected() {
        let result = health_test(&[], 256);
        assert!(!result.passed);
        assert_eq!(result.h_hat, 0.0);
    }

    #[test]
    fn health_test_few_bins_rejected() {
        let samples = vec![0i64; 256];
        let result = health_test(&samples, 1);
        assert!(!result.passed);
    }

    #[test]
    fn manufacturing_gate_empty_input_rejected() {
        let result = manufacturing_gate(&[]);
        assert!(!result.passed);
        assert_eq!(result.sigma_device, 0.0);
    }

    #[test]
    fn manufacturing_gate_identical_samples_rejected() {
        // No variance across trials -> sigma_device = 0 -> fail.
        let h_bars = vec![0.6f32; 16];
        let result = manufacturing_gate(&h_bars);
        assert!(!result.passed);
        assert!(result.sigma_device < 1e-5);
    }
}
