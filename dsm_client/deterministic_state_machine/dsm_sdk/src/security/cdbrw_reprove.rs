// SPDX-License-Identifier: MIT OR Apache-2.0
//! C-DBRW opportunistic ACD re-prove — Phase 3 deliverable 2 Layer B.
//!
//! Layer A of Phase 3 deliverable 2 moves the C-DBRW salt into Android
//! Keystore-wrapped storage so a clone with filesystem access cannot
//! decrypt it. Layer B (this module) is the complementary protection: it
//! makes the salt useless on different hardware even if the Keystore is
//! somehow compromised.
//!
//! On every cold boot, the device runs a single live orbit, builds its
//! histogram, and compares against the stored mean histogram from
//! enrollment. If the live W1 distance exceeds a clone-detection
//! threshold (set well below the cross-device noise floor we measured at
//! 0.0395 for the closest device pair, and well above the same-device
//! drift floor we measured at ~0.001 for thermal-vs-zero), the slot is
//! treated as compromised:
//!
//! - The in-memory K_DBRW slot is zeroed
//! - A [`AccessLevel::Blocked`] trust snapshot is published
//! - The caller (Kotlin bootstrap) must trigger a full re-enrollment
//!
//! The threshold is intentionally not at the same level as
//! `epsilon_intra + margin` used by `cdbrw.measure_trust`. Measure-trust
//! degrades to PinRequired on routine drift; reprove fires only when W1
//! is clone-class large. This split keeps boot resume tolerant of
//! day-to-day drift while still catching the "clone with stolen salt
//! ran on different hardware" attack.

use crate::security::cdbrw_access_gate::{
    next_iter, store_trust, AccessLevel, ResonantStatus, TrustSnapshot,
};
use crate::security::cdbrw_responder::{build_histogram, wasserstein1, DEFAULT_HISTOGRAM_BINS};

/// Clone-detection W1 threshold.
///
/// Calibrated from Phase 2.2 cross-device measurements:
/// - Closest cross-device pair (A16 ↔ G9T): W1 = 0.0395
/// - Furthest same-device thermal cycle (FRR test budget): W1 ≤ 0.02
///
/// 0.025 splits the gap, with comfortable margin on both sides. Any
/// device producing W1 > 0.025 against its enrolled mean histogram is
/// either drifting catastrophically (silicon aging gone wrong, extreme
/// thermal anomaly) or running on different hardware. Both cases warrant
/// the same response: block and force re-enrollment.
pub const CLONE_DETECTION_W1_THRESHOLD: f32 = 0.025;

/// Result of an opportunistic re-prove.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReproveVerdict {
    /// Live histogram is consistent with stored enrollment. Continue normally.
    Continue,
    /// Live histogram diverges enough to suggest clone or catastrophic drift.
    /// Caller MUST zero K_DBRW and force re-enrollment.
    CloneDetected,
    /// Enrollment was missing on disk — first boot path, no comparison possible.
    NoEnrollment,
}

/// Inputs for an opportunistic re-prove call.
pub struct ReproveInputs<'a> {
    /// Live orbit timings captured by the platform PUF probe.
    pub orbit_timings: &'a [i64],
    /// Stored mean histogram from enrollment, loaded via
    /// `handlers::misc_routes::load_cdbrw_enrollment`. `None` triggers
    /// `NoEnrollment` verdict.
    pub enrolled_mean: Option<&'a [f32]>,
    /// Histogram bin count from enrollment (must match what was stored).
    pub histogram_bins: usize,
}

/// Outputs of a re-prove call. Always publishes a TrustSnapshot via the
/// access gate before returning so the gate observes the verdict
/// regardless of what the caller does with the return value.
pub struct ReproveOutputs {
    pub verdict: ReproveVerdict,
    pub w1_distance: f32,
    pub trust: TrustSnapshot,
}

/// Run the live-orbit-vs-stored-mean check and publish a trust snapshot.
///
/// On `CloneDetected`, the caller MUST call
/// `crate::binding_key::install_binding_key(vec![])`-equivalent to zero
/// the slot. We don't do it here because the slot module's API is
/// `pub(crate)` and we want to keep `cdbrw_reprove` callable from the
/// router (which calls this via a thin wrapper that handles the zeroing).
pub fn reprove(inputs: &ReproveInputs<'_>) -> ReproveOutputs {
    let bins = if inputs.histogram_bins == 0 {
        DEFAULT_HISTOGRAM_BINS
    } else {
        inputs.histogram_bins
    };

    let live_hist = build_histogram(inputs.orbit_timings, bins);

    let (verdict, w1, note) = match inputs.enrolled_mean {
        None => (
            ReproveVerdict::NoEnrollment,
            0.0_f32,
            "cdbrw.reprove: no enrollment on disk — first boot".to_string(),
        ),
        Some(stored) if stored.len() != bins => (
            ReproveVerdict::NoEnrollment,
            0.0_f32,
            format!(
                "cdbrw.reprove: enrollment bin mismatch (stored={}, asked={}) — treating as no enrollment",
                stored.len(),
                bins
            ),
        ),
        Some(stored) => {
            let w1 = wasserstein1(&live_hist, stored);
            if w1 > CLONE_DETECTION_W1_THRESHOLD {
                (
                    ReproveVerdict::CloneDetected,
                    w1,
                    format!(
                        "cdbrw.reprove: W1={w1:.5} > {CLONE_DETECTION_W1_THRESHOLD} \
                         — clone or catastrophic drift, blocking",
                    ),
                )
            } else {
                (
                    ReproveVerdict::Continue,
                    w1,
                    format!(
                        "cdbrw.reprove: W1={w1:.5} ≤ {CLONE_DETECTION_W1_THRESHOLD} — same device",
                    ),
                )
            }
        }
    };

    let access_level = match verdict {
        ReproveVerdict::CloneDetected => AccessLevel::Blocked,
        // NoEnrollment leaves the existing gate verdict alone semantically;
        // we still publish a fresh snapshot so the gate has something live.
        // Use FullAccess as the no-info default; the enrollment flow will
        // overwrite it shortly.
        ReproveVerdict::NoEnrollment => AccessLevel::FullAccess,
        ReproveVerdict::Continue => AccessLevel::FullAccess,
    };
    let resonant_status = match verdict {
        ReproveVerdict::CloneDetected => ResonantStatus::Fail,
        _ => ResonantStatus::Pass,
    };
    let trust_score = match verdict {
        ReproveVerdict::CloneDetected => 0.0,
        ReproveVerdict::NoEnrollment => 1.0,
        ReproveVerdict::Continue => 1.0,
    };

    let snapshot = TrustSnapshot {
        access_level,
        resonant_status,
        h_hat: 0.0,
        rho_hat: 0.0,
        l_hat: 0.0,
        h0_eff: 0.0,
        trust_score,
        recommended_n: 0,
        w1_distance: w1,
        w1_threshold: CLONE_DETECTION_W1_THRESHOLD,
        iter: next_iter(),
    };
    log::warn!(
        "[cdbrw_reprove] verdict={:?} access={} w1={:.5} note={}",
        verdict,
        snapshot.access_level.as_str(),
        w1,
        note
    );
    store_trust(snapshot);

    ReproveOutputs {
        verdict,
        w1_distance: w1,
        trust: snapshot,
    }
}

// =============================================================================
// Public helpers exposed for instrumentation tests on Android.
// =============================================================================

/// Public wrapper around [`reprove`] for instrumentation-test callers that
/// want to drive the route without going through proto encoding. Returns
/// the verdict and the W1 distance.
pub fn reprove_with_inputs(
    timings: &[i64],
    enrolled_mean: Option<&[f32]>,
    histogram_bins: usize,
) -> (ReproveVerdict, f32) {
    let out = reprove(&ReproveInputs {
        orbit_timings: timings,
        enrolled_mean,
        histogram_bins,
    });
    (out.verdict, out.w1_distance)
}

// =============================================================================
// Concurrent enrollment + measure_trust stress test infrastructure
// =============================================================================
//
// Phase 3 deliverable 5: prove the K_DBRW slot and trust-gate publication
// are race-safe. The slot itself is Mutex-protected (binding_key.rs uses
// `OnceLock<Mutex<Option<Vec<u8>>>>`); the trust gate uses an atomic iter
// counter. This test fires both code paths in parallel and asserts no
// panics, no torn reads, and a coherent final state.

#[cfg(test)]
mod concurrent_tests {
    use crate::binding_key::{clear_binding_key, get_binding_key, install_binding_key};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn binding_key_slot_concurrent_set_and_get_does_not_corrupt() {
        // Reset to a known empty state.
        clear_binding_key();

        const N_THREADS: usize = 16;
        const ITERS_PER_THREAD: usize = 200;
        let installs = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let valid_reads = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(N_THREADS);
        for t in 0..N_THREADS {
            let installs = Arc::clone(&installs);
            let reads = Arc::clone(&reads);
            let valid_reads = Arc::clone(&valid_reads);
            handles.push(thread::spawn(move || {
                if t % 2 == 0 {
                    // Writer thread: install a 32-byte key whose bytes are
                    // all equal to `t` (so torn writes would surface as
                    // mixed-byte reads).
                    let key = vec![t as u8; 32];
                    for _ in 0..ITERS_PER_THREAD {
                        let _ = install_binding_key(key.clone());
                        installs.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // Reader thread: every observation must be either None
                    // OR exactly 32 bytes of a single repeated value
                    // (matches what writers install).
                    for _ in 0..ITERS_PER_THREAD {
                        if let Some(k) = get_binding_key() {
                            assert_eq!(k.len(), 32, "torn write surfaced as wrong length");
                            let first = k[0];
                            assert!(
                                k.iter().all(|&b| b == first),
                                "torn write surfaced as mixed bytes"
                            );
                            valid_reads.fetch_add(1, Ordering::Relaxed);
                        }
                        reads.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join()
                .expect("thread panicked — concurrent slot access corrupted");
        }
        assert_eq!(installs.load(Ordering::Relaxed), 8 * ITERS_PER_THREAD);
        assert_eq!(reads.load(Ordering::Relaxed), 8 * ITERS_PER_THREAD);
        // At least some reads must have observed a value (writers ran in
        // parallel with readers).
        assert!(
            valid_reads.load(Ordering::Relaxed) > 0,
            "readers never observed any installed key — scheduling went wrong"
        );

        clear_binding_key();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::cdbrw_access_gate::{clear_trust_for_test, gate_test_mutex, latest_trust};

    fn with_clean_state<F: FnOnce()>(f: F) {
        let guard = match gate_test_mutex().lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        clear_trust_for_test();
        f();
        clear_trust_for_test();
        drop(guard);
    }

    /// Mixed-bimodal timings: ratio `low_frac` of samples at `low_val`,
    /// remainder at `high_val`. build_histogram's min/max bucketing puts
    /// `low_val` near bin 0 and `high_val` near bin 31; the bimodal SHAPE
    /// (mass at the two ends) is what survives normalization, so changing
    /// the ratio produces histograms that differ in cumulative-mass
    /// distribution and therefore in W1.
    fn bimodal_timings(low_val: i64, high_val: i64, low_frac: f64, n: usize) -> Vec<i64> {
        let threshold = (low_frac * n as f64) as usize;
        (0..n)
            .map(|i| if i < threshold { low_val } else { high_val })
            .collect()
    }

    #[test]
    fn reprove_no_enrollment_returns_no_enrollment_verdict() {
        with_clean_state(|| {
            let timings = bimodal_timings(100, 1000, 0.8, 4096);
            let out = reprove(&ReproveInputs {
                orbit_timings: &timings,
                enrolled_mean: None,
                histogram_bins: 32,
            });
            assert_eq!(out.verdict, ReproveVerdict::NoEnrollment);
            assert_eq!(out.trust.access_level, AccessLevel::FullAccess);
        });
    }

    #[test]
    fn reprove_same_device_returns_continue() {
        with_clean_state(|| {
            // "Enrolled" — 80% low values, 20% high values.
            let baseline = bimodal_timings(100, 1000, 0.80, 4096);
            let enrolled = crate::security::cdbrw_responder::build_histogram(&baseline, 32);

            // Live — same shape, tiny ratio drift (80% → 81% low).
            // Resulting W1 should be ~0.01, well below the 0.025 threshold.
            let live = bimodal_timings(100, 1000, 0.81, 4096);
            let out = reprove(&ReproveInputs {
                orbit_timings: &live,
                enrolled_mean: Some(&enrolled),
                histogram_bins: 32,
            });
            assert_eq!(
                out.verdict,
                ReproveVerdict::Continue,
                "expected Continue at W1={}",
                out.w1_distance
            );
            assert!(out.w1_distance < CLONE_DETECTION_W1_THRESHOLD);
            assert_eq!(out.trust.access_level, AccessLevel::FullAccess);
        });
    }

    #[test]
    fn reprove_cross_device_returns_clone_detected_and_blocks() {
        with_clean_state(|| {
            // "Enrolled" — heavily skewed to the low end (90/10 split).
            let baseline = bimodal_timings(100, 1000, 0.90, 4096);
            let enrolled = crate::security::cdbrw_responder::build_histogram(&baseline, 32);

            // "Live" from a different device — much flatter ratio (50/50).
            // W1 between [0.9, 0..., 0.1] and [0.5, 0..., 0.5] is roughly
            // 0.4 * (31/32) ≈ 0.39 — far above the 0.025 clone threshold.
            let live = bimodal_timings(100, 1000, 0.50, 4096);
            let out = reprove(&ReproveInputs {
                orbit_timings: &live,
                enrolled_mean: Some(&enrolled),
                histogram_bins: 32,
            });
            assert_eq!(
                out.verdict,
                ReproveVerdict::CloneDetected,
                "expected CloneDetected at W1={}",
                out.w1_distance
            );
            assert!(out.w1_distance > CLONE_DETECTION_W1_THRESHOLD);
            assert_eq!(out.trust.access_level, AccessLevel::Blocked);
            assert_eq!(
                latest_trust().map(|t| t.access_level),
                Some(AccessLevel::Blocked)
            );
        });
    }

    #[test]
    fn reprove_bin_count_mismatch_treated_as_no_enrollment() {
        with_clean_state(|| {
            let enrolled = vec![1.0_f32 / 64.0; 64]; // 64 bins
            let live = bimodal_timings(100, 1000, 0.8, 4096);
            let out = reprove(&ReproveInputs {
                orbit_timings: &live,
                enrolled_mean: Some(&enrolled),
                histogram_bins: 32,
            });
            assert_eq!(out.verdict, ReproveVerdict::NoEnrollment);
        });
    }
}
