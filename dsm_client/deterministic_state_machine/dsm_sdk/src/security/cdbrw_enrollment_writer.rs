// SPDX-License-Identifier: MIT OR Apache-2.0
//! C-DBRW §6.1 enrollment writer — pure Rust replacement for the Kotlin
//! `SiliconFingerprint.enroll()` + `EnrollmentStore.write()` path.
//!
//! Kotlin's job is reduced to running the NDK silicon-PUF probe `K` times
//! and shuttling the raw orbit timings into [`CdbrwEnrollRequest`] — the
//! frontend never handles histograms, Wasserstein-1 distances, or the
//! attractor commitment.
//!
//! ## What this module guarantees
//!
//! - Builds `K` histograms using the same min/max/linear bucketing path as
//!   [`cdbrw_responder::build_histogram`] (byte-for-byte parity with Kotlin
//!   `CdbrwMath.buildHistogram`).
//! - Runs the manufacturing gate (§6.1) over the per-trial `Ĥ` values, with
//!   the same `σ_device = std(Ĥ) / max(Ĥ)` criterion the Kotlin path used.
//!   A failing gate becomes a non-fatal warning embedded in the published
//!   trust snapshot `note` so the responder layer decides the final verdict.
//! - Computes `epsilon_intra` as the P95 of Wasserstein-1 distances between
//!   each trial histogram and the mean histogram.
//! - Builds `anchorInput = meanBytes_LE ‖ epsilonBytes_BE ‖ metadataBytes`
//!   using the exact Kotlin layout (see `SiliconFingerprint.enroll`):
//!     - `meanBytes_LE` — little-endian f32 via
//!       [`cdbrw_responder::histogram_to_bytes`]
//!     - `epsilonBytes_BE` — big-endian f32 (matches Java
//!       `ByteBuffer.allocate(4).putFloat(ε_intra)`, which defaults to BE)
//!     - `metadataBytes` — `[binsLo, binsHi, rot, probesLo]`, matching
//!       `SiliconFingerprint.enroll` one-for-one
//! - Computes `AC_D = BLAKE3_keyed("DSM/silicon_fp/v4" ‖ NUL, env ‖ anchorInput)`
//!   via [`dsm::crypto::blake3::domain_hash_bytes`], which appends the NUL
//!   terminator so we stay in parity with Kotlin `CdbrwBlake3Native`.
//! - Serializes the enrollment to `dsm_silicon_fp_v4.bin` using the exact
//!   big-endian layout consumed by [`handlers::misc_routes::load_cdbrw_enrollment`]
//!   so existing readers keep working across the Kotlin→Rust cutover.
//! - Publishes a [`TrustSnapshot`] through the access gate using the first
//!   trial's health metrics (post-enrollment the device is either
//!   [`AccessLevel::FullAccess`] or degraded per health classification),
//!   so the gate is hot immediately after enrollment completes.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::cdbrw_moments::{compute_moments, tolerance_ball, MomentVector};

use crate::security::cdbrw_access_gate::{ResonantStatus, TrustSnapshot};
use crate::security::cdbrw_ffi::{self, BinRange, HealthResult, MfgGateResult};
use crate::security::cdbrw_responder::{
    build_histogram_in_range, classify_resonant_m_sample, histogram_to_bytes, mean_histogram,
    publish_trust_snapshot, wasserstein1, ADMISSION_M, DEFAULT_DISTANCE_MARGIN,
    DEFAULT_HISTOGRAM_BINS,
};

/// Wire revision written to `dsm_silicon_fp_v4.bin`.
///
/// Phase 9 (median-of-M admission) bumps this to **7**.  The file now
/// also carries `admission_m`, `trials_per_sample`, and per-sample
/// `h_hat`/`rho_hat`/`l_hat`/`epsilon_intra` arrays appended after the
/// v6 bin_range fields.  This makes the audit trail explicit: the
/// reader sees the full M-sample variance band that the device cleared
/// admission against, not just the median'd verdict.
///
/// Readers handle all four revisions (4 = no envelope, 5 = envelope,
/// 6 = bin_range, 7 = admission samples).  Revision-4/5/6 enrollments
/// invalidate under the new code path because the admission verdict
/// itself is structurally different (median over M vs single K-trial);
/// affected devices must re-enroll on first boot under v7.
pub const ENROLLMENT_REVISION: u32 = 7;

/// Filename consumed by [`handlers::misc_routes::load_cdbrw_enrollment`] via
/// `CDBRW_ENROLLMENT_FILE`. Hard-coding here keeps the writer and reader in
/// lockstep — any rename must touch both modules.
pub const ENROLLMENT_FILE_NAME: &str = "dsm_silicon_fp_v4.bin";

/// Minimum number of enrollment trials per C-DBRW §6.1. Writer rejects
/// requests with fewer trials — the Kotlin path allowed odd `K ≥ 1` values,
/// but the spec is explicit that `K ≥ 16` is required for stable σ_device
/// estimation. `K = 21` is the default used by the Kotlin
/// `SiliconFingerprint.Config`.
pub const MIN_ENROLL_TRIALS: usize = 16;

/// Inputs required by [`enroll_device`]. Borrowed view so the router
/// dispatch path does not have to clone the incoming proto trial vectors.
pub struct EnrollInputs<'a> {
    /// Device environment fingerprint (Build.BOARD, Build.HARDWARE, etc.)
    /// UTF-8 encoded with the `DSM/silicon_env/v2\0` prefix already applied
    /// by Kotlin. Opaque to Rust — never parsed, only hashed.
    pub env_bytes: &'a [u8],
    /// `M * trials_per_sample` orbit timing vectors. Each entry is the
    /// raw output of the NDK silicon-PUF probe.  Length must equal
    /// `M * trials_per_sample` where M is supplied via
    /// [`Self::admission_samples`].  Phase 9: callers batch all
    /// admission samples into one request so partitioning is a Rust-side
    /// invariant and there is no half-written intermediate file.
    pub trials: &'a [Vec<i64>],
    /// Per-trial CSPRNG challenges (Alg 2 line 1491). Parallel to `trials`
    /// — `trial_challenges[i]` is the 32-byte challenge that seeded the
    /// orbit producing `trials[i]`. Each entry must be 32 bytes and at
    /// least one byte non-zero; the writer rejects enrollments where any
    /// trial is missing or all-zero so a regression that strips
    /// per-trial challenges fails closed instead of silently downgrading
    /// to a challenge-independent orbit.
    pub trial_challenges: &'a [Vec<u8>],
    /// Enrollment config — mirrored from Kotlin `SiliconFingerprint.Config`.
    /// Stored on-disk and checked by the verifier at runtime to detect
    /// downgrade attempts.
    pub arena_bytes: u32,
    pub probes: u32,
    pub steps_per_probe: u32,
    pub histogram_bins: u32,
    pub rotation_bits: u32,
    /// Phase 9 admission protocol: number of independent K-trial
    /// samples in `trials`. The writer partitions `trials` into M
    /// contiguous chunks of `trials_per_sample` each and runs the
    /// median-of-M admission via
    /// [`classify_resonant_m_sample`]. Caller MUST match the SDK's
    /// compiled [`ADMISSION_M`] constant — a mismatch rejects the
    /// enrollment as `AdmissionShapeMismatch` defense-in-depth against
    /// version skew.
    pub admission_samples: u32,
    /// Phase 9: chunk size (K).  Must satisfy
    /// `trials_per_sample >= MIN_ENROLL_TRIALS`. The writer rejects
    /// `trials.len() != admission_samples * trials_per_sample`.
    pub trials_per_sample: u32,
}

/// Successful output — everything the router needs to build a
/// [`generated::CdbrwEnrollResponse`] plus the published trust snapshot.
#[derive(Debug)]
pub struct EnrollOutputs {
    pub revision: u32,
    pub epsilon_intra: f32,
    pub mean_histogram_len: u32,
    /// First 10 bytes of `AC_D`, used only for UI display. The full anchor
    /// is stored on disk and also returned inside `trust.w1_threshold = 0.0`
    /// snapshots — no secret material.
    pub reference_anchor_prefix: Vec<u8>,
    /// Full 32-byte `AC_D` attractor commitment. Returned to the Kotlin
    /// bootstrap layer so it can stash the anchor in SharedPreferences and
    /// ship it back as the opaque `cdbrw_hw_entropy` input to
    /// [`PlatformContext::bootstrap`] — this keeps K_DBRW derivation
    /// consistent between the freshly-enrolled device and subsequent boots.
    pub reference_anchor: [u8; 32],
    /// Phase 3 deliverable 3 (attractor envelope test) — eight statistical
    /// moments of the enrolled mean histogram, committed at enrollment and
    /// re-checked at every verification. See `dsm::crypto::cdbrw_moments`.
    pub baseline_moments: MomentVector,
    /// Per-moment acceptance radius derived from per-trial moment spread.
    /// At verification time the verifier asserts
    /// `|live_moments[i] - baseline_moments[i]| ≤ tolerance_ball[i]`
    /// for every i in 0..ENVELOPE_MOMENT_COUNT.
    pub tolerance_ball: MomentVector,
    pub trust: TrustSnapshot,
    pub note: String,
    /// Phase 9 admission audit: per-sample (h_hat, rho_hat, l_hat,
    /// epsilon_intra) for each of the M chunks. Length == admission_m.
    /// The Kotlin side logs these so a marginal device's variance band
    /// is visible without parsing the binary file.
    pub admission_samples: Vec<SampleAuditRecord>,
}

/// Phase 9: per-sample audit data captured during the M-sample
/// admission protocol.  Persisted on-disk in v7 layout and reported back
/// via [`EnrollOutputs`] so logs surface the full variance envelope of
/// a marginal device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SampleAuditRecord {
    pub h_hat: f32,
    pub rho_hat: f32,
    pub l_hat: f32,
    pub epsilon_intra: f32,
}

/// Failure modes for enrollment. Each variant publishes a fail-closed trust
/// snapshot before returning so the gate observes the failure even if the
/// caller drops the error.
#[derive(Debug)]
pub enum EnrollError {
    /// Fewer than [`MIN_ENROLL_TRIALS`] trials were supplied.
    InsufficientTrials { got: usize },
    /// One or more trials had zero timing samples.
    EmptyTrial { index: usize },
    /// `histogram_bins` was zero or not a power-of-two multiple of the
    /// Kotlin-approved set (256 / 512 / 1024). Keeping the same constraints
    /// as the Kotlin enrollment so anchors stay comparable.
    InvalidHistogramBins { bins: u32 },
    /// Per-trial challenge missing, wrong length, or all-zero (Alg 2 line
    /// 1491). A zero or absent challenge means the orbit wasn't actually
    /// challenge-seeded at the C++ layer — a spec violation we refuse to
    /// silently downgrade past.
    MissingTrialChallenge { index: usize, reason: &'static str },
    /// I/O error while writing `dsm_silicon_fp_v4.bin`.
    Io(String),
    /// Phase 9: `trials.len() != admission_samples * trials_per_sample`,
    /// or the supplied `admission_samples` doesn't equal the SDK's
    /// compiled `ADMISSION_M`. Defense-in-depth against version skew.
    AdmissionShapeMismatch {
        admission_samples: u32,
        trials_per_sample: u32,
        actual_trials: usize,
        expected_admission_m: u32,
    },
    /// Phase 9: M-sample admission classifier returned
    /// [`ResonantStatus::Fail`].  Carries the per-sample audit so the
    /// Kotlin side can log exactly which floor was hit on which sample.
    AdmissionRejected {
        samples: Vec<SampleAuditRecord>,
        median_h_hat: f32,
        median_rho_hat_abs: f32,
        median_l_hat: f32,
    },
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::InsufficientTrials { got } => write!(
                f,
                "insufficient enrollment trials: got {got}, need >= {MIN_ENROLL_TRIALS}"
            ),
            EnrollError::EmptyTrial { index } => {
                write!(f, "enrollment trial {index} has zero timing samples")
            }
            EnrollError::InvalidHistogramBins { bins } => {
                write!(f, "invalid histogram bin count {bins}")
            }
            EnrollError::MissingTrialChallenge { index, reason } => {
                write!(f, "enrollment trial {index} challenge invalid: {reason}")
            }
            EnrollError::Io(msg) => write!(f, "enrollment I/O error: {msg}"),
            EnrollError::AdmissionShapeMismatch {
                admission_samples,
                trials_per_sample,
                actual_trials,
                expected_admission_m,
            } => write!(
                f,
                "admission shape mismatch: admission_samples={admission_samples} \
                 (expected {expected_admission_m}), trials_per_sample={trials_per_sample}, \
                 trials.len()={actual_trials} (expected admission_samples * trials_per_sample)"
            ),
            EnrollError::AdmissionRejected {
                samples,
                median_h_hat,
                median_rho_hat_abs,
                median_l_hat,
            } => write!(
                f,
                "admission rejected: median H={median_h_hat:.4} |rho|={median_rho_hat_abs:.4} \
                 L={median_l_hat:.4} over {} samples — at least one sample below hard floor or \
                 median below H_HAT_WARN",
                samples.len()
            ),
        }
    }
}

impl std::error::Error for EnrollError {}

/// Run K-trial enrollment and persist the reference snapshot.
///
/// # Flow
///
/// 1. Validate the incoming trial list (§6.1 preconditions).
/// 2. For each trial: run the 3-condition health test and build its
///    histogram. Health metrics are averaged across trials for the final
///    snapshot so a single noisy probe does not flip the overall verdict.
/// 3. Feed per-trial `Ĥ` values into [`cdbrw_ffi::manufacturing_gate`] —
///    a failure here degrades the snapshot note but does NOT abort
///    enrollment (Kotlin did the same: "proceeding with stored enrollment
///    and deferring final trust decision to verification policy").
/// 4. Compute the mean histogram and `epsilon_intra = P95(w1(h_i, mean))`.
/// 5. Build `anchorInput` and compute `AC_D` via domain-separated BLAKE3.
/// 6. Serialize to `dsm_silicon_fp_v4.bin` in big-endian layout.
/// 7. Publish a [`TrustSnapshot`] with averaged health metrics and the new
///    drift window (`w1_distance = 0.0`, `w1_threshold = ε_intra + margin`).
pub fn enroll_device(
    base_dir: &Path,
    inputs: &EnrollInputs<'_>,
) -> Result<EnrollOutputs, EnrollError> {
    // ---- step 1: validate ----
    // Phase 9: admission shape must match the SDK's compiled constants.
    if inputs.admission_samples as usize != ADMISSION_M {
        return Err(EnrollError::AdmissionShapeMismatch {
            admission_samples: inputs.admission_samples,
            trials_per_sample: inputs.trials_per_sample,
            actual_trials: inputs.trials.len(),
            expected_admission_m: ADMISSION_M as u32,
        });
    }
    if (inputs.trials_per_sample as usize) < MIN_ENROLL_TRIALS {
        return Err(EnrollError::InsufficientTrials {
            got: inputs.trials_per_sample as usize,
        });
    }
    let expected_total =
        (inputs.admission_samples as usize).saturating_mul(inputs.trials_per_sample as usize);
    if inputs.trials.len() != expected_total {
        return Err(EnrollError::AdmissionShapeMismatch {
            admission_samples: inputs.admission_samples,
            trials_per_sample: inputs.trials_per_sample,
            actual_trials: inputs.trials.len(),
            expected_admission_m: ADMISSION_M as u32,
        });
    }
    let bins = if inputs.histogram_bins == 0 {
        DEFAULT_HISTOGRAM_BINS
    } else {
        inputs.histogram_bins as usize
    };
    // Match the Kotlin `Config.init` constraint (256/512/1024 only).
    if !matches!(bins, 256 | 512 | 1024) {
        return Err(EnrollError::InvalidHistogramBins {
            bins: inputs.histogram_bins,
        });
    }
    for (i, trial) in inputs.trials.iter().enumerate() {
        if trial.is_empty() {
            return Err(EnrollError::EmptyTrial { index: i });
        }
    }
    if inputs.trial_challenges.len() != inputs.trials.len() {
        return Err(EnrollError::MissingTrialChallenge {
            index: inputs.trial_challenges.len().min(inputs.trials.len()),
            reason: "challenge count must equal trial count",
        });
    }
    for (i, challenge) in inputs.trial_challenges.iter().enumerate() {
        if challenge.len() != 32 {
            return Err(EnrollError::MissingTrialChallenge {
                index: i,
                reason: "challenge must be exactly 32 bytes",
            });
        }
        if challenge.iter().all(|&b| b == 0) {
            return Err(EnrollError::MissingTrialChallenge {
                index: i,
                reason: "challenge is all zero — orbit was not CSPRNG-seeded",
            });
        }
    }

    // ---- step 2a: compute the robust binning range across the
    //               FULL M×K-trial sample set.  Same Phase-2 robust
    //               [P0.5, P99.5] trimming, expanded scope: every
    //               sample chunk's histograms must live in the same
    //               bin space so cross-chunk medians of mean
    //               histograms remain meaningful.
    let total_samples: usize = inputs.trials.iter().map(|t| t.len()).sum();
    let mut all_samples = Vec::with_capacity(total_samples);
    for trial in inputs.trials {
        all_samples.extend_from_slice(trial);
    }
    let bin_range = BinRange::from_samples_robust(
        &all_samples,
        crate::security::cdbrw_responder::ROBUST_BIN_LOW_PCT,
        crate::security::cdbrw_responder::ROBUST_BIN_HIGH_PCT,
    );

    // ---- step 2b: M-sample composition.  Partition `trials` into M
    //               contiguous chunks of `trials_per_sample` each; for
    //               each chunk run the existing per-trial health +
    //               histogram + mean + epsilon_intra + moment flow,
    //               then take element-wise medians across the M chunks
    //               to produce the persisted reference.
    let k = inputs.trials_per_sample as usize;
    let m = inputs.admission_samples as usize;

    let mut sample_mean_hists: Vec<Vec<f32>> = Vec::with_capacity(m);
    let mut sample_eps_intra: Vec<f32> = Vec::with_capacity(m);
    let mut sample_baseline_moments: Vec<MomentVector> = Vec::with_capacity(m);
    let mut sample_tolerance: Vec<MomentVector> = Vec::with_capacity(m);
    let mut sample_health: Vec<HealthResult> = Vec::with_capacity(m);
    let mut sample_h_bars: Vec<Vec<f32>> = Vec::with_capacity(m);

    for chunk_idx in 0..m {
        let start = chunk_idx * k;
        let end = start + k;
        let chunk = &inputs.trials[start..end];

        let mut chunk_histograms: Vec<Vec<f32>> = Vec::with_capacity(k);
        let mut chunk_healths: Vec<HealthResult> = Vec::with_capacity(k);
        let mut chunk_h_bars: Vec<f32> = Vec::with_capacity(k);
        let mut chunk_h_sum = 0.0f32;
        let mut chunk_rho_sum = 0.0f32;
        let mut chunk_l_sum = 0.0f32;
        for trial in chunk {
            let hist = build_histogram_in_range(trial, bins, bin_range);
            let health = cdbrw_ffi::health_test_in_range(trial, bins, bin_range);
            chunk_h_bars.push(health.h_hat);
            chunk_h_sum += health.h_hat;
            chunk_rho_sum += health.rho_hat;
            chunk_l_sum += health.l_hat;
            chunk_histograms.push(hist);
            chunk_healths.push(health);
        }
        let n_inv = 1.0 / k as f32;
        let chunk_health = HealthResult {
            h_hat: chunk_h_sum * n_inv,
            rho_hat: chunk_rho_sum * n_inv,
            l_hat: chunk_l_sum * n_inv,
            passed: chunk_healths.iter().all(|h| h.passed),
        };

        let hist_refs: Vec<&[f32]> = chunk_histograms.iter().map(|h| h.as_slice()).collect();
        let chunk_mean = mean_histogram(&hist_refs);

        let mut chunk_distances: Vec<f32> = chunk_histograms
            .iter()
            .map(|h| wasserstein1(h, &chunk_mean))
            .collect();
        chunk_distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p95_index = ((chunk_distances.len().saturating_sub(1)) * 95) / 100;
        let chunk_eps = chunk_distances.get(p95_index).copied().unwrap_or(0.0);

        let chunk_baseline = compute_moments(&chunk_mean);
        let per_trial_moments: Vec<MomentVector> = chunk_histograms
            .iter()
            .map(|h| compute_moments(h))
            .collect();
        let chunk_tol = tolerance_ball(&per_trial_moments);

        sample_mean_hists.push(chunk_mean);
        sample_eps_intra.push(chunk_eps);
        sample_baseline_moments.push(chunk_baseline);
        sample_tolerance.push(chunk_tol);
        sample_health.push(chunk_health);
        sample_h_bars.push(chunk_h_bars);
    }

    // Per-sample audit record (returned to caller + persisted on disk).
    let audit: Vec<SampleAuditRecord> = sample_health
        .iter()
        .zip(sample_eps_intra.iter())
        .map(|(h, eps)| SampleAuditRecord {
            h_hat: h.h_hat,
            rho_hat: h.rho_hat,
            l_hat: h.l_hat,
            epsilon_intra: *eps,
        })
        .collect();

    // ---- step 2c: M-sample admission verdict.  This is the gate
    //               that decides FULL_ACCESS vs READ_ONLY vs reject.
    let (admission_status, _admission_h0_eff, _recommended_n) =
        classify_resonant_m_sample(&sample_health);
    if admission_status == ResonantStatus::Fail {
        // Hard reject — compute median scalars for the error report
        // and publish a fail-closed snapshot before returning.  No
        // file written.
        let mut hs: Vec<f32> = sample_health.iter().map(|h| h.h_hat).collect();
        let mut rs: Vec<f32> = sample_health.iter().map(|h| h.rho_hat.abs()).collect();
        let mut ls: Vec<f32> = sample_health.iter().map(|h| h.l_hat).collect();
        let cmp = |a: &f32, b: &f32| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
        hs.sort_by(cmp);
        rs.sort_by(cmp);
        ls.sort_by(cmp);
        let mid = sample_health.len() / 2;
        let median_h = hs[mid];
        let median_r = rs[mid];
        let median_l = ls[mid];
        publish_trust_snapshot(
            HealthResult {
                h_hat: median_h,
                rho_hat: median_r,
                l_hat: median_l,
                passed: false,
            },
            0.0,
            0.0,
            &format!(
                "enroll_device: admission rejected over M={m} samples (median H={median_h:.3}, \
                 |rho|={median_r:.3}, L={median_l:.3})"
            ),
        );
        return Err(EnrollError::AdmissionRejected {
            samples: audit,
            median_h_hat: median_h,
            median_rho_hat_abs: median_r,
            median_l_hat: median_l,
        });
    }

    // ---- step 3: manufacturing gate over per-trial Ĥ aggregated
    //               across all M*K trials.  This stays a non-fatal
    //               signal — the admission verdict above is the real
    //               gate now.
    let mut all_h_bars: Vec<f32> = Vec::with_capacity(m * k);
    for chunk in &sample_h_bars {
        all_h_bars.extend_from_slice(chunk);
    }
    let mfg = cdbrw_ffi::manufacturing_gate(&all_h_bars);

    // ---- step 4: derive the persisted reference via element-wise
    //               median across the M sample mean histograms.  The
    //               resulting mean_hist is what every future
    //               measure_trust orbit gets W1-compared against, so
    //               it must reflect the *typical* device state, not
    //               an outlier-tail one.
    let mean_hist = element_wise_median_hist(&sample_mean_hists);

    let mut eps_sorted = sample_eps_intra.clone();
    eps_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let epsilon_intra = eps_sorted[m / 2];

    // Element-wise median across the M baseline moment vectors and the
    // M tolerance balls.  Each moment is independent so median per
    // index is well-defined.
    let baseline_moments = element_wise_median_moments(&sample_baseline_moments);
    let tolerance = element_wise_median_moments(&sample_tolerance);

    // ---- step 5: anchor input + AC_D ----
    // meanBytes_LE ‖ epsilonBytes_BE ‖ metadataBytes (4)
    let mean_bytes_le = histogram_to_bytes(&mean_hist);
    let epsilon_bytes_be = epsilon_intra.to_bits().to_be_bytes();
    let metadata_bytes = [
        (bins & 0xFF) as u8,
        ((bins >> 8) & 0xFF) as u8,
        (inputs.rotation_bits & 0xFF) as u8,
        (inputs.probes & 0xFF) as u8,
    ];

    let mut anchor_input =
        Vec::with_capacity(mean_bytes_le.len() + epsilon_bytes_be.len() + metadata_bytes.len());
    anchor_input.extend_from_slice(&mean_bytes_le);
    anchor_input.extend_from_slice(&epsilon_bytes_be);
    anchor_input.extend_from_slice(&metadata_bytes);

    // Fold the median'd baseline_moments + tolerance into the anchor
    // preimage so the anchor still commits to the envelope.
    for &v in baseline_moments.iter() {
        anchor_input.extend_from_slice(&v.to_le_bytes());
    }
    for &v in tolerance.iter() {
        anchor_input.extend_from_slice(&v.to_le_bytes());
    }

    // `domain_hash_bytes` prepends the domain tag with a trailing NUL,
    // matching Kotlin `CdbrwBlake3Native.nativeBlake3DomainHash` convention.
    let mut preimage = Vec::with_capacity(inputs.env_bytes.len() + anchor_input.len());
    preimage.extend_from_slice(inputs.env_bytes);
    preimage.extend_from_slice(&anchor_input);
    let anchor32 = domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_SILICON_FP_V4, &preimage);

    // ---- step 6: serialize to disk (BE layout consumed by load_cdbrw_enrollment) ----
    let file_path = base_dir.join(ENROLLMENT_FILE_NAME);
    write_enrollment_file(
        &file_path,
        ENROLLMENT_REVISION,
        inputs.arena_bytes,
        inputs.probes,
        inputs.steps_per_probe,
        bins as u32,
        inputs.rotation_bits,
        epsilon_intra,
        &mean_hist,
        &anchor32,
        &baseline_moments,
        &tolerance,
        bin_range,
        inputs.admission_samples,
        inputs.trials_per_sample,
        &audit,
    )
    .map_err(|e| {
        // On I/O failure, publish a Blocked snapshot so the gate knows
        // enrollment was not actually persisted.
        publish_trust_snapshot(
            HealthResult {
                h_hat: 0.0,
                rho_hat: 0.0,
                l_hat: 0.0,
                passed: false,
            },
            0.0,
            0.0,
            &format!("enroll_device: write failed: {e}"),
        );
        EnrollError::Io(e)
    })?;

    // ---- step 7: publish median trust snapshot ----
    let (median_health, note) = m_sample_health(&sample_health, mfg);
    let trust = publish_trust_snapshot(
        median_health,
        0.0,
        epsilon_intra + DEFAULT_DISTANCE_MARGIN,
        &note,
    );

    // Log per-sample h_hat so a marginal device's variance band shows
    // up directly in logcat without parsing the binary file.
    let per_sample_h: Vec<f32> = audit.iter().map(|s| s.h_hat).collect();
    log::info!(
        "[cdbrw_enroll] persisted M={} K={} bins={} eps_intra={:.6} \
         per_sample_h={:?} median_h={:.4} anchor_prefix={:02x?} access={} note={}",
        m,
        k,
        bins,
        epsilon_intra,
        per_sample_h,
        median_health.h_hat,
        &anchor32[..10.min(anchor32.len())],
        trust.access_level.as_str(),
        note
    );

    Ok(EnrollOutputs {
        revision: ENROLLMENT_REVISION,
        epsilon_intra,
        mean_histogram_len: mean_hist.len() as u32,
        reference_anchor_prefix: anchor32[..10.min(anchor32.len())].to_vec(),
        reference_anchor: anchor32,
        baseline_moments,
        tolerance_ball: tolerance,
        trust,
        note,
        admission_samples: audit,
    })
}

/// Element-wise median of M equal-length histograms.  For each bin
/// index, sort the M values and pick the middle one.  Re-normalises so
/// the resulting histogram still sums to 1.0 (medians of a
/// distribution don't preserve the unit-sum invariant under arbitrary
/// noise — we explicitly renormalise to keep W1 math meaningful).
fn element_wise_median_hist(samples: &[Vec<f32>]) -> Vec<f32> {
    if samples.is_empty() {
        return Vec::new();
    }
    let bins = samples[0].len();
    if bins == 0 {
        return Vec::new();
    }
    let m = samples.len();
    let mid = m / 2;
    let mut out = Vec::with_capacity(bins);
    let mut col = vec![0.0f32; m];
    let cmp = |a: &f32, b: &f32| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    for b in 0..bins {
        for (i, s) in samples.iter().enumerate() {
            col[i] = if b < s.len() { s[b] } else { 0.0 };
        }
        col.sort_by(cmp);
        out.push(col[mid]);
    }
    // Renormalise.
    let total: f32 = out.iter().sum();
    if total > 1e-12 {
        for v in out.iter_mut() {
            *v /= total;
        }
    } else {
        out.fill(0.0);
        out[0] = 1.0;
    }
    out
}

/// Element-wise median across M moment vectors.  Each moment slot is
/// independent so per-index median is well-defined.
fn element_wise_median_moments(samples: &[MomentVector]) -> MomentVector {
    let mut out: MomentVector = [0.0; dsm::crypto::cdbrw_moments::ENVELOPE_MOMENT_COUNT];
    let m = samples.len();
    if m == 0 {
        return out;
    }
    let mid = m / 2;
    for i in 0..out.len() {
        let mut col: Vec<f64> = samples.iter().map(|s| s[i]).collect();
        col.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        out[i] = col[mid];
    }
    out
}

/// Build a HealthResult carrying the median of M samples for the
/// published TrustSnapshot.  Mirrors the single-sample `averaged_health`
/// but uses medians (resistant to the same outliers the admission rule
/// is designed to absorb).
fn m_sample_health(samples: &[HealthResult], mfg: MfgGateResult) -> (HealthResult, String) {
    if samples.is_empty() {
        return (
            HealthResult {
                h_hat: 0.0,
                rho_hat: 0.0,
                l_hat: 0.0,
                passed: false,
            },
            "enroll_device: no sample health results".to_string(),
        );
    }
    let mut hs: Vec<f32> = samples.iter().map(|s| s.h_hat).collect();
    let mut rs: Vec<f32> = samples.iter().map(|s| s.rho_hat).collect();
    let mut ls: Vec<f32> = samples.iter().map(|s| s.l_hat).collect();
    let cmp = |a: &f32, b: &f32| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    hs.sort_by(cmp);
    rs.sort_by(cmp);
    ls.sort_by(cmp);
    let mid = samples.len() / 2;
    let median_h = hs[mid];
    let median_r = rs[mid];
    let median_l = ls[mid];
    let passed = samples.iter().all(|s| s.passed);
    let note = if mfg.passed {
        format!(
            "enroll_device: M={} K-trial samples, median h_hat={:.4} sigma_device={:.4} (mfg passed)",
            samples.len(),
            median_h,
            mfg.sigma_device
        )
    } else {
        format!(
            "enroll_device: M={} K-trial samples, median h_hat={:.4} sigma_device={:.4} (mfg \
             below target — verifier decides)",
            samples.len(),
            median_h,
            mfg.sigma_device
        )
    };
    (
        HealthResult {
            h_hat: median_h,
            rho_hat: median_r,
            l_hat: median_l,
            passed,
        },
        note,
    )
}

/// Serialize the enrollment snapshot to `path`.
///
/// Layout (big-endian, revision 7):
///
/// ```text
/// u32 BE  revision (4 .. 7)
/// u32 BE  arena_bytes
/// u32 BE  probes
/// u32 BE  steps_per_probe
/// u32 BE  histogram_bins
/// u32 BE  rotation_bits
/// f32 BE  epsilon_intra
/// u32 BE  mean_histogram_len
/// [mean_histogram_len × f32 BE]
/// u32 BE  reference_anchor_len
/// [reference_anchor_len × u8]
/// ---- v5 envelope extension ----
/// [ENVELOPE_MOMENT_COUNT × f64 BE]   baseline_moments
/// [ENVELOPE_MOMENT_COUNT × f64 BE]   tolerance_ball
/// ---- v6 bin_range extension ----
/// i64 BE  bin_range_low
/// i64 BE  bin_range_high
/// ---- v7 admission extension (Phase 9) ----
/// u32 BE  admission_m
/// u32 BE  trials_per_sample
/// [admission_m × {f32 BE h_hat, f32 BE rho_hat, f32 BE l_hat, f32 BE epsilon_intra}]
/// ```
///
/// Writes via a buffered writer so the file is not partially flushed on
/// error — the old snapshot (if any) is overwritten atomically enough for
/// the "crash mid-write means re-enroll" guarantee we need.
#[allow(clippy::too_many_arguments)]
fn write_enrollment_file(
    path: &Path,
    revision: u32,
    arena_bytes: u32,
    probes: u32,
    steps_per_probe: u32,
    histogram_bins: u32,
    rotation_bits: u32,
    epsilon_intra: f32,
    mean_histogram: &[f32],
    reference_anchor: &[u8],
    baseline_moments: &MomentVector,
    tolerance_ball: &MomentVector,
    bin_range: BinRange,
    admission_m: u32,
    trials_per_sample: u32,
    admission_audit: &[SampleAuditRecord],
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
    }
    let tmp_path = path.with_extension("bin.tmp");
    let file = File::create(&tmp_path).map_err(|e| format!("create {tmp_path:?}: {e}"))?;
    let mut writer = BufWriter::new(file);

    writer
        .write_all(&revision.to_be_bytes())
        .map_err(|e| format!("write revision: {e}"))?;
    writer
        .write_all(&arena_bytes.to_be_bytes())
        .map_err(|e| format!("write arena_bytes: {e}"))?;
    writer
        .write_all(&probes.to_be_bytes())
        .map_err(|e| format!("write probes: {e}"))?;
    writer
        .write_all(&steps_per_probe.to_be_bytes())
        .map_err(|e| format!("write steps_per_probe: {e}"))?;
    writer
        .write_all(&histogram_bins.to_be_bytes())
        .map_err(|e| format!("write histogram_bins: {e}"))?;
    writer
        .write_all(&rotation_bits.to_be_bytes())
        .map_err(|e| format!("write rotation_bits: {e}"))?;
    writer
        .write_all(&epsilon_intra.to_bits().to_be_bytes())
        .map_err(|e| format!("write epsilon_intra: {e}"))?;

    let mean_len = mean_histogram.len() as u32;
    writer
        .write_all(&mean_len.to_be_bytes())
        .map_err(|e| format!("write mean_histogram_len: {e}"))?;
    for v in mean_histogram {
        writer
            .write_all(&v.to_bits().to_be_bytes())
            .map_err(|e| format!("write mean_histogram: {e}"))?;
    }

    let anchor_len = reference_anchor.len() as u32;
    writer
        .write_all(&anchor_len.to_be_bytes())
        .map_err(|e| format!("write reference_anchor_len: {e}"))?;
    writer
        .write_all(reference_anchor)
        .map_err(|e| format!("write reference_anchor: {e}"))?;

    // v5 envelope extension — 8 × f64 BE baseline moments followed by
    // 8 × f64 BE tolerance ball. Readers gated on revision ≥ 5.
    if revision >= 5 {
        for v in baseline_moments.iter() {
            writer
                .write_all(&v.to_bits().to_be_bytes())
                .map_err(|e| format!("write baseline_moments: {e}"))?;
        }
        for v in tolerance_ball.iter() {
            writer
                .write_all(&v.to_bits().to_be_bytes())
                .map_err(|e| format!("write tolerance_ball: {e}"))?;
        }
    }

    // v6 bin_range extension — two i64 BE describing the robust
    // [P0.5, P99.5] binning range used to build the per-trial
    // histograms.  Readers gated on revision ≥ 6.  Without this the
    // measure_trust path can't reproduce the same bin space the
    // enrollment used, breaking mean-histogram + W1 alignment.
    if revision >= 6 {
        writer
            .write_all(&bin_range.low.to_be_bytes())
            .map_err(|e| format!("write bin_range.low: {e}"))?;
        writer
            .write_all(&bin_range.high.to_be_bytes())
            .map_err(|e| format!("write bin_range.high: {e}"))?;
    }

    // v7 admission extension (Phase 9) — admission_m + trials_per_sample
    // followed by per-sample (h_hat, rho_hat, l_hat, epsilon_intra)
    // quartets.  Readers gated on revision ≥ 7.  Lets the auditor see
    // the full M-sample variance band that cleared admission.
    if revision >= 7 {
        writer
            .write_all(&admission_m.to_be_bytes())
            .map_err(|e| format!("write admission_m: {e}"))?;
        writer
            .write_all(&trials_per_sample.to_be_bytes())
            .map_err(|e| format!("write trials_per_sample: {e}"))?;
        for s in admission_audit {
            writer
                .write_all(&s.h_hat.to_bits().to_be_bytes())
                .map_err(|e| format!("write admission h_hat: {e}"))?;
            writer
                .write_all(&s.rho_hat.to_bits().to_be_bytes())
                .map_err(|e| format!("write admission rho_hat: {e}"))?;
            writer
                .write_all(&s.l_hat.to_bits().to_be_bytes())
                .map_err(|e| format!("write admission l_hat: {e}"))?;
            writer
                .write_all(&s.epsilon_intra.to_bits().to_be_bytes())
                .map_err(|e| format!("write admission epsilon_intra: {e}"))?;
        }
    }

    writer.flush().map_err(|e| format!("flush: {e}"))?;
    // Rename the tmp file over the final path so readers never see a
    // half-written file.
    fs::rename(&tmp_path, path).map_err(|e| format!("rename {tmp_path:?} -> {path:?}: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::cdbrw_access_gate::{
        clear_trust_for_test, gate_test_mutex, latest_trust, AccessLevel,
    };
    use std::io::Cursor;
    use std::io::Read;
    use tempfile::TempDir;

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

    fn read_u32_be(cursor: &mut Cursor<&[u8]>) -> u32 {
        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf).expect("read u32");
        u32::from_be_bytes(buf)
    }

    fn read_f32_be(cursor: &mut Cursor<&[u8]>) -> f32 {
        let mut buf = [0u8; 4];
        cursor.read_exact(&mut buf).expect("read f32");
        f32::from_bits(u32::from_be_bytes(buf))
    }

    /// Build a synthetic set of orbit timings that look sufficiently
    /// "random" for the entropy health test to pass under the Phase 9
    /// per-sample admission gates.  Uses pure LCG output (no linear
    /// ramp) so consecutive samples are statistically independent — the
    /// pre-Phase-9 fixture added an `i*100` ramp which produced
    /// `rho_hat ≈ 0.9`, well above the new `RHO_HAT_HARD_REJECT=0.40`
    /// floor.
    fn synthetic_timings(seed: u64, n: usize) -> Vec<i64> {
        let mut state = seed.wrapping_add(0x9E3779B97F4A7C15);
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Take 24 bits of the LCG state to get a wide spread —
                // the original 16-bit window was too narrow for the
                // robust-binning histogram math.
                ((state >> 16) as i64) & 0x00FF_FFFF
            })
            .collect()
    }

    /// One distinct 32-byte non-zero challenge per trial. Mirrors what the
    /// Android side does with `SecureRandom().nextBytes(challenge)`.
    fn synthetic_challenges(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut c = vec![0u8; 32];
                for (j, b) in c.iter_mut().enumerate() {
                    *b = ((i + 1) as u8).wrapping_add(j as u8).wrapping_mul(13);
                }
                // Force the first byte non-zero so the all-zero guard never
                // trips for the synthetic fixture.
                c[0] |= 0x01;
                c
            })
            .collect()
    }

    /// Total trial count for M-sample admission shape: M*K trials.  Tests
    /// that use this constant pass the same number of challenges.
    const TOTAL_TRIALS: usize = ADMISSION_M * MIN_ENROLL_TRIALS;

    #[test]
    fn enroll_rejects_too_few_trials_per_sample() {
        let dir = TempDir::new().expect("tempdir");
        // trials_per_sample below MIN_ENROLL_TRIALS, total = M*(K-1).
        let bad_k = MIN_ENROLL_TRIALS - 1;
        let total = ADMISSION_M * bad_k;
        let trials: Vec<Vec<i64>> = (0..total)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let challenges = synthetic_challenges(trials.len());
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: bad_k as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::InsufficientTrials { .. }));
    }

    #[test]
    fn enroll_rejects_admission_shape_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        // M*K-1 trials with the writer expecting M*K — shape mismatch.
        let total = ADMISSION_M * MIN_ENROLL_TRIALS - 1;
        let trials: Vec<Vec<i64>> = (0..total)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let challenges = synthetic_challenges(trials.len());
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::AdmissionShapeMismatch { .. }));
    }

    #[test]
    fn enroll_rejects_wrong_admission_m() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let challenges = synthetic_challenges(trials.len());
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: (ADMISSION_M as u32) + 1, // wrong M
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::AdmissionShapeMismatch { .. }));
    }

    #[test]
    fn enroll_rejects_bad_bin_count() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let challenges = synthetic_challenges(trials.len());
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 77,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::InvalidHistogramBins { .. }));
    }

    #[test]
    fn enroll_rejects_missing_challenge() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        // One fewer challenge than trial — count mismatch.
        let challenges = synthetic_challenges(trials.len() - 1);
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::MissingTrialChallenge { .. }));
    }

    #[test]
    fn enroll_rejects_all_zero_challenge() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let mut challenges = synthetic_challenges(trials.len());
        challenges[3] = vec![0u8; 32];
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(
            err,
            EnrollError::MissingTrialChallenge { index: 3, .. }
        ));
    }

    #[test]
    fn enroll_rejects_wrong_length_challenge() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let mut challenges = synthetic_challenges(trials.len());
        challenges[0] = vec![0xFFu8; 16]; // half-length
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(
            err,
            EnrollError::MissingTrialChallenge { index: 0, .. }
        ));
    }

    #[test]
    fn enroll_rejects_empty_trial() {
        let dir = TempDir::new().expect("tempdir");
        let mut trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        trials[5] = Vec::new();
        let challenges = synthetic_challenges(trials.len());
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            trial_challenges: &challenges,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
            admission_samples: ADMISSION_M as u32,
            trials_per_sample: MIN_ENROLL_TRIALS as u32,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::EmptyTrial { index: 5 }));
    }

    #[test]
    fn enroll_writes_expected_v7_binary_layout() {
        with_clean_state(|| {
            let dir = TempDir::new().expect("tempdir");
            let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
                .map(|i| synthetic_timings(i as u64 + 1, 2048))
                .collect();
            let challenges = synthetic_challenges(trials.len());
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0BOARD|BRAND|DEVICE|HW|MFG|MODEL|SOC|com.test",
                trials: &trials,
                trial_challenges: &challenges,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
                admission_samples: ADMISSION_M as u32,
                trials_per_sample: MIN_ENROLL_TRIALS as u32,
            };
            let out = enroll_device(dir.path(), &inputs).expect("enroll");

            assert_eq!(out.revision, ENROLLMENT_REVISION);
            assert_eq!(out.mean_histogram_len, 256);
            assert!(out.epsilon_intra.is_finite());
            assert_eq!(out.reference_anchor_prefix.len(), 10);
            assert_eq!(out.admission_samples.len(), ADMISSION_M);

            // Parse the file we just wrote and confirm v7 layout.
            let bytes = fs::read(dir.path().join(ENROLLMENT_FILE_NAME)).expect("read bin");
            let mut cursor = Cursor::new(bytes.as_slice());
            assert_eq!(read_u32_be(&mut cursor), ENROLLMENT_REVISION);
            assert_eq!(read_u32_be(&mut cursor), 8 * 1024 * 1024); // arena_bytes
            assert_eq!(read_u32_be(&mut cursor), 4096); // probes
            assert_eq!(read_u32_be(&mut cursor), 4096); // steps_per_probe
            assert_eq!(read_u32_be(&mut cursor), 256); // histogram_bins
            assert_eq!(read_u32_be(&mut cursor), 7); // rotation_bits

            let eps = read_f32_be(&mut cursor);
            assert!((eps - out.epsilon_intra).abs() < 1e-6);

            let hist_len = read_u32_be(&mut cursor);
            assert_eq!(hist_len, 256);
            let mut mean_hist = vec![0.0f32; 256];
            for v in mean_hist.iter_mut() {
                *v = read_f32_be(&mut cursor);
            }
            let sum: f32 = mean_hist.iter().sum();
            assert!(
                (sum - 1.0).abs() < 1e-4,
                "mean histogram should be normalized, got sum={sum}"
            );

            let anchor_len = read_u32_be(&mut cursor);
            assert_eq!(anchor_len, 32);
            let mut anchor = vec![0u8; 32];
            cursor.read_exact(&mut anchor).expect("anchor");
            assert_eq!(&anchor[..10], out.reference_anchor_prefix.as_slice());
            assert_eq!(anchor.as_slice(), out.reference_anchor.as_slice());

            // v5 envelope: 8 baseline_moments + 8 tolerance_ball f64 BE.
            for _ in 0..(dsm::crypto::cdbrw_moments::ENVELOPE_MOMENT_COUNT * 2) {
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf).expect("envelope f64");
            }
            // v6 bin_range: 2 i64 BE.
            for _ in 0..2 {
                let mut buf = [0u8; 8];
                cursor.read_exact(&mut buf).expect("bin_range i64");
            }
            // v7 admission: m u32 + k u32 + M*(4*f32) = M*16 bytes.
            let m_read = read_u32_be(&mut cursor);
            let k_read = read_u32_be(&mut cursor);
            assert_eq!(m_read, ADMISSION_M as u32);
            assert_eq!(k_read, MIN_ENROLL_TRIALS as u32);
            for i in 0..(m_read as usize) {
                let h = read_f32_be(&mut cursor);
                let r = read_f32_be(&mut cursor);
                let l = read_f32_be(&mut cursor);
                let e = read_f32_be(&mut cursor);
                let audit = &out.admission_samples[i];
                assert!((h - audit.h_hat).abs() < 1e-6);
                assert!((r - audit.rho_hat).abs() < 1e-6);
                assert!((l - audit.l_hat).abs() < 1e-6);
                assert!((e - audit.epsilon_intra).abs() < 1e-6);
            }
        });
    }

    #[test]
    fn enroll_publishes_trust_snapshot() {
        with_clean_state(|| {
            let dir = TempDir::new().expect("tempdir");
            let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
                .map(|i| synthetic_timings(i as u64 + 1000, 4096))
                .collect();
            let challenges = synthetic_challenges(trials.len());
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0snapshot-test",
                trials: &trials,
                trial_challenges: &challenges,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
                admission_samples: ADMISSION_M as u32,
                trials_per_sample: MIN_ENROLL_TRIALS as u32,
            };
            let out = enroll_device(dir.path(), &inputs).expect("enroll");

            let latest = latest_trust().expect("trust published");
            assert_eq!(latest.iter, out.trust.iter);
            assert_ne!(
                latest.access_level,
                AccessLevel::Blocked,
                "enrollment should leave the gate hot, got {:?}",
                latest.access_level
            );
            assert!(latest.w1_distance.abs() < 1e-6);
            assert!(latest.w1_threshold >= out.epsilon_intra);
        });
    }

    #[test]
    fn enroll_atomic_tmp_rename() {
        // Enroll twice to confirm the tmp-rename logic overwrites cleanly.
        let dir = TempDir::new().expect("tempdir");
        for seed_base in [1u64, 9001u64] {
            let trials: Vec<Vec<i64>> = (0..TOTAL_TRIALS)
                .map(|i| synthetic_timings(seed_base + i as u64, 2048))
                .collect();
            let challenges = synthetic_challenges(trials.len());
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0rename-test",
                trials: &trials,
                trial_challenges: &challenges,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
                admission_samples: ADMISSION_M as u32,
                trials_per_sample: MIN_ENROLL_TRIALS as u32,
            };
            enroll_device(dir.path(), &inputs).expect("enroll");
        }
        let final_path = dir.path().join(ENROLLMENT_FILE_NAME);
        let tmp_path = final_path.with_extension("bin.tmp");
        assert!(final_path.exists(), "final file should exist");
        assert!(!tmp_path.exists(), "tmp file should have been renamed away");
    }
}
