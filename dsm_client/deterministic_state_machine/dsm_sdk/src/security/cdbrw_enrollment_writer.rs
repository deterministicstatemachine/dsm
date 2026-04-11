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

use crate::security::cdbrw_access_gate::TrustSnapshot;
use crate::security::cdbrw_ffi::{self, HealthResult, MfgGateResult};
use crate::security::cdbrw_responder::{
    build_histogram, histogram_to_bytes, mean_histogram, publish_trust_snapshot, wasserstein1,
    DEFAULT_DISTANCE_MARGIN, DEFAULT_HISTOGRAM_BINS,
};

/// Wire revision written to `dsm_silicon_fp_v4.bin`. Must match the Kotlin
/// `EnrollmentStore.write` revision (=4) and the `load_cdbrw_enrollment`
/// reader in `misc_routes.rs`.
pub const ENROLLMENT_REVISION: u32 = 4;

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
    /// `K` orbit timing vectors. Each entry is the raw output of the NDK
    /// silicon-PUF probe. Length must be `>= MIN_ENROLL_TRIALS`.
    pub trials: &'a [Vec<i64>],
    /// Enrollment config — mirrored from Kotlin `SiliconFingerprint.Config`.
    /// Stored on-disk and checked by the verifier at runtime to detect
    /// downgrade attempts.
    pub arena_bytes: u32,
    pub probes: u32,
    pub steps_per_probe: u32,
    pub histogram_bins: u32,
    pub rotation_bits: u32,
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
    pub trust: TrustSnapshot,
    pub note: String,
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
    /// I/O error while writing `dsm_silicon_fp_v4.bin`.
    Io(String),
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
            EnrollError::Io(msg) => write!(f, "enrollment I/O error: {msg}"),
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
    if inputs.trials.len() < MIN_ENROLL_TRIALS {
        return Err(EnrollError::InsufficientTrials {
            got: inputs.trials.len(),
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

    // ---- step 2: per-trial health + histograms ----
    let mut histograms: Vec<Vec<f32>> = Vec::with_capacity(inputs.trials.len());
    let mut health_results: Vec<HealthResult> = Vec::with_capacity(inputs.trials.len());
    let mut h_bars: Vec<f32> = Vec::with_capacity(inputs.trials.len());
    for trial in inputs.trials {
        let hist = build_histogram(trial, bins);
        let health = cdbrw_ffi::health_test(trial, bins);
        h_bars.push(health.h_hat);
        histograms.push(hist);
        health_results.push(health);
    }

    // ---- step 3: manufacturing gate over per-trial Ĥ (non-fatal) ----
    let mfg = cdbrw_ffi::manufacturing_gate(&h_bars);

    // ---- step 4: mean histogram + P95 intra-distance ----
    let hist_refs: Vec<&[f32]> = histograms.iter().map(|h| h.as_slice()).collect();
    let mean_hist = mean_histogram(&hist_refs);

    let mut distances: Vec<f32> = histograms
        .iter()
        .map(|h| wasserstein1(h, &mean_hist))
        .collect();
    // Kotlin: `sortedDistances[((n - 1) * 95) / 100]`. We mirror that index
    // exactly to keep `epsilon_intra` comparable across the cutover.
    // Safe partial_cmp — histograms only contain non-negative finite values.
    distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p95_index = ((distances.len().saturating_sub(1)) * 95) / 100;
    let epsilon_intra = distances.get(p95_index).copied().unwrap_or(0.0);

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

    // `domain_hash_bytes` prepends the domain tag with a trailing NUL,
    // matching Kotlin `CdbrwBlake3Native.nativeBlake3DomainHash` convention.
    // Keyed BLAKE3 over `env ‖ anchor_input` — same layout as Kotlin.
    let mut preimage = Vec::with_capacity(inputs.env_bytes.len() + anchor_input.len());
    preimage.extend_from_slice(inputs.env_bytes);
    preimage.extend_from_slice(&anchor_input);
    let anchor32 = domain_hash_bytes("DSM/silicon_fp/v4", &preimage);

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

    // ---- step 7: publish averaged trust snapshot ----
    let (avg_health, note) = averaged_health(&health_results, mfg);

    // Post-enrollment drift is identically zero (we just defined the mean),
    // and the threshold becomes the new `epsilon_intra + margin`.
    let trust = publish_trust_snapshot(
        avg_health,
        0.0,
        epsilon_intra + DEFAULT_DISTANCE_MARGIN,
        &note,
    );

    // Log the final state at info level. No secret material crosses the log
    // boundary — anchors are truncated and entropy metrics are scalars.
    log::info!(
        "[cdbrw_enroll] persisted K={} bins={} eps_intra={:.6} anchor_prefix={:02x?} access={} note={}",
        inputs.trials.len(),
        bins,
        epsilon_intra,
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
        trust,
        note,
    })
}

/// Average `h_hat`/`rho_hat`/`l_hat` across trials. Used for the post-enroll
/// trust snapshot so a single noisy probe can't swing the result. `passed`
/// is true iff every per-trial health test passed — same invariant the
/// Kotlin enrollment enforced.
fn averaged_health(results: &[HealthResult], mfg: MfgGateResult) -> (HealthResult, String) {
    if results.is_empty() {
        return (
            HealthResult {
                h_hat: 0.0,
                rho_hat: 0.0,
                l_hat: 0.0,
                passed: false,
            },
            "enroll_device: no health results".to_string(),
        );
    }
    let n = results.len() as f32;
    let h_hat = results.iter().map(|r| r.h_hat).sum::<f32>() / n;
    let rho_hat = results.iter().map(|r| r.rho_hat).sum::<f32>() / n;
    let l_hat = results.iter().map(|r| r.l_hat).sum::<f32>() / n;
    let passed = results.iter().all(|r| r.passed);

    let note = if mfg.passed {
        format!(
            "enroll_device: K={} sigma_device={:.4} (gate passed)",
            results.len(),
            mfg.sigma_device
        )
    } else {
        format!(
            "enroll_device: K={} sigma_device={:.4} (gate below target — verifier decides)",
            results.len(),
            mfg.sigma_device
        )
    };

    (
        HealthResult {
            h_hat,
            rho_hat,
            l_hat,
            passed,
        },
        note,
    )
}

/// Serialize the enrollment snapshot to `path` using the big-endian layout
/// consumed by `handlers::misc_routes::load_cdbrw_enrollment`:
///
/// ```text
/// u32 BE  revision
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
    /// "random" for the entropy health test to pass. We use a linear ramp
    /// plus a simple LCG perturbation — same pattern the responder tests
    /// rely on.
    fn synthetic_timings(seed: u64, n: usize) -> Vec<i64> {
        let mut state = seed;
        (0..n)
            .map(|i| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let noise = (state >> 16) as i64 & 0xFFFF;
                (i as i64) * 100 + noise
            })
            .collect()
    }

    #[test]
    fn enroll_rejects_too_few_trials() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..(MIN_ENROLL_TRIALS - 1))
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::InsufficientTrials { .. }));
    }

    #[test]
    fn enroll_rejects_bad_bin_count() {
        let dir = TempDir::new().expect("tempdir");
        let trials: Vec<Vec<i64>> = (0..MIN_ENROLL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 77,
            rotation_bits: 7,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::InvalidHistogramBins { .. }));
    }

    #[test]
    fn enroll_rejects_empty_trial() {
        let dir = TempDir::new().expect("tempdir");
        let mut trials: Vec<Vec<i64>> = (0..MIN_ENROLL_TRIALS)
            .map(|i| synthetic_timings(i as u64, 1024))
            .collect();
        trials[5] = Vec::new();
        let inputs = EnrollInputs {
            env_bytes: b"test-env",
            trials: &trials,
            arena_bytes: 8 * 1024 * 1024,
            probes: 4096,
            steps_per_probe: 4096,
            histogram_bins: 256,
            rotation_bits: 7,
        };
        let err = enroll_device(dir.path(), &inputs).unwrap_err();
        assert!(matches!(err, EnrollError::EmptyTrial { index: 5 }));
    }

    #[test]
    fn enroll_writes_expected_binary_layout() {
        with_clean_state(|| {
            let dir = TempDir::new().expect("tempdir");
            let trials: Vec<Vec<i64>> = (0..MIN_ENROLL_TRIALS)
                .map(|i| synthetic_timings(i as u64 + 1, 2048))
                .collect();
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0BOARD|BRAND|DEVICE|HW|MFG|MODEL|SOC|com.test",
                trials: &trials,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
            };
            let out = enroll_device(dir.path(), &inputs).expect("enroll");

            assert_eq!(out.revision, ENROLLMENT_REVISION);
            assert_eq!(out.mean_histogram_len, 256);
            assert!(out.epsilon_intra.is_finite());
            assert_eq!(out.reference_anchor_prefix.len(), 10);

            // Parse the file we just wrote and confirm it round-trips with the
            // reader layout used by `load_cdbrw_enrollment`.
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
            // mean histogram should sum ≈ 1.0 (normalized).
            let sum: f32 = mean_hist.iter().sum();
            assert!(
                (sum - 1.0).abs() < 1e-4,
                "mean histogram should be normalized, got sum={sum}"
            );

            let anchor_len = read_u32_be(&mut cursor);
            assert_eq!(anchor_len, 32);
            let mut anchor = vec![0u8; 32];
            cursor.read_exact(&mut anchor).expect("anchor");
            // First 10 bytes should match the prefix returned in the response.
            assert_eq!(&anchor[..10], out.reference_anchor_prefix.as_slice());
            // Full anchor must round-trip byte-for-byte with the disk layout.
            assert_eq!(anchor.as_slice(), out.reference_anchor.as_slice());
        });
    }

    #[test]
    fn enroll_publishes_trust_snapshot() {
        with_clean_state(|| {
            let dir = TempDir::new().expect("tempdir");
            let trials: Vec<Vec<i64>> = (0..MIN_ENROLL_TRIALS)
                .map(|i| synthetic_timings(i as u64 + 1000, 4096))
                .collect();
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0snapshot-test",
                trials: &trials,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
            };
            let out = enroll_device(dir.path(), &inputs).expect("enroll");

            // Gate should now hold a non-Blocked snapshot whose iter matches.
            let latest = latest_trust().expect("trust published");
            assert_eq!(latest.iter, out.trust.iter);
            assert_ne!(
                latest.access_level,
                AccessLevel::Blocked,
                "enrollment should leave the gate hot, got {:?}",
                latest.access_level
            );
            // Post-enroll drift is zero by construction.
            assert!(latest.w1_distance.abs() < 1e-6);
            assert!(latest.w1_threshold >= out.epsilon_intra);
        });
    }

    #[test]
    fn enroll_atomic_tmp_rename() {
        // Enroll twice to confirm the tmp-rename logic overwrites cleanly
        // rather than leaving both tmp and final file on disk.
        let dir = TempDir::new().expect("tempdir");
        for seed_base in [1u64, 9001u64] {
            let trials: Vec<Vec<i64>> = (0..MIN_ENROLL_TRIALS)
                .map(|i| synthetic_timings(seed_base + i as u64, 2048))
                .collect();
            let inputs = EnrollInputs {
                env_bytes: b"DSM/silicon_env/v2\0rename-test",
                trials: &trials,
                arena_bytes: 8 * 1024 * 1024,
                probes: 4096,
                steps_per_probe: 4096,
                histogram_bins: 256,
                rotation_bits: 7,
            };
            enroll_device(dir.path(), &inputs).expect("enroll");
        }
        let final_path = dir.path().join(ENROLLMENT_FILE_NAME);
        let tmp_path = final_path.with_extension("bin.tmp");
        assert!(final_path.exists(), "final file should exist");
        assert!(!tmp_path.exists(), "tmp file should have been renamed away");
    }
}
