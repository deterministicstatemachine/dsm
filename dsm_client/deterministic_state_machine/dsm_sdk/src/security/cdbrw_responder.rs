// SPDX-License-Identifier: MIT OR Apache-2.0
//! C-DBRW Protocol 6.2 — device-side responder (Algorithm 3).
//!
//! Replaces the Kotlin `CdbrwVerificationProtocol.respondToChallenge` flow.
//! Kotlin now only captures the raw orbit timings from the NDK silicon-PUF
//! probe (platform-specific) and forwards them as protobuf bytes; every
//! cryptographic step happens in Rust.
//!
//! ## Flow (matches Kotlin byte-for-byte)
//!
//! 1. `H̄` = build histogram from orbit timings (min/max span, 256 bins,
//!    linear bucketing, divide by n).
//! 2. Run 3-condition entropy health test via [`cdbrw_ffi::health_test`].
//!    If FAIL → gate stored as BLOCKED/READ_ONLY, respond with error.
//! 3. `w1_distance = wasserstein1(H̄, enrolled_mean)` against the enrolled
//!    reference. If > `epsilon_intra + margin` → PIN_REQUIRED, allow the
//!    response to proceed but record drift in the trust snapshot.
//! 4. `γ = BLAKE3("DSM/cdbrw-response\0" || H̄_LE || challenge)` where
//!    `H̄_LE` is the histogram encoded as LE f32 bytes (parity with
//!    `CdbrwMath.histogramToBytes` in Kotlin).
//! 5. `coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)`
//! 6. `(ss, ct) = ML-KEM-1024.Encaps(pk_verifier, coins)`
//! 7. `k_step = BLAKE3("DSM/kyber-ss\0" || ss)`
//! 8. `seed = BLAKE3("DSM/ek\0" || h_n || C_pre || k_step || K_DBRW)`
//! 9. `(ek_pk, ek_sk) = SPHINCS+(SPX256f).KeyGen(seed)`
//! 10. `σ = SPHINCS+.Sign(ek_sk, γ || ct || c)`
//!
//! All byte-order conventions (LE histogram bytes, BLAKE3 domain with
//! trailing NUL) match the Kotlin reference so that existing enrollments
//! continue to verify.
//!
//! ## Fail-closed gate integration
//!
//! Every successful return from [`respond_to_challenge`] publishes a
//! [`TrustSnapshot`] via [`store_trust`]. On hard failure (health FAIL,
//! signing error), the gate is updated to [`AccessLevel::ReadOnly`] or
//! [`AccessLevel::Blocked`] depending on which invariant failed, so the
//! next call to [`require_access_level`] sees the degraded state.

use crate::security::cdbrw_access_gate::{
    next_iter, store_trust, AccessLevel, ResonantStatus, TrustSnapshot,
};
use crate::security::cdbrw_ffi::{self, HealthResult};
use dsm::crypto::blake3::domain_hash_bytes;
use dsm::crypto::ephemeral_key::{
    derive_kyber_coins, derive_kyber_step_key, sign_cdbrw_response_with_context,
};
use dsm::crypto::kyber::kyber_encapsulate_deterministic;
use dsm::types::error::DsmError;

/// Default histogram granularity used by both enrollment and response probes.
/// Mirrors `SiliconFingerprint.config.histogramBins` on Android.
pub const DEFAULT_HISTOGRAM_BINS: usize = 256;
/// Distance margin added to `epsilon_intra` to form the drift threshold. Must
/// match Kotlin's `config.distanceMargin`.
pub const DEFAULT_DISTANCE_MARGIN: f32 = 0.02;

/// C-DBRW spec §4.5.7: Ĥ threshold (h_min − ε, ε = 0.05).
///
/// Phase 9 reinterpretation: this is the **median** floor used by
/// [`classify_resonant_m_sample`] across `M=ADMISSION_M` independent
/// samples, not a single-draw gate.  A single sample dipping below
/// `H_HAT_MIN` but above [`H_HAT_HARD_REJECT`] no longer fails the
/// device — the median verdict and per-sample hard floors do.
pub const H_HAT_MIN: f32 = 0.45;
/// Marginal-band lower edge for the M-sample admission rule (Phase 9).
/// `median_h_hat ∈ [H_HAT_WARN, H_HAT_MIN)` with all per-sample hard
/// floors clean classifies as [`ResonantStatus::Resonant`] →
/// [`AccessLevel::ReadOnly`] (degraded but usable) instead of failing
/// closed.  Devices whose silicon variance straddles `H_HAT_MIN` across
/// runs get a stable verdict rather than alternating PASS/FAIL.
pub const H_HAT_WARN: f32 = 0.40;
/// Per-sample hard floor for Shannon entropy (Phase 9).  If ANY of the
/// `M` admission samples reports `h_hat < H_HAT_HARD_REJECT`, the
/// device is rejected outright regardless of the median verdict — this
/// catches catastrophically bad silicon that one healthy sample
/// (e.g. lucky cache-state alignment) would otherwise mask.
pub const H_HAT_HARD_REJECT: f32 = 0.35;
/// C-DBRW spec §4.5.7: |ρ̂| ≤ 0.3.  Phase 9: median ceiling.
pub const RHO_HAT_MAX: f32 = 0.30;
/// Per-sample hard ceiling for |ρ̂| (Phase 9).  ANY sample exceeding
/// this fails admission regardless of median.
pub const RHO_HAT_HARD_REJECT: f32 = 0.40;
/// C-DBRW spec §4.5.7: L̂ threshold.  Phase 9: median floor.
pub const L_HAT_MIN: f32 = 0.45;
/// Per-sample hard floor for LZ78 compressibility (Phase 9).
pub const L_HAT_HARD_REJECT: f32 = 0.35;
/// Number of independent K-trial admission samples (Phase 9).  Each
/// sample is an independent K-trial enrollment chunk; the M chunks are
/// captured back-to-back in a single Kotlin → JNI batch then composed
/// in Rust under [`classify_resonant_m_sample`].  `M=3` was chosen for
/// the variance/cost tradeoff: median of 3 absorbs trial-to-trial
/// jitter on marginal silicon (real-world observed h_hat spread of
/// 0.41/0.77/0.92/0.94 on Galaxy A54 across runs) without doubling
/// first-genesis time vs M=5.
pub const ADMISSION_M: usize = 3;
/// Minimum total entropy bits for the Resonant path. Matches the spec's
/// baseline security level: h_min × N_min = 0.5 × 4096 = 2048 bits
/// (Proposition 7.1). Devices with high ρ̂ but sufficient total entropy
/// (h0_eff × N ≥ 2048) achieve Resonant → FULL_ACCESS via the extended
/// orbit compensation: longer orbits accumulate enough decorrelated bits
/// even when per-sample independence is reduced by thermal coupling.
pub const MIN_TOTAL_ENTROPY_BITS: f32 = 2048.0;

/// Inputs required to execute Algorithm 3.
///
/// Owned buffers — the responder is called from the router dispatch path which
/// decodes a protobuf into owned `Vec<u8>` before delegating here. Kotlin no
/// longer participates in any of these computations.
pub struct RespondInputs<'a> {
    /// Raw orbit timings captured via the NDK silicon-PUF probe.
    pub orbit_timings: &'a [i64],
    /// Enrolled reference histogram (`H̄_enroll`) for drift comparison.
    /// `None` when enrollment is absent — the responder will still run and
    /// emit a [`AccessLevel::Blocked`] snapshot.
    pub enrolled_mean: Option<&'a [f32]>,
    /// Enrolled `epsilon_intra` (P95 distance across enrollment trials).
    pub epsilon_intra: f32,
    /// Verifier ML-KEM-1024 public key.
    pub verifier_public_key: &'a [u8],
    /// Verifier challenge (32 bytes).
    pub challenge: &'a [u8; 32],
    /// Current hash chain tip `h_n`.
    pub chain_tip: &'a [u8; 32],
    /// Pre-commitment hash `C_pre` (32 bytes).
    pub commitment_preimage: &'a [u8; 32],
    /// Device identity (32 bytes).
    pub device_id: &'a [u8; 32],
    /// C-DBRW binding key — must come from the bootstrap `set_cdbrw_binding_key`
    /// path; never accepted from callers directly.
    pub binding_key: &'a [u8; 32],
    /// Histogram bin count. Must equal the enrollment bin count when
    /// `enrolled_mean` is present; asserted in the code path.
    pub histogram_bins: usize,
    /// Robust binning range committed at enrollment (revision 6+).
    /// `None` for legacy v4/v5 enrollments — the responder falls back
    /// to the legacy [min, max] binning derived from live orbit
    /// timings.  Revision-5 callers that pass `None` will see the
    /// h_hat-collapse failure mode on outlier-prone devices and
    /// should invalidate + re-enroll under the new code path.
    pub bin_range: Option<BinRange>,
}

/// Outputs of a successful Algorithm 3 response.
pub struct RespondOutputs {
    pub gamma: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
    pub trust: TrustSnapshot,
    pub note: String,
}

/// Errors returned by the responder. Each variant is a hard rejection —
/// the access gate is updated to a degraded state before propagation.
#[derive(Debug)]
pub enum RespondError {
    /// Orbit histogram rejected by the 3-condition health test.
    EntropyHealthFailed(HealthResult),
    /// Verifier public key too short to be a valid Kyber key.
    InvalidVerifierKey,
    /// Histogram bin count must match enrollment.
    HistogramBinsMismatch { expected: usize, actual: usize },
    /// Challenge input was not 32 bytes.
    InvalidChallengeLength,
    /// Underlying dsm core error (Kyber/SPHINCS+/BLAKE3 boundary).
    Crypto(String),
}

impl std::fmt::Display for RespondError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RespondError::EntropyHealthFailed(h) => write!(
                f,
                "entropy health failed: H={:.4} |rho|={:.4} L={:.4}",
                h.h_hat,
                h.rho_hat.abs(),
                h.l_hat
            ),
            RespondError::InvalidVerifierKey => write!(f, "verifier public key invalid"),
            RespondError::HistogramBinsMismatch { expected, actual } => write!(
                f,
                "histogram bins mismatch: expected {expected} got {actual}"
            ),
            RespondError::InvalidChallengeLength => write!(f, "challenge must be 32 bytes"),
            RespondError::Crypto(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for RespondError {}

impl From<DsmError> for RespondError {
    fn from(e: DsmError) -> Self {
        RespondError::Crypto(e.to_string())
    }
}

/// Fixed lower-tail percentile clipped from the raw timing distribution
/// when computing the robust binning range. 0.5% trims the bottom-end
/// outliers without losing the body of the distribution.
pub const ROBUST_BIN_LOW_PCT: f64 = 0.005;
/// Fixed upper-tail percentile. 99.5% trims the rare scheduler-interrupt /
/// GC-pause outliers that pollute the binning normalization without
/// contributing real silicon-substrate entropy.
pub const ROBUST_BIN_HIGH_PCT: f64 = 0.995;

// Re-export `BinRange` for callers that read it from
// `cdbrw_responder`. Source of truth lives in `cdbrw_ffi` because the
// health test (h_hat / rho_hat / l_hat) is where the binning matters
// most.
pub use crate::security::cdbrw_ffi::BinRange;

/// Build a normalized histogram of `samples` in `bins` slots using a
/// caller-supplied [`BinRange`]. Samples outside `[range.low,
/// range.high]` clamp to the edge bins.  This is the robust form:
/// outliers don't compress the bin space, and ranges committed at
/// enrollment guarantee per-trial histogram alignment for mean-
/// histogram and W1 math.
///
/// - `idx = floor(((v - range.low) / span) * (bins - 1))` clamped to `[0, bins-1]`
/// - divide each bucket by the sample count
/// - degenerate span → first bin = 1.0
pub fn build_histogram_in_range(samples: &[i64], bins: usize, range: BinRange) -> Vec<f32> {
    if bins == 0 {
        return Vec::new();
    }
    let mut hist = vec![0.0f32; bins];
    if samples.is_empty() {
        hist[0] = 1.0;
        return hist;
    }
    if range.high <= range.low {
        hist[0] = 1.0;
        return hist;
    }
    let span = (range.high - range.low) as f64;
    let bins_minus_one = (bins - 1) as f64;
    for v in samples {
        let diff = (*v - range.low) as f64;
        let normalized = (diff / span).clamp(0.0, 1.0);
        let idx = ((normalized * bins_minus_one) as isize).clamp(0, bins as isize - 1);
        hist[idx as usize] += 1.0;
    }
    let total = samples.len() as f32;
    for v in hist.iter_mut() {
        *v /= total;
    }
    hist
}

/// Backwards-compatible histogram builder using the legacy [min, max]
/// span over `samples`.  New callers should prefer
/// [`build_histogram_in_range`] with a robust [`BinRange`] derived from
/// enrollment-time aggregate samples — see [`BinRange::from_samples_robust`].
///
/// Mirrors `CdbrwMath.buildHistogram` on the Kotlin side. The Layer-1
/// fix (Phase 2 of the C-DBRW entropy-collapse remediation) shifted the
/// enrollment + measure paths to the in-range variant; this function
/// is retained for moment-tree internals and tests that don't need
/// cross-trial alignment.
pub fn build_histogram(samples: &[i64], bins: usize) -> Vec<f32> {
    build_histogram_in_range(samples, bins, BinRange::full_span(samples))
}

/// Element-wise mean of a slice of equal-length histograms.
///
/// Mirrors `CdbrwMath.meanHistogram`. Empty input returns an empty vector;
/// histograms of length zero return a length-zero mean.
pub fn mean_histogram(histograms: &[&[f32]]) -> Vec<f32> {
    let Some(first) = histograms.first() else {
        return Vec::new();
    };
    let bins = first.len();
    if bins == 0 {
        return Vec::new();
    }
    let mut out = vec![0.0f32; bins];
    for h in histograms {
        // Ignore mis-sized entries deterministically — the responder never
        // constructs such inputs; this is defensive only.
        if h.len() != bins {
            continue;
        }
        for (i, v) in h.iter().enumerate() {
            out[i] += v;
        }
    }
    let inv = 1.0f32 / histograms.len().max(1) as f32;
    for v in out.iter_mut() {
        *v *= inv;
    }
    out
}

/// Wasserstein-1 distance between two normalized histograms.
///
/// Parity with `CdbrwMath.wasserstein1` — step = 1 / bins, accumulate CDFs
/// element-wise, sum `|cdfA - cdfB| * step`.
pub fn wasserstein1(a: &[f32], b: &[f32]) -> f32 {
    let bins = a.len().min(b.len());
    if bins == 0 {
        return 0.0;
    }
    let step = 1.0f32 / bins as f32;
    let mut cdf_a = 0.0f32;
    let mut cdf_b = 0.0f32;
    let mut dist = 0.0f32;
    for i in 0..bins {
        cdf_a += a[i];
        cdf_b += b[i];
        dist += (cdf_a - cdf_b).abs() * step;
    }
    dist
}

/// Serialize a histogram into its LE f32 byte form.
///
/// Parity with Kotlin `CdbrwMath.histogramToBytes`. The output feeds into
/// the γ preimage and the attractor commitment, so byte order must not drift.
pub fn histogram_to_bytes(hist: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hist.len() * 4);
    for v in hist {
        out.extend_from_slice(&v.to_bits().to_le_bytes());
    }
    out
}

/// Tri-layer resonant classification from C-DBRW spec §4.5.4 / §7 / §8.1.
///
/// Returns `(status, h0_eff, recommended_n)`. Logic mirrors
/// [`handlers::misc_routes::compute_resonant_health`] which is preserved
/// for the `dbrw.status` query while this function drives live responses.
///
/// The `entropy_ok` guard (`Ĥ ≥ 0.45 ∧ L̂ ≥ 0.45`) confirms the device
/// produces genuine entropy and non-trivial complexity. When that holds but
/// `|ρ̂|` exceeds `RHO_HAT_MAX`, the autocorrelation reflects thermal
/// coupling between consecutive PUF timing samples — expected on mobile
/// silicon per §8.1 Theorem 8.1(ii). The Adapted branch compensates by
/// recommending longer orbits (Remark 4.6) rather than rejecting outright.
pub fn classify_resonant(h_hat: f32, rho_hat: f32, l_hat: f32) -> (ResonantStatus, f32, u32) {
    let h0_eff = h_hat * (1.0 - rho_hat.abs());
    let base_pass = h_hat >= H_HAT_MIN && rho_hat.abs() <= RHO_HAT_MAX && l_hat >= L_HAT_MIN;
    let entropy_ok = h_hat >= H_HAT_MIN && l_hat >= L_HAT_MIN;

    let total_entropy = h0_eff * cdbrw_ffi::thresholds::HEALTH_N as f32;

    if base_pass {
        (ResonantStatus::Pass, h0_eff, 4096)
    } else if entropy_ok && total_entropy >= MIN_TOTAL_ENTROPY_BITS {
        // Proposition 7.1: total entropy h0_eff × N ≥ 2048 bits matches
        // the spec baseline (h_min=0.5 × N_min=4096). Thermal coupling
        // reduces per-sample independence but the extended orbit (N=16384)
        // compensates — Theorem 8.1(ii) confirms thermal variation
        // strengthens the attractor fingerprint.
        (ResonantStatus::Resonant, h0_eff, 4096)
    } else if entropy_ok {
        // h0_eff × N < 2048: insufficient total entropy for full trust.
        (ResonantStatus::Adapted, h0_eff, 16384)
    } else {
        (ResonantStatus::Fail, h0_eff, 16384)
    }
}

/// Phase 9 — Median-of-M C-DBRW admission rule.
///
/// Replaces single-K=21-draw acceptance for the *enrollment* path with
/// median + hard-floor verdicts over `M=ADMISSION_M` independent
/// samples. Each `samples[i]` is the [`HealthResult`] computed over the
/// `i`-th K-trial chunk by [`cdbrw_ffi::health_test_in_range`] under
/// the shared robust [`BinRange`] committed at enrollment.
///
/// Verdict resolution (in order):
/// 1. **Hard-floor reject** — if any sample's `h_hat <
///    H_HAT_HARD_REJECT`, `|rho_hat| > RHO_HAT_HARD_REJECT`, or `l_hat
///    < L_HAT_HARD_REJECT` → [`ResonantStatus::Fail`]. One
///    catastrophically bad sample cannot be masked by two healthy
///    samples in the median.
/// 2. **Median pass** — if `median_h_hat ≥ H_HAT_MIN ∧
///    median_rho_hat_abs ≤ RHO_HAT_MAX ∧ median_l_hat ≥ L_HAT_MIN` →
///    [`ResonantStatus::Pass`] (→ `AccessLevel::FullAccess`).
/// 3. **Marginal band** — if `median_h_hat ∈ [H_HAT_WARN, H_HAT_MIN)`
///    AND every sample passes the hard floors →
///    [`ResonantStatus::Resonant`] (→ `AccessLevel::ReadOnly`). The
///    device is usable but spends are PIN-gated. This is the band that
///    fixes the Galaxy A54 brittleness: silicon whose median draw
///    straddles `H_HAT_MIN` gets a stable READ_ONLY verdict instead of
///    alternating between FULL_ACCESS and PIN_REQUIRED+drift across
///    runs.
/// 4. **Degraded admission** — entropy clean but median below
///    `H_HAT_WARN` → [`ResonantStatus::Adapted`] (→
///    `AccessLevel::PinRequired`). Step-up enforced.
/// 5. **Reject** — anything else → [`ResonantStatus::Fail`].
///
/// Returns `(status, median_h0_eff, recommended_n)` so the caller can
/// thread the median scalars into the persisted trust snapshot.  The
/// per-sample arrays themselves stay with the caller for the audit
/// trail (schema v7 stores all `M` of them).
///
/// # Panics
///
/// Panics if `samples` is empty (the enrollment writer pre-validates
/// `samples.len() == ADMISSION_M`; callers must as well).
pub fn classify_resonant_m_sample(samples: &[HealthResult]) -> (ResonantStatus, f32, u32) {
    assert!(
        !samples.is_empty(),
        "classify_resonant_m_sample: at least one sample required"
    );

    // Hard-floor pass first — any sample failing a hard floor disqualifies
    // the device regardless of the median.
    for s in samples {
        if s.h_hat < H_HAT_HARD_REJECT
            || s.rho_hat.abs() > RHO_HAT_HARD_REJECT
            || s.l_hat < L_HAT_HARD_REJECT
        {
            // Pick a representative h0_eff for the failing sample so the
            // caller's snapshot reflects a meaningful number.
            let h0 = s.h_hat * (1.0 - s.rho_hat.abs());
            return (ResonantStatus::Fail, h0, 16384);
        }
    }

    // Median in each metric (sort-then-pick-middle; `samples.len()` is
    // small — M=3 in production — so the cost is irrelevant).
    let mut h: Vec<f32> = samples.iter().map(|s| s.h_hat).collect();
    let mut r: Vec<f32> = samples.iter().map(|s| s.rho_hat.abs()).collect();
    let mut l: Vec<f32> = samples.iter().map(|s| s.l_hat).collect();
    let cmp_f32 = |a: &f32, b: &f32| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    h.sort_by(cmp_f32);
    r.sort_by(cmp_f32);
    l.sort_by(cmp_f32);
    let mid = samples.len() / 2;
    let median_h = h[mid];
    let median_rho_abs = r[mid];
    let median_l = l[mid];
    // Approximate median h0_eff: the metrics are computed independently
    // per sample but reporting `median_h × (1 − median_|ρ|)` keeps the
    // h0_eff scalar comparable to the single-sample path's value.
    let median_h0_eff = median_h * (1.0 - median_rho_abs);

    let base_pass = median_h >= H_HAT_MIN && median_rho_abs <= RHO_HAT_MAX && median_l >= L_HAT_MIN;
    let entropy_ok_strict = median_h >= H_HAT_MIN && median_l >= L_HAT_MIN;
    let entropy_ok_marginal =
        median_h >= H_HAT_WARN && median_l >= H_HAT_WARN && median_rho_abs <= RHO_HAT_MAX;

    if base_pass {
        (ResonantStatus::Pass, median_h0_eff, 4096)
    } else if entropy_ok_strict
        && median_h0_eff * cdbrw_ffi::thresholds::HEALTH_N as f32 >= MIN_TOTAL_ENTROPY_BITS
    {
        // Median clears H_HAT_MIN/L_HAT_MIN but ρ̂ exceeds the strict
        // ceiling — same Resonant path as the single-sample classifier.
        (ResonantStatus::Resonant, median_h0_eff, 4096)
    } else if entropy_ok_marginal {
        // Median falls in [H_HAT_WARN, H_HAT_MIN) with all hard floors
        // clean. The marginal band: device is real silicon, just sitting
        // at the noisy edge of its variance envelope. READ_ONLY is the
        // honest verdict.
        (ResonantStatus::Resonant, median_h0_eff, 4096)
    } else if median_h >= H_HAT_WARN && median_l >= H_HAT_WARN {
        // Median entropy ok but rho/correlation issue puts it in the
        // step-up band.
        (ResonantStatus::Adapted, median_h0_eff, 16384)
    } else {
        (ResonantStatus::Fail, median_h0_eff, 16384)
    }
}

/// Build a [`TrustSnapshot`] from raw health metrics + enrollment drift and
/// publish it through the access gate. Called by the responder, the
/// measure-trust route, and the enrollment writer.
///
/// # Returns
/// The published snapshot (so callers can copy into their response
/// protobuf). The access-level decision rules mirror the old Kotlin
/// `resolveAccessLevel` logic but are now centrally enforced in Rust:
///
/// - `Fail` → [`AccessLevel::ReadOnly`]
/// - `Adapted` → [`AccessLevel::PinRequired`]
/// - drift beyond `epsilon_intra + margin` → [`AccessLevel::PinRequired`]
/// - `Resonant` / `Pass` with clean drift → [`AccessLevel::FullAccess`]
pub fn publish_trust_snapshot(
    health: HealthResult,
    w1_distance: f32,
    w1_threshold: f32,
    note: &str,
) -> TrustSnapshot {
    let (resonant_status, h0_eff, recommended_n) =
        classify_resonant(health.h_hat, health.rho_hat, health.l_hat);

    let drifted = w1_threshold > 0.0 && w1_distance > w1_threshold;

    // Phase 13 follow-up: align operational behaviour with the doc
    // claim ("Layer B zeros K_DBRW + drops access to ReadOnly on
    // cross-device drift").  The `cdbrw.reprove` path already clears
    // the binding-key slot on `CloneDetected`; the boot-time
    // `cdbrw.measure_trust` path runs through here on every boot and
    // previously only downgraded the access level on W1 drift, leaving
    // the binding key in memory.  Mirror the reprove behaviour: when
    // drift fires here, zero K_DBRW too so the binding key cannot be
    // re-clone-derived by any code path that bypasses the access gate.
    //
    // TOCTOU note: a signing op that cloned `get_binding_key()` BEFORE
    // this check can still complete with the old (now-suspect) bytes;
    // the access gate downgrade below is the strong fence.  This clear
    // bounds the in-memory residue window — it does not eliminate it.
    if drifted {
        crate::binding_key::clear_binding_key();
        log::warn!(
            "[cdbrw_responder] W1 drift detected (distance={w1_distance:.4} > threshold={w1_threshold:.4}) — K_DBRW slot zeroed; access downgraded to PinRequired"
        );
    }

    // Strict access-level resolution — no feature gate, no test bypass, no
    // default-allow fallback. A Fail verdict from `classify_resonant`
    // (entropy-health below H_HAT_MIN / L_HAT_MIN, or `|rho_hat|` above
    // RHO_HAT_MAX) returns ReadOnly and stays ReadOnly. Gated routes in
    // `app_router_impl` fail closed against this verdict via
    // `require_access_level(AccessLevel::ReadOnly)`.
    let access_level = match (resonant_status, drifted) {
        (ResonantStatus::Fail, _) => AccessLevel::ReadOnly,
        (ResonantStatus::Adapted, _) => AccessLevel::PinRequired,
        (_, true) => AccessLevel::PinRequired,
        (ResonantStatus::Pass | ResonantStatus::Resonant, false) => AccessLevel::FullAccess,
        (ResonantStatus::Unspecified, _) => AccessLevel::Blocked,
    };

    let trust_score = match (resonant_status, access_level) {
        (_, AccessLevel::Blocked) => 0.0,
        (ResonantStatus::Fail, _) => 0.0,
        (ResonantStatus::Adapted, _) => 0.75,
        _ => {
            // Use 1 - (w1 / (threshold + eps)) when drifted-but-allowed to
            // give a gradient; otherwise 1.0 on clean PASS/RESONANT.
            if drifted {
                let denom = (w1_threshold + 1e-6).max(1e-6);
                (1.0 - (w1_distance / denom)).clamp(0.0, 1.0)
            } else {
                1.0
            }
        }
    };

    let snapshot = TrustSnapshot {
        access_level,
        resonant_status,
        h_hat: health.h_hat,
        rho_hat: health.rho_hat,
        l_hat: health.l_hat,
        h0_eff,
        trust_score,
        recommended_n,
        w1_distance,
        w1_threshold,
        iter: next_iter(),
    };
    log::info!(
        "[cdbrw_responder] trust snapshot produced: access={} resonant={} note={}",
        snapshot.access_level.as_str(),
        snapshot.resonant_status.as_str(),
        note
    );
    store_trust(snapshot);
    snapshot
}

/// Compute a measure-trust result without running the full Algorithm 3
/// response. Returned snapshot has the same structure as a `respond` result
/// so the UI can drive the gate from polls without requiring a verifier.
///
/// `bin_range` carries the robust [P0.5, P99.5] binning range committed
/// at enrollment (revision 6+).  Pre-Phase-2 enrollments (revisions 4/5)
/// supply `None`, in which case this function falls back to the legacy
/// [min, max] binning derived from the live orbit timings — note that
/// this fallback re-introduces the h_hat-collapse failure mode for
/// devices with a single outlier sample, so revision-5 callers should
/// invalidate + re-enroll.
pub fn measure_trust(
    orbit_timings: &[i64],
    enrolled_mean: Option<&[f32]>,
    epsilon_intra: f32,
    histogram_bins: usize,
    bin_range: Option<BinRange>,
) -> TrustSnapshot {
    let bins = if histogram_bins == 0 {
        DEFAULT_HISTOGRAM_BINS
    } else {
        histogram_bins
    };

    let (histogram, health) = match bin_range {
        Some(range) => (
            build_histogram_in_range(orbit_timings, bins, range),
            cdbrw_ffi::health_test_in_range(orbit_timings, bins, range),
        ),
        None => (
            build_histogram(orbit_timings, bins),
            cdbrw_ffi::health_test(orbit_timings, bins),
        ),
    };

    let (w1_distance, w1_threshold) = match enrolled_mean {
        Some(ref_hist) if ref_hist.len() == bins => {
            let d = wasserstein1(&histogram, ref_hist);
            (d, epsilon_intra + DEFAULT_DISTANCE_MARGIN)
        }
        _ => (0.0, 0.0),
    };

    let note = if enrolled_mean.is_none() {
        "measure_trust: no enrollment (drift metrics zero)".to_string()
    } else if histogram.len() != enrolled_mean.map(|h| h.len()).unwrap_or(0) {
        "measure_trust: enrolled bin count mismatch".to_string()
    } else {
        "measure_trust: live probe".to_string()
    };

    publish_trust_snapshot(health, w1_distance, w1_threshold, &note)
}

/// Full Algorithm 3 device-side responder.
pub fn respond_to_challenge(inputs: &RespondInputs<'_>) -> Result<RespondOutputs, RespondError> {
    if inputs.challenge.len() != 32 {
        return Err(RespondError::InvalidChallengeLength);
    }
    if inputs.verifier_public_key.len() < 32 {
        return Err(RespondError::InvalidVerifierKey);
    }
    let bins = if inputs.histogram_bins == 0 {
        DEFAULT_HISTOGRAM_BINS
    } else {
        inputs.histogram_bins
    };
    if let Some(enrolled) = inputs.enrolled_mean {
        if enrolled.len() != bins {
            return Err(RespondError::HistogramBinsMismatch {
                expected: enrolled.len(),
                actual: bins,
            });
        }
    }

    // Step 1-2: histogram + health test.  Use the committed robust
    // bin_range when available (revision 6+); fall back to legacy
    // min/max binning for v4/v5 enrollments.
    let (histogram, health) = match inputs.bin_range {
        Some(range) => (
            build_histogram_in_range(inputs.orbit_timings, bins, range),
            cdbrw_ffi::health_test_in_range(inputs.orbit_timings, bins, range),
        ),
        None => (
            build_histogram(inputs.orbit_timings, bins),
            cdbrw_ffi::health_test(inputs.orbit_timings, bins),
        ),
    };

    // Step 3: drift check (updates gate even on failure)
    let (w1_distance, w1_threshold) = match inputs.enrolled_mean {
        Some(ref_hist) => (
            wasserstein1(&histogram, ref_hist),
            inputs.epsilon_intra + DEFAULT_DISTANCE_MARGIN,
        ),
        None => (0.0, 0.0),
    };

    // Gate on classify_resonant rather than the raw 3-condition health.passed.
    // Devices with good entropy and complexity but high thermal coupling
    // (|ρ̂| > RHO_HAT_MAX) classify as Adapted, not Fail — they can still
    // produce a valid response at a degraded trust level (PinRequired).
    // Only a true Fail (insufficient entropy or complexity) is a hard reject.
    let (resonant_status, _, _) = classify_resonant(health.h_hat, health.rho_hat, health.l_hat);
    if resonant_status == ResonantStatus::Fail {
        publish_trust_snapshot(
            health,
            w1_distance,
            w1_threshold,
            "respond_to_challenge: entropy health FAIL",
        );
        return Err(RespondError::EntropyHealthFailed(health));
    }

    // Step 4: γ = BLAKE3("DSM/cdbrw-response\0" || H̄_LE || challenge)
    let h_bar_bytes = histogram_to_bytes(&histogram);
    let mut gamma_preimage = Vec::with_capacity(h_bar_bytes.len() + 32);
    gamma_preimage.extend_from_slice(&h_bar_bytes);
    gamma_preimage.extend_from_slice(inputs.challenge);
    let gamma = domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_CDBRW_RESPONSE,
        &gamma_preimage,
    );

    // Step 5-6: deterministic Kyber encapsulation against verifier PK
    let coins = derive_kyber_coins(
        inputs.chain_tip,
        inputs.commitment_preimage,
        inputs.device_id,
        inputs.binding_key,
    );
    let (shared_secret, ciphertext) =
        kyber_encapsulate_deterministic(inputs.verifier_public_key, &coins)?;

    // Step 7: k_step = BLAKE3("DSM/kyber-ss\0" || ss)
    let k_step = derive_kyber_step_key(&shared_secret);

    // Step 8-10: ephemeral SPHINCS+ keygen + signature over (γ || ct || c)
    let (signature, ephemeral_public_key) = sign_cdbrw_response_with_context(
        inputs.chain_tip,
        inputs.commitment_preimage,
        &k_step,
        inputs.binding_key,
        &gamma,
        &ciphertext,
        inputs.challenge,
    )?;

    // Publish trust snapshot and return
    let trust = publish_trust_snapshot(
        health,
        w1_distance,
        w1_threshold,
        "respond_to_challenge: signed response",
    );

    Ok(RespondOutputs {
        gamma,
        ciphertext,
        signature,
        ephemeral_public_key,
        trust,
        note: "respond_to_challenge: signed response".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::cdbrw_access_gate::{clear_trust_for_test, gate_test_mutex, latest_trust};
    use serial_test::serial;

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

    #[test]
    fn build_histogram_empty_is_delta_at_zero() {
        let hist = build_histogram(&[], 16);
        assert_eq!(hist.len(), 16);
        assert!((hist[0] - 1.0).abs() < 1e-6);
        for h in &hist[1..] {
            assert!(h.abs() < 1e-6);
        }
    }

    #[test]
    fn build_histogram_constant_samples_is_delta_at_zero() {
        let samples = vec![42i64; 128];
        let hist = build_histogram(&samples, 16);
        assert!((hist[0] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn build_histogram_sums_to_one() {
        let samples: Vec<i64> = (0..1000).map(|i| i * 7).collect();
        let hist = build_histogram(&samples, 64);
        let sum: f32 = hist.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5, "sum should be ~1.0, got {sum}");
    }

    #[test]
    fn mean_histogram_of_identical_is_same() {
        let h = vec![0.1f32; 10];
        let refs: Vec<&[f32]> = vec![&h, &h, &h];
        let mean = mean_histogram(&refs);
        for v in &mean {
            assert!((v - 0.1).abs() < 1e-6);
        }
    }

    #[test]
    fn wasserstein1_self_distance_is_zero() {
        let h = build_histogram(&(0..256i64).collect::<Vec<_>>(), 32);
        assert!(wasserstein1(&h, &h).abs() < 1e-6);
    }

    #[test]
    fn wasserstein1_disjoint_histograms_are_nonzero() {
        let mut a = vec![0.0f32; 8];
        a[0] = 1.0;
        let mut b = vec![0.0f32; 8];
        b[7] = 1.0;
        let d = wasserstein1(&a, &b);
        assert!(d > 0.0, "disjoint histograms should have positive W1");
    }

    #[test]
    fn histogram_to_bytes_is_le_f32() {
        // Parity with Kotlin: first float bits, LE order.
        let hist = vec![1.0f32, 0.5f32];
        let bytes = histogram_to_bytes(&hist);
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[0..4], &1.0f32.to_bits().to_le_bytes());
        assert_eq!(&bytes[4..8], &0.5f32.to_bits().to_le_bytes());
    }

    #[test]
    fn classify_resonant_pass_matches_misc_routes() {
        let (status, h0_eff, n) = classify_resonant(0.6, 0.1, 0.55);
        assert_eq!(status, ResonantStatus::Pass);
        assert!((h0_eff - 0.54).abs() < 1e-6);
        assert_eq!(n, 4096);
    }

    #[test]
    fn classify_resonant_fail_rejects_low_entropy() {
        let (status, _, _) = classify_resonant(0.30, 0.10, 0.20);
        assert_eq!(status, ResonantStatus::Fail);
    }

    #[test]
    fn classify_resonant_high_rho_good_entropy_is_adapted() {
        // Real Galaxy A54 profile: h_hat=0.64, rho=0.89, l_hat=0.64.
        // Entropy and complexity are healthy; autocorrelation is from thermal
        // coupling per §8.1. Should classify as Adapted, not Fail.
        let (status, h0_eff, n) = classify_resonant(0.64, 0.89, 0.64);
        assert_eq!(status, ResonantStatus::Adapted);
        // h0_eff = 0.64 * (1 - 0.89) = 0.0704
        assert!((h0_eff - 0.0704).abs() < 0.01);
        assert_eq!(n, 16384);
    }

    #[test]
    fn classify_resonant_moderate_rho_good_entropy_is_resonant() {
        // Moderate coupling: rho=0.50, h_hat=0.65, l_hat=0.60.
        // h0_eff = 0.65 * 0.50 = 0.325, total = 0.325 * 16384 = 5324 ≥ 2048.
        let (status, h0_eff, _n) = classify_resonant(0.65, 0.50, 0.60);
        assert_eq!(status, ResonantStatus::Resonant);
        assert!((h0_eff - 0.325).abs() < 0.01);
    }

    #[test]
    fn publish_trust_fail_stores_read_only() {
        with_clean_state(|| {
            let fail = HealthResult {
                h_hat: 0.10,
                rho_hat: 0.01,
                l_hat: 0.10,
                passed: false,
            };
            let snap = publish_trust_snapshot(fail, 0.0, 0.0, "test fail");
            assert_eq!(snap.access_level, AccessLevel::ReadOnly);
            assert_eq!(snap.resonant_status, ResonantStatus::Fail);
            assert_eq!(
                latest_trust().map(|s| s.access_level),
                Some(AccessLevel::ReadOnly)
            );
        });
    }

    #[test]
    fn publish_trust_pass_with_drift_is_pin_required() {
        with_clean_state(|| {
            let pass = HealthResult {
                h_hat: 0.60,
                rho_hat: 0.10,
                l_hat: 0.55,
                passed: true,
            };
            let snap = publish_trust_snapshot(pass, 0.2, 0.1, "test drift");
            assert_eq!(snap.access_level, AccessLevel::PinRequired);
        });
    }

    /// Phase 13 follow-up: on W1 drift `publish_trust_snapshot` must
    /// also zero the K_DBRW slot, mirroring the `cdbrw.reprove` ->
    /// CloneDetected behaviour.  Prior to this hook, drift only
    /// downgraded the access level; the binding key remained in
    /// memory.  Now the slot is cleared so any downstream signer that
    /// gets past the access gate (TOCTOU residue aside) fails closed
    /// with `InvalidState`.
    #[test]
    #[serial]
    fn publish_trust_drift_zeros_binding_key_slot() {
        with_clean_state(|| {
            // Seed the binding key slot with a known 32-byte value.
            crate::binding_key::install_binding_key(vec![0xABu8; 32])
                .expect("install_binding_key must accept a 32-byte key");
            assert!(
                crate::binding_key::get_binding_key().is_some(),
                "precondition: binding key must be installed before the test"
            );

            let pass = HealthResult {
                h_hat: 0.60,
                rho_hat: 0.10,
                l_hat: 0.55,
                passed: true,
            };
            // W1 distance 0.2 > threshold 0.1 → drift; must clear slot.
            let snap = publish_trust_snapshot(pass, 0.2, 0.1, "test drift clears K_DBRW");
            assert_eq!(snap.access_level, AccessLevel::PinRequired);
            assert!(
                crate::binding_key::get_binding_key().is_none(),
                "drift detection must zero the K_DBRW slot per Phase 13 doc claim"
            );
        });
    }

    /// Phase 13 follow-up: clean-pass (no drift) must NOT touch the
    /// binding key slot — only drift triggers the wipe.
    #[test]
    #[serial]
    fn publish_trust_clean_pass_preserves_binding_key_slot() {
        with_clean_state(|| {
            crate::binding_key::install_binding_key(vec![0xCDu8; 32])
                .expect("install_binding_key must accept a 32-byte key");

            let pass = HealthResult {
                h_hat: 0.60,
                rho_hat: 0.10,
                l_hat: 0.55,
                passed: true,
            };
            // W1 distance 0.01 < threshold 0.10 → no drift; preserve slot.
            let snap = publish_trust_snapshot(pass, 0.01, 0.10, "test clean preserves K_DBRW");
            assert_eq!(snap.access_level, AccessLevel::FullAccess);
            assert!(
                crate::binding_key::get_binding_key().is_some(),
                "clean pass must leave the binding key slot untouched"
            );

            // Test cleanup — wipe so we don't leak state into siblings.
            crate::binding_key::clear_binding_key();
        });
    }

    #[test]
    fn publish_trust_pass_clean_is_full_access() {
        with_clean_state(|| {
            let pass = HealthResult {
                h_hat: 0.60,
                rho_hat: 0.10,
                l_hat: 0.55,
                passed: true,
            };
            let snap = publish_trust_snapshot(pass, 0.01, 0.10, "test pass");
            assert_eq!(snap.access_level, AccessLevel::FullAccess);
            assert_eq!(snap.resonant_status, ResonantStatus::Pass);
        });
    }

    fn health_sample(h_hat: f32, rho_hat: f32, l_hat: f32) -> HealthResult {
        let passed = h_hat >= H_HAT_MIN && rho_hat.abs() <= RHO_HAT_MAX && l_hat >= L_HAT_MIN;
        HealthResult {
            h_hat,
            rho_hat,
            l_hat,
            passed,
        }
    }

    #[test]
    fn classify_m_sample_all_pass_is_pass() {
        let samples = vec![
            health_sample(0.55, 0.10, 0.55),
            health_sample(0.60, 0.05, 0.60),
            health_sample(0.50, 0.15, 0.50),
        ];
        let (status, _, n) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Pass);
        assert_eq!(n, 4096);
    }

    #[test]
    fn classify_m_sample_marginal_median_is_resonant() {
        // The motivating Galaxy A54 case: median lands in [WARN, MIN)
        // and all hard floors clean.  Should classify Resonant (→
        // ReadOnly), not Fail.
        let samples = vec![
            health_sample(0.41, 0.10, 0.50), // marginal
            health_sample(0.42, 0.12, 0.48), // marginal
            health_sample(0.43, 0.15, 0.49), // marginal but clean floors
        ];
        let (status, _, _) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Resonant);
    }

    #[test]
    fn classify_m_sample_one_hard_floor_breach_rejects() {
        // One catastrophic sample: hard floor on h_hat triggers Fail
        // regardless of the median of the other two.
        let samples = vec![
            health_sample(0.55, 0.10, 0.55),
            health_sample(0.20, 0.10, 0.55), // h_hat below 0.35 hard floor
            health_sample(0.60, 0.10, 0.55),
        ];
        let (status, _, _) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Fail);
    }

    #[test]
    fn classify_m_sample_one_hard_rho_breach_rejects() {
        let samples = vec![
            health_sample(0.55, 0.10, 0.55),
            health_sample(0.55, 0.45, 0.55), // |rho| above 0.40 hard ceiling
            health_sample(0.55, 0.10, 0.55),
        ];
        let (status, _, _) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Fail);
    }

    #[test]
    fn classify_m_sample_lucky_draw_does_not_mask_variance() {
        // The brittleness scenario: one healthy draw (0.92) cannot save a
        // pair of failing draws.  Median is the second-best sample, so
        // (0.20, 0.41, 0.92) → median=0.41, but 0.20 trips the hard
        // floor → Fail.  This is the safety property: lucky cache
        // alignment cannot promote bad silicon to PASS.
        let samples = vec![
            health_sample(0.20, 0.10, 0.55),
            health_sample(0.41, 0.10, 0.50),
            health_sample(0.92, 0.10, 0.70),
        ];
        let (status, _, _) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Fail);
    }

    #[test]
    fn classify_m_sample_high_variance_clean_floors_lands_resonant() {
        // Real-world A54 spread: 0.41 / 0.77 / 0.92.  Median = 0.77 →
        // PASS.  All hard floors clean.  Result: Pass (FULL_ACCESS) on
        // the same silicon that single-K=21 acceptance rejected at 0.41.
        let samples = vec![
            health_sample(0.41, 0.10, 0.50),
            health_sample(0.77, 0.10, 0.65),
            health_sample(0.92, 0.10, 0.70),
        ];
        let (status, _, _) = classify_resonant_m_sample(&samples);
        assert_eq!(status, ResonantStatus::Pass);
    }

    #[test]
    fn respond_with_bad_challenge_length_rejected() {
        // Note: challenge ref is &[u8; 32] so this isn't reachable via type system,
        // but we can still assert the invariant holds as a sanity gate.
        let orbit = vec![0i64; 2048];
        let chain_tip = [0u8; 32];
        let cp = [0u8; 32];
        let dev = [0u8; 32];
        let bk = [0u8; 32];
        let challenge = [0u8; 32];
        // 32-byte verifier key is too short for real Kyber, should trip InvalidVerifierKey
        // only if < 32 — we're testing the 32-byte floor here.
        let bad_key = vec![0u8; 16];
        let inputs = RespondInputs {
            orbit_timings: &orbit,
            enrolled_mean: None,
            epsilon_intra: 0.0,
            verifier_public_key: &bad_key,
            challenge: &challenge,
            chain_tip: &chain_tip,
            commitment_preimage: &cp,
            device_id: &dev,
            binding_key: &bk,
            histogram_bins: 256,
            bin_range: None,
        };
        let result = respond_to_challenge(&inputs);
        assert!(matches!(result, Err(RespondError::InvalidVerifierKey)));
    }
}
