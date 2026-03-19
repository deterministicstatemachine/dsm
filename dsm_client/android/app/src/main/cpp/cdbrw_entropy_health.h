// C-DBRW Entropy Health Test (C implementation)
//
// Implements the 3-condition health test from the C-DBRW paper:
//   1. H_hat >= 0.45 (Shannon entropy of normalized histogram)
//   2. |rho_hat| <= 0.3 (lag-1 autocorrelation of orbit timings)
//   3. L_hat >= 0.45 (LZ78 compressibility metric)
//
// Also implements the manufacturing gate:
//   sigma_device = std(H_bar) / max(H_bar) >= 0.04

#ifndef CDBRW_ENTROPY_HEALTH_H
#define CDBRW_ENTROPY_HEALTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Health test thresholds (normative)
#define CDBRW_H_HAT_MIN      0.45f
#define CDBRW_RHO_HAT_MAX    0.30f
#define CDBRW_L_HAT_MIN      0.45f
#define CDBRW_SIGMA_DEV_MIN  0.04f
#define CDBRW_HEALTH_N       2048

typedef struct {
    float h_hat;       // Shannon entropy (normalized, 0..1)
    float rho_hat;     // lag-1 autocorrelation (-1..1)
    float l_hat;       // LZ78 compressibility (0..1)
    int   passed;      // 1 if all 3 conditions met, 0 otherwise
} cdbrw_health_result_t;

typedef struct {
    float sigma_device;  // std(H_bar)/max(H_bar)
    int   passed;        // 1 if sigma_device >= threshold
} cdbrw_mfg_gate_result_t;

// Compute Shannon entropy of a histogram (normalized to [0,1]).
// hist: array of counts/probabilities
// bins: number of histogram bins
// Returns H_hat in [0, 1] (normalized by log2(bins)).
float cdbrw_shannon_entropy(const float *hist, size_t bins);

// Compute lag-1 autocorrelation of timing samples.
// samples: raw timing values
// n: number of samples (should be CDBRW_HEALTH_N)
// Returns rho_hat in [-1, 1].
float cdbrw_lag1_autocorrelation(const int64_t *samples, size_t n);

// Compute LZ78 compressibility metric.
// Quantizes timing samples to 8-bit symbols, then counts LZ78 phrases.
// L_hat = 1.0 - (phrases / n), bounded to [0, 1].
//
// samples: raw timing values
// n: number of samples
// Returns L_hat in [0, 1].
float cdbrw_lz78_compressibility(const int64_t *samples, size_t n);

// Run full 3-condition health test.
// samples: raw orbit timing values (nanoseconds)
// n: number of samples (should be CDBRW_HEALTH_N = 2048)
// bins: histogram bins for entropy calculation (e.g., 256)
cdbrw_health_result_t cdbrw_health_test(const int64_t *samples, size_t n, size_t bins);

// Manufacturing gate: evaluate device variance.
// h_bars: array of per-trial entropy values from enrollment
// num_trials: number of enrollment trials
cdbrw_mfg_gate_result_t cdbrw_manufacturing_gate(const float *h_bars, size_t num_trials);

#ifdef __cplusplus
}
#endif

#endif /* CDBRW_ENTROPY_HEALTH_H */
