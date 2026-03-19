// C-DBRW Entropy Health Test implementation.
// See cdbrw_entropy_health.h for spec references.

#include "cdbrw_entropy_health.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

// --- Shannon entropy ---

float cdbrw_shannon_entropy(const float *hist, size_t bins) {
    if (bins <= 1) return 0.0f;

    double entropy = 0.0;
    for (size_t i = 0; i < bins; i++) {
        double p = (double)hist[i];
        if (p > 1e-12) {
            entropy -= p * log2(p);
        }
    }
    // Normalize to [0, 1]
    double max_entropy = log2((double)bins);
    if (max_entropy < 1e-12) return 0.0f;
    double h_hat = entropy / max_entropy;
    if (h_hat > 1.0) h_hat = 1.0;
    if (h_hat < 0.0) h_hat = 0.0;
    return (float)h_hat;
}

// --- Lag-1 autocorrelation ---

float cdbrw_lag1_autocorrelation(const int64_t *samples, size_t n) {
    if (n < 3) return 0.0f;

    // Compute mean
    double mean = 0.0;
    for (size_t i = 0; i < n; i++) {
        mean += (double)samples[i];
    }
    mean /= (double)n;

    // Compute variance and lag-1 covariance
    double var = 0.0;
    double cov = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = (double)samples[i] - mean;
        var += d * d;
        if (i > 0) {
            double d_prev = (double)samples[i - 1] - mean;
            cov += d * d_prev;
        }
    }

    if (var < 1e-12) return 0.0f;
    double rho = cov / var;
    if (rho > 1.0) rho = 1.0;
    if (rho < -1.0) rho = -1.0;
    return (float)rho;
}

// --- LZ78 compressibility ---
// Simple LZ78 phrase counting using a trie.

// Trie node for LZ78
typedef struct lz78_node {
    uint16_t children[256]; // 0 = no child, otherwise index into pool
} lz78_node_t;

float cdbrw_lz78_compressibility(const int64_t *samples, size_t n) {
    if (n == 0) return 0.0f;

    // Quantize samples to 8-bit symbols
    // Use percentile-based quantization for robustness
    int64_t min_val = samples[0], max_val = samples[0];
    for (size_t i = 1; i < n; i++) {
        if (samples[i] < min_val) min_val = samples[i];
        if (samples[i] > max_val) max_val = samples[i];
    }

    uint8_t *symbols = (uint8_t *)malloc(n);
    if (!symbols) return 0.0f;

    int64_t range = max_val - min_val;
    if (range <= 0) range = 1;
    for (size_t i = 0; i < n; i++) {
        int64_t normalized = ((samples[i] - min_val) * 255) / range;
        if (normalized < 0) normalized = 0;
        if (normalized > 255) normalized = 255;
        symbols[i] = (uint8_t)normalized;
    }

    // LZ78 phrase counting with bounded trie
    // Max trie nodes: n + 1 (each phrase adds at most one node)
    size_t max_nodes = n + 1;
    if (max_nodes > 65535) max_nodes = 65535; // uint16_t index limit
    lz78_node_t *pool = (lz78_node_t *)calloc(max_nodes, sizeof(lz78_node_t));
    if (!pool) {
        free(symbols);
        return 0.0f;
    }

    size_t node_count = 1; // root is node 0
    size_t phrases = 0;
    size_t current = 0; // start at root

    for (size_t i = 0; i < n; i++) {
        uint8_t sym = symbols[i];
        uint16_t child = pool[current].children[sym];
        if (child != 0) {
            // Follow existing trie path
            current = child;
        } else {
            // New phrase found
            phrases++;
            if (node_count < max_nodes) {
                pool[current].children[sym] = (uint16_t)node_count;
                node_count++;
            }
            current = 0; // reset to root
        }
    }
    // Count final incomplete phrase
    if (current != 0) {
        phrases++;
    }

    free(pool);
    free(symbols);

    // L_hat = 1.0 - phrases/n
    float l_hat = 1.0f - (float)phrases / (float)n;
    if (l_hat < 0.0f) l_hat = 0.0f;
    if (l_hat > 1.0f) l_hat = 1.0f;
    return l_hat;
}

// --- Full health test ---

cdbrw_health_result_t cdbrw_health_test(const int64_t *samples, size_t n, size_t bins) {
    cdbrw_health_result_t result;
    memset(&result, 0, sizeof(result));

    if (n == 0 || bins == 0) return result;

    // Build histogram from raw samples
    float *hist = (float *)calloc(bins, sizeof(float));
    if (!hist) return result;

    int64_t min_val = samples[0], max_val = samples[0];
    for (size_t i = 1; i < n; i++) {
        if (samples[i] < min_val) min_val = samples[i];
        if (samples[i] > max_val) max_val = samples[i];
    }

    int64_t range = max_val - min_val;
    if (range <= 0) range = 1;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (size_t)(((samples[i] - min_val) * (int64_t)(bins - 1)) / range);
        if (idx >= bins) idx = bins - 1;
        hist[idx] += 1.0f;
    }
    // Normalize
    float inv_n = 1.0f / (float)n;
    for (size_t i = 0; i < bins; i++) {
        hist[i] *= inv_n;
    }

    result.h_hat = cdbrw_shannon_entropy(hist, bins);
    result.rho_hat = cdbrw_lag1_autocorrelation(samples, n);
    result.l_hat = cdbrw_lz78_compressibility(samples, n);

    result.passed = (result.h_hat >= CDBRW_H_HAT_MIN) &&
                    (fabsf(result.rho_hat) <= CDBRW_RHO_HAT_MAX) &&
                    (result.l_hat >= CDBRW_L_HAT_MIN);

    free(hist);
    return result;
}

// --- Manufacturing gate ---

cdbrw_mfg_gate_result_t cdbrw_manufacturing_gate(const float *h_bars, size_t num_trials) {
    cdbrw_mfg_gate_result_t result;
    memset(&result, 0, sizeof(result));

    if (num_trials < 2) return result;

    // Compute mean
    double mean = 0.0;
    float max_h = h_bars[0];
    for (size_t i = 0; i < num_trials; i++) {
        mean += (double)h_bars[i];
        if (h_bars[i] > max_h) max_h = h_bars[i];
    }
    mean /= (double)num_trials;

    // Compute std
    double var = 0.0;
    for (size_t i = 0; i < num_trials; i++) {
        double d = (double)h_bars[i] - mean;
        var += d * d;
    }
    var /= (double)(num_trials - 1); // sample variance
    double std_dev = sqrt(var);

    // sigma_device = std(H_bar) / max(H_bar)
    if ((double)max_h < 1e-12) {
        result.sigma_device = 0.0f;
        result.passed = 0;
        return result;
    }
    result.sigma_device = (float)(std_dev / (double)max_h);
    result.passed = (result.sigma_device >= CDBRW_SIGMA_DEV_MIN) ? 1 : 0;
    return result;
}
