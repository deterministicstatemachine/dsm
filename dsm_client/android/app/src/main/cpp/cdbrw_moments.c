// C-DBRW Attractor Envelope Test implementation.
// Computes m=8 statistical moments of orbit density, commits each via
// BLAKE3 domain hash, and builds a binary Merkle tree for proofs.

#include "cdbrw_moments.h"
#include "dsm_domain_hash.h"
#include <math.h>
#include <string.h>

// --- Moment computation ---

void cdbrw_compute_moments(const float *hist, size_t bins, double out_moments[CDBRW_NUM_MOMENTS]) {
    memset(out_moments, 0, sizeof(double) * CDBRW_NUM_MOMENTS);
    if (bins == 0) return;

    // Compute mean (first moment about origin, using bin centers)
    double mean = 0.0;
    double inv_bins = 1.0 / (double)bins;
    for (size_t i = 0; i < bins; i++) {
        double x = ((double)i + 0.5) * inv_bins; // bin center in [0,1]
        mean += (double)hist[i] * x;
    }
    out_moments[0] = mean;

    // Compute central moments 2..8
    double cm[9]; // cm[k] = E[(X - mean)^k]
    memset(cm, 0, sizeof(cm));
    for (size_t i = 0; i < bins; i++) {
        double x = ((double)i + 0.5) * inv_bins;
        double d = x - mean;
        double p = (double)hist[i];
        double dk = d;
        for (int k = 2; k <= 8; k++) {
            dk *= d;
            cm[k] += p * dk;
        }
    }

    // Variance (second central moment)
    out_moments[1] = cm[2];

    // Skewness (standardized third moment)
    double sd = sqrt(fabs(cm[2]));
    if (sd > 1e-12) {
        out_moments[2] = cm[3] / (sd * sd * sd);
    }

    // Kurtosis (standardized fourth moment, excess)
    if (cm[2] > 1e-12) {
        out_moments[3] = cm[4] / (cm[2] * cm[2]) - 3.0;
    }

    // Raw higher moments m5..m8
    for (int k = 5; k <= 8; k++) {
        out_moments[k - 1] = cm[k];
    }
}

// --- Moment commitments ---

static void store_le64(uint8_t *out, uint64_t v) {
    out[0] = (uint8_t)(v >>  0);
    out[1] = (uint8_t)(v >>  8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
    out[4] = (uint8_t)(v >> 32);
    out[5] = (uint8_t)(v >> 40);
    out[6] = (uint8_t)(v >> 48);
    out[7] = (uint8_t)(v >> 56);
}

static void store_le32(uint8_t *out, uint32_t v) {
    out[0] = (uint8_t)(v >>  0);
    out[1] = (uint8_t)(v >>  8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

void cdbrw_commit_moments(const double moments[CDBRW_NUM_MOMENTS], uint8_t *out_commitments) {
    for (int i = 0; i < CDBRW_NUM_MOMENTS; i++) {
        // Serialize moment as IEEE 754 double bits (LE) + index (LE32)
        uint64_t bits;
        memcpy(&bits, &moments[i], sizeof(uint64_t));

        uint8_t data[12]; // 8 bytes moment + 4 bytes index
        store_le64(data, bits);
        store_le32(data + 8, (uint32_t)i);

        dsm_domain_hash_str("DSM/moment", data, 12, out_commitments + i * 32);
    }
}

// --- Merkle tree ---
// Binary tree over 8 leaves = 15 nodes.
// Layout: nodes[0..7] = leaves, nodes[8..14] = internal, nodes[14] = root.
// Parent of i: (i - 1) / 2 for 1-indexed, but we use array layout:
//   leaves at [offset..offset+n-1], parents computed level by level.

// For 8 leaves: 3 levels of internal nodes.
// Level 0 (leaves): 8 nodes at index [0..7]
// Level 1: 4 nodes at index [8..11]
// Level 2: 2 nodes at index [12..13]
// Level 3 (root): 1 node at index [14]

void cdbrw_merkle_moments(const uint8_t *leaves, uint8_t out_root[32], uint8_t *out_tree) {
    const int n = CDBRW_NUM_MOMENTS; // 8
    const int total = 2 * n - 1;     // 15

    // Copy leaves to tree
    memcpy(out_tree, leaves, (size_t)n * 32);

    // Build internal nodes
    int src = 0;
    int dst = n;
    int level_size = n;
    while (level_size > 1) {
        int pairs = level_size / 2;
        for (int i = 0; i < pairs; i++) {
            // parent = H(left || right)
            uint8_t combined[64];
            memcpy(combined, out_tree + (size_t)(src + 2 * i) * 32, 32);
            memcpy(combined + 32, out_tree + (size_t)(src + 2 * i + 1) * 32, 32);

            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, combined, 64);
            blake3_hasher_finalize(&h, out_tree + (size_t)dst * 32, 32);
            dst++;
        }
        src += level_size;
        level_size = pairs;
    }

    // Root is the last node
    memcpy(out_root, out_tree + (size_t)(total - 1) * 32, 32);
}

int cdbrw_merkle_proof(const uint8_t *tree, int leaf_index, uint8_t *out_proof) {
    if (leaf_index < 0 || leaf_index >= CDBRW_NUM_MOMENTS) return 0;

    // For 8 leaves, proof depth = 3 (log2(8))
    const int depth = 3;
    int idx = leaf_index;
    int level_start = 0;
    int level_size = CDBRW_NUM_MOMENTS;

    for (int d = 0; d < depth; d++) {
        int sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        memcpy(out_proof + d * 32, tree + (size_t)(level_start + sibling) * 32, 32);
        level_start += level_size;
        idx /= 2;
        level_size /= 2;
    }

    return depth;
}
