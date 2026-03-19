// C-DBRW Attractor Envelope Test (Def. 6.3)
//
// Moment commitments: m >= 8 statistical moments of the orbit density,
// each committed via BLAKE3 domain hash, assembled into a Merkle tree.

#ifndef CDBRW_MOMENTS_H
#define CDBRW_MOMENTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CDBRW_NUM_MOMENTS 8

// Compute m raw statistical moments from a histogram.
// hist: normalized histogram (probabilities summing to ~1.0)
// bins: number of bins
// out_moments: array of CDBRW_NUM_MOMENTS doubles (mean, var, skew, kurt, m5..m8)
void cdbrw_compute_moments(const float *hist, size_t bins, double out_moments[CDBRW_NUM_MOMENTS]);

// Commit each moment: BLAKE3("DSM/moment\0" || LE64(moment_bits) || LE32(index))
// out_commitments: array of CDBRW_NUM_MOMENTS * 32 bytes
void cdbrw_commit_moments(const double moments[CDBRW_NUM_MOMENTS], uint8_t *out_commitments);

// Build binary Merkle tree from moment commitments.
// leaves: CDBRW_NUM_MOMENTS * 32 bytes (the moment commitments)
// out_root: 32 bytes (Merkle root)
// out_tree: (2 * CDBRW_NUM_MOMENTS - 1) * 32 bytes (full tree for proof extraction)
void cdbrw_merkle_moments(const uint8_t *leaves, uint8_t out_root[32], uint8_t *out_tree);

// Extract Merkle proof for leaf at index.
// tree: full tree from cdbrw_merkle_moments
// leaf_index: 0..CDBRW_NUM_MOMENTS-1
// out_proof: ceil(log2(CDBRW_NUM_MOMENTS)) * 32 bytes = 3 * 32 = 96 bytes for 8 leaves
// Returns number of proof elements (3 for 8 leaves).
int cdbrw_merkle_proof(const uint8_t *tree, int leaf_index, uint8_t *out_proof);

#ifdef __cplusplus
}
#endif

#endif /* CDBRW_MOMENTS_H */
