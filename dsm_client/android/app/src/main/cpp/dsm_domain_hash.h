// DSM Domain-Separated BLAKE3 Helper
// Implements: BLAKE3-256("DSM/<domain>\0" || data)
// All DSM hashing goes through this single entry point.

#ifndef DSM_DOMAIN_HASH_H
#define DSM_DOMAIN_HASH_H

#include "blake3/blake3.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute BLAKE3-256 with DSM domain separation.
// tag: NUL-terminated domain tag (e.g., "DSM/dbrw-bind\0")
// tag_len: length INCLUDING the trailing NUL byte
// data: payload bytes
// data_len: payload length
// out: 32-byte output buffer
static inline void dsm_domain_hash(
    const uint8_t *tag, size_t tag_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, tag, tag_len);
    blake3_hasher_update(&hasher, data, data_len);
    blake3_hasher_finalize(&hasher, out, 32);
}

// Convenience: tag from a C string literal (auto-includes NUL).
// Usage: dsm_domain_hash_str("DSM/dbrw-bind", data, len, out)
// The NUL byte is part of the hash preimage per DSM spec.
static inline void dsm_domain_hash_str(
    const char *tag,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
) {
    size_t tag_len = strlen(tag) + 1; // +1 for NUL terminator
    dsm_domain_hash((const uint8_t *)tag, tag_len, data, data_len, out);
}

#ifdef __cplusplus
}
#endif

#endif /* DSM_DOMAIN_HASH_H */
