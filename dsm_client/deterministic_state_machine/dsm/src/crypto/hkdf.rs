// SPDX-License-Identifier: Apache-2.0

//! HKDF (RFC 5869) over BLAKE3.
//!
//! The KDF of key schedule KS1 (`core::identity::key_schedule`): each root
//! secret has one Extract under a fixed protocol salt, and every derivation
//! is an Expand whose `info` carries its domain label and its context.
//!
//! The HMAC primitive is constructed per RFC 2104 with BLAKE3 as the
//! underlying hash function (BLAKE3 internal block size 64 bytes,
//! output 32 bytes).  Self-contained: depends only on the `blake3`
//! crate already in the workspace.

const BLAKE3_BLOCK_SIZE: usize = 64;
const BLAKE3_OUTPUT_SIZE: usize = 32;

const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

use zeroize::Zeroize;

/// HMAC-BLAKE3 per RFC 2104.  Output is 32 bytes.  Keys longer than the
/// block size are pre-hashed; shorter keys are zero-padded.
///
/// Every intermediate is key material: the condensed key block, both pads,
/// the two hasher states (each still buffers its pad) and the inner digest.
/// All of them are wiped before the MAC is returned.
fn hmac_blake3(key: &[u8], message: &[u8]) -> [u8; 32] {
    // Step 1: condense key to a single block.  If key > block size,
    // hash it; otherwise zero-pad.
    let mut block_key = [0u8; BLAKE3_BLOCK_SIZE];
    if key.len() > BLAKE3_BLOCK_SIZE {
        let mut h = ::blake3::hash(key);
        block_key[..BLAKE3_OUTPUT_SIZE].copy_from_slice(h.as_bytes());
        h.zeroize();
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    // Step 2: build inner and outer pads.
    let mut ipad = [0u8; BLAKE3_BLOCK_SIZE];
    let mut opad = [0u8; BLAKE3_BLOCK_SIZE];
    for i in 0..BLAKE3_BLOCK_SIZE {
        ipad[i] = block_key[i] ^ HMAC_IPAD;
        opad[i] = block_key[i] ^ HMAC_OPAD;
    }
    block_key.zeroize();

    // Step 3: inner hash = BLAKE3(ipad || message).
    let mut inner = ::blake3::Hasher::new();
    inner.update(&ipad);
    inner.update(message);
    let mut inner_digest = inner.finalize();
    inner.zeroize();
    ipad.zeroize();

    // Step 4: outer hash = BLAKE3(opad || inner_digest).
    let mut outer = ::blake3::Hasher::new();
    outer.update(&opad);
    outer.update(inner_digest.as_bytes());
    let mut outer_digest = outer.finalize();
    outer.zeroize();
    opad.zeroize();
    inner_digest.zeroize();
    let out: [u8; BLAKE3_OUTPUT_SIZE] = *outer_digest.as_bytes();
    outer_digest.zeroize();
    out
}

/// HKDF-Extract per RFC 5869 §2.2.  Returns the 32-byte pseudorandom
/// key (PRK).  Empty salt is treated as `[0u8; 32]` per the RFC.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    if salt.is_empty() {
        hmac_blake3(&[0u8; BLAKE3_OUTPUT_SIZE], ikm)
    } else {
        hmac_blake3(salt, ikm)
    }
}

/// HKDF-Expand per RFC 5869 §2.3.  Returns exactly `length` bytes.
///
/// Panics if `length > 255 * 32` (8160 bytes), the RFC 5869 cap.
pub fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let n = length.div_ceil(BLAKE3_OUTPUT_SIZE);
    assert!(
        n <= 255,
        "HKDF-Expand: requested length {length} exceeds 255 * HashLen ({} bytes)",
        255 * BLAKE3_OUTPUT_SIZE,
    );

    // `okm` is allocated at its full block length up front, so it never
    // reallocates and leaves no unwiped copy of earlier blocks behind; the
    // bytes past `length` are wiped before it is cut to size. Each block
    // `T(i)` is key material, so the chaining copy and every HMAC input that
    // carries it are wiped too.
    let mut okm = Vec::with_capacity(n * BLAKE3_OUTPUT_SIZE);
    let mut prev: [u8; BLAKE3_OUTPUT_SIZE] = [0u8; BLAKE3_OUTPUT_SIZE];
    let mut prev_len = 0usize;

    for i in 1..=n {
        let mut buf = Vec::with_capacity(prev_len + info.len() + 1);
        buf.extend_from_slice(&prev[..prev_len]);
        buf.extend_from_slice(info);
        buf.push(i as u8);
        let t = hmac_blake3(prk, &buf);
        buf.zeroize();
        okm.extend_from_slice(&t);
        prev = t;
        prev_len = BLAKE3_OUTPUT_SIZE;
    }
    prev.zeroize();

    okm[length..].zeroize();
    okm.truncate(length);
    okm
}

/// HKDF-Expand per RFC 5869 §2.3 for exactly one hash length (L = 32): the
/// output is the first block, `T(1) = HMAC(PRK, info ‖ 0x01)`, which is what
/// `expand(prk, info, 32)` returns.
pub fn expand32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(info.len() + 1);
    buf.extend_from_slice(info);
    buf.push(1u8);
    let t = hmac_blake3(prk, &buf);
    buf.zeroize();
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand32_is_the_first_block_of_expand() {
        let prk = extract(b"DSM/dev\0", b"some-input-keying-material");
        for info in [&b""[..], &b"label\0"[..], &b"label\0fields"[..]] {
            assert_eq!(
                expand32(&prk, info).as_slice(),
                expand(&prk, info, 32).as_slice()
            );
        }
    }

    #[test]
    fn extract_is_deterministic() {
        let salt = b"DSM/dev\0";
        let ikm = b"some-input-keying-material";
        let prk1 = extract(salt, ikm);
        let prk2 = extract(salt, ikm);
        assert_eq!(prk1, prk2);
        assert_eq!(prk1.len(), 32);
    }

    #[test]
    fn extract_differs_on_salt_change() {
        let ikm = b"ikm";
        let p1 = extract(b"DSM/dev\0", ikm);
        let p2 = extract(b"DSM/eph\0", ikm);
        assert_ne!(p1, p2);
    }

    #[test]
    fn extract_differs_on_ikm_change() {
        let salt = b"DSM/dev\0";
        let p1 = extract(salt, b"ikm-a");
        let p2 = extract(salt, b"ikm-b");
        assert_ne!(p1, p2);
    }

    #[test]
    fn extract_handles_empty_salt() {
        // RFC 5869: empty salt is treated as HashLen zero-bytes.
        let prk_empty = extract(b"", b"ikm");
        let prk_zero = extract(&[0u8; 32], b"ikm");
        assert_eq!(prk_empty, prk_zero);
    }

    #[test]
    fn extract_handles_long_salt() {
        // Salt longer than block size (64 B) gets pre-hashed.  Self-
        // consistency: producing PRK from a 100-byte salt completes
        // and is deterministic.
        let long_salt = vec![0xABu8; 100];
        let p1 = extract(&long_salt, b"ikm");
        let p2 = extract(&long_salt, b"ikm");
        assert_eq!(p1, p2);
    }

    #[test]
    fn expand_returns_exact_length() {
        let prk = extract(b"salt", b"ikm");
        for &len in &[1usize, 16, 32, 33, 64, 100, 8000] {
            let okm = expand(&prk, b"info", len);
            assert_eq!(okm.len(), len, "expand({len}) returned {} bytes", okm.len());
        }
    }

    #[test]
    fn expand_is_deterministic() {
        let prk = extract(b"salt", b"ikm");
        let okm1 = expand(&prk, b"info", 64);
        let okm2 = expand(&prk, b"info", 64);
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn expand_differs_on_info_change() {
        let prk = extract(b"salt", b"ikm");
        let a = expand(&prk, b"DSM/sphincs-plus-seed\0", 32);
        let b = expand(&prk, b"DSM/kyber\0", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn expand_differs_on_prk_change() {
        let prk1 = extract(b"salt", b"ikm-a");
        let prk2 = extract(b"salt", b"ikm-b");
        let a = expand(&prk1, b"info", 32);
        let b = expand(&prk2, b"info", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn expand_chains_correctly_across_blocks() {
        // For lengths > 32 the algorithm chains T(1), T(2), ...
        // T(2) must depend on T(1) so simply repeating T(1) twice
        // would NOT match.  Verify by construction: extract first
        // 32 bytes and last 32 bytes of a 64-byte expansion and
        // assert they differ (as they must under chaining).
        let prk = extract(b"salt", b"ikm");
        let okm = expand(&prk, b"info", 64);
        assert_eq!(okm.len(), 64);
        let first = &okm[..32];
        let second = &okm[32..];
        assert_ne!(first, second, "T(1) and T(2) must differ");
    }

    #[test]
    fn whitepaper_master_seed_shape_compiles() {
        // Smoke test that the DSM whitepaper §11.1 eq.13 derivation
        // shape works through this module.
        let g = [0xAAu8; 32];
        let devid = [0xBBu8; 32];
        let chain_head_wrap_key = [0xCCu8; 32];
        let s_0 = [0xDDu8; 32];
        let mut ikm = Vec::with_capacity(32 * 4);
        ikm.extend_from_slice(&g);
        ikm.extend_from_slice(&devid);
        ikm.extend_from_slice(&chain_head_wrap_key);
        ikm.extend_from_slice(&s_0);
        let s_master = extract(b"DSM/dev\0", &ikm);
        assert_eq!(s_master.len(), 32);
        // Sub-derivations under distinct sub-domains diverge.
        let sphincs_seed = expand(&s_master, b"DSM/sphincs-plus-seed\0", 32);
        let kyber_seed = expand(&s_master, b"DSM/kyber\0", 32);
        assert_ne!(sphincs_seed, kyber_seed);
    }
}
