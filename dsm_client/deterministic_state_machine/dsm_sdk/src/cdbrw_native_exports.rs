// SPDX-License-Identifier: MIT OR Apache-2.0
//! Plain-C exports consumed by `libsiliconfp.so` (the NDK C-DBRW probe).
//!
//! `siliconfp.cpp` must implement spec-compliant ARX orbits (cdbrw.instructions.md
//! Def 9.1 + Alg 1). To do that it needs three primitives from the Rust core:
//!
//! 1. `dsm_blake3_keyed` — domain-separated BLAKE3-256 for folding the silicon
//!    substrate readings `(t, v, τ, cycles, misses, cntvct)` into a single byte
//!    `µ_n` per Def 3.2.
//! 2. `dsm_seed_orbit` — challenge-seeded x_0 derivation per Alg 1 step 1,
//!    locking the C++ side to the same byte layout as the Rust source of truth
//!    in [`dsm::crypto::cdbrw_binding::seed_orbit`].
//! 3. `dsm_get_cdbrw_binding_key` — pull K_DBRW from the in-process slot so
//!    K_DBRW never crosses the JNI boundary as a parameter (defense in depth —
//!    Theorem 5.2 rule §K-DBRW key material rules).
//!
//! All three live in `libdsm_sdk.so`. `libsiliconfp.so` links against it via
//! the CMake `target_link_libraries(siliconfp dsm_sdk ...)` line.

use std::slice;

/// Domain-separated BLAKE3-256.
///
/// Computes `BLAKE3(tag || \0 || data)` where `tag` is a NUL-terminated C
/// string (e.g. `"DSM/cdbrw-thermal"`). The trailing NUL of the tag is added
/// by the underlying [`dsm::crypto::blake3::dsm_domain_hasher`], so callers
/// pass the tag without a trailing NUL — the byte at the C-string terminator
/// is read by `strlen` only and never hashed.
///
/// # Safety
/// - `tag` must be a valid NUL-terminated C string in readable memory.
/// - `data` must point to `data_len` readable bytes (may be NULL if
///   `data_len == 0`).
/// - `out` must point to 32 writable bytes.
/// - All buffers must not alias each other.
///
/// Returns `false` on invalid arguments (NULL `tag`, NULL `out`, tag does not
/// start with `"DSM/"` or `"DJTE."`).
#[no_mangle]
pub unsafe extern "C" fn dsm_blake3_keyed(
    tag: *const std::os::raw::c_char,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> bool {
    if tag.is_null() || out.is_null() {
        return false;
    }
    if data.is_null() && data_len != 0 {
        return false;
    }
    let tag_cstr = std::ffi::CStr::from_ptr(tag);
    let tag_str = match tag_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !(tag_str.starts_with("DSM/") || tag_str.starts_with("DJTE.")) {
        return false;
    }
    let data_slice: &[u8] = if data_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, data_len)
    };
    let digest = dsm::crypto::blake3::domain_hash_bytes(tag_str, data_slice);
    let out_slice = slice::from_raw_parts_mut(out, 32);
    out_slice.copy_from_slice(&digest);
    true
}

/// Challenge-seeded orbit start per Alg 1 step 1:
/// `x_0 = H("DSM/cdbrw-seed\0" || challenge || K_DBRW) mod 2^32`.
///
/// # Safety
/// - `challenge` must point to 32 readable bytes.
/// - `kdbrw` must point to 32 readable bytes (use a zero buffer for the
///   enrollment-trial form before K_DBRW is bound).
///
/// Returns the seed as a little-endian `u32`. On invalid args returns `0` —
/// callers MUST verify pointer validity before calling.
#[no_mangle]
pub unsafe extern "C" fn dsm_seed_orbit(challenge: *const u8, kdbrw: *const u8) -> u32 {
    if challenge.is_null() || kdbrw.is_null() {
        return 0;
    }
    let c = slice::from_raw_parts(challenge, 32);
    let k_slice = slice::from_raw_parts(kdbrw, 32);
    let mut k_arr = [0u8; 32];
    k_arr.copy_from_slice(k_slice);
    dsm::crypto::cdbrw_binding::seed_orbit(c, &k_arr)
}

/// Copy the bootstrap-installed K_DBRW into `out` (32 bytes).
///
/// Returns `true` if a key was present and copied, `false` if the slot is
/// empty (e.g. during enrollment trials before genesis). Callers MUST treat
/// `false` as "use zero K_DBRW for the orbit seed" and never invent a
/// substitute.
///
/// # Safety
/// - `out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn dsm_get_cdbrw_binding_key(out: *mut u8) -> bool {
    if out.is_null() {
        return false;
    }
    let Some(key) = crate::binding_key::get_binding_key() else {
        return false;
    };
    if key.len() != 32 {
        return false;
    }
    let out_slice = slice::from_raw_parts_mut(out, 32);
    out_slice.copy_from_slice(&key);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn blake3_keyed_matches_rust_one_shot() {
        let tag = CString::new("DSM/cdbrw-thermal").unwrap();
        let data = b"abc";
        let mut out = [0u8; 32];
        let ok = unsafe { dsm_blake3_keyed(tag.as_ptr(), data.as_ptr(), data.len(), out.as_mut_ptr()) };
        assert!(ok);
        let expected = dsm::crypto::blake3::domain_hash_bytes("DSM/cdbrw-thermal", data);
        assert_eq!(out, expected);
    }

    #[test]
    fn blake3_keyed_empty_data() {
        let tag = CString::new("DSM/cdbrw-thermal").unwrap();
        let mut out = [0u8; 32];
        let ok = unsafe { dsm_blake3_keyed(tag.as_ptr(), std::ptr::null(), 0, out.as_mut_ptr()) };
        assert!(ok);
        let expected = dsm::crypto::blake3::domain_hash_bytes("DSM/cdbrw-thermal", &[]);
        assert_eq!(out, expected);
    }

    #[test]
    fn blake3_keyed_rejects_non_dsm_tag() {
        let tag = CString::new("evil/tag").unwrap();
        let mut out = [0u8; 32];
        let ok = unsafe { dsm_blake3_keyed(tag.as_ptr(), b"x".as_ptr(), 1, out.as_mut_ptr()) };
        assert!(!ok);
    }

    #[test]
    fn blake3_keyed_rejects_null_tag() {
        let mut out = [0u8; 32];
        let ok = unsafe { dsm_blake3_keyed(std::ptr::null(), b"x".as_ptr(), 1, out.as_mut_ptr()) };
        assert!(!ok);
    }

    #[test]
    fn seed_orbit_matches_rust_canonical() {
        let c = [0x11u8; 32];
        let k = [0xABu8; 32];
        let via_ffi = unsafe { dsm_seed_orbit(c.as_ptr(), k.as_ptr()) };
        let via_rust = dsm::crypto::cdbrw_binding::seed_orbit(&c, &k);
        assert_eq!(via_ffi, via_rust);
    }

    #[test]
    fn seed_orbit_zero_kdbrw_is_enrollment_form() {
        // During enrollment trials, callers pass kdbrw = zeros.
        // The seed is still well-defined and challenge-dependent.
        let c1 = [0x01u8; 32];
        let c2 = [0x02u8; 32];
        let zeros = [0u8; 32];
        let s1 = unsafe { dsm_seed_orbit(c1.as_ptr(), zeros.as_ptr()) };
        let s2 = unsafe { dsm_seed_orbit(c2.as_ptr(), zeros.as_ptr()) };
        assert_ne!(s1, s2, "distinct challenges must yield distinct seeds");
    }

    #[test]
    fn seed_orbit_null_returns_zero() {
        assert_eq!(unsafe { dsm_seed_orbit(std::ptr::null(), std::ptr::null()) }, 0);
    }
}
