//! Small no_std helpers.

use alloc::vec::Vec;

/// Append a variable-length byte field to `buf` with a 4-byte little-endian
/// length prefix, so a canonical concatenation of variable-length fields is
/// unambiguously parseable (prefix-free). Used by `enc(Δ)` for the action fields
/// and the DSM SMT leaf proofs. The prefix is `u32`, not `u16`: a deep SMT proof
/// can exceed `u16` bytes, and a truncating prefix would alias distinct field
/// boundaries and break the collision/rebinding resistance the transition digest
/// `D` relies on (Thm 25).
pub fn push_var(buf: &mut Vec<u8>, field: &[u8]) {
    debug_assert!(
        field.len() <= u32::MAX as usize,
        "field too large to length-prefix"
    );
    buf.extend_from_slice(&u32_le(field.len() as u32));
    buf.extend_from_slice(field);
}

/// Constant-time equality for fixed 32-byte values (frontier / digest
/// comparisons). Avoids leaking how many leading bytes matched.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Securely wipe a secret buffer: volatile writes the optimizer may not elide,
/// fenced so the zeroing is not reordered past the buffer's last use.
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, writable `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Wipe a secret `Vec` and empty it (so an `is_empty()` "key present?" check reads
/// false only while a live key is present).
pub fn zeroize_vec(v: &mut Vec<u8>) {
    zeroize(v);
    v.clear();
}

/// Canonical little-endian encodings for integer protocol fields
/// (indices, counter values, slot ids).
#[inline]
pub fn u16_le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

#[inline]
pub fn u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[inline]
pub fn u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
