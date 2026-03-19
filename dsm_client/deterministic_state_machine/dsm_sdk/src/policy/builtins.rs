//! Built-in CPTA for the native token: immutable bytes + fixed 32-byte commit.
//! Protobuf-only, no JSON/base64, no clocks.

use blake3::hash;

#[derive(Copy, Clone, Debug)]
pub enum BuiltinPolicy {
    Native,
    Dbtc,
}

pub const NATIVE_POLICY_COMMIT: &[u8; 32] = include_bytes!("../policy_commits/native.commit32"); // 32 RAW BYTES
pub const NATIVE_POLICY_BYTES: &[u8] = include_bytes!("../policies/native.ctpa.bin"); // OPAQUE PROTOBUF BYTES

pub const DBTC_POLICY_COMMIT: &[u8; 32] = include_bytes!("../policy_commits/dbtc.commit32"); // 32 RAW BYTES
pub const DBTC_POLICY_BYTES: &[u8] = include_bytes!("../policies/dbtc.ctpa.bin"); // OPAQUE PROTOBUF BYTES

#[inline]
pub fn bytes_and_commit(p: BuiltinPolicy) -> (&'static [u8], &'static [u8; 32]) {
    match p {
        BuiltinPolicy::Native => (NATIVE_POLICY_BYTES, NATIVE_POLICY_COMMIT),
        BuiltinPolicy::Dbtc => (DBTC_POLICY_BYTES, DBTC_POLICY_COMMIT),
    }
}

/// Enforce that built-ins are sound at load time.
/// STRICT: zero-commit is forbidden; mismatch panics.
/// This is aligned with "strict-fail" policy (no dev defaults).
pub fn assert_builtins_sound() {
    for (label, policy) in [
        ("native", BuiltinPolicy::Native),
        ("dbtc", BuiltinPolicy::Dbtc),
    ] {
        let (bytes, commit) = bytes_and_commit(policy);

        // Forbid all-zero commit
        let zero = [0u8; 32];
        assert_ne!(
            commit, &zero,
            "{label}.commit32 is all zeros — provide real commit bytes"
        );

        let got = hash(bytes);
        assert_eq!(
            got.as_bytes(),
            commit,
            "CPTA builtin mismatch: blake3({label}.ctpa.bin) != {label}.commit32",
        );
    }
}
