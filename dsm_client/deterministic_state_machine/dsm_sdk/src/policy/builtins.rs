// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in policy bytes for dBTC: immutable bytes + fixed 32-byte commit.
//! ERA's policy is Core's (`dsm::core::token::era_policy`). Protobuf-only,
//! no JSON/base64, no clocks.

use blake3::hash;

#[derive(Copy, Clone, Debug)]
pub enum BuiltinPolicy {
    Dbtc,
}

pub const DBTC_POLICY_COMMIT: &[u8; 32] = include_bytes!("../policy_commits/dbtc.commit32"); // 32 RAW BYTES
pub const DBTC_POLICY_BYTES: &[u8] = include_bytes!("../policies/dbtc.ctpa.bin"); // OPAQUE PROTOBUF BYTES

#[inline]
pub fn bytes_and_commit(p: BuiltinPolicy) -> (&'static [u8], &'static [u8; 32]) {
    match p {
        BuiltinPolicy::Dbtc => (DBTC_POLICY_BYTES, DBTC_POLICY_COMMIT),
    }
}

/// Enforce that built-ins are sound at load time.
/// STRICT: zero-commit is forbidden; mismatch panics.
/// This is aligned with "strict-fail" policy (no dev defaults).
pub fn assert_builtins_sound() {
    let (bytes, commit) = bytes_and_commit(BuiltinPolicy::Dbtc);

    // Forbid all-zero commit
    let zero = [0u8; 32];
    assert_ne!(
        commit, &zero,
        "dbtc.commit32 is all zeros — provide real commit bytes"
    );

    let got = hash(bytes);
    assert_eq!(
        got.as_bytes(),
        commit,
        "CPTA builtin mismatch: blake3(dbtc.ctpa.bin) != dbtc.commit32",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbtc_policy_commit_is_32_bytes() {
        assert_eq!(DBTC_POLICY_COMMIT.len(), 32);
    }

    #[test]
    fn bytes_and_commit_dbtc_matches_constants() {
        let (bytes, commit) = bytes_and_commit(BuiltinPolicy::Dbtc);
        assert_eq!(bytes, DBTC_POLICY_BYTES);
        assert_eq!(commit, DBTC_POLICY_COMMIT);
    }

    #[test]
    fn dbtc_commit_not_all_zeros() {
        assert_ne!(DBTC_POLICY_COMMIT, &[0u8; 32]);
    }

    #[test]
    fn assert_builtins_sound_does_not_panic() {
        assert_builtins_sound();
    }

    #[test]
    fn builtin_enum_debug_format() {
        let dbtc = format!("{:?}", BuiltinPolicy::Dbtc);
        assert_eq!(dbtc, "Dbtc");
    }
}
