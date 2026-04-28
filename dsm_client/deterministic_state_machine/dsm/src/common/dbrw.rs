//! DBRW (Dual-Binding Random Walk) provider — WP §12.
//!
//! Returns the 32-byte K_DBRW binding used to derive per-device PQ key material
//! during genesis (WP §11.1).
//!
//! Privacy invariants (HARD):
//!   - K_DBRW is NEVER serialized into any wire message or persisted artifact.
//!   - K_DBRW is NEVER logged or printed.
//!   - It is consumed only as ephemeral key-derivation input.
//!
//! Production: this module ships a deterministic stub that derives a binding
//! from the 32-byte DevID (per-device, repeatable). A hardware-backed reader
//! that mixes platform attestation entropy is a future enhancement.
//!
//! Tests: when compiled with `cfg(test)`, an alternate path keyed by the
//! `DSM_TEST_DBRW_SEED` environment variable is honored to enable
//! deterministic, reproducible test vectors. The variable's bytes are mixed
//! into the binding; absent the env var, the test path falls back to the
//! production derivation.

use crate::crypto::blake3::dsm_domain_hasher;

/// Compute K_DBRW for a given 32-byte DevID.
///
/// Returns 32 bytes. Output is the same on every call for the same DevID
/// in production, and the same on every call for the same
/// `(DevID, DSM_TEST_DBRW_SEED)` pair under tests.
pub fn binding_for(devid_a: &[u8; 32]) -> [u8; 32] {
    #[cfg(test)]
    {
        if let Ok(seed) = std::env::var("DSM_TEST_DBRW_SEED") {
            let mut h = dsm_domain_hasher("DSM/dbrw");
            h.update(devid_a);
            h.update(seed.as_bytes());
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            return out;
        }
    }

    // Production / default test path: deterministic per-device derivation.
    // Hardware-backed entropy mixing is tracked separately.
    let mut h = dsm_domain_hasher("DSM/dbrw");
    h.update(devid_a);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_deterministic_per_devid() {
        let a = binding_for(&[0xAB; 32]);
        let b = binding_for(&[0xAB; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn binding_differs_across_devids() {
        let a = binding_for(&[0x01; 32]);
        let b = binding_for(&[0x02; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn binding_is_32_bytes_and_nonzero() {
        let a = binding_for(&[0x42; 32]);
        assert_eq!(a.len(), 32);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn test_seed_changes_binding() {
        // Without env var
        std::env::remove_var("DSM_TEST_DBRW_SEED");
        let baseline = binding_for(&[0x77; 32]);

        // With env var
        std::env::set_var("DSM_TEST_DBRW_SEED", "test-seed-alpha");
        let seeded = binding_for(&[0x77; 32]);
        std::env::remove_var("DSM_TEST_DBRW_SEED");

        assert_ne!(baseline, seeded);
    }
}
