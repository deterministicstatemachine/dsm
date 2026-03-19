// SPDX-License-Identifier: MIT OR Apache-2.0
//! Production identity derivations used at platform boundaries.
//!
//! - Device ID: `DevID_A = H("DSM/devid\0" || pk_A || attest_digest)`
//!
//! For DBRW binding key derivation, use the canonical implementation in
//! `dsm::crypto::dbrw::DbrwCommitment::derive_binding_key()`.
//!
//! All outputs are 32 bytes.

use crate::types::error::DsmError;
use dsm::crypto::blake3::dsm_domain_hasher;

pub const DOMAIN_DEVID: &[u8] = b"DSM/devid\0";

/// Derive a 32-byte device identifier from a public key and an attestation digest.
///
/// Normative:
/// $$\mathrm{DevID} = H(\text{"DSM/devid"}\0 \parallel pk \parallel attest)$$
pub fn derive_device_id(pk: &[u8], attest_digest: &[u8]) -> [u8; 32] {
    let mut h = dsm_domain_hasher("DSM/devid");
    h.update(pk);
    h.update(attest_digest);
    *h.finalize().as_bytes()
}

/// Strict parser for 32-byte identifiers.
pub fn parse_id32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], DsmError> {
    if bytes.len() != 32 {
        return Err(DsmError::invalid_parameter(format!(
            "{what} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_domain_separated_and_stable() {
        let pk = b"pubkey";
        let attest = b"attest";
        let a = derive_device_id(pk, attest);
        let b = derive_device_id(pk, attest);
        assert_eq!(a, b);

        let c = derive_device_id(b"pubkey2", attest);
        assert_ne!(a, c);
    }
}
