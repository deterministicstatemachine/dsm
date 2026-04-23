// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV lifecycle authoring (v3) — deterministic, clockless, bytes-only.
//!
//! Authors DlvOpenV3 proto objects for storage mirroring.  DLV creation
//! is no longer authored here; the real creation path goes through
//! LimboVault::prepare_vault (content+fulfillment+ref_state anchored) and
//! is packaged as DlvInstantiateV1 at the wire boundary.
//!
//! Authenticity is device-side (SPHINCS+ signatures in the envelope layer).
//! Storage nodes are dumb mirrors.

use prost::Message;

use crate::wire::{domain_hash_bytes, pb};

/// Author a DlvOpenV3 reveal.
///
/// Verifiers check that H("DSM/dlv/precommit\0" || reveal_material) matches the
/// precommit recorded on the corresponding accepted vault.
pub fn author_dlv_open(
    device_id: &[u8; 32],
    vault_id: &[u8; 32],
    reveal_material: &[u8],
) -> pb::DlvOpenV3 {
    pb::DlvOpenV3 {
        device_id: device_id.to_vec(),
        vault_id: vault_id.to_vec(),
        reveal_material: reveal_material.to_vec(),
    }
}

/// Convenience: deterministic digest for the authored DlvOpenV3.
pub fn dlv_open_digest(open: &pb::DlvOpenV3) -> [u8; 32] {
    let bytes = open.encode_to_vec();
    domain_hash_bytes("DSM/dlv/open\0", &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: [u8; 32] = [0xAA; 32];

    #[test]
    fn author_dlv_open_populates_fields() {
        let vault = [0xDD; 32];
        let reveal = b"reveal-data";
        let open = author_dlv_open(&DEVICE, &vault, reveal);
        assert_eq!(open.device_id, DEVICE.to_vec());
        assert_eq!(open.vault_id, vault.to_vec());
        assert_eq!(open.reveal_material, reveal.to_vec());
    }

    #[test]
    fn dlv_open_digest_deterministic() {
        let vault = [0xEE; 32];
        let open = author_dlv_open(&DEVICE, &vault, b"reveal");
        let d1 = dlv_open_digest(&open);
        let d2 = dlv_open_digest(&open);
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }
}
