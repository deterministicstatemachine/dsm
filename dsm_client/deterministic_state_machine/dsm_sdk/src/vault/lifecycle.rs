// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV lifecycle authoring (v3) — deterministic, clockless, bytes-only.
//!
//! This module authors the protobuf objects for storage mirroring:
//! - `DlvCreateV3` (commit)
//! - `DlvOpenV3` (reveal)
//!
//! Authenticity is device-side (SPHINCS+ signatures in the envelope layer).
//! Storage nodes are dumb mirrors.

use prost::Message;

use crate::wire::{domain_hash_bytes, pb};

/// Author a DlvCreateV3 commitment.
///
/// precommit := H("DSM/dlv/precommit\0" || reveal_material)
/// vault_id  := H("DSM/dlv\0" || device_id || policy_digest || precommit)
pub fn author_dlv_create(
    device_id: &[u8; 32],
    policy_digest: &[u8; 32],
    reveal_material: &[u8],
) -> pb::DlvCreateV3 {
    let precommit = domain_hash_bytes("DSM/dlv/precommit\0", reveal_material);

    let mut v_buf = Vec::with_capacity(32 * 3);
    v_buf.extend_from_slice(device_id);
    v_buf.extend_from_slice(policy_digest);
    v_buf.extend_from_slice(&precommit);
    let vault_id = domain_hash_bytes("DSM/dlv\0", &v_buf);

    pb::DlvCreateV3 {
        device_id: device_id.to_vec(),
        policy_digest: policy_digest.to_vec(),
        precommit: precommit.to_vec(),
        vault_id: vault_id.to_vec(),
        // Root of author's DLV stream (optional)
        parent_digest: Vec::new(),
    }
}

/// Author a DlvOpenV3 reveal.
///
/// Verifiers check that H("DSM/dlv/precommit\0" || reveal_material) matches the
/// precommit in the corresponding accepted `DlvCreateV3`.
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

/// Convenience: deterministic digest for the authored DlvCreateV3.
pub fn dlv_create_digest(create: &pb::DlvCreateV3) -> [u8; 32] {
    let bytes = create.encode_to_vec();
    domain_hash_bytes("DSM/dlv/create\0", &bytes)
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
    const POLICY: [u8; 32] = [0xBB; 32];

    #[test]
    fn author_dlv_create_populates_fields() {
        let reveal = b"secret-reveal-material";
        let create = author_dlv_create(&DEVICE, &POLICY, reveal);
        assert_eq!(create.device_id, DEVICE.to_vec());
        assert_eq!(create.policy_digest, POLICY.to_vec());
        assert!(!create.precommit.is_empty());
        assert!(!create.vault_id.is_empty());
        assert!(create.parent_digest.is_empty());
    }

    #[test]
    fn author_dlv_create_deterministic() {
        let reveal = b"same-material";
        let a = author_dlv_create(&DEVICE, &POLICY, reveal);
        let b = author_dlv_create(&DEVICE, &POLICY, reveal);
        assert_eq!(a.vault_id, b.vault_id);
        assert_eq!(a.precommit, b.precommit);
    }

    #[test]
    fn author_dlv_create_different_reveal_different_vault() {
        let a = author_dlv_create(&DEVICE, &POLICY, b"reveal-a");
        let b = author_dlv_create(&DEVICE, &POLICY, b"reveal-b");
        assert_ne!(a.vault_id, b.vault_id);
        assert_ne!(a.precommit, b.precommit);
    }

    #[test]
    fn author_dlv_create_different_device_different_vault() {
        let dev2 = [0xCC; 32];
        let a = author_dlv_create(&DEVICE, &POLICY, b"same");
        let b = author_dlv_create(&dev2, &POLICY, b"same");
        assert_ne!(a.vault_id, b.vault_id);
        assert_eq!(a.precommit, b.precommit, "precommit only depends on reveal_material");
    }

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
    fn dlv_create_digest_deterministic() {
        let create = author_dlv_create(&DEVICE, &POLICY, b"material");
        let d1 = dlv_create_digest(&create);
        let d2 = dlv_create_digest(&create);
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
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

    #[test]
    fn create_and_open_digests_differ() {
        let reveal = b"shared-material";
        let create = author_dlv_create(&DEVICE, &POLICY, reveal);
        let open = author_dlv_open(&DEVICE, &[0xFF; 32], reveal);
        let cd = dlv_create_digest(&create);
        let od = dlv_open_digest(&open);
        assert_ne!(cd, od);
    }

    #[test]
    fn precommit_is_32_bytes() {
        let create = author_dlv_create(&DEVICE, &POLICY, b"anything");
        assert_eq!(create.precommit.len(), 32);
    }

    #[test]
    fn vault_id_is_32_bytes() {
        let create = author_dlv_create(&DEVICE, &POLICY, b"anything");
        assert_eq!(create.vault_id.len(), 32);
    }
}
