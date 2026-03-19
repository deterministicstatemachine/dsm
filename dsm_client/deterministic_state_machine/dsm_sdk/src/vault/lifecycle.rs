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
