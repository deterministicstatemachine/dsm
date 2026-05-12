// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared helpers for DSM registry content addressing.
//!
//! The storage-node registry is a content-addressed KV store. Both the write
//! path (`storage_node_sdk::register_device_in_tree`) and the read path
//! (`app_router_impl::verify_device_tree_evidence_quorum`) must compute the
//! same content address for the same evidence blob, so the math lives here to
//! guarantee client/server alignment on a single source of truth.
//!
//! Address derivation (must match `dsm_storage_node::api::registry::content_addr_b64url`):
//!
//! ```text
//! addr = base64url_nopad(BLAKE3("DSM/registry\0" || body))
//! ```
//!
//! `dsm_domain_hasher` appends a trailing NUL after the domain tag; the server
//! uses the same raw `"DSM/registry\0"` prefix manually, so the two sides agree
//! byte-for-byte.

use dsm::crypto::blake3::dsm_domain_hasher;

/// Evidence blob length: `device_id (32) || genesis_hash (32) || parent (32) || depth (4)`
pub const DEVICE_TREE_EVIDENCE_LEN: usize = 32 + 32 + 32 + 4;

/// Minimum number of storage nodes that must hold a DeviceTreeEntry for the
/// quorum reader to consider it visible. Both the write path and the read path
/// agree on this threshold.
pub const REGISTRY_QUORUM_THRESHOLD: usize = 3;

/// Build the canonical 100-byte DeviceTreeEntry evidence for a root device.
///
/// Root devices have no parent and are at depth 0, so the trailing 36 bytes
/// are always zero. This layout is part of the binary wire format — do not
/// add padding or reorder fields.
#[inline]
pub fn build_root_device_tree_evidence(device_id: &[u8], genesis_hash: &[u8]) -> Vec<u8> {
    debug_assert_eq!(device_id.len(), 32, "device_id must be 32 bytes");
    debug_assert_eq!(genesis_hash.len(), 32, "genesis_hash must be 32 bytes");
    let mut out = Vec::with_capacity(DEVICE_TREE_EVIDENCE_LEN);
    out.extend_from_slice(device_id);
    out.extend_from_slice(genesis_hash);
    out.extend_from_slice(&[0u8; 32]); // parent hash (root: all zero)
    out.extend_from_slice(&[0u8; 4]); // tree depth = 0
    debug_assert_eq!(out.len(), DEVICE_TREE_EVIDENCE_LEN);
    out
}

/// Compute the content-addressed registry key for an evidence blob.
///
/// Mirrors `dsm_storage_node::api::registry::content_addr_b64url` exactly.
#[inline]
pub fn registry_content_addr_b64url(body: &[u8]) -> String {
    let mut hasher = dsm_domain_hasher("DSM/registry");
    hasher.update(body);
    let out = hasher.finalize();
    b64_url_no_pad(out.as_bytes())
}

/// Encode raw bytes as base64url without padding.
///
/// Matches the server's `b64_url_no_pad` exactly — used for registry keys only.
/// Do NOT use this for Envelope v3 or any protocol-level encoding; base64 is
/// permitted only at I/O boundaries per DSM rules.
#[inline]
pub fn b64_url_no_pad(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let n = input.len();
    let mut out = String::with_capacity(n.div_ceil(3) * 4);

    let mut i = 0;
    while i + 3 <= n {
        let a = input[i];
        let b = input[i + 1];
        let c = input[i + 2];

        out.push(T[(a >> 2) as usize] as char);
        out.push(T[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(T[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        out.push(T[(c & 0x3f) as usize] as char);

        i += 3;
    }

    match n - i {
        1 => {
            let a = input[i];
            out.push(T[(a >> 2) as usize] as char);
            out.push(T[((a & 0x03) << 4) as usize] as char);
        }
        2 => {
            let a = input[i];
            let b = input[i + 1];
            out.push(T[(a >> 2) as usize] as char);
            out.push(T[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            out.push(T[((b & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_layout_is_100_bytes() {
        let device_id = [0xAAu8; 32];
        let genesis_hash = [0xBBu8; 32];
        let evidence = build_root_device_tree_evidence(&device_id, &genesis_hash);
        assert_eq!(evidence.len(), DEVICE_TREE_EVIDENCE_LEN);
        assert_eq!(evidence.len(), 100);
        assert_eq!(&evidence[..32], &device_id);
        assert_eq!(&evidence[32..64], &genesis_hash);
        assert_eq!(&evidence[64..96], &[0u8; 32]);
        assert_eq!(&evidence[96..100], &[0u8; 4]);
    }

    #[test]
    fn registry_addr_is_deterministic() {
        let device_id = [
            0x04, 0xFE, 0xBC, 0x97, 0x85, 0xD6, 0xF4, 0x34, 0x7D, 0x01, 0xC0, 0xE9, 0xD7, 0x69,
            0x48, 0x6C, 0x9E, 0x8C, 0xCB, 0x28, 0x0B, 0xF8, 0x7D, 0x1E, 0x84, 0x0D, 0x52, 0x90,
            0x91, 0x33, 0x2D, 0x2E,
        ];
        let evidence = build_root_device_tree_evidence(&device_id, &device_id);
        let addr = registry_content_addr_b64url(&evidence);
        // Golden value computed via server-side content_addr_b64url
        // (see /tmp/compute_registry_addr.py — Device A reference).
        assert_eq!(addr, "vYk0o6pj2JOwjEYPDjtHfOyj9IblwwrYyT9xwSbP7Jk");
    }

    #[test]
    fn b64_url_rt_roundtrip_simple() {
        // Empty
        assert_eq!(b64_url_no_pad(&[]), "");
        // Single byte
        assert_eq!(b64_url_no_pad(&[0xFF]), "_w");
        // Two bytes
        assert_eq!(b64_url_no_pad(&[0xFF, 0xFF]), "__8");
        // Three bytes (full group)
        assert_eq!(b64_url_no_pad(&[0xFF, 0xFF, 0xFF]), "____");
    }
}
