// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared transfer and receipt helper free functions for AppRouterImpl.
//!
//! These are extracted verbatim from the original `app_router_impl.rs` top-level
//! free functions (backup lines 48–171).

/// Build canonical payload bytes plus a sovereign protocol commitment.
///
/// This helper is for DLV/faucet/bitcoin transitions that need deterministic
/// commitments without pretending to be bilateral stitched receipts.
pub(crate) fn build_protocol_transition_commitment(
    label: &[u8],
    parts: &[&[u8]],
) -> (Vec<u8>, [u8; 32]) {
    let payload = crate::sdk::receipts::encode_protocol_transition_payload(label, parts);
    let commitment = crate::sdk::receipts::compute_protocol_transition_commitment(&payload);
    (payload, commitment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_transition_commitment_deterministic() {
        let label = b"test-label";
        let parts: &[&[u8]] = &[b"part1", b"part2"];
        let (payload1, commit1) = build_protocol_transition_commitment(label, parts);
        let (payload2, commit2) = build_protocol_transition_commitment(label, parts);
        assert_eq!(payload1, payload2);
        assert_eq!(commit1, commit2);
    }

    #[test]
    fn protocol_transition_commitment_different_labels() {
        let parts: &[&[u8]] = &[b"data"];
        let (_, c1) = build_protocol_transition_commitment(b"label-a", parts);
        let (_, c2) = build_protocol_transition_commitment(b"label-b", parts);
        assert_ne!(c1, c2);
    }

    #[test]
    fn protocol_transition_commitment_different_parts() {
        let label = b"same-label";
        let (_, c1) = build_protocol_transition_commitment(label, &[b"x"]);
        let (_, c2) = build_protocol_transition_commitment(label, &[b"y"]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn protocol_transition_commitment_is_32_bytes() {
        let (_, commitment) = build_protocol_transition_commitment(b"lbl", &[b"d"]);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn protocol_transition_commitment_empty_parts() {
        let (payload, commitment) = build_protocol_transition_commitment(b"empty", &[]);
        assert!(!payload.is_empty());
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn protocol_transition_commitment_multiple_parts() {
        let parts: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let (payload, commitment) = build_protocol_transition_commitment(b"multi", parts);
        assert!(!payload.is_empty());
        assert_ne!(commitment, [0u8; 32]);
    }
}
