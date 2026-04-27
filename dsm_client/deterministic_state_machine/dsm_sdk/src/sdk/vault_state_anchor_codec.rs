// SPDX-License-Identifier: Apache-2.0

//! Proto codec + digest for `SignedVaultStateAnchor`.
//!
//! Lives in `dsm_sdk` (not `dsm` core) because the `dsm` crate cannot
//! depend on the generated proto bindings without a circular import
//! through `dsm_sdk`.

use dsm::dlv::vault_state_anchor::{AnchorError, SignedVaultStateAnchor};
use dsm::types::proto as generated;
use prost::Message;

/// Serialise a `SignedVaultStateAnchor` to its canonical
/// `VaultStateAnchorV1` proto bytes.  Used by:
///   * publishers, when posting `defi/vault-state/{vault_id_b32}/latest`;
///   * traders, when computing `vault_state_anchor_digest` for
///     route-commit binding (see `RouteCommitHopV1`).
pub fn encode_anchor_to_proto(anchor: &SignedVaultStateAnchor) -> Vec<u8> {
    let proto = generated::VaultStateAnchorV1 {
        vault_id: anchor.vault_id.to_vec(),
        sequence: anchor.sequence,
        reserves_digest: anchor.reserves_digest.to_vec(),
        owner_public_key: anchor.owner_public_key.clone(),
        owner_signature: anchor.owner_signature.clone(),
    };
    proto.encode_to_vec()
}

/// Deserialise canonical `VaultStateAnchorV1` proto bytes back into a
/// `SignedVaultStateAnchor`.  Length-validates the fixed-size byte
/// fields (`vault_id`, `reserves_digest` are both 32 bytes).
pub fn decode_anchor_from_proto(bytes: &[u8]) -> Result<SignedVaultStateAnchor, AnchorError> {
    let proto = generated::VaultStateAnchorV1::decode(bytes)
        .map_err(|e| AnchorError::SignFailed(format!("decode: {e}")))?;
    if proto.vault_id.len() != 32 {
        return Err(AnchorError::SignatureInvalid);
    }
    if proto.reserves_digest.len() != 32 {
        return Err(AnchorError::SignatureInvalid);
    }
    let mut vault_id = [0u8; 32];
    vault_id.copy_from_slice(&proto.vault_id);
    let mut reserves_digest = [0u8; 32];
    reserves_digest.copy_from_slice(&proto.reserves_digest);
    Ok(SignedVaultStateAnchor {
        vault_id,
        sequence: proto.sequence,
        reserves_digest,
        owner_public_key: proto.owner_public_key,
        owner_signature: proto.owner_signature,
    })
}

/// BLAKE3 digest of the canonical proto encoding.  Stamped into
/// `RouteCommitHopV1.vault_state_anchor_digest` so the unlock gate can
/// bind a hop to a specific anchor without re-shipping the full
/// signature blob.
pub fn compute_anchor_digest(anchor: &SignedVaultStateAnchor) -> [u8; 32] {
    let bytes = encode_anchor_to_proto(anchor);
    *blake3::hash(&bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::vault_state_anchor::{
        compute_reserves_digest, sign_vault_state_anchor, verify_vault_state_anchor,
    };

    #[test]
    fn anchor_proto_round_trip() {
        let (pk, sk) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x44u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let signed = sign_vault_state_anchor(&vault_id, 7, &reserves_digest, &pk, &sk)
            .expect("sign succeeds");

        let proto_bytes = encode_anchor_to_proto(&signed);
        let decoded = decode_anchor_from_proto(&proto_bytes).expect("decode succeeds");

        assert_eq!(decoded.vault_id, signed.vault_id);
        assert_eq!(decoded.sequence, signed.sequence);
        assert_eq!(decoded.reserves_digest, signed.reserves_digest);
        assert_eq!(decoded.owner_public_key, signed.owner_public_key);
        assert_eq!(decoded.owner_signature, signed.owner_signature);

        verify_vault_state_anchor(&decoded).expect("verify decoded succeeds");
    }

    #[test]
    fn anchor_digest_matches_blake3_over_proto() {
        let (pk, sk) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x55u8; 32];
        let reserves_digest = compute_reserves_digest(b"AAA", b"BBB", 100, 200, 30);

        let signed = sign_vault_state_anchor(&vault_id, 1, &reserves_digest, &pk, &sk)
            .expect("sign succeeds");

        let proto_bytes = encode_anchor_to_proto(&signed);
        let expected = blake3::hash(&proto_bytes);
        let computed = compute_anchor_digest(&signed);

        assert_eq!(computed, *expected.as_bytes());
    }
}
