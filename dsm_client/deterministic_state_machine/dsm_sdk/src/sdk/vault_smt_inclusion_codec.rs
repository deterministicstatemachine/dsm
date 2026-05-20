// SPDX-License-Identifier: Apache-2.0

//! Proto codec + storage publish/fetch for
//! `SignedVaultStateInclusionProof`.
//!
//! SoFi spec §4.1.2 / §8.4 step 2 — strictly stronger than the
//! `VaultStateAnchorV1` codec next door: an inclusion proof commits
//! the PD-SMT root + a 256-sibling Merkle path, so a stateless
//! attacker who recovered the owner's K_DBRW still cannot forge a
//! proof against the device's actual SMT.
//!
//! Lives in `dsm_sdk` (not `dsm` core) because the `dsm` crate cannot
//! depend on the generated proto bindings without a circular import
//! through `dsm_sdk`.

use dsm::dlv::vault_smt_leaf::{SignedVaultStateInclusionProof, VaultSmtLeafError};
use dsm::types::proto as generated;
use prost::Message;

/// Storage prefix for sequence-pinned inclusion proof records.  One
/// record per accepted vault state sequence — historical traceability.
pub const VAULT_STATE_INCLUSION_PREFIX: &str = "sofi/vault-state-inclusion/";

/// Build the sequence-pinned storage key for an inclusion proof.
/// Pad-16 big-endian sequence keeps lex order = numeric order so
/// `storage_list_objects` returns proofs in chain order.
pub fn inclusion_proof_seq_key(vault_id: &[u8; 32], sequence: u64) -> String {
    let vault_b32 = crate::util::text_id::encode_base32_crockford(vault_id);
    let mut seq_bytes = [0u8; 16];
    seq_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    let seq_b32 = crate::util::text_id::encode_base32_crockford(&seq_bytes);
    format!("{VAULT_STATE_INCLUSION_PREFIX}{vault_b32}/seq-{seq_b32}")
}

/// Build the `latest` mirror key for fast lookup at quote time.
/// Republished on every accepted sequence advance so off-device
/// traders read the freshest proof without enumerating seq-* keys.
pub fn inclusion_proof_latest_key(vault_id: &[u8; 32]) -> String {
    let vault_b32 = crate::util::text_id::encode_base32_crockford(vault_id);
    format!("{VAULT_STATE_INCLUSION_PREFIX}{vault_b32}/latest")
}

/// Serialise a `SignedVaultStateInclusionProof` to canonical
/// `VaultStateInclusionProofV1` proto bytes.  The 256-sibling vector
/// is flattened into the `smt_siblings` repeated field — each entry
/// is exactly 32 bytes; the decoder enforces this.
pub fn encode_inclusion_proof_to_proto(proof: &SignedVaultStateInclusionProof) -> Vec<u8> {
    let proto = generated::VaultStateInclusionProofV1 {
        vault_id: proof.vault_id.to_vec(),
        sequence: proof.sequence,
        reserves_digest: proof.reserves_digest.to_vec(),
        smt_root: proof.smt_root.to_vec(),
        smt_siblings: proof.smt_siblings.iter().map(|s| s.to_vec()).collect(),
        owner_public_key: proof.owner_public_key.clone(),
        owner_signature: proof.owner_signature.clone(),
    };
    proto.encode_to_vec()
}

/// Deserialise canonical `VaultStateInclusionProofV1` proto bytes
/// back into a `SignedVaultStateInclusionProof`.  Length-validates
/// every fixed-size byte field (`vault_id`, `reserves_digest`,
/// `smt_root` are 32 bytes each; each `smt_siblings` entry is 32
/// bytes; the siblings vector must have exactly 256 entries).
pub fn decode_inclusion_proof_from_proto(
    bytes: &[u8],
) -> Result<SignedVaultStateInclusionProof, VaultSmtLeafError> {
    let proto = generated::VaultStateInclusionProofV1::decode(bytes)
        .map_err(|e| VaultSmtLeafError::SignFailed(format!("decode: {e}")))?;
    if proto.vault_id.len() != 32 {
        return Err(VaultSmtLeafError::SignatureInvalid);
    }
    if proto.reserves_digest.len() != 32 {
        return Err(VaultSmtLeafError::SignatureInvalid);
    }
    if proto.smt_root.len() != 32 {
        return Err(VaultSmtLeafError::SignatureInvalid);
    }
    if proto.smt_siblings.len() != 256 {
        return Err(VaultSmtLeafError::BadSiblingCount {
            expected: 256,
            actual: proto.smt_siblings.len(),
        });
    }
    let mut vault_id = [0u8; 32];
    vault_id.copy_from_slice(&proto.vault_id);
    let mut reserves_digest = [0u8; 32];
    reserves_digest.copy_from_slice(&proto.reserves_digest);
    let mut smt_root = [0u8; 32];
    smt_root.copy_from_slice(&proto.smt_root);
    let mut smt_siblings = Vec::with_capacity(256);
    for (i, s) in proto.smt_siblings.iter().enumerate() {
        if s.len() != 32 {
            return Err(VaultSmtLeafError::SignFailed(format!(
                "smt_siblings[{i}] expected 32 bytes, got {}",
                s.len()
            )));
        }
        let mut sib = [0u8; 32];
        sib.copy_from_slice(s);
        smt_siblings.push(sib);
    }
    Ok(SignedVaultStateInclusionProof {
        vault_id,
        sequence: proto.sequence,
        reserves_digest,
        smt_root,
        smt_siblings,
        owner_public_key: proto.owner_public_key,
        owner_signature: proto.owner_signature,
    })
}

/// Publish a signed inclusion proof to BOTH the seq-pinned key
/// (historical traceability) AND the `latest` mirror (fast trader
/// fast-path).
///
/// Best-effort persistence: each write is independent — a failure on
/// the seq-pinned write does NOT roll back the latest write and vice
/// versa.  Either kind of failure is returned to the caller so the
/// dlv handler can log it; the local vault state is already
/// consistent (caller's responsibility), so a publish failure leaves
/// the vault locally usable but possibly not quotable off-device
/// until republish succeeds.
pub async fn publish_inclusion_proof(
    vault_id: &[u8; 32],
    sequence: u64,
    proto_bytes: &[u8],
) -> Result<(), String> {
    let seq_key = inclusion_proof_seq_key(vault_id, sequence);
    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(&seq_key, proto_bytes)
        .await
        .map_err(|e| format!("inclusion proof seq publish failed: {e}"))?;
    let latest_key = inclusion_proof_latest_key(vault_id);
    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(&latest_key, proto_bytes)
        .await
        .map_err(|e| format!("inclusion proof latest publish failed: {e}"))?;
    Ok(())
}

/// Fetch the latest inclusion proof for a vault from
/// `sofi/vault-state-inclusion/{vault_id_b32}/latest`.  Returns
/// `Ok(None)` when no proof has ever been published (vault pre-dates
/// the Phase-7 SMT flow or was just created and hasn't published
/// yet); `Ok(Some(_))` when found; `Err(_)` on storage / decode
/// failures other than "not found".
///
/// Phase 6 composition consumes this BEFORE folding pending pointers,
/// using it as the spec-strict baseline.
pub async fn fetch_latest_inclusion_proof(
    vault_id: &[u8; 32],
) -> Result<Option<SignedVaultStateInclusionProof>, String> {
    let key = inclusion_proof_latest_key(vault_id);
    let bytes = match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&key).await {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("not found") {
                return Ok(None);
            }
            return Err(msg);
        }
    };
    decode_inclusion_proof_from_proto(&bytes)
        .map(Some)
        .map_err(|e| format!("decode inclusion proof failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::vault_smt_leaf::{
        sign_vault_state_inclusion_proof, verify_vault_state_inclusion_proof,
    };

    /// Build a deterministic 256-sibling fixture so the proto round
    /// trip is exercised against a real-shaped payload.
    fn fixture_siblings(seed: u8) -> Vec<[u8; 32]> {
        (0..256u16)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = seed;
                s[1] = (i >> 8) as u8;
                s[2] = (i & 0xff) as u8;
                s
            })
            .collect()
    }

    #[test]
    fn inclusion_proof_proto_round_trip() {
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x77u8; 32];
        let reserves_digest = [0xABu8; 32];
        let smt_root = [0xCDu8; 32];
        let siblings = fixture_siblings(0x11);

        // Sign with real siblings — note we DON'T verify the inclusion
        // half here (fixture siblings don't form a valid Merkle path),
        // we only check the proto codec preserves every field exactly.
        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            13,
            &reserves_digest,
            &smt_root,
            siblings.clone(),
            &pk,
            &sk,
        )
        .expect("sign succeeds");

        let proto_bytes = encode_inclusion_proof_to_proto(&signed);
        let decoded = decode_inclusion_proof_from_proto(&proto_bytes).expect("decode succeeds");

        assert_eq!(decoded.vault_id, signed.vault_id);
        assert_eq!(decoded.sequence, signed.sequence);
        assert_eq!(decoded.reserves_digest, signed.reserves_digest);
        assert_eq!(decoded.smt_root, signed.smt_root);
        assert_eq!(decoded.smt_siblings, signed.smt_siblings);
        assert_eq!(decoded.owner_public_key, signed.owner_public_key);
        assert_eq!(decoded.owner_signature, signed.owner_signature);
    }

    #[test]
    fn decode_rejects_wrong_sibling_count() {
        let mut proto = generated::VaultStateInclusionProofV1 {
            vault_id: vec![0u8; 32],
            sequence: 0,
            reserves_digest: vec![0u8; 32],
            smt_root: vec![0u8; 32],
            smt_siblings: vec![vec![0u8; 32]; 128], // Wrong: should be 256
            owner_public_key: vec![],
            owner_signature: vec![],
        };
        let bytes = proto.encode_to_vec();
        match decode_inclusion_proof_from_proto(&bytes) {
            Err(VaultSmtLeafError::BadSiblingCount { expected, actual }) => {
                assert_eq!(expected, 256);
                assert_eq!(actual, 128);
            }
            other => panic!("expected BadSiblingCount, got {other:?}"),
        }

        // And one with a wrong-length sibling entry inside an
        // otherwise-correctly-sized vector.
        proto.smt_siblings = vec![vec![0u8; 32]; 256];
        proto.smt_siblings[5] = vec![0u8; 31];
        let bytes = proto.encode_to_vec();
        assert!(matches!(
            decode_inclusion_proof_from_proto(&bytes),
            Err(VaultSmtLeafError::SignFailed(_))
        ));
    }

    #[test]
    fn decode_rejects_wrong_fixed_length_fields() {
        let mut proto = generated::VaultStateInclusionProofV1 {
            vault_id: vec![0u8; 31], // Wrong: must be 32
            sequence: 0,
            reserves_digest: vec![0u8; 32],
            smt_root: vec![0u8; 32],
            smt_siblings: vec![vec![0u8; 32]; 256],
            owner_public_key: vec![],
            owner_signature: vec![],
        };
        assert!(matches!(
            decode_inclusion_proof_from_proto(&proto.encode_to_vec()),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));

        proto.vault_id = vec![0u8; 32];
        proto.smt_root = vec![0u8; 33]; // Wrong
        assert!(matches!(
            decode_inclusion_proof_from_proto(&proto.encode_to_vec()),
            Err(VaultSmtLeafError::SignatureInvalid)
        ));
    }

    #[test]
    fn end_to_end_proto_round_trip_with_real_smt_proof() {
        // This time use a REAL SMT-derived proof so we can also assert
        // verify_vault_state_inclusion_proof accepts the decoded form.
        use dsm::dlv::vault_smt_leaf::{compute_vault_smt_key, compute_vault_smt_value};
        use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let vault_id = [0x88u8; 32];
        let reserves_digest = [0xCCu8; 32];

        let mut tree = SparseMerkleTree::new(64);
        let leaf_key = compute_vault_smt_key(&vault_id);
        let leaf_value = compute_vault_smt_value(0, &reserves_digest);
        tree.update_leaf(&leaf_key, &leaf_value)
            .expect("update_leaf");
        let smt_root = *tree.root();
        let proof = tree.get_inclusion_proof(&leaf_key, 256).expect("proof");

        let signed = sign_vault_state_inclusion_proof(
            &vault_id,
            0,
            &reserves_digest,
            &smt_root,
            proof.siblings,
            &pk,
            &sk,
        )
        .expect("sign succeeds");

        let proto_bytes = encode_inclusion_proof_to_proto(&signed);
        let decoded = decode_inclusion_proof_from_proto(&proto_bytes).expect("decode succeeds");
        verify_vault_state_inclusion_proof(&decoded).expect("verifier accepts decoded proof");
    }

    #[test]
    fn storage_key_formats_are_stable() {
        let vault_id = [0x42u8; 32];
        let seq_key = inclusion_proof_seq_key(&vault_id, 0);
        let latest_key = inclusion_proof_latest_key(&vault_id);
        // Must share the same prefix and vault component.
        assert!(seq_key.starts_with(VAULT_STATE_INCLUSION_PREFIX));
        assert!(latest_key.starts_with(VAULT_STATE_INCLUSION_PREFIX));
        assert!(seq_key.ends_with(&format!(
            "{}/seq-{}",
            crate::util::text_id::encode_base32_crockford(&vault_id),
            crate::util::text_id::encode_base32_crockford(&[0u8; 16])
        )));
        assert!(latest_key.ends_with("/latest"));

        // seq=1 sorts lex-after seq=0 (16-byte BE pad-zero encoding
        // preserves numeric order).
        let seq1_key = inclusion_proof_seq_key(&vault_id, 1);
        assert!(seq1_key > seq_key, "seq=1 must sort after seq=0");
    }
}
