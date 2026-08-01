// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire codec + storage access for `VaultReserveInclusionProofV1`.
//!
//! Transport only. Every judgement about whether a proof is good lives in
//! [`dsm::dlv::vault_reserve_inclusion::verify_vault_reserve_inclusion_proof`],
//! so there is one verifier rather than one per caller.
//!
//! Published beside the vault-state inclusion proof and fetched with it: the
//! two must agree on `(vault_id, sequence, smt_root)`, and a composer holding
//! only one of them knows either what the vault's state is or what it holds,
//! never both.

use dsm::dlv::vault_reserve_inclusion::{ReserveLegProof, SignedVaultReserveInclusionProof};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;

/// Storage prefix for reserve inclusion proofs, keyed by vault then sequence.
///
/// Sequence is zero-padded big-endian so the lexical listing order a storage
/// node returns is the numeric order — the same convention the pending-pointer
/// prefix uses, and the reason "latest" can be taken from the last entry
/// without parsing every key.
pub(crate) const VAULT_RESERVE_PROOF_ROOT: &str = "sofi/vault-reserve/";

pub(crate) fn vault_reserve_proof_key(vault_id: &[u8; 32], sequence: u64) -> String {
    format!(
        "{}{}/{:016x}",
        VAULT_RESERVE_PROOF_ROOT,
        encode_base32_crockford(vault_id),
        sequence
    )
}

pub(crate) fn vault_reserve_proof_prefix(vault_id: &[u8; 32]) -> String {
    format!(
        "{}{}/",
        VAULT_RESERVE_PROOF_ROOT,
        encode_base32_crockford(vault_id)
    )
}

fn fixed32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    Some(out)
}

/// Proto → typed. `None` on any malformed field, never a partially populated
/// struct: a 31-byte root that silently became `[0u8; 32]` would be a proof
/// claiming inclusion in the empty tree.
pub(crate) fn reserve_proof_from_proto(
    p: &generated::VaultReserveInclusionProofV1,
) -> Option<SignedVaultReserveInclusionProof> {
    let mut legs = Vec::with_capacity(p.legs.len());
    for l in &p.legs {
        let mut smt_siblings = Vec::with_capacity(l.smt_siblings.len());
        for s in &l.smt_siblings {
            smt_siblings.push(fixed32(s)?);
        }
        legs.push(ReserveLegProof {
            policy_commit: fixed32(&l.policy_commit)?,
            amount: l.amount,
            smt_siblings,
        });
    }
    Some(SignedVaultReserveInclusionProof {
        vault_id: fixed32(&p.vault_id)?,
        sequence: p.sequence,
        smt_root: fixed32(&p.smt_root)?,
        owner_genesis: fixed32(&p.owner_genesis)?,
        owner_devid: fixed32(&p.owner_devid)?,
        legs,
        owner_public_key: p.owner_public_key.clone(),
        owner_signature: p.owner_signature.clone(),
    })
}

/// Typed → proto.
pub(crate) fn reserve_proof_to_proto(
    p: &SignedVaultReserveInclusionProof,
) -> generated::VaultReserveInclusionProofV1 {
    generated::VaultReserveInclusionProofV1 {
        vault_id: p.vault_id.to_vec(),
        sequence: p.sequence,
        smt_root: p.smt_root.to_vec(),
        owner_genesis: p.owner_genesis.to_vec(),
        owner_devid: p.owner_devid.to_vec(),
        legs: p
            .legs
            .iter()
            .map(|l| generated::VaultReserveLegProofV1 {
                policy_commit: l.policy_commit.to_vec(),
                amount: l.amount,
                smt_siblings: l.smt_siblings.iter().map(|s| s.to_vec()).collect(),
            })
            .collect(),
        owner_public_key: p.owner_public_key.clone(),
        owner_signature: p.owner_signature.clone(),
    }
}

/// Publish a reserve proof. The owner does this whenever its reserves move, so
/// a trader quoting at sequence N can fetch the proof for exactly N.
pub(crate) async fn publish_reserve_proof(
    proof: &SignedVaultReserveInclusionProof,
) -> Result<(), dsm::types::error::DsmError> {
    let key = vault_reserve_proof_key(&proof.vault_id, proof.sequence);
    let bytes = reserve_proof_to_proto(proof).encode_to_vec();
    BitcoinTapSdk::storage_put_bytes(&key, &bytes)
        .await
        .map(|_| ())
}

/// Fetch and fully verify the reserve proof for `(vault, sequence)`.
///
/// Fetched at an EXACT sequence rather than "latest". A composer folds onto a
/// specific baseline, so a proof for some other sequence is not a better answer
/// than none — it is a proof about a different state, and accepting it would
/// reintroduce exactly the drift the sequence binding exists to prevent.
///
/// `None` collapses absent, unfetchable, undecodable, mis-keyed and
/// failing-verification: the only decision downstream is whether the vault may
/// be quoted, and every one of these says it may not.
pub(crate) async fn fetch_verified_reserve_proof(
    vault_id: &[u8; 32],
    sequence: u64,
) -> Option<SignedVaultReserveInclusionProof> {
    let key = vault_reserve_proof_key(vault_id, sequence);
    let bytes = BitcoinTapSdk::storage_get_bytes(&key).await.ok()?;
    let proto = generated::VaultReserveInclusionProofV1::decode(bytes.as_slice()).ok()?;
    let proof = reserve_proof_from_proto(&proto)?;

    // Storage keys are labels the node chose; the record's own fields are the
    // claim. Require them to agree, or a node could answer a query about one
    // state with a proof about another.
    if proof.vault_id != *vault_id || proof.sequence != sequence {
        return None;
    }
    dsm::dlv::vault_reserve_inclusion::verify_vault_reserve_inclusion_proof(&proof).ok()?;
    Some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::vault_reserve_inclusion::{
        sign_vault_reserve_inclusion_proof, verify_vault_reserve_inclusion_proof,
    };
    use dsm::dlv::vault_reserve_leaf::{vault_reserve_key, vault_reserve_value};
    use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

    const G: [u8; 32] = [0xA0; 32];
    const D: [u8; 32] = [0xB0; 32];
    const V: [u8; 32] = [0x77; 32];

    fn sample() -> SignedVaultReserveInclusionProof {
        let held = [([0xE0u8; 32], 10_000u64), ([0xF0u8; 32], 5_000u64)];
        let mut tree = SparseMerkleTree::new(64);
        for (pc, amt) in &held {
            tree.update_leaf(
                &vault_reserve_key(&G, &D, &V, pc),
                &vault_reserve_value(*amt, 3),
            )
            .expect("update_leaf");
        }
        let root = *tree.root();
        let legs = held
            .iter()
            .map(|(pc, amt)| ReserveLegProof {
                policy_commit: *pc,
                amount: *amt,
                smt_siblings: tree
                    .get_inclusion_proof(&vault_reserve_key(&G, &D, &V, pc), 256)
                    .expect("proof")
                    .siblings,
            })
            .collect();
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        sign_vault_reserve_inclusion_proof(&V, 3, &root, &G, &D, legs, &pk, &sk).expect("sign")
    }

    /// The round trip must preserve every proven quantity AND still verify. A
    /// field-by-field comparison alone would not catch a path that survived the
    /// wire in the wrong order.
    #[test]
    fn round_trip_preserves_the_proof_and_it_still_verifies() {
        let p = sample();
        let bytes = reserve_proof_to_proto(&p).encode_to_vec();
        let decoded =
            generated::VaultReserveInclusionProofV1::decode(bytes.as_slice()).expect("decode");
        let back = reserve_proof_from_proto(&decoded).expect("typed");

        assert_eq!(back.vault_id, p.vault_id);
        assert_eq!(back.sequence, p.sequence);
        assert_eq!(back.smt_root, p.smt_root);
        assert_eq!(back.legs, p.legs);
        verify_trader_survives(&back);
    }

    fn verify_trader_survives(p: &SignedVaultReserveInclusionProof) {
        verify_vault_reserve_inclusion_proof(p).expect("survives the wire");
    }

    #[test]
    fn a_malformed_record_decodes_to_nothing_rather_than_to_defaults() {
        let p = sample();
        for (what, mutate) in [
            (
                "short vault id",
                Box::new(|x: &mut generated::VaultReserveInclusionProofV1| x.vault_id.truncate(31))
                    as Box<dyn Fn(&mut generated::VaultReserveInclusionProofV1)>,
            ),
            (
                "short root",
                Box::new(|x: &mut generated::VaultReserveInclusionProofV1| x.smt_root.truncate(31)),
            ),
            (
                "short leg commit",
                Box::new(|x: &mut generated::VaultReserveInclusionProofV1| {
                    x.legs[0].policy_commit.truncate(31)
                }),
            ),
            (
                "short sibling",
                Box::new(|x: &mut generated::VaultReserveInclusionProofV1| {
                    x.legs[0].smt_siblings[0].truncate(31)
                }),
            ),
        ] {
            let mut proto = reserve_proof_to_proto(&p);
            mutate(&mut proto);
            assert!(
                reserve_proof_from_proto(&proto).is_none(),
                "{what} must decode to None, not to a default-filled struct"
            );
        }
    }

    /// Keys sort lexically the way sequences sort numerically, or "latest"
    /// listing would return sequence 9 after sequence 10.
    #[test]
    fn keys_order_lexically_the_way_sequences_order_numerically() {
        let mut keys: Vec<String> = [1u64, 2, 9, 10, 11, 255, 256, u64::MAX]
            .iter()
            .map(|s| vault_reserve_proof_key(&V, *s))
            .collect();
        let sorted = {
            let mut k = keys.clone();
            k.sort();
            k
        };
        assert_eq!(keys, sorted, "key order must already be sequence order");
        keys.dedup();
        assert_eq!(keys.len(), 8, "each sequence gets its own key");
        assert!(vault_reserve_proof_key(&V, 1).starts_with(&vault_reserve_proof_prefix(&V)));
    }
}
