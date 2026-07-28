// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reserve inclusion proof — the reserves a trader quotes against are PROVEN.
//!
//! WHY THIS EXISTS. `compose_vault_state` takes the baseline reserves as
//! *arguments*. It cross-checks them against the owner's signed digest, which
//! sounds sufficient and is not: the digest is one-way, so the check can only
//! confirm that the numbers the caller already supplied hash to the value the
//! owner signed. Whoever chose those numbers chose what the vault appears to
//! hold. The owner signing a digest of its own claim adds authorship, not
//! solvency — an owner can sign a digest of reserves it never funded.
//!
//! This proof closes that. Each leg carries a 256-sibling path from the owner's
//! own vault-reserve leaf ([`crate::dlv::vault_reserve_leaf`]) up to the
//! `smt_root` the owner published, so "the vault holds 10,000 ERA" becomes "the
//! owner's device root commits 10,000 ERA encumbered in that vault at that
//! sequence". The magnitudes come OUT of the proof rather than going in.
//!
//! ONE ROOT, ONE SEQUENCE. `smt_root` and `sequence` must equal the vault-state
//! inclusion proof's. Reserve leaves carry the vault's own sequence rather than
//! a per-leaf counter precisely so both proofs meet at a single root, and a
//! verifier holding the pair can cross-check them without a third record. An
//! owner that could present reserves at one sequence and vault state at another
//! could show funded reserves beside a later, drained state.
//!
//! LEGS ARE LEX-SORTED AND DISTINCT. Without the ordering the signature payload
//! would depend on transmission order; without distinctness one leg could be
//! repeated to double-count an asset. Both are checked before the signature, so
//! a malformed set cannot reach the crypto at all.
//!
//! Verification is stateless — a trader runs it against published bytes with no
//! access to the owner's device. Domain-separated BLAKE3, SPHINCS+ signatures.

use crate::common::domain_tags::TAG_VAULT_RESERVE_INCLUSION;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::dlv::vault_reserve_leaf::{vault_reserve_key, vault_reserve_value};
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// One asset's proven encumbrance: how much, and the path proving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveLegProof {
    pub policy_commit: [u8; 32],
    /// Base units, in the same u64 space as `DeviceState::balances`.
    pub amount: u64,
    /// 256 siblings, leaf-to-root, for this leg's vault-reserve leaf.
    pub smt_siblings: Vec<[u8; 32]>,
}

/// Signed canonical form. Wire-encoded as `VaultReserveInclusionProofV1`.
#[derive(Debug, Clone)]
pub struct SignedVaultReserveInclusionProof {
    pub vault_id: [u8; 32],
    /// The vault's sequence — must equal the state proof's.
    pub sequence: u64,
    /// The owner's device root — must equal the state proof's.
    pub smt_root: [u8; 32],
    /// Key-derivation inputs. Present because a reserve leaf key is scoped to
    /// the owning device: without them a verifier could not recompute the leaf
    /// position, and with the wrong ones the path simply fails.
    pub owner_genesis: [u8; 32],
    pub owner_devid: [u8; 32],
    /// Lex-sorted by `policy_commit`, distinct, at least one.
    pub legs: Vec<ReserveLegProof>,
    pub owner_public_key: Vec<u8>,
    pub owner_signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReserveProofError {
    /// SPHINCS+ verification failed: bad signature, wrong key, or a tampered
    /// field inside the signed tuple.
    SignatureInvalid,
    SignFailed(String),
    /// A leg's path does not carry its recomputed reserve leaf up to
    /// `smt_root`. The owner claimed an encumbrance its own device root does
    /// not commit — the unfunded-vault case this type exists to reject.
    LegNotCommitted {
        policy_commit: [u8; 32],
    },
    /// Sibling vector length is not exactly 256.
    BadSiblingCount {
        expected: usize,
        actual: usize,
    },
    /// Legs are not lex-ascending by `policy_commit`, or an asset repeats.
    LegsNotCanonical,
    /// A proof with no legs proves no solvency; it must not read as a funded
    /// vault holding nothing.
    NoLegs,
}

impl core::fmt::Display for ReserveProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReserveProofError::SignatureInvalid => {
                write!(f, "reserve proof signature verification failed")
            }
            ReserveProofError::SignFailed(msg) => write!(f, "sphincs sign failed: {msg}"),
            ReserveProofError::LegNotCommitted { .. } => write!(
                f,
                "a reserve leg is not committed in the owner's published root",
            ),
            ReserveProofError::BadSiblingCount { expected, actual } => {
                write!(f, "SMT siblings must have length {expected}, got {actual}")
            }
            ReserveProofError::LegsNotCanonical => write!(
                f,
                "reserve legs must be lex-ascending by policy_commit and distinct",
            ),
            ReserveProofError::NoLegs => write!(f, "a reserve proof must carry at least one leg"),
        }
    }
}

impl std::error::Error for ReserveProofError {}

/// Canonical signing payload:
/// `H(tag ‖ vault_id ‖ sequence_be ‖ smt_root ‖ owner_genesis ‖ owner_devid
///    ‖ (policy_commit ‖ amount_be)*)`.
///
/// The sibling paths are deliberately NOT signed. They are self-authenticating
/// — a wrong path simply fails to reach `smt_root` — so signing them would add
/// bytes without adding a check, while making a proof re-derived from a fresh
/// tree walk fail to verify against an older signature over the same facts.
pub fn reserve_proof_sign_payload(
    vault_id: &[u8; 32],
    sequence: u64,
    smt_root: &[u8; 32],
    owner_genesis: &[u8; 32],
    owner_devid: &[u8; 32],
    legs: &[ReserveLegProof],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_VAULT_RESERVE_INCLUSION);
    h.update(vault_id);
    h.update(&sequence.to_be_bytes());
    h.update(smt_root);
    h.update(owner_genesis);
    h.update(owner_devid);
    for leg in legs {
        h.update(&leg.policy_commit);
        h.update(&leg.amount.to_be_bytes());
    }
    *h.finalize().as_bytes()
}

/// Legs must be lex-ascending by `policy_commit` and distinct, and there must be
/// at least one. Checked before any crypto so a malformed set never reaches it.
fn check_leg_shape(legs: &[ReserveLegProof]) -> Result<(), ReserveProofError> {
    if legs.is_empty() {
        return Err(ReserveProofError::NoLegs);
    }
    for w in legs.windows(2) {
        if w[0].policy_commit >= w[1].policy_commit {
            return Err(ReserveProofError::LegsNotCanonical);
        }
    }
    for leg in legs {
        if leg.smt_siblings.len() != 256 {
            return Err(ReserveProofError::BadSiblingCount {
                expected: 256,
                actual: leg.smt_siblings.len(),
            });
        }
    }
    Ok(())
}

/// Sign a reserve inclusion proof. The caller supplies paths already pulled from
/// its own SMT; this consults no tree state.
#[allow(clippy::too_many_arguments)]
pub fn sign_vault_reserve_inclusion_proof(
    vault_id: &[u8; 32],
    sequence: u64,
    smt_root: &[u8; 32],
    owner_genesis: &[u8; 32],
    owner_devid: &[u8; 32],
    legs: Vec<ReserveLegProof>,
    owner_public_key: &[u8],
    owner_secret_key: &[u8],
) -> Result<SignedVaultReserveInclusionProof, ReserveProofError> {
    check_leg_shape(&legs)?;
    let payload = reserve_proof_sign_payload(
        vault_id,
        sequence,
        smt_root,
        owner_genesis,
        owner_devid,
        &legs,
    );
    let signature = crate::crypto::sphincs::sphincs_sign(owner_secret_key, &payload)
        .map_err(|e| ReserveProofError::SignFailed(format!("{e:?}")))?;
    Ok(SignedVaultReserveInclusionProof {
        vault_id: *vault_id,
        sequence,
        smt_root: *smt_root,
        owner_genesis: *owner_genesis,
        owner_devid: *owner_devid,
        legs,
        owner_public_key: owner_public_key.to_vec(),
        owner_signature: signature,
    })
}

/// Verify a reserve inclusion proof end to end: leg shape, then the owner's
/// signature, then every leg's SMT path against `smt_root`.
///
/// Passing means the owner's own device root commits exactly these base units,
/// encumbered in this vault, at this sequence. That is what a quote needs before
/// it is worth signing, and it is what a self-declared number never established.
pub fn verify_vault_reserve_inclusion_proof(
    proof: &SignedVaultReserveInclusionProof,
) -> Result<(), ReserveProofError> {
    check_leg_shape(&proof.legs)?;
    let payload = reserve_proof_sign_payload(
        &proof.vault_id,
        proof.sequence,
        &proof.smt_root,
        &proof.owner_genesis,
        &proof.owner_devid,
        &proof.legs,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        &proof.owner_public_key,
        &payload,
        &proof.owner_signature,
    )
    .map_err(|_| ReserveProofError::SignatureInvalid)?;
    if !ok {
        return Err(ReserveProofError::SignatureInvalid);
    }

    for leg in &proof.legs {
        let key = vault_reserve_key(
            &proof.owner_genesis,
            &proof.owner_devid,
            &proof.vault_id,
            &leg.policy_commit,
        );
        // The leaf value folds the VAULT's sequence, which is why this proof and
        // the vault-state proof meet at one root.
        let value = vault_reserve_value(leg.amount, proof.sequence);
        let smt_proof = SmtInclusionProof {
            key,
            value: Some(value),
            siblings: leg.smt_siblings.clone(),
        };
        if !SparseMerkleTree::verify_proof_against_root(&smt_proof, &proof.smt_root) {
            return Err(ReserveProofError::LegNotCommitted {
                policy_commit: leg.policy_commit,
            });
        }
    }
    Ok(())
}

/// The proven amount for `policy_commit`, or `None` if this proof says nothing
/// about that asset.
///
/// Callers must treat `None` as "unproven", never as zero: a vault whose proof
/// omits a leg has not shown it holds nothing, it has shown nothing.
pub fn proven_amount(
    proof: &SignedVaultReserveInclusionProof,
    policy_commit: &[u8; 32],
) -> Option<u64> {
    proof
        .legs
        .iter()
        .find(|l| l.policy_commit == *policy_commit)
        .map(|l| l.amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::generate_sphincs_keypair;

    const G: [u8; 32] = [0xA0; 32];
    const D: [u8; 32] = [0xB0; 32];
    const V: [u8; 32] = [0x77; 32];

    fn pc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A tree holding exactly the encumbrances given, at `sequence` — the shape
    /// `DeviceState::fund_vault_reserves` produces. The end-to-end check against
    /// a real funded device lives beside that chokepoint, in `device_state.rs`.
    fn tree_with(assets: &[([u8; 32], u64)], sequence: u64) -> SparseMerkleTree {
        let mut tree = SparseMerkleTree::new(64);
        for (policy_commit, amount) in assets {
            let key = vault_reserve_key(&G, &D, &V, policy_commit);
            tree.update_leaf(&key, &vault_reserve_value(*amount, sequence))
                .expect("update_leaf");
        }
        tree
    }

    /// Legs claiming `assets`, with paths taken from `tree`. Claimed amounts are
    /// separate from the tree's on purpose, so a test can state an overstatement.
    fn legs_from(tree: &SparseMerkleTree, claims: &[([u8; 32], u64)]) -> Vec<ReserveLegProof> {
        let mut legs: Vec<ReserveLegProof> = claims
            .iter()
            .map(|(policy_commit, amount)| ReserveLegProof {
                policy_commit: *policy_commit,
                amount: *amount,
                smt_siblings: tree
                    .get_inclusion_proof(&vault_reserve_key(&G, &D, &V, policy_commit), 256)
                    .expect("proof")
                    .siblings,
            })
            .collect();
        legs.sort_by(|a, b| a.policy_commit.cmp(&b.policy_commit));
        legs
    }

    fn sign(
        legs: Vec<ReserveLegProof>,
        root: [u8; 32],
        sequence: u64,
    ) -> SignedVaultReserveInclusionProof {
        let (pk, sk) = generate_sphincs_keypair().expect("keypair");
        sign_vault_reserve_inclusion_proof(&V, sequence, &root, &G, &D, legs, &pk, &sk)
            .expect("sign")
    }

    fn signed_proof() -> SignedVaultReserveInclusionProof {
        let held = [(pc(0xE0), 10_000u64), (pc(0xF0), 5_000u64)];
        let tree = tree_with(&held, 3);
        sign(legs_from(&tree, &held), *tree.root(), 3)
    }

    #[test]
    fn a_genuinely_funded_vault_proves_its_reserves() {
        let p = signed_proof();
        verify_vault_reserve_inclusion_proof(&p).expect("real encumbrance must verify");
        assert_eq!(proven_amount(&p, &pc(0xE0)), Some(10_000));
        assert_eq!(proven_amount(&p, &pc(0xF0)), Some(5_000));
        assert_eq!(
            proven_amount(&p, &pc(0xD0)),
            None,
            "an asset this proof says nothing about must read as unproven, not zero"
        );
    }

    /// THE UNFUNDED-VAULT CASE, and the reason a signed digest was never enough.
    /// The owner signs honestly over its own claim; the path still fails, because
    /// the device root does not commit that amount.
    #[test]
    fn an_overstated_reserve_cannot_be_proven_even_with_a_valid_signature() {
        let held = [(pc(0xE0), 10_000u64), (pc(0xF0), 5_000u64)];
        let tree = tree_with(&held, 3);
        // Claim 10x the ERA actually encumbered, carrying the genuine path.
        let lie = sign(
            legs_from(&tree, &[(pc(0xE0), 100_000), (pc(0xF0), 5_000)]),
            *tree.root(),
            3,
        );
        assert!(matches!(
            verify_vault_reserve_inclusion_proof(&lie),
            Err(ReserveProofError::LegNotCommitted { .. })
        ));
    }

    /// A vault funded at one sequence must not prove those reserves at another.
    /// The leaf value folds the sequence, so a stale proof cannot be replayed
    /// against a later, drained state.
    #[test]
    fn reserves_cannot_be_proven_at_a_different_sequence() {
        let mut p = signed_proof();
        p.sequence = 4;
        assert!(
            verify_vault_reserve_inclusion_proof(&p).is_err(),
            "a proof re-pointed at another sequence must fail"
        );
    }

    #[test]
    fn every_signed_field_is_covered() {
        let p = signed_proof();
        let mutations: Vec<(&str, Box<dyn Fn(&mut SignedVaultReserveInclusionProof)>)> = vec![
            (
                "vault id",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| p.vault_id[0] ^= 0xff),
            ),
            (
                "smt root",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| p.smt_root[0] ^= 0xff),
            ),
            (
                "owner genesis",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| p.owner_genesis[0] ^= 0xff),
            ),
            (
                "owner devid",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| p.owner_devid[0] ^= 0xff),
            ),
            (
                "a leg amount",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| p.legs[0].amount += 1),
            ),
            (
                "a leg asset",
                Box::new(|p: &mut SignedVaultReserveInclusionProof| {
                    p.legs[0].policy_commit[0] ^= 0x01
                }),
            ),
        ];
        for (what, mutate) in mutations {
            let mut t = p.clone();
            mutate(&mut t);
            assert!(
                verify_vault_reserve_inclusion_proof(&t).is_err(),
                "tampering the {what} must invalidate the proof"
            );
        }
    }

    /// Order and distinctness are structural: the payload is built by walking the
    /// legs, so a reordered set signs differently, and a repeated asset would let
    /// one encumbrance be counted twice.
    #[test]
    fn legs_must_be_lex_ascending_and_distinct() {
        let mut reordered = signed_proof();
        reordered.legs.reverse();
        assert_eq!(
            verify_vault_reserve_inclusion_proof(&reordered),
            Err(ReserveProofError::LegsNotCanonical)
        );

        let mut duplicated = signed_proof();
        duplicated.legs[1] = duplicated.legs[0].clone();
        assert_eq!(
            verify_vault_reserve_inclusion_proof(&duplicated),
            Err(ReserveProofError::LegsNotCanonical)
        );
    }

    #[test]
    fn an_empty_or_short_proof_fails_closed() {
        let mut empty = signed_proof();
        empty.legs.clear();
        assert_eq!(
            verify_vault_reserve_inclusion_proof(&empty),
            Err(ReserveProofError::NoLegs),
            "a leg-less proof must not read as a funded vault"
        );

        let mut short = signed_proof();
        short.legs[0].smt_siblings.truncate(255);
        assert!(matches!(
            verify_vault_reserve_inclusion_proof(&short),
            Err(ReserveProofError::BadSiblingCount { .. })
        ));
    }

    #[test]
    fn another_key_cannot_sign_for_this_owner() {
        let mut p = signed_proof();
        let (other_pk, _) = generate_sphincs_keypair().expect("keypair");
        p.owner_public_key = other_pk;
        assert_eq!(
            verify_vault_reserve_inclusion_proof(&p),
            Err(ReserveProofError::SignatureInvalid)
        );
    }
}
