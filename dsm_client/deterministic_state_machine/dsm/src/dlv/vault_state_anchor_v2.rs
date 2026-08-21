// SPDX-License-Identifier: Apache-2.0

//! History-bound vault state anchor — `VaultStateAnchorV2`, Rev 15 Def 6.4.
//!
//! The parent binding every route allocation carries:
//!
//! ```text
//! p_v = H(DSM/vault-state-anchor/v2 ‖ vault_id ‖ generation
//!         ‖ parent_state_commitment ‖ reserves_digest ‖ storage_set_id ‖ q)
//! ```
//!
//! Two fields distinguish this from the legacy anchor, and both are the point.
//!
//! `parent_state_commitment` is `h_n` of Def 4.1 — `c_{n-1}` for `n > 0`, the
//! domain-separated genesis value at `n = 0`. Req 6.5 requires the anchor to
//! bind "the history commitment that produced the advertised reserves, not only
//! the vault identifier, local generation, and reserves digest", so two
//! histories arriving at identical reserves must still produce different
//! bindings. The legacy anchor cannot do that: it commits `(vault_id,
//! sequence, reserves_digest, storage_set_id)` and nothing about how the
//! reserves came to be.
//!
//! `q` is the owner-committed threshold. Req 15.8 requires Class K to count
//! against "the exact owner-committed S", and Req 6.11 forbids lowering the
//! threshold because a member is unavailable. A threshold recomputed locally
//! from set size is not owner-committed, and two clients with different rules
//! would disagree with nothing on the wire to detect it.
//!
//! ## Clean cut — Req 6.6
//!
//! This "uses a new domain/schema and must not be silently accepted as the
//! legacy anchor format or vice versa. Beta deployment uses a schema bump and
//! clean reprovision rather than a dual-read or fallback path."
//!
//! So there is no conversion from [`super::vault_state_anchor::SignedVaultStateAnchor`],
//! no `TryFrom`, and no "verify as V2, else fall back to V1" helper anywhere.
//! The separation is enforced by the domain tag rather than by discipline: a V1
//! payload and a V2 payload over the same logical vault hash differently, so a
//! signature over one cannot verify as the other. `a_v1_signature_never_verifies_as_v2`
//! pins that.

use crate::common::domain_tags::TAG_DSM_VAULT_STATE_ANCHOR_V2;
use crate::crypto::blake3::dsm_domain_hasher;

/// Errors from signing or verifying a V2 anchor.
///
/// Deliberately its own type rather than the legacy `AnchorError`: sharing one
/// would make a caller's error handling identical across the cut, which is the
/// first step toward treating the two formats as interchangeable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorV2Error {
    SignatureInvalid,
    SignFailed(String),
}

impl core::fmt::Display for AnchorV2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchorV2Error::SignatureInvalid => write!(f, "v2 anchor signature verification failed"),
            AnchorV2Error::SignFailed(msg) => write!(f, "v2 anchor sphincs sign failed: {msg}"),
        }
    }
}

impl std::error::Error for AnchorV2Error {}

/// A history-bound anchor, signed by the vault owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedVaultStateAnchorV2 {
    pub vault_id: [u8; 32],
    /// The vault-local generation `n`.
    pub generation: u64,
    /// `h_n` — `c_{n-1}`, or the genesis value at `n = 0`.
    pub parent_state_commitment: [u8; 32],
    pub reserves_digest: [u8; 32],
    pub storage_set_id: [u8; 32],
    /// The owner-committed settlement threshold. Not recomputed by a reader.
    pub quorum: u32,
    pub owner_public_key: Vec<u8>,
    pub owner_signature: Vec<u8>,
}

/// The Def 6.4 parent binding `p_v`, and the payload the owner signs.
///
/// Field order follows the definition exactly. `generation` and `quorum` are
/// big-endian fixed width; every digest is its bare 32 bytes.
pub fn parent_binding(
    vault_id: &[u8; 32],
    generation: u64,
    parent_state_commitment: &[u8; 32],
    reserves_digest: &[u8; 32],
    storage_set_id: &[u8; 32],
    quorum: u32,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_VAULT_STATE_ANCHOR_V2);
    h.update(vault_id);
    h.update(&generation.to_be_bytes());
    h.update(parent_state_commitment);
    h.update(reserves_digest);
    h.update(storage_set_id);
    h.update(&quorum.to_be_bytes());
    *h.finalize().as_bytes()
}

impl SignedVaultStateAnchorV2 {
    /// The `p_v` this anchor advertises.
    pub fn parent_binding(&self) -> [u8; 32] {
        parent_binding(
            &self.vault_id,
            self.generation,
            &self.parent_state_commitment,
            &self.reserves_digest,
            &self.storage_set_id,
            self.quorum,
        )
    }
}

/// Sign a V2 anchor over the Def 6.4 binding.
#[allow(clippy::too_many_arguments)]
pub fn sign_vault_state_anchor_v2(
    vault_id: &[u8; 32],
    generation: u64,
    parent_state_commitment: &[u8; 32],
    reserves_digest: &[u8; 32],
    storage_set_id: &[u8; 32],
    quorum: u32,
    owner_public_key: &[u8],
    owner_secret_key: &[u8],
) -> Result<SignedVaultStateAnchorV2, AnchorV2Error> {
    let payload = parent_binding(
        vault_id,
        generation,
        parent_state_commitment,
        reserves_digest,
        storage_set_id,
        quorum,
    );
    let signature = crate::crypto::sphincs::sphincs_sign(owner_secret_key, &payload)
        .map_err(|e| AnchorV2Error::SignFailed(format!("{e:?}")))?;
    Ok(SignedVaultStateAnchorV2 {
        vault_id: *vault_id,
        generation,
        parent_state_commitment: *parent_state_commitment,
        reserves_digest: *reserves_digest,
        storage_set_id: *storage_set_id,
        quorum,
        owner_public_key: owner_public_key.to_vec(),
        owner_signature: signature,
    })
}

/// Verify the owner's signature over the anchor's own public fields.
pub fn verify_vault_state_anchor_v2(
    anchor: &SignedVaultStateAnchorV2,
) -> Result<(), AnchorV2Error> {
    let payload = anchor.parent_binding();
    let ok = crate::crypto::sphincs::sphincs_verify(
        &anchor.owner_public_key,
        &payload,
        &anchor.owner_signature,
    )
    .map_err(|_| AnchorV2Error::SignatureInvalid)?;
    if ok {
        Ok(())
    } else {
        Err(AnchorV2Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlv::vault_state_anchor as v1;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    fn anchor(
        pk: &[u8],
        sk: &[u8],
        generation: u64,
        psc: [u8; 32],
        reserves: [u8; 32],
        q: u32,
    ) -> SignedVaultStateAnchorV2 {
        sign_vault_state_anchor_v2(
            &[0x7E; 32],
            generation,
            &psc,
            &reserves,
            &[0x55; 32],
            q,
            pk,
            sk,
        )
        .expect("sign")
    }

    #[test]
    fn a_signed_anchor_verifies() {
        let (pk, sk) = keypair();
        let a = anchor(&pk, &sk, 3, [0x01; 32], [0x02; 32], 4);
        assert_eq!(verify_vault_state_anchor_v2(&a), Ok(()));
    }

    /// PINS THE DOMAIN AND THE FIELD ORDER TO REV 15 DEF 6.4.
    ///
    /// Every other test here signs and verifies through the same code, so they
    /// stay green even if the tag were swapped wholesale — self-consistency is
    /// not conformance. This recomputes the binding from the literal spec bytes
    /// and demands equality, so the domain string, the `0x00` separator, the
    /// field order and the integer widths are all fixed to the specification
    /// rather than to whatever the implementation happens to do.
    #[test]
    fn the_binding_matches_the_definition_computed_from_literal_spec_bytes() {
        let vault = [0x7E; 32];
        let generation: u64 = 9;
        let psc = [0xC1; 32];
        let reserves = [0xC2; 32];
        let set = [0xC3; 32];
        let q: u32 = 4;

        // H(tag ‖ 0x00 ‖ vault_id ‖ generation_be ‖ psc ‖ reserves ‖ set ‖ q_be)
        let mut expected = blake3::Hasher::new();
        expected.update(b"DSM/vault-state-anchor/v2");
        expected.update(&[0u8]);
        expected.update(&vault);
        expected.update(&generation.to_be_bytes());
        expected.update(&psc);
        expected.update(&reserves);
        expected.update(&set);
        expected.update(&q.to_be_bytes());
        let expected: [u8; 32] = *expected.finalize().as_bytes();

        assert_eq!(
            parent_binding(&vault, generation, &psc, &reserves, &set, q),
            expected,
            "the binding must be Def 6.4 exactly — domain, order and widths"
        );

        // And it is NOT the legacy domain, which is the whole point of Req 6.6.
        let mut legacy_domain = blake3::Hasher::new();
        legacy_domain.update(b"DSM/vault-state-anchor\0");
        legacy_domain.update(&[0u8]);
        legacy_domain.update(&vault);
        legacy_domain.update(&generation.to_be_bytes());
        legacy_domain.update(&psc);
        legacy_domain.update(&reserves);
        legacy_domain.update(&set);
        legacy_domain.update(&q.to_be_bytes());
        assert_ne!(
            expected,
            *legacy_domain.finalize().as_bytes(),
            "the v2 domain must differ from the legacy one"
        );
    }

    /// REQ 6.5, the whole reason V2 exists. Same vault, same generation, same
    /// reserves — different history. The bindings must differ.
    #[test]
    fn identical_reserves_from_different_histories_bind_differently() {
        let (pk, sk) = keypair();
        let reserves = [0x02; 32];
        let from_one = anchor(&pk, &sk, 5, [0xAA; 32], reserves, 4);
        let from_other = anchor(&pk, &sk, 5, [0xBB; 32], reserves, 4);
        assert_eq!(from_one.reserves_digest, from_other.reserves_digest);
        assert_eq!(from_one.generation, from_other.generation);
        assert_ne!(
            from_one.parent_binding(),
            from_other.parent_binding(),
            "two histories reaching identical reserves must not share a parent binding"
        );
    }

    /// The legacy anchor cannot express that distinction, which is why a
    /// migration and not a field addition was required.
    #[test]
    fn the_legacy_anchor_cannot_distinguish_those_histories() {
        let one = v1::compute_anchor_digest(&[0x7E; 32], 5, &[0x02; 32]);
        let other = v1::compute_anchor_digest(&[0x7E; 32], 5, &[0x02; 32]);
        assert_eq!(
            one, other,
            "the legacy digest is a function of (vault, sequence, reserves) alone, \
             so divergent histories collide — exactly what Req 6.5 forbids"
        );
    }

    /// `q` is committed, so changing it changes the binding. A reader that
    /// recomputed the threshold locally could not detect a substitution.
    #[test]
    fn the_committed_quorum_is_part_of_the_binding() {
        let (pk, sk) = keypair();
        let at_four = anchor(&pk, &sk, 1, [0x01; 32], [0x02; 32], 4);
        let at_three = anchor(&pk, &sk, 1, [0x01; 32], [0x02; 32], 3);
        assert_ne!(at_four.parent_binding(), at_three.parent_binding());

        // A substituted q does not verify against the owner's signature.
        let mut tampered = at_four.clone();
        tampered.quorum = 3;
        assert_eq!(
            verify_vault_state_anchor_v2(&tampered),
            Err(AnchorV2Error::SignatureInvalid),
            "lowering the committed threshold must break the signature"
        );
    }

    /// REQ 6.6, the clean cut. A V1 signature must not verify as V2, because
    /// the domain tag differs — not because a caller remembered to check.
    #[test]
    fn a_v1_signature_never_verifies_as_v2() {
        let (pk, sk) = keypair();
        let vault = [0x7E; 32];
        let reserves = [0x02; 32];
        let set = [0x55; 32];

        let legacy = v1::sign_vault_state_anchor(&vault, 5, &reserves, &set, &pk, &sk)
            .expect("legacy anchor signs");

        // Lift the legacy signature onto a V2-shaped anchor over the same
        // logical vault. Every field a legacy anchor has is carried across.
        let smuggled = SignedVaultStateAnchorV2 {
            vault_id: legacy.vault_id,
            generation: legacy.sequence,
            parent_state_commitment: [0x00; 32],
            reserves_digest: legacy.reserves_digest,
            storage_set_id: legacy.storage_set_id,
            quorum: 4,
            owner_public_key: legacy.owner_public_key.clone(),
            owner_signature: legacy.owner_signature.clone(),
        };
        assert_eq!(
            verify_vault_state_anchor_v2(&smuggled),
            Err(AnchorV2Error::SignatureInvalid),
            "a legacy signature must not be accepted as a history-bound one"
        );

        // And the reverse: a V2 signature is not a legacy anchor's signature.
        let v2 = anchor(&pk, &sk, 5, [0x00; 32], reserves, 4);
        let downgraded = v1::SignedVaultStateAnchor {
            vault_id: v2.vault_id,
            sequence: v2.generation,
            reserves_digest: v2.reserves_digest,
            storage_set_id: v2.storage_set_id,
            owner_public_key: v2.owner_public_key.clone(),
            owner_signature: v2.owner_signature.clone(),
        };
        assert!(
            v1::verify_vault_state_anchor(&downgraded).is_err(),
            "a history-bound signature must not be accepted as a legacy one either"
        );
    }

    /// THE RECURRENCE, END TO END. The anchor's `parent_state_commitment` is
    /// not a free parameter: at generation 0 it is the genesis value, and at
    /// generation n it is `c_{n-1}` computed by the CCB encoder over the real
    /// prior state. This wires the two halves together so a drift between them
    /// is a test failure rather than a latent divergence.
    #[test]
    fn the_anchor_carries_h_n_from_the_ccb_encoder() {
        use crate::ccb::{
            genesis_parent_commitment, vault_state_commitment, EncumbranceSet, FeePolicy,
            MarketPolicy, ReleasePolicy, StorageSetMembers, VaultStateV2,
        };

        let vault = [0x7E; 32];
        let members: [&[u8]; 5] = [
            b"dsm-node-1",
            b"dsm-node-2",
            b"dsm-node-3",
            b"dsm-node-4",
            b"dsm-node-5",
        ];
        let mk = |generation: u64, r_a: u64, r_b: u64, h_n: [u8; 32]| VaultStateV2 {
            owner_genesis_id: [0xA1; 32],
            owner_device_id: [0xA2; 32],
            vault_id: vault,
            generation,
            reserve_a: r_a,
            reserve_b: r_b,
            market_policy: MarketPolicy::beta_constant_product([0x11; 32], [0x22; 32])
                .expect("ordered pair"),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(30).expect("30 bps"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: h_n,
            owner_root: [0xA3; 32],
            storage_set: StorageSetMembers::new(&members).expect("five members"),
            quorum: 4,
        };

        // n = 0: h_0 is the domain-separated genesis value, not a zero sentinel.
        let h0 = genesis_parent_commitment(&vault);
        assert_ne!(
            h0, [0u8; 32],
            "genesis is derived, never an all-zero sentinel"
        );
        let v0 = mk(0, 1_000_000, 500_000, h0);

        // n = 1: h_1 = c_0 over the real prior state.
        let c0 = vault_state_commitment(&v0).expect("c_0");
        let v1 = mk(1, 1_001_000, 499_547, c0);

        let (pk, sk) = keypair();
        let a0 = sign_vault_state_anchor_v2(
            &vault,
            0,
            &v0.parent_state_commitment,
            &[0x02; 32],
            &[0x55; 32],
            v0.quorum,
            &pk,
            &sk,
        )
        .expect("anchor 0");
        let a1 = sign_vault_state_anchor_v2(
            &vault,
            1,
            &v1.parent_state_commitment,
            &[0x03; 32],
            &[0x55; 32],
            v1.quorum,
            &pk,
            &sk,
        )
        .expect("anchor 1");

        assert_eq!(verify_vault_state_anchor_v2(&a0), Ok(()));
        assert_eq!(verify_vault_state_anchor_v2(&a1), Ok(()));
        assert_eq!(a0.parent_state_commitment, h0);
        assert_eq!(
            a1.parent_state_commitment, c0,
            "generation 1 must anchor to c_0, the canonical prior DLV state"
        );
        assert_eq!(a1.quorum, 4, "the committed q travels with the anchor");
        assert_ne!(
            a0.parent_binding(),
            a1.parent_binding(),
            "successive generations bind differently"
        );
    }

    /// One tamper applied to an otherwise valid anchor.
    type Mutation = Box<dyn Fn(&mut SignedVaultStateAnchorV2)>;

    /// Every field is inside the signature; none is advisory.
    #[test]
    fn every_field_is_bound_by_the_signature() {
        let (pk, sk) = keypair();
        let base = anchor(&pk, &sk, 2, [0x01; 32], [0x02; 32], 4);
        let mutate: Vec<(&str, Mutation)> = vec![
            (
                "vault_id",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.vault_id = [0x7F; 32]),
            ),
            (
                "generation",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.generation += 1),
            ),
            (
                "parent_state_commitment",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.parent_state_commitment = [0xEE; 32]),
            ),
            (
                "reserves_digest",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.reserves_digest = [0xEE; 32]),
            ),
            (
                "storage_set_id",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.storage_set_id = [0xEE; 32]),
            ),
            (
                "quorum",
                Box::new(|a: &mut SignedVaultStateAnchorV2| a.quorum = 5),
            ),
        ];
        for (field, apply) in mutate {
            let mut tampered = base.clone();
            apply(&mut tampered);
            assert_eq!(
                verify_vault_state_anchor_v2(&tampered),
                Err(AnchorV2Error::SignatureInvalid),
                "{field} must be inside the signature"
            );
        }
    }
}
