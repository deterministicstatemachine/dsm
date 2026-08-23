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
//! ## Signed is not validated
//!
//! This primitive proves `q` was **committed**, not that it is **correct**. It
//! holds `storage_set_id` rather than the resolved set, so it cannot know the
//! member count and cannot check `q` against the Req 6.13 beta profile — the
//! tests here deliberately sign `q = 3` to show an out-of-profile value signs
//! and verifies perfectly well at this layer.
//!
//! Closing Area 3 of the conformance delta therefore needs the lifecycle
//! verifier, which must resolve the authenticated `S`, require exactly five
//! members, require `q = 4`, and only then verify the anchor. Req 6.11 forbids
//! lowering the threshold when members disappear, and nothing here can enforce
//! that. Signature inclusion is a precondition of the rule, not the rule.
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
    /// The anchor's embedded key is not the owner key the caller authenticated
    /// elsewhere. Checked before the signature, because a signature verifying
    /// under a self-declared key proves only that *someone* signed.
    OwnerKeyMismatch,
}

impl core::fmt::Display for AnchorV2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AnchorV2Error::SignatureInvalid => write!(f, "v2 anchor signature verification failed"),
            AnchorV2Error::SignFailed(msg) => write!(f, "v2 anchor sphincs sign failed: {msg}"),
            AnchorV2Error::OwnerKeyMismatch => write!(
                f,
                "v2 anchor is signed by a key other than the authenticated vault owner"
            ),
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

/// Verify that **the authenticated vault owner** signed this anchor.
///
/// `expected_owner_public_key` must come from material the caller has already
/// authenticated — the vault's birth state, the reserve-owner record, the
/// composed `V_n`. It is a parameter rather than something read from the
/// anchor, deliberately.
///
/// An anchor carries `owner_public_key`, and verifying against that embedded
/// key would prove only "this key signed these bytes". Anyone can generate a
/// SPHINCS+ pair, put any `vault_id` in an anchor, sign it, and pass such a
/// check. The legacy anchor has exactly that weakness; the clean cut is the
/// moment to stop propagating it, so this function cannot be used without an
/// externally supplied key.
pub fn verify_vault_state_anchor_v2(
    anchor: &SignedVaultStateAnchorV2,
    expected_owner_public_key: &[u8],
) -> Result<(), AnchorV2Error> {
    if anchor.owner_public_key != expected_owner_public_key {
        return Err(AnchorV2Error::OwnerKeyMismatch);
    }
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
        assert_eq!(verify_vault_state_anchor_v2(&a, &pk), Ok(()));
    }

    /// A SELF-DECLARED KEY PROVES NOTHING. This is the attack the verifier's
    /// key parameter exists to stop: anyone can generate a SPHINCS+ pair, put
    /// any vault_id in an anchor, sign it, and produce something that verifies
    /// against its own embedded key.
    #[test]
    fn an_anchor_signed_by_a_stranger_does_not_verify_as_the_owners() {
        let (owner_pk, _owner_sk) = keypair();
        let (attacker_pk, attacker_sk) = keypair();

        // A perfectly well-formed anchor for the victim's vault, signed with
        // the attacker's own key.
        let forged = anchor(&attacker_pk, &attacker_sk, 5, [0x01; 32], [0x02; 32], 4);

        // It verifies against the key it carries — which is exactly the
        // guarantee the legacy primitive offered, and it is not ownership.
        assert_eq!(
            verify_vault_state_anchor_v2(&forged, &attacker_pk),
            Ok(()),
            "the forgery is internally well-formed, which is the problem"
        );

        // Against the authenticated owner key it is refused, before the
        // signature is even examined.
        assert_eq!(
            verify_vault_state_anchor_v2(&forged, &owner_pk),
            Err(AnchorV2Error::OwnerKeyMismatch),
            "an anchor signed by a stranger must not verify as the owner's"
        );

        // Relabelling the embedded key does not conjure the owner's signature,
        // so the check cannot be satisfied by editing that field.
        let mut relabelled = forged.clone();
        relabelled.owner_public_key = owner_pk.clone();
        assert_eq!(
            verify_vault_state_anchor_v2(&relabelled, &owner_pk),
            Err(AnchorV2Error::SignatureInvalid),
            "relabelling the key does not produce the owner's signature"
        );
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

        // And it is not the LEGACY payload for the same vault. Reconstructed
        // exactly as V1 builds it: the tag literal already ends in NUL and V1
        // hashes it directly, so there is no second separator, and the legacy
        // payload carries neither a parent state commitment nor q.
        let mut legacy = blake3::Hasher::new();
        legacy.update(b"DSM/vault-state-anchor\0");
        legacy.update(&vault);
        legacy.update(&generation.to_be_bytes());
        legacy.update(&reserves);
        legacy.update(&set);
        let legacy: [u8; 32] = *legacy.finalize().as_bytes();
        assert_ne!(
            expected, legacy,
            "the v2 binding must differ from the legacy payload for the same vault"
        );
        // Cross-check the reconstruction against V1's own code, so this pins
        // the real legacy construction rather than a guess at it.
        let (lpk, lsk) = keypair();
        let legacy_anchor =
            v1::sign_vault_state_anchor(&vault, generation, &reserves, &set, &lpk, &lsk)
                .expect("legacy signs");
        assert!(
            crate::crypto::sphincs::sphincs_verify(&lpk, &legacy, &legacy_anchor.owner_signature)
                .expect("verify runs"),
            "the reconstructed legacy payload must be the one V1 actually signs"
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
    ///
    /// Note this signs `q = 3`, which is NOT the Req 6.13 beta profile. That is
    /// deliberate: it shows the primitive commits whatever it is given.
    /// Validating `q` against the resolved set is the lifecycle verifier's job,
    /// because this layer holds only `storage_set_id` and cannot count members.
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
            verify_vault_state_anchor_v2(&tampered, &pk),
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
            verify_vault_state_anchor_v2(&smuggled, &pk),
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
            owner_authority_transition_digest: [0xA3; 32],
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

        // EVERY anchor input is derived from the state it describes. Nothing
        // synthetic: a test that copies the lineage field across but invents
        // the reserves digest and the set id proves the field can be carried,
        // not that one state yields one anchor.
        let anchor_for = |v: &VaultStateV2, pk: &[u8], sk: &[u8]| {
            let reserves_digest = crate::dlv::vault_state_anchor::compute_reserves_digest(
                v.market_policy.token_a(),
                v.market_policy.token_b(),
                v.reserve_a,
                v.reserve_b,
                v.fee_policy.fee_bps(),
            );
            let set_id = crate::ccb::storage_set_id(&v.storage_set).expect("set id");
            sign_vault_state_anchor_v2(
                &v.vault_id,
                v.generation,
                &v.parent_state_commitment,
                &reserves_digest,
                &set_id,
                v.quorum,
                pk,
                sk,
            )
            .expect("anchor signs")
        };

        let (pk, sk) = keypair();
        let a0 = anchor_for(&v0, &pk, &sk);
        let a1 = anchor_for(&v1, &pk, &sk);

        assert_eq!(verify_vault_state_anchor_v2(&a0, &pk), Ok(()));
        assert_eq!(verify_vault_state_anchor_v2(&a1, &pk), Ok(()));

        // The derived inputs really are the state's, not incidental constants.
        assert_eq!(
            a1.storage_set_id,
            crate::ccb::storage_set_id(&v1.storage_set).expect("set id"),
            "the anchor's set id is the one committed in V_n"
        );
        assert_ne!(
            a0.reserves_digest, a1.reserves_digest,
            "different reserves must give different digests, so the digest is derived"
        );
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
                verify_vault_state_anchor_v2(&tampered, &pk),
                Err(AnchorV2Error::SignatureInvalid),
                "{field} must be inside the signature"
            );
        }
    }
}
