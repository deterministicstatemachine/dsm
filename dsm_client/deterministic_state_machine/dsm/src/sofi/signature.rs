// SPDX-License-Identifier: Apache-2.0

//! What a SoFi operation's signature covers, and who must have produced it.
//!
//! THE THREE RULES, and there are only three:
//!
//! | Operation | Signs | Under |
//! |---|---|---|
//! | `SofiSetup` | `m_setup = H(setup-sign/v1 ‖ CCB(body))` | the body's committed key |
//! | `SofiFulfill` | `m_F = H(fulfillment-sign/v1 ‖ CCB(body))` | the body's committed key |
//! | `SofiVaultCreate` | the operation's canonical unsigned bytes | the owner's device key |
//! | `EscrowVaultCreate` | the operation's canonical unsigned bytes | the owner's device key |
//!
//! A setup and a fulfillment sign their PROTOCOL OBJECT, not the operation
//! that carries it, and they do not additionally carry a generic operation
//! signature. That is not a detail of local bookkeeping: the same `F` reaches
//! storage as bare object bytes with no operation around them, and every
//! reader verifies `m_F` there — Core's recognizer, when it reads the cell or
//! the index (`publication::recognize_fulfillment`); the member verifies
//! nothing (storage spec §9 rule 6). One object, one signature, verified
//! identically wherever it is read — a second rule at the operation layer
//! would be a signature a reader of the bare object could not check and the
//! trader would have to produce twice.
//!
//! A vault creation has no protocol object of its own to sign: `R_0` and the
//! `vault_id` are derivations of a preimage the operation carries, so what it
//! signs is the operation, by the one frozen rule in
//! [`Operation::signing_bytes`](crate::types::operations::Operation::signing_bytes).
//!
//! ## The key is never taken on the object's word
//!
//! Every body commits a `(signature_alg, claimant_public_key)` pair, and a key
//! travelling inside the material it authorizes proves nothing by itself. So
//! each check here takes the signer the CALLER already knows — the device
//! whose head is advancing, or the key the parent claim commits — and refuses
//! a body that names a different one. The body's key then only fixes the
//! encoding; the binding comes from outside it.

use super::derive;
use super::wire::{
    SignedSofiResolutionClaim, SofiResolutionClaim, SofiSetupBody, TraderFulfillmentBody,
    TraderPrecommitBody,
};
use crate::ccb::genesis::sigalg;
use crate::types::operations::Operation;

type D32 = [u8; 32];

/// Why a SoFi signature does not authorize its operation.
///
/// Every variant is a refusal, and none of them is a "try again with more
/// evidence": the object, its key and its signature are all in hand at the
/// point of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The body's bytes are not a canonical object of its class, so there is
    /// nothing to derive a signing digest from.
    BodyDoesNotDecode { class: &'static str },
    /// No signature at all. A SoFi operation is authorized by its own
    /// signature and by nothing else.
    Missing { what: &'static str },
    /// The body names a signature algorithm this profile does not declare.
    /// Refused rather than guessed: an undeclared algorithm has no key width
    /// and no verifier.
    UnknownAlg { alg: u16 },
    /// The body commits a key other than the signer the caller proved. A key
    /// carried inside the material it authorizes cannot introduce itself.
    NotTheExpectedSigner { what: &'static str },
    /// The signature does not verify under that key over that digest.
    DoesNotVerify { what: &'static str },
    /// The verifier itself failed. Never "invalid" — nothing was decided.
    VerifierFailed { what: &'static str },
    /// The key does not derive the device the object names:
    /// `derive_devid(key, AttA) != DevID`. A key and an `AttA` carried by the
    /// object prove authority only for the device they derive (DSM Amendment
    /// A10).
    NotTheNamedDevice { what: &'static str },
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BodyDoesNotDecode { class } => {
                write!(
                    f,
                    "the {class} bytes are not a canonical object of that class"
                )
            }
            Self::Missing { what } => write!(
                f,
                "{what} carries no signature; a SoFi operation is authorized by its \
                 own signature and by nothing else"
            ),
            Self::UnknownAlg { alg } => write!(
                f,
                "signature algorithm {alg:#06x} is not declared by this profile"
            ),
            Self::NotTheExpectedSigner { what } => write!(
                f,
                "{what} commits a key other than the signer proven for this \
                 position; the key it carries cannot introduce itself"
            ),
            Self::DoesNotVerify { what } => {
                write!(
                    f,
                    "the {what} signature does not verify over its own digest"
                )
            }
            Self::VerifierFailed { what } => {
                write!(f, "the {what} signature could not be checked")
            }
            Self::NotTheNamedDevice { what } => write!(
                f,
                "the {what} is signed by a key that, with the AttA it carries, does not \
                 derive the device it names"
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

impl From<SignatureError> for crate::types::error::DsmError {
    fn from(e: SignatureError) -> Self {
        crate::types::error::DsmError::invalid_operation(e.to_string())
    }
}

/// One verification, over exact bytes, under a declared algorithm. Shared
/// with the escrow verdict's signatures (`sofi::escrow`), so every SoFi
/// signature is checked by this one rule.
pub(crate) fn verify_bytes(
    what: &'static str,
    alg: u16,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    // An undeclared algorithm is refused before anything is hashed: this
    // profile declares exactly one, and enumerating over values invented at a
    // call site is how an unverifiable key width gets in.
    if sigalg::public_key_len(alg) != Some(key.len()) {
        return Err(SignatureError::UnknownAlg { alg });
    }
    if signature.is_empty() {
        return Err(SignatureError::Missing { what });
    }
    match crate::crypto::sphincs::sphincs_verify(key, message, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(SignatureError::DoesNotVerify { what }),
        Err(_) => Err(SignatureError::VerifierFailed { what }),
    }
}

/// The body's own key, once it is shown to be the signer the caller proved.
fn signer_key<'a>(
    what: &'static str,
    committed: &'a [u8],
    expected: &[u8],
) -> Result<&'a [u8], SignatureError> {
    if committed != expected {
        return Err(SignatureError::NotTheExpectedSigner { what });
    }
    Ok(committed)
}

/// `m_setup` — a setup signs its own body (F1).
pub fn verify_setup(
    body: &SofiSetupBody,
    signature: &[u8],
    expected_signer: &[u8],
) -> Result<(), SignatureError> {
    let key = signer_key("SofiSetup", body.claimant_public_key(), expected_signer)?;
    verify_bytes(
        "SofiSetup",
        body.signature_alg(),
        key,
        &derive::setup_signing_digest(body),
        signature,
    )
}

/// `m_F` — a fulfillment signs its own body (F2 stage 3).
///
/// This is the exercise boundary's signature. It is the same digest a storage
/// member checks at `K_ful` ingress, so a fulfillment that verifies here
/// verifies there, on the object alone.
pub fn verify_fulfillment(
    body: &TraderFulfillmentBody,
    signature: &[u8],
    expected_signer: &[u8],
) -> Result<(), SignatureError> {
    let key = signer_key("SofiFulfill", body.claimant_public_key(), expected_signer)?;
    verify_bytes(
        "SofiFulfill",
        body.signature_alg(),
        key,
        &derive::fulfillment_signing_digest(body),
        signature,
    )
}

/// `C_q` proves its own authority for `K_root(q)` (DSM Amendment A10, SoFi
/// Amendment S20): its signature verifies under the key it carries, over a
/// digest that commits that key and the carried `AttA`, and the key with that
/// `AttA` derives the device the claim names. Decided from the bytes in hand;
/// nothing is fetched. The derivation, a hash, is checked before the
/// signature, so a claim under any other key costs no verification.
pub fn verify_resolution_claim(signed: &SignedSofiResolutionClaim) -> Result<(), SignatureError> {
    if crate::core::identity::genesis_v2::derive_devid(
        signed.claimant_public_key(),
        signed.claimant_att_a(),
    ) != signed.claim().device_id
    {
        return Err(SignatureError::NotTheNamedDevice {
            what: "SofiResolutionClaim",
        });
    }
    verify_bytes(
        "SofiResolutionClaim",
        signed.signature_alg(),
        signed.claimant_public_key(),
        &derive::resolution_claim_signing_digest(
            signed.claim(),
            signed.signature_alg(),
            signed.claimant_public_key(),
            signed.claimant_att_a(),
        ),
        signed.signature(),
    )
}

/// Sign `C_q` as the trader device it names. Refused when the key and `AttA`
/// do not derive that device, so no producer emits a claim that recognition
/// would refuse.
pub fn sign_resolution_claim(
    claim: SofiResolutionClaim,
    signature_alg: u16,
    claimant_public_key: &[u8],
    claimant_att_a: [u8; 32],
    claimant_secret_key: &[u8],
) -> Result<SignedSofiResolutionClaim, crate::types::error::DsmError> {
    if crate::core::identity::genesis_v2::derive_devid(claimant_public_key, &claimant_att_a)
        != claim.device_id
    {
        return Err(SignatureError::NotTheNamedDevice {
            what: "SofiResolutionClaim",
        }
        .into());
    }
    let digest = derive::resolution_claim_signing_digest(
        &claim,
        signature_alg,
        claimant_public_key,
        &claimant_att_a,
    );
    let signature = crate::crypto::sphincs::sphincs_sign(claimant_secret_key, &digest)?;
    SignedSofiResolutionClaim::new(
        claim,
        signature_alg,
        claimant_public_key,
        claimant_att_a,
        &signature,
    )
    .map_err(|e| crate::types::error::DsmError::invalid_operation(e.to_string()))
}

/// `m_P` — a precommit signs its own body (F2 stage 1).
///
/// Verified under the key `P` itself commits, which is the right and complete
/// check HERE: this answers "did the holder of the key this `P` was built for
/// actually sign it", which is what a producer and an ingress both need
/// before they treat `P` as published. Binding that key to the trader's
/// identity is a different question with a different answer — the exact
/// parent claim at `p` — and it is checked where that claim is in hand.
pub fn verify_precommit(
    body: &TraderPrecommitBody,
    signature: &[u8],
) -> Result<(), SignatureError> {
    verify_bytes(
        "TraderPrecommit",
        body.signature_alg(),
        body.claimant_public_key(),
        &derive::precommit_signing_digest(body),
        signature,
    )
}

/// Verify whichever SoFi operation this is, by its own rule.
///
/// `device_public_key` is the key of the device whose head is advancing. It
/// is deliberately an argument and not something read out of the operation.
pub fn verify_operation(
    operation: &Operation,
    device_public_key: &[u8],
) -> Result<(), SignatureError> {
    match operation {
        Operation::SofiSetup {
            setup_body,
            signature,
        } => {
            let body = SofiSetupBody::decode(setup_body).map_err(|_| {
                SignatureError::BodyDoesNotDecode {
                    class: "SofiSetupBody",
                }
            })?;
            verify_setup(&body, signature, device_public_key)
        }
        Operation::SofiFulfill {
            fulfillment_body,
            signature,
            ..
        } => {
            let body = TraderFulfillmentBody::decode(fulfillment_body).map_err(|_| {
                SignatureError::BodyDoesNotDecode {
                    class: "TraderFulfillmentBody",
                }
            })?;
            verify_fulfillment(&body, signature, device_public_key)
        }
        // No protocol object of its own: the creation's `vault_id` and `R_0`
        // are derivations of the preimage it carries, so what it signs is the
        // operation, by the one frozen rule.
        Operation::SofiVaultCreate { signature, .. } => verify_bytes(
            "SofiVaultCreate",
            sigalg::SPHINCS_PLUS_SPX256F,
            device_public_key,
            &operation.signing_bytes(),
            signature,
        ),
        // The same rule for an escrow vault's creation (SoFi Amendment S21).
        Operation::EscrowVaultCreate { signature, .. } => verify_bytes(
            "EscrowVaultCreate",
            sigalg::SPHINCS_PLUS_SPX256F,
            device_public_key,
            &operation.signing_bytes(),
            signature,
        ),
        // Not a SoFi operation. Refused rather than silently passed: a caller
        // that routes something else here has already lost track of which
        // rule applies.
        _ => Err(SignatureError::BodyDoesNotDecode {
            class: "a SoFi operation",
        }),
    }
}

/// The exact bytes a producer must hand its signer, and the rule that fixed
/// them. There is no fourth rule and no generic fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningPayload {
    /// `m_setup`.
    SetupDigest(D32),
    /// `m_F`.
    FulfillmentDigest(D32),
    /// The operation's canonical encoding with the signature field cleared.
    OperationBytes(Vec<u8>),
}

impl SigningPayload {
    /// What to sign, as bytes. Both digests are signed as their own 32 bytes,
    /// never re-hashed: the tag is already inside them.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::SetupDigest(d) | Self::FulfillmentDigest(d) => d,
            Self::OperationBytes(b) => b,
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use crate::sofi::wire::{AttemptEntry, PrecommitLeg};

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const POS: u64 = 5;
    const ALG: u16 = sigalg::SPHINCS_PLUS_SPX256F;

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn keys() -> (Vec<u8>, Vec<u8>) {
        generate_sphincs_keypair().unwrap()
    }

    fn setup_body(key: &[u8]) -> SofiSetupBody {
        SofiSetupBody::new(G, DEV, POS, d(0xC1), d(0x66), d(0x67), ALG, key).unwrap()
    }

    fn fulfillment_body(key: &[u8]) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            d(0x0A),
            vec![d(0x71)],
            vec![AttemptEntry {
                vault_id: d(0xC1),
                attempt: 0,
            }],
            POS + 1,
            ALG,
            key,
            [0xA7; 32],
        )
        .unwrap()
    }

    /// A setup signs `m_setup` — the protocol object's digest — and the
    /// operation that carries it adds no second signature.
    #[test]
    fn a_setup_signs_its_own_digest() {
        let (pk, sk) = keys();
        let body = setup_body(&pk);
        let signature = sphincs_sign(&sk, &derive::setup_signing_digest(&body)).unwrap();
        assert_eq!(verify_setup(&body, &signature, &pk), Ok(()));

        let operation = Operation::SofiSetup {
            setup_body: body.encode(),
            signature: signature.clone(),
        };
        assert_eq!(verify_operation(&operation, &pk), Ok(()));

        // The OPERATION's bytes are a different message, and a signature over
        // them is not what this rule accepts.
        let over_the_operation = sphincs_sign(&sk, &operation.signing_bytes()).unwrap();
        assert_eq!(
            verify_setup(&body, &over_the_operation, &pk),
            Err(SignatureError::DoesNotVerify { what: "SofiSetup" })
        );
    }

    /// A fulfillment signs `m_F`, which is exactly the digest a storage member
    /// checks on the bare object.
    #[test]
    fn a_fulfillment_signs_its_own_digest() {
        let (pk, sk) = keys();
        let body = fulfillment_body(&pk);
        let signature = sphincs_sign(&sk, &derive::fulfillment_signing_digest(&body)).unwrap();
        assert_eq!(verify_fulfillment(&body, &signature, &pk), Ok(()));
        assert_eq!(
            verify_operation(
                &Operation::SofiFulfill {
                    fulfillment_body: body.encode(),
                    precommit_id: d(0x0A).to_vec(),
                    signature,
                },
                &pk
            ),
            Ok(())
        );
    }

    /// A vault creation has no object digest of its own, so it signs the
    /// operation — and a digest-shaped signature is refused.
    #[test]
    fn a_vault_creation_signs_the_operation() {
        let (pk, sk) = keys();
        let operation = Operation::SofiVaultCreate {
            genesis_preimage: vec![0x01, 0x02],
            creation: vec![0x03, 0x04],
            market_policy_preimage: vec![0x00, 0x07],
            funding_a_policy_commit: [0x5C; 32],
            funding_b_policy_commit: [0x5D; 32],
            signature: Vec::new(),
        };
        let bytes = operation.signing_bytes();
        let signed = Operation::SofiVaultCreate {
            genesis_preimage: vec![0x01, 0x02],
            creation: vec![0x03, 0x04],
            market_policy_preimage: vec![0x00, 0x07],
            funding_a_policy_commit: [0x5C; 32],
            funding_b_policy_commit: [0x5D; 32],
            signature: sphincs_sign(&sk, &bytes).unwrap(),
        };
        assert_eq!(verify_operation(&signed, &pk), Ok(()));
    }

    /// THE CARRIED MARKET POLICY IS UNDER THE SIGNATURE, and asserting it is
    /// not tautological.
    ///
    /// Coverage is structural — `Operation::signing_bytes` is the whole
    /// canonical encoding with the signature cleared — but only while the
    /// field is IN that encoding. Deleting its line from `Operation::to_bytes`
    /// would silently take it back out from under the signature, leaving the
    /// policy object substitutable after signing while every other check still
    /// passed. This test is what goes red if that happens.
    #[test]
    fn altering_the_carried_market_policy_after_signing_is_refused() {
        let (pk, sk) = keys();
        let build = |policy: Vec<u8>, signature: Vec<u8>| Operation::SofiVaultCreate {
            genesis_preimage: vec![0x01, 0x02],
            creation: vec![0x03, 0x04],
            market_policy_preimage: policy,
            funding_a_policy_commit: [0x5C; 32],
            funding_b_policy_commit: [0x5D; 32],
            signature,
        };
        let honest = vec![0x00, 0x07, 0x00, 0x01];
        let bytes = (build(honest.clone(), Vec::new())).signing_bytes();
        let signature = sphincs_sign(&sk, &bytes).unwrap();
        assert_eq!(
            verify_operation(&build(honest.clone(), signature.clone()), &pk),
            Ok(())
        );

        // ONLY the policy bytes differ, and the signature is the same one.
        let swapped = vec![0x00, 0x07, 0x00, 0x02];
        assert_ne!(swapped, honest);
        assert!(
            verify_operation(&build(swapped, signature), &pk).is_err(),
            "the carried market policy must be covered by the operation signature"
        );
    }

    /// The body's own key cannot introduce itself: a signature that verifies
    /// under the key the body names is still refused when that is not the
    /// signer the caller proved.
    #[test]
    fn a_body_cannot_name_its_own_signer() {
        let (pk, sk) = keys();
        let (other_pk, _) = keys();
        let body = setup_body(&pk);
        let signature = sphincs_sign(&sk, &derive::setup_signing_digest(&body)).unwrap();
        // Self-consistent, and refused.
        assert_eq!(verify_setup(&body, &signature, &pk), Ok(()));
        assert_eq!(
            verify_setup(&body, &signature, &other_pk),
            Err(SignatureError::NotTheExpectedSigner { what: "SofiSetup" })
        );
    }

    /// Missing, garbage and foreign-key signatures are each refused by name.
    #[test]
    fn nothing_passes_without_a_verifying_signature() {
        let (pk, sk) = keys();
        let (other_pk, other_sk) = keys();
        let body = setup_body(&pk);
        assert_eq!(
            verify_setup(&body, &[], &pk),
            Err(SignatureError::Missing { what: "SofiSetup" })
        );
        assert_eq!(
            verify_setup(&body, &[0xAB; 49_856], &pk),
            Err(SignatureError::DoesNotVerify { what: "SofiSetup" })
        );
        // Another identity's signature over the same digest.
        let foreign = sphincs_sign(&other_sk, &derive::setup_signing_digest(&body)).unwrap();
        assert_eq!(
            verify_setup(&body, &foreign, &pk),
            Err(SignatureError::DoesNotVerify { what: "SofiSetup" })
        );
        // And the same signature under its own key is still not this body's
        // committed signer.
        let _ = other_pk;
        // One byte of the body changes the digest and the signature no longer
        // covers it.
        let signature = sphincs_sign(&sk, &derive::setup_signing_digest(&body)).unwrap();
        let moved =
            SofiSetupBody::new(G, DEV, POS + 1, d(0xC1), d(0x66), d(0x67), ALG, &pk).unwrap();
        assert_eq!(
            verify_setup(&moved, &signature, &pk),
            Err(SignatureError::DoesNotVerify { what: "SofiSetup" })
        );
    }

    fn precommit_body(key: &[u8]) -> TraderPrecommitBody {
        TraderPrecommitBody::new(
            G,
            DEV,
            POS,
            crate::sofi::wire::ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            d(0x0E),
            vec![PrecommitLeg {
                vault_id: d(0xC1),
                parent_root: d(0x62),
                setup_ref: d(0x55),
            }],
            d(0xA1),
            d(0x61),
            d(0x77),
            ALG,
            key,
        )
        .unwrap()
    }

    fn signed_precommit(pk: &[u8], sk: &[u8]) -> crate::sofi::wire::SignedSofiObject {
        let body = precommit_body(pk);
        let sig = sphincs_sign(sk, &derive::precommit_signing_digest(&body)).unwrap();
        crate::sofi::wire::SignedSofiObject::new(
            crate::ccb::class::SOFI_TRADER_PRECOMMIT_BODY,
            &body.encode(),
            ALG,
            &sig,
        )
        .unwrap()
    }

    /// A body class the envelope does not carry is refused by its producer,
    /// and a hostile envelope naming one on the wire still decodes, so no
    /// recognizer takes it as any object. `G` has no issuer signature, so it
    /// does not belong in a signed envelope.
    #[test]
    fn an_unsupported_body_class_is_refused_at_both_ends() {
        let (pk, sk) = keys();
        let witness = crate::sofi::wire::DlvPolicyFulfillmentBody {
            precommit_id: d(0x0A),
            external_commitment: d(0x0B),
            vault_id: d(0x0C),
            parent_root: d(0x0D),
            shadow_core: d(0x0E),
        };
        let sig = sphincs_sign(&sk, &witness.encode()).unwrap();
        // The producer cannot build one.
        assert!(matches!(
            crate::sofi::wire::SignedSofiObject::new(
                crate::ccb::class::SOFI_DLV_POLICY_FULFILLMENT_BODY,
                &witness.encode(),
                ALG,
                &sig,
            ),
            Err(crate::sofi::wire::SofiWireError::UnsupportedSignedBodyClass { .. })
        ));
        // A hostile one that arrives on the wire decodes, and is no object.
        let mut bytes = signed_precommit(&pk, &sk).encode();
        bytes[4..6]
            .copy_from_slice(&crate::ccb::class::SOFI_DLV_POLICY_FULFILLMENT_BODY.to_be_bytes());
        crate::sofi::wire::SignedSofiObject::decode(&bytes)
            .expect("a hostile envelope decodes so it can be named");
        assert!(crate::sofi::publication::recognize_precommit(&bytes).is_none());
        assert!(crate::sofi::publication::recognize_fulfillment(&bytes).is_none());
        assert!(crate::sofi::publication::recognize_setup(&bytes).is_none());
    }

    /// `m_P` verifies under the key `P` commits — that is the question a
    /// producer and an ingress ask before treating `P` as published.
    #[test]
    fn a_precommit_signs_its_own_digest() {
        let (pk, sk) = keys();
        let precommit = TraderPrecommitBody::new(
            G,
            DEV,
            POS,
            crate::sofi::wire::ParentClaimRef::SingleRoot { claim_ref: d(0x66) },
            d(0x0E),
            vec![PrecommitLeg {
                vault_id: d(0xC1),
                parent_root: d(0x62),
                setup_ref: d(0x55),
            }],
            d(0xA1),
            d(0x61),
            d(0x77),
            ALG,
            &pk,
        )
        .unwrap();
        let signature = sphincs_sign(&sk, &derive::precommit_signing_digest(&precommit)).unwrap();
        assert_eq!(verify_precommit(&precommit, &signature), Ok(()));
        assert_eq!(
            verify_precommit(&precommit, &[0xAB; 49_856]),
            Err(SignatureError::DoesNotVerify {
                what: "TraderPrecommit"
            })
        );
    }

    /// A non-SoFi operation has no rule here and is refused rather than passed.
    #[test]
    fn a_foreign_operation_has_no_rule_here() {
        assert!(verify_operation(&Operation::Noop, &[0x01; 64]).is_err());
    }
}
