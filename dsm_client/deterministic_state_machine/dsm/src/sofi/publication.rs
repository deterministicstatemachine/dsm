// SPDX-License-Identifier: Apache-2.0

//! Part II §10 and §11, rebuild step R8: what a producer publishes, under
//! which namespace and locators, and how a reader recognizes it.
//!
//! Five kinds of protocol object are published as their exact canonical
//! bytes: the setup, `P`, `P(E)`, every `G_j`, and `F`. The three that carry a
//! trader signature travel in a [`SignedSofiObject`] envelope, because the
//! signature is what a verifier checks and the body alone does not carry it;
//! `P(E)` and `G_j` have no issuer signature and are published bare. Each
//! kind has its own immutable-store namespace, so the address binds the kind,
//! and is indexed under the locator Part II §11 assigns to it: `ρ` (and the
//! relationship index key) for a setup, `PrecommitId`, `L(E)`,
//! `PolicyFulfillmentId_j`, `FulfillmentId`.
//!
//! A reader never trusts a locator: it fetches every candidate, recomputes
//! the identity FROM THE BYTES with the recognizer of that kind, and keeps
//! the one whose identity is the locator. Recognition is not verification —
//! a recognized envelope carries a signature nobody has checked yet; that is
//! `verify_setup`, `verify_precommit` and `verify_fulfillment`, applied where
//! the expected signer is in hand.

use crate::ccb::class;
use crate::common::domain_tags::{
    TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT, TAG_DSM_SOFI_FULFILLMENT_ID,
    TAG_DSM_SOFI_FULFILLMENT_OBJECT, TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT,
    TAG_DSM_SOFI_PRECOMMIT_OBJECT, TAG_DSM_SOFI_PREIMAGE_LOCATOR, TAG_DSM_SOFI_PREIMAGE_OBJECT,
    TAG_DSM_SOFI_REL_INDEX, TAG_DSM_SOFI_SETUP_OBJECT, TAG_DSM_SOFI_SETUP_REF,
    TAG_DSM_SOFI_TRADER_PRECOMMIT_ID,
};
use crate::crypto::domain::TaggedHashDomain;
use crate::storage_object::immutable_addr;

use super::derive;
use super::wire::{
    DlvPolicyFulfillmentBody, SettlementPreimage, SignedSofiObject, SofiSetupBody, SofiWireError,
    TraderFulfillmentBody, TraderPrecommitBody,
};

type D32 = [u8; 32];

/// A signed body as it is published and fetched: the body and the signature
/// its envelope carries. The identity is over the body alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    pub body: T,
    pub signature: Vec<u8>,
}

/// One locator an object is indexed under: the index namespace and the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    pub index_namespace: &'static [u8],
    pub locator: D32,
}

/// An object to publish, borrowed from the producer that built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publication<'a> {
    /// The setup, in its envelope with the signature over `m_setup`.
    Setup {
        body: &'a SofiSetupBody,
        signature: &'a [u8],
    },
    /// `P`, in its envelope with the signature over `m_P`.
    Precommit {
        body: &'a TraderPrecommitBody,
        signature: &'a [u8],
    },
    /// `P(E)`, bare.
    Preimage(&'a SettlementPreimage),
    /// `G_j`, bare: it has no issuer signature.
    PolicyFulfillment(&'a DlvPolicyFulfillmentBody),
    /// `F`, in its envelope with the signature over `m_F`.
    Fulfillment {
        body: &'a TraderFulfillmentBody,
        signature: &'a [u8],
    },
}

fn envelope(
    body_class: u16,
    body_ccb: &[u8],
    alg: u16,
    sig: &[u8],
) -> Result<Vec<u8>, SofiWireError> {
    Ok(SignedSofiObject::new(body_class, body_ccb, alg, sig)?.encode())
}

impl Publication<'_> {
    /// The exact bytes a member stores: the envelope for a signed kind, the
    /// canonical body otherwise.
    pub fn object_bytes(&self) -> Result<Vec<u8>, SofiWireError> {
        match self {
            Self::Setup { body, signature } => envelope(
                class::SOFI_SETUP_BODY,
                &body.encode(),
                body.signature_alg(),
                signature,
            ),
            Self::Precommit { body, signature } => envelope(
                class::SOFI_TRADER_PRECOMMIT_BODY,
                &body.encode(),
                body.signature_alg(),
                signature,
            ),
            Self::Preimage(preimage) => preimage.encode(),
            Self::PolicyFulfillment(body) => Ok(body.encode()),
            Self::Fulfillment { body, signature } => envelope(
                class::SOFI_TRADER_FULFILLMENT_BODY,
                &body.encode(),
                body.signature_alg(),
                signature,
            ),
        }
    }

    /// The immutable-store namespace of this kind.
    pub fn namespace(&self) -> TaggedHashDomain<'static> {
        match self {
            Self::Setup { .. } => TAG_DSM_SOFI_SETUP_OBJECT,
            Self::Precommit { .. } => TAG_DSM_SOFI_PRECOMMIT_OBJECT,
            Self::Preimage(_) => TAG_DSM_SOFI_PREIMAGE_OBJECT,
            Self::PolicyFulfillment(_) => TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT,
            Self::Fulfillment { .. } => TAG_DSM_SOFI_FULFILLMENT_OBJECT,
        }
    }

    /// The content address the member computes from `(namespace, bytes)`,
    /// and the reader recomputes.
    pub fn address(&self) -> Result<D32, SofiWireError> {
        Ok(immutable_addr(self.namespace(), &self.object_bytes()?))
    }

    /// Where this object is indexed (Part II §11). A setup is indexed twice:
    /// under `ρ`, its identity, and under the relationship index key of
    /// `(G, DevID, v)`, which is how a trader's one setup for a vault is
    /// found without knowing `ρ`.
    pub fn locators(&self) -> Result<Vec<Locator>, SofiWireError> {
        Ok(match self {
            Self::Setup { body, .. } => vec![
                Locator {
                    index_namespace: TAG_DSM_SOFI_SETUP_REF.source_bytes(),
                    locator: derive::setup_ref(body),
                },
                Locator {
                    index_namespace: TAG_DSM_SOFI_REL_INDEX.source_bytes(),
                    locator: derive::relationship_index_key(
                        body.genesis(),
                        body.device_id(),
                        body.vault_id(),
                    ),
                },
            ],
            Self::Precommit { body, .. } => vec![Locator {
                index_namespace: TAG_DSM_SOFI_TRADER_PRECOMMIT_ID.source_bytes(),
                locator: derive::precommit_id(body),
            }],
            Self::Preimage(preimage) => vec![Locator {
                index_namespace: TAG_DSM_SOFI_PREIMAGE_LOCATOR.source_bytes(),
                locator: derive::preimage_locator(&derive::recompute_e(preimage)?),
            }],
            Self::PolicyFulfillment(body) => vec![Locator {
                index_namespace: TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT.source_bytes(),
                locator: derive::policy_fulfillment_id(body),
            }],
            Self::Fulfillment { body, .. } => vec![Locator {
                index_namespace: TAG_DSM_SOFI_FULFILLMENT_ID.source_bytes(),
                locator: derive::fulfillment_id(body),
            }],
        })
    }
}

// ── Recognition: bytes → (identity recomputed from the bytes, object) ───────

/// The body of a signed envelope of `body_class`, with the signature it
/// carries. The decoders are strict — every field fixed or length-checked,
/// and nothing may follow the last one — so bytes that decode are the
/// canonical encoding; there is no second reading to compare against. The
/// envelope's algorithm must be the one the body commits.
fn signed_body<T>(
    bytes: &[u8],
    body_class: u16,
    decode: impl Fn(&[u8]) -> Option<T>,
    alg: impl Fn(&T) -> u16,
) -> Option<Signed<T>> {
    let env = SignedSofiObject::decode(bytes).ok()?;
    if env.body_class() != body_class {
        return None;
    }
    let body = decode(env.body_ccb())?;
    if alg(&body) != env.signature_alg() {
        return None;
    }
    Some(Signed {
        body,
        signature: env.signature().to_vec(),
    })
}

/// A setup envelope; the identity is `ρ` over the body.
pub fn recognize_setup(bytes: &[u8]) -> Option<(D32, Signed<SofiSetupBody>)> {
    let signed = signed_body(
        bytes,
        class::SOFI_SETUP_BODY,
        |b| SofiSetupBody::decode(b).ok(),
        SofiSetupBody::signature_alg,
    )?;
    Some((derive::setup_ref(&signed.body), signed))
}

/// A setup envelope, identified by the relationship index key of the trader
/// and vault it names — the identity a reader scanning that index recomputes.
pub fn recognize_setup_by_relationship(bytes: &[u8]) -> Option<(D32, Signed<SofiSetupBody>)> {
    let (_, signed) = recognize_setup(bytes)?;
    let key = derive::relationship_index_key(
        signed.body.genesis(),
        signed.body.device_id(),
        signed.body.vault_id(),
    );
    Some((key, signed))
}

/// A precommit envelope; the identity is `PrecommitId` over the body.
pub fn recognize_precommit(bytes: &[u8]) -> Option<(D32, Signed<TraderPrecommitBody>)> {
    let signed = signed_body(
        bytes,
        class::SOFI_TRADER_PRECOMMIT_BODY,
        |b| TraderPrecommitBody::decode(b).ok(),
        TraderPrecommitBody::signature_alg,
    )?;
    Some((derive::precommit_id(&signed.body), signed))
}

/// `P(E)`; the identity is `L(E)` over the `E` the bytes recompute.
pub fn recognize_preimage(bytes: &[u8]) -> Option<(D32, SettlementPreimage)> {
    let preimage = SettlementPreimage::decode(bytes).ok()?;
    let e = derive::recompute_e(&preimage).ok()?;
    Some((derive::preimage_locator(&e), preimage))
}

/// `G_j`; the identity is `PolicyFulfillmentId_j` over the body.
pub fn recognize_policy_fulfillment(bytes: &[u8]) -> Option<(D32, DlvPolicyFulfillmentBody)> {
    let body = DlvPolicyFulfillmentBody::decode(bytes).ok()?;
    Some((derive::policy_fulfillment_id(&body), body))
}

/// A fulfillment envelope; the identity is `FulfillmentId` over the body.
pub fn recognize_fulfillment(bytes: &[u8]) -> Option<(D32, Signed<TraderFulfillmentBody>)> {
    let signed = signed_body(
        bytes,
        class::SOFI_TRADER_FULFILLMENT_BODY,
        |b| TraderFulfillmentBody::decode(b).ok(),
        TraderFulfillmentBody::signature_alg,
    )?;
    Some((derive::fulfillment_id(&signed.body), signed))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::sofi::signature::{verify_signed_object, SignedSofiBody};
    use crate::sofi::validation::fixtures::{swap_fixture_n, DEV, G};
    use crate::sofi::wire::{AttemptEntry, PrecommitLeg};

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    const KEY: [u8; 64] = [0x31; 64];
    const SIG: [u8; 8] = [0x77; 8];

    fn setup() -> SofiSetupBody {
        SofiSetupBody::new(G, DEV, 4, d(0x0A), d(0x0B), d(0x0C), ALG, &KEY).unwrap()
    }

    fn fulfillment(p: &TraderPrecommitBody) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            derive::precommit_id(p),
            vec![d(0x01), d(0x02)],
            p.legs()
                .iter()
                .map(|l| AttemptEntry {
                    vault_id: l.vault_id,
                    attempt: 0,
                })
                .collect(),
            p.position() + 1,
            ALG,
            &KEY,
        )
        .unwrap()
    }

    fn witness(p: &TraderPrecommitBody, leg: &PrecommitLeg) -> DlvPolicyFulfillmentBody {
        DlvPolicyFulfillmentBody {
            precommit_id: derive::precommit_id(p),
            external_commitment: *p.external_commitment(),
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            shadow_core: d(0x5D),
        }
    }

    /// Every kind round-trips through its own recognizer with the identity
    /// the reader recomputes from the bytes equal to the locator it is
    /// indexed under.
    #[test]
    fn every_kind_is_recognized_under_the_locator_it_is_indexed_under() {
        let f = swap_fixture_n(2);
        let s = setup();
        let p = f.precommit.clone();
        let g = witness(&p, &p.legs()[0]);
        let fb = fulfillment(&p);

        let setup_pub = Publication::Setup {
            body: &s,
            signature: &SIG,
        };
        let (rho, got) = recognize_setup(&setup_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(got.body, s);
        assert_eq!(got.signature, SIG.to_vec());
        let locs = setup_pub.locators().unwrap();
        assert_eq!(locs[0].locator, rho);
        assert_eq!(rho, derive::setup_ref(&s));
        let (rel, _) = recognize_setup_by_relationship(&setup_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(locs[1].locator, rel);
        assert_eq!(rel, derive::relationship_index_key(&G, &DEV, &d(0x0A)));

        let p_pub = Publication::Precommit {
            body: &p,
            signature: &SIG,
        };
        let (pid, got) = recognize_precommit(&p_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(got.body, p);
        assert_eq!(p_pub.locators().unwrap()[0].locator, pid);
        assert_eq!(pid, derive::precommit_id(&p));

        let pe_pub = Publication::Preimage(&f.preimage);
        let (loc, got) = recognize_preimage(&pe_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(got, f.preimage);
        assert_eq!(pe_pub.locators().unwrap()[0].locator, loc);
        assert_eq!(loc, derive::preimage_locator(p.external_commitment()));

        let g_pub = Publication::PolicyFulfillment(&g);
        let (gid, got) = recognize_policy_fulfillment(&g_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(got, g);
        assert_eq!(g_pub.locators().unwrap()[0].locator, gid);
        assert_eq!(gid, derive::policy_fulfillment_id(&g));

        let f_pub = Publication::Fulfillment {
            body: &fb,
            signature: &SIG,
        };
        let (fid, got) = recognize_fulfillment(&f_pub.object_bytes().unwrap()).unwrap();
        assert_eq!(got.body, fb);
        assert_eq!(f_pub.locators().unwrap()[0].locator, fid);
        assert_eq!(fid, derive::fulfillment_id(&fb));
    }

    /// The namespace is part of the address, one per kind, so the same bytes
    /// under another kind have another address and are never that kind.
    #[test]
    fn each_kind_has_its_own_namespace_and_recognizes_nothing_else() {
        let f = swap_fixture_n(2);
        let s = setup();
        let p = f.precommit.clone();
        let g = witness(&p, &p.legs()[0]);
        let fb = fulfillment(&p);
        let pubs = [
            Publication::Setup {
                body: &s,
                signature: &SIG,
            },
            Publication::Precommit {
                body: &p,
                signature: &SIG,
            },
            Publication::Preimage(&f.preimage),
            Publication::PolicyFulfillment(&g),
            Publication::Fulfillment {
                body: &fb,
                signature: &SIG,
            },
        ];
        let mut namespaces: Vec<&[u8]> =
            pubs.iter().map(|p| p.namespace().source_bytes()).collect();
        namespaces.sort();
        namespaces.dedup();
        assert_eq!(namespaces.len(), pubs.len(), "one namespace per kind");
        for (i, a) in pubs.iter().enumerate() {
            let bytes = a.object_bytes().unwrap();
            // The address changes with the namespace alone.
            for (j, b) in pubs.iter().enumerate() {
                if i != j {
                    assert_ne!(immutable_addr(b.namespace(), &bytes), a.address().unwrap());
                }
            }
            // Every other recognizer refuses these bytes.
            let recognized = [
                recognize_setup(&bytes).is_some(),
                recognize_precommit(&bytes).is_some(),
                recognize_preimage(&bytes).is_some(),
                recognize_policy_fulfillment(&bytes).is_some(),
                recognize_fulfillment(&bytes).is_some(),
            ];
            let expected: Vec<bool> = (0..5).map(|k| k == i).collect();
            assert_eq!(recognized.to_vec(), expected, "kind {i}");
        }
    }

    /// A recognized envelope is not a verified one: the signature travels,
    /// and `verify_signed_object` is what checks it, against the signer the
    /// caller proved. An envelope over non-canonical body bytes, or whose
    /// algorithm disagrees with the body, is not recognized at all.
    #[test]
    fn recognition_is_not_verification_and_refuses_a_non_canonical_envelope() {
        let s = setup();
        let bytes = Publication::Setup {
            body: &s,
            signature: &SIG,
        }
        .object_bytes()
        .unwrap();
        assert!(recognize_setup(&bytes).is_some());
        let env = SignedSofiObject::decode(&bytes).unwrap();
        assert!(matches!(
            verify_signed_object(&env, &KEY),
            Err(crate::sofi::signature::SignatureError::VerifierFailed { .. })
                | Err(crate::sofi::signature::SignatureError::DoesNotVerify { .. })
        ));
        // The setup arm of the verifier decodes the same envelope it refuses
        // to sign off on: the class is carried, not guessed.
        let wrong_signer = [0x32; 64];
        assert!(matches!(
            verify_signed_object(&env, &wrong_signer),
            Err(crate::sofi::signature::SignatureError::NotTheExpectedSigner { .. })
        ));
        // A body padded with a trailing byte does not decode: the decoders
        // are strict, which is what makes decoded bytes canonical.
        let mut padded = s.encode();
        padded.push(0);
        let env = SignedSofiObject::new(class::SOFI_SETUP_BODY, &padded, ALG, &SIG).unwrap();
        assert!(recognize_setup(&env.encode()).is_none());
        // An envelope whose algorithm is not the one the body commits. The
        // constructor refuses an undeclared algorithm, so this arrives only
        // as hostile bytes: the field sits after the 4-byte class envelope,
        // the 2-byte body class, the 4-byte length and the body.
        let mut hostile = bytes.clone();
        let alg_at = 4 + 2 + 4 + s.encode().len();
        assert_eq!(&hostile[alg_at..alg_at + 2], &ALG.to_be_bytes());
        hostile[alg_at..alg_at + 2].copy_from_slice(&0x0002u16.to_be_bytes());
        assert!(
            SignedSofiObject::decode(&hostile).is_ok(),
            "the envelope itself parses"
        );
        assert!(recognize_setup(&hostile).is_none());
        let _ = SignedSofiBody::Setup(s);
    }
}
