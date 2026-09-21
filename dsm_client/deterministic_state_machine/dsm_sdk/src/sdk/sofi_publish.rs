// SPDX-License-Identifier: Apache-2.0

//! Part II §10 to §12, rebuild step R8: publish the objects a producer hands
//! back, and fetch them back by locator.
//!
//! Publishing is three member operations and one read: put the exact bytes
//! under their kind's namespace at every member, append the address under
//! each locator Core assigns to the kind, then read the object back and let
//! Core derive `Stored` from the raw answers. The fanout's own accounting is
//! never the fact: a producer that needs `Stored` — `SetupRegistered`, and
//! "each put and `Stored`" at stage 4 — gets it from what the members
//! return, exactly as a verifier will.
//!
//! Fetching is Part II §11 as Core states it: every candidate under the
//! locator is fetched, its identity recomputed from the bytes by the kind's
//! recognizer, and the one whose identity is the locator is kept. What a
//! member appended proves nothing by itself.

use dsm::common::domain_tags::{
    TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT, TAG_DSM_SOFI_FULFILLMENT_ID,
    TAG_DSM_SOFI_FULFILLMENT_OBJECT, TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT,
    TAG_DSM_SOFI_PRECOMMIT_OBJECT, TAG_DSM_SOFI_PREIMAGE_LOCATOR, TAG_DSM_SOFI_PREIMAGE_OBJECT,
    TAG_DSM_SOFI_REL_INDEX, TAG_DSM_SOFI_SETUP_OBJECT, TAG_DSM_SOFI_SETUP_REF,
    TAG_DSM_SOFI_TRADER_PRECOMMIT_ID,
};
use dsm::crypto::domain::TaggedHashDomain;
use dsm::sofi::derive;
use dsm::sofi::publication::{
    recognize_fulfillment, recognize_policy_fulfillment, recognize_precommit, recognize_preimage,
    recognize_setup, recognize_setup_by_relationship, Locator, Publication, Signed,
};
use dsm::sofi::storage::Resolved;
use dsm::sofi::wire::{
    DlvPolicyFulfillmentBody, SettlementPreimage, SofiSetupBody, TraderFulfillmentBody,
    TraderPrecommitBody,
};
use dsm::types::error::DsmError;

use crate::sdk::sofi_evidence::LOCATOR_BUDGET;
use crate::sdk::sofi_sdk::{Produced, ToPublish};
use crate::sdk::storage_io::{
    append_to_index, put_immutable_to_all_members, read_stored_bytes, resolve_locator,
};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

fn wire_err(e: impl core::fmt::Display) -> DsmError {
    DsmError::verification(format!("sofi publication: {e}"))
}

/// What publishing one object established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The content address the members computed and the reader recomputes.
    pub addr: D32,
    /// `Stored(o)`, read back from the members after the put.
    pub stored: bool,
    /// Each locator the address was appended under, with the number of
    /// members that took the append.
    pub indexed: Vec<(Locator, u32)>,
}

/// Put `object` at every member, index it under every locator of its kind,
/// and read `Stored` back.
pub async fn publish(set: &StorageSet, object: &Publication<'_>) -> Result<Published, DsmError> {
    let bytes = object.object_bytes().map_err(wire_err)?;
    let namespace = object.namespace();
    let addr = dsm::storage_object::immutable_addr(namespace, &bytes);
    let namespace_str = String::from_utf8_lossy(namespace.source_bytes()).into_owned();
    let addr_b32 = crate::util::text_id::encode_base32_crockford(&addr);
    let _ = put_immutable_to_all_members(set, &namespace_str, &bytes, &addr_b32).await?;
    let mut indexed = Vec::new();
    for locator in object.locators().map_err(wire_err)? {
        let took = append_to_index(set, locator.index_namespace, &locator.locator, &addr).await?;
        indexed.push((locator, took));
    }
    // The fact, from the members' answers — never from the fanout.
    let stored = read_stored_bytes(set, &addr).await?.is_some();
    Ok(Published {
        addr,
        stored,
        indexed,
    })
}

/// Publish everything a produced operation hands back. `operation_signature`
/// is the signature the caller made over `produced.signs`; it completes the
/// envelope of the kind that signs through the operation — the setup's
/// `m_setup`, the fulfillment's `m_F`. Nothing is published before that
/// signature exists, because the object a member stores is the signed one.
pub async fn publish_produced(
    set: &StorageSet,
    produced: &Produced,
    operation_signature: &[u8],
) -> Result<Vec<Published>, DsmError> {
    let mut out = Vec::with_capacity(produced.publish.len());
    for item in &produced.publish {
        let publication = match item {
            ToPublish::Setup(body) => Publication::Setup {
                body,
                signature: operation_signature,
            },
            ToPublish::Precommit(signed) => Publication::Precommit {
                body: &signed.body,
                signature: &signed.signature,
            },
            ToPublish::Preimage(preimage) => Publication::Preimage(preimage),
            ToPublish::PolicyFulfillment(body) => Publication::PolicyFulfillment(body),
            ToPublish::Fulfillment(body) => Publication::Fulfillment {
                body,
                signature: operation_signature,
            },
        };
        out.push(publish(set, &publication).await?);
    }
    Ok(out)
}

async fn fetch<T>(
    set: &StorageSet,
    index_namespace: &[u8],
    object_namespace: TaggedHashDomain<'_>,
    locator: &D32,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Result<Resolved<T>, DsmError> {
    resolve_locator(
        set,
        index_namespace,
        object_namespace,
        locator,
        LOCATOR_BUDGET,
        recognize,
    )
    .await
}

/// The setup at `ρ`: `Kept` once its envelope is `Stored` and re-derives `ρ`.
pub async fn fetch_setup(
    set: &StorageSet,
    setup_ref: &D32,
) -> Result<Resolved<Signed<SofiSetupBody>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_SETUP_REF.source_bytes(),
        TAG_DSM_SOFI_SETUP_OBJECT,
        setup_ref,
        recognize_setup,
    )
    .await
}

/// The one setup of trader `(G, DevID)` for vault `v`, by the relationship
/// index key.
pub async fn fetch_setup_for(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    vault_id: &D32,
) -> Result<Resolved<Signed<SofiSetupBody>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_REL_INDEX.source_bytes(),
        TAG_DSM_SOFI_SETUP_OBJECT,
        &derive::relationship_index_key(genesis, device_id, vault_id),
        recognize_setup_by_relationship,
    )
    .await
}

/// `P` by `PrecommitId`, with the signature its envelope carries.
pub async fn fetch_precommit(
    set: &StorageSet,
    precommit_id: &D32,
) -> Result<Resolved<Signed<TraderPrecommitBody>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_TRADER_PRECOMMIT_ID.source_bytes(),
        TAG_DSM_SOFI_PRECOMMIT_OBJECT,
        precommit_id,
        recognize_precommit,
    )
    .await
}

/// `P(E)` by `E`: the one preimage under `L(E)` that recomputes `E`.
pub async fn fetch_preimage(
    set: &StorageSet,
    external_commitment: &D32,
) -> Result<Resolved<SettlementPreimage>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_PREIMAGE_LOCATOR.source_bytes(),
        TAG_DSM_SOFI_PREIMAGE_OBJECT,
        &derive::preimage_locator(external_commitment),
        recognize_preimage,
    )
    .await
}

/// `G_j` by `PolicyFulfillmentId_j`.
pub async fn fetch_policy_fulfillment(
    set: &StorageSet,
    policy_fulfillment_id: &D32,
) -> Result<Resolved<DlvPolicyFulfillmentBody>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_DLV_POLICY_FULFILLMENT.source_bytes(),
        TAG_DSM_SOFI_POLICY_FULFILLMENT_OBJECT,
        policy_fulfillment_id,
        recognize_policy_fulfillment,
    )
    .await
}

/// `F` by `FulfillmentId`, with the signature its envelope carries.
pub async fn fetch_fulfillment(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<Resolved<Signed<TraderFulfillmentBody>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_FULFILLMENT_ID.source_bytes(),
        TAG_DSM_SOFI_FULFILLMENT_OBJECT,
        fulfillment_id,
        recognize_fulfillment,
    )
    .await
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;

    use dsm::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use dsm::sofi::conformance::{
        fulfillment_conformance, ConformanceEvidence, ConformanceMissing, FulfillmentConformance,
    };
    use dsm::sofi::signature::{verify_fulfillment, verify_setup, SigningPayload};
    use dsm::types::operations::Operation;
    use serial_test::serial;

    use super::*;
    use crate::sdk::sofi_sdk::{build_fulfillment, draft_route};
    use crate::sdk::sofi_test_fixtures::{all_policies, five, RouteFixture};
    use crate::sdk::storage_io::fake_fleet;

    fn d(byte: u8) -> D32 {
        [byte; 32]
    }

    fn keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        KEYS.get_or_init(|| generate_sphincs_keypair().unwrap())
    }

    fn sign(message: &[u8]) -> Vec<u8> {
        sphincs_sign(&keys().1, message).unwrap()
    }

    fn block_on<T>(f: impl core::future::Future<Output = T>) -> T {
        crate::runtime::get_runtime().block_on(f)
    }

    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];
    const VAULT: D32 = [0x0A; 32];

    fn setup_body() -> SofiSetupBody {
        SofiSetupBody::new(G, DEV, 4, VAULT, d(0x0B), d(0x0C), ALG, &keys().0).unwrap()
    }

    /// What `build_setup` hands back, without its predecessor context: the
    /// operation, `m_setup`, and the body to publish once signed.
    fn produced_setup(body: &SofiSetupBody) -> Produced {
        Produced {
            operation: Operation::SofiSetup {
                setup_body: body.encode(),
                signature: Vec::new(),
            },
            signs: SigningPayload::SetupDigest(derive::setup_signing_digest(body)),
            publish: vec![ToPublish::Setup(body.clone())],
        }
    }

    fn no_conformance_evidence() -> ConformanceEvidence {
        ConformanceEvidence {
            precommit: None,
            preimage: None,
            closure: BTreeMap::new(),
            setups: BTreeMap::new(),
            prior_attempts: BTreeMap::new(),
        }
    }

    /// Part II §29 step 2: the setup body is put as an object and indexed
    /// under ρ (and the relationship index key); `SetupRegistered` holds once
    /// it is `Stored`, read back from the members. What is fetched is the
    /// envelope, and the setup's own rule verifies it.
    #[test]
    #[serial]
    fn a_setup_is_published_indexed_and_stored() {
        fake_fleet::reset();
        let set = five();
        let body = setup_body();
        let sig = sign(&derive::setup_signing_digest(&body));
        let published = block_on(publish_produced(&set, &produced_setup(&body), &sig)).unwrap();
        assert_eq!(published.len(), 1);
        let one = &published[0];
        assert!(
            one.stored,
            "SetupRegistered: three members return the exact bytes"
        );
        assert_eq!(
            one.indexed.len(),
            2,
            "under ρ and under the relationship index key"
        );
        assert!(one.indexed.iter().all(|(_, took)| *took == 5));
        let rho = derive::setup_ref(&body);
        assert_eq!(one.indexed[0].0.locator, rho);
        assert_eq!(
            one.indexed[1].0.locator,
            derive::relationship_index_key(&G, &DEV, &VAULT)
        );

        let by_ref = block_on(fetch_setup(&set, &rho)).unwrap();
        let by_relationship = block_on(fetch_setup_for(&set, &G, &DEV, &VAULT)).unwrap();
        let expected = Signed {
            body: body.clone(),
            signature: sig.clone(),
        };
        assert_eq!(by_ref, Resolved::Kept(expected.clone()));
        assert_eq!(by_relationship, Resolved::Kept(expected));
        let Resolved::Kept(fetched) = by_ref else {
            unreachable!()
        };
        assert_eq!(
            verify_setup(&fetched.body, &fetched.signature, &keys().0),
            Ok(())
        );
        // Another trader's vault, another locator: nothing there.
        assert_eq!(
            block_on(fetch_setup_for(&set, &G, &DEV, &d(0x0F))).unwrap(),
            Resolved::None
        );
    }

    /// Stages 4 and 5 of §31, then F: everything `build_fulfillment` hands
    /// back is put, indexed under the locator Part II §11 assigns to its
    /// kind, `Stored`, and found again with its identity recomputed from
    /// the bytes. The fetched P and P(E) are what conformance (R7) reads:
    /// over them alone the predicate waits on exactly the setups, which this
    /// operation never published.
    #[test]
    #[serial]
    fn everything_a_fulfillment_publishes_is_found_by_its_locator() {
        fake_fleet::reset();
        let set = five();
        let fx = RouteFixture::swap(2, set.id());
        fx.publish(&set, &all_policies());
        let evidence = fx.acquire(&set);
        let draft = draft_route(
            fx.hops.clone(),
            fx.cores.clone(),
            &fx.ctx(&keys().0),
            fx.realize_root,
            fx.void_root,
            &evidence,
        )
        .unwrap();
        let p_sig = sign(&draft.precommit_signing_digest());
        let attempts: Vec<(D32, u64)> = draft
            .precommit()
            .legs()
            .iter()
            .map(|l| (l.vault_id, 0))
            .collect();
        let produced = build_fulfillment(&draft, p_sig.clone(), &attempts).unwrap();
        let f_sig = sign(produced.signs.bytes());
        let published = block_on(publish_produced(&set, &produced, &f_sig)).unwrap();
        assert_eq!(published.len(), 2 + 2 + 1, "P, P(E), two G_j, F");
        assert!(published.iter().all(|p| p.stored), "each put and Stored");

        let precommit = draft.precommit().clone();
        let pid = derive::precommit_id(&precommit);
        assert_eq!(
            block_on(fetch_precommit(&set, &pid)).unwrap(),
            Resolved::Kept(Signed {
                body: precommit.clone(),
                signature: p_sig,
            })
        );
        assert_eq!(
            block_on(fetch_preimage(&set, precommit.external_commitment())).unwrap(),
            Resolved::Kept(draft.preimage().clone())
        );
        let mut fulfillment = None;
        for item in &produced.publish {
            match item {
                ToPublish::PolicyFulfillment(g) => {
                    let gid = derive::policy_fulfillment_id(g);
                    assert_eq!(
                        block_on(fetch_policy_fulfillment(&set, &gid)).unwrap(),
                        Resolved::Kept(*g)
                    );
                }
                ToPublish::Fulfillment(f) => fulfillment = Some(f.clone()),
                _ => {}
            }
        }
        let f = fulfillment.expect("F is published once m_F is signed");
        let fetched_f = block_on(fetch_fulfillment(&set, &derive::fulfillment_id(&f))).unwrap();
        assert_eq!(
            fetched_f,
            Resolved::Kept(Signed {
                body: f.clone(),
                signature: f_sig.clone(),
            })
        );
        assert_eq!(verify_fulfillment(&f, &f_sig, &keys().0), Ok(()));

        // Conformance over what was fetched, and nothing else.
        let Resolved::Kept(fetched_p) = block_on(fetch_precommit(&set, &pid)).unwrap() else {
            unreachable!()
        };
        let Resolved::Kept(fetched_pe) =
            block_on(fetch_preimage(&set, precommit.external_commitment())).unwrap()
        else {
            unreachable!()
        };
        let mut ev = no_conformance_evidence();
        ev.precommit = Some(fetched_p);
        ev.preimage = Some(fetched_pe);
        assert_eq!(
            fulfillment_conformance(&f, &f_sig, &ev),
            FulfillmentConformance::Unavailable(ConformanceMissing::Setup {
                setup_ref: precommit.legs()[0].setup_ref,
            }),
            "items 1 to 4, 7 and 8 hold over the fetched objects; the setups were never published"
        );
        assert_eq!(
            fulfillment_conformance(&f, &f_sig, &no_conformance_evidence()),
            FulfillmentConformance::Unavailable(ConformanceMissing::Precommit)
        );
    }

    /// Lean `unindexed_is_not_found`: an object put at every member but
    /// appended under no locator is `Stored` and unreachable — a locator is
    /// the only way in.
    #[test]
    #[serial]
    fn an_object_put_without_its_index_is_not_found() {
        fake_fleet::reset();
        let set = five();
        let body = setup_body();
        let publication = Publication::Setup {
            body: &body,
            signature: &[0x5E; 8],
        };
        let bytes = publication.object_bytes().unwrap();
        let addr = fake_fleet::put_object(&set, publication.namespace(), &bytes);
        assert_eq!(
            block_on(read_stored_bytes(&set, &addr)).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            block_on(fetch_setup(&set, &derive::setup_ref(&body))).unwrap(),
            Resolved::None
        );
    }

    /// Lean `published_is_found_past_foreign_candidates`: anyone may append
    /// anything under a locator; a candidate whose recomputed identity is not
    /// the locator is examined and passed over, and the published object is
    /// what the reader keeps.
    #[test]
    #[serial]
    fn a_foreign_candidate_under_the_locator_is_never_kept() {
        fake_fleet::reset();
        let set = five();
        let body = setup_body();
        let rho = derive::setup_ref(&body);
        // Another setup — Stored, well formed, and not this one — appended
        // first under ρ, then garbage that is not an object at all.
        let other =
            SofiSetupBody::new(G, DEV, 9, d(0x0D), d(0x0B), d(0x0C), ALG, &keys().0).unwrap();
        let other_pub = Publication::Setup {
            body: &other,
            signature: &[0x5E; 8],
        };
        let other_addr = fake_fleet::put_object(
            &set,
            other_pub.namespace(),
            &other_pub.object_bytes().unwrap(),
        );
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_SETUP_REF.source_bytes(),
            &rho,
            &other_addr,
        );
        let garbage_addr =
            fake_fleet::put_object(&set, TAG_DSM_SOFI_SETUP_OBJECT, b"not an envelope");
        fake_fleet::append_index(
            &set,
            TAG_DSM_SOFI_SETUP_REF.source_bytes(),
            &rho,
            &garbage_addr,
        );
        assert_eq!(block_on(fetch_setup(&set, &rho)).unwrap(), Resolved::None);

        let sig = sign(&derive::setup_signing_digest(&body));
        block_on(publish(
            &set,
            &Publication::Setup {
                body: &body,
                signature: &sig,
            },
        ))
        .unwrap();
        assert_eq!(
            block_on(fetch_setup(&set, &rho)).unwrap(),
            Resolved::Kept(Signed {
                body,
                signature: sig
            })
        );
    }

    /// `Stored` is what the members return, never what the fanout reports:
    /// with three members down the put reaches two, and the fact is false.
    #[test]
    #[serial]
    fn stored_is_read_back_from_the_members_not_inferred_from_the_put() {
        fake_fleet::reset();
        let set = five();
        let body = setup_body();
        let sig = sign(&derive::setup_signing_digest(&body));
        for m in ["m1", "m2", "m3"] {
            fake_fleet::fail_member(m);
        }
        let published = block_on(publish_produced(&set, &produced_setup(&body), &sig)).unwrap();
        assert!(!published[0].stored, "two members are not Stored");
        assert_eq!(
            block_on(fetch_setup(&set, &derive::setup_ref(&body))).unwrap(),
            Resolved::None,
            "the index reached two members too; nothing under it is Stored"
        );
        fake_fleet::heal_member("m3");
        let published = block_on(publish_produced(&set, &produced_setup(&body), &sig)).unwrap();
        assert!(published[0].stored, "the third copy makes the fact");
    }
}
