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
    TAG_DSM_SOFI_PREIMAGE_LOCATOR, TAG_DSM_SOFI_REL_INDEX, TAG_DSM_SOFI_SETUP_REF,
    TAG_DSM_SOFI_TRADER_PRECOMMIT_ID,
};
use dsm::sofi::derive;
use dsm::sofi::publication::{
    recognize_fulfillment, recognize_policy_fulfillment, recognize_precommit, recognize_preimage,
    recognize_setup, recognize_setup_by_relationship, Locator, Publication, Signed,
};
use dsm::sofi::storage::{Discovered, Resolved};
use dsm::sofi::wire::{
    DlvPolicyFulfillmentBody, SettlementPreimage, SofiSetupBody, TraderFulfillmentBody,
    TraderPrecommitBody,
};
use dsm::types::error::DsmError;

use crate::sdk::sofi_evidence::LOCATOR_BUDGET;
use crate::sdk::sofi_sdk::{Produced, ToPublish};
use crate::sdk::storage_io::{
    append_to_index, put_immutable, read_stored_bytes, resolve_locator, resolve_locator_all,
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
    let (addr, ..) = put_immutable(set, object.namespace(), &bytes).await?;
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
    locator: &D32,
    recognize: impl Fn(&[u8]) -> Option<(D32, T)>,
) -> Result<Resolved<T>, DsmError> {
    resolve_locator(set, index_namespace, locator, LOCATOR_BUDGET, recognize).await
}

/// The setup at `ρ`: `Kept` once its envelope is `Stored` and re-derives `ρ`.
pub async fn fetch_setup(
    set: &StorageSet,
    setup_ref: &D32,
) -> Result<Resolved<Signed<SofiSetupBody>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_SETUP_REF.source_bytes(),
        setup_ref,
        recognize_setup,
    )
    .await
}

/// The exact `Stored` envelope bytes of the setup at `ρ`: what `SetupValid`
/// and conformance item 6 are decided over.
pub async fn fetch_setup_bytes(
    set: &StorageSet,
    setup_ref: &D32,
) -> Result<Resolved<Vec<u8>>, DsmError> {
    fetch(
        set,
        TAG_DSM_SOFI_SETUP_REF.source_bytes(),
        setup_ref,
        |bytes| recognize_setup(bytes).map(|(rho, ..)| (rho, bytes.to_vec())),
    )
    .await
}

/// DISCOVERY of the setups trader `(G, DevID)` published for vault `v`, by
/// the relationship index key: every recognized setup envelope whose body
/// names that relationship, in append order.
///
/// The relationship index is references, never authority. A trader has one
/// setup per vault by construction — the relationship leaf is inserted from
/// absent exactly once in the trader's own tree, and the producer refuses a
/// second — but nothing stops a trader from PUBLISHING more than one body
/// (one never admitted, one built later at another `p`), and the index holds
/// them all. Which one applies is Core's question, answered by `ρ`: the
/// reference a precommit leg names and conformance checks (`fetch_setup`),
/// never by which arrived first here.
pub async fn fetch_setup_for(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    vault_id: &D32,
) -> Result<Discovered<Signed<SofiSetupBody>>, DsmError> {
    resolve_locator_all(
        set,
        TAG_DSM_SOFI_REL_INDEX.source_bytes(),
        &derive::relationship_index_key(genesis, device_id, vault_id),
        LOCATOR_BUDGET,
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
        fulfillment_id,
        recognize_fulfillment,
    )
    .await
}
