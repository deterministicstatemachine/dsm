// SPDX-License-Identifier: Apache-2.0
//! Stages 6 to 8 and 10 of §31, rebuild step R13: the fulfillment through the
//! one Core transition, and the resolved position into the validated lineage
//! through `advance_resolved`.
//!
//! `SofiFulfill` (36) rides the generalized admission seam like every other
//! value-bearing operation: a `SofiFulfillment` admission is prepared for
//! position `q`, attached to the head, and `DeviceState::advance` refuses the
//! operation without it. That admission is the fence: it engages the moment
//! local acceptance is durable and stands until the route resolves — it is
//! not finished by this device's own action (there is no witness to freeze
//! and no root to register) but by facts that arrive at storage, which
//! [`resolve_pending_position`] reads. While it stands, nothing descends
//! from `q` and no economic write advances.
//!
//! What resolution installs comes from Core alone: the ladder's answer over
//! raw reads (R12), and `advance_resolved`, which recomputes `C_q` from `P`
//! and `F` and never reads it out of a register, checks the parent claim
//! against the one this device itself registered at `p`, and selects the
//! root — `P.R_realize` for Realized, the predecessor's for Void. The leaves
//! that form the installed root are recomputed by Core too
//! (`trader_post_states`) and bound to the values `T°` states; the cache is
//! written only once it recomputes exactly that root.
use std::collections::BTreeMap;

use dsm::economic::admission::{
    dsm_operation_digest, AcceptedAdmissionCoords, PendingAdmissionKind, PendingEconomicAdmission,
};
use dsm::economic::lineage::{AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::economic::register::position_seed;
use dsm::economic::state::EconomicLeafState;
use dsm::economic::tree::EconomicSmt;
use dsm::sofi::arith::{resolve_objects, ObjectResolution};
use dsm::sofi::derive;
use dsm::sofi::lineage::{advance_resolved, descendant_fence, RegisteredClaims};
use dsm::sofi::publication::Publication;
use dsm::sofi::registration::Registration;
use dsm::sofi::resolution::{ParentPosition, PositionEffect, Resolution};
use dsm::sofi::storage::Resolved;
use dsm::sofi::validation::{trader_post_states, vault_post_states};
use dsm::sofi::wire::{
    next_position, ParentClaimRef, SettlementPreimage, TraderFulfillmentBody, TraderPrecommitBody,
    ValidationRef,
};
use dsm::types::device_state::RelationshipChainState;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::validated_root_or_activate;
use crate::sdk::economic_registers::{economic_root_namespace, names_root_key};
use crate::sdk::sofi_evidence::{acquire_evidence, LocalLeaves};
use crate::sdk::sofi_exercise::{build_exercise, read_attempt_cell, write_exercise, LegWrite};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_preimage};
use crate::sdk::sofi_register::{
    acquire_conformance_evidence, install_fulfillment, read_registration, InstallRequest, Installed,
};
use crate::sdk::sofi_chain::ChainWalker;
use dsm::sofi::resolution::VaultChain;
use crate::sdk::sofi_resolve::{Resolver, WALK_BUDGET};
use crate::sdk::storage_io::{leader_index, read_cell_raw};
use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::economic_lineage;

type D32 = [u8; 32];

fn refuse(what: impl std::fmt::Display) -> DsmError {
    DsmError::invalid_operation(format!("sofi advance: {what}"))
}

fn storage(what: &str, e: impl std::fmt::Display) -> DsmError {
    DsmError::storage(format!("sofi advance: {what}: {e}"), None::<std::io::Error>)
}

/// What the trader holds once `build_fulfillment` returned and `m_P` and
/// `m_F` are signed: the objects `publish_produced` published, and the exact
/// bytes it alone holds for the closure references that are its own.
#[derive(Debug, Clone, Copy)]
pub struct FulfillRequest<'a> {
    pub precommit: &'a TraderPrecommitBody,
    pub precommit_signature: &'a [u8],
    pub preimage: &'a SettlementPreimage,
    pub fulfillment: &'a TraderFulfillmentBody,
    pub fulfillment_signature: &'a [u8],
    pub own_objects: &'a BTreeMap<ValidationRef, Vec<u8>>,
}

/// The fulfillment's transition and install.
#[derive(Debug, Clone)]
pub struct Fulfilled {
    /// `q`, the position the fulfillment holds under its conditional claim.
    pub position: u64,
    pub fulfillment_id: D32,
    /// Stage 7: the pair at the leader of `s(q)` (R9).
    pub installed: Installed,
}

/// Stages 7 and 8, run again from what storage holds.
#[derive(Debug, Clone)]
pub struct Completed {
    pub position: u64,
    pub fulfillment_id: D32,
    pub installed: Installed,
    /// Stage 8: the exercise at every leg's key (R11).
    pub exercise: Vec<LegWrite>,
}

/// The acceptance coordinates of a fulfillment's admission: what the durable
/// pending row carries for a position whose claim is CONDITIONAL.
///
/// A resolved position's root enters the lineage through `advance_resolved`
/// and nowhere else, so until then the device's economic root is the
/// predecessor's — the root Void keeps and Realized leaves for `R_realize`.
/// That is what `post_economic_root` records here; nothing about it is a
/// selection. The accepted substrate is `F`'s own published object and the
/// manifest of what the position commits is `P`'s: both are content
/// addresses a verifier fetches (R8), not something this device asserts.
fn fulfillment_acceptance_coords(
    chain_state: &RelationshipChainState,
    predecessor_root: D32,
    fulfillment_addr: D32,
    precommit_addr: D32,
) -> AcceptedAdmissionCoords {
    AcceptedAdmissionCoords {
        post_economic_root: predecessor_root,
        accepted_substrate_addr: fulfillment_addr,
        admission_manifest_addr: precommit_addr,
        c_dsm_plus: chain_state.compute_chain_tip(),
        embedded_parent: chain_state.embedded_parent,
    }
}

/// Stage 6 of §31: the trader's transition carrying `SofiFulfill` through the
/// one Core transition, then stage 7, the install. The head advances with a
/// `SofiFulfillment` admission at `q` that fences the lineage until the route
/// resolves; stage 8, the exercise, is any party's
/// ([`complete_pending_fulfillment`] does it for this device).
///
/// Refused before anything is written unless `P` is built on exactly this
/// device's validated predecessor — its position and root — and names this
/// device. A failure AFTER the advance (a member unreachable at install)
/// leaves the position fenced and durable; [`complete_pending_fulfillment`]
/// finishes stages 7 and 8 from what storage holds.
pub async fn fulfill(
    core: &CoreSDK,
    set: &StorageSet,
    request: &FulfillRequest<'_>,
) -> Result<Fulfilled, DsmError> {
    let precommit = request.precommit;
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    if let Some(pending) = head.pending_economic_admission() {
        return Err(refuse(format!(
            "a pending admission stands at position {}; finish or resolve it first",
            pending.economic_position
        )));
    }
    if *precommit.genesis() != head.genesis_digest() || *precommit.device_id() != head.devid() {
        return Err(refuse(
            "P names another trader than the device whose head advances",
        ));
    }
    // Stage 0: the predecessor is resolved (the fence is inside this read),
    // and P was built on exactly it.
    let validated = validated_root_or_activate(core)?;
    if precommit.position() != validated.economic_position()
        || *precommit.void_root() != validated.economic_root()
    {
        return Err(refuse(format!(
            "P is built on position {} at another root; the validated predecessor is position {}",
            precommit.position(),
            validated.economic_position()
        )));
    }
    let q = next_position(precommit.position()).map_err(refuse)?;
    if request.fulfillment.position() != q
        || *request.fulfillment.precommit_id() != derive::precommit_id(precommit)
    {
        return Err(refuse("F is not this P's fulfillment at p + 1"));
    }
    let fulfillment_id = derive::fulfillment_id(request.fulfillment);
    let operation = Operation::SofiFulfill {
        fulfillment_body: request.fulfillment.encode(),
        precommit_id: derive::precommit_id(precommit).to_vec(),
        signature: request.fulfillment_signature.to_vec(),
    };
    let prepared = PendingEconomicAdmission::prepared(
        PendingAdmissionKind::SofiFulfillment { fulfillment_id },
        q,
        validated.economic_root(),
        dsm_operation_digest(&operation.to_bytes()),
    );
    let fulfillment_addr = Publication::Fulfillment {
        body: request.fulfillment,
        signature: request.fulfillment_signature,
    }
    .address()
    .map_err(refuse)?;
    let precommit_addr = Publication::Precommit {
        body: precommit,
        signature: request.precommit_signature,
    }
    .address()
    .map_err(refuse)?;
    let predecessor_root = validated.economic_root();
    // The transition: no balance delta — the claim it installs is
    // conditional, and the root a resolution selects enters through
    // `advance_resolved` (stage 10), never here.
    core.admitted_advance(
        operation,
        &[],
        prepared,
        |chain_state| {
            Ok((
                fulfillment_acceptance_coords(
                    chain_state,
                    predecessor_root,
                    fulfillment_addr,
                    precommit_addr,
                ),
                Vec::new(),
            ))
        },
        &set.id(),
        None,
    )?;
    let installed = install_pair(set, request).await?;
    Ok(Fulfilled {
        position: q,
        fulfillment_id,
        installed,
    })
}

fn install_request<'a>(request: &FulfillRequest<'a>) -> InstallRequest<'a> {
    InstallRequest {
        precommit: request.precommit,
        precommit_signature: request.precommit_signature,
        preimage: request.preimage,
        fulfillment: request.fulfillment,
        fulfillment_signature: request.fulfillment_signature,
        own_objects: request.own_objects,
    }
}

/// Stage 7: the pair at `s(q)`, conformance first (R9). Idempotent at the
/// members, which keep what they are given.
async fn install_pair(
    set: &StorageSet,
    request: &FulfillRequest<'_>,
) -> Result<Installed, DsmError> {
    install_fulfillment(set, &install_request(request))
        .await
        .map_err(|e| refuse(format!("install: {e:?}")))
}

/// Stage 8: the exercise, built over the evidence its conformance was
/// decided on, at every leg's key (R11).
async fn exercise_legs(
    set: &StorageSet,
    request: &FulfillRequest<'_>,
) -> Result<Vec<LegWrite>, DsmError> {
    let install = install_request(request);
    let evidence = acquire_conformance_evidence(set, &install).await?;
    let exercise = build_exercise(&install, &evidence)?;
    let recognized = dsm::sofi::exercise::recognize_exercise(&exercise.encode())
        .ok_or_else(|| refuse("the exercise built here does not recognize"))?;
    write_exercise(set, &exercise, &recognized).await
}

/// The pending fulfillment admission on the head, or why there is none.
fn pending_fulfillment(core: &CoreSDK) -> Result<(PendingEconomicAdmission, D32), DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    let pending = head
        .pending_economic_admission()
        .cloned()
        .ok_or_else(|| refuse("no pending admission: nothing to resolve"))?;
    match pending.kind {
        PendingAdmissionKind::SofiFulfillment { fulfillment_id } => Ok((pending, fulfillment_id)),
        _ => Err(refuse(format!(
            "the pending admission at position {} is not a SoFi fulfillment",
            pending.economic_position
        ))),
    }
}

/// The closure objects only this trader holds exactly, from its own durable
/// state: the claim envelope it registered at `p` for a `SingleRootClaim`
/// naming that claim; a `ConditionalClaim` is the final bytes at `K_root` of
/// the position it names, which are storage's.
async fn own_closure_objects(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
) -> Result<BTreeMap<ValidationRef, Vec<u8>>, DsmError> {
    let mut own = BTreeMap::new();
    for reference in preimage.settlement().closure().refs() {
        match reference {
            ValidationRef::SingleRootClaim { claim_ref } => {
                if let Some((_, bytes)) =
                    economic_lineage::get_frozen_root_claim(precommit.position())
                        .map_err(|e| storage("frozen root claim", e))?
                {
                    if derive::claim_ref(&bytes) == *claim_ref {
                        own.insert(*reference, bytes);
                    }
                }
            }
            ValidationRef::ConditionalClaim {
                genesis,
                device_id,
                position,
                ..
            } => {
                if let Some(bytes) =
                    final_root_cell(set, genesis, device_id, *position, precommit.void_root())
                        .await?
                {
                    own.insert(*reference, bytes);
                }
            }
            ValidationRef::ContentAddr { .. } | ValidationRef::Setup { .. } => {}
        }
    }
    Ok(own)
}

/// The final bytes at `K_root(position)` of `(genesis, device_id)`, the
/// leader drawn from the seed over `parent_root`; `None` while nothing is
/// final there.
async fn final_root_cell(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    parent_root: &D32,
) -> Result<Option<Vec<u8>>, DsmError> {
    let k_root = dsm::economic::register::economic_root_register_key(genesis, device_id, position);
    let seed = position_seed(genesis, device_id, position, parent_root);
    let leader = leader_index(set, &seed)?;
    let reads = read_cell_raw(set, economic_root_namespace(), &k_root).await?;
    let resolved = resolve_objects(&reads, leader, |bytes| names_root_key(bytes, &k_root))
        .map_err(|e| storage("root cell", e))?;
    Ok(match resolved {
        ObjectResolution::Final(bytes) => Some(bytes),
        ObjectResolution::LeaderHeld(_)
        | ObjectResolution::Open
        | ObjectResolution::Unavailable => None,
    })
}

/// The registered `F`, its `P` and `P(E)` for the pending position, from
/// storage: what a restarted device needs to finish or resolve without
/// having kept anything but the admission.
async fn pending_objects(
    set: &StorageSet,
    core: &CoreSDK,
) -> Result<
    (
        PendingEconomicAdmission,
        dsm::sofi::publication::Signed<TraderFulfillmentBody>,
        dsm::sofi::publication::Signed<TraderPrecommitBody>,
        SettlementPreimage,
    ),
    DsmError,
> {
    let (pending, fulfillment_id) = pending_fulfillment(core)?;
    let Resolved::Kept(fulfillment) = fetch_fulfillment(set, &fulfillment_id).await? else {
        return Err(refuse(
            "the pending fulfillment is not Stored; nothing to finish from",
        ));
    };
    let Resolved::Kept(precommit) = fetch_precommit(set, fulfillment.body.precommit_id()).await?
    else {
        return Err(refuse("the pending fulfillment's P is not Stored"));
    };
    let Resolved::Kept(preimage) =
        fetch_preimage(set, precommit.body.external_commitment()).await?
    else {
        return Err(refuse("the pending fulfillment's P(E) is not Stored"));
    };
    Ok((pending, fulfillment, precommit, preimage))
}

/// Stages 7 and 8 for the pending position, from what storage holds: a
/// device that crashed after its transition finishes its own install and
/// exercise here.
///
/// OWNER LOCAL, and the signature says so: it reads this device's head and
/// the admission on it, and it builds the exercise from the trader's OWN
/// closure objects. It is not the relay, whatever a passing device might
/// want — only the owning device may touch its own admission, fence, lineage
/// and leaf cache (owner ruling, §44.4). What any device may do is carry
/// already-signed material to storage: `sofi_relay::{relay_fulfillment,
/// relay_position_pair}`, which hold no `CoreSDK` and write nothing local.
pub async fn complete_pending_fulfillment(
    core: &CoreSDK,
    set: &StorageSet,
) -> Result<Completed, DsmError> {
    let (pending, fulfillment, precommit, preimage) = pending_objects(set, core).await?;
    let own = own_closure_objects(set, &precommit.body, &preimage).await?;
    let request = FulfillRequest {
        precommit: &precommit.body,
        precommit_signature: &precommit.signature,
        preimage: &preimage,
        fulfillment: &fulfillment.body,
        fulfillment_signature: &fulfillment.signature,
        own_objects: &own,
    };
    let installed = install_pair(set, &request).await?;
    let exercise = exercise_legs(set, &request).await?;
    Ok(Completed {
        position: pending.economic_position,
        fulfillment_id: derive::fulfillment_id(&fulfillment.body),
        installed,
        exercise,
    })
}

/// What stage 10 did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advanced {
    /// The route is not decided: the position stays fenced. Nothing written.
    Pending { position: u64, registered: bool },
    /// The route resolved and the lineage advanced: the admitted position is
    /// now `q` under the root the resolution selected.
    Installed {
        resolution: Resolution,
        effect: PositionEffect,
        validated: ValidatedEconomicRoot,
    },
}

/// The claim this device registered at `p`, in the form `P` names it — from
/// the device's own durable state, never read back out of a register: an
/// ordinary position's frozen claim envelope, a resolved SoFi position's
/// fulfillment.
fn own_parent_claim(admitted: &AdmittedEconomicPosition) -> Result<ParentClaimRef, DsmError> {
    match admitted {
        AdmittedEconomicPosition::SingleRoot {
            economic_position, ..
        } => {
            let (_, bytes) = economic_lineage::get_frozen_root_claim(*economic_position)
                .map_err(|e| storage("frozen root claim", e))?
                .ok_or_else(|| {
                    refuse(format!(
                        "no claim of this device's own at position {economic_position}: the \
                         parent claim P names cannot be checked"
                    ))
                })?;
            Ok(ParentClaimRef::SingleRoot {
                claim_ref: derive::claim_ref(&bytes),
            })
        }
        AdmittedEconomicPosition::ResolvedSofi { fulfillment_id, .. } => {
            Ok(ParentClaimRef::Conditional {
                fulfillment_id: *fulfillment_id,
            })
        }
        AdmittedEconomicPosition::UnresolvedSofi {
            economic_position, ..
        } => Err(refuse(format!(
            "the admitted position {economic_position} is conditional and unresolved"
        ))),
    }
}

/// The full post-transition leaf cache: the current cache with the states
/// `T°` wrote replaced (or removed), as Core recomputed and bound them.
fn post_leaf_cache(
    current: Vec<(D32, D32, Vec<u8>)>,
    post: &[(D32, Option<EconomicLeafState>)],
) -> Result<Vec<(D32, D32, Vec<u8>)>, DsmError> {
    let mut cache: BTreeMap<D32, (D32, Vec<u8>)> = current
        .into_iter()
        .map(|(k, v, ccb)| (k, (v, ccb)))
        .collect();
    for (key, state) in post {
        match state {
            Some(state) => {
                let value = state.leaf_value().map_err(|e| storage("leaf value", e))?;
                let ccb = state.encode().map_err(|e| storage("leaf state", e))?;
                cache.insert(*key, (value, ccb));
            }
            None => {
                cache.remove(key);
            }
        }
    }
    Ok(cache.into_iter().map(|(k, (v, ccb))| (k, v, ccb)).collect())
}

/// Stages 9 and 10 of §31: resolve the device's pending position from raw
/// reads (R12) and, once it is decided, advance the validated lineage through
/// `advance_resolved` and make it durable in the one admit transaction —
/// the resolved row at `q`, the leaf cache that recomputes the installed
/// root, the pending admission cleared, the head unfenced.
///
/// `Pending` writes nothing and keeps the fence. An `Invalid` resolution is
/// refused with its reason and keeps the fence too: the lineage is terminal
/// there, and no root follows it.
pub async fn resolve_pending_position(
    core: &CoreSDK,
    set: &StorageSet,
) -> Result<Advanced, DsmError> {
    let (pending, fulfillment_id) = pending_fulfillment(core)?;
    let q = pending.economic_position;
    let admitted = economic_lineage::get_admitted()
        .map_err(|e| storage("load admitted", e))?
        .ok_or_else(|| refuse("no admitted predecessor for the pending position"))?;
    // THE FENCE, on the path that produces the descendant at q: a resolved
    // conditional predecessor parents exactly the root it selected, and an
    // unresolved one parents nothing.
    descendant_fence(admitted.predecessor_claim(), &pending.pre_economic_root)
        .map_err(|e| refuse(e.to_string()))?;
    let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
        .map_err(|e| refuse(e.to_string()))?;
    if validated.economic_position() + 1 != q
        || validated.economic_root() != pending.pre_economic_root
    {
        return Err(refuse(
            "the pending position does not extend the admitted coordinate — local store \
             incoherent; refusing to guess",
        ));
    }
    let head = core
        .device_head()
        .ok_or_else(|| storage("device head", "none"))?;
    let (genesis, device_id) = (head.genesis_digest(), head.devid());

    // Registration, from the pair (R10). The F at q must be THIS one: the
    // device only ever writes its own claims at its own positions, so any
    // other outcome is a local incoherence, not a race to wait out.
    let registration =
        read_registration(set, &genesis, &device_id, q, &validated.economic_root()).await?;
    let fulfillment = match registration {
        Registration::Registered(signed)
            if derive::fulfillment_id(&signed.body) == fulfillment_id =>
        {
            signed
        }
        Registration::Registered(_) | Registration::NeverRegistered { .. } => {
            return Err(refuse(format!(
                "position {q} is held by a claim other than the pending fulfillment"
            )))
        }
        Registration::Unresolved => {
            return Ok(Advanced::Pending {
                position: q,
                registered: false,
            })
        }
    };
    let Resolved::Kept(precommit) = fetch_precommit(set, fulfillment.body.precommit_id()).await?
    else {
        return Ok(Advanced::Pending {
            position: q,
            registered: true,
        });
    };
    let precommit = precommit.body;

    // The exercise, read back from the first leg's cell: the object the
    // ladder resolves, and the one a restarted device has not kept.
    let Some(first) = precommit.legs().first() else {
        return Err(refuse("P names no leg"));
    };
    let attempt = fulfillment
        .body
        .attempts()
        .iter()
        .find(|a| a.vault_id == first.vault_id)
        .map(|a| a.attempt)
        .ok_or_else(|| refuse("F names no attempt for P's first leg"))?;
    let (_, exercise) =
        read_attempt_cell(set, &first.vault_id, &first.parent_root, attempt).await?;
    let Some(exercise) = exercise else {
        return Ok(Advanced::Pending {
            position: q,
            registered: true,
        });
    };

    // What this verifier brings: its leaves, the position it resolved
    // itself, and the canonical chain of each vault a leg names — walked
    // forward from the genesis or from the generations this device already
    // recorded, so a parent past genesis is decided rather than deferred.
    let local = LocalLeaves::of_validated(&validated)?;
    let mut parents = BTreeMap::new();
    if let AdmittedEconomicPosition::ResolvedSofi {
        fulfillment_id: parent_fid,
        selected_root,
        ..
    } = admitted
    {
        parents.insert(
            parent_fid,
            ParentPosition::ConditionalSelected { selected_root },
        );
    }
    // The canonical chain of every vault a leg names, walked forward over
    // successor cells from what this device already recorded (R14). This is
    // what lets a parent be REFUTED rather than only waited on: a chain
    // carries a generation, and the set of walked pairs it replaced did not.
    let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
    let walker = ChainWalker {
        set,
        local: &local,
        parents: &parents,
        now: crate::util::deterministic_time::tick() as i64,
    };
    for leg in precommit.legs() {
        if chains.contains_key(&leg.vault_id) {
            continue;
        }
        chains.insert(leg.vault_id, walker.chain(&leg.vault_id).await?);
    }
    let resolver = Resolver {
        set,
        local: &local,
        parents: &parents,
        chains: &chains,
    };
    let _ = WALK_BUDGET;
    let resolved = resolver.resolve_recognized(exercise.clone()).await?;
    let resolution = resolved.resolution;
    if resolution == Resolution::Pending {
        return Ok(Advanced::Pending {
            position: q,
            registered: true,
        });
    }

    // Stage 10. Every input to `advance_resolved` is this device's own: the
    // validated predecessor, the claim it registered at p, and C_q read
    // back final from K_root(q) — compared against the one (P, F) derive,
    // never believed.
    let parent = own_parent_claim(&admitted)?;
    let Some(conditional_bytes) =
        final_root_cell(set, &genesis, &device_id, q, &validated.economic_root()).await?
    else {
        return Ok(Advanced::Pending {
            position: q,
            registered: true,
        });
    };
    let claims = RegisteredClaims {
        parent,
        conditional: derive::claim_ref(&conditional_bytes),
    };
    let advanced = advance_resolved(
        &validated,
        &precommit,
        &fulfillment.body,
        &claims,
        resolution,
    )
    .map_err(|e| refuse(e.to_string()))?;

    // The leaves behind the installed root. Void moved nothing; Realized
    // wrote exactly what T° states, recomputed by Core from the evidence the
    // verdict was reached on. Either way the cache must recompute the root
    // before it is written.
    let current = economic_lineage::load_leaf_cache().map_err(|e| storage("leaf cache", e))?;
    let mut vault_heads = Vec::new();
    let leaves = match resolution {
        Resolution::Realized => {
            let evidence = acquire_evidence(set, &exercise.preimage, &local).await?;
            let post = trader_post_states(&precommit, &exercise.preimage, &evidence)
                .map_err(|e| refuse(format!("post states: {e:?}")))?;
            // The vaults moved too, and this device is the one that resolved
            // it: the post state each leg selected is kept so the NEXT trade
            // against that vault has evidence to stand on (§44.4). Recomputed
            // from the same evidence the verdict used, and bound to what each
            // `V°` states — never read back from anything the producer said.
            vault_heads = vault_post_states(&precommit, &exercise.preimage, &evidence)
                .map_err(|e| refuse(format!("vault post states: {e:?}")))?;
            post_leaf_cache(current, &post)?
        }
        Resolution::Void => current,
        Resolution::Invalid | Resolution::Pending => {
            return Err(refuse("unreachable: a terminal resolution advanced"))
        }
    };
    let mut tree = EconomicSmt::new();
    for (key, value, _) in &leaves {
        tree.insert(*key, *value);
    }
    if tree.root() != advanced.economic_root() {
        return Err(refuse(
            "the post leaves do not recompute the installed root — nothing written",
        ));
    }
    core.admit_economic_position(
        AdmittedEconomicPosition::ResolvedSofi {
            economic_position: q,
            selected_root: advanced.economic_root(),
            fulfillment_id,
        },
        &pending.operation_digest,
        &leaves,
        &set.id(),
        &[],
        &vault_heads,
    )?;
    Ok(Advanced::Installed {
        resolution,
        effect: resolved.effect,
        validated: advanced,
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use dsm::sofi::resolution::ParentStatus;
    use std::collections::BTreeSet;
    use dsm::crypto::sphincs::sphincs_sign;
    use dsm::economic::claim::EconomicRootClaimBody;
    use dsm::economic::claim_envelope::sign_economic_root_claim;
    use dsm::sofi::wire::SofiSetupBody;
    use serial_test::serial;

    use super::*;
    use crate::handlers::faucet_flow_tests_support::{setup, NETWORK};
    use crate::sdk::economic_admission_flow::resume_pending_admission;
    use crate::sdk::sofi_publish::publish_produced;
    use crate::sdk::sofi_sdk::{build_fulfillment, draft_route, ToPublish};
    use crate::sdk::sofi_test_fixtures::{
        all_policies, block_on, d, five, fold_under, produced_setup, token, RouteFixture,
        OWNER_DEV, OWNER_G, P_CREATE, P_POS, SIG_ALG,
    };
    use crate::sdk::sofi_relay::relay_fulfillment;
    use crate::storage::client_db::sofi_vault_head;
    use dsm::sofi::validation::VaultLeafPre;
    use crate::sdk::storage_io::{fake_fleet, fake_registers};
    use dsm::common::domain_tags::TAG_DSM_SOFI_SUCC_CELL_V2;
    use dsm::sofi::arith::CellResolution;
    use crate::storage::client_db;

    /// A device at position `P_POS`: its own identity and signing key, the
    /// route fixture's leaves as its admitted leaf cache, and the claim it
    /// registered there frozen locally — the premise every seam test starts
    /// from. Returns the device, its keys, the fixture and the parent claim
    /// `P` must name.
    struct Rig {
        core: CoreSDK,
        _fleet: crate::handlers::faucet_flow_tests_support::FleetGuard,
        set: StorageSet,
        pk: Vec<u8>,
        sk: Vec<u8>,
        fx: RouteFixture,
        parent_claim: ParentClaimRef,
        setups: Vec<SofiSetupBody>,
    }

    fn rig(seed: u8) -> Rig {
        let (core, fleet) = setup(seed);
        fake_fleet::reset();
        fake_registers::reset();
        let head = core.device_head().unwrap();
        let (genesis, device_id) = (head.genesis_digest(), head.devid());
        let (pk, sk) = crate::sdk::signing_authority::current_keypair().unwrap();
        let set = five();
        let setups: Vec<SofiSetupBody> = (0..2)
            .map(|j| {
                let vault_id = derive::vault_id(&OWNER_G, &OWNER_DEV, P_CREATE + j as u64);
                SofiSetupBody::new(
                    genesis,
                    device_id,
                    P_POS - 1,
                    vault_id,
                    d(0x0B),
                    d(0x0C),
                    SIG_ALG,
                    &pk,
                )
                .unwrap()
            })
            .collect();
        let rhos: Vec<D32> = setups.iter().map(derive::setup_ref).collect();
        let fx = RouteFixture::swap_for_trader(
            2,
            set.id(),
            (genesis, device_id),
            |j| (token(j), token(j + 1)),
            |j, _| rhos[j],
        );
        fx.publish(&set, &all_policies());
        for body in &setups {
            let sig = sphincs_sign(&sk, &derive::setup_signing_digest(body)).unwrap();
            block_on(publish_produced(&set, &produced_setup(body), &sig)).unwrap();
        }
        // The premise: position P_POS admitted with these leaves, and the
        // claim this device registered there.
        let rows: Vec<(D32, D32, Vec<u8>)> = fx
            .leaves
            .iter()
            .map(|(k, state)| (*k, state.leaf_value().unwrap(), state.encode().unwrap()))
            .collect();
        {
            let binding = client_db::get_connection().unwrap();
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn.transaction().unwrap();
            economic_lineage::record_admitted_with_conn(
                &tx,
                &AdmittedEconomicPosition::SingleRoot {
                    economic_position: P_POS,
                    economic_root: fx.void_root,
                },
                &rows,
                1,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let claim = EconomicRootClaimBody::new(
            genesis,
            device_id,
            P_POS,
            fx.void_root,
            d(0x5A),
            set.id(),
            dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &pk,
        )
        .unwrap();
        let claim_bytes = sign_economic_root_claim(&claim, &sk).unwrap();
        let k_root =
            dsm::economic::register::economic_root_register_key(&genesis, &device_id, P_POS);
        economic_lineage::put_frozen_root_claim(P_POS, &k_root, &claim_bytes, 1).unwrap();
        let parent_claim = ParentClaimRef::SingleRoot {
            claim_ref: derive::claim_ref(&claim_bytes),
        };
        Rig {
            core,
            _fleet: fleet,
            set,
            pk,
            sk,
            fx,
            parent_claim,
            setups,
        }
    }

    /// Stages 2 to 5 for the rig's route under `parent_claim`: the signed P
    /// and F, published.
    struct Built {
        precommit: TraderPrecommitBody,
        p_sig: Vec<u8>,
        preimage: SettlementPreimage,
        fulfillment: TraderFulfillmentBody,
        f_sig: Vec<u8>,
    }

    fn build(r: &Rig, parent_claim: ParentClaimRef) -> Built {
        let evidence = r.fx.acquire(&r.set);
        let draft = draft_route(
            r.fx.hops.clone(),
            r.fx.cores.clone(),
            &r.fx.ctx_with(parent_claim, &r.pk),
            r.fx.realize_root,
            r.fx.void_root,
            &evidence,
        )
        .unwrap();
        let p_sig = sphincs_sign(&r.sk, &draft.precommit_signing_digest()).unwrap();
        let attempts: Vec<(D32, u64)> = draft
            .precommit()
            .legs()
            .iter()
            .map(|l| (l.vault_id, 0))
            .collect();
        let produced = build_fulfillment(&draft, p_sig.clone(), &attempts).unwrap();
        let f_sig = sphincs_sign(&r.sk, produced.signs.bytes()).unwrap();
        block_on(publish_produced(&r.set, &produced, &f_sig)).unwrap();
        let fulfillment = produced
            .publish
            .iter()
            .find_map(|p| match p {
                ToPublish::Fulfillment(f) => Some(f.clone()),
                _ => None,
            })
            .unwrap();
        Built {
            precommit: draft.precommit().clone(),
            p_sig,
            preimage: draft.preimage().clone(),
            fulfillment,
            f_sig,
        }
    }

    fn request<'a>(b: &'a Built, own: &'a BTreeMap<ValidationRef, Vec<u8>>) -> FulfillRequest<'a> {
        FulfillRequest {
            precommit: &b.precommit,
            precommit_signature: &b.p_sig,
            preimage: &b.preimage,
            fulfillment: &b.fulfillment,
            fulfillment_signature: &b.f_sig,
            own_objects: own,
        }
    }

    /// The lifecycle, stages 6 to 10 (§31), and gate G4 at stage 10.
    ///
    /// The transition fences the position; a resolution read before the
    /// exercise is written is Pending and writes nothing; the resume path
    /// refuses to finish a fulfillment admission; once every leg's cell is
    /// final the position resolves Realized and the lineage advances: the
    /// admitted row is `ResolvedSofi` at q under exactly `Fold(T°, E)`
    /// recomputed from the cores, which is `P.R_realize`; `C_q` recomputed
    /// from P and F is the claim final at `K_root(q)`; the leaf cache
    /// recomputes the installed root; the fence is gone.
    #[test]
    #[serial]
    fn a_fulfilled_route_resolves_realized_and_advances_the_lineage() {
        let r = rig(0xD1);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        let req = request(&b, &own);
        let q = P_POS + 1;
        let fid = derive::fulfillment_id(&b.fulfillment);

        let fulfilled = block_on(fulfill(&r.core, &r.set, &req)).unwrap();
        assert_eq!(fulfilled.position, q);
        assert_eq!(fulfilled.fulfillment_id, fid);
        assert!(fulfilled.installed.leader_reached);
        // Fenced: the head carries the admission at q; the admitted row is p.
        let head = r.core.device_head().unwrap();
        let pending = head.pending_economic_admission().cloned().unwrap();
        assert_eq!(pending.economic_position, q);
        assert_eq!(
            pending.kind,
            PendingAdmissionKind::SofiFulfillment {
                fulfillment_id: fid
            }
        );
        assert!(pending.state.is_fencing());
        assert_eq!(
            economic_lineage::get_admitted()
                .unwrap()
                .unwrap()
                .economic_position(),
            P_POS
        );
        // A second fulfillment cannot stage past the fence.
        assert!(block_on(fulfill(&r.core, &r.set, &req))
            .unwrap_err()
            .to_string()
            .contains("a pending admission stands"));
        // The resume path refuses a fulfillment admission: it is finished by
        // resolution.
        let err = block_on(resume_pending_admission(&r.core, NETWORK, pending.clone()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("finished by its route's resolution"), "{err}");

        // Registered, but no exercise yet: Pending, nothing written.
        assert_eq!(
            block_on(resolve_pending_position(&r.core, &r.set)).unwrap(),
            Advanced::Pending {
                position: q,
                registered: true
            }
        );
        assert!(r
            .core
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_some());

        // Stage 8, then stages 9 and 10.
        let completed = block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        assert_eq!(completed.exercise.len(), 2);
        let advanced = block_on(resolve_pending_position(&r.core, &r.set)).unwrap();
        let Advanced::Installed {
            resolution,
            effect,
            validated,
        } = advanced
        else {
            panic!("the route is final at every leg: {advanced:?}")
        };
        assert_eq!(resolution, Resolution::Realized);
        assert_eq!(effect, PositionEffect::InstallRealizeRoot);
        assert_eq!(validated.economic_position(), q);

        // G4: the installed root IS Fold(T°, E) from the cores.
        let e = *b.precommit.external_commitment();
        assert_eq!(
            validated.economic_root(),
            fold_under(&r.fx.trader_core, &r.fx.leaves, &e)
        );
        assert_eq!(validated.economic_root(), *b.precommit.realize_root());
        // G4: C_q recomputed from (P, F) is the claim final at K_root(q).
        let head = r.core.device_head().unwrap();
        let at_q = block_on(final_root_cell(
            &r.set,
            &head.genesis_digest(),
            &head.devid(),
            q,
            &r.fx.void_root,
        ))
        .unwrap()
        .expect("C_q is final at K_root(q)");
        assert_eq!(
            at_q,
            derive::resolution_claim(&b.precommit, &b.fulfillment).encode()
        );
        // Durable, in one transaction: the resolved row, the cache that
        // recomputes it, no pending admission, an unfenced head.
        assert_eq!(
            economic_lineage::get_admitted().unwrap().unwrap(),
            AdmittedEconomicPosition::ResolvedSofi {
                economic_position: q,
                selected_root: *b.precommit.realize_root(),
                fulfillment_id: fid,
            }
        );
        assert_eq!(
            LocalLeaves::of_validated(&validated).unwrap().root(),
            *b.precommit.realize_root()
        );
        assert!(head.pending_economic_admission().is_none());
        // Resolving again has nothing to resolve.
        assert!(block_on(resolve_pending_position(&r.core, &r.set))
            .unwrap_err()
            .to_string()
            .contains("no pending admission"));
    }

    /// R14: the vault head past its genesis. After the route resolves, the
    /// post state each leg selected is kept, and it is exactly what the NEXT
    /// trade against that vault acquires as evidence.
    ///
    /// Before this, `acquire_evidence` gave up on any vault whose core named
    /// a root other than its genesis, so a second trade against the same
    /// vault could never be validated by anyone.
    #[test]
    #[serial]
    fn a_resolved_route_leaves_the_vault_head_the_next_trade_stands_on() {
        let r = rig(0xD5);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        let req = request(&b, &own);
        block_on(fulfill(&r.core, &r.set, &req)).unwrap();
        block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        let advanced = block_on(resolve_pending_position(&r.core, &r.set)).unwrap();
        assert!(matches!(
            advanced,
            Advanced::Installed {
                resolution: Resolution::Realized,
                ..
            }
        ));

        let evidence = r.fx.acquire(&r.set);
        let expected = vault_post_states(&b.precommit, &b.preimage, &evidence).unwrap();
        assert_eq!(expected.len(), b.precommit.legs().len());

        for post in &expected {
            // THE CHAIN, BOTH ENDS. A store of post roots alone would be a
            // set; a parent's status is asked about a generation.
            assert_eq!(
                sofi_vault_head::root_at(&post.vault_id, post.pre_generation).unwrap(),
                Some(post.pre_root),
                "the root this operation was built on, at its own generation"
            );
            assert_eq!(
                sofi_vault_head::root_at(&post.vault_id, post.state.generation).unwrap(),
                Some(post.root)
            );
            let head = sofi_vault_head::head(&post.vault_id).unwrap().unwrap();
            assert_eq!(head.generation, post.state.generation);
            assert_eq!(head.root, post.root);

            // The leaves the next trade needs, CHECKED against that root.
            let state_key = derive::vault_state_key(&post.vault_id);
            let rel_key = derive::relationship_key(
                b.precommit.genesis(),
                b.precommit.device_id(),
                &post.vault_id,
            );
            let keys: BTreeSet<D32> = [state_key, rel_key].into_iter().collect();
            let (got_head, leaves) = sofi_vault_head::leaves_at_head(&post.vault_id, &keys)
                .unwrap()
                .expect("the record reproduces its own root");
            assert_eq!(got_head, head);
            assert_eq!(
                leaves.get(&(post.vault_id, state_key)),
                Some(&VaultLeafPre::State(post.state.clone())),
                "the state leaf PREIMAGE, which a node store could never return"
            );
            let (_, rel) = post.relationship.unwrap();
            assert_eq!(
                leaves.get(&(post.vault_id, rel_key)),
                Some(&VaultLeafPre::Relationship(rel))
            );
            // A vault moves: the head is not the genesis it started from.
            assert_ne!(post.root, post.pre_root);
            assert_eq!(post.state.generation, 1, "one trade, one generation");
        }
    }

    /// Forget everything this device recorded about a vault, keeping only the
    /// committed set.
    fn forget_vault(vault_id: &D32) {
        let binding = crate::storage::client_db::get_connection().unwrap();
        let conn = binding.lock().unwrap();
        for table in ["sofi_vault_root", "sofi_vault_leaf"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE vault_id = ?1"),
                rusqlite::params![vault_id.as_slice()],
            )
            .unwrap();
        }
    }

    /// THE INDUCTION, WITHOUT THE RECORD. A settlement is resolved, and then
    /// everything this device recorded about the vault is DELETED. The walk
    /// must rebuild that generation from the committed set alone: find the
    /// exercise that consumed the genesis, RECOMPUTE what it did rather than
    /// read back what its producer stated, restore the full leaf set so the
    /// record reproduces its own root again, and then CONTINUE — reaching an
    /// open head at the new generation and refusing to refute anything there.
    ///
    /// This is what makes a vault past its genesis a derived lineage fact
    /// instead of a cache hit. A verifier that never traded with this vault
    /// holds exactly what this test leaves behind: the cells, and nothing.
    #[test]
    #[serial]
    fn the_walk_rebuilds_a_consumed_generation_from_storage_and_continues() {
        let r = rig(0xD7);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        let req = request(&b, &own);
        block_on(fulfill(&r.core, &r.set, &req)).unwrap();
        block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        block_on(resolve_pending_position(&r.core, &r.set)).unwrap();

        let evidence = r.fx.acquire(&r.set);
        let expected = vault_post_states(&b.precommit, &b.preimage, &evidence).unwrap();
        let post = expected[0].clone();
        let vault_id = post.vault_id;
        assert_eq!(post.pre_generation, 0);
        assert_eq!(post.state.generation, 1);
        assert_ne!(post.root, post.pre_root);

        forget_vault(&vault_id);
        assert_eq!(sofi_vault_head::root_at(&vault_id, 0).unwrap(), None);
        assert_eq!(sofi_vault_head::head(&vault_id).unwrap(), None);

        let parents = BTreeMap::new();
        let walker = ChainWalker {
            set: &r.set,
            local: &r.fx.local,
            parents: &parents,
            now: 0,
        };
        let chain = block_on(walker.chain(&vault_id)).unwrap();

        // Both generations, in order, derived and not remembered.
        assert_eq!(
            chain.roots,
            vec![post.pre_root, post.root],
            "the genesis, then the root the realized consumption produced"
        );
        assert_eq!(chain.head(), Some((1, post.root)));
        assert_eq!(chain.status_of(0, &post.pre_root), ParentStatus::Canonical);
        assert_eq!(chain.status_of(1, &post.root), ParentStatus::Canonical);
        assert_eq!(
            chain.status_of(1, &post.pre_root),
            ParentStatus::Orphaned,
            "the genesis is not the root of generation one"
        );

        // THE NEXT FULL LEAF STATE, rebuilt: the record reproduces its own
        // root, which is exactly what an incomplete one cannot do.
        let state_key = derive::vault_state_key(&vault_id);
        let rel_key =
            derive::relationship_key(b.precommit.genesis(), b.precommit.device_id(), &vault_id);
        let keys: BTreeSet<D32> = [state_key, rel_key].into_iter().collect();
        let (head, leaves) = sofi_vault_head::leaves_at_head(&vault_id, &keys)
            .unwrap()
            .expect("the rebuilt record reproduces its own root");
        assert_eq!(head.generation, 1);
        assert_eq!(head.root, post.root);
        assert_eq!(
            leaves.get(&(vault_id, state_key)),
            Some(&VaultLeafPre::State(post.state.clone())),
            "the state PREIMAGE the next trade stands on"
        );
        let (_, rel) = post.relationship.unwrap();
        assert_eq!(
            leaves.get(&(vault_id, rel_key)),
            Some(&VaultLeafPre::Relationship(rel))
        );

        // AND IT CONTINUED. Nothing has consumed generation one, so the walk
        // stopped at an open head — and an open head refutes nothing.
        assert_eq!(
            chain.status_of(2, &post.root),
            ParentStatus::Unavailable,
            "a generation nothing has produced yet is not a refuted one"
        );
        assert_ne!(chain.status_of(2, &post.root), ParentStatus::Orphaned);

        // WALKED AGAIN, now from the record it just wrote. The same chain,
        // and contiguously: a reader that took the HIGHEST recorded
        // generation rather than the contiguous prefix from zero would align
        // `roots[g]` to the wrong g, and every correct parent below the head
        // would read as refuted.
        let again = block_on(walker.chain(&vault_id)).unwrap();
        assert_eq!(
            again.roots, chain.roots,
            "the record round-trips the chain the walk derived"
        );
        assert_eq!(again.status_of(0, &post.pre_root), ParentStatus::Canonical);
    }

    /// THE RECORD IS CHECKED, NEVER TRUSTED. It is this device's own cache,
    /// so `leaves_at_head` rebuilds the tree from every stored leaf and
    /// requires the recomputed root to equal the recorded one. That equality
    /// is what detects an INCOMPLETE record — a vault another trader moved
    /// between our trades leaves us missing their leaf — and an incomplete
    /// record yields nothing, so Core answers `Unavailable` and the position
    /// waits rather than standing on a state this device never established.
    #[test]
    #[serial]
    fn a_vault_record_that_cannot_reproduce_its_own_root_is_not_evidence() {
        let r = rig(0xD6);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        block_on(fulfill(&r.core, &r.set, &request(&b, &own))).unwrap();
        block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        block_on(resolve_pending_position(&r.core, &r.set)).unwrap();

        let vault_id = b.precommit.legs()[0].vault_id;
        let state_key = derive::vault_state_key(&vault_id);
        let keys: BTreeSet<D32> = [state_key].into_iter().collect();
        assert!(sofi_vault_head::leaves_at_head(&vault_id, &keys)
            .unwrap()
            .is_some());

        // Drop one leaf, as an unseen trade by another trader would.
        {
            let binding = client_db::get_connection().unwrap();
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "DELETE FROM sofi_vault_leaf WHERE vault_id = ?1 AND leaf_key != ?2",
                rusqlite::params![vault_id.as_slice(), state_key.as_slice()],
            )
            .unwrap();
        }
        assert!(
            sofi_vault_head::leaves_at_head(&vault_id, &keys)
                .unwrap()
                .is_none(),
            "a record that cannot reproduce its own root is not evidence"
        );
        // The chain itself survives: what this device established about which
        // root belongs to which generation is a different fact from whether
        // it still holds the leaves.
        assert!(sofi_vault_head::root_at(&vault_id, 1).unwrap().is_some());
    }

    /// DEVICE SCENARIO 4 (§44.1): `F` registered, the trader offline, a
    /// relayer completes the cells and the position resolves.
    ///
    /// The relay holds no `CoreSDK` and writes nothing local — it takes a
    /// fulfillment id and a committed set and carries bytes that already
    /// exist (owner ruling, §44.4). Device A's own completion is stopped at
    /// the second leg by a fleet that refuses that cell, which is what an
    /// offline trader looks like from storage; the members are healed, a
    /// party with no device state relays, and only then does A resolve from
    /// its own durable admission.
    #[test]
    #[serial]
    fn a_relayer_completes_the_cells_and_the_owner_later_resolves_from_its_admission() {
        let r = rig(0xD3);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        let req = request(&b, &own);
        block_on(fulfill(&r.core, &r.set, &req)).unwrap();

        // The second leg's cell refuses every member: A gets the first leg
        // written and nothing else.
        let legs = b.precommit.legs();
        let stranded = &legs[1];
        let stranded_key =
            derive::successor_attempt_key(&stranded.vault_id, &stranded.parent_root, 0);
        let ns = TAG_DSM_SOFI_SUCC_CELL_V2.source_bytes();
        for m in r.set.members() {
            fake_registers::fail_cell(&m.member_id, ns, &stranded_key);
        }
        let completed = block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        let stranded_write = completed
            .exercise
            .iter()
            .find(|w| w.vault_id == stranded.vault_id)
            .unwrap();
        assert!(!stranded_write.leader_reached && stranded_write.copies == 0);
        assert_eq!(
            block_on(read_attempt_cell(
                &r.set,
                &stranded.vault_id,
                &stranded.parent_root,
                0
            ))
            .unwrap()
            .0,
            CellResolution::Unresolved,
            "one leg is stranded, so the route cannot be consumed"
        );
        assert_eq!(
            block_on(resolve_pending_position(&r.core, &r.set)).unwrap(),
            Advanced::Pending {
                position: P_POS + 1,
                registered: true
            }
        );

        // The members are back. A RELAYER — no CoreSDK, no head, no local
        // state — carries the exercise it finds at the first leg to the key
        // that lacks it.
        for m in r.set.members() {
            fake_registers::heal_cell(&m.member_id, ns, &stranded_key);
        }
        let fid = derive::fulfillment_id(&b.fulfillment);
        let relayed = block_on(relay_fulfillment(&r.set, &fid)).unwrap();
        assert_eq!(relayed.fulfillment_id, fid);
        assert_eq!(relayed.legs.len(), legs.len(), "every leg key the F names");
        for w in &relayed.legs {
            assert!(w.leader_reached);
        }
        let e = *b.precommit.external_commitment();
        for leg in legs {
            assert_eq!(
                block_on(read_attempt_cell(
                    &r.set,
                    &leg.vault_id,
                    &leg.parent_root,
                    0
                ))
                .unwrap()
                .0,
                CellResolution::Final(e),
                "the relayed bytes count at every key their F names"
            );
        }

        // Only now, and only the owning device, advances its own lineage.
        let advanced = block_on(resolve_pending_position(&r.core, &r.set)).unwrap();
        let Advanced::Installed { resolution, .. } = advanced else {
            panic!("every leg is final: {advanced:?}")
        };
        assert_eq!(resolution, Resolution::Realized);
        assert!(r
            .core
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_none());
    }

    /// A relayer cannot BUILD an exercise, and says so rather than papering
    /// over it: building one needs the trader's own closure objects. It
    /// still carries the position pair, which is already-signed material.
    #[test]
    #[serial]
    fn a_relay_carries_the_pair_but_never_invents_an_exercise() {
        let r = rig(0xD4);
        let b = build(&r, r.parent_claim);
        let own = BTreeMap::new();
        let req = request(&b, &own);
        block_on(fulfill(&r.core, &r.set, &req)).unwrap();
        let fid = derive::fulfillment_id(&b.fulfillment);
        let relayed = block_on(relay_fulfillment(&r.set, &fid)).unwrap();
        assert!(relayed.pair_leader_reached);
        assert_eq!(relayed.position, P_POS + 1);
        assert!(
            relayed.legs.is_empty(),
            "no cell holds an exercise yet, so there is nothing to carry"
        );
        let leg = &b.precommit.legs()[0];
        assert_eq!(
            block_on(read_attempt_cell(
                &r.set,
                &leg.vault_id,
                &leg.parent_root,
                0
            ))
            .unwrap()
            .0,
            CellResolution::Unresolved
        );
    }

    /// `advance_resolved`'s parent-claim conjunct at the seam: a P naming a
    /// parent claim other than the one this device registered at p never
    /// advances the lineage — refused at stage 10 with the reason, the row
    /// unchanged and the fence standing — even though the route itself is
    /// registered, conforming, valid and final at every leg.
    #[test]
    #[serial]
    fn a_precommit_naming_another_parent_claim_does_not_advance() {
        let r = rig(0xD2);
        let b = build(&r, ParentClaimRef::SingleRoot { claim_ref: d(0x66) });
        let own = BTreeMap::new();
        let req = request(&b, &own);
        block_on(fulfill(&r.core, &r.set, &req)).unwrap();
        block_on(complete_pending_fulfillment(&r.core, &r.set)).unwrap();
        let err = block_on(resolve_pending_position(&r.core, &r.set))
            .unwrap_err()
            .to_string();
        assert!(err.contains("K_root(p) is not the one P names"), "{err}");
        assert_eq!(
            economic_lineage::get_admitted()
                .unwrap()
                .unwrap()
                .economic_position(),
            P_POS
        );
        assert!(r
            .core
            .device_head()
            .unwrap()
            .pending_economic_admission()
            .is_some());
        let _ = &r.setups;
    }
}
