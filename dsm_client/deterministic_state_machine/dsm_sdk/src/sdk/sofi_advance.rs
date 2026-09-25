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
use dsm::economic::register::read_root_cell;
use dsm::economic::state::EconomicLeafState;
use dsm::economic::tree::EconomicSmt;
use dsm::route_chain::{CellReading, ChainState, Missing as CellMissing};
use dsm::sofi::derive;
use dsm::sofi::lineage::{advance_resolved, descendant_fence, RealizedReceipt, RegisteredClaims};
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
use crate::sdk::route_seats::{read_cell, value_of, NodeSeats};
use crate::sdk::sofi_evidence::{acquire_evidence, Acquired, LocalLeaves};
use crate::sdk::sofi_exercise::{build_exercise, read_attempt_cell, write_exercise, LegWrite};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_preimage};
use crate::sdk::sofi_chain::ChainWalker;
use crate::sdk::sofi_register::{
    acquire_conformance_evidence, install_fulfillment, position_cells, read_registration,
    InstallRequest, Installed,
};
use crate::sdk::sofi_resolve::{NotEstablished, PositionOutcome, Resolver};
use crate::sdk::storage_set::StorageSet;
use dsm::sofi::resolution::{Incomplete, VaultChain};
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
    let evidence = match acquire_conformance_evidence(set, &install).await? {
        Acquired::Complete(evidence) => evidence,
        Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
            return Err(storage(
                "exercise",
                format!("conformance evidence not in hand: {missing:?}"),
            ))
        }
    };
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
        PendingAdmissionKind::DsmBacked
        | PendingAdmissionKind::OfflineLoad { .. }
        | PendingAdmissionKind::OfflineUnload { .. } => Err(refuse(format!(
            "the pending admission at position {} is not a SoFi fulfillment",
            pending.economic_position
        ))),
    }
}

/// The closure objects only this trader holds exactly, from its own durable
/// state: the claim envelope it registered at `p` for a `SingleRootClaim`
/// naming that claim; a `ConditionalClaim` is the final bytes at `K_root` of
/// the position it names, which are storage's, read where that position's
/// cells are routed — by the root it was built on.
pub(crate) async fn own_closure_objects(
    set: &StorageSet,
    precommit: &TraderPrecommitBody,
    preimage: &SettlementPreimage,
) -> Result<BTreeMap<ValidationRef, Vec<u8>>, DsmError> {
    let mut own = BTreeMap::new();
    for reference in preimage.settlement().closure().refs() {
        match reference {
            ValidationRef::SingleRootClaim { claim_ref } => {
                if let Some((.., bytes)) =
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
                let Some(built_on) = own_root_before(*position)? else {
                    continue;
                };
                if let Some(bytes) =
                    final_root_cell(set, genesis, device_id, *position, &built_on).await?
                {
                    own.insert(*reference, bytes);
                }
            }
            ValidationRef::ContentAddr { .. } | ValidationRef::Setup { .. } => {}
        }
    }
    Ok(own)
}

/// The root this device's position `position` was built on — the root its
/// admitted position `position - 1` selected — which routes the cells of
/// `position` (`s(q)` from the parent root, as [`crate::sdk::sofi_register::cells_of`] routes `F.q` by
/// `P.void_root`). `None` when this device admitted no position there that
/// selected a root.
fn own_root_before(position: u64) -> Result<Option<D32>, DsmError> {
    let Some(before) = position.checked_sub(1) else {
        return Ok(None);
    };
    Ok(
        match economic_lineage::get_admitted_at(before)
            .map_err(|e| storage("admitted history", e))?
        {
            Some(AdmittedEconomicPosition::SingleRoot { economic_root, .. }) => Some(economic_root),
            Some(AdmittedEconomicPosition::ResolvedSofi { selected_root, .. }) => {
                Some(selected_root)
            }
            Some(AdmittedEconomicPosition::UnresolvedSofi { .. }) | None => None,
        },
    )
}

/// The bytes final at `K_root(position)` of `(genesis, device_id)`, routed
/// by `s(q)` from `parent_root`: the claim holding the cell whose chain is
/// Final. `None` while no claim is final there, or the reads do not decide
/// the cell yet — either way the final bytes are not in hand.
async fn final_root_cell(
    set: &StorageSet,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    parent_root: &D32,
) -> Result<Option<Vec<u8>>, DsmError> {
    let cells = position_cells(set, genesis, device_id, position, parent_root)?;
    let seats = NodeSeats::new(set)?;
    let evidence = read_cell(&seats, cells.root().routed()).await;
    Ok(match read_root_cell(cells.root(), &evidence) {
        Ok(CellReading::Held {
            id,
            state: ChainState::Final,
            ..
        }) => value_of(&evidence, &id),
        Ok(CellReading::Held { .. } | CellReading::Open) => None,
        Err(missing) => {
            log::info!("[sofi advance] K_root({position}) is not decided yet: {missing:?}");
            None
        }
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

/// Why the pending position is not resolved yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotResolved {
    /// The position pair's reads do not decide registration yet.
    Registration(CellMissing),
    /// `F` is not registered at `q` yet.
    NotRegistered,
    /// `F`'s `P` is not `Stored` yet.
    PrecommitNotStored,
    /// The first leg's cell does not hold the exercise yet, or its reads do
    /// not decide it.
    ExerciseNotRead,
    /// The resolver's facts are complete and the ladder does not resolve the
    /// position yet (Amendment S7).
    Ladder(Incomplete),
    /// A fact the ladder reads is not established.
    Facts(NotEstablished),
    /// Resolved, but the claim at `K_root(q)` is not final in hand yet.
    RootClaimNotFinal,
    /// Realized, but the evidence the advance consumes is not in hand.
    Evidence(String),
}

/// What stage 10 did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advanced {
    /// The position is not resolved yet: it stays fenced, and nothing is
    /// written.
    NotYet { position: u64, why: NotResolved },
    /// The route resolved Invalid: the lineage is terminal at `q`, no root
    /// follows it, and the fence stands.
    Invalid { position: u64 },
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
pub(crate) fn own_parent_claim(
    admitted: &AdmittedEconomicPosition,
) -> Result<ParentClaimRef, DsmError> {
    match admitted {
        AdmittedEconomicPosition::SingleRoot {
            economic_position, ..
        } => {
            let (.., bytes) = economic_lineage::get_frozen_root_claim(*economic_position)
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
    let not_yet = |why: NotResolved| Ok(Advanced::NotYet { position: q, why });
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
        match read_registration(set, &genesis, &device_id, q, &validated.economic_root()).await? {
            Ok(registration) => registration,
            Err(missing) => return not_yet(NotResolved::Registration(missing)),
        };
    let fulfillment = match &registration {
        Registration::Registered(signed)
            if derive::fulfillment_id(&signed.body) == fulfillment_id =>
        {
            signed.clone()
        }
        Registration::Registered(..) | Registration::NeverRegistered { .. } => {
            return Err(refuse(format!(
                "position {q} is held by a claim other than the pending fulfillment"
            )))
        }
        Registration::Unresolved => return not_yet(NotResolved::NotRegistered),
    };
    let precommit = match fetch_precommit(set, fulfillment.body.precommit_id()).await? {
        Resolved::Kept(precommit) => precommit.body,
        Resolved::None | Resolved::Unavailable => return not_yet(NotResolved::PrecommitNotStored),
    };

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
    let exercise =
        match read_attempt_cell(set, &first.vault_id, &first.parent_root, attempt).await? {
            Ok(read) => match read.exercise {
                Some(exercise) => exercise,
                None => return not_yet(NotResolved::ExerciseNotRead),
            },
            Err(missing) => {
                log::info!("[sofi advance] the first leg's cell is not decided yet: {missing:?}");
                return not_yet(NotResolved::ExerciseNotRead);
            }
        };

    // What this verifier brings: its leaves, the position it resolved
    // itself, and the canonical chain of each vault a leg names — walked
    // forward from the genesis or from the generations this device already
    // recorded, so a parent past genesis is decided rather than deferred.
    let local = LocalLeaves::of_validated(&genesis, &device_id, &validated)?;
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
    let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
    let walker = ChainWalker {
        set,
        local: &local,
        parents: &parents,
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
    let (resolution, effect) = match resolver
        .resolve_recognized(exercise.clone(), &registration)
        .await?
    {
        PositionOutcome::Resolved { resolution, effect } => (resolution, effect),
        PositionOutcome::NotYet(incomplete) => return not_yet(NotResolved::Ladder(incomplete)),
        PositionOutcome::NotEstablished(why) => return not_yet(NotResolved::Facts(why)),
    };
    // Only a realized or void route installs a root.
    let realized = match resolution {
        Resolution::Realized => true,
        Resolution::Void => false,
        Resolution::Invalid => return Ok(Advanced::Invalid { position: q }),
    };

    // Stage 10. Every input to `advance_resolved` is this device's own: the
    // validated predecessor, the claim it registered at p, and C_q read
    // back final from K_root(q) — compared against the one (P, F) derive,
    // never believed.
    let parent = own_parent_claim(&admitted)?;
    let Some(conditional_bytes) =
        final_root_cell(set, &genesis, &device_id, q, &validated.economic_root()).await?
    else {
        return not_yet(NotResolved::RootClaimNotFinal);
    };
    let claims = RegisteredClaims {
        parent,
        conditional: derive::claim_ref(&conditional_bytes),
    };
    // The evidence this verdict was reached on, acquired BEFORE the advance:
    // the adoption gate inside `advance_resolved` derives this operation's
    // credits from these same bytes, so it cannot be handed a different
    // settlement's. A Void moves nothing and needs none.
    let evidence = if realized {
        match acquire_evidence(set, &precommit, &exercise.preimage, &local).await? {
            Acquired::Complete(evidence) => Some(evidence),
            Acquired::Exhausted(missing) | Acquired::NoSource(missing) => {
                return not_yet(NotResolved::Evidence(format!("{missing:?}")))
            }
        }
    } else {
        None
    };
    let receipt = evidence.as_ref().map(|evidence| RealizedReceipt {
        preimage: &exercise.preimage,
        evidence,
        // `S_pre`: the state this advance succeeds. Adoption must PRECEDE
        // receipt, so it is this head's adoptions that decide, not the ones
        // the operation would leave behind.
        receiver: &head,
    });
    let advanced = advance_resolved(
        &validated,
        &precommit,
        &fulfillment.body,
        &claims,
        resolution,
        receipt.as_ref(),
    )
    .map_err(|e| refuse(e.to_string()))?;

    // The leaves behind the installed root. Void moved nothing; Realized
    // wrote exactly what T° states, recomputed by Core from the evidence the
    // verdict was reached on. Either way the cache must recompute the root
    // before it is written.
    let current = economic_lineage::load_leaf_cache().map_err(|e| storage("leaf cache", e))?;
    let mut vault_heads = Vec::new();
    let leaves = match (realized, evidence.as_ref()) {
        (true, Some(evidence)) => {
            let post = trader_post_states(&precommit, &exercise.preimage, evidence)
                .map_err(|e| refuse(format!("post states: {e:?}")))?;
            // The vaults moved too, and this device is the one that resolved
            // it: the post state each leg selected is kept so the NEXT trade
            // against that vault has evidence to stand on (§44.4). Recomputed
            // from the same evidence the verdict used, and bound to what each
            // `V°` states — never read back from anything the producer said.
            vault_heads = vault_post_states(&precommit, &exercise.preimage, evidence)
                .map_err(|e| refuse(format!("vault post states: {e:?}")))?;
            post_leaf_cache(current, &post)?
        }
        (false, None) => current,
        (true, None) | (false, Some(..)) => {
            return Err(refuse(
                "the evidence in hand is not the evidence this resolution consumes",
            ))
        }
    };
    let mut tree = EconomicSmt::new();
    for (key, value, ..) in &leaves {
        tree.insert(*key, *value);
    }
    if tree.root() != advanced.root.economic_root() {
        return Err(refuse(
            "the post leaves do not recompute the installed root — nothing written",
        ));
    }
    core.admit_resolved_sofi_position(
        &advanced,
        fulfillment_id,
        &pending.operation_digest,
        &leaves,
        &set.id(),
        &vault_heads,
    )?;
    Ok(Advanced::Installed {
        resolution,
        effect,
        validated: advanced.root,
    })
}
