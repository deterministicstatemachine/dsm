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
use dsm::sofi::conformance::ConformanceMissing;
use dsm::sofi::derive;
use dsm::sofi::facts::{Established, NotEstablished};
use dsm::sofi::lineage::{advance_resolved, descendant_fence, AdvanceError};
use dsm::sofi::publication::Publication;
use dsm::sofi::registration::Registration;
use dsm::sofi::resolution::{PositionEffect, Resolution};
use dsm::sofi::resolve::{value_of, Acquired, LocalLeaves};
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
use crate::sdk::route_seats::{read_cell, NodeSeats};
use crate::sdk::sofi_exercise::{build_exercise, write_exercise, LegWrite};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_preimage};
use crate::sdk::sofi_reads::{local_leaves_of_validated, verifier_error, VerifierContext};
use crate::sdk::sofi_register::{
    install_fulfillment, position_cells, InstallError, InstallRequest, Installed,
};
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

/// The fulfillment's transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fulfilled {
    /// `q`, the position the fulfillment holds under its conditional claim.
    pub position: u64,
    pub fulfillment_id: D32,
}

/// Stages 7 and 8, written from what storage holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    pub position: u64,
    pub fulfillment_id: D32,
    /// Stage 7: the pair at the leader of `s(q)` (R9).
    pub installed: Installed,
    /// Stage 8: the exercise at every leg's key (R11).
    pub exercise: Vec<LegWrite>,
}

/// What [`complete_pending_fulfillment`] did for the pending position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// The pair reached the leader of `s(q)` and the exercise the leader of
    /// every leg's key.
    Written(Box<Completed>),
    /// The network did not take a write, or did not establish an object a
    /// stage reads, this pass. The position stays pending and fenced and
    /// nothing negative is recorded (Amendment S3, storage §3): the next
    /// `sofi.resolve` runs the stages again from what storage holds.
    NotTaken { position: u64, why: NotTaken },
}

/// The network's status when stages 7 and 8 could not be written: never a
/// refusal, which is an error, and never a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotTaken {
    /// The pending `F`, its `P` or its `P(E)` — the named one — could not be
    /// read back: the scan did not establish the object's bytes.
    Unavailable(&'static str),
    /// Evidence conformance needs is not in hand after the acquisition
    /// rounds (rule T5).
    Evidence(Vec<ConformanceMissing>),
    /// The leader of `s(q)` did not answer with the pair's links.
    PairLeaderUnreached,
    /// The leader of a leg's key did not answer with the exercise's link, at
    /// these vaults.
    LegLeaderUnreached(Vec<D32>),
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
/// one Core transition. The head advances with a `SofiFulfillment` admission
/// at `q` that fences the lineage until the route resolves. Stages 7 and 8 —
/// the install and the exercise — are written from what storage holds by
/// [`complete_pending_fulfillment`], for a device that just advanced and for
/// one that comes back after a crash alike.
///
/// Refused before anything is written unless `P` is built on exactly this
/// device's validated predecessor — its position and root — and names this
/// device.
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
    Ok(Fulfilled {
        position: q,
        fulfillment_id,
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

/// This device as the verifier of its own position: its leaves at its
/// validated root, and the position it resolved itself.
struct OwnStanding {
    local: LocalLeaves,
    admitted: AdmittedEconomicPosition,
}

impl OwnStanding {
    fn of(
        core: &CoreSDK,
        admitted: AdmittedEconomicPosition,
        validated: &ValidatedEconomicRoot,
    ) -> Result<Self, DsmError> {
        let head = core
            .device_head()
            .ok_or_else(|| storage("device head", "none"))?;
        let local = local_leaves_of_validated(&head.genesis_digest(), &head.devid(), validated)?;
        Ok(Self { local, admitted })
    }

    fn context<'a>(&'a self, set: &'a StorageSet) -> Result<VerifierContext<'a>, DsmError> {
        VerifierContext::new(set, Some(&self.local), Some(&self.admitted))
    }
}

/// What an install that wrote nothing means: the network's status when the
/// leader did not answer or the evidence is not in hand, an error otherwise
/// — a non-conforming `F`, an object without canonical bytes, a member or
/// this device's own store that could not be read or written.
fn install_failure(e: InstallError) -> Result<NotTaken, DsmError> {
    match e {
        InstallError::LeaderUnreached => Ok(NotTaken::PairLeaderUnreached),
        InstallError::Unavailable(missing) => Ok(NotTaken::Evidence(missing)),
        InstallError::NotConforming(why) => Err(refuse(format!("install: {why:?}"))),
        InstallError::Wire(e) => Err(refuse(format!("install: {e:?}"))),
        InstallError::Storage(e) => Err(storage("install", e)),
    }
}

/// Stage 7: the pair at `s(q)`, conformance first (R9). Idempotent at the
/// members, which keep what they are given.
async fn install_pair(
    ctx: &VerifierContext<'_>,
    set: &StorageSet,
    request: &FulfillRequest<'_>,
) -> Result<Result<Installed, NotTaken>, DsmError> {
    match install_fulfillment(&ctx.verifier(), set, &install_request(request)).await {
        Ok(installed) => Ok(Ok(installed)),
        Err(e) => install_failure(e).map(Err),
    }
}

/// Stage 8: the exercise, built over the evidence its conformance was
/// decided on, at every leg's key (R11). Written when the leader of every
/// leg's key answered with its link.
async fn exercise_legs(
    ctx: &VerifierContext<'_>,
    set: &StorageSet,
    request: &FulfillRequest<'_>,
) -> Result<Result<Vec<LegWrite>, NotTaken>, DsmError> {
    let install = install_request(request);
    let evidence = match ctx
        .verifier()
        .acquire_conformance_evidence(&install.objects())
        .map_err(verifier_error)?
    {
        Acquired::Complete(evidence) => evidence,
        Acquired::Exhausted(missing) => return Ok(Err(NotTaken::Evidence(missing))),
        Acquired::NoSource(missing) => {
            return Err(refuse(format!(
                "exercise: conformance evidence has no source: {missing:?}"
            )))
        }
    };
    let exercise = build_exercise(&install, &evidence)?;
    let recognized = dsm::sofi::exercise::recognize_exercise(&exercise.encode())
        .ok_or_else(|| refuse("the exercise built here does not recognize"))?;
    let writes = write_exercise(set, &exercise, &recognized).await?;
    let unreached: Vec<D32> = writes
        .iter()
        .filter(|write| !write.reached_leader)
        .map(|write| write.vault_id)
        .collect();
    if !unreached.is_empty() {
        return Ok(Err(NotTaken::LegLeaderUnreached(unreached)));
    }
    Ok(Ok(writes))
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
/// having kept anything but the admission. `Err(name)` names the object the
/// scan could not establish this pass. An object the scan established absent
/// is a refusal: each was read back `Stored` before the transition, so a
/// network that has none of it contradicts this device's record.
async fn pending_objects(
    set: &StorageSet,
    fulfillment_id: &D32,
) -> Result<
    Result<
        (
            dsm::sofi::publication::Signed<TraderFulfillmentBody>,
            dsm::sofi::publication::Signed<TraderPrecommitBody>,
            SettlementPreimage,
        ),
        &'static str,
    >,
    DsmError,
> {
    let fulfillment = match fetch_fulfillment(set, fulfillment_id).await? {
        Resolved::Kept(fulfillment) => fulfillment,
        Resolved::Unavailable => return Ok(Err("fulfillment")),
        Resolved::None => {
            return Err(refuse(
                "the pending fulfillment is not Stored; nothing to finish from",
            ))
        }
    };
    let precommit = match fetch_precommit(set, fulfillment.body.precommit_id()).await? {
        Resolved::Kept(precommit) => precommit,
        Resolved::Unavailable => return Ok(Err("precommit")),
        Resolved::None => return Err(refuse("the pending fulfillment's P is not Stored")),
    };
    let preimage = match fetch_preimage(set, precommit.body.external_commitment()).await? {
        Resolved::Kept(preimage) => preimage,
        Resolved::Unavailable => return Ok(Err("preimage")),
        Resolved::None => return Err(refuse("the pending fulfillment's P(E) is not Stored")),
    };
    Ok(Ok((fulfillment, precommit, preimage)))
}

/// Stages 7 and 8 for the pending position, from what storage holds: the
/// device that just advanced and one that crashed after its transition write
/// their install and exercise here alike.
///
/// A stage the network did not take is [`Completion::NotTaken`], never an
/// error and never a verdict; an error is a refusal — the fence, a
/// non-conforming `F`, an object the network established absent — or a read
/// or write that failed, and it is reported as what it is.
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
) -> Result<Completion, DsmError> {
    let (pending, fulfillment_id) = pending_fulfillment(core)?;
    let position = pending.economic_position;
    let not_taken = |why: NotTaken| Ok(Completion::NotTaken { position, why });
    let (fulfillment, precommit, preimage) = match pending_objects(set, &fulfillment_id).await? {
        Ok(objects) => objects,
        Err(what) => return not_taken(NotTaken::Unavailable(what)),
    };
    let own = own_closure_objects(set, &precommit.body, &preimage).await?;
    let request = FulfillRequest {
        precommit: &precommit.body,
        precommit_signature: &precommit.signature,
        preimage: &preimage,
        fulfillment: &fulfillment.body,
        fulfillment_signature: &fulfillment.signature,
        own_objects: &own,
    };
    let admitted = economic_lineage::get_admitted()
        .map_err(|e| storage("load admitted", e))?
        .ok_or_else(|| refuse("no admitted predecessor for the pending position"))?;
    // THE FENCE, again on the path that finishes the descendant at q: the
    // pending position stands on the root its resolved predecessor selected,
    // or it is not finished.
    descendant_fence(admitted.predecessor_claim(), &pending.pre_economic_root)
        .map_err(|e| refuse(e.to_string()))?;
    let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
        .map_err(|e| refuse(e.to_string()))?;
    let standing = OwnStanding::of(core, admitted, &validated)?;
    let ctx = standing.context(set)?;
    let installed = match install_pair(&ctx, set, &request).await? {
        Ok(installed) => installed,
        Err(why) => return not_taken(why),
    };
    let exercise = match exercise_legs(&ctx, set, &request).await? {
        Ok(exercise) => exercise,
        Err(why) => return not_taken(why),
    };
    Ok(Completion::Written(Box::new(Completed {
        position,
        fulfillment_id,
        installed,
        exercise,
    })))
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
    /// The facts are complete and the ladder, run inside the advance, does
    /// not resolve the position yet (Amendment S7).
    Ladder(Incomplete),
    /// A fact the ladder reads is not established.
    Facts(NotEstablished),
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
    let standing = OwnStanding::of(core, admitted, &validated)?;
    let ctx = standing.context(set)?;
    let verifier = ctx.verifier();
    let registration = match verifier
        .read_registration(&genesis, &device_id, q, &validated.economic_root())
        .map_err(verifier_error)?
    {
        Ok(registration) => registration,
        Err(missing) => return not_yet(NotResolved::Registration(missing)),
    };
    let fulfillment = match registration.registration() {
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
    let exercise = match verifier
        .read_attempt_cell(&first.vault_id, &first.parent_root, attempt)
        .map_err(verifier_error)?
    {
        Ok(read) => match read.into_exercise() {
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
    let mut chains: BTreeMap<D32, VaultChain> = BTreeMap::new();
    for leg in precommit.legs() {
        if chains.contains_key(&leg.vault_id) {
            continue;
        }
        chains.insert(
            leg.vault_id,
            verifier.chain(&leg.vault_id).map_err(verifier_error)?,
        );
    }
    let established = match verifier
        .establish_own(&chains, &exercise, &registration)
        .map_err(verifier_error)?
    {
        Ok(established) => established,
        Err(why) => return not_yet(NotResolved::Facts(why)),
    };

    // Stage 10. Every input to `advance_resolved` is this device's own: the
    // validated predecessor, the claim it registered at p, the facts Core
    // established over its own reads, and the head whose adoptions decide
    // what a realized route may credit. The ladder runs inside the advance;
    // no resolution is named here.
    let parent = own_parent_claim(&admitted)?;
    let advanced = match advance_resolved(
        &validated,
        &precommit,
        &fulfillment.body,
        &parent,
        &established,
        &head,
    ) {
        Ok(advanced) => advanced,
        Err(AdvanceError::FactsIncomplete(incomplete)) => {
            return not_yet(NotResolved::Ladder(incomplete))
        }
        // The route resolved Invalid: the lineage is terminal at q, no root
        // follows it, and the fence stands.
        Err(AdvanceError::LineageIsTerminal) => return Ok(Advanced::Invalid { position: q }),
        Err(e) => return Err(refuse(e.to_string())),
    };

    // The leaves behind the installed root. Void moved nothing; Realized
    // wrote exactly what T° states, recomputed by Core from the evidence the
    // verdict was reached on — the evidence inside the established facts,
    // the same bytes the advance derived the balances from. Either way the
    // cache must recompute the root before it is written.
    let current = economic_lineage::load_leaf_cache().map_err(|e| storage("leaf cache", e))?;
    let mut vault_heads = Vec::new();
    let leaves = match (advanced.resolution, &established) {
        (Resolution::Realized, Established::Facts(facts)) => {
            let post = trader_post_states(&precommit, facts.preimage(), facts.evidence())
                .map_err(|e| refuse(format!("post states: {e:?}")))?;
            // The vaults moved too, and this device is the one that resolved
            // it: the post state each leg selected is kept so the NEXT trade
            // against that vault has evidence to stand on (§44.4). Recomputed
            // from the same evidence the verdict used, and bound to what each
            // `V°` states — never read back from anything the producer said.
            vault_heads = vault_post_states(&precommit, facts.preimage(), facts.evidence())
                .map_err(|e| refuse(format!("vault post states: {e:?}")))?;
            post_leaf_cache(current, &post)?
        }
        (Resolution::Void, _) => current,
        // The advance answers Realized over established facts only, and
        // never Invalid; stated so that a change to it is refused here.
        (Resolution::Realized, Established::RefutedInHand(..)) | (Resolution::Invalid, _) => {
            return Err(refuse(
                "the advance installed a root these facts cannot have produced",
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
        resolution: advanced.resolution,
        effect: advanced.effect,
        validated: advanced.root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::sofi::conformance::FulfillmentConformanceError;
    use dsm::sofi::wire::SofiWireError;

    /// An install the network did not take — the leader of `s(q)` silent,
    /// the evidence not in hand after the rounds — is the network's status.
    /// An install refused, or one whose read or write failed, is an error:
    /// never the status, never `RetriesExhausted`.
    #[test]
    fn only_an_install_the_network_did_not_take_is_the_network_status() {
        assert!(matches!(
            install_failure(InstallError::LeaderUnreached),
            Ok(NotTaken::PairLeaderUnreached)
        ));
        assert!(matches!(
            install_failure(InstallError::Unavailable(vec![ConformanceMissing::Preimage])),
            Ok(NotTaken::Evidence(missing)) if missing == vec![ConformanceMissing::Preimage]
        ));
        assert!(matches!(
            install_failure(InstallError::NotConforming(
                FulfillmentConformanceError::PrecommitMismatch
            )),
            Err(DsmError::InvalidOperation(..))
        ));
        assert!(matches!(
            install_failure(InstallError::Wire(SofiWireError::UnknownSignatureAlg {
                alg: 7
            })),
            Err(DsmError::InvalidOperation(..))
        ));
        assert!(matches!(
            install_failure(InstallError::Storage("the route record".to_string())),
            Err(DsmError::Storage { .. })
        ));
    }
}
