// SPDX-License-Identifier: Apache-2.0

//! The substrate-neutral economic admission machinery — build, finish, and
//! resume — shared by EVERY admitted operation (faucet claim, transfer
//! debit, burn, create-token fee). Split out of the faucet flow once the
//! producer seam generalized: only the ticket machinery is faucet-specific.
//!
//! ## The producer rule
//!
//! The witness is built by [`dsm::economic::write_set::build_write_set`] —
//! the SAME table the verifier's `verify_operation_write_set` conjunct
//! checks — from the exact PREPARED successor. Locator facts (the admitted
//! position, THE debit mutation index) are OUTPUTS of this build, never
//! predictions made beside it.

use std::collections::BTreeMap;

use dsm::economic::admission::{
    AcceptedAdmissionCoords, EconomicAdmissionState, PendingEconomicAdmission,
};
use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use dsm::economic::claim_envelope::sign_economic_root_claim;
use dsm::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    ValidatedEconomicRoot,
};
use dsm::economic::register::RegisteredEconomicRoot;
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{build_write_set, CreditSourceFacts};
use dsm::storage_object::immutable_inner;
use dsm::types::device_state::RelationshipChainState;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_registers::{register_economic_root, LiveRegisterResolver};
use crate::sdk::storage_set::{canonical_set, StorageSet};
use crate::storage::client_db;
use crate::storage::client_db::economic_lineage;

/// The claimant's committed network, from the STORED genesis record — the
/// same value Genesis v3 committed. Fail closed: no record, no admission.
/// The caller never chooses the network.
pub(crate) fn committed_network_id() -> Result<Vec<u8>, DsmError> {
    let g_vec = crate::sdk::app_state::AppState::get_genesis_hash().ok_or_else(|| {
        DsmError::storage("no genesis identity".to_string(), None::<std::io::Error>)
    })?;
    let g: [u8; 32] = g_vec
        .as_slice()
        .try_into()
        .map_err(|e| storage_err("genesis identity", e))?;
    let genesis_b32 = crate::util::text_id::encode_base32_crockford(&g);
    match crate::storage::client_db::get_genesis_record_by_id(&genesis_b32) {
        Ok(Some(rec)) => Ok(rec.network_id.into_bytes()),
        Ok(None) => Err(DsmError::storage(
            "no stored genesis record — cannot determine the committed network".to_string(),
            None::<std::io::Error>,
        )),
        Err(e) => Err(DsmError::storage(
            format!("genesis record: {e}"),
            None::<std::io::Error>,
        )),
    }
}

/// A finished admission, as the neutral machinery reports it.
#[derive(Debug, Clone, Copy)]
pub struct AdmittedOutcome {
    pub economic_position: u64,
}

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// The successful outcome: what the route reports.
pub struct ClaimOutcome {
    pub tokens_received: u64,
    pub economic_position: u64,
}

/// The validated economic root this device holds, or a fresh activation.
///
/// `activate` refuses a device that held value at its activation point —
/// calling those holdings "position 0" would be self-rooting at the base — so
/// a legacy value-holding device surfaces `UnsupportedLegacyEconomicState`
/// here. The activation point is the head the first admission was built on:
/// with nothing pending that is the head itself, and with the first admission
/// pending it is the head less that admission's own credit, read from its
/// frozen witness
/// ([`EconomicActivationSnapshot::before_first_admission`]).
pub(crate) fn validated_root_or_activate(
    core: &CoreSDK,
) -> Result<ValidatedEconomicRoot, DsmError> {
    if let Some(admitted) =
        economic_lineage::get_admitted().map_err(|e| storage_err("load admitted", e))?
    {
        // THE LOCAL FENCE, AT THE ONE PLACE EVERY LOCAL PRODUCER READS ITS
        // PREDECESSOR. `stage_admission`, the recipient prevalidation and the
        // resume path all reach their predecessor through here, so a
        // conditional position that has selected no root stops all of them at
        // once — and stops them with a reason, rather than by handing back
        // whichever of its two roots happened to be stored.
        return ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
            .map_err(|e| DsmError::invalid_operation(e.to_string()));
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let snapshot = match head.pending_economic_admission() {
        None => EconomicActivationSnapshot {
            online_balances_empty: head.balances_snapshot().is_empty(),
            outstanding_offline_allocation: head.holds_offline_value(),
        },
        Some(first) => {
            let (_, witness) = frozen_witness_of(first)?;
            EconomicActivationSnapshot::before_first_admission(&head, &witness)
                .map_err(|e| storage_err("activation point", e))?
        }
    };
    activate(snapshot).map_err(|e| DsmError::invalid_operation(e.to_string()))
}

/// The frozen witness of `pending`: the exact bytes frozen with its advance,
/// and their decode, bound to the admission by its operation digest and
/// post-root. Never re-derived.
fn frozen_witness_of(
    pending: &PendingEconomicAdmission,
) -> Result<(Vec<u8>, EconomicTransitionWitness), DsmError> {
    let witness_key_prefix = format!(
        "immutable::{}::",
        String::from_utf8_lossy(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ.source_bytes()
        )
    );
    let witness_bytes =
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            &witness_key_prefix,
            "economic-transition-witness",
        )
        .map_err(|e| storage_err("load frozen witness", e))?
        .ok_or_else(|| {
            DsmError::storage(
                "no frozen witness for the pending admission".to_string(),
                None::<std::io::Error>,
            )
        })?;
    let witness = dsm::economic::decode::decode_transition_witness(&witness_bytes)
        .map_err(|e| storage_err("decode frozen witness", e))?;
    let coords = pending
        .accepted_coords()
        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;
    if witness.operation_digest != pending.operation_digest
        || witness.post_economic_root != coords.post_economic_root
    {
        return Err(DsmError::storage(
            "frozen witness does not match the pending admission".to_string(),
            None::<std::io::Error>,
        ));
    }
    Ok((witness_bytes, witness))
}

/// This device's admitted economic root and the tree that recomputes it, for
/// a holdings proof to a connected application (DSM Amendment A11): the
/// proof names `(position, root)` for a foreign verifier, which validates the
/// root itself, and re-derives nothing. `None` before the first admission: a
/// device that has admitted nothing has no position to prove at, and proving
/// never activates it.
pub(crate) fn admitted_root_and_tree(
) -> Result<Option<(ValidatedEconomicRoot, EconomicSmt, AdmittedPreState)>, DsmError> {
    let Some(admitted) =
        economic_lineage::get_admitted().map_err(|e| storage_err("load admitted", e))?
    else {
        return Ok(None);
    };
    let validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(admitted)
        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;
    let (tree, pre) = producer_tree_and_pre_state(&validated)?;
    Ok(Some((validated, tree, pre)))
}

/// The producer-side economic tree at `validated`: Core's
/// ([`producer_tree_and_pre_state`]).
pub(crate) fn producer_tree(validated: &ValidatedEconomicRoot) -> Result<EconomicSmt, DsmError> {
    Ok(producer_tree_and_pre_state(validated)?.0)
}

/// The admitted pre-state a write set reads: every balance `R_econ` holds,
/// owned so it can outlive the decode, and the position the next transition
/// lands at. Core decides which leaf classes a write set starts from
/// (`ValidatedEconomicRoot::admitted_tree`).
#[derive(Debug, Default, Clone)]
pub(crate) struct AdmittedPreState {
    pub balances: BTreeMap<[u8; 32], u64>,
    /// The position the next transition LANDS AT: the successor of the
    /// admitted root these balances were decoded from.
    pub economic_position: u64,
}

impl AdmittedPreState {
    /// The borrowed view `build_write_set` takes.
    pub fn as_write_set_pre_state(&self) -> dsm::economic::write_set::EconomicPreState<'_> {
        dsm::economic::write_set::EconomicPreState::new(&self.balances, self.economic_position)
    }
}

/// The producer tree PLUS the admitted pre-state, both Core's: this device's
/// leaf cache handed to `ValidatedEconomicRoot::admitted_tree`, which binds
/// every row to its state and refuses rows that do not recompute the
/// validated root. This module computes no root (SoFi §2.1). Admission
/// pre-states come from `R_econ` ITSELF — never the device head, whose
/// balance map can carry credits no admission backs (a received transfer
/// awaiting PR4 recipient admission). Building from the head would pair a
/// mutation pre-state the validated pre-root cannot prove; building from the
/// tree makes unadmitted value simply unspendable, which is the economic-root
/// guarantee working.
pub(crate) fn producer_tree_and_pre_state(
    validated: &ValidatedEconomicRoot,
) -> Result<(EconomicSmt, AdmittedPreState), DsmError> {
    // The NEXT position: a pre-state at `p` is the pre-state of `p + 1`.
    // CHECKED: a counter with no successor is a refusal, never a clamp — a
    // saturated position would silently claim to be its own successor.
    let economic_position = validated
        .economic_position()
        .checked_add(1)
        .ok_or_else(|| {
            DsmError::invalid_operation("economic position has no successor".to_string())
        })?;
    let rows =
        economic_lineage::load_leaf_cache().map_err(|e| storage_err("load leaf cache", e))?;
    let (tree, balances) = validated
        .admitted_tree(&rows)
        .map_err(|e| {
            DsmError::storage(
                format!(
                    "economic leaf cache: {e} — discarded; witness replay recovery is required \
                     and no replay source exists yet"
                ),
                None::<std::io::Error>,
            )
        })?
        .into_parts();
    Ok((
        tree,
        AdmittedPreState {
            balances,
            economic_position,
        },
    ))
}

/// The portable P0–P6 authority material for THIS device, built from the
/// cached wallet seed (owner-side; verification stays seedless).
pub(crate) struct AuthorityMaterial {
    pub bytes: Vec<u8>,
    pub addr: [u8; 32],
    /// `t_0` — the transition DIGEST the manifest binds (never a tree root).
    pub position: [u8; 32],
}

pub(crate) fn authority_material(
    network_id: &[u8],
    genesis: &[u8; 32],
) -> Result<AuthorityMaterial, DsmError> {
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::storage(
                "no cached wallet seed — cannot build authority evidence".to_string(),
                None::<std::io::Error>,
            )
        })?;
    let (bytes, position) = crate::sdk::identity_presentation::build_authority_evidence(
        &wallet_seed,
        crate::sdk::identity_presentation::OwnerIdentityInputs::beta(network_id),
        genesis,
    )?;
    let addr = dsm::economic::authority_evidence::authority_evidence_addr(&bytes);
    Ok(AuthorityMaterial {
        bytes,
        addr,
        position,
    })
}

/// Everything a committed admission carries, built from the exact prepared
/// successor by the ONE write-set table.
pub(crate) struct DsmAdmissionParts {
    pub witness: EconomicTransitionWitness,
    pub manifest: EconomicAdmissionManifest,
    pub coords: AcceptedAdmissionCoords,
    pub artifacts: Vec<(String, Vec<u8>, &'static str)>,
    /// THE debit mutation's index in the built witness, for the ONE shape that
    /// has a wire locator — the online Transfer. This is the built value, never
    /// a prediction.
    pub debit_mutation_index: Option<u32>,
}

/// Build a DSM-substrate admission from the exact prepared successor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dsm_admission(
    genesis: &[u8; 32],
    devid: &[u8; 32],
    chain_state: &RelationshipChainState,
    operation: &Operation,
    pre_state: &AdmittedPreState,
    tree: &mut EconomicSmt,
    facts: &CreditSourceFacts,
    authority: &AuthorityMaterial,
    extra_artifacts: Vec<(String, Vec<u8>, &'static str)>,
) -> Result<DsmAdmissionParts, DsmError> {
    let c_dsm_plus = chain_state.compute_chain_tip();
    let op_bytes = operation.to_bytes();
    let op_digest = dsm::economic::admission::dsm_operation_digest(&op_bytes);
    let econ_op_id =
        dsm::economic::admission::dsm_economic_operation_id(genesis, devid, &c_dsm_plus);

    let built = build_write_set(
        operation,
        genesis,
        devid,
        &econ_op_id,
        &pre_state.as_write_set_pre_state(),
        tree,
        facts,
    )
    .map_err(|e| DsmError::invalid_operation(format!("write set: {e}")))?;
    // Both roots the witness names are the builder's, never this module's.
    let pre_root = built.pre_root;
    // THE DEBIT LOCATOR IS A TRANSFER FACT, AND ONLY A TRANSFER FACT. Its one
    // consumer is the online-transfer wire, where the recipient uses it to
    // locate the sender's debit; a Transfer sender's write set has exactly one
    // balance debit, so "the first mutation whose amount fell" is exact there.
    // It is silently wrong for any multi-leg write set — a funded vault
    // creation debits TWO balances, a close draws down TWO reserves — where
    // that scan names one arbitrary leg. So it is structurally confined to the
    // shape it is sound for: every other operation yields `None`, and a caller
    // needing a locator for one of them gets no answer rather than a wrong one.
    let debit_mutation_index = if matches!(operation, Operation::Transfer { .. }) {
        built
            .mutations
            .iter()
            .position(|m| {
                let pre = m
                    .pre_state
                    .as_ref()
                    .and_then(|s| s.credit_amount())
                    .unwrap_or(0);
                let post = m
                    .post_state
                    .as_ref()
                    .and_then(|s| s.credit_amount())
                    .unwrap_or(0);
                post < pre
            })
            .map(u32::try_from)
            .transpose()
            .map_err(|e| storage_err("debit mutation index", e))?
    } else {
        None
    };

    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        econ_op_id,
        op_digest,
        built.mutations,
        built.credit_sources,
    )
    .map_err(|e| storage_err("witness", e))?;
    let witness_bytes = witness
        .encode()
        .map_err(|e| storage_err("witness encode", e))?;
    let witness_addr = immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        &witness_bytes,
    );

    let sk = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?
        .1;
    let successor_bytes = dsm::economic::successor_evidence::sign_dsm_successor_evidence(
        &chain_state.rel_key,
        &chain_state.embedded_parent,
        &chain_state.counterparty_devid,
        &op_bytes,
        &chain_state.entropy,
        chain_state.encapsulated_entropy.as_deref(),
        genesis,
        devid,
        &sk,
    )
    .map_err(|e| storage_err("successor evidence", e))?;
    let substrate_addr =
        dsm::economic::successor_evidence::successor_evidence_addr(&successor_bytes);

    let manifest = EconomicAdmissionManifest::new(
        authority.position,
        witness_addr,
        authority.addr,
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: substrate_addr,
        },
        witness.derived_provenance_index(),
    )
    .map_err(|e| storage_err("manifest", e))?;
    let manifest_bytes = manifest
        .encode()
        .map_err(|e| storage_err("manifest encode", e))?;
    let manifest_addr = manifest
        .addr()
        .map_err(|e| storage_err("manifest addr", e))?;

    let coords = AcceptedAdmissionCoords {
        post_economic_root: built.post_root,
        accepted_substrate_addr: substrate_addr,
        admission_manifest_addr: manifest_addr,
        substrate: dsm::economic::admission::AcceptedSubstrateCoords::Successor {
            c_dsm_plus,
            embedded_parent: chain_state.embedded_parent,
        },
    };
    let mut artifacts = extra_artifacts;
    artifacts.push((
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
            &witness_bytes,
        ),
        witness_bytes,
        "economic-transition-witness",
    ));
    artifacts.push((
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
            &manifest_bytes,
        ),
        manifest_bytes,
        "economic-admission-manifest",
    ));
    artifacts.push((
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE,
            &successor_bytes,
        ),
        successor_bytes,
        "economic-dsm-successor-evidence",
    ));
    artifacts.push((
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
            &authority.bytes,
        ),
        authority.bytes.clone(),
        "economic-authority-evidence",
    ));
    Ok(DsmAdmissionParts {
        witness,
        manifest,
        coords,
        artifacts,
        debit_mutation_index,
    })
}

/// The authoritative economic predecessor and everything derived from it.
///
/// This is phase one of the ONE admission pipeline. Both typed facades —
/// [`admitted_self_loop_operation`] and [`admitted_dlv_create_funded`] — run
/// it, then perform their own advance, then run [`finish_admission`]. The
/// facades differ only in the SHAPE of the advance (a balance delta versus a
/// reserve mutation, plain versus staged writers); the admission itself has a
/// single implementation and is never duplicated per operation.
///
/// `pre_state` is the snapshot the write set will actually read — balances it
/// debits, vault reserves it draws down. A caller that needs a sufficiency
/// answer must take it from HERE and not re-read the economic root separately:
/// a second, independently-timed lookup reasons from a different observation
/// than the transition it is attempting.
pub(crate) struct StagedAdmission {
    pub network_id: Vec<u8>,
    pub genesis: [u8; 32],
    pub devid: [u8; 32],
    pub set: StorageSet,
    pub validated: ValidatedEconomicRoot,
    pub tree: EconomicSmt,
    pub pre_state: AdmittedPreState,
    pub authority: AuthorityMaterial,
    pub facts: CreditSourceFacts,
    pub extra_artifacts: Vec<(String, Vec<u8>, &'static str)>,
    pub prepared: PendingEconomicAdmission,
}

/// The predecessor an operation's published object was built on and names —
/// a vault genesis its `create_position`, a setup the validated root it is
/// built against. The admission is refused before anything is written unless
/// the staged predecessor is exactly it: a pending admission resumed on the
/// way in, or any other advance since the object was built, moves the
/// predecessor, and an object admitted at a position other than the one it
/// names would stand in the lineage naming a position it does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BuiltOn {
    pub position: u64,
    pub root: [u8; 32],
}

impl BuiltOn {
    pub(crate) fn of(validated: &ValidatedEconomicRoot) -> Self {
        Self {
            position: validated.economic_position(),
            root: validated.economic_root(),
        }
    }

    /// Refuse unless `validated` is the predecessor the object was built on.
    fn admits(&self, validated: &ValidatedEconomicRoot) -> Result<(), DsmError> {
        let staged = Self::of(validated);
        if staged == *self {
            return Ok(());
        }
        Err(DsmError::invalid_operation(format!(
            "the operation was built on position {} at root {}; the predecessor this device \
             stands on is position {} at root {} — build it again on that",
            self.position,
            crate::util::text_id::encode_base32_crockford(&self.root),
            staged.position,
            crate::util::text_id::encode_base32_crockford(&staged.root),
        )))
    }
}

/// Resolve the admitted predecessor, derive the producer tree and balances from
/// it, and prepare the successor coordinate this admission will CAS against.
///
/// Any pending admission is resumed first, so the caller always stages against
/// a settled predecessor. An operation whose published object names the
/// predecessor it was built on (`built_on`) is refused here, before anything
/// is written, when that is not the predecessor staged.
pub(crate) async fn stage_admission(
    core: &CoreSDK,
    operation: &Operation,
    facts: CreditSourceFacts,
    extra_artifacts: Vec<(String, Vec<u8>, &'static str)>,
    built_on: Option<BuiltOn>,
) -> Result<StagedAdmission, DsmError> {
    let network_id = committed_network_id()?;
    if let Some(pending) = core
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
    {
        resume_pending_admission(core, &network_id, pending).await?;
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(&network_id)?;
    let validated = validated_root_or_activate(core)?;
    if let Some(built_on) = built_on {
        built_on.admits(&validated)?;
    }
    let (tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let authority = authority_material(&network_id, &genesis)?;
    let target_position = validated.economic_position() + 1;
    let op_digest = dsm::economic::admission::dsm_operation_digest(&operation.to_bytes());
    let prepared = PendingEconomicAdmission::prepared(
        dsm::economic::admission::PendingAdmissionKind::DsmBacked,
        target_position,
        validated.economic_root(),
        op_digest,
    );
    Ok(StagedAdmission {
        network_id,
        genesis,
        devid,
        set,
        validated,
        tree,
        pre_state,
        authority,
        facts,
        extra_artifacts,
        prepared,
    })
}

/// One ADMITTED self-loop operation (Burn, CreateToken), end to end, with the
/// balance deltas its conservation rule takes — one debit for a burn; the ERA
/// fee debit and the genesis-supply credit for a creation: resume any pending
/// admission, assemble prerequisites, run the fence-
/// coupled advance through the generalized seam, publish/register/validate,
/// admit. The route gets the advance outcome back for its response
/// projection. The operation registers BEFORE the route reports success.
///
/// `facts` are the operation's credit-source facts, and `extra_artifacts` any
/// evidence objects beside them. The artifacts are frozen in the SAME
/// transaction as the advance and the pending admission, so the crash
/// invariant holds: either the operation never became locally accepted, or
/// the operation, its pending admission and its exact evidence bytes all
/// exist durably. `built_on` is the predecessor the operation's published
/// object names, when it names one: [`stage_admission`] refuses before the
/// advance unless the staged predecessor is exactly it.
pub(crate) async fn admitted_self_loop_operation(
    core: &CoreSDK,
    operation: Operation,
    deltas: &[dsm::types::device_state::BalanceDelta],
    facts: CreditSourceFacts,
    extra_artifacts: Vec<(String, Vec<u8>, &'static str)>,
    in_tx_extra: Option<
        &(dyn Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
        ) -> Result<(), DsmError>
              + Sync),
    >,
    built_on: Option<BuiltOn>,
) -> Result<(dsm::types::device_state::AdvanceOutcome, AdmittedOutcome), DsmError> {
    let StagedAdmission {
        network_id,
        genesis,
        devid,
        set,
        validated,
        mut tree,
        pre_state,
        authority,
        facts,
        extra_artifacts,
        prepared,
        ..
    } = stage_admission(core, &operation, facts, extra_artifacts, built_on).await?;
    let mut built: Option<DsmAdmissionParts> = None;
    let (outcome, pending) = core.admitted_advance(
        operation.clone(),
        deltas,
        prepared,
        |chain_state| {
            let parts = build_dsm_admission(
                &genesis,
                &devid,
                chain_state,
                &operation,
                &pre_state,
                &mut tree,
                &facts,
                &authority,
                extra_artifacts,
            )?;
            let coords = parts.coords;
            let artifacts = parts.artifacts.clone();
            built = Some(parts);
            Ok((coords, artifacts))
        },
        &set.id(),
        in_tx_extra.map(|f| {
            f as &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>
        }),
    )?;
    let parts = built.ok_or_else(|| {
        DsmError::storage(
            "advance committed without building the witness".to_string(),
            None::<std::io::Error>,
        )
    })?;
    let admitted = finish_admission(
        core,
        &network_id,
        &set,
        &validated,
        parts.witness,
        parts.manifest,
        AdmittedSubstrate::Dsm(Box::new(operation)),
        pending,
        Vec::new(),
    )
    .await?;
    Ok((outcome, admitted))
}

/// The frozen-artifact purpose of an offline boundary's body.
const OFFLINE_BOUNDARY_BODY_PURPOSE: &str = "economic-offline-boundary-body";

/// One ADMITTED offline boundary, end to end: a load of `amount` of `asset`
/// from the online balance into the offline account of `bundle`, or an
/// unload back. Resume any pending admission, take the boundary in Core,
/// build its body, write set, witness and manifest from exactly what Core
/// took, make the boundary and its admission durable together, then publish,
/// register, validate and admit — the one finish every admission runs. The
/// boundary registers BEFORE the route reports success.
/// This device's offline account's ancestry, for the boundary `boundary` Core
/// took: the anchor its bundle commits, where the account stood since its last
/// boundary, and every spend this device's anchor released since, which the
/// boundary exposes. Read under the state-machine lock the boundary is taken
/// under, so no spend lands between the chain and the boundary.
fn own_boundary_ancestry(
    pin: &crate::anchor::AnchorPin,
    bundle: &[u8; 32],
    boundary: &dsm::types::device_state::OfflineBoundaryOutcome,
) -> Result<dsm::economic::offline_boundary::BoundaryAncestry, DsmError> {
    use dsm::economic::offline_boundary::{BoundaryAncestry, BoundaryAnchor, BoundarySince};
    if pin.bundle != *bundle {
        return Err(DsmError::invalid_operation(
            "offline boundary: the attached anchor is not the account's",
        ));
    }
    let chain = client_db::offline_spends::own_offline_spends(bundle)
        .map_err(|e| storage_err("this device's unexposed offline spends", e))?;
    let funded = match &boundary.account_move.before {
        dsm::types::offline_account::StepBefore::Boundary { funding_chain, .. } => *funding_chain,
        dsm::types::offline_account::StepBefore::Spend { .. } => {
            return Err(DsmError::invalid_operation(
                "offline boundary: Core took a spend where a boundary was asked",
            ))
        }
    };
    let since = match (funded, chain.first()) {
        (None, _) => BoundarySince::Opened {
            frontier: boundary.account_move.account.frontier(),
        },
        (Some(_), Some(first)) => BoundarySince::Previous {
            account_root: dsm::types::offline_chain::SpendHop::from_bytes(first)?.starts_from(),
        },
        (Some(_), None) => BoundarySince::Previous {
            account_root: boundary.pre_account_root,
        },
    };
    Ok(BoundaryAncestry {
        anchor: BoundaryAnchor {
            anchor_id: pin.anchor_id,
            pk_chip: pin.pk_chip.clone(),
            pk_host: pin.partition_pk.clone(),
            enrolled_counter: pin.enrolled_counter,
            birth_commitment: pin.birth_commitment,
        },
        since,
        chain,
    })
}

pub(crate) async fn admitted_offline_boundary(
    core: &CoreSDK,
    bundle: [u8; 32],
    kind: dsm::types::device_state::OfflineBoundaryKind,
    asset: [u8; 32],
    amount: u64,
) -> Result<
    (
        dsm::types::device_state::OfflineBoundaryOutcome,
        AdmittedOutcome,
    ),
    DsmError,
> {
    use dsm::economic::offline_boundary::{
        offline_boundary_evidence_addr, offline_boundary_operation_digest, OfflineBoundaryBody,
    };
    let network_id = committed_network_id()?;
    if let Some(pending) = core
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
    {
        resume_pending_admission(core, &network_id, pending).await?;
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(&network_id)?;
    let validated = validated_root_or_activate(core)?;
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let authority = authority_material(&network_id, &genesis)?;
    let pending_kind = match kind {
        dsm::types::device_state::OfflineBoundaryKind::Load => {
            dsm::economic::admission::PendingAdmissionKind::OfflineLoad {
                asset_policy_commit: asset,
            }
        }
        dsm::types::device_state::OfflineBoundaryKind::Unload => {
            dsm::economic::admission::PendingAdmissionKind::OfflineUnload {
                asset_policy_commit: asset,
            }
        }
        // A settlement moves nothing across the account: it credits a payment
        // received offline, and is admitted by `admitted_offline_settlement`.
        dsm::types::device_state::OfflineBoundaryKind::Settle => {
            return Err(DsmError::invalid_operation(
                "offline boundary: a settlement is no account boundary — it is admitted as the \
                 settlement of the payment it names",
            ))
        }
    };
    let mut built: Option<(
        EconomicTransitionWitness,
        EconomicAdmissionManifest,
        Vec<u8>,
    )> = None;
    // The anchor the account belongs to, read before the boundary is taken: its
    // lock is never taken under the state-machine lock the boundary holds.
    let pin = core.attached_anchor_pin().ok_or_else(|| {
        DsmError::invalid_operation(
            "offline boundary: no anchor is attached, so the account's anchor cannot be named",
        )
    })?;
    let (outcome, pending) = core.admitted_boundary(
        &bundle,
        kind,
        &asset,
        amount,
        |boundary| {
            let body = OfflineBoundaryBody::of(
                boundary,
                kind,
                bundle,
                asset,
                amount,
                own_boundary_ancestry(&pin, &bundle, boundary)?,
            )?
            .encode()
            .map_err(|e| storage_err("boundary body", e))?;
            let digest = offline_boundary_operation_digest(&body);
            let evidence_addr = offline_boundary_evidence_addr(&body);
            let write_set = dsm::economic::write_set::build_boundary_write_set(
                &dsm::economic::write_set::BoundaryEffect {
                    kind,
                    asset,
                    amount,
                    boundary_id: boundary.operation_id,
                },
                &genesis,
                &devid,
                &pre_state.as_write_set_pre_state(),
                &mut tree,
            )
            .map_err(|e| DsmError::invalid_operation(format!("write set: {e}")))?;
            // Both roots are the builder's, never this module's.
            let pre_root = write_set.pre_root;
            let witness = EconomicTransitionWitness::new(
                pre_root,
                write_set.post_root,
                boundary.operation_id,
                digest,
                write_set.mutations,
                write_set.credit_sources,
            )
            .map_err(|e| storage_err("witness", e))?;
            let witness_bytes = witness
                .encode()
                .map_err(|e| storage_err("witness encode", e))?;
            let manifest = EconomicAdmissionManifest::new(
                authority.position,
                immutable_inner(
                    dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                    &witness_bytes,
                ),
                authority.addr,
                AdmissionSubstrate::OfflineBoundary { evidence_addr },
                witness.derived_provenance_index(),
            )
            .map_err(|e| storage_err("manifest", e))?;
            let manifest_bytes = manifest
                .encode()
                .map_err(|e| storage_err("manifest encode", e))?;
            let coords = AcceptedAdmissionCoords {
                post_economic_root: write_set.post_root,
                accepted_substrate_addr: evidence_addr,
                admission_manifest_addr: manifest
                    .addr()
                    .map_err(|e| storage_err("manifest addr", e))?,
                substrate: dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary,
            };
            let key = |tag, bytes: &[u8]| {
                crate::sdk::economic_registers::immutable_object_key(tag, bytes)
            };
            let artifacts = vec![
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                        &witness_bytes,
                    ),
                    witness_bytes,
                    "economic-transition-witness",
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
                        &manifest_bytes,
                    ),
                    manifest_bytes,
                    "economic-admission-manifest",
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE,
                        &body,
                    ),
                    body.clone(),
                    OFFLINE_BOUNDARY_BODY_PURPOSE,
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
                        &authority.bytes,
                    ),
                    authority.bytes.clone(),
                    "economic-authority-evidence",
                ),
            ];
            let prepared = PendingEconomicAdmission::prepared(
                pending_kind,
                validated.economic_position() + 1,
                pre_root,
                digest,
            );
            built = Some((witness, manifest, body));
            Ok((prepared, coords, artifacts))
        },
        &set.id(),
    )?;
    let (witness, manifest, body) = built.ok_or_else(|| {
        DsmError::storage(
            "boundary committed without building its admission".to_string(),
            None::<std::io::Error>,
        )
    })?;
    let admitted = finish_admission(
        core,
        &network_id,
        &set,
        &validated,
        witness,
        manifest,
        AdmittedSubstrate::OfflineBoundary(body),
        pending,
        Vec::new(),
    )
    .await?;
    Ok((outcome, admitted))
}

/// Settle a payment this device received offline (SA-91): once the payer's
/// online history exposed the spend — a walk of the payer this device ran
/// itself recorded the exposure — the payment is credited to the online balance
/// by an admitted economic transition of its own, funded by that spend and
/// consumed once. The settlement, its admission and the pending receipt's
/// settled mark are durable together; then the one finish runs.
pub(crate) async fn admitted_offline_settlement(
    core: &CoreSDK,
    release_message: [u8; 32],
) -> Result<AdmittedOutcome, DsmError> {
    use dsm::economic::offline_boundary::{
        offline_boundary_evidence_addr, offline_boundary_operation_digest, OfflineSettlementBody,
    };
    let (receipt, settled) = client_db::offline_receipts::offline_receipt(&release_message)
        .map_err(|e| storage_err("the payment received offline", e))?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "offline settlement: no payment received under this release",
            )
        })?;
    if let Some(position) = settled {
        return Err(DsmError::invalid_operation(format!(
            "offline settlement: the payment was settled at position {position}"
        )));
    }
    let exposure = client_db::economic_lineage::offline_exposure(&release_message)
        .map_err(|e| storage_err("the exposure of the payment", e))?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "offline settlement: the payer's online history has not exposed this spend yet — \
                 the payment stays pending",
            )
        })?;
    if *exposure.genesis() != receipt.payer_genesis
        || *exposure.device_id() != receipt.payer_device
        || *exposure.bundle() != receipt.bundle
        || exposure.payment().asset != receipt.asset
        || exposure.payment().amount != receipt.amount
    {
        return Err(DsmError::invalid_operation(
            "offline settlement: the exposed payment is not the one this device received",
        ));
    }
    let network_id = committed_network_id()?;
    if let Some(pending) = core
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
    {
        resume_pending_admission(core, &network_id, pending).await?;
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(&network_id)?;
    let validated = validated_root_or_activate(core)?;
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let authority = authority_material(&network_id, &genesis)?;
    let body = OfflineSettlementBody::of(&exposure).encode();
    let verified = OfflineSettlementBody::verify(&body, &genesis, &devid, &exposure)?;
    let mut built: Option<(EconomicTransitionWitness, EconomicAdmissionManifest)> = None;
    let pending = core.admitted_settlement(
        &receipt,
        || {
            let digest = offline_boundary_operation_digest(&body);
            let evidence_addr = offline_boundary_evidence_addr(&body);
            let pre_root = tree.root();
            let write_set = dsm::economic::write_set::build_boundary_write_set(
                &dsm::economic::write_set::BoundaryEffect {
                    kind: dsm::types::device_state::OfflineBoundaryKind::Settle,
                    asset: verified.asset(),
                    amount: verified.amount(),
                    boundary_id: verified.operation_id(),
                },
                &genesis,
                &devid,
                &pre_state.as_write_set_pre_state(),
                &mut tree,
            )
            .map_err(|e| DsmError::invalid_operation(format!("write set: {e}")))?;
            let witness = EconomicTransitionWitness::new(
                pre_root,
                write_set.post_root,
                verified.operation_id(),
                digest,
                write_set.mutations,
                write_set.credit_sources,
            )
            .map_err(|e| storage_err("witness", e))?;
            let witness_bytes = witness
                .encode()
                .map_err(|e| storage_err("witness encode", e))?;
            let manifest = EconomicAdmissionManifest::new(
                authority.position,
                immutable_inner(
                    dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                    &witness_bytes,
                ),
                authority.addr,
                AdmissionSubstrate::OfflineBoundary { evidence_addr },
                witness.derived_provenance_index(),
            )
            .map_err(|e| storage_err("manifest", e))?;
            let manifest_bytes = manifest
                .encode()
                .map_err(|e| storage_err("manifest encode", e))?;
            let coords = AcceptedAdmissionCoords {
                post_economic_root: write_set.post_root,
                accepted_substrate_addr: evidence_addr,
                admission_manifest_addr: manifest
                    .addr()
                    .map_err(|e| storage_err("manifest addr", e))?,
                substrate: dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary,
            };
            let key = |tag, bytes: &[u8]| {
                crate::sdk::economic_registers::immutable_object_key(tag, bytes)
            };
            let artifacts = vec![
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                        &witness_bytes,
                    ),
                    witness_bytes,
                    "economic-transition-witness",
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
                        &manifest_bytes,
                    ),
                    manifest_bytes,
                    "economic-admission-manifest",
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE,
                        &body,
                    ),
                    body.clone(),
                    OFFLINE_BOUNDARY_BODY_PURPOSE,
                ),
                (
                    key(
                        dsm::common::domain_tags::TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE,
                        &authority.bytes,
                    ),
                    authority.bytes.clone(),
                    "economic-authority-evidence",
                ),
            ];
            let prepared = PendingEconomicAdmission::prepared(
                dsm::economic::admission::PendingAdmissionKind::OfflineSettle {
                    asset_policy_commit: verified.asset(),
                },
                validated.economic_position() + 1,
                pre_root,
                digest,
            );
            built = Some((witness, manifest));
            Ok((prepared, coords, artifacts))
        },
        &set.id(),
    )?;
    let (witness, manifest) = built.ok_or_else(|| {
        DsmError::storage(
            "settlement committed without building its admission".to_string(),
            None::<std::io::Error>,
        )
    })?;
    finish_admission(
        core,
        &network_id,
        &set,
        &validated,
        witness,
        manifest,
        AdmittedSubstrate::OfflineBoundary(body),
        pending,
        Vec::new(),
    )
    .await
}

/// Settle every payment this device received offline that its payer's online
/// history now exposes (SA-91). Each payer is walked from this device's
/// frontier for it toward the head its register holds — the walk records the
/// spends the payer's boundaries exposed — and each exposed payment is settled
/// by its own admitted transition. A payment its payer has not exposed yet
/// stays pending; it is no failure. Returns how many were settled, and what
/// could not be done.
pub(crate) async fn settle_received_offline(core: &CoreSDK) -> (u32, Vec<String>) {
    let mut failures = Vec::new();
    let receipts = match client_db::offline_receipts::pending_offline_receipts() {
        Ok(receipts) => receipts,
        Err(e) => {
            failures.push(format!("the payments received offline are unreadable: {e}"));
            return (0, failures);
        }
    };
    let mut walked: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    for receipt in &receipts {
        if walked.insert(receipt.payer_device) {
            if let Err(e) = crate::sdk::economic_registers::prevalidate_contact(
                receipt.payer_genesis,
                receipt.payer_device,
            )
            .await
            {
                failures.push(format!(
                    "the payer {} of a payment received offline could not be walked: {e}",
                    crate::util::text_id::encode_base32_crockford(&receipt.payer_device)
                ));
            }
        }
    }
    let mut settled = 0u32;
    for receipt in receipts {
        match client_db::economic_lineage::offline_exposure(&receipt.release_message) {
            Ok(Some(_)) => match admitted_offline_settlement(core, receipt.release_message).await {
                Ok(_) => settled += 1,
                Err(e) => failures.push(format!("a payment received offline: {e}")),
            },
            Ok(None) => {}
            Err(e) => failures.push(format!("the exposure of a payment received offline: {e}")),
        }
    }
    (settled, failures)
}

/// ONE admission finish at a time on this device. The sync's crash recovery and
/// a live handler can both reach [`finish_admission`]; finishes must not
/// interleave. Held across the whole finish, which never re-enters itself.
fn admission_finish_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Whether `pending` is still this device's admission to finish.
///
/// * `Ok(None)`: the head still carries it (same position and operation), so
///   finish it.
/// * `Ok(Some(outcome))`: another finisher already admitted exactly it (its
///   position is the admitted one and the admitted root is its post-root), so
///   this call is a duplicate. Return that admission's outcome and write
///   nothing.
/// * `Err`: superseded or incoherent. Nothing is written.
fn admission_already_finished(
    core: &CoreSDK,
    pending: &PendingEconomicAdmission,
) -> Result<Option<AdmittedOutcome>, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    if head.pending_economic_admission().is_some_and(|current| {
        current.economic_position == pending.economic_position
            && current.operation_digest == pending.operation_digest
    }) {
        return Ok(None);
    }
    let coords = *pending
        .accepted_coords()
        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;
    match economic_lineage::get_admitted().map_err(|e| storage_err("load admitted", e))? {
        // A single-root admission at this position with this exact root is
        // the one shape that means "already finished". A conditional
        // admission does not match — not because it is wrong, but because a
        // position that has selected no root has not finished anything.
        Some(dsm::economic::lineage::AdmittedEconomicPosition::SingleRoot {
            economic_position: position,
            economic_root: root,
            ..
        }) if position == pending.economic_position && root == coords.post_economic_root => {
            Ok(Some(AdmittedOutcome {
                economic_position: position,
            }))
        }
        Some(dsm::economic::lineage::AdmittedEconomicPosition::SingleRoot { .. })
        | Some(dsm::economic::lineage::AdmittedEconomicPosition::ResolvedSofi { .. })
        | Some(dsm::economic::lineage::AdmittedEconomicPosition::UnresolvedSofi { .. })
        | None => Err(DsmError::storage(
            format!(
                "the pending admission at position {} is no longer this device's to finish: \
                 the head carries another or none, and it is not the admitted coordinate",
                pending.economic_position
            ),
            None::<std::io::Error>,
        )),
    }
}

/// The substrate an admission's finish validates against: the exact
/// operation a DSM successor carried, or the exact bytes of an offline
/// boundary's body. The finish verifies each again before it trusts it.
pub(crate) enum AdmittedSubstrate {
    // Boxed: an operation can carry a SPHINCS+ signature.
    Dsm(Box<Operation>),
    OfflineBoundary(Vec<u8>),
}

/// Everything after local acceptance. Separated so recovery re-enters here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_admission(
    core: &CoreSDK,
    network_id: &[u8],
    set: &StorageSet,
    validated: &ValidatedEconomicRoot,
    witness: EconomicTransitionWitness,
    manifest: EconomicAdmissionManifest,
    substrate: AdmittedSubstrate,
    pending: PendingEconomicAdmission,
    // Frozen only in the ADMIT transaction (the RELEASE object): nothing
    // here may reach the network before ECON_ADMITTED.
    post_admit_artifacts: Vec<(String, Vec<u8>, &'static str)>,
) -> Result<AdmittedOutcome, DsmError> {
    // SERIALIZED COMPARE-AND-FINISH: one finish at a time, and only of the
    // admission the head still carries. A duplicate returns the admitted
    // outcome; a superseded one refuses before anything is signed or written.
    let finishing = admission_finish_lock().lock().await;
    let outcome = finish_locked(
        core,
        network_id,
        set,
        validated,
        witness,
        manifest,
        substrate,
        pending,
        post_admit_artifacts,
    )
    .await;
    drop(finishing);
    outcome
}

/// [`finish_admission`]'s work, run while the finish lock is held.
#[allow(clippy::too_many_arguments)]
async fn finish_locked(
    core: &CoreSDK,
    network_id: &[u8],
    set: &StorageSet,
    validated: &ValidatedEconomicRoot,
    witness: EconomicTransitionWitness,
    manifest: EconomicAdmissionManifest,
    substrate: AdmittedSubstrate,
    mut pending: PendingEconomicAdmission,
    post_admit_artifacts: Vec<(String, Vec<u8>, &'static str)>,
) -> Result<AdmittedOutcome, DsmError> {
    if let Some(outcome) = admission_already_finished(core, &pending)? {
        return Ok(outcome);
    }
    let operation_digest = pending.operation_digest;
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let (public_key, secret_key) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;

    let coords = *pending
        .accepted_coords()
        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;
    // The evidence the claim names, put to the set and read back `Stored`
    // (storage spec §5 rule 6) before the claim is registered: a root whose
    // evidence nobody holds would be registered but unwalkable. The sweep
    // carries the EXACT frozen bytes. Anything of this admission's own not
    // yet `Stored` holds the admission for resume; the next pass publishes
    // it again. Only this admission's evidence — frozen with its manifest,
    // bound to its root, for its set — holds it: an object the device owes
    // the set for anything else is the sweep's (`storage.sync`), and holding
    // every admission on the device's whole table let one object that can
    // never be published stop them all (SA-134).
    let manifest_key = crate::sdk::economic_registers::immutable_object_key_for_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
        &coords.admission_manifest_addr,
    );
    crate::handlers::artifact_republish::republish_frozen_with(&manifest_key)
        .await
        .map_err(|e| storage_err("publish admission evidence", e))?;
    let unpublished =
        crate::storage::client_db::frozen_publication_artifact::list_unpublished_frozen_with(
            &manifest_key,
        )
        .map_err(|e| storage_err("check evidence", e))?;
    if let Some(row) = unpublished.first() {
        return Err(storage_err(
            "publish admission evidence",
            format!(
                "{} is not Stored yet ({}) — the admission stays held for resume",
                row.object_key, row.last_error
            ),
        ));
    }
    pending.state = EconomicAdmissionState::EvidencePublished;
    core.update_pending_admission_state(&pending)?;

    // The root claim: frozen-or-sign-once BEFORE the first member write.
    let manifest_addr = coords.admission_manifest_addr;
    let k_root = dsm::economic::register::economic_root_register_key(
        &genesis,
        &devid,
        pending.economic_position,
    );
    let frozen_root = match economic_lineage::get_frozen_root_claim(pending.economic_position)
        .map_err(|e| storage_err("load frozen root claim", e))?
    {
        Some((_, bytes)) => bytes,
        None => {
            // The claim proves its own authority for this device's cell: it
            // carries the AttA under which this key derives the device id
            // (DSM Amendment A10). A key that does not derive it would sign a
            // claim recognition refuses, so none is signed.
            let att_a = crate::sdk::signing_authority::current_att_a()
                .map_err(|e| storage_err("signing authority", e))?;
            if dsm::core::identity::genesis_v2::derive_devid(&public_key, &att_a) != devid {
                return Err(DsmError::invalid_operation(
                    "root claim: this device's key and AttA do not derive its device id — \
                     local identity incoherent; refusing to sign a claim for its cell",
                ));
            }
            let body = dsm::economic::claim::EconomicRootClaimBody::new(
                genesis,
                devid,
                pending.economic_position,
                coords.post_economic_root,
                manifest_addr,
                set.id(),
                dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
                &public_key,
                att_a,
            )
            .map_err(|e| storage_err("root claim body", e))?;
            let bytes = sign_economic_root_claim(&body, &secret_key)
                .map_err(|e| storage_err("sign root claim", e))?;
            economic_lineage::put_frozen_root_claim(pending.economic_position, &k_root, &bytes)
                .map_err(|e| storage_err("freeze root claim", e))?;
            economic_lineage::get_frozen_root_claim(pending.economic_position)
                .map_err(|e| storage_err("re-read frozen root claim", e))?
                .map(|(_, b)| b)
                .ok_or_else(|| {
                    DsmError::storage(
                        "frozen root claim did not persist".to_string(),
                        None::<std::io::Error>,
                    )
                })?
        }
    };
    // The claim goes along the root cell's route, leader first. The route's
    // seed takes the root this device validated at `q - 1`, so nothing about
    // where the race is decided is chosen here.
    let cell = crate::sdk::economic_registers::root_cell(
        set,
        network_id,
        &genesis,
        &devid,
        pending.economic_position,
        &validated.economic_root(),
    )?;
    let write = register_economic_root(set, &cell, &frozen_root).await?;
    let at_leader = write.leader();
    match at_leader {
        crate::sdk::route_seats::AtLeader::Link => {
            pending.state = EconomicAdmissionState::Registered;
            core.update_pending_admission_state(&pending)?;
        }
        // Another claim is first at the root cell's leader: the position is
        // decided for it, and nothing of this claim was put there. Which
        // claim holds it is Core's reading of the cell, below.
        crate::sdk::route_seats::AtLeader::Taken => log::warn!(
            "root register: another claim is first at position {}'s leader",
            pending.economic_position
        ),
        crate::sdk::route_seats::AtLeader::Unanswered => {
            return Err(storage_err(
                "root register",
                "the root cell's leader did not answer — the admission stays held for resume",
            ))
        }
    }
    // The position is this device's only once its claim is FINAL at the
    // cell. Another claim holding the leader link — this trader's own SoFi
    // `C_q`, for one — takes the position, and this admission never lands.
    let settled =
        crate::sdk::economic_registers::root_claim_settlement(set, &cell, &frozen_root).await?;
    match settled {
        crate::sdk::economic_registers::RootClaimSettlement::Final => {}
        crate::sdk::economic_registers::RootClaimSettlement::Lost { holder } => {
            let taken_by = match holder.single_root() {
                Ok(claim) => format!(
                    "another root claim, for root {}",
                    crate::util::text_id::encode_base32_crockford(&claim.body().post_economic_root)
                ),
                Err(conditional) => conditional.to_string(),
            };
            return Err(DsmError::invalid_operation(format!(
                "position {} is held by {taken_by}: this admission cannot land there",
                pending.economic_position
            )));
        }
        crate::sdk::economic_registers::RootClaimSettlement::Pending(why) => {
            let what = match at_leader {
                crate::sdk::route_seats::AtLeader::Taken => {
                    "another claim is first at the leader, and the reads do not show it yet"
                }
                crate::sdk::route_seats::AtLeader::Link
                | crate::sdk::route_seats::AtLeader::Unanswered => "the claim is not final yet",
            };
            return Err(storage_err(
                "root register",
                format!("{what} ({why}) — the admission stays held for resume"),
            ));
        }
    }

    // The VERIFIER's answer — the same predicate any foreign device runs, from
    // the same object. This device decodes and verifies the EXACT envelope it
    // registered rather than re-assembling the fields from locals: a
    // disagreement between what was registered and what is validated here
    // would otherwise be unobservable, and a corrupted frozen row would pass.
    let registered = RegisteredEconomicRoot::from_verified_single_root(
        dsm::economic::claim_envelope::decode_registered_economic_claim(&frozen_root)
            .map_err(|e| DsmError::invalid_operation(format!("registered claim: {e}")))?
            .single_root()
            .map_err(|conditional| {
                DsmError::invalid_operation(format!("registered claim: {conditional}"))
            })?,
    );
    let accepted = match substrate {
        AdmittedSubstrate::Dsm(operation) => {
            let operation = *operation;
            let (embedded_parent, c_dsm_plus) = coords.substrate.successor().ok_or_else(|| {
                DsmError::invalid_operation(
                    "a DSM admission whose coordinates are not a successor's",
                )
            })?;
            AcceptedSubstrate::from_verified_dsm_successor(
                operation,
                c_dsm_plus,
                embedded_parent,
                coords.accepted_substrate_addr,
            )
        }
        AdmittedSubstrate::OfflineBoundary(body) => {
            if dsm::economic::offline_boundary::offline_boundary_evidence_addr(&body)
                != coords.accepted_substrate_addr
            {
                return Err(DsmError::invalid_operation(
                    "the boundary body is not the one the admission names",
                ));
            }
            let verified = match dsm::economic::offline_boundary::offline_body_kind(&body)? {
                dsm::economic::offline_boundary::OfflineBodyKind::Boundary => {
                    dsm::economic::offline_boundary::OfflineBoundaryBody::verify(
                        &body,
                        &genesis,
                        &devid,
                        head.public_key(),
                    )
                    .map(|(verified, ..)| verified)?
                }
                // A settlement is held to the exposure this device's own walk of
                // the payer recorded.
                dsm::economic::offline_boundary::OfflineBodyKind::Settlement => {
                    let named =
                        dsm::economic::offline_boundary::OfflineSettlementBody::decode(&body)
                            .map_err(|e| {
                                DsmError::invalid_operation(format!(
                                    "an offline settlement body: {e}"
                                ))
                            })?;
                    let exposure =
                        client_db::economic_lineage::offline_exposure(&named.release_message)
                            .map_err(|e| storage_err("the exposure the settlement names", e))?
                            .ok_or_else(|| {
                                DsmError::invalid_operation(
                                    "the settlement names an exposure this device never recorded",
                                )
                            })?;
                    dsm::economic::offline_boundary::OfflineSettlementBody::verify(
                        &body, &genesis, &devid, &exposure,
                    )?
                }
            };
            AcceptedSubstrate::from_verified_offline_boundary(
                verified,
                coords.accepted_substrate_addr,
            )
        }
    };
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network_id.to_vec(),
    };
    let advanced = advance_validated(
        validated,
        &registered,
        &manifest,
        &witness,
        &accepted,
        &resolver,
        &genesis,
        &devid,
        network_id,
        &public_key,
    )
    .map_err(|e| DsmError::invalid_operation(format!("economic validation: {e}")))?;

    // ── ONE TX: admitted coordinate + leaf cache + clear pending + head ───
    // The cache is the FULL post-transition leaf set with exact state CCBs:
    // the previous cache rows updated by THIS witness's mutations — the same
    // replay rule recovery uses, so the two can never disagree. Never an
    // authority: `record_admitted_with_conn` admits it only against the
    // admitted root, and `producer_tree` re-checks root equality on load.
    let leaves: Vec<([u8; 32], [u8; 32], Vec<u8>)> = {
        use std::collections::BTreeMap;
        let mut cache: BTreeMap<[u8; 32], ([u8; 32], Vec<u8>)> =
            economic_lineage::load_leaf_cache()
                .map_err(|e| storage_err("load leaf cache", e))?
                .into_iter()
                .map(|(k, v, ccb)| (k, (v, ccb)))
                .collect();
        for m in &witness.mutations {
            let key = m
                .leaf_key(&genesis, &devid)
                .map_err(|e| storage_err("cache leaf key", e))?;
            match &m.post_state {
                Some(state) => {
                    cache.insert(
                        key,
                        (
                            state
                                .leaf_value()
                                .map_err(|e| storage_err("cache value", e))?,
                            state.encode().map_err(|e| storage_err("cache ccb", e))?,
                        ),
                    );
                }
                None => {
                    cache.remove(&key);
                }
            }
        }
        cache.into_iter().map(|(k, (v, ccb))| (k, v, ccb)).collect()
    };

    // ── THE INCLUSION PROOF for the leaves this transition wrote ─────────
    //
    // The register publishes WHICH root this device committed at this
    // position; it says nothing about which leaves that root commits. Every
    // counterparty that must cite one of our leaves — a trader proving our
    // vault reserves, an owner proving our settlement receipt — needs the
    // leaf and its path, and could not get them.
    //
    // Built HERE, from `tree`, which IS the post-transition tree the write
    // set advanced and whose root was just registered. That is the whole
    // one-snapshot guarantee: there is no second read, no rebuild and no
    // window in which the tree could move between naming the root and
    // taking the paths. The equality below states it rather than assuming
    // it, and `EconomicProofArtifact::new` re-derives every path against
    // that same root before the bytes exist.

    let had_post_admit = !post_admit_artifacts.is_empty();
    log::debug!(
        "[economic admission] position {} funds {} credit(s)",
        advanced.root.economic_position(),
        advanced.funded.len()
    );
    core.admit_economic_position(
        dsm::economic::lineage::AdmittedEconomicPosition::SingleRoot {
            economic_position: advanced.root.economic_position(),
            economic_root: advanced.root.economic_root(),
            claim_ref: advanced.claim.claim_ref(),
        },
        &operation_digest,
        &leaves,
        &set.id(),
        &post_admit_artifacts,
    )?;
    if had_post_admit {
        // Land the post-admission objects (the release) on the fleet NOW —
        // the promoted reply delivers later in this same pass, and the
        // sender fetches the release by address before finalizing. A failed
        // pass here is only latency: the sweep retries, the sender defers.
        if let Err(e) = crate::handlers::artifact_republish::republish_unpublished_artifacts().await
        {
            log::warn!(
                "[economic admission] post-admit publish pass failed (retried by the sweep): {e}"
            );
        }
    }

    Ok(AdmittedOutcome {
        economic_position: advanced.root.economic_position(),
    })
}

/// Finish an admission a previous run left pending. Everything needed is in
/// durable frozen state; NOTHING is re-signed and nothing is asked of the
/// user. Idempotent: republish carries frozen bytes, the registers re-ack
/// identical bytes, and the verifier is pure.
pub(crate) async fn resume_pending_admission(
    core: &CoreSDK,
    network_id: &[u8],
    pending: PendingEconomicAdmission,
) -> Result<AdmittedOutcome, DsmError> {
    // A fulfillment's admission is finished by the route's RESOLUTION
    // (`sofi_advance::resolve_pending_position`, R13) — facts that arrive at
    // storage, not a witness this device froze — so this path, which rebuilds
    // a DSM-backed admission from its frozen witness, has nothing to resume
    // and must not guess. The fence stands until the position resolves.
    if let dsm::economic::admission::PendingAdmissionKind::SofiFulfillment { fulfillment_id } =
        pending.kind
    {
        return Err(DsmError::invalid_operation(format!(
            "the pending admission at position {} is a SoFi fulfillment ({}): the position is \
             finished by its route's resolution, not by resuming an admission — resolve it \
             before staging anything after it",
            pending.economic_position,
            crate::util::text_id::encode_base32_crockford(&fulfillment_id)
        )));
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(network_id)?;

    // A duplicate resume (another finisher already admitted exactly this
    // admission) returns that outcome rather than tripping the coordinate check
    // below; a superseded one refuses without writing.
    if let Some(outcome) = admission_already_finished(core, &pending)? {
        return Ok(outcome);
    }

    // The validated PREDECESSOR: the admitted coordinate, or the activation
    // root before a first admission, decided at the activation point (the
    // head less this admission's own credit). Its root must equal the pending
    // pre-root — a mismatch means the local store is incoherent, which is a
    // stop, not a guess. An admitted position that has selected no root
    // stops here too: a device that crashed between a fulfillment's
    // registration and its route's resolution comes back with that shape.
    let validated = validated_root_or_activate(core)?;
    if validated.economic_root() != pending.pre_economic_root
        || validated.economic_position() + 1 != pending.economic_position
    {
        return Err(DsmError::storage(
            "pending admission does not extend the admitted coordinate — local store \
             incoherent; refusing to guess"
                .to_string(),
            None::<std::io::Error>,
        ));
    }

    // Reconstruct the witness from the FROZEN bytes (never re-derived).
    let (witness_bytes, witness) = frozen_witness_of(&pending)?;
    let coords = *pending
        .accepted_coords()
        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;

    // Reconstruct the manifest from FROZEN artifacts and derivation-only
    // inputs, and REQUIRE its address to equal the one the pending admission
    // bound — addr-equality is what makes reconstruction honest. Nothing is
    // re-signed: the authority evidence is read back frozen, and t_0 is a
    // pure derivation from the cached seed.
    let witness_addr = immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        &witness_bytes,
    );
    let authority_key_prefix = format!(
        "immutable::{}::",
        String::from_utf8_lossy(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_AUTHORITY_EVIDENCE.source_bytes()
        )
    );
    let authority_bytes =
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            &authority_key_prefix,
            "economic-authority-evidence",
        )
        .map_err(|e| storage_err("load frozen authority evidence", e))?
        .ok_or_else(|| {
            DsmError::storage(
                "no frozen authority evidence for the pending admission".to_string(),
                None::<std::io::Error>,
            )
        })?;
    let authority_addr =
        dsm::economic::authority_evidence::authority_evidence_addr(&authority_bytes);
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::storage(
                "no cached wallet seed — cannot re-derive t_0".to_string(),
                None::<std::io::Error>,
            )
        })?;
    let authority_position = crate::sdk::identity_presentation::derive_own_authority_context(
        &wallet_seed,
        crate::sdk::identity_presentation::OwnerIdentityInputs::beta(network_id),
    )?
    .position;
    let substrate_slot = match coords.substrate {
        dsm::economic::admission::AcceptedSubstrateCoords::Successor { .. } => {
            AdmissionSubstrate::DsmSuccessor {
                evidence_addr: coords.accepted_substrate_addr,
            }
        }
        dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary => {
            AdmissionSubstrate::OfflineBoundary {
                evidence_addr: coords.accepted_substrate_addr,
            }
        }
    };
    let manifest = EconomicAdmissionManifest::new(
        authority_position,
        witness_addr,
        authority_addr,
        substrate_slot,
        witness.derived_provenance_index(),
    )
    .map_err(|e| storage_err("reconstruct manifest", e))?;
    if manifest
        .addr()
        .map_err(|e| storage_err("manifest addr", e))?
        != coords.admission_manifest_addr
    {
        return Err(DsmError::storage(
            "reconstructed manifest does not address-match the pending admission".to_string(),
            None::<std::io::Error>,
        ));
    }

    // The producer tree AFTER this transition, for the leaf cache: replay the
    // frozen witness onto the validated pre-tree.
    let mut tree = producer_tree(&validated)?;
    for m in &witness.mutations {
        let key = m
            .leaf_key(&genesis, &devid)
            .map_err(|e| storage_err("witness leaf key", e))?;
        match &m.post_state {
            None => tree.remove(&key),
            Some(state) => tree.insert(
                key,
                state
                    .leaf_value()
                    .map_err(|e| storage_err("witness leaf", e))?,
            ),
        }
    }

    // An offline boundary finishes from its EXACT frozen body: verified again
    // in the finish, and bound here to the address and the digest the
    // admission carries.
    if let dsm::economic::admission::AcceptedSubstrateCoords::OfflineBoundary = coords.substrate {
        let body_key_prefix = format!(
            "immutable::{}::",
            String::from_utf8_lossy(
                dsm::common::domain_tags::TAG_DSM_ECONOMIC_OFFLINE_BOUNDARY_EVIDENCE.source_bytes()
            )
        );
        let body =
            crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
                &body_key_prefix,
                OFFLINE_BOUNDARY_BODY_PURPOSE,
            )
            .map_err(|e| storage_err("load frozen boundary body", e))?
            .ok_or_else(|| {
                DsmError::storage(
                    "no frozen boundary body for the pending admission".to_string(),
                    None::<std::io::Error>,
                )
            })?;
        if dsm::economic::offline_boundary::offline_boundary_evidence_addr(&body)
            != coords.accepted_substrate_addr
            || dsm::economic::offline_boundary::offline_boundary_operation_digest(&body)
                != pending.operation_digest
        {
            return Err(DsmError::storage(
                "frozen boundary body does not match the pending admission".to_string(),
                None::<std::io::Error>,
            ));
        }
        return finish_admission(
            core,
            network_id,
            &set,
            &validated,
            witness,
            manifest,
            AdmittedSubstrate::OfflineBoundary(body),
            pending,
            Vec::new(),
        )
        .await;
    }

    // The EXACT operation, from the frozen SUCCESSOR EVIDENCE — recovery
    // re-derives nothing and re-signs nothing. The evidence is verified the
    // same way a foreign walker verifies it, and its address must be the one
    // the admission bound.
    let substrate_key_prefix = format!(
        "immutable::{}::",
        String::from_utf8_lossy(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_SUCCESSOR_EVIDENCE.source_bytes()
        )
    );
    let successor_bytes =
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix_and_purpose(
            &substrate_key_prefix,
            "economic-dsm-successor-evidence",
        )
        .map_err(|e| storage_err("load frozen successor evidence", e))?
        .ok_or_else(|| {
            DsmError::storage(
                "no frozen successor evidence for the pending admission".to_string(),
                None::<std::io::Error>,
            )
        })?;
    if dsm::economic::successor_evidence::successor_evidence_addr(&successor_bytes)
        != coords.accepted_substrate_addr
    {
        return Err(DsmError::storage(
            "frozen successor evidence does not address-match the pending admission".to_string(),
            None::<std::io::Error>,
        ));
    }
    let own_pk = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?
        .0;
    let verified_successor = dsm::economic::successor_evidence::verify_dsm_successor_evidence(
        &successor_bytes,
        &genesis,
        &devid,
        &own_pk,
    )
    .map_err(|e| storage_err("verify frozen successor evidence", e))?;
    let operation = verified_successor.operation;
    if verified_successor.operation_digest != pending.operation_digest
        || Some(verified_successor.c_dsm_plus)
            != coords.substrate.successor().map(|(_, c_plus)| c_plus)
    {
        return Err(DsmError::storage(
            "frozen successor evidence does not match the pending admission".to_string(),
            None::<std::io::Error>,
        ));
    }

    // A recipient admission's RELEASE (frozen only at admit): recover the
    // exact bytes from the acceptance journal by the manifest address this
    // admission binds, so a crash-resumed recipient still publishes it.
    let post_admit =
        crate::storage::client_db::recipient_receipt_fold::find_release_bytes_for_manifest_addr(
            &coords.admission_manifest_addr,
        )
        .map_err(|e| storage_err("release lookup", e))?;
    // Only a recipient admission has a release; a sender's has none.
    let post_admit = match post_admit {
        Some(bytes) => vec![(
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE,
                &bytes,
            ),
            bytes,
            "recipient-economic-release",
        )],
        None => Vec::new(),
    };
    finish_admission(
        core,
        network_id,
        &set,
        &validated,
        witness,
        manifest,
        AdmittedSubstrate::Dsm(Box::new(operation)),
        pending,
        post_admit,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// Recipient-side admission (3.5b PR4)
// ═══════════════════════════════════════════════════════════════════════════

/// How recipient prevalidation refused. `Terminal` (a hostile or impossible
/// transfer) and `Quarantined` (a divergent register cell) refuse it BEFORE
/// any durable economic state, and nothing negative is recorded
/// (MR-DSM-0018); `Incomplete` leaves the row `ReadyToVerify` to retry next
/// poll (an outage is never an attack).
#[derive(Debug)]
pub(crate) enum PrevalidationRefusal {
    Terminal(String),
    Quarantined(String),
    Incomplete(String),
}

impl core::fmt::Display for PrevalidationRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Terminal(m) => write!(f, "terminal: {m}"),
            Self::Quarantined(m) => write!(f, "QUARANTINED: {m}"),
            Self::Incomplete(m) => write!(f, "incomplete: {m}"),
        }
    }
}

/// The signed transfer a recipient is admitting: SIG A and its message, the
/// A-side receipt wire, and the economic locator hint one of the transfer's
/// copies carried.
pub(crate) struct IncomingTransfer<'a> {
    pub canonical_operation_bytes: &'a [u8],
    pub signature: &'a [u8],
    pub hint: crate::storage::client_db::recipient_staging::LocatorHint,
    pub evidence_bytes: &'a [u8],
}

/// Everything the SYNC accept closure needs, established BEFORE the fence
/// exists: the validated sender debit, the Stored foreign closure, and
/// this device's own admission prerequisites. No awaits remain past here.
pub(crate) struct RecipientAdmissionPrereqs {
    pub peer_genesis: [u8; 32],
    pub peer_devid: [u8; 32],
    pub sender_economic_position: u64,
    pub sender_debit_mutation_index: u32,
    pub network_id: Vec<u8>,
    pub set: StorageSet,
    pub validated: ValidatedEconomicRoot,
    pub tree: EconomicSmt,
    pub pre_state: AdmittedPreState,
    pub authority: AuthorityMaterial,
    pub prepared: PendingEconomicAdmission,
    /// The wire's exact unsigned canonical operation bytes — the closure's
    /// verified transfer must be byte-identical to what was prevalidated.
    pub pinned_canonical_bytes: Vec<u8>,
}

/// Prevalidate an inbound online transfer BEFORE any durable local state
/// (owner corrections 3+8): resolve and validate the sender's debit via the
/// PR2 walker (a copy's locators as untrusted hints), bind the signed bytes to
/// the validated operation, require EK-ancestry portability, establish the
/// Stored evidence closure (correction 5, recorded at the ACTUAL fetch
/// boundary — correction 2), and assemble this device's own admission
/// prerequisites.
///
/// A refusal is about `incoming.hint`, not about the transfer: another
/// copy's hint may locate the debit.
pub(crate) async fn prevalidate_incoming_transfer_admission(
    core: &CoreSDK,
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    sender_ak: &[u8],
    incoming: &IncomingTransfer<'_>,
    rel_key: &[u8; 32],
) -> Result<RecipientAdmissionPrereqs, PrevalidationRefusal> {
    let incomplete = |m: String| PrevalidationRefusal::Incomplete(m);
    let terminal = |m: String| PrevalidationRefusal::Terminal(m);

    // ── The locators are untrusted HINTS; the signed bytes are the binding ─
    let canonical_operation_bytes = incoming.canonical_operation_bytes;
    let evidence_bytes = incoming.evidence_bytes;
    let sender_economic_position = incoming.hint.economic_position;
    let sender_debit_mutation_index = incoming.hint.debit_mutation_index;
    let evidence_receipt =
        dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(evidence_bytes)
            .map_err(|e| terminal(format!("evidence receipt does not decode: {e}")))?;

    // ── Own prerequisites (fail closed before any network walk) ────────────
    let network_id = committed_network_id().map_err(|e| incomplete(format!("network: {e}")))?;
    let set = canonical_set(&network_id).map_err(|e| incomplete(format!("register set: {e}")))?;
    // A pending admission is resumed at the poll level; reaching here with
    // one still attached means resume could not finish — hold the row.
    if let Some(p) = core
        .device_head()
        .and_then(|h| h.pending_economic_admission().cloned())
    {
        return Err(incomplete(format!(
            "an economic admission at position {} is pending — resumed at poll level",
            p.economic_position
        )));
    }
    // A value-holding unactivated device can NEVER admit a credit (beta: use
    // a fresh identity) — terminal for every inbound transfer.
    let validated =
        validated_root_or_activate(core).map_err(|e| terminal(format!("economic root: {e}")))?;
    let (tree, pre_state) = producer_tree_and_pre_state(&validated)
        .map_err(|e| incomplete(format!("economic tree: {e}")))?;
    let head = core
        .device_head()
        .ok_or_else(|| incomplete("no device head".to_string()))?;
    let (genesis, devid) = (head.genesis_digest(), head.devid());
    let authority = authority_material(&network_id, &genesis)
        .map_err(|e| incomplete(format!("authority evidence: {e}")))?;

    // ── The sender's validated debit, recorded at the fetch boundary ───────
    let live = crate::sdk::economic_registers::LiveRegisterResolver {
        set: &set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network_id.clone(),
    };
    let recorder = crate::sdk::economic_registers::RecordingResolver::new(&live);
    // DSM Amendment A19: the sender's lineage is validated from this device's
    // frontier for it, each step from the root validated before it, and each
    // of its credits' sources from this device's frontier for that source, so
    // the recorder observes exactly the closure this acceptance depends on.
    // A conditional position on the way is resolved from SoFi's public
    // objects for that position (SoFi Amendment S15).
    let peer = {
        let sofi = crate::sdk::sofi_reads::VerifierContext::new(&set, None, None)
            .map_err(|e| incomplete(format!("SoFi reads: {e}")))?;
        recorder.validated_peer_lineage(
            peer_genesis,
            peer_devid,
            sender_economic_position,
            &sofi.peer_position_resolver(),
        )
    };
    let peer = peer.map_err(|e| match e {
        dsm::economic::provenance::PeerLineageFailure::Invalid(m) => {
            terminal(format!("sender lineage INVALID: {m}"))
        }
        dsm::economic::provenance::PeerLineageFailure::Quarantined(m) => {
            PrevalidationRefusal::Quarantined(m)
        }
        dsm::economic::provenance::PeerLineageFailure::Incomplete(m) => {
            incomplete(format!("sender lineage: {m}"))
        }
        // The sender's position is conditional and its route has not
        // resolved. NOT terminal: the sender is honest and mid-route, and
        // `terminal` would refuse this transfer forever over a state that
        // resolves on its own. It is also not a defect in what we hold, so
        // the message says which it is rather than blaming a fetch.
        dsm::economic::provenance::PeerLineageFailure::Unresolved(m) => {
            incomplete(format!("sender lineage is undecided: {m}"))
        }
    })?;

    // ── The sender-side conjuncts — the SAME implementation the verifier's
    // credit arm runs post-accept, so the two can never drift ──────────────
    dsm::economic::provenance::prevalidate_sender_debit(
        &peer,
        peer_genesis,
        peer_devid,
        sender_debit_mutation_index,
        &devid,
    )
    .map_err(|e| terminal(format!("sender debit prevalidation: {e}")))?;
    // ── Wire ↔ validated-operation binding ─────────────────────────────────
    let peer_operation = peer.verified_operation().ok_or_else(|| {
        terminal("the validated debit is an offline boundary, not a signed operation".to_string())
    })?;
    if peer_operation.with_cleared_signature().to_bytes() != canonical_operation_bytes {
        return Err(terminal(
            "the signed operation bytes are not the validated debit operation".to_string(),
        ));
    }
    if Some(&evidence_receipt.child_tip) != peer.c_dsm_plus() {
        return Err(terminal(
            "the A-side receipt is for a different bilateral step than the validated debit \
             successor"
                .to_string(),
        ));
    }

    // ── EK-ancestry portability pre-check (fail closed BEFORE accepting an
    // acceptance we could never make foreign-walkable) ─────────────────────
    for (side, signer) in [
        (client_db::CertChainSide::Counterparty, *peer_devid),
        (client_db::CertChainSide::Local, devid),
    ] {
        let head_pk = client_db::load_cert_chain_head_pubkey(rel_key, side)
            .map_err(|e| incomplete(format!("cert head: {e}")))?;
        let tracked = client_db::economic_lineage::latest_ek_step(rel_key, &signer)
            .map_err(|e| incomplete(format!("ek step chain: {e}")))?;
        match (head_pk, tracked) {
            // Relationship genesis on this side: AK is the head, no step yet.
            (None, None) => {}
            (Some(head), Some((_, _, pk))) if head == pk => {}
            (head, tracked) => {
                return Err(incomplete(format!(
                    "EK ancestry is not portable for this relationship (side {side:?}: head \
                     present={}, tracked step present={}) — a step advanced without its \
                     content-addressed EkCertStepV1; the acceptance bundle would be \
                     unverifiable",
                    head.is_some(),
                    tracked.is_some(),
                )));
            }
        }
    }

    // ── The exact recorded closure, Stored on the set ──────────────────────
    // Every attempt publishes what it read; an object already proven Stored
    // is known per exact address and is not read back again. Take the
    // recorded closure OUT before awaiting — a RefCell borrow must never live
    // across an await point.
    let closure = std::mem::take(&mut *recorder.recorded.borrow_mut());
    crate::handlers::artifact_republish::ensure_closure_stored(&set, &closure)
        .await
        .map_err(incomplete)?;

    // ── The prepared admission for the exact signed op the apply will see ──
    let signed_op = dsm::types::operations::Operation::decode_and_bind_signed(
        canonical_operation_bytes,
        incoming.signature,
        sender_ak,
    )
    .map_err(|e| terminal(format!("signed operation does not bind: {e}")))?;
    let op_digest = dsm::economic::admission::dsm_operation_digest(&signed_op.to_bytes());
    let prepared = PendingEconomicAdmission::prepared(
        dsm::economic::admission::PendingAdmissionKind::DsmBacked,
        validated.economic_position() + 1,
        validated.economic_root(),
        op_digest,
    );

    Ok(RecipientAdmissionPrereqs {
        peer_genesis: *peer_genesis,
        peer_devid: *peer_devid,
        sender_economic_position,
        sender_debit_mutation_index,
        network_id,
        set,
        validated,
        tree,
        pre_state,
        authority,
        prepared,
        pinned_canonical_bytes: canonical_operation_bytes.to_vec(),
    })
}

/// What the recipient's build phase produced, beyond the generic parts: the
/// signed release (frozen, HELD until admitted) and the two EK-step rows the
/// accept transaction appends.
pub(crate) struct RecipientAdmissionBuild {
    pub parts: DsmAdmissionParts,
    pub release_bytes: Vec<u8>,
    /// `(signer_devid, step_addr, ek_pk)` rows for `ek_cert_step_chain`.
    pub ek_step_rows: Vec<([u8; 32], [u8; 32], Vec<u8>)>,
}

/// Build the recipient's admission from the exact prepared successor — SYNC,
/// runs inside `build_acceptance` under the state-machine lock (DB reads
/// only, no core re-entry, no awaits). Ordering: countersign wire bytes from
/// the generated B artifacts → both EkCertStepV1 objects (prior addrs from
/// the tracking table) → the acceptance bundle → `CreditSourceFacts::
/// PeerDebit` with the bundle addr as an OUTPUT → `build_dsm_admission` with
/// bundle + steps as extra frozen artifacts → the signed release from the
/// build's own coordinates.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_recipient_admission(
    prereqs: &RecipientAdmissionPrereqs,
    tree: &mut EconomicSmt,
    genesis: &[u8; 32],
    devid: &[u8; 32],
    chain_state: &RelationshipChainState,
    signed_op: &Operation,
    b_artifacts: &crate::handlers::recipient_receipt::GeneratedBArtifacts,
    incoming: &IncomingTransfer<'_>,
    rel_key: &[u8; 32],
) -> Result<RecipientAdmissionBuild, DsmError> {
    use prost::Message;
    let evidence_bytes = incoming.evidence_bytes;

    // ── The exact countersign wire bytes (deterministic from the journal
    // receipt — the same derivation the reply delta uses) ──────────────────
    let receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &b_artifacts.receipt_bytes,
    )
    .map_err(|e| DsmError::invalid_operation(format!("countersigned receipt: {e}")))?;
    let b = receipt
        .split_countersign_b()
        .map_err(|e| DsmError::invalid_operation(format!("countersign split: {e}")))?
        .1;
    let evidence_digest_a =
        dsm::crypto::spool_address::ArtifactRole::EvidenceA.content_digest(evidence_bytes);
    let countersign_bytes = dsm::types::proto::ReceiptCountersignB {
        commitment: b_artifacts.commitment.to_vec(),
        receipt_evidence_digest_a: evidence_digest_a.to_vec(),
        sig_b: b.sig_b.clone(),
        ek_cert_b: b.ek_cert_b.clone(),
        ek_pk_b: b.ek_pk_b.clone(),
        b_parent_tip: b_artifacts.applied_parent_tip_b.to_vec(),
        b_child_tip: b_artifacts.applied_child_tip_b.to_vec(),
        // The bundle is acceptance PROVENANCE — it never carries the
        // finalization release; only the promoted reply delta does.
        recipient_economic_release_addr: Vec::new(),
    }
    .encode_to_vec();

    // ── Both sides' EK step objects for THIS step; the bundle references
    // each side's PREDECESSOR (None at relationship genesis) ───────────────
    let a_prior = client_db::economic_lineage::latest_ek_step(rel_key, &prereqs.peer_devid)
        .map_err(|e| storage_err("ek step chain (A)", e))?
        .map(|(_, addr, _)| addr);
    let b_chain_head = client_db::economic_lineage::latest_ek_step(rel_key, devid)
        .map_err(|e| storage_err("ek step chain (B)", e))?
        .map(|(_, addr, _)| addr);
    // This device's countersignature chains, by Core's lineage rule, from its
    // own send still in flight when this apply follows it in its canonical
    // lineage — a transfer that crossed that send (owner ruling, 2026-10-29:
    // "both settle"). Its predecessor step is then that send's own step
    // object, built from the send's frozen A-side evidence on the chain as it
    // stood before the send, and recorded and published ahead of it.
    let own_send_step: Option<Vec<u8>> =
        match client_db::sender_proposal::get_unfinalized_proposal_for_relationship(rel_key)
            .map_err(|e| storage_err("this device's send in flight", e))?
        {
            Some(send)
                if matches!(
                    dsm::verification::receipt_verification::per_step_ek_predecessor_in_lineage(
                        &b_artifacts.applied_parent_tip_b,
                        Some((&send.canonical_child, ())),
                        None,
                        (),
                    ),
                    dsm::verification::receipt_verification::EkPredecessor::OwnStepInFlight(())
                ) =>
            {
                let evidence = crate::handlers::online_finalize::load_retained_evidence_a(&send)
                    .map_err(|e| storage_err("the send in flight's evidence", e))?
                    .ok_or_else(|| {
                        storage_err(
                            "the send in flight's evidence",
                            "the send retains no A-side evidence",
                        )
                    })?;
                let send_receipt =
                    dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                        &evidence.full_receipt_bytes,
                    )?;
                Some(
                    dsm::types::proto::EkCertStepV1 {
                        ek_pk: send_receipt.ek_pk_a.clone(),
                        authority: Some(dsm::types::proto::ek_cert_step_v1::Authority::EkCert(
                            send_receipt.ek_cert_a.clone(),
                        )),
                        h_n: send_receipt.parent_tip.to_vec(),
                        prior_step_addr: b_chain_head.map(|a| a.to_vec()),
                    }
                    .encode_to_vec(),
                )
            }
            _ => None,
        };
    let b_prior = match &own_send_step {
        Some(step) => Some(dsm::economic::peer_acceptance::ek_cert_step_addr(step)),
        None => b_chain_head,
    };
    let a_step_bytes = dsm::types::proto::EkCertStepV1 {
        ek_pk: receipt.ek_pk_a.clone(),
        authority: Some(dsm::types::proto::ek_cert_step_v1::Authority::EkCert(
            receipt.ek_cert_a.clone(),
        )),
        h_n: receipt.parent_tip.to_vec(),
        prior_step_addr: a_prior.map(|a| a.to_vec()),
    }
    .encode_to_vec();
    let b_step_bytes = dsm::types::proto::EkCertStepV1 {
        ek_pk: b.ek_pk_b.clone(),
        authority: Some(dsm::types::proto::ek_cert_step_v1::Authority::EkCert(
            b.ek_cert_b.clone(),
        )),
        h_n: receipt.parent_tip.to_vec(),
        prior_step_addr: b_prior.map(|a| a.to_vec()),
    }
    .encode_to_vec();
    let a_step_addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&a_step_bytes);
    let b_step_addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&b_step_bytes);

    // ── The acceptance bundle — the signed transfer, and the exact receipt
    // and countersign wire bytes. The transfer leg carries the signed parts
    // only (SIG A and its message): no locator hints — those are transport,
    // and the write set's facts carry the validated position — and nothing
    // a copy's wrapper said.
    let transfer_request_bytes = dsm::types::proto::OnlineTransferRequest {
        signature: incoming.signature.to_vec(),
        canonical_operation_bytes: incoming.canonical_operation_bytes.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    let bundle_bytes = dsm::types::proto::PeerTransferAcceptanceEvidenceV1 {
        transfer_request_bytes,
        receipt_evidence_a_bytes: evidence_bytes.to_vec(),
        receipt_countersign_b_bytes: countersign_bytes,
        a_prior_step_addr: a_prior.map(|a| a.to_vec()),
        b_prior_step_addr: b_prior.map(|a| a.to_vec()),
    }
    .encode_to_vec();
    let acceptance_evidence_addr =
        dsm::economic::peer_acceptance::acceptance_evidence_addr(&bundle_bytes);

    // ── The write set's facts: prevalidated locators + the addr OUTPUT ─────
    let facts = CreditSourceFacts::PeerDebit {
        peer_genesis: prereqs.peer_genesis,
        peer_devid: prereqs.peer_devid,
        peer_economic_position: prereqs.sender_economic_position,
        peer_debit_mutation_index: prereqs.sender_debit_mutation_index,
        acceptance_evidence_addr,
    };
    let mut extra_artifacts = vec![
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_PEER_TRANSFER_ACCEPTANCE,
                &bundle_bytes,
            ),
            bundle_bytes,
            "peer-transfer-acceptance",
        ),
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                &a_step_bytes,
            ),
            a_step_bytes,
            "ek-cert-step",
        ),
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                &b_step_bytes,
            ),
            b_step_bytes,
            "ek-cert-step",
        ),
    ];
    let own_send_row = match own_send_step {
        Some(step) => {
            let addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&step);
            let ek_pk = match dsm::types::proto::EkCertStepV1::decode(step.as_slice()) {
                Ok(decoded) => decoded.ek_pk,
                Err(e) => return Err(storage_err("the send in flight's step object", e)),
            };
            extra_artifacts.push((
                crate::sdk::economic_registers::immutable_object_key(
                    dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                    &step,
                ),
                step,
                "ek-cert-step",
            ));
            Some((*devid, addr, ek_pk))
        }
        None => None,
    };
    let parts = build_dsm_admission(
        genesis,
        devid,
        chain_state,
        signed_op,
        &prereqs.pre_state,
        tree,
        &facts,
        &prereqs.authority,
        extra_artifacts,
    )?;

    // ── The RELEASE: every field an output of THIS build, signed now,
    // frozen in the accept tx, deliverable only at ECON_ADMITTED ───────────
    let sk = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?
        .1;
    let release_bytes = dsm::economic::release::sign_recipient_economic_release(
        &dsm::economic::release::ReleaseFacts {
            receipt_commitment: b_artifacts.commitment,
            acceptance_evidence_addr,
            recipient_genesis: *genesis,
            recipient_devid: *devid,
            recipient_economic_position: prereqs.prepared.economic_position,
            post_economic_root: parts.coords.post_economic_root,
            admission_manifest_addr: parts.coords.admission_manifest_addr,
        },
        &sk,
    )
    .map_err(|e| DsmError::invalid_operation(format!("release sign: {e}")))?;

    // In chain order: the send in flight's own step before the
    // countersignature it precedes.
    let mut ek_step_rows = vec![(prereqs.peer_devid, a_step_addr, receipt.ek_pk_a.clone())];
    ek_step_rows.extend(own_send_row);
    ek_step_rows.push((*devid, b_step_addr, b.ek_pk_b.clone()));
    Ok(RecipientAdmissionBuild {
        parts,
        release_bytes,
        ek_step_rows,
    })
}

/// Why the sender's independent register read refused a release.
pub(crate) enum ReleaseRegisterCheck {
    /// The register could not answer (no quorum winner yet, outage) — retry;
    /// never treated as an attack.
    Unavailable(String),
    /// The register answered and DISAGREES with the release — a hostile or
    /// broken recipient; the artifact proves nothing.
    Mismatch(String),
}

/// The sender's INDEPENDENT half of release verification (3.5b PR4): walk
/// the recipient's lineage to the released position and require the
/// registered claim there to carry exactly the released post-root and
/// manifest address. A hostile recipient's private "admitted" flag is never
/// trusted — the root its network-registered lineage reaches is the fact.
pub(crate) async fn verify_release_against_register(
    release: &dsm::economic::release::ReleaseFacts,
) -> Result<(), ReleaseRegisterCheck> {
    use dsm::economic::provenance::PeerLineageFailure;
    use dsm::economic::provenance::ProvenanceResolver;
    use ReleaseRegisterCheck::{Mismatch, Unavailable};
    let network = committed_network_id().map_err(|e| Unavailable(format!("network: {e}")))?;
    let set = canonical_set(&network).map_err(|e| Unavailable(format!("register set: {e}")))?;
    let resolver = LiveRegisterResolver {
        set: &set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network,
    };
    // The recipient's lineage is walked to the released position. Every cell
    // on the way is read at a leader computed from a root THIS verifier
    // validated (Part II §7.2) — never from anything the release carries — so
    // the registered root at `q` is the one the recipient's own lineage
    // reaches, not a value a recipient could point the verifier at.
    let peer = tokio::task::block_in_place(|| {
        resolver.validated_peer_transition(
            &release.recipient_genesis,
            &release.recipient_devid,
            release.recipient_economic_position,
        )
    })
    .map_err(|e| match e {
        PeerLineageFailure::Incomplete(detail) => Unavailable(format!(
            "recipient lineage at the released position: {detail}"
        )),
        other => Mismatch(format!("recipient lineage: {other}")),
    })?;
    if peer.validated_root().economic_root() != release.post_economic_root
        || peer.admission_manifest_addr() != release.admission_manifest_addr
    {
        return Err(Mismatch(
            "the release names a root/manifest the register does not hold".to_string(),
        ));
    }
    Ok(())
}

/// The set a completed BLE step's EK step objects are frozen for: the
/// committed network's canonical storage set. Read before the step's advance
/// opens its transaction.
pub(crate) fn ble_ek_step_set_id() -> Result<[u8; 32], DsmError> {
    let network_id = committed_network_id()?;
    Ok(canonical_set(&network_id)?.id())
}

/// One signer's EK step of a bilateral step: the EK its receipt signed with,
/// the cert chaining it from the signer's previous head, and the parent tip
/// `h_n` the cert is bound to — all from the receipt that signer signed.
pub(crate) struct EkStep<'a> {
    pub signer: &'a [u8; 32],
    pub ek_pk: &'a [u8],
    pub ek_cert: &'a [u8],
    pub h_n: &'a [u8; 32],
}

impl<'a> EkStep<'a> {
    /// The sender's step, from its own receipt (A side).
    pub(crate) fn of_sender(
        sender: &'a [u8; 32],
        receipt: &'a dsm::types::receipt_types::StitchedReceiptV2,
    ) -> Self {
        Self {
            signer: sender,
            ek_pk: &receipt.ek_pk_a,
            ek_cert: &receipt.ek_cert_a,
            h_n: &receipt.parent_tip,
        }
    }

    /// The receiver's step, from its counter-signed receipt (B side).
    pub(crate) fn of_receiver(
        receiver: &'a [u8; 32],
        receipt: &'a dsm::types::receipt_types::StitchedReceiptV2,
    ) -> Self {
        Self {
            signer: receiver,
            ek_pk: &receipt.ek_pk_b,
            ek_cert: &receipt.ek_cert_b,
            h_n: &receipt.parent_tip,
        }
    }
}

/// Record both signers' `EkCertStepV1` objects for one completed BLE
/// bilateral step (3.5b PR4, correction 3), sender first, inside `tx` — the
/// transaction the step commits in: the signer-chain rows are appended and
/// the exact step bytes FROZEN as publication debt, bound to the head root
/// the step produced; the republish sweep publishes them when connectivity
/// returns. Both devices record the same two objects. A later ONLINE
/// acceptance bundle may not depend on these predecessors until that exact
/// closure is Stored (prevalidation checks per exact address).
pub(crate) fn record_ble_ek_steps_in_tx(
    tx: &rusqlite::Connection,
    set_id: &[u8; 32],
    bound_root: &[u8; 32],
    rel_key: &[u8; 32],
    steps: &[EkStep<'_>],
) -> Result<(), DsmError> {
    use prost::Message;
    for step in steps {
        let prior = economic_lineage::latest_ek_step_with_conn(tx, rel_key, step.signer)
            .map_err(|e| storage_err("ek step chain", e))?
            .map(|(_, addr, _)| addr);
        let step_bytes = dsm::types::proto::EkCertStepV1 {
            ek_pk: step.ek_pk.to_vec(),
            authority: Some(dsm::types::proto::ek_cert_step_v1::Authority::EkCert(
                step.ek_cert.to_vec(),
            )),
            h_n: step.h_n.to_vec(),
            prior_step_addr: prior.map(|a| a.to_vec()),
        }
        .encode_to_vec();
        let addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&step_bytes);
        economic_lineage::append_ek_step_with_conn(tx, rel_key, step.signer, &addr, step.ek_pk)
            .map_err(|e| storage_err("ek step append", e))?;
        crate::storage::client_db::frozen_publication_artifact::freeze_artifact_with_conn(
            tx,
            set_id,
            &crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                &step_bytes,
            ),
            &step_bytes,
            bound_root,
            "ek-cert-step",
        )
        .map_err(|e| storage_err("ek step freeze", e))?;
    }
    Ok(())
}
