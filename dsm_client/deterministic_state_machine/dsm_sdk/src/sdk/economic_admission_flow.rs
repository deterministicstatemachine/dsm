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
use dsm::economic::register::{resolve_root_register_profile, RegisteredEconomicRoot};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{build_write_set, CreditSourceFacts};
use dsm::storage_object::immutable_inner;
use dsm::types::device_state::RelationshipChainState;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_registers::{register_economic_root, LiveRegisterResolver};
use crate::sdk::storage_set::{StorageSet, StorageSetCatalog};
use crate::storage::client_db;
use crate::storage::client_db::economic_lineage;
use crate::util::deterministic_time::tick;

/// The claimant's committed network, from the STORED genesis record — the
/// same value Genesis v3 committed. Fail closed: no record, no admission.
/// The caller never chooses the network.
pub(crate) fn committed_network_id() -> Result<Vec<u8>, DsmError> {
    let g_vec = crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();
    let g: [u8; 32] = g_vec.as_slice().try_into().map_err(|_| {
        DsmError::storage("no genesis identity".to_string(), None::<std::io::Error>)
    })?;
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

/// Resolve the canonical register set for `network_id`, fail-closed, through
/// the catalog (never `sole_set` — consumers RESOLVE).
pub(crate) fn canonical_set(network_id: &[u8]) -> Result<StorageSet, DsmError> {
    let profile = resolve_root_register_profile(network_id)
        .map_err(|e| storage_err("resolve root register", e))?;
    let catalog =
        StorageSetCatalog::from_env_config().map_err(|e| storage_err("load storage catalog", e))?;
    catalog
        .resolve(&profile.storage_set_id)
        .cloned()
        .ok_or_else(|| {
            DsmError::storage(
                "the canonical register set is not resolvable from the local catalog — fail closed"
                    .to_string(),
                None::<std::io::Error>,
            )
        })
}

/// The validated economic root this device holds, or a fresh activation.
///
/// `activate` refuses a device already holding value — calling its current
/// holdings "position 0" would be self-rooting at the base — so a legacy
/// value-holding device surfaces `UnsupportedLegacyEconomicState` here.
pub(crate) fn validated_root_or_activate(
    core: &CoreSDK,
) -> Result<ValidatedEconomicRoot, DsmError> {
    if let Some((position, root)) =
        economic_lineage::get_admitted().map_err(|e| storage_err("load admitted", e))?
    {
        return Ok(ValidatedEconomicRoot::rehydrate_from_admitted_store(
            position, root,
        ));
    }
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let snapshot = EconomicActivationSnapshot {
        online_balances_empty: head.balances_snapshot().is_empty(),
        vault_reserves_empty: head.vault_reserves_snapshot().is_empty(),
        settlement_receipt_state_empty: true,
        outstanding_offline_allocation: !head.offline_allocations_snapshot().is_empty(),
    };
    activate(snapshot).map_err(|e| DsmError::invalid_operation(e.to_string()))
}

/// Rebuild the producer-side economic tree.
///
/// Strategy A (cache) with root-equality admission; the cache is NEVER an
/// authority — on mismatch it is discarded and the flow falls back to the
/// recovery truth (for position 0/1 in beta: the empty tree, since nothing
/// beyond the first admissions exists to replay yet).
pub(crate) fn producer_tree(validated: &ValidatedEconomicRoot) -> Result<EconomicSmt, DsmError> {
    Ok(producer_tree_and_balances(validated)?.0)
}

/// The producer tree PLUS the admitted balance map decoded from the same
/// cache rows. Admission pre-states come from `R_econ` ITSELF — never the
/// device head, whose balance map can carry credits no admission backs (a
/// received transfer awaiting PR4 recipient admission). Building from the
/// head would pair a mutation pre-state the validated pre-root cannot prove;
/// building from the tree makes unadmitted value simply unspendable, which
/// is the economic-root guarantee working.
pub(crate) fn producer_tree_and_balances(
    validated: &ValidatedEconomicRoot,
) -> Result<(EconomicSmt, BTreeMap<[u8; 32], u64>), DsmError> {
    let mut tree = EconomicSmt::new();
    let mut balances = BTreeMap::new();
    if validated.economic_position() == 0 {
        return Ok((tree, balances));
    }
    let leaves =
        economic_lineage::load_leaf_cache().map_err(|e| storage_err("load leaf cache", e))?;
    for (key, value, ccb) in &leaves {
        tree.insert(*key, *value);
        let state = dsm::economic::decode::decode_leaf_state(ccb)
            .map_err(|e| storage_err("decode cached leaf state", e))?;
        if let dsm::economic::state::EconomicLeafState::Balance(b) = state {
            balances.insert(b.policy_commit, b.amount);
        }
    }
    if tree.root() != validated.economic_root() {
        return Err(DsmError::storage(
            "economic leaf cache does not recompute the admitted root — discarded; witness \
             replay recovery is required and no replay source exists yet"
                .to_string(),
            None::<std::io::Error>,
        ));
    }
    Ok((tree, balances))
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
        crate::sdk::identity_presentation::OwnerIdentityInputs {
            network_id,
            wallet_index: 0,
            device_slot: 0,
            genesis_version: 3,
        },
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
    pre_balances: &BTreeMap<[u8; 32], u64>,
    tree: &mut EconomicSmt,
    facts: &CreditSourceFacts,
    authority: &AuthorityMaterial,
    extra_artifacts: Vec<(String, Vec<u8>, &'static str)>,
) -> Result<DsmAdmissionParts, DsmError> {
    let pre_root = tree.root();
    let c_dsm_plus = chain_state.compute_chain_tip();
    let op_bytes = operation.to_bytes();
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&op_bytes);
    let econ_op_id = dsm::economic::faucet::dsm_economic_operation_id(genesis, devid, &c_dsm_plus);

    let built = build_write_set(
        operation,
        genesis,
        devid,
        &econ_op_id,
        &dsm::economic::write_set::EconomicPreState::balances_only(pre_balances),
        tree,
        facts,
    )
    .map_err(|e| DsmError::invalid_operation(format!("write set: {e}")))?;
    // THE DEBIT LOCATOR IS A TRANSFER FACT, AND ONLY A TRANSFER FACT. Its one
    // consumer is the online-transfer wire, where the recipient uses it to
    // locate the sender's debit; a Transfer sender's write set has exactly one
    // balance debit, so "the first mutation whose amount fell" is exact there.
    // It is silently wrong for any multi-leg write set — a funded vault
    // creation debits TWO balances, a close draws down TWO reserves — where
    // that scan names one arbitrary leg. So it is structurally confined to the
    // shape it is sound for: every other operation yields `None`, and a caller
    // needing a locator for one of them gets no answer rather than a wrong one.
    let debit_mutation_index = match operation {
        Operation::Transfer { .. } => built
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
            .map(|i| i as u32),
        _ => None,
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

    let (_pk, sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;
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
        c_dsm_plus,
        embedded_parent: chain_state.embedded_parent,
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

/// One ADMITTED self-loop operation (Burn, CreateToken fee, Mint), end to
/// end: resume any pending admission, assemble prerequisites, run the fence-
/// coupled advance through the generalized seam, publish/register/validate,
/// admit. The route gets the advance outcome back for its response
/// projection. The operation registers BEFORE the route reports success.
///
/// `facts_for_position` supplies the operation's credit-source facts plus any
/// extra evidence artifacts, given the TARGET ECONOMIC POSITION this
/// admission will occupy. It runs after the position and operation digest are
/// fixed and before anything durable — a Mint builds and signs its `0x0029`
/// authorization here, binding the signed body to exactly the position the
/// admission seam CAS-checks. Pure operations pass
/// `|_| Ok((CreditSourceFacts::None, Vec::new()))`. The returned artifacts
/// are frozen in the SAME transaction as the advance and the pending
/// admission, so the crash invariant holds: either the operation never
/// became locally accepted, or the operation, its pending admission and its
/// exact evidence bytes all exist durably.
pub(crate) async fn admitted_self_loop_operation(
    core: &CoreSDK,
    operation: Operation,
    delta: dsm::types::device_state::BalanceDelta,
    facts_for_position: impl FnOnce(
        u64,
    ) -> Result<
        (CreditSourceFacts, Vec<(String, Vec<u8>, &'static str)>),
        DsmError,
    >,
    in_tx_extra: Option<
        &(dyn Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
        ) -> Result<(), DsmError>
              + Sync),
    >,
) -> Result<(dsm::types::device_state::AdvanceOutcome, AdmittedOutcome), DsmError> {
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
    let (mut tree, pre_balances) = producer_tree_and_balances(&validated)?;
    let authority = authority_material(&network_id, &genesis)?;
    let target_position = validated.economic_position() + 1;
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&operation.to_bytes());
    let (facts, extra_artifacts) = facts_for_position(target_position)?;
    let prepared = PendingEconomicAdmission::prepared(
        dsm::economic::admission::PendingAdmissionKind::DsmBacked,
        target_position,
        tree.root(),
        op_digest,
    );
    let mut built: Option<DsmAdmissionParts> = None;
    let (outcome, pending) = core.faucet_claim_advance(
        operation.clone(),
        &delta,
        prepared,
        |chain_state| {
            let parts = build_dsm_admission(
                &genesis,
                &devid,
                chain_state,
                &operation,
                &pre_balances,
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
        tree,
        parts.witness,
        parts.manifest,
        operation,
        pending,
        Vec::new(),
    )
    .await?;
    Ok((outcome, admitted))
}

/// Everything after local acceptance. Separated so recovery re-enters here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_admission(
    core: &CoreSDK,
    network_id: &[u8],
    set: &StorageSet,
    validated: &ValidatedEconomicRoot,
    tree: EconomicSmt,
    witness: EconomicTransitionWitness,
    manifest: EconomicAdmissionManifest,
    operation: Operation,
    mut pending: PendingEconomicAdmission,
    // Frozen only in the ADMIT transaction (the RELEASE object): nothing
    // here may reach the network before ECON_ADMITTED.
    post_admit_artifacts: Vec<(String, Vec<u8>, &'static str)>,
) -> Result<AdmittedOutcome, DsmError> {
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
    // Evidence to q members, attributed. The republish sweep carries the
    // EXACT frozen bytes.
    crate::handlers::artifact_republish::republish_unpublished_artifacts()
        .await
        .map_err(|e| storage_err("publish admission evidence", e))?;
    // ECON_EVIDENCE_PUBLISHED is a QUORUM fact, not a best-effort pass: the
    // sweep returns Ok while leaving below-quorum rows PublicationPending, so
    // require the frozen backlog to be EMPTY before the state advances — a
    // root registered ahead of q-durable evidence would be resolvable but
    // permanently unwalkable if the accepting minority died. Held-for-resume
    // is the correct outcome; the next resume re-runs the sweep.
    let unpublished =
        crate::storage::client_db::frozen_publication_artifact::list_unpublished_artifacts(1)
            .map_err(|e| storage_err("check evidence durability", e))?;
    if !unpublished.is_empty() {
        return Err(storage_err(
            "publish admission evidence",
            "frozen evidence is below storage quorum — the admission stays held for resume",
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
            let body = dsm::economic::claim::EconomicRootClaimBody::new(
                genesis,
                devid,
                pending.economic_position,
                coords.post_economic_root,
                manifest_addr,
                set.id(),
                dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
                &public_key,
            )
            .map_err(|e| storage_err("root claim body", e))?;
            let bytes = sign_economic_root_claim(&body, &secret_key)
                .map_err(|e| storage_err("sign root claim", e))?;
            economic_lineage::put_frozen_root_claim(
                pending.economic_position,
                &k_root,
                &bytes,
                tick() as i64,
            )
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
    register_economic_root(set, &frozen_root)
        .await
        .map_err(|e| storage_err("root register", e))?;
    pending.state = EconomicAdmissionState::Registered;
    core.update_pending_admission_state(&pending)?;

    // The VERIFIER's answer — the same predicate any foreign device runs.
    let registered = RegisteredEconomicRoot {
        trader_genesis: genesis,
        trader_devid: devid,
        economic_position: pending.economic_position,
        post_economic_root: coords.post_economic_root,
        admission_manifest_addr: manifest_addr,
        storage_set_id: set.id(),
    };
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(
        operation,
        coords.c_dsm_plus,
        coords.embedded_parent,
        coords.accepted_substrate_addr,
    );
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
        expected_network_id: network_id.to_vec(),
    };
    let (new_validated, _funded) = advance_validated(
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
        let _ = &tree;
        cache.into_iter().map(|(k, (v, ccb))| (k, v, ccb)).collect()
    };
    let had_post_admit = !post_admit_artifacts.is_empty();
    core.admit_economic_position(
        new_validated.economic_position(),
        &new_validated.economic_root(),
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
        economic_position: new_validated.economic_position(),
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
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(network_id)?;

    // The validated PREDECESSOR: the admitted coordinate, or activation-shape
    // for a first admission. Its root must equal the pending pre-root — a
    // mismatch means the local store is incoherent, which is a stop, not a
    // guess.
    let validated =
        match economic_lineage::get_admitted().map_err(|e| storage_err("load admitted", e))? {
            Some((position, root)) => {
                ValidatedEconomicRoot::rehydrate_from_admitted_store(position, root)
            }
            None => ValidatedEconomicRoot::rehydrate_from_admitted_store(
                pending.economic_position - 1,
                pending.pre_economic_root,
            ),
        };
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
    let coords = *pending
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
        crate::sdk::identity_presentation::OwnerIdentityInputs {
            network_id,
            wallet_index: 0,
            device_slot: 0,
            genesis_version: 3,
        },
    )?
    .position;
    let manifest = EconomicAdmissionManifest::new(
        authority_position,
        witness_addr,
        authority_addr,
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: coords.accepted_substrate_addr,
        },
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
    let (own_pk, _own_sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;
    let verified_successor = dsm::economic::successor_evidence::verify_dsm_successor_evidence(
        &successor_bytes,
        &genesis,
        &devid,
        &own_pk,
    )
    .map_err(|e| storage_err("verify frozen successor evidence", e))?;
    let operation = verified_successor.operation;
    if verified_successor.operation_digest != pending.operation_digest
        || verified_successor.c_dsm_plus != coords.c_dsm_plus
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
        .map_err(|e| storage_err("release lookup", e))?
        .map(|bytes| {
            vec![(
                crate::sdk::economic_registers::immutable_object_key(
                    dsm::common::domain_tags::TAG_DSM_RECIPIENT_ECONOMIC_RELEASE,
                    &bytes,
                ),
                bytes,
                "recipient-economic-release",
            )]
        })
        .unwrap_or_default();
    finish_admission(
        core, network_id, &set, &validated, tree, witness, manifest, operation, pending, post_admit,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// Recipient-side admission (3.5b PR4)
// ═══════════════════════════════════════════════════════════════════════════

/// How recipient prevalidation refused — the taxonomy decides the staging
/// row's fate: `Terminal` ⇒ TerminalReject (a hostile or impossible transfer,
/// refused BEFORE any durable econ state); `Quarantined` ⇒ terminal with the
/// register-divergence reason recorded; `Incomplete` ⇒ the row stays
/// `ReadyToVerify` and retries next poll (an outage is never an attack).
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

/// Everything the SYNC accept closure needs, established BEFORE the fence
/// exists: the validated sender debit, the q-durable foreign closure, and
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
    pub pre_balances: BTreeMap<[u8; 32], u64>,
    pub authority: AuthorityMaterial,
    pub prepared: PendingEconomicAdmission,
    /// The wire's exact unsigned canonical operation bytes — the closure's
    /// verified transfer must be byte-identical to what was prevalidated.
    pub pinned_canonical_bytes: Vec<u8>,
}

/// Prevalidate an inbound online transfer BEFORE any durable local state
/// (owner corrections 3+8): resolve and validate the sender's debit via the
/// PR2 walker (wire locators as untrusted hints), bind the wire bytes to the
/// validated operation, require EK-ancestry portability, establish the
/// q-durable evidence closure (correction 5, recorded at the ACTUAL fetch
/// boundary — correction 2), and assemble this device's own admission
/// prerequisites.
pub(crate) async fn prevalidate_incoming_transfer_admission(
    core: &CoreSDK,
    peer_genesis: &[u8; 32],
    peer_devid: &[u8; 32],
    sender_ak: &[u8],
    transfer_wire_bytes: &[u8],
    evidence_bytes: &[u8],
    rel_key: &[u8; 32],
) -> Result<RecipientAdmissionPrereqs, PrevalidationRefusal> {
    use prost::Message;
    let incomplete = |m: String| PrevalidationRefusal::Incomplete(m);
    let terminal = |m: String| PrevalidationRefusal::Terminal(m);

    // ── The wire: locators are untrusted HINTS; bytes are the binding ──────
    let wire = dsm::types::proto::OnlineTransferRequest::decode(transfer_wire_bytes)
        .map_err(|e| terminal(format!("transfer wire does not decode: {e}")))?;
    let sender_economic_position = wire.sender_economic_position;
    let sender_debit_mutation_index = wire.sender_debit_mutation_index;
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
    let (tree, pre_balances) = producer_tree_and_balances(&validated)
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
    // The economic watermark only authorizes the CACHED fast path: without
    // it, walk from the activation root so the recorder observes the FULL
    // closure this validation depends on (correction 4: durability is never
    // inferred).
    let closure_durable = client_db::economic_lineage::peer_closure_q_durable(
        peer_genesis,
        peer_devid,
        sender_economic_position,
    )
    .unwrap_or(false);
    let walk = if closure_durable {
        recorder.validated_peer_transition(peer_genesis, peer_devid, sender_economic_position)
    } else {
        crate::sdk::economic_registers::resolve_peer_with_cache_disabled(
            &recorder,
            &network_id,
            peer_genesis,
            peer_devid,
            sender_economic_position,
        )
    };
    let peer = walk.map_err(|e| match e {
        dsm::economic::provenance::PeerLineageFailure::Invalid(m) => {
            terminal(format!("sender lineage INVALID: {m}"))
        }
        dsm::economic::provenance::PeerLineageFailure::Quarantined(m) => {
            PrevalidationRefusal::Quarantined(m)
        }
        dsm::economic::provenance::PeerLineageFailure::Incomplete(m) => {
            incomplete(format!("sender lineage: {m}"))
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
    if peer.verified_operation.with_cleared_signature().to_bytes() != wire.canonical_operation_bytes
    {
        return Err(terminal(
            "the wire's canonical operation bytes are not the validated debit operation"
                .to_string(),
        ));
    }
    if evidence_receipt.child_tip != peer.c_dsm_plus {
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

    // ── q-durability of the exact recorded closure (correction 5) ──────────
    if !closure_durable {
        // Take the recorded closure OUT before awaiting — a RefCell borrow
        // must never live across an await point.
        let closure = std::mem::take(&mut *recorder.recorded.borrow_mut());
        crate::handlers::artifact_republish::ensure_immutable_closure_on_quorum(&set, &closure)
            .await
            .map_err(incomplete)?;
        let _ = client_db::economic_lineage::mark_peer_closure_q_durable(
            peer_genesis,
            peer_devid,
            sender_economic_position,
        );
    }

    // ── The prepared admission for the exact signed op the apply will see ──
    let signed_op = dsm::types::operations::Operation::decode_and_bind_signed(
        &wire.canonical_operation_bytes,
        &wire.signature,
        sender_ak,
    )
    .map_err(|e| terminal(format!("signed operation does not bind: {e}")))?;
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&signed_op.to_bytes());
    let prepared = PendingEconomicAdmission::prepared(
        dsm::economic::admission::PendingAdmissionKind::DsmBacked,
        validated.economic_position() + 1,
        tree.root(),
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
        pre_balances,
        authority,
        prepared,
        pinned_canonical_bytes: wire.canonical_operation_bytes,
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
    transfer_wire_bytes: &[u8],
    evidence_bytes: &[u8],
    rel_key: &[u8; 32],
) -> Result<RecipientAdmissionBuild, DsmError> {
    use prost::Message;

    // ── The exact countersign wire bytes (deterministic from the journal
    // receipt — the same derivation the reply delta uses) ──────────────────
    let receipt = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
        &b_artifacts.receipt_bytes,
    )
    .map_err(|e| DsmError::invalid_operation(format!("countersigned receipt: {e}")))?;
    let (_a_side, b) = receipt
        .split_countersign_b()
        .map_err(|e| DsmError::invalid_operation(format!("countersign split: {e}")))?;
    let evidence_digest_a = dsm::crypto::blake3::domain_hash_bytes(
        dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
        evidence_bytes,
    );
    let countersign_bytes = dsm::types::proto::ReceiptCountersignB {
        commitment: b_artifacts.commitment.to_vec(),
        receipt_evidence_digest_a: evidence_digest_a.to_vec(),
        sig_b: b.sig_b.clone(),
        ek_cert_b: b.ek_cert_b.clone(),
        ek_pk_b: b.ek_pk_b.clone(),
        kyber_ct_b: b.kyber_ct_b.clone(),
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
    let b_prior = client_db::economic_lineage::latest_ek_step(rel_key, devid)
        .map_err(|e| storage_err("ek step chain (B)", e))?
        .map(|(_, addr, _)| addr);
    let a_step_bytes = dsm::types::proto::EkCertStepV1 {
        ek_pk: receipt.ek_pk_a.clone(),
        ek_cert: receipt.ek_cert_a.clone(),
        h_n: receipt.parent_tip.to_vec(),
        prior_step_addr: a_prior.map(|a| a.to_vec()),
    }
    .encode_to_vec();
    let b_step_bytes = dsm::types::proto::EkCertStepV1 {
        ek_pk: b.ek_pk_b.clone(),
        ek_cert: b.ek_cert_b.clone(),
        h_n: receipt.parent_tip.to_vec(),
        prior_step_addr: b_prior.map(|a| a.to_vec()),
    }
    .encode_to_vec();
    let a_step_addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&a_step_bytes);
    let b_step_addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&b_step_bytes);

    // ── The acceptance bundle — exact frozen wire bytes on all three legs ──
    let bundle_bytes = dsm::types::proto::PeerTransferAcceptanceEvidenceV1 {
        transfer_request_bytes: transfer_wire_bytes.to_vec(),
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
    let extra_artifacts = vec![
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
    let parts = build_dsm_admission(
        genesis,
        devid,
        chain_state,
        signed_op,
        &prereqs.pre_balances,
        tree,
        &facts,
        &prereqs.authority,
        extra_artifacts,
    )?;

    // ── The RELEASE: every field an output of THIS build, signed now,
    // frozen in the accept tx, deliverable only at ECON_ADMITTED ───────────
    let (_pk, sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;
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

    let ek_step_rows = vec![
        (prereqs.peer_devid, a_step_addr, receipt.ek_pk_a.clone()),
        (*devid, b_step_addr, b.ek_pk_b.clone()),
    ];
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

/// The sender's INDEPENDENT half of release verification (3.5b PR4): quorum-
/// read the recipient's register cell at the released position and require
/// the registered claim to carry exactly the released post-root and manifest
/// address. A hostile recipient's private "admitted" flag is never trusted —
/// the network-registered root is the fact.
pub(crate) async fn verify_release_against_register(
    release: &dsm::economic::release::ReleaseFacts,
) -> Result<(), ReleaseRegisterCheck> {
    use ReleaseRegisterCheck::{Mismatch, Unavailable};
    let network = committed_network_id().map_err(|e| Unavailable(format!("network: {e}")))?;
    let set = canonical_set(&network).map_err(|e| Unavailable(format!("register set: {e}")))?;
    let k_root = dsm::economic::register::economic_root_register_key(
        &release.recipient_genesis,
        &release.recipient_devid,
        release.recipient_economic_position,
    );
    let cell = crate::sdk::economic_registers::read_economic_root_cell(&set, &k_root)
        .await
        .map_err(|e| match e {
            crate::sdk::economic_registers::RegisterError::Conflict { detail } => Mismatch(
                format!("QUARANTINED register cell at the released position: {detail}"),
            ),
            other => Unavailable(other.to_string()),
        })?;
    let Some(cell) = cell else {
        return Err(Unavailable(
            "no quorum winner at the released position yet".to_string(),
        ));
    };
    let claim = dsm::economic::claim_envelope::decode_and_verify_economic_root_claim(&cell)
        .map_err(|e| Mismatch(format!("registered claim: {e}")))?;
    let body = claim.body;
    if body.trader_genesis != release.recipient_genesis
        || body.trader_devid != release.recipient_devid
        || body.economic_position != release.recipient_economic_position
    {
        return Err(Mismatch(
            "registered claim names different coordinates than the release".to_string(),
        ));
    }
    if body.post_economic_root != release.post_economic_root
        || body.admission_manifest_addr != release.admission_manifest_addr
    {
        return Err(Mismatch(
            "the release names a root/manifest the register does not hold".to_string(),
        ));
    }
    Ok(())
}

/// Record BOTH signers' `EkCertStepV1` objects for one completed BLE
/// bilateral step from its countersigned receipt (3.5b PR4, correction 3):
/// the signer-chain rows are appended and the exact step bytes FROZEN as
/// publication debt through the generic frozen-artifact backlog — fully
/// offline; the republish sweep publishes them when connectivity returns. A
/// later ONLINE acceptance bundle may not depend on these predecessors until
/// that exact closure is q-durable (prevalidation checks per exact address).
///
/// Idempotent: re-recording the same step (same content address) is a no-op,
/// so crash-replay and both directions of the sweep converge.
pub(crate) fn record_ble_ek_steps_from_receipt(
    rel_key: &[u8; 32],
    devid_a: &[u8; 32],
    devid_b: &[u8; 32],
    receipt: &dsm::types::receipt_types::StitchedReceiptV2,
) -> Result<(), DsmError> {
    use prost::Message;
    let network_id = committed_network_id()?;
    let set = canonical_set(&network_id)?;
    let binding =
        crate::storage::client_db::get_connection().map_err(|e| storage_err("connection", e))?;
    let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let tx = conn
        .transaction()
        .map_err(|e| storage_err("ek step tx", e))?;
    for (signer, ek_pk, ek_cert) in [
        (devid_a, &receipt.ek_pk_a, &receipt.ek_cert_a),
        (devid_b, &receipt.ek_pk_b, &receipt.ek_cert_b),
    ] {
        if ek_pk.is_empty() || ek_cert.is_empty() {
            continue;
        }
        let prior = economic_lineage::latest_ek_step_with_conn(&tx, rel_key, signer)
            .map_err(|e| storage_err("ek step chain", e))?
            .map(|(_, addr, _)| addr);
        let step_bytes = dsm::types::proto::EkCertStepV1 {
            ek_pk: ek_pk.clone(),
            ek_cert: ek_cert.clone(),
            h_n: receipt.parent_tip.to_vec(),
            prior_step_addr: prior.map(|a| a.to_vec()),
        }
        .encode_to_vec();
        let addr = dsm::economic::peer_acceptance::ek_cert_step_addr(&step_bytes);
        economic_lineage::append_ek_step_with_conn(&tx, rel_key, signer, &addr, ek_pk)
            .map_err(|e| storage_err("ek step append", e))?;
        crate::storage::client_db::frozen_publication_artifact::freeze_artifact_with_conn(
            &tx,
            &set.id(),
            &crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                &step_bytes,
            ),
            &step_bytes,
            &[0u8; 32],
            "ek-cert-step",
        )
        .map_err(|e| storage_err("ek step freeze", e))?;
    }
    tx.commit().map_err(|e| storage_err("ek step commit", e))?;
    Ok(())
}
