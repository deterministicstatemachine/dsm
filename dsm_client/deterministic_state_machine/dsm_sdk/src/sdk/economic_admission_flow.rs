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
    /// THE debit mutation's index in the built witness, when the write set
    /// has one — the wire locator is THIS value, never a prediction.
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
        pre_balances,
        tree,
        facts,
    )
    .map_err(|e| DsmError::invalid_operation(format!("write set: {e}")))?;
    let debit_mutation_index = built
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
        .map(|i| i as u32);

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

/// One ADMITTED self-loop operation (Burn, CreateToken fee), end to end:
/// resume any pending admission, assemble prerequisites, run the fence-
/// coupled advance through the generalized seam, publish/register/validate,
/// admit. The route gets the advance outcome back for its response
/// projection. The debit registers BEFORE the route reports success.
pub(crate) async fn admitted_self_loop_operation(
    core: &CoreSDK,
    operation: Operation,
    delta: dsm::types::device_state::BalanceDelta,
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
                &CreditSourceFacts::None,
                &authority,
                Vec::new(),
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
    core.admit_economic_position(
        new_validated.economic_position(),
        &new_validated.economic_root(),
        &leaves,
    )?;

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
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix(
            &witness_key_prefix,
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
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix(
            &authority_key_prefix,
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
        crate::storage::client_db::frozen_publication_artifact::find_current_payload_with_prefix(
            &substrate_key_prefix,
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

    finish_admission(
        core, network_id, &set, &validated, tree, witness, manifest, operation, pending,
    )
    .await
}
