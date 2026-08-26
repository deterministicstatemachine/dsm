// SPDX-License-Identifier: Apache-2.0

//! The ERA faucet claim flow — the first production run of the whole economic
//! admission lifecycle.
//!
//! ```text
//! target position = admitted + 1        (position 0 = activate(), empty root)
//! loop attempts:
//!     ticket   = select_ticket(G, DevID, target, attempt)
//!     op       = FaucetClaim { era_faucet_id(network), ticket }
//!     envelope = frozen-or-sign-once(claim body binding target + op digest)
//!     quorum-claim the ticket           (contested -> next attempt)
//!     break
//! witness  = FROM the accepted core transition (one +100 ERA credit,
//!            0x0030 source)              -- core decides what +100 means
//! manifest = provenance index DERIVED from the witness
//! ONE TX   = advance (fence-coupled) + pending row + FROZEN evidence
//! publish evidence to q members (attributed)        -> EvidencePublished
//! register the root (frozen envelope, sign-once)    -> Registered
//! advance_validated with the LIVE resolver          -> verifier's answer
//! ONE TX   = admitted coordinate + leaf cache + clear pending + unfenced head
//! ```
//!
//! ## Recovery
//!
//! No timeout ever aborts an admission. Every external step is preceded by a
//! durable frozen artifact, so [`resume_pending_claim`] finishes the exact
//! same admission byte-identically from whichever boundary the crash hit:
//!
//! ```text
//! ticket won, nothing local     -> the frozen ticket envelope re-claims
//!                                  (held-identical) and the flow re-runs
//! accepted, evidence unpublished-> republish sweep carries the frozen bytes
//! published, root unregistered  -> the frozen root claim registers (or a
//!                                  lost response is resolved by READING)
//! registered, not admitted      -> re-verify, then admit
//! ```

use dsm::economic::admission::{EconomicAdmissionState, PendingAdmissionKind, PendingEconomicAdmission};
use dsm::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest};
use dsm::economic::claim_envelope::sign_economic_root_claim;
use dsm::economic::credit::{CreditSource, CreditSourceValidatedFaucetDistribution};
use dsm::economic::faucet::{
    dsm_economic_operation_id, dsm_operation_digest, era_faucet_id, faucet_claim_evidence_addr,
    sign_faucet_ticket_claim, FaucetTicketClaimBody, ERA_FAUCET_PAYOUT,
};
use dsm::economic::lineage::{
    activate, advance_validated, AcceptedSubstrate, EconomicActivationSnapshot,
    ValidatedEconomicRoot,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::register::{resolve_root_register_profile, RegisteredEconomicRoot};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::storage_object::immutable_inner;
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_registers::{
    claim_faucet_ticket, register_economic_root, select_ticket, LiveRegisterResolver, RegisterError,
};
use crate::sdk::storage_set::{StorageSet, StorageSetCatalog};
use crate::storage::client_db::economic_faucet;
use crate::util::deterministic_time::tick;

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
fn canonical_set(network_id: &[u8]) -> Result<StorageSet, DsmError> {
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
fn validated_root_or_activate(core: &CoreSDK) -> Result<ValidatedEconomicRoot, DsmError> {
    if let Some((position, root)) =
        economic_faucet::get_admitted().map_err(|e| storage_err("load admitted", e))?
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
fn producer_tree(validated: &ValidatedEconomicRoot) -> Result<EconomicSmt, DsmError> {
    let mut tree = EconomicSmt::new();
    if validated.economic_position() == 0 {
        return Ok(tree);
    }
    let leaves =
        economic_faucet::load_leaf_cache().map_err(|e| storage_err("load leaf cache", e))?;
    for (key, value, _ccb) in &leaves {
        tree.insert(*key, *value);
    }
    if tree.root() != validated.economic_root() {
        return Err(DsmError::storage(
            "economic leaf cache does not recompute the admitted root — discarded; witness \
             replay recovery is required and no replay source exists yet"
                .to_string(),
            None::<std::io::Error>,
        ));
    }
    Ok(tree)
}

/// Run one complete claim. Idempotent under crash + retry via the frozen
/// artifacts; a pending admission from a previous run is finished first.
pub async fn claim_era_faucet(core: &CoreSDK, network_id: &[u8]) -> Result<ClaimOutcome, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    if let Some(pending) = head.pending_economic_admission().cloned() {
        // No timeout ever aborts an admission: a pending one is FINISHED,
        // never abandoned. Resume from whichever boundary the crash hit.
        return resume_pending_claim(core, network_id, pending).await;
    }

    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(network_id)?;
    let validated = validated_root_or_activate(core)?;
    let target_position = validated.economic_position() + 1;
    let faucet_id = era_faucet_id(network_id);
    let (public_key, secret_key) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;

    // ── Win a ticket (strategy loop; any in-range ticket is valid) ─────────
    const MAX_ATTEMPTS: u64 = 64;
    let mut won: Option<(u64, Vec<u8>, [u8; 32])> = None; // (ticket, envelope, op_digest)
    for attempt in 0..MAX_ATTEMPTS {
        let ticket_index = select_ticket(&genesis, &devid, target_position, attempt)?;
        let op = Operation::FaucetClaim {
            faucet_id,
            ticket_index,
        };
        let op_digest = dsm_operation_digest(&op.to_bytes());

        // Frozen-or-sign-once, BEFORE any member write.
        let envelope = match economic_faucet::get_frozen_ticket_claim(&faucet_id, ticket_index)
            .map_err(|e| storage_err("load frozen ticket claim", e))?
        {
            Some(bytes) => bytes,
            None => {
                let body = FaucetTicketClaimBody {
                    faucet_id,
                    ticket_index,
                    claimant_genesis: genesis,
                    claimant_devid: devid,
                    claimant_economic_position: target_position,
                    recipient_operation_digest: op_digest,
                    claimant_public_key: public_key.clone(),
                    storage_set_id: set.id(),
                };
                let bytes = sign_faucet_ticket_claim(&body, &secret_key)
                    .map_err(|e| storage_err("sign ticket claim", e))?;
                economic_faucet::put_frozen_ticket_claim(
                    &faucet_id,
                    ticket_index,
                    &bytes,
                    tick() as i64,
                )
                .map_err(|e| storage_err("freeze ticket claim", e))?;
                // Read BACK rather than trusting the in-memory copy: a silent
                // retention failure must surface before anything goes out.
                economic_faucet::get_frozen_ticket_claim(&faucet_id, ticket_index)
                    .map_err(|e| storage_err("re-read frozen claim", e))?
                    .ok_or_else(|| {
                        DsmError::storage(
                            "frozen ticket claim did not persist".to_string(),
                            None::<std::io::Error>,
                        )
                    })?
            }
        };

        match claim_faucet_ticket(&set, &envelope).await {
            Ok(_) => {
                won = Some((ticket_index, envelope, op_digest));
                break;
            }
            Err(RegisterError::Contested { .. }) => continue, // ticket burned; next
            Err(e) => return Err(storage_err("ticket register", e)),
        }
    }
    let Some((ticket_index, envelope, op_digest)) = won else {
        return Err(DsmError::storage(
            format!("no ticket won in {MAX_ATTEMPTS} attempts — retry later"),
            None::<std::io::Error>,
        ));
    };

    // ── Build the witness FROM the accepted core transition ────────────────
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let mut tree = producer_tree(&validated)?;
    let pre_root = tree.root();
    let prior = head.balance(&era);
    let credit_state = EconomicLeafState::Balance(
        EconomicBalanceState::new(era, prior + ERA_FAUCET_PAYOUT)
            .map_err(|e| storage_err("credit state", e))?,
    );
    let pre_state = if prior > 0 {
        Some(EconomicLeafState::Balance(
            EconomicBalanceState::new(era, prior).map_err(|e| storage_err("pre state", e))?,
        ))
    } else {
        None
    };
    let key = credit_state.leaf_key(&genesis, &devid);
    let siblings = tree.siblings(&key).to_vec();
    let mutation = EconomicLeafMutation::new(pre_state, Some(credit_state.clone()), siblings)
        .map_err(|e| storage_err("mutation", e))?;
    tree.insert(
        key,
        credit_state
            .leaf_value()
            .map_err(|e| storage_err("leaf value", e))?,
    );
    let post_root = tree.root();

    let evidence_addr = faucet_claim_evidence_addr(&envelope);
    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        dsm_economic_operation_id(&genesis, &devid, &op_digest),
        op_digest,
        vec![mutation],
        vec![CreditSource::ValidatedFaucetDistribution(
            CreditSourceValidatedFaucetDistribution {
                credit_mutation_index: 0,
                faucet_id,
                ticket_index,
                faucet_claim_evidence_addr: evidence_addr,
            },
        )],
    )
    .map_err(|e| storage_err("witness", e))?;
    let witness_bytes = witness
        .encode()
        .map_err(|e| storage_err("witness encode", e))?;
    let witness_addr = immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        &witness_bytes,
    );

    let op = Operation::FaucetClaim {
        faucet_id,
        ticket_index,
    };
    let op_bytes = op.to_bytes();
    let substrate_addr = immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_DSM_SUBSTRATE_OBJ,
        &op_bytes,
    );

    let manifest = EconomicAdmissionManifest::new(
        core.device_tree_root_or_genesis(),
        witness_addr,
        genesis, // authority evidence: the authenticated genesis digest (beta)
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

    let pending = PendingEconomicAdmission {
        kind: PendingAdmissionKind::DsmBacked,
        state: EconomicAdmissionState::Prepared,
        economic_position: target_position,
        pre_economic_root: pre_root,
        post_economic_root: post_root,
        operation_digest: op_digest,
        accepted_substrate_addr: substrate_addr,
        admission_manifest_addr: manifest_addr,
    };

    // ── ONE TX: fence-coupled advance + pending row + frozen evidence ──────
    let artifacts = vec![
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_ERA_FAUCET_TICKET_CLAIM,
                &envelope,
            ),
            envelope.clone(),
            "faucet-ticket-claim",
        ),
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
                &witness_bytes,
            ),
            witness_bytes.clone(),
            "economic-transition-witness",
        ),
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_ECONOMIC_ADMISSION_MANIFEST,
                &manifest_bytes,
            ),
            manifest_bytes.clone(),
            "economic-admission-manifest",
        ),
        (
            crate::sdk::economic_registers::immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_ECONOMIC_DSM_SUBSTRATE_OBJ,
                &op_bytes,
            ),
            op_bytes.clone(),
            "economic-dsm-substrate",
        ),
    ];
    let delta = BalanceDelta {
        policy_commit: era,
        direction: BalanceDirection::Credit,
        amount: ERA_FAUCET_PAYOUT,
    };
    core.faucet_claim_advance(op, &delta, pending.clone(), artifacts, &set.id())?;

    // ── Publish evidence, register the root, verify, admit ────────────────
    finish_admission(
        core, network_id, &set, &validated, tree, witness, manifest, pending,
    )
    .await
}

/// Everything after local acceptance. Separated so recovery re-enters here.
#[allow(clippy::too_many_arguments)]
async fn finish_admission(
    core: &CoreSDK,
    network_id: &[u8],
    set: &StorageSet,
    validated: &ValidatedEconomicRoot,
    tree: EconomicSmt,
    witness: EconomicTransitionWitness,
    manifest: EconomicAdmissionManifest,
    mut pending: PendingEconomicAdmission,
) -> Result<ClaimOutcome, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let (public_key, secret_key) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;

    // Evidence to q members, attributed. The republish sweep carries the
    // EXACT frozen bytes.
    crate::handlers::artifact_republish::republish_unpublished_artifacts()
        .await
        .map_err(|e| storage_err("publish admission evidence", e))?;
    pending.state = EconomicAdmissionState::EvidencePublished;
    core.update_pending_admission_state(&pending)?;

    // The root claim: frozen-or-sign-once BEFORE the first member write.
    let manifest_addr = pending.admission_manifest_addr;
    let k_root = dsm::economic::register::economic_root_register_key(
        &genesis,
        &devid,
        pending.economic_position,
    );
    let frozen_root = match economic_faucet::get_frozen_root_claim(pending.economic_position)
        .map_err(|e| storage_err("load frozen root claim", e))?
    {
        Some((_, bytes)) => bytes,
        None => {
            let body = dsm::economic::claim::EconomicRootClaimBody::new(
                genesis,
                devid,
                pending.economic_position,
                pending.post_economic_root,
                manifest_addr,
                set.id(),
                dsm::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
                &public_key,
            )
            .map_err(|e| storage_err("root claim body", e))?;
            let bytes = sign_economic_root_claim(&body, &secret_key)
                .map_err(|e| storage_err("sign root claim", e))?;
            economic_faucet::put_frozen_root_claim(
                pending.economic_position,
                &k_root,
                &bytes,
                tick() as i64,
            )
            .map_err(|e| storage_err("freeze root claim", e))?;
            economic_faucet::get_frozen_root_claim(pending.economic_position)
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
        post_economic_root: pending.post_economic_root,
        admission_manifest_addr: manifest_addr,
        storage_set_id: set.id(),
    };
    let accepted = AcceptedSubstrate::from_verified_dsm_successor(
        pending.operation_digest,
        pending.accepted_substrate_addr,
    );
    let resolver = LiveRegisterResolver {
        set,
        runtime: tokio::runtime::Handle::current(),
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
    let leaves: Vec<([u8; 32], [u8; 32], Vec<u8>)> = {
        let mut out = Vec::new();
        // The post-transition tree's full leaf set with exact state CCBs —
        // here exactly one balance leaf (beta position 1) or the updated one.
        let era = dsm::core::token::token_state_manager::era_policy_commit();
        let head_after = core.device_head().ok_or_else(|| {
            DsmError::storage("no device head".to_string(), None::<std::io::Error>)
        })?;
        let state = EconomicLeafState::Balance(
            EconomicBalanceState::new(era, head_after.balance(&era))
                .map_err(|e| storage_err("cache state", e))?,
        );
        out.push((
            state.leaf_key(&genesis, &devid),
            state
                .leaf_value()
                .map_err(|e| storage_err("cache value", e))?,
            state.encode().map_err(|e| storage_err("cache ccb", e))?,
        ));
        let _ = &tree;
        out
    };
    core.admit_economic_position(
        new_validated.economic_position(),
        &new_validated.economic_root(),
        &leaves,
    )?;

    Ok(ClaimOutcome {
        tokens_received: ERA_FAUCET_PAYOUT,
        economic_position: new_validated.economic_position(),
    })
}

/// Finish an admission a previous run left pending. Everything needed is in
/// durable frozen state; NOTHING is re-signed and nothing is asked of the
/// user. Idempotent: republish carries frozen bytes, the registers re-ack
/// identical bytes, and the verifier is pure.
pub async fn resume_pending_claim(
    core: &CoreSDK,
    network_id: &[u8],
    pending: PendingEconomicAdmission,
) -> Result<ClaimOutcome, DsmError> {
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
        match economic_faucet::get_admitted().map_err(|e| storage_err("load admitted", e))? {
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
    if witness.operation_digest != pending.operation_digest
        || witness.post_economic_root != pending.post_economic_root
    {
        return Err(DsmError::storage(
            "frozen witness does not match the pending admission".to_string(),
            None::<std::io::Error>,
        ));
    }

    // Reconstruct the manifest from recomputable inputs and REQUIRE its
    // address to equal the one the pending admission bound. The manifest has
    // no decoder yet; addr-equality is what makes reconstruction honest.
    let witness_addr = immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_TRANSITION_WITNESS_OBJ,
        &witness_bytes,
    );
    let manifest = EconomicAdmissionManifest::new(
        core.device_tree_root_or_genesis(),
        witness_addr,
        genesis,
        AdmissionSubstrate::DsmSuccessor {
            evidence_addr: pending.accepted_substrate_addr,
        },
        witness.derived_provenance_index(),
    )
    .map_err(|e| storage_err("reconstruct manifest", e))?;
    if manifest
        .addr()
        .map_err(|e| storage_err("manifest addr", e))?
        != pending.admission_manifest_addr
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

    finish_admission(
        core, network_id, &set, &validated, tree, witness, manifest, pending,
    )
    .await
}
