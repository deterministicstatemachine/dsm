// SPDX-License-Identifier: Apache-2.0

//! The beta ERA faucet claim — one release of the network's native reserve
//! to the claimant, through the whole economic admission lifecycle.
//!
//! ```text
//! target position = admitted + 1        (position 0 = activate(), empty root)
//! loop attempts:
//!     head     = walk the reserve lineage (memoised)
//!     op       = FaucetClaim { era_reserve_id(network), head.generation + 1 }
//!     release  = frozen-or-sign-once(NativeReserveRelease naming THIS device,
//!                target position, op digest, x = ERA_FAUCET_PAYOUT)
//!     write it along K(reserve, R_head)'s route, leader first
//!     read back: OUR release Final  -> keep its completion proof; break
//!                another release    -> the head moved; next attempt
//! witness  = FROM the accepted core transition (one +x ERA credit,
//!            0x005D source)              -- core decides what +x means
//! manifest = provenance index DERIVED from the witness
//! ONE TX   = advance (fence-coupled) + pending row + FROZEN evidence
//! put the evidence, read it back Stored             -> EvidencePublished
//! register the root claim along K_root(q)'s route   -> Registered
//! read it back Final at K_root(q)
//! advance_validated with the LIVE resolver          -> verifier's answer
//! ONE TX   = admitted coordinate + leaf cache + clear pending + unfenced head
//! ```
//!
//! The claim names its recipient directly: the release is signed by this
//! device's AK and names this device, so `FaucetClaim(A, x) ⇒ recipient = A`
//! — no selection, no spend gate, nobody else paid. The release is final
//! once three of its cell's five seats hold its chain (storage spec §9).
//!
//! ## Recovery
//!
//! No timeout ever aborts an admission. Every external step is preceded by a
//! durable frozen artifact, so a resumed claim finishes the exact same
//! admission byte-identically from whichever boundary the crash hit:
//!
//! ```text
//! release final, nothing local  -> the walk memoises it; the release naming
//!                                  this device's target position is reused
//! accepted, evidence unpublished-> republish sweep carries the frozen bytes
//! published, root unregistered  -> the frozen root claim registers (or a
//!                                  lost response is resolved by READING)
//! registered, not admitted      -> re-verify, then admit
//! ```

use dsm::economic::admission::{dsm_operation_digest, PendingAdmissionKind, PendingEconomicAdmission};
use dsm::economic::native_reserve::{
    era_reserve_id, release_evidence_addr, sign_release, NativeReserveReleaseBody,
    NativeReserveState, ReleaseSource, SuccessorRead, WalkStop, ERA_FAUCET_PAYOUT,
};
use dsm::economic::write_set::CreditSourceFacts;
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::{
    authority_material, build_dsm_admission, finish_admission, producer_tree_and_pre_state,
    resume_pending_admission, validated_root_or_activate,
};
use crate::sdk::storage_set::canonical_set;
use crate::sdk::native_reserve::{keep_release_completion, read_successor, walk_reserve, write_release};
use crate::storage::client_db::native_reserve as reserve_db;

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// The successful outcome: what the route reports.
pub struct ClaimOutcome {
    pub tokens_received: u64,
    pub economic_position: u64,
}

/// Attempts at winning a generation before the claim reports "retry later".
/// Each attempt is one full leader-first write at the current head; losing
/// one means the head moved under a concurrent claimant.
const MAX_ATTEMPTS: u64 = 8;

/// Run one complete claim. Idempotent under crash + retry via the frozen
/// artifacts; a pending admission from a previous run is finished first.
pub async fn claim_era_faucet(core: &CoreSDK, network_id: &[u8]) -> Result<ClaimOutcome, DsmError> {
    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    if let Some(pending) = head.pending_economic_admission().cloned() {
        // No timeout ever aborts an admission: a pending one is FINISHED
        // first — whatever operation it carries — and only then does a fresh
        // claim proceed for the NEXT position.
        resume_pending_admission(core, network_id, pending).await?;
    }

    let head = core
        .device_head()
        .ok_or_else(|| DsmError::storage("no device head".to_string(), None::<std::io::Error>))?;
    let genesis = head.genesis_digest();
    let devid = head.devid();
    let set = canonical_set(network_id)?;
    let validated = validated_root_or_activate(core)?;
    let target_position = validated.economic_position() + 1;
    let reserve_id = era_reserve_id(network_id);
    let (public_key, secret_key) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| storage_err("signing authority", e))?;
    let runtime = tokio::runtime::Handle::current();

    // ── Win a generation of the reserve (leader first at the head) ────────
    let mut won: Option<(u64, Vec<u8>, [u8; 32])> = None; // (generation, envelope, op_digest)
    for attempt in 1..=MAX_ATTEMPTS {
        log::debug!("[faucet] attempt {attempt} at the reserve head");
        let stop = tokio::task::block_in_place(|| walk_reserve(&set, network_id, &runtime))?;
        // A release naming THIS position that the walk already established as
        // final is this claim, resumed: reuse it rather than releasing twice.
        if let Some((generation, envelope)) =
            reserve_db::release_for_recipient(&reserve_id, &genesis, &devid, target_position)
                .map_err(|e| storage_err("reserve memo", e))?
        {
            let reserve_genesis = crate::sdk::native_reserve::genesis_state(network_id)?;
            let win = reserve_db::release_at(&reserve_genesis, generation)
                .map_err(|e| storage_err("reserve memo", e))?
                .ok_or_else(|| {
                    storage_err(
                        "reserve memo",
                        format!("the release at generation {generation} has no memoised parent"),
                    )
                })?;
            if !keep_release_completion(&set, &win.parent, &envelope).await? {
                return Err(storage_err(
                    "reserve completion",
                    "the resumed release's completion proof could not be rebuilt from the \
                     seats yet — retry later",
                ));
            }
            let op = Operation::FaucetClaim {
                reserve_id,
                generation,
            };
            won = Some((generation, envelope, dsm_operation_digest(&op.to_bytes())));
            break;
        }
        let parent: NativeReserveState = match stop {
            WalkStop::Head(state) => state,
            WalkStop::LeaderHeld {
                settled, release, ..
            } => {
                // The next release is decided but its chain stopped short of
                // three links. Any party MAY continue a chain along the
                // remaining route (storage spec §9 rule 8), whoever's release
                // it is; the next attempt walks past it once it is final.
                write_release(&set, &settled, &release.envelope_bytes).await?;
                continue;
            }
            WalkStop::Unavailable { .. } | WalkStop::BudgetExhausted(..) => {
                return Err(DsmError::storage(
                    "the reserve head could not be read — retry later".to_string(),
                    None::<std::io::Error>,
                ))
            }
        };
        let generation = parent.generation + 1;
        let op = Operation::FaucetClaim {
            reserve_id,
            generation,
        };
        let op_digest = dsm_operation_digest(&op.to_bytes());

        // Frozen-or-sign-once per parent root, BEFORE any member write.
        let parent_root = parent.root();
        let envelope = match reserve_db::get_frozen_release(&reserve_id, &parent_root)
            .map_err(|e| storage_err("load frozen release", e))?
        {
            Some(bytes) => bytes,
            None => {
                let body = NativeReserveReleaseBody {
                    reserve_id,
                    parent_root,
                    generation,
                    amount: ERA_FAUCET_PAYOUT,
                    recipient_genesis: genesis,
                    recipient_devid: devid,
                    recipient_economic_position: target_position,
                    recipient_operation_digest: op_digest,
                    storage_set_id: set.id(),
                    source: ReleaseSource::FaucetClaimant {
                        claimant_public_key: public_key.clone(),
                    },
                };
                let bytes =
                    sign_release(&body, &secret_key).map_err(|e| storage_err("sign release", e))?;
                reserve_db::put_frozen_release(&reserve_id, &parent_root, &bytes)
                    .map_err(|e| storage_err("freeze release", e))?;
                // Read BACK rather than trusting the in-memory copy: a silent
                // retention failure must surface before anything goes out.
                reserve_db::get_frozen_release(&reserve_id, &parent_root)
                    .map_err(|e| storage_err("re-read frozen release", e))?
                    .ok_or_else(|| {
                        DsmError::storage(
                            "frozen release did not persist".to_string(),
                            None::<std::io::Error>,
                        )
                    })?
            }
        };

        let write = write_release(&set, &parent, &envelope).await?;
        if !write.reached_leader() {
            return Err(DsmError::storage(
                "the reserve cell's leader is unreachable — no member stands in; retry with \
                 the same bytes"
                    .to_string(),
                None::<std::io::Error>,
            ));
        }
        match read_successor(&set, &parent).await? {
            SuccessorRead::Final { release, .. } if release.envelope_bytes == envelope => {
                if !keep_release_completion(&set, &parent, &envelope).await? {
                    return Err(storage_err(
                        "reserve completion",
                        "the release read final but its completion proof could not be built \
                         from the seats — retry with the same bytes",
                    ));
                }
                won = Some((generation, envelope, op_digest));
                break;
            }
            SuccessorRead::LeaderHeld { release, .. } if release.envelope_bytes == envelope => {
                return Err(DsmError::storage(
                    "the release holds the reserve cell's leader link but its chain does not \
                     have three links yet — retry with the same bytes"
                        .to_string(),
                    None::<std::io::Error>,
                ));
            }
            // Another release got to the leader first: the head moved.
            SuccessorRead::Final { .. } | SuccessorRead::LeaderHeld { .. } => continue,
            SuccessorRead::Open | SuccessorRead::Unavailable(..) => {
                return Err(DsmError::storage(
                    "the reserve cell could not be read back — retry with the same bytes"
                        .to_string(),
                    None::<std::io::Error>,
                ))
            }
        }
    }
    let Some((generation, envelope, op_digest)) = won else {
        return Err(DsmError::storage(
            format!("no reserve generation won in {MAX_ATTEMPTS} attempts — retry later"),
            None::<std::io::Error>,
        ));
    };

    // ── Prepare-first, through the ONE generalized producer ────────────────
    // The witness is built by the SAME write-set table the verifier checks;
    // the claim contributes only its facts (the release's evidence address)
    // and its extra frozen artifact (the exact final release).
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let pre_root = tree.root();
    let op = Operation::FaucetClaim {
        reserve_id,
        generation,
    };
    let prepared = PendingEconomicAdmission::prepared(
        PendingAdmissionKind::DsmBacked,
        target_position,
        pre_root,
        op_digest,
    );
    let delta = BalanceDelta {
        policy_commit: dsm::core::token::token_state_manager::era_policy_commit(),
        direction: BalanceDirection::Credit,
        amount: ERA_FAUCET_PAYOUT,
    };
    let authority = authority_material(network_id, &genesis)?;
    let facts = CreditSourceFacts::NativeReserveRelease {
        release_evidence_addr: release_evidence_addr(&envelope),
    };
    let extra = vec![(
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_NATIVE_RESERVE_RELEASE,
            &envelope,
        ),
        envelope.clone(),
        "native-reserve-release",
    )];
    let mut built = None;
    let pending = core
        .faucet_claim_advance(
            op.clone(),
            &delta,
            prepared,
            |chain_state| {
                let parts = build_dsm_admission(
                    &genesis,
                    &devid,
                    chain_state,
                    &op,
                    &pre_state,
                    &mut tree,
                    &facts,
                    &authority,
                    extra,
                )?;
                let coords = parts.coords;
                let artifacts = parts.artifacts.clone();
                built = Some(parts);
                Ok((coords, artifacts))
            },
            &set.id(),
            None,
        )?
        .1;
    let parts = built.ok_or_else(|| {
        DsmError::storage(
            "advance committed without building the witness".to_string(),
            None::<std::io::Error>,
        )
    })?;

    // ── Publish evidence, register the root, verify, admit ────────────────
    let admitted = finish_admission(
        core,
        network_id,
        &set,
        &validated,
        parts.witness,
        parts.manifest,
        op,
        pending,
        Vec::new(),
    )
    .await?;
    Ok(ClaimOutcome {
        tokens_received: ERA_FAUCET_PAYOUT,
        economic_position: admitted.economic_position,
    })
}
