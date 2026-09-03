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

use dsm::economic::admission::{PendingAdmissionKind, PendingEconomicAdmission};
use dsm::economic::faucet::{
    dsm_operation_digest, era_faucet_id, faucet_claim_evidence_addr, sign_faucet_ticket_claim,
    FaucetTicketClaimBody, ERA_FAUCET_PAYOUT,
};
use dsm::economic::write_set::CreditSourceFacts;
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::{
    authority_material, build_dsm_admission, canonical_set, finish_admission,
    producer_tree_and_pre_state, resume_pending_admission, validated_root_or_activate,
};
use crate::sdk::economic_registers::{claim_faucet_ticket, select_ticket, RegisterError};
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

        match claim_faucet_ticket(&set, network_id, &envelope).await {
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

    // ── Prepare-first, through the ONE generalized producer ────────────────
    // The witness is built by the SAME write-set table the verifier checks;
    // the faucet contributes only its facts (the ticket evidence address)
    // and its extra frozen artifact (the exact winning envelope).
    let (mut tree, pre_state) = producer_tree_and_pre_state(&validated)?;
    let pre_root = tree.root();
    let op = Operation::FaucetClaim {
        faucet_id,
        ticket_index,
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
    let facts = CreditSourceFacts::FaucetTicket {
        faucet_claim_evidence_addr: faucet_claim_evidence_addr(&envelope),
    };
    let extra = vec![(
        crate::sdk::economic_registers::immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ERA_FAUCET_TICKET_CLAIM,
            &envelope,
        ),
        envelope.clone(),
        "faucet-ticket-claim",
    )];
    let mut built = None;
    let (_outcome, pending) = core.faucet_claim_advance(
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
    )?;
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
        tree,
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
