// SPDX-License-Identifier: MIT OR Apache-2.0
//! A relationship's lifecycle steps, online (DSM Amendment A33).
//!
//! A relationship's first step is ESTABLISH, a moneyless step the device
//! with the lower id makes when its person adds the contact, and the other
//! device countersigns when its person has added too: the relationship is
//! established on both sides once the countersigned step is held. Either side
//! ends it with TERMINATE, a moneyless step the other side acknowledges by
//! countersigning; nothing moves on it from the moment the step is made.
//!
//! A lifecycle step is made, delivered, countersigned and finalized exactly
//! as an online transfer is (`app_router_impl::send_online`, the ingestion
//! boundary, `storage_routes`), with nothing economic: no admission, no
//! debit, no release. Its proposal is the same durable record, deliverable
//! at once; its receipt is signed with the same per-step keys; its
//! countersignature finalizes the maker on `sig_b` alone.

use dsm::core::relationship_lifecycle::{establish_operation, terminate_operation, LifecycleStep};
use dsm::types::error::DsmError;

use super::app_router_impl::{contact_relationship_tip, AppRouterImpl};
use super::recipient_accept::VerifiedTransfer;
use crate::storage::client_db::{self, RelationshipState};

/// Which device makes a relationship's ESTABLISH step: the one with the
/// lower device id. One maker per relationship, so two establishments never
/// cross; the other device countersigns when its person adds.
pub(crate) fn makes_establishment(this: &[u8; 32], other: &[u8; 32]) -> bool {
    this < other
}

/// The relationship state after this device applies the other side's step.
pub(crate) fn state_after_applying(step: LifecycleStep) -> RelationshipState {
    match step {
        LifecycleStep::Establish { .. } => RelationshipState::Established,
        LifecycleStep::Terminate { .. } => RelationshipState::Ended,
    }
}

/// The other side countersigned this device's lifecycle step: the
/// relationship is established, or ended, on both sides.
pub(crate) fn record_step_countersigned(counterparty: &[u8; 32]) -> Result<(), String> {
    let state = client_db::relationship_state(counterparty).map_err(|e| e.to_string())?;
    let next = match state {
        RelationshipState::Proposed => RelationshipState::Established,
        RelationshipState::Ending => RelationshipState::Ended,
        // Already recorded, or the other side's own step moved it first (a
        // crossing termination): nothing to move.
        RelationshipState::Established | RelationshipState::Ended | RelationshipState::Opened => {
            return Ok(())
        }
    };
    client_db::set_relationship_state(counterparty, next).map_err(|e| e.to_string())
}

/// What the maker is about to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepToMake {
    Establish,
    Terminate,
}

/// Everything a lifecycle step determines before anything is deliverable,
/// committed with the canonical advance in one transaction.
struct LifecycleArtifacts {
    proposal: client_db::SenderOnlineProposal,
    outbox: client_db::SenderOutboxRecord,
    submission_id: String,
    ek_material: super::app_router_impl::PendingEkMaterial,
    extra_artifacts: Vec<client_db::SenderOutboxArtifact>,
    state_while_pending: RelationshipState,
}

impl AppRouterImpl {
    /// A contact was added, or added again: the relationship's establishment
    /// begins. The maker makes the ESTABLISH step; the other device records
    /// nothing more than the contact, and countersigns the step when it
    /// reads it.
    pub(crate) async fn begin_establishment(&self, counterparty: [u8; 32]) -> Result<(), String> {
        let state = client_db::relationship_state(&counterparty).map_err(|e| e.to_string())?;
        match state {
            RelationshipState::Opened
                if makes_establishment(&self.device_id_bytes, &counterparty) =>
            {
                self.make_lifecycle_step(counterparty, StepToMake::Establish)
                    .await
                    .map_err(|e| format!("establishing the relationship: {e}"))
            }
            // The other device makes it; or the step is already under way,
            // done, or the relationship is over.
            _ => Ok(()),
        }
    }

    /// End the relationship with `counterparty`: the TERMINATE step, from
    /// this device's current tip on it. Nothing moves on the relationship
    /// from here on; the other side acknowledges when it reads the step.
    ///
    /// A relationship whose establishment this device made and the other
    /// side has not countersigned holds a step in flight, and one step at a
    /// time is the rule: it ends on this device's record alone, with no
    /// second step. Nothing moves on it either way; the other side's wallet,
    /// if it countersigns later, holds the relationship established and its
    /// sends are refused here as sends on an ended relationship.
    pub(crate) async fn terminate_relationship(
        &self,
        counterparty: [u8; 32],
    ) -> Result<(), String> {
        let state = client_db::relationship_state(&counterparty).map_err(|e| e.to_string())?;
        match state {
            RelationshipState::Ending | RelationshipState::Ended => {
                Err("the relationship has already ended".to_string())
            }
            RelationshipState::Proposed => {
                log::info!(
                    "[relationship.step] ending the relationship with {}.. while its establishment \
                     is still proposed: ended on this device's record, no second step in flight",
                    crate::util::text_id::encode_base32_crockford(&counterparty[..4])
                );
                client_db::set_relationship_state(&counterparty, RelationshipState::Ended)
                    .map_err(|e| format!("ending the relationship: {e}"))
            }
            RelationshipState::Opened | RelationshipState::Established => self
                .make_lifecycle_step(counterparty, StepToMake::Terminate)
                .await
                .map_err(|e| format!("ending the relationship: {e}")),
        }
    }

    /// Make one lifecycle step on the relationship with `counterparty`, as a
    /// send is made: the preflight sync, the step door, the send-ready
    /// authority (for a lifecycle step), the Tripwire preflight, the signed
    /// operation, then the canonical advance with the proposal, gate, pending
    /// key head, outbox row and evidence in ONE transaction, then delivery.
    async fn make_lifecycle_step(
        &self,
        counterparty: [u8; 32],
        step: StepToMake,
    ) -> Result<(), String> {
        let from_device_id = self.device_id_bytes;
        let network = crate::sdk::economic_admission_flow::committed_network_id()
            .map_err(|e| format!("no committed network: {e}"))?;
        let spool_set = crate::sdk::storage_set::canonical_set(&network)
            .map_err(|e| format!("no pinned storage set: {e}"))?;
        let storage_endpoints: Vec<String> = spool_set
            .members()
            .iter()
            .map(|member| member.endpoint.clone())
            .collect();
        let local_genesis_bytes = self
            .core_sdk
            .local_genesis_hash()
            .await
            .map_err(|e| format!("local genesis unavailable: {e}"))?;
        let local_genesis: [u8; 32] = local_genesis_bytes
            .as_slice()
            .try_into()
            .map_err(|e| format!("the local genesis is not 32 bytes: {e}"))?;

        // A step the other side made is taken first.
        if let Err(e) = self
            .run_storage_sync_request(crate::sdk::inbox_poller::poll_sync_request())
            .await
        {
            return Err(format!(
                "the relationship could not be refreshed first: {e}"
            ));
        }
        let contact = client_db::get_contact_by_device_id(&counterparty)
            .map_err(|e| format!("the contact is unreadable: {e}"))?
            .ok_or_else(|| "the contact is not held".to_string())?;
        if contact.public_key.is_empty() || contact.kyber_public_key.is_empty() {
            return Err("the contact holds no keys".to_string());
        }
        let counterparty_genesis: [u8; 32] = contact
            .genesis_hash
            .as_slice()
            .try_into()
            .map_err(|e| format!("the contact's genesis is not 32 bytes: {e}"))?;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &from_device_id,
            &counterparty,
        );
        let resync_blocks = client_db::cert_resync_blocks_send(&rel_key)
            .map_err(|e| format!("cert-resync gate check failed: {e}"))?;
        if resync_blocks {
            return Err("this relationship needs a cert-chain resync before any step".to_string());
        }

        self.ensure_authoritative_wallet_state("relationship.step")
            .map_err(|e| format!("authoritative state: {e}"))?;

        // One step at a time on the relationship: the online reservation and
        // the send-ready check under the doors' one critical section.
        let door = crate::security::modal_sync_lock::STEP_DOOR.lock().await;
        let _modal_lock = crate::security::modal_sync_lock::PendingOnlineGuard::acquire(&rel_key)
            .ok_or_else(|| {
            "the relationship already has a pending online step; retry after sync".to_string()
        })?;
        let status = super::relationship_status::derive_step_status_for_contact(
            &contact,
            super::relationship_status::StepKind::Lifecycle,
        );
        if !status.send_ready {
            return Err(super::relationship_status::status_message(&status));
        }
        drop(door);

        let chain_tip_arr = contact_relationship_tip(&contact)?;
        let parent_still_free =
            client_db::contact_chain_tip_matches_expected(&counterparty, &chain_tip_arr)
                .map_err(|e| format!("the relationship's parent tip: {e}"))?;
        if !parent_still_free {
            return Err("ParentConsumed: the relationship tip moved before the step".to_string());
        }

        // The operation: an establishment names the counterparty and the
        // tip it is made from; a termination names the two devices.
        let (op, state_while_pending) = match step {
            StepToMake::Establish => (
                establish_operation(&counterparty, &chain_tip_arr),
                RelationshipState::Proposed,
            ),
            StepToMake::Terminate => (
                terminate_operation(&from_device_id, &counterparty),
                RelationshipState::Ending,
            ),
        };
        let signing_bytes = op.to_bytes();
        let canonical_signature = self
            .wallet
            .sign_operation_bytes(&signing_bytes)
            .map_err(|e| format!("signing the step: {e}"))?;
        let sender_pk = crate::sdk::signing_authority::current_public_key()
            .map_err(|e| format!("the signing authority's key: {e}"))?;
        let self_verified =
            dsm::crypto::sphincs::sphincs_verify(&sender_pk, &signing_bytes, &canonical_signature)
                .map_err(|e| format!("self-verifying the step's signature: {e}"))?;
        if !self_verified {
            return Err("the step's signature does not verify".to_string());
        }

        let to_device_id_str = crate::util::text_id::encode_base32_crockford(&counterparty);
        let sender_genesis_b32 = crate::util::text_id::encode_base32_crockford(&local_genesis);
        let counterparty_genesis_b32 =
            crate::util::text_id::encode_base32_crockford(&counterparty_genesis);
        let op_for_wire = op.clone();
        let build = |advance_outcome: &dsm::types::device_state::AdvanceOutcome|
         -> Result<LifecycleArtifacts, DsmError> {
            let transition_entropy = advance_outcome.transition_entropy();
            let receipt_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                &chain_tip_arr,
                &signing_bytes,
                &transition_entropy,
            )?;
            let new_chain_tip = dsm::core::bilateral_transaction_manager::compute_successor_tip(
                &chain_tip_arr,
                &signing_bytes,
                &transition_entropy,
                &receipt_sigma,
            );
            let local_device_tree_commitment =
                crate::sdk::app_state::AppState::get_device_tree_commitment().ok_or_else(|| {
                    DsmError::invalid_operation("this device holds no Device Tree commitment")
                })?;
            let rc_canonical = crate::sdk::receipts::build_bilateral_receipt(
                from_device_id,
                counterparty,
                advance_outcome,
                None,
                &local_device_tree_commitment,
            )?;
            let (receipt_commit_bytes, ek_material) =
                self.sign_receipt_as_sender(&rc_canonical, receipt_sigma)?;
            let parsed = dsm::types::receipt_types::StitchedReceiptV2::from_canonical_protobuf(
                &receipt_commit_bytes,
            )
            .map_err(|e| DsmError::invalid_operation(format!("signed receipt reparse: {e}")))?;
            let commitment = parsed
                .compute_commitment()
                .map_err(|e| DsmError::invalid_operation(format!("receipt commitment: {e}")))?;
            let operation_digest = client_db::canonical_apply_operation_digest(&signing_bytes);
            let submission_id = dsm::crypto::spool_address::submission_id(&commitment);
            let proposal = client_db::SenderOnlineProposal {
                relationship_key: rel_key,
                canonical_parent: parsed.parent_tip,
                canonical_child: parsed.child_tip,
                projection_parent: chain_tip_arr,
                projection_target: new_chain_tip,
                commitment,
                operation_digest,
                // A lifecycle step is applied once by its own digest.
                nonce_hash: client_db::relationship_nonce_hash(&rel_key, &operation_digest),
                message_id: None,
                tx_id: format!("relationship-step-{submission_id}"),
                counterparty_device_id: counterparty,
                // Moves nothing, names no token: what marks the proposal a
                // lifecycle step's.
                amount: 0,
                token_id: String::new(),
                status: client_db::PROPOSAL_PROPOSED.to_string(),
            };
            let routing_address = dsm::crypto::spool_address::inbox_address(
                &counterparty_genesis,
                &counterparty,
                &chain_tip_arr,
            );
            let evidence_digest = dsm::crypto::spool_address::ArtifactRole::EvidenceA
                .content_digest(&receipt_commit_bytes);
            let params = crate::sdk::b0x_sdk::B0xSubmissionParams {
                submission_id: submission_id.clone(),
                recipient_device_id: to_device_id_str.clone(),
                recipient_genesis_hash: counterparty_genesis_b32.clone(),
                transaction: op_for_wire.clone(),
                signature: canonical_signature.clone(),
                sender_genesis_hash: sender_genesis_b32.clone(),
                routing_address: routing_address.clone(),
                canonical_operation_bytes: signing_bytes.clone(),
                // Nothing economic: no locators, no terms.
                sender_economic_position: 0,
                sender_debit_mutation_index: 0,
                transfer_terms: Vec::new(),
            };
            let builder = crate::sdk::b0x_sdk::B0xSDK::new(
                crate::util::text_id::encode_base32_crockford(&from_device_id),
                self.core_sdk.clone(),
                storage_endpoints.clone(),
            )?;
            let (envelope_bytes, ..) = builder.build_envelope_bytes(&params)?;
            crate::sdk::b0x_sdk::seal_for(&counterparty, &submission_id, &envelope_bytes)?;
            let evidence_submission_id =
                dsm::crypto::spool_address::artifact_submission_id(&evidence_digest);
            let evidence_envelope = builder.build_evidence_envelope(
                &to_device_id_str,
                &counterparty_genesis_b32,
                &evidence_submission_id,
                &evidence_digest,
                &receipt_commit_bytes,
            )?;
            crate::sdk::b0x_sdk::seal_for(
                &counterparty,
                &evidence_submission_id,
                &evidence_envelope.bytes,
            )?;
            let outbox = client_db::SenderOutboxRecord {
                relationship_key: rel_key,
                canonical_parent: proposal.canonical_parent,
                proposal_nonce: proposal.nonce_hash,
                canonical_child: proposal.canonical_child,
                commitment,
                projection_parent: chain_tip_arr,
                projection_target: new_chain_tip,
                routing_address,
                submission_id: submission_id.clone(),
                envelope_bytes,
                local_expected_prev: ek_material.expected_prev.clone(),
                is_first_ek_step: ek_material.is_first_ek_step,
                // Deliverable at once: nothing holds a step that moves no value.
                status: client_db::OUTBOX_PENDING_SUBMIT.to_string(),
                message_ids: None,
            };
            let evidence_artifact = client_db::SenderOutboxArtifact {
                relationship_key: rel_key,
                canonical_parent: proposal.canonical_parent,
                proposal_nonce: proposal.nonce_hash,
                role: dsm::crypto::spool_address::ArtifactRole::EvidenceA,
                submission_id: evidence_submission_id,
                envelope_bytes: evidence_envelope.bytes,
                content_digest: evidence_digest,
                routing_address: None,
            };
            Ok(LifecycleArtifacts {
                proposal,
                outbox,
                submission_id,
                ek_material,
                extra_artifacts: vec![evidence_artifact],
                state_while_pending,
            })
        };
        let staged = self
            .core_sdk
            .execute_on_relationship_staged_with_admission(
                rel_key,
                counterparty,
                op,
                &[],
                build,
                |tx, _outcome, artifacts: &LifecycleArtifacts| {
                    client_db::commit_send_prerequisites_with_conn(
                        tx,
                        &artifacts.proposal,
                        &artifacts.outbox,
                        &artifacts.submission_id,
                        &artifacts.ek_material.ek_pk,
                        &artifacts.ek_material.ek_sk,
                        &artifacts.ek_material.at_rest_key,
                        artifacts.ek_material.is_init,
                        &artifacts.extra_artifacts,
                    )
                    .map_err(|e| {
                        DsmError::internal(
                            format!("durable step bundle write failed: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    client_db::set_relationship_state_with_conn(
                        tx,
                        &counterparty,
                        artifacts.state_while_pending,
                    )
                    .map_err(|e| {
                        DsmError::internal(
                            format!("relationship state write failed: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                    Ok(())
                },
                None,
            )
            .map_err(|e| format!("the step did not commit: {e}"))?;
        let LifecycleArtifacts {
            proposal,
            outbox,
            submission_id,
            extra_artifacts,
            ..
        } = staged.artifacts;
        log::info!(
            "[relationship.step] {step:?} with {} committed at {}..; delivering",
            &to_device_id_str[..8],
            &submission_id[..8.min(submission_id.len())]
        );

        // Delivery, as a send delivers: the frozen bytes under their frozen
        // ids and route. A failure here is not proof of non-delivery; the row
        // moves to `submission_uncertain` and the sweep resubmits it.
        let _in_flight = client_db::DeliveryInFlight::claim(
            &outbox.relationship_key,
            &outbox.canonical_parent,
            &outbox.proposal_nonce,
        );
        if let Err(e) = client_db::set_sender_outbox_status(
            &outbox.relationship_key,
            &outbox.canonical_parent,
            &outbox.proposal_nonce,
            client_db::OUTBOX_SUBMITTING,
        ) {
            log::warn!("[relationship.step] the outbox row could not be marked submitting: {e}");
            return Ok(());
        }
        let mut b0x = crate::sdk::b0x_sdk::B0xSDK::new(
            crate::util::text_id::encode_base32_crockford(&from_device_id),
            self.core_sdk.clone(),
            storage_endpoints,
        )
        .map_err(|e| format!("spool client: {e}"))?;
        let retry = crate::sdk::b0x_sdk::B0xRetryConfig::default();
        match b0x
            .deliver_frozen_logical_send(&outbox, &extra_artifacts, &retry)
            .await
        {
            Ok(_) => {
                if let Err(e) = client_db::advance_sender_outbox_status_if(
                    &outbox.relationship_key,
                    &outbox.canonical_parent,
                    &outbox.proposal_nonce,
                    &[client_db::OUTBOX_SUBMITTING],
                    client_db::OUTBOX_SUBMITTED,
                ) {
                    log::error!("[relationship.step] delivered, but not recorded submitted: {e}");
                }
                if let Err(e) = client_db::mark_sender_proposal_submitted_if_proposed(
                    &proposal.relationship_key,
                    &proposal.canonical_parent,
                    &submission_id,
                ) {
                    log::error!("[relationship.step] proposal message-id bind failed: {e}");
                }
                crate::sdk::inbox_poller::resume_poller();
                Ok(())
            }
            Err(e) => {
                log::warn!(
                    "[relationship.step] delivery outcome unknown ({e}); the sweep resubmits"
                );
                if let Err(e) = client_db::advance_sender_outbox_status_if(
                    &outbox.relationship_key,
                    &outbox.canonical_parent,
                    &outbox.proposal_nonce,
                    &[client_db::OUTBOX_SUBMITTING],
                    client_db::OUTBOX_SUBMISSION_UNCERTAIN,
                ) {
                    log::error!("[relationship.step] could not record submission_uncertain: {e}");
                }
                Ok(())
            }
        }
    }

    /// Apply the other side's lifecycle step, bound to its receipt: the
    /// finality barrier, the pinned head, then the one staged apply with the
    /// B-side artifacts, the journal (no release), the key-chain steps, the
    /// pair's acceptance and the relationship's state in ONE transaction;
    /// then the same convergence a transfer gets. Returns the accepted pair.
    pub(crate) async fn complete_lifecycle_pair(
        &self,
        v: &VerifiedTransfer,
        step: LifecycleStep,
    ) -> Result<client_db::recipient_staging::StagedPair, String> {
        use super::recipient_accept::accept_bound_pair;
        use super::recipient_receipt as rr;
        use crate::storage::client_db::recipient_staging;

        let self_device = super::recipient_dispatch::this_device()?;
        let sender = v.sender;
        let sender_b32 = crate::util::text_id::encode_base32_crockford(&sender);
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&sender, &self_device);
        let awaits_certificate = client_db::relationship_awaits_peer_finalization(&rel_key)
            .map_err(|e| format!("barrier read failed: {e}"))?;
        if awaits_certificate {
            return Err(
                "held: a prior acceptance on this relationship awaits the peer's finality \
                 certificate"
                    .to_string(),
            );
        }
        let (ak_pk, ak_sk) = self
            .wallet
            .ak_keypair_for_cert_chain()
            .map_err(|e| format!("AK keypair unavailable: {e}"))?;
        let contact = client_db::get_contact_by_device_id(&sender)
            .map_err(|e| format!("sender contact unreadable: {e}"))?
            .ok_or_else(|| "the sender is no longer a contact".to_string())?;
        let sender_kyber_pk = contact.kyber_public_key.clone();
        let pinned_head = match client_db::pinned_counterparty_a_head(&rel_key) {
            Ok(Some(pinned)) => pinned,
            Ok(None) => {
                dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                    &self_device,
                    &sender,
                )
            }
            Err(e) => return Err(format!("the sender's pinned head is unreadable: {e}")),
        };
        if v.receipt.parent_tip != pinned_head && v.receipt.child_tip != pinned_head {
            return Err(
                "the signed parent is not the sender's head this device pinned".to_string(),
            );
        }
        let wrap_key = crate::init::current_chain_head_at_rest_key()
            .map_err(|e| format!("wrap key unavailable: {e}"))?;
        let devid = self
            .core_sdk
            .device_head()
            .map(|h| h.devid())
            .ok_or_else(|| "no device head".to_string())?;
        let core_sdk = self.core_sdk.clone();
        let state_after = state_after_applying(step);

        let rel_lock = rr::relationship_lock(&rel_key);
        let _rel_guard = rel_lock.lock_owned().await;

        let (_, stored) = accept_bound_pair(v, |v| {
            let signed_parent = v.receipt.parent_tip;
            let signed_child = v.receipt.child_tip;
            let transition_entropy = v.receipt.transition_entropy;
            let signed_sigma = dsm::core::bilateral_transaction_manager::compute_precommit(
                &signed_parent,
                &v.canonical_operation_bytes,
                &transition_entropy,
            )
            .map_err(|e| format!("the signed step's C_pre: {e}"))?;
            let projection_parent: [u8; 32] = client_db::get_contact_chain_tip(&sender)
                .map_err(|e| format!("the sender's relationship tip is unreadable: {e}"))?
                .ok_or_else(|| "the sender is not a contact".to_string())?;
            let projection_target: [u8; 32] = {
                let sigma_sym = dsm::core::bilateral_transaction_manager::compute_precommit(
                    &projection_parent,
                    &v.canonical_operation_bytes,
                    &transition_entropy,
                )
                .map_err(|e| format!("the projected step's C_pre: {e}"))?;
                dsm::core::bilateral_transaction_manager::compute_successor_tip(
                    &projection_parent,
                    &v.canonical_operation_bytes,
                    &transition_entropy,
                    &sigma_sym,
                )
            };
            let tx_id = crate::types::identifiers::TransactionId::new(v.transfer_name());
            let receipt = &v.receipt;
            let op_id = v.pair.op_id;
            let ek_rows: std::cell::RefCell<Option<Vec<([u8; 32], [u8; 32], Vec<u8>)>>> =
                std::cell::RefCell::new(None);
            core_sdk
                .apply_incoming_lifecycle_step_staged(
                    crate::sdk::core_sdk::IncomingLifecycleStep {
                        op: v.signed_op.clone(),
                        tx_id: &tx_id,
                        sender_device_id: &sender_b32,
                        canonical_operation_bytes: &v.canonical_operation_bytes,
                        signed_parent_tip: signed_parent,
                        signed_child_tip: signed_child,
                        sender_transition_entropy: transition_entropy,
                    },
                    |_outcome, b_pair| {
                        let b_art = rr::generate_b_artifacts_from_inbound(
                            receipt,
                            &signed_sigma,
                            &sender_kyber_pk,
                            &ak_pk,
                            &ak_sk,
                            &wrap_key,
                            b_pair,
                        )
                        .map_err(|e| {
                            DsmError::invalid_operation(format!("B-side acceptance artifacts: {e}"))
                        })?;
                        let rows = crate::sdk::economic_admission_flow::lifecycle_ek_step_rows(
                            &rel_key, &sender, &devid, &b_art,
                        )?;
                        *ek_rows.borrow_mut() = Some(rows);
                        Ok(b_art)
                    },
                    |tx, _outcome, artifacts| {
                        let internal = |what: &str, e: anyhow::Error| {
                            DsmError::internal(
                                format!("in-tx {what} failed: {e}"),
                                None::<std::convert::Infallible>,
                            )
                        };
                        client_db::insert_prepared_acceptance_journal_with_conn(
                            tx,
                            &rr::journal_row(
                                artifacts,
                                rel_key,
                                signed_parent,
                                (projection_parent, projection_target),
                                None,
                            ),
                        )
                        .map_err(|e| internal("acceptance journal insert", e))?;
                        let rows = ek_rows.borrow();
                        let rows = rows.as_ref().ok_or_else(|| {
                            DsmError::internal(
                                "key-chain rows missing at write",
                                None::<std::convert::Infallible>,
                            )
                        })?;
                        for (signer, addr, pk) in rows.iter() {
                            client_db::economic_lineage::append_ek_step_with_conn(
                                tx, &rel_key, signer, addr, pk,
                            )
                            .map_err(|e| internal("EK step append", e))?;
                        }
                        recipient_staging::mark_pair_accepted_with_conn(tx, &op_id)
                            .map_err(|e| internal("pair acceptance", e))?;
                        client_db::set_relationship_state_with_conn(tx, &sender, state_after)
                            .map_err(|e| internal("relationship state write", e))?;
                        Ok(())
                    },
                )
                .map_err(|e| format!("apply failed: {e}"))
        })?;
        log::info!(
            "[storage.sync] relationship step {} from {}.. applied: {state_after:?}",
            v.transfer_name(),
            &sender_b32[..8]
        );

        // Converge from durable state, as a transfer does: tip sync, CAS both
        // heads, enqueue the reply (no release).
        let parent = v.receipt.parent_tip;
        match (
            client_db::get_acceptance_journal(&rel_key, &parent),
            client_db::get_canonical_apply_identity(&rel_key, &parent),
        ) {
            (Ok(Some(journal)), Ok(Some(record))) => {
                rr::converge_accepted_locked(&journal, &record, &wrap_key)
                    .map(|_| ())
                    .map_err(|e| format!("accepted; convergence deferred: {e}"))?;
            }
            (journal, record) => {
                return Err(format!(
                    "journal/apply-record missing after accept (journal {}, record {})",
                    journal
                        .map(|j| j.is_some())
                        .map_err(|e| e.to_string())
                        .map_or_else(|e| e, |p| p.to_string()),
                    record
                        .map(|r| r.is_some())
                        .map_err(|e| e.to_string())
                        .map_or_else(|e| e, |p| p.to_string()),
                ))
            }
        }
        Ok(stored)
    }
}
