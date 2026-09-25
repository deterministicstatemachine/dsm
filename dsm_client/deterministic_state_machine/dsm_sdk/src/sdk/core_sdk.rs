// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Core SDK Module (strict / proto-only / clockless)
//!
//! Deterministic state & crypto semantics only:
//! - No JSON
//! - No wall clocks
//! - No removed APIs
//! - No `bincode`
//!
//! All ambiguous features fail-closed with `DsmError`.

use blake3::Hasher;
use parking_lot::Mutex;
use prost::Message;
use std::collections::HashMap;

use dsm::core::state_machine::StateMachine;
use dsm::core::token::policy::TokenPolicySystem;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation as DsmOperation;
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::TokenMetadata;

use crate::storage::client_db;
use crate::generated::TokenMetadataProto;

use log;

/* ------------------------------- Types ---------------------------------- */

/// Operation types (binary-only; no JSON or clocks)
#[derive(Debug, Clone)]
pub enum Operation {
    Transfer {
        token_id: Vec<u8>,
        recipient: Vec<u8>,
        amount: u64,
    },
    CreateIdentity {
        device_id: Vec<u8>,
    },
    Generic {
        operation_type: String,
        data: Vec<u8>,
        message: String,
    },
}

/* ------------------------------- CoreSDK -------------------------------- */

pub struct CoreSDK {
    state_machine: Mutex<StateMachine>,
    device_info: DeviceInfo,
    policy_system: TokenPolicySystem,
    /// Device-level fused-anchor appliance (Software-Authority / Hardware-Identity; the
    /// silicon). Lazily birthed on the first offline-bearer transfer; persists across transfers so
    /// its down-counter + fused-anchor lineage advance. Its `commit_0` is bootstrapped into the
    /// DeviceState anchor-state leaf on birth; each bearer transfer drives PREPARE→COMMIT→EMIT→
    /// FINALIZE and advances the leaf in the same `DeviceState::advance`.
    anchor_appliance: Mutex<Option<Box<dyn crate::anchor::AnchorAppliance + Send>>>,
}

/// The pending economic admission each device's head carried when THIS PROCESS
/// built its first `CoreSDK` for that device, as `(economic_position,
/// operation_digest)`, or `None` if there was no head or nothing pending.
/// Recorded once per device per process and never replaced. The SDK can be initialized more than once in a process (a bridge
/// re-init, an Android activity recreated while the process lives); a router
/// built then must not adopt an admission a live handler of this process
/// created. Ownership ruled 2026-09-15: recovery owns only what predates
/// process startup.
static PROCESS_STARTUP_ADMISSIONS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<[u8; 32], Option<(u64, [u8; 32])>>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/* ------------------------------- Helpers -------------------------------- */

fn blake3_cat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct TokenRegistryUpdateList {
    #[prost(message, repeated, tag = "1")]
    items: ::prost::alloc::vec::Vec<TokenMetadataProto>,
}

/* ------------------------------- Impl ----------------------------------- */

/// What a staged advance committed: the successor state, the advance outcome,
/// and the artifacts written in the same transaction.
pub(crate) struct StagedAdvance<A> {
    pub(crate) state: State,
    pub(crate) outcome: dsm::types::device_state::AdvanceOutcome,
    pub(crate) artifacts: A,
}

/// One economic admission riding one relationship advance — the SINGLE
/// generalized producer seam every admitted operation (faucet claim, transfer
/// debit, burn, create-token fee) goes through inside
/// `execute_on_relationship_inner`. There is deliberately no second producer
/// path.
///
/// The admitted predecessor this admission extends is DERIVED from
/// `prepared` (`position - 1` at `pre_economic_root`; position 1 extends the
/// canonical empty activation root) and is checked twice: under the
/// state-machine lock before the prepare, and re-asserted CAS-style inside
/// the commit transaction before local acceptance becomes durable.
pub struct AdmissionPlan<'a> {
    /// The Prepared admission (digest-only — acceptance coordinates are
    /// built against the REAL prepared successor).
    pub prepared: dsm::economic::admission::PendingEconomicAdmission,
    pub storage_set_id: [u8; 32],
    /// Build the acceptance coordinates + frozen artifacts from the exact
    /// prepared outcome. Runs at the staged seam: after the pure prepare,
    /// before anything durable.
    #[allow(clippy::type_complexity)]
    pub build: Box<
        dyn FnOnce(
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<
                (
                    dsm::economic::admission::AcceptedAdmissionCoords,
                    Vec<(String, Vec<u8>, &'static str)>,
                ),
                DsmError,
            > + 'a,
    >,
    /// Receives the accepted (post-`Prepared`) admission on success.
    pub accepted_out: &'a mut Option<dsm::economic::admission::PendingEconomicAdmission>,
}

impl CoreSDK {
    fn restore_latest_archived_state(
        state_machine: &Mutex<StateMachine>,
        device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        if let Some(head) =
            crate::storage::client_db::load_bcr_device_head(device_id).map_err(|e| {
                DsmError::state_machine(format!(
                    "Failed to load cached device head during startup restore: {e}"
                ))
            })?
        {
            let root = head.root();
            state_machine.lock().set_device_head(head);
            log::info!(
                "[CoreSDK] restored cached device head root={} for device {}",
                crate::util::text_id::encode_base32_crockford(&root),
                crate::util::text_id::encode_base32_crockford(device_id)
            );
        }

        Ok(())
    }

    /// The fence-coupled faucet-claim advance, PREPARE-FIRST: attach the
    /// `Prepared` admission (digest only — acceptance coordinates do not
    /// exist yet), run the self-loop advance (whose accepting gate REQUIRES
    /// that admission), hand the prepared successor's `C_dsm+` to `build` —
    /// which constructs the witness, manifest, coordinates and frozen
    /// artifacts against the REAL successor — and commit head + pending row +
    /// frozen evidence in ONE transaction. This ordering is forced by the v2
    /// operation identity: the witness names WHICH successor performed the
    /// operation, so it cannot be built before the successor exists.
    ///
    /// On any failure the pending attachment is rolled off the in-memory head
    /// so the device is not left fenced by a claim that never happened.
    /// Returns the accepted admission (post-`Prepared`, coordinates
    /// installed) that is now riding the durable head.
    /// The fence-coupled faucet-claim advance — now a THIN wrapper over the
    /// generalized admission seam (self-loop relationship, single credit
    /// delta). The bespoke body this replaced was the only other producer
    /// path; deleting it is the point.
    pub(crate) fn faucet_claim_advance(
        &self,
        operation: dsm::types::operations::Operation,
        delta: &dsm::types::device_state::BalanceDelta,
        prepared: dsm::economic::admission::PendingEconomicAdmission,
        build: impl FnOnce(
            &dsm::types::device_state::RelationshipChainState,
        ) -> Result<
            (
                dsm::economic::admission::AcceptedAdmissionCoords,
                Vec<(String, Vec<u8>, &'static str)>,
            ),
            DsmError,
        >,
        storage_set_id: &[u8; 32],
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
    ) -> Result<
        (
            dsm::types::device_state::AdvanceOutcome,
            dsm::economic::admission::PendingEconomicAdmission,
        ),
        DsmError,
    > {
        self.admitted_advance(
            operation,
            std::slice::from_ref(delta),
            prepared,
            build,
            storage_set_id,
            in_tx_extra,
        )
    }

    /// The generalized admission seam: a self-loop advance carrying a
    /// pending admission, with whatever balance deltas the operation's
    /// conservation rule takes — one credit for a faucet claim, one debit for
    /// a burn, NONE for a SoFi fulfillment, which moves no online balance at
    /// its transition (the claim it installs is conditional; the root a
    /// resolution selects enters through `advance_resolved`, R13).
    pub(crate) fn admitted_advance(
        &self,
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        prepared: dsm::economic::admission::PendingEconomicAdmission,
        build: impl FnOnce(
            &dsm::types::device_state::RelationshipChainState,
        ) -> Result<
            (
                dsm::economic::admission::AcceptedAdmissionCoords,
                Vec<(String, Vec<u8>, &'static str)>,
            ),
            DsmError,
        >,
        storage_set_id: &[u8; 32],
        // Additional same-transaction writer (e.g. the token-registry row),
        // composed AFTER the admission's pending row + artifact freeze.
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
    ) -> Result<
        (
            dsm::types::device_state::AdvanceOutcome,
            dsm::economic::admission::PendingEconomicAdmission,
        ),
        DsmError,
    > {
        let dev_id = self.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let mut accepted_out = None;
        let plan = AdmissionPlan {
            prepared,
            storage_set_id: *storage_set_id,
            build: Box::new(move |o: &dsm::types::device_state::AdvanceOutcome| {
                build(&o.new_chain_state)
            }),
            accepted_out: &mut accepted_out,
        };
        let (_state, outcome) = self.execute_on_relationship_inner(
            rel_key,
            dev_id,
            operation,
            deltas,
            None,
            None,
            in_tx_extra,
            None,
            Some(plan),
        )?;
        let accepted = accepted_out.ok_or_else(|| {
            DsmError::internal(
                "admission advance committed without an accepted admission",
                None::<std::convert::Infallible>,
            )
        })?;
        Ok((outcome, accepted))
    }

    /// Persist a pending-admission lifecycle transition (EvidencePublished /
    /// Registered). Forward-only; the head's fence semantics are unchanged by
    /// these states (all three fence), so only the durable row moves.
    pub(crate) fn update_pending_admission_state(
        &self,
        pending: &dsm::economic::admission::PendingEconomicAdmission,
    ) -> Result<(), DsmError> {
        use crate::storage::client_db::get_connection;
        let devid = self.device_info.device_id;
        let binding = get_connection().map_err(|e| {
            DsmError::storage(format!("pending update: {e}"), None::<std::io::Error>)
        })?;
        let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        let tx = conn.transaction().map_err(|e| {
            DsmError::storage(format!("pending update tx: {e}"), None::<std::io::Error>)
        })?;
        crate::storage::client_db::economic_admission::put_pending_admission_with_conn(
            &tx, &devid, pending,
        )
        .map_err(|e| DsmError::storage(format!("pending update: {e}"), None::<std::io::Error>))?;
        tx.commit()
            .map_err(|e| DsmError::storage(format!("pending commit: {e}"), None::<std::io::Error>))
    }

    /// The terminal admission transaction: admitted coordinate + leaf cache +
    /// clear the pending row + persist the UNFENCED head — all or nothing, so
    /// "admitted" and "no longer pending" cannot disagree.
    ///
    /// For every admission but a resolved SoFi position, whose balances move
    /// at resolution: see [`Self::admit_resolved_sofi_position`].
    pub(crate) fn admit_economic_position(
        &self,
        admitted: dsm::economic::lineage::AdmittedEconomicPosition,
        operation_digest: &[u8; 32],
        leaves: &[([u8; 32], [u8; 32], Vec<u8>)],
        storage_set_id: &[u8; 32],
        post_admit_artifacts: &[(String, Vec<u8>, &'static str)],
    ) -> Result<(), DsmError> {
        let economic_root = match &admitted {
            dsm::economic::lineage::AdmittedEconomicPosition::SingleRoot {
                economic_root, ..
            } => *economic_root,
            dsm::economic::lineage::AdmittedEconomicPosition::ResolvedSofi { .. } => {
                return Err(DsmError::invalid_operation(
                    "admit: a resolved SoFi position moves the balances its resolution \
                     selected, and is admitted with them",
                ))
            }
            dsm::economic::lineage::AdmittedEconomicPosition::UnresolvedSofi { .. } => {
                return Err(DsmError::invalid_operation(
                    "admit: a conditional position that has selected no root is not terminal",
                ))
            }
        };
        self.admit(
            &admitted,
            economic_root,
            operation_digest,
            leaves,
            storage_set_id,
            post_admit_artifacts,
            &[],
            None,
        )
    }

    /// The terminal admission of a SoFi position `advance_resolved` resolved:
    /// the position is admitted at the root the resolution selected, the vault
    /// heads it selected are recorded, and the unfenced head takes the trader
    /// balances that root holds — all in the one admission transaction, so the
    /// head and the admitted root cannot disagree about what this device holds.
    pub(crate) fn admit_resolved_sofi_position(
        &self,
        advanced: &dsm::sofi::lineage::ResolvedAdvance,
        fulfillment_id: [u8; 32],
        operation_digest: &[u8; 32],
        leaves: &[([u8; 32], [u8; 32], Vec<u8>)],
        storage_set_id: &[u8; 32],
        // The vault heads this position selected (spec §44.4), recorded in
        // THIS transaction so a head and the position that chose it cannot
        // disagree.
        vault_heads: &[dsm::sofi::validation::VaultPostState],
    ) -> Result<(), DsmError> {
        let admitted = dsm::economic::lineage::AdmittedEconomicPosition::ResolvedSofi {
            economic_position: advanced.root.economic_position(),
            selected_root: advanced.root.economic_root(),
            fulfillment_id,
            claim_ref: advanced.claim.claim_ref(),
        };
        self.admit(
            &admitted,
            advanced.root.economic_root(),
            operation_digest,
            leaves,
            storage_set_id,
            &[],
            vault_heads,
            Some(&advanced.balances),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit(
        &self,
        admitted: &dsm::economic::lineage::AdmittedEconomicPosition,
        // The root the position holds, which the post-admit artifacts bind to.
        economic_root: [u8; 32],
        operation_digest: &[u8; 32],
        leaves: &[([u8; 32], [u8; 32], Vec<u8>)],
        storage_set_id: &[u8; 32],
        post_admit_artifacts: &[(String, Vec<u8>, &'static str)],
        vault_heads: &[dsm::sofi::validation::VaultPostState],
        resolved: Option<&dsm::sofi::lineage::ResolvedBalances>,
    ) -> Result<(), DsmError> {
        use crate::storage::client_db::{get_connection, update_bcr_device_head_with_conn};
        let economic_position = admitted.economic_position();
        let devid = self.device_info.device_id;
        let mut sm = self.state_machine.lock();
        let head = sm
            .device_head()
            .cloned()
            .ok_or_else(|| DsmError::storage("no head".to_string(), None::<std::io::Error>))?;
        // COMPARE-AND-ADMIT, under the state-machine lock: the head must still
        // carry exactly this admission. A stale admit writes nothing, so it can
        // neither clear a newer pending admission nor regress the admitted
        // coordinate.
        match head.pending_economic_admission() {
            Some(p)
                if p.economic_position == economic_position
                    && &p.operation_digest == operation_digest => {}
            other => {
                return Err(DsmError::invalid_operation(format!(
                    "admit: the head no longer carries the admission at position \
                     {economic_position} (it carries {}); refusing a stale admit",
                    other.map_or_else(|| "none".to_string(), |p| p.economic_position.to_string())
                )))
            }
        }
        let unfenced = match resolved {
            Some(balances) => head.with_resolved_position(balances)?,
            None => head,
        }
        .with_pending_economic_admission(None);
        {
            let binding = get_connection()
                .map_err(|e| DsmError::storage(format!("admit: {e}"), None::<std::io::Error>))?;
            let mut conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let tx = conn
                .transaction()
                .map_err(|e| DsmError::storage(format!("admit tx: {e}"), None::<std::io::Error>))?;
            crate::storage::client_db::economic_lineage::record_admitted_with_conn(
                &tx, admitted, leaves,
            )
            .map_err(|e| DsmError::storage(format!("admit record: {e}"), None::<std::io::Error>))?;
            for post in vault_heads {
                crate::storage::client_db::sofi_vault_head::record_resolved_with_conn(&tx, post)
                    .map_err(|e| {
                        DsmError::storage(format!("admit vault head: {e}"), None::<std::io::Error>)
                    })?;
            }
            crate::storage::client_db::economic_admission::clear_pending_admission_with_conn(
                &tx, &devid,
            )
            .map_err(|e| DsmError::storage(format!("admit clear: {e}"), None::<std::io::Error>))?;
            update_bcr_device_head_with_conn(&tx, &unfenced).map_err(|e| {
                DsmError::storage(format!("admit head: {e}"), None::<std::io::Error>)
            })?;
            // A held sender-outbox row becomes deliverable in THIS transaction
            // and no earlier: ECON_ADMITTED atomically releases the outbox.
            crate::storage::client_db::sender_outbox::promote_held_outbox_rows_with_conn(&tx)
                .map_err(|e| {
                    DsmError::storage(format!("admit promote: {e}"), None::<std::io::Error>)
                })?;
            // Likewise the recipient's HELD B→A reply (carrying the release
            // address): the sender may only ever finalize on a release whose
            // admission is terminal, so the reply becomes deliverable
            // atomically with ECON_ADMITTED.
            crate::storage::client_db::recipient_receipt_fold::promote_held_replies_with_conn(&tx)
                .map_err(|e| {
                    DsmError::storage(
                        format!("admit promote replies: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            // Post-admission artifacts (the RELEASE object): frozen in THIS
            // transaction and no earlier — the sweep may only ever publish a
            // release whose admission is terminal.
            for (key, payload, purpose) in post_admit_artifacts {
                crate::storage::client_db::frozen_publication_artifact::freeze_artifact_with_conn(
                    &tx,
                    storage_set_id,
                    key,
                    payload,
                    &economic_root,
                    purpose,
                )
                .map_err(|e| {
                    DsmError::storage(format!("admit freeze {key}: {e}"), None::<std::io::Error>)
                })?;
            }
            tx.commit().map_err(|e| {
                DsmError::storage(format!("admit commit: {e}"), None::<std::io::Error>)
            })?;
        }
        // The head in memory is the head just made durable.
        sm.set_device_head(unfenced);
        Ok(())
    }

    /// The full seam: head + pending row + FROZEN EVIDENCE, one transaction.
    ///
    /// `artifacts` are `(object_key, exact payload bytes, purpose)` — every
    /// canonical input recovery needs to reproduce the admission evidence
    /// byte-identically. Freezing them here, in the same transaction as the
    /// value-bearing acceptance, is the durability invariant: a crash leaves
    /// either nothing, or a head + pending row + complete frozen evidence.
    /// Recovery re-signs NOTHING and asks the user for nothing.
    pub(crate) fn commit_advance_with_pending_admission_and_artifacts(
        outcome: &dsm::types::device_state::AdvanceOutcome,
        bump_capsule: bool,
        pending: &dsm::economic::admission::PendingEconomicAdmission,
        artifacts: &[(String, Vec<u8>, &'static str)],
        storage_set_id: &[u8; 32],
        // Additional same-transaction writer (send prerequisites, token
        // registry, ...) — chained AFTER the pending row + artifact freeze so
        // callers COMPOSE with the admission commit rather than replace it.
        also: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
    ) -> Result<(), DsmError> {
        let devid = outcome.new_device_state.devid();
        if !dsm::economic::admission::head_carries_admission(
            outcome.new_device_state.pending_economic_admission(),
            pending,
        ) {
            return Err(DsmError::invalid_operation(
                "commit_advance_with_pending_admission: the head being committed does not carry \
                 this admission — the durable head and the durable row would disagree about \
                 whether the device is fenced",
            ));
        }
        let pending = pending.clone();
        let bound_root = outcome.new_device_state.root();
        let set_id = *storage_set_id;
        let artifacts: Vec<(String, Vec<u8>, &'static str)> = artifacts.to_vec();
        Self::dual_write_advance_outcome_with_extra(
            outcome,
            bump_capsule,
            Some(&move |tx: &rusqlite::Transaction<'_>,
                        o: &dsm::types::device_state::AdvanceOutcome| {
                // CAS re-assert of the admitted predecessor INSIDE the
                // transaction that makes local acceptance durable: the
                // pre-lock check can go stale only through this same
                // serialized path, but the invariant is cheap to restate and
                // a violated restatement is corruption, not a race.
                let admitted =
                    crate::storage::client_db::economic_lineage::get_admitted_with_conn(tx)
                        .map_err(|e| {
                            DsmError::storage(
                                format!("admission predecessor CAS: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;
                let (expect_pos, expect_root) = match admitted {
                    Some(a) => {
                        // THE FENCE, on the commit that makes acceptance
                        // durable. It decides more than the equality below:
                        // for a resolved conditional predecessor it requires
                        // this descendant to be built on the root the route
                        // actually selected, and for an unresolved one it
                        // refuses outright.
                        dsm::sofi::lineage::descendant_fence(
                            a.predecessor_claim(),
                            &pending.pre_economic_root,
                        )
                        .map_err(|e| {
                            DsmError::invalid_operation(format!("admission commit: {e}"))
                        })?;
                        let v = dsm::economic::lineage::ValidatedEconomicRoot::
                            rehydrate_from_admitted_store(a)
                            .map_err(|e| {
                                DsmError::invalid_operation(format!("admission commit: {e}"))
                            })?;
                        (v.economic_position() + 1, v.economic_root())
                    }
                    None => (1, dsm::economic::tree::empty_economic_root()),
                };
                if pending.economic_position != expect_pos
                    || pending.pre_economic_root != expect_root
                {
                    return Err(DsmError::invalid_operation(
                        "admission commit: the admitted predecessor changed under the \
                         admission — refusing to make a stale acceptance durable",
                    ));
                }
                crate::storage::client_db::economic_admission::put_pending_admission_with_conn(
                    tx, &devid, &pending,
                )
                .map_err(|e| {
                    DsmError::storage(
                        format!("commit pending economic admission: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
                for (key, payload, purpose) in &artifacts {
                    crate::storage::client_db::frozen_publication_artifact::
                        freeze_artifact_with_conn(tx, &set_id, key, payload, &bound_root, purpose)
                    .map_err(|e| {
                        DsmError::storage(
                            format!("freeze admission evidence {key}: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                }
                if let Some(also) = also {
                    also(tx, o)?;
                }
                Ok(())
            }),
        )
    }

    fn dual_write_advance_outcome_with_extra(
        outcome: &dsm::types::device_state::AdvanceOutcome,
        bump_capsule: bool,
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
    ) -> Result<(), DsmError> {
        use crate::storage::client_db::{
            get_connection, store_bcr_chain_state_with_conn, update_bcr_device_head_with_conn,
        };
        let devid = outcome.new_device_state.devid();

        let binding = get_connection().map_err(|e| {
            DsmError::storage(
                format!("dual-write: get_connection failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let mut conn = binding.lock().unwrap_or_else(|poisoned| {
            log::warn!("[CoreSDK] dual-write: DB lock poisoned, recovering");
            poisoned.into_inner()
        });

        let tx = conn.transaction().map_err(|e| {
            DsmError::storage(
                format!("dual-write: begin transaction failed: {e}"),
                None::<std::io::Error>,
            )
        })?;

        store_bcr_chain_state_with_conn(&tx, &devid, &outcome.new_chain_state, false).map_err(
            |e| {
                DsmError::storage(
                    format!("dual-write: store_bcr_chain_state failed: {e}"),
                    None::<std::io::Error>,
                )
            },
        )?;
        update_bcr_device_head_with_conn(&tx, &outcome.new_device_state).map_err(|e| {
            DsmError::storage(
                format!("dual-write: update_bcr_device_head failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        // Capsule currency (spec §5.1): advance the accepted-state index ATOMICALLY
        // with the state commit so a frontier-changing transition can never be
        // persisted without the recovery capsule being marked dirty. Closes the
        // post-commit fail-OPEN (a missed bump on already-committed state). Uses
        // the transaction's own connection — never opens a new one (deadlock).
        if bump_capsule {
            crate::storage::client_db::recovery::bump_accepted_state_index_with_conn(&tx).map_err(
                |e| {
                    DsmError::storage(
                        format!("dual-write: bump accepted_state_index failed: {e}"),
                        None::<std::io::Error>,
                    )
                },
            )?;
        }
        // §16.6: caller-injected full-state-consumption work (nonce consumption +
        // canonical apply record for the incoming-transfer apply). Same tx — an
        // Err here rolls back the state persistence too.
        if let Some(extra) = in_tx_extra {
            extra(&tx, outcome)?;
        }
        tx.commit().map_err(|e| {
            DsmError::storage(
                format!("dual-write: commit failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        Ok(())
    }

    /// Explicit head-cache write for genesis.
    ///
    /// Genesis has no `AdvanceOutcome` (no relationships exist yet), but the
    /// `bcr_device_heads` cache needs a row so restore / reader paths can
    /// locate the device. The `genesis_hash` argument is the canonical
    /// `G_A` digest from the genesis state — it populates `DeviceState.genesis`
    /// (§2.2) and is also used as the legacy SMT-root anchor for the
    /// initial head so `verify_state` checks against the genesis hash work
    /// before any relationship advance has fired.
    ///
    /// `genesis` is set UNCONDITIONALLY, on both branches. It used to be written
    /// only by the constructor in the `unwrap_or_else`, so a pre-existing head
    /// kept whatever root it was built with — and that is the branch genesis
    /// install always takes, because `StateMachine::set_state` materialises a
    /// head (with a `[0u8; 32]` genesis) before this runs. The result was a
    /// persisted head whose authority root was zeros while `AppState` held the
    /// correct `v3.g`, and every reader of `genesis_digest()` compared against
    /// zeros. Honouring the contract on both branches is the fix; nothing
    /// downstream is taught to tolerate a zero root.
    fn write_genesis_device_head(&self, genesis_hash: [u8; 32]) -> Result<(), DsmError> {
        use crate::storage::client_db::update_bcr_device_head;
        let mut head = self.device_head().unwrap_or_else(|| {
            dsm::types::device_state::DeviceState::new(
                genesis_hash,
                self.device_info.device_id,
                self.device_info.public_key.clone(),
            )
        });
        head.set_genesis_digest(genesis_hash);
        if head.legacy_anchor().is_none() {
            head.bootstrap_legacy_root(genesis_hash);
        }
        update_bcr_device_head(&head).map_err(|e| {
            DsmError::storage(
                format!("genesis head-cache write failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        // Install it IN MEMORY as well. `StateMachine::set_state` no longer
        // manufactures a head (it does not know `G` and must not invent one), so
        // this is now the only thing that gives the state machine a head at
        // genesis — and callers read `device_head()` straight after install.
        // Creating it here is the point: this function has the canonical root.
        self.state_machine.lock().set_device_head(head);
        Ok(())
    }

    /// Initialize CoreSDK with an explicit device identity (preferred for wallet/runtime use).
    ///
    /// Passing the canonical device_id here ensures that token/accounting paths which rely on
    /// `State.device_info` use the caller's real device identifier. This keeps token balances,
    /// mint/transfer senders, and storage keys aligned with the active wallet device.
    pub fn new_with_device(device_info: DeviceInfo) -> Result<Self, DsmError> {
        log::info!(
            "Initializing CoreSDK (strict/proto-only/clockless) for device {}",
            crate::util::text_id::encode_base32_crockford(&device_info.device_id)
        );
        let policy_system = TokenPolicySystem::new();
        // Preload standard token policies (ERA) synchronously
        policy_system.preload_standard_policies_blocking()?;

        let state_machine = Mutex::new(StateMachine::new());

        Self::restore_latest_archived_state(&state_machine, &device_info.device_id)?;
        Self::record_process_startup_admission(&state_machine, &device_info.device_id);

        Ok(Self {
            state_machine,
            device_info,
            policy_system,
            anchor_appliance: Mutex::new(None),
        })
    }

    /// Record, at the FIRST `CoreSDK` built for this device in this process, the
    /// pending admission its restored head carries (`None` when there is no head
    /// or nothing is pending). Never replaced: a later construction in the same
    /// process (a bridge re-init, an activity recreated while the process lives)
    /// records nothing, so no head created or loaded later in this process can
    /// have its admission adopted.
    fn record_process_startup_admission(state_machine: &Mutex<StateMachine>, device_id: &[u8; 32]) {
        let coords = state_machine.lock().device_head().and_then(|h| {
            h.pending_economic_admission()
                .map(|p| (p.economic_position, p.operation_digest))
        });
        PROCESS_STARTUP_ADMISSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(*device_id)
            .or_insert(coords);
    }

    /// Whether `pending` is the admission this device's head already carried when
    /// THIS PROCESS built its first `CoreSDK` for the device: an admission the
    /// running process did not create.
    pub(crate) fn admission_predates_startup(
        &self,
        pending: &dsm::economic::admission::PendingEconomicAdmission,
    ) -> bool {
        PROCESS_STARTUP_ADMISSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&self.device_info.device_id)
            .copied()
            .flatten()
            == Some((pending.economic_position, pending.operation_digest))
    }

    /// Forget every process-startup record. TEST ONLY: it models a process
    /// restart for tests that build a fresh router over the same database.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn forget_process_startup_admissions_for_testing() {
        PROCESS_STARTUP_ADMISSIONS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    pub fn get_device_identity(&self) -> DeviceInfo {
        self.device_info.clone()
    }

    /// Sign a dsm `Operation` in-place using the device's SPHINCS+ secret key.
    /// Uses `with_cleared_signature()` / `to_bytes()` for the canonical payload.
    /// Returns the operation with the signature field populated.
    ///
    pub fn sign_operation_sphincs(
        &self,
        mut operation: DsmOperation,
    ) -> Result<DsmOperation, DsmError> {
        let sk = crate::sdk::signing_authority::current_secret_key()?;

        let cleared = operation.with_cleared_signature();
        let payload = cleared.to_bytes();
        let sig = dsm::crypto::sphincs::sphincs_sign(&sk, &payload).map_err(|e| {
            DsmError::crypto(
                format!("Failed to sign operation: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Set the signature on the operation
        match &mut operation {
            DsmOperation::Transfer { signature, .. }
            | DsmOperation::CreateToken { signature, .. }
            | DsmOperation::AdoptToken { signature, .. }
            | DsmOperation::Lock { signature, .. }
            | DsmOperation::Unlock { signature, .. }
            | DsmOperation::LockToken { signature, .. }
            | DsmOperation::UnlockToken { signature, .. }
            | DsmOperation::Generic { signature, .. }
            | DsmOperation::DlvCreate { signature, .. }
            | DsmOperation::DlvUnlock { signature, .. }
            | DsmOperation::DlvClaim { signature, .. }
            | DsmOperation::DlvInvalidate { signature, .. } => {
                *signature = sig;
            }
            // FAIL, never return unsigned. This arm used to `log::warn!` and hand back
            // the operation with an empty signature and an `Ok`, so a caller that asked
            // to sign a value-moving operation got a success it had no reason to doubt
            // and an operation no verifier would accept. `DlvSettle` and `DlvOwnerApply`
            // fell through here — both are `EgressAsset::Asset` — and the unsigned
            // result was committed into the canonical root, where it cannot be
            // retro-signed because the signature is inside `compute_chain_tip`.
            other => {
                return Err(DsmError::invalid_operation(format!(
                    "sign_operation_sphincs: {} carries no signature field",
                    other.get_operation_type()
                )));
            }
        }

        Ok(operation)
    }

    /// Current tip state (fail-closed if none).
    ///
    /// Returns a compatibility `State` view derived from the canonical
    /// `DeviceState`. Prefer `device_head()` for new code.
    pub fn get_current_state(&self) -> Result<State, DsmError> {
        // Delegate to StateMachine::current_state. The canonical DeviceState head
        // is the single source of truth: the compat `State` is always synthesized
        // from the head's SMT root + balances, with no override that could shadow
        // it. Pre-genesis paths return None which we surface as an explicit error.
        let sm = self.state_machine.lock();
        sm.current_state()
            .ok_or_else(|| DsmError::state_machine("No current state available"))
    }

    /// Refresh the in-memory canonical tip from the latest archived sparse-replay
    /// snapshot for this device.
    pub fn restore_latest_archived_state_for_device(&self) -> Result<(), DsmError> {
        Self::restore_latest_archived_state(&self.state_machine, &self.device_info.device_id)
    }

    /// Normalize stale balance key formats in the current state.
    ///
    /// Migrates:
    ///  - `"{u128}|ERA"` → plain `"ERA"` (keep MAX if both exist)
    ///  - `"{device_b32}.{token}"` dot-format entries are removed (pipe-format is authoritative)
    pub fn migrate_token_balance_keys(&self) {
        let mut sm = self.state_machine.lock();
        let state = match sm.current_state() {
            Some(s) => s,
            None => return,
        };

        let mut updated = state;
        let mut changed = false;

        let canonical_era_key = dsm::core::token::derive_canonical_balance_key(
            crate::policy::builtins::NATIVE_POLICY_COMMIT,
            &updated.device_info.public_key,
            "ERA",
        );

        // Collect keys to remove and entries to migrate
        let mut keys_to_remove: Vec<String> = Vec::new();
        let mut era_max: Option<dsm::types::token_types::Balance> = None;

        for (key, balance) in &updated.token_balances {
            if key == "ERA" {
                keys_to_remove.push(key.clone());
                era_max = Some(match era_max {
                    Some(existing) if existing.value() >= balance.value() => existing,
                    _ => balance.clone(),
                });
                continue;
            }

            // Detect pipe-format ERA keys like "{u128}|ERA"
            if let Some((_, token_id)) = key.split_once('|') {
                if token_id == "ERA" {
                    if key != &canonical_era_key {
                        keys_to_remove.push(key.clone());
                    }
                    era_max = Some(match era_max {
                        Some(existing) if existing.value() >= balance.value() => existing,
                        _ => balance.clone(),
                    });
                }
            }
            // Detect dot-format keys like "{device_b32}.{token}"
            if key.contains('.') && !key.contains('|') {
                keys_to_remove.push(key.clone());
            }
        }

        // Apply removals
        for key in &keys_to_remove {
            updated.token_balances.remove(key);
            changed = true;
        }

        // Merge migrated ERA balance into the canonical balance-key entry
        if let Some(migrated) = era_max {
            let existing = updated
                .token_balances
                .get(&canonical_era_key)
                .map(|b| b.value())
                .unwrap_or(0);
            if migrated.value() > existing {
                updated.token_balances.insert(canonical_era_key, migrated);
                changed = true;
            }
        }

        if changed {
            if let Ok(h) = updated.compute_hash() {
                updated.hash = h;
            }
            sm.set_state(updated);
            log::info!("[CoreSDK] Migrated stale balance keys to canonical format");
        }
    }

    /// Deterministic transition (binary payloads only)
    pub fn execute_transition(&self, operation: Operation) -> Result<State, DsmError> {
        let (op_type, data, message) = match operation {
            Operation::Transfer {
                token_id,
                recipient,
                amount,
            } => {
                if token_id.is_empty() || recipient.is_empty() || amount == 0 {
                    return Err(DsmError::invalid_operation(
                        "Transfer: invalid token/recipient/amount",
                    ));
                }
                let payload = [
                    &b"xfer"[..],
                    token_id.as_slice(),
                    recipient.as_slice(),
                    &u64_le(amount),
                ]
                .concat();
                (b"transfer".to_vec(), payload, "Transfer".to_string())
            }
            Operation::CreateIdentity { device_id } => {
                if device_id.is_empty() {
                    return Err(DsmError::invalid_operation(
                        "CreateIdentity: empty device_id",
                    ));
                }
                let payload = [&b"cid"[..], device_id.as_slice()].concat();
                (
                    b"create_identity".to_vec(),
                    payload,
                    "Create identity".to_string(),
                )
            }
            Operation::Generic {
                operation_type,
                data,
                message,
            } => {
                if operation_type.is_empty() {
                    return Err(DsmError::invalid_operation("Generic: empty operation_type"));
                }
                (operation_type.into_bytes(), data, message)
            }
        };

        let mut dsm_op = DsmOperation::Generic {
            operation_type: op_type,
            data,
            message,
            signature: vec![],
        };

        dsm_op = self.sign_operation_sphincs(dsm_op)?;

        // Route through relationship path with self-loop for generic ops
        let dev_id = self.get_current_state()?.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&dev_id, &dev_id);
        let (state, _) = self.execute_on_relationship(rel_key, dev_id, dsm_op, &[])?;
        Ok(state)
    }

    /// Register a CPTA policy for a custom token with the underlying
    /// `TokenPolicySystem`.  This is the authoritative step that makes the
    /// policy visible to `PolicyEnforcer` and binds `policy_commit =
    /// PolicyAnchor::from_policy(&policy_file)` for all subsequent balance
    /// ops on `token_id`.
    ///
    /// Must run before any balance-changing op references `token_id`.
    pub async fn register_token_policy(
        &self,
        token_id: &str,
        policy_file: dsm::types::policy_types::PolicyFile,
    ) -> Result<dsm::types::policy_types::PolicyAnchor, DsmError> {
        self.policy_system
            .register_token_policy(token_id, policy_file)
            .await
    }

    /// Register policy bytes while preserving an externally-authoritative
    /// policy anchor (for example, a storage-layer `DSM/policy` commitment).
    /// Read access to the policy system, for tests that need to ask the
    /// enforcer directly whether it can see a token's policy.
    pub fn policy_system_ref(&self) -> &dsm::core::token::policy::TokenPolicySystem {
        &self.policy_system
    }

    /// Install the durable-storage resolver the policy enforcer consults when
    /// its process-local index misses. See
    /// `AppRouterImpl::install_policy_resolver` for why a miss must not be
    /// read as absence.
    pub fn set_policy_resolver(&self, resolver: dsm::core::token::policy::PolicyResolver) {
        self.policy_system.set_policy_resolver(resolver);
    }

    pub async fn register_token_policy_with_anchor(
        &self,
        token_id: &str,
        policy_file: dsm::types::policy_types::PolicyFile,
        anchor: [u8; 32],
    ) -> Result<(), DsmError> {
        self.policy_system
            .register_token_policy_with_anchor(
                token_id,
                policy_file,
                dsm::types::policy_types::PolicyAnchor::from_bytes(anchor),
            )
            .await
    }

    fn canonical_token_id_str(token_id: &[u8]) -> Option<&str> {
        std::str::from_utf8(token_id)
            .ok()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// What the supply cap is evaluated against: the asset and the amount
    /// the operation names. The circulating supply is derived where the chain
    /// is reachable (`enforce_policy_for_operation`), never here.
    fn insert_supply_witness(
        context: &mut HashMap<String, Vec<u8>>,
        policy_commit: &[u8; 32],
        amount: u64,
    ) {
        use dsm::core::token::policy::policy_enforcement::witness_keys;
        context.insert(
            witness_keys::POLICY_COMMIT.to_string(),
            policy_commit.to_vec(),
        );
        context.insert(
            witness_keys::AMOUNT.to_string(),
            amount.to_le_bytes().to_vec(),
        );
    }

    fn build_token_policy_context(
        operation: &dsm::types::operations::Operation,
        state_hash: [u8; 32],
    ) -> Result<Option<(String, String, HashMap<String, Vec<u8>>)>, DsmError> {
        let mut context = HashMap::new();
        context.insert("state_hash".to_string(), state_hash.to_vec());

        match operation {
            DsmOperation::Transfer {
                token_id,
                amount,
                recipient,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("recipient".to_string(), recipient.clone());
                Ok(Some((
                    token_id.to_string(),
                    "transfer".to_string(),
                    context,
                )))
            }
            DsmOperation::Burn {
                token_id,
                amount,
                policy_commit,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                // Whether the holder may burn is the policy's burn flag,
                // expressed as its operation restriction (SoFi §54).
                Self::insert_supply_witness(&mut context, policy_commit, amount_u64);
                Ok(Some((token_id.to_string(), "burn".to_string(), context)))
            }

            // Creation is gated by the token's own policy: the supply cap and
            // the operation restriction; who may create is the creator the
            // policy names (SoFi Amendment S8), checked at the genesis release.
            DsmOperation::CreateToken {
                token_id,
                initial_supply,
                policy_commit,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = initial_supply.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                Self::insert_supply_witness(&mut context, policy_commit, amount_u64);
                Ok(Some((
                    token_id.to_string(),
                    "create_token".to_string(),
                    context,
                )))
            }
            DsmOperation::Lock {
                token_id,
                amount,
                purpose,
                owner,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
                Ok(Some((token_id.to_string(), "lock".to_string(), context)))
            }
            DsmOperation::Unlock {
                token_id,
                amount,
                purpose,
                owner,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = amount.value();
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                context.insert("owner".to_string(), owner.clone());
                Ok(Some((token_id.to_string(), "unlock".to_string(), context)))
            }
            DsmOperation::LockToken {
                token_id,
                amount,
                purpose,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = u64::try_from(*amount).map_err(|_| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: LockToken amount must be non-negative",
                    )
                })?;
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                Ok(Some((token_id.to_string(), "lock".to_string(), context)))
            }
            DsmOperation::UnlockToken {
                token_id,
                amount,
                purpose,
                ..
            } => {
                let token_id = Self::canonical_token_id_str(token_id).ok_or_else(|| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: malformed or empty token_id",
                    )
                })?;
                let amount_u64 = u64::try_from(*amount).map_err(|_| {
                    DsmError::invalid_operation(
                        "Policy enforcement rejected: UnlockToken amount must be non-negative",
                    )
                })?;
                context.insert("amount_u64".to_string(), amount_u64.to_le_bytes().to_vec());
                context.insert("amount".to_string(), amount_u64.to_string().into_bytes());
                context.insert("purpose".to_string(), purpose.clone());
                Ok(Some((token_id.to_string(), "unlock".to_string(), context)))
            }
            _ => Ok(None),
        }
    }

    /// Circulating supply of an asset, DERIVED from this device's canonical
    /// chain history — never a cached counter, which a restored snapshot could
    /// misreport. A token's whole supply is released at creation (SoFi §51),
    /// so:
    ///
    ///   circulating = Σ CreateToken.initial_supply − Σ Burn
    ///                 (for operations naming this policy_commit)
    ///
    /// Returns `None` when the history could not be read in full. That is not
    /// the same as zero: a figure from partial history is a figure about
    /// another chain.
    ///
    /// `None` propagates as an ABSENT witness, and the enforcer already fails
    /// closed on an absent circulating supply rather than guessing.
    fn derive_circulating_supply(&self, policy_commit: &[u8; 32]) -> Option<u64> {
        use dsm::types::operations::Operation as O;
        let device_id = self.device_info.device_id;
        let Ok(states) = crate::storage::client_db::get_bcr_chain_states(&device_id, false) else {
            log::warn!("[supply] chain history unreadable — refusing to derive a supply figure");
            return None;
        };
        let mut circulating: u128 = 0;
        for state in states {
            match &state.operation {
                O::CreateToken {
                    initial_supply,
                    policy_commit: pc,
                    ..
                } if pc == policy_commit => {
                    circulating = circulating.saturating_add(initial_supply.value() as u128);
                }
                O::Burn {
                    amount,
                    policy_commit: pc,
                    ..
                } if pc == policy_commit => {
                    circulating = circulating.saturating_sub(amount.value() as u128);
                }
                _ => {}
            }
        }
        Some(u64::try_from(circulating).unwrap_or(u64::MAX))
    }

    fn enforce_policy_for_operation(
        &self,
        operation: &dsm::types::operations::Operation,
        state_hash: [u8; 32],
    ) -> Result<(), DsmError> {
        let Some((token_id, op_type, mut context)) =
            Self::build_token_policy_context(operation, state_hash)?
        else {
            return Ok(());
        };

        // The supply cap is evaluated against canonical history, so the
        // derivation happens HERE (where the chain is reachable) rather than
        // in the pure context builder.
        {
            use dsm::core::token::policy::policy_enforcement::witness_keys;
            if let Some(pc) = context.get(witness_keys::POLICY_COMMIT).cloned() {
                if let Ok(commit) = <[u8; 32]>::try_from(pc.as_slice()) {
                    // Absent, not zero, when the history is incomplete — the
                    // enforcer refuses a capped creation it cannot evaluate.
                    if let Some(circulating) = self.derive_circulating_supply(&commit) {
                        context.insert(
                            witness_keys::CIRCULATING.to_string(),
                            circulating.to_le_bytes().to_vec(),
                        );
                    }
                }
            }
        }

        let result = if tokio::runtime::Handle::try_current().is_ok() {
            let policy_system = self.policy_system.clone();
            let token_id_for_thread = token_id.clone();
            let op_type_for_thread = op_type.clone();
            let context_for_thread = context.clone();
            let join_res = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        DsmError::internal(
                            format!("Failed to build runtime for policy enforcement: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                rt.block_on(async {
                    policy_system
                        .enforce_policy(
                            &token_id_for_thread,
                            &op_type_for_thread,
                            &context_for_thread,
                        )
                        .await
                })
            })
            .join();

            match join_res {
                Ok(res) => res?,
                Err(_) => {
                    return Err(DsmError::internal(
                        "Failed to join policy enforcement thread",
                        None::<std::convert::Infallible>,
                    ));
                }
            }
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    DsmError::internal(
                        format!("Failed to build runtime for policy enforcement: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;

            rt.block_on(async {
                self.policy_system
                    .enforce_policy(&token_id, &op_type, &context)
                    .await
            })?
        };

        if !result.allowed {
            return Err(DsmError::policy_violation(
                token_id,
                result.reason,
                None::<std::convert::Infallible>,
            ));
        }

        Ok(())
    }

    /// Execute a DSM operation on a specific relationship chain (§2.2, §4.2).
    ///
    /// Returns `(State, AdvanceOutcome)` where the `State` is a compatibility
    /// view derived from the AdvanceOutcome's DeviceState + chain state. The
    /// `State` will be removed once all downstream readers migrate to
    /// `DeviceState`.
    /// Ordinary advance (no fused-anchor-state leaf). Thin wrapper over
    /// [`Self::execute_on_relationship_with_anchor_leaf`] with `anchor_leaf = None`, so the many
    /// non-bearer callers stay unchanged.
    pub fn execute_on_relationship(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_with_anchor_leaf(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            None, // anchor_leaf — ordinary online transition
            None, // offline_spend — ordinary online transition, no allocation draw
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_on_relationship_with_anchor_leaf(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            anchor_leaf,
            offline_spend,
            None,
            None,
            None,
        )
    }

    /// A staged advance with an economic admission riding the SAME advance
    /// (see [`AdmissionPlan`]).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_on_relationship_staged_with_admission<A>(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        build_artifacts: impl FnOnce(&dsm::types::device_state::AdvanceOutcome) -> Result<A, DsmError>,
        write_extra: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
        admission: Option<AdmissionPlan<'_>>,
    ) -> Result<StagedAdvance<A>, DsmError> {
        self.execute_on_relationship_staged_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            build_artifacts,
            write_extra,
            admission,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_on_relationship_staged_inner<A>(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        build_artifacts: impl FnOnce(&dsm::types::device_state::AdvanceOutcome) -> Result<A, DsmError>,
        write_extra: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
        admission: Option<AdmissionPlan<'_>>,
    ) -> Result<StagedAdvance<A>, DsmError> {
        // Artifacts are built once in `pre_write` (outside the transaction, so
        // signing may read the DB) and shared with the in-tx writer through a
        // cell. The in-tx closure NEVER rebuilds them — retries and the durable
        // record must carry byte-identical bytes.
        let built: std::cell::RefCell<Option<A>> = std::cell::RefCell::new(None);
        let builder: std::cell::RefCell<Option<_>> = std::cell::RefCell::new(Some(build_artifacts));

        let pre = |outcome: &dsm::types::device_state::AdvanceOutcome| -> Result<(), DsmError> {
            let f = builder.borrow_mut().take().ok_or_else(|| {
                DsmError::internal(
                    "staged advance: artifact builder already consumed",
                    None::<std::convert::Infallible>,
                )
            })?;
            *built.borrow_mut() = Some(f(outcome)?);
            Ok(())
        };

        let write = |tx: &rusqlite::Transaction<'_>,
                     outcome: &dsm::types::device_state::AdvanceOutcome|
         -> Result<(), DsmError> {
            let guard = built.borrow();
            let artifacts = guard.as_ref().ok_or_else(|| {
                DsmError::internal(
                    "staged advance: artifacts missing at write time",
                    None::<std::convert::Infallible>,
                )
            })?;
            write_extra(tx, outcome, artifacts)
        };

        let (state, outcome) = self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            None,
            None,
            Some(&write),
            Some(&pre),
            admission,
        )?;

        let artifacts = built.borrow_mut().take().ok_or_else(|| {
            DsmError::internal(
                "staged advance committed without artifacts",
                None::<std::convert::Infallible>,
            )
        })?;
        Ok(StagedAdvance {
            state,
            outcome,
            artifacts,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_on_relationship_guarded(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
        admission: Option<AdmissionPlan<'_>>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        self.execute_on_relationship_inner(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            None,
            None,
            in_tx_extra,
            None,
            admission,
        )
    }

    /// Re-project every balance the just-committed `head` carries into
    /// `balance_projections` — the rows `balance.list` renders from.
    ///
    /// The projection IS the head's cache (`client_db::tokens`), so it must be
    /// brought level with the head at the commit chokepoint, not at the next
    /// startup sweep. Operations that carry their debits inside the operation
    /// rather than in a caller-supplied delta list are exactly why: a funded
    /// vault creation once left the owner's wallet showing its pre-vault
    /// balances on hardware (2026-09-13).
    /// Best-effort by design: the head is already durable when this runs, so a
    /// failure here is a stale cache the startup reconcile repairs, never a
    /// lost transition.
    fn reproject_committed_head(head: &dsm::types::device_state::DeviceState) {
        match client_db::reconcile_projections_with_head(head) {
            Ok((0, _)) => {}
            Ok((rebuilt, checked)) => log::info!(
                "[projection] {rebuilt}/{checked} balance row(s) re-projected from the committed head"
            ),
            Err(e) => log::warn!(
                "[projection] re-projection from the committed head failed (cache stale until the startup sweep): {e}"
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_on_relationship_inner(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
        in_tx_extra: Option<
            &dyn Fn(
                &rusqlite::Transaction<'_>,
                &dsm::types::device_state::AdvanceOutcome,
            ) -> Result<(), DsmError>,
        >,
        // §16.6 staged advance: runs AFTER the pure prepare and BEFORE the
        // durable write opens its transaction. This is the only window in
        // which a caller may do work that itself touches the database (e.g.
        // per-step EK signing, which reads cert heads) — inside the write
        // transaction the global connection mutex is held and re-entry
        // deadlocks. An Err here aborts before anything is persisted.
        pre_write: Option<
            &dyn Fn(&dsm::types::device_state::AdvanceOutcome) -> Result<(), DsmError>,
        >,
        // The economic admission riding this advance, if the operation is an
        // admitted economic write. See [`AdmissionPlan`].
        admission: Option<AdmissionPlan<'_>>,
    ) -> Result<(State, dsm::types::device_state::AdvanceOutcome), DsmError> {
        // Phase 0 fail-closed recovery gate (spec condition R3): block
        // owner-initiated value egress while identity recovery is in progress.
        // `is_value_egress` is an exhaustive classifier (dsm core), so value
        // ingress (Receive) and identity/recovery operations still advance,
        // and any new Operation variant must be consciously classified. This is
        // the canonical state-advance chokepoint, so it covers bilateral
        // transfers, token ops, and DLV ops in one place.
        // Recovery egress gate (spec R3) + capsule currency (spec §5.1). Classify
        // before `operation` is moved into the advance.
        let is_egress = operation.is_value_egress();
        let frontier_changed = !matches!(
            operation,
            dsm::types::operations::Operation::Noop | dsm::types::operations::Operation::Genesis
        );

        // R2′ optimistic self-heal (BEFORE the lock, only when the capsule is
        // stale): re-seal so a current device is not needlessly blocked, while
        // keeping the heavy capsule rebuild off the hot path when already current.
        if is_egress && crate::storage::client_db::recovery::is_capsule_dirty() {
            crate::sdk::recovery_sdk::RecoverySDK::maybe_refresh_nfc_capsule();
        }

        let mut sm = self.state_machine.lock();

        // Authoritative fail-closed egress gate UNDER the state-machine lock, so
        // the decision is atomic with the commit + capsule-currency bump below.
        // This closes the check-before-lock TOCTOU where two concurrent egress
        // ops could both pass before either marked the capsule dirty.
        if is_egress {
            if let Some(reason) = crate::storage::client_db::recovery::value_egress_block_reason() {
                return Err(DsmError::invalid_operation(reason));
            }
            // P5 per-asset bearer gate (spec §0.4): in ADDITION to the identity-level gate
            // above, a recovered bearer asset stays LockedRecovery until its OWN verified
            // frontier reconciles — this persists AFTER recovery activation and is keyed by
            // the operation's egress asset. Fail-closed (unreadable/locked → refuse).
            if let Some(reason) =
                crate::storage::client_db::recovery::asset_egress_block_reason(&operation)
            {
                return Err(DsmError::invalid_operation(reason));
            }
        }

        // Enforce token policy constraints on the operation that will advance
        // state. This closes the previous gap where registration existed but
        // execution path skipped policy checks.
        let current_state_hash = sm
            .device_head()
            .map(|ds| ds.root())
            .ok_or_else(|| DsmError::state_machine("no device head to execute an operation on"))?;
        self.enforce_policy_for_operation(&operation, current_state_hash)?;
        // ── Admission serialization, UNDER the state-machine lock ──────────
        // A new admission atomically refuses an existing pending one and
        // CAS-checks the admitted predecessor it extends. A route-level
        // "resume first" cannot be the guard: two relationships can race
        // before either takes this lock; THIS is the serialization boundary.
        let admission = match admission {
            Some(plan) => {
                if sm
                    .device_head()
                    .and_then(|h| h.pending_economic_admission().cloned())
                    .is_some()
                {
                    return Err(DsmError::invalid_operation(
                        "advance: an economic admission is already pending — finish or resume \
                         it before starting another; positions are write-once and never \
                         overwritten",
                    ));
                }
                let admitted = crate::storage::client_db::economic_lineage::get_admitted()
                    .map_err(|e| {
                        DsmError::storage(
                            format!("admission predecessor read: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
                let (expected_position, expected_root) = match admitted {
                    Some(a) => {
                        // Same fence, on the advance that stages the plan.
                        dsm::sofi::lineage::descendant_fence(
                            a.predecessor_claim(),
                            &plan.prepared.pre_economic_root,
                        )
                        .map_err(|e| DsmError::invalid_operation(format!("advance: {e}")))?;
                        let v = dsm::economic::lineage::ValidatedEconomicRoot::
                            rehydrate_from_admitted_store(a)
                            .map_err(|e| DsmError::invalid_operation(format!("advance: {e}")))?;
                        (v.economic_position() + 1, v.economic_root())
                    }
                    None => (1, dsm::economic::tree::empty_economic_root()),
                };
                if plan.prepared.economic_position != expected_position
                    || plan.prepared.pre_economic_root != expected_root
                {
                    return Err(DsmError::invalid_operation(format!(
                        "advance: admission does not extend the admitted coordinate (expected \
                         position {expected_position}) — rebuild from the current admitted \
                         state rather than a stale snapshot",
                    )));
                }
                Some(plan)
            }
            None => None,
        };
        if let Some(plan) = &admission {
            sm.attach_pending_economic_admission(Some(plan.prepared.clone()));
        }
        // From here to commit, every error path must roll the attach off —
        // one restore point via the closure below, not scattered clears.
        let admission_result = (|| -> Result<
            (
                dsm::types::device_state::AdvanceOutcome,
                Option<dsm::economic::admission::PendingEconomicAdmission>,
                Vec<(String, Vec<u8>, &'static str)>,
                [u8; 32],
            ),
            DsmError,
        > {

        // Phase 4.1 fail-closed pattern (§4.3 acceptance, §6.1 single-writer):
        //   1. PREPARE — derive the AdvanceOutcome (pure; no head mutation).
        //   2. WRITE  — persist `bcr_chain_states` + `bcr_device_heads` in one
        //      SQLite transaction. If this fails, the in-memory head is
        //      unchanged and the operation is observable as never-happened.
        //   3. COMMIT — install the new head only after persistence succeeded.
        // The `sm` lock is held across all three steps, so the prepare/write/
        // commit sequence is atomic with respect to other advances.
        let outcome = sm.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            anchor_leaf, // Some(..) commits the fused-anchor-state leaf atomically (offline-bearer)
            offline_spend, // Some(..) draws the value from the offline-cash allocation instead of online balance
        )?;
        // The sender's signed A-side pair is deliberately NOT compared against
        // this device's own lineage here — see the doc comment on
        // `execute_on_relationship_guarded` for why such a comparison can never
        // hold between two honest devices. The local advance is authoritative
        // for the local lineage; A-side authority is enforced upstream in
        // `apply_incoming_transfer_full_state`.
        // The accepted-state index is bumped ATOMICALLY inside this transaction
        // (spec §5.1) — a frontier-changing transition can never persist without
        // the capsule being marked dirty. `in_tx_extra` (nonce consumption +
        // canonical apply record on the incoming-transfer path) runs in the SAME
        // transaction (§16.6 full-state consumption).
        // Staged artifact build (signing, envelope construction) — outside the
        // write transaction, so DB reads here cannot deadlock. Failing now
        // means nothing was persisted and nothing became deliverable.
        if let Some(pre) = pre_write {
            pre(&outcome)?;
        }
            match admission {
                Some(plan) => {
                    let (coords, artifacts) = (plan.build)(&outcome)?;
                    let accepted = plan
                        .prepared
                        .into_locally_accepted(coords)
                        .map_err(|e| DsmError::invalid_operation(e.to_string()))?;
                    let outcome = dsm::types::device_state::AdvanceOutcome {
                        new_device_state: outcome
                            .new_device_state
                            .with_pending_economic_admission(Some(accepted.clone())),
                        ..outcome
                    };
                    *plan.accepted_out = Some(accepted.clone());
                    Ok((outcome, Some(accepted), artifacts, plan.storage_set_id))
                }
                None => Ok((outcome, None, Vec::new(), [0u8; 32])),
            }
        })();
        let (outcome, accepted, artifacts, set_id) = match admission_result {
            Ok(v) => v,
            Err(e) => {
                // Restore the exact prior in-memory admission (None — the
                // pre-attach check proved nothing was pending).
                sm.attach_pending_economic_admission(None);
                return Err(e);
            }
        };
        let commit_result = match &accepted {
            // The caller's in-tx writer (send prerequisites / token registry /
            // canonical apply) COMPOSES with the admission commit via `also`.
            Some(accepted) => Self::commit_advance_with_pending_admission_and_artifacts(
                &outcome,
                frontier_changed,
                accepted,
                &artifacts,
                &set_id,
                in_tx_extra,
            ),
            None => {
                Self::dual_write_advance_outcome_with_extra(&outcome, frontier_changed, in_tx_extra)
            }
        };
        if let Err(e) = commit_result {
            if accepted.is_some() {
                sm.attach_pending_economic_admission(None);
            }
            return Err(e);
        }
        sm.commit_advance(&outcome);
        Self::reproject_committed_head(&outcome.new_device_state);

        // Build a compatibility State view from the outcome for callers that
        // still read State fields. This is a derived view, not the source of
        // truth — DeviceState IS the truth.
        let compat_state = {
            let cs = &outcome.new_chain_state;
            let mut s = State {
                hash: cs.compute_chain_tip(),
                prev_state_hash: cs.embedded_parent,
                entropy: cs.entropy.clone(),
                operation: cs.operation.clone(),
                device_info: dsm::types::state_types::DeviceInfo::new(
                    outcome.new_device_state.devid(),
                    outcome.new_device_state.public_key().to_vec(),
                ),
                ..State::default()
            };
            // Sync balances from DeviceState → legacy HashMap<String, Balance>
            // through the SAME shared helper the state machine's projection
            // uses, so the two views cannot drift. An unnameable balance is
            // omitted rather than surfaced under a `{prefix}|?` placeholder.
            let public_key = outcome.new_device_state.public_key();
            for (pc, val) in outcome.new_device_state.balances_snapshot() {
                let Some(key) = dsm::core::token::canonical_balance_key_for_commit(pc, public_key)
                else {
                    continue;
                };
                s.token_balances.insert(
                    key,
                    dsm::types::token_types::Balance::from_state(*val, s.hash),
                );
            }
            s
        };

        Ok((compat_state, outcome))
    }

    /// Establish the relationship with `counterparty_devid` on this device's
    /// head: its leaf enters the tree at `h_0` (§26), a root advance that
    /// moves no value, persisted before it is installed. Every step on the
    /// relationship then extends a leaf the device committed. A relationship
    /// already established stays as it is.
    pub fn establish_relationship(&self, counterparty_devid: [u8; 32]) -> Result<(), DsmError> {
        let mut sm = self.state_machine.lock();
        let next = {
            let head = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "establish_relationship: DeviceState not initialized (genesis first)",
                )
            })?;
            let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
                &head.devid(),
                &counterparty_devid,
            );
            if head.chain_tip(&rel_key).is_some() {
                return Ok(());
            }
            head.establish_relationship(counterparty_devid)?
        };
        crate::storage::client_db::update_bcr_device_head(&next).map_err(|e| {
            DsmError::storage(
                format!("establish_relationship: persist device head failed: {e}"),
                None::<std::io::Error>,
            )
        })?;
        sm.set_device_head(next);
        Ok(())
    }

    /// **Load** `amount` of `asset` from the online balance into this device's offline-cash allocation,
    /// bound to the enrolled anchor bundle `B`. An online, conserved regime shift: online
    /// `available` drops and the device-bound allocation rises by the same amount (device root advances).
    /// Fail-closed persistence: the new device head is durably written BEFORE it is installed, so a
    /// persist failure leaves the in-memory head on the prior state (the load is never-happened).
    pub fn load_offline_cash(
        &self,
        anchor_bundle_b: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    ) -> Result<dsm::types::device_state::OfflineAllocationOutcome, DsmError> {
        let mut sm = self.state_machine.lock();
        let outcome = {
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "load_offline_cash: DeviceState not initialized (genesis first)",
                )
            })?;
            ds.load_offline_cash(&anchor_bundle_b, &asset, amount)?
        };
        crate::storage::client_db::update_bcr_device_head(&outcome.new_device_state).map_err(
            |e| {
                DsmError::storage(
                    format!("load_offline_cash: persist device head failed: {e}"),
                    None::<std::io::Error>,
                )
            },
        )?;
        sm.set_device_head(outcome.new_device_state.clone());
        Self::reproject_committed_head(&outcome.new_device_state);
        Ok(outcome)
    }

    /// **Unload** `amount` from this device's offline-cash allocation back to the online balance
    /// (reconcile): the allocation drops and online `available` rises by the same amount. Same
    /// fail-closed persist-before-install discipline as [`Self::load_offline_cash`].
    pub fn unload_offline_cash(
        &self,
        anchor_bundle_b: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    ) -> Result<dsm::types::device_state::OfflineAllocationOutcome, DsmError> {
        let mut sm = self.state_machine.lock();
        let outcome = {
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "unload_offline_cash: DeviceState not initialized (genesis first)",
                )
            })?;
            ds.unload_offline_cash(&anchor_bundle_b, &asset, amount)?
        };
        crate::storage::client_db::update_bcr_device_head(&outcome.new_device_state).map_err(
            |e| {
                DsmError::storage(
                    format!("unload_offline_cash: persist device head failed: {e}"),
                    None::<std::io::Error>,
                )
            },
        )?;
        sm.set_device_head(outcome.new_device_state.clone());
        Self::reproject_committed_head(&outcome.new_device_state);
        Ok(outcome)
    }

    /// Current offline-cash allocation balance for `asset` under the enrolled anchor bundle `B`.
    pub fn offline_cash_balance(&self, anchor_bundle_b: [u8; 32], asset: [u8; 32]) -> u64 {
        let sm = self.state_machine.lock();
        match sm.device_head() {
            Some(ds) => {
                let key = dsm::types::offline_allocation_leaf::offline_allocation_key(
                    &ds.genesis_digest(),
                    &ds.devid(),
                    &anchor_bundle_b,
                    &asset,
                );
                ds.offline_allocation(&key)
            }
            None => 0,
        }
    }

    /// Get the canonical DeviceState head (§2.2 SMT root).
    pub fn device_head(&self) -> Option<dsm::types::device_state::DeviceState> {
        self.state_machine.lock().device_head().cloned()
    }

    /// Prepare-only view of the canonical [`AdvanceOutcome`] for an advance
    /// that hasn't committed yet.
    ///
    /// Used by the BLE sender in `send_bilateral_confirm` to build the
    /// stitched receipt (§4.2) with the real post-advance SMT roots + proofs
    /// *before* the sender advances canonical state — the canonical commit
    /// happens later in `mark_sender_committed_with_post_state_hash` via
    /// `execute_on_relationship_for_bilateral`, which re-runs prepare and
    /// then commits. Identical inputs → identical outcome, so the simulated
    /// receipt is byte-exact with the eventual canonical advance.
    #[allow(clippy::too_many_arguments)]
    pub fn simulate_advance_for_confirm(
        &self,
        rel_key: [u8; 32],
        counterparty_devid: [u8; 32],
        operation: dsm::types::operations::Operation,
        deltas: &[dsm::types::device_state::BalanceDelta],
        anchor_leaf: Option<dsm::types::device_state::AnchorLeafUpdate>,
        offline_spend: Option<dsm::types::device_state::OfflineSpend>,
    ) -> Result<dsm::types::device_state::AdvanceOutcome, DsmError> {
        let sm = self.state_machine.lock();
        sm.prepare_advance_relationship(
            rel_key,
            counterparty_devid,
            operation,
            deltas,
            anchor_leaf,
            offline_spend,
        )
    }

    /// Read device-level balance for a token by its 32-byte CPTA policy_commit.
    /// This reads from DeviceState directly (no string-key projection).
    pub fn get_device_balance(&self, policy_commit: &[u8; 32]) -> u64 {
        self.state_machine
            .lock()
            .device_head()
            .map(|ds| ds.balance(policy_commit))
            .unwrap_or(0)
    }

    /// Read the device's SMT root (canonical head identity per §2.2).
    pub fn device_smt_root(&self) -> Option<[u8; 32]> {
        self.state_machine.lock().device_head().map(|ds| ds.root())
    }

    /* -------------------- Proto-only, non-removed paths ---------------- */

    /// Install an already-computed canonical Genesis v2 [`GenesisState`] as the device's current
    /// state and seed the device-head cache. The caller (the `wallet.createGenesisV2` route) must
    /// construct this `CoreSDK` with the v2 `DeviceInfo` (DevID + AK public key) so the installed
    /// state + device head carry the canonical identity. Returns the installed genesis hash `G`.
    ///
    /// The GenesisState came from `create_genesis_v3_self_attested` over the
    /// unlocked wallet seed.
    pub fn install_v2_genesis(
        &self,
        genesis_state: &dsm::core::identity::genesis::GenesisState,
    ) -> Result<[u8; 32], DsmError> {
        let genesis_state_hash = {
            let mut sm = self.state_machine.lock();
            let mut s = State::new_genesis(genesis_state.genesis_nonce, self.device_info.clone());
            s.hash = genesis_state.hash;
            let snapshot = s.clone();
            sm.set_state(s);
            snapshot.hash
        };
        self.write_genesis_device_head(genesis_state_hash)?;
        Ok(genesis_state.hash)
    }
}

/// Producer-side offline-bearer artifacts from driving the device fused-anchor appliance for one
/// transfer: the wire release + the anchor-state leaf update the DSM advance must apply + the
/// appliance frontier lineage the receiver pins/adopts + the pin material to admit the anchor.
#[derive(Clone, Debug)]
pub struct OfflineBearerArtifacts {
    /// prost-encoded `dsm.anchor.OfflineRelease` (goes on `BilateralConfirmRequest.offline_release`).
    pub offline_release: Vec<u8>,
    /// The anchor-state leaf update the DSM advance applied (`Some(...)` on the canonical commit).
    pub anchor_leaf: dsm::types::device_state::AnchorLeafUpdate,
    /// The appliance frontier `h_i` this transfer consumes (the receiver's accepted frontier).
    pub appliance_prev_root: [u8; 32],
    /// The successor frontier `h_{i+1}` the receiver adopts after acceptance.
    pub appliance_next_root: [u8; 32],
    /// The pin material (B, anchor_id, H0, pk_host, pk_chip) the receiver admits for this anchor.
    pub pin: crate::anchor::AnchorPin,
}

/// A STAGED offline-bearer transition (v2 producer phase 1): the transition `Δ` and its successor
/// anchor-state leaf are fully determined from the appliance's active state, but NOTHING has been
/// signed or committed — the appliance is untouched. The DSM layer runs its advance simulation over
/// `anchor_leaf` to materialize the real device SMT roots `R_i`/`R_{i+1}` and the inclusion proofs
/// `Π_i`/`Π_{i+1}`, then feeds those into [`CoreSDK::release_offline_bearer`] so the release is
/// born with the real roots in its signed transcript (no placeholder stamping, no re-stamp).
#[derive(Clone)]
pub struct StagedBearerTransition {
    /// The fully-formed transition `Δ` (owned; `as_transition()` for the appliance call).
    pub transition: anchor_core::root_advance::OwnedTransition,
    /// The successor anchor-state leaf `L_{i+1} = H("DSM/anchor-state/v2" ‖ B ‖ h_{i+1} ‖ u_{i+1})`
    /// at the stable per-device key — what the DSM advance commits atomically with the transfer.
    pub anchor_leaf: dsm::types::device_state::AnchorLeafUpdate,
    /// The appliance frontier `h_i` this transfer consumes.
    pub appliance_prev_root: [u8; 32],
    /// The successor frontier `h_{i+1} = H(h_i ‖ D)`.
    pub appliance_next_root: [u8; 32],
    /// The pin material the receiver admits.
    pub pin: crate::anchor::AnchorPin,
}

/// Read-only snapshot of the sender's anchor appliance for the `anchor.status` diagnostics route
/// (signal (c)). Purely observational: NO staging, NO counter move, NO device-state mutation.
/// A disconnected snapshot (no appliance attachable) reports `connected = false` with zeroed
/// identity — a diagnostics read must never fail the route.
#[derive(Clone, Debug, Default)]
pub struct AnchorStatusSnapshot {
    pub connected: bool,
    pub anchor_id: [u8; 32],
    pub pk_chip: Vec<u8>,
    pub partition_pk: Vec<u8>,
    pub anchor_counter: u64,
    pub frontier_root: [u8; 32],
    pub enrolled_counter: u64,
    pub bundle: [u8; 32],
    pub status: String,
}

impl CoreSDK {
    /// Read-only anchor appliance snapshot for the `anchor.status` diagnostics route (signal (c)).
    /// Attaches (and caches) the appliance via the installed factory if not already attached, then
    /// reads `pin()`/`status()`. Unlike [`stage_offline_bearer_transition`](Self::stage_offline_bearer_transition)
    /// this performs NO anchor-state leaf reconciliation and NO mutation. When no appliance can
    /// attach (no device / fail-closed) it returns a disconnected snapshot rather than an error, so
    /// the diagnostics panel can render "no anchor connected" instead of failing.
    #[must_use]
    pub fn anchor_appliance_status(&self) -> AnchorStatusSnapshot {
        let dev = self.device_info.device_id;
        let seed = |tag: &str| blake3_cat(&[tag.as_bytes(), &dev]);

        let mut guard = self.anchor_appliance.lock();
        if guard.is_none() {
            let attached: Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> =
                match crate::bridge::anchor_appliance_factory() {
                    Some(factory) => factory(),
                    None => hardware_appliance_or_fail(&seed, dev),
                };
            match attached {
                Ok(a) => *guard = Some(a),
                Err(e) => {
                    log::info!("[anchor.status] no anchor appliance attached: {e}");
                    return AnchorStatusSnapshot {
                        status: "no anchor appliance connected".into(),
                        ..Default::default()
                    };
                }
            }
        }

        let app = match guard.as_mut() {
            Some(a) => a,
            None => {
                return AnchorStatusSnapshot {
                    status: "no anchor appliance connected".into(),
                    ..Default::default()
                }
            }
        };

        let pin = app.pin();
        match app.status() {
            Ok(s) => AnchorStatusSnapshot {
                connected: true,
                anchor_id: pin.anchor_id,
                pk_chip: pin.pk_chip,
                partition_pk: pin.partition_pk,
                anchor_counter: s.anchor_counter,
                frontier_root: s.root,
                enrolled_counter: pin.enrolled_counter,
                bundle: pin.bundle,
                status: format!("anchor connected (counter u={})", s.anchor_counter),
            },
            Err(e) => {
                log::warn!("[anchor.status] appliance attached but OP_STATUS failed: {e}");
                AnchorStatusSnapshot {
                    connected: false,
                    anchor_id: pin.anchor_id,
                    pk_chip: pin.pk_chip,
                    partition_pk: pin.partition_pk,
                    enrolled_counter: pin.enrolled_counter,
                    bundle: pin.bundle,
                    status: "anchor present but status read failed".into(),
                    ..Default::default()
                }
            }
        }
    }

    /// v2 producer phase 1 (Software-Authority / Hardware-Identity): lazily attach the appliance
    /// (reconciling the DeviceState anchor-state leaf to the chip's CURRENT active state), then
    /// deterministically stage the next transition — compute `D`, the successor frontier
    /// `h_{i+1} = H(h_i ‖ D)`, and the successor anchor-state leaf. NO appliance mutation, NO
    /// signatures, NO counter move: the caller first simulates the DSM advance over `anchor_leaf`
    /// to obtain the real device roots `R_i`/`R_{i+1}`, then calls
    /// [`release_offline_bearer`](Self::release_offline_bearer).
    #[allow(clippy::too_many_arguments)]
    pub fn stage_offline_bearer_transition(
        &self,
        relationship_id: [u8; 32],
        recipient_device_id: [u8; 32],
        object_id: [u8; 32],
        payload_hash: [u8; 32],
        authority_policy_hash: [u8; 32],
        action_type: u32,
        action_fields: Vec<u8>,
        receiver_challenge: [u8; 32],
    ) -> Result<StagedBearerTransition, DsmError> {
        use anchor_core::root_advance::{anchor_root_advance, anchor_state_leaf, transition_digest};
        use dsm::core::bilateral_transaction_manager::anchor_state_leaf_key;

        let dev = self.device_info.device_id;
        let seed = |tag: &str| blake3_cat(&[tag.as_bytes(), &dev]);

        let mut guard = self.anchor_appliance.lock();
        if guard.is_none() {
            // Sender-side appliance: the physical RP2350/TROPIC01 via the installed factory. On device
            // an absent factory FAILS CLOSED ("offline = chips"); the in-process mock is the test-only
            // producer. The factory is called once and cached (stateful appliance). Construction only —
            // the anchor-state-leaf reconcile is done PER stage call below (see the comment there), not
            // once at birth: the chip can advance between attach and a later transfer.
            let a: Box<dyn crate::anchor::AnchorAppliance + Send> =
                match crate::bridge::anchor_appliance_factory() {
                    Some(factory) => factory()?,
                    None => hardware_appliance_or_fail(&seed, dev)?,
                };
            *guard = Some(a);
        }

        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not birthed")
        })?;
        let pin = app.pin();

        // §26 recovery gate: NEVER stage a fresh bearer over an unsettled chip. OBSERVE recover() and
        // apply the existing host policy (`recovery_action`); anything other than Ready fails closed to
        // online recovery. This does NOT cancel or erase here — an orphaned/committed record is left for
        // the dedicated `resolve_prepared_on_reattach` seam (a Committed release must be re-emitted,
        // never erased, §26). Conservative `prepared_owned_by_session = true`: never auto-cancel in stage.
        let action = crate::anchor::recovery_action(app.recover()?, true);
        if action != crate::anchor::RecoveryAction::Ready {
            return Err(DsmError::invalid_operation(format!(
                "offline-bearer stage: appliance not Ready ({action:?}) — resolve/re-emit via recovery \
                 before staging a new transfer (fail closed to online)"
            )));
        }

        // Active state: the frontier this transfer consumes + the current counter floor.
        let before = app.status()?;
        let appliance_prev_root = before.root;

        // PER-CALL reconcile (the fix for receiver `PrevStateUncommitted`): keep the device-head
        // anchor-state leaf byte-equal to the value the certificate will claim —
        // `anchor_state_leaf(B, before.root, before.anchor_counter)` at `anchor_state_leaf_key(B)`.
        // `before` is a LIVE chip status read that drives cert.prev_frontier/anchor_counter, so the
        // leaf the sim's Π_i proves must be reconciled to the SAME live state. This previously ran only
        // once at first attach (`if guard.is_none()`), so any chip move afterward that was not mirrored
        // into a persisted device head — a committed-but-failed attempt (COMMIT burns the counter +
        // FINALIZE advances the frontier), a reflash-birth, or an online-only advance that rebuilt the
        // head — left the stored leaf stale, Π_i proved a stale value, and the receiver rejected.
        // `with_anchor_state_leaf` touches only `anchor_state_leaf_key(B)`; balances / relationship tips
        // / offline_allocations are untouched (allocation conservation is unaffected).
        {
            let value = anchor_state_leaf(&pin.bundle, &before.root, before.anchor_counter);
            let key = anchor_state_leaf_key(&pin.bundle);
            let mut sm = self.state_machine.lock();
            let ds = sm.device_head().ok_or_else(|| {
                DsmError::state_machine(
                    "offline-bearer: DeviceState not initialized (genesis first)",
                )
            })?;
            let stored = ds.extra_leaves_snapshot().get(&key).copied();
            // No-op guard: an idempotent same-value write preserves the SMT root, but the explicit
            // skip makes the determinism guarantee obvious and avoids a needless head replacement.
            if stored != Some(value) {
                log::info!(
                    "[offline-bearer] anchor-state leaf reconciled to live chip: u(anchor_counter)={} (stored={}, chip is source of truth)",
                    before.anchor_counter,
                    stored.map(|v| crate::util::text_id::encode_base32_crockford(&v[..6])).unwrap_or_else(|| "absent".into()),
                );
                let bootstrapped = ds.with_anchor_state_leaf(&key, &value)?;
                sm.set_device_head(bootstrapped);
            }
        }

        // Stage Δ°: the digest excludes `next_root`, so D is computable first and the successor
        // frontier is derived, never invented.
        let mut owned = anchor_core::root_advance::OwnedTransition {
            relationship_id,
            object_id,
            sender_device_id: dev,
            recipient_device_id,
            prev_root: appliance_prev_root,
            next_root: [0u8; 32],
            anchor_counter: before.anchor_counter,
            next_anchor_counter: before.anchor_counter + 1,
            action_type,
            action_fields,
            payload_hash,
            old_leaf_proof: Vec::new(),
            new_leaf_proof: Vec::new(),
            authority_policy_hash,
        };
        let d = transition_digest(&owned.as_transition(), &receiver_challenge);
        let appliance_next_root = anchor_root_advance(&appliance_prev_root, &d);
        owned.next_root = appliance_next_root;

        // Successor anchor-state leaf: what the device SMT holds AFTER this transfer commits.
        let anchor_leaf = dsm::types::device_state::AnchorLeafUpdate {
            key: anchor_state_leaf_key(&pin.bundle),
            new_value: anchor_state_leaf(
                &pin.bundle,
                &appliance_next_root,
                before.anchor_counter + 1,
            ),
        };

        Ok(StagedBearerTransition {
            transition: owned,
            anchor_leaf,
            appliance_prev_root,
            appliance_next_root,
            pin,
        })
    }

    /// v2 producer phase 2: drive the appliance PREPARE(t, r_R, R_i, R_{i+1}) → COMMIT → EMIT →
    /// FINALIZE for a staged transition, with the REAL device SMT roots the caller's advance
    /// simulation produced. The release is emitted with those roots inside the signed transcript
    /// (σ^DSM binding is the caller's; σ^chip + σ^host are produced here) — there is no placeholder
    /// stamping and no post-hoc re-stamp. The anchor-state inclusion proofs `Π_i`/`Π_{i+1}` (from
    /// the same simulation) are attached to the release package here — they sit OUTSIDE all three
    /// signatures (the receiver verifies them independently against `R_i`/`R_{i+1}`), so attaching
    /// them mutates no signed bytes. Fails closed if the appliance's post-finalize frontier
    /// diverges from the staged successor.
    pub fn release_offline_bearer(
        &self,
        staged: &StagedBearerTransition,
        receiver_challenge: [u8; 32],
        sender_device_root_before: [u8; 32],
        sender_device_root_after: [u8; 32],
        anchor_smt_proof_before: Vec<u8>,
        anchor_smt_proof_after: Vec<u8>,
    ) -> Result<OfflineBearerArtifacts, DsmError> {
        use prost::Message;

        let mut guard = self.anchor_appliance.lock();
        let app = guard.as_mut().ok_or_else(|| {
            DsmError::state_machine("offline-bearer: anchor appliance not birthed")
        })?;

        app.prepare(
            &staged.transition.as_transition(),
            &receiver_challenge,
            &sender_device_root_before,
            &sender_device_root_after,
        )?;
        app.commit()?;
        let emitted = app.emit()?;
        let new_frontier = app.finalize()?;
        if new_frontier != staged.appliance_next_root {
            return Err(DsmError::state_machine(
                "offline-bearer: post-finalize frontier diverged from the staged successor (fail closed)",
            ));
        }

        // Attach Π_i/Π_{i+1} to the package (unsigned carrier fields; see method doc).
        let mut rel =
            anchor_core::proto::pb::OfflineRelease::decode(&emitted[..]).map_err(|e| {
                DsmError::serialization_error(
                    "OfflineRelease",
                    "protobuf",
                    Some(e.to_string()),
                    Some(e),
                )
            })?;
        rel.anchor_smt_proof_before = anchor_smt_proof_before;
        rel.anchor_smt_proof_after = anchor_smt_proof_after;

        Ok(OfflineBearerArtifacts {
            offline_release: rel.encode_to_vec(),
            anchor_leaf: staged.anchor_leaf.clone(),
            appliance_prev_root: staged.appliance_prev_root,
            appliance_next_root: staged.appliance_next_root,
            pin: staged.pin.clone(),
        })
    }

    /// Cleanup: drive an ABANDONED prepared release back to `Ready` (e.g. the confirm build failed
    /// between PREPARE and COMMIT). `cancel()` discards the uncommitted record — no counter ever
    /// moved, so nothing is lost. Idempotent and best-effort: a no-op when there is no appliance or
    /// it is not `Prepared`.
    pub fn cancel_offline_bearer_release(&self) -> Result<(), DsmError> {
        let mut guard = self.anchor_appliance.lock();
        if let Some(app) = guard.as_mut() {
            match app.cancel() {
                Ok(()) => log::info!(
                    "[offline-bearer] cancelled an abandoned prepared bearer (appliance → Ready)"
                ),
                // `cancel()` is only valid in `Prepared`; a not-Prepared appliance is already fine.
                Err(e) => {
                    log::debug!("[offline-bearer] cancel no-op (appliance not Prepared): {e}")
                }
            }
        }
        Ok(())
    }

    /// §27/§28 host recovery seam. OBSERVE the sender appliance's recovery state at a re-attach
    /// (process restart / power loss) via [`AnchorAppliance::recover`], then apply the host cancel
    /// policy ([`crate::anchor::recovery_action`]): cancel ONLY an orphaned uncommitted `Prepared` —
    /// one with no in-flight/durable session owning it and whose counter has not moved. A committed
    /// release is NEVER cancelled or erased here (it is re-emitted or resolved online); a mismatch
    /// downgrades online. `recover()` observes; this method decides and executes ONLY the
    /// orphaned-`Prepared` cancel.
    ///
    /// `prepared_owned_by_session` is supplied by the caller — the bilateral handler knows whether an
    /// in-flight session still holds the matching prepared bearer. Pass `false` at a cold re-attach
    /// where the in-memory sessions are gone. Returns the decided [`crate::anchor::RecoveryAction`].
    pub fn resolve_prepared_on_reattach(
        &self,
        prepared_owned_by_session: bool,
    ) -> Result<crate::anchor::RecoveryAction, DsmError> {
        let mut guard = self.anchor_appliance.lock();
        let Some(app) = guard.as_mut() else {
            // No appliance attached yet -> nothing is prepared -> Ready.
            return Ok(crate::anchor::RecoveryAction::Ready);
        };
        let outcome = app.recover()?;
        let action = crate::anchor::recovery_action(outcome, prepared_owned_by_session);
        if action == crate::anchor::RecoveryAction::CancelOrphanedPrepared {
            // Host policy executes the cancel — `recover()` did not. Only an orphaned uncommitted
            // Prepared reaches here (no owning session, counter not moved), so nothing is lost.
            app.cancel()?;
            log::info!(
                "[offline-bearer] re-attach cancelled an orphaned prepared bearer (appliance → Ready)"
            );
        }
        Ok(action)
    }
}

/* ------------------------------ Private helpers ------------------------- */

/// User-facing error when an offline-bearer send finds no anchor appliance connected. It rides the
/// `DsmError` up through the confirm-build failure into the `BilateralEventFailed` event's message,
/// where the frontend maps it to a "connect your anchor device" toast (Stage 4 Slice 3 signal a).
/// A const so the not(test) producer and the wording test share one source of truth.
pub(crate) const OFFLINE_BEARER_NO_APPLIANCE_MSG: &str =
    "offline-bearer requires the anchor appliance; connect the anchor device (Pico) and retry (fail closed)";

/// The sender-side appliance when no hardware factory is installed: none.
/// Offline-bearer requires the physical anchor device ("offline = chips").
fn hardware_appliance_or_fail(
    _seed: &impl Fn(&str) -> [u8; 32],
    _dev: [u8; 32],
) -> Result<Box<dyn crate::anchor::AnchorAppliance + Send>, DsmError> {
    Err(DsmError::invalid_operation(OFFLINE_BEARER_NO_APPLIANCE_MSG))
}

impl CoreSDK {
    fn token_metadata_from_proto(proto: &TokenMetadataProto) -> TokenMetadata {
        TokenMetadata {
            token_id: proto.token_id.clone(),
            name: proto.name.clone(),
            symbol: proto.symbol.clone(),
            description: proto.description.clone().filter(|s| !s.is_empty()),
            icon_url: proto.icon_url.clone().filter(|s| !s.is_empty()),
            decimals: (proto.decimals as u8).min(18),
            token_type: match proto.token_type.to_uppercase().as_str() {
                "NATIVE" => dsm::types::token_types::TokenType::Native,
                "CREATED" => dsm::types::token_types::TokenType::Created,
                "RESTRICTED" => dsm::types::token_types::TokenType::Restricted,
                "WRAPPED" => dsm::types::token_types::TokenType::Wrapped,
                _ => dsm::types::token_types::TokenType::Created,
            },
            owner_id: {
                let bytes = crate::util::text_id::decode_base32_crockford(&proto.owner_id)
                    .unwrap_or_default();
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                }
                arr
            },
            metadata_uri: proto.metadata_uri.clone().filter(|s| !s.is_empty()),
            policy_anchor: proto.policy_anchor.clone().filter(|s| !s.is_empty()),
            fields: proto
                .fields
                .iter()
                .map(|field| (field.key.clone(), field.value.clone()))
                .collect(),
        }
    }

    fn token_metadata_for_operation(
        &self,
        op: &dsm::types::operations::Operation,
        token_id: &str,
    ) -> Option<TokenMetadata> {
        match op {
            // The canonical creation operation. Recognising it here is what
            // lets a token be recovered from the chain alone after a restart.
            dsm::types::operations::Operation::CreateToken {
                token_id: op_token_id,
                symbol,
                name,
                decimals,
                policy_commit,
                metadata_uri,
                ..
            } => {
                let op_token_id_str = String::from_utf8(op_token_id.clone()).ok()?;
                if op_token_id_str != token_id && symbol != token_id {
                    return None;
                }
                let anchor_b32 = crate::util::text_id::encode_base32_crockford(policy_commit);
                Some(TokenMetadata {
                    token_id: op_token_id_str,
                    name: name.clone(),
                    symbol: symbol.clone(),
                    description: None,
                    icon_url: None,
                    decimals: *decimals,
                    token_type: dsm::types::token_types::TokenType::Created,
                    owner_id: self.device_info.device_id,
                    metadata_uri: metadata_uri.clone(),
                    policy_anchor: Some(format!("dsm:policy:{anchor_b32}")),
                    fields: std::collections::HashMap::new(),
                })
            }
            dsm::types::operations::Operation::Create { metadata, .. } => {
                let proto = TokenMetadataProto::decode(metadata.as_slice()).ok()?;
                let token_metadata = Self::token_metadata_from_proto(&proto);
                if token_metadata.token_id == token_id || token_metadata.symbol == token_id {
                    Some(token_metadata)
                } else {
                    None
                }
            }
            dsm::types::operations::Operation::Generic {
                operation_type,
                data,
                ..
            } => {
                if operation_type.as_slice() == b"token_create"
                    || operation_type.as_slice() == b"token_registry_update"
                {
                    if let Ok(registry_update) = TokenRegistryUpdateList::decode(data.as_slice()) {
                        if let Some(proto) = registry_update
                            .items
                            .into_iter()
                            .find(|proto| proto.token_id == token_id || proto.symbol == token_id)
                        {
                            return Some(Self::token_metadata_from_proto(&proto));
                        }
                    }
                    if let Ok(proto) = TokenMetadataProto::decode(data.as_slice()) {
                        let token_metadata = Self::token_metadata_from_proto(&proto);
                        if token_metadata.token_id == token_id || token_metadata.symbol == token_id
                        {
                            return Some(token_metadata);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn resolve_policy_commit_strict(&self, token_id: &[u8]) -> Result<[u8; 32], DsmError> {
        let token_id = std::str::from_utf8(token_id)
            .map_err(|_| DsmError::invalid_operation("token_id must be valid UTF-8"))?;

        if let Some(commit) = crate::policy::builtin_policy_commit(token_id) {
            return Ok(commit);
        }

        // The registry is authoritative for the persisted token IDENTITY
        // mapping — ticker, token id, policy commitment, metadata — while
        // canonical DeviceState stays authoritative for balances and
        // transitions. Ask it before walking the archive.
        //
        // A device that ADOPTED a token by its CPTA anchor holds a registry
        // row and the anchored policy bytes, and has no CreateToken of its own
        // to find: adoption registers an identity, it is not a transition on
        // this device's chain. So an archive-only lookup resolved on the
        // CREATING device and could never resolve on the RECEIVING one, and
        // every incoming transfer of an adopted token fail-closed with
        // "Missing canonical policy anchor" after the sender had already
        // debited.
        //
        // This is not trusting a mutable cache. `load_policy_verified`
        // re-derives BLAKE3(TAG_DSM_POLICY, policy_bytes) and refuses bytes
        // that do not hash to the commitment they are stored under, so a row
        // that does not carry the real policy cannot resolve through here.
        for row in [
            crate::storage::client_db::token_registry::get_token(token_id),
            crate::storage::client_db::token_registry::get_token_by_ticker(token_id),
        ]
        .into_iter()
        .flatten()
        .flatten()
        {
            if matches!(
                crate::storage::client_db::token_registry::load_policy_verified(&row.policy_commit),
                Ok(Some(_))
            ) {
                return Ok(row.policy_commit);
            }
        }

        // Per §4.3 there is no `state_number`. Walk the per-relationship
        // chain-state archive newest-first looking for an op that registered
        // metadata for `token_id`. Chains are keyed by chain tip and ordered
        // by insertion time — no counter, no derived sparse index.
        let device_id = self.device_info.device_id;
        let states =
            crate::storage::client_db::get_bcr_chain_states(&device_id, false).map_err(|e| {
                DsmError::state(format!(
                    "Failed to load BCR chain states for policy commit lookup: {e}"
                ))
            })?;
        for state in states.into_iter().rev() {
            if let Some(token_metadata) =
                self.token_metadata_for_operation(&state.operation, token_id)
            {
                return crate::policy::strict_policy_commit_for_token(
                    token_id,
                    token_metadata.policy_anchor.as_deref(),
                );
            }
        }

        Err(DsmError::state(format!(
            "Missing canonical policy anchor for token {token_id}"
        )))
    }

    pub async fn local_genesis_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Return the genesis hash `G` from the genesis_records table.
        // This MUST match the genesis hash that contacts store during pairing,
        // otherwise b0x routing addresses will diverge between sender and receiver.
        match crate::storage::client_db::get_verified_genesis_record() {
            Ok(Some(rec)) => match crate::util::text_id::decode_base32_crockford(&rec.genesis_id) {
                Some(bytes) if bytes.len() == 32 => Ok(bytes),
                _ => Err(DsmError::internal(
                    "genesis_records.genesis_id is not a valid 32-byte base32 value",
                    None::<std::convert::Infallible>,
                )),
            },
            Ok(None) => Err(DsmError::internal(
                "no genesis record found; genesis has not been created yet",
                None::<std::convert::Infallible>,
            )),
            Err(e) => Err(DsmError::internal(
                format!("failed to read genesis record: {e}"),
                None::<std::convert::Infallible>,
            )),
        }
    }

    fn sync_token_projection_best_effort(
        &self,
        local_b32: &str,
        token_id: &[u8],
        new_state: &State,
        context: &str,
    ) {
        let token_id_str = String::from_utf8_lossy(token_id);
        let canonical_token_id = token_id_str.trim();
        if canonical_token_id.is_empty() {
            log::error!(
                "[{context}] CRITICAL: the operation names no token; no projection to sync"
            );
            return;
        }

        let existing_locked = match client_db::get_locked_balance(local_b32, canonical_token_id) {
            Ok(value) => value,
            Err(error) => {
                log::error!(
                    "[{context}] CRITICAL: failed to read {canonical_token_id} locked balance \
                     ({error}); the projection is left for the repair sweep"
                );
                return;
            }
        };

        let policy_commit = match self.resolve_policy_commit_strict(token_id) {
            Ok(commit) => commit,
            Err(error) => {
                log::error!(
                    "[{context}] CRITICAL: failed to resolve policy commit for {canonical_token_id}: {error}"
                );
                return;
            }
        };

        if let Err(error) = client_db::sync_token_projection_from_state(
            local_b32,
            canonical_token_id,
            &policy_commit,
            new_state,
            existing_locked,
        ) {
            log::error!(
                "[{context}] CRITICAL: failed to sync {canonical_token_id} projection: {error}"
            );
        } else {
            log::info!("[{context}] token projection synced: {canonical_token_id}");
        }
    }

    /// The ONE production canonical apply for an inbound online transfer —
    /// STAGED (§16.6 defect zero, recipient side).
    ///
    /// ```text
    /// lookup (Duplicate/Conflict return HERE, nothing built)
    ///   → pin (signed parent == pinned counterparty head)
    ///   → prepare (pure)
    ///   → build_acceptance(&AdvanceOutcome, outcome.relationship_pair())   pre-write:
    ///                                                                     DB reads + signing OK
    ///   → ONE tx { state advance, nonce, CanonicalApplyRecord (with B pair),
    ///              write_acceptance(tx, &outcome, &artifacts) }
    /// ```
    ///
    /// The builder sees the EXACT outcome that commits, so what it signs (the
    /// recipient's canonical pair) is the pair of the very advance that lands;
    /// the writer runs inside the same transaction, so a failed apply leaves no
    /// journal, no inert row and no re-sign question. `Duplicate` returns
    /// before the builder is invoked; `Conflict` never builds.
    ///
    /// `sender_transition_entropy` is the receipt's canonical field 21: the one
    /// value Core derived inside the sender's `advance` (Part VII step 3). It is
    /// what `C_pre` is computed over here (§39.3), and it lets this side
    /// recompute the sender's `child_tip` from `parent_tip`, the signed
    /// operation and that value — a receipt whose child is not that successor
    /// is refused before anything is built.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_incoming_transfer_staged<A>(
        &self,
        op: dsm::types::operations::Operation,
        tx_id: &crate::types::identifiers::TransactionId,
        sender_device_id: &str,
        canonical_operation_bytes: &[u8],
        signed_parent_tip: [u8; 32],
        signed_child_tip: [u8; 32],
        sender_transition_entropy: [u8; 32],
        build_acceptance: impl FnOnce(
            &dsm::types::device_state::AdvanceOutcome,
            ([u8; 32], [u8; 32]),
        ) -> Result<A, DsmError>,
        write_acceptance: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
        admission: Option<AdmissionPlan<'_>>,
    ) -> Result<crate::sdk::apply_outcome::ApplyOutcome, DsmError> {
        use crate::sdk::apply_outcome::ApplyOutcome;
        use crate::storage::client_db::{
            self as cdb, CanonicalApplyInsertOutcome, CanonicalApplyLookup, CanonicalApplyRecord,
        };
        use crate::storage::codecs::hash_blake3_bytes;

        // ---- validate the request (fail closed) ----
        let (nonce, amount_val, to_device_id, token_id) = match &op {
            dsm::types::operations::Operation::Transfer {
                nonce,
                amount,
                to_device_id,
                token_id,
                ..
            } => (
                nonce.clone(),
                amount.value(),
                to_device_id.clone(),
                token_id.clone(),
            ),
            _ => {
                return Err(DsmError::invalid_operation(
                    "apply_incoming_transfer_full_state: only Transfer operations are accepted",
                ))
            }
        };
        if nonce.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: empty transfer nonce",
            ));
        }
        if amount_val == 0 {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: zero transfer amount",
            ));
        }
        if canonical_operation_bytes.is_empty() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: empty canonical operation bytes",
            ));
        }
        let local_device_id_bytes = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::state_machine("missing local device_id (AppState)"))?;
        if local_device_id_bytes.len() != 32 {
            return Err(DsmError::state_machine(
                "local device_id must be 32 bytes (AppState corrupt)",
            ));
        }
        if to_device_id.as_slice() != local_device_id_bytes.as_slice() {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: transfer not addressed to this device",
            ));
        }
        let sender_id_bytes = crate::util::text_id::decode_base32_crockford(sender_device_id)
            .ok_or_else(|| DsmError::invalid_operation("sender_device_id not valid base32"))?;
        if sender_id_bytes.len() != 32 {
            return Err(DsmError::invalid_operation(
                "apply_incoming_transfer_full_state: sender_device_id must decode to 32 bytes",
            ));
        }
        let mut local_arr = [0u8; 32];
        local_arr.copy_from_slice(&local_device_id_bytes);
        let mut sender_arr = [0u8; 32];
        sender_arr.copy_from_slice(&sender_id_bytes);

        // ---- derive the PRE-EXECUTION request identity (no roots) ----
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&local_arr, &sender_arr);
        // AUTHORITY SOURCING: the request pair comes from the SIGNED receipt's
        // ASYMMETRIC canonical tips — the same formula-space as the DeviceState
        // embedded relationship lineage this apply advances. The SYMMETRIC
        // (`compute_successor_tip`) lineage is a projection/routing space and is
        // NEVER derived or compared here (cross-space comparison was the
        // AWYPCNK8 false-conflict bug). C_pre is bound to the signed parent
        // and takes the sender's transition entropy — the one value of the
        // transition (§39.3) — never the transfer nonce, which stays in the
        // operation bytes where it is already hashed (§39.4).
        let parent_tip = signed_parent_tip;
        let child_tip = signed_child_tip;
        let precommit_digest = dsm::core::bilateral_transaction_manager::compute_precommit(
            &parent_tip,
            canonical_operation_bytes,
            &sender_transition_entropy,
        );
        let operation_digest = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                dsm::crypto::domain::TaggedHashDomain::from_static(
                    b"DSM/canonical-apply-op-digest/v1",
                ),
            );
            h.update(canonical_operation_bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&h.finalize().as_bytes()[..32]);
            out
        };
        let nonce_hash = hash_blake3_bytes(&nonce);
        let canonical_apply_id = cdb::compute_canonical_apply_id(
            &rel_key,
            &parent_tip,
            &child_tip,
            &precommit_digest,
            &operation_digest,
            &sender_arr,
            &local_arr,
            &nonce_hash,
        );

        // ---- lookup BEFORE inspecting any mutable state or executing ----
        match cdb::lookup_canonical_apply_status(
            &canonical_apply_id,
            &rel_key,
            &parent_tip,
            &nonce_hash,
        )
        .map_err(|e| {
            DsmError::internal(
                format!("canonical apply lookup failed: {e}"),
                None::<std::convert::Infallible>,
            )
        })? {
            CanonicalApplyLookup::Duplicate(record) => {
                log::info!(
                    "[apply_full_state] duplicate of already-applied op (tx={}); returning stored record, no re-execution",
                    String::from_utf8_lossy(tx_id.as_bytes()),
                );
                return Ok(ApplyOutcome::AlreadyAppliedSameOperation { record: *record });
            }
            CanonicalApplyLookup::Conflict => {
                return Ok(ApplyOutcome::Conflict {
                    reason: "a different operation identity already consumed this (relationship, \
                             parent) or nonce"
                        .to_string(),
                });
            }
            CanonicalApplyLookup::Fresh => {}
        }

        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &local_arr,
            &sender_arr,
        );
        // §16.6 A-side head pin (the space-correct successor check).
        // The recipient cannot recompute the sender's child — chain tips are
        // per-device values — but it CAN pin the sender's asymmetric head and
        // require the signed parent to be exactly it. Before any transition has
        // been applied the pin is the spec-canonical genesis seed, the single
        // tip both sides derive identically. A stale, replayed, reordered, or
        // forked sender lineage fails closed HERE, before execution.
        let pinned_a_head = cdb::pinned_counterparty_a_head(&rel_key)
            .map_err(|e| {
                DsmError::internal(
                    format!("A-side head pin failed: {e}"),
                    None::<std::convert::Infallible>,
                )
            })?
            .unwrap_or(init_tip);
        if parent_tip != pinned_a_head {
            return Ok(ApplyOutcome::Conflict {
                reason: format!(
                    "signed parent ({}..) is not the pinned counterparty A-side head ({}..) — \
                     stale, replayed, or forked sender lineage",
                    crate::util::text_id::encode_base32_crockford(&parent_tip[..4]),
                    crate::util::text_id::encode_base32_crockford(&pinned_a_head[..4]),
                ),
            });
        }
        // §39.3: the signed child IS the v2 successor of the signed parent under
        // the signed operation and the carried transition entropy. The sender's
        // chain state hashes ITS counterparty devid (this device), the signed
        // operation bytes (signature included — `op` is byte-identical to what
        // the sender advanced, `decode_and_bind_signed` guarantees it) and the
        // entropy Core derived for that step. A receipt whose child is anything
        // else names a successor no honest advance produced.
        let expected_child = dsm::types::device_state::relationship_chain_tip_v2(
            &rel_key,
            &parent_tip,
            &local_arr,
            &op.to_bytes(),
            &sender_transition_entropy,
            None,
        );
        if child_tip != expected_child {
            return Ok(ApplyOutcome::Conflict {
                reason: format!(
                    "signed child ({}..) is not the successor of the signed parent under the \
                     signed operation and the carried transition entropy ({}..)",
                    crate::util::text_id::encode_base32_crockford(&child_tip[..4]),
                    crate::util::text_id::encode_base32_crockford(&expected_child[..4]),
                ),
            });
        }

        // ---- fresh: execute under the global lock with the single full-state tx ----
        let deltas = {
            let pc = self.resolve_policy_commit_strict(&token_id)?;
            vec![dsm::types::device_state::BalanceDelta {
                policy_commit: pc,
                direction: dsm::types::device_state::BalanceDirection::Credit,
                amount: amount_val,
            }]
        };
        let tx_id_str = String::from_utf8_lossy(tx_id.as_bytes()).into_owned();
        // The record every in-tx write derives from — built ONCE from the
        // outcome so the durable row and the returned value cannot drift.
        let record_for = |outcome: &dsm::types::device_state::AdvanceOutcome| {
            let (applied_parent_tip_b, applied_child_tip_b) = outcome.relationship_pair();
            CanonicalApplyRecord {
                relationship_key: rel_key,
                parent_tip,
                child_tip,
                precommit_digest,
                operation_digest,
                sender_device: sender_arr,
                recipient_device: local_arr,
                nonce_hash,
                applied_parent_root_b: outcome.parent_r_a,
                applied_child_root_b: outcome.child_r_a,
                applied_parent_tip_b,
                applied_child_tip_b,
            }
        };
        let build = |outcome: &dsm::types::device_state::AdvanceOutcome| -> Result<A, DsmError> {
            build_acceptance(outcome, outcome.relationship_pair())
        };
        let in_tx_extra = {
            let nonce = nonce.clone();
            let tx_id_str = tx_id_str.clone();
            move |tx: &rusqlite::Transaction<'_>,
                  outcome: &dsm::types::device_state::AdvanceOutcome,
                  artifacts: &A|
                  -> Result<(), DsmError> {
                // Nonce consumption INSIDE the full-state transaction.
                let spent = cdb::is_nonce_spent_with_conn(tx, &nonce).map_err(|e| {
                    DsmError::internal(
                        format!("in-tx nonce check failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })?;
                if spent {
                    return Err(DsmError::invalid_operation(
                        "full-state apply race: nonce consumed concurrently (fail closed)",
                    ));
                }
                cdb::mark_nonce_spent_with_conn(tx, &nonce, &tx_id_str, &sender_arr, amount_val)
                    .map_err(|e| {
                        DsmError::internal(
                            format!("in-tx nonce consume failed: {e}"),
                            None::<std::convert::Infallible>,
                        )
                    })?;
                // Canonical apply record with the AUTHORITATIVE applied B roots
                // and B pair from the state mutation itself.
                let record = record_for(outcome);
                match cdb::insert_canonical_apply_identity_with_conn(tx, &record).map_err(|e| {
                    DsmError::internal(
                        format!("in-tx canonical apply insert failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })? {
                    CanonicalApplyInsertOutcome::Inserted => {}
                    CanonicalApplyInsertOutcome::DuplicateSameOperation(_)
                    | CanonicalApplyInsertOutcome::Conflict => {
                        return Err(DsmError::invalid_operation(
                            "full-state apply race: canonical apply identity inserted \
                             concurrently (fail closed)",
                        ))
                    }
                }
                // The peer's canonical head: signed parent → signed child, CAS'd
                // in THIS transaction. The pre-execution pin above read the same
                // authority outside the tx; the CAS closes that window — a head
                // that moved underneath is a retryable apply error, never a
                // sticky conflict, and nothing here commits.
                match cdb::cas_advance_counterparty_canonical_head_with_conn(
                    tx,
                    &rel_key,
                    &sender_arr,
                    &parent_tip,
                    &child_tip,
                    &canonical_apply_id,
                    &init_tip,
                )
                .map_err(|e| {
                    DsmError::internal(
                        format!("in-tx counterparty canonical head CAS failed: {e}"),
                        None::<std::convert::Infallible>,
                    )
                })? {
                    cdb::CasCanonicalHeadOutcome::Advanced
                    | cdb::CasCanonicalHeadOutcome::GenesisInit
                    | cdb::CasCanonicalHeadOutcome::AlreadyAtTarget => {}
                    cdb::CasCanonicalHeadOutcome::Conflict { current } => {
                        return Err(DsmError::internal(
                            format!(
                                "counterparty canonical head moved during apply (now {}..) — \
                                 nothing committed; retry",
                                current
                                    .map(|c| crate::util::text_id::encode_base32_crockford(&c[..4]))
                                    .unwrap_or_else(|| "none".to_string())
                            ),
                            None::<std::convert::Infallible>,
                        ))
                    }
                }
                // The recipient's acceptance artifacts (journal), same tx.
                write_acceptance(tx, outcome, artifacts)
            }
        };

        let exec = self.execute_on_relationship_staged_with_admission(
            rel_key,
            sender_arr,
            op,
            &deltas,
            build,
            in_tx_extra,
            admission,
        );

        match exec {
            Ok(staged) => {
                // Post-commit convergence (best-effort projection; NEVER invalidates
                // the committed canonical transition).
                let local_b32 = crate::util::text_id::encode_base32_crockford(&local_arr);
                self.sync_token_projection_best_effort(
                    &local_b32,
                    &token_id,
                    &staged.state,
                    "apply_full_state",
                );
                let record = record_for(&staged.outcome);
                log::info!(
                    "[apply_full_state] ✅ applied transfer tx={} amount={} from={} (single full-state tx)",
                    tx_id_str,
                    amount_val,
                    sender_device_id,
                );
                Ok(ApplyOutcome::Applied {
                    record,
                    advance: Box::new(staged.outcome),
                })
            }
            Err(e) => {
                // Losing racer / stale request classification. The DB is the
                // authority: re-lookup the exact identity first.
                match cdb::get_canonical_apply_identity_by_id(&canonical_apply_id) {
                    Ok(Some(record)) => Ok(ApplyOutcome::AlreadyAppliedSameOperation { record }),
                    _ => {
                        let msg = e.to_string();
                        if msg.contains("apply parent validation failed")
                            || msg.contains("apply child validation failed")
                            || msg.contains("full-state apply race")
                        {
                            Ok(ApplyOutcome::Conflict { reason: msg })
                        } else {
                            Err(e)
                        }
                    }
                }
            }
        }
    }
}

/* ---------------------------------- Tests ----------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic_fixtures;
    use crate::storage::client_db;
    use crate::test_support::two_device::Pair;
    use serial_test::serial;

    fn count_for_relationship(table: &str, rel: &[u8; 32]) -> i64 {
        let binding = client_db::get_connection().expect("conn");
        let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE relationship_key = ?1"),
            rusqlite::params![rel.as_slice()],
            |r| r.get(0),
        )
        .expect("count")
    }

    /// Installing a wallet's genesis leaves a head whose authority root IS the
    /// canonical G, in memory and as persisted, and a second `CoreSDK` for the
    /// same device (what a router build makes) restores exactly that root.
    #[test]
    #[serial]
    fn an_installed_genesis_head_carries_the_canonical_root_across_a_restore() {
        let (identity, core) = economic_fixtures::local_device(0x61);
        assert_eq!(
            core.device_head().expect("head").genesis_digest(),
            identity.genesis
        );
        let persisted = client_db::load_bcr_device_head(&identity.device_id)
            .expect("reload")
            .expect("a persisted head");
        assert_eq!(persisted.genesis_digest(), identity.genesis);
        let restored = economic_fixtures::core_sdk_for(&identity);
        assert_eq!(
            restored
                .device_head()
                .expect("restored head")
                .genesis_digest(),
            identity.genesis,
            "a router build restores the canonical root, never a synthetic one"
        );
    }

    /// A router is built only over a device head. A device whose database was
    /// lost keeps its identity in `AppState` but has no head: the router
    /// refuses rather than start on a head it made up.
    #[test]
    #[serial]
    fn a_router_refuses_to_start_without_a_genesis_head() {
        economic_fixtures::local_device(0x62);
        client_db::reset_database_for_tests();
        client_db::init_database().expect("init db");
        let built = crate::handlers::app_router_impl::AppRouterImpl::new(crate::init::SdkConfig {
            node_id: "no-head".into(),
            storage_endpoints: Vec::new(),
            enable_offline: false,
        });
        match built {
            Err(e) => assert!(e.to_string().contains("device head"), "{e}"),
            Ok(_) => panic!("a router started with no genesis head"),
        }
    }

    /// A restart restores the head the last advance committed: the faucet
    /// admission's head, root for root, from the persisted row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_restart_restores_the_head_the_last_advance_committed() {
        let d = crate::test_support::one_device::Device::funded(0x63).await;
        let live = d.core().device_head().expect("head");
        let cached = client_db::load_bcr_device_head(&d.identity.device_id)
            .expect("reload")
            .expect("a persisted head");
        assert_eq!(
            cached.root(),
            live.root(),
            "the cached head tracks the live one"
        );
        let restored = economic_fixtures::core_sdk_for(&d.identity);
        let head = restored.device_head().expect("restored head");
        assert_eq!(head.root(), live.root());
        assert_eq!(head.balance(&era_commit()), 100);
    }

    fn era_commit() -> [u8; 32] {
        dsm::core::token::token_state_manager::era_policy_commit()
    }

    /// A transfer redelivered to a recipient that lost its record of having
    /// consumed it applies ONCE: the halves are still on the members, the
    /// recipient reads them again, and nothing re-executes — no second
    /// credit, no second apply, journal or reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_redelivered_transfer_applies_once_and_is_never_rebuilt() {
        let p = Pair::boot(100, 0).await;
        let rel = p.a.rel_key_with(&p.b);
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        assert_eq!(p.b.era_balance(), 10);

        p.b.enter();
        let root_before = p.b.router().core_sdk.device_head().expect("head").root();
        let journal_before = count_for_relationship("acceptance_fold_journal", &rel);
        let replies_before = count_for_relationship("recipient_outbound_reply", &rel);
        assert_eq!(count_for_relationship("canonical_apply_identity", &rel), 1);
        // B's database loses its consume marks and read positions — a damaged
        // or partly restored store that kept the apply.
        {
            let binding = client_db::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute_batch("DELETE FROM b0x_consumed; DELETE FROM b0x_read_position;")
                .expect("drop the consume marks");
        }

        let again = p.b.sync().await;
        assert!(again.success, "{:?}", again.errors);
        assert_eq!(p.b.era_balance(), 10, "no second credit");
        p.b.enter();
        assert_eq!(
            p.b.router().core_sdk.device_head().expect("head").root(),
            root_before,
            "nothing re-executed"
        );
        assert_eq!(count_for_relationship("canonical_apply_identity", &rel), 1);
        assert_eq!(
            count_for_relationship("acceptance_fold_journal", &rel),
            journal_before,
            "no second journal"
        );
        assert_eq!(
            count_for_relationship("recipient_outbound_reply", &rel),
            replies_before,
            "no second reply was built"
        );
    }

    /// AWYPCNK8: the apply consults only the SIGNED canonical pair. The
    /// symmetric projection (`contacts.chain_tip`) is a different formula
    /// space. B's poll stages A's next transfer; B's projection of the
    /// relationship then diverges from its canonical lineage — as the live
    /// rig's did — and B's next sync still applies the staged pair.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn an_apply_consults_the_signed_pair_never_the_projection() {
        use crate::handlers::recipient_dispatch::{
            dispatch_evidence_half, dispatch_transfer_half, DispatchOutcome,
        };
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        let finalized = p.a.sync().await;
        assert!(finalized.success, "{:?}", finalized.errors);
        let released = p.b.sync().await;
        assert!(released.success, "{:?}", released.errors);

        let sent = p.a.send(&p.b, 5).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let one = crate::test_support::arrivals::the_one_transfer(&p.b, &p.fleet).await;
        p.b.enter();
        assert!(matches!(
            dispatch_transfer_half(&one.key, &one.transfer_bytes, &p.a.ak_pk, &one.route)
                .expect("stage the transfer"),
            DispatchOutcome::Staged(_)
        ));
        assert!(matches!(
            dispatch_evidence_half(&one.evidence, &p.a.ak_pk, &one.evidence_route)
                .expect("stage the evidence"),
            DispatchOutcome::Staged(_)
        ));

        {
            let binding = client_db::get_connection().expect("conn");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            let changed = conn
                .execute(
                    "UPDATE contacts SET chain_tip = ?1 WHERE device_id = ?2",
                    rusqlite::params![p.b.genesis.as_slice(), p.a.device_id.as_slice()],
                )
                .expect("diverge the projection");
            assert_eq!(changed, 1, "B holds A as a contact");
        }

        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        assert_eq!(
            p.b.era_balance(),
            15,
            "a valid signed pair applies whatever the projection holds"
        );
    }

    /// The offline-bearer "no appliance" error names the anchor device the user
    /// connects, and never the deleted v1 "Path-B" concept.
    #[test]
    fn offline_bearer_no_appliance_message_is_v2_worded() {
        assert!(OFFLINE_BEARER_NO_APPLIANCE_MSG.contains("anchor device"));
        assert!(!OFFLINE_BEARER_NO_APPLIANCE_MSG.contains("Path-B"));
    }
}

/* ---------------------------- Result Structures ------------------------- */
