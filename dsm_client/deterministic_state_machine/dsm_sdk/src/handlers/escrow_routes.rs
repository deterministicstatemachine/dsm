// SPDX-License-Identifier: MIT OR Apache-2.0

//! Escrow vault routes (SoFi §19.9, Amendment S21). Each route decodes the
//! user's intent, checks its shape, and hands it to its entry in
//! `sdk::escrow_flow`; producers assemble, Core decides. A route never
//! interprets a storage read, and never takes a verdict from anything but
//! the verdict cell Core reads.

use dsm::route_chain::ChainState;
use dsm::sofi::wire::{EscrowBranch, EscrowOutcome, EscrowSigner};
use dsm::types::proto as generated;

use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};
use super::sofi_routes::{d32, entered, position_response, request, shown};
use super::wallet_routes::token_of_commit;
use crate::bridge::{AppInvoke, AppResult};
use crate::sdk::escrow_flow::{
    CreateEscrowIntent, EscrowCreated, EscrowParty, EscrowVaultView, LockOutcome, OutcomeIntent,
    VerdictView,
};
use crate::sdk::sofi_flow::Search;
use crate::sdk::storage_set::StorageSet;

fn signer(s: &generated::EscrowSignerV1, route: &str) -> Result<EscrowSigner, String> {
    let alg = u16::try_from(s.signature_alg)
        .map_err(|e| format!("{route}: signature_alg {}: {e}", s.signature_alg))?;
    EscrowSigner::new(alg, &s.public_key).map_err(|e| format!("{route}: signer: {e:?}"))
}

fn signer_v1(s: &EscrowSigner) -> generated::EscrowSignerV1 {
    generated::EscrowSignerV1 {
        signature_alg: u32::from(s.signature_alg()),
        public_key: s.public_key().to_vec(),
    }
}

fn branch(b: &generated::EscrowBranchV1, route: &str) -> Result<EscrowBranch, String> {
    let signers = b
        .signers
        .iter()
        .map(|s| signer(s, route))
        .collect::<Result<Vec<_>, _>>()?;
    let outcome = EscrowOutcome::new(&b.outcome, signers).map_err(|e| {
        format!(
            "{route}: outcome {:?}: {e:?}",
            String::from_utf8_lossy(&b.outcome)
        )
    })?;
    Ok(EscrowBranch::new(
        outcome,
        d32(&b.recipient_genesis, "recipient_genesis", route)?,
        d32(&b.recipient_device_id, "recipient_device_id", route)?,
    ))
}

fn verdict_response(view: VerdictView) -> AppResult {
    let (state, outcome) = match view.held {
        None => (generated::EscrowVerdictState::None, Vec::new()),
        Some((outcome, ChainState::LeaderHeld)) => {
            (generated::EscrowVerdictState::LeaderHeld, outcome)
        }
        Some((outcome, ChainState::Preserved)) => {
            (generated::EscrowVerdictState::Preserved, outcome)
        }
        Some((outcome, ChainState::Final)) => (generated::EscrowVerdictState::Final, outcome),
    };
    pack_envelope_ok(generated::envelope::Payload::EscrowVerdictResponse(
        generated::EscrowVerdictResponse {
            verdict_cell: view.verdict_cell.to_vec(),
            state: state as i32,
            outcome,
            passed_over: view
                .passed_over
                .iter()
                .map(|refusal| format!("{refusal:?}"))
                .collect(),
        },
    ))
}

/// An outcome of a vault's terms, and what it means for `me`.
fn outcome_v1(
    b: &dsm::sofi::wire::EscrowBranch,
    me: &EscrowParty,
) -> generated::EscrowVaultOutcomeV1 {
    generated::EscrowVaultOutcomeV1 {
        outcome: b.outcome().to_vec(),
        signers: b.signers().iter().map(signer_v1).collect(),
        recipient_genesis: b.recipient_genesis().to_vec(),
        recipient_device_id: b.recipient_device_id().to_vec(),
        decided_by_this_device: b.signers().contains(&me.signer),
        pays_this_device: b.recipient_genesis() == &me.genesis
            && b.recipient_device_id() == &me.device_id,
    }
}

fn vault_v1(
    v: &EscrowVaultView,
    me: &EscrowParty,
    route: &str,
) -> Result<generated::EscrowVaultV1, String> {
    let (token_symbol, ..) = token_of_commit(&v.token).map_err(|e| format!("{route}: {e}"))?;
    let status = match v.status {
        dsm::sofi::wire::VAULT_STATUS_ACTIVE => generated::SofiVaultStatus::Active,
        dsm::sofi::wire::VAULT_STATUS_RETIRED => generated::SofiVaultStatus::Retired,
        other => {
            return Err(format!(
                "{route}: vault status {other:#06x} is not declared"
            ))
        }
    };
    Ok(generated::EscrowVaultV1 {
        vault_id: v.vault_id.to_vec(),
        owner_genesis: v.owner_genesis.to_vec(),
        owner_device_id: v.owner_device_id.to_vec(),
        verdict_cell: v.verdict_cell.to_vec(),
        external_commitment: v.external_commitment.to_vec(),
        token_policy_commit: v.token.to_vec(),
        token_symbol,
        amount: v.amount,
        amount_display: shown(v.amount, &v.token, route)?,
        generation: v.generation,
        status: status as i32,
        outcomes: v.branches.iter().map(|b| outcome_v1(b, me)).collect(),
    })
}

fn vaults_response(
    views: &[EscrowVaultView],
    me: &EscrowParty,
    search: Search,
    route: &str,
) -> AppResult {
    let vaults = match views
        .iter()
        .map(|v| vault_v1(v, me, route))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(vaults) => vaults,
        Err(e) => return err(e),
    };
    let search = match search {
        Search::Complete => generated::SofiSearch::Complete,
        Search::Partial => generated::SofiSearch::Partial,
    };
    pack_envelope_ok(generated::envelope::Payload::EscrowVaultsResponse(
        generated::EscrowVaultsResponse {
            vaults,
            search: search as i32,
        },
    ))
}

fn created_response(done: EscrowCreated) -> AppResult {
    pack_envelope_ok(generated::envelope::Payload::EscrowCreatedResponse(
        generated::EscrowCreatedResponse {
            vault_id: done.vault_id.to_vec(),
            verdict_cell: done.verdict_cell.to_vec(),
            external_commitment: done.external_commitment.to_vec(),
            position: done.position,
        },
    ))
}

impl AppRouterImpl {
    pub(crate) async fn handle_escrow_invoke(&self, i: AppInvoke) -> AppResult {
        if i.method == "escrow.party" {
            return self.escrow_party();
        }
        let network = match crate::sdk::economic_admission_flow::committed_network_id() {
            Ok(n) => n,
            Err(e) => return err(format!("{}: no committed network: {e}", i.method)),
        };
        // Every escrow vault, verdict cell and gathered signature lives on the
        // network's pinned set (DSM Amendment A5).
        let set = match crate::sdk::storage_set::canonical_set(&network) {
            Ok(s) => s,
            Err(e) => return err(format!("{}: no pinned storage set: {e}", i.method)),
        };
        match i.method.as_str() {
            "escrow.create" => self.escrow_create(&i, &set).await,
            "escrow.lock" => self.escrow_lock(&i, &set).await,
            "escrow.sign" => self.escrow_sign(&i, &set).await,
            "escrow.adjudicate" => self.escrow_adjudicate(&i, &set).await,
            "escrow.verdict" => self.escrow_verdict(&i, &set).await,
            "escrow.release" => self.escrow_release(&i, &set).await,
            "escrow.locked" => self.escrow_locked(&i, &set).await,
            "escrow.vaults" => self.escrow_vaults(&set).await,
            other => err(format!("unknown escrow route: {other}")),
        }
    }

    fn escrow_party(&self) -> AppResult {
        match crate::sdk::escrow_flow::party(&self.core_sdk) {
            Ok(party) => pack_envelope_ok(generated::envelope::Payload::EscrowPartyResponse(
                generated::EscrowPartyResponse {
                    genesis: party.genesis.to_vec(),
                    device_id: party.device_id.to_vec(),
                    signer: Some(signer_v1(&party.signer)),
                },
            )),
            Err(e) => err(format!("escrow.party: {e}")),
        }
    }

    async fn escrow_create(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.create";
        let req: generated::EscrowCreateRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<CreateEscrowIntent, String> {
            let token = d32(&req.token_policy_commit, "token_policy_commit", ROUTE)?;
            let amount = entered(&req.amount_entered, &token, "stake", ROUTE)?;
            if amount == 0 {
                return Err(format!("{ROUTE}: the stake must be positive"));
            }
            let branches = req
                .branches
                .iter()
                .map(|b| branch(b, ROUTE))
                .collect::<Result<Vec<_>, _>>()?;
            let counterpart = match req.counterpart_vault_id.as_slice() {
                [] => None,
                bytes => Some(d32(bytes, "counterpart_vault_id", ROUTE)?),
            };
            Ok(CreateEscrowIntent {
                external: req.external.clone(),
                token,
                amount,
                branches,
                counterpart,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::create(&self.core_sdk, set, &intent).await {
            Ok(done) => created_response(done),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    /// `escrow.lock`: `escrow.create` with each outcome's signers and recipient
    /// named by device id, resolved by the SDK (`escrow_flow::branches_named`).
    async fn escrow_lock(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.lock";
        let req: generated::EscrowLockRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let intent = match (|| -> Result<CreateEscrowIntent, String> {
            let token = d32(&req.token_policy_commit, "token_policy_commit", ROUTE)?;
            let amount = entered(&req.amount_entered, &token, "stake", ROUTE)?;
            if amount == 0 {
                return Err(format!("{ROUTE}: the stake must be positive"));
            }
            let outcomes = req
                .outcomes
                .iter()
                .map(|o| {
                    Ok(LockOutcome {
                        outcome: o.outcome.clone(),
                        decided_by: o
                            .decided_by
                            .iter()
                            .map(|d| d32(d, "decided_by", ROUTE))
                            .collect::<Result<Vec<_>, String>>()?,
                        pays: d32(&o.pays, "pays", ROUTE)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let branches = crate::sdk::escrow_flow::branches_named(&self.core_sdk, &outcomes)
                .map_err(|e| format!("{ROUTE}: {e}"))?;
            let counterpart = match req.counterpart_vault_id.as_slice() {
                [] => None,
                bytes => Some(d32(bytes, "counterpart_vault_id", ROUTE)?),
            };
            Ok(CreateEscrowIntent {
                external: req.external.clone(),
                token,
                amount,
                branches,
                counterpart,
            })
        })() {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::create(&self.core_sdk, set, &intent).await {
            Ok(done) => created_response(done),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    fn outcome_intent(i: &AppInvoke, route: &str) -> Result<OutcomeIntent, String> {
        let req: generated::EscrowOutcomeRequest = request(i)?;
        if req.outcome.is_empty() {
            return Err(format!("{route}: an outcome has 1..=64 bytes"));
        }
        Ok(OutcomeIntent {
            vault_id: d32(&req.vault_id, "vault_id", route)?,
            outcome: req.outcome,
        })
    }

    async fn escrow_sign(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.sign";
        let intent = match Self::outcome_intent(i, ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::sign_outcome(&self.core_sdk, set, &intent).await {
            Ok(done) => pack_envelope_ok(generated::envelope::Payload::EscrowSignedResponse(
                generated::EscrowSignedResponse {
                    verdict_cell: done.verdict_cell.to_vec(),
                    gathered: done.gathered.to_vec(),
                },
            )),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn escrow_adjudicate(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.adjudicate";
        let intent = match Self::outcome_intent(i, ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::adjudicate(&self.core_sdk, set, &intent).await {
            Ok(view) => verdict_response(view),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn escrow_verdict(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.verdict";
        let req: generated::EscrowVerdictRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let vault_id = match d32(&req.vault_id, "vault_id", ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::verdict(&self.core_sdk, set, &vault_id).await {
            Ok(view) => verdict_response(view),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn escrow_release(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.release";
        let req: generated::EscrowReleaseRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let vault_id = match d32(&req.vault_id, "vault_id", ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match crate::sdk::escrow_flow::release(&self.core_sdk, set, &vault_id).await {
            Ok(outcome) => position_response(outcome),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn escrow_locked(&self, i: &AppInvoke, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.locked";
        let req: generated::EscrowLockedRequest = match request(i) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let verdict_cell = match d32(&req.verdict_cell, "verdict_cell", ROUTE) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let me = match crate::sdk::escrow_flow::party(&self.core_sdk) {
            Ok(me) => me,
            Err(e) => return err(format!("{ROUTE}: {e}")),
        };
        match crate::sdk::escrow_flow::locked(&self.core_sdk, set, &verdict_cell).await {
            Ok((views, search)) => vaults_response(&views, &me, search, ROUTE),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }

    async fn escrow_vaults(&self, set: &StorageSet) -> AppResult {
        const ROUTE: &str = "escrow.vaults";
        let me = match crate::sdk::escrow_flow::party(&self.core_sdk) {
            Ok(me) => me,
            Err(e) => return err(format!("{ROUTE}: {e}")),
        };
        match crate::sdk::escrow_flow::own_vaults(&self.core_sdk, set).await {
            Ok(views) => vaults_response(&views, &me, Search::Complete, ROUTE),
            Err(e) => err(format!("{ROUTE}: {e}")),
        }
    }
}
