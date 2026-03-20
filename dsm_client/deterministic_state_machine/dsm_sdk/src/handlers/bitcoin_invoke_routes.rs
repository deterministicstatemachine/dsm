// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bitcoin invoke route handlers for AppRouterImpl.
//!
//! Handles all `bitcoin.*` invoke methods:
//! - `bitcoin.wallet.import`, `bitcoin.wallet.create`, `bitcoin.wallet.select`
//! - `bitcoin.address.select`
//! - `bitcoin.deposit.initiate`, `bitcoin.deposit.complete`, `bitcoin.deposit.refund`
//! - `bitcoin.deposit.fund_and_broadcast`, `bitcoin.deposit.await_and_complete`
//! - `bitcoin.claim.build`, `bitcoin.claim.auto`
//! - `bitcoin.tx.broadcast`
//! - `bitcoin.refund.build`
//! - `bitcoin.fractional.exit`, `bitcoin.full.sweep`

use dsm::types::proto as generated;
use dsm::bitcoin::BitcoinSettlementObservation;
use prost::Message;
use rand::RngCore;
use std::sync::Arc;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, err};
use super::transfer_helpers::{build_online_receipt, build_online_receipt_and_sigma};

#[derive(Clone)]
struct DepositCompletionPrep {
    current_state: dsm::types::state_types::State,
    requester_key: Vec<u8>,
    signing_public_key: Vec<u8>,
    recipient: [u8; 32],
    receipt_bytes: Vec<u8>,
    stitched_receipt_sigma: [u8; 32],
    pre_applied_token_op: Option<dsm::types::token_types::TokenOperation>,
    pre_applied_token_state: Option<dsm::types::state_types::State>,
}

struct SweepBroadcastRequest<'a> {
    bitcoin_tap: &'a Arc<crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk>,
    bitcoin_keys: &'a Arc<tokio::sync::Mutex<crate::sdk::bitcoin_key_store::BitcoinKeyStore>>,
    source_exec_data: &'a crate::sdk::bitcoin_tap_sdk::VaultExecutionData,
    successor_vault_op_id: &'a str,
    exit_sats: u64,
    remainder_sats: u64,
    dest_addr: &'a str,
    successor_htlc_script: &'a [u8],
    network: dsm::bitcoin::types::BitcoinNetwork,
}

#[derive(Default)]
struct WithdrawalResolutionSummary {
    finalized: u32,
    pending: u32,
}

fn encode_proto_arg<T: Message>(message: &T) -> Vec<u8> {
    generated::ArgPack {
        codec: generated::Codec::Proto as i32,
        body: message.encode_to_vec(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn decode_internal_envelope(result: AppResult, route: &str) -> Result<generated::Envelope, String> {
    if !result.success {
        return Err(result
            .error_message
            .unwrap_or_else(|| format!("{route}: internal invoke failed")));
    }
    let payload = result
        .data
        .strip_prefix(&[0x03])
        .ok_or_else(|| format!("{route}: missing envelope v3 framing"))?;
    generated::Envelope::decode(payload)
        .map_err(|e| format!("{route}: failed to decode envelope: {e}"))
}

fn ensure_dbtc_exit_balance(
    route: &str,
    available_sats: u64,
    required_sats: u64,
) -> Result<(), String> {
    if available_sats < required_sats {
        return Err(format!(
            "{route}: insufficient dBTC balance: have {} sats, need {} sats",
            available_sats, required_sats
        ));
    }
    Ok(())
}

fn decode_policy_commit(route: &str, label: &str, policy_commit: &[u8]) -> Result<[u8; 32], String> {
    if policy_commit.len() != 32 {
        return Err(format!(
            "{route}: {label} policy_commit must be 32 bytes (got {})",
            policy_commit.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(policy_commit);
    Ok(out)
}

fn policy_commit_label(policy_commit: &[u8; 32]) -> String {
    crate::util::text_id::encode_base32_crockford(policy_commit)
}

fn ensure_policy_commit_match(
    route: &str,
    subject: &str,
    expected_policy_commit: &[u8; 32],
    actual_policy_commit: &[u8; 32],
) -> Result<(), String> {
    if expected_policy_commit == actual_policy_commit {
        return Ok(());
    }
    Err(format!(
        "{route}: {subject} policy_commit mismatch (expected {}, got {})",
        policy_commit_label(expected_policy_commit),
        policy_commit_label(actual_policy_commit)
    ))
}

fn persisted_withdrawal_policy_commit(
    route: &str,
    withdrawal_id: &str,
) -> Result<[u8; 32], String> {
    let withdrawal = crate::storage::client_db::get_withdrawal(withdrawal_id)
        .map_err(|e| format!("{route}: withdrawal metadata lookup failed: {e}"))?
        .ok_or_else(|| format!("{route}: withdrawal metadata not found for {withdrawal_id}"))?;
    decode_policy_commit(route, "persisted withdrawal", &withdrawal.policy_commit)
}

fn ensure_exec_data_matches_withdrawal_policy(
    route: &str,
    withdrawal_id: &str,
    source_vault_id: &str,
    exec_data: &crate::sdk::bitcoin_tap_sdk::VaultExecutionData,
) -> Result<(), String> {
    let expected_policy_commit = persisted_withdrawal_policy_commit(route, withdrawal_id)?;
    ensure_policy_commit_match(
        route,
        &format!("source vault {}", &source_vault_id[..source_vault_id.len().min(12)]),
        &expected_policy_commit,
        &exec_data.policy_commit,
    )
}

fn persist_withdrawal_leg(
    withdrawal_id: &str,
    leg_index: u32,
    vault_id: &str,
    leg_kind: &str,
    amount_sats: u64,
    estimated_fee_sats: u64,
    estimated_net_sats: u64,
    sweep_txid: Option<&str>,
    successor_vault_id: Option<&str>,
    successor_vault_op_id: Option<&str>,
    exit_vault_op_id: Option<&str>,
) -> Result<(), String> {
    let now = crate::util::deterministic_time::tick();
    crate::storage::client_db::upsert_withdrawal_leg(&crate::storage::client_db::InFlightWithdrawalLeg {
        withdrawal_id: withdrawal_id.to_string(),
        leg_index,
        vault_id: vault_id.to_string(),
        leg_kind: leg_kind.to_string(),
        amount_sats,
        estimated_fee_sats,
        estimated_net_sats,
        sweep_txid: sweep_txid.map(str::to_string),
        successor_vault_id: successor_vault_id.map(str::to_string),
        successor_vault_op_id: successor_vault_op_id.map(str::to_string),
        exit_vault_op_id: exit_vault_op_id.map(str::to_string),
        state: "broadcast".to_string(),
        proof_digest: None,
        created_at: now,
        updated_at: now,
    })
    .map_err(|e| format!("withdrawal leg persistence failed: {e}"))
}

fn persist_committed_withdrawal_metadata(
    withdrawal_id: &str,
    device_id: &str,
    amount_sats: u64,
    dest_address: &str,
    policy_commit: &[u8],
    burn_token_id: &str,
    burn_amount_sats: u64,
) -> Result<(), String> {
    if withdrawal_id.is_empty() {
        return crate::storage::client_db::create_withdrawal(
            crate::storage::client_db::CreateWithdrawalParams {
                withdrawal_id,
                device_id,
                amount_sats,
                dest_address,
                policy_commit,
                state: "committed",
                burn_token_id: Some(burn_token_id),
                burn_amount_sats,
            },
        )
        .map_err(|e| format!("withdrawal metadata creation failed: {e}"));
    }

    match crate::storage::client_db::get_withdrawal(withdrawal_id)
        .map_err(|e| format!("withdrawal metadata lookup failed: {e}"))?
    {
        Some(_) => crate::storage::client_db::set_withdrawal_state(withdrawal_id, "committed")
            .map_err(|e| format!("withdrawal metadata commit transition failed: {e}")),
        None => crate::storage::client_db::create_withdrawal(
            crate::storage::client_db::CreateWithdrawalParams {
                withdrawal_id,
                device_id,
                amount_sats,
                dest_address,
                policy_commit,
                state: "committed",
                burn_token_id: Some(burn_token_id),
                burn_amount_sats,
            },
        )
        .map_err(|e| format!("withdrawal metadata creation failed: {e}")),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WithdrawalExecutionTestRoute {
    Fractional,
    Full,
}

#[cfg(test)]
impl WithdrawalExecutionTestRoute {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fractional => "bitcoin.fractional.exit",
            Self::Full => "bitcoin.full.sweep",
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct WithdrawalExecutionTestExpectation {
    route: WithdrawalExecutionTestRoute,
    request: generated::BitcoinFractionalExitRequest,
    result: Result<generated::BitcoinFractionalExitResponse, String>,
}

#[cfg(test)]
impl WithdrawalExecutionTestExpectation {
    pub(crate) fn fractional(
        request: generated::BitcoinFractionalExitRequest,
        result: Result<generated::BitcoinFractionalExitResponse, String>,
    ) -> Self {
        Self {
            route: WithdrawalExecutionTestRoute::Fractional,
            request,
            result,
        }
    }

    pub(crate) fn full(
        request: generated::BitcoinFractionalExitRequest,
        result: Result<generated::BitcoinFractionalExitResponse, String>,
    ) -> Self {
        Self {
            route: WithdrawalExecutionTestRoute::Full,
            request,
            result,
        }
    }
}

#[cfg(test)]
static WITHDRAWAL_EXECUTION_TEST_RESULTS: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::VecDeque<WithdrawalExecutionTestExpectation>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::VecDeque::new()));

#[cfg(test)]
pub(crate) fn set_withdrawal_execution_test_expectations(
    results: impl IntoIterator<Item = WithdrawalExecutionTestExpectation>,
) {
    let mut state = WITHDRAWAL_EXECUTION_TEST_RESULTS
        .lock()
        .expect("withdrawal execution test state mutex poisoned");
    state.clear();
    state.extend(results);
}

#[cfg(test)]
pub(crate) fn assert_withdrawal_execution_test_expectations_drained() {
    let state = WITHDRAWAL_EXECUTION_TEST_RESULTS
        .lock()
        .expect("withdrawal execution test state mutex poisoned");
    assert!(
        state.is_empty(),
        "unused withdrawal execution test expectations remain: {state:?}"
    );
}

#[cfg(test)]
fn take_withdrawal_execution_test_result(
    route: WithdrawalExecutionTestRoute,
    req: &generated::BitcoinFractionalExitRequest,
) -> Option<Result<generated::BitcoinFractionalExitResponse, String>> {
    let expectation = WITHDRAWAL_EXECUTION_TEST_RESULTS
        .lock()
        .expect("withdrawal execution test state mutex poisoned")
        .pop_front()?;
    assert_eq!(
        expectation.route,
        route,
        "withdrawal execution test expected {} but received {}",
        expectation.route.as_str(),
        route.as_str()
    );
    // Compare all routing-relevant fields; skip plan_id which is a runtime-derived
    // opaque withdrawal identifier that the test cannot predict (tick-dependent).
    assert_eq!(
        expectation.request.source_vault_id,
        req.source_vault_id,
        "withdrawal execution test: source_vault_id mismatch for {}",
        route.as_str()
    );
    assert_eq!(
        expectation.request.exit_amount_sats,
        req.exit_amount_sats,
        "withdrawal execution test: exit_amount_sats mismatch for {}",
        route.as_str()
    );
    assert_eq!(
        expectation.request.successor_locktime,
        req.successor_locktime,
        "withdrawal execution test: successor_locktime mismatch for {}",
        route.as_str()
    );
    assert_eq!(
        expectation.request.refund_iterations,
        req.refund_iterations,
        "withdrawal execution test: refund_iterations mismatch for {}",
        route.as_str()
    );
    assert_eq!(
        expectation.request.destination_address,
        req.destination_address,
        "withdrawal execution test: destination_address mismatch for {}",
        route.as_str()
    );
    Some(expectation.result)
}

impl AppRouterImpl {
    async fn prepare_deposit_completion_prep(
        &self,
        route: &str,
        vault_op_id: &str,
        recipient: [u8; 32],
    ) -> Result<DepositCompletionPrep, String> {
        let current_state = self
            .core_sdk
            .get_current_state()
            .map_err(|e| format!("{route}: state unavailable: {e}"))?;
        let requester_key = self
            .wallet
            .get_kyber_public_key()
            .map_err(|e| format!("{route}: wallet Kyber key unavailable: {e}"))?;
        let signing_public_key = self
            .wallet
            .get_signing_keypair()
            .map(|(pk, _)| pk)
            .map_err(|e| format!("{route}: wallet SPHINCS key unavailable: {e}"))?;

        let deposit_record = self
            .bitcoin_tap
            .get_vault_record(vault_op_id)
            .await
            .map_err(|e| {
                format!("{route}: failed to fetch vault record for burn derivation: {e}")
            })?;
        let is_dbtc_exit = matches!(
            deposit_record.direction,
            crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc
        );

        let mut pre_applied_token_op: Option<dsm::types::token_types::TokenOperation> = None;
        let mut pre_applied_token_state: Option<dsm::types::state_types::State> = None;

        let sigma_state: dsm::types::state_types::State = if is_dbtc_exit {
            let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;
            let device_id_b32 =
                crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
            let current_sqlite =
                match crate::storage::client_db::get_token_balance(&device_id_b32, dbtc_id) {
                    Ok(Some((a, _))) => a,
                    Ok(None) => 0,
                    Err(e) => {
                        log::error!("[{route}] failed to read dBTC balance: {e}");
                        0
                    }
                };
            if current_sqlite < deposit_record.btc_amount_sats {
                return Err(format!(
                    "{route}: insufficient dBTC balance for burn: have {} need {}",
                    current_sqlite, deposit_record.btc_amount_sats
                ));
            }

            self.wallet
                .seed_token_balance_for_self(dbtc_id, current_sqlite)
                .map_err(|e| format!("{route}: failed to seed dBTC balance before burn: {e}"))?;

            let burn_op = dsm::types::token_types::TokenOperation::Burn {
                token_id: dbtc_id.to_string(),
                amount: deposit_record.btc_amount_sats,
            };
            let burn_applied_state = self
                .wallet
                .execute_token_operation(burn_op.clone())
                .await
                .map_err(|e| format!("{route}: failed to apply pre-unlock Burn transition: {e}"))?;

            if burn_applied_state.hash.len() == 32 {
                if let Err(e) =
                    crate::get_sdk_context().update_chain_tip(burn_applied_state.hash.to_vec())
                {
                    log::warn!(
                        "{route}: failed to update chain_tip after pre-unlock burn: {}",
                        e
                    );
                }
            }

            pre_applied_token_op = Some(burn_op);
            pre_applied_token_state = Some(burn_applied_state.clone());
            burn_applied_state
        } else {
            current_state.clone()
        };

        let (receipt_bytes, stitched_receipt_sigma): (Vec<u8>, [u8; 32]) =
            build_online_receipt_and_sigma(
                &sigma_state,
                &self.device_id_bytes,
                &recipient,
                crate::sdk::app_state::AppState::get_device_tree_root(),
            )
            .ok_or_else(|| {
                format!("{route}: failed to build canonical stitched receipt commitment")
            })?;

        Ok(DepositCompletionPrep {
            current_state,
            requester_key,
            signing_public_key,
            recipient,
            receipt_bytes,
            stitched_receipt_sigma,
            pre_applied_token_op,
            pre_applied_token_state,
        })
    }

    /// Generate a deterministic withdrawal ID for standalone (non-orchestrated) leg invocations.
    ///
    /// When a leg is dispatched by `execute_withdrawal_plan_internal`, the caller has already
    /// created a withdrawal record with `plan_id` as the key. When a leg is called directly
    /// (standalone, `plan_id` is empty), we generate a unique ID here so the in-flight
    /// withdrawal metadata row always has a non-empty, unique primary key.
    fn generate_standalone_withdrawal_id(device_str: &str, amount_sats: u64, dest: &str) -> String {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(device_str.as_bytes());
        preimage.extend_from_slice(&amount_sats.to_le_bytes());
        preimage.extend_from_slice(dest.as_bytes());
        preimage.extend_from_slice(&crate::util::deterministic_time::tick().to_le_bytes());
        let id_hash = dsm::crypto::blake3::domain_hash("DSM/withdrawal", &preimage);
        format!(
            "wd-{}",
            crate::util::text_id::encode_base32_crockford(&id_hash.as_bytes()[..16])
        )
    }

    async fn invoke_fractional_exit_internal(
        &self,
        req: generated::BitcoinFractionalExitRequest,
    ) -> Result<generated::BitcoinFractionalExitResponse, String> {
        #[cfg(test)]
        if let Some(result) =
            take_withdrawal_execution_test_result(WithdrawalExecutionTestRoute::Fractional, &req)
        {
            return result;
        }

        let env = decode_internal_envelope(
            Box::pin(self.handle_bitcoin_invoke(AppInvoke {
                method: "bitcoin.fractional.exit".to_string(),
                args: encode_proto_arg(&req),
            }))
            .await,
            "bitcoin.withdraw.execute/fractional",
        )?;

        match env.payload {
            Some(generated::envelope::Payload::BitcoinFractionalExitResponse(resp)) => Ok(resp),
            Some(generated::envelope::Payload::Error(err_payload)) => Err(err_payload.message),
            _ => {
                Err("bitcoin.withdraw.execute/fractional: unexpected response payload".to_string())
            }
        }
    }

    async fn invoke_full_sweep_internal(
        &self,
        req: generated::BitcoinFractionalExitRequest,
    ) -> Result<generated::BitcoinFractionalExitResponse, String> {
        #[cfg(test)]
        if let Some(result) =
            take_withdrawal_execution_test_result(WithdrawalExecutionTestRoute::Full, &req)
        {
            return result;
        }

        let env = decode_internal_envelope(
            Box::pin(self.handle_bitcoin_invoke(AppInvoke {
                method: "bitcoin.full.sweep".to_string(),
                args: encode_proto_arg(&req),
            }))
            .await,
            "bitcoin.withdraw.execute/full",
        )?;

        match env.payload {
            Some(generated::envelope::Payload::BitcoinFractionalExitResponse(resp)) => Ok(resp),
            Some(generated::envelope::Payload::Error(err_payload)) => Err(err_payload.message),
            _ => Err("bitcoin.withdraw.execute/full: unexpected response payload".to_string()),
        }
    }

    async fn execute_withdrawal_plan_internal(
        &self,
        req: generated::BitcoinWithdrawalExecuteRequest,
    ) -> Result<generated::BitcoinWithdrawalExecuteResponse, String> {
        const WITHDRAWAL_SUCCESSOR_LOCKTIME: u32 = 144;
        const WITHDRAWAL_REFUND_ITERATIONS: u64 = 10_000;

        self.ensure_withdrawal_bridge_sync("bitcoin.withdraw.execute")
            .await?;

        // Look up the cached plan (populated by bitcoin.withdraw.plan).
        // All routing data stays in Rust — frontend only sends plan_id + destination.
        let cached = self
            .take_cached_withdrawal_plan(&req.plan_id)
            .await
            .ok_or_else(|| {
                "bitcoin.withdraw.execute: plan not found or expired — review the withdrawal again"
                    .to_string()
            })?;

        let plan = cached.plan;

        if plan.plan_id.is_empty() || plan.legs.is_empty() {
            return Err(
                "bitcoin.withdraw.execute: cached plan has no executable route".to_string(),
            );
        }

        // Safety: verify the destination address matches what was planned.
        if cached.destination_address != req.destination_address {
            return Err(
                "bitcoin.withdraw.execute: destination address does not match the reviewed plan"
                    .to_string(),
            );
        }

        // Persist withdrawal execution metadata before broadcast so successful legs
        // can durably append their txids immediately.
        let withdrawal_id = {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(&self.device_id_bytes);
            preimage.extend_from_slice(&plan.requested_net_sats.to_le_bytes());
            preimage.extend_from_slice(req.destination_address.as_bytes());
            preimage.extend_from_slice(&crate::util::deterministic_time::tick().to_le_bytes());
            let id_hash = dsm::crypto::blake3::domain_hash("DSM/withdrawal", &preimage);
            format!(
                "wd-{}",
                crate::util::text_id::encode_base32_crockford(&id_hash.as_bytes()[..16])
            )
        };
        let device_id_str = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        // --- Bearer Fungibility: dBTC lock lifecycle ---
        // Individual leg handlers (bitcoin.fractional.exit, bitcoin.full.sweep) each
        // atomically lock their own burn amount (GROSS = net + fee) via lock_dbtc_for_exit.
        // The planner does NOT pre-lock here — doing so would double-lock because
        // invoke_{fractional,full}_internal re-enter the handler dispatch which has
        // its own lock_dbtc_for_exit call. Only the handler-level lock participates
        // in the finalize_exit_burn / release_locked_to_available lifecycle.
        //
        // Each handler burns the GROSS exit amount (net delivery + estimated Bitcoin tx fee)
        // because fees are lost BTC backing that must be matched by dBTC destruction.
        // Example: user requests 100,000 net → vault exits 104,700 gross → burns 104,700 dBTC,
        // miner takes ~4,700, user receives ~100,000 to their Bitcoin address.

        crate::storage::client_db::create_withdrawal(
            crate::storage::client_db::CreateWithdrawalParams {
                withdrawal_id: &withdrawal_id,
                device_id: &device_id_str,
                amount_sats: plan.requested_net_sats,
                dest_address: &req.destination_address,
                policy_commit: plan.policy_commit.as_slice(),
                state: "executing",
                burn_token_id: Some("dBTC"),
                burn_amount_sats: plan.total_gross_exit_sats,
            },
        )
        .map_err(|e| format!("withdrawal metadata init failed: {e}"))?;

        let mut executed_legs = Vec::with_capacity(plan.legs.len());
        let mut sweep_txids = Vec::with_capacity(plan.legs.len());
        for leg in &plan.legs {
            let route_result = match leg.kind {
                crate::sdk::bitcoin_tap_sdk::WithdrawalLegKind::Full => {
                    self.invoke_full_sweep_internal(generated::BitcoinFractionalExitRequest {
                        source_vault_id: leg.vault_id.clone(),
                        exit_amount_sats: 0,
                        successor_locktime: 0,
                        refund_iterations: 0,
                        destination_address: req.destination_address.clone(),
                        plan_id: withdrawal_id.clone(),
                    })
                    .await
                }
                crate::sdk::bitcoin_tap_sdk::WithdrawalLegKind::Partial => {
                    self.invoke_fractional_exit_internal(generated::BitcoinFractionalExitRequest {
                        source_vault_id: leg.vault_id.clone(),
                        exit_amount_sats: leg.gross_exit_sats,
                        successor_locktime: WITHDRAWAL_SUCCESSOR_LOCKTIME,
                        refund_iterations: WITHDRAWAL_REFUND_ITERATIONS,
                        destination_address: req.destination_address.clone(),
                        plan_id: withdrawal_id.clone(),
                    })
                    .await
                }
            };

            match route_result {
                Ok(resp) => {
                    let execution_leg = generated::BitcoinWithdrawalExecutionLeg {
                        vault_id: leg.vault_id.clone(),
                        kind: leg.kind.as_str().to_string(),
                        status: "broadcast".to_string(),
                        gross_exit_sats: leg.gross_exit_sats,
                        estimated_fee_sats: leg.estimated_fee_sats,
                        estimated_net_sats: leg.estimated_net_sats,
                        actual_remainder_sats: resp.remainder_sats,
                        successor_vault_id: resp.successor_vault_id,
                        successor_vault_op_id: resp.successor_vault_op_id,
                        exit_vault_op_id: resp.exit_vault_op_id,
                        sweep_txid: resp.sweep_txid,
                    };

                    let leg_index = executed_legs.len() as u32;
                    persist_withdrawal_leg(
                        &withdrawal_id,
                        leg_index,
                        &execution_leg.vault_id,
                        &execution_leg.kind,
                        execution_leg.gross_exit_sats,
                        execution_leg.estimated_fee_sats,
                        execution_leg.estimated_net_sats,
                        (!execution_leg.sweep_txid.is_empty()).then_some(execution_leg.sweep_txid.as_str()),
                        (!execution_leg.successor_vault_id.is_empty())
                            .then_some(execution_leg.successor_vault_id.as_str()),
                        (!execution_leg.successor_vault_op_id.is_empty())
                            .then_some(execution_leg.successor_vault_op_id.as_str()),
                        (!execution_leg.exit_vault_op_id.is_empty())
                            .then_some(execution_leg.exit_vault_op_id.as_str()),
                    )?;

                    // Mark vault as AwaitingSettlement to block grid routing
                    if let Err(e) = crate::storage::client_db::update_vault_record_state(
                        &leg.vault_id,
                        "AwaitingSettlement",
                    ) {
                        log::warn!(
                            "[bitcoin.withdraw.execute] vault {} AwaitingSettlement update failed: {e}",
                            leg.vault_id
                        );
                    }

                    if !execution_leg.sweep_txid.is_empty() {
                        sweep_txids.push(execution_leg.sweep_txid.clone());
                        crate::storage::client_db::set_withdrawal_redemption_txids(
                            &withdrawal_id,
                            &sweep_txids.join(","),
                            None,
                        )
                        .map_err(|e| format!("withdrawal txid persistence failed: {e}"))?;
                    }

                    executed_legs.push(execution_leg);
                }
                Err(message) => {
                    if executed_legs.is_empty() {
                        // Total failure: no legs executed, no handler-level locks were acquired.
                        // (Each handler's own lock_dbtc_for_exit already releases on failure.)
                        if let Err(e) = crate::storage::client_db::set_withdrawal_state(
                            &withdrawal_id,
                            "failed",
                        ) {
                            log::error!(
                                "[bitcoin.withdraw.execute] failed to mark ρ={} as failed: {e}",
                                withdrawal_id
                            );
                        }
                        log::info!(
                            "[bitcoin.withdraw.execute] total failure before durable execution, ρ={}",
                            withdrawal_id
                        );
                    } else {
                        if let Err(e) = crate::storage::client_db::set_withdrawal_state(
                            &withdrawal_id,
                            "committed",
                        ) {
                            log::error!(
                                "[bitcoin.withdraw.execute] failed to mark ρ={} as committed after partial execution: {e}",
                                withdrawal_id
                            );
                        }
                        log::warn!(
                            "[bitcoin.withdraw.execute] partial execution committed, ρ={} needs recovery",
                            withdrawal_id
                        );
                    }
                    #[allow(deprecated)]
                    return Ok(generated::BitcoinWithdrawalExecuteResponse {
                        plan_id: plan.plan_id,
                        plan_class: plan.plan_class,
                        status: if executed_legs.is_empty() {
                            "failed".to_string()
                        } else {
                            "committed".to_string()
                        },
                        message: if executed_legs.is_empty() {
                            message
                        } else {
                            format!(
                                "{}. {} leg(s) already broadcast; withdrawal remains committed for recovery.",
                                message,
                                executed_legs.len()
                            )
                        },
                        requested_net_sats: plan.requested_net_sats,
                        planned_net_sats: plan.planned_net_sats,
                        total_gross_exit_sats: plan.total_gross_exit_sats,
                        total_fee_sats: plan.total_fee_sats,
                        shortfall_sats: plan.shortfall_sats,
                        executed_legs,
                        blocked_vaults: plan
                            .blocked_vaults
                            .into_iter()
                            .map(|vault| generated::BitcoinWithdrawalBlockedVault {
                                vault_id: vault.vault_id,
                                amount_sats: vault.amount_sats,
                                reason: vault.reason,
                            })
                            .collect(),
                        route_commitment_id: vec![],
                        route_commitment_key: String::new(),
                    });
                }
            }
        }

        log::info!(
            "[bitcoin.withdraw.execute] all legs complete, \u{03c1}={} sweeps_broadcast (txids: {})",
            withdrawal_id,
            sweep_txids.join(",")
        );
        crate::storage::client_db::set_withdrawal_state(&withdrawal_id, "committed")
            .map_err(|e| format!("withdrawal commit transition failed: {e}"))?;

        #[allow(deprecated)]
        Ok(generated::BitcoinWithdrawalExecuteResponse {
            plan_id: plan.plan_id,
            plan_class: plan.plan_class,
            status: "committed".to_string(),
            message: format!(
                "Broadcast {} withdrawal leg(s). Final burn will complete after confirmation depth is reached.",
                executed_legs.len()
            ),
            requested_net_sats: plan.requested_net_sats,
            planned_net_sats: plan.planned_net_sats,
            total_gross_exit_sats: plan.total_gross_exit_sats,
            total_fee_sats: plan.total_fee_sats,
            shortfall_sats: plan.shortfall_sats,
            executed_legs,
            blocked_vaults: plan
                .blocked_vaults
                .into_iter()
                .map(|vault| generated::BitcoinWithdrawalBlockedVault {
                    vault_id: vault.vault_id,
                    amount_sats: vault.amount_sats,
                    reason: vault.reason,
                })
                .collect(),
            route_commitment_id: vec![],
            route_commitment_key: String::new(),
        })
    }

    async fn resolve_pending_withdrawals_with_client(
        &self,
        unresolved: &[crate::storage::client_db::InFlightWithdrawal],
        mempool: &super::mempool_api::MempoolClient,
        network: dsm::bitcoin::BitcoinNetwork,
        required: u64,
        log_prefix: &str,
    ) -> WithdrawalResolutionSummary {
        let mut summary = WithdrawalResolutionSummary::default();

        for wd in unresolved {
            let txid_csv = match &wd.redemption_txid {
                Some(txids) if !txids.is_empty() => txids.clone(),
                _ => {
                    summary.pending += 1;
                    continue;
                }
            };

            let txids: Vec<&str> = txid_csv.split(',').filter(|t| !t.is_empty()).collect();
            if txids.is_empty() {
                summary.pending += 1;
                continue;
            }

            let mut all_confirmed = true;
            for txid in &txids {
                match mempool.tx_status(txid).await {
                    Ok(status) if status.confirmed => {
                        let confs = if let Some(block_height) = status.block_height {
                            match mempool.chain_tip_height().await {
                                Ok(tip) => tip.saturating_sub(block_height) + 1,
                                Err(e) => {
                                    log::warn!(
                                        "[{}] chain_tip_height failed while resolving ρ={}: {}",
                                        log_prefix,
                                        wd.withdrawal_id,
                                        e
                                    );
                                    all_confirmed = false;
                                    continue;
                                }
                            }
                        } else {
                            1
                        };
                        let observation = BitcoinSettlementObservation {
                            network,
                            bitcoin_spend_observed: true,
                            confirmation_depth: confs,
                            min_confirmations: required,
                        };
                        if !observation.meets_confirmation_gate() {
                            all_confirmed = false;
                        }
                    }
                    Ok(_) => {
                        all_confirmed = false;
                    }
                    Err(e) => {
                        log::warn!(
                            "[{}] tx_status({}) unavailable for ρ={}: {}",
                            log_prefix,
                            txid,
                            wd.withdrawal_id,
                            e
                        );
                        all_confirmed = false;
                    }
                }
            }

            if all_confirmed {
                let expected_policy_commit =
                    match decode_policy_commit(log_prefix, "persisted withdrawal", &wd.policy_commit)
                    {
                        Ok(policy_commit) => policy_commit,
                        Err(message) => {
                            log::warn!("[{}] ρ={} {}", log_prefix, wd.withdrawal_id, message);
                            summary.pending += 1;
                            continue;
                        }
                    };
                let legs =
                    match crate::storage::client_db::list_withdrawal_legs(&wd.withdrawal_id) {
                        Ok(legs) if !legs.is_empty() => legs,
                        Ok(_) => {
                            log::warn!(
                                "[{}] ρ={} has no persisted withdrawal legs; refusing finalization without source policy metadata",
                                log_prefix,
                                wd.withdrawal_id
                            );
                            summary.pending += 1;
                            continue;
                        }
                        Err(e) => {
                            log::warn!(
                                "[{}] failed to load withdrawal legs for ρ={}: {}",
                                log_prefix,
                                wd.withdrawal_id,
                                e
                            );
                            summary.pending += 1;
                            continue;
                        }
                    };
                let mut policy_mismatch = false;
                for leg in &legs {
                    let exec_data = match self.bitcoin_tap.fetch_vault_execution_data(&leg.vault_id).await {
                        Ok(exec_data) => exec_data,
                        Err(e) => {
                            log::warn!(
                                "[{}] failed to fetch execution data for vault {} while finalizing ρ={}: {}",
                                log_prefix,
                                leg.vault_id,
                                wd.withdrawal_id,
                                e
                            );
                            policy_mismatch = true;
                            break;
                        }
                    };
                    if let Err(message) = ensure_policy_commit_match(
                        log_prefix,
                        &format!("withdrawal leg {}", leg.vault_id),
                        &expected_policy_commit,
                        &exec_data.policy_commit,
                    ) {
                        log::warn!("[{}] ρ={} {}", log_prefix, wd.withdrawal_id, message);
                        policy_mismatch = true;
                        break;
                    }
                }
                if policy_mismatch {
                    summary.pending += 1;
                    continue;
                }

                // ATOMIC STATE GUARD: re-read state to prevent double-burn if
                // the settlement poller fires twice in rapid succession.
                let current_state = crate::storage::client_db::get_withdrawal(&wd.withdrawal_id)
                    .ok()
                    .flatten()
                    .map(|w| w.state);
                if current_state.as_deref() != Some("committed") {
                    log::warn!(
                        "[{}] ρ={} state is {:?}, expected committed — skipping (race guard)",
                        log_prefix,
                        wd.withdrawal_id,
                        current_state
                    );
                    summary.pending += 1;
                    continue;
                }

                // Deferred burn: execute the token burn now that d_min is reached.
                // dBTC §13.1 Property 8: finality only at settlement depth.
                if wd.burn_amount_sats > 0 {
                    let dbtc_id = wd.burn_token_id.as_deref().unwrap_or("dBTC");
                    let dev_str = &wd.device_id;

                    // Seed in-memory balance from SQLite
                    let current = crate::storage::client_db::get_token_balance(dev_str, dbtc_id)
                        .ok()
                        .flatten()
                        .map(|(a, l)| a + l)
                        .unwrap_or(0);
                    if let Err(e) = self.wallet.seed_token_balance_for_self(dbtc_id, current) {
                        log::error!(
                            "[{}] deferred burn seed failed for ρ={}: {} — keeping pending",
                            log_prefix,
                            wd.withdrawal_id,
                            e
                        );
                        summary.pending += 1;
                        continue;
                    }

                    let burn_op = dsm::types::token_types::TokenOperation::Burn {
                        token_id: dbtc_id.to_string(),
                        amount: wd.burn_amount_sats,
                    };
                    match self.wallet.execute_token_operation(burn_op).await {
                        Ok(applied) => {
                            if applied.hash.len() == 32 {
                                let _ = crate::get_sdk_context()
                                    .update_chain_tip(applied.hash.to_vec());
                            }
                            let _ = crate::storage::client_db::finalize_exit_burn(
                                dev_str,
                                dbtc_id,
                                wd.burn_amount_sats,
                            );
                            log::info!(
                                "[{}] deferred burn OK for ρ={}: {} sats of {}",
                                log_prefix,
                                wd.withdrawal_id,
                                wd.burn_amount_sats,
                                dbtc_id
                            );
                        }
                        Err(e) => {
                            log::error!(
                                "[{}] deferred burn FAILED for ρ={}: {} — keeping pending",
                                log_prefix,
                                wd.withdrawal_id,
                                e
                            );
                            summary.pending += 1;
                            continue;
                        }
                    }
                }

                if let Err(e) = crate::storage::client_db::finalize_withdrawal(&wd.withdrawal_id) {
                    log::error!(
                        "[{}] failed to mark ρ={} as finalized: {}",
                        log_prefix,
                        wd.withdrawal_id,
                        e
                    );
                    summary.pending += 1;
                    continue;
                }
                log::info!(
                    "[{}] finalized ρ={} (all recorded txids at d_min)",
                    log_prefix,
                    wd.withdrawal_id
                );

                // Flip successor vault advertisements to green (routeable).
                // After settlement, each leg's successor vault has confirmed burial
                // and should be advertised as available liquidity.
                for leg in &legs {
                    if let Some(ref succ_vault_id) = leg.successor_vault_id {
                        if let Err(e) = self
                            .bitcoin_tap
                            .publish_vault_advertisement(succ_vault_id, &self.device_id_bytes)
                            .await
                        {
                            log::warn!(
                                "[{}] successor ad re-publish for {} failed: {}",
                                log_prefix,
                                succ_vault_id,
                                e
                            );
                        } else {
                            log::info!(
                                "[{}] re-advertised successor vault {} as routeable",
                                log_prefix,
                                succ_vault_id
                            );
                        }
                    }

                    // Prune spent source vault from storage nodes.
                    // Finalization is terminal — the UTXO is buried, no one
                    // needs the source advertisement anymore.
                    if let Err(e) = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::delete_vault_from_storage_nodes(
                        &leg.vault_id,
                    ).await {
                        log::warn!(
                            "[{}] vault prune failed for {}: {}",
                            log_prefix,
                            leg.vault_id,
                            e
                        );
                    }
                }

                summary.finalized += 1;
            } else {
                // Not yet confirmed — increment poll counter and check for refund threshold.
                let poll_count =
                    crate::storage::client_db::increment_settlement_poll_count(&wd.withdrawal_id)
                        .unwrap_or(0);

                if poll_count > crate::sdk::bitcoin_tap_sdk::DBTC_MAX_SETTLEMENT_POLLS {
                    log::warn!(
                        "[{}] ρ={} exceeded settlement poll budget; leaving withdrawal in committed state pending explicit failure or later settlement",
                        log_prefix,
                        wd.withdrawal_id
                    );
                }

                summary.pending += 1;
            }
        }

        summary
    }

    pub(crate) async fn handle_bitcoin_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "bitcoin.wallet.import" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinWalletImportRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinWalletImportRequest failed: {e}")),
                };

                let import_kind = req.import_kind.trim().to_ascii_lowercase();
                if !matches!(import_kind.as_str(), "wif" | "xpriv" | "mnemonic") {
                    return err(format!(
                        "bitcoin.wallet.import: import_kind must be one of wif|xpriv|mnemonic (got '{}')",
                        req.import_kind
                    ));
                }
                if req.secret.trim().is_empty() {
                    return err("bitcoin.wallet.import: secret is required".to_string());
                }

                let network = Self::bitcoin_network_from_u32(req.network);
                // WIF has exactly one address; start_index is not meaningful for WIF.
                let start_index = if import_kind == "wif" {
                    0u32
                } else {
                    req.start_index
                };
                let first_address = if import_kind == "wif" || start_index == 0 {
                    match Self::first_address_for_import(&import_kind, &req.secret, network) {
                        Ok(a) => a,
                        Err(e) => return err(format!("bitcoin.wallet.import failed: {e}")),
                    }
                } else {
                    // HD wallet with non-zero start_index: derive address at requested index.
                    let ks = match Self::keystore_from_import(&import_kind, &req.secret, network) {
                        Ok(k) => k,
                        Err(e) => return err(format!("bitcoin.wallet.import failed: {e}")),
                    };
                    match ks.peek_receive_address(start_index) {
                        Ok((addr, _)) => addr,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.wallet.import: start_index {} is out of range: {e}",
                                start_index
                            ))
                        }
                    }
                };

                let account_id = Self::bitcoin_account_id(&import_kind, &req.secret, req.network);
                let now = crate::util::deterministic_time::tick();
                let account = crate::storage::client_db::BitcoinAccountRecord {
                    account_id: account_id.clone(),
                    label: if req.label.trim().is_empty() {
                        format!("{} account", import_kind)
                    } else {
                        req.label.clone()
                    },
                    import_kind: import_kind.clone(),
                    secret_material: req.secret.as_bytes().to_vec(),
                    network: req.network,
                    first_address: Some(first_address.clone()),
                    active: true,
                    active_receive_index: start_index,
                    created_at: now,
                    updated_at: now,
                };

                if let Err(e) = crate::storage::client_db::upsert_bitcoin_account(&account) {
                    return err(format!(
                        "bitcoin.wallet.import failed to persist account: {e}"
                    ));
                }
                if let Err(e) = crate::storage::client_db::set_active_bitcoin_account(&account_id) {
                    return err(format!(
                        "bitcoin.wallet.import failed to activate account: {e}"
                    ));
                }

                if import_kind != "wif" {
                    let keystore =
                        match Self::keystore_from_import(&import_kind, &req.secret, network) {
                            Ok(k) => k,
                            Err(e) => return err(format!("bitcoin.wallet.import failed: {e}")),
                        };
                    let mut keys = self.bitcoin_keys.lock().await;
                    *keys = keystore;
                }

                pack_envelope_ok(generated::envelope::Payload::BitcoinWalletImportResponse(
                    generated::BitcoinWalletImportResponse {
                        success: true,
                        account_id,
                        message: if import_kind == "wif" {
                            format!(
                                "Imported WIF account ({first_address}). Address tracking enabled; HTLC signing path still requires xpriv/mnemonic."
                            )
                        } else {
                            format!("Imported and activated account ({first_address})")
                        },
                    },
                ))
            }

            "bitcoin.wallet.create" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinWalletCreateRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinWalletCreateRequest failed: {e}")),
                };

                // Generate cryptographically random entropy (32 bytes → 24 words).
                // 16 bytes → 12 words if word_count == 12.
                let entropy_len: usize = if req.word_count == 12 { 16 } else { 32 };
                let mut entropy = vec![0u8; entropy_len];
                rand::rngs::OsRng.fill_bytes(&mut entropy);
                // Ensure entropy is non-zero (astronomically unlikely, but guard anyway).
                if entropy.iter().all(|&b| b == 0) {
                    return err(
                        "bitcoin.wallet.create: entropy generation produced all-zero bytes"
                            .to_string(),
                    );
                }

                let mnemonic = match bip39::Mnemonic::from_entropy(&entropy) {
                    Ok(m) => m,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.wallet.create: BIP39 generation failed: {e}"
                        ))
                    }
                };
                let mnemonic_phrase = mnemonic.to_string();

                let network = Self::bitcoin_network_from_u32(req.network);
                let first_address =
                    match Self::first_address_for_import("mnemonic", &mnemonic_phrase, network) {
                        Ok(a) => a,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.wallet.create: address derivation failed: {e}"
                            ))
                        }
                    };

                let label = if req.label.trim().is_empty() {
                    let net_str = match req.network {
                        0 => "mainnet",
                        1 => "testnet",
                        2 => "signet",
                        _ => "signet",
                    };
                    format!("New wallet ({})", net_str)
                } else {
                    req.label.clone()
                };

                let account_id =
                    Self::bitcoin_account_id("mnemonic", &mnemonic_phrase, req.network);
                let now = crate::util::deterministic_time::tick();
                let account = crate::storage::client_db::BitcoinAccountRecord {
                    account_id: account_id.clone(),
                    label,
                    import_kind: "mnemonic".to_string(),
                    secret_material: mnemonic_phrase.as_bytes().to_vec(),
                    network: req.network,
                    first_address: Some(first_address.clone()),
                    active: true,
                    active_receive_index: 0,
                    created_at: now,
                    updated_at: now,
                };

                if let Err(e) = crate::storage::client_db::upsert_bitcoin_account(&account) {
                    return err(format!(
                        "bitcoin.wallet.create failed to persist account: {e}"
                    ));
                }
                if let Err(e) = crate::storage::client_db::set_active_bitcoin_account(&account_id) {
                    return err(format!(
                        "bitcoin.wallet.create failed to activate account: {e}"
                    ));
                }

                let keystore =
                    match Self::keystore_from_import("mnemonic", &mnemonic_phrase, network) {
                        Ok(k) => k,
                        Err(e) => return err(format!("bitcoin.wallet.create failed: {e}")),
                    };
                let mut keys = self.bitcoin_keys.lock().await;
                *keys = keystore;

                pack_envelope_ok(generated::envelope::Payload::BitcoinWalletCreateResponse(
                    generated::BitcoinWalletCreateResponse {
                        success: true,
                        account_id,
                        mnemonic: mnemonic_phrase,
                        first_address,
                        message:
                            "Wallet created. Back up your mnemonic — it will not be shown again."
                                .to_string(),
                    },
                ))
            }

            "bitcoin.wallet.select" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinWalletSelectRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinWalletSelectRequest failed: {e}")),
                };
                if req.account_id.trim().is_empty() {
                    return err("bitcoin.wallet.select: account_id is required".to_string());
                }

                let account = match crate::storage::client_db::get_bitcoin_account(&req.account_id)
                {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        return err(format!(
                            "bitcoin.wallet.select: unknown account_id '{}'",
                            req.account_id
                        ))
                    }
                    Err(e) => return err(format!("bitcoin.wallet.select failed: {e}")),
                };

                if let Err(e) =
                    crate::storage::client_db::set_active_bitcoin_account(&account.account_id)
                {
                    return err(format!("bitcoin.wallet.select failed: {e}"));
                }

                if account.import_kind != "wif" {
                    let secret = String::from_utf8(account.secret_material).map_err(|_| {
                        "bitcoin.wallet.select: secret material is not UTF-8".to_string()
                    });
                    let secret = match secret {
                        Ok(s) => s,
                        Err(e) => return err(e),
                    };
                    let network = Self::bitcoin_network_from_u32(account.network);
                    let keystore =
                        match Self::keystore_from_import(&account.import_kind, &secret, network) {
                            Ok(mut k) => {
                                // Restore persisted address index to prevent Index-0 Trap.
                                k.set_receive_index(account.active_receive_index);
                                k
                            }
                            Err(e) => return err(format!("bitcoin.wallet.select failed: {e}")),
                        };
                    let mut keys = self.bitcoin_keys.lock().await;
                    *keys = keystore;
                }

                pack_envelope_ok(generated::envelope::Payload::BitcoinWalletSelectResponse(
                    generated::BitcoinWalletSelectResponse {
                        success: true,
                        active_account_id: account.account_id,
                        message: "Bitcoin account activated".to_string(),
                    },
                ))
            }

            // -------- Bitcoin address index selection (mutation) --------
            "bitcoin.address.select" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinAddressSelectRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!("decode BitcoinAddressSelectRequest failed: {e}"))
                    }
                };

                match crate::storage::client_db::get_active_bitcoin_account() {
                    Ok(Some(active_account)) => {
                        if active_account.import_kind == "wif" {
                            return err("bitcoin.address.select: WIF accounts have a single address; index selection is not supported".into());
                        }
                        let secret = match String::from_utf8(active_account.secret_material.clone())
                        {
                            Ok(s) => s,
                            Err(_) => {
                                return err("bitcoin.address.select: secret is not UTF-8".into())
                            }
                        };
                        let network = Self::bitcoin_network_from_u32(active_account.network);
                        let ks = match Self::keystore_from_import(
                            &active_account.import_kind,
                            &secret,
                            network,
                        ) {
                            Ok(k) => k,
                            Err(e) => return err(format!("bitcoin.address.select: {e}")),
                        };
                        let (address, pk) = match ks.peek_receive_address(req.index) {
                            Ok(pair) => pair,
                            Err(e) => {
                                return err(format!(
                                    "bitcoin.address.select: index {} out of range: {e}",
                                    req.index
                                ))
                            }
                        };
                        if let Err(e) = crate::storage::client_db::set_active_receive_index(
                            &active_account.account_id,
                            req.index,
                        ) {
                            return err(format!(
                                "bitcoin.address.select: failed to persist index: {e}"
                            ));
                        }
                        log::info!(
                            "[bitcoin.address.select] account={} index={} address={}…",
                            active_account.account_id,
                            req.index,
                            &address[..address.len().min(12)]
                        );
                        pack_envelope_ok(
                            generated::envelope::Payload::BitcoinAddressSelectResponse(
                                generated::BitcoinAddressSelectResponse {
                                    success: true,
                                    address,
                                    index: req.index,
                                    compressed_pubkey: pk.to_vec(),
                                },
                            ),
                        )
                    }
                    Ok(None) => err("bitcoin.address.select: no Bitcoin account imported.".into()),
                    Err(e) => err(format!("bitcoin.address.select: DB error: {e}")),
                }
            }

            "bitcoin.deposit.initiate" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::DepositRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DepositRequest failed: {e}")),
                };
                let current_state = match self.core_sdk.get_current_state() {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!("bitcoin.deposit.initiate: state unavailable: {e}"))
                    }
                };
                let (creator_pk, creator_sk) = match self.wallet.get_signing_keypair() {
                    Ok(k) => k,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.initiate: wallet signing key unavailable: {e}"
                        ))
                    }
                };
                let kem_public_key = match self.wallet.get_kyber_public_key() {
                    Ok(k) => k,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.initiate: wallet Kyber key unavailable: {e}"
                        ))
                    }
                };
                let network = crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network();

                let mut keys = self.bitcoin_keys.lock().await;
                let (_addr, _idx, local_btc_pubkey) = match keys.next_receive_address() {
                    Ok(v) => v,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.initiate: bitcoin address derivation failed: {e}"
                        ))
                    }
                };
                // Persist the advanced receive index so balance scans survive restarts.
                {
                    let new_idx = keys.current_receive_index();
                    if let Ok(Some(acc)) = crate::storage::client_db::get_active_bitcoin_account() {
                        if let Err(e) = crate::storage::client_db::set_active_receive_index(
                            &acc.account_id,
                            new_idx,
                        ) {
                            log::warn!("[bitcoin.deposit.initiate] failed to persist receive_index {new_idx}: {e}");
                        }
                    }
                }
                drop(keys);

                let direction = req.direction.trim().to_ascii_lowercase();
                if direction == "btc_to_dbtc" || direction == "btc_to_dsm" {
                    let btc_pubkey = if req.btc_pubkey.len() == 33 {
                        req.btc_pubkey.as_slice()
                    } else {
                        local_btc_pubkey.as_ref()
                    };

                    match self
                        .bitcoin_tap
                        .open_tap(
                            req.btc_amount_sats,
                            btc_pubkey,
                            req.refund_iterations.max(1),
                            (&creator_pk, &creator_sk),
                            &current_state,
                            network,
                            kem_public_key.as_slice(),
                        )
                        .await
                    {
                        Ok(init) => {
                            let htlc_address_str = init.htlc_address.clone().unwrap_or_default();
                            let resp = generated::DepositResponse {
                                vault_op_id: init.vault_op_id,
                                status: "initiated".to_string(),
                                vault_id: init.vault_id,
                                external_commitment: init.external_commitment.to_vec(),
                                hash_lock: init.hash_lock.to_vec(),
                                htlc_script: init.htlc_script.unwrap_or_default(),
                                htlc_address: htlc_address_str.clone(),
                                message: "BTC→dBTC deposit initiated".to_string(),
                                funding_txid: String::new(),
                            };

                            pack_envelope_ok(generated::envelope::Payload::DepositResponse(resp))
                        }
                        Err(e) => err(format!("bitcoin.deposit.initiate failed: {e}")),
                    }
                } else {
                    err(format!(
                        "bitcoin.deposit.initiate: unsupported direction '{}'",
                        req.direction
                    ))
                }
            }

            "bitcoin.deposit.complete" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::DepositCompleteRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DepositCompleteRequest failed: {e}")),
                };
                if req.preimage.is_empty() {
                    return err("bitcoin.deposit.complete: preimage is required".to_string());
                }
                if req.bitcoin_txid.len() != 32 {
                    return err(format!(
                        "bitcoin.deposit.complete: bitcoin_txid must be 32 bytes (got {})",
                        req.bitcoin_txid.len()
                    ));
                }
                if req.block_header.len() != 80 {
                    return err(format!(
                        "bitcoin.deposit.complete: block_header must be 80 bytes (got {})",
                        req.block_header.len()
                    ));
                }
                if req.bitcoin_tx_raw.is_empty() {
                    return err("bitcoin.deposit.complete: bitcoin_tx_raw is required".to_string());
                }

                let mut bitcoin_txid = [0u8; 32];
                bitcoin_txid.copy_from_slice(&req.bitcoin_txid);
                let mut block_header = [0u8; 80];
                block_header.copy_from_slice(&req.block_header);

                let mut header_chain: Vec<[u8; 80]> = Vec::with_capacity(req.header_chain.len());
                for (idx, h) in req.header_chain.iter().enumerate() {
                    if h.len() != 80 {
                        return err(format!(
                            "bitcoin.deposit.complete: header_chain[{idx}] must be 80 bytes (got {})",
                            h.len()
                        ));
                    }
                    let mut arr = [0u8; 80];
                    arr.copy_from_slice(h);
                    header_chain.push(arr);
                }

                let deposit_record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await
                {
                    Ok(record) => record,
                    Err(e) => return err(format!("bitcoin.deposit.complete: {e}")),
                };
                if deposit_record.direction
                    == crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc
                {
                    return err(
                        "bitcoin.deposit.complete no longer supports dbtc_to_btc exits; use the planner-driven withdrawal flow"
                            .to_string(),
                    );
                }

                let recipient: [u8; 32] = if req.recipient_device_id.len() == 32 {
                    let mut r = [0u8; 32];
                    r.copy_from_slice(&req.recipient_device_id);
                    r
                } else {
                    self.device_id_bytes
                };

                let prep = match self
                    .prepare_deposit_completion_prep(
                        "bitcoin.deposit.complete",
                        &req.vault_op_id,
                        recipient,
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return err(e),
                };

                match self
                    .bitcoin_tap
                    .draw_tap(
                        &req.vault_op_id,
                        &req.preimage,
                        bitcoin_txid,
                        &req.bitcoin_tx_raw,
                        &req.spv_proof,
                        block_header,
                        &header_chain,
                        &prep.requester_key,
                        &prep.signing_public_key,
                        prep.recipient,
                        &prep.current_state,
                        Some(prep.receipt_bytes),
                        Some(prep.stitched_receipt_sigma),
                    )
                    .await
                {
                    Ok(completion) => {
                        // Apply DLV unlock operation only for withdrawals (dBTC→BTC).
                        // Deposits produce None — vault is only activated, not unlocked.
                        if let Some(unlock_op) = completion.dlv_unlock_operation.clone() {
                            let signed_unlock_op =
                                match self.core_sdk.sign_operation_sphincs(unlock_op) {
                                    Ok(op) => op,
                                    Err(e) => {
                                        return err(format!(
                                    "bitcoin.deposit.complete: failed to sign DLV unlock op: {e}"
                                ))
                                    }
                                };
                            let unlock_applied_state =
                                match self.core_sdk.execute_dsm_operation(signed_unlock_op) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        return err(format!(
                                    "bitcoin.deposit.complete: failed to apply DLV unlock op: {e}"
                                ))
                                    }
                                };
                            if unlock_applied_state.hash.len() == 32 {
                                if let Err(e) = crate::get_sdk_context()
                                    .update_chain_tip(unlock_applied_state.hash.to_vec())
                                {
                                    log::warn!(
                                        "bitcoin.deposit.complete: failed to update chain_tip after DLV unlock: {}",
                                        e
                                    );
                                }
                            }
                        }

                        let (effective_token_op, applied_state) = if let (Some(op), Some(state)) = (
                            prep.pre_applied_token_op.clone(),
                            prep.pre_applied_token_state.clone(),
                        ) {
                            (op, state)
                        } else {
                            let completion_op = completion.token_operation.clone();
                            let applied_state = match self
                                .wallet
                                .execute_token_operation(completion_op.clone())
                                .await
                            {
                                Ok(s) => s,
                                Err(e) => {
                                    return err(format!(
                                    "bitcoin.deposit.complete: token accounting apply failed: {e}"
                                ))
                                }
                            };

                            if applied_state.hash.len() == 32 {
                                if let Err(e) = crate::get_sdk_context()
                                    .update_chain_tip(applied_state.hash.to_vec())
                                {
                                    log::warn!(
                                            "bitcoin.deposit.complete: failed to update SDK_CONTEXT chain_tip: {}",
                                            e
                                        );
                                }
                            }

                            (completion_op, applied_state)
                        };

                        // Sync dBTC balance to SQLite using SQLite-authoritative arithmetic.
                        // The in-memory wallet value is stale when dBTC was received via bilateral
                        // transfer (bilateral recv updates SQLite only, not the in-memory wallet).
                        // Reading wallet.get_balance() here would overwrite the correct SQLite
                        // balance with 0 and zero out a bilaterally-received dBTC balance.
                        {
                            let dev = crate::util::text_id::encode_base32_crockford(
                                &self.device_id_bytes,
                            );
                            let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;
                            let (current_sqlite, existing_locked) =
                                match crate::storage::client_db::get_token_balance(&dev, dbtc_id) {
                                    Ok(Some((a, l))) => (a, l),
                                    Ok(None) => (0, 0),
                                    Err(e) => {
                                        return err(format!(
                                            "bitcoin.deposit.complete: failed to read dBTC balance: {e}"
                                        ));
                                    }
                                };
                            let new_sqlite = match &effective_token_op {
                                dsm::types::token_types::TokenOperation::Burn {
                                    amount, ..
                                } => {
                                    if current_sqlite < *amount {
                                        return err(format!(
                                            "bitcoin.deposit.complete: sqlite underflow guard hit: current={} burn={}",
                                            current_sqlite,
                                            amount
                                        ));
                                    }
                                    current_sqlite - *amount
                                }
                                dsm::types::token_types::TokenOperation::Mint {
                                    amount, ..
                                } => current_sqlite.saturating_add(*amount),
                                _ => current_sqlite,
                            };
                            if let Err(e) = crate::storage::client_db::upsert_token_balance(
                                &dev,
                                dbtc_id,
                                new_sqlite,
                                existing_locked,
                            ) {
                                return err(format!(
                                    "bitcoin.deposit.complete: failed to persist dBTC balance: {e}"
                                ));
                            }
                            log::info!("[bitcoin.deposit.complete] dBTC SQLite balance: {current_sqlite} → {new_sqlite}");
                        }

                        // Record the dBTC mint/burn in SQLite transaction history
                        // so it appears in wallet.history alongside ERA transfers.
                        {
                            let my_device_id_str = crate::util::text_id::encode_base32_crockford(
                                &self.device_id_bytes,
                            );
                            let (tx_type_str, token_id, amount, from_dev, to_dev) =
                                match &effective_token_op {
                                    dsm::types::token_types::TokenOperation::Mint {
                                        amount,
                                        ..
                                    } => (
                                        "dbtc_mint",
                                        "dBTC",
                                        *amount,
                                        "BITCOIN_NETWORK".to_string(),
                                        my_device_id_str.clone(),
                                    ),
                                    dsm::types::token_types::TokenOperation::Burn {
                                        amount,
                                        ..
                                    } => (
                                        "dbtc_burn",
                                        "dBTC",
                                        *amount,
                                        my_device_id_str.clone(),
                                        "BITCOIN_NETWORK".to_string(),
                                    ),
                                    _ => ("token_op", "dBTC", 0, String::new(), String::new()),
                                };
                            let tx_hash_txt =
                                crate::util::text_id::encode_base32_crockford(&applied_state.hash);
                            let mut metadata = std::collections::HashMap::new();
                            metadata.insert(
                                "vault_op_id".to_string(),
                                completion.vault_op_id.as_bytes().to_vec(),
                            );
                            metadata.insert("token_id".to_string(), token_id.as_bytes().to_vec());
                            let rec = crate::storage::client_db::TransactionRecord {
                                tx_id: format!("deposit_{}", completion.vault_op_id),
                                tx_hash: tx_hash_txt,
                                from_device: from_dev,
                                to_device: to_dev,
                                amount,
                                tx_type: tx_type_str.to_string(),
                                status: "completed".to_string(),
                                chain_height: applied_state.state_number,
                                step_index: 0,
                                commitment_hash: Some(applied_state.hash.to_vec()),
                                proof_data: build_online_receipt(
                                    &applied_state,
                                    &self.device_id_bytes,
                                    &self.device_id_bytes,
                                    crate::sdk::app_state::AppState::get_device_tree_root(),
                                ),
                                metadata,
                                created_at: crate::util::deterministic_time::tick(),
                            };
                            if let Err(e) = crate::storage::client_db::store_transaction(&rec) {
                                log::warn!(
                                    "bitcoin.deposit.complete: failed to record tx history: {e}"
                                );
                            }
                        }

                        // Store entry_txid as raw bytes (§8 Definition 9) before vault publication
                        if let Err(e) = crate::storage::client_db::update_vault_record_entry_txid(
                            &req.vault_op_id,
                            &bitcoin_txid,
                        ) {
                            log::warn!(
                                "[bitcoin.deposit.complete] failed to store entry_txid: {e}"
                            );
                        }
                        self.bitcoin_tap
                            .update_vault_record_entry_txid_in_memory(
                                &req.vault_op_id,
                                bitcoin_txid.to_vec(),
                            )
                            .await;

                        // dBTC §4 step 8: re-publish vault advertisement to storage nodes
                        // now that the vault is Active with entry_txid + htlc_address populated.
                        // open_tap() published early (PendingActive, no entry_txid); draw_tap()
                        // activates but does not re-publish. Without this, other bearers see a
                        // vault with empty entry_txid and cannot verify UTXO liveness (Definition 7).
                        if let Err(e) = self
                            .bitcoin_tap
                            .publish_vault_advertisement_mandatory(&completion.vault_id)
                            .await
                        {
                            log::error!(
                                "[bitcoin.deposit.complete] CRITICAL: failed to re-publish vault ad \
                                 after activation for vault {}: {e}",
                                &completion.vault_id[..completion.vault_id.len().min(12)],
                            );
                            // Don't return error — vault is activated and dBTC minted,
                            // but discovery is degraded until next refresh.
                        }

                        let (status, hash_lock, htlc_script, htlc_address, external_commitment) =
                            match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                                Ok(record) => {
                                    let status = match record.state {
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Initiated => {
                                            "initiated"
                                        }
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation => {
                                            "awaiting_confirmation"
                                        }
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Claimable => {
                                            "claimable"
                                        }
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Completed => {
                                            "completed"
                                        }
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Expired => "expired",
                                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Refunded => "refunded",
                                    }
                                    .to_string();
                                    (
                                        status,
                                        record.hash_lock.to_vec(),
                                        record.htlc_script.unwrap_or_default(),
                                        record.htlc_address.unwrap_or_default(),
                                        record
                                            .external_commitment
                                            .map(|c| c.to_vec())
                                            .unwrap_or_default(),
                                    )
                                }
                                Err(_) => (
                                    "completed".to_string(),
                                    vec![],
                                    vec![],
                                    String::new(),
                                    vec![],
                                ),
                            };

                        let op_label = match effective_token_op {
                            dsm::types::token_types::TokenOperation::Mint { .. } => "mint",
                            dsm::types::token_types::TokenOperation::Burn { .. } => "burn",
                            _ => "token-op",
                        };

                        let resp = generated::DepositResponse {
                            vault_op_id: completion.vault_op_id,
                            status,
                            vault_id: completion.vault_id,
                            external_commitment,
                            hash_lock,
                            htlc_script,
                            htlc_address,
                            message: format!(
                                "Deposit completed. Applied {op_label} operation; dBTC accounting finalized."
                            ),
                            funding_txid: String::new(),
                        };
                        pack_envelope_ok(generated::envelope::Payload::DepositResponse(resp))
                    }
                    Err(e) => err(format!("bitcoin.deposit.complete failed: {e}")),
                }
            }

            "bitcoin.deposit.refund" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::DepositRefundRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode DepositRefundRequest failed: {e}")),
                };
                let current_state = match self.core_sdk.get_current_state() {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!("bitcoin.deposit.refund: state unavailable: {e}"))
                    }
                };
                let (_creator_pk, creator_sk) = match self.wallet.get_signing_keypair() {
                    Ok(k) => k,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.refund: wallet signing key unavailable: {e}"
                        ))
                    }
                };

                match self
                    .bitcoin_tap
                    .close_tap(&req.vault_op_id, &creator_sk, &current_state)
                    .await
                {
                    Ok(restore_op) => {
                        // Execute the Unlock token operation to restore locked dBTC
                        if let Some(op) = restore_op {
                            match self.wallet.execute_token_operation(op.clone()).await {
                                Ok(applied_state) => {
                                    if applied_state.hash.len() == 32 {
                                        if let Err(e) = crate::get_sdk_context()
                                            .update_chain_tip(applied_state.hash.to_vec())
                                        {
                                            log::warn!("[bitcoin.deposit.refund] update_chain_tip failed: {e}");
                                        }
                                    }
                                    // Sync dBTC balance to SQLite (authoritative for bilateral debit path)
                                    {
                                        let dev = crate::util::text_id::encode_base32_crockford(
                                            &self.device_id_bytes,
                                        );
                                        let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;
                                        if let Ok(bal) = self.wallet.get_balance(Some(dbtc_id)) {
                                            if let Err(e) =
                                                crate::storage::client_db::upsert_token_balance(
                                                    &dev,
                                                    dbtc_id,
                                                    bal.available(),
                                                    bal.locked(),
                                                )
                                            {
                                                log::error!("[bitcoin.deposit.refund] CRITICAL: failed to persist dBTC balance: {e}");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!(
                                        "[bitcoin.deposit.refund] unlock token op failed: {e}"
                                    );
                                    return err(format!(
                                        "bitcoin.deposit.refund: unlock failed: {e}"
                                    ));
                                }
                            }
                        }

                        let resp = generated::DepositResponse {
                            vault_op_id: req.vault_op_id,
                            status: "refunded".to_string(),
                            vault_id: String::new(),
                            external_commitment: vec![],
                            hash_lock: vec![],
                            htlc_script: vec![],
                            htlc_address: String::new(),
                            message: "Deposit refunded, dBTC restored".to_string(),
                            funding_txid: String::new(),
                        };
                        pack_envelope_ok(generated::envelope::Payload::DepositResponse(resp))
                    }
                    Err(e) => err(format!("bitcoin.deposit.refund failed: {e}")),
                }
            }

            "bitcoin.claim.build" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinClaimTxRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinClaimTxRequest failed: {e}")),
                };
                if req.vault_op_id.trim().is_empty() {
                    return err("bitcoin.claim.build: vault_op_id is required".to_string());
                }
                if req.destination_address.trim().is_empty() {
                    return err("bitcoin.claim.build: destination_address is required".to_string());
                }
                if req.outpoint_txid.len() != 32 {
                    return err(format!(
                        "bitcoin.claim.build: outpoint_txid must be 32 bytes (got {})",
                        req.outpoint_txid.len()
                    ));
                }

                let record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.claim.build: deposit not found: {e}")),
                };

                let htlc_script = match record.htlc_script.as_ref() {
                    Some(s) if !s.is_empty() => s,
                    _ => {
                        return err(
                            "bitcoin.claim.build: missing HTLC script for this deposit".to_string()
                        )
                    }
                };

                let preimage: Vec<u8> = if !req.preimage.is_empty() {
                    req.preimage.clone()
                } else {
                    match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage(&record) {
                        Ok(p) => p,
                        Err(e) => {
                            return err(format!("bitcoin.claim.build: cannot derive preimage: {e}"))
                        }
                    }
                };

                let mut outpoint_txid = [0u8; 32];
                outpoint_txid.copy_from_slice(&req.outpoint_txid);

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let tx = match crate::sdk::bitcoin_tx_builder::build_htlc_claim_tx(
                    &crate::sdk::bitcoin_tx_builder::ClaimTxParams {
                        outpoint_txid: &outpoint_txid,
                        outpoint_vout: req.outpoint_vout,
                        htlc_script,
                        preimage: &preimage,
                        destination_addr: &req.destination_address,
                        amount_sats: record.btc_amount_sats,
                        fee_rate_sat_vb: req.fee_rate_sat_vb.max(1),
                        signer: crate::sdk::bitcoin_tx_builder::HtlcSpendSigner::MathOwned {
                            hash_lock: &record.hash_lock,
                        },
                        network: network.to_bitcoin_network(),
                    },
                ) {
                    Ok(t) => t,
                    Err(e) => return err(format!("bitcoin.claim.build failed: {e}")),
                };

                let raw_tx = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&tx);
                let txid = tx.compute_txid().to_string();

                let resp = generated::BitcoinClaimTxResponse { raw_tx, txid };
                pack_envelope_ok(generated::envelope::Payload::BitcoinClaimTxResponse(resp))
            }

            "bitcoin.tx.broadcast" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinBroadcastRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinBroadcastRequest failed: {e}")),
                };
                if req.raw_tx.is_empty() {
                    return err("bitcoin.tx.broadcast: raw_tx is required".to_string());
                }

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let txid = match self.broadcast_raw_tx(&req.raw_tx, network).await {
                    Ok(t) => t,
                    Err(e) => return err(format!("bitcoin.tx.broadcast failed: {e}")),
                };

                let resp = generated::BitcoinBroadcastResponse {
                    txid: txid.to_vec(),
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinBroadcastResponse(resp))
            }

            "bitcoin.claim.auto" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinAutoClaimRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinAutoClaimRequest failed: {e}")),
                };
                if req.vault_op_id.trim().is_empty() {
                    return err("bitcoin.claim.auto: vault_op_id is required".to_string());
                }
                if req.destination_address.trim().is_empty() {
                    return err("bitcoin.claim.auto: destination_address is required".to_string());
                }
                if req.funding_txid.len() != 32 {
                    return err(format!(
                        "bitcoin.claim.auto: funding_txid must be 32 bytes (got {})",
                        req.funding_txid.len()
                    ));
                }

                // 1. Look up vault record
                let record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.claim.auto: deposit not found: {e}")),
                };

                let htlc_script = match record.htlc_script.as_ref() {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => {
                        return err(
                            "bitcoin.claim.auto: missing HTLC script for this deposit".to_string()
                        )
                    }
                };

                let preimage =
                    match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage(&record) {
                        Ok(p) => p,
                        Err(e) => {
                            return err(format!("bitcoin.claim.auto: cannot derive preimage: {e}"))
                        }
                    };

                let mut outpoint_txid = [0u8; 32];
                outpoint_txid.copy_from_slice(&req.funding_txid);

                // 2. Resolve network for address validation + broadcast
                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                // 4. Build claim transaction
                let tx = match crate::sdk::bitcoin_tx_builder::build_htlc_claim_tx(
                    &crate::sdk::bitcoin_tx_builder::ClaimTxParams {
                        outpoint_txid: &outpoint_txid,
                        outpoint_vout: req.funding_vout,
                        htlc_script: &htlc_script,
                        preimage: &preimage,
                        destination_addr: &req.destination_address,
                        amount_sats: record.btc_amount_sats,
                        fee_rate_sat_vb: req.fee_rate_sat_vb.max(1),
                        signer: crate::sdk::bitcoin_tx_builder::HtlcSpendSigner::MathOwned {
                            hash_lock: &record.hash_lock,
                        },
                        network: network.to_bitcoin_network(),
                    },
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.claim.auto: build_htlc_claim_tx failed: {e}"
                        ))
                    }
                };
                let raw_tx = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&tx);

                let txid = match self.broadcast_raw_tx(&raw_tx, network).await {
                    Ok(t) => t,
                    Err(e) => return err(format!("bitcoin.claim.auto: broadcast failed: {e}")),
                };

                let resp = generated::BitcoinAutoClaimResponse {
                    txid: txid.to_vec(),
                    raw_tx,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinAutoClaimResponse(resp))
            }

            "bitcoin.refund.build" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinRefundTxRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => return err(format!("decode BitcoinRefundTxRequest failed: {e}")),
                };
                if req.vault_op_id.trim().is_empty() {
                    return err("bitcoin.refund.build: vault_op_id is required".to_string());
                }
                if req.refund_address.trim().is_empty() {
                    return err("bitcoin.refund.build: refund_address is required".to_string());
                }
                if req.outpoint_txid.len() != 32 {
                    return err(format!(
                        "bitcoin.refund.build: outpoint_txid must be 32 bytes (got {})",
                        req.outpoint_txid.len()
                    ));
                }

                let record = match self.bitcoin_tap.get_vault_record(&req.vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.refund.build: deposit not found: {e}")),
                };

                let htlc_script = match record.htlc_script.as_ref() {
                    Some(s) if !s.is_empty() => s,
                    _ => {
                        return err("bitcoin.refund.build: missing HTLC script for this deposit"
                            .to_string())
                    }
                };
                // Refund preimage is deterministic: H("DSM/dlv-refund" || hash_lock || refund_iterations)
                let refund_preimage = {
                    let mut buf = Vec::from(record.hash_lock.as_slice());
                    buf.extend_from_slice(&record.refund_iterations.to_le_bytes());
                    dsm::crypto::blake3::domain_hash_bytes("DSM/dlv-refund", &buf).to_vec()
                };

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let mut outpoint_txid = [0u8; 32];
                outpoint_txid.copy_from_slice(&req.outpoint_txid);

                let keys = self.bitcoin_keys.lock().await;
                let tx = match crate::sdk::bitcoin_tx_builder::build_htlc_refund_tx(
                    &crate::sdk::bitcoin_tx_builder::RefundTxParams {
                        outpoint_txid: &outpoint_txid,
                        outpoint_vout: req.outpoint_vout,
                        htlc_script,
                        preimage: &refund_preimage,
                        refund_addr: &req.refund_address,
                        amount_sats: record.btc_amount_sats,
                        fee_rate_sat_vb: req.fee_rate_sat_vb.max(1),
                        key_store: &keys,
                        signing_index: req.signing_index,
                        network: network.to_bitcoin_network(),
                    },
                ) {
                    Ok(t) => t,
                    Err(e) => return err(format!("bitcoin.refund.build failed: {e}")),
                };

                let raw_tx = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&tx);
                let txid = tx.compute_txid().to_string();

                let resp = generated::BitcoinRefundTxResponse { raw_tx, txid };
                pack_envelope_ok(generated::envelope::Payload::BitcoinRefundTxResponse(resp))
            }

            "bitcoin.withdraw.execute" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinWithdrawalExecuteRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "decode BitcoinWithdrawalExecuteRequest failed: {e}"
                        ))
                    }
                };

                match self.execute_withdrawal_plan_internal(req).await {
                    Ok(resp) => pack_envelope_ok(
                        generated::envelope::Payload::BitcoinWithdrawalExecuteResponse(resp),
                    ),
                    Err(e) => err(e),
                }
            }

            "bitcoin.fractional.exit" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinFractionalExitRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!("decode BitcoinFractionalExitRequest failed: {e}"))
                    }
                };
                if req.source_vault_id.trim().is_empty() {
                    return err("bitcoin.fractional.exit: source_vault_id is required".to_string());
                }
                if req.exit_amount_sats == 0 {
                    return err("bitcoin.fractional.exit: exit_amount_sats must be > 0".to_string());
                }

                if req.destination_address.trim().is_empty() {
                    return err(
                        "bitcoin.fractional.exit: destination_address is required".to_string()
                    );
                }

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                // Fetch vault execution data from storage nodes.
                let exec_data = match self
                    .bitcoin_tap
                    .fetch_vault_execution_data(&req.source_vault_id)
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        return err(format!(
                        "bitcoin.fractional.exit: fetch vault data from storage nodes failed: {e}"
                    ))
                    }
                };
                if !req.plan_id.is_empty() {
                    if let Err(message) = ensure_exec_data_matches_withdrawal_policy(
                        "bitcoin.fractional.exit",
                        &req.plan_id,
                        &req.source_vault_id,
                        &exec_data,
                    ) {
                        return err(message);
                    }
                }

                let dev = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;

                // Read dBTC balance early — gate check runs after burn_amount is known.
                let current_dbtc = match crate::storage::client_db::get_token_balance(&dev, dbtc_id)
                {
                    Ok(Some((a, _))) => a,
                    _ => self
                        .wallet
                        .get_balance(Some(dbtc_id))
                        .map(|b| b.available())
                        .unwrap_or(0),
                };

                // Successor vault creation needs keys + state (this device creates the successor)
                let state = match self.core_sdk.get_current_state() {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.fractional.exit: get current state failed: {e}"
                        ))
                    }
                };
                let (sphincs_pk, sphincs_sk) =
                    match dsm::crypto::sphincs::generate_sphincs_keypair() {
                        Ok(kp) => kp,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.fractional.exit: SPHINCS keygen failed: {e}"
                            ))
                        }
                    };
                let kyber_kp = match dsm::crypto::kyber::generate_kyber_keypair() {
                    Ok(kp) => kp,
                    Err(e) => {
                        return err(format!("bitcoin.fractional.exit: Kyber keygen failed: {e}"))
                    }
                };

                // pour_partial: compute successor vault + burn op
                let result = match self
                    .bitcoin_tap
                    .pour_partial(
                        &req.source_vault_id,
                        &exec_data.policy_commit,
                        exec_data.amount_sats,
                        exec_data.successor_depth,
                        req.exit_amount_sats,
                        req.refund_iterations,
                        (&sphincs_pk, &sphincs_sk),
                        &state,
                        network,
                        &kyber_kp.public_key,
                    )
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.fractional.exit failed: {e}")),
                };

                let burn_amount = match &result.token_operation {
                    dsm::types::token_types::TokenOperation::Burn { amount, .. } => *amount,
                    _ => result.exit_amount_sats,
                };

                // Gate 1: verify dBTC balance covers the exit amount
                if let Err(message) =
                    ensure_dbtc_exit_balance("bitcoin.fractional.exit", current_dbtc, burn_amount)
                {
                    return err(message);
                }

                // Detect whether this leg was dispatched by execute_withdrawal_plan_internal.
                // When orchestrated (plan_id non-empty), the outer function has ALREADY
                // created the in-flight withdrawal record. Repeating that step here would
                // corrupt the txid CSV for multi-leg plans (§13 Property 4: Amount-Exact).
                // Lock lifecycle is always owned by the handler — planner does not lock.
                let orchestrated = !req.plan_id.is_empty();

                // For standalone invocations, generate a deterministic withdrawal ID.
                // None when orchestrated (outer executor already created the record).
                let standalone_wd_id: Option<String> = if orchestrated {
                    None
                } else {
                    Some(Self::generate_standalone_withdrawal_id(
                        &dev,
                        burn_amount,
                        &req.destination_address,
                    ))
                };

                // ═══════════════════════════════════════════════════════
                // Phase 2: Pre-commitment (SQLite balance hold)
                // Lock dBTC so it cannot be double-spent during sweep.
                // Each handler always owns its own lock lifecycle.
                // ═══════════════════════════════════════════════════════
                if let Err(e) =
                    crate::storage::client_db::lock_dbtc_for_exit(&dev, dbtc_id, burn_amount)
                {
                    return err(format!("bitcoin.fractional.exit: balance lock failed: {e}"));
                }
                log::info!(
                    "[bitcoin.fractional.exit] Phase 2: locked {} sats for exit",
                    burn_amount
                );

                // Persist exit_amount_sats on successor record for crash recovery
                if let Err(e) = crate::storage::client_db::update_vault_record_exit_amount(
                    &result.successor_vault_op_id,
                    burn_amount,
                ) {
                    log::error!("[bitcoin.fractional.exit] failed to persist exit_amount: {e}");
                }
                // Mark state as SweepPending — must succeed to block double-exits
                if let Err(e) = crate::storage::client_db::update_vault_record_state(
                    &result.successor_vault_op_id,
                    "SweepPending",
                ) {
                    log::error!(
                        "[bitcoin.fractional.exit] CRITICAL: failed to mark SweepPending: {e}"
                    );
                    if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                        &dev,
                        dbtc_id,
                        burn_amount,
                    ) {
                        log::error!("[bitcoin.fractional.exit] also failed to release lock: {e2}");
                    }
                    return err(format!(
                        "bitcoin.fractional.exit: failed to mark SweepPending: {e}"
                    ));
                }

                // ═══════════════════════════════════════════════════════
                // Phase 3: Sweep broadcast (dBTC §6.4.3)
                // Broadcast sweep tx. Confirmation depth tracking is
                // handled by the existing check_confirmations polling
                // (same infrastructure as deposit confirmation).
                // ═══════════════════════════════════════════════════════
                let sweep_result = sweep_and_broadcast(SweepBroadcastRequest {
                    bitcoin_tap: &self.bitcoin_tap,
                    bitcoin_keys: &self.bitcoin_keys,
                    source_exec_data: &exec_data,
                    successor_vault_op_id: &result.successor_vault_op_id,
                    exit_sats: result.exit_amount_sats,
                    remainder_sats: result.remainder_sats,
                    dest_addr: &req.destination_address,
                    successor_htlc_script: &result.successor_htlc_script,
                    network,
                })
                .await;

                let sweep_txid = match sweep_result {
                    Ok(txid) => {
                        log::info!(
                            "[bitcoin.fractional.exit] Phase 3: sweep broadcast OK, txid={}",
                            txid
                        );
                        // Update successor record: funding_txid + state sync
                        if let Err(e) = self
                            .bitcoin_tap
                            .update_vault_record_funding_txid(&result.successor_vault_op_id, &txid)
                            .await
                        {
                            log::error!(
                                "[bitcoin.fractional.exit] failed to persist funding_txid: {e}"
                            );
                        }
                        // Sync in-memory state to AwaitingConfirmation so the
                        // deposit list shows the correct status and DepositCard polls
                        // confirmations via the BtcToDbtc completion path.
                        self.bitcoin_tap
                            .update_vault_record_state_in_memory(
                                &result.successor_vault_op_id,
                                crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation,
                                String::new(),
                            )
                            .await;
                        if let Err(e) = crate::storage::client_db::update_vault_record_state(
                            &result.successor_vault_op_id,
                            "AwaitingConfirmation",
                        ) {
                            log::error!("[bitcoin.fractional.exit] failed to persist AwaitingConfirmation state: {e}");
                        }
                        txid
                    }
                    Err(e) => {
                        // Sweep failed: release the locked balance and abort.
                        log::error!(
                            "[bitcoin.fractional.exit] Phase 3: sweep FAILED: {e} — releasing lock"
                        );
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!("[bitcoin.fractional.exit] CRITICAL: failed to release lock after sweep failure: {e2}");
                        }
                        if let Err(e2) = crate::storage::client_db::update_vault_record_state(
                            &result.successor_vault_op_id,
                            "SweepFailed",
                        ) {
                            log::error!(
                                "[bitcoin.fractional.exit] failed to mark SweepFailed: {e2}"
                            );
                        }
                        return err(format!(
                            "bitcoin.fractional.exit: sweep broadcast failed: {e}"
                        ));
                    }
                };

                // Successor vault advertisement is published by
                // update_successor_entry_txid_and_publish_ad() via the protobuf path.

                // ═══════════════════════════════════════════════════════
                // Phase 4: Record in-flight withdrawal (deferred burn)
                // dBTC §13.1 Property 8: tokens leave spendable circulation
                // at commitment but finality is only at d_min. Burn is
                // deferred to the settlement resolver.
                //
                // Skipped when orchestrated: the outer execute_withdrawal_plan_internal
                // created the in-flight record before dispatching legs, and will update
                // the redemption txid CSV atomically after each leg completes.
                // Creating or overwriting the record here would corrupt the txid CSV
                // for multi-leg plans (§13, Property 4: Amount-Exact Commitment).
                // ═══════════════════════════════════════════════════════
                if let Some(wd_id) = &standalone_wd_id {
                    if let Err(e) = crate::storage::client_db::create_withdrawal(
                        crate::storage::client_db::CreateWithdrawalParams {
                            withdrawal_id: wd_id,
                            device_id: &dev,
                            amount_sats: burn_amount,
                            dest_address: &req.destination_address,
                            policy_commit: &exec_data.policy_commit,
                            state: "committed",
                            burn_token_id: Some(dbtc_id),
                            burn_amount_sats: burn_amount,
                        },
                    ) {
                        log::error!(
                            "[bitcoin.fractional.exit] withdrawal metadata creation failed: {e}"
                        );
                    }

                    if let Err(e) = crate::storage::client_db::set_withdrawal_redemption_txids(
                        wd_id,
                        &sweep_txid,
                        Some(exec_data.vault_content_hash.as_slice()),
                    ) {
                        log::error!("[bitcoin.fractional.exit] set redemption txid failed: {e}");
                    }
                }

                // Mark successor vault as AwaitingSettlement (not Completed —
                // burn happens at d_min via the settlement resolver)
                if let Err(e) = crate::storage::client_db::update_vault_record_state(
                    &result.successor_vault_op_id,
                    "AwaitingSettlement",
                ) {
                    log::error!("[bitcoin.fractional.exit] failed to mark AwaitingSettlement: {e}");
                }

                log::info!(
                    "[bitcoin.fractional.exit] Phase 4: in-flight withdrawal recorded, \
                     burn deferred to settlement (sweep_txid={sweep_txid}, burn_amount={burn_amount})"
                );

                // Create visible exit vault record for the withdrawn amount (DbtcToBtc direction).
                // The successor deposit from pour_partial() is the remainder vault, not the exit.
                let exit_vault_op_id = match self
                    .bitcoin_tap
                    .create_exit_deposit_record(
                        &req.source_vault_id,
                        result.exit_amount_sats,
                        &req.destination_address,
                        &sweep_txid,
                    )
                    .await
                {
                    Ok(id) => {
                        log::info!(
                            "[bitcoin.fractional.exit] exit deposit {} created for {} sats",
                            id,
                            result.exit_amount_sats,
                        );
                        id
                    }
                    Err(e) => {
                        log::warn!("[bitcoin.fractional.exit] exit deposit creation failed: {e}");
                        String::new()
                    }
                };
                if let Some(wd_id) = &standalone_wd_id {
                    if let Err(e) = persist_withdrawal_leg(
                        wd_id,
                        0,
                        &req.source_vault_id,
                        "partial",
                        burn_amount,
                        crate::sdk::bitcoin_tap_sdk::estimated_partial_withdrawal_fee_sats(),
                        burn_amount.saturating_sub(
                            crate::sdk::bitcoin_tap_sdk::estimated_partial_withdrawal_fee_sats(),
                        ),
                        Some(&sweep_txid),
                        Some(&result.successor_vault_id),
                        Some(&result.successor_vault_op_id),
                        (!exit_vault_op_id.is_empty()).then_some(exit_vault_op_id.as_str()),
                    ) {
                        log::error!("[bitcoin.fractional.exit] withdrawal leg persistence failed: {e}");
                    }
                }

                let resp = generated::BitcoinFractionalExitResponse {
                    source_vault_id: req.source_vault_id.clone(),
                    successor_vault_id: result.successor_vault_id,
                    successor_vault_op_id: result.successor_vault_op_id,
                    exit_amount_sats: result.exit_amount_sats,
                    remainder_sats: result.remainder_sats,
                    successor_depth: result.successor_depth,
                    successor_htlc_script: result.successor_htlc_script,
                    successor_htlc_address: result.successor_htlc_address,
                    exit_vault_op_id,
                    // Exit anchor fields (dBTC §6.4.3, §12.1.3)
                    sweep_txid: sweep_txid.clone(),
                    // confirm_depth starts at 0; frontend polls
                    // check_confirmations to track burial progress.
                    confirm_depth: 0,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinFractionalExitResponse(
                    resp,
                ))
            }

            "bitcoin.full.sweep" => {
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                let req = match generated::BitcoinFractionalExitRequest::decode(&*pack.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!("decode BitcoinFractionalExitRequest failed: {e}"))
                    }
                };
                if req.source_vault_id.trim().is_empty() {
                    return err("bitcoin.full.sweep: source_vault_id is required".to_string());
                }

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                // ═══════════════════════════════════════════════════════
                // Fetch vault execution data from storage nodes.
                // Unilateral action — anyone with dBTC tokens can do this.
                // No local vault record needed. Storage nodes have everything.
                // The tokens are the key.
                // ═══════════════════════════════════════════════════════
                let exec_data = match self
                    .bitcoin_tap
                    .fetch_vault_execution_data(&req.source_vault_id)
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.full.sweep: fetch vault data from storage nodes failed: {e}"
                        ))
                    }
                };
                if !req.plan_id.is_empty() {
                    if let Err(message) = ensure_exec_data_matches_withdrawal_policy(
                        "bitcoin.full.sweep",
                        &req.plan_id,
                        &req.source_vault_id,
                        &exec_data,
                    ) {
                        return err(message);
                    }
                }

                let burn_amount = exec_data.amount_sats;
                let dev = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;

                // Detect whether this leg is orchestrated by execute_withdrawal_plan_internal.
                // When orchestrated (plan_id non-empty), the outer function has ALREADY
                // created the in-flight withdrawal record. Repeating that step here would
                // corrupt the txid CSV for multi-leg plans (§13 Property 4: Amount-Exact).
                // Lock lifecycle is always owned by the handler — planner does not lock.
                let orchestrated = !req.plan_id.is_empty();

                // For standalone invocations, generate a deterministic withdrawal ID.
                // None when orchestrated (outer executor already created the record).
                let standalone_wd_id: Option<String> = if orchestrated {
                    None
                } else {
                    Some(Self::generate_standalone_withdrawal_id(
                        &dev,
                        burn_amount,
                        &req.destination_address,
                    ))
                };

                // Gate 1: verify dBTC balance covers the vault amount
                let current_dbtc = match crate::storage::client_db::get_token_balance(&dev, dbtc_id)
                {
                    Ok(Some((a, _))) => a,
                    _ => self
                        .wallet
                        .get_balance(Some(dbtc_id))
                        .map(|b| b.available())
                        .unwrap_or(0),
                };
                if let Err(message) =
                    ensure_dbtc_exit_balance("bitcoin.full.sweep", current_dbtc, burn_amount)
                {
                    return err(message);
                }

                // ═══════════════════════════════════════════════════════
                // Phase 2: Lock dBTC (§13 state machine)
                // Moves available → locked. If broadcast fails we release.
                // Each handler always owns its own lock lifecycle.
                // ═══════════════════════════════════════════════════════
                if let Err(e) =
                    crate::storage::client_db::lock_dbtc_for_exit(&dev, dbtc_id, burn_amount)
                {
                    return err(format!("bitcoin.full.sweep: balance lock failed: {e}"));
                }
                log::info!(
                    "[bitcoin.full.sweep] Phase 2: locked {} sats for exit",
                    burn_amount
                );

                // ═══════════════════════════════════════════════════════
                // Phase 3: Build + broadcast Bitcoin claim tx.
                // Data comes from storage node advertisement.
                // ═══════════════════════════════════════════════════════
                let derived_preimage =
                    match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage_from_deposit_nonce(
                        &exec_data.deposit_nonce,
                        &exec_data.policy_commit,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            log::error!("[bitcoin.full.sweep] cannot derive preimage: {e}");
                            if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                                &dev, dbtc_id, burn_amount,
                            ) {
                                log::error!(
                                    "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                                );
                            }
                            return err(format!("bitcoin.full.sweep: cannot derive preimage: {e}"));
                        }
                    };

                let script = &exec_data.htlc_script;
                let addr = &exec_data.htlc_address;
                let pre = &derived_preimage;

                // Resolve destination address
                let claim_dest = if !req.destination_address.is_empty() {
                    req.destination_address.clone()
                } else {
                    let locked_keys = self.bitcoin_keys.lock().await;
                    let db_floor = match crate::storage::client_db::get_active_bitcoin_account() {
                        Ok(Some(a)) => a.active_receive_index,
                        Ok(None) => 0,
                        Err(e) => {
                            log::error!("[bitcoin] failed to read active bitcoin account: {e}");
                            0
                        }
                    };
                    let idx = locked_keys.current_receive_index().max(db_floor);
                    let (a, _) = locked_keys
                        .peek_receive_address(idx)
                        .unwrap_or_else(|_| (String::new(), [0u8; 33]));
                    drop(locked_keys);
                    a
                };

                if claim_dest.is_empty() {
                    log::error!("[bitcoin.full.sweep] no destination address available");
                    if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                        &dev,
                        dbtc_id,
                        burn_amount,
                    ) {
                        log::error!(
                            "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                        );
                    }
                    return err("bitcoin.full.sweep: no destination address available".to_string());
                }

                let client =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => {
                            log::error!("[bitcoin.full.sweep] mempool client init failed: {e}");
                            if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                                &dev,
                                dbtc_id,
                                burn_amount,
                            ) {
                                log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                            }
                            return err(format!(
                                "bitcoin.full.sweep: mempool client init failed: {e}"
                            ));
                        }
                    };

                let utxos = match client.list_address_utxos(std::slice::from_ref(addr)).await {
                    Ok(u) if !u.is_empty() => u,
                    Ok(_) => {
                        log::error!("[bitcoin.full.sweep] no UTXO at HTLC address {addr}");
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                        }
                        return err(format!(
                            "bitcoin.full.sweep: no UTXO at HTLC address {addr}"
                        ));
                    }
                    Err(e) => {
                        log::error!("[bitcoin.full.sweep] UTXO lookup failed: {e}");
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                        }
                        return err(format!("bitcoin.full.sweep: UTXO lookup failed: {e}"));
                    }
                };

                let utxo = &utxos[0];
                // hex_to_bytes is at the mempool.space boundary only — raw bytes from here on
                let utxo_txid_bytes = match super::mempool_api::hex_to_bytes(&utxo.txid) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        log::error!("[bitcoin.full.sweep] invalid utxo txid");
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                        }
                        return err(
                            "bitcoin.full.sweep: invalid utxo txid from mempool".to_string()
                        );
                    }
                };
                // Display order → internal order (reverse)
                let mut outpoint_txid = [0u8; 32];
                for (i, b) in utxo_txid_bytes.iter().enumerate() {
                    outpoint_txid[31 - i] = *b;
                }

                let lib_network = network.to_bitcoin_network();
                let tx_result = crate::sdk::bitcoin_tx_builder::build_htlc_claim_tx(
                    &crate::sdk::bitcoin_tx_builder::ClaimTxParams {
                        outpoint_txid: &outpoint_txid,
                        outpoint_vout: utxo.vout,
                        htlc_script: script,
                        preimage: pre,
                        destination_addr: &claim_dest,
                        amount_sats: burn_amount,
                        fee_rate_sat_vb:
                            crate::sdk::bitcoin_tap_sdk::withdrawal_fee_rate_sat_vb(),
                        signer: crate::sdk::bitcoin_tx_builder::HtlcSpendSigner::MathOwned {
                            hash_lock: &exec_data.hash_lock,
                        },
                        network: lib_network,
                    },
                );

                let claim_tx = match tx_result {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::error!("[bitcoin.full.sweep] build_htlc_claim_tx failed: {e}");
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                        }
                        return err(format!("bitcoin.full.sweep: build claim tx failed: {e}"));
                    }
                };

                let raw_claim = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&claim_tx);
                let sweep_txid = match client.broadcast_tx_raw(&raw_claim).await {
                    Ok(txid) => {
                        log::info!("[bitcoin.full.sweep] Phase 3: broadcast OK, txid={txid}");
                        txid
                    }
                    Err(e) => {
                        // Broadcast failed → release lock, no value stranded (§13, Property 9)
                        log::error!(
                            "[bitcoin.full.sweep] Phase 3: broadcast FAILED: {e} — releasing lock"
                        );
                        if let Err(e2) = crate::storage::client_db::release_locked_to_available(
                            &dev,
                            dbtc_id,
                            burn_amount,
                        ) {
                            log::error!(
                                "[bitcoin.full.sweep] CRITICAL: failed to release dBTC lock: {e2}"
                            );
                        }
                        return err(format!("bitcoin.full.sweep: broadcast failed: {e}"));
                    }
                };

                // Mark source vault as spent on storage nodes.
                // The UTXO is gone — future planners skip this vault without
                // hitting Bitcoin. Storage nodes prune spent ads after a TTL.
                if let Err(e) =
                    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::mark_vault_spent_on_storage_nodes(
                        &req.source_vault_id,
                    )
                    .await
                {
                    log::warn!("[bitcoin.full.sweep] mark_vault_spent failed: {e}");
                }

                // ═══════════════════════════════════════════════════════
                // Phase 4: Record in-flight withdrawal (deferred burn)
                // dBTC §13.1 Property 8: burn deferred to settlement.
                //
                // Skipped when orchestrated: the outer execute_withdrawal_plan_internal
                // created the in-flight record before dispatching legs, and will update
                // the redemption txid CSV atomically after each leg completes.
                // Creating or overwriting the record here would corrupt the txid CSV
                // for multi-leg plans (§13, Property 4: Amount-Exact Commitment).
                // ═══════════════════════════════════════════════════════
                if let Some(wd_id) = &standalone_wd_id {
                    if let Err(e) = crate::storage::client_db::create_withdrawal(
                        crate::storage::client_db::CreateWithdrawalParams {
                            withdrawal_id: wd_id,
                            device_id: &dev,
                            amount_sats: burn_amount,
                            dest_address: &req.destination_address,
                            policy_commit: &exec_data.policy_commit,
                            state: "committed",
                            burn_token_id: Some(dbtc_id),
                            burn_amount_sats: burn_amount,
                        },
                    ) {
                        log::error!(
                            "[bitcoin.full.sweep] withdrawal metadata creation failed: {e}"
                        );
                    }

                    if let Err(e) = crate::storage::client_db::set_withdrawal_redemption_txids(
                        wd_id,
                        &sweep_txid,
                        Some(exec_data.vault_content_hash.as_slice()),
                    ) {
                        log::error!("[bitcoin.full.sweep] set redemption txid failed: {e}");
                    }
                }

                log::info!(
                    "[bitcoin.full.sweep] Phase 4: in-flight withdrawal recorded, \
                     burn deferred to settlement (sweep_txid={sweep_txid}, burn_amount={burn_amount})"
                );

                // Create visible exit vault record for the withdrawn amount.
                let exit_vault_op_id = match self
                    .bitcoin_tap
                    .create_exit_deposit_record(
                        &req.source_vault_id,
                        burn_amount,
                        &req.destination_address,
                        &sweep_txid,
                    )
                    .await
                {
                    Ok(id) => {
                        log::info!(
                            "[bitcoin.full.sweep] exit deposit {} created for {} sats",
                            id,
                            burn_amount,
                        );
                        id
                    }
                    Err(e) => {
                        log::warn!("[bitcoin.full.sweep] exit deposit creation failed: {e}");
                        String::new()
                    }
                };
                if let Some(wd_id) = &standalone_wd_id {
                    if let Err(e) = persist_withdrawal_leg(
                        wd_id,
                        0,
                        &req.source_vault_id,
                        "full",
                        burn_amount,
                        crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats(),
                        burn_amount.saturating_sub(
                            crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats(),
                        ),
                        Some(&sweep_txid),
                        None,
                        None,
                        (!exit_vault_op_id.is_empty()).then_some(exit_vault_op_id.as_str()),
                    ) {
                        log::error!("[bitcoin.full.sweep] withdrawal leg persistence failed: {e}");
                    }
                }

                // Set exit deposit to AwaitingConfirmation with funding_txid so the
                // frontend polls check_confirmations for exit burial (dBTC §6.4.3).
                if !exit_vault_op_id.is_empty() {
                    if let Err(e) = self
                        .bitcoin_tap
                        .update_vault_record_funding_txid(&exit_vault_op_id, &sweep_txid)
                        .await
                    {
                        log::error!("[bitcoin.full.sweep] failed to set exit funding_txid: {e}");
                    }
                    if let Err(e) = crate::storage::client_db::update_vault_record_funding_txid(
                        &exit_vault_op_id,
                        &sweep_txid,
                    ) {
                        log::error!(
                            "[bitcoin.full.sweep] failed to persist exit funding_txid: {e}"
                        );
                    }
                    if let Err(e) = crate::storage::client_db::update_vault_record_state(
                        &exit_vault_op_id,
                        "awaiting_confirmation",
                    ) {
                        log::error!("[bitcoin.full.sweep] failed to persist exit state: {e}");
                    }
                    if !req.destination_address.is_empty() {
                        if let Err(e) =
                            crate::storage::client_db::set_vault_record_destination_address(
                                &exit_vault_op_id,
                                &req.destination_address,
                            )
                        {
                            log::error!(
                                "[bitcoin.full.sweep] failed to persist exit dest address: {e}"
                            );
                        }
                    }
                    self.bitcoin_tap
                        .update_vault_record_state_in_memory(
                            &exit_vault_op_id,
                            crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation,
                            req.destination_address.clone(),
                        )
                        .await;
                    log::info!(
                        "[bitcoin.full.sweep] exit deposit {} → AwaitingConfirmation (burial pending, txid={})",
                        exit_vault_op_id,
                        sweep_txid,
                    );
                }

                let resp = generated::BitcoinFractionalExitResponse {
                    source_vault_id: req.source_vault_id.clone(),
                    successor_vault_id: String::new(),
                    successor_vault_op_id: String::new(),
                    exit_amount_sats: burn_amount,
                    remainder_sats: 0,
                    successor_depth: 0,
                    successor_htlc_script: Vec::new(),
                    successor_htlc_address: String::new(),
                    exit_vault_op_id,
                    sweep_txid,
                    confirm_depth: 0,
                };
                pack_envelope_ok(generated::envelope::Payload::BitcoinFractionalExitResponse(
                    resp,
                ))
            }

            // -------- Universal: fund HTLC from user wallet + complete deposit --------
            "bitcoin.deposit.fund_and_broadcast" => {
                let vault_op_id = match generated::ArgPack::decode(&*i.args) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::DepositRefundRequest::decode(&*pack.body) {
                            Ok(req) if !req.vault_op_id.is_empty() => req.vault_op_id,
                            _ => return err("bitcoin.deposit.fund_and_broadcast: expected DepositRefundRequest with non-empty vault_op_id".into()),
                        }
                    }
                    _ => return err("bitcoin.deposit.fund_and_broadcast: expected ArgPack(codec=PROTO)".into()),
                };

                let record = match self.bitcoin_tap.get_vault_record(&vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.fund_and_broadcast: deposit not found: {e}"
                        ))
                    }
                };

                if record.state != crate::sdk::bitcoin_tap_sdk::VaultOpState::Initiated {
                    return err(format!(
                        "bitcoin.deposit.fund_and_broadcast: deposit {} is not in Initiated state",
                        vault_op_id
                    ));
                }

                let htlc_address = match &record.htlc_address {
                    Some(a) if !a.is_empty() => a.clone(),
                    _ => return err("bitcoin.deposit.fund_and_broadcast: no HTLC address".into()),
                };
                let deposit_sats = record.btc_amount_sats;
                if deposit_sats == 0 {
                    return err("bitcoin.deposit.fund_and_broadcast: invalid BTC amount".into());
                }

                // Resolve network from active account
                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                log::info!(
                    "[FUND_AND_BROADCAST] Deposit {} → HTLC {} with {} sats (network={:?}, fractional_successor={})",
                    vault_op_id, htlc_address, deposit_sats, network, record.is_fractional_successor
                );

                // ── Step 1: Build + broadcast funding tx from user's wallet ──

                let funding_txid_hex: String;

                if record.is_fractional_successor {
                    // Fractional successors are already funded by the sweep tx.
                    // Prefer the stored funding_txid (set by sweep_and_broadcast);
                    // fall back to on-chain UTXO lookup with retries for timing races.
                    if let Some(ref stored_txid) = record.funding_txid {
                        log::info!(
                            "[FUND_AND_BROADCAST] Using stored funding_txid for fractional successor: {}",
                            stored_txid
                        );
                        funding_txid_hex = stored_txid.clone();
                    } else {
                        // No stored txid — sweep may still be propagating.
                        // Try on-chain lookup with retries.
                        const MAX_RETRIES: u32 = 3;
                        const RETRY_DELAY_MS: u64 = 5000;

                        let mut found_txid: Option<String> = None;

                        let mempool =
                            match super::mempool_api::MempoolClient::from_config_for_network(
                                network,
                            ) {
                                Ok(c) => c,
                                Err(e) => return err(format!("mempool client init: {e}")),
                            };
                        for attempt in 1..=MAX_RETRIES {
                            match mempool
                                .list_address_utxos(std::slice::from_ref(&htlc_address))
                                .await
                            {
                                Ok(utxos) => {
                                    if let Some(u) = utxos.first() {
                                        found_txid = Some(u.txid.clone());
                                        break;
                                    }
                                    log::warn!(
                                        "[FUND_AND_BROADCAST] fractional successor UTXO not found (attempt {}/{}), retrying in {}ms",
                                        attempt, MAX_RETRIES, RETRY_DELAY_MS
                                    );
                                }
                                Err(e) => {
                                    log::warn!(
                                        "[FUND_AND_BROADCAST] mempool UTXO lookup failed (attempt {}/{}): {e}",
                                        attempt, MAX_RETRIES
                                    );
                                }
                            }
                            if attempt < MAX_RETRIES {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    RETRY_DELAY_MS,
                                ))
                                .await;
                            }
                        }

                        match found_txid {
                            Some(txid) => funding_txid_hex = txid,
                            None => return err(
                                "bitcoin.deposit.fund_and_broadcast: no UTXO for fractional successor \
                                 after retries — sweep tx may not have propagated yet. \
                                 Try bitcoin.sweep.recover or wait and retry."
                                    .to_string(),
                            ),
                        }
                    }
                } else {
                    // ── Normal deposit: build real funding TX from user's wallet UTXOs ──

                    // 1a. Gather all tracked user addresses
                    let mut wallet_addresses: Vec<String> = Vec::new();
                    let active_account = crate::storage::client_db::get_active_bitcoin_account()
                        .ok()
                        .flatten();
                    if let Some(acct) = &active_account {
                        if acct.import_kind == "wif" {
                            if let Ok(secret) = String::from_utf8(acct.secret_material.clone()) {
                                let net = Self::bitcoin_network_from_u32(acct.network);
                                if let Ok((addr, _)) = Self::wif_address_and_pubkey(&secret, net) {
                                    wallet_addresses.push(addr);
                                }
                            }
                        } else if let Some(addr) = &acct.first_address {
                            if !addr.trim().is_empty() {
                                wallet_addresses.push(addr.clone());
                            }
                        }
                    }

                    {
                        let keys = self.bitcoin_keys.lock().await;
                        let db_idx = active_account
                            .as_ref()
                            .map(|a| a.active_receive_index)
                            .unwrap_or(0);
                        // Scan a 5-address gap from the highest known index.
                        // Funds can exist at ANY derived index, not just the active one.
                        let high = keys.current_receive_index().max(db_idx);
                        let scan_limit = high.saturating_add(5).min(20);
                        for i in 0..=scan_limit {
                            if let Ok((addr, _)) = keys.peek_receive_address(i) {
                                if !wallet_addresses.iter().any(|a| a == &addr) {
                                    wallet_addresses.push(addr);
                                }
                            }
                        }
                        // Also gather change addresses for UTXO scanning
                        let change_high = keys.current_change_index();
                        let change_limit = change_high.saturating_add(5).min(20);
                        for i in 0..=change_limit {
                            if let Ok((addr, _)) = keys.peek_change_address(i) {
                                if !wallet_addresses.iter().any(|a| a == &addr) {
                                    wallet_addresses.push(addr);
                                }
                            }
                        }
                    }

                    if wallet_addresses.is_empty() {
                        return err(
                            "bitcoin.deposit.fund_and_broadcast: no wallet addresses found".into(),
                        );
                    }

                    log::info!(
                        "[FUND_AND_BROADCAST] Scanning {} wallet addresses for UTXOs: {:?}",
                        wallet_addresses.len(),
                        wallet_addresses
                    );

                    // 1b. Scan wallet UTXOs through mempool.
                    let mempool =
                        match super::mempool_api::MempoolClient::from_config_for_network(network) {
                            Ok(c) => c,
                            Err(e) => return err(format!("mempool client init: {e}")),
                        };
                    let utxos: Vec<super::mempool_api::RpcUtxo> =
                        match mempool.list_address_utxos(&wallet_addresses).await {
                            Ok(u) => u,
                            Err(e) => {
                                return err(format!(
                                "bitcoin.deposit.fund_and_broadcast: mempool UTXO scan failed: {e}"
                            ))
                            }
                        };

                    if utxos.is_empty() {
                        return err("bitcoin.deposit.fund_and_broadcast: no UTXOs found in wallet — fund your wallet first".into());
                    }

                    let total_available: u64 = utxos.iter().map(|u| u.amount_sats).sum();
                    if total_available < deposit_sats {
                        return err(format!(
                            "bitcoin.deposit.fund_and_broadcast: insufficient BTC balance: have {} sats, need {} sats",
                            total_available, deposit_sats
                        ));
                    }

                    let confirmed_utxos: Vec<super::mempool_api::RpcUtxo> =
                        utxos.iter().filter(|u| u.confirmed).cloned().collect();
                    let confirmed_total: u64 = confirmed_utxos.iter().map(|u| u.amount_sats).sum();
                    let unconfirmed_total = total_available.saturating_sub(confirmed_total);

                    // Confirmed-first policy prevents mempool ancestor chain-limit rejects
                    // (e.g. too-long-mempool-chain) when wallet UTXOs include deep
                    // unconfirmed dependency chains.
                    if confirmed_total < deposit_sats {
                        return err(format!(
                            "bitcoin.deposit.fund_and_broadcast: insufficient confirmed BTC for funding: confirmed={} sats, unconfirmed={} sats, need={} sats. Wait for confirmations and retry.",
                            confirmed_total,
                            unconfirmed_total,
                            deposit_sats
                        ));
                    }

                    // 1c. Map UTXOs to derivation indices and select inputs
                    let mut keys = self.bitcoin_keys.lock().await;
                    let db_idx = active_account
                        .as_ref()
                        .map(|a| a.active_receive_index)
                        .unwrap_or(0);
                    let recv_idx = keys.current_receive_index().max(db_idx).min(64);
                    let change_idx_max = keys.current_change_index().min(64);

                    // Build address→(change_flag, index) map
                    let mut addr_to_derivation: std::collections::HashMap<String, (u32, u32)> =
                        std::collections::HashMap::new();
                    for i in 0..=recv_idx {
                        if let Ok((addr, _)) = keys.peek_receive_address(i) {
                            addr_to_derivation.insert(addr, (0, i));
                        }
                    }
                    for i in 0..=change_idx_max {
                        if let Ok((addr, _)) = keys.peek_change_address(i) {
                            addr_to_derivation.insert(addr, (1, i));
                        }
                    }

                    // Select UTXOs (greedy largest-first) and build SelectedUtxo list
                    let mut sorted_utxos = confirmed_utxos;
                    sorted_utxos.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats));

                    let mut selected: Vec<crate::sdk::bitcoin_tx_builder::SelectedUtxo> =
                        Vec::new();
                    let mut selected_total: u64 = 0;
                    // Rough fee estimate: 1 sat/vB * (68*inputs + 43 + 31 + 11) for first pass
                    let fee_rate: u64 = 2; // conservative 2 sat/vB

                    for utxo in &sorted_utxos {
                        if selected_total >= deposit_sats + fee_rate * 200 {
                            break; // rough over-estimate, will refine
                        }
                        let (change_flag, index) = match addr_to_derivation.get(&utxo.address) {
                            Some(&(c, i)) => (c, i),
                            None => {
                                log::warn!(
                                    "[FUND_AND_BROADCAST] Skipping UTXO at unknown address: {}",
                                    utxo.address
                                );
                                continue;
                            }
                        };
                        let pubkey = match if change_flag == 1 {
                            keys.peek_change_address(index)
                        } else {
                            keys.peek_receive_address(index)
                        } {
                            Ok((_, pk)) => pk,
                            Err(e) => {
                                log::warn!("[FUND_AND_BROADCAST] Key derivation failed for ({change_flag}, {index}): {e}");
                                continue;
                            }
                        };
                        selected.push(crate::sdk::bitcoin_tx_builder::SelectedUtxo {
                            // utxo.txid arrives as display-hex (explorer format); convert to internal byte order.
                            txid: crate::sdk::bitcoin_tx_builder::display_txid_to_internal(
                                &utxo.txid,
                            ),
                            vout: utxo.vout,
                            amount_sats: utxo.amount_sats,
                            change: change_flag,
                            index,
                            pubkey,
                        });
                        selected_total += utxo.amount_sats;
                    }

                    if selected.is_empty() {
                        drop(keys);
                        return err(
                            "bitcoin.deposit.fund_and_broadcast: no usable UTXOs (unmapped addresses)"
                                .into(),
                        );
                    }

                    // 1d. Get change address
                    let (change_addr, _change_idx, _change_pk) = match keys.next_change_address() {
                        Ok(v) => v,
                        Err(e) => {
                            drop(keys);
                            return err(format!("bitcoin.deposit.fund_and_broadcast: change address derivation failed: {e}"));
                        }
                    };

                    // 1e. Build + sign funding transaction
                    let funding_tx = match crate::sdk::bitcoin_tx_builder::build_htlc_funding_tx(
                        &crate::sdk::bitcoin_tx_builder::FundingTxParams {
                            inputs: &selected,
                            htlc_address: &htlc_address,
                            htlc_amount_sats: deposit_sats,
                            change_address: &change_addr,
                            fee_rate_sat_vb: fee_rate,
                            key_store: &keys,
                            network: network.to_bitcoin_network(),
                        },
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            drop(keys);
                            return err(format!("bitcoin.deposit.fund_and_broadcast: build_htlc_funding_tx failed: {e}"));
                        }
                    };
                    drop(keys);

                    let raw_funding_tx =
                        crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&funding_tx);
                    let computed_txid = crate::sdk::bitcoin_tx_builder::compute_txid(&funding_tx);
                    // Display order: reverse byte order + hex encode
                    let mut display_bytes = computed_txid;
                    display_bytes.reverse();
                    funding_txid_hex = display_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();

                    log::info!(
                        "[FUND_AND_BROADCAST] Built funding tx: {} ({} bytes, {} inputs)",
                        funding_txid_hex,
                        raw_funding_tx.len(),
                        selected.len()
                    );

                    // 1f. Broadcast via mempool.
                    let mempool =
                        match super::mempool_api::MempoolClient::from_config_for_network(network) {
                            Ok(c) => c,
                            Err(e) => return err(format!("mempool client init: {e}")),
                        };
                    if let Err(e) = mempool.broadcast_tx_raw(&raw_funding_tx).await {
                        return err(format!(
                            "bitcoin.deposit.fund_and_broadcast: mempool broadcast failed: {e}"
                        ));
                    }
                }

                // Update vault record: store funding_txid + advance state to AwaitingConfirmation
                {
                    let mut ops = self.bitcoin_tap.pending_ops().write().await;
                    if let Some(rec) = ops.get_mut(&vault_op_id) {
                        rec.funding_txid = Some(funding_txid_hex.clone());
                        rec.state = crate::sdk::bitcoin_tap_sdk::VaultOpState::AwaitingConfirmation;
                        let persisted =
                            crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::to_persisted_vault_record(
                                rec,
                            );
                        if let Err(e) = crate::storage::client_db::upsert_vault_record(&persisted) {
                            log::error!("[bitcoin.deposit.fund_and_broadcast] CRITICAL: failed to persist vault record: {e}");
                        }
                    }
                }

                log::info!(
                    "[FUND_AND_BROADCAST] Broadcast OK → txid={} for deposit {}",
                    funding_txid_hex,
                    vault_op_id
                );

                let resp = generated::AppStateResponse {
                    key: "fund_and_broadcast".to_string(),
                    value: Some(funding_txid_hex),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- Universal: await confirmations + complete deposit --------
            "bitcoin.deposit.await_and_complete" => {
                let vault_op_id = match generated::ArgPack::decode(&*i.args) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::DepositRefundRequest::decode(&*pack.body) {
                            Ok(req) if !req.vault_op_id.is_empty() => req.vault_op_id,
                            _ => return err("bitcoin.deposit.await_and_complete: expected DepositRefundRequest with non-empty vault_op_id".into()),
                        }
                    }
                    _ => return err("bitcoin.deposit.await_and_complete: expected ArgPack(codec=PROTO)".into()),
                };

                let record = match self.bitcoin_tap.get_vault_record(&vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: deposit not found: {e}"
                        ))
                    }
                };

                let funding_txid_hex = match &record.funding_txid {
                    Some(t) if !t.is_empty() => t.clone(),
                    _ => return err("bitcoin.deposit.await_and_complete: no funding_txid — call fund_and_broadcast first".into()),
                };

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                log::info!(
                    "[AWAIT_AND_COMPLETE] Deposit {} → waiting for confirmations on txid {} (network={:?})",
                    vault_op_id, funding_txid_hex, network
                );

                // ── Wait for confirmations + build SPV proof ──

                let resolved = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
                let mut effective_min_conf = resolved.min_confirmations;

                // The vault stores its own min_confirmations (set at creation time).
                // The runtime config may differ, so always prefer the vault's value
                // to ensure header_chain.len() + 1 >= vault.min_confirmations in
                // verify_bitcoin_htlc (dBTC §6.4).
                if let Some(vault_id) = &record.vault_id {
                    match self.bitcoin_tap.dlv_manager().get_vault(vault_id).await {
                        Ok(vault_lock) => {
                            let vault = vault_lock.lock().await;
                            if let dsm::vault::fulfillment::FulfillmentMechanism::BitcoinHTLC {
                                min_confirmations,
                                ..
                            } = &vault.fulfillment_condition
                            {
                                log::info!(
                                    "[AWAIT_AND_COMPLETE] Vault {} min_confirmations={}, params={}",
                                    vault_id,
                                    min_confirmations,
                                    effective_min_conf
                                );
                                effective_min_conf = *min_confirmations;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "[AWAIT_AND_COMPLETE] Could not load vault {}: {} — using params.min_confirmations={}",
                                vault_id, e, effective_min_conf
                            );
                        }
                    }
                }

                let (txid_bytes, spv_proof, block_header, raw_tx, header_chain): (
                    [u8; 32],
                    Vec<u8>,
                    [u8; 80],
                    Vec<u8>,
                    Vec<[u8; 80]>,
                );

                let mempool =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => return err(format!("mempool client init: {e}")),
                    };

                // Single non-blocking confirmation check (frontend polls separately)
                let tx_status = match mempool.tx_status(&funding_txid_hex).await {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: tx_status failed: {e}"
                        ))
                    }
                };
                let confs = if tx_status.confirmed {
                    if let Some(bh) = tx_status.block_height {
                        match mempool.chain_tip_height().await {
                            Ok(tip) => tip.saturating_sub(bh) + 1,
                            Err(_) => 1,
                        }
                    } else {
                        1
                    }
                } else {
                    0
                };
                let observation = BitcoinSettlementObservation {
                    network,
                    bitcoin_spend_observed: tx_status.confirmed,
                    confirmation_depth: confs,
                    min_confirmations: effective_min_conf,
                };
                if !observation.meets_confirmation_gate() {
                    return err(format!(
                        "bitcoin.deposit.await_and_complete: not enough confirmations ({confs}/{}). Try again later.",
                        effective_min_conf
                    ));
                }
                log::info!(
                    "[AWAIT_AND_COMPLETE] txid {} has {confs}/{} confirmations — proceeding",
                    funding_txid_hex,
                    effective_min_conf
                );

                raw_tx = match mempool.raw_tx_bytes(&funding_txid_hex).await {
                    Ok(b) => b,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: get raw tx failed: {e}"
                        ))
                    }
                };

                let (tb, sp, bh) = match mempool.build_spv_proof(&funding_txid_hex).await {
                    Ok(v) => v,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: SPV proof failed: {e}"
                        ))
                    }
                };
                txid_bytes = tb;
                spv_proof = sp;
                block_header = bh;

                let status = match mempool.tx_status(&funding_txid_hex).await {
                    Ok(s) => s,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: tx status failed: {e}"
                        ))
                    }
                };
                let base_height = status.block_height.unwrap_or(0);
                let extra = effective_min_conf.saturating_sub(1);
                header_chain = match mempool.fetch_header_chain(base_height + 1, extra).await {
                    Ok(h) => h,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.deposit.await_and_complete: header chain failed: {e}"
                        ))
                    }
                };

                log::info!(
                    "[AWAIT_AND_COMPLETE] Built SPV proof + {} confirmation headers for deposit {}",
                    header_chain.len(),
                    vault_op_id
                );

                // ── Step 3: Get preimage + state + keys for completion ──

                let preimage = match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage(&record) {
                    Ok(p) => p,
                    Err(e) => return err(format!(
                        "bitcoin.deposit.await_and_complete: cannot derive preimage for {vault_op_id}: {e}"
                    )),
                };
                let prep = match self
                    .prepare_deposit_completion_prep(
                        "bitcoin.deposit.await_and_complete",
                        &vault_op_id,
                        self.device_id_bytes,
                    )
                    .await
                {
                    Ok(p) => p,
                    Err(e) => return err(e),
                };
                let device_id_bytes = self.device_id_bytes;

                // ── Step 4: Complete the deposit ──

                match self
                    .bitcoin_tap
                    .draw_tap(
                        &vault_op_id,
                        &preimage,
                        txid_bytes,
                        &raw_tx,
                        &spv_proof,
                        block_header,
                        &header_chain,
                        &prep.requester_key,
                        &prep.signing_public_key,
                        prep.recipient,
                        &prep.current_state,
                        Some(prep.receipt_bytes),
                        Some(prep.stitched_receipt_sigma),
                    )
                    .await
                {
                    Ok(completion) => {
                        // Apply DLV unlock operation only for withdrawals (dBTC→BTC).
                        if let Some(unlock_op) = completion.dlv_unlock_operation.clone() {
                            let signed_unlock_op = match self.core_sdk.sign_operation_sphincs(unlock_op) {
                                Ok(op) => op,
                                Err(e) => return err(format!("bitcoin.deposit.await_and_complete: failed to sign DLV unlock op: {e}")),
                            };
                            let unlock_applied_state = match self.core_sdk.execute_dsm_operation(signed_unlock_op) {
                                Ok(s) => s,
                                Err(e) => return err(format!("bitcoin.deposit.await_and_complete: failed to apply DLV unlock op: {e}")),
                            };
                            if unlock_applied_state.hash.len() == 32 {
                                if let Err(e) = crate::get_sdk_context()
                                    .update_chain_tip(unlock_applied_state.hash.to_vec())
                                {
                                    log::warn!("[AWAIT_AND_COMPLETE] failed to update chain_tip after DLV unlock: {e}");
                                }
                            }
                        }

                        // Fractional successors: the dBTC balance already has
                        // the remainder (bitcoin.fractional.exit Phase 4 only
                        // burned the exit amount). Skip the Mint to avoid
                        // double-crediting. DLV unlock above still activates
                        // the successor vault.
                        if record.is_fractional_successor {
                            log::info!(
                                "[AWAIT_AND_COMPLETE] Fractional successor {} — skipping token \
                                 Mint (balance already has remainder). Vault activated via DLV unlock.",
                                vault_op_id,
                            );
                        } else {
                            // Execute token operation once: if pre-applied during canonical prep,
                            // reuse it; otherwise apply completion token operation now.
                            let (effective_token_op, applied_state) = if let (
                                Some(op),
                                Some(state),
                            ) = (
                                prep.pre_applied_token_op.clone(),
                                prep.pre_applied_token_state.clone(),
                            ) {
                                (op, state)
                            } else {
                                let completion_op = completion.token_operation.clone();
                                match self
                                        .wallet
                                        .execute_token_operation(completion_op.clone())
                                        .await
                                    {
                                        Ok(state) => (completion_op, state),
                                        Err(e) => {
                                            return err(format!(
                                    "bitcoin.deposit.await_and_complete: token operation failed: {e}"
                                ))
                                        }
                                    }
                            };

                            if applied_state.hash.len() == 32 {
                                if let Err(e) = crate::get_sdk_context()
                                    .update_chain_tip(applied_state.hash.to_vec())
                                {
                                    log::warn!(
                                        "[AWAIT_AND_COMPLETE] Failed to update chain_tip: {e}"
                                    );
                                }
                            }

                            // Sync dBTC balance to SQLite
                            {
                                let dev =
                                    crate::util::text_id::encode_base32_crockford(&device_id_bytes);
                                let dbtc_id = crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID;
                                let (current_sqlite, existing_locked) =
                                    match crate::storage::client_db::get_token_balance(
                                        &dev, dbtc_id,
                                    ) {
                                        Ok(Some((a, l))) => (a, l),
                                        Ok(None) => (0, 0),
                                        Err(e) => {
                                            return err(format!(
                                                "bitcoin.deposit.await_and_complete: failed to read dBTC balance: {e}"
                                            ));
                                        }
                                    };
                                let new_sqlite = match &effective_token_op {
                                    dsm::types::token_types::TokenOperation::Burn {
                                        amount,
                                        ..
                                    } => {
                                        if current_sqlite < *amount {
                                            return err(format!(
                                                    "bitcoin.deposit.await_and_complete: dBTC sqlite underflow: current={} burn={}",
                                                    current_sqlite, amount
                                                ));
                                        }
                                        current_sqlite - *amount
                                    }
                                    dsm::types::token_types::TokenOperation::Mint {
                                        amount,
                                        ..
                                    } => current_sqlite.saturating_add(*amount),
                                    _ => current_sqlite,
                                };
                                if let Err(e) = crate::storage::client_db::upsert_token_balance(
                                    &dev,
                                    dbtc_id,
                                    new_sqlite,
                                    existing_locked,
                                ) {
                                    return err(format!(
                                        "bitcoin.deposit.await_and_complete: failed to persist dBTC balance: {e}"
                                    ));
                                }
                                log::info!(
                                    "[AWAIT_AND_COMPLETE] dBTC SQLite balance: {} → {} (deposit={})",
                                    current_sqlite,
                                    new_sqlite,
                                    completion.vault_op_id
                                );
                            }

                            // Record transaction in history
                            {
                                let my_device_id_str =
                                    crate::util::text_id::encode_base32_crockford(&device_id_bytes);
                                let (tx_type_str, token_id, amount, from_dev, to_dev) =
                                    match &effective_token_op {
                                        dsm::types::token_types::TokenOperation::Mint {
                                            amount,
                                            ..
                                        } => (
                                            "dbtc_mint",
                                            "dBTC",
                                            *amount,
                                            "BITCOIN_NETWORK".to_string(),
                                            my_device_id_str.clone(),
                                        ),
                                        dsm::types::token_types::TokenOperation::Burn {
                                            amount,
                                            ..
                                        } => (
                                            "dbtc_burn",
                                            "dBTC",
                                            *amount,
                                            my_device_id_str.clone(),
                                            "BITCOIN_NETWORK".to_string(),
                                        ),
                                        _ => ("token_op", "dBTC", 0, String::new(), String::new()),
                                    };
                                let tx_hash_txt = crate::util::text_id::encode_base32_crockford(
                                    &applied_state.hash,
                                );
                                let mut metadata = std::collections::HashMap::new();
                                metadata.insert(
                                    "vault_op_id".to_string(),
                                    completion.vault_op_id.as_bytes().to_vec(),
                                );
                                metadata
                                    .insert("token_id".to_string(), token_id.as_bytes().to_vec());
                                metadata.insert(
                                    "funding_txid".to_string(),
                                    funding_txid_hex.as_bytes().to_vec(),
                                );
                                let rec = crate::storage::client_db::TransactionRecord {
                                    tx_id: format!("deposit_{}", completion.vault_op_id),
                                    tx_hash: tx_hash_txt,
                                    from_device: from_dev,
                                    to_device: to_dev,
                                    amount,
                                    tx_type: tx_type_str.to_string(),
                                    status: "completed".to_string(),
                                    chain_height: applied_state.state_number,
                                    step_index: 0,
                                    commitment_hash: Some(applied_state.hash.to_vec()),
                                    proof_data: build_online_receipt(
                                        &applied_state,
                                        &device_id_bytes,
                                        &device_id_bytes,
                                        crate::sdk::app_state::AppState::get_device_tree_root(),
                                    ),
                                    metadata,
                                    created_at: crate::util::deterministic_time::tick(),
                                };
                                if let Err(e) = crate::storage::client_db::store_transaction(&rec) {
                                    log::warn!(
                                        "[AWAIT_AND_COMPLETE] failed to record tx history: {e}"
                                    );
                                }
                            }
                        } // end !is_fractional_successor

                        // ── Store entry_txid as raw bytes (§8 Definition 9) ──
                        // txid_bytes is [u8; 32] from SPV proof (internal byte order).
                        // No hex touches DSM internals. This must happen BEFORE vault
                        // publication so the advertisement carries the correct entry_txid.
                        if let Err(e) = crate::storage::client_db::update_vault_record_entry_txid(
                            &vault_op_id,
                            &txid_bytes,
                        ) {
                            log::warn!("[AWAIT_AND_COMPLETE] failed to store entry_txid: {e}");
                        }
                        self.bitcoin_tap
                            .update_vault_record_entry_txid_in_memory(
                                &vault_op_id,
                                txid_bytes.to_vec(),
                            )
                            .await;

                        // dBTC §4 step 8: re-publish vault advertisement now that
                        // entry_txid + lifecycle_state are finalized after draw_tap().
                        if let Err(e) = self
                            .bitcoin_tap
                            .publish_vault_advertisement_mandatory(&completion.vault_id)
                            .await
                        {
                            log::error!(
                                "[AWAIT_AND_COMPLETE] CRITICAL: failed to re-publish vault ad \
                                 after activation for vault {}: {e}",
                                &completion.vault_id[..completion.vault_id.len().min(12)],
                            );
                        }

                        log::info!(
                            "[AWAIT_AND_COMPLETE] Deposit {} completed. funding_txid={}",
                            completion.vault_op_id,
                            funding_txid_hex
                        );
                        let resp = generated::AppStateResponse {
                            key: "await_and_complete".to_string(),
                            value: Some(format!(
                                "Deposit {} completed. Funding txid: {}",
                                completion.vault_op_id, funding_txid_hex
                            )),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!(
                        "bitcoin.deposit.await_and_complete: draw_tap failed: {e}"
                    )),
                }
            }

            // -------- Exit deposit completion (dBTC §6.4.3 — exit anchor) --------
            //
            // For dbtc_to_btc exit deposits (fractional or full sweep), once the
            // sweep tx is buried under min_confirmations blocks, call this to:
            //   1. Verify the confirmation depth via mempool.space
            //   2. Fetch the block header at the confirmed height (exit anchor)
            //   3. Persist exit_header + exit_confirm_depth on the vault record
            //   4. Transition deposit state → Completed
            //
            // This is the exit-side counterpart of `bitcoin.deposit.await_and_complete`
            // (which handles deposit-side SPV proof + DLV unlock + token mint).
            "bitcoin.exit.complete" => {
                let vault_op_id = match generated::ArgPack::decode(&*i.args) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::DepositRefundRequest::decode(&*pack.body) {
                            Ok(req) if !req.vault_op_id.is_empty() => req.vault_op_id,
                            _ => return err("bitcoin.exit.complete: expected vault_op_id".into()),
                        }
                    }
                    _ => return err("bitcoin.exit.complete: expected ArgPack(codec=PROTO)".into()),
                };

                let record = match self.bitcoin_tap.get_vault_record(&vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.exit.complete: deposit not found: {e}")),
                };

                // Verify this is an exit deposit
                if record.direction != crate::sdk::bitcoin_tap_sdk::VaultDirection::DbtcToBtc {
                    return err(format!(
                        "bitcoin.exit.complete: deposit {} is not a dbtc_to_btc exit",
                        vault_op_id
                    ));
                }

                let funding_txid_hex = match &record.funding_txid {
                    Some(t) if !t.is_empty() => t.clone(),
                    _ => {
                        return err(
                            "bitcoin.exit.complete: no funding_txid (sweep not yet broadcast)"
                                .into(),
                        )
                    }
                };

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let mempool =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!("bitcoin.exit.complete: mempool client init: {e}"))
                        }
                    };

                let params = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
                let required = params.min_confirmations;

                let status = match mempool.tx_status(&funding_txid_hex).await {
                    Ok(s) => s,
                    Err(e) => return err(format!("bitcoin.exit.complete: tx_status failed: {e}")),
                };

                let confs = if status.confirmed {
                    if let Some(block_height) = status.block_height {
                        match mempool.chain_tip_height().await {
                            Ok(tip) => tip.saturating_sub(block_height) + 1,
                            Err(_) => 1,
                        }
                    } else {
                        1
                    }
                } else {
                    0
                };

                let observation = BitcoinSettlementObservation {
                    network,
                    bitcoin_spend_observed: status.confirmed,
                    confirmation_depth: confs,
                    min_confirmations: required,
                };
                if !observation.meets_confirmation_gate() {
                    return err(format!(
                        "bitcoin.exit.complete: not enough confirmations ({confs}/{required}). Try again later."
                    ));
                }

                // Fetch the exit anchor block header (dBTC §6.4.3)
                let exit_header: [u8; 80] = if let Some(bh) = status.block_height {
                    match mempool.block_hash_at_height(bh).await {
                        Ok(hash) => match mempool.block_header_raw(&hash).await {
                            Ok(hdr) => hdr,
                            Err(e) => {
                                log::warn!("[EXIT_COMPLETE] block_header_raw failed: {e}");
                                [0u8; 80]
                            }
                        },
                        Err(e) => {
                            log::warn!("[EXIT_COMPLETE] block_hash_at_height({bh}) failed: {e}");
                            [0u8; 80]
                        }
                    }
                } else {
                    [0u8; 80]
                };

                // Persist exit anchor on the vault record
                if let Err(e) = self
                    .bitcoin_tap
                    .update_vault_record_exit_anchor(&vault_op_id, exit_header, confs as u32)
                    .await
                {
                    log::warn!("[EXIT_COMPLETE] failed to persist exit anchor: {e}");
                }

                // Transition deposit state → Completed
                if let Err(e) =
                    crate::storage::client_db::update_vault_record_state(&vault_op_id, "completed")
                {
                    log::warn!("[EXIT_COMPLETE] failed to update DB deposit state: {e}");
                }
                self.bitcoin_tap
                    .update_vault_record_state_in_memory(
                        &vault_op_id,
                        crate::sdk::bitcoin_tap_sdk::VaultOpState::Completed,
                        String::new(),
                    )
                    .await;

                // §10.4 Step 7 + §7 Remark 2: publish the successor vault advertisement now
                // that the sweep tx has reached dmin confirmations.
                // entry_txid on the successor = txid(txsweep) in internal byte order.
                let source_vault_id_str =
                    record.vault_id.as_deref().unwrap_or_default().to_string();
                if !source_vault_id_str.is_empty() {
                    let sweep_txid_internal =
                        crate::sdk::bitcoin_tx_builder::display_txid_to_internal(&funding_txid_hex);
                    let device_id_bytes = crate::get_sdk_context().device_id_array();
                    if let Err(e) = self
                        .bitcoin_tap
                        .update_successor_entry_txid_and_publish_ad(
                            &source_vault_id_str,
                            &sweep_txid_internal,
                            &device_id_bytes,
                        )
                        .await
                    {
                        log::warn!(
                            "[EXIT_COMPLETE] successor ad update skipped for parent vault \
                             {source_vault_id_str}: {e}"
                        );
                    }
                }

                log::info!(
                    "[EXIT_COMPLETE] Exit deposit {} completed. {} confirmations, txid={}",
                    vault_op_id,
                    confs,
                    funding_txid_hex
                );

                let resp = generated::AppStateResponse {
                    key: "exit_complete".to_string(),
                    value: Some(format!(
                        "Exit deposit {} completed with {} confirmations. txid: {}",
                        vault_op_id, confs, funding_txid_hex
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            // -------- Withdrawal settlement tracker (dBTC paper §13) --------
            //
            // Checks unresolved in-flight withdrawals for this device.
            // For each withdrawal with recorded sweep txid(s), queries Bitcoin
            // for confirmation depth. If all recorded txids reach d_min, the
            // withdrawal is finalized. Missing txids or API errors remain pending.
            //
            // SAFETY (dBTC §13.1, Definition 15, Property 9 — No Stranded Value):
            // The settlement monitor is FAIL-CLOSED: it never emits a compensating
            // dBTC unlock or credit based on missing metadata or transient API errors.
            // - Withdrawals with no recorded txid → pending (not refunded).
            // - API / network errors on tx_status → pending (not refunded).
            // - Exceeded poll budget → warning logged, remains pending (not refunded).
            // Only positive confirmation at d_min against all recorded txids triggers
            // the deferred burn (resolve_pending_withdrawals_with_client). This ensures
            // the refund condition is "fail-before-settlement" (FailBeforeSettlement(ρ))
            // not "local metadata missing" or "external API errored", consistent with
            // the paper. See audit finding §2 (Critical), which documented a prior
            // auto-refund path that has since been removed.
            "bitcoin.withdraw.settle" => {
                let device_id_str =
                    crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                let unresolved =
                    match crate::storage::client_db::list_unresolved_withdrawals(&device_id_str) {
                        Ok(v) => v,
                        Err(e) => return err(format!("bitcoin.withdraw.settle: list failed: {e}")),
                    };

                if unresolved.is_empty() {
                    let resp = generated::AppStateResponse {
                        key: "withdraw_settle".to_string(),
                        value: Some("No committed withdrawals to finalize".to_string()),
                    };
                    return pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp));
                }

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                let mempool =
                    match super::mempool_api::MempoolClient::from_config_for_network(network) {
                        Ok(c) => c,
                        Err(e) => {
                            return err(format!(
                                "bitcoin.withdraw.settle: mempool client init: {e}"
                            ))
                        }
                    };

                let params = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
                let required = params.min_confirmations;
                let summary = self
                    .resolve_pending_withdrawals_with_client(
                        &unresolved,
                        &mempool,
                        network,
                        required,
                        "withdraw.settle",
                    )
                    .await;

                let resp = generated::AppStateResponse {
                    key: "withdraw_settle".to_string(),
                    value: Some(format!(
                        "Checked {} withdrawal(s): {} finalized, {} pending",
                        unresolved.len(),
                        summary.finalized,
                        summary.pending
                    )),
                };
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
            }

            "bitcoin.sweep.recover" => {
                // Crash recovery: reconstruct and broadcast sweep for an orphaned fractional successor.
                // The burn already happened but the sweep was never broadcast (device died, network issue, etc).
                let vault_op_id = match generated::ArgPack::decode(&*i.args) {
                    Ok(pack) if pack.codec == generated::Codec::Proto as i32 => {
                        match generated::DepositRefundRequest::decode(&*pack.body) {
                            Ok(req) if !req.vault_op_id.is_empty() => req.vault_op_id,
                            _ => return err("bitcoin.sweep.recover: expected DepositRefundRequest with non-empty vault_op_id".into()),
                        }
                    }
                    _ => return err("bitcoin.sweep.recover: expected ArgPack(codec=PROTO)".into()),
                };

                let record = match self.bitcoin_tap.get_vault_record(&vault_op_id).await {
                    Ok(r) => r,
                    Err(e) => return err(format!("bitcoin.sweep.recover: deposit not found: {e}")),
                };

                if !record.is_fractional_successor {
                    return err(
                        "bitcoin.sweep.recover: deposit is not a fractional successor".into(),
                    );
                }
                if record.funding_txid.is_some() {
                    return err(
                        "bitcoin.sweep.recover: sweep already broadcast (funding_txid is set)"
                            .into(),
                    );
                }
                let parent_vault_id = match &record.parent_vault_id {
                    Some(id) => id.clone(),
                    None => return err("bitcoin.sweep.recover: no parent_vault_id".into()),
                };

                let network = match crate::storage::client_db::list_bitcoin_accounts() {
                    Ok(accounts) => accounts
                        .into_iter()
                        .find(|a| a.active)
                        .map(|a| Self::bitcoin_network_from_u32(a.network))
                        .unwrap_or_else(
                            crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network,
                        ),
                    Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
                };

                // Fetch source vault data from storage nodes.
                let exec_data = match self
                    .bitcoin_tap
                    .fetch_vault_execution_data(&parent_vault_id)
                    .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        return err(format!(
                            "bitcoin.sweep.recover: fetch vault data from storage nodes failed: {e}"
                        ))
                    }
                };

                let remainder_sats = record.btc_amount_sats;
                let exit_sats = exec_data.amount_sats.saturating_sub(remainder_sats);

                let bitcoin_tap_clone = self.bitcoin_tap.clone();
                let bitcoin_keys_clone = Arc::clone(&self.bitcoin_keys);
                let successor_vault_op_id = vault_op_id.clone();

                let result = sweep_and_broadcast(SweepBroadcastRequest {
                    bitcoin_tap: &bitcoin_tap_clone,
                    bitcoin_keys: &bitcoin_keys_clone,
                    source_exec_data: &exec_data,
                    successor_vault_op_id: &successor_vault_op_id,
                    exit_sats,
                    remainder_sats,
                    dest_addr: "",
                    successor_htlc_script: record.htlc_script.as_deref().unwrap_or(&[]),
                    network,
                })
                .await;

                match result {
                    Ok(txid) => {
                        let resp = generated::AppStateResponse {
                            key: "sweep_recovered_txid".to_string(),
                            value: Some(txid),
                        };
                        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
                    }
                    Err(e) => err(format!("bitcoin.sweep.recover: {e}")),
                }
            }

            other => err(format!("unknown bitcoin invoke method: {other}")),
        }
    }

    /// Auto-check pending withdrawals on any online-connected lifecycle event.
    ///
    /// This is piggybacked on balance queries so that every time the wallet screen
    /// loads, the SDK refreshes settlement status for withdrawals with recorded
    /// Bitcoin execution. Absence of chain data never produces compensation.
    pub(crate) async fn auto_resolve_pending_withdrawals(&self) {
        let device_id_str = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);

        let unresolved =
            match crate::storage::client_db::list_unresolved_withdrawals(&device_id_str) {
                Ok(v) if !v.is_empty() => v,
                _ => return, // Nothing to resolve or DB error — silent return
            };

        log::info!(
            "[auto-resolve] found {} unresolved withdrawal(s), checking Bitcoin status",
            unresolved.len()
        );

        let network = match crate::storage::client_db::list_bitcoin_accounts() {
            Ok(accounts) => accounts
                .into_iter()
                .find(|a| a.active)
                .map(|a| Self::bitcoin_network_from_u32(a.network))
                .unwrap_or_else(crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network),
            Err(_) => crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network(),
        };

        let mempool = match super::mempool_api::MempoolClient::from_config_for_network(network) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[auto-resolve] mempool client init failed, skipping: {e}");
                return;
            }
        };

        let params = crate::sdk::bitcoin_tap_sdk::DbtcParams::resolve();
        let required = params.min_confirmations;
        let summary = self
            .resolve_pending_withdrawals_with_client(
                &unresolved,
                &mempool,
                network,
                required,
                "auto-resolve",
            )
            .await;
        log::info!(
            "[auto-resolve] checked {} withdrawal(s): {} finalized, {} pending",
            unresolved.len(),
            summary.finalized,
            summary.pending
        );
    }
}

/// Build and broadcast the sweep-and-change tx via mempool.space.
///
/// This is the production sweep path used by `bitcoin.fractional.exit`.
/// It:
/// 1. Looks up the source vault record (parent vault's HTLC script, address, preimage)
/// 2. Finds the source HTLC UTXO on-chain via mempool.space
/// 3. Builds the sweep-and-change tx (Output 0 → wallet, Output 1 → successor HTLC)
/// 4. Broadcasts via mempool.space `POST /api/tx`
/// 5. Updates the successor vault record with the broadcast txid
async fn sweep_and_broadcast(req: SweepBroadcastRequest<'_>) -> Result<String, String> {
    let SweepBroadcastRequest {
        bitcoin_tap,
        bitcoin_keys,
        source_exec_data,
        successor_vault_op_id,
        exit_sats,
        remainder_sats: _remainder_sats,
        dest_addr,
        successor_htlc_script,
        network,
    } = req;

    // All source vault data comes from storage node advertisement.
    let htlc_script = &source_exec_data.htlc_script;
    let htlc_address = &source_exec_data.htlc_address;
    let preimage = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage_from_deposit_nonce(
        &source_exec_data.deposit_nonce,
        &source_exec_data.policy_commit,
    )
    .map_err(|e| format!("derive preimage: {e}"))?;
    let total_sats = source_exec_data.amount_sats;

    // Query mempool.space for source HTLC UTXO
    let mempool = super::mempool_api::MempoolClient::from_config_for_network(network)
        .map_err(|e| format!("mempool client init: {e}"))?;

    let utxos = mempool
        .list_address_utxos(std::slice::from_ref(htlc_address))
        .await
        .map_err(|e| format!("source HTLC UTXO lookup: {e}"))?;

    let utxo = utxos
        .first()
        .ok_or_else(|| format!("no UTXO found at source HTLC address {htlc_address}"))?;

    let utxo_txid_bytes = super::mempool_api::hex_to_bytes(&utxo.txid)
        .map_err(|e| format!("parse utxo txid: {e}"))?;
    if utxo_txid_bytes.len() != 32 {
        return Err(format!("utxo txid not 32 bytes: {}", utxo_txid_bytes.len()));
    }
    let mut outpoint_txid = [0u8; 32];
    for (i, b) in utxo_txid_bytes.iter().enumerate() {
        outpoint_txid[31 - i] = *b;
    }

    // Resolve destination address
    let resolved_dest = if !dest_addr.is_empty() {
        dest_addr.to_string()
    } else {
        let locked = bitcoin_keys.lock().await;
        let db_floor = crate::storage::client_db::get_active_bitcoin_account()
            .ok()
            .flatten()
            .map(|a| a.active_receive_index)
            .unwrap_or(0);
        let wallet_idx = locked.current_receive_index().max(db_floor);
        let (addr, _) = locked
            .peek_receive_address(wallet_idx)
            .map_err(|e| format!("wallet address derivation: {e}"))?;
        drop(locked);
        addr
    };

    // Build sweep-and-change tx
    let lib_network = network.to_bitcoin_network();
    let sweep_tx = crate::sdk::bitcoin_tx_builder::build_sweep_and_change_tx(
        &crate::sdk::bitcoin_tx_builder::SweepTxParams {
            outpoint_txid: &outpoint_txid,
            outpoint_vout: utxo.vout,
            htlc_script,
            preimage: &preimage,
            dest_addr: &resolved_dest,
            claim_sats: exit_sats,
            successor_htlc_script,
            total_sats,
            fee_rate_sat_vb: crate::sdk::bitcoin_tap_sdk::withdrawal_fee_rate_sat_vb(),
            signer: crate::sdk::bitcoin_tx_builder::HtlcSpendSigner::MathOwned {
                hash_lock: &source_exec_data.hash_lock,
            },
            network: lib_network,
        },
    )
    .map_err(|e| format!("build sweep tx: {e}"))?;

    // Broadcast via mempool.space
    let raw_bytes = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&sweep_tx);
    let txid = mempool
        .broadcast_tx_raw(&raw_bytes)
        .await
        .map_err(|e| format!("broadcast sweep tx: {e}"))?;

    log::info!(
        "[BITCOIN sweep] Broadcast sweep tx: {txid} (source_vault={}, successor={successor_vault_op_id})",
        source_exec_data.vault_id,
    );

    // Update successor vault record with funding_txid
    if let Err(e) = bitcoin_tap
        .update_vault_record_funding_txid(successor_vault_op_id, &txid)
        .await
    {
        log::warn!("[BITCOIN sweep] Failed to update successor funding_txid: {e}");
    }

    // Mark source vault as spent on storage nodes.
    // The sweep consumed the source UTXO. Future planners skip it.
    if let Err(e) = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::mark_vault_spent_on_storage_nodes(
        &source_exec_data.vault_id,
    )
    .await
    {
        log::warn!("[BITCOIN sweep] mark_vault_spent failed: {e}");
    }

    Ok(txid)
}

/// Attempt to build + broadcast a claim tx for a full-sweep exit.
///
/// Used by both `bitcoin.full.sweep` (Phase 5) and `check_confirmations`
/// (auto-retry when `funding_txid` is missing on a DbtcToBtc exit).
/// On success, updates the vault record's `funding_txid` in both memory and SQLite.
pub(super) async fn try_claim_full_sweep_exit(
    bitcoin_tap: &std::sync::Arc<crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk>,
    vault_op_id: &str,
    record: &crate::sdk::bitcoin_tap_sdk::VaultOperation,
    network: dsm::bitcoin::types::BitcoinNetwork,
    expected_policy_commit: Option<[u8; 32]>,
) -> Result<String, String> {
    let vault_id = record
        .vault_id
        .as_deref()
        .ok_or("exit deposit has no vault_id")?;

    // Fetch execution data from storage nodes.
    let exec_data = bitcoin_tap
        .fetch_vault_execution_data(vault_id)
        .await
        .map_err(|e| format!("fetch vault data from storage nodes: {e}"))?;
    if let Some(expected_policy_commit) = expected_policy_commit {
        ensure_policy_commit_match(
            "bitcoin.deposit.check_confirmations",
            "full-sweep auto-claim",
            &expected_policy_commit,
            &exec_data.policy_commit,
        )?;
    }

    let preimage = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::derive_preimage_from_deposit_nonce(
        &exec_data.deposit_nonce,
        &exec_data.policy_commit,
    )
    .map_err(|e| format!("derive preimage: {e}"))?;

    let dest = record
        .destination_address
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(|d| d.to_string())
        .ok_or("exit deposit has no destination_address")?;

    let mempool = super::mempool_api::MempoolClient::from_config_for_network(network)
        .map_err(|e| format!("mempool client init: {e}"))?;
    let utxos = mempool
        .list_address_utxos(std::slice::from_ref(&exec_data.htlc_address))
        .await
        .map_err(|e| format!("HTLC UTXO lookup: {e}"))?;
    let utxo = utxos
        .first()
        .ok_or_else(|| format!("no UTXO at HTLC address {}", exec_data.htlc_address))?;

    let utxo_txid_bytes = super::mempool_api::hex_to_bytes(&utxo.txid)
        .map_err(|e| format!("parse utxo txid: {e}"))?;
    if utxo_txid_bytes.len() != 32 {
        return Err(format!("utxo txid not 32 bytes: {}", utxo_txid_bytes.len()));
    }
    let mut outpoint_txid = [0u8; 32];
    for (i, b) in utxo_txid_bytes.iter().enumerate() {
        outpoint_txid[31 - i] = *b;
    }

    let lib_network = network.to_bitcoin_network();
    let claim_tx = crate::sdk::bitcoin_tx_builder::build_htlc_claim_tx(
        &crate::sdk::bitcoin_tx_builder::ClaimTxParams {
            outpoint_txid: &outpoint_txid,
            outpoint_vout: utxo.vout,
            htlc_script: &exec_data.htlc_script,
            preimage: &preimage,
            destination_addr: &dest,
            amount_sats: exec_data.amount_sats,
            fee_rate_sat_vb: crate::sdk::bitcoin_tap_sdk::withdrawal_fee_rate_sat_vb(),
            signer: crate::sdk::bitcoin_tx_builder::HtlcSpendSigner::MathOwned {
                hash_lock: &exec_data.hash_lock,
            },
            network: lib_network,
        },
    )
    .map_err(|e| format!("build_htlc_claim_tx: {e}"))?;

    let raw = crate::sdk::bitcoin_tx_builder::serialize_raw_tx(&claim_tx);
    let txid = mempool
        .broadcast_tx_raw(&raw)
        .await
        .map_err(|e| format!("broadcast claim tx: {e}"))?;

    log::info!(
        "[try_claim_full_sweep_exit] Broadcast claim tx: {txid} for exit deposit {vault_op_id}"
    );

    if let Err(e) = bitcoin_tap
        .update_vault_record_funding_txid(vault_op_id, &txid)
        .await
    {
        log::error!("[try_claim_full_sweep_exit] failed to persist funding_txid: {e}");
    }
    if let Err(e) = crate::storage::client_db::update_vault_record_funding_txid(vault_op_id, &txid)
    {
        log::error!("[try_claim_full_sweep_exit] failed to persist funding_txid in SQLite: {e}");
    }

    Ok(txid)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use prost::Message;
    use serial_test::serial;

    use super::*;
    use crate::bridge::{AppInvoke, AppQuery, AppRouter as _};
    use crate::handlers::bitcoin_helpers::set_withdrawal_bridge_sync_test_results;
    use crate::init::SdkConfig;
    use crate::storage::client_db;

    fn init_withdrawal_invoke_test_router(test_name: &str) -> AppRouterImpl {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(PathBuf::from(format!(
            "./.dsm_testdata_{test_name}"
        )));
        crate::sdk::app_state::AppState::set_identity_info(
            vec![0xA1; 32],
            vec![0xB1; 32],
            vec![0xC1; 32],
            vec![0xD1; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        client_db::init_database().expect("init db");
        set_withdrawal_bridge_sync_test_results(Vec::new());
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reset_dbtc_storage_test_state();
        set_withdrawal_execution_test_expectations(Vec::new());

        AppRouterImpl::new(SdkConfig {
            node_id: format!("withdraw-invoke-{test_name}"),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn pack_proto<T: Message>(message: &T) -> Vec<u8> {
        generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body: message.encode_to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn decode_framed_envelope(bytes: &[u8], route: &str) -> generated::Envelope {
        assert!(!bytes.is_empty(), "{route}: empty response bytes");
        assert_eq!(bytes[0], 0x03, "{route}: expected FramedEnvelopeV3 prefix");
        generated::Envelope::decode(&bytes[1..])
            .unwrap_or_else(|e| panic!("{route}: failed to decode envelope: {e}"))
    }

    fn sync_response(success: bool, pulled: u32) -> generated::StorageSyncResponse {
        generated::StorageSyncResponse {
            success,
            pulled,
            processed: pulled,
            pushed: 0,
            errors: Vec::new(),
        }
    }

    fn put_active_vault(vault_id: &str, amount_sats: u64) {
        let proto = generated::LimboVaultProto {
            id: vault_id.to_string(),
            fulfillment_condition: Some(generated::FulfillmentMechanism {
                kind: Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(
                    generated::BitcoinHtlc {
                        hash_lock: vec![0x11; 32],
                        refund_hash_lock: vec![0x22; 32],
                        refund_iterations: 42,
                        bitcoin_pubkey: vec![0x03; 33],
                        expected_btc_amount_sats: amount_sats,
                        network: 0,
                        min_confirmations: 1,
                    },
                )),
            }),
            ..Default::default()
        }
        .encode_to_vec();

        client_db::put_vault(vault_id, &proto, "active", &[0x44; 80], amount_sats)
            .expect("store vault");
    }

    fn put_active_vault_record(vault_id: &str, amount_sats: u64) {
        client_db::upsert_vault_record(&client_db::PersistedVaultRecord {
            vault_op_id: format!("deposit-{vault_id}"),
            direction: "btc_to_dbtc".to_string(),
            vault_state: "completed".to_string(),
            hash_lock: vec![0x33; 32],
            vault_id: Some(vault_id.to_string()),
            btc_amount_sats: amount_sats,
            btc_pubkey: vec![0x03; 33],
            htlc_script: Some(vec![0x66; 64]),
            htlc_address: Some("tb1qtest".to_string()),
            external_commitment: None,
            refund_iterations: 42,
            created_at_state: 1,
            entry_header: Some(vec![0x44; 80]),
            parent_vault_id: None,
            successor_depth: 0,
            is_fractional_successor: false,
            refund_hash_lock: vec![0x22; 32],
            destination_address: None,
            funding_txid: None,
            exit_amount_sats: 0,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: Some(vec![0x55; 32]),
        })
        .expect("store vault record");
    }

    fn seed_vault_execution_advertisement(vault_id: &str, amount_sats: u64, policy_commit: [u8; 32]) {
        let ad_key = format!(
            "dbtc/manifold/{}/vault/{}",
            crate::util::text_id::encode_base32_crockford(&policy_commit),
            vault_id
        );
        let redeem_params = generated::DbtcRedeemParams {
            htlc_script: vec![0x66; 64],
            claim_pubkey: vec![0x03; 33],
            hash_lock: vec![0x33; 32],
            refund_hash_lock: vec![0x22; 32],
            refund_iterations: 42,
        }
        .encode_to_vec();
        let advertisement = generated::DbtcVaultAdvertisementV1 {
            version: 1,
            policy_commit: policy_commit.to_vec(),
            vault_id: vault_id.to_string(),
            controller_device_id: vec![0xA1; 32],
            amount_sats,
            successor_depth: 0,
            lifecycle_state: "active".to_string(),
            routeable: true,
            busy_reason: String::new(),
            updated_state_number: 1,
            vault_proto_key: String::new(),
            vault_proto_digest: vec![0x99; 32],
            entry_txid: vec![0x88; 32],
            htlc_address: "tb1qtest".to_string(),
            script_commit: vec![0x77; 32],
            redeem_params,
            deposit_nonce: vec![0x55; 32],
        };
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::seed_dbtc_storage_object(
            ad_key,
            advertisement.encode_to_vec(),
        );
    }

    /// Seed dBTC available balance for the test device ([0xA1; 32]).
    fn seed_dbtc_balance(amount_sats: u64) {
        let device_id = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);
        client_db::upsert_token_balance(&device_id, "dBTC", amount_sats, 0)
            .expect("seed dBTC balance");
    }

    #[test]
    fn persist_committed_withdrawal_metadata_transitions_existing_row() {
        let _router = init_withdrawal_invoke_test_router("withdraw_metadata_transition");
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);

        client_db::create_withdrawal(client_db::CreateWithdrawalParams {
            withdrawal_id: "wd-transition-test",
            device_id: &device_id_b32,
            amount_sats: 100_000,
            dest_address: "tb1qtransition",
            policy_commit: crate::policy::builtins::DBTC_POLICY_COMMIT,
            state: "executing",
            burn_token_id: Some("dBTC"),
            burn_amount_sats: 104_700,
        })
        .expect("create executing withdrawal");

        persist_committed_withdrawal_metadata(
            "wd-transition-test",
            &device_id_b32,
            104_700,
            "tb1qtransition",
            crate::policy::builtins::DBTC_POLICY_COMMIT,
            "dBTC",
            104_700,
        )
        .expect("transition withdrawal to committed");

        let persisted = client_db::get_withdrawal("wd-transition-test")
            .expect("read withdrawal")
            .expect("withdrawal exists");
        assert_eq!(persisted.state, "committed");
        assert_eq!(
            persisted.amount_sats, 100_000,
            "planner-authored requested net must remain intact"
        );
        assert_eq!(persisted.burn_amount_sats, 104_700);
    }

    #[test]
    fn ensure_dbtc_exit_balance_uses_required_amount() {
        let err = ensure_dbtc_exit_balance("bitcoin.fractional.exit", 100_000, 104_700)
            .expect_err("gross requirement should fail when only net is available");
        assert!(
            err.contains("have 100000 sats, need 104700 sats"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_execute_rejects_reuse_of_consumed_plan() {
        let router = init_withdrawal_invoke_test_router("withdraw_execute_consumed");
        let request_net_sats = 173_333;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        let source_amount = request_net_sats + full_fee;

        seed_dbtc_balance(request_net_sats * 3); // enough for multiple withdrawals
        put_active_vault("000-vault-consumed", source_amount);
        put_active_vault_record("000-vault-consumed", source_amount);

        set_withdrawal_bridge_sync_test_results(vec![
            Ok(sync_response(true, 0)),
            Ok(sync_response(true, 0)),
        ]);

        let plan_query = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats: request_net_sats,
                    destination_address: "tb1qdestination".to_string(),
                }),
            })
            .await;
        assert!(
            plan_query.success,
            "initial plan query should succeed: {:?}",
            plan_query.error_message
        );

        let plan_env = decode_framed_envelope(&plan_query.data, "bitcoin.withdraw.plan");
        let plan_resp = match plan_env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(resp)) => resp,
            other => panic!("unexpected plan payload: {other:?}"),
        };
        assert_eq!(plan_resp.legs.len(), 1);

        let expected_leg = plan_resp.legs.first().expect("expected one planned leg");
        let expected_request = generated::BitcoinFractionalExitRequest {
            source_vault_id: expected_leg.vault_id.clone(),
            exit_amount_sats: if expected_leg.kind == "full" {
                0
            } else {
                expected_leg.gross_exit_sats
            },
            successor_locktime: if expected_leg.kind == "full" { 0 } else { 144 },
            refund_iterations: if expected_leg.kind == "full" {
                0
            } else {
                10_000
            },
            destination_address: "tb1qdestination".to_string(),
            plan_id: String::new(),
        };
        let expected_result = Ok(generated::BitcoinFractionalExitResponse {
            source_vault_id: expected_leg.vault_id.clone(),
            successor_vault_id: String::new(),
            successor_vault_op_id: String::new(),
            exit_amount_sats: request_net_sats,
            remainder_sats: 0,
            successor_depth: 0,
            successor_htlc_script: Vec::new(),
            successor_htlc_address: String::new(),
            exit_vault_op_id: "exit-deposit-1".to_string(),
            sweep_txid: "txid-1".to_string(),
            confirm_depth: 0,
        });
        let expected_execution = if expected_leg.kind == "full" {
            WithdrawalExecutionTestExpectation::full(expected_request, expected_result)
        } else {
            WithdrawalExecutionTestExpectation::fractional(expected_request, expected_result)
        };
        set_withdrawal_execution_test_expectations(vec![expected_execution]);

        let first_execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: plan_resp.plan_id.clone(),
                    destination_address: "tb1qdestination".to_string(),
                    ..Default::default()
                }),
            })
            .await;
        assert!(
            first_execute.success,
            "first execute should succeed: {:?}",
            first_execute.error_message
        );

        set_withdrawal_bridge_sync_test_results(vec![Ok(sync_response(true, 0))]);

        let second_execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: plan_resp.plan_id,
                    destination_address: "tb1qdestination".to_string(),
                    ..Default::default()
                }),
            })
            .await;
        assert!(
            !second_execute.success,
            "second execute with same plan_id should fail (plan consumed)"
        );
        let err = second_execute
            .error_message
            .expect("expected consumed plan error");
        assert!(
            err.contains("plan not found or expired"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_execute_rejects_unknown_plan_id() {
        let router = init_withdrawal_invoke_test_router("withdraw_execute_unknown_plan");

        set_withdrawal_bridge_sync_test_results(vec![Ok(sync_response(true, 0))]);

        let execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: "nonexistent-plan-id".to_string(),
                    destination_address: "tb1qdestination".to_string(),
                    ..Default::default()
                }),
            })
            .await;

        assert!(
            !execute.success,
            "execute should fail when plan_id is not in cache"
        );
        let err = execute.error_message.expect("expected unknown plan error");
        assert!(
            err.contains("plan not found or expired"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_execute_uses_cached_plan() {
        const WITHDRAWAL_SUCCESSOR_LOCKTIME: u32 = 144;
        const WITHDRAWAL_REFUND_ITERATIONS: u64 = 10_000;

        let router = init_withdrawal_invoke_test_router("withdraw_execute_cached_plan");
        let request_net_sats = 150_000;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        let source_amount = request_net_sats + full_fee;

        seed_dbtc_balance(request_net_sats * 3);
        put_active_vault("vault-execute-success", source_amount);
        put_active_vault_record("vault-execute-success", source_amount);

        set_withdrawal_bridge_sync_test_results(vec![
            Ok(sync_response(true, 0)),
            Ok(sync_response(true, 0)),
        ]);

        let plan_query = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats: request_net_sats,
                    destination_address: "tb1qdestination".to_string(),
                }),
            })
            .await;
        assert!(plan_query.success, "plan query should succeed");

        let plan_env = decode_framed_envelope(&plan_query.data, "bitcoin.withdraw.plan");
        let plan_resp = match plan_env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(resp)) => resp,
            other => panic!("unexpected plan payload: {other:?}"),
        };

        let expected_leg = plan_resp.legs.first().expect("expected one planned leg");
        let expected_request = generated::BitcoinFractionalExitRequest {
            source_vault_id: expected_leg.vault_id.clone(),
            exit_amount_sats: if expected_leg.kind == "full" {
                0
            } else {
                expected_leg.gross_exit_sats
            },
            successor_locktime: if expected_leg.kind == "full" {
                0
            } else {
                WITHDRAWAL_SUCCESSOR_LOCKTIME
            },
            refund_iterations: if expected_leg.kind == "full" {
                0
            } else {
                WITHDRAWAL_REFUND_ITERATIONS
            },
            destination_address: "tb1qdestination".to_string(),
            plan_id: String::new(),
        };
        let expected_result = Ok(generated::BitcoinFractionalExitResponse {
            source_vault_id: expected_leg.vault_id.clone(),
            successor_vault_id: String::new(),
            successor_vault_op_id: String::new(),
            exit_amount_sats: request_net_sats,
            remainder_sats: 0,
            successor_depth: 0,
            successor_htlc_script: Vec::new(),
            successor_htlc_address: String::new(),
            exit_vault_op_id: "exit-deposit-1".to_string(),
            sweep_txid: "txid-1".to_string(),
            confirm_depth: 0,
        });
        let expected_execution = if expected_leg.kind == "full" {
            WithdrawalExecutionTestExpectation::full(expected_request, expected_result)
        } else {
            WithdrawalExecutionTestExpectation::fractional(expected_request, expected_result)
        };
        set_withdrawal_execution_test_expectations(vec![expected_execution]);

        let execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: plan_resp.plan_id.clone(),
                    destination_address: "tb1qdestination".to_string(),
                    ..Default::default()
                }),
            })
            .await;

        assert!(
            execute.success,
            "execute should use cached plan from plan query: {:?}",
            execute.error_message
        );
        let execute_env = decode_framed_envelope(&execute.data, "bitcoin.withdraw.execute");
        let execute_resp = match execute_env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalExecuteResponse(resp)) => resp,
            other => panic!("unexpected execute payload: {other:?}"),
        };
        assert_eq!(execute_resp.status, "committed");
        assert_eq!(execute_resp.executed_legs.len(), 1);
        assert_eq!(
            execute_resp.executed_legs[0].vault_id,
            expected_leg.vault_id
        );
        assert_eq!(execute_resp.executed_legs[0].kind, expected_leg.kind);
        assert_eq!(execute_resp.executed_legs[0].status, "broadcast");
        assert_eq!(execute_resp.executed_legs[0].sweep_txid, "txid-1");

        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);
        let unresolved = crate::storage::client_db::list_unresolved_withdrawals(&device_id_b32)
            .expect("list unresolved withdrawals");
        assert_eq!(unresolved.len(), 1, "expected one persisted withdrawal row");
        let persisted = &unresolved[0];
        assert_eq!(persisted.state, "committed");
        assert_eq!(persisted.redemption_txid.as_deref(), Some("txid-1"));

        let legs = crate::storage::client_db::list_withdrawal_legs(&persisted.withdrawal_id)
            .expect("list withdrawal legs");
        assert_eq!(legs.len(), 1, "expected one persisted leg");
        assert_eq!(legs[0].vault_id, expected_leg.vault_id);
        assert_eq!(legs[0].leg_kind, expected_leg.kind);
        assert_eq!(legs[0].sweep_txid.as_deref(), Some("txid-1"));
        assert_withdrawal_execution_test_expectations_drained();
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_execute_rejects_destination_address_mismatch() {
        let router = init_withdrawal_invoke_test_router("withdraw_execute_addr_mismatch");
        let request_net_sats = 150_000;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        let source_amount = request_net_sats + full_fee;

        put_active_vault("vault-addr-mismatch", source_amount);
        put_active_vault_record("vault-addr-mismatch", source_amount);

        set_withdrawal_bridge_sync_test_results(vec![
            Ok(sync_response(true, 0)),
            Ok(sync_response(true, 0)),
        ]);

        let plan_query = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats: request_net_sats,
                    destination_address: "tb1qdestination".to_string(),
                }),
            })
            .await;
        assert!(plan_query.success, "plan query should succeed");

        let plan_env = decode_framed_envelope(&plan_query.data, "bitcoin.withdraw.plan");
        let plan_resp = match plan_env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(resp)) => resp,
            other => panic!("unexpected plan payload: {other:?}"),
        };

        let execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: plan_resp.plan_id,
                    destination_address: "tb1q_DIFFERENT_ADDRESS".to_string(),
                    ..Default::default()
                }),
            })
            .await;

        assert!(
            !execute.success,
            "execute should fail when destination address doesn't match cached plan"
        );
        let err = execute
            .error_message
            .expect("expected address mismatch error");
        assert!(
            err.contains("destination address does not match"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_withdraw_execute_persists_policy_commit_from_plan() {
        let router = init_withdrawal_invoke_test_router("withdraw_policy_commit");
        let request_net_sats = 100_000;
        let full_fee = crate::sdk::bitcoin_tap_sdk::estimated_full_withdrawal_fee_sats();
        let source_amount = request_net_sats + full_fee;

        seed_dbtc_balance(request_net_sats * 3);
        put_active_vault("vault-policy", source_amount);
        put_active_vault_record("vault-policy", source_amount);

        set_withdrawal_bridge_sync_test_results(vec![
            Ok(sync_response(true, 0)),
            Ok(sync_response(true, 0)),
        ]);

        let plan_query = router
            .query(AppQuery {
                path: "bitcoin.withdraw.plan".to_string(),
                params: pack_proto(&generated::BitcoinWithdrawalPlanRequest {
                    requested_net_sats: request_net_sats,
                    destination_address: "tb1qpolicy".to_string(),
                }),
            })
            .await;
        assert!(plan_query.success, "plan query should succeed");

        let plan_env = decode_framed_envelope(&plan_query.data, "bitcoin.withdraw.plan");
        let plan_resp = match plan_env.payload {
            Some(generated::envelope::Payload::BitcoinWithdrawalPlanResponse(resp)) => resp,
            other => panic!("unexpected plan payload: {other:?}"),
        };

        // The plan response carries the routed policy_commit (32 bytes).
        assert_eq!(
            plan_resp.policy_commit.len(),
            32,
            "plan must carry a 32-byte policy commit"
        );

        let expected_leg = plan_resp.legs.first().expect("expected one planned leg");
        let expected_request = generated::BitcoinFractionalExitRequest {
            source_vault_id: expected_leg.vault_id.clone(),
            exit_amount_sats: if expected_leg.kind == "full" {
                0
            } else {
                expected_leg.gross_exit_sats
            },
            successor_locktime: if expected_leg.kind == "full" { 0 } else { 144 },
            refund_iterations: if expected_leg.kind == "full" {
                0
            } else {
                10_000
            },
            destination_address: "tb1qpolicy".to_string(),
            plan_id: String::new(),
        };
        let expected_result = Ok(generated::BitcoinFractionalExitResponse {
            source_vault_id: expected_leg.vault_id.clone(),
            sweep_txid: "txid-policy".to_string(),
            exit_vault_op_id: "exit-policy".to_string(),
            ..Default::default()
        });
        let expected_execution = if expected_leg.kind == "full" {
            WithdrawalExecutionTestExpectation::full(expected_request, expected_result)
        } else {
            WithdrawalExecutionTestExpectation::fractional(expected_request, expected_result)
        };
        set_withdrawal_execution_test_expectations(vec![expected_execution]);

        let execute = router
            .invoke(AppInvoke {
                method: "bitcoin.withdraw.execute".to_string(),
                args: pack_proto(&generated::BitcoinWithdrawalExecuteRequest {
                    plan_id: plan_resp.plan_id.clone(),
                    destination_address: "tb1qpolicy".to_string(),
                    ..Default::default()
                }),
            })
            .await;
        assert!(
            execute.success,
            "execute should succeed: {:?}",
            execute.error_message
        );

        // The persisted withdrawal row must carry the plan's policy_commit, not a hardcoded constant.
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);
        let unresolved = client_db::list_unresolved_withdrawals(&device_id_b32)
            .expect("list unresolved withdrawals");
        assert_eq!(unresolved.len(), 1);
        let persisted = &unresolved[0];
        assert_eq!(
            persisted.policy_commit, plan_resp.policy_commit,
            "persisted policy_commit must match the plan's routed value"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bitcoin_full_sweep_rejects_policy_mismatch_against_committed_withdrawal() {
        let router = init_withdrawal_invoke_test_router("full_sweep_policy_mismatch");
        let amount_sats = 125_000;
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);
        let actual_policy_commit = *crate::policy::builtins::DBTC_POLICY_COMMIT;
        let mismatched_policy_commit = [0xAB; 32];

        seed_dbtc_balance(amount_sats);
        seed_vault_execution_advertisement("vault-policy-mismatch", amount_sats, actual_policy_commit);
        client_db::create_withdrawal(client_db::CreateWithdrawalParams {
            withdrawal_id: "wd-policy-mismatch",
            device_id: &device_id_b32,
            amount_sats,
            dest_address: "tb1qpolicymismatch",
            policy_commit: &mismatched_policy_commit,
            state: "committed",
            burn_token_id: Some("dBTC"),
            burn_amount_sats: amount_sats,
        })
        .expect("create committed withdrawal row");

        let execute = router
            .invoke(AppInvoke {
                method: "bitcoin.full.sweep".to_string(),
                args: pack_proto(&generated::BitcoinFractionalExitRequest {
                    source_vault_id: "vault-policy-mismatch".to_string(),
                    destination_address: "tb1qpolicymismatch".to_string(),
                    plan_id: "wd-policy-mismatch".to_string(),
                    ..Default::default()
                }),
            })
            .await;

        assert!(
            !execute.success,
            "full sweep should fail closed on policy mismatch"
        );
        let err = execute
            .error_message
            .expect("expected policy mismatch error");
        assert!(
            err.contains("policy_commit mismatch"),
            "unexpected error: {err}"
        );

        let persisted = client_db::get_withdrawal("wd-policy-mismatch")
            .expect("load persisted withdrawal")
            .expect("withdrawal must exist");
        assert_eq!(persisted.state, "committed");
        assert!(persisted.redemption_txid.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn settlement_resolver_does_not_refund_on_poll_budget_exceeded() {
        let _router = init_withdrawal_invoke_test_router("settle_no_refund");
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&[0xA1; 32]);

        // Directly insert a committed withdrawal row that simulates a past execution.
        client_db::create_withdrawal(client_db::CreateWithdrawalParams {
            withdrawal_id: "wd-settle-test",
            device_id: &device_id_b32,
            amount_sats: 50_000,
            dest_address: "tb1qsettle",
            policy_commit: crate::policy::builtins::DBTC_POLICY_COMMIT,
            state: "committed",
            burn_token_id: Some("dBTC"),
            burn_amount_sats: 50_000,
        })
        .expect("create test withdrawal");

        client_db::set_withdrawal_redemption_txids("wd-settle-test", "fake-txid", None)
            .expect("set redemption txid");

        // Pump the poll count past the budget.
        let max_polls = crate::sdk::bitcoin_tap_sdk::DBTC_MAX_SETTLEMENT_POLLS;
        for _ in 0..=max_polls + 5 {
            let _ = client_db::increment_settlement_poll_count("wd-settle-test");
        }

        // Verify the row is still unresolved and NOT refunded.
        let unresolved = client_db::list_unresolved_withdrawals(&device_id_b32)
            .expect("list unresolved withdrawals");
        assert_eq!(unresolved.len(), 1, "withdrawal must still be listed");
        let wd = &unresolved[0];
        assert_eq!(
            wd.state, "committed",
            "state must remain committed, not refunded"
        );
        assert!(
            wd.settlement_poll_count > max_polls,
            "poll count should exceed budget: got {}",
            wd.settlement_poll_count
        );
    }
}
