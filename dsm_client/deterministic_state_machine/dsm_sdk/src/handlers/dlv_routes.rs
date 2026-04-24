// SPDX-License-Identifier: MIT OR Apache-2.0
//! DLV (Deterministic Limbo Vault) route handlers for AppRouterImpl.
//!
//! Handles `dlv.{create, invalidate, claim, unlock}` invoke routes.  Each
//! handler routes through `CoreSDK::execute_on_relationship` on the local
//! device's self-loop (rel_key = compute_smt_key(self, self)) per plan
//! Part D and the actor-self-loop routing rule.  No prefs-KV writes.

use dsm::types::proto as generated;
use prost::Message;

use crate::bridge::{AppInvoke, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

/// Unwrap an ArgPack if present, fall back to bare bytes.
fn unwrap_argpack(args: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(pack) = generated::ArgPack::decode(args) {
        if pack.codec != generated::Codec::Proto as i32 {
            return Err("ArgPack.codec must be PROTO".into());
        }
        Ok(pack.body)
    } else {
        Ok(args.to_vec())
    }
}

impl AppRouterImpl {
    /// Dispatch handler for `dlv.*` invoke routes.
    pub(crate) async fn handle_dlv_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "dlv.create" => self.dlv_create(i).await,
            "dlv.invalidate" => self.dlv_invalidate(i).await,
            "dlv.claim" => self.dlv_claim(i).await,
            "dlv.unlock" => self.dlv_unlock(i).await,
            other => err(format!("unknown dlv invoke method: {other}")),
        }
    }

    /// dlv.create — decode DlvInstantiateV1, verify digests, prepare the
    /// vault, emit Operation::DlvCreate on the creator's self-loop (Debit
    /// locked_amount when present), then finalize the vault.  Returns the
    /// Base32 Crockford vault_id in `AppStateResponse.value`.
    async fn dlv_create(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.create: {e}")),
        };
        if bytes.is_empty() {
            return err("dlv.create: empty DlvInstantiateV1 payload".into());
        }
        let req = match generated::DlvInstantiateV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("dlv.create: decode DlvInstantiateV1 failed: {e}")),
        };

        let spec = match req.spec.as_ref() {
            Some(s) => s,
            None => return err("dlv.create: DlvInstantiateV1.spec is required".into()),
        };
        if spec.policy_digest.len() != 32 {
            return err("dlv.create: spec.policy_digest must be 32 bytes".into());
        }
        if spec.content_digest.len() != 32 {
            return err("dlv.create: spec.content_digest must be 32 bytes".into());
        }
        if spec.fulfillment_digest.len() != 32 {
            return err("dlv.create: spec.fulfillment_digest must be 32 bytes".into());
        }

        // Strict-verify the content and fulfillment digests match the bytes.
        let expected_content_digest: [u8; 32] =
            dsm::crypto::blake3::domain_hash_bytes("DSM/dlv-content", &spec.content);
        if expected_content_digest.as_slice() != spec.content_digest.as_slice() {
            return err("dlv.create: content_digest does not match H(DSM/dlv-content, content)".into());
        }
        let expected_fm_digest: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
            "DSM/dlv-fulfillment",
            &spec.fulfillment_bytes,
        );
        if expected_fm_digest.as_slice() != spec.fulfillment_digest.as_slice() {
            return err("dlv.create: fulfillment_digest does not match H(DSM/dlv-fulfillment, fulfillment_bytes)".into());
        }

        if req.creator_public_key.is_empty() {
            return err("dlv.create: creator_public_key is required".into());
        }
        if req.signature.is_empty() {
            return err("dlv.create: signature is required".into());
        }
        if req.locked_amount_u128.len() != 16 {
            return err("dlv.create: locked_amount_u128 must be 16 bytes (big-endian u128)".into());
        }

        // Decode FulfillmentMechanism from the canonical proto bytes.
        let fm_proto = match generated::FulfillmentMechanism::decode(&*spec.fulfillment_bytes) {
            Ok(p) => p,
            Err(e) => return err(format!("dlv.create: decode FulfillmentMechanism failed: {e}")),
        };
        let fulfillment = match dsm::vault::FulfillmentMechanism::try_from(fm_proto) {
            Ok(m) => m,
            Err(e) => return err(format!("dlv.create: FulfillmentMechanism conversion failed: {e}")),
        };

        // Reference state (current device head).
        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.create: get_current_state failed: {e}")),
        };

        // Intended recipient (Kyber pk) — empty means self-encrypted.
        let intended_recipient_opt = if spec.intended_recipient.is_empty() {
            None
        } else {
            Some(spec.intended_recipient.clone())
        };
        // Encryption target: intended recipient's Kyber pk, or creator's own pk.
        let encryption_pk = intended_recipient_opt
            .clone()
            .unwrap_or_else(|| req.creator_public_key.clone());

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let draft = match dlv_manager.prepare_vault(
            &req.creator_public_key,
            fulfillment,
            &spec.content,
            "application/octet-stream",
            intended_recipient_opt.clone(),
            &encryption_pk,
            &reference_state.hash,
        ) {
            Ok(d) => d,
            Err(e) => return err(format!("dlv.create: prepare_vault failed: {e}")),
        };

        // Remember the vault_id bytes for the response + finalize step.  The
        // draft is consumed by finalize_vault below so we snapshot here.
        let vault_id: [u8; 32] = draft.id;

        // Locked amount + token (both optional — empty token_id = content-only vault).
        let token_id_str_opt: Option<String> = if req.token_id.is_empty() {
            None
        } else {
            match std::str::from_utf8(&req.token_id) {
                Ok(s) => Some(s.to_string()),
                Err(_) => return err("dlv.create: token_id is not valid UTF-8".into()),
            }
        };
        let locked_u64: u64 = {
            let mut acc: u128 = 0;
            for b in &req.locked_amount_u128 {
                acc = (acc << 8) | (*b as u128);
            }
            if acc == 0 {
                0
            } else {
                match u64::try_from(acc) {
                    Ok(v) => v,
                    Err(_) => {
                        return err(
                            "dlv.create: locked_amount exceeds u64::MAX (Balance is u64)".into(),
                        );
                    }
                }
            }
        };

        // Resolve the locked token's policy_commit once — reused for the
        // BalanceDelta below and for the posted-mode advertisement further
        // down.  A strict-fail on unregistered tokens here matches the
        // invariant landed in commit 3 (resolve_policy_commit fails closed).
        let policy_commit_opt: Option<[u8; 32]> =
            if let (Some(tid), true) = (token_id_str_opt.as_deref(), locked_u64 > 0) {
                match self.wallet.token_sdk.resolve_policy_commit_strict(tid) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        return err(format!(
                            "dlv.create: resolve policy_commit for {tid} failed: {e}"
                        ));
                    }
                }
            } else {
                None
            };
        let deltas: Vec<dsm::types::device_state::BalanceDelta> = match policy_commit_opt {
            Some(pc) => vec![dsm::types::device_state::BalanceDelta {
                policy_commit: pc,
                direction: dsm::types::device_state::BalanceDirection::Debit,
                amount: locked_u64,
            }],
            None => Vec::new(),
        };

        // Build Operation::DlvCreate.
        let locked_balance_opt = if locked_u64 > 0 {
            Some(dsm::types::token_types::Balance::from_state(
                locked_u64,
                reference_state.hash,
            ))
        } else {
            None
        };
        let op = dsm::types::operations::Operation::DlvCreate {
            vault_id: vault_id.to_vec(),
            creator_public_key: req.creator_public_key.clone(),
            parameters_hash: draft.parameters_hash.clone(),
            fulfillment_condition: spec.fulfillment_bytes.clone(),
            intended_recipient: intended_recipient_opt.clone(),
            token_id: token_id_str_opt.as_ref().map(|s| s.as_bytes().to_vec()),
            locked_amount: locked_balance_opt,
            signature: req.signature.clone(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        // Actor self-loop routing.
        let actor = reference_state.device_info.device_id;
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip =
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &actor, &actor,
            );
        if let Err(e) =
            self.core_sdk
                .execute_on_relationship(rel_key, actor, op, &deltas, Some(init_tip))
        {
            return err(format!("dlv.create: execute_on_relationship failed: {e}"));
        }

        // Persist vault state in the DLV manager.
        if let Err(e) = dlv_manager
            .finalize_vault(
                draft,
                &req.signature,
                token_id_str_opt.as_deref(),
                if locked_u64 > 0 { Some(locked_u64) } else { None },
            )
            .await
        {
            return err(format!("dlv.create: finalize_vault failed: {e}"));
        }

        // Posted-mode delivery: when an intended_recipient Kyber pk is set,
        // publish an advertisement + full VaultPostProto mirror to storage
        // nodes so the recipient's device can discover + `dlv.claim` it.
        // Best-effort — the canonical Operation::DlvCreate has already been
        // applied on-chain above.  A publish failure leaves the creator with
        // a valid local vault and no discoverable ad; the recipient cannot
        // claim until a retry publish succeeds, but nothing else breaks.
        if let Some(recipient_pk) = intended_recipient_opt.as_ref() {
            match dlv_manager
                .create_vault_post(&vault_id, "posted-dlv", None)
                .await
            {
                Ok(vault_post_bytes) => {
                    let policy_commit = policy_commit_opt.unwrap_or([0u8; 32]);
                    let publish_input = crate::sdk::posted_dlv_sdk::PublishActiveAdInput {
                        dlv_id: &vault_id,
                        recipient_kyber_pk: recipient_pk.as_slice(),
                        creator_public_key: req.creator_public_key.as_slice(),
                        policy_commit,
                        vault_post_bytes: &vault_post_bytes,
                    };
                    if let Err(e) =
                        crate::sdk::posted_dlv_sdk::publish_active_advertisement(publish_input)
                            .await
                    {
                        log::warn!(
                            "[dlv.create] posted-mode advertisement publish failed for {}: {e}",
                            crate::util::text_id::encode_base32_crockford(&vault_id)
                        );
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[dlv.create] create_vault_post for {} failed (advertisement skipped): {e}",
                        crate::util::text_id::encode_base32_crockford(&vault_id)
                    );
                }
            }
        }

        let resp = generated::AppStateResponse {
            key: "dlv.create".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// dlv.unlock — decode DlvOpenV3, emit Operation::DlvUnlock on the
    /// requester's self-loop (empty deltas; state-only transition per the
    /// `apply_token_operation::DlvUnlock` arm).
    async fn dlv_unlock(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.unlock: {e}")),
        };
        let req = match generated::DlvOpenV3::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("dlv.unlock: decode DlvOpenV3 failed: {e}")),
        };
        if req.device_id.len() != 32 {
            return err("dlv.unlock: device_id must be 32 bytes".into());
        }
        if req.vault_id.len() != 32 {
            return err("dlv.unlock: vault_id must be 32 bytes".into());
        }

        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);

        let op = dsm::types::operations::Operation::DlvUnlock {
            vault_id: vault_id.to_vec(),
            fulfillment_proof: req.reveal_material.clone(),
            requester_public_key: req.device_id.clone(),
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.unlock: get_current_state failed: {e}")),
        };
        let actor = reference_state.device_info.device_id;
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip =
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &actor, &actor,
            );
        if let Err(e) =
            self.core_sdk.execute_on_relationship(rel_key, actor, op, &[], Some(init_tip))
        {
            return err(format!("dlv.unlock: execute_on_relationship failed: {e}"));
        }

        let resp = generated::AppStateResponse {
            key: "dlv.unlock".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// dlv.invalidate — restore the creator's locked balance and mark the
    /// vault Invalidated.  Routes on the actor's self-loop with a Credit
    /// delta sourced from the vault's recorded locked_amount/token_id.
    ///
    /// FIXME(commit-5-followup): no dedicated proto message exists yet for
    /// DlvInvalidate requests.  Body shape here is `[32-byte vault_id]
    /// [utf8 reason]`.  A later commit should add a typed
    /// `DlvInvalidateV1 { vault_id, reason, creator_public_key, signature }`
    /// proto and update this decoder.
    async fn dlv_invalidate(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.invalidate: {e}")),
        };
        if bytes.len() < 32 {
            return err("dlv.invalidate: body must start with 32-byte vault_id".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&bytes[..32]);
        let reason = std::str::from_utf8(&bytes[32..])
            .map(|s| s.to_string())
            .unwrap_or_default();

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let vault_lock = match dlv_manager.get_vault(&vault_id).await {
            Ok(v) => v,
            Err(e) => return err(format!("dlv.invalidate: vault not found: {e}")),
        };
        let (creator_pk, locked_amount, token_id_opt) = {
            let v = vault_lock.lock().await;
            let (locked, tid): (u64, Option<String>) = match &v.fulfillment_condition {
                dsm::vault::fulfillment::FulfillmentMechanism::Payment {
                    amount,
                    token_id,
                    ..
                } => (*amount, Some(token_id.clone())),
                _ => (0, None),
            };
            (v.creator_public_key.clone(), locked, tid)
        };

        let deltas: Vec<dsm::types::device_state::BalanceDelta> = match (
            &token_id_opt,
            locked_amount,
        ) {
            (Some(tid), amt) if amt > 0 => {
                let pc = match self.wallet.token_sdk.resolve_policy_commit_strict(tid) {
                    Ok(c) => c,
                    Err(e) => {
                        return err(format!(
                            "dlv.invalidate: resolve policy_commit for {tid} failed: {e}"
                        ));
                    }
                };
                vec![dsm::types::device_state::BalanceDelta {
                    policy_commit: pc,
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: amt,
                }]
            }
            _ => Vec::new(),
        };

        let op = dsm::types::operations::Operation::DlvInvalidate {
            vault_id: vault_id.to_vec(),
            reason: reason.clone(),
            creator_public_key: creator_pk.clone(),
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.invalidate: get_current_state failed: {e}")),
        };
        let actor = reference_state.device_info.device_id;
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip =
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &actor, &actor,
            );
        if let Err(e) = self.core_sdk.execute_on_relationship(
            rel_key,
            actor,
            op,
            &deltas,
            Some(init_tip),
        ) {
            return err(format!("dlv.invalidate: execute_on_relationship failed: {e}"));
        }

        if let Err(e) = dlv_manager
            .invalidate_vault(&vault_id, &reason, &[], &reference_state.hash)
            .await
        {
            return err(format!("dlv.invalidate: invalidate_vault failed: {e}"));
        }

        let resp = generated::AppStateResponse {
            key: "dlv.invalidate".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// dlv.claim — claimant's self-loop Credit of the vault's locked
    /// balance.  This is the residual-uncertainty probe from the plan's
    /// Stage 7: the claimant may have zero prior exposure to the custom
    /// token; the Credit materialises a fresh `policy_commit` entry on
    /// the claimant's own chain (verified by I5.0).
    ///
    /// Routing rule: actor IS the claimant (local device), NOT the vault
    /// creator.  The rel_key MUST NOT be derived from
    /// `vault.creator_public_key`.
    ///
    /// FIXME(commit-5-followup): no dedicated proto message exists yet for
    /// DlvClaim requests.  Body shape here is `[32-byte vault_id]
    /// [claim_proof bytes]`.  A later commit should add a typed
    /// `DlvClaimV1 { vault_id, claim_proof, claimant_public_key, signature }`
    /// proto and update this decoder.
    async fn dlv_claim(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.claim: {e}")),
        };
        if bytes.len() < 32 {
            return err("dlv.claim: body must start with 32-byte vault_id".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&bytes[..32]);
        let claim_proof = bytes[32..].to_vec();

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let (locked_amount, token_id_opt, intended_recipient) =
            match dlv_manager.get_vault(&vault_id).await {
                Ok(vault_lock) => {
                    let v = vault_lock.lock().await;
                    let (amt, tid) = match &v.fulfillment_condition {
                        dsm::vault::fulfillment::FulfillmentMechanism::Payment {
                            amount,
                            token_id,
                            ..
                        } => (*amount, Some(token_id.clone())),
                        _ => (0u64, None),
                    };
                    (amt, tid, v.intended_recipient.clone())
                }
                Err(e) => return err(format!("dlv.claim: vault not found: {e}")),
            };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.claim: get_current_state failed: {e}")),
        };
        // Actor IS the claimant.  rel_key must NOT be derived from vault creator.
        let actor = reference_state.device_info.device_id;

        let deltas: Vec<dsm::types::device_state::BalanceDelta> = match (
            &token_id_opt,
            locked_amount,
        ) {
            (Some(tid), amt) if amt > 0 => {
                let pc = match self.wallet.token_sdk.resolve_policy_commit_strict(tid) {
                    Ok(c) => c,
                    Err(e) => {
                        return err(format!(
                            "dlv.claim: resolve policy_commit for {tid} failed: {e}"
                        ));
                    }
                };
                vec![dsm::types::device_state::BalanceDelta {
                    policy_commit: pc,
                    direction: dsm::types::device_state::BalanceDirection::Credit,
                    amount: amt,
                }]
            }
            _ => Vec::new(),
        };

        let claimant_pk = crate::sdk::signing_authority::current_public_key()
            .unwrap_or_default();
        let op = dsm::types::operations::Operation::DlvClaim {
            vault_id: vault_id.to_vec(),
            claim_proof: claim_proof.clone(),
            claimant_public_key: claimant_pk,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip =
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &actor, &actor,
            );
        if let Err(e) = self.core_sdk.execute_on_relationship(
            rel_key,
            actor,
            op,
            &deltas,
            Some(init_tip),
        ) {
            return err(format!("dlv.claim: execute_on_relationship failed: {e}"));
        }

        // Posted-mode: once the on-chain DlvClaim has been applied, flip
        // the corresponding storage-node advertisement from "active" to
        // "claimed" so creator devices (and any other interested observers)
        // learn the vault has been consumed.  The dedup rule — highest
        // updated_state_number wins — guarantees the claimed ad supersedes
        // the original on the next list.  Best-effort: a failure here only
        // leaves stale discovery state; the canonical truth lives on the
        // claimant's hash chain.
        if let Some(recipient_pk) = intended_recipient.as_ref() {
            if let Err(e) = crate::sdk::posted_dlv_sdk::publish_terminal_state(
                recipient_pk,
                &vault_id,
                crate::sdk::posted_dlv_sdk::LIFECYCLE_CLAIMED,
                Vec::new(),
            )
            .await
            {
                log::warn!(
                    "[dlv.claim] publish claimed-state ad for {} failed: {e}",
                    crate::util::text_id::encode_base32_crockford(&vault_id)
                );
            }
        }

        // Note: `claim_vault_content` on DLVManager decrypts the vault
        // content with a Kyber SK the claimant holds.  That secret is not
        // carried in this route shape, so the claim advance is recorded on
        // chain here and content decryption is a separate caller concern.
        let resp = generated::AppStateResponse {
            key: "dlv.claim".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}
