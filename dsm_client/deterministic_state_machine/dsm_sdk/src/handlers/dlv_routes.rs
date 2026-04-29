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
    /// Dispatch handler for `dlv.*` query (read-only) routes.
    pub(crate) async fn handle_dlv_query(&self, q: crate::bridge::AppQuery) -> AppResult {
        match q.path.as_str() {
            "dlv.listOwnedAmmVaults" => self.dlv_list_owned_amm_vaults(q).await,
            "dlv.getVaultStateAnchor" => self.dlv_get_vault_state_anchor(q).await,
            other => err(format!("unknown dlv query path: {other}")),
        }
    }

    /// Dispatch handler for `dlv.*` invoke routes.
    pub(crate) async fn handle_dlv_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "dlv.create" => self.dlv_create(i).await,
            "dlv.invalidate" => self.dlv_invalidate(i).await,
            "dlv.claim" => self.dlv_claim(i).await,
            "dlv.unlock" => self.dlv_unlock(i).await,
            "dlv.unlockRouted" => self.dlv_unlock_routed(i).await,
            other => err(format!("unknown dlv invoke method: {other}")),
        }
    }

    /// `dlv.listOwnedAmmVaults` (query) — enumerate the local
    /// `DLVManager` and return the AMM constant-product vaults whose
    /// `creator_public_key` matches the wallet's current SPHINCS+ pk.
    /// Each entry carries the live reserves + fee + advertised
    /// state_number from storage (best-effort: storage failure
    /// renders the vault as `routing_advertised = false`).
    async fn dlv_list_owned_amm_vaults(&self, _q: crate::bridge::AppQuery) -> AppResult {
        let wallet_pk = match crate::sdk::signing_authority::current_public_key() {
            Ok(pk) if !pk.is_empty() => pk,
            Ok(_) => {
                return err("dlv.listOwnedAmmVaults: wallet signing public key is empty".into());
            }
            Err(e) => {
                return err(format!(
                    "dlv.listOwnedAmmVaults: get_current_public_key failed: {e}"
                ));
            }
        };

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let summaries: Vec<generated::AmmVaultSummaryV1> = {
            let vault_ids = match dlv_manager.list_vaults().await {
                Ok(v) => v,
                Err(e) => {
                    return err(format!("dlv.listOwnedAmmVaults: list_vaults failed: {e}"));
                }
            };
            let mut out: Vec<generated::AmmVaultSummaryV1> = Vec::new();
            for vid in vault_ids {
                let vault_lock = match dlv_manager.get_vault(&vid).await {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let vault = vault_lock.lock().await;
                if vault.creator_public_key.as_slice() != wallet_pk.as_slice() {
                    continue;
                }
                let (token_a, token_b, reserve_a, reserve_b, fee_bps) =
                    match &vault.fulfillment_condition {
                        dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                            token_a,
                            token_b,
                            reserve_a,
                            reserve_b,
                            fee_bps,
                        } => (
                            token_a.clone(),
                            token_b.clone(),
                            *reserve_a,
                            *reserve_b,
                            *fee_bps,
                        ),
                        _ => continue,
                    };
                let anchor_sequence = vault.current_sequence;
                let anchor_enforcement = vault.anchor_enforcement;
                drop(vault);

                // Best-effort storage fetch for advertised state_number.
                let (state_number, advertised) =
                    match crate::sdk::routing_sdk::load_active_advertisements_for_pair(
                        &token_a, &token_b,
                    )
                    .await
                    {
                        Ok(ads) => match ads
                            .into_iter()
                            .find(|p| p.advertisement.vault_id == vid.to_vec())
                        {
                            Some(p) => (p.advertisement.updated_state_number, true),
                            None => (0, false),
                        },
                        Err(_) => (0, false),
                    };

                out.push(generated::AmmVaultSummaryV1 {
                    vault_id: vid.to_vec(),
                    token_a,
                    token_b,
                    reserve_a_u128: reserve_a.to_be_bytes().to_vec(),
                    reserve_b_u128: reserve_b.to_be_bytes().to_vec(),
                    fee_bps,
                    advertised_state_number: state_number,
                    routing_advertised: advertised,
                    anchor_sequence,
                    anchor_enforcement,
                });
            }
            out
        };

        let lines: Vec<String> = summaries
            .iter()
            .map(|s| crate::util::text_id::encode_base32_crockford(&s.encode_to_vec()))
            .collect();
        let resp = generated::AppStateResponse {
            key: "dlv.listOwnedAmmVaults".to_string(),
            value: Some(lines.join("\n")),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// `dlv.getVaultStateAnchor` (query) — fetch the latest signed
    /// `VaultStateAnchorV1` proto blob published at
    /// `defi/vault-state/{vault_id_b32}/latest`.  Vault internal
    /// state is authoritative; this route serves the
    /// off-device-trader discovery path only.  Returns the Base32
    /// Crockford encoding of the proto bytes in
    /// `AppStateResponse.value`, or an empty value when no anchor
    /// has been published yet.
    ///
    /// Input: `q.params` carries the vault_id Base32 string as
    /// UTF-8 bytes.
    async fn dlv_get_vault_state_anchor(&self, q: crate::bridge::AppQuery) -> AppResult {
        let vault_id_b32 = match std::str::from_utf8(&q.params) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                return err(format!(
                    "dlv.getVaultStateAnchor: vault id is not valid UTF-8: {e}"
                ));
            }
        };
        if vault_id_b32.is_empty() {
            return err("dlv.getVaultStateAnchor: vault id is empty".into());
        }
        let vault_id_bytes = match crate::util::text_id::decode_base32_crockford(&vault_id_b32) {
            Some(v) => v,
            None => {
                return err(
                    "dlv.getVaultStateAnchor: vault id is not valid Base32 Crockford".into(),
                );
            }
        };
        if vault_id_bytes.len() != 32 {
            return err(format!(
                "dlv.getVaultStateAnchor: vault id must decode to 32 bytes, got {}",
                vault_id_bytes.len()
            ));
        }
        let key = format!("defi/vault-state/{}/latest", vault_id_b32);
        let value = match crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&key).await
        {
            Ok(proto_bytes) => crate::util::text_id::encode_base32_crockford(&proto_bytes),
            Err(_) => {
                // No anchor published yet (or storage backend unreachable).
                // Return empty value — caller treats absent as "no anchor".
                String::new()
            }
        };
        let resp = generated::AppStateResponse {
            key: "dlv.getVaultStateAnchor".to_string(),
            value: Some(value),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
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
        let mut req = match generated::DlvInstantiateV1::decode(&*bytes) {
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

        // Compute the canonical digests Rust-side.  Per the
        // "all business logic stays in Rust" rule, the frontend MUST
        // NOT pre-compute these; if it does pass values in, they're
        // strict-verified against the local computation (cheap
        // sanity check that catches schema drift).  Empty fields are
        // the canonical request shape: caller declines to commit to
        // the digest and lets Rust derive it.
        let expected_content_digest: [u8; 32] =
            dsm::crypto::blake3::domain_hash_bytes("DSM/dlv-content", &spec.content);
        let expected_fm_digest: [u8; 32] =
            dsm::crypto::blake3::domain_hash_bytes("DSM/dlv-fulfillment", &spec.fulfillment_bytes);
        match spec.content_digest.len() {
            0 => {} // accept-or-compute path
            32 => {
                if expected_content_digest.as_slice() != spec.content_digest.as_slice() {
                    return err(
                        "dlv.create: content_digest does not match H(DSM/dlv-content, content)"
                            .into(),
                    );
                }
            }
            n => {
                return err(format!(
                    "dlv.create: spec.content_digest must be 0 or 32 bytes, got {n}"
                ));
            }
        }
        match spec.fulfillment_digest.len() {
            0 => {}
            32 => {
                if expected_fm_digest.as_slice() != spec.fulfillment_digest.as_slice() {
                    return err(
                        "dlv.create: fulfillment_digest does not match H(DSM/dlv-fulfillment, fulfillment_bytes)"
                            .into(),
                    );
                }
            }
            n => {
                return err(format!(
                    "dlv.create: spec.fulfillment_digest must be 0 or 32 bytes, got {n}"
                ));
            }
        }

        // Accept-or-stamp: empty `creator_public_key` is the canonical
        // request shape per the "all crypto stays in Rust" rule (Track
        // C.4 UI work).  When empty, the wallet's current SPHINCS+ pk
        // is stamped.  When supplied, it is honoured as-is —
        // preserves the off-device-signing path used by integration
        // tests + paste tools that pre-built a fully-signed
        // `DlvInstantiateV1`.
        if req.creator_public_key.is_empty() {
            match crate::sdk::signing_authority::current_public_key() {
                Ok(pk) if !pk.is_empty() => req.creator_public_key = pk,
                Ok(_) => {
                    return err("dlv.create: empty creator_public_key requested wallet \
                         signing but the wallet signing pk is empty"
                        .into());
                }
                Err(e) => {
                    return err(format!(
                        "dlv.create: empty creator_public_key requested wallet \
                         signing but get_current_public_key failed: {e}"
                    ));
                }
            }
        }
        if req.locked_amount_u128.len() != 16 {
            return err("dlv.create: locked_amount_u128 must be 16 bytes (big-endian u128)".into());
        }
        // Accept-or-sign: empty `signature` triggers wallet-side
        // signing.  Must run AFTER `creator_public_key` is finalised
        // so the signature covers the same canonical bytes the Rust
        // verifier will recompute.  The signing pre-image is a
        // domain-separated BLAKE3 over the encoded
        // `DlvInstantiateV1` bytes (with `signature` zero) +
        // `creator_public_key`, mirroring the chunk #6
        // `route_commit_sdk::canonicalise_for_commitment` pattern.
        if req.signature.is_empty() {
            let mut canonical_for_sign = req.clone();
            canonical_for_sign.signature = Vec::new();
            let canonical_bytes = canonical_for_sign.encode_to_vec();
            let signing_input: Vec<u8> = {
                let mut buf =
                    Vec::with_capacity(canonical_bytes.len() + req.creator_public_key.len());
                buf.extend_from_slice(&canonical_bytes);
                buf.extend_from_slice(&req.creator_public_key);
                buf
            };
            let canonical_digest: [u8; 32] =
                dsm::crypto::blake3::domain_hash_bytes("DSM/dlv-create-self-sign", &signing_input);
            let sk = match crate::sdk::signing_authority::current_secret_key() {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => {
                    return err("dlv.create: empty signature requested wallet signing \
                         but the wallet signing sk is empty"
                        .into());
                }
                Err(e) => {
                    return err(format!(
                        "dlv.create: empty signature requested wallet signing \
                         but get_current_secret_key failed: {e}"
                    ));
                }
            };
            let sig = match dsm::crypto::sphincs::sign(
                dsm::crypto::sphincs::SphincsVariant::SPX256f,
                &sk,
                canonical_digest.as_ref(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return err(format!("dlv.create: SPHINCS+ sign failed: {e}"));
                }
            };
            req.signature = sig;
        }

        // Decode FulfillmentMechanism from the canonical proto bytes.
        let fm_proto = match generated::FulfillmentMechanism::decode(&*spec.fulfillment_bytes) {
            Ok(p) => p,
            Err(e) => {
                return err(format!(
                    "dlv.create: decode FulfillmentMechanism failed: {e}"
                ))
            }
        };
        let fulfillment = match dsm::vault::FulfillmentMechanism::try_from(fm_proto) {
            Ok(m) => m,
            Err(e) => {
                return err(format!(
                    "dlv.create: FulfillmentMechanism conversion failed: {e}"
                ))
            }
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
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
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
                if locked_u64 > 0 {
                    Some(locked_u64)
                } else {
                    None
                },
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

        // Tier 2 Foundation: stamp the vault's `anchor_enforcement`
        // policy from the spec.  This is the LOCAL authoritative copy
        // consulted by the chunks #7 gate at routed-unlock time.  The
        // proto value is passed through verbatim — the gate decodes it
        // via `AnchorEnforcement::try_from` and falls back to
        // `Unspecified` for unknown variants.
        match dlv_manager.get_vault(&vault_id).await {
            Ok(vault_lock) => {
                let mut vault = vault_lock.lock().await;
                vault.anchor_enforcement = spec.anchor_enforcement;
            }
            Err(e) => {
                log::warn!(
                    "[dlv.create] anchor_enforcement stamp: get_vault for {} failed: {e}",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                );
            }
        }

        // Tier 2 Foundation: publish genesis vault state anchor
        // (sequence=0) for AMM vaults whose spec declares
        // anchor_enforcement = REQUIRED or OPTIONAL.  Vault internal
        // state is authoritative; the anchor is a best-effort
        // off-device-trader-readable advertisement.  Failure is
        // logged but does NOT roll back vault creation.
        {
            use dsm::types::proto::AnchorEnforcement;
            let enforcement = AnchorEnforcement::try_from(spec.anchor_enforcement)
                .unwrap_or(AnchorEnforcement::Unspecified);
            let should_publish = match enforcement {
                AnchorEnforcement::Required | AnchorEnforcement::Optional => true,
                AnchorEnforcement::Unspecified => false,
            };
            if should_publish {
                match dlv_manager.get_vault(&vault_id).await {
                    Ok(vault_lock) => {
                        let vault = vault_lock.lock().await;
                        let reserves_digest_opt = vault.current_reserves_digest();
                        drop(vault);
                        if let Some(reserves_digest) = reserves_digest_opt {
                            let pk_res = crate::sdk::signing_authority::current_public_key();
                            let sk_res = crate::sdk::signing_authority::current_secret_key();
                            match (pk_res, sk_res) {
                                (Ok(pk), Ok(sk)) if !pk.is_empty() && !sk.is_empty() => {
                                    match dsm::dlv::vault_state_anchor::sign_vault_state_anchor(
                                        &vault_id,
                                        0,
                                        &reserves_digest,
                                        &pk,
                                        &sk,
                                    ) {
                                        Ok(signed) => {
                                            let proto_bytes =
                                                crate::sdk::vault_state_anchor_codec::encode_anchor_to_proto(
                                                    &signed,
                                                );
                                            if let Err(e) =
                                                publish_vault_state_anchor(&vault_id, &proto_bytes)
                                                    .await
                                            {
                                                log::warn!(
                                                    "[dlv.create] genesis anchor publish failed for {}: {e}; vault is locally consistent but may not be quotable off-device until republish",
                                                    crate::util::text_id::encode_base32_crockford(&vault_id),
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!(
                                                "[dlv.create] genesis anchor sign failed for {}: {e:?}",
                                                crate::util::text_id::encode_base32_crockford(&vault_id),
                                            );
                                        }
                                    }
                                }
                                _ => {
                                    log::warn!(
                                        "[dlv.create] genesis anchor: signing authority unavailable for {}",
                                        crate::util::text_id::encode_base32_crockford(&vault_id),
                                    );
                                }
                            }
                        }
                        // No reserves digest: non-AMM vault.  Tier 2 Foundation
                        // is AMM-only — silently skip.
                    }
                    Err(e) => {
                        log::warn!(
                            "[dlv.create] genesis anchor: get_vault for {} failed: {e}",
                            crate::util::text_id::encode_base32_crockford(&vault_id),
                        );
                    }
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
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        if let Err(e) =
            self.core_sdk
                .execute_on_relationship(rel_key, actor, op, &[], Some(init_tip))
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
    /// Decoder accepts the typed `DlvInvalidateV1` proto.  When `creator_public_key`
    /// is omitted the handler falls back to the on-chain creator pk recorded
    /// on the vault — preserving the convenience UX while keeping the wire
    /// format strict.
    async fn dlv_invalidate(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.invalidate: {e}")),
        };
        if bytes.is_empty() {
            return err("dlv.invalidate: empty DlvInvalidateV1 payload".into());
        }
        let req = match generated::DlvInvalidateV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "dlv.invalidate: decode DlvInvalidateV1 failed: {e}"
                ))
            }
        };
        if req.vault_id.len() != 32 {
            return err("dlv.invalidate: vault_id must be 32 bytes".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);
        let reason = req.reason.clone();

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let vault_lock = match dlv_manager.get_vault(&vault_id).await {
            Ok(v) => v,
            Err(e) => return err(format!("dlv.invalidate: vault not found: {e}")),
        };
        let (creator_pk_on_vault, locked_amount, token_id_opt) = {
            let v = vault_lock.lock().await;
            let (locked, tid): (u64, Option<String>) = match &v.fulfillment_condition {
                dsm::vault::fulfillment::FulfillmentMechanism::Payment {
                    amount, token_id, ..
                } => (*amount, Some(token_id.clone())),
                _ => (0, None),
            };
            (v.creator_public_key.clone(), locked, tid)
        };
        // The wire-supplied creator_public_key MUST match the vault's recorded
        // creator pk (the strict-fail authority for invalidation).  An empty
        // wire field is allowed and resolves to the vault's recorded pk.
        let creator_pk = if req.creator_public_key.is_empty() {
            creator_pk_on_vault
        } else if req.creator_public_key.as_slice() == creator_pk_on_vault.as_slice() {
            req.creator_public_key.clone()
        } else {
            return err(
                "dlv.invalidate: creator_public_key on request does not match vault creator".into(),
            );
        };

        let deltas: Vec<dsm::types::device_state::BalanceDelta> =
            match (&token_id_opt, locked_amount) {
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
            signature: req.signature.clone(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.invalidate: get_current_state failed: {e}")),
        };
        let actor = reference_state.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        if let Err(e) =
            self.core_sdk
                .execute_on_relationship(rel_key, actor, op, &deltas, Some(init_tip))
        {
            return err(format!(
                "dlv.invalidate: execute_on_relationship failed: {e}"
            ));
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
    /// Decoder accepts the typed `DlvClaimV1` proto.  When `claimant_public_key`
    /// is omitted on the wire the handler falls back to the local device's
    /// signing pk — the on-chain claim binding is rooted in the actor
    /// self-loop regardless of which pk is recorded on the operation.
    async fn dlv_claim(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.claim: {e}")),
        };
        if bytes.is_empty() {
            return err("dlv.claim: empty DlvClaimV1 payload".into());
        }
        let req = match generated::DlvClaimV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("dlv.claim: decode DlvClaimV1 failed: {e}")),
        };
        if req.vault_id.len() != 32 {
            return err("dlv.claim: vault_id must be 32 bytes".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);
        let claim_proof = req.claim_proof.clone();

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

        let deltas: Vec<dsm::types::device_state::BalanceDelta> =
            match (&token_id_opt, locked_amount) {
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

        // Wire-supplied claimant pk takes precedence; fall back to the
        // local device's signing pk if the field is omitted.
        let claimant_pk = if req.claimant_public_key.is_empty() {
            crate::sdk::signing_authority::current_public_key().unwrap_or_default()
        } else {
            req.claimant_public_key.clone()
        };
        let op = dsm::types::operations::Operation::DlvClaim {
            vault_id: vault_id.to_vec(),
            claim_proof: claim_proof.clone(),
            claimant_public_key: claimant_pk,
            signature: req.signature.clone(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        if let Err(e) =
            self.core_sdk
                .execute_on_relationship(rel_key, actor, op, &deltas, Some(init_tip))
        {
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

    /// dlv.unlockRouted — atomic-route unlock path for SoFi (chunk #4).
    ///
    /// Decodes a `DlvUnlockRoutedV1` carrying a typed `RouteCommitV1`,
    /// runs the SDK eligibility check (vault_id ∈ RouteCommit AND
    /// `is_external_commitment_visible(X)` returns Ok(true)) before
    /// emitting the standard `Operation::DlvUnlock` on the unlocker's
    /// self-loop.  No new on-chain operation type — atomicity is
    /// achieved off-chain via the visibility of X (SoFi spec §3.2,
    /// §5.1; the state machine does not know about routing).
    ///
    /// Failure modes are typed via `RouteCommitVerifyError` so a
    /// failed verification returns a precise error (rather than a
    /// generic `dlv.unlock failed`) — this is what unlocks
    /// fail-closed semantics for vault owners that haven't yet seen
    /// the trader's anchor publish.
    async fn dlv_unlock_routed(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.unlockRouted: {e}")),
        };
        if bytes.is_empty() {
            return err("dlv.unlockRouted: empty DlvUnlockRoutedV1 payload".into());
        }
        let req = match generated::DlvUnlockRoutedV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "dlv.unlockRouted: decode DlvUnlockRoutedV1 failed: {e}"
                ));
            }
        };
        if req.vault_id.len() != 32 {
            return err("dlv.unlockRouted: vault_id must be 32 bytes".into());
        }
        if req.device_id.len() != 32 {
            return err("dlv.unlockRouted: device_id must be 32 bytes".into());
        }
        if req.route_commit_bytes.is_empty() {
            return err("dlv.unlockRouted: route_commit_bytes is required".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);

        // SDK eligibility gate.  Fails closed on every typed variant.
        let hop = match crate::sdk::route_commit_sdk::verify_route_commit_unlock_eligibility(
            &req.route_commit_bytes,
            &vault_id,
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                return err(format!(
                    "dlv.unlockRouted: route-commit eligibility rejected: {e:?}"
                ));
            }
        };

        // Chunk #7 — AMM re-simulation gate.  For vaults whose
        // fulfillment condition is `AmmConstantProduct`, re-run the
        // constant-product math against THE VAULT'S CURRENT
        // RESERVES (not the advertisement's, which may be stale)
        // and reject if the trader's claimed `expected_output` does
        // not match.  This is the difference between
        // "signed-route execution" and
        // "independently re-simulated reserve-math execution".
        //
        // Reserves are read inside the vault mutex but the actual
        // post-trade update happens AFTER `execute_on_relationship`
        // succeeds — see the post-advance block below.  A concurrent
        // unlock between read and update is serialised by
        // `Mutex<LimboVault>`, so the lock-free window only matters
        // if the on-chain advance fails (in which case reserves were
        // never advanced — correct fail-closed).
        let dlv_manager = self.bitcoin_tap.dlv_manager();
        // Tier 2 Foundation: track whether the anchor-enforcement gate
        // bypassed verification because the vault's policy was Optional
        // (with no fields supplied) or Unspecified.  Surfaced via log so
        // callers can audit identity-binding posture.  The literal
        // sentinel string `anchor_enforcement_bypassed_optional_vault`
        // appears verbatim in this path so the regression guard finds it.
        let mut anchor_bypassed_optional: bool = false;
        // Stage post-trade reserves in canonical (a, b) ordering.  When
        // the on-chain DlvUnlock succeeds below we re-acquire the vault
        // lock and write these into `fulfillment_condition`.
        let amm_post_trade_reserves: Option<(u128, u128)> = {
            let vault_lock = match dlv_manager.get_vault(&vault_id).await {
                Ok(v) => v,
                Err(e) => {
                    return err(format!(
                        "dlv.unlockRouted: vault {} not in local DLVManager: {e}",
                        crate::util::text_id::encode_base32_crockford(&vault_id)
                    ));
                }
            };
            let vault = vault_lock.lock().await;

            // Tier 2 Foundation: anchor enforcement gate.  Verify the
            // RouteCommit hop's vault state binding fields match the
            // vault's LOCAL internal state (`current_sequence` +
            // `current_reserves_digest`) per the vault's
            // `anchor_enforcement` policy.  Storage anchors are
            // advertisement-only — the gate trusts the local
            // `DLVManager`, never re-reading from storage to "confirm"
            // the anchor (that would re-introduce storage trust).
            //
            //   Required    => fields MUST be present and match → reject otherwise
            //   Optional    => if fields present, must match; if absent,
            //                  fall through with a flag so callers know
            //                  identity-binding wasn't enforced
            //   Unspecified => grandfathered; same behaviour as Optional
            //                  with no enforcement
            //
            // The (seq + reserves_digest) match is sufficient because
            // owner_signature on the storage anchor couples them.
            {
                use dsm::types::proto::AnchorEnforcement;
                let policy = AnchorEnforcement::try_from(vault.anchor_enforcement)
                    .unwrap_or(AnchorEnforcement::Unspecified);
                // `vault_state_anchor_seq` is u64; its zero value is
                // meaningful at genesis, so we cannot use 0 as
                // "missing".  The two digest fields' emptiness is the
                // missing-flag because both are 32-byte fixed-len when
                // present.
                let has_anchor_fields = !hop.vault_state_reserves_digest.is_empty()
                    && !hop.vault_state_anchor_digest.is_empty();
                match (policy, has_anchor_fields) {
                    (AnchorEnforcement::Required, false) => {
                        return err("dlv.unlockRouted: vault requires anchor binding but \
                             RouteCommit hop omits one or more fields \
                             (vault_state_reserves_digest / vault_state_anchor_digest)"
                            .to_string());
                    }
                    (AnchorEnforcement::Required, true) | (AnchorEnforcement::Optional, true) => {
                        let internal_seq = vault.current_sequence;
                        if hop.vault_state_anchor_seq != internal_seq {
                            return err(format!(
                                "dlv.unlockRouted: vault state anchor sequence mismatch \
                                 (route={}, vault={})",
                                hop.vault_state_anchor_seq, internal_seq,
                            ));
                        }
                        let internal_digest = match vault.current_reserves_digest() {
                            Some(d) => d,
                            None => {
                                return err("dlv.unlockRouted: AMM reserves digest unavailable \
                                     for non-AMM vault"
                                    .to_string());
                            }
                        };
                        if hop.vault_state_reserves_digest != internal_digest.to_vec() {
                            return err("dlv.unlockRouted: vault state reserves digest mismatch"
                                .to_string());
                        }
                        // anchor_digest is bound at quote time; the gate
                        // does not re-fetch storage.  Architectural
                        // commitment: never re-read storage to "confirm"
                        // the anchor.
                    }
                    (AnchorEnforcement::Optional, false) | (AnchorEnforcement::Unspecified, _) => {
                        anchor_bypassed_optional = true;
                        log::info!(
                            "[dlv.unlockRouted] anchor_enforcement_bypassed_optional_vault \
                             vault={} policy={:?}",
                            crate::util::text_id::encode_base32_crockford(&vault_id),
                            policy,
                        );
                    }
                }
            }

            match crate::sdk::route_commit_sdk::verify_amm_swap_against_reserves(
                &hop,
                &vault.fulfillment_condition,
            ) {
                Ok(Some(outcome)) => Some((outcome.new_reserve_a, outcome.new_reserve_b)),
                Ok(None) => None,
                Err(e) => {
                    return err(format!(
                        "dlv.unlockRouted: AMM re-simulation rejected: {e:?}"
                    ));
                }
            }
        };
        // Suppress unused-warning for the anchor-enforcement bypass
        // tracker when the function path doesn't otherwise consume it
        // (today the response path doesn't surface it).  Reading the
        // local keeps it visible to future response-shape changes
        // without flagging dead-code.
        let _ = anchor_bypassed_optional;

        // Past the gate.  Emit the standard DlvUnlock on the unlocker's
        // self-loop — same operation the non-routed `dlv.unlock` path
        // produces.  Atomicity is the X-visibility we just verified.
        let unlocker_pk = if req.unlocker_public_key.is_empty() {
            req.device_id.clone()
        } else {
            req.unlocker_public_key.clone()
        };
        let op = dsm::types::operations::Operation::DlvUnlock {
            vault_id: vault_id.to_vec(),
            fulfillment_proof: req.route_commit_bytes.clone(),
            requester_public_key: unlocker_pk,
            signature: req.signature.clone(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => {
                return err(format!("dlv.unlockRouted: get_current_state failed: {e}"));
            }
        };
        let actor = reference_state.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        if let Err(e) =
            self.core_sdk
                .execute_on_relationship(rel_key, actor, op, &[], Some(init_tip))
        {
            return err(format!(
                "dlv.unlockRouted: execute_on_relationship failed: {e}"
            ));
        }

        // Chunk #7 — post-advance reserve update.  The on-chain DlvUnlock
        // succeeded, so the swap is committed; mutate the vault's
        // reserves so the next routed unlock against this vault sees
        // the post-trade state and any stale routing-vault advertisement
        // gets caught at the chunk-#7 re-simulation gate.  After the
        // local reserve update we ALSO republish the routing-vault
        // advertisement on storage (republish-on-settled) so the next
        // trader's quote reflects the post-trade reserves rather than
        // hitting OutputMismatch on every attempt.
        if let Some((new_a, new_b)) = amm_post_trade_reserves {
            // Capture the canonical token pair from the vault's AMM
            // fulfillment so we can address the routing advertisement
            // for republish without reconstructing it from the route.
            let mut canonical_pair: Option<(Vec<u8>, Vec<u8>)> = None;
            // Tier 2 Foundation: capture the post-settle (sequence,
            // reserves_digest) cloned out of the lock so we can sign +
            // republish a fresh `VaultStateAnchorV1` after the lock is
            // released.  The local sequence is the LOCAL authoritative
            // truth — the chunks #7 gate binds against it.  The storage
            // anchor is republished best-effort as a discovery
            // advertisement only.
            let mut post_settle_anchor: Option<(u64, [u8; 32])> = None;
            // Best-effort: a failure here means the vault's local state
            // diverges from the advanced chain by one swap.  The chain
            // is authoritative; the vault state will resync at next
            // restart from the proto stored on chain.  Log + continue.
            match dlv_manager.get_vault(&vault_id).await {
                Ok(vault_lock) => {
                    let mut vault = vault_lock.lock().await;
                    if let dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                        token_a,
                        token_b,
                        reserve_a,
                        reserve_b,
                        fee_bps,
                    } = &mut vault.fulfillment_condition
                    {
                        *reserve_a = new_a;
                        *reserve_b = new_b;
                        let token_a_clone = token_a.clone();
                        let token_b_clone = token_b.clone();
                        let fee_bps_val: u32 = *fee_bps;
                        canonical_pair = Some((token_a_clone.clone(), token_b_clone.clone()));
                        // Advance vault internal sequence.  Use
                        // `current_sequence.saturating_add(1)` so a
                        // pathological u64::MAX doesn't wrap silently;
                        // saturation is correct fail-closed because the
                        // chunks #7 gate binds equality and any further
                        // routes against a saturated vault would simply
                        // mismatch and reject (preferable to silent wrap).
                        vault.current_sequence = vault.current_sequence.saturating_add(1);
                        let new_seq = vault.current_sequence;
                        let new_digest = dsm::dlv::vault_state_anchor::compute_reserves_digest(
                            &token_a_clone,
                            &token_b_clone,
                            new_a,
                            new_b,
                            fee_bps_val,
                        );
                        post_settle_anchor = Some((new_seq, new_digest));
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[dlv.unlockRouted] post-advance reserve update for {} failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&vault_id)
                    );
                }
            }

            // Republish the routing-vault advertisement with the new
            // reserves + bumped state_number so the next trader's
            // quote reflects post-trade liquidity.  Best-effort: a
            // failure (e.g. vault never advertised) leaves the vault
            // local-only and traders won't discover it for further
            // routes — correct fail-closed semantics.
            if let Some((token_a, token_b)) = canonical_pair {
                if let Err(e) =
                    crate::sdk::routing_sdk::republish_active_advertisement_with_reserves(
                        &token_a, &token_b, &vault_id, new_a, new_b,
                    )
                    .await
                {
                    log::warn!(
                        "[dlv.unlockRouted] post-advance routing-ad republish for {} failed (vault may not be advertised): {e}",
                        crate::util::text_id::encode_base32_crockford(&vault_id)
                    );
                }
            }

            // Tier 2 Foundation: republish the vault state anchor for
            // the post-settle (sequence, reserves_digest) so off-device
            // traders quoting the next swap stamp the matching
            // `RouteCommitHop` binding fields.  This is an
            // advertisement-only write — vault internal state is the
            // authoritative truth and the chunks #7 gate already
            // verified the prior anchor against the local vault.
            // Best-effort: failure logs a warning, never rolls back
            // the on-chain unlock.
            if let Some((new_seq, new_digest)) = post_settle_anchor {
                if let (Ok(pk), Ok(sk)) = (
                    crate::sdk::signing_authority::current_public_key(),
                    crate::sdk::signing_authority::current_secret_key(),
                ) {
                    if !pk.is_empty() && !sk.is_empty() {
                        match dsm::dlv::vault_state_anchor::sign_vault_state_anchor(
                            &vault_id,
                            new_seq,
                            &new_digest,
                            &pk,
                            &sk,
                        ) {
                            Ok(signed) => {
                                let proto_bytes =
                                    crate::sdk::vault_state_anchor_codec::encode_anchor_to_proto(
                                        &signed,
                                    );
                                if let Err(e) =
                                    publish_vault_state_anchor(&vault_id, &proto_bytes).await
                                {
                                    log::warn!(
                                        "[dlv.unlockRouted] anchor republish (seq={}) failed for {}: {e}",
                                        new_seq,
                                        crate::util::text_id::encode_base32_crockford(&vault_id),
                                    );
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "[dlv.unlockRouted] anchor sign failed for seq={} vault={}: {e:?}",
                                    new_seq,
                                    crate::util::text_id::encode_base32_crockford(&vault_id),
                                );
                            }
                        }
                    } else {
                        log::warn!(
                            "[dlv.unlockRouted] anchor republish (seq={}) skipped for {}: signing authority empty",
                            new_seq,
                            crate::util::text_id::encode_base32_crockford(&vault_id),
                        );
                    }
                } else {
                    log::warn!(
                        "[dlv.unlockRouted] anchor republish (seq={}) skipped for {}: signing authority unavailable",
                        new_seq,
                        crate::util::text_id::encode_base32_crockford(&vault_id),
                    );
                }
            }
        }

        let resp = generated::AppStateResponse {
            key: "dlv.unlockRouted".to_string(),
            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}

/// Publish a `VaultStateAnchorV1` proto blob to storage at the
/// canonical Tier 2 Foundation key
/// `defi/vault-state/{vault_id_b32}/latest`.  Best-effort —
/// vault internal state is authoritative; this storage write is
/// advertisement-and-discovery only.
async fn publish_vault_state_anchor(vault_id: &[u8; 32], proto_bytes: &[u8]) -> Result<(), String> {
    let key = format!(
        "defi/vault-state/{}/latest",
        crate::util::text_id::encode_base32_crockford(vault_id),
    );
    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(&key, proto_bytes)
        .await
        .map(|_| ())
        .map_err(|e| format!("storage put failed: {e:?}"))
}
