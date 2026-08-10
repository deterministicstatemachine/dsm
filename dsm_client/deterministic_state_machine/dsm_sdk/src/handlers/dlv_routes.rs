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

/// Human-readable name for an asset, resolved FROM its identity.
///
/// Deliberately one-directional. `policy_commit → ticker` is one-to-one, so it
/// cannot pick the wrong asset; `ticker → policy_commit` is one-to-many and is
/// exactly the ambiguity removed from the vault path. Falls back to the Base32
/// anchor, which is never ambiguous, rather than to a guess.
fn display_name_for(policy_commit: &[u8; 32]) -> String {
    match crate::storage::client_db::token_registry::get_token_by_policy_commit(policy_commit) {
        Ok(Some(row)) => row.token_id,
        _ => crate::util::text_id::encode_base32_crockford(policy_commit),
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
            "dlv.reconcile" => self.dlv_reconcile(i).await,
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
                let (token_a, token_b, fee_bps) = match &vault.fulfillment_condition {
                    dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                        token_a,
                        token_b,
                        fee_bps,
                    } => (token_a.clone(), token_b.clone(), *fee_bps),
                    _ => continue,
                };
                // Reserves come from THIS DEVICE'S encumbered leaves, not from
                // the condition and not from an advertisement. The owner's
                // screen must show what the owner actually holds.
                let (reserve_a, reserve_b) = {
                    let resolve = |t: &[u8]| -> Option<[u8; 32]> {
                        let tid = std::str::from_utf8(t).ok()?;
                        self.wallet.token_sdk.resolve_policy_commit_strict(tid).ok()
                    };
                    match (
                        self.core_sdk.device_head(),
                        resolve(&token_a),
                        resolve(&token_b),
                    ) {
                        (Some(head), Some(pc_a), Some(pc_b)) => (
                            head.vault_reserve(&vid, &pc_a),
                            head.vault_reserve(&vid, &pc_b),
                        ),
                        _ => (0, 0),
                    }
                };
                let anchor_sequence = vault.current_sequence;
                let anchor_enforcement = vault.anchor_enforcement;
                // Phase 13 follow-up: pull the persisted `policy_digest`
                // so the owner-side LiquidityScreen republish path can
                // pass the real digest (instead of 32 zero bytes) to
                // `route.publishRoutingAdvertisement` on retry.  Vaults
                // created before this field was added (legacy on-disk
                // state) carry `None`; the summary leaves both fields
                // empty and the frontend suppresses the Publish-retry
                // button for those vaults.
                let policy_digest_opt = vault.policy_digest;
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

                // Phase 13 follow-up: derive the canonical routing
                // advertisement key string entirely in Rust (Layer
                // Communication Law: protocol decisions belong in Rust,
                // frontend is a renderer).  Matches the original
                // create-flow construction
                // `defi/spec/amm/<first-16-chars-of-vault-id-b32>` so
                // the republish path stays bit-identical to the
                // original publish path.
                let unlock_spec_key_opt: Option<String> = policy_digest_opt.map(|_| {
                    let vid_b32 = crate::util::text_id::encode_base32_crockford(&vid);
                    let prefix: String = vid_b32.chars().take(16).collect();
                    format!("defi/spec/amm/{prefix}")
                });
                out.push(generated::AmmVaultSummaryV1 {
                    vault_id: vid.to_vec(),
                    token_a,
                    token_b,
                    reserve_a,
                    reserve_b,
                    // Reconciliation is not wired yet; the owner sees a real
                    // zero rather than an invented number.
                    pending_unapplied: 0,
                    fee_bps,
                    advertised_state_number: state_number,
                    routing_advertised: advertised,
                    anchor_sequence,
                    anchor_enforcement,
                    // Phase 13 follow-up: populate only when the vault
                    // has a persisted digest (post-fix vaults).  Legacy
                    // vaults carry `None` → frontend hides the
                    // Publish-retry button rather than corrupting the
                    // advertisement with 32 zero bytes.
                    unlock_spec_digest: policy_digest_opt.map(|d| d.to_vec()),
                    unlock_spec_key: unlock_spec_key_opt,
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
    /// `sofi/vault-state/{vault_id_b32}/latest`.  Vault internal
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
        let key = format!("sofi/vault-state/{}/latest", vault_id_b32);
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
        let expected_content_digest: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_DLV_CONTENT,
            &spec.content,
        );
        let expected_fm_digest: [u8; 32] = dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_DLV_FULFILLMENT,
            &spec.fulfillment_bytes,
        );
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
        // Accept-or-sign: the actual SPHINCS+ signature must cover the
        // LimboVault's `parameters_hash` (the same value `vault.verify()`
        // re-derives in `finalize_vault`). We don't know that hash until
        // `prepare_vault` runs, so the empty-signature wallet-sign
        // happens BELOW after the draft is built. Don't pre-compute a
        // wrong-domain signature here — it would mismatch the
        // canonical params digest and `finalize_vault` would reject.
        let needs_wallet_sign = req.signature.is_empty();

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
        // Captured before `fulfillment` is moved into the draft, so the
        // funding-leg check below can still see the pair the predicate declares.
        // Pair AND fee together: both are needed for the persisted vault record,
        // and reading them from one match keeps them describing one predicate.
        let amm_predicate: Option<(Vec<u8>, Vec<u8>, u32)> = match &fulfillment {
            dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                token_a,
                token_b,
                fee_bps,
            } => Some((token_a.clone(), token_b.clone(), *fee_bps)),
            _ => None,
        };
        let amm_pair: Option<(Vec<u8>, Vec<u8>)> = amm_predicate
            .as_ref()
            .map(|(a, b, _)| (a.clone(), b.clone()));
        let amm_fee_bps: u32 = amm_predicate.as_ref().map(|(_, _, f)| *f).unwrap_or(0);

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
        // Encryption target: intended recipient's Kyber pk if supplied,
        // otherwise the WALLET's Kyber pk (NOT creator_public_key, which
        // is the SPHINCS+ key and the wrong shape for kyber_encapsulate).
        // The wallet's Kyber keypair was generated at genesis and lives
        // in the keystore under `{device_id}_device_kyber_pk` — the same
        // accessor `posted_dlv_routes` uses for posted-DLV recipients.
        let encryption_pk = match intended_recipient_opt.clone() {
            Some(pk) => pk,
            None => match self.wallet.get_kyber_public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    return err(format!(
                        "dlv.create: empty intended_recipient defaults to self-encryption \
                         but wallet kyber pk is unavailable: {e}"
                    ));
                }
            },
        };

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

        // IDENTITY FIRST — before any signature is produced.
        //
        // The accept-or-sign block below spends a SPHINCS+ signature. A leg that
        // does not name a real asset can be rejected from its own bytes alone,
        // so rejecting it after signing would mean paying for crypto to
        // authorise a call that was never admissible.
        let mut funding: Vec<([u8; 32], u64)> = Vec::with_capacity(req.funding_legs.len());
        for leg in &req.funding_legs {
            if leg.amount == 0 {
                return err("dlv.create: a funding leg must carry a non-zero amount".into());
            }
            // The leg names the asset by its 32-byte policy commit. It used to
            // carry a ticker that was resolved through the local registry — and
            // that resolution is precisely the ambiguity being removed: a ticker
            // can name more than one token, so the lookup could encumber a
            // different asset than the caller meant with every downstream
            // signature still verifying. No fallback; a malformed identity dies
            // here, before any balance is touched.
            let Ok(pc) = <[u8; 32]>::try_from(leg.policy_commit.as_slice()) else {
                return err(format!(
                    "dlv.create: a funding leg must name a 32-byte policy commit, got {} bytes — \
                     a ticker is not an identity and is never resolved to one",
                    leg.policy_commit.len()
                ));
            };
            if funding.iter().any(|(prev, _)| *prev == pc) {
                return err("dlv.create: an asset appears twice in the funding legs".into());
            }
            funding.push((pc, leg.amount));
        }

        // An AMM vault's legs must BE its pair, in the canonical order the
        // predicate declares. Otherwise the reserves a trader quotes against
        // would describe different assets than the curve governs.
        //
        // Both sides go through the one pair parser, so the ordering here and
        // the ordering a trader derives at quote time cannot disagree.
        if let Some((token_a, token_b)) = amm_pair.as_ref() {
            let pair = match dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) {
                Ok(p) => p,
                Err(e) => return err(format!("dlv.create: vault pair is not canonical: {e}")),
            };
            if funding.len() != 2 {
                return err(
                    "dlv.create: an AMM vault must be funded with exactly two legs — its own pair"
                        .into(),
                );
            }
            let mut legs_sorted = [funding[0].0, funding[1].0];
            legs_sorted.sort();
            if legs_sorted != [pair.a(), pair.b()] {
                return err("dlv.create: the funding legs must be the vault's own pair".into());
            }
            // Store the legs in canonical order so the reserve leaves, the
            // advertisement and the predicate all agree on which side is which.
            if funding[0].0 != pair.a() {
                funding.swap(0, 1);
            }
        }

        // Accept-or-sign (Track C.4) — when the trader-supplied signature
        // was empty, sign the draft's `parameters_hash` with the wallet's
        // SPHINCS+ secret key.  `parameters_hash` is the same value
        // `vault.verify()` re-derives inside `finalize_vault` (see
        // limbo_vault.rs:1217-1226), so this is the only signature
        // shape that round-trips.
        if needs_wallet_sign {
            if draft.parameters_hash.len() != 32 {
                return err(format!(
                    "dlv.create: draft.parameters_hash unexpected length {} (expected 32)",
                    draft.parameters_hash.len()
                ));
            }
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
                &draft.parameters_hash,
            ) {
                Ok(s) => s,
                Err(e) => {
                    return err(format!("dlv.create: SPHINCS+ sign failed: {e}"));
                }
            };
            req.signature = sig;
        }

        // FUNDING LEGS — the assets this vault actually encumbers.
        //
        // Replaces a single `(token_id, locked_amount)` pair that could not
        // express a two-sided vault at all, which is why AMM vaults were
        // created holding nothing and advertised reserves nobody held. Zero
        // legs is a content-only vault; an AMM vault must carry exactly two.
        // Reject insufficiency BEFORE anything is built or signed, with a
        // message naming the shortfall. The chokepoint checks again — this is
        // the readable failure, that is the structural one.
        if let Some(head) = self.core_sdk.device_head() {
            for (pc, amount) in funding.iter() {
                let have = head.balance(pc);
                if have < *amount {
                    // DISPLAY metadata, resolved from the identity — never the
                    // other way round. commit → ticker is one-to-one and safe;
                    // ticker → commit is the ambiguous direction that was
                    // removed. If the name is unknown the anchor still names the
                    // asset exactly.
                    let named = display_name_for(pc);
                    return err(format!(
                        "dlv.create: insufficient {named} to encumber (need {amount}, have {have})"
                    ));
                }
            }
        }

        // Kept for the posted-mode advertisement further down, which describes
        // a single locked asset. Display only.
        let token_id_str_opt: Option<String> = funding.first().map(|(pc, _)| display_name_for(pc));
        let locked_u64: u64 = funding.first().map(|(_, a)| *a).unwrap_or(0);
        let policy_commit_opt: Option<[u8; 32]> = funding.first().map(|(pc, _)| *pc);

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
        // REFUSE A SECOND CREATION. `dlv.create` moves value, so a repeated
        // request is never permission to encumber again.
        //
        // Both persistence domains are inspected, because they can disagree
        // after a crash or a historical bug, and each disagreement is its own
        // refusal rather than something to quietly complete. Completing a partial
        // prior creation from inside a value-moving constructor would be a
        // repair; repairs belong in an explicit recovery operation where they can
        // be audited.
        //
        // This is the READABLE check. The race-proof ones are inside the atomic
        // boundary: `advance` refuses an existing reserve leaf under the `sm`
        // lock, and the record is re-checked inside the write transaction below.
        // A check here alone would leave a window between inspection and write
        // for a second concurrent creator.
        let existing_record =
            crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
                .unwrap_or(None);
        let existing_leaf = self.core_sdk.device_head().is_some_and(|h| {
            funding
                .iter()
                .any(|(pc, _)| h.vault_reserve_entry(&vault_id, pc).is_some())
        });
        match (existing_record.is_some(), existing_leaf) {
            (true, true) => {
                return err(
                    "dlv.create: this vault already exists and is funded — refusing to create it \
                     again"
                        .into(),
                )
            }
            (true, false) => {
                return err(
                    "dlv.create: a record for this vault exists but it holds no reserves — \
                     inconsistent state, refusing; this needs recovery, not creation"
                        .into(),
                )
            }
            (false, true) => {
                return err(
                    "dlv.create: this vault already holds encumbered reserves but has no record — \
                     orphaned encumbrance, refusing; this needs recovery, not creation"
                        .into(),
                )
            }
            (false, false) => {}
        }

        // The encumbrance rides THIS advance, and the vault's record is written
        // inside the same SQLite transaction as the head. Either the transition,
        // both reserve leaves and the record all land, or none of them do.
        let reserve_funding =
            amm_pair
                .as_ref()
                .map(|_| dsm::types::device_state::VaultReserveMutation::Fund {
                    vault_id,
                    legs: funding.clone(),
                    vault_sequence: 0,
                });
        let record_to_persist = match amm_pair.as_ref() {
            Some((token_a, token_b)) => {
                match dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) {
                    Ok(pair) => {
                        let owner = self.core_sdk.device_head();
                        let mut pd = [0u8; 32];
                        pd.copy_from_slice(&spec.policy_digest);
                        Some(
                            crate::storage::client_db::amm_vault_records::AmmVaultRecord {
                                vault_id,
                                owner_genesis: owner
                                    .as_ref()
                                    .map(|h| h.genesis())
                                    .unwrap_or_default(),
                                owner_devid: owner.as_ref().map(|h| h.devid()).unwrap_or_default(),
                                policy_commit_a: pair.a(),
                                policy_commit_b: pair.b(),
                                fee_bps: amm_fee_bps,
                                anchor_enforcement: spec.anchor_enforcement,
                                policy_digest: pd,
                            },
                        )
                    }
                    Err(e) => {
                        return err(format!("dlv.create: vault pair is not canonical: {e}"));
                    }
                }
            }
            None => None,
        };

        let in_tx = |tx: &rusqlite::Transaction<'_>,
                     _o: &dsm::types::device_state::AdvanceOutcome|
         -> Result<(), dsm::types::error::DsmError> {
            let Some(rec) = record_to_persist.as_ref() else {
                return Ok(());
            };
            // Re-check inside the transaction. Two concurrent creators could both
            // pass the readable check above; only one can hold this transaction.
            let already: i64 = tx
                .query_row(
                    "SELECT COUNT(1) FROM amm_vault_records WHERE vault_id = ?1",
                    rusqlite::params![rec.vault_id.as_slice()],
                    |r| r.get(0),
                )
                .map_err(|e| {
                    dsm::types::error::DsmError::storage(
                        format!("dlv.create: vault record pre-check: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            if already > 0 {
                return Err(dsm::types::error::DsmError::invalid_operation(
                    "dlv.create: a record for this vault appeared concurrently — refusing",
                ));
            }
            tx.execute(
                "INSERT INTO amm_vault_records(
                    vault_id, owner_genesis, owner_devid, policy_commit_a, policy_commit_b,
                    fee_bps, anchor_enforcement, policy_digest, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    rec.vault_id.as_slice(),
                    rec.owner_genesis.as_slice(),
                    rec.owner_devid.as_slice(),
                    rec.policy_commit_a.as_slice(),
                    rec.policy_commit_b.as_slice(),
                    rec.fee_bps,
                    rec.anchor_enforcement,
                    rec.policy_digest.as_slice(),
                    crate::util::deterministic_time::tick() as i64,
                ],
            )
            .map_err(|e| {
                dsm::types::error::DsmError::storage(
                    format!("dlv.create: persist vault record: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            Ok(())
        };

        if let Err(e) = self.core_sdk.execute_on_relationship_with_reserve_mutation(
            rel_key,
            actor,
            op,
            &[],
            Some(init_tip),
            reserve_funding,
            Some(&in_tx),
        ) {
            return err(format!("dlv.create: funded creation failed: {e}"));
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
        //
        // Phase 13 follow-up: also stamp the vault's `policy_digest` from
        // the spec.  This is the canonical 32-byte CPTA anchor that the
        // owner's first publish stamped into the routing advertisement's
        // `unlock_spec_digest`.  Persisting it on the vault lets the
        // owner-side LiquidityScreen republish path read the real digest
        // from `AmmVaultSummaryV1` instead of stamping 32 zero bytes
        // (which silently corrupted advertisements pre-fix).
        match dlv_manager.get_vault(&vault_id).await {
            Ok(vault_lock) => {
                let mut vault = vault_lock.lock().await;
                vault.anchor_enforcement = spec.anchor_enforcement;
                // spec.policy_digest length is already validated as 32
                // bytes at line 227-229; copy into a fixed array.  Skip
                // stamping if the spec carried no digest (defensive — the
                // earlier validation rejects empty too, so this is just
                // belt-and-braces).
                if spec.policy_digest.len() == 32 {
                    let mut pd = [0u8; 32];
                    pd.copy_from_slice(&spec.policy_digest);
                    vault.policy_digest = Some(pd);
                }
            }
            Err(e) => {
                log::warn!(
                    "[dlv.create] anchor_enforcement stamp: get_vault for {} failed: {e}",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                );
            }
        }

        // The vault's record was persisted INSIDE the advance transaction above,
        // so it cannot outlive a rolled-back creation or be lost to a crash that
        // leaves the reserves encumbered.

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
                        // Digest over the reserves this device just encumbered,
                        // read from its own leaves — the condition no longer
                        // carries quantities to hash.
                        let reserves_digest_opt = match self.core_sdk.device_head() {
                            Some(head) => {
                                let (ra, rb) = funding
                                    .first()
                                    .zip(funding.get(1))
                                    .map(|((pc_a, _), (pc_b, _))| {
                                        (
                                            head.vault_reserve(&vault_id, pc_a),
                                            head.vault_reserve(&vault_id, pc_b),
                                        )
                                    })
                                    .unwrap_or((0, 0));
                                vault.reserves_digest_for(ra, rb)
                            }
                            None => None,
                        };
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

                                    // Phase 7 — SoFi spec §4.1.2: also
                                    // commit the genesis vault state into
                                    // the PD-SMT and publish a
                                    // VaultStateInclusionProofV1.  The
                                    // anchor above is the legacy fast
                                    // path (works for composition without
                                    // SMT verification); the inclusion
                                    // proof is the spec-strict
                                    // strengthening that closes the
                                    // signing-key-forgery hole.
                                    publish_vault_state_inclusion_proof(
                                        self.core_sdk.as_ref(),
                                        &vault_id,
                                        0,
                                        &reserves_digest,
                                        &pk,
                                        &sk,
                                    )
                                    .await;

                                    // And the RESERVE inclusion proof, which is
                                    // what turns "the owner says this vault holds
                                    // 10,000 ERA" into "the owner's own device
                                    // root commits it". Without it a trader has
                                    // no authenticated liquidity to quote
                                    // against and `compose_vault_state` refuses
                                    // the vault outright.
                                    //
                                    // Published AFTER the vault-state leaf, and
                                    // that ordering is load-bearing:
                                    // `install_vault_state_leaf` performs its own
                                    // head mutation, so the root moves. Both
                                    // proofs must be built from the SAME final
                                    // head, because the composer requires them to
                                    // agree on `smt_root` — building the reserve
                                    // proof first would bind the pre-install root
                                    // and every quote would fail closed.
                                    let funded_commits: Vec<[u8; 32]> =
                                        funding.iter().map(|(pc, _)| *pc).collect();
                                    publish_reserve_inclusion_proof(
                                        self.core_sdk.as_ref(),
                                        &vault_id,
                                        0,
                                        &funded_commits,
                                        &pk,
                                        &sk,
                                    )
                                    .await;
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
    /// `dlv.reconcile` — the OWNER folds a verified settlement into its reserves.
    ///
    /// The trader's credit was final at the trader's own advance. This is the
    /// owner learning what already happened, so it AUTHORIZES nothing: every
    /// value acted on is re-derived from the receipt fetched under `(vault, x)`
    /// and verified against the trader's signature and SMT path. The request
    /// says only which settlement to look at.
    ///
    /// Idempotent. Folding the same receipt twice would move the reserves twice
    /// on a trade that happened once, so a receipt whose sequence step the vault
    /// has already taken applies nothing and reports success.
    async fn dlv_reconcile(&self, i: AppInvoke) -> AppResult {
        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.reconcile: {e}")),
        };
        let req = match generated::DlvReconcileV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("dlv.reconcile: decode DlvReconcileV1 failed: {e}")),
        };
        let (Ok(vault_id), Ok(x)) = (
            <[u8; 32]>::try_from(req.vault_id.as_slice()),
            <[u8; 32]>::try_from(req.x.as_slice()),
        ) else {
            return err("dlv.reconcile: vault_id and x must both be 32 bytes".into());
        };

        // The receipt is the authority. No receipt, nothing to apply — and that
        // is a refusal rather than a no-op, because the caller asked about a
        // settlement that is not witnessed.
        let Some(receipt) =
            crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x).await
        else {
            return err(format!(
                "dlv.reconcile: no verified settlement receipt for vault {} at that commitment",
                crate::util::text_id::encode_base32_crockford(&vault_id),
            ));
        };

        let Some(head) = self.core_sdk.device_head() else {
            return err("dlv.reconcile: no device head".into());
        };
        // IDEMPOTENCE, checked against the leaves rather than a bookkeeping
        // table: the reserve leaf already carries the sequence this receipt
        // would advance to, so a repeat is visible in the state itself.
        let already = head
            .vault_reserve_entry(&vault_id, &receipt.trade.input_policy_commit)
            .map(|e| e.sequence >= receipt.trade.new_sequence)
            .unwrap_or(false);
        if already {
            return pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                generated::AppStateResponse {
                    key: "dlv.reconcile".to_string(),
                    value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
                },
            ));
        }

        let op = dsm::types::operations::Operation::DlvOwnerApply {
            vault_id: vault_id.to_vec(),
            settlement_receipt_id: receipt.receipt_id,
            pending_pointer_x: x,
            parent_sequence: receipt.trade.parent_sequence,
            new_sequence: receipt.trade.new_sequence,
            parent_reserves_digest: [0u8; 32],
            new_reserves_digest: [0u8; 32],
            input_policy_commit: receipt.trade.input_policy_commit,
            output_policy_commit: receipt.trade.output_policy_commit,
            input_amount: receipt.trade.input_amount,
            output_amount: receipt.trade.output_amount,
            // Signed below. Empty here was previously the ONLY value this field could
            // hold — `with_signature` silently ignored the variant — so the owner's root
            // committed an unauthorized record of an authorized settlement.
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        // Sign BEFORE the advance, for the same reason as `DlvSettle`: the signature is
        // inside the committed operation bytes and therefore inside the chain tip.
        let op = match self.core_sdk.sign_operation_sphincs(op) {
            Ok(signed) => signed,
            Err(e) => return err(format!("dlv.reconcile: failed to sign DlvOwnerApply: {e}")),
        };
        let mutation = dsm::types::device_state::VaultReserveMutation::ApplySettlement {
            vault_id,
            input_policy_commit: receipt.trade.input_policy_commit,
            input_amount: receipt.trade.input_amount,
            output_policy_commit: receipt.trade.output_policy_commit,
            output_amount: receipt.trade.output_amount,
            new_sequence: receipt.trade.new_sequence,
        };

        let reference_state = match self.core_sdk.get_current_state() {
            Ok(s) => s,
            Err(e) => return err(format!("dlv.reconcile: get_current_state failed: {e}")),
        };
        let actor = reference_state.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        // EMPTY deltas: the owner's spendable balance is not part of a
        // settlement. Only the reserve leaves move, in this same advance.
        if let Err(e) = self.core_sdk.execute_on_relationship_with_reserve_mutation(
            rel_key,
            actor,
            op,
            &[],
            Some(init_tip),
            Some(mutation),
            None,
        ) {
            return err(format!("dlv.reconcile: advance failed: {e}"));
        }

        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
            generated::AppStateResponse {
                key: "dlv.reconcile".to_string(),
                value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
            },
        ))
    }

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
        // Unused while the unlock fails closed; the posture logging it feeds
        // returns with the settlement work.
        #[allow(unused_mut, unused_variables)]
        // Populated by the AMM re-simulation arm below, from values live there.
        let mut settle_terms: Option<SettleTerms> = None;
        // Stage post-trade reserves in canonical (a, b) ordering.  When
        // the on-chain DlvUnlock succeeds below we re-acquire the vault
        // lock and write these into `fulfillment_condition`.
        #[allow(unused_variables)]
        // The AMM gate runs for its REFUSALS. Its post-trade reserve figures are
        // deliberately not kept: a settling trader does not hold the owner's
        // liquidity, and the owner learns of the move by verifying the receipt.
        {
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
            // RESERVES COME FROM THE OWNER'S PROOF, never from this device.
            //
            // A settling trader does not hold the owner's reserves — they are
            // encumbered leaves in the OWNER's device SMT. The authoritative
            // source is `VaultReserveInclusionProofV1`, published by the owner
            // and verified here against its own signature and SMT paths. Passing
            // zeros, as this once did, would let a hop bind to reserves nobody
            // holds.
            // Filled by the proof block below; the settle terms are only built
            // on the path where that block succeeded.
            let amm_fee_bps;
            let pair_a_for_digest;
            let pair_b_for_digest;
            let fee_bps_for_digest;
            let reserve_owner_devid;
            let reserve_owner_genesis;
            let reserve_root;
            let (proven_a, proven_b) = {
                let Some(proof) =
                    crate::sdk::vault_reserve_proof_codec::fetch_verified_reserve_proof(
                        &vault_id,
                        hop.vault_state_anchor_seq,
                    )
                    .await
                else {
                    return err(format!(
                        "dlv.unlockRouted: no verified reserve proof for vault {} at sequence {} \
                         — its liquidity is unproven and cannot be settled against",
                        crate::util::text_id::encode_base32_crockford(&vault_id),
                        hop.vault_state_anchor_seq,
                    ));
                };
                // The pair comes from the vault's OWN condition, so the legs the
                // proof is read for are the ones the curve governs.
                let dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                    token_a: ref vt_a,
                    token_b: ref vt_b,
                    fee_bps: vault_fee_bps,
                } = vault.fulfillment_condition
                else {
                    return err("dlv.unlockRouted: routed settlement requires an AMM vault".into());
                };
                let (Some(pc_a), Some(pc_b)) = (
                    <[u8; 32]>::try_from(vt_a.as_slice()).ok(),
                    <[u8; 32]>::try_from(vt_b.as_slice()).ok(),
                ) else {
                    return err("dlv.unlockRouted: vault pair is not 32-byte policy commits".into());
                };
                let (Some(a), Some(b)) = (
                    dsm::dlv::vault_reserve_inclusion::proven_amount(&proof, &pc_a),
                    dsm::dlv::vault_reserve_inclusion::proven_amount(&proof, &pc_b),
                ) else {
                    // An absent leg is UNPROVEN, never zero: a half-proved vault
                    // must not be settled against as if it were empty on one side.
                    return err(
                        "dlv.unlockRouted: the reserve proof does not cover both sides of the \
                         vault's pair"
                            .into(),
                    );
                };
                amm_fee_bps = vault_fee_bps;
                pair_a_for_digest = vt_a.clone();
                pair_b_for_digest = vt_b.clone();
                fee_bps_for_digest = vault_fee_bps;
                reserve_owner_devid = proof.owner_devid;
                reserve_owner_genesis = proof.owner_genesis;
                reserve_root = proof.smt_root;
                (a, b)
            };
            {
                use crate::sdk::route_commit_sdk::{AnchorGateReject, AnchorPosture};
                use dsm::types::proto::AnchorEnforcement;
                let policy = AnchorEnforcement::try_from(vault.anchor_enforcement)
                    .unwrap_or(AnchorEnforcement::Unspecified);
                // Fail-closed anchor gate: the hop's bound (seq,
                // reserves_digest, anchor_digest) must match the vault's
                // LOCAL current state per policy.  A mismatch means the
                // vault advanced since the RouteCommit was bound (stale
                // state).  Pure + storage-free — never re-reads storage.
                // The digest the gate compares against is derived from the
                // PROVEN reserves, not from local state and not from `None`.
                // Passing `None` made `ReservesDigestUnavailable` the outcome for
                // every Required vault — the gate could never pass, because the
                // one thing it needs was never supplied.
                let proven_digest = dsm::dlv::vault_state_anchor::compute_reserves_digest(
                    &pair_a_for_digest,
                    &pair_b_for_digest,
                    proven_a,
                    proven_b,
                    fee_bps_for_digest,
                );
                match crate::sdk::route_commit_sdk::enforce_anchor_binding(
                    policy,
                    &hop,
                    &vault_id,
                    vault.current_sequence,
                    Some(proven_digest),
                ) {
                    Ok(AnchorPosture::Enforced) => {}
                    Ok(AnchorPosture::BypassedOptional)
                    | Ok(AnchorPosture::BypassedUnspecified) => {
                        log::info!(
                            "[dlv.unlockRouted] anchor_enforcement_bypassed_optional_vault \
                             vault={} policy={:?}",
                            crate::util::text_id::encode_base32_crockford(&vault_id),
                            policy,
                        );
                    }
                    Err(AnchorGateReject::MissingFields) => {
                        return err("dlv.unlockRouted: vault requires anchor binding but \
                             RouteCommit hop omits one or more fields \
                             (vault_state_reserves_digest / vault_state_anchor_digest)"
                            .to_string());
                    }
                    Err(AnchorGateReject::SequenceMismatch { route, vault }) => {
                        return err(format!(
                            "dlv.unlockRouted: vault state anchor sequence mismatch \
                             (route={route}, vault={vault})"
                        ));
                    }
                    Err(AnchorGateReject::ReservesDigestMismatch) => {
                        return err(
                            "dlv.unlockRouted: vault state reserves digest mismatch".to_string()
                        );
                    }
                    Err(AnchorGateReject::AnchorDigestMismatch) => {
                        return err(
                            "dlv.unlockRouted: vault state anchor digest mismatch".to_string()
                        );
                    }
                    Err(AnchorGateReject::ReservesDigestUnavailable) => {
                        return err("dlv.unlockRouted: AMM reserves digest unavailable \
                             for non-AMM vault"
                            .to_string());
                    }
                }
            }

            match crate::sdk::route_commit_sdk::verify_amm_swap_against_reserves(
                &hop,
                &vault.fulfillment_condition,
                proven_a,
                proven_b,
            ) {
                Ok(Some(outcome)) => {
                    // Everything the settlement authorization needs, taken from
                    // the hop that was just verified against the owner's PROVEN
                    // reserves. Reading any of it from a second source would let
                    // the deltas describe a trade the re-simulation never
                    // accepted.
                    let (Some(in_pc), Some(out_pc)) = (
                        <[u8; 32]>::try_from(hop.token_in.as_slice()).ok(),
                        <[u8; 32]>::try_from(hop.token_out.as_slice()).ok(),
                    ) else {
                        return err(
                            "dlv.unlockRouted: hop assets are not 32-byte policy commits".into(),
                        );
                    };
                    let (Ok(in_amt), Ok(out_amt)) = (
                        <[u8; 16]>::try_from(hop.input_amount_u128.as_slice())
                            .map_err(|_| ())
                            .and_then(|b| u64::try_from(u128::from_be_bytes(b)).map_err(|_| ())),
                        <[u8; 16]>::try_from(hop.expected_output_amount_u128.as_slice())
                            .map_err(|_| ())
                            .and_then(|b| u64::try_from(u128::from_be_bytes(b)).map_err(|_| ())),
                    ) else {
                        return err(
                            "dlv.unlockRouted: hop amounts do not fit u64 base units".into()
                        );
                    };
                    let mut parent_digest = [0u8; 32];
                    if hop.vault_state_reserves_digest.len() == 32 {
                        parent_digest.copy_from_slice(&hop.vault_state_reserves_digest);
                    }
                    let mut anchor_digest = [0u8; 32];
                    if hop.vault_state_anchor_digest.len() == 32 {
                        anchor_digest.copy_from_slice(&hop.vault_state_anchor_digest);
                    }
                    settle_terms = Some(SettleTerms {
                        owner_public_key: vault.creator_public_key.clone(),
                        owner_devid: reserve_owner_devid,
                        owner_genesis: reserve_owner_genesis,
                        input_policy_commit: in_pc,
                        output_policy_commit: out_pc,
                        input_amount: in_amt,
                        output_amount: out_amt,
                        parent_reserves_digest: parent_digest,
                        reserve_proof_root: reserve_root,
                        predicate_digest: anchor_digest,
                        fee_bps: amm_fee_bps,
                        sigma: [0u8; 32],
                        settler_devid: {
                            let mut d = [0u8; 32];
                            if req.device_id.len() == 32 {
                                d.copy_from_slice(&req.device_id);
                            }
                            d
                        },
                    });
                    let _ = outcome;
                }
                Ok(None) => {}
                Err(e) => {
                    return err(format!(
                        "dlv.unlockRouted: AMM re-simulation rejected: {e:?}"
                    ));
                }
            }
        };
        // Past the gates. This is a SETTLEMENT: value moves.
        let unlocker_pk = if req.unlocker_public_key.is_empty() {
            req.device_id.clone()
        } else {
            req.unlocker_public_key.clone()
        };

        // The trade, in the terms the conservation chokepoint checks. Taken from
        // the hop that was just verified against the owner's proven reserves, so
        // the deltas below cannot describe a different trade than the one the
        // AMM re-simulation accepted.
        let Some(settle) = settle_terms.as_ref() else {
            return err("dlv.unlockRouted: routed settlement requires a verified AMM hop".into());
        };

        // FIRST-WRITER CLAIM, immediately before the advance. Everything after
        // this moves value; everything before it is reversible by stopping. A
        // contested slot means another trade already holds this parent sequence,
        // and losing here costs nothing because nothing has moved.
        let Ok(rc_for_x) = generated::RouteCommitV1::decode(&*req.route_commit_bytes) else {
            return err("dlv.unlockRouted: route_commit_bytes did not decode".into());
        };
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc_for_x);
        if let Err(e) = crate::sdk::settlement_slot::claim_settlement_slot(
            &vault_id,
            hop.vault_state_anchor_seq,
            &x,
        )
        .await
        {
            return err(format!("dlv.unlockRouted: settlement slot not held: {e}"));
        }

        let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&vault_id, &x);
        let op = dsm::types::operations::Operation::DlvSettle {
            vault_id: vault_id.to_vec(),
            owner_public_key: settle.owner_public_key.clone(),
            owner_devid: settle.owner_devid,
            owner_genesis: settle.owner_genesis,
            input_policy_commit: settle.input_policy_commit,
            output_policy_commit: settle.output_policy_commit,
            parent_sequence: hop.vault_state_anchor_seq,
            parent_reserves_digest: settle.parent_reserves_digest,
            reserve_proof_root: settle.reserve_proof_root,
            predicate_digest: settle.predicate_digest,
            route_commit_bytes: req.route_commit_bytes.clone(),
            external_commitment_x: x,
            input_amount: settle.input_amount,
            output_amount: settle.output_amount,
            fee_bps: settle.fee_bps,
            sigma: settle.sigma,
            settler_public_key: unlocker_pk,
            settler_devid: settle.settler_devid,
            settlement_receipt_id: receipt_id,
            // Signed below, by THIS device. Not carried in from `req`: the settler is
            // the actor whose self-loop is being advanced, so the signature is ours to
            // produce, and a caller-supplied one is unverifiable material that only
            // looks like authorization.
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        // Sign BEFORE the advance: the signature is part of `operation.to_bytes()` and
        // therefore part of `compute_chain_tip()`, so a transition committed unsigned
        // cannot be signed afterwards without rewriting the tip and every descendant.
        let op = match self.core_sdk.sign_operation_sphincs(op) {
            Ok(signed) => signed,
            Err(e) => return err(format!("dlv.unlockRouted: failed to sign DlvSettle: {e}")),
        };

        // The two POSITIONAL deltas the conservation arm requires: the input the
        // trader pays, then the output it takes. Order and exactness are checked
        // against the operation's own authorization inside `advance`.
        let deltas = vec![
            dsm::types::device_state::BalanceDelta {
                policy_commit: settle.input_policy_commit,
                direction: dsm::types::device_state::BalanceDirection::Debit,
                amount: settle.input_amount,
            },
            dsm::types::device_state::BalanceDelta {
                policy_commit: settle.output_policy_commit,
                direction: dsm::types::device_state::BalanceDirection::Credit,
                amount: settle.output_amount,
            },
        ];

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
                .execute_on_relationship(rel_key, actor, op, &deltas, Some(init_tip))
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
        // THE RECEIPT. The trader's settlement is final at the advance above; this
        // is what makes it visible to everyone else.
        //
        // Without it the pending pointer stays inert, so the owner never
        // reconciles and later traders keep quoting the pre-trade reserves. The
        // leaf is already in the trader's own root — written by the DlvSettle
        // advance — so this only signs the inclusion path over it and publishes.
        //
        // Best-effort: the credit is already committed and cannot be withdrawn
        // by a publication failure. A missing receipt costs visibility, not
        // value, and republishing later is safe because the leaf does not move.
        if let Some(settle) = settle_terms.as_ref() {
            let head = match self.core_sdk.device_head() {
                Some(h) => h,
                None => {
                    log::warn!("[dlv.unlockRouted] no device head; receipt not published");
                    return pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                        generated::AppStateResponse {
                            key: "dlv.unlockRouted".to_string(),
                            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
                        },
                    ));
                }
            };
            let trade = dsm::dlv::settlement_receipt_leaf::SettledTrade {
                x,
                parent_sequence: hop.vault_state_anchor_seq,
                new_sequence: hop.vault_state_anchor_seq.saturating_add(1),
                input_policy_commit: settle.input_policy_commit,
                input_amount: settle.input_amount,
                output_policy_commit: settle.output_policy_commit,
                output_amount: settle.output_amount,
            };
            let key = dsm::dlv::settlement_receipt_leaf::settlement_receipt_key(
                &head.genesis(),
                &head.devid(),
                &vault_id,
                &receipt_id,
            );
            match head.inclusion_siblings(&key) {
                Ok(siblings) => {
                    match (
                        crate::sdk::signing_authority::current_public_key(),
                        crate::sdk::signing_authority::current_secret_key(),
                    ) {
                        (Ok(pk), Ok(sk)) if !pk.is_empty() && !sk.is_empty() => {
                            match dsm::dlv::settlement_receipt_leaf::sign_trader_settlement_receipt(
                                &vault_id,
                                &receipt_id,
                                trade,
                                &head.genesis(),
                                &head.devid(),
                                &head.root(),
                                siblings,
                                &pk,
                                &sk,
                            ) {
                                Ok(receipt) => {
                                    if let Err(e) =
                                        crate::sdk::settlement_receipt_codec::publish_settlement_receipt(
                                            &receipt,
                                        )
                                        .await
                                    {
                                        log::warn!(
                                            "[dlv.unlockRouted] receipt publish failed for {}: {e} \
                                             — the settlement is committed but stays invisible \
                                             until republished",
                                            crate::util::text_id::encode_base32_crockford(&vault_id),
                                        );
                                    }
                                }
                                Err(e) => log::warn!(
                                    "[dlv.unlockRouted] receipt sign failed for {}: {e}",
                                    crate::util::text_id::encode_base32_crockford(&vault_id),
                                ),
                            }
                        }
                        _ => log::warn!(
                            "[dlv.unlockRouted] signing authority unavailable; receipt not published"
                        ),
                    }
                }
                Err(e) => log::warn!(
                    "[dlv.unlockRouted] receipt inclusion path unavailable for {}: {e}",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                ),
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
/// `sofi/vault-state/{vault_id_b32}/latest`.  Best-effort —
/// vault internal state is authoritative; this storage write is
/// advertisement-and-discovery only.
async fn publish_vault_state_anchor(vault_id: &[u8; 32], proto_bytes: &[u8]) -> Result<(), String> {
    let key = format!(
        "sofi/vault-state/{}/latest",
        crate::util::text_id::encode_base32_crockford(vault_id),
    );
    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(&key, proto_bytes)
        .await
        .map(|_| ())
        .map_err(|e| format!("storage put failed: {e:?}"))
}

/// Phase 7 — SoFi spec §4.1.2 / §8.4 step 2.
///
/// 1. Commit a vault-state leaf into the device's PD-SMT at the
///    (sequence, reserves_digest) tuple — produces the canonical
///    smt_root + 256-sibling inclusion path.
/// 2. Sign the inclusion proof with the owner's SPHINCS+ secret key.
/// 3. Publish to BOTH the seq-pinned key (historical traceability)
///    AND the `latest` mirror (trader fast-path).
///
/// Caller has already confirmed `local_is_owner` (we are the vault
/// owner).  Failure logs a warning and returns — the on-chain operation
/// has already succeeded; the inclusion proof is an advertisement and
/// can be republished later.
/// Publish the reserve inclusion proof for a vault's legs.
///
/// This is the artifact that converts an owner's claim about its liquidity into
/// something a stranger can check: each leg carries a 256-sibling path from the
/// owner's own vault-reserve leaf up to the published device root. Without it
/// `compose_vault_state` returns `MissingReserveProof` and the vault cannot be
/// quoted at all — a signed reserves digest is not a substitute, because a
/// one-way digest can only confirm that numbers the caller already held hash to
/// what the owner signed.
///
/// Best-effort like its vault-state sibling: a publication failure leaves the
/// vault unquotable rather than mis-quoted, which is the safe direction.
/// Everything `Operation::DlvSettle` must carry, captured from the hop that was
/// verified against the owner's PROVEN reserves.
///
/// Collected in one place so the deltas and the authorization are built from a
/// single set of values. Reading any of them from a second source would let the
/// two describe different trades while each looked internally consistent.
struct SettleTerms {
    owner_public_key: Vec<u8>,
    owner_devid: [u8; 32],
    owner_genesis: [u8; 32],
    input_policy_commit: [u8; 32],
    output_policy_commit: [u8; 32],
    input_amount: u64,
    output_amount: u64,
    parent_reserves_digest: [u8; 32],
    reserve_proof_root: [u8; 32],
    predicate_digest: [u8; 32],
    fee_bps: u32,
    sigma: [u8; 32],
    settler_devid: [u8; 32],
}

async fn publish_reserve_inclusion_proof(
    core_sdk: &crate::sdk::core_sdk::CoreSDK,
    vault_id: &[u8; 32],
    sequence: u64,
    policy_commits: &[[u8; 32]],
    owner_pk: &[u8],
    owner_sk: &[u8],
) {
    // Read the legs from the CURRENT head — after the vault-state leaf install,
    // so the path binds the same root the state proof was signed over.
    let Some(head) = core_sdk.device_head() else {
        log::warn!("[dlv] reserve proof: no device head");
        return;
    };
    let legs = match head.vault_reserve_leg_proofs(vault_id, policy_commits) {
        Ok(l) => l,
        Err(e) => {
            log::warn!(
                "[dlv] reserve proof: cannot prove legs for {}: {e}",
                crate::util::text_id::encode_base32_crockford(vault_id),
            );
            return;
        }
    };
    let signed = match dsm::dlv::vault_reserve_inclusion::sign_vault_reserve_inclusion_proof(
        vault_id,
        sequence,
        &head.root(),
        &head.genesis(),
        &head.devid(),
        legs,
        owner_pk,
        owner_sk,
    ) {
        Ok(p) => p,
        Err(e) => {
            log::warn!(
                "[dlv] reserve proof: sign failed for {}: {e}",
                crate::util::text_id::encode_base32_crockford(vault_id),
            );
            return;
        }
    };
    if let Err(e) = crate::sdk::vault_reserve_proof_codec::publish_reserve_proof(&signed).await {
        log::warn!(
            "[dlv] reserve proof: publish failed for {} — the vault will not be quotable: {e}",
            crate::util::text_id::encode_base32_crockford(vault_id),
        );
    }
}

async fn publish_vault_state_inclusion_proof(
    core_sdk: &crate::sdk::core_sdk::CoreSDK,
    vault_id: &[u8; 32],
    sequence: u64,
    reserves_digest: &[u8; 32],
    owner_pk: &[u8],
    owner_sk: &[u8],
) {
    // (1) Mutate the device's PD-SMT to commit the new vault state.
    let (smt_root, siblings) =
        match core_sdk.install_vault_state_leaf(vault_id, sequence, reserves_digest) {
            Ok(pair) => pair,
            Err(e) => {
                log::warn!(
                    "[dlv] install_vault_state_leaf (seq={}) failed for {}: {e}",
                    sequence,
                    crate::util::text_id::encode_base32_crockford(vault_id),
                );
                return;
            }
        };

    // (2) Sign over (vault_id, sequence, reserves_digest, smt_root).
    let signed = match dsm::dlv::vault_smt_leaf::sign_vault_state_inclusion_proof(
        vault_id,
        sequence,
        reserves_digest,
        &smt_root,
        siblings,
        owner_pk,
        owner_sk,
    ) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "[dlv] sign_vault_state_inclusion_proof (seq={}) failed for {}: {e}",
                sequence,
                crate::util::text_id::encode_base32_crockford(vault_id),
            );
            return;
        }
    };

    // (3) Encode + publish to storage.
    let proto_bytes =
        crate::sdk::vault_smt_inclusion_codec::encode_inclusion_proof_to_proto(&signed);
    if let Err(e) = crate::sdk::vault_smt_inclusion_codec::publish_inclusion_proof(
        vault_id,
        sequence,
        &proto_bytes,
    )
    .await
    {
        log::warn!(
            "[dlv] inclusion proof publish (seq={}) failed for {}: {e}; vault is locally consistent but may not be quotable off-device until republish",
            sequence,
            crate::util::text_id::encode_base32_crockford(vault_id),
        );
    } else {
        log::info!(
            "[dlv] inclusion proof published seq={} vault={}",
            sequence,
            crate::util::text_id::encode_base32_crockford(vault_id),
        );
    }
}

#[cfg(test)]
mod funded_creation_tests {
    //! Funded creation as ONE lifecycle proof, across four persistence
    //! boundaries.
    //!
    //! The interesting claim is not "funded creation happened". It is that
    //! funded creation produced a PERSISTENT IDENTITY that survives a restart.
    //! Asserted separately, four passing checks could each be true while the
    //! chain between them is broken — a vault returned under one owner, stored
    //! under another, with leaves belonging to a third. Asserted as a chain,
    //! any disagreement is either an ownership bug or a persistence bug, and the
    //! test says which link broke.

    use super::*;
    use serial_test::serial;

    use crate::bridge::AppRouter;
    use crate::init::SdkConfig;

    fn install_identity() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
            std::env::remove_var("DSM_ENV_CONFIG_PATH");
        }
        crate::storage::client_db::reset_database_for_tests();
        let _ = crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_funded_creation",
        ));
        crate::reset_sdk_context_for_testing();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (device_id, genesis_hash, binding_key) =
            (vec![0x0Au8; 32], vec![0x0Bu8; 32], vec![0x0Cu8; 32]);
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("derive signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id,
            public_key,
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        crate::storage::client_db::init_database().expect("init db");
    }

    /// Install an identity keyed by `seed`, WITHOUT resetting storage.
    ///
    /// Identity is process-global, so a two-device test switches it between
    /// phases. The device heads and DLV managers are per-router, so each side
    /// keeps its own state — which is the boundary that matters: the trader has
    /// no access to the owner's leaves and must work from published artifacts.
    fn become_device(seed: u8) -> (Vec<u8>, [u8; 32]) {
        let device_id = vec![seed; 32];
        let genesis_hash = vec![seed.wrapping_add(1); 32];
        let binding_key = vec![seed.wrapping_add(2); 32];
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &binding_key,
        )
        .expect("derive signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(binding_key);
        crate::sdk::app_state::AppState::set_identity_info(
            device_id.clone(),
            public_key.clone(),
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        let mut did = [0u8; 32];
        did.copy_from_slice(&device_id);
        (public_key, did)
    }

    fn named_router(name: &str) -> AppRouterImpl {
        AppRouterImpl::new(SdkConfig {
            node_id: name.to_string(),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn router() -> AppRouterImpl {
        AppRouterImpl::new(SdkConfig {
            node_id: "funded-creation-test".to_string(),
            storage_endpoints: vec![],
            enable_offline: true,
        })
        .expect("router init")
    }

    fn pack(body: Vec<u8>) -> Vec<u8> {
        generated::ArgPack {
            schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
            codec: generated::Codec::Proto as i32,
            body,
        }
        .encode_to_vec()
    }

    fn amm_fulfillment_bytes(a: &[u8; 32], b: &[u8; 32], fee_bps: u32) -> Vec<u8> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        generated::FulfillmentMechanism {
            kind: Some(generated::fulfillment_mechanism::Kind::AmmConstantProduct(
                generated::AmmConstantProduct {
                    token_a: lo.to_vec(),
                    token_b: hi.to_vec(),
                    fee_bps,
                },
            )),
        }
        .encode_to_vec()
    }

    /// THE CHAIN: response owner → persisted record owner → reserve leaves under
    /// that vault and pair → the same owner after a restart.
    #[test]
    #[serial]
    fn funded_creation_produces_an_identity_that_survives_a_restart() {
        install_identity();
        let r = router();

        // A head holding spendable balance and nothing encumbered — creation is
        // what encumbers it.
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let spendable = crate::sdk::funded_vault_fixture::owner_holding(50_000, 20_000);
        let (owner_genesis, owner_devid) = (spendable.genesis(), spendable.devid());
        r.core_sdk.set_device_head_for_testing(spendable);

        let policy_digest = vec![0x5Au8; 32];
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: policy_digest.clone(),
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(
            res.success,
            "funded creation failed: {:?}",
            res.error_message
        );

        // BOUNDARY 1 — the head the route committed. Spendable fell by exactly
        // the legs, and the reserves hold them.
        let head = r.core_sdk.device_head().expect("a head after creation");
        assert_eq!(head.balance(&pc_a), 40_000, "leg A left spendable balance");
        assert_eq!(head.balance(&pc_b), 15_000, "leg B left spendable balance");

        // BOUNDARY 2 — the persisted record. Exactly one vault, owned by the
        // device that created it.
        let records = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list records");
        assert_eq!(records.len(), 1, "creation must persist exactly one record");
        let rec = &records[0];
        assert_eq!(
            (rec.owner_genesis, rec.owner_devid),
            (owner_genesis, owner_devid),
            "the persisted owner must be the device that created the vault"
        );
        assert_eq!((rec.policy_commit_a, rec.policy_commit_b), (pc_a, pc_b));
        assert_eq!(rec.fee_bps, 30);
        assert_eq!(
            rec.anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
            "enforcement must persist, or a restart silently downgrades the gate"
        );
        assert_eq!(rec.policy_digest.to_vec(), policy_digest);

        // BOUNDARY 3 — the reserve leaves belong to THAT vault and THAT pair,
        // under that owner's key derivation. A leaf under a different vault or
        // owner would be unattributable to this record.
        assert_eq!(head.vault_reserve(&rec.vault_id, &pc_a), 10_000);
        assert_eq!(head.vault_reserve(&rec.vault_id, &pc_b), 5_000);
        assert_eq!(
            head.vault_reserve(&[0x99u8; 32], &pc_a),
            0,
            "no other vault may hold this encumbrance"
        );

        // BOUNDARY 4 — RESTART. The head round-trips through the persistence
        // codec, and the vault is rebuilt from the record plus those leaves.
        // This is what makes the identity authoritative rather than a decoration
        // on the create response.
        let encoded = crate::storage::client_db::bcr::encode_device_state(&head);
        let (reloaded, _) = crate::storage::client_db::bcr::decode_device_state(&encoded)
            .expect("the head must survive the codec");
        let rebuilt = crate::sdk::vault_rehydration::rehydrate_all_amm_vaults(&reloaded);

        assert_eq!(rebuilt.len(), 1, "the vault must come back after a restart");
        let v = &rebuilt[0];
        assert_eq!(v.vault_id, rec.vault_id);
        assert_eq!((v.pair.a(), v.pair.b()), (pc_a, pc_b));

        // The owner is not carried OUT of rehydration — it is checked DURING
        // it, so a rebuilt vault is necessarily this device's. That the check is
        // load-bearing rather than decorative is proven by moving the record's
        // owner and requiring the rebuild to refuse: a foreign owner's reserve
        // leaves live under a different key space, so accepting the record would
        // produce a vault holding nothing while looking valid.
        let foreign = crate::storage::client_db::amm_vault_records::AmmVaultRecord {
            owner_devid: {
                let mut d = rec.owner_devid;
                d[0] ^= 0xff;
                d
            },
            ..rec.clone()
        };
        assert_eq!(
            crate::sdk::vault_rehydration::rehydrate_amm_vault(&foreign, &reloaded),
            Err(crate::sdk::vault_rehydration::RehydrationError::OwnerMismatch),
            "a record naming another owner must not rebuild against this device's leaves"
        );
        assert_eq!(
            v.anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
            "a restart must not relax enforcement"
        );
        assert_eq!(
            (v.reserve_a, v.reserve_b),
            (10_000, 5_000),
            "reserves come back from the leaves, not from the record"
        );
    }

    /// ACCEPT-OR-STAMP on `dlv.create`, proven on the artifact.
    ///
    /// Replaces greps for `if req.creator_public_key.is_empty() {` and for the
    /// two `signing_authority::current_*_key()` call sites. Those confirmed
    /// lines existed; they could not confirm the vault was signed by the key
    /// that got stamped, which is the property that makes a creator
    /// attributable at all.
    #[test]
    #[serial]
    fn create_stamps_the_wallet_identity_and_the_vault_carries_it() {
        install_identity();
        let r = router();

        let wallet_pk = crate::sdk::signing_authority::current_public_key().expect("pk");
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));

        // Empty creator key AND empty signature: both are the wallet's to fill.
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(
            res.success,
            "empty identity fields must be stamped, not rejected: {:?}",
            res.error_message
        );

        // THE ARTIFACT: the vault the handler actually built carries the
        // wallet's key as its creator. An empty key that stayed empty would
        // leave the vault unattributable while every field still looked
        // populated.
        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one record");
        let dlv_manager = r.bitcoin_tap.dlv_manager();
        let vault_lock = crate::runtime::get_runtime()
            .block_on(dlv_manager.get_vault(&rec.vault_id))
            .expect("the created vault must be in the local manager");
        let vault = crate::runtime::get_runtime().block_on(vault_lock.lock());
        assert_eq!(
            vault.creator_public_key, wallet_pk,
            "the vault must carry the stamped wallet key as its creator"
        );
        assert!(
            !vault.creator_signature.is_empty(),
            "an empty signature must be filled by the wallet, not left blank"
        );
    }

    /// Caller-supplied digests are STRICT-VERIFIED; absent ones are computed.
    ///
    /// Replaces greps for the literal comment `0 => {} // accept-or-compute
    /// path` and the string `must be 0 or 32 bytes`. A wrong-length digest is
    /// refused, and a supplied-but-wrong digest must not be accepted verbatim —
    /// otherwise a caller could bind a vault to content it does not hold.
    #[test]
    #[serial]
    fn create_refuses_a_malformed_digest_and_computes_an_absent_one() {
        install_identity();
        let r = router();

        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let build = |content_digest: Vec<u8>| generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                content_digest,
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let call = |req: generated::DlvInstantiateV1| {
            crate::runtime::get_runtime().block_on(async {
                r.invoke(AppInvoke {
                    method: "dlv.create".to_string(),
                    args: pack(req.encode_to_vec()),
                })
                .await
            })
        };

        // A digest that is neither absent nor 32 bytes is malformed, and is
        // refused on those grounds rather than truncated or padded.
        for bad_len in [1usize, 16, 31, 33, 64] {
            r.core_sdk.set_device_head_for_testing(
                crate::sdk::funded_vault_fixture::owner_holding(50_000, 20_000),
            );
            let res = call(build(vec![0xAAu8; bad_len]));
            assert!(
                !res.success,
                "a {bad_len}-byte content digest must be refused"
            );
            let msg = res.error_message.unwrap_or_default();
            assert!(
                msg.contains("0 or 32 bytes"),
                "must fail as a digest-length error, not incidentally: {msg}"
            );
        }

        // Absent is the accept-or-compute path: Rust derives it.
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));
        assert!(
            call(build(Vec::new())).success,
            "an absent digest must be computed, not required from the caller"
        );
    }

    /// A vault created FOR a recipient is advertised to that recipient.
    ///
    /// Replaces greps for `posted_dlv_sdk::publish_active_advertisement` and
    /// `intended_recipient_opt.as_ref()` appearing in the handler. Those confirm
    /// a call site and a field access; they cannot confirm the advertisement
    /// reaches the recipient's own prefix, which is the only thing that makes a
    /// posted vault discoverable by the party it was posted to.
    #[test]
    #[serial]
    fn a_vault_posted_to_a_recipient_is_advertised_under_that_recipient() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));

        let recipient = vec![0xC7u8; 1184];
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                intended_recipient: recipient.clone(),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(create.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "create failed: {:?}", res.error_message);

        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault");

        // The advertisement is readable at the address derived from the
        // RECIPIENT — the prefix that recipient scans.
        let key = crate::sdk::posted_dlv_sdk::advertisement_key(&recipient, &rec.vault_id);
        let bytes = crate::runtime::get_runtime()
            .block_on(crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&key))
            .expect("the posted vault must be advertised under its recipient");
        assert!(!bytes.is_empty());

        // And NOT under a different recipient's prefix, so one party cannot
        // discover offers made to another.
        let other = vec![0xD8u8; 1184];
        let other_key = crate::sdk::posted_dlv_sdk::advertisement_key(&other, &rec.vault_id);
        assert_ne!(key, other_key);
        assert!(
            crate::runtime::get_runtime()
                .block_on(crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_get_bytes(&other_key))
                .map(|b| b.is_empty())
                .unwrap_or(true),
            "a posted vault must not be discoverable under another recipient"
        );
    }

    /// TWO DEVICES. The owner and the trader are separate routers with separate
    /// identities, separate device heads and separate vault managers, and they
    /// communicate ONLY through storage.
    ///
    /// This is what the single-device lifecycle cannot show. There, the settling
    /// side happened to be the same process that funded the vault; the artifacts
    /// were verified honestly, but nothing forced them to be the only channel.
    /// Here the trader has no access to the owner's leaves at all — its own head
    /// holds no reserve for the vault — so every fact it settles against must
    /// have arrived as a published, verified artifact or it settles nothing.
    ///
    /// Process-global identity is switched between phases; heads and vault
    /// managers are per-router, which is the boundary that matters.
    #[test]
    #[serial]
    fn owner_and_trader_on_separate_devices_settle_through_storage_alone() {
        use prost::Message as _;

        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();

        // ── OWNER ────────────────────────────────────────────────────────────
        let (owner_pk, _owner_did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            owner
                .invoke(AppInvoke {
                    method: "dlv.create".to_string(),
                    args: pack(create.encode_to_vec()),
                })
                .await
        });
        assert!(res.success, "owner create failed: {:?}", res.error_message);
        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault");
        let vault_id = rec.vault_id;

        // The owner publishes the advertisement, which is how the trader finds
        // the vault at all.
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: vec![0x5Au8; 32],
            unlock_spec_key: "sofi/spec/two-device".to_string(),
            owner_public_key: Vec::new(),
            vault_proto_bytes: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            owner
                .invoke(AppInvoke {
                    method: "route.publishRoutingAdvertisement".to_string(),
                    args: pack(publish.encode_to_vec()),
                })
                .await
        });
        assert!(res.success, "publish failed: {:?}", res.error_message);

        // ── TRADER ───────────────────────────────────────────────────────────
        let (trader_pk, trader_did) = become_device(0x51);
        assert_ne!(trader_pk, owner_pk, "the two devices must be distinct");
        let trader = named_router("trader");
        // A head holding only the input asset. Crucially it holds NO reserve for
        // this vault — the trader does not own the liquidity it trades against.
        trader.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD2, 5_000, 0),
        );
        let trader_head = trader.core_sdk.device_head().expect("trader head");
        assert_eq!(
            trader_head.vault_reserve(&vault_id, &pc_a),
            0,
            "precondition: the trader holds none of the vault's reserves"
        );
        let (bal_a_before, bal_b_before) = (trader_head.balance(&pc_a), trader_head.balance(&pc_b));

        // The trader acquires the vault the only way it can: from storage.
        let pair = generated::RoutingPairRequest {
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            trader
                .invoke(AppInvoke {
                    method: "route.syncVaultsForPair".to_string(),
                    args: pack(pair.encode_to_vec()),
                })
                .await
        });
        assert!(res.success, "trader sync failed: {:?}", res.error_message);

        // And the reserve proof it will settle against — fetched and verified
        // from storage, with no access to the owner's leaves.
        let proof = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::vault_reserve_proof_codec::fetch_verified_reserve_proof(&vault_id, 0),
            )
            .expect("the trader must be able to verify the owner's published reserves");
        assert_eq!(
            dsm::dlv::vault_reserve_inclusion::proven_amount(&proof, &pc_a),
            Some(10_000)
        );

        let input = 1_000u64;
        let expected_out =
            crate::sdk::routing_path_sdk::constant_product_output(input, 10_000, 5_000, 30)
                .expect("curve output");
        let reserves_digest =
            dsm::dlv::vault_state_anchor::compute_reserves_digest(&pc_a, &pc_b, 10_000, 5_000, 30);
        let anchor_digest =
            dsm::dlv::vault_state_anchor::compute_anchor_digest(&vault_id, 0, &reserves_digest);
        let trader_sk = crate::sdk::signing_authority::current_secret_key().expect("trader sk");
        let mut rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: vec![0x22; 32],
            total_fee_bps: 30,
            initiator_public_key: trader_pk.clone(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vault_id.to_vec(),
                token_in: pc_a.to_vec(),
                token_out: pc_b.to_vec(),
                input_amount_u128: (input as u128).to_be_bytes().to_vec(),
                expected_output_amount_u128: (expected_out as u128).to_be_bytes().to_vec(),
                vault_state_anchor_seq: 0,
                vault_state_reserves_digest: reserves_digest.to_vec(),
                vault_state_anchor_digest: anchor_digest.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            dsm::crypto::sphincs::sphincs_sign(&trader_sk, &canonical).expect("trader signs");
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);
        crate::runtime::get_runtime()
            .block_on(
                crate::sdk::route_commit_sdk::publish_route_anchor_with_pointers(
                    &x,
                    &rc,
                    &trader_pk,
                    &trader_sk,
                    "two-device",
                ),
            )
            .expect("trader publishes X + pointer");

        let settle = generated::DlvUnlockRoutedV1 {
            vault_id: vault_id.to_vec(),
            device_id: trader_did.to_vec(),
            route_commit_bytes: rc.encode_to_vec(),
            unlocker_public_key: trader_pk.clone(),
            signature: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            trader
                .invoke(AppInvoke {
                    method: "dlv.unlockRouted".to_string(),
                    args: pack(settle.encode_to_vec()),
                })
                .await
        });
        assert!(
            res.success,
            "cross-device settlement failed: {:?}",
            res.error_message
        );

        // The TRADER's balances moved, on the TRADER's head.
        let trader_after = trader.core_sdk.device_head().expect("trader head");
        assert_eq!(trader_after.balance(&pc_a), bal_a_before - input);
        assert_eq!(trader_after.balance(&pc_b), bal_b_before + expected_out);
        assert_eq!(
            trader_after.vault_reserve(&vault_id, &pc_a),
            0,
            "settling must not put the owner's reserves on the trader's head"
        );

        // ── OWNER RECONCILES ─────────────────────────────────────────────────
        let _ = become_device(0x41);
        let owner_before = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            owner_before.vault_reserve(&vault_id, &pc_a),
            10_000,
            "the owner's reserves must be untouched until it folds the receipt"
        );

        // THE HEADS ARE GENUINELY SEPARATE. The trader's settlement moved the
        // trader's balances; the owner's are exactly where funding left them. If
        // the two routers shared a head this would fail, and every assertion
        // above about "the trader" would have been about the owner.
        assert_eq!(
            (owner_before.balance(&pc_a), owner_before.balance(&pc_b)),
            (40_000, 15_000),
            "a settlement on the trader's device must not touch the owner's balances"
        );
        assert_ne!(
            owner_before.devid(),
            trader_after.devid(),
            "the two routers must be different devices, not one head seen twice"
        );
        assert_ne!(owner_before.root(), trader_after.root());

        let reconcile = generated::DlvReconcileV1 {
            vault_id: vault_id.to_vec(),
            x: x.to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            owner
                .invoke(AppInvoke {
                    method: "dlv.reconcile".to_string(),
                    args: pack(reconcile.encode_to_vec()),
                })
                .await
        });
        assert!(
            res.success,
            "owner reconcile failed: {:?}",
            res.error_message
        );

        // THE TWO SIDES AGREE. What the trader paid is what the owner received,
        // and what the trader took is what the owner released — established
        // across the boundary by the receipt alone.
        let owner_after = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            owner_after.vault_reserve(&vault_id, &pc_a),
            10_000 + input,
            "the owner received exactly what the trader paid"
        );
        assert_eq!(
            owner_after.vault_reserve(&vault_id, &pc_b),
            5_000 - expected_out,
            "the owner released exactly what the trader took"
        );
        assert_eq!(
            owner_after
                .vault_reserve_entry(&vault_id, &pc_a)
                .expect("leg A")
                .sequence,
            1,
        );

        // CONSERVATION ACROSS THE PAIR, per asset. The trader's loss is the
        // vault's gain and vice versa — the headline number.
        let trader_delta_a = trader_after.balance(&pc_a) as i128 - bal_a_before as i128;
        let vault_delta_a = owner_after.vault_reserve(&vault_id, &pc_a) as i128 - 10_000i128;
        assert_eq!(trader_delta_a + vault_delta_a, 0, "asset A is conserved");
        let trader_delta_b = trader_after.balance(&pc_b) as i128 - bal_b_before as i128;
        let vault_delta_b = owner_after.vault_reserve(&vault_id, &pc_b) as i128 - 5_000i128;
        assert_eq!(trader_delta_b + vault_delta_b, 0, "asset B is conserved");
    }

    /// THE FULL SETTLEMENT LIFECYCLE, driven through the production dispatcher.
    ///
    /// Every piece has been proven separately; this is the first time they run
    /// as one execution. Settlement is `implemented` and `route-proven` until
    /// this passes — it becomes `wired` only when a settlement completes and the
    /// resulting state is asserted.
    ///
    /// Single device acting as both owner and trader. That is a real limitation
    /// and it is stated rather than hidden: the cross-device split is exercised
    /// by the artifacts, not by the process boundary. Every authority check
    /// still runs for real — the settling path reads the owner's PUBLISHED
    /// reserve proof back out of storage and verifies its signature and SMT
    /// paths, exactly as a separate device would, because it has no privileged
    /// access to the owner's leaves either way.
    #[test]
    #[serial]
    fn a_settlement_completes_and_the_resulting_state_is_asserted() {
        use prost::Message as _;

        install_identity();
        let r = router();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));

        // (1) FUND a vault through the dispatcher.
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(create.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "create failed: {:?}", res.error_message);

        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault");
        let vault_id = rec.vault_id;
        let before = r.core_sdk.device_head().expect("head");
        let (bal_a_before, bal_b_before) = (before.balance(&pc_a), before.balance(&pc_b));
        assert_eq!((bal_a_before, bal_b_before), (40_000, 15_000));
        assert_eq!(before.vault_reserve(&vault_id, &pc_a), 10_000);
        assert_eq!(before.vault_reserve(&vault_id, &pc_b), 5_000);

        // (2) The proof the settling path will read back. Its existence is the
        // precondition the reserve gate enforces.
        let proof = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::vault_reserve_proof_codec::fetch_verified_reserve_proof(&vault_id, 0),
            )
            .expect("dlv.create must publish a verifiable reserve proof");
        assert_eq!(
            dsm::dlv::vault_reserve_inclusion::proven_amount(&proof, &pc_a),
            Some(10_000)
        );

        // (3) Build and sign the RouteCommit the trader settles with. The hop's
        // bindings must match what the anchor gate re-derives from the PROVEN
        // reserves, so they are computed the same way rather than guessed.
        let input = 1_000u64;
        let expected_out =
            crate::sdk::routing_path_sdk::constant_product_output(input, 10_000, 5_000, 30)
                .expect("curve output");
        let reserves_digest =
            dsm::dlv::vault_state_anchor::compute_reserves_digest(&pc_a, &pc_b, 10_000, 5_000, 30);
        let anchor_digest =
            dsm::dlv::vault_state_anchor::compute_anchor_digest(&vault_id, 0, &reserves_digest);
        let (pk, sk) = (
            crate::sdk::signing_authority::current_public_key().expect("pk"),
            crate::sdk::signing_authority::current_secret_key().expect("sk"),
        );
        let mut rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: vec![0x11; 32],
            total_fee_bps: 30,
            initiator_public_key: pk.clone(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vault_id.to_vec(),
                token_in: pc_a.to_vec(),
                token_out: pc_b.to_vec(),
                input_amount_u128: (input as u128).to_be_bytes().to_vec(),
                expected_output_amount_u128: (expected_out as u128).to_be_bytes().to_vec(),
                vault_state_anchor_seq: 0,
                vault_state_reserves_digest: reserves_digest.to_vec(),
                vault_state_anchor_digest: anchor_digest.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            dsm::crypto::sphincs::sphincs_sign(&sk, &canonical).expect("sign rc");
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);

        // (4) Publish X, and the pointer that CLAIMS the settlement slot.
        crate::runtime::get_runtime()
            .block_on(
                crate::sdk::route_commit_sdk::publish_route_anchor_with_pointers(
                    &x,
                    &rc,
                    &pk,
                    &sk,
                    "lifecycle",
                ),
            )
            .expect("publish anchor + pointers");

        // (5) SETTLE through the dispatcher.
        let settle = generated::DlvUnlockRoutedV1 {
            vault_id: vault_id.to_vec(),
            device_id: before.devid().to_vec(),
            route_commit_bytes: rc.encode_to_vec(),
            unlocker_public_key: pk.clone(),
            signature: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.unlockRouted".to_string(),
                args: pack(settle.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "settlement failed: {:?}", res.error_message);

        // (6) BALANCES MOVED, by exactly the authorized amounts.
        let after = r.core_sdk.device_head().expect("head");
        assert_eq!(
            after.balance(&pc_a),
            bal_a_before - input,
            "the input must be debited exactly"
        );
        assert_eq!(
            after.balance(&pc_b),
            bal_b_before + expected_out,
            "the output must be credited exactly"
        );

        // (7) THE RECEIPT was published, and verifies.
        let receipt = crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x))
            .expect("the settlement must publish a verifiable receipt");
        assert_eq!(receipt.trade.input_amount, input);
        assert_eq!(receipt.trade.output_amount, expected_out);
        assert_eq!(receipt.trade.parent_sequence, 0);
        assert_eq!(receipt.trade.new_sequence, 1);
        assert_eq!(receipt.trade.input_policy_commit, pc_a);
        assert_eq!(receipt.trade.output_policy_commit, pc_b);

        // (8) RESTART: the post-trade state survives the codec.
        let encoded = crate::storage::client_db::bcr::encode_device_state(&after);
        let (reloaded, _) = crate::storage::client_db::bcr::decode_device_state(&encoded)
            .expect("head survives the codec");
        assert_eq!(reloaded.root(), after.root());
        assert_eq!(reloaded.balance(&pc_a), after.balance(&pc_a));
        assert_eq!(reloaded.balance(&pc_b), after.balance(&pc_b));

        // (9) And the vault rebuilds with its post-trade identity intact.
        let rebuilt = crate::sdk::vault_rehydration::rehydrate_all_amm_vaults(&reloaded);
        assert_eq!(rebuilt.len(), 1, "the vault must survive the restart");
        assert_eq!(rebuilt[0].vault_id, vault_id);
        assert_eq!(
            rebuilt[0].anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
        );

        // (10) THE OWNER RECONCILES. Until now the trader's credit is final but
        // the owner's reserve leaves still hold the pre-trade amounts — the
        // settlement is real and unrecorded on this side.
        let reserves_before_apply = (
            after.vault_reserve(&vault_id, &pc_a),
            after.vault_reserve(&vault_id, &pc_b),
        );
        assert_eq!(
            reserves_before_apply,
            (10_000, 5_000),
            "reserves must not move until the owner folds the receipt"
        );

        let reconcile = generated::DlvReconcileV1 {
            vault_id: vault_id.to_vec(),
            x: x.to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(reconcile.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "reconcile failed: {:?}", res.error_message);

        // (11) RESERVES MOVED, positionally: the input arrived, the output left.
        let applied = r.core_sdk.device_head().expect("head");
        assert_eq!(
            applied.vault_reserve(&vault_id, &pc_a),
            10_000 + input,
            "the input the trader paid must arrive in the reserve"
        );
        assert_eq!(
            applied.vault_reserve(&vault_id, &pc_b),
            5_000 - expected_out,
            "the output the trader took must leave the reserve"
        );

        // (12) THE SEQUENCE ADVANCED EXACTLY ONCE, on both legs.
        assert_eq!(
            applied
                .vault_reserve_entry(&vault_id, &pc_a)
                .expect("leg A")
                .sequence,
            1,
        );
        assert_eq!(
            applied
                .vault_reserve_entry(&vault_id, &pc_b)
                .expect("leg B")
                .sequence,
            1,
        );

        // (13) REPLAY IS A NO-OP. Folding the same receipt twice would move the
        // reserves twice on a trade that happened once.
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(reconcile.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "a repeated reconcile must not error");
        let twice = r.core_sdk.device_head().expect("head");
        assert_eq!(
            (
                twice.vault_reserve(&vault_id, &pc_a),
                twice.vault_reserve(&vault_id, &pc_b)
            ),
            (
                applied.vault_reserve(&vault_id, &pc_a),
                applied.vault_reserve(&vault_id, &pc_b)
            ),
            "replaying a receipt must move nothing"
        );
        assert_eq!(
            twice.root(),
            applied.root(),
            "and must not advance the device root"
        );

        // (14) A LATER QUOTE SEES POST-TRADE RESERVES. The owner can now prove
        // the new amounts at the new sequence, which is what the next trader
        // composes against.
        let legs_after = twice
            .vault_reserve_leg_proofs(&vault_id, &[pc_a, pc_b])
            .expect("legs after settlement");
        let proof_after = dsm::dlv::vault_reserve_inclusion::sign_vault_reserve_inclusion_proof(
            &vault_id,
            1,
            &twice.root(),
            &twice.genesis(),
            &twice.devid(),
            legs_after,
            &pk,
            &sk,
        )
        .expect("sign post-trade proof");
        dsm::dlv::vault_reserve_inclusion::verify_vault_reserve_inclusion_proof(&proof_after)
            .expect("the post-trade reserves must be provable");
        assert_eq!(
            dsm::dlv::vault_reserve_inclusion::proven_amount(&proof_after, &pc_a),
            Some(10_000 + input),
            "a later quote must see the post-trade reserve, not the parent's"
        );
        assert_eq!(
            dsm::dlv::vault_reserve_inclusion::proven_amount(&proof_after, &pc_b),
            Some(5_000 - expected_out),
        );
    }

    /// ONE CONTINUOUS LIFECYCLE, producer and consumers together.
    ///
    /// Gates 1 and 4 were each proven against hand-built funded state, because
    /// until funded creation encumbered, hand-built was the only funded state
    /// there was. Every layer could therefore be correct against a shape nothing
    /// produced. This runs the producer and both consumers in one pass over one
    /// head: create → read leaves → prove them → check the proof root is the
    /// root a quote would use → restart → rehydrate → compare everything.
    #[test]
    #[serial]
    fn a_dispatcher_created_vault_proves_and_rehydrates_end_to_end() {
        use dsm::dlv::vault_reserve_inclusion::{
            proven_amount, sign_vault_reserve_inclusion_proof, verify_vault_reserve_inclusion_proof,
        };

        install_identity();
        let r = router();

        // (1) CREATE through the real dispatcher.
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "create failed: {:?}", res.error_message);

        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one record");
        let head = r.core_sdk.device_head().expect("head");

        // (2) READ the leaves the dispatcher actually wrote.
        assert_eq!(head.vault_reserve(&rec.vault_id, &pc_a), 10_000);
        assert_eq!(head.vault_reserve(&rec.vault_id, &pc_b), 5_000);

        // (3) PROVE them from that exact head, and verify as a stranger would.
        let legs = head
            .vault_reserve_leg_proofs(&rec.vault_id, &[pc_a, pc_b])
            .expect("legs");
        let (pk, sk) = (
            crate::sdk::signing_authority::current_public_key().expect("pk"),
            crate::sdk::signing_authority::current_secret_key().expect("sk"),
        );
        let proof = sign_vault_reserve_inclusion_proof(
            &rec.vault_id,
            0,
            &head.root(),
            &head.genesis(),
            &head.devid(),
            legs,
            &pk,
            &sk,
        )
        .expect("sign reserve proof");
        verify_vault_reserve_inclusion_proof(&proof)
            .expect("a dispatcher-created vault must prove its own reserves");
        assert_eq!(proven_amount(&proof, &pc_a), Some(10_000));
        assert_eq!(proven_amount(&proof, &pc_b), Some(5_000));

        // (4) THE ROOT A QUOTE WOULD USE. `install_vault_state_leaf` performs
        // its own head mutation, so the root moves after funding. Both proofs
        // must bind the SAME final root or `compose_vault_state` refuses the
        // vault — this is the ordering dependency that would otherwise only
        // surface as every quote failing closed.
        let state_leaf_key = dsm::dlv::vault_smt_leaf::compute_vault_smt_key(&rec.vault_id);
        assert!(
            head.extra_leaves_snapshot().contains_key(&state_leaf_key),
            "the vault-state leaf must be in the same head as the reserve leaves"
        );
        assert_eq!(
            proof.smt_root,
            head.root(),
            "the reserve proof must bind the head's current root, which is what \
             the vault-state proof was signed over"
        );

        // (5) RESTART.
        let encoded = crate::storage::client_db::bcr::encode_device_state(&head);
        let (reloaded, _) = crate::storage::client_db::bcr::decode_device_state(&encoded)
            .expect("head survives the codec");
        assert_eq!(
            reloaded.root(),
            head.root(),
            "the codec must preserve the root"
        );

        // (6) REHYDRATE from the persisted record plus the decoded leaves.
        let rebuilt = crate::sdk::vault_rehydration::rehydrate_all_amm_vaults(&reloaded);
        assert_eq!(rebuilt.len(), 1, "the vault must come back");
        let v = &rebuilt[0];

        // (7) EVERYTHING MATCHES the pre-restart vault.
        assert_eq!(v.vault_id, rec.vault_id);
        assert_eq!((v.pair.a(), v.pair.b()), (pc_a, pc_b));
        assert_eq!(v.fee_bps, 30);
        assert_eq!(
            v.anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
            "a restart must not relax enforcement"
        );
        assert_eq!(v.policy_digest.to_vec(), vec![0x5Au8; 32]);
        assert_eq!((v.reserve_a, v.reserve_b), (10_000, 5_000));
        assert_eq!(v.current_sequence, 0, "sequence comes from the leaves");
        // Owner is checked DURING rehydration, so a rebuilt vault is
        // necessarily this device's — proven load-bearing by moving it.
        let foreign = crate::storage::client_db::amm_vault_records::AmmVaultRecord {
            owner_devid: {
                let mut d = rec.owner_devid;
                d[0] ^= 0xff;
                d
            },
            ..rec.clone()
        };
        assert_eq!(
            crate::sdk::vault_rehydration::rehydrate_amm_vault(&foreign, &reloaded),
            Err(crate::sdk::vault_rehydration::RehydrationError::OwnerMismatch),
        );

        // (8) THE REHYDRATED VAULT IS QUOTABLE: its reserves re-prove against
        // the reloaded head, which is what a trader's composition consumes.
        let legs_after = reloaded
            .vault_reserve_leg_proofs(&rec.vault_id, &[pc_a, pc_b])
            .expect("legs after restart");
        let proof_after = sign_vault_reserve_inclusion_proof(
            &rec.vault_id,
            0,
            &reloaded.root(),
            &reloaded.genesis(),
            &reloaded.devid(),
            legs_after,
            &pk,
            &sk,
        )
        .expect("sign after restart");
        verify_vault_reserve_inclusion_proof(&proof_after)
            .expect("the rehydrated vault must still prove its reserves");
        assert_eq!(
            (
                proven_amount(&proof_after, &pc_a),
                proven_amount(&proof_after, &pc_b)
            ),
            (Some(v.reserve_a), Some(v.reserve_b)),
            "the proof after restart must agree with the rehydrated vault"
        );
        assert_eq!(
            proof_after.smt_root, proof.smt_root,
            "and bind the same root, so a quote built before the restart and one \
             built after describe the same vault state"
        );
    }

    /// A second creation over the same pair is a DIFFERENT vault, and that is
    /// correct — an owner may run several vaults over one pair, which is exactly
    /// why the reserve leaf is keyed by `vault_id` and not by asset alone.
    ///
    /// This pins the boundary of the duplicate guard, which is easy to
    /// misunderstand. `vault_id` IS deterministic for identical inputs, but
    /// `reference_state_hash` is one of those inputs and necessarily moves after
    /// any successful advance. So the guard does not — and must not — make
    /// `dlv.create` idempotent at the request level. It is a backstop against
    /// INCONSISTENT STATE: a record or a reserve leaf already sitting under the
    /// vault id a creation is about to target, which is what a crash between the
    /// advance and its record write once produced.
    ///
    /// Each vault gets its own encumbrance, and the second draws from what the
    /// first left.
    #[test]
    #[serial]
    fn a_second_vault_over_the_same_pair_is_distinct_and_separately_funded() {
        install_identity();
        let r = router();

        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));

        let req = || generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let call = || {
            crate::runtime::get_runtime().block_on(async {
                r.invoke(AppInvoke {
                    method: "dlv.create".to_string(),
                    args: pack(req().encode_to_vec()),
                })
                .await
            })
        };

        assert!(call().success, "first creation");
        assert!(
            call().success,
            "a second vault over the same pair is allowed"
        );

        let records =
            crate::storage::client_db::amm_vault_records::list_amm_vault_records().expect("list");
        assert_eq!(records.len(), 2, "two vaults, two records");
        assert_ne!(
            records[0].vault_id, records[1].vault_id,
            "the second creation must be a DIFFERENT vault, not a re-funding of the first"
        );

        // Each vault holds its own encumbrance, and the owner paid twice.
        let head = r.core_sdk.device_head().expect("head");
        for rec in &records {
            assert_eq!(head.vault_reserve(&rec.vault_id, &pc_a), 10_000);
            assert_eq!(head.vault_reserve(&rec.vault_id, &pc_b), 5_000);
        }
        assert_eq!(head.balance(&pc_a), 30_000, "50_000 less two 10_000 legs");
        assert_eq!(head.balance(&pc_b), 10_000, "20_000 less two 5_000 legs");
    }

    /// An ORPHANED ENCUMBRANCE refuses: reserve leaves exist with no record.
    ///
    /// Creation must not quietly adopt them. Completing a partial prior creation
    /// from inside a value-moving constructor is a repair, and a repair belongs
    /// in an explicit recovery operation where it can be audited.
    #[test]
    #[serial]
    fn an_orphaned_encumbrance_refuses_rather_than_being_adopted() {
        install_identity();
        let r = router();

        // A head already holding reserves for the vault a creation would target,
        // with no record anywhere — the shape a crash between advance and record
        // write would once have left.
        let v = crate::sdk::funded_vault_fixture::funded_vault(10_000, 5_000, 30);
        let (pc_a, pc_b) = (v.pc_a, v.pc_b);
        r.core_sdk.set_device_head_for_testing(v.head.clone());
        assert!(
            crate::storage::client_db::amm_vault_records::list_amm_vault_records()
                .expect("list")
                .is_empty(),
            "precondition: no record"
        );

        // Both legs orphaned, then just one — a single stray leg is equally a
        // refusal, because half an encumbrance is not a fundable vault.
        for legs in [
            vec![(pc_a, 10_000u64), (pc_b, 5_000u64)],
            vec![(pc_a, 10_000u64)],
        ] {
            let req = generated::DlvInstantiateV1 {
                spec: Some(generated::DlvSpecV1 {
                    policy_digest: vec![0x5Au8; 32],
                    fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                    anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                    ..Default::default()
                }),
                creator_public_key: Vec::new(),
                signature: Vec::new(),
                funding_legs: legs
                    .iter()
                    .map(|(pc, amt)| generated::DlvFundingLegV1 {
                        policy_commit: pc.to_vec(),
                        amount: *amt,
                    })
                    .collect(),
            };
            let res = crate::runtime::get_runtime().block_on(async {
                r.invoke(AppInvoke {
                    method: "dlv.create".to_string(),
                    args: pack(req.encode_to_vec()),
                })
                .await
            });
            assert!(
                !res.success,
                "creation over an orphaned encumbrance must be refused"
            );
        }
    }

    /// Creation that cannot be paid for changes nothing — no balance moves, and
    /// no record is left behind for a restart to resurrect a vault from.
    #[test]
    #[serial]
    fn an_unaffordable_creation_leaves_no_record_and_no_encumbrance() {
        install_identity();
        let r = router();

        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let spendable = crate::sdk::funded_vault_fixture::owner_holding(100, 100);
        let root_before = spendable.root();
        r.core_sdk.set_device_head_for_testing(spendable);

        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5Au8; 32],
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                ..Default::default()
            }),
            creator_public_key: Vec::new(),
            signature: Vec::new(),
            funding_legs: vec![
                generated::DlvFundingLegV1 {
                    policy_commit: pc_a.to_vec(),
                    amount: 10_000,
                },
                generated::DlvFundingLegV1 {
                    policy_commit: pc_b.to_vec(),
                    amount: 5_000,
                },
            ],
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(!res.success, "an unaffordable creation must be refused");

        assert_eq!(
            r.core_sdk.device_head().expect("head").root(),
            root_before,
            "a refused creation must leave the device root untouched"
        );
        assert!(
            crate::storage::client_db::amm_vault_records::list_amm_vault_records()
                .expect("list")
                .is_empty(),
            "a refused creation must persist no record — otherwise a restart \
             rebuilds a vault that was never funded"
        );
    }
}
