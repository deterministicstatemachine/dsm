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
            "dlv.close" => self.dlv_close(i).await,
            other => err(format!("unknown dlv invoke method: {other}")),
        }
    }

    /// `dlv.listOwnedAmmVaults` (query) — the owner's AMM vaults, read from
    /// PERSISTED state: the `amm_vault_records` row for identity and policy,
    /// the device head's encumbered reserve leaves for reserves and sequence.
    ///
    /// It does NOT read the in-memory `DLVManager`. The manager holds only what
    /// this process happened to create, so a wallet that had merely been
    /// restarted showed an owner "My vaults (0)" over a funded, published vault
    /// — observed on a handset, and the same reason restart persistence was
    /// never actually exercised in production.
    ///
    /// Rebuilding a `LimboVault` to repopulate the manager was the alternative
    /// and is rejected deliberately: the record stores identity and policy, not
    /// `parameters_hash`, `creator_signature` or `encrypted_content`. Filling
    /// those in would put an object in the manager that looks complete to every
    /// consumer while carrying values nobody computed. The value-moving paths
    /// need the owner key and the vault's policy, both of which the verified
    /// record supplies; nothing here needs the sealed content.
    ///
    /// Every vault is rehydrated through `rehydrate_amm_vault`, so a record
    /// that is non-canonical, names another owner, carries an unknown
    /// enforcement mode, or whose reserve legs are absent or disagree makes
    /// that vault UNAVAILABLE. Absence is never rendered as zero.
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
        // Reserves and sequence are authenticated by this root. Without a head
        // there is no reserve evidence at all, so there is nothing to show and
        // nothing to guess.
        let Some(head) = self.core_sdk.device_head() else {
            return err("dlv.listOwnedAmmVaults: no device head; reserves unprovable".into());
        };
        let records = match crate::storage::client_db::amm_vault_records::list_amm_vault_records() {
            Ok(r) => r,
            Err(e) => {
                return err(format!(
                    "dlv.listOwnedAmmVaults: reading vault records failed: {e}"
                ));
            }
        };

        let mut summaries: Vec<generated::AmmVaultSummaryV1> = Vec::with_capacity(records.len());
        for rec in &records {
            // Fails closed on a non-canonical pair, an owner mismatch, an
            // unknown enforcement mode, an unfunded leg, or legs whose
            // sequences disagree. `owner_devid`/`owner_genesis` are checked
            // against this head, so a vault that survives belongs to THIS
            // device — which is what makes the wallet's own signing key the
            // right creator key for it.
            let v = match crate::sdk::vault_rehydration::rehydrate_amm_vault(rec, &head) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!(
                        "[dlv.listOwnedAmmVaults] vault {} unavailable: {e}",
                        crate::util::text_id::encode_base32_crockford(&rec.vault_id),
                    );
                    continue;
                }
            };

            // The pair IS the two 32-byte policy commits. Identity is never
            // decoded as UTF-8 nor resolved through the ticker registry: a ticker
            // can name more than one token, and this repo has had two distinct
            // tokens sharing one.
            let (pc_a, pc_b) = (v.pair.a(), v.pair.b());
            let token_a = pc_a.to_vec();
            let token_b = pc_b.to_vec();

            // Display labels, resolved HERE because a policy commit is a digest the
            // frontend cannot invert. NEVER EMPTY: an unresolved commit falls back to
            // its own canonical Base32 Crockford encoding — explicit, deterministic
            // and lossless. Labels only; the identity above is the commit.
            let ticker = |pc: &[u8; 32]| -> String {
                dsm::core::token::resolve_ticker_for_policy_commit(pc)
                    .unwrap_or_else(|| crate::util::text_id::encode_base32_crockford(pc))
            };
            let (token_a_ticker, token_b_ticker) = (ticker(&pc_a), ticker(&pc_b));

            // Settlements this owner has not folded yet. Traders settle without
            // the owner online, so the owner learns what is outstanding by
            // reading storage against its own leaves — ordered by generation,
            // because a fold consumes exactly the current parent.
            let pending_x =
                crate::sdk::vault_rehydration::unapplied_settlements_for_vault(&v.vault_id, &head)
                    .await;

            let (state_number, advertised) =
                match crate::sdk::routing_sdk::load_active_advertisements_for_pair(
                    &token_a, &token_b,
                )
                .await
                {
                    Ok(ads) => match ads
                        .into_iter()
                        .find(|p| p.advertisement.vault_id == v.vault_id.to_vec())
                    {
                        Some(p) => (p.advertisement.updated_state_number, true),
                        None => (0, false),
                    },
                    // Storage being unreachable says nothing about the vault;
                    // it is shown as un-advertised, never hidden.
                    Err(_) => (0, false),
                };

            let vid_b32 = crate::util::text_id::encode_base32_crockford(&v.vault_id);
            let prefix: String = vid_b32.chars().take(16).collect();

            summaries.push(generated::AmmVaultSummaryV1 {
                vault_id: v.vault_id.to_vec(),
                token_a,
                token_b,
                token_a_ticker,
                token_b_ticker,
                // From the owner's own encumbered leaves.
                reserve_a: v.reserve_a,
                reserve_b: v.reserve_b,
                // Real, read from storage against this head's leaves. It used
                // to be hardcoded 0 under a comment saying reconciliation was
                // not wired — so an owner with a settled trade waiting saw a
                // vault that looked caught up.
                pending_unapplied: pending_x.len() as u64,
                pending_x: pending_x.iter().map(|x| x.to_vec()).collect(),
                fee_bps: v.fee_bps,
                advertised_state_number: state_number,
                routing_advertised: advertised,
                anchor_sequence: v.current_sequence,
                anchor_enforcement: v.anchor_enforcement,
                unlock_spec_digest: Some(v.policy_digest.to_vec()),
                unlock_spec_key: Some(format!("defi/spec/amm/{prefix}")),
                // Both reserve leaves at zero IS the terminal state: `dlv.close`
                // drained the vault. Derived from the leaves, never a flag.
                closed: v.reserve_a == 0 && v.reserve_b == 0,
                // Derived from the frozen-artifact table: PUBLISHED iff every
                // birth object has reached quorum on the vault's birth set.
                publication_state: if birth_is_published(&v.vault_id) {
                    generated::VaultPublicationState::Published as i32
                } else {
                    generated::VaultPublicationState::Pending as i32
                },
            });
            // `wallet_pk` gates which device may see these at all; the
            // owner-match is enforced inside rehydration.
            let _ = &wallet_pk;
        }

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
        // The vault's pair + fee ride the mutation so `advance` DERIVES the
        // vault-state leaf (sequence 0, digest of the funded amounts) in the same
        // batch as the reserve leaves — one root for the transition, the reserves
        // and the vault state.
        let reserve_funding = match amm_pair.as_ref() {
            Some((token_a, token_b)) => {
                let pair = match dsm::dlv::pair_identity::CanonicalPair::parse(token_a, token_b) {
                    Ok(p) => p,
                    Err(e) => return err(format!("dlv.create: vault pair is not canonical: {e}")),
                };
                Some(dsm::types::device_state::VaultReserveMutation::Fund {
                    vault_id,
                    legs: funding.clone(),
                    vault_sequence: 0,
                    pair: dsm::types::device_state::VaultStatePair::from_pair(&pair, amm_fee_bps),
                })
            }
            None => None,
        };
        // THE CANONICAL STORAGE SET THIS VAULT IS BORN UNDER. Chosen ONCE, here,
        // from the configured catalog (beta: exactly one fleet), and immutable
        // for the vault's lifetime: the birth anchor binds it, publication
        // artifacts are frozen for it, and every later consumer resolves THAT id
        // through its own catalog — never its local node list.
        let birth_storage_set_id: Option<[u8; 32]> = if amm_pair.is_some() {
            let catalog = match crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
                Ok(c) => c,
                Err(e) => return err(format!("dlv.create: storage-set catalog unavailable: {e}")),
            };
            match catalog.sole_set() {
                Some(set) => Some(set.id()),
                None => {
                    return err(
                        "dlv.create: the storage-set catalog must hold exactly one set to \
                         choose a vault's birth set"
                            .into(),
                    )
                }
            }
        } else {
            None
        };
        let record_to_persist = match (amm_pair.as_ref(), birth_storage_set_id) {
            (Some((token_a, token_b)), Some(birth_set_id)) => {
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
                                storage_set_id: birth_set_id,
                                birth_state_ccb: Vec::new(),
                                birth_presentation: Vec::new(),
                            },
                        )
                    }
                    Err(e) => {
                        return err(format!("dlv.create: vault pair is not canonical: {e}"));
                    }
                }
            }
            // No AMM pair ⇒ no vault record and no birth set. The mixed shapes
            // cannot occur (both derive from `amm_pair`) and are refused rather
            // than papered over with a default.
            (None, None) => None,
            _ => {
                return err(
                    "dlv.create: internal: an AMM pair and its birth storage set must both be \
                     present"
                        .into(),
                )
            }
        };

        // The record write, shared by both shapes below: re-check inside the
        // transaction (two concurrent creators could both pass the readable
        // check above; only one can hold this transaction), then insert.
        let write_record = |tx: &rusqlite::Transaction<'_>,
                            rec: &crate::storage::client_db::amm_vault_records::AmmVaultRecord|
         -> Result<(), dsm::types::error::DsmError> {
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
                    fee_bps, anchor_enforcement, policy_digest, storage_set_id,
                    birth_state_ccb, birth_presentation, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    rec.vault_id.as_slice(),
                    rec.owner_genesis.as_slice(),
                    rec.owner_devid.as_slice(),
                    rec.policy_commit_a.as_slice(),
                    rec.policy_commit_b.as_slice(),
                    rec.fee_bps,
                    rec.anchor_enforcement,
                    rec.policy_digest.as_slice(),
                    rec.storage_set_id.as_slice(),
                    rec.birth_state_ccb.as_slice(),
                    rec.birth_presentation.as_slice(),
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

        match (reserve_funding, record_to_persist.as_ref()) {
            // AN AMM VAULT'S BIRTH: one staged advance. `build` runs after the
            // pure prepare and BEFORE anything is persisted, reading ONLY the
            // outcome (never `device_head()` — the state-machine lock is held):
            // it signs the vault's five birth objects off the exact root the
            // funding advance produced. `write` then persists the record AND
            // freezes those exact bytes inside the same SQLite transaction as
            // the head write. If any signature or freeze fails, nothing commits
            // — no encumbered reserves without their published-in-waiting proofs,
            // no proofs without the reserves. Publication (best-effort now, the
            // generic sweep thereafter) replays the frozen bytes byte-identically
            // until a quorum of the vault's birth storage set holds them.
            (Some(funding_mutation), Some(rec)) => {
                let birth_set_id = rec.storage_set_id;
                let pair = funding_mutation.pair();
                let build = |outcome: &dsm::types::device_state::AdvanceOutcome|
                 -> Result<VaultPublicationArtifacts, dsm::types::error::DsmError> {
                    build_vault_publication_artifacts(
                        outcome,
                        &vault_id,
                        &pair,
                        &birth_set_id,
                        dsm::ccb::genesis_parent_commitment(&vault_id),
                    )
                };
                let write = |tx: &rusqlite::Transaction<'_>,
                             _o: &dsm::types::device_state::AdvanceOutcome,
                             artifacts: &VaultPublicationArtifacts|
                 -> Result<(), dsm::types::error::DsmError> {
                    // The record carries the EXACT published bytes — the birth
                    // state and its presentation — so every later owner-side
                    // composition starts from what the market actually saw.
                    let mut rec_with_birth = rec.clone();
                    rec_with_birth.birth_state_ccb = artifacts.state_ccb.clone();
                    rec_with_birth.birth_presentation = artifacts.presentation.clone();
                    write_record(tx, &rec_with_birth)?;
                    for (key, bytes) in &artifacts.objects {
                        crate::storage::client_db::frozen_publication_artifact::freeze_artifact_with_conn(
                            tx,
                            &birth_set_id,
                            key,
                            bytes,
                            &artifacts.c_n,
                            BIRTH_ARTIFACT_PURPOSE,
                        )
                        .map_err(|e| {
                            dsm::types::error::DsmError::storage(
                                format!("dlv.create: freeze birth artifact {key}: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;
                    }
                    Ok(())
                };
                if let Err(e) = self
                    .core_sdk
                    .execute_on_relationship_staged_with_reserve_mutation(
                        rel_key,
                        actor,
                        op,
                        &[],
                        Some(init_tip),
                        Some(funding_mutation),
                        build,
                        write,
                    )
                {
                    return err(format!("dlv.create: funded creation failed: {e}"));
                }
            }
            // A non-AMM vault: the plain advance, nothing to freeze.
            (None, None) => {
                if let Err(e) = self.core_sdk.execute_on_relationship_with_reserve_mutation(
                    rel_key,
                    actor,
                    op,
                    &[],
                    Some(init_tip),
                    None,
                    None,
                ) {
                    return err(format!("dlv.create: creation failed: {e}"));
                }
            }
            // A funding mutation without a record (or vice versa) is an internal
            // contradiction: refuse before anything moves.
            _ => {
                return err(
                    "dlv.create: internal: AMM funding and vault record must both be present"
                        .into(),
                )
            }
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

        // PUBLISH THE BIRTH — best-effort now; the generic sweep (cold boot and
        // every `storage.sync`) replays the exact frozen bytes until a quorum of
        // the birth set holds them. Until then the vault is FUNDED but NOT
        // market-active: `publication_state` reports it, and the routing
        // advertisement refuses to publish.
        if record_to_persist.is_some() {
            match crate::handlers::artifact_republish::republish_unpublished_artifacts().await {
                Ok(n) => log::info!(
                    "[dlv.create] birth publication pass: {n} artifact(s) reached quorum for {}",
                    crate::util::text_id::encode_base32_crockford(&vault_id)
                ),
                Err(e) => log::warn!(
                    "[dlv.create] birth publication pass errored for {} — the sweep will retry: {e}",
                    crate::util::text_id::encode_base32_crockford(&vault_id)
                ),
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

        // Precondition: a reconcile needs a device head to advance.
        if self.core_sdk.device_head().is_none() {
            return err("dlv.reconcile: no device head".into());
        }
        // CONSUME-ONCE, by settlement IDENTITY — not by sequence alone. The
        // reserve leaf carries the generation but not WHICH settlement produced
        // it, so a sequence-only check (`leaf.sequence >= new_sequence`) cannot
        // tell the winner's idempotent replay from a DIFFERENT settlement that
        // raced the same parent — it reports both as success, which is exactly the
        // marker a loser must never be able to mistake for a fold. The durable
        // consume-once claim can tell them apart.
        match crate::storage::client_db::load_vault_generation_consumer(
            &vault_id,
            receipt.trade.parent_sequence,
        ) {
            Ok(Some(existing)) => {
                if existing.source_commitment == receipt.receipt_id {
                    // The SAME settlement, already folded: idempotent success, and
                    // nothing is re-applied.
                    return pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                        generated::AppStateResponse {
                            key: "dlv.reconcile".to_string(),
                            value: Some(crate::util::text_id::encode_base32_crockford(&vault_id)),
                        },
                    ));
                }
                // A DIFFERENT settlement already consumed this generation — refuse
                // with a typed error. This is never a success the loser could later
                // be mistaken as having folded.
                return err(format!(
                    "dlv.reconcile: vault {} generation {} was already consumed by a \
                     different settlement — this settlement cannot consume it",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                    receipt.trade.parent_sequence,
                ));
            }
            Ok(None) => {} // generation still open — fold it below
            Err(e) => return err(format!("dlv.reconcile: consumption lookup failed: {e}")),
        }

        let op = dsm::types::operations::Operation::DlvOwnerApply {
            vault_id: vault_id.to_vec(),
            settlement_receipt_id: receipt.receipt_id,
            pending_pointer_x: x,
            parent_sequence: receipt.trade.parent_sequence,
            new_sequence: receipt.trade.new_sequence,
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
        // The vault's pair + fee come from the owner's OWN record of the vault it
        // created — never from the receipt — so `advance` can derive the
        // vault-state leaf at `new_sequence` and refuse a settlement naming an
        // asset outside the pair. No record ⇒ this device did not create the
        // vault ⇒ it cannot fold anything for it.
        let record =
            match crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return err(
                        "dlv.reconcile: no AMM vault record for this vault on this device — \
                     only the creating owner can fold settlements"
                            .into(),
                    )
                }
                Err(e) => {
                    return err(format!(
                        "dlv.reconcile: reading the vault record failed: {e}"
                    ))
                }
            };
        let pair = match dsm::types::device_state::VaultStatePair::new(
            record.policy_commit_a,
            record.policy_commit_b,
            record.fee_bps,
        ) {
            Ok(p) => p,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: vault record pair is not canonical: {e}"
                ))
            }
        };
        let mutation = dsm::types::device_state::VaultReserveMutation::ApplySettlement {
            vault_id,
            input_policy_commit: receipt.trade.input_policy_commit,
            input_amount: receipt.trade.input_amount,
            output_policy_commit: receipt.trade.output_policy_commit,
            output_amount: receipt.trade.output_amount,
            parent_sequence: receipt.trade.parent_sequence,
            new_sequence: receipt.trade.new_sequence,
            pair,
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
        // The consume-once claim is written INSIDE the fold's advance
        // transaction, so the claim and the reserve move commit together or not at
        // all. `UNIQUE(vault_id, parent_sequence)` decides a race that slipped past
        // the pre-check above: a losing racer's claim resolves to `Conflict`, which
        // this closure turns into an error, rolling back the whole advance so the
        // loser moves no reserve.
        let claim_vault = vault_id;
        let claim_parent = receipt.trade.parent_sequence;
        let claim_child = receipt.trade.new_sequence;
        let claim_source = receipt.receipt_id;
        let record_consumption = move |tx: &rusqlite::Transaction<'_>,
                                       _outcome: &dsm::types::device_state::AdvanceOutcome|
              -> Result<(), dsm::types::error::DsmError> {
            use crate::storage::client_db::{
                cas_consume_vault_generation_with_conn, VaultGenerationConsumeOutcome,
            };
            match cas_consume_vault_generation_with_conn(
                tx,
                &claim_vault,
                claim_parent,
                claim_child,
                &claim_source,
            )
            .map_err(|e| {
                dsm::types::error::DsmError::storage(
                    format!("dlv.reconcile: consume-once claim failed: {e}"),
                    None::<std::io::Error>,
                )
            })? {
                VaultGenerationConsumeOutcome::Consumed
                | VaultGenerationConsumeOutcome::AlreadyConsumedSameSettlement => Ok(()),
                VaultGenerationConsumeOutcome::Conflict { .. } => {
                    Err(dsm::types::error::DsmError::invalid_operation(
                        "dlv.reconcile: this vault generation was consumed by a different \
                         settlement (race) — rolling back the fold",
                    ))
                }
            }
        };
        // EMPTY deltas: the owner's spendable balance is not part of a
        // settlement. Only the reserve leaves move, in this same advance.
        if let Err(e) = self.core_sdk.execute_on_relationship_with_reserve_mutation(
            rel_key,
            actor,
            op,
            &[],
            Some(init_tip),
            Some(mutation),
            Some(&record_consumption),
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

    /// Commit the canonical close: ONE staged advance in which the release, the
    /// consume-once claim for this generation, and the FIVE frozen terminal
    /// objects land together — or none of them do. Value is spendable at this
    /// commit, and durable, replayable terminal evidence exists locally at the
    /// same instant.
    ///
    /// Shared by `dlv.close` and by recovery, so a resumed close commits through
    /// exactly the same path (with the same frozen operation bytes) as the
    /// original attempt.
    #[allow(clippy::too_many_arguments)]
    async fn commit_canonical_close(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
        new_sequence: u64,
        pair: &dsm::types::device_state::VaultStatePair,
        storage_set_id: &[u8; 32],
        close_commitment: &[u8; 32],
        op: dsm::types::operations::Operation,
        reserve_a: u64,
        reserve_b: u64,
        parent_binding: [u8; 32],
    ) -> Result<(), String> {
        use crate::storage::client_db::dlv_close_intent as intent_db;
        // One staged advance: the release, the consume-once claim for this
        // generation, and the FIVE frozen terminal objects commit together, or
        // none of them do. Value is spendable at this commit — and durable,
        // replayable terminal evidence exists locally at the same instant.
        let reference_state = self
            .core_sdk
            .get_current_state()
            .map_err(|e| format!("dlv.close: get_current_state failed: {e}"))?;
        let actor = reference_state.device_info.device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        let mutation = dsm::types::device_state::VaultReserveMutation::Withdraw {
            vault_id: *vault_id,
            legs: vec![(pair.a(), reserve_a), (pair.b(), reserve_b)],
            parent_sequence,
            new_sequence,
            pair: *pair,
        };
        let build = |outcome: &dsm::types::device_state::AdvanceOutcome| {
            build_vault_publication_artifacts(
                outcome,
                vault_id,
                pair,
                storage_set_id,
                parent_binding,
            )
        };
        let write = |tx: &rusqlite::Transaction<'_>,
                     _o: &dsm::types::device_state::AdvanceOutcome,
                     artifacts: &VaultPublicationArtifacts|
         -> Result<(), dsm::types::error::DsmError> {
            use crate::storage::client_db::{
                cas_consume_vault_generation_with_conn, VaultGenerationConsumeOutcome,
            };
            match cas_consume_vault_generation_with_conn(
                tx,
                vault_id,
                parent_sequence,
                new_sequence,
                close_commitment,
            )
            .map_err(|e| {
                dsm::types::error::DsmError::storage(
                    format!("dlv.close: consume-once claim failed: {e}"),
                    None::<std::io::Error>,
                )
            })? {
                VaultGenerationConsumeOutcome::Consumed
                | VaultGenerationConsumeOutcome::AlreadyConsumedSameSettlement => {}
                VaultGenerationConsumeOutcome::Conflict { .. } => {
                    return Err(dsm::types::error::DsmError::invalid_operation(
                        "dlv.close: this vault generation was consumed by a settlement — rolling \
                         back the close",
                    ))
                }
            }
            for (key, bytes) in &artifacts.objects {
                crate::storage::client_db::frozen_publication_artifact::freeze_artifact_with_conn(
                    tx,
                    storage_set_id,
                    key,
                    bytes,
                    &artifacts.c_n,
                    TERMINAL_ARTIFACT_PURPOSE,
                )
                .map_err(|e| {
                    dsm::types::error::DsmError::storage(
                        format!("dlv.close: freeze terminal artifact {key}: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            }
            intent_db::set_state_with_conn(
                tx,
                vault_id,
                parent_sequence,
                intent_db::CloseIntentState::CanonicalCloseCommitted,
            )
            .map_err(|e| {
                dsm::types::error::DsmError::storage(
                    format!("dlv.close: intent state write failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
            Ok(())
        };
        if let Err(e) = self
            .core_sdk
            .execute_on_relationship_staged_with_reserve_mutation(
                rel_key,
                actor,
                op,
                &[],
                Some(init_tip),
                Some(mutation),
                build,
                write,
            )
        {
            // NOT abandoned here. This error can be transient (a busy database,
            // a lock) or permanent (the owner folded a settlement in between, so
            // the generation moved and the reserve arm refuses). Abandoning on
            // the transient case would wedge the parent we hold in the register
            // forever, so the decision is left to `resume_close_intents`: it
            // re-reads the leaves each pass and abandons only when the frontier
            // has genuinely moved past this close.
            return Err(format!("dlv.close: canonical close failed: {e}"));
        }

        // Publish the terminal set — best-effort now, the generic sweep
        // thereafter. The value is already spendable; this makes the vault's
        // death visible to the market.
        match crate::handlers::artifact_republish::republish_unpublished_artifacts().await {
            Ok(n) => log::info!(
                "[dlv.close] {}: {n} terminal artifact(s) at quorum",
                crate::util::text_id::encode_base32_crockford(vault_id)
            ),
            Err(e) => log::warn!(
                "[dlv.close] {}: publication pass errored: {e}",
                crate::util::text_id::encode_base32_crockford(vault_id)
            ),
        }
        Ok(())
    }

    /// Resume every close this device started but did not finish.
    ///
    /// Runs on each `storage.sync` push pass. It never re-signs the claim (the
    /// register compares exact bytes, so a re-encode would read as a different
    /// claimant) and never infers closure from a pointer or a held claim — the
    /// canonical state decides.
    ///
    /// THE S INVARIANT IS RE-ESTABLISHED FIRST. Between the crash and now the
    /// vault's lineage could have been re-read; before touching anything the
    /// resume re-composes and requires
    /// `claim.storage_set_id == composed.storage_set_id == record.storage_set_id`.
    /// Anything else is abandoned — the vault stays open and encumbered, which
    /// is the safe direction.
    ///
    /// The claim is then re-run with the SAME frozen bytes (idempotent at any
    /// member that already holds them). A `Contested` result means another
    /// contestant took the parent while we were down: abandon.
    pub(crate) async fn resume_close_intents(&self) -> Result<u32, String> {
        use crate::storage::client_db::dlv_close_intent as intent_db;

        let intents = intent_db::list_unfinished_intents().map_err(|e| e.to_string())?;
        if intents.is_empty() {
            return Ok(0);
        }
        // A locked wallet cannot sign the terminal proofs, so there is nothing
        // to finish; leave every intent exactly as it is and retry later. Note
        // this ASKS whether signing is possible without binding the keys —
        // nothing below this line holds a signing key, and that is the point of
        // the split with `finish_prepared_close`.
        if !crate::sdk::signing_authority::can_sign() {
            return Ok(0);
        }
        let mut finished = 0u32;
        for intent in intents {
            let vault_b32 = crate::util::text_id::encode_base32_crockford(&intent.vault_id);
            let abandon = |why: &str| {
                log::warn!("[dlv.close resume] {vault_b32}: abandoning — {why}");
                let _ = intent_db::set_state(
                    &intent.vault_id,
                    intent.parent_sequence,
                    intent_db::CloseIntentState::Abandoned,
                );
            };

            // The vault as this device knows it, and as its lineage says it is.
            let Ok(Some(record)) =
                crate::storage::client_db::amm_vault_records::get_amm_vault_record(
                    &intent.vault_id,
                )
            else {
                abandon("no vault record on this device");
                continue;
            };
            let Some(head) = self.core_sdk.device_head() else {
                return Ok(finished);
            };
            let Ok(live) = crate::sdk::vault_rehydration::rehydrate_amm_vault(&record, &head)
            else {
                abandon("the vault could not be rehydrated");
                continue;
            };
            if live.current_sequence != intent.parent_sequence {
                // Either the close already committed (leaves at parent+1) or a
                // settlement was folded in between; nothing to resume.
                abandon("the vault has moved past this close's generation");
                continue;
            }
            let Ok(pair) = dsm::types::device_state::VaultStatePair::new(
                live.pair.a(),
                live.pair.b(),
                live.fee_bps,
            ) else {
                abandon("the vault pair is not canonical");
                continue;
            };
            let _ = &pair; // pair validity was the gate above; composition re-derives it
            let Ok(composed) = compose_own_vault(&intent.vault_id).await else {
                // Composition unavailable (baseline unpublished, storage
                // unreachable): keep the intent and try again later.
                continue;
            };
            // THE FROZEN ENVELOPE, FROM STORAGE. This is the only claim this
            // pass can submit: `FrozenClaimEnvelope` has no constructor that
            // takes bytes or keys, so nothing below can build one.
            let claim = match crate::sdk::settlement_slot::FrozenClaimEnvelope::load(
                &intent.vault_id,
                intent.parent_sequence,
                &intent.x_close,
            ) {
                Ok(Some(c)) => c,
                Ok(None) => {
                    abandon("no frozen claim envelope is retained for this close");
                    continue;
                }
                Err(_) => {
                    abandon("the frozen claim envelope no longer verifies");
                    continue;
                }
            };
            // THE THREE-WAY S EQUALITY: the frozen claim, the vault's
            // birth-bound lineage, and the local record must all name one set.
            let claim_set_id = claim.storage_set_id();
            if claim_set_id != composed.storage_set_id
                || record.storage_set_id != composed.storage_set_id
            {
                abandon("the storage set no longer agrees across claim, lineage and record");
                continue;
            }
            if composed.sequence != intent.parent_sequence {
                abandon("the composed frontier moved past this close's generation");
                continue;
            }
            let Ok(catalog) = crate::sdk::storage_set::StorageSetCatalog::from_env_config() else {
                continue;
            };
            let Some(claim_set) = catalog.resolve(&composed.storage_set_id) else {
                continue;
            };
            let claim_set = claim_set.clone();

            // Re-run the claim with the retained envelope.
            match crate::sdk::settlement_slot::claim_settlement_slot(
                &claim_set,
                &claim,
                &intent.vault_id,
                intent.parent_sequence,
                &intent.x_close,
            )
            .await
            {
                Ok(_) => {
                    let _ = intent_db::set_state(
                        &intent.vault_id,
                        intent.parent_sequence,
                        intent_db::CloseIntentState::ClaimPublished,
                    );
                }
                Err(crate::sdk::settlement_slot::SlotClaimError::Contested { .. }) => {
                    abandon("another contestant holds this vault generation");
                    let _ = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_delete_key(
                        &intent.pointer_key,
                    )
                    .await;
                    continue;
                }
                // Quorum unknown: keep the intent and retry on a later pass.
                Err(_) => continue,
            }

            // The operation is REPLAYED from the frozen bytes — never rebuilt.
            let Ok(op) = dsm::types::operations::Operation::from_bytes(&intent.op_bytes) else {
                abandon("the frozen close operation no longer decodes");
                continue;
            };
            let Some(new_sequence) = intent.parent_sequence.checked_add(1) else {
                abandon("sequence overflow");
                continue;
            };
            let close_commitment = {
                let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                    dsm::common::domain_tags::TAG_DSM_DLV_CLOSE_COMMIT,
                );
                h.update(&intent.vault_id);
                h.update(&intent.parent_sequence.to_be_bytes());
                *h.finalize().as_bytes()
            };
            match self
                .finish_prepared_close(
                    &intent.vault_id,
                    intent.parent_sequence,
                    new_sequence,
                    &pair,
                    &composed.storage_set_id,
                    &close_commitment,
                    op,
                    live.reserve_a,
                    live.reserve_b,
                )
                .await
            {
                Ok(()) => {
                    finished += 1;
                    log::info!("[dlv.close resume] {vault_b32}: close completed after restart");
                }
                Err(e) => log::warn!("[dlv.close resume] {vault_b32}: {e}"),
            }
        }
        Ok(finished)
    }

    /// The COMMIT half of a resumed close: replay the frozen operation and sign
    /// the terminal publication set.
    ///
    /// Split from [`Self::resume_close_intents`] so that the claim half holds
    /// no signing key at all. Terminal proofs genuinely have to be signed here
    /// — they did not exist when the close was interrupted — but the parent
    /// claim must never be, and keeping the key out of that scope is what makes
    /// "never" a property of the code rather than of the current author's
    /// discipline.
    #[allow(clippy::too_many_arguments)]
    async fn finish_prepared_close(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
        new_sequence: u64,
        pair: &dsm::types::device_state::VaultStatePair,
        storage_set_id: &[u8; 32],
        close_commitment: &[u8; 32],
        op: dsm::types::operations::Operation,
        reserve_a: u64,
        reserve_b: u64,
    ) -> Result<(), String> {
        // The terminal state's predecessor edge: the c_n of the frontier this
        // close consumes, recomputed from the vault's own published baseline.
        let composed = compose_own_vault(vault_id)
            .await
            .map_err(|e| format!("resumed close: {e}"))?;
        if composed.sequence != parent_sequence {
            return Err(format!(
                "resumed close: the composed frontier is at generation {} but this close \
                 consumes {parent_sequence} — reconcile first",
                composed.sequence
            ));
        }
        self.commit_canonical_close(
            vault_id,
            parent_sequence,
            new_sequence,
            pair,
            storage_set_id,
            close_commitment,
            op,
            reserve_a,
            reserve_b,
            composed.c_n,
        )
        .await
    }

    /// `dlv.close` — the owner withdraws ALL remaining liquidity and retires the
    /// vault.
    ///
    /// The request names only the vault. Every field of the canonical
    /// `Operation::DlvClose` is DERIVED here from the owner's VERIFIED frontier
    /// and signed, so the signature binds the whole transition and a caller
    /// cannot state what it withdraws.
    ///
    /// Order, and why: the frontier gate first (a close must consume exactly the
    /// current composed generation, with exactly the reserves that generation
    /// holds); then durable intent — the exact bytes this device will publish,
    /// claim and advance — BEFORE anything external, so a crash resumes instead
    /// of re-signing; then the parent claim in the vault's quorum register,
    /// because everything after it moves value and everything before it is
    /// reversible by stopping; then the canonical close, which makes the value
    /// spendable AND freezes the terminal proof set in the same transaction.
    async fn dlv_close(&self, i: AppInvoke) -> AppResult {
        use crate::storage::client_db::dlv_close_intent as intent_db;

        let bytes = match unwrap_argpack(&i.args) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.close: {e}")),
        };
        let req = match generated::DlvCloseV1::decode(&*bytes) {
            Ok(r) => r,
            Err(e) => return err(format!("dlv.close: decode DlvCloseV1 failed: {e}")),
        };
        if req.vault_id.len() != 32 {
            return err("dlv.close: vault_id must be 32 bytes".into());
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&req.vault_id);
        let vault_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);

        let Some(head) = self.core_sdk.device_head() else {
            return err("dlv.close: no device head".into());
        };
        // The owner's OWN record of the vault it created: pair, fee, and the
        // storage set it was born under. No record ⇒ this device did not create
        // the vault ⇒ it cannot close it.
        let record =
            match crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    return err(
                        "dlv.close: no AMM vault record on this device — only the creating owner \
                         can close a vault"
                            .into(),
                    )
                }
                Err(e) => return err(format!("dlv.close: reading the vault record failed: {e}")),
            };
        // Reserves and generation come from the LEAVES, never from a request.
        let live = match crate::sdk::vault_rehydration::rehydrate_amm_vault(&record, &head) {
            Ok(v) => v,
            Err(e) => return err(format!("dlv.close: vault unavailable: {e:?}")),
        };
        let pair = match dsm::types::device_state::VaultStatePair::new(
            live.pair.a(),
            live.pair.b(),
            live.fee_bps,
        ) {
            Ok(p) => p,
            Err(e) => return err(format!("dlv.close: vault pair is not canonical: {e}")),
        };
        let parent_sequence = live.current_sequence;
        let Some(new_sequence) = parent_sequence.checked_add(1) else {
            return err("dlv.close: vault sequence overflow".into());
        };
        if live.reserve_a == 0 && live.reserve_b == 0 {
            return err("dlv.close: this vault is already closed (both reserves are zero)".into());
        }

        // ── THE FRONTIER GATE ────────────────────────────────────────────────
        // A close may consume ONLY the current composed generation, and only
        // when this device has already folded everything that generation
        // contains. Sequence equality alone is not enough: the reserves must
        // agree too, or a close could drain amounts the market has already
        // moved past. Any composition failure is a refusal — never close blind.
        let composed = match compose_own_vault(&vault_id).await {
            Ok(c) => c,
            Err(e) => {
                return err(format!(
                    "dlv.close: the vault's composed state could not be verified ({e}) — \
                     refusing to close blind"
                ))
            }
        };
        if composed.sequence != parent_sequence {
            return err(format!(
                "dlv.close: the market has moved past this device's view (composed generation {} \
                 vs local {parent_sequence}) — reconcile the outstanding settlements first",
                composed.sequence
            ));
        }
        if pair.reserves_digest(composed.reserves_a, composed.reserves_b)
            != pair.reserves_digest(live.reserve_a, live.reserve_b)
        {
            return err(
                "dlv.close: the composed reserves disagree with this device's leaves at the same \
                 generation — refusing (reconcile, then close)"
                    .into(),
            );
        }
        // The set is the vault's BIRTH-bound one, a member list inside the
        // signed `V_n` itself; the local record is a cache and must agree.
        if record.storage_set_id != composed.storage_set_id {
            return err(
                "dlv.close: the local vault record names a different storage set than the vault's \
                 signed state — refusing"
                    .into(),
            );
        }
        let storage_set_id = composed.storage_set_id;
        let claim_set = {
            let catalog = match crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
                Ok(c) => c,
                Err(e) => return err(format!("dlv.close: storage-set catalog: {e}")),
            };
            match catalog.resolve(&storage_set_id) {
                Some(sset) => sset.clone(),
                None => {
                    return err(
                        "dlv.close: the vault's storage set is not resolvable through this \
                         device's catalog — cannot claim its parent; refusing"
                            .into(),
                    )
                }
            }
        };

        // ── THE CLOSE'S IDENTITY ─────────────────────────────────────────────
        // Deterministic, so a retry occupies the SAME slot rather than a second
        // one, and a recovery replays the same bytes.
        let x_close = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                dsm::common::domain_tags::TAG_DSM_DLV_CLOSE_X,
            );
            h.update(&vault_id);
            h.update(&parent_sequence.to_be_bytes());
            h.update(&head.devid());
            *h.finalize().as_bytes()
        };
        let close_commitment = {
            let mut h = dsm::crypto::blake3::dsm_domain_hasher(
                dsm::common::domain_tags::TAG_DSM_DLV_CLOSE_COMMIT,
            );
            h.update(&vault_id);
            h.update(&parent_sequence.to_be_bytes());
            *h.finalize().as_bytes()
        };

        // The canonical operation: derived, then signed.
        let op = dsm::types::operations::Operation::DlvClose {
            vault_id: vault_id.to_vec(),
            leg_a_policy_commit: pair.a(),
            leg_a_amount: live.reserve_a,
            leg_b_policy_commit: pair.b(),
            leg_b_amount: live.reserve_b,
            parent_sequence,
            new_sequence,
            fee_bps: pair.fee_bps(),
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };
        let op = match self.core_sdk.sign_operation_sphincs(op) {
            Ok(signed) => signed,
            Err(e) => return err(format!("dlv.close: failed to sign DlvClose: {e}")),
        };
        let (owner_pk, owner_sk) = match (
            crate::sdk::signing_authority::current_public_key(),
            crate::sdk::signing_authority::current_secret_key(),
        ) {
            (Ok(pk), Ok(sk)) if !pk.is_empty() && !sk.is_empty() => (pk, sk),
            _ => return err("dlv.close: signing authority unavailable (wallet locked)".into()),
        };

        // The DISCOVERY pointer: it tells the next quote that this parent is in
        // flight. It is not the claim — exclusivity is the register's job — and
        // it can never be activated, because no receipt will ever hash to a
        // close commitment.
        let terminal_digest = pair.reserves_digest(0, 0);
        let pointer = match dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer(
            &vault_id,
            parent_sequence,
            new_sequence,
            &x_close,
            &terminal_digest,
            &close_commitment,
            &owner_pk,
            &owner_sk,
        ) {
            Ok(p) => p,
            Err(e) => return err(format!("dlv.close: failed to sign the close pointer: {e}")),
        };
        let pointer_bytes = generated::VaultPendingPointerV1 {
            vault_id: pointer.vault_id.to_vec(),
            parent_sequence: pointer.parent_sequence,
            new_sequence: pointer.new_sequence,
            x: pointer.x.to_vec(),
            new_reserves_digest: pointer.new_reserves_digest.to_vec(),
            expected_receipt_hash: pointer.expected_receipt_hash.to_vec(),
            publisher_public_key: pointer.publisher_public_key.clone(),
            publisher_signature: pointer.publisher_signature.clone(),
        }
        .encode_to_vec();
        let pointer_key = crate::sdk::route_commit_sdk::vault_pending_pointer_key(
            &vault_id,
            new_sequence,
            &x_close,
        );

        // The register claim, signed once and RETAINED — retries replay these
        // exact bytes.
        let claim = match crate::sdk::settlement_slot::frozen_claim_envelope(
            &vault_id,
            parent_sequence,
            &x_close,
            &storage_set_id,
        ) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.close: build slot claim: {e}")),
        };

        // ── DURABLE INTENT, BEFORE ANYTHING EXTERNAL ─────────────────────────
        // Recovery orchestration only; never authority.
        let intent = intent_db::CloseIntent {
            vault_id,
            parent_sequence,
            state: intent_db::CloseIntentState::PreparedClose,
            op_bytes: op.to_bytes(),
            x_close,
            pointer_key: pointer_key.clone(),
            pointer_bytes: pointer_bytes.clone(),
            storage_set_id,
            insertion_ordinal: 0,
        };
        if let Err(e) = intent_db::put_intent(&intent) {
            return err(format!("dlv.close: could not record the close intent: {e}"));
        }

        // Discovery first (best-effort: the register decides exclusivity, so a
        // pointer that does not land costs a quote, not safety).
        if let Err(e) = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_put_bytes(
            &pointer_key,
            &pointer_bytes,
        )
        .await
        {
            log::warn!("[dlv.close] {vault_b32}: discovery pointer publish failed: {e:?}");
        }

        // ── CLAIM THE PARENT ─────────────────────────────────────────────────
        match crate::sdk::settlement_slot::claim_settlement_slot(
            &claim_set,
            &claim,
            &vault_id,
            parent_sequence,
            &x_close,
        )
        .await
        {
            Ok(_) => {
                let _ = intent_db::set_state(
                    &vault_id,
                    parent_sequence,
                    intent_db::CloseIntentState::ClaimPublished,
                );
            }
            Err(crate::sdk::settlement_slot::SlotClaimError::Contested { .. }) => {
                // Another contestant holds this parent. Abandon: the vault stays
                // open and encumbered, and the owner may close again at the next
                // generation once that trade is folded.
                let _ = intent_db::set_state(
                    &vault_id,
                    parent_sequence,
                    intent_db::CloseIntentState::Abandoned,
                );
                let _ =
                    crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_delete_key(&pointer_key)
                        .await;
                return err(
                    "dlv.close: another trade holds this vault generation — reconcile it, then \
                     close at the next generation"
                        .into(),
                );
            }
            Err(e) => {
                // Quorum unknown: the close stays PREPARED and is resumed later.
                return err(format!(
                    "dlv.close: could not establish exclusive use of this vault generation: {e}"
                ));
            }
        }

        if let Err(e) = self
            .commit_canonical_close(
                &vault_id,
                parent_sequence,
                new_sequence,
                &pair,
                &storage_set_id,
                &close_commitment,
                op,
                live.reserve_a,
                live.reserve_b,
                composed.c_n,
            )
            .await
        {
            return err(e);
        }

        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
            generated::AppStateResponse {
                key: "dlv.close".to_string(),
                value: Some(vault_b32),
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
            // vault's COMPOSED current state (generation + reserves digest)
            // per the vault's `anchor_enforcement` policy.
            //
            //   Required    => fields MUST be present and match → reject otherwise
            //   Optional    => if fields present, must match; if absent,
            //                  fall through with a flag so callers know
            //                  identity-binding wasn't enforced
            //   Unspecified => grandfathered; same behaviour as Optional
            //                  with no enforcement
            //
            // RESERVES ARE COMPOSED FROM THE OWNER'S PROOF, never taken from
            // this device and never from a caller-supplied number.
            //
            // A settling trader does not hold the owner's reserves — they are
            // encumbered leaves in the OWNER's device SMT. The authoritative
            // baseline is `VaultReserveInclusionProofV1`, published by the owner
            // and verified against its own signature and SMT paths; every later
            // generation is a verified trader receipt folded onto it. Passing
            // zeros, as this once did, would let a hop bind to reserves nobody
            // holds; demanding an owner proof at every generation, as it did
            // next, let nothing settle past the first trade.
            // Filled by the composition block below; the settle terms are only
            // built on the path where that block succeeded.
            let amm_fee_bps;
            let reserve_owner_devid;
            let reserve_owner_genesis;
            let parent_binding;
            let composed_sequence;
            let vault_storage_set_id;
            let (proven_a, proven_b) = {
                // The pair comes from the vault's OWN condition, so the legs the
                // reserves are read for are the ones the curve governs.
                let dsm::vault::FulfillmentMechanism::AmmConstantProduct {
                    token_a: ref vt_a,
                    token_b: ref vt_b,
                    fee_bps: vault_fee_bps,
                } = vault.fulfillment_condition
                else {
                    return err("dlv.unlockRouted: routed settlement requires an AMM vault".into());
                };

                // DELEGATED LIQUIDITY. The vault's state at the hop's parent is
                // COMPOSED: the owner's baseline — the exact `CCB(V_0)` and
                // `AnchorPresentationV3` the birth published, re-verified
                // through the full P0-P6 predicate — plus every verified
                // trader generation folded on top of it (a trader-signed
                // pending pointer, a trader-signed settlement receipt
                // SMT-verified against that trader's own root and matching the
                // pointer's committed hash, the RouteCommit bound to X and
                // eligible, the hop's parent binding naming the fold cursor's
                // c_n, and the AMM re-simulation reproducing the trader's
                // expected output).
                //
                // This is exactly the authority the QUOTE side already trusts
                // when it binds a hop to a parent, and it is what lets the
                // market keep moving while the LP is offline: no owner
                // signature is needed on any transition after the baseline.
                let composed = match compose_own_vault(&vault_id).await {
                    Ok(c) => c,
                    // Every composition failure is "the liquidity is unproven".
                    // Fail closed — nothing here may be guessed at.
                    Err(e) => {
                        return err(format!(
                            "dlv.unlockRouted: vault {} cannot be composed from its published \
                             baseline ({e}); its liquidity is unproven and cannot be settled \
                             against",
                            crate::util::text_id::encode_base32_crockford(&vault_id),
                        ));
                    }
                };

                // THE PARENT BINDING GUARD — before anything moves. The hop
                // must name EXACTLY the c_n the composition reached: one
                // byte-equality that pins the generation, the reserves, the
                // pair and the fee all at once, because they are members of
                // the identified V_n. Behind the frontier, the parent was
                // already consumed by an earlier trader; ahead of it, the
                // trader is pre-settling a state that does not exist. Both
                // read as a binding mismatch and both are refusals.
                {
                    use crate::sdk::route_commit_sdk::{enforce_parent_binding, ParentBindingReject};
                    match enforce_parent_binding(&hop, &composed.c_n) {
                        Ok(()) => {}
                        Err(ParentBindingReject::MissingBinding) => {
                            return err("dlv.unlockRouted: the RouteCommit hop carries no parent \
                                 binding — an unbound hop names no state and cannot be \
                                 settled"
                                .to_string());
                        }
                        Err(ParentBindingReject::StaleParent) => {
                            return err(format!(
                                "dlv.unlockRouted: vault {} is at generation {} but the route \
                                 binds a different parent state — that parent is stale, \
                                 already consumed, or was never this vault's state",
                                crate::util::text_id::encode_base32_crockford(&vault_id),
                                composed.sequence,
                            ));
                        }
                    }
                }

                amm_fee_bps = vault_fee_bps;
                // The settlement records the owner the composition PROVED (the
                // P0-P6 chain at the state's committed authority position) and
                // the parent identity it consumes.
                reserve_owner_devid = composed.owner_devid;
                reserve_owner_genesis = composed.owner_genesis;
                parent_binding = composed.c_n;
                composed_sequence = composed.sequence;
                vault_storage_set_id = composed.storage_set_id;
                (composed.reserves_a, composed.reserves_b)
            };
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
                    settle_terms = Some(SettleTerms {
                        owner_public_key: vault.creator_public_key.clone(),
                        owner_devid: reserve_owner_devid,
                        owner_genesis: reserve_owner_genesis,
                        input_policy_commit: in_pc,
                        output_policy_commit: out_pc,
                        input_amount: in_amt,
                        output_amount: out_amt,
                        parent_binding,
                        parent_sequence: composed_sequence,
                        fee_bps: amm_fee_bps,
                        sigma: [0u8; 32],
                        storage_set_id: vault_storage_set_id,
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
        // The register is the vault's BIRTH set, resolved from its signed anchor
        // through this device's catalog — never this device's own node list. A
        // set this device cannot resolve is a refusal: it cannot know who holds
        // the parent.
        let claim_set =
            {
                let catalog = match crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
                    Ok(c) => c,
                    Err(e) => return err(format!("dlv.unlockRouted: storage-set catalog: {e}")),
                };
                match catalog.resolve(&settle.storage_set_id) {
                    Some(s) => s.clone(),
                    None => return err(
                        "dlv.unlockRouted: the vault's storage set is not resolvable through this \
                         device's catalog — cannot claim its parent; refusing"
                            .into(),
                    ),
                }
            };
        // The claim envelope is signed ONCE and retained durably; a retry of this
        // request replays the exact same bytes (a byte-different re-encode would
        // read as a different claimant at every member that already holds ours).
        let frozen_claim = match crate::sdk::settlement_slot::frozen_claim_envelope(
            &vault_id,
            settle.parent_sequence,
            &x,
            &settle.storage_set_id,
        ) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.unlockRouted: build slot claim: {e}")),
        };
        if let Err(e) = crate::sdk::settlement_slot::claim_settlement_slot(
            &claim_set,
            &frozen_claim,
            &vault_id,
            settle.parent_sequence,
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
            parent_sequence: settle.parent_sequence,
            parent_binding: settle.parent_binding,
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
                parent_sequence: settle.parent_sequence,
                new_sequence: settle.parent_sequence.saturating_add(1),
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

/// Purpose label frozen on a vault's birth objects (opaque to the
/// publication layer; for operators and proofs).
const BIRTH_ARTIFACT_PURPOSE: &str = "dlv-birth";
/// Purpose label frozen on a vault's TERMINAL objects.
const TERMINAL_ARTIFACT_PURPOSE: &str = "dlv-terminal";

/// A vault generation's publication set, built and signed off ONE
/// `AdvanceOutcome` — the exact reserves the advance landed — before anything
/// is persisted, then frozen byte-for-byte inside the advance transaction.
///
/// TWO durable objects, each an Area-4 immutable `(namespace, payload)`
/// tuple: `CCB(V_n)` under `DSM/vault-state`, and the owner's
/// `AnchorPresentationV3` under `DSM/anchor-presentation/v1`. Everything the
/// old five-object set restated — the anchor, the `/latest` mirrors, the
/// inclusion and reserve proofs — is a field of the `V_n` that `c_n`
/// identifies, or is proven by the presentation's P0–P6 chain, so nothing
/// else is published.
struct VaultPublicationArtifacts {
    /// `(object_key, exact bytes)` — what gets frozen and replayed. Keys use
    /// [`immutable_object_key`], so the sweep replays them through the
    /// immutable endpoint (write-once on the tuple), never the mutable KV path.
    objects: Vec<(String, Vec<u8>)>,
    /// `c_n` of the published state — recorded as the artifact binding.
    c_n: [u8; 32],
    /// `CCB(V_n)`, exactly as published (also stored on the vault record).
    state_ccb: Vec<u8>,
    /// The presentation proto bytes, exactly as published.
    presentation: Vec<u8>,
}

/// The frozen-artifact object key for an immutable `(namespace, payload)`
/// tuple: `immutable::{namespace}::{addr_b32}`. The address is the Area-4
/// derivation, so the key names exactly one byte string forever — the sweep
/// parses this shape and delivers through the immutable endpoint.
pub(crate) fn immutable_object_key(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    payload: &[u8],
) -> String {
    let addr = dsm::storage_object::immutable_addr(namespace, payload);
    format!(
        "immutable::{}::{}",
        String::from_utf8_lossy(namespace.source_bytes()),
        crate::util::text_id::encode_base32_crockford(&addr)
    )
}

/// The owner-identity inputs for presentation building, resolved from the
/// persisted genesis record. Fail-closed: a device with no v3 genesis record
/// cannot author a presentation and cannot birth a vault.
fn owner_presentation_inputs() -> Result<(Vec<u8>, String, [u8; 32]), dsm::types::error::DsmError> {
    use dsm::types::error::DsmError;
    let seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::invalid_operation("vault publication: wallet locked — no cached seed")
        })?;
    // THE record for the identity this process holds — looked up by the
    // installed genesis id, never "the latest row". Two identities sharing a
    // process (tests, multi-profile) each keep their own row, and recency
    // would hand one identity another's derivation inputs.
    let g_vec = crate::sdk::app_state::AppState::get_genesis_hash().unwrap_or_default();
    let g = <[u8; 32]>::try_from(g_vec.as_slice()).map_err(|_| {
        DsmError::invalid_operation("vault publication: no installed genesis identity")
    })?;
    let g_b32 = crate::util::text_id::encode_base32_crockford(&g);
    let record = crate::storage::client_db::get_genesis_record_by_id(&g_b32)
        .map_err(|e| {
            DsmError::storage(
                format!("vault publication: genesis record read: {e}"),
                None::<std::io::Error>,
            )
        })?
        .ok_or_else(|| {
            DsmError::invalid_operation("vault publication: no genesis record on this device")
        })?;
    Ok((seed.to_vec(), record.network_id, g))
}

/// Build + sign the two publication objects for one vault generation, from
/// the advance's own outcome.
///
/// Reads ONLY `outcome` plus device-local configuration (this runs under the
/// state-machine lock in `pre_write`; `device_head()` would deadlock). The
/// reserves come from `outcome.new_device_state` — what `advance` DERIVED and
/// landed — so the state the anchor commits is the state the root actually
/// holds. `parent_state_commitment` is the caller's edge: the genesis parent
/// at birth, the consumed frontier's `c_n` at close.
fn build_vault_publication_artifacts(
    outcome: &dsm::types::device_state::AdvanceOutcome,
    vault_id: &[u8; 32],
    pair: &dsm::types::device_state::VaultStatePair,
    birth_set_id: &[u8; 32],
    parent_state_commitment: [u8; 32],
) -> Result<VaultPublicationArtifacts, dsm::types::error::DsmError> {
    use dsm::ccb::{
        vault_state_commitment, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy,
        StorageSetMembers, VaultStateV2,
    };
    use dsm::types::error::DsmError;
    use prost::Message;

    let head = &outcome.new_device_state;
    let witness = outcome.vault_state_proof.as_ref().ok_or_else(|| {
        DsmError::invalid_operation(
            "vault publication: the advance produced no vault-state witness — refusing to \
             publish a generation without it",
        )
    })?;
    if witness.vault_id != *vault_id {
        return Err(DsmError::invalid_operation(
            "vault publication: the advance's vault-state witness names a different vault",
        ));
    }
    let generation = witness.sequence;
    let reserve_a = head.vault_reserve(vault_id, &pair.a());
    let reserve_b = head.vault_reserve(vault_id, &pair.b());

    // The storage set the vault is born under, as MEMBERS — the id is derived
    // from them, and it must re-derive to the record's cached id or the record
    // and the published state would name different sets.
    let catalog = crate::sdk::storage_set::StorageSetCatalog::from_env_config().map_err(|e| {
        DsmError::invalid_operation(format!("vault publication: storage-set catalog: {e}"))
    })?;
    let set = catalog.resolve(birth_set_id).ok_or_else(|| {
        DsmError::invalid_operation(
            "vault publication: the vault's storage set is not resolvable through this \
             device's catalog",
        )
    })?;
    let member_ids: Vec<&[u8]> = set
        .members()
        .iter()
        .map(|m| m.member_id.as_bytes())
        .collect();
    let storage_set = StorageSetMembers::new(&member_ids)
        .map_err(|e| DsmError::invalid_operation(format!("vault publication: set members: {e}")))?;
    if dsm::ccb::storage_set_id(&storage_set)
        .map_err(|e| DsmError::invalid_operation(format!("vault publication: set id: {e}")))?
        != *birth_set_id
    {
        return Err(DsmError::invalid_operation(
            "vault publication: resolved set members do not re-derive the birth set id",
        ));
    }

    // The owner's authority position — invariant across every generation this
    // owner authors — and the identity it belongs to.
    let (seed, network_id, g) = owner_presentation_inputs()?;
    let inputs = crate::sdk::identity_presentation::OwnerIdentityInputs {
        network_id: network_id.as_bytes(),
        wallet_index: 0,
        device_slot: 0,
        genesis_version: 3,
    };
    let auth = crate::sdk::identity_presentation::derive_own_authority_context(&seed, inputs)?;
    if auth.g != g {
        return Err(DsmError::invalid_operation(format!(
            "vault publication: re-derived G ({}) does not match the installed genesis id ({}) \
             under network id {:?} (fail closed)",
            crate::util::text_id::encode_base32_crockford(&auth.g),
            crate::util::text_id::encode_base32_crockford(&g),
            network_id,
        )));
    }

    let state = VaultStateV2 {
        owner_genesis_id: auth.g,
        owner_device_id: auth.devid,
        vault_id: *vault_id,
        generation,
        reserve_a,
        reserve_b,
        market_policy: MarketPolicy::beta_constant_product(pair.a(), pair.b())
            .map_err(|e| DsmError::invalid_parameter(format!("vault publication: pair: {e}")))?,
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(pair.fee_bps())
            .map_err(|e| DsmError::invalid_parameter(format!("vault publication: fee: {e}")))?,
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: None,
        parent_state_commitment,
        owner_authority_transition_digest: auth.position,
        storage_set,
        quorum: set.quorum(),
    };
    let state_ccb = state
        .encode()
        .map_err(|e| DsmError::invalid_parameter(format!("vault publication: encode: {e}")))?;
    let c_n = vault_state_commitment(&state)
        .map_err(|e| DsmError::invalid_parameter(format!("vault publication: c_n: {e}")))?;

    let presentation = crate::sdk::identity_presentation::build_own_anchor_presentation(
        &seed, inputs, &auth.g, &c_n,
    )?;
    let presentation_bytes = presentation.encode_to_vec();

    let vn_key = immutable_object_key(dsm::common::domain_tags::TAG_DSM_VAULT_STATE, &state_ccb);
    let pres_key = immutable_object_key(
        dsm::common::domain_tags::TAG_DSM_ANCHOR_PRESENTATION_V1,
        &presentation_bytes,
    );
    Ok(VaultPublicationArtifacts {
        objects: vec![
            (vn_key, state_ccb.clone()),
            (pres_key, presentation_bytes.clone()),
        ],
        c_n,
        state_ccb,
        presentation: presentation_bytes,
    })
}

/// The object keys a vault's BIRTH published, derived from the record's own
/// stored bytes. `None` when the record is absent or pre-dates the blobs —
/// which reads as "not published", failing closed.
pub(crate) fn birth_object_keys(vault_id: &[u8; 32]) -> Option<[String; 2]> {
    let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
        .ok()
        .flatten()?;
    if record.birth_state_ccb.is_empty() || record.birth_presentation.is_empty() {
        return None;
    }
    Some([
        immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_VAULT_STATE,
            &record.birth_state_ccb,
        ),
        immutable_object_key(
            dsm::common::domain_tags::TAG_DSM_ANCHOR_PRESENTATION_V1,
            &record.birth_presentation,
        ),
    ])
}

/// `true` iff both of a vault's birth objects have reached quorum on the
/// vault's birth storage set — the activation boundary: FUNDED locally is not
/// MARKET-ACTIVE until this holds.
pub(crate) fn birth_is_published(vault_id: &[u8; 32]) -> bool {
    let Some(keys) = birth_object_keys(vault_id) else {
        return false;
    };
    keys.iter().all(|k| {
        crate::storage::client_db::frozen_publication_artifact::is_artifact_published(k)
            .unwrap_or(false)
    })
}

/// Compose this device's OWN vault from its stored birth objects: the exact
/// `CCB(V_0)` + `AnchorPresentationV3` the birth published, with every
/// receipted trader generation folded on top. ONE composition path — the
/// owner verifies its own vault exactly the way a stranger does, so the two
/// can never disagree about what the frontier is.
async fn compose_own_vault(
    vault_id: &[u8; 32],
) -> Result<crate::sdk::vault_state_composition::ComposedVaultState, String> {
    use prost::Message as _;
    let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
        .map_err(|e| format!("vault record read failed: {e}"))?
        .ok_or_else(|| "no AMM vault record for this vault on this device".to_string())?;
    if record.birth_state_ccb.is_empty() || record.birth_presentation.is_empty() {
        return Err(
            "the vault record carries no birth state/presentation — reprovision (no legacy \
             upgrade path exists)"
                .to_string(),
        );
    }
    let presentation =
        crate::generated::AnchorPresentationV3::decode(record.birth_presentation.as_slice())
            .map_err(|e| format!("stored birth presentation does not decode: {e}"))?;
    let pair = dsm::types::device_state::VaultStatePair::new(
        record.policy_commit_a,
        record.policy_commit_b,
        record.fee_bps,
    )
    .map_err(|e| format!("vault record pair is not canonical: {e}"))?;
    crate::sdk::vault_state_composition::compose_vault_state(
        vault_id,
        &presentation,
        &record.birth_state_ccb,
        &pair.a(),
        &pair.b(),
        pair.fee_bps(),
    )
    .await
    .map_err(|e| format!("composition failed: {e}"))
}

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
    /// `c_n` of the exact composed state this settlement consumes — the ONE
    /// parent fact; generation, reserves and predicate are members of the
    /// `V_n` it identifies — plus its generation, for the slot claim and the
    /// receipt (both are keyed by sequence).
    parent_binding: [u8; 32],
    parent_sequence: u64,
    fee_bps: u32,
    sigma: [u8; 32],
    settler_devid: [u8; 32],
    /// The vault's birth-bound canonical storage set, from its verified
    /// composition — the set whose register the settlement-slot claim goes to.
    /// Never from local config.
    storage_set_id: [u8; 32],
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
        // The "storage node" every device in these tests shares is a
        // process-global in-memory object store, and vault ids are
        // deterministic in (owner, spec, funding). Without this reset, one
        // test's published pointers and receipts leak into the next test's
        // composition of the SAME vault id — and the settle side, correctly,
        // sees a vault already at a later generation. Each test starts empty.
        crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::reset_dbtc_storage_test_state();
        // Same reasoning for the member fleet: publication state and the
        // settlement-slot register are per-member and process-global, so a
        // previous test's quorum on the SAME deterministic vault id would make
        // a later vault look born, published, or already claimed.
        crate::sdk::storage_io::fake_fleet::reset();
        let _ = crate::storage_utils::set_storage_base_dir(std::path::PathBuf::from(
            "./.dsm_testdata_funded_creation",
        ));
        crate::reset_sdk_context_for_testing();
        crate::sdk::app_state::AppState::reset_memory_for_testing();
        crate::sdk::app_state::AppState::prime_memory_for_testing();
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        // The database must exist BEFORE the identity: `become_device`
        // persists the genesis record the presentation builder reads back.
        crate::storage::client_db::init_database().expect("init db");
        become_device(0x0A);
    }

    /// Install an identity keyed by `seed`, WITHOUT resetting storage.
    ///
    /// Identity is process-global, so a two-device test switches it between
    /// phases. The device heads and DLV managers are per-router, so each side
    /// keeps its own state — which is the boundary that matters: the trader has
    /// no access to the owner's leaves and must work from published artifacts.
    fn become_device(seed: u8) -> (Vec<u8>, [u8; 32]) {
        // A REAL v3 identity: the state-identity cut derives every vault
        // birth's authority chain (GRK → D_0 → T_0) from the wallet seed, so
        // fixture identities are seed-rooted exactly like production ones.
        let wallet_seed = vec![seed; 64];
        let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
        let genesis = dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested(
            &wallet_seed,
            b"dsm-test",
            0,
            0,
            3,
            &aph,
        )
        .expect("v3 genesis");
        let device_id = genesis.devid.to_vec();
        let genesis_hash = genesis.g.to_vec();
        // ONE session secret: the signing authority's cached seed IS the
        // wallet seed (set_binding_key_for_testing writes the same cache the
        // presentation builder reads), so both derive from the same root.
        crate::sdk::signing_authority::clear_binding_key_for_testing();
        let (public_key, _sk) = crate::sdk::signing_authority::derive_signing_keys_for_testing(
            &device_id,
            &genesis_hash,
            &wallet_seed,
        )
        .expect("derive signing keypair");
        crate::sdk::signing_authority::set_binding_key_for_testing(wallet_seed);
        // The persisted genesis record is where the presentation builder reads
        // its derivation inputs back from (network id in particular).
        crate::storage::client_db::store_genesis_record_with_verification(
            &crate::storage::client_db::GenesisRecord {
                genesis_id: crate::util::text_id::encode_base32_crockford(&genesis.g),
                device_id: crate::util::text_id::encode_base32_crockford(&genesis.devid),
                mpc_proof: String::new(),
                device_birth_binding: String::new(),
                merkle_root: crate::util::text_id::encode_base32_crockford(&[0u8; 32]),
                participant_count: 0,
                progress_marker: "genesis".to_string(),
                publication_hash: crate::util::text_id::encode_base32_crockford(&genesis.g),
                storage_nodes: Vec::new(),
                entropy_hash: crate::util::text_id::encode_base32_crockford(&genesis.genesis_nonce),
                protocol_version: "genesis-v3".to_string(),
                hash_chain_proof: None,
                smt_proof: None,
                verification_step: None,
                genesis_nonce: crate::util::text_id::encode_base32_crockford(
                    &genesis.genesis_nonce,
                ),
                genesis_profile: "MnemonicV3".to_string(),
                network_id: "dsm-test".to_string(),
            },
        )
        .expect("store genesis record");
        crate::sdk::app_state::AppState::set_identity_info(
            device_id.clone(),
            public_key.clone(),
            genesis_hash,
            vec![0u8; 32],
        );
        crate::sdk::app_state::AppState::set_has_identity(true);
        (public_key, genesis.devid)
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

    /// PRODUCTION STARTUP: a funded vault survives losing the router entirely.
    ///
    /// The router and its `DLVManager` are DROPPED, and a fresh one is built
    /// from the same database and persisted head — the closest a host test gets
    /// to a cold app start. Then the real `dlv.listOwnedAmmVaults` route runs.
    ///
    /// This is the test that was missing. `rehydrate_all_amm_vaults` was
    /// correct and had coverage, but every one of those tests called it
    /// DIRECTLY, so none could observe that nothing in production did. A
    /// handset showed it first: restart the wallet and the owner's funded,
    /// published vault was gone from the screen.
    #[test]
    #[serial]
    fn a_funded_vault_is_listed_by_a_router_that_never_created_it() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let vault_id;
        let root_before;
        let head_before;
        {
            let r = router();
            r.core_sdk.set_device_head_for_testing(
                crate::sdk::funded_vault_fixture::owner_holding(50_000, 20_000),
            );
            let create = generated::DlvInstantiateV1 {
                spec: Some(generated::DlvSpecV1 {
                    policy_digest: vec![0x5A; 32],
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
                .expect("records")
                .pop()
                .expect("one vault");
            vault_id = rec.vault_id;
            let head = r.core_sdk.device_head().expect("head");
            root_before = head.root();
            head_before = head;
        }

        // A FRESH router. Its DLVManager has never seen this vault.
        let r2 = router();
        r2.core_sdk.set_device_head_for_testing(head_before.clone());

        assert!(
            crate::runtime::get_runtime()
                .block_on(r2.bitcoin_tap.dlv_manager().list_vaults())
                .expect("list_vaults")
                .is_empty(),
            "the fresh router's DLVManager must be EMPTY - if it ever holds this \
             vault, the route is served by a cache and this test proves nothing",
        );

        let q = crate::runtime::get_runtime().block_on(async {
            r2.query(crate::bridge::AppQuery {
                path: "dlv.listOwnedAmmVaults".to_string(),
                params: Vec::new(),
            })
            .await
        });
        assert!(q.success, "list failed: {:?}", q.error_message);
        let listed = decode_summaries(&q.data);
        assert_eq!(
            listed.len(),
            1,
            "the funded vault must be listed after a cold start"
        );
        let got = &listed[0];

        assert_eq!(got.vault_id, vault_id.to_vec(), "same vault id");
        assert_eq!(
            got.token_a,
            pc_a.to_vec(),
            "policy commit A verbatim, never a ticker"
        );
        assert_eq!(
            got.token_b,
            pc_b.to_vec(),
            "policy commit B verbatim, never a ticker"
        );
        assert_eq!(got.reserve_a, 10_000, "reserve A from the encumbered leaf");
        assert_eq!(got.reserve_b, 5_000, "reserve B from the encumbered leaf");
        assert_eq!(got.anchor_sequence, 0, "sequence from the leaves");
        assert_eq!(got.fee_bps, 30);
        assert_eq!(
            got.anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
            "enforcement must survive; defaulting it trades under rules nobody chose",
        );

        // Reading is not writing.
        let head_after = r2.core_sdk.device_head().expect("head after");
        assert_eq!(
            head_after.root(),
            root_before,
            "listing must not move the root"
        );
        assert_eq!(
            crate::storage::client_db::bcr::encode_device_state(&head_after),
            crate::storage::client_db::bcr::encode_device_state(&head_before),
            "listing must not change a single byte of the head",
        );
    }

    /// A leg that is not funded makes the vault UNAVAILABLE, never zero.
    ///
    /// Zero and absent are the same number and completely different facts. A
    /// vault rendered with 0 reserves is quotable, priceable and settleable
    /// against liquidity that was never encumbered.
    #[test]
    #[serial]
    fn a_vault_missing_a_reserve_leg_is_withheld_rather_than_shown_as_zero() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let r = router();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: vec![0x5A; 32],
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

        // The RECORD stays; the LEAVES are gone. Exactly the shape a
        // half-written or tampered state takes.
        let r2 = router();
        r2.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));
        let q = crate::runtime::get_runtime().block_on(async {
            r2.query(crate::bridge::AppQuery {
                path: "dlv.listOwnedAmmVaults".to_string(),
                params: Vec::new(),
            })
            .await
        });
        assert!(q.success, "the route still answers: {:?}", q.error_message);
        assert!(
            decode_summaries(&q.data).is_empty(),
            "a vault whose reserve legs are absent must be WITHHELD, never listed with 0",
        );
    }

    /// Decode the route's newline-separated Base32 summaries.
    fn decode_summaries(data: &[u8]) -> Vec<generated::AmmVaultSummaryV1> {
        // v3 framing: a 0x03 prefix byte, then the Envelope proto.
        let env = generated::Envelope::decode(&data[1..]).expect("envelope");
        let value = match env.payload {
            Some(generated::envelope::Payload::AppStateResponse(r)) => r.value.unwrap_or_default(),
            other => panic!("unexpected payload: {other:?}"),
        };
        value
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let bytes = crate::util::text_id::decode_base32_crockford(l).expect("b32");
                generated::AmmVaultSummaryV1::decode(bytes.as_slice()).expect("summary")
            })
            .collect()
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

        // And the verified state it will settle against — the presentation +
        // `CCB(V_0)` fetched and verified with no access to the owner's
        // leaves: the reserves come OUT of the authenticated state.
        let frontier = composed_frontier(&vault_id);
        assert_eq!(
            (frontier.sequence, frontier.reserves_a, frontier.reserves_b),
            (0, 10_000, 5_000),
            "the trader's verified view is the owner's published birth state"
        );

        let input = 1_000u64;
        let expected_out =
            crate::sdk::routing_path_sdk::constant_product_output(input, 10_000, 5_000, 30)
                .expect("curve output");
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
                state_number: 0,
                parent_binding: frontier.c_n.to_vec(),
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

        // (2) The verified baseline the settling path will read back. Its
        // existence — a P0-P6-verifiable presentation and the exact CCB(V_0)
        // — is the precondition the composition gate enforces.
        let frontier = composed_frontier(&vault_id);
        assert_eq!(
            (frontier.sequence, frontier.reserves_a, frontier.reserves_b),
            (0, 10_000, 5_000),
            "dlv.create must publish a verifiable birth state"
        );

        // (3) Build and sign the RouteCommit the trader settles with. The
        // hop's parent binding must be the c_n the vault-side gate re-derives
        // from its own composition, so it is computed the same way rather
        // than guessed.
        let input = 1_000u64;
        let expected_out =
            crate::sdk::routing_path_sdk::constant_product_output(input, 10_000, 5_000, 30)
                .expect("curve output");
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
                state_number: 0,
                parent_binding: frontier.c_n.to_vec(),
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

        // (15) THE CONSUME-ONCE CLAIM is durably recorded through the production
        // reconcile route, naming the settlement that won generation 0 (written
        // inside the fold's own transaction). This is what lets a DIFFERENT
        // settlement racing the same parent be refused at reconcile — the winner's
        // receipt id occupies `(vault, 0)`, so a foreign receipt id resolves to a
        // typed Conflict rather than a silent double-fold (proven at the claim
        // level in vault_generation_consumption's unit tests).
        let consumer = crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
            .expect("load consumer")
            .expect("generation 0 must be recorded as consumed");
        assert_eq!(
            consumer.source_commitment, receipt.receipt_id,
            "the durable claim must name the settlement that actually consumed the generation"
        );
        assert_eq!(consumer.child_sequence, 1);
    }

    /// Build a GENUINELY FOREIGN, fully valid settlement receipt: a different
    /// trader device (its own genesis/devid/keypair), funded, settling the SAME
    /// owner vault at parent generation 0 with a DISTINCT external commitment `x`.
    /// The receipt is signed against that trader's own post-settle root and
    /// verifies stand-alone (`verify_trader_settlement_receipt` is stateless), so
    /// it is exactly what a second device produces in a cross-partition race — the
    /// case the storage slot-claim cannot prevent and the durable consume-once
    /// claim must catch at reconcile.
    fn build_foreign_receipt(
        vault_id: &[u8; 32],
        pc_in: &[u8; 32],
        pc_out: &[u8; 32],
        x: [u8; 32],
        seed: u8,
    ) -> dsm::dlv::settlement_receipt_leaf::SignedTraderSettlementReceipt {
        use dsm::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
        use dsm::types::operations::{Operation, TransactionMode};
        use dsm::types::token_types::Balance;

        let kp = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[seed; 32])
            .expect("foreign trader keypair");
        let dev = [seed; 32];
        let rel = compute_smt_key(&dev, &dev);
        let init = initial_chain_tip_from_device_ids(&dev, &dev);
        let sign = |op: Operation| -> Operation {
            let sig = dsm::crypto::sphincs::sphincs_sign(
                &kp.secret_key,
                &op.with_cleared_signature().to_bytes(),
            )
            .expect("sign foreign op");
            op.with_signature(sig)
        };

        // Fund the foreign trader with the input asset so its settle can pay it.
        let head = DeviceState::new(dev, dev, kp.public_key.clone(), 64);
        let head = head
            .advance(
                rel,
                dev,
                Operation::Mint {
                    amount: Balance::from_state(10_000, [0u8; 32]),
                    token_id: b"IN".to_vec(),
                    policy_commit: *pc_in,
                    authorized_by: b"self".to_vec(),
                    proof_of_authorization: Vec::new(),
                    message: "seed".into(),
                },
                vec![0x11; 32],
                None,
                &[BalanceDelta {
                    policy_commit: *pc_in,
                    direction: BalanceDirection::Credit,
                    amount: 10_000,
                }],
                Some(init),
                None,
                None,
                None,
            )
            .expect("foreign mint")
            .new_device_state;

        let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(vault_id, &x);
        let (input_amount, output_amount) = (1_000u64, 500u64);
        let settle = sign(Operation::DlvSettle {
            vault_id: vault_id.to_vec(),
            owner_public_key: Vec::new(),
            owner_devid: [0u8; 32],
            owner_genesis: [0u8; 32],
            input_policy_commit: *pc_in,
            output_policy_commit: *pc_out,
            parent_sequence: 0,
            parent_binding: [0u8; 32],
            route_commit_bytes: Vec::new(),
            external_commitment_x: x,
            input_amount,
            output_amount,
            fee_bps: 30,
            sigma: [0u8; 32],
            settler_public_key: kp.public_key.clone(),
            settler_devid: dev,
            settlement_receipt_id: receipt_id,
            signature: Vec::new(),
            mode: TransactionMode::Unilateral,
        });
        let head = head
            .advance(
                rel,
                dev,
                settle,
                vec![0x22; 32],
                None,
                &[
                    BalanceDelta {
                        policy_commit: *pc_in,
                        direction: BalanceDirection::Debit,
                        amount: input_amount,
                    },
                    BalanceDelta {
                        policy_commit: *pc_out,
                        direction: BalanceDirection::Credit,
                        amount: output_amount,
                    },
                ],
                Some(init),
                None,
                None,
                None,
            )
            .expect("foreign settle")
            .new_device_state;

        let key = dsm::dlv::settlement_receipt_leaf::settlement_receipt_key(
            &head.genesis(),
            &head.devid(),
            vault_id,
            &receipt_id,
        );
        let siblings = head
            .inclusion_siblings(&key)
            .expect("receipt leaf siblings");
        let trade = dsm::dlv::settlement_receipt_leaf::SettledTrade {
            x,
            parent_sequence: 0,
            new_sequence: 1,
            input_policy_commit: *pc_in,
            input_amount,
            output_policy_commit: *pc_out,
            output_amount,
        };
        dsm::dlv::settlement_receipt_leaf::sign_trader_settlement_receipt(
            vault_id,
            &receipt_id,
            trade,
            &head.genesis(),
            &head.devid(),
            &head.root(),
            siblings,
            &kp.public_key,
            &kp.secret_key,
        )
        .expect("sign foreign receipt")
    }

    /// INVARIANT 3 at the PRODUCTION reconcile route: two genuinely foreign, fully
    /// valid receipts settle the same vault parent generation; exactly one is
    /// accepted, and the SECOND — driven through `dlv.reconcile` — physically hits
    /// the typed consume-once conflict branch. It leaves NO durable success state
    /// of any kind: no canonical mutation (root unchanged), no reserve mutation, no
    /// change to the consumption row, no success envelope.
    ///
    /// This is exactly the boundary where the old sequence-only idempotence gate
    /// returned a misleading successful no-op (`leaf.sequence >= new_sequence`
    /// was true for the loser too).
    ///
    /// A single device cannot produce two receipts at one parent through the settle
    /// route — the storage slot-claim blocks the second locally — so the second
    /// trader is built directly, which is precisely the cross-partition case the
    /// slot-claim admits it cannot prevent.
    #[test]
    #[serial_test::serial]
    fn reconcile_refuses_a_second_foreign_receipt_at_an_already_consumed_generation() {
        use prost::Message as _;

        install_identity();
        let r = router();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::owner_holding(
                50_000, 20_000,
            ));

        // Fund an owner vault at generation 0.
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
        let vault_id = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault")
            .vault_id;

        // WINNER: trader A settles generation 0. Publish its receipt and reconcile
        // it through the production route — it consumes the generation.
        let x_a = [0xA0u8; 32];
        let receipt_a = build_foreign_receipt(&vault_id, &pc_a, &pc_b, x_a, 0xC1);
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&receipt_a))
            .expect("publish winner receipt");
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(
                    generated::DlvReconcileV1 {
                        vault_id: vault_id.to_vec(),
                        x: x_a.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await
        });
        assert!(
            res.success,
            "winner reconcile failed: {:?}",
            res.error_message
        );

        // Snapshot every durable surface AFTER the winner consumed the generation.
        let after_winner = r.core_sdk.device_head().expect("head");
        let root_before = after_winner.root();
        let (res_a_before, res_b_before) = (
            after_winner.vault_reserve(&vault_id, &pc_a),
            after_winner.vault_reserve(&vault_id, &pc_b),
        );
        let claim_before = crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
            .expect("load claim")
            .expect("generation 0 is consumed by the winner");
        assert_eq!(
            claim_before.source_commitment, receipt_a.receipt_id,
            "the winner's receipt id owns generation 0"
        );

        // LOSER: trader B is a different device that also settled generation 0
        // (a cross-partition race the slot-claim could not prevent). Its receipt is
        // fully valid and fetch-verifies — but reconcile must REFUSE it.
        let x_b = [0xB0u8; 32];
        let receipt_b = build_foreign_receipt(&vault_id, &pc_a, &pc_b, x_b, 0xC2);
        assert_ne!(
            receipt_b.receipt_id, receipt_a.receipt_id,
            "the two settlements are distinct"
        );
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&receipt_b))
            .expect("publish loser receipt");

        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(
                    generated::DlvReconcileV1 {
                        vault_id: vault_id.to_vec(),
                        x: x_b.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await
        });

        // (1) REFUSED with a typed error — never a successful no-op.
        assert!(
            !res.success,
            "the second settlement at an already-consumed generation MUST be refused, \
             not folded or reported as a successful no-op"
        );
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("already consumed"),
            "the refusal must name the already-consumed generation: {:?}",
            res.error_message
        );

        // (2) NO canonical mutation, NO reserve mutation.
        let after_loser = r.core_sdk.device_head().expect("head");
        assert_eq!(
            after_loser.root(),
            root_before,
            "the refused fold left the device root unchanged"
        );
        assert_eq!(
            (
                after_loser.vault_reserve(&vault_id, &pc_a),
                after_loser.vault_reserve(&vault_id, &pc_b)
            ),
            (res_a_before, res_b_before),
            "the refused fold moved no reserve"
        );

        // (3) NO consumption-row change: generation 0 still belongs to the winner;
        // the loser wrote no durable success marker of any kind.
        let claim_after = crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
            .expect("load claim")
            .expect("generation 0 is still consumed");
        assert_eq!(
            claim_after.source_commitment, receipt_a.receipt_id,
            "the loser must not overwrite or duplicate the winner's consumption claim"
        );

        // (4) REPLAY OF THE WINNER remains idempotent; REPLAY OF THE LOSER stays
        // refused — the two never collapse.
        let winner_again = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(
                    generated::DlvReconcileV1 {
                        vault_id: vault_id.to_vec(),
                        x: x_a.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await
        });
        assert!(winner_again.success, "winner replay must stay idempotent");
        assert_eq!(
            r.core_sdk.device_head().expect("head").root(),
            root_before,
            "winner replay moves nothing"
        );
        let loser_again = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.reconcile".to_string(),
                args: pack(
                    generated::DlvReconcileV1 {
                        vault_id: vault_id.to_vec(),
                        x: x_b.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await
        });
        assert!(
            !loser_again.success,
            "the loser's replay must remain refused after the winner is committed"
        );
    }

    /// One trader's full production settle against `vault_id` at generation
    /// `seq`, whose reserves the trader believes to be `(ra, rb)`: mirror the
    /// vault, bind a hop to `(seq, reserves_digest, anchor_digest)`, sign the
    /// RouteCommit, publish X + pointer, and `dlv.unlockRouted`. `expected_out`
    /// is what the trader claims the curve pays; a well-behaved trader passes
    /// `constant_product_output(input, ra, rb, 30)`, and a probe may lie.
    /// Returns the route result and the external commitment `x`.
    ///
    /// The caller must have switched process identity to this trader
    /// (`become_device`) and installed the trader's head on `router`.
    #[allow(clippy::too_many_arguments)]
    fn trader_settles(
        router: &AppRouterImpl,
        trader_pk: &[u8],
        trader_did: &[u8; 32],
        vault_id: &[u8; 32],
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
        seq: u64,
        (ra, rb): (u64, u64),
        input: u64,
        expected_out: u64,
        nonce: u8,
    ) -> (AppResult, [u8; 32]) {
        use prost::Message as _;

        let pair = generated::RoutingPairRequest {
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            router
                .invoke(AppInvoke {
                    method: "route.syncVaultsForPair".to_string(),
                    args: pack(pair.encode_to_vec()),
                })
                .await
        });
        assert!(res.success, "sync failed: {:?}", res.error_message);

        // The parent this trade consumes, exactly as the vault-side gate will
        // re-derive it: the composed frontier's c_n.
        let frontier = composed_frontier(vault_id);
        assert_eq!(
            (frontier.sequence, frontier.reserves_a, frontier.reserves_b),
            (seq, ra, rb),
            "the caller's expected frontier must be the composed one"
        );
        let trader_sk = crate::sdk::signing_authority::current_secret_key().expect("trader sk");
        let mut rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: vec![nonce; 32],
            total_fee_bps: 30,
            initiator_public_key: trader_pk.to_vec(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vault_id.to_vec(),
                token_in: pc_a.to_vec(),
                token_out: pc_b.to_vec(),
                input_amount_u128: (input as u128).to_be_bytes().to_vec(),
                expected_output_amount_u128: (expected_out as u128).to_be_bytes().to_vec(),
                state_number: seq,
                parent_binding: frontier.c_n.to_vec(),
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
                    trader_pk,
                    &trader_sk,
                    "lp-offline",
                ),
            )
            .expect("publish anchor + pointers");

        let settle = generated::DlvUnlockRoutedV1 {
            vault_id: vault_id.to_vec(),
            device_id: trader_did.to_vec(),
            route_commit_bytes: rc.encode_to_vec(),
            unlocker_public_key: trader_pk.to_vec(),
            signature: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            router
                .invoke(AppInvoke {
                    method: "dlv.unlockRouted".to_string(),
                    args: pack(settle.encode_to_vec()),
                })
                .await
        });
        (res, x)
    }

    /// The vault's full composed frontier, as ANY verifier derives it: the
    /// birth presentation + `CCB(V_0)` through P0-P6, plus every verified
    /// trader generation folded on.
    fn composed_frontier(
        vault_id: &[u8; 32],
    ) -> crate::sdk::vault_state_composition::ComposedVaultState {
        crate::runtime::get_runtime()
            .block_on(compose_own_vault(vault_id))
            .expect("the vault composes from its published baseline")
    }

    /// Every immutable object key the fleet has seen a PUT for. The terminal
    /// set's keys are content-derived, so tests read them back from the
    /// delivery log rather than re-deriving the terminal state by hand.
    fn immutable_keys_in_fleet() -> Vec<String> {
        let mut keys: Vec<String> = crate::sdk::storage_io::fake_fleet::put_log()
            .into_iter()
            .filter(|(_, key, _)| key.starts_with("immutable::"))
            .map(|(_, key, _)| key)
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// The composed state as the production QUOTE side sees it, reduced to
    /// `(sequence, reserve_a, reserve_b)`.
    fn composed(vault_id: &[u8; 32], _pc_a: &[u8; 32], _pc_b: &[u8; 32]) -> (u64, u64, u64) {
        let c = composed_frontier(vault_id);
        (c.sequence, c.reserves_a, c.reserves_b)
    }

    fn reconcile(owner: &AppRouterImpl, vault_id: &[u8; 32], x: &[u8; 32]) -> AppResult {
        use prost::Message as _;
        crate::runtime::get_runtime().block_on(async {
            owner
                .invoke(AppInvoke {
                    method: "dlv.reconcile".to_string(),
                    args: pack(
                        generated::DlvReconcileV1 {
                            vault_id: vault_id.to_vec(),
                            x: x.to_vec(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await
        })
    }

    /// INVARIANT 2 — DELEGATED LIQUIDITY. The LP funds a vault and disappears.
    /// The market advances it through THREE generations (0→1→2→3), three
    /// independent traders settling through the production route, with NO owner
    /// signature or participation on any transition — each generation consumes
    /// exactly one parent and the reserves stay conserved. When the LP returns,
    /// its local state reconciles to the already-final generation, in order,
    /// without being debited a second time; a fold against a non-current
    /// generation is refused; replay is idempotent.
    ///
    /// The settle side achieves this by settling against the COMPOSED vault
    /// state — the owner's seq-0 baseline proof plus every verified trader
    /// receipt folded on (the same authority the quote side already trusts) —
    /// rather than demanding an owner-published proof at every generation.
    /// Its load-bearing guard is `composed.sequence == hop.vault_state_anchor_seq`:
    /// a hop bound to a generation the vault has moved past (already consumed)
    /// or has not reached (unproven) is refused, so a trader can neither
    /// re-settle a consumed parent nor pre-settle a future one.
    #[test]
    #[serial]
    fn lp_offline_market_advances_three_generations_and_lp_reconciles_each_once() {
        use prost::Message as _;

        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let cp = |input: u64, ra: u64, rb: u64| -> u64 {
            crate::sdk::routing_path_sdk::constant_product_output(input, ra, rb, 30)
                .expect("curve output")
        };

        // ── OWNER funds a Required-policy vault at generation 0, advertises it,
        //    and then goes OFFLINE (no further owner action until the end). ─────
        let (_owner_pk, _owner_did) = become_device(0x41);
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
        let vault_id = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault")
            .vault_id;
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: vec![0x5Au8; 32],
            unlock_spec_key: "sofi/spec/lp-offline".to_string(),
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
        let owner_spendable_before = {
            let h = owner.core_sdk.device_head().expect("owner head");
            (h.balance(&pc_a), h.balance(&pc_b))
        };
        assert_eq!(owner_spendable_before, (40_000, 15_000));

        // ── THE MARKET, WITH THE LP GONE: three traders, three generations. ────
        // Each trader settles against the reserves the COMPOSED state says the
        // vault holds at that generation — nothing the owner published past 0.
        let mut reserves = (10_000u64, 5_000u64);
        let inputs = [1_000u64, 700, 400];
        let mut xs: Vec<[u8; 32]> = Vec::new();
        for (i, &input) in inputs.iter().enumerate() {
            let gen = i as u64;
            let seed = 0x51 + i as u8;
            let (tpk, tdid) = become_device(seed);
            let trader = named_router(&format!("trader{i}"));
            trader.core_sdk.set_device_head_for_testing(
                crate::sdk::funded_vault_fixture::device_holding(0xD2 + i as u8, 5_000, 0),
            );
            let before = trader.core_sdk.device_head().expect("trader head");
            let (ba, bb) = (before.balance(&pc_a), before.balance(&pc_b));

            // The composed state must have reached this generation with the
            // reserves the previous settlements imply — the fold IS the vault.
            assert_eq!(
                composed(&vault_id, &pc_a, &pc_b),
                (gen, reserves.0, reserves.1),
                "composition must reach generation {gen} before trader {i} settles"
            );

            let out = cp(input, reserves.0, reserves.1);
            let (res, x) = trader_settles(
                &trader,
                &tpk,
                &tdid,
                &vault_id,
                &pc_a,
                &pc_b,
                gen,
                reserves,
                input,
                out,
                0x20 + i as u8,
            );
            assert!(
                res.success,
                "trader {i} must settle generation {gen} -> {} with the LP offline: {:?}",
                gen + 1,
                res.error_message
            );
            let after = trader.core_sdk.device_head().expect("trader head");
            assert_eq!(
                after.balance(&pc_a),
                ba - input,
                "trader {i} paid its input"
            );
            assert_eq!(
                after.balance(&pc_b),
                bb + out,
                "trader {i} took the curve's output"
            );
            let receipt = crate::runtime::get_runtime()
                .block_on(
                    crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x),
                )
                .expect("receipt published");
            assert_eq!(
                (receipt.trade.parent_sequence, receipt.trade.new_sequence),
                (gen, gen + 1),
                "each generation consumes exactly one parent"
            );
            reserves = (reserves.0 + input, reserves.1 - out);
            xs.push(x);
        }
        let final_reserves = reserves;
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (3, final_reserves.0, final_reserves.1),
            "the market moved the vault to generation 3 without the LP"
        );

        // ── STALE AND FUTURE HOPS ARE REFUSED (the delegation guard). ─────────
        // A hop bound BEHIND the composed generation (parent already consumed)…
        {
            let (tpk, tdid) = become_device(0x61);
            let probe = named_router("probe-behind");
            probe.core_sdk.set_device_head_for_testing(
                crate::sdk::funded_vault_fixture::device_holding(0xE1, 5_000, 0),
            );
            let (res, _) = trader_settles(
                &probe,
                &tpk,
                &tdid,
                &vault_id,
                &pc_a,
                &pc_b,
                1,
                (11_000, 5_000 - cp(1_000, 10_000, 5_000)),
                300,
                cp(300, 11_000, 5_000 - cp(1_000, 10_000, 5_000)),
                0x31,
            );
            // Refused by the delegation guard — and, as defense in depth, by the
            // AMM re-simulation against the composed reserves and by the
            // first-writer slot claim even if the guard were absent. Only the
            // outcome is pinned here; the guard's own necessity is proven by the
            // AHEAD probe below, which nothing else catches.
            assert!(
                !res.success,
                "a hop at an already-consumed generation must be refused"
            );
        }
        // …and a hop bound AHEAD of it (pre-settling a generation that does not
        // exist), even one whose amounts are computed against the CURRENT
        // reserves so the AMM re-simulation would pass. Without the sequence
        // guard this settles and emits a receipt naming a parent it never
        // consumed — a self-credit no owner fold can ever honour.
        {
            let (tpk, tdid) = become_device(0x62);
            let probe = named_router("probe-ahead");
            probe.core_sdk.set_device_head_for_testing(
                crate::sdk::funded_vault_fixture::device_holding(0xE2, 5_000, 0),
            );
            let out_now = cp(300, final_reserves.0, final_reserves.1);
            let (res, _) = trader_settles(
                &probe,
                &tpk,
                &tdid,
                &vault_id,
                &pc_a,
                &pc_b,
                5,
                final_reserves,
                300,
                out_now,
                0x32,
            );
            assert!(
                !res.success,
                "a hop bound to a future generation must be refused"
            );
            assert!(
                res.error_message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("generation"),
                "refusal names the generation mismatch: {:?}",
                res.error_message
            );
            let h = probe.core_sdk.device_head().expect("probe head");
            assert_eq!(h.balance(&pc_a), 5_000, "the refused probe moved no value");
        }

        // ── THE LP RETURNS. Nothing was folded while it was away. ─────────────
        let _ = become_device(0x41);
        let back = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            (
                back.vault_reserve(&vault_id, &pc_a),
                back.vault_reserve(&vault_id, &pc_b)
            ),
            (10_000, 5_000),
            "the owner's own reserve leaves are untouched until it folds"
        );
        assert_eq!(
            back.vault_reserve_entry(&vault_id, &pc_a)
                .expect("leg")
                .sequence,
            0
        );

        // Folding out of order is REFUSED: generation 1 is not current.
        let res = reconcile(&owner, &vault_id, &xs[1]);
        assert!(
            !res.success,
            "folding generation 1->2 before 0->1 must be refused (parent not current)"
        );
        let h = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            h.vault_reserve(&vault_id, &pc_a),
            10_000,
            "a refused fold moved nothing"
        );

        // In order, each fold consumes exactly the next parent, once.
        let mut expect = (10_000u64, 5_000u64);
        for (i, &input) in inputs.iter().enumerate() {
            let out = cp(input, expect.0, expect.1);
            let res = reconcile(&owner, &vault_id, &xs[i]);
            assert!(res.success, "fold {i} failed: {:?}", res.error_message);
            expect = (expect.0 + input, expect.1 - out);
            let h = owner.core_sdk.device_head().expect("owner head");
            assert_eq!(
                (
                    h.vault_reserve(&vault_id, &pc_a),
                    h.vault_reserve(&vault_id, &pc_b)
                ),
                expect,
                "after fold {i} the reserves reflect exactly generations 0..={i}"
            );
            assert_eq!(
                h.vault_reserve_entry(&vault_id, &pc_a)
                    .expect("leg")
                    .sequence,
                i as u64 + 1,
                "each fold advances the generation by exactly one"
            );
            let consumer =
                crate::storage::client_db::load_vault_generation_consumer(&vault_id, i as u64)
                    .expect("load")
                    .expect("generation consumed");
            assert_eq!(
                consumer.source_commitment,
                dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&vault_id, &xs[i]),
                "generation {i} is recorded as consumed by trader {i}'s settlement"
            );
        }
        assert_eq!(
            expect, final_reserves,
            "the LP's reconciled reserves equal the market's composed state"
        );

        // NO SECOND DEBIT: the LP's spendable balance never moved — the fee
        // accrued inside the reserves, the settlements moved reserves only.
        let h = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            (h.balance(&pc_a), h.balance(&pc_b)),
            owner_spendable_before,
            "reconciling already-final generations must not charge the LP"
        );

        // REPLAY is idempotent: same receipt again, nothing moves.
        let root = h.root();
        let res = reconcile(&owner, &vault_id, &xs[2]);
        assert!(res.success, "replaying the last fold must not error");
        assert_eq!(owner.core_sdk.device_head().expect("head").root(), root);
    }
    // ── CLOSE / WITHDRAWAL ───────────────────────────────────────────────────
    // Invariant 4 at the ROUTE. The core arm proves the mutation is unforgeable;
    // these prove the route that drives it: what the owner gets back, when the
    // close is allowed to run at all, and what happens when it is interrupted.

    fn close(owner: &AppRouterImpl, vault_id: &[u8; 32]) -> AppResult {
        use prost::Message as _;
        crate::runtime::get_runtime().block_on(async {
            owner
                .invoke(AppInvoke {
                    method: "dlv.close".to_string(),
                    args: pack(
                        generated::DlvCloseV1 {
                            vault_id: vault_id.to_vec(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await
        })
    }

    /// The vault's reserve LEAVES as the owner's head holds them, as
    /// `(amount_a, amount_b, generation)`. Absence is an assertion failure, not
    /// a zero: a deleted leaf and an emptied one are different vaults.
    fn leaves(
        owner: &AppRouterImpl,
        vault_id: &[u8; 32],
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
    ) -> (u64, u64, u64) {
        let h = owner.core_sdk.device_head().expect("owner head");
        let a = h
            .vault_reserve_entry(vault_id, pc_a)
            .expect("leg A leaf present");
        let b = h
            .vault_reserve_entry(vault_id, pc_b)
            .expect("leg B leaf present");
        assert_eq!(a.sequence, b.sequence, "the legs must share a generation");
        (a.amount, b.amount, a.sequence)
    }

    /// The member ids of the set a vault was BORN under, resolved the way
    /// production resolves it: by re-hashing the catalog's entries against the
    /// id in the vault's own record, never by assuming the configured fleet.
    fn vault_storage_members(vault_id: &[u8; 32]) -> Vec<String> {
        let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
            .expect("record read")
            .expect("the owner has a record for this vault");
        crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .resolve(&record.storage_set_id)
            .expect("the vault's birth set resolves through this device's catalog")
            .members()
            .iter()
            .map(|m| m.member_id.clone())
            .collect()
    }

    fn spendable(owner: &AppRouterImpl, pc_a: &[u8; 32], pc_b: &[u8; 32]) -> (u64, u64) {
        let h = owner.core_sdk.device_head().expect("owner head");
        (h.balance(pc_a), h.balance(pc_b))
    }

    /// Fund a vault, let ONE trader move it a generation, and (optionally) fold
    /// that settlement back. Returns `(vault_id, reserves_now, x)` — `x` names
    /// the settlement, so a caller that skipped the fold can perform it later.
    fn vault_after_one_trade(
        owner: &AppRouterImpl,
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
        fold: bool,
    ) -> ([u8; 32], (u64, u64), [u8; 32]) {
        use prost::Message as _;
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            owner, pc_a, pc_b, 10_000, 5_000,
        );
        // Advertise it: a trader discovers vaults through the routing index, so
        // an unadvertised vault is one no trader can settle against.
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: vec![0x5Au8; 32],
            unlock_spec_key: "sofi/spec/close".to_string(),
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
        assert!(res.success, "advertise failed: {:?}", res.error_message);
        let out = crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
            .expect("curve output");
        let (tpk, tdid) = become_device(0x51);
        let trader = named_router("trader");
        trader.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD2, 5_000, 0),
        );
        let (res, x) = trader_settles(
            &trader,
            &tpk,
            &tdid,
            &vault_id,
            pc_a,
            pc_b,
            0,
            (10_000, 5_000),
            1_000,
            out,
            0x20,
        );
        assert!(res.success, "trader settle failed: {:?}", res.error_message);
        let _ = become_device(0x41);
        if fold {
            let res = reconcile(owner, &vault_id, &x);
            assert!(res.success, "owner fold failed: {:?}", res.error_message);
        }
        (vault_id, (11_000, 5_000 - out), x)
    }

    /// INVARIANT 4 — WITHDRAWAL, THE WHOLE ROUND TRIP.
    ///
    /// Value delegated to a vault comes back to the owner's SPENDABLE balance
    /// exactly, at the leaf amounts of the generation the market actually
    /// reached — not the amounts it was funded with, and not amounts the caller
    /// states (the request names only the vault). The vault then dies: its
    /// leaves stay PRESENT at zero one generation on, so the id can never be
    /// refunded or reused; its five terminal objects are frozen and at quorum;
    /// and a second close is refused.
    ///
    /// The pairing is the point. "Value returned" alone would pass for a close
    /// that left a live vault behind, and "vault dead" alone would pass for one
    /// that burned the liquidity.
    #[test]
    #[serial]
    fn closing_a_traded_vault_returns_exactly_the_leaf_reserves_and_kills_the_vault() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );

        let (vault_id, reserves, _x) = vault_after_one_trade(&owner, &pc_a, &pc_b, true);
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (reserves.0, reserves.1, 1),
            "the fold left the vault at generation 1 with the traded reserves"
        );
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (1, reserves.0, reserves.1),
            "and the market sees the same generation"
        );
        let before = spendable(&owner, &pc_a, &pc_b);
        assert_eq!(before, (40_000, 15_000), "funding is still delegated");

        let res = close(&owner, &vault_id);
        assert!(res.success, "close failed: {:?}", res.error_message);

        // THE RETURN IS EXACT — the leaf amounts, both legs, nothing rounded.
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (before.0 + reserves.0, before.1 + reserves.1),
            "the close credits exactly what the leaves held"
        );
        // Stated as the round trip: everything funded came back, plus what the
        // market added and minus what it took.
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (51_000, 20_000 - (5_000 - reserves.1)),
            "delegation is a loop: funded out, traded, withdrawn back"
        );

        // THE VAULT IS DEAD — but its leaves are still there, at zero.
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (0, 0, 2),
            "closing ends the leaves at 0 @ K+1: present, never deleted"
        );
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (2, 0, 0),
            "the market composes the vault's death from its published terminal set"
        );

        // The terminal objects of the CLOSING generation — the terminal
        // `CCB(V_n)` and its presentation — at quorum. Their keys are
        // content-derived, so they are read back from the delivery log: the
        // birth published two immutable objects, the close two more.
        let keys = immutable_keys_in_fleet();
        assert_eq!(
            keys.len(),
            4,
            "birth + terminal = four immutable objects, got {keys:?}"
        );
        for key in &keys {
            assert!(
                crate::storage::client_db::frozen_publication_artifact::is_artifact_published(key)
                    .expect("artifact state"),
                "immutable object {key} must have reached quorum"
            );
            assert!(
                crate::sdk::storage_io::fake_fleet::any_member_holding(key).is_some(),
                "…and the fleet must actually hold {key}"
            );
        }

        // A SECOND CLOSE IS REFUSED, and moves nothing.
        let after = spendable(&owner, &pc_a, &pc_b);
        let res = close(&owner, &vault_id);
        assert!(!res.success, "a closed vault cannot be closed again");
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("already closed"),
            "the refusal says the vault is already closed: {:?}",
            res.error_message
        );
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            after,
            "the refused second close credited nothing"
        );

        // Nothing is left for recovery to finish.
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("resume pass");
        assert_eq!(resumed, 0, "a committed close leaves no unfinished intent");
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            after,
            "and the resume pass credited nothing"
        );
    }

    /// THE FRONTIER GATE. A close consumes the CURRENT composed generation, so
    /// an owner holding a stale view cannot close: it would drain amounts the
    /// market has already moved past, at a parent a trader may still be
    /// settling against.
    ///
    /// The gate is a SEQUENCING rule, not a lock — the second half proves the
    /// same vault closes cleanly once the outstanding settlement is folded.
    #[test]
    #[serial]
    fn a_close_is_refused_while_a_settlement_is_unreconciled() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );

        // Traded, NOT folded: the owner's leaves say generation 0, the market
        // says generation 1.
        let (vault_id, reserves, x) = vault_after_one_trade(&owner, &pc_a, &pc_b, false);
        assert_eq!(leaves(&owner, &vault_id, &pc_a, &pc_b), (10_000, 5_000, 0));
        assert_eq!(composed(&vault_id, &pc_a, &pc_b).0, 1);

        let res = close(&owner, &vault_id);
        assert!(!res.success, "a stale close must be refused");
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("moved past"),
            "the refusal names the frontier: {:?}",
            res.error_message
        );
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "the refused close moved no reserves"
        );
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (40_000, 15_000),
            "and credited nothing"
        );

        // A close refused at the gate is refused BEFORE anything durable: no
        // intent, so nothing for a later sweep to pick up and finish.
        let pending = crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
            .expect("intent read");
        assert!(
            pending.is_none(),
            "a close refused at the gate never records an intent"
        );

        // SEQUENCING, NOT LOCKING. Fold the outstanding settlement and the SAME
        // vault closes, returning the reserves of the generation the market
        // actually reached — the ones the refused close would have missed.
        let res = reconcile(&owner, &vault_id, &x);
        assert!(res.success, "fold failed: {:?}", res.error_message);
        let res = close(&owner, &vault_id);
        assert!(
            res.success,
            "once folded, the same vault must close: {:?}",
            res.error_message
        );
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (40_000 + reserves.0, 15_000 + reserves.1),
            "the close returns the TRADED reserves, not the funded ones"
        );
        assert_eq!(leaves(&owner, &vault_id, &pc_a, &pc_b), (0, 0, 2));
    }

    /// A CONTESTED PARENT. Exclusivity over a generation belongs to the quorum
    /// register, not to the owner: if a trader's claim is already at quorum on
    /// this parent, the close loses and must move nothing. The intent is
    /// ABANDONED so no later sweep can resurrect a close whose parent someone
    /// else consumed.
    ///
    /// The contesting claim is signed by a different device and submitted
    /// straight to the fleet — the register's own validity rules are the
    /// storage node's tests; what is proven here is the close's reaction to
    /// losing.
    #[test]
    #[serial]
    fn a_contested_parent_refuses_the_close_and_moves_nothing() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &owner, &pc_a, &pc_b, 10_000, 5_000,
        );
        let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
            .expect("record read")
            .expect("the owner has a record");

        // Another contestant takes generation 0 first, at quorum.
        let set = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .resolve(&record.storage_set_id)
            .expect("the vault's birth set resolves through this device's catalog")
            .clone();
        let (rival_pk, _rival_did) = become_device(0x71);
        let rival_sk = crate::sdk::signing_authority::current_secret_key().expect("rival sk");
        let envelope = dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(
            &dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
                vault_id,
                parent_sequence: 0,
                x: [0x99u8; 32],
                claimant_public_key: rival_pk,
                storage_set_id: record.storage_set_id,
            },
            &rival_sk,
        )
        .expect("rival signs its claim");
        let fanout = crate::sdk::storage_io::fake_fleet::claim(&set, &envelope);
        let accepted = fanout
            .outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o.result,
                    crate::sdk::storage_node_sdk::MemberClaimResult::Accepted
                )
            })
            .count();
        assert!(
            accepted as u32 >= set.quorum(),
            "the rival claim must reach quorum before the owner tries to close"
        );

        let _ = become_device(0x41);
        let res = close(&owner, &vault_id);
        assert!(!res.success, "the close must lose a contested parent");
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("another trade holds this vault generation"),
            "the refusal names the contest: {:?}",
            res.error_message
        );
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "a lost contest moves no reserves"
        );
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (40_000, 15_000),
            "and credits nothing"
        );
        let intent = crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
            .expect("intent read")
            .expect("the close recorded an intent before claiming");
        assert_eq!(
            intent.state,
            crate::storage::client_db::dlv_close_intent::CloseIntentState::Abandoned,
            "a lost contest abandons the intent so no sweep can resurrect it"
        );
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("resume pass");
        assert_eq!(resumed, 0, "and the resume pass leaves it abandoned");
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "the vault stays open and funded — the safe direction"
        );
    }

    /// AN INTERRUPTED CLOSE IS FINISHED BY THE RESUME PASS, WITH THE SAME BYTES.
    ///
    /// The fleet is unreachable when the owner closes, so the parent claim
    /// cannot reach quorum. That is the reversible half of the close: no value
    /// moves, and the intent stays PREPARED rather than being abandoned —
    /// abandoning a transient failure would strand the vault forever.
    ///
    /// When the fleet comes back the resume pass submits the SAME claim
    /// envelope, commits the canonical close, and publishes the terminal set.
    ///
    /// What the digest assertions prove, precisely: every claim attempt before
    /// and after the outage carried ONE envelope, and it is the one frozen with
    /// the intent. That is the property the register compares — a claimant is
    /// its exact bytes, so an envelope differing in `x`, in the storage set, in
    /// the claimant key, or merely in field order would lose the slot it
    /// already held.
    ///
    /// What they deliberately do NOT prove: that the bytes were read from disk
    /// rather than reconstructed. SPHINCS+ signing here is deterministic
    /// (`R = H(sk_prf || m)`, dsm-sphincs `sig_randomizer`), so rebuilding the
    /// same body with the same key yields byte-identical bytes and no
    /// wire-level assertion can separate the two. That rule is enforced
    /// STRUCTURALLY instead: `claim_settlement_slot` accepts only a
    /// `FrozenClaimEnvelope`, whose single constructor loads already-retained
    /// bytes, so the resume path has no way to build or sign one. Claiming this
    /// test proves provenance would be claiming more than it observes.
    #[test]
    #[serial]
    fn an_interrupted_close_is_completed_by_the_resume_pass_with_identical_bytes() {
        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &owner, &pc_a, &pc_b, 10_000, 5_000,
        );
        assert!(
            birth_is_published(&vault_id),
            "the vault must be born and published before this test unplugs the fleet"
        );

        // The fleet goes away mid-close. The members are the vault's OWN —
        // read from the set it was born under — because a hardcoded member name
        // that matches nothing fails nothing, and the test would then assert a
        // refusal against a fleet that was never down.
        let members = vault_storage_members(&vault_id);
        assert!(
            members.len() >= 2,
            "this test needs a set whose quorum can actually be lost, got {members:?}"
        );
        for m in &members {
            crate::sdk::storage_io::fake_fleet::fail_member(m);
        }
        let res = close(&owner, &vault_id);
        assert!(
            !res.success,
            "a close that cannot claim its parent must stop"
        );
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("exclusive use"),
            "the refusal names the claim: {:?}",
            res.error_message
        );
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "nothing moved before the claim"
        );
        assert_eq!(spendable(&owner, &pc_a, &pc_b), (40_000, 15_000));
        let intent = crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
            .expect("intent read")
            .expect("intent recorded");
        assert_eq!(
            intent.state,
            crate::storage::client_db::dlv_close_intent::CloseIntentState::PreparedClose,
            "an unreachable fleet is transient: the close stays PREPARED, never abandoned"
        );
        // The retained envelope, from the one place that holds it.
        let frozen_claim =
            crate::storage::client_db::settlement_slot_claim_local::get_frozen_claim(
                &vault_id,
                0,
                &intent.x_close,
            )
            .expect("retention read")
            .expect("the close retained its claim envelope before going out");

        // The fleet returns; the sweep finishes what the owner started.
        for m in &members {
            crate::sdk::storage_io::fake_fleet::heal_member(m);
        }
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("resume pass");
        assert_eq!(
            resumed, 1,
            "the interrupted close is completed exactly once"
        );

        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (50_000, 20_000),
            "the recovered close returns the full delegation"
        );
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (0, 0, 1),
            "and ends the leaves at 0 @ K+1"
        );
        assert_eq!(
            crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
                .expect("intent read")
                .expect("intent")
                .state,
            crate::storage::client_db::dlv_close_intent::CloseIntentState::CanonicalCloseCommitted,
        );

        // ONE ENVELOPE ACROSS THE OUTAGE, and it is the frozen one. The
        // register identifies a claimant BY these bytes, so this is the
        // property that decides whether the resumed close keeps the slot it
        // already holds.
        let claim_digests: std::collections::BTreeSet<[u8; 32]> =
            crate::sdk::storage_io::fake_fleet::put_log()
                .into_iter()
                .filter(|(_, key, _)| key.starts_with("slot:"))
                .map(|(_, _, digest)| digest)
                .collect();
        assert_eq!(
            claim_digests.len(),
            1,
            "every claim attempt, before and after the outage, carried one envelope"
        );
        assert_eq!(
            claim_digests.into_iter().next(),
            Some(*blake3::hash(&frozen_claim).as_bytes()),
            "…and that envelope is the one frozen with the intent"
        );

        // The terminal set published, and each content-addressed object was
        // PUT with exactly one content digest across every attempt.
        let terminal = immutable_keys_in_fleet();
        assert!(
            terminal.len() >= 2,
            "the terminal V_n and presentation must both have been delivered"
        );
        for key in &terminal {
            assert!(
                crate::storage::client_db::frozen_publication_artifact::is_artifact_published(key)
                    .expect("artifact state"),
                "terminal object {key} must have reached quorum after recovery"
            );
            let digests: std::collections::BTreeSet<[u8; 32]> =
                crate::sdk::storage_io::fake_fleet::put_log()
                    .into_iter()
                    .filter(|(_, k, _)| k == key)
                    .map(|(_, _, d)| d)
                    .collect();
            assert_eq!(
                digests.len(),
                1,
                "{key} was republished from frozen bytes, never re-signed"
            );
        }

        // A second pass has nothing left to do.
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("second resume pass");
        assert_eq!(resumed, 0);
        assert_eq!(spendable(&owner, &pc_a, &pc_b), (50_000, 20_000));
    }

    /// A CLOSED VAULT IS NOT A MARKET.
    ///
    /// After withdrawal the vault's proven reserves are zero at generation K+1.
    /// A trader presenting a hop that names the reserves the vault held BEFORE
    /// the close is settling against liquidity nobody backs — and would credit
    /// itself an output from a vault that holds nothing.
    ///
    /// The probe syncs while the vault is still alive, so it holds the vault in
    /// its own DLVManager and is refused on the STATE, not on ignorance of the
    /// vault's existence. Refusal is asserted together with the probe's balance:
    /// a refusal that still moved value would pass the first assertion alone.
    #[test]
    #[serial]
    fn a_closed_vault_cannot_be_traded() {
        use prost::Message as _;

        install_identity();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );
        let (vault_id, reserves, _x) = vault_after_one_trade(&owner, &pc_a, &pc_b, true);

        // The probe learns the vault while it is still live and funded.
        let (tpk, tdid) = become_device(0x52);
        let probe = named_router("probe-dead-market");
        probe.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xE3, 5_000, 0),
        );
        let res = crate::runtime::get_runtime().block_on(async {
            probe
                .invoke(AppInvoke {
                    method: "route.syncVaultsForPair".to_string(),
                    args: pack(
                        generated::RoutingPairRequest {
                            token_a: pc_a.to_vec(),
                            token_b: pc_b.to_vec(),
                        }
                        .encode_to_vec(),
                    ),
                })
                .await
        });
        assert!(res.success, "probe sync failed: {:?}", res.error_message);
        let probe_before = {
            let h = probe.core_sdk.device_head().expect("probe head");
            (h.balance(&pc_a), h.balance(&pc_b))
        };

        // The owner withdraws everything.
        let _ = become_device(0x41);
        let res = close(&owner, &vault_id);
        assert!(res.success, "close failed: {:?}", res.error_message);
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (2, 0, 0),
            "the market composes the vault as dead"
        );

        // The probe settles against the reserves the vault held before the
        // close, at the generation the close produced.
        let _ = become_device(0x52);
        let out =
            crate::sdk::routing_path_sdk::constant_product_output(300, reserves.0, reserves.1, 30)
                .expect("curve output on the pre-close reserves");
        let (res, _x) = trader_settles(
            &probe, &tpk, &tdid, &vault_id, &pc_a, &pc_b, 2, reserves, 300, out, 0x40,
        );
        assert!(!res.success, "a closed vault must not settle a trade");
        // The refusal must come from the vault's STATE. "The trader has never
        // heard of this vault" would also be a refusal, and would leave the
        // dangerous case — a trader that DID hold the vault — untested.
        let msg = res.error_message.as_deref().unwrap_or_default().to_string();
        assert!(
            !msg.contains("not in local DLVManager"),
            "the probe must know the vault and be refused on its state: {msg}"
        );
        assert!(
            msg.contains("re-simulation rejected"),
            "the settle side re-simulates the curve against the composed (zero) reserves: {msg}"
        );
        let h = probe.core_sdk.device_head().expect("probe head");
        assert_eq!(
            (h.balance(&pc_a), h.balance(&pc_b)),
            probe_before,
            "the refused trade moved none of the probe's value"
        );

        // …and the vault is still dead: a refused settle cannot revive it.
        let _ = become_device(0x41);
        assert_eq!(leaves(&owner, &vault_id, &pc_a, &pc_b), (0, 0, 2));
    }

    /// Only the creating owner can close. A device with no record of the vault
    /// has no pair, no fee and no birth-bound storage set for it — everything
    /// the close derives — so it is refused before any of it is guessed.
    #[test]
    #[serial]
    fn a_vault_this_device_never_created_cannot_be_closed() {
        install_identity();
        let owner = named_router("owner");
        owner.core_sdk.set_device_head_for_testing(
            crate::sdk::funded_vault_fixture::device_holding(0xD1, 50_000, 20_000),
        );
        let res = close(&owner, &[0x7Eu8; 32]);
        assert!(!res.success, "an unknown vault cannot be closed");
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("only the creating owner can close"),
            "the refusal says why: {:?}",
            res.error_message
        );
    }
    /// THE ROUTE THAT HAD NO TEST — which is why both wounds shipped.
    ///
    /// `dlv_list_owned_amm_vaults` parsed `AmmConstantProduct.token_a/token_b` as UTF-8
    /// ticker text. Those fields are 32-byte CPTA policy commits (the proto has always
    /// said so; the Rust doc used to say "token id"), so `from_utf8` failed, the `?`
    /// returned `None`, and the match fell to `_ => (0, 0)`: the owner's own screen
    /// showed ZERO reserves for a funded vault. The same misreading reached the frontend,
    /// which UTF-8-decoded the commits into mojibake pair labels.
    ///
    /// Two tests LOOK like they cover this — both assert `(10_000, 5_000)` — but both
    /// bind `v` from `rehydrate_all_amm_vaults`, a different path entirely.
    ///
    /// This drives the REAL route once and pins all three properties together.
    #[test]
    #[serial_test::serial]
    fn list_owned_amm_vaults_keeps_commits_reports_real_reserves_and_resolves_tickers() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();

        // Known display names for those exact commits.
        dsm::core::token::register_policy_commit_ticker(pc_a, "AAA");
        dsm::core::token::register_policy_commit_ticker(pc_b, "BBB");

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
        let created = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.create".to_string(),
                args: pack(req.encode_to_vec()),
            })
            .await
        });
        assert!(
            created.success,
            "create failed: {:?}",
            created.error_message
        );

        // THE ACTUAL ROUTE, through the dispatcher.
        let res = crate::runtime::get_runtime().block_on(async {
            r.query(crate::bridge::AppQuery {
                path: "dlv.listOwnedAmmVaults".to_string(),
                params: Vec::new(),
            })
            .await
        });
        assert!(res.success, "list failed: {:?}", res.error_message);

        // `pack_envelope_ok` prefixes a 0x03 v3 framing byte before the Envelope.
        assert_eq!(res.data.first(), Some(&0x03u8), "Envelope v3 framing byte");
        let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
        let Some(generated::envelope::Payload::AppStateResponse(state)) = env.payload else {
            panic!("expected AppStateResponse");
        };
        let line = state.value.expect("value");
        let bytes = crate::util::text_id::decode_base32_crockford(line.trim())
            .expect("summary decodes from Base32");
        let v = generated::AmmVaultSummaryV1::decode(&*bytes).expect("summary");

        // 1. The commit fields keep their established meaning — byte-exact, unchanged.
        assert_eq!(
            v.token_a, pc_a,
            "token_a must remain the exact 32-byte policy commit"
        );
        assert_eq!(v.token_b, pc_b, "token_b must remain the exact commit");

        // 2. THE CORRECTNESS WOUND: real reserves, not the (0, 0) the broken lookup gave.
        assert_eq!(
            (v.reserve_a, v.reserve_b),
            (10_000, 5_000),
            "reserves must come from the owner's encumbered leaves; (0, 0) means the \
             policy commit was parsed as ticker text again"
        );

        // 3. THE DISPLAY WOUND: resolved labels, so the frontend never decodes a digest.
        assert_eq!(v.token_a_ticker, "AAA");
        assert_eq!(v.token_b_ticker, "BBB");
    }

    /// WIRE COMPATIBILITY for the additive display fields.
    ///
    /// `token_a_ticker` / `token_b_ticker` are new tags (17, 18) on a QUERY RESPONSE.
    /// Additive, so this is not a head-format change and adds no wipe/reseed requirement —
    /// but it must actually be additive, which means both directions have to hold:
    /// a message written by an OLD encoder must still decode, and a message written by
    /// the new one must round-trip byte-for-byte.
    #[test]
    fn the_additive_display_fields_are_wire_compatible_in_both_directions() {
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::pair_commits();

        // OLD -> NEW: a producer that never heard of tags 17/18. Encoding a summary with
        // the fields empty is byte-identical to what the pre-change encoder emitted,
        // because proto3 omits empty strings entirely.
        let old_shape = generated::AmmVaultSummaryV1 {
            vault_id: vec![0x11u8; 32],
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            reserve_a: 10_000,
            reserve_b: 5_000,
            fee_bps: 30,
            ..Default::default()
        };
        let old_bytes = old_shape.encode_to_vec();
        assert!(
            !old_bytes.iter().any(|b| *b == 0x8A || *b == 0x92),
            "empty display fields must not be emitted at all (tags 17/18 absent on the wire)"
        );
        let decoded = generated::AmmVaultSummaryV1::decode(&*old_bytes).expect("old decodes");
        assert_eq!(decoded.token_a, pc_a, "existing commit semantics preserved");
        assert_eq!((decoded.reserve_a, decoded.reserve_b), (10_000, 5_000));
        assert!(
            decoded.token_a_ticker.is_empty() && decoded.token_b_ticker.is_empty(),
            "absent display fields decode to empty, never to garbage"
        );

        // NEW -> NEW: full round trip, values intact.
        let new_shape = generated::AmmVaultSummaryV1 {
            token_a_ticker: "AAA".to_string(),
            token_b_ticker: crate::util::text_id::encode_base32_crockford(&pc_b),
            ..old_shape.clone()
        };
        let round =
            generated::AmmVaultSummaryV1::decode(&*new_shape.encode_to_vec()).expect("new decodes");
        assert_eq!(round, new_shape, "round trip must be lossless");
        assert_eq!(
            round.token_a, pc_a,
            "commits still untouched by the display fields"
        );
        assert_eq!(
            round.token_b_ticker.len(),
            52,
            "an encoded 32-byte commit is 52 Base32 Crockford chars — inside the 64 cap"
        );
    }

    /// An UNREGISTERED commit still gets a deterministic, non-empty label: its own
    /// canonical Base32 Crockford encoding. Empty would push the guess back into React,
    /// which is the shape of the bug being fixed.
    #[test]
    #[serial_test::serial]
    fn an_unresolvable_token_falls_back_to_its_canonical_encoding_never_empty() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) = ([0x7Eu8; 32], [0x7Fu8; 32]);

        r.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::device_holding(
                0x99, 50_000, 20_000,
            ));
        let _ = (pc_a, pc_b);

        // Resolution itself is the unit under test here — the route wraps exactly this.
        let label = |pc: [u8; 32]| -> String {
            dsm::core::token::resolve_ticker_for_policy_commit(&pc)
                .unwrap_or_else(|| crate::util::text_id::encode_base32_crockford(&pc))
        };
        let a = label(pc_a);
        assert!(!a.is_empty(), "a label must never be empty");
        assert_eq!(
            a,
            crate::util::text_id::encode_base32_crockford(&pc_a),
            "an unresolved commit renders as its own canonical encoding"
        );
        assert!(
            !a.contains('\u{FFFD}'),
            "never a replacement character — that is what UTF-8-decoding a digest produced"
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

        // (4) THE ROOT A QUOTE WOULD USE. The funding advance wrote the reserve
        // leaves and the vault-state leaf in ONE SMT batch, so there is exactly
        // one root and both proofs bind it — `compose_vault_state` requires them
        // to agree on `smt_root`, and that now holds by construction rather than
        // by call ordering.
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
