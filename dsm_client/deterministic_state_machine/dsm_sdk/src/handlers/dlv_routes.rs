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

/// THE MARKET-LEG TOKEN-POLICY PRE-FLIGHT (SoFi Def 4.1 / Req 4.4 / Req 4.6).
///
/// A non-builtin leg requires this device's OWN rooting in the token's public
/// anchor: locally anchored bytes, or a fetch from the authoritative
/// content-addressed path — re-hashed against the commit before anything
/// trusts a byte, then persisted (anchors are public; anyone holding one may
/// root). The parsed policy must then permit the asset as a market leg —
/// today that means `transferable`, the one movement-relevant commitment a
/// token policy carries. ERA and dBTC are pre-rooted on every device and
/// skip.
///
/// This is the ROUTE layer of a three-layer rule: the advance funnel enforces
/// the same matrix from local rooting for every caller, and the economic
/// verifier reruns it foreign-verifiably in `advance_validated`. Only this
/// layer may touch the network, which is why the fetch lives here.
/// 2c-C3.1 ruling D, effect 4. An execution that consumes a composed parent
/// refuses on a quarantined lineage INDEPENDENTLY of the walk's own cursor
/// check and of the observer's: each stands when the others are removed, and
/// each has its own control.
fn refuse_quarantined_lineage(
    route: &str,
    vault_id: &[u8; 32],
    generation: u64,
    c_n: &[u8; 32],
) -> Result<(), String> {
    use crate::storage::client_db::dlv_lineage_quarantine as quarantine;
    match quarantine::refusing_root(vault_id, generation, c_n) {
        Ok(None) => Ok(()),
        Ok(Some(root)) => Err(format!(
            "{route}: STORAGE_SAFETY_VIOLATION {}: {}",
            dsm::dlv::successor_validity::Reason::LineageQuarantined.as_str(),
            quarantine::describe_refusal(&root, generation)
        )),
        Err(e) => Err(format!(
            "{route}: the lineage quarantine table is unreadable ({e}); refusing"
        )),
    }
}

async fn require_rooted_market_leg(route: &str, pc: &[u8; 32]) -> Result<(), String> {
    if dsm::core::token::token_state_manager::builtin_token_id_for_policy_commit(pc).is_some() {
        return Ok(());
    }
    let bytes = match crate::storage::client_db::token_registry::load_policy_verified(pc) {
        Ok(Some(b)) => b,
        _ => {
            let fetched = crate::handlers::token_routes::try_fetch_policy_from_network(pc)
                .await
                .map_err(|e| {
                    format!(
                        "{route}: policy fetch failed for market leg {}: {e}",
                        crate::util::text_id::encode_base32_crockford(pc)
                    )
                })?;
            let Some(b) = fetched else {
                return Err(format!(
                    "{route}: market leg {} is not rooted and its policy is not retrievable \
                     from the anchor path — root this device to the token, then retry",
                    crate::util::text_id::encode_base32_crockford(pc)
                ));
            };
            if dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, &b)
                != *pc
            {
                return Err(format!(
                    "{route}: fetched policy bytes do not hash to market leg {} — refusing",
                    crate::util::text_id::encode_base32_crockford(pc)
                ));
            }
            let _ = crate::storage::client_db::token_registry::upsert_policy(pc, &b);
            b
        }
    };
    let policy = dsm::economic::issuance::parse_issuance_policy(&bytes)
        .map_err(|e| format!("{route}: market leg policy: {e}"))?;
    dsm::economic::issuance::check_market_leg_permitted(&policy)
        .map_err(|e| format!("{route}: {e}"))?;
    Ok(())
}

impl AppRouterImpl {
    /// Dispatch handler for `dlv.*` query (read-only) routes.
    pub(crate) async fn handle_dlv_query(&self, q: crate::bridge::AppQuery) -> AppResult {
        match q.path.as_str() {
            "dlv.listOwnedAmmVaults" => self.dlv_list_owned_amm_vaults(q).await,
            "dlv.composeVault" => self.dlv_compose_vault(q).await,
            "dlv.lineageQuarantine" => self.dlv_lineage_quarantine(q).await,
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
                publication_state: if baseline_is_published(&v.vault_id) {
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

    /// `dlv.composeVault` (query, read-only) — the composed STATE of a
    /// DISCOVERED vault, exactly as any verifier derives it: advertisement →
    /// presentation → `c_n` → exact `CCB(V_n)` bytes → P0–P6 → receipted
    /// fold. Owner and stranger run the SAME path here, which is the point:
    /// two devices querying this route about one vault must answer with the
    /// same bytes or the milestone's symmetry claim is false.
    ///
    /// Input (`q.params`, UTF-8): `"<vault_id_b32>:<token_a_b32>:<token_b_b32>:<fee_bps>"`.
    /// Output (`AppStateResponse.value`): `"<generation>:<reserve_a>:<reserve_b>:<c_n_b32>"`.
    ///
    /// NOT a frontier answer. Two devices agreeing here proves they derive the
    /// same successor from the same published artifacts — which is what the
    /// two-device verdict checks and all it checks. It does NOT prove the state
    /// is the latest: the fold stops when the pointer listing it read runs out,
    /// that listing came from one member, and absence is indistinguishable from
    /// omission. Establishing maximality needs a live quorum read this query
    /// does not perform.
    async fn dlv_compose_vault(&self, q: crate::bridge::AppQuery) -> AppResult {
        let params = match std::str::from_utf8(&q.params) {
            Ok(s) => s.trim().to_string(),
            Err(e) => return err(format!("dlv.composeVault: params not UTF-8: {e}")),
        };
        let parts: Vec<&str> = params.split(':').collect();
        if parts.len() != 4 {
            return err(
                "dlv.composeVault: params must be vault_id:token_a:token_b:fee_bps (Base32 \
                 Crockford ids)"
                    .into(),
            );
        }
        let decode32 = |what: &str, s: &str| -> Result<[u8; 32], String> {
            crate::util::text_id::decode_base32_crockford(s)
                .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                .ok_or_else(|| format!("dlv.composeVault: {what} is not a 32-byte Base32 id"))
        };
        let vault_id = match decode32("vault_id", parts[0]) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let token_a = match decode32("token_a", parts[1]) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let token_b = match decode32("token_b", parts[2]) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let fee_bps: u32 = match parts[3].parse() {
            Ok(v) => v,
            Err(e) => return err(format!("dlv.composeVault: fee_bps: {e}")),
        };
        let composed = match crate::sdk::vault_state_composition::compose_discovered_vault(
            &vault_id, &token_a, &token_b, fee_bps,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => return err(format!("dlv.composeVault: {e}")),
        };
        let resp = generated::AppStateResponse {
            key: "dlv.composeVault".to_string(),
            value: Some(format!(
                "{}:{}:{}:{}",
                composed.sequence,
                composed.reserves_a,
                composed.reserves_b,
                crate::util::text_id::encode_base32_crockford(&composed.c_n),
            )),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// dlv.lineageQuarantine — the quarantine roots of one vault on this
    /// device, with both evidence objects (2c-C3.1 ruling D, effect 2). Params:
    /// the vault id, Base32 Crockford. One root per line:
    /// `root_c_n:root_generation:storage_set_id:quorum:first_evidence:second_evidence`,
    /// the evidence as Base32 Crockford of the client-local encoding. An empty
    /// value means no root.
    async fn dlv_lineage_quarantine(&self, q: crate::bridge::AppQuery) -> AppResult {
        let params = match std::str::from_utf8(&q.params) {
            Ok(s) => s.trim().to_string(),
            Err(e) => return err(format!("dlv.lineageQuarantine: params not UTF-8: {e}")),
        };
        let Some(vault_id) = crate::util::text_id::decode_base32_crockford(&params)
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        else {
            return err("dlv.lineageQuarantine: vault_id is not a 32-byte Base32 id".into());
        };
        let roots =
            match crate::storage::client_db::dlv_lineage_quarantine::roots_for_vault(&vault_id) {
                Ok(r) => r,
                Err(e) => {
                    return err(format!(
                        "dlv.lineageQuarantine: the quarantine table is unreadable: {e}"
                    ))
                }
            };
        let b32 = crate::util::text_id::encode_base32_crockford;
        let lines: Vec<String> = roots
            .iter()
            .map(|r| {
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    b32(&r.root_c_n),
                    r.root_generation,
                    b32(&r.storage_set_id),
                    r.quorum,
                    b32(&r.first_evidence),
                    b32(&r.second_evidence),
                )
            })
            .collect();
        let resp = generated::AppStateResponse {
            key: "dlv.lineageQuarantine".to_string(),
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
        // `policy_digest` is the DLV-POLICY digest and, for an AMM vault, it is
        // DERIVED below from the vault's own release and fee policy — a caller
        // may leave it empty or may supply the value it expects, but cannot
        // choose it. Shape is checked here; the derivation runs once the
        // predicate is known.
        if !(spec.policy_digest.is_empty() || spec.policy_digest.len() == 32) {
            return err(
                "dlv.create: spec.policy_digest must be empty (derived) or 32 bytes".into(),
            );
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

        // THE AMM DLV-POLICY DIGEST IS DERIVED, NOT CHOSEN.
        //
        // An AMM vault's policy identity is a deterministic view of the two
        // DLV-layer members the creator-signed `VaultStateV2` commits — its
        // release policy (the beta family) and its fee policy — and never of
        // the pair's CPTA commits, which are the TOKEN layer and independent
        // authorities of their own. It used to be 32 free bytes the UI asked a
        // human to paste ("policy anchor"), labelled a CPTA anchor and compared
        // to nothing: a token identity in a vault-policy slot. Now `dlv.create`
        // computes it, refuses a supplied value that disagrees, persists and
        // echoes only the derived value, and folds it into `parameters_hash`
        // so the creator SIGNS it. Non-AMM vaults have no DLV-layer policy
        // object to derive from; their supplied 32 bytes are kept, and are now
        // at least covered by the creator signature.
        let policy_digest: [u8; 32] = if amm_pair.is_some() {
            let fee = match dsm::ccb::FeePolicy::new(amm_fee_bps) {
                Ok(f) => f,
                Err(e) => return err(format!("dlv.create: fee policy: {e}")),
            };
            let derived = dsm::ccb::dlv_policy_digest(
                &dsm::ccb::ReleasePolicy::beta_owner_local_full_close(),
                &fee,
            );
            if !spec.policy_digest.is_empty() && spec.policy_digest.as_slice() != derived {
                return err(
                    "dlv.create: spec.policy_digest is not this AMM vault's DLV-policy digest — it is \
                     derived from the vault's release and fee policy, never chosen; leave it empty \
                     or supply the derived value"
                        .into(),
                );
            }
            derived
        } else {
            if spec.policy_digest.len() != 32 {
                return err(
                    "dlv.create: spec.policy_digest must be 32 bytes for a non-AMM vault".into(),
                );
            }
            let mut pd = [0u8; 32];
            pd.copy_from_slice(&spec.policy_digest);
            pd
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
            // Signed with the rest of the parameters: the vault's DLV-policy
            // identity is part of what the creator attests to at birth.
            Some(policy_digest),
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
            // ANCHOR BINDING IS NOT A SETTING. `enforce_parent_binding` — the
            // code that actually decides whether a hop's vault-state binding is
            // accepted — has never consulted `anchor_enforcement`; it is
            // unconditional. The selector was therefore a knob whose gate was
            // already dead, and the one thing a dead knob can still do is be
            // read back later as authority ("this vault was created Optional").
            // It is retired here: the only posture a new AMM vault may be
            // created under is the canonical REQUIRED one, so nothing
            // downstream can ever be handed a weaker persisted value.
            //
            // SCOPED TO THE AMM BRANCH ON PURPOSE. `anchor_enforcement` reaches
            // durable state only through `AmmVaultRecord`, which only this
            // branch writes. A non-AMM or posted DLV never persists the field,
            // and the shipping frontend's own non-AMM spec builders leave it
            // unset — refusing those would remove a working capability to fence
            // a column they do not touch.
            //
            // Unspecified (0) is refused with the rest: defaulting 0 into
            // behaviour is exactly the repair that turns a missing field into
            // permissive enforcement, and this is the last place a new 0 can
            // enter the vault record.
            if spec.anchor_enforcement != generated::AnchorEnforcement::Required as i32 {
                return err(format!(
                    "dlv.create: anchor binding is unconditional; an AMM vault's \
                     spec.anchor_enforcement must be ANCHOR_ENFORCEMENT_REQUIRED ({}), got {} — \
                     the selector is retired, not configurable",
                    generated::AnchorEnforcement::Required as i32,
                    spec.anchor_enforcement,
                ));
            }
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

        // Both legs must satisfy the applicable token policy BEFORE anything
        // durable — and a leg must be a real, rooted asset at all: until this
        // gate, any 32 random bytes with a balance under them was an
        // acceptable funding leg.
        for (pc, _) in &funding {
            if let Err(e) = require_rooted_market_leg("dlv.create", pc).await {
                return err(e);
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
        // Sufficiency is NOT checked here any more. It was read from
        // `device_head()`, a different ledger from the one the write set
        // actually debits — on a device whose head and `R_econ` had diverged
        // the route reported "sufficient" and the admission then failed. The
        // funded path now decides it inside the admission facade, against the
        // exact staged predecessor the transition is built on, so there is one
        // observation instead of two. See `admitted_dlv_create_funded`.

        let policy_commit_opt: Option<[u8; 32]> = funding.first().map(|(pc, _)| *pc);

        // Build the creation operation. A funded (AMM) vault is a
        // DlvCreateFundedV2 — both legs + fee in the SIGNED operation, signed
        // LOCALLY by this device (the legacy caller-supplied signature died
        // with the legacy value-bearing DlvCreate, owner directive
        // 2026-08-28). A tokenless vault stays the state-only DlvCreate.
        let op = if amm_pair.is_some() {
            let unsigned = dsm::types::operations::Operation::DlvCreateFundedV2 {
                vault_id: vault_id.to_vec(),
                creator_public_key: req.creator_public_key.clone(),
                parameters_hash: draft.parameters_hash.clone(),
                fulfillment_condition: spec.fulfillment_bytes.clone(),
                leg_a_policy_commit: funding[0].0,
                leg_a_amount: funding[0].1,
                leg_b_policy_commit: funding[1].0,
                leg_b_amount: funding[1].1,
                fee_bps: amm_fee_bps,
                signature: Vec::new(),
                mode: dsm::types::operations::TransactionMode::Unilateral,
            };
            match self.core_sdk.sign_operation_sphincs(unsigned) {
                Ok(signed) => signed,
                Err(e) => return err(format!("dlv.create: sign funded create: {e}")),
            }
        } else {
            dsm::types::operations::Operation::DlvCreate {
                vault_id: vault_id.to_vec(),
                creator_public_key: req.creator_public_key.clone(),
                parameters_hash: draft.parameters_hash.clone(),
                fulfillment_condition: spec.fulfillment_bytes.clone(),
                intended_recipient: intended_recipient_opt.clone(),
                signature: req.signature.clone(),
                mode: dsm::types::operations::TransactionMode::Unilateral,
            }
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
                        // NO HEAD, NO RECORD. This used to be
                        // `.unwrap_or_default()` on both identity fields, which
                        // WOULD have persisted a vault owned by 32 zero bytes:
                        // an owner no presentation can prove, whose reserve
                        // leaves live under a key space nothing derives, and
                        // which every later gate — rehydration's owner check,
                        // the composed-owner binding below — refuses. Today
                        // `get_current_state()` errors earlier on a head-less
                        // device, so this branch is defensive; it exists so the
                        // fabrication cannot return if that ordering changes.
                        let Some(owner) = self.core_sdk.device_head() else {
                            return err(
                                "dlv.create: no device head, so this vault's record would name a \
                                 32-zero owner — an identity nothing can authenticate and no \
                                 later gate can repair; refusing to create rather than persist it"
                                    .into(),
                            );
                        };
                        // The DERIVED digest, never the caller's bytes.
                        let pd = policy_digest;
                        Some(
                            crate::storage::client_db::amm_vault_records::AmmVaultRecord {
                                vault_id,
                                owner_genesis: owner.genesis(),
                                owner_devid: owner.devid(),
                                policy_commit_a: pair.a(),
                                policy_commit_b: pair.b(),
                                fee_bps: amm_fee_bps,
                                // DEPRECATION RESIDUE. The column still
                                // exists, so it is written with the one
                                // posture the route accepts — never with a
                                // caller-chosen value, and never with 0. No
                                // decision reads it back; see the field's doc
                                // on `AmmVaultRecord`.
                                anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                                policy_digest: pd,
                                storage_set_id: birth_set_id,
                                baseline_state_ccb: Vec::new(),
                                baseline_presentation: Vec::new(),
                                // Stamped after finalize + policy stamping below,
                                // the earliest point at which the bytes are final.
                                vault_post_proto: Vec::new(),
                                // Stamped after the admitted create publishes
                                // the artifact — it does not exist yet, and a
                                // placeholder would be a locator pointing
                                // nowhere.
                                economic_proof: None,
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
                    baseline_state_ccb, baseline_presentation, vault_post_proto, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
                    rec.baseline_state_ccb.as_slice(),
                    rec.baseline_presentation.as_slice(),
                    rec.vault_post_proto.as_slice(),
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
                    rec_with_birth.baseline_state_ccb = artifacts.state_ccb.clone();
                    rec_with_birth.baseline_presentation = artifacts.presentation.clone();
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
                // ADMITTED. A funded creation is an economically originating
                // operation: it moves spendable balance into vault reserves, so
                // it belongs in `R_econ` exactly like a mint or a faucet claim,
                // and the accepting layer now REFUSES it without an attached
                // DSM-backed admission. Same staged build/write as before — the
                // birth objects are still signed off this advance's own root
                // and frozen in its transaction — the difference is that the
                // economic transition is now real rather than head-only.
                let admitted =
                    match crate::sdk::economic_admission_flow::admitted_dlv_create_funded(
                        &self.core_sdk,
                        op,
                        rel_key,
                        actor,
                        init_tip,
                        funding_mutation,
                        display_name_for,
                        build,
                        write,
                    )
                    .await
                    {
                        Ok((_outcome, admitted)) => admitted,
                        Err(e) => return err(format!("dlv.create: funded creation failed: {e}")),
                    };
                // THE LOCATOR, stamped once the thing it points at exists. The
                // admitted create published an inclusion proof for the reserve
                // leaves it just wrote; the address and the position whose
                // registered root it names are what a trader needs to find it,
                // and the routing advertisement carries them from here.
                //
                // A funded create ALWAYS writes two reserve leaves, so the
                // artifact is always published: its absence is a contradiction
                // between this route and the producer, not a vault without a
                // proof, and is refused rather than left to surface later as an
                // unexplained missing locator.
                let Some(proof_addr) = admitted.economic_proof_addr else {
                    return err(
                        "dlv.create: the admitted creation published no reserve-proof artifact — \
                         refusing to leave the vault without a locator"
                            .into(),
                    );
                };
                if let Err(e) =
                    crate::storage::client_db::amm_vault_records::update_economic_proof_locator(
                        &vault_id,
                        &crate::storage::client_db::amm_vault_records::EconomicProofLocator {
                            addr: proof_addr,
                            position: admitted.economic_position,
                        },
                    )
                {
                    return err(format!(
                        "dlv.create: stamping the reserve-proof locator: {e}"
                    ));
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
        if let Err(e) = dlv_manager.finalize_vault(draft, &req.signature).await {
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

        // `LimboVault.anchor_enforcement` is SEMANTICALLY DEAD and is stamped
        // with the canonical REQUIRED posture only so the in-memory struct
        // does not carry a 0 that a future reader could mistake for a choice.
        // It is not persisted in `LimboVaultProto` (the decoder hardcodes 0),
        // no gate consults it, and `enforce_parent_binding` is unconditional.
        // Scheduled for removal with the `anchor_enforcement` column.
        //
        // The DLV-policy digest is NOT stamped here: it rode the draft into
        // `parameters_hash` and was signed there, so the finalized vault
        // already carries it (see `LimboVault::policy_digest`).
        match dlv_manager.get_vault(&vault_id).await {
            Ok(vault_lock) => {
                let mut vault = vault_lock.lock().await;
                vault.anchor_enforcement = generated::AnchorEnforcement::Required as i32;
                debug_assert_eq!(
                    vault.policy_digest,
                    Some(policy_digest),
                    "the finalized vault carries the derived, signed DLV-policy digest"
                );
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

        // FREEZE THE VAULT POST. The routing advertisement's full proto mirror
        // is the encoded `VaultPostProto`; deriving it from the in-memory
        // DLVManager made ad publication impossible after a restart (the
        // manager's vaults are process-lifetime, by doctrine). The bytes are
        // final only now — after `finalize_vault` applied the creator
        // signature and the block above stamped enforcement + policy digest —
        // so they are produced once here and stamped onto the vault's record,
        // where the publisher replays them from durable state. MANDATORY for
        // an AMM vault: a vault whose post cannot be frozen could never be
        // advertised, so that is surfaced here rather than at first publish.
        if record_to_persist.is_some() {
            let post_bytes = match dlv_manager
                .create_vault_post(&vault_id, "dlv.create", None)
                .await
            {
                Ok(b) => b,
                Err(e) => return err(format!("dlv.create: freezing the vault post failed: {e}")),
            };
            if let Err(e) = crate::storage::client_db::amm_vault_records::update_vault_post_proto(
                &vault_id,
                &post_bytes,
            ) {
                return err(format!("dlv.create: stamping the vault post failed: {e}"));
            }
        }

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
        let vault_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);
        use crate::sdk::settlement_receipt_codec::ReceiptFetch;
        let receipt = match crate::sdk::settlement_receipt_codec::fetch_verified_receipt(
            &vault_id, &x,
        )
        .await
        {
            ReceiptFetch::Verified(r) => *r,
            ReceiptFetch::Absent => {
                return err(format!(
                    "dlv.reconcile: no settlement receipt for vault {vault_b32} at that commitment"
                ))
            }
            ReceiptFetch::Unavailable(e) => {
                return err(format!(
                    "dlv.reconcile: the receipt for vault {vault_b32} could not be read (retryable): {e}"
                ))
            }
            ReceiptFetch::Malformed(why) => {
                return err(format!(
                    "dlv.reconcile: the receipt for vault {vault_b32} is malformed: {why}"
                ))
            }
            // The operator is told the truth: a receipt is sitting in storage
            // and it does not verify. That is not "no receipt".
            ReceiptFetch::Invalid(e) => {
                return err(format!(
                    "dlv.reconcile: the receipt for vault {vault_b32} FAILS VERIFICATION: {e}"
                ))
            }
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

        // v2: the signed operation binds the exact PARENT vault state this
        // settlement consumed. The composition chain already holds it: before
        // the settlement folds locally the composed head IS the parent
        // (`composed.c_n`); after it folds, the successor names its parent as
        // `parent_state_commitment`. Any other composed generation means this
        // device's view cannot name the consumed parent — refuse rather than
        // guess.
        // THE AUTHORITATIVE PARENT STATE, from the verified composition: the
        // baseline is presentation-verified against the owner's signed anchor,
        // and every fold on the way to the frontier re-simulated its own trade,
        // so the state at `parent_sequence` is this device's PROVEN view of the
        // state this settlement consumed. Pair, fee, reserves and identity all
        // come from it — never from the SQLite record (a cache), never from the
        // receipt (the trader's witness of what the trader committed).
        let composed = match compose_own_vault(&vault_id).await {
            Ok(c) => c,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: cannot compose the vault to name the consumed parent \
                     state: {e}"
                ))
            }
        };
        // 2c-C3.1 ruling D, effect 4: independent of the walk.
        if let Err(e) =
            refuse_quarantined_lineage("dlv.reconcile", &vault_id, composed.sequence, &composed.c_n)
        {
            return err(e);
        }
        let parent_state: dsm::ccb::VaultStateV2 =
            if composed.sequence == receipt.trade.parent_sequence {
                composed.state.clone()
            } else if let Some(folded) = composed
                .folded_parents
                .iter()
                .find(|f| f.generation == receipt.trade.parent_sequence)
            {
                // The fold consumed this exact historical parent on the way
                // to the frontier — an LP reconciling N generations back
                // names it from the chain the composition itself verified.
                folded.state.clone()
            } else {
                return err(format!(
                    "dlv.reconcile: the composed chain (frontier {}) never consumed \
                     generation {} — this device's view cannot name the parent this \
                     settlement consumed; refusing",
                    composed.sequence, receipt.trade.parent_sequence,
                ));
            };
        let parent_binding = match dsm::ccb::vault_state_commitment(&parent_state) {
            Ok(c) => c,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: the parent state does not commit: {e}"
                ))
            }
        };
        let parent_state_bytes = match parent_state.encode() {
            Ok(b) => b,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: the parent state does not encode: {e}"
                ))
            }
        };
        let fee_bps = parent_state.fee_policy.fee_bps();
        let pair = match dsm::types::device_state::VaultStatePair::new(
            *parent_state.market_policy.token_a(),
            *parent_state.market_policy.token_b(),
            fee_bps,
        ) {
            Ok(p) => p,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: the parent state's pair is not canonical: {e}"
                ))
            }
        };

        // THE PRE-SIGN MIRROR of the core check — an early refusal, not an
        // authority: `advance` re-derives every one of these facts from the
        // leaves it consumes and would refuse the same fold after signing.
        // Refusing HERE keeps the owner from ever signing arithmetic it has not
        // checked. Same inputs as core, in the same order: the parent state's
        // committed pair and fee, the reserve of the asset the trader paid as
        // the input reserve (by asset identity, never by pair order), the one
        // canonical curve, exact equality.
        let (reserve_in, reserve_out) = if receipt.trade.input_policy_commit == pair.a()
            && receipt.trade.output_policy_commit == pair.b()
        {
            (parent_state.reserve_a, parent_state.reserve_b)
        } else if receipt.trade.input_policy_commit == pair.b()
            && receipt.trade.output_policy_commit == pair.a()
        {
            (parent_state.reserve_b, parent_state.reserve_a)
        } else {
            return err(
                "dlv.reconcile: the receipt's legs are not this vault's pair — refusing before \
                 signing"
                    .into(),
            );
        };
        match crate::sdk::routing_path_sdk::constant_product_output(
            receipt.trade.input_amount,
            reserve_in,
            reserve_out,
            fee_bps,
        ) {
            Some(curve) if curve == receipt.trade.output_amount => {}
            Some(curve) => {
                return err(format!(
                    "dlv.reconcile: the receipt's output is not what this vault's curve yields \
                     from the parent state's reserves (curve {curve}, receipt {}) — refusing \
                     before signing",
                    receipt.trade.output_amount,
                ))
            }
            None => {
                return err(
                    "dlv.reconcile: the receipt's trade does not simulate against the parent \
                     state's reserves — refusing before signing"
                        .into(),
                )
            }
        }
        let op = dsm::types::operations::Operation::DlvOwnerApplyV2 {
            vault_id: vault_id.to_vec(),
            settlement_receipt_id: receipt.receipt_id,
            pending_pointer_x: x,
            parent_sequence: receipt.trade.parent_sequence,
            new_sequence: receipt.trade.new_sequence,
            parent_binding,
            input_policy_commit: receipt.trade.input_policy_commit,
            output_policy_commit: receipt.trade.output_policy_commit,
            input_amount: receipt.trade.input_amount,
            output_amount: receipt.trade.output_amount,
            // The parent state's committed fee — the same one the curve above ran on.
            fee_bps,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };

        // Sign BEFORE the advance, for the same reason as `DlvSettle`: the signature is
        // inside the committed operation bytes and therefore inside the chain tip.
        let op = match self.core_sdk.sign_operation_sphincs(op) {
            Ok(signed) => signed,
            Err(e) => {
                return err(format!(
                    "dlv.reconcile: failed to sign DlvOwnerApplyV2: {e}"
                ))
            }
        };
        // The fold moves reserve value under both pair assets; each must
        // satisfy the applicable token policy before the apply is derived.
        for pc in [pair.a(), pair.b()] {
            if let Err(e) = require_rooted_market_leg("dlv.reconcile", &pc).await {
                return err(e);
            }
        }

        let mutation = dsm::types::device_state::VaultReserveMutation::ApplySettlement {
            vault_id,
            input_policy_commit: receipt.trade.input_policy_commit,
            input_amount: receipt.trade.input_amount,
            output_policy_commit: receipt.trade.output_policy_commit,
            output_amount: receipt.trade.output_amount,
            parent_sequence: receipt.trade.parent_sequence,
            new_sequence: receipt.trade.new_sequence,
            pair,
            parent_state: parent_state_bytes,
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
            // THE PUBLISHED TERMINAL STATE IS THE PERMITTED CONTINUATION.
            // `close_commitment` is `c_{n+1}` of the successor the owner
            // authorized and the fence permits (2c-A.1 ruling 3); the
            // artifacts were rebuilt off the advance's outcome. Two names for
            // one death would fork the chain at it — refused INSIDE the
            // transaction, so a mismatch consumes and advances nothing.
            if artifacts.c_n != *close_commitment {
                return Err(dsm::types::error::DsmError::invalid_operation(
                    "dlv.close: the terminal state this device would publish is not the \
                     successor the fence permits (c_{n+1} differs) — rolling back the close",
                ));
            }
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
            // The record's baseline ADVANCES to the terminal state in the same
            // transaction: from here on, every composition of this vault —
            // the owner's own and any stranger's via the record-served
            // presentation — starts at the death, not the birth.
            crate::storage::client_db::amm_vault_records::update_baseline_with_conn(
                tx,
                vault_id,
                &artifacts.state_ccb,
                &artifacts.presentation,
            )
            .map_err(|e| {
                dsm::types::error::DsmError::storage(
                    format!("dlv.close: baseline advance failed: {e}"),
                    None::<std::io::Error>,
                )
            })?;
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
            let live = match crate::sdk::vault_rehydration::rehydrate_amm_vault(&record, &head) {
                Ok(v) => v,
                // These two say something about the HEAD we are holding, not
                // about the intent: a head that has not caught up commits no
                // vault-state leaf for this vault, or commits one the row does
                // not match yet. Abandoning is irreversible, so keep the
                // intent and try again — the same treatment composition-
                // unavailable gets below.
                Err(
                    e @ (crate::sdk::vault_rehydration::RehydrationError::VaultStateLeafMissing
                    | crate::sdk::vault_rehydration::RehydrationError::RecordDisagreesWithRoot),
                ) => {
                    log::warn!(
                        "[dlv.close resume] {vault_b32}: not resumable against this head: {e}"
                    );
                    continue;
                }
                Err(_) => {
                    abandon("the vault could not be rehydrated");
                    continue;
                }
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
            let composed = match compose_own_vault(&intent.vault_id).await {
                Ok(c) => c,
                Err(e) => {
                    // Composition unavailable (baseline unpublished, frontier
                    // unreadable): keep the intent and try again later.
                    log::warn!("[dlv.close resume] {vault_b32}: cannot compose yet: {e}");
                    continue;
                }
            };
            // THE BINDING IS NOT RE-DRIVEN HERE. Restart recovery
            // (`settlement_resume::recover_all`, wired at cold boot) is the ONE
            // mechanism that resumes an unresolved QuorumBind transaction: it
            // reconstructs the bundle from the persisted fence, resumes ABOVE
            // the persisted ballot, and drives `run_fenced`. A second driver in
            // this pass would open a competing transaction over the same parent
            // and reuse ballots that recovery has already spent.
            //
            // What this pass still owns is the close-specific FINALIZATION: once
            // the binding is final and the walk has folded the close, the local
            // device still has to write its terminal state.
            if record.storage_set_id != composed.storage_set_id {
                abandon("the storage set no longer agrees between lineage and record");
                continue;
            }
            // Three ways the world can look, and only one of them is ours.
            if composed.sequence == intent.parent_sequence.saturating_add(1) {
                // The close BOUND AND FOLDED while we were away — the composed
                // frontier is already the terminal generation. Fall through and
                // finalize locally.
                // ...AND IT IS THIS CLOSE. The kind says a close consumed the
                // generation; the terminal commitment says WHICH close: the
                // composed frontier at `parent + 1` IS the folded terminal
                // state, and ruling 3 (2c-A.1) has recovery compare it against
                // the exact `c_{n+1}` this device prepared. A close over the
                // same parent whose successor differs is somebody else's.
                let folded_ours = composed
                    .folded_parents
                    .iter()
                    .find(|f| f.generation == intent.parent_sequence)
                    .is_some_and(|f| {
                        f.bound_kind == dsm::dlv::settlement_bundle::BundleShape::OwnerClose
                    })
                    && composed.c_n == intent.close_commitment;
                if !folded_ours {
                    // Something else consumed that generation. Not our close.
                    abandon("another consumer folded this vault generation");
                    continue;
                }
            } else if composed.sequence == intent.parent_sequence {
                // Still at our parent. Whether we hold it is the FENCE's
                // question, and recovery's to resolve — not this pass's.
                match composed.frontier_binding {
                    crate::sdk::vault_state_composition::FrontierBinding::LocallyFenced {
                        ..
                    } => {
                        // Our transaction is still unresolved. Leave the intent
                        // PREPARED; recovery drives it and a later pass
                        // finalizes.
                        log::info!(
                            "[dlv.close resume] {vault_b32}: the close is still fenced; \
                             restart recovery owns it"
                        );
                        continue;
                    }
                    crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                        ..
                    } => {
                        abandon("another candidate holds this vault generation");
                        let _ = crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::storage_delete_key(
                            &intent.pointer_key,
                        )
                        .await;
                        continue;
                    }
                    crate::sdk::vault_state_composition::FrontierBinding::Free => {
                        // No binding and no fence: the transaction never
                        // mutated anything. Nothing to finalize and nothing to
                        // recover; a fresh `dlv.close` may start over.
                        abandon("the close never established a binding");
                        continue;
                    }
                }
            } else {
                abandon("the composed state moved past this close's generation");
                continue;
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
            // The permitted continuation this close prepared: `c_{n+1}` of the
            // exact drained successor the owner authorized (2c-A.1 ruling 3).
            // Recorded, never re-derived — a re-derivation could name a
            // successor other than the one the fence permits.
            let close_commitment = intent.close_commitment;
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
        // THE PARENT THIS CLOSE CONSUMES — which is not always the frontier.
        //
        // The claim half already published, and a published close claim is a
        // real successor edge: the frontier walk folds it to the terminal
        // state, so re-composing here legitimately reports `parent + 1`. The
        // c_n this commit needs is the PARENT's, and the walk already computed
        // it on the way through — it is the folded parent binding for exactly
        // this generation. Any other composed generation means the vault moved
        // for some other reason and the close must not proceed blind.
        let parent_binding = if composed.sequence == parent_sequence {
            composed.c_n
        } else if composed.sequence == parent_sequence.saturating_add(1) {
            let folded = composed
                .folded_parents
                .iter()
                .find(|f| f.generation == parent_sequence)
                .ok_or_else(|| {
                    format!(
                        "resumed close: the composed state is at generation {} but names no \
                         parent binding for {parent_sequence}",
                        composed.sequence
                    )
                })?;
            // WHAT CONSUMED THAT GENERATION MUST BE THIS CLOSE.
            //
            // "the walk moved to parent+1" is not by itself evidence that OUR
            // close is what moved it: a market settle folding at the same
            // generation produces an identical sequence, and finalizing against
            // it would write this vault's terminal zero-reserve state on the
            // strength of somebody else's trade. Two checks, because either
            // alone is satisfiable by the wrong event — the KIND (a market fold
            // is not a close) and the IDENTITY (another owner-close bundle for
            // this vault would still be a different transaction).
            if folded.bound_kind != dsm::dlv::settlement_bundle::BundleShape::OwnerClose {
                return Err(format!(
                    "resumed close: generation {parent_sequence} was consumed by a market \
                     settlement, not by this close — reconcile it instead"
                ));
            }
            // Ruling 3 (2c-A.1): recovery compares against the exact `c_{n+1}`.
            // At `parent + 1` the composed frontier IS the folded terminal
            // state, so its commitment must be the continuation this close
            // prepared — a different drained successor over the same parent
            // is a different close.
            if composed.c_n != *close_commitment {
                return Err(format!(
                    "resumed close: generation {parent_sequence} was consumed by a close whose \
                     terminal state is not the successor this device authorized — refusing to \
                     finalize somebody else's transaction"
                ));
            }
            // The identity comes from THIS DEVICE'S OWN FENCE over that
            // parent — the durable record of which transaction it drove. A
            // close bundle's digest is not otherwise recoverable here without
            // re-deriving and re-signing it, and a re-signed bundle would be a
            // different object if the signature is not byte-stable.
            let fence =
                crate::storage::client_db::trader_parent_fence::active_fence(vault_id, &folded.c_n)
                    .map_err(|e| format!("resumed close: the fence table is unreadable: {e}"))?
                    .ok_or_else(|| {
                        format!(
                            "resumed close: this device holds no fence over generation \
                     {parent_sequence}, so it cannot show that close was its own"
                        )
                    })?;
            if folded.bound_by != fence.tx_id {
                return Err(format!(
                    "resumed close: generation {parent_sequence} was consumed by a different \
                     close bundle than this device fenced — refusing to finalize somebody \
                     else's transaction"
                ));
            }
            folded.c_n
        } else {
            return Err(format!(
                "resumed close: the composed state is at generation {} but this close \
                 consumes {parent_sequence} — reconcile first",
                composed.sequence
            ));
        };
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
            parent_binding,
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
        // 2c-C3.1 ruling D, effect 4: the close is the operation that advances
        // the baseline, so it refuses on a quarantined lineage independently
        // of the walk that just composed it.
        if let Err(e) =
            refuse_quarantined_lineage("dlv.close", &vault_id, composed.sequence, &composed.c_n)
        {
            return err(e);
        }
        // ── OCCUPANCY, BEFORE ANYTHING ELSE ──────────────────────────────────
        // A bound parent cannot be closed, and finding that out HERE costs one
        // read instead of a full Paxos round-trip that ends in ConflictFinal.
        match composed.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::Free => {}
            // This device's OWN close is already in flight over this exact
            // parent. Not an error: recovery drives it and `resume_close_intents`
            // finalizes. Starting a second one would open a competing
            // transaction over the same parent.
            crate::sdk::vault_state_composition::FrontierBinding::LocallyFenced { .. } => {
                return err(
                    "dlv.close: a close of this vault generation is already in flight on this \
                     device; it stays fenced until recovery resolves it"
                        .into(),
                );
            }
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized { .. } => {
                return err(
                    "dlv.close: another trade holds this vault generation — reconcile it, then \
                     close at the next generation"
                        .into(),
                );
            }
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

        // ── THE CLOSE'S IDENTITY: c_{n+1} OF THE EXACT DRAINED SUCCESSOR ────
        // 2c-A.1 ruling 3. The successor is the frozen predicate's own
        // derivation from the composed parent (`derive_close_successor`), so a
        // retry re-derives byte-identical state and names the SAME
        // continuation. The consume-once claim, the pointer, the durable
        // intent and the fence all name this one commitment — and recovery
        // compares the folded terminal state against it.
        let next_state = match dsm::dlv::successor_validity::derive_close_successor(
            &composed.state,
            composed.c_n,
        ) {
            dsm::dlv::successor_validity::DeriveExpected::Derived(v) => *v,
            dsm::dlv::successor_validity::DeriveExpected::Refused(r) => {
                return err(format!(
                    "dlv.close: the successor predicate refuses a close of this parent ({r}) — \
                     nothing was signed"
                ))
            }
        };
        let close_commitment = match dsm::ccb::vault_state_commitment(&next_state) {
            Ok(c) => c,
            Err(e) => {
                return err(format!(
                    "dlv.close: the close successor does not encode: {e}"
                ))
            }
        };

        // The release must satisfy the applicable token policy (Req 4.6 /
        // Req 21.14): both legs checked before anything is signed. The owner
        // rooted both at creation; this fails closed rather than assuming.
        for pc in [pair.a(), pair.b()] {
            if let Err(e) = require_rooted_market_leg("dlv.close", &pc).await {
                return err(e);
            }
        }

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
        // close commitment. A close has no route set, so its `x` slot carries
        // the one identity the close has: `c_{n+1}`.
        let terminal_digest = pair.reserves_digest(0, 0);
        let pointer = match dsm::dlv::vault_pending_pointer::sign_vault_pending_pointer(
            &vault_id,
            parent_sequence,
            new_sequence,
            &close_commitment,
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
            &close_commitment,
        );

        // The register claim, signed once and RETAINED — retries replay these
        // exact bytes.
        // ── DURABLE INTENT, BEFORE ANYTHING EXTERNAL ─────────────────────────
        // Recovery orchestration only; never authority.
        let intent = intent_db::CloseIntent {
            vault_id,
            parent_sequence,
            state: intent_db::CloseIntentState::PreparedClose,
            op_bytes: op.to_bytes(),
            close_commitment,
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

        // ── BIND THE PARENT via QuorumBind (5c-1) ────────────────────────────
        // The owner close consumes one vault parent through the client-driven
        // quorum transaction. COMMITTED is binding-final; because an owner close
        // is complete before binding (Req 6.30), it folds one-phase below.
        let Some(proposer_id) = crate::sdk::settlement_bind::local_proposer_id() else {
            return err("dlv.close: no local proposer identity".into());
        };
        // ── THE CLOSE AUTHORIZATION, PROVEN BEFORE ANY MUTATING OP ───────────
        // `c_{n+1}` is a public derivation from a public parent, so a close
        // bundle carrying the drained successor proves only that SOMEBODY
        // built one. What makes it the owner's close
        // is a signature over the exact release successor — and the composer
        // verifies that signature under the authority committed by THIS parent
        // (`composed.owner_public_key`), which is not necessarily the key this
        // device signs with today.
        //
        // So the candidate is verified HERE, before the first mutating binding
        // op. Signing with the current AK and discovering at fold time that the
        // parent committed a different authority would leave the vault BOUND
        // (occupancy taken) and permanently UNREALIZABLE — a bricked vault. A
        // refusal before occupancy costs nothing.
        let release = dsm::dlv::close_authorization::CloseSuccessor {
            vault_id,
            leg_a_policy_commit: pair.a(),
            leg_a_amount: composed.reserves_a,
            leg_b_policy_commit: pair.b(),
            leg_b_amount: composed.reserves_b,
            parent_sequence,
            fee_bps: pair.fee_bps(),
        };
        let owner_authorization = {
            let kp = match crate::sdk::signing_authority::derive_current_signing_keypair() {
                Ok(kp) => kp,
                Err(e) => return err(format!("dlv.close: no signing authority: {e}")),
            };
            match dsm::dlv::close_authorization::sign_close_authorization(&release, &kp.secret_key)
            {
                Ok(sig) => sig,
                Err(e) => return err(format!("dlv.close: could not authorize the close: {e}")),
            }
        };
        // The canonical close bundle (2c-A.1): no market terms, one transition
        // carrying the EXACT successor `close_commitment` names, and the
        // owner's authorization over it.
        let close_bundle = match crate::sdk::settlement_bind::close_bundle(
            composed.c_n,
            next_state,
            owner_authorization,
        ) {
            Ok(b) => b,
            Err(e) => {
                return err(format!(
                    "dlv.close: the close bundle could not be built: {e:?}"
                ))
            }
        };
        // PREFLIGHT. Exactly what every composer will run, run here first.
        if let Err(e) = dsm::dlv::close_authorization::verify_close_authorization(
            &close_bundle,
            &release,
            &composed.owner_public_key,
        ) {
            return err(format!(
                "dlv.close: this device cannot authorize a close of this vault — the parent \
                 commits a different owner authority ({e}). Refusing before binding, so the \
                 vault stays open rather than becoming bound and unclosable."
            ));
        }
        match crate::sdk::settlement_bind::bind_settlement(
            &claim_set,
            proposer_id,
            &close_bundle,
            vault_id,     // trader_chain_id: the vault's own chain
            composed.c_n, // the parent state the fence protects
        )
        .await
        {
            Ok(Ok(dsm::dlv::quorum_bind::Outcome::Committed)) => {
                let _ = intent_db::set_state(
                    &vault_id,
                    parent_sequence,
                    intent_db::CloseIntentState::ClaimPublished,
                );
            }
            Ok(Ok(
                dsm::dlv::quorum_bind::Outcome::ConflictFinal { .. }
                | dsm::dlv::quorum_bind::Outcome::Aborted,
            )) => {
                // Another transaction holds this parent. Abandon: the vault stays
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
            Ok(Ok(dsm::dlv::quorum_bind::Outcome::Invalid)) => {
                return err(
                    "dlv.close: the settlement bundle was refused as invalid storage metadata"
                        .into(),
                );
            }
            Ok(Err(_unresolved)) => {
                // Quorum unknown: the close stays PREPARED and fenced; restart
                // recovery resumes it to a terminal outcome (Req 16.4/16.5).
                return err(
                    "dlv.close: could not establish exclusive use of this vault generation; it \
                     stays fenced and recovery will resume it"
                        .into(),
                );
            }
            Err(e) => {
                return err(format!(
                    "dlv.close: could not drive the settlement bind: {e:?}"
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
        // There is no anchor-enforcement bypass left to track. The per-vault
        // selector is retired: binding is unconditional, so no vault can be in
        // an Optional or Unspecified posture and there is no bypass to audit.
        // (The sentinel string this comment used to pin for a regression guard
        // had no guard left anywhere in the tree to find it.)
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

            // ANCHOR BINDING GATE — UNCONDITIONAL. The RouteCommit hop's
            // vault-state binding fields MUST be present and MUST match the
            // vault's COMPOSED current state (generation + reserves digest);
            // anything else is rejected. There is no per-vault posture. The
            // Optional and Unspecified arms this comment used to describe were
            // never consulted by `enforce_parent_binding`, which has always
            // been unconditional, and the selector that named them is retired.
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
            let parent_binding;
            let composed_sequence;
            let frontier_binding_for_terms;
            // 5c-2 Step 4. The settle the trader signs names the OWNER's
            // identity and the VAULT's fee, and all four die with the
            // composition block unless carried out of it. `provenance` checks
            // each against the authenticated `V_n`, so a wrong value here is a
            // refusal later rather than a silent mis-settlement — but it can
            // only check what the operation carries, and the operation can
            // only carry what survives this scope.
            let owner_public_key;
            let owner_devid;
            let owner_genesis;
            let settle_fee_bps;
            // The authenticated parent `V_n` itself. `derive_market_successor`
            // computes the successor FROM it, so the successor a bundle
            // carries is a function of the state `c_n` names rather than of
            // anything the trader supplies.
            let composed_state;
            let composed_authority_evidence;
            let composed_economic_proof;
            let composed_storage_set_id;
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
                //
                // THE DISCOVERED PATH, DELIBERATELY. The settler is usually a
                // TRADER device that holds no amm_vault_record — its whole
                // knowledge of the vault came from storage. Composing through
                // the owner's local record here would work on the owner's
                // device and on every shared-database test fixture, and then
                // refuse on real foreign hardware; the discovered path is the
                // one both kinds of device can run, and it is the same
                // verification either way.
                let composed = match crate::sdk::vault_state_composition::compose_discovered_vault(
                    &vault_id,
                    vt_a,
                    vt_b,
                    vault_fee_bps,
                )
                .await
                {
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

                // 2c-C3.1 ruling D, effect 4: independent of the walk.
                if let Err(e) = refuse_quarantined_lineage(
                    "dlv.unlockRouted",
                    &vault_id,
                    composed.sequence,
                    &composed.c_n,
                ) {
                    return err(e);
                }

                // The parent identity this settlement would consume, and
                // whether it was still available when composed. Carried on
                // SettleTerms because `x` — which decides whether a bound
                // parent is OURS — is derived after this block closes.
                frontier_binding_for_terms = composed.frontier_binding.clone();
                parent_binding = composed.c_n;
                composed_sequence = composed.sequence;
                owner_public_key = composed.owner_public_key.clone();
                owner_devid = composed.owner_devid;
                owner_genesis = composed.owner_genesis;
                settle_fee_bps = vault_fee_bps;
                composed_state = composed.state.clone();
                composed_authority_evidence = composed.owner_authority_evidence.clone();
                composed_economic_proof = composed.owner_economic_proof;
                composed_storage_set_id = composed.storage_set_id;
                (composed.reserves_a, composed.reserves_b)
            };
            match crate::sdk::route_commit_sdk::verify_amm_swap_against_reserves(
                &hop,
                &vault.fulfillment_condition,
                proven_a,
                proven_b,
            ) {
                Ok(Some(outcome)) => {
                    // The legs, from the hop that was just verified against the
                    // owner's PROVEN reserves — the rooting gate below reads
                    // them from here and from no second source.
                    let (Some(in_pc), Some(out_pc)) = (
                        <[u8; 32]>::try_from(hop.token_in.as_slice()).ok(),
                        <[u8; 32]>::try_from(hop.token_out.as_slice()).ok(),
                    ) else {
                        return err(
                            "dlv.unlockRouted: hop assets are not 32-byte policy commits".into(),
                        );
                    };
                    settle_terms = Some(SettleTerms {
                        input_policy_commit: in_pc,
                        output_policy_commit: out_pc,
                        owner_public_key: owner_public_key.clone(),
                        owner_devid,
                        owner_genesis,
                        fee_bps: settle_fee_bps,
                        // From the verified outcome, not re-derived: these are
                        // the amounts the re-simulation actually proved against
                        // the owner's authenticated reserves.
                        input_amount: outcome.input_amount,
                        output_amount: outcome.expected_output,
                        parent_state: composed_state.clone(),
                        owner_authority_evidence: composed_authority_evidence.clone(),
                        owner_economic_proof: composed_economic_proof,
                        storage_set_id: composed_storage_set_id,
                        parent_binding,
                        parent_sequence: composed_sequence,
                        frontier_binding: frontier_binding_for_terms,
                    });
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
        // Ruling I. The settler key is a correspondence claim checked against
        // the proven authority at economic admission (provenance.rs). It used to
        // fall back to `req.device_id` -- 32 DevID bytes in a 64-byte AK field --
        // which passed the device-head advance (the signature is verified
        // against THIS device's key, not the operation's) and could only fail
        // later. A DevID is not an authority key, and no key is manufactured:
        // an absent key is a refusal.
        if req.unlocker_public_key.is_empty() {
            return err(
                "dlv.unlockRouted: unlocker_public_key is required; a DevID is not an \
                 authority key and none is manufactured in its place"
                    .to_string(),
            );
        }
        if req.unlocker_public_key.len() != dsm::dlv::successor_validity::AUTHORITY_KEY_LEN {
            return err(format!(
                "dlv.unlockRouted: unlocker_public_key must be {} bytes (an authority key), got {}",
                dsm::dlv::successor_validity::AUTHORITY_KEY_LEN,
                req.unlocker_public_key.len()
            ));
        }

        // The trade, in the terms the conservation chokepoint checks. Taken from
        // the hop that was just verified against the owner's proven reserves, so
        // the deltas below cannot describe a different trade than the one the
        // AMM re-simulation accepted.
        let Some(settle) = settle_terms.as_ref() else {
            return err("dlv.unlockRouted: routed settlement requires a verified AMM hop".into());
        };

        // Both traded assets must satisfy the applicable token policy, and
        // the TRADER must be rooted in their public anchors — before the
        // first-writer claim, where a refusal still costs nothing. A trader
        // may root here for the first time: adoption is open to anyone
        // holding the commit, and the hop just authenticated both commits.
        for pc in [&settle.input_policy_commit, &settle.output_policy_commit] {
            if let Err(e) = require_rooted_market_leg("dlv.unlockRouted", pc).await {
                return err(e);
            }
        }

        // THE TRADE'S IDENTITY. `x` is recomputed from the RouteCommit bytes
        // themselves; it decides whether a bound parent is this trade's own.
        let Ok(rc_for_x) = generated::RouteCommitV1::decode(&*req.route_commit_bytes) else {
            return err("dlv.unlockRouted: route_commit_bytes did not decode".into());
        };
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc_for_x);
        // ── OCCUPANCY, FOR THIS TRADE ────────────────────────────────────────
        // Naming the right parent is not enough: it must still be ours to take.
        // Three cases, and only the middle one is subtle.
        //
        //   Free            -> nobody holds it; this settle may bind.
        //   BoundUnrealized -> SOMETHING holds it. If that something is THIS
        //                      trade's own bundle (same X), this is a retry of
        //                      a bind we already won, and refusing would strand
        //                      our own trade. Any other X is a rival, and
        //                      binding would lose ConflictFinal after we had
        //                      already priced and authorized the trade.
        //   LocallyFenced   -> this device has an unresolved transaction over
        //                      the parent; recovery owns it, and starting a
        //                      second one would reuse ballots recovery spent.
        //
        // The BoundUnrealized arm is also the seam 5c-2 grows into: once
        // realization is gated on the accepted trader successor plus `TA_B`,
        // "our own bundle is bound but not yet realized" stops being a retry
        // case and becomes the normal mid-flight state.
        match settle.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::Free => {}
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } if route_set_commitment == x => {}
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized { .. } => {
                return err(format!(
                    "dlv.unlockRouted: vault {} has this generation bound by another trade — \
                     re-quote against the composed frontier",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                ));
            }
            crate::sdk::vault_state_composition::FrontierBinding::LocallyFenced { .. } => {
                return err(format!(
                    "dlv.unlockRouted: this device holds an unresolved transaction over vault \
                     {}'s current generation; it stays fenced until recovery resolves it",
                    crate::util::text_id::encode_base32_crockford(&vault_id),
                ));
            }
        }

        // ── MARKET EMISSION: LIVE, AND IT STOPS AT BOUND-BUT-UNREALIZED ─────
        //
        // 5c-2 Step 4. The refusal that stood here was correct for exactly as
        // long as its reason held: a canonical market bundle needs the trader's
        // prepared successor and its `0x0031` evidence, and no producer could
        // make them. 5c-2 Step 2 built that producer, so the reason is spent and
        // keeping the refusal would itself be the stale thing.
        //
        // WHAT THIS DOES NOT LIFT. Realization. 2c-C4 Ruling R1 and V3 put the
        // bundle-acceptance witness, market fence release, receipt publication
        // and the realized frontier behind 2c-D, and nothing below reaches any
        // of them. The end state here is BOUND-BUT-UNREALIZED, which the
        // composition walk already models and tests. Binding a trade is not
        // settling it.
        //
        // ORDER MATTERS AND IS NOT INCIDENTAL. Sign, then prepare, then
        // produce, then publish, then fence, then bind. The settle's signature
        // is INSIDE the bytes the chain tip hashes, so a settle cannot be
        // signed after the advance; and `bind_settlement` publishes the
        // canonical bundle to a quorum of the vault's committed set and
        // refuses BEFORE any fence or binding round if that publication is not
        // durable, so a failed publication leaves no bind, no fence and no
        // rival excluded.
        let actor = match self.core_sdk.get_current_state() {
            Ok(st) => st.device_info.device_id,
            Err(e) => return err(format!("dlv.unlockRouted: no local device identity: {e}")),
        };
        let head = match self.core_sdk.device_head() {
            Some(h) => h,
            None => return err("dlv.unlockRouted: no local device head".into()),
        };
        let keypair = match crate::sdk::signing_authority::derive_current_signing_keypair() {
            Ok(kp) => kp,
            Err(e) => return err(format!("dlv.unlockRouted: no signing authority: {e}")),
        };
        // A market settle advances the trader's SELF-LOOP. The owner neither
        // signs nor advances at settle time; their side is a later, separate
        // owner-apply on the owner's own loop.
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );

        let Ok(nonce) = <[u8; 32]>::try_from(rc_for_x.nonce.as_slice()) else {
            return err("dlv.unlockRouted: the RouteCommit nonce is not 32 bytes".into());
        };
        let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&vault_id, &x);

        // THE SETTLE. Every field is a composed or verified fact: the owner
        // identity and the fee come from the authenticated `V_n`, the amounts
        // from the re-simulation that proved them against the owner's reserves,
        // and `provenance` re-checks each against `V_n` later. Nothing here is
        // caller-supplied except the route bytes the trader signed.
        let unsigned = dsm::types::operations::Operation::DlvSettle {
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
            sigma: [0u8; 32],
            settler_public_key: req.unlocker_public_key.clone(),
            settler_devid: actor,
            settlement_receipt_id: receipt_id,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };
        let signed = match self.core_sdk.sign_operation_sphincs(unsigned) {
            Ok(op) => op,
            Err(e) => {
                return err(format!(
                    "dlv.unlockRouted: the settle could not be signed: {e}"
                ))
            }
        };

        // THE PURE PREPARE. No writes, no head install: it exists to learn the
        // embedded parent and the entropy the chain tip is computed over, both
        // of which are the device's own and neither of which a caller may pick.
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
        let outcome = match self.core_sdk.simulate_advance_for_confirm(
            rel_key,
            actor,
            signed.clone(),
            &deltas,
            Some(init_tip),
            None,
            None,
        ) {
            Ok(o) => o,
            Err(e) => {
                return err(format!(
                    "dlv.unlockRouted: the trader's own advance does not prepare: {e}"
                ))
            }
        };
        let embedded_parent = outcome.new_chain_state.embedded_parent;
        let Ok(entropy) = <[u8; 32]>::try_from(outcome.new_chain_state.entropy.as_slice()) else {
            return err("dlv.unlockRouted: the prepared entropy is not 32 bytes".into());
        };

        // PRODUCE. `prepare_market_successor` RECOMPUTES the successor from the
        // signed bytes; there is no parameter through which one could be
        // supplied, and `market_terms` runs `G1`-`G4` over its own output.
        let prepared = match dsm::dlv::market_producer::prepare_market_successor(
            rel_key,
            embedded_parent,
            actor,
            &signed,
            entropy,
            &dsm::dlv::market_producer::TraderIdentity {
                genesis: head.genesis(),
                device_id: actor,
            },
            &keypair.secret_key,
        ) {
            Ok(p) => p,
            Err(e) => return err(format!("dlv.unlockRouted: {e}")),
        };
        // The producer and the prepare must agree about the successor. They
        // compute it by the same rule from the same inputs, so a disagreement
        // means one of them is not doing what it says, and binding a successor
        // this device would not actually advance to is the one outcome worth
        // refusing hardest.
        if prepared.trader_successor() != outcome.new_chain_state.compute_chain_tip() {
            return err(
                "dlv.unlockRouted: the produced successor is not the one this device would \
                 advance to; refusing before any publication or binding"
                    .into(),
            );
        }

        // THE BUNDLE. The vault successor is DERIVED from the authenticated
        // parent by the same constant-product rule every verifier applies, so
        // it is a function of `V_n` rather than of anything the trader supplies.
        let successor = match dsm::dlv::successor_validity::derive_market_successor(
            &settle.parent_state,
            settle.parent_binding,
            &dsm::dlv::successor_validity::MarketTerms {
                input_policy_commit: settle.input_policy_commit,
                output_policy_commit: settle.output_policy_commit,
                input_amount: settle.input_amount,
                fee_bps: settle.fee_bps,
            },
        ) {
            dsm::dlv::successor_validity::DeriveExpected::Derived(v) => *v,
            dsm::dlv::successor_validity::DeriveExpected::Refused(r) => {
                return err(format!(
                    "dlv.unlockRouted: the market successor does not derive from the \
                     authenticated parent: {r:?}"
                ))
            }
        };
        let market_terms = match dsm::dlv::market_producer::market_terms(
            dsm::ccb::TradeIntent {
                token_in: settle.input_policy_commit,
                amount_in: settle.input_amount,
                token_out: settle.output_policy_commit,
                exact_out: settle.output_amount,
                fee_bps: settle.fee_bps,
                nonce,
            },
            x,
            match dsm::ccb::Route::new(vec![dsm::ccb::RouteLeg::Single(dsm::ccb::Allocation {
                parent_binding: settle.parent_binding,
                delta_in: settle.input_amount,
                delta_out: settle.output_amount,
                encumbrance_claim: [0u8; 32],
                fee_policy: match dsm::ccb::FeePolicy::new(settle.fee_bps) {
                    Ok(f) => f,
                    Err(e) => return err(format!("dlv.unlockRouted: fee policy: {e:?}")),
                },
            })]) {
                Ok(r) => r,
                Err(e) => return err(format!("dlv.unlockRouted: route: {e:?}")),
            },
            &prepared,
        ) {
            Ok(t) => t,
            Err(e) => return err(format!("dlv.unlockRouted: {e}")),
        };
        let transition =
            match dsm::ccb::ConsumedDlvTransition::market(settle.parent_binding, successor) {
                Ok(t) => t,
                Err(e) => return err(format!("dlv.unlockRouted: transition: {e:?}")),
            };
        let bundle = match dsm::ccb::SettlementBundle::market(market_terms, vec![transition]) {
            Ok(b) => b,
            Err(e) => return err(format!("dlv.unlockRouted: bundle: {e:?}")),
        };

        // PUBLISH, FENCE, BIND — in that order, and all inside
        // `bind_settlement`. The fence is keyed on the TRADER's own chain and
        // parent, NOT on the vault: a market settle consumes the trader's
        // sovereign chain position, and reusing the close path's vault-keyed
        // identity would fence the wrong thing.
        let Some(proposer_id) = crate::sdk::settlement_bind::local_proposer_id() else {
            return err("dlv.unlockRouted: no local proposer identity".into());
        };
        let bind_set =
            {
                let catalog = match crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
                    Ok(c) => c,
                    Err(e) => return err(format!("dlv.unlockRouted: storage-set catalog: {e}")),
                };
                match catalog.resolve(&settle.storage_set_id) {
                    Some(sset) => sset.clone(),
                    None => return err(
                        "dlv.unlockRouted: the vault's committed storage set is not resolvable \
                         through this device's catalog; refusing before publication"
                            .into(),
                    ),
                }
            };
        match crate::sdk::settlement_bind::bind_settlement(
            &bind_set,
            proposer_id,
            &bundle,
            rel_key,
            embedded_parent,
        )
        .await
        {
            Ok(Ok(dsm::dlv::quorum_bind::Outcome::Committed)) => {
                // THE BINDING IS AUTHORITATIVE. Now, and only now, the trader
                // advances its OWN chain to the successor the bundle names,
                // with the economic admission attached (Step 4 requirement 6).
                //
                // The credit arm is `0x0026 DlvReserveConsumption`: a trader's
                // settle output is funded by consuming an owner vault reserve.
                // The evidence names the exact `V_n`, the owner's authority
                // evidence and the owner's economic proof, so a verifier
                // REPLAYS the owner's ancestry instead of trusting this device.
                let Some(locator) = settle.owner_economic_proof else {
                    return err(
                        "dlv.unlockRouted: the vault's advertisement carries no economic-proof \
                         locator, so this trade cannot be admitted; it is BOUND and must be \
                         reconciled once the owner republishes one"
                            .into(),
                    );
                };
                let evidence_bytes = {
                    let vn = match settle.parent_state.encode() {
                        Ok(v) => v,
                        Err(e) => return err(format!("dlv.unlockRouted: V_n encode: {e:?}")),
                    };
                    generated::ReserveConsumptionEvidenceV1 {
                        exact_vault_state_ccb: vn,
                        owner_authority_evidence: settle.owner_authority_evidence.clone(),
                        economic_proof_addr: locator.addr.to_vec(),
                    }
                    .encode_to_vec()
                };
                // `b`, DERIVED ONCE. The write set needs it to emit the
                // bundle-acceptance leaf (2c-D producer adoption) and the
                // response reports it; deriving it twice would be two chances
                // to derive it differently.
                let b = match dsm::dlv::settlement_bundle::canon(&bundle) {
                    Ok(c) => dsm::dlv::settlement_bundle::bundle_digest(&c),
                    Err(e) => return err(format!("dlv.unlockRouted: canon: {e:?}")),
                };
                // `expected_successor` is the exact successor the bundle was
                // BOUND to. The advance refuses if it would commit any other,
                // checked after the pure prepare and before anything is
                // written — so a device that would diverge leaves nothing
                // persisted and nothing credited.
                if let Err(e) = crate::sdk::economic_admission_flow::admitted_dlv_settle(
                    &self.core_sdk,
                    signed.clone(),
                    b,
                    rel_key,
                    actor,
                    init_tip,
                    &deltas,
                    evidence_bytes,
                    locator.position,
                    prepared.trader_successor(),
                    |_o| Ok(()),
                    |_tx, _o, _a| Ok(()),
                )
                .await
                {
                    // The bundle is bound and stays bound; what failed is this
                    // device's own admission. Reported as a refusal so no
                    // caller reads it as a completed trade.
                    return err(format!(
                        "dlv.unlockRouted: the trade is BOUND but this device could not admit its \
                         own advance ({e}); nothing was credited and the parent stays fenced"
                    ));
                }

                // BOUND, ACCEPTED, AND DELIBERATELY NOT REALIZED. The trader's
                // own chain accepted the successor and its credit is admitted,
                // so the value it holds is foreign-verifiable. What has NOT
                // happened: the market fold stays PartialPendingRealization,
                // the vault's reserves have not moved, no Def 14.2 receipt is
                // published, and THE FENCE IS NOT RELEASED — Ruling V3 gates
                // release on a certifying verdict, and ordinary DSM
                // advancement is not one.
                //
                // The admission above now also PUBLISHES the canonical `TA_B`
                // for `b` (2c-D §6, producer adoption), so the sentence that
                // used to stand here — "no bundle-acceptance witness exists to
                // construct" — would be read as still true and is not. Stated
                // exactly: the ARTIFACT exists and is fetchable; the WITNESS
                // does not, because `BundleAcceptanceWitness` has one
                // constructor and it is 2c-D §7's verifier, which nothing on
                // this path calls. Constructing one additionally needs the
                // composed bundle and an independently established trader AK.
                pack_envelope_ok(generated::envelope::Payload::AppStateResponse(
                    generated::AppStateResponse {
                        key: "dlv.unlockRouted".to_string(),
                        value: Some(format!(
                            "bound-unrealized:{}",
                            crate::util::text_id::encode_base32_crockford(&b)
                        )),
                    },
                ))
            }
            Ok(Ok(
                dsm::dlv::quorum_bind::Outcome::ConflictFinal { .. }
                | dsm::dlv::quorum_bind::Outcome::Aborted,
            )) => err(
                "dlv.unlockRouted: another transaction holds this trader parent; re-quote against \
                 the composed frontier"
                    .into(),
            ),
            Ok(Ok(dsm::dlv::quorum_bind::Outcome::Invalid)) => {
                err("dlv.unlockRouted: the storage set refused the bundle as invalid".into())
            }
            Ok(Err(_unresolved)) => err(
                "dlv.unlockRouted: the binding transaction is unresolved; the trader parent stays \
                 fenced and restart recovery resumes it"
                    .into(),
            ),
            Err(e) => err(format!("dlv.unlockRouted: binding refused: {e:?}")),
        }
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
    let entries: Vec<(&[u8], [u8; 32])> = set
        .members()
        .iter()
        .map(|m| (m.member_id.as_bytes(), m.register_incarnation_id))
        .collect();
    let storage_set = StorageSetMembers::new(&entries)
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

/// A vault's CURRENT published baseline (birth at creation, terminal after
/// close) — the two stored blobs, checked against each other and against the
/// vault they claim to describe.
#[derive(Debug)]
pub(crate) struct VerifiedBaseline {
    /// `[CCB(V_n) object key, AnchorPresentationV3 object key]`.
    pub keys: [String; 2],
    /// `inner(DSM/anchor-presentation-v1, presentation bytes)` — the discovery
    /// handle a routing advertisement carries. Produced HERE, so no caller
    /// re-hashes the blob on its own and skips the checks below.
    pub presentation_inner: [u8; 32],
}

/// THE SINGLE VERIFIED ACCESSOR for a vault's stored baseline blobs.
///
/// These two blobs used to be hashed into object keys after an `is_empty()`
/// check and nothing else — and those keys are what decides FUNDED versus
/// MARKET-ACTIVE, the boolean `route.publishRoutingAdvertisement` enforces. So
/// a row carrying two well-formed blobs that belong to DIFFERENT vaults, or a
/// presentation anchoring a different state than the CCB stored beside it,
/// activated a vault whose birth proofs describe something else.
///
/// Two byte-equalities close that, and both are local and cheap — this runs
/// inside the `listOwnedAmmVaults` loop, so it performs no P0–P6 walk, no
/// `await` and no network read:
///
/// - the presentation's `state_commitment` must equal
///   `inner(DSM/vault-state, baseline_state_ccb)`, which pairs the two blobs
///   TO EACH OTHER (that inner digest is `c_n` by construction — the birth
///   site stores exactly this value into the presentation);
/// - the decoded state's `vault_id` must be THIS vault, which binds the
///   verified pair to the vault being asked about.
///
/// WHAT THIS IS NOT — AND THE LIMIT IS THE POINT: it is TWO BYTE-EQUALITIES
/// and it AUTHENTICATES NOTHING. No signature is checked here, so a
/// presentation edited anywhere other than `state_commitment` still pairs and
/// still passes. The presentation's P0–P6 authority chain is verified in
/// `vault_state_composition`, the same way a stranger verifies it. This is the
/// local coherence gate that stops a stale, cross-pasted or foreign row from
/// becoming an activation, and it claims nothing beyond that.
pub(crate) fn verified_baseline(vault_id: &[u8; 32]) -> Result<VerifiedBaseline, String> {
    use prost::Message as _;
    let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
        .map_err(|e| format!("vault record read failed: {e}"))?
        .ok_or_else(|| "no AMM vault record for this vault on this device".to_string())?;
    if record.baseline_state_ccb.is_empty() || record.baseline_presentation.is_empty() {
        return Err(
            "the vault record carries no birth state/presentation — reprovision (no legacy \
             upgrade path exists)"
                .to_string(),
        );
    }
    let presentation =
        crate::generated::AnchorPresentationV3::decode(record.baseline_presentation.as_slice())
            .map_err(|e| format!("the stored birth presentation does not decode: {e}"))?;
    let c_n = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_VAULT_STATE,
        &record.baseline_state_ccb,
    );
    if presentation.state_commitment != c_n {
        return Err(
            "the stored birth presentation anchors a different state than the CCB stored beside \
             it — the record's two baseline blobs do not belong together"
                .to_string(),
        );
    }
    let state = dsm::ccb::decode_vault_state(&record.baseline_state_ccb)
        .map_err(|e| format!("the stored birth state does not decode: {e}"))?;
    if state.vault_id != *vault_id {
        return Err(format!(
            "the stored birth state names vault {} — not this vault",
            crate::util::text_id::encode_base32_crockford(&state.vault_id)
        ));
    }
    Ok(VerifiedBaseline {
        keys: [
            immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_VAULT_STATE,
                &record.baseline_state_ccb,
            ),
            immutable_object_key(
                dsm::common::domain_tags::TAG_DSM_ANCHOR_PRESENTATION_V1,
                &record.baseline_presentation,
            ),
        ],
        presentation_inner: dsm::storage_object::immutable_inner(
            dsm::common::domain_tags::TAG_DSM_ANCHOR_PRESENTATION_V1,
            &record.baseline_presentation,
        ),
    })
}

/// `true` iff the vault's baseline VERIFIES and both of its objects have
/// reached quorum on the vault's storage set — the activation boundary:
/// FUNDED locally is not MARKET-ACTIVE until this holds.
pub(crate) fn baseline_is_published(vault_id: &[u8; 32]) -> bool {
    let keys = match verified_baseline(vault_id) {
        Ok(v) => v.keys,
        Err(e) => {
            log::warn!(
                "[dlv] vault {} has no verified baseline; reporting it unpublished: {e}",
                crate::util::text_id::encode_base32_crockford(vault_id)
            );
            return false;
        }
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
    // The blobs go through the ONE verified accessor first: the same pairing
    // and the same vault-id binding the activation boolean gets, applied on the
    // owner path too, ahead of composition's own P0-P6 authority verification.
    // It also subsumes the emptiness check this function used to make.
    verified_baseline(vault_id)?;
    let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
        .map_err(|e| format!("vault record read failed: {e}"))?
        .ok_or_else(|| "no AMM vault record for this vault on this device".to_string())?;
    let presentation =
        crate::generated::AnchorPresentationV3::decode(record.baseline_presentation.as_slice())
            .map_err(|e| format!("stored birth presentation does not decode: {e}"))?;
    let pair = dsm::types::device_state::VaultStatePair::new(
        record.policy_commit_a,
        record.policy_commit_b,
        record.fee_bps,
    )
    .map_err(|e| format!("vault record pair is not canonical: {e}"))?;
    let composed = crate::sdk::vault_state_composition::compose_vault_state(
        vault_id,
        &presentation,
        &record.baseline_state_ccb,
        &pair.a(),
        &pair.b(),
        pair.fee_bps(),
    )
    .await
    .map_err(|e| format!("composition failed: {e}"))?;

    // THE OWNER THE PRESENTATION PROVES vs THE OWNER THE ROW CLAIMS.
    //
    // `composed.owner_genesis` / `owner_devid` are not another local copy:
    // they come out of the AUTHENTICATED presentation's P0–P6 chain and the
    // signed state it anchors. The record's copies are a row. Composition
    // returned them and nothing compared them, so a row naming a different
    // owner composed happily and every caller spent the result as if the two
    // identities agreed.
    //
    // DELIBERATELY NOT COMPARED AGAINST THE CURRENT DEVICE HEAD. The head is a
    // third statement of the same fact, but it MOVES: a legitimate device
    // rotation or re-root would make a vault this device really owns refuse to
    // compose — and every production caller already checks the record's owner
    // against the head through `rehydrate_amm_vault`. What was missing is
    // exactly this: verified authority versus the local row.
    if composed.owner_genesis != record.owner_genesis || composed.owner_devid != record.owner_devid
    {
        let which = match (
            composed.owner_genesis != record.owner_genesis,
            composed.owner_devid != record.owner_devid,
        ) {
            (true, true) => "genesis and devid",
            (true, false) => "genesis",
            _ => "devid",
        };
        return Err(format!(
            "the vault's authenticated birth names owner {}/{} but its record claims {}/{} — \
             the {which} disagree; refusing to compose",
            crate::util::text_id::encode_base32_crockford(&composed.owner_genesis),
            crate::util::text_id::encode_base32_crockford(&composed.owner_devid),
            crate::util::text_id::encode_base32_crockford(&record.owner_genesis),
            crate::util::text_id::encode_base32_crockford(&record.owner_devid),
        ));
    }
    Ok(composed)
}

/// The composed facts a routed settlement stands on once its ONE hop has been
/// verified against the owner's PROVEN reserves: the trade's legs, the parent
/// it would consume and that parent's occupancy.
///
/// Collected in one place so every gate reads a single set of values — and,
/// since 5c-2 Step 4, these ARE the values the settle operation is built from.
/// The owner identity, the vault's fee and the checked amounts are carried
/// here because they die with the composition block otherwise, and the
/// operation cannot name what did not survive that scope.
struct SettleTerms {
    input_policy_commit: [u8; 32],
    output_policy_commit: [u8; 32],
    /// The OWNER's identity, as the authenticated `V_n` commits it. The settle
    /// carries all three and `provenance` requires each to equal `V_n`'s, so
    /// they are read from the composition and never from a caller.
    owner_public_key: Vec<u8>,
    owner_devid: [u8; 32],
    owner_genesis: [u8; 32],
    /// The VAULT's fee rate, which is the authority. `provenance` refuses a
    /// settle whose fee is not `V_n`'s, so the hop's own rate is not a
    /// substitute for it.
    fee_bps: u32,
    /// The checked amounts, narrowed ONCE at the re-simulation. Carried rather
    /// than re-narrowed, because a second narrowing site is how the difference
    /// gets minted.
    input_amount: u64,
    output_amount: u64,
    /// The authenticated parent `V_n`. The market successor is DERIVED from it
    /// by the rule every verifier applies, so it is a function of the state
    /// `c_n` names rather than of anything the trader supplies.
    parent_state: dsm::ccb::VaultStateV2,
    /// The owner's `AuthorityEvidenceV1`, re-encoded from the same six values
    /// the presentation authenticated. The reserve-consumption evidence names
    /// it so a verifier can REPLAY the owner's authority rather than trust it.
    owner_authority_evidence: Vec<u8>,
    /// Where the owner's economic proof lives, per the unsigned advertisement.
    /// `None` means this trade cannot be admitted: the credit source needs it,
    /// and inventing a locator would only move the failure somewhere with less
    /// context to explain it.
    owner_economic_proof: Option<crate::sdk::vault_state_composition::OwnerEconomicProofLocator>,
    /// The vault's COMMITTED storage set. The bundle publishes there, not to
    /// whatever fleet this device happens to have configured.
    storage_set_id: [u8; 32],
    /// `c_n` of the exact composed state this settlement would consume — the
    /// ONE parent fact; generation, reserves and predicate are members of the
    /// `V_n` it identifies — plus its generation, for the refusal's own
    /// account of what was NOT bound.
    parent_binding: [u8; 32],
    parent_sequence: u64,
    /// Whether that parent was still available when it was composed. Carried
    /// here because `x` — which decides whether a bound parent is OURS — is
    /// derived after the composition block closes.
    frontier_binding: crate::sdk::vault_state_composition::FrontierBinding,
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
        respawn_fleet();
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
        crate::sdk::binding_fleet_double::reset_all();
        // Register the canonical fleet with the binding double NOW. The
        // transport registers lazily on first use, which is too late for an
        // id-keyed injection made before any binding op — and an injection that
        // resolves to no member is a test that proves nothing.
        if let Ok(catalog) = crate::sdk::storage_set::StorageSetCatalog::from_env_config() {
            if let Some(set) = catalog.sole_set() {
                crate::sdk::binding_fleet_double::register_set(set);
            }
        }
        // The ECONOMIC ROOT REGISTER is a third store, separate from both the
        // object fleet and the settlement-slot register: under cfg(test)
        // `submit_economic_root_claim` writes to `fake_registers`. It holds one
        // write-once cell per (device, economic position), and these tests
        // reuse identity seeds — so without this reset the second test to fund
        // the same identity is refused with "REGISTER CONFLICT — quarantine",
        // which is the register correctly refusing what looks like equivocation.
        // Every other admitting suite already resets it (two_device.rs:393,
        // faucet_flow_tests.rs:115, storage_routes.rs); this one did not,
        // because until now nothing here admitted anything.
        crate::sdk::storage_io::fake_registers::reset();
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
    /// A three-node fake fleet, FRESH PER TEST.
    ///
    /// Deliberately not spawned once for the binary. The economic root register
    /// is stateful: it holds one write-once record per (device, economic
    /// position), and these tests reuse identity seeds. A shared fleet therefore
    /// makes the second test to fund the same identity collide with the first —
    /// "REGISTER CONFLICT — quarantine, do not retry" — which is the register
    /// behaving CORRECTLY against what looks to it like equivocation.
    /// `Pair::boot` spawns per-test for the same reason.
    fn fleet_slot() -> &'static std::sync::Mutex<Vec<crate::test_support::fake_node::FakeB0xNode>> {
        static SLOT: std::sync::OnceLock<
            std::sync::Mutex<Vec<crate::test_support::fake_node::FakeB0xNode>>,
        > = std::sync::OnceLock::new();
        SLOT.get_or_init(|| std::sync::Mutex::new(Vec::new()))
    }

    /// Replace the fleet. Called by `install_identity`, i.e. once per test.
    fn respawn_fleet() {
        let nodes: Vec<_> = (0..3)
            .map(|_| crate::test_support::fake_node::FakeB0xNode::spawn())
            .collect();
        *fleet_slot().lock().expect("fleet slot") = nodes;
    }

    /// The current fleet's endpoints, with the loader pointed at them.
    ///
    /// `point_env_config_at` names the members canonically (`dsm-node-N`), which
    /// is what makes the beta root-register profile resolve: the catalog matches
    /// a set by RE-HASHING its member ids, so a differently-named fleet can
    /// never satisfy it and admission fails closed. In test mode the env var
    /// alone decides and deliberately does not persist, so this runs on every
    /// use rather than once.
    fn fleet_endpoints() -> Vec<String> {
        let guard = fleet_slot().lock().expect("fleet slot");
        assert!(
            !guard.is_empty(),
            "fleet_endpoints before install_identity: every test must respawn its own fleet"
        );
        let eps: Vec<String> = guard.iter().map(|n| n.endpoint.clone()).collect();
        drop(guard);
        crate::test_support::fake_node::point_env_config_at(&eps);
        eps
    }

    fn become_device(seed: u8) -> (Vec<u8>, [u8; 32]) {
        crate::sdk::funded_vault_fixture::install_v3_identity_on_fleet(seed, &fleet_endpoints())
    }

    fn named_router(name: &str) -> AppRouterImpl {
        let router = AppRouterImpl::new(SdkConfig {
            node_id: name.to_string(),
            storage_endpoints: fleet_endpoints(),
            enable_offline: true,
        })
        .expect("router init");
        // As production bring-up does (`init.rs`): the durable policy resolver
        // the enforcer consults on an in-memory miss.
        router.install_policy_resolver();
        router
    }

    fn router() -> AppRouterImpl {
        named_router("funded-creation-test")
    }

    /// The current fleet's nodes — what a participant boots against. Points
    /// the loader at them as a side effect, exactly like `fleet_endpoints`.
    fn fleet_nodes() -> Vec<crate::test_support::fake_node::FakeB0xNode> {
        let _ = fleet_endpoints();
        fleet_slot().lock().expect("fleet slot").clone()
    }

    /// A market participant on its OWN database slot, identity, router and
    /// head — the isolation two handsets actually have.
    ///
    /// Owner and traders used to share one database under a swapped process
    /// identity, which handed a trader the owner's token registry and vault
    /// record for free. On hardware a trader's whole knowledge of the market
    /// is what was published, and its whole holding of the owner's asset is
    /// what the owner sent it; a separate slot makes both true here.
    fn participant(slot: &'static str, tag: u8) -> crate::test_support::two_device::TestDevice {
        let nodes = fleet_nodes();
        let mut dev = crate::test_support::two_device::TestDevice::create(slot, tag);
        dev.boot(&nodes);
        dev
    }

    /// The display name the OWNER registered for `pc`. Read while the owner is
    /// the entered device — only its registry knows the tokens it created.
    fn ticker_of(pc: &[u8; 32]) -> String {
        crate::storage::client_db::token_registry::get_token_by_policy_commit(pc)
            .expect("registry read")
            .expect("a created asset")
            .ticker
    }

    /// The owner's asset reaches a trader the ONLY legitimate way.
    ///
    /// The trader roots itself to the owner's PUBLIC policy anchor — fetched
    /// from the storage node's copy and re-hashed against the commit, never
    /// copied out of the owner's registry — and then receives a canonical,
    /// admitted owner→trader transfer (0x0025) through the real `wallet.send`
    /// and `storage.sync`. No holder is hand-seeded anywhere.
    fn owner_transfers(
        owner: &crate::test_support::two_device::TestDevice,
        trader: &crate::test_support::two_device::TestDevice,
        policy_commit: &[u8; 32],
        amount: u64,
    ) {
        let rt = crate::runtime::get_runtime();
        owner.enter();
        let ticker = ticker_of(policy_commit);
        owner.add_contact(trader);
        trader.enter();
        trader.add_contact(owner);
        // First sync = registration on every node, which is what lets the
        // owner resolve the trader's identity at quorum before sending.
        rt.block_on(trader.sync());
        let rooted = rt.block_on(trader.router().query(crate::bridge::AppQuery {
            path: "tokens.addByAnchor".to_string(),
            params: crate::util::text_id::encode_base32_crockford(policy_commit).into_bytes(),
        }));
        assert!(
            rooted.success,
            "the trader roots to {ticker} from the network: {:?}",
            rooted.error_message
        );
        owner.enter();
        rt.block_on(owner.sync());
        let sent = rt.block_on(owner.send_token(trader, &ticker, amount));
        assert!(
            sent.success,
            "the owner sends {amount} {ticker}: {:?}",
            sent.error_message
        );
        trader.enter();
        rt.block_on(trader.sync());
        let held = trader
            .router()
            .core_sdk
            .device_head()
            .map(|h| h.balance(policy_commit))
            .unwrap_or(0);
        assert_eq!(
            held, amount,
            "the trader holds exactly what the owner sent, admitted on its own head"
        );
        // The sender's finalize-on-receipt pass.
        owner.enter();
        rt.block_on(owner.sync());
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

        // Spendable balance from ADMITTED origins — faucet ERA, then two
        // created-and-minted assets. Creation is what encumbers it. A
        // fabricated head cannot be used any more: a funded create is an
        // admitted operation, and `activate` refuses to self-root a device
        // already holding value it never admitted.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let head = r.core_sdk.device_head().expect("funded head");
        let (owner_genesis, owner_devid) = (head.genesis(), head.devid());

        // The DLV-policy digest this vault will be born with — supplied explicitly here so
        // the restart test also exercises the accept-the-derived-value path.
        let policy_digest: Vec<u8> = dsm::ccb::dlv_policy_digest(
            &dsm::ccb::ReleasePolicy::beta_owner_local_full_close(),
            &dsm::ccb::FeePolicy::new(30).expect("fee"),
        )
        .to_vec();
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
            "the residue column carries only the canonical value; nothing reads it for a decision"
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
        let (reloaded, _) = crate::storage::client_db::bcr::decode_device_state(&encoded, None)
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
            "the rehydrated posture is DERIVED (canonical REQUIRED), never read from the row"
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
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);

        // Empty creator key AND empty signature: both are the wallet's to fill.
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let build = |content_digest: Vec<u8>| generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        // Absent is the accept-or-compute path: Rust derives it. The refusals
        // above moved nothing, so the admitted funding is all still there.
        assert!(
            call(build(Vec::new())).success,
            "an absent digest must be computed, not required from the caller"
        );
    }

    /// THE RETIRED SELECTOR. `anchor_enforcement` is no longer a posture a
    /// creator may choose for an AMM vault: anchor binding is unconditional in
    /// the code that enforces it, so the only thing a persisted non-`Required`
    /// value could ever do is be read back as authority for something weaker.
    ///
    /// The refusals run FIRST and must move nothing; the POSITIVE CONTROL
    /// afterwards proves the same request succeeds under the canonical
    /// posture, so the refusals are attributable to the field and not to a
    /// broken fixture.
    #[test]
    #[serial]
    fn amm_dlv_create_refuses_every_posture_but_the_canonical_required_one() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let build = |anchor_enforcement: i32| generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
                fulfillment_bytes: amm_fulfillment_bytes(&pc_a, &pc_b, 30),
                anchor_enforcement,
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

        for posture in [
            generated::AnchorEnforcement::Unspecified as i32,
            generated::AnchorEnforcement::Optional as i32,
            99,
        ] {
            let res = call(build(posture));
            assert!(
                !res.success,
                "anchor_enforcement={posture} must be refused, not accepted"
            );
            let msg = res.error_message.unwrap_or_default();
            assert!(
                msg.contains("the selector is retired"),
                "the refusal must say the selector is retired: {msg}"
            );
        }
        assert!(
            crate::storage::client_db::amm_vault_records::list_amm_vault_records()
                .expect("records")
                .is_empty(),
            "a refused create must persist no vault record"
        );

        // POSITIVE CONTROL.
        let res = call(build(generated::AnchorEnforcement::Required as i32));
        assert!(
            res.success,
            "the canonical posture must still create: {:?}",
            res.error_message
        );
        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("records")
            .pop()
            .expect("one vault");
        assert_eq!(
            rec.anchor_enforcement,
            generated::AnchorEnforcement::Required as i32,
            "the residue column carries only the canonical value — never a 0",
        );
        assert_ne!(
            rec.owner_genesis, [0u8; 32],
            "and the owner is a real identity, never the 32-zero default"
        );
    }

    /// Read one vault record, or fail the test.
    fn record_of(
        vault_id: &[u8; 32],
    ) -> crate::storage::client_db::amm_vault_records::AmmVaultRecord {
        crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
            .expect("vault record read")
            .expect("the vault has a record")
    }

    /// Write a whole record back — the TEST-ONLY writer, which is exactly the
    /// tampering these tests need and production no longer has.
    fn write_record(rec: &crate::storage::client_db::amm_vault_records::AmmVaultRecord) {
        crate::storage::client_db::amm_vault_records::put_amm_vault_record(rec)
            .expect("write the vault record");
    }

    /// THE BASELINE BINDING. The record's two birth blobs decide FUNDED versus
    /// MARKET-ACTIVE, and they used to be hashed into object keys after an
    /// `is_empty()` check and nothing else. Four rows that used to activate a
    /// vault must not: either blob edited, the two cross-pasted from different
    /// vaults, and a valid pair that describes SOMEONE ELSE'S vault.
    ///
    /// Every case is bracketed by a POSITIVE CONTROL — the untouched row
    /// verifies and publishes — so a refusal is attributable to the mutation
    /// and not to a broken fixture.
    /// THE AMM DLV-POLICY DIGEST IS DERIVED, NOT CHOSEN. An AMM create with the
    /// field empty is born with the digest derived from its release and fee
    /// policy; the record, the in-memory vault and the creator SIGNATURE all
    /// carry that value. A create that supplies any other 32 bytes is refused
    /// by name (a token anchor in the vault-policy slot is exactly what used to
    /// be pasted here). A create that supplies the derived value is accepted —
    /// the positive control that pins the refusal to the mismatch.
    #[test]
    #[serial]
    fn an_amm_create_derives_the_dlv_policy_digest_and_refuses_a_chosen_one() {
        use crate::bridge::{AppInvoke, AppRouter};
        use prost::Message as _;
        install_identity();
        let r = router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let derived = dsm::ccb::dlv_policy_digest(
            &dsm::ccb::ReleasePolicy::beta_owner_local_full_close(),
            &dsm::ccb::FeePolicy::new(30).expect("fee"),
        );
        let create = |policy_digest: Vec<u8>, content: &[u8]| {
            let (lo, hi) = if pc_a <= pc_b {
                (pc_a, pc_b)
            } else {
                (pc_b, pc_a)
            };
            let fulfillment = generated::FulfillmentMechanism {
                kind: Some(generated::fulfillment_mechanism::Kind::AmmConstantProduct(
                    generated::AmmConstantProduct {
                        token_a: lo.to_vec(),
                        token_b: hi.to_vec(),
                        fee_bps: 30,
                    },
                )),
            }
            .encode_to_vec();
            let req = generated::DlvInstantiateV1 {
                spec: Some(generated::DlvSpecV1 {
                    policy_digest,
                    fulfillment_bytes: fulfillment,
                    content: content.to_vec(),
                    anchor_enforcement: generated::AnchorEnforcement::Required as i32,
                    ..Default::default()
                }),
                creator_public_key: Vec::new(),
                signature: Vec::new(),
                funding_legs: vec![
                    generated::DlvFundingLegV1 {
                        policy_commit: pc_a.to_vec(),
                        amount: 1_000,
                    },
                    generated::DlvFundingLegV1 {
                        policy_commit: pc_b.to_vec(),
                        amount: 500,
                    },
                ],
            };
            let args = generated::ArgPack {
                schema_hash: Some(generated::Hash32 { v: vec![0u8; 32] }),
                codec: generated::Codec::Proto as i32,
                body: req.encode_to_vec(),
            }
            .encode_to_vec();
            crate::runtime::get_runtime().block_on(async {
                r.invoke(AppInvoke {
                    method: "dlv.create".to_string(),
                    args,
                })
                .await
            })
        };

        // (1) A chosen digest — a token anchor pasted into the vault-policy slot.
        let res = create(vec![0x5Au8; 32], b"chosen digest");
        assert!(!res.success, "a chosen policy digest must be refused");
        let msg = res.error_message.unwrap_or_default();
        assert!(
            msg.contains("not this AMM vault's DLV-policy digest"),
            "the refusal names the derivation, got: {msg}"
        );

        // (2) Empty — derived. The record and the signed vault carry the derivation.
        let res = create(Vec::new(), b"derived digest");
        assert!(
            res.success,
            "an empty digest is derived: {:?}",
            res.error_message
        );
        // The refused create above recorded nothing, so this is the only record.
        let vault_id: [u8; 32] =
            crate::storage::client_db::amm_vault_records::list_amm_vault_records()
                .expect("records")
                .pop()
                .expect("the derived-digest create recorded a vault")
                .vault_id;
        assert_eq!(
            record_of(&vault_id).policy_digest,
            derived,
            "the record carries the derived value"
        );
        let vault_lock = crate::runtime::get_runtime()
            .block_on(r.bitcoin_tap.dlv_manager().get_vault(&vault_id))
            .expect("the created vault");
        let vault = crate::runtime::get_runtime()
            .block_on(vault_lock.lock())
            .clone();
        assert_eq!(
            vault.policy_digest,
            Some(derived),
            "the vault carries the derived value"
        );
        assert!(
            vault.verify().expect("verify"),
            "and the creator signature covers it"
        );

        // (3) The derived value supplied explicitly — accepted. Positive control.
        let res = create(derived.to_vec(), b"supplied derived digest");
        assert!(
            res.success,
            "supplying the derived digest is accepted: {:?}",
            res.error_message
        );
    }

    #[test]
    #[serial]
    fn a_tampered_or_cross_pasted_baseline_is_not_market_active() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let v1 = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 10_000, 5_000,
        );
        let v2 = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 9_000, 4_000,
        );
        assert_ne!(v1, v2, "the fixture must produce two DISTINCT vaults");

        let rec1 = record_of(&v1);
        let rec2 = record_of(&v2);

        // POSITIVE CONTROL.
        assert!(
            verified_baseline(&v1).is_ok(),
            "a vault born through the real route must verify its own baseline"
        );
        assert!(
            baseline_is_published(&v1),
            "and it must be market-active before anything is mutated"
        );

        // (1) THE STATE BLOB EDITED. The presentation anchors `c_n` over the
        // exact bytes, so any edit breaks the pairing.
        let mut ccb_edited = rec1.clone();
        let last = ccb_edited.baseline_state_ccb.len() - 1;
        ccb_edited.baseline_state_ccb[last] ^= 0x01;
        write_record(&ccb_edited);
        let e = verified_baseline(&v1).expect_err("an edited state blob must not verify");
        assert!(e.contains("do not belong together"), "{e}");
        assert!(
            !baseline_is_published(&v1),
            "and the vault must fall back out of MARKET-ACTIVE"
        );
        write_record(&rec1);
        assert!(verified_baseline(&v1).is_ok(), "restored");

        // (2) THE PRESENTATION'S ANCHORED COMMITMENT EDITED. Rebuilt through
        // the proto so the edit lands on exactly the field the pairing check
        // reads, rather than on whichever field a blind byte happens to hit.
        let mut pres_edited = rec1.clone();
        {
            let mut p = crate::generated::AnchorPresentationV3::decode(
                rec1.baseline_presentation.as_slice(),
            )
            .expect("the stored presentation decodes");
            p.state_commitment[0] ^= 0x01;
            pres_edited.baseline_presentation = p.encode_to_vec();
        }
        write_record(&pres_edited);
        let e = verified_baseline(&v1).expect_err("an edited presentation must not verify");
        assert!(e.contains("do not belong together"), "{e}");
        assert!(!baseline_is_published(&v1));
        write_record(&rec1);
        assert!(verified_baseline(&v1).is_ok(), "restored");

        // (2b) AND ANY OTHER BYTE OF THE PRESENTATION. `verified_baseline`
        // deliberately does NOT authenticate the presentation — the P0–P6
        // walk in `vault_state_composition` does, and duplicating it here
        // would put a signature verification inside the vault-list loop. What
        // must still hold is that a tampered blob cannot be MARKET-ACTIVE: the
        // object key is taken over the bytes, so an edited presentation names
        // an object no member ever acked.
        let mut byte_edited = rec1.clone();
        let last = byte_edited.baseline_presentation.len() - 1;
        byte_edited.baseline_presentation[last] ^= 0x01;
        write_record(&byte_edited);
        assert!(
            !baseline_is_published(&v1),
            "an edited presentation blob names an object the fleet never acked"
        );
        write_record(&rec1);
        assert!(verified_baseline(&v1).is_ok(), "restored");

        // (3) TWO VALID BLOBS, CROSS-PASTED. Both come from real births; they
        // simply do not describe each other.
        let mut cross = rec1.clone();
        cross.baseline_presentation = rec2.baseline_presentation.clone();
        write_record(&cross);
        let e = verified_baseline(&v1).expect_err("cross-pasted blobs must not verify");
        assert!(e.contains("do not belong together"), "{e}");
        assert!(!baseline_is_published(&v1));

        // (4) A VALID, SELF-CONSISTENT PAIR THAT NAMES ANOTHER VAULT. This is
        // the case only the vault-id binding catches: the blobs agree with
        // each other, so (1)–(3) all pass.
        let mut foreign = rec1.clone();
        foreign.baseline_state_ccb = rec2.baseline_state_ccb.clone();
        foreign.baseline_presentation = rec2.baseline_presentation.clone();
        write_record(&foreign);
        let e = verified_baseline(&v1).expect_err("another vault's baseline must not verify here");
        assert!(e.contains("not this vault"), "{e}");
        assert!(!baseline_is_published(&v1));

        write_record(&rec1);
        assert!(
            verified_baseline(&v1).is_ok() && baseline_is_published(&v1),
            "the vault comes back exactly as it was once the row is restored"
        );
    }

    /// THE OWNER BINDING. `compose_own_vault` returns an owner proven by the
    /// presentation's P0–P6 chain and never compared it to anything, so a row
    /// naming a different owner composed happily and every caller spent the
    /// result as if the two identities agreed.
    ///
    /// The comparison is against the RECORD, not the device head: the head
    /// moves under a legitimate rotation, and the record-vs-head check already
    /// lives in `rehydrate_amm_vault`.
    #[test]
    #[serial]
    fn composing_an_owner_vault_binds_the_proven_owner_to_the_row() {
        install_identity();
        let r = router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 10_000, 5_000,
        );
        let rt = crate::runtime::get_runtime();

        // POSITIVE CONTROL: the owner composes its own vault.
        rt.block_on(compose_own_vault(&vault_id))
            .expect("the owner must be able to compose its own vault");

        let rec = record_of(&vault_id);

        // THE DEVID the row claims is not the one the birth proves.
        let mut forged_devid = rec.clone();
        forged_devid.owner_devid = [0xEE; 32];
        write_record(&forged_devid);
        let e = rt
            .block_on(compose_own_vault(&vault_id))
            .expect_err("a row naming another devid must not compose");
        assert!(
            e.contains("the devid disagree"),
            "the refusal must name WHICH pair disagreed: {e}"
        );
        write_record(&rec);
        rt.block_on(compose_own_vault(&vault_id)).expect("restored");

        // THE GENESIS the row claims is not the one the birth proves — the
        // 32-zero owner a head-less create used to persist is this shape.
        let mut zero_owner = rec.clone();
        zero_owner.owner_genesis = [0u8; 32];
        write_record(&zero_owner);
        let e = rt
            .block_on(compose_own_vault(&vault_id))
            .expect_err("a row naming another genesis must not compose");
        assert!(e.contains("the genesis disagree"), "{e}");
        write_record(&rec);
        rt.block_on(compose_own_vault(&vault_id))
            .expect("restored again");
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
        let vault_id;
        let root_before;
        let head_before;
        let (pc_a, pc_b);
        {
            let r = router();
            (pc_a, pc_b) =
                crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
            let create = generated::DlvInstantiateV1 {
                spec: Some(generated::DlvSpecV1 {
                    policy_digest: Vec::new(),
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
            "the posture is DERIVED (canonical REQUIRED); no row value can weaken it",
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
        let r = router();
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        // half-written or tampered state takes — a head carrying the real
        // identity and no reserves at all.
        let r2 = router();
        r2.core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::observer_device());
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
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);

        let recipient = vec![0xC7u8; 1184];
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
    /// The trader has no access to the owner's leaves at all — its own head
    /// holds no reserve for the vault — so every fact its settle is gated on
    /// must have arrived as a published, verified artifact. It clears every
    /// gate on those artifacts alone, and is then refused at EMISSION: a
    /// canonical market bundle needs the bundled trader successor evidence,
    /// which no device can produce before 5c-2 Step 2 (2c-A.1 ruling 2, as
    /// amended). What this pins is the fail-closed half of that ruling —
    /// refused after the last gate, before the first mutating op, with nothing
    /// moved on either device. The settle-through lifecycle returns with the
    /// seam.
    ///
    /// Process-global identity is switched between phases; heads and vault
    /// managers are per-router, which is the boundary that matters.
    #[test]
    #[serial]
    fn a_foreign_trader_clears_every_gate_and_binds_to_bound_unrealized() {
        use prost::Message as _;

        install_identity();

        // ── OWNER ────────────────────────────────────────────────────────────
        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        // The OWNER funds from ADMITTED origins. 55_000/20_000 is load-bearing:
        // after the 10_000 leg and the 5_000 it sends the trader, this test
        // pins the owner's spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 55_000, 20_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
            unlock_spec_digest: Vec::new(),
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
        // THE FOREIGN-DEVICE CONDITION, made real rather than nominal: the
        // trader is its own device — own database, registry, identity and
        // head — so it holds NO amm_vault_record and NO copy of the owner's
        // policy. Its whole knowledge of the vault comes from storage, and its
        // whole holding of the input asset came from the owner through a
        // canonical admitted transfer. A settle that needs anything else is a
        // settle that only works on the owner's own device.
        let trader_dev = participant("trader", 0x51);
        let (trader_pk, trader_did) = (trader_dev.ak_pk.clone(), trader_dev.device_id);
        assert_ne!(
            trader_pk, owner_dev.ak_pk,
            "the two devices must be distinct"
        );
        owner_transfers(&owner_dev, &trader_dev, &pc_a, 5_000);
        trader_dev.enter();
        let trader = trader_dev.router();
        assert!(
            crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
                .expect("record read")
                .is_none(),
            "the trader's own database holds no record of the owner's vault"
        );
        // Crucially the trader holds NO reserve for this vault — it does not
        // own the liquidity it trades against.
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
        // leaves OR the owner's record: the discovered path is the trader's
        // only path, and the reserves come OUT of the authenticated state.
        let frontier = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::vault_state_composition::compose_discovered_vault(
                    &vault_id, &pc_a, &pc_b, 30,
                ),
            )
            .expect("the foreign device composes from published artifacts alone");
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
                fee_bps: 30,
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
        // ── BOUND BY A GENUINELY FOREIGN DEVICE, AND NOT REALIZED ───────────
        // The foreign device composed the vault from storage alone, bound its
        // hop to the real c_n, cleared eligibility, quarantine, authority-key
        // and rooting, found the generation free — and now carries the trade
        // through publication, its OWN trader-parent fence and QuorumBind to a
        // committed binding. This is the property that matters most about the
        // whole design: a device holding no owner record and no owner signature
        // can bind a trade against the owner's liquidity while the owner is
        // offline. What it still cannot do is realize it.
        assert!(
            res.success,
            "a foreign trader binds: {:?}",
            res.error_message
        );

        // THE FOREIGN TRADER'S OWN VALUE MOVED, exactly and admissibly: 1,000
        // in, 453 out. A device that holds no owner record and no owner
        // signature has bound a trade against the owner's liquidity while the
        // owner is offline, advanced its own chain to the bound successor, and
        // had its credit admitted.
        let trader_after = trader.core_sdk.device_head().expect("trader head");
        assert_eq!(
            (trader_after.balance(&pc_a), trader_after.balance(&pc_b)),
            (bal_a_before - 1_000, bal_b_before + 453),
            "the foreign trader paid exactly the input and received exactly the derived output"
        );
        assert_ne!(
            trader_after.root(),
            trader_head.root(),
            "and its own head advanced"
        );
        // NOT REALIZED. The binding and the trader's own advance both happened;
        // what has not is realization. No receipt exists, because publishing one
        // would claim a settlement this state has not reached.
        assert!(
            matches!(
                crate::runtime::get_runtime().block_on(
                    crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x)
                ),
                crate::sdk::settlement_receipt_codec::ReceiptFetch::Absent
            ),
            "no receipt was published"
        );
        let after = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::vault_state_composition::compose_discovered_vault(
                    &vault_id, &pc_a, &pc_b, 30,
                ),
            )
            .expect("the vault still composes");
        match after.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(route_set_commitment, x, "bound by THIS foreign trade"),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }
        assert_eq!(
            (after.sequence, after.reserves_a, after.reserves_b),
            (0, 10_000, 5_000),
            "the frontier stops AT the bound parent: reserves move on realization, not binding"
        );
        // The fence is on the FOREIGN TRADER's own chain, not on the vault.
        assert!(
            crate::storage::client_db::trader_parent_fence::active_fence(&vault_id, &frontier.c_n)
                .expect("fence read")
                .is_none(),
            "no VAULT-keyed fence: a market settle fences the trader's own chain position"
        );
        // And the positive half: the fence IS on the FOREIGN trader's own chain,
        // and its own advance did not release it. Absence of a vault-keyed row
        // alone would also be satisfied by no fence existing at all.
        let foreign_rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&trader_did, &trader_did);
        let foreign_parent = trader_head.chain_tip(&foreign_rel_key).unwrap_or_else(|| {
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &trader_did,
                &trader_did,
            )
        });
        let foreign_fence = crate::storage::client_db::trader_parent_fence::active_fence(
            &foreign_rel_key,
            &foreign_parent,
        )
        .expect("trader fence read")
        .expect("the market fence is on the FOREIGN trader's own chain");
        assert!(
            matches!(
                foreign_fence.state,
                dsm::dlv::trader_fence::FenceState::CommittedAwaitingAcceptance { .. }
            ),
            "committed and awaiting acceptance, not Released ({:?})",
            foreign_fence.state
        );

        // ── THE OWNER IS UNTOUCHED, and has nothing to reconcile. ────────────
        owner_dev.enter();
        let owner_after = owner.core_sdk.device_head().expect("owner head");
        assert_eq!(
            (
                owner_after.vault_reserve(&vault_id, &pc_a),
                owner_after.vault_reserve(&vault_id, &pc_b)
            ),
            (10_000, 5_000),
            "the owner's reserves are exactly where funding left them"
        );
        assert_eq!(
            (owner_after.balance(&pc_a), owner_after.balance(&pc_b)),
            (40_000, 15_000),
            "and so is the owner's spendable balance"
        );
        let res = reconcile(owner, &vault_id, &x);
        assert!(!res.success, "there is no settlement to reconcile");
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("no settlement receipt"),
            "the owner sees no receipt for a trade that never emitted: {:?}",
            res.error_message
        );
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
    /// The e2e observable answers with EXACTLY the composed state: the
    /// route runs the discovered-vault path, the helper runs the owner's own
    /// record path, and the two must agree byte-for-byte — the single-device
    /// form of the two-device symmetry claim.
    #[test]
    #[serial]
    fn the_compose_vault_query_answers_with_the_composed_frontier() {
        install_identity();
        let r = router();
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 10_000, 5_000,
        );
        // The discovered path needs the ad, exactly like any stranger.
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: Vec::new(),
            unlock_spec_key: "sofi/spec/observable".to_string(),
            owner_public_key: Vec::new(),
            vault_proto_bytes: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.publishRoutingAdvertisement".to_string(),
                args: pack(publish.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "ad publish failed: {:?}", res.error_message);

        let params = format!(
            "{}:{}:{}:30",
            crate::util::text_id::encode_base32_crockford(&vault_id),
            crate::util::text_id::encode_base32_crockford(&pc_a),
            crate::util::text_id::encode_base32_crockford(&pc_b),
        );
        let res = crate::runtime::get_runtime().block_on(async {
            r.query(crate::bridge::AppQuery {
                path: "dlv.composeVault".to_string(),
                params: params.into_bytes(),
            })
            .await
        });
        assert!(res.success, "composeVault failed: {:?}", res.error_message);
        let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
        let generated::envelope::Payload::AppStateResponse(resp) = env.payload.expect("payload")
        else {
            panic!("unexpected payload")
        };
        let value = resp.value.expect("value");
        let frontier = composed_frontier(&vault_id, &pc_a, &pc_b);
        assert_eq!(
            value,
            format!(
                "0:10000:5000:{}",
                crate::util::text_id::encode_base32_crockford(&frontier.c_n)
            ),
            "the observable is the composed state, byte for byte"
        );
    }

    /// 2c-C3.1 ruling D, effect 4 — the route surfaces. A quarantine root on
    /// this device's own vault refuses the close (the operation that could
    /// carry a verifier past its own root), the walk refuses the same vault,
    /// and the owner's query surface lists the root with both evidence
    /// objects.
    #[test]
    #[serial]
    fn a_quarantined_lineage_refuses_the_close_and_is_listed_by_the_query() {
        use crate::storage::client_db::dlv_lineage_quarantine as quarantine;
        use prost::Message as _;
        install_identity();
        let r = router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 10_000, 5_000,
        );
        let frontier = crate::runtime::get_runtime()
            .block_on(compose_own_vault(&vault_id))
            .expect("composes before any root exists");
        quarantine::quarantine_root(&quarantine::QuarantineRoot {
            vault_id,
            root_c_n: frontier.c_n,
            root_generation: frontier.sequence,
            storage_set_id: frontier.storage_set_id,
            quorum: 2,
            first_evidence: vec![0xA1],
            second_evidence: vec![0xB2],
            insertion_ordinal: 0,
        })
        .expect("root written");

        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.close".to_string(),
                args: pack(
                    generated::DlvCloseV1 {
                        vault_id: vault_id.to_vec(),
                    }
                    .encode_to_vec(),
                ),
            })
            .await
        });
        assert!(!res.success, "a quarantined lineage must not close");
        let msg = res.error_message.unwrap_or_default();
        assert!(msg.contains("LINEAGE_QUARANTINED"), "{msg}");

        assert!(
            crate::runtime::get_runtime()
                .block_on(compose_own_vault(&vault_id))
                .is_err(),
            "the walk refuses the quarantined vault too"
        );

        let res = crate::runtime::get_runtime().block_on(async {
            r.query(crate::bridge::AppQuery {
                path: "dlv.lineageQuarantine".to_string(),
                params: crate::util::text_id::encode_base32_crockford(&vault_id).into_bytes(),
            })
            .await
        });
        assert!(
            res.success,
            "the query lists roots: {:?}",
            res.error_message
        );
        let env = generated::Envelope::decode(&res.data[1..]).expect("envelope");
        let generated::envelope::Payload::AppStateResponse(resp) = env.payload.expect("payload")
        else {
            panic!("unexpected payload")
        };
        let value = resp.value.expect("value");
        let b32 = crate::util::text_id::encode_base32_crockford;
        assert!(
            value.starts_with(&format!("{}:{}:", b32(&frontier.c_n), frontier.sequence)),
            "the root is named: {value}"
        );
        assert!(
            value.ends_with(&format!(":{}:{}", b32(&[0xA1]), b32(&[0xB2]))),
            "both evidence objects are listed: {value}"
        );
    }

    /// The admission check stands on its own: it names a quarantined parent
    /// directly, with no walk in between, so removing the walk's cursor check
    /// leaves this red and removing this leaves that red.
    #[test]
    #[serial]
    fn the_admission_check_refuses_a_quarantined_parent_on_its_own() {
        use crate::storage::client_db::dlv_lineage_quarantine as quarantine;
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
        let vault = [0x5A; 32];
        let root_c_n = [0x5B; 32];
        quarantine::quarantine_root(&quarantine::QuarantineRoot {
            vault_id: vault,
            root_c_n,
            root_generation: 4,
            storage_set_id: [0x55; 32],
            quorum: 2,
            first_evidence: vec![1],
            second_evidence: vec![2],
            insertion_ordinal: 0,
        })
        .expect("root written");
        assert!(
            refuse_quarantined_lineage("t", &vault, 3, &[0x11; 32]).is_ok(),
            "below the root"
        );
        let e = refuse_quarantined_lineage("t", &vault, 4, &root_c_n).expect_err("the root");
        assert!(e.contains("LINEAGE_QUARANTINED"), "{e}");
        assert!(
            refuse_quarantined_lineage("t", &vault, 9, &[0x12; 32]).is_err(),
            "beyond the root, by generation"
        );
        assert!(
            refuse_quarantined_lineage("t", &[0x5C; 32], 9, &root_c_n).is_ok(),
            "another vault is untouched"
        );
    }

    /// THE SINGLE-DEVICE ROUTE, gate by gate, to the emission refusal. The
    /// setup is the full production one — an admitted funded vault, its
    /// advertisement, a verifiable birth state, a RouteCommit bound to the
    /// composed c_n, X and the pointer published — so the refusal proven here
    /// is the LAST thing the route does, not the first gate it hit. Steps (6)
    /// onward pin 2c-A.1 ruling 2 (amended): refused, nothing moved, nothing
    /// emitted, repeatable. The settled lifecycle returns with 5c-2 Step 2.
    #[test]
    #[serial]
    fn a_routed_settle_clears_every_gate_and_binds_to_bound_unrealized() {
        use prost::Message as _;

        install_identity();
        let r = router();
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        // 50_000/20_000: this test pins the POST-LEG spendable balance at
        // (40_000, 15_000), so the funding headroom is load-bearing here.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);

        // (1) FUND a vault through the dispatcher.
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        // The advertisement: the discovery record the pointer publisher (and
        // any trader) resolves the vault through. Production traders always
        // hold one — it is how they found the vault at all.
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: Vec::new(),
            unlock_spec_key: "sofi/spec/settle-test".to_string(),
            owner_public_key: Vec::new(),
            vault_proto_bytes: Vec::new(),
        };
        let res = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "route.publishRoutingAdvertisement".to_string(),
                args: pack(publish.encode_to_vec()),
            })
            .await
        });
        assert!(res.success, "ad publish failed: {:?}", res.error_message);

        // (2) The verified baseline the settling path will read back. Its
        // existence — a P0-P6-verifiable presentation and the exact CCB(V_0)
        // — is the precondition the composition gate enforces.
        let frontier = composed_frontier(&vault_id, &pc_a, &pc_b);
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
                fee_bps: 30,
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
        // (6) BOUND, AND DELIBERATELY NOT REALIZED (5c-2 Step 4). Every gate
        // held, and the route now carries the trade all the way through
        // publication, the trader-parent fence and QuorumBind to a committed
        // binding. It stops there. The refusal that used to stand here was
        // correct only while no producer could build the operands; 5c-2 Step 2
        // built one, so the reason is spent.
        assert!(
            res.success,
            "the market settle binds now: {:?}",
            res.error_message
        );

        // (7) THE END STATE IS BOUND-BUT-UNREALIZED, and every half of that is
        // asserted separately, because "it bound" and "it did not realize" fail
        // in opposite directions.
        //
        // ACCEPTED. The trader advanced its OWN chain to the successor the
        // bundle names, with the economic admission attached, so the value it
        // now holds is foreign-verifiable rather than a raw local credit.
        // The movement is asserted EXACTLY: 1,000 in, 453 out — the
        // constant-product output for this pool and fee. A range check here
        // would pass for a trade that credited the wrong amount.
        let after = r.core_sdk.device_head().expect("head");
        assert_eq!(
            (after.balance(&pc_a), after.balance(&pc_b)),
            (bal_a_before - 1_000, bal_b_before + 453),
            "the trader paid exactly the input and received exactly the derived output"
        );
        assert_ne!(
            after.root(),
            before.root(),
            "the trader's head advanced: that is what accepting the successor means"
        );
        // AND STILL NOT REALIZED. The vault's reserves are the OWNER's leaves
        // and they do not move until realization, which 2c-D gates. This is
        // the half that would silently break if an advance were ever mistaken
        // for a settlement.
        assert_eq!(
            (
                after.vault_reserve(&vault_id, &pc_a),
                after.vault_reserve(&vault_id, &pc_b)
            ),
            (10_000, 5_000),
            "the vault's reserves are untouched until realization"
        );
        assert!(
            matches!(
                crate::runtime::get_runtime().block_on(
                    crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x)
                ),
                crate::sdk::settlement_receipt_codec::ReceiptFetch::Absent
            ),
            "no receipt: publication waits on 2c-D, and a receipt would claim a realized \
             settlement this state has not reached"
        );

        // BOUND. The generation is occupied by THIS trade, named by its own
        // route-set commitment, and the frontier stops at the bound parent.
        let frontier_after = composed_frontier(&vault_id, &pc_a, &pc_b);
        match frontier_after.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(
                route_set_commitment, x,
                "bound by THIS trade, not merely bound"
            ),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }
        assert_eq!(
            frontier_after.c_n, frontier.c_n,
            "the frontier stops AT the bound parent and does not advance past it"
        );

        // THE FENCE IS ON THE TRADER, NOT THE VAULT (requirement 5). The close
        // path fences `(vault_id, c_n)`; a market settle consumes the TRADER's
        // own sovereign chain position, so fencing the vault's identity would
        // fence the wrong thing. The absence of a vault-keyed row is the
        // checkable half of that.
        assert!(
            crate::storage::client_db::trader_parent_fence::active_fence(&vault_id, &frontier.c_n)
                .expect("fence read")
                .is_none(),
            "no VAULT-keyed fence: the market fence is keyed on the trader's own chain"
        );
        // REQUIREMENT 9, POSITIVELY. The fence IS on the trader's own chain,
        // and the advance did NOT release it. Ordinary DSM advancement is not
        // a certifying verdict; Ruling V3 gates release on one, and a market
        // verdict cannot certify until 2c-D. So the fence must still be
        // active — holding the trader's parent — even though the successor it
        // permits has now been accepted.
        let actor = r
            .core_sdk
            .get_current_state()
            .expect("state")
            .device_info
            .device_id;
        let trader_rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        // The parent the fence is keyed on is the trader's chain tip as it
        // stood BEFORE this settle — which is not the initial tip, because the
        // trader's self-loop already advanced when it was funded.
        let trader_parent = before.chain_tip(&trader_rel_key).unwrap_or_else(|| {
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &actor, &actor,
            )
        });
        let fence = crate::storage::client_db::trader_parent_fence::active_fence(
            &trader_rel_key,
            &trader_parent,
        )
        .expect("trader fence read")
        .expect("the market fence is on the TRADER's chain and is still active");
        assert!(
            matches!(
                fence.state,
                dsm::dlv::trader_fence::FenceState::CommittedAwaitingAcceptance { .. }
            ),
            "the fence is committed and AWAITING acceptance, not Released: an ordinary \
             advance is not a fence-release event ({:?})",
            fence.state
        );
        assert!(
            crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
                .expect("load consumer")
                .is_none(),
            "no consume-once claim: that belongs to realization"
        );

        // (8) And the refusal is REPEATABLE — the same request refuses the same
        // way, because nothing it left behind can change the answer.
        let again = crate::runtime::get_runtime().block_on(async {
            r.invoke(AppInvoke {
                method: "dlv.unlockRouted".to_string(),
                args: pack(settle.encode_to_vec()),
            })
            .await
        });
        // NO DOUBLE SPEND. Once the trader has accepted the successor, the
        // same request is REFUSED rather than replayed: its chain has moved,
        // so the retry prepares from a different parent and the quorum finds
        // the vault generation already taken. Refusing is the safe direction —
        // an idempotent "success" here would have to either credit twice or
        // lie about having done anything.
        assert!(
            !again.success,
            "a replayed settle must not be accepted a second time"
        );
        // The assertion that actually matters: the retry moved nothing. A
        // refusal that had already debited would be worse than an acceptance.
        let after_retry = r.core_sdk.device_head().expect("head");
        assert_eq!(
            (after_retry.balance(&pc_a), after_retry.balance(&pc_b)),
            (bal_a_before - 1_000, bal_b_before + 453),
            "the replay credited and debited nothing further"
        );
        assert_eq!(
            (
                after_retry.vault_reserve(&vault_id, &pc_a),
                after_retry.vault_reserve(&vault_id, &pc_b)
            ),
            (10_000, 5_000),
            "and still nothing is realized"
        );
    }

    /// Build a GENUINELY FOREIGN, fully valid settlement receipt: a different
    /// trader device — its own database, identity and keypair, holding the
    /// input asset through an admitted owner→trader transfer — settling the
    /// SAME owner vault at parent generation 0 with a DISTINCT external
    /// commitment `x`. The settle is advanced on the trader's real head
    /// directly rather than through the route, because the route's storage
    /// slot-claim would refuse the second settle locally — and this is
    /// precisely the cross-partition case the slot-claim admits it cannot
    /// prevent, which the durable consume-once claim must catch at reconcile.
    /// The receipt is signed against the trader's post-settle root and
    /// verifies stand-alone (`verify_trader_settlement_receipt` is stateless).
    fn build_foreign_receipt(
        trader: &crate::test_support::two_device::TestDevice,
        vault_id: &[u8; 32],
        pc_in: &[u8; 32],
        pc_out: &[u8; 32],
        x: [u8; 32],
        // What the receipt claims the vault paid. The owner's fold now prices
        // every receipt by the vault's own curve, so a fixture that means to
        // FOLD passes the curve's value and one that means to be REFUSED
        // passes anything else.
        output_amount: u64,
    ) -> dsm::dlv::settlement_receipt_leaf::SignedTraderSettlementReceipt {
        use dsm::core::bilateral_transaction_manager::{
            compute_smt_key, initial_chain_tip_from_device_ids,
        };
        use dsm::types::device_state::{BalanceDelta, BalanceDirection};
        use dsm::types::operations::{Operation, TransactionMode};

        trader.enter();
        let head = trader
            .router()
            .core_sdk
            .device_head()
            .expect("the foreign trader's admitted head");
        let dev = trader.device_id;
        let rel = compute_smt_key(&dev, &dev);
        let init = initial_chain_tip_from_device_ids(&dev, &dev);
        let sign = |op: Operation| -> Operation {
            let sig = dsm::crypto::sphincs::sphincs_sign(
                &trader.ak_sk,
                &op.with_cleared_signature().to_bytes(),
            )
            .expect("sign foreign op");
            op.with_signature(sig)
        };

        let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(vault_id, &x);
        let input_amount = 1_000u64;
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
            settler_public_key: trader.ak_pk.clone(),
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
            &trader.ak_pk,
            &trader.ak_sk,
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
        let owner_dev = participant("owner", 0x41);
        let r = owner_dev.router();
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        // 20_000 of A: 10_000 for the vault leg, 5_000 for each foreign trader.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(r, 20_000, 5_000);

        // Fund an owner vault at generation 0.
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        // Both foreign traders hold the input asset through admitted
        // owner→trader transfers BEFORE either settles: the owner's own sends
        // advance the owner's head, and the property below is that a REFUSED
        // fold moves nothing — so nothing else may move the owner in between.
        let trader_a = participant("trader-a", 0xC1);
        owner_transfers(&owner_dev, &trader_a, &pc_a, 5_000);
        let trader_b = participant("trader-b", 0xC2);
        owner_transfers(&owner_dev, &trader_b, &pc_a, 5_000);

        let x_a = [0xA0u8; 32];
        let receipt_a =
            build_foreign_receipt(&trader_a, &vault_id, &pc_a, &pc_b, x_a, curve_at_birth());
        owner_dev.enter();
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
        let receipt_b =
            build_foreign_receipt(&trader_b, &vault_id, &pc_a, &pc_b, x_b, curve_at_birth());
        owner_dev.enter();
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

    /// What the vault created by these tests pays for 1 000 of A at birth:
    /// 10 000/5 000 reserves at 30 bps, by the ONE canonical implementation.
    fn curve_at_birth() -> u64 {
        crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
            .expect("curve")
    }

    /// THE PRE-SIGN MIRROR. A receipt priced one unit off the vault's own
    /// curve is refused by `dlv.reconcile` BEFORE the owner signs anything:
    /// the refusal is the route's own, it names the curve, and nothing durable
    /// moves — root, both reserve leaves and the consume-once row are
    /// untouched. A receipt priced exactly by the curve then folds. (The core
    /// arm refuses the same fold after signing; this proves the owner never
    /// signs it in the first place.)
    #[test]
    #[serial_test::serial]
    fn a_receipt_priced_off_the_vaults_curve_is_refused_before_the_owner_signs() {
        use prost::Message as _;

        install_identity();
        let owner_dev = participant("owner", 0x43);
        let r = owner_dev.router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(r, 20_000, 5_000);
        // Fund an owner vault at generation 0.
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        let trader = participant("trader-off-curve", 0xC3);
        owner_transfers(&owner_dev, &trader, &pc_a, 5_000);
        let curve = curve_at_birth();
        let root_before = r.core_sdk.device_head().expect("head").root();

        // One unit above the curve: refused before signing, nothing moves.
        let x_bad = [0xD0u8; 32];
        let bad = build_foreign_receipt(&trader, &vault_id, &pc_a, &pc_b, x_bad, curve + 1);
        owner_dev.enter();
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&bad))
            .expect("publish the off-curve receipt");
        let res = reconcile(r, &vault_id, &x_bad);
        assert!(!res.success, "an off-curve receipt must not fold");
        let msg = res.error_message.unwrap_or_default();
        assert!(
            msg.contains("refusing before signing") && msg.contains("curve"),
            "the refusal must be the route's pre-sign curve check, got: {msg}"
        );
        let after = r.core_sdk.device_head().expect("head");
        assert_eq!(
            after.root(),
            root_before,
            "the refused fold left the root unchanged"
        );
        assert_eq!(
            (
                after.vault_reserve(&vault_id, &pc_a),
                after.vault_reserve(&vault_id, &pc_b)
            ),
            (10_000, 5_000),
            "the refused fold moved no reserve"
        );
        assert!(
            crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
                .expect("load claim")
                .is_none(),
            "the refused fold consumed nothing"
        );

        // Exactly the curve: folds, and the generation is consumed by it.
        let x_good = [0xD1u8; 32];
        let good = build_foreign_receipt(&trader, &vault_id, &pc_a, &pc_b, x_good, curve);
        owner_dev.enter();
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&good))
            .expect("publish the curve-priced receipt");
        let res = reconcile(r, &vault_id, &x_good);
        assert!(
            res.success,
            "the curve-priced receipt folds: {:?}",
            res.error_message
        );
        let after = r.core_sdk.device_head().expect("head");
        assert_eq!(
            (
                after.vault_reserve(&vault_id, &pc_a),
                after.vault_reserve(&vault_id, &pc_b)
            ),
            (11_000, 5_000 - curve)
        );
        assert_eq!(
            crate::storage::client_db::load_vault_generation_consumer(&vault_id, 0)
                .expect("load claim")
                .expect("generation 0 is consumed")
                .source_commitment,
            good.receipt_id
        );
    }

    /// THE ADMITTED PRE-STATE MUST CARRY WHAT A WRITE SET DRAWS DOWN.
    ///
    /// An admitted funded create writes both vault-reserve leaves into
    /// `R_econ`, and `finish_admission` caches them with their exact state
    /// CCBs. The producer rebuilds the tree from those same rows — so the root
    /// matched all along — but it used to lift ONLY balance leaves into the
    /// pre-state, which told the write-set builder the reserves were absent
    /// from a root that provably commits them. `DlvOwnerApply` (and `DlvClose`)
    /// read exactly those leaves, so the owner-apply write set could not be
    /// built at all: fail-closed on state the device holds.
    ///
    /// The proposition is the difference, and it is checked both ways: the
    /// produced pre-state builds the owner-apply write set; the balances-only
    /// view of the SAME admitted root refuses it by name. (The write set is a
    /// pure function; the settlement-payment coordinates below are its inputs,
    /// not persisted economic state, and nothing here advances a chain.)
    #[test]
    #[serial_test::serial]
    fn the_admitted_pre_state_carries_the_vault_reserves_an_owner_apply_draws_down() {
        use dsm::economic::write_set::{build_write_set, CreditSourceFacts, EconomicPreState};
        use prost::Message as _;

        install_identity();
        let owner_dev = participant("owner", 0x45);
        let r = owner_dev.router();
        // 20 000 of A and 5 000 of B admitted; 10 000 / 5 000 of it encumbered.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(r, 20_000, 5_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        // The admitted predecessor, and the pre-state derived from it.
        let validated =
            crate::sdk::economic_admission_flow::validated_root_or_activate(&r.core_sdk)
                .expect("the funded create admitted a root");
        let (tree, pre) =
            crate::sdk::economic_admission_flow::producer_tree_and_pre_state(&validated)
                .expect("producer pre-state");

        // Both reserve legs, at the generation the create produced.
        for (pc, amount) in [(pc_a, 10_000u64), (pc_b, 5_000u64)] {
            let leg = pre
                .vault_reserves
                .get(&(vault_id, pc))
                .unwrap_or_else(|| panic!("the admitted root commits a reserve leg for {pc:02x?}"));
            assert_eq!(
                leg.amount, amount,
                "the reserve leg carries its admitted amount"
            );
            assert_eq!(
                leg.vault_sequence, 0,
                "at the vault generation the create produced"
            );
            assert_eq!(leg.vault_id, vault_id);
            assert_eq!(leg.policy_commit, pc);
        }
        // The balance arm is unchanged: what was not encumbered is still there.
        assert_eq!(
            pre.balances.get(&pc_a).copied(),
            Some(10_000),
            "the unencumbered remainder is still an admitted balance"
        );

        // The owner apply this vault would fold: 1 000 of A in, the curve out.
        let head = r.core_sdk.device_head().expect("head");
        let (genesis, devid) = (head.genesis(), head.devid());
        let out_amount =
            crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
                .expect("curve");
        let op = dsm::types::operations::Operation::DlvOwnerApplyV2 {
            vault_id: vault_id.to_vec(),
            settlement_receipt_id: [0x21; 32],
            pending_pointer_x: [0x22; 32],
            parent_sequence: 0,
            new_sequence: 1,
            parent_binding: [0x23; 32],
            input_policy_commit: pc_a,
            output_policy_commit: pc_b,
            input_amount: 1_000,
            output_amount: out_amount,
            fee_bps: 30,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };
        let facts = CreditSourceFacts::DlvSettlementPayment {
            trader_genesis: [0x31; 32],
            trader_devid: [0x32; 32],
            trader_economic_position: 1,
            payment_evidence_addr: [0x33; 32],
        };

        // WITH the produced pre-state: the write set builds, and it moves
        // exactly the two reserve legs.
        let built = build_write_set(
            &op,
            &genesis,
            &devid,
            &[0x44; 32],
            &pre.as_write_set_pre_state(),
            &mut tree.clone(),
            &facts,
            &dsm::economic::write_set::EconomicWriteContext::NonSettlement,
        )
        .expect("the owner-apply write set builds from the admitted reserves");
        assert_eq!(
            built.mutations.len(),
            2,
            "an owner apply moves exactly the input and output reserve legs"
        );

        // WITH the balances-only view of the SAME admitted root: refused by
        // name. This is the gap the producer used to create.
        let err = build_write_set(
            &op,
            &genesis,
            &devid,
            &[0x44; 32],
            &EconomicPreState::balances_only(&pre.balances),
            &mut tree.clone(),
            &facts,
            &dsm::economic::write_set::EconomicWriteContext::NonSettlement,
        )
        .expect_err("a balances-only pre-state cannot see the reserves");
        assert!(
            format!("{err}").contains("no output reserve"),
            "the refusal must name the absent reserve leaf, got: {err}"
        );
    }

    /// THE TRANSPORT, END TO END, ON A REAL ADMISSION.
    ///
    /// A device's register cell publishes WHICH root it committed at a
    /// position. It never published which leaves that root commits, so every
    /// counterparty that must cite one — a trader proving these reserves —
    /// had nothing to fetch. An admitted funded create now publishes an
    /// inclusion proof for the externally citable leaves it wrote, and a
    /// reader holding only the publisher's coordinates, position and root
    /// recomputes them.
    ///
    /// What is proven here is the reader's side: the artifact is fetched by
    /// content address, re-hashed to that address by the fetch, and then
    /// every leaf key, commitment and path is recomputed against the root the
    /// READER names. The address is a locator; naming a different position or
    /// root refuses the same bytes.
    #[test]
    #[serial_test::serial]
    fn an_admitted_create_publishes_an_inclusion_proof_a_stranger_can_verify() {
        use prost::Message as _;

        install_identity();
        let owner_dev = participant("owner", 0x47);
        let r = owner_dev.router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(r, 20_000, 5_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

        // What a stranger would establish for itself from the register.
        let validated =
            crate::sdk::economic_admission_flow::validated_root_or_activate(&r.core_sdk)
                .expect("the create admitted a root");
        let head = r.core_sdk.device_head().expect("head");
        let (genesis, devid) = (head.genesis(), head.devid());

        // The artifact reached the fleet under its own namespace.
        let published: Vec<Vec<u8>> = crate::sdk::storage_io::fake_fleet::put_log()
            .into_iter()
            .filter(|(_, key, _)| key.starts_with("immutable::DSM/economic-proof-artifact/v1::"))
            .filter_map(|(_, key, _)| crate::sdk::storage_io::fake_fleet::any_member_holding(&key))
            .collect();
        assert!(
            !published.is_empty(),
            "the admitted create must publish an inclusion proof for the reserves it wrote"
        );
        let bytes = published.last().expect("one artifact").clone();
        let addr = dsm::storage_object::immutable_inner(
            dsm::common::domain_tags::TAG_DSM_ECONOMIC_PROOF_ARTIFACT,
            &bytes,
        );

        // THE READER. Fetch by address, verify against coordinates it named.
        let artifact = crate::runtime::get_runtime()
            .block_on(
                crate::sdk::economic_registers::fetch_verified_economic_proof(
                    &addr,
                    &genesis,
                    &devid,
                    validated.economic_position(),
                    &validated.economic_root(),
                ),
            )
            .expect("a stranger verifies the artifact against the registered root");

        // Both reserve legs are provable, at the create's vault generation.
        let mut proven: Vec<([u8; 32], u64, u64)> = artifact
            .states()
            .filter_map(|s| match s {
                dsm::economic::state::EconomicLeafState::VaultReserve(v) => {
                    assert_eq!(v.vault_id, vault_id);
                    Some((v.policy_commit, v.amount, v.vault_sequence))
                }
                _ => None,
            })
            .collect();
        proven.sort();
        let mut want = vec![(pc_a, 10_000u64, 0u64), (pc_b, 5_000u64, 0u64)];
        want.sort();
        assert_eq!(
            proven, want,
            "both reserve legs are provable at generation 0"
        );

        // Balance leaves are NOT carried: no evidence type asks a stranger to
        // prove one, and each path would add 8 KiB to every admission.
        assert!(
            artifact
                .states()
                .all(|s| !matches!(s, dsm::economic::state::EconomicLeafState::Balance(_))),
            "balance leaves are the device's own state and are deliberately not published"
        );

        // THE LOCATOR IS NOT A WARRANT. The same bytes, read at a position or
        // a root the reader did not establish, are refused.
        for (name, position, root) in [
            (
                "a position the reader did not establish",
                validated.economic_position() + 1,
                validated.economic_root(),
            ),
            (
                "a root the reader did not establish",
                validated.economic_position(),
                [0x99u8; 32],
            ),
        ] {
            let e = crate::runtime::get_runtime()
                .block_on(
                    crate::sdk::economic_registers::fetch_verified_economic_proof(
                        &addr, &genesis, &devid, position, &root,
                    ),
                )
                .expect_err(name);
            assert!(
                format!("{e}").contains("economic proof artifact"),
                "{name}: {e}"
            );
        }
    }

    /// THE LOCATOR, END TO END, ACROSS TWO DEVICES.
    ///
    /// The owner's admitted create publishes an inclusion proof for the reserve
    /// leaves it wrote, and stamps WHERE it lives onto the vault record; the
    /// advertisement carries that address and the economic position whose
    /// registered root the proof names. A trader on its own device, holding no
    /// record of this vault, reads the advertisement and turns that untrusted
    /// pair into VERIFIED reserve leaves — resolving the position's root from
    /// the owner's own register cell and recomputing every path against it.
    ///
    /// Before this, both halves of the trader's 0x0026 evidence had no source:
    /// the 256-sibling paths existed only inside the owner's tree, and nothing
    /// mapped a vault to its owner's economic position.
    ///
    /// The last two arms are the point of an unsigned advertisement: a locator
    /// naming another position, or another artifact, FAILS. It cannot yield
    /// leaves under a root the owner did not register.
    #[test]
    #[serial]
    fn a_trader_turns_the_advertised_locator_into_verified_owner_reserves() {
        use prost::Message as _;

        install_identity();
        let owner_dev = participant("owner", 0x49);
        let owner = owner_dev.router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 20_000, 5_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        assert!(res.success, "create failed: {:?}", res.error_message);
        let rec = crate::storage::client_db::amm_vault_records::list_amm_vault_records()
            .expect("list")
            .pop()
            .expect("one vault");
        let vault_id = rec.vault_id;

        // (1) The create stamped the locator onto the record.
        let locator = rec
            .economic_proof
            .expect("the admitted create stamps where its reserve proof lives");
        assert_ne!(locator.addr, [0u8; 32]);
        let (owner_genesis, owner_devid) = (rec.owner_genesis, rec.owner_devid);

        // (2) The advertisement carries it.
        let publish = generated::PublishRoutingAdvertisementRequest {
            vault_id: vault_id.to_vec(),
            token_a: pc_a.to_vec(),
            token_b: pc_b.to_vec(),
            fee_bps: 30,
            unlock_spec_digest: Vec::new(),
            unlock_spec_key: "sofi/spec/locator".to_string(),
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

        // ── TRADER: its own device, no record of this vault ──────────────────
        let trader_dev = participant("trader", 0x59);
        trader_dev.enter();
        assert!(
            crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
                .expect("record read")
                .is_none(),
            "the trader holds no record of the owner's vault"
        );
        let ads = crate::runtime::get_runtime()
            .block_on(crate::sdk::routing_sdk::load_all_advertisements_for_pair(
                &pc_a, &pc_b,
            ))
            .expect("advertisements load");
        let ad = ads
            .into_iter()
            .find(|a| a.advertisement.vault_id == vault_id.to_vec())
            .expect("the trader finds the vault through storage alone")
            .advertisement;
        let advertised_addr: [u8; 32] = ad
            .economic_proof_addr
            .as_slice()
            .try_into()
            .expect("the ad carries a 32-byte reserve-proof address");
        assert_eq!(
            advertised_addr, locator.addr,
            "the ad carries the record's locator"
        );
        assert_eq!(ad.economic_proof_position, locator.position);

        // (3) THE READ. The untrusted pair becomes verified leaves.
        let network_id =
            crate::sdk::economic_admission_flow::committed_network_id().expect("network id");
        let set = crate::sdk::economic_admission_flow::canonical_set(&network_id).expect("set");
        let leaves = crate::runtime::get_runtime()
            .block_on(async {
                crate::sdk::economic_registers::verified_owner_reserve_leaves(
                    &set,
                    &network_id,
                    &owner_genesis,
                    &owner_devid,
                    &vault_id,
                    &advertised_addr,
                    ad.economic_proof_position,
                )
            })
            .expect("a trader verifies the owner's reserve leaves from the advertised locator");
        let mut got: Vec<([u8; 32], u64, u64)> = leaves
            .iter()
            .map(|l| (l.policy_commit, l.amount, l.vault_sequence))
            .collect();
        got.sort();
        let mut want = vec![(pc_a, 10_000u64, 0u64), (pc_b, 5_000u64, 0u64)];
        want.sort();
        assert_eq!(
            got, want,
            "both reserve legs, at the create's vault generation"
        );

        // (4) A LOCATOR IS NOT A WARRANT. A different position, or a different
        // artifact, cannot produce leaves under a root the owner registered.
        let network_id2 =
            crate::sdk::economic_admission_flow::committed_network_id().expect("network id");
        let set2 = crate::sdk::economic_admission_flow::canonical_set(&network_id2).expect("set");
        for (name, addr, position) in [
            (
                "another position",
                advertised_addr,
                ad.economic_proof_position + 1,
            ),
            ("another artifact", [0x99u8; 32], ad.economic_proof_position),
        ] {
            let e = crate::runtime::get_runtime().block_on(async {
                crate::sdk::economic_registers::verified_owner_reserve_leaves(
                    &set2,
                    &network_id2,
                    &owner_genesis,
                    &owner_devid,
                    &vault_id,
                    &addr,
                    position,
                )
            });
            assert!(e.is_err(), "{name} must not yield verified leaves");
        }
    }

    /// THE 0x0026 BUNDLE, BUILT BY A TRADER AND ACCEPTED BY THE PRODUCTION
    /// VERIFIER.
    ///
    /// Everything the bundle needs comes from material the trader
    /// authenticated for itself: `CCB(V_n)` re-encoded from the composition
    /// whose commitment the settle names, the owner's authority evidence as
    /// the composition's own anchor presentation resolved it, and the address
    /// of the owner's generic proof artifact located through the
    /// advertisement. The bundle carries NO leaves of its own — the artifact
    /// is the one proof source — and the verifier fetches it, re-hashes it,
    /// and checks it against the owner, position and root the verifier
    /// derived.
    ///
    /// The credit is then driven through the REAL write-set builder from the
    /// trader's REAL admitted pre-state, so the producer is not a helper
    /// nothing consumes.
    ///
    /// The mutation arms each break a different binding, and each must fail
    /// for its own reason: the artifact address, the economic position, the
    /// reserve generation, the vault identity, and the owner authority.
    #[test]
    #[serial]
    fn a_trader_builds_a_reserve_consumption_bundle_the_production_verifier_accepts() {
        use dsm::economic::provenance::{verify_transition_provenance, ProvenanceContext};
        use dsm::economic::witness::EconomicTransitionWitness;
        use dsm::economic::write_set::{build_write_set, CreditSourceFacts};
        use prost::Message as _;

        install_identity();
        let owner_dev = participant("owner", 0x4B);
        let owner = owner_dev.router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 55_000, 20_000);
        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        assert!(res.success, "create failed: {:?}", res.error_message);
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
            unlock_spec_digest: Vec::new(),
            unlock_spec_key: "sofi/spec/0026".to_string(),
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

        // ── TRADER: own device, own database, no record of this vault ───────
        let trader_dev = participant("trader", 0x5B);
        owner_transfers(&owner_dev, &trader_dev, &pc_a, 5_000);
        trader_dev.enter();
        let trader = trader_dev.router();
        assert!(
            crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
                .expect("record read")
                .is_none(),
            "the trader holds no record of the owner's vault"
        );
        let res = crate::runtime::get_runtime().block_on(async {
            trader
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
        assert!(res.success, "sync failed: {:?}", res.error_message);

        // The vault, composed from storage; and the locator, from the ad.
        let composed = composed_frontier(&vault_id, &pc_a, &pc_b);
        let ads = crate::runtime::get_runtime()
            .block_on(crate::sdk::routing_sdk::load_all_advertisements_for_pair(
                &pc_a, &pc_b,
            ))
            .expect("ads load");
        let ad = ads
            .into_iter()
            .find(|a| a.advertisement.vault_id == vault_id.to_vec())
            .expect("the trader finds the vault through storage alone")
            .advertisement;
        let proof_addr: [u8; 32] = ad
            .economic_proof_addr
            .as_slice()
            .try_into()
            .expect("the ad carries the locator");
        let owner_position = ad.economic_proof_position;

        // THE BUNDLE.
        let bundle = crate::sdk::reserve_consumption_producer::build_reserve_consumption_bundle(
            &composed,
            &proof_addr,
        )
        .expect("the trader builds the 0x0026 bundle");
        let network_id =
            crate::sdk::economic_admission_flow::committed_network_id().expect("network id");
        let set = crate::sdk::economic_admission_flow::canonical_set(&network_id).expect("set");
        let publish_immutable =
            |bytes: &[u8], tag: dsm::crypto::domain::TaggedHashDomain<'static>| {
                let outer = dsm::storage_object::immutable_addr(tag, bytes);
                let ns = String::from_utf8_lossy(tag.source_bytes()).to_string();
                let b32 = crate::util::text_id::encode_base32_crockford(&outer);
                crate::runtime::get_runtime()
                    .block_on(crate::sdk::storage_io::put_immutable_to_all_members(
                        &set, &ns, bytes, &b32,
                    ))
                    .expect("publish immutable");
            };
        publish_immutable(
            &bundle.bytes,
            dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        );

        // The trade, signed for real: a RouteCommit bound to the composed
        // parent, its external commitment published, and the settlement slot
        // claimed through the production first-writer register.
        let input: u64 = 1_000;
        let output = crate::sdk::routing_path_sdk::constant_product_output(
            input,
            composed.reserves_a,
            composed.reserves_b,
            30,
        )
        .expect("curve");
        let trader_sk = crate::sdk::signing_authority::current_secret_key().expect("trader sk");
        let trader_pk = trader_dev.ak_pk.clone();
        let mut rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: vec![0x26; 32],
            total_fee_bps: 30,
            initiator_public_key: trader_pk.clone(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vault_id.to_vec(),
                token_in: pc_a.to_vec(),
                token_out: pc_b.to_vec(),
                input_amount_u128: (input as u128).to_be_bytes().to_vec(),
                expected_output_amount_u128: (output as u128).to_be_bytes().to_vec(),
                fee_bps: 30,
                parent_binding: composed.c_n.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            dsm::crypto::sphincs::sphincs_sign(&trader_sk, &canonical).expect("sign rc");
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);
        crate::runtime::get_runtime()
            .block_on(
                crate::sdk::route_commit_sdk::publish_route_anchor_with_pointers(
                    &x,
                    &rc,
                    &trader_pk,
                    &trader_sk,
                    "0026-bundle",
                ),
            )
            .expect("publish anchor + pointers");
        // THE BINDING, through the production driver — no hand-built record.
        // The core verifier this test runs below re-derives k(c_n) itself and
        // re-hashes the bundle, so the bundle bound here has to be the real one.
        let settle_bundle = market_bundle_at(&composed, &pc_a, &pc_b, input, x);
        crate::sdk::binding_fleet_double::register_set(&set);
        let bound = crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_bind::bind_settlement(
                &set,
                [0x2B; 32],
                &settle_bundle,
                vault_id,
                composed.c_n,
            ))
            .expect("drive the settle bind");
        assert_eq!(
            bound,
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the settle's binding must be final before the verifier reads it"
        );

        let settle = {
            let unsigned = dsm::types::operations::Operation::DlvSettle {
                vault_id: vault_id.to_vec(),
                owner_public_key: composed.owner_public_key.clone(),
                owner_devid: composed.owner_devid,
                owner_genesis: composed.owner_genesis,
                input_policy_commit: pc_a,
                output_policy_commit: pc_b,
                parent_sequence: composed.sequence,
                parent_binding: composed.c_n,
                route_commit_bytes: rc.encode_to_vec(),
                external_commitment_x: x,
                input_amount: input,
                output_amount: output,
                fee_bps: 30,
                sigma: [0u8; 32],
                settler_public_key: trader_pk.clone(),
                settler_devid: trader_dev.device_id,
                settlement_receipt_id: dsm::dlv::settlement_receipt_leaf::derive_receipt_id(
                    &vault_id, &x,
                ),
                signature: Vec::new(),
                mode: dsm::types::operations::TransactionMode::Unilateral,
            };
            trader
                .core_sdk
                .sign_operation_sphincs(unsigned)
                .expect("sign the settle")
        };

        // ── THE REAL WRITE-SET BUILDER, from the REAL admitted pre-state ────
        let validated =
            crate::sdk::economic_admission_flow::validated_root_or_activate(&trader.core_sdk)
                .expect("the trader has an admitted root");
        let head = trader.core_sdk.device_head().expect("head");
        let (g, d) = (head.genesis(), head.devid());
        let facts = |addr: [u8; 32], position: u64| CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: position,
            reserve_consumption_evidence_addr: addr,
        };
        let build = |addr: [u8; 32], position: u64| {
            let (mut tree, pre) =
                crate::sdk::economic_admission_flow::producer_tree_and_pre_state(&validated)
                    .expect("producer pre-state");
            let pre_root = tree.root();
            let built = build_write_set(
                &settle,
                &g,
                &d,
                &[0x26; 32],
                &pre.as_write_set_pre_state(),
                &mut tree,
                &facts(addr, position),
                // A settle, so it needs its bundle context. The fixture's `b`
                // is arbitrary because this test is about the provenance arm,
                // not about which bundle was composed.
                &dsm::economic::write_set::EconomicWriteContext::DlvSettle {
                    bundle_id: [0xBB; 32],
                },
            )
            .expect("the settle write set builds from the trader's admitted pre-state");
            EconomicTransitionWitness::new(
                pre_root,
                built.post_root,
                [0x26; 32],
                dsm::economic::faucet::dsm_operation_digest(&settle.to_bytes()),
                built.mutations,
                built.credit_sources,
            )
            .expect("witness")
        };

        // ── THE PRODUCTION VERIFIER ─────────────────────────────────────────
        // One runtime context for the whole verification: the live resolver
        // reads registers and immutable objects through it, so the resolver,
        // every publish and every verify happen inside it rather than nesting
        // block_on calls.
        let ns_evidence = String::from_utf8_lossy(
            dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE.source_bytes(),
        )
        .to_string();
        crate::runtime::get_runtime().block_on(async {
            let resolver = crate::sdk::economic_registers::LiveRegisterResolver {
                set: &set,
                runtime: tokio::runtime::Handle::current(),
                expected_network_id: network_id.clone(),
            };
            let ctx = ProvenanceContext {
                genesis: &g,
                device_id: &d,
                economic_position: validated.economic_position() + 1,
                network_id: &network_id,
                proven_ak: &trader_pk,
                canonical_storage_set_id: set.id(),
                substrate_b_pair: None,
                verified_operation: Some(&settle),
            };
            let verify = |w: &EconomicTransitionWitness| {
                tokio::task::block_in_place(|| verify_transition_provenance(w, &resolver, &ctx))
                    .map_err(|e| format!("{e:?}"))
            };
            let funded = verify(&build(bundle.addr, owner_position))
                .expect("the production 0x0026 verifier accepts the trader-built bundle");
            assert_eq!(funded.len(), 1, "exactly one funded credit");
            assert_eq!(funded[0].policy_commit, pc_b);
            assert_eq!(funded[0].amount, output);

            // Publish a variant bundle and return the address that names it.
            let publish_variant = |bytes: Vec<u8>| {
                let ns = ns_evidence.clone();
                let set = &set;
                async move {
                    let outer = dsm::storage_object::immutable_addr(
                        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
                        &bytes,
                    );
                    let b32 = crate::util::text_id::encode_base32_crockford(&outer);
                    crate::sdk::storage_io::put_immutable_to_all_members(set, &ns, &bytes, &b32)
                        .await
                        .expect("publish variant");
                    dsm::storage_object::immutable_inner(
                        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
                        &bytes,
                    )
                }
            };
            let decoded = |b: &[u8]| {
                generated::ReserveConsumptionEvidenceV1::decode(b).expect("bundle decodes")
            };

            // ── MUTATION ARMS, each breaking a different binding ────────────
            // (1) the artifact address: a bundle naming another proof.
            let mut b = decoded(&bundle.bytes);
            b.economic_proof_addr = vec![0x99; 32];
            let addr = publish_variant(b.encode_to_vec()).await;
            let e = verify(&build(addr, owner_position)).expect_err("another artifact");
            assert!(
                e.contains("immutable object not found"),
                "arm 1 must fail because the named proof does not exist, got: {e}"
            );

            // (2) the economic position: the right artifact, wrong position.
            let e = verify(&build(bundle.addr, owner_position + 1)).expect_err("position");
            assert!(
                e.contains("names economic position"),
                "arm 2 must fail on the artifact's own position binding, got: {e}"
            );

            // (3) the owner authority.
            let mut b = decoded(&bundle.bytes);
            b.owner_authority_evidence = Vec::new();
            let addr = publish_variant(b.encode_to_vec()).await;
            let e = verify(&build(addr, owner_position)).expect_err("authority");
            assert!(
                e.contains("vault-bound owner authority"),
                "arm 3 must fail on the owner's authority evidence, got: {e}"
            );

            // (4) the vault identity and (5) the reserve generation. Both stop
            // hashing to the settle's parent_binding, which is the binding
            // that makes a valid proof of some OTHER state useless here.
            for (name, mutate) in [
                (
                    "another vault",
                    Box::new(|v: &mut dsm::ccb::VaultStateV2| v.vault_id = [0x77; 32])
                        as Box<dyn Fn(&mut dsm::ccb::VaultStateV2)>,
                ),
                (
                    "another generation",
                    Box::new(|v: &mut dsm::ccb::VaultStateV2| v.generation += 1),
                ),
            ] {
                let mut vn = composed.state.clone();
                mutate(&mut vn);
                let mut b = decoded(&bundle.bytes);
                b.exact_vault_state_ccb = vn.encode().expect("encode");
                let addr = publish_variant(b.encode_to_vec()).await;
                let e = verify(&build(addr, owner_position)).expect_err(name);
                assert!(
                    e.contains("does not hash to the settle's parent binding"),
                    "the {name} arm must fail on the parent binding, got: {e}"
                );
            }

            // The honest bundle still funds, so every refusal above is the
            // mutation and not the setup decaying.
            assert!(verify(&build(bundle.addr, owner_position)).is_ok());
        });
    }

    /// One trader's full production settle against `vault_id` at generation
    /// `seq`, whose reserves the trader believes to be `(ra, rb)`: mirror the
    /// vault, bind a hop to `(seq, reserves_digest, anchor_digest)`, sign the
    /// RouteCommit, publish X + pointer, and `dlv.unlockRouted`. `expected_out`
    /// is what the trader claims the curve pays; a well-behaved trader passes
    /// `constant_product_output(input, ra, rb, 30)`, and a probe may lie.
    /// Returns the route result and the external commitment `x`.
    ///
    /// Until 5c-2 Step 2 the route refuses every well-formed settle at
    /// EMISSION (2c-A.1 ruling 2, amended), so this is how a test reaches the
    /// route's gates — the probes — or its emission refusal;
    /// [`trader_settles_by_fixture`] is how it gets a settled generation.
    ///
    /// The caller must have ENTERED this trader's device
    /// (`TestDevice::enter`), so its identity, database and head are active.
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

        // The parent this trade consumes. A caller naming the composed
        // frontier binds its real c_n; a caller deliberately naming some
        // OTHER (already-consumed or not-yet-existing) state gets the c_n of
        // exactly the state it claims — so what refuses it is the vault-side
        // byte-equality gate, not a malformed fixture.
        let frontier = composed_frontier(vault_id, pc_a, pc_b);
        let parent_binding =
            if (frontier.sequence, frontier.reserves_a, frontier.reserves_b) == (seq, ra, rb) {
                frontier.c_n
            } else {
                let mut claimed = frontier.state.clone();
                claimed.generation = seq;
                claimed.reserve_a = ra;
                claimed.reserve_b = rb;
                dsm::ccb::vault_state_commitment(&claimed).expect("claimed state encodes")
            };
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
                fee_bps: 30,
                parent_binding: parent_binding.to_vec(),
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

    /// A DETERMINISTIC per-claimant proposer id for fixture binds.
    /// `local_proposer_id` reads the app's genesis hash, which a fixture trader
    /// need not have installed — and two claimants sharing a proposer would
    /// collide on rounds.
    fn proposer_for(claimant_pk: &[u8]) -> [u8; 32] {
        let mut h = dsm::crypto::blake3::dsm_domain_hasher(
            dsm::common::domain_tags::TAG_DSM_BINDING_KEYSET,
        );
        h.update(b"test-proposer");
        h.update(claimant_pk);
        *h.finalize().as_bytes()
    }

    /// The canonical market bundle a trader binds for ONE hop at `frontier`:
    /// field 2 is the EXACT successor the frozen predicate derives for the
    /// trade (`derive_market_successor`), the operand VDS.COMMON.10.a compares
    /// the bundle against.
    ///
    /// A TEST-ONLY SHORTCUT, and no longer a stand-in for a missing producer:
    /// since 5c-2 Step 4 `dlv.unlockRouted` binds for real, so a test that
    /// wants a bound generation WITHOUT driving the whole route — no trader
    /// advance, no admission — binds this through the production driver
    /// instead. Tests that want the real thing call the route.
    fn market_bundle_at(
        frontier: &crate::sdk::vault_state_composition::ComposedVaultState,
        pc_in: &[u8; 32],
        pc_out: &[u8; 32],
        input: u64,
        x: [u8; 32],
    ) -> dsm::ccb::SettlementBundle {
        use dsm::dlv::successor_validity::{derive_market_successor, DeriveExpected, MarketTerms};
        let successor = match derive_market_successor(
            &frontier.state,
            frontier.c_n,
            &MarketTerms {
                input_policy_commit: *pc_in,
                output_policy_commit: *pc_out,
                input_amount: input,
                fee_bps: frontier.state.fee_policy.fee_bps(),
            },
        ) {
            DeriveExpected::Derived(v) => *v,
            DeriveExpected::Refused(r) => panic!("the fixture trade must derive: {r}"),
        };
        dsm::ccb::settlement::fixtures::market_bundle(frontier.c_n, successor, x)
    }

    /// ONE MARKET GENERATION WITHOUT THE PRODUCER. The trader signs a
    /// RouteCommit bound to the composed frontier's `c_n` and publishes it
    /// under `x`; binds the canonical market bundle for it through the
    /// production driver; settles on its OWN head through the production
    /// advance (the DlvSettle and its two conservation deltas); and publishes
    /// the receipt of that advance. That is everything `dlv.unlockRouted` did
    /// past its gates before 2c-A.1 made market emission fail closed (ruling
    /// 2, amended), and everything 5c-2 Step 2 owes — so what the walk folds
    /// is what it folded before: a bound bundle whose `x` locates a verified
    /// receipt and an eligible RouteCommit naming this parent.
    ///
    /// Returns the trade's `x` and the curve's output. Enters the trader's
    /// device and leaves it entered.
    #[allow(clippy::too_many_arguments)]
    fn trader_settles_by_fixture(
        trader_dev: &crate::test_support::two_device::TestDevice,
        vault_id: &[u8; 32],
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
        gen: u64,
        (ra, rb): (u64, u64),
        input: u64,
        nonce: u8,
    ) -> ([u8; 32], u64) {
        use prost::Message as _;

        trader_dev.enter();
        let trader = trader_dev.router();
        let frontier = composed_frontier(vault_id, pc_a, pc_b);
        assert_eq!(
            (frontier.sequence, frontier.reserves_a, frontier.reserves_b),
            (gen, ra, rb),
            "the composed frontier must be the generation this trade consumes"
        );
        let out = crate::sdk::routing_path_sdk::constant_product_output(input, ra, rb, 30)
            .expect("curve output");
        let (tpk, tsk) = (trader_dev.ak_pk.clone(), trader_dev.ak_sk.clone());

        // The RouteCommit, bound to the exact parent, published under X.
        let mut rc = generated::RouteCommitV1 {
            version: crate::sdk::route_commit_sdk::ROUTE_COMMIT_VERSION,
            nonce: vec![nonce; 32],
            total_fee_bps: 30,
            initiator_public_key: tpk.clone(),
            initiator_signature: Vec::new(),
            hops: vec![generated::RouteCommitHopV1 {
                vault_id: vault_id.to_vec(),
                token_in: pc_a.to_vec(),
                token_out: pc_b.to_vec(),
                input_amount_u128: (input as u128).to_be_bytes().to_vec(),
                expected_output_amount_u128: (out as u128).to_be_bytes().to_vec(),
                fee_bps: 30,
                parent_binding: frontier.c_n.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let canonical =
            crate::sdk::route_commit_sdk::canonicalise_for_commitment(&rc).encode_to_vec();
        rc.initiator_signature =
            dsm::crypto::sphincs::sphincs_sign(&tsk, &canonical).expect("trader signs");
        let x = crate::sdk::route_commit_sdk::compute_external_commitment(&rc);
        crate::runtime::get_runtime()
            .block_on(
                crate::sdk::route_commit_sdk::publish_route_anchor_with_pointers(
                    &x,
                    &rc,
                    &tpk,
                    &tsk,
                    "fixture-settle",
                ),
            )
            .expect("publish anchor + pointers");

        // THE BINDING, through the production driver, in the vault's own set.
        let set = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .resolve(&frontier.storage_set_id)
            .expect("the vault's birth set resolves through this device's catalog")
            .clone();
        crate::sdk::binding_fleet_double::register_set(&set);
        let bundle = market_bundle_at(&frontier, pc_a, pc_b, input, x);
        let bound = crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_bind::bind_settlement(
                &set,
                proposer_for(&tpk),
                &bundle,
                *vault_id,
                frontier.c_n,
            ))
            .expect("drive the bind");
        assert_eq!(
            bound,
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the fixture's bind must commit"
        );

        // THE SETTLE, on the trader's own head, through the production advance.
        // Both legs rooted first, exactly as the route's gate has a trader do
        // before its first mutating op — adoption is open to anyone holding
        // the commit, and the advance refuses an unrooted leg.
        for pc in [pc_a, pc_b] {
            crate::runtime::get_runtime()
                .block_on(require_rooted_market_leg("fixture-settle", pc))
                .expect("the trader roots the market legs");
        }
        let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(vault_id, &x);
        let op = dsm::types::operations::Operation::DlvSettle {
            vault_id: vault_id.to_vec(),
            owner_public_key: frontier.owner_public_key.clone(),
            owner_devid: frontier.owner_devid,
            owner_genesis: frontier.owner_genesis,
            input_policy_commit: *pc_a,
            output_policy_commit: *pc_b,
            parent_sequence: gen,
            parent_binding: frontier.c_n,
            route_commit_bytes: rc.encode_to_vec(),
            external_commitment_x: x,
            input_amount: input,
            output_amount: out,
            fee_bps: 30,
            sigma: [0u8; 32],
            settler_public_key: tpk.clone(),
            settler_devid: trader_dev.device_id,
            settlement_receipt_id: receipt_id,
            signature: Vec::new(),
            mode: dsm::types::operations::TransactionMode::Unilateral,
        };
        let op = trader
            .core_sdk
            .sign_operation_sphincs(op)
            .expect("sign the settle");
        let deltas = vec![
            dsm::types::device_state::BalanceDelta {
                policy_commit: *pc_a,
                direction: dsm::types::device_state::BalanceDirection::Debit,
                amount: input,
            },
            dsm::types::device_state::BalanceDelta {
                policy_commit: *pc_b,
                direction: dsm::types::device_state::BalanceDirection::Credit,
                amount: out,
            },
        ];
        let actor = trader
            .core_sdk
            .get_current_state()
            .expect("state")
            .device_info
            .device_id;
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(&actor, &actor);
        let init_tip = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &actor, &actor,
        );
        trader
            .core_sdk
            .execute_on_relationship(rel_key, actor, op, &deltas, Some(init_tip))
            .expect("the trader's settle advances its own head");

        // THE RECEIPT, off the advanced head.
        let head = trader.core_sdk.device_head().expect("trader head");
        let key = dsm::dlv::settlement_receipt_leaf::settlement_receipt_key(
            &head.genesis(),
            &head.devid(),
            vault_id,
            &receipt_id,
        );
        let siblings = head
            .inclusion_siblings(&key)
            .expect("receipt leaf siblings");
        let receipt = dsm::dlv::settlement_receipt_leaf::sign_trader_settlement_receipt(
            vault_id,
            &receipt_id,
            dsm::dlv::settlement_receipt_leaf::SettledTrade {
                x,
                parent_sequence: gen,
                new_sequence: gen + 1,
                input_policy_commit: *pc_a,
                input_amount: input,
                output_policy_commit: *pc_b,
                output_amount: out,
            },
            &head.genesis(),
            &head.devid(),
            &head.root(),
            siblings,
            &tpk,
            &tsk,
        )
        .expect("sign the receipt");
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_receipt_codec::publish_settlement_receipt(&receipt))
            .expect("publish the receipt");
        (x, out)
    }

    /// The vault's full composed state, as ANY verifier derives it: the
    /// advertisement locates the birth presentation, then `CCB(V_0)` through
    /// P0-P6, plus every verified trader generation folded on. The DISCOVERED
    /// path deliberately — a trader on its own device has no record to compose
    /// from, and the owner must agree with what a stranger derives.
    fn composed_frontier(
        vault_id: &[u8; 32],
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
    ) -> crate::sdk::vault_state_composition::ComposedVaultState {
        crate::runtime::get_runtime()
            .block_on(
                crate::sdk::vault_state_composition::compose_discovered_vault(
                    vault_id, pc_a, pc_b, 30,
                ),
            )
            .expect("the vault composes from its published advertisement and baseline")
    }

    /// Every VAULT object key the fleet has seen a PUT for — the vault-state
    /// and anchor-presentation namespaces. The terminal set's keys are
    /// content-derived, so tests read them back from the delivery log rather
    /// than re-deriving the terminal state by hand. Scoped to the vault's own
    /// namespaces because every economic admission (faucet, issuance,
    /// transfer, settlement) publishes its own immutable evidence to the same
    /// fleet, and those are not what a close is accountable for.
    fn immutable_keys_in_fleet() -> Vec<String> {
        let mut keys: Vec<String> = crate::sdk::storage_io::fake_fleet::put_log()
            .into_iter()
            .filter(|(_, key, _)| {
                key.starts_with("immutable::DSM/vault-state::")
                    || key.starts_with("immutable::DSM/anchor-presentation/v1::")
            })
            .map(|(_, key, _)| key)
            .collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// The composed state as the production QUOTE side sees it, reduced to
    /// `(sequence, reserve_a, reserve_b)`.
    fn composed(vault_id: &[u8; 32], pc_a: &[u8; 32], pc_b: &[u8; 32]) -> (u64, u64, u64) {
        let c = composed_frontier(vault_id, pc_a, pc_b);
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
    /// independent traders each binding and settling its generation, with NO
    /// owner signature or participation on any transition — each generation consumes
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
    ///
    /// Each trader's bind-and-settle goes through `trader_settles_by_fixture`,
    /// which performs — through the production driver and the production
    /// advance — what the route does past its gates. Since 5c-2 Step 4 the
    /// route could drive this itself; the fixture is kept because this test is
    /// about THREE generations of LP reconciliation, and driving the full
    /// route three times would make it a test of the route instead. The probes
    /// Set up an owner, a funded vault at 10,000/5,000, its advertisement, and
    /// `n` funded traders. Returns the vault, the pair, the owner device and
    /// the traders.
    ///
    /// Extracted for the two Step 4 requirement-10 controls below, which need
    /// the same live market but diverge at the settle.
    fn market_with_traders(
        spec_key: &str,
        traders: &[(&'static str, u8)],
    ) -> (
        [u8; 32],
        ([u8; 32], [u8; 32]),
        crate::test_support::two_device::TestDevice,
        Vec<crate::test_support::two_device::TestDevice>,
    ) {
        use prost::Message as _;

        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 75_000, 20_000);
        let traders: Vec<_> = traders
            .iter()
            .map(|(slot, tag)| {
                let t = participant(slot, *tag);
                owner_transfers(&owner_dev, &t, &pc_a, 5_000);
                t
            })
            .collect();
        owner_dev.enter();

        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        assert!(res.success, "create failed: {:?}", res.error_message);
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
            unlock_spec_digest: Vec::new(),
            unlock_spec_key: spec_key.to_string(),
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
        (vault_id, (pc_a, pc_b), owner_dev, traders)
    }

    /// The trader-keyed fence for `dev`, if one exists.
    fn trader_fence_of(
        dev: &crate::test_support::two_device::TestDevice,
    ) -> Option<crate::storage::client_db::trader_parent_fence::TraderFence> {
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &dev.device_id,
            &dev.device_id,
        );
        let head = dev.router().core_sdk.device_head().expect("head");
        let parent = head.chain_tip(&rel_key).unwrap_or_else(|| {
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &dev.device_id,
                &dev.device_id,
            )
        });
        crate::storage::client_db::trader_parent_fence::active_fence(&rel_key, &parent)
            .expect("fence read")
    }

    /// STEP 4 REQUIREMENT 10: publication below quorum leaves NO fence and NO
    /// bind — driven through `dlv.unlockRouted`, not through `bind_settlement`
    /// with a hand-built bundle.
    ///
    /// `bind_settlement`'s own tests already prove the refusal at that layer.
    /// What they cannot show is that the LIVE route reaches it: that the whole
    /// producer path — sign, prepare, produce, resolve the vault's committed
    /// set — runs and then refuses at publication, leaving nothing behind. Two
    /// of three members are down, so publication is attributable at 1 of 3
    /// against a quorum of 2.
    #[test]
    #[serial]
    fn a_settle_whose_publication_misses_quorum_binds_nothing_and_fences_nothing() {
        install_identity();
        let (vault_id, (pc_a, pc_b), _owner_dev, traders) =
            market_with_traders("sofi/spec/pub-quorum", &[("trader0", 0x51)]);

        let trader_dev = &traders[0];
        trader_dev.enter();
        let trader = trader_dev.router();
        let before = trader.core_sdk.device_head().expect("trader head");
        let (ba, bb) = (before.balance(&pc_a), before.balance(&pc_b));
        let frontier_before = composed_frontier(&vault_id, &pc_a, &pc_b);
        assert!(
            trader_fence_of(trader_dev).is_none(),
            "no fence before the attempt"
        );

        // TAKE THE FLEET BELOW QUORUM. n=3, q=2; two down leaves one
        // attributable acceptance, which `put_bundle` refuses.
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-1");
        crate::sdk::storage_io::fake_fleet::fail_member("dsm-node-2");

        let (res, _x) = trader_settles(
            trader,
            &trader_dev.ak_pk.clone(),
            &trader_dev.device_id,
            &vault_id,
            &pc_a,
            &pc_b,
            0,
            (10_000, 5_000),
            1_000,
            crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
                .expect("curve output"),
            0x31,
        );
        assert!(
            !res.success,
            "a settle that cannot publish durably must refuse"
        );
        // NAME THE REFUSAL. Without this the test would also pass if the
        // settle had died earlier for some unrelated reason — which, with two
        // storage members down, is exactly the plausible false pass. The
        // counts prove the whole producer path ran and stopped at the
        // publication quorum: one attributable acceptance out of three,
        // against a required two.
        let why = res.error_message.clone().unwrap_or_default();
        assert!(
            why.contains("PublicationNotDurable")
                && why.contains("accepted: 1")
                && why.contains("required: 2"),
            "the refusal must be the publication quorum itself, got: {why}"
        );

        // NOTHING BEHIND IT. No fence row, no binding, no value moved — the
        // refusal came before the first mutating op, which is the whole claim.
        assert!(
            trader_fence_of(trader_dev).is_none(),
            "a fence row was written despite a non-durable publication"
        );
        let after = trader.core_sdk.device_head().expect("trader head");
        assert_eq!(
            (after.balance(&pc_a), after.balance(&pc_b)),
            (ba, bb),
            "no value moved"
        );
        assert_eq!(
            after.root(),
            before.root(),
            "the trader's head did not advance"
        );

        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-1");
        crate::sdk::storage_io::fake_fleet::heal_member("dsm-node-2");
        let frontier_after = composed_frontier(&vault_id, &pc_a, &pc_b);
        assert_eq!(
            frontier_after.frontier_binding,
            crate::sdk::vault_state_composition::FrontierBinding::Free,
            "the generation is still FREE: nothing was bound"
        );
        assert_eq!(
            (frontier_after.c_n, frontier_after.sequence),
            (frontier_before.c_n, frontier_before.sequence),
            "and the frontier did not move"
        );
    }

    /// STEP 4 REQUIREMENT 10: a conflicting value for the same parent stays
    /// excluded AFTER a commit — at the route, between two real devices.
    ///
    /// The rival is a genuinely distinct trader with its own database,
    /// identity and funding, quoting the same vault generation under a
    /// DIFFERENT external commitment. It must be refused, and — the part that
    /// matters more than the refusal — it must take nothing with it: its own
    /// balances and head unmoved, and the vault still bound by the FIRST
    /// trade rather than by the rival's.
    ///
    /// EXCLUSION DOES NOT REST ON THE EARLY-OUT THIS TEST PINS. Removing the
    /// `BoundUnrealized` arm of the frontier pre-check above and re-running
    /// this test was executed, not reasoned about: the rival then reaches the
    /// settlement register and is refused `ConflictFinal`, and every
    /// nothing-moved assertion below still holds. The pre-check is a liveness
    /// courtesy that declines to price a trade the register would reject; the
    /// register is the authority. Two separate identities are at work and
    /// neither substitutes for the other — the register slot is keyed by the
    /// vault generation, which is what makes two traders rivals at all, while
    /// the fence is keyed by the trader relationship (Step 4 requirement 5).
    #[test]
    #[serial]
    fn a_rival_settle_on_a_committed_parent_is_excluded_and_changes_nothing() {
        install_identity();
        let (vault_id, (pc_a, pc_b), _owner_dev, traders) =
            market_with_traders("sofi/spec/rival", &[("trader0", 0x51), ("rival", 0x52)]);
        let out = crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
            .expect("curve output");

        // THE FIRST TRADE COMMITS.
        let winner = &traders[0];
        winner.enter();
        let (res, first_x) = trader_settles(
            winner.router(),
            &winner.ak_pk.clone(),
            &winner.device_id,
            &vault_id,
            &pc_a,
            &pc_b,
            0,
            (10_000, 5_000),
            1_000,
            out,
            0x41,
        );
        assert!(
            res.success,
            "the first settle binds: {:?}",
            res.error_message
        );
        let bound = composed_frontier(&vault_id, &pc_a, &pc_b);
        match bound.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(route_set_commitment, first_x, "bound by the FIRST trade"),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }

        // THE RIVAL QUOTES THE SAME PARENT under a different commitment.
        let rival = &traders[1];
        rival.enter();
        let rival_router = rival.router();
        let rival_before = rival_router.core_sdk.device_head().expect("rival head");
        let (rba, rbb) = (rival_before.balance(&pc_a), rival_before.balance(&pc_b));
        let (res, rival_x) = trader_settles(
            rival_router,
            &rival.ak_pk.clone(),
            &rival.device_id,
            &vault_id,
            &pc_a,
            &pc_b,
            0,
            (10_000, 5_000),
            1_000,
            out,
            0x42,
        );
        assert_ne!(rival_x, first_x, "a genuinely different trade identity");
        assert!(
            !res.success,
            "a rival on a committed parent must be excluded, not admitted"
        );
        // NAME THE GATE. At HEAD the rival never reaches the register: the
        // route reads the composed frontier first and declines to price a
        // trade it would lose. Pinning the message here is what makes removing
        // that early-out show up as a failure in this named test.
        let why = res.error_message.clone().unwrap_or_default();
        assert!(
            why.contains("bound by another trade"),
            "the rival must be refused against the composed frontier, got: {why}"
        );

        // IT TOOK NOTHING WITH IT.
        let rival_after = rival_router.core_sdk.device_head().expect("rival head");
        assert_eq!(
            (rival_after.balance(&pc_a), rival_after.balance(&pc_b)),
            (rba, rbb),
            "the excluded rival was neither debited nor credited"
        );
        assert_eq!(
            rival_after.root(),
            rival_before.root(),
            "and its own head did not advance"
        );

        // AND THE WINNER STILL OWNS THE PARENT.
        let still = composed_frontier(&vault_id, &pc_a, &pc_b);
        match still.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(
                route_set_commitment, first_x,
                "the parent is still the FIRST trade's, not the rival's"
            ),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }
        assert_eq!(
            (still.c_n, still.sequence),
            (bound.c_n, bound.sequence),
            "and the frontier did not move"
        );
    }

    /// 2c-D PRODUCER ADOPTION, OVER THE LIVE ROUTE: a settled market publishes
    /// the canonical `TA_B` for the bundle it accepted — and realizes nothing.
    ///
    /// The two halves are asserted together on purpose. Producing `TA_B` is the
    /// step that makes realization *possible*, so the risk it introduces is
    /// that something starts treating the artifact's existence as permission.
    /// A test that only proved publication would not notice; a test that only
    /// proved nothing released would pass just as well before the producer
    /// existed. Paired, the failure mode is visible.
    ///
    /// `TA_B` is read back as BYTES. The type has no decoder — deliberately,
    /// because a decoder without §7 behind it invites reading a decoded
    /// acceptance as an accepted one — so the field offsets of registry §5.40
    /// are what this test reads, and `b` is taken from the fence the binding
    /// froze rather than from the artifact being checked.
    #[test]
    #[serial]
    fn a_settled_market_publishes_a_trader_acceptance_and_realizes_nothing() {
        install_identity();
        let (vault_id, (pc_a, pc_b), _owner_dev, traders) =
            market_with_traders("sofi/spec/ta-b", &[("trader0", 0x51)]);

        let trader_dev = &traders[0];
        trader_dev.enter();
        let trader = trader_dev.router();
        // The parent the fence will be keyed by, captured BEFORE the advance:
        // a successful settle moves the trader's chain tip, so reading the
        // fence afterwards from the CURRENT tip finds nothing and would make
        // the release assertion below vacuous.
        let before = trader.core_sdk.device_head().expect("trader head");
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &trader_dev.device_id,
            &trader_dev.device_id,
        );
        let fenced_parent = before.chain_tip(&rel_key).unwrap_or_else(|| {
            dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
                &trader_dev.device_id,
                &trader_dev.device_id,
            )
        });

        let (res, x) = trader_settles(
            trader,
            &trader_dev.ak_pk.clone(),
            &trader_dev.device_id,
            &vault_id,
            &pc_a,
            &pc_b,
            0,
            (10_000, 5_000),
            1_000,
            crate::sdk::routing_path_sdk::constant_product_output(1_000, 10_000, 5_000, 30)
                .expect("curve output"),
            0x61,
        );
        assert!(res.success, "the settle binds: {:?}", res.error_message);

        // `b`, from the fence the binding transaction froze — tx_id is the
        // bundle digest. An independent source from the artifact under test.
        let fence =
            crate::storage::client_db::trader_parent_fence::active_fence(&rel_key, &fenced_parent)
                .expect("fence read")
                .expect("the settle fenced the trader's own parent");
        let b = fence.tx_id;

        // ── THE ARTIFACT REACHED THE FLEET ──────────────────────────────
        let keys: std::collections::BTreeSet<String> =
            crate::sdk::storage_io::fake_fleet::put_log()
                .into_iter()
                .map(|(_, key, _)| key)
                .filter(|k| k.starts_with("immutable::DSM/trader-settlement-acceptance/v2::"))
                .collect();
        assert_eq!(
            keys.len(),
            1,
            "a settled market publishes exactly one trader acceptance: {keys:?}"
        );
        let key = keys.iter().next().expect("one key").clone();
        let bytes = &crate::sdk::storage_io::fake_fleet::any_member_holding(&key)
            .expect("the acceptance is held by a member");
        assert_eq!(
            bytes.len(),
            dsm::economic::trader_acceptance::TRADER_ACCEPTANCE_LEN,
            "registry §5.40 pins 8,308 bytes"
        );
        assert_eq!(&bytes[0..4], &[0x00, 0x11, 0x00, 0x01], "0x0011 schema 1");
        assert_eq!(
            &bytes[4..36],
            before.genesis_digest().as_slice(),
            "the trader's own genesis, not a carried stranger's"
        );
        assert_eq!(
            &bytes[44..48],
            &[0x00, 0x32, 0x00, 0x01],
            "field 3 is the complete nested 0x0032 CCB, envelope included"
        );
        assert_eq!(
            &bytes[48..80],
            b.as_slice(),
            "the acceptance leaf commits the EXACT bundle the binding froze"
        );
        assert_eq!(
            &bytes[112..116],
            &[0x00, 0x00, 0x01, 0x00],
            "u32_be(256) precedes the siblings"
        );
        // CONTENT-ADDRESSED, and by its own canonical identity: the key is
        // derived from these exact bytes under this namespace, whose inner
        // digest IS `ta_B` (pinned by
        // `the_publication_address_is_the_canonical_identity`). So a Def 14.2
        // receipt binding `ta_B` names the object at this key.
        assert_eq!(
            key,
            format!(
                "immutable::DSM/trader-settlement-acceptance/v2::{}",
                crate::util::text_id::encode_base32_crockford(
                    &dsm::storage_object::immutable_addr(
                        dsm::common::domain_tags::TAG_DSM_TRADER_SETTLEMENT_ACCEPTANCE,
                        bytes,
                    )
                )
            ),
            "the published key must be the content address of the published bytes"
        );

        // ── AND NOTHING WAS REALIZED ────────────────────────────────────
        assert!(
            matches!(
                fence.state,
                dsm::dlv::trader_fence::FenceState::CommittedAwaitingAcceptance { .. }
            ),
            "the fence is committed and awaiting acceptance, not Released ({:?})",
            fence.state
        );
        assert!(
            matches!(
                crate::runtime::get_runtime().block_on(
                    crate::sdk::settlement_receipt_codec::fetch_verified_receipt(&vault_id, &x)
                ),
                crate::sdk::settlement_receipt_codec::ReceiptFetch::Absent
            ),
            "no Def 14.2 receipt was published merely because TA_B exists"
        );
        let after = composed_frontier(&vault_id, &pc_a, &pc_b);
        match after.frontier_binding {
            crate::sdk::vault_state_composition::FrontierBinding::BoundUnrealized {
                route_set_commitment,
                ..
            } => assert_eq!(route_set_commitment, x, "still bound, still unrealized"),
            other => panic!("expected BoundUnrealized, got {other:?}"),
        }
        assert_eq!(
            (after.sequence, after.reserves_a, after.reserves_b),
            (0, 10_000, 5_000),
            "the frontier stops AT the bound parent: reserves move on realization"
        );
    }

    /// below still go through the route.
    #[test]
    #[serial]
    fn lp_offline_market_advances_three_generations_and_lp_reconciles_each_once() {
        use prost::Message as _;

        install_identity();
        let cp = |input: u64, ra: u64, rb: u64| -> u64 {
            crate::sdk::routing_path_sdk::constant_product_output(input, ra, rb, 30)
                .expect("curve output")
        };

        // ── OWNER funds a Required-policy vault at generation 0, advertises it,
        //    and then goes OFFLINE (no further owner action until the end). ─────
        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        // The OWNER funds from ADMITTED origins. 75_000/20_000 is load-bearing:
        // after the 10_000 leg and the 5 × 5_000 it sends the market's
        // participants, this test pins the LP's spendable at (40_000, 15_000)
        // and requires it NEVER to move again.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 75_000, 20_000);

        // The market's participants, each on its own device, each holding the
        // input asset only because the LP sent it — before the LP goes away.
        let traders: Vec<_> = [("trader0", 0x51u8), ("trader1", 0x52), ("trader2", 0x53)]
            .into_iter()
            .map(|(slot, tag)| {
                let t = participant(slot, tag);
                owner_transfers(&owner_dev, &t, &pc_a, 5_000);
                t
            })
            .collect();
        let probe_behind = participant("probe-behind", 0x61);
        owner_transfers(&owner_dev, &probe_behind, &pc_a, 5_000);
        let probe_ahead = participant("probe-ahead", 0x62);
        owner_transfers(&owner_dev, &probe_ahead, &pc_a, 5_000);
        owner_dev.enter();

        let create = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
            unlock_spec_digest: Vec::new(),
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
            let trader_dev = &traders[i];
            trader_dev.enter();
            let trader = trader_dev.router();
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
            let (x, paid) = trader_settles_by_fixture(
                trader_dev,
                &vault_id,
                &pc_a,
                &pc_b,
                gen,
                reserves,
                input,
                0x20 + i as u8,
            );
            assert_eq!(paid, out, "the fixture settles at the curve's output");
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
                .verified()
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
            probe_behind.enter();
            let probe = probe_behind.router();
            let (tpk, tdid) = (probe_behind.ak_pk.clone(), probe_behind.device_id);
            let (res, _) = trader_settles(
                probe,
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
            probe_ahead.enter();
            let probe = probe_ahead.router();
            let (tpk, tdid) = (probe_ahead.ak_pk.clone(), probe_ahead.device_id);
            let out_now = cp(300, final_reserves.0, final_reserves.1);
            let (res, _) = trader_settles(
                probe,
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
        owner_dev.enter();
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
        let res = reconcile(owner, &vault_id, &xs[1]);
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
            let res = reconcile(owner, &vault_id, &xs[i]);
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
        let res = reconcile(owner, &vault_id, &xs[2]);
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
    /// The committed member ids of the vault's BIRTH-bound set — and, as a
    /// side effect, that set registered with the binding double.
    ///
    /// The registration is here because every caller of this helper is about to
    /// inject a member failure by id, and the double registers lazily on first
    /// use: an injection made before any binding op would resolve to no member.
    /// `binding_fleet_double` panics loudly on that rather than silently doing
    /// nothing, and this is what keeps it from having to.
    fn vault_storage_members(vault_id: &[u8; 32]) -> Vec<String> {
        let record = crate::storage::client_db::amm_vault_records::get_amm_vault_record(vault_id)
            .expect("record read")
            .expect("the owner has a record for this vault");
        let set = crate::sdk::storage_set::StorageSetCatalog::from_env_config()
            .expect("catalog")
            .resolve(&record.storage_set_id)
            .expect("the vault's birth set resolves through this device's catalog")
            .clone();
        crate::sdk::binding_fleet_double::register_set(&set);
        set.members().iter().map(|m| m.member_id.clone()).collect()
    }

    fn spendable(owner: &AppRouterImpl, pc_a: &[u8; 32], pc_b: &[u8; 32]) -> (u64, u64) {
        let h = owner.core_sdk.device_head().expect("owner head");
        (h.balance(pc_a), h.balance(pc_b))
    }

    /// Fund a vault, let ONE trader move it a generation, and (optionally) fold
    /// that settlement back. Returns `(vault_id, reserves_now, x)` — `x` names
    /// the settlement, so a caller that skipped the fold can perform it later.
    fn vault_after_one_trade(
        owner_dev: &crate::test_support::two_device::TestDevice,
        pc_a: &[u8; 32],
        pc_b: &[u8; 32],
        fold: bool,
    ) -> ([u8; 32], (u64, u64), [u8; 32]) {
        use prost::Message as _;
        owner_dev.enter();
        let owner = owner_dev.router();
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
            unlock_spec_digest: Vec::new(),
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
        let trader_dev = participant("trader", 0x51);
        owner_transfers(owner_dev, &trader_dev, pc_a, 5_000);
        let (x, out) = trader_settles_by_fixture(
            &trader_dev,
            &vault_id,
            pc_a,
            pc_b,
            0,
            (10_000, 5_000),
            1_000,
            0x20,
        );
        owner_dev.enter();
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
        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        // The OWNER funds from ADMITTED origins. 55_000/20_000 is load-bearing:
        // after the 10_000 leg and the 5_000 sent to the trader, this test
        // pins the owner's spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 55_000, 20_000);

        let (vault_id, reserves, _x) = vault_after_one_trade(&owner_dev, &pc_a, &pc_b, true);
        assert_eq!(
            leaves(owner, &vault_id, &pc_a, &pc_b),
            (reserves.0, reserves.1, 1),
            "the fold left the vault at generation 1 with the traded reserves"
        );
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (1, reserves.0, reserves.1),
            "and the market sees the same generation"
        );
        let before = spendable(owner, &pc_a, &pc_b);
        assert_eq!(before, (40_000, 15_000), "funding is still delegated");

        let res = close(owner, &vault_id);
        assert!(res.success, "close failed: {:?}", res.error_message);

        // THE RETURN IS EXACT — the leaf amounts, both legs, nothing rounded.
        assert_eq!(
            spendable(owner, &pc_a, &pc_b),
            (before.0 + reserves.0, before.1 + reserves.1),
            "the close credits exactly what the leaves held"
        );
        // Stated as the round trip: everything funded came back, plus what the
        // market added and minus what it took.
        assert_eq!(
            spendable(owner, &pc_a, &pc_b),
            (51_000, 20_000 - (5_000 - reserves.1)),
            "delegation is a loop: funded out, traded, withdrawn back"
        );

        // THE VAULT IS DEAD — but its leaves are still there, at zero.
        assert_eq!(
            leaves(owner, &vault_id, &pc_a, &pc_b),
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
        let after = spendable(owner, &pc_a, &pc_b);
        let res = close(owner, &vault_id);
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
            spendable(owner, &pc_a, &pc_b),
            after,
            "the refused second close credited nothing"
        );

        // Nothing is left for recovery to finish.
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("resume pass");
        assert_eq!(resumed, 0, "a committed close leaves no unfinished intent");
        assert_eq!(
            spendable(owner, &pc_a, &pc_b),
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
        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        // The OWNER funds from ADMITTED origins. 55_000/20_000 is load-bearing:
        // after the 10_000 leg and the 5_000 sent to the trader, this test
        // pins the owner's spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 55_000, 20_000);

        // Traded, NOT folded: the owner's leaves say generation 0, the market
        // says generation 1.
        let (vault_id, reserves, x) = vault_after_one_trade(&owner_dev, &pc_a, &pc_b, false);
        assert_eq!(leaves(owner, &vault_id, &pc_a, &pc_b), (10_000, 5_000, 0));
        assert_eq!(composed(&vault_id, &pc_a, &pc_b).0, 1);

        let res = close(owner, &vault_id);
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
            leaves(owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "the refused close moved no reserves"
        );
        assert_eq!(
            spendable(owner, &pc_a, &pc_b),
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
        let res = reconcile(owner, &vault_id, &x);
        assert!(res.success, "fold failed: {:?}", res.error_message);
        let res = close(owner, &vault_id);
        assert!(
            res.success,
            "once folded, the same vault must close: {:?}",
            res.error_message
        );
        assert_eq!(
            spendable(owner, &pc_a, &pc_b),
            (40_000 + reserves.0, 15_000 + reserves.1),
            "the close returns the TRADED reserves, not the funded ones"
        );
        assert_eq!(leaves(owner, &vault_id, &pc_a, &pc_b), (0, 0, 2));
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
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        // The OWNER funds from ADMITTED origins. 50_000/20_000 is load-bearing:
        // these tests pin the post-leg spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&owner, 50_000, 20_000);
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
        // THE RIVAL MUST NAME THE VAULT'S REAL c_0.
        //
        // Under the old cell the key was (vault_id, parent_sequence), so a
        // rival could carry a BOGUS parent binding and still land on the cell
        // the owner would read — the walk then rejected it by content. The
        // binding key is DERIVED from `c_n`, so a bogus parent now lands on a
        // DIFFERENT KEY ENTIRELY and the owner would never see it: the test
        // would pass while proving nothing about contention.
        let composed = crate::runtime::get_runtime()
            .block_on(compose_own_vault(&vault_id))
            .expect("the owner composes its own fresh vault");
        assert_eq!(composed.sequence, 0, "a fresh vault is at generation 0");
        let rival_x = [0x99u8; 32];
        let rival_bundle = market_bundle_at(&composed, &pc_a, &pc_b, 300, rival_x);
        let mut proposer = [0u8; 32];
        proposer[..rival_pk.len().min(32)].copy_from_slice(&rival_pk[..rival_pk.len().min(32)]);
        let bound = crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_bind::bind_settlement(
                &set,
                proposer,
                &rival_bundle,
                vault_id,
                composed.c_n,
            ))
            .expect("drive the rival bind");
        assert_eq!(
            bound,
            Ok(dsm::dlv::quorum_bind::Outcome::Committed),
            "the rival binding must be final before the owner tries to close"
        );

        let _ = become_device(0x41);
        let res = close(&owner, &vault_id);
        assert!(!res.success, "the close must lose a contested parent");
        // THE REFUSAL NOW COMES EARLIER, AND SAYS MORE. The close's first act
        // is to establish the vault's frontier by reading the settlement-slot
        // cells at quorum, and that read finds this generation already
        // consumed by a claim it cannot reconcile with the owner's view. So
        // the close stops before it records anything at all — a stronger
        // outcome than the abandoned intent this test used to assert, because
        // there is nothing for any sweep to resurrect.
        //
        // The close's own contested-claim path is NOT dead: it still guards
        // the race where a rival takes the slot between this composition and
        // the owner's own claim.
        let message = res.error_message.as_deref().unwrap_or_default().to_string();
        assert!(
            message.contains("another trade holds this vault generation"),
            "the refusal names the consumed generation: {message}"
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
        assert!(
            crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
                .expect("intent read")
                .is_none(),
            "a close that never established its frontier records no intent"
        );
        let resumed = crate::runtime::get_runtime()
            .block_on(owner.resume_close_intents())
            .expect("resume pass");
        assert_eq!(resumed, 0, "and there is nothing for the sweep to finish");
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "the vault stays open and funded — the safe direction"
        );
    }

    /// A CLOSE WILL NOT ACT ON A FRONTIER IT COULD NOT READ.
    ///
    /// The owner's close consumes an exact generation with exact reserves, so
    /// its first act is a live quorum read of the vault's settlement-slot
    /// cells. With the fleet unreadable, that read establishes nothing — not
    /// "no successor", which is what a single-member listing would have
    /// reported — and the close stops before recording an intent or moving a
    /// unit. The vault stays open and funded, which is the safe direction.
    #[test]
    #[serial]
    fn a_close_refuses_when_the_frontier_cannot_be_read() {
        install_identity();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        // The OWNER funds from ADMITTED origins. 50_000/20_000 is load-bearing:
        // these tests pin the post-leg spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&owner, 50_000, 20_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &owner, &pc_a, &pc_b, 10_000, 5_000,
        );
        let members = vault_storage_members(&vault_id);
        for m in &members {
            crate::sdk::binding_fleet_double::fail_member_id(m);
        }

        let res = close(&owner, &vault_id);
        assert!(!res.success, "a close cannot proceed on an unread frontier");
        let message = res.error_message.as_deref().unwrap_or_default().to_string();
        assert!(
            message.contains("DLV_BINDING_EVIDENCE_UNAVAILABLE"),
            "the refusal names the unavailable binding evidence: {message}"
        );
        assert_eq!(
            leaves(&owner, &vault_id, &pc_a, &pc_b),
            (10_000, 5_000, 0),
            "nothing moved"
        );
        assert_eq!(spendable(&owner, &pc_a, &pc_b), (40_000, 15_000));
        assert!(
            crate::storage::client_db::dlv_close_intent::get_intent(&vault_id, 0)
                .expect("intent read")
                .is_none(),
            "and nothing was recorded to resume"
        );

        // POSITIVE CONTROL: the same close succeeds the moment the frontier is
        // readable again, so the refusal above is the quorum read and not a
        // broken fixture.
        for m in &members {
            crate::sdk::binding_fleet_double::heal_member_id(m);
        }
        let res = close(&owner, &vault_id);
        assert!(
            res.success,
            "close failed once readable: {:?}",
            res.error_message
        );
        assert_eq!(
            spendable(&owner, &pc_a, &pc_b),
            (50_000, 20_000),
            "the recovered close returns the full delegation"
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
    /// A CLOSE THIS DEVICE CANNOT AUTHORIZE MUST CONSUME NOTHING.
    ///
    /// `dlv.close` signs with the device's CURRENT authority key; every
    /// composer verifies under the authority the vault's PARENT committed. When
    /// those differ — a rotated or delegated owner authority — the ORDER of
    /// authorize-vs-bind decides whether the failure is recoverable:
    ///
    ///   preflight first -> refusal, parent untouched, retry still possible
    ///   bind first      -> the application-blind register accepts it, the
    ///                      parent is consumed, and no composer will ever
    ///                      realize it: the vault is permanently unclosable
    ///
    /// This is the router-level control for that ordering, and it exists
    /// because it was missing: a mutation moving the preflight after the bind
    /// left all 34 close tests GREEN. None could construct a signer that fails
    /// the parent's authority, so the preflight's POSITION was unobservable and
    /// the gate was only apparently covered.
    #[test]
    #[serial]
    fn a_close_this_device_cannot_authorize_leaves_the_parent_untouched() {
        install_identity();
        let (_pk, _did) = become_device(0x51);
        let owner = named_router("owner");
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&owner, 50_000, 20_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &owner, &pc_a, &pc_b, 10_000, 5_000,
        );

        // The vault's parent committed device 0x51's authority. Switch the
        // process signing identity: from here the device signs with a key the
        // vault's own state never authorized.
        let (_other_pk, _other_did) = become_device(0x52);

        let res = close(&owner, &vault_id);
        assert!(
            !res.success,
            "a close signed by an authority this vault's parent never committed must refuse"
        );

        // AND THE PARENT IS UNTOUCHED. This is the half the ordering buys: no
        // occupancy was consumed, so the vault is still closable by whoever
        // does hold its committed authority.
        let composed = crate::runtime::get_runtime()
            .block_on(compose_own_vault(&vault_id))
            .expect("the vault still composes");
        assert_eq!(
            composed.frontier_binding,
            crate::sdk::vault_state_composition::FrontierBinding::Free,
            "a refused close must consume NOTHING — a bound parent here would be a \
             permanently unclosable vault"
        );
    }

    #[test]
    #[serial]
    fn an_interrupted_close_is_completed_by_the_resume_pass_with_identical_bytes() {
        install_identity();
        let (_pk, _did) = become_device(0x41);
        let owner = named_router("owner");
        // The OWNER funds from ADMITTED origins. 50_000/20_000 is load-bearing:
        // these tests pin the post-leg spendable balance at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&owner, 50_000, 20_000);
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &owner, &pc_a, &pc_b, 10_000, 5_000,
        );
        assert!(
            baseline_is_published(&vault_id),
            "the vault must be born and published before this test unplugs the fleet"
        );

        // The fleet stops ACCEPTING mid-close while still ANSWERING. The
        // members are the vault's OWN — read from the set it was born under —
        // because a hardcoded member name that matches nothing fails nothing,
        // and the test would then assert a refusal against a fleet that was
        // never down.
        //
        // Reads must keep working: a close first establishes the vault's
        // frontier by reading the settlement-slot cells at quorum, and a close
        // that cannot read its own frontier stops before it has anything to
        // resume (proved separately by
        // `a_close_refuses_when_the_frontier_cannot_be_read`). The
        // interruption this test is about happens LATER — the claim cannot
        // reach quorum — which is exactly where a resumable intent is left.
        let members = vault_storage_members(&vault_id);
        assert!(
            members.len() >= 2,
            "this test needs a set whose quorum can actually be lost, got {members:?}"
        );
        for m in &members {
            crate::sdk::binding_fleet_double::refuse_writes_id(m);
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
        // THE FENCE is what the close retained. It names the bundle by content
        // identity and holds the ballot the interrupted attempt reached, so
        // recovery resumes ABOVE that ballot rather than re-opening at zero.
        let fence = crate::storage::client_db::trader_parent_fence::active_fence(
            &vault_id,
            &crate::runtime::get_runtime()
                .block_on(compose_own_vault(&vault_id))
                .expect("the owner composes its own vault")
                .c_n,
        )
        .expect("fence read")
        .expect("the close fenced its parent before going out");

        // The fleet accepts again. RECOVERY drives the binding to a terminal
        // outcome — it is the ONE mechanism that re-drives a QuorumBind
        // transaction — and only then does the close pass finalize locally.
        for m in &members {
            crate::sdk::binding_fleet_double::accept_writes_id(m);
        }
        crate::runtime::get_runtime()
            .block_on(crate::sdk::settlement_resume::recover_all())
            .expect("restart recovery pass");
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

        // ONE BUNDLE IDENTITY ACROSS THE OUTAGE. The register identifies a
        // transaction BY the value its record names, so this is the property
        // that decides whether recovery keeps the binding the close already
        // holds rather than opening a second one.
        //
        // Projected onto (tx_id, value_digest, value_addr) and NOT the whole
        // record: rounds and ballots legitimately differ across a recovery —
        // that is the protocol working, and digesting the full record would
        // fail on exactly the behaviour this test exists to prove.
        let proposed: std::collections::BTreeSet<([u8; 32], [u8; 32], [u8; 32])> =
            crate::sdk::binding_fleet_double::cas_log()
                .into_iter()
                .map(|(_, _, r)| (r.tx_id, r.value_digest, r.value_addr))
                .collect();
        assert_eq!(
            proposed.len(),
            1,
            "every attempt, before and after the outage, proposed ONE bundle identity"
        );
        assert_eq!(
            proposed.into_iter().next(),
            Some((fence.tx_id, fence.tx_id, fence.value_addr)),
            "…and that identity is the one the fence froze (tx_id = value_digest = b)"
        );
        // The bundle bytes themselves went out exactly once as a content
        // address, so one identity above means one object below.
        let bundle_keys: std::collections::BTreeSet<String> =
            crate::sdk::storage_io::fake_fleet::put_log()
                .into_iter()
                .map(|(_, key, _)| key)
                .filter(|k| k.starts_with("immutable::DSM/settlement-bundle::"))
                .collect();
        assert_eq!(
            bundle_keys.len(),
            1,
            "one settlement bundle was published across the outage: {bundle_keys:?}"
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
        let owner_dev = participant("owner", 0x41);
        let owner = owner_dev.router();
        // The OWNER funds from ADMITTED origins: a 10_000 leg, 5_000 to the
        // trader and 5_000 to the probe leave it at (40_000, 15_000).
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(owner, 60_000, 20_000);
        let (vault_id, reserves, _x) = vault_after_one_trade(&owner_dev, &pc_a, &pc_b, true);

        // The probe learns the vault while it is still live and funded.
        let probe_dev = participant("probe-dead-market", 0x54);
        let (tpk, tdid) = (probe_dev.ak_pk.clone(), probe_dev.device_id);
        owner_transfers(&owner_dev, &probe_dev, &pc_a, 5_000);
        probe_dev.enter();
        let probe = probe_dev.router();
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
        owner_dev.enter();
        let res = close(owner, &vault_id);
        assert!(res.success, "close failed: {:?}", res.error_message);
        assert_eq!(
            composed(&vault_id, &pc_a, &pc_b),
            (2, 0, 0),
            "the market composes the vault as dead"
        );

        // The probe settles against the reserves the vault held before the
        // close, at the generation the close produced.
        probe_dev.enter();
        let out =
            crate::sdk::routing_path_sdk::constant_product_output(300, reserves.0, reserves.1, 30)
                .expect("curve output on the pre-close reserves");
        let (res, _x) = trader_settles(
            probe, &tpk, &tdid, &vault_id, &pc_a, &pc_b, 2, reserves, 300, out, 0x40,
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
        // The claimed parent — generation 2 with the PRE-close reserves — is a
        // state this vault never held, so the byte-equality gate refuses it
        // before the curve is even consulted. (Under the old three-field gate
        // the sequence matched and the refusal fell through to the AMM
        // re-simulation against the zero reserves; the binding subsumes both.)
        assert!(
            msg.contains("binds a different parent state"),
            "the refusal is the parent-binding gate, on the vault's own composed state: {msg}"
        );
        let h = probe.core_sdk.device_head().expect("probe head");
        assert_eq!(
            (h.balance(&pc_a), h.balance(&pc_b)),
            probe_before,
            "the refused trade moved none of the probe's value"
        );

        // …and the vault is still dead: a refused settle cannot revive it.
        owner_dev.enter();
        assert_eq!(leaves(owner, &vault_id, &pc_a, &pc_b), (0, 0, 2));
    }

    /// Only the creating owner can close. A device with no record of the vault
    /// has no pair, no fee and no birth-bound storage set for it — everything
    /// the close derives — so it is refused before any of it is guessed.
    #[test]
    #[serial]
    fn a_vault_this_device_never_created_cannot_be_closed() {
        install_identity();
        let owner = named_router("owner");
        owner
            .core_sdk
            .set_device_head_for_testing(crate::sdk::funded_vault_fixture::observer_device());
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
        // Two ADMITTED assets, created by this device under their display
        // names — which is what the route resolves for the screen.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        assert_eq!(v.token_a_ticker, ticker_of(&pc_a));
        assert_eq!(v.token_b_ticker, ticker_of(&pc_b));
        let mut names = [v.token_a_ticker.as_str(), v.token_b_ticker.as_str()];
        names.sort_unstable();
        assert_eq!(names, ["AAA", "BBB"], "both created assets, by name");
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
        // Fixed byte patterns, NOT the rooted fixture pair: this test's
        // subject is the WIRE (the naive tag scan below reads raw bytes, and
        // a real commit can legitimately contain 0x8A/0x92 in its hash). No
        // route or policy is involved here.
        let (pc_a, pc_b) = ([0xA1u8; 32], [0xB2u8; 32]);

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
        let pc_a = [0x7Eu8; 32];

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
        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 10_000, 5_000);
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
        let (reloaded, _) = crate::storage::client_db::bcr::decode_device_state(&encoded, None)
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
            "the rehydrated posture is DERIVED (canonical REQUIRED), never read from the row"
        );
        assert_eq!(
            v.policy_digest.to_vec(),
            dsm::ccb::dlv_policy_digest(
                &dsm::ccb::ReleasePolicy::beta_owner_local_full_close(),
                &dsm::ccb::FeePolicy::new(30).expect("fee")
            )
        );
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

        // Two ADMITTED assets: faucet ERA, then create+mint. The commits come
        // back from the funding because they do not exist until the tokens do.
        // 50_000/20_000: two 10_000/5_000 vaults, and the remainder is pinned.
        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);

        let req = || generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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

    /// A RECORD WHOSE HEAD COMMIT WAS LOST refuses creation rather than being
    /// adopted.
    ///
    /// A vault's id is derived from the creator, the spec AND the reference
    /// state hash, so on an honest head no later request can ever re-derive
    /// an id whose reserve leaves already sit in that head — the leaves moved
    /// the hash. The inconsistency a creation CAN meet is the other one: a
    /// record persisted under an id the current head derives, with no reserves
    /// behind it — a head commit lost to a restored backup or a tampered
    /// database. That is corrupted durable state, constructed here as an
    /// explicit invalid vector from two REAL states: the head before the
    /// creation, reinstalled behind the record the creation wrote.
    ///
    /// Completing a partial prior creation from inside a value-moving
    /// constructor is a repair, and a repair belongs in an explicit recovery
    /// operation where it can be audited.
    #[test]
    #[serial]
    fn an_inconsistent_record_refuses_creation_rather_than_being_adopted() {
        install_identity();
        let r = router();

        let (pc_a, pc_b) =
            crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 50_000, 20_000);
        let head_before = r.core_sdk.device_head().expect("the funded head");
        let vault_id = crate::sdk::funded_vault_fixture::create_funded_amm_vault(
            &r, &pc_a, &pc_b, 10_000, 5_000,
        );
        assert!(
            crate::storage::client_db::amm_vault_records::get_amm_vault_record(&vault_id)
                .expect("record read")
                .is_some(),
            "precondition: the creation wrote its record"
        );

        // THE CORRUPTION: the head commit is lost — the device is back on the
        // head it held before the creation, while the record survived.
        r.core_sdk.set_device_head_for_testing(head_before.clone());
        assert_eq!(
            r.core_sdk
                .device_head()
                .expect("head")
                .vault_reserve(&vault_id, &pc_a),
            0,
            "precondition: this head holds no reserves for the recorded vault"
        );

        // The SAME creation again derives the SAME id — same creator, same
        // spec, same reference state — and meets its own record with nothing
        // behind it. It must refuse, naming the inconsistency, and move nothing.
        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
            !res.success,
            "creation over an inconsistent record must be refused"
        );
        assert!(
            res.error_message
                .as_deref()
                .unwrap_or_default()
                .contains("inconsistent state"),
            "the refusal names the inconsistency, not an incidental failure: {:?}",
            res.error_message
        );
        assert_eq!(
            r.core_sdk.device_head().expect("head").root(),
            head_before.root(),
            "a refused creation moves nothing"
        );
    }

    /// Creation that cannot be paid for changes nothing — no balance moves, and
    /// no record is left behind for a restart to resurrect a vault from.
    #[test]
    #[serial]
    fn an_unaffordable_creation_leaves_no_record_and_no_encumbrance() {
        install_identity();
        let r = router();

        // Holding 100 of each from admitted origins; asking to encumber far more.
        let (pc_a, pc_b) = crate::sdk::funded_vault_fixture::admitted_device_holding(&r, 100, 100);
        let root_before = r.core_sdk.device_head().expect("head").root();

        let req = generated::DlvInstantiateV1 {
            spec: Some(generated::DlvSpecV1 {
                policy_digest: Vec::new(),
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
