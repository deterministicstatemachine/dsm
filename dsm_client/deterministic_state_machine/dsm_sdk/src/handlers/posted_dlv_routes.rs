// SPDX-License-Identifier: MIT OR Apache-2.0
//! Posted-mode DLV query / invoke routes.
//!
//! * `posted_dlv.list` (query): enumerate active advertisements addressed to
//!   the local device's Kyber public key.  Read-only — does not mirror
//!   anything locally.  Useful for UI "you have N new vaults" badges.
//!
//! * `posted_dlv.sync` (invoke): mirror every active advertisement into the
//!   local `DLVManager` so a subsequent `dlv.claim` call can succeed.
//!   Verifies the advertisement digest against the full `VaultPostProto`
//!   and runs `LimboVault::from_vault_post` (which checks the creator's
//!   SPHINCS+ signature) before inserting.  Returns the Base32 vault_ids
//!   that were newly mirrored in this sync.
//!
//! Security: neither route touches the hash chain.  The authoritative
//! state advance happens later in `dlv.claim` via `execute_on_relationship`.
//! A recipient seeing a forged advertisement fails closed at
//! `fetch_and_verify_vault_post` (digest mismatch) or at
//! `LimboVault::from_vault_post` (signature mismatch).

use dsm::types::proto as generated;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_envelope_ok};

impl AppRouterImpl {
    /// Query dispatch for `posted_dlv.*` read-only paths.
    pub(crate) async fn handle_posted_dlv_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "posted_dlv.list" => self.posted_dlv_list().await,
            other => err(format!("unknown posted_dlv query path: {other}")),
        }
    }

    /// Invoke dispatch for `posted_dlv.*` mutating paths.
    pub(crate) async fn handle_posted_dlv_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "posted_dlv.sync" => self.posted_dlv_sync().await,
            other => err(format!("unknown posted_dlv invoke method: {other}")),
        }
    }

    /// List active posted-mode DLV advertisements addressed to the local
    /// device's Kyber public key.  Returns a newline-separated string of
    /// `"dlv_id_b32 creator_pk_b32"` pairs in `AppStateResponse.value` so
    /// callers (and tests) can assert on the surface without a new proto.
    /// A later commit can promote this to a typed `PostedDlvListResponse`.
    async fn posted_dlv_list(&self) -> AppResult {
        let recipient_pk = match self.wallet.get_kyber_public_key() {
            Ok(pk) if !pk.is_empty() => pk,
            Ok(_) => return err("posted_dlv.list: local Kyber public key is empty".into()),
            Err(e) => return err(format!("posted_dlv.list: get_kyber_public_key failed: {e}")),
        };

        let ads =
            match crate::sdk::posted_dlv_sdk::load_active_advertisements_for_recipient(&recipient_pk)
                .await
            {
                Ok(v) => v,
                Err(e) => return err(format!("posted_dlv.list: load failed: {e}")),
            };

        let lines: Vec<String> = ads
            .iter()
            .map(|p| {
                format!(
                    "{} {}",
                    crate::util::text_id::encode_base32_crockford(&p.advertisement.dlv_id),
                    crate::util::text_id::encode_base32_crockford(
                        &p.advertisement.creator_public_key
                    ),
                )
            })
            .collect();
        let value = lines.join("\n");
        let resp = generated::AppStateResponse {
            key: "posted_dlv.list".to_string(),
            value: Some(value),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }

    /// Fetch + verify + mirror every active advertisement addressed to the
    /// local device into the local `DLVManager`.  Idempotent — vaults
    /// already present are skipped.  Returns the newline-separated Base32
    /// vault_ids that were freshly inserted this call.
    async fn posted_dlv_sync(&self) -> AppResult {
        let recipient_pk = match self.wallet.get_kyber_public_key() {
            Ok(pk) if !pk.is_empty() => pk,
            Ok(_) => return err("posted_dlv.sync: local Kyber public key is empty".into()),
            Err(e) => return err(format!("posted_dlv.sync: get_kyber_public_key failed: {e}")),
        };

        let ads =
            match crate::sdk::posted_dlv_sdk::load_active_advertisements_for_recipient(&recipient_pk)
                .await
            {
                Ok(v) => v,
                Err(e) => return err(format!("posted_dlv.sync: load failed: {e}")),
            };

        let dlv_manager = self.bitcoin_tap.dlv_manager();
        let mut newly_mirrored: Vec<[u8; 32]> = Vec::new();

        for published in ads {
            let ad = &published.advertisement;
            if ad.dlv_id.len() != 32 {
                log::warn!(
                    "[posted_dlv.sync] skipping: ad.dlv_id not 32 bytes (len={})",
                    ad.dlv_id.len()
                );
                continue;
            }
            let mut dlv_id = [0u8; 32];
            dlv_id.copy_from_slice(&ad.dlv_id);

            // Idempotency: if DLVManager already has it, skip.
            if dlv_manager.get_vault(&dlv_id).await.is_ok() {
                continue;
            }

            let post_proto =
                match crate::sdk::posted_dlv_sdk::fetch_and_verify_vault_post(ad).await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!(
                            "[posted_dlv.sync] skipping {}: fetch_and_verify failed: {e}",
                            crate::util::text_id::encode_base32_crockford(&ad.dlv_id)
                        );
                        continue;
                    }
                };

            let post = match dsm::vault::limbo_vault::VaultPost::try_from(&post_proto) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!(
                        "[posted_dlv.sync] skipping {}: VaultPost conversion failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&ad.dlv_id)
                    );
                    continue;
                }
            };

            let vault = match dsm::vault::limbo_vault::LimboVault::from_vault_post(&post) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!(
                        "[posted_dlv.sync] skipping {}: from_vault_post (signature/commitment) failed: {e}",
                        crate::util::text_id::encode_base32_crockford(&ad.dlv_id)
                    );
                    continue;
                }
            };

            if let Err(e) = dlv_manager.add_vault(vault).await {
                log::warn!(
                    "[posted_dlv.sync] add_vault failed for {}: {e}",
                    crate::util::text_id::encode_base32_crockford(&ad.dlv_id)
                );
                continue;
            }
            newly_mirrored.push(dlv_id);
        }

        let value = newly_mirrored
            .iter()
            .map(|id| crate::util::text_id::encode_base32_crockford(id))
            .collect::<Vec<_>>()
            .join("\n");
        let resp = generated::AppStateResponse {
            key: "posted_dlv.sync".to_string(),
            value: Some(value),
        };
        pack_envelope_ok(generated::envelope::Payload::AppStateResponse(resp))
    }
}
