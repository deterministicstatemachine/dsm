// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two-device cert-head forward resync — the online b0x flow.
//!
//! Three legs over the existing UniversalTx tag (no new payload tag, no fleet
//! redeploy), each discriminated by an explicit invoke method:
//!
//!   initiate  (8XK)  --certResyncRequest-->  (D3) handle_request
//!   handle_request (D3) --certResyncAck-->    (8XK) handle_ack
//!   handle_ack (8XK)  = finalize: both heads installed, send-gate cleared.
//!
//! ASYMMETRIC re-root: the initiator (head-loss side) re-roots its own Local head
//! from a fresh EK and installs the responder's asserted Local head as its
//! Counterparty; the responder ONLY CAS-advances the stale Counterparty head it
//! holds for the initiator and leaves its own healthy Local head untouched. Each
//! Local head is only ever changed by its owner.
//!
//! Every mutation is gated by: both-device AK cosignatures, a strictly-monotonic
//! per-relationship epoch, one pending resync per relationship, and the
//! non-bypassable core (`storage::client_db::cert_resync`).

use dsm::crypto::sphincs::{sphincs_sign, sphincs_verify};
use dsm::types::error::DsmError;

use crate::storage::client_db::{
    self, cert_resync_signing_target, cert_resync_status, compute_joint_auth_hash,
    finalize_cert_resync_atomically, finalize_cert_resync_responder_atomically, CertChainSide,
    CertResyncAck, CertResyncRequest, LocalResyncKey, ResyncAudit, CERT_RESYNC_ACK_METHOD,
    CERT_RESYNC_REQUEST_METHOD, RESYNC_PENDING,
};

fn err<T>(msg: impl Into<String>) -> Result<T, DsmError> {
    Err(DsmError::invalid_operation(msg.into()))
}

/// Derive the deterministic fresh EK for a resync epoch. Re-derivable, so the
/// ack handler reconstructs the exact key the request advertised.
fn derive_resync_ek(
    rel_key: &[u8; 32],
    agreed_tip: &[u8; 32],
    joint: &[u8; 32],
    epoch: i64,
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let s_master = crate::init::current_smaster()?;
    let mut k_step = [0u8; 32];
    k_step[..8].copy_from_slice(&epoch.to_le_bytes());
    let ctx = crate::sdk::receipts::PerStepEkContext {
        chain_id: *rel_key,
        h_n: *agreed_tip,
        c_pre: *joint,
        k_step,
    };
    crate::sdk::receipts::derive_per_step_ek(&ctx, &s_master)
}

/// Find the contact that forms `rel_key` with this device, returning
/// `(device_id_bytes, genesis, ak_pubkey)`.
fn peer_for_relationship(
    self_device: &[u8; 32],
    rel_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>), DsmError> {
    let contacts = client_db::get_all_contacts()
        .map_err(|e| DsmError::internal(format!("contacts load: {e}"), None::<std::io::Error>))?;
    for c in contacts {
        let cd: [u8; 32] = match c.device_id.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let rk = dsm::core::bilateral_transaction_manager::compute_smt_key(&cd, self_device);
        if &rk == rel_key {
            let genesis: [u8; 32] = c
                .genesis_hash
                .as_slice()
                .try_into()
                .map_err(|_| DsmError::invalid_operation("peer genesis not 32 bytes"))?;
            if c.public_key.is_empty() {
                return err("peer contact has no AK public key for cosign verification");
            }
            return Ok((cd, genesis, c.public_key));
        }
    }
    err("no contact forms this relationship")
}

/// Resolve just the peer device id for a relationship (used by the poller's
/// auto-initiate). `None` if no contact forms it.
pub(crate) fn peer_device_for_relationship(
    self_device: &[u8; 32],
    rel_key: &[u8; 32],
) -> Option<[u8; 32]> {
    peer_for_relationship(self_device, rel_key)
        .ok()
        .map(|(d, _, _)| d)
}

impl super::app_router_impl::AppRouterImpl {
    /// INITIATE (head-loss side). Build and send the resync request to the peer.
    pub(crate) async fn initiate_cert_resync(
        &self,
        to_device_id: [u8; 32],
        storage_endpoints: Vec<String>,
    ) -> Result<(), DsmError> {
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id_bytes,
            &to_device_id,
        );

        // Anchor: the last accepted transition this restart is bound to.
        let proposal = client_db::get_finalized_proposal_for_relationship(&rel_key)
            .map_err(|e| DsmError::internal(format!("anchor load: {e}"), None::<std::io::Error>))?
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "cert resync: no finalized accepted transition to anchor the restart to",
                )
            })?;
        let commitment = proposal.commitment;
        let agreed_tip = proposal.projection_target; // the address both sides converge on
        let accepted_parent = proposal.canonical_parent;
        let accepted_child = proposal.canonical_child;

        let epoch = cert_resync_status(&rel_key)
            .map_err(|e| DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>))?
            .1
            + 1;
        client_db::begin_cert_resync(&rel_key, epoch)
            .map_err(|e| DsmError::invalid_operation(format!("begin resync: {e}")))?;

        let joint = compute_joint_auth_hash(&rel_key, &agreed_tip, epoch, &commitment);
        let (ek_pk_a, _ek_sk_a) = derive_resync_ek(&rel_key, &agreed_tip, &joint, epoch)?;
        let (_ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let intent_sig = sphincs_sign(&ak_sk, &cert_resync_signing_target(&joint, &ek_pk_a))?;
        let _ = (accepted_parent, accepted_child); // carried by the responder's audit lookup

        let (peer_device, peer_genesis, _peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;

        // Tell the responder EXACTLY where to address the ack: the route THIS
        // device polls for this relationship. The initiator's own tip may have
        // diverged from `agreed_tip`, so addressing the ack to `agreed_tip` would
        // strand it.
        let local_genesis = crate::sdk::app_state::AppState::get_genesis_hash()
            .and_then(|g| <[u8; 32]>::try_from(g.as_slice()).ok())
            .unwrap_or([0u8; 32]);
        let reply_to_tip = client_db::get_contact_by_device_id(&peer_device)
            .ok()
            .flatten()
            .and_then(|c| {
                super::app_router_impl::relationship_tip_for_contact_restore(
                    self.device_id_bytes,
                    local_genesis,
                    &c,
                )
            })
            .unwrap_or(agreed_tip);

        let req = CertResyncRequest {
            relationship_key: rel_key,
            agreed_tip,
            epoch,
            preserved_acceptance_commitment: commitment,
            reply_to_tip,
            initiator_ek_pubkey: ek_pk_a,
            intent_sig,
        };

        let sender_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        let mut b0x =
            crate::sdk::b0x_sdk::B0xSDK::new(sender_b32, self.core_sdk.clone(), storage_endpoints)?;
        b0x.submit_cert_resync_message(
            CERT_RESYNC_REQUEST_METHOD,
            req.to_body(),
            &peer_genesis,
            &peer_device,
            &agreed_tip,
        )
        .await?;
        log::info!(
            "[cert-resync] request sent to {}.. epoch={epoch}",
            crate::util::text_id::encode_base32_crockford(&peer_device)
                .chars()
                .take(8)
                .collect::<String>()
        );
        Ok(())
    }

    /// RESPONDER (healthy peer). Verify the request, CAS-advance the stale
    /// Counterparty head, and reply with an ack asserting our own Local head.
    pub(crate) async fn handle_cert_resync_request(
        &self,
        body: &[u8],
        storage_endpoints: Vec<String>,
    ) -> Result<(), DsmError> {
        let req = CertResyncRequest::from_body(body)
            .ok_or_else(|| DsmError::invalid_operation("cert resync request: malformed body"))?;
        let rel_key = req.relationship_key;

        let (initiator_device, initiator_genesis, initiator_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;

        // Cosign check: the initiator's AK authorized exactly this EK + restart.
        let joint = compute_joint_auth_hash(
            &rel_key,
            &req.agreed_tip,
            req.epoch,
            &req.preserved_acceptance_commitment,
        );
        let target = cert_resync_signing_target(&joint, &req.initiator_ek_pubkey);
        if !sphincs_verify(&initiator_ak, &target, &req.intent_sig).unwrap_or(false) {
            return err("cert resync request: initiator cosignature failed verification");
        }

        // We must be HEALTHY on this relationship: our own Local head present and a
        // (stale) Counterparty head to advance. Otherwise this is two-sided loss —
        // out of scope; refuse.
        let responder_local_head =
            client_db::load_cert_chain_head_pubkey(&rel_key, CertChainSide::Local)
                .ok()
                .flatten()
                .ok_or_else(|| {
                    DsmError::invalid_operation(
                "cert resync request: responder has no Local head (two-sided loss) — refusing",
            )
                })?;
        let stale_counterparty =
            client_db::load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
                .ok()
                .flatten();

        // Anchor evidence for the audit row (best-effort from our own record).
        let (accepted_parent, accepted_child) =
            client_db::get_finalized_proposal_for_relationship(&rel_key)
                .ok()
                .flatten()
                .map(|p| (p.canonical_parent, p.canonical_child))
                .unwrap_or(([0u8; 32], req.agreed_tip));

        finalize_cert_resync_responder_atomically(
            &rel_key,
            req.epoch,
            &req.initiator_ek_pubkey,
            stale_counterparty.as_deref(),
            ResyncAudit {
                preserved_acceptance_commitment: &req.preserved_acceptance_commitment,
                accepted_parent_tip: &accepted_parent,
                accepted_child_tip: &accepted_child,
                joint_auth_hash: &joint,
                reason_code: "peer-head-loss",
            },
            &responder_local_head,
        )
        .map_err(|e| DsmError::invalid_operation(format!("responder finalize: {e}")))?;

        // Assert our (unchanged) Local head back to the initiator.
        let (_ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let assert_sig = sphincs_sign(
            &ak_sk,
            &cert_resync_signing_target(&joint, &responder_local_head),
        )?;
        let ack = CertResyncAck {
            relationship_key: rel_key,
            agreed_tip: req.agreed_tip,
            epoch: req.epoch,
            preserved_acceptance_commitment: req.preserved_acceptance_commitment,
            responder_local_head,
            assert_sig,
        };

        let sender_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        let mut b0x =
            crate::sdk::b0x_sdk::B0xSDK::new(sender_b32, self.core_sdk.clone(), storage_endpoints)?;
        b0x.submit_cert_resync_message(
            CERT_RESYNC_ACK_METHOD,
            ack.to_body(),
            &initiator_genesis,
            &initiator_device,
            &req.reply_to_tip,
        )
        .await?;
        log::info!(
            "[cert-resync] responder advanced counterparty + acked epoch={}",
            req.epoch
        );
        Ok(())
    }

    /// INITIATOR (head-loss side). Verify the ack and FINALIZE: install both heads,
    /// clear the send-gate.
    pub(crate) async fn handle_cert_resync_ack(&self, body: &[u8]) -> Result<(), DsmError> {
        let ack = CertResyncAck::from_body(body)
            .ok_or_else(|| DsmError::invalid_operation("cert resync ack: malformed body"))?;
        let rel_key = ack.relationship_key;

        // Must be a PENDING resync at exactly this epoch.
        let (state, epoch) = cert_resync_status(&rel_key).map_err(|e| {
            DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
        })?;
        if state != RESYNC_PENDING || epoch != ack.epoch {
            return err(format!(
                "cert resync ack: no matching pending resync (state={state} epoch={epoch} ack={})",
                ack.epoch
            ));
        }

        let (_peer_device, _peer_genesis, peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;

        let joint = compute_joint_auth_hash(
            &rel_key,
            &ack.agreed_tip,
            ack.epoch,
            &ack.preserved_acceptance_commitment,
        );
        let target = cert_resync_signing_target(&joint, &ack.responder_local_head);
        if !sphincs_verify(&peer_ak, &target, &ack.assert_sig).unwrap_or(false) {
            return err("cert resync ack: responder cosignature failed verification");
        }

        // Re-derive OUR fresh EK (deterministic — same as the request advertised).
        let (ek_pk_a, ek_sk_a) = derive_resync_ek(&rel_key, &ack.agreed_tip, &joint, ack.epoch)?;
        let at_rest_key = crate::init::current_chain_head_at_rest_key()?;

        let (accepted_parent, accepted_child) =
            client_db::get_finalized_proposal_for_relationship(&rel_key)
                .ok()
                .flatten()
                .map(|p| (p.canonical_parent, p.canonical_child))
                .unwrap_or(([0u8; 32], ack.agreed_tip));

        finalize_cert_resync_atomically(
            &rel_key,
            ack.epoch,
            LocalResyncKey {
                pubkey: &ek_pk_a,
                secret_key: &ek_sk_a,
                wrap_key: &at_rest_key,
            },
            None, // our Local head is absent → GenesisInit
            &ack.responder_local_head,
            None, // our Counterparty head is absent → GenesisInit
            ResyncAudit {
                preserved_acceptance_commitment: &ack.preserved_acceptance_commitment,
                accepted_parent_tip: &accepted_parent,
                accepted_child_tip: &accepted_child,
                joint_auth_hash: &joint,
                reason_code: "head-loss-recovery",
            },
        )
        .map_err(|e| DsmError::invalid_operation(format!("initiator finalize: {e}")))?;

        log::info!(
            "[cert-resync] FINALIZED epoch={} — both heads installed, send-gate cleared",
            ack.epoch
        );
        Ok(())
    }
}
