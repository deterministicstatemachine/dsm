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
//! non-bypassable local core (`storage::client_db::cert_resync`). The joint
//! statement, the bytes each AK signs, the cosignature check and the epoch rule
//! are Core's (`dsm::bilateral::cert_resync`), computed once for both sides.

use dsm::bilateral::cert_resync::{
    cert_resync_signing_target, compute_joint_auth_hash, verify_cert_resync_cosignature,
    CosignatureRefusal,
};
use dsm::crypto::sphincs::sphincs_sign;
use dsm::types::error::DsmError;

use crate::storage::client_db::{
    self, cert_resync_status, finalize_cert_resync_atomically,
    finalize_cert_resync_responder_atomically, CertChainSide, CertResyncAck, CertResyncRequest,
    LocalResyncKey, ResyncAudit, CERT_RESYNC_ACK_METHOD, CERT_RESYNC_REQUEST_METHOD,
    RESYNC_PENDING,
};

fn err<T>(msg: impl Into<String>) -> Result<T, DsmError> {
    Err(DsmError::invalid_operation(msg.into()))
}

/// Why a cert-resync message read from the inbox was not taken.
#[derive(Debug)]
pub(crate) enum CertResyncRefusal {
    /// The message's own bytes say it never will be taken: its body does not
    /// decode, or its cosignature does not verify under the AK this device
    /// pins for the relationship's peer. It is passed over by its content, so
    /// it is not read and refused again on every sync.
    NotRecognized(DsmError),
    /// It could not be taken now (storage, network, no matching resync); it
    /// is read again.
    Failed(DsmError),
}

impl From<DsmError> for CertResyncRefusal {
    fn from(e: DsmError) -> Self {
        Self::Failed(e)
    }
}

impl std::fmt::Display for CertResyncRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRecognized(e) => write!(f, "not recognized: {e}"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

fn not_recognized<T>(msg: &str) -> Result<T, CertResyncRefusal> {
    Err(CertResyncRefusal::NotRecognized(
        DsmError::invalid_operation(msg),
    ))
}

/// A refused cosignature, each reason kept as itself. A signature that is not
/// one, or that does not verify, is the message's own: it never will be taken.
/// An AK this device pins for the peer that is not a key, or a verifier that
/// refused its inputs, is no verdict on the message; it is read again.
fn cosignature_refused<T>(what: &str, refusal: CosignatureRefusal) -> Result<T, CertResyncRefusal> {
    let error = DsmError::invalid_operation(format!("{what}: {refusal}"));
    match refusal {
        CosignatureRefusal::MalformedSignature { .. } | CosignatureRefusal::DoesNotVerify => {
            Err(CertResyncRefusal::NotRecognized(error))
        }
        CosignatureRefusal::MalformedKey { .. } | CosignatureRefusal::VerifierError(_) => {
            Err(CertResyncRefusal::Failed(error))
        }
    }
}

/// The epoch this device's next resync of `rel_key` takes: one past the last.
/// A contact's resync request can raise the stored epoch as far as it likes; at
/// the top there is no next one, which is an error for that relationship
/// alone, never an overflow panic inside the sync every route runs through
/// (SA-146).
pub(crate) fn next_resync_epoch(rel_key: &[u8; 32]) -> Result<i64, DsmError> {
    let (_state, current) = cert_resync_status(rel_key)
        .map_err(|e| DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>))?;
    current.checked_add(1).ok_or_else(|| {
        DsmError::invalid_operation(
            "cert resync: this relationship's epochs are spent; it cannot be resynced",
        )
    })
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

/// The contact that forms `rel_key` with this device, as
/// `(device_id_bytes, genesis, ak_pubkey)`; `None` when no contact forms it.
fn find_peer_for_relationship(
    self_device: &[u8; 32],
    rel_key: &[u8; 32],
) -> Result<Option<([u8; 32], [u8; 32], Vec<u8>)>, DsmError> {
    let contacts = client_db::get_all_contacts()
        .map_err(|e| DsmError::internal(format!("contacts load: {e}"), None::<std::io::Error>))?;
    for c in contacts {
        let cd: [u8; 32] = c.device_id.as_slice().try_into().map_err(|_| {
            DsmError::invalid_operation(format!(
                "a stored contact's device id is {} bytes, not 32",
                c.device_id.len()
            ))
        })?;
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
            return Ok(Some((cd, genesis, c.public_key)));
        }
    }
    Ok(None)
}

fn peer_for_relationship(
    self_device: &[u8; 32],
    rel_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>), DsmError> {
    find_peer_for_relationship(self_device, rel_key)?
        .ok_or_else(|| DsmError::invalid_operation("no contact forms this relationship"))
}

/// The peer device of a relationship (the poller's auto-initiate); `None`
/// when no contact forms it.
pub(crate) fn peer_device_for_relationship(
    self_device: &[u8; 32],
    rel_key: &[u8; 32],
) -> Result<Option<[u8; 32]>, DsmError> {
    Ok(find_peer_for_relationship(self_device, rel_key)?.map(|(d, _, _)| d))
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

        let epoch = next_resync_epoch(&rel_key)?;
        client_db::begin_cert_resync(&rel_key, epoch)
            .map_err(|e| DsmError::invalid_operation(format!("begin resync: {e}")))?;

        let joint = compute_joint_auth_hash(&rel_key, &agreed_tip, epoch, &commitment);
        let (ek_pk_a, _ek_sk_a) = derive_resync_ek(&rel_key, &agreed_tip, &joint, epoch)?;
        let (_ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let intent_sig = sphincs_sign(&ak_sk, &cert_resync_signing_target(&joint, &ek_pk_a))?;

        let (peer_device, peer_genesis, _peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;

        // Tell the responder EXACTLY where to address the ack: the route THIS
        // device polls for this relationship. The initiator's own tip may have
        // diverged from `agreed_tip`, so addressing the ack to `agreed_tip` would
        // strand it.
        let peer_contact = client_db::get_contact_by_device_id(&peer_device)
            .map_err(|e| {
                DsmError::storage(format!("cert-resync: contact: {e}"), None::<std::io::Error>)
            })?
            .ok_or_else(|| DsmError::relationship("cert-resync: the peer is not a contact"))?;
        let reply_to_tip = super::app_router_impl::contact_relationship_tip(&peer_contact)
            .map_err(DsmError::relationship)?;

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
    ) -> Result<(), CertResyncRefusal> {
        let Some(req) = CertResyncRequest::from_body(body) else {
            return not_recognized("cert resync request: malformed body");
        };
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
        if let Err(refusal) = verify_cert_resync_cosignature(
            &initiator_ak,
            &joint,
            &req.initiator_ek_pubkey,
            &req.intent_sig,
        ) {
            return cosignature_refused(
                "cert resync request: the initiator's cosignature",
                refusal,
            );
        }

        // We must be HEALTHY on this relationship: our own Local head present and a
        // (stale) Counterparty head to advance. Otherwise this is two-sided loss —
        // out of scope; refuse.
        let head = |side| {
            client_db::load_cert_chain_head_pubkey(&rel_key, side).map_err(|e| {
                DsmError::storage(
                    format!("cert resync request: cert-chain head unreadable: {e}"),
                    None::<std::io::Error>,
                )
            })
        };
        let responder_local_head = head(CertChainSide::Local)?.ok_or_else(|| {
            DsmError::invalid_operation(
                "cert resync request: responder has no Local head (two-sided loss) — refusing",
            )
        })?;
        let stale_counterparty = head(CertChainSide::Counterparty)?;

        finalize_cert_resync_responder_atomically(
            &rel_key,
            req.epoch,
            &req.initiator_ek_pubkey,
            stale_counterparty.as_deref(),
            ResyncAudit {
                preserved_acceptance_commitment: &req.preserved_acceptance_commitment,
                agreed_tip: &req.agreed_tip,
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
    pub(crate) async fn handle_cert_resync_ack(
        &self,
        body: &[u8],
    ) -> Result<(), CertResyncRefusal> {
        let Some(ack) = CertResyncAck::from_body(body) else {
            return not_recognized("cert resync ack: malformed body");
        };
        let rel_key = ack.relationship_key;

        // Must be a PENDING resync at exactly this epoch.
        let (state, epoch) = cert_resync_status(&rel_key).map_err(|e| {
            DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
        })?;
        // An ack below the relationship's current epoch answers a request
        // this device has since replaced. Epochs only rise, so it never will
        // match: it is passed over by its content (§6.104), not read again.
        if ack.epoch < epoch {
            return not_recognized(&format!(
                "cert resync ack: epoch {} is below this relationship's current {epoch}",
                ack.epoch
            ));
        }
        if state != RESYNC_PENDING || epoch != ack.epoch {
            return Err(CertResyncRefusal::Failed(DsmError::invalid_operation(
                format!(
                "cert resync ack: no matching pending resync (state={state} epoch={epoch} ack={})",
                ack.epoch
            ),
            )));
        }

        let (_peer_device, _peer_genesis, peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;

        let joint = compute_joint_auth_hash(
            &rel_key,
            &ack.agreed_tip,
            ack.epoch,
            &ack.preserved_acceptance_commitment,
        );
        if let Err(refusal) = verify_cert_resync_cosignature(
            &peer_ak,
            &joint,
            &ack.responder_local_head,
            &ack.assert_sig,
        ) {
            return cosignature_refused("cert resync ack: the responder's cosignature", refusal);
        }

        // Re-derive OUR fresh EK (deterministic — same as the request advertised).
        let (ek_pk_a, ek_sk_a) = derive_resync_ek(&rel_key, &ack.agreed_tip, &joint, ack.epoch)?;
        let at_rest_key = crate::init::current_chain_head_at_rest_key()?;

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
                agreed_tip: &ack.agreed_tip,
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

#[cfg(test)]
mod tests {
    use crate::storage::client_db::{self as cdb, CertChainSide};
    use crate::test_support::two_device::{Pair, TestDevice};
    use serial_test::serial;

    /// One statement on `device`'s store.
    fn execute(device: &TestDevice, sql: &str, params: impl rusqlite::Params) {
        device.enter();
        cdb::get_connection()
            .expect("the store")
            .lock()
            .expect("the store's lock")
            .execute(sql, params)
            .expect(sql);
    }

    /// The AK `device` pins for `peer`, replaced with `ak`.
    fn pin(device: &TestDevice, peer: &TestDevice, ak: &[u8]) {
        execute(
            device,
            "UPDATE contacts SET public_key = ?1 WHERE device_id = ?2",
            rusqlite::params![ak, peer.device_id.as_slice()],
        );
    }

    fn head(device: &TestDevice, rel: &[u8; 32], side: CertChainSide) -> Option<Vec<u8>> {
        device.enter();
        cdb::load_cert_chain_head_pubkey(rel, side).expect("the head reads")
    }

    /// `(state, epoch)` of `device`'s resync of `rel`.
    fn resync_state(device: &TestDevice, rel: &[u8; 32]) -> (i64, i64) {
        device.enter();
        cdb::cert_resync_status(rel).expect("the resync state reads")
    }

    /// A lost both of its cert-chain heads on its relationship with B after a
    /// finalized transfer, and asks B to restart the chain. B takes the
    /// request only under the AK B pins for A:
    /// - under a pinned AK that is not a key, the request is not judged: it is
    ///   read again, and B's head for A does not move;
    /// - under another AK, the cosignature does not verify: the request is
    ///   passed over, and B's head for A does not move;
    /// - under A's own AK, A's requests are taken. A asked twice, so B's ack
    ///   for the first answers a request A replaced: A refuses it as below its
    ///   epoch and finalizes on the second. Both sides end at that epoch with
    ///   nothing pending: B's head for A is A's restarted head, A holds B's
    ///   unchanged head, and B's own head is untouched.
    /// - a further sync on each side is clean: no resync starts again and the
    ///   replaced ack is not read again.
    /// - A's next transfer is held by B and reported as held, with its reason:
    ///   the open defect §6.117 records.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_resync_request_is_taken_only_under_the_ak_the_responder_pins() {
        let p = Pair::boot(100, 0).await;
        let sent = p.a.send(&p.b, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.b.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        let finalized = p.a.sync().await;
        assert!(finalized.success, "{:?}", finalized.errors);

        let rel = p.a.rel_key_with(&p.b);
        let lost = head(&p.a, &rel, CertChainSide::Local).expect("A's head before the loss");
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(lost.clone())
        );
        execute(
            &p.a,
            "DELETE FROM cert_chain_heads WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
        );
        p.a.enter();
        cdb::mark_cert_resync_required(&rel).expect("the head loss is marked");
        p.a.sync().await;
        assert_eq!(resync_state(&p.a, &rel).0, cdb::RESYNC_PENDING);

        pin(&p.b, &p.a, &p.a.ak_pk[1..]);
        let unjudged = p.b.sync().await;
        assert!(
            unjudged
                .errors
                .iter()
                .any(|e| e.contains("not an SPX256f public key") && !e.contains("passed over")),
            "{:?}",
            unjudged.errors
        );
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(lost.clone())
        );

        let other = dsm::crypto::sphincs::generate_sphincs_keypair()
            .expect("another AK")
            .0;
        pin(&p.b, &p.a, &other);
        let refused = p.b.sync().await;
        assert!(
            refused
                .errors
                .iter()
                .any(|e| e.contains("does not verify") && e.contains("passed over")),
            "{:?}",
            refused.errors
        );
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(lost.clone())
        );

        // B pins A's AK again. A asks twice before B answers, so one of B's
        // acks will answer a request A has since replaced.
        pin(&p.b, &p.a, &p.a.ak_pk);
        let own = head(&p.b, &rel, CertChainSide::Local).expect("B's own head");
        p.a.sync().await;
        let replaced = resync_state(&p.a, &rel).1;
        p.a.sync().await;
        let (_, epoch) = resync_state(&p.a, &rel);
        assert!(epoch > replaced, "A asked again under a later epoch");
        let answered = p.b.sync().await;
        assert!(answered.errors.is_empty(), "{:?}", answered.errors);

        // A finalizes on the ack for its current epoch; the one for the epoch
        // it replaced is refused as below it.
        let finished = p.a.sync().await;
        assert_eq!(finished.errors.len(), 1, "{:?}", finished.errors);
        assert!(
            finished.errors[0].contains(&format!("epoch {replaced} is below")),
            "{:?}",
            finished.errors
        );
        assert_eq!(
            resync_state(&p.a, &rel),
            (cdb::RESYNC_CLEAR, epoch),
            "A finalized at its current epoch and owes nothing"
        );
        assert_eq!(
            resync_state(&p.b, &rel),
            (cdb::RESYNC_CLEAR, epoch),
            "B recorded the same epoch and is not blocked"
        );
        let fresh = head(&p.a, &rel, CertChainSide::Local).expect("A's restarted head");
        assert_ne!(fresh, lost);
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(fresh),
            "B's head for A is A's restarted head"
        );
        assert_eq!(
            head(&p.a, &rel, CertChainSide::Counterparty),
            Some(own.clone()),
            "A holds B's head"
        );
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Local),
            Some(own),
            "B's own head is untouched"
        );

        // A further sync on each side is clean: no resync starts again, and
        // the replaced ack is not read again.
        let again = p.a.sync().await;
        assert!(again.errors.is_empty(), "{:?}", again.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_CLEAR, epoch));
        let quiet = p.b.sync().await;
        assert!(quiet.errors.is_empty(), "{:?}", quiet.errors);

        // OPEN DEFECT (§6.117), asserted as it stands until the owner rules on
        // how a restart is made portable; then this becomes "applied". A's
        // next transfer reaches B and is held: B's tracked EK step for A is
        // still the lost head, so the restarted EK has no portable ancestry.
        // The hold is reported, never only logged, and nothing is credited.
        let held = p.b.era_balance();
        let next = p.a.send(&p.b, 5).await;
        assert!(next.success, "{:?}", next.error_message);
        let holding = p.b.sync().await;
        assert!(
            holding
                .errors
                .iter()
                .any(|e| e.contains("held at locator") && e.contains("EK ancestry is not portable")),
            "{:?}",
            holding.errors
        );
        assert_eq!(
            p.b.era_balance(),
            held,
            "nothing is credited while it is held"
        );
    }
}
