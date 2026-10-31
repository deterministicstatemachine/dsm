// SPDX-License-Identifier: MIT OR Apache-2.0
//! Two-device certificate restart — the online b0x flow (DSM Amendment A20).
//!
//! Four legs over the existing UniversalTx tag (no new payload tag), each
//! discriminated by an explicit invoke method:
//!
//!   initiate (8XK)        --certResyncRequest-->  (D3) handle_request
//!   handle_request (D3)   --certResyncOffer-->    (8XK) handle_offer
//!   handle_offer (8XK)    --certResyncConfirm-->  (D3) handle_confirm
//!   handle_confirm (D3)   --certResyncDone-->     (8XK) handle_done
//!
//! The device that lost its chain (the initiator) asks under its AK, naming the
//! relationship's latest accepted step and its new key. The healthy peer (the
//! responder) checks that step against its own record and offers the
//! initiator's latest step it holds as the predecessor, its own latest step,
//! and its AK signature over the restart statement. The initiator checks both
//! steps (each its owner's, at the agreed step, and the predecessor its own
//! latest while it holds any step of its chain), signs the same statement and
//! sends the restart step. The responder records it as the initiator's next
//! step and confirms under its AK; the initiator takes the restart only on
//! that confirmation. A message lost anywhere is recovered by asking again at
//! a later epoch.
//!
//! Each Local head is only ever changed by its owner. The statements, the
//! restart step's bytes, the signature and chain checks and the epoch rule are
//! Core's (`dsm::bilateral::cert_resync`, `dsm::economic::peer_acceptance`);
//! the head writes, guards and audit are `storage::client_db::cert_resync`.

use dsm::bilateral::cert_resync::{
    check_offered_step_position, check_restart_step, restart_done_statement,
    restart_request_statement, verify_restart_signature, AgreedStep, CosignatureRefusal,
    RestartFields, RestartParty,
};
use dsm::crypto::sphincs::sphincs_sign;
use dsm::economic::peer_acceptance::{certified_key_at, ek_cert_step_addr, AcceptanceParty, EkSteps};
use dsm::economic::provenance::PeerLineageFailure;
use dsm::types::error::DsmError;
use prost::Message;

use crate::sdk::storage_set::StorageSet;
use crate::storage::client_db::{
    self, cert_resync_status, finalize_cert_resync_atomically,
    finalize_cert_resync_responder_atomically, CertChainSide, CertResyncConfirm, CertResyncDone,
    CertResyncOffer, CertResyncRequest, LocalResyncKey, ResyncAudit, ResyncStep,
    CERT_RESYNC_CONFIRM_METHOD, CERT_RESYNC_DONE_METHOD, CERT_RESYNC_OFFER_METHOD,
    CERT_RESYNC_REQUEST_METHOD, RESYNC_CLEAR, RESYNC_PENDING,
};

fn err<T>(msg: impl Into<String>) -> Result<T, DsmError> {
    Err(DsmError::invalid_operation(msg.into()))
}

/// Why a cert-resync message read from the inbox was not taken.
#[derive(Debug)]
pub(crate) enum CertResyncRefusal {
    /// The message's own bytes say it never will be taken: its body does not
    /// decode, a signature in it does not verify under the AK this device
    /// pins for the relationship's peer, or what it names is not the
    /// relationship's state and never will be. It is passed over by its
    /// content, so it is not read and refused again on every sync.
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

fn failed<T>(msg: impl Into<String>) -> Result<T, CertResyncRefusal> {
    Err(CertResyncRefusal::Failed(DsmError::invalid_operation(
        msg.into(),
    )))
}

/// A refused signature, each reason kept as itself. A signature that is not
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

/// A chain walk's verdict on a step a message names: a step that does not
/// chain (or a lineage quarantined) is the message's own; one that could not
/// be walked now is read again.
fn walk_refused<T>(what: &str, failure: PeerLineageFailure) -> Result<T, CertResyncRefusal> {
    match failure {
        PeerLineageFailure::Invalid(e) | PeerLineageFailure::Quarantined(e) => Err(
            CertResyncRefusal::NotRecognized(DsmError::invalid_operation(format!("{what}: {e}"))),
        ),
        PeerLineageFailure::Incomplete(e) | PeerLineageFailure::Unresolved(e) => {
            failed(format!("{what}: {e}"))
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

/// A stored epoch as the restart statement carries it. Epochs start at one,
/// so a negative one is a store that is not usable.
fn statement_epoch(epoch: i64) -> Result<u64, DsmError> {
    u64::try_from(epoch)
        .map_err(|e| DsmError::invalid_operation(format!("cert resync epoch {epoch}: {e}")))
}

/// A restart statement's epoch as this device stores it.
fn stored_epoch(epoch: u64) -> Result<i64, CertResyncRefusal> {
    i64::try_from(epoch).map_err(|e| {
        CertResyncRefusal::NotRecognized(DsmError::invalid_operation(format!(
            "cert resync: the restart's epoch {epoch} is past any this device stores: {e}"
        )))
    })
}

/// Derive the deterministic fresh EK for a resync epoch. Re-derivable, so each
/// leg reconstructs the exact key the request advertised.
fn derive_resync_ek(
    rel_key: &[u8; 32],
    agreed_tip: &[u8; 32],
    commitment: &[u8; 32],
    epoch: i64,
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let s_master = crate::init::current_smaster()?;
    let mut k_step = [0u8; 32];
    k_step[..8].copy_from_slice(&epoch.to_le_bytes());
    let ctx = crate::sdk::receipts::PerStepEkContext {
        chain_id: *rel_key,
        h_n: *agreed_tip,
        c_pre: *commitment,
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

/// The relationship's current tip, as this device's contact record for
/// `peer` holds it: where its own inbox for the peer is polled.
fn relationship_tip(peer: &[u8; 32]) -> Result<[u8; 32], DsmError> {
    let contact = client_db::get_contact_by_device_id(peer)
        .map_err(|e| {
            DsmError::storage(format!("cert-resync: contact: {e}"), None::<std::io::Error>)
        })?
        .ok_or_else(|| DsmError::relationship("cert-resync: the peer is not a contact"))?;
    super::app_router_impl::contact_relationship_tip(&contact).map_err(DsmError::relationship)
}

/// The relationship's latest accepted step, as this device records it: the
/// agreed step a restart is anchored to.
fn agreed_step(peer: &[u8; 32], rel_key: &[u8; 32]) -> Result<AgreedStep, DsmError> {
    let tip = relationship_tip(peer)?;
    client_db::latest_accepted_step(rel_key, &tip)
        .map_err(|e| {
            DsmError::storage(
                format!("cert-resync: accepted step: {e}"),
                None::<std::io::Error>,
            )
        })?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "cert resync: no accepted step reaches the relationship's current tip, so \
                 there is no chain to continue",
            )
        })
}

/// The latest step this device records in `signer`'s chain on `rel_key`.
fn latest_step(
    rel_key: &[u8; 32],
    signer: &[u8; 32],
) -> Result<Option<([u8; 32], Vec<u8>)>, DsmError> {
    Ok(client_db::economic_lineage::latest_ek_step(rel_key, signer)
        .map_err(|e| {
            DsmError::storage(
                format!("cert-resync: ek step chain: {e}"),
                None::<std::io::Error>,
            )
        })?
        .map(|(_, addr, key)| (addr, key)))
}

/// The network's storage set: where certificate steps are published.
fn step_set() -> Result<StorageSet, DsmError> {
    crate::sdk::storage_set::canonical_set(dsm::economic::register::BETA_NETWORK_ID)
}

/// Certificate steps for a chain walk: the ones this device holds, and the
/// published ones, fetched from `set`.
struct LiveEkSteps<'s> {
    set: &'s StorageSet,
    runtime: tokio::runtime::Handle,
}

impl EkSteps for LiveEkSteps<'_> {
    fn held(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        crate::sdk::economic_registers::held_ek_step(signer, addr)
    }

    fn fetch(&self, addr: &[u8; 32]) -> Result<Vec<u8>, PeerLineageFailure> {
        tokio::task::block_in_place(|| {
            self.runtime
                .block_on(crate::sdk::storage_io::fetch_immutable(
                    self.set,
                    dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                    addr,
                ))
        })
        .map_err(|e| PeerLineageFailure::Incomplete(format!("EK step fetch: {e}")))?
        .ok_or_else(|| {
            PeerLineageFailure::Incomplete(format!(
                "no member holds the EK step {}",
                crate::util::text_id::encode_base32_crockford(addr)
            ))
        })
    }
}

/// The published step at `addr`, its bytes re-hashed to the address and
/// canonically encoded.
async fn fetch_step(
    set: &StorageSet,
    addr: &[u8; 32],
) -> Result<dsm::types::proto::EkCertStepV1, CertResyncRefusal> {
    let Some(bytes) = crate::sdk::storage_io::fetch_immutable(
        set,
        dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
        addr,
    )
    .await?
    else {
        return failed(format!(
            "cert resync: no member holds the offered step {}",
            crate::util::text_id::encode_base32_crockford(addr)
        ));
    };
    decode_step(&bytes)
}

/// A restart step's own bytes: canonical, and a restart.
fn decode_step(bytes: &[u8]) -> Result<dsm::types::proto::EkCertStepV1, CertResyncRefusal> {
    let step = dsm::types::proto::EkCertStepV1::decode(bytes).map_err(|e| {
        CertResyncRefusal::NotRecognized(DsmError::invalid_operation(format!(
            "cert resync: the step does not decode: {e}"
        )))
    })?;
    if step.encode_to_vec() != bytes {
        return not_recognized("cert resync: the step's encoding is not canonical");
    }
    Ok(step)
}

fn restart_of(
    step: &dsm::types::proto::EkCertStepV1,
) -> Result<&dsm::types::proto::CertRestartV1, CertResyncRefusal> {
    match &step.authority {
        Some(dsm::types::proto::ek_cert_step_v1::Authority::Restart(restart)) => Ok(restart),
        _ => not_recognized("cert resync: the step is not a restart step"),
    }
}

/// One device of the relationship, as a chain walk reads it.
struct Device<'a> {
    devid: [u8; 32],
    ak: &'a [u8],
}

impl Device<'_> {
    fn party(&self) -> AcceptanceParty<'_> {
        AcceptanceParty {
            devid: self.devid,
            proven_ak: self.ak,
        }
    }

    fn restart_party(&self) -> RestartParty<'_> {
        RestartParty {
            devid: self.devid,
            proven_ak: self.ak,
        }
    }
}

/// The initiator's check of one step a responder offers (DSM Amendment A20):
/// it is `signer`'s (its certificates chain to that device's AK, a restart on
/// both AKs) and it is at the agreed accepted step. Returns the key it
/// certifies.
async fn check_offered_step(
    what: &str,
    steps: &LiveEkSteps<'_>,
    agreed: &AgreedStep,
    addr: &[u8; 32],
    signer: &Device<'_>,
    other: &Device<'_>,
) -> Result<Vec<u8>, CertResyncRefusal> {
    let step = fetch_step(steps.set, addr).await?;
    if let Err(refusal) = check_offered_step_position(&step, agreed) {
        return not_recognized(&format!("cert resync offer: {what}: {refusal}"));
    }
    match certified_key_at(*addr, &signer.party(), &other.party(), steps) {
        Ok(key) => Ok(key),
        Err(failure) => walk_refused(&format!("cert resync offer: {what}"), failure),
    }
}

/// While this device holds any step of its own chain, the offered
/// predecessor is its latest step, or continues it through restart steps
/// this device signed (a restart its counterparty recorded and whose
/// confirmation never arrived). Restart steps are only walked here once
/// `check_offered_step` verified them.
async fn continues_own_latest(
    set: &StorageSet,
    rel_key: &[u8; 32],
    me: &[u8; 32],
    predecessor: &[u8; 32],
) -> Result<(), CertResyncRefusal> {
    let Some((held, _)) = latest_step(rel_key, me)? else {
        return Ok(());
    };
    let mut cursor = *predecessor;
    while cursor != held {
        let step = fetch_step(set, &cursor).await?;
        cursor = match (&step.authority, step.prior_step_addr.as_deref()) {
            (Some(dsm::types::proto::ek_cert_step_v1::Authority::Restart(_)), Some(prior)) => {
                <[u8; 32]>::try_from(prior).map_err(|e| {
                    CertResyncRefusal::NotRecognized(DsmError::invalid_operation(format!(
                        "cert resync offer: a restart's predecessor is not 32 bytes: {e}"
                    )))
                })?
            }
            _ => {
                return not_recognized(
                    "cert resync offer: the offered predecessor does not continue the latest \
                     step this device holds of its own chain",
                )
            }
        };
    }
    Ok(())
}

/// Both steps a responder offers: the predecessor, in this device's chain,
/// and the responder's own latest step, which, while this device holds any
/// step of the responder's chain, is its latest. Returns the key the
/// responder's step certifies: this device's new Counterparty head.
async fn check_offered_steps(
    set: &StorageSet,
    rel_key: &[u8; 32],
    agreed: &AgreedStep,
    me: &Device<'_>,
    peer: &Device<'_>,
    predecessor: &[u8; 32],
    counterparty_step: &[u8; 32],
) -> Result<Vec<u8>, CertResyncRefusal> {
    let steps = LiveEkSteps {
        set,
        runtime: tokio::runtime::Handle::current(),
    };
    check_offered_step(
        "the offered predecessor",
        &steps,
        agreed,
        predecessor,
        me,
        peer,
    )
    .await?;
    continues_own_latest(set, rel_key, &me.devid, predecessor).await?;
    let key = check_offered_step(
        "the responder's latest step",
        &steps,
        agreed,
        counterparty_step,
        peer,
        me,
    )
    .await?;
    if let Some((held, _)) = latest_step(rel_key, &peer.devid)? {
        if &held != counterparty_step {
            return not_recognized(
                "cert resync offer: the responder's latest step is not the latest step this \
                 device holds of its chain",
            );
        }
    }
    Ok(key)
}

impl super::app_router_impl::AppRouterImpl {
    fn b0x(&self, storage_endpoints: Vec<String>) -> Result<crate::sdk::b0x_sdk::B0xSDK, DsmError> {
        let sender_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        crate::sdk::b0x_sdk::B0xSDK::new(sender_b32, self.core_sdk.clone(), storage_endpoints)
    }

    /// INITIATE (head-loss side). Ask the peer for a restart under this
    /// device's AK.
    pub(crate) async fn initiate_cert_resync(
        &self,
        to_device_id: [u8; 32],
        storage_endpoints: Vec<String>,
    ) -> Result<(), DsmError> {
        let rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &self.device_id_bytes,
            &to_device_id,
        );
        let (peer_device, peer_genesis, _peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;
        let agreed = agreed_step(&peer_device, &rel_key)?;

        let epoch = next_resync_epoch(&rel_key)?;
        client_db::begin_cert_resync(&rel_key, epoch)
            .map_err(|e| DsmError::invalid_operation(format!("begin resync: {e}")))?;
        let (new_key, _new_sk) =
            derive_resync_ek(&rel_key, &agreed.tip, &agreed.commitment, epoch)?;
        let (_ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let request_sig = sphincs_sign(
            &ak_sk,
            &restart_request_statement(
                &rel_key,
                &agreed.tip,
                statement_epoch(epoch)?,
                &agreed.commitment,
                &new_key,
            ),
        )?;
        let req = CertResyncRequest {
            relationship_key: rel_key,
            agreed_tip: agreed.tip,
            epoch,
            preserved_acceptance_commitment: agreed.commitment,
            reply_to_tip: relationship_tip(&peer_device)?,
            new_key,
            request_sig,
        };
        self.b0x(storage_endpoints)?
            .submit_cert_resync_message(
                CERT_RESYNC_REQUEST_METHOD,
                req.to_body(),
                &peer_genesis,
                &peer_device,
                &agreed.tip,
            )
            .await?;
        log::info!("[cert-resync] request sent, epoch={epoch}");
        Ok(())
    }

    /// RESPONDER (healthy peer). Check the request against this device's own
    /// record of the agreed step and offer the predecessor, its own latest
    /// step and its AK signature over the restart statement. Nothing on this
    /// device changes.
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
        let epoch = statement_epoch(req.epoch).map_err(CertResyncRefusal::NotRecognized)?;
        if let Err(refusal) = verify_restart_signature(
            &initiator_ak,
            &restart_request_statement(
                &rel_key,
                &req.agreed_tip,
                epoch,
                &req.preserved_acceptance_commitment,
                &req.new_key,
            ),
            &req.request_sig,
        ) {
            return cosignature_refused("cert resync request: the initiator's signature", refusal);
        }
        let (_state, recorded) = cert_resync_status(&rel_key).map_err(|e| {
            DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
        })?;
        if let Err(e) = dsm::bilateral::cert_resync::cert_resync_epoch_advances(req.epoch, recorded)
        {
            return not_recognized(&format!("cert resync request: {e}"));
        }
        if let Some(reason) = client_db::resync_pending_obligation(&rel_key).map_err(|e| {
            DsmError::storage(format!("cert resync request: {e}"), None::<std::io::Error>)
        })? {
            return failed(format!("cert resync request: {reason}"));
        }
        let agreed = agreed_step(&initiator_device, &rel_key)?;
        if (agreed.tip, agreed.commitment) != (req.agreed_tip, req.preserved_acceptance_commitment)
        {
            return not_recognized(
                "cert resync request: the agreed step it names is not this device's latest \
                 accepted step of the relationship",
            );
        }
        let Some((predecessor, _)) = latest_step(&rel_key, &initiator_device)? else {
            return failed(
                "cert resync request: this device holds no step of the initiator's chain",
            );
        };
        let Some((counterparty_step, _)) = latest_step(&rel_key, &self.device_id_bytes)? else {
            return failed("cert resync request: this device holds no step of its own chain");
        };
        let statement = RestartFields {
            relationship_key: rel_key,
            predecessor,
            agreed_tip: req.agreed_tip,
            epoch,
            preserved_acceptance_commitment: req.preserved_acceptance_commitment,
            new_key: &req.new_key,
        }
        .statement();
        let (_ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let offer = CertResyncOffer {
            relationship_key: rel_key,
            epoch: req.epoch,
            predecessor,
            counterparty_step,
            counterparty_sig: sphincs_sign(&ak_sk, &statement)?,
        };
        self.b0x(storage_endpoints)?
            .submit_cert_resync_message(
                CERT_RESYNC_OFFER_METHOD,
                offer.to_body(),
                &initiator_genesis,
                &initiator_device,
                &req.reply_to_tip,
            )
            .await?;
        log::info!("[cert-resync] offered, epoch={}", req.epoch);
        Ok(())
    }

    /// INITIATOR. Check the offered steps, sign the same statement, publish
    /// the restart step and send it. Nothing on this device changes until the
    /// responder confirms it recorded the step.
    pub(crate) async fn handle_cert_resync_offer(
        &self,
        body: &[u8],
        storage_endpoints: Vec<String>,
    ) -> Result<(), CertResyncRefusal> {
        let Some(offer) = CertResyncOffer::from_body(body) else {
            return not_recognized("cert resync offer: malformed body");
        };
        let rel_key = offer.relationship_key;
        let (state, epoch) = cert_resync_status(&rel_key).map_err(|e| {
            DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
        })?;
        // An offer below the relationship's current epoch answers a request
        // this device has since replaced. Epochs only rise, so it never will
        // match: it is passed over by its content (§6.104), not read again.
        if offer.epoch < epoch {
            return not_recognized(&format!(
                "cert resync offer: epoch {} is below this relationship's current {epoch}",
                offer.epoch
            ));
        }
        // With no resync pending, an offer answers one this device finished.
        if state == RESYNC_CLEAR {
            return not_recognized(&format!(
                "cert resync offer: epoch {} answers a resync this device has finished",
                offer.epoch
            ));
        }
        if state != RESYNC_PENDING || epoch != offer.epoch {
            return failed(format!(
                "cert resync offer: no matching pending resync (state={state} epoch={epoch} \
                 offer={})",
                offer.epoch
            ));
        }
        let (peer_device, peer_genesis, peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;
        let agreed = agreed_step(&peer_device, &rel_key)?;
        let (new_key, _new_sk) =
            derive_resync_ek(&rel_key, &agreed.tip, &agreed.commitment, epoch)?;
        let (ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let set = step_set()?;
        check_offered_steps(
            &set,
            &rel_key,
            &agreed,
            &Device {
                devid: self.device_id_bytes,
                ak: &ak_pk,
            },
            &Device {
                devid: peer_device,
                ak: &peer_ak,
            },
            &offer.predecessor,
            &offer.counterparty_step,
        )
        .await?;

        let fields = RestartFields {
            relationship_key: rel_key,
            predecessor: offer.predecessor,
            agreed_tip: agreed.tip,
            epoch: statement_epoch(epoch)?,
            preserved_acceptance_commitment: agreed.commitment,
            new_key: &new_key,
        };
        let statement = fields.statement();
        if let Err(refusal) =
            verify_restart_signature(&peer_ak, &statement, &offer.counterparty_sig)
        {
            return cosignature_refused("cert resync offer: the responder's signature", refusal);
        }
        let restart_step = fields
            .step(sphincs_sign(&ak_sk, &statement)?, offer.counterparty_sig)
            .encode_to_vec();
        let restart_addr = ek_cert_step_addr(&restart_step);
        crate::handlers::artifact_republish::ensure_closure_stored(
            &set,
            &[(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                restart_addr,
                restart_step,
            )],
        )
        .await
        .map_err(|e| CertResyncRefusal::Failed(DsmError::invalid_operation(e)))?;

        let confirm = CertResyncConfirm {
            relationship_key: rel_key,
            reply_to_tip: relationship_tip(&peer_device)?,
            restart_step: restart_addr,
        };
        self.b0x(storage_endpoints)?
            .submit_cert_resync_message(
                CERT_RESYNC_CONFIRM_METHOD,
                confirm.to_body(),
                &peer_genesis,
                &peer_device,
                &agreed.tip,
            )
            .await?;
        log::info!("[cert-resync] restart step sent, epoch={epoch}");
        Ok(())
    }

    /// RESPONDER. Record the restart step as the initiator's next step and
    /// advance the stale Counterparty head, then confirm under this device's
    /// AK. A restart step already recorded is confirmed again, changing
    /// nothing.
    pub(crate) async fn handle_cert_resync_confirm(
        &self,
        body: &[u8],
        storage_endpoints: Vec<String>,
    ) -> Result<(), CertResyncRefusal> {
        let Some(confirm) = CertResyncConfirm::from_body(body) else {
            return not_recognized("cert resync confirm: malformed body");
        };
        let rel_key = confirm.relationship_key;
        let addr = confirm.restart_step;
        let set = step_set()?;
        let step = fetch_step(&set, &addr).await?;
        let restart = restart_of(&step)?;
        let (initiator_device, initiator_genesis, initiator_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;
        let (ak_pk, ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let Some((own_step, _)) = latest_step(&rel_key, &self.device_id_bytes)? else {
            return failed("cert resync confirm: this device holds no step of its own chain");
        };
        let latest = latest_step(&rel_key, &initiator_device)?;

        if latest.as_ref().map(|(held, _)| held) != Some(&addr) {
            if let Err(refusal) = check_restart_step(
                &step,
                restart,
                Device {
                    devid: initiator_device,
                    ak: &initiator_ak,
                }
                .restart_party(),
                Device {
                    devid: self.device_id_bytes,
                    ak: &ak_pk,
                }
                .restart_party(),
                None,
            ) {
                return not_recognized(&format!("cert resync confirm: {refusal}"));
            }
            let epoch = stored_epoch(restart.epoch)?;
            let (_state, recorded) = cert_resync_status(&rel_key).map_err(|e| {
                DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
            })?;
            if let Err(e) = dsm::bilateral::cert_resync::cert_resync_epoch_advances(epoch, recorded)
            {
                return not_recognized(&format!("cert resync confirm: {e}"));
            }
            let Some((predecessor, expected_counterparty)) = latest else {
                return failed(
                    "cert resync confirm: this device holds no step of the initiator's chain",
                );
            };
            if step.prior_step_addr.as_deref() != Some(predecessor.as_slice()) {
                return not_recognized(
                    "cert resync confirm: the restart does not continue the initiator's latest \
                     step this device holds",
                );
            }
            let agreed = agreed_step(&initiator_device, &rel_key)?;
            if step.h_n.as_slice() != agreed.tip.as_slice()
                || restart.preserved_acceptance_commitment.as_slice()
                    != agreed.commitment.as_slice()
            {
                return not_recognized(
                    "cert resync confirm: the restart names another agreed step than this \
                     device's latest accepted step",
                );
            }
            if let Some(reason) = client_db::resync_pending_obligation(&rel_key).map_err(|e| {
                DsmError::storage(format!("cert resync confirm: {e}"), None::<std::io::Error>)
            })? {
                return failed(format!("cert resync confirm: {reason}"));
            }
            let responder_local_head =
                client_db::load_cert_chain_head_pubkey(&rel_key, CertChainSide::Local)
                    .map_err(|e| {
                        DsmError::storage(
                            format!("cert resync confirm: head: {e}"),
                            None::<std::io::Error>,
                        )
                    })?
                    .ok_or_else(|| {
                        DsmError::invalid_operation(
                            "cert resync confirm: this device has no Local head (two-sided loss)",
                        )
                    })?;
            let stale_counterparty =
                client_db::load_cert_chain_head_pubkey(&rel_key, CertChainSide::Counterparty)
                    .map_err(|e| {
                        DsmError::storage(
                            format!("cert resync confirm: head: {e}"),
                            None::<std::io::Error>,
                        )
                    })?;
            if stale_counterparty.as_deref() != Some(expected_counterparty.as_slice()) {
                return failed(
                    "cert resync confirm: this device's head for the initiator is not the key of \
                     the initiator's latest step it holds",
                );
            }
            crate::handlers::artifact_republish::ensure_closure_stored(
                &set,
                &[(
                    dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                    addr,
                    step.encode_to_vec(),
                )],
            )
            .await
            .map_err(|e| CertResyncRefusal::Failed(DsmError::invalid_operation(e)))?;
            let statement = RestartFields {
                relationship_key: rel_key,
                predecessor,
                agreed_tip: agreed.tip,
                epoch: restart.epoch,
                preserved_acceptance_commitment: agreed.commitment,
                new_key: &step.ek_pk,
            }
            .statement();
            finalize_cert_resync_responder_atomically(
                &rel_key,
                epoch,
                &step.ek_pk,
                Some(&expected_counterparty),
                ResyncStep {
                    signer: initiator_device,
                    addr,
                    key: &step.ek_pk,
                },
                ResyncAudit {
                    epoch,
                    preserved_acceptance_commitment: &agreed.commitment,
                    agreed_tip: &agreed.tip,
                    restart_statement: &statement,
                    reason_code: "peer-head-loss",
                },
                &responder_local_head,
            )
            .map_err(|e| DsmError::invalid_operation(format!("responder finalize: {e}")))?;
        }

        let done = CertResyncDone {
            relationship_key: rel_key,
            restart_step: addr,
            counterparty_step: own_step,
            done_sig: sphincs_sign(&ak_sk, &restart_done_statement(&addr, &own_step))?,
        };
        self.b0x(storage_endpoints)?
            .submit_cert_resync_message(
                CERT_RESYNC_DONE_METHOD,
                done.to_body(),
                &initiator_genesis,
                &initiator_device,
                &confirm.reply_to_tip,
            )
            .await?;
        log::info!(
            "[cert-resync] responder recorded the restart step, epoch={}",
            restart.epoch
        );
        Ok(())
    }

    /// INITIATOR. On the responder's confirmation, take the restart: install
    /// both heads, record the restart step (and the responder's latest step,
    /// when this device's record of it was lost) and clear the send gate.
    pub(crate) async fn handle_cert_resync_done(
        &self,
        body: &[u8],
    ) -> Result<(), CertResyncRefusal> {
        let Some(done) = CertResyncDone::from_body(body) else {
            return not_recognized("cert resync done: malformed body");
        };
        let rel_key = done.relationship_key;
        let addr = done.restart_step;
        let (state, epoch) = cert_resync_status(&rel_key).map_err(|e| {
            DsmError::internal(format!("resync status: {e}"), None::<std::io::Error>)
        })?;
        let (peer_device, _peer_genesis, peer_ak) =
            peer_for_relationship(&self.device_id_bytes, &rel_key)?;
        if let Err(refusal) = verify_restart_signature(
            &peer_ak,
            &restart_done_statement(&addr, &done.counterparty_step),
            &done.done_sig,
        ) {
            return cosignature_refused("cert resync done: the responder's signature", refusal);
        }
        let set = step_set()?;
        let step = fetch_step(&set, &addr).await?;
        let restart = restart_of(&step)?;
        let restart_epoch = stored_epoch(restart.epoch)?;
        // With no resync pending, a confirmation this device took is passed
        // over, and any other confirms a restart it no longer waits for.
        if state == RESYNC_CLEAR {
            if latest_step(&rel_key, &self.device_id_bytes)?.map(|(held, _)| held) == Some(addr) {
                return Ok(());
            }
            return not_recognized(&format!(
                "cert resync done: epoch {restart_epoch} confirms a restart this device no longer \
                 waits for"
            ));
        }
        // A restart this device signed under an epoch it has since asked past
        // is still taken: the counterparty recorded it, and asking again does
        // not undo that. One past its current epoch it never asked for.
        if restart_epoch > epoch {
            return not_recognized(&format!(
                "cert resync done: epoch {restart_epoch} is past this relationship's current {epoch}"
            ));
        }
        if state != RESYNC_PENDING {
            return failed(format!(
                "cert resync done: no resync pending (state={state} epoch={epoch})"
            ));
        }
        let (ak_pk, _ak_sk) = self.wallet.ak_keypair_for_cert_chain()?;
        let me = Device {
            devid: self.device_id_bytes,
            ak: &ak_pk,
        };
        let peer = Device {
            devid: peer_device,
            ak: &peer_ak,
        };
        if let Err(refusal) = check_restart_step(
            &step,
            restart,
            me.restart_party(),
            peer.restart_party(),
            None,
        ) {
            return not_recognized(&format!("cert resync done: {refusal}"));
        }
        let agreed = agreed_step(&peer_device, &rel_key)?;
        let (new_key, new_sk) =
            derive_resync_ek(&rel_key, &agreed.tip, &agreed.commitment, restart_epoch)?;
        if step.ek_pk != new_key
            || step.h_n.as_slice() != agreed.tip.as_slice()
            || restart.preserved_acceptance_commitment.as_slice() != agreed.commitment.as_slice()
        {
            return not_recognized(
                "cert resync done: the restart step is not the one this device asked for at its \
                 agreed step",
            );
        }
        let Some(predecessor) = step.prior_step_addr.as_deref() else {
            return not_recognized("cert resync done: the restart names no predecessor");
        };
        let predecessor = <[u8; 32]>::try_from(predecessor).map_err(|e| {
            CertResyncRefusal::NotRecognized(DsmError::invalid_operation(format!(
                "cert resync done: the predecessor is not 32 bytes: {e}"
            )))
        })?;
        let counterparty_key = check_offered_steps(
            &set,
            &rel_key,
            &agreed,
            &me,
            &peer,
            &predecessor,
            &done.counterparty_step,
        )
        .await?;

        let head = |side| {
            client_db::load_cert_chain_head_pubkey(&rel_key, side).map_err(|e| {
                DsmError::storage(
                    format!("cert resync done: head: {e}"),
                    None::<std::io::Error>,
                )
            })
        };
        let expected_local = head(CertChainSide::Local)?;
        let expected_counterparty = head(CertChainSide::Counterparty)?;
        let mut steps = Vec::with_capacity(2);
        if latest_step(&rel_key, &peer_device)?.map(|(held, _)| held)
            != Some(done.counterparty_step)
        {
            steps.push(ResyncStep {
                signer: peer_device,
                addr: done.counterparty_step,
                key: &counterparty_key,
            });
        }
        steps.push(ResyncStep {
            signer: self.device_id_bytes,
            addr,
            key: &new_key,
        });
        let statement = RestartFields {
            relationship_key: rel_key,
            predecessor,
            agreed_tip: agreed.tip,
            epoch: restart.epoch,
            preserved_acceptance_commitment: agreed.commitment,
            new_key: &new_key,
        }
        .statement();
        let at_rest_key = crate::init::current_chain_head_at_rest_key()?;
        finalize_cert_resync_atomically(
            &rel_key,
            epoch,
            LocalResyncKey {
                pubkey: &new_key,
                secret_key: &new_sk,
                wrap_key: &at_rest_key,
            },
            expected_local.as_deref(),
            &counterparty_key,
            expected_counterparty.as_deref(),
            &steps,
            ResyncAudit {
                epoch: restart_epoch,
                preserved_acceptance_commitment: &agreed.commitment,
                agreed_tip: &agreed.tip,
                restart_statement: &statement,
                reason_code: "head-loss-recovery",
            },
        )
        .map_err(|e| DsmError::invalid_operation(format!("initiator finalize: {e}")))?;
        log::info!(
            "[cert-resync] FINALIZED epoch={restart_epoch}: the chain continues from its restart step"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db as cdb;
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

    /// The latest step `device` records in `signer`'s chain on `rel`.
    fn latest(
        device: &TestDevice,
        rel: &[u8; 32],
        signer: &TestDevice,
    ) -> Option<([u8; 32], Vec<u8>)> {
        device.enter();
        latest_step(rel, &signer.device_id).expect("the step chain reads")
    }

    /// `device`'s AK signature over `statement`.
    fn signed_by(device: &TestDevice, statement: &[u8; 32]) -> Vec<u8> {
        device.enter();
        let (_pk, sk) = device
            .router()
            .wallet
            .ak_keypair_for_cert_chain()
            .expect("the AK");
        sphincs_sign(&sk, statement).expect("sign")
    }

    /// A paid B `amounts` in turn, each step finalized on both sides.
    async fn paid(p: &Pair, amounts: &[u64]) {
        for amount in amounts {
            let sent = p.a.send(&p.b, *amount).await;
            assert!(sent.success, "{:?}", sent.error_message);
            let applied = p.b.sync().await;
            assert!(applied.success, "{:?}", applied.errors);
            let finalized = p.a.sync().await;
            assert!(finalized.success, "{:?}", finalized.errors);
        }
    }

    /// A loses its cert-chain heads on its relationship with B, and with
    /// `steps_too` its record of both chains' steps as well; the send gate's
    /// mark follows.
    fn lose(p: &Pair, rel: &[u8; 32], steps_too: Loss) {
        execute(
            &p.a,
            "DELETE FROM cert_chain_heads WHERE relationship_key = ?1",
            rusqlite::params![rel.as_slice()],
        );
        if let Loss::HeadsAndSteps = steps_too {
            execute(
                &p.a,
                "DELETE FROM ek_cert_step_chain WHERE rel_key = ?1",
                rusqlite::params![rel.as_slice()],
            );
        }
        p.a.enter();
        cdb::mark_cert_resync_required(rel).expect("the head loss is marked");
    }

    enum Loss {
        Heads,
        HeadsAndSteps,
    }

    /// A lost its whole record of the chain (heads and steps) after a
    /// finalized transfer. The restart runs in its four legs, and each changes
    /// only what it should:
    /// - B's offer changes nothing on B, and A's restart step changes nothing
    ///   on A until B confirms;
    /// - on B's confirmation each side records the restart step as A's
    ///   latest step: B's head for A is the restarted key, A holds B's own
    ///   head and latest step, and both end CLEAR at the same epoch;
    /// - A's next transfer is applied by B and finalized by A on B's
    ///   acceptance, and B's next transfer is applied by A: the restarted
    ///   relationship carries both directions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_restart_continues_the_chain_and_carries_the_next_transfer_to_acceptance() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10]).await;
        let rel = p.a.rel_key_with(&p.b);
        let lost = head(&p.a, &rel, CertChainSide::Local).expect("A's head before the loss");
        let (held_for_a, held_key) = latest(&p.b, &rel, &p.a).expect("B holds A's step");
        assert_eq!(held_key, lost);
        let b_own = latest(&p.b, &rel, &p.b).expect("B holds its own step");
        let b_head = head(&p.b, &rel, CertChainSide::Local).expect("B's own head");
        lose(&p, &rel, Loss::HeadsAndSteps);

        let asked = p.a.sync().await;
        assert!(asked.errors.is_empty(), "{:?}", asked.errors);
        let (state, epoch) = resync_state(&p.a, &rel);
        assert_eq!(state, cdb::RESYNC_PENDING);

        let offered = p.b.sync().await;
        assert!(offered.errors.is_empty(), "{:?}", offered.errors);
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(lost.clone())
        );
        assert_eq!(latest(&p.b, &rel, &p.a).map(|(a, _)| a), Some(held_for_a));

        let confirmed = p.a.sync().await;
        assert!(confirmed.errors.is_empty(), "{:?}", confirmed.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_PENDING, epoch));
        assert_eq!(head(&p.a, &rel, CertChainSide::Local), None);

        let recorded = p.b.sync().await;
        assert!(recorded.errors.is_empty(), "{:?}", recorded.errors);
        let fresh = head(&p.b, &rel, CertChainSide::Counterparty).expect("B's head for A");
        assert_ne!(fresh, lost);
        let (restart, restart_key) = latest(&p.b, &rel, &p.a).expect("the restart step");
        assert_ne!(restart, held_for_a);
        assert_eq!(restart_key, fresh);
        assert_eq!(resync_state(&p.b, &rel), (cdb::RESYNC_CLEAR, epoch));

        let taken = p.a.sync().await;
        assert!(taken.errors.is_empty(), "{:?}", taken.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_CLEAR, epoch));
        assert_eq!(head(&p.a, &rel, CertChainSide::Local), Some(fresh.clone()));
        assert_eq!(
            head(&p.a, &rel, CertChainSide::Counterparty),
            Some(b_head.clone())
        );
        assert_eq!(latest(&p.a, &rel, &p.a), Some((restart, fresh)));
        assert_eq!(latest(&p.a, &rel, &p.b), Some(b_own));
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Local),
            Some(b_head),
            "B's own head is untouched"
        );

        let quiet = p.b.sync().await;
        assert!(quiet.errors.is_empty(), "{:?}", quiet.errors);
        let again = p.a.sync().await;
        assert!(again.errors.is_empty(), "{:?}", again.errors);

        let next = p.a.send(&p.b, 5).await;
        assert!(next.success, "{:?}", next.error_message);
        let applied = p.b.sync().await;
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert_eq!(
            p.b.era_balance(),
            15,
            "B applied A's transfer after the restart"
        );
        let accepted = p.a.sync().await;
        assert!(accepted.errors.is_empty(), "{:?}", accepted.errors);
        p.a.enter();
        let finalized = cdb::get_finalized_proposal_for_relationship(&rel)
            .expect("the proposals read")
            .expect("a finalized proposal");
        assert_eq!(
            finalized.amount, 5,
            "A finalized its transfer on B's acceptance"
        );
        assert_ne!(
            latest(&p.b, &rel, &p.a).map(|(a, _)| a),
            Some(restart),
            "A's chain moved on from its restart step"
        );

        let before = p.a.era_balance();
        let back = p.b.send(&p.a, 3).await;
        assert!(back.success, "{:?}", back.error_message);
        let taken_back = p.a.sync().await;
        assert!(taken_back.errors.is_empty(), "{:?}", taken_back.errors);
        assert_eq!(
            p.a.era_balance(),
            before + 3,
            "A applied B's transfer after the restart"
        );
    }

    /// A sent its restart step, then asked again under a later epoch before
    /// B's confirmation arrived. B recorded the first restart and offers it as
    /// the predecessor of the second. A still takes the first on its
    /// confirmation (B recorded it, and asking again does not undo that) and
    /// passes over the second offer, as it waits for no restart any more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_confirmation_arriving_after_the_initiator_asked_again_is_still_taken() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10]).await;
        let rel = p.a.rel_key_with(&p.b);
        lose(&p, &rel, Loss::HeadsAndSteps);
        p.a.sync().await;
        let (_, first) = resync_state(&p.a, &rel);
        let offered = p.b.sync().await;
        assert!(offered.errors.is_empty(), "{:?}", offered.errors);
        let confirmed = p.a.sync().await;
        assert!(confirmed.errors.is_empty(), "{:?}", confirmed.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_PENDING, first));
        let asked_again = p.a.sync().await;
        assert!(asked_again.errors.is_empty(), "{:?}", asked_again.errors);
        let (_, second) = resync_state(&p.a, &rel);
        assert!(second > first, "A asked again under a later epoch");

        let recorded = p.b.sync().await;
        assert!(recorded.errors.is_empty(), "{:?}", recorded.errors);
        let (restart, fresh) = latest(&p.b, &rel, &p.a).expect("B recorded the first restart");
        assert_eq!(resync_state(&p.b, &rel), (cdb::RESYNC_CLEAR, first));

        let taken = p.a.sync().await;
        assert_eq!(taken.errors.len(), 1, "{:?}", taken.errors);
        assert!(
            taken.errors[0].contains("finished") && taken.errors[0].contains("passed over"),
            "{:?}",
            taken.errors
        );
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_CLEAR, second));
        assert_eq!(latest(&p.a, &rel, &p.a), Some((restart, fresh.clone())));
        assert_eq!(head(&p.a, &rel, CertChainSide::Local), Some(fresh));

        let next = p.a.send(&p.b, 5).await;
        assert!(next.success, "{:?}", next.error_message);
        let carried = p.b.sync().await;
        assert!(carried.errors.is_empty(), "{:?}", carried.errors);
        assert_eq!(p.b.era_balance(), 15);
    }

    /// The relationship's latest step was one A received: B paid A, and A
    /// then lost its whole record of the chain. A's next send is blocked as a
    /// lost head (the relationship has a step, though A never sent on it), the
    /// restart is anchored to the step A received, and A's next transfer is
    /// applied by B.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_relationship_whose_latest_step_was_received_restarts_from_it() {
        let p = Pair::boot(100, 100).await;
        let sent = p.b.send(&p.a, 10).await;
        assert!(sent.success, "{:?}", sent.error_message);
        let applied = p.a.sync().await;
        assert!(applied.success, "{:?}", applied.errors);
        let finalized = p.b.sync().await;
        assert!(finalized.success, "{:?}", finalized.errors);
        let rel = p.a.rel_key_with(&p.b);
        lose(&p, &rel, Loss::HeadsAndSteps);
        p.a.enter();
        cdb::get_connection()
            .expect("the store")
            .lock()
            .expect("the store's lock")
            .execute(
                "DELETE FROM cert_resync_state WHERE relationship_key = ?1",
                rusqlite::params![rel.as_slice()],
            )
            .expect("the mark undone");

        let blocked = p.a.send(&p.b, 5).await;
        assert!(!blocked.success, "a send over a lost head goes through");
        assert!(
            blocked
                .error_message
                .as_deref()
                .is_some_and(|e| e.contains("needs a cert-chain resync")),
            "{:?}",
            blocked.error_message
        );
        assert_eq!(resync_state(&p.a, &rel).0, cdb::RESYNC_REQUIRED);

        p.a.sync().await;
        let (_, epoch) = resync_state(&p.a, &rel);
        let offered = p.b.sync().await;
        assert!(offered.errors.is_empty(), "{:?}", offered.errors);
        let confirmed = p.a.sync().await;
        assert!(confirmed.errors.is_empty(), "{:?}", confirmed.errors);
        let recorded = p.b.sync().await;
        assert!(recorded.errors.is_empty(), "{:?}", recorded.errors);
        let taken = p.a.sync().await;
        assert!(taken.errors.is_empty(), "{:?}", taken.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_CLEAR, epoch));

        let before = p.b.era_balance();
        let next = p.a.send(&p.b, 5).await;
        assert!(next.success, "{:?}", next.error_message);
        let carried = p.b.sync().await;
        assert!(carried.errors.is_empty(), "{:?}", carried.errors);
        assert_eq!(
            p.b.era_balance(),
            before + 5,
            "B applied A's transfer after the restart"
        );
    }

    /// A lost its cert-chain heads after a finalized transfer and asks B to
    /// restart the chain. B takes the request only under the AK B pins for A:
    /// - under a pinned AK that is not a key, the request is not judged: it is
    ///   read again, and B offers nothing;
    /// - under another AK, the signature does not verify: the request is
    ///   passed over;
    /// - under A's own AK, A's requests are taken. A asked twice, so B's offer
    ///   for the first answers a request A replaced: A passes it over as below
    ///   its epoch and restarts on the second.
    /// - with B's record of the restart step wound back, A's next transfer is
    ///   held at B's prevalidation, and the hold is in B's report.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_resync_request_is_taken_only_under_the_ak_the_responder_pins() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10]).await;
        let rel = p.a.rel_key_with(&p.b);
        let lost = head(&p.a, &rel, CertChainSide::Local).expect("A's head before the loss");
        lose(&p, &rel, Loss::Heads);
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

        pin(&p.b, &p.a, &p.a.ak_pk);
        p.a.sync().await;
        let replaced = resync_state(&p.a, &rel).1;
        p.a.sync().await;
        let (_, epoch) = resync_state(&p.a, &rel);
        assert!(epoch > replaced, "A asked again under a later epoch");
        let answered = p.b.sync().await;
        assert!(answered.errors.is_empty(), "{:?}", answered.errors);

        let confirmed = p.a.sync().await;
        assert_eq!(confirmed.errors.len(), 1, "{:?}", confirmed.errors);
        assert!(
            confirmed.errors[0].contains(&format!("epoch {replaced} is below")),
            "{:?}",
            confirmed.errors
        );
        let recorded = p.b.sync().await;
        assert!(recorded.errors.is_empty(), "{:?}", recorded.errors);
        let taken = p.a.sync().await;
        assert!(taken.errors.is_empty(), "{:?}", taken.errors);
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_CLEAR, epoch));
        assert_eq!(resync_state(&p.b, &rel), (cdb::RESYNC_CLEAR, epoch));

        // B's record of the restart step is wound back: its head for A is the
        // restarted key, its latest step of A's chain the lost one. A's next
        // transfer is held at prevalidation, and the hold is reported with its
        // reason, never only logged; nothing is credited.
        execute(
            &p.b,
            "DELETE FROM ek_cert_step_chain WHERE rel_key = ?1 AND signer_devid = ?2 \
             AND step_ordinal = (SELECT MAX(step_ordinal) FROM ek_cert_step_chain \
             WHERE rel_key = ?1 AND signer_devid = ?2)",
            rusqlite::params![rel.as_slice(), p.a.device_id.as_slice()],
        );
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

    /// After two transfers, B's record of A's chain is wound back to A's first
    /// step: B offers that step as the predecessor. It was certified at
    /// another tip than the agreed accepted step's, so A passes the offer
    /// over, signs nothing and stays pending, and B's record does not move.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn an_offered_predecessor_not_at_the_agreed_step_is_passed_over() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10, 5]).await;
        let rel = p.a.rel_key_with(&p.b);
        execute(
            &p.b,
            "DELETE FROM ek_cert_step_chain WHERE rel_key = ?1 AND signer_devid = ?2 \
             AND step_ordinal = (SELECT MAX(step_ordinal) FROM ek_cert_step_chain \
             WHERE rel_key = ?1 AND signer_devid = ?2)",
            rusqlite::params![rel.as_slice(), p.a.device_id.as_slice()],
        );
        let wound_back = latest(&p.b, &rel, &p.a).expect("A's first step");
        lose(&p, &rel, Loss::HeadsAndSteps);
        p.a.sync().await;
        let (_, epoch) = resync_state(&p.a, &rel);
        let offered = p.b.sync().await;
        assert!(offered.errors.is_empty(), "{:?}", offered.errors);

        let refused = p.a.sync().await;
        assert!(
            refused
                .errors
                .iter()
                .any(|e| e.contains("the offered predecessor") && e.contains("another tip")),
            "{:?}",
            refused.errors
        );
        assert_eq!(
            resync_state(&p.a, &rel),
            (cdb::RESYNC_PENDING, epoch + 1),
            "A asked again"
        );
        let quiet = p.b.sync().await;
        assert!(
            quiet.errors.iter().all(|e| !e.contains("confirm")),
            "B was sent no restart step: {:?}",
            quiet.errors
        );
        assert_eq!(latest(&p.b, &rel, &p.a), Some(wound_back));
    }

    /// The facts of a restart of A's chain as B holds them: the relationship,
    /// A's latest step B holds, B's agreed step, the next epoch on B, and a
    /// fresh key.
    struct RestartOnB {
        rel: [u8; 32],
        predecessor: [u8; 32],
        agreed: AgreedStep,
        epoch: u64,
        new_key: Vec<u8>,
    }

    impl RestartOnB {
        fn read(p: &Pair) -> Self {
            let rel = p.a.rel_key_with(&p.b);
            let (predecessor, _) = latest(&p.b, &rel, &p.a).expect("B holds A's step");
            p.b.enter();
            let agreed = agreed_step(&p.a.device_id, &rel).expect("B's agreed step");
            let (_, recorded) = cdb::cert_resync_status(&rel).expect("the epoch reads");
            Self {
                rel,
                predecessor,
                agreed,
                epoch: u64::try_from(recorded + 1).expect("an epoch"),
                new_key: dsm::crypto::sphincs::generate_sphincs_keypair()
                    .expect("a key")
                    .0,
            }
        }

        fn fields(&self) -> RestartFields<'_> {
            RestartFields {
                relationship_key: self.rel,
                predecessor: self.predecessor,
                agreed_tip: self.agreed.tip,
                epoch: self.epoch,
                preserved_acceptance_commitment: self.agreed.commitment,
                new_key: &self.new_key,
            }
        }

        /// The restart step both AKs signed over its own fields.
        fn step(&self, p: &Pair) -> dsm::types::proto::EkCertStepV1 {
            let statement = self.fields().statement();
            self.fields()
                .step(signed_by(&p.a, &statement), signed_by(&p.b, &statement))
        }
    }

    /// `step` published from `device`, as a restart step travels: by its
    /// address.
    async fn published(device: &TestDevice, step: &dsm::types::proto::EkCertStepV1) -> [u8; 32] {
        let bytes = step.encode_to_vec();
        let addr = ek_cert_step_addr(&bytes);
        device.enter();
        crate::handlers::artifact_republish::ensure_closure_stored(
            &step_set().expect("the set"),
            &[(dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP, addr, bytes)],
        )
        .await
        .expect("published");
        addr
    }

    /// B's answer to a confirm naming `step`, published.
    async fn confirm_on_b(
        p: &Pair,
        rel: &[u8; 32],
        step: &dsm::types::proto::EkCertStepV1,
    ) -> Result<(), CertResyncRefusal> {
        let restart_step = published(&p.a, step).await;
        p.b.enter();
        let body = CertResyncConfirm {
            relationship_key: *rel,
            reply_to_tip: *rel,
            restart_step,
        }
        .to_body();
        p.b.router()
            .handle_cert_resync_confirm(&body, p.fleet.endpoints())
            .await
    }

    fn passed_over(what: &str, outcome: Result<(), CertResyncRefusal>, says: &str) {
        match outcome {
            Err(CertResyncRefusal::NotRecognized(e)) if e.to_string().contains(says) => {}
            other => panic!("{what}: {other:?}"),
        }
    }

    /// B records a restart step of A's chain only when both AKs signed it over
    /// its own fields, it continues A's latest step B holds, it names B's own
    /// agreed step, and its epoch is past the last B recorded. A missing or
    /// forged signature, another predecessor, another commitment and a
    /// replayed epoch are each passed over with nothing recorded; the genuine
    /// step is then recorded, the same step confirmed again changes nothing,
    /// and a request under the epoch B recorded is passed over.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_restart_step_is_recorded_only_as_both_devices_signed_it_over_bs_own_record() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10]).await;
        let facts = RestartOnB::read(&p);
        let rel = facts.rel;
        let lost = head(&p.b, &rel, CertChainSide::Counterparty).expect("B's head for A");
        let genuine = facts.step(&p);
        let statement = facts.fields().statement();
        let restart_mut = |s: &mut dsm::types::proto::EkCertStepV1| match &mut s.authority {
            Some(dsm::types::proto::ek_cert_step_v1::Authority::Restart(r)) => r.clone(),
            _ => panic!("not a restart"),
        };
        let with = |edit: &dyn Fn(&mut dsm::types::proto::CertRestartV1)| {
            let mut s = genuine.clone();
            let mut r = restart_mut(&mut s);
            edit(&mut r);
            s.authority = Some(dsm::types::proto::ek_cert_step_v1::Authority::Restart(r));
            s
        };
        let another = dsm::crypto::sphincs::generate_sphincs_keypair()
            .expect("another AK")
            .1;
        let forged = sphincs_sign(&another, &statement).expect("sign");

        passed_over(
            "A's signature missing",
            confirm_on_b(&p, &rel, &with(&|r| r.restarting_sig = Vec::new())).await,
            "restarting device's signature",
        );
        passed_over(
            "A's signature by another key",
            confirm_on_b(&p, &rel, &with(&|r| r.restarting_sig = forged.clone())).await,
            "restarting device's signature",
        );
        let mut elsewhere = genuine.clone();
        elsewhere.prior_step_addr = Some(vec![0x5Eu8; 32]);
        passed_over(
            "another predecessor",
            confirm_on_b(&p, &rel, &elsewhere).await,
            "restarting device's signature",
        );
        let other_commitment = RestartOnB {
            agreed: AgreedStep {
                commitment: [0x5Fu8; 32],
                ..facts.agreed
            },
            new_key: facts.new_key.clone(),
            ..facts
        };
        passed_over(
            "another commitment",
            confirm_on_b(&p, &rel, &other_commitment.step(&p)).await,
            "another agreed step",
        );
        let not_its_latest = RestartOnB {
            predecessor: [0x60u8; 32],
            new_key: facts.new_key.clone(),
            ..other_commitment
        };
        let not_its_latest = RestartOnB {
            agreed: facts.agreed,
            ..not_its_latest
        };
        passed_over(
            "a predecessor B does not hold as A's latest",
            confirm_on_b(&p, &rel, &not_its_latest.step(&p)).await,
            "does not continue the initiator's latest step",
        );
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(lost.clone())
        );
        assert_eq!(
            latest(&p.b, &rel, &p.a).map(|(a, _)| a),
            Some(facts.predecessor)
        );

        confirm_on_b(&p, &rel, &genuine)
            .await
            .expect("the genuine restart step");
        let addr = ek_cert_step_addr(&genuine.encode_to_vec());
        assert_eq!(
            latest(&p.b, &rel, &p.a),
            Some((addr, facts.new_key.clone()))
        );
        assert_eq!(
            head(&p.b, &rel, CertChainSide::Counterparty),
            Some(facts.new_key.clone())
        );
        confirm_on_b(&p, &rel, &genuine)
            .await
            .expect("the same step confirmed again");
        assert_eq!(
            latest(&p.b, &rel, &p.a),
            Some((addr, facts.new_key.clone()))
        );

        let replayed = RestartOnB {
            predecessor: addr,
            epoch: facts.epoch,
            new_key: dsm::crypto::sphincs::generate_sphincs_keypair()
                .expect("a key")
                .0,
            ..RestartOnB::read(&p)
        };
        let replayed = RestartOnB {
            agreed: AgreedStep {
                tip: replayed.agreed.tip,
                ..replayed.agreed
            },
            ..replayed
        };
        passed_over(
            "a replayed epoch",
            confirm_on_b(&p, &rel, &replayed.step(&p)).await,
            "is not greater than the last",
        );
        let old_request = CertResyncRequest {
            relationship_key: rel,
            agreed_tip: facts.agreed.tip,
            epoch: i64::try_from(facts.epoch).expect("an epoch"),
            preserved_acceptance_commitment: facts.agreed.commitment,
            reply_to_tip: rel,
            new_key: facts.new_key.clone(),
            request_sig: signed_by(
                &p.a,
                &restart_request_statement(
                    &rel,
                    &facts.agreed.tip,
                    facts.epoch,
                    &facts.agreed.commitment,
                    &facts.new_key,
                ),
            ),
        };
        p.b.enter();
        passed_over(
            "a request under an epoch B recorded",
            p.b.router()
                .handle_cert_resync_request(&old_request.to_body(), p.fleet.endpoints())
                .await,
            "is not greater than the last",
        );
    }

    /// Each leg's message is taken only on its own signature and only for the
    /// relationship's own state:
    /// - B passes over a request naming another commitment than its own latest
    ///   accepted step's, though A's AK signed it;
    /// - pending, A passes over an offer whose signature is not B's AK's;
    /// - A passes over a confirmation whose signature is not B's AK's, one B
    ///   signed for a restart A's AK did not sign, and one B signed for a
    ///   restart both AKs signed under another key than the one A derived
    ///   for that epoch.
    /// Nothing moves on either side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_leg_whose_signature_or_state_is_not_the_relationships_is_passed_over() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10]).await;
        let facts = RestartOnB::read(&p);
        let rel = facts.rel;
        let another = dsm::crypto::sphincs::generate_sphincs_keypair()
            .expect("another AK")
            .1;

        let other_commitment = [0x5Fu8; 32];
        let request = CertResyncRequest {
            relationship_key: rel,
            agreed_tip: facts.agreed.tip,
            epoch: 1,
            preserved_acceptance_commitment: other_commitment,
            reply_to_tip: rel,
            new_key: facts.new_key.clone(),
            request_sig: signed_by(
                &p.a,
                &restart_request_statement(
                    &rel,
                    &facts.agreed.tip,
                    1,
                    &other_commitment,
                    &facts.new_key,
                ),
            ),
        };
        p.b.enter();
        passed_over(
            "a request naming another commitment",
            p.b.router()
                .handle_cert_resync_request(&request.to_body(), p.fleet.endpoints())
                .await,
            "agreed step it names",
        );

        lose(&p, &rel, Loss::Heads);
        p.a.sync().await;
        let (_, epoch) = resync_state(&p.a, &rel);
        let (b_step, _) = latest(&p.b, &rel, &p.b).expect("B's own step");
        p.a.enter();
        let (key, _) = derive_resync_ek(&rel, &facts.agreed.tip, &facts.agreed.commitment, epoch)
            .expect("A's key");
        let asked = RestartOnB {
            epoch: u64::try_from(epoch).expect("an epoch"),
            new_key: key,
            ..facts
        };
        let statement = asked.fields().statement();
        let offer = CertResyncOffer {
            relationship_key: rel,
            epoch,
            predecessor: asked.predecessor,
            counterparty_step: b_step,
            counterparty_sig: sphincs_sign(&another, &statement).expect("sign"),
        };
        p.a.enter();
        passed_over(
            "an offer not signed by B's AK",
            p.a.router()
                .handle_cert_resync_offer(&offer.to_body(), p.fleet.endpoints())
                .await,
            "responder's signature",
        );

        let addr = published(&p.a, &asked.step(&p)).await;
        let forged = CertResyncDone {
            relationship_key: rel,
            restart_step: addr,
            counterparty_step: b_step,
            done_sig: sphincs_sign(&another, &restart_done_statement(&addr, &b_step))
                .expect("sign"),
        };
        p.a.enter();
        passed_over(
            "a confirmation not signed by B's AK",
            p.a.router()
                .handle_cert_resync_done(&forged.to_body())
                .await,
            "responder's signature",
        );

        let mut not_by_a = asked.step(&p);
        if let Some(dsm::types::proto::ek_cert_step_v1::Authority::Restart(r)) =
            &mut not_by_a.authority
        {
            r.restarting_sig = sphincs_sign(&another, &statement).expect("sign");
        }
        let not_by_a_addr = published(&p.b, &not_by_a).await;
        let unsigned = CertResyncDone {
            relationship_key: rel,
            restart_step: not_by_a_addr,
            counterparty_step: b_step,
            done_sig: signed_by(&p.b, &restart_done_statement(&not_by_a_addr, &b_step)),
        };
        p.a.enter();
        passed_over(
            "a confirmation of a restart A's AK did not sign",
            p.a.router()
                .handle_cert_resync_done(&unsigned.to_body())
                .await,
            "restarting device's signature",
        );

        let other_key = RestartOnB {
            new_key: dsm::crypto::sphincs::generate_sphincs_keypair()
                .expect("a key")
                .0,
            ..asked
        };
        let other_addr = published(&p.b, &other_key.step(&p)).await;
        let other = CertResyncDone {
            relationship_key: rel,
            restart_step: other_addr,
            counterparty_step: b_step,
            done_sig: signed_by(&p.b, &restart_done_statement(&other_addr, &b_step)),
        };
        p.a.enter();
        passed_over(
            "a confirmation of a restart under another key",
            p.a.router().handle_cert_resync_done(&other.to_body()).await,
            "not the one this device asked for",
        );
        assert_eq!(resync_state(&p.a, &rel), (cdb::RESYNC_PENDING, epoch));
        assert_eq!(head(&p.a, &rel, CertChainSide::Local), None);
        assert_eq!(
            latest(&p.b, &rel, &p.a).map(|(a, _)| a),
            Some(asked.predecessor)
        );
    }

    /// A still holds its own chain after two transfers and lost only its
    /// heads. B's record of A's chain names a restart step both AKs signed
    /// that continues A's FIRST step, not its latest. A walks it, finds it
    /// genuine and at the agreed tip, and still refuses it: it does not
    /// continue the latest step A holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial]
    async fn a_predecessor_that_does_not_continue_the_initiators_own_latest_step_is_passed_over() {
        let p = Pair::boot(100, 0).await;
        paid(&p, &[10, 5]).await;
        let rel = p.a.rel_key_with(&p.b);
        p.b.enter();
        let first: [u8; 32] = {
            let conn = cdb::get_connection().expect("the store");
            let conn = conn.lock().expect("the store's lock");
            let addr: Vec<u8> = conn
                .query_row(
                    "SELECT step_addr FROM ek_cert_step_chain WHERE rel_key = ?1 \
                     AND signer_devid = ?2 ORDER BY step_ordinal ASC LIMIT 1",
                    rusqlite::params![rel.as_slice(), p.a.device_id.as_slice()],
                    |r| r.get(0),
                )
                .expect("A's first step");
            <[u8; 32]>::try_from(addr.as_slice()).expect("32 bytes")
        };
        let facts = RestartOnB {
            predecessor: first,
            ..RestartOnB::read(&p)
        };
        let off_course = facts.step(&p).encode_to_vec();
        let addr = ek_cert_step_addr(&off_course);
        p.b.enter();
        crate::handlers::artifact_republish::ensure_closure_stored(
            &step_set().expect("the set"),
            &[(
                dsm::common::domain_tags::TAG_DSM_EK_CERT_STEP,
                addr,
                off_course,
            )],
        )
        .await
        .expect("published");
        {
            let conn = cdb::get_connection().expect("the store");
            let conn = conn.lock().expect("the store's lock");
            cdb::economic_lineage::append_ek_step_with_conn(
                &conn,
                &rel,
                &p.a.device_id,
                &addr,
                &facts.new_key,
            )
            .expect("recorded on B");
        }

        lose(&p, &rel, Loss::Heads);
        p.a.sync().await;
        let offered = p.b.sync().await;
        assert!(offered.errors.is_empty(), "{:?}", offered.errors);
        let refused = p.a.sync().await;
        assert!(
            refused
                .errors
                .iter()
                .any(|e| e.contains("does not continue the latest step this device holds")),
            "{:?}",
            refused.errors
        );
        assert_eq!(resync_state(&p.a, &rel).0, cdb::RESYNC_PENDING);
        assert_eq!(head(&p.a, &rel, CertChainSide::Local), None);
    }
}
