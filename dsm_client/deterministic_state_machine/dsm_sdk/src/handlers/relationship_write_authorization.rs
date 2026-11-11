// SPDX-License-Identifier: MIT OR Apache-2.0
//! A relationship's write keys and grants, as the two wallets make, answer
//! and keep them (DSM Amendment A34).
//!
//! Each device has a write key of its own for each relationship it
//! established, toward each counterparty: it comes back from the master seed,
//! the relationship instance and the two device ids, so nothing secret is
//! stored. Each device grants the other's key its inbox for that instance,
//! signed by its AK. Everything rides with the messages establishment already
//! sends, so nobody waits for anything establishment does not already wait
//! for:
//!
//! - the maker freezes its offer in the transaction that commits its
//!   ESTABLISH step, and delivers it with the step;
//! - the other device freezes its own offer in the transaction that applies
//!   the step, then, in the same sync, grants the maker's key and delivers
//!   both;
//! - the maker, in the sync that reads them once it has finalized on the
//!   countersignature, takes the grant and grants the other device's key in
//!   turn.
//!
//! An offer is answered only on a relationship this device holds established,
//! for the instance its own establishment recorded: an establishment that
//! failed or never finished leaves no grant to use. No storage node takes part
//! in any of it.

use dsm::core::relationship_write_grant::{
    decode_write_authorization_wire, decode_write_key_offer_wire, decode_write_lock_wire,
    derive_write_keypair, derive_write_lock_keypair, relationship_instance_id,
    verify_write_authorization, verify_write_key_offer, write_authorization_wire,
    AuthorizationExpectation, OfferExpectation, WriteGrant, WriteKeyOffer, WriteLock,
};
use dsm::types::error::DsmError;
use prost::Message;

use super::app_router_impl::{contact_relationship_tip, AppRouterImpl};
use crate::sdk::wallet_sdk::WalletSDK;
use crate::storage::client_db::{
    self, HeldGrant, RelationshipState, WriteAuthorizationRecorded, WriteDirection,
};

/// This device's offer for one relationship instance, built and signed, ready
/// to be frozen with the establishment that opened the instance.
#[derive(Clone, Debug)]
pub(crate) struct FrozenOffer {
    pub relationship_instance_id: [u8; 32],
    pub write_public_key: Vec<u8>,
    pub wire: Vec<u8>,
}

impl FrozenOffer {
    /// Freeze it in the establishment's own transaction.
    pub(crate) fn freeze_with_conn(
        &self,
        conn: &rusqlite::Connection,
        counterparty: &[u8; 32],
    ) -> Result<(), DsmError> {
        client_db::freeze_own_offer_with_conn(
            conn,
            counterparty,
            &self.relationship_instance_id,
            &self.write_public_key,
            &self.wire,
        )
        .map(|_| ())
        .map_err(|e| {
            DsmError::internal(
                format!("the write-key offer was not frozen: {e}"),
                None::<std::io::Error>,
            )
        })
    }
}

/// Build this device's offer of its write key to `counterparty`, for the
/// instance the establishment reaching `established_tip` opens. The write key
/// signs possession; this device's AK binds it. Both signatures are checked
/// here before anything is frozen.
pub(crate) fn build_own_offer(
    wallet: &WalletSDK,
    this_device: &[u8; 32],
    counterparty: &[u8; 32],
    relationship_key: &[u8; 32],
    established_tip: &[u8; 32],
) -> Result<FrozenOffer, DsmError> {
    let instance = relationship_instance_id(relationship_key, established_tip);
    let s_master = zeroize::Zeroizing::new(crate::init::current_smaster()?);
    let write_key = derive_write_keypair(&s_master, &instance, this_device, counterparty)?;
    let offer = WriteKeyOffer {
        relationship_instance_id: instance,
        sender_device_id: *this_device,
        recipient_device_id: *counterparty,
        write_public_key: write_key.public_key.clone(),
    };
    let possession =
        dsm::crypto::sphincs::sphincs_sign(&write_key.secret_key, &offer.possession_target())?;
    let binding = wallet.sign_operation_bytes(&offer.binding_target())?;
    let wire = offer.to_wire(possession, binding);
    let own_ak = crate::sdk::signing_authority::current_public_key()?;
    verify_write_key_offer(
        &wire,
        &OfferExpectation {
            relationship_instance_id: &instance,
            sender_device_id: this_device,
            recipient_device_id: counterparty,
            sender_ak: &own_ak,
        },
    )?;
    Ok(FrozenOffer {
        relationship_instance_id: instance,
        write_public_key: write_key.public_key.clone(),
        wire: wire.encode_to_vec(),
    })
}

/// What reading one offer or grant came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteAuthorizationChecked {
    /// Answered or recorded, or already held: the copy has done all it can.
    Done,
    /// Not yet: the relationship is not established here, or this device's
    /// own establishment has not reached its key. Left on its route and read
    /// again.
    NotEstablished(String),
    /// It never will be anything here. Passed over.
    Refused(String),
}

fn device_32(bytes: &[u8], what: &str) -> Result<[u8; 32], WriteAuthorizationChecked> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|e| WriteAuthorizationChecked::Refused(format!("{what}: {e}")))
}

/// The counterparty's contact and this device's own write authorization
/// toward it, when the relationship is established here.
fn established_with(
    counterparty: &[u8; 32],
) -> Result<(client_db::ContactRecord, client_db::OwnWriteAuthorization), WriteAuthorizationChecked>
{
    let contact = match client_db::get_contact_by_device_id(counterparty) {
        Ok(Some(contact)) => contact,
        Ok(None) => {
            return Err(WriteAuthorizationChecked::Refused(
                "it comes from no contact".to_string(),
            ))
        }
        Err(e) => {
            return Err(WriteAuthorizationChecked::NotEstablished(format!(
                "the contact is unreadable: {e}"
            )))
        }
    };
    match client_db::relationship_state(counterparty) {
        // Established here, or this device's own ESTABLISH in flight: its
        // chain already holds the step, and the instance it opened is the one
        // this device's own row records. The maker must take the other side's
        // grant before it can finalize: its certificate goes to a locked inbox.
        Ok(RelationshipState::Established | RelationshipState::Proposed) => {}
        Ok(state) if state.is_over() => {
            return Err(WriteAuthorizationChecked::Refused(
                "the relationship has ended".to_string(),
            ))
        }
        Ok(state) => {
            return Err(WriteAuthorizationChecked::NotEstablished(format!(
                "the relationship is {} here, not established",
                state.as_str()
            )))
        }
        Err(e) => {
            return Err(WriteAuthorizationChecked::NotEstablished(format!(
                "the relationship's state is unreadable: {e}"
            )))
        }
    }
    match client_db::own_write_authorization(counterparty) {
        Ok(Some(own)) => Ok((contact, own)),
        Ok(None) => Err(WriteAuthorizationChecked::NotEstablished(
            "this device's establishment holds no write key for the relationship".to_string(),
        )),
        Err(e) => Err(WriteAuthorizationChecked::NotEstablished(format!(
            "this device's write key is unreadable: {e}"
        ))),
    }
}

impl AppRouterImpl {
    /// Answer a counterparty's offer of its write key with this device's
    /// grant, when the relationship is established here and the offer is for
    /// the instance this device's own establishment recorded.
    pub(crate) async fn take_in_write_key_offer(&self, body: &[u8]) -> WriteAuthorizationChecked {
        let wire = match decode_write_key_offer_wire(body) {
            Ok(wire) => wire,
            Err(e) => return WriteAuthorizationChecked::Refused(e.to_string()),
        };
        let sender = match device_32(&wire.sender_device_id, "its sender") {
            Ok(sender) => sender,
            Err(refused) => return refused,
        };
        if wire.recipient_device_id.as_slice() != self.device_id_bytes.as_slice() {
            return WriteAuthorizationChecked::Refused(
                "it is addressed to another device".to_string(),
            );
        }
        let (contact, own) = match established_with(&sender) {
            Ok(held) => held,
            Err(not_yet) => return not_yet,
        };
        let offer = match verify_write_key_offer(
            &wire,
            &OfferExpectation {
                relationship_instance_id: &own.relationship_instance_id,
                sender_device_id: &sender,
                recipient_device_id: &self.device_id_bytes,
                sender_ak: &contact.public_key,
            },
        ) {
            Ok(offer) => offer,
            Err(e) => return WriteAuthorizationChecked::Refused(e.to_string()),
        };
        match client_db::issued_write_grant(&sender) {
            Ok(Some(issued)) if issued.write_public_key == offer.write_public_key => {
                return WriteAuthorizationChecked::Done
            }
            Ok(Some(_)) => {
                return WriteAuthorizationChecked::Refused(
                    "this device already granted the contact another write key".to_string(),
                )
            }
            Ok(None) => {}
            Err(e) => {
                return WriteAuthorizationChecked::NotEstablished(format!(
                    "the grants issued are unreadable: {e}"
                ))
            }
        }
        let issued = match self.issue_write_grant(&offer).await {
            Ok(issued) => issued,
            Err(e) => {
                return WriteAuthorizationChecked::NotEstablished(format!(
                    "the grant could not be signed: {e}"
                ))
            }
        };
        match client_db::record_grant_issued(
            &sender,
            &offer.relationship_instance_id,
            &offer.write_public_key,
            &issued,
        ) {
            Ok(WriteAuthorizationRecorded::Recorded) => {
                log::info!(
                    "[relationship.write] granted {}..'s write key this device's inbox for the \
                     relationship",
                    crate::util::text_id::encode_base32_crockford(&sender[..4])
                );
                WriteAuthorizationChecked::Done
            }
            Ok(WriteAuthorizationRecorded::AlreadyHeld) => WriteAuthorizationChecked::Done,
            Err(e) => WriteAuthorizationChecked::Refused(e.to_string()),
        }
    }

    /// This device's authorization of a verified offer's key: its write lock
    /// over its inbox for the instance, bound by its AK to the instance,
    /// itself and the sender, and the lock's grant of the key. Checked as the
    /// sender will check it before it is returned.
    async fn issue_write_grant(&self, offer: &WriteKeyOffer) -> Result<HeldGrant, DsmError> {
        let genesis = self.core_sdk.local_genesis_hash().await?;
        let genesis: [u8; 32] = genesis.as_slice().try_into().map_err(|e| {
            DsmError::invalid_operation(format!("the local genesis is not 32 bytes: {e}"))
        })?;
        let s_master = zeroize::Zeroizing::new(crate::init::current_smaster()?);
        let lock_key = derive_write_lock_keypair(
            &s_master,
            &offer.relationship_instance_id,
            &self.device_id_bytes,
            &offer.sender_device_id,
        )?;
        let lock = WriteLock {
            relationship_instance_id: offer.relationship_instance_id,
            recipient_genesis: genesis,
            recipient_device_id: self.device_id_bytes,
            authorized_sender_device_id: offer.sender_device_id,
            lock_public_key: lock_key.public_key.clone(),
        };
        let lock_wire = lock.to_wire(self.wallet.sign_operation_bytes(&lock.binding_target())?);
        let grant = WriteGrant::of_key(
            offer.relationship_instance_id,
            offer.write_public_key.clone(),
        );
        let grant_wire = grant.to_wire(dsm::crypto::sphincs::sphincs_sign(
            &lock_key.secret_key,
            &grant.signing_target(),
        )?);
        let authorization = write_authorization_wire(&lock_wire, &grant_wire);
        let own_ak = crate::sdk::signing_authority::current_public_key()?;
        verify_write_authorization(
            &authorization,
            &AuthorizationExpectation {
                relationship_instance_id: &offer.relationship_instance_id,
                recipient_genesis: &genesis,
                recipient_device_id: &self.device_id_bytes,
                sender_device_id: &offer.sender_device_id,
                write_public_key: &offer.write_public_key,
                recipient_ak: &own_ak,
            },
        )?;
        Ok(HeldGrant {
            grant_id: grant.grant_id(),
            grant_wire: authorization,
        })
    }

    /// Take a counterparty's authorization of this device's write key, when
    /// the relationship is established here: its AK bound its lock to this
    /// device's instance, itself and this device, and the lock granted this
    /// device's own write key.
    pub(crate) fn take_in_write_grant(&self, body: &[u8]) -> WriteAuthorizationChecked {
        let lock = match decode_write_authorization_wire(body)
            .and_then(|authorization| decode_write_lock_wire(&authorization.lock))
        {
            Ok(lock) => lock,
            Err(e) => return WriteAuthorizationChecked::Refused(e.to_string()),
        };
        let granter = match device_32(&lock.recipient_device_id, "its recipient") {
            Ok(granter) => granter,
            Err(refused) => return refused,
        };
        if lock.authorized_sender_device_id.as_slice() != self.device_id_bytes.as_slice() {
            return WriteAuthorizationChecked::Refused("it authorizes another device".to_string());
        }
        let (contact, own) = match established_with(&granter) {
            Ok(held) => held,
            Err(not_yet) => return not_yet,
        };
        let genesis = match device_32(&contact.genesis_hash, "the contact's genesis") {
            Ok(genesis) => genesis,
            Err(refused) => return refused,
        };
        let verified = match verify_write_authorization(
            body,
            &AuthorizationExpectation {
                relationship_instance_id: &own.relationship_instance_id,
                recipient_genesis: &genesis,
                recipient_device_id: &granter,
                sender_device_id: &self.device_id_bytes,
                write_public_key: &own.write_public_key,
                recipient_ak: &contact.public_key,
            },
        ) {
            Ok(verified) => verified,
            Err(e) => return WriteAuthorizationChecked::Refused(e.to_string()),
        };
        let held = HeldGrant {
            grant_id: verified.grant.grant_id(),
            grant_wire: body.to_vec(),
        };
        match client_db::record_grant_received(&granter, &own.relationship_instance_id, &held) {
            Ok(WriteAuthorizationRecorded::Recorded) => {
                log::info!(
                    "[relationship.write] {}.. granted this device's write key its inbox",
                    crate::util::text_id::encode_base32_crockford(&granter[..4])
                );
                WriteAuthorizationChecked::Done
            }
            Ok(WriteAuthorizationRecorded::AlreadyHeld) => WriteAuthorizationChecked::Done,
            Err(e) => WriteAuthorizationChecked::Refused(e.to_string()),
        }
    }

    /// Deliver every frozen offer and issued grant not yet delivered, to
    /// `only` or to every counterparty, on the relationship's current route.
    /// A delivery that failed stays owed for the next sync; a relationship
    /// over is owed nothing more. Answers what could not be done.
    pub(crate) async fn deliver_owed_write_authorizations(
        &self,
        storage_endpoints: &[String],
        only: Option<[u8; 32]>,
    ) -> Vec<String> {
        let owed = match client_db::owed_write_authorizations() {
            Ok(owed) => owed,
            Err(e) => return vec![format!("write authorizations owed: {e}")],
        };
        let mut failures = Vec::new();
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
        for item in owed
            .into_iter()
            .filter(|item| only.is_none_or(|device| device == item.counterparty_device_id))
        {
            let counterparty = item.counterparty_device_id;
            let short = crate::util::text_id::encode_base32_crockford(&counterparty[..4]);
            match client_db::relationship_state(&counterparty) {
                Ok(state) if state.is_over() => continue,
                Ok(_) => {}
                Err(e) => {
                    failures.push(format!("{short}..'s relationship state: {e}"));
                    continue;
                }
            }
            let contact = match client_db::get_contact_by_device_id(&counterparty) {
                Ok(Some(contact)) => contact,
                Ok(None) => continue,
                Err(e) => {
                    failures.push(format!("{short}..'s contact: {e}"));
                    continue;
                }
            };
            // Under the counterparty's lock once its grant is held; until
            // then on the relationship's first inbox, under this device's own
            // key there (DSM Amendment A34).
            let route = match crate::sdk::spool_write::holds_grant(&counterparty) {
                Ok(held) if held => contact_relationship_tip(&contact).and_then(|tip| {
                    <[u8; 32]>::try_from(contact.genesis_hash.as_slice())
                        .map(|genesis| (genesis, tip))
                        .map_err(|e| format!("the contact's genesis: {e}"))
                }),
                Ok(_) => crate::sdk::spool_write::first_inbox(&counterparty)
                    .map(|(first_tip, genesis, _)| (genesis, first_tip))
                    .map_err(|e| format!("the first inbox: {e}")),
                Err(e) => Err(format!("the write authorization: {e}")),
            };
            let (genesis, tip) = match route {
                Ok(route) => route,
                Err(e) => {
                    failures.push(format!("{short}..'s route: {e}"));
                    continue;
                }
            };
            let method = match item.direction {
                WriteDirection::Outbound => {
                    crate::sdk::b0x_sdk::RELATIONSHIP_WRITE_KEY_OFFER_METHOD
                }
                WriteDirection::Inbound => crate::sdk::b0x_sdk::RELATIONSHIP_WRITE_GRANT_METHOD,
            };
            let mut b0x = match crate::sdk::b0x_sdk::B0xSDK::new(
                device_id_b32.clone(),
                self.core_sdk.clone(),
                storage_endpoints.to_vec(),
            ) {
                Ok(b0x) => b0x,
                Err(e) => {
                    failures.push(format!("the inbox client: {e}"));
                    continue;
                }
            };
            if let Err(e) = b0x
                .submit_control_message(method, item.message, &genesis, &counterparty, &tip)
                .await
            {
                failures.push(format!(
                    "delivering the {} write authorization to {short}..: {e}",
                    item.direction.as_str()
                ));
                continue;
            }
            if let Err(e) =
                client_db::mark_write_authorization_delivered(&counterparty, item.direction)
            {
                failures.push(format!(
                    "marking the {} write authorization to {short}.. delivered: {e}",
                    item.direction.as_str()
                ));
            }
        }
        failures
    }
}
