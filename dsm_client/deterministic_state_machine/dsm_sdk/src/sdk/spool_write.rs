// SPDX-License-Identifier: MIT OR Apache-2.0
//! The write a device sends a storage node for each envelope it puts in a
//! counterparty's inbox (DSM Amendment A34): the envelope, the inbox's key,
//! that key's grant of this device's write key, and this device's signature
//! over the address, the message id and the envelope.
//!
//! At the relationship's **first inbox** (the address its first tip routes
//! to), this device writes before either side holds a lock: it fixes a key of
//! its own there, lock and write key at once, the same one every time. At
//! **every other address** it writes under the counterparty's lock, carrying
//! the grant the counterparty sent it; with no grant held yet, it does not
//! write there, and the caller retries once the grant has been read. The node
//! sees public keys alone.

use dsm::core::relationship_write_grant::{
    decode_write_authorization_wire, decode_write_lock_wire, derive_first_inbox_keypair,
    derive_write_keypair, relationship_instance_id, self_granted_spool_write, signed_spool_write,
};
use dsm::types::error::DsmError;

use crate::storage::client_db;

fn decode_fixed<const N: usize>(text: &str, what: &str) -> Result<[u8; N], DsmError> {
    let bytes = crate::util::text_id::decode_base32_crockford(text)
        .ok_or_else(|| DsmError::invalid_parameter(format!("{what} is not Base32")))?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|e| {
        DsmError::invalid_parameter(format!("{what} is {} bytes, not {N}: {e}", bytes.len()))
    })
}

fn this_device() -> Result<([u8; 32], [u8; 32]), DsmError> {
    let device = crate::sdk::app_state::AppState::get_device_id()
        .ok_or_else(|| DsmError::invalid_operation("no device id"))?;
    let genesis = crate::sdk::app_state::AppState::get_genesis_hash()
        .ok_or_else(|| DsmError::invalid_operation("no genesis"))?;
    Ok((
        <[u8; 32]>::try_from(device.as_slice())
            .map_err(|e| DsmError::invalid_operation(format!("the device id: {e}")))?,
        <[u8; 32]>::try_from(genesis.as_slice())
            .map_err(|e| DsmError::invalid_operation(format!("the genesis: {e}")))?,
    ))
}

/// The tip `recipient`'s relationship with this device opened at, and the
/// address of `recipient`'s first inbox on it.
pub(crate) fn first_inbox(recipient: &[u8; 32]) -> Result<([u8; 32], [u8; 32], String), DsmError> {
    let (device, genesis) = this_device()?;
    let contact = client_db::get_contact_by_device_id(recipient)
        .map_err(|e| DsmError::invalid_operation(format!("the recipient's contact: {e}")))?
        .ok_or_else(|| DsmError::invalid_operation("the recipient is no contact"))?;
    let recipient_genesis = <[u8; 32]>::try_from(contact.genesis_hash.as_slice())
        .map_err(|e| DsmError::invalid_operation(format!("the recipient's genesis: {e}")))?;
    let first_tip = dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip(
        &device,
        &genesis,
        recipient,
        &recipient_genesis,
    );
    let address =
        dsm::crypto::spool_address::inbox_address(&recipient_genesis, recipient, &first_tip);
    Ok((first_tip, recipient_genesis, address))
}

/// Whether this device holds `recipient`'s grant for its write key.
pub(crate) fn holds_grant(recipient: &[u8; 32]) -> Result<bool, DsmError> {
    client_db::own_write_authorization(recipient)
        .map(|own| own.is_some_and(|own| own.grant.is_some()))
        .map_err(|e| DsmError::invalid_operation(format!("the write authorization: {e}")))
}

/// The write this device sends for `envelope` to `recipient`'s inbox at
/// `routing_key` under `message_id_b32`: the request body a storage node
/// takes.
pub(crate) fn write_for(
    recipient: &[u8; 32],
    routing_key: &str,
    message_id_b32: &str,
    envelope: &[u8],
) -> Result<Vec<u8>, DsmError> {
    let address: [u8; 32] = decode_fixed(routing_key, "the inbox address")?;
    let message_id: [u8; 16] = decode_fixed(message_id_b32, "the message id")?;
    let (device, _) = this_device()?;
    let s_master = zeroize::Zeroizing::new(crate::init::current_smaster()?);
    let relationship_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(&device, recipient);
    let (first_tip, _, first_address) = first_inbox(recipient)?;
    if routing_key == first_address {
        let key = derive_first_inbox_keypair(
            &s_master,
            &relationship_key,
            &first_tip,
            &device,
            recipient,
        )?;
        return self_granted_spool_write(
            &key,
            &relationship_instance_id(&relationship_key, &first_tip),
            &address,
            &message_id,
            envelope,
        );
    }
    let own = client_db::own_write_authorization(recipient)
        .map_err(|e| DsmError::invalid_operation(format!("the write authorization: {e}")))?
        .ok_or_else(|| {
            DsmError::invalid_operation(
                "no write key toward the recipient: the relationship is not established here",
            )
        })?;
    let held = own.grant.ok_or_else(|| {
        DsmError::invalid_operation(
            "the recipient's write grant is not held yet: it is read on the next sync",
        )
    })?;
    let authorization = decode_write_authorization_wire(&held.grant_wire)?;
    let lock = decode_write_lock_wire(&authorization.lock)?;
    let write_key =
        derive_write_keypair(&s_master, &own.relationship_instance_id, &device, recipient)?;
    signed_spool_write(
        &write_key,
        &lock.lock_public_key,
        authorization.grant,
        &address,
        &message_id,
        envelope,
    )
}

/// The counterparty of the relationship `relationship_key` names, among this
/// device's contacts.
pub(crate) fn counterparty_of(relationship_key: &[u8; 32]) -> Result<[u8; 32], DsmError> {
    let (device, _) = this_device()?;
    let contacts = client_db::get_all_contacts()
        .map_err(|e| DsmError::invalid_operation(format!("the contacts: {e}")))?;
    for contact in contacts {
        let peer = match <[u8; 32]>::try_from(contact.device_id.as_slice()) {
            Ok(peer) => peer,
            Err(e) => {
                log::warn!("[spool.write] contact {}'s device id: {e}", contact.alias);
                continue;
            }
        };
        if &dsm::core::bilateral_transaction_manager::compute_smt_key(&device, &peer)
            == relationship_key
        {
            return Ok(peer);
        }
    }
    Err(DsmError::invalid_operation(
        "no contact holds the relationship the write is on",
    ))
}
