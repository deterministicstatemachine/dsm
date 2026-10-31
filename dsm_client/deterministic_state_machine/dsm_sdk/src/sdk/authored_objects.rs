// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authored objects, as this device publishes and reads them (storage spec
//! §5, §7).
//!
//! What an authored object is, the statement its author signs, the locator
//! it is appended under and how a reader recognizes one from its own bytes
//! are Core's (`dsm::authored_object`): an author and every reader apply the
//! one rule. Here are signing under this device's AK, and the storage reads
//! and writes.

use dsm::authored_object::{check, locator, statement, Authored, MAX_PAYLOAD_BYTES};
use dsm::common::domain_tags::{TAG_DSM_AUTHORED_LOCATOR, TAG_DSM_AUTHORED_OBJECT};
use dsm::sofi::storage::Discovered;
use dsm::types::error::DsmError;
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::storage_io::{append_to_index, put_immutable, read_stored_bytes, resolve_locator_all};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// Candidates one read examines before it is Partial.
pub const READ_BUDGET: usize = 256;

fn refuse(what: impl Into<String>) -> DsmError {
    DsmError::verification(format!("authored object: {}", what.into()))
}

/// Core's [`check`] as a locator scan takes it: a candidate that is not an
/// authored object is nothing, and why is logged.
pub fn recognize(bytes: &[u8]) -> Option<(D32, Authored)> {
    match check(bytes) {
        Ok(recognized) => Some(recognized),
        Err(why) => {
            log::debug!("[authored] a candidate is no authored object: {why}");
            None
        }
    }
}

/// This device's object on `topic` carrying `payload`: its bytes, signed
/// under this device's AK.
pub fn authored_by_this_device(topic: &D32, payload: &[u8]) -> Result<Vec<u8>, DsmError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(refuse(format!(
            "a payload of {} bytes is past the {MAX_PAYLOAD_BYTES}-byte bound",
            payload.len()
        )));
    }
    let (card, att_a) = crate::sdk::connect::signed::own_card().map_err(refuse)?;
    let body = generated::AuthoredObjectBodyV1 {
        author_genesis: card.genesis_hash,
        author_device_id: card.device_id,
        author_ak: card.signing_public_key,
        author_att_a: att_a.to_vec(),
        topic: topic.to_vec(),
        payload: payload.to_vec(),
    }
    .encode_to_vec();
    let (_, secret) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| refuse(format!("this device's signing key: {e}")))?;
    let signature = dsm::crypto::sphincs::sphincs_sign(&secret, &statement(&body))
        .map_err(|e| refuse(format!("signing: {e}")))?;
    Ok(generated::AuthoredObjectV1 { body, signature }.encode_to_vec())
}

/// What publishing one object established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub address: D32,
    pub locator: D32,
    /// `Stored`, read back from the members after the put.
    pub stored: bool,
}

/// Publish this device's object on `topic`: put its bytes at every member,
/// append its address under this device's locator for the topic, and read
/// `Stored` back. Publishing the same payload again is the same object.
pub async fn publish(set: &StorageSet, topic: &D32, payload: &[u8]) -> Result<Published, DsmError> {
    let bytes = authored_by_this_device(topic, payload)?;
    let (_, recognized) =
        recognize(&bytes).ok_or_else(|| refuse("this device's own object does not verify"))?;
    let (address, _) = put_immutable(set, TAG_DSM_AUTHORED_OBJECT, &bytes).await?;
    let locator = locator(&recognized.author_device_id, topic);
    append_to_index(
        set,
        TAG_DSM_AUTHORED_LOCATOR.source_bytes(),
        &locator,
        &address,
    )
    .await?;
    let stored = read_stored_bytes(set, &address)
        .await?
        .is_some_and(|read| read == bytes);
    Ok(Published {
        address,
        locator,
        stored,
    })
}

/// Every object `author` published on `topic`, each recognized from its own
/// bytes, in append order; `Partial` when not every candidate was read.
pub async fn read(
    set: &StorageSet,
    author: &D32,
    topic: &D32,
) -> Result<Discovered<Authored>, DsmError> {
    resolve_locator_all(
        set,
        TAG_DSM_AUTHORED_LOCATOR.source_bytes(),
        &locator(author, topic),
        READ_BUDGET,
        recognize,
    )
    .await
}
