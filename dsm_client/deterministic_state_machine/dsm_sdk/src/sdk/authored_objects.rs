// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authored objects: content-addressed immutable objects an account
//! publishes under a topic of its own, each signed by its author's AK.
//!
//! An object is `AuthoredObjectV1 { body, signature }`, the body naming its
//! author (genesis, device id, AK, AttA), a 32-byte topic and a payload. It
//! is put under the namespace `DSM/object/authored/v1` and its address is
//! appended under `H(DSM/object/authored-locator/v1 ‖ author device id ‖
//! topic)` (storage spec §5, §7). A reader recognizes an object from its own
//! bytes alone: the body is canonical, the AK and AttA derive the device id
//! it names (`DevID = H(DSM/devid ‖ AK ‖ AttA)`), and the AK signed
//! `H(DSM/object/authored-statement/v1 ‖ body)`. Anyone can append to a
//! locator; a candidate that is not the named author's object is nothing.
//!
//! The payloads mean nothing here. An application decides what its own
//! objects say, and a reader decides whose objects it asks for.

use dsm::crypto::blake3::domain_hash;
use dsm::crypto::domain::TaggedHashDomain;
use dsm::sofi::storage::Discovered;
use dsm::types::error::DsmError;
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::storage_io::{append_to_index, put_immutable, read_stored_bytes, resolve_locator_all};
use crate::sdk::storage_set::StorageSet;

type D32 = [u8; 32];

/// The namespace an authored object is put under.
pub const TAG_AUTHORED_OBJECT: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/object/authored/v1");
/// The domain of the author's signature over a body.
pub const TAG_AUTHORED_STATEMENT: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/object/authored-statement/v1");
/// The domain of an author's locator for a topic, and the index namespace.
pub const TAG_AUTHORED_LOCATOR: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/object/authored-locator/v1");

/// The longest payload one object carries.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
/// Candidates one read examines before it is Partial.
pub const READ_BUDGET: usize = 256;

fn refuse(what: impl Into<String>) -> DsmError {
    DsmError::verification(format!("authored object: {}", what.into()))
}

fn d32(bytes: &[u8], what: &str) -> Result<D32, String> {
    bytes.try_into().map_err(|e| format!("{what}: {e}"))
}

/// `H(DSM/object/authored-locator/v1 ‖ author ‖ topic)`.
pub fn locator(author_device_id: &D32, topic: &D32) -> D32 {
    let mut parts = Vec::with_capacity(64);
    parts.extend_from_slice(author_device_id);
    parts.extend_from_slice(topic);
    *domain_hash(TAG_AUTHORED_LOCATOR, &parts).as_bytes()
}

fn statement(body: &[u8]) -> D32 {
    *domain_hash(TAG_AUTHORED_STATEMENT, body).as_bytes()
}

/// One object recognized from its own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authored {
    /// Its immutable address.
    pub address: D32,
    pub author_genesis: D32,
    pub author_device_id: D32,
    pub topic: D32,
    pub payload: Vec<u8>,
}

/// The locator `bytes` belong under and what they say, when they are an
/// authored object: canonical, its AK and AttA deriving the device id it
/// names, and its signature that AK's over the body. Why not, otherwise.
pub fn check(bytes: &[u8]) -> Result<(D32, Authored), String> {
    let object =
        generated::AuthoredObjectV1::decode(bytes).map_err(|e| format!("the object: {e}"))?;
    if object.encode_to_vec() != bytes {
        return Err("the object is not in its canonical encoding".into());
    }
    let body = generated::AuthoredObjectBodyV1::decode(object.body.as_slice())
        .map_err(|e| format!("the body: {e}"))?;
    if body.encode_to_vec() != object.body {
        return Err("the body is not in its canonical encoding".into());
    }
    if body.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!("a payload past {MAX_PAYLOAD_BYTES} bytes"));
    }
    let author_genesis = d32(&body.author_genesis, "the author's genesis")?;
    let author_device_id = d32(&body.author_device_id, "the author's device id")?;
    let att_a = d32(&body.author_att_a, "the author's AttA")?;
    let topic = d32(&body.topic, "the topic")?;
    if dsm::core::identity::genesis_v2::derive_devid(&body.author_ak, &att_a) != author_device_id {
        return Err("the AK and AttA do not derive the device id the object names".into());
    }
    match dsm::crypto::sphincs::sphincs_verify(
        &body.author_ak,
        &statement(&object.body),
        &object.signature,
    ) {
        Ok(verified) if verified => {}
        Ok(..) => return Err("the signature does not verify under the author's AK".into()),
        Err(e) => return Err(format!("the signature cannot be checked: {e}")),
    }
    Ok((
        locator(&author_device_id, &topic),
        Authored {
            address: dsm::storage_object::immutable_addr(TAG_AUTHORED_OBJECT, bytes),
            author_genesis,
            author_device_id,
            topic,
            payload: body.payload,
        },
    ))
}

/// [`check`] as a locator scan takes it: a candidate that is not an
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
    let (address, _) = put_immutable(set, TAG_AUTHORED_OBJECT, &bytes).await?;
    let locator = locator(&recognized.author_device_id, topic);
    append_to_index(set, TAG_AUTHORED_LOCATOR.source_bytes(), &locator, &address).await?;
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
        TAG_AUTHORED_LOCATOR.source_bytes(),
        &locator(author, topic),
        READ_BUDGET,
        recognize,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsVariant};

    /// An object authored by a fresh key, with the device id its AK and AttA
    /// derive, unless `device_id` names another.
    fn object(device_id: Option<D32>, payload: &[u8]) -> Result<(Vec<u8>, D32), String> {
        let kp = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        let att_a = [9u8; 32];
        let derived = dsm::core::identity::genesis_v2::derive_devid(&kp.public_key, &att_a);
        let body = generated::AuthoredObjectBodyV1 {
            author_genesis: vec![1; 32],
            author_device_id: match device_id {
                Some(claimed) => claimed.to_vec(),
                None => derived.to_vec(),
            },
            author_ak: kp.public_key.clone(),
            author_att_a: att_a.to_vec(),
            topic: vec![5; 32],
            payload: payload.to_vec(),
        }
        .encode_to_vec();
        let signature =
            sphincs_sign(&kp.secret_key, &statement(&body)).map_err(|e| e.to_string())?;
        Ok((
            generated::AuthoredObjectV1 { body, signature }.encode_to_vec(),
            derived,
        ))
    }

    #[test]
    fn an_object_is_recognized_under_its_authors_locator_for_its_topic() -> Result<(), String> {
        let (bytes, author) = object(None, b"state 1")?;
        let (at, read) = recognize(&bytes).ok_or("recognized")?;
        assert_eq!(at, locator(&author, &[5; 32]));
        assert_eq!(read.author_device_id, author);
        assert_eq!(read.payload, b"state 1".to_vec());
        assert_eq!(
            read.address,
            dsm::storage_object::immutable_addr(TAG_AUTHORED_OBJECT, &bytes)
        );
        assert_ne!(locator(&author, &[5; 32]), locator(&author, &[6; 32]));
        assert_ne!(locator(&author, &[5; 32]), locator(&[4; 32], &[5; 32]));
        Ok(())
    }

    /// An object naming a device its AK does not derive, a signature over
    /// another body, and bytes not in their canonical encoding are nothing.
    #[test]
    fn an_object_not_its_authors_own_is_nothing() -> Result<(), String> {
        let (claimed, _) = object(Some([4; 32]), b"state 1")?;
        assert!(
            recognize(&claimed).is_none(),
            "a device the AK does not derive"
        );

        let (bytes, _) = object(None, b"state 1")?;
        let mut object =
            generated::AuthoredObjectV1::decode(bytes.as_slice()).map_err(|e| e.to_string())?;
        let mut body = generated::AuthoredObjectBodyV1::decode(object.body.as_slice())
            .map_err(|e| e.to_string())?;
        body.payload = b"state 2".to_vec();
        object.body = body.encode_to_vec();
        assert!(
            recognize(&object.encode_to_vec()).is_none(),
            "a payload the signature does not cover"
        );

        let mut longer = bytes.clone();
        longer.extend([0x08, 0x01]);
        assert!(recognize(&longer).is_none(), "bytes past the object");
        Ok(())
    }
}
