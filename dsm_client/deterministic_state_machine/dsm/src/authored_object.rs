// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authored objects: content-addressed immutable objects an account
//! publishes under a topic of its own, each signed by its author's AK
//! (storage spec §5, §7).
//!
//! An object is `AuthoredObjectV1 { body, signature }`, the body naming its
//! author (genesis, device id, AK, AttA), a 32-byte topic and a payload. It
//! is put under the namespace `DSM/object/authored/v1` and its address is
//! appended under `H(DSM/object/authored-locator/v1 ‖ author device id ‖
//! topic)`. A reader recognizes an object from its own bytes alone, by the
//! same rule its author signed under, so the rule exists once, here: the
//! body is canonical, the AK and AttA derive the device id it names
//! (`DevID = H(DSM/devid ‖ AK ‖ AttA)`), and the AK signed
//! `H(DSM/object/authored-statement/v1 ‖ body)`. Anyone can append to a
//! locator; a candidate that is not the named author's object is nothing.
//!
//! The payloads mean nothing here. An application decides what its own
//! objects say, and a reader decides whose objects it asks for.

use prost::Message;

use crate::common::domain_tags::{
    TAG_DSM_AUTHORED_LOCATOR, TAG_DSM_AUTHORED_OBJECT, TAG_DSM_AUTHORED_STATEMENT,
};
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::blake3::domain_hash;
use crate::crypto::sphincs::sphincs_verify;
use crate::storage_object::immutable_addr;
use crate::types::proto::{AuthoredObjectBodyV1, AuthoredObjectV1};

type D32 = [u8; 32];

/// The longest payload one object carries.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// `H(DSM/object/authored-locator/v1 ‖ author ‖ topic)`.
pub fn locator(author_device_id: &D32, topic: &D32) -> D32 {
    let mut parts = Vec::with_capacity(64);
    parts.extend_from_slice(author_device_id);
    parts.extend_from_slice(topic);
    *domain_hash(TAG_DSM_AUTHORED_LOCATOR, &parts).as_bytes()
}

/// The 32 bytes an author signs for the body `body`.
pub fn statement(body: &[u8]) -> D32 {
    *domain_hash(TAG_DSM_AUTHORED_STATEMENT, body).as_bytes()
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

/// Why bytes are not an authored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoredError {
    /// The object or its body does not decode.
    DoesNotDecode { what: &'static str, why: String },
    /// The object or its body is not in its canonical encoding.
    NotCanonical { what: &'static str },
    /// The payload is past [`MAX_PAYLOAD_BYTES`].
    PayloadPastBound { len: usize },
    /// A field naming a 32-byte value is another length.
    NotThirtyTwoBytes { what: &'static str, why: String },
    /// The AK and AttA do not derive the device id the object names.
    DeviceIdNotDerived,
    /// The signature is not the author's AK's over the body.
    SignatureDoesNotVerify,
    /// The signature could not be checked at all.
    SignatureUncheckable { why: String },
}

impl core::fmt::Display for AuthoredError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthoredError::DoesNotDecode { what, why } => write!(f, "{what}: {why}"),
            AuthoredError::NotCanonical { what } => {
                write!(f, "{what} is not in its canonical encoding")
            }
            AuthoredError::PayloadPastBound { len } => write!(
                f,
                "a payload of {len} bytes is past {MAX_PAYLOAD_BYTES} bytes"
            ),
            AuthoredError::NotThirtyTwoBytes { what, why } => write!(f, "{what}: {why}"),
            AuthoredError::DeviceIdNotDerived => write!(
                f,
                "the AK and AttA do not derive the device id the object names"
            ),
            AuthoredError::SignatureDoesNotVerify => {
                write!(f, "the signature does not verify under the author's AK")
            }
            AuthoredError::SignatureUncheckable { why } => {
                write!(f, "the signature cannot be checked: {why}")
            }
        }
    }
}

impl std::error::Error for AuthoredError {}

fn d32(bytes: &[u8], what: &'static str) -> Result<D32, AuthoredError> {
    bytes.try_into().map_err(
        |e: core::array::TryFromSliceError| AuthoredError::NotThirtyTwoBytes {
            what,
            why: e.to_string(),
        },
    )
}

/// The locator `bytes` belong under and what they say, when they are an
/// authored object: canonical, its AK and AttA deriving the device id it
/// names, and its signature that AK's over the body. Why not, otherwise.
pub fn check(bytes: &[u8]) -> Result<(D32, Authored), AuthoredError> {
    let object = AuthoredObjectV1::decode(bytes).map_err(|e| AuthoredError::DoesNotDecode {
        what: "the object",
        why: e.to_string(),
    })?;
    if object.encode_to_vec() != bytes {
        return Err(AuthoredError::NotCanonical { what: "the object" });
    }
    let body = AuthoredObjectBodyV1::decode(object.body.as_slice()).map_err(|e| {
        AuthoredError::DoesNotDecode {
            what: "the body",
            why: e.to_string(),
        }
    })?;
    if body.encode_to_vec() != object.body {
        return Err(AuthoredError::NotCanonical { what: "the body" });
    }
    if body.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthoredError::PayloadPastBound {
            len: body.payload.len(),
        });
    }
    let author_genesis = d32(&body.author_genesis, "the author's genesis")?;
    let author_device_id = d32(&body.author_device_id, "the author's device id")?;
    let att_a = d32(&body.author_att_a, "the author's AttA")?;
    let topic = d32(&body.topic, "the topic")?;
    if derive_devid(&body.author_ak, &att_a) != author_device_id {
        return Err(AuthoredError::DeviceIdNotDerived);
    }
    match sphincs_verify(&body.author_ak, &statement(&object.body), &object.signature) {
        Ok(verified) if verified => {}
        Ok(..) => return Err(AuthoredError::SignatureDoesNotVerify),
        Err(e) => {
            return Err(AuthoredError::SignatureUncheckable { why: e.to_string() });
        }
    }
    Ok((
        locator(&author_device_id, &topic),
        Authored {
            address: immutable_addr(TAG_DSM_AUTHORED_OBJECT, bytes),
            author_genesis,
            author_device_id,
            topic,
            payload: body.payload,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsVariant};

    /// The bytes the SDK derived before these rules moved here (owner,
    /// 2026-10-28), pinned on fixed inputs: what an author signs, the locator
    /// a reader asks under and an object's address.
    #[test]
    fn the_statement_locator_and_address_keep_the_bytes_they_had_in_the_sdk() {
        let b32 = crate::utils::text_id::encode_base32_crockford;
        assert_eq!(
            b32(&statement(b"authored body")),
            "V4TPHEPAYSR4YNJGHGEBYHWWN1AVMPT7H53GEX2Y3QJD7FDBSGJG"
        );
        assert_eq!(
            b32(&locator(&[4; 32], &[5; 32])),
            "QD43T4WWKM8TERT7ZC5EXBPFH6FC6NFQ4S4V7JQ19A4DBAG65S0G"
        );
        assert_eq!(
            b32(&immutable_addr(TAG_DSM_AUTHORED_OBJECT, b"object bytes")),
            "91WDFQRHFXH6M06W9ZY7E65QBQDXG3P1R94GVD6B5T9KC95E6040"
        );
    }

    /// An object authored by a fresh key, with the device id its AK and AttA
    /// derive, unless `device_id` names another.
    fn object(device_id: Option<D32>, payload: &[u8]) -> Result<(Vec<u8>, D32), String> {
        let kp = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        let att_a = [9u8; 32];
        let derived = derive_devid(&kp.public_key, &att_a);
        let body = AuthoredObjectBodyV1 {
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
            AuthoredObjectV1 { body, signature }.encode_to_vec(),
            derived,
        ))
    }

    #[test]
    fn an_object_is_recognized_under_its_authors_locator_for_its_topic() -> Result<(), String> {
        let (bytes, author) = object(None, b"state 1")?;
        let (at, read) = check(&bytes).map_err(|e| e.to_string())?;
        assert_eq!(at, locator(&author, &[5; 32]));
        assert_eq!(read.author_device_id, author);
        assert_eq!(read.payload, b"state 1".to_vec());
        assert_eq!(
            read.address,
            immutable_addr(TAG_DSM_AUTHORED_OBJECT, &bytes)
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
        assert_eq!(
            check(&claimed),
            Err(AuthoredError::DeviceIdNotDerived),
            "a device the AK does not derive"
        );

        let (bytes, _) = object(None, b"state 1")?;
        let mut object = AuthoredObjectV1::decode(bytes.as_slice()).map_err(|e| e.to_string())?;
        let mut body =
            AuthoredObjectBodyV1::decode(object.body.as_slice()).map_err(|e| e.to_string())?;
        body.payload = b"state 2".to_vec();
        object.body = body.encode_to_vec();
        assert_eq!(
            check(&object.encode_to_vec()),
            Err(AuthoredError::SignatureDoesNotVerify),
            "a payload the signature does not cover"
        );

        let mut longer = bytes.clone();
        longer.extend([0x08, 0x01]);
        check(&longer).expect_err("bytes past the object");
        Ok(())
    }

    /// An object or a body not in its canonical encoding is nothing, although
    /// its author's signature verifies over the very bytes it carries: a field
    /// written twice decodes to the same object, and is refused.
    #[test]
    fn an_object_or_a_body_not_in_its_canonical_encoding_is_nothing() -> Result<(), String> {
        let kp = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        let att_a = [9u8; 32];
        let body = AuthoredObjectBodyV1 {
            author_genesis: vec![1; 32],
            author_device_id: derive_devid(&kp.public_key, &att_a).to_vec(),
            author_ak: kp.public_key.clone(),
            author_att_a: att_a.to_vec(),
            topic: vec![5; 32],
            payload: b"state 1".to_vec(),
        };
        let signed = |body: &[u8]| -> Result<Vec<u8>, String> {
            let signature =
                sphincs_sign(&kp.secret_key, &statement(body)).map_err(|e| e.to_string())?;
            Ok(AuthoredObjectV1 {
                body: body.to_vec(),
                signature,
            }
            .encode_to_vec())
        };

        let canonical_body = body.encode_to_vec();
        let honest = signed(&canonical_body)?;
        check(&honest).map_err(|e| e.to_string())?;

        let mut doubled_body = canonical_body.clone();
        doubled_body.extend(
            AuthoredObjectBodyV1 {
                topic: body.topic.clone(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        assert_eq!(
            check(&signed(&doubled_body)?),
            Err(AuthoredError::NotCanonical { what: "the body" }),
            "a body with its topic written twice, signed as it is"
        );

        let object = AuthoredObjectV1::decode(honest.as_slice()).map_err(|e| e.to_string())?;
        let mut doubled_object = honest.clone();
        doubled_object.extend(
            AuthoredObjectV1 {
                body: Vec::new(),
                signature: object.signature,
            }
            .encode_to_vec(),
        );
        assert_eq!(
            check(&doubled_object),
            Err(AuthoredError::NotCanonical { what: "the object" }),
            "an object with its signature written twice"
        );
        Ok(())
    }
}
