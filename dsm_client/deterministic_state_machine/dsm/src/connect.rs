// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed objects of DSM Connect (DSM Amendment A11), the digests their
//! two parties name each other by, and the identity a contact card names.
//!
//! The application and the wallet each check what the other signed, so each
//! rule here is one both compute identically, and it exists once. Each
//! object carries its body bytes and a SPHINCS+ signature by its author's AK
//! over its statement `H(<tag> ‖ body)`: `DSM/connect/offer` (the
//! application), `DSM/connect/accept` (the wallet), `DSM/connect/request`
//! (the application) and `DSM/connect/response` (the wallet). A body is
//! accepted only in its canonical encoding, so the bytes a signature covers
//! are the only bytes that mean what it says. Signing with a device's own
//! key is the device's: it signs [`statement`].

use prost::Message;

use crate::common::domain_tags::{
    TAG_DSM_CONNECT_ACCEPT, TAG_DSM_CONNECT_OFFER, TAG_DSM_CONNECT_OFFER_DIGEST,
    TAG_DSM_CONNECT_REQUEST, TAG_DSM_CONNECT_RESPONSE, TAG_DSM_CONNECT_SESSION,
    TAG_DSM_TLS_CERT_HASH,
};
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};
use crate::crypto::domain::TaggedHashDomain;
use crate::crypto::sphincs::sphincs_verify;
use crate::types::proto::ContactQrV3;

/// Which signed object a body is, and so the domain its signature is under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signed {
    Offer,
    Accept,
    Request,
    Response,
}

impl Signed {
    fn tag(self) -> TaggedHashDomain<'static> {
        match self {
            Signed::Offer => TAG_DSM_CONNECT_OFFER,
            Signed::Accept => TAG_DSM_CONNECT_ACCEPT,
            Signed::Request => TAG_DSM_CONNECT_REQUEST,
            Signed::Response => TAG_DSM_CONNECT_RESPONSE,
        }
    }
}

/// Why a connect object, or the card it names its author by, is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// A body does not decode.
    DoesNotDecode { what: &'static str, why: String },
    /// A body decodes, but is not the canonical encoding of what it decodes to.
    NotCanonical { what: &'static str },
    /// The signature is not its signer's over this body as this kind.
    SignatureDoesNotVerify { kind: Signed },
    /// The signature could not be checked at all.
    SignatureUncheckable { kind: Signed, why: String },
    /// A field naming a 32-byte value is another length.
    NotThirtyTwoBytes {
        what: &'static str,
        got: usize,
        why: String,
    },
    /// The card's AK is not a SPHINCS+ public key's length.
    AkNotSixtyFourBytes { got: usize },
    /// The card is on another network than the reader's.
    AnotherNetwork { card: String, reader: String },
    /// The card's AK and AttA do not derive the device id it names.
    DeviceIdNotDerived,
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnectError::DoesNotDecode { what, why } => write!(f, "{what}: {why}"),
            ConnectError::NotCanonical { what } => {
                write!(f, "{what} is not in its canonical encoding")
            }
            ConnectError::SignatureDoesNotVerify { kind } => write!(
                f,
                "the {kind:?} signature does not verify under its signer's key"
            ),
            ConnectError::SignatureUncheckable { kind, why } => {
                write!(f, "the {kind:?} signature cannot be checked: {why}")
            }
            ConnectError::NotThirtyTwoBytes { what, got, why } => {
                write!(f, "{what} is {got} bytes, not 32: {why}")
            }
            ConnectError::AkNotSixtyFourBytes { got } => {
                write!(f, "the card's AK is {got} bytes, not 64")
            }
            ConnectError::AnotherNetwork { card, reader } => write!(
                f,
                "the card is on network {card:?}; this device is on {reader:?}"
            ),
            ConnectError::DeviceIdNotDerived => {
                write!(f, "the card's AK and AttA do not derive its device id")
            }
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<ConnectError> for String {
    fn from(e: ConnectError) -> String {
        e.to_string()
    }
}

/// The 32 bytes an author's signature over `body` as `kind` signs.
pub fn statement(kind: Signed, body: &[u8]) -> [u8; 32] {
    *domain_hash(kind.tag(), body).as_bytes()
}

/// Accepted only when `signature` is `ak`'s signature over `body` as
/// `kind`. Anything but a verifying signature is a refusal.
pub fn verify(kind: Signed, body: &[u8], ak: &[u8], signature: &[u8]) -> Result<(), ConnectError> {
    match sphincs_verify(ak, &statement(kind, body), signature) {
        Ok(verified) if verified => Ok(()),
        Ok(..) => Err(ConnectError::SignatureDoesNotVerify { kind }),
        Err(e) => Err(ConnectError::SignatureUncheckable {
            kind,
            why: e.to_string(),
        }),
    }
}

/// `body` decoded, refused unless it is the canonical encoding of what it
/// decodes to.
pub fn canonical<M: Message + Default>(body: &[u8], what: &'static str) -> Result<M, ConnectError> {
    let decoded = M::decode(body).map_err(|e| ConnectError::DoesNotDecode {
        what,
        why: e.to_string(),
    })?;
    if decoded.encode_to_vec() != body {
        return Err(ConnectError::NotCanonical { what });
    }
    Ok(decoded)
}

/// The digest a connect code names an offer by.
pub fn offer_digest(offer_body: &[u8]) -> [u8; 32] {
    *domain_hash(TAG_DSM_CONNECT_OFFER_DIGEST, offer_body).as_bytes()
}

/// A session's id: the offer it answered and the wallet that answered it.
pub fn session_id(offer_digest: &[u8; 32], wallet_device_id: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_CONNECT_SESSION);
    h.update(offer_digest);
    h.update(wallet_device_id);
    *h.finalize().as_bytes()
}

/// The pin of a TLS leaf certificate: the TLS certificate hash of its DER.
pub fn cert_pin(leaf_der: &[u8]) -> [u8; 32] {
    *domain_hash(TAG_DSM_TLS_CERT_HASH, leaf_der).as_bytes()
}

/// The identity a contact card names, checked from the card's own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardIdentity {
    pub device_id: [u8; 32],
    pub genesis: [u8; 32],
    pub ak: Vec<u8>,
}

fn d32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], ConnectError> {
    <[u8; 32]>::try_from(bytes).map_err(|e| ConnectError::NotThirtyTwoBytes {
        what,
        got: bytes.len(),
        why: e.to_string(),
    })
}

/// The identity `card` names, accepted only when its AK with `att_a` derives
/// its device id (`DevID = H(DSM/devid ‖ AK ‖ AttA)`), so a signature under
/// that AK is the named device's, and only when it is on `network`.
pub fn card_identity(
    card: &ContactQrV3,
    att_a: &[u8],
    network: &str,
) -> Result<CardIdentity, ConnectError> {
    let device_id = d32(&card.device_id, "the card's device id")?;
    let genesis = d32(&card.genesis_hash, "the card's genesis")?;
    let att_a = d32(att_a, "the AttA")?;
    if card.signing_public_key.len() != 64 {
        return Err(ConnectError::AkNotSixtyFourBytes {
            got: card.signing_public_key.len(),
        });
    }
    if card.network != network {
        return Err(ConnectError::AnotherNetwork {
            card: card.network.clone(),
            reader: network.to_string(),
        });
    }
    if derive_devid(&card.signing_public_key, &att_a) != device_id {
        return Err(ConnectError::DeviceIdNotDerived);
    }
    Ok(CardIdentity {
        device_id,
        genesis,
        ak: card.signing_public_key.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsVariant};

    /// The bytes the SDK derived before these rules moved here (owner,
    /// 2026-10-28), pinned on fixed inputs: what each kind's signature signs,
    /// the offer digest a code names, a session's id and a certificate pin.
    #[test]
    fn the_statements_and_digests_keep_the_bytes_they_had_in_the_sdk() {
        let b32 = crate::utils::text_id::encode_base32_crockford;
        for (kind, pinned) in [
            (
                Signed::Offer,
                "24S3Y7WDNF8NX7CGZX4EDETFF7RX1EZQCDZGHD1G35CGPMNQAFWG",
            ),
            (
                Signed::Accept,
                "MH0PQF48CPK2ERX5551TXQNDR5169S0BRW6QG7GMMSMAM9NEP4G0",
            ),
            (
                Signed::Request,
                "W4MRH86K45Q4J20VE0P3QEFWAQXKBT954N63PWVY6WE64G0VXCS0",
            ),
            (
                Signed::Response,
                "PEV88KGFY8TSHQ8HJNPF9VK151Q9NGTMWEHEP8WD7PQ4P7PECV20",
            ),
        ] {
            assert_eq!(b32(&statement(kind, b"one body")), pinned, "{kind:?}");
        }
        assert_eq!(
            b32(&offer_digest(b"offer body")),
            "QYRF8277AR21BERDGMDPS3MF2V6K98RQBMKT9HA4YY4Z3P74KG30"
        );
        assert_eq!(
            b32(&session_id(&[0x01; 32], &[0x02; 32])),
            "CTKJCP7YNA7D7V25G2CTQFMH09BR8PTR8ZCZYCFT7EDV11SBATCG"
        );
        assert_eq!(
            b32(&cert_pin(b"leaf der")),
            "J7TC72FYKKKDYFNEG008MEBYYBG5Q3VAB34RT0FF2YQ01HAR6340"
        );
    }

    #[test]
    fn each_signed_object_signs_under_its_own_domain() {
        let body = b"one body";
        let digests = [
            statement(Signed::Offer, body),
            statement(Signed::Accept, body),
            statement(Signed::Request, body),
            statement(Signed::Response, body),
        ];
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b, "two connect objects share a signing domain");
            }
        }
    }

    #[test]
    fn a_signature_verifies_only_as_its_own_kind_and_body() -> Result<(), String> {
        let kp = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        let body = b"pay 3";
        let sig = sphincs_sign(&kp.secret_key, &statement(Signed::Request, body))
            .map_err(|e| e.to_string())?;
        verify(Signed::Request, body, &kp.public_key, &sig)?;
        verify(Signed::Response, body, &kp.public_key, &sig).expect_err("must be refused");
        verify(Signed::Request, b"pay 4", &kp.public_key, &sig).expect_err("must be refused");
        let other = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        verify(Signed::Request, body, &other.public_key, &sig).expect_err("must be refused");
        Ok(())
    }

    /// A body is taken only in its canonical encoding: the same message with
    /// bytes past it, or a field written twice, is refused although it
    /// decodes.
    #[test]
    fn a_body_is_taken_only_in_its_canonical_encoding() -> Result<(), String> {
        let card = ContactQrV3 {
            device_id: vec![1; 32],
            network: "dsm-testnet".into(),
            ..Default::default()
        };
        let bytes = card.encode_to_vec();
        assert_eq!(canonical::<ContactQrV3>(&bytes, "the card")?, card);

        let mut repeated = bytes.clone();
        repeated.extend_from_slice(&bytes);
        assert_eq!(
            canonical::<ContactQrV3>(&repeated, "the card"),
            Err(ConnectError::NotCanonical { what: "the card" }),
            "a field written twice decodes, and is not canonical"
        );
        canonical::<ContactQrV3>(&[0xFF], "the card").expect_err("bytes that do not decode");
        Ok(())
    }

    #[test]
    fn a_card_names_its_device_only_through_its_own_key() -> Result<(), String> {
        let kp = generate_keypair(SphincsVariant::SPX256f).map_err(|e| e.to_string())?;
        let att_a = [4u8; 32];
        let device_id = derive_devid(&kp.public_key, &att_a);
        let card = ContactQrV3 {
            device_id: device_id.to_vec(),
            network: "dsm-testnet".into(),
            genesis_hash: vec![6; 32],
            signing_public_key: kp.public_key.clone(),
            ..Default::default()
        };
        assert_eq!(
            card_identity(&card, &att_a, "dsm-testnet")?.device_id,
            device_id
        );
        assert_eq!(
            card_identity(&card, &[5u8; 32], "dsm-testnet"),
            Err(ConnectError::DeviceIdNotDerived),
            "another AttA"
        );
        card_identity(&card, &att_a, "another-net").expect_err("another network");
        let mut swapped = card.clone();
        swapped.device_id = vec![8; 32];
        assert_eq!(
            card_identity(&swapped, &att_a, "dsm-testnet"),
            Err(ConnectError::DeviceIdNotDerived),
            "another device id"
        );
        Ok(())
    }
}
