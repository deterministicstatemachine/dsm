// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed objects of DSM Connect (DSM Amendment A11) and the identities
//! they name.
//!
//! Each object carries its body bytes and a SPHINCS+ signature by its
//! author's AK over `H(<tag> ‖ body)`: `DSM/connect/offer` (the application),
//! `DSM/connect/accept` (the wallet), `DSM/connect/request` (the application)
//! and `DSM/connect/response` (the wallet). A body is accepted only in its
//! canonical encoding, so the bytes a signature covers are the only bytes
//! that mean what it says.

use dsm::common::domain_tags::{
    TAG_DSM_CONNECT_ACCEPT, TAG_DSM_CONNECT_OFFER, TAG_DSM_CONNECT_OFFER_DIGEST,
    TAG_DSM_CONNECT_REQUEST, TAG_DSM_CONNECT_RESPONSE, TAG_DSM_CONNECT_SESSION,
    TAG_DSM_TLS_CERT_HASH,
};
use dsm::crypto::blake3::{domain_hash, dsm_domain_hasher};
use dsm::crypto::domain::TaggedHashDomain;
use dsm::types::proto as generated;
use prost::Message;

use super::d32;

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

/// The 32 bytes a signature over `body` signs.
fn signing_digest(kind: Signed, body: &[u8]) -> [u8; 32] {
    *domain_hash(kind.tag(), body).as_bytes()
}

/// Sign `body` as `kind` under this device's AK.
pub fn sign_own(kind: Signed, body: &[u8]) -> Result<Vec<u8>, String> {
    let (_, sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| format!("this device's signing key: {e}"))?;
    dsm::crypto::sphincs::sphincs_sign(&sk, &signing_digest(kind, body))
        .map_err(|e| format!("signing the {kind:?}: {e}"))
}

/// Whether `signature` is `ak`'s signature over `body` as `kind`. Anything
/// but a verifying signature is a refusal.
pub fn verify(kind: Signed, body: &[u8], ak: &[u8], signature: &[u8]) -> Result<(), String> {
    match dsm::crypto::sphincs::sphincs_verify(ak, &signing_digest(kind, body), signature) {
        Ok(verified) if verified => Ok(()),
        Ok(..) => Err(format!(
            "the {kind:?} signature does not verify under its signer's key"
        )),
        Err(e) => Err(format!("the {kind:?} signature cannot be checked: {e}")),
    }
}

/// `body` decoded, refused unless it is the canonical encoding of what it
/// decodes to.
pub fn canonical<M: Message + Default>(body: &[u8], what: &str) -> Result<M, String> {
    let decoded = M::decode(body).map_err(|e| format!("{what}: {e}"))?;
    if decoded.encode_to_vec() != body {
        return Err(format!("{what} is not in its canonical encoding"));
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

/// The identity `card` names, accepted only when its AK with `att_a` derives
/// its device id (`DevID = H(DSM/devid ‖ AK ‖ AttA)`), so a signature under
/// that AK is the named device's, and only when it is on `network`.
pub fn card_identity(
    card: &generated::ContactQrV3,
    att_a: &[u8],
    network: &str,
) -> Result<CardIdentity, String> {
    let device_id = d32(&card.device_id, "the card's device id")?;
    let genesis = d32(&card.genesis_hash, "the card's genesis")?;
    let att_a = d32(att_a, "the AttA")?;
    if card.signing_public_key.len() != 64 {
        return Err(format!(
            "the card's AK is {} bytes, not 64",
            card.signing_public_key.len()
        ));
    }
    if card.network != network {
        return Err(format!(
            "the card is on network {:?}; this device is on {network:?}",
            card.network
        ));
    }
    if dsm::core::identity::genesis_v2::derive_devid(&card.signing_public_key, &att_a) != device_id
    {
        return Err("the card's AK and AttA do not derive its device id".into());
    }
    Ok(CardIdentity {
        device_id,
        genesis,
        ak: card.signing_public_key.clone(),
    })
}

/// This device's own card and AttA, as an offer or an accept carries them.
pub fn own_card() -> Result<(generated::ContactQrV3, [u8; 32]), String> {
    let card = crate::handlers::identity_routes::contact_card()
        .map_err(|e| format!("this device's contact card: {e}"))?;
    let att_a = crate::sdk::signing_authority::current_att_a()
        .map_err(|e| format!("this device's AttA: {e}"))?;
    Ok((card, att_a))
}

/// The network this device's genesis committed, as a card names it.
pub fn own_network() -> Result<String, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("this device's committed network: {e}"))?;
    String::from_utf8(network).map_err(|e| format!("the committed network id: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_signed_object_signs_under_its_own_domain() {
        let body = b"one body";
        let digests = [
            signing_digest(Signed::Offer, body),
            signing_digest(Signed::Accept, body),
            signing_digest(Signed::Request, body),
            signing_digest(Signed::Response, body),
        ];
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b, "two connect objects share a signing domain");
            }
        }
    }

    #[test]
    fn a_signature_verifies_only_as_its_own_kind_and_body() -> Result<(), String> {
        let kp =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .map_err(|e| e.to_string())?;
        let body = b"pay 3";
        let sig = dsm::crypto::sphincs::sphincs_sign(
            &kp.secret_key,
            &signing_digest(Signed::Request, body),
        )
        .map_err(|e| e.to_string())?;
        verify(Signed::Request, body, &kp.public_key, &sig)?;
        verify(Signed::Response, body, &kp.public_key, &sig).expect_err("must be refused");
        verify(Signed::Request, b"pay 4", &kp.public_key, &sig).expect_err("must be refused");
        let other =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .map_err(|e| e.to_string())?;
        verify(Signed::Request, body, &other.public_key, &sig).expect_err("must be refused");
        Ok(())
    }

    #[test]
    fn a_card_names_its_device_only_through_its_own_key() -> Result<(), String> {
        let kp =
            dsm::crypto::sphincs::generate_keypair(dsm::crypto::sphincs::SphincsVariant::SPX256f)
                .map_err(|e| e.to_string())?;
        let att_a = [4u8; 32];
        let device_id = dsm::core::identity::genesis_v2::derive_devid(&kp.public_key, &att_a);
        let card = generated::ContactQrV3 {
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
        card_identity(&card, &[5u8; 32], "dsm-testnet").expect_err("another AttA");
        card_identity(&card, &att_a, "another-net").expect_err("another network");
        let mut swapped = card.clone();
        swapped.device_id = vec![8; 32];
        card_identity(&swapped, &att_a, "dsm-testnet").expect_err("another device id");
        Ok(())
    }
}
