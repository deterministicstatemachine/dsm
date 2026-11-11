// SPDX-License-Identifier: MIT OR Apache-2.0

//! A recipient's authorization of one sender's write key for one relationship
//! (DSM Amendment A34).
//!
//! Once a relationship is established, each device offers the other a write
//! key of its own, for that relationship instance and that direction, and each
//! device grants the other's key its inbox for that instance. A grant is the
//! recipient's signature, under its AK, over exactly what it authorizes: one
//! relationship instance, one recipient, one sender, one write key, the
//! recipient's inbox for that relationship. It authorizes no step, moves no
//! value, names no other relationship or namespace, and delegates nothing. No
//! storage node takes part: the two devices make it, and anyone holding the
//! recipient's AK can check it.
//!
//! An offer carries two signatures over one body. The sender's AK binds the
//! key to the instance and the two devices; the key itself proves its holder
//! has the secret. An offered key that is the sender's AK is refused: a write
//! key never reuses the root signing secret.
//!
//! Every field has a fixed length, so the concatenation each signature covers
//! is canonical without a length prefix. The wire forms are strict protobuf:
//! known tags only, each once, each its exact length, re-encoding to the same
//! bytes.

use crate::common::domain_tags::{
    TAG_DSM_RELATIONSHIP_INSTANCE, TAG_DSM_RELATIONSHIP_WRITE_GRANT,
    TAG_DSM_RELATIONSHIP_WRITE_GRANT_ID, TAG_DSM_RELATIONSHIP_WRITE_KEY,
    TAG_DSM_RELATIONSHIP_WRITE_KEY_BINDING, TAG_DSM_RELATIONSHIP_WRITE_KEY_POSSESSION,
};
use crate::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher, dsm_domain_hasher_keyed};
use crate::crypto::sphincs::{
    generate_keypair_from_seed, public_key_bytes, sphincs_verify, SphincsKeyPair, SphincsVariant,
};
use crate::types::error::DsmError;
use crate::types::proto::{RelationshipWriteGrantV1, RelationshipWriteKeyOfferV1};
use crate::types::receipt_types::{validate_length_delimited_wire, FieldLimit};

/// The one version of an offer and a grant.
pub const WRITE_AUTHORIZATION_VERSION: u32 = 1;
/// The one scope a grant names: the recipient's inbox for the relationship
/// instance, at every address that relationship's tips route to.
pub const SCOPE_RELATIONSHIP_INBOX: u32 = 1;
/// A write key is a SPHINCS+ SPX256f key, the scheme every DSM device key uses.
pub const WRITE_KEY_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
/// Its public key's length, `PK.seed ‖ PK.root`.
pub const WRITE_PUBLIC_KEY_LEN: usize = 64;
/// The longest signature either object carries (SPX256f is 49,856 bytes).
const SIGNATURE_MAX_LEN: usize = 65_535;

/// The relationship instance an establishment opened: the relationship key
/// and the tip its ESTABLISH step reached. Both devices compute it from what
/// both of them signed, and no two establishments share it: the tip hashes
/// the step's own entropy and receipt.
pub fn relationship_instance_id(
    relationship_key: &[u8; 32],
    established_tip: &[u8; 32],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_RELATIONSHIP_INSTANCE);
    h.update(relationship_key);
    h.update(established_tip);
    *h.finalize().as_bytes()
}

/// The write key `sender` writes to `recipient` with on `instance`: SPHINCS+
/// key generation from `keyed-BLAKE3(Smaster, "DSM/relationship-write-key/v1"
/// ‖ instance ‖ sender ‖ recipient)`. It comes back from the master seed
/// alone, so nothing secret is stored, and it is one key per instance and per
/// direction. The AK is derived under other contexts, so the write key never
/// is the root signing key.
pub fn derive_write_keypair(
    s_master: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    sender_device_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    let mut h = dsm_domain_hasher_keyed(TAG_DSM_RELATIONSHIP_WRITE_KEY, s_master);
    h.update(relationship_instance_id);
    h.update(sender_device_id);
    h.update(recipient_device_id);
    let seed = zeroize::Zeroizing::new(*h.finalize().as_bytes());
    generate_keypair_from_seed(WRITE_KEY_VARIANT, &seed)
}

/// Why an offer or a grant is not what it must be. Each refusal names one
/// check; none is ever read as another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteAuthorizationRefusal {
    /// The bytes are not the strict wire form.
    Wire(String),
    /// A version other than [`WRITE_AUTHORIZATION_VERSION`].
    Version(u32),
    /// A scope other than [`SCOPE_RELATIONSHIP_INBOX`].
    Scope(u32),
    /// It names another relationship instance.
    WrongInstance,
    /// It names another sender.
    WrongSender,
    /// It names another recipient device.
    WrongRecipient,
    /// It names another recipient genesis.
    WrongRecipientGenesis,
    /// It names another write key than the one expected.
    WrongWriteKey,
    /// The offered write key is the sender's AK.
    WriteKeyIsTheSendersAk,
    /// The grant's identifier is not the hash of its fields.
    GrantIdMismatch,
    /// The sender's AK did not sign the offer.
    BindingSignature,
    /// The write key did not sign the offer.
    PossessionSignature,
    /// The recipient's AK did not sign the grant.
    GrantSignature,
    /// A signature could not be checked at all.
    Crypto(String),
}

impl std::fmt::Display for WriteAuthorizationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(why) => write!(f, "not a strict write-authorization wire: {why}"),
            Self::Version(v) => write!(f, "version {v} is not {WRITE_AUTHORIZATION_VERSION}"),
            Self::Scope(s) => write!(f, "scope {s} is not the relationship inbox"),
            Self::WrongInstance => f.write_str("it names another relationship instance"),
            Self::WrongSender => f.write_str("it names another sender"),
            Self::WrongRecipient => f.write_str("it names another recipient"),
            Self::WrongRecipientGenesis => f.write_str("it names another recipient genesis"),
            Self::WrongWriteKey => f.write_str("it names another write key"),
            Self::WriteKeyIsTheSendersAk => f.write_str("the write key is the sender's AK"),
            Self::GrantIdMismatch => f.write_str("the grant id is not the hash of its fields"),
            Self::BindingSignature => f.write_str("the sender's AK did not sign the offer"),
            Self::PossessionSignature => f.write_str("the write key did not sign the offer"),
            Self::GrantSignature => f.write_str("the recipient's AK did not sign the grant"),
            Self::Crypto(why) => write!(f, "a signature could not be checked: {why}"),
        }
    }
}

impl std::error::Error for WriteAuthorizationRefusal {}

impl From<WriteAuthorizationRefusal> for DsmError {
    fn from(refusal: WriteAuthorizationRefusal) -> Self {
        DsmError::invalid_operation(format!("write authorization refused: {refusal}"))
    }
}

fn arr32(bytes: &[u8]) -> Result<[u8; 32], WriteAuthorizationRefusal> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|e| WriteAuthorizationRefusal::Wire(format!("{} bytes, not 32: {e}", bytes.len())))
}

fn be_u32(bytes: &[u8]) -> Result<u32, WriteAuthorizationRefusal> {
    <[u8; 4]>::try_from(bytes)
        .map(u32::from_be_bytes)
        .map_err(|e| WriteAuthorizationRefusal::Wire(format!("{} bytes, not 4: {e}", bytes.len())))
}

fn verified(
    pk: &[u8],
    target: &[u8; 32],
    sig: &[u8],
    refusal: WriteAuthorizationRefusal,
) -> Result<(), WriteAuthorizationRefusal> {
    let valid = sphincs_verify(pk, target, sig)
        .map_err(|e| WriteAuthorizationRefusal::Crypto(e.to_string()))?;
    if valid {
        Ok(())
    } else {
        Err(refusal)
    }
}

/// A sender's offer of its write key for one relationship instance and one
/// recipient, before its signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteKeyOffer {
    pub relationship_instance_id: [u8; 32],
    pub sender_device_id: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub write_public_key: Vec<u8>,
}

impl WriteKeyOffer {
    /// `version ‖ instance ‖ sender ‖ recipient ‖ write key`: what both of the
    /// offer's signatures cover.
    pub fn body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + 3 * 32 + WRITE_PUBLIC_KEY_LEN);
        body.extend_from_slice(&WRITE_AUTHORIZATION_VERSION.to_be_bytes());
        body.extend_from_slice(&self.relationship_instance_id);
        body.extend_from_slice(&self.sender_device_id);
        body.extend_from_slice(&self.recipient_device_id);
        body.extend_from_slice(&self.write_public_key);
        body
    }

    /// What the sender's AK signs: the key is its, for this instance and this
    /// recipient.
    pub fn binding_target(&self) -> [u8; 32] {
        domain_hash_bytes(TAG_DSM_RELATIONSHIP_WRITE_KEY_BINDING, &self.body())
    }

    /// What the write key signs: its holder has the secret.
    pub fn possession_target(&self) -> [u8; 32] {
        domain_hash_bytes(TAG_DSM_RELATIONSHIP_WRITE_KEY_POSSESSION, &self.body())
    }

    /// The wire form with both signatures.
    pub fn to_wire(
        &self,
        possession_signature: Vec<u8>,
        binding_signature: Vec<u8>,
    ) -> RelationshipWriteKeyOfferV1 {
        RelationshipWriteKeyOfferV1 {
            version: WRITE_AUTHORIZATION_VERSION.to_be_bytes().to_vec(),
            relationship_instance_id: self.relationship_instance_id.to_vec(),
            sender_device_id: self.sender_device_id.to_vec(),
            recipient_device_id: self.recipient_device_id.to_vec(),
            write_public_key: self.write_public_key.clone(),
            possession_signature,
            binding_signature,
        }
    }
}

/// What a recipient holds an offer to: the relationship instance it
/// established, the device it established it with, itself, and that device's
/// AK as its contact record holds it.
#[derive(Debug, Clone, Copy)]
pub struct OfferExpectation<'a> {
    pub relationship_instance_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    pub sender_ak: &'a [u8],
}

/// The recipient's check of an offer: it names this instance, this sender and
/// this recipient; its key is a write key and not the sender's AK; the
/// sender's AK bound it and the key proved possession.
pub fn verify_write_key_offer(
    wire: &RelationshipWriteKeyOfferV1,
    expected: &OfferExpectation<'_>,
) -> Result<WriteKeyOffer, WriteAuthorizationRefusal> {
    let version = be_u32(&wire.version)?;
    if version != WRITE_AUTHORIZATION_VERSION {
        return Err(WriteAuthorizationRefusal::Version(version));
    }
    let offer = WriteKeyOffer {
        relationship_instance_id: arr32(&wire.relationship_instance_id)?,
        sender_device_id: arr32(&wire.sender_device_id)?,
        recipient_device_id: arr32(&wire.recipient_device_id)?,
        write_public_key: wire.write_public_key.clone(),
    };
    if offer.write_public_key.len() != public_key_bytes(WRITE_KEY_VARIANT) {
        return Err(WriteAuthorizationRefusal::Wire(format!(
            "write key is {} bytes, not {}",
            offer.write_public_key.len(),
            public_key_bytes(WRITE_KEY_VARIANT)
        )));
    }
    if &offer.relationship_instance_id != expected.relationship_instance_id {
        return Err(WriteAuthorizationRefusal::WrongInstance);
    }
    if &offer.sender_device_id != expected.sender_device_id {
        return Err(WriteAuthorizationRefusal::WrongSender);
    }
    if &offer.recipient_device_id != expected.recipient_device_id {
        return Err(WriteAuthorizationRefusal::WrongRecipient);
    }
    if offer.write_public_key.as_slice() == expected.sender_ak {
        return Err(WriteAuthorizationRefusal::WriteKeyIsTheSendersAk);
    }
    verified(
        expected.sender_ak,
        &offer.binding_target(),
        &wire.binding_signature,
        WriteAuthorizationRefusal::BindingSignature,
    )?;
    verified(
        &offer.write_public_key,
        &offer.possession_target(),
        &wire.possession_signature,
        WriteAuthorizationRefusal::PossessionSignature,
    )?;
    Ok(offer)
}

/// A recipient's grant of its inbox for one relationship instance to one
/// sender's write key, before its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteGrant {
    pub relationship_instance_id: [u8; 32],
    pub recipient_genesis: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub authorized_sender_device_id: [u8; 32],
    pub authorized_write_public_key: Vec<u8>,
    pub permitted_scope: u32,
}

impl WriteGrant {
    /// The grant a recipient issues for an offer it verified, from its own
    /// genesis.
    pub fn for_offer(offer: &WriteKeyOffer, recipient_genesis: [u8; 32]) -> Self {
        WriteGrant {
            relationship_instance_id: offer.relationship_instance_id,
            recipient_genesis,
            recipient_device_id: offer.recipient_device_id,
            authorized_sender_device_id: offer.sender_device_id,
            authorized_write_public_key: offer.write_public_key.clone(),
            permitted_scope: SCOPE_RELATIONSHIP_INBOX,
        }
    }

    /// `version ‖ instance ‖ recipient genesis ‖ recipient ‖ sender ‖ key ‖
    /// scope`: the fields before the identifier, in tag order.
    fn fields_before_id(&self) -> Vec<u8> {
        let mut fields = Vec::with_capacity(4 + 4 * 32 + WRITE_PUBLIC_KEY_LEN + 4);
        fields.extend_from_slice(&WRITE_AUTHORIZATION_VERSION.to_be_bytes());
        fields.extend_from_slice(&self.relationship_instance_id);
        fields.extend_from_slice(&self.recipient_genesis);
        fields.extend_from_slice(&self.recipient_device_id);
        fields.extend_from_slice(&self.authorized_sender_device_id);
        fields.extend_from_slice(&self.authorized_write_public_key);
        fields.extend_from_slice(&self.permitted_scope.to_be_bytes());
        fields
    }

    /// The grant's identifier: the same grant always has the same one, so
    /// issuing it again issues nothing new.
    pub fn grant_id(&self) -> [u8; 32] {
        domain_hash_bytes(
            TAG_DSM_RELATIONSHIP_WRITE_GRANT_ID,
            &self.fields_before_id(),
        )
    }

    /// What the recipient's AK signs: `BLAKE3("DSM/relationship-write-grant/v1"
    /// ‖ canonical(WriteGrant))`, every field including the identifier.
    pub fn signing_target(&self) -> [u8; 32] {
        let mut canonical = self.fields_before_id();
        canonical.extend_from_slice(&self.grant_id());
        domain_hash_bytes(TAG_DSM_RELATIONSHIP_WRITE_GRANT, &canonical)
    }

    /// The wire form with the recipient's signature.
    pub fn to_wire(&self, grant_signature: Vec<u8>) -> RelationshipWriteGrantV1 {
        RelationshipWriteGrantV1 {
            version: WRITE_AUTHORIZATION_VERSION.to_be_bytes().to_vec(),
            relationship_instance_id: self.relationship_instance_id.to_vec(),
            recipient_genesis: self.recipient_genesis.to_vec(),
            recipient_device_id: self.recipient_device_id.to_vec(),
            authorized_sender_device_id: self.authorized_sender_device_id.to_vec(),
            authorized_write_public_key: self.authorized_write_public_key.clone(),
            permitted_scope: self.permitted_scope.to_be_bytes().to_vec(),
            grant_id: self.grant_id().to_vec(),
            grant_signature,
        }
    }

    /// Whether this grant authorizes `sender`'s key `write_public_key` to
    /// write to `recipient`'s inbox for `relationship_instance_id`. Nothing
    /// else is ever authorized by it.
    pub fn authorizes(
        &self,
        relationship_instance_id: &[u8; 32],
        recipient_device_id: &[u8; 32],
        sender_device_id: &[u8; 32],
        write_public_key: &[u8],
    ) -> bool {
        self.permitted_scope == SCOPE_RELATIONSHIP_INBOX
            && &self.relationship_instance_id == relationship_instance_id
            && &self.recipient_device_id == recipient_device_id
            && &self.authorized_sender_device_id == sender_device_id
            && self.authorized_write_public_key.as_slice() == write_public_key
    }
}

/// The check anyone holding the recipient's AK can make of a grant, with no
/// expectation of what it names: version and scope, the identifier is the
/// hash of the fields, and the recipient's AK signed it.
pub fn verify_write_grant_signature(
    wire: &RelationshipWriteGrantV1,
    recipient_ak: &[u8],
) -> Result<WriteGrant, WriteAuthorizationRefusal> {
    let version = be_u32(&wire.version)?;
    if version != WRITE_AUTHORIZATION_VERSION {
        return Err(WriteAuthorizationRefusal::Version(version));
    }
    let scope = be_u32(&wire.permitted_scope)?;
    if scope != SCOPE_RELATIONSHIP_INBOX {
        return Err(WriteAuthorizationRefusal::Scope(scope));
    }
    if wire.authorized_write_public_key.len() != public_key_bytes(WRITE_KEY_VARIANT) {
        return Err(WriteAuthorizationRefusal::Wire(format!(
            "write key is {} bytes, not {}",
            wire.authorized_write_public_key.len(),
            public_key_bytes(WRITE_KEY_VARIANT)
        )));
    }
    let grant = WriteGrant {
        relationship_instance_id: arr32(&wire.relationship_instance_id)?,
        recipient_genesis: arr32(&wire.recipient_genesis)?,
        recipient_device_id: arr32(&wire.recipient_device_id)?,
        authorized_sender_device_id: arr32(&wire.authorized_sender_device_id)?,
        authorized_write_public_key: wire.authorized_write_public_key.clone(),
        permitted_scope: scope,
    };
    if arr32(&wire.grant_id)? != grant.grant_id() {
        return Err(WriteAuthorizationRefusal::GrantIdMismatch);
    }
    verified(
        recipient_ak,
        &grant.signing_target(),
        &wire.grant_signature,
        WriteAuthorizationRefusal::GrantSignature,
    )?;
    Ok(grant)
}

/// What a sender holds a grant for its key to: its own relationship instance,
/// the recipient's genesis and device as its contact record holds them, itself,
/// its own write key, and the recipient's AK.
#[derive(Debug, Clone, Copy)]
pub struct GrantExpectation<'a> {
    pub relationship_instance_id: &'a [u8; 32],
    pub recipient_genesis: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub write_public_key: &'a [u8],
    pub recipient_ak: &'a [u8],
}

/// The sender's check of a grant for its key: everything
/// [`verify_write_grant_signature`] checks, and it names exactly this
/// instance, this recipient, this sender and this key.
pub fn verify_write_grant(
    wire: &RelationshipWriteGrantV1,
    expected: &GrantExpectation<'_>,
) -> Result<WriteGrant, WriteAuthorizationRefusal> {
    let grant = verify_write_grant_signature(wire, expected.recipient_ak)?;
    if &grant.relationship_instance_id != expected.relationship_instance_id {
        return Err(WriteAuthorizationRefusal::WrongInstance);
    }
    if &grant.recipient_genesis != expected.recipient_genesis {
        return Err(WriteAuthorizationRefusal::WrongRecipientGenesis);
    }
    if &grant.recipient_device_id != expected.recipient_device_id {
        return Err(WriteAuthorizationRefusal::WrongRecipient);
    }
    if &grant.authorized_sender_device_id != expected.sender_device_id {
        return Err(WriteAuthorizationRefusal::WrongSender);
    }
    if grant.authorized_write_public_key.as_slice() != expected.write_public_key {
        return Err(WriteAuthorizationRefusal::WrongWriteKey);
    }
    Ok(grant)
}

fn offer_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 => Some(FieldLimit::Fixed(4)),
        2..=4 => Some(FieldLimit::Fixed(32)),
        5 => Some(FieldLimit::Fixed(WRITE_PUBLIC_KEY_LEN)),
        6 | 7 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

fn grant_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 | 7 => Some(FieldLimit::Fixed(4)),
        2..=5 | 8 => Some(FieldLimit::Fixed(32)),
        6 => Some(FieldLimit::Fixed(WRITE_PUBLIC_KEY_LEN)),
        9 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

/// Strict decode of an offer: tags 1-7 only, each once, all present, each its
/// exact or bounded length, re-encoding to the same bytes.
pub fn decode_write_key_offer_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteKeyOfferV1, WriteAuthorizationRefusal> {
    use prost::Message;
    validate_length_delimited_wire(bytes, "write-key offer", 7, offer_field_limit, |tag| {
        (1..=7).contains(&tag)
    })
    .map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    let offer = RelationshipWriteKeyOfferV1::decode(bytes)
        .map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    if offer.encode_to_vec() != bytes {
        return Err(WriteAuthorizationRefusal::Wire(
            "non-canonical field ordering or encoding".to_string(),
        ));
    }
    Ok(offer)
}

/// Strict decode of a grant: tags 1-9 only, each once, all present, each its
/// exact or bounded length, re-encoding to the same bytes.
pub fn decode_write_grant_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteGrantV1, WriteAuthorizationRefusal> {
    use prost::Message;
    validate_length_delimited_wire(bytes, "write grant", 9, grant_field_limit, |tag| {
        (1..=9).contains(&tag)
    })
    .map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    let grant = RelationshipWriteGrantV1::decode(bytes)
        .map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    if grant.encode_to_vec() != bytes {
        return Err(WriteAuthorizationRefusal::Wire(
            "non-canonical field ordering or encoding".to_string(),
        ));
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsKeyPair};
    use prost::Message;

    type Refusal = WriteAuthorizationRefusal;

    /// A device as the grant sees it: its id, its genesis, its AK.
    struct Device {
        id: [u8; 32],
        genesis: [u8; 32],
        ak: SphincsKeyPair,
    }

    fn device(tag: u8) -> Result<Device, DsmError> {
        Ok(Device {
            id: [tag; 32],
            genesis: [tag ^ 0xF0; 32],
            ak: generate_keypair(WRITE_KEY_VARIANT)?,
        })
    }

    /// `sender`'s offer of `write_key` to `recipient` for `instance`, both
    /// signatures made by the keys that must make them.
    fn offer(
        instance: [u8; 32],
        sender: &Device,
        recipient: &Device,
        write_key: &SphincsKeyPair,
    ) -> Result<(WriteKeyOffer, RelationshipWriteKeyOfferV1), DsmError> {
        let offer = WriteKeyOffer {
            relationship_instance_id: instance,
            sender_device_id: sender.id,
            recipient_device_id: recipient.id,
            write_public_key: write_key.public_key.clone(),
        };
        let possession = sphincs_sign(&write_key.secret_key, &offer.possession_target())?;
        let binding = sphincs_sign(&sender.ak.secret_key, &offer.binding_target())?;
        let wire = offer.to_wire(possession, binding);
        Ok((offer, wire))
    }

    /// `recipient`'s grant for `offer`, signed by `signer`.
    fn grant(
        offer: &WriteKeyOffer,
        recipient: &Device,
        signer: &SphincsKeyPair,
    ) -> Result<RelationshipWriteGrantV1, DsmError> {
        let grant = WriteGrant::for_offer(offer, recipient.genesis);
        let signature = sphincs_sign(&signer.secret_key, &grant.signing_target())?;
        Ok(grant.to_wire(signature))
    }

    fn offer_expectation<'a>(
        instance: &'a [u8; 32],
        sender: &'a Device,
        recipient: &'a Device,
    ) -> OfferExpectation<'a> {
        OfferExpectation {
            relationship_instance_id: instance,
            sender_device_id: &sender.id,
            recipient_device_id: &recipient.id,
            sender_ak: &sender.ak.public_key,
        }
    }

    fn grant_expectation<'a>(
        instance: &'a [u8; 32],
        sender: &'a Device,
        recipient: &'a Device,
        write_key: &'a SphincsKeyPair,
    ) -> GrantExpectation<'a> {
        GrantExpectation {
            relationship_instance_id: instance,
            recipient_genesis: &recipient.genesis,
            recipient_device_id: &recipient.id,
            sender_device_id: &sender.id,
            write_public_key: &write_key.public_key,
            recipient_ak: &recipient.ak.public_key,
        }
    }

    const INSTANCE: [u8; 32] = [0x5A; 32];

    #[test]
    fn a_write_key_is_one_per_instance_and_direction_and_comes_back_from_the_master_seed(
    ) -> Result<(), DsmError> {
        let (s_a, s_b) = ([0xA5; 32], [0xB5; 32]);
        let (a, b) = ([0x0A; 32], [0x0B; 32]);
        let ab = derive_write_keypair(&s_a, &INSTANCE, &a, &b)?;
        let again = derive_write_keypair(&s_a, &INSTANCE, &a, &b)?;
        assert_eq!(
            (&ab.public_key, &ab.secret_key),
            (&again.public_key, &again.secret_key)
        );
        let ba = derive_write_keypair(&s_b, &INSTANCE, &b, &a)?;
        assert_ne!(ab.public_key, ba.public_key);
        // The same master seed, the other direction or another instance.
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_a, &INSTANCE, &b, &a)?.public_key
        );
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_a, &[0x6B; 32], &a, &b)?.public_key
        );
        // Another master seed.
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_b, &INSTANCE, &a, &b)?.public_key
        );
        assert_eq!(ab.public_key.len(), WRITE_PUBLIC_KEY_LEN);
        Ok(())
    }

    #[test]
    fn an_instance_is_its_relationship_and_its_establishing_tip() {
        let rel = [0x11; 32];
        let tip = [0x22; 32];
        let id = relationship_instance_id(&rel, &tip);
        assert_eq!(id, relationship_instance_id(&rel, &tip));
        assert_ne!(id, relationship_instance_id(&rel, &[0x23; 32]));
        assert_ne!(id, relationship_instance_id(&[0x12; 32], &tip));
    }

    #[test]
    fn a_recipients_grant_for_a_verified_offer_verifies() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, wire) = offer(INSTANCE, &a, &b, &wk)?;

        let checked = verify_write_key_offer(&wire, &offer_expectation(&INSTANCE, &a, &b))?;
        assert_eq!(checked, sent);

        let granted = grant(&checked, &b, &b.ak)?;
        let held = verify_write_grant(&granted, &grant_expectation(&INSTANCE, &a, &b, &wk))?;
        assert!(held.authorizes(&INSTANCE, &b.id, &a.id, &wk.public_key));
        assert_eq!(held.permitted_scope, SCOPE_RELATIONSHIP_INBOX);
        Ok(())
    }

    #[test]
    fn each_direction_has_its_own_key_and_its_own_grant() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let (wk_ab, wk_ba) = (
            generate_keypair(WRITE_KEY_VARIANT)?,
            generate_keypair(WRITE_KEY_VARIANT)?,
        );
        let (offer_ab, _) = offer(INSTANCE, &a, &b, &wk_ab)?;
        let (offer_ba, _) = offer(INSTANCE, &b, &a, &wk_ba)?;
        let grant_ab = grant(&offer_ab, &b, &b.ak)?;
        let grant_ba = grant(&offer_ba, &a, &a.ak)?;

        verify_write_grant(&grant_ab, &grant_expectation(&INSTANCE, &a, &b, &wk_ab))?;
        verify_write_grant(&grant_ba, &grant_expectation(&INSTANCE, &b, &a, &wk_ba))?;
        assert_ne!(grant_ab.grant_id, grant_ba.grant_id);
        // B's grant to A is not A's grant to B: it is signed by B, for B's inbox.
        assert_eq!(
            verify_write_grant(&grant_ab, &grant_expectation(&INSTANCE, &b, &a, &wk_ab)),
            Err(Refusal::GrantSignature)
        );
        Ok(())
    }

    #[test]
    fn a_forged_recipient_signature_fails() -> Result<(), DsmError> {
        let (a, b, mallory) = (device(0x0A)?, device(0x0B)?, device(0x0C)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (offer, _) = offer(INSTANCE, &a, &b, &wk)?;
        let expected = grant_expectation(&INSTANCE, &a, &b, &wk);

        // Signed by a key that is not B's AK.
        let by_mallory = grant(&offer, &b, &mallory.ak)?;
        assert_eq!(
            verify_write_grant(&by_mallory, &expected),
            Err(Refusal::GrantSignature)
        );
        // B's own signature, one bit flipped.
        let mut flipped = grant(&offer, &b, &b.ak)?;
        flipped.grant_signature[100] ^= 0x01;
        assert_eq!(
            verify_write_grant(&flipped, &expected),
            Err(Refusal::GrantSignature)
        );
        // B's signature over a grant whose fields were changed after signing.
        let mut widened = grant(&offer, &b, &b.ak)?;
        widened.authorized_sender_device_id = mallory.id.to_vec();
        assert_eq!(
            verify_write_grant_signature(&widened, &b.ak.public_key),
            Err(Refusal::GrantIdMismatch)
        );
        Ok(())
    }

    #[test]
    fn an_unrelated_senders_key_fails() -> Result<(), DsmError> {
        let (a, b, c) = (device(0x0A)?, device(0x0B)?, device(0x0C)?);
        let (wk_a, wk_c) = (
            generate_keypair(WRITE_KEY_VARIANT)?,
            generate_keypair(WRITE_KEY_VARIANT)?,
        );
        let (offer_a, _) = offer(INSTANCE, &a, &b, &wk_a)?;
        let granted = grant(&offer_a, &b, &b.ak)?;

        // C's key under A's grant.
        assert_eq!(
            verify_write_grant(&granted, &grant_expectation(&INSTANCE, &a, &b, &wk_c)),
            Err(Refusal::WrongWriteKey)
        );
        // C presenting A's grant as its own.
        assert_eq!(
            verify_write_grant(&granted, &grant_expectation(&INSTANCE, &c, &b, &wk_a)),
            Err(Refusal::WrongSender)
        );
        let held = verify_write_grant_signature(&granted, &b.ak.public_key)?;
        assert!(!held.authorizes(&INSTANCE, &b.id, &c.id, &wk_c.public_key));
        assert!(!held.authorizes(&INSTANCE, &b.id, &a.id, &wk_c.public_key));

        // An offer naming A but bound by C's AK is not A's.
        let (_, c_as_a) = offer(INSTANCE, &c, &b, &wk_c)?;
        let mut c_as_a = c_as_a;
        c_as_a.sender_device_id = a.id.to_vec();
        assert_eq!(
            verify_write_key_offer(&c_as_a, &offer_expectation(&INSTANCE, &a, &b)),
            Err(Refusal::BindingSignature)
        );
        Ok(())
    }

    #[test]
    fn a_grant_for_another_recipient_fails() -> Result<(), DsmError> {
        let (a, b, c) = (device(0x0A)?, device(0x0B)?, device(0x0C)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (to_b, _) = offer(INSTANCE, &a, &b, &wk)?;
        let from_b = grant(&to_b, &b, &b.ak)?;

        // B's grant read as C's: C's AK did not sign it.
        assert_eq!(
            verify_write_grant(&from_b, &grant_expectation(&INSTANCE, &a, &c, &wk)),
            Err(Refusal::GrantSignature)
        );
        // B's grant does not authorize C's inbox.
        let held = verify_write_grant_signature(&from_b, &b.ak.public_key)?;
        assert!(!held.authorizes(&INSTANCE, &c.id, &a.id, &wk.public_key));

        // An offer to B is not an offer to C.
        let (_, offer_to_b) = offer(INSTANCE, &a, &b, &wk)?;
        assert_eq!(
            verify_write_key_offer(&offer_to_b, &offer_expectation(&INSTANCE, &a, &c)),
            Err(Refusal::WrongRecipient)
        );

        // A grant naming C's device but signed by B's AK, read under B's AK
        // with C expected, is refused for the recipient it names.
        let mut for_c = WriteGrant::for_offer(&to_b, b.genesis);
        for_c.recipient_device_id = c.id;
        let signed = for_c.to_wire(sphincs_sign(&b.ak.secret_key, &for_c.signing_target())?);
        let mut expect = grant_expectation(&INSTANCE, &a, &b, &wk);
        expect.recipient_ak = &b.ak.public_key;
        assert_eq!(
            verify_write_grant(&signed, &expect),
            Err(Refusal::WrongRecipient)
        );
        Ok(())
    }

    #[test]
    fn a_grant_for_another_relationship_fails() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let other: [u8; 32] = [0x6B; 32];
        let (for_x, wire_x) = offer(INSTANCE, &a, &b, &wk)?;
        let granted_x = grant(&for_x, &b, &b.ak)?;

        assert_eq!(
            verify_write_grant(&granted_x, &grant_expectation(&other, &a, &b, &wk)),
            Err(Refusal::WrongInstance)
        );
        assert_eq!(
            verify_write_key_offer(&wire_x, &offer_expectation(&other, &a, &b)),
            Err(Refusal::WrongInstance)
        );
        let held = verify_write_grant_signature(&granted_x, &b.ak.public_key)?;
        assert!(!held.authorizes(&other, &b.id, &a.id, &wk.public_key));
        Ok(())
    }

    #[test]
    fn a_grant_is_not_reused_across_instances_of_one_pair() -> Result<(), DsmError> {
        // The same two devices, the same write key, a later instance of their
        // relationship: the first instance's grant authorizes nothing in it.
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let first: [u8; 32] = [0x01; 32];
        let second: [u8; 32] = [0x02; 32];
        let (closed, _) = offer(first, &a, &b, &wk)?;
        let old_grant = grant(&closed, &b, &b.ak)?;

        assert_eq!(
            verify_write_grant(&old_grant, &grant_expectation(&second, &a, &b, &wk)),
            Err(Refusal::WrongInstance)
        );
        let held = verify_write_grant_signature(&old_grant, &b.ak.public_key)?;
        assert!(!held.authorizes(&second, &b.id, &a.id, &wk.public_key));

        // Rewriting the instance breaks the identifier, and an identifier
        // recomputed breaks B's signature.
        let mut moved = old_grant.clone();
        moved.relationship_instance_id = second.to_vec();
        assert_eq!(
            verify_write_grant_signature(&moved, &b.ak.public_key),
            Err(Refusal::GrantIdMismatch)
        );
        let mut rehashed = WriteGrant::for_offer(&closed, b.genesis);
        rehashed.relationship_instance_id = second;
        let replayed = rehashed.to_wire(old_grant.grant_signature.clone());
        assert_eq!(
            verify_write_grant_signature(&replayed, &b.ak.public_key),
            Err(Refusal::GrantSignature)
        );
        Ok(())
    }

    #[test]
    fn possessing_a_key_without_the_recipients_grant_authorizes_nothing() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, wire) = offer(INSTANCE, &a, &b, &wk)?;
        // The offer proves possession, and is no grant.
        verify_write_key_offer(&wire, &offer_expectation(&INSTANCE, &a, &b))?;

        let expected = grant_expectation(&INSTANCE, &a, &b, &wk);
        // A grant A signs for itself, with its write key or with its AK.
        assert_eq!(
            verify_write_grant(&grant(&sent, &b, &wk)?, &expected),
            Err(Refusal::GrantSignature)
        );
        assert_eq!(
            verify_write_grant(&grant(&sent, &b, &a.ak)?, &expected),
            Err(Refusal::GrantSignature)
        );
        Ok(())
    }

    #[test]
    fn an_offer_proves_possession_with_the_key_it_names() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, mut wire) = offer(INSTANCE, &a, &b, &wk)?;
        // The possession signature made by A's AK instead of the write key.
        wire.possession_signature = sphincs_sign(&a.ak.secret_key, &sent.possession_target())?;
        assert_eq!(
            verify_write_key_offer(&wire, &offer_expectation(&INSTANCE, &a, &b)),
            Err(Refusal::PossessionSignature)
        );
        Ok(())
    }

    #[test]
    fn a_write_key_is_never_the_senders_ak() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let (_, wire) = offer(INSTANCE, &a, &b, &a.ak)?;
        assert_eq!(
            verify_write_key_offer(&wire, &offer_expectation(&INSTANCE, &a, &b)),
            Err(Refusal::WriteKeyIsTheSendersAk)
        );
        Ok(())
    }

    #[test]
    fn issuing_the_same_grant_again_issues_the_same_bytes() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, _) = offer(INSTANCE, &a, &b, &wk)?;
        let once = grant(&sent, &b, &b.ak)?.encode_to_vec();
        let twice = grant(&sent, &b, &b.ak)?.encode_to_vec();
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn the_wire_forms_are_strict() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, offer_wire) = offer(INSTANCE, &a, &b, &wk)?;
        let grant_wire = grant(&sent, &b, &b.ak)?;

        let offer_bytes = offer_wire.encode_to_vec();
        assert_eq!(decode_write_key_offer_wire(&offer_bytes)?, offer_wire);
        let grant_bytes = grant_wire.encode_to_vec();
        assert_eq!(decode_write_grant_wire(&grant_bytes)?, grant_wire);

        // An unknown field.
        let mut extra = grant_bytes.clone();
        extra.extend_from_slice(&[0x52, 0x01, 0x00]); // field 10, one byte
        assert!(matches!(
            decode_write_grant_wire(&extra),
            Err(Refusal::Wire(_))
        ));
        // A field missing.
        let mut short = grant_wire.clone();
        short.grant_id.clear();
        assert!(matches!(
            decode_write_grant_wire(&short.encode_to_vec()),
            Err(Refusal::Wire(_))
        ));
        // A field of the wrong length.
        let mut long_key = offer_wire.clone();
        long_key.write_public_key.push(0);
        assert!(matches!(
            decode_write_key_offer_wire(&long_key.encode_to_vec()),
            Err(Refusal::Wire(_))
        ));
        // A scope other than the relationship inbox, even signed.
        let mut wider = WriteGrant::for_offer(&sent, b.genesis);
        wider.permitted_scope = 2;
        let signed = wider.to_wire(sphincs_sign(&b.ak.secret_key, &wider.signing_target())?);
        assert_eq!(
            verify_write_grant_signature(&signed, &b.ak.public_key),
            Err(Refusal::Scope(2))
        );
        Ok(())
    }
}
