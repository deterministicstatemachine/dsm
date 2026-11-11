// SPDX-License-Identifier: MIT OR Apache-2.0

//! A relationship's write lock, its grants, and the proof every write to an
//! inbox carries (DSM Amendment A34).
//!
//! Once a relationship is established, each device offers the other a write
//! key of its own, for that relationship instance and that direction. Each
//! device also holds a **write lock** for its own inbox on the relationship: a
//! key pair it derives for that relationship, never its AK. Its AK binds the
//! lock to the instance, itself and the other device, which tells the other
//! wallet whose lock it is; the lock then signs the **grant** of the other
//! device's write key. A grant names no identity, only the instance (an opaque
//! hash), the key and the scope, so the proof a write carries shows a storage
//! node public keys alone.
//!
//! A **write** to an inbox address carries the lock's public key, the grant,
//! and the writer's signature over the address, the write's message id and the
//! commitment of the envelope written. The first write stored at an address
//! fixes its key; a node stores a later write there only when it carries that
//! key, a grant that verifies under it and a write signature that verifies
//! under the granted key ([`verify_spool_write`]). At a relationship's first
//! inbox, before either side holds a lock for it, the writer fixes a key of
//! its own ([`derive_first_inbox_keypair`]): its key there is lock and write
//! key at once.
//!
//! An offer carries two signatures over one body: the sender's AK binds the
//! key, and the key proves possession. An offered key that is the sender's AK
//! is refused. Every signed field has a fixed length, so each signed
//! concatenation is canonical without a length prefix; the wire forms are
//! strict protobuf: known tags only, each once, each its exact length,
//! re-encoding to the same bytes.

use crate::common::domain_tags::{
    TAG_DSM_RELATIONSHIP_FIRST_INBOX_KEY, TAG_DSM_RELATIONSHIP_INSTANCE,
    TAG_DSM_RELATIONSHIP_WRITE_GRANT, TAG_DSM_RELATIONSHIP_WRITE_GRANT_ID,
    TAG_DSM_RELATIONSHIP_WRITE_KEY, TAG_DSM_RELATIONSHIP_WRITE_KEY_BINDING,
    TAG_DSM_RELATIONSHIP_WRITE_KEY_POSSESSION, TAG_DSM_RELATIONSHIP_WRITE_LOCK,
    TAG_DSM_RELATIONSHIP_WRITE_LOCK_BINDING, TAG_DSM_SPOOL_WRITE, TAG_DSM_SPOOL_WRITE_ENVELOPE,
};
use crate::crypto::blake3::{domain_hash_bytes, dsm_domain_hasher, dsm_domain_hasher_keyed};
use crate::crypto::sphincs::{
    generate_keypair_from_seed, public_key_bytes, sphincs_verify, SphincsKeyPair, SphincsVariant,
};
use crate::types::error::DsmError;
use crate::types::proto::{
    RelationshipWriteAuthorizationV1, RelationshipWriteGrantV1, RelationshipWriteKeyOfferV1,
    RelationshipWriteLockV1, SpoolWriteV1,
};
use crate::types::receipt_types::{validate_length_delimited_wire, FieldLimit};

/// The one version of an offer, a lock and a grant.
pub const WRITE_AUTHORIZATION_VERSION: u32 = 1;
/// The one scope a grant names: the recipient's inbox for the relationship
/// instance, at every address that relationship's tips route to.
pub const SCOPE_RELATIONSHIP_INBOX: u32 = 1;
/// Write keys and locks are SPHINCS+ SPX256f keys, the scheme every DSM device
/// key uses.
pub const WRITE_KEY_VARIANT: SphincsVariant = SphincsVariant::SPX256f;
/// A public key's length, `PK.seed ‖ PK.root`.
pub const WRITE_PUBLIC_KEY_LEN: usize = 64;
/// The longest signature any object carries (SPX256f is 49,856 bytes).
const SIGNATURE_MAX_LEN: usize = 65_535;
/// The longest envelope a write carries: the spool's envelope cap.
pub const SPOOL_WRITE_ENVELOPE_MAX_LEN: usize = crate::spool::MAX_ENVELOPE_BYTES;
/// An inbox address's length, decoded.
pub const INBOX_ADDRESS_LEN: usize = 32;
/// A spool message id's length.
pub const MESSAGE_ID_LEN: usize = 16;

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

fn keypair_from(
    tag: crate::crypto::domain::TaggedHashDomain<'static>,
    s_master: &[u8; 32],
    parts: &[&[u8; 32]],
) -> Result<SphincsKeyPair, DsmError> {
    let mut h = dsm_domain_hasher_keyed(tag, s_master);
    for part in parts {
        h.update(*part);
    }
    let seed = zeroize::Zeroizing::new(*h.finalize().as_bytes());
    generate_keypair_from_seed(WRITE_KEY_VARIANT, &seed)
}

/// The write key `sender` writes to `recipient` with on `instance`: SPHINCS+
/// key generation from `keyed-BLAKE3(Smaster, "DSM/relationship-write-key/v1"
/// ‖ instance ‖ sender ‖ recipient)`. It comes back from the master seed
/// alone, so nothing secret is stored, one per instance and direction. The AK
/// is derived under other contexts, so it is never the root signing key.
pub fn derive_write_keypair(
    s_master: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    sender_device_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    keypair_from(
        TAG_DSM_RELATIONSHIP_WRITE_KEY,
        s_master,
        &[
            relationship_instance_id,
            sender_device_id,
            recipient_device_id,
        ],
    )
}

/// The write lock `recipient` holds over its inbox for `instance`, toward
/// `sender`: SPHINCS+ key generation from `keyed-BLAKE3(Smaster,
/// "DSM/relationship-write-lock/v1" ‖ instance ‖ recipient ‖ sender)`. One
/// per relationship and direction, never the AK, and nothing secret stored.
pub fn derive_write_lock_keypair(
    s_master: &[u8; 32],
    relationship_instance_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
    sender_device_id: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    keypair_from(
        TAG_DSM_RELATIONSHIP_WRITE_LOCK,
        s_master,
        &[
            relationship_instance_id,
            recipient_device_id,
            sender_device_id,
        ],
    )
}

/// The key `writer` fixes at `recipient`'s first inbox on the relationship
/// `relationship_key` opened at `first_tip`, before either side holds a lock
/// for it: SPHINCS+ key generation from `keyed-BLAKE3(Smaster,
/// "DSM/relationship-first-inbox-key/v1" ‖ relationship key ‖ first tip ‖
/// writer ‖ recipient)`. It is lock and write key at once.
pub fn derive_first_inbox_keypair(
    s_master: &[u8; 32],
    relationship_key: &[u8; 32],
    first_tip: &[u8; 32],
    writer_device_id: &[u8; 32],
    recipient_device_id: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    keypair_from(
        TAG_DSM_RELATIONSHIP_FIRST_INBOX_KEY,
        s_master,
        &[
            relationship_key,
            first_tip,
            writer_device_id,
            recipient_device_id,
        ],
    )
}

/// Why an offer, a lock, a grant or a write is not what it must be. Each
/// refusal names one check; none is ever read as another.
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
    /// The lock is the recipient's AK.
    LockIsTheRecipientsAk,
    /// The grant's identifier is not the hash of its fields.
    GrantIdMismatch,
    /// The sender's AK did not sign the offer.
    BindingSignature,
    /// The write key did not sign the offer.
    PossessionSignature,
    /// The recipient's AK did not bind the lock.
    LockBindingSignature,
    /// The lock did not sign the grant.
    GrantSignature,
    /// The granted key did not sign the write.
    WriteSignature,
    /// The address is neither the route digest bound to the key nor the
    /// digest's open address.
    WrongAddress,
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
            Self::LockIsTheRecipientsAk => f.write_str("the lock is the recipient's AK"),
            Self::GrantIdMismatch => f.write_str("the grant id is not the hash of its fields"),
            Self::BindingSignature => f.write_str("the sender's AK did not sign the offer"),
            Self::PossessionSignature => f.write_str("the write key did not sign the offer"),
            Self::LockBindingSignature => f.write_str("the recipient's AK did not bind the lock"),
            Self::GrantSignature => f.write_str("the lock did not sign the grant"),
            Self::WriteSignature => f.write_str("the granted key did not sign the write"),
            Self::WrongAddress => {
                f.write_str("the address is not the route bound to the key, nor its open address")
            }
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

fn check_version(bytes: &[u8]) -> Result<(), WriteAuthorizationRefusal> {
    let version = be_u32(bytes)?;
    if version == WRITE_AUTHORIZATION_VERSION {
        Ok(())
    } else {
        Err(WriteAuthorizationRefusal::Version(version))
    }
}

fn check_key_len(key: &[u8]) -> Result<(), WriteAuthorizationRefusal> {
    if key.len() == public_key_bytes(WRITE_KEY_VARIANT) {
        Ok(())
    } else {
        Err(WriteAuthorizationRefusal::Wire(format!(
            "a key of {} bytes, not {}",
            key.len(),
            public_key_bytes(WRITE_KEY_VARIANT)
        )))
    }
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

fn strict<M: prost::Message + Default>(
    bytes: &[u8],
    wire: &str,
    max_tag: u32,
    limit: fn(u32) -> Option<FieldLimit>,
) -> Result<M, WriteAuthorizationRefusal> {
    validate_length_delimited_wire(bytes, wire, max_tag, limit, |tag| {
        (1..=max_tag).contains(&tag)
    })
    .map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    let message = M::decode(bytes).map_err(|e| WriteAuthorizationRefusal::Wire(e.to_string()))?;
    if message.encode_to_vec() != bytes {
        return Err(WriteAuthorizationRefusal::Wire(format!(
            "{wire}: non-canonical field ordering or encoding"
        )));
    }
    Ok(message)
}

// ---------------------------------------------------------------------------
// The offer of a write key.
// ---------------------------------------------------------------------------

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
    check_version(&wire.version)?;
    check_key_len(&wire.write_public_key)?;
    let offer = WriteKeyOffer {
        relationship_instance_id: arr32(&wire.relationship_instance_id)?,
        sender_device_id: arr32(&wire.sender_device_id)?,
        recipient_device_id: arr32(&wire.recipient_device_id)?,
        write_public_key: wire.write_public_key.clone(),
    };
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

// ---------------------------------------------------------------------------
// The write lock.
// ---------------------------------------------------------------------------

/// A recipient's write lock over its inbox for one instance, toward one
/// sender, before the AK's binding signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLock {
    pub relationship_instance_id: [u8; 32],
    pub recipient_genesis: [u8; 32],
    pub recipient_device_id: [u8; 32],
    pub authorized_sender_device_id: [u8; 32],
    pub lock_public_key: Vec<u8>,
}

impl WriteLock {
    /// What the recipient's AK signs: `version ‖ instance ‖ recipient genesis
    /// ‖ recipient ‖ sender ‖ lock`, under the lock-binding domain.
    pub fn binding_target(&self) -> [u8; 32] {
        let mut body = Vec::with_capacity(4 + 4 * 32 + WRITE_PUBLIC_KEY_LEN);
        body.extend_from_slice(&WRITE_AUTHORIZATION_VERSION.to_be_bytes());
        body.extend_from_slice(&self.relationship_instance_id);
        body.extend_from_slice(&self.recipient_genesis);
        body.extend_from_slice(&self.recipient_device_id);
        body.extend_from_slice(&self.authorized_sender_device_id);
        body.extend_from_slice(&self.lock_public_key);
        domain_hash_bytes(TAG_DSM_RELATIONSHIP_WRITE_LOCK_BINDING, &body)
    }

    /// The wire form with the AK's binding signature.
    pub fn to_wire(&self, binding_signature: Vec<u8>) -> RelationshipWriteLockV1 {
        RelationshipWriteLockV1 {
            version: WRITE_AUTHORIZATION_VERSION.to_be_bytes().to_vec(),
            relationship_instance_id: self.relationship_instance_id.to_vec(),
            recipient_genesis: self.recipient_genesis.to_vec(),
            recipient_device_id: self.recipient_device_id.to_vec(),
            authorized_sender_device_id: self.authorized_sender_device_id.to_vec(),
            lock_public_key: self.lock_public_key.clone(),
            binding_signature,
        }
    }
}

// ---------------------------------------------------------------------------
// The grant.
// ---------------------------------------------------------------------------

/// A write lock's grant of its inbox for one instance to one write key,
/// before the lock's signature. It names no identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteGrant {
    pub relationship_instance_id: [u8; 32],
    pub authorized_write_public_key: Vec<u8>,
    pub permitted_scope: u32,
}

impl WriteGrant {
    /// The grant of `write_public_key` for `relationship_instance_id`.
    pub fn of_key(relationship_instance_id: [u8; 32], write_public_key: Vec<u8>) -> Self {
        WriteGrant {
            relationship_instance_id,
            authorized_write_public_key: write_public_key,
            permitted_scope: SCOPE_RELATIONSHIP_INBOX,
        }
    }

    /// `version ‖ instance ‖ key ‖ scope`: the fields before the identifier.
    fn fields_before_id(&self) -> Vec<u8> {
        let mut fields = Vec::with_capacity(4 + 32 + WRITE_PUBLIC_KEY_LEN + 4);
        fields.extend_from_slice(&WRITE_AUTHORIZATION_VERSION.to_be_bytes());
        fields.extend_from_slice(&self.relationship_instance_id);
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

    /// What the lock signs: `BLAKE3("DSM/relationship-write-grant/v1" ‖
    /// canonical(WriteGrant))`, every field including the identifier.
    pub fn signing_target(&self) -> [u8; 32] {
        let mut canonical = self.fields_before_id();
        canonical.extend_from_slice(&self.grant_id());
        domain_hash_bytes(TAG_DSM_RELATIONSHIP_WRITE_GRANT, &canonical)
    }

    /// The wire form with the lock's signature.
    pub fn to_wire(&self, grant_signature: Vec<u8>) -> RelationshipWriteGrantV1 {
        RelationshipWriteGrantV1 {
            version: WRITE_AUTHORIZATION_VERSION.to_be_bytes().to_vec(),
            relationship_instance_id: self.relationship_instance_id.to_vec(),
            authorized_write_public_key: self.authorized_write_public_key.clone(),
            permitted_scope: self.permitted_scope.to_be_bytes().to_vec(),
            grant_id: self.grant_id().to_vec(),
            grant_signature,
        }
    }
}

/// The check anyone holding a lock's public key can make of a grant, a
/// storage node included: version and scope, the identifier is the hash of
/// the fields, and the lock signed it.
pub fn verify_write_grant_signature(
    wire: &RelationshipWriteGrantV1,
    lock_public_key: &[u8],
) -> Result<WriteGrant, WriteAuthorizationRefusal> {
    check_version(&wire.version)?;
    let scope = be_u32(&wire.permitted_scope)?;
    if scope != SCOPE_RELATIONSHIP_INBOX {
        return Err(WriteAuthorizationRefusal::Scope(scope));
    }
    check_key_len(&wire.authorized_write_public_key)?;
    check_key_len(lock_public_key)?;
    let grant = WriteGrant {
        relationship_instance_id: arr32(&wire.relationship_instance_id)?,
        authorized_write_public_key: wire.authorized_write_public_key.clone(),
        permitted_scope: scope,
    };
    if arr32(&wire.grant_id)? != grant.grant_id() {
        return Err(WriteAuthorizationRefusal::GrantIdMismatch);
    }
    verified(
        lock_public_key,
        &grant.signing_target(),
        &wire.grant_signature,
        WriteAuthorizationRefusal::GrantSignature,
    )?;
    Ok(grant)
}

// ---------------------------------------------------------------------------
// The authorization a recipient sends: its lock, bound, and the lock's grant.
// ---------------------------------------------------------------------------

/// What a sender holds an authorization to: its own instance and write key,
/// the recipient's genesis and device as its contact record holds them, and
/// the recipient's AK.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationExpectation<'a> {
    pub relationship_instance_id: &'a [u8; 32],
    pub recipient_genesis: &'a [u8; 32],
    pub recipient_device_id: &'a [u8; 32],
    pub sender_device_id: &'a [u8; 32],
    pub write_public_key: &'a [u8],
    pub recipient_ak: &'a [u8],
}

/// A verified authorization: the lock (whose it is was checked) and the grant
/// it signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorization {
    pub lock: WriteLock,
    pub grant: WriteGrant,
    /// The grant's exact wire bytes, which every write carries.
    pub grant_wire: Vec<u8>,
}

/// The sender's check of an authorization: the recipient's AK bound the lock
/// to exactly this instance, recipient and sender, and the lock is not that
/// AK; the lock signed a grant of exactly this instance and this sender's
/// write key.
pub fn verify_write_authorization(
    bytes: &[u8],
    expected: &AuthorizationExpectation<'_>,
) -> Result<VerifiedAuthorization, WriteAuthorizationRefusal> {
    use prost::Message;
    let authorization = decode_write_authorization_wire(bytes)?;
    let lock_wire = decode_write_lock_wire(&authorization.lock)?;
    let grant_wire = decode_write_grant_wire(&authorization.grant)?;
    check_version(&lock_wire.version)?;
    check_key_len(&lock_wire.lock_public_key)?;
    let lock = WriteLock {
        relationship_instance_id: arr32(&lock_wire.relationship_instance_id)?,
        recipient_genesis: arr32(&lock_wire.recipient_genesis)?,
        recipient_device_id: arr32(&lock_wire.recipient_device_id)?,
        authorized_sender_device_id: arr32(&lock_wire.authorized_sender_device_id)?,
        lock_public_key: lock_wire.lock_public_key.clone(),
    };
    if &lock.relationship_instance_id != expected.relationship_instance_id {
        return Err(WriteAuthorizationRefusal::WrongInstance);
    }
    if &lock.recipient_genesis != expected.recipient_genesis {
        return Err(WriteAuthorizationRefusal::WrongRecipientGenesis);
    }
    if &lock.recipient_device_id != expected.recipient_device_id {
        return Err(WriteAuthorizationRefusal::WrongRecipient);
    }
    if &lock.authorized_sender_device_id != expected.sender_device_id {
        return Err(WriteAuthorizationRefusal::WrongSender);
    }
    if lock.lock_public_key.as_slice() == expected.recipient_ak {
        return Err(WriteAuthorizationRefusal::LockIsTheRecipientsAk);
    }
    verified(
        expected.recipient_ak,
        &lock.binding_target(),
        &lock_wire.binding_signature,
        WriteAuthorizationRefusal::LockBindingSignature,
    )?;
    let grant = verify_write_grant_signature(&grant_wire, &lock.lock_public_key)?;
    if &grant.relationship_instance_id != expected.relationship_instance_id {
        return Err(WriteAuthorizationRefusal::WrongInstance);
    }
    if grant.authorized_write_public_key.as_slice() != expected.write_public_key {
        return Err(WriteAuthorizationRefusal::WrongWriteKey);
    }
    Ok(VerifiedAuthorization {
        lock,
        grant,
        grant_wire: grant_wire.encode_to_vec(),
    })
}

/// The authorization's wire bytes from a bound lock and its grant.
pub fn write_authorization_wire(
    lock: &RelationshipWriteLockV1,
    grant: &RelationshipWriteGrantV1,
) -> Vec<u8> {
    use prost::Message;
    RelationshipWriteAuthorizationV1 {
        lock: lock.encode_to_vec(),
        grant: grant.encode_to_vec(),
    }
    .encode_to_vec()
}

// ---------------------------------------------------------------------------
// One write to an inbox address.
// ---------------------------------------------------------------------------

/// The commitment of a written envelope's bytes.
pub fn envelope_commitment(envelope: &[u8]) -> [u8; 32] {
    domain_hash_bytes(TAG_DSM_SPOOL_WRITE_ENVELOPE, envelope)
}

/// What a writer's key signs for one write: the inbox address, the write's
/// message id and the commitment of the envelope, under the spool-write
/// domain. A copy of the signature fits no other address, id or bytes.
pub fn spool_write_target(
    address: &[u8; INBOX_ADDRESS_LEN],
    message_id: &[u8; MESSAGE_ID_LEN],
    envelope: &[u8],
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_SPOOL_WRITE);
    h.update(address);
    h.update(message_id);
    h.update(&envelope_commitment(envelope));
    *h.finalize().as_bytes()
}

/// A write as a storage node receives it.
pub fn spool_write_wire(
    envelope: Vec<u8>,
    lock_public_key: Vec<u8>,
    grant_wire: Vec<u8>,
    write_signature: Vec<u8>,
    route_digest: [u8; 32],
) -> SpoolWriteV1 {
    SpoolWriteV1 {
        envelope,
        lock_public_key,
        grant: grant_wire,
        write_signature,
        route_digest: route_digest.to_vec(),
    }
}

/// One write signed by `writer` under the grant `grant_wire` of the lock
/// `lock_public_key`: the bytes a node receives.
pub fn signed_spool_write(
    writer: &SphincsKeyPair,
    lock_public_key: &[u8],
    grant_wire: Vec<u8>,
    route_digest: &[u8; 32],
    address: &[u8; INBOX_ADDRESS_LEN],
    message_id: &[u8; MESSAGE_ID_LEN],
    envelope: &[u8],
) -> Result<Vec<u8>, DsmError> {
    use prost::Message;
    let signature = crate::crypto::sphincs::sphincs_sign(
        &writer.secret_key,
        &spool_write_target(address, message_id, envelope),
    )?;
    Ok(spool_write_wire(
        envelope.to_vec(),
        lock_public_key.to_vec(),
        grant_wire,
        signature,
        *route_digest,
    )
    .encode_to_vec())
}

/// One write under a key that is lock and write key at once: the key a
/// writer fixes at a relationship's first inbox, granting itself for
/// `relationship_instance_id`.
pub fn self_granted_spool_write(
    key: &SphincsKeyPair,
    relationship_instance_id: &[u8; 32],
    route_digest: &[u8; 32],
    address: &[u8; INBOX_ADDRESS_LEN],
    message_id: &[u8; MESSAGE_ID_LEN],
    envelope: &[u8],
) -> Result<Vec<u8>, DsmError> {
    use prost::Message;
    let grant = WriteGrant::of_key(*relationship_instance_id, key.public_key.clone());
    let grant_wire = grant
        .to_wire(crate::crypto::sphincs::sphincs_sign(
            &key.secret_key,
            &grant.signing_target(),
        )?)
        .encode_to_vec();
    signed_spool_write(
        key,
        &key.public_key,
        grant_wire,
        route_digest,
        address,
        message_id,
        envelope,
    )
}

/// A write that verified: the key it carries (which the node compares with,
/// or fixes as, the address's key) and the envelope it stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSpoolWrite {
    pub lock_public_key: Vec<u8>,
    pub envelope: Vec<u8>,
    /// Which kind of inbox address the write proved it is for.
    pub inbox: InboxKind,
}

/// The two kinds of inbox address (DSM Amendment A34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxKind {
    /// The address is the route digest bound to the key the write carries:
    /// the key is the address's own, by derivation. Every inbox of a
    /// relationship after its first.
    Locked,
    /// The address is the route digest's open address: a relationship's
    /// first inbox, whose key its first write fixes.
    Open,
}

/// The node's check of one write, for `address` under `message_id`: the
/// write is strict wire; the address is the write's route digest bound to the
/// key it carries ([`InboxKind::Locked`]: the key is the address's by
/// derivation) or the digest's open address ([`InboxKind::Open`]: the key is
/// the caller's comparison with what the address's first write fixed); the
/// grant verifies under the key, and the granted key signed this address,
/// this id and these bytes. Nothing here names or reveals an identity.
pub fn verify_spool_write(
    bytes: &[u8],
    address: &[u8; INBOX_ADDRESS_LEN],
    message_id: &[u8; MESSAGE_ID_LEN],
) -> Result<VerifiedSpoolWrite, WriteAuthorizationRefusal> {
    let write = decode_spool_write_wire(bytes)?;
    let route_digest = arr32(&write.route_digest)?;
    let inbox = if crate::crypto::spool_address::locked_inbox_address_bytes(
        &route_digest,
        &write.lock_public_key,
    ) == *address
    {
        InboxKind::Locked
    } else if crate::crypto::spool_address::open_inbox_address_bytes(&route_digest) == *address {
        InboxKind::Open
    } else {
        return Err(WriteAuthorizationRefusal::WrongAddress);
    };
    let grant_wire = decode_write_grant_wire(&write.grant)?;
    let grant = verify_write_grant_signature(&grant_wire, &write.lock_public_key)?;
    verified(
        &grant.authorized_write_public_key,
        &spool_write_target(address, message_id, &write.envelope),
        &write.write_signature,
        WriteAuthorizationRefusal::WriteSignature,
    )?;
    Ok(VerifiedSpoolWrite {
        lock_public_key: write.lock_public_key,
        envelope: write.envelope,
        inbox,
    })
}

// ---------------------------------------------------------------------------
// Strict wire decoders.
// ---------------------------------------------------------------------------

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
        1 | 4 => Some(FieldLimit::Fixed(4)),
        2 | 5 => Some(FieldLimit::Fixed(32)),
        3 => Some(FieldLimit::Fixed(WRITE_PUBLIC_KEY_LEN)),
        6 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

fn lock_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 => Some(FieldLimit::Fixed(4)),
        2..=5 => Some(FieldLimit::Fixed(32)),
        6 => Some(FieldLimit::Fixed(WRITE_PUBLIC_KEY_LEN)),
        7 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

fn authorization_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 | 2 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        _ => None,
    }
}

fn spool_write_field_limit(tag: u32) -> Option<FieldLimit> {
    match tag {
        1 => Some(FieldLimit::Max(SPOOL_WRITE_ENVELOPE_MAX_LEN)),
        2 => Some(FieldLimit::Fixed(WRITE_PUBLIC_KEY_LEN)),
        3 | 4 => Some(FieldLimit::Max(SIGNATURE_MAX_LEN)),
        5 => Some(FieldLimit::Fixed(INBOX_ADDRESS_LEN)),
        _ => None,
    }
}

/// Strict decode of an offer: tags 1-7 only, each once, all present.
pub fn decode_write_key_offer_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteKeyOfferV1, WriteAuthorizationRefusal> {
    strict(bytes, "write-key offer", 7, offer_field_limit)
}

/// Strict decode of a grant: tags 1-6 only, each once, all present.
pub fn decode_write_grant_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteGrantV1, WriteAuthorizationRefusal> {
    strict(bytes, "write grant", 6, grant_field_limit)
}

/// Strict decode of a write lock: tags 1-7 only, each once, all present.
pub fn decode_write_lock_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteLockV1, WriteAuthorizationRefusal> {
    strict(bytes, "write lock", 7, lock_field_limit)
}

/// Strict decode of an authorization: tags 1-2 only, each once, both present.
pub fn decode_write_authorization_wire(
    bytes: &[u8],
) -> Result<RelationshipWriteAuthorizationV1, WriteAuthorizationRefusal> {
    strict(bytes, "write authorization", 2, authorization_field_limit)
}

/// Strict decode of a write: tags 1-5 only, each once, all present.
pub fn decode_spool_write_wire(bytes: &[u8]) -> Result<SpoolWriteV1, WriteAuthorizationRefusal> {
    strict(bytes, "spool write", 5, spool_write_field_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_keypair, sphincs_sign};
    use prost::Message;

    type Refusal = WriteAuthorizationRefusal;

    /// A device as the lock sees it: its id, its genesis, its AK.
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

    const INSTANCE: [u8; 32] = [0x5A; 32];
    const ROUTE: [u8; 32] = [0xAD; 32];
    const MESSAGE_ID: [u8; 16] = [0x1D; 16];

    /// `sender`'s offer of `write_key` to `recipient` for `instance`.
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

    /// `recipient`'s authorization of `write_key` for `sender`: `lock`, bound
    /// by `binder`, signing the grant as `grant_signer`.
    fn authorization(
        instance: [u8; 32],
        recipient: &Device,
        sender: &Device,
        lock: &SphincsKeyPair,
        binder: &SphincsKeyPair,
        grant_signer: &SphincsKeyPair,
        write_key: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        let bound = WriteLock {
            relationship_instance_id: instance,
            recipient_genesis: recipient.genesis,
            recipient_device_id: recipient.id,
            authorized_sender_device_id: sender.id,
            lock_public_key: lock.public_key.clone(),
        };
        let lock_wire = bound.to_wire(sphincs_sign(&binder.secret_key, &bound.binding_target())?);
        let grant = WriteGrant::of_key(instance, write_key.to_vec());
        let grant_wire = grant.to_wire(sphincs_sign(
            &grant_signer.secret_key,
            &grant.signing_target(),
        )?);
        Ok(write_authorization_wire(&lock_wire, &grant_wire))
    }

    fn expect<'a>(
        instance: &'a [u8; 32],
        recipient: &'a Device,
        sender: &'a Device,
        write_key: &'a [u8],
    ) -> AuthorizationExpectation<'a> {
        AuthorizationExpectation {
            relationship_instance_id: instance,
            recipient_genesis: &recipient.genesis,
            recipient_device_id: &recipient.id,
            sender_device_id: &sender.id,
            write_public_key: write_key,
            recipient_ak: &recipient.ak.public_key,
        }
    }

    /// One write of `envelope` to the address of `route` under `message_id`,
    /// carrying `lock` and `grant_wire`, signed by `writer`; the address is
    /// `route` bound to `lock`.
    fn write(
        route: &[u8; 32],
        message_id: &[u8; 16],
        envelope: &[u8],
        lock: &[u8],
        grant_wire: Vec<u8>,
        writer: &SphincsKeyPair,
    ) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
        let address = crate::crypto::spool_address::locked_inbox_address_bytes(route, lock);
        let bytes = signed_spool_write(
            writer, lock, grant_wire, route, &address, message_id, envelope,
        )?;
        Ok((bytes, address))
    }

    #[test]
    fn keys_and_locks_are_one_per_instance_and_direction_and_come_back_from_the_master_seed(
    ) -> Result<(), DsmError> {
        let (s_a, s_b) = ([0xA5; 32], [0xB5; 32]);
        let (a, b) = ([0x0A; 32], [0x0B; 32]);
        let ab = derive_write_keypair(&s_a, &INSTANCE, &a, &b)?;
        let again = derive_write_keypair(&s_a, &INSTANCE, &a, &b)?;
        assert_eq!(
            (&ab.public_key, &ab.secret_key),
            (&again.public_key, &again.secret_key)
        );
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_b, &INSTANCE, &b, &a)?.public_key
        );
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_a, &INSTANCE, &b, &a)?.public_key
        );
        assert_ne!(
            ab.public_key,
            derive_write_keypair(&s_a, &[0x6B; 32], &a, &b)?.public_key
        );
        // A's lock over its inbox toward B is neither A's write key toward B
        // nor A's first-inbox key.
        let lock = derive_write_lock_keypair(&s_a, &INSTANCE, &a, &b)?;
        let first = derive_first_inbox_keypair(&s_a, &[0x11; 32], &[0x22; 32], &a, &b)?;
        assert_ne!(lock.public_key, ab.public_key);
        assert_ne!(first.public_key, ab.public_key);
        assert_ne!(first.public_key, lock.public_key);
        Ok(())
    }

    #[test]
    fn an_instance_is_its_relationship_and_its_establishing_tip() {
        let (rel, tip) = ([0x11; 32], [0x22; 32]);
        let id = relationship_instance_id(&rel, &tip);
        assert_eq!(id, relationship_instance_id(&rel, &tip));
        assert_ne!(id, relationship_instance_id(&rel, &[0x23; 32]));
        assert_ne!(id, relationship_instance_id(&[0x12; 32], &tip));
    }

    #[test]
    fn an_offer_binds_its_key_and_proves_possession() -> Result<(), DsmError> {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let (sent, wire) = offer(INSTANCE, &a, &b, &wk)?;
        let expected = OfferExpectation {
            relationship_instance_id: &INSTANCE,
            sender_device_id: &a.id,
            recipient_device_id: &b.id,
            sender_ak: &a.ak.public_key,
        };
        assert_eq!(verify_write_key_offer(&wire, &expected)?, sent);
        // Possession signed by the AK, not the key.
        let mut by_ak = wire.clone();
        by_ak.possession_signature = sphincs_sign(&a.ak.secret_key, &sent.possession_target())?;
        assert_eq!(
            verify_write_key_offer(&by_ak, &expected),
            Err(Refusal::PossessionSignature)
        );
        // An offer bound by another device's AK.
        let c = device(0x0C)?;
        let (_, by_c) = offer(INSTANCE, &c, &b, &wk)?;
        let mut by_c = by_c;
        by_c.sender_device_id = a.id.to_vec();
        assert_eq!(
            verify_write_key_offer(&by_c, &expected),
            Err(Refusal::BindingSignature)
        );
        // The AK offered as a write key.
        let (_, ak_offer) = offer(INSTANCE, &a, &b, &a.ak)?;
        assert_eq!(
            verify_write_key_offer(&ak_offer, &expected),
            Err(Refusal::WriteKeyIsTheSendersAk)
        );
        Ok(())
    }

    #[test]
    fn a_recipients_authorization_verifies_and_names_no_identity_to_a_node() -> Result<(), DsmError>
    {
        let (a, b) = (device(0x0A)?, device(0x0B)?);
        let (wk, lock) = (
            generate_keypair(WRITE_KEY_VARIANT)?,
            generate_keypair(WRITE_KEY_VARIANT)?,
        );
        let bytes = authorization(INSTANCE, &b, &a, &lock, &b.ak, &lock, &wk.public_key)?;
        let held = verify_write_authorization(&bytes, &expect(&INSTANCE, &b, &a, &wk.public_key))?;
        assert_eq!(held.lock.lock_public_key, lock.public_key);
        // The grant a node sees carries no genesis, device id or AK.
        let grant = decode_write_grant_wire(&held.grant_wire).map_err(DsmError::from)?;
        for secret in [&b.genesis[..], &b.id[..], &a.id[..], &b.ak.public_key[..]] {
            assert!(
                !grant
                    .encode_to_vec()
                    .windows(secret.len())
                    .any(|w| w == secret),
                "the grant carries an identity"
            );
        }
        Ok(())
    }

    #[test]
    fn a_forged_or_misdirected_authorization_fails() -> Result<(), DsmError> {
        let (a, b, c) = (device(0x0A)?, device(0x0B)?, device(0x0C)?);
        let (wk, lock) = (
            generate_keypair(WRITE_KEY_VARIANT)?,
            generate_keypair(WRITE_KEY_VARIANT)?,
        );
        let ok = expect(&INSTANCE, &b, &a, &wk.public_key);
        // The lock bound by another device's AK.
        let by_c = authorization(INSTANCE, &b, &a, &lock, &c.ak, &lock, &wk.public_key)?;
        assert_eq!(
            verify_write_authorization(&by_c, &ok),
            Err(Refusal::LockBindingSignature)
        );
        // The grant signed by a key other than the bound lock: the sender's
        // own key, a self-made grant.
        let self_made = authorization(INSTANCE, &b, &a, &lock, &b.ak, &wk, &wk.public_key)?;
        assert_eq!(
            verify_write_authorization(&self_made, &ok),
            Err(Refusal::GrantSignature)
        );
        // Another sender's key, another recipient, another instance.
        let other_key = generate_keypair(WRITE_KEY_VARIANT)?;
        let honest = authorization(INSTANCE, &b, &a, &lock, &b.ak, &lock, &wk.public_key)?;
        assert_eq!(
            verify_write_authorization(&honest, &expect(&INSTANCE, &b, &a, &other_key.public_key)),
            Err(Refusal::WrongWriteKey)
        );
        assert_eq!(
            verify_write_authorization(&honest, &expect(&INSTANCE, &b, &c, &wk.public_key)),
            Err(Refusal::WrongSender)
        );
        assert_eq!(
            verify_write_authorization(&honest, &expect(&INSTANCE, &c, &a, &wk.public_key)),
            Err(Refusal::WrongRecipientGenesis)
        );
        assert_eq!(
            verify_write_authorization(&honest, &expect(&[0x6B; 32], &b, &a, &wk.public_key)),
            Err(Refusal::WrongInstance)
        );
        // The AK used as the lock.
        let ak_lock = authorization(INSTANCE, &b, &a, &b.ak, &b.ak, &b.ak, &wk.public_key)?;
        assert_eq!(
            verify_write_authorization(&ak_lock, &ok),
            Err(Refusal::LockIsTheRecipientsAk)
        );
        Ok(())
    }

    #[test]
    fn a_grant_from_one_instance_is_not_reused_in_another() -> Result<(), DsmError> {
        let lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let old = WriteGrant::of_key([0x01; 32], wk.public_key.clone());
        let signature = sphincs_sign(&lock.secret_key, &old.signing_target())?;
        let mut moved = old.to_wire(signature.clone());
        moved.relationship_instance_id = [0x02; 32].to_vec();
        assert_eq!(
            verify_write_grant_signature(&moved, &lock.public_key),
            Err(Refusal::GrantIdMismatch)
        );
        let rehashed = WriteGrant::of_key([0x02; 32], wk.public_key.clone()).to_wire(signature);
        assert_eq!(
            verify_write_grant_signature(&rehashed, &lock.public_key),
            Err(Refusal::GrantSignature)
        );
        Ok(())
    }

    #[test]
    fn issuing_the_same_grant_again_issues_the_same_bytes() -> Result<(), DsmError> {
        let lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let grant = WriteGrant::of_key(INSTANCE, vec![0x77; WRITE_PUBLIC_KEY_LEN]);
        let once = grant.to_wire(sphincs_sign(&lock.secret_key, &grant.signing_target())?);
        let twice = grant.to_wire(sphincs_sign(&lock.secret_key, &grant.signing_target())?);
        assert_eq!(once.encode_to_vec(), twice.encode_to_vec());
        Ok(())
    }

    #[test]
    fn a_write_verifies_only_for_its_own_address_id_and_bytes() -> Result<(), DsmError> {
        let lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let wk = generate_keypair(WRITE_KEY_VARIANT)?;
        let grant = WriteGrant::of_key(INSTANCE, wk.public_key.clone());
        let grant_wire = grant
            .to_wire(sphincs_sign(&lock.secret_key, &grant.signing_target())?)
            .encode_to_vec();
        let (bytes, address) = write(
            &ROUTE,
            &MESSAGE_ID,
            b"sealed",
            &lock.public_key,
            grant_wire.clone(),
            &wk,
        )?;
        let held = verify_spool_write(&bytes, &address, &MESSAGE_ID)?;
        assert_eq!(held.lock_public_key, lock.public_key);
        assert_eq!(held.envelope, b"sealed".to_vec());
        assert_eq!(held.inbox, InboxKind::Locked);
        // The same write presented at another address, or under another id.
        assert_eq!(
            verify_spool_write(&bytes, &[0xAE; 32], &MESSAGE_ID),
            Err(Refusal::WrongAddress)
        );
        assert_eq!(
            verify_spool_write(&bytes, &address, &[0x1E; 16]),
            Err(Refusal::WriteSignature)
        );
        // Its signature over other bytes.
        let mut swapped = decode_spool_write_wire(&bytes).map_err(DsmError::from)?;
        swapped.envelope = b"other".to_vec();
        assert_eq!(
            verify_spool_write(&swapped.encode_to_vec(), &address, &MESSAGE_ID),
            Err(Refusal::WriteSignature)
        );
        // Signed by a key the lock never granted.
        let stranger = generate_keypair(WRITE_KEY_VARIANT)?;
        let (unsigned, _) = write(
            &ROUTE,
            &MESSAGE_ID,
            b"sealed",
            &lock.public_key,
            grant_wire.clone(),
            &stranger,
        )?;
        assert_eq!(
            verify_spool_write(&unsigned, &address, &MESSAGE_ID),
            Err(Refusal::WriteSignature)
        );
        // A grant another lock signed, carried under this lock.
        let other_lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let foreign = grant
            .to_wire(sphincs_sign(
                &other_lock.secret_key,
                &grant.signing_target(),
            )?)
            .encode_to_vec();
        let (carried, _) = write(
            &ROUTE,
            &MESSAGE_ID,
            b"sealed",
            &lock.public_key,
            foreign,
            &wk,
        )?;
        assert_eq!(
            verify_spool_write(&carried, &address, &MESSAGE_ID),
            Err(Refusal::GrantSignature)
        );
        Ok(())
    }

    /// A locked address is its route bound to the recipient's lock: a
    /// stranger's own lock, however well it grants and signs, yields another
    /// address, so its write is refused at this one, by derivation alone. A
    /// write presenting the route's open address never fits a locked one.
    #[test]
    fn a_locked_address_takes_only_its_own_lock() -> Result<(), DsmError> {
        let lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let locked =
            crate::crypto::spool_address::locked_inbox_address_bytes(&ROUTE, &lock.public_key);
        let stranger = generate_keypair(WRITE_KEY_VARIANT)?;
        let own =
            self_granted_spool_write(&stranger, &INSTANCE, &ROUTE, &locked, &MESSAGE_ID, b"junk")?;
        assert_eq!(
            verify_spool_write(&own, &locked, &MESSAGE_ID),
            Err(Refusal::WrongAddress)
        );
        // The open address of the same route takes a self-granted key: the
        // relationship's first inbox.
        let open = crate::crypto::spool_address::open_inbox_address_bytes(&ROUTE);
        let first =
            self_granted_spool_write(&stranger, &INSTANCE, &ROUTE, &open, &MESSAGE_ID, b"first")?;
        assert_eq!(
            verify_spool_write(&first, &open, &MESSAGE_ID)?.inbox,
            InboxKind::Open
        );
        Ok(())
    }

    #[test]
    fn the_wire_forms_are_strict() -> Result<(), DsmError> {
        let lock = generate_keypair(WRITE_KEY_VARIANT)?;
        let grant = WriteGrant::of_key(INSTANCE, lock.public_key.clone());
        let grant_wire = grant.to_wire(sphincs_sign(&lock.secret_key, &grant.signing_target())?);
        let bytes = grant_wire.encode_to_vec();
        assert_eq!(decode_write_grant_wire(&bytes)?, grant_wire);
        let mut extra = bytes.clone();
        extra.extend_from_slice(&[0x3A, 0x01, 0x00]); // field 7, one byte
        assert!(matches!(
            decode_write_grant_wire(&extra),
            Err(Refusal::Wire(_))
        ));
        let mut short = grant_wire.clone();
        short.grant_id.clear();
        assert!(matches!(
            decode_write_grant_wire(&short.encode_to_vec()),
            Err(Refusal::Wire(_))
        ));
        let mut wider = grant.clone();
        wider.permitted_scope = 2;
        let signed = wider.to_wire(sphincs_sign(&lock.secret_key, &wider.signing_target())?);
        assert_eq!(
            verify_write_grant_signature(&signed, &lock.public_key),
            Err(Refusal::Scope(2))
        );
        assert!(matches!(
            decode_spool_write_wire(b"\x0a\x01"),
            Err(Refusal::Wire(_))
        ));
        Ok(())
    }
}
