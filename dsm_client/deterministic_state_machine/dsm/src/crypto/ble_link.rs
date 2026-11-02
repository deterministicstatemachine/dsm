// SPDX-License-Identifier: MIT OR Apache-2.0

//! The session two contacts run on one BLE link (DSM Amendment A27, SA-35).
//!
//! A passive observer in radio range learns no permanent identifier, no
//! amount, no salt and no other transfer data: after the handshake every byte
//! a wallet writes on the link is a sealed record, and the handshake itself
//! carries no identity in the clear.
//!
//! The handshake is a post-quantum KK pattern over the ML-KEM-768 keys each
//! contact already pinned from the other's AK-signed directory entry (DSM
//! Amendment A3), so no signature crosses the link:
//!
//! 1. **Hello**, initiator to responder: an ephemeral ML-KEM public key `e`, a
//!    ciphertext `ct₁` to the responder's pinned key, and the initiator's
//!    device id, genesis and a fresh nonce `n_I`, sealed under a key from
//!    `ss₁` and a transcript that names the responder's device id. Only the
//!    responder it was meant for opens it.
//! 2. **Reply**, responder to initiator: `ct₂` to the initiator's pinned key
//!    and `ct₃` to `e`, and a fresh nonce `n_R` sealed under a key chained
//!    from `ss₁ ‖ ss₂ ‖ ss₃`. Only the holder of the responder's key could
//!    seal it.
//! 3. **Confirm**, initiator to responder: nothing, sealed under the next key
//!    in the chain, whose transcript names `n_R`. Only the holder of the
//!    initiator's key could seal it, and only for this Reply.
//!
//! The chain then gives one key per direction and a session id. `e` gives the
//! session forward secrecy: the static keys re-derive from the wallet seed.
//! A responder that cannot open a Hello says so with a Decline, so an
//! initiator that does not know which contact answered tries the next one.
//!
//! A record is `counter ‖ XChaCha20-Poly1305(padded plaintext)`, its nonce
//! the direction, the counter and the session id, its associated data the
//! session id and the counter. A record is taken only with a counter past the
//! last one taken, so a replayed or reordered record never opens; gaps are
//! taken, since the radio drops writes. Every record is [`RECORD_LEN`] bytes,
//! one BLE notification: its plaintext is padded to
//! [`RECORD_PLAINTEXT_LEN`], so a record's length says nothing about what it
//! carries.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::common::domain_tags::{TAG_DSM_BLE_LINK_KEY, TAG_DSM_BLE_LINK_TRANSCRIPT};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::kyber::{generate_kyber_keypair, kyber_decapsulate, kyber_encapsulate};
use crate::crypto::rng::generate_secure_random;

type D32 = [u8; 32];

/// An ML-KEM-768 public key.
pub const KEM_PUBLIC_KEY_LEN: usize = 1184;
/// An ML-KEM-768 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
/// The Poly1305 tag a sealed message carries.
const TAG_LEN: usize = 16;
/// A record's counter.
const COUNTER_LEN: usize = 8;
/// Every record's length: with its one-byte radio tag, one notification at
/// the 512-byte ATT MTU this transport negotiates, which carries 509 bytes.
pub const RECORD_LEN: usize = 500;
/// Every record's padded plaintext: what is left of [`RECORD_LEN`] after the
/// counter and the tag.
pub const RECORD_PLAINTEXT_LEN: usize = RECORD_LEN - COUNTER_LEN - TAG_LEN;
/// The most a record carries: its plaintext, then the `0x80` that starts the
/// padding.
pub const RECORD_CAPACITY: usize = RECORD_PLAINTEXT_LEN - 1;

/// The sealed body of a Hello: device id, genesis, nonce.
const HELLO_SEALED_LEN: usize = 32 + 32 + 32 + TAG_LEN;
/// The sealed body of a Reply or a Confirm: one nonce.
const NONCE_SEALED_LEN: usize = 32 + TAG_LEN;

/// A wallet's identity on a link: what its contacts pinned it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkIdentity {
    pub device_id: D32,
    pub genesis: D32,
}

/// Why a handshake message or a record is not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The bytes are not the message they were read as.
    Malformed(String),
    /// The cipher refused to seal.
    Seal(String),
    /// An ML-KEM operation failed.
    Kem(String),
    /// The randomness source failed.
    Entropy(String),
    /// The Hello opened, and names a device that is not a contact of this
    /// wallet, or names a contact under another genesis.
    NotAContact,
    /// A Reply, a Confirm or a record does not open under what this side
    /// holds: it was not made by the contact this handshake is with.
    DoesNotOpen(String),
    /// A record's counter is not past the last one taken.
    Replayed { counter: u64, last: u64 },
    /// This side has sealed every counter.
    CounterExhausted,
    /// More plaintext than one record carries.
    TooLong { len: usize },
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "not a {what}"),
            Self::Seal(e) => write!(f, "sealing: {e}"),
            Self::Kem(e) => write!(f, "ML-KEM: {e}"),
            Self::Entropy(e) => write!(f, "randomness: {e}"),
            Self::NotAContact => write!(f, "the Hello names no contact of this wallet"),
            Self::DoesNotOpen(e) => {
                write!(f, "the message does not open under this handshake: {e}")
            }
            Self::Replayed { counter, last } => {
                write!(
                    f,
                    "record {counter} is not past the last record taken, {last}"
                )
            }
            Self::CounterExhausted => write!(f, "every record counter is used"),
            Self::TooLong { len } => write!(
                f,
                "{len} bytes do not fit one record, which carries {RECORD_CAPACITY}"
            ),
        }
    }
}

impl std::error::Error for LinkError {}

fn kem(e: impl core::fmt::Display) -> LinkError {
    LinkError::Kem(e.to_string())
}

fn d32_of(bytes: &[u8]) -> Result<D32, LinkError> {
    <D32>::try_from(bytes).map_err(|e| LinkError::Malformed(format!("32-byte value: {e}")))
}

fn seal_refused(e: chacha20poly1305::aead::Error) -> LinkError {
    LinkError::Seal(e.to_string())
}

fn does_not_open(e: chacha20poly1305::aead::Error) -> LinkError {
    LinkError::DoesNotOpen(e.to_string())
}

fn fresh_nonce() -> Result<D32, LinkError> {
    let bytes = generate_secure_random(32).map_err(|e| LinkError::Entropy(e.to_string()))?;
    d32_of(&bytes)
}

/// `H(DSM/ble-link/transcript/v1; label ‖ parts…)`.
fn transcript(label: &[u8], parts: &[&[u8]]) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_BLE_LINK_TRANSCRIPT);
    h.update(label);
    for part in parts {
        h.update(part);
    }
    *h.finalize().as_bytes()
}

/// `H(DSM/ble-link/key/v1; label ‖ transcript ‖ secret)`.
fn key(label: &[u8], transcript: &D32, secret: &[u8]) -> Zeroizing<D32> {
    let mut h = dsm_domain_hasher(TAG_DSM_BLE_LINK_KEY);
    h.update(label);
    h.update(transcript);
    h.update(secret);
    Zeroizing::new(*h.finalize().as_bytes())
}

/// Seal `plaintext` under `key`, its nonce and associated data the
/// transcript: each handshake key seals exactly one message.
fn seal_once(key: &D32, transcript: &D32, plaintext: &[u8]) -> Result<Vec<u8>, LinkError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&transcript[..24]),
            Payload {
                msg: plaintext,
                aad: transcript,
            },
        )
        .map_err(seal_refused)
}

fn open_once(key: &D32, transcript: &D32, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, LinkError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&transcript[..24]),
            Payload {
                msg: sealed,
                aad: transcript,
            },
        )
        .map(Zeroizing::new)
        .map_err(does_not_open)
}

// ── The three messages and the decline ───────────────────────────────────────

/// The initiator's first message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sealed: Vec<u8>,
}

impl Hello {
    pub const LEN: usize = KEM_PUBLIC_KEY_LEN + KEM_CIPHERTEXT_LEN + HELLO_SEALED_LEN;

    pub fn encode(&self) -> Vec<u8> {
        [
            self.ephemeral_public_key.as_slice(),
            &self.ciphertext,
            &self.sealed,
        ]
        .concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() != Self::LEN {
            return Err(LinkError::Malformed(format!(
                "Hello of {} bytes",
                bytes.len()
            )));
        }
        let (e, rest) = bytes.split_at(KEM_PUBLIC_KEY_LEN);
        let (ct, sealed) = rest.split_at(KEM_CIPHERTEXT_LEN);
        Ok(Self {
            ephemeral_public_key: e.to_vec(),
            ciphertext: ct.to_vec(),
            sealed: sealed.to_vec(),
        })
    }
}

/// The responder's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub to_initiator: Vec<u8>,
    pub to_ephemeral: Vec<u8>,
    pub sealed: Vec<u8>,
}

impl Reply {
    pub const LEN: usize = KEM_CIPHERTEXT_LEN + KEM_CIPHERTEXT_LEN + NONCE_SEALED_LEN;

    pub fn encode(&self) -> Vec<u8> {
        [
            self.to_initiator.as_slice(),
            &self.to_ephemeral,
            &self.sealed,
        ]
        .concat()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() != Self::LEN {
            return Err(LinkError::Malformed(format!(
                "Reply of {} bytes",
                bytes.len()
            )));
        }
        let (ct2, rest) = bytes.split_at(KEM_CIPHERTEXT_LEN);
        let (ct3, sealed) = rest.split_at(KEM_CIPHERTEXT_LEN);
        Ok(Self {
            to_initiator: ct2.to_vec(),
            to_ephemeral: ct3.to_vec(),
            sealed: sealed.to_vec(),
        })
    }
}

/// The initiator's proof that it holds its key: an empty message sealed
/// under the key that the chain and the Reply's nonce derive, so its opening
/// is the whole check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub sealed: Vec<u8>,
}

impl Confirm {
    pub const LEN: usize = TAG_LEN;

    pub fn encode(&self) -> Vec<u8> {
        self.sealed.clone()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LinkError> {
        if bytes.len() != Self::LEN {
            return Err(LinkError::Malformed(format!(
                "Confirm of {} bytes",
                bytes.len()
            )));
        }
        Ok(Self {
            sealed: bytes.to_vec(),
        })
    }
}

// ── The handshake ────────────────────────────────────────────────────────────

/// An initiator between its Hello and the Reply.
pub struct Initiating {
    own: LinkIdentity,
    peer: LinkIdentity,
    ephemeral_secret: Zeroizing<Vec<u8>>,
    ss1: Zeroizing<Vec<u8>>,
    hello_transcript: D32,
    initiator_nonce: D32,
}

impl Initiating {
    /// The contact this handshake is with.
    pub fn peer(&self) -> &LinkIdentity {
        &self.peer
    }
}

/// Start a handshake from `own` with `peer`, whose pinned ML-KEM key is
/// `peer_kem_public_key`.
pub fn initiate(
    own: &LinkIdentity,
    peer: &LinkIdentity,
    peer_kem_public_key: &[u8],
) -> Result<(Hello, Initiating), LinkError> {
    let ephemeral = generate_kyber_keypair().map_err(kem)?;
    let (ss1, ct1) = kyber_encapsulate(peer_kem_public_key).map_err(kem)?;
    let ss1 = Zeroizing::new(ss1);
    let initiator_nonce = fresh_nonce()?;
    let hello_transcript = transcript(b"hello", &[&peer.device_id, &ephemeral.public_key, &ct1]);
    let k1 = key(b"hello", &hello_transcript, &ss1);
    let body = Zeroizing::new([own.device_id, own.genesis, initiator_nonce].concat());
    let sealed = seal_once(&k1, &hello_transcript, &body)?;
    Ok((
        Hello {
            ephemeral_public_key: ephemeral.public_key.clone(),
            ciphertext: ct1,
            sealed,
        },
        Initiating {
            own: *own,
            peer: *peer,
            ephemeral_secret: Zeroizing::new(ephemeral.secret_key.clone()),
            ss1,
            hello_transcript,
            initiator_nonce,
        },
    ))
}

/// A responder between its Reply and the Confirm.
pub struct Responding {
    peer: LinkIdentity,
    chain: Zeroizing<D32>,
    reply_transcript: D32,
    responder_nonce: D32,
}

impl Responding {
    /// The contact this handshake is with.
    pub fn peer(&self) -> &LinkIdentity {
        &self.peer
    }
}

/// What a responder makes of a Hello.
pub enum Answer {
    /// The Hello was not sealed for this wallet: answer with a Decline.
    NotForMe,
    /// The Hello names a contact: send the Reply and wait for the Confirm.
    Reply(Reply, Box<Responding>),
}

/// The reply transcript both sides compute from the Hello's transcript, the
/// initiator's identity and nonce, and the Reply's two ciphertexts.
fn reply_transcript(
    hello_transcript: &D32,
    initiator: &LinkIdentity,
    initiator_nonce: &D32,
    ct2: &[u8],
    ct3: &[u8],
) -> D32 {
    transcript(
        b"reply",
        &[
            hello_transcript,
            &initiator.device_id,
            &initiator.genesis,
            initiator_nonce,
            ct2,
            ct3,
        ],
    )
}

/// The chain key from the three shared secrets.
fn chain_key(reply_transcript: &D32, ss1: &[u8], ss2: &[u8], ss3: &[u8]) -> Zeroizing<D32> {
    let secrets = Zeroizing::new([ss1, ss2, ss3].concat());
    key(b"chain", reply_transcript, &secrets)
}

/// Answer `hello` as `own`, holding `own_kem_secret_key`. `contact` gives the
/// genesis and pinned ML-KEM key of a contact by device id, or `None` for a
/// device that is not one.
pub fn respond(
    hello: &Hello,
    own: &LinkIdentity,
    own_kem_secret_key: &[u8],
    contact: impl Fn(&D32) -> Option<(D32, Vec<u8>)>,
) -> Result<Answer, LinkError> {
    let ss1 =
        Zeroizing::new(kyber_decapsulate(own_kem_secret_key, &hello.ciphertext).map_err(kem)?);
    let hello_transcript = transcript(
        b"hello",
        &[
            &own.device_id,
            &hello.ephemeral_public_key,
            &hello.ciphertext,
        ],
    );
    let k1 = key(b"hello", &hello_transcript, &ss1);
    let body = match open_once(&k1, &hello_transcript, &hello.sealed) {
        Ok(body) => body,
        Err(LinkError::DoesNotOpen(..)) => return Ok(Answer::NotForMe),
        Err(other) => return Err(other),
    };
    let initiator = LinkIdentity {
        device_id: d32_of(&body[..32])?,
        genesis: d32_of(&body[32..64])?,
    };
    let initiator_nonce = d32_of(&body[64..96])?;
    let Some((pinned_genesis, pinned_kem_key)) = contact(&initiator.device_id) else {
        return Err(LinkError::NotAContact);
    };
    if pinned_genesis != initiator.genesis {
        return Err(LinkError::NotAContact);
    }
    let (ss2, ct2) = kyber_encapsulate(&pinned_kem_key).map_err(kem)?;
    let ss2 = Zeroizing::new(ss2);
    let (ss3, ct3) = kyber_encapsulate(&hello.ephemeral_public_key).map_err(kem)?;
    let ss3 = Zeroizing::new(ss3);
    let reply_transcript =
        reply_transcript(&hello_transcript, &initiator, &initiator_nonce, &ct2, &ct3);
    let chain = chain_key(&reply_transcript, &ss1, &ss2, &ss3);
    let responder_nonce = fresh_nonce()?;
    let k2 = key(b"reply", &reply_transcript, chain.as_slice());
    let sealed = seal_once(&k2, &reply_transcript, &responder_nonce)?;
    Ok(Answer::Reply(
        Reply {
            to_initiator: ct2,
            to_ephemeral: ct3,
            sealed,
        },
        Box::new(Responding {
            peer: initiator,
            chain,
            reply_transcript,
            responder_nonce,
        }),
    ))
}

/// The confirm transcript both sides compute from the reply transcript and
/// the responder's nonce.
fn confirm_transcript(reply_transcript: &D32, responder_nonce: &D32) -> D32 {
    transcript(b"confirm", &[reply_transcript, responder_nonce])
}

/// Take `reply` as the initiator, holding `own_kem_secret_key`: the Confirm
/// to send, and the session.
pub fn complete(
    initiating: Initiating,
    reply: &Reply,
    own_kem_secret_key: &[u8],
) -> Result<(Confirm, LinkSession), LinkError> {
    let ss2 =
        Zeroizing::new(kyber_decapsulate(own_kem_secret_key, &reply.to_initiator).map_err(kem)?);
    let ss3 = Zeroizing::new(
        kyber_decapsulate(&initiating.ephemeral_secret, &reply.to_ephemeral).map_err(kem)?,
    );
    let reply_transcript = reply_transcript(
        &initiating.hello_transcript,
        &initiating.own,
        &initiating.initiator_nonce,
        &reply.to_initiator,
        &reply.to_ephemeral,
    );
    let chain = chain_key(&reply_transcript, &initiating.ss1, &ss2, &ss3);
    let k2 = key(b"reply", &reply_transcript, chain.as_slice());
    let responder_nonce = d32_of(&open_once(&k2, &reply_transcript, &reply.sealed)?)?;
    let confirm_transcript = confirm_transcript(&reply_transcript, &responder_nonce);
    let k3 = key(b"confirm", &confirm_transcript, chain.as_slice());
    let sealed = seal_once(&k3, &confirm_transcript, &[])?;
    Ok((
        Confirm { sealed },
        LinkSession::new(
            &chain,
            &confirm_transcript,
            Role::Initiator,
            initiating.peer,
        ),
    ))
}

/// Take `confirm` as the responder: the session.
pub fn finish(responding: Responding, confirm: &Confirm) -> Result<LinkSession, LinkError> {
    let confirm_transcript =
        confirm_transcript(&responding.reply_transcript, &responding.responder_nonce);
    let k3 = key(b"confirm", &confirm_transcript, responding.chain.as_slice());
    open_once(&k3, &confirm_transcript, &confirm.sealed)?;
    Ok(LinkSession::new(
        &responding.chain,
        &confirm_transcript,
        Role::Responder,
        responding.peer,
    ))
}

// ── The session ──────────────────────────────────────────────────────────────

/// Which side of the handshake a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn direction(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// One link's session: a key per direction, the session id, and the
/// counters.
pub struct LinkSession {
    role: Role,
    peer: LinkIdentity,
    send_key: Zeroizing<D32>,
    receive_key: Zeroizing<D32>,
    session_id: D32,
    next_send: u64,
    last_received: Option<u64>,
}

impl LinkSession {
    fn new(chain: &D32, confirm_transcript: &D32, role: Role, peer: LinkIdentity) -> Self {
        let initiator_to_responder = key(b"initiator-to-responder", confirm_transcript, chain);
        let responder_to_initiator = key(b"responder-to-initiator", confirm_transcript, chain);
        let session_id = *key(b"session-id", confirm_transcript, chain);
        let (send_key, receive_key) = match role {
            Role::Initiator => (initiator_to_responder, responder_to_initiator),
            Role::Responder => (responder_to_initiator, initiator_to_responder),
        };
        Self {
            role,
            peer,
            send_key,
            receive_key,
            session_id,
            next_send: 0,
            last_received: None,
        }
    }

    /// The contact this session is with, as the handshake authenticated it.
    pub fn peer(&self) -> &LinkIdentity {
        &self.peer
    }

    pub fn role(&self) -> Role {
        self.role
    }

    fn nonce(&self, direction: Role, counter: u64) -> XNonce {
        let mut nonce = [direction.direction(); 24];
        nonce[1..9].copy_from_slice(&counter.to_be_bytes());
        nonce[9..24].copy_from_slice(&self.session_id[..15]);
        *XNonce::from_slice(&nonce)
    }

    fn aad(&self, counter: u64) -> Vec<u8> {
        [&self.session_id[..], &counter.to_be_bytes()].concat()
    }

    /// Seal `plaintext` as the next record this side sends.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, LinkError> {
        if plaintext.len() > RECORD_CAPACITY {
            return Err(LinkError::TooLong {
                len: plaintext.len(),
            });
        }
        let counter = self.next_send;
        self.next_send = counter.checked_add(1).ok_or(LinkError::CounterExhausted)?;
        let mut padded = Zeroizing::new(Vec::with_capacity(RECORD_PLAINTEXT_LEN));
        padded.extend_from_slice(plaintext);
        padded.push(0x80);
        padded.resize(RECORD_PLAINTEXT_LEN, 0x00);
        let sealed = XChaCha20Poly1305::new((&*self.send_key).into())
            .encrypt(
                &self.nonce(self.role, counter),
                Payload {
                    msg: &padded,
                    aad: &self.aad(counter),
                },
            )
            .map_err(seal_refused)?;
        Ok([&counter.to_be_bytes()[..], &sealed].concat())
    }

    /// Open `record`, the next record the other side sent: refused unless
    /// its counter is past the last one taken.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, LinkError> {
        if record.len() != RECORD_LEN {
            return Err(LinkError::Malformed(format!(
                "record of {} bytes",
                record.len()
            )));
        }
        let (counter, sealed) = record.split_at(COUNTER_LEN);
        let counter = u64::from_be_bytes(
            <[u8; COUNTER_LEN]>::try_from(counter)
                .map_err(|e| LinkError::Malformed(format!("record counter: {e}")))?,
        );
        if let Some(last) = self.last_received {
            if counter <= last {
                return Err(LinkError::Replayed { counter, last });
            }
        }
        let mut padded = XChaCha20Poly1305::new((&*self.receive_key).into())
            .decrypt(
                &self.nonce(self.role.other(), counter),
                Payload {
                    msg: sealed,
                    aad: &self.aad(counter),
                },
            )
            .map_err(does_not_open)?;
        let end = padded
            .iter()
            .rposition(|&b| b != 0x00)
            .filter(|&at| padded[at] == 0x80)
            .ok_or_else(|| LinkError::Malformed("padded record".into()))?;
        let plaintext = padded[..end].to_vec();
        padded.zeroize();
        self.last_received = Some(counter);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
