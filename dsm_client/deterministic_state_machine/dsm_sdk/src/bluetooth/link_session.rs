// SPDX-License-Identifier: MIT OR Apache-2.0

//! The radio's session layer (DSM Amendment A27, SA-35).
//!
//! Every byte this wallet writes on a BLE link, and every byte it takes from
//! one, is either a fragment of the link handshake or a sealed record of the
//! link's session (`dsm::crypto::ble_link`). A passive observer in range sees
//! random-looking handshake messages and fixed-size records: no device id, no
//! genesis, no amount, no salt.
//!
//! - **Radio bytes.** `0x05 ‖ kind ‖ index ‖ total ‖ data` is a handshake
//!   fragment (kind 1 Hello, 2 Reply, 3 Confirm, 4 Decline); `0x06 ‖ record`
//!   is a sealed record. Nothing else is taken. Neither tag can begin a
//!   `BleChunk`, whose first byte is a protobuf field key.
//! - **Roles.** The GATT client initiates, trying its target contact first
//!   and then every other contact with a pinned ML-KEM key, one Hello each; a
//!   Decline moves it to the next. The GATT server answers.
//! - **Pairing.** The handshake is the pairing. The server takes the
//!   client's Confirm, which proves the client holds the session keys, and
//!   answers with a sealed ready record; the client takes that record, which
//!   proves the server took the Confirm. Each side completes pairing at that
//!   point and never before, as each side did at the old protocol's third
//!   phase.
//! - **Reconnection.** A session lives in memory for one link, keyed by the
//!   link's address and this wallet's role on it, and is dropped when the
//!   link closes. Every connection runs the handshake again; a record sealed
//!   on one link never opens on another.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

use dsm::crypto::ble_link::{
    complete, finish, initiate, respond, Answer, Confirm, Hello, Initiating, LinkError,
    LinkIdentity, LinkSession, Reply, Responding,
};
use dsm::types::error::DsmError;
use zeroize::Zeroizing;

type D32 = [u8; 32];

/// The first byte of a handshake fragment.
pub const HANDSHAKE: u8 = 0x05;
/// The first byte of a sealed record.
pub const RECORD: u8 = 0x06;
/// The plaintext of the server's first record: it took the Confirm.
const READY: u8 = 0x07;
/// The data one handshake fragment carries.
const FRAGMENT_DATA: usize = 400;
/// The most fragments a handshake message takes: a Hello, the longest, takes
/// six.
const MAX_FRAGMENTS: usize = 8;

/// This wallet's side of a GATT link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GattRole {
    /// It connected: it initiates the handshake.
    Client,
    /// It was connected to: it answers.
    Server,
}

impl GattRole {
    /// The role as the platform names it across the JNI boundary.
    pub fn from_wire(value: i32) -> Result<Self, DsmError> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Server),
            other => Err(DsmError::invalid_operation(format!(
                "GATT role {other} is neither client (1) nor server (2)"
            ))),
        }
    }

    pub fn to_wire(self) -> i32 {
        match self {
            Self::Client => 1,
            Self::Server => 2,
        }
    }
}

/// One BLE link: where it is, and which side of it this wallet is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    pub address: String,
    pub role: GattRole,
}

/// A contact a link can be with, as this wallet pinned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub identity: LinkIdentity,
    pub kem_public_key: Vec<u8>,
}

/// What a handshake needs of this wallet: its identity, its ML-KEM secret
/// key, and its contacts' pinned keys.
pub trait LinkKeys {
    fn own(&self) -> Result<LinkIdentity, DsmError>;
    fn own_kem_secret(&self) -> Result<Zeroizing<Vec<u8>>, DsmError>;
    fn contact(&self, device_id: &D32) -> Result<Option<Contact>, DsmError>;
    fn contacts(&self) -> Result<Vec<Contact>, DsmError>;
}

/// The wallet's own keys and contacts, from its store. Fails closed while
/// the wallet is locked.
pub struct WalletKeys;

fn d32(bytes: &[u8], what: &str) -> Result<D32, DsmError> {
    <D32>::try_from(bytes)
        .map_err(|e| DsmError::invalid_operation(format!("{what} is not 32 bytes: {e}")))
}

/// A stored contact, when it pinned an ML-KEM key: one this wallet can run a
/// handshake with.
fn contact_of(
    record: &crate::storage::client_db::ContactRecord,
) -> Result<Option<Contact>, DsmError> {
    if record.kyber_public_key.len() != dsm::crypto::ble_link::KEM_PUBLIC_KEY_LEN {
        return Ok(None);
    }
    Ok(Some(Contact {
        identity: LinkIdentity {
            device_id: d32(&record.device_id, "a contact's device id")?,
            genesis: d32(&record.genesis_hash, "a contact's genesis")?,
        },
        kem_public_key: record.kyber_public_key.clone(),
    }))
}

impl LinkKeys for WalletKeys {
    fn own(&self) -> Result<LinkIdentity, DsmError> {
        let device_id = crate::sdk::app_state::AppState::get_device_id()
            .ok_or_else(|| DsmError::invalid_operation("this device's id is not set"))?;
        let genesis = crate::sdk::app_state::AppState::get_genesis_hash()
            .ok_or_else(|| DsmError::invalid_operation("this device's genesis is not set"))?;
        Ok(LinkIdentity {
            device_id: d32(&device_id, "this device's id")?,
            genesis: d32(&genesis, "this device's genesis")?,
        })
    }

    fn own_kem_secret(&self) -> Result<Zeroizing<Vec<u8>>, DsmError> {
        crate::sdk::b0x_sdk::local_kyber_secret()
    }

    fn contact(&self, device_id: &D32) -> Result<Option<Contact>, DsmError> {
        let record = crate::storage::client_db::get_contact_by_device_id(device_id)
            .map_err(|e| DsmError::storage(format!("contact: {e}"), None::<std::io::Error>))?;
        match record {
            Some(record) => contact_of(&record),
            None => Ok(None),
        }
    }

    fn contacts(&self) -> Result<Vec<Contact>, DsmError> {
        let records = crate::storage::client_db::get_all_contacts()
            .map_err(|e| DsmError::storage(format!("contacts: {e}"), None::<std::io::Error>))?;
        let mut contacts = Vec::with_capacity(records.len());
        for record in &records {
            if let Some(contact) = contact_of(record)? {
                contacts.push(contact);
            }
        }
        Ok(contacts)
    }
}

/// The kinds of handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Hello = 1,
    Reply = 2,
    Confirm = 3,
    Decline = 4,
}

impl Kind {
    fn of(byte: u8) -> Result<Self, DsmError> {
        match byte {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Reply),
            3 => Ok(Self::Confirm),
            4 => Ok(Self::Decline),
            other => Err(DsmError::invalid_operation(format!(
                "handshake kind {other} is not Hello, Reply, Confirm or Decline"
            ))),
        }
    }
}

/// `message` as radio fragments. An empty message, a Decline, is one empty
/// fragment.
fn fragments(kind: Kind, message: &[u8]) -> Result<Vec<Vec<u8>>, DsmError> {
    let mut parts: Vec<&[u8]> = message.chunks(FRAGMENT_DATA).collect();
    if parts.is_empty() {
        parts.push(&[]);
    }
    if parts.len() > MAX_FRAGMENTS {
        return Err(DsmError::invalid_operation(format!(
            "a handshake message of {} bytes is too long to fragment",
            message.len()
        )));
    }
    let total = u8::try_from(parts.len())
        .map_err(|e| DsmError::invalid_operation(format!("a handshake fragment count: {e}")))?;
    Ok(parts
        .iter()
        .enumerate()
        .map(|(index, data)| [&[HANDSHAKE, kind as u8, index as u8, total][..], data].concat())
        .collect())
}

/// A handshake message arriving in fragments.
#[derive(Default)]
struct Fragments {
    kind: Option<u8>,
    parts: Vec<Option<Vec<u8>>>,
}

impl Fragments {
    /// Take one fragment: the whole message once its last part arrives.
    fn take(&mut self, fragment: &[u8]) -> Result<Option<(Kind, Vec<u8>)>, DsmError> {
        let [kind, index, total, data @ ..] = fragment else {
            return Err(DsmError::invalid_operation(
                "a handshake fragment shorter than its header",
            ));
        };
        let (index, total) = (usize::from(*index), usize::from(*total));
        if total == 0 || total > MAX_FRAGMENTS || index >= total || data.len() > FRAGMENT_DATA {
            return Err(DsmError::invalid_operation(format!(
                "handshake fragment {index} of {total} with {} bytes",
                data.len()
            )));
        }
        if self.kind != Some(*kind) || self.parts.len() != total {
            self.kind = Some(*kind);
            self.parts = vec![None; total];
        }
        self.parts[index] = Some(data.to_vec());
        if self.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let message = self.parts.drain(..).flatten().flatten().collect();
        self.kind = None;
        Ok(Some((Kind::of(*kind)?, message)))
    }
}

/// Where one link's handshake stands.
enum State {
    /// The server, before a Hello it answered.
    Listening,
    /// The client, waiting for the Reply to its Hello to `attempt`'s contact,
    /// with the contacts it tries next.
    Initiating {
        attempt: Initiating,
        rest: VecDeque<Contact>,
    },
    /// The server, waiting for the Confirm.
    Responding(Responding),
    /// The session, and whether the other side has proved it holds the keys
    /// and took this side's last handshake message.
    Established {
        session: LinkSession,
        pairing: Pairing,
    },
}

/// Whether an established link is paired yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pairing {
    /// The client sent its Confirm and waits for the server's ready record.
    AwaitingReady,
    /// Each side proved it holds the keys, and took the other's last
    /// handshake message.
    Paired,
}

impl State {
    /// The contact this link is paired with, once it is.
    fn paired_peer(&self) -> Option<&LinkIdentity> {
        match self {
            State::Established {
                session,
                pairing: Pairing::Paired,
            } => Some(session.peer()),
            State::Established {
                pairing: Pairing::AwaitingReady,
                ..
            }
            | State::Listening
            | State::Initiating { .. }
            | State::Responding(..) => None,
        }
    }
}

struct Entry {
    state: State,
    fragments: Fragments,
}

/// What one write from the radio came to.
#[derive(Default)]
pub struct Inbound {
    /// Radio bytes to write back on the same link.
    pub reply: Vec<Vec<u8>>,
    /// A radio unit the other side sealed, opened: for the bilateral
    /// transport.
    pub unit: Option<Vec<u8>>,
    /// The contact this write completed pairing with on this link.
    pub paired: Option<LinkIdentity>,
}

/// The links this wallet holds a session or a handshake on.
#[derive(Default)]
pub struct Links {
    links: Mutex<HashMap<Link, Entry>>,
}

static LINKS: LazyLock<Links> = LazyLock::new(Links::default);

/// The process's links.
pub fn links() -> &'static Links {
    &LINKS
}

fn locked<T>(
    links: &Mutex<HashMap<Link, Entry>>,
    f: impl FnOnce(&mut HashMap<Link, Entry>) -> T,
) -> T {
    let mut held = match links.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut held)
}

impl Links {
    /// A link came up. The server listens; the client sends a Hello to its
    /// first candidate, `target` first when it names a contact. Returns the
    /// radio bytes to write.
    pub fn opened(
        &self,
        link: Link,
        target: Option<D32>,
        keys: &impl LinkKeys,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        let (state, frames) = match link.role {
            GattRole::Server => (State::Listening, Vec::new()),
            GattRole::Client => {
                let mut candidates: VecDeque<Contact> = keys.contacts()?.into();
                if let Some(target) = target {
                    if let Some(at) = candidates
                        .iter()
                        .position(|c| c.identity.device_id == target)
                    {
                        if let Some(first) = candidates.remove(at) {
                            candidates.push_front(first);
                        }
                    }
                }
                let Some(first) = candidates.pop_front() else {
                    return Err(DsmError::invalid_operation(
                        "no contact with a pinned ML-KEM key to run a link handshake with",
                    ));
                };
                let (hello, attempt) = Self::hello(&first, keys)?;
                (
                    State::Initiating {
                        attempt,
                        rest: candidates,
                    },
                    hello,
                )
            }
        };
        locked(&self.links, |links| {
            links.insert(
                link,
                Entry {
                    state,
                    fragments: Fragments::default(),
                },
            )
        });
        Ok(frames)
    }

    fn hello(
        contact: &Contact,
        keys: &impl LinkKeys,
    ) -> Result<(Vec<Vec<u8>>, Initiating), DsmError> {
        let (hello, attempt) = initiate(&keys.own()?, &contact.identity, &contact.kem_public_key)
            .map_err(|e| {
            DsmError::crypto(format!("link Hello: {e}"), None::<std::io::Error>)
        })?;
        Ok((fragments(Kind::Hello, &hello.encode())?, attempt))
    }

    /// The link closed: its session and handshake are dropped, and the
    /// contact it was paired with, if any, is returned.
    pub fn closed(&self, link: &Link) -> Option<LinkIdentity> {
        locked(&self.links, |links| links.remove(link))
            .and_then(|entry| entry.state.paired_peer().copied())
    }

    /// Take radio bytes the other side wrote on `link`.
    pub fn inbound(
        &self,
        link: &Link,
        bytes: &[u8],
        keys: &impl LinkKeys,
    ) -> Result<Inbound, DsmError> {
        match bytes.split_first() {
            Some((&HANDSHAKE, fragment)) => self.handshake(link, fragment, keys),
            Some((&RECORD, record)) => self.record(link, record),
            Some((first, ..)) => Err(DsmError::invalid_operation(format!(
                "radio bytes beginning {first:#04x} are neither a handshake fragment nor a sealed \
                 record"
            ))),
            None => Ok(Inbound::default()),
        }
    }

    fn handshake(
        &self,
        link: &Link,
        fragment: &[u8],
        keys: &impl LinkKeys,
    ) -> Result<Inbound, DsmError> {
        let Some(mut entry) = locked(&self.links, |links| links.remove(link)) else {
            return Err(DsmError::invalid_operation(
                "a handshake fragment on a link not opened",
            ));
        };
        let message = match entry.fragments.take(fragment) {
            Ok(Some(message)) => message,
            Ok(None) => {
                locked(&self.links, |links| links.insert(link.clone(), entry));
                return Ok(Inbound::default());
            }
            Err(e) => return Err(e),
        };
        let (state, inbound) = Self::step(entry.state, message, keys)?;
        entry.state = state;
        locked(&self.links, |links| links.insert(link.clone(), entry));
        Ok(inbound)
    }

    /// One whole handshake message, in the state the link stands in. A
    /// refused message drops the link's handshake: the link is closed.
    fn step(
        state: State,
        (kind, message): (Kind, Vec<u8>),
        keys: &impl LinkKeys,
    ) -> Result<(State, Inbound), DsmError> {
        let refused = |e: dsm::crypto::ble_link::LinkError| {
            DsmError::crypto(format!("link handshake: {e}"), None::<std::io::Error>)
        };
        match (state, kind) {
            (State::Listening, Kind::Hello) => {
                let hello = Hello::decode(&message).map_err(refused)?;
                let secret = keys.own_kem_secret()?;
                let contacts = keys.contacts()?;
                let answer = respond(&hello, &keys.own()?, &secret, |device_id| {
                    contacts
                        .iter()
                        .find(|contact| contact.identity.device_id == *device_id)
                        .map(|contact| (contact.identity.genesis, contact.kem_public_key.clone()))
                });
                match answer {
                    Ok(Answer::Reply(reply, responding)) => Ok((
                        State::Responding(*responding),
                        Inbound {
                            reply: fragments(Kind::Reply, &reply.encode())?,
                            ..Inbound::default()
                        },
                    )),
                    Ok(Answer::NotForMe) | Err(dsm::crypto::ble_link::LinkError::NotAContact) => {
                        Ok((
                            State::Listening,
                            Inbound {
                                reply: fragments(Kind::Decline, &[])?,
                                ..Inbound::default()
                            },
                        ))
                    }
                    Err(other) => Err(refused(other)),
                }
            }
            (State::Initiating { attempt, .. }, Kind::Reply) => {
                let reply = Reply::decode(&message).map_err(refused)?;
                let secret = keys.own_kem_secret()?;
                let (confirm, session) = complete(attempt, &reply, &secret).map_err(refused)?;
                Ok((
                    State::Established {
                        session,
                        pairing: Pairing::AwaitingReady,
                    },
                    Inbound {
                        reply: fragments(Kind::Confirm, &confirm.encode())?,
                        ..Inbound::default()
                    },
                ))
            }
            (State::Initiating { mut rest, .. }, Kind::Decline) => {
                let Some(next) = rest.pop_front() else {
                    return Err(DsmError::invalid_operation(
                        "no contact of this wallet answered on the link",
                    ));
                };
                let (hello, attempt) = Self::hello(&next, keys)?;
                Ok((
                    State::Initiating { attempt, rest },
                    Inbound {
                        reply: hello,
                        ..Inbound::default()
                    },
                ))
            }
            (State::Responding(responding), Kind::Confirm) => {
                let confirm = Confirm::decode(&message).map_err(refused)?;
                let mut session = finish(responding, &confirm).map_err(refused)?;
                let ready = session.seal(&[READY]).map_err(refused)?;
                let peer = *session.peer();
                Ok((
                    State::Established {
                        session,
                        pairing: Pairing::Paired,
                    },
                    Inbound {
                        reply: vec![[&[RECORD][..], &ready].concat()],
                        paired: Some(peer),
                        ..Inbound::default()
                    },
                ))
            }
            (.., kind) => Err(DsmError::invalid_operation(format!(
                "a handshake {kind:?} out of turn"
            ))),
        }
    }

    fn record(&self, link: &Link, record: &[u8]) -> Result<Inbound, DsmError> {
        locked(&self.links, |links| {
            let Some(Entry {
                state: State::Established { session, pairing },
                ..
            }) = links.get_mut(link)
            else {
                return Err(DsmError::invalid_operation(
                    "a sealed record on a link with no session",
                ));
            };
            // A record at or below the last one taken is one the radio carried again: a
            // sender whose window ACK timed out resends its whole transfer. It is not
            // taken a second time, and it is dropped without closing the link, so the
            // records after it still arrive.
            let plaintext = match session.open(record) {
                Ok(plaintext) => plaintext,
                Err(LinkError::Replayed { .. }) => return Ok(Inbound::default()),
                Err(e) => {
                    return Err(DsmError::crypto(
                        format!("link record: {e}"),
                        None::<std::io::Error>,
                    ))
                }
            };
            match (*pairing, plaintext.as_slice()) {
                // The client's first record from the server is its ready.
                (Pairing::AwaitingReady, [READY]) => {
                    *pairing = Pairing::Paired;
                    Ok(Inbound {
                        paired: Some(*session.peer()),
                        ..Inbound::default()
                    })
                }
                (Pairing::AwaitingReady, ..) => Err(DsmError::invalid_operation(
                    "a record before the server's ready",
                )),
                (Pairing::Paired, [READY]) => {
                    Err(DsmError::invalid_operation("a ready record out of turn"))
                }
                (Pairing::Paired, ..) => Ok(Inbound {
                    unit: Some(plaintext),
                    ..Inbound::default()
                }),
            }
        })
    }

    /// Seal `units` for the session on `link`, as radio bytes. Refused while
    /// the link has no session.
    pub fn seal_on(&self, link: &Link, units: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, DsmError> {
        locked(&self.links, |links| {
            let Some(Entry {
                state: State::Established { session, .. },
                ..
            }) = links.get_mut(link)
            else {
                return Err(DsmError::invalid_operation(
                    "nothing is sealed on a link with no session",
                ));
            };
            units
                .iter()
                .map(|unit| {
                    session
                        .seal(unit)
                        .map(|record| [&[RECORD][..], &record].concat())
                        .map_err(|e| {
                            DsmError::crypto(format!("link record: {e}"), None::<std::io::Error>)
                        })
                })
                .collect()
        })
    }

    /// The link this wallet is paired with `device_id` on, when it is: the
    /// one Rust seals frames for that contact on.
    pub fn link_of(&self, device_id: &D32) -> Option<Link> {
        locked(&self.links, |links| {
            links
                .iter()
                .find(|(_, entry)| {
                    entry.state.paired_peer().map(|peer| peer.device_id) == Some(*device_id)
                })
                .map(|(link, _)| link.clone())
        })
    }

    /// The links with a session at `address`, either role.
    pub fn at_address(&self, address: &str) -> Vec<Link> {
        locked(&self.links, |links| {
            links
                .iter()
                .filter(|(link, entry)| {
                    link.address == address && matches!(entry.state, State::Established { .. })
                })
                .map(|(link, _)| link.clone())
                .collect()
        })
    }
}
