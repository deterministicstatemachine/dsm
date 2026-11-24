// SPDX-License-Identifier: MIT OR Apache-2.0

//! Inbox doorbells: a device asks a node to push its phone (Firebase Cloud
//! Messaging for Android, the Apple Push Notification service for an
//! iPhone) when an entry lands on any of its spools, so a wallet off
//! screen is woken instead of keeping a connection open. The push carries
//! nothing ([`crate::push`]); the device wakes and reads its spools as it
//! always does, so nothing a device or a node verifies depends on a doorbell,
//! and a lost, late or extra push changes no protocol fact.
//!
//! **Who may change a doorbell.** A doorbell is named by the hash of a
//! 32-byte key its device holds, a key the device derives for this node
//! alone. Registering under a key replaces that key's doorbell; removing
//! takes down that key's doorbell; nothing else touches it. So no one but
//! the device can replace or remove its token: another device's
//! registration, on any spool, is a doorbell of its own beside it.
//!
//! **Why no write grant (DSM Amendment A34) guards it.** A grant guards what
//! a spool holds, which readers verify. A doorbell holds nothing anyone
//! reads: it only says where an empty push goes. What a stranger could do
//! with a doorbell of their own on someone's spool is learn when an entry
//! lands there, and the only parties who know a spool's address — the writer
//! of the relationship, and the nodes that hold it — see every entry land
//! already. Nor could a grant work: a relationship's first inbox is bound to
//! its writer's lock (DSM Amendment A37), so the reader holds no key for it.
//!
//! **Bounds.** Doorbells are kept in memory, never in the store: the node's
//! schema is unchanged, a restart forgets them, and devices register again
//! each time they plan their waits. A node keeps at most [`MAX_DOORBELLS`]
//! doorbells watching at most [`MAX_DOORBELL_WATCHES`] spools in all, and at
//! most [`MAX_DOORBELLS_PER_PEER`] registered from one peer
//! ([`crate::liveness::Peer`]). A peer registering past its share takes down
//! its own oldest doorbell, never another peer's; a registration past the
//! node's bounds is refused (`503`), and its device keeps its waits. So a
//! flood of registrations takes no device's doorbell down: at worst new
//! devices are listened for as they were before doorbells. An arrival rings
//! every doorbell on its spool, and a spool takes at most
//! [`MAX_DOORBELLS_PER_SPOOL`]: one past it is refused (`503`), never put up in
//! place of one that stands. Pushes are sent one at a time from a queue of
//! [`RING_QUEUE`]; a doorbell already queued is not queued again, and an
//! arrival that finds the queue full rings no one (the device reads its
//! inbox the next time it is opened).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::{body::Bytes, http::StatusCode, routing::post, Extension, Router};
use prost::Message;

use crate::push::{Delivery, Pusher};
use crate::AppState;
use dsm::types::proto::PushService;
use dsm::utils::text_id;

/// Spools one doorbell watches: every inbox route of a device with a few
/// hundred contacts, as a wait names them.
pub const MAX_DOORBELL_ADDRESSES: usize = super::b0x::MAX_WAIT_MARKS;

/// Doorbells a node keeps.
pub const MAX_DOORBELLS: usize = 32_768;

/// Spools watched across every doorbell on the node.
pub const MAX_DOORBELL_WATCHES: usize = 262_144;

/// Doorbells registered from one peer: every device behind one address, as
/// [`super::b0x::MAX_WAITERS_PER_PEER`] bounds its waits.
pub const MAX_DOORBELLS_PER_PEER: usize = super::b0x::MAX_WAITERS_PER_PEER;

/// Doorbells one spool takes: a spool is read by one device, which may have
/// registered more than once while its token changed. Every doorbell on a
/// spool rings; a ninth is refused, so no registration displaces one that
/// stands.
pub const MAX_DOORBELLS_PER_SPOOL: usize = 8;

/// The shortest and the longest APNs device token taken, in bytes. Apple's
/// are 32 today and documented as variable in length.
pub const MIN_APNS_DEVICE_BYTES: usize = 16;
pub const MAX_APNS_DEVICE_BYTES: usize = 100;

/// The longest push token taken. Firebase registration tokens are a few
/// hundred characters.
pub const MAX_PUSH_TOKEN_BYTES: usize = 1024;

/// Pushes waiting to be sent.
pub const RING_QUEUE: usize = 4096;

/// A registration's body: [`MAX_DOORBELL_ADDRESSES`] spool keys and a token
/// fit well inside it.
const MAX_DOORBELL_BODY_BYTES: usize = 64 * 1024;

/// A doorbell's name: the hash of its key.
type DoorbellId = [u8; 32];

/// The peer a doorbell was registered from, or nothing when the app is
/// served without the node's listener.
type Registrant = Option<crate::liveness::Peer>;

/// One doorbell: the service its push goes through and where, the spools it
/// watches, the peer it was registered from, and when, in the node's own
/// order of registrations.
struct Doorbell {
    service: PushService,
    push_token: String,
    spools: Vec<[u8; 32]>,
    registrant: Registrant,
    registered: u64,
}

/// The node keeps as many doorbells as it can: this one is refused.
#[derive(Debug, PartialEq, Eq)]
struct BookFull;

/// Every doorbell, by name, by the spools each watches, and by the peer each
/// was registered from, in the order they were registered.
#[derive(Default)]
struct Book {
    by_id: HashMap<DoorbellId, Doorbell>,
    by_spool: HashMap<[u8; 32], BTreeMap<u64, DoorbellId>>,
    by_registrant: HashMap<Registrant, BTreeMap<u64, DoorbellId>>,
    watches: usize,
    next_registration: u64,
}

impl Book {
    fn take_down(&mut self, id: &DoorbellId) -> Option<Doorbell> {
        let doorbell = self.by_id.remove(id)?;
        if let Some(registered) = self.by_registrant.get_mut(&doorbell.registrant) {
            registered.remove(&doorbell.registered);
            if registered.is_empty() {
                self.by_registrant.remove(&doorbell.registrant);
            }
        }
        for spool in &doorbell.spools {
            if let Some(ringing) = self.by_spool.get_mut(spool) {
                ringing.remove(&doorbell.registered);
                if ringing.is_empty() {
                    self.by_spool.remove(spool);
                }
            }
        }
        self.watches -= doorbell.spools.len();
        Some(doorbell)
    }

    /// Put up `id`'s doorbell, registered from `registrant`, in place of the
    /// one it had. A registrant at [`MAX_DOORBELLS_PER_PEER`] takes down its
    /// own oldest; a doorbell past [`MAX_DOORBELLS`] or
    /// [`MAX_DOORBELL_WATCHES`] is refused, and every other doorbell stands.
    fn put_up(
        &mut self,
        id: DoorbellId,
        registrant: Registrant,
        service: PushService,
        push_token: String,
        spools: Vec<[u8; 32]>,
    ) -> Result<(), BookFull> {
        while let Some(oldest) = self.by_registrant.get(&registrant).and_then(|registered| {
            let replacing = registered.values().any(|other| *other == id);
            if registered.len() - usize::from(replacing) < MAX_DOORBELLS_PER_PEER {
                return None;
            }
            registered.values().find(|other| **other != id).copied()
        }) {
            self.take_down(&oldest);
        }
        let (held, held_watches) = match self.by_id.get(&id) {
            Some(standing) => (1, standing.spools.len()),
            None => (0, 0),
        };
        let spool_full = spools.iter().any(|spool| {
            self.by_spool.get(spool).is_some_and(|ringing| {
                ringing.values().filter(|other| **other != id).count() >= MAX_DOORBELLS_PER_SPOOL
            })
        });
        if spool_full
            || self.by_id.len() - held >= MAX_DOORBELLS
            || self.watches - held_watches + spools.len() > MAX_DOORBELL_WATCHES
        {
            return Err(BookFull);
        }
        self.take_down(&id);
        let registered = self.next_registration;
        self.next_registration += 1;
        for spool in &spools {
            self.by_spool
                .entry(*spool)
                .or_default()
                .insert(registered, id);
        }
        self.watches += spools.len();
        self.by_registrant
            .entry(registrant)
            .or_default()
            .insert(registered, id);
        self.by_id.insert(
            id,
            Doorbell {
                service,
                push_token,
                spools,
                registrant,
                registered,
            },
        );
        Ok(())
    }

    /// The doorbells an arrival on `spool` rings: every one on it, in the
    /// order they were registered.
    fn ringing(&self, spool: &[u8; 32]) -> Vec<DoorbellId> {
        match self.by_spool.get(spool) {
            Some(ringing) => ringing.values().copied().collect(),
            None => Vec::new(),
        }
    }
}

/// The node's doorbells, the push services it is configured for, and the
/// queue their pushes are sent from.
pub struct Doorbells {
    book: Mutex<Book>,
    services: Vec<PushService>,
    queued: Mutex<HashSet<DoorbellId>>,
    rings: tokio::sync::mpsc::Sender<DoorbellId>,
}

/// A lock whose holder panicked leaves the book whole: every change to it is
/// made under the lock and completes before the lock is let go.
fn whole<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Doorbells {
    /// The node's doorbells, their pushes sent by `pusher`. Starts the task
    /// that sends them, on the current Tokio runtime, for as long as the
    /// doorbells are kept.
    pub fn start(pusher: Pusher) -> Arc<Self> {
        let (rings, mut queue) = tokio::sync::mpsc::channel(RING_QUEUE);
        let doorbells = Arc::new(Self {
            book: Mutex::new(Book::default()),
            services: pusher.services(),
            queued: Mutex::new(HashSet::new()),
            rings,
        });
        let kept = Arc::downgrade(&doorbells);
        tokio::spawn(async move {
            while let Some(id) = queue.recv().await {
                let Some(doorbells) = kept.upgrade() else {
                    break;
                };
                doorbells.send(&pusher, id).await;
            }
        });
        doorbells
    }

    /// Ring every doorbell on `spool`, which just took an entry.
    pub fn ring(&self, spool: &[u8; 32]) {
        let ringing = whole(&self.book).ringing(spool);
        for id in ringing {
            if !whole(&self.queued).insert(id) {
                continue;
            }
            if let Err(e) = self.rings.try_send(id) {
                whole(&self.queued).remove(&id);
                log::warn!("doorbell: a push was not queued: {e}");
            }
        }
    }

    /// Send the push for `id`, as its doorbell stands now.
    async fn send(&self, pusher: &Pusher, id: DoorbellId) {
        // Taken off the queue first: an entry landing while this push is out
        // rings again.
        whole(&self.queued).remove(&id);
        let (service, push_token) = match whole(&self.book).by_id.get(&id) {
            Some(doorbell) => (doorbell.service, doorbell.push_token.clone()),
            None => return,
        };
        match pusher.ring(service, &push_token).await {
            Delivery::Taken => {}
            Delivery::TokenGone => {
                log::info!("doorbell: its push token is no app's any more; taking it down");
                let mut book = whole(&self.book);
                // Only the doorbell as it was rung: its device may have put
                // up a new token meanwhile.
                if book
                    .by_id
                    .get(&id)
                    .is_some_and(|doorbell| doorbell.push_token == push_token)
                {
                    book.take_down(&id);
                }
            }
            Delivery::NotSent(why) => log::warn!("doorbell: a push was not sent: {why}"),
        }
    }

    /// The service the doorbell `key` names rings through, if it is up.
    pub fn service(&self, key: &[u8; 32]) -> Option<PushService> {
        whole(&self.book)
            .by_id
            .get(&doorbell_id(key))
            .map(|d| d.service)
    }

    /// The doorbell `key` names: its token and the spools it watches, if it
    /// is up.
    pub fn registered(&self, key: &[u8; 32]) -> Option<(String, Vec<String>)> {
        whole(&self.book).by_id.get(&doorbell_id(key)).map(|d| {
            (
                d.push_token.clone(),
                d.spools
                    .iter()
                    .map(|spool| text_id::encode_base32_crockford(spool))
                    .collect(),
            )
        })
    }
}

/// What a node names the doorbell `key` registers: its hash, so the key is
/// never kept.
fn doorbell_id(key: &[u8; 32]) -> DoorbellId {
    dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_B0X_DOORBELL, key)
}

/// A doorbell key: exactly 32 bytes.
fn doorbell_key(bytes: &[u8]) -> Result<[u8; 32], StatusCode> {
    <[u8; 32]>::try_from(bytes).map_err(|e| {
        log::info!("doorbell: the key is {} bytes: {e}", bytes.len());
        StatusCode::BAD_REQUEST
    })
}

/// A push token: printable ASCII, as every Firebase registration token is,
/// and at most [`MAX_PUSH_TOKEN_BYTES`].
fn push_token(registration: &str) -> Result<String, StatusCode> {
    if registration.is_empty()
        || registration.len() > MAX_PUSH_TOKEN_BYTES
        || !registration.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(registration.to_string())
}

/// An APNs device: the device token's bytes, Base32 Crockford, between
/// [`MIN_APNS_DEVICE_BYTES`] and [`MAX_APNS_DEVICE_BYTES`] long, kept in its
/// one canonical spelling.
fn apns_device(registration: &str) -> Result<String, StatusCode> {
    let bytes = text_id::decode_base32_crockford(registration).ok_or(StatusCode::BAD_REQUEST)?;
    if !(MIN_APNS_DEVICE_BYTES..=MAX_APNS_DEVICE_BYTES).contains(&bytes.len()) {
        log::info!("doorbell: an APNs device token is {} bytes", bytes.len());
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(text_id::encode_base32_crockford(&bytes))
}

/// The spools a doorbell names, each once, in their canonical spelling.
fn doorbell_spools(addresses: &[String]) -> Result<Vec<[u8; 32]>, StatusCode> {
    if addresses.is_empty() || addresses.len() > MAX_DOORBELL_ADDRESSES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut spools = Vec::with_capacity(addresses.len());
    for address in addresses {
        let bytes = text_id::decode_base32_crockford(address).ok_or(StatusCode::BAD_REQUEST)?;
        let spool = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|e| {
            log::info!("doorbell: a spool key is {} bytes: {e}", bytes.len());
            StatusCode::BAD_REQUEST
        })?;
        spools.push(spool);
    }
    spools.sort_unstable();
    spools.dedup();
    Ok(spools)
}

/// The doorbell routes, served only by a node configured to push
/// (`[push.fcm]`, `[push.apns]`, or both): a node that is not answers `404`,
/// and its devices keep their waits. A doorbell through a service the node
/// is not configured for is answered `404` as well.
///
/// - `POST /api/v2/b0x/doorbell`: a [`dsm::types::proto::B0xDoorbell`]. Puts
///   up the doorbell its key names, in place of the one that key had.
/// - `POST /api/v2/b0x/doorbell/remove`: a
///   [`dsm::types::proto::B0xDoorbellRemove`]. Takes it down.
///
/// Both answer `204`, whether or not a doorbell stood there, and `400` for a
/// body that is not one. A registration past the node's bounds is answered
/// `503`, and its device keeps its waits.
pub fn router(app: Arc<AppState>, doorbells: Arc<Doorbells>) -> Router<()> {
    Router::new()
        .route("/api/v2/b0x/doorbell", post(put_up))
        .route("/api/v2/b0x/doorbell/remove", post(take_down))
        .layer(Extension(doorbells))
        .layer(Extension(app))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            MAX_DOORBELL_BODY_BYTES,
        ))
}

async fn put_up(
    Extension(doorbells): Extension<Arc<Doorbells>>,
    request: axum::extract::Request,
) -> Result<StatusCode, StatusCode> {
    super::b0x::require_protobuf(request.headers())?;
    let registrant = request.extensions().get::<crate::liveness::Peer>().copied();
    let body = axum::body::to_bytes(request.into_body(), MAX_DOORBELL_BODY_BYTES)
        .await
        .map_err(|e| {
            log::info!("doorbell: the registration's body was not read: {e}");
            StatusCode::BAD_REQUEST
        })?;
    let doorbell = dsm::types::proto::B0xDoorbell::decode(body).map_err(|e| {
        log::info!("doorbell: the registration does not decode: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let key = doorbell_key(&doorbell.key)?;
    let service = PushService::try_from(doorbell.service).map_err(|e| {
        log::info!("doorbell: no such push service: {e}");
        StatusCode::BAD_REQUEST
    })?;
    if !doorbells.services.contains(&service) {
        log::info!("doorbell: this node does not push through {service:?}");
        return Err(StatusCode::NOT_FOUND);
    }
    let push_token = match service {
        PushService::Fcm => push_token(&doorbell.push_token)?,
        PushService::Apns => apns_device(&doorbell.push_token)?,
    };
    let spools = doorbell_spools(&doorbell.addresses)?;
    whole(&doorbells.book)
        .put_up(doorbell_id(&key), registrant, service, push_token, spools)
        .map_err(|BookFull| {
            log::warn!("doorbell: the node keeps as many doorbells as it can; one refused");
            StatusCode::SERVICE_UNAVAILABLE
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn take_down(
    Extension(doorbells): Extension<Arc<Doorbells>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    super::b0x::require_protobuf(&headers)?;
    let remove = dsm::types::proto::B0xDoorbellRemove::decode(body).map_err(|e| {
        log::info!("doorbell: the removal does not decode: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let key = doorbell_key(&remove.key)?;
    whole(&doorbells.book).take_down(&doorbell_id(&key));
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spool(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// The peer `n`, as the node's listener names a connection's peer.
    fn peer(n: u32) -> Registrant {
        Some(crate::liveness::Peer::of(std::net::IpAddr::V4(
            std::net::Ipv4Addr::from(0x0A00_0000 + n),
        )))
    }

    /// A doorbell put up again under its key is replaced, never doubled; one
    /// under another key stands beside it; taking one down leaves the other.
    #[test]
    fn a_key_replaces_and_removes_only_its_own_doorbell() {
        let mut book = Book::default();
        let mine = doorbell_id(&[1; 32]);
        let theirs = doorbell_id(&[2; 32]);
        assert_eq!(
            book.put_up(
                mine,
                peer(1),
                PushService::Fcm,
                "mine-1".into(),
                vec![spool(7)]
            ),
            Ok(())
        );
        assert_eq!(
            book.put_up(
                theirs,
                peer(2),
                PushService::Fcm,
                "theirs".into(),
                vec![spool(7)]
            ),
            Ok(())
        );
        assert_eq!(
            book.put_up(
                mine,
                peer(1),
                PushService::Fcm,
                "mine-2".into(),
                vec![spool(7), spool(8)]
            ),
            Ok(())
        );
        assert_eq!(book.ringing(&spool(7)), vec![theirs, mine]);
        assert_eq!(book.ringing(&spool(8)), vec![mine]);
        assert_eq!(book.watches, 3);
        book.take_down(&theirs);
        assert_eq!(book.ringing(&spool(7)), vec![mine]);
        assert_eq!(
            book.by_id.get(&mine).map(|d| d.push_token.clone()),
            Some("mine-2".to_string())
        );
    }

    /// A node that keeps as many spools as it can refuses a newcomer and
    /// takes no doorbell down for it; a standing doorbell is still replaced
    /// in place.
    #[test]
    fn a_full_book_refuses_a_newcomer_and_keeps_every_doorbell() {
        let mut book = Book::default();
        let per = MAX_DOORBELL_ADDRESSES;
        let bells = MAX_DOORBELL_WATCHES / per;
        let key = |n: usize| {
            let mut key = [0xA5; 32];
            key[..8].copy_from_slice(&(n as u64).to_be_bytes());
            key
        };
        for n in 0..bells {
            let spools = (0..per)
                .map(|i| {
                    let mut s = [0x5A; 32];
                    s[..8].copy_from_slice(&(n as u64).to_be_bytes());
                    s[8..16].copy_from_slice(&(i as u64).to_be_bytes());
                    s
                })
                .collect();
            assert_eq!(
                book.put_up(
                    doorbell_id(&key(n)),
                    peer(n as u32),
                    PushService::Fcm,
                    format!("t{n}"),
                    spools
                ),
                Ok(())
            );
        }
        assert_eq!(book.watches, MAX_DOORBELL_WATCHES);
        let newcomer = doorbell_id(&[0xEE; 32]);
        assert_eq!(
            book.put_up(
                newcomer,
                peer(9_999),
                PushService::Fcm,
                "newcomer".into(),
                vec![spool(0xEE)]
            ),
            Err(BookFull)
        );
        assert_eq!(book.by_id.len(), bells);
        assert!(!book.by_id.contains_key(&newcomer));
        assert_eq!(
            book.put_up(
                doorbell_id(&key(0)),
                peer(0),
                PushService::Fcm,
                "t0-new".into(),
                vec![spool(0xEF)]
            ),
            Ok(())
        );
        assert_eq!(book.by_id.len(), bells);
    }

    /// A peer registering past its share takes down its own oldest doorbell,
    /// never another peer's.
    #[test]
    fn a_peer_past_its_share_takes_down_only_its_own_oldest() {
        let mut book = Book::default();
        let other = doorbell_id(&[0xBB; 32]);
        assert_eq!(
            book.put_up(
                other,
                peer(2),
                PushService::Fcm,
                "other".into(),
                vec![spool(1)]
            ),
            Ok(())
        );
        let ids: Vec<DoorbellId> = (0..=MAX_DOORBELLS_PER_PEER)
            .map(|n| {
                let mut key = [0xCC; 32];
                key[..8].copy_from_slice(&(n as u64).to_be_bytes());
                doorbell_id(&key)
            })
            .collect();
        for (n, id) in ids.iter().enumerate() {
            let mut own = [0xDD; 32];
            own[..8].copy_from_slice(&(n as u64).to_be_bytes());
            assert_eq!(
                book.put_up(*id, peer(1), PushService::Fcm, format!("t{n}"), vec![own]),
                Ok(())
            );
        }
        assert!(!book.by_id.contains_key(&ids[0]));
        assert!(ids[1..].iter().all(|id| book.by_id.contains_key(id)));
        assert!(book.by_id.contains_key(&other));
    }

    /// A spool takes no more than [`MAX_DOORBELLS_PER_SPOOL`] doorbells: one
    /// past it is refused, and every one standing still rings, the first
    /// registered included. A standing doorbell is still replaced in place.
    #[test]
    fn a_spool_refuses_a_doorbell_past_its_bound_and_rings_every_one() {
        let mut book = Book::default();
        let ids: Vec<DoorbellId> = (0..=MAX_DOORBELLS_PER_SPOOL as u8)
            .map(|n| doorbell_id(&[n; 32]))
            .collect();
        for (n, id) in ids[..MAX_DOORBELLS_PER_SPOOL].iter().enumerate() {
            assert_eq!(
                book.put_up(
                    *id,
                    peer(n as u32),
                    PushService::Fcm,
                    format!("t{n}"),
                    vec![spool(9)]
                ),
                Ok(())
            );
        }
        assert_eq!(
            book.put_up(
                ids[MAX_DOORBELLS_PER_SPOOL],
                peer(99),
                PushService::Fcm,
                "late".into(),
                vec![spool(9)]
            ),
            Err(BookFull)
        );
        assert_eq!(
            book.ringing(&spool(9)),
            ids[..MAX_DOORBELLS_PER_SPOOL].to_vec()
        );
        assert_eq!(
            book.put_up(
                ids[0],
                peer(0),
                PushService::Fcm,
                "t0-new".into(),
                vec![spool(9)]
            ),
            Ok(())
        );
        assert_eq!(book.ringing(&spool(9)).len(), MAX_DOORBELLS_PER_SPOOL);
    }

    #[test]
    fn a_doorbell_is_refused_unless_its_parts_are_what_they_must_be() {
        assert_eq!(doorbell_key(&[7; 31]), Err(StatusCode::BAD_REQUEST));
        assert_eq!(push_token(""), Err(StatusCode::BAD_REQUEST));
        assert_eq!(push_token("a b"), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            push_token(&"x".repeat(MAX_PUSH_TOKEN_BYTES + 1)),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(doorbell_spools(&[]), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            doorbell_spools(&["not-a-key".to_string()]),
            Err(StatusCode::BAD_REQUEST)
        );
        let key = text_id::encode_base32_crockford(&spool(3));
        assert_eq!(
            doorbell_spools(&[key.clone(), key.to_lowercase()]),
            Ok(vec![spool(3)])
        );
    }
}
