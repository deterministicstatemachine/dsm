// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Inbox doorbell — the nodes push the phone when something lands
//!
//! While the app is off screen, a wallet holds no connection to the nodes:
//! each member it waits on keeps a doorbell for it instead
//! (`/api/v2/b0x/doorbell`), naming the spools the waiter plans on and the
//! app's push token, and sends one empty push (Firebase Cloud Messaging) when
//! an entry lands on any of them. The push wakes the app, which runs the sync
//! a wait's answer runs ([`on_push_wake`]): what landed is read and verified
//! exactly as it always is. The push carries nothing.
//!
//! A doorbell is put up under a key this device derives for each member from
//! its master seed ([`doorbell_key`]), so only this device replaces or takes
//! it down, and no member holds a key another member takes. Doorbells are
//! put up again whenever the routes or the token change, and every time the
//! waiter plans while the app is off screen, so a node that restarted and
//! forgot them has them back at the next wake.
//!
//! The doorbells cover the fleet ([`covers_fleet`]) when they stand on as
//! many members as the waits must: N - K + 1 of N, so every delivery, complete
//! at K members, lands on one that rings. Until they do — no push on this
//! phone (no Google Play services, no token yet), a member that does not
//! push, a member down — the app keeps today's way of listening off screen:
//! its waits, the host's foreground service, and the battery exemption.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use prost::Message;

use dsm::types::error::DsmError;
use dsm::types::proto::PushService;

/// This phone's push service and token, once the platform has one: an
/// Android app's Firebase registration token, or an iPhone's APNs device
/// token (its bytes, Base32 Crockford).
static PUSH_TOKEN: Mutex<Option<(PushService, String)>> = Mutex::new(None);

/// Each member's doorbell as it was last put up: its token and its spools.
static PUT_UP: once_cell::sync::Lazy<Mutex<HashMap<String, Doorbell>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Pushes and trips off screen so far: the waiter puts the doorbells up at
/// every member at its next plan after either, so a member that restarted and
/// forgot its doorbell has it back.
static REFRESHES_ASKED: AtomicU64 = AtomicU64::new(0);

/// Members whose doorbell stands for the routes and the token now, and the
/// members needed for those to see every delivery. None are needed until a
/// plan says how many: until then the fleet is not covered.
static MEMBERS_RINGING: AtomicUsize = AtomicUsize::new(0);
static MEMBERS_NEEDED: AtomicUsize = AtomicUsize::new(usize::MAX);

/// A doorbell as one member holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Doorbell {
    service: PushService,
    push_token: String,
    spools: BTreeSet<String>,
}

fn locked<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Android handed over this app's Firebase registration token (at start, and
/// whenever it changes). The waiter puts the doorbells up again with it.
pub fn set_push_token(push_token: String) {
    set_push(PushService::Fcm, push_token);
}

/// iOS handed over this phone's APNs device token (at start, and whenever it
/// changes): its bytes, which the doorbells carry as Base32 Crockford.
pub fn set_apns_device_token(device: &[u8]) {
    set_push(
        PushService::Apns,
        crate::util::text_id::encode_base32_crockford(device),
    );
}

fn set_push(service: PushService, push_token: String) {
    let changed = {
        let mut held = locked(&PUSH_TOKEN);
        let next = (service, push_token);
        let changed = held.as_ref() != Some(&next);
        *held = Some(next);
        changed
    };
    if changed {
        log::info!("[inbox_doorbell] a push token: the doorbells are put up with it");
        crate::sdk::inbox_waiter::replan();
    }
}

/// The platform has no push on this phone (no Google Play services, no APNs
/// registration, or no token could be had): the app keeps its waits and, on
/// Android, its foreground service.
pub fn push_unavailable(why: &str) {
    log::warn!(
        "[inbox_doorbell] no push on this phone ({why}): the app keeps listening off screen \
         with its waits and its foreground service"
    );
    *locked(&PUSH_TOKEN) = None;
    uncovered();
    crate::sdk::inbox_waiter::replan();
}

/// A node pushed this phone: something landed on a spool it reads. Runs the
/// sync a wait's answer runs; what landed is read and verified as always.
pub fn on_push_wake() {
    log::info!("[inbox_doorbell] a node rang: syncing");
    ask_refresh();
    crate::sdk::inbox_poller::resume_poller();
}

/// What a push woke, as iOS reports it back to the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushWake {
    /// The wallet is not started in this process: the host starts it first.
    NotStarted,
    /// The sync the push woke ran to its end within the time given.
    Synced,
    /// The sync was started, and had not ended when the time given ran out.
    Started,
}

/// A node pushed this phone, and the host may be suspended as soon as it
/// answers (iOS): run [`on_push_wake`] and wait for the sync it starts, at
/// most `limit`.
pub fn on_push_wake_and_wait(limit: std::time::Duration) -> PushWake {
    let started = crate::sdk::app_state::AppState::readable()
        && crate::sdk::app_state::AppState::get_device_id().is_some()
        && crate::bridge::full_app_router_installed();
    if !started {
        log::info!("[inbox_doorbell] a node rang before the wallet was started in this process");
        return PushWake::NotStarted;
    }
    let before = crate::sdk::inbox_poller::cycles_completed();
    on_push_wake();
    crate::runtime::get_runtime().block_on(crate::sdk::inbox_poller::cycle_after(before, limit));
    if crate::sdk::inbox_poller::cycles_completed() > before {
        PushWake::Synced
    } else {
        PushWake::Started
    }
}

/// Ask the waiter to put the doorbells up at every member at its next plan.
pub(crate) fn ask_refresh() {
    REFRESHES_ASKED.fetch_add(1, Ordering::SeqCst);
}

/// Refreshes asked so far ([`ask_refresh`]).
pub(crate) fn refreshes_asked() -> u64 {
    REFRESHES_ASKED.load(Ordering::SeqCst)
}

/// Whether the doorbells stand on enough members that every delivery rings
/// one of them.
pub(crate) fn covers_fleet() -> bool {
    MEMBERS_RINGING.load(Ordering::SeqCst) >= MEMBERS_NEEDED.load(Ordering::SeqCst)
}

fn uncovered() {
    MEMBERS_RINGING.store(0, Ordering::SeqCst);
}

/// The member at `endpoint` failed a wait: it may have restarted, and a
/// restarted node keeps no doorbell. It no longer counts as ringing, and the
/// next plan puts the doorbell up there again.
pub(crate) fn forget(endpoint: &str) {
    if locked(&PUT_UP).remove(endpoint).is_some() {
        let ringing = MEMBERS_RINGING.load(Ordering::SeqCst);
        MEMBERS_RINGING.store(ringing.saturating_sub(1), Ordering::SeqCst);
    }
}

/// The key this device puts its doorbell up under at the member at
/// `endpoint`: keyed BLAKE3 of the endpoint under the master seed. It comes
/// back from the seed alone, one per member.
pub(crate) fn doorbell_key(endpoint: &str) -> Result<[u8; 32], DsmError> {
    let s_master = crate::init::current_smaster()?;
    let mut h = dsm::crypto::blake3::dsm_domain_hasher_keyed(
        dsm::common::domain_tags::TAG_DSM_B0X_DOORBELL_KEY,
        &s_master,
    );
    h.update(endpoint.as_bytes());
    Ok(*h.finalize().as_bytes())
}

/// One member, as the waiter plans on it.
pub(crate) struct Member<'a> {
    pub(crate) endpoint: &'a str,
    pub(crate) client: &'a reqwest::Client,
}

/// When the doorbells are put up again although nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refresh {
    /// Only where the routes or the token changed.
    WhereChanged,
    /// At every member: a push woke the app or it went off screen, and a
    /// member that restarted since it last put them up forgot its doorbell.
    Everywhere,
}

/// Put this device's doorbell up at each of `members` for `spools`, where it
/// does not already stand as it must, and record how many members it stands
/// on out of the `needed` that cover the fleet. With no push token there is
/// nothing to put up.
pub(crate) async fn put_up(
    members: &[Member<'_>],
    spools: &BTreeSet<String>,
    needed: usize,
    refresh: Refresh,
) {
    MEMBERS_NEEDED.store(needed, Ordering::SeqCst);
    let Some((service, push_token)) = locked(&PUSH_TOKEN).clone() else {
        uncovered();
        return;
    };
    let wanted = Doorbell {
        service,
        push_token,
        spools: spools.clone(),
    };
    let mut puts = tokio::task::JoinSet::new();
    let mut ringing = 0;
    for member in members {
        let standing = locked(&PUT_UP).get(member.endpoint) == Some(&wanted);
        if standing && refresh == Refresh::WhereChanged {
            ringing += 1;
            continue;
        }
        let key = match doorbell_key(member.endpoint) {
            Ok(key) => key,
            Err(e) => {
                log::error!("[inbox_doorbell] no doorbell key: {e}");
                uncovered();
                return;
            }
        };
        let endpoint = member.endpoint.to_string();
        let client = member.client.clone();
        let wanted = wanted.clone();
        puts.spawn(async move {
            let put = put_up_at(&client, &endpoint, &key, &wanted).await;
            (endpoint, wanted, put)
        });
    }
    while let Some(joined) = puts.join_next().await {
        let (endpoint, wanted, put) = match joined {
            Ok(done) => done,
            Err(e) => {
                log::error!("[inbox_doorbell] a doorbell task ended without an answer: {e}");
                continue;
            }
        };
        match put {
            Ok(PutUp::Standing) => {
                locked(&PUT_UP).insert(endpoint, wanted);
                ringing += 1;
            }
            Ok(PutUp::NotPushing) => {
                log::info!("[inbox_doorbell] {endpoint} does not push; its waits stand");
                locked(&PUT_UP).remove(&endpoint);
            }
            Err(e) => {
                log::warn!("[inbox_doorbell] doorbell at {endpoint} not put up: {e}");
                locked(&PUT_UP).remove(&endpoint);
            }
        }
    }
    MEMBERS_RINGING.store(ringing, Ordering::SeqCst);
}

/// What a member answered a doorbell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PutUp {
    /// It stands (`204`).
    Standing,
    /// The member is not configured to push, or not through this phone's
    /// service (`404`).
    NotPushing,
}

/// Put the doorbell `key` names up at the member at `endpoint`.
pub(crate) async fn put_up_at(
    client: &reqwest::Client,
    endpoint: &str,
    key: &[u8; 32],
    doorbell: &Doorbell,
) -> Result<PutUp, DsmError> {
    let body = dsm::types::proto::B0xDoorbell {
        key: key.to_vec(),
        push_token: doorbell.push_token.clone(),
        addresses: doorbell.spools.iter().cloned().collect(),
        service: doorbell.service.into(),
    };
    let url = format!("{}/api/v2/b0x/doorbell", endpoint.trim_end_matches('/'));
    let answer = client
        .post(&url)
        .header("Content-Type", "application/protobuf")
        .body(body.encode_to_vec())
        .send()
        .await
        .map_err(|e| {
            DsmError::network(
                format!("doorbell at {endpoint}: {e}"),
                None::<std::io::Error>,
            )
        })?;
    match answer.status() {
        reqwest::StatusCode::NO_CONTENT => Ok(PutUp::Standing),
        reqwest::StatusCode::NOT_FOUND => Ok(PutUp::NotPushing),
        status => Err(DsmError::network(
            format!("doorbell at {endpoint} answered HTTP {status}"),
            None::<std::io::Error>,
        )),
    }
}
