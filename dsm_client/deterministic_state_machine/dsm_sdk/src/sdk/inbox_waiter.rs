// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Inbox waiter — long-poll on the storage nodes
//!
//! Holds a wait (`/api/v2/b0x/wait`) open on every member of the pinned set,
//! over every inbox route this device reads, and runs a sync the moment any
//! member answers that one of them holds something new. A transfer, a reply
//! or a certificate is then taken within a round trip of landing, instead of
//! at the next poll.
//!
//! A wait reads nothing and moves nothing: the sync it wakes reads the spools
//! exactly as a poll does. The inbox poller keeps running beside it as the
//! safety net, at a slower cadence while the waits cover the fleet
//! ([`covers_fleet`]), and at its own cadence whenever they do not: a fleet
//! that does not serve waits yet, a member down, no connection.
//!
//! The waiter runs while the poller runs, and stops with it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::sdk::b0x_sdk::WaitAnswer;

/// How long a member is asked to hold each wait: the node's own cap
/// (`dsm_storage_node::api::transport::b0x::MAX_WAIT`).
const WAIT: Duration = Duration::from_secs(25);

/// How long a member that failed a wait, or does not hold them, is left out
/// of the next ones. The poller reads it meanwhile.
const MEMBER_REST: Duration = Duration::from_secs(30);

/// How long the waiter waits for the sync a wake asked for.
const SYNC_WAIT: Duration = Duration::from_secs(60);

/// How long the waiter rests when it has nothing to wait on (no identity, no
/// contact) or could not work out what to, before it looks again. A sync
/// that completes meanwhile ends the rest early.
const IDLE_REST: Duration = Duration::from_secs(30);

/// A round answered within this of starting, again and again, is a member
/// naming a spool the sync it wakes does not read to its end: the waiter
/// backs off instead of syncing in a loop.
const QUICK_ROUND: Duration = Duration::from_secs(1);

/// Quick rounds in a row before the waiter backs off.
const QUICK_ROUNDS_BEFORE_BACKOFF: u32 = 3;

/// The longest back-off between quick rounds.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Waiter tasks running: one at most.
static WAITERS_RUNNING: AtomicUsize = AtomicUsize::new(0);

/// Members whose last wait was held to an answer, and the members needed for
/// those waits to see every delivery (see [`covers_fleet`]). None are needed
/// until a plan says how many: until then the fleet is not covered.
static MEMBERS_HOLDING: AtomicUsize = AtomicUsize::new(0);
static MEMBERS_NEEDED: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Ends a held round at once when the poller is stopped.
static WAITER_STOP: once_cell::sync::Lazy<Notify> = once_cell::sync::Lazy::new(Notify::new);

/// Whether waits are held on enough members that every delivery lands on one
/// of them: a delivery is complete at the register quorum K of N members, so
/// waits held on N - K + 1 of them see every delivery. While they are, the
/// poller can poll slowly.
pub(crate) fn covers_fleet() -> bool {
    MEMBERS_HOLDING.load(Ordering::SeqCst) >= MEMBERS_NEEDED.load(Ordering::SeqCst)
}

/// The fleet is no longer known to be covered.
fn uncovered() {
    MEMBERS_HOLDING.store(0, Ordering::SeqCst);
}

/// The members needed to cover a fleet of `members` whose deliveries are
/// complete at `quorum_k`.
pub(crate) fn members_to_cover(members: usize, quorum_k: usize) -> usize {
    (members + 1).saturating_sub(quorum_k).max(1)
}

/// Ends a round held now; the waiter then sees the poller stopped and stops.
pub(crate) fn wake_to_stop() {
    WAITER_STOP.notify_waiters();
}

/// Clears the running flag when the waiter ends, however it ends.
struct RunningFlag;

impl Drop for RunningFlag {
    fn drop(&mut self) {
        uncovered();
        WAITERS_RUNNING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Start the waiter beside the poller. Idempotent: a waiter already running
/// keeps running.
pub(crate) fn start() {
    if WAITERS_RUNNING.fetch_add(1, Ordering::SeqCst) > 0 {
        WAITERS_RUNNING.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    crate::runtime::get_runtime().spawn(async move {
        let _running = RunningFlag;
        log::info!("[inbox_waiter] started");
        run().await;
        log::info!("[inbox_waiter] stopped");
    });
}

/// One member's spool marks: where each of this device's routes was read to.
struct MemberPlan {
    endpoint: String,
    client: reqwest::Client,
    marks: Vec<(String, u64)>,
}

/// What a round waits on.
struct Plan {
    members: Vec<MemberPlan>,
    addresses: BTreeSet<String>,
    /// Members whose waits cover every delivery ([`members_to_cover`]).
    needed: usize,
}

/// How a round ended.
enum Round {
    /// A member named a spool holding something new.
    Ready,
    /// Every member's wait ran out with nothing new, or no member held one.
    Quiet,
    /// A sync moved the routes this device reads: wait on the new ones.
    Replan,
    /// The poller was stopped.
    Stopped,
}

async fn run() {
    // The first sync records where each spool was read to; until it has run,
    // a wait would only wake for what that sync is about to read anyway.
    wait_for_cycle_after(crate::sdk::inbox_poller::cycles_completed(), SYNC_WAIT).await;

    let mut resting: HashMap<String, Instant> = HashMap::new();
    let mut holding: HashSet<String> = HashSet::new();
    let mut quick_rounds: u32 = 0;
    while !crate::sdk::inbox_poller::poller_stopping() {
        let plan = match plan(&mut resting) {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                uncovered();
                wait_for_cycle_after(crate::sdk::inbox_poller::cycles_completed(), IDLE_REST).await;
                continue;
            }
            Err(e) => {
                uncovered();
                log::error!("[inbox_waiter] cannot work out what to wait on: {e}");
                wait_for_cycle_after(crate::sdk::inbox_poller::cycles_completed(), IDLE_REST).await;
                continue;
            }
        };

        let started = Instant::now();
        let round = hold(&plan, &mut resting, &mut holding).await;
        MEMBERS_NEEDED.store(plan.needed, Ordering::SeqCst);
        MEMBERS_HOLDING.store(holding.len(), Ordering::SeqCst);
        match round {
            Round::Stopped => break,
            Round::Replan => continue,
            Round::Quiet => {
                quick_rounds = 0;
            }
            Round::Ready => {
                quick_rounds = if started.elapsed() < QUICK_ROUND {
                    quick_rounds.saturating_add(1)
                } else {
                    0
                };
                let before = crate::sdk::inbox_poller::cycles_completed();
                crate::sdk::inbox_poller::resume_poller();
                wait_for_cycle_after(before, SYNC_WAIT).await;
                if quick_rounds >= QUICK_ROUNDS_BEFORE_BACKOFF {
                    let backoff = backoff_after(quick_rounds);
                    log::warn!(
                        "[inbox_waiter] {quick_rounds} waits in a row answered at once; the \
                         sync they wake does not read what they name — waiting {backoff:?}"
                    );
                    rest_unless_stopped(backoff).await;
                }
            }
        }
    }
}

/// The back-off after `quick_rounds` quick rounds in a row: one second at the
/// first that backs off, doubling, at most [`MAX_BACKOFF`].
pub(crate) fn backoff_after(quick_rounds: u32) -> Duration {
    let doublings = quick_rounds
        .saturating_sub(QUICK_ROUNDS_BEFORE_BACKOFF)
        .min(5);
    Duration::from_secs(1u64 << doublings).min(MAX_BACKOFF)
}

/// This device's routes and where each member's spool at each was read to,
/// or `None` when there is nothing to wait on yet.
fn plan(resting: &mut HashMap<String, Instant>) -> Result<Option<Plan>, String> {
    let Some(device) = crate::sdk::app_state::AppState::get_device_id() else {
        return Ok(None);
    };
    let Some(genesis) = crate::sdk::app_state::AppState::get_genesis_hash() else {
        return Ok(None);
    };
    let device: [u8; 32] = device
        .as_slice()
        .try_into()
        .map_err(|e| format!("device id is not 32 bytes: {e}"))?;
    let genesis: [u8; 32] = genesis
        .as_slice()
        .try_into()
        .map_err(|e| format!("genesis is not 32 bytes: {e}"))?;
    let contacts = crate::storage::client_db::get_all_contacts()
        .map_err(|e| format!("contacts unreadable: {e}"))?;
    if contacts.is_empty() {
        return Ok(None);
    }
    let addresses: BTreeSet<String> =
        crate::handlers::app_router_impl::collect_tagged_inbox_addresses(
            genesis, device, &contacts,
        )?
        .into_iter()
        .map(|tagged| tagged.address)
        .collect();
    if addresses.is_empty() {
        return Ok(None);
    }

    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("no committed network: {e}"))?;
    let set = crate::sdk::storage_set::canonical_set(&network)
        .map_err(|e| format!("no pinned storage set: {e}"))?;
    let profile = dsm::economic::register::resolve_root_register_profile(&network)
        .map_err(|e| format!("root register profile: {e}"))?;
    let quorum_k =
        crate::storage::client_db::publication::quorum_for(profile.members.len()) as usize;

    let now = Instant::now();
    resting.retain(|_, until| *until > now);
    let mut members = Vec::with_capacity(set.members().len());
    for member in set.members() {
        if resting.contains_key(&member.endpoint) {
            continue;
        }
        let client =
            crate::sdk::storage_node_sdk::member_client(&member.member_id, &member.endpoint)
                .map_err(|e| format!("client for {}: {e}", member.endpoint))?;
        let mut marks = Vec::with_capacity(addresses.len());
        for address in &addresses {
            let from = match crate::sdk::b0x_sdk::spool_end(address, &member.endpoint) {
                Some(end) => end,
                None => crate::storage::client_db::b0x_consumed::read_position(
                    address,
                    &member.endpoint,
                )
                .map_err(|e| format!("read position unreadable: {e}"))?,
            };
            marks.push((address.clone(), from));
        }
        members.push(MemberPlan {
            endpoint: member.endpoint.clone(),
            client,
            marks,
        });
    }
    Ok(Some(Plan {
        members,
        addresses,
        needed: members_to_cover(set.members().len(), quorum_k),
    }))
}

/// Hold one round of waits, one per member not resting, until a member names
/// a spool, every wait runs out, a sync moves the routes, or the poller
/// stops. Keeps the members that held their wait to an answer in `holding`,
/// and rests those that failed or do not hold waits.
async fn hold(
    plan: &Plan,
    resting: &mut HashMap<String, Instant>,
    holding: &mut HashSet<String>,
) -> Round {
    let mut waits = tokio::task::JoinSet::new();
    for member in &plan.members {
        let endpoint = member.endpoint.clone();
        let client = member.client.clone();
        let marks = member.marks.clone();
        waits.spawn(async move {
            let answer =
                crate::sdk::b0x_sdk::wait_on_member(&client, &endpoint, &marks, WAIT).await;
            (endpoint, answer)
        });
    }
    let cycles_at_start = crate::sdk::inbox_poller::cycles_completed();
    loop {
        let cycle_done = crate::sdk::inbox_poller::cycle_done();
        tokio::pin!(cycle_done);
        cycle_done.as_mut().enable();
        let stop = WAITER_STOP.notified();
        tokio::pin!(stop);
        stop.as_mut().enable();
        if crate::sdk::inbox_poller::poller_stopping() {
            return Round::Stopped;
        }
        if crate::sdk::inbox_poller::cycles_completed() != cycles_at_start && routes_moved(plan) {
            return Round::Replan;
        }
        tokio::select! {
            joined = waits.join_next() => {
                let Some(joined) = joined else {
                    return Round::Quiet;
                };
                let (endpoint, answer) = match joined {
                    Ok(answered) => answered,
                    Err(e) => {
                        log::error!("[inbox_waiter] a wait task ended without an answer: {e}");
                        continue;
                    }
                };
                match answer {
                    Ok(WaitAnswer::Ready(ready)) => {
                        holding.insert(endpoint.clone());
                        log::info!(
                            "[inbox_waiter] {endpoint} has new entries on {} route(s): syncing",
                            ready.len()
                        );
                        return Round::Ready;
                    }
                    Ok(WaitAnswer::Quiet) => {
                        holding.insert(endpoint);
                    }
                    Ok(WaitAnswer::NotHeld(status)) => {
                        log::info!(
                            "[inbox_waiter] {endpoint} does not hold waits ({status}); the poller \
                             reads it"
                        );
                        holding.remove(&endpoint);
                        resting.insert(endpoint, Instant::now() + MEMBER_REST);
                    }
                    Err(e) => {
                        log::warn!("[inbox_waiter] wait at {endpoint} failed: {e}");
                        holding.remove(&endpoint);
                        resting.insert(endpoint, Instant::now() + MEMBER_REST);
                    }
                }
            }
            () = &mut cycle_done => {}
            () = &mut stop => return Round::Stopped,
        }
    }
}

/// Whether the routes this device reads are no longer the ones `plan` waits
/// on. Routes that cannot be worked out now count as moved: the next plan
/// says why.
fn routes_moved(plan: &Plan) -> bool {
    let Some(device) = crate::sdk::app_state::AppState::get_device_id() else {
        return plan_differs(plan, BTreeSet::new());
    };
    let Some(genesis) = crate::sdk::app_state::AppState::get_genesis_hash() else {
        return plan_differs(plan, BTreeSet::new());
    };
    let (Ok(device), Ok(genesis)) = (
        <[u8; 32]>::try_from(device.as_slice()),
        <[u8; 32]>::try_from(genesis.as_slice()),
    ) else {
        return plan_differs(plan, BTreeSet::new());
    };
    let contacts = match crate::storage::client_db::get_all_contacts() {
        Ok(contacts) => contacts,
        Err(e) => {
            log::error!("[inbox_waiter] contacts unreadable: {e}");
            return plan_differs(plan, BTreeSet::new());
        }
    };
    match crate::handlers::app_router_impl::collect_tagged_inbox_addresses(
        genesis, device, &contacts,
    ) {
        Ok(tagged) => plan_differs(plan, tagged.into_iter().map(|t| t.address).collect()),
        Err(e) => {
            log::error!("[inbox_waiter] routes unreadable: {e}");
            plan_differs(plan, BTreeSet::new())
        }
    }
}

fn plan_differs(plan: &Plan, now: BTreeSet<String>) -> bool {
    plan.addresses != now
}

/// Wait until a poller cycle after the `before`-th has completed, `limit`
/// passes, or the poller stops.
async fn wait_for_cycle_after(before: u64, limit: Duration) {
    let deadline = Instant::now() + limit;
    loop {
        let cycle_done = crate::sdk::inbox_poller::cycle_done();
        tokio::pin!(cycle_done);
        cycle_done.as_mut().enable();
        let stop = WAITER_STOP.notified();
        tokio::pin!(stop);
        stop.as_mut().enable();
        if crate::sdk::inbox_poller::cycles_completed() > before
            || crate::sdk::inbox_poller::poller_stopping()
        {
            return;
        }
        tokio::select! {
            () = &mut cycle_done => {}
            () = &mut stop => return,
            () = tokio::time::sleep_until(deadline) => return,
        }
    }
}

/// Rest for `limit`, or until the poller stops.
async fn rest_unless_stopped(limit: Duration) {
    let stop = WAITER_STOP.notified();
    tokio::pin!(stop);
    stop.as_mut().enable();
    if crate::sdk::inbox_poller::poller_stopping() {
        return;
    }
    tokio::select! {
        () = &mut stop => {}
        () = tokio::time::sleep(limit) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A delivery is complete at K of N members, so waits on N - K + 1 of
    /// them see every one: 3 of 5 for the beta fleet's 5/3, 2 of 3 for a
    /// 3/2 one. One fewer can miss a delivery that skipped exactly those.
    #[test]
    fn waits_cover_the_fleet_on_one_more_than_a_delivery_can_skip() {
        assert_eq!(members_to_cover(5, 3), 3);
        assert_eq!(members_to_cover(3, 2), 2);
        assert_eq!(members_to_cover(1, 1), 1);
        assert_eq!(members_to_cover(4, 4), 1);
    }

    /// On the storage node's own code, over TLS as a device reaches it: a
    /// wait held at a member on a spool past its last entry is answered,
    /// naming the spool, when an envelope lands there; a wait whose mark is
    /// already met is answered at once; and one whose mark is past the end
    /// runs its length and names nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn a_wait_held_at_a_member_is_answered_when_a_delivery_lands() {
        let nodes = crate::test_support::nodes::NodeSet::start().await;
        let _config = crate::economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let member = set.members()[0].clone();
        let client =
            crate::sdk::storage_node_sdk::member_client(&member.member_id, &member.endpoint)
                .expect("a member client");
        let address = crate::util::text_id::encode_base32_crockford(&[0x7Au8; 32]);

        let started = Instant::now();
        let waiting = {
            let (client, endpoint, marks) = (
                client.clone(),
                member.endpoint.clone(),
                vec![(address.clone(), 1)],
            );
            tokio::spawn(async move {
                crate::sdk::b0x_sdk::wait_on_member(&client, &endpoint, &marks, WAIT).await
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !waiting.is_finished(),
            "the wait was answered before anything landed"
        );

        let submitted = client
            .post(format!("{}/api/v2/b0x/submit", member.endpoint))
            .header("Content-Type", "application/octet-stream")
            .header("x-dsm-recipient", address.as_str())
            .body(vec![0x0Au8, 0x01, 0x03])
            .send()
            .await
            .expect("the member takes the delivery");
        assert_eq!(submitted.status(), reqwest::StatusCode::NO_CONTENT);

        let answer = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the wait was not answered when the delivery landed")
            .expect("the waiting task")
            .expect("the member answered the wait");
        assert_eq!(answer, WaitAnswer::Ready(vec![address.clone()]));
        assert!(started.elapsed() < Duration::from_secs(10));

        let met = crate::sdk::b0x_sdk::wait_on_member(
            &client,
            &member.endpoint,
            &[(address.clone(), 1)],
            WAIT,
        )
        .await
        .expect("the member answers");
        assert_eq!(met, WaitAnswer::Ready(vec![address.clone()]));

        let started = Instant::now();
        let past_the_end = crate::sdk::b0x_sdk::wait_on_member(
            &client,
            &member.endpoint,
            &[(address, 2)],
            Duration::from_millis(400),
        )
        .await
        .expect("the member answers");
        assert_eq!(past_the_end, WaitAnswer::Quiet);
        assert!(started.elapsed() >= Duration::from_millis(400));
    }

    /// The back-off starts at one second after the third quick round in a
    /// row, doubles with each one after, and stops at thirty seconds.
    #[test]
    fn quick_rounds_back_off_doubling_to_thirty_seconds() {
        assert_eq!(backoff_after(3), Duration::from_secs(1));
        assert_eq!(backoff_after(4), Duration::from_secs(2));
        assert_eq!(backoff_after(6), Duration::from_secs(8));
        assert_eq!(backoff_after(8), Duration::from_secs(30));
        assert_eq!(backoff_after(u32::MAX), Duration::from_secs(30));
    }
}
