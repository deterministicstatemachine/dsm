// SPDX-License-Identifier: MIT OR Apache-2.0
//! Many devices on one network, under faults. A seeded schedule over four
//! devices on the five real nodes: online sends on every relationship, syncs,
//! member outages (a failed spool, or a node that crashes and restarts on its
//! database; one member, or enough to break the quorum) and device restarts.
//! Every step is checked, and every phase ends at rest and is checked there.
//!
//! After every step:
//! - a send that answers done armed the sender's gate toward the recipient.
//!   A send counts as sent when it armed that gate, whatever its answer says:
//!   a debit whose admission is held or whose delivery is unknown answers
//!   with an error, and the answer does not say structurally that the debit
//!   stands (§6.121);
//! - no device holds less than it started with less what it sent, nor more
//!   than that plus what was sent to it, and the devices together never hold
//!   more than they started with: no value is created.
//!
//! At rest (every member serving, rounds of syncs until a round moves
//! nothing):
//! - each device holds exactly what it started with, less what it sent, plus
//!   what was sent to it: every send applied once, none lost;
//! - the two devices of every relationship hold one tip and are send-ready
//!   toward each other.
//!
//! The run ends with a transfer each way on every relationship, settled.

use super::TestDevice;
use crate::economic_fixtures::{self, FleetGuard};
use crate::storage::client_db as cdb;
use crate::test_support::nodes::NodeSet;
use serial_test::serial;

const SLOTS: [&str; 4] = ["M0", "M1", "M2", "M3"];
const SEEDS: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
/// Each device's funding in whole ERA: two funded and two not, so value has
/// to travel to reach every device.
const FUNDING: [u64; 4] = [100, 100, 0, 0];
const STEPS_PER_PHASE: usize = 16;
/// Rounds of syncs a phase gets to come to rest in.
const REST_ROUNDS: usize = 10;
/// The largest send, in base units.
const MAX_SEND: u64 = 40;

/// Seeded choice: xorshift64.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(n).expect("small")).expect("small")
    }
}

/// Which members are out, and how: a failed spool (the node serves its cells
/// and refuses every b0x submit and read), or the node down (its listener
/// closed and its connections shut, restarted later on the same database and
/// address).
#[derive(Clone, PartialEq, Eq, Debug)]
enum Outage {
    Serving,
    SpoolFailed(String),
    SpoolsFailedPastQuorum,
    Down(String),
    DownPastQuorum,
}

impl Outage {
    fn failed_spools(&self) -> Vec<String> {
        match self {
            Outage::SpoolFailed(member) => vec![member.clone()],
            Outage::SpoolsFailedPastQuorum => economic_fixtures::members_to_break_quorum(),
            Outage::Serving | Outage::Down(_) | Outage::DownPastQuorum => Vec::new(),
        }
    }

    fn down(&self) -> Vec<String> {
        match self {
            Outage::Down(member) => vec![member.clone()],
            Outage::DownPastQuorum => economic_fixtures::members_to_break_quorum(),
            Outage::Serving | Outage::SpoolFailed(_) | Outage::SpoolsFailedPastQuorum => Vec::new(),
        }
    }
}

/// What every device holds and every relationship's tips, as the devices hold
/// them: equal before and after a round of syncs means the round moved
/// nothing.
#[derive(PartialEq, Eq, Debug)]
struct Snapshot {
    held: Vec<u64>,
    tips: Vec<Option<[u8; 32]>>,
}

struct Mesh {
    nodes: NodeSet,
    fleet: FleetGuard,
    devices: Vec<TestDevice>,
    initial: Vec<u64>,
    sent: Vec<u64>,
    received: Vec<u64>,
    outage: Outage,
    /// Sends that debited their sender while some member was out.
    debited_while_out: usize,
    steps: Vec<String>,
    _poller_hold: crate::sdk::inbox_poller::PollerHold,
}

impl Mesh {
    /// The nodes, four booted devices each holding every other as a contact,
    /// and the funded ones funded through the faucet.
    async fn boot() -> Self {
        let poller_hold = crate::sdk::inbox_poller::hold_off_for_two_device_harness().await;
        economic_fixtures::use_test_storage_dir();
        cdb::reset_database_for_tests();
        let nodes = NodeSet::start().await;
        let fleet = economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let mut devices: Vec<TestDevice> = SLOTS
            .iter()
            .copied()
            .zip(SEEDS)
            .map(|(slot, seed)| TestDevice::create(slot, seed))
            .collect();
        for device in &mut devices {
            device.boot(&fleet).await;
        }
        for me in &devices {
            for peer in devices.iter().filter(|peer| peer.device_id != me.device_id) {
                me.add_contact(peer).await;
            }
        }
        for (device, whole) in devices.iter().zip(FUNDING) {
            if whole > 0 {
                device.fund_admitted(whole).await;
            }
        }
        let initial = devices.iter().map(TestDevice::era_balance).collect();
        let n = devices.len();
        Self {
            nodes,
            fleet,
            devices,
            initial,
            sent: vec![0; n],
            received: vec![0; n],
            outage: Outage::Serving,
            debited_while_out: 0,
            steps: Vec::new(),
            _poller_hold: poller_hold,
        }
    }

    /// The last steps taken, for a failure's message.
    fn trail(&self) -> String {
        let from = self.steps.len().saturating_sub(12);
        self.steps[from..].join("; ")
    }

    /// The step `from`'s gate toward `to` holds: the one its last send armed.
    fn gate(&self, from: usize, to: usize) -> Option<Vec<u8>> {
        self.devices[from].enter();
        cdb::get_pending_online_outbox(&self.devices[to].device_id)
            .expect("the gate reads")
            .map(|gate| gate.next_tip)
    }

    /// A send of `amount` from `from` to `to`; whether it armed the sender's
    /// gate, i.e. debited the sender.
    async fn send(&mut self, from: usize, to: usize, amount: u64) -> bool {
        let before = self.gate(from, to);
        let answer = self.devices[from].send(&self.devices[to], amount).await;
        let after = self.gate(from, to);
        let armed = after.is_some() && after != before;
        let said = match answer.error_message.as_deref() {
            Some(why) => why.to_string(),
            None => "done".to_string(),
        };
        self.steps
            .push(format!("{}->{} {amount}: {said}", SLOTS[from], SLOTS[to]));
        if answer.success {
            assert!(
                armed,
                "{}: the wallet answered done and armed no gate",
                self.trail()
            );
        }
        if armed {
            self.sent[from] += amount;
            self.received[to] += amount;
            if self.outage != Outage::Serving {
                self.debited_while_out += 1;
            }
        }
        armed
    }

    async fn sync(&mut self, d: usize) {
        let synced = self.devices[d].sync().await;
        self.steps.push(format!(
            "{} syncs{}",
            SLOTS[d],
            if synced.success { "" } else { " (incomplete)" }
        ));
    }

    fn restart(&mut self, d: usize) {
        self.devices[d].start(&self.fleet);
        self.steps.push(format!("{} restarts", SLOTS[d]));
    }

    async fn set_outage(&mut self, outage: Outage) {
        if outage == self.outage {
            return;
        }
        self.nodes
            .restore_spools(&self.outage.failed_spools())
            .await;
        self.nodes.bring_up(&self.outage.down()).await;
        self.nodes.fail_spools(&outage.failed_spools()).await;
        self.nodes.take_down(&outage.down()).await;
        self.steps.push(format!("outage {outage:?}"));
        self.outage = outage;
    }

    fn held(&self) -> Vec<u64> {
        self.devices.iter().map(TestDevice::era_balance).collect()
    }

    /// The bounds every step keeps.
    fn check(&self) {
        let held = self.held();
        for (i, now) in held.iter().enumerate() {
            let floor = i128::from(self.initial[i]) - i128::from(self.sent[i]);
            let ceiling = floor + i128::from(self.received[i]);
            let now = i128::from(*now);
            assert!(
                now >= floor,
                "{}: {} holds {now}, less than it started with less what it sent ({floor})",
                self.trail(),
                SLOTS[i]
            );
            assert!(
                now <= ceiling,
                "{}: {} holds {now}, more than it started with less what it sent plus what was \
                 sent to it ({ceiling})",
                self.trail(),
                SLOTS[i]
            );
        }
        assert!(
            held.iter().sum::<u64>() <= self.initial.iter().sum::<u64>(),
            "{}: the devices hold more than they started with",
            self.trail()
        );
    }

    fn snapshot(&self) -> Snapshot {
        let mut tips = Vec::new();
        for me in &self.devices {
            for peer in self
                .devices
                .iter()
                .filter(|peer| peer.device_id != me.device_id)
            {
                me.enter();
                tips.push(cdb::get_contact_chain_tip(&peer.device_id).expect("the tip reads"));
            }
        }
        Snapshot {
            held: self.held(),
            tips,
        }
    }

    /// What `me` and `peer` hold of their relationship, for a failure's
    /// message: `me`'s pending admission and proposals, and what `peer` has
    /// applied and staged from `me`.
    fn diagnose(me: &TestDevice, peer: &TestDevice) -> String {
        let rel = me.rel_key_with(peer);
        me.enter();
        let pending = me
            .router()
            .core_sdk
            .device_head()
            .and_then(|head| head.pending_economic_admission().cloned());
        let proposals = super::proposal_statuses(&rel);
        peer.enter();
        let applied = super::rows_for_relationship("canonical_apply_identity", &rel);
        let staged =
            cdb::recipient_staging::unbound_transfer_count(&me.device_id).expect("staging reads");
        let receipts =
            cdb::recipient_staging::unbound_receipt_count(&me.device_id).expect("staging reads");
        let awaits = cdb::relationship_awaits_peer_finalization(&rel).expect("awaits reads");
        format!(
            "{} admission pending: {}; proposals {proposals:?}; {} applied {applied}, \
             unbound transfers {staged}, unbound receipts {receipts}, awaits {awaits}",
            me.slot,
            pending.is_some(),
            peer.slot
        )
    }

    /// Every ordered pair whose sender is not send-ready, and why.
    fn not_send_ready(&self) -> Vec<String> {
        let mut blocked = Vec::new();
        for me in &self.devices {
            for peer in self
                .devices
                .iter()
                .filter(|peer| peer.device_id != me.device_id)
            {
                me.enter();
                let status = super::send_status(peer);
                if !status.send_ready {
                    blocked.push(format!(
                        "{}->{}: {} [{}]",
                        me.slot,
                        peer.slot,
                        status.send_block_message,
                        Self::diagnose(me, peer)
                    ));
                }
            }
        }
        blocked
    }

    /// Every member serving, rounds of syncs until a round moves nothing,
    /// then the at-rest checks.
    async fn come_to_rest(&mut self) {
        self.set_outage(Outage::Serving).await;
        let mut last = self.snapshot();
        for round in 0..REST_ROUNDS {
            for device in &self.devices {
                let synced = device.sync().await;
                assert!(
                    synced.success,
                    "{}: {} syncs with every member serving: {:?}",
                    self.trail(),
                    device.slot,
                    synced.errors
                );
            }
            let now = self.snapshot();
            let blocked = self.not_send_ready();
            if now == last && blocked.is_empty() {
                break;
            }
            assert!(
                round + 1 < REST_ROUNDS,
                "{}: the network did not come to rest; still moving: {}; not send-ready: {:?}",
                self.trail(),
                now != last,
                blocked
            );
            last = now;
        }
        self.steps.push("at rest".to_string());
        for (i, now) in self.held().iter().enumerate() {
            assert_eq!(
                i128::from(*now),
                i128::from(self.initial[i]) - i128::from(self.sent[i])
                    + i128::from(self.received[i]),
                "{}: at rest {} holds what it started with, less what it sent, plus what was \
                 sent to it",
                self.trail(),
                SLOTS[i]
            );
        }
        for (i, me) in self.devices.iter().enumerate() {
            for peer in &self.devices[i + 1..] {
                me.enter();
                let mine = cdb::get_contact_chain_tip(&peer.device_id).expect("the tip reads");
                peer.enter();
                let theirs = cdb::get_contact_chain_tip(&me.device_id).expect("the tip reads");
                assert_eq!(
                    mine,
                    theirs,
                    "{}: {} and {} hold one tip",
                    self.trail(),
                    me.slot,
                    peer.slot
                );
                for (a, b) in [(me, peer), (peer, me)] {
                    a.enter();
                    let status = super::send_status(b);
                    assert!(
                        status.send_ready,
                        "{}: {} is send-ready toward {}: {}",
                        self.trail(),
                        a.slot,
                        b.slot,
                        status.send_block_message
                    );
                }
            }
        }
    }
}

/// Four devices, five real nodes, a seeded schedule of sends, syncs, failed
/// spools, node crashes and device restarts in four phases, each opened with
/// another kind of outage; each step keeps the bounds, each phase comes to
/// rest with every send applied once and every relationship on one tip, and
/// afterwards every relationship carries a transfer each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn many_devices_conserve_value_and_settle_under_outages_crashes_and_restarts() {
    let mut mesh = Mesh::boot().await;
    let n = mesh.devices.len();
    let members = economic_fixtures::canonical_member_ids();
    let mut rng = Rng(0x4D45_5348_0001);
    let openings = [
        Outage::SpoolFailed(members[rng.below(members.len())].clone()),
        Outage::Down(members[rng.below(members.len())].clone()),
        Outage::SpoolsFailedPastQuorum,
        Outage::DownPastQuorum,
    ];
    for (phase, opening) in openings.into_iter().enumerate() {
        mesh.steps.push(format!("phase {phase}"));
        mesh.set_outage(opening).await;
        for _ in 0..STEPS_PER_PHASE {
            match rng.below(10) {
                0..=4 => {
                    let from = rng.below(n);
                    let to = (from + 1 + rng.below(n - 1)) % n;
                    let held = mesh.devices[from].era_balance();
                    if held == 0 {
                        mesh.sync(from).await;
                    } else {
                        let most = usize::try_from(held.min(MAX_SEND)).expect("small");
                        let amount = u64::try_from(1 + rng.below(most)).expect("small");
                        mesh.send(from, to, amount).await;
                    }
                }
                5 | 6 => mesh.sync(rng.below(n)).await,
                7 => {
                    let member = members[rng.below(members.len())].clone();
                    let outage = match rng.below(2) {
                        0 => Outage::SpoolFailed(member),
                        _ => Outage::Down(member),
                    };
                    mesh.set_outage(outage).await;
                }
                8 => {
                    let outage = match rng.below(3) {
                        0 => Outage::SpoolsFailedPastQuorum,
                        1 => Outage::DownPastQuorum,
                        _ => Outage::Serving,
                    };
                    mesh.set_outage(outage).await;
                }
                _ => mesh.restart(rng.below(n)),
            }
            mesh.check();
        }
        mesh.come_to_rest().await;
    }
    println!(
        "[many devices] sent {:?}, received {:?}, {} debited while a member was out; steps: {}",
        mesh.sent,
        mesh.received,
        mesh.debited_while_out,
        mesh.steps.join("; ")
    );
    assert!(
        mesh.debited_while_out >= 4,
        "the schedule debited only {} sends while a member was out",
        mesh.debited_while_out
    );
    // A transfer each way on every relationship: first every pair from the
    // lower device to the higher, then back, so no device sends to a peer
    // whose transfer it has just taken up and awaits the finality of. A
    // device that holds nothing yet sends after a rest, once paid.
    for back in [0, 1] {
        let mut owed: Vec<(usize, usize)> = (0..n)
            .flat_map(|low| (low + 1..n).map(move |high| (low, high)))
            .map(|(low, high)| if back == 0 { (low, high) } else { (high, low) })
            .collect();
        while !owed.is_empty() {
            let mut later = Vec::new();
            for (from, to) in owed.iter().copied() {
                if mesh.devices[from].era_balance() == 0 {
                    later.push((from, to));
                    continue;
                }
                let debited = mesh.send(from, to, 1).await;
                assert!(
                    debited,
                    "{}: at rest, {} sends {} one unit",
                    mesh.trail(),
                    SLOTS[from],
                    SLOTS[to]
                );
                mesh.check();
            }
            mesh.come_to_rest().await;
            assert!(
                later.len() < owed.len(),
                "{}: no device that holds nothing was paid",
                mesh.trail()
            );
            owed = later;
        }
    }
}
