// SPDX-License-Identifier: MIT OR Apache-2.0

//! Model-to-code correspondence for the bilateral models (MR-DSM-0267, DSM
//! Amendment A23, G3 ruling B9): each test drives the production offline
//! protocol — real devices on real nodes, each with its own database, wallet,
//! router and anchor appliance, every frame carried as bytes through the
//! production handler — through a model's actions, and compares what the
//! devices hold with what the model holds after every step.

use std::collections::{BTreeSet, HashMap};

use super::{bearer_transfer, history_row_exists, OfflineDevice};
use crate::economic_fixtures;
use crate::test_support::appliance::{HostAppliance, InstalledAppliances};
use crate::test_support::nodes::NodeSet;
use crate::test_support::two_device::TestDevice;

/// Devices on one fleet, every relationship the test names established and
/// each listed device's offline allocation loaded under its own anchor, its
/// counterparties having validated its online history through the load.
struct World {
    devices: Vec<OfflineDevice>,
    _appliances: InstalledAppliances,
    _fleet: economic_fixtures::FleetGuard,
    _nodes: NodeSet,
    _poller: crate::sdk::inbox_poller::PollerHold,
}

impl World {
    async fn boot(
        slots: &[(&'static str, u8)],
        relationships: &[(usize, usize)],
        loaded: &[usize],
    ) -> Self {
        let poller = crate::sdk::inbox_poller::hold_off_for_two_device_harness().await;
        economic_fixtures::use_test_storage_dir();
        crate::storage::client_db::reset_database_for_tests();
        let nodes = NodeSet::start().await;
        let fleet = economic_fixtures::point_sdk_at(&nodes.members(), nodes.ca_pem());
        let mut devices: Vec<TestDevice> = slots
            .iter()
            .map(|(slot, seed)| TestDevice::create(slot, *seed))
            .collect();
        for device in devices.iter_mut() {
            device.boot(&fleet).await;
        }
        for (i, j) in relationships {
            devices[*i].add_contact(&devices[*j]).await;
            devices[*j].add_contact(&devices[*i]).await;
        }
        for device in &devices {
            device.fund_admitted(100).await;
        }
        let appliances = HostAppliance::install_each(
            devices
                .iter()
                .enumerate()
                .map(|(n, device)| {
                    let seed = [0xC0 + u8::try_from(n).expect("a handful of devices"); 32];
                    (device.device_id, HostAppliance::birth(device, seed, 64))
                })
                .collect(),
        );
        let offline: Vec<OfflineDevice> = devices.iter().map(OfflineDevice::new).collect();
        for &i in loaded {
            offline[i].device.enter();
            let load = offline[i]
                .device
                .invoke(
                    "wallet.loadOffline",
                    &crate::generated::OfflineCashRequest {
                        token_id: "ERA".to_string(),
                        amount: "20.00".to_string(),
                    },
                )
                .await;
            assert!(load.success, "the load: {:?}", load.error_message);
            let (genesis, devid) = {
                let head = offline[i]
                    .device
                    .router()
                    .core_sdk
                    .device_head()
                    .expect("the device's head");
                (head.genesis_digest(), head.devid())
            };
            let loaded_at = economic_fixtures::admitted_position().expect("activated");
            for (a, b) in relationships {
                let counterparty = if *b == i {
                    *a
                } else if *a == i {
                    *b
                } else {
                    continue;
                };
                offline[counterparty].device.enter();
                economic_fixtures::foreign_walk(genesis, devid, loaded_at).await;
            }
        }
        Self {
            devices: offline,
            _appliances: appliances,
            _fleet: fleet,
            _nodes: nodes,
            _poller: poller,
        }
    }

    fn id(&self, d: usize) -> [u8; 32] {
        self.devices[d].device.device_id
    }
}

/// The payload a frame's envelope carries, by the one name the handler's
/// match arms give it.
fn payload_of(frame: &[u8]) -> &'static str {
    use crate::generated::envelope::Payload;
    match crate::envelope::from_canonical_bytes(frame)
        .expect("a frame the handler wrote decodes")
        .payload
    {
        Some(Payload::UniversalTx(_)) => "transaction",
        Some(Payload::BilateralPrepareResponse(_)) => "response",
        Some(Payload::BilateralPrepareReject(_)) => "rejection",
        Some(Payload::BilateralCommitResponse(_)) => "ack",
        other => panic!("a frame the offline protocol does not send: {other:?}"),
    }
}

/// The model's kind of an owed frame.
fn kind_of(kind: crate::bluetooth::bilateral_session::OfflineFrameKind) -> Kind {
    use crate::bluetooth::bilateral_session::OfflineFrameKind;
    match kind {
        OfflineFrameKind::Prepare => Kind::Prepare,
        OfflineFrameKind::PrepareResponse => Kind::Response,
        OfflineFrameKind::Confirm => Kind::Confirm,
    }
}

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

// ---------------------------------------------------------------------------
// tla/DSM_OfflineFinality.tla, its checked configuration: two devices, one
// step each, a balance of one, every implementation switch set as the code.
// Step `s` is device `s`'s step; its receiver is the other device. With
// `LinkLossFailsNothing` set, no action reaches the model's `Failed`.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ph {
    None,
    Prepared,
    ConfirmPending,
    PendingUser,
    Accepted,
    Rejected,
    Ended,
    Committed,
}

impl Ph {
    fn in_flight(self) -> bool {
        matches!(
            self,
            Ph::Prepared | Ph::ConfirmPending | Ph::PendingUser | Ph::Accepted
        )
    }

    /// The phase a device stores for the step. The model tells the side that
    /// ended a step without committing (`Rejected`) from the side told
    /// (`Ended`); a device stores both as its rejection. A committed step
    /// keeps no session: its history row is what the device holds of it.
    fn stored(self) -> Option<&'static str> {
        match self {
            Ph::None | Ph::Committed => None,
            Ph::Prepared => Some("prepared"),
            Ph::PendingUser => Some("pending_user_action"),
            Ph::Accepted => Some("accepted"),
            Ph::ConfirmPending => Some("confirm_pending"),
            Ph::Rejected | Ph::Ended => Some("rejected"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Kind {
    Prepare,
    Response,
    Reject,
    Cancel,
    Confirm,
    Ack,
}

/// Which of the model's actions a trace takes: any, or, once its exploring
/// budget is spent, only those that make progress (the fairness the model's
/// `SessionTermination` assumes, with the link staying up).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Explore,
    Settle,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Link {
    Up,
    Down,
}

#[derive(Clone, Debug)]
struct Fin {
    chain: [Vec<usize>; 2],
    phase: [[Ph; 2]; 2],
    parent: [Option<usize>; 2],
    net: BTreeSet<(Kind, usize)>,
    link: Link,
}

#[derive(Clone, Copy, Debug)]
enum Act {
    Propose(usize),
    RecvPrepare(usize),
    UserAccept(usize),
    UserReject(usize),
    RecvResponse(usize),
    RecvReject(usize),
    Cancel(usize),
    RecvCancel(usize),
    RecvConfirm(usize),
    RecvAck(usize),
    Resend(usize, usize),
    LinkDown,
    LinkUp,
    /// A device restarts: the model's state is unchanged (every phase is
    /// durable before its frame leaves, and the frames in the air are the
    /// carrier's), so this is a stutter the code must match.
    Restart(usize),
}

/// An action that ends a step without its commit.
fn ends_early(act: Act) -> bool {
    matches!(act, Act::Cancel(_) | Act::UserReject(_))
}

fn proposer(s: usize) -> usize {
    s
}

fn receiver(s: usize) -> usize {
    1 - s
}

impl Fin {
    fn init() -> Self {
        Fin {
            chain: [Vec::new(), Vec::new()],
            phase: [[Ph::None; 2]; 2],
            parent: [None, None],
            net: BTreeSet::new(),
            link: Link::Up,
        }
    }

    fn tip(&self, d: usize) -> usize {
        self.chain[d].len()
    }

    fn in_chain(&self, d: usize, s: usize) -> bool {
        self.chain[d].contains(&s)
    }

    fn in_flight(&self, d: usize) -> bool {
        self.phase[d].iter().any(|p| p.in_flight())
    }

    fn balance(&self, d: usize) -> usize {
        let own = self.chain[d].iter().filter(|s| proposer(**s) == d).count();
        let received = self.chain[d].len() - own;
        1 + received - own
    }

    fn owed(&self, d: usize, s: usize) -> Option<Kind> {
        match self.phase[d][s] {
            Ph::Prepared => Some(Kind::Prepare),
            Ph::Accepted => Some(Kind::Response),
            Ph::ConfirmPending => Some(Kind::Confirm),
            _ => None,
        }
    }

    fn linked(&self) -> bool {
        self.link == Link::Up
    }

    /// Every step proposed, or its proposer unable to propose it.
    fn proposed(&self) -> bool {
        (0..2).all(|s| self.parent[s].is_some() || self.in_flight(proposer(s)))
    }

    fn settled(&self) -> bool {
        !self.in_flight(0) && !self.in_flight(1)
    }

    fn enabled(&self, mode: Mode) -> Vec<Act> {
        let explore = mode == Mode::Explore;
        let mut acts = Vec::new();
        let linked = self.linked();
        for s in 0..2 {
            let (p, r) = (proposer(s), receiver(s));
            if explore
                && self.phase[p][s] == Ph::None
                && self.parent[s].is_none()
                && !self.in_flight(p)
                && self.balance(p) >= 1
            {
                acts.push(Act::Propose(s));
            }
            if self.phase[r][s] == Ph::PendingUser {
                acts.push(Act::UserAccept(s));
                if explore {
                    acts.push(Act::UserReject(s));
                }
            }
            if explore && self.phase[p][s] == Ph::Prepared {
                acts.push(Act::Cancel(s));
            }
            for (kind, act) in [
                (Kind::Prepare, Act::RecvPrepare(s)),
                (Kind::Response, Act::RecvResponse(s)),
                (Kind::Reject, Act::RecvReject(s)),
                (Kind::Cancel, Act::RecvCancel(s)),
                (Kind::Confirm, Act::RecvConfirm(s)),
                (Kind::Ack, Act::RecvAck(s)),
            ] {
                if linked && self.net.contains(&(kind, s)) {
                    acts.push(act);
                }
            }
            for d in 0..2 {
                if let Some(kind) = self.owed(d, s) {
                    if linked && !self.net.contains(&(kind, s)) {
                        acts.push(Act::Resend(d, s));
                    }
                }
            }
        }
        match (self.link, mode) {
            (Link::Up, Mode::Explore) => acts.push(Act::LinkDown),
            (Link::Down, _) => acts.push(Act::LinkUp),
            (Link::Up, Mode::Settle) => {}
        }
        if explore {
            acts.push(Act::Restart(0));
            acts.push(Act::Restart(1));
        }
        acts
    }

    fn emit(&mut self, kind: Kind, s: usize) {
        if self.linked() {
            self.net.insert((kind, s));
        }
    }

    /// `m` delivered and answered with `answer`, or consumed.
    fn take(&mut self, m: (Kind, usize), answer: Option<Kind>) -> Option<Kind> {
        self.net.remove(&m);
        if let Some(kind) = answer {
            self.net.insert((kind, m.1));
        }
        answer
    }

    /// Apply `act`; the frame kind the code must answer a delivery with, or
    /// emit for a local action.
    fn apply(&mut self, act: Act) -> Option<Kind> {
        match act {
            Act::Propose(s) => {
                let p = proposer(s);
                self.phase[p][s] = Ph::Prepared;
                self.parent[s] = Some(self.tip(p));
                self.emit(Kind::Prepare, s);
                Some(Kind::Prepare)
            }
            Act::RecvPrepare(s) => {
                let r = receiver(s);
                let answer = match self.phase[r][s] {
                    Ph::Accepted => Some(Kind::Response),
                    Ph::Rejected => Some(Kind::Reject),
                    Ph::Ended => Some(Kind::Cancel),
                    Ph::None if self.in_flight(r) => {
                        self.phase[r][s] = Ph::Rejected;
                        Some(Kind::Reject)
                    }
                    Ph::None if Some(self.tip(r)) != self.parent[s] => Some(Kind::Reject),
                    Ph::None => {
                        self.phase[r][s] = Ph::PendingUser;
                        None
                    }
                    _ => None,
                };
                self.take((Kind::Prepare, s), answer)
            }
            Act::UserAccept(s) => {
                self.phase[receiver(s)][s] = Ph::Accepted;
                self.emit(Kind::Response, s);
                Some(Kind::Response)
            }
            Act::UserReject(s) => {
                self.phase[receiver(s)][s] = Ph::Rejected;
                self.emit(Kind::Reject, s);
                Some(Kind::Reject)
            }
            Act::RecvResponse(s) => {
                let p = proposer(s);
                let answer = match self.phase[p][s] {
                    Ph::Prepared if Some(self.tip(p)) == self.parent[s] => {
                        self.chain[p].push(s);
                        self.phase[p][s] = Ph::ConfirmPending;
                        Some(Kind::Confirm)
                    }
                    Ph::ConfirmPending => Some(Kind::Confirm),
                    Ph::Rejected => Some(Kind::Cancel),
                    Ph::Ended => Some(Kind::Reject),
                    _ => None,
                };
                self.take((Kind::Response, s), answer)
            }
            Act::RecvReject(s) => {
                let p = proposer(s);
                if self.phase[p][s] == Ph::Prepared {
                    self.phase[p][s] = Ph::Ended;
                }
                self.take((Kind::Reject, s), None)
            }
            Act::Cancel(s) => {
                self.phase[proposer(s)][s] = Ph::Rejected;
                self.emit(Kind::Cancel, s);
                Some(Kind::Cancel)
            }
            Act::RecvCancel(s) => {
                let r = receiver(s);
                if matches!(self.phase[r][s], Ph::PendingUser | Ph::Accepted) {
                    self.phase[r][s] = Ph::Ended;
                }
                self.take((Kind::Cancel, s), None)
            }
            Act::RecvConfirm(s) => {
                let r = receiver(s);
                let answer = match self.phase[r][s] {
                    Ph::Accepted if Some(self.tip(r)) == self.parent[s] => {
                        self.chain[r].push(s);
                        self.phase[r][s] = Ph::Committed;
                        Some(Kind::Ack)
                    }
                    Ph::Committed => Some(Kind::Ack),
                    _ => None,
                };
                self.take((Kind::Confirm, s), answer)
            }
            Act::RecvAck(s) => {
                let p = proposer(s);
                match self.phase[p][s] {
                    Ph::ConfirmPending if self.in_chain(p, s) => {
                        self.phase[p][s] = Ph::Committed;
                    }
                    Ph::ConfirmPending if Some(self.tip(p)) == self.parent[s] => {
                        self.chain[p].push(s);
                        self.phase[p][s] = Ph::Committed;
                    }
                    _ => {}
                }
                self.take((Kind::Ack, s), None)
            }
            Act::Resend(d, s) => {
                let kind = self
                    .owed(d, s)
                    .expect("Resend is enabled only for an owed frame");
                self.net.insert((kind, s));
                Some(kind)
            }
            Act::LinkDown => {
                self.link = Link::Down;
                self.net.clear();
                None
            }
            Act::LinkUp => {
                self.link = Link::Up;
                None
            }
            Act::Restart(_) => None,
        }
    }
}

/// The code's side of one trace: the two devices, each step's commitment once
/// proposed, the bytes of the last frame of each kind the code wrote for each
/// step, and the relationship tip after each commit of the trace.
struct FinCode<'w> {
    world: &'w mut World,
    amount: u64,
    commitment: [Option<[u8; 32]>; 2],
    frames: HashMap<(Kind, usize), Vec<u8>>,
    tips: Vec<[u8; 32]>,
}

impl FinCode<'_> {
    fn dev(&self, d: usize) -> &OfflineDevice {
        &self.world.devices[d]
    }

    fn c(&self, s: usize) -> [u8; 32] {
        self.commitment[s].expect("the step was proposed")
    }

    fn frame(&self, kind: Kind, s: usize) -> Vec<u8> {
        match self.frames.get(&(kind, s)) {
            Some(frame) => frame.clone(),
            None => panic!("the code wrote no {kind:?} for step {s}"),
        }
    }

    /// A signed ending of step `s`: the receiver's rejection, or the
    /// proposer's cancellation, by who signed it.
    fn ending_kind(&self, frame: &[u8], s: usize) -> Kind {
        use crate::generated::envelope::Payload;
        let Some(Payload::BilateralPrepareReject(reject)) =
            crate::envelope::from_canonical_bytes(frame)
                .expect("a frame the handler wrote decodes")
                .payload
        else {
            panic!("an ending is a signed rejection");
        };
        if reject.rejector_device_id.as_slice() == self.world.id(receiver(s)).as_slice() {
            Kind::Reject
        } else if reject.rejector_device_id.as_slice() == self.world.id(proposer(s)).as_slice() {
            Kind::Cancel
        } else {
            panic!("an ending signed by neither device of step {s}");
        }
    }

    /// Make `act` through the production handler; the kind of the frame the
    /// code answered or emitted, if any.
    async fn make(&mut self, act: Act, why: &mut Vec<String>) -> Option<Kind> {
        match act {
            Act::Propose(s) => {
                let (p, r) = (proposer(s), receiver(s));
                self.dev(p).device.enter();
                let proposal = bearer_transfer(self.dev(r), self.amount);
                let (prepare, commitment) = self
                    .dev(p)
                    .propose(self.dev(r), proposal)
                    .await
                    .expect("the model's proposal is made");
                self.commitment[s] = Some(commitment);
                self.frames.insert((Kind::Prepare, s), prepare);
                Some(Kind::Prepare)
            }
            Act::RecvPrepare(s) => {
                let r = receiver(s);
                self.dev(r).device.enter();
                let frame = self.frame(Kind::Prepare, s);
                match self
                    .dev(r)
                    .handler
                    .handle_prepare_request(&frame, None)
                    .await
                {
                    Ok((answer, _)) if answer.is_empty() => None,
                    Ok((answer, _)) => {
                        let kind = match payload_of(&answer) {
                            "response" => Kind::Response,
                            "rejection" => self.ending_kind(&answer, s),
                            other => panic!("a prepare answered with a {other}"),
                        };
                        self.frames.insert((kind, s), answer);
                        Some(kind)
                    }
                    Err(e) => {
                        why.push(format!("prepare {s}: {e}"));
                        None
                    }
                }
            }
            Act::UserAccept(s) => {
                let r = receiver(s);
                self.dev(r).device.enter();
                let response = self
                    .dev(r)
                    .handler
                    .create_prepare_accept_envelope(self.c(s))
                    .await
                    .expect("the user accepts a proposal awaiting it");
                self.frames.insert((Kind::Response, s), response);
                Some(Kind::Response)
            }
            Act::UserReject(s) => {
                let r = receiver(s);
                self.dev(r).device.enter();
                let rejection = self
                    .dev(r)
                    .handler
                    .create_prepare_reject_envelope_with_cleanup(self.c(s), "model".to_string())
                    .await
                    .expect("the user rejects a proposal awaiting it");
                self.frames.insert((Kind::Reject, s), rejection);
                Some(Kind::Reject)
            }
            Act::RecvResponse(s) => {
                let p = proposer(s);
                self.dev(p).device.enter();
                let frame = self.frame(Kind::Response, s);
                match self.dev(p).handler.handle_prepare_response(&frame).await {
                    Ok((answer, _)) if answer.is_empty() => None,
                    Ok((answer, _)) => {
                        let kind = match payload_of(&answer) {
                            "transaction" => Kind::Confirm,
                            "rejection" => self.ending_kind(&answer, s),
                            other => panic!("a response answered with a {other}"),
                        };
                        self.frames.insert((kind, s), answer);
                        Some(kind)
                    }
                    Err(e) => {
                        why.push(format!("response {s}: {e}"));
                        None
                    }
                }
            }
            Act::RecvReject(s) | Act::RecvCancel(s) => {
                let (d, kind) = match act {
                    Act::RecvReject(_) => (proposer(s), Kind::Reject),
                    _ => (receiver(s), Kind::Cancel),
                };
                self.dev(d).device.enter();
                let frame = self.frame(kind, s);
                if let Err(e) = self.dev(d).handler.handle_prepare_reject(&frame).await {
                    why.push(format!("{kind:?} {s}: {e}"));
                }
                None
            }
            Act::Cancel(s) => {
                let p = proposer(s);
                self.dev(p).device.enter();
                let cancellation = self
                    .dev(p)
                    .handler
                    .cancel_proposal(self.c(s), "model".to_string())
                    .await
                    .expect("a proposal not yet confirmed is cancelled");
                self.frames.insert((Kind::Cancel, s), cancellation);
                Some(Kind::Cancel)
            }
            Act::RecvConfirm(s) => {
                let r = receiver(s);
                self.dev(r).device.enter();
                let frame = self.frame(Kind::Confirm, s);
                match self.dev(r).handler.handle_confirm_request(&frame).await {
                    Ok(answer) if answer.is_empty() => None,
                    Ok(answer) => {
                        assert_eq!(
                            payload_of(&answer),
                            "ack",
                            "a confirm is answered by its ack"
                        );
                        self.frames.insert((Kind::Ack, s), answer);
                        Some(Kind::Ack)
                    }
                    Err(e) => {
                        why.push(format!("confirm {s}: {e}"));
                        None
                    }
                }
            }
            Act::RecvAck(s) => {
                let p = proposer(s);
                self.dev(p).device.enter();
                let frame = self.frame(Kind::Ack, s);
                if let Err(e) = self.dev(p).handler.handle_commit_response(&frame).await {
                    why.push(format!("ack {s}: {e}"));
                }
                None
            }
            Act::Resend(d, s) => {
                self.dev(d).device.enter();
                let peer = self.world.id(1 - d);
                let owed = self.dev(d).handler.frames_owed_to(&peer).await;
                let Some(frame) = owed.into_iter().find(|f| f.commitment_hash == self.c(s)) else {
                    panic!("device {d} owes no frame for step {s}");
                };
                let kind = kind_of(frame.kind);
                self.frames.insert((kind, s), frame.bytes);
                Some(kind)
            }
            Act::LinkDown | Act::LinkUp => None,
            Act::Restart(d) => {
                let restarted = self.world.devices[d].restarted().await;
                self.world.devices[d] = restarted;
                None
            }
        }
    }

    /// The model's disabled endings, attempted: a proposer's cancellation
    /// past its confirm (`CancelOnlyBeforeConfirm`) and a user's rejection
    /// of a proposal it already accepted. The code refuses each.
    async fn probe_disabled(&mut self, fin: &Fin, at: &str) {
        for s in 0..2 {
            let Some(c) = self.commitment[s] else {
                continue;
            };
            let (p, r) = (proposer(s), receiver(s));
            if matches!(fin.phase[p][s], Ph::ConfirmPending | Ph::Committed) {
                self.dev(p).device.enter();
                if let Ok(frame) = self
                    .dev(p)
                    .handler
                    .cancel_proposal(c, "probe".to_string())
                    .await
                {
                    panic!(
                        "{at}: step {s} cancelled past its confirm ({} bytes)",
                        frame.len()
                    );
                }
            }
            if matches!(fin.phase[r][s], Ph::Accepted | Ph::Committed) {
                self.dev(r).device.enter();
                if let Ok(frame) = self
                    .dev(r)
                    .handler
                    .create_prepare_reject_envelope_with_cleanup(c, "probe".to_string())
                    .await
                {
                    panic!(
                        "{at}: step {s} rejected after its acceptance ({} bytes)",
                        frame.len()
                    );
                }
            }
        }
    }

    /// What the devices hold, compared with the model.
    async fn compare(&mut self, fin: &Fin, at: &str) {
        for d in 0..2 {
            let peer = self.world.id(1 - d);
            self.dev(d).device.enter();
            for s in 0..2 {
                let Some(c) = self.commitment[s] else {
                    assert!(
                        fin.phase[d][s] == Ph::None,
                        "{at}: an unproposed step has a phase"
                    );
                    continue;
                };
                let stored = crate::storage::client_db::get_bilateral_session(&c)
                    .expect("read the session")
                    .map(|session| session.phase);
                assert_eq!(
                    stored.as_deref(),
                    fin.phase[d][s].stored(),
                    "{at}: device {d}'s phase for step {s}; model {fin:?}"
                );
                assert_eq!(
                    history_row_exists(&c),
                    fin.in_chain(d, s),
                    "{at}: device {d} holds step {s} committed; model {fin:?}"
                );
            }
            let owed: BTreeSet<(Kind, usize)> = self
                .dev(d)
                .handler
                .frames_owed_to(&peer)
                .await
                .into_iter()
                .filter_map(|f| {
                    let s = (0..2).find(|s| self.commitment[*s] == Some(f.commitment_hash))?;
                    Some((kind_of(f.kind), s))
                })
                .collect();
            let model_owed: BTreeSet<(Kind, usize)> = (0..2)
                .filter_map(|s| fin.owed(d, s).map(|kind| (kind, s)))
                .collect();
            assert_eq!(
                owed, model_owed,
                "{at}: what device {d} owes; model {fin:?}"
            );
            let tip = self.dev(d).tip_with(&self.world.devices[1 - d]);
            let n = fin.tip(d);
            if self.tips.len() == n {
                self.tips.push(tip);
            }
            assert_eq!(
                tip, self.tips[n],
                "{at}: device {d}'s tip after {n} commits"
            );
        }
    }
}

/// MR-DSM-0267 (G3 ruling B9): the offline protocol refines
/// `tla/DSM_OfflineFinality.tla` in its checked configuration — two devices,
/// one step each, every implementation switch as the code sets it — along 32
/// seeded traces of the model's `Next` made by the production handlers of two
/// real devices on real nodes, each with its own anchor appliance and offline
/// allocation, every frame carried as bytes. A delivery is the model's
/// message taken from its bag; a lost link empties the bag; a restart (a
/// stutter in the model) rebuilds a device's handler from its storage. After
/// every step each device's stored phase for each step, the steps it holds
/// committed, its relationship tip and the frames it owes are the model's, and
/// every frame the code answers or emits is the kind the model's action does.
/// Each trace then runs only the model's progress actions — the link up, every
/// frame delivered, every owed frame sent again, every waiting user accepting
/// — until no step is in flight (`SessionTermination`). After every step the
/// endings the model disables are attempted too — a cancellation past the
/// confirm, a rejection after the acceptance — and each is refused with
/// nothing changed.
/// MUTATION CONTROL: the receiver taking a proposal while a step of its own
/// is in flight (the model's `ReceiverRefusesWhileInFlight`), or a
/// cancellation after the confirm (`CancelOnlyBeforeConfirm`), turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_offline_session_refines_the_offline_finality_model() {
    let mut world = World::boot(&[("A", 0x0A), ("B", 0x0B)], &[(0, 1)], &[0, 1]).await;
    let mut kinds_seen = BTreeSet::new();
    for trace in 0..32u64 {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (trace + 1).wrapping_mul(0xD1B5_4A32_D192_ED03));
        let mut fin = Fin::init();
        let mut code = FinCode {
            world: &mut world,
            amount: 1 + trace,
            commitment: [None, None],
            frames: HashMap::new(),
            tips: Vec::new(),
        };
        let mut why = Vec::new();
        code.compare(&fin, &format!("trace {trace}, start")).await;
        let mut step = 0usize;
        loop {
            let mode = if step < 30 {
                Mode::Explore
            } else {
                Mode::Settle
            };
            // Both steps ended or never proposed and nothing in the air: what
            // is left is only a lost link or a restart.
            if fin.settled() && fin.linked() && fin.net.is_empty() && fin.proposed() {
                break;
            }
            let mut acts = fin.enabled(mode);
            // Restarts and lost links are offered one step in four, and
            // endings without a commit one in three, so the traces reach the
            // protocol's later phases as often as its endings.
            let disturbs = |a: &Act| matches!(a, Act::Restart(_) | Act::LinkDown);
            if rng.below(4) != 0 && acts.iter().any(|a| !disturbs(a)) {
                acts.retain(|a| !disturbs(a));
            }
            if rng.below(3) != 0 && acts.iter().any(|a| !ends_early(*a)) {
                acts.retain(|a| !ends_early(*a));
            }
            assert!(
                !acts.is_empty(),
                "trace {trace}: the model is stuck at {fin:?}"
            );
            assert!(
                step < 200,
                "trace {trace}: no settlement after 200 steps: {fin:?}"
            );
            let act = acts[rng.below(acts.len())];
            let expected = fin.apply(act);
            let made = code.make(act, &mut why).await;
            let at = format!("trace {trace}, step {step}, {act:?}");
            eprintln!("{at} -> model {expected:?}, code {made:?}; {why:?}");
            assert_eq!(made, expected, "{at}: the frame the code wrote; {why:?}");
            if let Some(kind) = made {
                kinds_seen.insert(kind);
            }
            code.compare(&fin, &at).await;
            code.probe_disabled(&fin, &at).await;
            code.compare(&fin, &format!("{at}, after the refused endings"))
                .await;
            step += 1;
        }
    }
    assert_eq!(
        kinds_seen.len(),
        6,
        "the traces reached every kind of frame: {kinds_seen:?}"
    );
}

// ---------------------------------------------------------------------------
// tla/DSM_Tripwire.tla, its checked configuration: devices d1, d2, d3, the
// relationships {d1, d2} and {d2, d3}, every device revision at most 4.
// ---------------------------------------------------------------------------

/// The model's relationships: `{d1, d2}` and `{d2, d3}`.
const TRIPWIRE_RELS: [[usize; 2]; 2] = [[0, 1], [1, 2]];

fn rel_of(x: usize, y: usize) -> usize {
    match TRIPWIRE_RELS
        .iter()
        .position(|r| r.contains(&x) && r.contains(&y))
    {
        Some(rel) => rel,
        None => panic!("{x} and {y} share no relationship"),
    }
}

/// `HonestStep` advances a tip by one; `AdversaryForkAttempt`'s strategy A
/// takes the current tip to another successor (the model's `+ 999`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Successor {
    Honest,
    Fork,
}

impl Successor {
    fn other(self) -> Self {
        match self {
            Successor::Honest => Successor::Fork,
            Successor::Fork => Successor::Honest,
        }
    }

    fn next(self, tip: u64) -> u64 {
        match self {
            Successor::Honest => tip + 1,
            Successor::Fork => tip + 999,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Accepted {
    a: usize,
    b: usize,
    rel: usize,
    old_tip: u64,
    new_tip: u64,
    r1: u64,
    r2: u64,
}

#[derive(Clone, Debug)]
struct Tripwire {
    roots: [u64; 3],
    smt: [[u64; 2]; 3],
    ledger: Vec<Accepted>,
}

impl Tripwire {
    fn init() -> Self {
        Tripwire {
            roots: [0; 3],
            smt: [[0; 2]; 3],
            ledger: Vec::new(),
        }
    }

    /// The steps `Next` enables within the configuration's state constraint.
    fn enabled(&self) -> Vec<(usize, usize, Successor)> {
        let mut steps = Vec::new();
        for [x, y] in TRIPWIRE_RELS {
            for (a, b) in [(x, y), (y, x)] {
                if self.roots[a] < 4 && self.roots[b] < 4 {
                    steps.push((a, b, Successor::Honest));
                    steps.push((a, b, Successor::Fork));
                }
            }
        }
        steps
    }

    /// `ProcessReceipt(a, b, tip, successor(tip), roots)`: every guard holds
    /// for a step from the current tip at the current roots.
    fn step(&mut self, a: usize, b: usize, successor: Successor) {
        let rel = rel_of(a, b);
        let old_tip = self.smt[a][rel];
        assert_eq!(old_tip, self.smt[b][rel], "the two devices hold one tip");
        let new_tip = successor.next(old_tip);
        self.ledger.push(Accepted {
            a,
            b,
            rel,
            old_tip,
            new_tip,
            r1: self.roots[a],
            r2: self.roots[b],
        });
        self.roots[a] += 1;
        self.roots[b] += 1;
        self.smt[a][rel] = new_tip;
        self.smt[b][rel] = new_tip;
    }

    /// `AdversaryForkAttempt`'s strategy B from `old_tip`, which the guards
    /// refuse: some device of the relationship no longer holds it.
    fn rollback_enabled(&self, rel: usize, old_tip: u64) -> bool {
        TRIPWIRE_RELS[rel]
            .iter()
            .all(|d| self.smt[*d][rel] == old_tip)
    }
}

/// A child signed and held back: its proposer's door takes one proposal at a
/// time, so it ends the child it will not send, which its receiver never saw.
struct HeldBack {
    /// The trace it was signed in: its tip is that trace's model value.
    trace: u64,
    a: usize,
    b: usize,
    rel: usize,
    old_tip: u64,
    prepare: Vec<u8>,
    commitment: [u8; 32],
}

/// A committed step, kept to deliver its prepare again.
struct Committed {
    a: usize,
    b: usize,
    prepare: Vec<u8>,
    commitment: [u8; 32],
}

/// MR-DSM-0267 (G3 ruling B9): the offline protocol refines
/// `tla/DSM_Tripwire.tla` in its checked configuration — three real devices on
/// real nodes, A–B and B–C, each with its own anchor and allocation — along 8
/// seeded traces of the model's `Next` to its state constraint (B, in both
/// relationships, takes part in every step). Each `HonestStep` or strategy-A
/// fork is a full offline step through the production handlers, committed on
/// both devices; before it, its proposer signs the other successor of the same
/// tip and holds it back. After every step:
/// - each device's relationship tip is the model's (`CurrentRelationshipAgreement`),
///   each device's root moved exactly when the model's revision did, and every
///   step of the model's ledger is committed on both its devices;
/// - every child held back so far — a second successor of a tip some device of
///   the relationship no longer holds, the model's strategy B, which its guards
///   refuse — is refused by its receiver as stale, keeps no session and moves
///   no tip (`TripwireInvariant`, `ConsumedParentUniqueness`);
/// - every committed step's prepare delivered again is answered with nothing
///   and commits nothing again.
/// MUTATION CONTROL: the receiver deciding a proposal without comparing its
/// claimed tip with the tip it holds (Core's stale-tip arm in
/// `decide_prepare`) turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_offline_steps_refine_the_tripwire_model() {
    let world = World::boot(
        &[("A", 0x0A), ("B", 0x0B), ("C", 0x0C)],
        &[(0, 1), (1, 2)],
        &[0, 1, 2],
    )
    .await;
    let mut held_back: Vec<HeldBack> = Vec::new();
    let mut committed: Vec<Committed> = Vec::new();
    let mut amount = 1u64;
    for trace in 0..8u64 {
        let mut rng = Rng(0xA076_1D64_78BD_642F ^ (trace + 1).wrapping_mul(0xE703_7ED1_A0B4_28DB));
        let mut model = Tripwire::init();
        // Each relationship's real tip for each model tip value, and each
        // device's real root for each model revision, this trace.
        let mut tips: HashMap<(usize, u64), [u8; 32]> = HashMap::new();
        let mut roots: HashMap<(usize, u64), [u8; 32]> = HashMap::new();
        let mut ledger_commitments: Vec<[u8; 32]> = Vec::new();
        loop {
            // Compare.
            for (rel, [x, y]) in TRIPWIRE_RELS.iter().enumerate() {
                for (d, peer) in [(*x, *y), (*y, *x)] {
                    let real = world.devices[d].tip_with(&world.devices[peer]);
                    let held = *tips.entry((rel, model.smt[d][rel])).or_insert(real);
                    assert_eq!(
                        real, held,
                        "trace {trace}: device {d}'s tip on relationship {rel}"
                    );
                }
            }
            for d in 0..3 {
                world.devices[d].device.enter();
                let real = world.devices[d]
                    .device
                    .router()
                    .core_sdk
                    .device_head()
                    .expect("the device's head")
                    .root();
                let held = *roots.entry((d, model.roots[d])).or_insert(real);
                assert_eq!(
                    real, held,
                    "trace {trace}: device {d}'s root at revision {}",
                    model.roots[d]
                );
            }
            let distinct: BTreeSet<[u8; 32]> = roots.values().copied().collect();
            assert_eq!(
                distinct.len(),
                roots.len(),
                "trace {trace}: a root came back"
            );
            for (i, x) in model.ledger.iter().enumerate() {
                assert!(x.new_tip > x.old_tip, "AcceptedReceiptsAdvance");
                assert_ne!(
                    tips[&(x.rel, x.old_tip)],
                    tips[&(x.rel, x.new_tip)],
                    "trace {trace}: a committed step left its relationship's tip where it was"
                );
                for y in &model.ledger[i + 1..] {
                    if x.rel == y.rel && x.old_tip == y.old_tip {
                        assert_eq!((x.new_tip, x.r1, x.r2), (y.new_tip, y.r1, y.r2));
                    }
                }
            }
            assert_eq!(model.ledger.len(), ledger_commitments.len());
            for (step, commitment) in model.ledger.iter().zip(&ledger_commitments) {
                for d in [step.a, step.b] {
                    world.devices[d].device.enter();
                    assert!(
                        history_row_exists(commitment),
                        "trace {trace}: {step:?} on {d}"
                    );
                }
            }
            for child in &held_back {
                assert!(
                    child.trace != trace || !model.rollback_enabled(child.rel, child.old_tip),
                    "trace {trace}: a held-back child the model's guards would take"
                );
                let receiver = &world.devices[child.b];
                receiver.device.enter();
                let before = receiver.tip_with(&world.devices[child.a]);
                let (answer, _) = receiver
                    .handler
                    .handle_prepare_request(&child.prepare, None)
                    .await
                    .expect("a held-back child is answered");
                super::refused_as_stale(&answer, "a second successor of a tip moved past");
                assert!(
                    crate::storage::client_db::get_bilateral_session(&child.commitment)
                        .expect("read the session")
                        .is_none(),
                    "trace {trace}: a session kept for a held-back child"
                );
                assert!(
                    !history_row_exists(&child.commitment),
                    "trace {trace}: a fork committed"
                );
                assert_eq!(
                    receiver.tip_with(&world.devices[child.a]),
                    before,
                    "trace {trace}: a held-back child moved a tip"
                );
            }
            for step in &committed {
                let receiver = &world.devices[step.b];
                receiver.device.enter();
                let before = receiver.tip_with(&world.devices[step.a]);
                let (answer, _) = receiver
                    .handler
                    .handle_prepare_request(&step.prepare, None)
                    .await
                    .expect("a committed step's prepare is answered");
                assert!(
                    answer.is_empty(),
                    "trace {trace}: a committed step's prepare answered"
                );
                assert!(
                    history_row_exists(&step.commitment),
                    "the step stays committed"
                );
                assert_eq!(receiver.tip_with(&world.devices[step.a]), before);
            }

            let steps = model.enabled();
            if steps.is_empty() {
                break;
            }
            let (a, b, successor) = steps[rng.below(steps.len())];
            let rel = rel_of(a, b);
            let old_tip = model.smt[a][rel];

            // Each successor of this tip is a payment of its own amount. The
            // other one is signed and held back.
            let amount_of = |which: Successor| match which {
                Successor::Honest => amount,
                Successor::Fork => amount + 1,
            };
            let (sender, receiver) = (&world.devices[a], &world.devices[b]);
            sender.device.enter();
            let (other_prepare, other_commitment) = sender
                .propose(
                    receiver,
                    bearer_transfer(receiver, amount_of(successor.other())),
                )
                .await
                .expect("the held-back child is signed");
            sender
                .handler
                .cancel_proposal(other_commitment, "held back".to_string())
                .await
                .expect("its proposer ends it");
            held_back.push(HeldBack {
                trace,
                a,
                b,
                rel,
                old_tip,
                prepare: other_prepare,
                commitment: other_commitment,
            });

            // The model's step, committed on both devices.
            sender.device.enter();
            let (prepare, commitment) = sender
                .propose(receiver, bearer_transfer(receiver, amount_of(successor)))
                .await
                .expect("the model's step is proposed");
            super::deliver_and_commit(sender, receiver, &prepare, commitment).await;
            committed.push(Committed {
                a,
                b,
                prepare,
                commitment,
            });
            ledger_commitments.push(commitment);
            amount += 2;
            model.step(a, b, successor);
        }
    }
}

// ---------------------------------------------------------------------------
// tla/DSM_NonInterference.tla, its checked configuration: devices d1..d4,
// relationships {d1, d2} and {d3, d4}, two sessions, chains of at most 2, a
// balance of 2 per device. Each device is in one relationship, so its chain
// tip and balance on that relationship are its own.
// ---------------------------------------------------------------------------

/// The model's relationships.
const NI_RELS: [[usize; 2]; 2] = [[0, 1], [2, 3]];

fn ni_rel(d: usize) -> usize {
    d / 2
}

fn ni_peer(d: usize) -> usize {
    d ^ 1
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NiPh {
    Prepared,
    PendingUserAction,
    Accepted,
    Committed,
    Failed,
}

impl NiPh {
    fn in_flight(self) -> bool {
        matches!(
            self,
            NiPh::Prepared | NiPh::PendingUserAction | NiPh::Accepted
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct NiSession {
    phase: NiPh,
    sender: usize,
    receiver: usize,
    tip_at_creation: u64,
    amount: u64,
}

#[derive(Clone, Debug)]
struct NonInterference {
    chain_tip: [u64; 4],
    balance: [u64; 4],
    rel_tip: [u64; 2],
    sessions: [Option<NiSession>; 2],
}

#[derive(Clone, Copy, Debug)]
enum NiAct {
    Prepare {
        sender: usize,
        sid: usize,
        amount: u64,
    },
    Receive(usize),
    Accept(usize),
    Commit(usize),
    Fail(usize),
}

impl NonInterference {
    fn init() -> Self {
        NonInterference {
            chain_tip: [0; 4],
            balance: [2; 4],
            rel_tip: [0; 2],
            sessions: [None, None],
        }
    }

    fn enabled(&self) -> Vec<NiAct> {
        let mut acts = Vec::new();
        for sid in 0..2 {
            match self.sessions[sid] {
                None => {
                    for sender in 0..4 {
                        let busy = self.sessions.iter().flatten().any(|other| {
                            other.phase.in_flight()
                                && other.sender == sender
                                && ni_rel(other.sender) == ni_rel(sender)
                        });
                        for amount in 1..=2u64 {
                            if !busy && self.balance[sender] >= amount && self.chain_tip[sender] < 2
                            {
                                acts.push(NiAct::Prepare {
                                    sender,
                                    sid,
                                    amount,
                                });
                            }
                        }
                    }
                }
                Some(session) => match session.phase {
                    NiPh::Prepared => {
                        acts.push(NiAct::Receive(sid));
                        acts.push(NiAct::Fail(sid));
                    }
                    NiPh::PendingUserAction => {
                        acts.push(NiAct::Accept(sid));
                        acts.push(NiAct::Fail(sid));
                    }
                    NiPh::Accepted => {
                        if self.chain_tip[session.sender] == session.tip_at_creation
                            && self.chain_tip[session.sender] < 2
                            && self.chain_tip[session.receiver] < 2
                        {
                            acts.push(NiAct::Commit(sid));
                        }
                        acts.push(NiAct::Fail(sid));
                    }
                    NiPh::Committed | NiPh::Failed => {}
                },
            }
        }
        acts
    }

    fn apply(&mut self, act: NiAct) {
        match act {
            NiAct::Prepare {
                sender,
                sid,
                amount,
            } => {
                self.sessions[sid] = Some(NiSession {
                    phase: NiPh::Prepared,
                    sender,
                    receiver: ni_peer(sender),
                    tip_at_creation: self.chain_tip[sender],
                    amount,
                });
            }
            NiAct::Receive(sid) => self.set_phase(sid, NiPh::PendingUserAction),
            NiAct::Accept(sid) => self.set_phase(sid, NiPh::Accepted),
            NiAct::Commit(sid) => {
                let session = self.session(sid);
                self.set_phase(sid, NiPh::Committed);
                self.balance[session.sender] -= session.amount;
                self.balance[session.receiver] += session.amount;
                self.chain_tip[session.sender] += 1;
                self.chain_tip[session.receiver] += 1;
                self.rel_tip[ni_rel(session.sender)] += 1;
            }
            NiAct::Fail(sid) => self.set_phase(sid, NiPh::Failed),
        }
    }

    fn session(&self, sid: usize) -> NiSession {
        match self.sessions[sid] {
            Some(session) => session,
            None => panic!("session {sid} was never prepared"),
        }
    }

    fn set_phase(&mut self, sid: usize, phase: NiPh) {
        let mut session = self.session(sid);
        session.phase = phase;
        self.sessions[sid] = Some(session);
    }

    /// The model's invariants, on its own state.
    fn check(&self) {
        for (rel, devices) in NI_RELS.iter().enumerate() {
            let committed = self
                .sessions
                .iter()
                .flatten()
                .any(|s| ni_rel(s.sender) == rel && s.phase == NiPh::Committed);
            if !committed {
                assert_eq!(self.rel_tip[rel], 0, "NonInterference");
                for d in devices {
                    assert_eq!(
                        (self.chain_tip[*d], self.balance[*d]),
                        (0, 2),
                        "NonInterference"
                    );
                }
            }
            assert_eq!(
                devices.iter().map(|d| self.balance[*d]).sum::<u64>(),
                4,
                "PerPairConservation"
            );
        }
    }
}

/// The code's side of a NonInterference trace: each session's commitment,
/// its real amount and the frames its steps passed.
struct NiCode {
    commitment: [Option<[u8; 32]>; 2],
    amount: [u64; 2],
    response: [Option<Vec<u8>>; 2],
    prepare: [Option<Vec<u8>>; 2],
    /// Whether the receiver took the proposal (held it, or refused it).
    taken: [Option<()>; 2],
}

/// What a device holds of value on its relationship: its offline allocation
/// and the payments it received offline, held pending.
fn ni_value(device: &OfflineDevice) -> u64 {
    device.device.enter();
    let era = dsm::core::token::token_state_manager::era_policy_commit();
    let allocation = match device.device.router().core_sdk.offline_allocation_of(&era) {
        Some(units) => units,
        None => panic!("{}: no anchor is attached", device.device.slot),
    };
    let pending = crate::storage::client_db::offline_receipts::pending_offline_value(&era)
        .expect("the payments received offline");
    allocation + pending
}

/// MR-DSM-0267 (G3 ruling B9): the offline protocol refines
/// `tla/DSM_NonInterference.tla` in its checked configuration — four real
/// devices on real nodes, A–B and C–D, each with its own anchor and
/// allocation — along 16 seeded traces. Each trace takes the model's enabled
/// actions in a seeded order and makes each through the production handlers:
/// a proposal, its delivery, its user's acceptance, its commit (the
/// confirm and the acknowledgment), its failure (a cancellation, or its
/// user's rejection, delivered to the other side). Where the code refuses
/// an action the model allows — a proposal while the relationship has a step
/// in flight in either direction, a proposal its receiver takes while its own
/// step is in flight — the code's transition is the model's stutter or
/// `SessionFail`, which the test asserts is enabled. After every step each
/// device's tip and its value (allocation and payments held pending) are the
/// model's, each session's two stored phases are the model's phase, a
/// relationship with nothing committed holds every device of it where it
/// started (`NonInterference`, `ZeroRefreshForInactive`), and each pair's
/// value is conserved (`PerPairConservation`).
/// MUTATION CONTROL: a receiver's commit that holds no payment pending turns
/// this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_offline_steps_refine_the_non_interference_model() {
    let world = World::boot(
        &[("A", 0x0A), ("B", 0x0B), ("C", 0x0C), ("D", 0x0D)],
        &[(0, 1), (2, 3)],
        &[0, 1, 2, 3],
    )
    .await;
    let mut next_amount = 1u64;
    let mut refusals = 0usize;
    for trace in 0..16u64 {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D ^ (trace + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut model = NonInterference::init();
        let mut code = NiCode {
            commitment: [None, None],
            amount: [0, 0],
            response: [None, None],
            prepare: [None, None],
            taken: [None, None],
        };
        let start_tip: Vec<[u8; 32]> = (0..4)
            .map(|d| world.devices[d].tip_with(&world.devices[ni_peer(d)]))
            .collect();
        let start_value: Vec<u64> = world.devices.iter().map(ni_value).collect();
        let mut tips: HashMap<(usize, u64), [u8; 32]> = HashMap::new();
        for (d, tip) in start_tip.iter().enumerate() {
            tips.insert((ni_rel(d), 0), *tip);
        }
        loop {
            model.check();
            // Compare.
            for (d, start) in start_value.iter().enumerate() {
                let real = world.devices[d].tip_with(&world.devices[ni_peer(d)]);
                let held = *tips.entry((ni_rel(d), model.chain_tip[d])).or_insert(real);
                assert_eq!(real, held, "trace {trace}: device {d}'s tip; {model:?}");
                let moved: i128 = model
                    .sessions
                    .iter()
                    .enumerate()
                    .filter_map(|(sid, s)| s.map(|s| (sid, s)))
                    .filter(|(_, s)| s.phase == NiPh::Committed)
                    .map(|(sid, s)| {
                        let amount = i128::from(code.amount[sid]);
                        if s.sender == d {
                            -amount
                        } else if s.receiver == d {
                            amount
                        } else {
                            0
                        }
                    })
                    .sum();
                assert_eq!(
                    i128::from(ni_value(&world.devices[d])) - i128::from(*start),
                    moved,
                    "trace {trace}: device {d}'s value; {model:?}"
                );
            }
            for sid in 0..2 {
                let (Some(session), Some(c)) = (model.sessions[sid], code.commitment[sid]) else {
                    continue;
                };
                let expected: [Option<&str>; 2] = match session.phase {
                    NiPh::Prepared => [Some("prepared"), None],
                    NiPh::PendingUserAction => [Some("prepared"), Some("pending_user_action")],
                    NiPh::Accepted => [Some("prepared"), Some("accepted")],
                    NiPh::Committed => [None, None],
                    NiPh::Failed => [Some("rejected"), Some("rejected")],
                };
                for (side, device) in [session.sender, session.receiver].into_iter().enumerate() {
                    world.devices[device].device.enter();
                    let stored = crate::storage::client_db::get_bilateral_session(&c)
                        .expect("read the session")
                        .map(|s| s.phase);
                    // A receiver that never took the proposal holds nothing of it.
                    let expected = match (side, code.taken[sid]) {
                        (1, None) => None,
                        _ => expected[side],
                    };
                    assert_eq!(
                        stored.as_deref(),
                        expected,
                        "trace {trace}: session {sid} on device {device}; {model:?}"
                    );
                    assert_eq!(
                        history_row_exists(&c),
                        session.phase == NiPh::Committed,
                        "trace {trace}: session {sid} committed on device {device}"
                    );
                }
            }

            let acts = model.enabled();
            if acts.is_empty() {
                break;
            }
            let act = acts[rng.below(acts.len())];
            match act {
                NiAct::Prepare {
                    sender,
                    sid,
                    amount: _,
                } => {
                    let (s, r) = (&world.devices[sender], &world.devices[ni_peer(sender)]);
                    s.device.enter();
                    match s.propose(r, bearer_transfer(r, next_amount)).await {
                        Ok((prepare, commitment)) => {
                            code.commitment[sid] = Some(commitment);
                            code.prepare[sid] = Some(prepare);
                            code.amount[sid] = next_amount;
                            next_amount += 1;
                            model.apply(act);
                        }
                        Err(e) => {
                            // The relationship has a step in flight in the
                            // other direction: the code's stutter.
                            let busy =
                                model.sessions.iter().flatten().any(|o| {
                                    o.phase.in_flight() && ni_rel(o.sender) == ni_rel(sender)
                                });
                            assert!(
                                busy,
                                "trace {trace}: a proposal refused on a free relationship: {e}"
                            );
                            refusals += 1;
                        }
                    }
                }
                NiAct::Receive(sid) => {
                    let session = model.session(sid);
                    let receiver = &world.devices[session.receiver];
                    receiver.device.enter();
                    let Some(prepare) = &code.prepare[sid] else {
                        panic!("session {sid} has no prepare");
                    };
                    let (answer, _) = receiver
                        .handler
                        .handle_prepare_request(prepare, None)
                        .await
                        .expect("the proposal is answered");
                    code.taken[sid] = Some(());
                    if answer.is_empty() {
                        model.apply(act);
                    } else {
                        // Refused: the receiver has a step of its own in
                        // flight. The refusal reaches the proposer, and the
                        // step fails on both sides: the model's SessionFail.
                        assert_eq!(payload_of(&answer), "rejection");
                        let proposer = &world.devices[session.sender];
                        proposer.device.enter();
                        proposer
                            .handler
                            .handle_prepare_reject(&answer)
                            .await
                            .expect("the proposer takes the refusal");
                        assert!(
                            model
                                .enabled()
                                .iter()
                                .any(|a| matches!(a, NiAct::Fail(f) if *f == sid)),
                            "trace {trace}: the code failed a session the model cannot fail"
                        );
                        refusals += 1;
                        model.apply(NiAct::Fail(sid));
                    }
                }
                NiAct::Accept(sid) => {
                    let session = model.session(sid);
                    let receiver = &world.devices[session.receiver];
                    receiver.device.enter();
                    let response = receiver
                        .handler
                        .create_prepare_accept_envelope(code.commitment[sid].expect("proposed"))
                        .await
                        .expect("the user accepts");
                    code.response[sid] = Some(response);
                    model.apply(act);
                }
                NiAct::Commit(sid) => {
                    let session = model.session(sid);
                    let (proposer, receiver) = (
                        &world.devices[session.sender],
                        &world.devices[session.receiver],
                    );
                    let Some(response) = &code.response[sid] else {
                        panic!("session {sid} has no acceptance");
                    };
                    proposer.device.enter();
                    let (confirm, _) = proposer
                        .handler
                        .handle_prepare_response(response)
                        .await
                        .expect("the proposer confirms");
                    receiver.device.enter();
                    let ack = receiver
                        .handler
                        .handle_confirm_request(&confirm)
                        .await
                        .expect("the receiver commits");
                    proposer.device.enter();
                    proposer
                        .handler
                        .handle_commit_response(&ack)
                        .await
                        .expect("the proposer files the ack");
                    model.apply(act);
                }
                NiAct::Fail(sid) => {
                    let session = model.session(sid);
                    let c = code.commitment[sid].expect("proposed");
                    let (proposer, receiver) = (
                        &world.devices[session.sender],
                        &world.devices[session.receiver],
                    );
                    match session.phase {
                        NiPh::PendingUserAction if rng.below(2) == 0 => {
                            receiver.device.enter();
                            let rejection = receiver
                                .handler
                                .create_prepare_reject_envelope_with_cleanup(c, "model".to_string())
                                .await
                                .expect("the user rejects");
                            proposer.device.enter();
                            proposer
                                .handler
                                .handle_prepare_reject(&rejection)
                                .await
                                .expect("the proposer takes the rejection");
                        }
                        _ => {
                            proposer.device.enter();
                            let cancellation = proposer
                                .handler
                                .cancel_proposal(c, "model".to_string())
                                .await
                                .expect("the proposer cancels");
                            if session.phase != NiPh::Prepared {
                                receiver.device.enter();
                                receiver
                                    .handler
                                    .handle_prepare_reject(&cancellation)
                                    .await
                                    .expect("the receiver takes the cancellation");
                            }
                        }
                    }
                    model.apply(act);
                }
            }
        }
    }
    assert!(
        refusals > 0,
        "the traces reached a step the code refuses and the model allows"
    );
}
