// SPDX-License-Identifier: MIT OR Apache-2.0

//! Model-to-code correspondence for the online bilateral models (MR-DSM-0267,
//! DSM Amendment A23, G3 ruling B9): `tla/DSM.tla`'s online protocol and
//! `tla/DSM_BilateralLiveness.tla`'s, which state the same rules — Send,
//! RecvTransfer, RecvDelta, CertQuorum, RecvCert and the projection sync with
//! crossing steps joined.
//!
//! Two real devices on real nodes run seeded traces of sends (some with every
//! spool failed, so they cross), syncs and spool faults through production
//! code. After every send and every sync, what the devices hold is compared
//! with the model: the observed state must be one the model reaches from its
//! previous state by that device's actions alone. A send the model refuses
//! must be refused; a send it takes must be debited and frozen with the parent
//! the model holds. The model's values are the devices' own hashes: a fresh
//! value (a child, a lineage head) is the one the device produced, and a join
//! is Core's `join_concurrent_tips` — the function the model's join oracle
//! stands for. At the end both devices sync fairly until the relationship is
//! at rest, as BilateralLiveness's `OnlineSendSettles` and
//! `RelationshipReturnsToRest` say they must, and the model's at-rest
//! invariants hold on what they hold.

use std::collections::{BTreeMap, BTreeSet};

use super::{Pair, TestDevice};
use crate::storage::client_db as cdb;

type Tip = [u8; 32];

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
// The model's online protocol, its values the devices' hashes.
// Device 0 is A, device 1 is B; `side[d]` is d's view toward the other.
// A step is named by its sender's signed child (`sc`), unique per step.
// ---------------------------------------------------------------------------

/// One device's view of the relationship (`online[<<d,p>>]` and its tip).
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
struct Side {
    chain: Tip,
    prev: Option<Tip>,
    local: Tip,
    lin: Tip,
    pin: Tip,
    gate: Option<Tip>,
    awaits: Option<Tip>,
}

/// Whether a frozen send is finalized (`fin`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
enum Stage {
    Sent,
    Finalized,
}

/// A frozen send not yet released (`outbox`).
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
struct Frozen {
    from: usize,
    amount: u64,
    sp: Tip,
    sc: Tip,
    pp: Tip,
    pc: Tip,
    stage: Stage,
}

/// Whether the storage members serve while a send is made.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Spools {
    Serving,
    Failed,
}

/// A recipient's countersign delta awaiting the certificate (`journal`): the
/// step it acknowledges, and the recipient's lineage step for it.
#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
struct Delta {
    at: usize,
    bp: Tip,
    bc: Tip,
}

#[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
struct Model {
    side: [Side; 2],
    balance: [u64; 2],
    outbox: BTreeMap<Tip, Frozen>,
    journal: BTreeMap<Tip, Delta>,
    certs: BTreeSet<Tip>,
    ledger: BTreeSet<(usize, Tip, Tip)>,
}

/// The view `sync_tip_projections_in_tx` reads, and what it writes.
#[derive(Clone, Copy)]
struct View {
    chain: Tip,
    prev: Option<Tip>,
    local: Tip,
}

/// `TipSync`, case for case, the join by Core's function.
fn tip_sync(v: View, parent: Tip, target: Tip) -> Option<View> {
    if v.chain == target {
        return Some(View {
            chain: target,
            prev: v.prev,
            local: target,
        });
    }
    if v.chain == parent {
        return Some(View {
            chain: target,
            prev: Some(parent),
            local: target,
        });
    }
    if v.prev == Some(parent) && v.local == v.chain {
        let joined = dsm::core::bilateral_transaction_manager::join_concurrent_tips(
            &parent, &v.chain, &target,
        )
        .expect("two distinct children of one parent join");
        return Some(View {
            chain: joined,
            prev: Some(v.chain),
            local: joined,
        });
    }
    if let Some(sibling) = v.prev {
        if sibling != parent && sibling != target && v.local == v.chain {
            if let Ok(joined) = dsm::core::bilateral_transaction_manager::join_concurrent_tips(
                &parent, &sibling, &target,
            ) {
                if joined == v.chain {
                    return Some(v);
                }
            }
        }
    }
    None
}

impl Model {
    fn view(&self, d: usize) -> View {
        View {
            chain: self.side[d].chain,
            prev: self.side[d].prev,
            local: self.side[d].local,
        }
    }

    fn set_view(&mut self, d: usize, v: View) {
        self.side[d].chain = v.chain;
        self.side[d].prev = v.prev;
        self.side[d].local = v.local;
    }

    /// `Send`'s guard: the finality barrier and the balance.
    fn may_send(&self, d: usize, amount: u64) -> bool {
        let s = &self.side[d];
        s.gate.is_none() && s.awaits.is_none() && s.local == s.chain && self.balance[d] >= amount
    }

    /// `Send`, its fresh values the ones the device froze.
    fn send(&mut self, d: usize, frozen: Frozen) {
        let s = &mut self.side[d];
        s.lin = frozen.sc;
        s.local = frozen.pc;
        s.gate = Some(frozen.sc);
        self.balance[d] -= frozen.amount;
        self.outbox.insert(frozen.sc, frozen);
    }

    /// `RecvTransfer` of step `step` at `d`, its fresh lineage head `bc`.
    fn recv_transfer(&self, d: usize, step: &Tip, bc: Tip) -> Option<Model> {
        let p = 1 - d;
        let t = self.outbox.get(step)?;
        if t.from != p
            || self.ledger.contains(&(p, t.sp, t.sc))
            || self.side[d].awaits.is_some()
            || t.sp != self.side[d].pin
            || t.pp != self.side[d].chain
        {
            return None;
        }
        let synced = tip_sync(self.view(d), t.pp, t.pc)?;
        let mut next = self.clone();
        next.set_view(d, synced);
        let bp = next.side[d].lin;
        next.side[d].lin = bc;
        next.side[d].pin = t.sc;
        next.side[d].awaits = Some(*step);
        next.balance[d] += t.amount;
        next.ledger.insert((p, t.sp, t.sc));
        next.journal.insert(*step, Delta { at: d, bp, bc });
        Some(next)
    }

    /// `RecvDelta` for `d`'s send `step`.
    fn recv_delta(&self, d: usize, step: &Tip) -> Option<Model> {
        let p = 1 - d;
        let t = self.outbox.get(step)?;
        let delta = self.journal.get(step)?;
        if t.from != d
            || t.stage == Stage::Finalized
            || self.side[d].gate != Some(*step)
            || delta.bp != self.side[d].pin
        {
            return None;
        }
        let synced = tip_sync(self.view(d), t.pp, t.pc)?;
        let mut next = self.clone();
        next.set_view(d, synced);
        next.side[d].pin = delta.bc;
        next.ledger.insert((p, delta.bp, delta.bc));
        if let Some(sent) = next.outbox.get_mut(step) {
            sent.stage = Stage::Finalized;
        }
        Some(next)
    }

    /// `CertPost` at `d`: its finalized send's certificate reaches quorum on
    /// storage. The gate stays.
    fn cert_post(&self, d: usize) -> Option<Model> {
        let step = self.side[d].gate?;
        if self.outbox.get(&step)?.stage != Stage::Finalized || self.certs.contains(&step) {
            return None;
        }
        let mut next = self.clone();
        next.certs.insert(step);
        Some(next)
    }

    /// `GateRelease` at `d`: its sweep finds the certificate at quorum.
    fn gate_release(&self, d: usize) -> Option<Model> {
        let step = self.side[d].gate?;
        if !self.certs.contains(&step) {
            return None;
        }
        let mut next = self.clone();
        next.outbox.remove(&step);
        next.side[d].gate = None;
        Some(next)
    }

    /// What the devices show of this state: everything but which certificates
    /// storage holds, which neither device's store records.
    fn visible(&self) -> Model {
        let mut shown = self.clone();
        shown.certs.clear();
        shown
    }

    /// `RecvCert` at `d`.
    fn recv_cert(&self, d: usize) -> Option<Model> {
        let step = self.side[d].awaits?;
        if !self.certs.contains(&step) {
            return None;
        }
        let mut next = self.clone();
        next.journal.remove(&step);
        next.side[d].awaits = None;
        Some(next)
    }

    /// Every state `d`'s own actions reach from this one. A transfer `d`
    /// applies takes as its fresh lineage head the one `d` recorded for it
    /// (`children`, by the sender's child); one `d` holds no record of is not
    /// a transfer it applied.
    fn reach_by(&self, d: usize, children: &BTreeMap<Tip, Tip>) -> Vec<Model> {
        let mut seen: BTreeSet<Model> = BTreeSet::new();
        let mut frontier = vec![self.clone()];
        seen.insert(self.clone());
        while let Some(m) = frontier.pop() {
            let mut moves: Vec<Model> = Vec::new();
            for step in m.outbox.keys() {
                if let Some(bc) = children.get(step) {
                    moves.extend(m.recv_transfer(d, step, *bc));
                }
                moves.extend(m.recv_delta(d, step));
            }
            moves.extend(m.cert_post(d));
            moves.extend(m.gate_release(d));
            moves.extend(m.recv_cert(d));
            for next in moves {
                if seen.insert(next.clone()) {
                    frontier.push(next);
                }
            }
        }
        seen.into_iter().collect()
    }

    fn at_rest(&self) -> bool {
        self.outbox.is_empty()
            && self
                .side
                .iter()
                .all(|s| s.gate.is_none() && s.awaits.is_none())
    }
}

// ---------------------------------------------------------------------------
// What the devices hold, read as the model's variables.
// ---------------------------------------------------------------------------

fn tip_of(bytes: Vec<u8>) -> Tip {
    <[u8; 32]>::try_from(bytes.as_slice()).expect("a 32-byte tip")
}

/// The proposals `me` froze for `rel`: (sp, sc, pp, pc, amount, status).
fn proposals(rel: &Tip) -> Vec<(Tip, Tip, Tip, Tip, u64, String)> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().expect("the store lock");
    let mut stmt = conn
        .prepare(
            "SELECT canonical_parent, canonical_child, projection_parent, projection_target, \
             amount, status FROM sender_online_proposal WHERE relationship_key = ?1",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| {
        Ok((
            tip_of(r.get(0)?),
            tip_of(r.get(1)?),
            tip_of(r.get(2)?),
            tip_of(r.get(3)?),
            u64::try_from(r.get::<_, i64>(4)?).expect("an amount"),
            r.get::<_, String>(5)?,
        ))
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("rows")
}

/// The transfers `me` applied on `rel`: (sender parent, sender child, own
/// lineage parent, own lineage child).
fn applied(rel: &Tip) -> Vec<(Tip, Tip, Tip, Tip)> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().expect("the store lock");
    let mut stmt = conn
        .prepare(
            "SELECT parent_tip, child_tip, applied_parent_tip_b, applied_child_tip_b \
             FROM canonical_apply_identity WHERE relationship_key = ?1",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| {
        Ok((
            tip_of(r.get(0)?),
            tip_of(r.get(1)?),
            tip_of(r.get(2)?),
            tip_of(r.get(3)?),
        ))
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("rows")
}

/// The sender children of the journals `me` holds that await the peer's
/// certificate on `rel`.
fn awaiting(rel: &Tip) -> Vec<Tip> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().expect("the store lock");
    let mut stmt = conn
        .prepare(
            "SELECT child_tip FROM acceptance_fold_journal WHERE relationship_key = ?1 \
             AND status != 'rejected' AND peer_finalized = 0",
        )
        .expect("prepare");
    stmt.query_map(rusqlite::params![rel.as_slice()], |r| Ok(tip_of(r.get(0)?)))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("rows")
}

/// The entered device's `previous_chain_tip` toward `peer`.
fn previous_tip(peer: &[u8; 32]) -> Option<Tip> {
    let binding = cdb::get_connection().expect("conn");
    let conn = binding.lock().expect("the store lock");
    conn.query_row(
        "SELECT previous_chain_tip FROM contacts WHERE device_id = ?1",
        rusqlite::params![peer.as_slice()],
        |r| r.get::<_, Option<Vec<u8>>>(0),
    )
    .expect("the contact")
    .map(tip_of)
}

/// Everything one device holds toward its peer, read from its own store.
struct Held {
    side: Side,
    balance: u64,
    sends: Vec<(Tip, Tip, Tip, Tip, u64, String)>,
    gate_next: Option<Tip>,
    applied: Vec<(Tip, Tip, Tip, Tip)>,
}

fn held(me: &TestDevice, peer: &TestDevice, rel: &Tip, genesis: &Tip) -> Held {
    me.enter();
    let sends = proposals(rel);
    let gate_next = cdb::get_pending_online_outbox(&peer.device_id)
        .expect("the gate")
        .map(|g| tip_of(g.next_tip));
    let gate = gate_next.map(|next| {
        sends
            .iter()
            .find(|(_, _, _, pc, _, _)| *pc == next)
            .map(|(_, sc, _, _, _, _)| *sc)
            .expect("the gate guards a frozen send")
    });
    let awaits = awaiting(rel);
    assert!(
        awaits.len() <= 1,
        "{}: one awaited certificate at most: {awaits:?}",
        me.slot
    );
    let lin = me
        .router()
        .core_sdk
        .device_head()
        .and_then(|head| head.rel_chain_tip(rel).map(|t| t.chain_tip))
        .expect("the relationship's lineage head");
    let side = Side {
        chain: cdb::get_contact_chain_tip(&peer.device_id)
            .expect("the tip")
            .expect("a contact"),
        prev: previous_tip(&peer.device_id),
        local: cdb::get_local_bilateral_chain_tip(&peer.device_id)
            .expect("the local tip")
            .expect("a local tip"),
        lin,
        pin: match cdb::load_counterparty_canonical_head(rel).expect("the pin") {
            Some(head) => head,
            // No row: the relationship's first step pins the genesis seed.
            None => *genesis,
        },
        gate,
        awaits: awaits.first().copied(),
    };
    Held {
        side,
        balance: me.era_balance(),
        sends,
        gate_next,
        applied: applied(rel),
    }
}

/// The model state the two devices hold.
fn observe(p: &Pair, rel: &Tip, genesis: &Tip) -> Model {
    let h = [
        held(&p.a, &p.b, rel, genesis),
        held(&p.b, &p.a, rel, genesis),
    ];
    let mut outbox = BTreeMap::new();
    let mut ledger = BTreeSet::new();
    let mut journal = BTreeMap::new();
    for (d, device) in h.iter().enumerate() {
        for (sp, sc, pp, pc, amount, status) in &device.sends {
            let stage = match status.as_str() {
                cdb::PROPOSAL_PROPOSED | cdb::PROPOSAL_SUBMITTED => Stage::Sent,
                cdb::PROPOSAL_FINALIZED => Stage::Finalized,
                other => panic!("a frozen send in status {other}"),
            };
            // Released: its gate gone after its finalization.
            if stage == Stage::Finalized && device.gate_next != Some(*pc) {
                continue;
            }
            outbox.insert(
                *sc,
                Frozen {
                    from: d,
                    amount: *amount,
                    sp: *sp,
                    sc: *sc,
                    pp: *pp,
                    pc: *pc,
                    stage,
                },
            );
        }
    }
    for d in 0..2 {
        let p = 1 - d;
        for (sp, sc, bp, bc) in &h[d].applied {
            ledger.insert((p, *sp, *sc));
            let sender_finalized = h[p]
                .sends
                .iter()
                .any(|(s, c, _, _, _, st)| s == sp && c == sc && st == cdb::PROPOSAL_FINALIZED);
            if sender_finalized {
                ledger.insert((d, *bp, *bc));
            }
            if h[d].side.awaits == Some(*sc) {
                journal.insert(
                    *sc,
                    Delta {
                        at: d,
                        bp: *bp,
                        bc: *bc,
                    },
                );
            }
        }
    }
    Model {
        side: [h[0].side.clone(), h[1].side.clone()],
        balance: [h[0].balance, h[1].balance],
        outbox,
        journal,
        certs: BTreeSet::new(),
        ledger,
    }
}

/// The fields of two model states that differ, for a failure message.
fn differences(model: &Model, held: &Model) -> String {
    let mut out = Vec::new();
    for d in 0..2 {
        if model.side[d] != held.side[d] {
            out.push(format!(
                "side[{d}]: model {:?} / held {:?}",
                model.side[d], held.side[d]
            ));
        }
    }
    if model.balance != held.balance {
        out.push(format!(
            "balance: model {:?} / held {:?}",
            model.balance, held.balance
        ));
    }
    if model.outbox != held.outbox {
        out.push(format!(
            "outbox: model {:?} / held {:?}",
            model.outbox, held.outbox
        ));
    }
    if model.journal != held.journal {
        out.push(format!(
            "journal: model {:?} / held {:?}",
            model.journal, held.journal
        ));
    }
    if model.certs != held.certs {
        out.push(format!(
            "certs: model {:?} / held {:?}",
            model.certs, held.certs
        ));
    }
    if model.ledger != held.ledger {
        out.push(format!(
            "ledger: model {:?} / held {:?}",
            model.ledger, held.ledger
        ));
    }
    out.join("\n  ")
}

// ---------------------------------------------------------------------------
// The driver.
// ---------------------------------------------------------------------------

struct Run {
    p: Pair,
    rel: Tip,
    genesis: Tip,
    /// Every model state consistent with what the devices have shown: they
    /// agree on all but the certificates storage holds.
    models: Vec<Model>,
    steps: Vec<String>,
    /// Whether the members a quorum cannot spare are failed (`fault`).
    quorum: Spools,
    /// The value the two devices held at the start, in base units.
    total: u64,
}

impl Run {
    async fn boot() -> Self {
        let p = Pair::boot(1_000, 1_000).await;
        let rel = p.a.rel_key_with(&p.b);
        let genesis = dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(
            &p.a.device_id,
            &p.b.device_id,
        );
        let model = observe(&p, &rel, &genesis);
        // Init: each space starts at its own seed, the same on both devices —
        // the projection at the relationship's first tip, both lineages and
        // both pins at the genesis seed.
        let first = model.side[0].chain;
        for side in &model.side {
            assert_eq!(
                (side.chain, side.prev, side.local, side.lin, side.pin),
                (first, None, first, genesis, genesis),
                "Init: both projections at one first tip, lineages and pins at the genesis seed"
            );
        }
        assert!(model.at_rest(), "Init: nothing in flight");
        Self {
            p,
            rel,
            genesis,
            total: model.balance[0] + model.balance[1],
            models: vec![model],
            steps: Vec::new(),
            quorum: Spools::Serving,
        }
    }

    /// The members still serving: all of them, or those `fault` left.
    fn serving(&self) -> Vec<String> {
        let breaking = crate::economic_fixtures::members_to_break_quorum();
        crate::economic_fixtures::canonical_member_ids()
            .into_iter()
            .filter(|m| self.quorum == Spools::Serving || !breaking.contains(m))
            .collect()
    }

    fn device(&self, d: usize) -> &TestDevice {
        if d == 0 {
            &self.p.a
        } else {
            &self.p.b
        }
    }

    fn fail(&self, what: &str) -> ! {
        panic!("{what}\nafter: {:?}", self.steps)
    }

    /// The recipient lineage child `d` recorded for each transfer it applied,
    /// by the sender's child.
    fn children(&self, d: usize) -> BTreeMap<Tip, Tip> {
        self.device(d).enter();
        applied(&self.rel)
            .into_iter()
            .map(|(_, sc, _, bc)| (sc, bc))
            .collect()
    }

    /// A real send: `wallet.send` first takes up what has arrived (its
    /// preflight), then makes the send or refuses it. The devices must hold a
    /// state the model reaches by the sender's own actions and then `Send` —
    /// taken where the model's barrier and the balance allow it, refused where
    /// they do not — with the parent the model holds.
    async fn send(&mut self, d: usize, amount: u64, spools: Spools) {
        self.steps.push(format!("send {d} {amount} {spools:?}"));
        let members = self.serving();
        if spools == Spools::Failed {
            self.p.nodes.fail_spools(&members).await;
        }
        let out = self.device(d).send(self.device(1 - d), amount).await;
        if spools == Spools::Failed {
            self.p.nodes.restore_spools(&members).await;
        }
        let held = observe(&self.p, &self.rel, &self.genesis);
        let children = self.children(d);
        let mut kept: BTreeSet<Model> = BTreeSet::new();
        let mut outcomes = Vec::new();
        for model in &self.models {
            for before in model.reach_by(d, &children) {
                let fresh: Vec<Frozen> = held
                    .outbox
                    .values()
                    .filter(|f| f.from == d && !before.outbox.contains_key(&f.sc))
                    .cloned()
                    .collect();
                match fresh.as_slice() {
                    [] if !before.may_send(d, amount) && held == before.visible() => {
                        kept.insert(before);
                    }
                    [frozen] if before.may_send(d, amount) => {
                        let mut after = before.clone();
                        after.send(d, frozen.clone());
                        let parent_held = frozen.sp == before.side[d].lin
                            && frozen.pp == before.side[d].chain
                            && frozen.amount == amount;
                        if parent_held && after.visible() == held {
                            kept.insert(after);
                        } else {
                            outcomes.push(differences(&after.visible(), &held));
                        }
                    }
                    _ => outcomes.push(differences(&before.visible(), &held)),
                }
            }
        }
        if kept.is_empty() {
            let nearest = outcomes
                .iter()
                .min_by_key(|o| o.len())
                .expect("the model reaches at least its own state");
            self.fail(&format!(
                "the send ({:?}) reached a state no sequence of the sender's model actions and \
                 `Send` reaches:\n  {nearest}",
                out.error_message
            ));
        }
        self.models = kept.into_iter().collect();
    }

    /// A real sync of device `d`, compared with every state `d`'s actions
    /// reach.
    async fn sync(&mut self, d: usize) {
        self.steps.push(format!("sync {d}"));
        let synced = self.device(d).sync().await;
        let held = observe(&self.p, &self.rel, &self.genesis);
        let children = self.children(d);
        let reachable: Vec<Model> = self
            .models
            .iter()
            .flat_map(|m| m.reach_by(d, &children))
            .collect();
        let kept: BTreeSet<Model> = reachable
            .iter()
            .filter(|m| m.visible() == held)
            .cloned()
            .collect();
        if kept.is_empty() {
            let nearest = reachable
                .iter()
                .min_by_key(|m| differences(&m.visible(), &held).len())
                .expect("the model reaches at least its own state");
            self.fail(&format!(
                "sync {d} reached a state no sequence of its model actions reaches (sync errors \
                 {:?}):\n  {}",
                synced.errors,
                differences(&nearest.visible(), &held)
            ));
        }
        self.models = kept.into_iter().collect();
    }

    /// What the devices hold, as every consistent model state shows it.
    fn model(&self) -> &Model {
        self.models
            .first()
            .expect("at least one consistent model state")
    }

    async fn fault(&mut self, spools: Spools) {
        let breaking = crate::economic_fixtures::members_to_break_quorum();
        self.steps.push(format!("quorum {spools:?}"));
        if spools != self.quorum {
            match spools {
                Spools::Failed => self.p.nodes.fail_spools(&breaking).await,
                Spools::Serving => self.p.nodes.restore_spools(&breaking).await,
            }
            self.quorum = spools;
        }
    }

    /// Fair syncs until the relationship is at rest; then the model's at-rest
    /// invariants on what the devices hold, and a send each way.
    async fn come_to_rest(&mut self) {
        self.fault(Spools::Serving).await;
        for round in 0..8 {
            if self.model().at_rest() {
                break;
            }
            assert!(
                round < 7,
                "OnlineSendSettles: the relationship did not come to rest"
            );
            self.sync(0).await;
            self.sync(1).await;
        }
        let m = self.model().visible();
        assert_eq!(
            m.side[0].chain, m.side[1].chain,
            "ProjectionAgreement: one tip"
        );
        assert_eq!(
            m.side[0].pin, m.side[1].lin,
            "ProjectionAgreement: A pins B's head"
        );
        assert_eq!(
            m.side[1].pin, m.side[0].lin,
            "ProjectionAgreement: B pins A's head"
        );
        let mut signers: BTreeMap<(usize, Tip), Tip> = BTreeMap::new();
        for (signer, parent, child) in &m.ledger {
            if let Some(other) = signers.insert((*signer, *parent), *child) {
                assert_eq!(
                    other, *child,
                    "Tripwire: device {signer} consumed a parent twice"
                );
            }
        }
        assert_eq!(
            m.balance[0] + m.balance[1],
            self.total,
            "TokenConservation at rest"
        );
        for d in [0, 1] {
            self.send(d, 1, Spools::Serving).await;
            for _ in 0..3 {
                self.sync(1 - d).await;
                self.sync(d).await;
            }
            assert!(
                self.model().at_rest(),
                "RelationshipReturnsToRest after a send from {d}"
            );
        }
    }
}

/// One seeded trace: sends (a third with every spool failed, so the next send
/// the other way crosses it), syncs and spool faults, each compared with the
/// model, then a fair finish to rest.
async fn trace(seed: u64, steps: usize) -> Run {
    let mut run = Run::boot().await;
    let mut rng = Rng(seed);
    let mut quorum = Spools::Serving;
    for _ in 0..steps {
        match rng.below(10) {
            0..=2 => {
                let d = rng.below(2);
                let amount = 1 + u64::try_from(rng.below(5)).expect("small");
                let spools = match rng.below(3) {
                    0 => Spools::Failed,
                    _ => Spools::Serving,
                };
                run.send(d, amount, spools).await;
            }
            3..=7 => {
                let d = rng.below(2);
                run.sync(d).await;
            }
            _ => {
                quorum = match quorum {
                    Spools::Serving => Spools::Failed,
                    Spools::Failed => Spools::Serving,
                };
                run.fault(quorum).await;
            }
        }
    }
    run.come_to_rest().await;
    run
}

/// DSM.tla's online protocol: every send and sync of two seeded traces is a
/// state the model reaches; the crossing pattern is driven explicitly in the
/// first, and the trace's own sends cross where the dice fall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_online_transfers_refine_the_dsm_online_model() {
    let mut run = Run::boot().await;
    // Two sends that cross, each made before its sender applied the other's.
    run.send(0, 10, Spools::Failed).await;
    run.send(1, 7, Spools::Failed).await;
    let crossing: Vec<Frozen> = run.model().outbox.values().cloned().collect();
    assert_eq!(crossing.len(), 2, "both sends are in flight");
    for _ in 0..4 {
        run.sync(1).await;
        run.sync(0).await;
    }
    assert!(
        run.model().at_rest(),
        "the crossing settled: {:?}",
        run.steps
    );
    assert_eq!(
        crossing[0].pp, crossing[1].pp,
        "both were made on one projection tip"
    );
    let joined = dsm::core::bilateral_transaction_manager::join_concurrent_tips(
        &crossing[0].pp,
        &crossing[0].pc,
        &crossing[1].pc,
    )
    .expect("the crossing's join");
    assert_eq!(
        run.model().side[0].chain,
        joined,
        "both devices hold the joined tip"
    );
    drop(run);
    let run = trace(0x5EED_0D5A, 24).await;
    assert!(run.model().at_rest());
}

/// DSM_BilateralLiveness.tla: the same rules along a longer seeded trace with
/// more spool faults, and its liveness obligations on the devices — every
/// gate releases, every awaited certificate arrives, and the relationship
/// returns to rest and carries a send each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_online_transfers_refine_the_bilateral_liveness_model() {
    let run = trace(0xB1_1A7E, 32).await;
    assert!(run.model().at_rest());
    let sends = run.steps.iter().filter(|s| s.starts_with("send")).count();
    assert!(sends >= 6, "the trace sent: {:?}", run.steps);
}
