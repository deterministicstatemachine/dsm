// SPDX-License-Identifier: Apache-2.0

//! TEST-ONLY in-process fleet for the generic binding register.
//!
//! The settlement-slot register had `storage_io::fake_fleet`; the QuorumBind
//! path needs the same for `/api/v2/storage/binding/{cas,read}` so the live
//! settle-path tests can drive the real Class K decision (PR 2) through a
//! deterministic fleet without HTTP. [`FakeBindingTransport`] implements
//! [`BindingTransport`] over one global in-process store whose per-member
//! compare-and-exchange mirrors `dsm_storage_node::db::binding::decide_compare_exchange`
//! byte-for-byte: byte-identical replay re-acks; the prior set digest must
//! match; the replacement round must strictly supersede every held round. Each
//! member echoes the committed `(member_id, register_incarnation)` so the
//! runner's attribution runs for real.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use dsm::storage::binding_record::{
    record_digest_of_bytes, record_set_digest, BindingRecord, Round, SetCell,
};

use super::binding_http_transport::MemberEndpoint;
use super::quorum_bind_runner::{BindingTransport, CasOutcome, TransportCas, TransportRead};

#[derive(Default)]
struct FleetState {
    /// member endpoint -> (key -> (canonical record bytes, round)).
    members: BTreeMap<String, BTreeMap<[u8; 32], (Vec<u8>, Round)>>,
    /// member endpoint -> the (member_id, register_incarnation) it echoes.
    echo: BTreeMap<String, (Vec<u8>, [u8; 32])>,
    /// members whose ops all fail (Unavailable).
    down: std::collections::HashSet<String>,
    /// members that serve reads but refuse CAS (a read-only / full node): the
    /// binding analogue of the old register's `refuse_claims`.
    refuse_writes: std::collections::HashSet<String>,
    /// every CAS the fleet was ASKED to perform, applied or not — the binding
    /// analogue of the object store's `put_log`.
    cas_log: Vec<(String, Vec<[u8; 32]>, BindingRecord)>,
}

static STATE: once_cell::sync::Lazy<Mutex<FleetState>> =
    once_cell::sync::Lazy::new(|| Mutex::new(FleetState::default()));

fn state() -> std::sync::MutexGuard<'static, FleetState> {
    STATE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Reset the fleet and register a set's members with the identity each echoes.
/// `members` pairs an endpoint with the `(member_id, register_incarnation)` the
/// caller committed, so an attributed answer counts.
pub fn reset_with(members: &[(String, Vec<u8>, [u8; 32])]) {
    let mut s = state();
    *s = FleetState::default();
    for (endpoint, member_id, incarnation) in members {
        s.members.insert(endpoint.clone(), BTreeMap::new());
        s.echo
            .insert(endpoint.clone(), (member_id.clone(), *incarnation));
    }
}

/// Register a set's members if they are not already present, WITHOUT clearing
/// held records — so a settle-path test that never touches the fleet directly
/// still has its members attributed. Idempotent.
pub fn ensure_registered(members: &[(String, Vec<u8>, [u8; 32])]) {
    let mut s = state();
    for (endpoint, member_id, incarnation) in members {
        s.members.entry(endpoint.clone()).or_default();
        s.echo
            .entry(endpoint.clone())
            .or_insert_with(|| (member_id.clone(), *incarnation));
    }
}

/// Clear the whole fleet — for the shared test reset, so records never leak
/// between tests.
pub fn reset_all() {
    *state() = FleetState::default();
}

/// Take a member offline (all its ops answer Unavailable).
pub fn fail_member(endpoint: &str) {
    state().down.insert(endpoint.to_string());
}

/// Bring a member back online.
pub fn heal_member(endpoint: &str) {
    state().down.remove(endpoint);
}

/// A member that answers reads but refuses every CAS (Unavailable on write).
pub fn refuse_writes(endpoint: &str) {
    state().refuse_writes.insert(endpoint.to_string());
}

/// Override the `(member_id, register_incarnation)` a member echoes — to
/// exercise the runner's attribution (an answer that names the wrong member or
/// a rebuilt register incarnation must not count).
pub fn set_echo(endpoint: &str, member_id: Vec<u8>, incarnation: [u8; 32]) {
    state()
        .echo
        .insert(endpoint.to_string(), (member_id, incarnation));
}

/// The endpoint a committed `member_id` maps to. Derived from the echo table
/// the fleet already keeps, so there is no second source of truth about which
/// endpoint is which member.
fn endpoint_of(member_id: &str) -> Option<String> {
    let s = state();
    s.echo
        .iter()
        .find(|(_, (id, _))| id.as_slice() == member_id.as_bytes())
        .map(|(ep, _)| ep.clone())
}

/// Resolve a committed member id to its endpoint, or PANIC.
///
/// Every id-keyed control below goes through this, and it is deliberately loud.
/// An injection that names a member the fleet does not know is not a no-op —
/// it is a test that passes for the wrong reason, because the failure it was
/// supposed to inject never happened. The old fake fleet's controls were
/// silent, and this double registers members lazily on first use, so a control
/// called before the first binding op would quietly do nothing.
fn require_endpoint(member_id: &str, control: &str) -> String {
    endpoint_of(member_id).unwrap_or_else(|| {
        panic!(
            "binding_fleet_double::{control}: no member {member_id:?} is registered. \
             Register the set (reset_with / ensure_registered) before injecting, or the \
             injection silently does nothing and the test proves nothing."
        )
    })
}

/// Take a member offline BY COMMITTED MEMBER ID.
///
/// Tests name members the way the vault's committed set does (`dsm-node-1`),
/// not by endpoint. Resolving through the echo table keeps every migrated call
/// site a literal substitution for its `fake_fleet` original, and keeps the
/// endpoint mapping out of the tests.
pub fn fail_member_id(member_id: &str) {
    fail_member(&require_endpoint(member_id, "fail_member_id"));
}

/// Bring a member back online by committed member id.
pub fn heal_member_id(member_id: &str) {
    heal_member(&require_endpoint(member_id, "heal_member_id"));
}

/// Serve reads but refuse every CAS, by committed member id.
pub fn refuse_writes_id(member_id: &str) {
    let ep = require_endpoint(member_id, "refuse_writes_id");
    state().refuse_writes.insert(ep);
}

/// Accept CAS again, by committed member id.
pub fn accept_writes_id(member_id: &str) {
    let ep = require_endpoint(member_id, "accept_writes_id");
    state().refuse_writes.remove(&ep);
}

/// The endpoint a committed member id maps to — for the one control that must
/// name an endpoint rather than a member: making a member answer under ANOTHER
/// member's identity.
pub fn endpoint_for_member(member_id: &str) -> Option<String> {
    endpoint_of(member_id)
}

/// Register a storage set's members so id-keyed controls resolve BEFORE the
/// first binding op. The transport registers lazily, which is fine for a bind
/// but too late for an injection.
pub fn register_set(set: &crate::sdk::storage_set::StorageSet) {
    let tuples: Vec<(String, Vec<u8>, [u8; 32])> = set
        .members()
        .iter()
        .map(|m| {
            (
                m.endpoint.clone(),
                m.member_id.as_bytes().to_vec(),
                m.register_incarnation_id,
            )
        })
        .collect();
    ensure_registered(&tuples);
}

/// Undo a [`set_echo`] impersonation: make `endpoint` echo `member_id` and
/// `incarnation` again.
///
/// It takes the endpoint explicitly BECAUSE the impersonation it undoes has
/// already broken the id -> endpoint lookup: after `set_echo`, the echo table
/// no longer maps that endpoint to its true member, so resolving by member id
/// here would silently find nothing and restore nothing.
pub fn restore_echo(endpoint: &str, member_id: &str, incarnation: [u8; 32]) {
    state().echo.insert(
        endpoint.to_string(),
        (member_id.as_bytes().to_vec(), incarnation),
    );
}

/// Every CAS the fleet was asked to perform, applied or not, in order.
pub fn cas_log() -> Vec<(String, Vec<[u8; 32]>, BindingRecord)> {
    state().cas_log.clone()
}

/// Plant a committed ACCEPTED record directly on chosen members.
///
/// Needed because the DRIVER cannot produce some states a hostile or degraded
/// network can. Two in particular: a sub-quorum accept (with `n=3, q=2`,
/// failing two members means no quorum forms at all, so the driver can never
/// leave exactly one holder), and a record bound at `k(c_n)` whose bundle names
/// a DIFFERENT parent — `K(B)` is derived from `parent_state_commitment`, so
/// only a hand-built key set puts those two out of step, and the node is
/// application-blind and would accept one.
///
/// Writing the canonical record straight in is the honest way to reach those:
/// the alternative is a test that pretends the driver did something it
/// structurally cannot.
pub fn plant_committed(
    member_ids: &[&str],
    keys: &[[u8; 32]],
    tx_id: [u8; 32],
    value_digest: [u8; 32],
    value_addr: [u8; 32],
    round: Round,
) {
    let record = BindingRecord {
        schema: dsm::storage::binding_record::BINDING_RECORD_SCHEMA_V1,
        round,
        tx_id,
        keyset_digest: dsm::storage::binding_record::keyset_digest(keys),
        value_digest,
        value_addr,
        status: dsm::dlv::quorum_bind::BINDING_STATUS_ACCEPTED,
    };
    let bytes = record.encode();
    let endpoints: Vec<String> = member_ids.iter().filter_map(|id| endpoint_of(id)).collect();
    let mut s = state();
    for ep in endpoints {
        let member = s.members.entry(ep).or_default();
        for k in keys {
            member.insert(*k, (bytes.clone(), round));
        }
    }
}

/// The transport a test hands to the driver. It routes `member_ix` to the
/// endpoint at that index in `endpoints`.
pub struct FakeBindingTransport {
    endpoints: Vec<MemberEndpoint>,
}

impl FakeBindingTransport {
    pub fn new(endpoints: Vec<MemberEndpoint>) -> Self {
        FakeBindingTransport { endpoints }
    }

    fn endpoint(&self, ix: usize) -> Option<String> {
        self.endpoints.get(ix).map(|m| m.endpoint.clone())
    }
}

#[async_trait]
impl BindingTransport for FakeBindingTransport {
    async fn read_binding(&self, member_ix: usize, keys: &[[u8; 32]]) -> TransportRead {
        let none = TransportRead {
            echoed_member_id: None,
            echoed_incarnation: None,
            records: None,
        };
        let Some(ep) = self.endpoint(member_ix) else {
            return none;
        };
        let s = state();
        if s.down.contains(&ep) {
            return none;
        }
        let Some((id, inc)) = s.echo.get(&ep).cloned() else {
            return none;
        };
        let held = s.members.get(&ep);
        let records = keys
            .iter()
            .map(|k| {
                held.and_then(|m| m.get(k))
                    .map(|(b, _)| BindingRecord::decode_canonical(b).expect("stored canonical"))
            })
            .collect();
        TransportRead {
            echoed_member_id: Some(id),
            echoed_incarnation: Some(inc),
            records: Some(records),
        }
    }

    async fn compare_exchange(
        &self,
        member_ix: usize,
        keys: &[[u8; 32]],
        expected: [u8; 32],
        repl: &[u8],
    ) -> TransportCas {
        let none = TransportCas {
            echoed_member_id: None,
            echoed_incarnation: None,
            outcome: None,
        };
        let Some(ep) = self.endpoint(member_ix) else {
            return none;
        };
        let Ok(repl_rec) = BindingRecord::decode_canonical(repl) else {
            return none;
        };
        let mut s = state();
        if s.down.contains(&ep) || s.refuse_writes.contains(&ep) {
            return none;
        }
        let Some((id, inc)) = s.echo.get(&ep).cloned() else {
            return none;
        };
        s.cas_log
            .push((ep.clone(), keys.to_vec(), repl_rec.clone()));
        let member = s.members.entry(ep).or_default();
        let held: Vec<Option<(Vec<u8>, Round)>> =
            keys.iter().map(|k| member.get(k).cloned()).collect();
        // 1) byte-identical replay on EVERY key → Applied.
        let outcome = if held
            .iter()
            .all(|h| h.as_ref().is_some_and(|(b, _)| b == repl))
        {
            CasOutcome::Applied
        } else {
            let cur = record_set_digest(
                &keys
                    .iter()
                    .zip(held.iter())
                    .map(|(k, h)| SetCell {
                        key: *k,
                        record_digest: h.as_ref().map(|(b, _)| record_digest_of_bytes(b)),
                    })
                    .collect::<Vec<_>>(),
            );
            if cur != expected || held.iter().flatten().any(|(_, r)| repl_rec.round <= *r) {
                CasOutcome::ExpectationMismatch
            } else {
                for k in keys {
                    member.insert(*k, (repl.to_vec(), repl_rec.round));
                }
                CasOutcome::Applied
            }
        };
        TransportCas {
            echoed_member_id: Some(id),
            echoed_incarnation: Some(inc),
            outcome: Some(outcome),
        }
    }
}
