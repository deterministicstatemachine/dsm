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

/// Take a member offline BY COMMITTED MEMBER ID.
///
/// Tests name members the way the vault's committed set does (`dsm-node-1`),
/// not by endpoint. Resolving through the echo table keeps every migrated call
/// site a literal substitution for its `fake_fleet` original, and keeps the
/// endpoint mapping out of the tests — a hardcoded endpoint that matches no
/// member is an injection that silently does nothing.
pub fn fail_member_id(member_id: &str) {
    if let Some(ep) = endpoint_of(member_id) {
        fail_member(&ep);
    }
}

/// Bring a member back online by committed member id.
pub fn heal_member_id(member_id: &str) {
    if let Some(ep) = endpoint_of(member_id) {
        heal_member(&ep);
    }
}

/// Serve reads but refuse every CAS, by committed member id.
pub fn refuse_writes_id(member_id: &str) {
    if let Some(ep) = endpoint_of(member_id) {
        state().refuse_writes.insert(ep);
    }
}

/// Accept CAS again, by committed member id.
pub fn accept_writes_id(member_id: &str) {
    if let Some(ep) = endpoint_of(member_id) {
        state().refuse_writes.remove(&ep);
    }
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
