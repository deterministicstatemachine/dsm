// SPDX-License-Identifier: Apache-2.0

//! Client-side quorum operations on the economic write-once registers, plus
//! ticket selection and the live provenance resolver.
//!
//! ## Counting (Req 15.8, with the owner's tightened write rule)
//!
//! A member's answer counts toward quorum ONLY when the echoed `x-dsm-node-id`
//! equals the member id queried. On writes: `accepted` and `held-identical`
//! count (attributed); a `refused` whose held digest equals OUR digest is an
//! acceptance in different words (attributed, and not taken on trust
//! otherwise); a generic `refused` NEVER counts. Unattributed refusals still
//! count toward "contested" — an unattributed refusal can only fail the claim
//! closed, never open.
//!
//! ## Frozen envelopes
//!
//! Every envelope is signed ONCE, durably retained BEFORE the first
//! register-member write, and replayed byte-identically forever. SPHINCS+
//! signing here is deterministic: a regenerated envelope is indistinguishable
//! from a replayed one downstream, so the safe design is for regeneration to
//! be impossible — the load-only discipline of `FrozenClaimEnvelope`, applied
//! to both new registers.
//!
//! ## Ticket selection is STRATEGY, not validity
//!
//! Any in-range ticket is valid. [`select_ticket`] only decides where this
//! client looks first, which is why it lives here (SDK) and not in protocol
//! core: changing the search strategy later must not masquerade as a protocol
//! change. The seed includes the TARGET ECONOMIC POSITION so each admitted
//! position gets its own deterministic sequence — without it, claim 10,001
//! would walk the identity's 10,000 already-consumed tickets first. Selection
//! is publicly predictable; V1 promises conservation, not anti-targeting.

use dsm::common::domain_tags::TAG_DSM_ERA_FAUCET_TICKET_SELECT;
use dsm::crypto::blake3::dsm_domain_hasher;
use dsm::economic::faucet::{faucet_claim_evidence_addr, ERA_FAUCET_TICKET_COUNT};
use dsm::economic::provenance::{FaucetTicketWin, ProvenanceResolver, ValidatedPeerTransition};
use dsm::types::error::DsmError;

use crate::sdk::storage_node_sdk::{ClaimFanout, MemberClaimResult};
use crate::sdk::storage_set::StorageSet;
use crate::util::text_id;

/// Deterministically choose the ticket this claimant tries at `attempt` for
/// `target_economic_position`. Exact-uniform over the ticket space via the
/// DJTE rejection sampler.
pub fn select_ticket(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    target_economic_position: u64,
    attempt: u64,
) -> Result<u64, DsmError> {
    let mut h = dsm_domain_hasher(TAG_DSM_ERA_FAUCET_TICKET_SELECT);
    h.update(genesis);
    h.update(device_id);
    h.update(&target_economic_position.to_be_bytes());
    h.update(&attempt.to_be_bytes());
    let seed = *h.finalize().as_bytes();
    dsm::emissions::uniform_index(&seed, ERA_FAUCET_TICKET_COUNT)
}

/// Unforgeable evidence that THIS claim envelope won its cell at quorum.
/// Private fields; constructible only by the claim functions below.
#[derive(Debug, Clone)]
pub struct ClaimedCell {
    accepted: u32,
    total: u32,
}

impl ClaimedCell {
    pub fn accepted(&self) -> u32 {
        self.accepted
    }
    pub fn total(&self) -> u32 {
        self.total
    }
}

/// Why a register operation did not establish its cell.
#[derive(Debug)]
pub enum RegisterError {
    /// Not enough attributed members answered; retry later with the SAME bytes.
    StorageUnavailable { accepted: u32, total: u32 },
    /// Another value holds the cell. For a ticket: pick the next attempt's
    /// ticket. For a root cell: see `Conflict` — contested here means OUR
    /// bytes lost, which for a root written only by us is already abnormal.
    Contested { refused_by: u32 },
    /// CATASTROPHIC (root register only): members hold DIFFERENT values for
    /// one cell, or a cell this device owns holds bytes this device never
    /// signed. Quarantine — never hash-order, never overwrite, never retry.
    Conflict { detail: String },
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StorageUnavailable { accepted, total } => write!(
                f,
                "register unavailable: {accepted}/{total} attributed acceptances — retry with \
                 the SAME frozen bytes"
            ),
            Self::Contested { refused_by } => {
                write!(
                    f,
                    "register cell held by another value ({refused_by} refusals)"
                )
            }
            Self::Conflict { detail } => write!(
                f,
                "REGISTER CONFLICT — quarantine, do not retry, do not overwrite: {detail}"
            ),
        }
    }
}

/// Count a claim fan-out under Req 15.8 + the tightened write rule.
fn count_claim(
    fanout: &ClaimFanout,
    our_digest: &[u8; 32],
    quorum: u32,
) -> Result<ClaimedCell, RegisterError> {
    let mut accepted = 0u32;
    let mut refused_by = 0u32;
    for o in &fanout.outcomes {
        let attributed = o.echoed_node_id.as_deref() == Some(o.member_id.as_str());
        match &o.result {
            MemberClaimResult::Accepted | MemberClaimResult::HeldIdentical => {
                if attributed {
                    accepted += 1;
                }
            }
            MemberClaimResult::Refused { held_digest } => {
                // Refused-with-OUR-digest is an acceptance in different words
                // — and carries the same attribution requirement. A generic
                // refusal NEVER counts toward quorum.
                if held_digest.as_deref() == Some(our_digest.as_slice()) {
                    if attributed {
                        accepted += 1;
                    }
                } else {
                    refused_by += 1;
                }
            }
            MemberClaimResult::Unavailable(_) => {}
        }
    }
    if accepted >= quorum {
        Ok(ClaimedCell {
            accepted,
            total: fanout.total,
        })
    } else if refused_by > 0 {
        Err(RegisterError::Contested { refused_by })
    } else {
        Err(RegisterError::StorageUnavailable {
            accepted,
            total: fanout.total,
        })
    }
}

/// Claim one faucet ticket with the FROZEN envelope bytes.
pub async fn claim_faucet_ticket(
    set: &StorageSet,
    frozen_envelope: &[u8],
) -> Result<ClaimedCell, RegisterError> {
    let digest = faucet_claim_evidence_addr(frozen_envelope);
    let fanout = crate::sdk::storage_io::submit_faucet_ticket_claim(set, frozen_envelope)
        .await
        .map_err(|e| RegisterError::StorageUnavailable {
            accepted: 0,
            total: {
                let _ = e;
                set.len() as u32
            },
        })?;
    count_claim(&fanout, &digest, set.quorum())
}

/// Register the economic root with the FROZEN claim envelope bytes.
pub async fn register_economic_root(
    set: &StorageSet,
    frozen_envelope: &[u8],
) -> Result<ClaimedCell, RegisterError> {
    let digest =
        dsm::economic::claim_envelope::economic_root_claim_envelope_digest(frozen_envelope);
    let fanout = crate::sdk::storage_io::submit_economic_root_claim(set, frozen_envelope)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    match count_claim(&fanout, &digest, set.quorum()) {
        // A root cell is written ONLY by its owner with frozen bytes, so a
        // contest is not a race lost — it is a cell this device owns holding
        // bytes this device never sent from this store. Quarantine.
        Err(RegisterError::Contested { refused_by }) => Err(RegisterError::Conflict {
            detail: format!(
                "{refused_by} member(s) hold a DIFFERENT record for this device's own \
                 economic position"
            ),
        }),
        other => other,
    }
}

/// Read the quorum-agreed winner for one register cell: q attributed members
/// returning byte-identical values. Divergent non-identical values are
/// reported so a caller that owns the cell can quarantine.
async fn read_cell_quorum(
    set: &StorageSet,
    rows: Vec<(String, Option<String>, Option<Vec<u8>>)>,
) -> Result<Option<Vec<u8>>, RegisterError> {
    use std::collections::HashMap;
    let mut counts: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut distinct = 0usize;
    for (member_id, echoed, bytes) in rows {
        let attributed = echoed.as_deref() == Some(member_id.as_str());
        if !attributed {
            continue;
        }
        if let Some(b) = bytes {
            let c = counts.entry(b).or_insert(0);
            if *c == 0 {
                distinct += 1;
            }
            *c += 1;
        }
    }
    if let Some((bytes, _)) = counts.iter().find(|(_, c)| **c >= set.quorum()) {
        return Ok(Some(bytes.clone()));
    }
    if distinct > 1 {
        return Err(RegisterError::Conflict {
            detail: format!("{distinct} distinct values observed for one write-once cell"),
        });
    }
    Ok(None)
}

/// The quorum winner for one faucet ticket, if established.
pub async fn read_winning_faucet_ticket(
    set: &StorageSet,
    faucet_id: &[u8; 32],
    ticket_index: u64,
) -> Result<Option<Vec<u8>>, RegisterError> {
    let rows = crate::sdk::storage_io::read_faucet_ticket_cell(set, faucet_id, ticket_index)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    read_cell_quorum(set, rows).await
}

/// The quorum winner for one economic-root cell, if established. Used for
/// lost-response recovery: a crash after a register write is resolved by
/// READING the register, never by re-signing.
pub async fn read_economic_root_cell(
    set: &StorageSet,
    k_root: &[u8; 32],
) -> Result<Option<Vec<u8>>, RegisterError> {
    let rows = crate::sdk::storage_io::read_economic_root_cell_rows(set, k_root)
        .await
        .map_err(|_| RegisterError::StorageUnavailable {
            accepted: 0,
            total: set.len() as u32,
        })?;
    read_cell_quorum(set, rows).await
}

/// The LIVE provenance resolver: answers the verifier's questions from quorum
/// reads against the canonical set. Holds no state and asserts nothing — a
/// question it cannot answer at quorum returns `None`, and the verifier fails
/// closed on it.
pub struct LiveRegisterResolver<'a> {
    pub set: &'a StorageSet,
    pub runtime: tokio::runtime::Handle,
}

impl ProvenanceResolver for LiveRegisterResolver<'_> {
    fn validated_peer_transition(
        &self,
        _peer_genesis: &[u8; 32],
        _peer_devid: &[u8; 32],
        _peer_economic_position: u64,
    ) -> Option<ValidatedPeerTransition> {
        // No peer-transition store exists yet (3.5b); a faucet claim needs
        // none. Fail closed.
        None
    }

    fn winning_faucet_ticket(
        &self,
        faucet_id: &[u8; 32],
        ticket_index: u64,
    ) -> Option<FaucetTicketWin> {
        let set = self.set;
        let fid = *faucet_id;
        let bytes = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(read_winning_faucet_ticket(set, &fid, ticket_index))
        })
        .ok()
        .flatten()?;
        Some(FaucetTicketWin {
            envelope_bytes: bytes,
        })
    }
}

/// Base32 path helpers shared by live and fake paths.
pub(crate) fn faucet_ticket_path(faucet_id: &[u8; 32], ticket_index: u64) -> String {
    format!(
        "/api/v2/faucet-ticket/{}/{}",
        text_id::encode_base32_crockford(faucet_id),
        ticket_index
    )
}

pub(crate) fn economic_root_path(k_root: &[u8; 32]) -> String {
    format!(
        "/api/v2/economic-root/{}",
        text_id::encode_base32_crockford(k_root)
    )
}

/// The republish-sweep object key for an immutable blob:
/// `immutable::{namespace}::{addr_b32}`. Same shape `dlv_routes` uses, so the
/// one generic sweep carries faucet evidence too.
pub(crate) fn immutable_object_key(
    namespace: dsm::crypto::domain::TaggedHashDomain<'_>,
    payload: &[u8],
) -> String {
    let addr = dsm::storage_object::immutable_addr(namespace, payload);
    format!(
        "immutable::{}::{}",
        String::from_utf8_lossy(namespace.source_bytes()),
        text_id::encode_base32_crockford(&addr)
    )
}

#[cfg(test)]
mod tests {
    //! Direct controls on the Req 15.8 counting rules — the pure gates every
    //! register operation funnels through. Each test is the mutation control
    //! for one counting clause: weaken that clause and its test goes red.

    use super::*;
    use crate::sdk::storage_node_sdk::{ClaimFanout, MemberClaimOutcome, MemberClaimResult};
    use crate::sdk::storage_set::StorageMember;

    fn three_member_set() -> StorageSet {
        StorageSet::new(
            (1..=3)
                .map(|i| StorageMember {
                    member_id: format!("dsm-node-{i}"),
                    endpoint: format!("http://127.0.0.1:808{i}"),
                })
                .collect(),
        )
        .expect("set")
    }

    fn outcome(member: &str, echo: Option<&str>, result: MemberClaimResult) -> MemberClaimOutcome {
        MemberClaimOutcome {
            member_id: member.to_string(),
            endpoint: String::new(),
            result,
            echoed_node_id: echo.map(str::to_string),
        }
    }

    fn fanout(outcomes: Vec<MemberClaimOutcome>) -> ClaimFanout {
        let total = outcomes.len() as u32;
        ClaimFanout { outcomes, total }
    }

    #[test]
    fn an_unattributed_acceptance_never_counts() {
        // Two members say "accepted" but one echoes a DIFFERENT node id —
        // a response that cannot be attributed to the member queried is
        // uncountable (Req 15.8), so quorum is NOT met.
        let f = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-2",
                Some("dsm-node-9"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-3",
                None,
                MemberClaimResult::Unavailable("down".into()),
            ),
        ]);
        match count_claim(&f, &[0u8; 32], 2) {
            Err(RegisterError::StorageUnavailable { accepted, .. }) => assert_eq!(accepted, 1),
            other => panic!("unattributed acceptance counted: {other:?}"),
        }
    }

    #[test]
    fn a_generic_refusal_never_counts_toward_quorum() {
        // One attributed acceptance + one generic refusal at q=2: the refusal
        // must fail the claim CLOSED (contested), never count toward it.
        let f = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome(
                "dsm-node-2",
                Some("dsm-node-2"),
                MemberClaimResult::Refused { held_digest: None },
            ),
            outcome(
                "dsm-node-3",
                None,
                MemberClaimResult::Unavailable("down".into()),
            ),
        ]);
        match count_claim(&f, &[0u8; 32], 2) {
            Err(RegisterError::Contested { refused_by }) => assert_eq!(refused_by, 1),
            other => panic!("generic refusal mis-counted: {other:?}"),
        }
    }

    #[test]
    fn refused_with_our_exact_digest_counts_only_when_attributed() {
        // held-identical reported as a refusal carrying OUR digest is an
        // acceptance in different words — with the same attribution bar.
        let ours = [7u8; 32];
        let held = MemberClaimResult::Refused {
            held_digest: Some(ours.to_vec()),
        };
        let attributed = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome("dsm-node-2", Some("dsm-node-2"), held.clone()),
        ]);
        let cell = count_claim(&attributed, &ours, 2).expect("attributed identical digest counts");
        assert_eq!(cell.accepted(), 2);

        let unattributed = fanout(vec![
            outcome(
                "dsm-node-1",
                Some("dsm-node-1"),
                MemberClaimResult::Accepted,
            ),
            outcome("dsm-node-2", Some("dsm-node-9"), held),
        ]);
        assert!(
            count_claim(&unattributed, &ours, 2).is_err(),
            "identical digest without attribution must not count"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn divergent_values_in_one_write_once_cell_are_a_conflict() {
        // Two attributed members holding DIFFERENT bytes for one cell is the
        // catastrophic case: quarantine, never hash-order, never overwrite.
        let set = three_member_set();
        let rows = vec![
            (
                "dsm-node-1".to_string(),
                Some("dsm-node-1".to_string()),
                Some(vec![1u8]),
            ),
            (
                "dsm-node-2".to_string(),
                Some("dsm-node-2".to_string()),
                Some(vec![2u8]),
            ),
            (
                "dsm-node-3".to_string(),
                Some("dsm-node-3".to_string()),
                None,
            ),
        ];
        match read_cell_quorum(&set, rows).await {
            Err(RegisterError::Conflict { .. }) => {}
            other => panic!("divergent cell not quarantined: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unattributed_read_row_is_uncountable() {
        // q identical values where one echo is wrong: only ONE countable row
        // remains, so no winner is established — fail closed, not open.
        let set = three_member_set();
        let rows = vec![
            (
                "dsm-node-1".to_string(),
                Some("dsm-node-1".to_string()),
                Some(vec![9u8]),
            ),
            (
                "dsm-node-2".to_string(),
                Some("dsm-node-9".to_string()),
                Some(vec![9u8]),
            ),
            (
                "dsm-node-3".to_string(),
                Some("dsm-node-3".to_string()),
                None,
            ),
        ];
        let winner = read_cell_quorum(&set, rows).await.expect("no conflict");
        assert!(winner.is_none(), "unattributed rows must be uncountable");
    }
}
