// SPDX-License-Identifier: MIT OR Apache-2.0
//! Predecessor-linked canonical head reconstruction.
//!
//! Rebuilds a device head by replaying preserved relationship chain states from a
//! TRUSTED CHECKPOINT, applying only a successor that is
//!
//!   1. **uniquely linked** — exactly one preserved state device-wide names the
//!      current reconstructed head's tip as its `embedded_parent`, and
//!   2. **cryptographically valid** — re-deriving the transition through the
//!      canonical [`DeviceState::advance`] reproduces the stored chain tip byte
//!      for byte.
//!
//! If there is no unique successor, reconstruction STOPS. It never guesses.
//!
//! # Why ambiguity is the normal stopping condition, not an edge case
//!
//! `embedded_parent` orders transitions *within one relationship*. It says nothing
//! about order *between* relationships. And `DeviceState` carries no predecessor
//! field at all — it is current-truth-only, anchored by its SMT root — so no
//! device-level predecessor/successor linkage exists in the stored artifacts.
//!
//! So when two relationships each have an unconsumed successor, their relative
//! order is genuinely unprovable from what is stored. Picking one — by largest
//! balance witness, by "looks newest", by insertion order — would install a head
//! that no evidence supports. This module returns [`RebuildStop::Ambiguous`] and
//! leaves the caller quarantined instead.
//!
//! A balance witness is NOT a shortcut. It records what the device believed at
//! that transition; it is evidence, not authority. The head is always RECOMPUTED.

use anyhow::{anyhow, Result};
use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState, RelationshipChainState};
use dsm::types::operations::Operation;

/// Why replay stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebuildStop {
    /// No preserved state names the current head as its parent. Clean terminus:
    /// the reconstruction is complete and total.
    Terminus,
    /// More than one preserved state claims the current head as parent, across
    /// different relationships. Device-level order between them is not encoded in
    /// any artifact, so it cannot be inferred. STOP — stay quarantined.
    Ambiguous { candidate_tips: Vec<[u8; 32]> },
    /// A successor was uniquely linked, but re-deriving it did not reproduce the
    /// stored chain tip. The artifact is corrupt or does not belong to this
    /// device's lineage. STOP — never install a head from an unverified step.
    Divergent {
        rel_key: [u8; 32],
        stored_tip: [u8; 32],
        recomputed_tip: [u8; 32],
    },
    /// The canonical advance itself rejected the transition (e.g. balance
    /// conservation). STOP.
    Rejected { rel_key: [u8; 32], reason: String },
}

/// The outcome of a replay. `head` is only safe to install when `stop` is
/// [`RebuildStop::Terminus`].
#[derive(Debug, Clone)]
pub struct RebuildReport {
    pub head: DeviceState,
    /// Chain tips applied, in the order they were applied.
    pub applied: Vec<[u8; 32]>,
    pub stop: RebuildStop,
}

impl RebuildReport {
    /// True only for a complete, unambiguous, fully verified reconstruction.
    pub fn is_total(&self) -> bool {
        matches!(self.stop, RebuildStop::Terminus)
    }
}

/// A preserved chain state together with the chain tip it was stored under.
pub type PreservedState = (RelationshipChainState, [u8; 32]);

/// Replay preserved states from `checkpoint`, applying only uniquely-linked,
/// cryptographically valid successors.
///
/// Pure: touches no database and mutates nothing. The caller decides whether the
/// report is good enough to install.
pub fn rebuild_head_from_checkpoint(
    checkpoint: DeviceState,
    preserved: &[PreservedState],
) -> Result<RebuildReport> {
    let mut head = checkpoint;
    let mut applied: Vec<[u8; 32]> = Vec::new();
    let mut consumed: Vec<[u8; 32]> = Vec::new();

    loop {
        // Candidates: any unconsumed preserved state whose embedded_parent equals
        // the head's CURRENT tip for that state's own relationship. A state whose
        // relationship has no tip yet is a first-ever advance and links to the
        // parent it carries.
        let candidates: Vec<&PreservedState> = preserved
            .iter()
            .filter(|(_, tip)| !consumed.contains(tip))
            .filter(|(st, _)| match head.chain_tip(&st.rel_key) {
                // Steady state: this transition must name the relationship's
                // current tip as its parent.
                Some(current) => current == st.embedded_parent,
                // First-ever advance on this relationship. Only the ROOT of that
                // relationship's preserved chain qualifies — the one whose parent
                // is not produced by any other preserved state in the same
                // relationship. Without this, every state of an untouched
                // relationship would look like a candidate and a perfectly
                // ordered chain would be reported as ambiguous.
                None => !preserved.iter().any(|(other, other_tip)| {
                    other.rel_key == st.rel_key && *other_tip == st.embedded_parent
                }),
            })
            .collect();

        match candidates.len() {
            0 => {
                return Ok(RebuildReport {
                    head,
                    applied,
                    stop: RebuildStop::Terminus,
                })
            }
            1 => {}
            _ => {
                // Two or more successors are equally well-linked. If they are all
                // in the SAME relationship the artifacts are inconsistent; if they
                // are in different relationships the order is simply not encoded.
                // Either way it is not inferable.
                return Ok(RebuildReport {
                    head,
                    applied,
                    stop: RebuildStop::Ambiguous {
                        candidate_tips: candidates.iter().map(|(_, t)| *t).collect(),
                    },
                });
            }
        }

        let (state, stored_tip) = candidates[0];

        // Re-derive the transition through the canonical advance. This is the
        // validity check: conservation is enforced inside `advance`, and the
        // resulting tip must reproduce the stored one exactly.
        let deltas = deltas_for_transition(state, &head.devid());

        let outcome = match head.advance(
            state.rel_key,
            state.counterparty_devid,
            state.operation.clone(),
            state.entropy.clone(),
            state.encapsulated_entropy.clone(),
            &deltas,
            Some(state.embedded_parent),
            None,
            None,
            None,
        ) {
            Ok(o) => o,
            Err(e) => {
                return Ok(RebuildReport {
                    head,
                    applied,
                    stop: RebuildStop::Rejected {
                        rel_key: state.rel_key,
                        reason: e.to_string(),
                    },
                })
            }
        };

        let recomputed_tip = outcome.new_chain_state.compute_chain_tip();
        if recomputed_tip != *stored_tip {
            return Ok(RebuildReport {
                head,
                applied,
                stop: RebuildStop::Divergent {
                    rel_key: state.rel_key,
                    stored_tip: *stored_tip,
                    recomputed_tip,
                },
            });
        }

        head = outcome.new_device_state;
        applied.push(*stored_tip);
        consumed.push(*stored_tip);
    }
}

/// Derive the balance delta a transition must carry, from the signed operation.
///
/// This mirrors `validate_conservation` exactly — the delta is fully determined by
/// the operation and the device's role in it, so nothing here is a choice. If it
/// were ever wrong, the canonical advance rejects the transition rather than
/// applying a value that the operation does not authorize.
fn deltas_for_transition(
    state: &RelationshipChainState,
    local_devid: &[u8; 32],
) -> Vec<BalanceDelta> {
    match &state.operation {
        Operation::Transfer {
            to_device_id,
            amount,
            policy_commit,
            ..
        } => {
            let is_recipient =
                to_device_id.len() == 32 && to_device_id.as_slice() == local_devid.as_slice();
            vec![BalanceDelta {
                policy_commit: *policy_commit,
                direction: if is_recipient {
                    BalanceDirection::Credit
                } else {
                    BalanceDirection::Debit
                },
                amount: amount.value(),
            }]
        }
        // `Mint` carries no `policy_commit`, and conservation does not check one
        // for mints. Take it from the transition's OWN balance witness, and only
        // when that is unambiguous. If it is not, emit no delta: conservation
        // then rejects the transition and replay STOPS. Guessing a policy here
        // would credit value under a commitment no artifact attests to.
        Operation::Mint { amount, .. } => {
            let mut keys = state.balance_witness.keys();
            match (keys.next(), keys.next()) {
                (Some(policy_commit), None) => vec![BalanceDelta {
                    policy_commit: *policy_commit,
                    direction: BalanceDirection::Credit,
                    amount: amount.value(),
                }],
                _ => Vec::new(),
            }
        }
        // Non-value operations carry no delta; conservation rejects anything else.
        _ => Vec::new(),
    }
}

/// Load every preserved chain state for a device and decode it.
pub fn load_preserved_states(device_id: &[u8; 32]) -> Result<Vec<PreservedState>> {
    let binding = super::get_connection()?;
    let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
    let mut stmt = conn
        .prepare("SELECT state_bytes FROM bcr_chain_states WHERE device_id = ?1 ORDER BY rowid")?;
    let rows = stmt
        .query_map(rusqlite::params![device_id.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    drop(conn);

    rows.iter()
        .map(|b| {
            super::bcr::decode_rel_chain_state(b)
                .map_err(|e| anyhow!("preserved chain state failed to decode: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn checkpoint() -> DeviceState {
        DeviceState::new([0x01u8; 32], [0x02u8; 32], vec![0xAAu8; 32], 16)
    }

    /// A preserved state that claims `parent` on `rel`, carrying a witness so the
    /// shape is realistic. Its stored tip is deliberately NOT the tip a real
    /// advance would produce — these fixtures exercise the linkage and stop rules,
    /// which run before any tip is recomputed.
    fn state_on(rel: u8, parent: [u8; 32], witness: u64) -> PreservedState {
        let mut bw = BTreeMap::new();
        bw.insert([0x77u8; 32], witness);
        (
            RelationshipChainState {
                rel_key: [rel; 32],
                embedded_parent: parent,
                counterparty_devid: [0x09u8; 32],
                operation: dsm::types::operations::Operation::Generic {
                    operation_type: "probe".into(),
                    data: Vec::new(),
                    message: String::new(),
                    signature: Vec::new(),
                },
                entropy: vec![0x11u8; 32],
                encapsulated_entropy: None,
                balance_witness: bw,
                entity_sig: None,
                counterparty_sig: None,
            },
            [rel ^ 0xFF; 32],
        )
    }

    /// No evidence is a clean terminus, not a failure.
    #[test]
    fn empty_evidence_is_a_clean_terminus() {
        let r = rebuild_head_from_checkpoint(checkpoint(), &[]).unwrap();
        assert!(r.is_total());
        assert!(r.applied.is_empty());
    }

    /// THE RULE THIS MODULE EXISTS FOR.
    ///
    /// Two relationships each offer a successor. `embedded_parent` orders
    /// transitions only WITHIN a relationship, and `DeviceState` has no
    /// predecessor field, so their relative order is not encoded anywhere. The
    /// rebuild must refuse — not pick the larger witness, not pick the smaller,
    /// not pick the first.
    #[test]
    fn cross_relationship_ambiguity_stops_instead_of_guessing() {
        let a = state_on(0xA1, [0x00u8; 32], 300);
        let b = state_on(0xB2, [0x00u8; 32], 275);
        let r = rebuild_head_from_checkpoint(checkpoint(), &[a, b]).unwrap();

        assert!(!r.is_total(), "an ambiguous rebuild is never total");
        assert!(
            r.applied.is_empty(),
            "nothing may be applied once the order is unprovable"
        );
        match r.stop {
            RebuildStop::Ambiguous { candidate_tips } => {
                assert_eq!(candidate_tips.len(), 2);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// A uniquely-linked successor that does not reproduce its stored tip is
    /// rejected. The head is never advanced on an unverified step.
    #[test]
    fn a_successor_that_does_not_reproduce_its_tip_is_refused() {
        let only = state_on(0xC3, [0x00u8; 32], 42);
        let r = rebuild_head_from_checkpoint(checkpoint(), &[only]).unwrap();
        assert!(!r.is_total());
        assert!(
            r.applied.is_empty(),
            "a step that fails verification must not be applied"
        );
        assert!(
            matches!(
                r.stop,
                RebuildStop::Divergent { .. } | RebuildStop::Rejected { .. }
            ),
            "expected Divergent or Rejected, got {:?}",
            r.stop
        );
    }

    /// Within ONE relationship a preserved chain is fully ordered by
    /// `embedded_parent`, so only its root is a first-ever candidate. Without
    /// that rule every state of an untouched relationship looks like a candidate
    /// and a perfectly ordered chain is misreported as ambiguous.
    #[test]
    fn an_ordered_chain_in_one_relationship_is_not_ambiguous() {
        // A -> B -> C, all in rel 0xE5, none applied yet.
        let a = ([0xE5u8; 32], [0x00u8; 32], [0xA0u8; 32]);
        let b = ([0xE5u8; 32], [0xA0u8; 32], [0xB0u8; 32]);
        let c = ([0xE5u8; 32], [0xB0u8; 32], [0xC0u8; 32]);
        let mk = |(rel, parent, tip): ([u8; 32], [u8; 32], [u8; 32])| {
            let mut bw = BTreeMap::new();
            bw.insert([0x77u8; 32], 1u64);
            (
                RelationshipChainState {
                    rel_key: rel,
                    embedded_parent: parent,
                    counterparty_devid: [0x09u8; 32],
                    operation: dsm::types::operations::Operation::Generic {
                        operation_type: "probe".into(),
                        data: Vec::new(),
                        message: String::new(),
                        signature: Vec::new(),
                    },
                    entropy: vec![0x11u8; 32],
                    encapsulated_entropy: None,
                    balance_witness: bw,
                    entity_sig: None,
                    counterparty_sig: None,
                },
                tip,
            )
        };
        let preserved = vec![mk(c), mk(a), mk(b)]; // deliberately out of order
        let r = rebuild_head_from_checkpoint(checkpoint(), &preserved).unwrap();
        assert!(
            !matches!(r.stop, RebuildStop::Ambiguous { .. }),
            "a single ordered relationship chain must not be ambiguous, got {:?}",
            r.stop
        );
    }

    /// A state whose parent matches nothing is simply not a successor — it is not
    /// silently applied, and it does not make the terminus dirty.
    #[test]
    fn an_unlinked_state_is_not_a_successor() {
        let orphan = state_on(0xD4, [0xEEu8; 32], 7);
        // The relationship has no tip yet, so this WOULD link as a first-ever
        // advance; give the checkpoint that relationship's tip so it cannot.
        let mut cp = checkpoint();
        let seeded = cp.advance(
            [0xD4u8; 32],
            [0x09u8; 32],
            dsm::types::operations::Operation::Generic {
                operation_type: "seed".into(),
                data: Vec::new(),
                message: String::new(),
                signature: Vec::new(),
            },
            vec![0x22u8; 32],
            None,
            &[],
            Some([0x33u8; 32]),
            None,
            None,
            None,
        );
        if let Ok(o) = seeded {
            cp = o.new_device_state;
            let r = rebuild_head_from_checkpoint(cp, &[orphan]).unwrap();
            assert!(
                r.is_total() && r.applied.is_empty(),
                "an unlinked artifact is ignored, not applied: {:?}",
                r.stop
            );
        }
    }
}
