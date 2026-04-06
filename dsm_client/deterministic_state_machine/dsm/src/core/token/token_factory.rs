//! Token Factory (STRICT, deterministic combiner; BLAKE3-only)
//!
//! DSM has no blocks. "Token genesis" here is an initial *anchor* record that can be
//! committed into a state transition. This module does shown below:
//! - bytes-only boundaries (fixed [u8; 32] identifiers where applicable)
//! - no OS RNG, no wall-clock time
//! - threshold >= 3, participants >= 3, no simulated/alternate-path contributions
//! - domain-separated BLAKE3 hashing only
//!
//! Any network collection of contributions happens outside core (SDK layer).

use crate::types::error::DsmError;
use crate::types::policy_types::PolicyAnchor;

/// 32-byte participant identifier (device/identity/node id).
pub type ParticipantId = [u8; 32];

/// One participant's contribution material for token genesis.
/// This is the exact bytes that were committed/revealed (protocol boundary).
#[derive(Debug, Clone)]
pub struct TokenContribution {
    pub participant: ParticipantId,
    pub material: [u8; 32],
}

/// Deterministic "token genesis" anchor record.
/// This is not a block, not a ledger object; it is a commitment artifact that
/// can be referenced/embedded into a state transition.
#[derive(Debug, Clone)]
pub struct TokenGenesis {
    /// H( domain || token_descriptor || policy_anchor? || threshold || participants || materials )
    pub token_hash: [u8; 32],

    /// H( domain || token_hash || materials )
    pub token_entropy: [u8; 32],

    pub threshold: usize,
    pub participants: Vec<ParticipantId>,

    /// Optional content-addressed policy anchor (32B).
    pub policy_anchor: Option<PolicyAnchor>,

    /// Sorted-by-participant contributions (canonical order).
    pub contributions: Vec<TokenContribution>,
}

#[inline]
fn ds(label: &'static [u8]) -> &'static [u8] {
    label
}

fn hash32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/token-factory");
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

fn ensure_min_threshold(participants: usize, threshold: usize) -> Result<(), DsmError> {
    if participants < 3 {
        return Err(DsmError::invalid_parameter(
            "token genesis requires ≥3 participants",
        ));
    }
    if threshold < 3 {
        return Err(DsmError::invalid_parameter(
            "token genesis requires threshold ≥3",
        ));
    }
    if threshold > participants {
        return Err(DsmError::invalid_parameter(
            "token genesis threshold must be ≤ participants",
        ));
    }
    Ok(())
}

/// Create a deterministic TokenGenesis from already-collected contribution material.
///
/// `token_descriptor` is bytes-only: canonical encoding of (name/symbol/decimals/supply/whatever)
/// that you want bound into the token hash.
///
/// `contributions` must contain at least `threshold` entries and must not be "simulated".
/// The SDK / transport layer is responsible for collecting these.
pub fn create_token_genesis(
    threshold: usize,
    participants: Vec<ParticipantId>,
    token_descriptor: &[u8],
    policy_anchor: Option<PolicyAnchor>,
    mut contributions: Vec<TokenContribution>,
) -> Result<TokenGenesis, DsmError> {
    ensure_min_threshold(participants.len(), threshold)?;

    // Canonicalize participants (lexicographic by bytes) for deterministic hashing.
    let mut participants_sorted = participants.clone();
    participants_sorted.sort();

    // Canonicalize contributions:
    // - must all be in participant set
    // - unique by participant
    // - sort by participant for deterministic hashing
    {
        let mut set = std::collections::BTreeSet::<ParticipantId>::new();
        for p in &participants_sorted {
            set.insert(*p);
        }

        let mut seen = std::collections::BTreeSet::<ParticipantId>::new();
        for c in &contributions {
            if !set.contains(&c.participant) {
                return Err(DsmError::invalid_parameter(
                    "contribution participant is not in participants set",
                ));
            }
            if !seen.insert(c.participant) {
                return Err(DsmError::invalid_parameter(
                    "duplicate contribution for participant",
                ));
            }
        }

        if contributions.len() < threshold {
            return Err(DsmError::invalid_parameter(
                "insufficient contributions for threshold",
            ));
        }

        contributions.sort_by_key(|c| c.participant);
    }

    // Only the first `threshold` contributions count (deterministic after sorting).
    let contributions = contributions
        .into_iter()
        .take(threshold)
        .collect::<Vec<_>>();

    // Flatten participants and materials as bytes for hashing.
    let mut participants_bytes = Vec::with_capacity(participants_sorted.len() * 32);
    for p in &participants_sorted {
        participants_bytes.extend_from_slice(p);
    }

    let mut materials_bytes = Vec::with_capacity(contributions.len() * 32);
    for c in &contributions {
        materials_bytes.extend_from_slice(&c.material);
    }

    let threshold_le = u64_le(threshold as u64);

    // policy anchor: treat as 32 bytes if present
    let (policy_flag, policy_bytes) = if let Some(pa) = &policy_anchor {
        (b"\x01".as_slice(), pa.0.as_slice())
    } else {
        (b"\x00".as_slice(), &[][..])
    };

    // token_hash binds descriptor + policy + threshold + participant set + materials
    let token_hash = hash32(&[
        ds(b"DSM/TOKEN/GENESIS_HASH/V2"),
        token_descriptor,
        policy_flag,
        policy_bytes,
        &threshold_le,
        &participants_bytes,
        &materials_bytes,
    ]);

    // token_entropy binds token_hash + materials
    let token_entropy = hash32(&[
        ds(b"DSM/TOKEN/GENESIS_ENTROPY/V2"),
        &token_hash,
        &materials_bytes,
    ]);

    Ok(TokenGenesis {
        token_hash,
        token_entropy,
        threshold,
        participants: participants_sorted,
        policy_anchor,
        contributions,
    })
}

/// Derive a deterministic sub-token genesis from a parent genesis.
/// This is still not a "block" concept; it’s a derived anchor that can be committed into state.
///
/// Enforces threshold >= 3 and requires explicit participant set + contributions.
pub fn derive_sub_token_genesis(
    parent: &TokenGenesis,
    sub_id: &[u8], // bytes-only sub-identifier (e.g. “vesting tranche #1” encoded canonically)
    threshold: usize,
    participants: Vec<ParticipantId>,
    policy_anchor: Option<PolicyAnchor>,
    contributions: Vec<TokenContribution>,
) -> Result<TokenGenesis, DsmError> {
    // domain-separated descriptor: H(parent_hash || sub_id)
    let descriptor = hash32(&[
        ds(b"DSM/TOKEN/SUB/DESCRIPTOR/V2"),
        &parent.token_hash,
        sub_id,
    ]);

    create_token_genesis(
        threshold,
        participants,
        &descriptor,
        policy_anchor.or_else(|| parent.policy_anchor.clone()),
        contributions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u8) -> ParticipantId {
        [n; 32]
    }

    fn contrib(n: u8) -> TokenContribution {
        TokenContribution {
            participant: pid(n),
            material: [n + 100; 32],
        }
    }

    fn three_participants() -> Vec<ParticipantId> {
        vec![pid(1), pid(2), pid(3)]
    }

    fn three_contributions() -> Vec<TokenContribution> {
        vec![contrib(1), contrib(2), contrib(3)]
    }

    fn descriptor() -> &'static [u8] {
        b"test-token-descriptor"
    }

    // ── ensure_min_threshold (via create_token_genesis) ─────────────

    #[test]
    fn fewer_than_3_participants_is_rejected() {
        let result = create_token_genesis(
            3,
            vec![pid(1), pid(2)],
            descriptor(),
            None,
            vec![contrib(1), contrib(2)],
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("≥3 participants"), "got: {msg}");
    }

    #[test]
    fn threshold_below_3_is_rejected() {
        let result = create_token_genesis(
            2,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("threshold ≥3"), "got: {msg}");
    }

    #[test]
    fn threshold_exceeding_participants_is_rejected() {
        let result = create_token_genesis(
            4,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("threshold must be ≤ participants"),
            "got: {msg}"
        );
    }

    #[test]
    fn exactly_3_participants_3_threshold_succeeds() {
        let result = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn five_participants_threshold_3_succeeds() {
        let participants = vec![pid(1), pid(2), pid(3), pid(4), pid(5)];
        let contributions = vec![contrib(1), contrib(2), contrib(3), contrib(4), contrib(5)];
        let result = create_token_genesis(3, participants, descriptor(), None, contributions);
        assert!(result.is_ok());
        let genesis = result.unwrap();
        assert_eq!(genesis.threshold, 3);
        assert_eq!(genesis.participants.len(), 5);
        assert_eq!(genesis.contributions.len(), 3);
    }

    // ── create_token_genesis success cases ──────────────────────────

    #[test]
    fn produces_valid_token_genesis() {
        let genesis = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(genesis.threshold, 3);
        assert_eq!(genesis.participants.len(), 3);
        assert_eq!(genesis.contributions.len(), 3);
        assert_eq!(genesis.token_hash.len(), 32);
        assert_eq!(genesis.token_entropy.len(), 32);
        assert!(genesis.policy_anchor.is_none());
        assert_ne!(genesis.token_hash, [0u8; 32]);
        assert_ne!(genesis.token_entropy, [0u8; 32]);
    }

    #[test]
    fn participants_are_sorted_in_output() {
        let participants = vec![pid(3), pid(1), pid(2)];
        let genesis =
            create_token_genesis(3, participants, descriptor(), None, three_contributions())
                .unwrap();

        assert_eq!(genesis.participants[0], pid(1));
        assert_eq!(genesis.participants[1], pid(2));
        assert_eq!(genesis.participants[2], pid(3));
    }

    #[test]
    fn contributions_are_sorted_by_participant() {
        let contributions = vec![contrib(3), contrib(1), contrib(2)];
        let genesis =
            create_token_genesis(3, three_participants(), descriptor(), None, contributions)
                .unwrap();

        assert_eq!(genesis.contributions[0].participant, pid(1));
        assert_eq!(genesis.contributions[1].participant, pid(2));
        assert_eq!(genesis.contributions[2].participant, pid(3));
    }

    #[test]
    fn token_hash_and_entropy_are_32_bytes() {
        let genesis = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(genesis.token_hash.len(), 32);
        assert_eq!(genesis.token_entropy.len(), 32);
    }

    #[test]
    fn different_descriptors_produce_different_hashes() {
        let g1 = create_token_genesis(
            3,
            three_participants(),
            b"descriptor-A",
            None,
            three_contributions(),
        )
        .unwrap();

        let g2 = create_token_genesis(
            3,
            three_participants(),
            b"descriptor-B",
            None,
            three_contributions(),
        )
        .unwrap();

        assert_ne!(g1.token_hash, g2.token_hash);
        assert_ne!(g1.token_entropy, g2.token_entropy);
    }

    #[test]
    fn same_inputs_produce_same_hash_determinism() {
        let g1 = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        let g2 = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(g1.token_hash, g2.token_hash);
        assert_eq!(g1.token_entropy, g2.token_entropy);
    }

    // ── create_token_genesis error cases ────────────────────────────

    #[test]
    fn contribution_from_non_participant_is_rejected() {
        let outsider = TokenContribution {
            participant: pid(99),
            material: [0xAA; 32],
        };
        let contributions = vec![contrib(1), contrib(2), outsider];
        let result =
            create_token_genesis(3, three_participants(), descriptor(), None, contributions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("not in participants set"), "got: {msg}");
    }

    #[test]
    fn duplicate_contribution_for_same_participant_is_rejected() {
        let dup = TokenContribution {
            participant: pid(1),
            material: [0xBB; 32],
        };
        let contributions = vec![contrib(1), dup, contrib(2)];
        let result =
            create_token_genesis(3, three_participants(), descriptor(), None, contributions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("duplicate contribution"), "got: {msg}");
    }

    #[test]
    fn insufficient_contributions_is_rejected() {
        let contributions = vec![contrib(1), contrib(2)];
        let result =
            create_token_genesis(3, three_participants(), descriptor(), None, contributions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("insufficient contributions"), "got: {msg}");
    }

    // ── create_token_genesis with policy anchor ─────────────────────

    #[test]
    fn policy_anchor_changes_token_hash() {
        let anchor = PolicyAnchor([0x42; 32]);

        let without = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        let with = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            Some(anchor.clone()),
            three_contributions(),
        )
        .unwrap();

        assert_ne!(without.token_hash, with.token_hash);
        assert_ne!(without.token_entropy, with.token_entropy);
    }

    #[test]
    fn policy_anchor_propagates_to_result() {
        let anchor = PolicyAnchor([0x42; 32]);
        let genesis = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            Some(anchor.clone()),
            three_contributions(),
        )
        .unwrap();

        assert_eq!(genesis.policy_anchor, Some(anchor));
    }

    // ── derive_sub_token_genesis ────────────────────────────────────

    #[test]
    fn derive_produces_valid_sub_token_genesis() {
        let parent = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        let sub = derive_sub_token_genesis(
            &parent,
            b"sub-1",
            3,
            three_participants(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(sub.threshold, 3);
        assert_eq!(sub.participants.len(), 3);
        assert_ne!(sub.token_hash, [0u8; 32]);
        assert_ne!(sub.token_hash, parent.token_hash);
    }

    #[test]
    fn different_sub_id_produces_different_result() {
        let parent = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        let sub_a = derive_sub_token_genesis(
            &parent,
            b"sub-A",
            3,
            three_participants(),
            None,
            three_contributions(),
        )
        .unwrap();

        let sub_b = derive_sub_token_genesis(
            &parent,
            b"sub-B",
            3,
            three_participants(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_ne!(sub_a.token_hash, sub_b.token_hash);
        assert_ne!(sub_a.token_entropy, sub_b.token_entropy);
    }

    #[test]
    fn derive_inherits_parent_policy_anchor_when_none_provided() {
        let anchor = PolicyAnchor([0x77; 32]);
        let parent = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            Some(anchor.clone()),
            three_contributions(),
        )
        .unwrap();

        let sub = derive_sub_token_genesis(
            &parent,
            b"sub-inherit",
            3,
            three_participants(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(sub.policy_anchor, Some(anchor));
    }

    #[test]
    fn derive_overrides_policy_anchor_when_provided() {
        let parent_anchor = PolicyAnchor([0x77; 32]);
        let child_anchor = PolicyAnchor([0x88; 32]);
        let parent = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            Some(parent_anchor),
            three_contributions(),
        )
        .unwrap();

        let sub = derive_sub_token_genesis(
            &parent,
            b"sub-override",
            3,
            three_participants(),
            Some(child_anchor.clone()),
            three_contributions(),
        )
        .unwrap();

        assert_eq!(sub.policy_anchor, Some(child_anchor));
    }

    // ── Determinism tests ───────────────────────────────────────────

    #[test]
    fn identical_inputs_produce_identical_results() {
        let make = || {
            create_token_genesis(
                3,
                three_participants(),
                descriptor(),
                None,
                three_contributions(),
            )
            .unwrap()
        };

        let a = make();
        let b = make();
        assert_eq!(a.token_hash, b.token_hash);
        assert_eq!(a.token_entropy, b.token_entropy);
        assert_eq!(a.threshold, b.threshold);
        assert_eq!(a.participants, b.participants);
        assert_eq!(a.contributions.len(), b.contributions.len());
        for (ca, cb) in a.contributions.iter().zip(b.contributions.iter()) {
            assert_eq!(ca.participant, cb.participant);
            assert_eq!(ca.material, cb.material);
        }
    }

    #[test]
    fn contribution_order_does_not_affect_result() {
        let g1 = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            vec![contrib(1), contrib(2), contrib(3)],
        )
        .unwrap();

        let g2 = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            vec![contrib(3), contrib(1), contrib(2)],
        )
        .unwrap();

        assert_eq!(g1.token_hash, g2.token_hash);
        assert_eq!(g1.token_entropy, g2.token_entropy);
    }

    #[test]
    fn participant_order_does_not_affect_result() {
        let g1 = create_token_genesis(
            3,
            vec![pid(1), pid(2), pid(3)],
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        let g2 = create_token_genesis(
            3,
            vec![pid(3), pid(1), pid(2)],
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_eq!(g1.token_hash, g2.token_hash);
        assert_eq!(g1.token_entropy, g2.token_entropy);
    }

    #[test]
    fn only_threshold_contributions_are_kept() {
        let participants = vec![pid(1), pid(2), pid(3), pid(4), pid(5)];
        let contributions = vec![contrib(1), contrib(2), contrib(3), contrib(4), contrib(5)];
        let genesis =
            create_token_genesis(3, participants, descriptor(), None, contributions).unwrap();

        assert_eq!(genesis.contributions.len(), 3);
        assert_eq!(genesis.contributions[0].participant, pid(1));
        assert_eq!(genesis.contributions[1].participant, pid(2));
        assert_eq!(genesis.contributions[2].participant, pid(3));
    }

    #[test]
    fn token_hash_differs_from_token_entropy() {
        let genesis = create_token_genesis(
            3,
            three_participants(),
            descriptor(),
            None,
            three_contributions(),
        )
        .unwrap();

        assert_ne!(genesis.token_hash, genesis.token_entropy);
    }
}
