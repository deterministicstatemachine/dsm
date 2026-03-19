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

        contributions.sort_by(|a, b| a.participant.cmp(&b.participant));
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
