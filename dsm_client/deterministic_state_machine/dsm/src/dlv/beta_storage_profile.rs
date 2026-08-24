// SPDX-License-Identifier: Apache-2.0

//! The beta storage profile — a FIXED PROFILE, not a quorum function.
//!
//! OWNER DECISION (2026-08-23): the deployed beta storage set is the
//! THREE-member Alibaba ECS fleet, and the profile is fixed at `q = 2`. If
//! one member is unavailable, both remaining members are required; if two or
//! more are unavailable, a new settlement decision cannot be established
//! until the fixed threshold is again reachable. Rev 15 Req 6.13's text
//! still describes the earlier five-member/q=4 profile — the spec amendment
//! is owed; code is authoritative for the deployed set per the
//! reconciliation doctrine.
//!
//! That is a threshold for ONE cardinality. There is no quorum function
//! over arbitrary `n`, so this module refuses every other set size rather than
//! interpolating one. `n-1`, a lookup table over `{1,3,5}`, and a piecewise
//! majority rule would each invent protocol semantics the specification never
//! states, and would then be indistinguishable from a rule that had been
//! normatively derived.
//!
//! Why a hard refusal and not a fallback: once `VaultStateAnchorV2` exists, `q`
//! is committed by the owner inside the signed anchor preimage (Definition
//! 6.4), and consumers READ the committed value rather than recomputing it from
//! set size. This helper therefore decides only what an owner may commit at
//! vault birth. A fallback here would let a nonconformant `q` be signed into an
//! anchor once and then be honoured forever by every verifier that trusts the
//! committed value — the divergence would survive precisely because the anchor
//! made it authoritative.
//!
//! ## Not the identity-publication threshold
//!
//! `dsm_sdk`'s `publication::quorum_for` is a strict-majority helper for wallet
//! identity publication, where majority is a deliberate choice so that one
//! unreachable node cannot block wallet creation. Req 6.13 does not govern it.
//! It is intentionally left alone; whether that threshold should change is a
//! separate design question that has not been reviewed.
//!
//! ## Wiring status
//!
//! The state-identity cut commits `q` inside the signed `V_n` (field 15),
//! sourced at birth from `quorum_for(|S|)` over the resolved catalog set —
//! which equals this profile's threshold for the three-member fleet. This
//! module remains the named, testable statement of the fixed profile a
//! conformance check reads against, rather than a recomputation.

/// The one storage-set cardinality the beta profile defines a threshold
/// for: the deployed three-member fleet.
pub const SOFI_BETA_MEMBERS: usize = 3;

/// The fixed threshold for that cardinality.
pub const SOFI_BETA_QUORUM: u32 = 2;

/// A storage set that is not the Rev 15 beta profile.
///
/// Carries the offending cardinality so a caller can say what it was handed
/// rather than only that something was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonconformantProfile {
    pub members: usize,
}

impl core::fmt::Display for NonconformantProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "storage set has {} members; the beta profile defines a threshold only for \
             the {}-member set, and no quorum function over other cardinalities",
            self.members, SOFI_BETA_MEMBERS
        )
    }
}

impl std::error::Error for NonconformantProfile {}

/// The owner-committed `q` for a Rev 15 beta storage set.
///
/// Returns `SOFI_BETA_QUORUM` for exactly `SOFI_BETA_MEMBERS`, and refuses
/// every other cardinality. There is no fallback and no interpolation: a set
/// size Rev 15 does not speak to is nonconformant, not approximately conformant.
pub fn sofi_beta_quorum_for(member_count: usize) -> Result<u32, NonconformantProfile> {
    if member_count == SOFI_BETA_MEMBERS {
        Ok(SOFI_BETA_QUORUM)
    } else {
        Err(NonconformantProfile {
            members: member_count,
        })
    }
}

/// Whether `q` is the threshold Rev 15 fixes for a set of this size.
///
/// The verifier's side of the same rule: a consumer reading a committed `q` out
/// of an anchor checks it here rather than recomputing a threshold of its own.
pub fn is_conformant_commitment(member_count: usize, committed_q: u32) -> bool {
    matches!(sofi_beta_quorum_for(member_count), Ok(q) if q == committed_q)
}

/// Single-node development threshold. **Never valid for a production anchor.**
///
/// `#[cfg(test)]` on purpose, and narrower than it strictly needs to be: no
/// production build can reach it, and neither can a non-test consumer in
/// another crate. The live one-node local-dev fleet does not need it, because
/// local dev stays on the legacy V1 path and its majority helper until the
/// clean cut.
///
/// It exists so that "development needs one node" has a named home other than a
/// fallback inside [`sofi_beta_quorum_for`] — which is the single change that
/// would undo this module. Widening this beyond `test` should be a deliberate
/// act with its own review, not a quiet edit to the attribute.
#[cfg(test)]
pub fn dev_only_single_node_quorum() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile the owner fixed for the deployed fleet.
    #[test]
    fn the_three_member_beta_set_commits_two() {
        assert_eq!(sofi_beta_quorum_for(3).expect("the beta profile"), 2);
        assert_eq!(SOFI_BETA_QUORUM, 2);
        assert_eq!(SOFI_BETA_MEMBERS, 3);
    }

    /// EVERY other cardinality is refused, including the ones that look
    /// plausible. `5` is the superseded profile, `1` is local dev, and `2`
    /// and `4` are one step either side — none of them is the beta storage
    /// set, and none may be silently mapped to a threshold.
    #[test]
    fn every_other_cardinality_is_refused_rather_than_mapped() {
        for n in [0usize, 1, 2, 4, 5, 6, 7, 9, 100] {
            let err = sofi_beta_quorum_for(n)
                .expect_err("only the three-member profile has a defined threshold");
            assert_eq!(err.members, n, "the error names the set it was handed");
        }
    }

    /// The refusals are not a majority rule wearing a different coat. If a
    /// future edit reintroduced `n/2 + 1` as a fallback, these would pass a
    /// value instead of erroring — so assert the specific thresholds a majority
    /// helper would have produced are NOT returned.
    #[test]
    fn no_majority_fallback_survives_behind_the_refusal() {
        for (n, majority) in [(1usize, 1u32), (5, 3), (6, 4), (7, 4)] {
            match sofi_beta_quorum_for(n) {
                Err(_) => {}
                Ok(q) => panic!(
                    "n={n} returned q={q} (majority would give {majority}) — \
                     a fallback has been reintroduced"
                ),
            }
        }
    }

    /// The verifier side agrees with the constructor side, and rejects a
    /// committed `q` that is merely plausible for the set size.
    #[test]
    fn a_committed_q_is_checked_against_the_profile_not_recomputed() {
        assert!(is_conformant_commitment(3, 2));
        assert!(
            !is_conformant_commitment(3, 3),
            "unanimity of three is not q"
        );
        assert!(
            !is_conformant_commitment(3, 1),
            "one-of-three is not q either"
        );
        assert!(
            !is_conformant_commitment(5, 4),
            "the superseded five-member profile is no longer conformant at any q"
        );
    }

    /// The dev threshold is reachable only from test/demos builds, and is not
    /// the production rule.
    #[test]
    fn the_dev_threshold_is_separate_from_the_profile() {
        assert_eq!(dev_only_single_node_quorum(), 1);
        assert!(
            sofi_beta_quorum_for(1).is_err(),
            "a one-node set is never a conformant beta profile, dev path or not"
        );
    }
}
