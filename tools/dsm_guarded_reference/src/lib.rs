//! DSM guarded-candidate enforcement — reference implementation.
//!
//! Self-contained realization of Appendix D of Ramsay, "Deterministic State
//! Machines as Guarded Linear Constraint Systems" (June 2026): the production
//! enforcement rule for resource keys, as `verify_candidate` / `apply_candidate`.
//!
//! This mirrors, in executable Rust, the formal model proved in
//! `lean4/DSMGuardedTripwire.lean` and model-checked in `tla/DSM_Guarded.tla`:
//!
//!   * resource consumption keys are DERIVED from the parent state and the
//!     canonical resource descriptors (paper Rule 2, Def 27 — never accepted
//!     from branch-supplied data);
//!   * a candidate is rejected unless its committed keys equal the derived keys,
//!     its guard family is well formed (no conflict-class key split — G5/G7),
//!     and none of its keys are already in the consumed-parent set Sigma;
//!   * the successor is canonically recomputed and its digest must match the
//!     committed candidate digest.
//!
//! It is a REFERENCE artifact: standalone, dependency-free, not wired into the
//! production state machine. The `derive`/`commit`/`digest` functions are simple
//! deterministic stand-ins for the protocol's BLAKE3 domain-separated hashes —
//! only determinism is needed to exercise the enforcement logic.

use std::collections::BTreeSet;

/// Resource consumption key kappa_res(s, x) (paper Def 27). Derived from the
/// parent root and a canonical resource descriptor — never branch-supplied.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ResKey {
    pub parent_root: u64,
    pub descriptor: u64,
}

/// A precommitted candidate branch in a guard family Gamma_s (paper Def 11, 14).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Branch {
    pub bid: u64,
    /// The single resource consumption key this branch consumes.
    pub key: ResKey,
    /// Canonically recomputed successor root digest (StructuralOK, Def 38).
    pub succ: u64,
    /// Committed digest of the successor's guard family (rho component).
    pub next_fam_digest: u64,
    /// Whether a canonical witness verifies this branch's guard (GuardOK).
    pub guard: bool,
}

/// The DSM parent state: current root, the consumed-parent set Sigma, and the
/// committed guard family Gamma_s.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct State {
    pub root: u64,
    pub consumed: BTreeSet<ResKey>,
    pub family: Vec<Branch>,
}

/// A candidate transition presented to the verifier (paper Def 11). The
/// `committed_keys` and `successor_digest` are what the parent root commits to;
/// the verifier re-derives them and rejects on mismatch (Rule 2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Candidate {
    /// Index of the chosen branch within `parent.family`.
    pub branch_index: usize,
    /// Canonical resource descriptor(s) the candidate claims to consume.
    pub resource_descriptors: Vec<u64>,
    /// Keys the candidate claims (must equal the derived keys).
    pub committed_keys: BTreeSet<ResKey>,
    /// Committed successor digest (must equal the recomputed digest).
    pub successor_digest: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BranchOutOfRange,
    ResourceKeyMismatch,
    MalformedGuardFamily,
    ConflictKeySplit,
    AlreadyConsumed,
    GuardNotFulfilled,
    SuccessorDigestMismatch,
}

/// Derive the authoritative resource consumption keys from the parent state and
/// the candidate's canonical resource descriptors (paper Rule 2 / Def 27).
/// kappa_res(s, x) is modeled as `(parent.root, descriptor)`.
fn derive_resource_keys(parent: &State, descriptors: &[u64]) -> BTreeSet<ResKey> {
    descriptors
        .iter()
        .map(|&d| ResKey {
            parent_root: parent.root,
            descriptor: d,
        })
        .collect()
}

/// Guard-family well-formedness (paper Rule 1, G5 exclusive fulfillment + G7
/// resource-key consistency): any two FULFILLED branches sharing a key must
/// resolve to the same successor and successor-family digest.
fn guard_family_well_formed(family: &[Branch]) -> bool {
    for (i, a) in family.iter().enumerate() {
        for b in family.iter().skip(i + 1) {
            if a.guard
                && b.guard
                && a.key == b.key
                && (a.succ != b.succ || a.next_fam_digest != b.next_fam_digest)
            {
                return false;
            }
        }
    }
    true
}

/// A conflict class has a key split when two fulfilled branches consume the same
/// key but resolve to different successors (the malformed case that forks).
fn conflict_class_has_key_split(family: &[Branch]) -> bool {
    for (i, a) in family.iter().enumerate() {
        for b in family.iter().skip(i + 1) {
            if a.guard && b.guard && a.key == b.key && a.succ != b.succ {
                return true;
            }
        }
    }
    false
}

fn consumed_set_contains_any(consumed: &BTreeSet<ResKey>, keys: &BTreeSet<ResKey>) -> bool {
    keys.iter().any(|k| consumed.contains(k))
}

/// Deterministic stand-in for the canonical successor recomputation
/// (paper App. D `recompute_successor`; production uses BLAKE3). The digest is a
/// pure function of (parent root, branch successor, next-family digest, the
/// consumed key set), so two candidates with the same committed digest from the
/// same parent are bound to the same successor.
fn successor_digest(parent_root: u64, branch: &Branch, next_consumed: &BTreeSet<ResKey>) -> u64 {
    let mut acc = parent_root
        .wrapping_mul(0x9E3779B1)
        .wrapping_add(branch.succ.wrapping_mul(31))
        .wrapping_add(branch.next_fam_digest.wrapping_mul(131));
    for k in next_consumed {
        acc = acc
            .wrapping_add(k.parent_root.wrapping_mul(17))
            .wrapping_add(k.descriptor.wrapping_mul(19))
            .rotate_left(7);
    }
    acc
}

/// Verify a candidate against the parent state (paper App. D `verify_candidate`).
/// Returns the chosen branch and the derived key set on success.
pub fn verify_candidate<'a>(
    parent: &'a State,
    candidate: &Candidate,
) -> Result<(&'a Branch, BTreeSet<ResKey>), Error> {
    let branch = parent
        .family
        .get(candidate.branch_index)
        .ok_or(Error::BranchOutOfRange)?;

    let derived_keys = derive_resource_keys(parent, &candidate.resource_descriptors);

    // Rule 2: keys must be derived, not branch-supplied.
    if derived_keys != candidate.committed_keys {
        return Err(Error::ResourceKeyMismatch);
    }
    // The branch must actually consume the derived key set.
    if !derived_keys.contains(&branch.key) || derived_keys.len() != 1 {
        return Err(Error::ResourceKeyMismatch);
    }
    if !guard_family_well_formed(&parent.family) {
        return Err(Error::MalformedGuardFamily);
    }
    if conflict_class_has_key_split(&parent.family) {
        return Err(Error::ConflictKeySplit);
    }
    if consumed_set_contains_any(&parent.consumed, &derived_keys) {
        return Err(Error::AlreadyConsumed);
    }
    // GuardOK (Def 37): the branch's guard must be fulfilled.
    if !branch.guard {
        return Err(Error::GuardNotFulfilled);
    }
    Ok((branch, derived_keys))
}

/// Verify and apply a candidate, producing the canonical successor state
/// (paper App. D `apply_candidate`). Rejects on a successor-digest mismatch.
pub fn apply_candidate(parent: &State, candidate: &Candidate) -> Result<State, Error> {
    let (branch, keys) = verify_candidate(parent, candidate)?;

    let mut next_consumed = parent.consumed.clone();
    for k in &keys {
        next_consumed.insert(*k);
    }

    let digest = successor_digest(parent.root, branch, &next_consumed);
    if digest != candidate.successor_digest {
        return Err(Error::SuccessorDigestMismatch);
    }

    Ok(State {
        root: branch.succ,
        consumed: next_consumed,
        family: Vec::new(), // successor's committed family is a separate concern
    })
}

/// Helper for callers/tests: the digest a well-formed candidate must commit to.
pub fn expected_successor_digest(parent: &State, branch: &Branch) -> u64 {
    let mut next_consumed = parent.consumed.clone();
    next_consumed.insert(branch.key);
    successor_digest(parent.root, branch, &next_consumed)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // unwrap/expect are idiomatic in tests
mod tests {
    use super::*;

    fn k(parent_root: u64, descriptor: u64) -> ResKey {
        ResKey {
            parent_root,
            descriptor,
        }
    }

    /// Well-formed parent: a real conflict class {bid 1, bid 2} at key (root=0,
    /// desc=1) resolving to the SAME successor, plus a disjoint branch at a
    /// different key.
    fn well_formed_parent() -> State {
        State {
            root: 0,
            consumed: BTreeSet::new(),
            family: vec![
                Branch { bid: 1, key: k(0, 1), succ: 10, next_fam_digest: 100, guard: true },
                Branch { bid: 2, key: k(0, 1), succ: 10, next_fam_digest: 100, guard: true },
                Branch { bid: 3, key: k(0, 2), succ: 20, next_fam_digest: 200, guard: true },
            ],
        }
    }

    fn candidate_for(parent: &State, branch_index: usize, descriptor: u64) -> Candidate {
        let branch = &parent.family[branch_index];
        let mut committed = BTreeSet::new();
        committed.insert(branch.key);
        Candidate {
            branch_index,
            resource_descriptors: vec![descriptor],
            committed_keys: committed,
            successor_digest: expected_successor_digest(parent, branch),
        }
    }

    #[test]
    fn well_formed_candidate_accepts_and_consumes() {
        let parent = well_formed_parent();
        let cand = candidate_for(&parent, 0, 1);
        let next = apply_candidate(&parent, &cand).expect("well-formed candidate must apply");
        assert_eq!(next.root, 10);
        assert!(next.consumed.contains(&k(0, 1)));
    }

    #[test]
    fn conflict_class_two_candidates_same_successor() {
        // Corollary 1: candidate multiplicity (two branches at the same key)
        // does not produce a realized fork — both resolve to the same successor.
        let parent = well_formed_parent();
        let a = apply_candidate(&parent, &candidate_for(&parent, 0, 1)).unwrap();
        let b = apply_candidate(&parent, &candidate_for(&parent, 1, 1)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn disjoint_keys_progress_independently() {
        // Prop 12 / DisjointProgressAllowed: distinct keys reach distinct
        // successors and that is not a fork.
        let parent = well_formed_parent();
        let a = apply_candidate(&parent, &candidate_for(&parent, 0, 1)).unwrap();
        let c = apply_candidate(&parent, &candidate_for(&parent, 2, 2)).unwrap();
        assert_ne!(a.root, c.root);
    }

    #[test]
    fn key_split_family_rejects() {
        // Malformed: two fulfilled branches at the same key, different succ.
        let mut parent = well_formed_parent();
        parent.family = vec![
            Branch { bid: 1, key: k(0, 1), succ: 10, next_fam_digest: 100, guard: true },
            Branch { bid: 4, key: k(0, 1), succ: 99, next_fam_digest: 100, guard: true },
        ];
        let cand = candidate_for(&parent, 0, 1);
        let err = verify_candidate(&parent, &cand).unwrap_err();
        assert!(err == Error::MalformedGuardFamily || err == Error::ConflictKeySplit);
    }

    #[test]
    fn already_consumed_key_rejects() {
        let mut parent = well_formed_parent();
        parent.consumed.insert(k(0, 1));
        let cand = candidate_for(&parent, 0, 1);
        assert_eq!(verify_candidate(&parent, &cand).unwrap_err(), Error::AlreadyConsumed);
    }

    #[test]
    fn branch_supplied_keys_rejected_when_not_derived() {
        // Rule 2: a candidate cannot smuggle a key set that differs from the
        // keys derived from the parent + descriptors.
        let parent = well_formed_parent();
        let mut cand = candidate_for(&parent, 0, 1);
        cand.committed_keys = {
            let mut s = BTreeSet::new();
            s.insert(k(0, 999)); // not derivable from descriptor 1
            s
        };
        assert_eq!(verify_candidate(&parent, &cand).unwrap_err(), Error::ResourceKeyMismatch);
    }

    #[test]
    fn wrong_successor_digest_rejects() {
        let parent = well_formed_parent();
        let mut cand = candidate_for(&parent, 0, 1);
        cand.successor_digest ^= 0xDEAD_BEEF;
        assert_eq!(apply_candidate(&parent, &cand).unwrap_err(), Error::SuccessorDigestMismatch);
    }

    #[test]
    fn unfulfilled_guard_rejects() {
        let mut parent = well_formed_parent();
        parent.family[0].guard = false;
        let cand = candidate_for(&parent, 0, 1);
        assert_eq!(verify_candidate(&parent, &cand).unwrap_err(), Error::GuardNotFulfilled);
    }
}
