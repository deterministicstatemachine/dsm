// SPDX-License-Identifier: Apache-2.0

//! The sequential economic-transition verifier.
//!
//! Given an authenticated pre-root and an ordered list of leaf mutations, this
//! recomputes the post-root the mutations actually produce. It is the half of
//! `verify_economic_transition` that establishes **what changed**. Establishing
//! **why a credit may appear** is credit provenance, which is a separate and
//! conjunctive obligation — a closed write set alone cannot distinguish a
//! funded credit from an invented one.
//!
//! ## Why the input is not a CCB object yet
//!
//! `EconomicTransitionWitness` (class `0x001D`) additionally carries
//! `credit_sources`, whose members are classes `0x0023`–`0x0028`. Those field
//! tables are not defined: the plan fixes those classes' semantic roles, not
//! an encoding exact enough to burn. A witness names its credit sources, so
//! its own encoding cannot be fixed before theirs.
//!
//! Writing an encoder for `0x001D` now would therefore fix, by implementation
//! accident, how a witness references its provenance — the "encoder defines
//! the protocol" inversion [`crate::ccb`] refuses in its own header. `0x001D`
//! is **allocated in [`crate::ccb::reserved`] and unusable on the wire** until
//! the provenance-wire freeze installs the schema; it is not merely
//! unimplemented, it has no canonical bytes to produce, hash-address or sign.
//!
//! That freeze is the **immediately following** PR, not a distant one, because
//! the admission manifest and evidence DAG need an exact, hash-addressable
//! transition witness. Carrying a noncanonical witness through lineage and
//! admission would mean retrofitting its hash identity afterwards, which is
//! the same mistake arriving later and more expensively.
//!
//! [`EconomicMutationSequence`] is therefore a **verification input, not a
//! wire object**: no class, no canonical bytes, nothing to sign.
//!
//! ## Why sequential
//!
//! Each mutation's siblings authenticate it against the root left by the
//! mutation before it, not against the transition's pre-root. A batch check
//! against a single root would accept two mutations that each look valid in
//! isolation but whose paths describe incompatible trees.

use crate::ccb::CcbError;
use crate::types::identifiers::encode_crockford;
use crate::economic::mutation::EconomicLeafMutation;

/// What a verifier is given to check a transition's write set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicMutationSequence {
    pub pre_economic_root: [u8; 32],
    pub post_economic_root: [u8; 32],
    /// Strictly ascending by **derived** leaf key. The ordering is canonical
    /// so that one write set has one representation, and duplicates are
    /// rejected rather than folded — two mutations at one key are two
    /// disagreeing claims about that leaf, not a sequence of edits.
    pub mutations: Vec<EconomicLeafMutation>,
}

/// Why a mutation sequence does not establish its claimed post-root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicWitnessError {
    /// No mutations. A transition that changes no economic leaf has no
    /// witness at all — it is `EconomicEffect::None`. An empty sequence
    /// asserting `pre == post` would be a witness for a non-event.
    EmptyMutationSet,
    /// Keys out of order, or repeated.
    KeysNotStrictlyAscending { index: usize },
    /// The mutation's pre-state is not a member of the root standing at that
    /// point in the sequence.
    PreStateNotInRoot {
        index: usize,
        expected_root: [u8; 32],
        derived_root: [u8; 32],
    },
    /// The mutations produce a different root than the one claimed.
    PostRootMismatch {
        claimed: [u8; 32],
        derived: [u8; 32],
    },
    /// A mutation or leaf state has no canonical bytes.
    Malformed { index: usize, cause: CcbError },
}

impl core::fmt::Display for EconomicWitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyMutationSet => write!(
                f,
                "economic witness: empty mutation set — a transition that changes no economic \
                 leaf has no witness, it has EconomicEffect::None"
            ),
            Self::KeysNotStrictlyAscending { index } => write!(
                f,
                "economic witness: mutation {index} is not strictly after its predecessor by \
                 derived leaf key — duplicates are two disagreeing claims about one leaf, not \
                 a sequence of edits"
            ),
            Self::PreStateNotInRoot {
                index,
                expected_root,
                derived_root,
            } => write!(
                f,
                "economic witness: mutation {index} pre-state is not in the standing root \
                 (expected {}, path derives {})",
                encode_crockford(expected_root),
                encode_crockford(derived_root)
            ),
            Self::PostRootMismatch { claimed, derived } => write!(
                f,
                "economic witness: mutations derive root {} but the witness claims {}",
                encode_crockford(derived),
                encode_crockford(claimed)
            ),
            Self::Malformed { index, cause } => {
                write!(
                    f,
                    "economic witness: mutation {index} is malformed: {cause}"
                )
            }
        }
    }
}

impl std::error::Error for EconomicWitnessError {}

/// Recompute the post-root a mutation sequence produces, and check it against
/// the claimed one.
///
/// `genesis` and `device_id` are the **authenticated** identity of the actor
/// whose economic tree this is — they must come from the P0–P6 authority
/// resolution, never from the witness. Every leaf key binds them, so supplying
/// them from the same object being verified would let a trader mutate a tree
/// it does not own.
///
/// Returns the derived post-root on success, which equals
/// `sequence.post_economic_root`.
pub fn verify_mutation_sequence(
    sequence: &EconomicMutationSequence,
    genesis: &[u8; 32],
    device_id: &[u8; 32],
) -> Result<[u8; 32], EconomicWitnessError> {
    if sequence.mutations.is_empty() {
        return Err(EconomicWitnessError::EmptyMutationSet);
    }

    let mut root = sequence.pre_economic_root;
    let mut previous_key: Option<[u8; 32]> = None;

    for (index, mutation) in sequence.mutations.iter().enumerate() {
        let malformed = |cause: CcbError| EconomicWitnessError::Malformed { index, cause };

        let key = mutation.leaf_key(genesis, device_id).map_err(malformed)?;
        if let Some(prev) = previous_key {
            if key <= prev {
                return Err(EconomicWitnessError::KeysNotStrictlyAscending { index });
            }
        }
        previous_key = Some(key);

        let derived_pre = mutation
            .expected_pre_root(genesis, device_id)
            .map_err(malformed)?;
        if derived_pre != root {
            return Err(EconomicWitnessError::PreStateNotInRoot {
                index,
                expected_root: root,
                derived_root: derived_pre,
            });
        }

        root = mutation
            .resulting_root(genesis, device_id)
            .map_err(malformed)?;
    }

    if root != sequence.post_economic_root {
        return Err(EconomicWitnessError::PostRootMismatch {
            claimed: sequence.post_economic_root,
            derived: root,
        });
    }
    Ok(root)
}
