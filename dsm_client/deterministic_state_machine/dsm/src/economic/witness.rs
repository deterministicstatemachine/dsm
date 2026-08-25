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
//! ## The witness object and the verifier input
//!
//! [`EconomicTransitionWitness`] (class `0x001D`) is the wire object: it
//! carries the roots, the operation identity, the mutations, and the **inline**
//! credit sources that fund the transition's credits. Its encoding is frozen.
//!
//! [`EconomicMutationSequence`] remains a **verification input, not a wire
//! object** — no class, no canonical bytes, nothing to sign. It exists because
//! recomputing a post-root needs only roots and mutations, and a verifier that
//! can be handed exactly that is a verifier that cannot accidentally depend on
//! provenance it has not checked.
//!
//! ## What the witness proves, and what it does not
//!
//! Structurally checkable from the bytes alone, with nothing fetched: source
//! count, source classes, ordering, credit-mutation indices, duplicate
//! mappings, and the credit/source bijection. Whether a named source
//! **actually establishes** the units it claims is acceptance semantics, and
//! none of that is implemented here.
//!
//! ## Why sequential
//!
//! Each mutation's siblings authenticate it against the root left by the
//! mutation before it, not against the transition's pre-root. A batch check
//! against a single root would accept two mutations that each look valid in
//! isolation but whose paths describe incompatible trees.

use crate::ccb::{class, push_digest32, push_envelope, push_u32, CcbError, CcbObject};
use crate::economic::credit::CreditSource;
use crate::types::identifiers::encode_crockford;
use crate::economic::mutation::EconomicLeafMutation;

/// `0x001D` schema 1 — a complete pre-root → post-root economic transition.
///
/// `operation_digest` and `economic_operation_id` are both members, and both
/// are load-bearing. Without a shared `operation_digest` binding the witness to
/// the local acceptance, a trader could present a valid successor and a valid
/// economic transition **describing different operations**.
///
/// The witness does **not** carry `trader_genesis` / `trader_devid`. Those come
/// from the authority resolution, and a witness that named its own identity
/// would let a producer choose whose tree it was mutating. That is also why
/// mutation key-ordering is checked by the verifier rather than the encoder:
/// leaf keys bind `G ‖ DevID`, which the encoder does not have and must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicTransitionWitness {
    pub pre_economic_root: [u8; 32],
    pub post_economic_root: [u8; 32],
    pub economic_operation_id: [u8; 32],
    pub operation_digest: [u8; 32],
    pub mutations: Vec<EconomicLeafMutation>,
    /// Strictly ascending by `credit_mutation_index`. Inline, heterogeneous
    /// CCB objects of classes `0x0023`–`0x0028`; each carries its own envelope,
    /// which is what keeps the sequence parseable without a side-channel
    /// discriminant.
    pub credit_sources: Vec<CreditSource>,
}

impl CcbObject for EconomicTransitionWitness {
    const CLASS: u16 = class::ECONOMIC_TRANSITION_WITNESS;
    const SCHEMA: u16 = 1;
}

impl EconomicTransitionWitness {
    /// Checks every structural rule, so an ill-formed witness has no canonical
    /// bytes and cannot be hash-addressed into an evidence DAG.
    pub fn new(
        pre_economic_root: [u8; 32],
        post_economic_root: [u8; 32],
        economic_operation_id: [u8; 32],
        operation_digest: [u8; 32],
        mutations: Vec<EconomicLeafMutation>,
        credit_sources: Vec<CreditSource>,
    ) -> Result<Self, CcbError> {
        let w = Self {
            pre_economic_root,
            post_economic_root,
            economic_operation_id,
            operation_digest,
            mutations,
            credit_sources,
        };
        w.check()?;
        Ok(w)
    }

    /// The frozen structural rules:
    ///
    /// ```text
    /// credit_sources strictly ascending by credit_mutation_index
    /// exactly one source for every positive credit
    /// no duplicate credit_mutation_index          (implied by strict ascent)
    /// no source for a non-credit mutation
    /// ```
    ///
    /// All four are decidable from the witness bytes alone.
    pub fn check(&self) -> Result<(), CcbError> {
        if self.mutations.is_empty() {
            return Err(CcbError::WitnessHasNoMutations);
        }

        let mut previous: Option<u32> = None;
        for (i, source) in self.credit_sources.iter().enumerate() {
            let index = source.credit_mutation_index();
            if let Some(prev) = previous {
                if index <= prev {
                    return Err(CcbError::CreditSourcesNotStrictlyAscending { index: i });
                }
            }
            previous = Some(index);

            let position = usize::try_from(index).map_err(|_| CcbError::CreditIndexOutOfRange {
                index,
                mutations: self.mutations.len(),
            })?;
            let mutation = self
                .mutations
                .get(position)
                .ok_or(CcbError::CreditIndexOutOfRange {
                    index,
                    mutations: self.mutations.len(),
                })?;
            if !mutation.is_positive_credit() {
                return Err(CcbError::SourceForNonCredit {
                    mutation_index: index,
                });
            }
            if let CreditSource::SameTransitionMove(m) = source {
                let debit = usize::try_from(m.debit_mutation_index).map_err(|_| {
                    CcbError::CreditIndexOutOfRange {
                        index: m.debit_mutation_index,
                        mutations: self.mutations.len(),
                    }
                })?;
                if debit >= self.mutations.len() {
                    return Err(CcbError::CreditIndexOutOfRange {
                        index: m.debit_mutation_index,
                        mutations: self.mutations.len(),
                    });
                }
                if debit == position {
                    return Err(CcbError::SameTransitionMoveIsSelfFunding { index });
                }
            }
        }

        // The other half of the bijection: every credit is funded. Checked
        // last so the more specific errors above win.
        for (i, mutation) in self.mutations.iter().enumerate() {
            if mutation.is_positive_credit()
                && !self
                    .credit_sources
                    .iter()
                    .any(|s| usize::try_from(s.credit_mutation_index()) == Ok(i))
            {
                return Err(CcbError::UnfundedCredit { mutation_index: i });
            }
        }
        Ok(())
    }

    /// Every distinct external evidence address the credit sources reference,
    /// sorted and deduplicated. This is exactly what
    /// `EconomicAdmissionManifest::provenance_evidence_addrs` must equal.
    pub fn derived_provenance_index(&self) -> Vec<[u8; 32]> {
        let mut addrs: Vec<[u8; 32]> = self
            .credit_sources
            .iter()
            .filter_map(CreditSource::external_evidence_addr)
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// Fields 1..6 in registry order. Both sequences are `u32` counts followed
    /// by inline complete CCB objects.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        self.check()?;
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.pre_economic_root); // 1
        push_digest32(&mut out, &self.post_economic_root); // 2
        push_digest32(&mut out, &self.economic_operation_id); // 3
        push_digest32(&mut out, &self.operation_digest); // 4

        let mutations =
            u32::try_from(self.mutations.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, mutations); // 5
        for mutation in &self.mutations {
            out.extend_from_slice(&mutation.encode()?);
        }

        let sources =
            u32::try_from(self.credit_sources.len()).map_err(|_| CcbError::LengthOverflow)?;
        push_u32(&mut out, sources); // 6
        for source in &self.credit_sources {
            out.extend_from_slice(&source.encode()?);
        }
        Ok(out)
    }

    /// The mutation sequence this witness asserts, for
    /// [`verify_mutation_sequence`].
    pub fn mutation_sequence(&self) -> EconomicMutationSequence {
        EconomicMutationSequence {
            pre_economic_root: self.pre_economic_root,
            post_economic_root: self.post_economic_root,
            mutations: self.mutations.clone(),
        }
    }
}

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
