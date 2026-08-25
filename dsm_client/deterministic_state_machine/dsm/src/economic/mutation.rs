// SPDX-License-Identifier: Apache-2.0

//! `EconomicLeafMutation` — CCB class `0x001E`.
//!
//! One leaf changing, with the authentication path that proves what it was.
//! A mutation carries **no key**: the key is derived from the state objects it
//! carries, which is what makes "valid object filed at the wrong position"
//! unrepresentable rather than merely checked for.
//!
//! The sibling count is exactly [`ECONOMIC_SMT_HEIGHT`] and that is a validity
//! condition, not a bound. A variable-length path lets a producer prove
//! membership in a shallower tree and present it as membership in this one.

use crate::ccb::{class, push_absent, push_envelope, push_present, CcbError, CcbObject};
use crate::economic::state::EconomicLeafState;
use crate::economic::tree::{leaf_node, root_from_path, ECONOMIC_SMT_HEIGHT};

/// `0x001E` schema 1 — a single leaf's pre-state, post-state and path.
///
/// At least one of `pre_state` and `post_state` is present:
///
/// ```text
/// pre absent,  post present  =>  insertion
/// pre present, post present  =>  replacement (same position, checked)
/// pre present, post absent   =>  removal (how a balance reaches zero)
/// pre absent,  post absent   =>  INVALID
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicLeafMutation {
    pub pre_state: Option<EconomicLeafState>,
    pub post_state: Option<EconomicLeafState>,
    pub siblings: Vec<[u8; 32]>,
}

impl CcbObject for EconomicLeafMutation {
    const CLASS: u16 = class::ECONOMIC_LEAF_MUTATION;
    const SCHEMA: u16 = 1;
}

impl EconomicLeafMutation {
    /// Checks the conditions that make a mutation well-formed at all, so an
    /// ill-formed one has no canonical bytes and cannot reach a verifier.
    pub fn new(
        pre_state: Option<EconomicLeafState>,
        post_state: Option<EconomicLeafState>,
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, CcbError> {
        let m = Self {
            pre_state,
            post_state,
            siblings,
        };
        m.check()?;
        Ok(m)
    }

    fn check(&self) -> Result<(), CcbError> {
        if self.pre_state.is_none() && self.post_state.is_none() {
            return Err(CcbError::MutationBothStatesAbsent);
        }
        if self.siblings.len() != ECONOMIC_SMT_HEIGHT {
            return Err(CcbError::MutationSiblingCount {
                expected: ECONOMIC_SMT_HEIGHT,
                got: self.siblings.len(),
            });
        }
        if let (Some(pre), Some(post)) = (&self.pre_state, &self.post_state) {
            if pre.position_material() != post.position_material() {
                return Err(CcbError::MutationClassMismatch {
                    pre: pre.class(),
                    post: post.class(),
                });
            }
        }
        Ok(())
    }

    /// The leaf this mutation touches. Both states agree on it by
    /// construction, so either one answers.
    pub fn leaf_key(&self, genesis: &[u8; 32], device_id: &[u8; 32]) -> Result<[u8; 32], CcbError> {
        self.check()?;
        let state = self
            .pre_state
            .as_ref()
            .or(self.post_state.as_ref())
            .ok_or(CcbError::MutationBothStatesAbsent)?;
        Ok(state.leaf_key(genesis, device_id))
    }

    /// The root this mutation's pre-state must be a member of.
    pub fn expected_pre_root(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<[u8; 32], CcbError> {
        let key = self.leaf_key(genesis, device_id)?;
        let value = match &self.pre_state {
            None => None,
            Some(s) => Some(s.leaf_value()?),
        };
        Ok(root_from_path(
            &key,
            &leaf_node(&key, value.as_ref()),
            &self.sibling_array()?,
        ))
    }

    /// The root that results from applying this mutation.
    pub fn resulting_root(
        &self,
        genesis: &[u8; 32],
        device_id: &[u8; 32],
    ) -> Result<[u8; 32], CcbError> {
        let key = self.leaf_key(genesis, device_id)?;
        let value = match &self.post_state {
            None => None,
            Some(s) => Some(s.leaf_value()?),
        };
        Ok(root_from_path(
            &key,
            &leaf_node(&key, value.as_ref()),
            &self.sibling_array()?,
        ))
    }

    fn sibling_array(&self) -> Result<[[u8; 32]; ECONOMIC_SMT_HEIGHT], CcbError> {
        self.siblings
            .as_slice()
            .try_into()
            .map_err(|_| CcbError::MutationSiblingCount {
                expected: ECONOMIC_SMT_HEIGHT,
                got: self.siblings.len(),
            })
    }

    /// Whether this mutation increases a quantity, and therefore owes a
    /// funding source.
    ///
    /// Computable from the mutation **alone** — no identity, no fetched
    /// evidence, no tree. That is what lets a verifier check the
    /// credit/source bijection before retrieving a single provenance blob.
    /// An absent state counts as zero, so an insertion of 25 is a credit and a
    /// removal is not.
    pub fn is_positive_credit(&self) -> bool {
        let amount = |s: &Option<EconomicLeafState>| {
            s.as_ref()
                .and_then(EconomicLeafState::credit_amount)
                .unwrap_or(0)
        };
        amount(&self.post_state) > amount(&self.pre_state)
    }

    /// Fields 1..3 in registry order. Optionals carry their marker even when
    /// absent, so an absent pre-state cannot shift the post-state into its
    /// place.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        self.check()?;
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        for state in [&self.pre_state, &self.post_state] {
            // 1, 2
            match state {
                None => push_absent(&mut out),
                Some(s) => {
                    push_present(&mut out);
                    out.extend_from_slice(&s.encode()?);
                }
            }
        }
        for sibling in &self.siblings {
            // 3 — fixed count, so no length prefix
            out.extend_from_slice(sibling);
        }
        Ok(out)
    }
}
