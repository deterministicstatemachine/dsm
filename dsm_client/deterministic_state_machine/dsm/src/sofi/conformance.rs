// SPDX-License-Identifier: Apache-2.0

//! Three-valued validation composition and the mechanical conformance of a
//! fulfillment `F` against its pre-commit `P`.
//!
//! Nothing here evaluates DLV policy, balances, canonicality, attempt liveness
//! or storage finality. `RouteValidation` is static semantic validity; the
//! checks below are the mechanical part of F ingress that needs only P, F and
//! the per-leg shadow digests committed by E.

use super::derive::{policy_fulfillment_id, precommit_id};
use super::wire::{
    next_position, DlvPolicyFulfillmentBody, SofiWireError, TraderFulfillmentBody,
    TraderPrecommitBody,
};

/// Static semantic validity. `Invalid` is permanent; `Unavailable` is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    Valid,
    Invalid,
    Unavailable,
}

impl Validation {
    /// The three-valued conjunction: any Invalid is Invalid; otherwise any
    /// Unavailable is Unavailable; otherwise Valid. Missing evidence can never
    /// mask a proven invalidity, and can never be read as one.
    pub fn and(self, other: Validation) -> Validation {
        match (self, other) {
            (Validation::Invalid, _) | (_, Validation::Invalid) => Validation::Invalid,
            (Validation::Unavailable, _) | (_, Validation::Unavailable) => Validation::Unavailable,
            _ => Validation::Valid,
        }
    }

    /// The conjunction over every per-leg and route-wide result.
    pub fn all(results: impl IntoIterator<Item = Validation>) -> Validation {
        results.into_iter().fold(Validation::Valid, Validation::and)
    }
}

/// Why a fulfillment is not a mechanical fulfillment of its pre-commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FulfillmentConformanceError {
    /// `F.precommit_id` does not name this P.
    PrecommitMismatch,
    /// `F.position` is not `P.position + 1`.
    PositionNotSuccessor { expected: u64, got: u64 },
    /// F is signed under a different algorithm or key than P commits.
    KeyMismatch,
    /// The caller supplied a shadow digest count that is not one per P leg.
    ShadowCountMismatch { legs: usize, shadows: usize },
    /// The policy-fulfillment set is not exactly the canonical derived set.
    PolicyFulfillmentSetNotCanonical,
    /// The attempt vector does not cover exactly P's legs.
    AttemptsDoNotCoverLegs,
    /// The successor position does not exist.
    Wire(SofiWireError),
}

/// The canonical `G_j` identity for every DLV leg of `P`, in P's leg order.
///
/// `shadow_cores[j]` is `c°_{V,j}`, the shadow digest E commits for leg `j`.
/// Because each `G_j` is a function of P's leg and E alone, a fulfillment has
/// exactly one admissible policy-fulfillment set.
pub fn derive_policy_fulfillments(
    precommit: &TraderPrecommitBody,
    shadow_cores: &[[u8; 32]],
) -> Result<Vec<DlvPolicyFulfillmentBody>, FulfillmentConformanceError> {
    if shadow_cores.len() != precommit.legs().len() {
        return Err(FulfillmentConformanceError::ShadowCountMismatch {
            legs: precommit.legs().len(),
            shadows: shadow_cores.len(),
        });
    }
    let pid = precommit_id(precommit);
    Ok(precommit
        .legs()
        .iter()
        .zip(shadow_cores)
        .map(|(leg, shadow)| DlvPolicyFulfillmentBody {
            precommit_id: pid,
            external_commitment: *precommit.external_commitment(),
            vault_id: leg.vault_id,
            parent_root: leg.parent_root,
            shadow_core: *shadow,
        })
        .collect())
}

/// The mechanical conformance of `F` to `P`: identity, successor position,
/// signing key, the complete canonical policy-fulfillment set, and an attempt
/// vector over exactly P's legs.
///
/// A subset, an extra identity, or a non-derived identity is refused — there
/// is no half-fulfillment. This does NOT require any referenced parent to be
/// unconsumed: a fulfillment may register after a parent is lost and then
/// resolves Void.
pub fn check_fulfillment_against_precommit(
    precommit: &TraderPrecommitBody,
    fulfillment: &TraderFulfillmentBody,
    shadow_cores: &[[u8; 32]],
) -> Result<(), FulfillmentConformanceError> {
    if fulfillment.precommit_id() != &precommit_id(precommit) {
        return Err(FulfillmentConformanceError::PrecommitMismatch);
    }
    let expected =
        next_position(precommit.position()).map_err(FulfillmentConformanceError::Wire)?;
    if fulfillment.position() != expected {
        return Err(FulfillmentConformanceError::PositionNotSuccessor {
            expected,
            got: fulfillment.position(),
        });
    }
    if fulfillment.signature_alg() != precommit.signature_alg()
        || fulfillment.claimant_public_key() != precommit.claimant_public_key()
    {
        return Err(FulfillmentConformanceError::KeyMismatch);
    }
    let mut derived: Vec<[u8; 32]> = derive_policy_fulfillments(precommit, shadow_cores)?
        .iter()
        .map(policy_fulfillment_id)
        .collect();
    derived.sort();
    if fulfillment.policy_fulfillment_set() != derived.as_slice() {
        return Err(FulfillmentConformanceError::PolicyFulfillmentSetNotCanonical);
    }
    let leg_vaults: Vec<[u8; 32]> = precommit.legs().iter().map(|l| l.vault_id).collect();
    let attempt_vaults: Vec<[u8; 32]> = fulfillment.attempts().iter().map(|a| a.vault_id).collect();
    if leg_vaults != attempt_vaults {
        return Err(FulfillmentConformanceError::AttemptsDoNotCoverLegs);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Validation::{Invalid, Unavailable, Valid};
    use super::*;

    #[test]
    fn invalid_dominates_and_unavailable_never_becomes_invalid() {
        assert_eq!(Valid.and(Valid), Valid);
        assert_eq!(Valid.and(Unavailable), Unavailable);
        assert_eq!(Unavailable.and(Invalid), Invalid);
        assert_eq!(Invalid.and(Unavailable), Invalid);
        assert_eq!(Validation::all([Valid, Unavailable, Valid]), Unavailable);
        assert_eq!(Validation::all([]), Valid);
    }
}
