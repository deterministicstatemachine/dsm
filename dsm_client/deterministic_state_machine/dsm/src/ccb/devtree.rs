// SPDX-License-Identifier: Apache-2.0

//! Device Tree root-progression objects — registry §5.16–§5.18, substrate
//! classes `0x0019` and `0x001A`.
//!
//! Each object is both hashed and signed, under **two domains over one
//! preimage** (§2.9): an identity domain for its digest and a signing domain
//! for its signature. The signature is never a field of the CCB — the CCB
//! *is* the signed preimage.
//!
//! ```text
//! del_i = H_dom(DSM/devtree-delegation, CCB(D_i))       # identity
//! GRK signs H_dom(DSM/devtree-delegation-sign, CCB(D_i))
//!
//! t_j   = H_dom(DSM/devtree-transition, CCB(T_j))       # identity
//! delegate signs H_dom(DSM/devtree-transition-sign, CCB(T_j))
//! ```

use super::{push_bytes, push_digest32, push_envelope, push_u16, push_u64, CcbError, CcbObject};
use crate::common::domain_tags::{
    TAG_DSM_DEVTREE_DELEGATION, TAG_DSM_DEVTREE_DELEGATION_GENESIS_SENTINEL_V1,
    TAG_DSM_DEVTREE_DELEGATION_SIGN, TAG_DSM_DEVTREE_TRANSITION,
    TAG_DSM_DEVTREE_TRANSITION_GENESIS_SENTINEL_V1, TAG_DSM_DEVTREE_TRANSITION_SIGN,
};
use crate::crypto::blake3::dsm_domain_hasher;

/// `authority_role` — registry §3.1. The scope a root-authority delegation
/// confers. Deliberately narrow: the GRK exists to delegate one capability,
/// and a role meaning "may act for the owner" would make the delegation a
/// universal authority, which the area 8 semantics forbid.
pub mod role {
    /// May sign `0x001A` transitions for the named genesis, and nothing else.
    pub const DEVICE_TREE_ROOT_PROGRESSION: u16 = 0x0001;
    /// The one role version the beta profile declares.
    pub const BETA_ROLE_VERSION: u16 = 1;
}

/// Delegation chain origin: `H_dom(tag, ε)` — a constant. Used as
/// `parent_delegation_digest` at `i = 0`.
pub fn delegation_genesis_sentinel() -> [u8; 32] {
    *dsm_domain_hasher(TAG_DSM_DEVTREE_DELEGATION_GENESIS_SENTINEL_V1)
        .finalize()
        .as_bytes()
}

/// Transition chain origin: `H_dom(tag, ε)` — a constant. Used as
/// `activation_transition_digest` at `i = 0` ("effective from the start of
/// the chain") and as `predecessor_transition_digest` at `j = 0` — both
/// denote the same thing: the position before `T_0`.
pub fn transition_genesis_sentinel() -> [u8; 32] {
    *dsm_domain_hasher(TAG_DSM_DEVTREE_TRANSITION_GENESIS_SENTINEL_V1)
        .finalize()
        .as_bytes()
}

/// `0x0019` schema 1 — a GRK-signed root-progression delegation.
///
/// Field 5 names the authorized key **by key, never by DevID or tree
/// position** — that is the whole non-circularity condition: nothing about
/// the delegation's validity depends on the Device Tree it authorizes
/// changes to.
///
/// Field 8 names a **transition digest, not a root value**, because root
/// values recur (add a device, remove it, and the root returns); a root
/// value would activate a delegation at two chain positions at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootProgressionDelegation {
    pub genesis_id: [u8; 32],
    pub role: u16,
    pub role_version: u16,
    pub delegated_alg_id: u16,
    pub delegated_pk: Vec<u8>,
    pub delegation_number: u64,
    /// `del_{i−1}`; [`delegation_genesis_sentinel`] at `i = 0`.
    pub parent_delegation_digest: [u8; 32],
    /// The transition **after** which this delegation takes effect;
    /// [`transition_genesis_sentinel`] at `i = 0`.
    pub activation_transition_digest: [u8; 32],
}

impl CcbObject for RootProgressionDelegation {
    const CLASS: u16 = super::class::ROOT_PROGRESSION_DELEGATION;
    const SCHEMA: u16 = 1;
}

impl RootProgressionDelegation {
    /// Fields 1..8 in registry order. Validates the key against its declared
    /// algorithm width, exactly as `GenesisParamsV3` does.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let expected = super::genesis::sigalg::public_key_len(self.delegated_alg_id).ok_or(
            CcbError::UnknownSignatureAlg {
                alg: self.delegated_alg_id,
            },
        )?;
        if self.delegated_pk.len() != expected {
            return Err(CcbError::KeyLengthMismatch {
                alg: self.delegated_alg_id,
                expected,
                got: self.delegated_pk.len(),
            });
        }
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.genesis_id); // 1
        push_u16(&mut out, self.role); // 2
        push_u16(&mut out, self.role_version); // 3
        push_u16(&mut out, self.delegated_alg_id); // 4
        push_bytes(&mut out, &self.delegated_pk)?; // 5
        push_u64(&mut out, self.delegation_number); // 6
        push_digest32(&mut out, &self.parent_delegation_digest); // 7
        push_digest32(&mut out, &self.activation_transition_digest); // 8
        Ok(out)
    }

    /// `del_i = H_dom(DSM/devtree-delegation, CCB(D_i))`.
    pub fn digest(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_DEVTREE_DELEGATION);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }

    /// The 32-byte message the GRK signs:
    /// `H_dom(DSM/devtree-delegation-sign, CCB(D_i))`.
    pub fn signing_digest(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_DEVTREE_DELEGATION_SIGN);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }
}

/// `0x001A` schema 1 — a delegate-signed Device Tree root transition.
///
/// Field 2 is an **edge, not a state value**: root values recur, so
/// `old_root` plus a monotone version does not identify a unique predecessor
/// — one signed transition would attach at two positions with two ancestries,
/// and withholding could shorten an ancestry until a superseded delegation's
/// activation fell out of scope. The predecessor digest makes ancestry a
/// property of the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTreeRootTransition {
    pub genesis_id: [u8; 32],
    /// `t_{j−1}`; [`transition_genesis_sentinel`] at `j = 0`.
    pub predecessor_transition_digest: [u8; 32],
    /// The Device Tree Merkle root this transition establishes.
    pub new_root: [u8; 32],
    /// Strictly monotone; an ordering assertion, never the ancestry
    /// mechanism.
    pub version_number: u64,
    /// `del_i` of the delegation this transition acts under.
    pub delegation_digest: [u8; 32],
}

impl CcbObject for DeviceTreeRootTransition {
    const CLASS: u16 = super::class::DEVICE_TREE_ROOT_TRANSITION;
    const SCHEMA: u16 = 1;
}

impl DeviceTreeRootTransition {
    /// Fields 1..5 in registry order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.genesis_id); // 1
        push_digest32(&mut out, &self.predecessor_transition_digest); // 2
        push_digest32(&mut out, &self.new_root); // 3
        push_u64(&mut out, self.version_number); // 4
        push_digest32(&mut out, &self.delegation_digest); // 5
        out
    }

    /// `t_j = H_dom(DSM/devtree-transition, CCB(T_j))`.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_DEVTREE_TRANSITION);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// The 32-byte message the delegated key signs:
    /// `H_dom(DSM/devtree-transition-sign, CCB(T_j))`.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = dsm_domain_hasher(TAG_DSM_DEVTREE_TRANSITION_SIGN);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sentinels match the spec construction — `BLAKE3(tag ‖ 0x00)` over
    /// empty input, tags typed from the registry — and are distinct from each
    /// other and from the all-zero digest.
    #[test]
    fn sentinels_match_the_spec_and_are_distinct() {
        let mut d = b"DSM/devtree-delegation/genesis-sentinel/v1".to_vec();
        d.push(0x00);
        assert_eq!(delegation_genesis_sentinel(), *blake3::hash(&d).as_bytes());

        let mut t = b"DSM/devtree-transition/genesis-sentinel/v1".to_vec();
        t.push(0x00);
        assert_eq!(transition_genesis_sentinel(), *blake3::hash(&t).as_bytes());

        assert_ne!(delegation_genesis_sentinel(), transition_genesis_sentinel());
        assert_ne!(delegation_genesis_sentinel(), [0u8; 32]);
        assert_ne!(transition_genesis_sentinel(), [0u8; 32]);
    }

    /// Identity and signing digests differ over the same CCB — two domains,
    /// one preimage — so a digest can never be replayed as a signature
    /// preimage or vice versa.
    #[test]
    fn identity_and_signing_domains_do_not_collide() {
        let t = DeviceTreeRootTransition {
            genesis_id: [1; 32],
            predecessor_transition_digest: transition_genesis_sentinel(),
            new_root: [2; 32],
            version_number: 0,
            delegation_digest: [3; 32],
        };
        assert_ne!(t.digest(), t.signing_digest());
    }

    /// A mis-sized delegated key is refused at encode, like every other
    /// declared-width key in the registry.
    #[test]
    fn a_wrong_length_delegated_key_is_refused() {
        let d = RootProgressionDelegation {
            genesis_id: [1; 32],
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: super::super::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: vec![0u8; 32], // not 64
            delegation_number: 0,
            parent_delegation_digest: delegation_genesis_sentinel(),
            activation_transition_digest: transition_genesis_sentinel(),
        };
        assert!(d.encode().is_err());
    }
}
