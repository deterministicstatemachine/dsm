// SPDX-License-Identifier: MIT OR Apache-2.0

//! Genesis hashing — the canonical DSM genesis hash `G` (binary-only).
//!
//! Deterministic, BLAKE3 domain-separated computation of the genesis hash per
//! whitepaper §2.5. Genesis is an n-of-n commit-then-reveal entropy aggregation
//! (≥3 storage nodes each contribute `b_i`, revealed and folded into one hash) —
//! NOT threshold cryptography; `b_1, …, b_n` is index notation for "all n
//! contributions", with no t-of-n DKG or Shamir. This module is the single
//! source of truth for `G`, used by both the genesis session (producer) and
//! `verify_genesis_state` (verifier).
//!
//! Acyclic form (whitepaper §2.5):
//!
//! ```text
//! G := H_g("DSM/genesis"
//!          ∥ device_id
//!          ∥ ( "DSM/genesis/mpc\0" ∥ H(m_i)  for each contribution, sorted ))
//! ```
//!
//! The public-key bundle is deliberately EXCLUDED from `G`: keys are *derived
//! from* `G` (`keys ← S_master ← G`; GenesisV2 is mnemonic-rooted), so folding
//! them back into the preimage would be circular. They bind to genesis by
//! derivation, not by inclusion. Anti-cloning is NOT part of `G`: it is enforced
//! downstream by the fused hardware anchor (σ^chip + σ^host), not by any device
//! fingerprint (the former K_DBRW binding was removed). Wall-clock and mutable metadata are likewise
//! excluded, keeping `G` clockless and publicly recomputable from the public
//! `device_id` plus the revealed contributions. No hex/json/base64/serde here.

use crate::crypto::blake3::{domain_hash, dsm_domain_hasher};

/// Fixed-length digest (BLAKE3).
pub type Digest32 = [u8; 32];

/// Sub-domain separator isolating each per-contribution digest inside the
/// already domain-separated genesis hasher (`dsm_domain_hasher("DSM/genesis")`),
/// so contribution folds cannot collide with any other region of the preimage.
const DOMAIN_MPC: &[u8] = b"DSM/genesis/mpc\0";

/// A single genesis contribution: one storage node's revealed entropy, or the
/// device's own contribution. Only `contribution_hash` is folded into `G`;
/// `contributor_id` is a deterministic tie-breaker for the canonical sort and
/// is never part of the preimage.
#[derive(Clone, Debug)]
pub struct MPCContribution {
    /// ID of the contributing party (storage node or device). Tie-breaker only.
    pub contributor_id: String,
    /// Canonical 32-byte digest of the contribution material, `H(m_i)`.
    pub contribution_hash: Digest32,
    /// Signature over the contribution (verified upstream; not folded into `G`).
    pub signature: Vec<u8>,
    /// Non-canonical tick of contribution (UI/ops only; not folded into `G`).
    pub tick: u64,
}

impl MPCContribution {
    /// Create a new contribution record (does not verify signature content).
    pub fn new(
        contributor_id: String,
        contribution_hash: Digest32,
        signature: Vec<u8>,
        tick: u64,
    ) -> Self {
        Self {
            contributor_id,
            contribution_hash,
            signature,
            tick,
        }
    }
}

/// Canonical digest of one contribution's raw material, `H(m_i)`.
///
/// Domain-separated so contribution digests cannot collide with any other
/// BLAKE3 use, and so variable-length materials (the device contribution is
/// `device_id ∥ device_entropy`; node contributions are 32-byte entropies) all
/// normalise to a uniform 32-byte fold input.
pub fn hash_contribution(material: &[u8]) -> Digest32 {
    *domain_hash(crate::tagged_domain!(b"DSM/genesis/contribution"), material).as_bytes()
}

/// Compute the canonical genesis hash `G` (whitepaper §2.5, acyclic form).
///
/// ```text
/// G := H_g("DSM/genesis" ∥ device_id ∥ ⟦ "DSM/genesis/mpc\0" ∥ H(m_i) ⟧ sorted )
/// ```
///
/// Contributions are folded in canonical order — sorted by
/// `(contribution_hash, contributor_id)` — so transport-time ordering cannot
/// change `G`. Only `contribution_hash` enters the preimage; `contributor_id`
/// breaks ties solely in the (cryptographically unreachable) event of equal
/// contribution hashes, where the folded bytes are identical regardless.
///
/// `G` is acyclic and publicly recomputable: it depends only on `device_id`
/// and the revealed contributions, never on values derived from `G` (keys,
/// keys), which bind to genesis by being derived from it.
pub fn compute_genesis_hash(device_id: &[u8; 32], contributions: &[MPCContribution]) -> Digest32 {
    let mut h = dsm_domain_hasher(crate::crypto::domain::TaggedHashDomain::from_static(
        b"DSM/genesis",
    ));
    h.update(device_id);

    let mut ordered: Vec<&MPCContribution> = contributions.iter().collect();
    ordered.sort_by(|a, b| {
        a.contribution_hash
            .cmp(&b.contribution_hash)
            .then_with(|| a.contributor_id.cmp(&b.contributor_id))
    });
    for c in &ordered {
        h.update(DOMAIN_MPC);
        h.update(&c.contribution_hash);
    }

    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrib(id: &str, material: &[u8]) -> MPCContribution {
        MPCContribution::new(id.to_string(), hash_contribution(material), Vec::new(), 0)
    }

    #[test]
    fn genesis_hash_is_order_independent() {
        let did = [0x42u8; 32];
        let ab = vec![
            contrib("a", b"c1"),
            contrib("b", b"c2"),
            contrib("c", b"c3"),
        ];
        let ba = vec![
            contrib("c", b"c3"),
            contrib("a", b"c1"),
            contrib("b", b"c2"),
        ];
        assert_eq!(
            compute_genesis_hash(&did, &ab),
            compute_genesis_hash(&did, &ba),
            "contribution order must not affect canonical G"
        );
    }

    #[test]
    fn genesis_hash_depends_on_device_id() {
        let c = vec![contrib("a", b"x"), contrib("b", b"y")];
        assert_ne!(
            compute_genesis_hash(&[1u8; 32], &c),
            compute_genesis_hash(&[2u8; 32], &c),
            "device_id must bind into G"
        );
    }

    #[test]
    fn genesis_hash_depends_on_contributions() {
        let did = [7u8; 32];
        let base = vec![contrib("a", b"x"), contrib("b", b"y")];
        let changed = vec![contrib("a", b"x"), contrib("b", b"z")];
        assert_ne!(
            compute_genesis_hash(&did, &base),
            compute_genesis_hash(&did, &changed),
            "changing any contribution must change G"
        );
    }

    #[test]
    fn genesis_hash_excludes_contributor_id() {
        // Same contribution hashes, different contributor ids ⇒ identical G:
        // contributor_id is a sort tie-breaker only, never folded in.
        let did = [9u8; 32];
        let h1 = hash_contribution(b"m1");
        let h2 = hash_contribution(b"m2");
        let a = vec![
            MPCContribution::new("alpha".into(), h1, Vec::new(), 0),
            MPCContribution::new("bravo".into(), h2, Vec::new(), 0),
        ];
        let b = vec![
            MPCContribution::new("zulu".into(), h1, Vec::new(), 9),
            MPCContribution::new("yankee".into(), h2, Vec::new(), 9),
        ];
        assert_eq!(
            compute_genesis_hash(&did, &a),
            compute_genesis_hash(&did, &b),
            "contributor_id must not affect G"
        );
    }

    #[test]
    fn hash_contribution_is_deterministic_and_domain_separated() {
        let m = b"some-contribution-material";
        assert_eq!(hash_contribution(m), hash_contribution(m));
        // Domain-separated: not equal to a raw BLAKE3 of the same bytes.
        assert_ne!(hash_contribution(m), *blake3::hash(m).as_bytes());
    }
}
