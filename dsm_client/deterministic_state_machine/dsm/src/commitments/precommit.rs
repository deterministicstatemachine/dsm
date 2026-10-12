// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bilateral precommit: the branch commitment a transition binds,
//!
//! ```text
//! C_pre = H("DSM/precommit/commitment-hash/v2\0" || h_n || payload || e)
//! ```
//!
//! with every field length-prefixed under its own domain. The fork-aware
//! precommit family (several candidates under one committed root, one
//! selected, the others invalidated) is not built: no producer made a fork
//! witness, and the check a receiver ran compared the sender's candidate set
//! only with itself.

use crate::crypto::canonical_lp;
use crate::crypto::domain::TaggedHashDomain;

const DOM_PRECOMMIT_COMMITMENT_HASH: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/precommit/commitment-hash/v2");

/// The branch commitment `C_pre` of `payload` under entropy `e` at parent tip `h_n`.
pub fn branch_commitment_hash(parent_tip: &[u8; 32], payload: &[u8], entropy: &[u8]) -> [u8; 32] {
    canonical_lp::hash_lp3(DOM_PRECOMMIT_COMMITMENT_HASH, parent_tip, payload, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LAYER PROOF for rule 3 (hash_lp*): the domain's bytes are frozen across
    /// the delimiter cut (docs/adr/0001-impact-table.md rows 1-2).
    #[test]
    fn rule3_precommit_domain_is_frozen_across_the_delimiter_cut() {
        let h = canonical_lp::hash_lp1(DOM_PRECOMMIT_COMMITMENT_HASH, b"layer-proof-input");
        assert_eq!(
            format!("{h:?}"),
            "[252, 225, 191, 185, 103, 184, 181, 38, 16, 155, 116, 221, 16, 93, 73, 145, 134, 89, 101, 114, 172, 227, 200, 132, 254, 164, 60, 179, 66, 126, 200, 97]",
            "the precommit domain moved across the delimiter cut"
        );
    }

    /// The branch commitment is the canonical lp3 form under its domain, and
    /// deterministic.
    #[test]
    fn k1_v2_positive_branch_commitment_hash() {
        let h_n: [u8; 32] = [0x11; 32];
        let payload = b"payload-A";
        let entropy = b"entropy-A";
        let got = branch_commitment_hash(&h_n, payload, entropy);
        let expected =
            canonical_lp::hash_lp3(DOM_PRECOMMIT_COMMITMENT_HASH, &h_n, payload, entropy);
        assert_eq!(
            got, expected,
            "v2 branch commitment hash diverged from canonical lp3 form"
        );
        assert_eq!(
            got,
            branch_commitment_hash(&h_n, payload, entropy),
            "v2 commitment hash is not deterministic"
        );
    }
}
