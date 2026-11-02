// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contact-set commitment (gate-set anchor, R4):
//! `BLAKE3("DSM/recovery-contact-set" || u32 count || for each sorted id:
//! u32 len || id_bytes)`, each id in its canonical Crockford encoding.
//! Deterministic in the sorted set, so the frozen gate set and the activation
//! seal commit to the same bytes for the same contacts.

use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use std::collections::BTreeSet;

const RECOVERY_CONTACT_SET_DOMAIN: TaggedHashDomain<'static> =
    crate::common::domain_tags::TAG_DSM_RECOVERY_CONTACT_SET;

/// The commitment to a set of 32-byte device ids.
pub fn contact_set_commit_from_device_ids(ids: &BTreeSet<[u8; 32]>) -> [u8; 32] {
    let mut strs: Vec<String> = ids
        .iter()
        .map(|id| crate::utils::text_id::encode_base32_crockford(id))
        .collect();
    strs.sort_unstable();
    let mut hasher = dsm_domain_hasher(RECOVERY_CONTACT_SET_DOMAIN);
    hasher.update(&(strs.len() as u32).to_le_bytes());
    for id in &strs {
        let b = id.as_bytes();
        hasher.update(&(b.len() as u32).to_le_bytes());
        hasher.update(b);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The commitment depends on the set alone: the order the ids arrive in
    /// changes nothing, one more member changes everything.
    #[test]
    fn the_commitment_is_the_sets() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        let ab = BTreeSet::from([a, b]);
        let ba = BTreeSet::from([b, a]);
        assert_eq!(
            contact_set_commit_from_device_ids(&ab),
            contact_set_commit_from_device_ids(&ba)
        );
        let abc = BTreeSet::from([a, b, [0xCC; 32]]);
        assert_ne!(
            contact_set_commit_from_device_ids(&ab),
            contact_set_commit_from_device_ids(&abc)
        );
        assert_ne!(
            contact_set_commit_from_device_ids(&BTreeSet::from([a])),
            contact_set_commit_from_device_ids(&BTreeSet::new())
        );
    }
}
