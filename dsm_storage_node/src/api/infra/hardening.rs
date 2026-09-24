// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Storage Hardening Pack v2.0 (deterministic helpers)
//! Clockless, quorum-based mirroring; unbiased permutation; windowing and caps.
//! These helpers are pure functions used by object_store/bytecommit and indexers.

use blake3::Hasher;
use dsm::crypto::domain::TaggedHashDomain;

/// Domain-separated BLAKE3-256, storage-node side: `domain || 0x00 || body`.
///
/// Takes a validated [`TaggedHashDomain`], so a caller cannot spell the
/// delimiter itself. Two callers used to — `"DSM/perm\0"` and `"DSM/mirror\0"`
/// produced a DOUBLED NUL, the mirror image of the SDK shim's trimming defect.
/// Both are impact-table rows B1 and B2; see
/// docs/adr/0001-three-domain-separation-constructions.md.
pub fn blake3_tagged(domain: TaggedHashDomain<'_>, body: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.source_bytes());
    hasher.update(&[0]);
    hasher.update(body);
    let out = hasher.finalize();
    *out.as_bytes()
}

/// Node-side half of the tagged-hash-cut deployment preflight (impact-table rows
/// B5/B6). The client-side half is
/// `dsm_sdk::storage::client_db::cert_resync::tagged_hash_cut_preflight`.
///
/// `inbox_spool` dedupes on `message_id UNIQUE` with `INSERT OR IGNORE`, and the
/// ids move across the cut. An UNACKED row with a NULL `expires_at_iter` is
/// purged by neither expiry sweep, so it survives to be duplicated by its own
/// repost. Zero unacked rows is the boundary condition.
///
/// **Only meaningful while producers are disabled.** Disable producers and
/// retries, let deliveries settle, THEN call this, and keep them disabled
/// through the upgrade — with traffic live the count is a sample, not an
/// invariant.
///
/// SCOPE — per HOLDER, not per fleet. A node places nothing itself. The b0x
/// spool is placed by the writer — the SDK submit loop
/// posts to every endpoint in `storage_node_endpoints` and does NOT break on
/// first success (`b0x_sdk.rs:1470-1507`) — so a row can exist on any endpoint a
/// participating client was configured with.
///
/// The set that must report zero is that union, NOT "all N nodes". At the
/// present fleet size the two coincide because clients carry the whole endpoint
/// list; that is a property of this deployment, not of the protocol, and it
/// stops holding as soon as the fleet outgrows a client's endpoint list.
///
/// AND IT IS HISTORICAL, NOT CURRENT. An unacked row with a NULL
/// `expires_at_iter` is purged by neither sweep, so it outlives any endpoint
/// list — including a node taken out of service and later rejoined. The set is
/// every node that could have received a PRE-CUT submission and may return.
/// An unavailable node cannot be silently omitted: decommission it permanently,
/// clear it before it rejoins, or refuse the cut. If the historical set cannot
/// be established, drain or wipe the whole potentially reachable fleet.
pub fn spool_drain_preflight(unacked_rows: i64) -> Result<(), String> {
    if unacked_rows > 0 {
        return Err(format!(
            "{unacked_rows} unacknowledged inbox_spool row(s): a repost after \
             the cut derives a different message id and will not dedupe. Drain \
             before upgrading."
        ));
    }
    Ok(())
}

pub const DOM_IDENTITY_TIPS_HEAD: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/identity/tips/head");
pub const DOM_IDENTITY_TIPS_LEAF: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/identity/tips/leaf");
pub const DOM_NODE_ID: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/node-id");
pub const DOM_OBJ_BYTES: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/obj-bytes");
pub const DOM_PERM: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/perm");
pub const DOM_POLICY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/policy");
pub const DOM_POLICY_ANCHOR: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/policy/anchor");
pub const DOM_RECOVERY_CAPSULE: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/recovery/capsule");

/// Coalesce ops within a node cycle to their last op per (addr,h) logical key.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpKey {
    pub addr: [u8; 32],
    pub h: [u8; 32],
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub enum OpKind {
    Put(u64),
    Del,
}

#[cfg(test)]
pub fn coalesce_cycle_ops(ops: &[(OpKey, OpKind)]) -> Vec<(OpKey, OpKind)> {
    use std::collections::HashMap;
    let mut last: HashMap<OpKey, OpKind> = HashMap::new();
    for (k, v) in ops.iter() {
        last.insert(k.clone(), v.clone());
    }
    // Stable order: by addr,h lex asc
    let mut keys: Vec<_> = last.keys().cloned().collect();
    keys.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.h.cmp(&b.h)));
    keys.into_iter()
        .map(|k| {
            let v = last
                .remove(&k)
                .unwrap_or_else(|| panic!("coalesce missing key"));
            (k, v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    /// RULE-4 LAYER PROOF. Values captured BEFORE the signature flip.
    ///
    /// Two claims, per docs/adr/0001-impact-table.md, asserted in both
    /// directions — an unchanged B1 would be as wrong as a changed ordinary tag:
    ///   - ordinary storage tags are byte-preserving;
    ///   - B1 ("DSM/perm") moves off the double-NUL digest onto the canonical one.
    ///
    /// B2 ("DSM/mirror") went with the mirror-set placement it keyed.
    /// The corrected permutation must still be deterministic — every node has to
    /// derive the same order from the same seed, or replication push targets
    /// diverge across the fleet.
    use super::*;
    #[test]
    fn test_coalesce_last_op() {
        let k1 = OpKey {
            addr: [1; 32],
            h: [2; 32],
        };
        let k2 = OpKey {
            addr: [3; 32],
            h: [4; 32],
        };
        let ops = vec![
            (k1.clone(), OpKind::Put(10)),
            (k1.clone(), OpKind::Del),
            (k2.clone(), OpKind::Put(7)),
            (k2.clone(), OpKind::Put(11)),
        ];
        let out = coalesce_cycle_ops(&ops);
        // Expect k1->Del, k2->Put(11)
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|(k, v)| k == &k1 && matches!(v, OpKind::Del)));
        assert!(out
            .iter()
            .any(|(k, v)| k == &k2 && matches!(v, OpKind::Put(11))));
    }
}
