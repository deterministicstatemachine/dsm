// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Storage Hardening Pack v2.0 (deterministic helpers)
//! Clockless, quorum-based mirroring; unbiased permutation; windowing and caps.
//! These helpers are pure functions used by object_store/bytecommit and indexers.

use blake3::Hasher;
use dsm::crypto::domain::TaggedHashDomain;
use std::env;

// ─────────────────────────────────────────────────────────────────────────────
// Normative parameters (clockless) - per whitepaper Sec. storage-regulation
// These constants define the protocol economics and are reserved for future use
// in ByteCommit verification, capacity signals, and Node Registry operations.
// ─────────────────────────────────────────────────────────────────────────────
#[allow(dead_code)]
pub const MMIRROR: usize = 3; // mirror set size
#[allow(dead_code)]
pub const QUORUM_Q: usize = 2; // acceptance quorum

#[allow(dead_code)]
pub const B_GLOBAL: usize = 1 << 18; // 262,144 StorageRef per window
#[allow(dead_code)]
pub const BEV: usize = 1 << 12; // events per node cycle threshold
#[allow(dead_code)]
pub const BBYTES: usize = 1 << 30; // bytes per node cycle threshold

#[allow(dead_code)]
pub const U_UP: f64 = 0.85; // up-signal utilization threshold
#[allow(dead_code)]
pub const U_DOWN: f64 = 0.35; // down-signal utilization threshold
#[allow(dead_code)]
pub const SIG_WIN_CYCLES: usize = 4; // consecutive cycles for signal
#[allow(dead_code)]
pub const GRACE_WINDOWS: usize = 12; // new-position grace in global windows

#[allow(dead_code)]
pub const SHARE_CAP_PCT: f64 = 0.01; // per-device cap contribution

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
/// SCOPE — per HOLDER, not per fleet. Replication here is epidemic: an object
/// lives on its ASSIGNED replica set (`get_replication_targets` permutes alive
/// nodes and takes `replication_factor`; `mirror_set_w` takes `MMIRROR`), not on
/// every node. The b0x spool is placed differently again — the SDK submit loop
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

/// Storage-node tagged-hash domains. The delimiter belongs to the encoder,
/// never to these constants — a NUL here fails to compile.
pub const DOM_APPLY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/apply");
pub const DOM_BYTECOMMIT: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/bytecommit");
pub const DOM_DRAIN: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/drain");
pub const DOM_IDENTITY_DEVTREE_ROOT: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/identity/devtree/root");
pub const DOM_IDENTITY_TIPS_HEAD: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/identity/tips/head");
pub const DOM_IDENTITY_TIPS_LEAF: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/identity/tips/leaf");
pub const DOM_MIRROR: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/mirror");
pub const DOM_NODE_ID: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/node-id");
pub const DOM_OBJ_BYTECOMMIT: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/obj-bytecommit");
pub const DOM_OBJ_BYTES: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/obj-bytes");
pub const DOM_OBJECT: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/object");
pub const DOM_ORDER: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/order");
pub const DOM_PAY_STORAGE: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/pay/storage");
pub const DOM_PERM: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/perm");
pub const DOM_PLACE: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/place");
pub const DOM_POLICY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/policy");
pub const DOM_POLICY_ANCHOR: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/policy/anchor");
pub const DOM_POSITIONS_SALT: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/positions/salt");
pub const DOM_RECOVERY_CAPSULE: TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/recovery/capsule");
pub const DOM_REGISTRY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/registry");
pub const DOM_SIGNAL_DOWN: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/signal/down");
pub const DOM_SIGNAL_UP: TaggedHashDomain<'static> = dsm::tagged_domain!(b"DSM/signal/up");
pub const DOM_WIN_SEED: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/win-seed");

/// Enforce production-only safety in release builds.
/// Rejects dev/test toggles and dev config paths when compiled without debug assertions.
pub fn enforce_release_safety(config_path: &str) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Ok(());
    }

    // Reject dev/test flags in release builds.
    let forbidden_envs = [
        "DSM_DEV_MODE",
        "DSM_DEV_ENABLE_DEBUG_ENDPOINTS",
        "DSM_DEV_ENABLE_HOT_RELOAD",
        "DSM_DEV_SKIP_AUTH",
        "DSM_DEV_NODE_PORTS",
        "DSM_TEST_MODE",
        "DSM_TEST_MODE_ENV",
        "DSM_DEV_GENESIS",
        "DSM_DEV_VAULT",
        "DSM_DEV_ALLOW_INSECURE",
        "DSM_DISABLE_REPLAY_GUARD",
    ];

    for key in forbidden_envs.iter() {
        if let Ok(val) = env::var(key) {
            let v = val.trim().to_lowercase();
            let enabled = !v.is_empty() && v != "0" && v != "false" && v != "no";
            if enabled {
                return Err(format!(
                    "release build refused: env {} is set (value={})",
                    key, val
                ));
            }
        }
    }

    // Guard against accidentally running dev configs in release mode.
    let path_lc = config_path.to_lowercase();
    if path_lc.contains("dev") || path_lc.contains("local") || path_lc.contains("test") {
        return Err(format!(
            "release build refused: config path looks non-production ({})",
            config_path
        ));
    }

    Ok(())
}

/// Deterministic, unbiased Fisher–Yates permutation using a BLAKE3 stream and rejection sampling.
pub fn permute_unbiased<T: Clone>(seed: [u8; 32], items: &[T]) -> Vec<T> {
    let mut a: Vec<T> = items.to_vec();
    let mut i: isize = a.len() as isize - 1;
    if i <= 0 {
        return a;
    }

    // PRF stream state
    let mut ctr: u64 = 0;
    let mut buf: [u8; 32] = blake3_tagged_stream(seed, ctr);
    ctr += 1;
    let mut k: usize = 0;

    while i > 0 {
        let range = (i as u64) + 1;
        let j = sample_u64(&mut buf, &mut k, &mut ctr, seed) % range;
        let j = j as usize;
        a.swap(i as usize, j);
        i -= 1;
    }
    a
}

fn blake3_tagged_stream(seed: [u8; 32], ctr: u64) -> [u8; 32] {
    let mut inbuf = Vec::with_capacity(40);
    inbuf.extend_from_slice(&seed);
    inbuf.extend_from_slice(&ctr.to_le_bytes());
    blake3_tagged(DOM_PERM, &inbuf)
}

fn sample_u64(buf: &mut [u8; 32], k: &mut usize, ctr: &mut u64, seed: [u8; 32]) -> u64 {
    if *k + 8 > buf.len() {
        *buf = blake3_tagged_stream(seed, *ctr);
        *ctr += 1;
        *k = 0;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*k..*k + 8]);
    *k += 8;
    u64::from_le_bytes(bytes)
}

/// Mirror set for a given window seed `sw`: first MMIRROR entries of permute(H("DSM/mirror\0"||nodeID||sw), ActivePositions\exclude)
pub fn mirror_set_w(
    node_id: &[u8],
    window_seed: [u8; 32],
    active_positions: &[Vec<u8>],
    exclude_node: &[u8],
) -> Vec<Vec<u8>> {
    let mut tag_input = Vec::with_capacity(node_id.len() + window_seed.len());
    tag_input.extend_from_slice(node_id);
    tag_input.extend_from_slice(&window_seed);
    let seed = blake3_tagged(DOM_MIRROR, &tag_input);

    // Filter exclude
    let filtered: Vec<Vec<u8>> = active_positions
        .iter()
        .filter(|id| id.as_slice() != exclude_node)
        .cloned()
        .collect();
    let p = permute_unbiased(seed, &filtered);
    p.into_iter().take(MMIRROR).collect()
}

/// Compute global window index: floor(|Fglobal| / B)
pub fn window_index(global_receipts_count: usize) -> usize {
    global_receipts_count / B_GLOBAL
}

/// Apply per-device share cap α=1% for Drefs_w selection.
/// Input receipts must be pre-sorted by (DevID asc, seq asc), we take up to cap per device across the first B_GLOBAL.
#[cfg(test)]
pub fn cap_receipts_for_window(
    receipts: &[(Vec<u8>, u64, [u8; 32])],
) -> Vec<(Vec<u8>, u64, [u8; 32])> {
    use std::collections::HashMap;
    let cap_per_device = ((B_GLOBAL as f64) * SHARE_CAP_PCT).floor() as usize;
    let mut per_dev: HashMap<&[u8], usize> = HashMap::new();
    let mut out: Vec<(Vec<u8>, u64, [u8; 32])> = Vec::with_capacity(B_GLOBAL);
    for (dev, seq, dig) in receipts.iter() {
        let cnt = per_dev.entry(dev.as_slice()).or_insert(0);
        if *cnt >= cap_per_device {
            continue;
        }
        out.push((dev.clone(), *seq, *dig));
        *cnt += 1;
        if out.len() == B_GLOBAL {
            break;
        }
    }
    out
}

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
    /// Three claims, per docs/adr/0001-impact-table.md, asserted in both
    /// directions — an unchanged B1 would be as wrong as a changed ordinary tag:
    ///   - ordinary storage tags are byte-preserving;
    ///   - B1 ("DSM/perm") moves off the double-NUL digest onto the canonical one;
    ///   - B2 ("DSM/mirror") moves likewise.
    #[test]
    fn rule4_storage_domains_are_frozen_across_the_delimiter_cut() {
        const B1_OLD_DOUBLE_NUL: [u8; 32] = [
            214, 71, 179, 114, 59, 108, 160, 214, 43, 124, 227, 252, 69, 195, 198, 228, 72, 67, 45,
            193, 112, 235, 184, 221, 85, 209, 103, 92, 64, 242, 241, 43,
        ];
        const B2_OLD_DOUBLE_NUL: [u8; 32] = [
            59, 50, 18, 175, 194, 250, 56, 224, 128, 98, 56, 134, 175, 75, 34, 192, 169, 247, 251,
            166, 233, 91, 105, 148, 214, 249, 230, 180, 184, 214, 95, 97,
        ];
        const B1_CANONICAL: [u8; 32] = [
            192, 226, 168, 144, 237, 15, 13, 143, 45, 124, 61, 12, 144, 177, 255, 15, 229, 196, 50,
            242, 74, 36, 196, 67, 118, 246, 162, 120, 114, 109, 125, 138,
        ];
        const B2_CANONICAL: [u8; 32] = [
            40, 107, 152, 69, 115, 17, 208, 245, 70, 252, 25, 83, 130, 197, 146, 82, 116, 37, 97,
            58, 157, 227, 63, 141, 94, 6, 160, 237, 20, 53, 69, 13,
        ];
        const ORDINARY_FROZEN: &str = "[20, 244, 53, 207, 97, 62, 162, 23, 252, 252, 203, 51, 44, 183, 186, 142, 162, 162, 224, 30, 124, 189, 220, 5, 243, 4, 243, 107, 192, 55, 147, 32],[6, 81, 32, 82, 42, 52, 187, 62, 126, 60, 132, 18, 100, 88, 67, 28, 77, 18, 56, 232, 156, 121, 89, 141, 88, 201, 247, 245, 10, 93, 196, 83],[88, 45, 78, 57, 126, 145, 72, 87, 220, 118, 211, 211, 4, 178, 35, 25, 10, 93, 112, 209, 136, 231, 21, 30, 67, 227, 157, 82, 1, 131, 57, 250],[171, 171, 162, 255, 106, 186, 31, 224, 132, 150, 162, 161, 170, 200, 122, 71, 35, 138, 5, 123, 51, 86, 72, 63, 164, 145, 233, 27, 0, 35, 144, 41]";

        let b1 = blake3_tagged(DOM_PERM, b"layer-proof-input");
        let b2 = blake3_tagged(DOM_MIRROR, b"layer-proof-input");

        assert_eq!(b1, B1_CANONICAL, "B1 did not land on the canonical digest");
        assert_eq!(b2, B2_CANONICAL, "B2 did not land on the canonical digest");
        assert_ne!(
            b1, B1_OLD_DOUBLE_NUL,
            "B1 still produces the doubled-NUL digest — the cut did not take"
        );
        assert_ne!(
            b2, B2_OLD_DOUBLE_NUL,
            "B2 still produces the doubled-NUL digest"
        );

        let ord: Vec<String> = [DOM_PLACE, DOM_REGISTRY, DOM_OBJECT, DOM_NODE_ID]
            .iter()
            .map(|t| format!("{:?}", blake3_tagged(*t, b"layer-proof-input")))
            .collect();
        assert_eq!(
            ord.join(","),
            ORDINARY_FROZEN,
            "an ordinary storage domain moved; only B1 and B2 may change"
        );
    }

    /// The corrected permutation must still be deterministic — every node has to
    /// derive the same order from the same seed, or replication push targets
    /// diverge across the fleet.
    #[test]
    fn rule4_corrected_permutation_is_deterministic_across_nodes() {
        let items: Vec<u8> = (0u8..16).collect();
        let seed = blake3_tagged(DOM_PLACE, b"object-key");
        let node_a = permute_unbiased(seed, &items);
        let node_b = permute_unbiased(seed, &items);
        assert_eq!(
            node_a, node_b,
            "permutation is not reproducible from a seed"
        );
        assert_ne!(node_a, items, "permutation is the identity");
    }

    use super::*;
    #[test]
    fn test_permutation_determinism() {
        let seed = [42u8; 32];
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let p1 = permute_unbiased(seed, &v);
        let p2 = permute_unbiased(seed, &v);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), v.len());
        // basic sanity: permutation should differ from identity in general
        assert!(p1 != v);
    }

    #[test]
    fn test_mirror_set_size_and_exclude() {
        let node_id = vec![0xAA, 0xBB];
        let sw = [7u8; 32];
        let active: Vec<Vec<u8>> = (0..10).map(|i| vec![i]).collect();
        let set = mirror_set_w(&node_id, sw, &active, &[3]);
        assert_eq!(set.len(), MMIRROR);
        assert!(!set.iter().any(|id| id.as_slice() == [3]));
    }

    #[test]
    fn test_window_and_cap() {
        assert_eq!(window_index(0), 0);
        assert_eq!(window_index(B_GLOBAL - 1), 0);
        assert_eq!(window_index(B_GLOBAL), 1);

        // Build receipts for two devices alternating
        let mut recs: Vec<(Vec<u8>, u64, [u8; 32])> = Vec::new();
        for i in 0..(B_GLOBAL as u64) * 2 {
            let dev = if i % 2 == 0 { vec![0x01] } else { vec![0x02] };
            recs.push((dev, i, [i as u8; 32]));
        }
        // Sort lex (DevID, seq) as required
        recs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let capped = cap_receipts_for_window(&recs);
        // With only two devices and a 1% per-device cap, total selected
        // receipts cannot exceed cap_per_device * num_devices.
        let cap = ((B_GLOBAL as f64) * SHARE_CAP_PCT).floor() as usize;
        let expected_total = std::cmp::min(B_GLOBAL, cap * 2);
        let dev1 = capped
            .iter()
            .filter(|(d, _, _)| d.as_slice() == [0x01])
            .count();
        let dev2 = capped
            .iter()
            .filter(|(d, _, _)| d.as_slice() == [0x02])
            .count();
        assert!(dev2 <= cap);
        assert_eq!(dev1 + dev2, expected_total);
    }

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
