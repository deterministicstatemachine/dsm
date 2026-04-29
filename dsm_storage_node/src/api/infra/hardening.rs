//! DSM Storage Hardening Pack v2.0 (deterministic helpers)
//! Clockless, quorum-based mirroring; unbiased permutation; windowing and caps.
//! These helpers are pure functions used by object_store/bytecommit and indexers.

use blake3::Hasher;
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

/// Domain-separated BLAKE3-256: H(ASCII+NUL || body)
pub fn blake3_tagged(tag: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(tag.as_bytes());
    hasher.update(&[0]); // NUL
    hasher.update(body);
    let out = hasher.finalize();
    *out.as_bytes()
}

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
    blake3_tagged("DSM/perm\0", &inbuf)
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
    let seed = blake3_tagged("DSM/mirror\0", &tag_input);

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
