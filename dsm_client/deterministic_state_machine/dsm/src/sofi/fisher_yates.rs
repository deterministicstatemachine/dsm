// SPDX-License-Identifier: Apache-2.0

//! Root-seeded Fisher-Yates ordering of the COMMITTED storage set — Part II §7.
//!
//! The first member of the ordering is the leader of a cell: the member whose
//! first object naming the key is the winner there, the one place a race at a
//! key ends. The writer and Core compute it from a seed and the committed set
//! `S`; a storage node never does. Availability, the caller's identity and
//! node ids never enter a seed, and an offline member stays in `S`, so the
//! leader of a cell never depends on who is online. The input to `permute` is
//! `S`, not a caller's view of who is reachable — a caller that passed what it
//! could reach would compute a different function (`leader.rs`,
//! `a_reachable_subset_can_name_another_leader`). The ordering is frozen by
//! vectors (`dsm/tests/sofi_v8_independent.rs`); its safety role is stated in
//! `tla/DSM_SofiSuccessorCells.tla` (`LeaderFromCommittedSet`).
//!
//! ## Normative algorithm
//!
//! 1. `S` is canonicalized by sorting member ids ascending (raw bytes); a
//!    duplicate member id is refused.
//! 2. `s = H(DSM/sofi/storage-seed/v4 ‖ v ‖ R_n)` (see `derive::storage_seed`).
//! 3. For `i` from `n − 1` down to `1`: draw `j` uniformly from `0..=i` and swap
//!    positions `i` and `j`.
//! 4. A draw for bound `range = i + 1` reads words
//!    `w = u64_be(first 8 bytes of H(DSM/sofi/fy-prf/v1 ‖ s ‖ u32be(i) ‖ u32be(ctr)))`
//!    for `ctr = 0, 1, …` and accepts the first `w ≥ (2^64 mod range)`,
//!    returning `w mod range`. Rejection sampling makes the draw unbiased.
//! 5. `ctr` is 32-bit. Exhausting it is a defined error, never a wrap.
//! 6. The first member is `π[0]`.

use crate::common::domain_tags::TAG_DSM_SOFI_FY_PRF;
use crate::crypto::blake3::dsm_domain_hasher;

/// Why an ordering could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FisherYatesError {
    /// The view is empty.
    EmptyView,
    /// The view names one member twice.
    DuplicateMember,
    /// The view is larger than a 32-bit index can address.
    ViewTooLarge,
    /// Every 32-bit counter value was rejected for one draw.
    PrfCounterExhausted { index: u32 },
}

fn prf_word(seed: &[u8; 32], index: u32, ctr: u32) -> u64 {
    let mut h = dsm_domain_hasher(TAG_DSM_SOFI_FY_PRF);
    h.update(seed);
    h.update(&index.to_be_bytes());
    h.update(&ctr.to_be_bytes());
    let out = h.finalize();
    let mut w = [0u8; 8];
    w.copy_from_slice(&out.as_bytes()[..8]);
    u64::from_be_bytes(w)
}

fn uniform_draw(seed: &[u8; 32], index: u32, range: u64) -> Result<u64, FisherYatesError> {
    // 2^64 mod range, computed without a 128-bit intermediate.
    let threshold = u64::MAX.wrapping_sub(range).wrapping_add(1) % range;
    let mut ctr: u32 = 0;
    loop {
        let w = prf_word(seed, index, ctr);
        if w >= threshold {
            return Ok(w % range);
        }
        ctr = ctr
            .checked_add(1)
            .ok_or(FisherYatesError::PrfCounterExhausted { index })?;
    }
}

/// The canonical Fisher-Yates permutation of the committed set `view` under
/// `seed`.
pub fn permute(seed: &[u8; 32], view: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, FisherYatesError> {
    if view.is_empty() {
        return Err(FisherYatesError::EmptyView);
    }
    if u32::try_from(view.len()).is_err() {
        return Err(FisherYatesError::ViewTooLarge);
    }
    let mut perm: Vec<Vec<u8>> = view.to_vec();
    perm.sort();
    if perm.windows(2).any(|w| w[0] == w[1]) {
        return Err(FisherYatesError::DuplicateMember);
    }
    let n = perm.len();
    for i in (1..n).rev() {
        let j = uniform_draw(seed, i as u32, (i as u64) + 1)? as usize;
        perm.swap(i, j);
    }
    Ok(perm)
}

/// `L = π(S)[0]` — the leader of the cell, where the writer writes first and
/// where Core reads the winner.
pub fn first_member(seed: &[u8; 32], view: &[Vec<u8>]) -> Result<Vec<u8>, FisherYatesError> {
    Ok(permute(seed, view)?.swap_remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u8) -> Vec<Vec<u8>> {
        (0..n).map(|k| vec![k; 4]).collect()
    }

    #[test]
    fn permutation_is_a_permutation_and_input_order_independent() {
        let seed = [9u8; 32];
        let a = permute(&seed, &ids(5)).expect("permute");
        let mut reversed = ids(5);
        reversed.reverse();
        let b = permute(&seed, &reversed).expect("permute");
        assert_eq!(a, b, "the view is canonicalized before shuffling");
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(sorted, ids(5));
    }

    #[test]
    fn empty_and_duplicate_views_are_refused() {
        let seed = [1u8; 32];
        assert_eq!(permute(&seed, &[]), Err(FisherYatesError::EmptyView));
        let dup = vec![vec![1u8], vec![1u8]];
        assert_eq!(permute(&seed, &dup), Err(FisherYatesError::DuplicateMember));
    }

    #[test]
    fn different_seeds_can_choose_different_first_members() {
        let view = ids(5);
        let firsts: std::collections::BTreeSet<Vec<u8>> = (0u8..32)
            .map(|s| first_member(&[s; 32], &view).expect("first"))
            .collect();
        assert!(firsts.len() > 1, "the seed must influence the ordering");
    }
}
