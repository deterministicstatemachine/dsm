// SPDX-License-Identifier: Apache-2.0

//! Successor-cell arithmetic over one attempt key — pure, storage-fact only.
//!
//! One observation per committed member of the fixed five-member set. The
//! caller supplies them in committed-set order; members are distinct by
//! construction of that set, so each position counts once.
//!
//! ```text
//! FinalE(E)  ⟺ #{i : cell_i = E} ≥ 3
//! Dead       ⟺ max_E #{i : cell_i = E} + #Empty + #Unknown < 3      (max is 0 with no values)
//! otherwise  Unresolved
//! ```
//!
//! `Unknown` covers an unread member, a timeout, and any contacted member whose
//! response is malformed or unverifiable. It counts toward `u` exactly like
//! `Empty` — it could be empty or could hold any value — and it is NEVER
//! treated as empty for a finality count. That is what makes a Dead verdict on
//! a partial observation sound: every completion of the unknown cells is also
//! Dead. This module decides storage facts only; whether a final E is valid,
//! canonical or live is not its business.

use super::wire::{STORAGE_FINALITY_COUNT, STORAGE_MEMBER_COUNT};

/// What one committed member's cell at one attempt key was observed to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellObservation {
    /// A well-formed held value.
    Holds([u8; 32]),
    /// An authenticated read of an empty cell.
    Empty,
    /// Unread, unavailable, timed out, or an unverifiable response.
    Unknown,
}

/// The storage-level resolution of one attempt key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellResolution {
    /// Three matching cells hold this value.
    Final([u8; 32]),
    /// No value can reach three under any completion of the observation.
    Dead,
    /// Neither is established yet.
    Unresolved,
}

/// Resolve one attempt key from exactly one observation per committed member.
pub fn resolve(observations: &[CellObservation; STORAGE_MEMBER_COUNT]) -> CellResolution {
    let mut values: Vec<([u8; 32], usize)> = Vec::new();
    let mut open = 0usize;
    for obs in observations {
        match obs {
            CellObservation::Holds(v) => match values.iter_mut().find(|(k, _)| k == v) {
                Some((_, n)) => *n += 1,
                None => values.push((*v, 1)),
            },
            CellObservation::Empty | CellObservation::Unknown => open += 1,
        }
    }
    if let Some((v, _)) = values.iter().find(|(_, n)| *n >= STORAGE_FINALITY_COUNT) {
        return CellResolution::Final(*v);
    }
    let max = values.iter().map(|(_, n)| *n).max().unwrap_or(0);
    if max + open < STORAGE_FINALITY_COUNT {
        CellResolution::Dead
    } else {
        CellResolution::Unresolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CellObservation::{Empty, Holds, Unknown};

    const A: [u8; 32] = [0xA; 32];
    const B: [u8; 32] = [0xB; 32];
    const C: [u8; 32] = [0xC; 32];

    #[test]
    fn three_matching_cells_are_final() {
        assert_eq!(
            resolve(&[Holds(A), Holds(A), Holds(A), Empty, Unknown]),
            CellResolution::Final(A)
        );
    }

    #[test]
    fn two_two_one_is_dead() {
        assert_eq!(
            resolve(&[Holds(A), Holds(A), Holds(B), Holds(B), Holds(C)]),
            CellResolution::Dead
        );
    }

    #[test]
    fn two_two_unknown_is_unresolved_never_dead() {
        assert_eq!(
            resolve(&[Holds(A), Holds(A), Holds(B), Holds(B), Unknown]),
            CellResolution::Unresolved
        );
    }

    #[test]
    fn four_distinct_values_and_one_unknown_is_dead() {
        let d = [0xD; 32];
        assert_eq!(
            resolve(&[Holds(A), Holds(B), Holds(C), Holds(d), Unknown]),
            CellResolution::Dead
        );
    }

    #[test]
    fn all_empty_is_unresolved() {
        assert_eq!(resolve(&[Empty; 5]), CellResolution::Unresolved);
    }

    /// Soundness of Dead under partial observation: every completion of the
    /// Unknown cells into Empty or any value among a small alphabet is also
    /// Dead. Exhaustive over the alphabet `{Empty, A, B, C, D}`.
    #[test]
    fn dead_on_a_partial_read_survives_every_completion() {
        let d = [0xD; 32];
        let alphabet = [Empty, Holds(A), Holds(B), Holds(C), Holds(d)];
        let partial = [Holds(A), Holds(B), Holds(C), Holds(d), Unknown];
        assert_eq!(resolve(&partial), CellResolution::Dead);
        for fill in alphabet {
            let mut full = partial;
            full[4] = fill;
            assert_eq!(resolve(&full), CellResolution::Dead, "completion {fill:?}");
        }
    }
}
