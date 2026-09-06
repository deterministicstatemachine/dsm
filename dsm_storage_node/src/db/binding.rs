// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic conditional-binding DECISION, shared by both backends.
//!
//! `CompareExchangeMany` (SoFi Rev 15 §15.5, Req 15.6) is atomic within one
//! member and inspects only generic storage fields. The decision of whether
//! a replacement may be applied is pure and lives here, once, so Postgres and
//! SQLite cannot drift into two rules, and so it is testable without a
//! database. The backends supply I/O around it: lock, read what is held,
//! decide, write all-or-none, commit durably.

use dsm::storage::binding_record::{record_set_digest, Round, SetCell};
use std::collections::BTreeMap;

/// One cell as this member holds it. `record_bytes` are the canonical bytes
/// exactly as received; this member never re-encodes what it stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBinding {
    pub key: [u8; 32],
    pub record_bytes: Vec<u8>,
    pub record_digest: [u8; 32],
    pub round: Round,
}

/// What one `CompareExchangeMany` did at this member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// Every named key now holds the replacement (or already held exactly
    /// it). `resulting_digest` is the digest of the record set over the keys
    /// AFTER the call — the caller's next `expected_digest`.
    Applied { resulting_digest: [u8; 32] },
    /// Nothing changed. Either the prior record set was not the one the
    /// caller expected, or the replacement's round does not supersede every
    /// round already held. `current_digest` is the set digest the caller
    /// must read against.
    ExpectationMismatch { current_digest: [u8; 32] },
}

/// The digest of the record set this member holds over `keys`, absences
/// included as absences.
pub fn set_digest_over(keys: &[[u8; 32]], held: &BTreeMap<[u8; 32], StoredBinding>) -> [u8; 32] {
    let cells: Vec<SetCell> = keys
        .iter()
        .map(|k| SetCell {
            key: *k,
            record_digest: held.get(k).map(|b| b.record_digest),
        })
        .collect();
    record_set_digest(&cells)
}

/// The replacement a caller proposes, already decoded and validated by
/// `dsm::storage::binding_record::decode_compare_exchange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement<'a> {
    pub bytes: &'a [u8],
    pub digest: [u8; 32],
    pub round: Round,
}

/// Decide whether `replacement` may be applied over `keys` given what the
/// member holds. Checks, in order, each fail-closed:
///
/// 1. byte-identical replay on EVERY key → `Applied` with the current
///    digest — idempotent, like a re-ack, so a crashed proposer converges by
///    retrying the same bytes;
/// 2. the exact prior set digest must equal `expected_digest`;
/// 3. the replacement's round must be STRICTLY greater than every round
///    already held. A matching digest proves the caller saw the state; a
///    round that does not supersede it must still not overwrite it, and an
///    equal round with different bytes is a proposer reusing a round for a
///    second value, which is refused.
pub fn decide_compare_exchange(
    keys: &[[u8; 32]],
    held: &BTreeMap<[u8; 32], StoredBinding>,
    expected_digest: &[u8; 32],
    replacement: &Replacement<'_>,
) -> CasOutcome {
    let current_digest = set_digest_over(keys, held);
    let identical_everywhere = keys.iter().all(|k| {
        held.get(k)
            .map(|b| b.record_bytes.as_slice() == replacement.bytes)
            .unwrap_or(false)
    });
    if identical_everywhere {
        return CasOutcome::Applied {
            resulting_digest: current_digest,
        };
    }
    if &current_digest != expected_digest {
        return CasOutcome::ExpectationMismatch { current_digest };
    }
    if held.values().any(|b| replacement.round <= b.round) {
        return CasOutcome::ExpectationMismatch { current_digest };
    }
    let after: BTreeMap<[u8; 32], StoredBinding> = keys
        .iter()
        .map(|k| {
            (
                *k,
                StoredBinding {
                    key: *k,
                    record_bytes: replacement.bytes.to_vec(),
                    record_digest: replacement.digest,
                    round: replacement.round,
                },
            )
        })
        .collect();
    CasOutcome::Applied {
        resulting_digest: set_digest_over(keys, &after),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // unwrap/expect acceptable in deterministic tests
    use super::*;
    use dsm::storage::binding_record::{empty_set_digest, record_digest_of_bytes};

    fn r(counter: u64, proposer: u8, bytes: &[u8]) -> ([u8; 32], Round) {
        (
            record_digest_of_bytes(bytes),
            Round {
                counter,
                proposer_id: [proposer; 32],
            },
        )
    }

    #[test]
    fn a_first_writer_exchanges_from_the_empty_digest_and_a_stale_expectation_is_refused() {
        let keys = [[1u8; 32], [2u8; 32]];
        let held = BTreeMap::new();
        let (d, round) = r(1, 1, b"A");
        let rep = Replacement {
            bytes: b"A",
            digest: d,
            round,
        };
        let applied = decide_compare_exchange(&keys, &held, &empty_set_digest(&keys), &rep);
        let CasOutcome::Applied { resulting_digest } = applied else {
            panic!("first write from the empty digest applies")
        };
        // Someone still expecting the empty set after that is refused with
        // the digest they must read against.
        let mut held2 = BTreeMap::new();
        for k in keys {
            held2.insert(
                k,
                StoredBinding {
                    key: k,
                    record_bytes: b"A".to_vec(),
                    record_digest: d,
                    round,
                },
            );
        }
        let (d2, round2) = r(2, 2, b"B");
        let rep2 = Replacement {
            bytes: b"B",
            digest: d2,
            round: round2,
        };
        assert_eq!(
            decide_compare_exchange(&keys, &held2, &empty_set_digest(&keys), &rep2),
            CasOutcome::ExpectationMismatch {
                current_digest: resulting_digest
            }
        );
        // With the right expectation AND a higher round, B supersedes A.
        assert!(matches!(
            decide_compare_exchange(&keys, &held2, &resulting_digest, &rep2),
            CasOutcome::Applied { .. }
        ));
    }

    #[test]
    fn a_round_that_does_not_supersede_is_refused_even_with_the_right_expectation() {
        let keys = [[1u8; 32]];
        let (d, round) = r(5, 9, b"A");
        let mut held = BTreeMap::new();
        held.insert(
            keys[0],
            StoredBinding {
                key: keys[0],
                record_bytes: b"A".to_vec(),
                record_digest: d,
                round,
            },
        );
        let current = set_digest_over(&keys, &held);
        // Lower counter: refused.
        let (d2, r2) = r(4, 0xFF, b"B");
        assert!(matches!(
            decide_compare_exchange(
                &keys,
                &held,
                &current,
                &Replacement {
                    bytes: b"B",
                    digest: d2,
                    round: r2
                }
            ),
            CasOutcome::ExpectationMismatch { .. }
        ));
        // Same counter, same proposer, DIFFERENT bytes: a proposer reusing a
        // round for a second value — refused.
        let (d3, r3) = r(5, 9, b"C");
        assert!(matches!(
            decide_compare_exchange(
                &keys,
                &held,
                &current,
                &Replacement {
                    bytes: b"C",
                    digest: d3,
                    round: r3
                }
            ),
            CasOutcome::ExpectationMismatch { .. }
        ));
        // Same counter, HIGHER proposer id: lexicographically greater — applies.
        let (d4, r4) = r(5, 10, b"D");
        assert!(matches!(
            decide_compare_exchange(
                &keys,
                &held,
                &current,
                &Replacement {
                    bytes: b"D",
                    digest: d4,
                    round: r4
                }
            ),
            CasOutcome::Applied { .. }
        ));
    }

    #[test]
    fn byte_identical_replay_re_acks_without_needing_the_expectation() {
        let keys = [[1u8; 32], [2u8; 32]];
        let (d, round) = r(1, 1, b"A");
        let mut held = BTreeMap::new();
        for k in keys {
            held.insert(
                k,
                StoredBinding {
                    key: k,
                    record_bytes: b"A".to_vec(),
                    record_digest: d,
                    round,
                },
            );
        }
        let current = set_digest_over(&keys, &held);
        let rep = Replacement {
            bytes: b"A",
            digest: d,
            round,
        };
        // A stale (wrong) expectation does not matter for an identical replay:
        // the member already holds exactly these bytes everywhere.
        assert_eq!(
            decide_compare_exchange(&keys, &held, &[0xEE; 32], &rep),
            CasOutcome::Applied {
                resulting_digest: current
            }
        );
        // But identical on only SOME keys is not a replay; it is a
        // partial state, and the expectation must match.
        held.remove(&keys[1]);
        assert!(matches!(
            decide_compare_exchange(&keys, &held, &[0xEE; 32], &rep),
            CasOutcome::ExpectationMismatch { .. }
        ));
    }
}
