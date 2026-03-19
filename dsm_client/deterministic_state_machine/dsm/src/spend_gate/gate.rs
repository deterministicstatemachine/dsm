// SPDX-License-Identifier: MIT OR Apache-2.0

//! PaidK spend-gate implementation.
//!
//! Validates that the required token amount (`K`) has been committed before
//! allowing gated operations. Uses `BTreeMap` for deterministic ordering.

use crate::types::error::DsmError;
use std::collections::BTreeMap;

/// Payment evidence for a single storage operator.
///
/// The SDK is responsible for verifying any signatures and canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoragePaymentReceipt {
    /// Operator identifier (32 bytes). This SHOULD be the storage node_id.
    pub operator_id: [u8; 32],
    /// Amount paid in protocol units.
    pub amount: u64,
}

/// Spend-gate parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidKParams {
    pub k: usize,
    pub flat_rate: u64,
}

impl PaidKParams {
    pub const fn new(k: usize, flat_rate: u64) -> Self {
        Self { k, flat_rate }
    }
}

/// Returns true iff PaidK is satisfied.
///
/// Predicate: cardinality of {operator_id | receipt.amount >= flat_rate} is >= k.
pub fn paid_k_satisfied(
    params: PaidKParams,
    receipts: &[StoragePaymentReceipt],
) -> Result<bool, DsmError> {
    if params.k == 0 {
        return Err(DsmError::invalid_parameter("PaidKParams.k must be >= 1"));
    }
    if params.flat_rate == 0 {
        return Err(DsmError::invalid_parameter(
            "PaidKParams.flat_rate must be >= 1",
        ));
    }

    let mut per_operator_best: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for r in receipts {
        let entry = per_operator_best.entry(r.operator_id).or_insert(0);
        if r.amount > *entry {
            *entry = r.amount;
        }
    }

    let mut distinct = 0usize;
    for (_op, best_amount) in per_operator_best {
        if best_amount >= params.flat_rate {
            distinct += 1;
            if distinct >= params.k {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paid_k_counts_distinct_operators_at_threshold() {
        let p = PaidKParams::new(3, 10);

        let r = vec![
            StoragePaymentReceipt {
                operator_id: [1u8; 32],
                amount: 10,
            },
            StoragePaymentReceipt {
                operator_id: [2u8; 32],
                amount: 11,
            },
            StoragePaymentReceipt {
                operator_id: [3u8; 32],
                amount: 9,
            },
            StoragePaymentReceipt {
                operator_id: [3u8; 32],
                amount: 10,
            },
        ];

        assert!(paid_k_satisfied(p, &r).unwrap());
    }

    #[test]
    fn paid_k_fails_when_not_enough_distinct() {
        let p = PaidKParams::new(3, 10);

        let r = vec![
            StoragePaymentReceipt {
                operator_id: [1u8; 32],
                amount: 999,
            },
            StoragePaymentReceipt {
                operator_id: [1u8; 32],
                amount: 10,
            },
            StoragePaymentReceipt {
                operator_id: [2u8; 32],
                amount: 10,
            },
        ];

        assert!(!paid_k_satisfied(p, &r).unwrap());
    }
}
