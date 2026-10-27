// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi Amendment S11, MR-SOFI-0337: at the reserve's exhaustion a faucet claim
//! is refused before anything is signed or written.
//!
//! A real reserve reaches exhaustion only after every unit of ERA's committed
//! genesis supply has been released, so no run reaches that state through the
//! claim flow. Core's `faucet_claim_admissible` decides the refusal and its
//! own tests drive a reserve to zero; what this checks is that the claim flow
//! asks it at the reserve head before it signs or freezes a release, reading
//! `claim_era_faucet`'s calls in source order.

mod source_calls;

use source_calls::{calls_in_order, production_fn, sdk_source};

/// MUTATION CONTROL: deleting the `faucet_claim_admissible` call from
/// `claim_era_faucet`, or moving it after the release is signed, turns this
/// red.
#[test]
fn a_faucet_claim_asks_whether_the_reserve_is_exhausted_before_it_signs_or_freezes() {
    let flow = sdk_source("sdk/faucet_claim_flow.rs");
    let calls = calls_in_order(&production_fn(&flow, "claim_era_faucet"));
    let first = |name: &str| calls.iter().position(|c| c == name);
    let Some(asked) = first("faucet_claim_admissible") else {
        panic!("claim_era_faucet never asks whether the reserve is exhausted: {calls:?}");
    };
    for written in ["sign_release", "freeze_release"] {
        let Some(at) = first(written) else {
            panic!("claim_era_faucet calls {written}: {calls:?}");
        };
        assert!(
            asked < at,
            "claim_era_faucet calls {written} before it asks whether the reserve is \
             exhausted: {calls:?}"
        );
    }
}
