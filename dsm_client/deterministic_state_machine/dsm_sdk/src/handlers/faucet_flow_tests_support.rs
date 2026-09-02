// SPDX-License-Identifier: Apache-2.0

//! Shared test support: a testnet identity funded through a REAL faucet
//! claim over the fake fleet — the canonical way any economic test obtains
//! value with ancestry (a balance written directly onto a head has no
//! economic lineage, which no admission can debit).

use crate::sdk::core_sdk::CoreSDK;

pub(crate) use crate::handlers::faucet_flow_tests::{setup, FleetGuard, NETWORK};

/// A device with an ADMITTED position 1 (+100 ERA via a live faucet claim).
pub(crate) async fn setup_funded(seed: u8) -> (CoreSDK, FleetGuard) {
    let (core, guard) = setup(seed);
    let outcome = crate::sdk::faucet_claim_flow::claim_era_faucet(&core, NETWORK)
        .await
        .expect("funding claim");
    assert_eq!(outcome.economic_position, 1);
    (core, guard)
}
