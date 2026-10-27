// SPDX-License-Identifier: MIT OR Apache-2.0
//! SoFi §46, MR-SOFI-0281: one function prepares every transition, and no SoFi
//! producer calls a lower-level advance.
//!
//! The one preparing function is `CoreSDK::admitted_advance`: the guarded,
//! fence-coupled advance with its admission, which `admitted_self_loop_
//! operation` runs for a self-loop operation. A realized head's own
//! transitions (`advance`, `establish_relationship`, the offline boundary and
//! account, the resolved position and the pending admission) and the state
//! machine's installer are the lower level it is built from. This reads every
//! SoFi producer's production functions and fails on a call to any of them,
//! and on a SoFi producer set that no longer reaches the preparing function.

mod source_calls;

use source_calls::{calls_in_order, production_fns, sdk_source};

/// Every file that produces a SoFi, escrow, computed or outcome transition.
const PRODUCERS: &[&str] = &[
    "sdk/sofi_advance.rs",
    "sdk/sofi_flow.rs",
    "sdk/sofi_exercise.rs",
    "sdk/sofi_publish.rs",
    "sdk/sofi_register.rs",
    "sdk/sofi_relay.rs",
    "sdk/sofi_sdk.rs",
    "sdk/escrow_flow.rs",
    "sdk/computed_flow.rs",
    "sdk/outcome_programs.rs",
    "sdk/apply_outcome.rs",
    "sdk/seed_vault.rs",
    "handlers/sofi_routes.rs",
    "handlers/escrow_routes.rs",
];

/// The lower-level advances, all methods: what `admitted_advance` is built
/// from.
const LOWER_LEVEL: &[&str] = &[
    ".advance",
    ".establish_relationship",
    ".cross_offline_boundary",
    ".open_offline_account",
    ".with_resolved_position",
    ".with_pending_economic_admission",
    ".set_device_head",
    ".execute_on_relationship_guarded",
];

/// The preparing function, a method of `CoreSDK`, and the self-loop path that
/// runs it.
const PREPARING: &[&str] = &[".admitted_advance", "admitted_self_loop_operation"];

/// MUTATION CONTROL: a SoFi producer that advances its head directly — say
/// `core.device_head()?.advance(..)` in `sofi_advance.rs` in place of
/// `admitted_advance` — turns this red, naming the file and function.
#[test]
fn every_sofi_producer_advances_only_through_the_one_preparing_function() {
    let mut reaches_preparing = Vec::new();
    for rel in PRODUCERS {
        for (name, block) in production_fns(&sdk_source(rel)) {
            let calls = calls_in_order(&block);
            for call in &calls {
                assert!(
                    !LOWER_LEVEL.contains(&call.as_str()),
                    "{rel}: {name} calls the lower-level advance {call}; SoFi transitions are \
                     prepared only by admitted_advance"
                );
            }
            if calls.iter().any(|c| PREPARING.contains(&c.as_str())) {
                reaches_preparing.push(format!("{rel}: {name}"));
            }
        }
    }
    assert!(
        !reaches_preparing.is_empty(),
        "no SoFi producer reaches admitted_advance: the producer list no longer names the \
         files that advance"
    );
}
