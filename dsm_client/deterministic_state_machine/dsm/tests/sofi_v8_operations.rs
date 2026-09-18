// SPDX-License-Identifier: Apache-2.0

//! SoFi v8 operations: the manual arms that a new variant does NOT force.
//!
//! `get_signature`, `with_cleared_signature` and `with_signature` all end in a
//! wildcard, so a signed variant missing from any of them compiles perfectly
//! and is silently unsigned — or, worse, signs over bytes that still contain a
//! signature. The compiler says nothing. These tests do.

#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

use dsm::sofi::admission::{admissible, NotAdmissible};
use dsm::sofi::wire::{OwnerAuthority, PreEClosureIndex, SettlementBody, SwapHop, ROUTE_MAX_LEGS};
use dsm::types::operations::Operation;

const SIG: [u8; 8] = [0xA1; 8];

fn sofi_operations() -> Vec<Operation> {
    vec![
        Operation::SofiSetup {
            setup_body: vec![0x36, 0x00],
            signature: Vec::new(),
        },
        Operation::SofiVaultCreate {
            genesis_preimage: vec![0x5A, 0x00],
            creation: vec![0x5B, 0x00],
            signature: Vec::new(),
        },
        Operation::SofiFulfill {
            fulfillment_body: vec![0x39, 0x00],
            precommit_id: vec![0x11; 32],
            signature: Vec::new(),
        },
    ]
}

/// Every SoFi operation carries a signature THROUGH all three manual arms.
/// A variant missing from `with_signature` never gets one; a variant missing
/// from `get_signature` has one nobody can read; a variant missing from
/// `with_cleared_signature` signs over its own signature.
#[test]
fn every_sofi_operation_round_trips_a_signature() {
    for unsigned in sofi_operations() {
        let name = unsigned.get_operation_type();
        assert!(
            unsigned.get_signature().is_none(),
            "{name}: an empty signature is not a signature"
        );

        let signed = unsigned.with_signature(SIG.to_vec());
        assert_eq!(
            signed.get_signature(),
            Some(SIG.to_vec()),
            "{name}: with_signature must reach this variant"
        );

        let cleared = signed.with_cleared_signature();
        assert!(
            cleared.get_signature().is_none(),
            "{name}: with_cleared_signature must reach this variant"
        );
        // The signing payload is the operation WITHOUT its signature, so
        // clearing must actually change the bytes.
        assert_ne!(
            signed.to_bytes(),
            cleared.to_bytes(),
            "{name}: the signature must be inside the canonical bytes"
        );
        assert_eq!(
            cleared.to_bytes(),
            unsigned.to_bytes(),
            "{name}: clearing returns exactly the unsigned operation"
        );
    }
}

/// The canonical bytes discriminate: no two SoFi operations, and no SoFi
/// operation and any other, share an encoding.
#[test]
fn sofi_operations_have_distinct_canonical_tags() {
    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    for op in sofi_operations() {
        let bytes = op.to_bytes();
        let tag = bytes.first().copied().expect("a tagged encoding");
        assert!(
            (34..=36).contains(&tag),
            "{}: SoFi operations are tags 34-36, got {tag}",
            op.get_operation_type()
        );
        for (name, other) in &seen {
            assert_ne!(
                &bytes,
                other,
                "{} and {name} share canonical bytes",
                op.get_operation_type()
            );
        }
        seen.push((op.get_operation_type().to_string(), bytes));
    }
    assert_eq!(seen.len(), 3);
}

/// A signed operation with no signature is refused at the authorization gate,
/// so an unsigned SoFi transition cannot advance a chain.
#[test]
fn an_unsigned_sofi_operation_is_refused_authorization() {
    for unsigned in sofi_operations() {
        let name = unsigned.get_operation_type();
        assert!(
            dsm::core::state_machine::transition::enforce_operation_authorization(&unsigned)
                .is_err(),
            "{name}: an unsigned SoFi operation must not be authorized"
        );
        let signed = unsigned.with_signature(SIG.to_vec());
        assert!(
            dsm::core::state_machine::transition::enforce_operation_authorization(&signed).is_ok(),
            "{name}: a signed one must pass"
        );
    }
}

/// The economic classification of each SoFi operation, and the egress gate's
/// own invariant over them.
#[test]
fn sofi_operations_are_classified_and_gated() {
    use dsm::economic::classifier::{classify, EconomicEffect};
    for op in sofi_operations() {
        let name = op.get_operation_type();
        assert_eq!(
            classify(&op),
            EconomicEffect::ClosedWriteSet,
            "{name}: a SoFi operation writes a closed set, never nothing"
        );
        // The frozen invariant: egress exactly when the asset is not NotEgress.
        assert_eq!(
            op.is_value_egress(),
            !matches!(
                op.egress_asset(),
                dsm::types::operations::EgressAsset::NotEgress
            ),
            "{name}: is_value_egress and egress_asset must agree"
        );
    }
    // A setup moves nothing; the other two do.
    let ops = sofi_operations();
    assert!(!ops[0].is_value_egress(), "a setup is not value egress");
    assert!(ops[1].is_value_egress(), "a funded creation is egress");
    assert!(ops[2].is_value_egress(), "a fulfillment is egress");
}

/// Beta executes at most two hops, and never the reserved authority — while
/// both remain canonical objects.
#[test]
fn beta_admission_is_the_cap_not_the_codec() {
    let hop = |vault: u8| SwapHop {
        vault_id: [vault; 32],
        parent_root: [vault ^ 0x0F; 32],
        setup_ref: [vault ^ 0xF0; 32],
        token_in: [0x51; 32],
        amount_in: 100,
        token_out: [0x52; 32],
        amount_out: 90,
    };
    let three = SettlementBody::Swap {
        token_in: [0x51; 32],
        amount_in: 100,
        token_out: [0x52; 32],
        exact_out: 90,
        hops: vec![hop(0xC1), hop(0xC2), hop(0xC3)],
        trader_core: [0xD1; 32],
        dlv_cores: vec![[0xE1; 32], [0xE2; 32], [0xE3; 32]],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert!(three.encode().is_ok(), "three hops are canonical bytes");
    assert_eq!(
        admissible(&three),
        Err(NotAdmissible::TooManyLegs {
            legs: 3,
            max: ROUTE_MAX_LEGS
        })
    );

    let reserved = SettlementBody::Close {
        vault_id: [0xC1; 32],
        parent_root: [0xC2; 32],
        setup_ref: [0xC3; 32],
        owner_authority: OwnerAuthority::DsmSuccessor {
            authority_class: 0x1234,
            authority_addr: [0x5D; 32],
        },
        reserve_a: 10,
        reserve_b: 20,
        trader_core: [0xD1; 32],
        dlv_core: [0xD2; 32],
        closure: PreEClosureIndex::new(Vec::new()).unwrap(),
    };
    assert!(reserved.encode().is_ok(), "the reserved branch encodes");
    assert_eq!(
        admissible(&reserved),
        Err(NotAdmissible::OwnerAuthorityNotActivated)
    );
}
