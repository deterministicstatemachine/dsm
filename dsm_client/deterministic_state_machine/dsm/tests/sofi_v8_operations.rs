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
            funding_a_policy_commit: [0x5C; 32],
            funding_b_policy_commit: [0x5D; 32],
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
        // The signature is committed by the canonical bytes — which is why a
        // chain tip binds it — so clearing must actually change them. (What
        // the signature COVERS is a separate rule per operation:
        // `sofi::signature`. Only a vault creation signs these bytes.)
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

/// EACH SOFI OPERATION SIGNS ITS OWN THING, and the other rule is refused.
///
/// A setup signs `m_setup` and a fulfillment signs `m_F` — their own objects'
/// digests, which is what a storage member checks when the object arrives with
/// no operation around it. Only a vault creation, which has no object digest
/// of its own, signs the operation's canonical unsigned bytes.
///
/// The cross-checks are the point: a signature produced under the OTHER rule
/// must not authorize the operation. Otherwise "which bytes are signed" would
/// be unobservable, and the member and the device could disagree forever.
#[test]
fn each_sofi_operation_signs_its_own_rule_and_not_the_other() {
    use dsm::core::state_machine::transition::operation_signing_bytes;
    use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use dsm::sofi::derive;
    use dsm::sofi::signature::{verify_operation, SignatureError};
    use dsm::sofi::wire::{AttemptEntry, SofiSetupBody, TraderFulfillmentBody};

    let (pk, sk) = generate_sphincs_keypair().unwrap();
    let d = |b: u8| [b; 32];

    let setup =
        SofiSetupBody::new(d(0x11), d(0x22), 5, d(0xC1), d(0x66), d(0x67), 0x0001, &pk).unwrap();
    let fulfillment = TraderFulfillmentBody::new(
        d(0x0A),
        vec![d(0x71)],
        vec![AttemptEntry {
            vault_id: d(0xC1),
            attempt: 0,
        }],
        6,
        0x0001,
        &pk,
    )
    .unwrap();

    let unsigned_setup = Operation::SofiSetup {
        setup_body: setup.encode(),
        signature: Vec::new(),
    };
    let unsigned_fulfill = Operation::SofiFulfill {
        fulfillment_body: fulfillment.encode(),
        precommit_id: d(0x0A).to_vec(),
        signature: Vec::new(),
    };
    let unsigned_create = Operation::SofiVaultCreate {
        genesis_preimage: vec![0x5A, 0x00],
        creation: vec![0x5B, 0x00],
        funding_a_policy_commit: [0x5C; 32],
        funding_b_policy_commit: [0x5D; 32],
        signature: Vec::new(),
    };

    // Each operation's OWN rule authorizes it.
    for (unsigned, message, name) in [
        (
            &unsigned_setup,
            derive::setup_signing_digest(&setup).to_vec(),
            "SofiSetup",
        ),
        (
            &unsigned_fulfill,
            derive::fulfillment_signing_digest(&fulfillment).to_vec(),
            "SofiFulfill",
        ),
        (
            &unsigned_create,
            operation_signing_bytes(&unsigned_create),
            "SofiVaultCreate",
        ),
    ] {
        let signed = unsigned.with_signature(sphincs_sign(&sk, &message).unwrap());
        assert_eq!(
            verify_operation(&signed, &pk),
            Ok(()),
            "{name}: its own rule must authorize it"
        );
    }

    // And the other rule does not. A setup or a fulfillment signed over the
    // operation's bytes is exactly the generic signature this protocol does
    // NOT ask for, and it is refused.
    for (unsigned, name) in [
        (&unsigned_setup, "SofiSetup"),
        (&unsigned_fulfill, "SofiFulfill"),
    ] {
        let over_the_operation =
            unsigned.with_signature(sphincs_sign(&sk, &operation_signing_bytes(unsigned)).unwrap());
        assert_eq!(
            verify_operation(&over_the_operation, &pk),
            Err(SignatureError::DoesNotVerify { what: name }),
            "{name}: a generic operation signature must not authorize it"
        );
    }

    // Conversely, a creation signed over a digest of its own bytes is refused:
    // there is no second creation rule to fall back on.
    let create_over_a_digest = unsigned_create.with_signature(
        sphincs_sign(
            &sk,
            dsm::crypto::blake3::hash_blake3(&operation_signing_bytes(&unsigned_create)).as_bytes(),
        )
        .unwrap(),
    );
    assert_eq!(
        verify_operation(&create_over_a_digest, &pk),
        Err(SignatureError::DoesNotVerify {
            what: "SofiVaultCreate"
        })
    );
}

/// EVERY SOFI OPERATION SURVIVES `to_bytes` → `from_bytes`, signed and
/// unsigned.
///
/// This is the gate whose ABSENCE let the codec ship one-way. The file's other
/// round-trip test is named `every_sofi_operation_round_trips_a_signature`,
/// but it only exercises `with_signature` / `with_cleared_signature` — it
/// never touches `from_bytes`, so all three tags encoded fine and decoded to
/// "unknown op tag". Tag 31 above records the identical defect being found
/// the hard way, when successor-evidence replay crossed it.
///
/// `economic/successor_evidence.rs` decodes the exact frozen operation bytes
/// through `from_bytes` during foreign and replay verification, so a missing
/// arm means a committed operation no verifier can reconstruct.
#[test]
fn every_sofi_operation_round_trips_through_the_byte_codec() {
    for unsigned in sofi_operations() {
        let name = unsigned.get_operation_type();
        for op in [unsigned.clone(), unsigned.with_signature(SIG.to_vec())] {
            let bytes = op.to_bytes();
            let decoded = Operation::from_bytes(&bytes)
                .unwrap_or_else(|e| panic!("{name}: encodable but not decodable: {e}"));
            assert_eq!(decoded, op, "{name}: the decode is not the operation");
            // And it is canonical: re-encoding reproduces the same bytes.
            assert_eq!(decoded.to_bytes(), bytes, "{name}: re-encode drifted");
        }
    }
}

/// The creation's TWO funding commits both survive the round trip, in order.
///
/// They are the fields most likely to be dropped or transposed by a decoder
/// written from memory: the operation would still decode, and it would name
/// different assets than the signature covered.
#[test]
fn a_creation_round_trips_both_funding_commits_in_order() {
    let op = Operation::SofiVaultCreate {
        genesis_preimage: vec![0x5A, 0x00],
        creation: vec![0x5B, 0x00],
        funding_a_policy_commit: [0xA1; 32],
        funding_b_policy_commit: [0xB2; 32],
        signature: SIG.to_vec(),
    };
    let decoded = Operation::from_bytes(&op.to_bytes()).expect("decodes");
    match decoded {
        Operation::SofiVaultCreate {
            funding_a_policy_commit,
            funding_b_policy_commit,
            ..
        } => {
            assert_eq!(funding_a_policy_commit, [0xA1; 32]);
            assert_eq!(funding_b_policy_commit, [0xB2; 32], "not transposed");
        }
        other => panic!("a creation, got {other:?}"),
    }

    // A truncated field is refused, not zero-padded into a different asset.
    let mut short = op.to_bytes();
    short.truncate(short.len() - 1);
    assert!(Operation::from_bytes(&short).is_err());
}
