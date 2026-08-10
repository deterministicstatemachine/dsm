// SPDX-License-Identifier: MIT OR Apache-2.0
//! Acceptance suite for the `DlvSettle` / `DlvOwnerApply` signing repair.
//!
//! Both are value-moving egress (`EgressAsset::Asset`, operations.rs:885-901) and both
//! sit in the must-sign set of what transition.rs calls "the canonical rule", whose only
//! documented exemptions are `Genesis`, `Noop`, `Receive`. Before this repair neither
//! could be signed at all: `with_cleared_signature` omitted them (so the documented
//! preimage `with_cleared_signature().to_bytes()` contained the signature it was meant
//! to produce), `with_signature` was a silent no-op, `get_signature` returned `None`,
//! and `sign_operation_sphincs` returned `Ok` with the operation unsigned.
//!
//! Every property below is asserted for BOTH variants. The signer is the AK of the
//! actor whose SELF-LOOP transition is being advanced — verified against the head's own
//! `public_key`, never against a key carried inside the operation, because a key
//! travelling inside the material it authorizes proves nothing.

#![allow(clippy::disallowed_methods)]

use dsm::core::bilateral_transaction_manager::{compute_smt_key, initial_chain_tip_from_device_ids};
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState, VaultReserveMutation};
use dsm::types::operations::{Operation, TransactionMode};

const ACTOR: [u8; 32] = [0xA7; 32];
const VAULT: [u8; 32] = [0x5A; 32];

fn actor_keypair() -> &'static SignatureKeyPair {
    static KP: std::sync::OnceLock<SignatureKeyPair> = std::sync::OnceLock::new();
    KP.get_or_init(|| SignatureKeyPair::generate_from_entropy(&[0xA7; 32]).expect("actor keypair"))
}

/// A DIFFERENT device's key — the counterparty / wrong actor.
fn other_keypair() -> &'static SignatureKeyPair {
    static KP: std::sync::OnceLock<SignatureKeyPair> = std::sync::OnceLock::new();
    KP.get_or_init(|| SignatureKeyPair::generate_from_entropy(&[0x0E; 32]).expect("other keypair"))
}

fn era() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA")
}
fn dbtc() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("dBTC").expect("dBTC")
}

fn sign_with(kp: &SignatureKeyPair, op: &Operation) -> Vec<u8> {
    let payload = op.with_cleared_signature().to_bytes();
    dsm::crypto::sphincs::sphincs_sign(&kp.secret_key, &payload).expect("sign")
}

fn owner_apply_op() -> Operation {
    Operation::DlvOwnerApply {
        vault_id: VAULT.to_vec(),
        settlement_receipt_id: [0x77; 32],
        pending_pointer_x: [0x88; 32],
        parent_sequence: 0,
        new_sequence: 1,
        parent_reserves_digest: [0u8; 32],
        new_reserves_digest: [0u8; 32],
        input_policy_commit: era(),
        output_policy_commit: dbtc(),
        input_amount: 100,
        output_amount: 60,
        signature: Vec::new(),
        mode: TransactionMode::Unilateral,
    }
}

fn settle_op() -> Operation {
    Operation::DlvSettle {
        vault_id: VAULT.to_vec(),
        owner_public_key: other_keypair().public_key.clone(),
        owner_devid: [0xA1; 32],
        owner_genesis: [0u8; 32],
        input_policy_commit: era(),
        output_policy_commit: dbtc(),
        parent_sequence: 0,
        parent_reserves_digest: [0x11; 32],
        reserve_proof_root: [0x22; 32],
        predicate_digest: [0x33; 32],
        route_commit_bytes: vec![0x44; 8],
        external_commitment_x: [0x55; 32],
        input_amount: 100,
        output_amount: 60,
        fee_bps: 30,
        sigma: [0x66; 32],
        settler_public_key: actor_keypair().public_key.clone(),
        settler_devid: ACTOR,
        settlement_receipt_id: [0x77; 32],
        signature: Vec::new(),
        mode: TransactionMode::Unilateral,
    }
}

/// Every variant under test, by name.
fn both() -> Vec<(&'static str, Operation)> {
    vec![
        ("DlvOwnerApply", owner_apply_op()),
        ("DlvSettle", settle_op()),
    ]
}

/// A head whose `public_key` IS the actor's AK, funded and with the vault encumbered —
/// exactly the production relationship between a device head and its signing key.
fn actor_head() -> DeviceState {
    let base = DeviceState::new(ACTOR, ACTOR, actor_keypair().public_key.clone(), 64);
    let rel = compute_smt_key(&ACTOR, &ACTOR);
    let init = initial_chain_tip_from_device_ids(&ACTOR, &ACTOR);

    let mut head = base;
    for (pc, tok, amt) in [
        (era(), &b"ERA"[..], 10_000u64),
        (dbtc(), &b"dBTC"[..], 10_000),
    ] {
        head = head
            .advance(
                rel,
                ACTOR,
                Operation::Mint {
                    amount: dsm::types::token_types::Balance::from_state(amt, [0u8; 32]),
                    token_id: tok.to_vec(),
                    policy_commit: pc,
                    authorized_by: b"self".to_vec(),
                    proof_of_authorization: Vec::new(),
                    message: "seed".to_string(),
                },
                vec![0x11; 32],
                None,
                &[BalanceDelta {
                    policy_commit: pc,
                    direction: BalanceDirection::Credit,
                    amount: amt,
                }],
                Some(init),
                None,
                None,
                None,
            )
            .expect("mint")
            .new_device_state;
    }
    head.fund_vault_reserves(&VAULT, &[(era(), 5_000), (dbtc(), 4_000)], 0)
        .expect("fund")
        .new_device_state
}

/// Advance the actor's self-loop with `op`. `DlvOwnerApply` also moves reserves.
fn advance_with(
    head: &DeviceState,
    op: Operation,
) -> Result<DeviceState, dsm::types::error::DsmError> {
    let is_owner_apply = matches!(op, Operation::DlvOwnerApply { .. });
    let deltas: Vec<BalanceDelta> = if is_owner_apply {
        Vec::new()
    } else {
        vec![
            BalanceDelta {
                policy_commit: era(),
                direction: BalanceDirection::Debit,
                amount: 100,
            },
            BalanceDelta {
                policy_commit: dbtc(),
                direction: BalanceDirection::Credit,
                amount: 60,
            },
        ]
    };
    head.advance(
        compute_smt_key(&ACTOR, &ACTOR),
        ACTOR,
        op,
        vec![0x44; 32],
        None,
        &deltas,
        Some(initial_chain_tip_from_device_ids(&ACTOR, &ACTOR)),
        None,
        None,
        is_owner_apply.then_some(VaultReserveMutation::ApplySettlement {
            vault_id: VAULT,
            input_policy_commit: era(),
            input_amount: 100,
            output_policy_commit: dbtc(),
            output_amount: 60,
            new_sequence: 1,
        }),
    )
    .map(|o| o.new_device_state)
}

// (1) sign -> get_signature returns EXACTLY the installed signature.
#[test]
fn get_signature_returns_exactly_what_was_installed() {
    for (name, op) in both() {
        let sig = sign_with(actor_keypair(), &op);
        let signed = op.with_signature(sig.clone());
        assert_eq!(
            signed.get_signature().as_deref(),
            Some(sig.as_slice()),
            "{name}: get_signature must round-trip the installed signature exactly"
        );
        assert_eq!(sig.len(), 49_856, "{name}: SPX256f signature length");
    }
}

// (2) verification succeeds with the correct actor AK.
// (4) wrong actor / counterparty AK is rejected.
#[test]
fn verification_binds_to_the_actor_ak_and_rejects_any_other_key() {
    let head = actor_head();
    for (name, op) in both() {
        let signed = op.with_signature(sign_with(actor_keypair(), &op));
        assert!(
            advance_with(&head, signed).is_ok(),
            "{name}: the actor's own AK must authorize its self-loop transition"
        );

        // Signed by a DIFFERENT device. For DlvSettle this is the counterparty (the
        // vault owner), whose key is even carried inside the operation as
        // `owner_public_key` — verifying against that would accept this forgery.
        let forged = op.with_signature(sign_with(other_keypair(), &op));
        let err = advance_with(&head, forged).expect_err("wrong-key signature must reject");
        assert!(
            format!("{err}").contains("signature invalid"),
            "{name}: wrong-key rejection must be a signature failure, got: {err}"
        );
    }
}

// (3) an UNSIGNED operation is rejected by the real advance path.
#[test]
fn the_real_advance_path_rejects_an_unsigned_operation() {
    let head = actor_head();
    for (name, op) in both() {
        let err = advance_with(&head, op).expect_err("unsigned must reject");
        assert!(
            format!("{err}").contains("missing signature"),
            "{name}: unsigned must fail closed on the advance path, got: {err}"
        );
    }
}

// (5) mutation of any signed field invalidates the signature.
#[test]
fn mutating_a_signed_field_invalidates_the_signature() {
    let head = actor_head();

    // DlvOwnerApply: change the output amount the settlement pays out.
    let op = owner_apply_op();
    let signed = op.with_signature(sign_with(actor_keypair(), &op));
    let Operation::DlvOwnerApply { signature, .. } = &signed else {
        unreachable!()
    };
    let mut tampered = owner_apply_op();
    if let Operation::DlvOwnerApply { output_amount, .. } = &mut tampered {
        *output_amount = 61; // was 60
    }
    let tampered = tampered.with_signature(signature.clone());
    let err = advance_with(&head, tampered).expect_err("field mutation must reject");
    assert!(
        format!("{err}").contains("signature invalid"),
        "DlvOwnerApply: mutating output_amount must invalidate the signature, got: {err}"
    );

    // DlvSettle: change the input amount the trader pays.
    let op = settle_op();
    let signed = op.with_signature(sign_with(actor_keypair(), &op));
    let Operation::DlvSettle { signature, .. } = &signed else {
        unreachable!()
    };
    // Deliberately a field CONSERVATION DOES NOT POLICE. Tampering `input_amount` is
    // also rejected, but by the conservation arm ("delta[0] must debit the authorized
    // input exactly"), which runs first — so it proves defence in depth, not that the
    // signature binds. `fee_bps` is signed and conservation-invisible, which isolates
    // the signature as the gate that catches it.
    let mut tampered = settle_op();
    if let Operation::DlvSettle { fee_bps, .. } = &mut tampered {
        *fee_bps = 31; // was 30
    }
    let tampered = tampered.with_signature(signature.clone());
    let err = advance_with(&head, tampered).expect_err("field mutation must reject");
    assert!(
        format!("{err}").contains("signature invalid"),
        "DlvSettle: mutating fee_bps must invalidate the signature, got: {err}"
    );

    // And the amount tamper is still caught — earlier, by conservation.
    let mut tampered = settle_op();
    if let Operation::DlvSettle { input_amount, .. } = &mut tampered {
        *input_amount = 101;
    }
    let tampered = tampered.with_signature(signature.clone());
    assert!(
        advance_with(&head, tampered).is_err(),
        "DlvSettle: mutating input_amount must still be rejected"
    );
}

// (6) mutation of the SIGNATURE invalidates verification.
#[test]
fn mutating_the_signature_invalidates_verification() {
    let head = actor_head();
    for (name, op) in both() {
        let mut sig = sign_with(actor_keypair(), &op);
        sig[0] ^= 0x01;
        let err = advance_with(&head, op.with_signature(sig)).expect_err("bit flip must reject");
        assert!(
            format!("{err}").contains("signature invalid"),
            "{name}: a single flipped bit must invalidate, got: {err}"
        );
    }
}

// (7) the canonical preimage is identical before signing and after
//     with_cleared_signature() on the SIGNED operation.
//
// This is the property whose absence made signing ill-defined: clearing did not clear
// these variants, so the preimage a verifier recomputed contained the signature, and
// signing as documented was not well-founded.
#[test]
fn the_canonical_preimage_is_stable_across_signing() {
    for (name, op) in both() {
        let before = op.with_cleared_signature().to_bytes();
        let signed = op.with_signature(sign_with(actor_keypair(), &op));
        let after = signed.with_cleared_signature().to_bytes();
        assert_eq!(
            before, after,
            "{name}: the signing preimage must not depend on the signature"
        );
        assert!(
            signed.to_bytes().len() > after.len(),
            "{name}: the signed encoding must actually carry the signature"
        );
    }
}

/// The head that results from a signed advance still round-trips through persistence
/// with a matching root — a signature is 49,856 bytes and rides inside the committed
/// operation bytes, so it must survive encode/decode intact.
#[test]
fn a_signed_advance_round_trips_through_persistence() {
    use dsm_sdk::storage::client_db::{decode_device_state, encode_device_state};

    let head = actor_head();
    let op = owner_apply_op();
    let after = advance_with(&head, op.with_signature(sign_with(actor_keypair(), &op)))
        .expect("signed advance");

    let bytes = encode_device_state(&after);
    let (decoded, stored_root) = decode_device_state(&bytes).expect("decode");
    assert_eq!(
        decoded.root(),
        stored_root,
        "recomputed root == stored root"
    );
    assert_eq!(decoded.root(), after.root());

    let committed = decoded
        .tip_state(&compute_smt_key(&ACTOR, &ACTOR))
        .expect("tip state");
    assert_eq!(
        committed.operation.get_signature().map(|s| s.len()),
        Some(49_856),
        "the signature must survive the persistence round trip intact"
    );
}
