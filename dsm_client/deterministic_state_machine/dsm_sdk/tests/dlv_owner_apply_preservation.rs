// SPDX-License-Identifier: MIT OR Apache-2.0
//! State-preservation invariants for `Operation::DlvOwnerApply` (`dlv.reconcile`).
//!
//! Written to explain the owner head that contracted 51,101 -> 1,202 bytes on the
//! first live owner reconciliation (P1 `D67B8551`, 2026-08-01). Diagnosis-first:
//! these tests establish what a DLV owner settlement is ALLOWED to change before
//! anything is fixed, so a later repair has a standard to meet.
//!
//! The contraction itself is size, not loss: a device head is current-truth-only, so
//! `tips[rel].state` holds only the CURRENT transition, and its `operation` carries a
//! SPX256f signature (49,856 bytes) whenever the operation is a signed one. Replacing
//! a signed operation with an unsigned one drops ~49.9 KB by construction. The
//! superseded operation stays durable in `bcr_chain_states`.
//!
//! What the size drop actually reveals is the subject of the second test.

#![allow(clippy::disallowed_methods)]

use dsm::core::bilateral_transaction_manager::{compute_smt_key, initial_chain_tip_from_device_ids};
use dsm::core::state_machine::transition::enforce_operation_authorization;
use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState, VaultReserveMutation};
use dsm::types::operations::{Operation, TransactionMode};
use dsm_sdk::storage::client_db::{decode_device_state, encode_device_state};

/// The owner device's ACTUAL signing keypair, cached (SPHINCS+ keygen is slow).
/// `advance` verifies DlvOwnerApply against the advancing head's own public key, so the
/// head must carry a real SPX256f key and the test must sign with its mate — exactly the
/// production relationship between a device head and its AK.
fn owner_keypair() -> &'static dsm::crypto::signatures::SignatureKeyPair {
    static KP: std::sync::OnceLock<dsm::crypto::signatures::SignatureKeyPair> =
        std::sync::OnceLock::new();
    KP.get_or_init(|| {
        dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[0xD6; 32])
            .expect("owner keypair")
    })
}

/// Sign over the canonical preimage `with_cleared_signature().to_bytes()`.
fn sign_as_owner(op: Operation) -> Operation {
    let payload = op.with_cleared_signature().to_bytes();
    let sig = dsm::crypto::sphincs::sphincs_sign(&owner_keypair().secret_key, &payload)
        .expect("sign operation");
    op.with_signature(sig)
}

const OWNER: [u8; 32] = [0xD6; 32];
const PEER: [u8; 32] = [0xB8; 32];
const VAULT: [u8; 32] = [0x5A; 32];

fn era() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA policy commit")
}

fn sofi() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("dBTC").expect("dBTC policy commit")
}

fn mint(head: &DeviceState, policy: [u8; 32], token: &[u8], amount: u64) -> DeviceState {
    let rel = compute_smt_key(&OWNER, &OWNER);
    let init = initial_chain_tip_from_device_ids(&OWNER, &OWNER);
    head.advance(
        rel,
        OWNER,
        Operation::Mint {
            amount: dsm::types::token_types::Balance::from_state(amount, [0u8; 32]),
            token_id: token.to_vec(),
            policy_commit: policy,
            authorized_by: b"self".to_vec(),
            proof_of_authorization: Vec::new(),
            message: "seed".to_string(),
        },
        vec![0x11; 32],
        None,
        &[BalanceDelta {
            policy_commit: policy,
            direction: BalanceDirection::Credit,
            amount,
        }],
        Some(init),
        None,
        None,
        None,
    )
    .expect("mint advance")
    .new_device_state
}

/// An owner head carrying non-trivial material in every field a settlement does NOT
/// own: two balances, a second (peer) relationship tip, a vault-state extra leaf, and
/// funded reserves on both legs.
fn rich_owner_head() -> DeviceState {
    let base = DeviceState::new(OWNER, OWNER, owner_keypair().public_key.clone(), 64);
    let head = mint(&base, era(), b"ERA", 1_000);
    let head = mint(&head, sofi(), b"dBTC", 2_000);

    // A SECOND relationship, so the test can prove an unrelated tip survives intact.
    let peer_rel = compute_smt_key(&OWNER, &PEER);
    let peer_init = initial_chain_tip_from_device_ids(&OWNER, &PEER);
    let head = head
        .advance(
            peer_rel,
            PEER,
            Operation::Noop,
            vec![0x22; 32],
            None,
            &[],
            Some(peer_init),
            None,
            None,
            None,
        )
        .expect("peer advance")
        .new_device_state;

    // A vault-state extra leaf (commits into r_A, must be replayed by restore).
    let head = head
        .with_vault_state_leaf(&VAULT, 0, &[0x33; 32])
        .expect("vault state leaf")
        .new_device_state;

    // Encumber both legs so ApplySettlement has reserves to move.
    head.fund_vault_reserves(&VAULT, &[(era(), 500), (sofi(), 400)], 0)
        .expect("fund reserves")
        .new_device_state
}

/// The operation exactly as `dlv.reconcile` builds it today
/// (dsm_sdk/src/handlers/dlv_routes.rs:1395).
fn owner_apply_op_as_built_by_reconcile() -> Operation {
    Operation::DlvOwnerApply {
        vault_id: VAULT.to_vec(),
        settlement_receipt_id: [0x77; 32],
        pending_pointer_x: [0x88; 32],
        parent_sequence: 0,
        new_sequence: 1,
        // dlv_routes.rs:1401-1402 zeroes both.
        parent_reserves_digest: [0u8; 32],
        new_reserves_digest: [0u8; 32],
        input_policy_commit: era(),
        output_policy_commit: sofi(),
        input_amount: 100,
        output_amount: 60,
        // dlv_routes.rs:1408.
        signature: Vec::new(),
        mode: TransactionMode::Unilateral,
    }
}

fn apply_settlement(head: &DeviceState, op: Operation) -> DeviceState {
    let rel = compute_smt_key(&OWNER, &OWNER);
    head.advance(
        rel,
        OWNER,
        op,
        vec![0x44; 32],
        None,
        &[],
        Some(initial_chain_tip_from_device_ids(&OWNER, &OWNER)),
        None,
        None,
        Some(VaultReserveMutation::ApplySettlement {
            vault_id: VAULT,
            input_policy_commit: era(),
            input_amount: 100,
            output_policy_commit: sofi(),
            output_amount: 60,
            new_sequence: 1,
        }),
    )
    .expect("owner apply advance")
    .new_device_state
}

/// THE PRESERVATION INVARIANT.
///
/// A DLV owner settlement may change the fields the transition explicitly owns — the
/// two named reserve legs, the vault-state leaf, and the tip of the relationship it
/// advances on. It must preserve every unrelated authoritative field entry-for-entry.
#[test]
fn owner_apply_preserves_every_field_the_settlement_does_not_own() {
    let before = rich_owner_head();
    let peer_rel = compute_smt_key(&OWNER, &PEER);

    let balances_before = before.balances_snapshot().clone();
    let peer_tip_before = before.rel_chain_tip(&peer_rel).expect("peer tip").clone();
    let extra_before = before.extra_leaves_snapshot().clone();
    let allocations_before = before.offline_allocations_snapshot().clone();
    let reserves_before = before.vault_reserves_snapshot();

    let after = apply_settlement(
        &before,
        sign_as_owner(owner_apply_op_as_built_by_reconcile()),
    );

    // --- identity is immutable ---
    assert_eq!(after.genesis_digest(), before.genesis_digest());
    assert_eq!(after.devid(), before.devid());
    assert_eq!(after.public_key(), before.public_key());
    assert_eq!(after.legacy_anchor(), before.legacy_anchor());

    // --- balances are UNTOUCHED: a settlement moves nothing spendable ---
    assert_eq!(
        after.balances_snapshot(),
        &balances_before,
        "a settlement must not move spendable balance; the fee accrues in reserves"
    );

    // --- the unrelated relationship tip survives ENTRY-FOR-ENTRY ---
    let peer_tip_after = after.rel_chain_tip(&peer_rel).expect("peer tip preserved");
    assert_eq!(
        peer_tip_after.chain_tip, peer_tip_before.chain_tip,
        "an unrelated relationship's tip must not move"
    );
    assert_eq!(
        peer_tip_after.counterparty_devid,
        peer_tip_before.counterparty_devid
    );
    assert_eq!(
        peer_tip_after.state.is_some(),
        peer_tip_before.state.is_some(),
        "an unrelated tip must not be downgraded to a digest-only tip"
    );

    // --- offline allocations are not a settlement's business ---
    assert_eq!(
        after.offline_allocations_snapshot(),
        &allocations_before,
        "offline-cash allocations are untouched by a vault settlement"
    );

    // --- extra leaves: nothing DISAPPEARS (the settlement may add/replace) ---
    for key in extra_before.keys() {
        assert!(
            after.extra_leaves_snapshot().contains_key(key),
            "extra leaf {key:02x?} vanished; restore would recompute a different root"
        );
    }

    // --- reserves: exactly the two named legs move, by exactly the named amounts ---
    let reserves_after = after.vault_reserves_snapshot();
    for (key, before_val) in &reserves_before {
        let after_val = reserves_after.get(key).expect("reserve leaf preserved");
        let delta = after_val.amount as i128 - before_val.amount as i128;
        assert!(
            delta == 100 || delta == -60 || delta == 0,
            "a reserve leg moved by an amount the settlement did not name: {delta}"
        );
    }
    assert_eq!(
        reserves_after.len(),
        reserves_before.len(),
        "a settlement neither creates nor destroys reserve legs"
    );
}

/// The head must survive persistence: encode -> decode -> the recomputed root equals
/// the stored root, and every collection round-trips.
#[test]
fn owner_apply_head_round_trips_through_persistence() {
    let after = apply_settlement(
        &rich_owner_head(),
        sign_as_owner(owner_apply_op_as_built_by_reconcile()),
    );

    let bytes = encode_device_state(&after);
    let (decoded, stored_root) = decode_device_state(&bytes).expect("decode");

    assert_eq!(
        decoded.root(),
        stored_root,
        "recomputed root must equal the stored root"
    );
    assert_eq!(decoded.root(), after.root(), "root survives the round trip");
    assert_eq!(decoded.balances_snapshot(), after.balances_snapshot());
    assert_eq!(
        decoded.extra_leaves_snapshot(),
        after.extra_leaves_snapshot(),
        "extra leaves must round-trip or restore recomputes a different root"
    );
    assert_eq!(
        decoded.vault_reserves_snapshot(),
        after.vault_reserves_snapshot()
    );
    assert_eq!(
        decoded.relationship_keys().len(),
        after.relationship_keys().len()
    );
}

/// `DlvSettle` and `DlvOwnerApply` are signed, and the real path verifies them.
///
/// THIS WAS #634's RED-ON-PURPOSE ACCEPTANCE TEST. Its assertions are unchanged; only
/// the `#[ignore]`, the fixture (which now holds a real key and signs), and this name
/// have moved. It was called `value_moving_dlv_operations_cannot_be_signed_by_any_code_path`
/// and it recorded that:
///
/// Both are classified as value-moving egress — `EgressAsset::Asset` at
/// operations.rs:885-901, "the owner's OUTPUT leg leaves its reserves" — and both sit
/// in the must-sign set of what transition.rs:393 calls "the canonical rule", whose
/// documented exemptions are only `Genesis`, `Noop`, `Receive`. Yet neither can be
/// signed by any code in the tree:
///
/// * The documented signing payload is `with_cleared_signature().to_bytes()`
///   (transition.rs:835, core_sdk.rs:351). `with_cleared_signature`
///   (operations.rs:2424-2442) enumerates eleven variants and drops these two into
///   `_ => {}` — while `to_bytes` DOES emit their `signature` field
///   (operations.rs:1506, :1536). The preimage therefore contains the signature it is
///   supposed to produce. As specified, signing is not merely unimplemented; it is not
///   well-founded.
/// * `with_signature` cannot install one and `get_signature` returns `None` for them
///   regardless of contents (operations.rs:2366-2385, :2449-2467).
/// * `sign_operation_sphincs` (core_sdk.rs:357-401) routes them to a
///   `log::warn!("non-signable operation type")` and returns `Ok(operation)` UNSIGNED —
///   a producer that reports success while omitting the material a gate requires.
///
/// So `signature: Vec::new()` at dlv_routes.rs:1408 is not a forgotten call; it is the
/// only value the field can currently hold.
///
/// This is NOT the head contraction. That is benign: the head is current-truth-only,
/// the ~49.9 KB was the superseded `DlvCreate`'s SPX256f signature, and it stays
/// durable in `bcr_chain_states`. Nor is it presently exploitable — `tip_state()` has
/// one production reader (state_machine/mod.rs:206, entropy only) and every
/// re-verification surface is hash-only by explicit design
/// (succession_binding.rs:136-140).
///
/// What makes it urgent is irreversibility. The signature lives inside
/// `operation.to_bytes()`, hence inside `compute_chain_tip()`, hence inside the SMT
/// leaf and root `r_A`. Signing these operations later REWRITES the tip and every
/// descendant. Every settlement committed before the fix is permanently unverifiable
/// and cannot be retro-signed in place.
#[test]
fn value_moving_dlv_operations_are_signed_and_verified_on_the_real_path() {
    let op = owner_apply_op_as_built_by_reconcile();

    // The canonical rule refuses it, and DlvOwnerApply is not among the documented
    // no-signature exemptions (Genesis, Noop, Receive) at transition.rs:399-400.
    assert!(
        enforce_operation_authorization(&op).is_err(),
        "precondition: the canonical rule must reject an unsigned DlvOwnerApply"
    );

    // Yet the signing preimage is self-referential: clearing does not clear.
    let cleared = op.with_cleared_signature();
    let Operation::DlvOwnerApply { .. } = &cleared else {
        panic!("with_cleared_signature must preserve the variant");
    };
    let signed = op.clone().with_signature(vec![0xAB; 64]);
    let Operation::DlvOwnerApply { signature, .. } = &signed else {
        panic!("with_signature must preserve the variant");
    };
    assert!(
        !signature.is_empty(),
        "DEFECT: with_signature cannot install a signature on DlvOwnerApply — it falls \
         through operations.rs:2449-2467's `_ => {{}}` arm, so the field is unwritable \
         and `signature: Vec::new()` at dlv_routes.rs:1408 is the only value it admits"
    );

    // And advance() commits the unsigned operation into the canonical root regardless:
    // DeviceState::advance calls no authorization gate (the rule's only two callers,
    // relationship.rs:598 and transition.rs:551, are both off this path).
    let before = rich_owner_head();
    let after = apply_settlement(&before, sign_as_owner(op));
    assert_ne!(after.root(), before.root(), "the advance did happen");

    let committed = after
        .tip_state(&compute_smt_key(&OWNER, &OWNER))
        .expect("owner tip carries the committed operation");
    let Operation::DlvOwnerApply { signature, .. } = &committed.operation else {
        panic!("owner tip should carry the DlvOwnerApply operation");
    };
    assert!(
        !signature.is_empty(),
        "DEFECT: root {} commits an unsigned value-egress transition. It cannot be \
         retro-signed — the signature is inside compute_chain_tip, so signing rewrites \
         this tip and every descendant.",
        hex_root(&after)
    );
}

fn hex_root(s: &DeviceState) -> String {
    s.root()[..6].iter().map(|b| format!("{b:02x}")).collect()
}
