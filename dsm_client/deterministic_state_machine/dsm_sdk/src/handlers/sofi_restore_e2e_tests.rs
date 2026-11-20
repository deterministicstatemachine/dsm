// SPDX-License-Identifier: MIT OR Apache-2.0

//! A wallet that traded in SoFi, restored from its 24 words on storage nodes
//! (DSM Amendment A40). The network holds only the root a realized position
//! selected; the restored wallet derives the leaves that root holds from
//! SoFi's public objects, exactly as its lost device derived them when it took
//! the position, and keeps them only when they recompute that root (owner,
//! 2026-11-19: "There's no reason it shouldn't work").

use dsm::types::proto as generated;
use serial_test::serial;

use super::node_e2e_tests::{
    admitted_position, adopt, args, balance, entered, genesis_root_of,
    head_agrees_with_admitted_root, invoke, member_name, open_market, position_of,
    realized_through, standing_of, Market,
};
use super::restore_from_phrase_tests::{back_up, restore};
use crate::economic_fixtures::{test_mnemonic, NETWORK};
use crate::sdk::app_state::AppState;
use crate::sdk::sofi_exercise::attempt_cell;
use crate::sdk::sofi_reads::VerifierContext;
use crate::sdk::storage_set::canonical_set;
use crate::storage::client_db::sofi_vault_head;
use crate::test_support::two_device::{Pair, TestDevice};

/// `d`'s one-hop trade of `amount_in` ERA for TKN in the market.
fn trade(d: &TestDevice, m: &Market, amount_in: u64) -> Vec<u8> {
    args(&generated::SofiTradeRequest {
        vault_id: m.vault_id.to_vec(),
        token_in_policy_commit: m.era.to_vec(),
        amount_in_entered: entered(d, &m.era, amount_in),
        min_amount_out_entered: entered(d, &m.tkn, 1),
        token_out_policy_commit: m.tkn.to_vec(),
    })
}

/// What `d` holds of the market's two tokens: `(ERA, TKN)`.
fn holdings(d: &TestDevice, m: &Market) -> (u64, u64) {
    (balance(d, &m.era), balance(d, &m.tkn))
}

/// The vault's head as `d` recorded it.
fn vault_head(d: &TestDevice, m: &Market) -> sofi_vault_head::VaultHead {
    d.enter();
    sofi_vault_head::head(&m.vault_id)
        .expect("the vault head reads")
        .expect("the vault's head is recorded")
}

/// B trades in A's market and the position realizes: B's register holds, at
/// that position, only the root the resolution selected. B backs up and its
/// phone is lost. Restored from its words, B comes back at that position with
/// exactly the ERA and the TKN it held, its head agreeing with the leaves the
/// root holds, and trades again from there: the next position realizes on top
/// of the restored one.
///
/// MUTATION CONTROL: with the replay of a realized position refused, as before
/// it was built (`fold_own`), the restore is refused and this goes red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_wallet_restored_after_a_realized_trade_holds_both_tokens_and_trades_on() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let q = realized_through(&p.b, "sofi.trade", trade(&p.b, &m, 10)).await;
    let held = holdings(&p.b, &m);
    assert!(held.1 > 0, "the trade paid B in TKN");
    back_up(&p.b, 1).await;

    let mut restored = p.b.on_a_new_device("B-restored");
    let answer = restore(&test_mnemonic(p.b.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&p.fleet);
    assert_eq!(admitted_position(&restored), q, "the register's head");
    assert_eq!(holdings(&restored, &m), held, "both tokens, exactly");
    head_agrees_with_admitted_root(&restored, &[m.era, m.tkn]);

    let next = realized_through(&restored, "sofi.trade", trade(&restored, &m, 10)).await;
    assert_eq!(next, q + 1, "the next position lands on the restored head");
    let after = holdings(&restored, &m);
    assert_eq!(after.0, held.0 - 10, "the second trade spent 10 more");
    assert!(after.1 > held.1, "and paid more TKN");
    head_agrees_with_admitted_root(&restored, &[m.era, m.tkn]);
}

/// The same trade with no backup on the nodes: the register alone brings B
/// back at the realized position with both tokens, and the vault's state the
/// position selected is recorded as B's lost device recorded it. B adds the
/// token again, as a wallet with no backup must, and trades on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_realized_trade_comes_back_from_the_register_alone() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let q = realized_through(&p.b, "sofi.trade", trade(&p.b, &m, 10)).await;
    let held = holdings(&p.b, &m);
    let recorded = vault_head(&p.b, &m);

    let mut restored = p.b.on_a_new_device("B-restored");
    let answer = restore(&test_mnemonic(p.b.seed)).await;
    assert!(answer.success, "the restore: {:?}", answer.error_message);
    restored.start(&p.fleet);
    assert_eq!(admitted_position(&restored), q);
    assert_eq!(holdings(&restored, &m), held, "both tokens, exactly");
    head_agrees_with_admitted_root(&restored, &[m.era, m.tkn]);
    assert_eq!(
        vault_head(&restored, &m),
        recorded,
        "the vault's state the position selected"
    );

    adopt(&restored, &m.tkn).await;
    let next = realized_through(&restored, "sofi.trade", trade(&restored, &m, 10)).await;
    assert_eq!(next, q + 1);
    assert_eq!(holdings(&restored, &m).0, held.0 - 10);
    head_agrees_with_admitted_root(&restored, &[m.era, m.tkn]);
}

/// B trades while the vault's first attempt key refuses writes at its leader:
/// the fulfillment registers and the position stays open. A restore then is
/// refused, says why and when to try again, and leaves no identity behind,
/// since nothing decides the position's root yet. Once the leader takes writes
/// and the position realizes, the restore tried again on the same device brings
/// B back at that position with what it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_restore_waits_for_an_open_position_and_then_takes_its_result() {
    let p = Pair::boot(500, 200).await;
    let m = open_market(&p).await;
    let set = canonical_set(NETWORK).expect("the pinned set");
    let q = admitted_position(&p.b) + 1;
    let (own, parents) = standing_of(&p.b);
    let ctx = VerifierContext::new(&set, Some(own), parents.as_ref()).expect("a verifier");
    let r0 = genesis_root_of(&ctx.verifier(), &m.vault_id);
    let attempt = attempt_cell(&set, &m.vault_id, &r0, 0).expect("the first attempt key");
    let leader = member_name(attempt.routed().route().leader());
    p.nodes
        .refuse_cell_writes(&leader, &[*attempt.routed().key()])
        .await;
    let open = invoke(&p.b, "sofi.trade", trade(&p.b, &m, 10)).await;
    assert_eq!(
        position_of(&open, "sofi.trade"),
        (q, generated::SofiPositionState::RetriesExhausted as i32),
        "the position is open"
    );

    p.b.on_a_new_device("B-restored");
    let waiting = restore(&test_mnemonic(p.b.seed)).await;
    assert!(!waiting.success, "nothing decides position {q} yet");
    let why = waiting.error_message.expect("a refusal says why");
    assert!(
        why.contains(&format!("not decided past position {}", q - 1)) && why.contains("try again"),
        "{why}"
    );
    assert!(
        !AppState::get_has_identity(),
        "a refused restore leaves no identity"
    );

    p.nodes.accept_cell_writes(&leader).await;
    let resolved = position_of(
        &invoke(
            &p.b,
            "sofi.resolve",
            args(&generated::SofiResolveRequest {}),
        )
        .await,
        "sofi.resolve",
    );
    assert_eq!(resolved, (q, generated::SofiPositionState::Realized as i32));
    let held = holdings(&p.b, &m);

    // The same new device, its app opened again over what the refused attempt
    // left in its database.
    let mut restored = p.b.on_a_new_device("B-restored");
    let answer = restore(&test_mnemonic(p.b.seed)).await;
    assert!(
        answer.success,
        "the restore again: {:?}",
        answer.error_message
    );
    restored.start(&p.fleet);
    assert_eq!(admitted_position(&restored), q);
    assert_eq!(holdings(&restored, &m), held);
    head_agrees_with_admitted_root(&restored, &[m.era, m.tkn]);
}
